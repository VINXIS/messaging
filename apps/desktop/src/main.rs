use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use eframe::egui::{self, Color32};
use identity_core::UserIdentity;
use libp2p::Multiaddr;
use messaging_proto::core::ServerAdvert;
use net_overlay::{OverlayCommand, OverlayConfig, OverlayEvent, OverlayNode};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet, VecDeque, btree_map::Entry},
    fs,
    path::PathBuf,
    sync::Arc,
};
use tokio::{runtime::Runtime, sync::mpsc::error::TryRecvError};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    ensure_display_env()?;
    info!("starting messaging desktop MVP shell");

    let runtime = Arc::new(Runtime::new()?);
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Messaging MVP",
        options,
        Box::new(move |_cc| {
            let runtime = runtime.clone();
            Ok(Box::new(App::new(runtime)))
        }),
    )?;
    Ok(())
}

/// Verifies a windowing backend exists before spawning egui; otherwise exits with a clear error.
fn ensure_display_env() -> Result<()> {
    if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
        return Ok(());
    }
    let has_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("WAYLAND_SOCKET").is_some();
    let has_x11 = std::env::var_os("DISPLAY").is_some();
    if has_wayland || has_x11 {
        Ok(())
    } else {
        bail!(
            "no windowing backend detected (set DISPLAY for X11 or WAYLAND_DISPLAY/WAYLAND_SOCKET for Wayland)"
        )
    }
}

struct App {
    runtime: Arc<Runtime>,
    identity: Option<UserIdentity>,
    identity_display: String,
    overlay: Option<OverlayHandle>,
    listen_multiaddr_input: String,
    bootstrap_input: String,
    additional_advertise_input: String,
    server_id_input: String,
    server_name_input: String,
    publish_public: bool,
    find_server_id_input: String,
    dial_addr_input: String,
    last_ui_error: Option<String>,
    cached_bootstrap: Vec<Multiaddr>,
    peer_log: VecDeque<String>,
    discovered_servers: BTreeMap<String, ServerAdvert>,
    loaded_catalog_message: Option<String>,
    loaded_ui_state_message: Option<String>,
    ui_state_dirty: bool,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_overlay_events();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Messaging MVP");

            if let Some(err) = &self.last_ui_error {
                ui.colored_label(Color32::from_rgb(200, 50, 50), err);
                ui.separator();
            }

            if let Some(message) = self.loaded_ui_state_message.take() {
                ui.colored_label(Color32::from_rgb(60, 170, 60), message);
                ui.separator();
            }

            if let Some(message) = self.loaded_catalog_message.take() {
                ui.colored_label(Color32::from_rgb(60, 170, 60), message);
                ui.separator();
            }

            if self.identity.is_none() {
                if ui.button("Generate identity").clicked() {
                    match UserIdentity::generate() {
                        Ok(id) => {
                            let display = id.format_public_key();
                            if let Err(err) = persist_identity(&id) {
                                tracing::error!(?err, "failed to persist identity");
                                self.last_ui_error =
                                    Some("Failed to save identity to disk".to_string());
                            } else {
                                self.last_ui_error = None;
                            }
                            self.identity_display = display;
                            self.identity = Some(id);
                        }
                        Err(err) => {
                            tracing::error!(?err, "failed to generate identity");
                            self.last_ui_error = Some("Unable to generate identity".to_string());
                        }
                    }
                }
            }

            if !self.identity_display.is_empty() {
                ui.label(format!("Public key: {}", self.identity_display));
            }

            ui.separator();

            if let Some(identity) = self.identity.clone() {
                self.render_overlay_controls(ui, identity);
            } else {
                ui.label("Generate an identity to unlock overlay controls.");
            }
        });
    }
}

impl App {
    fn new(runtime: Arc<Runtime>) -> Self {
        let mut identity = None;
        let mut identity_display = String::new();
        let mut last_ui_error = None;
        let mut peer_log = VecDeque::new();
        let mut cached_bootstrap = Vec::new();
        let mut discovered_servers = BTreeMap::new();
        let mut loaded_catalog_message = None;
        let mut loaded_ui_state_message = None;
        let mut listen_multiaddr_input = DEFAULT_LISTEN_ADDR.to_string();
        let mut bootstrap_input = String::new();
        let mut additional_advertise_input = String::new();

        match load_identity_from_disk() {
            Ok(Some(id)) => {
                info!("loaded persisted identity");
                identity_display = id.format_public_key();
                identity = Some(id);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(?err, "failed to load persisted identity");
                last_ui_error = Some("Failed to load saved identity".to_string());
            }
        }

        match load_cached_peers() {
            Ok(peers) => {
                if !peers.is_empty() {
                    info!(count = peers.len(), "loaded cached bootstrap peers");
                    for addr in &peers {
                        peer_log.push_back(format!("Cached peer {addr}"));
                    }
                    cached_bootstrap = peers;
                    if let Err(err) = persist_known_peers(&cached_bootstrap) {
                        tracing::error!(?err, "failed to refresh bootstrap cache on load");
                        last_ui_error
                            .get_or_insert("Failed to refresh bootstrap cache".to_string());
                    }
                }
            }
            Err(err) => {
                tracing::error!(?err, "failed to load cached peers");
                last_ui_error.get_or_insert("Failed to load bootstrap cache".to_string());
            }
        }

        match load_overlay_settings() {
            Ok(Some(settings)) => {
                if !settings.listen_multiaddr.is_empty() {
                    listen_multiaddr_input = settings.listen_multiaddr;
                }
                bootstrap_input = settings.bootstrap_peers;
                additional_advertise_input = settings.additional_advertise;
                loaded_ui_state_message = Some("Restored overlay settings".to_string());
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(?err, "failed to load overlay settings");
                last_ui_error.get_or_insert("Failed to load overlay settings".to_string());
            }
        }

        match load_server_catalog() {
            Ok(Some(catalog)) => {
                if !catalog.is_empty() {
                    info!(count = catalog.len(), "loaded discovered server catalog");
                    peer_log.push_front(format!("Loaded {} servers from catalog", catalog.len()));
                    discovered_servers = catalog;
                    loaded_catalog_message = Some("Loaded saved server catalog".to_string());
                }
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(?err, "failed to load server catalog");
                last_ui_error.get_or_insert("Failed to load server catalog".to_string());
            }
        }

        Self {
            runtime,
            identity,
            identity_display,
            overlay: None,
            listen_multiaddr_input,
            bootstrap_input,
            additional_advertise_input,
            server_id_input: String::new(),
            server_name_input: String::new(),
            publish_public: true,
            find_server_id_input: String::new(),
            dial_addr_input: String::new(),
            last_ui_error,
            cached_bootstrap,
            peer_log,
            discovered_servers,
            loaded_catalog_message,
            loaded_ui_state_message,
            ui_state_dirty: false,
        }
    }

    fn render_overlay_controls(&mut self, ui: &mut egui::Ui, identity: UserIdentity) {
        if self.overlay.is_none() {
            ui.heading("Overlay setup");
            ui.label("Listen multiaddrs (one per line, blank uses default)");
            if ui
                .text_edit_multiline(&mut self.listen_multiaddr_input)
                .changed()
            {
                self.ui_state_dirty = true;
            }

            ui.add_space(4.0);
            ui.label("Bootstrap peers (optional, one per line)");
            if ui.text_edit_multiline(&mut self.bootstrap_input).changed() {
                self.ui_state_dirty = true;
            }

            if ui.button("Start overlay").clicked() {
                match self.start_overlay(identity.clone()) {
                    Ok(()) => {
                        self.last_ui_error = None;
                    }
                    Err(err) => {
                        tracing::error!(?err, "failed to start overlay");
                        self.last_ui_error = Some(format!("Overlay launch failed: {err}"));
                    }
                }
            }

            self.render_overlay_settings_footer(ui, true);

            if !self.cached_bootstrap.is_empty() || !self.discovered_servers.is_empty() {
                ui.add_space(6.0);
                if ui.button("Clear cached peers & servers").clicked() {
                    self.clear_cached_state();
                }
            }
            return;
        }

        ui.heading("Overlay");
        if let Some(overlay) = &self.overlay {
            ui.label(format!("Peer ID: {}", overlay.peer_id));

            if overlay.event_channel_closed {
                ui.colored_label(Color32::from_rgb(200, 50, 50), "Event channel closed");
            }

            if overlay.listen_addrs.is_empty() {
                ui.label("Waiting for listener addresses...");
            } else {
                ui.label("Listening on:");
                for addr in &overlay.listen_addrs {
                    ui.monospace(addr);
                }
            }

            if !self.cached_bootstrap.is_empty() {
                ui.separator();
                ui.label("Cached bootstrap peers:");
                for addr in &self.cached_bootstrap {
                    ui.monospace(addr.to_string());
                }
            }
        }

        ui.separator();
        ui.heading("Publish server advert");
        ui.horizontal(|ui| {
            ui.label("Server ID");
            ui.text_edit_singleline(&mut self.server_id_input);
        });
        ui.horizontal(|ui| {
            ui.label("Display name");
            ui.text_edit_singleline(&mut self.server_name_input);
        });
        ui.checkbox(&mut self.publish_public, "Public server");
        ui.label("Additional advertised addresses (optional)");
        if ui
            .text_edit_multiline(&mut self.additional_advertise_input)
            .changed()
        {
            self.ui_state_dirty = true;
        }

        self.render_overlay_settings_footer(ui, false);

        if ui.button("Publish advert").clicked() {
            match self.publish_server_advert() {
                Ok(()) => {
                    self.last_ui_error = None;
                }
                Err(err) => {
                    tracing::error!(?err, "failed to publish advert");
                    self.last_ui_error = Some(format!("Advert publish failed: {err}"));
                }
            }
        }

        ui.separator();
        ui.heading("Lookup server advert");
        ui.horizontal(|ui| {
            ui.label("Server ID");
            ui.text_edit_singleline(&mut self.find_server_id_input);
        });
        if ui.button("Find advert").clicked() {
            match self.find_server_advert() {
                Ok(()) => {
                    self.last_ui_error = None;
                }
                Err(err) => {
                    tracing::error!(?err, "failed to find advert");
                    self.last_ui_error = Some(format!("Lookup failed: {err}"));
                }
            }
        }

        ui.separator();
        ui.heading("Dial peer");
        ui.horizontal(|ui| {
            ui.label("Multiaddr");
            ui.text_edit_singleline(&mut self.dial_addr_input);
        });
        if ui.button("Dial").clicked() {
            match self.dial_peer_address() {
                Ok(()) => {
                    self.last_ui_error = None;
                }
                Err(err) => {
                    tracing::error!(?err, "dial failed");
                    self.last_ui_error = Some(format!("Dial failed: {err}"));
                }
            }
        }

        if !self.discovered_servers.is_empty() {
            ui.separator();
            ui.heading("Discovered servers");

            let entries: Vec<_> = self
                .discovered_servers
                .iter()
                .map(|(id, advert)| (id.clone(), advert.clone()))
                .collect();

            for (server_id, advert) in entries {
                let addresses = advert.bootstrap_addresses.clone();
                let mut fill_addr: Option<String> = None;
                let mut cache_all = false;

                ui.group(|ui| {
                    ui.heading(&advert.display_name);
                    ui.label(format!("Server ID: {server_id}"));
                    ui.label(format!(
                        "Public: {}",
                        if advert.is_public { "yes" } else { "no" }
                    ));
                    if addresses.is_empty() {
                        ui.label("No bootstrap addresses advertised");
                    } else {
                        ui.label("Bootstrap addresses:");
                        for addr in &addresses {
                            ui.monospace(addr);
                        }
                        ui.horizontal(|ui| {
                            if let Some(addr) = addresses.first() {
                                if ui.button("Fill dial").clicked() {
                                    fill_addr = Some(addr.clone());
                                }
                            }
                            if ui.button("Cache all").clicked() {
                                cache_all = true;
                            }
                        });
                    }
                });

                if let Some(addr) = fill_addr {
                    self.dial_addr_input = addr;
                    self.last_ui_error = None;
                }

                if cache_all {
                    for raw in addresses {
                        match raw.parse::<Multiaddr>() {
                            Ok(addr) => self.record_known_peer(addr),
                            Err(err) => warn!(%raw, ?err, "failed to cache advert address"),
                        }
                    }
                }
            }
        }

        ui.separator();
        ui.heading("Overlay events");
        if let Some(overlay) = &self.overlay {
            egui::ScrollArea::vertical()
                .id_source("overlay-events")
                .max_height(220.0)
                .show(ui, |ui| {
                    for entry in overlay.events.iter() {
                        ui.label(entry);
                    }
                });
        }

        if !self.peer_log.is_empty() {
            ui.separator();
            ui.heading("Known peers");
            egui::ScrollArea::vertical()
                .id_source("peer-log")
                .max_height(180.0)
                .show(ui, |ui| {
                    for entry in &self.peer_log {
                        ui.label(entry);
                    }
                });
        }

        if !self.cached_bootstrap.is_empty() || !self.discovered_servers.is_empty() {
            ui.add_space(6.0);
            if ui.button("Clear cached peers & servers").clicked() {
                self.clear_cached_state();
            }
        }
    }

    fn render_overlay_settings_footer(&mut self, ui: &mut egui::Ui, allow_reset: bool) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if allow_reset && ui.button("Reset to defaults").clicked() {
                self.reset_overlay_settings();
            }

            let save_clicked = ui
                .add_enabled(
                    self.ui_state_dirty,
                    egui::Button::new("Save overlay settings"),
                )
                .clicked();
            if save_clicked {
                self.persist_overlay_settings_inputs(Some("Overlay settings saved"));
            }

            if self.ui_state_dirty {
                ui.add_space(6.0);
                ui.colored_label(Color32::from_rgb(200, 120, 0), "Unsaved changes");
            }
        });
    }

    fn persist_overlay_settings_inputs(&mut self, success_message: Option<&str>) {
        let snapshot = OverlaySettingsSnapshot {
            listen_multiaddr: self.listen_multiaddr_input.clone(),
            bootstrap_peers: self.bootstrap_input.clone(),
            additional_advertise: self.additional_advertise_input.clone(),
        };

        match persist_overlay_settings(&snapshot) {
            Ok(()) => {
                self.ui_state_dirty = false;
                if let Some(msg) = success_message {
                    self.loaded_ui_state_message = Some(msg.to_string());
                }
            }
            Err(err) => {
                tracing::error!(?err, "failed to persist overlay settings");
                self.last_ui_error
                    .get_or_insert("Failed to save overlay settings".to_string());
            }
        }
    }

    fn reset_overlay_settings(&mut self) {
        self.listen_multiaddr_input = DEFAULT_LISTEN_ADDR.to_string();
        self.bootstrap_input.clear();
        self.additional_advertise_input.clear();
        self.ui_state_dirty = true;
        self.loaded_ui_state_message =
            Some("Overlay settings reset to defaults (unsaved)".to_string());
    }

    fn start_overlay(&mut self, identity: UserIdentity) -> Result<()> {
        let mut listen_addrs = parse_multiaddr_list(&self.listen_multiaddr_input)?;
        if listen_addrs.is_empty() {
            listen_addrs.push(
                DEFAULT_LISTEN_ADDR
                    .parse()
                    .context("default listen multiaddr invalid")?,
            );
        }

        let mut bootstrap_peers = parse_multiaddr_list(&self.bootstrap_input)?;
        bootstrap_peers.extend(self.cached_bootstrap.iter().cloned());

        let mut seen = HashSet::new();
        bootstrap_peers.retain(|addr| seen.insert(addr.to_string()));

        let config = OverlayConfig {
            identity,
            listen_addresses: listen_addrs,
            bootstrap_peers,
        };

        let node = self
            .runtime
            .block_on(OverlayNode::launch(config))
            .context("overlay bootstrap task failed")?;

        let mut handle = OverlayHandle::new(node);
        handle.push_event("Overlay launched");
        self.overlay = Some(handle);
        self.persist_overlay_settings_inputs(Some("Overlay settings saved"));
        Ok(())
    }

    fn publish_server_advert(&mut self) -> Result<()> {
        let server_id = self.server_id_input.trim();
        if server_id.is_empty() {
            bail!("Server ID required");
        }

        let display_name = self.server_name_input.trim();
        if display_name.is_empty() {
            bail!("Display name required");
        }

        let overlay = self.overlay.as_ref().context("overlay is not running")?;

        let mut advertised = overlay.listen_addrs.clone();
        let additional = parse_multiaddr_list(&self.additional_advertise_input)?;
        advertised.extend(additional.into_iter().map(|addr| addr.to_string()));
        advertised.sort();
        advertised.dedup();

        let advert = ServerAdvert {
            server_id: server_id.to_string(),
            display_name: display_name.to_string(),
            bootstrap_addresses: advertised,
            is_public: self.publish_public,
        };

        let sender = overlay.node.command_sender();
        let advert_clone = advert.clone();
        self.runtime
            .block_on(sender.send(OverlayCommand::PublishServerAdvert(advert_clone)))
            .map_err(|err| anyhow::anyhow!("command channel closed: {err}"))?;

        if let Some(overlay) = &mut self.overlay {
            overlay.push_event(format!("Publish requested for {server_id}"));
        }

        self.record_server_advert(advert);
        self.persist_overlay_settings_inputs(None);

        Ok(())
    }

    fn find_server_advert(&mut self) -> Result<()> {
        let server_id = self.find_server_id_input.trim();
        if server_id.is_empty() {
            bail!("Server ID required");
        }

        let overlay = self.overlay.as_ref().context("overlay is not running")?;
        let sender = overlay.node.command_sender();
        self.runtime
            .block_on(sender.send(OverlayCommand::FindServerAdvert {
                server_id: server_id.to_string(),
            }))
            .map_err(|err| anyhow::anyhow!("command channel closed: {err}"))?;

        if let Some(overlay) = &mut self.overlay {
            overlay.push_event(format!("Lookup requested for {server_id}"));
        }

        Ok(())
    }

    fn dial_peer_address(&mut self) -> Result<()> {
        let raw = self.dial_addr_input.trim();
        if raw.is_empty() {
            bail!("Enter a multiaddr to dial");
        }

        let addr: Multiaddr = raw.parse().context("invalid multiaddr")?;
        let overlay = self.overlay.as_ref().context("overlay is not running")?;
        let sender = overlay.node.command_sender();
        self.runtime
            .block_on(sender.send(OverlayCommand::DialAddress(addr)))
            .map_err(|err| anyhow::anyhow!("command channel closed: {err}"))?;

        if let Some(overlay) = &mut self.overlay {
            overlay.push_event(format!("Dial requested for {raw}"));
        }

        Ok(())
    }

    fn drain_overlay_events(&mut self) {
        loop {
            let event = {
                let Some(overlay) = self.overlay.as_mut() else {
                    break;
                };

                match overlay.node.event_rx.try_recv() {
                    Ok(event) => event,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        overlay.event_channel_closed = true;
                        overlay.push_event("Event stream disconnected");
                        self.last_ui_error = self
                            .last_ui_error
                            .clone()
                            .or_else(|| Some("Overlay event stream disconnected".to_string()));
                        break;
                    }
                }
            };

            match &event {
                OverlayEvent::BootstrapDialQueued(addr) => {
                    self.record_known_peer(addr.clone());
                }
                OverlayEvent::ServerAdvertFound { advert, .. } => {
                    self.record_server_advert(advert.clone());
                }
                _ => {}
            }

            if let Some(overlay) = self.overlay.as_mut() {
                handle_overlay_event(overlay, event, &mut self.last_ui_error);
            } else {
                break;
            }
        }
    }

    fn clear_cached_state(&mut self) {
        if self.cached_bootstrap.is_empty() && self.discovered_servers.is_empty() {
            return;
        }

        self.cached_bootstrap.clear();
        self.discovered_servers.clear();
        self.loaded_catalog_message = None;

        if let Err(err) = persist_known_peers(&self.cached_bootstrap) {
            tracing::error!(?err, "failed to persist bootstrap peers after clearing");
            self.last_ui_error
                .get_or_insert("Failed to clear bootstrap cache".to_string());
        }

        if let Err(err) = persist_server_catalog(&self.discovered_servers) {
            tracing::error!(?err, "failed to persist server catalog after clearing");
            self.last_ui_error
                .get_or_insert("Failed to clear server catalog".to_string());
        }

        if let Some(overlay) = self.overlay.as_mut() {
            overlay.push_event("Cleared cached peers and servers");
        }

        self.peer_log
            .push_front("Cleared cached peers and servers".to_string());
        while self.peer_log.len() > MAX_KNOWN_PEERS {
            self.peer_log.pop_back();
        }
    }

    fn record_known_peer(&mut self, addr: Multiaddr) {
        if self
            .cached_bootstrap
            .iter()
            .any(|existing| existing == &addr)
        {
            return;
        }

        if self.cached_bootstrap.len() >= MAX_KNOWN_PEERS {
            self.cached_bootstrap.remove(0);
        }
        self.cached_bootstrap.push(addr.clone());

        let entry = format!("Cached peer {addr}");
        self.peer_log.push_front(entry);
        while self.peer_log.len() > MAX_KNOWN_PEERS {
            self.peer_log.pop_back();
        }

        if let Err(err) = persist_known_peers(&self.cached_bootstrap) {
            tracing::error!(?err, "failed to persist bootstrap peers");
            self.last_ui_error
                .get_or_insert("Failed to persist bootstrap peers".to_string());
        }
    }

    fn record_server_advert(&mut self, advert: ServerAdvert) {
        let server_id = advert.server_id.clone();
        let display_name = advert.display_name.clone();

        let is_existing = self.discovered_servers.contains_key(&server_id);
        if !is_existing && self.discovered_servers.len() >= MAX_DISCOVERED_SERVERS {
            if let Some(oldest) = self.discovered_servers.keys().next().cloned() {
                self.discovered_servers.remove(&oldest);
            }
        }

        let mut newly_inserted = false;
        match self.discovered_servers.entry(server_id.clone()) {
            Entry::Occupied(mut entry) => {
                entry.insert(advert.clone());
            }
            Entry::Vacant(vacant) => {
                vacant.insert(advert.clone());
                newly_inserted = true;
            }
        }

        if newly_inserted {
            self.peer_log
                .push_front(format!("Discovered server {server_id} ({display_name})"));
            while self.peer_log.len() > MAX_KNOWN_PEERS {
                self.peer_log.pop_back();
            }
        }

        for raw in &advert.bootstrap_addresses {
            match raw.parse::<Multiaddr>() {
                Ok(addr) => self.record_known_peer(addr),
                Err(err) => warn!(%raw, ?err, "skipping advert address"),
            }
        }

        if let Err(err) = persist_server_catalog(&self.discovered_servers) {
            tracing::error!(?err, "failed to persist server catalog");
            self.last_ui_error
                .get_or_insert("Failed to persist server catalog".to_string());
        }
    }
}

fn handle_overlay_event(
    overlay: &mut OverlayHandle,
    event: OverlayEvent,
    last_ui_error: &mut Option<String>,
) {
    match event {
        OverlayEvent::ListeningOn(addr) => {
            let addr_str = addr.to_string();
            if !overlay.listen_addrs.contains(&addr_str) {
                overlay.listen_addrs.push(addr_str.clone());
            }
            overlay.push_event(format!("Now listening on {addr_str}"));
        }
        OverlayEvent::BootstrapDialQueued(addr) => {
            overlay.push_event(format!("Dialing bootstrap {addr}"));
        }
        OverlayEvent::ServerAdvertStored { server_id } => {
            overlay.push_event(format!("Advert stored for {server_id}"));
        }
        OverlayEvent::ServerAdvertFound { server_id, advert } => {
            let addresses = if advert.bootstrap_addresses.is_empty() {
                "<none>".to_string()
            } else {
                advert.bootstrap_addresses.join(", ")
            };
            overlay.push_event(format!(
                "Found advert {server_id} => name='{}' public={} addrs=[{}]",
                advert.display_name, advert.is_public, addresses
            ));
        }
        OverlayEvent::ServerAdvertNotFound { server_id } => {
            overlay.push_event(format!("No advert found for {server_id}"));
        }
        OverlayEvent::PeerDiscovered(peer) => {
            overlay.push_event(format!("Kademlia discovered peer {peer}"));
        }
        OverlayEvent::SwarmError(err) => {
            overlay.push_event(format!("Error: {err}"));
            if last_ui_error.is_none() {
                *last_ui_error = Some(err);
            }
        }
    }
}

struct OverlayHandle {
    node: OverlayNode,
    peer_id: String,
    listen_addrs: Vec<String>,
    events: VecDeque<String>,
    event_channel_closed: bool,
}

impl OverlayHandle {
    fn new(node: OverlayNode) -> Self {
        let peer_id = node.peer_id().to_string();
        Self {
            node,
            peer_id,
            listen_addrs: Vec::new(),
            events: VecDeque::new(),
            event_channel_closed: false,
        }
    }

    fn push_event<S: Into<String>>(&mut self, line: S) {
        self.events.push_front(line.into());
        while self.events.len() > MAX_EVENT_LOG_ENTRIES {
            self.events.pop_back();
        }
    }
}

const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/udp/0/quic-v1";
const MAX_EVENT_LOG_ENTRIES: usize = 128;
const MAX_KNOWN_PEERS: usize = 64;
const MAX_DISCOVERED_SERVERS: usize = 128;

fn parse_multiaddr_list(input: &str) -> Result<Vec<Multiaddr>> {
    let mut out = Vec::new();
    for part in input
        .split(|c| matches!(c, ',' | ';' | '\n' | '\r'))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let addr: Multiaddr = part.parse().context(format!("invalid multiaddr: {part}"))?;
        out.push(addr);
    }
    Ok(out)
}

fn persist_known_peers(peers: &[Multiaddr]) -> Result<()> {
    if let Some(path) = peers_storage_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create peer cache directory at {}", parent.display()))?;
        }
        let serialized: Vec<String> = peers.iter().map(|addr| addr.to_string()).collect();
        let data = serde_json::to_vec(&serialized).context("serialize bootstrap peers")?;
        fs::write(&path, data)
            .with_context(|| format!("write bootstrap peers at {}", path.display()))?;
        info!(path = %path.display(), count = peers.len(), "persisted bootstrap peers");
    }
    Ok(())
}

fn load_cached_peers() -> Result<Vec<Multiaddr>> {
    let Some(path) = peers_storage_path() else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data =
        fs::read(&path).with_context(|| format!("read bootstrap peers at {}", path.display()))?;
    let encoded: Vec<String> = serde_json::from_slice(&data)
        .with_context(|| format!("deserialize bootstrap peers at {}", path.display()))?;

    let mut peers = Vec::new();
    for raw in encoded {
        match raw.parse::<Multiaddr>() {
            Ok(addr) => peers.push(addr),
            Err(err) => warn!(%raw, ?err, "skipping invalid cached peer"),
        }
    }

    if peers.len() > MAX_KNOWN_PEERS {
        peers.truncate(MAX_KNOWN_PEERS);
    }

    Ok(peers)
}

fn persist_overlay_settings(settings: &OverlaySettingsSnapshot) -> Result<()> {
    if let Some(path) = overlay_settings_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create overlay settings directory at {}", parent.display())
            })?;
        }

        let data = serde_json::to_vec(settings).context("serialize overlay settings")?;
        fs::write(&path, data)
            .with_context(|| format!("write overlay settings at {}", path.display()))?;
        info!(path = %path.display(), "persisted overlay settings");
    }
    Ok(())
}

fn load_overlay_settings() -> Result<Option<OverlaySettingsSnapshot>> {
    let Some(path) = overlay_settings_path() else {
        return Ok(None);
    };

    if !path.exists() {
        return Ok(None);
    }

    let data =
        fs::read(&path).with_context(|| format!("read overlay settings at {}", path.display()))?;
    let settings: OverlaySettingsSnapshot = serde_json::from_slice(&data)
        .with_context(|| format!("deserialize overlay settings at {}", path.display()))?;
    Ok(Some(settings))
}

fn persist_server_catalog(catalog: &BTreeMap<String, ServerAdvert>) -> Result<()> {
    if let Some(path) = server_catalog_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create server catalog directory at {}", parent.display())
            })?;
        }

        let serialized: Vec<PersistedAdvert> = catalog
            .iter()
            .map(|(server_id, advert)| PersistedAdvert {
                server_id: server_id.clone(),
                display_name: advert.display_name.clone(),
                bootstrap_addresses: advert.bootstrap_addresses.clone(),
                is_public: advert.is_public,
            })
            .collect();

        let data = serde_json::to_vec(&serialized).context("serialize server catalog")?;
        fs::write(&path, data)
            .with_context(|| format!("write server catalog at {}", path.display()))?;
        info!(path = %path.display(), count = catalog.len(), "persisted server catalog");
    }
    Ok(())
}

fn load_server_catalog() -> Result<Option<BTreeMap<String, ServerAdvert>>> {
    let Some(path) = server_catalog_path() else {
        return Ok(None);
    };

    if !path.exists() {
        return Ok(None);
    }

    let data =
        fs::read(&path).with_context(|| format!("read server catalog at {}", path.display()))?;
    let entries: Vec<PersistedAdvert> = serde_json::from_slice(&data)
        .with_context(|| format!("deserialize server catalog at {}", path.display()))?;

    let mut catalog = BTreeMap::new();
    for advert in entries {
        let server_id = advert.server_id.clone();
        let rebuilt = ServerAdvert {
            server_id: advert.server_id,
            display_name: advert.display_name,
            bootstrap_addresses: advert.bootstrap_addresses,
            is_public: advert.is_public,
        };
        catalog.insert(server_id, rebuilt);
    }

    Ok(Some(catalog))
}

fn persist_identity(identity: &UserIdentity) -> Result<()> {
    if let Some(path) = identity_storage_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create identity directory at {}", parent.display()))?;
        }
        let data = serde_json::to_vec(identity).context("serialize identity")?;
        fs::write(&path, data)
            .with_context(|| format!("write identity file at {}", path.display()))?;
        info!(path = %path.display(), "persisted identity");
    } else {
        warn!("unable to determine identity storage directory; identity will not persist");
    }
    Ok(())
}

fn load_identity_from_disk() -> Result<Option<UserIdentity>> {
    let Some(path) = identity_storage_path() else {
        warn!("no project directory available for identity storage");
        return Ok(None);
    };

    if !path.exists() {
        return Ok(None);
    }

    let data =
        fs::read(&path).with_context(|| format!("read identity file at {}", path.display()))?;
    let identity: UserIdentity = serde_json::from_slice(&data)
        .with_context(|| format!("deserialize identity file at {}", path.display()))?;
    Ok(Some(identity))
}

fn identity_storage_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.data_dir().join("identity.json"))
}

fn peers_storage_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.data_dir().join("bootstrap_peers.json"))
}

fn overlay_settings_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.data_dir().join("overlay_settings.json"))
}

fn server_catalog_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.data_dir().join("server_catalog.json"))
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "vinxis", "messaging")
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OverlaySettingsSnapshot {
    listen_multiaddr: String,
    bootstrap_peers: String,
    additional_advertise: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedAdvert {
    server_id: String,
    display_name: String,
    bootstrap_addresses: Vec<String>,
    is_public: bool,
}
