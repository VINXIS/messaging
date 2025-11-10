use anyhow::{Result, bail};
use eframe::egui;
use identity_core::UserIdentity;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    ensure_display_env()?;
    info!("starting messaging desktop MVP shell");

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Messaging MVP",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
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

#[derive(Default)]
struct App {
    identity: Option<UserIdentity>,
    identity_display: String,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Messaging MVP");

            if self.identity.is_none() {
                if ui.button("Generate identity").clicked() {
                    match UserIdentity::generate() {
                        Ok(id) => {
                            self.identity_display = id.format_public_key();
                            self.identity = Some(id);
                        }
                        Err(err) => {
                            tracing::error!(?err, "failed to generate identity");
                        }
                    }
                }
            }

            if !self.identity_display.is_empty() {
                ui.label(format!("Public key: {}", self.identity_display));
            }

            ui.separator();
            ui.label("Networking and storage wiring will land in subsequent iterations.");
        });
    }
}
