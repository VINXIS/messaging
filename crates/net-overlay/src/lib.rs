use anyhow::{Context, Result};
use identity_core::UserIdentity;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
    futures::StreamExt,
    identify,
    identity::{self, Keypair},
    kad::{self, PeerRecord, Quorum, Record, RecordKey, store::MemoryStore},
    swarm::{DialError, NetworkBehaviour, Swarm, SwarmEvent, dial_opts::DialOpts},
};
use messaging_proto::core::ServerAdvert;
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const IDENTIFY_PROTOCOL: &str = "/messaging-mvp/identify/0.1";
const DIRECTORY_PROTOCOL: &str = "/messaging-mvp/directory/0.1";
const DIRECTORY_NAMESPACE: &str = "messaging.directory";

/// Configuration for constructing an overlay node.
#[derive(Debug)]
pub struct OverlayConfig {
    pub identity: UserIdentity,
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
}

/// Commands accepted by the overlay behaviour.
#[derive(Debug)]
pub enum OverlayCommand {
    PublishServerAdvert(ServerAdvert),
    FindServerAdvert { server_id: String },
    DialAddress(Multiaddr),
}

/// Events surfaced to higher layers.
#[derive(Debug)]
pub enum OverlayEvent {
    ListeningOn(Multiaddr),
    BootstrapDialQueued(Multiaddr),
    ServerAdvertStored {
        server_id: String,
    },
    ServerAdvertFound {
        server_id: String,
        advert: ServerAdvert,
    },
    ServerAdvertNotFound {
        server_id: String,
    },
    PeerDiscovered(PeerId),
    SwarmError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let identity = UserIdentity::generate().expect("identity");
        let mut bytes = identity.to_ed25519_keypair_bytes();
        let ed = identity::ed25519::Keypair::try_from_bytes(&mut bytes).expect("ed25519");
        let _ = Keypair::from(ed);
    }
}

/// Handle returned to higher layers once the overlay task has been spawned.
pub struct OverlayNode {
    peer_id: PeerId,
    command_tx: mpsc::Sender<OverlayCommand>,
    pub event_rx: mpsc::Receiver<OverlayEvent>,
}

impl OverlayNode {
    /// Boots the libp2p swarm and spawns the networking task.
    pub async fn launch(config: OverlayConfig) -> Result<Self> {
        let OverlayConfig {
            identity,
            listen_addresses,
            bootstrap_peers,
        } = config;

        let mut keypair_bytes = identity.to_ed25519_keypair_bytes();
        let ed25519 = identity::ed25519::Keypair::try_from_bytes(&mut keypair_bytes)?;
        let keypair = Keypair::from(ed25519);
        let peer_id = PeerId::from(keypair.public());

        let mut swarm = build_swarm(keypair)?;

        for addr in &listen_addresses {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => info!(%addr, "listening requested"),
                Err(err) => warn!(?err, %addr, "failed to start listener"),
            }
        }

        let (command_tx, mut command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(64);

        for addr in &bootstrap_peers {
            let _ = event_tx
                .send(OverlayEvent::BootstrapDialQueued(addr.clone()))
                .await;
            if let Err(err) = swarm.dial(addr.clone()) {
                warn!(?err, %addr, "bootstrap dial failed");
            }
        }

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(cmd) = command_rx.recv() => {
                        if let Err(err) = handle_command(&mut swarm, cmd).await {
                            if event_tx.send(OverlayEvent::SwarmError(err)).await.is_err() {
                                break;
                            }
                        }
                    }
                    event = swarm.select_next_some() => {
                        if let Err(send_err) = handle_swarm_event(event, &event_tx).await {
                            warn!(?send_err, "overlay event channel closed");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            peer_id,
            command_tx,
            event_rx,
        })
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn command_sender(&self) -> mpsc::Sender<OverlayCommand> {
        self.command_tx.clone()
    }
}

fn build_swarm(keypair: Keypair) -> Result<Swarm<Behaviour>> {
    let builder = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic();

    let builder = builder
        .with_behaviour(|local_key| Ok(Behaviour::new(local_key)))
        .map_err(|err| anyhow::anyhow!("failed to attach behaviour: {err}"))?;

    let swarm = builder.build();
    Ok(swarm)
}

async fn handle_command(
    swarm: &mut Swarm<Behaviour>,
    command: OverlayCommand,
) -> Result<(), String> {
    match command {
        OverlayCommand::PublishServerAdvert(advert) => {
            publish_server_advert(swarm, advert).map_err(|err| err.to_string())?;
        }
        OverlayCommand::FindServerAdvert { server_id } => {
            let key = directory_record_key(&server_id);
            swarm.behaviour_mut().kademlia.get_record(key);
        }
        OverlayCommand::DialAddress(addr) => {
            let raw = addr.to_string();
            match swarm.dial(addr.clone()) {
                Ok(()) => {}
                Err(err) => match err {
                    DialError::NoAddresses => {
                        let dial = DialOpts::unknown_peer_id().address(addr).build();
                        swarm.dial(dial).map_err(|fallback_err| {
                            format!("failed to dial {raw}: {fallback_err}")
                        })?;
                    }
                    other => {
                        return Err(format!("failed to dial {raw}: {other}"));
                    }
                },
            }
        }
    }
    Ok(())
}

async fn handle_swarm_event(
    event: SwarmEvent<BehaviourEvent>,
    event_tx: &mpsc::Sender<OverlayEvent>,
) -> Result<(), mpsc::error::SendError<OverlayEvent>> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            event_tx.send(OverlayEvent::ListeningOn(address)).await?;
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            ..
        })) => {
            debug!(%peer_id, "identify exchange complete");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad_event)) => {
            handle_kad_event(kad_event, event_tx).await?;
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let msg = format!("outgoing connection error with {:?}: {error}", peer_id);
            event_tx.send(OverlayEvent::SwarmError(msg)).await?;
        }
        SwarmEvent::IncomingConnectionError {
            send_back_addr,
            error,
            ..
        } => {
            let msg = format!("incoming connection error from {send_back_addr}: {error}");
            event_tx.send(OverlayEvent::SwarmError(msg)).await?;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "connection closed");
        }
        _ => {}
    }
    Ok(())
}

async fn handle_kad_event(
    event: kad::Event,
    event_tx: &mpsc::Sender<OverlayEvent>,
) -> Result<(), mpsc::error::SendError<OverlayEvent>> {
    match event {
        kad::Event::RoutingUpdated { peer, .. } => {
            event_tx.send(OverlayEvent::PeerDiscovered(peer)).await?;
        }
        kad::Event::OutboundQueryProgressed { result, .. } => match result {
            kad::QueryResult::GetRecord(Ok(ok)) => match ok {
                kad::GetRecordOk::FoundRecord(PeerRecord { record, .. }) => {
                    if let Some(event) = advert_from_record(record) {
                        event_tx.send(event).await?;
                    }
                }
                kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {}
            },
            kad::QueryResult::GetRecord(Err(err)) => {
                let server_id = key_to_server_id(err.key());
                event_tx
                    .send(OverlayEvent::ServerAdvertNotFound { server_id })
                    .await?;
            }
            kad::QueryResult::PutRecord(Ok(ok)) => {
                let server_id = key_to_server_id(&ok.key);
                event_tx
                    .send(OverlayEvent::ServerAdvertStored { server_id })
                    .await?;
            }
            kad::QueryResult::PutRecord(Err(err)) => {
                let server_id = key_to_server_id(err.key());
                let msg = format!("failed to store advert for {server_id}: {err}");
                event_tx.send(OverlayEvent::SwarmError(msg)).await?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn publish_server_advert(swarm: &mut Swarm<Behaviour>, advert: ServerAdvert) -> Result<()> {
    let server_id = advert.server_id.clone();
    let mut payload = Vec::new();
    advert
        .encode(&mut payload)
        .context("failed to encode server advert")?;

    let record = Record {
        key: directory_record_key(&server_id),
        value: payload,
        publisher: Some(*swarm.local_peer_id()),
        expires: None,
    };

    swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, Quorum::One)
        .map_err(|err| anyhow::anyhow!("kad put failed: {err}"))?;
    Ok(())
}

fn advert_from_record(record: Record) -> Option<OverlayEvent> {
    match ServerAdvert::decode(&*record.value) {
        Ok(advert) => Some(OverlayEvent::ServerAdvertFound {
            server_id: advert.server_id.clone(),
            advert,
        }),
        Err(err) => {
            warn!(?err, "failed to decode server advert from record");
            None
        }
    }
}

fn directory_record_key(server_id: &str) -> RecordKey {
    let key = format!("{DIRECTORY_NAMESPACE}:{server_id}");
    RecordKey::new(&key)
}

fn key_to_server_id(key: &RecordKey) -> String {
    let raw = String::from_utf8_lossy(key.as_ref());
    raw.split_once(':')
        .map(|(_, tail)| tail.to_string())
        .unwrap_or_else(|| raw.into())
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
}

impl Behaviour {
    fn new(local_key: &Keypair) -> Self {
        let peer_id = PeerId::from(local_key.public());
        let store = MemoryStore::new(peer_id);

        let protocol = StreamProtocol::new(DIRECTORY_PROTOCOL);
        let mut kad_config = kad::Config::new(protocol);
        kad_config.set_publication_interval(None);

        let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
        kademlia.set_mode(Some(kad::Mode::Server));

        let identify = identify::Behaviour::new(identify::Config::new(
            IDENTIFY_PROTOCOL.into(),
            local_key.public().clone(),
        ));

        Self { kademlia, identify }
    }
}
