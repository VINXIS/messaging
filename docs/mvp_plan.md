# Messaging MVP Architecture Plan

## Goals
- Deliver a desktop-only proof of concept that demonstrates distributed persistent text chat with support for private and public servers.
- Operate without a global authority while allowing server creators to choose their own bootstrap peers.
- Establish foundations for future features such as moderation, voice/video, and mobile clients.

## Core Components
1. **identity-core**
   - Generates and manages Ed25519 key material for users.
   - Provides signing/verification helpers for protocol messages.

2. **messaging-proto**
   - Houses Protocol Buffer definitions for control-plane (server adverts) and data-plane (channel message) payloads.
   - Supplies generated Rust types via `prost` for use across crates.

3. **net-overlay**
   - Wraps `libp2p` QUIC transport, Kademlia DHT, and gossipsub (future step).
   - Exposes an async API for launching nodes, publishing server adverts, and reacting to overlay events.
   - Keeps the network peer-run by letting server owners host or nominate bootstrap peers; public server adverts are pushed into the shared DHT.

4. **storage-ledger**
   - Uses `sled` to persist encrypted channel ciphertext chunks and metadata.
   - Handles append-only writes and replay for message history.

5. **desktop app**
   - Built with `eframe`/`egui` for rapid native UI iteration.
   - Manages local identity creation, server discovery, channel messaging, and diagnostics.

## Networking & Discovery
- Public servers publish signed adverts (server id, display name, bootstrap multiaddresses, visibility flag) into the libp2p Kademlia DHT namespace.
- Private servers share bootstrap multiaddresses via out-of-band invites (not yet implemented in MVP skeleton).
- To avoid dominance by long-lived nodes, operators can rotate bootstrap peers; clients will treat adverts as advisory and fall back to cached peer sets when possible.

## Storage & Replication
- Each channel maintains an append-only log segmented into ciphertext chunks.
- Chunks are stored LOCALLY in sled and replicated opportunistically to a configurable number of peers (replication logic forthcoming).
- Long-term retention defaults to indefinite; auto-delete policies will be layered on by pruning stored chunks once policy checks are in place.

## Roadmap
1. Flesh out protocol schemas (membership events, invites, channel operations).
2. Expand `net-overlay` to wire gossipsub for real-time chat traffic and to back server advert publication.
3. Implement invite flow and server membership state tracking.
4. Integrate storage ledger with networking so incoming messages are decrypted (once key exchange implemented) and persisted.
5. Build desktop UI flows for server list, channel view, and diagnostics.
6. Add integration tests and simulation harness for churn/resilience verification.

This document will evolve as features land; each milestone should update the plan with implementation details and testing notes.
