use std::path::Path;

use anyhow::Result;
use sled::Db;
use thiserror::Error;
use tracing::info;

/// Encapsulates the sled-backed persistence layer for channel logs.
pub struct Ledger {
    db: Db,
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("channel not found: {0}")]
    ChannelMissing(String),
}

impl Ledger {
    /// Opens or initializes the ledger at the supplied path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Persists an opaque ciphertext chunk for a channel.
    pub fn append_ciphertext(&self, channel_id: &str, payload: &[u8]) -> Result<()> {
        let tree = self.db.open_tree(channel_id)?;
        let next_index = tree.len().to_be_bytes();
        tree.insert(next_index, payload)?;
        tree.flush()?;
        info!(channel_id, "appended ciphertext chunk");
        Ok(())
    }

    /// Replays all ciphertext chunks for a channel in insertion order.
    pub fn load_ciphertexts(&self, channel_id: &str) -> Result<Vec<Vec<u8>>> {
        let tree = self
            .db
            .open_tree(channel_id)
            .map_err(|_| LedgerError::ChannelMissing(channel_id.to_owned()))?;
        let mut messages = Vec::with_capacity(tree.len() as usize);
        for result in tree.iter() {
            let (_, value) = result?;
            messages.push(value.to_vec());
        }
        Ok(messages)
    }
}
