use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Represents the core identity for a user in the distributed overlay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserIdentity {
    signing_key: [u8; 32],
    verifying_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("verification failed")]
    VerificationFailed,
}

impl UserIdentity {
    /// Generates a fresh identity backed by an Ed25519 keypair.
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key: signing_key.to_bytes(),
            verifying_key: verifying_key.to_bytes(),
        })
    }

    /// Returns the public verifying key in hex form for display.
    pub fn format_public_key(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    /// Signs arbitrary payload, typically to prove authorship of protocol messages.
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signing_key().sign(payload).to_vec()
    }

    /// Access to read-only verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.verifying_key).expect("verifying key bytes are valid")
    }

    /// Checks a payload/signature pair against the verifying key.
    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| IdentityError::VerificationFailed)?;
        self.verifying_key()
            .verify_strict(payload, &sig)
            .map_err(|_| IdentityError::VerificationFailed)?;
        Ok(())
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_key)
    }

    /// Returns the concatenated secret+public bytes used by libp2p.
    pub fn to_ed25519_keypair_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let secret = self.signing_key;
        let public = self.verifying_key;
        bytes[..32].copy_from_slice(&secret);
        bytes[32..].copy_from_slice(&public);
        bytes
    }
}
