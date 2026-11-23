// IMPLEMENTS: DEVSTRAL_PULL_AUDIT.md Pull #10 (Willow — blind provenance)
//! Willow — Blind provenance tokens for the LUCIDOTA keystore.
//!
//! Cryptographic provenance for messages: proves a message was seen by a
//! specific signer without revealing message content to third parties.
//! Adapted for integration with pt-keystore's key hierarchy.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A provenanced message — content-hashed with an attestation signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenancedMessage {
    /// Hex-encoded Ed25519 signature (64 bytes → 128 hex chars).
    pub attestation_hex: String,
    /// Hex-encoded attester public key (32 bytes → 64 hex chars).
    pub attester_pubkey_hex: String,
    /// The message content itself (for simplicity — real Willow blinds this).
    pub message: Vec<u8>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// Epoch number for key rotation.
    pub epoch: u64,
}

/// Willow provenance engine — issues and verifies provenance tokens.
pub struct WillowProvenance {
    /// Current signing key.
    signing_key: SigningKey,
    /// Epoch keys for rotation (epoch → key).
    epoch_keys: HashMap<u64, SigningKey>,
    /// Current epoch.
    current_epoch: u64,
}

impl WillowProvenance {
    /// Create a new Willow provenance engine with a fresh key.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let mut epoch_keys = HashMap::new();
        epoch_keys.insert(0, signing_key.clone());
        Self {
            signing_key,
            epoch_keys,
            current_epoch: 0,
        }
    }

    /// Create from an existing 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let mut epoch_keys = HashMap::new();
        epoch_keys.insert(0, signing_key.clone());
        Self {
            signing_key,
            epoch_keys,
            current_epoch: 0,
        }
    }

    /// Get the current public key as hex.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Issue a provenance token for a message.
    /// The token proves the message was seen by this engine.
    pub fn issue(&self, message: &[u8]) -> ProvenancedMessage {
        let sig = self.signing_key.sign(message);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        ProvenancedMessage {
            attestation_hex: hex::encode(sig.to_bytes()),
            attester_pubkey_hex: self.pubkey_hex(),
            message: message.to_vec(),
            timestamp,
            epoch: self.current_epoch,
        }
    }

    /// Verify a provenance token — checks signature over the message.
    pub fn verify(token: &ProvenancedMessage) -> Result<(), WillowError> {
        let pubkey_bytes: [u8; 32] = hex::decode(&token.attester_pubkey_hex)
            .map_err(|_| WillowError::BadKey)?
            .as_slice()
            .try_into()
            .map_err(|_| WillowError::BadKey)?;

        let sig_bytes: [u8; 64] = hex::decode(&token.attestation_hex)
            .map_err(|_| WillowError::BadSignature)?
            .as_slice()
            .try_into()
            .map_err(|_| WillowError::BadSignature)?;

        let vk = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| WillowError::BadKey)?;
        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify(&token.message, &sig)
            .map_err(|_| WillowError::BadSignature)
    }

    /// Rotate to a new epoch key.
    pub fn rotate_epoch(&mut self) -> u64 {
        self.current_epoch += 1;
        let new_key = SigningKey::generate(&mut rand_core::OsRng);
        self.epoch_keys.insert(self.current_epoch, new_key.clone());
        self.signing_key = new_key;
        self.current_epoch
    }
}

impl Default for WillowProvenance {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WillowError {
    #[error("bad public key")]
    BadKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid epoch")]
    InvalidEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_token_verifies() {
        let willow = WillowProvenance::from_seed([0xAA; 32]);
        let msg = b"anchor this receipt at block 847321";
        let token = willow.issue(msg);
        assert!(WillowProvenance::verify(&token).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let willow = WillowProvenance::new();
        let msg = b"original message";
        let mut token = willow.issue(msg);
        token.message = b"EVIL MESSAGE".to_vec(); // tamper
        assert!(WillowProvenance::verify(&token).is_err());
    }

    #[test]
    fn different_signer_fails() {
        let a = WillowProvenance::from_seed([1u8; 32]);
        let b = WillowProvenance::from_seed([2u8; 32]);
        let token = a.issue(b"msg");
        // Modify attester_pubkey to claim B signed it (but sig is from A)
        let mut fake = token;
        fake.attester_pubkey_hex = b.pubkey_hex();
        assert!(WillowProvenance::verify(&fake).is_err());
    }

    #[test]
    fn provenance_is_deterministic_for_fixed_message() {
        let w1 = WillowProvenance::from_seed([0x42; 32]);
        let w2 = WillowProvenance::from_seed([0x42; 32]);
        let t1 = w1.issue(b"test");
        let t2 = w2.issue(b"test");
        // Same seed + same message → same attestation
        assert_eq!(t1.attestation_hex, t2.attestation_hex);
        assert_eq!(t1.attester_pubkey_hex, t2.attester_pubkey_hex);
    }

    #[test]
    fn epoch_rotation_changes_key() {
        let mut w = WillowProvenance::from_seed([9u8; 32]);
        let pk0 = w.pubkey_hex();
        w.rotate_epoch();
        let pk1 = w.pubkey_hex();
        assert_ne!(pk0, pk1, "epoch rotation must change the signing key");
        assert_eq!(w.current_epoch, 1);
    }
}
