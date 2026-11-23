//! pt-compose — the pt crypto-infrastructure trio, composed.
//!
//! The three recovered crates were built for each other but never wired:
//!
//! - **pt-forged** produces `GateVerdict`s that "THE ORACLE consumes", and
//!   its provenance story is documentary — module headers asserting a forge
//!   chain and a PoUW ledger token. Nothing in the crate lets a consumer
//!   verify that a verdict is authentic, or detect one that was altered
//!   after the gate produced it.
//! - **pt-contracts**' VM trusts `ExecutionContext.kernel_signature_valid`,
//!   a bool the CALLER asserts. Its own design says the flag is sound only
//!   if the caller actually verified the kernel signature — but no caller
//!   existed in the recovered tree.
//! - **pt-keystore** is the estate's key custody: the natural signer for
//!   the first gap and the natural verifier for the second.
//!
//! This crate is that wiring. It changes none of the three crates' own
//! behaviour; it composes them:
//!
//! 1. `sign_verdict` / `verify_signed_verdict` — a gate verdict,
//!    canonically serialized, signed by a keystore role key. Verification
//!    re-checks the signature over the exact bytes and only then parses
//!    the verdict back out.
//! 2. `verified_context` — an `ExecutionContext` whose
//!    `kernel_signature_valid` is the outcome of a real Ed25519
//!    verification of the kernel signature against a keystore-held pubkey.
//!    The VM then executes exactly as designed — but the bool is earned.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pt_contracts::ExecutionContext;
use pt_forged::GateVerdict;
use pt_keystore::{KeyRole, Keystore};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("keystore: {0}")]
    Keystore(#[from] pt_keystore::KeystoreError),
    #[error("serde: {0}")]
    Serde(String),
    #[error("bad hex in signed artifact: {0}")]
    BadHex(String),
    #[error("bad key or signature encoding")]
    BadKeyMaterial,
    #[error("signature does not verify — artifact was altered or signed by another key")]
    SignatureInvalid,
}

/// A pt-forged gate verdict signed by a pt-keystore role key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVerdict {
    /// Canonical JSON of the `GateVerdict` — the exact bytes that were signed.
    pub verdict_json: String,
    /// Which keystore role signed it.
    pub signer_role: KeyRole,
    /// The signer's public key, hex.
    pub signer_pubkey: String,
    /// Ed25519 signature over `verdict_json` bytes, hex.
    pub signature: String,
}

/// Run nothing, change nothing: take a verdict the gate already produced
/// and sign it with a keystore key.
pub fn sign_verdict(
    ks: &Keystore,
    role: KeyRole,
    verdict: &GateVerdict,
) -> Result<SignedVerdict, ComposeError> {
    let verdict_json =
        serde_json::to_string(verdict).map_err(|e| ComposeError::Serde(e.to_string()))?;
    let sig = ks.sign(role, verdict_json.as_bytes())?;
    Ok(SignedVerdict {
        verdict_json,
        signer_role: role,
        signer_pubkey: hex::encode(ks.pubkey(role)?.to_bytes()),
        signature: hex::encode(sig.to_bytes()),
    })
}

/// Verify a signed verdict: the signature must check out against the
/// enclosed pubkey over the exact enclosed bytes; only then is the
/// verdict parsed and returned. A tampered verdict fails here, not at
/// some later consumer.
pub fn verify_signed_verdict(sv: &SignedVerdict) -> Result<GateVerdict, ComposeError> {
    let pk_bytes: [u8; 32] = hex::decode(&sv.signer_pubkey)
        .map_err(|e| ComposeError::BadHex(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| ComposeError::BadKeyMaterial)?;
    let sig_bytes: [u8; 64] = hex::decode(&sv.signature)
        .map_err(|e| ComposeError::BadHex(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| ComposeError::BadKeyMaterial)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| ComposeError::BadKeyMaterial)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(sv.verdict_json.as_bytes(), &sig)
        .map_err(|_| ComposeError::SignatureInvalid)?;
    serde_json::from_str(&sv.verdict_json).map_err(|e| ComposeError::Serde(e.to_string()))
}

/// Build an `ExecutionContext` for pt-contracts whose
/// `kernel_signature_valid` is EARNED: the kernel signature is verified
/// against the keystore pubkey for `role` over `kernel_msg`. If the
/// signature is wrong, the context honestly carries `false` and the VM
/// will refuse signature-gated scripts — the caller never gets to just
/// assert the flag.
pub fn verified_context(
    ks: &Keystore,
    role: KeyRole,
    kernel_msg: &[u8],
    kernel_sig: &[u8; 64],
    block_height: u64,
    block_timestamp: u64,
    confirmations: u64,
) -> Result<ExecutionContext, ComposeError> {
    let vk = ks.pubkey(role)?;
    let sig = Signature::from_bytes(kernel_sig);
    let valid = vk.verify(kernel_msg, &sig).is_ok();
    Ok(ExecutionContext {
        block_height,
        block_timestamp,
        caller: vk.to_bytes(),
        tx_fee: 0,
        kernel_signature_valid: valid,
        confirmations,
    })
}
