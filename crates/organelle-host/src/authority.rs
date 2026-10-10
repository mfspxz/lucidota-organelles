//! Unforgeable authority at the transport boundary (P0 hardening).
//!
//! Before this module, every external surface (unix socket, MCP stdio, REST)
//! built a [`crate::CallContext`] straight from caller-supplied `caller` +
//! `capabilities` fields, and the host's `authorize()` trusted them. Any
//! peer that could reach a surface could claim any capability — authority
//! was forgeable at the transport boundary.
//!
//! Now: the host is the sole issuer and verifier of **capability grants**.
//! A grant is an HMAC-SHA256-authenticated token (RFC 2104 construction over
//! the SHA-256 primitive, via the `hmac` crate — no hand-rolled crypto)
//! binding a caller identity to a capability set, with an expiry and,
//! optionally, single-use semantics for replay protection. External surfaces
//! authenticate callers by presenting a grant; the host derives the
//! `CallContext` **only** from the verified grant. Caller-supplied
//! capability claims are never read.
//!
//! Fail-closed properties:
//! - no grant, malformed grant, bad signature, expired grant -> denial.
//! - a grant presented under a different caller identity -> denial.
//! - a single-use grant presented twice -> denial (replay cache in the host).
//! - the grant key is 256 bits from the OS CSPRNG, generated per `Host`;
//!   grants do not survive host restarts, and a host that cannot obtain
//!   randomness refuses to exist rather than minting forgeable grants.

use hmac::{Hmac, Mac};
use organelle_manifest::{canonical_json, unix_now};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::Read;

/// Token wire format version.
const GRANT_VERSION: u32 = 1;

/// HMAC-SHA256 over the hex transport form of the grant payload.
type GrantMac = Hmac<Sha256>;

/// The signed body of a grant. Serialized with `canonical_json` so the
/// signed bytes are deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantPayload {
    v: u32,
    /// Caller identity this grant was issued to.
    sub: String,
    /// The ONLY capabilities this grant confers. Derived from, never added to.
    caps: Vec<String>,
    /// Issued-at / expires-at, unix epoch seconds.
    iat: u64,
    exp: u64,
    /// Unique grant id (hex); replay-tracked when `single_use`.
    jti: String,
    /// When true, the grant is accepted exactly once.
    single_use: bool,
}

/// What a verified grant confers on the presenter.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    pub caller: String,
    pub capabilities: Vec<String>,
}

/// Why a grant was refused. Never carries the grant value itself
/// (secret-freeze: no credential material in errors, logs, or receipts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantErrorKind {
    Malformed,
    InvalidSignature,
    Expired,
    Replayed,
}

#[derive(Debug, Clone)]
pub struct GrantError {
    pub kind: GrantErrorKind,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.kind {
            GrantErrorKind::Malformed => "malformed grant",
            GrantErrorKind::InvalidSignature => "grant signature invalid",
            GrantErrorKind::Expired => "grant expired",
            GrantErrorKind::Replayed => "grant already used (replay)",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for GrantError {}

/// Per-host grant state: the HMAC key and the single-use replay cache
/// (`jti` -> `exp`; expired entries are pruned on every verification).
pub struct GrantAuthority {
    key: [u8; 32],
    used: HashMap<String, u64>,
}

fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

impl GrantAuthority {
    /// Create with an explicit 256-bit key (operator-provided, e.g. from a
    /// secrets manager or env). The operator owns key distribution and
    /// rotation; grants minted under a stable key survive host restarts.
    pub fn with_key(key: [u8; 32]) -> Self {
        GrantAuthority { key, used: HashMap::new() }
    }

    /// Create with a fresh 256-bit key from the OS CSPRNG. Fail-closed: if
    /// randomness is unavailable the host must not exist, because every
    /// grant it minted would be forgeable.
    pub fn new() -> Self {
        let bytes = random_bytes(32).expect(
            "grant authority: /dev/urandom unavailable — refusing to run \
             without unforgeable grant keys",
        );
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        GrantAuthority { key, used: HashMap::new() }
    }

    fn sign(&self, payload_hex: &str) -> String {
        let mut mac = GrantMac::new_from_slice(&self.key)
            .expect("HMAC accepts any key length");
        mac.update(payload_hex.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn mint(&self, sub: &str, caps: Vec<String>, ttl_secs: u64, single_use: bool) -> String {
        let now = unix_now();
        let jti = hex::encode(random_bytes(16).expect("grant jti: /dev/urandom unavailable"));
        let payload = GrantPayload {
            v: GRANT_VERSION,
            sub: sub.to_string(),
            caps,
            iat: now,
            exp: now.saturating_add(ttl_secs),
            jti,
            single_use,
        };
        let payload_hex = hex::encode(canonical_json(&serde_json::to_value(&payload).unwrap()));
        let tag = self.sign(&payload_hex);
        format!("{payload_hex}.{tag}")
    }

    /// Issue a multi-use grant: valid for `ttl_secs`, usable for any number
    /// of calls within that window.
    pub fn issue(&self, sub: &str, caps: Vec<String>, ttl_secs: u64) -> String {
        self.mint(sub, caps, ttl_secs, false)
    }

    /// Issue a single-use grant: the first presentation is honored, any
    /// replay is denied. For high-risk or exactly-once flows.
    pub fn issue_single_use(&self, sub: &str, caps: Vec<String>, ttl_secs: u64) -> String {
        self.mint(sub, caps, ttl_secs, true)
    }

    /// Verify a grant token. On success returns what the presenter is
    /// authorized as — caller identity and capabilities derived ONLY from
    /// the trusted grant.
    pub fn verify(&mut self, token: &str) -> Result<VerifiedGrant, GrantError> {
        let malformed = || GrantError { kind: GrantErrorKind::Malformed };
        let (payload_hex, tag_hex) = token.split_once('.').ok_or_else(malformed)?;
        if payload_hex.is_empty() || tag_hex.is_empty() {
            return Err(malformed());
        }
        // Constant-time signature check (hmac's verify_slice).
        let mut mac = GrantMac::new_from_slice(&self.key)
            .expect("HMAC accepts any key length");
        mac.update(payload_hex.as_bytes());
        let tag = hex::decode(tag_hex).map_err(|_| malformed())?;
        mac.verify_slice(&tag)
            .map_err(|_| GrantError { kind: GrantErrorKind::InvalidSignature })?;

        let payload_bytes = hex::decode(payload_hex).map_err(|_| malformed())?;
        let payload: GrantPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| malformed())?;
        if payload.v != GRANT_VERSION {
            return Err(malformed());
        }
        if payload.sub.is_empty() {
            return Err(malformed());
        }
        let now = unix_now();
        if payload.exp <= now {
            return Err(GrantError { kind: GrantErrorKind::Expired });
        }

        if payload.single_use {
            // Prune expired entries so the cache stays bounded.
            self.used.retain(|_, exp| *exp > now);
            if self.used.contains_key(&payload.jti) {
                return Err(GrantError { kind: GrantErrorKind::Replayed });
            }
            self.used.insert(payload.jti.clone(), payload.exp);
        }

        Ok(VerifiedGrant { caller: payload.sub, capabilities: payload.caps })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_multi_use() {
        let mut a = GrantAuthority::new();
        let g = a.issue("alice", vec!["kv.write".to_string()], 300);
        let v = a.verify(&g).unwrap();
        assert_eq!(v.caller, "alice");
        assert_eq!(v.capabilities, vec!["kv.write".to_string()]);
        // Multi-use: second presentation is fine.
        assert!(a.verify(&g).is_ok());
    }

    #[test]
    fn tampered_payload_denied() {
        let mut a = GrantAuthority::new();
        let g = a.issue("alice", vec!["kv.read".to_string()], 300);
        let (payload_hex, tag) = g.split_once('.').unwrap();
        let mut bytes = hex::decode(payload_hex).unwrap();
        // Flip a byte inside the payload; signature must not verify.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let forged = format!("{}.{}", hex::encode(&bytes), tag);
        let e = a.verify(&forged).unwrap_err();
        assert_eq!(e.kind, GrantErrorKind::InvalidSignature);
    }

    #[test]
    fn escalated_caps_require_resigning() {
        // Attacker takes a valid low-privilege grant and rewrites caps.
        let mut a = GrantAuthority::new();
        let g = a.issue("alice", vec!["kv.read".to_string()], 300);
        let (payload_hex, tag) = g.split_once('.').unwrap();
        let mut payload: GrantPayload =
            serde_json::from_slice(&hex::decode(payload_hex).unwrap()).unwrap();
        payload.caps = vec!["kv.write".to_string(), "admin.*".to_string()];
        let forged = format!(
            "{}.{}",
            hex::encode(canonical_json(&serde_json::to_value(&payload).unwrap())),
            tag
        );
        let e = a.verify(&forged).unwrap_err();
        assert_eq!(e.kind, GrantErrorKind::InvalidSignature);
    }

    #[test]
    fn garbage_denied_as_malformed() {
        let mut a = GrantAuthority::new();
        for bad in ["", "no-dot-here", ".", "zz.zz", "a.b.c"] {
            assert_eq!(
                a.verify(bad).unwrap_err().kind,
                GrantErrorKind::Malformed,
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn expired_denied() {
        let mut a = GrantAuthority::new();
        let g = a.issue("alice", vec![], 0); // exp == now -> expired
        // exp <= now is expired even at the same second.
        assert_eq!(a.verify(&g).unwrap_err().kind, GrantErrorKind::Expired);
    }

    #[test]
    fn single_use_replay_denied() {
        let mut a = GrantAuthority::new();
        let g = a.issue_single_use("alice", vec!["kv.write".to_string()], 300);
        assert!(a.verify(&g).is_ok());
        let e = a.verify(&g).unwrap_err();
        assert_eq!(e.kind, GrantErrorKind::Replayed);
    }

    #[test]
    fn cross_host_grant_denied() {
        // A grant minted by another host (different key) is forgeable
        // nowhere: it must fail signature verification here.
        let a = GrantAuthority::new();
        let mut b = GrantAuthority::new();
        let g = a.issue("alice", vec!["kv.write".to_string()], 300);
        assert_eq!(
            b.verify(&g).unwrap_err().kind,
            GrantErrorKind::InvalidSignature
        );
    }
}
