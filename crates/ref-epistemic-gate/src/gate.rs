//! pt-oracle gate — Verification gate organelle.
//! Promotes Candidate→Proven through receipt-based rule evaluation.

use std::collections::HashMap;

/// Re-exported from GO-50 ontology — the canonical ternary valence type.
pub use ref_ontology_terms::TernaryValence as Valence;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OracleReceipt {
    pub ts: u64, pub artifact_hash: [u8; 32], pub agent: String,
    pub verdict: Valence, pub evidence_hashes: Vec<[u8; 32]>,
    pub findings: Vec<String>, pub absurd_tag: String,
    /// Ed25519 signature by the issuing gate over `receipt_signing_payload`.
    /// `None` = unsigned: never counted by `promote`. Ported 2026-11-23
    /// from pt-oracle commit 1e22c3f (signed-receipts treatment);
    /// `#[serde(default)]` keeps pre-fix serialized receipts readable —
    /// they verify as unsigned and are rejected by the quorum, which is
    /// the point.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
}

/// Canonical bytes the gate signs. Domain-separated, length-prefixed,
/// field-order fixed — any change to a signed field changes the payload.
pub fn receipt_signing_payload(r: &OracleReceipt) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"pt-oracle/gate-receipt/v1\0");
    p.extend_from_slice(&r.ts.to_le_bytes());
    p.extend_from_slice(&r.artifact_hash);
    p.extend_from_slice(&(r.agent.len() as u64).to_le_bytes());
    p.extend_from_slice(r.agent.as_bytes());
    p.extend_from_slice(&r.verdict.as_int().to_le_bytes());
    p.extend_from_slice(&(r.evidence_hashes.len() as u64).to_le_bytes());
    for h in &r.evidence_hashes { p.extend_from_slice(h); }
    p.extend_from_slice(&(r.findings.len() as u64).to_le_bytes());
    for f in &r.findings {
        p.extend_from_slice(&(f.len() as u64).to_le_bytes());
        p.extend_from_slice(f.as_bytes());
    }
    p.extend_from_slice(&(r.absurd_tag.len() as u64).to_le_bytes());
    p.extend_from_slice(r.absurd_tag.as_bytes());
    p
}

/// Third-party verification: does `receipt` carry a valid signature from
/// the gate whose public key is `gate_public_key`? Anyone holding the
/// gate's public key can check a receipt without trusting the bearer.
pub fn verify_receipt_signature(receipt: &OracleReceipt, gate_public_key: &[u8; 32]) -> bool {
    use ed25519_dalek::Verifier;
    let Some(sig) = &receipt.signature else { return false };
    let Ok(sig): Result<[u8; 64], _> = sig.as_slice().try_into() else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(gate_public_key) else { return false };
    vk.verify(&receipt_signing_payload(receipt), &ed25519_dalek::Signature::from_bytes(&sig)).is_ok()
}

pub trait VerificationGate {
    type Error: std::fmt::Debug;
    fn verify(&mut self, hash: &[u8;32], agent: &str, claim: &[u8], evidence: &[OracleReceipt]) -> Result<OracleReceipt, Self::Error>;
    fn promote(&mut self, hash: &[u8;32], receipts: &[OracleReceipt], quorum: usize) -> Result<Valence, Self::Error>;
    fn demote(&mut self, hash: &[u8;32], refutation: &[u8]) -> Result<Valence, Self::Error>;
}

pub struct VerificationResult { pub rule_name: String, pub passed: bool, pub confidence: f32, pub detail: String }

pub struct RuleEngine { rules: HashMap<String, Box<dyn Fn(&[u8], &[OracleReceipt]) -> VerificationResult>> }

impl RuleEngine {
    pub fn new() -> Self { Self { rules: HashMap::new() } }
    pub fn register<F: Fn(&[u8], &[OracleReceipt]) -> VerificationResult + 'static>(&mut self, name: &str, rule: F) {
        self.rules.insert(name.to_string(), Box::new(rule));
    }
    pub fn evaluate(&self, claim: &[u8], evidence: &[OracleReceipt]) -> (Valence, Vec<VerificationResult>) {
        let results: Vec<_> = self.rules.values().map(|r| r(claim, evidence)).collect();
        if results.is_empty() { return (Valence::Candidate, results); }
        let passed = results.iter().filter(|r| r.passed).count();
        let ratio = passed as f32 / results.len() as f32;
        (if ratio >= 0.67 { Valence::Proven } else if ratio <= 0.33 { Valence::Tainted } else { Valence::Candidate }, results)
    }
}

impl Default for RuleEngine { fn default() -> Self { Self::new() } }

pub fn rule_non_empty(claim: &[u8], _: &[OracleReceipt]) -> VerificationResult {
    VerificationResult { rule_name: "non_empty".into(), passed: !claim.is_empty(), confidence: if claim.is_empty() { 1.0 } else { 0.99 }, detail: if claim.is_empty() { "empty rejected".into() } else { "non-empty".into() } }
}

pub struct Oracle { engine: RuleEngine, receipts: Vec<OracleReceipt>, signing_key: ed25519_dalek::SigningKey }

impl Oracle {
    pub fn new() -> Self { Self::with_signing_key(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)) }
    pub fn with_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        let mut e = RuleEngine::new(); e.register("non_empty", rule_non_empty);
        Self { engine: e, receipts: vec![], signing_key }
    }
    /// The gate's public key — publish this so third parties can verify
    /// receipts with `verify_receipt_signature`.
    pub fn public_key(&self) -> [u8; 32] { self.signing_key.verifying_key().to_bytes() }
}

impl VerificationGate for Oracle {
    type Error = OracleError;
    fn verify(&mut self, hash: &[u8;32], agent: &str, claim: &[u8], evidence: &[OracleReceipt]) -> Result<OracleReceipt, OracleError> {
        let (verdict, results) = self.engine.evaluate(claim, evidence);
        let findings: Vec<_> = results.iter().map(|r| format!("[{}] pass={} conf={:.2}: {}", r.rule_name, r.passed, r.confidence, r.detail)).collect();
        let mut receipt = OracleReceipt {
            ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            artifact_hash: *hash, agent: agent.to_string(), verdict, evidence_hashes: evidence.iter().map(|r| r.artifact_hash).collect(),
            findings, absurd_tag: format!("oracle:v1:{}", verdict.as_int()),
            signature: None,
        };
        // The gate signs every receipt it issues. A receipt without this
        // signature did not come from the gate, whatever its fields claim.
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(&receipt_signing_payload(&receipt));
        receipt.signature = Some(sig.to_bytes().to_vec());
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }
    fn promote(&mut self, hash: &[u8;32], receipts: &[OracleReceipt], quorum: usize) -> Result<Valence, OracleError> {
        // Only receipts this gate actually signed count toward the quorum.
        // Unsigned, forged, tampered, or foreign-gate receipts are rejected
        // (not counted) — before the fix, any hand-built struct counted.
        let pk = self.public_key();
        let count = receipts.iter().filter(|r| r.artifact_hash == *hash && r.verdict == Valence::Proven && verify_receipt_signature(r, &pk)).count();
        Ok(if count >= quorum { Valence::Proven } else { Valence::Candidate })
    }
    fn demote(&mut self, _hash: &[u8;32], refutation: &[u8]) -> Result<Valence, OracleError> {
        if refutation.is_empty() { return Err(OracleError::InvalidRefutation); }
        Ok(Valence::Tainted)
    }
}

impl Default for Oracle { fn default() -> Self { Self::new() } }

#[derive(Debug)] pub enum OracleError { InvalidRefutation, InsufficientEvidence, StoreError(String) }
impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::InvalidRefutation => write!(f, "invalid refutation"), Self::InsufficientEvidence => write!(f, "insufficient evidence"), Self::StoreError(m) => write!(f, "store: {m}") }
    }
}
impl std::error::Error for OracleError {}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn empty_tainted() { let mut o = Oracle::new(); assert_eq!(o.verify(&[0;32],"t",b"",&[]).unwrap().verdict, Valence::Tainted); }
    #[test] fn nonempty_proven() { let mut o = Oracle::new(); assert_eq!(o.verify(&[1;32],"t",b"x",&[]).unwrap().verdict, Valence::Proven); }
    // NOTE (signed-receipts port, 2026-11-23): this test originally built
    // OracleReceipt structs by hand and expected them to promote — it encoded
    // the forgery defect itself. It now mints receipts through the gate
    // (verify) and keeps the same quorum assertions.
    #[test] fn quorum() { let mut o = Oracle::new(); let r: Vec<_> = (0..5).map(|i| o.verify(&[9;32],&format!("a{i}"),b"claim",&[]).unwrap()).collect(); assert_eq!(o.promote(&[9;32],&r,3).unwrap(),Valence::Proven); assert_eq!(o.promote(&[9;32],&r,6).unwrap(),Valence::Candidate); }
}
