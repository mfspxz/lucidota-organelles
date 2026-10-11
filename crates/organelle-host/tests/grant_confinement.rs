//! P1 lane 3 — capability grants cannot escape their intended domains.
//!
//! Two confinement mechanisms, both fail-closed with receipts:
//! 1. **Audience binding**: `issue_scoped_grant` binds the grant to ONE
//!    organelle codon; presenting it to any other codon is denied.
//! 2. **Nested-call domain confinement**: an invocation authorized by a
//!    grant confines every nested (organelle->organelle) call beneath it to
//!    the intersection of the calling organelle's manifest grants and the
//!    grant's capability domain — transitively. A grant for capability X
//!    cannot be escalated to capability Y through a nested call.
//!
//! Invocations that did not arrive under a grant (native surface) keep the
//! org-011 membrane identity model: the organelle's manifest grants govern.

use organelle_host::{CallContext, CallVerdict, Host, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn manifest(codon: &str, op: &str, required_cap: &str, granted: Vec<String>) -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: format!("test-{codon}"),
        codon: codon.to_string(),
        version: "1.0.0".to_string(),
        description: "grant-confinement test organelle".to_string(),
        contracts: vec![Contract {
            op: op.to_string(),
            description: "test op".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            mutation_class: None,
            required_capability: Some(required_cap.to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: granted,
        },
        transports: vec![Transport::Native],
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

struct Echo {
    manifest: OrganelleManifest,
}

impl Organelle for Echo {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }
    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        assert_eq!(op, "ping");
        Ok(serde_json::json!({"echo": input}))
    }
}

/// Organelle that relays to another organelle through the host, threading
/// the outer invocation's trace id (honest organelle, per the P1 contract).
struct Proxy {
    manifest: OrganelleManifest,
    op: String,
    target_codon: String,
    target_op: String,
    hits: Arc<AtomicUsize>,
}

impl Organelle for Proxy {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }
    fn handle(
        &self,
        ctx: &CallContext,
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        assert_eq!(op, self.op);
        self.hits.fetch_add(1, Ordering::SeqCst);
        // Propagate the nested error unchanged: the outer failure reason
        // must name the boundary denial (grant-confined) verbatim.
        host.call_organelle(
            &self.manifest.codon,
            &ctx.trace_id,
            &self.target_codon,
            &self.target_op,
            input,
        )
    }
}

struct Sink {
    manifest: OrganelleManifest,
    hits: Arc<AtomicUsize>,
}

impl Organelle for Sink {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }
    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        assert_eq!(op, "use");
        self.hits.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"sunk": true}))
    }
}

fn proxy(
    codon: &str,
    op: &str,
    required_cap: &str,
    granted: &[&str],
    target_codon: &str,
    target_op: &str,
    hits: Arc<AtomicUsize>,
) -> Proxy {
    Proxy {
        manifest: manifest(
            codon,
            op,
            required_cap,
            granted.iter().map(|s| s.to_string()).collect(),
        ),
        op: op.to_string(),
        target_codon: target_codon.to_string(),
        target_op: target_op.to_string(),
        hits,
    }
}

// -- audience binding -----------------------------------------------------

#[test]
fn scoped_grant_cross_organelle_reuse_denied() {
    let h = Host::new();
    h.register(Arc::new(Echo { manifest: manifest("aa", "ping", "ping.use", vec![]) }))
        .unwrap();
    h.register(Arc::new(Echo { manifest: manifest("bb", "ping", "ping.use", vec![]) }))
        .unwrap();
    let grant = h.issue_scoped_grant("alice", "aa", vec!["ping.use".to_string()], 300);
    // The intended organelle: proceeds.
    let ok = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "aa",
            "ping",
            serde_json::json!({}),
        )
        .unwrap();
    assert!(!ok.receipt_id.is_empty());
    // Any other organelle: denied with receipt, even though the capability
    // check alone would pass.
    let e = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "bb",
            "ping",
            serde_json::json!({}),
        )
        .unwrap_err();
    assert_eq!(e.verdict, CallVerdict::Denied);
    assert!(e.reason.contains("scoped to organelle"), "{}", e.reason);
    assert!(!e.receipt_id.is_empty());
    let r = h
        .receipts()
        .iter()
        .find(|r| r.id == e.receipt_id)
        .expect("denial receipt must exist")
        .clone();
    assert_eq!(r.verdict, CallVerdict::Denied);
    assert_eq!(r.codon, "bb");
    assert!(h.verify_chain().is_ok());
}

#[test]
fn unscoped_grant_still_invokes_any_organelle() {
    // Back-compat: grants without an audience are not codon-confined.
    let h = Host::new();
    h.register(Arc::new(Echo { manifest: manifest("aa", "ping", "ping.use", vec![]) }))
        .unwrap();
    h.register(Arc::new(Echo { manifest: manifest("bb", "ping", "ping.use", vec![]) }))
        .unwrap();
    let grant = h.issue_grant("alice", vec!["ping.use".to_string()], 300);
    for codon in ["aa", "bb"] {
        h.call_with_grant(&grant, Some("alice"), Transport::Native, codon, "ping", serde_json::json!({}))
            .unwrap();
    }
}

#[test]
fn scoped_grant_without_capability_still_denied() {
    // Audience binding is not a capability bypass: the scoped organelle's
    // own required capabilities still apply.
    let h = Host::new();
    h.register(Arc::new(Echo { manifest: manifest("aa", "ping", "ping.use", vec![]) }))
        .unwrap();
    let grant = h.issue_scoped_grant("alice", "aa", vec![], 300);
    let e = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "aa",
            "ping",
            serde_json::json!({}),
        )
        .unwrap_err();
    assert_eq!(e.verdict, CallVerdict::Denied);
    assert!(e.reason.contains("ping.use"), "{}", e.reason);
}

// -- nested-call domain confinement ---------------------------------------

fn chain_host() -> (Arc<Host>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    // px --relay--> sk(use, requires model.call).
    // px's manifest grants model.call: without confinement the nested call
    // would succeed on the organelle's identity alone.
    let h = Host::new();
    let px_hits = Arc::new(AtomicUsize::new(0));
    let sk_hits = Arc::new(AtomicUsize::new(0));
    h.register(Arc::new(proxy(
        "px", "relay", "proxy.use", &["model.call"], "sk", "use", px_hits.clone(),
    )))
    .unwrap();
    h.register(Arc::new(Sink {
        manifest: manifest("sk", "use", "model.call", vec![]),
        hits: sk_hits.clone(),
    }))
    .unwrap();
    (h, px_hits, sk_hits)
}

#[test]
fn nested_capability_escalation_via_grant_denied() {
    let (h, px_hits, sk_hits) = chain_host();
    // The grant confers ONLY proxy.use: enough for the outer relay, not for
    // the nested model.call — even though px's manifest grants it.
    let grant = h.issue_grant("alice", vec!["proxy.use".to_string()], 300);
    let e = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "px",
            "relay",
            serde_json::json!({}),
        )
        .unwrap_err();
    // The relay itself failed: the boundary denial happened inside it.
    assert_eq!(e.verdict, CallVerdict::Failed);
    assert!(e.reason.contains("grant-confined"), "{}", e.reason);
    // The sink never ran: no side effect escaped the grant's domain.
    assert_eq!(px_hits.load(Ordering::SeqCst), 1);
    assert_eq!(sk_hits.load(Ordering::SeqCst), 0);
    // The nested attempt was denied, logged, and receipted.
    let denials = h.boundary_denials();
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].caller_codon, "px");
    assert_eq!(denials[0].target_codon, "sk");
    let r = h
        .receipts()
        .iter()
        .find(|r| r.id == denials[0].receipt_id)
        .expect("denial receipt must exist")
        .clone();
    assert_eq!(r.verdict, CallVerdict::Denied);
    assert_eq!(r.codon, "sk");
    // The receipt records the confined authority the nested call ran with:
    // empty, not the manifest's grant.
    assert!(r.granted_capabilities.is_empty());
    assert!(h.verify_chain().is_ok());
}

#[test]
fn nested_call_with_grant_covering_both_caps_ok() {
    let (h, _, sk_hits) = chain_host();
    // Positive control: the grant's domain covers both hops.
    let grant = h.issue_grant(
        "alice",
        vec!["proxy.use".to_string(), "model.call".to_string()],
        300,
    );
    let ok = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "px",
            "relay",
            serde_json::json!({}),
        )
        .unwrap();
    assert_eq!(ok.output["sunk"], serde_json::json!(true));
    assert_eq!(sk_hits.load(Ordering::SeqCst), 1);
    assert!(h.boundary_denials().is_empty());
    // The nested receipt records the confined (intersected) authority.
    let r = h
        .receipts()
        .iter()
        .find(|r| r.kind == organelle_host::ReceiptKind::Invocation && r.codon == "sk")
        .expect("nested receipt must exist")
        .clone();
    assert_eq!(r.verdict, CallVerdict::Ok);
    assert_eq!(r.granted_capabilities, vec!["model.call".to_string()]);
}

#[test]
fn nested_call_native_surface_keeps_membrane_identity() {
    // Deliberate boundary: without a grant there is no grant domain, so the
    // org-011 membrane identity model is unchanged — the organelle's
    // manifest grants govern the nested call even when the native caller's
    // context carries only the outer op's capability.
    let (h, _, sk_hits) = chain_host();
    let ctx = CallContext::new("test", vec!["proxy.use".to_string()]);
    let ok = h.call(&ctx, "px", "relay", serde_json::json!({})).unwrap();
    assert_eq!(ok.output["sunk"], serde_json::json!(true));
    assert_eq!(sk_hits.load(Ordering::SeqCst), 1);
    assert!(h.boundary_denials().is_empty());
}

#[test]
fn grant_confinement_is_transitive() {
    // px --relay--> md --relay2--> dp.
    // Grant domain: {proxy.use, model.call}. md's manifest grants deep.call,
    // but the domain does not include it, so md->dp is denied even though
    // px->md succeeded. Without transitive propagation, md->dp would run on
    // md's manifest grants alone.
    let h = Host::new();
    let px_hits = Arc::new(AtomicUsize::new(0));
    let md_hits = Arc::new(AtomicUsize::new(0));
    let dp_hits = Arc::new(AtomicUsize::new(0));
    h.register(Arc::new(proxy(
        "px", "relay", "proxy.use", &["model.call"], "md", "relay2", px_hits.clone(),
    )))
    .unwrap();
    h.register(Arc::new(proxy(
        "md", "relay2", "model.call", &["deep.call"], "dp", "use", md_hits.clone(),
    )))
    .unwrap();
    h.register(Arc::new(Sink {
        manifest: manifest("dp", "use", "deep.call", vec![]),
        hits: dp_hits.clone(),
    }))
    .unwrap();
    let grant = h.issue_grant(
        "alice",
        vec!["proxy.use".to_string(), "model.call".to_string()],
        300,
    );
    let e = h
        .call_with_grant(
            &grant,
            Some("alice"),
            Transport::Native,
            "px",
            "relay",
            serde_json::json!({}),
        )
        .unwrap_err();
    assert_eq!(e.verdict, CallVerdict::Failed);
    assert!(e.reason.contains("grant-confined"), "{}", e.reason);
    assert_eq!(px_hits.load(Ordering::SeqCst), 1);
    assert_eq!(md_hits.load(Ordering::SeqCst), 1);
    assert_eq!(dp_hits.load(Ordering::SeqCst), 0);
    let denials = h.boundary_denials();
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].caller_codon, "md");
    assert_eq!(denials[0].target_codon, "dp");
    assert!(h.verify_chain().is_ok());
}
