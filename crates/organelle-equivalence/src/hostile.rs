//! org-007 hostile extension — adversarial authority equivalence.
//!
//! The happy-path matrix proves the four transports agree on allowed calls.
//! This module proves they agree on REFUSED calls: every hostile scenario
//! must produce the same denial verdict, the same denial message, and the
//! same receipt shape (verdict/kind/codon/op/transport, plus the
//! content-addressed `output_hash` when the reason is transport-independent)
//! on native, unix-socket, MCP, and REST. A transport that allows what the
//! others deny — or denies with a different verdict — fails the matrix.

use crate::{build_host, TransportAdapter};
use organelle_host::{CallVerdict, Host, Organelle, OrganelleError, Receipt, ReceiptKind, RoutePolicy};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Hostile token model
// ---------------------------------------------------------------------------

/// How the presented grant is attacked. Built per-adapter from that
/// adapter's own host, so a token is always verified against the key that
/// (honestly) minted it — except where the attack says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostileToken {
    /// Valid grant, one payload byte flipped, original tag kept.
    Forged,
    /// Valid grant, caps surgically rewritten to a superset, tag kept.
    EscalatedCaps,
    /// Valid grant for "equivalence", presented with caller claim "mallory".
    WrongCaller,
    /// Single-use grant presented twice; the SECOND verdict is asserted.
    ReplayedSingleUse,
    /// Grant scoped (audience) to codon "kv", presented to another codon.
    CrossOrganelle,
    /// Grant with ttl 0 (exp == iat, already expired).
    Expired,
    /// Not a grant at all.
    Malformed,
    /// Honestly issued grant — the attack is in the input or the arrival
    /// transport, not the token.
    Honest,
}

/// What "passing" means for one hostile case on one transport.
#[derive(Debug, Clone, Copy)]
pub enum HostileExpect {
    Deny {
        needle: &'static str,
        verdict: CallVerdict,
        /// Compare the receipt `output_hash` cross-transport too. False
        /// only when the denial reason legitimately names the arrival
        /// transport (the non-declared-transport case).
        compare_output_hash: bool,
    },
    /// The call must succeed (positive control, e.g. the declared
    /// transport for a transport-restricted organelle).
    Allow,
}

impl HostileExpect {
    fn deny(needle: &'static str, verdict: CallVerdict) -> Self {
        HostileExpect::Deny { needle, verdict, compare_output_hash: true }
    }
}

pub struct HostileCase {
    pub name: &'static str,
    pub token: HostileToken,
    pub caller_claim: &'static str,
    pub codon: &'static str,
    pub op: &'static str,
    pub input: Value,
    /// Capabilities minted into the underlying honest grant (before any
    /// tampering). Chosen so the ONLY reason for refusal is the attack.
    pub capabilities: Vec<String>,
    pub expect: HostileExpect,
    /// Transports this case runs on (adapter `name()`s). None = all four.
    /// Used where the attack is transport-relative by construction: the
    /// non-declared-transport case cannot deny on the declared transport.
    pub only: Option<&'static [&'static str]>,
}

// ---------------------------------------------------------------------------
// Token construction (per-adapter host)
// ---------------------------------------------------------------------------

fn flip_payload_bit(grant: &str) -> String {
    let (payload_hex, tag) = grant.split_once('.').expect("grant wire shape");
    let mut bytes = hex::decode(payload_hex).expect("grant payload hex");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    format!("{}.{}", hex::encode(bytes), tag)
}

fn escalate_caps(grant: &str) -> String {
    let (payload_hex, tag) = grant.split_once('.').expect("grant wire shape");
    let mut payload: Value =
        serde_json::from_slice(&hex::decode(payload_hex).expect("grant payload hex"))
            .expect("grant payload json");
    payload["caps"] =
        serde_json::json!(["kv.write", "admin.*", "ledger.write", "net.fetch", "model.call"]);
    format!("{}.{}", hex::encode(organelle_manifest::canonical_json(&payload)), tag)
}

/// Build the token this hostile case presents, minted (then attacked)
/// against the given adapter's own host.
pub fn build_hostile_token(host: &Host, case: &HostileCase) -> String {
    let sub = "equivalence";
    let caps = case.capabilities.clone();
    match case.token {
        HostileToken::Forged => flip_payload_bit(&host.issue_grant(sub, caps, 300)),
        HostileToken::EscalatedCaps => escalate_caps(&host.issue_grant(sub, caps, 300)),
        HostileToken::WrongCaller => host.issue_grant(sub, caps, 300),
        HostileToken::ReplayedSingleUse => host.issue_single_use_grant(sub, caps, 300),
        HostileToken::CrossOrganelle => host.issue_scoped_grant(sub, "kv", caps, 300),
        HostileToken::Expired => host.issue_grant(sub, caps, 0),
        HostileToken::Malformed => "not-a-grant".to_string(),
        HostileToken::Honest => host.issue_grant(sub, caps, 300),
    }
}

// ---------------------------------------------------------------------------
// Hostile probe organelles (registered on every matrix host)
// ---------------------------------------------------------------------------

fn receipt_policy() -> ReceiptPolicy {
    ReceiptPolicy {
        content_addressed: true,
        algorithm: RECEIPT_ALGORITHM.to_string(),
        chain: true,
    }
}

fn base_authority() -> Authority {
    Authority {
        mutation_class: MutationClass::ReadOnly,
        declared_valence: Valence::Proven,
        required_capability: None,
        granted_capabilities: vec![],
    }
}

/// Codon `nt`: declares ONLY the native transport. Presented over any other
/// surface, the host must deny with "not declared".
struct NativeOnly;
impl Organelle for NativeOnly {
    fn manifest(&self) -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "native-only-probe".to_string(),
            codon: "nq".to_string(),
            version: "1.0.0".to_string(),
            description: "hostile-matrix probe: native transport only".to_string(),
            contracts: vec![Contract {
                op: "ping".to_string(),
                description: "ping".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: None,
            }],
            authority: base_authority(),
            transports: vec![Transport::Native],
            receipt_policy: receipt_policy(),
        }
    }
    fn handle(
        &self,
        _ctx: &organelle_host::CallContext,
        _host: &dyn organelle_host::HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        if op != "ping" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        Ok(serde_json::json!({"pong": true}))
    }
}

/// Codon `vk`: two registered versions with DIFFERENT authority policy.
/// v1 requires `vk.admin`; v2 requires nothing. The matrix pins the route
/// to v1: a host that authorized against latest (v2) but executed the
/// pinned v1 would wrongly allow. Denial proves authorize and execute
/// consulted the same resolution.
struct VersionSkew {
    version: &'static str,
    require_admin: bool,
}
impl Organelle for VersionSkew {
    fn manifest(&self) -> OrganelleManifest {
        let mut authority = base_authority();
        if self.require_admin {
            authority.required_capability = Some("vk.admin".to_string());
        }
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "version-skew-probe".to_string(),
            codon: "vk".to_string(),
            version: self.version.to_string(),
            description: "hostile-matrix probe: version-skewed authority".to_string(),
            contracts: vec![Contract {
                op: "run".to_string(),
                description: "run".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: if self.require_admin {
                    Some("vk.admin".to_string())
                } else {
                    None
                },
            }],
            authority,
            transports: Transport::all().to_vec(),
            receipt_policy: receipt_policy(),
        }
    }
    fn handle(
        &self,
        _ctx: &organelle_host::CallContext,
        _host: &dyn organelle_host::HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        if op != "run" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        Ok(serde_json::json!({"ran": true, "version": self.version}))
    }
}

/// Codon `nx`: its `nest` op attempts a nested membrane call to `kv.put`.
/// The probe's manifest grants NOTHING, so the membrane boundary must deny
/// on every transport — a grant for kv.write cannot be laundered through a
/// nested call the organelle itself is not granted.
struct NestedProbe;
impl Organelle for NestedProbe {
    fn manifest(&self) -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "nested-boundary-probe".to_string(),
            codon: "nx".to_string(),
            version: "1.0.0".to_string(),
            description: "hostile-matrix probe: nested membrane boundary".to_string(),
            contracts: vec![Contract {
                op: "nest".to_string(),
                description: "attempt nested kv.put".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: None,
            }],
            authority: base_authority(),
            transports: Transport::all().to_vec(),
            receipt_policy: receipt_policy(),
        }
    }
    fn handle(
        &self,
        ctx: &organelle_host::CallContext,
        host: &dyn organelle_host::HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        if op != "nest" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        match host.call_organelle(
            "nx",
            &ctx.trace_id,
            "kv",
            "put",
            serde_json::json!({"key": "nx-escape", "value": 1}),
        ) {
            Ok(v) => Ok(v),
            Err(e) => Err(OrganelleError::failed(format!("nested call refused: {e}"))),
        }
    }
}

/// Register the hostile probe organelles on a matrix host and pin the
/// `vk` route to v1 (the version that requires `vk.admin`).
pub fn register_hostile_organelles(host: &Arc<Host>) {
    host.register(Arc::new(NativeOnly)).expect("nt registers");
    host.register(Arc::new(VersionSkew { version: "1.0.0", require_admin: true }))
        .expect("vk 1.0.0 registers");
    host.register(Arc::new(VersionSkew { version: "2.0.0", require_admin: false }))
        .expect("vk 2.0.0 registers");
    host.set_route("vk", RoutePolicy::Pinned("1.0.0".to_string()))
        .expect("vk route pins to 1.0.0");
    host.register(Arc::new(NestedProbe)).expect("nx registers");
}

/// Matrix host: the standard 12 reference organelles plus the hostile
/// probes. Existing happy-path scenarios are unaffected (they address the
/// reference codons only).
pub fn build_hostile_host(outbox_dir: &str, cas_dir: &str) -> Arc<Host> {
    let h = build_host(outbox_dir, cas_dir);
    register_hostile_organelles(&h);
    h
}

// ---------------------------------------------------------------------------
// The hostile scenario suite
// ---------------------------------------------------------------------------

fn caps(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// `inside_ledger` must be under the harness write roots; `outside_ledger`
/// must not be (an absolute path outside them).
pub fn build_hostile_cases(inside_ledger: &str, outside_ledger: &str) -> Vec<HostileCase> {
    let kvw = caps(&["kv.write"]);
    vec![
        HostileCase {
            name: "forged-grant",
            token: HostileToken::Forged,
            caller_claim: "equivalence",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny("grant signature invalid", CallVerdict::Denied),
            only: None,
        },
        HostileCase {
            name: "escalated-caps",
            token: HostileToken::EscalatedCaps,
            caller_claim: "equivalence",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny("grant signature invalid", CallVerdict::Denied),
            only: None,
        },
        HostileCase {
            name: "wrong-caller-grant",
            token: HostileToken::WrongCaller,
            caller_claim: "mallory",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny(
                "does not match grant subject",
                CallVerdict::Denied,
            ),
            only: None,
        },
        HostileCase {
            name: "replayed-single-use-grant",
            token: HostileToken::ReplayedSingleUse,
            caller_claim: "equivalence",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny("already used (replay)", CallVerdict::Denied),
            only: None,
        },
        HostileCase {
            name: "expired-grant",
            token: HostileToken::Expired,
            caller_claim: "equivalence",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny("grant expired", CallVerdict::Denied),
            only: None,
        },
        HostileCase {
            name: "malformed-grant",
            token: HostileToken::Malformed,
            caller_claim: "equivalence",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "hx", "value": 1}),
            capabilities: kvw.clone(),
            expect: HostileExpect::deny("malformed grant", CallVerdict::Denied),
            only: None,
        },
        // Grant scoped (audience) to kv, presented to la: the grant's
        // domain cannot escape its intended organelle.
        HostileCase {
            name: "cross-organelle-grant",
            token: HostileToken::CrossOrganelle,
            caller_claim: "equivalence",
            codon: "la",
            op: "append",
            input: serde_json::json!({"entry": {"k": "v"}, "ledger_path": inside_ledger}),
            capabilities: caps(&["ledger.write"]),
            expect: HostileExpect::deny("grant scoped to organelle", CallVerdict::Denied),
            only: None,
        },
        // nt declares native only: arrival over any other surface is a
        // fail-closed denial. Native is excluded by construction — it is
        // the declared transport (see the nt-declared-ok control).
        HostileCase {
            name: "non-declared-transport",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "nq",
            op: "ping",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: HostileExpect::Deny {
                needle: "not declared",
                verdict: CallVerdict::Denied,
                compare_output_hash: false, // reason names the arrival transport
            },
            only: Some(&["unix_socket", "mcp", "rest"]),
        },
        // Positive control: the same organelle+grant+op over its declared
        // transport succeeds, proving the denial above is transport
        // gating, not a broken probe.
        HostileCase {
            name: "nt-declared-ok",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "nq",
            op: "ping",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: HostileExpect::Allow,
            only: Some(&["native"]),
        },
        // Filesystem write outside the approved roots.
        HostileCase {
            name: "write-outside-root",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "la",
            op: "append",
            input: serde_json::json!({"entry": {"k": "v"}, "ledger_path": outside_ledger}),
            capabilities: caps(&["ledger.write"]),
            expect: HostileExpect::deny("write denied", CallVerdict::Failed),
            only: None,
        },
        // Egress to a host outside the allowlist.
        HostileCase {
            name: "egress-disallowed-host",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "hf",
            op: "fetch",
            input: serde_json::json!({"url": "http://10.0.0.1:9/"}),
            capabilities: caps(&["net.fetch"]),
            expect: HostileExpect::deny("egress denied", CallVerdict::Failed),
            only: None,
        },
        // vk route pinned to v1 (requires vk.admin); v2 requires nothing.
        // Invoking with no caps must deny: authorize and execute consulted
        // the same pinned resolution.
        HostileCase {
            name: "version-skew-pinned-route",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "vk",
            op: "run",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: HostileExpect::deny("missing capability", CallVerdict::Denied),
            only: None,
        },
        // nx.nest tries to launder kv.write through a nested membrane
        // call its own manifest was never granted.
        HostileCase {
            name: "nested-boundary-escalation",
            token: HostileToken::Honest,
            caller_claim: "equivalence",
            codon: "nx",
            op: "nest",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: HostileExpect::deny("lacks granted capability", CallVerdict::Failed),
            only: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

pub struct HostileTransportReport {
    pub transport: &'static str,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

pub struct HostileReport {
    pub cases: usize,
    pub transports: Vec<HostileTransportReport>,
    pub cross_transport_mismatches: Vec<String>,
}

impl HostileReport {
    pub fn all_green(&self) -> bool {
        self.transports.iter().all(|t| t.failed == 0)
            && self.cross_transport_mismatches.is_empty()
    }

    pub fn total_assertions(&self) -> usize {
        self.transports.iter().map(|t| t.passed + t.failed).sum::<usize>()
            + self.cross_transport_mismatches.len()
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "hostile equivalence: {} cases x transports\n",
            self.cases
        );
        for t in &self.transports {
            s.push_str(&format!(
                "  {:12} passed {:3} failed {:3}\n",
                t.transport, t.passed, t.failed
            ));
            for f in &t.failures {
                s.push_str(&format!("    FAIL: {f}\n"));
            }
        }
        for m in &self.cross_transport_mismatches {
            s.push_str(&format!("  CROSS-MISMATCH: {m}\n"));
        }
        s.push_str(if self.all_green() { "  VERDICT: GREEN\n" } else { "  VERDICT: RED\n" });
        s
    }
}

/// Receipt shape compared across transports for one hostile case.
/// The arrival `transport` is deliberately EXCLUDED: it legitimately
/// differs per surface (it records where the attempt arrived). Everything
/// else — verdict, kind, target, and the content-addressed denial reason —
/// must be identical.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptShape {
    verdict: CallVerdict,
    kind: ReceiptKind,
    codon: String,
    op: String,
    output_hash: Option<String>,
}

fn shape_of(r: &Receipt, compare_output_hash: bool) -> ReceiptShape {
    ReceiptShape {
        verdict: r.verdict,
        kind: r.kind,
        codon: r.codon.clone(),
        op: r.op.clone(),
        output_hash: if compare_output_hash { Some(r.output_hash.clone()) } else { None },
    }
}

fn check_receipt_shape(
    adapter: &dyn TransportAdapter,
    case: &HostileCase,
    want_verdict: CallVerdict,
    compare_output_hash: bool,
) -> Result<ReceiptShape, String> {
    let r = adapter
        .last_receipt()
        .ok_or_else(|| "no receipt recorded for this call".to_string())?;
    if r.verdict != want_verdict {
        return Err(format!(
            "receipt verdict {:?} != expected {:?}",
            r.verdict, want_verdict
        ));
    }
    if r.kind != ReceiptKind::Invocation {
        return Err(format!("receipt kind {:?} != Invocation", r.kind));
    }
    if r.codon != case.codon || r.op != case.op {
        return Err(format!(
            "receipt targets {}:{} != case {}:{}",
            r.codon, r.op, case.codon, case.op
        ));
    }
    if r.transport != Some(adapter.arrival()) {
        return Err(format!(
            "receipt transport {:?} != arrival {:?}",
            r.transport,
            Some(adapter.arrival())
        ));
    }
    Ok(shape_of(&r, compare_output_hash))
}

/// Run every hostile case on every adapter, then cross-compare the denial
/// receipt shapes across transports.
pub fn run_hostile_equivalence(
    cases: &[HostileCase],
    adapters: &mut [Box<dyn TransportAdapter>],
) -> HostileReport {
    // shapes[adapter_idx]: (case_name, ReceiptShape)
    let mut shapes: Vec<Vec<(String, ReceiptShape)>> = vec![Vec::new(); adapters.len()];
    let mut reports = Vec::new();

    for (ai, adapter) in adapters.iter_mut().enumerate() {
        let mut rep = HostileTransportReport {
            transport: adapter.name(),
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        };
        for case in cases {
            if let Some(only) = case.only {
                if !only.contains(&adapter.name()) {
                    continue;
                }
            }
            let res = adapter.hostile_call(case);
            match (&case.expect, res) {
                (HostileExpect::Deny { needle, verdict, compare_output_hash }, Err(msg)) => {
                    if !msg.contains(needle) {
                        rep.failed += 1;
                        rep.failures.push(format!(
                            "{}: denial message {msg:?} does not contain {needle:?}",
                            case.name
                        ));
                        continue;
                    }
                    match check_receipt_shape(
                        adapter.as_ref(),
                        case,
                        *verdict,
                        *compare_output_hash,
                    ) {
                        Ok(shape) => {
                            shapes[ai].push((case.name.to_string(), shape));
                            rep.passed += 1;
                        }
                        Err(e) => {
                            rep.failed += 1;
                            rep.failures.push(format!("{}: {e}", case.name));
                        }
                    }
                }
                (HostileExpect::Deny { needle, .. }, Ok(out)) => {
                    rep.failed += 1;
                    rep.failures.push(format!(
                        "{}: expected denial containing {needle:?}, got output {out}",
                        case.name
                    ));
                }
                (HostileExpect::Allow, Ok(_)) => {
                    match check_receipt_shape(adapter.as_ref(), case, CallVerdict::Ok, false) {
                        Ok(shape) => {
                            shapes[ai].push((case.name.to_string(), shape));
                            rep.passed += 1;
                        }
                        Err(e) => {
                            rep.failed += 1;
                            rep.failures.push(format!("{}: {e}", case.name));
                        }
                    }
                }
                (HostileExpect::Allow, Err(e)) => {
                    rep.failed += 1;
                    rep.failures.push(format!(
                        "{}: expected success (positive control), got error: {e}",
                        case.name
                    ));
                }
            }
        }
        reports.push(rep);
    }

    // Cross-transport: every case run on >= 2 transports must show the
    // identical receipt shape on each.
    let mut mismatches = Vec::new();
    for case in cases {
        let mut seen: Vec<(&str, &ReceiptShape)> = Vec::new();
        for (ai, adapter) in adapters.iter().enumerate() {
            if let Some((_, shape)) = shapes[ai].iter().find(|(n, _)| n == case.name) {
                seen.push((adapter.name(), shape));
            }
        }
        if seen.len() > 1 {
            let first = seen[0].1;
            for (tname, shape) in seen.iter().skip(1) {
                if *shape != first {
                    mismatches.push(format!(
                        "case '{}': '{}' shape {:?} != '{}' shape {:?}",
                        case.name, seen[0].0, first, tname, shape
                    ));
                }
            }
        }
    }

    HostileReport { cases: cases.len(), transports: reports, cross_transport_mismatches: mismatches }
}
