//! org-029 — Reference organelle: policy-gate-evaluator (codon `pg`).
//!
//! Deterministic evaluation of ordered hard gates over caller-supplied
//! policy data (GAP-04 in the 2026-11-22 decomposition map: six scoped
//! softwares — SUB, WRK, EXC, RTR, VAN, MCP — hand-roll the same gate
//! stack today: EXC's `govern.rs` 11-gate governor, MCP's governor
//! server, VAN's `oracle_gates.rs`, WRK's govern core, the ai-router's
//! fail-closed tier policy, the substrate host's domain checks).
//!
//! The doctrine this crate is built under (Zack, 2026-11-21):
//! **telemetry and granular reporting are good; hardcoded policy rules
//! are bad.**  Every policy value — every threshold, every gate name,
//! every behaviour on an empty policy or a missing input — is a
//! caller-supplied knob expressed as data.  This crate ships **no
//! presets, no named groupings, and no defaults**: the [`Policy`]
//! struct deserializes only from data that states its own
//! configuration in full, and the evaluator contributes nothing but
//! the semantics of comparison and conjunction.  The organelle
//! evaluates; it does not legislate.
//!
//! A caller supplies:
//!
//! * a [`Policy`] — an ordered list of [`Gate`]s, each a list of
//!   [`Predicate`]s over named inputs with caller-chosen thresholds;
//! * the [`Inputs`] — named JSON values (number / boolean / string /
//!   array).  Time, quota counters, capability lists and every other
//!   fact are inputs; evaluation itself reads no clock, no RNG, no
//!   environment, and performs no I/O.
//!
//! and gets back an [`Evaluation`]: the verdict plus the complete
//! trace — every gate, every predicate, its input name, the actual
//! value seen, the threshold it was compared against, and its
//! individual outcome — with a sha256 over the canonical trace so the
//! whole record drops straight into a receipt or an evidence log.
//!
//! Evaluation semantics (the evaluator's contract, not policy):
//!
//! * Gates run in the caller's order.  Inside a gate, **every**
//!   predicate is evaluated — no intra-gate short-circuit — so the
//!   trace always shows the full state of the gate that failed.
//! * The first failing gate ends the run.  Every later gate still
//!   appears in the trace with outcome
//!   [`GateOutcome::NotEvaluated`], and each of its predicates appears
//!   with [`PredicateOutcome::NotEvaluated`] and no actual value.
//!   Nothing is silently omitted — the same honesty EXC's governor
//!   hand-codes as its `vacuous()` trace entries, generated here so a
//!   gate can never be absent from the record by accident.
//! * A predicate that cannot be proven true has not passed: a missing
//!   input, a type mismatch, or a malformed predicate are each
//!   recorded with their own outcome label and fail their gate —
//!   unless the caller's policy data configures the missing-input
//!   case as an evaluation error instead.  Either way the behaviour
//!   is the caller's stated choice, never a rule of this crate.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The named values a policy is evaluated against.  A `BTreeMap`, so
/// iteration and serialization order are part of the determinism
/// contract.  Values are plain JSON: number, boolean, string, array
/// (for `in` / `contains`), or null (a present null is a value; an
/// absent key is a missing input — the two are distinct in the trace).
pub type Inputs = BTreeMap<String, Value>;

// ---------------------------------------------------------------------
// Policy as data.  Every field is required: there are no serde
// defaults in this crate, because a default would be a rule the
// caller never stated.
// ---------------------------------------------------------------------

/// What to do when the policy contains no gates at all.  Stated by
/// the caller in the policy data; the crate has no opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyPolicy {
    /// An empty policy denies.  The trace is empty and no gate is
    /// named as failed — the record shows the denial came from the
    /// caller's configuration, not from any gate.
    Deny,
    /// An empty policy is a caller error: evaluation returns
    /// [`PolicyError`] and no verdict is produced.
    Error,
}

/// What to do when a predicate's named input is absent from the
/// inputs.  Stated by the caller in the policy data.  (The `exists`
/// operator is exempt: for `exists`, absence *is* the evaluated
/// fact, so it yields a plain pass/fail, never this path.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingInput {
    /// The predicate is recorded with
    /// [`PredicateOutcome::MissingInput`] and fails its gate.
    Fail,
    /// Evaluation aborts with [`PolicyError`]; no verdict or trace
    /// is produced.
    Error,
}

/// A complete policy, expressed as data.  Deserializing a `Policy`
/// from JSON requires every field — `on_empty`, `on_missing_input`,
/// and `gates` — because each one is a decision the caller must
/// make explicitly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Behaviour when `gates` is empty.  Caller-stated, required.
    pub on_empty: EmptyPolicy,
    /// Behaviour when a predicate's input is absent.  Caller-stated,
    /// required.
    pub on_missing_input: MissingInput,
    /// The gates, in the caller's evaluation order.
    pub gates: Vec<Gate>,
}

/// One named hard gate: a conjunction of predicates.  The gate
/// passes iff every predicate passes.  A gate with no predicates
/// passes vacuously — the standard semantics of conjunction — and
/// its trace entry shows the empty predicate list, so the vacuity
/// is on the record rather than hidden.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gate {
    /// Caller-chosen gate name (e.g. `QUOTA`).  Names are the
    /// caller's vocabulary; the crate attaches no meaning to them.
    pub name: String,
    pub predicates: Vec<Predicate>,
}

/// A single comparison over one named input.  `threshold` is the
/// caller-chosen value the input is compared against; it is
/// required for every operator except `exists` and `is_true`,
/// which take none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// Name of the input to read.
    pub input: String,
    pub op: Op,
    /// Caller-chosen comparison value.  Must be present for all
    /// operators except `exists` / `is_true`, and absent for those
    /// two; a predicate that violates this is recorded as
    /// [`PredicateOutcome::InvalidPredicate`] and fails its gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Value>,
}

/// The comparison vocabulary.  This is semantics, not policy: the
/// operators define what comparison *means*; every value compared
/// is caller data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// numeric: actual < threshold
    Lt,
    /// numeric: actual <= threshold
    Le,
    /// numeric: actual > threshold
    Gt,
    /// numeric: actual >= threshold
    Ge,
    /// any type: actual == threshold (JSON equality)
    Eq,
    /// any type: actual != threshold (JSON equality)
    Ne,
    /// threshold is an array: actual is an element of it
    In,
    /// string contains substring, or array contains element
    Contains,
    /// the input is present (any value, including null); takes no
    /// threshold
    Exists,
    /// the input is the boolean `true`; takes no threshold
    IsTrue,
}

impl Op {
    fn needs_threshold(self) -> bool {
        !matches!(self, Op::Exists | Op::IsTrue)
    }
}

// ---------------------------------------------------------------------
// Trace + verdict.  Everything here is evidence: serializable,
// deterministic, and complete by construction.
// ---------------------------------------------------------------------

/// The individual outcome of one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOutcome {
    Passed,
    Failed,
    /// The named input was absent and the policy configured
    /// missing inputs to fail their predicate.
    MissingInput,
    /// The actual value (or threshold) has a type the operator
    /// cannot compare (e.g. `lt` over a string).
    TypeMismatch,
    /// The predicate itself is malformed (threshold present where
    /// the operator takes none, or absent where it requires one;
    /// `in` with a non-array threshold).
    InvalidPredicate,
    /// An earlier gate failed; this predicate was never evaluated.
    NotEvaluated,
}

/// One predicate's full trace record: what was asked, what was
/// seen, what it was compared against, and how it came out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredicateTrace {
    pub input: String,
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Value>,
    /// The actual input value, or `None` when the input was absent
    /// or the predicate was not evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<Value>,
    pub outcome: PredicateOutcome,
}

/// The outcome of one gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Passed,
    Failed,
    /// An earlier gate failed; this gate was never evaluated.
    NotEvaluated,
}

/// One gate's trace record: every predicate in the gate, accounted
/// for, evaluated or explicitly not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateTrace {
    pub gate: String,
    pub outcome: GateOutcome,
    pub predicates: Vec<PredicateTrace>,
}

/// The verdict.  `Allow` iff every gate passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// The complete result of an evaluation: verdict + full trace +
/// the sha256 of the canonical trace record, ready to embed in a
/// receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    /// Name of the gate that failed, or `None` on allow — and also
    /// `None` when an empty policy denies by caller configuration,
    /// so the record never attributes a denial to a gate that did
    /// not make it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_gate: Option<String>,
    pub trace: Vec<GateTrace>,
    /// sha256 (hex) over the canonical JSON of
    /// `{verdict, failed_gate, trace}`.
    pub trace_sha256: String,
}

/// An evaluation the caller's own configuration asked to abort:
/// an empty policy under [`EmptyPolicy::Error`], or a missing
/// input under [`MissingInput::Error`].  Never produced by a rule
/// of this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy-gate: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

// ---------------------------------------------------------------------
// Evaluation.  Pure: no clock, no RNG, no I/O, no environment.
// ---------------------------------------------------------------------

/// Evaluate `policy` against `inputs`, deterministically.
///
/// Same policy data + same inputs always produce a byte-identical
/// [`Evaluation`] (including `trace_sha256`): inputs iterate in
/// `BTreeMap` order, gates and predicates in the caller's order,
/// and the trace hash is taken over serde_json's canonical
/// (sorted-key) serialization.
pub fn evaluate(policy: &Policy, inputs: &Inputs) -> Result<Evaluation, PolicyError> {
    if policy.gates.is_empty() {
        return match policy.on_empty {
            EmptyPolicy::Deny => Ok(finish(Verdict::Deny, None, Vec::new())),
            EmptyPolicy::Error => Err(PolicyError(
                "empty policy: caller configured on_empty = error".to_string(),
            )),
        };
    }

    let mut trace: Vec<GateTrace> = Vec::with_capacity(policy.gates.len());
    let mut failed_gate: Option<String> = None;

    for gate in &policy.gates {
        if failed_gate.is_some() {
            // Short-circuit honesty: the gate and every one of its
            // predicates appear in the trace, marked not evaluated.
            trace.push(GateTrace {
                gate: gate.name.clone(),
                outcome: GateOutcome::NotEvaluated,
                predicates: gate
                    .predicates
                    .iter()
                    .map(|p| PredicateTrace {
                        input: p.input.clone(),
                        op: p.op,
                        threshold: p.threshold.clone(),
                        actual: None,
                        outcome: PredicateOutcome::NotEvaluated,
                    })
                    .collect(),
            });
            continue;
        }

        // No intra-gate short-circuit: every predicate is evaluated
        // so the trace shows the gate's full state.
        let mut predicates: Vec<PredicateTrace> = Vec::with_capacity(gate.predicates.len());
        let mut gate_passed = true;
        for p in &gate.predicates {
            let t = eval_predicate(p, inputs, policy.on_missing_input)?;
            if t.outcome != PredicateOutcome::Passed {
                gate_passed = false;
            }
            predicates.push(t);
        }
        if !gate_passed {
            failed_gate = Some(gate.name.clone());
        }
        trace.push(GateTrace {
            gate: gate.name.clone(),
            outcome: if gate_passed {
                GateOutcome::Passed
            } else {
                GateOutcome::Failed
            },
            predicates,
        });
    }

    let verdict = if failed_gate.is_none() {
        Verdict::Allow
    } else {
        Verdict::Deny
    };
    Ok(finish(verdict, failed_gate, trace))
}

fn eval_predicate(
    p: &Predicate,
    inputs: &Inputs,
    on_missing_input: MissingInput,
) -> Result<PredicateTrace, PolicyError> {
    let actual = inputs.get(&p.input).cloned();
    let trace = |actual: Option<Value>, outcome: PredicateOutcome| PredicateTrace {
        input: p.input.clone(),
        op: p.op,
        threshold: p.threshold.clone(),
        actual,
        outcome,
    };

    // Predicate shape first: a malformed predicate is recorded as
    // such and fails — it is never silently reinterpreted.
    if p.op.needs_threshold() != p.threshold.is_some() {
        return Ok(trace(actual, PredicateOutcome::InvalidPredicate));
    }
    if p.op == Op::In && !p.threshold.as_ref().map(Value::is_array).unwrap_or(false) {
        return Ok(trace(actual, PredicateOutcome::InvalidPredicate));
    }

    // `exists`: absence is the evaluated fact, not a missing input.
    if p.op == Op::Exists {
        return Ok(match actual {
            Some(v) => trace(Some(v), PredicateOutcome::Passed),
            None => trace(None, PredicateOutcome::Failed),
        });
    }

    let actual = match actual {
        Some(v) => v,
        None => {
            return match on_missing_input {
                MissingInput::Fail => Ok(trace(None, PredicateOutcome::MissingInput)),
                MissingInput::Error => Err(PolicyError(format!(
                    "missing input '{}': caller configured on_missing_input = error",
                    p.input
                ))),
            }
        }
    };

    let outcome = compare(p.op, &actual, p.threshold.as_ref());
    Ok(trace(Some(actual), outcome))
}

/// The comparison semantics.  Returns `Passed` / `Failed` for a
/// genuine comparison, `TypeMismatch` when the values' types do not
/// support the operator.  Threshold presence has already been
/// validated by the caller.
fn compare(op: Op, actual: &Value, threshold: Option<&Value>) -> PredicateOutcome {
    use PredicateOutcome::*;
    match op {
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            let (Some(a), Some(t)) = (actual.as_f64(), threshold.and_then(Value::as_f64)) else {
                return TypeMismatch;
            };
            let pass = match op {
                Op::Lt => a < t,
                Op::Le => a <= t,
                Op::Gt => a > t,
                _ => a >= t,
            };
            if pass {
                Passed
            } else {
                Failed
            }
        }
        Op::Eq => {
            if threshold == Some(actual) {
                Passed
            } else {
                Failed
            }
        }
        Op::Ne => {
            if threshold != Some(actual) {
                Passed
            } else {
                Failed
            }
        }
        Op::In => {
            // Threshold array-ness validated before compare.
            let Some(Value::Array(items)) = threshold else {
                return InvalidPredicate;
            };
            if items.iter().any(|item| item == actual) {
                Passed
            } else {
                Failed
            }
        }
        Op::Contains => match (actual, threshold) {
            (Value::String(haystack), Some(Value::String(needle))) => {
                if haystack.contains(needle.as_str()) {
                    Passed
                } else {
                    Failed
                }
            }
            (Value::Array(items), Some(needle)) => {
                if items.iter().any(|item| item == needle) {
                    Passed
                } else {
                    Failed
                }
            }
            _ => TypeMismatch,
        },
        Op::IsTrue => match actual {
            Value::Bool(true) => Passed,
            Value::Bool(false) => Failed,
            _ => TypeMismatch,
        },
        // `exists` is fully handled in eval_predicate.
        Op::Exists => Passed,
    }
}

fn finish(verdict: Verdict, failed_gate: Option<String>, trace: Vec<GateTrace>) -> Evaluation {
    // The digest covers exactly the fields a receipt needs to bind:
    // verdict, failing gate, and the full trace.  serde_json's Map
    // is BTreeMap-backed in this workspace (no preserve_order), so
    // this serialization is canonical.
    let digest_input = serde_json::json!({
        "verdict": verdict,
        "failed_gate": failed_gate,
        "trace": trace,
    });
    let bytes = serde_json::to_vec(&digest_input).expect("trace values are always serializable");
    let trace_sha256 = hex::encode(Sha256::digest(&bytes));
    Evaluation {
        verdict,
        failed_gate,
        trace,
        trace_sha256,
    }
}

// ---------------------------------------------------------------------
// Organelle surface.  One op: `evaluate`.  The organelle is a pure
// function in a manifest: ReadOnly, no capabilities, no state.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "policy-gate".to_string(),
        codon: "pg".to_string(),
        version: "1.0.0".to_string(),
        description:
            "deterministic ordered hard-gate evaluator over caller-supplied policy data; \
             returns verdict + complete evaluation trace; ships no presets, groupings or defaults"
                .to_string(),
        contracts: vec![Contract {
            op: "evaluate".to_string(),
            description:
                "evaluate {policy, inputs} -> {verdict, failed_gate, trace, trace_sha256}; \
                 policy is data in full (on_empty, on_missing_input, gates with thresholds); \
                 evaluation is pure — time and every other fact arrive as inputs"
                    .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["policy", "inputs"],
                "properties": {
                    "policy": {
                        "type": "object",
                        "required": ["on_empty", "on_missing_input", "gates"],
                        "properties": {
                            "on_empty": {"enum": ["deny", "error"]},
                            "on_missing_input": {"enum": ["fail", "error"]},
                            "gates": {"type": "array"}
                        }
                    },
                    "inputs": {"type": "object"}
                }
            }),
            mutation_class: None,
            required_capability: None,
        }],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

#[cfg(feature = "organelle")]
pub struct PolicyGate {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(PolicyGate {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
impl Organelle for PolicyGate {
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
        match op {
            "evaluate" => {
                let policy: Policy = serde_json::from_value(input["policy"].clone())
                    .map_err(|e| OrganelleError::new("rejected", format!("policy: {e}")))?;
                let inputs_value = &input["inputs"];
                if !inputs_value.is_object() {
                    return Err(OrganelleError::new(
                        "rejected",
                        "inputs must be an object of named values",
                    ));
                }
                let inputs: Inputs = serde_json::from_value(inputs_value.clone())
                    .map_err(|e| OrganelleError::new("rejected", format!("inputs: {e}")))?;
                let evaluation = evaluate(&policy, &inputs)
                    .map_err(|e| OrganelleError::new("rejected", e.to_string()))?;
                serde_json::to_value(&evaluation)
                    .map_err(|e| OrganelleError::failed(format!("serialize evaluation: {e}")))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The four required proofs are determinism,
// trace completeness + short-circuit honesty, no-built-in-policy,
// and caller-configured missing-input behaviour; the rest pin the
// comparison semantics.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inputs(pairs: &[(&str, Value)]) -> Inputs {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn pred(input: &str, op: Op, threshold: Option<Value>) -> Predicate {
        Predicate {
            input: input.to_string(),
            op,
            threshold,
        }
    }

    fn policy(gates: Vec<Gate>) -> Policy {
        Policy {
            on_empty: EmptyPolicy::Deny,
            on_missing_input: MissingInput::Fail,
            gates,
        }
    }

    /// A three-gate policy in the estate's usual shape.  Every
    /// threshold here is test data, chosen by this test — the crate
    /// ships none.
    fn three_gate_policy() -> Policy {
        policy(vec![
            Gate {
                name: "IDENTITY".to_string(),
                predicates: vec![pred("authenticated", Op::IsTrue, None)],
            },
            Gate {
                name: "QUOTA".to_string(),
                predicates: vec![
                    pred("quota_used", Op::Le, Some(json!(40))),
                    pred("quota_window_open", Op::IsTrue, None),
                ],
            },
            Gate {
                name: "INTEGRITY".to_string(),
                predicates: vec![pred("seal_ok", Op::IsTrue, None)],
            },
        ])
    }

    #[test]
    fn determinism_byte_identical() {
        let p = three_gate_policy();
        let i = inputs(&[
            ("authenticated", json!(true)),
            ("quota_used", json!(41)),
            ("quota_window_open", json!(true)),
            ("seal_ok", json!(true)),
        ]);
        let a = evaluate(&p, &i).unwrap();
        let b = evaluate(&p, &i).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "same policy + same inputs must serialize byte-identically"
        );
        assert_eq!(a.trace_sha256.len(), 64);
        // And the verdict for this data: quota 41 > 40 fails QUOTA.
        assert_eq!(a.verdict, Verdict::Deny);
        assert_eq!(a.failed_gate.as_deref(), Some("QUOTA"));
    }

    #[test]
    fn trace_completeness_and_short_circuit_honesty() {
        let p = three_gate_policy();
        let i = inputs(&[
            ("authenticated", json!(true)),
            ("quota_used", json!(41)),
            ("quota_window_open", json!(false)),
            ("seal_ok", json!(true)),
        ]);
        let ev = evaluate(&p, &i).unwrap();
        // Every gate is in the trace, in order.
        assert_eq!(ev.trace.len(), 3);
        assert_eq!(ev.trace[0].gate, "IDENTITY");
        assert_eq!(ev.trace[0].outcome, GateOutcome::Passed);
        assert_eq!(ev.trace[1].gate, "QUOTA");
        assert_eq!(ev.trace[1].outcome, GateOutcome::Failed);
        // No intra-gate short-circuit: both QUOTA predicates were
        // evaluated even though the first already failed.
        assert_eq!(ev.trace[1].predicates.len(), 2);
        assert_eq!(ev.trace[1].predicates[0].outcome, PredicateOutcome::Failed);
        assert_eq!(ev.trace[1].predicates[0].actual, Some(json!(41)));
        assert_eq!(ev.trace[1].predicates[0].threshold, Some(json!(40)));
        assert_eq!(ev.trace[1].predicates[1].outcome, PredicateOutcome::Failed);
        // The gate after the failure is present, explicitly marked
        // not evaluated, predicate and all — never omitted.
        assert_eq!(ev.trace[2].gate, "INTEGRITY");
        assert_eq!(ev.trace[2].outcome, GateOutcome::NotEvaluated);
        assert_eq!(ev.trace[2].predicates.len(), 1);
        assert_eq!(
            ev.trace[2].predicates[0].outcome,
            PredicateOutcome::NotEvaluated
        );
        assert_eq!(ev.trace[2].predicates[0].actual, None);
        // Total accounting: 1 + 2 + 1 predicates, all present.
        let total: usize = ev.trace.iter().map(|g| g.predicates.len()).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn empty_policy_never_invents_a_rule() {
        let i = inputs(&[("anything", json!(true))]);
        // Caller configured Deny: verdict is Deny, the trace is
        // empty, and NO gate is blamed — the denial is recorded as
        // the caller's configuration, not a rule of this crate.
        let deny = Policy {
            on_empty: EmptyPolicy::Deny,
            on_missing_input: MissingInput::Fail,
            gates: vec![],
        };
        let ev = evaluate(&deny, &i).unwrap();
        assert_eq!(ev.verdict, Verdict::Deny);
        assert_eq!(ev.failed_gate, None);
        assert!(ev.trace.is_empty());
        // Caller configured Error: evaluation errors, no verdict.
        let error = Policy {
            on_empty: EmptyPolicy::Error,
            on_missing_input: MissingInput::Fail,
            gates: vec![],
        };
        assert!(evaluate(&error, &i).is_err());
        // And the configuration itself cannot be left unstated:
        // policy data missing the behaviour fields does not parse.
        assert!(serde_json::from_value::<Policy>(json!({"gates": []})).is_err());
        assert!(serde_json::from_value::<Policy>(
            json!({"on_empty": "deny", "gates": []})
        )
        .is_err());
    }

    #[test]
    fn missing_input_is_caller_configured() {
        let gate = Gate {
            name: "QUOTA".to_string(),
            predicates: vec![pred("quota_used", Op::Le, Some(json!(40)))],
        };
        let i = inputs(&[]); // quota_used absent
        let fail = Policy {
            on_empty: EmptyPolicy::Deny,
            on_missing_input: MissingInput::Fail,
            gates: vec![gate.clone()],
        };
        let ev = evaluate(&fail, &i).unwrap();
        assert_eq!(ev.verdict, Verdict::Deny);
        assert_eq!(
            ev.trace[0].predicates[0].outcome,
            PredicateOutcome::MissingInput
        );
        assert_eq!(ev.trace[0].predicates[0].actual, None);
        let error = Policy {
            on_empty: EmptyPolicy::Deny,
            on_missing_input: MissingInput::Error,
            gates: vec![gate],
        };
        let err = evaluate(&error, &i).unwrap_err();
        assert!(err.0.contains("quota_used"));
    }

    #[test]
    fn thresholds_are_caller_data() {
        // The same predicate shape, two different caller-chosen
        // thresholds, opposite verdicts — the number lives in the
        // policy data, nowhere else.
        let i = inputs(&[("quota_used", json!(39))]);
        let mk = |cap: u64| {
            policy(vec![Gate {
                name: "QUOTA".to_string(),
                predicates: vec![pred("quota_used", Op::Le, Some(json!(cap)))],
            }])
        };
        assert_eq!(evaluate(&mk(40), &i).unwrap().verdict, Verdict::Allow);
        assert_eq!(evaluate(&mk(38), &i).unwrap().verdict, Verdict::Deny);
    }

    #[test]
    fn ops_matrix() {
        let i = inputs(&[
            ("n", json!(5)),
            ("s", json!("cute-city")),
            ("b", json!(true)),
            ("tags", json!(["trike", "cargo"])),
            ("nothing", Value::Null),
        ]);
        let one = |p: Predicate| {
            let pol = policy(vec![Gate {
                name: "G".to_string(),
                predicates: vec![p],
            }]);
            evaluate(&pol, &i).unwrap().trace[0].predicates[0].outcome
        };
        use PredicateOutcome::*;
        assert_eq!(one(pred("n", Op::Lt, Some(json!(6)))), Passed);
        assert_eq!(one(pred("n", Op::Le, Some(json!(5)))), Passed);
        assert_eq!(one(pred("n", Op::Gt, Some(json!(5)))), Failed);
        assert_eq!(one(pred("n", Op::Ge, Some(json!(5)))), Passed);
        assert_eq!(one(pred("s", Op::Eq, Some(json!("cute-city")))), Passed);
        assert_eq!(one(pred("s", Op::Ne, Some(json!("cute-city")))), Failed);
        assert_eq!(one(pred("s", Op::In, Some(json!(["x", "cute-city"])))), Passed);
        assert_eq!(one(pred("s", Op::Contains, Some(json!("city")))), Passed);
        assert_eq!(one(pred("tags", Op::Contains, Some(json!("cargo")))), Passed);
        assert_eq!(one(pred("tags", Op::Contains, Some(json!("nope")))), Failed);
        assert_eq!(one(pred("nothing", Op::Exists, None)), Passed);
        assert_eq!(one(pred("absent", Op::Exists, None)), Failed);
        assert_eq!(one(pred("b", Op::IsTrue, None)), Passed);
        // Type mismatches are recorded, not coerced.
        assert_eq!(one(pred("s", Op::Lt, Some(json!(3)))), TypeMismatch);
        assert_eq!(one(pred("n", Op::IsTrue, None)), TypeMismatch);
        assert_eq!(one(pred("tags", Op::Contains, Some(json!(3)))), Failed);
        // Malformed predicates are recorded, not reinterpreted.
        assert_eq!(one(pred("n", Op::Lt, None)), InvalidPredicate);
        assert_eq!(one(pred("b", Op::IsTrue, Some(json!(true)))), InvalidPredicate);
        assert_eq!(one(pred("s", Op::In, Some(json!("cute-city")))), InvalidPredicate);
    }

    #[test]
    fn all_gates_pass_allows() {
        let p = three_gate_policy();
        let i = inputs(&[
            ("authenticated", json!(true)),
            ("quota_used", json!(40)),
            ("quota_window_open", json!(true)),
            ("seal_ok", json!(true)),
        ]);
        let ev = evaluate(&p, &i).unwrap();
        assert_eq!(ev.verdict, Verdict::Allow);
        assert_eq!(ev.failed_gate, None);
        assert!(ev.trace.iter().all(|g| g.outcome == GateOutcome::Passed));
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::*;
    use organelle_host::Host;

    #[test]
    fn evaluate_via_host() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let out = h
            .call(
                &ctx,
                "pg",
                "evaluate",
                serde_json::json!({
                    "policy": {
                        "on_empty": "deny",
                        "on_missing_input": "fail",
                        "gates": [{
                            "name": "QUOTA",
                            "predicates": [
                                {"input": "quota_used", "op": "le", "threshold": 40}
                            ]
                        }]
                    },
                    "inputs": {"quota_used": 41}
                }),
            )
            .unwrap()
            .output;
        assert_eq!(out["verdict"], serde_json::json!("deny"));
        assert_eq!(out["failed_gate"], serde_json::json!("QUOTA"));
        assert_eq!(out["trace"][0]["predicates"][0]["actual"], serde_json::json!(41));
        assert_eq!(out["trace"][0]["predicates"][0]["threshold"], serde_json::json!(40));
        assert_eq!(out["trace_sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn policy_missing_behaviour_fields_rejected() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let err = h
            .call(
                &ctx,
                "pg",
                "evaluate",
                serde_json::json!({
                    "policy": {"gates": []},
                    "inputs": {}
                }),
            )
            .unwrap_err();
        assert_eq!(err.verdict, organelle_host::CallVerdict::Rejected);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
