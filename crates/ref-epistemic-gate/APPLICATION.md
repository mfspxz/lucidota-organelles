# Applying `ref-epistemic-gate` — pt-oracle's verification gate (TEG)

Harvested by copy from the pt-oracle treatment app
(`~/workspace/full-send/projects/pt-oracle/app/src/gate.rs`,
91 lines, kept as `src/gate.rs`). The project tree keeps its own
code; this crate is the composable organelle form. One recorded
adaptation: the gate's valence import now resolves to
`ref-ontology-terms::TernaryValence` (the harvested go-ontology)
instead of the `go-ontology` path dependency — the convergence
the source itself documents (`pub use go_ontology::TernaryValence
as Valence;` in the original). No other line of the harvested
file differs. `src/lib.rs` adds only re-exports and organelle glue.

## What it is

A receipt-based epistemic gate: it promotes Candidate→Proven
through rule evaluation over evidence receipts, and it is the
piece the pt-oracle treatment assembled for the first time (the
source's `gate.rs` was orphaned — never declared as a module —
until that treatment wired `pub mod gate;`).

- **`VerificationGate`** (the seam): `verify` evaluates a claim
  against evidence receipts and emits an `OracleReceipt`;
  `promote` returns Proven iff at least `quorum` Proven receipts
  exist for the artifact hash; `demote` taints on a non-empty
  refutation (empty refutation is an error).
- **`RuleEngine`** (the validator seam): rules are caller-supplied
  closures `Fn(&[u8], &[OracleReceipt]) -> VerificationResult`.
  Verdict mapping: ≥0.67 of rules passed → Proven, ≤0.33 →
  Tainted, otherwise Candidate. No rules → Candidate, never
  Proven.
- **`Oracle`**: the reference gate — a `RuleEngine` pre-loaded
  with the `non_empty` rule, retaining every receipt it issues.

## The validator seam, stated exactly

pt-oracle's deterministic byte-span `Validator`
(`validator.rs`: capture-hash binding, exact-span field checks,
URL/genre validation) is **not** in this crate. It is bound to
pt-oracle's `CandidateStore`/`StagedCandidate` types and to
`pt-core`'s CAS hash type, so it does not extract cleanly as a
standalone piece; forcing it would have meant copying the
candidate store and a pt-core stub with it. The gate's own seam
is the honest extraction: a span check is a `RuleEngine` rule —
a closure over claim bytes + receipts — and a consumer with a
real validator plugs it in there.

## API

```toml
[dependencies]
ref-epistemic-gate = {
  path = "<relative path>/organelles/crates/ref-epistemic-gate",
  default-features = false, # pure gate only
}
```

```rust
use ref_epistemic_gate::{Oracle, VerificationGate, Valence};

let mut gate = Oracle::new();
let receipt = gate.verify(&artifact_hash, "agent", claim_bytes, &evidence)?;
assert_eq!(gate.promote(&artifact_hash, &[receipt], 1)?, Valence::Proven);
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `eg`, ops `verify` / `promote`; the glue constructs
a fresh gate per call because the harvested `Oracle` is not
`Sync` — its `RuleEngine` holds boxed closures — and the ops are
receipt-in/receipt-out with no cross-call state).

## Consumers

- **pt-oracle** is the origin: its assembled gate is this code.
  Adoption there is a dependency swap.
- **Any pipeline with a Candidate→Proven promotion step** —
  oracle/extraction lanes, claim stores, evidence gates — that
  currently promotes on a caller's say-so.

## Adoption steps

1. Add the path dependency above.
2. Register your validators as `RuleEngine` rules (span checks,
   signature checks, corroboration counts — each a closure
   returning `VerificationResult`).
3. Issue receipts through `verify`; promote only through
   `promote` with an explicit quorum; never write Proven
   directly.
4. Keep the receipts: promotion is a function of receipts, so
   the audit trail is the receipt set, not a log line.

## Known limits (inherited from the source, stated not fixed)

~~Gate receipts are unsigned and `promote` counts receipts without
verifying them~~ — FIXED 2026-11-23, ported mechanically from the
pt-oracle treatment (pt-oracle app commit `1e22c3f`). The gate now
holds an Ed25519 signing key (`Oracle::with_signing_key` for a
caller-supplied key, `Oracle::public_key` to publish the
verifying half), signs every receipt it issues over the
domain-separated canonical payload
`pt-oracle/gate-receipt/v1`, and `promote` counts only receipts
whose signature verifies against the gate's own key. Third
parties verify with the public
`verify_receipt_signature(receipt, gate_public_key)`.
`OracleReceipt.signature` is `Option<Vec<u8>>` with
`#[serde(default)]`: pre-fix serialized receipts still parse,
read back as unsigned, and are rejected by the quorum. Pinned by
`tests/gate_receipt_signing.rs` (legit promotes + public verify,
forged rejected, tampered rejected, foreign-gate rejected).
Remaining inherited limits are the ones in the sections above
(no persistence, no span validator in this harvest).
