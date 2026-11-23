# Applying `ref-evidence-gate` — the anti-overclaim gate (TEV)

Harvested by copy from pt-forged, the pt-crypto-infra treatment
crate (`~/workspace/full-send/projects/pt-crypto-infra/app/pt-forged/`).
Harvested files, each byte-identical (sha256 verified both sides):

- `src/lib.rs` (9 lines) → `src/forged.rs`
  (`6ddf4de14c04a3df…`)
- `src/evidence_gate.rs` (215 lines) → `src/forged/evidence_gate.rs`
  (`a3c2eb4616609493…`)

The proving test (`tests/e2e.rs`) is copied with only the
crate-name import updated (`pt_forged` → `ref_evidence_gate`).
The project tree keeps its own code; this crate is the composable
organelle form. `src/lib.rs` adds only re-exports and organelle
glue. The relocation is a module-path move only — no line differs.

## What it is

The forge pipeline's output gate, ported from a Python
status-ledger gate: an anti-overclaim classifier for claims about
the estate's own work.

- `classify_claim(text)` → `ClaimClass` — flags broad, unscoped
  overclaims ("the whole system is 100% production ready") as
  `BroadMyth`; scoped claims classify as admissible classes.
- `classify_status(status)` → `StatusClass` — matches the status
  string against the source policy's known sets (verified /
  upgrade / partial / …); anything else is `Unknown`.
- `gate(claim, status, schema_recognized)` → `GateVerdict` —
  admits the pair or blocks it with named blockers
  (`broad_unscoped_overclaim`, `unrecognized_status:<status>`,
  `schema_not_recognized`). The verdict is serde-round-trippable
  and is the artefact "THE ORACLE consumes" (pt-oracle /
  ref-epistemic-gate territory).

**What it is not:** the crate contains no signing or attestation
code at all — verdict provenance in the source is documentary
(forge-chain headers). That gap is precisely what
`ref-verified-context` closes by signing verdicts with a
`ref-keystore` key. Treatment-era wart, already fixed in the
source and inherited here: `gate` / `classify_status` are
re-exported at the crate root.

## API

```toml
[dependencies]
ref-evidence-gate = {
  path = "<relative path>/organelles/crates/ref-evidence-gate",
  default-features = false, # pure gate only (regex/serde/serde_json)
}
```

```rust
use ref_evidence_gate::gate;

let verdict = gate("the whole system is 100% production ready", "VERIFIED", true);
assert!(!verdict.admitted); // blocker: broad_unscoped_overclaim
let ok = gate("golden path regression gate passes on the proof kernel", "VERIFIED", true);
assert!(ok.admitted); // scoped claim, terminal status — the e2e test's proven case
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `ev`, op `gate` with `claim` / `status` /
`schema_recognized` inputs).

## Consumers

- **Origin**: pt-forged in the pt-crypto-infra treatment tree —
  adoption there is a dependency swap.
- **ref-verified-context**: signs this crate's `GateVerdict`s
  (it consumes this organelle under the dependency rename
  `pt-forged`, see its APPLICATION.md).
- **Status/report tooling** that wants a deterministic
  admit/block verdict on completion claims before they are
  published or consumed downstream.

## wasm32 status

Native: builds clean, tests 9/9 (8 unit + 1 e2e).
wasm32-unknown-unknown check: **PASS**.

## Adoption steps

1. Add the path dependency above.
2. Run every outward completion claim through `gate` before it
   is published or fed to a consumer; act on `blockers`, don't
   paraphrase them away.
3. Transport verdicts as `SignedVerdict`s via
   `ref-verified-context`, not as bare `GateVerdict`s, wherever
   provenance matters.
