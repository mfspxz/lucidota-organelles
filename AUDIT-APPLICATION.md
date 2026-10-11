# RIGOR-AUDIT application — organelles

**Repo:** `~/workspace/organelles` (organelle-host substrate rebuild,
Rust, org-001..org-024)
**Date:** 2026-10-10 ~15:05 PDT
**Audit:** `~/workspace/dogfood/audit/RIGOR-AUDIT.md` (R-1..R-12)
**Corpus state:** scaffolded 2026-10-07; suspend/kill lifecycle commit
2026-10-10; waves/ holds QA-audit outputs (untracked scratch).

## Per-finding disposition

### R-1 (instance-only fix-verification claims) — APPLIED (policy)
No falsification ledger in this repo; the claim analog is the
`waves/qa-audit-{1,2}/RESULTS.md` verdict tables (✅/⚠️/❌ per repo) and
the README's "Equivalence verdict: GREEN". These are instance
verifications (one manifest sweep, one test run, one matrix execution).
Policy (new): any future `PROVEN`/✅ claim against an audit must carry
`class_scope: instance-only` until a dedicated re-audit with NEW probes
signs off; a bypass/defeat must be recorded against the original claim
(one book — no separate defeat log).

### R-2 (honest guardrail bounds) — APPLIED
The host's fail-closed router (profile → codon → op → capability →
schema → handle) already documents honest behavior in README
("Honesty notes": notify queues as `queued` never `sent`; model-call is
a labeled deterministic stub; time-oracle declares Candidate).
Applied: README now states the receipt-chain bound explicitly — the
chain is in-memory only (`Vec<Receipt>` behind an `RwLock`), recomputed
by `verify_chain()`; it is a **process-integrity structure, not
tamper-evidence**: any holder of the `Host` can rewrite history. No
hardening past this bound without an out-of-band anchor.

### R-3 (out-of-band head for hash-chained logs) — N/A
The only hash chain in the repo is the in-memory receipt chain
(`organelle-host`, org-010) plus test-only uses in `noter`'s adapter
(outside this repo). No durable chained log file exists, so there is
no head to copy to `~/workspace/dogfood/audit/oob-heads/`. Creating an
empty OOB record would be ritual; instead this documents the N/A.
If receipts are ever persisted to disk, an OOB head copy becomes
mandatory before any tamper-evidence claim (R-3).

**P2 update (2026-10-10):** receipts ARE now persisted
(`organelle-host/src/receipt_log.rs`: append-only `ORL1`-framed log,
fsync before the id returns, torn-tail truncation, corruption
fails-closed) and the OOB head copy exists as `ReceiptAnchor`
(`export_anchor` / `write_anchor` / `verify_against_anchor`). The honest
bound moved accordingly: see `docs/VERIFIER.md` §§1–5 (what
`verify_chain`, persistence, and anchors do and do not prove, and the
residual trust assumptions). R-2's "process-integrity only" bound now
applies only when the receipt log is NOT enabled.

### R-4 (backlog triage) — APPLIED
Standing known issues in THIS repo's own tree:
- `waves/` contains untracked QA-audit scratch (`qa-audit-1/RESULTS.md`,
  `qa-audit-2/`, `wave-3/`, `wave-4b2/`, `wave-4c/`, `wave-5/`,
  `wave-7a/`, plus modified `MIGRATION-INVENTORY.md`,
  `MIGRATION-STATUS.md`, `waves/wave-7b/validate/Cargo.toml`). These
  are another lane's in-flight migration waves, not this repo's
  defects — **not claimed as my backlog; not committed by me.**
- The QA audits' cross-repo findings (codon collisions `va`/`ce`,
  missing MAPPING.md on Tier C, `sec-organelles` non-manifest pointer
  doc) belong to the migration wave owners, not this substrate repo.
  Recorded here for visibility; no action taken (never commit/touch
  another lane's files).
- This repo's own standing HIGH backlog: **none.** No wont-fix entries
  required. Backlog rule: any future standing HIGH gets FIX with a
  complexity budget or explicit WONT-FIX; the list must not grow
  unbounded.

### R-5 (signature/denylist games) — N/A
No signature, denylist, blocklist, or content-strip logic exists
anywhere in the substrate or reference organelles. Nothing to budget.

### R-6 (detector without consumer) — N/A
No warn/flag/detector machinery in the substrate. The fail-closed
verdicts (`Denied` vs `Rejected`) are gates by construction: every
denial emits a receipt and blocks the call — detector and enforcement
are the same step.

### R-7 (property vs change-detection tests) — APPLIED (policy)
The 19-scenario × 4-transport equivalence matrix states invariants
("byte-diff = fail") without naming the transport internals —
property-style. The unit tests (manifest validation, fail-closed
routing) are largely change-detection. Policy (new): equivalence
matrix = PROPERTY tests; their expectations may never be rewritten to
match a behavior change without adversarial (red-team) sign-off on the
new behavior. Unit tests = change-detection, labeled as such.
Documented here; test files unchanged.

### R-8 (unsigned "provenance") — APPLIED (honest-unsigned declaration)
Receipts are content-addressed (sha256 over canonical JSON) and
hash-chained but **unsigned and unanchored**. They carry valence labels
that are honest about their power: `Proven` = recomputable/deterministic
only; `Candidate` = unverified clock / stub / external. Declared
honestly-unsigned: verification power = detect accidental corruption
via recomputation; NOT tamper-evidence, NOT identity binding. The
`wreck-claim.*.json` files under `waves/wave-4c/scratch/` are test
scratch fixtures, not provenance claims.

### R-9 (frozen claim-log schema) — N/A
No claim/falsification log in this repo. If one is created it must ship
with frozen enum verdicts + SUPERSEDED-BY-BYPASS from day one.

### R-10 (live record-keeping) — N/A
No scoreboard analog; `waves/` scratch is explicitly scratch, not the
record.

### R-11 (explicit UNKNOWN list)
1. `time-oracle` clock: declares Candidate — actual clock accuracy is
   UNKNOWN (unverified).
2. `model-call`: a deterministic stub unless `MODEL_API_URL` is set —
   real-provider behavior UNKNOWN by design.
3. `notify`: queues locally, never sends — delivery UNKNOWN/out of scope.
4. `http-fetch`/`scrape-extract`: http-only reference client — any
   https behavior is UNKNOWN (refused by design).
5. Cross-process receipt verification: the chain is in-memory only —
   what a *second* process would see is UNKNOWN (no such reader exists).
6. Kill/checkpoint semantics under hostile conditions: declared and
   unit-tested, never adversarially red-teamed — UNKNOWN.

### R-12 (no unsourced oral footnotes)
Swept README, MIGRATION-*, ORGANELLE-MIGRATION-STANDARD.md,
waves/qa-audit-2/RESULTS.md for "probably/likely/unverified source/I
heard" class claims: **none found.** One inference is stated with its
reasoning (qa-audit-1: the unlisted 17th repo identified as
`security/redteam`) — labeled as inference, not fact.

## Commits (this pass)
- (pending — selective staging of AUDIT-APPLICATION.md + README bound
  note; never push; another lane's untracked waves/ and modified
  MIGRATION-*.md are NOT staged)

## Tests
- `cargo test --offline --workspace --exclude claim-reconciler`:
  **all green, 0 failed** (measured 2026-10-10; 13 `test result: ok`
  suites covering the README's 112 tests + 76 equivalence assertions).
- `claim-reconciler` (another lane's in-flight WIP, NOT mine): 6 passed,
  4 FAILED as of 2026-10-10 — expectation mismatches in its adversarial
  tests (`"Failed"` vs `"Denied"` etc.). Not touched by this pass.

## BRUTAL-AUDIT ROLLOUT ROUND 2 — LANE 1 (2026-10-10)

**Scope:** resolve organelle-host/hmac build collision + CallOk API fallout.
**Pin strategy:** hmac 0.12.1 estate-wide — see `~/workspace/dogfood/audit/rollout/HMAC-PIN-STRATEGY.md`.

**This repo:**
- Commit(s): 476aa4d + fad22bb
- Tests: claim-reconciler 15/15 (5 unit + 10 adversarial); ref-model-call 4/4 x3 runs
- Change: claim-reconciler tests indexed CallOk as Value (pre-380ed26 API) -> X[".."] => X.output[".."], ingest_claim returns .unwrap().output. ref-model-call live-provider test flaked on MODEL_API_URL env race between parallel tests -> static ENV_LOCK Mutex serializing env-mutating tests.
- Method: mechanical, test-only, zero behavior change. Selective staging; lane WIP (if any) left untouched.
