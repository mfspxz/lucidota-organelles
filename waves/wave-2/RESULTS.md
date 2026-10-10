# Wave 2 results — security suite organelle migration (corrected doctrine)

Worker: wave-2 security lane. Date: 2026-10-10. All 8 repos Tier A native
(Rust `Organelle` trait impls, path deps on `organelle-manifest` +
`organelle-host`, hash-chained receipts, `verify_chain` green).

Wave-1 state found: one `src/organelle.rs` draft per repo (unwired — no
`mod` declaration, no Cargo deps, 3-byte placeholder manifests, no
MAPPING.md, no execution.json, no tests). Wave 2 implemented the real
doctrine on top: genuine capability decomposition, map-or-design per unit
with justification in `organelles/MAPPING.md`, real manifests generated
from the Rust `manifest()` (equality-tested), `organelles/execution.json`,
register→call→verify_chain tests. Existing tests all stayed green.

## Per-repo results

### 1. vault (sec-002) — commit 3f08537
- **Units:** in-memory zeroizing store (insert/remove/contains/names),
  closure-scoped access + audit (audit op only — the closure cannot cross
  the boundary), Redactor (redact op, call-scoped values), strict env-file
  loader (load_env op — wave-1 draft had dropped this public fn).
- **Decisions:** one bespoke organelle `vault` (codon `va`), 7 ops.
  ref-kv-store REJECTED (its contract lacks zeroize-on-drop, no-value-escape,
  audit-without-values — adopting it would drop the security invariant).
  No `get` op by design. Write ops gated by `vault.write`.
- **Kill semantics:** suspend = LOCK (zeroize values, keep names+audit —
  the anti-checkpoint IS the checkpoint); kill = zeroize all.
- **Valence:** Candidate (stateful). **Tests:** 13 green.

### 2. cute-e2ee (sec-001) — commit fb7b763
- **Units:** X25519 keygen, sealed boxes, secretboxes, fingerprints
  (added — wave-1 missed this public method), BLAKE3 hash primitive.
- **Decisions:** one bespoke organelle `cute-e2ee` (codon `ce`), 7 ops.
  ref-hash-seal REJECTED (it seals canonical-JSON/sha256 + timestamp
  attestation; this is raw BLAKE3 over bytes — different computation).
  Key serialization subsumed by op boundaries (recorded exclusion).
- **Known duplication:** sec-organelles `sl` has near-identical ops —
  recorded in both MAPPING.md files (`ce` = primitive boundary,
  `sl` = service deployment; consolidation queued, not this wave).
- **Valence:** Proven. **Tests:** 16 green.

### 3. airgap-toolkit (sec-003) — commit 1d16552
- **Units:** export_armored / import_armored (AIRGAP1 wire protocol,
  fail-closed reassembly).
- **Decisions:** one bespoke organelle `airgap-toolkit` (codon `at`), 2 ops.
  ref-text-transform / ref-file-cas / ref-hash-seal all REJECTED (domain
  protocol with ordered per-chunk verification ≠ generic transform, CAS,
  or standalone attestation).
- **Valence:** Proven. **Tests:** 12 green.

### 4. threatmodel (sec-008/009/010) — commit 085b9ff
- **Units:** compiled-in registry serve (list/get/stats). `load()` is
  substrate, not an op (recorded).
- **Decisions:** one bespoke organelle `threatmodel` (codon `tm`), 3 ops.
  ref-json-validate REJECTED (no caller input; fixed machine-verified
  schema). ref-kv-store REJECTED (static domain registry with enforced
  invariants ≠ general store). TM-*.md prose docs deliberately excluded.
- **Fix required:** wave-1 draft assumed `Threat: Serialize`; lib.rs only
  derived Deserialize — added Serialize (additive, tests stayed green).
- **Valence:** Proven (registry include_str!-pinned at build). **Tests:** 10 green.

### 5. ir-runner (sec-011) — commit d4d759e
- **Units:** playbook registry (IR-1/IR-2/IR-4) + drill execution in a
  fresh SimEnv per call (fail-closed step→verify→receipt ordering).
- **Decisions:** one bespoke organelle `ir-runner` (codon `ir`), 2 ops.
  ReadOnly justified: mutation confined to per-call simulation.
  ref-model-call REJECTED (deterministic closures, no LLM). SimEnv
  internals subsumed by DrillReport (recorded).
- **Valence:** Candidate (drills simulate; canned verify closures — honest).
- **Tests:** 9 green.

### 6. backup-crypto (sec-012) — commit 723cf89
- **Units:** backup (dir → sealed blob, ReadOnly) / restore (verify ALL
  hashes BEFORE any write + path-escape check, Write + `backup.restore`).
- **Decisions:** one bespoke organelle `backup-crypto` (codon `bu` —
  see codon note), 2 ops. ref-file-cas / ref-hash-seal REJECTED (encrypted
  archiving + verify-before-write ordering ≠ CAS or standalone seal).
- **Fixes required:** wave-1 E0502 borrow bug in test; wave-1 receipt-count
  assertion off by one. Commit amended twice, local-only unpushed —
  single commit preserved per the one-commit rule.
- **Codon note:** `bc` was already claimed by another wave-2 worker's
  `bin/organelles/checkpoint-compute.manifest.json` (created 11:40 PDT,
  before this commit); `bk` by `bin-backup`. Renamed to `bu` (verified free).
- **Valence:** Candidate (touches caller filesystems). **Tests:** 10 green.

### 7. redteam (sec-014) — commit 46512f9
- **Units:** 14 attacks (a1–a14) across 7 target crates; verdict semantics
  Held / FindingPinned(F-RT1/F-RT2) / regression-net-break.
- **Decisions:** one bespoke organelle `redteam` (codon `rt`), 3 ops
  (attacks/attack/campaign). Attack bodies are the SAME fns the #[test]
  suite runs (`pub(crate)`, no duplication). No ref organelle fits.
  REDTEAM-REPORT.md prose deliberately excluded (human record).
- **Valence:** Proven (deterministic assertions; 14/14 green as cargo test).
- **Tests:** 17 green (14 attack + 3 organelle).

### 8. sec-organelles (sec-013) — commit 033306c
- **Verified pre-shaped:** Tier A impls already existed (9 tests green at
  wave start). Wave 2 added: real `seal.manifest.json` + `verify.manifest.json`
  (replacing the 3-byte wave-1 placeholder, left as a superseded-by pointer
  doc per archive-don't-delete), MAPPING.md, execution.json (both organelles),
  static-manifest-equality + verify_chain tests.
- **Decisions:** `seal` (`sl`) = service-level E2EE deployment;
  `verify` (`vf`) = fail-closed boolean verification (never throws) +
  provenance-chain checks. ref-hash-seal REJECTED for verify_seal (AEAD
  decryptability check ≠ hash matching). `validate_all()` recorded exclusion
  (test/setup helper; host registration already validates manifests —
  a validate-manifests op would be redundant).
- **Valence:** Proven (both). **Tests:** 11 green.
- **Untracked leftover:** wave-1 `src/organelle.rs` draft (a speculative
  third "meta organelle" `so`) left untracked — not adopted: host
  registration already validates manifests, making it redundant. Not
  deleted per archive-don't-delete.

## Codon verification (wave-1 flag resolved)

- The "no codon field" flag applied to wave-1's 3-byte placeholder
  manifests — all replaced with real manifests carrying codons.
- Final codons: va, ce, at, tm, ir, bu, rt, sl, vf — each verified unique
  across all `*.manifest.json` in the workspace (target/ excluded).
- The failclosed `fc` collision was already resolved by a prior wave
  (failclosed is now `fd`; ref-file-cas holds `fc`).
- **OPEN:** `sl` collision — `longtail/rust/soleita/organelles/soleita.manifest.json`
  (another worker, created 2026-10-10 ~11:51 PDT, uncommitted) uses `sl`.
  sec-organelles' `sl` predates it (baked into the repo's original source:
  docstrings, tests, host call sites). Precedence says soleita yields —
  flagged for coordinator; not renamed here (invasive to pre-existing source).

## Cross-cutting notes

- No key material, KDF details, or secret values in any manifest —
  capability names only (per the security-repos rule).
- One-shot `tmp_emit_manifest` tests were used to generate each static
  manifest from the Rust `manifest()` (guaranteeing equality), then removed
  before commit — final trees contain only the permanent equality tests.
- Selective staging throughout; no reset/stash/clean/force-push/amend of
  pushed history (two local-only amends on unpushed seconds-old commits to
  preserve the one-commit-per-repo rule — documented above).
- MIGRATION-STATUS.md untouched (coordinator-owned).
