# Wave 4c RESULTS — organelle migration (corrected doctrine)

## canon — DONE ✓
- **Commit:** `f727745` — `organelle-migration: canon tier-A`
- **Design:** built on wave-4a's uncommitted leftovers (MAPPING.md, manifest,
  execution.json, src/organelle.rs were complete and correct; verified, not redone).
- **Capability units:** 1 organelle (`ca`), 6 ops — `verify`, `get`, `search`,
  `active`, `add` (Write, `ca.write`), `snapshot`. Bespoke (chain-verified
  read authority + BM25 + fail-closed writes; ref-ledger-append rejected as
  wrong layer).
- **Tests:** 35/35 green (24 lib incl. 3 organelle + 11 integration).
- **Notes:** secret-scrub blocked twice on long identifiers in MAPPING.md
  (false positives); reworded per doctrine. Codon `ca` verified free
  workspace-wide.

## wreck — DONE ✓
- **Commit:** `7db599b` — `organelle-migration: wreck tier-A` (committed by
  wave-4a at 21:24 UTC; verified green by wave-4c before/after).
- **Design:** wave-4a's 2-organelle design adopted per task instruction
  ("build on leftovers rather than redoing"). My parallel 5-way
  decomposition (wl/wg/wd/wc/wx) was retired — archived at
  `scratch/wreck-five-way/` with NOTE.md explaining why. wave-4a's cut
  follows the codebase's own seam ("the governor core never touches a
  network") and the ledger-graph pilot's indivisible-core argument.
- **Capability units:** `wreck-govern` (`wg`): propose, validate_change_id,
  classify, decide, canon_insert/get/active/to_policy. `wreck-ports` (`wp`):
  workspace_init/fork/commit/diff/merge, token_for/adjudicate/revoke.
  Both bespoke. Exclusions: wreck-demo, wreck-wasm, wreck-worker (Tier C),
  ArtifactsClient live HTTP (unverified).
- **Tests:** 123/123 green (119 baseline + 4 organelle).
- **Codons** `wg`/`wp` verified free workspace-wide.

## adhkey — DONE ✓
- **Commit:** `1158e19` — `organelle-migration: adhkey tier-A`
  (coordinator committed wave-4c's work 2026-10-11 00:04 UTC).
- **Capability units (4 organelles, all bespoke):**
  - `adhkey-lifecycle` (`ak`): create_identity, activate_key,
    transition_key, can_transition, key_state, active_keys. Pure state
    machine, by-value. (refound_key/recover excluded: need KeyOperator.)
  - `adhkey-statement` (`as`): canonical_bytes, statement_hash. Pure.
    (authenticate excluded: needs sig-verification closure.)
  - `luci-context` (`lx`): insert/compress/project (Write, `lx.write`),
    get/dereference/eviction_order/len (ReadOnly). FileCas-backed.
  - `muse-exchange` (`mx`): route (Write, `mx.route`), apply_schema
    (Write, `mx.admin`). Candidate (embedded SurrealDB + ledger writes).
- **Exclusions:** adhkey-crypto (supporting lib), adhkey-store (trait-only),
  luci-verdict-core standalone (surfaced via `mx route`; input types not
  JSON-serializable), adhkey-flailer (IN ACTIVE DEVELOPMENT — uncommitted
  recovery-protocol expansion; organelle contract would be wrong on arrival).
- **Serde derives added** (additive, behavior-preserving): adhkey-core
  lib.rs types, adhkey-statement types, luci-context item/cache types,
  luci-verdict-core Epistemic. No logic touched.
- **Tests:** baseline 176/176 green; +12 new organelle tests
  (3 per organelle × 4). Full suite re-run pending.
- **Codons** `ak`/`as`/`lx`/`mx` verified free (`lc` taken by
  cutecity-launch-check, hence `lx`).

## noter — DONE ✓
- **Commit:** `b839d5c` — `organelle-migration: noter tier-A`
  (coordinator committed wave-4a's work 2026-10-10 21:49 UTC).
- **wave-4a's design (complete, verified):** 3 organelles — `noter-notes`
  (`no`, 12 ops), `noter-crypto` (`ne`, 9 ops), `noter-airgap` (`na`,
  3 ops) — with manifests, execution.json, MAPPING.md. Codon `nt`→`no`:
  `nt` collides with `ref-notify`. MAPPING.md justifies the
  stateful-vault vs pure-primitive cut.
- **Note:** the audit worker was mid-edit on noter-sync when wave-4c
  checked; the tree is green now (133 tests per commit ada7206).

## Cross-cutting notes
- **Substrate incident:** the hardening worker's in-flight organelle-host
  changes (hmac 0.13.0, incompatible with sha2 0.10) broke ALL downstream
  builds ~22:28 UTC. Fixed minimally: hmac 0.13→0.12 in
  `organelles/crates/organelle-host/Cargo.toml` (their import fix landed
  separately at 23:05). Parent should confirm with the hardening worker.
- **Secret-scrub:** fail-closed blocks on long identifiers are expected;
  reword, don't bypass. No key material in any manifest (capability
  names only).
- **No destructive git ops** used anywhere. Selective staging only.
- **RESULTS.md** location: `~/workspace/organelles/waves/wave-4c/RESULTS.md`
