# Organelle Migration — Status (started 2026-10-10)

Standard: [ORGANELLE-MIGRATION-STANDARD.md](ORGANELLE-MIGRATION-STANDARD.md) ·
Inventory: [MIGRATION-INVENTORY.md](MIGRATION-INVENTORY.md)

## Legend
- ✅ done (tier noted) · 🔄 in progress · ⬜ queued · 🚫 excluded (scratch)

**DOCTRINE (Zack's law, 2026-10-10 — supersedes blind per-repo templating):**
per repo, analyze what the code ACTUALLY does and decompose its real capabilities
into organelles. Per capability unit, genuine map-or-design: if the unit GENUINELY
IS one of the 12 reference organelles → adopt it, do not reinvent; if NOT →
design purpose-built with own codon/contract. Every mapping justified in
`organelles/MAPPING.md` per repo. Calibrated example: ledger-graph
(src/organelle.rs + organelles/MAPPING.md). Phase 4 v1 (blind stamping) was
HALTED by Zack; Phase 4 v2 runs under this doctrine.

## Pilot
- ✅ ledger-graph — tier-A — commit 1e3c412 (+ e9d1324 mapping justification) — 5/5 tests green. Refined under corrected doctrine: organelles/MAPPING.md records per-unit map-or-design (parse/view bespoke — ledger-specific indexing/graph views, no ref organelle fits; bench deliberately excluded as dev harness).

## Wave 1 — small Rust utils (Tier A) ✅ DONE (2026-10-10)
- ✅ security/failclosed — tier-A — commit 379301a — codon `fd` (was `fc`, collided with ref-file-cas — fixed) — ops decide/write, verify — 12/12 tests
- ✅ security/ipc — tier-A — commit fdf92eb — codon `ip` — ops roundtrip, auth_probe — 10/10 tests (fixed wrong test expectation from prior work)
- ✅ security/provenance — tier-A — commit 904c87e — codon `pv` — ops record/write, lineage, verify — 11/11 tests
- ✅ security/auditor — tier-A — commit e4421fc — codon `ad` — op scan (ReadOnly, honest Candidate) — 12/12 tests
- ✅ longtail/rust/lt-tools — tier-A — commit b589d2b — codon `lt` — 14 ops (13 ReadOnly; ports ExternalEffect) — 18/18 tests (`retry` deliberately excluded — spawns arbitrary subprocesses)
- ✅ longtail/rust/ornament — tier-A — commit 3728c3f — codon `or` — ops pack_load, pack_check, profile, questions, calibrate — 20/20 tests
- All six: genuine per-unit map-or-design in organelles/MAPPING.md; no ref organelle fit (documented why each near-miss failed). Results: waves/wave-1/RESULTS.md

## Wave 2 — security suite (Tier A) ✅ DONE (2026-10-10)
- ✅ security/vault — tier-A — commit 3f08537 — codon `va` — zeroizing store + Redactor + strict env-loader (restored wave-1-dropped fn) — 13/13 tests. Suspend=LOCK (zeroize values). Candidate.
- ✅ security/cute-e2ee — tier-A — commit fb7b763 — codon `ce` — keygen/sealed-boxes/secretboxes/fingerprint/BLAKE3 — 16/16 tests. Proven.
- ✅ security/airgap-toolkit — tier-A — commit 1d16552 — codon `at` — AIRGAP1 export/import armored — 12/12 tests. Proven.
- ✅ security/threatmodel — tier-A — commit 085b9ff — codon `tm` — registry serve list/get/stats — 10/10 tests. Proven.
- ✅ security/ir-runner — tier-A — commit d4d759e — codon `ir` — playbook registry + per-call SimEnv drills — 9/9 tests. Candidate (honest "drills simulate").
- ✅ security/backup-crypto — tier-A — commit 723cf89 — codon `bu` — backup/restore (verify-ALL-hashes-before-ANY-write) — 10/10 tests. Candidate.
- ✅ security/redteam — tier-A — commit 46512f9 — codon `rt` — 14 attacks a1–a14 (same fns as #[test] suite, zero duplication) — 17/17 tests. Proven.
- ✅ security/sec-organelles — tier-A — commit 033306c — codons `sl` (E2EE service) + `vf` (fail-closed verify) — verified pre-shaped, added real manifests + MAPPING.md — 11/11 tests.
- All 8: genuine map-or-design (ref organelles rejected on contract, documented). Also repaired wave-1's unwired drafts in failclosed/ipc/provenance. Codon `sl` precedence: sec-organelles (pre-existing source) > soleita (uncommitted) — wave-3 notified. Results: waves/wave-2/RESULTS.md

## Wave 3 — longtail Rust (Tier A) 🔄 IN FLIGHT
- 🔄 longtail/percyphonai
- 🔄 longtail/rust/percyphon
- 🔄 longtail/rust/diogenes-kernel
- 🔄 longtail/rust/soleita
- 🔄 longtail/rust/coldmail
- 🔄 longtail/rust/chainstay
- 🔄 longtail/rust/brightideas
- 🔄 longtail/rust/py-ports
- 🔄 longtail/rust/shinder_mcowls

## Wave 4 — big Rust systems (Tier A, careful)

**8 parallel workers active (max useful parallelism — coordinator integrates).**
Worker slices (disjoint — no two workers share a repo):

| Worker | Slice | Repos |
|---|---|---|
| wave-2 | security suite | security/vault, cute-e2ee, airgap-toolkit, redteam, threatmodel, ir-runner, backup-crypto, sec-organelles (8) ✅ DONE |
| wave-3 | longtail Rust | percyphonai, percyphon, diogenes-kernel, soleita (codon collision: `sl` taken by sec-organelles — soleita must rename), coldmail, chainstay, brightideas, py-ports, shinder_mcowls (9) 🔄 |
| wave-4a | big systems A | lucidota-core, canon, wreck, noter, adhkey, gis, krampus-express, indy-reads, dispatch-fabric (9) 🔄 |
| wave-4b1 | big systems B1 | litebox-organelle-host (verify), organelle/factory (verify), lanectl, shambhala, park-send-wreck (5) 🔄 |
| wave-4b2 | big systems B2 | proof-ledger/rs, mcp-servers/experiment-desk, cutecity-git/lucidota, litebox/litebox (Tier C declared) (4) 🔄 |
| wave-5 | Python/mixed | compute, proof-ledger, exchange, dogfood, cutecity, batch-compile, bin, verifier-mission (8) 🔄 |
| wave-7a | remotes A | mFSpx/diogenes, mFSpx/mneme (2) 🔄 |
| wave-7b | remotes B | mFSpx/legal_authority_system, mfspx/doggystyle (2) 🔄 |

Done: pilot (ledger-graph) ✅ · wave-1 (6) ✅ · wave-6 (2) ✅ = 9/56. In flight: 47.
Reassignment rule: a worker that finishes its slice early gets the next remaining slice — keep all 8 hot until done.

### Wave 4a — big systems A (Tier A, careful) 🔄 IN FLIGHT
- 🔄 lucidota-core
- 🔄 canon
- 🔄 wreck
- 🔄 noter
- 🔄 adhkey
- 🔄 gis
- 🔄 krampus-express
- 🔄 indy-reads (12GB — capability units only, no data migration)
- 🔄 dispatch-fabric (worktrees excluded)

### Wave 4b-1 — big systems B1 🔄 IN FLIGHT
- 🔄 litebox-organelle-host (verify existing host experiment, likely already conformant)
- 🔄 organelle/factory (verify)
- 🔄 lanectl
- 🔄 shambhala
- 🔄 park-send-wreck

### Wave 4b-2 — big systems B2 🔄 IN FLIGHT
- 🔄 proof-ledger/rs (nested; parent proof-ledger is Tier B)
- 🔄 mcp-servers/experiment-desk
- 🔄 cutecity-git/lucidota
- 🔄 litebox/litebox (upstream fork — Tier C declared, do not re-architect upstream)

## Wave 5 — Python/mixed (Tier B, surface adapters) 🔄 IN FLIGHT
- 🔄 compute
- 🔄 proof-ledger (parent; rs nested is Tier A)
- 🔄 exchange
- 🔄 dogfood
- 🔄 cutecity
- 🔄 batch-compile
- 🔄 bin (scripts — one manifest per script group)
- 🔄 verifier-mission

## Wave 6 — declared (Tier C)
- ✅ system-ontology (docs) — tier-C — commit f319f62 — 15 contracts (ontology primitives), valence candidate, manifest validated vs schema
- ✅ free-stack (docs) — tier-C — commit 8546f9d — 5 contracts (stack layers), valence candidate, manifest validated vs schema

## Wave 7 — remote (clone, migrate, PR/push per repo policy)

Split across two workers (disjoint):
- 🔄 wave-7a: mFSpx/diogenes (GitHub), mFSpx/mneme (GitHub)
- 🔄 wave-7b: mFSpx/legal_authority_system (GitHub), mfspx/doggystyle (GitLab)
Push policy: push only if clean and safe; never force-push; flag risky pushes.

## Excluded
- 🚫 dispatch-fabric worktrees (38 wt-* dirs — not repos)
- 🚫 .scratch/capnweb, .scratch/cfos-v4, scratch/rec1-tmp (scratch)
- 🚫 organelles/ itself (is the substrate)

## Rules (every wave)
1. Rust-first for new code; adapters thin.
2. Existing tests stay green — if they can't run here, record why, don't fake it.
3. Never destructive: no reset/stash/clean/force-push. Selective staging for dirty trees.
4. One commit per repo: `organelle-migration: <repo> tier-<A|B|C>`.
5. Update this file per repo.
