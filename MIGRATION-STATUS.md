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

## ⚠️ ACTIVE SECURITY WARNING (2026-10-11 — swarm round 3 R3-V4, STILL OPEN after repair)

**`organelles R3-V4 — reconciliation poisoning of the claim–defeat reconciliation organelle`**
(PROVEN by runnable probe: `dogfood/track-j/scratch/swarm/organelles/round3/src/bin/r3_v4_integrity.rs`).
An attacker with their own grant can forge claims, fabricate `SUPERSEDED_BY_BYPASS` of a real
claim with invented defeating probes, self-attest `CLASS_CLOSED` — and the organelle's own
`verify` reports `ok:true` over the poisoned book.

**Round-5 status:** lane-4 repair (organelles `fe82e79` — grant-bound store handles, probe
provenance, self-attestation refusal) RAISED THE ATTACK COST but **the full R3-V4 chain still
works end-to-end** (lane-5 retest `0ff03e7`, 11/11 green, 4 bypasses filed):
- **CR-1 CRITICAL:** `open-store` is self-service — any `claims.write` holder opens a grant for
  another operator's live book. Grant binds (caller, path) but authorizes no ownership.
- **CR-2 HIGH:** probe authenticity is hash-integrity only — a well-formed lying artifact
  still defeats a real claim (`reproduces_fixed_behavior` is a self-asserted boolean).
- **CR-3 HIGH:** self-attestation refusal is per-grant, not per-caller — unlimited self-service
  grants defeat it (record with grant 1, attest with grant 2).
- **CR-4 MEDIUM:** `verify` returns `ok:true` over the well-formed poisoned book (consequence).
**Round-6 addendum (panopticon round 22/24):** commit `4c50729` ("security: claim-reconciler
legacy-exemption closed", 2026-10-11 10:40 UTC) closed a SEPARATE bypass — verify()'s pre-grant
legacy exemption let a forged supersede entry without `artifact_path` pass `verify` with
`ok:true`; verify now fails closed (reproducer + regression tests, crate suite 38/38 green,
fix-claim falsification seq 270). This is a fail-closed hardening, NOT a CR-1..CR-4 closure.
**RULE until CR-1..CR-3 close: do NOT rely on claim-reconciler `verify`/CLASS_CLOSED outputs as
verification authority.** CR-1's fix (per-operator write roots vs book-ownership registry) is a
product decision queued for Zack (DECISION-REQUESTS.md DR-3). Workers: treat reconciler verdicts
as untrusted input, not proof.

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
- QA audit-2 (waves/qa-audit-2/RESULTS.md, read-only, 14 repos: waves 5/4b2/7b): FINDINGS — (1) **wave-5: 36 manifests INVALID** under authoritative `validate_manifest_json` (capability names use `:` e.g. `compute.pipeline:live`; substrate charset is `[a-z0-9._-]`). Fix worker dispatched: `:`→`.` + re-run tests + re-validate, one commit per repo. (2) proof-ledger/rs full-suite red on `t009_2_real_ledger_differential` — pre-existing test-hygiene defect (hardcoded 0-claims expectation vs live growing ~/ledger/ledger-0001.jsonl); py/rs differential itself is CLEAN; migration untouched; NOT a migration defect, left for the owning wave. (3) **New collision:** `so` = soleita (20:11 UTC) vs shambhala/sham-offline (21:30 UTC) — soleita wins; shambhala renamed so→sb (commit e8f725c, tests green). (4) Stale old codons in compute/dogfood execution.json + false "no collision" prose in experiment-desk/lucidota MAPPING.md — ALL FIXED (fix worker + coordinator commits e9c1fed, 6b88488). (5) One-commit rule: wave-5 repos have 2+ base commits (prior pass + corrected pass, same message); lucidota/litebox have 2 tier-C commits. **RULING: grandfathered, no squash** — history is append-only; recorded as approved exceptions like ledger-graph's 2nd commit. **Wave-5 charset fix LANDED:** 35 manifests `:`→`.` in capability names (86 replacements), 52/52 manifests VALID under authoritative validator, all 8 repos 5/5 tests green, one commit per repo (`organelle-migration: <repo> capability charset fix (: -> .)`). (6) Verified clean: all 14 MAPPING.md genuine, no secrets, no destructive git ops, qa-audit-1 F3 fixed, wave-5's deferred host registration honestly reported not faked. doggystyle rated strongest migration in batch.

## Wave 3 — longtail Rust (Tier A) ✅ DONE (2026-10-10)
- ✅ coldmail — tier-A — commit d2f0bea — codon `cm` — parse_contacts/render/queue (pure). ref-text-transform + ref-notify genuinely rejected (contact-aware mail-merge; sending NOT wired — `send_wired: false`). 7/7 green.
- ✅ py-ports — tier-A — commit c4d651f — codon `yp` — 12-per-category priority selection + URL dedup. ref-json-validate/ref-scrape-extract rejected. 3/3 green.
- ✅ soleita — tier-A — commit 525c5db — codon `so` (renamed sl→so: sec-organelles owns `sl`) — listing/net/pack + fs-backed SalesLedger (record_sale, ledger_total; `..` path rejection). ref-ledger-append rejected (typed domain ledger vs plain append). 10/10 green.
- ✅ brightideas — tier-A — commit 0676ebe — codon `bi` — score/intake/triage/backlog_due/by_route. **Caught blind templating in skeleton:** routes op hardcoded thresholds instead of calling real `route_for` — fixed + boundary tests. ref-model-call rejected ("No model judging" — deterministic rubric). 6/6 green.
- ✅ shinder_mcowls — tier-A — commit ed4631b — codon `sm` — generate_character/build_pack + append-only LoreBible (namespaced ids, duplicate refusal, explicit retcons). ref-kv-store rejected (id-namespace + retcon discipline). 10/10 green.
- ✅ diogenes-kernel — tier-A — commit 491bc4d — TWO organelles: `diogenes-kernel` (`dk`, pure: mutation_allows/claim_new/slop_audit/packet_verify/min_authority) + `diogenes-workflow` (`dw`, RFC-060 ABSURD store: enqueue/lease/start/succeed/fail/dead_letter). Split at the statefulness seam. 26/26 green.
- ✅ chainstay — tier-A — commit de613ee — TWO organelles: `chainstay` (`cs`, 11 pure rule ops) + `chainstay-store` (`ct`, 8 store ops incl. bunker as JSON in AUX). ref-ledger-append rejected (redb event-sourced DB vs plain append). 34/34 green.
- ✅ percyphonai — tier-A — commit 527b382 — THREE organelles: `percyphon-forge` (`pf`), `percyphon-kronenberg` (`pk`, copy-on-borrow FACE/VOICE/WORDS/STYLE/HANDS/MIND), `percyphon-custody` (`pu`, mint/hydrate/archival refusal/verify_receipts). ref-kv-store/ref-ledger-append/ref-hash-seal all genuinely rejected (custody chains, Valhalla semantics). 48/48 green.
- ✅ percyphon — tier-A — commits 1f2862e+4eca3ca — THREE organelles `pg`/`pq`/`px` (names disambiguated from percyphonai; self-caught collision `pv`→`px`: security/provenance owns `pv`). Variant differences recorded (audited `restore` op, ReceiptLog). 38/38 green.
- 15 new codons verified unique; 0/12 refs adopted (all rejections justified per-repo in MAPPING.md). Results: waves/wave-3/RESULTS.md
- 🔄 longtail/rust/shinder_mcowls

## Wave 4 — big Rust systems (Tier A, careful)

**8 parallel workers active (max useful parallelism — coordinator integrates).**
Worker slices (disjoint — no two workers share a repo):

| Worker | Slice | Repos |
|---|---|---|
| wave-2 | security suite | security/vault, cute-e2ee, airgap-toolkit, redteam, threatmodel, ir-runner, backup-crypto, sec-organelles (8) ✅ DONE |
| wave-3 | longtail Rust | percyphonai, percyphon, diogenes-kernel, soleita, coldmail, chainstay, brightideas, py-ports, shinder_mcowls (9) ✅ |
| wave-4a | big systems A | lucidota-core, gis, krampus-express, indy-reads, dispatch-fabric (5) ✅ |
| wave-4c | big systems C | canon, wreck, noter, adhkey (4) ✅ |
| wave-4b1 | big systems B1 | litebox-organelle-host, organelle/factory, lanectl, shambhala, park-send-wreck (5) ✅ |
| wave-4b2 | big systems B2 | proof-ledger/rs, mcp-servers/experiment-desk, cutecity-git/lucidota, litebox/litebox (Tier C declared) (4) ✅ |
| wave-5 | Python/mixed | compute, proof-ledger, exchange, dogfood, cutecity, batch-compile, bin, verifier-mission (8) 🔄 |
| wave-7a | remotes A | mFSpx/diogenes, mFSpx/mneme (2) ✅ (account LOST — read-only, no pushes) |
| wave-7b | remotes B | mFSpx/legal_authority_system, mfspx/doggystyle (2) ✅ (mFSpx lost — read-only; doggystyle push BLOCKED, flagged) |

Done: pilot (ledger-graph) ✅ · wave-1 (6) ✅ · wave-6 (2) ✅ = 9/56. In flight: 47.
Reassignment rule: a worker that finishes its slice early gets the next remaining slice — keep all 8 hot until done.

### Wave 4a — big systems A (Tier A, careful) ✅ DONE (2026-10-10/11)
- ✅ lucidota-core — tier-A — commit c0e49ea — codon `ld` — 13 ops. 36/36 green.
- ✅ gis — tier-A — commits 11500cc+a021fab — 3 organelles (`ge`/`gi`/`gj`; `gr`→`gj` collision with park-send-wreck, earlier). 5/5 organelle + 27 workspace green.
- ✅ krampus-express — tier-A — commits 4e04d96+737184d — 5 organelles (`kx`/`kn`/`ks`/`kd`/`ke`). 9/9 organelle + 80 workspace green.
- ✅ indy-reads — tier-A — commit 07a6bd4 — 5 organelles (`iv`/`ig`/`im`/`ia`/`ie`). 8/8 organelle + 191 lib green.
- ✅ dispatch-fabric — tier-A — commits f3ecb35+a021fab — 4 organelles (`fp`/`fe`/`fv`/`fb`; `fw`→`fb` + `fx`→`fe` collisions with factory, earlier). 5/5 organelle green.
- Worker interrupted before writing final commit; coordinator verified + committed dispatch-fabric (f3ecb35 was already landed) + repaired CallOk breakage in canon/wreck/noter (substrate P0/P1 API change).
- Results: waves/wave-4a/RESULTS.md

### Wave 4c — big systems C (Tier A, careful) ✅ DONE (2026-10-10)
- ✅ canon — tier-A — commit f727745 — codon `ca` — 6 ops (verify/get/search/active/add/snapshot). ref-ledger-append rejected (wrong layer — would bypass validate→dedup→chain→lock). 35/35 green.
- ✅ wreck — tier-A — commit 7db599b — codons `wg`+`wp` (wreck-govern + wreck-ports) — adopted wave-4a's 2-organelle design; parallel 5-way decomposition retired to scratch (not deleted). 123/123 green.
- ✅ adhkey — tier-A — commits 1158e19+e14b0fd — 4 organelles (`ak`/`as`/`lz`/`mu`) — 2 post-commit collisions resolved (mx→mu, lx→lz); also repaired pre-existing organelle-test breakage (host.call() returns CallOk, tests now index .output). 188 tests green.
- ✅ noter — tier-A — commit b839d5c — 3 organelles (`no`/`ne`/`na`; `nt`→`no` because `nt` collides with ref-notify). 133 tests green.
- Substrate incident: hardening worker's hmac 0.13 broke downstream builds ~22:28 UTC; wave-4c worker fixed minimally (→0.12). Parent should confirm with hardening coordinator.
- Results: waves/wave-4c/RESULTS.md

### Wave 4b-1 — big systems B1 ✅ DONE (2026-10-10)
- ✅ lanectl — tier-A — commit 8335ce6 — 10 organelles (+ 12 nested crate commits)
- ✅ shambhala — tier-A — commits 004ef6c+e8f725c — 11 organelles — codon `so`→`sb` (collision with soleita, earlier)
- ✅ park-send-wreck — tier-A — commits 2ae4c1a+02d22e7 — 14 organelles — 3 post-commit collisions resolved (ck→qk, ct→qt, pg→qp); 209 tests green
- ✅ organelle/factory — tier-A+B — commit 7d4a090 — 4 organelles (`fx`/`fa`/`fw`/`fj`) — 54/54 scheduler + 15/15 workers tests green
- ✅ litebox-organelle-host — tier-A — commit a40e6fc — codon `lh` — verified vs standard (minimal gap fixes, main.rs untouched)
- Results: waves/wave-4b1/RESULTS.md

### Wave 4b-2 — big systems B2 ✅ DONE (2026-10-10)
- ✅ proof-ledger/rs — tier-A — commit 2933879 — codon `pl` — 14 ops over the 13 `pl` subcommands (audit/audit_reprobe honestly split: reprobe executes probes = ExternalEffect). Zero ref adoptions (all 12 genuinely considered and rejected: PL-1 evidence records + receipt-envelope spec + probe execution are bespoke). 3/3 organelle tests + full repo suite 92/92 green. Binary untouched (wasm-gated).
- ✅ mcp-servers/experiment-desk — tier-B (brief said A; code is pure Python — corrected) — commit 33254f4 — codon `ex` (renamed ed→ex, commit 0072b91; `ed` belongs to exchange, earlier) — 13 ops = the 13 MCP tools 1:1, manifest generated from the server's own TOOLS list. Thin Rust adapter → persistent server.py stdio child. 3/3 + attest_tool_test.py 20/20 green.
- ✅ cutecity-git/lucidota — tier-C analysis — commit 399842b — codon `lu` (renamed lc→lu, commit f9b32ee; `lc` belongs to cutecity, earlier). Finding: Python/JS tools are stale snapshot copies of live originals (migrating = duplicate stale organelles); corpus is the unique content. Existing Tier C manifest stands + MAPPING.md records where each live tool migrates.
- ✅ litebox/litebox — tier-C — commit 11f1550 — manifest already existed (verified, not duplicated). MAPPING.md added: no map-or-design applies (LiteBox is the sandbox substrate itself, the §19/§23 source of the standard). Notes the describe-op over-gating wart, left as-is per no-rearchitect rule.

## Wave 5 — Python/mixed (Tier B, surface adapters) ✅ DONE (2026-10-10)
- ✅ compute — tier-B — commits 9517786+1cb6d8c — 14 real stages — 5/5 green (dispatch 27/27, registry 28/28, governor 19/19 preserved). **3 genuine reference adoptions**: ledger.record→ref-ledger-append, integrity.seal→ref-hash-seal, adapters.execute→ref-model-call.
- ✅ proof-ledger (parent) — tier-B — commit 6e4abc0 — 3 units — 5/5 green.
- ✅ exchange — tier-B — commits 45923ea+54ec4ab — 10 units — 5/5 green.
- ✅ dogfood — tier-B — commit 5b62fd2 — 5 track units — 5/5 green (found pre-existing defect: track-b missing status.py).
- ✅ cutecity — tier-B — commit fbd593b — 5 check/gate units — 5/5 green.
- ✅ batch-compile — tier-B — commit 85e45ff — 1 unit (3 blind splits consolidated) — 5/5 green.
- ✅ verifier-mission — tier-B — commit 9ab8ce1 — 6 lane units (2 deliberate exclusions recorded) — 5/5 green.
- ✅ bin — tier-B — commit 281722e — 8 script-group units — 5/5 green.
- Also repaired a sibling lane's doctrine violations (shared codons, zero MAPPING.md, fake units). 67 manifests workspace-wide now codon-unique. Open (recorded, not faked): Tier-B live host registration + kill-drill receipts need a host-side exec surface. Results: waves/wave-5/RESULTS.md

## Wave 6 — declared (Tier C)
- ✅ system-ontology (docs) — tier-C — commit f319f62 — 15 contracts (ontology primitives), valence candidate, manifest validated vs schema
- ✅ free-stack (docs) — tier-C — commit 8546f9d — 5 contracts (stack layers), valence candidate, manifest validated vs schema

## Wave 7 — remote (clone, migrate, PR/push per repo policy)

Split across two workers (disjoint):
- 🔄 wave-7a: mFSpx/diogenes (GitHub), mFSpx/mneme (GitHub) ✅ DONE (2026-10-10) — account LOST, read-only history, no pushes (see below)
- ✅ wave-7b: mFSpx/legal_authority_system (GitHub), mfspx/doggystyle (GitLab) — DONE (2026-10-10) — mFSpx account LOST (read-only); doggystyle push BLOCKED (see below)
Push policy: push only if clean and safe; never force-push; flag risky pushes. **Account correction (Zack, 2026-10-10): mFSpx is LOST — never push to those 3 repos; new GitHub account mfspxz is the retarget for remote pushes. GitLab mfspx/doggystyle unchanged.**
- ✅ diogenes — tier-B — commit 0b369189 — 6 organelles: `diogenes-spine` (`ds`, Postgres CAS-ETL), `diogenes-router` (`dr`, local-first model router), `diogenes-membrane` (`dm`, deterministic intake + 4-lane weave), `diogenes-fairyfuse` (`df`, sha256→ternary command router), `diogenes-rfcs` (`rf`, Tier C declared 21-RFC doctrine corpus), `diogenes-workers` (`wk`, Tier C declared 719-script family). **Genuine ref adoption:** `ref-model-call` for the router's inference legs; `ref-file-cas` REJECTED for the spine (Postgres rows ≠ filesystem CAS). Repo AGENTS.md honored (originals untouched); DB-gated pytest recorded-not-faked. 10/10 codons verified unique. **mFSpx account LOST (2026-10-10) — read-only history, no pushes ever.**
- ✅ mneme — tier-A — commit c61d14e — 4 native organelles: `mneme-memory` (`mm`, SurrealDB engine, 15 ops), `mneme-exec` (`mx`, skill subprocess), `mneme-critic` (`mn`, pure deterministic audit, Proven), `mneme-agent` (`ma`, metacognitive cycle — **adopts `ref-model-call`** for the Bonsai/FSM230 edge). Ablation (dead `todo!()`) + benchmark/LiveTest/CLI honestly excluded. 19/19 cargo tests green; SurrealDB/LLM ops Candidate (no cluster here — recorded not faked). **mFSpx account LOST (2026-10-10) — read-only history, no pushes ever.**
- ⚠️ legal_authority_system — tier-C — commit e1d8ee7 — codon `ls` — finding: repo holds exactly two files (README 7 lines + LICENSE); "engine code" from the brief does not exist. 4 declared contracts from the README's own words. Manifest VALID. **mFSpx account LOST (2026-10-10) — read-only history, no pushes ever.**
- ✅ doggystyle — tier-B — commit 170631d — codons `dg` (ontology, 20 ops) / `ck` (claims, 9 ops) / `bl` (blobs, 2 ops) — renamed db→bl, dc→ck (commit d6c9e76; both belonged to dogfood, earlier). Real Python kernel (5,671 lines) behind genuinely thin adapter: unix-socket JSON-lines daemon dispatching straight to kernel.cli.cmd_* (zero new computation; AST-audited). ref-file-cas considered and REJECTED with reasons (encrypted evidence store ≠ plain CAS). Pre-existing 44/44 pytest green + new adapter_roundtrip integration test green (real daemon, verify_chain green incl. after kill, daemon actually exits on kill). **Push BLOCKED — GitLab auth failed (no GitLab credential on VM). Needs Zackary.**

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
