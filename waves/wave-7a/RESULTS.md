# Wave 7a — RESULTS (remote repos: diogenes, mneme)

Completed 2026-10-10. Corrected doctrine: per repo, decompose ACTUAL
capabilities; per unit, genuine map-or-design. No blind templating.

## diogenes (GitHub mFSpx/diogenes) — Tier B

- **Clone:** clean, HEAD 6c4acc2e ("Case file workflow: 7 PostgREST Big Board views").
- **Capability units (6):**
  - `diogenes-spine` (`ds`) — Postgres-backed content-addressed ETL: walk→sha256→chunk→date/entity extract→persist + ingest_run bookkeeping. **Bespoke** (Postgres CAS ≠ ref-file-cas filesystem CAS). Write, Candidate.
  - `diogenes-router` (`dr`) — local-first model router (bge-m3 embed / modernbert NER / smoldocling docparse, Groq+llama.cpp failover, backoff, JSONL telemetry). **Adopts `ref-model-call` (`mc`) for the inference legs**; failover policy bespoke. ExternalEffect, Candidate.
  - `diogenes-membrane` (`dm`) — deterministic intake: RETE regex fast-path, CPU semantic-neighbor fallback, minhash RAG quotes, 4-lane output weaving. **Bespoke**. ReadOnly, Proven.
  - `diogenes-fairyfuse` (`df`) — deterministic sha256→ternary-vector command router; honest symbolic mode when weights/kernel missing. **Bespoke**. ReadOnly, Proven.
  - `diogenes-rfcs` (`rf`) — Tier C declared: 21 RFCs (RFC-000..RFC-200 incl. RFC-010 SLOP-LAWS), project brain, durable workflow contracts. Candidate.
  - `diogenes-workers` (`wk`) — Tier C declared family: 719 scripts/*.py entrypoints. Candidate.
- **Reference check:** all 12 considered; `ref-model-call` adopted for router LLM legs; `ref-file-cas` rejected on storage-contract grounds (documented in MAPPING.md).
- **Tests:** 6/6 manifests validate against manifest-json-schema.json; Tier B adapter (`organelles/adapter.py`, JSON-lines) live-tested 3/3 (df.route symbolic, dm.route_inbound_text RETE path, dm.rag_exact_quotes). Repo pytest suite: DB_BLOCKED per the repo's own test-gating law (Postgres is source of truth; gate unavailable) — recorded, not faked.
- **Commit:** `0b369189` "organelle-migration: diogenes tier-B" (9 files added, nothing modified).
- **Push:** BLOCKED — `remote: Permission to mFSpx/diogenes.git denied to mfspxz` (403). Commit is local. Zack or an authorized writer must push.
- **Codons:** ds dr dm df rf wk — unique vs full registry (checked 2026-10-10).

## mneme (GitHub mFSpx/mneme) — Tier A

- **Clone:** clean, HEAD d7c11d6 ("feat: FSM230 wired for reflection critique").
- **Capability units (4, all native `Organelle` trait impls in `src/organelle.rs`):**
  - `mneme-memory` (`mm`) — SurrealDB engine: Letta blocks (write/read/persona-edit), Voyager skills (register/retrieve-by-embedding/verify/record-result), Reflexion episodes (record/recall/reinforce), MARS decay count, Voyager curriculum (add/next/complete/stats). **Bespoke** (one indivisible connection; embedding retrieval ≠ kv-store). Write, Candidate, cap `mneme.memory`.
  - `mneme-exec` (`mx`) — skill subprocess execution (bash/sh, surrealql). **Bespoke** (no ref organelle spawns processes). ExternalEffect, Candidate, cap `mneme.exec`.
  - `mneme-critic` (`mn`) — pure deterministic audit fns: Voyager critic evaluate, Reflexion reflection prompt, Letta pack/importance, Mem0 hybrid score. **Bespoke**. ReadOnly, Proven.
  - `mneme-agent` (`ma`) — full metacognitive cycle (Observe→…→Learn). **Bespoke orchestrator + adopts `ref-model-call` (`mc.chat`) for the Bonsai/FSM230 LLM edge.** ExternalEffect, Candidate, cap `mneme.agent`.
- **Excluded (recorded in MAPPING.md):** `ablation.rs` (run_task is `todo!()` — dead harness), `benchmark.rs`/`LiveTest`/CLI (dev harnesses).
- **Tests:** full `cargo test --offline`: **19/19 green** (12 pre-existing + 7 new organelle tests: `static_manifests_validate` 4/4, `rust_manifests_match_static_json` — Rust manifest() == organelles/*.json, `codons_unique_against_ref_set`, `critic_registers_and_scores_through_host` 5 ops, `exec_registers_and_runs_shell_through_host` real bash, `fail_closed_capability_gates` — denial without capability proven, `memory_manifest_registers_on_host`). Pre-existing suite untouched and green. SurrealDB/LLM-dependent ops (mm.*, ma.cycle) unverifiable here — no cluster/endpoints; valence Candidate, recorded not faked.
- **Commit:** `c61d14e` "organelle-migration: mneme tier-A" (src/organelle.rs new, main.rs + Cargo.toml/lock, organelles/ with 4 manifests + execution.json + MAPPING.md).
- **Push:** BLOCKED — `remote: Permission to mFSpx/mneme.git denied to mfspxz` (403). Commit is local. Zack or an authorized writer must push.
- **Codons:** mm mx mn ma — unique vs full registry (checked 2026-10-10).

## Codon registry delta (this wave)

New: ds dr dm df rf wk mm mx mn ma. All verified free against the pre-wave registry (refs fc gp hf hs jv kv la mc nt se to tt + migrated ad…yp + lg). No collisions.
