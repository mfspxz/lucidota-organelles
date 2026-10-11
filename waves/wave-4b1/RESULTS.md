# Wave 4b-1 — RESULTS

Organelle migration, corrected doctrine (Zack's law): per-repo real capability
analysis, genuine map-or-design per unit, Rust-first, tests green, one commit
per repo. Repos 1–3 were completed by the prior worker (recorded here);
repos 4–5 finished this wave by the current worker.

## 1. lanectl — Tier A ✅ (prior worker)

- **Commit:** `8335ce6` — `organelle-migration: lanectl tier-A`.
- **Units (10, all bespoke native):** provider-registry (`pr`),
  enrollment-checkpoints (`ec`), credential-vault (`cv`),
  provisioning-engine (`pe`), quota-accounting (`qa`), cost-governor (`cg`),
  health-monitor (`hm`), workload-scheduler (`ws`), provider-adapter (`pd`),
  evidence-ledger (`el`).
- **Decisions:** all bespoke; ref-organelle near-misses genuinely rejected
  (e.g. credential-vault stores REFERENCES not values — opposite trust shape
  to a vault; evidence-ledger is SQLite-chained vs ref-ledger-append's JSONL).
  Valence: 9 Candidate, 1 Proven (cost-governor, pure spend math).
  `crates/lane-core` (types only), the provider-adapter trait, and the CLI
  excluded as non-capabilities/facades.
- **Tests:** `cargo test --workspace` — 20 suites, 0 failures. Every organelle
  test proves register → call → verify_chain; capability gates fail closed.
- **Note:** HEAD has since moved on (brutal-audit, now `348d067`); the
  migration commit above is the wave record.

## 2. shambhala — Tier A ✅ (prior worker)

- **Commits:** `004ef6c` — `organelle-migration: shambhala tier-A`, plus
  `e8f725c` — `organelle-migration: shambhala codon so->sb` (collision with
  soleita caught and fixed same wave — the codon-uniqueness rule working).
- **Units (11, all bespoke native):** sham-astar (`sa`), sham-eta (`et`),
  sham-gesture (`sg`), sham-layers (`ly`), sham-odin-svc (`od`),
  sham-offline (`sb`), sham-ping (`vn`), sham-redteam (`st`),
  sham-route (`sr`), sham-vehicles (`vh`), sham-zone (`sz`).
- **Tests:** `cargo test --workspace` — all suites green.
- **Note:** HEAD has since moved on (brutal-audit, now `1d14450`).

## 3. park-send-wreck — Tier A ✅ (prior worker)

- **Commit:** `2ae4c1a` — `organelle-migration: park-send-wreck tier-A`.
- **Units (14, all bespoke native):** psw-archive (`ar`), psw-arts-crafts
  (`ac`), psw-cockpit (`ck`), psw-court (`ct`), psw-forge (`fg`), psw-lab
  (`lb`), psw-observatory (`ob`), psw-parity (`py`), psw-pipeline (`pp`),
  psw-quarantine (`qn`), psw-reconstruction (`rc`), psw-workbench (`wb`),
  pw-grid (`gr`), pw-plugin (`pg`).
- **Tests:** `cargo test --workspace` — all suites green.
- **Note:** HEAD has since moved on (brutal-audit, now `f35ac1d`).

## 4. organelle/factory — Tier A+B ✅ (this wave)

The prior worker wrote a `factory-plan` spec only; this wave did the real
decomposition and built the units.

- **Commit:** `7d4a090` — `organelle-migration: factory tier-A+B`.
- **Units (4, all bespoke):**
  - `factory-dispatch` (`fx`) — Tier A native. `scheduler/src/` pipeline:
    parse → partition → FIFO queue → isolated LLM worker subprocesses.
    Ops: plan (ReadOnly), dispatch_round (Write, cap `factory.dispatch`),
    queue_status (ReadOnly). Candidate.
  - `factory-assemble` (`fa`) — Tier A native. Collect unit sources → wire
    `build() -> Composed` → `cargo test` → `plan_hash` receipt. Ops: preview
    (ReadOnly), assemble (Write, cap `factory.assemble`). Candidate.
  - `factory-worker` (`fw`) — Tier B. `workers/worker.py` + `worktree.py` +
    provider adapters via `organelles/adapter.py` (JSON-lines bridge).
    Ops: run_assignment (ExternalEffect, cap `factory.worker`),
    build_prompt, worktree_create/collect/destroy. Candidate.
  - `factory-jobs` (`fj`) — Tier B. `ui/jobs.py` genesis-hash job store via
    the adapter. Ops: input_hash_of, create_job, append_progress, mark_done,
    get_status, collect_bundle, list_jobs. Candidate.
- **Decisions:** ref-model-call considered for the worker's LLM edge —
  rejected (the worker's computation is the bounded lifecycle + receipt, not
  the raw inference call); ref-kv-store/ref-ledger-append rejected for
  `fj` (domain job lifecycle, not generic primitives). Excluded: repo-root
  `src/lib.rs` (vestige superseded by `scheduler/`), `ui/server.py` +
  `ui/mcp_server.py` (facades), demo-job fixtures, empty `jobs/`,
  `worktrees/` scratch.
- **Tests:** `cargo test --offline` in `scheduler/` — **54/54 green**
  (40 unit + 4 pipeline + 10 new organelle tests: manifest-vs-JSON equality,
  register→plan→verify_chain, fail-closed dispatch, honest dispatch with
  grant — Failed outcome since no worker layer in sandbox, never faked —
  queue_status, assemble preview + honest error path, suspend/kill receipts,
  unknown-op denial). `pytest workers/test_workers.py` — **15/15 green**.
  Adapter smoke live: `fj/input_hash_of`, `fj/create_job`, `fw/build_prompt`
  3/3; unknown ops honestly rejected. All 4 manifests validate against
  `organelles/manifest-json-schema.json`.
- **Codons** `fx fa fw fj`: unique workspace-wide (167 manifests + 12 ref
  codons grepped).

## 5. litebox-organelle-host — Tier A ✅ with one deferred proof (this wave)

Verify-against-standard of the existing host experiment.

- **Commit:** `a40e6fc` — `organelle-migration: litebox-organelle-host tier-A`.
- **Units (1, bespoke):** `litebox-host` (`lh`) — the hardened sandboxed
  execution host itself (namespaces + seccomp + rlimits + watchdog outside,
  LiteBox inside; emits the PL-style receipt). Ops: describe (ReadOnly),
  run (ExternalEffect, cap `litebox.run`). Candidate (external security
  review open — the hardening coordinator's lane, not this migration).
- **Verification:** all six standard aspects conformant after minimal gap
  fixes — the gaps were the missing migration surface only (no `organelles/`
  dir, no trait impl, no registration). Fixed with: `src/lib.rs` (lib target;
  `src/main.rs` untouched), `src/organelle_impl.rs` (thin wrapper — `run`
  shells to the real binary, `describe` calls the real
  `sandbox::describe()`), `tests/organelle_registration.rs`,
  `organelles/litebox-host.manifest.json` + `.execution.json` + `MAPPING.md`.
  No re-architecture; sandbox logic untouched. Two manifest concepts
  documented (litebox *guest* manifest = op input; migration manifest = the
  unit's contract). No ref organelle is a sandboxed-execution host.
- **Dirty-tree discipline:** the hardening coordinator's uncommitted work
  (`src/main.rs`, `src/manifest.rs`, `src/guest.rs`, `src/sandbox.rs`,
  `threat-model.md`, `tests/hostile/*`, `tests/evidence/`) was left
  completely untouched and unstaged — the commit stages only the 7
  migration files.
- **Deferred (external, transient):** at commit time the `organelle-host`
  substrate had non-compiling refactor work in flight by the organelles
  hardening coordinator (uncommitted `crates/organelle-host/src/lib.rs`,
  edited 23:51 UTC). The migration code was verified against the last
  committed substrate (`f928bc6`) — all 14 public API items used are
  signature-stable there — and the test file mirrors the factory's green
  suite; the static manifest validates against the JSON schema. Full
  `cargo test --test organelle_registration` must be rerun once the
  substrate compiles again. Nothing faked: invocation proofs deferred,
  not asserted.
- **Codon** `lh`: unique workspace-wide.

## Wave codon delta

New: `fx fa fw fj lh` (this wave) + `cg cv ec el hm pd pe pr qa ws`
(lanectl) + `et ly od sa sb sg sr st sz vh vn` (shambhala) +
`ac ar ck ct fg gr lb ob pg pp py qn rc wb` (park-send-wreck).
Pre-existing collisions observed in the registry (not this wave's to fix):
`ck` (doggystyle-claims / psw-cockpit), `ct` (chainstay-store / psw-court),
`gr gv me pg wg` (misc duplicates), plus `compute/*` manifests duplicated
under `backups/compute-snapshots/`. This wave's 5 codons are clean.

## Notes

- `MIGRATION-STATUS.md` not touched (per wave instructions).
- Factory commit is migration-scoped: `scheduler/` core files, `ui/`,
  `demo-job/`, and the pre-existing `workers/worker.py` modification remain
  uncommitted builder work.
