# Wave 5 — Tier B organelle migration (corrected doctrine) — RESULTS

Date: 2026-10-10. Worker: wave-5 lane (subagent).
Doctrine: Zack's law — per repo, decompose ACTUAL capabilities; per unit,
genuine map-or-design (adopt a reference organelle only if the unit GENUINELY
IS it; otherwise purpose-built with own codon). Every mapping justified in
`<repo>/organelles/MAPPING.md`. Calibrated against ledger-graph.

## What the prior pass got wrong (fixed in this wave)

A sibling wave-5 pass had already committed `organelle-migration: <repo> tier-B`
for all 8 repos, but with two systematic doctrine violations:
1. **One shared codon per repo** (compute=`co`×14, exchange=`ex`×10,
   dogfood=`dg`×11, …) — 58 manifests, 8 identities. A host registry cannot
   distinguish organelles sharing a codon. Fixed: every unit has its own codon.
2. **No MAPPING.md anywhere** — the justification record (the whole job under
   the corrected doctrine) was missing entirely. Written for all 8 repos.
3. Plus per-repo defects: fake `dir`-mode units (dogfood 10/13 ops,
   verifier-mission lane-f/h), invented ops for non-code (dogfood track-a),
   blind splits with identical dispatch (batch-compile 3 manifests, 1 command),
   wrong-script dispatch (bin `verify`→sign-receipt.sh; proof-ledger bare `pl`
   with no subcommand), and a subprocess/CLI-flag adapter for compute whose
   modules are libraries with no CLIs (could never have worked).

Adapter shape (all repos): thin unix-socket JSON-lines shim. Replies mirror
`surface-unix` WireResponse (`id/ok/output/error` + `receipt`), with an
interim content-addressed receipt (`adapter-interim:sha256:<hex>`) until the
host issues chain receipts at registration. `suspend`/`kill` specials handled
in-adapter (drain/final-receipt). No business logic in any adapter.

## Per-repo results

### 1. bin — commit `281722e`
- **Units (8):** bin-backup `bk`, bin-checkpoint-compute `bc`,
  bin-coding-agents `be`, bin-graph-etl `bg`, bin-keyman-vault `bv`,
  bin-receipt-tools `br`, bin-secret-scrub `bs`, bin-shamir `bm` (new —
  SLIP-0039 split/combine was unmapped).
- **Map/design:** all 8 bespoke (backup rotation, checkpointing, env setup,
  graph ETL, key lifecycle, receipt envelope signing, secret scrubbing, secret
  sharing — none of the 12 refs fit).
- **Fixes:** `verify` op now dispatches to `verify-receipt.sh` (was
  `sign-receipt.sh`); multi-script groups got real per-script ops
  (etl_devgraph/etl_enrich/etl_watchdog, manage/export_vault/export_keepassxc,
  scrub/extract_scrub). Deliberate exclusions: `git` PATH shim, `shamir/venv`,
  `__pycache__`.
- **Adapter:** subprocess per (codon,op); `be/env` proven end-to-end (exit 0).
- **Tests:** 5/5 organelle tests green. No repo test suite (operator scripts).

### 2. cutecity — commit `fbd593b`
- **Units (5):** cutecity-a11y-audit `ay`, cutecity-launch-check `lc`,
  cutecity-tipjar-check `tj`, cutecity-uptime-check `up`, cutecity-voice-pass `vp`.
- **Map/design:** all 5 bespoke (a11y audit verdict ≠ scrape-extract; launch
  gate; Solana tip-jar verifier; uptime probe+ledger record; voice-pass
  staging gate). Uptime's ledger write noted as future host-layer delegation
  to `ref-ledger-append`, not the unit's identity.
- **Deliberate exclusions:** `voice-pass/` + `staging/` (data), `rust/`
  (Tier A, separate wave), binary blob, snapshot JSONs.
- **Adapter:** subprocess per (codon,op). **Tests:** 5/5 green.

### 3. batch-compile — commit `85e45ff`
- **Units (1, consolidated):** batch-compile-driver `bd` — the prior pass's
  3 manifests (driver/partitioner/parser) all ran the IDENTICAL driver
  command. The driver's real seam is its modes: ops `dry_run`, `shadow_run`,
  `live_run` (`live_run` = ExternalEffect, capability-gated). Superseded
  manifests `git rm`'d, consolidation recorded in MAPPING.md.
- **Map/design:** bespoke (mission work-order execution; computation lives in
  compute/pipeline — this is the mission-control invocation facet; delegates
  to `compute-pipeline/cp` once registered).
- **Adapter:** `pymod` mode (`python3 -m pipeline.driver`, cwd forced to
  `~/workspace/compute`), forced mode flags, positional WORK_ORDER.
  `dry_run` proven end-to-end: exit 0, plan materialized, sealed run receipt.
- **Tests:** 5/5 green.

### 4. proof-ledger (parent; `rs/` is Tier A, separate wave) — commit `6e4abc0`
- **Units (3):** proof-ledger-parity `pa` (ximpl py-vs-rs differential),
  proof-ledger-pl-cli `pc` (glue facet over the Tier-A `pl` binary:
  `wrap`/`verify`/`verify_chain`), proof-ledger-projection `pj`
  (RFC 6902 projection `build`/`check`).
- **Map/design:** all 3 bespoke. pl-cli's contract is the lucidota-receipt/1
  envelope — not `ref-hash-seal`.
- **Fixes:** pl-cli dispatch was bare `pl` for all 3 ops → now
  `pl envelope op=<op> k=v…` (the binary's real CLI); projection split into
  real `build`/`check` subcommand ops. Deliberate exclusions: `rs/`,
  versioned `*.v0` artifacts, `repro/`, `fixtures/`, `rust-nightly.sh`.
- **Adapter:** `kvenv` mode (k=v args) + `pysub` mode. `verify` proven
  end-to-end: fail-closed on an unsigned envelope (exit 1, "missing sig").
  `check` proven: exit 3 = honest "stale" verdict.
- **Tests:** 5/5 green.

### 5. verifier-mission — commit `9ab8ce1`
- **Units (6):** lane-a `va` (NVIDIA attestation adapter), lane-b `vb`
  (read-only discovery probe), lane-c `vc` (hardened subprocess executor),
  lane-d `vd` (K8s provenance doctrine mapping — Proven, pure/deterministic),
  lane-e `ve` (signed-attestation verifier), lane-g `vg` (witness-binding
  prototype — Candidate, stated honestly).
- **Map/design:** all 6 bespoke (attestation semantics ≠ hash seals;
  discovery ≠ extraction).
- **Fixes:** lane-f (STAGED library, no entrypoint) and lane-h (docs-only)
  were fake `dir`-mode units → recorded as deliberate exclusions, manifests
  removed. Also excluded: `integration-test-1.py`, receipts/evidence dirs.
- **Adapter:** subprocess per (codon,op). `vd/check_doctrine` proven
  end-to-end (exit 0). **Tests:** 5/5 green.

### 6. dogfood — commit `5b62fd2`
- **Units (5):** dogfood-track-b `db` (7 provider-benchmarking apps),
  dogfood-track-c `dc` (5 lifelog apps + ledger→Notion sync),
  dogfood-track-d `dd` (build-ledger + compose planner),
  dogfood-track-e `de` (47 proof-batch scripts, one `run_batch` op with batch
  selector), dogfood-track-k `dk` (gate/seal/collect drivers).
- **Map/design:** all 5 bespoke (app suites, not primitives; provider
  benchmarking ≠ `ref-model-call` — these apps *measure* providers).
- **Fixes:** 10 fake `dir`-mode ops replaced with real entrypoint dispatch
  (`pymain`: `python3 <app>/__main__.py`, cwd=app dir); track-a's invented
  gmail ops removed (apps exist only as work-order.txt — archived).
  Deliberate exclusions: track-a/f/g/h (no live code), track-i (Android
  build tree), track-j (test-double adapters), `_void-archive/`.
- **Adapter:** `pymain`/`py-template`/`py`/`sh` modes. `quota_alerts` proven
  end-to-end (exit 0, "0 alerts appended"). Found pre-existing app defect:
  `track-b/nvidia-status/__main__.py` imports missing `status.py` (broken
  upstream — adapter dispatches correctly; not an adapter bug).
- **Tests:** 5/5 green.

### 7. exchange — commit `45923ea`
- **Units (10):** ballot-cost-rollup `eb`, deploy-governor `eo`,
  discover-local `ed`, evidence-graph-sync `eg`, intelligence-per-byte `ei`,
  mint-claimant `ec`, mint-submit `em`, mint-worker `ew`,
  probe-harness `ep`, refresh-mirror `er`.
- **Map/design:** all 10 bespoke (Exchange-protocol ops with delegation
  fields/leases/capabilities ≠ generic http-fetch; minting protocol ≠
  hash-seal; edge-mirror ≠ kv-store).
- **Deliberate exclusions:** `fake-claimant.py` (test double), `tests/`,
  `migrations/`, `d1-mirror.db`/`evidence-graph.db` (data), `envelope.js`
  (single-file glue, noted).
- **Adapter:** subprocess per (codon,op). `discover` proven end-to-end:
  exit 0, real skill scan (9 scanned, 6 vault-connected found).
- **Tests:** 5/5 green.

### 8. compute — commit `9517786` (deepest; task explicitly demanded real stages)
- **Units (14):** compute-pipeline `cp`, compute-dispatch `cd`,
  compute-registry `cr`, compute-burn `cb`, compute-ledger `cl`,
  compute-envelope `ce`, compute-court `cc`, compute-router `co`,
  compute-governor `cg`, compute-integrity `ci`, compute-recovery `cv`,
  compute-merge `cm`, compute-verifier `cf`, compute-adapters `ca`.
- **Map/design — 3 genuine reference adoptions:**
  - `compute-ledger.record` → **adopt `ref-ledger-append` (`la`)** — the
    universal append-only execution ledger IS ledger-append (identity gate
    at ingest, envelope emission). `verify_envelopes` stays bespoke
    (two-tier strictness is domain-specific).
  - `compute-integrity.seal`/`verify_seal` → **adopt `ref-hash-seal` (`hs`)**
    — file sealing IS hash-sealing (sha256 + manifest sidecar, chain-head
    tracking for chained logs).
  - `compute-adapters.execute` → **adopt `ref-model-call` (`mc`)** —
    provider adapters ARE model-call endpoints (measured capabilities only).
  - The other 11 units bespoke (pipeline DAG driver, supervised dispatch
    state machine, sealed registry + feasibility filter, burn pacing,
    receipt envelope, DONE-gate court, deterministic router, governor,
    torn-write recovery, test-gated merge, independent verifier).
- **Fixes:** adapter rewritten — `call` mode (import module, call function
  in-process with mechanical dataclass coercion), `pymod` (pipeline driver),
  `subproc` (merge.py's real CLI), `statusfile` (burn.STATUS.json). The old
  subprocess/CLI-flag dispatch could never have worked (the modules are
  libraries with no argparse). Added missing real stages the prior pass never
  mapped: pipeline, registry, envelope, adapters. Removed 4 dev-harness
  manifests + 1 stale rename duplicate (bench/boundary/gemini-gate/canon-e2e,
  independent-verifier). `burn.py::main` (long-running engine loop)
  deliberately not an op — exposed surface is `cycle` + `status`.
- **Proven end-to-end via adapter --once:** `cr/list` → 4 real registered
  sources; `ci/verify_seal` on registry.json → True (hashes match);
  `cp/dry_run` → exit 0, sealed run receipt.
- **Tests:** 5/5 organelle tests green; existing repo tests green —
  dispatch 27/27, registry 28/28, governor 19/19, envelope interop ALL OK
  (run as standalone scripts; they `sys.exit` at module level, not
  pytest-collectable).

## Cross-cutting notes

- **Codon registry (this wave):** bin bk/bc/be/bg/bv/br/bs/bm ·
  cutecity ay/lc/tj/up/vp · batch-compile bd · proof-ledger pa/pc/pj ·
  verifier-mission va/vb/vc/vd/ve/vg · dogfood db/dc/dd/de/dk ·
  exchange eb/eo/ed/eg/ei/ek/em/ew/ep/er ·
  compute cp/cd/cr/cb/cl/ce/cc/co/gv/ci/cy/cm/cf/cx.
  All distinct; none collide with the 12 reference codons
  (kv/hf/tt/jv/hs/to/gp/la/nt/se/fc/mc) or the ledger-graph pilot (`lg`),
  or any other repo's organelles in the workspace (verified by scan —
  follow-up commits `1cb6d8c`/`54ec4ab` remapped 4 collisions with
  canon/lanectl manifests from other waves: ca→cx, cg→gv, cv→cy, ec→ek).
- **No secrets** in any manifest/adapter (capability names only; verified by
  `test_no_secrets` in every repo).
- **No destructive git ops** anywhere (no reset/stash/clean/force-push);
  selective staging per repo; dirty worktrees left untouched except the
  staged organelle files. Superseded manifests removed via `git rm` with the
  reason recorded in the repo's MAPPING.md (migration artifacts only — no
  user code removed anywhere).
- **MIGRATION-STATUS.md not touched** (coordinator updates centrally).
- **Registration bar (standard §host-registration):** manifests validate via
  the org-001 JSON schema; adapters proven dispatching real entrypoints with
  WireResponse-shaped replies + interim content-addressed receipts. Live
  host registration (native `Host::register` is Tier-A-only; Tier-B reverse
  dispatch needs a host-side exec surface) and kill-drill receipts remain
  coordinator-level follow-ups — recorded here, not faked.
- **Pre-existing defects found (not mine, reported not fixed):**
  dogfood `track-b/nvidia-status` missing `status.py` (broken import);
  compute `queue.py` assumed library-only (no CLI found).
