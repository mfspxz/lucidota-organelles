# WAVE 7b RESULTS — organelle migration, remote repos (2026-10-10)

Worker: wave-7b. Repos: `mFSpx/legal_authority_system` (GitHub), `mfspx/doggystyle`
(GitLab). Cloned to `~/workspace/remote-repos/<name>`. Corrected doctrine applied:
per repo, decompose ACTUAL capabilities; per unit, genuine map-or-design with
justification in per-repo `organelles/MAPPING.md`. `MIGRATION-STATUS.md` NOT touched
(coordinator-owned).

## Summary

| Repo | Tier | Units (codons) | Map/design | Tests | Commit | Push |
|---|---|---|---|---|---|---|
| legal_authority_system | C (declared) | legal-authority (`ls`) | bespoke-declared | n/a (no harness) | `e1d8ee7` | ❌ BLOCKED (see below) |
| doggystyle | B (surface-adapted) | doggystyle-ontology (`dg`), doggystyle-claims (`dc`), doggystyle-blobs (`db`) | all bespoke, all 12 refs checked+rejected | 44/44 pytest + 1/1 new adapter integration | `170631d` | ❌ BLOCKED (see below) |

## legal_authority_system — tier-C

- **Clone:** ok (`gh repo clone mFSpx/legal_authority_system`, commit `9355033`).
- **Finding:** the repo contains exactly two files — `README.md` (7 lines) + `LICENSE`.
  The brief's "engine code" does not exist. Tier C is the honest classification
  (standard: "Docs-only / unmigratable. Manifest only, valence Candidate/Disproven,
  no live registration").
- **Unit:** `legal-authority` (`ls`) — 4 declared contracts derived from the README's
  own words (`resolve_source`, `rank_authority`, `attach_provenance`, `cite`);
  write op gated on `tier-c-declared-only`; valence Candidate; zero-envelope
  execution.json (explicitly n/a, not ambiguous).
- **Map-or-design:** all 12 refs considered, none adopted — legal authority
  ranking + provenance discipline is domain adjudication; `ref-http-fetch`
  fetches bytes, `ref-scrape-extract` extracts text, neither adjudicates
  whether a source is an official statute.
- **Validation:** manifest VALID via `organelle-manifest::validate_manifest_json`
  (wave-7b validation lane).
- **Commit:** `e1d8ee7` `organelle-migration: legal_authority_system tier-C`
  (3 files, `organelles/` only).
- **Push:** ❌ **BLOCKED — 403** `remote: Permission to mFSpx/legal_authority_system.git
  denied to mfspxz`. The gh PAT authenticates as `mfspxz`, which lacks push
  permission on Zackary's `mFSpx/legal_authority_system`. Commit is local.
  **Needs Zackary:** grant push or push himself.

## doggystyle — tier-B

- **Clone:** ok (public GitLab URL, commit `0e852b5`).
- **Decomposition (from the code's actual seams, not the CLI list):**
  - `doggystyle-ontology` (`dg`) — V3 deterministic ontology graph kernel
    (genesis-locked policy, ≤5000 soul UUIDs, 12 trait slots, 88 domain slots,
    trinary state, temporal deltas, Valhalla burn archive): 20 ops + suspend/kill.
  - `doggystyle-claims` (`dc`) — V1 claim/evidence graph (scopes, nodes with
    modality/status, merkle snapshots + proofs, Ed25519 signatures, endpoint
    packets): 9 ops + suspend/kill.
  - `doggystyle-blobs` (`db`) — content-addressed blob store with optional AEAD:
    `put_blob`/`get_blob` + suspend/kill.
- **Map-or-design:** all three bespoke; all 12 refs genuinely considered and
  rejected with reasons (notably `ref-file-cas` for the blob unit — rejected
  because `LocalBlobStore` is an *encrypted evidence store* (AEAD, dual hashes,
  `BlobRef` metadata), not plain CAS; adopting would mean re-architecture or
  misrepresentation; and `ref-model-call` — a stub — rejected for
  `semantic_route` per the wave-1 ornament precedent: adopting a stub
  misrepresents deterministic embedding routing).
- **Exclusions (recorded in MAPPING.md):** `bench*` (measurement harness),
  `generate-fixture`/`load-fixture` (test tooling), `doctor`/`transparency`/`hash`
  (diagnostics), `grpc/kernel.proto` (design artifact; gRPC boundary explicitly
  unimplemented in Mark 2).
- **Tier B adapter (genuinely thin):**
  - `organelles/adapter/dogd.py` — unix-socket JSON-lines daemon; dispatch table
    `(codon, op) -> kernel.cli.cmd_*`; no new computation. Two documented
    transport adaptations: base64 for blob bytes; `OP_DEFAULTS` replays the CLI
    parser's own non-None defaults (AST-audited, since the adapter bypasses argparse).
  - `organelles/adapter/shim/` — Rust `ShimOrganelle`: validates manifest at load,
    forwards one JSON line per call; authority/receipts/kill/envelope stay on the
    host; only shim-side enforcement is the wall-clock timeout. `suspend`/`kill`
    forwarded as control frames (daemon is stateless: suspend = no-op ack,
    kill = drain + exit 0).
  - Secrets: `secret_env` carries only variable NAMES; AEAD master key read from
    home-local `.env`/`CLAIM_KERNEL_MASTER_KEY_B64` exactly as the CLI does.
    Secret-scrub gate clean.
- **Tests:** pre-existing 44/44 pytest green (kernel untouched); new
  `adapter_roundtrip` integration test green — spawns real `dogd.py`, registers
  all 3 units on a running `organelle-host`, exercises dg/dc/db ops end-to-end,
  proves Write-without-capability is denied + receipted, `verify_chain` green
  (incl. after kill), suspend + kill each receipted, daemon **actually exits**
  on kill (asserted via process wait).
- **Validation:** all 3 manifests VALID via `organelle-manifest::validate_manifest_json`.
- **Codons** `dg`/`dc`/`db` (+ `ls`): checked unique against all 12 refs and all
  migrated repos — no collisions.
- **Commit:** `170631d` `organelle-migration: doggystyle tier-B`
  (14 files, `organelles/` only; `target/` + `__pycache__` excluded via new `.gitignore`s).
- **Push:** ❌ **BLOCKED — GitLab auth failed** (`HTTP Basic: Access denied`).
  No GitLab credential is configured on this VM (only the public clone URL was
  provided). Commit is local. **Needs Zackary:** GitLab push auth or push himself.

## Validation lane

`~/workspace/organelles/waves/wave-7b/validate/` — tiny Rust binary calling
`organelle-manifest::validate_manifest_json` over manifest paths; used for all
4 manifests (all VALID). Kept as wave scratch for reuse by other workers.

## Notes for the coordinator

1. **Both pushes blocked, both commits local** — the wave's push policy held
   (no force-push, no risky auth attempts). Zackary action needed for both.
2. `dogd.py`'s `OP_DEFAULTS` is the one maintenance-sensitive spot: if upstream
   adds CLI args with non-None defaults, the table needs the new entries (the
   AST-audit method is documented in MAPPING.md).
3. doggystyle's `kernel/__pycache__/` + `tests/__pycache__/` + shim `target/`
   are build artifacts left untracked/ignored, not committed.
4. No `MIGRATION-STATUS.md` edits (coordinator-owned). No destructive git ops used
   anywhere (`git restore --staged` used once to unstage an accidentally-staged
   `target/` dir — non-destructive).
