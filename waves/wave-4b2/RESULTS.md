# Wave 4b-2 results — big systems B2 (corrected doctrine)

Worker: wave-4b2 agent (depth 2). Date: 2026-10-10. All 4 repos done.

## 1. ~/workspace/proof-ledger/rs — Tier A (native) ✅

- **Capability units**: one organelle `pl` (codon `pl`, unique), 14 ops over the
  13 `pl` subcommands: claim, assert, verify, status, history, audit,
  audit_reprobe, export, inspect, checkpoint, envelope, repair, bundle, project.
  `audit`/`audit_reprobe` split is the honest seam (reprobe executes probes =
  ExternalEffect, vs read-only audit).
- **Map-or-design**: all 12 ref organelles considered, **none adopted** —
  genuinely bespoke. `ref-ledger-append` appends generic JSONL; pl appends are
  typed PL-1 evidence records (I7 dup-text, I4 orphan-assertion).
  `ref-hash-seal` seals values; the envelope is the `lucidota-receipt/1` spec.
  No ref organelle executes subprocesses/HTTP probes. `time::now_iso` and
  `canon.rs` deliberately excluded (internal plumbing, not capabilities).
  Precedent for one-organelle-many-ops: `lt-tools` (14 ops, codon `lt`).
- **Mutation classes**: Write → claim/assert/checkpoint/repair/bundle/project
  (capability `pl.write`); ExternalEffect → verify/audit_reprobe
  (`pl.probe`); ReadOnly → status/history/audit/export/inspect/envelope.
  bundle/project conservatively gate read-only sub-ops under Write.
  Valence: Candidate (stateful ledger + subprocess probes).
- **Implementation**: `src/organelle.rs` (new, wasm-gated in `lib.rs`;
  path deps on organelle-host/manifest under non-wasm target cfg so the WASM
  governor core is untouched). Delegates to the pl library — binary untouched.
  Manifest JSON generated from the Rust `manifest()` (single source of truth).
- **Tests**: 3/3 organelle tests green (manifest validates; Rust/JSON agree;
  full lifecycle claim→assert→verify(File probe)→status→…→repair(truncated
  tail)→verify_chain). Full repo suite: **92/92 green**. Existing pytest
  untouched (Rust repo).
- **Commit**: `2933879` — `organelle-migration: proof-ledger/rs tier-A`
  (selective staging; other waves' uncommitted changes left alone).

## 2. ~/workspace/mcp-servers/experiment-desk — Tier B (surface-adapted) ✅

- **Tier correction**: brief said "Tier A Rust"; the code is pure Python
  (zero `.rs` files). Corrected doctrine → **Tier B**, honestly labeled.
- **Capability units**: one organelle `experiment-desk` (codon `ed`, unique),
  13 ops = the server's 13 MCP tools 1:1 (dotted names kept). Manifest
  **generated from the server's own TOOLS list** — genuine mapping.
  Write classes: experiment.* → `experiment.write`; evidence ops →
  `evidence.write`; authority.mint_warrant/witness.attest → `authority.write`;
  status/ledger ReadOnly. Valence Candidate.
- **Map-or-design**: all 12 refs considered, none adopted (HMAC'd journal,
  hash-chained artifacts, kind-licensed resolve are bespoke). Only new code
  is the thin adapter — no computation reinvented.
- **Implementation**: `organelles/adapter/` Rust crate implements the
  `Organelle` trait, forwarding to a persistent `server.py` stdio child
  (initialize handshake, tools/call, MCP content envelope). Computation
  stays in Python. Secret policy: journal/authority keys server-managed,
  never in manifests.
- **Tests**: 3/3 adapter tests green (manifest validates; full epistemic
  flow create→preregister→start→observe→verify(VERIFIED)→resolve(ACCEPT)→
  status/ledger→refute→verify_chain). Existing `attest_tool_test.py`:
  **20/20 PASS** (server.py untouched).
- **Commit**: `33254f4` — `organelle-migration: mcp-servers/experiment-desk tier-B`.

## 3. ~/workspace/cutecity-git/lucidota — Tier C (analysis) ✅

- **Brief said "Tier A, analyze first" — analysis done**:
  - Zero Rust → Tier A impossible.
  - The Python/JS tools present are **stale snapshot copies** of live code:
    `system/geppetto-wave.py` DIFFERS from `~/workspace/system/geppetto-wave.py`
    (live); `mcp-servers/experiment-desk/server.py` DIFFERS from the live
    copy migrated Tier B this wave. Migrating them here would mint duplicate
    stale organelles. (Repo history: "snapshot 2026-10-06".)
  - Unique content = the corpus (336 md files, graphs, recovery) → the
    existing Tier C manifest (`ee2d6dc`, codon `lc`) stands, honest.
- **Deliverable**: `organelles/MAPPING.md` with the findings + where each
  live tool migrates. No code changes.
- **Commit**: `399842b` — `organelle-migration: lucidota tier-C (mapping analysis)`.

## 4. ~/workspace/litebox/litebox — Tier C (declared) ✅

- Manifest already existed from a prior worker (`fa8d38a`, codon `lx`,
  valence Candidate, no registration, no code changes) — verified, not
  duplicated.
- **Deliverable**: `organelles/MAPPING.md` — why no map-or-design applies
  (LiteBox is the sandbox substrate itself, the §19/§23 source of the
  migration standard; mapping it onto its own substrate would be circular).
  Notes the `describe`-op over-gating wart (inherits ExternalEffect;
  validates via inheritance) — left as-is per the no-rearchitect rule.
- **Commit**: `11f1550` — `organelle-migration: litebox tier-C (mapping)`.

## Cross-cutting

- **Codons**: `pl`, `ed` checked unique against the migration-wide registry
  (no collision with `pa/pc/pj/pv/fc/lg/lx/lc/…`).
- **Secrets**: no key material in any manifest (capability names only).
- **MIGRATION-STATUS.md**: untouched per instructions.
- **No destructive git ops**; selective staging only; other waves'
  uncommitted changes (proof-ledger/rs: canon/envelope/projection) left alone.
- **Open item for coordinator**: lucidota's *live* tool copies
  (`~/workspace/system/`, workers, remaining `~/workspace/mcp-servers/*`)
  still need their own Tier B waves — this wave deliberately did not migrate
  the snapshot copies.
