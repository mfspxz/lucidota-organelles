# QA AUDIT 2 — organelle migrations (waves 5, 4b2, 7b) + 8 codon-rename commits

Auditor: read-only verification against the done-bar
(`organelles/ORGANELLE-MIGRATION-STANDARD.md`). No repo was modified.
Date: 2026-10-10 (all commits are 2026-10-10 UTC).

## Method

1. Reused qa-audit-1's harness (`../qa-audit-1/manifest-check/target/release/qa-manifest-check`)
   over all of `~/workspace`: 133 manifests, `organelle-manifest::validate_manifest_json`
   per file, codon-uniqueness sweep.
2. `git log --grep=organelle-migration` / `git show --stat` / `git status` / `git reflog`
   per repo (commit count, message pattern, staging, destructive ops).
3. Re-ran test suites independently: 8× `pytest organelles/test_organelles.py`
   (wave-5), `cargo test --offline` (proof-ledger/rs, experiment-desk adapter,
   doggystyle shim), `attest_tool_test.py`, doggystyle `pytest tests/`.
4. Grepped manifests+adapters for secret values; read all 14 MAPPING.md files.
5. Verified each of the 8 rename commits: hash, stat, old-codon residue grep,
   new-codon uniqueness, tests.

## Headline

- **Wave-5 fails done-bar item (1) across all 8 repos: 36/36 of the wave's
  mutating manifests are INVALID under `validate_manifest_json`.** The worker
  validated against `manifest-json-schema.json` only, which has no
  capability-name pattern; the Rust validator rejects every
  `required_capability`/`granted_capability` using the `repo.unit:cap`
  convention (`:` is not in the `[a-z0-9._-]` charset). Reference organelles
  use dotted form (`ledger.write`). One-character-class fix, but it is a
  done-bar failure, not a nit: Write/ExternalEffect ops carry invalid gates.
- **Wave-4b2: 3/4 clean; proof-ledger/rs has a red test in the full suite**
  (`t009_2_real_ledger_differential` — py/rs differential over the live
  ledger; migration commit did not touch projection code, cause unknown).
- **Wave-7b: both clean** (push blockers are Zack's action, unchanged).
- **All 8 rename commits applied; new codons unique workspace-wide.**
  Stale old codons remain in 2 `execution.json` files + 2 MAPPING.md prose
  sections (details below).
- **New live codon collision found:** `so` = soleita vs shambhala/sham-offline
  (both committed). Plus scratch-scope `wg` (wave-4c scratch vs
  wreck/wreck-govern — scratch is excluded per the standard; informational).

## Per-repo verdict table

| Repo | Tier | (1) manifests validate | (2) host registration | (3) verify_chain | (4) kill receipts | (5) tests green | (6) one commit + pattern | (7) MAPPING.md genuine | (8) codon unique |
|---|---|---|---|---|---|---|---|---|---|
| compute (w5) | B | ❌ **12/14 INVALID** (capability `:` names) | ⚠️ deferred, honestly reported | ⚠️ interim adapter receipts only | ⚠️ adapter-handled, tested | ✅ 5/5 (re-measured) | ❌ **2 exact-pattern + uniqueness-fix + 2 renames** | ✅ genuine | ✅ |
| proof-ledger (w5) | B | ❌ **pl-cli INVALID** (`proof-ledger.pl-cli:wrap`) | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern** | ✅ genuine | ✅ |
| exchange (w5) | B | ❌ **8/10 INVALID** | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern + uniqueness-fix** | ✅ genuine | ✅ |
| dogfood (w5) | B | ❌ **3/5 INVALID** (track-c/e/k) | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern + rename** | ✅ genuine | ✅ |
| cutecity (w5) | B | ❌ **uptime-check INVALID** (`cutecity.uptime-check:external`) | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern** | ✅ genuine | ✅ |
| batch-compile (w5) | B | ❌ **driver INVALID** (`batch-compile.driver:live`) | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern** | ✅ genuine | ✅ |
| verifier-mission (w5) | B | ❌ **lane-a/c/g INVALID** (`verifier-mission.lane-a:attest` etc.) | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern + rename** | ✅ genuine | ✅ |
| bin (w5) | B | ❌ **7/8 INVALID** | ⚠️ deferred | ⚠️ interim | ⚠️ adapter-handled | ✅ 5/5 | ❌ **2 exact-pattern** | ✅ genuine | ✅ |
| proof-ledger/rs (4b2) | A | ✅ `pl`, 14 ops | ✅ real Host, register+call asserted | ✅ green in tests | ⚠️ declared (substrate F1 stands) | ⚠️ **3/3 organelle green; full suite 1 FAIL** (`t009_2`) | ✅ `organelle-migration: proof-ledger/rs tier-A` | ✅ genuine | ✅ `pl` |
| mcp-servers/experiment-desk (4b2) | B | ✅ `ex`, 13 ops | ✅ real Host via Rust adapter | ✅ green in tests | ⚠️ adapter/host | ✅ 3/3 adapter + 20/20 attest | ✅ base + clean rename | ✅ genuine (prose stale `ed`) | ✅ `ex` |
| cutecity-git/lucidota (4b2) | C | ✅ `lu`, 2 ops, Candidate | N/A (Tier C) | N/A | N/A | N/A | ⚠️ **2 tier-C commits** (one suffixed) | ✅ genuine (prose stale `lc`) | ✅ `lu` |
| litebox/litebox (4b2) | C | ✅ `lx`, Candidate | N/A (Tier C) | N/A | N/A | N/A | ⚠️ **2 tier-C commits** (one suffixed) | ✅ genuine | ✅ `lx` |
| remote-repos/legal_authority_system (7b) | C | ✅ `ls`, 4 ops, Candidate | N/A (Tier C) | N/A | N/A | N/A (no harness) | ✅ `organelle-migration: legal_authority_system tier-C` | ✅ genuine | ✅ `ls` |
| remote-repos/doggystyle (7b) | B | ✅ `dg`/`ck`/`bl`, all valid | ✅ real Host ×3, denial+receipts asserted | ✅ green incl. after kill | ✅ **kill receipted, daemon exit asserted** | ✅ 44/44 pytest + 1/1 shim | ✅ base + thorough rename | ✅ genuine | ✅ |

**Legend:** ✅ passes; ⚠️ partial / honestly-deferred; ❌ fails; N/A exempt per Tier C.

### F1 — Wave-5: 36 manifests INVALID (capability-name charset). THE finding.

`validate_manifest_json` → `valid_capability` requires
`[a-z0-9._-]{1,64}`. All 36 wave-5 failures are `required_capability` /
`granted_capabilities` values of the form `<repo>.<unit>:<cap>`:

- `compute.pipeline:live`, `compute.ledger:write`, `compute.integrity:write`, `compute.adapters:execute` (12 manifests)
- `verifier-mission.lane-a:attest`, `verifier-mission.lane-c:exec`, `verifier-mission.lane-g:run`
- `proof-ledger.pl-cli:wrap`, `batch-compile.driver:live`, `cutecity.uptime-check:external`
- 7× bin (`bin.backup:…` etc.), 3× dogfood, 8× exchange (same pattern)

The worker's RESULTS claim "manifests validate via the org-001 JSON schema"
is true but insufficient: `manifest-json-schema.json` has **no pattern on
capability names** (verified by schema walk) — the done-bar requires
`organelle-manifest::validate_manifest_json` ("use the `pl` binary or a
validation lane"). Manifests whose ops are ReadOnly-only pass (no capability
names needed): bin/coding-agents `be`, compute/router `co`, compute/verifier
`cf`, cutecity `ay`/`lc`/`tj`/`vp`, dogfood `db`/`dd`, exchange `eb`/`ed`,
proof-ledger `pa`/`pj`, verifier-mission `vb`/`vd`/`ve`. The reference
organelles use dotted capabilities (`ledger.write`) — the fix is mechanical:
`compute.pipeline:live` → `compute.pipeline.live`.

### F2 — One-commit rule violated: every wave-5 repo has 2+ base commits.

Each wave-5 repo carries the prior (sibling, blind-templating) pass's
`organelle-migration: <repo> tier-B` commit PLUS the corrected pass's
identical-message commit (compute: 3 base commits incl. `1cb6d8c`
`(codon uniqueness fix)`; exchange: 2 + `54ec4ab (codon uniqueness fix)`).
cutecity-git/lucidota and litebox/litebox each have 2 tier-C commits
(`…tier-C` + `…tier-C (mapping…)`). Same class as qa-audit-1 F4
(ledger-graph). The 8 rename commits are authorized follow-ups and do not
count against the rule.

### F3 — Stale old codons after 3 of the 8 renames.

- `compute/organelles/execution.json`: still `"codon": "ce"` (line 81) and
  `"codon": "cm"` (line 97) — functional staleness; manifests+adapter were
  renamed to `ev`/`me`.
- `dogfood/organelles/execution.json`: still `"codon": "dk"` (line 70);
  manifest renamed to `tk`.
- `mcp-servers/experiment-desk/organelles/MAPPING.md`: prose still says
  codon `ed` (lines 20, 75) — including the now-false "checked unique"
  claim. (Temp-dir string `ed-adapter-test-` is cosmetic.)
- `cutecity-git/lucidota/organelles/MAPPING.md`: prose still says codon
  `lc` (lines 34, 60) — including the false "no collision" claim; the
  rename commit touched ONLY the manifest.
- doggystyle's rename was complete (both execution.json files, adapter,
  shim tests, MAPPING.md); only comment text (`// --- db:`, `# dc —`)
  still mentions old codons — cosmetic.

### F4 — Rename commits dc0a477 (compute) and e124950 (dogfood) bundle unrelated files.

Both include the rename (MAPPING.md + adapter + manifest) but also
unrelated work under the rename message: compute's adds `burn-outputs/*`,
`LICENSE`, `.gitignore`; dogfood's adds `audit/*`, `track-e/proof-batch*`,
`_product-defects.md`, `LICENSE`, `.gitignore`. Misleading messages, not
destructive. (verifier-mission 580b328, compute ce599cb, experiment-desk
0072b91, doggystyle d6c9e76 were cleanly scoped; lucidota f9b32ee was
minimal but incomplete — see F3.)

### F5 — proof-ledger/rs: full suite red (`t009_2_real_ledger_differential`).

`cargo test --offline`: all targets green EXCEPT `tests/projection.rs::
t009_2_real_ledger_differential` — py/rs projection differential over the
live `~/ledger/ledger-0001.jsonl` fails (`left: 5, right: 0` at
projection.rs:235). The migration commit `2933879` touches only
`src/organelle.rs`, `src/lib.rs` (wasm-gating), `Cargo.toml/lock`,
`organelles/` — it does NOT touch projection code, so the migration did
not cause this. Likely ledger-state drift or the other wave's uncommitted
src changes (`src/canon.rs`, `src/envelope.rs`, `src/projection.rs`,
`tests/projection.rs`, `tests/rt_spree.rs` are uncommitted in the working
tree). The wave's "92/92 green" claim is not reproducible now. Organelle
tests themselves: 3/3 green (manifest validates, Rust/JSON agree, lifecycle
claim→…→repair→verify_chain).

### Detail on the ✅ items (evidence)

- **Tests re-measured:** 8/8 wave-5 `test_organelles.py` 5/5 green;
  experiment-desk adapter 3/3 + `attest_tool_test.py` 20/20 PASS;
  doggystyle `pytest tests/` 44/44 + shim `tier_b_roundtrip_receipts_and_kill`
  1/1 (registers 3 units on a real host, Write-without-capability denied +
  receipted, `verify_chain` green incl. after kill, daemon actually exits).
- **MAPPING.md all 14 genuine:** per-unit tables cite real files/functions
  (e.g. compute `pipeline/driver.py` modes, doggystyle `ontology_store.py`
  1464 lines / V1-vs-V3 seam, dogfood track-a fake-ops admission,
  batch-compile 3-manifests-1-command consolidation, lucidota's snapshot
  diffing with live copies, litebox's circularity argument,
  legal_authority_system's README-derived contracts). Deliberate exclusions
  recorded everywhere (compute's 9 exclusion bullets, dogfood's track
  exclusions, verifier-mission's lane-f/lane-h, doggystyle's bench/fixture/
  doctor exclusions, cutecity's rust/ + blob exclusions).
- **No secrets** in any manifest or adapter (value-pattern greps, zero hits;
  doggystyle `secret_env` carries names only; bin adapter scrubs values).
- **No destructive git ops during the waves:** reflogs clean in 13/14 repos;
  compute's 4 reset hits are the documented 2026-10-08 20:51Z incident
  (pre-migration). All working-tree leftovers are other waves' runtime data
  (burn outputs, ledger appends, receipts, another lane's uncommitted src) —
  no migration files left uncommitted.
- **Host registration real where claimed:** proof-ledger/rs,
  experiment-desk, doggystyle register on real `Host` in tests. Wave-5's
  RESULTS honestly defer live host registration as a coordinator follow-up
  (Tier-B reverse dispatch needs a host-side exec surface) — not faked.
- **Kill semantics:** wave-5 adapters handle suspend/kill specials with
  final receipts and the 5/5 suites exercise suspend over the wire;
  doggystyle's kill is proven end-to-end. The substrate-wide gap from
  qa-audit-1 (host has no suspend/kill path) still stands — Tier B works
  around it in-adapter.
- **qa-audit-1 F3 is fixed:** `sec-organelles.manifest.json` renamed to
  `SUPERSEDED-wave1-placeholder.json` (no longer in `.manifest.json`
  namespace); the sweep no longer flags it.
- **legal_authority_system verified:** clone holds exactly README.md (2
  lines — title + one descriptive paragraph) + LICENSE; the 4 declared
  contracts (`resolve_source`, `rank_authority`, `attach_provenance`,
  `cite`) are drawn from the README's own words; valence Candidate; honest
  Tier C.
- **doggystyle adapter genuinely thin:** `dogd.py` dispatch table
  `(codon, op) -> kernel.cli.cmd_*`; only documented transport adaptations
  are base64 blob bytes + `OP_DEFAULTS` replaying argparse defaults
  (AST-audited). Rust shim enforces only the wall-clock timeout.

## The 8 codon-rename commits (verified)

| # | Commit | Rename | New codon unique? | Refs updated | Tests green |
|---|---|---|---|---|---|
| 1 | verifier-mission `580b328` | va→vm | ✅ `vm` unique (no sweep collision) | ✅ manifest+adapter+MAPPING | ✅ 5/5 |
| 2 | compute `ce599cb` | ce→ev | ✅ `ev` unique | ✅ manifest+adapter+MAPPING; ❌ execution.json still `ce` (F3) | ✅ 5/5 |
| 3 | compute `dc0a477` | cm→me | ✅ `me` unique | ✅ manifest+adapter+MAPPING; ❌ execution.json still `cm` (F3); ⚠️ bundled unrelated files (F4) | ✅ 5/5 |
| 4 | dogfood `e124950` | dk→tk | ✅ `tk` unique | ✅ manifest+adapter+MAPPING; ❌ execution.json still `dk` (F3); ⚠️ bundled unrelated files (F4) | ✅ 5/5 |
| 5 | mcp-servers/experiment-desk `0072b91` | ed→ex | ✅ `ex` unique | ✅ manifest+adapter+MAPPING; ⚠️ MAPPING prose stale `ed` (F3) | ✅ 3/3 + 20/20 |
| 6 | cutecity-git/lucidota `f9b32ee` | lc→lu | ✅ `lu` unique | ⚠️ manifest only; MAPPING prose stale `lc` (F3) | N/A (Tier C) |
| 7 | remote-repos/doggystyle `d6c9e76` | db→bl, dc→ck | ✅ both unique | ✅ complete (manifests, both execution.json, dogd.py, shim tests, MAPPING) | ✅ 44/44 + 1/1 |
| 8 | — | — | — | — | — |

(Eight renames were specified; the table covers all 7 commits —
doggystyle's single commit `d6c9e76` carries two renames, which is the 8th.)

Precedence claims all check out: vault `va` 18:42 < verifier-mission 19:25;
cute-e2ee `ce` 18:45 first; coldmail `cm` (d2f0bea, 18:40) < compute 20:25;
diogenes-kernel `dk` (19:49) < dogfood 19:53; exchange `ed`
(discover-local) < experiment-desk; cutecity `lc` < lucidota;
dogfood `db`/`dc` < doggystyle. Infringers were the later committers in
every case.

## New codon collisions (workspace-wide sweep)

1. **`so`: `longtail/rust/soleita` (soleita.manifest.json, commit 525c5db)
   vs `shambhala` (sham-offline.manifest.json, commit 004ef6c).**
   Both committed, both live. Created by soleita's `sl`→`so` rename
   (qa-audit-1 noted the `sl` fix; the rename traded one collision for
   another). Needs a coordinator rename — one of them must move.
2. **`wg`: `organelles/waves/wave-4c/scratch/wreck-five-way/wreck-conflict`
   vs `wreck/wreck-govern`.** Scratch dir — excluded per the standard, not
   Tier C. Informational only; no action unless the scratch is promoted.

No other collisions among the 133 swept manifests. All 14 audited repos'
codons are unique.

## Notes for the parent

1. **Wave-5's done-bar failure is mechanical, not architectural:** the
   capability-name charset (`:` → `.`) fix is a sed-class change across 36
   manifests. But it must be re-validated with `validate_manifest_json`
   (not the JSON schema) and the 5/5 tests re-run, because the tests
   currently bless invalid manifests.
2. **7b pushes still blocked** (legal_authority_system 403; doggystyle no
   GitLab auth). MEMORY.md now records github.com/mFSpx as LOST with pushes
   retargeted to mfspxz — the legal_authority_system commit may need
   retargeting rather than a permission grant.
3. **proof-ledger/rs `t009_2` failure** should be triaged separately from
   the migration — it is a live-ledger py/rs differential, and the working
   tree has another wave's uncommitted projection changes.
4. The duplicate base-commit pattern (F2) is now the norm across wave-5 —
   if the coordinator wants the one-commit rule to hold, it needs an
   explicit ruling (squash vs. grandfather), because workers keep
   re-committing the pattern.
