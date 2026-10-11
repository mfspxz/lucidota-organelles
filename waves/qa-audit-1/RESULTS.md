# QA AUDIT — organelle migrations (waves: pilot, 1, 2, 6-Tier-C)

Auditor: read-only verification against the done-bar
(`organelles/ORGANELLE-MIGRATION-STANDARD.md`). No repo was modified.
Date: 2026-10-10 (all commits are 2026-10-10 UTC).

**Scope note:** the task said "17 repos" but named 16. The 17th is clearly
`security/redteam` (wave-2's 8th repo, commit 46512f9) — audited as an extra
and labeled as such.

## Method

1. Wrote a validation harness (`manifest-check/`, Rust, path-dep on
   `organelle-manifest` v1) that runs every `organelles/*.manifest.json`
   through `organelle-manifest::validate_manifest_json` (not eyeballed).
2. Swept all live (non-`target/`, non-`.git/`, non-`backups/`) `*.manifest.json`
   in the workspace for codon uniqueness and validity.
3. `cargo test --offline` per repo (14 Rust repos; Tier C has no code).
4. `git log`/`git show`/`git status`/`git reflog` per repo for commit-count,
   message pattern, selective staging, destructive ops.
5. Grepped substrate (`organelle-host` + all 3 surface adapters, src+tests)
   for suspend/kill/checkpoint machinery.
6. Grepped all manifests for secret/key material; read all 14 MAPPING.md
   files for genuineness.

## Per-repo verdict table

| Repo | Tier | (1) manifest validates | (2) host registration | (3) verify_chain | (4) kill receipts | (5) tests green | (6) one commit + pattern | (7) MAPPING.md genuine | (8) codon unique |
|---|---|---|---|---|---|---|---|---|---|
| ledger-graph (pilot) | A | ✅ `lg`, 2 ops | ✅ | ✅ | ⚠️ declared only | ✅ 5/5 | ❌ **2 commits**; 2nd msg `organelle-migration: ledger-graph mapping justification (map-or-design record)` doesn't match pattern | ✅ genuine | ✅ `lg` |
| security/failclosed | A | ✅ `fd`, 3 ops | ✅ | ✅ | ⚠️ declared only | ✅ 12/12 | ✅ `organelle-migration: failclosed tier-A` | ✅ genuine | ✅ `fd` |
| security/ipc | A | ✅ `ip`, 2 ops | ✅ | ✅ | ⚠️ declared only | ✅ 10/10 | ✅ `organelle-migration: ipc tier-A` | ✅ genuine | ✅ `ip` |
| security/provenance | A | ✅ `pv`, 3 ops | ✅ | ✅ | ⚠️ declared only | ✅ 10/10 | ✅ `organelle-migration: provenance tier-A` | ✅ genuine | ✅ `pv` |
| security/auditor | A | ✅ `ad`, 1 op | ✅ | ✅ | ⚠️ declared only | ✅ 12/12 | ✅ `organelle-migration: auditor tier-A` | ✅ genuine | ✅ `ad` |
| longtail/rust/lt-tools | A | ✅ `lt`, 14 ops | ✅ | ✅ | ⚠️ declared only | ✅ 18/18 | ✅ `organelle-migration: lt-tools tier-A` | ✅ genuine | ✅ `lt` |
| longtail/rust/ornament | A | ✅ `or`, 5 ops | ✅ | ✅ | ⚠️ declared only | ✅ 20/20 | ✅ `organelle-migration: ornament tier-A` | ✅ genuine | ✅ `or` |
| security/vault | A | ✅ `va`, 7 ops | ✅ | ✅ | ⚠️ declared only | ✅ 13/13 | ✅ `organelle-migration: vault tier-A` | ✅ genuine | ⚠️ `va` **collides** with `verifier-mission/lane-a.manifest.json` (committed 19:25 UTC, AFTER vault 18:42 UTC — verifier-mission is the infringer) |
| security/cute-e2ee | A | ✅ `ce`, 7 ops | ✅ | ✅ | ⚠️ declared only | ✅ 16/16 | ✅ `organelle-migration: cute-e2ee tier-A` | ✅ genuine | ⚠️ `ce` **collides** with `compute/organelles/envelope.manifest.json` (uncommitted, wave-5 in flight — cute-e2ee 18:45 UTC has precedence) |
| security/airgap-toolkit | A | ✅ `at`, 2 ops | ✅ | ✅ | ⚠️ declared only | ✅ 10/10 | ✅ `organelle-migration: airgap-toolkit tier-A` | ✅ genuine | ✅ `at` |
| security/threatmodel | A | ✅ `tm`, 3 ops | ✅ | ✅ | ⚠️ declared only | ✅ 10/10 | ✅ `organelle-migration: threatmodel tier-A` | ✅ genuine | ✅ `tm` |
| security/ir-runner | A | ✅ `ir`, 2 ops | ✅ | ✅ | ⚠️ declared only | ✅ 9/9 | ✅ `organelle-migration: ir-runner tier-A` | ✅ genuine | ✅ `ir` |
| security/backup-crypto | A | ✅ `bu`, 2 ops | ✅ | ✅ | ⚠️ declared only | ✅ 10/10 | ✅ `organelle-migration: backup-crypto tier-A` | ✅ genuine | ✅ `bu` |
| security/sec-organelles | A | ❌ **2/3 valid**: `seal` (`sl`), `verify` (`vf`) OK; `sec-organelles.manifest.json` is a non-manifest pointer doc (`{"note":...,"superseded_by":[...]}`) that FAILS `validate_manifest_json` (`missing field schema_version`) | ✅ (seal+verify) | ✅ | ⚠️ declared only | ✅ 11/11 | ✅ `organelle-migration: sec-organelles tier-A` | ✅ genuine | ✅ `sl`,`vf` (`sl` collision with soleita RESOLVED — wave-3 renamed soleita to `so`, committed 20:11 UTC) |
| security/redteam (unlisted 17th) | A | ✅ `rt`, 3 ops | ✅ | ✅ | ⚠️ declared only | ✅ 17/17 | ✅ `organelle-migration: redteam tier-A` | ✅ genuine | ✅ `rt` |
| system-ontology | C | ✅ `sy`, 15 ops, valence=candidate | N/A (Tier C: no live registration by design) | N/A (no host calls) | ⚠️ declared only | N/A (no code) | ✅ `organelle-migration: system-ontology tier-C` | ❌ **MISSING** | ✅ `sy` |
| free-stack | C | ✅ `fs`, 5 ops, valence=candidate | N/A (Tier C: no live registration by design) | N/A (no code) | ⚠️ declared only | N/A (no code) | ✅ `organelle-migration: free-stack tier-C` | ❌ **MISSING** | ✅ `fs` |

**Legend:** ✅ = passes the done-bar item; ⚠️ = partially passes (see notes);
❌ = fails; N/A = exempt per the standard's Tier C definition.

### Detail on the ✅ items (evidence)

- **(1) Validation was executed, not eyeballed:** `manifest-check` compiled
  against the real `organelle-manifest` crate and ran
  `validate_manifest_json` over all 18 manifests in scope (16 repos +
  substrate refs): 17 valid, 1 invalid
  (`security/sec-organelles/organelles/sec-organelles.manifest.json`).
- **(2) Registration genuinely succeeds:** every repo's organelle test does
  `host.register(organelle()).expect("registration must succeed")` on a
  real `Host::new()` and the tests pass — registration receipts are emitted
  and asserted via `verify_chain`.
- **(3) `verify_chain` green** asserted in each repo's test after a real
  call sequence (e.g. failclosed: `register + 4 calls + denial = >=5 receipts`;
  all 15 Rust repos reference `verify_chain` in test code and pass).
- **(5) Test counts re-measured independently:** `cargo test --offline` gives
  5, 12, 10, 11, 12, 18, 20 (pilot + wave-1), 13, 16, 12, 10, 9, 10, 11, 17
  (wave-2 + redteam) — all green, matching the wave reports' claims exactly.
  Two cosmetic warnings only: unused `std::path::Path` (ipc), unused
  `PathBuf` (auditor).
- **(7) MAPPING.md files are genuine:** all 14 read; they cite specific
  modules/functions/line counts and give per-candidate rejection rationales
  (e.g. lt-tools: "ref-text-transform has a *closed mode enum*"; vault:
  "ref-kv-store lacks zeroize-on-drop"). Not templated filler.
- **No secrets in any manifest** (grepped for key/secret/token/password/
  private-key/mnemonic patterns with values — zero hits).
- **No destructive git ops:** `git reflog` shows zero `reset --hard` (or any
  reset) in all 16 repos. (Wave-2's two "local-only amends on unpushed
  seconds-old commits" for backup-crypto are not visible in reflog —
  plausible since the amended commits were never pushed and the reflog only
  retains the final state; the claim is unverifiable but the current history
  is linear and clean.)
- **Selective staging holds:** migration commits contain only `organelles/`
  files + `src/organelle.rs` + `Cargo.toml` path-dep wiring + `mod organelle`
  lines (+ one exception noted below). Working trees are clean except:
  auditor's `.secrets-allowlist` (pre-existing, pre-wave, left unstaged —
  matches wave-1's note) and sec-organelles' untracked `src/organelle.rs`
  draft (documented as rejected, left untracked per archive-don't-delete;
  it declares codon `so` which soleita now holds — dead draft, hygiene note).

### Detail on the ❌/⚠️ items

**F1 — Kill semantics are declared but undemonstrable, substrate-wide.**
Every repo declares kill semantics in `organelles/execution.json`
(`kill_semantics` block present in all 16). But the done-bar requires the
*suspend/kill path produces receipts (tests cover it)*. The `organelle-host`
crate has **no `suspend()` or `kill()` methods** (`Host` exposes:
register/call/call_as_organelle/receipts/verify_chain/profiles/routes only;
the `Organelle` trait is `manifest()` + `handle()` only). `ReceiptKind` has
no Suspend/Kill/Checkpoint variants. A workspace-wide grep of
`organelle-host` + all three surface adapters (src + tests) for
`suspend|kill|checkpoint|final_receipt` returns **zero hits**. No test in any
repo can cover a path that doesn't exist. The wave reports' claim
"(covered by host machinery, asserted via verify_chain in tests)" is
**false for the suspend/kill path** — `verify_chain` in tests covers
register+call receipts only. ⚠️ for every repo; the real defect is in the
substrate, not the migrations.

**F2 — Workspace-wide codon collisions involving audited repos.**
`va`: `security/vault` (committed 18:42 UTC) vs
`verifier-mission/organelles/lane-a.manifest.json` (committed 19:25 UTC —
infringer, wave-5). `ce`: `security/cute-e2ee` (committed 18:45 UTC) vs
`compute/organelles/envelope.manifest.json` (uncommitted, wave-5 in flight).
Vault/cute-e2ee hold precedence; the collisions were introduced by other
workers AFTER these repos were done, so this is a coordinator-level routing
hazard, not builder error — but the done-bar says "unique workspace-wide"
and it is not. (Resolved in-flight: soleita's `sl` → renamed `so`,
committed 20:11 UTC, verified. Note soleita now has TWO commits both
messaged `organelle-migration: soleita tier-A` — out of audit scope but the
same one-commit-rule violation. Other live collisions outside audit scope:
`cg`, `cm`, `cv`, `dk`, `ec`, `lc` — all in in-flight waves.)

**F3 — `security/sec-organelles/organelles/sec-organelles.manifest.json` is
an invalid manifest wearing a `.manifest.json` name.** Content:
`{"note":"wave-1 placeholder manifest (was 3 bytes). This repo exposes TWO
organelles, not one.","superseded_by":["seal.manifest.json","verify.manifest.json"]}`.
`validate_manifest_json` rejects it (`$`: `missing field schema_version`).
Any workspace-wide manifest sweep (host registration scans, coordinator
codon audits, this QA harness) picks it up as an invalid manifest.
Archive-don't-delete was the right instinct; the wrong file name. Rename to
e.g. `SUPERSEDED.md` or `superseded-by.json` (drop the `.manifest.json`
suffix) — one-line fix, no deletion.

**F4 — ledger-graph has two migration commits.** `1e3c412`
`organelle-migration: ledger-graph tier-A` (the real migration) plus
`e9d1324` `organelle-migration: ledger-graph mapping justification
(map-or-design record)` (adds only `organelles/MAPPING.md`). The done-bar
requires *exactly one* commit matching
`organelle-migration: <repo> tier-<X>`; the second message matches neither
the pattern nor the count.

**F5 — Tier C repos lack `organelles/MAPPING.md`.** Neither system-ontology
nor free-stack has one (their `organelles/` dirs contain only the manifest +
execution.json). The done-bar's MAPPING.md check is per-repo and Tier C is
not exempted from it in the standard; their map-or-design justifications
exist nowhere.

**F6 (minor) — ledger-graph's migration commit relaxes `.secrets-allowlist`.**
`1e3c412` changes `^// -{30,} [a-z0-9/:> -]+$` →
`^// -{30,}( [A-Za-z0-9/:> ()+.,-]+)?$` (trailing separator text made
optional, charset widened). Plausibly needed for the new `organelle.rs`
comment style, but it weakens the secret-scrub gate inside a migration
commit — worth the coordinator's eye, not a leak.

## The 3 most serious findings (for the parent)

1. **Suspend/kill receipts are undemonstrable — the host has no suspend/kill
   path at all.** The done-bar's kill-semantics bar ("suspend/kill path
   produces receipts, tests cover it") cannot be met by any repo because
   `organelle-host` implements no such path (no methods, no receipt kinds,
   zero grep hits across host + 3 surface adapters). All 15 Rust repos'
   "kill semantics" are prose in `execution.json`. Either the bar must be
   downgraded to "declared" or the substrate must implement
   suspend→checkpoint→kill with receipts.
2. **Workspace-wide codon collisions on two audited repos:** `va`
   (vault vs verifier-mission/lane-a, committed — verifier-mission infringed
   at 19:25 UTC after vault's 18:42) and `ce` (cute-e2ee vs compute/envelope,
   uncommitted). Codons route on the host — live collisions are a routing
   defect. Plus five more live collisions in other in-flight waves
   (`cg`, `cm`, `cv`, `dk`, `ec`, `lc`).
3. **`sec-organelles/organelles/sec-organelles.manifest.json` is an invalid
   manifest by name.** The superseded-by pointer doc fails
   `validate_manifest_json` and will poison any workspace manifest sweep;
   rename it out of the `.manifest.json` namespace.

## Audit artifacts

- Validation harness: `manifest-check/` (this dir; `target/release/qa-manifest-check`)
- This report: `RESULTS.md`
