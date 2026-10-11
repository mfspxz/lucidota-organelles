# WAVE 4a — Results (narrowed slice)

Worker slice (per coordinator narrowing 2026-10-10): **gis, krampus-express,
indy-reads, dispatch-fabric** (+ lucidota-core, done pre-narrowing).
canon / wreck / noter / adhkey handed to a new worker — this lane's commits
there are already landed (canon `f727745`, wreck `7db599b`, noter `b839d5c`,
adhkey `1158e19`); nothing uncommitted was left behind in those four.

Doctrine: decompose ACTUAL capabilities per repo; map-or-design per unit
(adopt a ref organelle only if the unit genuinely IS it); justify in
`organelles/MAPPING.md`; unique codons; deliberate exclusions recorded.
Standard: Tier A = Organelle trait natively, Host registration, hash-chained
receipts, tests proving register→call→verify_chain.

## 1. lucidota-core — DONE (pre-narrowing)

- Commit: `c0e49ea`
- Units: one organelle `ld`, 13 ops (correct_*, gate, lint, receipt_*
  stateless-by-value, fleet_*).
- Tests: 36/36 green.

## 2. gis (CuteCity GIS backend) — DONE

- Commits: `11500cc` (migration), `7e461d5` (codon fix)
- Units (3 organelles, new crate `crates/gis-organelles`):
  - `ge` gis-geo: pure geodesy (haversine, tile_xy, projections) — **bespoke**
    (no ref organelle does geodesy).
  - `gi` gis-poi: POI store w/ JSON persistence — **bespoke** (not a blind
    KV; spatial queries + file persistence).
  - `gj` gis-route: pedicab routing graph, grade-penalized Dijkstra —
    **bespoke** (no ref organelle routes).
- **Codon collision**: `gr` → `gj` — `gr` owned by park-send-wreck's
  `pw-grid` (committed 21:44 UTC, earlier than gis 23:41 UTC). Renamed in
  manifest, `gr.write`→`gj.write`, tests, MAPPING.md, execution.json.
- Tests: 5/5 organelle + 27 full-workspace, all green.

## 3. krampus-express (scraper fleet) — DONE

- Commits: `4e04d96` (migration), `737184d` (host API compat)
- Units (5 organelles in `krx-organelles`; `kx`/`kn` pre-existed, extended
  with 3):
  - `kx` krx-extract: pure feed/JSON/HTML parsing — **bespoke** (pure parse
    of supplied bytes; `ref-scrape-extract` couples fetch+extract).
  - `kn` krx-normalize: canonical rebuild + identity assert — **bespoke**.
  - `ks` krx-scrape: 144-source fleet registry + batches — **bespoke**.
  - `kd` krx-schedule: polite scheduling, backoff state machine —
    **bespoke**.
  - `ke` krx-etl: dedup filter + sealed run manifests — **bespoke**.
- Deliberate exclusions: actual fetching (network), typed ETL pipeline
  stages (framework), krx-redteam/exchange/hardening/health (operator
  tooling), LUCI_FOREMAN voice (needs audio/GPU).
- Infra fix: `cargo update -p hmac --precise 0.12.1` — organelle-host pins
  `hmac = "=0.12.1"` but the lock was stale at 0.13.0 (incompatible with
  sha2 0.10). Other repos' locks may carry the same staleness.
- Tests: 9/9 organelle + 80 full-workspace, all green.

## 4. indy-reads (voice research agent) — DONE

- Commit: `07a6bd4`
- Units (5 organelles, new `src/organelles/` module in lib):
  - `iv` indy-voice: honest diarization + epistemic prosody derivation
    (pure) — **bespoke**.
  - `ig` indy-gmail: fail-closed Gmail search/read — **bespoke**.
  - `im` indy-mcp: tool descriptors, forbidden-arg stripping, governed
    dispatch — **bespoke**.
  - `ia` indy-ai: governed AI router (provider selection, classified
    failover, fixture mode) — **bespoke** (NOT `ref-model-call`, which is
    a stub; the governor path is the capability).
  - `ie` indy-receipts: chained receipt construction — **bespoke** (NOT
    `ref-hash-seal`; builds chained claim receipts).
- Structural: `src/ai.rs` moved from binary-only to lib (`pub mod ai`).
- Capability units only — no data dirs touched.
- Tests: 8/8 organelle + 191 full lib suite, all green.

## 5. dispatch-fabric — DONE

- Commit: `f3ecb35`
- Units (4 organelles, new crate `crates/fabric-organelle`):
  - `fp` fabric-spec: spec parse/validate/plan (pure) — **bespoke**.
  - `fx` fabric-dispatch: dispatch envelopes + in-flight ledger —
    **bespoke**.
  - `fv` fabric-verify: in-toto/DSSE attestation parsing + verdict
    receipts — **bespoke**.
  - `fw` fabric-driver: work-order execution driver (heavyweight `run`) —
    **bespoke**.
- Deliberate exclusions: old `fabric-organelles` crate (targets OLD
  organelle-core — left untouched); fabric-graph/workspace/records/
  registry/quota/adapters/types (supporting libs); 38 `wt-*` worktrees;
  tools/dogfood/spec/work-order/evidence dirs.
- Tests: 5/5 organelle green; full workspace 76 passed, 1 failed —
  `fabric-adapters::copilot::tests::documented_non_interactive_mode_is_supported`
  is a pre-existing environmental failure (fake-`gh`-binary probe) in a
  crate this migration does not touch.

## Cross-cutting notes for the coordinator

1. **organelle-host P0/P1 hardening** (commits `f928bc6` 23:39 UTC,
   `89a6d58` 00:14 UTC, 2026-10-10/11) changed the API mid-wave:
   `host.call` → `CallOk { output, receipt_id }`, `HostRef::call_organelle`
   gained `caller_trace`, new required methods `approve_write_path` /
   `approve_egress`. All four repos in this slice were patched; the new
   worker's four repos (canon/wreck/noter/adhkey) were committed BEFORE
   P0/P1 and their organelle tests will break on rebuild — flagging.
2. **hmac lock staleness**: organelle-host pins `hmac = "=0.12.1"`;
   krampus's lock had 0.13.0 (build-breaking). Fixed in krampus; other
   repos may need `cargo update -p hmac --precise 0.12.1`.
3. **adhkey note**: a parallel lane's organelle work (ak/as/lx/mx) was
   verified green (125 tests) and committed as `1158e19` BEFORE the
   narrowing arrived. Two `.secrets-allowlist` entries added for proven
   false positives (long identifiers in pre-existing code).
4. No secrets/key material in any manifest (capability names only).
5. One commit per repo, `organelle-migration: <repo> tier-A` format.
   MIGRATION-STATUS.md untouched.
