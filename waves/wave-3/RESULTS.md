# WAVE 3 — organelle migration results (2026-10-10)

Corrected doctrine: per repo, decompose what the code ACTUALLY does; per
capability unit, a genuine map-or-design decision (reference vs bespoke),
justified in each repo's `organelles/MAPPING.md`. Tier A = native `Organelle`
trait impl, `Host::register`, hash-chained receipts, register→call→
`verify_chain` tests. One commit per repo: `organelle-migration: <repo> tier-A`.

## Per-repo results

### 1. coldmail — commit d2f0bea — 7/7 tests green
- **Units:** parse_contacts, render, queue (all pure).
- **Decisions:** one organelle `coldmail` (`cm`), all bespoke. `ref-text-transform` rejected (generic text ops vs contact-aware mail-merge + sequence scheduling); `ref-notify` rejected (the crate's defining feature is that sending is NOT wired — `queue` receipts carry `send_wired: false`).
- **Exclusions:** send (does not exist — structural), CLI arg parsing.
- **Valence:** Proven, ReadOnly.

### 2. py-ports — commit c4d651f — 3/3 tests green
- **Units:** assemble (12-per-category priority selection, URL dedup, SHORT warnings), categories.
- **Decisions:** one organelle `py-ports` (`yp`), bespoke. `ref-json-validate` rejected (we select records, not validate conformance); `ref-scrape-extract` rejected (pool is pre-verified).
- **Exclusions:** binary file IO (entrypoint transport detail; organelle exposes the pure selection core).
- **Valence:** Proven, ReadOnly.

### 3. soleita — commit 525c5db — 10/10 tests green
- **Units:** listing, net, pack (pure) + record_sale, ledger_total (fs-backed SalesLedger).
- **Decisions:** one organelle `soleita` (`so` — **renamed from `sl` per coordinator: `sl` owned by security/sec-organelles' `seal`**), bespoke. `ref-ledger-append` rejected (plain append, no schema/computed return; soleita's ledger is a typed domain object). `record_sale` = Write + `soleita.ledger.write` capability; `..` path rejection.
- **Exclusions:** CLI arg parsing.
- **Valence:** Candidate (honest — two ops touch caller fs), mixed mutation classes.
- **Note:** one pre-existing test (`catalog::tests::status_flow`) flaked once under parallel temp-file collision, green on rerun; unrelated to migration.

### 4. brightideas — commit 0676ebe — 6/6 tests green
- **Units:** score (real `route_for`), intake, triage, backlog_due, by_route.
- **Decisions:** one organelle `brightideas` (`bi`), bespoke. **Caught blind templating in the pre-staged skeleton:** its `routes` op returned a hardcoded copy of the thresholds instead of calling `route_for` — replaced with the real function + boundary-total tests. The fs-backed IdeaLog (unexposed by the skeleton) is now exposed as intake/triage (Write + `brightideas.log.write`) / backlog_due / by_route. `ref-model-call` rejected ("No model judging" — explicit deterministic rubric); `ref-kv-store` rejected (dedup + routing + re-triage semantics).
- **Exclusions:** CLI arg parsing.
- **Valence:** Candidate, mixed mutation.

### 5. shinder_mcowls — commit ed4631b — 10/10 tests green
- **Units:** generate_character, build_pack (pure) + canon_check, lore_add, lore_retcon, lore_list (fs-backed LoreBible).
- **Decisions:** one organelle `shinder-mcowls` (`sm` — manifest names forbid `_`, so `shinder-mcowls` not `shinder_mcowls`), bespoke. The append-only lore bible (namespaced ids, duplicate refusal, explicit retcons) was unexposed by the skeleton; now lore_add/lore_retcon (Write + `shinder.bible.write`) / lore_list. `ref-kv-store` rejected (id-namespace + append-only + retcon discipline).
- **Exclusions:** CLI arg parsing.
- **Valence:** Candidate, mixed mutation.

### 6. diogenes-kernel — commit 491bc4d — 26/26 tests green
- **Units:** mutation_allows, claim_new, slop_audit (pure) + packet_verify, min_authority (RFC-050 authority module — missed by the skeleton) + workflow store.
- **Decisions:** TWO organelles. `diogenes-kernel` (`dk`, ReadOnly, Proven): the five pure kernel primitives. `diogenes-workflow` (`dw`, Write + `diogenes.workflow.write`, Candidate): RFC-060 ABSURD store — enqueue, lease, start, succeed, fail, dead_letter, get (ReadOnly). Split at the statefulness seam. `register_contract` excluded (in-memory only; folded into `enqueue` as a documented adapter: contract re-registered per call, worker defaults to caller name). `ref-time-oracle` rejected for packet_verify (the unit is packet verification, not time provision).
- **Exclusions:** register_contract alone, CLI arg parsing.
- **Tests prove:** real minted packet verifies; tampered packet fails; capability-less write denied; full enqueue→lease→start→succeed lifecycle.

### 7. chainstay — commit de613ee — 34/34 tests green
- **Units:** 11 pure rule ops + 8 store ops.
- **Decisions:** TWO organelles. `chainstay` (`cs`, ReadOnly, Proven): compose_name, component_new/append/verify (skeleton's `wallet` renamed — the wallet IS the component logbook), workorder_open/advance/dry_run/andon, quote_totals, schedule_book, part_preview. `chainstay-store` (`ct`, Write + `chainstay.store.write`, Candidate): save_wo, get_wo, wo_history, aux_put/aux_get, bunker_push/pending/flush (bunker persisted as JSON in AUX — documented adapter; `sync` closure excluded as caller orchestration). `ref-ledger-append` rejected (plain append vs redb event-sourced DB).
- **Exclusions:** BunkerQueue::sync, CLI arg parsing. Demo andon PIN is a code constant, in no manifest.
- **Test fixes during migration:** taxonomy rejects `.` in segments; WoState db strings are UPPERCASE (`TRIAGE`).

### 8. percyphonai — commit 527b382 — 48/48 tests green (42 lib + 6 bin)
- **Units:** the Ghost Swarm engine, carefully decomposed (NOT the skeleton's single facade).
- **Decisions:** THREE organelles. `percyphon-forge` (`pf`, ReadOnly, Proven): generate + fingerprint (pure projection, one core). `percyphon-kronenberg` (`pk`, ReadOnly, Proven): wear + verify_link (copy-on-borrow identity components FACE/VOICE/WORDS/STYLE/HANDS/MIND, sources never mutated). `percyphon-custody` (`pu`, Write + `percyphon.custody.write`, Candidate): mint, mint_for_run (sanctioned run path), hydrate (REFUSES archived), set_state, deprecate_slot, archive, verify_receipts (ReadOnly). `ref-kv-store` rejected (lifecycle + integrity + Valhalla semantics); `ref-ledger-append` rejected (plain append, NO chain — the chain IS the custody guarantee); `ref-hash-seal` rejected (single payload vs chained log).
- **Exclusions:** cli.rs + mcp_server.rs (transport surfaces), wordlist/epigenome (support modules).
- **Tests prove:** determinism, vuuid binding, copy-on-borrow slot overlay, fresh-link drift verification, idempotent mint, archived-hydration refusal, custody chain verification.

### 9. percyphon — commits 1f2862e + 4eca3ca — 38/38 tests green
- **Units:** same three-way split as percyphonai (sibling long-002 rebuild, different code).
- **Decisions:** THREE organelles `percyphon-rs-forge` (`pg`) / `percyphon-rs-kronenberg` (`pq`) / `percyphon-rs-custody` (`px`). Names disambiguated from percyphonai's (`percyphon-*`); codons workspace-unique. **Collision found and fixed in verification:** first cut used `pv` for the custody organelle, but `security/provenance` already owns `pv` — renamed to `px` (commit 4eca3ca), tests re-green. Variant differences recorded: `ReceiptLog` (string op/vuuid/detail receipts, still hash-chained), `dispatch::mint_for_run` (index derived from run_id via sha256), audited `restore` op (Valhalla snapshot restore — percyphonai lacks it). Seed phrase never lands in receipts (detail = index/env/wordlist_hash/actor). Capability name shared (`percyphon.custody.write`) — same product trust domain, documented.
- **Exclusions:** cli.rs + mcp.rs (transport surfaces), wordlist/epigenome (support).
- **Tests prove:** determinism, run-id idempotency, archived-hydration refusal, receipt chain verification.

## Cross-cutting notes

- **Codon registry:** all 15 new codons verified unique across every `*/organelles/*.manifest.json` in the workspace: `so cm yp bi sm dk dw cs ct pf pk pu pg pq px`. Two collisions found and fixed during the work: `sl`→`so` (coordinator decision — `security/sec-organelles` `seal` owns `sl`); `pv`→`px` (my own verification caught it — `security/provenance` owns `pv`). `pc` was avoided up front (proof-ledger `pl-cli`). sec-organelles untouched.
- **Reference-organelle adoption:** 0 of 12 adopted, 12/12 genuinely considered per repo. Every rejection is justified in the MAPPING.md files (the common pattern: ref organelles are generic primitives — plain append, untyped KV, schema validation — while these repos' units carry domain semantics: custody chains, lifecycle state machines, taxonomy discipline, control packets, idea funnels).
- **Manifest JSON generation:** dumped from the Rust `manifest()` via a temporary test (guarantees `rust_manifest_matches_static_json`), temp test removed after.
- **Existing tests:** all stayed green; no test was modified except organelle-module tests written in wave staging.
- **Git hygiene:** selective staging only (specific files per commit); no reset/stash/clean/force-push. Migration ADDS files; no code removed.
- **MIGRATION-STATUS.md:** untouched (coordinator updates centrally).
