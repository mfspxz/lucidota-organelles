[Active R&D Lab] — no CI runs on record; active development, expect rough edges.

# Organelles — parkwreck-organelle-host rebuild

Scaffold slice **org-001 … org-024**, built 2026-10-07, Rust-first (Rust 1.99.0,
deps: serde/serde_json/sha2/hex only — surfaces are std-only).

Grounded in Zackary's surviving `ToolOrganelle` trait (pt-organelle-core,
from the repomix pack) and `ORGANELLES_6_0y0q.md`: codon dispatch,
`handle(ctx, input)`, `mutation_class` (ReadOnly/Write/ExternalEffect),
`declared_valence` (Disproven/Candidate/Proven), `requires_capability`,
`input_schema`. Fail-closed everywhere; every host action emits a
content-addressed, hash-chained receipt (org-010).

## Crates

| Crate | Item | What |
|---|---|---|
| `organelle-manifest` | org-001 | Manifest schema v1: types, `validate_manifest_json` (Write/ExternalEffect without capability = invalid), JSON-Schema-subset runtime validator, canonical JSON, sha256, UTC clock |
| `organelle-host` | org-002/008/009/010/011/012 | Registry, fail-closed router (profile → codon → op → capability → schema → handle), receipts w/ `verify_chain`, profiles + rollback, organelle→organelle authority boundary (`granted_capabilities`), hot-swap (Pinned/Latest/Split) + rollback. `Host::call` **is** the native surface (org-003) |
| `surface-unix` | org-004 | JSON-lines over unix socket |
| `surface-mcp` | org-005 | Manifest → MCP tools generator; JSON-RPC 2.0 stdio server; `organelle-mcp-stdio` bin exposes all 12 reference organelles |
| `surface-rest` | org-006 | Manifest → routes + OpenAPI 3.0; std-only HTTP/1.1; `/api/organelles`, `/api/organelle/call`, `/openapi.json`, `/api/receipts` |
| `organelle-equivalence` | org-007 | Same 19-scenario suite on all 4 transports; byte-diff = fail |
| `ref-common` | — | std-only http:// client + HTML extractor (shared) |
| `ref-*` (12) | org-013…024 | kv-store, http-fetch, text-transform, json-validate, hash-seal, time-oracle, geo-point, ledger-append, notify, scrape-extract, model-call, file-cas |

Honesty notes: `notify` queues to a local outbox (`queued`, never `sent`);
`model-call` runs a labeled deterministic stub unless `MODEL_API_URL` is set;
`http-fetch`/`scrape-extract` refuse https:// (reference client is http-only);
`time-oracle` declares Candidate (unverified clock); pure organelles declare
Proven (recomputable).

## Test counts (all green, 0 failures, 0 warnings)

| Area | Tests |
|---|---|
| manifest (org-001) | 17 |
| host (org-002: 25, org-008 fail-closed: 6) | 31 |
| ref-common + 12 reference organelles (org-013–024) | 46 |
| surface-unix (org-004) | 4 |
| surface-mcp (org-005: 2 unit + 5 live stdio) | 7 |
| surface-rest (org-006) | 6 |
| equivalence (org-007: 19 scenarios × 4 transports) | 1 test / 76 assertions |
| **Total** | **112 tests, 76 equivalence assertions** |

Equivalence verdict: **GREEN** — zero cross-transport diffs.

## Run

```bash
cd ~/workspace/organelles
cargo test --offline --workspace          # everything
cargo test --offline -p organelle-equivalence -- --nocapture   # the matrix report
```

## Decisions (also on the ledger, seq 526…714)

- Rust installed via rustup ($0); offline build from the local cargo cache.
- Lock is never held across `handle()` — organelle→host callbacks can't deadlock.
- Receipt id = sha256 over canonical JSON of the receipt body (content-addressed, not a UUID); chain verified offline by recomputation.
- **R-2 bound (2026-10-10):** the receipt chain is in-memory only
  (`Vec<Receipt>` behind an `RwLock`, no persistence); it is a
  process-integrity structure, NOT tamper-evidence — anyone holding the
  `Host` can rewrite history. Honestly unsigned (see AUDIT-APPLICATION.md
  R-8). No hardening past this bound without an out-of-band anchor.
- Denied vs Rejected are distinct verdicts (authz vs schema), both receipted.
- MCP `dispatch()` is a pure function shared by the stdio loop and the harness — one JSON-RPC implementation, two membranes.
- Valence mapping: pure/deterministic → Proven; stateful/unverified/external → Candidate. Documented per organelle.
