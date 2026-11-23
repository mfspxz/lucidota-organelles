# Applying `ref-cf-storage` (org-027, codon `cs`)

The estate's Cloudflare storage surface: KV / D1 / R2 / Queues
behind one trait surface, with two backends — the Cloudflare REST
API v4 (native, via `ref-https-transport`) and the Workers runtime
bindings (wasm32, async). It closes GAP-02 of the 2026-11-22
decomposition map: eight scoped softwares (SUB, PL, WRK, EXC, RTR,
TRN, SDX, TEN) hand-roll this access today. `ref-kv-store`
(org-013), `ref-file-cas` (org-024) and `ref-ledger-append`
(org-020) remain the store contracts; this crate is the edge
backend family behind those shapes.

## Dependency stanzas

Client-only consumers (CLIs, adapters, worker cores) — no
host/manifest deps in their graph:

```toml
ref-cf-storage = {
  path = "<relative path>/organelles/crates/ref-cf-storage",
  default-features = false,
  features = ["native"],
}
```

Hosts registering the organelle surface take the default features
(`organelle` + `native`) and register either
`ref_cf_storage::organelle()` (configured from the host
environment's `CF_ACCOUNT_ID` + `CF_API_TOKEN`) or
`ref_cf_storage::organelle_with_client(client)` with an injected
`CfRestClient`. Ops and capabilities: `kv_get` / `kv_list`
(`cf.kv.read`), `kv_put` / `kv_delete` (`cf.kv.write`), `d1_query`
(`cf.d1.read`), `d1_execute` (`cf.d1.write`), `r2_get`
(`cf.r2.read`), `r2_put` / `r2_delete` (`cf.r2.write`),
`queue_send` (`cf.queue.send`).

Wasm worker cores use the same crate with default features off and
no `native` feature: `wasm_bindings::CfBindings::new(env)` →
`.kv(name)` / `.d1(name)` / `.r2(name)` / `.queue(name)`. The
bindings face is async because the platform is; R2 `get` returns
the object handle (metadata sync, body as bytes / text / raw
ReadableStream passthrough) and `put` accepts bytes, text, or a raw
stream value.

## Credential rule (non-negotiable)

Credentials are **injected**, never sourced by this crate: the
caller constructs `CfRestClient::new(account_id, token)` (or sets
the two env vars for the organelle surface). The crate reads no
files, no vault, no other env vars; the token is never printed
(`Debug` redacts it) and never appears in errors. On this estate
the injection source is the Cloudflare connector's surrogate flow
(the same `hsurr:*` mechanism `cf.py` uses) — a harness fetches the
surrogate and passes it in; the crate neither knows nor cares.

## Semantics every adopter gets

- **Error taxonomy.** `Transport` = no HTTP response exists.
  `Auth` = Cloudflare answered 401/403 (credential rejected or
  under-scoped — a scope question before a key question). `Api` =
  `success: false` or another error status, with Cloudflare's own
  error codes preserved. `InvalidRequest` = refused client-side
  before any call. `Binding` = wasm binding missing / mistyped /
  threw. Nothing panics on an API response.
- **Misses are data.** KV `get` and R2 `get` return `None` on 404.
  KV/R2 `delete` are idempotent (404 is the desired end state).
- **D1.** `d1_query` / `d1_execute` split is intent, not
  enforcement: the REST endpoint executes any SQL either way, so
  read-only-ness is the caller's contract (the organelle surface
  documents this on the `d1_query` op). Statement-level failure
  (`success: false` inside a 200 envelope) surfaces as `Api`.
- **Values.** The Rust API is bytes throughout. The organelle
  surface is text (`value_text`) — binary payloads (R2 bundles,
  CAS blobs) use the Rust API, not the organelle ops.
- **Keys cannot reshape URLs.** Keys / ids are percent-encoded
  (R2 keys keep `/` as the path separator; KV keys encode it).
- **Token scopes are per-service.** The REST face needs the
  token to carry KV / D1 / R2 / Queues permissions for the services
  actually called; R2's S3-compatible API is a different face and
  is out of scope here.

## Adoption steps — the 8 GAP-02 consumers

1. **SUB — organelle substrate.** Register `cs` beside `kv` / `fc`
   / `la` in host bootstraps that run at the edge, constructed via
   `organelle_with_client` with the host's injected client. The
   in-memory `ref-kv-store` stays the local/test backend; the host
   receipt log's D1 backend is `d1_execute` inserts (chain
   semantics stay in `organelle-host` — this crate is storage
   transport, not receipt logic).
2. **PL — proof-ledger.** Two steps. (a) Now, native face: `pl`'s
   Rust tooling gains an off-box backup verb — `ledger.jsonl` /
   projection bundles to R2 via `r2_put` under their sha256 ids
   (the `ref-file-cas` addressing rule), through an injected
   client. (b) When the owed JS ledger worker is ported, its D1
   receipt index becomes `WasmD1` calls behind the same binding
   name it uses today.
3. **WRK — wreck.** `wreck-worker` (`wreck-governor`) declares
   `GOVERNOR_KV` (KV), `CHAIN_D1` (D1) and the `wreck-push-events`
   queue. When its Rust core lands behind the GAP-07 shell, those
   become `CfBindings::kv("GOVERNOR_KV")`, `.d1("CHAIN_D1")`,
   `.queue("wreck-push-events")` — the binding names do not
   change, only the language driving them. (wreck-wasm is the
   estate's deployed-proven wasm pattern; follow it.)
4. **EXC — exchange.** The live Rust `exchange-worker` talks to
   D1 `EXCHANGE_DB` (`0ea89801-9b0a-4efa-9d2f-170d7d285e69`)
   through workers-rs bindings today. Adoption is an exchange-lane
   job, gated on its parity suite: swap the worker's D1 access
   layer to `WasmD1` (prepare/bind/all/run map 1:1 onto
   `query`/`execute`). Separately, the native face is available
   *today* to exchange tooling for read-only D1 inspection without
   wrangler — proven 2026-11-22 against this very database
   (`SELECT 1 AS one` → `[{"one":1}]`, see the A6 report). Do not
   touch the deployed worker from a cf-storage lane.
5. **RTR — ai-router.** JS today; durable state in KV `LANES_KV`
   (`12bdef850f5642f793fafebd1afe06bb`). No JS-side action. The
   native face serves router diagnostics now (read lane state by
   namespace id via `kv_get`); when the router ports to Rust/wasm
   (with GAP-10 model-call-live), its KV access becomes
   `CfBindings::kv("LANES_KV")` with the binding name unchanged.
6. **TRN — translink-repeater.** JS today; snapshots in KV `SNAP`
   (`afd887dd573b405d8f2897c673568cc6`). Native face first: the
   residential-IP fallback poller writes snapshots via REST
   `kv_put` instead of shelling out to wrangler. The wasm face
   rides the Rust-core port (with GAP-21 gtfs-rt-decode):
   `CfBindings::kv("SNAP")`.
7. **SDX — SupDox / Manual Forge.** Caveat first: the SupDox
   worker's source is not in `~/workspace` (estate inventory:
   owed + unverified), so this step is conditional on that source
   landing. Manual Forge is Rust today: its publish step adopts
   the native face — rendered manuals to R2 (`r2_put`, bundles) /
   KV (`kv_put`, per-section text) via an injected client. The
   serving worker, when ported, reads through the wasm face under
   its existing binding names.
8. **TEN — tentacle-corp infra.** Five JS workers hand-roll the
   shell; `infra/worker` alone uses KV `CTCC_KV`
   (`8738ec40b04742fb887ba16d2d7aabb2`) and D1 `HEARTBEAT_DB`
   (`heartbeat-log`, `ccb25914-29b4-4b2d-96d7-52e899d074e1`).
   Adoption rides the GAP-07 edge-shell port, one worker at a
   time: heartbeat Merkle appends → `WasmD1::execute`, status
   ingest → `WasmKv::put_text`, ledger viewer reads →
   `WasmD1::query` — binding names unchanged throughout.

## Verification pattern for adopters

Mirror the A5/A6 proofs: recorded-shape tests for the swap (the
crate's own suite is the template), then one read-only live call
through the native face (`SELECT 1`, a KV `list` with limit 1)
before any write path is trusted, then the consumer's existing
smoke. A storage swap that changes observable behaviour is a
failed adoption, whatever the cause.
