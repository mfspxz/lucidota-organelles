# Applying `ref-https-transport` (org-026, codon `ht`)

The estate's production HTTPS client: one request/response API over
ureq 3 + rustls (native) and the host `fetch` API
(`wasm32-unknown-unknown`). It closes GAP-01 of the 2026-11-22
decomposition map — nine scoped softwares re-implement HTTPS
transport today. `ref-http-fetch` (org-014) remains the contract
organelle; this crate is the production transport behind that shape
(and, unlike the reference client, it does HTTPS).

## Dependency stanza

Client-only consumers (CLIs, adapters) — no host/manifest deps:

```toml
ref-https-transport = {
  path = "<relative path>/organelles/crates/ref-https-transport",
  default-features = false,
  features = ["native"],
}
```

Hosts registering the organelle surface take the default features
(`organelle` + `native`) and register `ref_https_transport::organelle()`
(codon `ht`, capability `net.fetch`, host egress approval first —
same policy seam as `ref-http-fetch`).

On wasm32 the `native` feature is inert; the transport is
`send_async` (host fetch is promise-based, so the blocking entry
point returns `TransportError::Unsupported` there rather than
pretending to block).

## Semantics every adopter gets

- **Honest status mapping.** Any HTTP status is `Ok(HttpsResponse)`;
  `TransportError` means no response exists (DNS, TLS, timeout,
  connection, refused scheme). Callers wanting curl `--fail`
  behaviour check `resp.status >= 400` themselves.
- **HTTPS only** unless `allow_http(true)` (local fixtures/dev).
  Refusal happens before any socket or fetch call.
- **Timeouts** are whole-transfer (`timeout_ms`, default 30 s).
- **Body cap** (`max_bytes`, default 1 MiB) truncates and sets
  `truncated` — never a silent cut, never an error.
- **Redirects** follow the backend default (ureq 3: 5).
- **Proxy env**: the native backend honours `HTTPS_PROXY` /
  `HTTP_PROXY`, bypassed per `NO_PROXY`, like curl and urllib.
- **Roots**: the platform verifier (OS root store). Hosts behind
  TLS-intercepting egress proxies whose CA is installed system-wide
  verify correctly; Mozilla-only pinning is not currently exposed.

## Why ureq 3 (do not substitute ureq 2)

ureq 2.12.1's `send_prelude` rewrites the request target to
absolute-form whenever *any* HTTP proxy is configured — including
inside an HTTPS CONNECT tunnel, where strict proxies close the
connection on sight (proven 2026-11-22 against this sandbox's egress
proxy: origin-form → 200, absolute-form → connection closed before
the status line). ureq 3 sends origin-form in tunnels. The
wreck-adapters lane's ureq 2 usage is unaffected (it runs without a
proxy configured); any *new* proxied consumer must not copy it.

## Adoption steps — the 9 GAP-01 consumers

Proof adoption is done: **SKZ `fetch-sro`** (see the A5 report).
The rest, in the decomposition map's order:

1. **SUB — organelle substrate.** Register `ht` beside `hf` in host
   bootstraps that need HTTPS egress. No code change in the host:
   the organelle surface speaks the existing manifest/host
   contracts and reuses the `net.fetch` egress policy.
2. **FAC — organelle factory** (`~/workspace/organelle/factory/workers/`).
   Replace the per-worker provider HTTP wiring (DeepSeek / NVIDIA /
   Gemini) with `send_blocking` POSTs + auth headers. Keys stay
   where they are (env) — credential custody is GAP-03, not
   transport. One worker first (the DeepSeek adapter), diff its
   outputs, then the rest.
3. **EXC — exchange** (`exchange/rs/.../adapters.rs`, `exchange-rs`
   clients). Swap the adapters' HTTP calls for `send_blocking`;
   claim/complete and provider POSTs map 1:1 (method, headers,
   body). Status-as-data matches the governor's existing
   exact-model bookkeeping. (Exchange was out of scope for the A5
   lane itself; this is a follow-up lane's work.)
4. **EVD — eventd.** Replace the webhook dispatch HTTP call in
   `src/main.rs` with `send_blocking`; eventd keeps its own
   retry/deadline policy around it (retry policy is GAP-06 —
   transport provides the per-call timeout only).
5. **RTR — ai-router / edge workers (JS).** No JS-side action. When
   a router lane is ported to a Rust/wasm worker (GAP-07/GAP-10),
   its upstream calls use `send_async` on wasm32 — the same API
   the native adapters use, so the port is a backend swap, not a
   rewrite.
6. **TRN — translink-repeater (JS).** Same pattern as RTR: when the
   Rust core lands behind the edge shell (with GAP-21 gtfs-rt-decode),
   the upstream feed pull becomes `send_async`; the JS `fetch`
   retires with the shell port.
7. **SKZ — skidz tools.** `fetch-sro` DONE (A5 proof). Remaining:
   `fetch-osm` (identical curl-subprocess swap), then `nim-package`
   and `estate-demo` (curl subprocesses to the ai-router →
   `send_blocking` POSTs; keep their byte-exact stdout writers
   untouched — only the `fetch` fn changes, as in `fetch-sro`).
8. **MCP — mcp servers / fabric.** The Rust consumer is `mcpd`
   (`mcp-fabric`): its HTTP transport adopts `send_blocking` for
   remote MCP endpoints. The 11 Python servers (`web`, `github`, …)
   adopt only through their own Rust ports — do not wrap Python
   HTTP in a subprocess call to this crate.
9. **TEN — tentacle-corp infra (JS workers).** No JS-side action;
   adoption rides the GAP-07 edge-shell port, via `send_async` on
   wasm32, as with RTR/TRN.

## Verification pattern for adopters

Mirror the `fetch-sro` proof: build the consumer, run its existing
smoke against the live endpoint, and confirm the observable output
(records parsed, counts, stdout shape) matches the pre-adoption
run. A transport swap that changes output bytes is a failed
adoption, whatever the cause.
