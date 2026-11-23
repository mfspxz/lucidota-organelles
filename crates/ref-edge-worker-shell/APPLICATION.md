# Applying `ref-edge-worker-shell` (org-031, codon `ew`)

The thin Cloudflare Workers shell as one crate: a small router,
a fail-closed secret gate, honest JSON envelopes, fetch +
scheduled dispatch, and storage bindings composed over
`ref-cf-storage` (org-027). It closes GAP-07 of the 2026-11-22
decomposition map: five scoped softwares (WRK, EXC, RTR, TRN,
TEN) need this shell — TEN alone writes it five times in JS
(webhook router, ledger viewer, status ingest, heartbeat
receiver, Odin map worker), TRN and RTR twice more. The one
proven production instance of the pattern in Rust is the
Exchange's worker; this crate is that glue, generalised. A new
worker is then: shell + organelles + route handlers, nothing
else — `examples/minimal-worker/` is the whole of one and is
the adoption proof (it compiles for `wasm32-unknown-unknown`
against the real workers-rs types).

## The doctrine every adopter gets

- **The gate runs before routing.** An unauthenticated request
  is rejected before any handler runs and before the router is
  consulted, so it learns nothing about which routes exist
  (an unknown path without the secret is a 401, not a 404).
- **Fail-closed in every direction.** No secret configured in
  the env → deny. Missing or empty presented value → deny.
  Mismatch → deny. The comparison is timing-safe
  (constant-time over the longer input, length difference
  folded in — no early exit on length, unlike the JS
  originals). There is no configuration in which the gate
  fails open.
- **Caller-supplied knobs only.** `GateConfig` has no
  defaults: the header name, the secret binding name, the
  exempt paths, and whether a `?key=`-style query fallback is
  accepted are all required construction data. The router has
  no built-in routes — not even a health route; a worker that
  wants one registers it and, if it should be public, exempts
  it.
- **Honest envelopes.** Success is `{"ok": true, ...}`;
  failure is `{"ok": false, "error": "<code>", "message":
  "<detail>"}` (`message` omitted when empty — never
  present-but-blank). A handler error becomes its envelope;
  an unknown route is a 404 envelope that names the route; a
  known path under the wrong method is a 405 with an `Allow`
  header, never a misleading 404.
- **Scheduled dispatch is exact-match.** A cron string the
  shell does not know is an error the glue logs — never a
  silent run of some other handler. Scheduled events carry no
  presented secret, so the gate does not apply to them; exact
  cron matching is their discipline.
- **No storage of its own.** Handlers receive a `Ctx` whose
  KV / D1 / R2 / Queue accessors are org-027's `wasm_bindings`
  types, resolved from the worker env. On native, handlers
  use org-027's REST client directly.

## Dependency stanzas

A real worker (needs the workers-rs glue):

```toml
ref-edge-worker-shell = {
  path = "<relative path>/organelles/crates/ref-edge-worker-shell",
  features = ["workers"],
}
```

Pure-API consumers (native cores, tests, hosts validating
route tables through the organelle surface) take the default
features; consumers that want neither the surface nor the
host/manifest deps take `default-features = false`, the same
discipline as org-025 through org-030. The `workers` feature's
dependencies are target-gated to wasm32, so enabling it costs
a native build nothing.

The entry points are two lines each — see
`examples/minimal-worker/src/lib.rs`: `#[event(fetch)]` calls
`workers_glue::fetch_dispatch`, `#[event(scheduled)]` calls
`workers_glue::scheduled_dispatch`, and the `Shell` itself is
built once (`OnceLock`) from gate config + routes + crons.

## Per-consumer adoption steps

### WRK — wreck (`wreck-worker`, the designed exemplar)

`wreck-worker` is the hybrid pattern's designed exemplar: a JS
shell (caps, routing, lease modules) over the `wreck-wasm`
core. GAP-07 adoption replaces the JS shell half; the core is
untouched (its lease/idempotency lifecycle is GAP-05 /
org-030's step, not this one's).

1. New worker crate beside `wreck-wasm`, depending on the
   shell with `features = ["workers"]`; the existing core
   becomes the handlers' callee, exactly as the JS shell
   calls it today.
2. State the gate once: `GateConfig` with the header and
   secret binding names `wreck-worker`'s JS gate already
   uses, `exempt` = the routes the JS shell currently serves
   unauthenticated (named one by one — the shell ships no
   exemptions of its own), `query_param` = the JS gate's
   current fallback setting, stated explicitly.
3. Move each JS route to a `Shell::route` registration with
   the same method + path; handlers call the wasm core and
   return `ShellResponse::ok` / `ShellError` instead of the
   JS envelope code, which is deleted.
4. Storage the JS shell reaches for directly goes through
   `Ctx` accessors (`GOVERNOR_KV`, `CHAIN_D1`,
   `wreck-push-events` — org-027's bindings over the same
   wrangler names).
5. Retire the JS shell when the Rust worker serves the same
   routes; behaviour fixtures are the JS worker's current
   responses (gate refusals, envelopes, status codes).

### EXC — Exchange (`exchange-worker`, the reference instance)

No adoption is owed: `~/workspace/exchange/rs/exchange-worker`
is the proven production instance this crate was generalised
from, and it stays as it is. The shell's existence changes
EXC's future, not its present:

1. Any *new* Exchange-adjacent worker starts from the shell
   (plus org-027 bindings) instead of copying exchange-worker
   and deleting the parts it doesn't need.
2. If exchange-worker's glue is ever refactored, it refactors
   *onto* this crate — the dispatch shapes here are its
   shapes, so the migration is a dependency swap behind the
   same route surface, gated on the claim/complete/replay
   batteries passing unchanged. Until that refactor is
   scheduled, the deployed worker is not touched for this
   GAP.

### RTR — ai-router (`~/workspace/free-stack/workers/ai-router.js`)

One JS file carrying lane routing, its own key handling, and
the LANES_KV registry (namespace `12bdef850f5642f793fafebd1afe06bb`).

1. New worker crate with `features = ["workers"]`; the
   lane/provider logic becomes handlers, the shell takes
   routing and the gate.
2. The router's existing key checks become one `GateConfig`
   (header + binding names as the JS states them today;
   `query_param: None` unless the JS currently accepts one —
   the audit trail says the pinned-model behaviour is
   header-driven, so the honest starting value is `None`).
3. LANES_KV access moves to `Ctx::kv("LANES_KV")` (org-027);
   the deploy keeps the existing KV binding — deploying
   without it breaks durable state, as the Nov 22 router fix
   proved.
4. The model-pin convention (`<lane>/<model-id>`, alias
   `nim`) is handler logic, not shell logic: it lands in the
   route handlers unchanged, including the loud
   `x-model-substituted` headers — those are response headers
   the handler sets on its `ShellResponse`.

### TRN — translink-repeater (`~/workspace/translink-repeater/`)

A JS worker serving decoded GTFS-RT JSON from KV snapshots
(`/v1/vehicles|trips|alerts`, health, route+bbox filters),
with a refresh floor driven by its fetch cycle.

1. New worker crate with `features = ["workers"]`. Routes:
   `GET /health` (registered + exempt if it is public today),
   `GET /v1/vehicles`, `GET /v1/trips`, `GET /v1/alerts`;
   the snapshot refresh becomes a `Shell::scheduled`
   handler under the cron string the incumbent worker's
   wrangler config states.
2. Snapshots stay in the same KV namespace (binding name
   `SNAP` per the incumbent config; org-027 via
   `Ctx::kv`), so the client contract — `feed_ts` /
   `fetched_at` / `age_s` on every response — is preserved
   by the handlers, not renegotiated.
3. The GTFS-RT decoder (`gtfsrt.js`, 163 lines) is GAP-21's
   organelle, not this crate's: shell adoption and decoder
   port are separate steps, and the honest order is decoder
   first or both in one change — a Rust shell cannot call
   the JS decoder. Until then TRN's shell adoption is
   *specified, not started*.
4. The `TRANSLINK_API_KEY` secret stays a dashboard-set
   Worker secret (its placement is Zack-gated, unchanged by
   this GAP); the ported worker reads it through the env
   like the incumbent does.

### TEN — tentacle-corp infra (five JS workers, one shell)

The five copies, each becoming a small crate (or one crate
with five wrangler configs — the shell doesn't care):

1. **Edge webhook router** (`infra/worker/worker.js`) —
   shared-secret verify + action routing + cron skeleton
   maps one-to-one: one `GateConfig`, actions as routes, the
   cron skeleton as `Shell::scheduled` registrations.
2. **Private ledger viewer** (`infra/ledger/worker.js`) —
   the estate's `?key=` shell: its `GateConfig` is the one
   TEN worker that states `query_param: Some("key")`,
   because the incumbent accepts it; the timing-safe
   compare it hand-rolls is `timing_safe_eq` here. The
   entries API + tail become routes.
3. **Status ingest** (`infra/status/worker.js` +
   `districts/status/worker.js`) — gated ingest route +
   `status.json` served via `ShellResponse::raw_json` (a
   bare document contract, no envelope — the shell supports
   both, the handler chooses).
4. **Heartbeat receiver** (`infra/heartbeat/`) — the
   `x-heartbeat-secret` header gate is exactly the shape
   `examples/minimal-worker` ships; the Merkle cascading
   (`merkle.js`) is GAP-18's organelle, consumed by the
   handler, not re-implemented in the shell step.
5. **Odin map worker** (`infra/odin-map/worker.js`) — gated
   app shell + probe forwarding: the gate + routes here;
   forwarding is a handler calling org-026
   (`ref-https-transport`) or org-027 bindings.

Each TEN worker keeps its existing secret values, binding
names, and routes; the migration is per-worker and
independently deployable, and no worker's migration blocks
another's.

## What this crate deliberately does not do

- **No deployment.** Uploading a worker, setting its
  bindings and cron triggers, is GAP-13 (`worker-deploy`).
  This crate's contract ends at compiling against the real
  runtime types and dispatching correctly — the example's
  Cargo.toml states the wrangler side as the consumer's
  step.
- **No binary request bodies in the glue.**
  `fetch_dispatch` reads the body as text for the methods
  that carry one (the estate's edge APIs are JSON/text). A
  worker whose contract is binary states that itself and
  does not use this glue path for those routes.
- **No routing policy.** No built-in routes, no default
  exemptions, no fallback handler: what a path does without
  the secret, and whether it exists at all, is the
  consumer's stated data.
- **No storage code.** Bindings are org-027's; the shell
  resolves and hands over, it does not wrap or cache.
