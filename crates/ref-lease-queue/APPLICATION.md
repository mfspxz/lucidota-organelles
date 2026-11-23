# Applying `ref-lease-queue` (org-030, codon `lq`)

The estate's reusable lease queue: enqueue → claim → heartbeat /
complete / fail, with atomic single-winner claims, claim-resume,
lease-expiry reaping, and idempotency keys. It closes GAP-05 of
the 2026-11-22 decomposition map: six scoped softwares (FAC,
WRK, EXC, EVD, VAN, MCP) re-implement this lifecycle today —
`factory-dispatch`/`factory-jobs`, wreck-worker's JS lease
modules, the Exchange's `claims.rs`, eventd's webhook retries,
VanCan's dispatch state, and the MCP vending machine's
single-use tokens. The Exchange machinery is the semantics
reference; this crate is that lifecycle with the governor, the
ballot, and the provider adapters stripped off.

## The doctrine every adopter gets

- **Atomic single-winner claim.** Claims go through the store's
  compare-and-swap on the item version. One claimant wins an
  item, even with threads racing in-process (in-memory backend)
  and even across two processes sharing one SQLite file
  (conditional `UPDATE ... WHERE version = ?`). Both are proven
  by tests, not asserted.
- **Claim-resume (the Exchange v0.7.2 lesson).** A claimant that
  comes back — process restart, lost response — re-attaches to
  its own live lease via `claim` (resume is checked first) or
  `resume_claim`. It never gets a second item while its lease is
  live, and nobody else can take the item or act on the lease.
- **Leases are time-bounded; time is an input.** The core never
  reads a system clock. Every operation takes time from the
  injected `Clock` (`ManualClock` for tests/hosts that supply
  time, `SystemClock` on native). Expiry is evaluated lazily by
  every operation that touches a leased item and in bulk by
  `reap()` — the zombie sweep.
- **Completion after expiry is rejected.** The Exchange's W4
  rule: a worker that outran its lease does not get its
  completion accepted. The item is expired-transitioned and the
  caller gets `QueueError::LeaseExpired`.
- **Caller-supplied knobs only.** `QueueConfig` has no
  `Default` and no optional fields: `lease_duration_ms`,
  `max_attempts`, `backoff` (fixed / linear / exponential /
  explicit schedule, as data), and `on_exhausted`
  (`dead_letter` | `discard`) are all stated at construction
  and validated as a whole (a retry schedule shorter than the
  retries the cap allows does not construct).
- **Telemetry.** Every transition appends a `QueueEvent`
  (enqueued, duplicate enqueue, claimed, resumed, heartbeat,
  completed, failed, retry scheduled, lease expired, exhausted,
  discarded) with a sequence number and the injected clock's
  timestamp. Persist it via `ref-ledger-append` if it must
  outlive the process; the queue keeps it in memory.
- **Determinism.** Same operation sequence + same clock
  readings → identical items and identical event log,
  byte-for-byte (proven by test). Lease ids are sha256 over the
  canonical claim facts — a name for the claim, not a secret.

## Dependency stanzas

Pure-API consumers (worker cores, CLIs, dispatchers) — no
host/manifest deps in their graph:

```toml
ref-lease-queue = {
  path = "<relative path>/organelles/crates/ref-lease-queue",
  default-features = false,
}
```

Add `features = ["sqlite"]` on native for the durable backend.
Hosts registering the organelle surface take the default
features and register `ref_lease_queue::organelle()` (starts
unconfigured — fails closed until a `configure` call supplies
the complete config) or `ref_lease_queue::organelle_with(config)`.

## Storage backends — stated plainly

| Backend | Where | Durable | wasm32 |
|---|---|---|---|
| `MemoryStore` | in-process map | no | yes |
| `SqliteStore` (feature `sqlite`) | one SQLite file, bundled rusqlite | yes | **no — native only**, cfg-gated out |

The core (state machine, config, backoff, events) compiles and
checks on `wasm32-unknown-unknown` in every feature combination.
On the edge, storage is the host's: a D1- or KV-backed `Store`
implementation is an adopter-side composition with
`ref-cf-storage` (org-027) — the `Store` trait is six methods
(`insert`, `get`, `get_by_idempotency_key`, `list`, `cas`,
`remove`), and `cas` is the only one with a semantic demand:
it must be atomic.

## Per-consumer adoption steps

### FAC — organelle factory (`factory-dispatch` / `factory-jobs`)

`fx`'s crash-safe persisted FIFO queue and `fj`'s job store are
this lifecycle, factory-scoped.

1. Depend on `ref-lease-queue` with `default-features = false,
   features = ["sqlite"]` from the factory core crate.
2. One `SqliteStore` file per work-order run (the run's existing
   directory); `factory-jobs` keeps owning hash-chained result
   bundles — the queue owns lifecycle only, `fj` keeps results.
3. Map: work-order unit → `enqueue(unit_id, payload =
   {work_order, unit}, idempotency_key = genesis input-hash)`;
   worker pickup → `claim(worker_id)`; the worker subprocess
   timeout becomes the lease (`lease_duration_ms` = the run's
   stated timeout, not a new constant); subprocess exit 0 →
   `complete`, nonzero → `fail` with the run's existing retry
   count as `max_attempts` and its retry delay as
   `BackoffPolicy::Fixed`.
4. Replace the persisted-queue recovery scan with `reap()` at
   dispatch start: a crashed worker's units come back exactly
   the way the Exchange's zombie sweep returns its claims.
5. Delete the FIFO/claim code from `fx`; keep its parse →
   partition front end unchanged.

### WRK — wreck (`wreck-worker` JS caps/lease/idempotency modules)

The JS worker hand-rolls lease + idempotency at the edge; the
Rust core behind `wreck-wasm` is where this lands.

1. In the wreck core crate, depend with `default-features =
   false` (no SQLite: edge storage is D1/KV).
2. Implement `Store` over the worker's existing D1 binding
   (six methods; `cas` = `UPDATE ... WHERE id = ? AND version
   = ?` against the claims table wreck-worker already keeps).
   This is the GAP-02 composition — `ref-cf-storage`'s D1 face
   is the transport.
3. Map: a push/event delivery → `enqueue` with
   `idempotency_key` = the event id the JS idempotency module
   already dedupes on; a worker lease → `claim` /
   `heartbeat` / `complete` with the lease durations the JS
   modules currently hardcode, moved into the `QueueConfig`
   the worker constructs at startup.
4. Retire the JS lease/idempotency modules once the wasm core
   serves the same routes; the JS shell keeps caps and routing
   (GAP-07's shell), not lifecycle.

### EXC — Exchange (`exchange-core` `claims.rs` / leases)

The semantics reference itself. Adoption is a transplant of the
lifecycle, not of the governor: `govern.rs`, the ballot, and
the policy gates stay exactly where they are (gates are
`ref-policy-gate`'s job, org-029).

1. Depend with `default-features = false` from `exchange-core`.
2. Implement `Store` over the existing D1 abstraction (`db.rs`)
   — the claims/leases tables already carry every field `Item`
   needs; `cas` maps to the conditional updates `claims.rs`
   already performs.
3. Map one-to-one: `create_lease` (~60 s TTL) →
   `QueueConfig { lease_duration_ms: 60_000, .. }` stated by
   the caller, per the existing policy snapshot; claim →
   `claim` (the v0.7.2 `resume: true` path is `claim`'s
   built-in resume — the orphan-lease bug class it fixed
   cannot recur, because resume is checked before any fresh
   claim); the completing flip's lease-expiry re-check →
   `complete`'s built-in expiry rejection; `sweepExpiredClaims`
   → `reap()`.
4. Keep receipts, the governor trace, and the ballot in
   `exchange-core`; feed them from `LeaseQueue::events()`
   instead of the hand-maintained transition log.
5. Do this behind the existing route surface in one change —
   the deployed worker's behaviour is the test fixture
   (claim/complete/replay batteries must pass unchanged).

### EVD — eventd (webhook dispatch with retries/deadline)

eventd's `Webhook` struct retries deliveries against a deadline
inside the 1,166-line `main.rs`.

1. Depend with `default-features = false, features =
   ["sqlite"]` (or keep `MemoryStore` — eventd's outbox is
   already its durable log; the queue need not be).
2. Map: a watch firing a webhook → `enqueue(delivery_id,
   payload = {url, body, watch}, idempotency_key =
   event_id)`; the dispatcher loop → `claim("webhook")` →
   POST → `complete` on 2xx, `fail` on error with
   `max_attempts` and `backoff` = the retry count and delays
   `eventd.toml` already states per watch (they become config
   data, per-watch queues if they differ).
3. The delivery deadline becomes lease expiry: a hung POST is
   reaped by `reap()` on the next interval tick instead of by
   the hand-rolled deadline check.
4. Delivery outcomes land in the outbox from `events()` —
   one `retry_scheduled`/`exhausted` record per transition,
   replacing the dispatcher's ad-hoc logging.

### VAN — VanCan / Tricycle GIS (`vancan` dispatch claim/lease state)

`vancan/src/dispatch/{dispatch,state}.rs` holds claim/lease
state for driver assignment next to the oracle gates.

1. Depend with `default-features = false, features =
   ["sqlite"]` from the `vancan` crate (dispatch state is
   already file-backed in spirit; `SqliteStore` gives it one
   file).
2. Map: a pickup request → `enqueue(request_id, payload =
   {depot, cans, zone}, idempotency_key = request_id)`; a
   driver taking the job → `claim(driver_id)` — single-winner
   is the whole point of dispatch, and the race test is the
   proof to cite; the driver's completion window →
   `lease_duration_ms` from dispatch config; no-show / timeout
   → `reap()` returns the request to the pool under backoff.
3. The oracle gates in `oracle_gates.rs` stay (they are
   GAP-04 / `ref-policy-gate`); they run *before* enqueue, on
   the request, not inside the queue.
4. Payout stays in `vancan/payout/` — a `Completed` event for
   a request is the trigger the payout ledger consumes.

### MCP — MCP servers / vending machine (single-use tokens)

The vending machine's token contract is a lease queue with
`max_attempts = 1`: a token is claimed exactly once or it is
burned.

1. Depend with `default-features = false` from the gateway /
   minter implementation (when built — the contract and demo
   exist, the minter is GAP-03/GAP-09 work).
2. Map: minting → `enqueue(token_id, payload = {scope,
   grant}, idempotency_key = jti)`; redemption → `claim(jti
   holder)` + `complete` in one step, with `QueueConfig {
   max_attempts: 1, on_exhausted: DeadLetter }` — a second
   redemption attempt finds no queued item, and a replayed
   mint returns `Duplicate` with the token's state. The
   seen-seal registry (GAP-09) can be built on exactly this
   `Duplicate` outcome.
3. Token TTL → `lease_duration_ms` + `reap()`: an expired,
   unredeemed token is transitioned by the sweep, and its
   `LeaseExpired` event is the audit record.
4. The `governor` MCP server's lease checks (authority/lease/
   gate/invariant) delegate to `get`/`stats` reads on the same
   queue instead of re-deriving lease state.

## What this crate deliberately does not do

- **No priorities, no fairness policy.** FIFO by enqueue order
  is the stated order; a priority discipline is a different
  caller's data problem (re-enqueue under a new id), not a
  knob smuggled in here.
- **No persistence of the event log.** Events are in-memory
  telemetry; durability is `ref-ledger-append` composition.
- **No D1/KV backend in the crate.** Edge storage belongs to
  `ref-cf-storage`; this crate defines the `Store` contract
  those backends satisfy.
- **No governance.** Whether a claimant *may* claim is a
  policy-gate question (org-029) answered by the caller before
  it calls `claim`; the queue records who claimed, it does not
  adjudicate who should.
