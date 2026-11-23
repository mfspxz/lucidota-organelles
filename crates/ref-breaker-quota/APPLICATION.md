# Applying `ref-breaker-quota` (org-032, codon `bq`)

The estate's circuit breaker + quota meter: a closed / open /
half-open breaker with caller-stated failure threshold,
counting window, cooldown schedule and probe budget, and a
quota meter with caller-stated limit and window shape (fixed,
sliding, calendar-day). It closes GAP-06 of the 2026-11-22
decomposition map: five scoped softwares (FAC, EXC, EVD, RTR,
TRN) re-implement the same machinery today — RTR's per-lane
breakers and RPM windows in `ai-router.js`, EXC's `quotas`
table in the governor, FAC's `RateLimiter` in
`factory/workers/adapters/_limits.py`, EVD's resource-governor
watch, TRN's per-feed poll floor.

## The doctrine every adopter gets

- **The organelle meters and trips; it does not legislate.**
  There are no presets, no named groupings, and no defaults in
  this crate. `BreakerConfig` and `QuotaConfig` deserialize
  only from data that states every field, and construction
  validates what was stated (threshold ≥ 1, window > 0,
  non-empty cooldown schedule, limit ≥ 1). A number that
  decides behaviour is a number the caller wrote down.
  Config JSON in this document is illustrative adopter data,
  never shipped crate data.
- **Telemetry is the product.** Every state transition —
  trip, half-open, close, reopen, failure-record clear, quota
  window reset, quota exhaustion, manual reset — appends a
  `TraceRecord`: caller time, the counts at that moment, the
  event-specific facts (cooldown applied, jitter supplied,
  usage at exhaustion, previous window's usage), and the
  sha256 of the config in force. Persist it via composition
  (`ref-ledger-append`, `ref-cf-storage`, a host receipt log).
- **Time and jitter are inputs.** The cores take `now_ms` on
  every call and never read a clock; jitter is a signed
  per-failure input, so a replayed script reproduces the exact
  cooldowns a live run took. Same script + same configs →
  byte-identical state and trace.
- **Backpressure honesty.** Quota consumption is
  all-or-nothing: a request larger than the remaining quota
  is denied whole and consumes nothing. A denial carries
  `retry_at_ms` whenever the window shape makes it knowable,
  and `None` when the request can never fit the limit — never
  a guessed number. Breaker denials likewise: open gives the
  exact cooldown end; a saturated probe budget gives `None`
  (a probe completion, not a clock, changes that).

## Dependency stanzas

Pure-API consumers (worker cores, governors, daemons) — no
host/manifest deps in their graph:

```toml
ref-breaker-quota = {
  path = "<relative path>/organelles/crates/ref-breaker-quota",
  default-features = false,
}
```

Hosts registering the organelle surface take the default
features and register `ref_breaker_quota::organelle()`. Ops:
`configure_breaker` / `configure_quota` (config as data —
required before use; an unconfigured name fails closed),
`admit`, `record_success`, `record_failure`, `try_consume`,
`available`, `state`, `trace`. Timed ops take `now_ms` as an
input. Write ops require the `breaker.quota` capability.
Concurrent embedders use `SyncBreaker` / `SyncQuota`: the
mutex makes check-and-consume and check-and-admit atomic, so
racing callers cannot overshoot a quota or a probe budget.

## Semantics worth knowing

- **Breaker failure counting is consecutive-within-window:**
  failures older than `window_ms` stop counting, and a
  success in the closed state clears the record. Stating a
  window at least as long as the longest plausible failure
  burst reproduces pure consecutive counting (RTR's current
  semantics).
- **Outcomes recorded while open are ignored.** A late
  failure from a pre-trip call does not extend the cooldown;
  a late success does not close a breaker nobody probed.
- **Closing resets the escalation.** Probe success resets
  `open_count` to 0, so the next trip starts at the first
  cooldown of the caller's schedule again.
- **Persistence is adopter-side.** The cores are in-memory
  state machines; an adopter that must survive restarts
  snapshots state + trace through `ref-cf-storage` /
  `ref-ledger-append`, the same composition as the other
  reference organelles.
- **The wasm face is compile-proven, not runtime-proven** in
  a deployed worker (the standing caveat shared with
  org-026/027/028/029/031).

## Adoption steps, per consumer

### RTR — the ai-router (`free-stack/workers/ai-router.js`)

Today, per lane: `BREAKER_FAILS = 3` consecutive failures
opens the breaker; `BREAKER_BACKOFF_S = [30, 60, 120, 300]`
seconds escalates by `openCount`; `COOLDOWN_JITTER = 0.25`
(±25%); RPM is a sliding window over a `ts[]` array against a
per-lane `rpmLimit`; a provider 429 sets a provider-supplied
cooldown via `recordThrottle`. All of those constants move
from JS literals into per-lane config data (the KV lane
registry the router already keeps):

```json
{"name": "<lane>", "config": {
  "failure_threshold": 3,
  "window_ms": 600000,
  "cooldown": {"schedule": {"cooldowns_ms": [30000, 60000, 120000, 300000]}},
  "half_open_max_probes": 1,
  "half_open_successes_to_close": 1}}
{"name": "<lane>:rpm", "config": {
  "limit": "<rpmLimit from lane config>",
  "window": {"sliding": {"window_ms": 60000}}}}
```

Exact step (rides the GAP-10 Rust port of the router): the
lane loop calls `admit` before an attempt, `record_success`
/ `record_failure` after it, passing the router's own
jitter sample (`±25%` of the scheduled cooldown, sampled by
the router as today) as `jitter_ms`. Admission control
becomes `try_consume` on the lane's RPM quota; a denial's
`retry_at_ms` replaces the hand-computed window maths. The
429 path maps exactly, not approximately: a dedicated
threshold-1 breaker per lane with `{"fixed": {"cooldown_ms":
0}}`, where `record_failure(now, retry_after_ms)` applies
the provider's own cooldown as the jitter input. The `bq`
trace replaces the router's hand-kept incident log entries
for breaker trips — `/admin/incidents` reads the trace,
which now also carries the config fingerprint per trip.

### EXC — the Exchange (`exchange/rs/exchange-core`)

Two distinct adoptions; the deployed worker is untouched by
this crate and both happen on EXC's own release cadence.

1. **The governor's QUOTA gate.** `govern.rs` reads a D1
   `quotas` table whose rows carry THROTTLED (with
   `throttled_until`) and exhausted/suspended states, and
   hand-builds the gate's bookkeeping. Exact step: keep the
   table as the persistence layer, but let the state machine
   be org-032 — one `Breaker` + one `QuotaMeter` per
   resource, configs assembled from the same `key_config` /
   `exchange_config` rows the governor already loads,
   snapshots persisted back to D1 through the existing db
   layer (adopter-side composition). `throttled_until` is
   the breaker's `cooldown_until_ms`; suspension is a quota
   whose window the operator states. The gate's trace
   entries come from the `bq` trace instead of hand-built
   strings, so a quota denial carries counts + config
   fingerprint like every other gate's evidence.
2. **The D1 rows-read budget — the burn lesson.** The
   Exchange died at roughly 09:20Z every day because
   `migrate()` re-ran on cold isolates over an unindexed
   COUNT and burned the D1 free-tier daily rows-read cap
   (~5M rows/day) before noon; the A3 fix gated the
   migration, but nothing *metered* the burn — the first
   symptom was the cap itself. Exact step: meter every D1
   result's `rows_read` through one quota, stated by the
   operator as data:

   ```json
   {"name": "d1-rows-read", "config": {
     "limit": "<operator's daily budget, below the plan cap>",
     "window": {"calendar_day": {"utc_offset_ms": 0}}}}
   ```

   Each query consumes its measured rows-read as cost
   units; the `quota_exhausted` trace record fires at the
   budget line — an alarm with the day's counts attached,
   hours before a hard cap would have killed the worker.
   The limit is the operator's number to state (an alarm
   line, deliberately under the cap); the crate ships no
   figure of its own.

### FAC — the factory workers (`organelle/factory/workers/adapters/_limits.py`)

Today: a sliding-window `RateLimiter` per provider (at most
`rpm` calls per rolling 60s, reject-don't-queue), with `rpm`
read from `quotas.json` — and a baked-in fallback of 60 when
the file or the provider entry is missing. That fallback is
a default that decides behaviour; adoption deletes it.

Exact step: `limiter_for(provider)` constructs a `SyncQuota`
with `{"sliding": {"window_ms": 60000}}` and the provider's
`rpm` from `quotas.json`, now *required* — a provider absent
from the file is a construction error at worker start, not a
silent 60. `acquire()` becomes `try_consume(now, 1)`: on
denial it raises the same `RateLimited`, with the message's
retry figure taken from the outcome's `retry_at_ms` (the
moment the oldest in-window call expires — the number
`_limits.py` currently hand-computes). The reject-don't-queue
contract the dispatcher relies on is unchanged. Python
workers reach the meter over the REST/unix surface until the
factory's own Rust port; the state machine is org-032 either
way.

### EVD — eventd (`eventd.toml` resource-governor watch)

Today the resource governor is a watch entry running a bash
script (`resource-governor`) whose thresholds live in shell,
surfacing as `watch.error` warn lines with raw memory
figures in the daemon log. Exact step: the numbers move into
`eventd.toml` as stated config — a `Breaker` per watch
command (caller-stated failure threshold, window and
cooldown schedule) gating re-arm when a watch command fails
repeatedly, instead of the daemon discovering a failing
watch through log noise; and the governor's resource
readings metered as cost units against a caller-stated
ceiling, with the `bq` trace (not warn lines) as the record
that lands in the outbox: each record carries the reading,
the ceiling in force, and its config fingerprint. eventd
already injects time everywhere; it passes its tick time as
`now_ms` unchanged.

### TRN — the TransLink repeater (`translink-repeater/worker.js`)

Today: `REFRESH_MS = 5000` — a snapshot refreshes on demand
at most once per 5s per feed regardless of client count,
with an inflight dedup map; the upstream is TransLink's
keyed GTFS-RT API. Exact step (rides TRN's Rust port, after
the GAP-21 decoder): the poll floor becomes one quota per
feed, stated in the worker's config instead of a JS
constant —

```json
{"name": "feed:<name>", "config": {
  "limit": 1,
  "window": {"fixed": {"window_ms": "<refresh floor from config>", "anchor_ms": 0}}}}
```

An upstream poll consumes 1; a denial means "serve the KV
snapshot", which is already the worker's behaviour — the
denial's `retry_at_ms` is exactly the snapshot's earliest
refresh moment, replacing the `Date.now() - fetched_at`
comparison. Add a second meter for the upstream key itself:
`calendar_day` at offset 0 with the operator-stated daily
budget from TransLink's key terms, so the repeater degrades
to stale snapshots at the budget line instead of learning
about the cap from upstream 429s.
