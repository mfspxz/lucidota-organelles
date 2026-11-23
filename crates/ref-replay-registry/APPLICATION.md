# Applying `ref-replay-registry` (org-034, codon `rr`)

The estate's reusable seen-seal registry: the first
presentation of a sha256 seal registers it; every later
presentation is a replay verdict carrying the original
registration record. It closes GAP-09 of the 2026-11-22
decomposition map: five scoped softwares (PL, WRK, EXC, EVD,
MCP) re-implement replay / single-use-token / duplicate-event
registries today — the Exchange's envelope seal registry,
proof-ledger's seal handling, wreck's single-use tokens,
eventd's duplicate-event suppression, and the MCP vending
machine's `jti` single-use redemption. None exists as an
organelle; each system specifies the shape privately.

## The doctrine every adopter gets

- **Instances are values, never globals.** A registry is a
  `Registry` constructed over a caller-supplied `Store` and a
  caller-supplied `Retention`, and passed explicitly. There
  is no `static`, no `LazyLock`, no process-global set in the
  crate (grep-verifiable). Two registries are isolated by
  construction — the property the Exchange's test harness
  lacked when its seal set was a process global and parallel
  tests minted identical seals into it, eating false 409s
  until the 2026-11-22 harness-isolation fix bolted on an
  `Env`-injected set. Here the injected set is the only kind
  there is.
- **Retention is caller data, with no baked defaults.** TTL
  and capacity arrive in `Retention`, validated at
  construction (a stated TTL must be positive; a stated
  capacity must be ≥ 1). The crate ships no TTL and no
  capacity of its own, and `Retention` has no `Default` impl.
  The Exchange's one hour / 10,000 are *its* policy, stated
  by its adopter as data (see the EXC step).
- **Eviction is explicit and reported.** Nothing is evicted
  lazily inside `present`: an expired-but-unswept seal is
  still a replay. `sweep(now_ms)` is the only eviction path —
  it evicts TTL-expired registrations first, then (over
  capacity) the oldest by `(first_seen_ms, seal)` — and
  returns exactly the records it evicted, sorted by
  `(first_seen_ms, seal)`. Compare the Exchange's private
  shape: a silent `retain` inside the request path plus a
  `LIMIT 500` prune in a cron module, neither of which
  reports what it removed.
- **Saturation fails closed.** At capacity, a *new* seal is
  refused with `RegistryError::Saturated` — never silently
  registered over an eviction, never silently dropped, never
  misreported as a replay. Replay detection for held seals is
  never blocked by saturation: saturation stops the registry
  learning *new* seals, not answering about old ones. (The
  Exchange's private check agrees in shape: at
  `REPLAY_MAX_SEEN` it returns `"full"` and the routes
  reject, and a store error returns `"unavailable"` — also a
  rejection. This crate's store errors propagate the same
  way: no error path registers, evicts, or reports a verdict
  that did not happen.)
- **Time is an input.** `present` and `sweep` take `now_ms`
  from the caller; the core never reads a clock, so scripted
  sequences replay to byte-identical verdicts (proven by
  test, memory vs SQLite included).
- **Seals are sha256, validated at the door.** A seal is
  exactly 64 hex characters, normalized to lowercase;
  anything else is refused and registers nothing.
  `seal_of(content)` is the estate's seal for a byte string.

## Dependency stanzas

Pure-API consumers (worker cores, CLIs, daemons) — no
host/manifest deps in their graph:

```toml
ref-replay-registry = { path = "../organelles/crates/ref-replay-registry", default-features = false }
```

With the durable backend (native only; the `sqlite` feature
is cfg-gated out on wasm32, where storage is the host's
problem and a D1/KV adapter composes over the `Store`
trait):

```toml
ref-replay-registry = { path = "../organelles/crates/ref-replay-registry", default-features = false, features = ["sqlite"] }
```

Organelle-surface consumers take the default features and
register `ref_replay_registry::organelle_with(retention)`
(codon `rr`, capability `replay.registry` for the write ops
`present` and `sweep`; `check` and `stats` are
capability-free). The surface constructor takes the
retention as an argument — retention is caller data, so it
is not a constant of the crate. (`organelle()` exists for
the reference instance and is unbounded, stated in its own
doc comment; adopters with a policy use `organelle_with`.)

## Storage backends — stated plainly

- `MemoryStore` — B-tree map; the test/embedded backend and
  the organelle surface's backend.
- `SqliteStore` (feature `sqlite`, native only) — rusqlite
  bundled, one `registrations` table. `insert_if_absent` is
  `INSERT OR IGNORE` on the seal primary key — the same
  statement shape the Exchange's durable `seal_registry`
  table is written with — so first-vs-replay at the store
  layer is the database's decision, not a check-then-insert
  a second connection can race.
- The core's verdict logic runs over the trait, so backends
  answer identically. Concurrency: within one process,
  atomicity is the caller's mutex discipline —
  `SharedRegistry` (an `Arc<Mutex<Registry>>` wrapper) is
  provided and is what the surface uses; across processes
  over one SQLite file, the primary-key insert keeps the
  first/replay classification correct (the losing writer's
  presentation is answered as the replay it is, from the
  record that won).

## Per-consumer adoption steps

### EXC — the Exchange `seal_registry`

The proven production instance, and the most direct
transplant. Today (read from `exchange-core` for this
application note; the Exchange tree is not modified by this
adoption until EXC's own schedule takes it):

- `routes.rs::check_replay_db` sweeps a process-global
  `SEEN_SEALS` map (TTL `REPLAY_TTL_MS` = 3,600,000 ms,
  cap `REPLAY_MAX_SEEN` = 10,000), answers `"replay"` /
  `"full"` / `"ok"` / `"unavailable"`, and writes the
  durable table `seal_registry (seal TEXT PRIMARY KEY,
  first_seen INTEGER)` via `INSERT … ON CONFLICT DO
  NOTHING`; `observe.rs::prune_seal_registry` deletes the
  oldest 500 rows per prune; `Env.seen_seals` is the
  harness-isolation injection point.

Adoption:

1. Construct one registry per isolate over the durable
   store: on Workers, a `Store` adapter over the existing
   D1 `seal_registry` table (its schema is already
   seal + first_seen; the adapter adds the `presentations`
   count in its own column or side table — the table is
   additive, the deployed worker's other tables untouched).
   Retention is the Exchange's own numbers, now stated as
   data: `Retention::new(Some(3_600_000), Some(10_000))`.
2. `check_replay_db` becomes one `present(seal, now_ms)`
   call: `First` → `"ok"`, `Replay` → `"replay"` (HTTP 409,
   unchanged), `Err(Saturated)` → `"full"`, `Err(Store)` →
   `"unavailable"`. The route's outward behaviour is
   identical; the stringly-typed four-way answer becomes a
   typed verdict with the original record attached (the
   rejection receipt can now name the seal's first-seen
   instant, which the current code cannot report).
3. Delete the in-isolate `SEEN_SEALS` global, its lazy
   `sweep_seen_seals`, and the `Env.seen_seals` injection
   field. Tests construct their own `Registry` values —
   the isolation the harness fix simulated becomes the
   only possibility, and `clear_seen_seals_for_test` has
   no successor because there is nothing shared to clear.
4. The reaction loop's `prune_seal_registry` becomes an
   explicit `sweep(now_ms)` on the same registry: TTL
   expiry is the retention's job, and the sweep's returned
   eviction list replaces the unreported `LIMIT 500`
   delete — the prune becomes a receipt-shaped record of
   exactly which seals aged out.
5. The two-layer shape (fast in-isolate map in front of a
   durable table) is preserved if EXC wants it: two
   registries, one per layer, composed by the caller —
   present to the durable registry is authoritative; the
   in-memory layer is a `check` cache. Composition is the
   caller's stated policy, not a crate feature.

### MCP — vending token redemption (`jti` single-use)

The TOKEN-CONTRACT-v1 token payload carries
`{v, sub, caps, iat, exp, jti, single_use, aud}`; redemption
checks "single-use (jti not seen)" against a private
seen-set in the gateway.

1. The gateway constructs its registry over its durable
   store with retention derived from the token policy it
   already states: TTL = the maximum token lifetime it
   honours (a `jti` need only be remembered until its
   token's `exp` has passed — after that the token fails
   expiry regardless), capacity = the gateway's stated
   redemption volume. Both are the gateway's numbers,
   passed in.
2. Redemption of a `single_use` token is
   `present(seal_of(jti), now_ms)`: `First` redeems,
   `Replay` refuses — and the refusal carries the original
   record, so the gateway's decision log (the contract
   already records "the token's jti, the decision, and the
   ontological justification") gains the first-redemption
   instant and the presentation count instead of a bare
   "seen".
3. Multi-use tokens (`single_use` false) do not touch the
   registry — stated here so the adoption doesn't grow a
   behaviour the contract doesn't have.
4. The minter needs no registry: minting is
   `ref-credential-broker`'s `grant` (org-028). Broker and
   registry compose at the gateway: broker mints and
   redeems grants, the registry is the redemption's
   single-use memory.

### PL — proof-ledger seals

`pl` seals envelopes and work products; its replay surface
is the same shape at smaller volume.

1. Anywhere `pl` (or a verifier built on it) tracks "have I
   seen this seal" — envelope intake, wsign manifest
   checks — the ad-hoc set becomes a `Registry` over the
   caller's store, constructed where the check happens.
2. Retention is PL's stated policy per call site: a
   verifier that must never forget a seal within an audit
   window states that window as its TTL; there is no
   estate-wide number to inherit.
3. Because instances are values, `pl`'s many short-lived
   CLI invocations each construct exactly the registry
   they mean — over `SqliteStore` where the memory must
   outlive the process, over `MemoryStore` where it must
   not.

### WRK — wreck single-use tokens and duplicate events

Wreck's `wp` token custody (see org-028's application note:
`token_for` ≙ broker `grant`) spends tokens once; its
governor also dedups events.

1. Token spend is `present(seal_of(token_id), now_ms)` on a
   registry the governor constructs over its D1-backed
   store (composition with `ref-cf-storage`, org-027);
   `Replay` is a refused spend carrying the original spend
   record for the canon receipt.
2. Duplicate-event suppression uses a second, separate
   registry instance — different retention, different
   store — which costs nothing to keep separate precisely
   because instances are values: token memory and event
   memory cannot contaminate each other.

### EVD — eventd duplicate-event registry

Eventd's watches can re-fire on the same underlying change
(restarts, ledger-tail overlaps); its dedup is a private
seen-set inside the daemon.

1. The daemon constructs one registry at startup over a
   `SqliteStore` in its state directory — the memory
   survives the daemon's own restarts, which is exactly
   when duplicate fires cluster.
2. Event ids are seals: `seal_of(event_id_bytes)` (or the
   event's existing content hash, where the outbox already
   computes one). First → dispatch; Replay → suppress,
   with the original record available to the log line that
   explains the suppression.
3. The daemon's periodic housekeeping calls `sweep` and
   logs the eviction count — the registry's mass and its
   forgetting both become telemetry, per the estate's
   telemetry-over-hardcoded-policy doctrine: the TTL is
   eventd.toml's stated value, passed in at construction.

## Compositions

### With `ref-credential-broker` (org-028) — broker receipts

The broker appends a `BrokerReceipt` per operation,
including failed and unknown-ref attempts, keyed by a
sha256 receipt id. Where a broker deployment must answer
"has this exact operation been presented before" —
duplicate `execute` submissions, replayed `redeem`
presentations — the receipt id *is* the seal:
`present(receipt_id, now_ms)` on a registry the broker's
host constructs beside the broker. The broker's receipt
log stays the audit trail; the registry is the
detection index over it, and a `Replay` verdict's record
points back into the log by first-seen instant.

### With `ref-lease-queue` (org-030) — idempotency keys

`ref-lease-queue` items carry an optional
`idempotency_key`, and its `enqueue` already dedups within
the queue. The registry is for the layer *outside* the
queue: a producer retrying an enqueue across processes, or
a consumer acknowledging a completion twice.

1. Producer side: before enqueue, `present(seal_of(key),
   now_ms)` on the producer's registry; `Replay` means the
   key was already submitted — fetch the existing item via
   the queue's `get_by_idempotency_key` instead of
   enqueueing a twin.
2. The queue's own in-queue dedup stays (it is the queue's
   invariant); the registry covers the cross-process and
   cross-restart cases the queue's store may not span.
   Retention is the producer's stated retry horizon.

## What this crate deliberately does not do

- **No globals.** No statics, no lazy singletons, no
  "default registry". If two parts of a system must share
  a registry, they share a value (`SharedRegistry` clones
  are one registry) — sharing is visible in the types.
- **No baked retention.** No default TTL, no default
  capacity, no presets. `Retention::unbounded()` exists
  because "no limit" is a legitimate stated policy, not
  because the crate chose one for you.
- **No lazy eviction.** `present` never sweeps. A registry
  that must forget must be swept, by its owner, on its
  owner's schedule — and the sweep says what it forgot.
- **No clock.** `now_ms` is an argument everywhere. A
  caller who wants wall time reads its own clock and
  passes the reading in, where it becomes part of the
  record.
- **No seal semantics.** A seal is an opaque sha256 to
  this crate: what was sealed, and what a replay *means*
  (409, refused spend, suppressed event), is the
  adopter's decision. The crate detects; it does not
  legislate the response.
