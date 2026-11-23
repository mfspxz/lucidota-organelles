# Applying `ref-policy-gate` (org-029, codon `pg`)

The estate's deterministic policy-gate evaluator: ordered hard
gates over **caller-supplied policy data**, returning a verdict
plus the complete evaluation trace. It closes GAP-04 of the
2026-11-22 decomposition map: six scoped softwares (SUB, WRK,
EXC, RTR, VAN, MCP) re-implement the same gate stack today —
EXC `govern.rs`, MCP `governor/server.py`, VAN `oracle_gates.rs`,
WRK's govern core, the ai-router's fail-closed tier policy, and
ad-hoc domain checks around the substrate host's dispatch.

## The doctrine every adopter gets

- **The organelle evaluates; it does not legislate.** There are
  no presets, no named groupings, and no defaults in this crate.
  A `Policy` deserializes only from data that states, in full:
  `on_empty` (what an empty gate list means), `on_missing_input`
  (what an absent input means), and `gates` — each gate a list of
  predicates whose thresholds are the caller's numbers, strings,
  booleans, or lists. Policy JSON shown in this document is
  illustrative adopter data, never shipped crate data.
- **Telemetry is the product.** The `Evaluation` records every
  gate and every predicate: input name, actual value seen,
  threshold compared against, individual outcome, plus a
  `trace_sha256` over the canonical record. Drop it into a
  receipt or an evidence log as-is.
- **Short-circuit honesty.** Gates run in the caller's order;
  the first failing gate ends the run, and every later gate is
  still present in the trace with outcome `not_evaluated` (each
  predicate likewise, with no actual value). Inside a gate there
  is no short-circuit: all predicates evaluate, so the trace
  shows the failing gate's full state.
- **Determinism.** Same policy data + same inputs →
  byte-identical `Evaluation`. Evaluation reads no clock, no
  RNG, no environment, no I/O. Time is an input like any other:
  the caller supplies `now`; predicates compare it.
- **Nothing is silently reinterpreted.** A missing input, a
  type mismatch, and a malformed predicate (threshold present
  where the operator takes none, absent where it requires one,
  `in` over a non-array) are three distinct recorded outcomes,
  and each fails its gate — unless the caller's own
  `on_missing_input: "error"` configuration turns the first into
  an evaluation error instead. `exists` is exempt from the
  missing-input path: for `exists`, absence is the evaluated
  fact (pass = present, including a present `null`).

## Dependency stanzas

Pure-API consumers (worker cores, governors, CLIs) — no
host/manifest deps in their graph:

```toml
ref-policy-gate = {
  path = "<relative path>/organelles/crates/ref-policy-gate",
  default-features = false,
}
```

Hosts registering the organelle surface take the default
features and register `ref_policy_gate::organelle()`. One op:
`evaluate` with `{policy, inputs}`, returning the `Evaluation`
JSON. No capability is required — evaluation is a pure function
of its inputs.

## Operator vocabulary (semantics, not policy)

`lt` `le` `gt` `ge` (numeric), `eq` `ne` (any JSON value),
`in` (actual ∈ threshold array), `contains` (substring, or
array membership), `exists` (input present; no threshold),
`is_true` (input is boolean `true`; no threshold). A gate
passes iff every predicate passes; a gate with no predicates
passes vacuously and its trace entry shows the empty list, so
the vacuity is on the record.

## Adoption steps, per consumer

### EXC — the Exchange governor (`exchange/rs/exchange-core/src/govern.rs`)

Today `govern()` runs 11 ordered gates — IDENTITY, AUTHORITY,
DATA, CAPABILITY, EVIDENCE, QUOTA, COST, MODEL, CONFIG,
INTEGRITY, EFFICIENCY — hand-building its trace with `gate()`
and back-filling unreached gates via `vacuous()` ("vacuous —
no candidate reached this gate"), while thresholds live as
branches in `govern.rs` / `policy.rs` over values read from
the D1 config tables (`key_config`, `exchange_config`).

Exact step: keep `govern()` as the **input producer** — it
alone knows how to fetch candidate rows, health, evidence and
config from D1. For each candidate, build `Inputs` from the
row + config, and express each gate's checks as `pg`
predicates whose thresholds are read from the same config
rows the governor already loads. Illustrative shape (values
from the key's config row at submit time, not constants):

```json
{"name": "QUOTA", "predicates": [
  {"input": "quota_remaining", "op": "gt", "threshold": 0}]}
{"name": "COST", "predicates": [
  {"input": "est_cost_micro", "op": "le", "threshold": "<cost_cap from key_config>"},
  {"input": "paid_authorized", "op": "eq", "threshold": true}]}
{"name": "EVIDENCE", "predicates": [
  {"input": "usable", "op": "eq", "threshold": true},
  {"input": "evidence_tier_rank", "op": "ge", "threshold": "<warranted tier>"}]}
{"name": "MODEL", "predicates": [
  {"input": "model_match", "op": "eq", "threshold": true}]}
```

Then delete the `gate()` / `vacuous()` trace plumbing: the
`pg` `Evaluation` *is* the governor trace, and verdict `deny`
+ `failed_gate` replaces the `rejected[].gate` bookkeeping
one-for-one. One semantic upgrade to plan for: EXC's
`vacuous()` marks unreached gates `pass: true`; `pg` marks
them `not_evaluated`. Receipts get more honest — any consumer
matching on "vacuous" trace entries must switch to reading
the outcome field. The deployed worker is untouched by this
crate; adoption happens inside `exchange-core` on EXC's own
release cadence.

### WRK — the wreck decision core (`wreck-governor`)

WRK's core is intentionally one organelle (claim → view →
policy → verdict, per its MAPPING.md), so adoption is inside
`wreck-governor`, not a split: the **policy** step becomes a
`pg` call. `wreck-graph`'s view supplies the inputs (claim
fields, view facts, canon state); the work order supplies the
gates and thresholds as data. The `pg` trace attaches to the
canon receipt beside the verdict — the merge record gains the
full per-predicate proof instead of the governor's private
gate bookkeeping.

### VAN — VanCan dispatch (`vancan/dispatch/oracle_gates.rs`)

Today: one Rust function per gate returning `GateResult` —
`gate_driver_active_lot`, `gate_lot_already_assigned(lot_id,
assigned_lot_ids)`, `gate_driver_eligibility(driver_id,
is_active)`. Exact step: keep the function signatures as
**input builders** during migration (they already gather
exactly the right state), and replace their comparison bodies
with one shared `pg` policy assembled from dispatch config:

```json
{"name": "ELIGIBILITY", "predicates": [
  {"input": "driver_is_active", "op": "is_true"}]}
{"name": "LOT", "predicates": [
  {"input": "lot_assigned", "op": "eq", "threshold": false}]}
```

`GateResult` maps from the verdict (`allow` = pass). The
split/payout rules stay bespoke in VAN (GAP-24 is correctly
not a common organelle); only the gate evaluation moves.

### MCP — the vending-machine governor (`mcp-servers/governor/server.py`)

The Python governor server stops evaluating its own gate
chain. Per request it assembles inputs from the token
presentation — scope, expiry, the single-use registry's
answer — and calls `pg` over the REST or unix-socket surface
(the manifest declares all transports), with thresholds taken
from the token-contract configuration (TOKEN-CONTRACT-v1) as
policy data:

```json
{"name": "SINGLE-USE", "predicates": [
  {"input": "jti_seen", "op": "eq", "threshold": false}]}
{"name": "EXPIRY", "predicates": [
  {"input": "now", "op": "le", "threshold": "<exp claim>"}]}
{"name": "SCOPE", "predicates": [
  {"input": "scope", "op": "in", "threshold": ["<granted scopes>"]}]}
```

`now` is supplied by the server per request — `pg` never
reads a clock, so the trace remains reproducible from the
receipt alone. The returned trace is the governor's audit
record, replacing hand-written denial reasons.

### RTR — the ai-router (rides the GAP-10 Rust port)

The router's admission rules are policy today in JS form:
the keyless tier is fragments-only compartmentation, the
`x-fail-closed` header skips keyless lanes, a missing secret
is a 503 fail-closed. `pg` is conjunctive, so the router
assembles one caller-owned policy document per request class
(keyed / keyless-fragments / fail-closed) — assembling policy
per class is itself caller logic, expressed in data at
runtime, not a crate grouping. Predicates per class, with
lane-config values as thresholds:

```json
{"name": "COMPARTMENT", "predicates": [
  {"input": "lane_keyed", "op": "eq", "threshold": true},
  {"input": "secret_present", "op": "is_true"}]}
{"name": "RATE", "predicates": [
  {"input": "lane_rpm", "op": "le", "threshold": "<rpm cap from lane config>"}]}
```

Breaker state and RPM counters arrive as inputs from the
router's existing bookkeeping; the `pg` trace goes into the
KV incident log the router already keeps, replacing
hand-written admission reasons with the full predicate
record.

### SUB — the substrate host (`organelle-host`)

No change to the host's own contract enforcement: capability
and schema gating before dispatch is the substrate's job and
stays there (it is not domain policy). What moves is the
domain-level admission logic hosts hand-code *around*
dispatch: the host (or a governor organelle it hosts)
evaluates a `pg` policy before dispatch with the call
context as inputs — e.g. the caller's granted capabilities
as an array input:

```json
{"name": "CAPABILITY", "predicates": [
  {"input": "granted_capabilities", "op": "contains",
   "threshold": "<capability the caller requires>"}]}
```

The evaluation trace rides the host's existing
content-addressed, chained receipt log, so a denied dispatch
carries the same complete evidence as an allowed one.

## Semantics worth knowing

- **Empty gates list in a gate-ful policy** is a caller
  configuration question, answered by the caller's `on_empty`
  — never by the crate. Under `deny`, the denial's
  `failed_gate` is `null`: the record refuses to attribute a
  denial to a gate that did not make it.
- **Numbers** compare as JSON numbers (`f64`). Callers with
  integer-exact requirements above 2^53 should compare as
  strings with `eq`/`in`, or scale units — the trace shows
  the exact values compared either way.
- **Persistence is adopter-side.** The crate holds no state;
  traces persist via composition (`ref-ledger-append`,
  `ref-cf-storage`, the host receipt log), like the other
  reference organelles.
