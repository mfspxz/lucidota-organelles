# Applying `ref-graph-store` (org-033, codon `gs`)

The estate's reusable typed triple store: assertions with
ternary state, provenance, and validity intervals; point
lookup, predicate scan, one-hop and bounded traversal, and
temporal filtering over them. It closes GAP-08 of the
2026-11-22 decomposition map: five scoped softwares (WRK,
EXC, SDX, VAN, MCP) re-implement graph storage and query
today — wreck's graph views, the Exchange's evidence-graph
SQLite store, SupDox's manual section graph, VanCan's
standalone graph checker, and the MCP graph server's
arbitrary-Cypher surface. Two more estate consumers — Zack's
entity graph and the hypertimeline — hold the same shape in
ad-hoc files and tables.

## The doctrine every adopter gets

- **Ternary state, always attached.** Every assertion carries
  a `State` — `proven` | `claimed` | `unknown` — and a
  provenance reference. There is no API in this crate that
  returns a bare fact: every query shape (point lookup,
  predicate scan, filtered lookup, neighbors, traversal,
  list, and the organelle surface) returns full `Assertion`
  records. An `unknown` assertion comes back *as* unknown
  from every shape — never dropped, never promoted, never
  coerced to false or absence. Unknown stays unknown.
- **Time is the fourth dimension, and it is data.** Every
  assertion carries a validity interval (`valid_from_ms`
  inclusive, `valid_to_ms` exclusive, either side
  unbounded). Temporal queries take the time `T` as an
  input (`Query::at` / `at_ms`). The store never reads a
  clock.
- **No invented edges.** The store contains exactly what
  callers asserted. Traversal follows asserted edges only,
  to exactly the depth the caller supplies — depth 0 means
  no edges, depth 1 means exactly the one-hop set. Cycles
  terminate; a node is expanded once, at its shallowest
  depth.
- **Conflicting assertions coexist.** The same triple
  asserted in two states, or from two provenances, is two
  assertions with two ids. Neither overwrites the other —
  the graph records who asserted what, in which state, on
  what evidence. Re-asserting *identical* content (same
  triple, state, provenance, interval) is a replay: the
  existing record is returned, nothing is duplicated.
- **Stable ids are content hashes.** An assertion's id is
  the sha256 of its canonical content; a forged id (one
  that does not match its content) is refused by
  `assert_raw`. Node ids follow the typed-traits rule —
  `sha256(canonical_json(thing))`, exposed as `thing_id`.
  Never a process-local hash.
- **Vocabulary aligned with typed-traits-v1**
  (`~/workspace/coal-harbour-cute-city/typed-traits.json`):
  the crate ships the schema's classes (`CLASSES`: Authority,
  Community, Funder, Lease, Operator, Person, Place,
  Program, Vehicle) and verbs (`VERBS`: does, is_done_to,
  touches, located_at, authorizes, operates, funds,
  competes_with, partners_with, contains, permits,
  requires, supports, finds, opens, decides, endorses,
  leases, binds, expires, renews, lends, subsidizes,
  trains, employs, hosts, patrols, moves, carries,
  represents, endorses_claimed) as constants. The store
  itself accepts any non-empty predicate — adopters with
  their own predicate sets are not forced into one domain's
  verbs. A caller that wants the closed vocabulary
  enforced gates `assert` with `ref-policy-gate` (org-029).
- **Determinism.** All query logic runs over the store's
  full assertion set, sorted by assertion id, so results
  are byte-identical across backends and independent of
  insertion order (proven by test, memory vs SQLite
  included).

## Dependency stanzas

Pure-API consumers (worker cores, CLIs, checkers) — no
host/manifest deps in their graph:

```toml
ref-graph-store = { path = "../organelles/crates/ref-graph-store", default-features = false }
```

With the durable backend (native only; the `sqlite` feature
is cfg-gated out on wasm32, where storage is the host's
problem and a D1/KV adapter composes over the `Store`
trait):

```toml
ref-graph-store = { path = "../organelles/crates/ref-graph-store", default-features = false, features = ["sqlite"] }
```

Organelle-surface consumers take the default features and
register `ref_graph_store::organelle()` (codon `gs`,
capability `graph.store` for the write ops `declare_node`
and `assert`; reads are capability-free).

## Storage backends — stated plainly

- `MemoryStore` — B-tree maps; the test/embedded backend.
- `SqliteStore` (feature `sqlite`, native only) — rusqlite
  bundled, one file (or `:memory:`), `assertions` +
  `nodes` tables. Terms and states are stored as their
  canonical JSON strings, so a row round-trips to exactly
  the assertion that was asserted.
- Query logic is deliberately *not* pushed down into SQL:
  the core evaluates over the full id-sorted set so every
  backend answers identically. An adopter whose assertion
  count outgrows a full scan writes a `Store` whose
  `assertions()` is still total and ordered — the contract
  is the sorted set, not the scan.

## Per-consumer adoption steps

### EXC — the Exchange evidence graph

The evidence graph is already SQLite; this is the most
direct transplant of the five.

1. Open the evidence DB through `SqliteStore` (feature
   `sqlite`) beside the existing tables; the crate's
   `assertions`/`nodes` tables are additive.
2. Map each evidence record to an assertion: subject =
   the resource/capability node, predicate = the evidence
   relation, object = the observed value or node, state =
   the governor's own verdict vocabulary mapped onto
   proven/claimed/unknown (a health observation that
   quarantined a resource is an assertion whose provenance
   is the evidence-log id — the reference the governor
   already writes).
3. Validity intervals carry the evidence window:
   `valid_from_ms` = observation time, `valid_to_ms` = the
   moment the observation goes stale under the caller's
   own freshness policy (caller data, as always).
4. Governor reads become `lookup`/`traverse` with `at_ms`
   = the evaluation instant — which removes the hand-rolled
   "latest observation" queries and makes "what did we
   believe at time T" a query the store answers natively.
5. The deployed worker is untouched by this adoption until
   EXC's own port schedule takes it; the store is exercised
   first from the mirror/refresh tooling that already reads
   the same D1/SQLite data.

### WRK — wreck graph views

`wreck-graph`'s decision core stays one indivisible
organelle (its MAPPING.md justifies claim → view → policy →
verdict); what adopts `gs` is the *view* layer around it.

1. Project each wreck-graph view into assertions: nodes =
   claims, receipts, canon entries; predicates = the view's
   own relations; provenance = the receipt/canon id that
   backs the edge — an edge without a receipt behind it is
   asserted `unknown` or not asserted at all, never
   silently `proven`.
2. Replace view-specific traversal code with `traverse`
   (depth stated by the caller — the governor's view depth
   becomes configuration, not a constant buried in a view).
3. GAP-22 (code-graph-parse, the tree-sitter replacement)
   is a separate organelle; when it lands, its output —
   code entities and relations — is asserted into this
   store with provenance = file path + span, and wreck's
   code-graph queries become lookups here instead of a
   second private graph.

### SDX — SupDox / Manual Forge section graph

`mf`'s cross-reference graph is a section graph wearing a
monolith.

1. Declare each manual section a node (class stated by the
   adopter — the store's vocabulary is open; `Program` is
   the nearest typed-traits class, or SDX states its own).
   Node id = `thing_id` of the canonical section record
   (manual id + section number), so the Law-of-Root
   numbering and the id rule agree.
2. Cross-references become assertions: subject = section,
   predicate = `references` (adopter vocabulary), object =
   target section, state = `proven` when the reference was
   extracted from the section's own text, provenance =
   manual file + section span. A reference whose target
   does not exist is asserted `unknown`, never dropped —
   the broken-reference report is then a `by_predicate`
   scan filtered to unknown, not a separate checker.
3. `get_children` becomes a depth-1 `traverse` over the
   containment predicate; ranked search (GAP-12) stays a
   separate organelle and consumes this store's node set.
4. GAP-19 (manual-section-graph) is the parser; this store
   is where its output lives. SKZ's manual, the waiting
   consumer, ingests through the same two steps.

### VAN — VanCan graph checker

`tools/graph-checker` is a standalone checker over the
dispatch/GIS graph; its checks become queries.

1. Load the VanCan graph (dispatch state + GIS scenarios)
   as assertions: provenance = the source file (dispatch
   module, `gis/*.geojson` feature id), state per the
   locked VanCan rules — simulation facts are `claimed`
   unless a receipt proves them; `depot_receipts.is_simulated`
   stays a data property, and no checker output may promote
   a simulated fact to `proven`.
2. Each existing check is rewritten as a `lookup` or
   `traverse` whose result is reported *with* states: a
   route that exists only on claimed edges is reported as
   claimed, not as pass. The checker's exit condition
   becomes a caller-stated policy over the result states
   (compose `ref-policy-gate`, org-029) instead of a
   boolean baked into the checker.
3. The standalone crate is then deleted from the build —
   the checker is a query pack over this store, not a
   second graph implementation.

### MCP — the graph server

The MCP `graph` server accepts arbitrary Cypher today.
Arbitrary query languages invent edges by typo; the
bounded surface does not.

1. Replace the Cypher endpoint with the four query ops —
   `lookup`, `by_predicate` (as `lookup` with only a
   predicate), `neighbors`, `traverse` — exposed through
   the existing server shell. Depth is a required caller
   input on `traverse`; there is no unbounded walk.
2. Every answer the server returns is a list of full
   assertions. The server's response shaping must not
   project assertions down to (subject, predicate, object)
   triples — that projection is exactly the bare-fact API
   this crate refuses to provide, and re-adding it at the
   server layer re-opens the hole.
3. Writes go through `assert` with the caller's provenance
   (the MCP client's identity + the source it cites);
   the server mints no provenance of its own.

### The entity graph (Zack's people/groups graph)

The entity graph lives as per-person/group pages plus
ad-hoc structure today.

1. Each person/group page's facts become assertions:
   subject = the entity's node id (`thing_id` of the
   canonical entity record), predicates from `VERBS`
   where the schema covers the relation, provenance =
   the memory page + line (e.g. `memory/people/kai.md#L…`)
   — the citation discipline the memory system already
   keeps, now carried inside the data.
2. Facts Zack stated are `proven`; facts reported by
   others or inferred by a lane are `claimed`; subjects
   of open questions are `unknown` — the graph's current
   practice, made structural: a query over the entity
   graph can no longer return an inferred relation in the
   same shape as a stated one.
3. Validity intervals carry relationship time (a role held
   from–to, a crew affiliation that ended): `lookup` at a
   past `at_ms` answers "as of then" without a second
   snapshot.

### The hypertimeline (coverage: 306 assertions vs 153,057 nodes)

The coverage map's finding — 153,057 graph nodes against
306 assertions on the hypertimeline — is a coverage fact
that prose keeps rediscovering. In this store it is a
`stats()` call.

1. Ingest the hypertimeline's existing assertions through
   `assert_raw` (ids recomputed and verified against
   content — a mismatch names the corrupt record instead
   of importing it).
2. Declare the 153,057 nodes. `stats()` then reports
   `{assertions: 306, nodes: 153057, by_state: {…}}` —
   the gap is a number on every read, not a finding that
   needs a wave to re-derive.
3. New timeline assertions land with provenance = the
   ingest source (Drive file id, Takeout part, ledger seq)
   and validity intervals = the event's own time span;
   pattern analysis (patternalysis) queries `traverse`
   with `at_ms` windows instead of walking raw tables.
4. Nodes with no assertions stay visibly assertion-free in
   stats. Closing the gap is ingest work (OUROBOROS lanes);
   this store's job is that the gap can never again be
   *invisible*.

## What this crate deliberately does not do

- **No bare-fact projection.** There is no method that
  returns triples without state and provenance, and there
  will not be one. Adopters must not re-add the projection
  at their own layer (see MCP step 2).
- **No state promotion.** Nothing in the crate moves an
  assertion between states. A state change is a *new*
  assertion by whoever re-evaluated the evidence, with its
  own provenance; the old assertion remains, with its
  validity interval closed by the adopter if the adopter
  states that policy.
- **No clock.** The store never reads system time.
  Validity is data; query time is an input.
- **No query language.** No Cypher, no SPARQL, no string
  queries to parse or inject. The surface is four typed
  operations with stated bounds.
- **No inference.** Traversal returns asserted edges only.
  Transitive conclusions are the caller's to assert, with
  the caller's provenance.
