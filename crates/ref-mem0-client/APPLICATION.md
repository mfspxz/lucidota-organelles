# APPLICATION — ref-mem0-client (org-039, codon `m0`)

The estate's Rust client for the Mem0 hosted platform. It replaces
the throwaway Python import driver (`~/workspace/mem0-import/driver.py`)
as the durable Mem0 face: everything the driver proved against the
live API on 2026-11-23 is preserved as tested request shapes, and
everything the driver did with print statements and a progress file
is now typed outcomes and receipts.

## What it provides

- `Mem0Client` over org-026 (`ref-https-transport`), with two
  drivers sharing one set of request builders, one status-mapping
  finish, and one receipt path: sync (`add` / `search` / `list` /
  `get` / `delete`) and async (`add_async` / …) over the
  org-035-pattern `AsyncHttpsTransport` seam — the async driver is
  the one a Worker uses, where the only send is host `fetch`.
- `Mem0Config { base_url, version, timeout_ms, max_response_bytes }`
  — all caller data, no defaults, no baked endpoint. The API
  **version is part of the config** (see below), stated next to the
  base URL, and recorded on every receipt.
- `Mem0ApiKey` — injected at construction, spent only into the
  `Authorization: Token <key>` header. No `Display`, redacted
  `Debug`, zeroing `Drop`. The grep test proves the key reaches the
  wire and appears in no receipt, error, or debug output.
- Honest async: `add` returns `AddOutcome { events }` — event
  receipts with `PENDING` status and `event_id`s. Extraction is
  server-side; memories are observed through search/list. The type
  carries no field that could be mistaken for stored memories.
- Typed errors: `InvalidRequest` (refused before any send — no
  scope ids, empty query/messages/id), `RateLimited` (HTTP 429,
  with `Retry-After` when sent; the client never retries — estate
  rule is the caller stops), `Http { status, body }`,
  `Transport` (no response exists — never disguised as an empty
  result), `Decode` (a 2xx body that is not the documented shape).
- One `Mem0Receipt` per call in the estate `calls.jsonl` shape:
  `call_id` (`m0-…`), `tool`, `op`, `version`, `endpoint`,
  `status`, `http`, `latency_ms`, `ts`, scope ids, `event_id`,
  `memory_id`, `result_count`. Never the key; never memory content.
  Sinks: `JsonlFileSink` (append, drops counted), `MemorySink`,
  `NoopSink` — org-035's set, same semantics.
- Organelle surface (`organelle` feature): ops `add` / `search` /
  `list` / `get` / `delete` with JSON schemas; add/delete are
  `ExternalEffect`, reads are `ReadOnly`. `organelle()` with no
  client is fail-closed — every op errors "not configured" and
  nothing is sent. `organelle_with_client` takes a constructed
  client; the host approves egress for the configured base URL
  before any send.

## v1 versus v3 — the version is a decision, not a default buried in paths

The estate runs **v1** today because v1 is what is proven: the
2026-11-23 import submitted 2,376 items against it and verified by
search. The current Mem0 docs lead with v3 (manual
`~/workspace/mem0-manual/MANUAL.md` §3.8.2, §4.3, §4.8; snapshot
2026-11-23, `llms-full.txt` sha256
`267dd6dfea01e7047509b67b7dc3773d9b00e49aecf9898c6e10f6ea6c0367aa`).
The migration guide states v1/v2 endpoints continue to work — no
forced migration. The client implements both shape families behind
`ApiVersion`; v1 shapes are byte-tested against tonight's traffic,
v3 shapes are unit-tested against the manual's documented shapes
and are **doc-derived, not live-proven** until someone runs the
live smoke with `MEM0_API_VERSION=v3`.

| Op     | v1 (proven)                                        | v3 (doc-derived)                                        |
|--------|----------------------------------------------------|---------------------------------------------------------|
| add    | `POST /v1/memories/`, scope ids top-level          | `POST /v3/memories/add/`, scope ids top-level; response may be a single event object instead of an array (both parse) |
| search | `POST /v1/memories/search/`, scope ids top-level   | `POST /v3/memories/search/`, scope ids nested in `filters`; server threshold default is 0.1 — the client sends `threshold` only when the caller states one |
| list   | `GET /v1/memories/?user_id=…`, bare-array response (tonight's probe); envelope also parses | `POST /v3/memories/` with `filters` + `page`/`page_size`; paginated envelope `{count, next, previous, results}` |
| get    | `GET /v1/memories/{id}/`                           | same — get is a v1 management path in the current docs; no v3 path exists to use |
| delete | `DELETE /v1/memories/{id}/`                        | same — v1 management path under both versions           |

Moving the estate to v3 later is a config change (`version:
ApiVersion::V3`) plus a live-smoke run — not a code change, and
not a silent one: receipts record the version that served every
call, so a mixed history is visible in the log.

## How the import driver retires onto this client

The driver's job splits into what the client now owns and what
stays with the caller:

**Moves into the client (delete from the driver):**
- Request formation and auth: the driver's hand-built
  `{"messages": […], "user_id": …, "metadata": …}` POST to
  `https://api.mem0.ai/v1/memories/` is `Mem0Client::host(config,
  key, sink).add(&AddRequest::new(messages, Scope::user("zack"))
  .metadata(json!({"source": source})))` with
  `Mem0Config::new("https://api.mem0.ai", ApiVersion::V1,
  120_000, …)` — the driver's 120 s timeout, preserved as data.
- The 429 stop rule: the driver open-coded "429 → set stop flag".
  The client returns `Mem0Error::RateLimited`; the importer stops
  submitting on the first one — same behavior, typed.
- Receipts: `progress.jsonl` (idx/source/status/event_id per item)
  is replaced by the client's `JsonlFileSink` pointed at the same
  directory — every submission lands a `Mem0Receipt` with the
  event id, endpoint, version, latency, and status. The importer's
  own per-item index mapping stays in a thin caller-side log if
  resume-by-index is still wanted.

**Stays with the caller (it was never transport work):**
- Corpus chunking (files → heading-split items), import ordering
  (core files first, logs newest-first), and the resume set
  (which indices are already submitted) — that's import policy.
- Concurrency: the driver ran 6 threads. `Mem0Client` methods
  take `&self` and the receipt sequence is atomic, so one client
  behind an `Arc` serves a thread pool unchanged; each thread's
  calls receipt independently.
- The key source: the driver read `MEM0_KEY` from its process
  environment and stored it nowhere. The importer keeps doing
  exactly that and hands the value to `Mem0ApiKey::new` at
  construction.

## How future memory flows call it

**Session-end memory capture** (the flow this organelle exists
for): when a session wraps, the caller distills the session's
durable facts into messages and submits them under the person's
scope, then — later, not in the same breath — verifies by search:

```rust
let client = Mem0Client::host(
    Mem0Config::new("https://api.mem0.ai", ApiVersion::V1, 120_000, 1_048_576),
    Mem0ApiKey::new(key_from_vault),
    JsonlFileSink::new("mem0-usage/calls.jsonl"),
);
let outcome = client.add(&AddRequest::new(
    vec![Message::user(session_facts_text)],
    Scope::user("zack"),
).metadata(json!({"source": "session-end-capture"})))?;
// outcome.events[i].event_id is the receipt.  Extraction is
// still running server-side; do NOT report the memories as
// stored.  A later search (seconds to minutes on) observes
// what landed:
let landed = client.search(&SearchRequest::new("session facts", Scope::user("zack")))?;
```

Rules the flow inherits from the client, restated because they
are the point: a `RateLimited` return stops the capture run (no
retry loop); a `Transport` error means "unknown whether anything
was submitted" for add — re-submission policy is the caller's,
stated in its own docs, never assumed; receipts go to the usage
log so memory writes are as auditable as model calls already are.

## Live smoke

One bounded end-to-end pass (add → poll search → delete → verify
404) under the dedicated `lucidota-smoke` scope — the real import
scope is never touched:

```text
MEM0_LIVE=1 MEM0_KEY=<key> cargo test -p ref-mem0-client \
    --test live_mem0 -- --nocapture
```

`MEM0_API_VERSION=v3` in the environment runs the same pass
against the doc-derived v3 shapes; that run is what promotes v3
from doc-derived to live-proven, and the report should be updated
when it happens.

## Limits, stated

- Response records model the fields the estate uses (`id`,
  `memory`, scope ids, `metadata`, `categories`, `score`,
  timestamps). Other API fields (`hash`, `expiration_date`, …)
  are parsed past, not surfaced.
- `Retry-After` is parsed in its delta-seconds form only; the
  HTTP-date form reports as absent rather than guessed.
- The wasm face is compile-proven, not runtime-proven (the
  estate's standing caveat for every org-026 consumer).
- No consumer has migrated yet: the import driver still exists
  and still works; this crate is its retirement path, not a
  flag-day.
