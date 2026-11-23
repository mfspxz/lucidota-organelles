# Applying `ref-model-call-live` (org-035, codon `ml`)

The estate's production OpenAI-compatible model call: provider
lanes as caller-supplied data, exact-model binding (pins),
failover, and substitution that is never silent. It closes
GAP-10 of the 2026-11-22 decomposition map: five scoped
softwares (SUB, FAC, EXC, SKZ, RTR) need production model
calls — `ref-model-call` (org-023) is a contract + stub, the
ai-router's `ai-router.js` is the real implementation
un-decomposed in one JS file, and FAC / EXC / SKZ each wire
their own provider HTTP beside it.

## The doctrine every adopter gets

- **A pin is a contract.** `"<lane>/<model-id>"` (aliases are
  config data) is attempted only on that lane with only that
  model; any failure is `PinFailed` naming the lane and model.
  No strategy pick, no pool rotation, no cross-lane failover.
- **Substitution is loud or it does not happen.** Every
  response carries `model_requested` / `model_sent` /
  `model_served` / `substituted`; a provider that answers a
  pin with a different `model` field returns success **with
  `substituted: true`**, in-band and on the receipt.
- **Every attempt is receipted** — one `CallReceipt` per
  attempt (success, HTTP failure, transport failure,
  credential failure, guard denial) in the estate `calls.jsonl`
  shape, extended with `lane` / `pinned` / `substituted` /
  `attempt`.
- **Configuration is data, stated in full.** Lane order is
  walk order; strategies, aliases, timeouts, and the failover
  policy are the caller's. The config structs have no serde
  defaults and no `Default` impls; `ModelCaller::new`
  validates. This crate ships no lane definitions, no provider
  URLs, and no model names.
- **Credentials are references.** Lanes name an org-028
  `CredentialRef`; values arrive through the host's
  `CredentialResolver` and are attached inside this crate.
  Nothing in this crate reads a file, an env var, or a vault
  for a key, and no error or receipt can contain one.
- **Breaker/quota is a seam, not a policy.** The `CallGuard`
  trait is two callbacks; the `guard-bq` feature adapts
  org-032's `SyncBreaker` / `SyncQuota` (`BreakerQuotaGuard`).
  Thresholds remain the adopter's org-032 configs.

## Dependency stanza

```toml
# Client-only (no organelle surface in your graph):
ref-model-call-live = { path = "../ref-model-call-live", default-features = false, features = ["native"] }

# With the org-032 guard adapter:
ref-model-call-live = { path = "../ref-model-call-live", default-features = false, features = ["native", "guard-bq"] }
```

(Relative to `~/workspace/organelles/crates/<your-crate>`; the
workspace registration is already done.)

## The shape of an adoption

```rust
let caller = ModelCaller::host(config, credentials, guard, sink)?;
let resp = caller.chat(&request)?;
```

`config: RouterConfig` is built (or deserialized — every
config type is `Serialize`/`Deserialize`) from the adopter's
own stated values. `credentials` implements
`CredentialResolver`; `guard` is `NoGuard` or a
`BreakerQuotaGuard` with org-032 state machines registered
per lane; `sink` is `JsonlFileSink` at the adopter's usage
log, or `MemorySink` / `NoopSink`.

---

## RTR — the ai-router port (the reference adoption)

`ai-router.js` (2,047 lines) is this organelle's semantics in
JS: lane defs with priorities, `selectNvidiaModel`,
`parseModelPin`, the failover walk, the `x-model-*` headers.
The port path is: **org-031 `ref-edge-worker-shell` as the
Worker shell + org-035 as its model-call core**, one lane of
work, not a rewrite of the router's policy — the policy moves
into config, where it becomes inspectable data.

Exact steps:

1. **Transcribe `laneDefs(env)` into a `RouterConfig`.** The
   13 lanes in priority order — gemini, groq, mistral, zai,
   nvidia, openrouter, sambanova, deepseek, github-models,
   pollinations, kilo, ovh, llm7 — become `lanes` in that
   order (org-035 has no priority field; list order IS the
   walk order). Per lane: `base_url` from its
   `openaiCompatRequest` base; `credential` =
   `CredentialRef::new("<lane>", "router")` resolved from the
   Worker's secrets by the shell's resolver; `models` = the
   lane's pool; `timeout_ms` from the lane's attempt budget
   (20_000 default, 60_000 for llm7); `abort_lane_on_429: true`
   for nvidia only (its 429s are account-level — the JS says
   so in its lane comment).
2. **NVIDIA's `selectNvidiaModel` becomes `SizeRules` data**
   (proven expressible by the crate's
   `size_rules_express_the_router_pick` test): two rules
   naming the dense model (`min_prompt_tokens: 4000`;
   `min_output_tokens: 4096`), one small rule
   (`prompt_tokens_below: 1000, max_output_tokens: 512` →
   bolt), the vision rule (`vision: true` → super-vl),
   `fallback` = laguna, and `model_timeouts_ms` transcribed
   from `NVIDIA_MODEL_TIMEOUTS`. `NVIDIA_MODEL` /
   `NVIDIA_MODELS` env overrides become config regeneration,
   not code paths.
3. **The failover policy is stated once**, with the router's
   documented values: `failover_statuses: [401, 403, 404,
   429]`, `failover_on_5xx: true`,
   `failover_on_transport_error: true`. The caller-caused
   statuses (400/413/422) are terminal by construction —
   anything not listed and not 5xx returns as `ProviderError`
   immediately, which is the JS behaviour.
4. **Pins and aliases carry over as data:** `aliases:
   [("nim", "nvidia")]`. The `x-model-requested` /
   `x-model-served` / `x-model-substituted` / `x-model-pinned`
   response headers become a thin shell mapping from
   `ChatResponse`'s fields — the values are the same because
   the semantics are the same code, ported.
5. **Breakers/cooldowns move to org-032 configs** behind
   `BreakerQuotaGuard`: `BREAKER_FAILS = 3`,
   `BREAKER_BACKOFF_S = [30, 60, 120, 300]` is a
   `CooldownPolicy::Schedule` an adopter states; per-lane
   `rpmLimit` values become `QuotaConfig` sliding windows.
   Jitter (±25%) is the caller's input to org-032, as org-032
   specifies.
6. **The KV lane registry (`LANES_KV`) becomes config
   generation:** KV lane objects validate (the JS
   `validateKvLane` rules) and serialize into `RouterConfig`
   JSON; the shell rebuilds the `ModelCaller` on registry
   change. Dynamic load-balance reordering (`orderLanes`
   modes) likewise becomes "regenerate the config in the new
   order" — org-035 never reorders behind the caller's back,
   which is the point of the contract.
7. **Receipts replace the router's ad-hoc accounting:** point
   `JsonlFileSink` at the lane's usage log, or drain
   `MemorySink` into KV with the shell's write-behind.

Two honest limits of the port, stated before anyone starts:

- **Streaming.** The JS router proxies SSE (`stream: true`).
  Org-035 v1 refuses streaming (whole-body transport) — the
  port either keeps streaming callers on the JS worker until a
  streaming transport exists, or lands that transport first.
  It must not silently buffer.
- **The Gemini lane is not OpenAI-compatible** — it builds a
  `generateContent` request and translates the response. In
  the port it stays a translating transport in front of
  org-035 (an `HttpsTransport` that rewrites request/response
  for that one lane), or out of the first cut. The other 12
  lanes are pass-through OpenAI-compatible today and port
  directly.

## SKZ — the SkidZ NPC caller

Today: `tools/rust/src/bin/estate-demo.rs` step 3 shells out
to `curl` against the deployed router
(`https://ai-router.cutecity.workers.dev/v1/chat/completions`),
reads the router key from
`custom-skills/local-ai-router/bin/.router_key`, and records
whatever substitution the response shows — the RFC-002 proof
that caught the router substituting (SKIDZ-MANUAL prove-or-
break #1).

Adoption (one bin, one lane):

1. Depend on org-035 with
   `default-features = false, features = ["native"]`.
2. State one lane: name `router`, base_url
   `https://ai-router.cutecity.workers.dev/v1`, `models`
   stating the model the NPC line asks for, credential =
   `CredentialRef::unscoped("router")`, resolved by a
   `MemoryCredentials` the bin provisions from the same key
   file it reads today (the value never enters the crate's
   logs — `SecretString` is redacted by construction).
3. Replace the curl subprocess + manual header reading with
   `caller.chat(...)`: the proof now asserts on
   `resp.model_served` / `resp.substituted` directly instead
   of parsing `x-model-*` headers, and the attempt's receipt
   (JsonlFileSink beside the demo's RESULTS.md) is the
   durable record.
4. When the NPC line must be the 550B, say so as a pin
   through the router lane's grammar — and after the RTR port,
   the same bin repoints its single lane at NIM directly with
   `nim/…` and nothing else changes.

## The provider CLIs

The connector CLIs (`custom.legacy-nvidia-nim/bin/nvidia-nim`,
the OpenRouter / DeepSeek / Groq / Mistral CLI families under
`~/workspace/skills/*/bin/` and `custom-connectors/`) are
Python connector tooling and stay Python — but every Rust
consumer that today shells out to them for a chat call, or
re-implements their HTTP + `calls.jsonl` logging, adopts
org-035 instead:

1. Implement `CredentialResolver` over the estate surrogate
   protocol — the same one the CLIs use: POST
   `{"name": "<connector credential name>"}` to
   `/v1/credentials/surrogate` on the authd unix socket
   (`$JARVIS_AUTHD_SOCK`, default `/run/hatch/auth/authd.sock`),
   take the `access_token` entry's `hsurr:*` surrogate with
   its stated placement (`bearer_header` → `AuthStyle::Bearer`,
   a `custom_header` placement → `AuthStyle::Header(name)`).
   The surrogate is what travels; the real key never enters
   your process. (Org-035's `tests/live_nim.rs` is a working
   reference implementation of exactly this resolver feed.)
2. State the provider as one lane (base URL + the model pool
   you actually call), the failover policy you actually want,
   and point `JsonlFileSink` at the provider's existing usage
   log (`~/workspace/nvidia-usage/calls.jsonl`,
   `~/workspace/openrouter-usage/calls.jsonl`) — the receipt
   shape is the same shape those files already carry, so
   existing log readers keep working and gain `lane` /
   `pinned` / `substituted` per line.
3. Retire the per-tool HTTP + logging code; the CLI keeps its
   argument parsing and its purpose/task-class annotations,
   which map onto `ChatRequest::purpose` and the receipt.

## FAC / EXC / SUB (noted, per the map)

- **FAC**: the factory's provider adapters inside
  `factory/workers/` are per-provider lanes + one resolver
  over the factory's credential provisioning; the quota
  handling they hand-roll is org-032 behind `guard-bq`.
- **EXC**: the Exchange's inference calls take a lane set
  whose credential refs resolve through org-028's broker
  backends (the host implements `CredentialResolver` over the
  same provisioning the broker uses); the governor's model
  choices become pins where exact-model binding is the
  requirement — which, after 2026-11-21's claim-orphan and
  substitution lessons, is most of them.
- **SUB**: a host embedding org-035 states its lanes in its
  deployment config and gets receipts for free; the bare
  `organelle()` surface (no lanes) is the fail-closed placeholder
  until it does.
