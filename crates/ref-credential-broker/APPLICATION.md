# Applying `ref-credential-broker` (org-028, codon `cb`)

The estate's scoped credential broker: callers name a credential
by reference (name + scope) and the broker acts — performs the
authenticated HTTP request, mints a scoped short-lived grant
handle, or checks a presented value — **without the secret value
ever crossing the API boundary**. It closes GAP-03 of the
2026-11-22 decomposition map: six scoped softwares (FAC, WRK,
EXC, RTR, MCP, TEN) hand-roll credential handling today, and the
patterns that exist (host capability grants, EXC's authd
surrogate, the MCP vending token contract) are piecemeal. This
crate is the single organelle behind those shapes.

## Dependency stanzas

Client-only consumers (worker cores, CLIs, adapters) — no
host/manifest deps in their graph:

```toml
ref-credential-broker = {
  path = "<relative path>/organelles/crates/ref-credential-broker",
  default-features = false,
  features = ["native"],
}
```

Hosts registering the organelle surface take the default features
(`organelle` + `native`) and register
`ref_credential_broker::organelle_with_broker(Arc::new(broker))`
with the broker they provisioned. Plain `organelle()` is the
fail-closed shell (a `NoBackend` broker): every credential op
fails with `unknown credential ref` until a real broker is
injected. Ops and capabilities: `execute` / `redeem`
(`cred.broker`), `grant` / `revoke` (`cred.grant`), `verify`
(`cred.verify`), `receipts` (no capability — receipt records
contain no values).

## The non-negotiable rules every adopter gets

- **Values never cross the API.** The public surface carries
  `CredentialRef` (name + scope), `GrantHandle` (opaque id +
  scope + expiry), `BrokerReceipt`, and HTTP responses. There is
  no op, method, error, or Debug string that yields a value:
  `SecretValue` has no `Display`, a redacted `Debug`, a
  zeroing `Drop`, and a `pub(crate)`-only door to the value,
  spent solely by `Placement::attach` inside the crate. The test
  suite greps every output shape for a loud fixture secret
  (`secret_appears_nowhere_in_outputs`).
- **Header placements only.** `BearerHeader` and
  `CustomHeader(name)` are the whole enum. There is deliberately
  no query-param / URL-path placement — values in URLs land in
  logs (the same refusal EXC `creds.rs` makes). Brokered auth
  also *wins*: a caller-supplied copy of the placement header is
  replaced, never duplicated.
- **Fail-closed everywhere.** Unknown ref → `UnknownRef`, nothing
  sent, at execute, grant, and verify time alike. Grants are
  minted only for refs that resolve *now*. Grant redemption
  checks handle-known → expiry → uses → host scope, in that
  order, before any credential is resolved.
- **Every operation receipts.** Success or failure, the broker
  appends a `BrokerReceipt` (sha256 receipt id; caller, ref
  name/scope, operation, method + host, outcome, unix-ms time).
  A consumer that needs an audit trail reads `broker.receipts()`
  or the `receipts` op — it never needs to log anything
  credential-shaped itself.
- **Backends are constructed, never sourced.** `MemoryBackend`
  is provisioned by the host process that already holds the
  values. `FileBackend` receives its full (ref → path,
  placement) list at construction; the crate hardcodes no paths,
  reads no environment, and reads a file only when its ref is
  resolved (one trailing newline/CRLF trimmed). New backends
  (authd, a vault, a Workers env adapter) implement
  `CredentialBackend` — two methods — and inherit every rule
  above; a backend must never embed a value in an error or
  Debug string.

## Semantics worth knowing

- **Grants are scope, not secrets.** A handle id is a sha256
  over broker-instance nonce material; leaking one leaks a
  capability bounded by its hosts, TTL, and use count — mint
  narrow (`max_uses: Some(1)` for single-call jobs), revoke when
  done. `"*"` in `scope_hosts` means any host and is scope in
  name only; the broker accepts it because the minter asked,
  and the receipt log shows who minted it.
- **Verify is one-way.** `verify_presentation` answers a bool
  (constant-time compare inside the crate) for the
  inbound shared-secret shape. It accepts a presented value
  from the caller; it never returns the stored one.
- **Transport is injected.** `Broker<B, T: HttpsTransport>`;
  `Broker::with_host_transport` gives the platform default
  (ureq 3 + rustls via `ref-https-transport`). Recorded/fixture
  transports plug in for tests — the crate's own suite is the
  template.
- **On wasm32** the crate compiles and the grant/receipt/
  verify logic runs, but `HostTransport` is the transport's
  honest `Unsupported` there: wasm consumers inject a host-fetch
  transport (the `ref-https-transport` `send_async` shape) —
  compile-proven, not yet runtime-proven in a deployed worker.

## Adoption steps — the 6 GAP-03 consumers

1. **FAC — organelle factory** (`~/workspace/organelle/factory/workers/`).
   Today the provider adapters (DeepSeek / NVIDIA / Gemini HTTP)
   read provider keys from process env in the worker layer.
   Step: the factory *host* provisions a broker at startup —
   `FileBackend` entries injected from the host's existing key
   locations (refs `deepseek@provider-api`, `nvidia@provider-api`,
   `gemini@provider-api`, bearer placement) — and workers stop
   reading env entirely. Per job, the dispatcher mints a grant
   (scope_hosts = the one provider API host, ttl = the job's
   time budget, max_uses = the job's call budget) and hands the
   worker the *handle*; the worker redeems through `cb`. A dead
   or leaked worker then holds a dying capability, not a key,
   and the receipt log is the per-job provider-call audit.
2. **WRK — wreck** (`wreck-ports`, `wp`). Token custody exists
   here already — `token_for` / `token_adjudicate` /
   `token_revoke` — as a bespoke organelle op set. Step: `wp`'s
   custodian becomes a broker client instead of a second
   implementation: `token_for` ≙ broker `grant` (the wp token
   *is* a grant handle — same scope/TTL shape), `token_revoke`
   ≙ `revoke`, and `token_adjudicate` reads the broker receipt
   log instead of re-deriving provenance. The govern core (`wg`)
   does not change; custody semantics move to the one broker,
   and wreck's workers redeem handles rather than handling
   capability tokens minted by private code.
3. **EXC — exchange** (`~/workspace/exchange/rs/exchange-organelles/src/creds.rs`).
   This is the pattern GAP-03 generalizes: the authd surrogate
   flow (`hsurr:*` tokens, `bearer_header` / `custom_header`
   placements, host allowlist, "surrogates are NEVER logged").
   Step, in two parts. (a) Now: implement `AuthdBackend` behind
   `CredentialBackend` — `resolve` performs creds.rs's existing
   authd call and maps its placements 1:1 onto broker
   `Placement` (its refused placements — `url_path_segment`,
   `query_param` — are exactly the variants the broker enum
   does not have); exchange ops then call the broker and gain
   receipts for every credentialed request, replacing the
   "never logged" discipline-by-convention with
   receipts-by-construction. (b) The deployed worker is not
   touched by this lane: worker-side provider keys stay worker
   secrets until the exchange lane itself adopts, under its
   parity suite.
4. **RTR — ai-router** (`~/workspace/tentacle-corp/city-os/public-router/ai-router.js`).
   JS today; the lane table reads raw provider keys straight
   from the worker env (`env.GEMINI_KEY`, `env.GROQ_KEY`,
   `env.MISTRAL_KEY`, `env.ZAI_KEY`, `env.NVIDIA_KEY`,
   `env.OPENROUTER_KEY`, `env.SAMBANOVA_KEY`, `env.DEEPSEEK_KEY`,
   …) — the widest raw-key exposure in the estate. No JS-side
   action. Step: when the router ports to Rust/wasm behind
   GAP-10 (`model-call-live`), lanes stop holding keys: the
   router core holds one `CredentialRef` per lane and the
   broker executes provider calls (or, for hot lanes, the core
   mints itself per-lane grants scoped to each provider host).
   The fail-closed keyless-tier policy the router already
   enforces maps onto `UnknownRef` — an unprovisioned lane is
   a broker error, not a code path.
5. **MCP — vending machine** (`~/workspace/mcp-vending-machine/TOKEN-CONTRACT-v1.md`).
   The scoped-grant token contract is written; the minter and
   gateway are not built — this organelle is the missing
   implementation. Step: implement the contract directly on
   the broker. The contract's token ≙ a grant handle (its
   `jti` is the handle id; single-use tokens are
   `max_uses: Some(1)`; scope claims are `scope_hosts` +
   ref), the minter is the `grant` op behind the vending
   server's existing authority checks, and the gateway is
   `redeem` / `execute` — the gateway never sees the
   underlying credential, only the handle and the response.
   The Python demo stays a demo; the Rust broker is the
   contract's first real minter, and its receipt log is the
   vend audit trail the contract asks for.
6. **TEN — tentacle-corp infra** (`~/workspace/tentacle-corp/infra/`).
   Five+ JS workers each do their own secret handling — the
   heartbeat worker compares `x-heartbeat-secret` against
   `HEARTBEAT_SECRET` in worker code, the ledger viewer does
   its own timing-safe compare and secret gate, and the Python
   lane tools that *call* these workers carry the shared
   secrets in their own env. Step, riding the GAP-07 shell
   port: (a) inbound — each worker's compare becomes the
   broker's `verify` op against a ref (`heartbeat@ingest`,
   `ledger@viewer`): the shell presents what it received, the
   broker answers match / no-match, and the stored secret
   leaves worker code entirely (the constant-time compare
   lives in one audited place, not five JS copies). (b)
   outbound — the lane tools resolve refs through a
   `FileBackend`-provisioned broker instead of reading env
   secrets, so the shared secret exists in exactly one
   provisioned place per host.

## Verification pattern for adopters

Mirror the A5/A6/A8 proofs and this crate's own suite: a
recorded-transport test that the brokered request carries the
auth header (and that a caller-supplied copy is replaced, not
duplicated); a wire-level fixture test like
`brokered_request_carries_auth_end_to_end`; the grep test —
run every output, error, and Debug shape your integration
produces and assert the fixture secret appears in none of them;
and a fail-closed test (unknown ref sends nothing, and the
attempt is on the receipt log). An adoption that puts a value
in a log, a manifest, or an error is a failed adoption,
whatever else it does.
