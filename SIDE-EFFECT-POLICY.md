# Side-Effect Containment Policy (P1 lane 3)

The host is the membrane. Organelles never decide for themselves whether a
filesystem write or a network egress is allowed — they ask the host through
`HostRef` (`approve_write_path` / `approve_egress`), and the host answers from
the deployment's declared policy. Both policies are **fail-closed and
default-deny**: an unconfigured host refuses every organelle filesystem write
and every organelle network egress.

Preserved from earlier lanes: fail-closed verdicts on every path (every
refusal emits a receipt), the `InvocationBinding` (extended, not redesigned),
the HMAC grant system (extended with audience binding), honest reference
organelles (their honest labeling is untouched), and the
manifest → host → transport separation (policy lives in the host; manifests
declare needs, never permissions).

## 1. Write roots

- **Where it lives:** `Host::set_write_roots(Vec<PathBuf>)` /
  `Host::write_roots()`. Each root is canonicalized at set time; an
  unresolvable root refuses the whole update and the previous policy stands.
- **Default:** no roots = deny all writes.
- **Enforcement:** `HostRef::approve_write_path(raw) -> Result<PathBuf, _>`.
  The host canonicalizes the nearest existing ancestor (resolving symlinks),
  re-attaches the missing tail lexically (`..` is rejected up front), and
  requires the result to sit under an approved root. It returns the canonical
  absolute path the organelle **must** write to — organelles never re-derive
  a path from raw input after approval (that would reopen the check/use gap).
- **Adopted by:** `ref-ledger-append` (`la.append` → `ledger_path`),
  `ref-file-cas` (`fc.put` → store dir; the content id is a validated 64-hex
  name joined onto the approved dir), `ref-notify` (`nt.send` → outbox dir).
- **Not filesystem writers:** `ref-kv-store` is in-memory only (no paths to
  scope; containment is the `kv.write` capability gate plus per-host-instance
  memory). `ref-text-transform`, `ref-json-validate`, `ref-hash-seal`,
  `ref-time-oracle`, `ref-geo-point` are pure compute — no side effects.
- **Relative paths** resolve against the host process's cwd.
- **Known limitation:** approval and write are not atomic; a concurrent
  filesystem mutator racing the two is outside this reference membrane's
  threat model (documented in `policy.rs`, not hidden).

## 2. Outbound network (egress) policy

- **Where it lives:** `Host::set_egress_policy(EgressPolicy)`.
  `EgressPolicy::allowlist(&["api.example.com", "*.internal.example"])`
  parses exact hosts and `*.domain` suffix patterns (the suffix pattern covers
  the bare domain and all subdomains; matching is case-insensitive; ports are
  not part of patterns). A malformed allowlist is refused wholesale — never
  installed partially.
- **Default:** `EgressPolicy::deny_all()` — every egress denied until the
  operator allowlists hosts. There is deliberately no "allow all" constructor.
- **Enforcement:** `HostRef::approve_egress(url) -> Result<(), _>`, called by
  the organelle *before* any socket is opened. The denial names only the
  URL's host, never the full URL (query strings may carry secrets).
- **Adopted by:** `ref-http-fetch` (`hf.fetch`), `ref-scrape-extract`
  (`se.extract`), `ref-model-call` (live provider path only — the honest stub
  performs no I/O and needs no approval). Scheme enforcement stays with the
  transport layer: `ref-common` still honestly refuses non-`http://` URLs.
- **Tests:** allowed host ok / disallowed host denied before any socket /
  no-policy default deny (see `ref-http-fetch`, `ref-scrape-extract`).

## 3. Grant domain confinement

Grants bind subject + capabilities (P0). Lane 3 adds two confinement
mechanisms so a grant cannot escape its intended domain:

- **Audience binding.** `Host::issue_scoped_grant(caller, codon, caps, ttl)`
  (and `issue_single_use_scoped_grant`) mint a grant whose signed payload
  carries `aud` = the one organelle codon it may be presented to.
  `call_with_grant` denies presenting it to any other codon — even when the
  capability check would pass. Unscoped grants (`issue_grant`) keep working
  against any codon (back-compat). The `aud` field is `#[serde(default)]`:
  v1 tokens minted before it existed still verify, as unscoped. Tampering
  with `aud` breaks the HMAC and is denied as `InvalidSignature`.
- **Nested-call confinement (transitive).** While a grant-authorized
  invocation is live, its trace id is registered in the host's `grant_domains`
  table with the grant's capability set. A nested (organelle→organelle) call
  under that trace runs with the **intersection** of the calling organelle's
  manifest `granted_capabilities` and the grant's domain — a grant for
  capability X cannot be escalated to capability Y through a nested call,
  even when the organelle's own manifest would allow Y. The nested
  invocation's own trace carries its effective caps, so confinement propagates
  transitively down the call chain. The invocation binding and the receipt
  record the effective (intersected) caps — the receipt shows exactly what
  authority the nested call ran with.
- **Deliberate boundary:** invocations that did not arrive under a grant
  (native in-process surface) keep the org-011 membrane identity model —
  the organelle's manifest grants govern nested calls, unchanged. The native
  surface has no grant domain to escape.

## Operator configuration

```rust
let h = Host::new();
// Filesystem: approve exactly the dirs organelles may write.
h.set_write_roots(vec!["/var/lib/organelles".into()])?;
// Network: allowlist the hosts organelles may contact.
h.set_egress_policy(EgressPolicy::allowlist(&["api.example.com", "*.internal.example"])?);
// Grants: confine a caller's grant to one organelle.
let g = h.issue_scoped_grant("etl-job", "la", vec!["ledger.write".into()], 300);
```

Until `set_write_roots` / `set_egress_policy` are called, the corresponding
side effects are denied. The operator owns these lists; organelles cannot
widen them. Grant keys remain operator-owned under the standing secret freeze
(this host never logs or exposes key material).

## Test map

- `crates/organelle-host/src/policy.rs` — 11 unit tests: pattern parsing
  (incl. wholesale refusal of malformed allowlists), host extraction,
  default-deny, `..` lexical rejection, symlink escape, outside-root denial.
- `crates/organelle-host/src/authority.rs` — audience roundtrip, tampered
  audience → `InvalidSignature`, pre-audience v1 token still verifies.
- `crates/organelle-host/tests/grant_confinement.rs` — 7 tests: scoped
  grant cross-organelle reuse denied (+receipt), unscoped back-compat,
  scoped≠capability-bypass, nested escalation denied (sink never runs,
  denial logged + receipted with empty effective caps), positive control,
  native-surface membrane model unchanged, transitivity (3-level chain).
- Ref crates — write-outside-roots denied (la/fc/nt), no-roots default deny
  (la), symlink escape (la), disallowed-host + no-policy deny (hf/se).
- `organelle-equivalence` — the harness declares write roots + a
  localhost-only egress allowlist in `build_host`; the 19×4=76 matrix stays
  green, proving the policies hold identically on all four transports.
