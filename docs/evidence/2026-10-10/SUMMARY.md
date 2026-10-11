# P2 hostile equivalence matrix — revision-bound audit evidence

- Date: 2026-10-10 (America/Vancouver)
- Lane: ORGANELLES P2 LANE 2 — hostile equivalence tests + evidence preservation
- Parent commit: `d5dd246` ("P2: receipt persistence, crash recovery, external checkpoints")
- Lane commit: this evidence was committed as part of the lane commit
  ("P2: hostile equivalence matrix + revision-bound audit evidence");
  re-derive with `git log --format=%H -1 -- docs/evidence/2026-10-10`

## Exact commands run

```
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --workspace --offline --no-fail-fast --exclude claim-reconciler   # full suite
cargo test -p organelle-equivalence --offline --test equivalence_matrix -- --nocapture
cargo test -p organelle-equivalence --offline --test hostile_matrix -- --nocapture
cargo test -p ref-model-call --offline --lib                                   # flake isolation
cargo test -p ref-model-call --offline --lib -- --test-threads=1                # flake isolation (x4)
```

Rust toolchain: cargo 1.99 stable from ~/.cargo/bin (preinstalled on VM).
`--offline` throughout: no network, no card, no spend. No secrets touched.

## Raw counts

- Full workspace suite (excl. claim-reconciler): **207 passed, 0 failed**
  (this evidence run; exit 0). Stable count is 207 when the known flake
  below does not fire; 206 when it does (the flaky test itself fails, all
  others pass). Baseline per lane brief: 206 passed, 0 failed.
- Happy-path equivalence matrix: **19 scenarios x 4 transports = 76
  assertions, GREEN** (unchanged, still passing after the refactor).
- Hostile equivalence matrix (new): **13 cases; 48 per-transport
  assertions, all passing; 12 cross-transport receipt-shape comparisons,
  zero mismatches. VERDICT: GREEN.**

## New hostile scenarios (13)

Token attacks (valid grant would authorize; only the token is hostile):
1. `forged-grant` — payload byte flipped, original HMAC tag kept → Denied "grant signature invalid"
2. `escalated-caps` — caps surgically rewritten to a superset, tag kept → Denied "grant signature invalid"
3. `wrong-caller-grant` — grant for "equivalence" presented with caller claim "mallory" → Denied "does not match grant subject"
4. `replayed-single-use-grant` — single-use grant presented twice; second verdict asserted → Denied "already used (replay)"
5. `expired-grant` — ttl 0 → Denied "grant expired"
6. `malformed-grant` — "not-a-grant" → Denied "malformed grant"
7. `cross-organelle-grant` — grant scoped (audience) to `kv`, presented to `la.append` → Denied "grant scoped to organelle"

Transport / policy / membrane attacks (honest grant; the attack is elsewhere):
8. `non-declared-transport` — probe codon `nq` declares native only; presented over unix/mcp/rest → Denied "not declared" (native excluded by construction; see control)
9. `nq-declared-ok` — POSITIVE CONTROL: same organelle+grant+op over native succeeds, proving case 8 is transport gating, not a broken probe
10. `write-outside-root` — `la.append` with ledger path outside approved write roots → Failed "write denied"
11. `egress-disallowed-host` — `hf.fetch` to `http://10.0.0.1:9/` (not in allowlist) → Failed "egress denied"
12. `version-skew-pinned-route` — codon `vk` has v1 (requires `vk.admin`) and v2 (no cap); route pinned to v1; invoked with no caps → Denied "missing capability" (proves authorize+execute used the same pinned resolution)
13. `nested-boundary-escalation` — probe `nx.nest` attempts nested `kv.put` its manifest was never granted → Failed "lacks granted capability" (grant cannot be laundered through a nested call)

## Parity enforcement

Each hostile case asserts, per transport:
- the denial message contains the expected needle (message parity);
- a fresh receipt exists with the expected verdict (`Denied` for authority
  refusals, `Failed` for organelle-level fail-closed refusals), kind
  `Invocation`, the case's codon/op, and the adapter's arrival transport
  (receipt-shape parity);
- cross-transport: the receipt shape (verdict, kind, codon, op, and the
  content-addressed `output_hash` = the denial reason) is IDENTICAL on every
  transport that ran the case. The arrival transport is excluded from the
  comparison — it legitimately differs per surface.

**Parity failures found in the product: NONE.** No transport allowed what
the others denied; no transport denied with a different verdict or reason.
(Authority parity — the reviewer's explicit gap — is now matrix-enforced.)

## Issues found and fixed during lane work (harness/test bugs, not product)

1. Codon collision: probe codon `nt` collided with ref-notify (`nt`);
   registration refused ("codon nt already owned by notify"). Renamed probe
   to `nq`. Caught by manifest validation, fail-closed, as designed.
2. Receipt-shape comparison initially included the arrival transport and
   (correctly) flagged every case — the transport legitimately differs per
   surface. Removed it from the cross-transport shape; per-adapter
   `receipt.transport == arrival` is still asserted individually.
3. Test assertion count: 60 → 48. Cross-transport comparisons only add to
   the total as mismatches (same convention as the happy-path runner).

## Known flake (NOT fixed — reported per lane instructions)

- Test: `ref-model-call` lib test `live_provider_path_against_local_stub_server`
- Failure mode: `assert_eq!(out["stub"], json!(false))` fails with
  `left = Bool(true)`: the organelle took the stub path because
  `MODEL_API_URL` was unset when `handle()` read it.
- Root cause: `stub_is_honest_and_deterministic` → `chat()` calls
  `std::env::remove_var("MODEL_API_URL")` while the live test (parallel
  thread, same process) does `set_var` then depends on it. Process-global
  env var + parallel test threads = race. (Pre-existing; not introduced by
  this lane.)
- Rerun behavior: intermittent — observed failing in ~5 of ~9 full-suite
  runs; 4/4 runs with `-- --test-threads=1` green.
- Fix direction (not applied; out of lane scope): serialize the env-var
  access (e.g. a mutex around set/remove in these two tests) — NOT weakening
  the assertions.

## Files changed

- `crates/organelle-equivalence/Cargo.toml` — added `hex` (workspace dep) for grant tampering
- `crates/organelle-equivalence/src/lib.rs` — `TransportAdapter` extended
  (`hostile_call`, `arrival`, `last_receipt`); each adapter refactored with
  a `present()` wire helper; constructors use the hostile host
- `crates/organelle-equivalence/src/hostile.rs` — NEW: hostile token model,
  3 probe organelles (`nq` native-only, `vk` version-skewed, `nx` nested
  boundary), 13-case suite, cross-transport receipt-shape runner
- `crates/organelle-equivalence/tests/hostile_matrix.rs` — NEW: matrix test
- `docs/evidence/2026-10-10/` — this evidence (log, detail log, summary, hashes)

Prior lanes' guarantees preserved: HMAC grant auth, InvocationBinding,
invocation-specific receipts, write-root/egress policies, grant audience
confinement, receipt persistence — all untouched; the happy-path matrix is
still 76/76 green.

## Remaining unknowns

- The `ref-model-call` env-var race is reported, not fixed (see above).
- `claim-reconciler` was excluded from the suite per lane instructions;
  its state is unknown to this lane.
- Hostile coverage is transport-authority focused; it does not cover
  receipt-log crash recovery under hostile input (P2 lane 1's domain) or
  multi-organelle collusion scenarios.
