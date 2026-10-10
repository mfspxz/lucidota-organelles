# substrate-suspend-kill — RESULTS

Date: 2026-10-10. Crate: `~/workspace/organelles/crates/organelle-host/src/lib.rs`.
Closes the adversarial-QA gap: Host had register/call/receipts/verify_chain/profiles/routes
but no suspend/kill; ReceiptKind had no lifecycle variants; the Organelle trait was
manifest+handle only. Kill semantics were prose. They are now code + receipts.

## Added

- `ReceiptKind::{Suspend, Checkpoint, Kill}` (snake_case serialized: `suspend`,
  `checkpoint`, `kill`). Receipts stay content-addressed sha256 + hash-chained;
  manifest schema untouched (no new required fields — old manifests validate).
- `Organelle` trait lifecycle hooks with **default no-op impls** — all existing
  organelles (15 migrated + 12 ref) compile untouched:
  - `fn suspend(&self) -> Checkpoint` — default returns an ephemeral (empty-bytes) checkpoint.
  - `fn kill(&self)` — default no-op.
- `pub struct Checkpoint { codon, ts, bytes: Vec<u8>, ephemeral: bool }` — serializable.
- `Host::suspend(&self, codon: &str) -> Result<Checkpoint, String>` — emits a `Suspend`
  receipt then a `Checkpoint` receipt whose `output_hash` is the sha256 of the checkpoint
  bytes (chain commits to the exact captured state). Organelle hook runs outside the
  dispatch lock (same deadlock rule as `handle()`). Unknown codon → clean error carrying
  the receipt id + a `Denied` Suspend receipt (fail-closed, same shape as `call()`).
- `Host::kill(&self, codon: &str) -> Result<(), String>` — suspend-first per doctrine:
  re-runs suspend (Suspend + Checkpoint receipts), invokes the organelle's `kill()` hook,
  then emits a final `Kill` receipt. No silent kill. Unknown codon errors cleanly + receipt.
- Module docs updated to describe the lifecycle (suspend → checkpoint → kill, no silent
  kill, hooks outside the dispatch lock).

## Tests (5 new, all in lib.rs)

1. `suspend_captures_checkpoint_and_receipts_it` — stateful Counter organelle (overridden
   `suspend()`/`kill()`): 3× inc → suspend; checkpoint bytes JSON round-trip (`{"count":3}`);
   exactly 2 receipts (Suspend then Checkpoint); Checkpoint receipt `output_hash` ==
   sha256(checkpoint bytes); `verify_chain` green.
2. `kill_is_suspend_first_with_final_kill_receipt` — kill → organelle `kill()` hook ran
   (AtomicBool); exactly 3 receipts (Suspend, Checkpoint, Kill last); `verify_chain` green.
3. `kill_unknown_codon_errors_cleanly_with_receipt` — error names the codon and carries the
   receipt id; exactly 1 `Denied` Kill receipt; chain green.
4. `suspend_unknown_codon_errors_cleanly_with_receipt` — same shape for suspend.
5. `default_lifecycle_hooks_are_ephemeral_and_noop` — Echo (no overrides) suspends as
   ephemeral with empty bytes; kill is a no-op; all 5 lifecycle receipts chained; green.

## Counts

- organelle-host: 30 unit + 6 integration (tests/fail_closed.rs) = **36, all green**.
- Full workspace (`cargo test --offline --workspace`): **116 passed, 0 failed**
  (111 pre-existing + 5 new).
- Pre-existing flake (NOT caused by this change): `ref-model-call`
  `live_provider_path_against_local_stub_server` failed once on the first baseline run
  and passed on every rerun (port-binding race in the stub server fixture). Unrelated to
  the substrate; left untouched.

## Commit

`organelle-substrate: suspend/kill lifecycle with checkpoint receipts` — single commit,
only `crates/organelle-host/src/lib.rs` staged (selective staging; no reset/stash/clean).
