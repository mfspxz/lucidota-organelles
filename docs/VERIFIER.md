# The Verifier: exactly what it proves, and what it does not

**Scope:** `organelle-host` receipts — the content-addressed, hash-chained
per-action record (`Receipt`), the durable log (`receipt_log.rs`), and the
external checkpoint (`ReceiptAnchor`). Read this before making any claim of
the form "the receipts prove X."

Epistemic rule for this whole document: **proven / disproven / unknown.**
Anything not listed under "establishes" is not established.

---

## 1. What `verify_chain()` establishes

Given the in-memory (or log-reloaded) receipt vector, `verify_chain()`
checks, per receipt:

1. `receipt.compute_id() == receipt.id` — the id is the sha256 over the
   canonical JSON of every other field (seq, kind, codon, op,
   manifest_version, caller, granted_capabilities, transport, input_hash,
   output_hash, verdict, valence, prev, note, ts). Any mutation of any
   covered field breaks the id.
2. `receipt.prev` equals the previous receipt's id (or `"GENESIS"` for
   the first) — the chain is unbroken, in order.
3. `seq` is strictly increasing.

**This establishes:**

- **Internal consistency of the presented chain.** The receipts you are
  looking at have not been modified, reordered, or spliced since their ids
  were computed — doing any of that breaks (1) or (2).
- **Completeness of the presented prefix.** No receipt was *inserted into
  the middle* of this chain or *removed from the middle* without breaking
  the prev-links.
- **The binding claim for each receipt.** `granted_capabilities`,
  `transport`, `manifest_version`, and `caller` are covered by the id:
  the receipt commits to exactly the authority tuple the invocation ran
  with. (Whether that tuple was *correct* is a separate question — see §4.)

**This does NOT establish:**

- **That the chain is complete.** Deleting receipts from the *tail* (the
  newest end) leaves a shorter chain that still verifies. `verify_chain`
  cannot distinguish "the full history" from "a truncated prefix of the
  history." Tail-truncation is detected only by an external anchor whose
  seq is *beyond* the truncation point (§3).
- **That any particular invocation happened.** If no receipt was emitted
  (crash before emission, or the host never ran it), there is nothing to
  verify. Absence of a receipt is not evidence of absence of the action —
  it is only evidence that no receipt was emitted.
- **Wall-clock truth of `ts`.** Timestamps come from the operator's clock.
  The chain proves *ordering*, not *time*.
- **That the chain is the only chain.** Two hosts (or one host at two
  times) can hold divergent chains that each verify. Forks are invisible
  to `verify_chain`.

---

## 2. What durable persistence establishes

When `enable_receipt_log(path)` is active, every emission is appended to
the log as `ORL1 | len:u64 LE | JSON` and `fsync`'d **before** the receipt
id is returned to the caller or the receipt enters the in-memory chain.

**This establishes:**

- **A returned receipt id is durable against process crash.** `fsync`
  precedes the return, so `process::exit`, a panic, SIGKILL, or any other
  process death after the caller holds the id cannot lose the record.
  Proven by `crash_mid_invocation_no_phantom_receipt` (real subprocess
  killed mid-handle) and `returned_id_is_durable_before_return` (record
  present via an uncooperative file handle before `call` returns).
- **No half-written records survive.** A torn trailing write (crash
  mid-append) is detected on recovery by the length prefix and truncated
  openly (`RecoveryOutcome::Repaired`, with the dropped byte count). The
  log always holds a valid prefix — never a corrupt-looking middle.
- **Corruption fails closed.** A fully-written record that does not parse,
  fails id recomputation, breaks a prev-link, or breaks seq monotonicity
  is *corruption, not a crash artifact*: recovery refuses the log
  (`enable_receipt_log` returns `Err`, nothing is attached, the host
  serves nothing from it). Proven by `corrupt_record_fails_closed`.
- **Log-write failure fails closed.** If an append or fsync fails (disk
  full, I/O error), the host panics while holding the dispatch write
  guard, poisoning the `RwLock`: every subsequent operation on that host
  fails instead of serving receipts that are not durable. Loud death beats
  silent audit loss. Proven by `log_write_failure_poisons_host`.
- **No lost-and-unacknowledged invocations.** The two crash cases are
  exhaustive at the receipt boundary: (a) crash *before* emission — no
  receipt exists and the caller received no id, so nothing was
  acknowledged and nothing is owed (§2 first bullet covers the converse);
  (b) crash *after* the id was returned — the record is fsync'd, so
  recovery replays it. There is no third state in which the caller holds
  an id for a record that does not exist.

**This does NOT establish:**

- **Machine-crash durability beyond the OS's honesty.** `fsync` is a
  request to the storage stack. A lying disk controller, a filesystem that
  reorders across fsync barriers, or power loss mid-flush can still lose
  the tail. What survives is whatever the storage stack actually persisted;
  recovery then truncates the torn tail openly. We claim process-crash
  safety as proven; machine-crash safety as *best-effort modulo the
  storage stack*.
- **Multi-writer safety.** The log assumes a single host process. Two
  hosts appending to one file interleave records; the next open detects
  the mismatch and fails closed, but concurrent writers are operator
  error, not a supported configuration.
- **Confidentiality.** The log is plaintext JSON. Receipts contain input
  *hashes*, not inputs, and denial reasons (which may name paths, hosts,
  or capabilities) — but no secret values by construction. Protect the
  file like any other audit trail.

---

## 3. What an external anchor establishes

`export_anchor()` / `write_anchor()` pins `(seq, head_id, count)` at a
point in time. `verify_against_anchor(anchor)` checks the live chain
still contains that exact `(seq, head_id)` pair. The anchor is meant to
be stored **where the host operator does not control it** — a separate
machine, an append-only store, a printed page.

**This establishes:**

- **No rewind below the anchor.** If the chain is truncated or rolled back
  to before the anchor's seq, the pair is absent → `Err`. Proven by the
  rewind simulation in `anchor_export_verify_and_rewind_detection`.
- **No rewrite at or before the anchor.** Any modification of any receipt
  at seq ≤ anchor.seq changes its id (content-addressed) → mismatch → `Err`.

**This does NOT establish:**

- **Anything about receipts newer than the anchor.** Tail truncation
  *after* the anchor point is invisible to that anchor. Anchors must be
  exported often; the detection window is only as tight as the export
  cadence.
- **Fork-freedom.** Two chains sharing the anchored prefix both verify
  against the anchor. The anchor pins a point, not a unique future.
- **Anchor authenticity.** If the attacker controls the anchor store, they
  can present a freshly-exported anchor for a rewritten chain. The anchor
  is only as trustworthy as its store's independence from the host
  operator. This is the load-bearing residual assumption of the whole
  scheme — see §5.

---

## 4. What no receipt can prove (residual limits of the record itself)

- **Receipts record the host's view, not ground truth.** A receipt says
  "the host authorized invocation I under binding B and the organelle
  returned output with hash H." If the host binary is modified, the
  organelle lies in its output, or the binding inputs were wrong, the
  receipt faithfully records a falsehood. `Valence` labels (Proven /
  Candidate / Disproven) describe the *claim's* standing, not a proof of
  the underlying fact.
- **A compromised organelle's identity assertions are its own.** The
  receipt binds `caller: "organelle:X"` because the host routed codon X —
  it does not prove the code behind codon X is the code the operator
  believes it is. Supply-chain integrity of organelle implementations is
  out of scope for the receipt layer.
- **Denial receipts prove refusal, not cause.** A `Denied` receipt proves
  the host refused and why *it says* it refused; it does not prove the
  underlying policy evaluation was correct.

---

## 5. Residual trust assumptions (the honest list)

The verifier's guarantees hold only while ALL of these hold. Each is a
single point of failure for the corresponding guarantee:

1. **Operator key custody.** Grant HMAC keys (`with_grant_key`) are minted
   and kept by the operator. Key compromise forges grants; the receipt
   layer cannot detect it. Secret freeze applies: the host never logs,
   rotates, or exposes the key.
2. **Clock.** `ts` fields and grant TTLs trust the operator's clock.
   Ordering comes from `seq`, not from time — do not use `ts` for
   ordering arguments.
3. **Storage integrity between loads.** Bitrot in the *middle* of the log
   is caught on the next open (fail-closed), but a record that rots and is
   never re-read is never caught. The log is not a substitute for
   checksummed backups.
4. **fsync honesty** (§2) — the storage stack actually persists on fsync.
5. **Write-root operator correctness.** The log and anchor paths must be
   under approved write roots (`set_write_roots`); with no roots the host
   refuses to attach a log (default deny). A misconfigured root (e.g. a
   world-writable or attacker-controlled directory) voids the durability
   argument.
6. **Single writer.** One host process per log file (§2).
7. **Anchor-store independence** (§3) — the anchor must live outside the
   host operator's control, or it attests to nothing.
8. **Host binary integrity.** A modified host can emit false receipts that
   verify perfectly. Receipts are tamper-*evident*, not tamper-*proof*
   against the party that holds the host.
9. **No silent emission paths.** The guarantee "every call emits exactly
   one receipt" is a code invariant (every `call` path goes through
   `emit_receipt`), enforced by review and by `no_silent_pass_every_call_
   receipted`-style tests — not by the type system. A future code path
   that bypasses `emit_receipt` would break it silently.

---

## 6. Operator runbook (the 30-second version)

1. `set_write_roots(vec![...])` — bless a directory the host may write to.
2. `enable_receipt_log("<root>/receipts.log")` — **before** registering
   organelles. Check the returned `RecoveryOutcome`: `Fresh` (new),
   `Loaded{n}` (restart), `Repaired{..}` (crash tail truncated — expected
   after a hard kill, investigate if frequent).
3. Operate. Every returned receipt id is durable (process-crash safe).
4. Periodically: `write_anchor("<root>/anchors/<ts>.json")` and copy the
   anchor **off the host** (separate store/machine). Cadence sets the
   rewind-detection window.
5. To verify later: load the chain (`enable_receipt_log` on a fresh host),
   `verify_chain()`, then `verify_against_anchor(&anchor)` for each
   out-of-band anchor, newest first.
6. If `enable_receipt_log` ever returns `Err`: **stop.** The log is
   corrupt or foreign. Do not delete it, do not "fix" it by hand —
   investigate with the file preserved (archive-don't-delete).
