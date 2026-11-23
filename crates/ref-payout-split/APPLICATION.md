# APPLICATION — ref-payout-split (org-037, codon `ps`)

The payout-split ledger organelle behind VanCan/Canswer
(decomposition GAP-24). It replaces the split math and payout ledger
currently hand-rolled in the `vancan` monolith
(`vancan/payout/{payout,ledger}.rs`).

## What it provides

- `compute_split(gross_cents, table, rule)` — integer-cent split.
  Parts sum **exactly** to the gross for every input (property-tested,
  40k randomized cases across both remainder rules). No floats.
- `SplitTable` — ordered (party, weight) shares, caller-supplied and
  validated (non-empty, no duplicate parties, total weight > 0).
- `RemainderRule` — the rounding policy, chosen by the caller on every
  call: `LargestRemainder { tie_break }` or `EntireRemainderTo { party }`.
  The crate has no default rule and no baked-in percentages.
- `SplitLedger<Simulated>` — append-only entries {seq, gross, table
  snapshot, rule, parts, memo, is_simulated}. No removal or mutation
  API exists. Per-party totals conserve the gross by construction.
- JSONL persistence (`jsonl` feature): every line verified on load —
  gapless sequence, `is_simulated == true`, parts recompute exactly
  from gross + table + rule. Any failure refuses the whole load.
- Organelle surface (`organelle` feature): `split` (compute + return
  the would-be entry) and `verify_entry`, both ReadOnly. Persistence
  composes with ref-ledger-append (org-020): the caller appends the
  entry JSON line; this organelle never touches files itself.

## How VanCan adopts it

1. Replace `vancan/payout/payout.rs::split_payout` with
   `compute_split`. Note the signature change: the old function takes
   a single `canner_pct` and derives the rest implicitly; the
   organelle takes the whole table as data. The programme table is
   `vancan_split.json` — canner 69 / driver 21 / vancan 10 — loaded by
   the caller and passed in, so a future split change is a data
   change, not a code change.
2. Replace `vancan/payout/ledger.rs` with `SplitLedger<Simulated>`.
   The old ledger's `record(..., is_simulated: bool)` lets any caller
   pass `false`; the organelle removes the parameter — the flag is
   the entry's type. Depot receipts keep their existing signing path
   (pl envelope + wsign); the entry JSON is the payload that gets
   signed.
3. Pick the remainder rule as programme policy and record it. The old
   code's rounding was whatever the single-percentage math happened
   to do; under the organelle the rule is named in every entry
   (`rule.tag()`), so historical payouts are auditable against the
   exact rule that produced them.

## How Canswer adopts it

Same composition, different table — supplied as data by the caller:
customer 69 / driver 26 / platform 5 at BC's 10¢ per container
(the 100-bottle case, 1000¢ → 690/260/50, is a named test). Canswer
and VanCan run different tables through the same organelle; neither
table lives in the crate.

## What changes when REAL_PAYOUTS ever flips

Honest answer: it is **not** a flag flip, by design. Today
`REAL_PAYOUTS=false` is mirrored as a missing trait implementation —
`SplitLedger::<Real>` does not compile. Making real payouts possible
requires, at minimum:

1. `impl PayoutMode for Real` in this crate — a deliberate,
   reviewable, signed code change, with `IS_SIMULATED = false`.
2. A serialization story for mixed history: `from_jsonl` for
   `SplitLedger<Simulated>` refuses real entries (and vice versa the
   real loader must refuse simulated ones), so simulated and real
   histories stay separate ledgers. A depot that ran simulated lots
   and later real lots holds two files, not one flag-flipped file.
3. Money-movement code lives **outside** this organelle. The
   organelle computes and records splits; it holds no keys, talks to
   no payment rail, and that does not change when the mode flips.
   The adopter wires `Real` entries to whatever payment execution
   layer exists then, under its own approvals.
4. VanCan-side: the programme's locked rule
   (`depot_receipts.is_simulated` must be true) is a programme
   decision. Flipping it is Zack's call, recorded as a new decision —
   the organelle neither grants nor blocks it beyond forcing it to be
   explicit in types.

## Limits

- Gross is `u64` cents, non-negative. Refunds/chargebacks (negative
  flows) are a separate entry type this version does not model.
- Weights are `u64`; exact shares use u128 intermediates, so no
  realistic gross × weight overflows.
- The ledger is in-memory + JSONL. Concurrent writers to one JSONL
  file need the caller's composition (e.g. ref-ledger-append's
  host-approved write path); this crate does no file locking.
- Wasm face: the core is std-only and target-independent; the
  organelle surface compiles for wasm32 like its sibling reference
  organelles (compile-proven pattern; runtime proof happens in the
  adopting worker, as with org-036).
