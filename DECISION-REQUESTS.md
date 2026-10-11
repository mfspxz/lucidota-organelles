# Decision Requests — awaiting Zack (created 2026-10-11)

These are product/design decisions that lanes cannot make on their own.
Nothing here is implemented until Zack picks an option.

---

## DR-1: ph_cycle22 `test_live_log_ledger_anchored` expectation

**Status:** AWAITING DECISION
**Source:** brutal-audit rollout round 4 (lane C proved identical failure on pristine HEAD)

The test pins live-ledger state and fails against the documented falsification scars
(seq 249 = grandfathered chain scar, seq 262 = documented mis-seal). This is not a
regression — the root cause is documented scar state, not our code. Left failing per
the rule "don't fix others' bugs," but the failing test is now noise in every full-suite run.

- **Option A:** Update the test's expectation to match the documented scars (knock-on pattern).
- **Option B:** Leave it failing as a permanent scar-marker.

---

## DR-2: F-RT2 persistent nonce store

**Status:** AWAITING DECISION
**Source:** brutal-audit rollout round 4/5 (F-RT2 re-attack wave: 16 fresh probes, 11 HELD / 5 RESIDUAL-CONFIRMED / 0 BYPASSED)

One confirmed residual is **restart-amnesia**: the nonce/dedup state lives in memory, so a
restart wipes it and previously-seen frames can replay. Documented, not filed as a defect
(no claim violated). Fixing it requires a **persistent nonce store** — disk-backed state,
write-ahead discipline, crash recovery semantics. That is a design change to the component's
architecture, not a bug fix.

- **Option A:** Approve the persistent nonce store design (lane designs + implements).
- **Option B:** Accept restart-amnesia as a documented residual (instance-only scope stands).

---

## DR-3: CR-1 — claim-reconciler `open-store` is self-service (CRITICAL)

**Status:** AWAITING DECISION
**Source:** swarm round 3 (R3-V4), retested by rollout round-5 lane-5 (`0ff03e7`, 11/11 green, 4 bypasses filed: CR-1..CR-4)

**The finding:** `open-store` is self-service — any `claims.write` holder can open a grant
for *another operator's* live book. The grant binds (caller, path) but authorizes no
ownership. End-to-end, the full R3-V4 reconciliation-poisoning chain still works: forged
claims, fabricated `SUPERSEDED_BY_BYPASS` with invented defeating probes, self-attested
`CLASS_CLOSED`, and `verify` reports `ok:true` over the poisoned book. The fe82e79 repair
(grant-bound store handles + probe provenance + self-attestation refusal) raised the attack
cost — 7 held controls — but did not close the class.

**Why this is yours:** the fix defines the multi-operator trust model. Two directions:

- **Option A — per-operator write roots:** each operator gets their own write root; `open-store`
  can only open books under the caller's root. Simple, strong isolation; operators cannot
  share books (or sharing needs an explicit delegation mechanism, designed later).
- **Option B — book-ownership registry:** a registry maps books to owners; `open-store`
  checks ownership before granting. More flexible (shared books possible with ACLs), but the
  registry itself becomes a trust anchor that needs its own protection.

Until CR-1..CR-3 close: claim-reconciler `verify`/CLASS_CLOSED outputs are untrusted input,
not verification authority (standing rule in organelles/MIGRATION-STATUS.md).

---

## Log

- 2026-10-11: file created. DR-1/DR-2 carried from rollout round-5 report; DR-3 materialized
  after panopticon round 14 found no decision document on disk.
