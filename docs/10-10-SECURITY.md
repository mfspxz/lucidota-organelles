# Organelles: the road to 10/10 security

**Status:** hardening campaign complete through the reviewer's full repair order (2026-10-10).
**Revision:** `311fb04` (six commits: `f928bc6` → `89a6d58` → `380ed26` → `656d7cf` → `d5dd246` → `311fb04`).
**External review baseline:** 7.2/10 overall (8.5 architecture, 4/10 security assurance).
**This document:** what 10/10 means per category, which gaps the campaign closed, what remains, milestones with acceptance tests, and how re-audit works. It does not claim 10/10.

Evidence: `docs/evidence/2026-10-10/` (full suite log, matrix detail, SUMMARY.md, SHA256SUMS).
Verifier bounds: `docs/VERIFIER.md`. Policy model: `SIDE-EFFECT-POLICY.md`.

---

## 1. Threat model

**Adversaries:**
- **A1 — malicious transport peer:** reaches unix socket / MCP stdio / REST with crafted wire bytes. Goal: invoke organelles with capabilities they were never granted, replay grants, confuse identity.
- **A2 — compromised or malicious organelle:** runs inside the membrane. Goal: escalate capabilities via nested calls, write outside its sandbox, exfiltrate over the network, lie in receipts.
- **A3 — careless operator / buggy client:** misconfigures policies, reuses keys, misreads receipts. Goal (unintentional): weaken the system.

**Assets:** capability grants (authority), receipt chain (evidence), organelle sandbox (containment), host integrity.

**Trust boundaries:**
1. **Transport membrane** (surface crates → host): A1 lives outside this. Nothing caller-supplied is trusted past it.
2. **Organelle membrane** (host → organelle handler, org-011): A2 lives inside this. The host enforces caps, policies, and bindings; the organelle's own assertions (codon, trace id) are *not* trusted for authority.
3. **Host core:** trusted. A compromised host binary is out of scope (see §6).

**Explicitly out of scope:** host binary compromise, storage stack lying about `fsync`, DNS-rebinding past host allowlists, physical access, side channels.

---

## 2. What 10/10 means per category

| Category | 10/10 bar | Campaign exit (honest) |
|---|---|---|
| Architecture | Membrane theory fully realized: every trust boundary enforced in exactly one place, no ambient authority | ~9 — boundaries hold; advertisement filtering and route-versioning gaps remain (§4) |
| Crate boundaries | manifest→host→transport separation; policy code lives in host, never surfaces | Good — preserved and extended; new `policy.rs`/`authority.rs`/`receipt_log.rs` all host-side |
| Deterministic core | Same inputs → same verdicts, byte-identical receipts, replayable | Improved — receipt log framing is deterministic; single-writer assumption documented |
| Evidence & receipts | Every invocation durably receipted; chain tamper-evident; external anchors; verifier bounds written down | Strong — persistence + anchors + `VERIFIER.md`; anchor publication still manual |
| Capability enforcement | Unforgeable, least-privilege, non-escalatable, domain-confined | ~7 — grants unforgeable, audience-bound, nested intersection; residuals in §4 |
| Transport parity | Same behavior AND same authority decisions on all four transports, hostile-tested | Strong — 13 hostile scenarios × 4 transports matrix-enforced, zero parity failures |
| Production readiness | Deployable: key management, runbook, monitoring, flake-free suite, independent re-audit | **Not established** — see milestones |

---

## 3. Gaps closed by this campaign

- **P0 — forgeable authority** (`f928bc6`): all three external surfaces built `CallContext` from caller-supplied `caller`/`capabilities`. Now: host-issued HMAC-SHA256 grants only (`hmac` 0.12, constant-time verify); per-`Host` 256-bit key from `/dev/urandom`; single-use replay cache; fail-closed `Denied` + receipt. Forged/escalated/replayed/wrong-caller grants denied on unix, MCP, REST (35 new tests).
- **P1 — version/identity binding** (`89a6d58`): `call_as_organelle` authorized against the *latest* registered version while executing the *routed* (possibly pinned) version. Now: single `InvocationBinding` (caller, codon, op, version, granted caps, transport) established once, moved by value through authorize → execute → receipt; receipt body hash commits to caps + transport. Transport restrictions enforced at `authorize` (empty `transports` fail-closed at registration).
- **P1 — receipt correlation** (`380ed26`): REST/unix success paths returned `receipts().last()` — a cross-wiring race. Now: `CallOk { output, receipt_id }`, receipt constructed at invocation time; `emit_receipt` atomic under the store write lock. Concurrent correlation tests (16×25, 12×20, 12×16, 8×10, wire-level 8×20).
- **P1 — side-effect containment** (`656d7cf`): unscoped writes (ledger-append had a lexical `..` check only; file-cas/notify none); open egress. Now: `Host::set_write_roots` + canonicalizing `approve_write_path` (symlinks resolved); egress allowlist default-deny (exact hosts + `*.domain`); grant `aud` audience + nested-call capability intersection (manifest ∩ grant-domain, transitive). `SIDE-EFFECT-POLICY.md`.
- **P2 — recovery/integrity** (`d5dd246`): receipts were `Vec` behind `RwLock` — restart wiped everything. Now: append-only `receipt_log.rs` (`ORL1` framing, `write_all` + `sync_all` per emission, fsync *before* the id returns); torn-tail truncation as open `Repaired`; corrupt record → fail-closed; external `ReceiptAnchor` export/verify (rewind/rewrite detection). Crash probe (`exit(42)` mid-handle) proves acked receipts durable. `docs/VERIFIER.md` states exact prover bounds.
- **P2 — hostile matrix** (`311fb04`): 13 hostile scenarios (token attacks, policy/membrane attacks, version-skew, nested laundering) × 4 transports = 48 assertions + 12 cross-transport receipt-shape comparisons, all green. Revision-bound evidence in `docs/evidence/2026-10-10/` with SHA256 manifest.

**Suite:** baseline 116 passed → **207 passed, 0 failed** (`--exclude claim-reconciler`). Happy-path matrix 19×4=76 still green.

---

## 4. What remains (residuals — the honest list)

1. **Bearer window:** multi-use grants are bearer tokens; theft within TTL is usable. Mitigation exists (single-use grants, short TTL) but no theft detection.
2. **Self-asserted identity:** organelles assert their own codon and thread their own trace id; the membrane enforces caps *given* those assertions. A compromised organelle lying about identity is out of scope by design — but it is a design limit, not a proof.
3. **Approval→write TOCTOU:** write-path approval and the organelle's write are not atomic (documented in `policy.rs`).
4. **Advertisement gap:** surfaces advertise organelles over transports the manifest doesn't declare (`generate_tools`/`openapi_json` unfiltered). Invocation is denied; discovery is not.
5. **Route-change mid-flight:** `set_route` between outer resolution and nested re-resolution is a theoretical TOCTOU (trace-threading covers Split determinism; route *changes* aren't versioned).
6. **Egress granularity:** host-only patterns, no ports; DNS-rebinding subtleties not modeled.
7. **Pre-existing flake:** `ref-model-call::live_provider_path_against_local_stub_server` fails ~5/9 parallel runs (process-global env-var race: one test's `remove_var("MODEL_API_URL")` vs another's `set_var`). Always green `--test-threads=1`. Documented, not fixed.
8. **Uncovered:** multi-organelle collusion scenarios; crash-recovery under hostile input; `claim-reconciler` crate state (another campaign's; excluded from this workspace build).
9. **Key management:** per-`Host` random key or operator-seeded (`with_grant_key` / `ORGANELLE_GRANT_KEY`). No rotation story, no restart-stable key management beyond env vars.
10. **Anchors:** publication is manual; anchor-store independence is an operator responsibility (`VERIFIER.md`).
11. **No independent re-audit yet.** Everything above is builder-tested. The reviewer's ledger row stays at "fixed" until an independent party re-runs.

---

## 5. Milestones to 10/10 (each with acceptance tests)

- **M1 — kill the flake.** Fix the `MODEL_API_URL` env race (e.g. per-test ports/unique vars, or serialize). *Acceptance:* 20 consecutive full-suite runs, 0 failures, default thread count.
- **M2 — independent re-audit.** External reviewer re-runs the hostile matrix + full suite on the new HEAD, confirms or refutes each §3 claim. *Acceptance:* audit-ledger row → "tests independently reproduced", signed note.
- **M3 — close the membrane gaps.** Filter advertisements by declared transports; version route changes (or freeze routes during inflight invocations). *Acceptance:* new hostile matrix cases green (advertised-only-over-declared; route-change-mid-flight denied or version-pinned).
- **M4 — key management.** Documented rotation, restart-stable keys without env fragility, grant-key compromise response. *Acceptance:* runbook + test (rotate → old grants die, new grants work, receipts still verify).
- **M5 — collusion + hostile-crash coverage.** Multi-organelle collusion scenarios; crash recovery under adversarial input (corrupt log injection, anchor forgery). *Acceptance:* matrix extended, green.
- **M6 — production runbook.** Deploy checklist, monitoring (anchor publication automation, alert on `Repaired`/fail-closed events), backup/restore of receipt log. *Acceptance:* fresh VM deploy from runbook, all green.
- **M7 — workspace unity.** `claim-reconciler` builds clean in the workspace; no `--exclude` needed. *Acceptance:* `cargo test --workspace --offline` green, zero excludes.

---

## 6. Verification strategy

- **Revision-bound evidence:** every claim ties to a commit SHA + `docs/evidence/<date>/` (commands, raw logs, SHA256SUMS). Never "done" — ledger statuses: `queued → in review → source-reviewed → tests independently reproduced → fixed and re-audited`.
- **Who re-audits:** (a) the original external reviewer (continuity — they own the 7.2/10 baseline); (b) one independent second party (no shared context with the builders). Builders never self-certify.
- **How:** re-run `cargo test --workspace --offline --exclude claim-reconciler` (M7 removes the exclude), both matrix binaries with `--nocapture`, the `crash_probe`, and anchor round-trip; compare against `docs/evidence/2026-10-10/SUMMARY.md` expectations. Any divergence reopens the finding.
- **What I could NOT verify:** I (the coordinator) verified commits exist, the suite passes (207/0, run myself), and evidence files are present — I did **not** independently re-run each lane's adversarial tests one by one, did not review every line of the ~3,500 added, and did not test deployment. The per-lane test evidence is builder-reported; M2 exists precisely because of this.

## 7. Scorecard (coordinator's honest read, not a certification)

| Category | Reviewer baseline | Now |
|---|---|---|
| Architecture | 8.5 | ~9 |
| Crate boundaries | Good | Good |
| Deterministic core | Promising | Improved |
| Evidence & receipts | Good prototype | Strong |
| Capability enforcement | 4 | ~7 |
| Transport parity | structure good, authority weak | Strong (matrix-enforced) |
| Production readiness | Not established | Not established |
| **Overall** | **7.2** | **~8.2 (builder-assessed; M2 decides)** |
