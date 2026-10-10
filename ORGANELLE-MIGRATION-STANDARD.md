# ORGANELLE-MIGRATION-STANDARD v1 (2026-10-10)

What a repo must have to count as "truly organelles". Grounded in:
- LiteBox spec §19: organelle = COMPUTATION + CAPABILITY CONTRACT + EXECUTION PERSONALITY + PROVENANCE + RESOURCE ENVELOPE + KILL SEMANTICS
- LiteBox spec §23: manifest fields (organelle_id, authority, input/output hashes, fs allowlist/readonly, network/process/device/secret policy, cpu/mem/timeout, sandbox, platform, receipt/kill policy)
- `~/workspace/organelles` substrate: `organelle-manifest` (org-001), `organelle-host` (org-002/008–012), 3 surfaces, 12 ref organelles, 112 tests green

## The six required aspects

### 1. COMPUTATION
The repo's capability units are enumerated. A capability unit = one independently callable thing (binary, service, library crate, script entrypoint). Each repo gets `organelles/` dir at root containing one manifest per capability unit.

### 2. CAPABILITY CONTRACT
Each manifest declares, in `organelle-manifest` v1 terms:
- `name` (lowercase-digits-dashes, ≤64), `codon` (2 chars), `version` (semver), `description`
- `contracts[]`: op name + JSON-Schema input + per-op `mutation_class` (ReadOnly/Write/ExternalEffect) + per-op `required_capability`
- `authority`: default mutation class, `declared_valence` (Proven/Candidate/Disproven), capability gates; Write/ExternalEffect without a capability = INVALID (host refuses registration)
- `transports`: subset of [native, unix_socket, mcp, rest]
- `receipt_policy`: content-addressed + sha256 + chained (always true)

### 3. EXECUTION PERSONALITY
Manifest (or companion `execution.json`) declares: filesystem allowlist + readonly flags, network policy (none/localhost/egress-allowlist), process/device policy, secret policy (never-in-env? vault-ref only), platform, sandbox mode (none / linux-userland / litebox / tee). Rust-native organelles implement the `Organelle` trait; non-Rust code registers through a host surface (unix-socket JSON-lines preferred, MCP or REST where it fits) — the adapter is thin, computation stays in its language.

### 4. PROVENANCE
- Manifest hash pinned in every receipt the organelle emits.
- Build provenance: source commit hash recorded at registration; receipts carry input/output hashes.
- Valence honest: pure/deterministic → Proven; stateful/unverified/external → Candidate; known-broken → Disproven. No valence inflation.

### 5. RESOURCE ENVELOPE
Every manifest declares cpu / mem / wall-time / IO caps. The host enforces (suspend-first on breach — never silent kill). No manifest without an envelope registers.

### 6. KILL SEMANTICS
Every organelle declares its kill policy: suspend → checkpoint → kill ordering; what "suspend" means for its state (in-memory state must be checkpointable or declared ephemeral); kill always emits a final receipt. Suspend-first doctrine (fabric law) — the host never SIGKILLs without a suspend attempt and a receipt, except declared-ephemeral compute.

## Host registration (the bar)

A repo is DONE when:
1. `organelles/<unit>.manifest.json` exists per capability unit, validates via `organelle-manifest::validate_manifest_json` (use the `pl` binary or a validation lane).
2. Every unit is registered on a running `organelle-host` (native trait impl for Rust; surface adapter for the rest) — registration receipted.
3. Every invocation path emits content-addressed, hash-chained receipts (`verify_chain` green).
4. Kill semantics demonstrated: suspend + kill each produce receipts.
5. Existing tests stay green; new manifest/registration covered by tests where the repo has a harness.
6. One commit per repo, message `organelle-migration: <repo> tier-<A|B|C>`.

## Tiers

- **Tier A (native):** Rust repo. Capability crates implement `Organelle` (manifest() + handle()), registered via `Host::register`, equivalence-tested across transports where it matters.
- **Tier B (surface-adapted):** Python/JS/mixed. Manifest JSON + thin adapter (unix-socket JSON-lines client calling into the host). Authority, receipts, kill, envelope enforced by the host; computation untouched.
- **Tier C (declared):** Docs-only / unmigratable. Manifest only, valence Candidate/Disproven, no live registration. Scratch dirs are excluded, not Tier C.

## Never

- No `git reset`/`stash`/`clean -f`/force-push/history rewrite (standing rule).
- Never break existing tests. If a repo's tests can't run here (e.g. needs network/Gradle), record that in the status file — don't fake green.
- Never migrate secrets into manifests. Capability names, never credential values.
- Archive-don't-delete: migration adds files; it never removes code.
