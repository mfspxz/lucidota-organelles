# WAVE 1 RESULTS — organelle migration (2026-10-10)

Six Tier A Rust repos. All native Organelle trait impls, registered on Host,
hash-chained receipts, `verify_chain` green. One commit per repo:
`organelle-migration: <repo> tier-A`. `~/workspace/organelles/MIGRATION-STATUS.md`
NOT touched (coordinator-owned).

| Repo | Codon | Ops | Decision | Tests | Commit |
|---|---|---|---|---|---|
| security/failclosed | `fd` | decide (Write, `fd.write`), verify, receipts | bespoke | 12/12 (9 pre + 3 org) | 379301a |
| security/ipc | `ip` | roundtrip, auth_probe (both ExternalEffect, `ip.roundtrip`) | bespoke | 10/10 (7 pre + 3 org) | fdf92eb |
| security/provenance | `pv` | record (Write, `pv.write`), lineage, verify | bespoke | 11/11 (8 pre + 3 org) | 904c87e |
| security/auditor | `ad` | scan (ReadOnly, Candidate) | bespoke | 12/12 (9 pre + 3 org) | e4421fc |
| longtail/rust/lt-tools | `lt` | 14 ops (13 ReadOnly; ports ExternalEffect, `lt.net.probe`) | bespoke | 18/18 (15 pre + 3 org) | b589d2b |
| longtail/rust/ornament | `or` | pack_load, pack_check, profile, questions, calibrate (all ReadOnly) | bespoke | 20/20 (17 pre + 3 org) | 3728c3f |

## Per-repo map-or-design (one-line justifications)

- **failclosed** (`fd`): deny-by-default decision + BLAKE3 chain is the unit's
  identity; ref-hash-seal would cover only the hash primitive (wrong layer),
  ref-kv-store the wrong data model, ref-ledger-append the wrong computation
  (file appends vs. decision chain). Bespoke. Full record:
  `security/failclosed/organelles/MAPPING.md`.
- **ipc** (`ip`): framed-JSON unix-socket protocol with BLAKE3(token||challenge)
  auth + failclosed-gated dispatch; ref-http-fetch/scrape-extract are the wrong
  protocol (HTTP/TCP vs. unix sockets + challenge-response). Bespoke. Full
  record: `security/ipc/organelles/MAPPING.md`.
- **provenance** (`pv`): append-only event recording with artifact lineage edges
  + replay verifier; ref-ledger-append would flatten provenance into blind file
  appends and lose lineage + verification. Bespoke. Full record:
  `security/provenance/organelles/MAPPING.md`.
- **auditor** (`ad`): security-heuristic source scan (secret-literal,
  unsafe-block, panic-path, TODO, secret-file-perms, wildcard-deps) with
  audit-allow waivers; ref-scrape-extract is web pages, not source trees
  (category error). Valence honestly Candidate — "heuristic, not a proof".
  The `audit` CLI binary is covered by the `scan` op (thin wrapper, no separate
  organelle). Full record: `security/auditor/organelles/MAPPING.md`.
- **lt-tools** (`lt`): 14 of 15 utilities as ops. All 12 reference organelles
  checked per-op; the serious candidates failed on contract: ref-text-transform
  has a *closed mode enum* (b64/urlx/tpl not members — would require changing
  the reference contract), ref-hash-seal seals JSON not file bytes (shapin),
  ref-time-oracle gives clock not conversion math (epoch), ref-http-fetch is a
  protocol not a probe (ports), ref-json-validate validates not filters/decodes
  (jgrep/jwtdec). `retry` deliberately EXCLUDED (spawns arbitrary subprocesses —
  cannot be capability-contracted as a data op). 11 ops exactly recomputable;
  epoch:now/uuid7/unseeded-passgen draw from clock/urandom (declared, not
  hidden). Full record: `longtail/rust/lt-tools/organelles/MAPPING.md`.
- **ornament** (`or`): 5 ops = 5 CLI commands (pack_load, pack_check, profile,
  questions, calibrate). ref-model-call rejected on honesty grounds — question
  generation is template-based, not model output; adopting it would misrepresent
  the computation. Full record: `longtail/rust/ornament/organelles/MAPPING.md`.

## Defects found and fixed during the wave

1. **Codon collision (failclosed):** prior partial work used codon `fc`, which
   belongs to reference organelle `ref-file-cas`. Codons route on the host —
   a collision is a defect. Renamed to `fd` (manifest JSON, execution.json,
   organelle.rs incl. capability `fc.write`→`fd.write`, tests).
2. **Wrong test expectation (ipc):** prior partial work asserted that
   `roundtrip` with an unknown principal fails auth — but the ephemeral server
   registers the supplied principal/token by design, so auth cannot fail
   there. Fixed the test to assert the real fail-closed path (missing required
   input); the negative auth path is covered by `auth_probe` as designed.
3. **lt-tools Cargo.toml:** path deps appended after `[[bin]]` sections landed
   in a bin table, not `[dependencies]` — moved. (auditor's file had no
   `[[bin]]` sections, so its append was correct.)

## Deliberate exclusions (recorded in per-repo MAPPING.md, not dropped)

- failclosed: none (whole crate is one unit).
- ipc: frame codec + handler/policy registration surface (internal, not
  independently callable).
- provenance: to_json/from_json (transport, not computation).
- auditor: none (CLI covered by `scan`).
- lt-tools: `retry` (subprocess spawn — not hostable).
- ornament: none (5 commands = 5 ops).

## Notes for the coordinator

- Pre-existing condition, out of wave-1 scope: 8 other already-migrated
  security manifests (airgap-toolkit, backup-crypto, cute-e2ee, ir-runner,
  redteam, sec-organelles, threatmodel, vault) appear to have NO codon field
  at all. Codons route on the host — worth a sweep before those repos'
  registrations collide or fail. Not touched (not my wave).
- auditor's `.secrets-allowlist` was modified before this wave; left unstaged
  (selective staging).
- All tests ran locally on this VM — no faked greens, no network needed.
- No secrets in any manifest (capability names only; `granted_capabilities`
  empty except failclosed/ipc/provenance which grant their own write caps by
  name).
- Kill semantics: suspend-first per fabric doctrine; stateful organelles
  (failclosed, provenance) checkpoint via receipts/lineage export and declare
  cross-restart state ephemeral; stateless ones (auditor, lt-tools, ornament,
  ipc's ephemeral servers) suspend=no-op, kill=drop. Host emits final receipt
  in all cases (covered by host machinery, asserted via verify_chain in tests).
