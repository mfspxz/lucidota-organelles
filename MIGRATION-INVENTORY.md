# Organelle Migration — Repo Inventory (2026-10-10)

54 real repos (22 top-level + 28 nested + 4 remote). Excluded: 38 dispatch-fabric git worktrees, scratch dirs (.scratch/*, scratch/rec1-tmp).

## Top-level git repos (~/workspace/*/)

| Repo | Lang | Size | Purpose |
|---|---|---|---|
| adhkey | rust | 473MB | Portable identity/key-lifecycle protocol above vault/wallet |
| batch-compile | mixed | 19MB | Batch-compile doctrine tooling |
| bin | scripts | 19MB | Operator scripts (secret-scrub, coding-agents-env, etc.) |
| canon | rust | 669MB | CANON — Canonical Engineering Authority (RFC-002) |
| compute | python | 319MB | Free-compute fabric: pipeline, dispatch, registry, burn |
| cutecity | mixed | 313MB | CuteCity site / frontend |
| dispatch-fabric | rust | 3.8GB | Dispatch fabric (+38 worktrees, excluded) |
| dogfood | mixed | 3.1GB | Dogfooding loop work dirs (40-cycle app builds) |
| exchange | mixed | 13MB | Free Compute Exchange |
| free-stack | docs | 1.3MB | Free-stack master plan docs |
| gis | rust | 444MB | CuteCity GIS backend |
| indy-reads | rust | 12GB | Indy_Reads voice research agent (thesis vertical) |
| krampus-express | rust | 3.6GB | Krampus Express scraper fleet (144 scrapers) |
| ledger-graph | rust | 21MB | Fast ledger parser + on-demand graph views |
| litebox-organelle-host | rust | 945MB | LiteBox-backed organelle host experiment |
| lucidota-core | rust | 315MB | LUCIDOTA CORE deterministic exocortex kernel |
| noter | rust | 1.7GB | NOTER E2EE notes (12 crates, 120 tests green) |
| organelles | rust | 619MB | The organelle substrate itself (org-001…024, 112 tests) — ALREADY ORGANELLES |
| park-send-wreck | rust | 533MB | park-send-wreck |
| proof-ledger | mixed | 4.3GB | Proof ledger (Rust impl nested at proof-ledger/rs) |
| shambhala | rust | 302MB | shambhala |
| system-ontology | docs | 196KB | System Ontology scaffold docs |
| verifier-mission | mixed | 24MB | verifier-mission |
| wreck | rust | 4.5GB | wreck — deterministic merge of proven state transitions |

## Nested git repos

| Repo | Lang | Purpose |
|---|---|---|
| lanectl | rust | 108-lane compute control plane |
| mcp-servers/experiment-desk | mixed | Experiment desk MCP server |
| cutecity-git/lucidota | mixed | lucidota (cutecity-git) |
| longtail/percyphonai | rust | Deterministic persona/identity engine ("Ghost Swarm") |
| longtail/rust/percyphon | rust | percyphon |
| longtail/rust/diogenes-kernel | rust | diogenes kernel |
| longtail/rust/soleita | rust | soleita |
| longtail/rust/coldmail | rust | coldmail |
| longtail/rust/ornament | rust | ornament |
| longtail/rust/chainstay | rust | chainstay |
| longtail/rust/py-ports | rust | py-ports |
| longtail/rust/brightideas | rust | brightideas |
| longtail/rust/lt-tools | rust | lt-tools |
| longtail/rust/shinder_mcowls | rust | shinder_mcowls |
| security/vault | rust | vault |
| security/cute-e2ee | rust | cute-e2ee |
| security/provenance | rust | provenance |
| security/auditor | rust | auditor |
| security/failclosed | rust | failclosed |
| security/ipc | rust | ipc |
| security/airgap-toolkit | rust | airgap-toolkit |
| security/redteam | rust | redteam |
| security/threatmodel | rust | threatmodel |
| security/ir-runner | rust | ir-runner |
| security/backup-crypto | rust | backup-crypto |
| security/sec-organelles | rust | sec-organelles |
| organelle/factory | rust | Organelle factory (workers/scheduler/jobs/ui) |
| litebox/litebox | rust | LiteBox upstream fork |
| proof-ledger/rs | rust | Proof ledger Rust impl (nested) |

## Remote (not cloned locally)

| Repo | Host | Lang | Purpose |
|---|---|---|---|
| mFSpx/diogenes | GitHub | mixed | ~20 RFCs, Lucidota operator (SLOP-LAWS) |
| mFSpx/mneme | GitHub | rust | Metacognitive agent (Voyager/Reflexion/MARS) |
| mFSpx/legal_authority_system | GitHub | mixed | BC/Canada legal-source engine |
| mfspx/doggystyle | GitLab | python | Ontological graph kernel ("State Machine of Spite" dashboard) |

## Migration tiers

- **Tier A (native):** Rust repos — implement the `Organelle` trait per capability crate, register with `organelle-host`, equivalence-tested across transports.
- **Tier B (surface-adapted):** Python/JS/mixed repos — `organelle-manifest.json` per capability unit + thin adapter over a host surface (unix-socket JSON-lines preferred; MCP or REST where it fits). Computation stays in its language; authority/receipts/kill go through the host.
- **Tier C (declared):** Docs/scratch repos — manifest only, valence Disproven/Candidate, no live registration. Scratch dirs excluded entirely.
- **Already organelles:** `organelles/` itself (substrate), `litebox-organelle-host` (host experiment), `organelle/factory` (to verify).
