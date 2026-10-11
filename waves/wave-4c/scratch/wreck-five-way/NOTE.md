# wreck five-way decomposition — SUPERSEDED (archived 2026-10-10, wave-4c)

During wave-4c I built a five-organelle decomposition of wreck (one organelle
per crate: wreck-claim/wl, wreck-conflict/wg, wreck-decide/wd, wreck-canon/wc,
wreck-substrate/wx) before discovering wave-4a's in-flight work: a
`wreck-organelles` crate with TWO organelles (wreck-govern/wg, wreck-ports/wp)
following the codebase's own seam ("the governor core never touches a
network").

Per the wave-4c task instruction ("build on [wave-4a's] uncommitted files
rather than redoing"), the five-way approach was retired:

- wave-4a's two-organelle design is the better map of the actual capabilities:
  protocol + graph + governor + canon form ONE indivisible decision pipeline
  (claim -> view -> policy -> sealed verdict); splitting them across four
  organelles would force callers to orchestrate four units for one decision
  (the ledger-graph pilot's "indivisible core" argument).
- Keeping both designs would collide on codon `wg` and ship two competing
  organelle sets in one repo.

These files are preserved here (archive-don't-delete), not deleted. They
compiled and their per-crate tests passed at retirement time; they were simply
the wrong decomposition. Do not reintroduce without reconciling codons.
