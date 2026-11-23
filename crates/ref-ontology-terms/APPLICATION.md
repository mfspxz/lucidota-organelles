# Applying `ref-ontology-terms` — the GO-50 term store (TOT)

Harvested by copy from the go-ontology treatment app
(`~/workspace/full-send/projects/go-ontology/app/src/lib.rs`,
703 lines, byte-identical, kept as `src/ontology.rs`). The project
tree keeps its own code; this crate is the composable organelle
form. `src/lib.rs` adds only re-exports and the organelle glue.

## What it is

The PALANTOUR federation's shared vocabulary as a Rust crate:

- **GO-50**: the 50 core terms (RECEIPT, LEDGER, CAS, ORACLE,
  GATE, …), each an `OntologyTerm` with a definition, one of 8
  `TermType`s (Object 14 / Event 2 / Edge 1 / Tool 10 / Mode 12 /
  Time 2 / Agent 6 / Shell 3), a parent hierarchy, and a default
  ternary valence.
- **`TernaryValence`**: the canonical -1/0/+1 type
  (Tainted/Candidate/Proven) the family's scattered valence enums
  are meant to converge on. The convergence is partly real
  already: pt-oracle's gate re-exports it as its `Valence`.
- **`OntologyStore`** trait over the store: `resolve`, `by_type`,
  `children`, `is_a` (transitive), `all_terms`;
  `InMemoryOntology` is the in-memory implementation, loadable
  from the bootstrap set or from JSON.

What the ontology does NOT contain: TRIPARTOKEN is a Tool-type
*term* in the vocabulary ("A three-lane tokenization system:
FASTLANE tokens, SLOWLANE tokens, DEEPLANE research tokens") —
there is no tokenization code, no token type, no lane-routing
logic anywhere in the source. The crate records the concept; it
does not implement it. The header's O-25 Object-Types and C-25
Client Functions are likewise marked UNIMPLEMENTED in the source.

## API

```toml
[dependencies]
ref-ontology-terms = {
  path = "<relative path>/organelles/crates/ref-ontology-terms",
  default-features = false, # term store only (serde/serde_json)
}
```

```rust
use ref_ontology_terms::{InMemoryOntology, OntologyStore, TernaryValence};

let store = InMemoryOntology::bootstrap_core();
assert_eq!(store.all_terms().len(), 50);
assert!(store.is_a("RECEIPT", "OBJECT"));
let valence = TernaryValence::from_int(1); // Proven
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `ot`, ops `resolve` / `is_a` / `count` over the
bootstrapped GO-50 store).

## Consumers

- **pt-oracle / ref-epistemic-gate**: the gate's valence type is
  this crate's `TernaryValence` (via `ref-epistemic-gate`, which
  depends on this crate with `default-features = false`).
- **Any pt-family crate** still carrying its own valence enum:
  adopting this crate deletes a divergent type, which is the
  convergence the source was written for.
- **Graph/ledger tooling** that needs term definitions, types, or
  hierarchy checks against the shared vocabulary.

## Adoption steps

1. Add the path dependency above.
2. Replace local valence enums with `TernaryValence`
   (`as_int`/`from_int` bridge to the -1/0/+1 wire form).
3. Load the store once (`bootstrap_core()` or
   `load_from_json(...)`) and pass `&dyn OntologyStore` where
   vocabulary questions are asked.
4. Treat the term set as data: extending the vocabulary means
   supplying a different JSON set, not forking the crate.
