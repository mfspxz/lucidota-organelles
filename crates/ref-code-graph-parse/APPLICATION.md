# org-038 ref-code-graph-parse — APPLICATION

Built 2026-11-23 under WO-09 (Wreck seek-and-install), from the
GAP-22 design report (`~/workspace/wasm-audit/estate-proof-2026-11-22/code-graph-parse.md`).
The design report reserved number org-037; that number was taken
by ref-payout-split in the interim, so the crate landed as
**org-038**, codon `cg`.

## What landed

- `enclosing_functions(source, ranges)` — drop-in replacement for
  wreck-graph's tree-sitter function: same signature, same
  semantics (sorted, deduplicated names; 1-indexed inclusive line
  spans; empty on unparseable source), implemented over `syn`
  spans. Covers free functions, impl methods and trait methods
  (all `function_item`s in the tree-sitter-rust grammar).
- `parse_files(ParseConfig, &[SourceFile]) -> CodeGraph` —
  symbols (functions, methods, structs, enums, traits, type
  aliases, consts, statics, modules) with org-033 `thing_id`
  content-hash ids, plus org-033 `Assertion` edges:
  CallGraph (`calls`, Proven only on exact-path resolution,
  Claimed for bare-name/method/external), Ownership
  (`implements_for` / `implements_trait:<path>` / `has_field_type`),
  DataFlow (`takes_type` / `returns_type`, signature-level only),
  and `imports` edges.
- `ParseConfig` has no `Default` and no serde defaults: layers,
  max file bytes, and the cross-file-resolution switch are all
  caller-supplied; empty layers or a zero cap fail construction.
- Organelle surface (feature `organelle`, default on): ops
  `enclosing_functions` and `parse`. Consumers that want only the
  pure parser use `default-features = false` (no host/manifest,
  no graph-store organelle deps enter their graph).

## Verification (2026-11-23, this build)

- `cargo test -p ref-code-graph-parse`: 4 unit + 4 acceptance,
  all pass. Acceptance parses the real fixture crate org-036
  ref-gtfs-rt-decode end to end: 10 named ground-truth symbols
  present, parser fn count within ±2 of an independent naive line
  scan, 6 hand-verified call edges present (decode_vehicles →
  parse_fields / parse_trip_descriptor / parse_vehicle_descriptor
  / parse_position; decode_trips → parse_fields; decode_alerts →
  parse_fields), output byte-identical across reversed input
  order, and wreck-graph's four structural cases reproduced.
- `cargo test -p ref-code-graph-parse --no-default-features`:
  pass (3 unit + 4 acceptance).
- `cargo check -p ref-code-graph-parse --target wasm32-unknown-unknown`:
  PASS — no C toolchain anywhere in the dependency graph.

## Adoption — wreck-graph (done, WO-09)

`wreck-graph/src/lib.rs`: the tree-sitter body of
`enclosing_functions` is replaced by a one-line delegation to
this crate; `tree-sitter`, `tree-sitter-rust` and
`streaming-iterator` are removed from `wreck-graph/Cargo.toml`.
Wreck's public API is unchanged. `wreck-adapters/src/local.rs`
and `wreck-demo/src/main.rs` only mention tree-sitter in
comments (verified by grep 2026-11-23) — they call wreck-graph's
helper, they carry no second copy.

## Limits (from the design, unchanged)

- Rust only in v1. JS/TS/GDScript are not parsed and not
  pretended at.
- CallGraph resolution is syntactic, not type-checked;
  trait-method dispatch is Claimed at best.
- DataFlow is signature-level (params / returns / fields), not
  intra-procedural.
- Macro bodies are token trees to `syn`; expanded code is
  invisible. Inner-fn calls roll up to the enclosing function.
