# Applying `ref-template-engine` — the Regulator Router template engine (TRJ)

Harvested by copy from the Regulator Router treatment app
(`~/workspace/full-send/projects/regulator-router/app/src/`):
`engine.rs` (940 lines, the Jinja2-subset parser), `render.rs`
(607 lines, the evaluator + filesystem template loader) and
`value.rs` (182 lines, the dynamic value model) are byte-identical
copies. The project tree keeps its own code; this crate is the
composable organelle form of the same engine. `src/lib.rs` adds
only the organelle glue (manifest, trait surface, JSON↔Value
conversion).

## What it is

A Jinja2-subset template engine written to render the recovered
Regulator Router templates byte-for-byte unmodified, matching the
original Python Jinja2 configuration (`trim_blocks=True`,
`lstrip_blocks=True`, `keep_trailing_newline=True`,
`autoescape=False`):

- `{{ expr }}` output, `{# comments #}`, whitespace control
  (`{{-`, `-%}`…)
- `{% if/elif/else %}`, `{% for %}` (tuple unpacking, `loop.*`),
  `{% set %}` (incl. `namespace()` attribute assignment),
  `{% macro %}`, `{% from "…" import … %}`
- expressions: attribute/index/slice access, method calls (`.get`,
  `.items`, `.replace`, `.strip`), dict/list literals, ternary,
  `and/or/not`, comparisons, `in`, `is defined`, `~` concatenation,
  arithmetic, filters (`length`, `join`, `replace`, `upper`,
  `lower`, `title`, `default`, `trim`)
- Undefined names/keys behave like Jinja's default `Undefined`:
  empty output, falsy, attribute access stays undefined.

The engine core is std-only — no serde, no host deps — with
`default-features = false`.

## API

```toml
[dependencies]
ref-template-engine = {
  path = "<relative path>/organelles/crates/ref-template-engine",
  default-features = false, # pure engine only: std-only
}
```

```rust
use ref_template_engine::{Renderer, Value};

let mut renderer = Renderer::new(templates_dir.as_ref());
let context = Value::map(vec![
    ("name".into(), Value::str("Zack")),
    ("items".into(), Value::List(vec![Value::str("a")])),
]);
let out = renderer.render("letter.md.j2", context)?;
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `tj`, op `render` with input
`{"templates_dir": "…", "template": "…", "context": {…}}`, output
`{"rendered": "…"}`; the glue converts the JSON context into the
engine's `Value` model).

## Consumers

- **Regulator Router** is the origin and the proven consumer: its
  binary renders the 33 recovered regulator templates (RTB, Law
  Society, BCFSA, …) through this exact code today. Adopting the
  organelle there is a dependency swap, not a rewrite: the app's
  `engine`/`render`/`value` modules are the same files.
- Any estate tool that renders documents from templates —
  complaint packets, dossier assembly, manual generation — gets a
  deterministic, offline, dependency-free engine instead of a
  Python Jinja2 runtime dependency.

## Adoption steps

1. Add the path dependency above (pure form first).
2. Build your context as `Value` (or, via the organelle surface,
   as JSON — the glue converts).
3. Point `Renderer::new` at the template directory; templates are
   loaded and parsed on first use and cached per `Renderer`.
4. Pin behaviour with golden renders: the recovered templates'
   byte-exactness was the design constraint, so a consumer's
   templates deserve the same treatment — render fixtures in tests
   (see `tests/render.rs` for the shape).

## What this crate deliberately does not do

No JSON parsing, no SHA-256, no lint, no packet model — the
Regulator Router app also has `json.rs`, `sha256.rs`, `lint.rs`,
`model.rs`, `plugins.rs`, `extract.rs`; those are separate pieces
with separate consumers and were not part of this harvest. The
engine renders templates; composing documents is the caller's job.
