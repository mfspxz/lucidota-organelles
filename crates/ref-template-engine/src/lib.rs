//! Reference organelle: template-engine (codon `tj`).
//!
//! A Jinja2-subset template engine, harvested BY COPY from the
//! Regulator Router treatment app
//! (`~/workspace/full-send/projects/regulator-router/app/src/`:
//! `engine.rs` + `render.rs` + `value.rs`, byte-identical copies).
//! It renders the recovered Regulator Router templates byte-for-byte
//! unmodified: `{{ expr }}` output, `{# comments #}`, whitespace
//! control, `{% if/elif/else %}`, `{% for %}` (tuple unpacking,
//! `loop.*`), `{% set %}` (incl. `namespace()`), `{% macro %}`,
//! `{% from "…" import … %}`, and the filter surface the templates
//! use. Undefined names behave like Jinja's default `Undefined`:
//! empty output, falsy, attribute access stays undefined.
//!
//! The pure API is [`render::Renderer`] over [`value::Value`]:
//!
//! ```rust,ignore
//! let mut r = ref_template_engine::render::Renderer::new(dir.as_ref());
//! let out = r.render("letter.md.j2", context_value)?;
//! ```
//!
//! Everything below the module declarations is organelle glue
//! (manifest + trait surface + JSON↔Value conversion), written for
//! this crate; it is not harvested code.

pub mod engine;
pub mod render;
pub mod value;

pub use render::Renderer;
pub use value::Value;

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
    use super::{Renderer, Value};
    use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
    use organelle_manifest::{
        Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
        MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
    };
    use serde_json::Value as Json;
    use std::path::Path;
    use std::sync::Arc;

    fn manifest() -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "template-engine".to_string(),
            codon: "tj".to_string(),
            version: "1.0.0".to_string(),
            description: "Jinja2-subset template engine (Regulator Router harvest)".to_string(),
            contracts: vec![Contract {
                op: "render".to_string(),
                description: "render a template file from templates_dir against a JSON context"
                    .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["templates_dir", "template", "context"],
                    "properties": {
                        "templates_dir": {"type": "string"},
                        "template": {"type": "string"},
                        "context": {"type": "object"}
                    }
                }),
                mutation_class: None,
                required_capability: None,
            }],
            authority: Authority {
                mutation_class: MutationClass::ReadOnly,
                declared_valence: Valence::Proven,
                required_capability: None,
                granted_capabilities: vec![],
            },
            transports: Transport::all().to_vec(),
            receipt_policy: ReceiptPolicy {
                content_addressed: true,
                algorithm: RECEIPT_ALGORITHM.to_string(),
                chain: true,
            },
        }
    }

    pub struct TemplateEngine {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(TemplateEngine {
            manifest: manifest(),
        })
    }

    /// JSON → engine Value (the engine's dynamic model has no serde;
    /// this conversion is the glue's one job).
    fn to_value(j: &Json) -> Value {
        match j {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else {
                    Value::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            Json::String(s) => Value::Str(s.clone()),
            Json::Array(items) => Value::List(items.iter().map(to_value).collect()),
            Json::Object(map) => {
                Value::Map(map.iter().map(|(k, v)| (k.clone(), to_value(v))).collect())
            }
        }
    }

    impl Organelle for TemplateEngine {
        fn manifest(&self) -> OrganelleManifest {
            self.manifest.clone()
        }

        fn handle(
            &self,
            _ctx: &CallContext,
            _host: &dyn HostRef,
            op: &str,
            input: Json,
        ) -> Result<Json, OrganelleError> {
            match op {
                "render" => {
                    let dir = input["templates_dir"].as_str().unwrap_or("");
                    let template = input["template"].as_str().unwrap_or("");
                    let context = to_value(&input["context"]);
                    let mut renderer = Renderer::new(Path::new(dir));
                    let rendered = renderer
                        .render(template, context)
                        .map_err(OrganelleError::failed)?;
                    Ok(serde_json::json!({"rendered": rendered}))
                }
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
