//! Integration tests for the harvested engine, exercising the pure
//! API the way the Regulator Router binary does: templates on disk,
//! rendered against a Value context.

use ref_template_engine::render::Renderer;
use ref_template_engine::Value;
use std::fs;
use std::path::PathBuf;

fn scratch(name: &str, templates: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ref-template-engine-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (file, body) in templates {
        fs::write(dir.join(file), body).unwrap();
    }
    dir
}

fn ctx() -> Value {
    Value::map(vec![
        ("name".into(), Value::str("Zack")),
        (
            "items".into(),
            Value::List(vec![Value::str("a"), Value::str("b"), Value::str("c")]),
        ),
        ("count".into(), Value::Int(3)),
    ])
}

#[test]
fn output_if_and_filters() {
    let dir = scratch(
        "basic",
        &[(
            "t.j2",
            "Hello {{ name | upper }}!{% if count > 2 %} many{% else %} few{% endif %}: {{ items | join(', ') }} ({{ items | length }})",
        )],
    );
    let mut r = Renderer::new(&dir);
    let out = r.render("t.j2", ctx()).unwrap();
    assert_eq!(out, "Hello ZACK! many: a, b, c (3)");
}

#[test]
fn for_loop_with_loop_vars() {
    let dir = scratch(
        "loop",
        &[(
            "t.j2",
            "{% for x in items %}{{ loop.index }}={{ x }};{% endfor %}",
        )],
    );
    let mut r = Renderer::new(&dir);
    let out = r.render("t.j2", ctx()).unwrap();
    assert_eq!(out, "1=a;2=b;3=c;");
}

#[test]
fn undefined_renders_empty_and_falsy() {
    let dir = scratch(
        "undef",
        &[(
            "t.j2",
            "[{{ missing }}]{% if missing %}Y{% else %}N{% endif %}",
        )],
    );
    let mut r = Renderer::new(&dir);
    let out = r.render("t.j2", ctx()).unwrap();
    assert_eq!(out, "[]N");
}

#[test]
fn macro_and_import() {
    let dir = scratch(
        "macro",
        &[
            ("macros.j2", "{% macro hi(n) %}Hi {{ n }}!{% endmacro %}"),
            ("t.j2", "{% from \"macros.j2\" import hi %}{{ hi(name) }}"),
        ],
    );
    let mut r = Renderer::new(&dir);
    let out = r.render("t.j2", ctx()).unwrap();
    assert_eq!(out, "Hi Zack!");
}
