//! org-038 — Reference organelle: code-graph-parse (codon `cg`).
//!
//! Rust source parsing to a code graph — the pure-Rust replacement
//! for the estate's tree-sitter surface (GAP-22 in the 2026-11-22
//! decomposition map). GAP-22's named consumer, wreck-graph, used
//! exactly one tree-sitter function — `enclosing_functions` — and
//! that single C build script (cc-rs, no clang on the estate box)
//! blocked six wreck crates on wasm32. This crate is `syn`-only:
//! no C toolchain anywhere in its graph, wasm32-clean by
//! construction.
//!
//! What v1 does, stated plainly:
//!
//! * **Symbols** (nodes): functions, methods (with their impl
//!   type), structs, enums, traits, type aliases, consts, statics,
//!   modules. Node ids are org-033 `thing_id`s — sha256 of the
//!   canonical JSON of `{kind, crate, module_path, name}` — never
//!   a process-local hash.
//! * **CallGraph edges**: caller → callee for call expressions.
//!   `Proven` only when the callee path resolves exactly to a
//!   symbol defined in the parsed input; `Claimed` when resolved
//!   by bare name only, for method calls (syntactic resolution),
//!   and for calls to symbols outside the parsed set (recorded
//!   against a declared `external` node).
//! * **Import edges**: file module → `use` path (literal).
//! * **Ownership edges**: impl block → type, type → field type,
//!   trait → implementor.
//! * **DataFlow edges** (bounded, honest subset): function →
//!   parameter types, function → return type. Full
//!   intra-procedural dataflow is OUT of scope, named here, not
//!   approximated.
//! * **`enclosing_functions` compatibility op**: same signature
//!   and semantics as wreck-graph's tree-sitter version (sorted,
//!   deduplicated names of functions whose 1-indexed line span
//!   intersects any changed range; empty on unparseable source).
//!   This is the drop-in that lets wreck-graph drop tree-sitter.
//!
//! Edges are emitted as org-033 [`Assertion`] values: parse-derived
//! structure is `Proven` with provenance naming the parser, file
//! and span; anything resolved by name alone is `Claimed`, never
//! silently Proven.
//!
//! Limits (stated, not faked):
//!
//! * v1 parses **Rust only**. No pure-Rust parser of estate
//!   quality for JS/TS or GDScript was available offline; those
//!   languages are not pretended at.
//! * CallGraph resolution is syntactic (syn-level), not
//!   type-checked. Trait-method dispatch is `Claimed` at best.
//!   No rustc internals, no MIR.
//! * Macro-expanded code is invisible beyond what `syn` sees in
//!   the invocation tokens; `macro_rules` bodies are token trees.

use ref_graph_store::{thing_id, Assertion, State, Term};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use syn::spanned::Spanned;

// ---------------------------------------------------------------------
// Config. No serde defaults, no Default impl: the caller supplies
// every knob (estate policy doctrine). Underspecified config fails
// to construct.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    CallGraph,
    DataFlow,
    Ownership,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseConfig {
    /// Which edge layers to emit. Must be non-empty.
    pub layers: BTreeSet<Layer>,
    /// Files larger than this are refused, not truncated.
    pub max_file_bytes: usize,
    /// Whether bare-name call resolution may cross file boundaries
    /// inside the parsed set. Exact-path resolution always applies.
    pub cross_file_resolution: bool,
}

impl ParseConfig {
    pub fn new(
        layers: BTreeSet<Layer>,
        max_file_bytes: usize,
        cross_file_resolution: bool,
    ) -> Result<Self, ParseError> {
        if layers.is_empty() {
            return Err(ParseError::Config(
                "layers must be non-empty; an empty layer set parses nothing".into(),
            ));
        }
        if max_file_bytes == 0 {
            return Err(ParseError::Config(
                "max_file_bytes must be positive".into(),
            ));
        }
        Ok(Self {
            layers,
            max_file_bytes,
            cross_file_resolution,
        })
    }

    fn has(&self, layer: Layer) -> bool {
        self.layers.contains(&layer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Config(String),
    TooLarge { path: String, bytes: usize, max: usize },
    Syntax { path: String, message: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Config(m) => write!(f, "config: {m}"),
            ParseError::TooLarge { path, bytes, max } => {
                write!(f, "{path}: {bytes} bytes exceeds max_file_bytes {max}")
            }
            ParseError::Syntax { path, message } => write!(f, "{path}: {message}"),
        }
    }
}
impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------
// Inputs and outputs.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub crate_name: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolNode {
    pub id: String,
    /// function | method | struct | enum | trait | type_alias |
    /// const | static | module | external
    pub kind: String,
    pub crate_name: String,
    pub module_path: String,
    pub name: String,
    /// crate::module::name (methods: crate::module::Type::name)
    pub qualified: String,
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodeGraph {
    pub nodes: Vec<SymbolNode>,
    pub assertions: Vec<Assertion>,
}

fn node_id(kind: &str, crate_name: &str, module_path: &str, name: &str) -> String {
    thing_id(&serde_json::json!({
        "kind": kind,
        "crate": crate_name,
        "module_path": module_path,
        "name": name,
    }))
}

fn type_text(ty: &syn::Type) -> String {
    quote::ToTokens::to_token_stream(ty).to_string()
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

// ---------------------------------------------------------------------
// enclosing_functions — the wreck-graph compatibility op.
// ---------------------------------------------------------------------

struct FnSpan {
    name: String,
    start: u32,
    end: u32,
}

fn collect_fn_spans(items: &[syn::Item], out: &mut Vec<FnSpan>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.push(FnSpan {
                name: f.sig.ident.to_string(),
                start: f.sig.fn_token.span().start().line as u32,
                end: f.block.span().end().line as u32,
            }),
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_fn_spans(items, out);
                }
            }
            syn::Item::Impl(imp) => {
                for it in &imp.items {
                    if let syn::ImplItem::Fn(m) = it {
                        out.push(FnSpan {
                            name: m.sig.ident.to_string(),
                            start: m.sig.fn_token.span().start().line as u32,
                            end: m.block.span().end().line as u32,
                        });
                    }
                }
            }
            syn::Item::Trait(t) => {
                for it in &t.items {
                    if let syn::TraitItem::Fn(m) = it {
                        let end = m
                            .default
                            .as_ref()
                            .map(|b| b.span().end().line as u32)
                            .unwrap_or_else(|| m.sig.fn_token.span().end().line as u32);
                        out.push(FnSpan {
                            name: m.sig.ident.to_string(),
                            start: m.sig.fn_token.span().start().line as u32,
                            end,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Names of functions whose 1-indexed line span intersects any
/// changed range — sorted, deduplicated, empty on unparseable
/// source. Semantics identical to wreck-graph's tree-sitter
/// original (which matched free functions, impl methods and trait
/// methods alike, all being `function_item`s in the Rust grammar).
pub fn enclosing_functions(source: &str, ranges: &[(u32, u32)]) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    let mut spans = vec![];
    collect_fn_spans(&file.items, &mut spans);
    let mut out: Vec<String> = spans
        .iter()
        .filter(|s| ranges.iter().any(|(a, b)| *a <= s.end && s.start <= *b))
        .map(|s| s.name.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------
// The parser.
// ---------------------------------------------------------------------

struct FileSymbols {
    nodes: Vec<SymbolNode>,
    /// qualified path -> node id
    by_qualified: BTreeMap<String, String>,
    /// bare name -> node ids (functions/methods only)
    fn_by_name: BTreeMap<String, Vec<String>>,
    fn_types: Vec<FnTypes>,
    impl_edges: Vec<(String, String, String, u32)>, // from_id, predicate, object literal, line
    field_edges: Vec<(String, String, u32)>,        // from_id, type text, line
    imports: Vec<(String, u32)>,                    // use path, line
    calls: Vec<CallSite>,
}

struct FnTypes {
    node_id: String,
    params: Vec<String>,
    ret: Option<String>,
    line: u32,
}

struct CallSite {
    caller_id: String,
    /// Full path text for ExprCall; bare method name for method calls.
    callee_path: String,
    callee_name: String,
    is_method: bool,
    file: String,
    line: u32,
}

struct Collector<'a> {
    cfg: &'a ParseConfig,
    file: &'a SourceFile,
    module_stack: Vec<String>,
    out: FileSymbols,
}

impl<'a> Collector<'a> {
    fn module_path(&self) -> String {
        self.module_stack.join("::")
    }

    fn add_node(
        &mut self,
        kind: &str,
        name: &str,
        owner: Option<&str>,
        start: u32,
        end: u32,
    ) -> String {
        let mp = self.module_path();
        // qualified = crate [:: module_path] [:: owner] :: name
        let mut parts: Vec<&str> = vec![self.file.crate_name.as_str()];
        if !mp.is_empty() {
            parts.push(&mp);
        }
        if let Some(o) = owner {
            parts.push(o);
        }
        parts.push(name);
        let qualified = parts.join("::");
        let id = node_id(kind, &self.file.crate_name, &mp, &qualified);
        let node = SymbolNode {
            id: id.clone(),
            kind: kind.to_string(),
            crate_name: self.file.crate_name.clone(),
            module_path: mp,
            name: name.to_string(),
            qualified: qualified.clone(),
            file: self.file.path.clone(),
            start_line: start,
            end_line: end,
        };
        self.out.by_qualified.insert(qualified, id.clone());
        if kind == "function" || kind == "method" {
            self.out
                .fn_by_name
                .entry(name.to_string())
                .or_default()
                .push(id.clone());
        }
        self.out.nodes.push(node);
        id
    }

    fn fn_types(&mut self, node_id: String, sig: &syn::Signature, line: u32) {
        let mut params = vec![];
        for arg in &sig.inputs {
            if let syn::FnArg::Typed(p) = arg {
                params.push(type_text(&p.ty));
            }
        }
        let ret = match &sig.output {
            syn::ReturnType::Type(_, ty) => Some(type_text(ty)),
            syn::ReturnType::Default => None,
        };
        self.out.fn_types.push(FnTypes {
            node_id,
            params,
            ret,
            line,
        });
    }

    fn walk_items(&mut self, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Fn(f) => {
                    let line = f.sig.fn_token.span().start().line as u32;
                    let id = self.add_node(
                        "function",
                        &f.sig.ident.to_string(),
                        None,
                        line,
                        f.block.span().end().line as u32,
                    );
                    self.fn_types(id.clone(), &f.sig, line);
                    if self.cfg.has(Layer::CallGraph) {
                        let mut v = CallVisitor {
                            caller_id: id,
                            file: self.file.path.clone(),
                            calls: vec![],
                        };
                        syn::visit::Visit::visit_block(&mut v, &f.block);
                        self.out.calls.extend(v.calls);
                    }
                }
                syn::Item::Struct(s) => {
                    let id = self.add_node(
                        "struct",
                        &s.ident.to_string(),
                        None,
                        s.ident.span().start().line as u32,
                        s.ident.span().end().line as u32,
                    );
                    if self.cfg.has(Layer::Ownership) {
                        for field in s.fields.iter() {
                            self.out.field_edges.push((
                                id.clone(),
                                type_text(&field.ty),
                                field.ty.span().start().line as u32,
                            ));
                        }
                    }
                }
                syn::Item::Enum(e) => {
                    self.add_node(
                        "enum",
                        &e.ident.to_string(),
                        None,
                        e.ident.span().start().line as u32,
                        e.ident.span().end().line as u32,
                    );
                }
                syn::Item::Trait(t) => {
                    let tname = t.ident.to_string();
                    self.add_node(
                        "trait",
                        &tname,
                        None,
                        t.ident.span().start().line as u32,
                        t.ident.span().end().line as u32,
                    );
                    for it in &t.items {
                        if let syn::TraitItem::Fn(m) = it {
                            let line = m.sig.fn_token.span().start().line as u32;
                            let id = self.add_node(
                                "method",
                                &m.sig.ident.to_string(),
                                Some(&tname),
                                line,
                                m.sig.fn_token.span().end().line as u32,
                            );
                            self.fn_types(id, &m.sig, line);
                        }
                    }
                }
                syn::Item::Type(t) => {
                    self.add_node(
                        "type_alias",
                        &t.ident.to_string(),
                        None,
                        t.ident.span().start().line as u32,
                        t.ident.span().end().line as u32,
                    );
                }
                syn::Item::Const(c) => {
                    self.add_node(
                        "const",
                        &c.ident.to_string(),
                        None,
                        c.ident.span().start().line as u32,
                        c.ident.span().end().line as u32,
                    );
                }
                syn::Item::Static(s) => {
                    self.add_node(
                        "static",
                        &s.ident.to_string(),
                        None,
                        s.ident.span().start().line as u32,
                        s.ident.span().end().line as u32,
                    );
                }
                syn::Item::Mod(m) => {
                    let mname = m.ident.to_string();
                    self.add_node(
                        "module",
                        &mname,
                        None,
                        m.ident.span().start().line as u32,
                        m.ident.span().end().line as u32,
                    );
                    if let Some((_, items)) = &m.content {
                        self.module_stack.push(mname);
                        self.walk_items(items);
                        self.module_stack.pop();
                    }
                }
                syn::Item::Impl(imp) => {
                    let self_ty = type_text(&imp.self_ty);
                    let owner = self_ty
                        .split(['<', ' ', '&'])
                        .next_back()
                        .unwrap_or(&self_ty)
                        .trim()
                        .to_string();
                    let trait_path = imp.trait_.as_ref().map(|(_, p, _)| path_text(p));
                    for it in &imp.items {
                        if let syn::ImplItem::Fn(m) = it {
                            let line = m.sig.fn_token.span().start().line as u32;
                            let id = self.add_node(
                                "method",
                                &m.sig.ident.to_string(),
                                Some(&owner),
                                line,
                                m.block.span().end().line as u32,
                            );
                            self.fn_types(id.clone(), &m.sig, line);
                            if self.cfg.has(Layer::Ownership) {
                                let pred = match &trait_path {
                                    Some(tp) => format!("implements_trait:{tp}"),
                                    None => "implements_for".to_string(),
                                };
                                self.out.impl_edges.push((
                                    id.clone(),
                                    pred,
                                    self_ty.clone(),
                                    line,
                                ));
                            }
                            if self.cfg.has(Layer::CallGraph) {
                                let mut v = CallVisitor {
                                    caller_id: id,
                                    file: self.file.path.clone(),
                                    calls: vec![],
                                };
                                syn::visit::Visit::visit_block(&mut v, &m.block);
                                self.out.calls.extend(v.calls);
                            }
                        }
                    }
                }
                syn::Item::Use(u) => {
                    let mut paths = vec![];
                    flatten_use(&u.tree, String::new(), &mut paths);
                    for p in paths {
                        self.out
                            .imports
                            .push((p, u.use_token.span().start().line as u32));
                    }
                }
                _ => {}
            }
        }
    }
}

fn flatten_use(tree: &syn::UseTree, prefix: String, out: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(p) => {
            let pre = if prefix.is_empty() {
                p.ident.to_string()
            } else {
                format!("{prefix}::{}", p.ident)
            };
            flatten_use(&p.tree, pre, out);
        }
        syn::UseTree::Name(n) => {
            out.push(if prefix.is_empty() {
                n.ident.to_string()
            } else {
                format!("{prefix}::{}", n.ident)
            });
        }
        syn::UseTree::Rename(r) => {
            out.push(if prefix.is_empty() {
                r.ident.to_string()
            } else {
                format!("{prefix}::{}", r.ident)
            });
        }
        syn::UseTree::Glob(_) => out.push(format!("{prefix}::*")),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix.clone(), out);
            }
        }
    }
}

struct CallVisitor {
    caller_id: String,
    file: String,
    calls: Vec<CallSite>,
}

impl<'ast> syn::visit::Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let text = path_text(&p.path);
            let name = p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            self.calls.push(CallSite {
                caller_id: self.caller_id.clone(),
                callee_path: text,
                callee_name: name,
                is_method: false,
                file: self.file.clone(),
                line: p.path.span().start().line as u32,
            });
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.calls.push(CallSite {
            caller_id: self.caller_id.clone(),
            callee_path: node.method.to_string(),
            callee_name: node.method.to_string(),
            is_method: true,
            file: self.file.clone(),
            line: node.method.span().start().line as u32,
        });
        syn::visit::visit_expr_method_call(self, node);
    }

    // Items inside a body are not top-level items, so their calls
    // cannot be attributed to them by the item walk; attribute
    // inner-fn calls to the enclosing function instead of recursing
    // here (the visit of the outer body already covers the tokens).
    // Stated limit: inner-fn calls roll up to the outer function.
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        syn::visit::visit_block(self, &node.block);
    }
}

/// Parse a set of Rust source files into a code graph.
pub fn parse_files(cfg: &ParseConfig, files: &[SourceFile]) -> Result<CodeGraph, ParseError> {
    let mut all_nodes: Vec<SymbolNode> = vec![];
    let mut assertions: Vec<Assertion> = vec![];
    let mut by_qualified: BTreeMap<String, String> = BTreeMap::new();
    let mut fn_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut per_file: Vec<(usize, FileSymbols)> = vec![];

    for (idx, file) in files.iter().enumerate() {
        if file.source.len() > cfg.max_file_bytes {
            return Err(ParseError::TooLarge {
                path: file.path.clone(),
                bytes: file.source.len(),
                max: cfg.max_file_bytes,
            });
        }
        let parsed = syn::parse_file(&file.source).map_err(|e| ParseError::Syntax {
            path: file.path.clone(),
            message: e.to_string(),
        })?;
        let mut col = Collector {
            cfg,
            file,
            module_stack: vec![],
            out: FileSymbols {
                nodes: vec![],
                by_qualified: BTreeMap::new(),
                fn_by_name: BTreeMap::new(),
                fn_types: vec![],
                impl_edges: vec![],
                field_edges: vec![],
                imports: vec![],
                calls: vec![],
            },
        };
        col.walk_items(&parsed.items);
        for (q, id) in &col.out.by_qualified {
            by_qualified.insert(q.clone(), id.clone());
        }
        for (n, ids) in &col.out.fn_by_name {
            fn_by_name.entry(n.clone()).or_default().extend(ids.clone());
        }
        per_file.push((idx, col.out));
    }

    let prov = |file: &str, line: u32| format!("ref-code-graph-parse/1 file={file} line={line}");
    let push = |assertions: &mut Vec<Assertion>,
                subj: String,
                pred: &str,
                obj: Term,
                state: State,
                provenance: String| {
        if let Ok(a) = Assertion::new(
            Term::node(subj),
            pred.to_string(),
            obj,
            state,
            provenance,
            None,
            None,
        ) {
            assertions.push(a);
        }
    };

    for (idx, fs) in &per_file {
        let file = &files[*idx];
        all_nodes.extend(fs.nodes.iter().cloned());

        // Import edges (structural, always emitted).
        let file_mod_id = node_id("module", &file.crate_name, "", &file.crate_name);
        for (path, line) in &fs.imports {
            push(
                &mut assertions,
                file_mod_id.clone(),
                "imports",
                Term::literal(serde_json::json!(path)),
                State::Proven,
                prov(&file.path, *line),
            );
        }
        if cfg.has(Layer::DataFlow) {
            for ft in &fs.fn_types {
                for p in &ft.params {
                    push(
                        &mut assertions,
                        ft.node_id.clone(),
                        "takes_type",
                        Term::literal(serde_json::json!(p)),
                        State::Proven,
                        prov(&file.path, ft.line),
                    );
                }
                if let Some(r) = &ft.ret {
                    push(
                        &mut assertions,
                        ft.node_id.clone(),
                        "returns_type",
                        Term::literal(serde_json::json!(r)),
                        State::Proven,
                        prov(&file.path, ft.line),
                    );
                }
            }
        }
        if cfg.has(Layer::Ownership) {
            for (from, pred, obj, line) in &fs.impl_edges {
                push(
                    &mut assertions,
                    from.clone(),
                    pred,
                    Term::literal(serde_json::json!(obj)),
                    State::Proven,
                    prov(&file.path, *line),
                );
            }
            for (from, ty, line) in &fs.field_edges {
                push(
                    &mut assertions,
                    from.clone(),
                    "has_field_type",
                    Term::literal(serde_json::json!(ty)),
                    State::Proven,
                    prov(&file.path, *line),
                );
            }
        }
        if cfg.has(Layer::CallGraph) {
            for call in &fs.calls {
                // Exact-path resolution: the path as written, or
                // with the crate prefix made explicit.
                let mut resolved: Option<(String, State)> = None;
                if !call.is_method {
                    let candidates = [
                        call.callee_path.clone(),
                        format!("{}::{}", file.crate_name, call.callee_path),
                    ];
                    for cand in &candidates {
                        if let Some(id) = by_qualified.get(cand) {
                            resolved = Some((id.clone(), State::Proven));
                            break;
                        }
                    }
                }
                if resolved.is_none() {
                    // Bare-name resolution: same file first, then
                    // the parsed set if the caller allows it.
                    let same_file: Vec<String> = fs
                        .fn_by_name
                        .get(&call.callee_name)
                        .cloned()
                        .unwrap_or_default();
                    let pool: Vec<String> = if !same_file.is_empty() {
                        same_file
                    } else if cfg.cross_file_resolution {
                        fn_by_name
                            .get(&call.callee_name)
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        vec![]
                    };
                    if pool.len() == 1 {
                        resolved = Some((pool[0].clone(), State::Claimed));
                    }
                }
                let (obj, state) = match resolved {
                    Some((id, st)) => (id, st),
                    None => {
                        // External / unresolved: declared external node.
                        let ext_id = node_id("external", &file.crate_name, "", &call.callee_name);
                        if !all_nodes.iter().any(|n| n.id == ext_id) {
                            all_nodes.push(SymbolNode {
                                id: ext_id.clone(),
                                kind: "external".to_string(),
                                crate_name: file.crate_name.clone(),
                                module_path: String::new(),
                                name: call.callee_name.clone(),
                                qualified: call.callee_name.clone(),
                                file: String::new(),
                                start_line: 0,
                                end_line: 0,
                            });
                        }
                        (ext_id, State::Claimed)
                    }
                };
                push(
                    &mut assertions,
                    call.caller_id.clone(),
                    "calls",
                    Term::node(obj),
                    state,
                    prov(&call.file, call.line),
                );
            }
        }
    }

    all_nodes.sort_by(|a, b| a.id.cmp(&b.id));
    all_nodes.dedup_by(|a, b| a.id == b.id);
    assertions.sort_by(|a, b| a.id.cmp(&b.id));
    assertions.dedup_by(|a, b| a.id == b.id);
    Ok(CodeGraph {
        nodes: all_nodes,
        assertions,
    })
}

// ---------------------------------------------------------------------
// Organelle surface.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
#[cfg(feature = "organelle")]
use std::sync::Arc;

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "code-graph-parse".to_string(),
        codon: "cg".to_string(),
        version: "1.0.0".to_string(),
        description: "Rust source parsing to a code graph (syn-based, tree-sitter replacement)"
            .to_string(),
        contracts: vec![
            Contract {
                op: "enclosing_functions".to_string(),
                description: "names of functions whose line span intersects the given ranges"
                    .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["source", "ranges"],
                    "properties": {
                        "source": {"type": "string"},
                        "ranges": {"type": "array", "items": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2}}
                    }
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "parse".to_string(),
                description: "parse Rust source files into symbol nodes + org-033 assertions"
                    .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["config", "files"],
                    "properties": {
                        "config": {"type": "object", "required": ["layers", "max_file_bytes", "cross_file_resolution"]},
                        "files": {"type": "array", "items": {"type": "object", "required": ["path", "crate_name", "source"]}}
                    }
                }),
                mutation_class: None,
                required_capability: None,
            },
        ],
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

#[cfg(feature = "organelle")]
pub struct CodeGraphParse {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(CodeGraphParse {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
impl Organelle for CodeGraphParse {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OrganelleError> {
        match op {
            "enclosing_functions" => {
                let source = input["source"].as_str().unwrap_or("");
                let mut ranges = vec![];
                if let Some(rs) = input["ranges"].as_array() {
                    for r in rs {
                        if let (Some(a), Some(b)) = (
                            r[0].as_u64().map(|x| x as u32),
                            r[1].as_u64().map(|x| x as u32),
                        ) {
                            ranges.push((a, b));
                        }
                    }
                }
                Ok(serde_json::json!({"functions": enclosing_functions(source, &ranges)}))
            }
            "parse" => {
                let cfg: ParseConfig = serde_json::from_value(input["config"].clone())
                    .map_err(|e| OrganelleError::failed(format!("config: {e}")))?;
                let cfg =
                    ParseConfig::new(cfg.layers, cfg.max_file_bytes, cfg.cross_file_resolution)
                        .map_err(|e| OrganelleError::failed(e.to_string()))?;
                let files: Vec<SourceFile> = serde_json::from_value(input["files"].clone())
                    .map_err(|e| OrganelleError::failed(format!("files: {e}")))?;
                let graph = parse_files(&cfg, &files)
                    .map_err(|e| OrganelleError::failed(e.to_string()))?;
                serde_json::to_value(&graph)
                    .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ParseConfig {
        ParseConfig::new(
            [Layer::CallGraph, Layer::DataFlow, Layer::Ownership]
                .into_iter()
                .collect(),
            1_000_000,
            true,
        )
        .unwrap()
    }

    #[test]
    fn config_has_no_default_and_rejects_empty() {
        assert!(ParseConfig::new(BTreeSet::new(), 10, true).is_err());
        assert!(ParseConfig::new([Layer::CallGraph].into_iter().collect(), 0, true).is_err());
    }

    #[test]
    fn enclosing_matches_wreck_semantics() {
        const SRC: &str = "fn alpha() {\n    let x = 1;\n}\n\nfn beta() {\n    let y = 2;\n}\n\nfn gamma() {\n    let z = 3;\n}\n";
        assert_eq!(enclosing_functions(SRC, &[(5, 7)]), vec!["beta"]);
        assert_eq!(
            enclosing_functions(SRC, &[(1, 3), (9, 11)]),
            vec!["alpha", "gamma"]
        );
        assert!(enclosing_functions(SRC, &[(4, 4)]).is_empty());
        assert!(enclosing_functions("fn broken((", &[(1, 1)]).is_empty());
    }

    #[test]
    fn parse_small_graph() {
        let src = r#"
use std::collections::BTreeMap;

pub struct Point { pub x: i32 }

fn helper(p: Point) -> i32 { p.x }

pub fn compute(p: Point) -> i32 {
    let v = helper(p);
    unknown_external(v)
}
"#;
        let files = vec![SourceFile {
            path: "src/lib.rs".into(),
            crate_name: "demo".into(),
            source: src.into(),
        }];
        let g = parse_files(&cfg(), &files).unwrap();
        let names: Vec<&str> = g.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"compute"), "{names:?}");
        assert!(names.contains(&"helper"), "{names:?}");
        assert!(names.contains(&"Point"), "{names:?}");
        let compute = g.nodes.iter().find(|n| n.name == "compute").unwrap();
        let helper = g.nodes.iter().find(|n| n.name == "helper").unwrap();
        assert!(
            g.assertions.iter().any(|a| a.predicate == "calls"
                && a.subject.as_node() == Some(compute.id.as_str())
                && a.object.as_node() == Some(helper.id.as_str())),
            "missing compute->helper call edge"
        );
        assert!(g
            .nodes
            .iter()
            .any(|n| n.kind == "external" && n.name == "unknown_external"));
        assert!(g.assertions.iter().any(|a| a.predicate == "takes_type"
            && a.subject.as_node() == Some(compute.id.as_str())));
        let g2 = parse_files(&cfg(), &files).unwrap();
        assert_eq!(
            serde_json::to_string(&g).unwrap(),
            serde_json::to_string(&g2).unwrap()
        );
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
