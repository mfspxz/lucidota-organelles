//! Template rendering: evaluates the AST produced by `engine.rs` against a
//! context, with Jinja-compatible semantics for the recovered templates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::engine::{parse_template, BinOp, Expr, MacroTable, Node, UnOp};
use crate::value::Value;

pub struct Renderer {
    templates_dir: PathBuf,
    parsed: HashMap<String, Rc<Vec<Node>>>,
    macro_tables: HashMap<String, Rc<MacroTable>>,
}

type Frame = HashMap<String, Value>;

struct Ctx {
    frames: Vec<Frame>,
    /// Macro bindings visible at the current point: name -> (home template, def)
    macros: HashMap<String, (String, Vec<String>, Vec<Node>)>,
}

impl Renderer {
    pub fn new(templates_dir: &Path) -> Renderer {
        Renderer {
            templates_dir: templates_dir.to_path_buf(),
            parsed: HashMap::new(),
            macro_tables: HashMap::new(),
        }
    }

    fn load(&mut self, rel_path: &str) -> Result<Rc<Vec<Node>>, String> {
        if let Some(n) = self.parsed.get(rel_path) {
            return Ok(n.clone());
        }
        let full = self.templates_dir.join(rel_path);
        let src = std::fs::read_to_string(&full)
            .map_err(|e| format!("cannot read template {}: {}", rel_path, e))?;
        let nodes = parse_template(&src).map_err(|e| format!("template {}: {}", rel_path, e))?;
        let rc = Rc::new(nodes);
        self.parsed.insert(rel_path.to_string(), rc.clone());
        Ok(rc)
    }

    fn macro_table(&mut self, rel_path: &str) -> Result<Rc<MacroTable>, String> {
        if let Some(t) = self.macro_tables.get(rel_path) {
            return Ok(t.clone());
        }
        let nodes = self.load(rel_path)?;
        let mut table = MacroTable::new();
        for n in nodes.iter() {
            if let Node::MacroDef { name, params, body } = n {
                table.insert(name.clone(), (params.clone(), body.clone()));
            }
        }
        let rc = Rc::new(table);
        self.macro_tables.insert(rel_path.to_string(), rc.clone());
        Ok(rc)
    }

    pub fn render(&mut self, rel_path: &str, context: Value) -> Result<String, String> {
        let nodes = self.load(rel_path)?;
        let mut frame = Frame::new();
        if let Value::Map(pairs) = context {
            for (k, v) in pairs {
                frame.insert(k, v);
            }
        }
        let mut ctx = Ctx { frames: vec![frame], macros: HashMap::new() };
        // Bind this template's own macros.
        let table = self.macro_table(rel_path)?;
        for (name, (params, body)) in table.iter() {
            ctx.macros.insert(
                name.clone(),
                (rel_path.to_string(), params.clone(), body.clone()),
            );
        }
        let mut out = String::new();
        self.render_nodes(&nodes, &mut ctx, &mut out)?;
        Ok(out)
    }

    fn render_nodes(&mut self, nodes: &[Node], ctx: &mut Ctx, out: &mut String) -> Result<(), String> {
        for node in nodes {
            match node {
                Node::Text(t) => out.push_str(t),
                Node::Output(e) => {
                    let v = self.eval(e, ctx)?;
                    out.push_str(&v.render());
                }
                Node::If { branches, else_body } => {
                    let mut done = false;
                    for (cond, body) in branches {
                        if self.eval(cond, ctx)?.truthy() {
                            self.render_nodes(body, ctx, out)?;
                            done = true;
                            break;
                        }
                    }
                    if !done {
                        if let Some(body) = else_body {
                            self.render_nodes(body, ctx, out)?;
                        }
                    }
                }
                Node::For { targets, iter, body } => {
                    let items = match self.eval(iter, ctx)? {
                        Value::List(l) => l,
                        Value::Map(m) => m
                            .into_iter()
                            .map(|(k, v)| Value::List(vec![Value::Str(k), v]))
                            .collect(),
                        _ => Vec::new(),
                    };
                    let len = items.len();
                    for (idx, item) in items.into_iter().enumerate() {
                        let mut frame = Frame::new();
                        if targets.len() == 1 {
                            frame.insert(targets[0].clone(), item);
                        } else if let Value::List(parts) = &item {
                            for (t, p) in targets.iter().zip(parts.iter()) {
                                frame.insert(t.clone(), p.clone());
                            }
                        }
                        let loop_val = crate::vmap![
                            "index" => Value::Int(idx as i64 + 1),
                            "index0" => Value::Int(idx as i64),
                            "first" => Value::Bool(idx == 0),
                            "last" => Value::Bool(idx + 1 == len),
                            "length" => Value::Int(len as i64),
                        ];
                        frame.insert("loop".to_string(), loop_val);
                        ctx.frames.push(frame);
                        let r = self.render_nodes(body, ctx, out);
                        ctx.frames.pop();
                        r?;
                    }
                }
                Node::Set { name, attr, expr } => {
                    let v = self.eval(expr, ctx)?;
                    match attr {
                        None => {
                            if let Some(top) = ctx.frames.last_mut() {
                                top.insert(name.clone(), v);
                            }
                        }
                        Some(attr) => {
                            // Mutate the named map in whichever frame holds it
                            // (namespace semantics: shared across scopes).
                            let mut found = false;
                            for frame in ctx.frames.iter_mut().rev() {
                                if let Some(slot) = frame.get_mut(name) {
                                    if let Value::Map(_) = slot {
                                        slot.set_key(attr, v.clone());
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            if !found {
                                return Err(format!("set {}.{}: no such namespace", name, attr));
                            }
                        }
                    }
                }
                Node::MacroDef { .. } => { /* definitions emit nothing */ }
                Node::FromImport { path, names } => {
                    let table = self.macro_table(path)?;
                    for name in names {
                        if let Some((params, body)) = table.get(name) {
                            ctx.macros.insert(
                                name.clone(),
                                (path.clone(), params.clone(), body.clone()),
                            );
                        } else {
                            return Err(format!("macro {} not found in {}", name, path));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn lookup(&self, ctx: &Ctx, name: &str) -> Value {
        for frame in ctx.frames.iter().rev() {
            if let Some(v) = frame.get(name) {
                return v.clone();
            }
        }
        Value::Undefined
    }

    fn eval(&mut self, expr: &Expr, ctx: &mut Ctx) -> Result<Value, String> {
        match expr {
            Expr::Lit(v) => Ok(v.clone()),
            Expr::Name(n) => Ok(self.lookup(ctx, n)),
            Expr::Attr(base, name) => {
                let b = self.eval(base, ctx)?;
                Ok(attr_of(&b, name))
            }
            Expr::Index(base, idx) => {
                let b = self.eval(base, ctx)?;
                let i = self.eval(idx, ctx)?;
                Ok(index_of(&b, &i))
            }
            Expr::Slice(base, lo, hi) => {
                let b = self.eval(base, ctx)?;
                let lo = match lo {
                    Some(e) => Some(self.eval(e, ctx)?.as_f64().unwrap_or(0.0) as i64),
                    None => None,
                };
                let hi = match hi {
                    Some(e) => Some(self.eval(e, ctx)?.as_f64().unwrap_or(0.0) as i64),
                    None => None,
                };
                Ok(slice_of(&b, lo, hi))
            }
            Expr::ListLit(items) => {
                let mut out = Vec::new();
                for e in items {
                    out.push(self.eval(e, ctx)?);
                }
                Ok(Value::List(out))
            }
            Expr::DictLit(pairs) => {
                let mut out = Vec::new();
                for (k, v) in pairs {
                    let key = self.eval(k, ctx)?.render();
                    let val = self.eval(v, ctx)?;
                    out.push((key, val));
                }
                Ok(Value::Map(out))
            }
            Expr::Unary(UnOp::Not, e) => {
                let v = self.eval(e, ctx)?;
                Ok(Value::Bool(!v.truthy()))
            }
            Expr::Unary(UnOp::Neg, e) => {
                let v = self.eval(e, ctx)?;
                match v {
                    Value::Int(i) => Ok(Value::Int(-i)),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    _ => Ok(Value::Undefined),
                }
            }
            Expr::Ternary(val, cond, els) => {
                if self.eval(cond, ctx)?.truthy() {
                    self.eval(val, ctx)
                } else if let Some(e) = els {
                    self.eval(e, ctx)
                } else {
                    Ok(Value::Undefined)
                }
            }
            Expr::IsDefined(inner, negated) => {
                let v = self.eval(inner, ctx)?;
                Ok(Value::Bool(v.is_defined() != *negated))
            }
            Expr::BinOp(l, op, r) => self.eval_binop(l, *op, r, ctx),
            Expr::Filter(base, fname, args) => {
                let b = self.eval(base, ctx)?;
                let mut argv = Vec::new();
                for a in args {
                    argv.push(self.eval(a, ctx)?);
                }
                apply_filter(&b, fname, &argv)
            }
            Expr::Method(base, name, args) => {
                let b = self.eval(base, ctx)?;
                let mut argv = Vec::new();
                for a in args {
                    argv.push(self.eval(a, ctx)?);
                }
                apply_method(&b, name, &argv)
            }
            Expr::Call(callee, args, kwargs) => {
                // namespace(...) builtin
                if let Expr::Name(n) = &**callee {
                    if n == "namespace" {
                        let mut pairs = Vec::new();
                        for (k, v) in kwargs {
                            pairs.push((k.clone(), self.eval(v, ctx)?));
                        }
                        return Ok(Value::Map(pairs));
                    }
                    // Macro call
                    if let Some((_, params, body)) = ctx.macros.get(n).cloned() {
                        let mut frame = Frame::new();
                        for (i, p) in params.iter().enumerate() {
                            let val = if i < args.len() {
                                self.eval(&args[i], ctx)?
                            } else if let Some((_, kv)) = kwargs.iter().find(|(k, _)| k == p) {
                                self.eval(kv, ctx)?
                            } else {
                                Value::Undefined
                            };
                            frame.insert(p.clone(), val);
                        }
                        ctx.frames.push(frame);
                        let mut out = String::new();
                        let r = self.render_nodes(&body, ctx, &mut out);
                        ctx.frames.pop();
                        r?;
                        return Ok(Value::Str(out));
                    }
                }
                Err("only macro calls and namespace() are callable".into())
            }
        }
    }

    fn eval_binop(&mut self, l: &Expr, op: BinOp, r: &Expr, ctx: &mut Ctx) -> Result<Value, String> {
        match op {
            BinOp::Or => {
                let lv = self.eval(l, ctx)?;
                if lv.truthy() {
                    Ok(lv)
                } else {
                    self.eval(r, ctx)
                }
            }
            BinOp::And => {
                let lv = self.eval(l, ctx)?;
                if !lv.truthy() {
                    Ok(lv)
                } else {
                    self.eval(r, ctx)
                }
            }
            BinOp::Concat => {
                let lv = self.eval(l, ctx)?;
                let rv = self.eval(r, ctx)?;
                Ok(Value::Str(format!("{}{}", lv.render(), rv.render())))
            }
            BinOp::Eq | BinOp::Ne => {
                let lv = self.eval(l, ctx)?;
                let rv = self.eval(r, ctx)?;
                let eq = values_equal(&lv, &rv);
                Ok(Value::Bool(if op == BinOp::Eq { eq } else { !eq }))
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let lv = self.eval(l, ctx)?;
                let rv = self.eval(r, ctx)?;
                Ok(Value::Bool(compare(&lv, &rv, op)))
            }
            BinOp::In | BinOp::NotIn => {
                let lv = self.eval(l, ctx)?;
                let rv = self.eval(r, ctx)?;
                let found = match &rv {
                    Value::List(items) => items.iter().any(|x| values_equal(x, &lv)),
                    Value::Str(hay) => match &lv {
                        Value::Str(needle) => hay.contains(needle.as_str()),
                        _ => false,
                    },
                    Value::Map(pairs) => match &lv {
                        Value::Str(k) => pairs.iter().any(|(pk, _)| pk == k),
                        _ => false,
                    },
                    _ => false,
                };
                Ok(Value::Bool(if op == BinOp::In { found } else { !found }))
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::FloorDiv | BinOp::Mod => {
                let lv = self.eval(l, ctx)?;
                let rv = self.eval(r, ctx)?;
                arith(&lv, &rv, op)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Value operations
// ---------------------------------------------------------------------------

pub fn attr_of(base: &Value, name: &str) -> Value {
    match base {
        Value::Map(_) => base.get_key(name),
        Value::List(l) => match name {
            "length" => Value::Int(l.len() as i64),
            _ => Value::Undefined,
        },
        Value::Str(s) => match name {
            "length" => Value::Int(s.chars().count() as i64),
            _ => Value::Undefined,
        },
        _ => Value::Undefined,
    }
}

fn index_of(base: &Value, idx: &Value) -> Value {
    match (base, idx) {
        (Value::List(l), Value::Int(i)) => {
            let n = norm_index(*i, l.len());
            n.and_then(|n| l.get(n).cloned()).unwrap_or(Value::Undefined)
        }
        (Value::Str(s), Value::Int(i)) => {
            let chars: Vec<char> = s.chars().collect();
            let n = norm_index(*i, chars.len());
            n.map(|n| Value::Str(chars[n].to_string()))
                .unwrap_or(Value::Undefined)
        }
        (Value::Map(_), Value::Str(k)) => base.get_key(k),
        _ => Value::Undefined,
    }
}

fn norm_index(i: i64, len: usize) -> Option<usize> {
    let n = if i < 0 { len as i64 + i } else { i };
    if n < 0 || n as usize >= len {
        None
    } else {
        Some(n as usize)
    }
}

fn slice_of(base: &Value, lo: Option<i64>, hi: Option<i64>) -> Value {
    fn range(len: usize, lo: Option<i64>, hi: Option<i64>) -> (usize, usize) {
        let conv = |v: Option<i64>, default: i64| -> i64 {
            match v {
                None => default,
                Some(x) if x < 0 => len as i64 + x,
                Some(x) => x,
            }
        };
        let a = conv(lo, 0).clamp(0, len as i64) as usize;
        let b = conv(hi, len as i64).clamp(0, len as i64) as usize;
        (a, b.max(a))
    }
    match base {
        Value::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            let (a, b) = range(chars.len(), lo, hi);
            Value::Str(chars[a..b].iter().collect())
        }
        Value::List(l) => {
            let (a, b) = range(l.len(), lo, hi);
            Value::List(l[a..b].to_vec())
        }
        _ => Value::Undefined,
    }
}

pub fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Float(y)) | (Value::Float(y), Value::Int(x)) => (*x as f64) == *y,
        (Value::Undefined, Value::Undefined) => true,
        (Value::Undefined, _) | (_, Value::Undefined) => false,
        _ => a == b,
    }
}

fn compare(a: &Value, b: &Value, op: BinOp) -> bool {
    let ord = match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => match (a, b) {
            (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
            _ => None,
        },
    };
    match (ord, op) {
        (Some(std::cmp::Ordering::Less), BinOp::Lt) => true,
        (Some(std::cmp::Ordering::Less), BinOp::Le) => true,
        (Some(std::cmp::Ordering::Equal), BinOp::Le) => true,
        (Some(std::cmp::Ordering::Equal), BinOp::Ge) => true,
        (Some(std::cmp::Ordering::Greater), BinOp::Gt) => true,
        (Some(std::cmp::Ordering::Greater), BinOp::Ge) => true,
        _ => false,
    }
}

fn arith(a: &Value, b: &Value, op: BinOp) -> Result<Value, String> {
    match (a, b, op) {
        (Value::Str(x), Value::Str(y), BinOp::Add) => {
            Ok(Value::Str(format!("{}{}", x, y)))
        }
        (Value::List(x), Value::List(y), BinOp::Add) => {
            let mut out = x.clone();
            out.extend(y.iter().cloned());
            Ok(Value::List(out))
        }
        _ => {
            let (x, y) = match (a.as_f64(), b.as_f64()) {
                (Some(x), Some(y)) => (x, y),
                _ => return Ok(Value::Undefined),
            };
            let both_int = matches!(a, Value::Int(_)) && matches!(b, Value::Int(_));
            let r = match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div => x / y,
                BinOp::FloorDiv => (x / y).floor(),
                BinOp::Mod => x % y,
                _ => unreachable!(),
            };
            if both_int && op != BinOp::Div {
                Ok(Value::Int(r as i64))
            } else {
                Ok(Value::Float(r))
            }
        }
    }
}

fn apply_filter(base: &Value, name: &str, args: &[Value]) -> Result<Value, String> {
    match name {
        "length" => Ok(Value::Int(match base {
            Value::Str(s) => s.chars().count() as i64,
            Value::List(l) => l.len() as i64,
            Value::Map(m) => m.len() as i64,
            _ => 0,
        })),
        "join" => {
            let sep = args.get(0).map(|v| v.render()).unwrap_or_default();
            match base {
                Value::List(items) => Ok(Value::Str(
                    items
                        .iter()
                        .map(|v| v.render())
                        .collect::<Vec<_>>()
                        .join(&sep),
                )),
                _ => Ok(Value::Str(String::new())),
            }
        }
        "replace" => {
            let old = args.get(0).map(|v| v.render()).unwrap_or_default();
            let new = args.get(1).map(|v| v.render()).unwrap_or_default();
            Ok(Value::Str(base.render().replace(&old, &new)))
        }
        "upper" => Ok(Value::Str(base.render().to_uppercase())),
        "lower" => Ok(Value::Str(base.render().to_lowercase())),
        "title" => Ok(Value::Str(py_title(&base.render()))),
        "trim" => Ok(Value::Str(base.render().trim().to_string())),
        "default" => {
            if matches!(base, Value::Undefined) {
                Ok(args.get(0).cloned().unwrap_or(Value::Undefined))
            } else {
                Ok(base.clone())
            }
        }
        other => Err(format!("unsupported filter: {}", other)),
    }
}

fn apply_method(base: &Value, name: &str, args: &[Value]) -> Result<Value, String> {
    match name {
        "get" => {
            let key = args.get(0).map(|v| v.render()).unwrap_or_default();
            let v = base.get_key(&key);
            if v.is_defined() {
                Ok(v)
            } else {
                Ok(args.get(1).cloned().unwrap_or(Value::Undefined))
            }
        }
        "items" => match base {
            Value::Map(pairs) => Ok(Value::List(
                pairs
                    .iter()
                    .map(|(k, v)| Value::List(vec![Value::Str(k.clone()), v.clone()]))
                    .collect(),
            )),
            _ => Ok(Value::List(Vec::new())),
        },
        "keys" => match base {
            Value::Map(pairs) => Ok(Value::List(
                pairs.iter().map(|(k, _)| Value::Str(k.clone())).collect(),
            )),
            _ => Ok(Value::List(Vec::new())),
        },
        "replace" => {
            let old = args.get(0).map(|v| v.render()).unwrap_or_default();
            let new = args.get(1).map(|v| v.render()).unwrap_or_default();
            Ok(Value::Str(base.render().replace(&old, &new)))
        }
        "strip" => Ok(Value::Str(base.render().trim().to_string())),
        "upper" => Ok(Value::Str(base.render().to_uppercase())),
        "lower" => Ok(Value::Str(base.render().to_lowercase())),
        other => Err(format!("unsupported method: {}", other)),
    }
}

/// Python `str.title()`: capitalise the first letter of each word
/// (words are separated by non-alphabetic characters), lowercase the rest.
fn py_title(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_alpha = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_alpha {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_alpha = true;
        } else {
            out.push(c);
            prev_alpha = false;
        }
    }
    out
}
