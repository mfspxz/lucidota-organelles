//! A Jinja2-subset template engine, written to render the *recovered*
//! Regulator Router templates byte-for-byte unmodified.
//!
//! The original used Python Jinja2 with `trim_blocks=True`,
//! `lstrip_blocks=True`, `keep_trailing_newline=True`, `autoescape=False`
//! (chat evidence, 2026-03-11 exploration of render.py). This engine
//! implements exactly the construct surface the 33 recovered templates use:
//!
//! - `{{ expr }}` output, `{# comments #}`, whitespace control (`{{-`, `-%}`…)
//! - `{% if/elif/else %}`, `{% for %}` (incl. tuple unpacking, `loop.*`),
//!   `{% set %}` (incl. `namespace()` attribute assignment),
//!   `{% macro %}`, `{% from "…" import … %}`
//! - expressions: attribute/index/slice access, method calls (`.get`,
//!   `.items`, `.replace`, `.strip`), dict/list literals, ternary,
//!   `and/or/not`, comparisons, `in`, `is defined`, `~` concatenation,
//!   arithmetic, and the filters the templates use
//!   (`length`, `join`, `replace`, `upper`, `lower`, `title`, `default`, `trim`)
//!
//! Undefined names/keys behave like Jinja's default `Undefined` for
//! rendering: empty output, falsy, attribute access stays undefined.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Text(String),
    Output(String),
    Tag(String),
    Comment,
}

fn lex(src: &str) -> Vec<Tok> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    let mut text_start = 0usize;
    // Each token records trim flags via wrapping: we handle trims in a
    // post-pass using these side tables keyed by token index.
    let mut trims: Vec<(bool, bool)> = Vec::new(); // (trim_left, trim_right)
    while i < b.len() {
        let (open, kind) = if src[i..].starts_with("{{") {
            ("{{", 0)
        } else if src[i..].starts_with("{%") {
            ("{%", 1)
        } else if src[i..].starts_with("{#") {
            ("{#", 2)
        } else {
            i += src[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            continue;
        };
        let close = match kind {
            0 => "}}",
            1 => "%}",
            _ => "#}",
        };
        let mut j = i + 2;
        let trim_left = j < b.len() && b[j] == b'-';
        if trim_left {
            j += 1;
        }
        // Find the close delimiter (string literals inside could contain it;
        // the recovered templates never do, but skip quoted spans anyway).
        let mut k = j;
        let mut end = None;
        while k < b.len() {
            let c = b[k];
            // Quoted spans can hide a close delimiter in {{ }} and {% %}
            // tags — but never in {# #} comments, where an apostrophe is
            // just prose ("Tenant's Notice") and must not start a "string".
            if kind != 2 && (c == b'\'' || c == b'"') {
                let q = c;
                k += 1;
                while k < b.len() && b[k] != q {
                    if b[k] == b'\\' {
                        k += 1;
                    }
                    k += src[k..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                }
                k += 1;
                continue;
            }
            if src[k..].starts_with(close) {
                end = Some(k);
                break;
            }
            k += src[k..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
        }
        let k = match end {
            Some(k) => k,
            None => break, // unterminated: treat the rest as text
        };
        let mut inner_end = k;
        let trim_right = inner_end > j && b[inner_end - 1] == b'-';
        if trim_right {
            inner_end -= 1;
        }
        if text_start < i {
            toks.push(Tok::Text(src[text_start..i].to_string()));
            trims.push((false, false));
        }
        let inner = src[j..inner_end].to_string();
        match kind {
            0 => toks.push(Tok::Output(inner)),
            1 => toks.push(Tok::Tag(inner)),
            _ => toks.push(Tok::Comment),
        }
        trims.push((trim_left, trim_right));
        let _ = open;
        i = k + 2;
        text_start = i;
    }
    if text_start < b.len() {
        toks.push(Tok::Text(src[text_start..].to_string()));
        trims.push((false, false));
    }
    apply_trims(&mut toks, &trims);
    toks
}

/// Implements Jinja whitespace behaviour: explicit `-` trims, plus
/// `trim_blocks` / `lstrip_blocks` for `{% %}` and `{# #}` tags.
fn apply_trims(toks: &mut Vec<Tok>, trims: &[(bool, bool)]) {
    for idx in 0..toks.len() {
        let is_block = matches!(toks[idx], Tok::Tag(_) | Tok::Comment);
        let (tl, tr) = trims[idx];
        if matches!(toks[idx], Tok::Text(_)) {
            continue;
        }
        // Left side: modify preceding text token.
        if idx > 0 {
            if let Tok::Text(prev) = &mut toks[idx - 1] {
                if tl {
                    let trimmed = prev.trim_end().to_string();
                    *prev = trimmed;
                } else if is_block {
                    // lstrip_blocks: strip spaces/tabs back to the newline
                    // when only whitespace precedes the tag on its line.
                    let mut cut = prev.len();
                    let bytes = prev.as_bytes();
                    let mut p = bytes.len();
                    while p > 0 && (bytes[p - 1] == b' ' || bytes[p - 1] == b'\t') {
                        p -= 1;
                    }
                    if p == 0 || bytes[p - 1] == b'\n' {
                        cut = p;
                    }
                    prev.truncate(cut);
                }
            }
        }
        // Right side: modify following text token.
        if idx + 1 < toks.len() {
            if let Tok::Text(next) = &mut toks[idx + 1] {
                if tr {
                    let trimmed = next.trim_start().to_string();
                    *next = trimmed;
                } else if is_block {
                    // trim_blocks: drop a single leading newline.
                    if next.starts_with("\r\n") {
                        *next = next[2..].to_string();
                    } else if next.starts_with('\n') {
                        *next = next[1..].to_string();
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(crate::value::Value),
    Name(String),
    Attr(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Slice(Box<Expr>, Option<Box<Expr>>, Option<Box<Expr>>),
    Call(Box<Expr>, Vec<Expr>, Vec<(String, Expr)>),
    Method(Box<Expr>, String, Vec<Expr>),
    Filter(Box<Expr>, String, Vec<Expr>),
    BinOp(Box<Expr>, BinOp, Box<Expr>),
    Unary(UnOp, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Option<Box<Expr>>),
    IsDefined(Box<Expr>, bool),
    ListLit(Vec<Expr>),
    DictLit(Vec<(Expr, Expr)>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Concat,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Text(String),
    Output(Expr),
    If {
        branches: Vec<(Expr, Vec<Node>)>,
        else_body: Option<Vec<Node>>,
    },
    For {
        targets: Vec<String>,
        iter: Expr,
        body: Vec<Node>,
    },
    Set {
        name: String,
        attr: Option<String>,
        expr: Expr,
    },
    MacroDef {
        name: String,
        params: Vec<String>,
        body: Vec<Node>,
    },
    FromImport {
        path: String,
        names: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Expression parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum ETok {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    Punct(char),
    Op(String),
}

fn lex_expr(src: &str) -> Result<Vec<ETok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'\'' | b'"' => {
                let q = c;
                i += 1;
                let mut s = String::new();
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                        match b[i] {
                            b'n' => s.push('\n'),
                            b'r' => s.push('\r'),
                            b't' => s.push('\t'),
                            b'\\' => s.push('\\'),
                            b'\'' => s.push('\''),
                            b'"' => s.push('"'),
                            other => {
                                s.push('\\');
                                s.push(other as char);
                            }
                        }
                        i += 1;
                    } else {
                        // one UTF-8 code point
                        let start = i;
                        i += 1;
                        while i < b.len() && (b[i] & 0xC0) == 0x80 {
                            i += 1;
                        }
                        s.push_str(&src[start..i]);
                    }
                }
                if i >= b.len() {
                    return Err("unterminated string literal".into());
                }
                i += 1;
                out.push(ETok::Str(s));
            }
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                let text = &src[start..i];
                if text.contains('.') {
                    out.push(ETok::Float(text.parse().map_err(|_| "bad float")?));
                } else {
                    out.push(ETok::Int(text.parse().map_err(|_| "bad int")?));
                }
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(ETok::Ident(src[start..i].to_string()));
            }
            b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b':' | b'.' | b'|' | b'~' | b'+'
            | b'-' | b'*' | b'%' => {
                if c == b'-' && src[i..].starts_with("->") {
                    return Err("unexpected ->".into());
                }
                out.push(ETok::Punct(c as char));
                i += 1;
            }
            b'/' => {
                if src[i..].starts_with("//") {
                    out.push(ETok::Op("//".into()));
                    i += 2;
                } else {
                    out.push(ETok::Punct('/'));
                    i += 1;
                }
            }
            b'=' => {
                if src[i..].starts_with("==") {
                    out.push(ETok::Op("==".into()));
                    i += 2;
                } else {
                    out.push(ETok::Punct('='));
                    i += 1;
                }
            }
            b'!' => {
                if src[i..].starts_with("!=") {
                    out.push(ETok::Op("!=".into()));
                    i += 2;
                } else {
                    return Err("unexpected !".into());
                }
            }
            b'<' => {
                if src[i..].starts_with("<=") {
                    out.push(ETok::Op("<=".into()));
                    i += 2;
                } else {
                    out.push(ETok::Punct('<'));
                    i += 1;
                }
            }
            b'>' => {
                if src[i..].starts_with(">=") {
                    out.push(ETok::Op(">=".into()));
                    i += 2;
                } else {
                    out.push(ETok::Punct('>'));
                    i += 1;
                }
            }
            other => return Err(format!("unexpected character '{}' in expression", other as char)),
        }
    }
    Ok(out)
}

pub struct ExprParser {
    toks: Vec<ETok>,
    pos: usize,
}

impl ExprParser {
    pub fn new(src: &str) -> Result<Self, String> {
        Ok(ExprParser { toks: lex_expr(src)?, pos: 0 })
    }
    fn peek(&self) -> Option<&ETok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<ETok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat_punct(&mut self, c: char) -> bool {
        if self.peek() == Some(&ETok::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_punct(&mut self, c: char) -> Result<(), String> {
        if self.eat_punct(c) {
            Ok(())
        } else {
            Err(format!("expected '{}', found {:?}", c, self.peek()))
        }
    }
    fn eat_ident(&mut self, name: &str) -> bool {
        if matches!(self.peek(), Some(ETok::Ident(s)) if s == name) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    pub fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    pub fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<Expr, String> {
        let first = self.parse_or()?;
        if self.eat_ident("if") {
            let cond = self.parse_or()?;
            let els = if self.eat_ident("else") {
                Some(Box::new(self.parse_ternary()?))
            } else {
                None
            };
            return Ok(Expr::Ternary(Box::new(first), Box::new(cond), els));
        }
        Ok(first)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_and()?;
        while self.eat_ident("or") {
            let rhs = self.parse_and()?;
            lhs = Expr::BinOp(Box::new(lhs), BinOp::Or, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_not()?;
        while self.eat_ident("and") {
            let rhs = self.parse_not()?;
            lhs = Expr::BinOp(Box::new(lhs), BinOp::And, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if self.eat_ident("not") {
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnOp::Not, Box::new(inner)));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_additive()?;
        loop {
            // `is [not] defined`
            if matches!(self.peek(), Some(ETok::Ident(s)) if s == "is") {
                self.pos += 1;
                let negated = self.eat_ident("not");
                if self.eat_ident("defined") {
                    lhs = Expr::IsDefined(Box::new(lhs), negated);
                    continue;
                }
                return Err("only the 'defined' test is supported".into());
            }
            if self.eat_ident("in") {
                let rhs = self.parse_additive()?;
                lhs = Expr::BinOp(Box::new(lhs), BinOp::In, Box::new(rhs));
                continue;
            }
            if matches!(self.peek(), Some(ETok::Ident(s)) if s == "not")
                && matches!(self.toks.get(self.pos + 1), Some(ETok::Ident(s)) if s == "in")
            {
                self.pos += 2;
                let rhs = self.parse_additive()?;
                lhs = Expr::BinOp(Box::new(lhs), BinOp::NotIn, Box::new(rhs));
                continue;
            }
            let op = match self.peek() {
                Some(ETok::Op(s)) if s == "==" => BinOp::Eq,
                Some(ETok::Op(s)) if s == "!=" => BinOp::Ne,
                Some(ETok::Op(s)) if s == "<=" => BinOp::Le,
                Some(ETok::Op(s)) if s == ">=" => BinOp::Ge,
                Some(ETok::Punct('<')) => BinOp::Lt,
                Some(ETok::Punct('>')) => BinOp::Gt,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_additive()?;
            lhs = Expr::BinOp(Box::new(lhs), op, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_additive(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_mult()?;
        loop {
            let op = match self.peek() {
                Some(ETok::Punct('+')) => BinOp::Add,
                Some(ETok::Punct('-')) => BinOp::Sub,
                Some(ETok::Punct('~')) => BinOp::Concat,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_mult()?;
            lhs = Expr::BinOp(Box::new(lhs), op, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_mult(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(ETok::Punct('*')) => BinOp::Mul,
                Some(ETok::Punct('/')) => BinOp::Div,
                Some(ETok::Op(s)) if s == "//" => BinOp::FloorDiv,
                Some(ETok::Punct('%')) => BinOp::Mod,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_unary()?;
            lhs = Expr::BinOp(Box::new(lhs), op, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.eat_punct('-') {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary(UnOp::Neg, Box::new(inner)));
        }
        self.parse_postfix()
    }

    fn parse_args(&mut self) -> Result<(Vec<Expr>, Vec<(String, Expr)>), String> {
        // Assumes '(' already consumed; consumes through ')'.
        let mut args = Vec::new();
        let mut kwargs = Vec::new();
        if self.eat_punct(')') {
            return Ok((args, kwargs));
        }
        loop {
            // keyword arg: Ident '=' expr (but not '==')
            let is_kw = matches!(self.peek(), Some(ETok::Ident(_)))
                && self.toks.get(self.pos + 1) == Some(&ETok::Punct('='));
            if is_kw {
                let name = match self.next() {
                    Some(ETok::Ident(s)) => s,
                    _ => unreachable!(),
                };
                self.pos += 1; // '='
                let v = self.parse_expr()?;
                kwargs.push((name, v));
            } else {
                args.push(self.parse_expr()?);
            }
            if self.eat_punct(',') {
                continue;
            }
            self.expect_punct(')')?;
            return Ok((args, kwargs));
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.eat_punct('.') {
                match self.next() {
                    Some(ETok::Ident(name)) => {
                        if self.eat_punct('(') {
                            let (args, kwargs) = self.parse_args()?;
                            if !kwargs.is_empty() {
                                return Err("method kwargs unsupported".into());
                            }
                            expr = Expr::Method(Box::new(expr), name, args);
                        } else {
                            expr = Expr::Attr(Box::new(expr), name);
                        }
                    }
                    Some(ETok::Int(n)) => {
                        expr = Expr::Index(
                            Box::new(expr),
                            Box::new(Expr::Lit(crate::value::Value::Int(n))),
                        );
                    }
                    other => return Err(format!("expected attribute name, found {:?}", other)),
                }
            } else if self.eat_punct('[') {
                // index or slice
                let lo = if self.peek() == Some(&ETok::Punct(':')) {
                    None
                } else {
                    Some(Box::new(self.parse_expr()?))
                };
                if self.eat_punct(':') {
                    let hi = if self.peek() == Some(&ETok::Punct(']')) {
                        None
                    } else {
                        Some(Box::new(self.parse_expr()?))
                    };
                    self.expect_punct(']')?;
                    expr = Expr::Slice(Box::new(expr), lo, hi);
                } else {
                    self.expect_punct(']')?;
                    expr = Expr::Index(Box::new(expr), lo.unwrap());
                }
            } else if self.eat_punct('(') {
                let (args, kwargs) = self.parse_args()?;
                expr = Expr::Call(Box::new(expr), args, kwargs);
            } else if self.eat_punct('|') {
                match self.next() {
                    Some(ETok::Ident(fname)) => {
                        let args = if self.eat_punct('(') {
                            let (a, kw) = self.parse_args()?;
                            if !kw.is_empty() {
                                return Err("filter kwargs unsupported".into());
                            }
                            a
                        } else {
                            Vec::new()
                        };
                        expr = Expr::Filter(Box::new(expr), fname, args);
                    }
                    other => return Err(format!("expected filter name, found {:?}", other)),
                }
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(ETok::Str(s)) => Ok(Expr::Lit(crate::value::Value::Str(s))),
            Some(ETok::Int(n)) => Ok(Expr::Lit(crate::value::Value::Int(n))),
            Some(ETok::Float(f)) => Ok(Expr::Lit(crate::value::Value::Float(f))),
            Some(ETok::Ident(name)) => match name.as_str() {
                "true" | "True" => Ok(Expr::Lit(crate::value::Value::Bool(true))),
                "false" | "False" => Ok(Expr::Lit(crate::value::Value::Bool(false))),
                "none" | "None" => Ok(Expr::Lit(crate::value::Value::Null)),
                _ => Ok(Expr::Name(name)),
            },
            Some(ETok::Punct('(')) => {
                let e = self.parse_expr()?;
                self.expect_punct(')')?;
                Ok(e)
            }
            Some(ETok::Punct('[')) => {
                let mut items = Vec::new();
                if self.eat_punct(']') {
                    return Ok(Expr::ListLit(items));
                }
                loop {
                    items.push(self.parse_expr()?);
                    if self.eat_punct(',') {
                        continue;
                    }
                    self.expect_punct(']')?;
                    return Ok(Expr::ListLit(items));
                }
            }
            Some(ETok::Punct('{')) => {
                let mut pairs = Vec::new();
                if self.eat_punct('}') {
                    return Ok(Expr::DictLit(pairs));
                }
                loop {
                    let k = self.parse_expr()?;
                    self.expect_punct(':')?;
                    let v = self.parse_expr()?;
                    pairs.push((k, v));
                    if self.eat_punct(',') {
                        continue;
                    }
                    self.expect_punct('}')?;
                    return Ok(Expr::DictLit(pairs));
                }
            }
            other => Err(format!("unexpected token {:?}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Template parser
// ---------------------------------------------------------------------------

pub fn parse_template(src: &str) -> Result<Vec<Node>, String> {
    let toks = lex(src);
    let mut pos = 0usize;
    let (nodes, stop) = parse_block(&toks, &mut pos, &[])?;
    if stop.is_some() {
        return Err("unexpected closing tag at top level".into());
    }
    Ok(nodes)
}

fn tag_head(tag: &str) -> &str {
    tag.trim_start().split_whitespace().next().unwrap_or("")
}

/// Returns (nodes, stop_tag) where stop_tag is the raw tag text that ended
/// the block (one of `stops`), or None at end of input.
fn parse_block(
    toks: &[Tok],
    pos: &mut usize,
    stops: &[&str],
) -> Result<(Vec<Node>, Option<String>), String> {
    let mut nodes = Vec::new();
    while *pos < toks.len() {
        match &toks[*pos] {
            Tok::Text(t) => {
                if !t.is_empty() {
                    nodes.push(Node::Text(t.clone()));
                }
                *pos += 1;
            }
            Tok::Comment => {
                *pos += 1;
            }
            Tok::Output(src) => {
                let mut p = ExprParser::new(src)?;
                let e = p.parse_expr()?;
                if !p.at_end() {
                    return Err(format!("trailing tokens in output tag: {}", src));
                }
                nodes.push(Node::Output(e));
                *pos += 1;
            }
            Tok::Tag(src) => {
                let head = tag_head(src);
                if stops.contains(&head) {
                    return Ok((nodes, Some(src.clone())));
                }
                *pos += 1;
                match head {
                    "if" => {
                        let cond_src = src.trim_start()[2..].to_string();
                        let mut p = ExprParser::new(&cond_src)?;
                        let cond = p.parse_expr()?;
                        let mut branches = Vec::new();
                        let (body, mut stop) = parse_block(toks, pos, &["elif", "else", "endif"])?;
                        branches.push((cond, body));
                        let mut else_body = None;
                        loop {
                            match stop.as_deref().map(tag_head) {
                                Some("elif") => {
                                    let s = stop.take().unwrap();
                                    *pos += 1;
                                    let cs = s.trim_start()[4..].to_string();
                                    let mut p = ExprParser::new(&cs)?;
                                    let c = p.parse_expr()?;
                                    let (b, st) = parse_block(toks, pos, &["elif", "else", "endif"])?;
                                    branches.push((c, b));
                                    stop = st;
                                }
                                Some("else") => {
                                    *pos += 1;
                                    let (b, st) = parse_block(toks, pos, &["endif"])?;
                                    else_body = Some(b);
                                    stop = st;
                                    break;
                                }
                                Some("endif") => break,
                                _ => return Err("if without endif".into()),
                            }
                        }
                        if stop.as_deref().map(tag_head) != Some("endif") {
                            return Err("if without endif".into());
                        }
                        *pos += 1;
                        nodes.push(Node::If { branches, else_body });
                    }
                    "for" => {
                        // for <targets> in <expr>
                        let rest = src.trim_start()[3..].trim().to_string();
                        let in_idx = find_top_level_in(&rest)?;
                        let targets: Vec<String> = rest[..in_idx]
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                        // in_idx is the space before " in " (4 chars total).
                        let mut p = ExprParser::new(&rest[in_idx + 4..])?;
                        let iter = p.parse_expr()?;
                        if !p.at_end() {
                            return Err(format!("trailing tokens in for tag: {}", rest));
                        }
                        let (body, stop) = parse_block(toks, pos, &["endfor"])?;
                        if stop.is_none() {
                            return Err("for without endfor".into());
                        }
                        *pos += 1;
                        nodes.push(Node::For { targets, iter, body });
                    }
                    "set" => {
                        // set name = expr | set ns.attr = expr
                        let rest = src.trim_start()[3..].trim().to_string();
                        let eq = find_assign_eq(&rest)?;
                        let lhs = rest[..eq].trim();
                        let mut p = ExprParser::new(&rest[eq + 1..])?;
                        let expr = p.parse_expr()?;
                        if let Some(dot) = lhs.find('.') {
                            nodes.push(Node::Set {
                                name: lhs[..dot].trim().to_string(),
                                attr: Some(lhs[dot + 1..].trim().to_string()),
                                expr,
                            });
                        } else {
                            nodes.push(Node::Set {
                                name: lhs.to_string(),
                                attr: None,
                                expr,
                            });
                        }
                    }
                    "macro" => {
                        let rest = src.trim_start()[5..].trim().to_string();
                        let open = rest.find('(').ok_or("macro without parens")?;
                        let name = rest[..open].trim().to_string();
                        let close = rest.rfind(')').ok_or("macro without close paren")?;
                        let params: Vec<String> = rest[open + 1..close]
                            .split(',')
                            .map(|s| s.trim().split('=').next().unwrap_or("").trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let (body, stop) = parse_block(toks, pos, &["endmacro"])?;
                        if stop.is_none() {
                            return Err("macro without endmacro".into());
                        }
                        *pos += 1;
                        nodes.push(Node::MacroDef { name, params, body });
                    }
                    "from" => {
                        // from "path" import a, b, c
                        let rest = src.trim_start()[4..].trim().to_string();
                        let import_idx = rest
                            .find(" import ")
                            .ok_or("from without import")?;
                        let path = rest[..import_idx]
                            .trim()
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string();
                        let names: Vec<String> = rest[import_idx + 8..]
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        nodes.push(Node::FromImport { path, names });
                    }
                    other => return Err(format!("unsupported tag: {}", other)),
                }
            }
        }
    }
    Ok((nodes, None))
}

/// Finds the top-level ` in ` separator of a for-tag (not inside brackets
/// or strings). Returns the byte index of the space before `in`.
fn find_top_level_in(s: &str) -> Result<usize, String> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'\'' | b'"' => {
                let q = b[i];
                i += 1;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
            }
            b' ' if depth == 0 && s[i..].starts_with(" in ") => return Ok(i),
            _ => {}
        }
        i += 1;
    }
    Err("for tag without ' in '".into())
}

/// Finds the assignment `=` in a set tag (not `==`, not inside brackets).
fn find_assign_eq(s: &str) -> Result<usize, String> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'\'' | b'"' => {
                let q = b[i];
                i += 1;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
            }
            b'=' if depth == 0 => {
                if s[i..].starts_with("==") {
                    i += 1;
                } else {
                    return Ok(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("set tag without '='".into())
}

pub type MacroTable = HashMap<String, (Vec<String>, Vec<Node>)>;
