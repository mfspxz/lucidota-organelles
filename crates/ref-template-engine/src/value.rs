//! The dynamic value model shared by the JSON layer, the packet store and
//! the template engine. Mirrors the Python/Jinja semantics the recovered
//! templates were written against: missing names/keys yield `Undefined`,
//! which renders as an empty string and is falsy.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Undefined,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    /// Insertion-ordered map (Jinja dicts preserve order; so do we).
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
    pub fn map(pairs: Vec<(String, Value)>) -> Value {
        Value::Map(pairs)
    }
    pub fn obj() -> Value {
        Value::Map(Vec::new())
    }

    pub fn get_key(&self, key: &str) -> Value {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Undefined),
            _ => Value::Undefined,
        }
    }

    pub fn set_key(&mut self, key: &str, val: Value) {
        if let Value::Map(pairs) = self {
            if let Some(slot) = pairs.iter_mut().find(|(k, _)| k == key) {
                slot.1 = val;
                return;
            }
            pairs.push((key.to_string(), val));
        }
    }

    pub fn is_defined(&self) -> bool {
        !matches!(self, Value::Undefined)
    }

    /// Python/Jinja truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Undefined | Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Map(m) => !m.is_empty(),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Undefined => "undefined",
            Value::Null => "none",
            Value::Bool(_) => "bool",
            Value::Int(_) | Value::Float(_) => "number",
            Value::Str(_) => "string",
            Value::List(_) => "list",
            Value::Map(_) => "dict",
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// String conversion the way Jinja renders a value into output text.
    pub fn render(&self) -> String {
        match self {
            Value::Undefined | Value::Null => String::new(),
            Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => {
                if f.fract() == 0.0 && f.is_finite() {
                    format!("{:.1}", f)
                } else {
                    format!("{}", f)
                }
            }
            Value::Str(s) => s.clone(),
            Value::List(l) => {
                let parts: Vec<String> = l.iter().map(|v| v.repr()).collect();
                format!("[{}]", parts.join(", "))
            }
            Value::Map(m) => {
                // A regulator/contact dict rendered whole (the wildlife
                // templates pass `regulator` straight into packet_header):
                // prefer its human name, as the printed packets did.
                if let Value::Str(n) = self.get_key("name") {
                    return n;
                }
                let parts: Vec<String> = m
                    .iter()
                    .map(|(k, v)| format!("'{}': {}", k, v.repr()))
                    .collect();
                format!("{{{}}}", parts.join(", "))
            }
        }
    }

    /// Python-repr-flavoured rendering for nested positions.
    fn repr(&self) -> String {
        match self {
            Value::Str(s) => format!("'{}'", s),
            other => other.render(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::Str(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::Str(s)
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Value {
        Value::Int(i)
    }
}
impl From<usize> for Value {
    fn from(i: usize) -> Value {
        Value::Int(i as i64)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}
impl From<Vec<Value>> for Value {
    fn from(l: Vec<Value>) -> Value {
        Value::List(l)
    }
}
impl From<BTreeMap<String, Value>> for Value {
    fn from(m: BTreeMap<String, Value>) -> Value {
        Value::Map(m.into_iter().collect())
    }
}

/// Build a `Value::Map` from literal pairs: `vmap!["a" => v1, "b" => v2]`.
#[macro_export]
macro_rules! vmap {
    ($($k:expr => $v:expr),* $(,)?) => {
        $crate::value::Value::Map(vec![$(($k.to_string(), $v)),*])
    };
}
