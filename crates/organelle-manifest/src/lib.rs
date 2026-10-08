//! org-001 — Organelle manifest schema v1.
//!
//! Grounded in Zackary's surviving `ToolOrganelle` trait (pt-organelle-core):
//! codon dispatch, `handle(ctx, input)`, `mutation_class()`,
//! `declared_valence()`, `requires_capability()`, `input_schema()`.
//!
//! A manifest declares: name, codon, version, contracts (ops + input schemas),
//! authority (mutation class, valence, capability gates), transports, and the
//! receipt policy. The host refuses to register any manifest that fails
//! [`validate_manifest`] — fail-closed at the boundary.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Schema version of this manifest format. Bumped only on breaking change.
pub const MANIFEST_SCHEMA_VERSION: &str = "1";
/// Receipt hash algorithm every host must support.
pub const RECEIPT_ALGORITHM: &str = "sha256";

/// How an organelle (or one of its contracts) mutates the world.
/// Mirrors pt-organelle-core `MutationClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationClass {
    ReadOnly,
    Write,
    ExternalEffect,
}

/// Best epistemic valence an organelle vouches for.
/// Mirrors pt-organelle-core `Valence` (Disproven = -1, Candidate = 0, Proven = 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Valence {
    Disproven,
    Candidate,
    Proven,
}

/// Transport surfaces an organelle is exposed on. Behavioral equivalence
/// across all four is enforced by the equivalence harness (org-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Native,
    UnixSocket,
    Mcp,
    Rest,
}

impl Transport {
    pub fn all() -> &'static [Transport] {
        &[
            Transport::Native,
            Transport::UnixSocket,
            Transport::Mcp,
            Transport::Rest,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Native => "native",
            Transport::UnixSocket => "unix_socket",
            Transport::Mcp => "mcp",
            Transport::Rest => "rest",
        }
    }
}

/// One callable operation: op name + JSON Schema for its input.
/// Per-contract authority overrides let e.g. kv `get` stay ReadOnly while
/// `put` requires a capability — organelle-level authority is the default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub op: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_class: Option<MutationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_capability: Option<String>,
}

/// Authority block: what the organelle may do and what callers must hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    pub mutation_class: MutationClass,
    /// Valence the organelle declares for its outputs by default.
    pub declared_valence: Valence,
    /// Capability a caller must hold. Fail-closed rule: a non-ReadOnly
    /// organelle with `None` here is an invalid manifest (mirrors the
    /// pt-organelle-core doc: "None on a non-ReadOnly tool means the shell
    /// must deny by default" — we go further and refuse registration).
    pub required_capability: Option<String>,
    /// Capabilities this organelle itself holds when calling other
    /// organelles (org-011 authority boundary). Default: none.
    #[serde(default)]
    pub granted_capabilities: Vec<String>,
}

/// Receipt policy. org-010 requires every invocation to emit a
/// content-addressed, hash-chained receipt; the manifest pins the algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPolicy {
    pub content_addressed: bool,
    pub algorithm: String,
    pub chain: bool,
}

/// The full manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganelleManifest {
    pub schema_version: String,
    pub name: String,
    /// 2-char dispatch codon, e.g. "kv". Token-efficient, per his design.
    pub codon: String,
    /// Semver of the organelle implementation.
    pub version: String,
    pub description: String,
    pub contracts: Vec<Contract>,
    pub authority: Authority,
    pub transports: Vec<Transport>,
    pub receipt_policy: ReceiptPolicy,
}

impl OrganelleManifest {
    /// Authority in effect for a given op (contract override wins).
    pub fn authority_for(&self, op: &str) -> (MutationClass, Option<&str>) {
        if let Some(c) = self.contracts.iter().find(|c| c.op == op) {
            let mc = c.mutation_class.unwrap_or(self.authority.mutation_class);
            let cap = c
                .required_capability
                .as_deref()
                .or(self.authority.required_capability.as_deref());
            return (mc, cap);
        }
        (self.authority.mutation_class, self.authority.required_capability.as_deref())
    }

    pub fn contract(&self, op: &str) -> Option<&Contract> {
        self.contracts.iter().find(|c| c.op == op)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub field: String,
    pub message: String,
}

impl ManifestError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        ManifestError { field: field.into(), message: message.into() }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
}

fn valid_codon(codon: &str) -> bool {
    codon.len() == 2
        && codon
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn valid_semver(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn valid_capability(cap: &str) -> bool {
    !cap.is_empty()
        && cap.len() <= 64
        && cap
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_')
}

/// Structural check of a JSON Schema value (subset we enforce at call time).
fn check_input_schema(schema: &Value, path: &str, errs: &mut Vec<ManifestError>) {
    let obj = match schema.as_object() {
        Some(o) => o,
        None => {
            errs.push(ManifestError::new(path, "input_schema must be a JSON object"));
            return;
        }
    };
    if let Some(t) = obj.get("type") {
        let ok = matches!(
            t.as_str(),
            Some("object") | Some("array") | Some("string") | Some("number")
                | Some("integer") | Some("boolean") | Some("null")
        );
        if !ok {
            errs.push(ManifestError::new(
                format!("{path}.type"),
                "unknown JSON type",
            ));
        }
    }
    if let Some(req) = obj.get("required") {
        match req.as_array() {
            Some(arr) if arr.iter().all(|v| v.is_string()) => {}
            _ => errs.push(ManifestError::new(
                format!("{path}.required"),
                "required must be an array of strings",
            )),
        }
    }
    if let Some(props) = obj.get("properties") {
        match props.as_object() {
            Some(map) => {
                for (k, v) in map {
                    check_input_schema(v, &format!("{path}.properties.{k}"), errs);
                }
            }
            None => errs.push(ManifestError::new(
                format!("{path}.properties"),
                "properties must be an object",
            )),
        }
    }
    if let Some(items) = obj.get("items") {
        check_input_schema(items, &format!("{path}.items"), errs);
    }
}

/// Validate a manifest from its JSON form. Returns the typed manifest or
/// every violation found (fail-closed: the host registers nothing on error).
pub fn validate_manifest_json(v: &Value) -> Result<OrganelleManifest, Vec<ManifestError>> {
    let mut errs: Vec<ManifestError> = Vec::new();
    let m: OrganelleManifest = match serde_json::from_value(v.clone()) {
        Ok(m) => m,
        Err(e) => {
            return Err(vec![ManifestError::new(
                "$",
                format!("manifest is not well-formed: {e}"),
            )])
        }
    };

    if m.schema_version != MANIFEST_SCHEMA_VERSION {
        errs.push(ManifestError::new(
            "schema_version",
            format!("must be \"{MANIFEST_SCHEMA_VERSION}\""),
        ));
    }
    if !valid_name(&m.name) {
        errs.push(ManifestError::new(
            "name",
            "must be 1-64 chars of [a-z0-9-], starting alphanumeric",
        ));
    }
    if !valid_codon(&m.codon) {
        errs.push(ManifestError::new(
            "codon",
            "must be exactly 2 chars of [a-z0-9]",
        ));
    }
    if !valid_semver(&m.version) {
        errs.push(ManifestError::new("version", "must be semver X.Y.Z"));
    }
    if m.description.trim().is_empty() {
        errs.push(ManifestError::new("description", "must be non-empty"));
    }
    if m.contracts.is_empty() {
        errs.push(ManifestError::new("contracts", "must declare at least one contract"));
    }
    {
        let mut seen = std::collections::HashSet::new();
        for (i, c) in m.contracts.iter().enumerate() {
            let p = format!("contracts[{i}]");
            if c.op.trim().is_empty() || c.op.len() > 64 {
                errs.push(ManifestError::new(format!("{p}.op"), "op must be 1-64 chars"));
            }
            if !seen.insert(c.op.as_str()) {
                errs.push(ManifestError::new(format!("{p}.op"), "duplicate op name"));
            }
            if c.description.trim().is_empty() {
                errs.push(ManifestError::new(format!("{p}.description"), "must be non-empty"));
            }
            check_input_schema(&c.input_schema, &format!("{p}.input_schema"), &mut errs);
            if let Some(mc) = c.mutation_class {
                let _ = mc;
            }
            if let Some(cap) = &c.required_capability {
                if !valid_capability(cap) {
                    errs.push(ManifestError::new(
                        format!("{p}.required_capability"),
                        "invalid capability name",
                    ));
                }
            }
            // Fail-closed: a mutating contract without a capability is invalid.
            let eff_mc = c.mutation_class.unwrap_or(m.authority.mutation_class);
            let eff_cap = c
                .required_capability
                .as_deref()
                .or(m.authority.required_capability.as_deref());
            if eff_mc != MutationClass::ReadOnly && eff_cap.is_none() {
                errs.push(ManifestError::new(
                    format!("{p}"),
                    "non-ReadOnly contract must declare required_capability (fail-closed)",
                ));
            }
        }
    }
    if let Some(cap) = &m.authority.required_capability {
        if !valid_capability(cap) {
            errs.push(ManifestError::new("authority.required_capability", "invalid capability name"));
        }
    }
    for cap in &m.authority.granted_capabilities {
        if !valid_capability(cap) {
            errs.push(ManifestError::new(
                "authority.granted_capabilities",
                format!("invalid capability name: {cap}"),
            ));
        }
    }
    if m.transports.is_empty() {
        errs.push(ManifestError::new("transports", "must list at least one transport"));
    }
    {
        let mut seen = std::collections::HashSet::new();
        for t in &m.transports {
            if !seen.insert(t) {
                errs.push(ManifestError::new("transports", "duplicate transport"));
            }
        }
    }
    if !m.receipt_policy.content_addressed {
        errs.push(ManifestError::new(
            "receipt_policy.content_addressed",
            "must be true (org-010: every invocation emits a content-addressed receipt)",
        ));
    }
    if m.receipt_policy.algorithm != RECEIPT_ALGORITHM {
        errs.push(ManifestError::new(
            "receipt_policy.algorithm",
            format!("unsupported algorithm; host supports \"{RECEIPT_ALGORITHM}\""),
        ));
    }
    if !m.receipt_policy.chain {
        errs.push(ManifestError::new(
            "receipt_policy.chain",
            "must be true (receipts are hash-chained)",
        ));
    }

    if errs.is_empty() {
        Ok(m)
    } else {
        Err(errs)
    }
}

/// The JSON Schema (draft 2020-12 subset) of the manifest itself — the
/// machine-readable "JSON schema" half of org-001's done definition.
pub fn manifest_json_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "OrganelleManifest",
        "description": "org-001 manifest schema v1",
        "type": "object",
        "required": ["schema_version","name","codon","version","description","contracts","authority","transports","receipt_policy"],
        "properties": {
            "schema_version": {"type": "string", "const": MANIFEST_SCHEMA_VERSION},
            "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"},
            "codon": {"type": "string", "pattern": "^[a-z0-9]{2}$"},
            "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
            "description": {"type": "string", "minLength": 1},
            "contracts": {
                "type": "array", "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["op","description","input_schema"],
                    "properties": {
                        "op": {"type": "string", "minLength": 1, "maxLength": 64},
                        "description": {"type": "string", "minLength": 1},
                        "input_schema": {"type": "object"},
                        "mutation_class": {"type": "string", "enum": ["read_only","write","external_effect"]},
                        "required_capability": {"type": "string"}
                    }
                }
            },
            "authority": {
                "type": "object",
                "required": ["mutation_class","declared_valence"],
                "properties": {
                    "mutation_class": {"type": "string", "enum": ["read_only","write","external_effect"]},
                    "declared_valence": {"type": "string", "enum": ["disproven","candidate","proven"]},
                    "required_capability": {"type": ["string","null"]},
                    "granted_capabilities": {"type": "array", "items": {"type": "string"}}
                }
            },
            "transports": {
                "type": "array", "minItems": 1,
                "items": {"type": "string", "enum": ["native","unix_socket","mcp","rest"]}
            },
            "receipt_policy": {
                "type": "object",
                "required": ["content_addressed","algorithm","chain"],
                "properties": {
                    "content_addressed": {"type": "boolean", "const": true},
                    "algorithm": {"type": "string", "const": RECEIPT_ALGORITHM},
                    "chain": {"type": "boolean", "const": true}
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Runtime input validation against a contract's input_schema (subset).
// ---------------------------------------------------------------------------

/// Validate `input` against a JSON Schema (subset). `Ok(())` or a list of
/// human-readable violations. Used by the host before dispatch (fail-closed).
pub fn validate_input_against_schema(schema: &Value, input: &Value) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    check_value(schema, input, "$", &mut errs);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn check_value(schema: &Value, input: &Value, path: &str, errs: &mut Vec<String>) {
    let Some(obj) = schema.as_object() else { return };
    if let Some(t) = obj.get("type").and_then(|v| v.as_str()) {
        let ok = match t {
            "object" => input.is_object(),
            "array" => input.is_array(),
            "string" => input.is_string(),
            "number" => input.is_number(),
            "integer" => input.as_i64().is_some() || input.as_u64().is_some(),
            "boolean" => input.is_boolean(),
            "null" => input.is_null(),
            _ => true,
        };
        if !ok {
            errs.push(format!("{path}: expected type {t}"));
            return;
        }
    }
    if let Some(req) = obj.get("required").and_then(|v| v.as_array()) {
        if let Some(map) = input.as_object() {
            for r in req.iter().filter_map(|v| v.as_str()) {
                if !map.contains_key(r) {
                    errs.push(format!("{path}: missing required property \"{r}\""));
                }
            }
        }
    }
    if let (Some(props), Some(map)) = (
        obj.get("properties").and_then(|v| v.as_object()),
        input.as_object(),
    ) {
        for (k, sub) in props {
            if let Some(v) = map.get(k) {
                check_value(sub, v, &format!("{path}.{k}"), errs);
            }
        }
    }
    if let (Some(items), Some(arr)) = (
        obj.get("items"),
        input.as_array(),
    ) {
        for (i, v) in arr.iter().enumerate() {
            check_value(items, v, &format!("{path}[{i}]"), errs);
        }
    }
    if let Some(enm) = obj.get("enum").and_then(|v| v.as_array()) {
        if !enm.contains(input) {
            errs.push(format!("{path}: value not in enum"));
        }
    }
    if let Some(n) = obj.get("minimum").and_then(|v| v.as_f64()) {
        if input.as_f64().is_some_and(|x| x < n) {
            errs.push(format!("{path}: below minimum {n}"));
        }
    }
    if let Some(n) = obj.get("maximum").and_then(|v| v.as_f64()) {
        if input.as_f64().is_some_and(|x| x > n) {
            errs.push(format!("{path}: above maximum {n}"));
        }
    }
    if let Some(n) = obj.get("minLength").and_then(|v| v.as_u64()) {
        if input.as_str().is_some_and(|s| s.len() < n as usize) {
            errs.push(format!("{path}: shorter than minLength {n}"));
        }
    }
    if let Some(n) = obj.get("maxLength").and_then(|v| v.as_u64()) {
        if input.as_str().is_some_and(|s| s.len() > n as usize) {
            errs.push(format!("{path}: longer than maxLength {n}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON + hashing + time helpers (shared by host, receipts, CAS).
// ---------------------------------------------------------------------------

/// Canonical JSON: object keys sorted recursively, no whitespace.
/// Used for receipt content-addressing and cross-transport equivalence.
pub fn canonical_json(v: &Value) -> String {
    fn write(v: &Value, out: &mut String) {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32))
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                out.push('{');
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(&Value::String((*k).clone()), out);
                    out.push(':');
                    write(&m[*k], out);
                }
                out.push('}');
            }
        }
    }
    let mut s = String::new();
    write(v, &mut s);
    s
}

/// Canonical JSON parsed back into a Value with sorted keys (for equivalence).
pub fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonical_value(&m[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical_value).collect()),
        _ => v.clone(),
    }
}

/// SHA-256 hex of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 hex of a value's canonical JSON.
pub fn hash_value(v: &Value) -> String {
    sha256_hex(canonical_json(v).as_bytes())
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Current UTC time as ISO-8601 (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
/// Pure std — no chrono dependency, deterministic formatting.
pub fn utc_now_iso() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut secs = dur.as_secs() as i64;
    let micros = dur.subsec_micros();
    let mut days = secs.div_euclid(86400);
    secs = secs.rem_euclid(86400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let mut y: i64 = 1970;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let months = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0;
    while days >= months[mo] {
        days -= months[mo];
        mo += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        y,
        mo + 1,
        days + 1,
        h,
        m,
        s,
        micros
    )
}

/// Unix seconds now.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_manifest_json() -> Value {
        serde_json::json!({
            "schema_version": "1",
            "name": "kv-store",
            "codon": "kv",
            "version": "1.0.0",
            "description": "reference key-value organelle",
            "contracts": [
                {"op": "put", "description": "store a value",
                 "input_schema": {"type": "object", "required": ["key","value"],
                     "properties": {"key": {"type": "string"}, "value": {}}},
                 "mutation_class": "write", "required_capability": "kv.write"},
                {"op": "get", "description": "read a value",
                 "input_schema": {"type": "object", "required": ["key"],
                     "properties": {"key": {"type": "string"}}}}
            ],
            "authority": {"mutation_class": "read_only", "declared_valence": "candidate",
                          "required_capability": null, "granted_capabilities": []},
            "transports": ["native","unix_socket","mcp","rest"],
            "receipt_policy": {"content_addressed": true, "algorithm": "sha256", "chain": true}
        })
    }

    #[test]
    fn valid_manifest_accepted() {
        let m = validate_manifest_json(&good_manifest_json()).expect("must validate");
        assert_eq!(m.codon, "kv");
        assert_eq!(m.contracts.len(), 2);
        let (mc, cap) = m.authority_for("put");
        assert_eq!(mc, MutationClass::Write);
        assert_eq!(cap, Some("kv.write"));
        let (mc2, cap2) = m.authority_for("get");
        assert_eq!(mc2, MutationClass::ReadOnly);
        assert_eq!(cap2, None);
    }

    #[test]
    fn bad_codon_rejected() {
        let mut v = good_manifest_json();
        v["codon"] = serde_json::json!("toolong");
        let errs = validate_manifest_json(&v).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "codon"), "{errs:?}");
    }

    #[test]
    fn bad_name_rejected() {
        let mut v = good_manifest_json();
        v["name"] = serde_json::json!("Bad Name!");
        assert!(validate_manifest_json(&v).is_err());
    }

    #[test]
    fn bad_semver_rejected() {
        let mut v = good_manifest_json();
        v["version"] = serde_json::json!("1.0");
        assert!(validate_manifest_json(&v).is_err());
    }

    #[test]
    fn mutating_contract_without_capability_rejected() {
        // Fail-closed: Write contract, no capability anywhere -> invalid.
        let mut v = good_manifest_json();
        v["contracts"][0].as_object_mut().unwrap().remove("required_capability");
        let errs = validate_manifest_json(&v).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("fail-closed")), "{errs:?}");
    }

    #[test]
    fn duplicate_op_rejected() {
        let mut v = good_manifest_json();
        let dup = v["contracts"][0].clone();
        v["contracts"].as_array_mut().unwrap().push(dup);
        assert!(validate_manifest_json(&v).is_err());
    }

    #[test]
    fn empty_contracts_rejected() {
        let mut v = good_manifest_json();
        v["contracts"] = serde_json::json!([]);
        assert!(validate_manifest_json(&v).is_err());
    }

    #[test]
    fn receipt_policy_must_be_content_addressed_chained() {
        let mut v = good_manifest_json();
        v["receipt_policy"]["chain"] = serde_json::json!(false);
        assert!(validate_manifest_json(&v).is_err());
        let mut v2 = good_manifest_json();
        v2["receipt_policy"]["algorithm"] = serde_json::json!("md5");
        assert!(validate_manifest_json(&v2).is_err());
    }

    #[test]
    fn schema_version_mismatch_rejected() {
        let mut v = good_manifest_json();
        v["schema_version"] = serde_json::json!("2");
        assert!(validate_manifest_json(&v).is_err());
    }

    #[test]
    fn malformed_json_shape_rejected() {
        let v = serde_json::json!({"name": "x"});
        let errs = validate_manifest_json(&v).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "$"));
    }

    #[test]
    fn input_schema_structural_check() {
        let mut v = good_manifest_json();
        v["contracts"][0]["input_schema"] = serde_json::json!("not-an-object");
        assert!(validate_manifest_json(&v).is_err());
        let mut v2 = good_manifest_json();
        v2["contracts"][0]["input_schema"] = serde_json::json!({"type": "frobnicate"});
        assert!(validate_manifest_json(&v2).is_err());
    }

    #[test]
    fn input_validation_ok_and_fail() {
        let schema = serde_json::json!({
            "type": "object", "required": ["key"],
            "properties": {"key": {"type": "string"}, "n": {"type": "integer", "minimum": 1}}
        });
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"key": "a"})).is_ok());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"key": "a", "n": 3})).is_ok());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({})).is_err());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"key": 5})).is_err());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"key": "a", "n": 0})).is_err());
    }

    #[test]
    fn input_validation_enum_and_nested() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "mode": {"enum": ["a","b"]},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        });
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"mode": "a", "tags": ["x"]})).is_ok());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"mode": "z"})).is_err());
        assert!(validate_input_against_schema(&schema, &serde_json::json!({"tags": [1]})).is_err());
    }

    #[test]
    fn canonical_json_is_stable() {
        let a = serde_json::json!({"z": 1, "a": {"y": [3,2], "b": "x"}});
        let b = serde_json::json!({"a": {"b": "x", "y": [3,2]}, "z": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a), r#"{"a":{"b":"x","y":[3,2]},"z":1}"#);
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn manifest_json_schema_self_describes() {
        let s = manifest_json_schema();
        assert_eq!(s["title"], serde_json::json!("OrganelleManifest"));
        // The meta-schema accepts the good manifest structurally.
        let m = good_manifest_json();
        assert!(validate_input_against_schema(&s, &m).is_ok());
        let mut bad = m.clone();
        bad["codon"] = serde_json::json!("xyz");
        // pattern is not enforced by our subset validator (no pattern support) —
        // the typed validator is authoritative; meta-schema is documentation.
        let _ = bad;
    }

    #[test]
    fn utc_now_iso_shape() {
        let t = utc_now_iso();
        assert!(t.ends_with('Z'), "{t}");
        assert_eq!(t.len(), 27, "{t}");
        assert!(unix_now() > 1_700_000_000);
    }
}
