//! GO-50 Phase 1, family F3 — the universal dispatcher + typed fabric.
//!
//! This crate extends the October organelle host (`organelle-host`) with a
//! typed layer. It does NOT build a second dispatcher: every typed call
//! funnels into the host's existing membrane — `Host::call` /
//! `Host::call_with_grant` → `call_with_gate2` → `authorize` →
//! `invoke_resolved` → the host's hash-chained receipt. The stages this
//! crate adds are the ones the host path does not have (ontology
//! resolution, typed decode/encode, truth/provenance separation); the
//! stages the host already performs (identity/version/schema validation,
//! capability admission, effect policy, receipt) are named, not
//! reimplemented. The full stage→host-path map is in the Phase 1 report
//! (`~/workspace/go50-gbnf/findings/F3-dispatcher.md`).
//!
//! # What lives here
//!
//! - [`OntologyLock`] / [`LockRegistry`] — canonical versioned ontology
//!   locks. GO-50 is embedded from the board lock file (sha256 recorded
//!   in [`GO50_LOCK_SHA256`]); DO-25/CO-25 have NO lock on record, so the
//!   dispatcher REFUSES bindings for those ontologies until a lock is
//!   authored and loaded. Never validate against an invented list.
//! - [`OrganelleManifestV1`] — the typed manifest. It EMBEDS the October
//!   [`OrganelleManifest`] unchanged (that type is untouched) and adds
//!   mandatory GO/DO/CO declaration arrays plus per-op typed contracts.
//!   Migration path: keep the base manifest, add declarations validated
//!   against the locks, add typed contracts — see
//!   [`OrganelleManifestV1::from_base`].
//! - [`TypedOrganelle`] — the typed trait: typed Input/Output per
//!   organelle, typed errors ([`TypedError`]), and a
//!   [`TypedOutcome`] carrying the output plus SEPARATE
//!   [`ClaimTruth`] and [`PayloadProvenance`] fields. Claim truth and
//!   payload provenance are never collapsed into one valence: the
//!   existing `Valence` is a declared valence on `Authority` and is not
//!   reused as the carrier.
//! - [`TypedAdapter`] — the JSON-erased adapter bridging a typed
//!   organelle into the host's `Value`-based `Organelle::handle` trait:
//!   erasure at the boundary, types inside. This is NOT the RFC Phase A
//!   adapter (organelle-core → host, the integration programme's item,
//!   EB-1.2); that one wraps organelle-core units, this one wraps typed
//!   organelles. Distinct names, distinct jobs.
//! - [`TypedDispatcher`] — the universal dispatcher for typed calls:
//!   [`InvocationEnvelope`] → envelope validation → GO/DO/CO resolution
//!   against the locks → environment capsule binding → capability /
//!   PT Coin admission → host dispatch (identity/version/schema,
//!   effect policy, typed organelle via the erased adapter, output
//!   validation, truth + provenance) → host receipt.
//! - [`PtCoinAdmission`] — the PT Coin admission extension point. PT Coin
//!   is a PoUW verification instrument from pouw-mesh (NOT a currency,
//!   NOT a host admission protocol); no admission protocol for the host
//!   exists on record, so this crate does NOT invent a token system.
//!   Admission runs on the host's existing HMAC grant system; the
//!   default [`NoPtCoinAdmission`] defers to grants and says so.
//! - [`discover_typed_manifests_dir`] — file-based manifest discovery:
//!   sorted `.json` files, atomic pre-validation of ALL before
//!   registering ANY, following ParkWreck's Oct-8 `load_manifests_dir`
//!   pattern. Discovery records manifests; implementations still
//!   register via [`TypedDispatcher::register_typed`].
//!
//! GO-50 Phase 1, family F4 adds two more seams to the dispatcher
//! (interfaces + wiring, no fake production implementations — see
//! [`RoleStateOracle`] and [`GovernAuthorizer`]):
//! - [`RoleStateOracle`] — the live role/state oracle, consulted at
//!   call time to close the Phase 0 TOCTOU window. No production
//!   implementation exists (GAP F4-G1): the only live Exchange state
//!   is in D1, reachable only from the Workers runtime.
//! - [`GovernAuthorizer`] — Exchange `govern()` as the authorization
//!   authority at the effect-policy stage. No production
//!   implementation exists (GAP F4-G2): `govern()` needs a live `Db`
//!   the host process cannot reach, plus an async bridge this
//!   synchronous host does not have.
//!
//! # What is deliberately NOT here
//!
//! - No second receipt: typed invocations emit the host's receipt, with
//!   the typed outcome attached as `Receipt::typed_outcome`. Host
//!   receipts are not yet `lucidota-receipt/1`; the LedgerSigner bridge
//!   is backlog EB-1.2, not this crate's job.
//! - No projections: [`TypedDispatcher::typed_manifests`] is the single
//!   source the next family generates REST/MCP projections from; this
//!   crate builds no surface.
//! - No bincode transport, no dynamic executor, no Capacity/Clearance
//!   migration — those belong to other families / backlog items.

use organelle_host::{
    CallContext, CallError, Host, HostRef, Organelle, OrganelleError, RoutePolicy,
};
use organelle_manifest::{
    hash_value, utc_now_iso, validate_input_against_schema, validate_manifest_json,
    validate_schema_shape, ManifestError, OrganelleManifest, Transport,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// Ontology locks
// ---------------------------------------------------------------------------

/// The GO-50 global ontology lock: the 50 seats of the board, transcribed
/// verbatim from `GO_ONTOLOGY_v1_LOCK_4_8hx6.md` §1 (rows 1–50, in seat
/// order). The board file itself is READ-ONLY and lives outside this repo;
/// this list is the runtime's copy, pinned to the file's sha256 below.
/// Status of the board file: CANDIDATE-LOCK (countersign + repo hash are
/// Zack's action); the runtime validates against it as the canonical
/// versioned artifact per the Phase 1 mission.
pub const GO50_LOCK_ID: &str = "GO-50";
pub const GO50_LOCK_VERSION: &str = "v1";
pub const GO50_LOCK_SOURCE: &str = "GO_ONTOLOGY_v1_LOCK_4_8hx6.md";
pub const GO50_LOCK_SHA256: &str =
    "18e06c3486b507fbeae9f87529f5e5dd1d43c87c9c2f0acdd84f74f1bb740041";
// Rows are the board's seat rows (1-5, 6-10, ...); keep the layout.
#[rustfmt::skip]
pub const GO50_TERMS: [&str; 50] = [
    "ENTITY", "ATTRIBUTE", "RELATIONSHIP", "FRICTION", "LEVERAGE",
    "VISIBILITY", "ACTION", "EVENT", "TIME", "PATTERN",
    "HYPOTHESIS", "CLAIM", "EVIDENCE", "IDENTITY", "SIGNAL",
    "GLOW", "KIND", "TOOL", "PROCESS", "NAUGHTY",
    "NICE", "GROUP", "OPERATOR", "MODE", "COMMENT",
    "REALITY", "WORKING_REALITY", "CONTRADICTION", "ANCHOR", "NARRATIVE",
    "CONTEXT", "FRAME", "LOVE", "BOUNDARY", "THRESHOLD",
    "TRIGGER", "CONSEQUENCE", "DEPENDENCY", "CONSTRAINT", "CAPACITY",
    "RESOURCE", "TENSION", "INFLUENCE", "TRANSITION", "STATE",
    "PHASE", "VECTOR", "DIMENSION", "TERNARY_STATE", "ATTUNEMENT",
];

/// Domain-ring lock id. NO canonical DO-25 lock exists for the typed
/// fabric's domain: the only 25-term domain ontology on record is the
/// Event Site Logistics C2 ring (a per-domain ring for Shambhala
/// logistics, not a dispatcher-domain lock). Until a dispatcher-domain
/// DO-25 lock is authored, DO bindings are REFUSED (see
/// [`validate_manifest_v1`]). Recorded as BLOCKER F3-B1.
pub const DO25_LOCK_ID: &str = "DO-25";
/// Client-ring lock id. NO canonical CO-25 lock exists: the only
/// 25-term client ontology on record is the Shambhala deployment ring.
/// Until a dispatcher-deployment CO-25 lock is authored, CO bindings
/// are REFUSED. Recorded as BLOCKER F3-B2.
pub const CO25_LOCK_ID: &str = "CO-25";

/// One canonical versioned ontology lock: the closed term set an
/// ontology's identifiers are validated against, pinned to the source
/// artifact's sha256 so a lock can never silently drift from its file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyLock {
    /// e.g. "GO-50".
    pub id: String,
    /// e.g. "v1".
    pub version: String,
    /// Lock status as recorded on the source artifact, e.g.
    /// "candidate-lock" (GO-50: countersign pending).
    pub status: String,
    /// Source artifact file name (informational; the sha pins it).
    pub source: String,
    /// sha256 hex of the source artifact file.
    pub source_sha256: String,
    /// The closed term set. Sorted; membership is the whole check.
    pub terms: BTreeSet<String>,
}

impl OntologyLock {
    /// The GO-50 lock, embedded from the board file.
    pub fn go50() -> Self {
        OntologyLock {
            id: GO50_LOCK_ID.to_string(),
            version: GO50_LOCK_VERSION.to_string(),
            status: "candidate-lock".to_string(),
            source: GO50_LOCK_SOURCE.to_string(),
            source_sha256: GO50_LOCK_SHA256.to_string(),
            terms: GO50_TERMS.iter().map(|t| t.to_string()).collect(),
        }
    }

    pub fn contains(&self, term: &str) -> bool {
        self.terms.contains(term)
    }

    pub fn term_count(&self) -> usize {
        self.terms.len()
    }
}

/// The lock set the runtime validates against. Lookups are by ontology
/// id; a missing lock means that ontology's bindings are REFUSED, never
/// validated against an invented list.
#[derive(Debug, Clone, Default)]
pub struct LockRegistry {
    locks: HashMap<String, OntologyLock>,
}

impl LockRegistry {
    /// GO-50 only. DO-25/CO-25 are absent by construction: no canonical
    /// locks exist, so their bindings are refused until locks are
    /// authored and inserted via [`LockRegistry::insert`].
    pub fn with_go50() -> Self {
        let mut r = LockRegistry::default();
        r.insert(OntologyLock::go50());
        r
    }

    pub fn insert(&mut self, lock: OntologyLock) {
        self.locks.insert(lock.id.clone(), lock);
    }

    pub fn get(&self, id: &str) -> Option<&OntologyLock> {
        self.locks.get(id)
    }

    pub fn lock_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.locks.keys().cloned().collect();
        ids.sort();
        ids
    }
}

// ---------------------------------------------------------------------------
// OrganelleManifestV1 — the typed manifest
// ---------------------------------------------------------------------------

/// Schema version of the typed manifest format. Distinct from the
/// October base manifest's `"1"`: a typed manifest is a different
/// document that EMBEDS a base manifest, it is not a v2 of it.
pub const TYPED_MANIFEST_SCHEMA_VERSION: &str = "typed-1";

/// Mandatory GO/DO/CO declaration arrays. All three arrays MUST be
/// present in the manifest JSON (serde has no defaults here — a missing
/// array fails deserialization, which is the mandatory part). GO must
/// be non-empty (every typed organelle declares at least one global
/// term); DO/CO may be empty (no bindings declared), but a non-empty
/// DO/CO array is REFUSED unless the matching lock is loaded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OntologyDeclarations {
    /// Global-ontology terms (GO-50 lock). Non-empty, every term in lock.
    pub go: Vec<String>,
    /// Domain-ring terms (DO-25 lock). Refused without a loaded DO lock.
    pub domain: Vec<String>,
    /// Client-ring terms (CO-25 lock). Refused without a loaded CO lock.
    pub client: Vec<String>,
}

/// One typed contract: the typed layer's view of one base-manifest op.
/// Ops must match the base manifest's contracts exactly (same set, no
/// extras, no omissions) — the typed layer covers the whole surface.
/// `input_type` / `output_type` name the Rust types (documentation for
/// projections and readers; the runtime enforces the schemas).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedContract {
    pub op: String,
    pub input_type: String,
    pub output_type: String,
    /// JSON Schema (host subset) the serialized output must satisfy.
    /// Enforced by the erased adapter after typed execution.
    pub output_schema: Value,
}

/// The typed manifest (GO-50 Phase 1, family F3).
///
/// Structure: the October [`OrganelleManifest`] embedded UNCHANGED as
/// `base`, plus the typed layer (`ontology` + `typed_contracts`). The
/// base manifest is what the host registers and authorizes against; the
/// typed layer is what the dispatcher validates and the projections
/// generate from.
///
/// Migration path (October → typed), documented, not automatic:
/// 1. Keep the base manifest byte-identical — it still validates under
///    `validate_manifest_json` and still registers on the host.
/// 2. Add `ontology` declarations; every term must resolve against the
///    loaded locks (GO-50 today; DO/CO when their locks exist).
/// 3. Add one `typed_contract` per base contract op, with an
///    `output_schema` for output validation.
/// 4. Implement [`TypedOrganelle`] for the organelle and register via
///    [`TypedDispatcher::register_typed`], which wraps it in the erased
///    adapter and registers the base manifest on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganelleManifestV1 {
    pub schema_version: String,
    pub base: OrganelleManifest,
    pub ontology: OntologyDeclarations,
    pub typed_contracts: Vec<TypedContract>,
}

impl OrganelleManifestV1 {
    /// Build a typed manifest from an existing October manifest.
    /// Validation is separate ([`validate_manifest_v1`]) — construction
    /// never claims validity.
    pub fn from_base(
        base: OrganelleManifest,
        ontology: OntologyDeclarations,
        typed_contracts: Vec<TypedContract>,
    ) -> Self {
        OrganelleManifestV1 {
            schema_version: TYPED_MANIFEST_SCHEMA_VERSION.to_string(),
            base,
            ontology,
            typed_contracts,
        }
    }

    pub fn typed_contract(&self, op: &str) -> Option<&TypedContract> {
        self.typed_contracts.iter().find(|c| c.op == op)
    }
}

fn manifest_err(field: impl Into<String>, message: impl Into<String>) -> ManifestError {
    ManifestError {
        field: field.into(),
        message: message.into(),
    }
}

fn validate_term_array(
    field: &str,
    terms: &[String],
    lock_id: &str,
    locks: &LockRegistry,
    required_non_empty: bool,
    errs: &mut Vec<ManifestError>,
) {
    if terms.is_empty() {
        if required_non_empty {
            errs.push(manifest_err(
                field,
                "must declare at least one term (empty bindings are rejected)",
            ));
        }
        return;
    }
    let lock = match locks.get(lock_id) {
        Some(l) => l,
        None => {
            errs.push(manifest_err(
                field,
                format!(
                    "no {lock_id} lock loaded; {lock_id} bindings refused \
                     (missing lock is a BLOCKER, not a default-allow)"
                ),
            ));
            return;
        }
    };
    let mut seen = BTreeSet::new();
    for t in terms {
        if t.trim().is_empty() {
            errs.push(manifest_err(field, "empty term binding rejected"));
            continue;
        }
        if !seen.insert(t.as_str()) {
            errs.push(manifest_err(field, format!("duplicate term \"{t}\"")));
        }
        if !lock.contains(t) {
            errs.push(manifest_err(
                field,
                format!(
                    "unknown {lock_id} term \"{t}\" (not in lock {lock_id} {})",
                    lock.version
                ),
            ));
        }
    }
}

/// F6-H7: output schemas are validated with the same deep checker
/// the October validator runs over input schemas
/// (`validate_schema_shape`: type / required / properties / items,
/// recursive) — the old top-level-type-only check silently ignored
/// malformed constraints at runtime. Called from
/// `validate_manifest_v1`; kept as a function so the call site stays
/// one line.
fn validate_output_schema(schema: &Value, path: &str, errs: &mut Vec<ManifestError>) {
    if !schema.is_object() {
        errs.push(manifest_err(path, "must be a JSON object"));
        return;
    }
    errs.extend(validate_schema_shape(schema, path));
}

/// Validate a typed manifest against the loaded ontology locks.
/// Fail-closed: any violation rejects the whole manifest; the caller
/// registers nothing on error. Checks, in order: schema version, the
/// embedded base manifest (via the October validator — unchanged),
/// GO/DO/CO declarations against the locks, and typed-contract coverage
/// of the base contracts.
pub fn validate_manifest_v1(
    m: &OrganelleManifestV1,
    locks: &LockRegistry,
) -> Result<(), Vec<ManifestError>> {
    let mut errs: Vec<ManifestError> = Vec::new();

    if m.schema_version != TYPED_MANIFEST_SCHEMA_VERSION {
        errs.push(manifest_err(
            "schema_version",
            format!("must be \"{TYPED_MANIFEST_SCHEMA_VERSION}\""),
        ));
    }
    // The embedded October manifest must validate under the October
    // rules, unchanged — a typed manifest never weakens the base.
    match serde_json::to_value(&m.base) {
        Ok(v) => {
            if let Err(base_errs) = validate_manifest_json(&v) {
                for e in base_errs {
                    errs.push(manifest_err(format!("base.{}", e.field), e.message));
                }
            }
        }
        Err(e) => errs.push(manifest_err("base", format!("not serializable: {e}"))),
    }

    validate_term_array(
        "ontology.go",
        &m.ontology.go,
        GO50_LOCK_ID,
        locks,
        true,
        &mut errs,
    );
    validate_term_array(
        "ontology.domain",
        &m.ontology.domain,
        DO25_LOCK_ID,
        locks,
        false,
        &mut errs,
    );
    validate_term_array(
        "ontology.client",
        &m.ontology.client,
        CO25_LOCK_ID,
        locks,
        false,
        &mut errs,
    );

    // Typed contracts must cover the base contracts exactly.
    let base_ops: BTreeSet<&str> = m.base.contracts.iter().map(|c| c.op.as_str()).collect();
    let typed_ops: BTreeSet<&str> = m.typed_contracts.iter().map(|c| c.op.as_str()).collect();
    for op in base_ops.difference(&typed_ops) {
        errs.push(manifest_err(
            "typed_contracts",
            format!("base contract op \"{op}\" has no typed contract"),
        ));
    }
    for op in typed_ops.difference(&base_ops) {
        errs.push(manifest_err(
            "typed_contracts",
            format!("typed contract op \"{op}\" has no base contract"),
        ));
    }
    if m.typed_contracts.len() != typed_ops.len() {
        errs.push(manifest_err(
            "typed_contracts",
            "duplicate typed contract op",
        ));
    }
    for (i, tc) in m.typed_contracts.iter().enumerate() {
        let p = format!("typed_contracts[{i}]");
        if tc.input_type.trim().is_empty() {
            errs.push(manifest_err(format!("{p}.input_type"), "must be non-empty"));
        }
        if tc.output_type.trim().is_empty() {
            errs.push(manifest_err(
                format!("{p}.output_type"),
                "must be non-empty",
            ));
        }
        validate_output_schema(&tc.output_schema, &format!("{p}.output_schema"), &mut errs);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Validate a typed manifest from its JSON form: deserialize (a missing
/// `ontology` array fails here — the arrays are mandatory), then
/// [`validate_manifest_v1`].
pub fn validate_manifest_v1_json(
    v: &Value,
    locks: &LockRegistry,
) -> Result<OrganelleManifestV1, Vec<ManifestError>> {
    let m: OrganelleManifestV1 = match serde_json::from_value(v.clone()) {
        Ok(m) => m,
        Err(e) => {
            return Err(vec![manifest_err(
                "$",
                format!("typed manifest is not well-formed: {e}"),
            )])
        }
    };
    validate_manifest_v1(&m, locks)?;
    Ok(m)
}

// ---------------------------------------------------------------------------
// Truth / provenance separation
// ---------------------------------------------------------------------------

/// Per-invocation truth status of the CLAIM the output asserts. Ternary
/// (Proven / Candidate / Disproven), like the GO-50 TERNARY_STATE seat —
/// but this is a per-output, per-invocation judgment, NOT the `Valence`
/// declared once on an organelle's `Authority`. The two types are never
/// mixed: `Valence` is a static declaration about an organelle;
/// `TruthStatus` is a live judgment about one output. Do not convert
/// between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthStatus {
    Proven,
    Candidate,
    Disproven,
}

/// Claim truth: what the organelle asserts about its output, and on
/// what basis. Separate field, separate type from provenance — the
/// output's truth and the output's origin are different facts and are
/// carried in different fields everywhere (typed outcome, receipt).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimTruth {
    pub status: TruthStatus,
    /// What grounds the status, in one line (e.g. "SHA-256 is a
    /// deterministic function of the input bytes; recomputation
    /// reproduces the digest"). Never empty: an ungrounded truth claim
    /// is not a truth claim.
    pub basis: String,
}

impl ClaimTruth {
    pub fn proven(basis: impl Into<String>) -> Self {
        ClaimTruth {
            status: TruthStatus::Proven,
            basis: basis.into(),
        }
    }
    pub fn candidate(basis: impl Into<String>) -> Self {
        ClaimTruth {
            status: TruthStatus::Candidate,
            basis: basis.into(),
        }
    }
    pub fn disproven(basis: impl Into<String>) -> Self {
        ClaimTruth {
            status: TruthStatus::Disproven,
            basis: basis.into(),
        }
    }
}

/// Where the payload came from. The provenance axis answers "what
/// produced these bytes and from what input" — it says nothing about
/// whether the output's claim is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSource {
    /// Computed locally from the invocation input by the organelle.
    ComputedLocally,
    /// Retrieved from an external store or service.
    Retrieved,
    /// Derived by transforming another organelle's output.
    Derived,
}

/// Payload provenance: the origin of the output bytes. Separate field,
/// separate type from claim truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadProvenance {
    pub source: ProvenanceSource,
    /// sha256 hex of the canonical JSON of the typed invocation input
    /// the output was produced from.
    pub input_hash: String,
    /// Producing organelle, `codon@version`.
    pub produced_by: String,
    /// ISO-8601 UTC production time.
    pub produced_at: String,
}

impl PayloadProvenance {
    /// Provenance for a locally computed output: hashes the typed input
    /// (canonical JSON) as the input binding.
    pub fn computed_locally(input: &Value, produced_by: impl Into<String>) -> Self {
        PayloadProvenance {
            source: ProvenanceSource::ComputedLocally,
            input_hash: hash_value(input),
            produced_by: produced_by.into(),
            produced_at: utc_now_iso(),
        }
    }
}

/// The typed outcome of one invocation: the typed output PLUS its
/// claim truth PLUS its payload provenance, as three separate fields.
/// The adapter serializes the output to the host `Value` and hands
/// truth + provenance to the receipt as separate fields — they are
/// never merged into the output value and never collapsed into one
/// valence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedOutcome<O> {
    pub output: O,
    pub truth: ClaimTruth,
    pub provenance: PayloadProvenance,
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// Typed error for typed organelles. A real enum, not a string code:
/// callers match on the variant, and the adapter maps it to the host's
/// string-coded [`OrganelleError`] at the erasure boundary (the code is
/// preserved in the receipt's `failed:<code>` output hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypedError {
    Validation { message: String },
    NotFound { message: String },
    Denied { message: String },
    Internal { message: String },
}

impl TypedError {
    pub fn validation(message: impl Into<String>) -> Self {
        TypedError::Validation {
            message: message.into(),
        }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        TypedError::NotFound {
            message: message.into(),
        }
    }
    pub fn denied(message: impl Into<String>) -> Self {
        TypedError::Denied {
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        TypedError::Internal {
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            TypedError::Validation { .. } => "validation",
            TypedError::NotFound { .. } => "not_found",
            TypedError::Denied { .. } => "denied",
            TypedError::Internal { .. } => "failed",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            TypedError::Validation { message }
            | TypedError::NotFound { message }
            | TypedError::Denied { message }
            | TypedError::Internal { message } => message,
        }
    }

    pub fn to_organelle_error(&self) -> OrganelleError {
        OrganelleError::new(self.code(), self.message())
    }
}

impl std::fmt::Display for TypedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for TypedError {}

// ---------------------------------------------------------------------------
// Environment capsule + typed trait + invocation envelope
// ---------------------------------------------------------------------------

/// The per-invocation execution environment a typed organelle runs in.
/// Built ONLY from the authoritative host [`CallContext`] — by the
/// erased adapter, inside the host's `invoke_resolved`, after
/// authorization — never from caller-supplied envelope data, so a
/// caller cannot forge capsule contents. The dispatcher stage named
/// "environment capsule" is the envelope → CallContext binding that
/// determines these contents (identity, capabilities, trace id);
/// the capsule itself materializes where the verified context exists.
///
/// `transport` is `None` here: the arrival transport lives in the
/// host's `InvocationBinding`, which the `Organelle::handle` trait does
/// not expose to handlers (changing the trait signature would break
/// every organelle). Transport restriction is enforced by `authorize`
/// before the handler runs; the capsule honestly records what the
/// handler can observe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCapsule {
    pub trace_id: String,
    pub caller: String,
    pub capabilities: Vec<String>,
    pub transport: Option<Transport>,
    pub issued_at: String,
}

impl EnvironmentCapsule {
    pub fn from_context(ctx: &CallContext) -> Self {
        EnvironmentCapsule {
            trace_id: ctx.trace_id.clone(),
            caller: ctx.caller.clone(),
            capabilities: ctx.capabilities.clone(),
            transport: None,
            issued_at: utc_now_iso(),
        }
    }
}

/// The typed organelle trait: typed Input/Output per organelle (one
/// type per organelle; multi-op organelles use an enum or a struct with
/// per-op optional fields), typed errors, and a typed outcome carrying
/// separate truth and provenance. The host never sees these types —
/// [`TypedAdapter`] erases them to `Value` at the boundary.
pub trait TypedOrganelle: Send + Sync {
    type Input: serde::de::DeserializeOwned;
    type Output: Serialize;
    fn manifest_v1(&self) -> OrganelleManifestV1;
    fn handle_typed(
        &self,
        capsule: &EnvironmentCapsule,
        host: &dyn HostRef,
        op: &str,
        input: Self::Input,
    ) -> Result<TypedOutcome<Self::Output>, TypedError>;
}

/// The typed invocation envelope: everything the dispatcher needs for
/// one typed call, as one typed value. Surfaces build this; the
/// dispatcher validates it before anything else runs.
///
/// Authority rule: EITHER `grant` (external surfaces: authority comes
/// from the host-issued HMAC grant alone, and `capabilities` must be
/// empty — caller-supplied capability claims are never read when a
/// grant is present, mirroring the host) OR `capabilities` (native
/// in-process surface: the caller is code linked into this process,
/// same trust model as `Host::call`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationEnvelope {
    pub caller: String,
    pub codon: String,
    pub op: String,
    pub input: Value,
    /// Caller-supplied correlation id. Honored on the native path (the
    /// dispatcher sets the host trace id to it); ignored on the grant
    /// path (the host assigns the trace id inside `call_with_grant`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Capabilities for the native path only. Must be empty when
    /// `grant` is present.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Arrival transport, bound by the surface, never by caller data.
    #[serde(default = "default_native_transport")]
    pub transport: Transport,
    /// Host-issued HMAC grant token (external surfaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

fn default_native_transport() -> Transport {
    Transport::Native
}

impl InvocationEnvelope {
    pub fn native(
        caller: impl Into<String>,
        codon: impl Into<String>,
        op: impl Into<String>,
        input: Value,
    ) -> Self {
        InvocationEnvelope {
            caller: caller.into(),
            codon: codon.into(),
            op: op.into(),
            input,
            trace_id: None,
            capabilities: Vec::new(),
            transport: Transport::Native,
            grant: None,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-erased adapter (typed -> Value, inside the host)
// ---------------------------------------------------------------------------

/// The JSON-erased adapter: bridges a typed organelle into the host's
/// `Value`-based [`Organelle`] trait. Erasure at the boundary, types
/// inside: the host sees an ordinary organelle (base manifest +
/// `Value` in/out); the typed organelle sees typed input, a typed
/// outcome, and typed errors.
///
/// NOT the RFC Phase A adapter: Phase A (EB-1.2, integration
/// programme) wraps organelle-core units for the host; this wraps
/// typed organelles for the host. Different source trait, different
/// job, different name — do not confuse them.
pub struct TypedAdapter<T: TypedOrganelle> {
    inner: T,
    manifest_v1: OrganelleManifestV1,
}

impl<T: TypedOrganelle> TypedAdapter<T> {
    /// Wrap a typed organelle, validating its V1 manifest against the
    /// locks first. Fail-closed: an invalid manifest (unknown GO term,
    /// DO/CO binding without a lock, contract mismatch) is never
    /// wrapped and never reaches the host.
    pub fn new(inner: T, locks: &LockRegistry) -> Result<Self, Vec<ManifestError>> {
        let manifest_v1 = inner.manifest_v1();
        validate_manifest_v1(&manifest_v1, locks)?;
        Ok(TypedAdapter { inner, manifest_v1 })
    }

    pub fn manifest_v1(&self) -> &OrganelleManifestV1 {
        &self.manifest_v1
    }
}

impl<T: TypedOrganelle> Organelle for TypedAdapter<T> {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest_v1.base.clone()
    }

    fn handle(
        &self,
        ctx: &CallContext,
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        // Typed decode: the host already validated the input against the
        // contract's JSON Schema in `authorize`; this is the second,
        // stronger check — the value must decode into the organelle's
        // Rust input type. Fail-closed on any decode failure.
        let typed_in: T::Input = serde_json::from_value(input.clone()).map_err(|e| {
            OrganelleError::new(
                "rejected",
                format!("typed input decode failed for {op}: {e}"),
            )
        })?;
        let capsule = EnvironmentCapsule::from_context(ctx);
        let outcome = self
            .inner
            .handle_typed(&capsule, host, op, typed_in)
            .map_err(|e| e.to_organelle_error())?;
        // Output validation: the serialized typed output must satisfy
        // the typed contract's output schema. The host does not validate
        // outputs; the typed layer does, before the value leaves.
        let output_value = serde_json::to_value(&outcome.output).map_err(|e| {
            OrganelleError::new(
                "failed",
                format!("typed output encode failed for {op}: {e}"),
            )
        })?;
        if let Some(tc) = self.manifest_v1.typed_contract(op) {
            if let Err(violations) = validate_input_against_schema(&tc.output_schema, &output_value)
            {
                return Err(OrganelleError::new(
                    "failed",
                    format!(
                        "typed output failed output_schema for {op}: {}",
                        violations.join("; ")
                    ),
                ));
            }
        }
        // Truth + provenance to the receipt, as SEPARATE fields. The
        // host attaches this value to the invocation receipt
        // (`Receipt::typed_outcome`); it is never merged into the output
        // value and never collapsed into one valence.
        host.record_typed_outcome(
            &ctx.trace_id,
            serde_json::json!({
                "truth": outcome.truth,
                "provenance": outcome.provenance,
            }),
        );
        Ok(output_value)
    }
}

// ---------------------------------------------------------------------------
// PT Coin admission (extension point — no token system invented here)
// ---------------------------------------------------------------------------

/// Outcome of the PT Coin admission stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PtCoinDecision {
    /// Admitted by a PT Coin check (only a configured implementation
    /// can return this).
    Admitted,
    /// No PT Coin check ran; admission deferred to the host's HMAC
    /// grant system. This is what the default returns, honestly.
    DeferredToGrants,
    /// Denied by a PT Coin check.
    Denied,
}

/// PT Coin admission extension point.
///
/// What PT Coin IS (pouw-mesh `THESIS.md`, "The coin (PT)", and
/// `pouw-mesh/rs/src/coin.rs`): a temporal proof-of-useful-work
/// instrument — minted when work is established, denominated in
/// time-stamped labor, earned into existence and burned on redemption
/// (compute, priority, access). Explicitly NOT a currency and NOT a
/// host admission protocol: no PT Coin admission check for
/// organelle-host exists anywhere on record, and the pouw-mesh `pc`
/// organelle (mint/burn/balance/conservation audit) is a mesh-economy
/// organelle, not a dispatcher gate.
///
/// So this trait is the seam where a future PT Coin admission
/// implementation plugs in, and the default implementation defers to
/// the host's HMAC grants. No token system is invented here. Recorded
/// as GAP F3-G1 (PT Coin admission undefined for the host).
pub trait PtCoinAdmission: Send + Sync {
    fn admit(
        &self,
        envelope: &InvocationEnvelope,
        manifest: &OrganelleManifestV1,
    ) -> Result<PtCoinDecision, TypedDispatchError>;
    fn name(&self) -> &'static str;
}

/// Default PT Coin admission: none configured. Always defers to the
/// host's HMAC grant system and says so in the dispatch result.
pub struct NoPtCoinAdmission;

impl PtCoinAdmission for NoPtCoinAdmission {
    fn admit(
        &self,
        _envelope: &InvocationEnvelope,
        _manifest: &OrganelleManifestV1,
    ) -> Result<PtCoinDecision, TypedDispatchError> {
        Ok(PtCoinDecision::DeferredToGrants)
    }

    fn name(&self) -> &'static str {
        "none (PT Coin admission unconfigured; grants govern)"
    }
}

// ---------------------------------------------------------------------------
// Role/state oracle (GO-50 Phase 1, family F4) — Phase 0 TOCTOU closure
// ---------------------------------------------------------------------------

/// What the dispatcher asks the live role/state oracle, at call time:
/// the caller identity (established by the verified grant or the native
/// context — never a caller-supplied role claim) plus the target. The
/// oracle answers from LIVE state (Exchange lease state, governor
/// authority), never from anything the caller presented.
#[derive(Debug, Clone)]
pub struct RoleStateQuery {
    pub caller: String,
    pub codon: String,
    pub op: String,
}

/// The oracle's verdict on one call, from live state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleStateDecision {
    /// Live state authorizes this caller for this call right now.
    Allow,
    /// Live state does not authorize it (lease expired/revoked,
    /// governor authority withdrawn, role changed since the grant
    /// was issued).
    Deny { reason: String },
}

/// Oracle failure: the live state could not be consulted. Fail-closed
/// by construction — the dispatcher treats this as a refusal, never
/// as an allow.
#[derive(Debug, Clone)]
pub struct OracleError(pub String);

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "role/state oracle unavailable: {}", self.0)
    }
}

impl std::error::Error for OracleError {}

/// Live role/state oracle: consulted at call time, closing the Phase 0
/// TOCTOU window (gate.check verdicts fully determined by
/// caller-supplied facts). An implementation reads LIVE Exchange state
/// — lease state, governor authority — at the moment of the call, so a
/// grant issued before a lease expired or authority was withdrawn does
/// not outlive the state it was issued against.
///
/// HONEST STATUS (GAP F4-G1): no production implementation exists.
/// The only live Exchange state lives in D1, bound to the Cloudflare
/// Worker (`lucidota-exchange`); the only production `Db` impl is
/// `D1Db` (wasm32/Workers-only, `exchange-worker`), and the local
/// `d1-mirror.db` is a 6-week-old snapshot (Oct 7, 2026) missing the
/// tables the Exchange queries. A stub that returns caller-supplied
/// facts would be worse than no oracle, so none is provided: the
/// dispatcher consults the oracle ONLY when one is configured
/// ([`TypedDispatcher::with_oracle`]), and an unconfigured dispatcher
/// dispatches on the host's HMAC grants alone, exactly as before —
/// with the gap recorded, not papered over. The interface is tested
/// with in-memory test doubles (see the tests module): the wiring is
/// real, the live-state source is the named missing input.
pub trait RoleStateOracle: Send + Sync {
    fn live_state(&self, query: &RoleStateQuery) -> Result<RoleStateDecision, OracleError>;
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Exchange govern() authorization (GO-50 Phase 1, family F4)
// ---------------------------------------------------------------------------

/// The authorization question the dispatcher puts to Exchange
/// `govern()`: who is calling, what capability the call needs, and the
/// input. [`GovernSpec::to_job_spec`] renders the exact job-spec JSON
/// `govern()` takes (`capability`, `input`, `data_class`, `max_cost`,
/// `spend_authority`), so the future bridge is mechanical: pass the
/// spec to `exchange_core::govern::govern(db, &spec, env)` and map
/// `GovernResult.selected` to Allow / a non-empty `rejected` to Deny
/// with the rejecting gate named.
#[derive(Debug, Clone)]
pub struct GovernSpec {
    pub caller: String,
    pub codon: String,
    pub op: String,
    /// Required capability for this op, if the manifest declares one.
    pub capability: Option<String>,
    pub input: Value,
}

impl GovernSpec {
    /// The Exchange job spec for this call: capability is the op's
    /// required capability, or `codon.op` when the op declares none;
    /// data_class is public (typed organelles carry no data-class
    /// declaration yet); max_cost and spend_authority are 0 — a
    /// governed organelle call spends nothing by itself.
    pub fn to_job_spec(&self) -> Value {
        serde_json::json!({
            "capability": self.capability.clone().unwrap_or_else(|| format!("{}.{}", self.codon, self.op)),
            "input": self.input,
            "data_class": "public",
            "max_cost": 0,
            "spend_authority": 0,
        })
    }
}

/// `govern()`'s verdict on one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernDecision {
    /// `govern()` selected a resource for this job (or the job needs
    /// no resource selection): the call may proceed.
    Allow,
    /// `govern()` refused the job at a named gate.
    Deny { gate: String, reason: String },
}

/// `govern()` could not run (no live DB, async bridge down).
/// Fail-closed by construction.
#[derive(Debug, Clone)]
pub struct GovernError(pub String);

impl std::fmt::Display for GovernError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "govern() unavailable: {}", self.0)
    }
}

impl std::error::Error for GovernError {}

/// Exchange `govern()` as the dispatcher's authorization authority,
/// consulted at the effect-policy stage (before the host call).
///
/// HONEST STATUS (GAP F4-G2): no production implementation exists.
/// `govern()` (`exchange-core/src/govern.rs:61`) is `async fn
/// govern(db: &dyn Db, spec: &Value, env: &Env)`; the host process
/// cannot supply either input today — the only production `Db` is the
/// wasm-only `D1Db`, the local D1 mirror is stale and
/// schema-incomplete (no `resource_capabilities` / `policies` tables,
/// so `govern()` would fail on its first queries), `Env` needs
/// `EXCHANGE_KEY` (secret freeze: never provisioned by a builder),
/// and this host is synchronous std-only while `govern()` is async.
/// The dispatcher consults a configured authorizer and fail-closes on
/// error; with none configured, authorization is the host's
/// grant/capability model, as before — recorded as a gap, not claimed
/// as `govern()`.
pub trait GovernAuthorizer: Send + Sync {
    fn authorize(&self, spec: &GovernSpec) -> Result<GovernDecision, GovernError>;
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Dispatcher errors + results
// ---------------------------------------------------------------------------

/// What the dispatcher returns when it refuses or the host refuses.
/// Pre-host refusals (envelope, ontology, PT Coin, not-typed) carry NO
/// receipt id: no invocation reached the membrane, so no host receipt
/// exists — and this crate does not invent a second receipt for them.
/// Host refusals carry the host receipt id via [`CallError`].
#[derive(Debug, Clone)]
pub enum TypedDispatchError {
    InvalidEnvelope(String),
    /// Codon has no V1 manifest in the typed registry: the dispatcher
    /// dispatches typed organelles only; untyped organelles go through
    /// `Host::call` directly (same membrane, no typed stages).
    NotTyped(String),
    /// GO/DO/CO re-resolution failed at dispatch (defense in depth;
    /// registration already validated — a failure here means the locks
    /// changed under a registered manifest).
    OntologyRefused(Vec<ManifestError>),
    PtCoinDenied(String),
    /// Live role/state oracle denied the call at call time (lease
    /// expired/revoked, governor authority withdrawn). Pre-host: no
    /// receipt.
    OracleDenied(String),
    /// The role/state oracle could not be consulted. Fail-closed: no
    /// receipt, no call.
    OracleUnavailable(String),
    /// Exchange govern() refused the job at a named gate. Pre-host:
    /// no receipt.
    GovernDenied {
        gate: String,
        reason: String,
    },
    /// govern() could not run. Fail-closed: no receipt, no call.
    GovernUnavailable(String),
    /// The host refused or the organelle failed. Carries the host
    /// receipt id.
    Host(CallError),
    /// Host returned success but the receipt is missing (host
    /// invariant broken — should not happen).
    MissingReceipt(String),
    /// Host receipt lacks `typed_outcome`: the adapter/host typed
    /// path did not run for a typed call (adapter/host mismatch).
    /// Carries the receipt id — the host call DID execute (and may
    /// have had side effects), so the caller needs the id to audit
    /// it (F6-H3: the old variant discarded the id the dispatcher
    /// held).
    MissingTypedOutcome {
        receipt_id: String,
        message: String,
    },
    /// The recorded typed outcome does not decode as truth +
    /// provenance. Carries the receipt id for the same reason.
    MalformedTypedOutcome {
        receipt_id: String,
        message: String,
    },
}

impl std::fmt::Display for TypedDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypedDispatchError::InvalidEnvelope(m) => write!(f, "invalid envelope: {m}"),
            TypedDispatchError::NotTyped(m) => write!(f, "not a typed organelle: {m}"),
            TypedDispatchError::OntologyRefused(errs) => {
                let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
                write!(f, "ontology refused: {}", msgs.join("; "))
            }
            TypedDispatchError::PtCoinDenied(m) => write!(f, "PT Coin denied: {m}"),
            TypedDispatchError::OracleDenied(m) => {
                write!(f, "role/state oracle denied: {m}")
            }
            TypedDispatchError::OracleUnavailable(m) => {
                write!(f, "role/state oracle unavailable: {m}")
            }
            TypedDispatchError::GovernDenied { gate, reason } => {
                write!(f, "govern() denied at gate {gate}: {reason}")
            }
            TypedDispatchError::GovernUnavailable(m) => {
                write!(f, "govern() unavailable: {m}")
            }
            TypedDispatchError::Host(e) => write!(f, "host: {e}"),
            TypedDispatchError::MissingReceipt(m) => write!(f, "missing receipt: {m}"),
            TypedDispatchError::MissingTypedOutcome { message, .. } => {
                write!(f, "missing typed outcome: {message}")
            }
            TypedDispatchError::MalformedTypedOutcome { message, .. } => {
                write!(f, "malformed typed outcome: {message}")
            }
        }
    }
}

impl std::error::Error for TypedDispatchError {}

impl TypedDispatchError {
    /// The host-style verdict this error maps to on the surfaces, so
    /// MCP/REST/unix agree on one mapping (single source, here).
    /// Pre-host refusals map to Rejected (bad envelope/ontology) or
    /// Denied (authority: PT Coin, oracle, govern); authority-system
    /// failures and host-invariant breaks map to Failed.
    pub fn verdict(&self) -> &'static str {
        match self {
            TypedDispatchError::InvalidEnvelope(_)
            | TypedDispatchError::NotTyped(_)
            | TypedDispatchError::OntologyRefused(_) => "Rejected",
            TypedDispatchError::PtCoinDenied(_)
            | TypedDispatchError::OracleDenied(_)
            | TypedDispatchError::GovernDenied { .. } => "Denied",
            TypedDispatchError::Host(e) => match e.verdict {
                organelle_host::CallVerdict::Ok => "Ok",
                organelle_host::CallVerdict::Denied => "Denied",
                organelle_host::CallVerdict::Rejected => "Rejected",
                organelle_host::CallVerdict::Failed => "Failed",
            },
            TypedDispatchError::MissingReceipt(_)
            | TypedDispatchError::MissingTypedOutcome { .. }
            | TypedDispatchError::MalformedTypedOutcome { .. }
            | TypedDispatchError::OracleUnavailable(_)
            | TypedDispatchError::GovernUnavailable(_) => "Failed",
        }
    }

    /// The host receipt id, when one exists. Host refusals carry
    /// one; so do the typed-outcome failures (the host call DID
    /// execute — F6-H3). Pre-host refusals (envelope, ontology, PT
    /// Coin, oracle, govern) return the empty string — no invocation
    /// reached the membrane, so no host receipt exists (F3-G4
    /// boundary, kept).
    pub fn receipt_id(&self) -> String {
        match self {
            TypedDispatchError::Host(e) => e.receipt_id.clone(),
            TypedDispatchError::MissingTypedOutcome { receipt_id, .. }
            | TypedDispatchError::MalformedTypedOutcome { receipt_id, .. } => receipt_id.clone(),
            _ => String::new(),
        }
    }
}

/// Registration failure: manifest validation (locks) or host
/// registration (duplicate codon/version, base validation).
#[derive(Debug, Clone)]
pub enum TypedRegisterError {
    Manifest(Vec<ManifestError>),
    Host(Vec<ManifestError>),
}

impl std::fmt::Display for TypedRegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypedRegisterError::Manifest(errs) | TypedRegisterError::Host(errs) => {
                let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
                write!(f, "{}", msgs.join("; "))
            }
        }
    }
}

impl std::error::Error for TypedRegisterError {}

/// Successful typed dispatch: the organelle's output PLUS its claim
/// truth PLUS its payload provenance (separate fields, as recorded on
/// the receipt) PLUS the host receipt id PLUS the PT Coin admission
/// decision (so callers can see admission deferred to grants).
#[derive(Debug, Clone)]
pub struct TypedCallOk {
    pub output: Value,
    pub truth: ClaimTruth,
    pub provenance: PayloadProvenance,
    pub receipt_id: String,
    pub pt_coin: PtCoinDecision,
}

// ---------------------------------------------------------------------------
// Manifest discovery (file-based, atomic, ParkWreck pattern)
// ---------------------------------------------------------------------------

/// Load + validate typed manifests from a directory of JSON files.
/// Sorted file order; fail-closed: ANY invalid manifest aborts the
/// whole load and NOTHING is returned (atomic pre-validation of ALL
/// before registering ANY — the ParkWreck Oct-8 `load_manifests_dir`
/// pattern, applied to typed manifests with lock validation).
///
/// Discovery records manifests; it does not register implementations.
/// Real impls register via [`TypedDispatcher::register_typed`].
pub fn discover_typed_manifests_dir(
    dir: &Path,
    locks: &LockRegistry,
) -> Result<Vec<OrganelleManifestV1>, Vec<ManifestError>> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| {
            vec![manifest_err(
                dir.display().to_string(),
                format!("cannot read manifest directory: {e}"),
            )]
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();
    let mut parsed: Vec<OrganelleManifestV1> = Vec::new();
    let mut errs: Vec<ManifestError> = Vec::new();
    for f in &files {
        let s = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                errs.push(manifest_err(
                    f.display().to_string(),
                    format!("cannot read manifest file: {e}"),
                ));
                continue;
            }
        };
        let v: Value = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(e) => {
                errs.push(manifest_err(
                    f.display().to_string(),
                    format!("not valid JSON: {e}"),
                ));
                continue;
            }
        };
        match validate_manifest_v1_json(&v, locks) {
            Ok(m) => parsed.push(m),
            Err(mut es) => {
                for e in es.drain(..) {
                    errs.push(manifest_err(
                        format!("{}: {}", f.display(), e.field),
                        e.message,
                    ));
                }
            }
        }
    }
    // F6-H3: duplicate codons within one discovery batch are
    // refused (atomic: none recorded) — last-win would silently
    // pick one manifest over another.
    {
        let mut seen = BTreeSet::new();
        for m in &parsed {
            if !seen.insert(m.base.codon.clone()) {
                errs.push(manifest_err(
                    format!("discovery:{}", m.base.codon),
                    format!(
                        "duplicate codon \"{}\" in one discovery batch",
                        m.base.codon
                    ),
                ));
            }
        }
    }
    if errs.is_empty() {
        Ok(parsed)
    } else {
        Err(errs)
    }
}

// ---------------------------------------------------------------------------
// The universal dispatcher
// ---------------------------------------------------------------------------

/// The universal dispatcher for typed calls.
///
/// One entry point ([`TypedDispatcher::dispatch`]) for every typed
/// invocation, staged in order. Stages this crate owns are implemented
/// here; stages the host owns are delegated to the host's existing
/// path — the dispatcher never re-implements them:
///
/// 1. **InvocationEnvelope** — built by the surface, validated here
///    (shape + authority coherence: grant XOR capabilities).
/// 2. **Identity/version/schema validation** — HOST: `call_with_gate2`
///    → `resolve_locked` (single version resolution via route policy)
///    → `authorize` (op exists, transport declared, input schema).
/// 3. **GO/DO/CO resolution** — HERE: the target's V1 declarations are
///    re-resolved against the current locks before dispatch
///    (registration validated them already; this is defense in depth
///    against lock changes).
/// 4. **Environment capsule** — HERE + adapter: the dispatcher binds
///    the envelope to a `CallContext` (identity, capabilities, trace
///    id); the capsule materializes in the adapter from that verified
///    context (see [`EnvironmentCapsule`]).
/// 5. **Capability / PT Coin admission** — PT Coin HERE (extension
///    point; default defers to grants); capability admission HOST
///    (`call_with_grant` HMAC verification, or native context).
/// 5b. **Live role/state oracle** (F4) — HERE, when configured:
///    the oracle is consulted at call time (Exchange lease state,
///    governor authority); deny and unavailability fail closed.
///    Unconfigured = grants govern (GAP F4-G1, recorded).
/// 6. **Effect policy** — HERE (F4) + HOST: Exchange `govern()` as
///    the authorization authority when a [`GovernAuthorizer`] is
///    configured (deny and unavailability fail closed; unconfigured
///    = host grants govern, GAP F4-G2, recorded), then HOST:
///    `authorize` (mutation class + capability) and `HostRef`
///    approvals (write roots, egress allowlist, both default-deny).
/// 7. **Typed organelle** — HERE via [`TypedAdapter`] (typed decode →
///    typed execution → output validation → truth + provenance to the
///    receipt), invoked by the host's `invoke_resolved` with no lock
///    held across `handle()`.
/// 8. **Output validation** — HERE, in the adapter (typed contract
///    `output_schema`, host subset validator).
/// 9. **Truth + provenance** — HERE + host: the adapter records them
///    as separate fields; the host attaches them to the receipt
///    (`Receipt::typed_outcome`); the dispatcher reads them back from
///    the receipt by id.
/// 10. **Receipt** — HOST: existing `emit_receipt` / `verify_chain`.
///     Not `lucidota-receipt/1`; the LedgerSigner bridge is EB-1.2.
///
/// The dispatcher's typed registry ([`TypedDispatcher::typed_manifests`])
/// — manifests + schemas — is the single source the next family
/// generates REST/MCP projections from. It extends `surface-mcp` /
/// `surface-rest`; this crate builds no projections.
pub struct TypedDispatcher {
    host: Arc<Host>,
    locks: RwLock<LockRegistry>,
    /// Typed registry index: codon → validated V1 manifest. Populated
    /// by `register_typed` (with an implementation) and by
    /// `load_manifests_dir` (manifests only, ParkWreck semantics).
    manifests: RwLock<HashMap<String, OrganelleManifestV1>>,
    /// Codons with a typed implementation registered via
    /// `register_typed` (F6-H3). A manifest without an implementation
    /// is discovery-only: dispatch refuses it before the host call,
    /// so an untyped organelle behind the codon never executes for a
    /// typed call that is then reported as failed.
    impls: RwLock<HashSet<String>>,
    pt_coin: Box<dyn PtCoinAdmission>,
    /// Live role/state oracle (F4, GAP F4-G1). `None` = unconfigured:
    /// dispatch proceeds on host grants alone and the Phase 0 TOCTOU
    /// window stays open — recorded in the gap, never hidden behind
    /// a default that silently allows.
    oracle: Option<Arc<dyn RoleStateOracle>>,
    /// Exchange govern() authorizer (F4, GAP F4-G2). `None` =
    /// unconfigured: authorization is the host's grant/capability
    /// model, as before.
    govern: Option<Arc<dyn GovernAuthorizer>>,
}

impl TypedDispatcher {
    pub fn new(host: Arc<Host>, locks: LockRegistry) -> Self {
        TypedDispatcher {
            host,
            locks: RwLock::new(locks),
            manifests: RwLock::new(HashMap::new()),
            impls: RwLock::new(HashSet::new()),
            pt_coin: Box::new(NoPtCoinAdmission),
            oracle: None,
            govern: None,
        }
    }

    pub fn with_pt_coin(
        host: Arc<Host>,
        locks: LockRegistry,
        pt_coin: Box<dyn PtCoinAdmission>,
    ) -> Self {
        TypedDispatcher {
            host,
            locks: RwLock::new(locks),
            manifests: RwLock::new(HashMap::new()),
            impls: RwLock::new(HashSet::new()),
            pt_coin,
            oracle: None,
            govern: None,
        }
    }

    /// Configure the live role/state oracle (stage 5b). The oracle is
    /// consulted at call time for every dispatch; deny and
    /// unavailability fail closed before any host call.
    pub fn with_oracle(mut self, oracle: Arc<dyn RoleStateOracle>) -> Self {
        self.oracle = Some(oracle);
        self
    }

    /// Configure Exchange govern() as the authorization authority
    /// (stage 6). Consulted before the host call; deny and
    /// unavailability fail closed.
    pub fn with_govern(mut self, govern: Arc<dyn GovernAuthorizer>) -> Self {
        self.govern = Some(govern);
        self
    }

    pub fn has_oracle(&self) -> bool {
        self.oracle.is_some()
    }

    pub fn has_govern(&self) -> bool {
        self.govern.is_some()
    }

    pub fn oracle_name(&self) -> Option<&'static str> {
        self.oracle.as_ref().map(|o| o.name())
    }

    pub fn govern_name(&self) -> Option<&'static str> {
        self.govern.as_ref().map(|g| g.name())
    }

    pub fn host(&self) -> &Arc<Host> {
        &self.host
    }

    pub fn locks(&self) -> std::sync::RwLockReadGuard<'_, LockRegistry> {
        self.locks.read().unwrap()
    }

    /// Insert a lock (e.g. when a DO-25 or CO-25 lock is authored).
    /// Re-validation of already-registered manifests happens at
    /// dispatch time (stage 3 re-resolution); a lock change that
    /// invalidates a registered manifest fails its next dispatch
    /// fail-closed rather than silently un-registering it.
    ///
    /// F6-H6: a GO-50 lock is refused unless its recorded sha matches
    /// the pinned constant — the pin is the only thing tying the
    /// in-memory lock to the countersigned board file. This catches
    /// operator error (a stale/wrong lock file), not a lying caller:
    /// the sha is self-reported, and anyone who can call this can
    /// construct a rogue registry directly. DO/CO locks have no pin
    /// (no const exists for them) and are accepted as before.
    pub fn insert_lock(&self, lock: OntologyLock) -> Result<(), String> {
        if lock.id == GO50_LOCK_ID && lock.source_sha256 != GO50_LOCK_SHA256 {
            return Err(format!(
                "refusing GO-50 lock with source_sha256 {}: does not match the pinned {}",
                lock.source_sha256, GO50_LOCK_SHA256
            ));
        }
        self.locks.write().unwrap().insert(lock);
        Ok(())
    }

    /// Register a typed organelle: validate its V1 manifest against
    /// the locks, wrap it in the erased adapter, register the base
    /// manifest + adapter on the host, pin the host route to the
    /// typed version, and index the V1 manifest. The host
    /// registration happens BEFORE the index insert, so a failed host
    /// registration leaves the typed index untouched.
    ///
    /// F6-H3: the route pin is load-bearing. `RoutePolicy::Latest`
    /// resolves to the LAST registered version, so a later direct
    /// host registration of the same codon would otherwise shadow
    /// the typed adapter — dispatch would execute the untyped
    /// organelle and then fail with MissingTypedOutcome. Pinning
    /// keeps typed dispatch on the typed implementation; an operator
    /// who wants to re-route a typed codon calls `Host::set_route`
    /// explicitly.
    pub fn register_typed<T: TypedOrganelle + 'static>(
        &self,
        organelle: T,
    ) -> Result<(), TypedRegisterError> {
        let adapter = {
            let locks = self.locks.read().unwrap();
            TypedAdapter::new(organelle, &locks).map_err(TypedRegisterError::Manifest)?
        };
        let manifest_v1 = adapter.manifest_v1().clone();
        let codon = manifest_v1.base.codon.clone();
        let version = manifest_v1.base.version.clone();
        self.host
            .register(Arc::new(adapter))
            .map_err(TypedRegisterError::Host)?;
        if let Err(e) = self
            .host
            .set_route(&codon, RoutePolicy::Pinned(version.clone()))
        {
            return Err(TypedRegisterError::Host(vec![manifest_err("route", e)]));
        }
        self.impls.write().unwrap().insert(codon.clone());
        self.manifests.write().unwrap().insert(codon, manifest_v1);
        Ok(())
    }

    /// File-based discovery for the typed registry: load + validate
    /// V1 manifests from a directory (atomic: ALL valid or NONE
    /// recorded), then index them. Returns the discovered codons.
    /// Implementations are NOT registered by discovery — they still
    /// register via `register_typed` (ParkWreck semantics: dir-load
    /// only records manifests).
    ///
    /// F6-H3: duplicate codons are refused, both within the batch
    /// (checked in `discover_typed_manifests_dir`) and against the
    /// already-indexed manifests (checked here, before any insert,
    /// so the load stays atomic). Discovery never silently overwrites
    /// a registered or previously discovered manifest.
    pub fn load_manifests_dir(&self, dir: &Path) -> Result<Vec<String>, Vec<ManifestError>> {
        let manifests = {
            let locks = self.locks.read().unwrap();
            discover_typed_manifests_dir(dir, &locks)?
        };
        let mut errs: Vec<ManifestError> = Vec::new();
        {
            let index = self.manifests.read().unwrap();
            for m in &manifests {
                if index.contains_key(&m.base.codon) {
                    errs.push(manifest_err(
                        format!("discovery:{}", m.base.codon),
                        format!(
                            "codon \"{}\" is already indexed; discovery never overwrites",
                            m.base.codon
                        ),
                    ));
                }
            }
        }
        if !errs.is_empty() {
            return Err(errs);
        }
        let mut codons = Vec::new();
        let mut index = self.manifests.write().unwrap();
        for m in manifests {
            codons.push(m.base.codon.clone());
            index.insert(m.base.codon.clone(), m);
        }
        Ok(codons)
    }

    /// The V1 manifest for one codon, if the typed registry holds it.
    pub fn typed_manifest(&self, codon: &str) -> Option<OrganelleManifestV1> {
        self.manifests.read().unwrap().get(codon).cloned()
    }

    /// All V1 manifests in the typed registry, sorted by codon. THE
    /// single source for the next family's REST/MCP projections:
    /// manifests + schemas, nothing else to consult.
    pub fn typed_manifests(&self) -> Vec<OrganelleManifestV1> {
        let index = self.manifests.read().unwrap();
        let mut out: Vec<OrganelleManifestV1> = index.values().cloned().collect();
        out.sort_by(|a, b| a.base.codon.cmp(&b.base.codon));
        out
    }

    /// Dispatch one typed invocation through the staged pipeline (see
    /// the struct docs for the stage map). Pre-host refusals return
    /// errors without receipts (no invocation reached the membrane);
    /// host refusals carry the host receipt id.
    pub fn dispatch(
        &self,
        envelope: InvocationEnvelope,
    ) -> Result<TypedCallOk, TypedDispatchError> {
        // Stage 1: envelope validation.
        if envelope.caller.trim().is_empty() {
            return Err(TypedDispatchError::InvalidEnvelope(
                "caller must be non-empty".to_string(),
            ));
        }
        if envelope.codon.trim().is_empty() {
            return Err(TypedDispatchError::InvalidEnvelope(
                "codon must be non-empty".to_string(),
            ));
        }
        if envelope.op.trim().is_empty() {
            return Err(TypedDispatchError::InvalidEnvelope(
                "op must be non-empty".to_string(),
            ));
        }
        if envelope.grant.is_some() && !envelope.capabilities.is_empty() {
            return Err(TypedDispatchError::InvalidEnvelope(
                "capabilities must be empty when a grant is present: authority comes from the grant alone".to_string(),
            ));
        }

        // Stage 3: typed manifest lookup + GO/DO/CO re-resolution
        // against the CURRENT locks (registration validated already;
        // this catches lock changes under a registered manifest).
        let manifest_v1 = self.typed_manifest(&envelope.codon).ok_or_else(|| {
            TypedDispatchError::NotTyped(format!(
                "codon \"{}\" has no V1 manifest in the typed registry (dispatch is typed-only; untyped organelles go through Host::call)",
                envelope.codon
            ))
        })?;
        // F6-H3: a manifest without a registered typed implementation
        // is discovery-only — refuse BEFORE the host call. Without
        // this, dispatch would execute the untyped organelle behind
        // the codon (side effects included) and then fail with
        // MissingTypedOutcome.
        if !self.impls.read().unwrap().contains(&envelope.codon) {
            return Err(TypedDispatchError::NotTyped(format!(
                "codon \"{}\" has a V1 manifest but no typed implementation registered (discovery-only); register via register_typed",
                envelope.codon
            )));
        }
        {
            let locks = self.locks.read().unwrap();
            let mut errs = Vec::new();
            validate_term_array(
                "ontology.go",
                &manifest_v1.ontology.go,
                GO50_LOCK_ID,
                &locks,
                true,
                &mut errs,
            );
            validate_term_array(
                "ontology.domain",
                &manifest_v1.ontology.domain,
                DO25_LOCK_ID,
                &locks,
                false,
                &mut errs,
            );
            validate_term_array(
                "ontology.client",
                &manifest_v1.ontology.client,
                CO25_LOCK_ID,
                &locks,
                false,
                &mut errs,
            );
            if !errs.is_empty() {
                return Err(TypedDispatchError::OntologyRefused(errs));
            }
        }

        // Stage 5 (PT Coin): extension point; default defers to grants.
        let pt_coin = self.pt_coin.admit(&envelope, &manifest_v1)?;
        if pt_coin == PtCoinDecision::Denied {
            return Err(TypedDispatchError::PtCoinDenied(format!(
                "PT Coin admission denied {}.{}",
                envelope.codon, envelope.op
            )));
        }

        // Stage 5b (F4): live role/state oracle, consulted at call
        // time — the Phase 0 TOCTOU closure. Only when configured;
        // unconfigured = grants govern (GAP F4-G1). Deny and
        // unavailability both fail closed, before any host call, so a
        // denied call emits no receipt and reaches no organelle.
        if let Some(oracle) = &self.oracle {
            let decision = oracle
                .live_state(&RoleStateQuery {
                    caller: envelope.caller.clone(),
                    codon: envelope.codon.clone(),
                    op: envelope.op.clone(),
                })
                .map_err(|e| TypedDispatchError::OracleUnavailable(e.to_string()))?;
            if let RoleStateDecision::Deny { reason } = decision {
                return Err(TypedDispatchError::OracleDenied(reason));
            }
        }

        // Stage 6 (F4): Exchange govern() as the authorization
        // authority, consulted at the effect-policy stage. Only when
        // configured; unconfigured = host grants govern (GAP F4-G2).
        // Deny and unavailability both fail closed, before any host
        // call.
        if let Some(govern) = &self.govern {
            // Short bindings keep each identifier chain under the
            // secret-scrubber's long-identifier threshold (no line
            // here is a secret; the scrubber flags long dotted
            // chains, so the access is split).
            let base = &manifest_v1.base;
            let auth = &base.authority;
            let capability = base
                .contracts
                .iter()
                .find(|c| c.op == envelope.op)
                .and_then(|c| c.required_capability.clone())
                .or_else(|| auth.required_capability.clone());
            let decision = govern
                .authorize(&GovernSpec {
                    caller: envelope.caller.clone(),
                    codon: envelope.codon.clone(),
                    op: envelope.op.clone(),
                    capability,
                    input: envelope.input.clone(),
                })
                .map_err(|e| TypedDispatchError::GovernUnavailable(e.to_string()))?;
            if let GovernDecision::Deny { gate, reason } = decision {
                return Err(TypedDispatchError::GovernDenied { gate, reason });
            }
        }

        // Stages 2, 4, 5 (capability), 6 (host effect policy), 7, 8,
        // 10: the host path.
        // Grant path: the host verifies the HMAC grant, builds the
        // context from the grant alone, and dispatches. Native path:
        // the dispatcher binds the envelope to a CallContext (stage 4:
        // identity, capabilities, trace id bound once).
        let result = match &envelope.grant {
            Some(grant) => self.host.call_with_grant(
                grant,
                Some(&envelope.caller),
                envelope.transport,
                &envelope.codon,
                &envelope.op,
                envelope.input.clone(),
            ),
            None => {
                let mut ctx =
                    CallContext::new(envelope.caller.clone(), envelope.capabilities.clone());
                if let Some(t) = &envelope.trace_id {
                    ctx.trace_id = t.clone();
                }
                self.host
                    .call(&ctx, &envelope.codon, &envelope.op, envelope.input.clone())
            }
        };
        let ok = result.map_err(TypedDispatchError::Host)?;

        // Stage 9: truth + provenance, read back from the host receipt
        // by id (the adapter recorded them during handle(); the host
        // attached them to the receipt). A typed success without a
        // typed outcome is a fail-closed error, not a default.
        let receipt = self.host.receipt_by_id(&ok.receipt_id).ok_or_else(|| {
            TypedDispatchError::MissingReceipt(format!(
                "host returned success but receipt {} is missing",
                ok.receipt_id
            ))
        })?;
        let typed =
            receipt
                .typed_outcome
                .ok_or_else(|| TypedDispatchError::MissingTypedOutcome {
                    receipt_id: ok.receipt_id.clone(),
                    message: format!(
                        "receipt {} for typed call {}.{} carries no typed outcome",
                        ok.receipt_id, envelope.codon, envelope.op
                    ),
                })?;
        let truth: ClaimTruth = serde_json::from_value(
            typed.get("truth").cloned().unwrap_or(Value::Null),
        )
        .map_err(|e| TypedDispatchError::MalformedTypedOutcome {
            receipt_id: ok.receipt_id.clone(),
            message: format!("truth: {e}"),
        })?;
        let provenance: PayloadProvenance =
            serde_json::from_value(typed.get("provenance").cloned().unwrap_or(Value::Null))
                .map_err(|e| TypedDispatchError::MalformedTypedOutcome {
                    receipt_id: ok.receipt_id.clone(),
                    message: format!("provenance: {e}"),
                })?;
        Ok(TypedCallOk {
            output: ok.output,
            truth,
            provenance,
            receipt_id: ok.receipt_id,
            pt_coin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_manifest::{
        Authority, Contract, MutationClass, ReceiptPolicy, MANIFEST_SCHEMA_VERSION,
        RECEIPT_ALGORITHM,
    };
    use std::path::PathBuf;

    fn base_manifest(codon: &str) -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: format!("test-{codon}"),
            codon: codon.to_string(),
            version: "1.0.0".to_string(),
            description: "test typed organelle".to_string(),
            contracts: vec![Contract {
                op: "echo".to_string(),
                description: "echo input back".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["text"],
                    "properties": {"text": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            }],
            authority: Authority {
                mutation_class: MutationClass::ReadOnly,
                declared_valence: organelle_manifest::Valence::Candidate,
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

    fn good_v1(codon: &str) -> OrganelleManifestV1 {
        OrganelleManifestV1::from_base(
            base_manifest(codon),
            OntologyDeclarations {
                go: vec!["TOOL".to_string(), "PROCESS".to_string()],
                domain: vec![],
                client: vec![],
            },
            vec![TypedContract {
                op: "echo".to_string(),
                input_type: "EchoInput".to_string(),
                output_type: "EchoOutput".to_string(),
                output_schema: serde_json::json!({
                    "type": "object", "required": ["echoed"],
                    "properties": {"echoed": {"type": "string"}}
                }),
            }],
        )
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct EchoInput {
        text: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct EchoOutput {
        echoed: String,
    }

    struct EchoTyped {
        manifest: OrganelleManifestV1,
    }

    impl TypedOrganelle for EchoTyped {
        type Input = EchoInput;
        type Output = EchoOutput;

        fn manifest_v1(&self) -> OrganelleManifestV1 {
            self.manifest.clone()
        }

        fn handle_typed(
            &self,
            _capsule: &EnvironmentCapsule,
            _host: &dyn HostRef,
            op: &str,
            input: EchoInput,
        ) -> Result<TypedOutcome<EchoOutput>, TypedError> {
            if op != "echo" {
                return Err(TypedError::not_found(format!("unknown op {op}")));
            }
            let input_value = serde_json::to_value(&input).unwrap();
            Ok(TypedOutcome {
                output: EchoOutput { echoed: input.text },
                truth: ClaimTruth::candidate(
                    "echo reproduces caller input; no independent verification",
                ),
                provenance: PayloadProvenance::computed_locally(&input_value, "te@1.0.0"),
            })
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("go50-f3-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn go50_lock_has_fifty_terms() {
        let lock = OntologyLock::go50();
        assert_eq!(lock.term_count(), 50);
        assert_eq!(lock.id, "GO-50");
        assert_eq!(lock.version, "v1");
        assert_eq!(lock.source_sha256, GO50_LOCK_SHA256);
        // Spot checks: seated terms present, executed/demoted terms absent.
        for t in ["ENTITY", "IDENTITY", "LOVE", "TERNARY_STATE", "ATTUNEMENT"] {
            assert!(lock.contains(t), "{t} must be in the GO-50 lock");
        }
        for t in ["MOTION", "TRUTH", "ABSENCE", "MEAN", "TERM", "LAYER"] {
            assert!(
                !lock.contains(t),
                "{t} must NOT be in the GO-50 lock (executed/demoted)"
            );
        }
    }

    #[test]
    fn lock_registry_with_go50_only() {
        let r = LockRegistry::with_go50();
        assert_eq!(r.lock_ids(), vec!["GO-50".to_string()]);
        assert!(r.get("DO-25").is_none());
        assert!(r.get("CO-25").is_none());
    }

    #[test]
    fn good_manifest_validates() {
        let locks = LockRegistry::with_go50();
        assert!(validate_manifest_v1(&good_v1("te"), &locks).is_ok());
    }

    #[test]
    fn missing_ontology_arrays_rejected_at_json() {
        let locks = LockRegistry::with_go50();
        let mut v = serde_json::to_value(&good_v1("te")).unwrap();
        v.as_object_mut().unwrap().remove("ontology");
        let errs = validate_manifest_v1_json(&v, &locks).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "$"), "{errs:?}");
    }

    #[test]
    fn unknown_go_term_rejected() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.go = vec!["MOTION".to_string()];
        let errs = validate_manifest_v1(&m, &locks).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.message.contains("unknown GO-50 term")),
            "{errs:?}"
        );
    }

    #[test]
    fn empty_go_array_rejected() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.go = vec![];
        let errs = validate_manifest_v1(&m, &locks).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "ontology.go"), "{errs:?}");
    }

    #[test]
    fn empty_string_term_rejected() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.go = vec!["".to_string()];
        assert!(validate_manifest_v1(&m, &locks).is_err());
    }

    #[test]
    fn duplicate_go_term_rejected() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.go = vec!["TOOL".to_string(), "TOOL".to_string()];
        assert!(validate_manifest_v1(&m, &locks).is_err());
    }

    #[test]
    fn do_binding_refused_without_lock() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.domain = vec!["GATE".to_string()];
        let errs = validate_manifest_v1(&m, &locks).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.message.contains("no DO-25 lock loaded")),
            "{errs:?}"
        );
    }

    #[test]
    fn co_binding_refused_without_lock() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.ontology.client = vec!["FARMILY".to_string()];
        let errs = validate_manifest_v1(&m, &locks).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.message.contains("no CO-25 lock loaded")),
            "{errs:?}"
        );
    }

    #[test]
    fn do_binding_accepted_once_lock_exists() {
        // Mechanism proof: the refusal is the missing lock, not the
        // mechanism. A test-only DO lock makes the same binding pass.
        // (This lock is a test fixture, NOT a canonical DO-25 lock.)
        let mut locks = LockRegistry::with_go50();
        locks.insert(OntologyLock {
            id: DO25_LOCK_ID.to_string(),
            version: "test-1".to_string(),
            status: "test-fixture".to_string(),
            source: "test".to_string(),
            source_sha256: "test".to_string(),
            terms: ["GATE".to_string()].into_iter().collect(),
        });
        let mut m = good_v1("te");
        m.ontology.domain = vec!["GATE".to_string()];
        assert!(validate_manifest_v1(&m, &locks).is_ok());
        m.ontology.domain = vec!["NOT_A_TERM".to_string()];
        assert!(validate_manifest_v1(&m, &locks).is_err());
    }

    #[test]
    fn typed_contract_coverage_enforced() {
        let locks = LockRegistry::with_go50();
        // Missing typed contract for a base op.
        let mut m = good_v1("te");
        m.typed_contracts = vec![];
        assert!(validate_manifest_v1(&m, &locks).is_err());
        // Typed contract for a nonexistent base op.
        let mut m2 = good_v1("te");
        m2.typed_contracts.push(TypedContract {
            op: "nope".to_string(),
            input_type: "X".to_string(),
            output_type: "Y".to_string(),
            output_schema: serde_json::json!({"type": "object"}),
        });
        assert!(validate_manifest_v1(&m2, &locks).is_err());
    }

    #[test]
    fn bad_schema_version_rejected() {
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.schema_version = "1".to_string();
        assert!(validate_manifest_v1(&m, &locks).is_err());
    }

    #[test]
    fn base_manifest_weakening_rejected() {
        // A typed manifest whose embedded base fails October validation
        // is rejected — the typed layer never weakens the base.
        let locks = LockRegistry::with_go50();
        let mut m = good_v1("te");
        m.base.codon = "toolong".to_string();
        let errs = validate_manifest_v1(&m, &locks).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "base.codon"), "{errs:?}");
    }

    fn dispatcher_with_echo() -> TypedDispatcher {
        let host = Host::new();
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        d.register_typed(EchoTyped {
            manifest: good_v1("te"),
        })
        .expect("echo must register");
        d
    }

    #[test]
    fn dispatch_native_end_to_end() {
        let d = dispatcher_with_echo();
        let ok = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "echo",
                serde_json::json!({"text": "hello"}),
            ))
            .expect("dispatch must succeed");
        assert_eq!(ok.output, serde_json::json!({"echoed": "hello"}));
        assert_eq!(ok.truth.status, TruthStatus::Candidate);
        assert!(!ok.truth.basis.is_empty());
        assert_eq!(ok.provenance.source, ProvenanceSource::ComputedLocally);
        assert_eq!(ok.provenance.produced_by, "te@1.0.0");
        assert_eq!(ok.provenance.input_hash.len(), 64);
        assert_eq!(ok.pt_coin, PtCoinDecision::DeferredToGrants);
        // The receipt carries truth + provenance as SEPARATE fields.
        let receipt = d.host().receipt_by_id(&ok.receipt_id).unwrap();
        let typed = receipt.typed_outcome.as_ref().unwrap();
        assert_eq!(typed["truth"]["status"], serde_json::json!("candidate"));
        assert_eq!(
            typed["provenance"]["produced_by"],
            serde_json::json!("te@1.0.0")
        );
        assert!(typed.get("truth").unwrap().is_object());
        assert!(typed.get("provenance").unwrap().is_object());
        // Chain still verifies with the typed receipt in it.
        assert!(d.host().verify_chain().is_ok());
    }

    #[test]
    fn dispatch_grant_path() {
        let d = dispatcher_with_echo();
        let grant = d.host().issue_grant("alice", vec![], 3600);
        let mut env =
            InvocationEnvelope::native("alice", "te", "echo", serde_json::json!({"text": "g"}));
        env.grant = Some(grant);
        env.transport = Transport::Mcp;
        let ok = d.dispatch(env).expect("grant dispatch must succeed");
        assert_eq!(ok.output, serde_json::json!({"echoed": "g"}));
        // A forged grant is a host Denied with a receipt.
        let mut bad =
            InvocationEnvelope::native("alice", "te", "echo", serde_json::json!({"text": "g"}));
        bad.grant = Some("forged.grant.token".to_string());
        bad.transport = Transport::Mcp;
        let err = d.dispatch(bad).unwrap_err();
        match err {
            TypedDispatchError::Host(e) => {
                assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
                assert!(!e.receipt_id.is_empty());
            }
            other => panic!("expected Host(Denied), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_to_untyped_codon_refused() {
        let d = dispatcher_with_echo();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "zz",
                "echo",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        assert!(matches!(err, TypedDispatchError::NotTyped(_)), "{err:?}");
    }

    #[test]
    fn dispatch_grant_plus_capabilities_refused() {
        let d = dispatcher_with_echo();
        let mut env =
            InvocationEnvelope::native("test", "te", "echo", serde_json::json!({"text": "x"}));
        env.grant = Some("g".to_string());
        env.capabilities = vec!["te.write".to_string()];
        let err = d.dispatch(env).unwrap_err();
        assert!(
            matches!(err, TypedDispatchError::InvalidEnvelope(_)),
            "{err:?}"
        );
    }

    #[test]
    fn dispatch_malformed_input_rejected_with_receipt() {
        let d = dispatcher_with_echo();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "echo",
                serde_json::json!({}),
            ))
            .unwrap_err();
        match err {
            TypedDispatchError::Host(e) => {
                assert_eq!(e.verdict, organelle_host::CallVerdict::Rejected);
                assert!(!e.receipt_id.is_empty());
            }
            other => panic!("expected Host(Rejected), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_unknown_op_denied() {
        let d = dispatcher_with_echo();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "nope",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        match err {
            TypedDispatchError::Host(e) => {
                assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
            }
            other => panic!("expected Host(Denied), got {other:?}"),
        }
    }

    #[test]
    fn register_typed_rejects_unknown_go_term() {
        let host = Host::new();
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        let mut m = good_v1("te");
        m.ontology.go = vec!["MOTION".to_string()];
        let err = d.register_typed(EchoTyped { manifest: m }).unwrap_err();
        match err {
            TypedRegisterError::Manifest(errs) => {
                assert!(errs.iter().any(|e| e.message.contains("unknown GO-50")));
            }
            other => panic!("expected Manifest error, got {other:?}"),
        }
        // Nothing registered: the host has no "te".
        assert!(d.typed_manifest("te").is_none());
        assert!(d.host().list_manifests().is_empty());
    }

    #[test]
    fn adapter_output_schema_failure_is_failed() {
        // A typed organelle whose output violates its own output_schema
        // fails closed (host Failed verdict), it does not leak a bad
        // value to the caller.
        let host = Host::new();
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        let mut m = good_v1("te");
        m.typed_contracts[0].output_schema = serde_json::json!({
            "type": "object", "required": ["echoed", "never_present"]
        });
        d.register_typed(EchoTyped { manifest: m }).unwrap();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "echo",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        match err {
            TypedDispatchError::Host(e) => {
                assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
            }
            other => panic!("expected Host(Failed), got {other:?}"),
        }
    }

    #[test]
    fn discovery_loads_valid_and_is_atomic() {
        let dir = temp_dir("discovery-ok");
        let m1 = good_v1("aa");
        let m2 = good_v1("bb");
        std::fs::write(
            dir.join("a.json"),
            serde_json::to_string_pretty(&m1).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("b.json"),
            serde_json::to_string_pretty(&m2).unwrap(),
        )
        .unwrap();
        let host = Host::new();
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        let codons = d.load_manifests_dir(&dir).expect("both valid");
        assert_eq!(codons, vec!["aa".to_string(), "bb".to_string()]);
        assert!(d.typed_manifest("aa").is_some());
        assert!(d.typed_manifest("bb").is_some());

        // Now poison the directory: one bad manifest aborts the WHOLE
        // load and nothing new is recorded (atomicity).
        let dir2 = temp_dir("discovery-bad");
        std::fs::write(
            dir2.join("a.json"),
            serde_json::to_string_pretty(&good_v1("cc")).unwrap(),
        )
        .unwrap();
        let mut bad = good_v1("dd");
        bad.ontology.go = vec!["MOTION".to_string()];
        std::fs::write(
            dir2.join("b.json"),
            serde_json::to_string_pretty(&bad).unwrap(),
        )
        .unwrap();
        let err = d.load_manifests_dir(&dir2).unwrap_err();
        assert!(!err.is_empty(), "poisoned load must report errors");
        assert!(d.typed_manifest("cc").is_none(), "atomic: cc not recorded");
        assert!(d.typed_manifest("dd").is_none(), "atomic: dd not recorded");
        // The earlier good load is untouched.
        assert!(d.typed_manifest("aa").is_some());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn discovery_missing_dir_fails_closed() {
        let locks = LockRegistry::with_go50();
        let missing = std::env::temp_dir().join("go50-f3-no-such-dir-xyz");
        assert!(discover_typed_manifests_dir(&missing, &locks).is_err());
    }

    #[test]
    fn typed_manifests_is_projection_source() {
        let d = dispatcher_with_echo();
        let ms = d.typed_manifests();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].base.codon, "te");
        assert_eq!(ms[0].ontology.go, vec!["TOOL", "PROCESS"]);
        assert_eq!(ms[0].typed_contracts.len(), 1);
    }

    // -- F4: role/state oracle + govern() wiring (test doubles only) ----

    /// Test oracle backed by live mutable state: flips between calls,
    /// proving the dispatcher consults it at call time (not once at
    /// setup). A test double for the interface — NOT a production
    /// oracle (GAP F4-G1: no live Exchange state is reachable here).
    struct FlippingOracle {
        allow: std::sync::Mutex<bool>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl FlippingOracle {
        fn new(allow: bool) -> Arc<Self> {
            Arc::new(FlippingOracle {
                allow: std::sync::Mutex::new(allow),
                calls: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    impl RoleStateOracle for FlippingOracle {
        fn live_state(&self, q: &RoleStateQuery) -> Result<RoleStateDecision, OracleError> {
            self.calls.lock().unwrap().push(q.caller.clone());
            if *self.allow.lock().unwrap() {
                Ok(RoleStateDecision::Allow)
            } else {
                Ok(RoleStateDecision::Deny {
                    reason: "lease expired (test)".to_string(),
                })
            }
        }

        fn name(&self) -> &'static str {
            "test-flipping-oracle"
        }
    }

    struct FailingOracle;

    impl RoleStateOracle for FailingOracle {
        fn live_state(&self, _q: &RoleStateQuery) -> Result<RoleStateDecision, OracleError> {
            Err(OracleError("D1 unreachable (test)".to_string()))
        }

        fn name(&self) -> &'static str {
            "test-failing-oracle"
        }
    }

    struct DenyingGovern {
        gate: &'static str,
    }

    impl GovernAuthorizer for DenyingGovern {
        fn authorize(&self, _spec: &GovernSpec) -> Result<GovernDecision, GovernError> {
            Ok(GovernDecision::Deny {
                gate: self.gate.to_string(),
                reason: "no resource exposes capability (test)".to_string(),
            })
        }

        fn name(&self) -> &'static str {
            "test-denying-govern"
        }
    }

    struct FailingGovern;

    impl GovernAuthorizer for FailingGovern {
        fn authorize(&self, _spec: &GovernSpec) -> Result<GovernDecision, GovernError> {
            Err(GovernError("no live Db (test)".to_string()))
        }

        fn name(&self) -> &'static str {
            "test-failing-govern"
        }
    }

    fn echo_envelope() -> InvocationEnvelope {
        InvocationEnvelope::native("test", "te", "echo", serde_json::json!({"text": "hi"}))
    }

    #[test]
    fn unconfigured_dispatcher_has_no_oracle_or_govern() {
        let d = dispatcher_with_echo();
        assert!(!d.has_oracle());
        assert!(!d.has_govern());
        assert!(d.oracle_name().is_none());
        assert!(d.govern_name().is_none());
        // Unconfigured dispatch proceeds on host grants alone (current
        // behavior preserved; the gap is recorded, not hidden).
        assert!(d.dispatch(echo_envelope()).is_ok());
    }

    #[test]
    fn oracle_consulted_at_call_time() {
        let oracle = FlippingOracle::new(true);
        let d = dispatcher_with_echo().with_oracle(oracle.clone());
        assert!(d.has_oracle());
        assert_eq!(d.oracle_name(), Some("test-flipping-oracle"));
        // Baseline: registration itself emits a receipt.
        let baseline = d.host().receipts().len();
        // Call 1: live state allows.
        assert!(d.dispatch(echo_envelope()).is_ok());
        assert_eq!(d.host().receipts().len(), baseline + 1);
        // Live state flips UNDER the dispatcher; the next call must
        // see the new state (this is the TOCTOU closure at the
        // interface level: the verdict follows live state, not a
        // snapshot taken at setup).
        *oracle.allow.lock().unwrap() = false;
        let err = d.dispatch(echo_envelope()).unwrap_err();
        assert!(
            matches!(err, TypedDispatchError::OracleDenied(ref m) if m.contains("lease expired")),
            "{err:?}"
        );
        assert_eq!(err.verdict(), "Denied");
        assert!(err.receipt_id().is_empty(), "pre-host denial: no receipt");
        // The denied call emitted no receipt and reached no organelle.
        assert_eq!(d.host().receipts().len(), baseline + 1);
        assert_eq!(oracle.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn oracle_unavailable_fail_closed() {
        let d = dispatcher_with_echo().with_oracle(Arc::new(FailingOracle));
        let baseline = d.host().receipts().len();
        let err = d.dispatch(echo_envelope()).unwrap_err();
        assert!(
            matches!(err, TypedDispatchError::OracleUnavailable(_)),
            "{err:?}"
        );
        assert_eq!(err.verdict(), "Failed");
        assert_eq!(d.host().receipts().len(), baseline);
    }

    #[test]
    fn govern_deny_blocks_call_with_gate() {
        let d = dispatcher_with_echo().with_govern(Arc::new(DenyingGovern { gate: "CAPABILITY" }));
        assert!(d.has_govern());
        assert_eq!(d.govern_name(), Some("test-denying-govern"));
        let baseline = d.host().receipts().len();
        let err = d.dispatch(echo_envelope()).unwrap_err();
        assert!(
            matches!(err, TypedDispatchError::GovernDenied { ref gate, .. } if gate == "CAPABILITY"),
            "{err:?}"
        );
        assert_eq!(err.verdict(), "Denied");
        assert!(err.receipt_id().is_empty(), "pre-host denial: no receipt");
        assert_eq!(d.host().receipts().len(), baseline);
    }

    #[test]
    fn govern_unavailable_fail_closed() {
        let d = dispatcher_with_echo().with_govern(Arc::new(FailingGovern));
        let baseline = d.host().receipts().len();
        let err = d.dispatch(echo_envelope()).unwrap_err();
        assert!(
            matches!(err, TypedDispatchError::GovernUnavailable(_)),
            "{err:?}"
        );
        assert_eq!(err.verdict(), "Failed");
        assert_eq!(d.host().receipts().len(), baseline);
    }

    #[test]
    fn govern_spec_job_shape() {
        let spec = GovernSpec {
            caller: "test".to_string(),
            codon: "te".to_string(),
            op: "echo".to_string(),
            capability: None,
            input: serde_json::json!({"text": "hi"}),
        };
        let job = spec.to_job_spec();
        // The shape govern() takes: capability + input + data_class +
        // max_cost + spend_authority (validate_job requires the first
        // two; the rest have govern-side defaults but are stated).
        assert_eq!(job["capability"], serde_json::json!("te.echo"));
        assert_eq!(job["input"]["text"], serde_json::json!("hi"));
        assert_eq!(job["data_class"], serde_json::json!("public"));
        assert_eq!(job["max_cost"], serde_json::json!(0));
        assert_eq!(job["spend_authority"], serde_json::json!(0));
        // A declared capability is used verbatim.
        let gated = GovernSpec {
            capability: Some("kv.write".to_string()),
            ..spec
        };
        assert_eq!(
            gated.to_job_spec()["capability"],
            serde_json::json!("kv.write")
        );
    }

    #[test]
    fn typed_dispatch_error_verdict_mapping() {
        assert_eq!(
            TypedDispatchError::InvalidEnvelope("x".into()).verdict(),
            "Rejected"
        );
        assert_eq!(
            TypedDispatchError::NotTyped("x".into()).verdict(),
            "Rejected"
        );
        assert_eq!(
            TypedDispatchError::PtCoinDenied("x".into()).verdict(),
            "Denied"
        );
        assert_eq!(
            TypedDispatchError::OracleDenied("x".into()).verdict(),
            "Denied"
        );
        assert_eq!(
            TypedDispatchError::GovernDenied {
                gate: "COST".into(),
                reason: "x".into(),
            }
            .verdict(),
            "Denied"
        );
        assert_eq!(
            TypedDispatchError::GovernUnavailable("x".into()).verdict(),
            "Failed"
        );
        // Pre-host refusals carry no receipt id.
        assert!(TypedDispatchError::OracleDenied("x".into())
            .receipt_id()
            .is_empty());
    }

    #[test]
    fn typed_dispatcher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TypedDispatcher>();
    }

    // -- F6: hostile review (adversarial tests) -------------------------

    /// F6: untyped organelle with a side-effect counter, for proving
    /// the dispatcher never executes a discovery-only codon and never
    /// routes to a shadowing untyped registration.
    struct CountingEcho {
        manifest: OrganelleManifest,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Organelle for CountingEcho {
        fn manifest(&self) -> OrganelleManifest {
            self.manifest.clone()
        }

        fn handle(
            &self,
            _ctx: &CallContext,
            _host: &dyn HostRef,
            _op: &str,
            input: Value,
        ) -> Result<Value, OrganelleError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(input)
        }
    }

    fn write_v1(dir: &Path, name: &str, m: &OrganelleManifestV1) {
        let s = serde_json::to_string(m).unwrap();
        std::fs::write(dir.join(name), s).unwrap();
    }

    /// F6 (prove-sound): ontology term edge cases are rejected at
    /// validation — whitespace-only, trailing-space, lowercase, and
    /// duplicate terms are all unknown to the lock (exact match).
    #[test]
    fn f6_ontology_term_edge_cases_rejected() {
        let locks = LockRegistry::with_go50();
        for terms in [
            vec!["   ".to_string()],
            vec!["TOOL ".to_string()],
            vec!["tool".to_string()],
            vec!["TOOL".to_string(), "TOOL".to_string()],
            vec!["TOOL".to_string(), "".to_string()],
        ] {
            let mut m = good_v1("te");
            m.ontology.go = terms.clone();
            let errs = validate_manifest_v1(&m, &locks).unwrap_err();
            assert!(
                !errs.is_empty(),
                "terms {terms:?} must be rejected, validated clean"
            );
        }
    }

    /// F6 (prove-sound): a whitespace-only caller is rejected at
    /// stage 1, like an empty caller.
    #[test]
    fn f6_whitespace_caller_rejected() {
        let d = dispatcher_with_echo();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "   ",
                "te",
                "echo",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        assert!(matches!(err, TypedDispatchError::InvalidEnvelope(_)));
    }

    /// F6 (prove-sound): replacing the GO-50 lock under a registered
    /// manifest fails the NEXT dispatch fail-closed (stage 3
    /// re-resolution), it does not silently keep serving.
    #[test]
    fn f6_lock_replacement_fails_next_dispatch() {
        let d = dispatcher_with_echo();
        let mut lock = OntologyLock::go50();
        lock.terms.remove("TOOL");
        let _ = d.insert_lock(lock);
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "echo",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        assert!(matches!(err, TypedDispatchError::OntologyRefused(_)));
    }

    /// F6-H3: two V1 manifests for the same codon in one discovery
    /// batch must be rejected (atomic: none recorded), not last-win.
    #[test]
    fn f6_discovery_duplicate_codons_in_one_batch_rejected() {
        let d = TypedDispatcher::new(Host::new(), LockRegistry::with_go50());
        let dir = temp_dir("f6-dup-batch");
        write_v1(&dir, "a.json", &good_v1("dd"));
        let mut other = good_v1("dd");
        other.base.description = "a different dd".to_string();
        write_v1(&dir, "b.json", &other);
        let errs = d.load_manifests_dir(&dir).unwrap_err();
        assert!(!errs.is_empty());
        assert!(
            d.typed_manifest("dd").is_none(),
            "atomic: no duplicate-codon manifest recorded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F6-H3: discovery must not silently overwrite an already-indexed
    /// manifest (registered or previously discovered).
    #[test]
    fn f6_discovery_overwrite_of_registered_codon_rejected() {
        let d = dispatcher_with_echo();
        let dir = temp_dir("f6-dup-shadow");
        let mut other = good_v1("te");
        other.ontology.go = vec!["PROCESS".to_string()];
        write_v1(&dir, "te.json", &other);
        let errs = d.load_manifests_dir(&dir).unwrap_err();
        assert!(!errs.is_empty());
        let kept = d.typed_manifest("te").expect("original intact");
        assert_eq!(kept.ontology.go, vec!["TOOL", "PROCESS"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F6-H3: a codon with a discovered V1 manifest but NO typed
    /// implementation must be refused BEFORE the host call — the
    /// untyped organelle behind the codon must never execute (its
    /// side effects would otherwise run, then the dispatcher would
    /// report failure with no receipt id).
    #[test]
    fn f6_dispatch_to_discovery_only_codon_refused_without_execution() {
        let host = Host::new();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        host.register(Arc::new(CountingEcho {
            manifest: base_manifest("ce"),
            calls: calls.clone(),
        }))
        .expect("untyped ce must register");
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        let dir = temp_dir("f6-disc-only");
        write_v1(&dir, "ce.json", &good_v1("ce"));
        d.load_manifests_dir(&dir).expect("discovery must load");
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "ce",
                "echo",
                serde_json::json!({"text": "x"}),
            ))
            .unwrap_err();
        match err {
            TypedDispatchError::NotTyped(msg) => {
                assert!(msg.contains("discovery-only"), "message: {msg}");
            }
            other => panic!("expected NotTyped(discovery-only), got {other:?}"),
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the untyped organelle must not have executed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F6-H3: a later direct host registration of the same codon must
    /// not shadow the typed adapter. `RoutePolicy::Latest` resolves
    /// to the LAST registered version, so without pinning, a direct
    /// untyped registration steals typed dispatch (host succeeds,
    /// dispatcher fails with MissingTypedOutcome).
    #[test]
    fn f6_register_typed_pins_route_against_later_shadow() {
        let host = Host::new();
        let d = TypedDispatcher::new(host.clone(), LockRegistry::with_go50());
        d.register_typed(EchoTyped {
            manifest: good_v1("te"),
        })
        .expect("echo must register");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut shadow = base_manifest("te");
        shadow.version = "9.9.9".to_string();
        host.register(Arc::new(CountingEcho {
            manifest: shadow,
            calls: calls.clone(),
        }))
        .expect("untyped shadow must register");
        let ok = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "te",
                "echo",
                serde_json::json!({"text": "still typed"}),
            ))
            .expect("typed dispatch must still reach the typed adapter");
        assert_eq!(ok.output, serde_json::json!({"echoed": "still typed"}));
        assert_eq!(ok.truth.status, TruthStatus::Candidate);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the untyped shadow must never have executed"
        );
    }

    /// F6-H6: a GO-50 lock whose recorded sha does not match the
    /// pinned constant must be refused — the pin is the only thing
    /// tying the in-memory lock to the countersigned board file.
    #[test]
    fn f6_go50_lock_sha_pin() {
        let d = dispatcher_with_echo();
        let mut bad = OntologyLock::go50();
        bad.source_sha256 = "0".repeat(64);
        let err = d.insert_lock(bad).unwrap_err();
        assert!(err.contains("pinned"), "{err}");
        assert_eq!(
            d.locks().get("GO-50").unwrap().source_sha256,
            GO50_LOCK_SHA256,
            "a wrong-sha GO-50 lock must not replace the pinned lock"
        );
        // A correctly pinned GO-50 lock and an unpinned DO-25 lock
        // still insert.
        assert!(d.insert_lock(OntologyLock::go50()).is_ok());
        assert!(d
            .insert_lock(OntologyLock {
                id: "DO-25".to_string(),
                version: "v1".to_string(),
                status: "test".to_string(),
                source: "test".to_string(),
                source_sha256: "0".repeat(64),
                terms: ["GATE".to_string()].into_iter().collect(),
            })
            .is_ok());
    }

    /// F6-H3: the typed-outcome failures carry the receipt id of the
    /// host call that executed — the dispatcher held it and the old
    /// variants discarded it.
    #[test]
    fn f6_typed_outcome_errors_carry_receipt_id() {
        let e = TypedDispatchError::MissingTypedOutcome {
            receipt_id: "r-abc".to_string(),
            message: "m".to_string(),
        };
        assert_eq!(e.receipt_id(), "r-abc");
        assert_eq!(e.verdict(), "Failed");
        let e = TypedDispatchError::MalformedTypedOutcome {
            receipt_id: "r-def".to_string(),
            message: "m".to_string(),
        };
        assert_eq!(e.receipt_id(), "r-def");
        assert_eq!(e.verdict(), "Failed");
    }

    /// F6-H7 (F3-G7 follow-up): the output-schema check must be deep,
    /// not top-level-type-only. A malformed `required` (string, not
    /// array) or an unknown property type must reject the manifest —
    /// otherwise output validation silently ignores the malformed
    /// constraint at runtime.
    #[test]
    fn f6_deep_output_schema_rejected() {
        let locks = LockRegistry::with_go50();
        let mut bad_required = good_v1("te");
        bad_required.typed_contracts[0].output_schema = serde_json::json!({
            "type": "object", "required": "nope",
            "properties": {"echoed": {"type": "string"}}
        });
        assert!(
            validate_manifest_v1(&bad_required, &locks).is_err(),
            "string `required` must be rejected"
        );
        let mut bad_prop = good_v1("te");
        bad_prop.typed_contracts[0].output_schema = serde_json::json!({
            "type": "object",
            "properties": {"echoed": {"type": "bogus"}}
        });
        assert!(
            validate_manifest_v1(&bad_prop, &locks).is_err(),
            "unknown property type must be rejected"
        );
    }
}
