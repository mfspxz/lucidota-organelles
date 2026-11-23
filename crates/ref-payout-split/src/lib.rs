//! org-037 — Reference organelle: payout-split (codon `ps`).
//!
//! Split computation over integer cents plus an append-only split
//! ledger, for VanCan/Canswer-style payout splits (decomposition
//! GAP-24, bespoke: no other scoped software splits payouts).
//!
//! Design rules, all structural rather than conventional:
//!
//! - **Split tables are caller data.** Parties, weights, and the
//!   rounding rule are supplied on every call. The crate ships no
//!   split percentages, no party names, and no default rounding rule
//!   — a rule must be chosen explicitly or the call does not typecheck
//!   as a complete request.
//! - **Parts always sum EXACTLY to the whole.** Computation is integer
//!   arithmetic (u128 intermediates): each party's exact share is
//!   floored, and the leftover cents — always fewer than the number of
//!   parties — are distributed by the caller's stated
//!   [`RemainderRule`]. No float ever touches money here.
//! - **Simulation is a type-level fact.** Ledger entries are generic
//!   over a [`PayoutMode`]. This version implements [`PayoutMode`] for
//!   [`Simulated`] only. A [`Real`] marker type exists so call sites
//!   can name it, but it has **no** `PayoutMode` implementation, so a
//!   real-mode ledger cannot be constructed, appended to, or loaded —
//!   mirroring VanCan's `REAL_PAYOUTS=false` as a compile-time refusal
//!   instead of a runtime flag check. Every entry therefore carries
//!   `is_simulated == true`, set from the type at construction, never
//!   from caller input; deserialization of an entry claiming
//!   `is_simulated == false` is refused.
//!
//! The pure core (split math + in-memory ledger) is std-only. JSONL
//! persistence is behind the `jsonl` feature; the Organelle trait
//! surface behind `organelle`.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

// ---------------------------------------------------------------------
// Parties and split tables — caller data, validated at construction.
// ---------------------------------------------------------------------

/// An opaque party identifier. The crate never interprets it; it is
/// whatever string the caller uses for a payee (a role name, an
/// account id, …). Empty ids are refused.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(String);

impl PartyId {
    pub fn new(id: impl Into<String>) -> Result<PartyId, SplitError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SplitError::EmptyPartyId);
        }
        Ok(PartyId(id))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A split table: an ordered list of (party, weight) shares. Weights
/// are relative — percentages, basis points, or raw ratios all work;
/// only their proportions matter. Order is significant: it is the
/// ledger's canonical part order and the `EarliestInTable` tie-break
/// refers to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTable {
    entries: Vec<(PartyId, u64)>,
    total_weight: u128,
}

impl SplitTable {
    /// Validates: at least one party, no duplicate party, total
    /// weight > 0. Individual zero weights are allowed (the party is
    /// recorded and receives exactly its floor — zero — plus a
    /// remainder cent only if a rule explicitly names it).
    pub fn new(entries: Vec<(PartyId, u64)>) -> Result<SplitTable, SplitError> {
        if entries.is_empty() {
            return Err(SplitError::EmptyTable);
        }
        let mut seen = std::collections::HashSet::new();
        let mut total: u128 = 0;
        for (party, w) in &entries {
            if !seen.insert(party.clone()) {
                return Err(SplitError::DuplicateParty(party.clone()));
            }
            total += *w as u128;
        }
        if total == 0 {
            return Err(SplitError::ZeroTotalWeight);
        }
        Ok(SplitTable {
            entries,
            total_weight: total,
        })
    }

    pub fn entries(&self) -> &[(PartyId, u64)] {
        &self.entries
    }
    pub fn total_weight(&self) -> u128 {
        self.total_weight
    }
    pub fn weight_of(&self, party: &PartyId) -> Option<u64> {
        self.entries
            .iter()
            .find(|(p, _)| p == party)
            .map(|(_, w)| *w)
    }
    pub fn contains(&self, party: &PartyId) -> bool {
        self.weight_of(party).is_some()
    }
}

// ---------------------------------------------------------------------
// Rounding — the remainder rule is caller-chosen policy data.
// ---------------------------------------------------------------------

/// How a tie between equal fractional remainders is broken under
/// [`RemainderRule::LargestRemainder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// The party appearing first in the split table wins the cent.
    EarliestInTable,
    /// The lexicographically smallest party id wins the cent.
    LowestPartyId,
}

/// The caller-chosen rule that assigns the leftover cents after every
/// party's exact share is floored. Both variants guarantee the parts
/// sum exactly to the gross; they differ only in *who* receives the
/// remainder, which is a policy decision the crate refuses to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemainderRule {
    /// Leftover cents go one each to the parties with the largest
    /// fractional remainders (classic largest-remainder / Hamilton
    /// apportionment), ties resolved by `tie_break`.
    LargestRemainder { tie_break: TieBreak },
    /// Every leftover cent goes to the named party, which must be in
    /// the split table.
    EntireRemainderTo { party: PartyId },
}

impl RemainderRule {
    /// Canonical tag recorded in ledger entries, e.g.
    /// `largest_remainder/earliest_in_table`.
    pub fn tag(&self) -> String {
        match self {
            RemainderRule::LargestRemainder { tie_break } => match tie_break {
                TieBreak::EarliestInTable => {
                    "largest_remainder/earliest_in_table".to_string()
                }
                TieBreak::LowestPartyId => "largest_remainder/lowest_party_id".to_string(),
            },
            RemainderRule::EntireRemainderTo { party } => {
                format!("entire_remainder_to/{}", party.as_str())
            }
        }
    }
}

// ---------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    EmptyPartyId,
    EmptyTable,
    DuplicateParty(PartyId),
    ZeroTotalWeight,
    /// A rule named a party that is not in the split table.
    RemainderPartyNotInTable(PartyId),
    /// A serialized entry claimed `is_simulated == false`. Real-mode
    /// entries are refused by construction in this version.
    RealEntryRefused,
    /// A serialized entry failed verification on load (parts do not
    /// recompute from gross + table + rule, sequence gap, bad flag…).
    EntryVerificationFailed(String),
    /// Malformed serialized input.
    BadRecord(String),
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::EmptyPartyId => write!(f, "party id must not be empty"),
            SplitError::EmptyTable => write!(f, "split table must not be empty"),
            SplitError::DuplicateParty(p) => write!(f, "duplicate party in table: {p}"),
            SplitError::ZeroTotalWeight => write!(f, "split table total weight is zero"),
            SplitError::RemainderPartyNotInTable(p) => {
                write!(f, "remainder party not in split table: {p}")
            }
            SplitError::RealEntryRefused => write!(
                f,
                "entry claims is_simulated=false; real payouts are refused by \
                 construction in this version (REAL_PAYOUTS=false)"
            ),
            SplitError::EntryVerificationFailed(m) => {
                write!(f, "entry verification failed: {m}")
            }
            SplitError::BadRecord(m) => write!(f, "bad record: {m}"),
        }
    }
}

impl std::error::Error for SplitError {}

// ---------------------------------------------------------------------
// The split computation.
// ---------------------------------------------------------------------

/// Compute the split of `gross_cents` over `table` under `rule`.
///
/// Returns parts in table order. Guarantees, for every input:
///
/// - `parts.len() == table.entries().len()`
/// - `sum(parts) == gross_cents` exactly
/// - under `LargestRemainder`, each part is its exact share's floor
///   or floor + 1, and a zero-weight party's part is 0
/// - under `EntireRemainderTo`, every non-named party's part is its
///   floor and the named party absorbs the whole remainder
pub fn compute_split(
    gross_cents: u64,
    table: &SplitTable,
    rule: &RemainderRule,
) -> Result<Vec<(PartyId, u64)>, SplitError> {
    let gross = gross_cents as u128;
    let total_w = table.total_weight();
    let n = table.entries().len();

    // Exact shares in u128: floor and fractional remainder (scaled by
    // total weight, so remainders compare exactly without floats).
    let mut floors: Vec<u64> = Vec::with_capacity(n);
    let mut fracs: Vec<u128> = Vec::with_capacity(n);
    let mut floor_sum: u128 = 0;
    for (_, w) in table.entries() {
        let exact = gross * (*w as u128);
        let fl = exact / total_w;
        floors.push(fl as u64);
        fracs.push(exact % total_w);
        floor_sum += fl;
    }
    // leftover == sum(fracs)/total_w < n, so it always fits and the
    // distribution loops below terminate within the table.
    let leftover = (gross - floor_sum) as u64;
    debug_assert!(leftover < n as u64 || n == 0);

    let mut parts = floors;
    match rule {
        RemainderRule::LargestRemainder { tie_break } => {
            let mut order: Vec<usize> = (0..n).collect();
            match tie_break {
                TieBreak::EarliestInTable => {
                    order.sort_by(|&a, &b| fracs[b].cmp(&fracs[a]).then(a.cmp(&b)));
                }
                TieBreak::LowestPartyId => {
                    order.sort_by(|&a, &b| {
                        fracs[b]
                            .cmp(&fracs[a])
                            .then_with(|| table.entries()[a].0.cmp(&table.entries()[b].0))
                    });
                }
            }
            // leftover < count of parties with frac > 0 whenever
            // leftover > 0 (each frac < total_w, sum(fracs) =
            // leftover * total_w), so cents only land on parties with
            // a genuine fractional claim — never on zero-weight ones.
            for &idx in order.iter().take(leftover as usize) {
                parts[idx] += 1;
            }
        }
        RemainderRule::EntireRemainderTo { party } => {
            let idx = table
                .entries()
                .iter()
                .position(|(p, _)| p == party)
                .ok_or_else(|| SplitError::RemainderPartyNotInTable(party.clone()))?;
            parts[idx] += leftover;
        }
    }

    Ok(table
        .entries()
        .iter()
        .map(|(p, _)| p.clone())
        .zip(parts)
        .collect())
}

// ---------------------------------------------------------------------
// Payout modes — simulation is a type-level fact.
// ---------------------------------------------------------------------

/// Sealed-by-construction mode marker for ledger entries. Only
/// [`Simulated`] implements this trait in this version.
pub trait PayoutMode {
    const IS_SIMULATED: bool;
}

/// Simulated payouts — the only constructible mode. Mirrors the
/// VanCan programme rule that `depot_receipts.is_simulated` must be
/// true: here an entry *cannot* be built unflagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Simulated;
impl PayoutMode for Simulated {
    const IS_SIMULATED: bool = true;
}

/// Real payouts. This marker exists so call sites and future work can
/// name the mode, but it deliberately has **no** [`PayoutMode`]
/// implementation in this version: `SplitLedger::<Real>::new()`,
/// `append`, and `from_jsonl` all fail to compile. Flipping
/// REAL_PAYOUTS is therefore a deliberate type-level change (see
/// APPLICATION.md), not a flag flip.
///
/// ```compile_fail
/// use ref_payout_split::{Real, SplitLedger};
/// let _ledger = SplitLedger::<Real>::new();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Real;

// ---------------------------------------------------------------------
// Ledger entries and the append-only split ledger.
// ---------------------------------------------------------------------

/// One append-only split-ledger entry: the gross, the table snapshot
/// it was split by, the rule used, and the resulting parts. Fields
/// are private; entries are created only by [`SplitLedger::append`]
/// (or verified load), so an entry's parts always recompute exactly
/// from its gross + table + rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitEntry<M: PayoutMode> {
    seq: u64,
    gross_cents: u64,
    table: SplitTable,
    rule: RemainderRule,
    parts: Vec<(PartyId, u64)>,
    memo: Option<String>,
    is_simulated: bool,
    _mode: PhantomData<M>,
}

impl<M: PayoutMode> SplitEntry<M> {
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn gross_cents(&self) -> u64 {
        self.gross_cents
    }
    pub fn table(&self) -> &SplitTable {
        &self.table
    }
    pub fn rule(&self) -> &RemainderRule {
        &self.rule
    }
    pub fn parts(&self) -> &[(PartyId, u64)] {
        &self.parts
    }
    pub fn memo(&self) -> Option<&str> {
        self.memo.as_deref()
    }
    /// Always the mode's constant — for any entry that exists in this
    /// version, `true`. It comes from the type, never from input.
    pub fn is_simulated(&self) -> bool {
        self.is_simulated
    }
    pub fn part_of(&self, party: &PartyId) -> Option<u64> {
        self.parts
            .iter()
            .find(|(p, _)| p == party)
            .map(|(_, c)| *c)
    }
    /// Recompute the split from the recorded gross + table + rule and
    /// check the recorded parts and flag against it.
    pub fn verify(&self) -> Result<(), SplitError> {
        if self.is_simulated != M::IS_SIMULATED {
            return Err(SplitError::EntryVerificationFailed(format!(
                "is_simulated={} but mode requires {}",
                self.is_simulated,
                M::IS_SIMULATED
            )));
        }
        let recomputed = compute_split(self.gross_cents, &self.table, &self.rule)?;
        if recomputed != self.parts {
            return Err(SplitError::EntryVerificationFailed(format!(
                "parts {recomputed:?} != recorded {:?} (recomputed vs recorded)",
                self.parts
            )));
        }
        let sum: u128 = self.parts.iter().map(|(_, c)| *c as u128).sum();
        if sum != self.gross_cents as u128 {
            return Err(SplitError::EntryVerificationFailed(format!(
                "parts sum {sum} != gross {}",
                self.gross_cents
            )));
        }
        Ok(())
    }
}

/// An append-only ledger of split entries for one payout mode. There
/// is deliberately no removal, replacement, or mutation API: history
/// is only ever extended, and [`SplitLedger::entries`] hands out
/// shared references.
#[derive(Debug, Clone)]
pub struct SplitLedger<M: PayoutMode> {
    entries: Vec<SplitEntry<M>>,
    _mode: PhantomData<M>,
}

impl<M: PayoutMode> Default for SplitLedger<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: PayoutMode> SplitLedger<M> {
    pub fn new() -> Self {
        SplitLedger {
            entries: Vec::new(),
            _mode: PhantomData,
        }
    }

    /// Compute a split and append it as the next entry. Returns the
    /// appended entry's sequence number (0-based, gapless).
    pub fn append(
        &mut self,
        gross_cents: u64,
        table: SplitTable,
        rule: RemainderRule,
        memo: Option<String>,
    ) -> Result<u64, SplitError> {
        let parts = compute_split(gross_cents, &table, &rule)?;
        let seq = self.entries.len() as u64;
        let entry = SplitEntry {
            seq,
            gross_cents,
            table,
            rule,
            parts,
            memo,
            is_simulated: M::IS_SIMULATED,
            _mode: PhantomData,
        };
        entry.verify()?;
        self.entries.push(entry);
        Ok(seq)
    }

    pub fn entries(&self) -> &[SplitEntry<M>] {
        &self.entries
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total gross across all entries.
    pub fn total_gross_cents(&self) -> u128 {
        self.entries.iter().map(|e| e.gross_cents as u128).sum()
    }

    /// Per-party totals across all entries, sorted by party id.
    /// Conservation holds by construction: the per-party totals sum
    /// to [`SplitLedger::total_gross_cents`].
    pub fn totals_by_party(&self) -> Vec<(PartyId, u128)> {
        let mut totals: BTreeMap<PartyId, u128> = BTreeMap::new();
        for e in &self.entries {
            for (p, c) in &e.parts {
                *totals.entry(p.clone()).or_insert(0) += *c as u128;
            }
        }
        totals.into_iter().collect()
    }
}

// ---------------------------------------------------------------------
// JSONL persistence (feature `jsonl`). Records are verified on load:
// sequence must be gapless from 0, is_simulated must be true, and
// every entry's parts must recompute exactly from gross+table+rule.
// ---------------------------------------------------------------------

#[cfg(feature = "jsonl")]
pub mod jsonl {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct RuleRecord {
        pub kind: String,
        pub tie_break: Option<String>,
        pub party: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct EntryRecord {
        pub seq: u64,
        pub gross_cents: u64,
        pub table: Vec<(String, u64)>,
        pub rule: RuleRecord,
        pub parts: Vec<(String, u64)>,
        pub memo: Option<String>,
        pub is_simulated: bool,
    }

    pub fn rule_to_record(rule: &RemainderRule) -> RuleRecord {
        match rule {
            RemainderRule::LargestRemainder { tie_break } => RuleRecord {
                kind: "largest_remainder".to_string(),
                tie_break: Some(match tie_break {
                    TieBreak::EarliestInTable => "earliest_in_table".to_string(),
                    TieBreak::LowestPartyId => "lowest_party_id".to_string(),
                }),
                party: None,
            },
            RemainderRule::EntireRemainderTo { party } => RuleRecord {
                kind: "entire_remainder_to".to_string(),
                tie_break: None,
                party: Some(party.as_str().to_string()),
            },
        }
    }

    pub fn rule_from_record(rec: &RuleRecord) -> Result<RemainderRule, SplitError> {
        match rec.kind.as_str() {
            "largest_remainder" => {
                let tie_break = match rec.tie_break.as_deref() {
                    Some("earliest_in_table") => TieBreak::EarliestInTable,
                    Some("lowest_party_id") => TieBreak::LowestPartyId,
                    other => {
                        return Err(SplitError::BadRecord(format!(
                            "unknown tie_break: {other:?}"
                        )))
                    }
                };
                Ok(RemainderRule::LargestRemainder { tie_break })
            }
            "entire_remainder_to" => {
                let party = rec
                    .party
                    .as_deref()
                    .ok_or_else(|| SplitError::BadRecord("rule missing party".into()))?;
                Ok(RemainderRule::EntireRemainderTo {
                    party: PartyId::new(party)?,
                })
            }
            other => Err(SplitError::BadRecord(format!("unknown rule kind: {other}"))),
        }
    }

    fn party_vec(raw: &[(String, u64)]) -> Result<Vec<(PartyId, u64)>, SplitError> {
        raw.iter()
            .map(|(p, w)| Ok((PartyId::new(p.clone())?, *w)))
            .collect()
    }

    impl<M: PayoutMode> SplitEntry<M> {
        pub fn to_record(&self) -> EntryRecord {
            EntryRecord {
                seq: self.seq,
                gross_cents: self.gross_cents,
                table: self
                    .table
                    .entries()
                    .iter()
                    .map(|(p, w)| (p.as_str().to_string(), *w))
                    .collect(),
                rule: rule_to_record(&self.rule),
                parts: self
                    .parts
                    .iter()
                    .map(|(p, c)| (p.as_str().to_string(), *c))
                    .collect(),
                memo: self.memo.clone(),
                is_simulated: self.is_simulated,
            }
        }

        pub fn to_json(&self) -> String {
            serde_json::to_string(&self.to_record())
                .expect("entry record serialization is infallible")
        }

        /// Parse and verify one entry record. The mode is taken from
        /// the type parameter, never from the record: a record whose
        /// flag disagrees with the mode is refused, and a record
        /// claiming a real payout is refused outright in this
        /// version.
        pub fn from_record(rec: EntryRecord) -> Result<SplitEntry<M>, SplitError> {
            if !rec.is_simulated {
                return Err(SplitError::RealEntryRefused);
            }
            if rec.is_simulated != M::IS_SIMULATED {
                return Err(SplitError::EntryVerificationFailed(format!(
                    "record is_simulated={} but mode requires {}",
                    rec.is_simulated,
                    M::IS_SIMULATED
                )));
            }
            let table = SplitTable::new(party_vec(&rec.table)?)?;
            let rule = rule_from_record(&rec.rule)?;
            let parts = party_vec(&rec.parts)?;
            let entry = SplitEntry {
                seq: rec.seq,
                gross_cents: rec.gross_cents,
                table,
                rule,
                parts,
                memo: rec.memo,
                is_simulated: rec.is_simulated,
                _mode: PhantomData,
            };
            entry.verify()?;
            Ok(entry)
        }

        pub fn from_json(line: &str) -> Result<SplitEntry<M>, SplitError> {
            let rec: EntryRecord = serde_json::from_str(line)
                .map_err(|e| SplitError::BadRecord(e.to_string()))?;
            Self::from_record(rec)
        }
    }

    impl<M: PayoutMode> SplitLedger<M> {
        /// Serialize the whole ledger as JSONL, one entry per line,
        /// in sequence order.
        pub fn to_jsonl(&self) -> String {
            let mut out = String::new();
            for e in self.entries() {
                out.push_str(&e.to_json());
                out.push('\n');
            }
            out
        }

        /// Load a ledger from JSONL, verifying every line: sequence
        /// gapless from 0, every entry simulated, every entry's parts
        /// recomputing exactly. Any failure refuses the whole load —
        /// a partially verified ledger is never returned.
        pub fn from_jsonl(text: &str) -> Result<SplitLedger<M>, SplitError> {
            let mut ledger = SplitLedger::new();
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry = SplitEntry::from_json(line)?;
                if entry.seq != ledger.entries.len() as u64 {
                    return Err(SplitError::EntryVerificationFailed(format!(
                        "sequence gap: expected {}, found {}",
                        ledger.entries.len(),
                        entry.seq
                    )));
                }
                ledger.entries.push(entry);
            }
            Ok(ledger)
        }
    }
}

#[cfg(feature = "jsonl")]
pub use jsonl::{rule_from_record, rule_to_record, EntryRecord, RuleRecord};

// ---------------------------------------------------------------------
// Organelle surface (feature `organelle`). ReadOnly: the surface
// computes and verifies; persistence is the caller's composition
// (append the entry JSON via ref-ledger-append, org-020).
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod surface {
    use super::jsonl::{rule_from_record, RuleRecord};
    use super::*;
    use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
    use organelle_manifest::{
        Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport,
        Valence, MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn manifest() -> OrganelleManifest {
        let split_input = json!({
            "type": "object",
            "required": ["gross_cents", "table", "rule"],
            "properties": {
                "gross_cents": {"type": "integer", "minimum": 0},
                "table": {
                    "type": "array", "minItems": 1,
                    "items": {
                        "type": "object", "required": ["party", "weight"],
                        "properties": {
                            "party": {"type": "string", "minLength": 1},
                            "weight": {"type": "integer", "minimum": 0}
                        }
                    }
                },
                "rule": {
                    "type": "object", "required": ["kind"],
                    "properties": {
                        "kind": {"enum": ["largest_remainder", "entire_remainder_to"]},
                        "tie_break": {"enum": ["earliest_in_table", "lowest_party_id"]},
                        "party": {"type": "string", "minLength": 1}
                    }
                },
                "memo": {"type": "string"}
            }
        });
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "payout-split".to_string(),
            codon: "ps".to_string(),
            version: "1.0.0".to_string(),
            description: "integer-cent payout split + append-only split ledger; simulated mode only (real payouts refused by construction)".to_string(),
            contracts: vec![
                Contract {
                    op: "split".to_string(),
                    description: "compute a split and return the would-be simulated ledger entry (gross, table, rule, parts, is_simulated=true)".to_string(),
                    input_schema: split_input,
                    mutation_class: Some(MutationClass::ReadOnly),
                    required_capability: None,
                },
                Contract {
                    op: "verify_entry".to_string(),
                    description: "verify a recorded split entry: flag must be simulated and parts must recompute exactly from gross+table+rule".to_string(),
                    input_schema: json!({
                        "type": "object", "required": ["entry"],
                        "properties": {"entry": {"type": "object"}}
                    }),
                    mutation_class: Some(MutationClass::ReadOnly),
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

    pub struct PayoutSplit {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(PayoutSplit {
            manifest: manifest(),
        })
    }

    fn rejected(e: SplitError) -> OrganelleError {
        OrganelleError::new("rejected", e.to_string())
    }

    fn parse_table(input: &Value) -> Result<SplitTable, OrganelleError> {
        let arr = input["table"]
            .as_array()
            .ok_or_else(|| OrganelleError::new("rejected", "table must be an array"))?;
        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let party = item["party"].as_str().ok_or_else(|| {
                OrganelleError::new("rejected", "table entry party must be a string")
            })?;
            let weight = item["weight"].as_u64().ok_or_else(|| {
                OrganelleError::new("rejected", "table entry weight must be a u64")
            })?;
            entries.push((
                PartyId::new(party).map_err(rejected)?,
                weight,
            ));
        }
        SplitTable::new(entries).map_err(rejected)
    }

    fn parse_rule(input: &Value) -> Result<RemainderRule, OrganelleError> {
        let rec: RuleRecord = serde_json::from_value(input["rule"].clone()).map_err(|e| {
            OrganelleError::new("rejected", format!("rule: {e}"))
        })?;
        rule_from_record(&rec).map_err(rejected)
    }

    impl Organelle for PayoutSplit {
        fn manifest(&self) -> OrganelleManifest {
            self.manifest.clone()
        }

        fn handle(
            &self,
            _ctx: &CallContext,
            _host: &dyn HostRef,
            op: &str,
            input: Value,
        ) -> Result<Value, OrganelleError> {
            match op {
                "split" => {
                    let gross = input["gross_cents"].as_u64().ok_or_else(|| {
                        OrganelleError::new("rejected", "gross_cents must be a u64")
                    })?;
                    let table = parse_table(&input)?;
                    let rule = parse_rule(&input)?;
                    let memo = input["memo"].as_str().map(|s| s.to_string());
                    let mut ledger = SplitLedger::<Simulated>::new();
                    let seq = ledger
                        .append(gross, table, rule, memo)
                        .map_err(rejected)?;
                    let entry = &ledger.entries()[seq as usize];
                    Ok(json!({
                        "seq": entry.seq(),
                        "entry": entry.to_record(),
                        "is_simulated": true,
                        "rule_tag": entry.rule().tag(),
                        "parts_sum": entry.parts().iter().map(|(_, c)| *c as u128).sum::<u128>() as u64,
                    }))
                }
                "verify_entry" => {
                    let rec: super::EntryRecord =
                        serde_json::from_value(input["entry"].clone()).map_err(|e| {
                            OrganelleError::new("rejected", format!("entry: {e}"))
                        })?;
                    let entry = SplitEntry::<Simulated>::from_record(rec).map_err(rejected)?;
                    Ok(json!({
                        "valid": true,
                        "seq": entry.seq(),
                        "is_simulated": entry.is_simulated(),
                        "gross_cents": entry.gross_cents(),
                        "parts_sum": entry.parts().iter().map(|(_, c)| *c as u128).sum::<u128>() as u64,
                    }))
                }
                other => Err(OrganelleError::not_found(format!("unknown op {other}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use surface::organelle;

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(&str, u64)]) -> SplitTable {
        SplitTable::new(
            entries
                .iter()
                .map(|(p, w)| (PartyId::new(*p).unwrap(), *w))
                .collect(),
        )
        .unwrap()
    }

    fn lr() -> RemainderRule {
        RemainderRule::LargestRemainder {
            tie_break: TieBreak::EarliestInTable,
        }
    }

    fn cents(parts: &[(PartyId, u64)]) -> Vec<u64> {
        parts.iter().map(|(_, c)| *c).collect()
    }

    #[test]
    fn table_validation() {
        assert_eq!(SplitTable::new(vec![]).unwrap_err(), SplitError::EmptyTable);
        let dup = SplitTable::new(vec![
            (PartyId::new("a").unwrap(), 1),
            (PartyId::new("a").unwrap(), 2),
        ]);
        assert!(matches!(dup, Err(SplitError::DuplicateParty(_))));
        let zero = SplitTable::new(vec![(PartyId::new("a").unwrap(), 0)]);
        assert_eq!(zero.unwrap_err(), SplitError::ZeroTotalWeight);
        assert_eq!(PartyId::new("").unwrap_err(), SplitError::EmptyPartyId);
    }

    #[test]
    fn zero_gross_splits_to_zero() {
        let parts = compute_split(0, &table(&[("a", 69), ("b", 26), ("c", 5)]), &lr()).unwrap();
        assert_eq!(cents(&parts), vec![0, 0, 0]);
    }

    #[test]
    fn single_party_gets_everything_under_both_rules() {
        let t = table(&[("only", 7)]);
        assert_eq!(cents(&compute_split(123, &t, &lr()).unwrap()), vec![123]);
        let to = RemainderRule::EntireRemainderTo {
            party: PartyId::new("only").unwrap(),
        };
        assert_eq!(cents(&compute_split(123, &t, &to).unwrap()), vec![123]);
    }

    #[test]
    fn remainder_party_must_be_in_table() {
        let t = table(&[("a", 1), ("b", 1)]);
        let to = RemainderRule::EntireRemainderTo {
            party: PartyId::new("ghost").unwrap(),
        };
        assert!(matches!(
            compute_split(10, &t, &to),
            Err(SplitError::RemainderPartyNotInTable(_))
        ));
    }

    #[test]
    fn ledger_append_only_and_totals_conserve() {
        let mut ledger = SplitLedger::<Simulated>::new();
        let t = table(&[("customer", 69), ("driver", 26), ("platform", 5)]);
        ledger.append(1000, t.clone(), lr(), None).unwrap();
        ledger
            .append(1000, t, lr(), Some("second".to_string()))
            .unwrap();
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.total_gross_cents(), 2000);
        let totals = ledger.totals_by_party();
        let sum: u128 = totals.iter().map(|(_, c)| *c).sum();
        assert_eq!(sum, 2000);
        assert!(ledger.entries().iter().all(|e| e.is_simulated()));
    }

    #[cfg(feature = "jsonl")]
    #[test]
    fn jsonl_round_trip_and_tamper_refusal() {
        let mut ledger = SplitLedger::<Simulated>::new();
        let t = table(&[("customer", 69), ("driver", 26), ("platform", 5)]);
        ledger.append(1000, t.clone(), lr(), None).unwrap();
        ledger.append(999, t, lr(), Some("odd".to_string())).unwrap();
        let text = ledger.to_jsonl();
        let loaded = SplitLedger::<Simulated>::from_jsonl(&text).unwrap();
        assert_eq!(loaded.entries(), ledger.entries());

        // Tamper: flip the simulation flag -> refused as a real entry.
        let tampered = text.replacen("\"is_simulated\":true", "\"is_simulated\":false", 1);
        assert_eq!(
            SplitLedger::<Simulated>::from_jsonl(&tampered).unwrap_err(),
            SplitError::RealEntryRefused
        );

        // Tamper: move a cent between parts -> recompute mismatch.
        let tampered2 = text.replacen("\"platform\",50", "\"platform\",49", 1);
        assert_ne!(tampered2, text);
        assert!(matches!(
            SplitLedger::<Simulated>::from_jsonl(&tampered2),
            Err(SplitError::EntryVerificationFailed(_))
        ));
    }
}
