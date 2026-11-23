//! org-036 — Reference organelle: gtfs-rt-decode (codon `gd`).
//!
//! GTFS-Realtime protobuf decoding — vehicle positions, trip
//! updates, and service alerts (GAP-21 in the 2026-11-22
//! decomposition map: a named capability with exactly one
//! implementation in the estate, the hand-rolled JS decoder
//! `~/workspace/translink-repeater/gtfsrt.js`, live in production
//! in the translink-repeater worker).
//!
//! This crate is a faithful port of that decoder.  The JS source
//! is the authority, and the port replicates its observable
//! behaviour exactly — including the places where the JS is
//! loose rather than spec-correct:
//!
//! * Varints accumulate *unsigned* (the JS uses `BigInt` with no
//!   sign extension), so a negative GTFS-RT `int32` delay — which
//!   the wire encodes as a 64-bit two's-complement varint —
//!   decodes to the same huge positive `f64` the JS produces,
//!   not to a negative number.  Parity, not prettiness.
//! * A length-delimited field whose declared length overruns the
//!   buffer is *clamped* to the remaining bytes (JS `subarray`
//!   semantics), and the clamped bytes are what submessage
//!   parsing sees.  Truncated fixed-width fields, truncated
//!   varints, over-long varints, and unsupported wire types are
//!   errors, with the JS error strings.
//! * String fields decode with the JS `TextDecoder` default:
//!   lossy UTF-8, invalid sequences replaced by U+FFFD.
//! * The `|| null` idiom in the JS turns empty strings into
//!   `null` for id/label/route fields; `str()` fields without
//!   the idiom (entity_id, stop_id, header, description) keep
//!   empty strings.  The port applies the filter at exactly the
//!   same sites.
//! * `stop_updates` counts *every* entry under TripUpdate
//!   field 2, whatever its wire type — the JS counts the raw
//!   entry list, not just submessages.
//!
//! What the decoder does *not* do, by design: freshness
//! bookkeeping.  `feed_ts` is decoded here (it is in the feed);
//! `fetched_at`, `age_s`, `served_at`, `stale`, and the snapshot
//! `count` are worker concerns (see `worker-main.js` in the
//! repeater) and belong to the org-031 shell handlers that will
//! call this organelle, never to the decoder.
//!
//! JSON output: [`VehiclesFeed::to_json`], [`TripsFeed::to_json`]
//! and [`AlertsFeed::to_json`] render byte-identical text to
//! `JSON.stringify` of the JS decoder's return value — same key
//! order, same JS number formatting (shortest round-trip digits
//! under the ECMAScript `Number::toString` layout rules, `-0`
//! as `0`, non-finite floats as `null`).  The parity suite in
//! `tests/parity.rs` proves this against golden files generated
//! by the JS decoder itself, over live MBTA feed snapshots and
//! synthetic edge-case feeds.

use std::collections::HashMap;
use std::fmt;

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
#[cfg(feature = "organelle")]
use serde_json::Value;
#[cfg(feature = "organelle")]
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Errors — the strings mirror the JS decoder's Error messages where it has
// them, so a caller comparing implementations sees the same failures.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gtfs-rt-decode: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

fn err(msg: impl Into<String>) -> DecodeError {
    DecodeError(msg.into())
}

// ---------------------------------------------------------------------------
// Protobuf wire primitives — a direct transcription of parseFields /
// readVarint from gtfsrt.js.
// ---------------------------------------------------------------------------

/// One parsed field occurrence.  Mirrors the JS `{wire, val}` entries:
/// varints keep their full unsigned value (u128 covers the 11-byte /
/// 77-bit maximum the JS BigInt path can produce), length-delimited
/// values own their (possibly clamped) bytes, and fixed-width values
/// are already widened the way the JS DataView reads them.
#[derive(Debug, Clone, PartialEq)]
enum Entry {
    Varint(u128),
    Bytes(Vec<u8>),
    F32(f32),
    F64(f64),
}

/// field number -> occurrences in wire order, as in the JS Map.
type FieldMap = HashMap<u128, Vec<Entry>>;

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u128, DecodeError> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    while *pos < buf.len() {
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u128) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 70 {
            return Err(err("varint too long"));
        }
    }
    Err(err("truncated varint"))
}

fn parse_fields(buf: &[u8]) -> Result<FieldMap, DecodeError> {
    let mut out: FieldMap = HashMap::new();
    let mut pos: usize = 0;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let field = tag >> 3;
        let wire = (tag & 7) as u8;
        let entry = match wire {
            0 => Entry::Varint(read_varint(buf, &mut pos)?),
            2 => {
                let len = read_varint(buf, &mut pos)?;
                let avail = (buf.len() - pos) as u128;
                // JS: buf.subarray(pos, pos + len) clamps to the
                // buffer end, and pos += len ends the loop.  The
                // clamped slice is the value; replicate exactly.
                if len > avail {
                    let v = buf[pos..].to_vec();
                    pos = buf.len();
                    Entry::Bytes(v)
                } else {
                    let l = len as usize;
                    let v = buf[pos..pos + l].to_vec();
                    pos += l;
                    Entry::Bytes(v)
                }
            }
            5 => {
                // JS DataView.getFloat32 throws when out of bounds.
                if buf.len() - pos < 4 {
                    return Err(err("truncated fixed32 field"));
                }
                let v = f32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
                pos += 4;
                Entry::F32(v)
            }
            1 => {
                if buf.len() - pos < 8 {
                    return Err(err("truncated fixed64 field"));
                }
                let v = f64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                Entry::F64(v)
            }
            w => return Err(err(format!("unsupported wire type {w}"))),
        };
        out.entry(field).or_default().push(entry);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Field accessors — transcriptions of the JS subs/sub/str/num/flt helpers.
// ---------------------------------------------------------------------------

/// All wire-2 occurrences of `n`, each parsed as a submessage.
/// The JS parses every occurrence even when only the first is
/// used, so parse errors anywhere in the list propagate here too.
fn subs(m: &FieldMap, n: u128) -> Result<Vec<FieldMap>, DecodeError> {
    let mut out = Vec::new();
    if let Some(entries) = m.get(&n) {
        for e in entries {
            if let Entry::Bytes(b) = e {
                out.push(parse_fields(b)?);
            }
        }
    }
    Ok(out)
}

/// First wire-2 occurrence of `n` parsed as a submessage.
fn sub(m: &FieldMap, n: u128) -> Result<Option<FieldMap>, DecodeError> {
    Ok(subs(m, n)?.into_iter().next())
}

/// First wire-2 occurrence of `n` as a lossy UTF-8 string
/// (JS TextDecoder default: invalid sequences become U+FFFD).
fn get_str(m: &FieldMap, n: u128) -> Option<String> {
    m.get(&n)?.iter().find_map(|e| match e {
        Entry::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    })
}

/// First wire-0 occurrence of `n` as an f64 (JS `Number(BigInt)`:
/// round-to-nearest-even conversion of the unsigned value).
fn get_num(m: &FieldMap, n: u128) -> Option<f64> {
    m.get(&n)?.iter().find_map(|e| match e {
        Entry::Varint(v) => Some(*v as f64),
        _ => None,
    })
}

/// First occurrence of `n` with wire 5 or 1, in wire order;
/// float32 values widen to f64 exactly as the JS DataView read does.
fn get_flt(m: &FieldMap, n: u128) -> Option<f64> {
    m.get(&n)?.iter().find_map(|e| match e {
        Entry::F32(v) => Some(*v as f64),
        Entry::F64(v) => Some(*v),
        _ => None,
    })
}

/// The JS `x || null` idiom: empty strings become null.
fn or_null(s: Option<String>) -> Option<String> {
    s.filter(|x| !x.is_empty())
}

/// Raw occurrence count of a field, all wire types — the JS
/// `(map.get(n) || []).length` used for stop_updates.
fn entry_count(m: &FieldMap, n: u128) -> usize {
    m.get(&n).map(|v| v.len()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// GTFS-RT field maps (gtfs-realtime.proto; field numbers are NOT in
// declaration order — route_id is 5 in TripDescriptor, vehicle is 8 and
// position is 2 in VehiclePosition.  The JS source is the authority.)
// ---------------------------------------------------------------------------

struct TripDescriptor {
    trip_id: Option<String>,
    route_id: Option<String>,
    direction_id: Option<f64>,
}

fn parse_trip_descriptor(m: Option<&FieldMap>) -> TripDescriptor {
    match m {
        None => TripDescriptor {
            trip_id: None,
            route_id: None,
            direction_id: None,
        },
        Some(m) => TripDescriptor {
            trip_id: get_str(m, 1),
            route_id: get_str(m, 5),
            direction_id: get_num(m, 6),
        },
    }
}

struct VehicleDescriptor {
    vehicle_id: Option<String>,
    label: Option<String>,
    // Parsed by the JS and part of its descriptor shape, though no
    // current decode surface emits it.
    #[allow(dead_code)]
    license_plate: Option<String>,
}

fn parse_vehicle_descriptor(m: Option<&FieldMap>) -> VehicleDescriptor {
    match m {
        None => VehicleDescriptor {
            vehicle_id: None,
            label: None,
            license_plate: None,
        },
        Some(m) => VehicleDescriptor {
            vehicle_id: get_str(m, 1),
            label: get_str(m, 2),
            license_plate: get_str(m, 3),
        },
    }
}

struct Position {
    lat: Option<f64>,
    lon: Option<f64>,
    bearing: Option<f64>,
    speed: Option<f64>,
}

fn parse_position(m: Option<&FieldMap>) -> Position {
    match m {
        None => Position {
            lat: None,
            lon: None,
            bearing: None,
            speed: None,
        },
        Some(m) => Position {
            lat: get_flt(m, 1),
            lon: get_flt(m, 2),
            bearing: get_flt(m, 3),
            speed: get_flt(m, 5),
        },
    }
}

fn feed_ts(root: &FieldMap) -> Result<Option<f64>, DecodeError> {
    match sub(root, 1)? {
        None => Ok(None),
        Some(header) => Ok(get_num(&header, 3)),
    }
}

// ---------------------------------------------------------------------------
// Decoded output shapes — field order matches the JS object literals
// exactly, because to_json renders in this order.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Vehicle {
    pub entity_id: Option<String>,
    pub vehicle_id: Option<String>,
    pub label: Option<String>,
    pub route_id: Option<String>,
    pub trip_id: Option<String>,
    pub direction_id: Option<f64>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub bearing: Option<f64>,
    pub speed: Option<f64>,
    pub stop_id: Option<String>,
    pub ts: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VehiclesFeed {
    pub feed_ts: Option<f64>,
    pub vehicles: Vec<Vehicle>,
}

/// Transcription of the JS `decodeVehicles`.
pub fn decode_vehicles(buf: &[u8]) -> Result<VehiclesFeed, DecodeError> {
    let root = parse_fields(buf)?;
    let ts = feed_ts(&root)?;
    let mut vehicles = Vec::new();
    for ent in subs(&root, 2)? {
        let vp = match sub(&ent, 4)? {
            None => continue,
            Some(v) => v,
        };
        let trip_m = sub(&vp, 1)?;
        let trip = parse_trip_descriptor(trip_m.as_ref());
        let veh_m = sub(&vp, 8)?;
        let veh = parse_vehicle_descriptor(veh_m.as_ref());
        let pos_m = sub(&vp, 2)?;
        let pos = parse_position(pos_m.as_ref());
        vehicles.push(Vehicle {
            entity_id: get_str(&ent, 1),
            vehicle_id: or_null(veh.vehicle_id),
            label: or_null(veh.label),
            route_id: or_null(trip.route_id),
            trip_id: or_null(trip.trip_id),
            direction_id: trip.direction_id,
            lat: pos.lat,
            lon: pos.lon,
            bearing: pos.bearing,
            speed: pos.speed,
            stop_id: get_str(&vp, 7),
            ts: get_num(&vp, 5),
        });
    }
    Ok(VehiclesFeed {
        feed_ts: ts,
        vehicles,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trip {
    pub entity_id: Option<String>,
    pub trip_id: Option<String>,
    pub route_id: Option<String>,
    pub vehicle_id: Option<String>,
    pub delay: Option<f64>,
    pub ts: Option<f64>,
    pub stop_updates: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TripsFeed {
    pub feed_ts: Option<f64>,
    pub trips: Vec<Trip>,
}

/// Transcription of the JS `decodeTrips`.
pub fn decode_trips(buf: &[u8]) -> Result<TripsFeed, DecodeError> {
    let root = parse_fields(buf)?;
    let ts = feed_ts(&root)?;
    let mut trips = Vec::new();
    for ent in subs(&root, 2)? {
        let tu = match sub(&ent, 3)? {
            None => continue,
            Some(v) => v,
        };
        let trip_m = sub(&tu, 1)?;
        let trip = parse_trip_descriptor(trip_m.as_ref());
        let veh_m = sub(&tu, 3)?;
        let veh = parse_vehicle_descriptor(veh_m.as_ref());
        trips.push(Trip {
            entity_id: get_str(&ent, 1),
            trip_id: or_null(trip.trip_id),
            route_id: or_null(trip.route_id),
            vehicle_id: or_null(veh.vehicle_id),
            delay: get_num(&tu, 5),
            ts: get_num(&tu, 4),
            stop_updates: entry_count(&tu, 2),
        });
    }
    Ok(TripsFeed {
        feed_ts: ts,
        trips,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Period {
    pub start: Option<f64>,
    pub end: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub entity_id: Option<String>,
    pub routes: Vec<String>,
    pub periods: Vec<Period>,
    pub header: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertsFeed {
    pub feed_ts: Option<f64>,
    pub alerts: Vec<Alert>,
}

fn translated_text(m: Option<&FieldMap>) -> Result<Option<String>, DecodeError> {
    match m {
        None => Ok(None),
        Some(m) => match sub(m, 1)? {
            None => Ok(None),
            Some(tr) => Ok(get_str(&tr, 1)),
        },
    }
}

/// Transcription of the JS `decodeAlerts`.
pub fn decode_alerts(buf: &[u8]) -> Result<AlertsFeed, DecodeError> {
    let root = parse_fields(buf)?;
    let ts = feed_ts(&root)?;
    let mut alerts = Vec::new();
    for ent in subs(&root, 2)? {
        let al = match sub(&ent, 5)? {
            None => continue,
            Some(v) => v,
        };
        let mut routes = Vec::new();
        for ie in subs(&al, 5)? {
            // JS: const r = str(ie, 2); if (r) routes.push(r) —
            // null and empty string are both excluded.
            if let Some(r) = get_str(&ie, 2) {
                if !r.is_empty() {
                    routes.push(r);
                }
            }
        }
        let periods = subs(&al, 1)?
            .iter()
            .map(|p| Period {
                start: get_num(p, 1),
                end: get_num(p, 2),
            })
            .collect();
        let header_m = sub(&al, 10)?;
        let desc_m = sub(&al, 11)?;
        alerts.push(Alert {
            entity_id: get_str(&ent, 1),
            routes,
            periods,
            header: translated_text(header_m.as_ref())?,
            description: translated_text(desc_m.as_ref())?,
        });
    }
    Ok(AlertsFeed {
        feed_ts: ts,
        alerts,
    })
}

// ---------------------------------------------------------------------------
// JSON emission — byte-identical to JSON.stringify of the JS result.
//
// serde_json's float rendering is NOT the JS rendering (it emits
// "0.0" where JS emits "0", and different exponent forms), so the
// text form is produced here directly: shortest round-trip digits
// (via Rust's LowerExp, which selects the same digit string as
// V8's Grisu/Ryu path) laid out by the ECMAScript
// Number::toString rules.  Non-finite floats render as `null`,
// exactly as JSON.stringify renders NaN/Infinity.
// ---------------------------------------------------------------------------

/// Render an f64 the way JS `JSON.stringify` renders the number.
pub fn js_number(x: f64) -> String {
    if !x.is_finite() {
        return "null".to_string();
    }
    if x == 0.0 {
        // Covers -0.0: JSON.stringify(-0) === "0".
        return "0".to_string();
    }
    let neg = x < 0.0;
    let a = x.abs();
    // Shortest round-trip digits: "d[.ddd]e<exp>" with value =
    // digits * 10^(exp - (k-1)), k = digit count.
    let s = format!("{a:e}");
    let (mant, exp) = s.split_once('e').expect("LowerExp always has e");
    let exp: i64 = exp.parse().expect("LowerExp exponent is an integer");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    // ECMAScript's n: value = digits * 10^(n-k).
    let n = exp + 1;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let ni = n as usize;
        out.push_str(&digits[..ni]);
        out.push('.');
        out.push_str(&digits[ni..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        if k == 1 {
            out.push_str(&digits);
        } else {
            out.push_str(&digits[..1]);
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
        }
        out.push_str(&e.to_string());
    }
    out
}

fn json_num(x: Option<f64>) -> String {
    match x {
        None => "null".to_string(),
        Some(v) => js_number(v),
    }
}

/// Quote a string exactly as JSON.stringify does: only `"`, `\`,
/// and control characters below U+0020 are escaped (with the
/// \b \f \n \r \t short forms); everything else is raw UTF-8.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_string(s: &Option<String>) -> String {
    match s {
        None => "null".to_string(),
        Some(v) => json_string(v),
    }
}

impl Vehicle {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"entity_id\":{},\"vehicle_id\":{},\"label\":{},\"route_id\":{},\"trip_id\":{},\"direction_id\":{},\"lat\":{},\"lon\":{},\"bearing\":{},\"speed\":{},\"stop_id\":{},\"ts\":{}}}",
            json_opt_string(&self.entity_id),
            json_opt_string(&self.vehicle_id),
            json_opt_string(&self.label),
            json_opt_string(&self.route_id),
            json_opt_string(&self.trip_id),
            json_num(self.direction_id),
            json_num(self.lat),
            json_num(self.lon),
            json_num(self.bearing),
            json_num(self.speed),
            json_opt_string(&self.stop_id),
            json_num(self.ts),
        )
    }
}

impl VehiclesFeed {
    pub fn to_json(&self) -> String {
        let items: Vec<String> = self.vehicles.iter().map(|v| v.to_json()).collect();
        format!(
            "{{\"feed_ts\":{},\"vehicles\":[{}]}}",
            json_num(self.feed_ts),
            items.join(",")
        )
    }
}

impl Trip {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"entity_id\":{},\"trip_id\":{},\"route_id\":{},\"vehicle_id\":{},\"delay\":{},\"ts\":{},\"stop_updates\":{}}}",
            json_opt_string(&self.entity_id),
            json_opt_string(&self.trip_id),
            json_opt_string(&self.route_id),
            json_opt_string(&self.vehicle_id),
            json_num(self.delay),
            json_num(self.ts),
            self.stop_updates,
        )
    }
}

impl TripsFeed {
    pub fn to_json(&self) -> String {
        let items: Vec<String> = self.trips.iter().map(|t| t.to_json()).collect();
        format!(
            "{{\"feed_ts\":{},\"trips\":[{}]}}",
            json_num(self.feed_ts),
            items.join(",")
        )
    }
}

impl Period {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"start\":{},\"end\":{}}}",
            json_num(self.start),
            json_num(self.end)
        )
    }
}

impl Alert {
    pub fn to_json(&self) -> String {
        let routes: Vec<String> = self.routes.iter().map(|r| json_string(r)).collect();
        let periods: Vec<String> = self.periods.iter().map(|p| p.to_json()).collect();
        format!(
            "{{\"entity_id\":{},\"routes\":[{}],\"periods\":[{}],\"header\":{},\"description\":{}}}",
            json_opt_string(&self.entity_id),
            routes.join(","),
            periods.join(","),
            json_opt_string(&self.header),
            json_opt_string(&self.description),
        )
    }
}

impl AlertsFeed {
    pub fn to_json(&self) -> String {
        let items: Vec<String> = self.alerts.iter().map(|a| a.to_json()).collect();
        format!(
            "{{\"feed_ts\":{},\"alerts\":[{}]}}",
            json_num(self.feed_ts),
            items.join(",")
        )
    }
}

// ---------------------------------------------------------------------------
// Organelle surface (feature = "organelle").
//
// Input for every op: {"bytes_hex": "<hex of one GTFS-RT feed
// payload>"}.  Output: the decoded feed as a JSON value — the same
// data to_json renders as text (numbers travel as f64 values; any
// downstream text rendering is the serialiser's choice, and the
// byte-parity form is to_json).
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn num_value(x: Option<f64>) -> Value {
    match x {
        None => Value::Null,
        Some(v) => serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null),
    }
}

#[cfg(feature = "organelle")]
fn opt_string_value(s: &Option<String>) -> Value {
    match s {
        None => Value::Null,
        Some(v) => Value::String(v.clone()),
    }
}

#[cfg(feature = "organelle")]
impl Vehicle {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "entity_id": opt_string_value(&self.entity_id),
            "vehicle_id": opt_string_value(&self.vehicle_id),
            "label": opt_string_value(&self.label),
            "route_id": opt_string_value(&self.route_id),
            "trip_id": opt_string_value(&self.trip_id),
            "direction_id": num_value(self.direction_id),
            "lat": num_value(self.lat),
            "lon": num_value(self.lon),
            "bearing": num_value(self.bearing),
            "speed": num_value(self.speed),
            "stop_id": opt_string_value(&self.stop_id),
            "ts": num_value(self.ts),
        })
    }
}

#[cfg(feature = "organelle")]
impl VehiclesFeed {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "feed_ts": num_value(self.feed_ts),
            "vehicles": self.vehicles.iter().map(|v| v.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[cfg(feature = "organelle")]
impl Trip {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "entity_id": opt_string_value(&self.entity_id),
            "trip_id": opt_string_value(&self.trip_id),
            "route_id": opt_string_value(&self.route_id),
            "vehicle_id": opt_string_value(&self.vehicle_id),
            "delay": num_value(self.delay),
            "ts": num_value(self.ts),
            "stop_updates": self.stop_updates,
        })
    }
}

#[cfg(feature = "organelle")]
impl TripsFeed {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "feed_ts": num_value(self.feed_ts),
            "trips": self.trips.iter().map(|t| t.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[cfg(feature = "organelle")]
impl Alert {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "entity_id": opt_string_value(&self.entity_id),
            "routes": self.routes.iter().map(|r| Value::String(r.clone())).collect::<Vec<_>>(),
            "periods": self.periods.iter().map(|p| serde_json::json!({
                "start": num_value(p.start),
                "end": num_value(p.end),
            })).collect::<Vec<_>>(),
            "header": opt_string_value(&self.header),
            "description": opt_string_value(&self.description),
        })
    }
}

#[cfg(feature = "organelle")]
impl AlertsFeed {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "feed_ts": num_value(self.feed_ts),
            "alerts": self.alerts.iter().map(|a| a.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let bytes_input = serde_json::json!({
        "type": "object",
        "required": ["bytes_hex"],
        "properties": {
            "bytes_hex": {"type": "string", "description": "hex-encoded GTFS-RT feed payload"}
        }
    });
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "gtfs-rt-decode".to_string(),
        codon: "gd".to_string(),
        version: "1.0.0".to_string(),
        description: "GTFS-Realtime protobuf decoder (vehicles / trips / alerts); byte-parity port of the translink-repeater gtfsrt.js".to_string(),
        contracts: vec![
            Contract {
                op: "decode_vehicles".to_string(),
                description: "decode a GTFS-RT payload into {feed_ts, vehicles} (VehiclePosition entities)".to_string(),
                input_schema: bytes_input.clone(),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "decode_trips".to_string(),
                description: "decode a GTFS-RT payload into {feed_ts, trips} (TripUpdate entities)".to_string(),
                input_schema: bytes_input.clone(),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "decode_alerts".to_string(),
                description: "decode a GTFS-RT payload into {feed_ts, alerts} (Alert entities)".to_string(),
                input_schema: bytes_input,
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
pub struct GtfsRtDecode {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(GtfsRtDecode {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
impl Organelle for GtfsRtDecode {
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
        let hex_str = input["bytes_hex"].as_str().ok_or_else(|| {
            OrganelleError::new("rejected", "bytes_hex must be a hex string")
        })?;
        let buf = hex::decode(hex_str)
            .map_err(|e| OrganelleError::new("rejected", format!("bytes_hex: {e}")))?;
        let rejected = |e: DecodeError| OrganelleError::new("rejected", e.0);
        match op {
            "decode_vehicles" => Ok(decode_vehicles(&buf).map_err(rejected)?.to_value()),
            "decode_trips" => Ok(decode_trips(&buf).map_err(rejected)?.to_value()),
            "decode_alerts" => Ok(decode_alerts(&buf).map_err(rejected)?.to_value()),
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_layout() {
        // ECMAScript Number::toString cases, incl. the layout
        // boundaries at n = 21 / n = -6 and the -0 rule.
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (100.0, "100"),
            (0.5, "0.5"),
            (0.1, "0.1"),
            (1.5, "1.5"),
            (-2.25, "-2.25"),
            (1234567.0, "1234567"),
            (1762000000.0, "1762000000"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1.23e21, "1.23e+21"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (5e-324, "5e-324"),
            (18446744073709551616.0, "18446744073709552000"),
            (49.2827f32 as f64, "49.28269958496094"),
            (-123.125f32 as f64, "-123.125"),
            (0.30000000000000004, "0.30000000000000004"),
        ];
        for (x, want) in cases {
            assert_eq!(js_number(*x), *want, "js_number({x})");
        }
        assert_eq!(js_number(f64::NAN), "null");
        assert_eq!(js_number(f64::INFINITY), "null");
        assert_eq!(js_number(f64::NEG_INFINITY), "null");
    }

    #[test]
    fn empty_feed() {
        let v = decode_vehicles(&[]).unwrap();
        assert_eq!(v.to_json(), "{\"feed_ts\":null,\"vehicles\":[]}");
        let t = decode_trips(&[]).unwrap();
        assert_eq!(t.to_json(), "{\"feed_ts\":null,\"trips\":[]}");
        let a = decode_alerts(&[]).unwrap();
        assert_eq!(a.to_json(), "{\"feed_ts\":null,\"alerts\":[]}");
    }

    #[test]
    fn wire_errors_match_js() {
        // [0x0b] = field 1, wire type 3.
        assert_eq!(
            decode_vehicles(&[0x0b]).unwrap_err().0,
            "unsupported wire type 3"
        );
        // [0x08, 0x80] = field 1 varint, continuation then EOF.
        assert_eq!(
            decode_vehicles(&[0x08, 0x80]).unwrap_err().0,
            "truncated varint"
        );
        // Eleven continuation bytes: the 11th pushes shift past 70.
        let mut long = vec![0x08u8];
        long.extend([0x80u8; 11]);
        assert_eq!(decode_vehicles(&long).unwrap_err().0, "varint too long");
    }

    #[test]
    fn clamped_length_delimited() {
        // Entity field (2) declares 100 bytes but only 2 remain:
        // the JS clamps the slice instead of throwing.  The two
        // bytes are a valid empty VehiclePosition submessage
        // (field 4 absent -> the entity is skipped, no error).
        let buf = [0x12u8, 100, 0x00, 0x00];
        let v = decode_vehicles(&buf).unwrap();
        assert_eq!(v.vehicles.len(), 0);
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::*;
    use organelle_host::Host;

    #[test]
    fn decode_vehicles_shape() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let out = h
            .call(&ctx, "gd", "decode_vehicles", serde_json::json!({"bytes_hex": ""}))
            .unwrap()
            .output;
        assert_eq!(
            out,
            serde_json::json!({"feed_ts": null, "vehicles": []})
        );
    }

    #[test]
    fn decode_rejects_bad_hex() {
        // Host semantics: an error raised inside handle() lands as
        // verdict Failed with the organelle's code preserved in the
        // receipt ("failed:rejected"); Rejected verdicts are the
        // host gates' own.  The code is what callers key on.
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let err = h
            .call(
                &ctx,
                "gd",
                "decode_alerts",
                serde_json::json!({"bytes_hex": "zz"}),
            )
            .unwrap_err();
        assert_eq!(err.verdict, organelle_host::CallVerdict::Failed);
        assert!(err.reason.contains("[rejected]"), "reason: {}", err.reason);
        assert!(err.reason.contains("bytes_hex"), "reason: {}", err.reason);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
