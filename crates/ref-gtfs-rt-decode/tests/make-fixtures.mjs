// make-fixtures.mjs — regenerate every fixture + golden in
// tests/fixtures/ for the ref-gtfs-rt-decode parity suite.
//
// Goldens are produced by the AUTHORITY implementation
// (~/workspace/translink-repeater/gtfsrt.js) — never by the Rust
// port — so the parity tests compare the port against the JS,
// not against itself.
//
// Live fixtures (mbta-*.pb) are snapshots fetched from MBTA's
// public GTFS-RT CDN (https://cdn.mbta.com/realtime/{Vehicle
// Positions,TripUpdates,Alerts}.pb) on 2026-11-23 ~08:02 UTC;
// they are committed bytes and are NOT refetched by this script.
// This script (re)builds the synthetic + error fixtures and then
// regenerates every golden from whatever .pb files are present.
//
// Usage: node tests/make-fixtures.mjs
import { writeFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");
const gtfsrt = new URL("../../../../translink-repeater/gtfsrt.js", import.meta.url);
const { decodeVehicles, decodeTrips, decodeAlerts } = await import(gtfsrt);

// ---- minimal protobuf encoder (test-side only) --------------------------
function varint(n) {
  // n: BigInt, unsigned.
  const out = [];
  let v = n;
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return Buffer.from(out);
}
const tag = (field, wire) => varint(BigInt((field << 3) | wire));
const lenField = (field, bytes) => Buffer.concat([tag(field, 2), varint(BigInt(bytes.length)), bytes]);
const varField = (field, n) => Buffer.concat([tag(field, 0), varint(n)]);
const strField = (field, s) => lenField(field, Buffer.from(s, "utf8"));
const bytesField = (field, b) => lenField(field, b);
function f32Field(field, x) {
  const b = Buffer.alloc(4);
  b.writeFloatLE(x, 0);
  return Buffer.concat([tag(field, 5), b]);
}
function f64Field(field, x) {
  const b = Buffer.alloc(8);
  b.writeDoubleLE(x, 0);
  return Buffer.concat([tag(field, 1), b]);
}
const msg = (...parts) => Buffer.concat(parts);

// ---- synthetic.pb: one FeedMessage exercising the edge shapes -----------
// Header with timestamp; a fully-populated vehicle (empty route_id
// -> null, empty label -> null, empty stop_id kept, bearing 0.0,
// speed as float64); a sparse vehicle (float64 lat, NaN bearing,
// no trip/vehicle); a trip update (negative delay as a 64-bit
// two's-complement varint, stop_time_update entries of mixed wire
// types); an alert (empty route excluded, first translation wins,
// empty description kept); an id-only entity (skipped everywhere);
// an entity whose id is invalid UTF-8 (lossy-decode parity).
const header = msg(strField(1, "2.0"), varField(3, 1762000000n));

const tripDesc1 = msg(strField(1, "T1"), strField(5, ""), varField(6, 1n));
const position1 = msg(
  f32Field(1, 49.25),
  f32Field(2, -123.1),
  f32Field(3, 0.0),
  f64Field(5, 12.5)
);
const vehicleDesc1 = msg(strField(1, "V1"), strField(2, ""));
const vp1 = msg(
  lenField(1, tripDesc1),
  lenField(2, position1),
  varField(5, 1762000001n),
  strField(7, ""),
  lenField(8, vehicleDesc1)
);
const ent1 = msg(strField(1, "synth-v1"), lenField(4, vp1));

const position2 = msg(f64Field(1, 49.2827), f32Field(3, NaN));
const vp2 = msg(lenField(2, position2));
const ent2 = msg(strField(1, "synth-v2"), lenField(4, vp2));

const NEG_DELAY = (1n << 64n) - 300n; // int32 -300 as the wire sends it
const stuA = lenField(2, msg(varField(1, 5n))); // stop_time_update, wire 2
const stuB = varField(2, 7n); // stop_time_update field, wire 0 (counts!)
const stuC = lenField(2, msg()); // stop_time_update, wire 2, empty
const tu = msg(
  lenField(1, msg(strField(1, "T9"), strField(5, "99"))),
  stuA,
  stuB,
  stuC,
  lenField(3, msg(strField(1, "V9"))),
  varField(4, 1762000002n),
  varField(5, NEG_DELAY)
);
const ent3 = msg(strField(1, "synth-t1"), lenField(3, tu));

const periodA = msg(varField(1, 1762000000n));
const periodB = msg(varField(1, 1n), varField(2, 2n));
const ieA = msg(strField(2, "R1"));
const ieB = msg(strField(2, ""));
const ieC = msg();
// header_text is a TranslatedString: repeated Translation at
// field 1, each Translation carrying its text at field 1.
const headerText = msg(
  lenField(1, msg(strField(1, "First"))),
  lenField(1, msg(strField(1, "Second")))
);
const descText = msg(lenField(1, msg(strField(1, ""))));
const alert = msg(
  lenField(1, periodA),
  lenField(1, periodB),
  lenField(5, ieA),
  lenField(5, ieB),
  lenField(5, ieC),
  lenField(10, headerText),
  lenField(11, descText)
);
const ent4 = msg(strField(1, "synth-a1"), lenField(5, alert));

const ent5 = msg(strField(1, "synth-none"));

const badId = Buffer.from([0xff, 0xfe]);
const vp6 = msg(lenField(2, msg(f32Field(1, 1.5), f32Field(2, 2.5))));
const ent6 = msg(bytesField(1, badId), lenField(4, vp6));

const synthetic = msg(
  lenField(1, header),
  lenField(2, ent1),
  lenField(2, ent2),
  lenField(2, ent3),
  lenField(2, ent4),
  lenField(2, ent5),
  lenField(2, ent6)
);
writeFileSync(join(fixtures, "synthetic.pb"), synthetic);

// synthetic-noheader.pb: same vehicle entity, no header -> feed_ts null.
writeFileSync(join(fixtures, "synthetic-noheader.pb"), msg(lenField(2, ent1)));

// ---- error fixtures ------------------------------------------------------
// field 1, wire type 3 -> "unsupported wire type 3" in both decoders.
writeFileSync(join(fixtures, "bad-wire.pb"), Buffer.from([0x0b]));
// field 1 varint with a dangling continuation byte -> "truncated varint".
writeFileSync(join(fixtures, "truncated.pb"), Buffer.from([0x08, 0x80]));

// ---- goldens --------------------------------------------------------------
const decoders = [
  ["vehicles", decodeVehicles],
  ["trips", decodeTrips],
  ["alerts", decodeAlerts],
];
for (const name of readdirSync(fixtures).sort()) {
  if (!name.endsWith(".pb")) continue;
  const base = name.slice(0, -3);
  const buf = new Uint8Array(readFileSync(join(fixtures, name)));
  for (const [dname, decode] of decoders) {
    let text;
    try {
      text = JSON.stringify(decode(buf));
    } catch (e) {
      text = `ERROR: ${e.message}`;
    }
    writeFileSync(join(fixtures, `${base}.${dname}.json`), text);
    console.log(`${base}.${dname}.json  ${text.length} chars`);
  }
}
console.log("fixtures + goldens written to", fixtures);
