//! Parity suite: the Rust port vs the JS authority.
//!
//! Every `.pb` fixture in tests/fixtures/ is decoded by all three
//! decoders, and the port's `to_json` text must equal the golden
//! file byte for byte.  Goldens are `JSON.stringify` output (or
//! `ERROR: <message>` for error fixtures) generated from the JS
//! decoder by tests/make-fixtures.mjs — never from this crate.
//!
//! Fixture provenance:
//! * mbta-vehicles.pb / mbta-trips.pb / mbta-alerts.pb — live
//!   snapshots of MBTA's public GTFS-RT CDN feeds
//!   (cdn.mbta.com/realtime/{VehiclePositions,TripUpdates,Alerts}.pb)
//!   fetched 2026-11-23 ~08:02 UTC.
//! * synthetic.pb / synthetic-noheader.pb — hand-encoded feeds
//!   covering the edge shapes the live snapshots do not: empty
//!   strings through the `|| null` sites, float64 positions, a
//!   NaN bearing, a negative delay in 64-bit varint form,
//!   mixed-wire stop_time_update entries, an invalid-UTF-8
//!   entity id, and a missing feed header.
//! * bad-wire.pb / truncated.pb — malformed inputs; both
//!   implementations must fail with the same message.

use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn decode(decoder: &str, buf: &[u8]) -> Result<String, String> {
    match decoder {
        "vehicles" => decode_vehicles_text(buf),
        "trips" => decode_trips_text(buf),
        "alerts" => decode_alerts_text(buf),
        _ => unreachable!(),
    }
}

use ref_gtfs_rt_decode::{decode_alerts, decode_trips, decode_vehicles};

fn decode_vehicles_text(buf: &[u8]) -> Result<String, String> {
    decode_vehicles(buf)
        .map(|f| f.to_json())
        .map_err(|e| e.0)
}

fn decode_trips_text(buf: &[u8]) -> Result<String, String> {
    decode_trips(buf).map(|f| f.to_json()).map_err(|e| e.0)
}

fn decode_alerts_text(buf: &[u8]) -> Result<String, String> {
    decode_alerts(buf).map(|f| f.to_json()).map_err(|e| e.0)
}

#[test]
fn parity_all_fixtures_all_decoders() {
    let dir = fixtures_dir();
    let mut pbs: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "pb").unwrap_or(false))
        .collect();
    pbs.sort();
    assert!(!pbs.is_empty(), "no fixtures found in {dir:?}");

    let mut checked = 0usize;
    for pb in &pbs {
        let base = pb.file_stem().unwrap().to_str().unwrap().to_string();
        let buf = fs::read(pb).unwrap();
        for decoder in ["vehicles", "trips", "alerts"] {
            let golden_path = dir.join(format!("{base}.{decoder}.json"));
            let golden = fs::read_to_string(&golden_path)
                .unwrap_or_else(|e| panic!("missing golden {golden_path:?}: {e}"));
            match golden.strip_prefix("ERROR: ") {
                Some(want_msg) => {
                    let got = decode(decoder, &buf);
                    assert!(
                        got.is_err(),
                        "{base}.{decoder}: JS failed ({want_msg}) but Rust succeeded: {got:?}"
                    );
                    assert_eq!(
                        got.unwrap_err(),
                        want_msg,
                        "{base}.{decoder}: error message mismatch"
                    );
                }
                None => {
                    let got = decode(decoder, &buf).unwrap_or_else(|e| {
                        panic!("{base}.{decoder}: Rust failed ({e}) but JS golden exists")
                    });
                    assert_eq!(
                        got, golden,
                        "{base}.{decoder}: JSON mismatch\nrust: {}\njs:   {}",
                        &got[..got.len().min(400)],
                        &golden[..golden.len().min(400)]
                    );
                }
            }
            checked += 1;
        }
    }
    // 6 fixtures x 3 decoders at the time of writing; the count
    // guards against a silently empty fixture set.
    assert!(checked >= 18, "only {checked} parity cases ran");
}
