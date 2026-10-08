//! org-019 — Reference organelle: geo-point (codon `gp`).
//!
//! Pure geodesic math: haversine distance and bounding-box containment.
//! ReadOnly, Proven (deterministic recomputation).

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

const EARTH_M: f64 = 6_371_000.0;

fn manifest() -> OrganelleManifest {
    let coord = serde_json::json!({"type": "number", "minimum": -180.0, "maximum": 180.0});
    let lat = serde_json::json!({"type": "number", "minimum": -90.0, "maximum": 90.0});
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "geo-point".to_string(),
        codon: "gp".to_string(),
        version: "1.0.0".to_string(),
        description: "reference geodesic math organelle".to_string(),
        contracts: vec![
            Contract {
                op: "distance".to_string(),
                description: "haversine distance in meters".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["lat1", "lon1", "lat2", "lon2"],
                    "properties": {"lat1": lat, "lon1": coord, "lat2": lat, "lon2": coord}
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "in_bbox".to_string(),
                description: "point-in-bounding-box test".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["lat", "lon", "min_lat", "min_lon", "max_lat", "max_lon"],
                    "properties": {
                        "lat": lat, "min_lat": lat, "max_lat": lat,
                        "lon": coord, "min_lon": coord, "max_lon": coord
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

pub struct GeoPoint {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(GeoPoint { manifest: manifest() })
}

fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_M * a.sqrt().asin()
}

impl Organelle for GeoPoint {
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
        let f = |k: &str| input[k].as_f64().unwrap_or(0.0);
        match op {
            "distance" => {
                let m = haversine_m(f("lat1"), f("lon1"), f("lat2"), f("lon2"));
                Ok(serde_json::json!({"meters": m}))
            }
            "in_bbox" => {
                let inside = f("lat") >= f("min_lat")
                    && f("lat") <= f("max_lat")
                    && f("lon") >= f("min_lon")
                    && f("lon") <= f("max_lon");
                Ok(serde_json::json!({"inside": inside}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn call(op: &str, input: Value) -> Value {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        h.call(&ctx, "gp", op, input).unwrap()
    }

    #[test]
    fn distance_known() {
        // Vancouver (49.2827,-123.1207) -> New Westminster (49.2067,-122.9111):
        // roughly 17.5 km. Assert a sane band, not a fragile exact figure.
        let out = call(
            "distance",
            serde_json::json!({"lat1": 49.2827, "lon1": -123.1207, "lat2": 49.2067, "lon2": -122.9111}),
        );
        let m = out["meters"].as_f64().unwrap();
        assert!((15_000.0..20_000.0).contains(&m), "got {m}");
        // Zero distance to self.
        let zero = call(
            "distance",
            serde_json::json!({"lat1": 0.0, "lon1": 0.0, "lat2": 0.0, "lon2": 0.0}),
        );
        assert_eq!(zero["meters"].as_f64().unwrap(), 0.0);
    }

    #[test]
    fn bbox() {
        let inside = call(
            "in_bbox",
            serde_json::json!({"lat": 49.28, "lon": -123.12,
                "min_lat": 49.0, "min_lon": -124.0, "max_lat": 50.0, "max_lon": -122.0}),
        );
        assert_eq!(inside["inside"], serde_json::json!(true));
        let outside = call(
            "in_bbox",
            serde_json::json!({"lat": 48.0, "lon": -123.12,
                "min_lat": 49.0, "min_lon": -124.0, "max_lat": 50.0, "max_lon": -122.0}),
        );
        assert_eq!(outside["inside"], serde_json::json!(false));
    }

    #[test]
    fn out_of_range_rejected() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "gp", "distance",
                serde_json::json!({"lat1": 91.0, "lon1": 0.0, "lat2": 0.0, "lon2": 0.0}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Rejected);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
