//! Print the compiled manifest as pretty JSON. Used to generate
//! `organelles/claim-reconciler.manifest.json`:
//! `cargo run -p claim-reconciler --example emit_manifest > organelles/claim-reconciler.manifest.json`
//! The `manifest_json_validates_and_matches_compiled` test pins the two together.

use claim_reconciler::organelle;

fn main() {
    let v = serde_json::to_value(organelle().manifest()).expect("manifest serializable");
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
