//! Treatment-lane tool: generate a keystore file with the CURRENT (pre-fix)
//! code and write it to disk as a legacy-format fixture. The post-fix test
//! suite loads this exact file to prove backward compatibility.
//! Usage: cargo run --example legacy_fixture -- <out-path>
use ref_keystore::{KeyRole, Keystore};

fn main() {
    let out = std::env::args().nth(1).expect("out path");
    let ks = Keystore::create("treatment-fixture-passphrase").unwrap();
    let json = ks.to_json().unwrap();
    std::fs::write(&out, &json).unwrap();
    for r in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
        println!("{r:?} pubkey {}", hex::encode(ks.pubkey(r).unwrap().to_bytes()));
    }
    println!("wrote {out} ({} bytes)", json.len());
}
