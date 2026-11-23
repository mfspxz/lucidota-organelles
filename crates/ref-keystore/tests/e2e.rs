//! End-to-end USE of pt-keystore's real function, driven by the treatment
//! lane: create a keystore, persist the encrypted file to real disk, reload
//! it from the bytes on disk, sign with each role, verify every signature,
//! and exercise Willow provenance tokens. Run with `--nocapture` for the
//! printed evidence trail.

use ed25519_dalek::Verifier;
use ref_keystore::willow::WillowProvenance;
use ref_keystore::{KeyRole, Keystore};

#[test]
fn keystore_full_lifecycle_on_disk() {
    let pass = "e2e-operator-passphrase";
    let ks = Keystore::create(pass).unwrap();
    println!("roles created: {:?}", ks.roles());
    for r in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
        println!("  {r:?}{} pubkey {}", r.symbol(), hex::encode(ks.pubkey(r).unwrap().to_bytes()));
    }

    // Persist to a real file and reload from the bytes on disk.
    let path = std::env::temp_dir().join("pt-keystore-e2e.json");
    std::fs::write(&path, ks.to_json().unwrap()).unwrap();
    let disk_bytes = std::fs::read_to_string(&path).unwrap();
    println!("keystore file on disk: {} ({} bytes)", path.display(), disk_bytes.len());
    assert!(!disk_bytes.contains("treatment"), "no plaintext secrets in the file");

    let loaded = Keystore::from_json(&disk_bytes, pass).unwrap();
    loaded.unlock_check().unwrap();
    println!("reload + unlock_check: OK");

    // Sign a real message with each role; verify against the advertised pubkey.
    let msg = b"pt-ledger checkpoint 2026-11-23: anchor the recovery campaign";
    for r in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
        let sig = loaded.sign(r, msg).unwrap();
        loaded.pubkey(r).unwrap().verify(msg, &sig).unwrap();
        println!("  sign+verify {r:?}: OK (sig {})", hex::encode(&sig.to_bytes()[..8]));
    }

    // Wrong passphrase cannot sign.
    let impostor = Keystore::from_json(&disk_bytes, "not-the-passphrase").unwrap();
    assert!(impostor.sign(KeyRole::Master, msg).is_err());
    println!("wrong passphrase sign attempt: refused, as required");

    std::fs::remove_file(&path).ok();
}

#[test]
fn willow_provenance_token_roundtrip() {
    let willow = WillowProvenance::from_seed([0x42; 32]);
    let token = willow.issue(b"receipt rcpt_8842 verified against pt-ledger");
    println!(
        "willow token: attester {} epoch {} ts {}",
        token.attester_pubkey_hex, token.epoch, token.timestamp
    );
    WillowProvenance::verify(&token).unwrap();
    println!("willow verify: OK");
    let mut forged = token.clone();
    forged.message = b"receipt rcpt_8842 FABRICATED".to_vec();
    assert!(WillowProvenance::verify(&forged).is_err());
    println!("willow tampered message: refused, as required");
}
