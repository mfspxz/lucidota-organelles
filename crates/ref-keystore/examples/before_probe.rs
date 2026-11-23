//! Treatment-lane BEFORE probe — demonstrates the two pt-keystore defects on
//! the pre-fix code, using only the public API + the crate's own deps:
//!
//! DEFECT A (no AAD binding): an entry's ciphertext/salt/nonce can be
//! transplanted into another role's slot. sign(Master) then silently signs
//! with the transplanted key, producing a signature that does NOT verify
//! against the pubkey the keystore advertises for Master.
//!
//! DEFECT B (KDF params not persisted): the file records only the string
//! "argon2id". Decryption works ONLY with the exact Argon2 parameters
//! compiled into this build (Argon2::default()). Any future parameter
//! upgrade silently bricks every existing file, and the file itself carries
//! no information a future reader could use to derive correctly.
//!
//! Usage: cargo run --example before_probe -- <fixture-json-path>
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::Verifier;
use ref_keystore::{KeyRole, Keystore};

fn manual_decrypt(
    entry: &serde_json::Value,
    passphrase: &str,
    params: Params,
) -> Result<Vec<u8>, ()> {
    let salt = hex::decode(entry["salt"].as_str().unwrap()).unwrap();
    let nonce = hex::decode(entry["nonce"].as_str().unwrap()).unwrap();
    let ct = hex::decode(entry["ciphertext"].as_str().unwrap()).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|_| ())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| ())
}

fn main() {
    let path = std::env::args().nth(1).expect("fixture path");
    let json = std::fs::read_to_string(&path).unwrap();
    let pass = "treatment-fixture-passphrase";

    // ── DEFECT B ────────────────────────────────────────────────────────
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    println!(
        "DEFECT B: keystore file top-level keys = {:?}",
        v.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    println!("DEFECT B: kdf field = {:?} (a label, no parameters)", v["kdf"]);
    let master = &v["keys"][0];
    let with_default = manual_decrypt(master, pass, Params::default());
    let with_upgraded = manual_decrypt(master, pass, Params::new(65536, 3, 1, Some(32)).unwrap());
    println!(
        "DEFECT B: decrypt with compiled-in default params: {}",
        if with_default.is_ok() { "OK" } else { "FAIL" }
    );
    println!(
        "DEFECT B: decrypt with upgraded params (m=65536,t=3): {} — the file records nothing that would let a future build know which params to use",
        if with_upgraded.is_ok() { "OK" } else { "FAIL (AEAD auth)" }
    );

    // ── DEFECT A ────────────────────────────────────────────────────────
    let mut t = v.clone();
    let keys = t["keys"].as_array_mut().unwrap();
    // Transplant Personal's encrypted material into Master's slot, keeping
    // Master's role + advertised pubkey.
    let personal_enc = (
        keys[1]["salt"].clone(),
        keys[1]["nonce"].clone(),
        keys[1]["ciphertext"].clone(),
    );
    keys[0]["salt"] = personal_enc.0;
    keys[0]["nonce"] = personal_enc.1;
    keys[0]["ciphertext"] = personal_enc.2;
    let tampered = serde_json::to_string(&t).unwrap();
    let ks = Keystore::from_json(&tampered, pass).unwrap();
    let msg = b"treatment probe message";
    let sig = ks.sign(KeyRole::Master, msg).unwrap();
    let advertised_master = ks.pubkey(KeyRole::Master).unwrap();
    let verifies = advertised_master.verify(msg, &sig).is_ok();
    println!(
        "DEFECT A: after transplant, sign(Master) succeeded and signature verifies against advertised Master pubkey: {} — the keystore silently signed with Personal's key under Master's name",
        verifies
    );
}
