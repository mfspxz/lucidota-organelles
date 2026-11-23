//! pt-keystore — encrypted key-at-rest for the LUCIDOTA chain.
//!
//! ## What this fixes (the honest gap)
//! Before this crate, every key was either a hardcoded test seed (`from_seed([0x2a;32])`)
//! or an ephemeral in-RAM `generate(OsRng)` that vanished at process exit. No key ever
//! touched disk, and nothing was encrypted at rest. This crate is the real key lifecycle:
//!
//!   - keys GENERATED from the OS CSPRNG (never a hardcoded seed in production),
//!   - key material ENCRYPTED AT REST with XChaCha20-Poly1305 (AEAD),
//!   - the encryption key DERIVED from a passphrase via Argon2id (memory-hard KDF),
//!   - secret bytes ZEROIZED on drop (no lingering key material in freed memory).
//!
//! ## The operator key hierarchy (3 keys, held here)
//!   - MASTER   — top signing authority (public face = its verifying key)
//!   - PERSONAL — the operator's everyday signing key
//!   - VOID     — the ✦ (U+2726) key: sole grant/revoke authority over the secret
//!     Void storage layer of the chain. "Mine and Lucidota's alone to grant entry to,
//!     ever." This key's mere USE is the sovereign's silent exception; the keystore
//!     stores it like the others, but the Void toggle logic (silent, symbol-gated,
//!     second-key) is a SEPARATE build gated on operator confirmation — NOT here yet.
//!
//! Every secret key is an Ed25519 32-byte seed. The public (verifying) keys are derived
//! and stored in the clear (they're public by definition); only the SECRET seeds are
//! encrypted.

pub mod willow;

use argon2::{Argon2, Params};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Which key in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRole {
    Master,
    Personal,
    /// The ✦ (U+2726) Void grant/revoke key — secret-storage access authority.
    Void,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRole::Master => "master",
            KeyRole::Personal => "personal",
            KeyRole::Void => "void",
        }
    }
    /// The ✦ symbol is the Void's marker (U+2726 BLACK FOUR POINTED STAR).
    pub fn symbol(&self) -> &'static str {
        match self {
            KeyRole::Void => "\u{2726}",
            _ => "",
        }
    }
}

/// One encrypted secret key on disk. `pubkey` is cleartext (public by definition);
/// only `ciphertext` (the 32-byte Ed25519 seed) is encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    pub role: KeyRole,
    pub pubkey: String,     // hex, cleartext
    pub salt: String,       // hex, per-key Argon2 salt
    pub nonce: String,      // hex, 24-byte XChaCha nonce
    pub ciphertext: String, // hex, AEAD(seed)
}

/// Argon2id cost parameters, persisted in the keystore file.
///
/// Treatment fix (2026-11-23): pre-fix files recorded only the label
/// `"argon2id"` and derived with whatever `Argon2::default()` happened to
/// be compiled in — a silent weld between every existing file and one
/// build's defaults. Any future parameter upgrade would have bricked every
/// file, and the file carried nothing a future reader could derive with.
/// Files now record the parameters they were written under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Argon2 memory cost, KiB.
    pub m_cost_kib: u32,
    /// Argon2 time cost (iterations).
    pub t_cost: u32,
    /// Argon2 parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// The parameters this build derives with by default.
    pub fn current_default() -> Self {
        Self {
            m_cost_kib: Params::DEFAULT_M_COST,
            t_cost: Params::DEFAULT_T_COST,
            p_cost: Params::DEFAULT_P_COST,
        }
    }

    fn to_params(&self) -> Result<Params, KeystoreError> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| KeystoreError::Kdf)
    }
}

/// The on-disk keystore file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    pub version: u32,
    pub kdf: String,    // "argon2id"
    pub cipher: String, // "xchacha20poly1305"
    /// KDF parameters every key in this file was encrypted under.
    /// Absent in pre-fix files — those are read with the legacy compiled-in
    /// defaults they were written under (`KdfParams::current_default()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<KdfParams>,
    pub keys: Vec<EncryptedKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed — wrong passphrase or tampered keystore")]
    Decrypt,
    #[error("no key with role {0:?}")]
    NoSuchRole(KeyRole),
    #[error("bad key material: {0}")]
    BadKey(String),
    #[error("io: {0}")]
    Io(String),
    #[error("serde: {0}")]
    Serde(String),
}

/// Derive a 32-byte AEAD key from a passphrase + salt via Argon2id (memory-hard),
/// using the cost parameters recorded in the keystore file.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &Params,
) -> Result<[u8; 32], KeystoreError> {
    let mut out = [0u8; 32];
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params.clone())
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| KeystoreError::Kdf)?;
    Ok(out)
}

/// Additional authenticated data binding an encrypted seed to its slot: the
/// role it belongs to and the public key it must correspond to.
///
/// Treatment fix (2026-11-23): pre-fix entries were encrypted with no AAD,
/// so an entry's salt/nonce/ciphertext could be transplanted into another
/// role's slot and `sign(that_role)` would silently sign with the wrong
/// key — the signature then fails against the pubkey the keystore
/// advertises for that role. New entries are AEAD-bound to (role, pubkey);
/// a transplanted entry no longer decrypts at all.
fn entry_aad(role: KeyRole, pubkey_hex: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + pubkey_hex.len());
    aad.extend_from_slice(b"pt-keystore/v1\0");
    aad.extend_from_slice(role.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(pubkey_hex.as_bytes());
    aad
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// Encrypt a 32-byte Ed25519 seed under a passphrase. Fresh salt + nonce each
/// call. The ciphertext is AEAD-bound to (role, pubkey) via AAD — see
/// `entry_aad`.
fn encrypt_seed(
    seed: &[u8; 32],
    passphrase: &[u8],
    params: &Params,
    aad: &[u8],
) -> Result<(String, String, String), KeystoreError> {
    let salt = rand_bytes::<16>();
    let nonce = rand_bytes::<24>();
    let mut aead_key = derive_key(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed.as_slice(),
                aad,
            },
        )
        .map_err(|_| KeystoreError::Encrypt)?;
    aead_key.zeroize();
    Ok((hex::encode(salt), hex::encode(nonce), hex::encode(ct)))
}

fn decrypt_seed(
    ek: &EncryptedKey,
    passphrase: &[u8],
    params: &Params,
) -> Result<[u8; 32], KeystoreError> {
    let salt = hex::decode(&ek.salt).map_err(|e| KeystoreError::BadKey(e.to_string()))?;
    let nonce = hex::decode(&ek.nonce).map_err(|e| KeystoreError::BadKey(e.to_string()))?;
    let ct = hex::decode(&ek.ciphertext).map_err(|e| KeystoreError::BadKey(e.to_string()))?;
    let mut aead_key = derive_key(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = entry_aad(ek.role, &ek.pubkey);
    // Current format: AAD-bound. Legacy fallback: entries written before the
    // AAD fix carry no binding, so if the bound attempt fails, retry unbound
    // — that path exists ONLY so pre-fix files stay readable; everything
    // written by this build is bound, and a transplanted bound entry fails
    // both attempts (its ciphertext was sealed under a different AAD).
    let mut pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ct.as_slice(),
                aad: &aad,
            },
        )
        .or_else(|_| cipher.decrypt(XNonce::from_slice(&nonce), ct.as_slice()))
        .map_err(|_| KeystoreError::Decrypt)?;
    aead_key.zeroize();
    if pt.len() != 32 {
        pt.zeroize();
        return Err(KeystoreError::BadKey("seed not 32 bytes".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pt);
    pt.zeroize();
    Ok(seed)
}

/// The in-memory keystore. Secret seeds live here only transiently; on disk they are
/// always encrypted. Call `lock()` semantics by dropping — seeds zeroize on drop.
pub struct Keystore {
    file: KeystoreFile,
    passphrase: Vec<u8>,
    /// The KDF parameters in force for this keystore (recorded in the file,
    /// or the legacy defaults for a pre-fix file).
    kdf: KdfParams,
}

impl Keystore {
    /// Create a fresh keystore, generating all three keys from the OS CSPRNG and
    /// encrypting each under the passphrase.
    pub fn create(passphrase: &str) -> Result<Self, KeystoreError> {
        Self::create_with_params(passphrase, KdfParams::current_default())
    }

    /// Create a fresh keystore with explicit Argon2id cost parameters. The
    /// parameters are recorded in the file, so the file stays decryptable
    /// even after this build's defaults change.
    pub fn create_with_params(
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<Self, KeystoreError> {
        kdf.to_params()?; // validate before doing any work
        let mut ks = Keystore {
            file: KeystoreFile {
                version: 1,
                kdf: "argon2id".into(),
                cipher: "xchacha20poly1305".into(),
                kdf_params: Some(kdf),
                keys: Vec::new(),
            },
            passphrase: passphrase.as_bytes().to_vec(),
            kdf,
        };
        for role in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
            ks.add_key(role)?;
        }
        Ok(ks)
    }

    /// Generate a new key for a role (OS CSPRNG) and store it encrypted.
    pub fn add_key(&mut self, role: KeyRole) -> Result<VerifyingKey, KeystoreError> {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let vk = sk.verifying_key();
        let pubkey_hex = hex::encode(vk.to_bytes());
        let aad = entry_aad(role, &pubkey_hex);
        let params = self.kdf.to_params()?;
        let mut seed = sk.to_bytes(); // 32-byte Ed25519 seed
        let (salt, nonce, ct) = encrypt_seed(&seed, &self.passphrase, &params, &aad)?;
        seed.zeroize();
        self.file.keys.retain(|k| k.role != role); // one key per role
        self.file.keys.push(EncryptedKey {
            role,
            pubkey: pubkey_hex,
            salt,
            nonce,
            ciphertext: ct,
        });
        Ok(vk)
    }

    /// The public (verifying) key for a role — cleartext, safe to publish.
    pub fn pubkey(&self, role: KeyRole) -> Result<VerifyingKey, KeystoreError> {
        let ek = self
            .file
            .keys
            .iter()
            .find(|k| k.role == role)
            .ok_or(KeystoreError::NoSuchRole(role))?;
        let bytes = hex::decode(&ek.pubkey).map_err(|e| KeystoreError::BadKey(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::BadKey("pubkey len".into()))?;
        VerifyingKey::from_bytes(&arr).map_err(|e| KeystoreError::BadKey(e.to_string()))
    }

    /// Decrypt a role's secret and sign a message with it. The secret seed is zeroized
    /// immediately after signing — it never lingers.
    pub fn sign(&self, role: KeyRole, msg: &[u8]) -> Result<Signature, KeystoreError> {
        let ek = self
            .file
            .keys
            .iter()
            .find(|k| k.role == role)
            .ok_or(KeystoreError::NoSuchRole(role))?;
        let params = self.kdf.to_params()?;
        let mut seed = decrypt_seed(ek, &self.passphrase, &params)?;
        let sk = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(sk.sign(msg))
    }

    /// Serialize the ENCRYPTED keystore to JSON (safe to write to disk).
    pub fn to_json(&self) -> Result<String, KeystoreError> {
        serde_json::to_string_pretty(&self.file).map_err(|e| KeystoreError::Serde(e.to_string()))
    }

    /// Load an encrypted keystore from JSON with the passphrase. Does NOT decrypt any
    /// secret yet (lazy — secrets decrypt only at sign time).
    pub fn from_json(json: &str, passphrase: &str) -> Result<Self, KeystoreError> {
        let file: KeystoreFile =
            serde_json::from_str(json).map_err(|e| KeystoreError::Serde(e.to_string()))?;
        // Pre-fix files carry no recorded parameters; they were written
        // under the compiled-in defaults, so those are what reads them.
        let kdf = file.kdf_params.unwrap_or_else(KdfParams::current_default);
        Ok(Keystore {
            file,
            passphrase: passphrase.as_bytes().to_vec(),
            kdf,
        })
    }

    /// Verify the passphrase actually decrypts a key (call after from_json to fail fast
    /// on a wrong passphrase instead of at first sign).
    pub fn unlock_check(&self) -> Result<(), KeystoreError> {
        let ek = self
            .file
            .keys
            .first()
            .ok_or(KeystoreError::BadKey("empty keystore".into()))?;
        let params = self.kdf.to_params()?;
        let mut seed = decrypt_seed(ek, &self.passphrase, &params)?;
        seed.zeroize();
        Ok(())
    }

    pub fn roles(&self) -> Vec<KeyRole> {
        self.file.keys.iter().map(|k| k.role).collect()
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn create_generates_three_keys() {
        let ks = Keystore::create("correct horse battery staple").unwrap();
        assert_eq!(ks.roles().len(), 3);
        for r in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
            assert!(ks.pubkey(r).is_ok(), "role {r:?} must have a pubkey");
        }
    }

    #[test]
    fn sign_and_verify_roundtrip_per_role() {
        let ks = Keystore::create("pw").unwrap();
        let msg = b"anchor this event";
        for r in [KeyRole::Master, KeyRole::Personal, KeyRole::Void] {
            let sig = ks.sign(r, msg).unwrap();
            let vk = ks.pubkey(r).unwrap();
            assert!(vk.verify(msg, &sig).is_ok(), "role {r:?} sig must verify");
        }
    }

    #[test]
    fn keys_are_actually_encrypted_at_rest() {
        let ks = Keystore::create("s3cret").unwrap();
        let json = ks.to_json().unwrap();
        // The JSON must NOT contain any raw secret seed. We can't know the seed bytes,
        // but we CAN assert the ciphertext differs from the pubkey and that decrypting
        // with a WRONG passphrase fails (AEAD tamper/auth).
        assert!(json.contains("xchacha20poly1305"));
        assert!(json.contains("argon2id"));
        let wrong = Keystore::from_json(&json, "WRONG").unwrap();
        assert!(
            wrong.unlock_check().is_err(),
            "wrong passphrase must fail AEAD auth"
        );
        let right = Keystore::from_json(&json, "s3cret").unwrap();
        assert!(right.unlock_check().is_ok(), "right passphrase must unlock");
    }

    #[test]
    fn persisted_key_signs_same_as_original() {
        let ks = Keystore::create("pw2").unwrap();
        let msg = b"round-trip through disk";
        let sig1 = ks.sign(KeyRole::Master, msg).unwrap();
        let vk = ks.pubkey(KeyRole::Master).unwrap();
        // reload from JSON, sign again — same key, so same pubkey verifies both
        let json = ks.to_json().unwrap();
        let ks2 = Keystore::from_json(&json, "pw2").unwrap();
        let sig2 = ks2.sign(KeyRole::Master, msg).unwrap();
        use ed25519_dalek::Verifier;
        assert!(vk.verify(msg, &sig1).is_ok());
        assert!(vk.verify(msg, &sig2).is_ok());
        assert_eq!(
            ks2.pubkey(KeyRole::Master).unwrap().to_bytes(),
            vk.to_bytes()
        );
    }

    #[test]
    fn void_role_carries_the_star_symbol() {
        // ✦ U+2726 is the Void marker.
        assert_eq!(KeyRole::Void.symbol(), "\u{2726}");
        assert_eq!(KeyRole::Master.symbol(), "");
    }

    /// Treatment regression: KDF parameters are recorded in the file and are
    /// what decryption actually uses — tampering with them breaks unlock.
    #[test]
    fn kdf_params_are_persisted_and_load_bearing() {
        let light = KdfParams {
            m_cost_kib: 4096,
            t_cost: 1,
            p_cost: 1,
        };
        let ks = Keystore::create_with_params("pw", light).unwrap();
        let json = ks.to_json().unwrap();
        assert!(
            json.contains("\"kdf_params\""),
            "file must record its KDF parameters"
        );
        let reloaded = Keystore::from_json(&json, "pw").unwrap();
        assert!(reloaded.unlock_check().is_ok());
        let sig = reloaded.sign(KeyRole::Master, b"m").unwrap();
        assert!(reloaded
            .pubkey(KeyRole::Master)
            .unwrap()
            .verify(b"m", &sig)
            .is_ok());

        // Rewrite the recorded params to the defaults: derivation now uses
        // the wrong costs, AEAD auth must fail — the params are load-bearing.
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let d = KdfParams::current_default();
        v["kdf_params"] = serde_json::json!({
            "m_cost_kib": d.m_cost_kib, "t_cost": d.t_cost, "p_cost": d.p_cost
        });
        let tampered = Keystore::from_json(&serde_json::to_string(&v).unwrap(), "pw").unwrap();
        assert!(
            tampered.unlock_check().is_err(),
            "deriving with params other than the recorded ones must fail"
        );
    }

    /// Treatment regression: a keystore file written by the PRE-FIX code
    /// (no kdf_params field, no AAD binding — fixture generated 2026-11-23
    /// with examples/legacy_fixture.rs against the untouched crate) still
    /// loads, unlocks, and signs with the same keys.
    #[test]
    fn legacy_file_without_params_or_aad_still_loads() {
        let json = include_str!("../tests/fixtures/keystore_v1_legacy.json");
        assert!(
            !json.contains("kdf_params"),
            "fixture must be a genuine pre-fix file"
        );
        let ks = Keystore::from_json(json, "treatment-fixture-passphrase").unwrap();
        ks.unlock_check().unwrap();
        // Master pubkey printed by the fixture generator at creation time.
        assert_eq!(
            hex::encode(ks.pubkey(KeyRole::Master).unwrap().to_bytes()),
            "76ef10fd58cff907f00af9a49662e8d9e8c756473987045e7c6559185e4bc4f3"
        );
        let sig = ks.sign(KeyRole::Master, b"legacy").unwrap();
        assert!(ks
            .pubkey(KeyRole::Master)
            .unwrap()
            .verify(b"legacy", &sig)
            .is_ok());
    }

    /// Treatment regression: transplanting one role's encrypted material
    /// into another role's slot (the pre-fix silent key-substitution) now
    /// fails at decryption, because entries are AEAD-bound to (role, pubkey).
    #[test]
    fn transplanted_entry_no_longer_decrypts() {
        let light = KdfParams {
            m_cost_kib: 4096,
            t_cost: 1,
            p_cost: 1,
        };
        let ks = Keystore::create_with_params("pw", light).unwrap();
        let json = ks.to_json().unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys = v["keys"].as_array_mut().unwrap();
        let personal_enc = (
            keys[1]["salt"].clone(),
            keys[1]["nonce"].clone(),
            keys[1]["ciphertext"].clone(),
        );
        keys[0]["salt"] = personal_enc.0;
        keys[0]["nonce"] = personal_enc.1;
        keys[0]["ciphertext"] = personal_enc.2;
        let tampered = Keystore::from_json(&serde_json::to_string(&v).unwrap(), "pw").unwrap();
        assert!(
            tampered.sign(KeyRole::Master, b"x").is_err(),
            "a transplanted entry must fail AEAD, not silently sign with the wrong key"
        );
    }

    #[test]
    fn wrong_passphrase_cannot_sign() {
        let ks = Keystore::create("real-pw").unwrap();
        let json = ks.to_json().unwrap();
        let imposter = Keystore::from_json(&json, "guess").unwrap();
        assert!(
            imposter.sign(KeyRole::Void, b"x").is_err(),
            "no passphrase, no Void signature"
        );
    }
}
