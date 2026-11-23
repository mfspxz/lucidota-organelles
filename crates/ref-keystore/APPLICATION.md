# Applying `ref-keystore` — encrypted key-at-rest (TKS)

Harvested by copy from pt-keystore, the pt-crypto-infra treatment
crate (`~/workspace/full-send/projects/pt-crypto-infra/app/pt-keystore/`).
Harvested files, each byte-identical (sha256 verified both sides):

- `src/lib.rs` (551 lines) → `src/keystore.rs`
  (`811021a9395d9458…`)
- `src/willow.rs` (186 lines) → `src/keystore/willow.rs`
  (`2018eda49ae4cd1e…`)
- `tests/fixtures/keystore_v1_legacy.json` → same path
  (`4a1cac45721c8c63…`)

The proving tests and examples are copied with only the
crate-name import updated (`pt_keystore` → `ref_keystore`).
The project tree keeps its own code; this crate is the composable
organelle form. `src/lib.rs` adds only re-exports and organelle
glue. The relocation (`lib.rs` → `keystore.rs`, `willow.rs` under
it) is a module-path move only — no line differs.

## What it is

The chain's real key lifecycle, replacing hardcoded test seeds
and in-RAM-only ephemeral keys:

- **Hierarchy**: three Ed25519 keys — MASTER (top signing
  authority), PERSONAL (everyday signing), VOID ✦ (the
  grant/revoke key for the secret Void storage layer; stored like
  the others — the symbol-gated Void *toggle logic* is
  deliberately not in this crate).
- **At rest**: secret seeds encrypted with XChaCha20-Poly1305
  (AEAD); the encryption key is derived from a passphrase via
  Argon2id. The file records its own `kdf_params` and derivation
  uses the recorded values (treatment fix 1: pre-fix files that
  recorded only the label `"argon2id"` still load, via compiled-in
  defaults matching their era).
- **Bound entries**: every entry is AEAD-sealed with its
  (role, pubkey) as authenticated data — transplanting an entry
  into another role's slot fails decryption instead of signing
  wrong (treatment fix 2). Honest seam, inherited from the
  treatment: entries in pre-fix files stay unbound until the key
  is re-added.
- **Zeroize**: secret bytes are zeroized on drop.
- **Willow** (`willow` module): provenance tokens proving "this
  signer saw this exact content," with epoch key rotation;
  tampered messages are refused.

## API

```toml
[dependencies]
ref-keystore = {
  path = "<relative path>/organelles/crates/ref-keystore",
  default-features = false, # pure keystore only
}
```

```rust
use ref_keystore::{KeyRole, Keystore};

let mut ks = Keystore::create("passphrase")?;       // generates the hierarchy
let master_pub = ks.pubkey(KeyRole::Master)?;
let sig = ks.sign(KeyRole::Master, b"message")?;
let json = ks.to_json()?;                            // encrypted at rest
let ks2 = Keystore::from_json(&json, "passphrase")?; // wrong passphrase cannot sign
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `ks`, op `roles` — the stateless half; signing and
unlocking need a live passphrase-held `Keystore` and stay on the
pure API).

## Consumers

- **Origin**: pt-keystore in the pt-crypto-infra treatment tree —
  adoption there is a dependency swap.
- **ref-verified-context**: composes this crate as the signer /
  verifier for gate verdicts and kernel signatures (it consumes
  this organelle under the dependency rename `pt-keystore`, see
  its APPLICATION.md).
- **Any estate crate** still holding keys as hardcoded seeds or
  process-lifetime RAM values.

## wasm32 status

Native: builds clean, tests 16/16 (14 unit + 2 e2e, incl. the
legacy-fixture and transplant regression tests).
wasm32-unknown-unknown check: **PASS**, with the org-025 remedy
recorded in this crate's Cargo.toml: the graph pulls getrandom
0.2 with no wasm backend, so the `js` feature is enabled for
wasm32 only via a target-gated same-name dependency entry.
(Native unaffected; native suite re-run green after the change.)

## Adoption steps

1. Add the path dependency above.
2. Create or load the keystore once (`create` / `from_json`);
   hold it in memory, never the passphrase.
3. Sign and verify through role keys (`sign`, `pubkey`); persist
   only `to_json()` output.
4. Re-add keys in any pre-fix keystore files you still carry, so
   their entries become AEAD-bound.
