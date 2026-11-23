//! Proving tests for the composition: the trio working as one system.
//! Run with `--nocapture` for the printed evidence trail.

use ref_verified_context::{sign_verdict, verified_context, verify_signed_verdict, SignedVerdict};
use pt_contracts::contracts::MultiSigWallet;
use pt_contracts::vm::Vm;
use pt_contracts::{Contract, GasMeter};
use pt_forged::gate;
use pt_keystore::{KdfParams, KeyRole, Keystore};

fn fast_keystore() -> Keystore {
    Keystore::create_with_params(
        "compose-test-passphrase",
        KdfParams {
            m_cost_kib: 4096,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap()
}

#[test]
fn forged_verdict_signed_by_keystore_verifies_and_tamper_fails() {
    let ks = fast_keystore();

    // The gate does its real work first.
    let verdict = gate(
        "golden path regression gate passes on the proof kernel",
        "VERIFIED",
        true,
    );
    assert!(verdict.admitted);

    // The keystore's Master key signs the verdict — provenance is now a
    // signature, not a header comment.
    let signed = sign_verdict(&ks, KeyRole::Master, &verdict).unwrap();
    println!(
        "signed verdict: role={:?} pubkey={}… sig={}…",
        signed.signer_role,
        &signed.signer_pubkey[..16],
        &signed.signature[..16]
    );
    let back = verify_signed_verdict(&signed).unwrap();
    assert_eq!(back, verdict);
    println!("verify_signed_verdict: OK, verdict round-trips intact");

    // Alter the verdict after signing (flip admitted on a blocked claim)
    // and the signature refuses it.
    let blocked = gate("the whole system is 100% production ready", "PASS", true);
    assert!(!blocked.admitted);
    let mut forged_pkt = sign_verdict(&ks, KeyRole::Master, &blocked).unwrap();
    forged_pkt.verdict_json = forged_pkt.verdict_json.replace("\"admitted\":false", "\"admitted\":true");
    let res = verify_signed_verdict(&forged_pkt);
    println!("tampered verdict (admitted flipped post-signing): {res:?}");
    assert!(res.is_err(), "a verdict altered after signing must not verify");

    // A packet signed by a different keystore does not verify under this
    // packet's claimed pubkey either (pubkey substitution).
    let other = fast_keystore();
    let foreign = sign_verdict(&other, KeyRole::Master, &verdict).unwrap();
    let swapped = SignedVerdict {
        signer_pubkey: signed.signer_pubkey.clone(),
        ..foreign
    };
    assert!(verify_signed_verdict(&swapped).is_err());
    println!("pubkey-substituted packet: refused, as required");
}

#[test]
fn contracts_kernel_flag_earned_by_real_signature() {
    let ks = fast_keystore();
    let signers: Vec<[u8; 32]> = (1..=3u8).map(|i| [i; 32]).collect();
    let wallet = MultiSigWallet::new(2, signers);
    let script = wallet.compile();
    let state = wallet.initial_state();

    // The "kernel message" stands in for the pt-coin tx kernel digest the
    // enclosing transaction would carry. The keystore's Personal key signs
    // it — a real signature, produced by the real custody crate.
    let kernel_msg = b"omote-ura kernel: tx 8842, excess proof binding";
    let sig = ks.sign(KeyRole::Personal, kernel_msg).unwrap();
    let ctx = verified_context(
        &ks,
        KeyRole::Personal,
        kernel_msg,
        &sig.to_bytes(),
        100,
        1_750_000_000,
        1,
    )
    .unwrap();
    println!("context with REAL valid kernel sig: kernel_signature_valid={}", ctx.kernel_signature_valid);
    assert!(ctx.kernel_signature_valid);
    let mut gas = GasMeter::new(10_000);
    let ok = Vm::execute(&script, &state, &ctx, &mut gas).unwrap();
    println!("multisig execute: passed={} gas_used={}", ok.passed, ok.gas_used);
    assert!(ok.passed);

    // Same script, but the signature was made over a DIFFERENT kernel
    // message (an attacker's or a stale one): the context honestly carries
    // false and the VM refuses — nobody asserted the bool.
    let wrong_sig = ks.sign(KeyRole::Personal, b"a different tx entirely").unwrap();
    let ctx2 = verified_context(
        &ks,
        KeyRole::Personal,
        kernel_msg,
        &wrong_sig.to_bytes(),
        100,
        1_750_000_000,
        1,
    )
    .unwrap();
    println!("context with WRONG kernel sig: kernel_signature_valid={}", ctx2.kernel_signature_valid);
    assert!(!ctx2.kernel_signature_valid);
    let mut gas2 = GasMeter::new(10_000);
    let refused = Vm::execute(&script, &state, &ctx2, &mut gas2);
    println!("multisig execute with unearned flag: {refused:?}");
    assert!(refused.is_err(), "VM must refuse when the flag was not earned");
}
