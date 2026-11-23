//! End-to-end USE of pt-contracts' real function, driven by the treatment
//! lane: compile the two built-in contracts and execute them through the VM
//! on realistic ledger scenarios. Run with `--nocapture` for evidence.

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

use ref_contracts_vm::contracts::{MultiSigWallet, TransferContract};
use ref_contracts_vm::vm::Vm;
use ref_contracts_vm::{Contract, ContractState, ExecutionContext, GasMeter};

fn ctx(height: u64, confirmations: u64, kernel_ok: bool) -> ExecutionContext {
    ExecutionContext {
        block_height: height,
        block_timestamp: 1_750_000_000,
        caller: [1u8; 32],
        tx_fee: 0,
        kernel_signature_valid: kernel_ok,
        confirmations,
    }
}

#[test]
fn escrow_transfer_unlocks_at_lock_height_and_chains_state() {
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    // Escrow: transfer to Bob, locked until block 200, 6 confirmations maturity.
    let contract = TransferContract::new(bob).with_lock(200).with_maturity(6);
    let script = contract.compile();
    let state = ContractState::genesis(alice, bob.to_vec());
    println!("genesis state hash: {}", hex(&state.hash()));

    // Too early on both locks.
    let mut gas = GasMeter::new(10_000);
    let early = Vm::execute(&script, &state, &ctx(150, 12, true), &mut gas);
    println!("execute at height 150 (lock 200): {:?}", early.as_ref().map(|_| ()).map_err(|e| e.to_string()));
    assert!(early.is_err(), "absolute lock must block at height 150");

    let mut gas = GasMeter::new(10_000);
    let immature = Vm::execute(&script, &state, &ctx(200, 3, true), &mut gas);
    assert!(immature.is_err(), "maturity must block at 3 confirmations");

    // Both locks satisfied: executes, commits the new state.
    let mut gas = GasMeter::new(10_000);
    let done = Vm::execute(&script, &state, &ctx(200, 12, true), &mut gas).unwrap();
    println!(
        "execute at height 200, 12 confs: passed={} gas_used={}",
        done.passed, done.gas_used
    );
    assert!(done.passed);
    let post = done.new_state.unwrap();
    println!("post-transfer state hash: {}", hex(&post.hash()));
    assert_eq!(post.prior_state_hash, state.hash(), "state hash must chain to genesis");
    assert_eq!(post.data, bob.to_vec());
}

#[test]
fn multisig_wallet_executes_and_rekeys_state() {
    let signers: Vec<[u8; 32]> = (1..=3u8).map(|i| [i; 32]).collect();
    let wallet = MultiSigWallet::new(2, signers.clone()).with_daily_limit(0);
    let script = wallet.compile();
    let state = wallet.initial_state();
    println!("multisig genesis hash: {}", hex(&state.hash()));

    let mut gas = GasMeter::new(10_000);
    let ok = Vm::execute(&script, &state, &ctx(100, 1, true), &mut gas).unwrap();
    println!("2-of-3 with valid kernel sig: passed={} gas_used={}", ok.passed, ok.gas_used);
    assert!(ok.passed);
    let post = ok.new_state.unwrap();
    assert_eq!(post.prior_state_hash, state.hash());
    println!("multisig post-state hash: {}", hex(&post.hash()));

    // Same script, kernel signature invalid → the predicate must fail.
    let mut gas = GasMeter::new(10_000);
    let bad = Vm::execute(&script, &state, &ctx(100, 1, false), &mut gas);
    println!("2-of-3 with INVALID kernel sig: {:?}", bad.as_ref().map(|_| ()).map_err(|e| e.to_string()));
    assert!(bad.is_err());
}
