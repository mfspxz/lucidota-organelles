//! TransferContract — simple value transfer with optional time-lock.
//!
//! The workhorse contract: moves value from one owner to another. Supports
//! absolute time-locks (`lock_until_block`) and relative time-locks
//! (`maturity_blocks`) for delayed settlements.
//!
//! ## Script logic
//!
//! ```text
//!   OP_STATE_LOAD          // push current state data
//!   <recipient> OP_EQ      // check recipient matches
//!   OP_VERIFY              // abort if not
//!   <locktime> OP_CHECK_LOCKTIME OP_DROP  // optional absolute lock
//!   <sequence> OP_CHECK_SEQUENCE OP_DROP   // optional relative lock
//!   <new_state> OP_STATE_STORE            // commit new state
//!   OP_1                   // success
//! ```
//!
//! The recipient is encoded in the state data as a 32-byte public key.

use crate::vm::{OpCode, Script, ScriptBuilder};
use crate::{Contract, ContractState, PublicKey};

/// A simple transfer contract: moves ownership to a recipient, optionally
/// locked until a block height or minimum confirmations.
pub struct TransferContract {
    /// The receiving public key (32 bytes).
    pub recipient: PublicKey,

    /// Absolute lock: transaction invalid until this block height.
    /// 0 = no lock.
    pub lock_until_block: u64,

    /// Relative lock: transaction invalid until this many confirmations
    /// have elapsed since the UTXO was created. 0 = no lock.
    pub maturity_blocks: u64,
}

impl TransferContract {
    pub fn new(recipient: PublicKey) -> Self {
        Self {
            recipient,
            lock_until_block: 0,
            maturity_blocks: 0,
        }
    }

    pub fn with_lock(mut self, block: u64) -> Self {
        self.lock_until_block = block;
        self
    }

    pub fn with_maturity(mut self, blocks: u64) -> Self {
        self.maturity_blocks = blocks;
        self
    }
}

impl Contract for TransferContract {
    fn compile(&self) -> Script {
        let mut sb = ScriptBuilder::new();

        // Push the current state data (contains current owner pubkey).
        sb.push_op(OpCode::StateLoad);

        // Check that the recipient in the desired state matches.
        sb.push_data(&self.recipient);
        sb.push_op(OpCode::Eq);
        sb.push_op(OpCode::Verify);

        // Optional absolute time-lock.
        if self.lock_until_block > 0 {
            sb.push_int(self.lock_until_block as i64);
            sb.push_op(OpCode::CheckLocktime);
            sb.push_op(OpCode::Drop);
        }

        // Optional relative time-lock (maturity).
        if self.maturity_blocks > 0 {
            sb.push_int(self.maturity_blocks as i64);
            sb.push_op(OpCode::CheckSequence);
            sb.push_op(OpCode::Drop);
        }

        // Store new state: owner = recipient, data = empty (simple transfer).
        // The recipient's pubkey becomes the new state data.
        sb.push_data(&self.recipient);
        sb.push_op(OpCode::StateStore);

        // Success.
        sb.push_int(1);

        sb.build()
    }

    fn initial_state(&self) -> ContractState {
        // Initial state: the sender's public key. In practice this is set
        // by the UTXO creator, not by the contract template.
        ContractState::genesis([0u8; 32], Vec::new())
    }

    fn contract_type(&self) -> &'static str {
        "Transfer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Vm;
    use crate::{ExecutionContext, GasMeter, gas_costs};

    #[test]
    fn transfer_to_correct_recipient_passes() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let contract = TransferContract::new(bob);
        let script = contract.compile();

        // State data must match the contract's embedded recipient pubkey.
        // StateLoad pushes state.data; the contract checks data == recipient.
        let state = ContractState::genesis(alice, bob.to_vec());

        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: alice,
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };

        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas).unwrap();

        assert!(result.passed, "transfer to correct recipient must pass");
        assert!(result.new_state.is_some(), "must commit new state");
        let ns = result.new_state.unwrap();
        assert_eq!(ns.data, bob.to_vec(), "new state data = recipient pubkey");
    }

    #[test]
    fn transfer_to_wrong_recipient_fails() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let mallory = [99u8; 32];

        let contract = TransferContract::new(bob); // expecting bob
        let script = contract.compile();

        // State owned by alice but state data = mallory (wrong recipient in state)
        let state = ContractState::genesis(alice, mallory.to_vec());

        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: alice,
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };

        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas);
        assert!(result.is_err(), "transfer to wrong recipient must fail");
    }

    #[test]
    fn transfer_with_lock_blocks_until_mature() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let contract = TransferContract::new(bob).with_lock(200);
        let script = contract.compile();

        let state = ContractState::genesis(alice, bob.to_vec());

        // Block height 100 < lock 200 → should fail
        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: alice,
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };
        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas);
        assert!(result.is_err(), "locked transfer must fail before maturity");

        // Block height 200 >= lock 200 → should pass
        let ctx2 = ExecutionContext {
            block_height: 200,
            ..ctx
        };
        let mut gas2 = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result2 = Vm::execute(&script, &state, &ctx2, &mut gas2).unwrap();
        assert!(result2.passed, "locked transfer must pass after maturity");
    }

    #[test]
    fn transfer_with_relative_maturity() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let contract = TransferContract::new(bob).with_maturity(6);
        let script = contract.compile();

        let state = ContractState::genesis(alice, bob.to_vec());

        // 3 confirmations < 6 required → fail
        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: alice,
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 3,
        };
        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas);
        assert!(result.is_err(), "immature UTXO must fail");

        // 12 confirmations >= 6 required → pass
        let ctx2 = ExecutionContext {
            confirmations: 12,
            ..ctx
        };
        let mut gas2 = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result2 = Vm::execute(&script, &state, &ctx2, &mut gas2).unwrap();
        assert!(result2.passed, "mature UTXO must pass");
    }
}
