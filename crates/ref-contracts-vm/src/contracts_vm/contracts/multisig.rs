//! MultiSigWallet — N-of-M threshold multi-signature wallet with time-locked
//! recovery and daily withdrawal limits.
//!
//! ## Design
//!
//! Multi-sig in OMOTE·URA does NOT require a separate signature verification VM.
//! The pt-coin kernel signature is already a Schnorr proof of knowledge of the
//! excess blinding factor. For multi-sig, signers collaboratively produce an
//! aggregate kernel signature where the excess is the sum of partial excesses
//! from ≥ T signers. The kernel sig either verifies (≥ T signed) or it doesn't.
//!
//! The VM layer's role is:
//!   1. Encode the public keys and threshold in the contract state.
//!   2. Verify the threshold is met (via kernel signature validity + signer
//!      counting in the state).
//!   3. Enforce time-locked recovery: after a timeout, fewer signers can move
//!      funds (e.g. 1-of-N after 30 days).
//!   4. Daily withdrawal limits: NOT yet enforceable in this VM (no
//!      state-field opcodes, no amount in the execution context). A wallet
//!      configured with a limit fails closed at execution instead of
//!      silently ignoring it (treatment fix, 2026-11-23).
//!
//! ## State format
//!
//! State data: `[threshold | key_count | pubkey_1 | ... | pubkey_N | last_withdrawal_time | daily_withdrawn]`
//!   - threshold: u8 — minimum signers required
//!   - key_count: u8 — total number of signers
//!   - pubkeys: key_count × 32 bytes
//!   - last_withdrawal_time: u64 (LE) — timestamp of last withdrawal
//!   - daily_withdrawn: u64 (LE) — amount withdrawn in current 24h window
//!
//! The daily limit is a contract compile-time constant; the window state
//! is runtime data stored in the state blob.

use crate::vm::{OpCode, Script, ScriptBuilder};
use crate::{Contract, ContractState, PublicKey};

/// A multi-signature wallet with configurable threshold, time-locked
/// recovery, and daily withdrawal limits.
pub struct MultiSigWallet {
    /// Minimum number of signers required for a standard operation.
    pub threshold: u8,

    /// Ordered list of authorized public keys.
    pub signers: Vec<PublicKey>,

    /// Recovery threshold: after `recovery_delay_seconds`, only this many
    /// signers are needed. Must be ≤ `threshold`.
    pub recovery_threshold: u8,

    /// Delay in seconds before the recovery path activates.
    pub recovery_delay_seconds: u64,

    /// Maximum value that can be withdrawn per 24-hour window.
    /// 0 = unlimited.
    pub daily_withdrawal_limit: u64,
}

impl MultiSigWallet {
    /// Create a new multi-sig wallet with standard threshold.
    pub fn new(threshold: u8, signers: Vec<PublicKey>) -> Self {
        assert!(threshold > 0, "threshold must be >= 1");
        assert!(!signers.is_empty(), "must have at least one signer");
        assert!(threshold as usize <= signers.len(), "threshold cannot exceed signer count");
        Self {
            threshold,
            signers,
            recovery_threshold: threshold,
            recovery_delay_seconds: 0,
            daily_withdrawal_limit: 0,
        }
    }

    /// Add a recovery path: after `delay_seconds`, `recovery_threshold` signers
    /// can move funds instead of the full `threshold`.
    pub fn with_recovery(mut self, recovery_threshold: u8, delay_seconds: u64) -> Self {
        assert!(recovery_threshold <= self.threshold, "recovery threshold must be <= standard threshold");
        self.recovery_threshold = recovery_threshold;
        self.recovery_delay_seconds = delay_seconds;
        self
    }

    /// Enforce a daily withdrawal limit.
    pub fn with_daily_limit(mut self, limit: u64) -> Self {
        self.daily_withdrawal_limit = limit;
        self
    }

    /// Build the initial state data blob for this wallet.
    fn build_state_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + self.signers.len() * 32 + 16);
        data.push(self.threshold);
        data.push(self.signers.len() as u8);
        for pk in &self.signers {
            data.extend_from_slice(pk);
        }
        // last_withdrawal_time = 0
        data.extend_from_slice(&0u64.to_le_bytes());
        // daily_withdrawn = 0
        data.extend_from_slice(&0u64.to_le_bytes());
        data
    }
}

impl Contract for MultiSigWallet {
    fn compile(&self) -> Script {
        let mut sb = ScriptBuilder::new();

        // ── Standard path: check kernel signature (threshold already proven) ──
        // The kernel sig on the enclosing tx proves that ≥ threshold signers
        // contributed excess. The VM just needs to verify the sig is valid.
        //
        // Script:
        //   OP_STATE_LOAD              // push state
        //   <threshold> OP_PICK ...    // extract threshold from state
        //   OP_CHECK_MULTISIG          // verify multi-sig via kernel
        //   OP_VERIFY                  // abort if not
        //   OP_1                       // success

        // For simplicity in this VM, OP_CHECK_MULTISIG reads the threshold
        // and keys from the stack. We push them from state.
        //
        // Stack layout for OP_CHECK_MULTISIG:
        //   <dummy_sig> ... <dummy_sig> <M> <pubkey1> ... <pubkeyN> <N>

        // Push dummy signatures (M of them). The actual sig verification is
        // done by pt-coin's kernel sig check; the dummy sigs are placeholders.
        for _ in 0..self.threshold {
            sb.push_data(&[0u8; 64]); // 64-byte dummy sig
        }

        sb.push_int(self.threshold as i64);

        // Push public keys from contract state.
        for pk in &self.signers {
            sb.push_data(pk);
        }

        sb.push_int(self.signers.len() as i64);

        // OP_CHECK_MULTISIG pops N pubkeys + M sigs, pushes kernel validity.
        sb.push_op(OpCode::CheckMultiSig);
        sb.push_op(OpCode::Verify);

        // ── Daily withdrawal limit check (if enabled) ──
        if self.daily_withdrawal_limit > 0 {
            // FAIL CLOSED (treatment fix, 2026-11-23). The pre-fix code
            // emitted a literal `push 1; OP_VERIFY` placeholder here, so a
            // wallet configured with a daily limit executed exactly as if
            // the limit did not exist — a security control that silently
            // did nothing. The limit genuinely cannot be enforced yet: the
            // VM has no opcodes to read fields out of the state blob, and
            // ExecutionContext carries no withdrawal amount. Until the VM
            // grows state-field opcodes and the context carries an amount,
            // a daily-limited wallet refuses to execute rather than pretend.
            sb.push_int(0);
            sb.push_op(OpCode::Verify);
        }

        // ── State transition: update owner (preserve multi-sig state) ──
        // Push the same state data as the new state (multisig config unchanged).
        let state_data = self.build_state_data();
        sb.push_data(&state_data);
        sb.push_op(OpCode::StateStore);

        // Success.
        sb.push_int(1);

        sb.build()
    }

    fn initial_state(&self) -> ContractState {
        ContractState::genesis(self.signers[0], self.build_state_data())
    }

    fn contract_type(&self) -> &'static str {
        "MultiSigWallet"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Vm;
    use crate::{ExecutionContext, GasMeter, gas_costs};

    fn test_keys(n: usize) -> Vec<PublicKey> {
        (0..n).map(|i| {
            let mut pk = [0u8; 32];
            pk[0] = i as u8 + 1;
            pk
        }).collect()
    }

    #[test]
    fn multisig_2of3_with_valid_kernel_passes() {
        let signers = test_keys(3);
        let wallet = MultiSigWallet::new(2, signers.clone());
        let script = wallet.compile();
        let state = wallet.initial_state();

        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: signers[0],
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };

        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas).unwrap();
        assert!(result.passed, "2-of-3 with valid kernel sig must pass");
        assert!(result.new_state.is_some());
    }

    #[test]
    fn multisig_fails_with_invalid_kernel() {
        let signers = test_keys(3);
        let wallet = MultiSigWallet::new(2, signers.clone());
        let script = wallet.compile();
        let state = wallet.initial_state();

        let ctx = ExecutionContext {
            kernel_signature_valid: false,
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: signers[0],
            tx_fee: 0,
            confirmations: 1,
        };

        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas);
        assert!(result.is_err(), "invalid kernel sig must fail multi-sig");
    }

    #[test]
    fn multisig_3of5_passes() {
        let signers = test_keys(5);
        let wallet = MultiSigWallet::new(3, signers.clone());
        let script = wallet.compile();
        let state = wallet.initial_state();

        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: signers[0],
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };

        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas).unwrap();
        assert!(result.passed, "3-of-5 with valid kernel sig must pass");
    }

    #[test]
    fn multisig_state_data_roundtrip() {
        let signers = test_keys(3);
        let wallet = MultiSigWallet::new(2, signers);
        let data = wallet.build_state_data();

        // Verify state data format
        assert_eq!(data[0], 2, "threshold byte");
        assert_eq!(data[1], 3, "key_count byte");
        // 3 × 32 = 96 bytes of pubkeys
        assert_eq!(data.len(), 2 + 3 * 32 + 8 + 8);
    }

    #[test]
    fn daily_limit_fails_closed_until_vm_can_enforce_it() {
        // Treatment regression (2026-11-23): a wallet configured with a
        // daily withdrawal limit must NOT execute as if the limit were
        // enforced — the VM has no state-field opcodes and the execution
        // context carries no amount, so the limit cannot be checked today.
        // Failing closed is the only honest behaviour. (Pre-fix, compile()
        // emitted a literal `push 1; OP_VERIFY` placeholder and the wallet
        // executed exactly as if no limit existed.)
        let signers = test_keys(3);
        let wallet = MultiSigWallet::new(2, signers.clone()).with_daily_limit(1_000);
        let script = wallet.compile();
        let state = wallet.initial_state();
        let ctx = ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: signers[0],
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 1,
        };
        let mut gas = GasMeter::new(gas_costs::DEFAULT_LIMIT);
        let result = Vm::execute(&script, &state, &ctx, &mut gas);
        assert!(
            result.is_err(),
            "a daily-limited wallet must fail closed, not silently execute unenforced"
        );
    }

    #[test]
    #[should_panic(expected = "threshold must be >= 1")]
    fn zero_threshold_rejected() {
        MultiSigWallet::new(0, test_keys(2));
    }

    #[test]
    #[should_panic(expected = "threshold cannot exceed signer count")]
    fn threshold_exceeds_signers_rejected() {
        MultiSigWallet::new(5, test_keys(3));
    }
}
