//! pt-contracts — smart contract VM for the OMOTE·URA confidential-transaction ledger.
//!
//! ## Design Decision: Declarative Predicate VM (Bitcoin Script lineage)
//!
//! The OMOTE·URA ledger already proves conservation + authorization via kernel
//! signatures (H-1 Schnorr over B_blinding). Adding a Turing-complete VM (WASM,
//! custom bytecode) would balloon the security surface without proportional gain.
//! Instead, we extend Bitcoin Script's proven "predicate that must return true"
//! model with three additions:
//!
//!   1. **State commitment** — contracts may commit a serialised state hash into
//!      output metadata (`OP_STATE_LOAD`, `OP_STATE_STORE`, `OP_STATE_HASH`).
//!   2. **Threshold multi-sig** — `OP_CHECK_MULTISIG` delegates to the kernel
//!      signature aggregation model native to pt-coin.
//!   3. **Time-locks** — `OP_CHECK_LOCKTIME`, `OP_CHECK_SEQUENCE` enforce block-
//!      height / relative maturity constraints.
//!
//! ## What We Stole (and What We Avoided)
//!
//! **Stolen from Bitcoin Script:** stack-based, bounded opcodes, no loops, every
//!   opcode has a fixed gas cost. This is the most battle-tested contract VM alive.
//! **Stolen from Mimblewimble/Grin:** scriptless scripts — multi-sig is NOT a
//!   separate signature-checking VM; it is threshold Schnorr aggregation on the
//!   kernel signature. `OP_CHECK_MULTISIG` merely checks the threshold count.
//! **Avoided from Ethereum:** Turing-completeness, CALL/DELEGATECALL, reentrancy
//!   surfaces, dynamic gas costs, SELFDESTRUCT, CREATE2. All of these are
//!   contract-security footguns that the OMOTE·URA design does not need.
//! **Avoided from Mina:** recursive zk-SNARK verification in the VM. Mina's
//!   constant-size blockchain is elegant but requires a trusted-setup ceremony
//!   (or a STARK prover). OMOTE·URA uses Bulletproofs (no trusted setup).
//! **Avoided from Aleo:** Leo language compilation to AVM bytecode. Adding a
//!   compiler pipeline is premature for a contract layer that can express 90%+
//!   of real-world use cases (transfers, multisig, escrow, time-locks) in ~15
//!   opcodes.
//!
//! ## Architecture
//!
//! ```text
//!   Contract trait
//!     └─ compile() -> Script       // produce VM bytecode
//!     └─ initial_state() -> State  // genesis contract state
//!
//!   VM (interpreter)
//!     └─ execute(script, state, ctx) -> Result<(State, GasUsed)>
//!
//!   ConfidentialTx (pt-coin)
//!     └─ outputs[].metadata  // contract state hash committed here
//! ```
//!
//! The contract's state hash is committed as a 32-byte metadata field on one of
//! the transaction outputs. Verifiers recompute the state transition from the
//! public script (on-chain) + the pre-state hash (previous output metadata) →
//! the post-state hash (current output metadata). If the VM execution returns
//! `true` on the top stack, the state transition is valid.

pub mod contracts;
pub mod vm;

use thiserror::Error;

/// Public key type — a 32-byte compressed Ristretto point (the owner's view key).
/// In a full deployment this is a discrete-log keypair over B_blinding.
pub type PublicKey = [u8; 32];

/// A 32-byte hash (SHA-256) used for state commitments and script hashes.
pub type Hash256 = [u8; 32];

/// The number of confirmations after which a contract output is considered final.
pub const FINALITY_DEPTH: u64 = 12;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("VM execution error: {0}")]
    Vm(String),

    #[error("out of gas: used={used}, limit={limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("stack underflow: needed {needed}, have {have}")]
    StackUnderflow { needed: usize, have: usize },

    #[error("script returned false (predicate failed)")]
    PredicateFalse,

    #[error("invalid opcode: 0x{0:02x} at position {1}")]
    InvalidOpcode(u8, usize),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("multi-sig threshold {threshold} exceeds key count {key_count}")]
    ThresholdExceedsKeys { threshold: usize, key_count: usize },

    #[error("time-lock not satisfied: required={required}, current={current}")]
    LocktimeNotSatisfied { required: u64, current: u64 },

    #[error("sequence not mature: required={required}, elapsed={elapsed}")]
    SequenceNotMature { required: u64, elapsed: u64 },

    #[error("state hash mismatch: expected {expected:02x?}, got {got:02x?}")]
    StateHashMismatch { expected: Box<Hash256>, got: Box<Hash256> },

    #[error("contract error: {0}")]
    Other(String),
}

// ── Contract Trait ──────────────────────────────────────────────────────────

/// A smart contract that can be compiled to VM bytecode, executed, and whose
/// state transitions are committed to the OMOTE·URA ledger.
pub trait Contract {
    /// Produce the VM script (bytecode) that encodes this contract's logic.
    fn compile(&self) -> vm::Script;

    /// The initial state of this contract before any execution.
    fn initial_state(&self) -> ContractState;

    /// A human-readable name for the contract type (e.g. "Transfer", "MultiSig").
    fn contract_type(&self) -> &'static str;

    /// The contract version (must be incremented on breaking changes).
    fn version(&self) -> u32 { 1 }
}

// ── Contract State ──────────────────────────────────────────────────────────

/// Serializable contract state committed to output metadata on the ledger.
/// The state hash is `sha256(owner ‖ state_hash ‖ data)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractState {
    /// The public key that owns this contract instance.
    pub owner: PublicKey,

    /// Hash of the previous state (or zeros for genesis).
    pub prior_state_hash: Hash256,

    /// Opaque contract-specific data (serialized by the contract implementor).
    pub data: Vec<u8>,
}

impl ContractState {
    /// Create a genesis state (prior_state_hash = zeros).
    pub fn genesis(owner: PublicKey, data: Vec<u8>) -> Self {
        Self { owner, prior_state_hash: [0u8; 32], data }
    }

    /// Compute the state hash: sha256(owner ‖ prior_state_hash ‖ data).
    pub fn hash(&self) -> Hash256 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&self.owner);
        h.update(&self.prior_state_hash);
        h.update(&self.data);
        let out = h.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&out);
        hash
    }

    /// Transition to a new state, chaining the prior hash.
    pub fn transition(&self, new_owner: PublicKey, new_data: Vec<u8>) -> Self {
        Self {
            owner: new_owner,
            prior_state_hash: self.hash(),
            data: new_data,
        }
    }
}

// ── Execution Context ───────────────────────────────────────────────────────

/// The environment available to a contract during VM execution.
/// Mirrors what a verifier can derive from the public ledger state.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Current block height.
    pub block_height: u64,

    /// Block timestamp (UNIX seconds).
    pub block_timestamp: u64,

    /// The public key invoking the contract (spender / signer).
    pub caller: PublicKey,

    /// The transaction fee (public, from ConfidentialTx.fee).
    pub tx_fee: u64,

    /// Kernel signature from the enclosing ConfidentialTx.
    /// The VM does NOT verify this — pt-coin::verify already did.
    /// It is available for OP_CHECK_SIG / OP_CHECK_MULTISIG.
    pub kernel_signature_valid: bool,

    /// Number of confirmations since the contract's UTXO was created.
    pub confirmations: u64,
}

impl ExecutionContext {
    /// Context for a contract UTXO that has just been created (0 confirmations).
    pub fn new(caller: PublicKey, block_height: u64, block_timestamp: u64, tx_fee: u64, kernel_ok: bool) -> Self {
        Self {
            block_height,
            block_timestamp,
            caller,
            tx_fee,
            kernel_signature_valid: kernel_ok,
            confirmations: 0,
        }
    }
}

// ── Gas Meter ───────────────────────────────────────────────────────────────

/// Tracks gas consumption during VM execution. Every opcode has a fixed cost.
#[derive(Debug, Clone)]
pub struct GasMeter {
    pub limit: u64,
    pub used: u64,
}

/// Standard gas costs per opcode family.
pub mod gas_costs {
    pub const CONSTANT: u64   = 1;   // OP_0..OP_16, OP_PUSHDATA
    pub const STACK: u64      = 2;   // OP_DUP, OP_SWAP, OP_DROP, etc.
    pub const ARITHMETIC: u64 = 4;   // OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD
    pub const COMPARISON: u64 = 3;   // OP_EQ, OP_LT, OP_GT, etc.
    pub const LOGIC: u64      = 3;   // OP_AND, OP_OR, OP_NOT
    pub const HASH: u64       = 20;  // OP_SHA256, OP_HASH256
    pub const SIG_CHECK: u64  = 100; // OP_CHECK_SIG (most expensive)
    pub const MULTISIG: u64   = 100; // OP_CHECK_MULTISIG (per key checked)
    pub const TIMELOCK: u64   = 2;   // OP_CHECK_LOCKTIME, OP_CHECK_SEQUENCE
    pub const STATE: u64      = 10;  // OP_STATE_LOAD, OP_STATE_STORE
    pub const CONTROL: u64    = 2;   // OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY

    /// Default gas limit for a single contract execution.
    pub const DEFAULT_LIMIT: u64 = 10_000;
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Consume `amount` gas. Returns `Err(OutOfGas)` if exceeded.
    pub fn consume(&mut self, amount: u64) -> Result<(), ContractError> {
        self.used = self.used.saturating_add(amount);
        if self.used > self.limit {
            Err(ContractError::OutOfGas { used: self.used, limit: self.limit })
        } else {
            Ok(())
        }
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}
