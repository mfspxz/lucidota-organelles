//! Built-in contract implementations for the OMOTE·URA ledger.
//!
//! Each contract implements the [`Contract`] trait, producing a VM script
//! that can be executed by [`Vm::execute`]. Contracts are NOT on-chain code;
//! they are templates that compile to deterministic bytecode. The bytecode
//! hash identifies the contract type; the state hash commits its instance data.

pub mod multisig;
pub mod transfer;

pub use multisig::MultiSigWallet;
pub use transfer::TransferContract;
