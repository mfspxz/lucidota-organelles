//! Reference organelle: contracts-vm (codon `cv`).
//!
//! The OMOTE·URA predicate-contract VM, harvested BY COPY from
//! pt-contracts (`~/workspace/full-send/projects/pt-crypto-infra/
//! app/pt-contracts/src/`): `lib.rs` (258 lines, kept byte-identical
//! as `contracts_vm.rs`), `vm.rs` (912 lines) and
//! `contracts/{mod,multisig,transfer}.rs` kept byte-identical under
//! `contracts_vm/`. The project tree keeps its own code; this crate
//! is the composable organelle form. This file adds only
//! re-exports and organelle glue.
//!
//! A Bitcoin-Script-lineage stack VM: ~35 opcodes, no loops, fixed
//! gas per opcode, contract state transitions committed as hashes
//! chained to the prior state. Ships TransferContract (timelocked
//! escrow) and MultiSigWallet (scriptless threshold multisig — the
//! VM checks the threshold count and trusts
//! `ExecutionContext.kernel_signature_valid`, a flag the caller
//! must have earned; see `ref-verified-context`).
//!
//! Pure API: [`Contract`], [`ContractState`], [`ExecutionContext`],
//! [`GasMeter`], [`gas_costs`], and the [`contracts`] / [`vm`]
//! modules (`vm::Vm`, `vm::ScriptBuilder`, …).

mod contracts_vm;

pub use contracts_vm::*;

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
    use super::gas_costs;
    use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
    use organelle_manifest::{
        Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
        MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
    };
    use serde_json::Value;
    use std::sync::Arc;

    fn manifest() -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "contracts-vm".to_string(),
            codon: "cv".to_string(),
            version: "1.0.0".to_string(),
            description: "Bitcoin-Script-lineage predicate VM for OMOTE-URA contracts: transfer + multisig (pt-contracts harvest)".to_string(),
            contracts: vec![Contract {
                op: "gas_costs".to_string(),
                description: "the VM's fixed per-opcode-class gas costs".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": [],
                    "properties": {}
                }),
                mutation_class: None,
                required_capability: None,
            }],
            authority: Authority {
                mutation_class: MutationClass::ReadOnly,
                declared_valence: Valence::Proven,
                required_capability: None,
                granted_capabilities: vec![],
            },
            transports: Transport::all().to_vec(),
            receipt_policy: ReceiptPolicy {
                content_addressed: true,
                algorithm: RECEIPT_ALGORITHM.to_string(),
                chain: true,
            },
        }
    }

    pub struct ContractsVm {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(ContractsVm {
            manifest: manifest(),
        })
    }

    impl Organelle for ContractsVm {
        fn manifest(&self) -> OrganelleManifest {
            self.manifest.clone()
        }

        fn handle(
            &self,
            _ctx: &CallContext,
            _host: &dyn HostRef,
            op: &str,
            _input: Value,
        ) -> Result<Value, OrganelleError> {
            match op {
                // The stateless half: full script execution needs a
                // contract state + execution context and stays on
                // the pure API.
                "gas_costs" => Ok(serde_json::json!({
                    "constant": gas_costs::CONSTANT,
                    "stack": gas_costs::STACK,
                    "arithmetic": gas_costs::ARITHMETIC,
                    "comparison": gas_costs::COMPARISON,
                    "logic": gas_costs::LOGIC,
                    "hash": gas_costs::HASH,
                    "sig_check": gas_costs::SIG_CHECK,
                    "multisig": gas_costs::MULTISIG,
                    "timelock": gas_costs::TIMELOCK,
                    "state": gas_costs::STATE,
                    "control": gas_costs::CONTROL,
                    "default_limit": gas_costs::DEFAULT_LIMIT
                })),
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
