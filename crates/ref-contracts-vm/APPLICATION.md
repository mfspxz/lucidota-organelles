# Applying `ref-contracts-vm` — the OMOTE·URA predicate VM (TCV)

Harvested by copy from pt-contracts, the pt-crypto-infra treatment
crate (`~/workspace/full-send/projects/pt-crypto-infra/app/pt-contracts/`).
Harvested files, each byte-identical (sha256 verified both sides):

- `src/lib.rs` (258 lines) → `src/contracts_vm.rs`
  (`0a6f997cd4b84555…`)
- `src/vm.rs` (912 lines) → `src/contracts_vm/vm.rs`
  (`58006e1d837b9555…`)
- `src/contracts/mod.rs` → `src/contracts_vm/contracts/mod.rs`
  (`b4f3e78bec465e2a…`)
- `src/contracts/multisig.rs` (312 lines) →
  `src/contracts_vm/contracts/multisig.rs` (`1952648080831ec3…`)
- `src/contracts/transfer.rs` (231 lines) →
  `src/contracts_vm/contracts/transfer.rs` (`4432609cdb0921da…`)

The proving tests (`tests/e2e.rs`, `tests/nested_cond.rs`) are
copied with only the crate-name import updated (`pt_contracts` →
`ref_contracts_vm`). The project tree keeps its own code; this
crate is the composable organelle form. `src/lib.rs` adds only
re-exports and organelle glue. The relocation is a module-path
move only — no line differs; the harvested files' internal
`crate::…` paths resolve through this crate's root re-exports.

**Recorded manifest adaptation:** the source Cargo.toml declares
a `pt-coin` path dependency, but the harvested source never
imports `pt_coin` — the name appears only in doc comments (the VM
deliberately trusts a pre-verified kernel-signature flag instead
of verifying kernel signatures itself). The dependency is not
carried into this crate. Consequence, stated plainly: this
crate's dependency graph is sha2 + thiserror only, which is also
why its wasm32 check passes where the source tree's graph (with
pt-coin's dalek/bulletproofs chain) would not.

## What it is

A smart-contract VM for the OMOTE·URA confidential-transaction
ledger, built like Bitcoin Script on purpose: a stack machine,
~35 opcodes, no loops, no backward jumps, every opcode at a fixed
gas price (`gas_costs`), so any script's cost and behaviour are
bounded before it runs. Contracts compile to this bytecode;
running a script against a contract state yields a verdict and,
if it passes, a new state whose hash chains to the old one — the
hash committed onto a transaction output.

Two contracts ship in the box (`contracts` module):

- **TransferContract** — ownership transfer with optional absolute
  lock (not before block N) and relative maturity (not before K
  confirmations). Treatment-run as escrow: refused at height 150
  against a lock of 200 (`time-lock not satisfied: required=200,
  current=150`); executed at 200 (38 gas, state chained to
  genesis).
- **MultiSigWallet** — M-of-N wallet, scriptless in the
  Mimblewimble sense: the enclosing transaction's kernel signature
  proves M signers contributed, so `OP_CHECK_MULTISIG` checks the
  threshold count and trusts `ExecutionContext`'s
  `kernel_signature_valid` flag — **a flag the caller must have
  earned** by verifying the kernel signature first (that caller is
  `ref-verified-context`). Treatment fix inherited: daily-limited
  wallets fail closed at compile time (the VM has no state-field
  opcodes to enforce a limit honestly), and the nested-branch
  defect — an `OP_ELSE` inside a dead outer branch resurrecting
  execution, up to `OP_STATE_STORE` — is fixed with cumulative
  exec frames; `tests/nested_cond.rs` is its regression proof.

## API

```toml
[dependencies]
ref-contracts-vm = {
  path = "<relative path>/organelles/crates/ref-contracts-vm",
  default-features = false, # pure VM only
}
```

```rust
use ref_contracts_vm::contracts::MultiSigWallet;
use ref_contracts_vm::vm::Vm;
use ref_contracts_vm::{Contract, ContractState, ExecutionContext, GasMeter};

let wallet = MultiSigWallet::new(owners, 2, None);
let script = wallet.compile()?;
let genesis = wallet.initial_state();
let ctx = ExecutionContext::new(caller, height, ts, fee, kernel_signature_valid);
let (state, gas) = Vm::execute(&script, &genesis, &ctx, &mut GasMeter::new(10_000))?;
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `cv`, op `gas_costs` — the stateless half; script
execution needs a state + context and stays on the pure API).

## Consumers

- **Origin**: pt-contracts in the pt-crypto-infra treatment tree —
  adoption there is a dependency swap.
- **ref-verified-context**: builds `ExecutionContext`s whose
  `kernel_signature_valid` is a real verification result (it
  consumes this organelle under the dependency rename
  `pt-contracts`, see its APPLICATION.md).
- **Any OMOTE·URA tooling** that needs to evaluate transfer /
  multisig predicates off-chain before committing state hashes.

## wasm32 status

Native: builds clean, tests 26/26 (22 unit + 2 e2e + 2
nested-cond). wasm32-unknown-unknown check: **PASS** (sha2 +
thiserror graph; see the manifest-adaptation note above — the
pass is a property of the harvested source's actual imports, not
of a workaround).

## Adoption steps

1. Add the path dependency above.
2. Compile contracts to scripts once; execute against explicit
   `ContractState` + `ExecutionContext` values.
3. Never set `kernel_signature_valid` by assertion — build
   contexts through `ref-verified-context::verified_context`.
4. Treat a daily-limited multisig as unbuildable until the VM
   grows state-field opcodes; it fails closed by design.
