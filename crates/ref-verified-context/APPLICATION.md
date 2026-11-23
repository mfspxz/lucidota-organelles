# Applying `ref-verified-context` — the pt-compose wiring (TVC)

Harvested by copy from pt-compose, the treatment-lane composition
crate (`~/workspace/full-send/projects/pt-crypto-infra/app/pt-compose/src/lib.rs`,
128 lines, kept byte-identical as `src/compose.rs`; its proving
tests are copied to `tests/compose.rs` with only the crate-name
import updated). The project tree keeps its own code; this crate
is the composable organelle form. `src/lib.rs` adds only
re-exports and organelle glue.

## What it is

The wiring that composes the recovered pt crypto-infrastructure
trio (pt-keystore / pt-contracts / pt-forged) the way their own
designs intend, closing the two gaps each left for a caller that
never existed in the recovered tree:

1. **`sign_verdict` / `verify_signed_verdict`** — a pt-forged
   `GateVerdict`, canonically serialized, signed by a pt-keystore
   role key (Master/Personal/Void). Verification re-checks the
   Ed25519 signature over the exact enclosed bytes against the
   enclosed pubkey, and only then parses the verdict back out.
   Flipping `admitted` after signing → `SignatureInvalid`;
   substituting the pubkey is refused the same way. Provenance
   becomes cryptographic instead of documentary.
2. **`verified_context`** — a pt-contracts `ExecutionContext`
   whose `kernel_signature_valid` is *earned*: the kernel
   signature is verified against the keystore pubkey for the role
   over the kernel message. Right signature → the VM executes
   signature-gated scripts (proven end-to-end with a 2-of-3
   multisig); signature over a different message → flag `false`
   → the VM refuses.

## API

```toml
[dependencies]
ref-verified-context = {
  path = "<relative path>/organelles/crates/ref-verified-context",
  default-features = false, # pure wiring only
}
```

```rust
use ref_verified_context::{sign_verdict, verify_signed_verdict, verified_context};
use pt_keystore::KeyRole;

let signed = sign_verdict(&keystore, KeyRole::Master, &verdict)?;
let verdict = verify_signed_verdict(&signed)?; // tamper-evident
let ctx = verified_context(&keystore, KeyRole::Master, kernel_msg,
                           &kernel_sig, height, ts, confirmations)?;
```

Drop `default-features = false` to also get the Organelle trait
surface (codon `vc`, op `verify_signed_verdict` — the stateless
half of the wiring; signing and context-building need a live
keystore and stay on the pure API).

## Consumers and the dependency fact

- **Origin**: pt-compose in the pt-crypto-infra treatment tree —
  adoption there is a dependency swap.
- **Any consumer of pt-forged verdicts or pt-contracts execution**
  that currently asserts provenance or the kernel-signature flag
  itself.

The three composed crates **are organelles now** (harvest wave 2,
`ORGANELLE-HARVEST-2.md`): this crate consumes them as crate deps
on `ref-keystore` / `ref-contracts-vm` / `ref-evidence-gate`
(`default-features = false` — the pure APIs only), under
dependency renames that expose them to the code under the
original pt-* names (`pt-keystore`, `pt-contracts`, `pt-forged`),
so the harvested `compose.rs` compiles byte-identical. No path
into the campaign tree remains.

## wasm32 status

Native: builds clean, tests 2/2. wasm32-unknown-unknown check:
**PASS** (re-checked after the wave-2 rewiring).

History, kept because it explains the pass: at harvest wave 1
this check FAILED in two layers. (1) `getrandom` had no wasm
backend in the pt-* graph — fixed with the org-025 remedy
(target-gated `getrandom` 0.2 `js` + 0.4 `wasm_js` features in
this crate's Cargo.toml; `ref-keystore` now carries its own 0.2
remedy too). (2) The check then reached `clear_on_drop v0.2.5`'s
cc-rs build script, which requires `clang` — not installed on
this box. That C build step was never this wiring's: it entered
through pt-contracts' declared `pt-coin` path dependency
(curve25519-dalek-ng's graph), a dependency the pt-contracts
source never actually imports. Harvest wave 2's
`ref-contracts-vm` does not carry it, the subtree is gone, and
the check now runs to completion.

## Adoption steps

1. Add the path dependency above.
2. Sign every gate verdict at production time with a keystore
   role key; transport the `SignedVerdict`, not the bare verdict.
3. Verify before consuming: `verify_signed_verdict` first, act on
   the returned verdict only.
4. Build execution contexts only through `verified_context`, so
   `kernel_signature_valid` is always a verification result,
   never an assertion.
