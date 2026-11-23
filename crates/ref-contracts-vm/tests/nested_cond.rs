//! Regression tests for the VM conditional-execution model.
//!
//! The bug these pin down (found by the treatment lane, 2026-11-23): the VM
//! tracked "are we executing?" as ONLY the innermost OP_IF frame's bool.
//! OP_ELSE flips that bool unconditionally — so an OP_ELSE inside a branch
//! that an OUTER OP_IF had already skipped would flip execution back ON,
//! and the payload in that dead branch would run (including OP_STATE_STORE,
//! i.e. a contract state transition inside a branch that should be dead).

use ref_contracts_vm::vm::{OpCode, ScriptBuilder, Vm};
use ref_contracts_vm::{ContractState, ExecutionContext, GasMeter};

fn ctx() -> ExecutionContext {
    ExecutionContext {
        block_height: 100,
        block_timestamp: 1_750_000_000,
        caller: [7u8; 32],
        tx_fee: 0,
        kernel_signature_valid: true,
        confirmations: 20,
    }
}

fn state() -> ContractState {
    ContractState::genesis([1u8; 32], vec![1, 2, 3])
}

#[test]
fn payload_in_doubly_skipped_branch_never_executes() {
    // OP_0 OP_IF            outer branch: DEAD
    //   OP_1 OP_IF          inner if (itself inside the dead branch)
    //   OP_ELSE             must NOT resurrect execution
    //     <payload: store state>
    //   OP_ENDIF OP_ENDIF
    // OP_1
    let mut sb = ScriptBuilder::new();
    sb.push_int(0).push_op(OpCode::If);
    sb.push_int(1).push_op(OpCode::If);
    sb.push_op(OpCode::Else);
    sb.push_data(&[0xAA]); // payload
    sb.push_op(OpCode::StateStore); // payload: commit a state transition
    sb.push_op(OpCode::EndIf);
    sb.push_op(OpCode::EndIf);
    sb.push_int(1);
    let script = sb.build();

    let mut gas = GasMeter::new(10_000);
    let result = Vm::execute(&script, &state(), &ctx(), &mut gas).unwrap();
    assert!(result.passed);
    assert!(
        result.new_state.is_none(),
        "OP_STATE_STORE inside a doubly-skipped branch executed — dead-branch payload ran"
    );
    assert!(
        result.stack.iter().all(|v| v.as_int() != Some(0xAA)),
        "payload value leaked onto the stack from a dead branch"
    );
}

#[test]
fn else_inside_live_outer_branch_still_executes() {
    // OP_1 OP_IF            outer branch: LIVE
    //   OP_0 OP_IF          inner condition false
    //     OP_2              dead
    //   OP_ELSE
    //     OP_3              must execute
    //   OP_ENDIF OP_ENDIF
    let mut sb = ScriptBuilder::new();
    sb.push_int(1).push_op(OpCode::If);
    sb.push_int(0).push_op(OpCode::If);
    sb.push_int(2);
    sb.push_op(OpCode::Else);
    sb.push_int(3);
    sb.push_op(OpCode::EndIf);
    sb.push_op(OpCode::EndIf);
    let script = sb.build();

    let mut gas = GasMeter::new(10_000);
    let result = Vm::execute(&script, &state(), &ctx(), &mut gas).unwrap();
    assert_eq!(
        result.stack.last().and_then(|v| v.as_int()),
        Some(3),
        "else branch inside a live outer branch must execute"
    );
}
