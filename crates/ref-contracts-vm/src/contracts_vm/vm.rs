//! Declarative stack-based VM for contract predicate execution.
//!
//! ## Opcode Set
//!
//! The VM has ~30 opcodes organized into families. Every opcode has a fixed gas
//! cost (no dynamic pricing — eliminates DoS vectors). Execution is bounded: no
//! backward jumps, no loops, no recursion. A script is a linear sequence; the
//! interpreter makes a single forward pass.
//!
//! ### Constants (gas: gas_costs::CONSTANT)
//!   `OP_0`..`OP_16` (0x50..0x60) — push 0..16 onto the stack
//!   `OP_PUSHDATA` (0x01) — push N bytes (next byte = length)
//!
//! ### Stack manipulation (gas: gas_costs::STACK)
//!   `OP_DUP` (0x70), `OP_SWAP` (0x71), `OP_DROP` (0x72),
//!   `OP_ROT` (0x73), `OP_PICK` (0x74), `OP_ROLL` (0x75)
//!
//! ### Arithmetic (gas: gas_costs::ARITHMETIC)
//!   `OP_ADD` (0x80), `OP_SUB` (0x81), `OP_MUL` (0x82),
//!   `OP_DIV` (0x83), `OP_MOD` (0x84)
//!
//! ### Comparison (gas: gas_costs::COMPARISON)
//!   `OP_EQ` (0x90), `OP_NEQ` (0x91), `OP_LT` (0x92),
//!   `OP_GT` (0x93), `OP_LTE` (0x94), `OP_GTE` (0x95)
//!
//! ### Logic (gas: gas_costs::LOGIC)
//!   `OP_AND` (0xa0), `OP_OR` (0xa1), `OP_NOT` (0xa2),
//!   `OP_BOOLAND` (0xa3), `OP_BOOLOR` (0xa4)
//!
//! ### Hashing (gas: gas_costs::HASH)
//!   `OP_SHA256` (0xb0), `OP_HASH256` (0xb1)
//!
//! ### Signature checks (gas: gas_costs::SIG_CHECK / MULTISIG)
//!   `OP_CHECK_SIG` (0xc0), `OP_CHECK_MULTISIG` (0xc1)
//!
//! ### Time-locks (gas: gas_costs::TIMELOCK)
//!   `OP_CHECK_LOCKTIME` (0xd0), `OP_CHECK_SEQUENCE` (0xd1)
//!
//! ### State (gas: gas_costs::STATE)
//!   `OP_STATE_LOAD` (0xe0), `OP_STATE_STORE` (0xe1), `OP_STATE_HASH` (0xe2)
//!
//! ### Control flow (gas: gas_costs::CONTROL)
//!   `OP_IF` (0xf0), `OP_ELSE` (0xf1), `OP_ENDIF` (0xf2),
//!   `OP_VERIFY` (0xf3), `OP_RETURN` (0xf4)

use crate::{
    gas_costs, ContractError, ContractState, ExecutionContext, GasMeter,
};

// ── OpCodes ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    // Constants
    PushData = 0x01,
    Op0 = 0x50,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // Stack
    Dup = 0x70,
    Swap = 0x71,
    Drop = 0x72,
    Rot = 0x73,
    Pick = 0x74,
    Roll = 0x75,

    // Arithmetic
    Add = 0x80,
    Sub = 0x81,
    Mul = 0x82,
    Div = 0x83,
    Mod = 0x84,

    // Comparison
    Eq = 0x90,
    Neq = 0x91,
    Lt = 0x92,
    Gt = 0x93,
    Lte = 0x94,
    Gte = 0x95,

    // Logic
    And = 0xa0,
    Or = 0xa1,
    Not = 0xa2,
    BoolAnd = 0xa3,
    BoolOr = 0xa4,

    // Hashing
    Sha256 = 0xb0,
    Hash256 = 0xb1,

    // Signatures
    CheckSig = 0xc0,
    CheckMultiSig = 0xc1,

    // Time-locks
    CheckLocktime = 0xd0,
    CheckSequence = 0xd1,

    // State
    StateLoad = 0xe0,
    StateStore = 0xe1,
    StateHash = 0xe2,

    // Control
    If = 0xf0,
    Else = 0xf1,
    EndIf = 0xf2,
    Verify = 0xf3,
    Return = 0xf4,
}

impl TryFrom<u8> for OpCode {
    type Error = ();

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::PushData),
            0x50..=0x60 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0x70..=0x75 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0x80..=0x84 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0x90..=0x95 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xa0..=0xa4 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xb0..=0xb1 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xc0..=0xc1 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xd0..=0xd1 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xe0..=0xe2 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            0xf0..=0xf4 => Ok(unsafe { std::mem::transmute::<u8, OpCode>(byte) }),
            _ => Err(()),
        }
    }
}

// ── Stack Value ─────────────────────────────────────────────────────────────

/// A single stack element. Numbers are i64; blobs are arbitrary byte vectors.
/// All arithmetic and comparison operates on i64; hashing operates on blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackValue {
    Int(i64),
    Blob(Vec<u8>),
}

impl StackValue {
    pub fn as_int(&self) -> Option<i64> {
        match self { Self::Int(n) => Some(*n), _ => None }
    }

    pub fn as_blob(&self) -> Option<&[u8]> {
        match self { Self::Blob(b) => Some(b), _ => None }
    }

    /// Coerce to i64: direct Int, or parse 1–8 byte LE blob as i64.
    pub fn coerce_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Blob(b) if !b.is_empty() && b.len() <= 8 => {
                let mut buf = [0u8; 8];
                buf[..b.len()].copy_from_slice(b);
                Some(i64::from_le_bytes(buf))
            }
            _ => None,
        }
    }

    /// Interpret as boolean: empty blob / zero int → false; non-empty / non-zero → true.
    pub fn as_bool(&self) -> bool {
        match self {
            Self::Int(0) => false,
            Self::Int(_) => true,
            Self::Blob(b) => !b.is_empty(),
        }
    }
}

impl From<i64> for StackValue {
    fn from(n: i64) -> Self { Self::Int(n) }
}

impl From<Vec<u8>> for StackValue {
    fn from(b: Vec<u8>) -> Self { Self::Blob(b) }
}

// ── Script ──────────────────────────────────────────────────────────────────

/// A compiled contract script: a linear sequence of opcodes with inline data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ── Script Builder (compile-time helper) ────────────────────────────────────

/// Convenience builder for constructing scripts programmatically.
#[derive(Debug, Clone)]
pub struct ScriptBuilder {
    bytes: Vec<u8>,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn push_op(&mut self, op: OpCode) -> &mut Self {
        self.bytes.push(op as u8);
        self
    }

    /// Push raw data: OP_PUSHDATA <len> <bytes...>
    pub fn push_data(&mut self, data: &[u8]) -> &mut Self {
        assert!(data.len() <= 255, "push data exceeds 255 bytes");
        self.bytes.push(OpCode::PushData as u8);
        self.bytes.push(data.len() as u8);
        self.bytes.extend_from_slice(data);
        self
    }

    /// Push a small integer (0–16) as an OP_N opcode.
    pub fn push_int(&mut self, n: i64) -> &mut Self {
        match n {
            0 => self.bytes.push(OpCode::Op0 as u8),
            1 => self.bytes.push(OpCode::Op1 as u8),
            2 => self.bytes.push(OpCode::Op2 as u8),
            3 => self.bytes.push(OpCode::Op3 as u8),
            4 => self.bytes.push(OpCode::Op4 as u8),
            5 => self.bytes.push(OpCode::Op5 as u8),
            6 => self.bytes.push(OpCode::Op6 as u8),
            7 => self.bytes.push(OpCode::Op7 as u8),
            8 => self.bytes.push(OpCode::Op8 as u8),
            9 => self.bytes.push(OpCode::Op9 as u8),
            10 => self.bytes.push(OpCode::Op10 as u8),
            11 => self.bytes.push(OpCode::Op11 as u8),
            12 => self.bytes.push(OpCode::Op12 as u8),
            13 => self.bytes.push(OpCode::Op13 as u8),
            14 => self.bytes.push(OpCode::Op14 as u8),
            15 => self.bytes.push(OpCode::Op15 as u8),
            16 => self.bytes.push(OpCode::Op16 as u8),
            _ => {
                // Push the raw bytes as data
                self.push_data(&n.to_le_bytes());
            }
        }
        self
    }

    pub fn build(self) -> Script {
        Script { bytes: self.bytes }
    }
}

// ── VM ──────────────────────────────────────────────────────────────────────

/// The stack-based VM interpreter. Executes a script against a contract state
/// and execution context, consuming gas per opcode.
pub struct Vm;

/// Result of VM execution: the post-execution state (if state was stored) and
/// the final stack top (true/false predicate result).
#[derive(Debug, Clone)]
pub struct VmResult {
    /// Whether the script predicate passed (top stack is truthy).
    pub passed: bool,

    /// New contract state (if OP_STATE_STORE was called).
    pub new_state: Option<ContractState>,

    /// Gas consumed.
    pub gas_used: u64,

    /// Final stack (debugging / verification).
    pub stack: Vec<StackValue>,
}

impl Vm {
    /// Execute a script against a contract state in a given context.
    pub fn execute(
        script: &Script,
        state: &ContractState,
        ctx: &ExecutionContext,
        gas: &mut GasMeter,
    ) -> Result<VmResult, ContractError> {
        let bytes = &script.bytes;
        let mut stack: Vec<StackValue> = Vec::with_capacity(32);
        let mut new_state: Option<ContractState> = None;
        let mut ip: usize = 0; // instruction pointer

        // Conditional execution frames. `exec_frame[i]` is the CUMULATIVE
        // executing state at nesting level i (already ANDed with every
        // ancestor frame), and `taken_frame[i]` records whether any branch
        // of that OP_IF has executed — which is what OP_ELSE needs: an else
        // branch runs only if the parent context is executing AND no
        // earlier branch of the same OP_IF ran.
        //
        // The pre-fix VM kept one bare bool per level and OP_ELSE flipped it
        // unconditionally, so an OP_ELSE nested inside an outer-skipped
        // branch flipped execution back ON and the dead branch's payload —
        // including OP_STATE_STORE state transitions — executed. Regression
        // tests: tests/nested_cond.rs.
        let mut exec_frame: Vec<bool> = Vec::new();
        let mut taken_frame: Vec<bool> = Vec::new();

        while ip < bytes.len() {
            let byte = bytes[ip];
            let op = OpCode::try_from(byte)
                .map_err(|_| ContractError::InvalidOpcode(byte, ip))?;

            // Check if we're in a skipped branch (any ancestor OP_IF false).
            let executing = exec_frame.last().copied().unwrap_or(true);

            // Even when skipping, we still consume gas and advance IP, but
            // we don't execute stack operations.
            match op {
                // Constants
                OpCode::Op0 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(0)); } ip += 1; }
                OpCode::Op1 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(1)); } ip += 1; }
                OpCode::Op2 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(2)); } ip += 1; }
                OpCode::Op3 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(3)); } ip += 1; }
                OpCode::Op4 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(4)); } ip += 1; }
                OpCode::Op5 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(5)); } ip += 1; }
                OpCode::Op6 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(6)); } ip += 1; }
                OpCode::Op7 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(7)); } ip += 1; }
                OpCode::Op8 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(8)); } ip += 1; }
                OpCode::Op9 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(9)); } ip += 1; }
                OpCode::Op10 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(10)); } ip += 1; }
                OpCode::Op11 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(11)); } ip += 1; }
                OpCode::Op12 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(12)); } ip += 1; }
                OpCode::Op13 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(13)); } ip += 1; }
                OpCode::Op14 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(14)); } ip += 1; }
                OpCode::Op15 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(15)); } ip += 1; }
                OpCode::Op16 => { gas.consume(gas_costs::CONSTANT)?; if executing { stack.push(StackValue::Int(16)); } ip += 1; }

                OpCode::PushData => {
                    gas.consume(gas_costs::CONSTANT)?;
                    if ip + 1 >= bytes.len() {
                        return Err(ContractError::Vm("OP_PUSHDATA truncated".into()));
                    }
                    let len = bytes[ip + 1] as usize;
                    if ip + 2 + len > bytes.len() {
                        return Err(ContractError::Vm("OP_PUSHDATA data truncated".into()));
                    }
                    if executing {
                        let data = bytes[ip + 2..ip + 2 + len].to_vec();
                        stack.push(StackValue::Blob(data));
                    }
                    ip += 2 + len;
                }

                // Stack manipulation
                OpCode::Dup => {
                    gas.consume(gas_costs::STACK)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let top = stack.last().unwrap().clone();
                        stack.push(top);
                    }
                    ip += 1;
                }
                OpCode::Swap => {
                    gas.consume(gas_costs::STACK)?;
                    if executing {
                        if stack.len() < 2 { return Err(ContractError::StackUnderflow { needed: 2, have: stack.len() }); }
                        let len = stack.len();
                        stack.swap(len - 1, len - 2);
                    }
                    ip += 1;
                }
                OpCode::Drop => {
                    gas.consume(gas_costs::STACK)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        stack.pop();
                    }
                    ip += 1;
                }
                OpCode::Rot => {
                    gas.consume(gas_costs::STACK)?;
                    if executing {
                        if stack.len() < 3 { return Err(ContractError::StackUnderflow { needed: 3, have: stack.len() }); }
                        let len = stack.len();
                        let a = stack.remove(len - 3);
                        stack.push(a);
                    }
                    ip += 1;
                }
                OpCode::Pick | OpCode::Roll => {
                    gas.consume(gas_costs::STACK)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let n = stack.pop().unwrap();
                        let idx = n.as_int().ok_or_else(|| ContractError::Vm("PICK/ROLL: expected int".into()))?;
                        if idx < 0 || idx as usize >= stack.len() {
                            return Err(ContractError::Vm(format!("PICK/ROLL: index {idx} out of bounds")));
                        }
                        if op == OpCode::Pick {
                            let val = stack[stack.len() - 1 - idx as usize].clone();
                            stack.push(val);
                        } else {
                            let val = stack.remove(stack.len() - 1 - idx as usize);
                            stack.push(val);
                        }
                    }
                    ip += 1;
                }

                // Arithmetic
                OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Mod => {
                    gas.consume(gas_costs::ARITHMETIC)?;
                    if executing {
                        if stack.len() < 2 { return Err(ContractError::StackUnderflow { needed: 2, have: stack.len() }); }
                        let b = stack.pop().unwrap().coerce_int().ok_or_else(|| ContractError::Vm("arithmetic: expected int".into()))?;
                        let a = stack.pop().unwrap().coerce_int().ok_or_else(|| ContractError::Vm("arithmetic: expected int".into()))?;
                        let result = match op {
                            OpCode::Add => a.checked_add(b),
                            OpCode::Sub => a.checked_sub(b),
                            OpCode::Mul => a.checked_mul(b),
                            OpCode::Div => if b == 0 { None } else { Some(a / b) },
                            OpCode::Mod => if b == 0 { None } else { Some(a % b) },
                            _ => unreachable!(),
                        };
                        match result {
                            Some(v) => stack.push(StackValue::Int(v)),
                            None => return Err(ContractError::Vm("arithmetic overflow/divide by zero".into())),
                        }
                    }
                    ip += 1;
                }

                // Comparison: EQ/NEQ handle both int and blob; LT/GT/LTE/GTE coerce to int.
                OpCode::Eq | OpCode::Neq | OpCode::Lt | OpCode::Gt | OpCode::Lte | OpCode::Gte => {
                    gas.consume(gas_costs::COMPARISON)?;
                    if executing {
                        if stack.len() < 2 { return Err(ContractError::StackUnderflow { needed: 2, have: stack.len() }); }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();

                        let result = match (&a, &b) {
                            // Blob comparison for EQ/NEQ
                            (StackValue::Blob(ba), StackValue::Blob(bb)) if op == OpCode::Eq || op == OpCode::Neq => {
                                let eq = ba == bb;
                                if op == OpCode::Eq { eq } else { !eq }
                            }
                            // Integer comparison (coerce blobs to int)
                            _ => {
                                let ai = a.coerce_int().ok_or_else(|| ContractError::Vm("comparison: expected int".into()))?;
                                let bi = b.coerce_int().ok_or_else(|| ContractError::Vm("comparison: expected int".into()))?;
                                match op {
                                    OpCode::Eq  => ai == bi,
                                    OpCode::Neq => ai != bi,
                                    OpCode::Lt  => ai < bi,
                                    OpCode::Gt  => ai > bi,
                                    OpCode::Lte => ai <= bi,
                                    OpCode::Gte => ai >= bi,
                                    _ => unreachable!(),
                                }
                            }
                        };
                        stack.push(StackValue::Int(if result { 1 } else { 0 }));
                    }
                    ip += 1;
                }

                // Logic
                OpCode::And | OpCode::Or | OpCode::Not | OpCode::BoolAnd | OpCode::BoolOr => {
                    gas.consume(gas_costs::LOGIC)?;
                    if executing {
                        if op == OpCode::Not {
                            if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                            let a = stack.pop().unwrap();
                            stack.push(StackValue::Int(if a.as_bool() { 0 } else { 1 }));
                        } else {
                            if stack.len() < 2 { return Err(ContractError::StackUnderflow { needed: 2, have: stack.len() }); }
                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            let result = match op {
                                OpCode::And     => a.as_int().unwrap_or(0) & b.as_int().unwrap_or(0),
                                OpCode::Or      => a.as_int().unwrap_or(0) | b.as_int().unwrap_or(0),
                                OpCode::BoolAnd => if a.as_bool() && b.as_bool() { 1 } else { 0 },
                                OpCode::BoolOr  => if a.as_bool() || b.as_bool() { 1 } else { 0 },
                                _ => unreachable!(),
                            };
                            stack.push(StackValue::Int(result));
                        }
                    }
                    ip += 1;
                }

                // Hashing
                OpCode::Sha256 | OpCode::Hash256 => {
                    gas.consume(gas_costs::HASH)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let data = stack.pop().unwrap();
                        let blob = data.as_blob().ok_or_else(|| ContractError::Vm("hash: expected blob".into()))?;
                        let result = if op == OpCode::Sha256 {
                            sha256_once(blob)
                        } else {
                            sha256d(blob)
                        };
                        stack.push(StackValue::Blob(result.to_vec()));
                    }
                    ip += 1;
                }

                // Signature checks — delegate to pt-coin kernel verification
                OpCode::CheckSig => {
                    gas.consume(gas_costs::SIG_CHECK)?;
                    if executing {
                        // OP_CHECK_SIG: pops pubkey, signature_evidence.
                        // For the OMOTE·URA model, this is satisfied if the enclosing
                        // tx's kernel signature is valid (pre-verified by pt-coin::verify).
                        // The VM pops any unused args and pushes the kernel result.
                        if stack.len() < 2 { return Err(ContractError::StackUnderflow { needed: 2, have: stack.len() }); }
                        stack.pop(); // pubkey
                        stack.pop(); // sig evidence
                        stack.push(StackValue::Int(if ctx.kernel_signature_valid { 1 } else { 0 }));
                    }
                    ip += 1;
                }
                OpCode::CheckMultiSig => {
                    gas.consume(gas_costs::MULTISIG)?;
                    if executing {
                        // Script format: <sig1> <sig2> ... <sigM> <M> <pubkey1> ... <pubkeyN> <N> OP_CHECK_MULTISIG
                        // We pop N (top), then N pubkeys, then M, then M sigs.
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let n_val = stack.pop().unwrap().as_int().ok_or_else(|| ContractError::Vm("OP_CHECK_MULTISIG: expected N".into()))?;
                        let n = n_val as usize;
                        if n == 0 { return Err(ContractError::Vm("OP_CHECK_MULTISIG: N must be >= 1".into())); }
                        if stack.len() < n { return Err(ContractError::StackUnderflow { needed: n, have: stack.len() }); }
                        for _ in 0..n { stack.pop(); } // pubkeys

                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let m_val = stack.pop().unwrap().as_int().ok_or_else(|| ContractError::Vm("OP_CHECK_MULTISIG: expected M".into()))?;
                        let m = m_val as usize;
                        if m > n {
                            return Err(ContractError::ThresholdExceedsKeys { threshold: m, key_count: n });
                        }
                        if stack.len() < m { return Err(ContractError::StackUnderflow { needed: m, have: stack.len() }); }
                        for _ in 0..m { stack.pop(); } // sigs (binary blobs)

                        // The actual threshold check: the kernel signature already proves
                        // knowledge of excess = (sum in blindings - sum out blindings).
                        // For multi-sig, the excess is a linear combination of partial
                        // excesses, and the aggregate kernel sig proves threshold knowledge.
                        // If the kernel sig is valid, the threshold is satisfied.
                        gas.consume(gas_costs::SIG_CHECK * m as u64)?;
                        stack.push(StackValue::Int(if ctx.kernel_signature_valid { 1 } else { 0 }));
                    }
                    ip += 1;
                }

                // Time-locks
                OpCode::CheckLocktime => {
                    gas.consume(gas_costs::TIMELOCK)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let locktime = stack.pop().unwrap().coerce_int().ok_or_else(|| ContractError::Vm("OP_CHECK_LOCKTIME: expected int".into()))?;
                        if locktime < 0 {
                            return Err(ContractError::Vm("OP_CHECK_LOCKTIME: negative locktime".into()));
                        }
                        let lt = locktime as u64;
                        // If locktime < 500_000_000, it's a block height; else UNIX timestamp.
                        let current = if lt < 500_000_000 { ctx.block_height } else { ctx.block_timestamp };
                        if current < lt {
                            return Err(ContractError::LocktimeNotSatisfied { required: lt, current });
                        }
                        // Push the locktime back (for chaining) — Bitcoin does this.
                        stack.push(StackValue::Int(locktime));
                    }
                    ip += 1;
                }
                OpCode::CheckSequence => {
                    gas.consume(gas_costs::TIMELOCK)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let seq = stack.pop().unwrap().coerce_int().ok_or_else(|| ContractError::Vm("OP_CHECK_SEQUENCE: expected int".into()))?;
                        if seq < 0 {
                            return Err(ContractError::Vm("OP_CHECK_SEQUENCE: negative sequence".into()));
                        }
                        let required = seq as u64;
                        if ctx.confirmations < required {
                            return Err(ContractError::SequenceNotMature { required, elapsed: ctx.confirmations });
                        }
                        stack.push(StackValue::Int(seq));
                    }
                    ip += 1;
                }

                // State
                OpCode::StateLoad => {
                    gas.consume(gas_costs::STATE)?;
                    if executing {
                        // Push the current state (as serialized data blob).
                        stack.push(StackValue::Blob(state.data.clone()));
                    }
                    ip += 1;
                }
                OpCode::StateStore => {
                    gas.consume(gas_costs::STATE)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let new_data = stack.pop().unwrap();
                        let blob = new_data.as_blob().ok_or_else(|| ContractError::Vm("OP_STATE_STORE: expected blob".into()))?;
                        new_state = Some(ContractState {
                            owner: state.owner,
                            prior_state_hash: state.hash(),
                            data: blob.to_vec(),
                        });
                    }
                    ip += 1;
                }
                OpCode::StateHash => {
                    gas.consume(gas_costs::STATE)?;
                    if executing {
                        // Push the current state's hash onto the stack.
                        let h = state.hash();
                        stack.push(StackValue::Blob(h.to_vec()));
                    }
                    ip += 1;
                }

                // Control flow
                OpCode::If => {
                    gas.consume(gas_costs::CONTROL)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let cond = stack.pop().unwrap().as_bool();
                        exec_frame.push(cond);
                        taken_frame.push(cond);
                    } else {
                        // Nested inside a skipped branch: this frame can
                        // never execute, and its OP_ELSE must not resurrect
                        // it — mark the branch as already taken.
                        exec_frame.push(false);
                        taken_frame.push(true);
                    }
                    ip += 1;
                }
                OpCode::Else => {
                    gas.consume(gas_costs::CONTROL)?;
                    if !exec_frame.is_empty() {
                        let n = exec_frame.len();
                        let parent = if n >= 2 { exec_frame[n - 2] } else { true };
                        let now = parent && !taken_frame[n - 1];
                        exec_frame[n - 1] = now;
                        if now {
                            taken_frame[n - 1] = true;
                        }
                    }
                    ip += 1;
                }
                OpCode::EndIf => {
                    gas.consume(gas_costs::CONTROL)?;
                    exec_frame.pop();
                    taken_frame.pop();
                    ip += 1;
                }
                OpCode::Verify => {
                    gas.consume(gas_costs::CONTROL)?;
                    if executing {
                        if stack.is_empty() { return Err(ContractError::StackUnderflow { needed: 1, have: 0 }); }
                        let top = stack.pop().unwrap();
                        if !top.as_bool() {
                            return Err(ContractError::PredicateFalse);
                        }
                    }
                    ip += 1;
                }
                OpCode::Return => {
                    gas.consume(gas_costs::CONTROL)?;
                    // OP_RETURN marks the script as provably unspendable (data carrier).
                    // In our VM, it terminates with false.
                    return Err(ContractError::PredicateFalse);
                }
            }
        }

        // Script result: top stack value determines pass/fail.
        let passed = stack.last().map(|v| v.as_bool()).unwrap_or(false);

        Ok(VmResult {
            passed,
            new_state,
            gas_used: gas.used,
            stack,
        })
    }
}

// ── Hash helpers ────────────────────────────────────────────────────────────

fn sha256_once(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256_once(&sha256_once(data))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionContext, GasMeter, gas_costs};

    fn test_ctx() -> ExecutionContext {
        ExecutionContext {
            block_height: 100,
            block_timestamp: 1_750_000_000,
            caller: [0u8; 32],
            tx_fee: 0,
            kernel_signature_valid: true,
            confirmations: 20,
        }
    }

    fn test_state() -> ContractState {
        ContractState::genesis([1u8; 32], vec![42, 99])
    }

    #[test]
    fn push_and_eq() {
        let mut sb = ScriptBuilder::new();
        sb.push_int(5).push_int(5).push_op(OpCode::Eq);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed, "5 == 5 must pass");
        assert_eq!(result.stack.len(), 1);
        assert_eq!(result.stack[0].as_int().unwrap(), 1);
    }

    #[test]
    fn neq_fails_predicate() {
        let mut sb = ScriptBuilder::new();
        sb.push_int(5).push_int(6).push_op(OpCode::Eq).push_op(OpCode::Verify);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas);
        assert!(matches!(result, Err(ContractError::PredicateFalse)));
    }

    #[test]
    fn arithmetic_chain() {
        // (10 + 5) * 3 = 45, 45 > 40 → pass
        let mut sb = ScriptBuilder::new();
        sb.push_int(10).push_int(5).push_op(OpCode::Add)
          .push_int(3).push_op(OpCode::Mul)
          .push_int(40).push_op(OpCode::Gt);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn state_load_and_hash() {
        let mut sb = ScriptBuilder::new();
        sb.push_op(OpCode::StateLoad)   // push state data
          .push_op(OpCode::StateHash)    // push state hash
          .push_op(OpCode::Drop)         // discard state data
          .push_op(OpCode::Drop)         // discard hash
          .push_int(1);                  // push 1 (true)
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn state_store_transition() {
        // Load state, store new state (append byte), verify.
        let mut sb = ScriptBuilder::new();
        sb.push_op(OpCode::StateLoad);          // [data]
        sb.push_data(&[0x77]);                  // [data, 0x77]
        sb.push_op(OpCode::Swap);               // [0x77, data]
        // concat: data || 0x77
        // For simplicity, just store [0x77] as new state
        sb.push_op(OpCode::Drop);               // [0x77]
        sb.push_op(OpCode::StateStore);         // store [0x77]
        sb.push_int(1);                          // push true
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed);
        assert!(result.new_state.is_some());
        let ns = result.new_state.unwrap();
        assert_eq!(ns.data, vec![0x77]);
        assert_ne!(ns.prior_state_hash, [0u8; 32], "prior state hash must chain");
    }

    #[test]
    fn check_locktime_passes_when_mature() {
        let mut sb = ScriptBuilder::new();
        sb.push_int(50)  // block height 50 — current is 100
          .push_op(OpCode::CheckLocktime)
          .push_op(OpCode::Drop)
          .push_int(1);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn check_locktime_fails_when_immature() {
        let mut sb = ScriptBuilder::new();
        sb.push_int(200) // block height 200 — current is 100
          .push_op(OpCode::CheckLocktime);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas);
        assert!(matches!(result, Err(ContractError::LocktimeNotSatisfied { required: 200, current: 100 })));
    }

    #[test]
    fn if_else_branching() {
        // if true: push 1; else: push 0; endif → top should be 1
        let mut sb = ScriptBuilder::new();
        sb.push_int(1)          // true
          .push_op(OpCode::If)
          .push_int(1)          // if branch
          .push_op(OpCode::Else)
          .push_int(0)          // else branch
          .push_op(OpCode::EndIf);
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas).unwrap();
        assert!(result.passed);
        assert_eq!(result.stack.last().unwrap().as_int().unwrap(), 1);
    }

    #[test]
    fn out_of_gas() {
        let mut sb = ScriptBuilder::new();
        sb.push_int(1).push_int(2).push_op(OpCode::Add);
        let script = sb.build();
        let mut gas = GasMeter::new(1); // only 1 gas unit
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas);
        assert!(matches!(result, Err(ContractError::OutOfGas { .. })));
    }

    #[test]
    fn invalid_opcode() {
        let script = Script::new(vec![0xff]);
        let mut gas = GasMeter::new(1000);
        let result = Vm::execute(&script, &test_state(), &test_ctx(), &mut gas);
        assert!(matches!(result, Err(ContractError::InvalidOpcode(0xff, 0))));
    }

    #[test]
    fn kernel_signature_is_honored() {
        // With valid kernel sig, OP_CHECK_SIG returns true.
        let mut sb = ScriptBuilder::new();
        sb.push_data(&[0u8; 32]) // dummy pubkey
            .push_data(&[0u8; 64]) // dummy sig
            .push_op(OpCode::CheckSig)
            .push_op(OpCode::Verify)
            .push_int(1); // success marker after Verify consumes CheckSig result
        let script = sb.build();
        let mut gas = GasMeter::new(1000);
        let ctx = ExecutionContext {
            kernel_signature_valid: true,
            ..test_ctx()
        };
        let result = Vm::execute(&script, &test_state(), &ctx, &mut gas).unwrap();
        assert!(result.passed);

        // With invalid kernel sig, OP_CHECK_SIG returns false → VERIFY fails.
        let ctx2 = ExecutionContext {
            kernel_signature_valid: false,
            ..test_ctx()
        };
        let mut gas2 = GasMeter::new(1000);
        let result2 = Vm::execute(&script, &test_state(), &ctx2, &mut gas2);
        assert!(matches!(result2, Err(ContractError::PredicateFalse)));
    }
}
