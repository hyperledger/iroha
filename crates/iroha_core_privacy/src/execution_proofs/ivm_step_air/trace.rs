//! Bounded public scalar segments with canonical fetch and complete register continuity.
//!
//! This internal relation proves 1–64 attempted scalar steps from an explicitly
//! supplied public boundary. Signed/unsigned comparison and signed MIN/MAX use
//! the same comparison equations as conditional branches. Wrapping NEG, bitwise
//! NOT and GETGAS reuse the ALU bank; direct JMP and JAL with rd0 change only
//! the PC. CMOV/CMOVI use the full-word nonzero predicate and preserve the old
//! destination when false. POPCNT/CLZ/CTZ share the existing Boolean source
//! bits and one zero-prefix bank. MUL/MULHU/MULHSU/MULH reuse that workspace
//! for exact product digits with bounded carries and signed corrections. DIV/DIVU/
//! REM/REMU and signed ABS include exact last-attempt gas/arithmetic traps before
//! invocation cleanup. ABS rejects `i64::MIN` after the one-unit gas debit.
//! MEAN computes the signed 65-bit sum and truncates toward zero, charging two
//! gas units and completing three cycles. Final-attempt cycle admission follows
//! the interpreter pre-dispatch limit, including a completed last-step crossing.
//! ISQRT proves n=q²+r and 0<=r<=2q with a 32-bit root, charging six gas
//! and cycles. `DIV_CEIL` proves the signed quotient plus its exact same-sign
//! nonzero-remainder correction, charging twelve gas and cycles; OOG takes
//! precedence over denominator-zero and signed-overflow traps. All use the
//! existing arithmetic workspaces. GCD uses five constrained mode cells and
//! 93 physical rows per attempt whenever the complete authenticated code contains
//! a GCD opcode (including unreachable words); other programs use one row per
//! attempt. Architectural state freezes until commit. JAL with a link register is excluded. This
//! relation does not prove call entry/return, memory, private values, host effects,
//! deployment authority, finality or invocation completion.
//! There is no serialized statement or production verifier registration. The
//! interpreter recorder provides untrusted witness material, never authority.
//! Cycle admission uses the immutable artifact policy, including the default
//! ZK limit. Host `set_max_cycles` overrides are outside this bounded relation.
// TODO: Bind this substrate into the sole complete IVM invocation AIR only after
// memory, host/state, private execution, call ownership and terminal relations exist.

mod absolute;
pub(super) mod bit_count;
pub(super) mod ceiling;
pub(super) mod division;
mod gcd;
pub(super) mod mean;
pub(super) mod multiply;
pub(super) mod square_root;

use ivm::{
    PreparedContract,
    error::VmTrapKind,
    execution_step_recorder::{DiagnosticStepOutcome, DiagnosticStepRecord, DiagnosticStepState},
};

use super::{
    ALU_BANK_CONSTRAINTS, ALU_BANK_WIDTH, AggregateStarkDomainsV1, AggregateStarkParametersV1, F,
    GoldilocksDigest384V1, NOTE_COPY_AUX_WIDTH_V1, NOTE_COPY_FIXED_WIDTH_V1, NOTE_COPY_WIDTH_V1,
    NoteCopyCellPolicyV1, NoteCopyChallengesV1, NoteCopyScheduleV1, ProofManagedNoteStarkAdapterV1,
    ProofManagedNoteStarkErrorV1 as Error, ProofManagedNoteStarkProtocolV1, TRACE_LOG2, TRACE_SIZE,
    TransparentStarkDigestContextV1, TransparentTranscriptV1, alu_bank_residues, alu_bank_witness,
    bit, branch, goldilocks_digest384_frame_v1, immediate_operand, semantic_opcode, shift, wide,
    word::{self, Sources},
};

const MAX_STEPS: usize = 64;
const MAX_WORDS: usize = 64;
const _: () = assert!(MAX_STEPS * gcd::STRIDE < TRACE_SIZE);
const REGISTERS: usize = 256;
const REGISTER_WIDTH: usize = REGISTERS * 2;
const PC: usize = REGISTER_WIDTH;
const GAS: usize = PC + 1;
const GAS_DIGITS: usize = GAS + 2;
const GAS_BORROW: usize = GAS_DIGITS + 32;
const CYCLES: usize = GAS_BORROW + 1;
const CYCLE_DIGITS: usize = CYCLES + 2;
const CYCLE_CARRY: usize = CYCLE_DIGITS + 32;
const FETCH: usize = CYCLE_CARRY + 1;
const SOURCES: usize = FETCH + MAX_WORDS;
const ALU: usize = SOURCES + word::WIDTH;
const BRANCH: usize = ALU + ALU_BANK_WIDTH;
const SHIFT: usize = BRANCH + branch::BANK_WIDTH;
const RESULT: usize = SHIFT + shift::BANK_WIDTH;
const BIT_COUNT: usize = RESULT + 2;
const MULTIPLY: usize = BIT_COUNT + bit_count::WIDTH;
const ABSOLUTE: usize = MULTIPLY + multiply::WIDTH;
const MEAN_GAS: usize = ABSOLUTE + absolute::WIDTH;
const GCD: usize = MEAN_GAS + mean::GAS_WIDTH;
const ROW_WIDTH: usize = GCD + gcd::WIDTH;
const EXEC: usize = 0;
const TRANSITION: usize = 1;
const FIRST: usize = 2;
const END: usize = 3;
const OUT_OF_GAS: usize = 4;
const ASSERTION_FAILED: usize = 5;
const LAST_ATTEMPT: usize = 6;
const SLOT_ENTRY: usize = 7;
const SLOT_WORK: usize = 8;
const SLOT_COMMIT: usize = 9;
const FIXED_WIDTH: usize = 10;
// Fetch Boolean/disabled-word checks, sum and PC; source links; result links;
// every register transition and r0; PC/gas/cycle transitions; u64 range/carries;
// full boundary register/control checks; arithmetic banks.
const CONSTRAINT_COUNT: usize = 2 * MAX_WORDS
    + 2
    + 4
    + 2
    + REGISTER_WIDTH
    + 2
    + 5
    + 2 * (32 + 2 + 1)
    + 2 * (REGISTER_WIDTH + 5)
    + word::WIDTH
    + ALU_BANK_CONSTRAINTS
    + branch::BANK_CONSTRAINTS
    + shift::BANK_CONSTRAINTS
    + bit_count::CONSTRAINTS
    + multiply::CONSTRAINTS
    + division::CONSTRAINTS
    + ceiling::CONSTRAINTS
    + square_root::CONSTRAINTS
    + absolute::CONSTRAINTS
    + mean::CONSTRAINTS
    + gcd::CONSTRAINTS
    + 2
    + absolute::WIDTH
    + mean::GAS_WIDTH
    + 2;
const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"ivm-public-scalar-segment-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"ivm-scalar-segment-base-leaf-v1",
    base_node: b"ivm-scalar-segment-base-node-v1",
    aux_leaf: b"ivm-scalar-segment-aux-leaf-v1",
    aux_node: b"ivm-scalar-segment-aux-node-v1",
    composition_leaf: b"ivm-scalar-segment-composition-leaf-v1",
    composition_node: b"ivm-scalar-segment-composition-node-v1",
    fri_leaf: b"ivm-scalar-segment-fri-leaf-v1",
    fri_node: b"ivm-scalar-segment-fri-node-v1",
    layout_label: b"ivm-scalar-segment-layout-v1",
    base_root_label: b"ivm-scalar-segment-base-root-v1",
    aux_root_label: b"ivm-scalar-segment-aux-root-v1",
    composition_root_label: b"ivm-scalar-segment-composition-root-v1",
    fri_root_label: b"ivm-scalar-segment-fri-root-v1",
    fri_beta_label: b"ivm-scalar-segment-fri-beta-v1",
    query_seed: b"ivm-scalar-segment-query-seed-v1",
};
const PROFILE: &[u8] = b"ivm-public-scalar-segment-v1:attempts=1..64:whole-code<=64-words:prepared-v1-artifact:dynamic-one-hot-fetch:256-registers:two-u32-limbs:all-tags-public-zero:pre-read-post-write:r0:alu-branch-shift:compare=slt-sltu-seq-sne:signed-min-max:wrapping-neg:not:getgas:direct-jmp-jal-rd0:cmov-cmovi:full-word-nonzero:retain-false-destination:popcnt-clz-ctz:shared-source-bits:count-product-workspace:mul-mulhu-mulhsu-mulh:exact-radix16-product:18-bit-carries:two-signed-high-corrections:mean:signed65bit-sum:truncation-toward-zero:reuse-absolute-workspace:gas2-cycles3:gas-first-trap:last-attempt-cycle-limit:canonical-inactive-absolute-and-mean-cells:isqrt:root32:square-plus-remainder:strict-next-square:gas6-cycles6:div-ceil:signed-quotient:nonzero-same-sign-correction:gas12-cycles12:abs:canonical-rs1-zero-unused-operand:exact-signed-magnitude:min-trap-after-one-gas:div-divu-rem-remu:exact-product-plus-remainder:strict-remainder-bound:typed-last-attempt-outcome:gas-before-arithmetic:trap-before-invocation-cleanup:u64-gas-and-cycles:no-wrap:artifact-cycle-limit:zk-zero-default:no-host-cycle-overrides:gcd:signed-input-unsigned-magnitude:euclid-exact-product-remainder:terminal-denominator-zero:fixed91-divisions:program-derived-stride=93-if-any-code-word-opcode-is-gcd-else-1:entry-work-commit:gas12-cycles12-once:no-internal-traps:degree4:explicit-boundaries:padding-freezes:no-invocation-admission";
const BRANCH_OPS: [u8; 6] = [
    wide::control::BEQ,
    wide::control::BNE,
    wide::control::BLT,
    wide::control::BGE,
    wide::control::BLTU,
    wide::control::BGEU,
];
const SHIFT_OPS: [u8; 5] = [
    wide::arithmetic::SLL,
    wide::arithmetic::SRL,
    wide::arithmetic::SRA,
    wide::arithmetic::ROTL,
    wide::arithmetic::ROTR,
];

const DIVISION_OPS: [u8; 4] = [
    wide::arithmetic::DIV,
    wide::arithmetic::DIVU,
    wide::arithmetic::REM,
    wide::arithmetic::REMU,
];

const MULTIPLY_OPS: [u8; 4] = [
    wide::arithmetic::MUL,
    wide::arithmetic::MULHU,
    wide::arithmetic::MULHSU,
    wide::arithmetic::MULH,
];

const COUNT_OPS: [u8; 3] = [
    wide::arithmetic::POPCNT,
    wide::arithmetic::CLZ,
    wide::arithmetic::CTZ,
];

const COMPARE_OPS: [u8; 6] = [
    wide::arithmetic::SLT,
    wide::arithmetic::SLTU,
    wide::arithmetic::SEQ,
    wide::arithmetic::SNE,
    wide::arithmetic::MIN,
    wide::arithmetic::MAX,
];
// Both selections use signed less-than. For MAX, swapping the selected
// operands yields the exact maximum; equal operands have identical word bits.
const COMPARE_PREDICATES: [usize; 6] = [2, 4, 0, 1, 2, 2];

#[derive(Clone, Copy)]
enum Family {
    Alu(u8),
    Branch(usize),
    Shift(usize),
    Compare(usize),
    Jump(i64),
    Move(Operand),
    Count(usize),
    Multiply(usize),
    Division(usize),
    Absolute,
    Mean,
    SquareRoot,
    Gcd,
}

fn family(word: u32) -> Option<Family> {
    let opcode = wide::opcode(word);
    if opcode == wide::arithmetic::GCD {
        return Some(Family::Gcd);
    }
    if opcode == wide::arithmetic::ISQRT {
        return Some(Family::SquareRoot);
    }
    if opcode == wide::arithmetic::DIV_CEIL {
        return Some(Family::Division(4));
    }
    if matches!(
        semantic_opcode(opcode),
        wide::arithmetic::ADD
            | wide::arithmetic::SUB
            | wide::arithmetic::AND
            | wide::arithmetic::OR
            | wide::arithmetic::XOR
    ) {
        return Some(Family::Alu(semantic_opcode(opcode)));
    }
    match opcode {
        wide::arithmetic::CMOV => return Some(Family::Move(Operand::Register(wide::rs1(word)))),
        wide::arithmetic::CMOVI => {
            return Some(Family::Move(Operand::Constant(i64::cast_unsigned(
                i64::from(wide::imm8(word)),
            ))));
        }
        wide::arithmetic::ABS => return Some(Family::Absolute),
        wide::arithmetic::MEAN => return Some(Family::Mean),
        wide::arithmetic::NEG => return Some(Family::Alu(wide::arithmetic::SUB)),
        wide::arithmetic::NOT => return Some(Family::Alu(wide::arithmetic::XOR)),
        wide::system::GETGAS => return Some(Family::Alu(wide::arithmetic::ADD)),
        wide::control::JMP => return Some(Family::Jump(i64::from(wide::imm24(word)) * 4)),
        // The admitted interpreter only changes PC for rd0. Linked calls own
        // protected return/call-table state and cannot enter this scalar cut.
        wide::control::JAL if wide::rd(word) == 0 => {
            return Some(Family::Jump(i64::from(wide::imm16(word)) * 4));
        }
        _ => {}
    }
    if let Some(index) = DIVISION_OPS
        .iter()
        .position(|candidate| *candidate == opcode)
    {
        return Some(Family::Division(index));
    }
    if let Some(index) = MULTIPLY_OPS
        .iter()
        .position(|candidate| *candidate == opcode)
    {
        return Some(Family::Multiply(index));
    }
    if let Some(index) = COUNT_OPS.iter().position(|candidate| *candidate == opcode) {
        return Some(Family::Count(index));
    }
    if let Some(index) = COMPARE_OPS
        .iter()
        .position(|candidate| *candidate == opcode)
    {
        return Some(Family::Compare(index));
    }
    if let Some(index) = BRANCH_OPS.iter().position(|candidate| *candidate == opcode) {
        return Some(Family::Branch(index));
    }
    let opcode = match opcode {
        wide::arithmetic::ROTL_IMM => wide::arithmetic::ROTL,
        wide::arithmetic::ROTR_IMM => wide::arithmetic::ROTR,
        other => other,
    };
    SHIFT_OPS
        .iter()
        .position(|candidate| *candidate == opcode)
        .map(Family::Shift)
}

// This is the canonical completed dispatch cost, not the gas price. MEAN
// charges two gas units but completes three cycles in the sole interpreter.
fn completed_cycles(word: u32) -> u64 {
    match wide::opcode(word) {
        wide::arithmetic::MEAN => 3,
        wide::arithmetic::ISQRT => 6,
        wide::arithmetic::DIV_CEIL | wide::arithmetic::GCD => 12,
        _ => 1,
    }
}

fn immediate(word: u32) -> Option<u64> {
    immediate_operand(word).or_else(|| {
        matches!(
            wide::opcode(word),
            wide::arithmetic::ROTL_IMM | wide::arithmetic::ROTR_IMM
        )
        .then(|| u64::from(i8::cast_unsigned(wide::imm8(word))))
    })
}

/// Canonical reads for the shared arithmetic banks. Unused instruction fields
/// never become semantic operands; gas is already range constrained in the row.
#[derive(Clone, Copy)]
enum Operand {
    Register(usize),
    Constant(u64),
    GasRemaining,
}

impl Operand {
    fn value(self, state: &DiagnosticStepState) -> u64 {
        match self {
            Self::Register(index) => state.registers[index],
            Self::Constant(value) => value,
            Self::GasRemaining => state.gas_remaining,
        }
    }

    fn half(self, row: &[F], half: usize) -> F {
        match self {
            Self::Register(index) => row[2 * index + half],
            Self::Constant(value) => halves(value)[half],
            Self::GasRemaining => row[GAS + half],
        }
    }
}

fn operands(word: u32, family: Family) -> [Operand; 2] {
    use Operand::{Constant, GasRemaining, Register};
    match wide::opcode(word) {
        wide::arithmetic::NEG => [Constant(0), Register(wide::rs1(word))],
        wide::arithmetic::NOT => [Register(wide::rs1(word)), Constant(u64::MAX)],
        wide::system::GETGAS => [GasRemaining, Constant(0)],
        _ => match family {
            Family::Branch(_) => [Register(wide::rd(word)), Register(wide::rs1(word))],
            Family::Jump(_) => [Constant(0), Constant(0)],
            Family::Count(_) | Family::Absolute | Family::SquareRoot => {
                [Register(wide::rs1(word)), Constant(0)]
            }
            Family::Move(_) => [
                Register(if wide::opcode(word) == wide::arithmetic::CMOV {
                    wide::rs2(word)
                } else {
                    wide::rs1(word)
                }),
                Constant(0),
            ],
            _ => [
                Register(wide::rs1(word)),
                immediate(word).map_or(Register(wide::rs2(word)), Constant),
            ],
        },
    }
}

fn halves(value: u64) -> [F; 2] {
    [F(value & 0xffff_ffff), F(value >> 32)]
}
fn half_from_limbs(bank: &[F], offset: usize, half: usize) -> F {
    bank[offset + 2 * half].add(bank[offset + 2 * half + 1].mul(F(1 << 16)))
}
fn signed(value: i64) -> F {
    if value < 0 {
        F::ZERO.sub(F(value.unsigned_abs()))
    } else {
        F(i64::cast_unsigned(value))
    }
}

/// Public opcode-boundary outcome. Traps end the final attempted arithmetic
/// instruction before global invocation cleanup; they do not authorize effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SegmentOutcome {
    Continue = 0,
    AssertionFailed = 1,
    OutOfGas = 2,
}

impl SegmentOutcome {
    fn trapped(self) -> bool {
        self != Self::Continue
    }

    fn diagnostic(self) -> DiagnosticStepOutcome {
        match self {
            Self::Continue => DiagnosticStepOutcome::Completed,
            Self::AssertionFailed => DiagnosticStepOutcome::Trapped(VmTrapKind::AssertionFailed),
            Self::OutOfGas => DiagnosticStepOutcome::Trapped(VmTrapKind::OutOfGas),
        }
    }
}

/// Immutable verifier-owned code and explicit public segment boundaries.
/// Construction never accepts a supplied instruction table or claimed code hash.
struct ScalarSegment {
    contract: PreparedContract,
    words: Vec<u32>,
    first_pc: u32,
    steps: usize,
    before: DiagnosticStepState,
    after: DiagnosticStepState,
    outcome: SegmentOutcome,
}

impl ScalarSegment {
    fn new(
        contract: PreparedContract,
        steps: usize,
        before: DiagnosticStepState,
        after: DiagnosticStepState,
        outcome: SegmentOutcome,
    ) -> Result<Self, Error> {
        let first_pc = contract
            .code_offset()
            .checked_sub(contract.header_len())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::InvalidProfile)?;
        let bytes = contract
            .artifact()
            .get(contract.code_offset()..)
            .ok_or(Error::InvalidProfile)?;
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) || bytes.len() / 4 > MAX_WORDS {
            return Err(Error::InvalidProfile);
        }
        let words = bytes
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte chunk")))
            .collect();
        let result = Self {
            contract,
            words,
            first_pc,
            steps,
            before,
            after,
            outcome,
        };
        result.validate()?;
        Ok(result)
    }

    /// The same artifact-derived normalization used by IVM program installation.
    /// A future invocation owner must bind any host override as explicit context;
    /// this substrate never infers such authority from diagnostic snapshots.
    fn cycle_limit(&self) -> u64 {
        let metadata = self.contract.metadata();
        if metadata.max_cycles == 0 && metadata.mode & ivm::ivm_mode::ZK != 0 {
            ivm::zk::MAX_CYCLES
        } else {
            metadata.max_cycles
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let completed = self
            .steps
            .checked_sub(usize::from(self.outcome.trapped()))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(Error::InvalidProfile)?;
        let maximum_step_cycles = self
            .words
            .iter()
            .copied()
            .map(completed_cycles)
            .max()
            .unwrap_or(1);
        let maximum_completed = completed
            .checked_mul(maximum_step_cycles)
            .ok_or(Error::InvalidProfile)?;
        let observed_completed = self
            .after
            .cycles
            .checked_sub(self.before.cycles)
            .ok_or(Error::InvalidProfile)?;
        let last_attempt = self
            .steps
            .checked_sub(1)
            .and_then(|count| self.before.cycles.checked_add(count as u64))
            .ok_or(Error::InvalidProfile)?;
        let executable = self
            .contract
            .artifact()
            .get(self.contract.code_offset()..)
            .ok_or(Error::InvalidProfile)?;
        if !(1..=MAX_STEPS).contains(&self.steps)
            || self.words.is_empty()
            || self.words.len() > MAX_WORDS
            || self.contract.metadata().abi_version != 1
            || self.contract.contract_interface().abi_hash
                != ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1)
            || executable.len() != self.words.len() * 4
            || executable
                .chunks_exact(4)
                .zip(&self.words)
                .any(|(bytes, word)| bytes != word.to_le_bytes())
            || self
                .contract
                .code_offset()
                .checked_sub(self.contract.header_len())
                != Some(self.first_pc as usize)
            || u64::from(self.first_pc) + executable.len() as u64 > u64::from(u32::MAX)
            || (observed_completed < completed || observed_completed > maximum_completed)
            || self.before.vector_length != self.after.vector_length
            || (self.cycle_limit() != 0
                && (self.after.cycles > self.cycle_limit().saturating_add(maximum_step_cycles - 1)
                    || last_attempt >= self.cycle_limit()))
        {
            return Err(Error::InvalidProfile);
        }
        for boundary in [&self.before, &self.after] {
            let relative = boundary
                .pc
                .checked_sub(u64::from(self.first_pc))
                .ok_or(Error::InvalidProfile)?;
            if !self.contract.is_instruction_boundary(relative)
                || boundary.registers[0] != 0
                || boundary.tags.iter().any(|tag| *tag)
                || boundary.halted
                || boundary.constraint_failed
            {
                return Err(Error::InvalidProfile);
            }
        }
        Ok(())
    }

    fn digest(&self) -> Result<GoldilocksDigest384V1, Error> {
        self.validate()?;
        let mut boundaries = Vec::with_capacity(2 * (6 * 8 + REGISTERS * 9));
        for state in [&self.before, &self.after] {
            for value in [
                state.pc,
                state.gas_remaining,
                state.cycles,
                u64::try_from(state.vector_length).map_err(|_| Error::InvalidProfile)?,
            ] {
                boundaries.extend_from_slice(&value.to_be_bytes());
            }
            boundaries.extend([u8::from(state.halted), u8::from(state.constraint_failed)]);
            for value in state.registers {
                boundaries.extend_from_slice(&value.to_be_bytes());
            }
            boundaries.extend(state.tags.map(u8::from));
        }
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"ivm-scalar-segment-public-v1",
            b"boundaries",
            0,
            0,
            0,
            &[
                self.contract.code_hash().as_ref(),
                &self.contract.contract_interface().abi_hash,
                &(self.steps as u64).to_be_bytes(),
                &[self.outcome as u8],
                &boundaries,
            ],
        )
        .map_err(|_| Error::InvalidProfile)
    }

    /// Derived from the complete immutable code, including unreachable GCD words.
    /// The witness supplies neither a schedule nor an instruction subset.
    fn stride(&self) -> usize {
        if self
            .words
            .iter()
            .any(|word| wide::opcode(*word) == wide::arithmetic::GCD)
        {
            gcd::STRIDE
        } else {
            1
        }
    }

    fn physical_steps(&self) -> usize {
        self.steps * self.stride()
    }

    fn fixed_row(&self, row: usize) -> [F; FIXED_WIDTH] {
        let stride = self.stride();
        let active = row < self.physical_steps();
        let last = active && row / stride + 1 == self.steps;
        let phase = row % stride;
        [
            F(u64::from(active)),
            F(u64::from(row + 1 < TRACE_SIZE)),
            F(u64::from(row == 0)),
            F(u64::from(row == self.physical_steps())),
            F(u64::from(last && self.outcome == SegmentOutcome::OutOfGas)),
            F(u64::from(
                last && self.outcome == SegmentOutcome::AssertionFailed,
            )),
            F(u64::from(last)),
            F(u64::from(active && stride > 1 && phase == 0)),
            F(u64::from(active && phase > 0 && phase + 1 < stride)),
            F(u64::from(active && phase + 1 == stride)),
        ]
    }

    /// Build bounded candidate rows. AIR verification, not recorder agreement,
    /// establishes the relation; tests intentionally mutate these rows afterward.
    fn witness_rows(&self, records: &[DiagnosticStepRecord]) -> Result<Vec<Vec<F>>, Error> {
        self.validate()?;
        if records.len() != self.steps
            || records[0].before != self.before
            || records[self.steps - 1].after != self.after
        {
            return Err(Error::InvalidTrace);
        }
        let mut rows = Vec::with_capacity(self.physical_steps() + 1);
        let scalar_vector_length = self.before.vector_length;
        for (index, record) in records.iter().enumerate() {
            let outcome = if index + 1 == self.steps {
                self.outcome
            } else {
                SegmentOutcome::Continue
            };
            if record.outcome != outcome.diagnostic()
                || (index > 0 && records[index - 1].after != record.before)
                || record
                    .before
                    .tags
                    .iter()
                    .chain(&record.after.tags)
                    .any(|tag| *tag)
                || record.before.halted
                || record.after.halted
                || record.before.constraint_failed
                || record.after.constraint_failed
                || record.before.vector_length != scalar_vector_length
                || record.after.vector_length != scalar_vector_length
            {
                return Err(Error::InvalidTrace);
            }
            let offset = record
                .before
                .pc
                .checked_sub(u64::from(self.first_pc))
                .ok_or(Error::InvalidTrace)?;
            let word_index = usize::try_from(offset / 4).map_err(|_| Error::InvalidTrace)?;
            let word = *self.words.get(word_index).ok_or(Error::InvalidTrace)?;
            if !offset.is_multiple_of(4)
                || record.instruction != Some(word)
                || record.opcode != Some(wide::opcode(word))
                || record.opcode_gas != super::gas::cost_of(word)
                || record
                    .before
                    .cycles
                    .checked_add(completed_cycles(word) * u64::from(!outcome.trapped()))
                    != Some(record.after.cycles)
                || (self.cycle_limit() != 0 && record.before.cycles >= self.cycle_limit())
                || family(word).is_none()
                || (outcome.trapped()
                    && !matches!(
                        family(word),
                        Some(
                            Family::Division(_)
                                | Family::Absolute
                                | Family::Mean
                                | Family::SquareRoot
                                | Family::Gcd
                        )
                    ))
            {
                return Err(Error::InvalidTrace);
            }
            let mut pair = if matches!(family(word), Some(Family::Gcd)) {
                [
                    gcd::magnitude(record.before.registers[wide::rs1(word)]),
                    gcd::magnitude(record.before.registers[wide::rs2(word)]),
                ]
            } else {
                [0, 0]
            };
            for phase in 0..self.stride() {
                rows.push(self.witness_row_at(
                    &record.before,
                    Some((word_index, word)),
                    phase,
                    pair,
                ));
                if phase > 0 && phase + 1 < self.stride() && pair[1] != 0 {
                    pair = [pair[1], pair[0] % pair[1]];
                }
            }
        }
        rows.push(self.witness_row(&self.after, None));
        Ok(rows)
    }

    fn witness_row(
        &self,
        state: &DiagnosticStepState,
        instruction: Option<(usize, u32)>,
    ) -> Vec<F> {
        self.witness_row_at(state, instruction, 0, [0, 0])
    }

    fn witness_row_at(
        &self,
        state: &DiagnosticStepState,
        instruction: Option<(usize, u32)>,
        phase: usize,
        pair: [u64; 2],
    ) -> Vec<F> {
        let mut row = vec![F::ZERO; ROW_WIDTH];
        for (register, value) in state.registers.into_iter().enumerate() {
            row[2 * register..2 * register + 2].copy_from_slice(&halves(value));
        }
        row[PC] = F(state.pc);
        for (offset, digits, value) in [
            (GAS, GAS_DIGITS, state.gas_remaining),
            (CYCLES, CYCLE_DIGITS, state.cycles),
        ] {
            row[offset..offset + 2].copy_from_slice(&halves(value));
            for digit in 0..32 {
                row[digits + digit] = F((value >> (2 * digit)) & 3);
            }
        }
        let mut alu_opcode = wide::arithmetic::ADD;
        let mut branch_opcode = wide::control::BEQ;
        let mut shift_opcode = wide::arithmetic::SLL;
        let (mut left, mut right) = (0, 0);
        let mut selected_family = None;
        if let Some((index, word)) = instruction {
            row[FETCH + index] = F::ONE;
            selected_family = family(word);
            let sources = operands(word, selected_family.expect("validated scalar instruction"));
            [left, right] = sources.map(|source| source.value(state));
            if matches!(selected_family, Some(Family::Gcd))
                && state.gas_remaining >= 12
                && phase > 0
            {
                [left, right] = pair;
            }
            match selected_family {
                Some(Family::Alu(opcode)) => alu_opcode = opcode,
                Some(Family::Branch(index)) => branch_opcode = BRANCH_OPS[index],
                Some(Family::Shift(index)) => shift_opcode = SHIFT_OPS[index],
                Some(Family::Compare(index)) => {
                    branch_opcode = BRANCH_OPS[COMPARE_PREDICATES[index]]
                }
                Some(
                    Family::Jump(_)
                    | Family::Count(_)
                    | Family::Multiply(_)
                    | Family::Division(_)
                    | Family::Absolute
                    | Family::Mean
                    | Family::SquareRoot
                    | Family::Gcd,
                ) => {}
                Some(Family::Move(_)) => branch_opcode = wide::control::BNE,
                None => unreachable!("validated scalar instruction"),
            }
            let cost = super::gas::cost_of(word).expect("admitted scalar cost");
            let arithmetic_trap = match selected_family {
                Some(Family::Division(kind)) => {
                    state.gas_remaining < cost
                        || right == 0
                        || (division::signed_kind(kind)
                            && left == i64::cast_unsigned(i64::MIN)
                            && right == u64::MAX)
                }
                Some(Family::Absolute) => {
                    state.gas_remaining < cost || left == i64::cast_unsigned(i64::MIN)
                }
                Some(Family::Mean | Family::SquareRoot | Family::Gcd) => state.gas_remaining < cost,
                _ => false,
            };
            let effective_cost = if matches!(
                selected_family,
                Some(
                    Family::Division(_)
                        | Family::Absolute
                        | Family::Mean
                        | Family::SquareRoot
                        | Family::Gcd
                )
            ) && state.gas_remaining < cost
            {
                0
            } else {
                cost
            };
            row[GAS_BORROW] = F(u64::from(
                (state.gas_remaining & 0xffff_ffff) < effective_cost,
            ));
            row[CYCLE_CARRY] = F(u64::from(
                !arithmetic_trap
                    && (state.cycles & 0xffff_ffff) + completed_cycles(word) > 0xffff_ffff,
            ));
        }
        row[SOURCES..ALU].copy_from_slice(&word::witness(left, right));
        row[ALU..BRANCH].copy_from_slice(&alu_bank_witness(alu_opcode, left, right));
        row[BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(branch_opcode, left, right));
        row[SHIFT..RESULT].copy_from_slice(&shift::bank_witness(shift_opcode, left, right));
        if let Some(bank_offset) = match selected_family {
            Some(Family::Alu(_)) => Some(ALU),
            Some(Family::Shift(_)) => Some(SHIFT),
            _ => None,
        } {
            for half in 0..2 {
                row[RESULT + half] = half_from_limbs(&row[bank_offset..], 0, half);
            }
        }
        if let Some(Family::Compare(index)) = selected_family {
            let result = if index < 4 {
                row[BRANCH + branch::TAKEN_BANK_OFFSET].0
            } else if index == 4 {
                i64::cast_unsigned(u64::cast_signed(left).min(u64::cast_signed(right)))
            } else {
                i64::cast_unsigned(u64::cast_signed(left).max(u64::cast_signed(right)))
            };
            row[RESULT..RESULT + 2].copy_from_slice(&halves(result));
        }
        if let Some(Family::Move(value)) = selected_family {
            let (_, word) = instruction.expect("selected conditional move");
            let result = if left != 0 {
                value.value(state)
            } else {
                state.registers[wide::rd(word)]
            };
            row[RESULT..RESULT + 2].copy_from_slice(&halves(result));
        }
        let input_bits = Sources::new(&row[SOURCES..ALU]).bits(0);
        let prefixes = bit_count::witness(
            input_bits,
            matches!(selected_family, Some(Family::Count(1))),
        );
        if let Some(Family::Count(index)) = selected_family {
            row[RESULT] = if index == 0 {
                input_bits.iter().copied().fold(F::ZERO, F::add)
            } else {
                prefixes.into_iter().fold(F::ZERO, F::add)
            };
        }
        let workspace = if matches!(selected_family, Some(Family::Multiply(_))) {
            multiply::product_digits(left, right)
        } else {
            prefixes
        };
        row[BIT_COUNT..MULTIPLY].copy_from_slice(&workspace);
        row[MULTIPLY..ABSOLUTE].copy_from_slice(&multiply::witness(
            left,
            right,
            &workspace,
            matches!(selected_family, Some(Family::Multiply(_))),
        ));
        if let Some(Family::Multiply(index)) = selected_family {
            for half in 0..2 {
                row[RESULT + half] = multiply::result_half(&row[MULTIPLY..ABSOLUTE], index, half);
            }
        }
        if let Some(Family::Division(kind)) = selected_family {
            let witness = division::witness(left, right, state.gas_remaining, kind);
            row[SHIFT..RESULT].copy_from_slice(&witness.bank);
            row[BIT_COUNT..MULTIPLY].copy_from_slice(&witness.digits);
            row[MULTIPLY..ABSOLUTE].copy_from_slice(&witness.product);
            row[BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(
                wide::control::BEQ,
                witness.remainder,
                witness.denominator,
            ));
            for half in 0..2 {
                row[RESULT + half] = division::result_half(&witness.bank, kind, half);
            }
            if kind == 4 {
                let bank = ceiling::witness(&witness.bank);
                for half in 0..2 {
                    row[RESULT + half] = half_from_limbs(&bank, 0, half);
                }
                row[ABSOLUTE..MEAN_GAS].copy_from_slice(&bank);
            }
        }
        if let Some(Family::SquareRoot) = selected_family {
            let witness = square_root::witness(left, state.gas_remaining);
            row[SHIFT..RESULT].copy_from_slice(&witness.bank);
            row[BIT_COUNT..MULTIPLY].copy_from_slice(&witness.digits);
            row[MULTIPLY..ABSOLUTE].copy_from_slice(&witness.product);
            for half in 0..2 {
                row[RESULT + half] = half_from_limbs(&witness.bank, division::QUOTIENT, half);
            }
        }
        if let Some(Family::Absolute) = selected_family {
            let bank = absolute::witness(left, state.gas_remaining);
            for half in 0..2 {
                row[RESULT + half] = half_from_limbs(&bank, 0, half);
            }
            row[ABSOLUTE..MEAN_GAS].copy_from_slice(&bank);
        }
        if let Some(Family::Mean) = selected_family {
            let (bank, gas) = mean::witness(left, right, state.gas_remaining);
            for half in 0..2 {
                row[RESULT + half] = half_from_limbs(&bank, 0, half);
            }
            row[ABSOLUTE..MEAN_GAS].copy_from_slice(&bank);
            row[MEAN_GAS..GCD].copy_from_slice(&gas);
        }
        if let Some(Family::Gcd) = selected_family {
            let (absolute, gas) = gcd::gas_witness(state.gas_remaining);
            row[ABSOLUTE..MEAN_GAS].copy_from_slice(&absolute);
            row[MEAN_GAS..GCD].copy_from_slice(&gas);
            if state.gas_remaining >= 12 {
                let entering = phase == 0;
                let working = phase > 0 && phase + 1 < self.stride();
                let committing = phase + 1 == self.stride();
                row[GCD..].copy_from_slice(&[
                    F::ONE,
                    F(u64::from(entering)),
                    F(u64::from(working)),
                    F(u64::from(working && right != 0)),
                    F(u64::from(committing)),
                ]);
                if entering || working {
                    let witness = gcd::witness(left, right, entering);
                    row[SHIFT..RESULT].copy_from_slice(&witness.bank);
                    row[BIT_COUNT..MULTIPLY].copy_from_slice(&witness.digits);
                    row[MULTIPLY..ABSOLUTE].copy_from_slice(&witness.product);
                    row[BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(
                        wide::control::BEQ,
                        witness.remainder,
                        witness.denominator,
                    ));
                }
                if committing {
                    row[RESULT..RESULT + 2].copy_from_slice(&halves(left));
                }
            }
        }
        if phase + 1 != self.stride() {
            row[GAS_BORROW] = F::ZERO;
            row[CYCLE_CARRY] = F::ZERO;
        }
        row
    }

    fn columns(&self, records: &[DiagnosticStepRecord]) -> Result<Vec<Vec<F>>, Error> {
        let rows = self.witness_rows(records)?;
        let mut columns = vec![vec![F::ZERO; TRACE_SIZE]; NOTE_COPY_WIDTH_V1 + ROW_WIDTH];
        for (index, column) in columns[NOTE_COPY_WIDTH_V1..].iter_mut().enumerate() {
            for (row, value) in column.iter_mut().enumerate() {
                *value = rows[row.min(self.physical_steps())][index];
            }
        }
        Ok(columns)
    }
}

fn range_u64(out: &mut Vec<F>, row: &[F], offset: usize, digits: usize, carry: usize) {
    for digit in &row[digits..digits + 32] {
        out.push(
            digit
                .mul(digit.sub(F::ONE))
                .mul(digit.sub(F(2)))
                .mul(digit.sub(F(3))),
        );
    }
    for half in 0..2 {
        let value = (0..16).fold(F::ZERO, |sum, digit| {
            sum.add(row[digits + half * 16 + digit].mul(F(1 << (2 * digit))))
        });
        out.push(row[offset + half].sub(value));
    }
    out.push(bit(row[carry]));
}

fn residues(segment: &ScalarSegment, row: &[F], next: &[F], fixed: &[F]) -> Result<Vec<F>, Error> {
    if row.len() != ROW_WIDTH || next.len() != ROW_WIDTH || fixed.len() != FIXED_WIDTH {
        return Err(Error::InvalidTrace);
    }
    let mut out = Vec::with_capacity(CONSTRAINT_COUNT);
    let mut fetch_sum = F::ZERO;
    let mut fetched_pc = F::ZERO;
    let mut cost = F::ZERO;
    let mut left = [F::ZERO; 2];
    let mut right = [F::ZERO; 2];
    let mut writes = [F::ZERO; REGISTERS];
    let mut alu_selectors = [F::ZERO; 4];
    let mut branch_selectors = [F::ZERO; 6];
    let mut shift_selectors = [F::ZERO; 5];
    let mut compare_selectors = [F::ZERO; 6];
    let mut count_selectors = [F::ZERO; 3];
    let mut multiply_selectors = [F::ZERO; 4];
    let mut division_selectors = [F::ZERO; 5];
    let mut square_selected = F::ZERO;
    let mut gcd_selected = F::ZERO;
    let mut absolute_selected = F::ZERO;
    let mut mean_selected = F::ZERO;
    let mut last_cycle_refusal = F::ZERO;
    let mut alu_selected = F::ZERO;
    let mut branch_selected = F::ZERO;
    let mut shift_selected = F::ZERO;
    let mut displacement = F::ZERO;
    let mut jump_selected = F::ZERO;
    let mut jump_displacement = F::ZERO;
    let mut move_selected = F::ZERO;
    let mut move_value = [F::ZERO; 2];
    let mut move_retained = [F::ZERO; 2];
    for index in 0..MAX_WORDS {
        let selected = row[FETCH + index];
        out.push(bit(selected));
        let decoded = segment
            .words
            .get(index)
            .and_then(|word| family(*word).map(|family| (*word, family)));
        out.push(if decoded.is_some() { F::ZERO } else { selected });
        fetch_sum = fetch_sum.add(selected);
        let Some((word, family)) = decoded else {
            continue;
        };
        fetched_pc =
            fetched_pc.add(selected.mul(F(u64::from(segment.first_pc) + 4 * index as u64)));
        let sources = operands(word, family);
        for half in 0..2 {
            left[half] = left[half].add(selected.mul(sources[0].half(row, half)));
            right[half] = right[half].add(selected.mul(sources[1].half(row, half)));
        }
        cost = cost.add(selected.mul(F(super::gas::cost_of(word).ok_or(Error::InvalidProfile)?)));
        // The last attempt's exact start cycle is determined by the bound public
        // end cycle and selected canonical opcode. All earlier successful rows
        // advance by a positive amount, so this also admits their start cycles.
        let increment = completed_cycles(word) * u64::from(!segment.outcome.trapped());
        let last_allowed = segment
            .after
            .cycles
            .checked_sub(increment)
            .is_some_and(|before| segment.cycle_limit() == 0 || before < segment.cycle_limit());
        last_cycle_refusal = last_cycle_refusal.add(selected.mul(F(u64::from(!last_allowed))));
        if !matches!(family, Family::Branch(_) | Family::Jump(_)) && wide::rd(word) != 0 {
            writes[wide::rd(word)] = writes[wide::rd(word)].add(selected);
        }
        match family {
            Family::Alu(operation) => {
                alu_selected = alu_selected.add(selected);
                if let Some(index) = [
                    wide::arithmetic::SUB,
                    wide::arithmetic::AND,
                    wide::arithmetic::OR,
                    wide::arithmetic::XOR,
                ]
                .iter()
                .position(|opcode| *opcode == operation)
                {
                    alu_selectors[index] = alu_selectors[index].add(selected);
                }
            }
            Family::Branch(index) => {
                branch_selected = branch_selected.add(selected);
                branch_selectors[index] = branch_selectors[index].add(selected);
                displacement =
                    displacement.add(selected.mul(signed(i64::from(wide::imm8(word)) * 4)));
            }
            Family::Shift(index) => {
                shift_selected = shift_selected.add(selected);
                shift_selectors[index] = shift_selectors[index].add(selected);
            }
            Family::Compare(index) => {
                compare_selectors[index] = compare_selectors[index].add(selected);
                let predicate = COMPARE_PREDICATES[index];
                branch_selectors[predicate] = branch_selectors[predicate].add(selected);
            }
            Family::Jump(displacement) => {
                jump_selected = jump_selected.add(selected);
                jump_displacement = jump_displacement.add(selected.mul(signed(displacement)));
            }
            Family::Absolute => absolute_selected = absolute_selected.add(selected),
            Family::Mean => mean_selected = mean_selected.add(selected),
            Family::SquareRoot => square_selected = square_selected.add(selected),
            Family::Gcd => gcd_selected = gcd_selected.add(selected),
            Family::Division(index) => {
                division_selectors[index] = division_selectors[index].add(selected);
            }
            Family::Multiply(index) => {
                multiply_selectors[index] = multiply_selectors[index].add(selected);
            }
            Family::Count(index) => {
                count_selectors[index] = count_selectors[index].add(selected);
            }
            Family::Move(value) => {
                move_selected = move_selected.add(selected);
                branch_selectors[1] = branch_selectors[1].add(selected);
                for half in 0..2 {
                    move_value[half] = move_value[half].add(selected.mul(value.half(row, half)));
                    move_retained[half] =
                        move_retained[half].add(selected.mul(row[2 * wide::rd(word) + half]));
                }
            }
        }
    }
    out.push(fixed[LAST_ATTEMPT].mul(last_cycle_refusal));
    out.push(fetch_sum.sub(fixed[EXEC]));
    out.push(fixed[EXEC].mul(row[PC]).sub(fetched_pc));
    // Non-selected banks still execute a fully constrained dummy operation on
    // the same source words; division routes the comparison to its remainder bound.
    // Quartic range constraints are never selector-gated.
    let compare_selected = compare_selectors.into_iter().fold(F::ZERO, F::add);
    branch_selectors[0] = branch_selectors[0].add(
        F::ONE
            .sub(branch_selected)
            .sub(compare_selected)
            .sub(move_selected),
    );
    shift_selectors[0] = shift_selectors[0].add(F::ONE.sub(shift_selected));
    let sources = Sources::new(&row[SOURCES..ALU]);
    let gcd_entry = row[GCD + gcd::ENTRY];
    let gcd_work = row[GCD + gcd::WORK];
    let gcd_divide = row[GCD + gcd::DIVIDE];
    let gcd_commit = row[GCD + gcd::COMMIT];
    let canonical_reads = F::ONE.sub(row[GCD + gcd::ACTIVE]).add(gcd_entry);
    for half in 0..2 {
        out.push(canonical_reads.mul(sources.half(0, half).sub(left[half])));
        out.push(canonical_reads.mul(sources.half(1, half).sub(right[half])));
    }
    let division_selected = division_selectors.into_iter().fold(F::ZERO, F::add);
    let ceiling_selected = division_selectors[4];
    let division_signed = division_selectors[0]
        .add(division_selectors[2])
        .add(ceiling_selected);
    let trap = fixed[OUT_OF_GAS].add(fixed[ASSERTION_FAILED]);
    cost = cost.mul(F::ONE.sub(fixed[OUT_OF_GAS]));
    let division_trap = trap.mul(division_selected);
    let taken = row[BRANCH + branch::TAKEN_BANK_OFFSET];
    let compare_boolean = compare_selectors[..4].iter().copied().fold(F::ZERO, F::add);
    let source_bits = sources.bits(0);
    let population = source_bits.iter().copied().fold(F::ZERO, F::add);
    let zeros = row[BIT_COUNT..MULTIPLY]
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    let count = count_selectors[0]
        .mul(population)
        .add(count_selectors[1].add(count_selectors[2]).mul(zeros));
    for half in 0..2 {
        // These are already linked to the canonical source reads. Using the
        // common bits keep opcode × predicate × value at degree three.
        let left = sources.half(0, half);
        let right = sources.half(1, half);
        let minimum = taken.mul(left).add(F::ONE.sub(taken).mul(right));
        let maximum = taken.mul(right).add(F::ONE.sub(taken).mul(left));
        let boolean = if half == 0 { taken } else { F::ZERO };
        out.push(
            row[RESULT + half]
                .sub(alu_selected.mul(half_from_limbs(&row[ALU..], 0, half)))
                .sub(shift_selected.mul(half_from_limbs(&row[SHIFT..], 0, half)))
                .sub(compare_boolean.mul(boolean))
                .sub(compare_selectors[4].mul(minimum))
                .sub(compare_selectors[5].mul(maximum))
                // Value/retained each already includes one fetch selector.
                // The nonzero predicate is constrained over four u16 limbs,
                // never a u64 reduced to one field element.
                .sub(taken.mul(move_value[half]))
                .sub(F::ONE.sub(taken).mul(move_retained[half]))
                .sub(if half == 0 { count } else { F::ZERO })
                .sub(
                    absolute_selected
                        .add(mean_selected)
                        .add(ceiling_selected)
                        .mul(half_from_limbs(&row[ABSOLUTE..MEAN_GAS], 0, half)),
                )
                .sub(gcd_commit.mul(sources.half(0, half)))
                .sub(square_selected.mul(half_from_limbs(
                    &row[SHIFT..RESULT],
                    division::QUOTIENT,
                    half,
                )))
                .sub(division_selectors[..4].iter().enumerate().fold(
                    F::ZERO,
                    |sum, (kind, selector)| {
                        sum.add(selector.mul(division::result_half(
                            &row[SHIFT..RESULT],
                            kind,
                            half,
                        )))
                    },
                ))
                .sub(multiply_selectors.iter().enumerate().fold(
                    F::ZERO,
                    |sum, (kind, selector)| {
                        sum.add(selector.mul(multiply::result_half(
                            &row[MULTIPLY..ABSOLUTE],
                            kind,
                            half,
                        )))
                    },
                )),
        );
    }
    for (register, write) in writes.into_iter().enumerate() {
        let write = write.mul(F::ONE.sub(trap));
        for half in 0..2 {
            let offset = 2 * register + half;
            out.push(
                fixed[TRANSITION].mul(next[offset].sub(row[offset])).sub(
                    fixed[SLOT_COMMIT]
                        .mul(write)
                        .mul(row[RESULT + half].sub(row[offset])),
                ),
            );
        }
    }
    out.extend([row[0], row[1]]);
    out.push(
        fixed[TRANSITION].mul(next[PC].sub(row[PC])).sub(
            fixed[SLOT_COMMIT].mul(
                fixed[EXEC]
                    .sub(trap)
                    .mul(F(4))
                    .add(taken.mul(displacement.sub(branch_selected.mul(F(4)))))
                    .add(jump_displacement.sub(jump_selected.mul(F(4)))),
            ),
        ),
    );
    out.push(
        fixed[TRANSITION]
            .mul(row[GAS].sub(next[GAS]).add(row[GAS_BORROW].mul(F(1 << 32))))
            .sub(fixed[SLOT_COMMIT].mul(cost)),
    );
    out.push(fixed[TRANSITION].mul(row[GAS + 1].sub(row[GAS_BORROW]).sub(next[GAS + 1])));
    out.push(
        fixed[TRANSITION]
            .mul(
                row[CYCLES]
                    .sub(next[CYCLES])
                    .sub(row[CYCLE_CARRY].mul(F(1 << 32))),
            )
            .add(
                fixed[SLOT_COMMIT].mul(
                    fixed[EXEC]
                        .add(mean_selected.mul(F(2)))
                        .add(square_selected.mul(F(5)))
                        .add(ceiling_selected.add(gcd_selected).mul(F(11)))
                        .mul(F::ONE.sub(trap)),
                ),
            ),
    );
    out.push(fixed[TRANSITION].mul(row[CYCLES + 1].add(row[CYCLE_CARRY]).sub(next[CYCLES + 1])));
    out.push(F::ONE.sub(fixed[SLOT_COMMIT]).mul(row[GAS_BORROW]));
    out.push(F::ONE.sub(fixed[SLOT_COMMIT]).mul(row[CYCLE_CARRY]));
    range_u64(&mut out, row, GAS, GAS_DIGITS, GAS_BORROW);
    range_u64(&mut out, row, CYCLES, CYCLE_DIGITS, CYCLE_CARRY);
    for (mask, boundary) in [
        (fixed[FIRST], &segment.before),
        (fixed[END], &segment.after),
    ] {
        for (register, value) in boundary.registers.into_iter().enumerate() {
            for (half, expected) in halves(value).into_iter().enumerate() {
                out.push(mask.mul(row[2 * register + half].sub(expected)));
            }
        }
        out.push(mask.mul(row[PC].sub(F(boundary.pc))));
        for (offset, value) in [(GAS, boundary.gas_remaining), (CYCLES, boundary.cycles)] {
            for (half, expected) in halves(value).into_iter().enumerate() {
                out.push(mask.mul(row[offset + half].sub(expected)));
            }
        }
    }
    sources.append_residues(&mut out);
    out.extend(alu_bank_residues(&row[ALU..BRANCH], sources, alu_selectors));
    let division_workspace = division_selected.add(gcd_entry).add(gcd_work);
    out.extend(branch::bank_residues(
        &row[BRANCH..SHIFT],
        std::array::from_fn(|operand| {
            std::array::from_fn(|limb| {
                let divided = if operand == 0 {
                    row[SHIFT + division::REMAINDER + limb]
                } else {
                    row[MULTIPLY + multiply::SIGNED_SIGNED + limb]
                };
                F::ONE
                    .sub(division_workspace)
                    .mul(sources.limb(operand, limb))
                    .add(division_workspace.mul(divided))
            })
        }),
        [sources.sign(0), sources.sign(1)],
        branch_selectors,
    ));
    let shift_start = out.len();
    out.extend(shift::bank_residues(
        &row[SHIFT..RESULT],
        sources,
        shift_selectors,
    ));
    for residual in &mut out[shift_start..] {
        *residual = F::ONE
            .sub(division_workspace)
            .sub(square_selected)
            .mul(*residual);
    }
    let multiply_selected = multiply_selectors.into_iter().fold(F::ZERO, F::add);
    let prefix_start = out.len();
    bit_count::append_residues(
        &mut out,
        &row[BIT_COUNT..MULTIPLY],
        source_bits,
        count_selectors[1],
    );
    // Multiply and division rows use these cells as radix-four product digits.
    // On every old opcode and padding row the original cubic prefix equation
    // remains exact. The mask raises its degree to four, never five.
    for residual in &mut out[prefix_start..] {
        *residual = F::ONE
            .sub(multiply_selected)
            .sub(division_workspace)
            .sub(square_selected)
            .mul(*residual);
    }
    multiply::append_residues(
        &mut out,
        &row[MULTIPLY..ABSOLUTE],
        &row[BIT_COUNT..MULTIPLY],
        sources,
        multiply::Selection {
            multiply: multiply_selected,
            division: division_workspace,
            square: square_selected,
            other: F::ZERO,
            signed: division_signed.add(gcd_entry),
            success: division_selected
                .sub(division_trap)
                .add(square_selected.mul(F::ONE.sub(trap)))
                .add(gcd_divide),
            quotient: std::array::from_fn(|limb| row[SHIFT + division::QUOTIENT + limb]),
        },
    );
    division::append_residues(
        &mut out,
        &row[SHIFT..RESULT],
        &row[MULTIPLY..ABSOLUTE],
        sources,
        &row[GAS_DIGITS..GAS_DIGITS + 32],
        row[BRANCH + branch::BORROW + 3],
        division::Selection {
            active: division_selected,
            signed: division_signed,
            ceiling: ceiling_selected,
            out_of_gas: fixed[OUT_OF_GAS].mul(division_selected),
            assertion_failed: fixed[ASSERTION_FAILED].mul(division_selected),
        },
    );
    square_root::append_residues(
        &mut out,
        &row[SHIFT..RESULT],
        &row[MULTIPLY..ABSOLUTE],
        sources,
        &row[GAS_DIGITS..GAS_DIGITS + 32],
        square_selected,
        fixed[OUT_OF_GAS].mul(square_selected),
        fixed[ASSERTION_FAILED].mul(square_selected),
    );
    ceiling::append_residues(
        &mut out,
        &row[ABSOLUTE..MEAN_GAS],
        &row[SHIFT..RESULT],
        ceiling_selected,
    );
    absolute::append_residues(
        &mut out,
        &row[ABSOLUTE..MEAN_GAS],
        sources,
        &row[GAS_DIGITS..GAS_DIGITS + 32],
        absolute_selected,
        fixed[OUT_OF_GAS].mul(absolute_selected),
        fixed[ASSERTION_FAILED].mul(absolute_selected),
    );
    mean::append_residues(
        &mut out,
        &row[ABSOLUTE..MEAN_GAS],
        &row[MEAN_GAS..GCD],
        &row[ALU..BRANCH],
        sources,
        &row[GAS_DIGITS..GAS_DIGITS + 32],
        mean_selected,
        fixed[OUT_OF_GAS].mul(mean_selected),
        fixed[ASSERTION_FAILED].mul(mean_selected),
    );
    gcd::append_residues(
        &mut out,
        &row[GCD..],
        &row[SHIFT..RESULT],
        &row[MULTIPLY..ABSOLUTE],
        &row[ABSOLUTE..MEAN_GAS],
        &row[MEAN_GAS..GCD],
        sources,
        Sources::new(&next[SOURCES..ALU]),
        &row[GAS_DIGITS..GAS_DIGITS + 32],
        row[BRANCH + branch::BORROW + 3],
        gcd::Selection {
            fetched: gcd_selected,
            out_of_gas: fixed[OUT_OF_GAS],
            assertion_failed: fixed[ASSERTION_FAILED],
            entry: fixed[SLOT_ENTRY],
            work: fixed[SLOT_WORK],
            commit: fixed[SLOT_COMMIT],
        },
    );
    // Every newly introduced cell has a canonical inactive value. In particular,
    // the ABS inverse cells must not become free witness cells on other opcodes.
    out.extend(row[ABSOLUTE..MEAN_GAS].iter().map(|cell| {
        F::ONE
            .sub(absolute_selected)
            .sub(mean_selected)
            .sub(ceiling_selected)
            .sub(gcd_selected)
            .mul(*cell)
    }));
    out.extend(
        row[MEAN_GAS..GCD]
            .iter()
            .map(|cell| F::ONE.sub(mean_selected).sub(gcd_selected).mul(*cell)),
    );
    // A declared trap must belong to an explicitly constrained trapping family.
    out.push(
        trap.mul(
            F::ONE
                .sub(division_selected)
                .sub(absolute_selected)
                .sub(mean_selected)
                .sub(square_selected)
                .sub(gcd_selected),
        ),
    );
    debug_assert_eq!(out.len(), CONSTRAINT_COUNT);
    Ok(out)
}

impl ProofManagedNoteStarkAdapterV1 for ScalarSegment {
    type ProfileChallenges = ();
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"ISC1",
                proof_version: 1,
                security_lanes: 1,
                query_count: 136,
                blowup_log2: 3,
                terminal_log2: 10,
                terminal_degree_bound: 143,
                composition_degree_chunks: 4,
                minimum_trace_log2: TRACE_LOG2,
                maximum_trace_log2: TRACE_LOG2,
                maximum_trace_groups: 1,
                maximum_segment_instances: 1,
                maximum_base_columns_per_instance: NOTE_COPY_WIDTH_V1 + ROW_WIDTH,
                maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1,
                maximum_proof_bytes: 4 * 1024 * 1024,
            },
            domains: DOMAINS,
            maximum_constraint_degree: 4,
            profile_binding_label: b"ivm-scalar-segment-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"ivm-scalar-segment-relation-layout-v1",
        }
    }
    fn public_input_digest_v1(&self) -> Result<GoldilocksDigest384V1, Error> {
        self.digest()
    }
    fn trace_log2_v1(&self) -> u8 {
        TRACE_LOG2
    }
    fn base_width_v1(&self) -> usize {
        NOTE_COPY_WIDTH_V1 + ROW_WIDTH
    }
    fn profile_aux_width_v1(&self) -> usize {
        0
    }
    fn profile_fixed_width_v1(&self) -> usize {
        FIXED_WIDTH
    }
    fn profile_constraint_count_v1(&self) -> usize {
        CONSTRAINT_COUNT
    }
    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, Error> {
        Ok(NoteCopyScheduleV1 {
            policies: vec![[NoteCopyCellPolicyV1::Inactive; NOTE_COPY_WIDTH_V1]; TRACE_SIZE],
            sigma: (0..TRACE_SIZE)
                .map(|row| {
                    std::array::from_fn(|column| (row * NOTE_COPY_WIDTH_V1 + column + 1) as u32)
                })
                .collect(),
        })
    }
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, Error> {
        self.validate()?;
        Ok((0..FIXED_WIDTH)
            .map(|column| {
                (0..TRACE_SIZE)
                    .map(|row| self.fixed_row(row)[column])
                    .collect()
            })
            .collect())
    }
    fn derive_profile_challenges_v1(
        &self,
        _: &mut TransparentTranscriptV1,
        _: NoteCopyChallengesV1,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn build_profile_aux_columns_v1(
        &self,
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: NoteCopyChallengesV1,
        (): &(),
    ) -> Result<Vec<Vec<F>>, Error> {
        Ok(Vec::new())
    }
    fn profile_constraint_residues_v1(
        &self,
        current: &[F],
        next: &[F],
        _: &[F],
        _: &[F],
        fixed: &[F],
        _: NoteCopyChallengesV1,
        (): &(),
    ) -> Result<Vec<F>, Error> {
        residues(
            self,
            current
                .get(NOTE_COPY_WIDTH_V1..)
                .ok_or(Error::InvalidTrace)?,
            next.get(NOTE_COPY_WIDTH_V1..).ok_or(Error::InvalidTrace)?,
            fixed
                .get(NOTE_COPY_FIXED_WIDTH_V1..)
                .ok_or(Error::InvalidTrace)?,
        )
    }
}

#[cfg(test)]
mod tests;
