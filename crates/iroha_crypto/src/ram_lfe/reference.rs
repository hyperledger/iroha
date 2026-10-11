//! Cleartext reference interpreter for the canonical eleven-instruction tape.
//!
//! This is the exact plaintext meaning of a hidden program: the oracle an
//! encrypted evaluator and an execution relation are compared against. It works
//! on plaintext, so it is a tool for the program owner and for tests. An
//! evaluator never holds the plaintext input and never runs it on client data.
//! It is not constant time.
//!
//! The interpreter executes a tape instruction by instruction. The normalizing
//! lowering does not: its plaintext definition is the sibling `normal_form`
//! module, which shares the field arithmetic and the selection formula below
//! and is tested for exact equality with this interpreter.
//!
//! Registers and state lanes are created inside each call and dropped at its
//! end. No call receives state from an earlier call.
//!
//! The input, the initialized lanes and the machine state each live in one
//! heap allocation that is cleared on drop, on an error return and during
//! unwinding. Scalars the compiler copies while executing an instruction are
//! not covered.

use super::{
    HiddenRamFheInstruction, HiddenRamFheProgram, RamLfeError,
    canonical::{
        RamLfeAssociatedDataHashV1, RamLfeFunctionIdV1, RamLfeFunctionIdentityV1,
        RamLfeProgramKeyV1,
    },
    class::{
        RAM_LFE_V1_INPUT_SLOTS, RAM_LFE_V1_MAX_INPUT_BYTES, RAM_LFE_V1_MAX_INSTRUCTIONS,
        RAM_LFE_V1_MAX_OUTPUTS, RAM_LFE_V1_PLAINTEXT_MODULUS, RAM_LFE_V1_REGISTERS,
        RAM_LFE_V1_STATE_LANES, RamLfeClassReportV1, RamLfeClassV1,
    },
    clearing::ClearingArray,
    initialization,
};
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

const MODULUS: u32 = RAM_LFE_V1_PLAINTEXT_MODULUS as u32;
/// Scalars in one trace row: registers followed by state lanes.
pub const RAM_LFE_V1_TRACE_ROW_SCALARS: usize = RAM_LFE_V1_REGISTERS + RAM_LFE_V1_STATE_LANES;

fn invalid(message: &'static str) -> RamLfeError {
    RamLfeError::InvalidCanonicalValue(message)
}

fn canonical_scalar(value: u16) -> bool {
    value < RAM_LFE_V1_PLAINTEXT_MODULUS
}

/// Admitted plaintext input: a byte string of at most 63 bytes.
///
/// Slot 0 is the byte length, slots `1..=length` are the bytes and every other
/// slot is zero. The value 256 is never a valid byte slot.
///
/// The slots live in one heap allocation that is cleared on drop.
pub struct RamLfeReferenceInputV1(ClearingArray<u16, RAM_LFE_V1_INPUT_SLOTS>);

impl RamLfeReferenceInputV1 {
    /// Encode an input byte string into its 64 scalar slots.
    ///
    /// # Errors
    /// Rejects more than 63 bytes.
    pub fn from_bytes(input: &[u8]) -> Result<Self, RamLfeError> {
        if input.len() > RAM_LFE_V1_MAX_INPUT_BYTES {
            return Err(invalid("input exceeds 63 bytes"));
        }
        let mut slots = ClearingArray::zeroed();
        slots[0] = u16::try_from(input.len()).expect("bounded input length");
        for (slot, byte) in slots[1..].iter_mut().zip(input) {
            *slot = u16::from(*byte);
        }
        Ok(Self(slots))
    }

    /// Validate already encoded input slots.
    ///
    /// # Errors
    /// Rejects a slot count other than 64, a length above 63, a byte slot above
    /// 255 and a nonzero slot after the declared length.
    pub fn from_slots(slots: &[u16]) -> Result<Self, RamLfeError> {
        let slots: &[u16; RAM_LFE_V1_INPUT_SLOTS] = slots
            .try_into()
            .map_err(|_| invalid("input requires exactly 64 slots"))?;
        let length = usize::from(slots[0]);
        if length > RAM_LFE_V1_MAX_INPUT_BYTES {
            return Err(invalid("input length slot exceeds 63"));
        }
        if slots[1..=length].iter().any(|&slot| slot > 255) {
            return Err(invalid("input byte slot exceeds 255"));
        }
        if slots[length + 1..].iter().any(|&slot| slot != 0) {
            return Err(invalid("input slot after the declared length is not zero"));
        }
        Ok(Self(ClearingArray::copy_of(slots)))
    }

    /// Use 64 arbitrary scalars of the field as the input slots.
    ///
    /// This is not an admitted input. It exists so tests can compare the
    /// normal form with this interpreter on every slot vector of the field,
    /// which no public constructor admits.
    #[cfg(test)]
    pub(super) fn from_field_slots(slots: &[u16; RAM_LFE_V1_INPUT_SLOTS]) -> Self {
        assert!(
            slots.iter().copied().all(canonical_scalar),
            "input slot exceeds 256"
        );
        Self(ClearingArray::copy_of(slots))
    }

    /// Borrow the 64 scalar slots.
    #[must_use]
    pub fn slots(&self) -> &[u16; RAM_LFE_V1_INPUT_SLOTS] {
        &self.0
    }
}

impl fmt::Debug for RamLfeReferenceInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE reference input]")
    }
}

/// State lanes initialized for exactly one execution.
///
/// The lanes live in one heap allocation that is cleared on drop. A clone is a
/// second allocation with its own clearing. Equality is constant time.
#[derive(Clone, PartialEq, Eq)]
pub struct RamLfeInitialMemoryV1(ClearingArray<u16, RAM_LFE_V1_STATE_LANES>);

impl RamLfeInitialMemoryV1 {
    /// Derive the canonical lanes for one execution.
    ///
    /// The lanes depend on the program key, the stable function identity and
    /// the associated data. They do not depend on the policy, on any encryption
    /// key or on anything an earlier execution stored.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn derive(
        key: &RamLfeProgramKeyV1,
        function: RamLfeFunctionIdV1,
        associated_data: RamLfeAssociatedDataHashV1,
    ) -> Result<Self, RamLfeError> {
        let mut lanes = ClearingArray::zeroed();
        initialization::derive_lanes_v1(
            key.expose(),
            *function.as_hash(),
            *associated_data.as_hash(),
            &mut lanes,
        )?;
        Ok(Self(lanes))
    }

    /// Use explicit lanes as an oracle vector.
    ///
    /// This is for differential tests of an evaluator or relation against fixed
    /// lanes. It is not a way to carry state from one execution into another.
    ///
    /// # Errors
    /// Rejects a lane count other than 32 and a lane above 256.
    pub fn from_lanes(lanes: &[u16]) -> Result<Self, RamLfeError> {
        let lanes: &[u16; RAM_LFE_V1_STATE_LANES] = lanes
            .try_into()
            .map_err(|_| invalid("memory requires exactly 32 lanes"))?;
        if !lanes.iter().copied().all(canonical_scalar) {
            return Err(invalid("memory lane exceeds 256"));
        }
        Ok(Self(ClearingArray::copy_of(lanes)))
    }

    /// Borrow the 32 initialized lanes.
    #[must_use]
    pub fn lanes(&self) -> &[u16; RAM_LFE_V1_STATE_LANES] {
        &self.0
    }
}

impl fmt::Debug for RamLfeInitialMemoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE initial memory]")
    }
}

/// Ordered plaintext output: 1..=64 scalars in emission order.
///
/// An output is a scalar in `0..=256`, not a byte. The value 256 is never truncated.
#[derive(Clone, PartialEq, Eq)]
pub struct RamLfeOrderedOutputV1(Zeroizing<Vec<u16>>);

impl RamLfeOrderedOutputV1 {
    /// Validate an ordered output, for example one recovered by an opener.
    ///
    /// # Errors
    /// Rejects an empty output, more than 64 scalars and a scalar above 256.
    pub fn from_scalars(scalars: &[u16]) -> Result<Self, RamLfeError> {
        if scalars.is_empty() || scalars.len() > RAM_LFE_V1_MAX_OUTPUTS {
            return Err(invalid("output requires 1..=64 scalars"));
        }
        if !scalars.iter().copied().all(canonical_scalar) {
            return Err(invalid("output scalar exceeds 256"));
        }
        let mut owned = Zeroizing::new(Vec::with_capacity(scalars.len()));
        owned.extend_from_slice(scalars);
        Ok(Self(owned))
    }

    /// Borrow the scalars in emission order.
    #[must_use]
    pub fn scalars(&self) -> &[u16] {
        &self.0
    }

    /// The 64 output slots an opening commits: the scalars in emission order
    /// followed by zeros.
    ///
    /// The encrypted evaluation pads the output to the 64 slots of the class
    /// maximum, and an opener never holds the tape, so it cannot tell a
    /// trailing zero the tape emitted from padding. Every V1 opening therefore
    /// commits these 64 slots, and the ordered-output frame of an opening has
    /// `output_count` 64. The number of scalars the tape emitted is conveyed to
    /// nobody.
    ///
    /// This is an acceptance rule for openings, not an invariant of this type:
    /// the cleartext reference keeps exactly the scalars the tape emitted, and
    /// a differential check compares an opened output with the reference
    /// output padded by this function.
    // TODO(R.8): nothing enforces the rule yet. The output commitment hides the
    // count from validators, so the decryption proof of R.8 must bind these 64
    // slots to the output ciphertext, to the output commitment and to the
    // output component of the identifier-PRF derivation.
    #[must_use]
    pub fn padded_for_opening(&self) -> Self {
        let mut slots = Zeroizing::new(Vec::with_capacity(RAM_LFE_V1_MAX_OUTPUTS));
        slots.extend_from_slice(&self.0);
        slots.resize(RAM_LFE_V1_MAX_OUTPUTS, 0);
        Self(slots)
    }
}

impl fmt::Debug for RamLfeOrderedOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE ordered output]")
    }
}

/// Private plaintext snapshots of one reference execution.
///
/// Row zero is the initialized machine. Row `i + 1` follows instruction `i`.
/// Each row holds the four registers followed by the 32 state lanes.
pub struct RamLfeReferenceTraceV1 {
    snapshots: Zeroizing<Vec<u16>>,
    steps: usize,
}

impl RamLfeReferenceTraceV1 {
    fn new() -> Self {
        Self {
            snapshots: Zeroizing::new(Vec::with_capacity(
                (RAM_LFE_V1_MAX_INSTRUCTIONS + 1) * RAM_LFE_V1_TRACE_ROW_SCALARS,
            )),
            steps: 0,
        }
    }

    fn record(&mut self, machine: &Machine<'_>, executed: bool) {
        self.snapshots
            .extend_from_slice(machine.registers.as_slice());
        self.snapshots.extend_from_slice(machine.lanes.as_slice());
        self.steps += usize::from(executed);
    }

    /// Number of instructions executed.
    #[must_use]
    pub const fn step_count(&self) -> usize {
        self.steps
    }

    /// Borrow one row: four registers followed by 32 state lanes.
    #[must_use]
    pub fn snapshot(&self, row: usize) -> Option<&[u16]> {
        if row > self.steps {
            return None;
        }
        let start = row.checked_mul(RAM_LFE_V1_TRACE_ROW_SCALARS)?;
        self.snapshots
            .get(start..start.checked_add(RAM_LFE_V1_TRACE_ROW_SCALARS)?)
    }
}

impl fmt::Debug for RamLfeReferenceTraceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE reference trace]")
    }
}

impl Drop for RamLfeReferenceTraceV1 {
    fn drop(&mut self) {
        self.steps.zeroize();
    }
}

/// Result of one cleartext reference execution.
#[derive(Debug)]
pub struct RamLfeReferenceExecutionV1 {
    output: RamLfeOrderedOutputV1,
    initial_memory: RamLfeInitialMemoryV1,
    report: RamLfeClassReportV1,
    trace: RamLfeReferenceTraceV1,
}

impl RamLfeReferenceExecutionV1 {
    /// Ordered plaintext output.
    #[must_use]
    pub const fn output(&self) -> &RamLfeOrderedOutputV1 {
        &self.output
    }

    /// State lanes this execution was initialized with.
    #[must_use]
    pub const fn initial_memory(&self) -> &RamLfeInitialMemoryV1 {
        &self.initial_memory
    }

    /// Class accounting, including the canonical refresh schedule.
    #[must_use]
    pub const fn report(&self) -> &RamLfeClassReportV1 {
        &self.report
    }

    /// Private per-instruction plaintext snapshots.
    #[must_use]
    pub const fn trace(&self) -> &RamLfeReferenceTraceV1 {
        &self.trace
    }
}

struct Machine<'a> {
    input: &'a [u16; RAM_LFE_V1_INPUT_SLOTS],
    registers: ClearingArray<u16, RAM_LFE_V1_REGISTERS>,
    lanes: ClearingArray<u16, RAM_LFE_V1_STATE_LANES>,
    output: Zeroizing<Vec<u16>>,
}

fn reduce(value: u32) -> u16 {
    u16::try_from(value % MODULUS).expect("residue below 257")
}

pub(super) fn add(lhs: u16, rhs: u16) -> u16 {
    reduce(u32::from(lhs) + u32::from(rhs))
}

pub(super) fn subtract(lhs: u16, rhs: u16) -> u16 {
    reduce(u32::from(lhs) + MODULUS - u32::from(rhs) % MODULUS)
}

pub(super) fn multiply(lhs: u16, rhs: u16) -> u16 {
    reduce(u32::from(lhs) * u32::from(rhs))
}

/// `nonzero + (1 - condition^256) * (zero - nonzero)` with the tape's own schedule:
/// eight squarings, one multiplication by one and one selection multiplication.
pub(super) fn select_eq_zero(condition: u16, if_zero: u16, if_non_zero: u16) -> u16 {
    let mut power = condition;
    for _ in 0..8 {
        power = multiply(power, power);
    }
    let power = multiply(1, power);
    let indicator = subtract(1, power);
    add(
        if_non_zero,
        multiply(indicator, subtract(if_zero, if_non_zero)),
    )
}

impl Machine<'_> {
    fn register(&self, index: u16) -> u16 {
        self.registers[usize::from(index)]
    }

    // Every source is read before the destination is written, so a destination
    // may alias any source.
    fn step(&mut self, instruction: HiddenRamFheInstruction) {
        use HiddenRamFheInstruction as Op;
        let (destination, value) = match instruction {
            Op::LoadInput(destination, slot) => (destination, self.input[usize::from(slot)]),
            Op::LoadState(destination, lane) => (destination, self.lanes[usize::from(lane)]),
            Op::StoreState(lane, source) => {
                self.lanes[usize::from(lane)] = self.register(source);
                return;
            }
            Op::LoadConst(destination, immediate) => (
                destination,
                u16::try_from(immediate).expect("structurally bounded immediate"),
            ),
            Op::Add(destination, lhs, rhs) => {
                (destination, add(self.register(lhs), self.register(rhs)))
            }
            Op::AddPlain(destination, source, immediate) => (
                destination,
                add(
                    self.register(source),
                    u16::try_from(immediate).expect("structurally bounded immediate"),
                ),
            ),
            Op::SubPlain(destination, source, immediate) => (
                destination,
                subtract(
                    self.register(source),
                    u16::try_from(immediate).expect("structurally bounded immediate"),
                ),
            ),
            Op::MulPlain(destination, source, immediate) => (
                destination,
                multiply(
                    self.register(source),
                    u16::try_from(immediate).expect("structurally bounded immediate"),
                ),
            ),
            Op::Mul(destination, lhs, rhs) => (
                destination,
                multiply(self.register(lhs), self.register(rhs)),
            ),
            Op::SelectEqZero(destination, condition, if_zero, if_non_zero) => (
                destination,
                select_eq_zero(
                    self.register(condition),
                    self.register(if_zero),
                    self.register(if_non_zero),
                ),
            ),
            Op::Output(source) => {
                let value = self.register(source);
                self.output.push(value);
                return;
            }
        };
        self.registers[usize::from(destination)] = value;
    }
}

// TODO(R.3, R.12): only tests call this oracle. No execution relation (R.3) and no
// encrypted evaluator (R.12) is compared with it yet.
/// Execute a hidden program on plaintext with explicit initialized lanes.
///
/// The program must be a member of `class`. Registers start at zero and the
/// lanes start at `memory` for this call only.
///
/// # Errors
/// Returns the structural or class-membership error for the program.
pub fn ram_lfe_reference_execute_v1(
    class: RamLfeClassV1,
    program: &HiddenRamFheProgram,
    memory: &RamLfeInitialMemoryV1,
    input: &RamLfeReferenceInputV1,
) -> Result<RamLfeReferenceExecutionV1, RamLfeError> {
    let report = class.membership(program)?;
    let mut machine = Machine {
        input: input.slots(),
        registers: ClearingArray::zeroed(),
        lanes: ClearingArray::copy_of(memory.lanes()),
        output: Zeroizing::new(Vec::with_capacity(RAM_LFE_V1_MAX_OUTPUTS)),
    };
    let mut trace = RamLfeReferenceTraceV1::new();
    trace.record(&machine, false);
    for instruction in program.instructions() {
        machine.step(instruction);
        trace.record(&machine, true);
    }
    let output = RamLfeOrderedOutputV1(std::mem::take(&mut machine.output));
    debug_assert_eq!(output.scalars().len(), usize::from(report.output_count()));
    Ok(RamLfeReferenceExecutionV1 {
        output,
        initial_memory: memory.clone(),
        report,
        trace,
    })
}

/// Evaluate a committed hidden function on plaintext.
///
/// The program key and program must open `function`. The state lanes are
/// derived for this call from the program key, the function identity and the
/// associated data, so two calls with the same arguments are identical and no
/// call observes what another one stored.
///
/// # Errors
/// Returns [`RamLfeError::CommitmentMismatch`] when the key and program do not
/// open the identity, and the class, associated-data or encoding error otherwise.
pub fn ram_lfe_reference_evaluate_v1(
    function: &RamLfeFunctionIdentityV1,
    key: &RamLfeProgramKeyV1,
    program: &HiddenRamFheProgram,
    associated_data: &[u8],
    input: &RamLfeReferenceInputV1,
) -> Result<RamLfeReferenceExecutionV1, RamLfeError> {
    function.verify_opening(key, program)?;
    let memory = RamLfeInitialMemoryV1::derive(
        key,
        function.id()?,
        RamLfeAssociatedDataHashV1::commit(associated_data)?,
    )?;
    ram_lfe_reference_execute_v1(function.class, program, &memory, input)
}

#[cfg(test)]
#[path = "reference_tests.rs"]
mod tests;
