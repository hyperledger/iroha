//! Cleartext normalizer of the canonical tape: the specification oracle of the
//! normalizing lowering.
//!
//! The normalizing lowering is the mandatory way a V1 tape is evaluated on
//! ciphertexts (`specs/ram_lfe_execution_proof.md`, "Normalizing lowering").
//! This module is its plaintext definition and nothing more. It folds every run
//! of plaintext instructions into exact affine forms over the field of 257
//! elements, with every coefficient reduced, and keeps each ciphertext
//! multiplication, each `SelectEqZero` and each refresh of the canonical
//! schedule as one gate in tape order. State updates, register and lane
//! aliasing and output snapshots are resolved while folding, so the normal form
//! computes exactly what the cleartext reference computes.
//!
//! It reads the hidden tape and works on plaintext, so it is a tool for the
//! program owner and for tests. It is not constant time. A normal form has no
//! canonical encoding and enters no commitment: the function identity commits
//! the tape, and the class is decided on the tape.
//!
//! A normal form is not canonical for the function a tape computes. Plaintext
//! runs that give the same forms leave no trace, but a scaling moved across a
//! gate stays in the coefficients, and a gate nothing reads stays a gate.
//!
//! The buffers of a normal form and of one evaluation are heap allocations of
//! fixed capacity that are cleared when they drop: when a form or an
//! evaluation ends, when an error is returned and during unwinding. A class
//! refusal is returned before any buffer exists, so the only error returned
//! while a buffer holds data is an allocation failure. Scalars the compiler
//! copies while folding are not covered.
//!
//! TODO(R.3): this is a cleartext oracle. No encrypted normalizer, no fixed
//! public schedule and no proof of the lowering exist. R.3 builds them for
//! `affine.v1` and compares them with this oracle; R.7 and R.9 extend them to
//! the multiplication, selection and refresh gates.

use super::{
    HiddenRamFheInstruction, HiddenRamFheProgram, RamLfeError,
    class::{
        RAM_LFE_V1_INPUT_SLOTS, RAM_LFE_V1_MAX_INSTRUCTIONS, RAM_LFE_V1_MAX_OUTPUTS,
        RAM_LFE_V1_PLAINTEXT_MODULUS, RAM_LFE_V1_REGISTERS, RAM_LFE_V1_SELECT_BRANCH_RANK,
        RAM_LFE_V1_SELECT_CONDITION_RANK, RAM_LFE_V1_STATE_LANES, RamLfeClassReportV1,
        RamLfeClassV1, RamLfeOpcodeV1,
    },
    reference::{
        RAM_LFE_V1_TRACE_ROW_SCALARS, RamLfeInitialMemoryV1, RamLfeOrderedOutputV1,
        RamLfeReferenceInputV1, add, multiply, select_eq_zero, subtract,
    },
};
use std::{fmt, ops::Range};
use zeroize::{Zeroize as _, Zeroizing};

/// Column of the constant one in every affine form.
pub const RAM_LFE_V1_NORMAL_CONSTANT_COLUMN: usize = 0;
/// First of the 64 input-slot columns.
pub const RAM_LFE_V1_NORMAL_INPUT_COLUMN: usize = 1;
/// First of the 32 initialized-lane columns.
pub const RAM_LFE_V1_NORMAL_LANE_COLUMN: usize =
    RAM_LFE_V1_NORMAL_INPUT_COLUMN + RAM_LFE_V1_INPUT_SLOTS;
/// Columns that exist before the first gate: the constant one, the input slots
/// and the initialized lanes. Gate `g` adds column `97 + g`.
pub const RAM_LFE_V1_NORMAL_BASE_COLUMNS: usize =
    RAM_LFE_V1_NORMAL_LANE_COLUMN + RAM_LFE_V1_STATE_LANES;
/// Largest magnitude of the centered representative of a reduced coefficient.
///
/// A folded run of plaintext multiplications is one coefficient, so it
/// contributes this factor once, however many instructions the run had.
pub const RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE: u16 = (RAM_LFE_V1_PLAINTEXT_MODULUS - 1) / 2;

/// Operand forms stored for every gate; a gate of fewer operands leaves the rest zero.
const GATE_OPERANDS: usize = 3;
/// A tape has at least one output, so at most 255 instructions are gates.
const MAX_NONLINEAR_GATES: u16 = 255;
const MAX_OUTPUTS: u16 = 64;
const BASE_COLUMNS: u16 = 97;

// The narrow constants above are the class limits of the descriptor.
const _: () = {
    assert!(MAX_NONLINEAR_GATES as usize == RAM_LFE_V1_MAX_INSTRUCTIONS - 1);
    assert!(MAX_OUTPUTS as usize == RAM_LFE_V1_MAX_OUTPUTS);
    assert!(BASE_COLUMNS as usize == RAM_LFE_V1_NORMAL_BASE_COLUMNS);
    assert!(RAM_LFE_V1_TRACE_ROW_SCALARS == RAM_LFE_V1_REGISTERS + RAM_LFE_V1_STATE_LANES);
};

/// Return the centered representative of a scalar: the integer of least
/// magnitude in its residue class modulo 257, in `-128..=128`.
#[must_use]
pub const fn ram_lfe_v1_centered_scalar(scalar: u16) -> i16 {
    let residue = scalar % RAM_LFE_V1_PLAINTEXT_MODULUS;
    if residue > RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE {
        residue.cast_signed() - RAM_LFE_V1_PLAINTEXT_MODULUS.cast_signed()
    } else {
        residue.cast_signed()
    }
}

/// What the normalizing lowering does with an instruction of one opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RamLfeNormalRoleV1 {
    /// Folded into affine forms. The instruction leaves no operation of its own.
    Folded,
    /// Kept as exactly one gate, in tape order.
    Boundary,
    /// Records the affine form its register holds as the next ordered output.
    Snapshot,
}

impl RamLfeNormalRoleV1 {
    /// Role of every instruction with this opcode.
    #[must_use]
    pub const fn of(opcode: RamLfeOpcodeV1) -> Self {
        match opcode {
            RamLfeOpcodeV1::LoadInput
            | RamLfeOpcodeV1::LoadState
            | RamLfeOpcodeV1::StoreState
            | RamLfeOpcodeV1::LoadConst
            | RamLfeOpcodeV1::Add
            | RamLfeOpcodeV1::AddPlain
            | RamLfeOpcodeV1::SubPlain
            | RamLfeOpcodeV1::MulPlain => Self::Folded,
            RamLfeOpcodeV1::Mul | RamLfeOpcodeV1::SelectEqZero => Self::Boundary,
            RamLfeOpcodeV1::Output => Self::Snapshot,
        }
    }

    /// Stable name used by the specification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Folded => "folded",
            Self::Boundary => "boundary",
            Self::Snapshot => "snapshot",
        }
    }
}

impl fmt::Display for RamLfeNormalRoleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Kind of one gate of a normal form.
///
/// A gate takes affine forms over the columns that exist before it and adds
/// one column: its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RamLfeNormalGateKindV1 {
    /// One `Mul` instruction: the product of two affine forms.
    Mul,
    /// One `SelectEqZero` instruction: condition, zero branch, nonzero branch.
    SelectEqZero,
    /// One refresh of the canonical `refresh.v1` schedule: the identity on the
    /// plaintext of one affine form.
    Refresh,
}

impl RamLfeNormalGateKindV1 {
    /// Every kind, in the order of its stored code.
    pub const ALL: [Self; 3] = [Self::Mul, Self::SelectEqZero, Self::Refresh];

    /// Number of affine operand forms.
    #[must_use]
    pub const fn operand_count(self) -> usize {
        match self {
            Self::Mul => 2,
            Self::SelectEqZero => 3,
            Self::Refresh => 1,
        }
    }

    /// Ciphertext multiplications the gate stands for: one for `Mul`, ten for
    /// the complete `SelectEqZero`, none for a refresh.
    #[must_use]
    pub const fn ciphertext_multiplications(self) -> u32 {
        match self {
            Self::Mul => 1,
            Self::SelectEqZero => RAM_LFE_V1_SELECT_CONDITION_RANK as u32,
            Self::Refresh => 0,
        }
    }

    /// Stable name used by the specification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mul => "Mul",
            Self::SelectEqZero => "SelectEqZero",
            Self::Refresh => "Refresh",
        }
    }

    /// Multiplication depth the gate adds above one operand, or `None` when the
    /// result starts a new segment at depth zero.
    const fn added_depth(self, operand: usize) -> Option<u16> {
        match (self, operand) {
            (Self::Mul, _) => Some(1),
            (Self::SelectEqZero, 0) => Some(RAM_LFE_V1_SELECT_CONDITION_RANK),
            (Self::SelectEqZero, _) => Some(RAM_LFE_V1_SELECT_BRANCH_RANK),
            (Self::Refresh, _) => None,
        }
    }

    const fn code(self) -> u16 {
        match self {
            Self::Mul => 0,
            Self::SelectEqZero => 1,
            Self::Refresh => 2,
        }
    }

    const fn from_code(code: u16) -> Self {
        match code {
            0 => Self::Mul,
            1 => Self::SelectEqZero,
            _ => Self::Refresh,
        }
    }
}

impl fmt::Display for RamLfeNormalGateKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Largest normal form of one class. It is a function of the class alone.
///
/// Every tape of the class normalizes to a form within these bounds, and each
/// bound is reached by some tape of the class. In a class with nonlinear
/// gates, one tape of 255 nonlinear instructions and one output reaches every
/// bound except `outputs` at once: the nonlinear gates, the refreshes, the
/// columns, the depth and the ciphertext multiplications. Only the output
/// bound and the gate bound exclude each other, because an output and a
/// nonlinear gate are one instruction each and a tape has at most 256: a tape
/// with 64 outputs has at most 192 nonlinear gates. `affine.v1` has no gate,
/// so one tape of 64 outputs reaches its whole shape. A fixed public schedule
/// provides every gate, refresh and output slot, so it pads to all bounds
/// together; no count of a hidden tape selects a smaller shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamLfeNormalShapeV1 {
    /// `Mul` and `SelectEqZero` gates.
    pub nonlinear_gates: u16,
    /// Refresh gates.
    pub refreshes: u16,
    /// Ordered output forms.
    pub outputs: u16,
    /// Columns of the widest affine form: 97 plus one for every gate.
    pub columns: u16,
    /// Multiplication depth of any gate result, between refreshes where they exist.
    pub depth: u16,
    /// Ciphertext multiplications when every nonlinear gate is a `SelectEqZero`.
    pub ciphertext_multiplications: u32,
}

impl RamLfeNormalShapeV1 {
    /// Shape of one class.
    #[must_use]
    pub const fn of(class: RamLfeClassV1) -> Self {
        let nonlinear_gates = if class.admits(RamLfeOpcodeV1::Mul) {
            MAX_NONLINEAR_GATES
        } else {
            0
        };
        let refreshes = class.max_refreshes();
        Self {
            nonlinear_gates,
            refreshes,
            outputs: MAX_OUTPUTS,
            columns: BASE_COLUMNS + nonlinear_gates + refreshes,
            depth: class.max_rank(),
            ciphertext_multiplications: nonlinear_gates as u32
                * RamLfeNormalGateKindV1::SelectEqZero.ciphertext_multiplications(),
        }
    }

    /// Gates of both kinds.
    #[must_use]
    pub const fn gates(self) -> u16 {
        self.nonlinear_gates + self.refreshes
    }
}

/// Fixed-capacity heap buffer of secret scalars, cleared on drop.
///
/// The capacity is reserved once and never grows, so no write moves the
/// scalars and leaves a copy behind.
struct Scalars(Vec<u16>);

fn allocation_error(reason: &dyn fmt::Display) -> RamLfeError {
    super::invalid_program_error(&format!("normal form allocation failed: {reason}"))
}

/// Reserve the whole fixed capacity of one buffer of this module.
///
/// Every buffer this module owns is reserved here: those of a normal form,
/// and the column values and the final row of an evaluation. A failure here
/// is therefore the only error a normalization or an evaluation of a member
/// tape returns while an earlier buffer holds data; the buffers already
/// written clear as the error returns.
fn reserve(cells: &mut Vec<u16>, capacity: usize) -> Result<(), RamLfeError> {
    #[cfg(test)]
    if allocation_refused() {
        return Err(allocation_error(&"refused by the test"));
    }
    cells
        .try_reserve_exact(capacity)
        .map_err(|error| allocation_error(&error))
}

impl Scalars {
    fn with_capacity(capacity: usize) -> Result<Self, RamLfeError> {
        let mut cells = Vec::new();
        reserve(&mut cells, capacity)?;
        Ok(Self(cells))
    }

    fn zeroed(length: usize) -> Result<Self, RamLfeError> {
        let mut scalars = Self::with_capacity(length)?;
        scalars.0.resize(length, 0);
        Ok(scalars)
    }

    fn push(&mut self, scalar: u16) {
        assert!(self.0.len() < self.0.capacity(), "bounded normal form");
        self.0.push(scalar);
    }

    fn extend(&mut self, scalars: &[u16]) {
        assert!(
            self.0.len() + scalars.len() <= self.0.capacity(),
            "bounded normal form"
        );
        self.0.extend_from_slice(scalars);
    }
}

impl Drop for Scalars {
    fn drop(&mut self) {
        // Nothing is ever removed, so the initialized cells are every cell written.
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        observe_clear(&self.0);
    }
}

/// Dot product of an affine form with the values of its columns, modulo 257.
fn dot(form: &[u16], values: &[u16]) -> u16 {
    debug_assert!(form.len() <= values.len());
    // At most 416 terms below 2^16 each.
    let mut sum = Zeroizing::new(0_u32);
    for (&coefficient, &value) in form.iter().zip(values) {
        *sum += u32::from(coefficient) * u32::from(value);
    }
    u16::try_from(*sum % u32::from(RAM_LFE_V1_PLAINTEXT_MODULUS)).expect("residue below 257")
}

/// Normal form of one hidden program under one class.
///
/// Columns: column 0 is the constant one, columns `1..=64` are the input
/// slots, columns `65..=96` are the lanes the execution was initialized with
/// and column `97 + g` is the result of gate `g`. An affine form is one
/// coefficient in `0..=256` for each column. Gate `g` takes forms over the
/// columns before `97 + g`. Output `k` is the form its register held when the
/// `k`-th `Output` executed.
///
/// The form is private with the tape. It never prints its contents.
pub struct RamLfeNormalFormV1 {
    class: RamLfeClassV1,
    report: RamLfeClassReportV1,
    /// Scalars stored for each form: the widest form of the class.
    stride: usize,
    gates: usize,
    outputs: usize,
    depth: u16,
    kinds: Scalars,
    operands: Scalars,
    output_forms: Scalars,
    /// Final machine: the four registers followed by the 32 lanes.
    state: Scalars,
}

impl RamLfeNormalFormV1 {
    /// Class the tape was normalized under.
    #[must_use]
    pub const fn class(&self) -> RamLfeClassV1 {
        self.class
    }

    /// Class accounting of the tape, including the canonical refresh schedule.
    #[must_use]
    pub const fn report(&self) -> &RamLfeClassReportV1 {
        &self.report
    }

    /// Number of gates: one for each `Mul`, each `SelectEqZero` and each
    /// scheduled refresh, in execution order.
    #[must_use]
    pub const fn gate_count(&self) -> usize {
        self.gates
    }

    /// Number of ordered outputs.
    #[must_use]
    pub const fn output_count(&self) -> usize {
        self.outputs
    }

    /// Number of columns: 97 plus the number of gates.
    #[must_use]
    pub const fn columns(&self) -> usize {
        RAM_LFE_V1_NORMAL_BASE_COLUMNS + self.gates
    }

    /// Highest multiplication depth of any gate result, between refreshes.
    ///
    /// The depth of a column is zero for the constant, an input slot, a lane
    /// and a refresh. The depth of a form is the highest depth of a column
    /// with a nonzero coefficient. It is at most the logical rank the class
    /// accounting gives the tape, and can be lower when coefficients cancel.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Ciphertext multiplications of all gates: one for each `Mul`, ten for
    /// each `SelectEqZero`.
    #[must_use]
    pub fn ciphertext_multiplications(&self) -> u32 {
        self.kinds
            .0
            .iter()
            .map(|&code| RamLfeNormalGateKindV1::from_code(code).ciphertext_multiplications())
            .sum()
    }

    /// Kind of one gate.
    #[must_use]
    pub fn gate_kind(&self, gate: usize) -> Option<RamLfeNormalGateKindV1> {
        self.kinds
            .0
            .get(gate)
            .map(|&code| RamLfeNormalGateKindV1::from_code(code))
    }

    /// One operand of one gate: an affine form over the `97 + gate` columns
    /// that exist before the gate.
    #[must_use]
    pub fn gate_operand(&self, gate: usize, operand: usize) -> Option<&[u16]> {
        if operand >= self.gate_kind(gate)?.operand_count() {
            return None;
        }
        let start = (gate * GATE_OPERANDS + operand) * self.stride;
        self.operands
            .0
            .get(start..start + RAM_LFE_V1_NORMAL_BASE_COLUMNS + gate)
    }

    /// One ordered output: an affine form over every column.
    #[must_use]
    pub fn output_form(&self, output: usize) -> Option<&[u16]> {
        if output >= self.outputs {
            return None;
        }
        let start = output * self.stride;
        self.output_forms.0.get(start..start + self.columns())
    }

    /// The form a register holds after the last instruction.
    #[must_use]
    pub fn register_form(&self, register: usize) -> Option<&[u16]> {
        if register >= RAM_LFE_V1_REGISTERS {
            return None;
        }
        let start = register * self.stride;
        self.state.0.get(start..start + self.columns())
    }

    /// The form a state lane holds after the last instruction.
    #[must_use]
    pub fn lane_form(&self, lane: usize) -> Option<&[u16]> {
        if lane >= RAM_LFE_V1_STATE_LANES {
            return None;
        }
        let start = (RAM_LFE_V1_REGISTERS + lane) * self.stride;
        self.state.0.get(start..start + self.columns())
    }

    /// Value of every column for one execution: one, the input slots, the
    /// lanes and each gate result in order.
    fn column_values(
        &self,
        memory: &RamLfeInitialMemoryV1,
        input: &RamLfeReferenceInputV1,
    ) -> Result<Scalars, RamLfeError> {
        let mut values = Scalars::with_capacity(self.columns())?;
        values.push(1);
        values.extend(input.slots());
        values.extend(memory.lanes());
        for gate in 0..self.gates {
            let kind = RamLfeNormalGateKindV1::from_code(self.kinds.0[gate]);
            let operand = |index: usize| {
                let start = (gate * GATE_OPERANDS + index) * self.stride;
                dot(&self.operands.0[start..start + values.0.len()], &values.0)
            };
            let result = match kind {
                RamLfeNormalGateKindV1::Mul => multiply(operand(0), operand(1)),
                RamLfeNormalGateKindV1::SelectEqZero => {
                    select_eq_zero(operand(0), operand(1), operand(2))
                }
                RamLfeNormalGateKindV1::Refresh => operand(0),
            };
            values.push(result);
        }
        Ok(values)
    }

    /// Evaluate the normal form on plaintext.
    ///
    /// The result equals the output of [`super::ram_lfe_reference_execute_v1`]
    /// for the same class, tape, lanes and input. Tests compare the two.
    ///
    /// # Errors
    /// Reports an allocation failure.
    pub fn evaluate(
        &self,
        memory: &RamLfeInitialMemoryV1,
        input: &RamLfeReferenceInputV1,
    ) -> Result<RamLfeOrderedOutputV1, RamLfeError> {
        let values = self.column_values(memory, input)?;
        let mut output = Scalars::with_capacity(self.outputs)?;
        for form in self.output_forms.0.chunks_exact(self.stride) {
            output.push(dot(&form[..values.0.len()], &values.0));
        }
        RamLfeOrderedOutputV1::from_scalars(&output.0)
    }

    /// Evaluate the machine the tape leaves behind: the four registers
    /// followed by the 32 state lanes, as one row of the reference trace.
    ///
    /// The result equals the last snapshot of the reference trace for the same
    /// class, tape, lanes and input. Tests compare the two.
    ///
    /// # Errors
    /// Reports an allocation failure.
    pub fn evaluate_final_state(
        &self,
        memory: &RamLfeInitialMemoryV1,
        input: &RamLfeReferenceInputV1,
    ) -> Result<Zeroizing<Vec<u16>>, RamLfeError> {
        let values = self.column_values(memory, input)?;
        let mut row = Zeroizing::new(Vec::new());
        reserve(&mut row, RAM_LFE_V1_TRACE_ROW_SCALARS)?;
        for form in self.state.0.chunks_exact(self.stride) {
            row.push(dot(&form[..values.0.len()], &values.0));
        }
        Ok(row)
    }
}

impl fmt::Debug for RamLfeNormalFormV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE normal form]")
    }
}

impl Drop for RamLfeNormalFormV1 {
    fn drop(&mut self) {
        self.gates.zeroize();
        self.outputs.zeroize();
        self.depth.zeroize();
    }
}

/// Symbolic machine: every register and lane holds an affine form.
struct Folding {
    stride: usize,
    gates: usize,
    outputs: usize,
    depth: u16,
    /// Registers followed by lanes, `stride` scalars each.
    state: Scalars,
    /// Multiplication depth of every column.
    column_depths: Scalars,
    kinds: Scalars,
    operands: Scalars,
    output_forms: Scalars,
}

impl Folding {
    fn new(shape: RamLfeNormalShapeV1) -> Result<Self, RamLfeError> {
        let stride = usize::from(shape.columns);
        let gates = usize::from(shape.gates());
        let mut state = Scalars::zeroed(RAM_LFE_V1_TRACE_ROW_SCALARS * stride)?;
        // Registers start at zero. Lane `l` starts as its own column.
        for lane in 0..RAM_LFE_V1_STATE_LANES {
            state.0
                [(RAM_LFE_V1_REGISTERS + lane) * stride + RAM_LFE_V1_NORMAL_LANE_COLUMN + lane] = 1;
        }
        Ok(Self {
            stride,
            gates: 0,
            outputs: 0,
            depth: 0,
            state,
            column_depths: Scalars::zeroed(stride)?,
            kinds: Scalars::with_capacity(gates)?,
            operands: Scalars::with_capacity(gates * GATE_OPERANDS * stride)?,
            output_forms: Scalars::with_capacity(usize::from(shape.outputs) * stride)?,
        })
    }

    fn register(&self, register: u16) -> Range<usize> {
        let start = usize::from(register) * self.stride;
        start..start + self.stride
    }

    fn lane(&self, lane: u16) -> Range<usize> {
        let start = (RAM_LFE_V1_REGISTERS + usize::from(lane)) * self.stride;
        start..start + self.stride
    }

    /// Make a register hold exactly one column.
    fn set_column(&mut self, register: u16, column: usize) {
        let row = self.register(register);
        self.state.0[row.clone()].zeroize();
        self.state.0[row.start + column] = 1;
    }

    /// Fold a unary plaintext instruction: every source coefficient is read
    /// before the destination coefficient of the same column is written, so
    /// the destination may be the source.
    fn fold(&mut self, destination: u16, source: u16, coefficient: impl Fn(usize, u16) -> u16) {
        let (destination, source) = (
            self.register(destination).start,
            self.register(source).start,
        );
        for column in 0..self.stride {
            self.state.0[destination + column] = coefficient(column, self.state.0[source + column]);
        }
    }

    /// Multiplication depth of the form a register holds.
    fn form_depth(&self, register: u16) -> u16 {
        self.state.0[self.register(register)]
            .iter()
            .zip(&self.column_depths.0)
            .filter(|&(&coefficient, _)| coefficient != 0)
            .map(|(_, &depth)| depth)
            .max()
            .unwrap_or(0)
    }

    /// Append one gate over the forms of its operand registers and return its column.
    fn gate(&mut self, kind: RamLfeNormalGateKindV1, registers: &[u16]) -> usize {
        debug_assert_eq!(registers.len(), kind.operand_count());
        let depth = registers
            .iter()
            .enumerate()
            .filter_map(|(operand, &register)| {
                kind.added_depth(operand)
                    .map(|added| self.form_depth(register).saturating_add(added))
            })
            .max()
            .unwrap_or(0);
        for operand in 0..GATE_OPERANDS {
            match registers.get(operand) {
                Some(&register) => {
                    let row = self.register(register);
                    self.operands.extend(&self.state.0[row]);
                }
                None => {
                    for _ in 0..self.stride {
                        self.operands.push(0);
                    }
                }
            }
        }
        let column = RAM_LFE_V1_NORMAL_BASE_COLUMNS + self.gates;
        self.kinds.push(kind.code());
        self.column_depths.0[column] = depth;
        self.depth = self.depth.max(depth);
        self.gates += 1;
        column
    }

    /// Refresh a register in place: one identity gate, then the register holds
    /// the gate's column. Other copies of the form are not refreshed.
    fn refresh(&mut self, register: u16) {
        let column = self.gate(RamLfeNormalGateKindV1::Refresh, &[register]);
        self.set_column(register, column);
    }

    fn step(&mut self, instruction: HiddenRamFheInstruction) {
        use HiddenRamFheInstruction as Op;
        let scalar =
            |immediate: u64| u16::try_from(immediate).expect("structurally bounded immediate");
        match instruction {
            Op::LoadInput(destination, slot) => {
                self.set_column(
                    destination,
                    RAM_LFE_V1_NORMAL_INPUT_COLUMN + usize::from(slot),
                );
            }
            Op::LoadState(destination, lane) => {
                let (source, destination) = (self.lane(lane), self.register(destination).start);
                self.state.0.copy_within(source, destination);
            }
            Op::StoreState(lane, source) => {
                let (source, destination) = (self.register(source), self.lane(lane).start);
                self.state.0.copy_within(source, destination);
            }
            Op::LoadConst(destination, immediate) => {
                let row = self.register(destination);
                self.state.0[row.clone()].zeroize();
                self.state.0[row.start + RAM_LFE_V1_NORMAL_CONSTANT_COLUMN] = scalar(immediate);
            }
            Op::Add(destination, lhs, rhs) => {
                let (destination, lhs, rhs) = (
                    self.register(destination).start,
                    self.register(lhs).start,
                    self.register(rhs).start,
                );
                for column in 0..self.stride {
                    self.state.0[destination + column] =
                        add(self.state.0[lhs + column], self.state.0[rhs + column]);
                }
            }
            Op::AddPlain(destination, source, immediate) => {
                let immediate = scalar(immediate);
                self.fold(destination, source, |column, coefficient| {
                    if column == RAM_LFE_V1_NORMAL_CONSTANT_COLUMN {
                        add(coefficient, immediate)
                    } else {
                        coefficient
                    }
                });
            }
            Op::SubPlain(destination, source, immediate) => {
                let immediate = scalar(immediate);
                self.fold(destination, source, |column, coefficient| {
                    if column == RAM_LFE_V1_NORMAL_CONSTANT_COLUMN {
                        subtract(coefficient, immediate)
                    } else {
                        coefficient
                    }
                });
            }
            Op::MulPlain(destination, source, immediate) => {
                let immediate = scalar(immediate);
                self.fold(destination, source, |_, coefficient| {
                    multiply(coefficient, immediate)
                });
            }
            Op::Mul(destination, lhs, rhs) => {
                let column = self.gate(RamLfeNormalGateKindV1::Mul, &[lhs, rhs]);
                self.set_column(destination, column);
            }
            Op::SelectEqZero(destination, condition, if_zero, if_non_zero) => {
                let column = self.gate(
                    RamLfeNormalGateKindV1::SelectEqZero,
                    &[condition, if_zero, if_non_zero],
                );
                self.set_column(destination, column);
            }
            Op::Output(source) => {
                let row = self.register(source);
                self.output_forms.extend(&self.state.0[row]);
                self.outputs += 1;
            }
        }
    }

    fn finish(mut self, class: RamLfeClassV1, report: RamLfeClassReportV1) -> RamLfeNormalFormV1 {
        let take = |scalars: &mut Scalars| std::mem::replace(scalars, Scalars(Vec::new()));
        RamLfeNormalFormV1 {
            class,
            report,
            stride: self.stride,
            gates: self.gates,
            outputs: self.outputs,
            depth: self.depth,
            kinds: take(&mut self.kinds),
            operands: take(&mut self.operands),
            output_forms: take(&mut self.output_forms),
            state: take(&mut self.state),
        }
    }
}

impl Drop for Folding {
    fn drop(&mut self) {
        self.gates.zeroize();
        self.outputs.zeroize();
        self.depth.zeroize();
    }
}

// TODO(R.3): only tests call this oracle. No encrypted evaluator follows a normal
// form and no relation proves one. R.3 compares its normalized affine evaluation
// with it; R.7 and R.9 extend the comparison to the gates.
/// Normalize a hidden program of a declared class on plaintext.
///
/// The program must be a member of `class`; the class is decided on the tape
/// and normalization never changes it. The refresh gates are the canonical
/// schedule of the class accounting: each scheduled register is refreshed in
/// place immediately before the instruction that required it.
///
/// ```
/// use iroha_crypto::{
///     HiddenRamFheInstruction as Op, HiddenRamFheProgram, RamLfeClassV1, RamLfeInitialMemoryV1,
///     RamLfeReferenceInputV1, ram_lfe_reference_execute_v1, ram_lfe_reference_normalize_v1,
/// };
/// let mut tape = HiddenRamFheProgram::builder()?;
/// tape.push(Op::LoadInput(0, 1))?;
/// for _ in 0..100 {
///     tape.push(Op::MulPlain(0, 0, 128))?;
/// }
/// tape.push(Op::Output(0))?;
/// let program = tape.finish()?;
/// let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Affine, &program)?;
/// // One hundred plaintext multiplications are one coefficient of one output.
/// assert_eq!((normal.gate_count(), normal.output_count()), (0, 1));
/// let form = normal.output_form(0).expect("one output");
/// assert_eq!(form.iter().filter(|&&coefficient| coefficient != 0).count(), 1);
/// // The normal form computes what the reference computes.
/// let lanes = RamLfeInitialMemoryV1::from_lanes(&[0; 32])?;
/// let input = RamLfeReferenceInputV1::from_bytes(b"A")?;
/// let reference =
///     ram_lfe_reference_execute_v1(RamLfeClassV1::Affine, &program, &lanes, &input)?;
/// assert_eq!(
///     normal.evaluate(&lanes, &input)?.scalars(),
///     reference.output().scalars()
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// Returns the structural or class-membership error for the program, and
/// reports an allocation failure.
pub fn ram_lfe_reference_normalize_v1(
    class: RamLfeClassV1,
    program: &HiddenRamFheProgram,
) -> Result<RamLfeNormalFormV1, RamLfeError> {
    let report = class.membership(program)?;
    let shape = RamLfeNormalShapeV1::of(class);
    // Flat `(instruction, register)` pairs of the canonical schedule.
    let mut schedule = Scalars::with_capacity(usize::from(shape.refreshes) * 2)?;
    for point in report.refresh_points() {
        schedule.push(point.instruction);
        schedule.push(point.register);
    }
    let mut folding = Folding::new(shape)?;
    let mut pending = schedule.0.chunks_exact(2).peekable();
    for (index, instruction) in program.instructions().enumerate() {
        while let Some(point) = pending.next_if(|point| usize::from(point[0]) == index) {
            folding.refresh(point[1]);
        }
        folding.step(instruction);
    }
    let unplaced = pending.count();
    debug_assert_eq!(unplaced, 0, "every scheduled refresh is placed");
    debug_assert_eq!(folding.outputs, usize::from(report.output_count()));
    Ok(folding.finish(class, report))
}

#[cfg(test)]
thread_local! {
    static CLEARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Reservations still granted before one is refused; `None` refuses none.
    static GRANTED_BEFORE_REFUSAL: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Make this thread refuse one reservation of [`reserve`]: the one that
/// follows `granted` successful ones. The refusal disarms itself.
#[cfg(test)]
fn refuse_allocation_after(granted: usize) {
    GRANTED_BEFORE_REFUSAL.with(|remaining| remaining.set(Some(granted)));
}

/// Whether the reservation being made is the one a test asked to refuse.
#[cfg(test)]
fn allocation_refused() -> bool {
    GRANTED_BEFORE_REFUSAL.with(|remaining| match remaining.get() {
        Some(0) => {
            remaining.set(None);
            true
        }
        Some(granted) => {
            remaining.set(Some(granted - 1));
            false
        }
        None => false,
    })
}

/// Record that a buffer dropped with every scalar it ever held cleared.
#[cfg(test)]
fn observe_clear(scalars: &[u16]) {
    assert!(
        scalars.iter().all(|&scalar| scalar == 0),
        "a normal-form buffer dropped with a nonzero scalar"
    );
    CLEARED.with(|count| count.set(count.get() + scalars.len()));
}

/// Number of scalars this thread has observed cleared at drop.
#[cfg(test)]
fn cleared_scalars() -> usize {
    CLEARED.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "normal_form_tests.rs"]
mod tests;
