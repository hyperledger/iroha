//! The costing harness: the eleven V1 tape instructions lowered onto RNS-BGV.
//!
//! One lowering, [`Machine`], runs over two back ends:
//!
//! - [`Planned`] moves public shapes only (level, components, noise bound)
//!   through the `plan_*` methods of the profile. It needs no key and no
//!   ciphertext, so it runs a maximum-shape tape on a full-size profile in
//!   milliseconds.
//! - [`Encrypted`] moves real ciphertexts through the homomorphic operations.
//!
//! Because the evaluator takes the shape of every result from the same
//! `plan_*` methods, both back ends make the same level decisions and end
//! with the same bounds; `tests/bgv_tape_plan.rs` checks that instruction by
//! instruction, and checks the decrypted registers against [`Cleartext`].
//!
//! The machine also keeps the [`Ledger`]: operation counts and model work
//! units per opcode (from [`CostModel`]) and the bytes of the live buffers.
//!
//! # The lowering
//!
//! Every register and state lane holds one scalar broadcast to all slots.
//! Registers start as the noiseless embedding of zero and lanes as the
//! noiseless embedding of their initial scalars, at the top level.
//!
//! | Instruction | Lowering |
//! | --- | --- |
//! | `LoadInput(dst, j)` | multiply the packed input by the idempotent of slot `j`, then for each broadcast element apply the automorphism and add |
//! | `LoadState`, `StoreState` | copy |
//! | `LoadConst(dst, v)` | the noiseless embedding of `v` at the top level |
//! | `Add` | align, add |
//! | `AddPlain`, `SubPlain` | add or subtract the constant polynomial |
//! | `MulPlain` | multiply by the constant polynomial |
//! | `Mul` | lowered product (below) |
//! | `SelectEqZero(dst, c, z, n)` | eight lowered squarings of `c`, a lowered product with the embedded one, `indicator = 1 - c^256`, `delta = z - n`, `dst = n + indicator * delta` |
//! | `Output(src)` | multiply by the idempotent of the next output slot and add to the accumulator |
//! | end of tape | multiply the accumulator by the mask that zeroes every unused output slot |
//!
//! # Level policy
//!
//! Lazy: a value stays at its level until an operation needs otherwise.
//!
//! - **Align.** A binary operation switches the operand at the higher level
//!   down to the level of the other.
//! - **Lowered product.** After aligning, both operands are switched down one
//!   prime at a time while [`BgvProfile::plan_lower_multiplication`] says that
//!   leaves more capacity above the product; a squaring switches its operand
//!   once.
//!
//! A linear operation never gains capacity from a modulus switch (the bound
//! and the capacity shrink together and the rounding term is added), so for
//! chains of linear operations this policy is the one that fits the longest
//! chain. It keeps values at high levels, which makes the charged work an
//! upper estimate. It is the costing policy of this harness, not a schedule
//! any consumer has adopted: a hidden-program evaluation needs levels that do
//! not depend on the hidden tape, which is the consumers' design.
use iroha_fhe::{
    bgv::{
        BgvError, BgvProfile, Ciphertext, CiphertextShape, EvaluationKeys, Plaintext, SlotEncoding,
        cost::CostModel,
    },
    natural::Natural,
};

/// Registers of the V1 machine (`RAM_LFE_V1_REGISTERS`).
pub const REGISTERS: usize = 4;
/// State lanes of the V1 machine (`RAM_LFE_V1_STATE_LANES`).
pub const STATE_LANES: usize = 32;
/// Input slots of the V1 machine (`RAM_LFE_V1_INPUT_SLOTS`).
pub const INPUT_SLOTS: usize = 64;
/// Largest number of tape instructions (`RAM_LFE_V1_MAX_INSTRUCTIONS`).
pub const MAX_INSTRUCTIONS: usize = 256;
/// Largest number of ordered outputs (`RAM_LFE_V1_MAX_OUTPUTS`).
pub const MAX_OUTPUTS: usize = 64;
/// Largest logical rank of a `bounded.v1` value (`RAM_LFE_V1_BOUNDED_MAX_RANK`).
pub const BOUNDED_MAX_RANK: usize = 16;
/// Squarings of the equality test: `x^256` over the field of 257 elements.
pub const SELECT_SQUARINGS: usize = 8;
/// Ciphertext multiplications of one `SelectEqZero` (`RAM_LFE_V1_SELECT_CONDITION_RANK`).
pub const SELECT_MULTIPLICATIONS: usize = SELECT_SQUARINGS + 2;

/// One tape instruction; operands are register, lane and slot indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// `dst = input[slot]`.
    LoadInput { dst: usize, slot: usize },
    /// `dst = state[lane]`.
    LoadState { dst: usize, lane: usize },
    /// `state[lane] = src`.
    StoreState { lane: usize, src: usize },
    /// `dst = value`.
    LoadConst { dst: usize, value: u64 },
    /// `dst = lhs + rhs`.
    Add { dst: usize, lhs: usize, rhs: usize },
    /// `dst = src + value`.
    AddPlain { dst: usize, src: usize, value: u64 },
    /// `dst = src - value`.
    SubPlain { dst: usize, src: usize, value: u64 },
    /// `dst = src * value`.
    MulPlain { dst: usize, src: usize, value: u64 },
    /// `dst = lhs * rhs`.
    Mul { dst: usize, lhs: usize, rhs: usize },
    /// `dst = nonzero + (1 - cond^256) * (zero - nonzero)`.
    SelectEqZero {
        dst: usize,
        cond: usize,
        zero: usize,
        nonzero: usize,
    },
    /// Append `src` to the ordered output.
    Output { src: usize },
}

/// The eleven opcodes in tag order, with the names of the V1 semantics descriptor.
pub const OPCODE_NAMES: [&str; 11] = [
    "LoadInput",
    "LoadState",
    "StoreState",
    "LoadConst",
    "Add",
    "AddPlain",
    "SubPlain",
    "MulPlain",
    "Mul",
    "SelectEqZero",
    "Output",
];

impl Instruction {
    /// The canonical tape tag of the opcode.
    pub const fn tag(&self) -> usize {
        match self {
            Self::LoadInput { .. } => 0,
            Self::LoadState { .. } => 1,
            Self::StoreState { .. } => 2,
            Self::LoadConst { .. } => 3,
            Self::Add { .. } => 4,
            Self::AddPlain { .. } => 5,
            Self::SubPlain { .. } => 6,
            Self::MulPlain { .. } => 7,
            Self::Mul { .. } => 8,
            Self::SelectEqZero { .. } => 9,
            Self::Output { .. } => 10,
        }
    }

    /// Whether `affine.v1` admits the opcode: everything but `Mul` and `SelectEqZero`.
    pub const fn is_affine(&self) -> bool {
        !matches!(self, Self::Mul { .. } | Self::SelectEqZero { .. })
    }
}

/// The cleartext V1 machine over the field of 257 elements.
///
/// Written from the V1 plaintext-semantics descriptor; it shares no code with
/// the lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cleartext {
    /// The packed input scalars; a slot beyond them reads zero.
    pub input: Vec<u64>,
    /// The four registers.
    pub registers: [u64; REGISTERS],
    /// The 32 state lanes.
    pub state: [u64; STATE_LANES],
    /// The ordered outputs so far.
    pub outputs: Vec<u64>,
}

impl Cleartext {
    /// A machine with zero registers and the given initial lane scalars.
    pub fn new(input: &[u64], initial_state: &[u64]) -> Self {
        let mut state = [0_u64; STATE_LANES];
        state[..initial_state.len()].copy_from_slice(initial_state);
        Self {
            input: input.to_vec(),
            registers: [0; REGISTERS],
            state,
            outputs: Vec::new(),
        }
    }

    /// Execute one instruction.
    pub fn step(&mut self, instruction: Instruction) {
        const T: u64 = 257;
        let registers = &mut self.registers;
        match instruction {
            Instruction::LoadInput { dst, slot } => {
                registers[dst] = self.input.get(slot).copied().unwrap_or(0);
            }
            Instruction::LoadState { dst, lane } => registers[dst] = self.state[lane],
            Instruction::StoreState { lane, src } => self.state[lane] = registers[src],
            Instruction::LoadConst { dst, value } => registers[dst] = value % T,
            Instruction::Add { dst, lhs, rhs } => {
                registers[dst] = (registers[lhs] + registers[rhs]) % T;
            }
            Instruction::AddPlain { dst, src, value } => {
                registers[dst] = (registers[src] + value) % T;
            }
            Instruction::SubPlain { dst, src, value } => {
                registers[dst] = (registers[src] + T - value % T) % T;
            }
            Instruction::MulPlain { dst, src, value } => {
                registers[dst] = registers[src] * (value % T) % T;
            }
            Instruction::Mul { dst, lhs, rhs } => {
                registers[dst] = registers[lhs] * registers[rhs] % T;
            }
            Instruction::SelectEqZero {
                dst,
                cond,
                zero,
                nonzero,
            } => {
                registers[dst] = if registers[cond] == 0 {
                    registers[zero]
                } else {
                    registers[nonzero]
                };
            }
            Instruction::Output { src } => self.outputs.push(registers[src]),
        }
    }
}

/// The largest logical rank a tape reaches, by the rank rules of the V1 descriptor.
pub fn peak_rank(tape: &[Instruction]) -> usize {
    let mut registers = [0_usize; REGISTERS];
    let mut state = [0_usize; STATE_LANES];
    let mut peak = 0;
    for instruction in tape {
        match *instruction {
            Instruction::LoadInput { dst, .. } | Instruction::LoadConst { dst, .. } => {
                registers[dst] = 0;
            }
            Instruction::LoadState { dst, lane } => registers[dst] = state[lane],
            Instruction::StoreState { lane, src } => state[lane] = registers[src],
            Instruction::Add { dst, lhs, rhs } => {
                registers[dst] = registers[lhs].max(registers[rhs]);
            }
            Instruction::AddPlain { dst, src, .. }
            | Instruction::SubPlain { dst, src, .. }
            | Instruction::MulPlain { dst, src, .. } => registers[dst] = registers[src],
            Instruction::Mul { dst, lhs, rhs } => {
                registers[dst] = registers[lhs].max(registers[rhs]) + 1;
            }
            Instruction::SelectEqZero {
                dst,
                cond,
                zero,
                nonzero,
            } => {
                registers[dst] = (registers[cond] + SELECT_MULTIPLICATIONS)
                    .max(registers[zero] + 1)
                    .max(registers[nonzero] + 1);
            }
            Instruction::Output { .. } => {}
        }
        peak = peak.max(registers.iter().copied().max().unwrap_or(0));
    }
    peak
}

/// What the lowering needs from a representation of ciphertexts.
pub trait Backend {
    /// A ciphertext, or its public shape.
    type Value: Clone;

    /// The profile.
    fn profile(&self) -> &BgvProfile;
    /// The public shape of a value.
    fn shape(&self, value: &Self::Value) -> CiphertextShape;
    /// The encrypted packed input, fresh at the top level.
    fn input(&mut self) -> Result<Self::Value, BgvError>;
    /// The noiseless embedding of the scalar `value` in every slot, at `level`.
    fn constant(&mut self, value: u64, level: usize) -> Result<Self::Value, BgvError>;
    /// `lhs + rhs` at one level.
    fn add(&mut self, lhs: &Self::Value, rhs: &Self::Value) -> Result<Self::Value, BgvError>;
    /// `lhs - rhs` at one level.
    fn sub(&mut self, lhs: &Self::Value, rhs: &Self::Value) -> Result<Self::Value, BgvError>;
    /// `-value`.
    fn negate(&mut self, value: &Self::Value) -> Result<Self::Value, BgvError>;
    /// `value + scalar` in every slot.
    fn add_scalar(&mut self, value: &Self::Value, scalar: u64) -> Result<Self::Value, BgvError>;
    /// `value - scalar` in every slot.
    fn sub_scalar(&mut self, value: &Self::Value, scalar: u64) -> Result<Self::Value, BgvError>;
    /// `value * scalar` in every slot.
    fn mul_scalar(&mut self, value: &Self::Value, scalar: u64) -> Result<Self::Value, BgvError>;
    /// `value` times the idempotent of `slot`.
    fn mul_slot_mask(&mut self, value: &Self::Value, slot: usize) -> Result<Self::Value, BgvError>;
    /// `value` times the mask that keeps the first `count` slots.
    fn mul_prefix_mask(
        &mut self,
        value: &Self::Value,
        count: usize,
    ) -> Result<Self::Value, BgvError>;
    /// The image of `value` under the automorphism of `element`.
    fn galois(&mut self, value: &Self::Value, element: u32) -> Result<Self::Value, BgvError>;
    /// The relinearized product at one level.
    fn multiply(&mut self, lhs: &Self::Value, rhs: &Self::Value) -> Result<Self::Value, BgvError>;
    /// `value` with the last prime of its level dropped.
    fn switch_down(&mut self, value: &Self::Value) -> Result<Self::Value, BgvError>;
}

/// The back end of public shapes.
pub struct Planned<'a> {
    profile: &'a BgvProfile,
    encoding: SlotEncoding,
}

impl<'a> Planned<'a> {
    /// The planning back end of `profile`.
    pub fn new(profile: &'a BgvProfile) -> Result<Self, BgvError> {
        Ok(Self {
            profile,
            encoding: SlotEncoding::new(profile)?,
        })
    }
}

impl Backend for Planned<'_> {
    type Value = CiphertextShape;

    fn profile(&self) -> &BgvProfile {
        self.profile
    }

    fn shape(&self, value: &CiphertextShape) -> CiphertextShape {
        value.clone()
    }

    fn input(&mut self) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_fresh()
    }

    fn constant(&mut self, _value: u64, level: usize) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_trivial(level)
    }

    fn add(
        &mut self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_add(lhs, rhs)
    }

    fn sub(
        &mut self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_add(lhs, rhs)
    }

    fn negate(&mut self, value: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        Ok(value.clone())
    }

    fn add_scalar(
        &mut self,
        value: &CiphertextShape,
        _scalar: u64,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile
            .plan_add_plain(value, Plaintext::constant_bound(self.profile))
    }

    fn sub_scalar(
        &mut self,
        value: &CiphertextShape,
        _scalar: u64,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile
            .plan_add_plain(value, Plaintext::constant_bound(self.profile))
    }

    fn mul_scalar(
        &mut self,
        value: &CiphertextShape,
        _scalar: u64,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile
            .plan_mul_plain(value, Plaintext::constant_bound(self.profile))
    }

    fn mul_slot_mask(
        &mut self,
        value: &CiphertextShape,
        _slot: usize,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile
            .plan_mul_plain(value, self.encoding.mask_bound())
    }

    fn mul_prefix_mask(
        &mut self,
        value: &CiphertextShape,
        _count: usize,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile
            .plan_mul_plain(value, self.encoding.vector_bound())
    }

    fn galois(
        &mut self,
        value: &CiphertextShape,
        _element: u32,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_galois(value)
    }

    fn multiply(
        &mut self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_multiply(lhs, rhs)
    }

    fn switch_down(&mut self, value: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        self.profile.plan_switch_down(value)
    }
}

/// The back end of real ciphertexts.
pub struct Encrypted<'a> {
    profile: &'a BgvProfile,
    encoding: SlotEncoding,
    keys: &'a EvaluationKeys,
    input: Ciphertext,
}

impl<'a> Encrypted<'a> {
    /// The evaluating back end over `keys` and the encrypted packed `input`.
    pub fn new(
        profile: &'a BgvProfile,
        keys: &'a EvaluationKeys,
        input: Ciphertext,
    ) -> Result<Self, BgvError> {
        Ok(Self {
            profile,
            encoding: SlotEncoding::new(profile)?,
            keys,
            input,
        })
    }

    fn scalar(&self, value: u64) -> Result<Plaintext, BgvError> {
        Plaintext::constant(self.profile, value % self.profile.plaintext_modulus())
    }
}

impl Backend for Encrypted<'_> {
    type Value = Ciphertext;

    fn profile(&self) -> &BgvProfile {
        self.profile
    }

    fn shape(&self, value: &Ciphertext) -> CiphertextShape {
        value.shape()
    }

    fn input(&mut self) -> Result<Ciphertext, BgvError> {
        Ok(self.input.clone())
    }

    fn constant(&mut self, value: u64, level: usize) -> Result<Ciphertext, BgvError> {
        Ciphertext::trivial(self.profile, &self.scalar(value)?, level)
    }

    fn add(&mut self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.profile.add(lhs, rhs)
    }

    fn sub(&mut self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.profile.sub(lhs, rhs)
    }

    fn negate(&mut self, value: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.profile.negate(value)
    }

    fn add_scalar(&mut self, value: &Ciphertext, scalar: u64) -> Result<Ciphertext, BgvError> {
        self.profile.add_plain(value, &self.scalar(scalar)?)
    }

    fn sub_scalar(&mut self, value: &Ciphertext, scalar: u64) -> Result<Ciphertext, BgvError> {
        self.profile.sub_plain(value, &self.scalar(scalar)?)
    }

    fn mul_scalar(&mut self, value: &Ciphertext, scalar: u64) -> Result<Ciphertext, BgvError> {
        self.profile.mul_plain(value, &self.scalar(scalar)?)
    }

    fn mul_slot_mask(&mut self, value: &Ciphertext, slot: usize) -> Result<Ciphertext, BgvError> {
        let mask = self.encoding.slot_mask(self.profile, slot)?;
        self.profile.mul_plain(value, &mask)
    }

    fn mul_prefix_mask(
        &mut self,
        value: &Ciphertext,
        count: usize,
    ) -> Result<Ciphertext, BgvError> {
        let mask = self.encoding.prefix_mask(self.profile, count)?;
        self.profile.mul_plain(value, &mask)
    }

    fn galois(&mut self, value: &Ciphertext, element: u32) -> Result<Ciphertext, BgvError> {
        let key = self
            .keys
            .galois(element)
            .ok_or(BgvError::WrongSwitchingKey)?;
        self.profile.apply_galois(value, key)
    }

    fn multiply(&mut self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.profile.multiply(lhs, rhs, self.keys.relinearization())
    }

    fn switch_down(&mut self, value: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.profile.switch_down(value)
    }
}

/// Operation counts and model work units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Plaintext multiplications (constants and masks).
    pub plaintext_multiplications: u64,
    /// Key switches: one per automorphism and one per relinearization.
    pub key_switches: u64,
    /// Ciphertext multiplications with relinearization.
    pub multiplications: u64,
    /// Modulus switches of one prime.
    pub modulus_switches: u64,
    /// Model work units of [`CostModel`], each operation at the level it ran.
    pub units: u64,
}

impl Work {
    fn add(&mut self, other: Self) {
        self.plaintext_multiplications += other.plaintext_multiplications;
        self.key_switches += other.key_switches;
        self.multiplications += other.multiplications;
        self.modulus_switches += other.modulus_switches;
        self.units += other.units;
    }
}

/// What a run of the machine cost.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// Work of the whole tape, the final zeroing mask included.
    pub total: Work,
    /// Work per opcode tag; index 11 is the final zeroing mask.
    pub by_opcode: [Work; 12],
    /// Instructions per opcode tag.
    pub instructions: [u64; 11],
    /// The largest work of one instruction per opcode tag.
    pub costliest: [Work; 11],
    /// Largest residue bytes of the input, the registers, the lanes and the
    /// output accumulator at an instruction boundary.
    pub peak_persistent_bytes: u64,
    /// Largest residue bytes live inside one operation: the persistent
    /// buffers, the temporaries of the instruction and the scratch of the
    /// operation.
    pub peak_working_bytes: u64,
}

/// The V1 register machine over one back end.
pub struct Machine<'model, B: Backend> {
    backend: B,
    model: CostModel<'model>,
    broadcast: Vec<u32>,
    input: B::Value,
    registers: Vec<B::Value>,
    lanes: Vec<B::Value>,
    output: Option<B::Value>,
    outputs: usize,
    current: Work,
    ledger: Ledger,
}

impl<'model, B: Backend> Machine<'model, B> {
    /// A machine with zero registers and the given initial lane scalars (missing lanes are zero).
    ///
    /// `profile` is the profile of the back end; it is taken separately so the
    /// cost model can borrow it for the lifetime of the machine.
    pub fn new(
        mut backend: B,
        profile: &'model BgvProfile,
        initial_state: &[u64],
    ) -> Result<Self, BgvError> {
        assert_eq!(profile.identity(), backend.profile().identity());
        assert!(initial_state.len() <= STATE_LANES);
        let top = profile.top_level();
        let input = backend.input()?;
        let zero = backend.constant(0, top)?;
        let mut lanes = Vec::with_capacity(STATE_LANES);
        for lane in 0..STATE_LANES {
            let scalar = initial_state.get(lane).copied().unwrap_or(0);
            lanes.push(backend.constant(scalar, top)?);
        }
        let mut machine = Self {
            backend,
            model: CostModel::new(profile),
            broadcast: SlotEncoding::new(profile)?.broadcast_elements(),
            input,
            registers: vec![zero; REGISTERS],
            lanes,
            output: None,
            outputs: 0,
            current: Work::default(),
            ledger: Ledger::default(),
        };
        machine.ledger.peak_persistent_bytes = machine.persistent_bytes()?;
        machine.ledger.peak_working_bytes = machine.ledger.peak_persistent_bytes;
        Ok(machine)
    }

    /// The back end, for decrypting the values of an encrypted run.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The noiseless embedding of `value` at `level`, from the back end.
    pub fn constant(&mut self, value: u64, level: usize) -> Result<B::Value, BgvError> {
        self.backend.constant(value, level)
    }

    /// The packed input.
    pub fn input(&self) -> &B::Value {
        &self.input
    }

    /// Register `index`.
    pub fn register(&self, index: usize) -> &B::Value {
        &self.registers[index]
    }

    /// State lane `index`.
    pub fn lane(&self, index: usize) -> &B::Value {
        &self.lanes[index]
    }

    /// The output accumulator, once an output was emitted.
    pub fn output(&self) -> Option<&B::Value> {
        self.output.as_ref()
    }

    /// Outputs emitted so far.
    pub const fn outputs(&self) -> usize {
        self.outputs
    }

    /// The ledger so far.
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn level(&self, value: &B::Value) -> usize {
        self.backend.shape(value).level()
    }

    fn bytes(&self, value: &B::Value) -> Result<u64, BgvError> {
        let shape = self.backend.shape(value);
        self.model
            .ciphertext_residue_bytes(shape.level(), shape.components())
    }

    fn persistent_bytes(&self) -> Result<u64, BgvError> {
        let mut total = self.bytes(&self.input)?;
        for value in self
            .registers
            .iter()
            .chain(&self.lanes)
            .chain(self.output.as_ref())
        {
            total += self.bytes(value)?;
        }
        Ok(total)
    }

    /// Record the working set of one operation: the persistent buffers, the
    /// listed temporaries and `scratch` bytes.
    fn working(&mut self, temporaries: &[&B::Value], scratch: u64) -> Result<(), BgvError> {
        let mut total = self.persistent_bytes()? + scratch;
        for value in temporaries {
            total += self.bytes(value)?;
        }
        self.ledger.peak_working_bytes = self.ledger.peak_working_bytes.max(total);
        Ok(())
    }

    /// Scratch bytes of one key switch at `level`.
    fn key_switch_scratch(&self, level: usize) -> Result<u64, BgvError> {
        Ok(8 * self.model.key_switch_scratch_words(level)?)
    }

    fn switch_down(&mut self, value: &B::Value) -> Result<B::Value, BgvError> {
        let level = self.level(value);
        let lower = self.backend.switch_down(value)?;
        self.current.modulus_switches += 1;
        self.current.units += self.model.switch_down_units(level)?;
        Ok(lower)
    }

    fn switch_to(&mut self, value: &B::Value, level: usize) -> Result<B::Value, BgvError> {
        let mut current = value.clone();
        while self.level(&current) > level {
            current = self.switch_down(&current)?;
        }
        Ok(current)
    }

    /// Both operands at the lower of their two levels.
    fn align(&mut self, lhs: &B::Value, rhs: &B::Value) -> Result<(B::Value, B::Value), BgvError> {
        let level = self.level(lhs).min(self.level(rhs));
        Ok((self.switch_to(lhs, level)?, self.switch_to(rhs, level)?))
    }

    fn mul_plain_units(&mut self, level: usize) -> Result<(), BgvError> {
        self.current.plaintext_multiplications += 1;
        self.current.units += self.model.plaintext_multiplication_units(level)?;
        Ok(())
    }

    /// The product at the level the policy chooses; `same` marks a squaring.
    fn lowered_product(
        &mut self,
        lhs: &B::Value,
        rhs: &B::Value,
        same: bool,
    ) -> Result<B::Value, BgvError> {
        let (mut lhs, mut rhs) = if same {
            (lhs.clone(), lhs.clone())
        } else {
            self.align(lhs, rhs)?
        };
        while self
            .backend
            .profile()
            .plan_lower_multiplication(&self.backend.shape(&lhs), &self.backend.shape(&rhs))?
            .is_some()
        {
            lhs = self.switch_down(&lhs)?;
            rhs = if same {
                lhs.clone()
            } else {
                self.switch_down(&rhs)?
            };
        }
        let level = self.level(&lhs);
        // The three-component tensor and the key-switch scratch are live with both operands.
        let tensor = self.model.ciphertext_residue_bytes(level, 3)?;
        let scratch = tensor + self.key_switch_scratch(level)?;
        if same {
            self.working(&[&lhs], scratch)?;
        } else {
            self.working(&[&lhs, &rhs], scratch)?;
        }
        let product = self.backend.multiply(&lhs, &rhs)?;
        self.current.multiplications += 1;
        self.current.key_switches += 1;
        self.current.units += self.model.multiplication_units(level)?;
        Ok(product)
    }

    fn load_input(&mut self, slot: usize) -> Result<B::Value, BgvError> {
        let input = self.input.clone();
        let level = self.level(&input);
        let mut current = self.backend.mul_slot_mask(&input, slot)?;
        self.mul_plain_units(level)?;
        let scratch = self.key_switch_scratch(level)?;
        for index in 0..self.broadcast.len() {
            let element = self.broadcast[index];
            let image = self.backend.galois(&current, element)?;
            self.current.key_switches += 1;
            self.current.units += self.model.automorphism_units(level)?;
            self.working(&[&current, &image], scratch)?;
            current = self.backend.add(&current, &image)?;
        }
        Ok(current)
    }

    /// The `SelectEqZero` lowering on three values: `nonzero + (1 - cond^256) * (zero - nonzero)`.
    ///
    /// Slot-wise on whatever the values hold; the machine itself only passes
    /// broadcast scalars. Work is charged to the instruction in progress.
    pub fn select(
        &mut self,
        cond: &B::Value,
        zero: &B::Value,
        nonzero: &B::Value,
    ) -> Result<B::Value, BgvError> {
        let mut powered = cond.clone();
        for _ in 0..SELECT_SQUARINGS {
            powered = self.lowered_product(&powered, &powered, true)?;
        }
        let level = self.level(&powered);
        let one = self.backend.constant(1, level)?;
        let powered = self.lowered_product(&powered, &one, false)?;
        let negated = self.backend.negate(&powered)?;
        let indicator = self.backend.add_scalar(&negated, 1)?;
        let (zero, nonzero) = self.align(zero, nonzero)?;
        let delta = self.backend.sub(&zero, &nonzero)?;
        // The indicator, the difference and the aligned branches are live across the product.
        self.working(&[&indicator, &delta, &zero, &nonzero], 0)?;
        let product = self.lowered_product(&indicator, &delta, false)?;
        let (nonzero, product) = self.align(&nonzero, &product)?;
        self.backend.add(&nonzero, &product)
    }

    /// Execute one instruction.
    pub fn step(&mut self, instruction: Instruction) -> Result<(), BgvError> {
        self.current = Work::default();
        match instruction {
            Instruction::LoadInput { dst, slot } => {
                self.registers[dst] = self.load_input(slot)?;
            }
            Instruction::LoadState { dst, lane } => {
                self.registers[dst] = self.lanes[lane].clone();
            }
            Instruction::StoreState { lane, src } => {
                self.lanes[lane] = self.registers[src].clone();
            }
            Instruction::LoadConst { dst, value } => {
                let top = self.backend.profile().top_level();
                self.registers[dst] = self.backend.constant(value, top)?;
            }
            Instruction::Add { dst, lhs, rhs } => {
                let (lhs, rhs) = {
                    let (lhs, rhs) = (self.registers[lhs].clone(), self.registers[rhs].clone());
                    self.align(&lhs, &rhs)?
                };
                self.working(&[&lhs, &rhs], 0)?;
                self.registers[dst] = self.backend.add(&lhs, &rhs)?;
            }
            Instruction::AddPlain { dst, src, value } => {
                let source = self.registers[src].clone();
                self.registers[dst] = self.backend.add_scalar(&source, value)?;
            }
            Instruction::SubPlain { dst, src, value } => {
                let source = self.registers[src].clone();
                self.registers[dst] = self.backend.sub_scalar(&source, value)?;
            }
            Instruction::MulPlain { dst, src, value } => {
                let source = self.registers[src].clone();
                let level = self.level(&source);
                self.registers[dst] = self.backend.mul_scalar(&source, value)?;
                self.mul_plain_units(level)?;
            }
            Instruction::Mul { dst, lhs, rhs } => {
                let (left, right) = (self.registers[lhs].clone(), self.registers[rhs].clone());
                self.registers[dst] = self.lowered_product(&left, &right, lhs == rhs)?;
            }
            Instruction::SelectEqZero {
                dst,
                cond,
                zero,
                nonzero,
            } => {
                let (cond, zero, nonzero) = (
                    self.registers[cond].clone(),
                    self.registers[zero].clone(),
                    self.registers[nonzero].clone(),
                );
                self.registers[dst] = self.select(&cond, &zero, &nonzero)?;
            }
            Instruction::Output { src } => {
                let source = self.registers[src].clone();
                let level = self.level(&source);
                let term = self.backend.mul_slot_mask(&source, self.outputs)?;
                self.mul_plain_units(level)?;
                self.output = Some(match self.output.take() {
                    None => term,
                    Some(accumulator) => {
                        let (accumulator, term) = self.align(&accumulator, &term)?;
                        self.working(&[&accumulator, &term], 0)?;
                        self.backend.add(&accumulator, &term)?
                    }
                });
                self.outputs += 1;
            }
        }
        let tag = instruction.tag();
        let work = self.current;
        self.ledger.total.add(work);
        self.ledger.by_opcode[tag].add(work);
        self.ledger.instructions[tag] += 1;
        if work.units >= self.ledger.costliest[tag].units {
            self.ledger.costliest[tag] = work;
        }
        let persistent = self.persistent_bytes()?;
        self.ledger.peak_persistent_bytes = self.ledger.peak_persistent_bytes.max(persistent);
        self.ledger.peak_working_bytes = self.ledger.peak_working_bytes.max(persistent);
        Ok(())
    }

    /// Zero every unused output slot and return the packed output with the ledger.
    ///
    /// The accumulator is taken: a second call has nothing to pack. The
    /// registers and lanes stay live until the machine is dropped, so a caller
    /// that measures can time their release on its own.
    ///
    /// # Errors
    /// [`BgvError::SlotOutOfRange`] when the tape emitted no output.
    pub fn finish(&mut self) -> Result<(B::Value, Ledger), BgvError> {
        let accumulator = self.output.take().ok_or(BgvError::SlotOutOfRange {
            index: 0,
            slots: MAX_OUTPUTS,
        })?;
        self.current = Work::default();
        let level = self.level(&accumulator);
        let packed = self.backend.mul_prefix_mask(&accumulator, self.outputs)?;
        self.mul_plain_units(level)?;
        let work = self.current;
        self.ledger.total.add(work);
        self.ledger.by_opcode[11].add(work);
        Ok((packed, self.ledger.clone()))
    }
}

/// What planning one tape on one profile gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TapePlan {
    /// Every instruction and the final mask were admitted.
    Fits {
        /// Shape of the packed output.
        output: CiphertextShape,
        /// Bit length of the capacity of the output level.
        capacity_bits: usize,
        /// The ledger of the run.
        ledger: Box<Ledger>,
    },
    /// The noise budget or the chain ran out.
    Refused {
        /// Index of the first refused instruction; the tape length for the final mask.
        instruction: usize,
        /// Opcode tag of that instruction; 11 for the final mask.
        tag: usize,
    },
}

impl TapePlan {
    /// Whether the tape was admitted.
    pub const fn fits(&self) -> bool {
        matches!(self, Self::Fits { .. })
    }
}

/// Plan `tape` on `profile` with the public shapes only.
pub fn plan_tape(profile: &BgvProfile, tape: &[Instruction]) -> Result<TapePlan, BgvError> {
    let refusal = |error: BgvError, instruction: usize, tag: usize| match error {
        BgvError::NoiseBudgetExceeded { .. } | BgvError::NoLevelLeft => {
            Ok(TapePlan::Refused { instruction, tag })
        }
        other => Err(other),
    };
    let mut machine = match Machine::new(Planned::new(profile)?, profile, &[]) {
        Ok(machine) => machine,
        // A chain that cannot hold a fresh ciphertext refuses before the first instruction.
        Err(error) => return refusal(error, 0, tape.first().map_or(11, Instruction::tag)),
    };
    for (index, instruction) in tape.iter().enumerate() {
        if let Err(error) = machine.step(*instruction) {
            return refusal(error, index, instruction.tag());
        }
    }
    match machine.finish() {
        Ok((output, ledger)) => Ok(TapePlan::Fits {
            capacity_bits: profile.capacity(output.level())?.bit_len(),
            output,
            ledger: Box::new(ledger),
        }),
        Err(error) => refusal(error, tape.len(), 11),
    }
}

/// The noise bound after a projected flooding sanitization of an output.
///
/// For `2^log2_releases` adaptive releases and statistical distance
/// `2^-kappa`, a uniform flood of half-width `F` on every coefficient of the
/// error hides a shift of at most `Delta` when `2F + 1 >= H * N * Delta *
/// 2^kappa`. With `E = ceil(V / t)` bounding the error of the output,
/// `Delta = 2E` and `F = H * N * E * 2^kappa`, the flooded and re-randomized
/// ciphertext has the bound `V + t*F + V_fresh`. This is a projection of one
/// published technique with parameters nobody has selected; it is not a
/// sanitization construction and establishes nothing.
pub fn flooded_bound(
    profile: &BgvProfile,
    bound: &Natural,
    log2_releases: u32,
    kappa: u32,
) -> Natural {
    let t = profile.plaintext_modulus();
    let error = bound.div_ceil_u64(t).unwrap_or_default();
    let mut flood = error.mul_u64(u64::try_from(profile.degree()).unwrap_or(u64::MAX));
    for _ in 0..log2_releases + kappa {
        flood = flood.mul_u64(2);
    }
    bound.add(&flood.mul_u64(t)).add(profile.fresh_noise())
}

/// The maximum-shape tape families of the cost model.
pub mod families {
    use super::{Instruction, MAX_INSTRUCTIONS, MAX_OUTPUTS};

    /// The scalar of every `MulPlain`: the largest centered magnitude.
    const SCALE: u64 = 128;

    fn repeat(tape: &mut Vec<Instruction>, count: usize, instruction: Instruction) {
        tape.extend(std::iter::repeat_n(instruction, count));
    }

    fn outputs(tape: &mut Vec<Instruction>, count: usize, src: usize) {
        repeat(tape, count, Instruction::Output { src });
    }

    /// `affine.loads`: 255 input loads and one output; the key-switch extreme.
    pub fn affine_loads() -> Vec<Instruction> {
        let loads = MAX_INSTRUCTIONS - 1;
        let mut tape: Vec<Instruction> = (0..loads)
            .map(|index| Instruction::LoadInput {
                dst: index % 4,
                slot: index % 64,
            })
            .collect();
        outputs(&mut tape, 1, (loads - 1) % 4);
        tape
    }

    /// `affine.scale_chain`: one load, 254 sequential constant multiplications, one output.
    pub fn affine_scale_chain() -> Vec<Instruction> {
        scale_chain(MAX_INSTRUCTIONS - 2, 1)
    }

    /// `affine.scale_then_outputs`: one load, 191 constant multiplications, 64 outputs.
    pub fn affine_scale_then_outputs() -> Vec<Instruction> {
        scale_chain(MAX_INSTRUCTIONS - 1 - MAX_OUTPUTS, MAX_OUTPUTS)
    }

    /// One load, `scales` sequential constant multiplications and `count` outputs.
    pub fn scale_chain(scales: usize, count: usize) -> Vec<Instruction> {
        frontier(0, scales, count)
    }

    /// `affine.state_and_registers`: every affine opcode, with every register and
    /// every state lane holding an encrypted value, and 64 outputs.
    pub fn affine_state_and_registers() -> Vec<Instruction> {
        let mut tape = Vec::with_capacity(MAX_INSTRUCTIONS);
        for register in 0..4 {
            tape.push(Instruction::LoadInput {
                dst: register,
                slot: register,
            });
        }
        for lane in 0..32 {
            tape.push(Instruction::StoreState {
                lane,
                src: lane % 4,
            });
        }
        for round in 0..26 {
            tape.extend([
                Instruction::LoadState {
                    dst: 0,
                    lane: round % 32,
                },
                Instruction::AddPlain {
                    dst: 0,
                    src: 0,
                    value: 5,
                },
                Instruction::SubPlain {
                    dst: 0,
                    src: 0,
                    value: 3,
                },
                Instruction::Add {
                    dst: 1,
                    lhs: 0,
                    rhs: 1,
                },
                Instruction::LoadConst { dst: 2, value: 7 },
                Instruction::Add {
                    dst: 3,
                    lhs: 2,
                    rhs: 3,
                },
            ]);
        }
        for index in 0..MAX_OUTPUTS {
            tape.push(Instruction::Output { src: index % 4 });
        }
        tape
    }

    /// `bounded.selects`: 255 independent selects and one output; the multiplication extreme.
    pub fn bounded_selects() -> Vec<Instruction> {
        let mut tape = Vec::with_capacity(MAX_INSTRUCTIONS);
        repeat(
            &mut tape,
            MAX_INSTRUCTIONS - 1,
            Instruction::SelectEqZero {
                dst: 0,
                cond: 1,
                zero: 2,
                nonzero: 3,
            },
        );
        outputs(&mut tape, 1, 0);
        tape
    }

    /// One load, `rank` sequential squarings, `scales` sequential constant
    /// multiplications and `count` outputs.
    pub fn frontier(rank: usize, scales: usize, count: usize) -> Vec<Instruction> {
        let mut tape = vec![Instruction::LoadInput { dst: 0, slot: 0 }];
        repeat(
            &mut tape,
            rank,
            Instruction::Mul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
        );
        repeat(
            &mut tape,
            scales,
            Instruction::MulPlain {
                dst: 0,
                src: 0,
                value: SCALE,
            },
        );
        outputs(&mut tape, count, 0);
        tape
    }

    /// `bounded.scaled_rank_chain`: one load, 238 constant multiplications,
    /// 16 squarings and one output; 256 instructions at rank 16.
    pub fn bounded_scaled_rank_chain() -> Vec<Instruction> {
        let mut tape = vec![Instruction::LoadInput { dst: 0, slot: 0 }];
        repeat(
            &mut tape,
            MAX_INSTRUCTIONS - 2 - super::BOUNDED_MAX_RANK,
            Instruction::MulPlain {
                dst: 0,
                src: 0,
                value: SCALE,
            },
        );
        repeat(
            &mut tape,
            super::BOUNDED_MAX_RANK,
            Instruction::Mul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
        );
        outputs(&mut tape, 1, 0);
        tape
    }

    /// `bounded.rank_chain_outputs`: one load, 16 squarings and 64 outputs.
    pub fn bounded_rank_chain_outputs() -> Vec<Instruction> {
        frontier(super::BOUNDED_MAX_RANK, 0, MAX_OUTPUTS)
    }

    /// `bounded.alternating_rank_chain`: one load, sixteen rounds of one
    /// constant multiplication and one squaring, one more constant
    /// multiplication and 64 outputs.
    pub fn bounded_alternating_rank_chain() -> Vec<Instruction> {
        let scale = Instruction::MulPlain {
            dst: 0,
            src: 0,
            value: SCALE,
        };
        let mut tape = vec![Instruction::LoadInput { dst: 0, slot: 0 }];
        for _ in 0..super::BOUNDED_MAX_RANK {
            tape.push(scale);
            tape.push(Instruction::Mul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            });
        }
        tape.push(scale);
        outputs(&mut tape, MAX_OUTPUTS, 0);
        tape
    }

    /// `bounded.select_then_products`: two loads and a constant, one select
    /// on the loaded condition (rank 10), six squarings (rank 16) and 64 outputs.
    pub fn bounded_select_then_products() -> Vec<Instruction> {
        let mut tape = vec![
            Instruction::LoadInput { dst: 0, slot: 5 },
            Instruction::LoadInput { dst: 1, slot: 9 },
            Instruction::LoadConst { dst: 2, value: 77 },
            Instruction::SelectEqZero {
                dst: 3,
                cond: 0,
                zero: 1,
                nonzero: 2,
            },
        ];
        repeat(
            &mut tape,
            super::BOUNDED_MAX_RANK - super::SELECT_MULTIPLICATIONS,
            Instruction::Mul {
                dst: 3,
                lhs: 3,
                rhs: 3,
            },
        );
        outputs(&mut tape, MAX_OUTPUTS, 3);
        tape
    }

    /// One instruction of every `affine.v1` opcode on operands loaded at the
    /// top level, with two outputs: the tape behind the per-instruction costs.
    pub fn instruction_profile_affine() -> Vec<Instruction> {
        let mut tape = instruction_profile_prefix();
        tape.extend([
            Instruction::Output { src: 3 },
            Instruction::Output { src: 2 },
        ]);
        tape
    }

    /// The affine profile followed by one `Mul` and one `SelectEqZero`.
    pub fn instruction_profile_bounded() -> Vec<Instruction> {
        let mut tape = instruction_profile_prefix();
        tape.extend([
            Instruction::Mul {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Instruction::SelectEqZero {
                dst: 3,
                cond: 0,
                zero: 1,
                nonzero: 3,
            },
            Instruction::Output { src: 3 },
            Instruction::Output { src: 2 },
        ]);
        tape
    }

    fn instruction_profile_prefix() -> Vec<Instruction> {
        vec![
            Instruction::LoadInput { dst: 0, slot: 5 },
            Instruction::LoadInput { dst: 1, slot: 9 },
            Instruction::LoadState { dst: 2, lane: 0 },
            Instruction::StoreState { lane: 1, src: 0 },
            Instruction::LoadConst { dst: 3, value: 77 },
            Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Instruction::AddPlain {
                dst: 2,
                src: 2,
                value: 5,
            },
            Instruction::SubPlain {
                dst: 2,
                src: 2,
                value: 3,
            },
            Instruction::MulPlain {
                dst: 2,
                src: 2,
                value: SCALE,
            },
        ]
    }

    /// Every named family with the class it belongs to.
    pub fn all() -> Vec<(&'static str, &'static str, Vec<Instruction>)> {
        vec![
            ("affine.v1", "affine.loads", affine_loads()),
            ("affine.v1", "affine.scale_chain", affine_scale_chain()),
            (
                "affine.v1",
                "affine.scale_then_outputs",
                affine_scale_then_outputs(),
            ),
            (
                "affine.v1",
                "affine.state_and_registers",
                affine_state_and_registers(),
            ),
            ("bounded.v1", "bounded.selects", bounded_selects()),
            (
                "bounded.v1",
                "bounded.scaled_rank_chain",
                bounded_scaled_rank_chain(),
            ),
            (
                "bounded.v1",
                "bounded.rank_chain_outputs",
                bounded_rank_chain_outputs(),
            ),
            (
                "bounded.v1",
                "bounded.alternating_rank_chain",
                bounded_alternating_rank_chain(),
            ),
            (
                "bounded.v1",
                "bounded.select_then_products",
                bounded_select_then_products(),
            ),
        ]
    }
}
