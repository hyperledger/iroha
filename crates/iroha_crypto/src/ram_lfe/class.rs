//! Canonical V1 program classes, exact plaintext semantics and class membership.
//!
//! The eleven-instruction tape has one plaintext meaning over the field of 257
//! elements. A class restricts which tapes a policy may commit to; it never
//! changes what an admitted instruction computes. Logical rank is a dependency
//! depth of ciphertext multiplications. It is not a noise budget: additions and
//! plaintext multiplications consume noise without changing rank, and the
//! leveled plan belongs to the encryption profile.
//!
//! The limits below are the candidate first-release shape recorded before any
//! measurement. A changed limit changes the plaintext-semantics descriptor and
//! therefore every function identity.

use super::{
    BFV_PROGRAM_IDENTIFIER_SLOT_COUNT, BFV_PROGRAM_MAX_INSTRUCTIONS, BFV_PROGRAM_REGISTER_COUNT,
    BFV_PROGRAM_STATE_WIDTH, Hash, HiddenRamFheInstruction, HiddenRamFheProgram, RamLfeError,
    canonical::public_digest,
};
use crate::RAM_LFE_BFV_PLAINTEXT_MODULUS;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

/// Plaintext field modulus; every scalar is canonical in `0..=256`.
pub const RAM_LFE_V1_PLAINTEXT_MODULUS: u16 = 257;
/// Registers, zero-initialized at the start of each execution.
pub const RAM_LFE_V1_REGISTERS: usize = 4;
/// State lanes, initialized at the start of each execution.
pub const RAM_LFE_V1_STATE_LANES: usize = 32;
/// Input slots: one length slot followed by byte slots.
pub const RAM_LFE_V1_INPUT_SLOTS: usize = 64;
/// Maximum input byte length carried by the input slots.
pub const RAM_LFE_V1_MAX_INPUT_BYTES: usize = RAM_LFE_V1_INPUT_SLOTS - 1;
/// Maximum number of tape instructions.
pub const RAM_LFE_V1_MAX_INSTRUCTIONS: usize = 256;
/// Maximum number of ordered outputs.
pub const RAM_LFE_V1_MAX_OUTPUTS: usize = 64;
/// Maximum logical rank of a `bounded.v1` value.
pub const RAM_LFE_V1_BOUNDED_MAX_RANK: u16 = 16;
/// Maximum logical rank of a `refresh.v1` value between two refreshes.
pub const RAM_LFE_V1_REFRESH_MAX_RANK_BETWEEN_REFRESHES: u16 = 16;
/// Maximum number of refreshes in one `refresh.v1` execution.
pub const RAM_LFE_V1_REFRESH_MAX_REFRESHES: u16 = 64;
/// Ciphertext multiplications between a `SelectEqZero` condition and its result:
/// eight squarings, one multiplication by the embedded one, one selection.
pub const RAM_LFE_V1_SELECT_CONDITION_RANK: u16 = 10;
/// Ciphertext multiplications between a `SelectEqZero` branch and its result.
pub const RAM_LFE_V1_SELECT_BRANCH_RANK: u16 = 1;

// The tape owner and the diagnostic evaluator share this single machine shape.
const _: () = {
    assert!(RAM_LFE_V1_PLAINTEXT_MODULUS as u64 == RAM_LFE_BFV_PLAINTEXT_MODULUS);
    assert!(RAM_LFE_V1_REGISTERS == BFV_PROGRAM_REGISTER_COUNT);
    assert!(RAM_LFE_V1_STATE_LANES == BFV_PROGRAM_STATE_WIDTH);
    assert!(RAM_LFE_V1_INPUT_SLOTS == BFV_PROGRAM_IDENTIFIER_SLOT_COUNT);
    assert!(RAM_LFE_V1_MAX_INSTRUCTIONS == BFV_PROGRAM_MAX_INSTRUCTIONS);
    assert!(RAM_LFE_V1_MAX_OUTPUTS == BFV_PROGRAM_IDENTIFIER_SLOT_COUNT);
    assert!(RAM_LFE_V1_BOUNDED_MAX_RANK == crate::BFV_EXACT_EVALUATOR_MAX_MULTIPLICATIVE_DEPTH);
};

/// Exact plaintext semantics committed by every V1 function identity.
///
/// The text is the normative contract. `specs/ram_lfe_execution_proof.md`
/// carries the same bytes. Tests compare the two, rebuild every other line
/// from the compiled constants, and evaluate each opcode line against the tape
/// codec, the cleartext reference and the class accounting.
pub const RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR: &str = "\
iroha.ram_lfe.plaintext_semantics.v1
field=F257;scalar=0..256;arithmetic=mod257
registers=4;register-init=0;state-lanes=32;state-init=per-execution;state-persistence=none
input-slots=64;input=slot0:length(0..63),slots1..length:byte(0..255),rest:0
instructions=1..256;outputs=1..64;output=ordered-scalar(0..256)-snapshot;immediate=0..256
tape=48-bytes-per-instruction;words=6*u64le;unused-words=0
opcode=0:LoadInput(dst,slot):dst=input[slot];rank=0
opcode=1:LoadState(dst,lane):dst=state[lane];rank=state[lane]
opcode=2:StoreState(lane,src):state[lane]=src;rank=src
opcode=3:LoadConst(dst,imm):dst=imm;rank=0
opcode=4:Add(dst,lhs,rhs):dst=lhs+rhs;rank=max(lhs,rhs)
opcode=5:AddPlain(dst,src,imm):dst=src+imm;rank=src
opcode=6:SubPlain(dst,src,imm):dst=src-imm;rank=src
opcode=7:MulPlain(dst,src,imm):dst=src*imm;rank=src
opcode=8:Mul(dst,lhs,rhs):dst=lhs*rhs;rank=max(lhs,rhs)+1
opcode=9:SelectEqZero(dst,cond,zero,nonzero):dst=nonzero+(1-cond^256)*(zero-nonzero);rank=max(cond+10,zero+1,nonzero+1)
opcode=10:Output(src):append(src);rank=src
class=affine.v1;opcodes=0,1,2,3,4,5,6,7,10;max-rank=0;max-refreshes=0
class=bounded.v1;opcodes=0,1,2,3,4,5,6,7,8,9,10;max-rank=16;max-refreshes=0
class=refresh.v1;opcodes=0,1,2,3,4,5,6,7,8,9,10;max-rank=16;max-refreshes=64
refresh=plaintext-identity;schedule=lazy;trigger=result-rank>max-rank;targets=distinct-nonzero-rank-operand-registers;order=operand;effect=rank:=0,in-place
initializer=blake3-derive-key-xof;context=iroha.ram_lfe.v1.initial_state;frame=iroha_crypto::ram_lfe::RamLfeInitializationInputV1;fields=function_identity,associated_data_hash,program_key;stream-bytes=1024;lane=32-bytes-unsigned-big-endian-mod257;lane-order=ascending
associated-data=0..512-bytes
";

pub(super) const PLAINTEXT_SEMANTICS_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.plaintext_semantics";

/// Return the digest of [`RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR`].
#[must_use]
pub fn ram_lfe_v1_plaintext_semantics_hash() -> Hash {
    public_digest(
        PLAINTEXT_SEMANTICS_DOMAIN,
        RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR.as_bytes(),
    )
}

/// One of the eleven canonical tape opcodes.
///
/// The tag is the first word of the instruction's canonical tape slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RamLfeOpcodeV1 {
    /// Load one input slot into a register.
    LoadInput,
    /// Load one state lane into a register.
    LoadState,
    /// Store a register into one state lane.
    StoreState,
    /// Load a plaintext constant into a register.
    LoadConst,
    /// Add two registers.
    Add,
    /// Add a plaintext scalar to a register.
    AddPlain,
    /// Subtract a plaintext scalar from a register.
    SubPlain,
    /// Multiply a register by a plaintext scalar.
    MulPlain,
    /// Multiply two registers.
    Mul,
    /// Select between two registers on whether a third is zero.
    SelectEqZero,
    /// Append a register to the ordered output.
    Output,
}

impl RamLfeOpcodeV1 {
    /// Every opcode, in ascending tag order.
    pub const ALL: [Self; 11] = [
        Self::LoadInput,
        Self::LoadState,
        Self::StoreState,
        Self::LoadConst,
        Self::Add,
        Self::AddPlain,
        Self::SubPlain,
        Self::MulPlain,
        Self::Mul,
        Self::SelectEqZero,
        Self::Output,
    ];

    /// Canonical tape tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::LoadInput => 0,
            Self::LoadState => 1,
            Self::StoreState => 2,
            Self::LoadConst => 3,
            Self::Add => 4,
            Self::AddPlain => 5,
            Self::SubPlain => 6,
            Self::MulPlain => 7,
            Self::Mul => 8,
            Self::SelectEqZero => 9,
            Self::Output => 10,
        }
    }

    /// Stable opcode name used by the plaintext-semantics descriptor.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LoadInput => "LoadInput",
            Self::LoadState => "LoadState",
            Self::StoreState => "StoreState",
            Self::LoadConst => "LoadConst",
            Self::Add => "Add",
            Self::AddPlain => "AddPlain",
            Self::SubPlain => "SubPlain",
            Self::MulPlain => "MulPlain",
            Self::Mul => "Mul",
            Self::SelectEqZero => "SelectEqZero",
            Self::Output => "Output",
        }
    }
}

impl fmt::Display for RamLfeOpcodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl HiddenRamFheInstruction {
    /// Return this instruction's canonical opcode.
    #[must_use]
    pub const fn opcode(self) -> RamLfeOpcodeV1 {
        match self {
            Self::LoadInput(..) => RamLfeOpcodeV1::LoadInput,
            Self::LoadState(..) => RamLfeOpcodeV1::LoadState,
            Self::StoreState(..) => RamLfeOpcodeV1::StoreState,
            Self::LoadConst(..) => RamLfeOpcodeV1::LoadConst,
            Self::Add(..) => RamLfeOpcodeV1::Add,
            Self::AddPlain(..) => RamLfeOpcodeV1::AddPlain,
            Self::SubPlain(..) => RamLfeOpcodeV1::SubPlain,
            Self::MulPlain(..) => RamLfeOpcodeV1::MulPlain,
            Self::Mul(..) => RamLfeOpcodeV1::Mul,
            Self::SelectEqZero(..) => RamLfeOpcodeV1::SelectEqZero,
            Self::Output(..) => RamLfeOpcodeV1::Output,
        }
    }
}

/// Mandatory RAM-LFE program class committed by a function identity.
///
/// Every class has the same plaintext semantics for the instructions it admits.
/// A tape admitted by a smaller class is also admitted by a larger one, but the
/// declared class is part of the function identity: the same tape under two
/// classes is two different functions.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeClassV1")]
pub enum RamLfeClassV1 {
    /// `affine.v1`: no ciphertext multiplication and no refresh.
    Affine,
    /// `bounded.v1`: all eleven instructions within a bounded logical rank.
    Bounded,
    // TODO(R.9, C.8): only membership and the canonical refresh schedule exist for
    // this class. No refresh runs between segments until R.9 delivers the class on the
    // shared bootstrap arithmetic of C.8.
    /// `refresh.v1`: bounded semantics plus refresh between rank-bounded segments.
    Refresh,
}

impl RamLfeClassV1 {
    /// Every class, smallest first.
    pub const ALL: [Self; 3] = [Self::Affine, Self::Bounded, Self::Refresh];

    /// Stable class identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Affine => "affine.v1",
            Self::Bounded => "bounded.v1",
            Self::Refresh => "refresh.v1",
        }
    }

    /// Return whether the class admits an opcode.
    #[must_use]
    pub const fn admits(self, opcode: RamLfeOpcodeV1) -> bool {
        match self {
            Self::Affine => !matches!(opcode, RamLfeOpcodeV1::Mul | RamLfeOpcodeV1::SelectEqZero),
            Self::Bounded | Self::Refresh => true,
        }
    }

    /// Maximum logical rank of any value, between refreshes where they exist.
    #[must_use]
    pub const fn max_rank(self) -> u16 {
        match self {
            Self::Affine => 0,
            Self::Bounded => RAM_LFE_V1_BOUNDED_MAX_RANK,
            Self::Refresh => RAM_LFE_V1_REFRESH_MAX_RANK_BETWEEN_REFRESHES,
        }
    }

    /// Maximum number of refreshes in one execution.
    #[must_use]
    pub const fn max_refreshes(self) -> u16 {
        match self {
            Self::Affine | Self::Bounded => 0,
            Self::Refresh => RAM_LFE_V1_REFRESH_MAX_REFRESHES,
        }
    }

    /// Check that a hidden program is a member of this class.
    ///
    /// The returned report and the error positions describe the hidden tape.
    /// They belong to the program owner and must not reach a public refusal.
    ///
    /// # Errors
    /// Returns a structural error for a malformed tape,
    /// [`RamLfeError::InstructionOutsideClass`] for an instruction the class
    /// does not admit, [`RamLfeError::ClassRankExceeded`] when a value exceeds
    /// the class rank and [`RamLfeError::ClassRefreshLimitExceeded`] when the
    /// canonical refresh schedule needs more refreshes than the class allows.
    pub fn membership(
        self,
        program: &HiddenRamFheProgram,
    ) -> Result<RamLfeClassReportV1, RamLfeError> {
        super::validate_hidden_program_structure(program)?;
        account(self, program)
    }
}

impl fmt::Display for RamLfeClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One refresh of the canonical `refresh.v1` schedule.
///
/// The named register is refreshed in place immediately before the named
/// instruction executes. Refresh is the identity on plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamLfeRefreshPointV1 {
    /// Index of the instruction that required the refresh.
    pub instruction: u16,
    /// Register refreshed before that instruction.
    pub register: u16,
}

/// Private structural accounting of one hidden program under one class.
///
/// Counts, ranks and refresh points are functions of the hidden tape. The owner
/// never prints them. Its refresh schedule is a heap buffer cleared on drop. Its
/// four scalar counts are plain fields: they are cleared when the report drops,
/// and a move of the report copies them.
pub struct RamLfeClassReportV1 {
    class: RamLfeClassV1,
    instruction_count: u16,
    output_count: u16,
    peak_rank: u16,
    ciphertext_multiplications: u32,
    // Flat `(instruction, register)` pairs in schedule order.
    refresh_points: Zeroizing<Vec<u16>>,
}

impl RamLfeClassReportV1 {
    /// Class the program was checked against.
    #[must_use]
    pub const fn class(&self) -> RamLfeClassV1 {
        self.class
    }

    /// Number of tape instructions.
    #[must_use]
    pub const fn instruction_count(&self) -> u16 {
        self.instruction_count
    }

    /// Number of ordered outputs.
    #[must_use]
    pub const fn output_count(&self) -> u16 {
        self.output_count
    }

    /// Highest logical rank any value reached between refreshes.
    #[must_use]
    pub const fn peak_rank(&self) -> u16 {
        self.peak_rank
    }

    /// Ciphertext multiplications: one per `Mul`, ten per `SelectEqZero`.
    #[must_use]
    pub const fn ciphertext_multiplications(&self) -> u32 {
        self.ciphertext_multiplications
    }

    /// Number of refreshes in the canonical schedule.
    #[must_use]
    pub fn refresh_count(&self) -> u16 {
        u16::try_from(self.refresh_points.len() / 2).expect("bounded refresh schedule")
    }

    /// Iterate over the canonical refresh schedule in execution order.
    pub fn refresh_points(&self) -> impl ExactSizeIterator<Item = RamLfeRefreshPointV1> + '_ {
        self.refresh_points
            .chunks_exact(2)
            .map(|pair| RamLfeRefreshPointV1 {
                instruction: pair[0],
                register: pair[1],
            })
    }
}

impl fmt::Debug for RamLfeClassReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED RAM-LFE class report]")
    }
}

impl Drop for RamLfeClassReportV1 {
    fn drop(&mut self) {
        self.instruction_count.zeroize();
        self.output_count.zeroize();
        self.peak_rank.zeroize();
        self.ciphertext_multiplications.zeroize();
    }
}

/// Rank bookkeeping for one structurally valid tape.
struct Accounting {
    class: RamLfeClassV1,
    registers: Zeroizing<[u16; RAM_LFE_V1_REGISTERS]>,
    lanes: Zeroizing<[u16; RAM_LFE_V1_STATE_LANES]>,
    report: RamLfeClassReportV1,
}

impl Accounting {
    fn new(class: RamLfeClassV1, instruction_count: u16) -> Result<Self, RamLfeError> {
        let mut refresh_points = Zeroizing::new(Vec::new());
        refresh_points
            .try_reserve_exact(usize::from(class.max_refreshes()) * 2)
            .map_err(|error| {
                super::invalid_program_error(&format!("class report allocation failed: {error}"))
            })?;
        Ok(Self {
            class,
            registers: Zeroizing::new([0; RAM_LFE_V1_REGISTERS]),
            lanes: Zeroizing::new([0; RAM_LFE_V1_STATE_LANES]),
            report: RamLfeClassReportV1 {
                class,
                instruction_count,
                output_count: 0,
                peak_rank: 0,
                ciphertext_multiplications: 0,
                refresh_points,
            },
        })
    }

    fn register(&self, index: u16) -> u16 {
        self.registers[usize::from(index)]
    }

    fn set(&mut self, register: u16, rank: u16) {
        self.registers[usize::from(register)] = rank;
        self.report.peak_rank = self.report.peak_rank.max(rank);
    }

    /// Rank of a multiplication result from `(register, added rank)` operands.
    fn product_rank(&self, operands: &[(u16, u16)]) -> u16 {
        operands
            .iter()
            .map(|&(register, added)| self.register(register).saturating_add(added))
            .max()
            .unwrap_or(0)
    }

    /// Apply the class rank rule, refreshing operands where the class allows it.
    ///
    /// Operands are refreshed before the destination is written, so a
    /// destination that aliases an operand sees the refreshed operand.
    fn multiply(
        &mut self,
        instruction: usize,
        destination: u16,
        operands: &[(u16, u16)],
        multiplications: u32,
    ) -> Result<(), RamLfeError> {
        let limit = self.class.max_rank();
        let mut rank = self.product_rank(operands);
        if rank > limit && self.class.max_refreshes() > 0 {
            for (position, &(register, _)) in operands.iter().enumerate() {
                let repeated = operands[..position]
                    .iter()
                    .any(|&(earlier, _)| earlier == register);
                if repeated || self.register(register) == 0 {
                    continue;
                }
                if self.report.refresh_count() == self.class.max_refreshes() {
                    return Err(RamLfeError::ClassRefreshLimitExceeded {
                        class: self.class,
                        instruction,
                        limit: self.class.max_refreshes(),
                    });
                }
                self.registers[usize::from(register)] = 0;
                self.report.refresh_points.extend_from_slice(&[
                    u16::try_from(instruction).expect("bounded tape index"),
                    register,
                ]);
            }
            rank = self.product_rank(operands);
        }
        if rank > limit {
            return Err(RamLfeError::ClassRankExceeded {
                class: self.class,
                instruction,
                rank,
                limit,
            });
        }
        self.report.ciphertext_multiplications = self
            .report
            .ciphertext_multiplications
            .saturating_add(multiplications);
        self.set(destination, rank);
        Ok(())
    }

    fn step(
        &mut self,
        instruction: usize,
        value: HiddenRamFheInstruction,
    ) -> Result<(), RamLfeError> {
        use HiddenRamFheInstruction as Op;
        let opcode = value.opcode();
        if !self.class.admits(opcode) {
            return Err(RamLfeError::InstructionOutsideClass {
                class: self.class,
                instruction,
                opcode,
            });
        }
        match value {
            Op::LoadInput(destination, _) | Op::LoadConst(destination, _) => {
                self.set(destination, 0);
            }
            Op::LoadState(destination, lane) => {
                let rank = self.lanes[usize::from(lane)];
                self.set(destination, rank);
            }
            Op::StoreState(lane, source) => {
                self.lanes[usize::from(lane)] = self.register(source);
            }
            Op::Add(destination, lhs, rhs) => {
                let rank = self.register(lhs).max(self.register(rhs));
                self.set(destination, rank);
            }
            Op::AddPlain(destination, source, _)
            | Op::SubPlain(destination, source, _)
            | Op::MulPlain(destination, source, _) => {
                let rank = self.register(source);
                self.set(destination, rank);
            }
            Op::Mul(destination, lhs, rhs) => {
                self.multiply(instruction, destination, &[(lhs, 1), (rhs, 1)], 1)?;
            }
            Op::SelectEqZero(destination, condition, if_zero, if_non_zero) => {
                self.multiply(
                    instruction,
                    destination,
                    &[
                        (condition, RAM_LFE_V1_SELECT_CONDITION_RANK),
                        (if_zero, RAM_LFE_V1_SELECT_BRANCH_RANK),
                        (if_non_zero, RAM_LFE_V1_SELECT_BRANCH_RANK),
                    ],
                    u32::from(RAM_LFE_V1_SELECT_CONDITION_RANK),
                )?;
            }
            Op::Output(_) => {
                self.report.output_count = self.report.output_count.saturating_add(1);
            }
        }
        Ok(())
    }
}

/// Account one structurally valid tape under one class.
fn account(
    class: RamLfeClassV1,
    program: &HiddenRamFheProgram,
) -> Result<RamLfeClassReportV1, RamLfeError> {
    let instruction_count =
        u16::try_from(program.instruction_count()).expect("structurally bounded tape");
    let mut accounting = Accounting::new(class, instruction_count)?;
    for (instruction, value) in program.instructions().enumerate() {
        accounting.step(instruction, value)?;
    }
    let Accounting { report, .. } = accounting;
    Ok(report)
}

#[cfg(test)]
#[path = "class_tests.rs"]
mod tests;
