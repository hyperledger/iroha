//! Aggregate fixed-topology AIR for the native private-note relation.
//!
//! The circuit keeps every intermediate SHA-256 digest private.  A fixed
//! byte-copy permutation connects note fields, hash inputs and outputs,
//! accumulator children, value arithmetic, and VM state.  Public statement
//! bytes are fixed constraints at their final endpoints only.
use super::{
    codec::{PRIVATE_PROGRAM_BYTES_V1, decode_private_program_v1, encode_private_program_v1},
    relation::{
        ACCUMULATOR_LEAF_DOMAIN_V1, ACCUMULATOR_NODE_DOMAIN_V1, AUDIT_INPUT_OPENINGS_DOMAIN_V1,
        HASH_FRAME_DOMAIN_V1, IvmPrivateNoteWitnessV1, NOTE_AUTHORITY_DOMAIN_V1,
        NOTE_COMMITMENT_DOMAIN_V1, NOTE_NULLIFIER_DOMAIN_V1, PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1,
        PRIVATE_NOTE_TREE_DEPTH_V1, PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1, PROGRAM_ID_DOMAIN_V1,
        PrivateInstructionV1, PrivateNoteRelationProfileV1, PrivateOpcodeV1,
        Sha256InvocationRoleV1, Sha256InvocationV1, namespace_v1, public_balance_sides,
        validate_private_note_relation_with_profile_v1, validate_statement_with_profile_v1,
    },
};
use crate::privacy_engines::transparent_stark::{GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F};
use iroha_data_model::privacy::IrohaIvmPrivateNoteStarkStatementV1;
use std::collections::BTreeMap;
use thiserror::Error;
pub const PRIVATE_NOTE_TRACE_LOG2_V1: u8 = 14;
pub const PRIVATE_NOTE_TRACE_SIZE_V1: usize = 1 << PRIVATE_NOTE_TRACE_LOG2_V1;
pub(super) const PRIVATE_NOTE_COPY_WIDTH_V1: usize = 8;
pub(super) const PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1: usize = 64;
pub(super) const PRIVATE_NOTE_SHA_STATE_WORDS_V1: usize = 8;
pub(super) const PRIVATE_NOTE_SHA_BIT_GROUPS_V1: usize = 11;
pub(super) const PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1: usize = 32;
pub(super) const PRIVATE_NOTE_SHA_BIT_COLUMNS_V1: usize =
    PRIVATE_NOTE_SHA_BIT_GROUPS_V1 * PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1;
pub(super) const COPY_OFFSET: usize = 0;
pub(super) const SHA_SCHEDULE_OFFSET: usize = COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1;
pub(super) const SHA_INITIAL_STATE_OFFSET: usize =
    SHA_SCHEDULE_OFFSET + PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1;
pub(super) const SHA_STATE_OFFSET: usize =
    SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1;
pub(super) const SHA_BITS_OFFSET: usize = SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1;
pub(super) const SHA_T1_OFFSET: usize = SHA_BITS_OFFSET + PRIVATE_NOTE_SHA_BIT_COLUMNS_V1;
pub(super) const SHA_T2_OFFSET: usize = SHA_T1_OFFSET + 1;
pub(super) const SHA_CARRY_OFFSET: usize = SHA_T2_OFFSET + 1;
pub(super) const SHA_CARRY_WIDTH: usize = 18;
pub(super) const SCRATCH_OFFSET: usize = SHA_CARRY_OFFSET + SHA_CARRY_WIDTH;
pub(super) const SCRATCH_WIDTH: usize = 96;
pub const PRIVATE_NOTE_BASE_WIDTH_V1: usize = SCRATCH_OFFSET + SCRATCH_WIDTH;
pub(super) const SCRATCH_NONZERO_BYTE_SELECT_OFFSET: usize = SCRATCH_OFFSET;
pub(super) const SCRATCH_NONZERO_BIT_SELECT_OFFSET: usize =
    SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1;
pub(super) const SCRATCH_BYTE_BITS_OFFSET: usize = SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8;
pub(super) const SCRATCH_RUNNING_BEFORE: usize = SCRATCH_BYTE_BITS_OFFSET + 8;
pub(super) const SCRATCH_RUNNING_AFTER: usize = SCRATCH_RUNNING_BEFORE + 1;
pub(super) const SCRATCH_RELATION_CARRY_BEFORE: usize = SCRATCH_RUNNING_AFTER + 1;
pub(super) const SCRATCH_RELATION_CARRY_AFTER: usize = SCRATCH_RELATION_CARRY_BEFORE + 1;
pub(super) const SCRATCH_RELATION_CARRY_BITS_OFFSET: usize = SCRATCH_RELATION_CARRY_AFTER + 1;
pub(super) const SCRATCH_VM_OPCODE_SELECT_OFFSET: usize = SCRATCH_RELATION_CARRY_BITS_OFFSET + 2;
pub(super) const SCRATCH_VM_DESTINATION_SELECT_OFFSET: usize = SCRATCH_VM_OPCODE_SELECT_OFFSET + 9;
pub(super) const SCRATCH_VM_LEFT_SELECT_OFFSET: usize = SCRATCH_VM_DESTINATION_SELECT_OFFSET + 8;
pub(super) const SCRATCH_VM_RIGHT_SELECT_OFFSET: usize = SCRATCH_VM_LEFT_SELECT_OFFSET + 8;
pub(super) const SCRATCH_VM_IMMEDIATE_OFFSET: usize = SCRATCH_VM_RIGHT_SELECT_OFFSET + 8;
pub(super) const SCRATCH_VM_HALTED_BEFORE: usize = SCRATCH_VM_IMMEDIATE_OFFSET + 4;
pub(super) const SCRATCH_VM_HALTED_AFTER: usize = SCRATCH_VM_HALTED_BEFORE + 1;
pub(super) const SCRATCH_VM_CARRY_BEFORE: usize = SCRATCH_VM_HALTED_AFTER + 1;
pub(super) const SCRATCH_VM_CARRY_AFTER: usize = SCRATCH_VM_CARRY_BEFORE + 1;
pub(super) const SCRATCH_VM_DIFFERENCE: usize = SCRATCH_VM_CARRY_AFTER + 1;
pub(super) const SCRATCH_VM_RESULT: usize = SCRATCH_VM_DIFFERENCE + 1;
pub(super) const SCRATCH_VM_RESULT_BITS_OFFSET: usize = SCRATCH_VM_RESULT + 1;
pub(super) const SCRATCH_VM_DIFFERENCE_BITS_OFFSET: usize = SCRATCH_VM_RESULT_BITS_OFFSET + 8;
pub(super) const SHA256_INITIAL_STATE_V1: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
pub(super) const SHA256_ROUND_CONSTANTS_V1: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];
/// Stable aggregate AIR descriptor.
pub const IVM_PRIVATE_NOTE_AGGREGATE_AIR_DESCRIPTOR_V1: &[u8] = b"ivm-private-note-aggregate-air-v1:trace=16384:copy-width=8:copy-lanes=3:sha256-wide-round64-private-io:value=u128-byte-carry:vm=fixed16-private-opcode-byte-state:tree=depth32-private-direction";
/// Aggregate trace construction or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(super) enum IvmPrivateNoteAirErrorV1 {
    #[error("private-note AIR relation is invalid")]
    Relation,
    #[error("private-note AIR topology is invalid")]
    Topology,
    #[error("private-note AIR byte assignment is inconsistent")]
    Assignment,
    #[error("private-note AIR resource bound is exceeded")]
    Resource,
    #[error("private-note AIR SHA-256 schedule is invalid")]
    Sha256,
    #[error("private-note AIR copy permutation is invalid")]
    Copy,
}
include!("../shared_note_air.rs");
define_note_air_trace_core_v1! {
    error: IvmPrivateNoteAirErrorV1,
    role: Sha256InvocationRoleV1,
    fixed_row: PrivateNoteFixedRowV1,
    base_width: PRIVATE_NOTE_BASE_WIDTH_V1,
    copy_width: PRIVATE_NOTE_COPY_WIDTH_V1,
    sha_bits_per_group: PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1,
    tree_depth: PRIVATE_NOTE_TREE_DEPTH_V1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(variant_size_differences)]
pub(super) enum PrivateNoteFixedRowV1 {
    ShaRound {
        round: u8,
        invocation: u8,
        block: u8,
        block_count: u8,
    },
    ShaEnd {
        invocation: u8,
        block: u8,
        block_count: u8,
        digest_chunk: u8,
        public_digest: Option<[u8; 32]>,
    },
    NodeSelect {
        input: u8,
        level: u8,
        byte: u8,
    },
    Membership {
        input: u8,
        value_byte: u8,
        root_chunk: u8,
    },
    Distinct {
        comparison: u8,
        chunk: u8,
        chunks: u8,
    },
    NonZero {
        component: u16,
        chunk: u8,
        chunks: u8,
    },
    Sum {
        side: SumSideV1,
        byte: u8,
    },
    VmHeader,
    VmProgram {
        instruction: u8,
    },
    VmPrevious {
        instruction: u8,
        byte: u8,
    },
    VmNext {
        instruction: u8,
        byte: u8,
    },
    Padding,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SumSideV1 {
    Inputs,
    Outputs,
    Conservation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PrivateNoteFixedTraceV1 {
    pub(super) rows: Vec<PrivateNoteFixedRowV1>,
    copy_cells: Vec<[CopyCellV1; PRIVATE_NOTE_COPY_WIDTH_V1]>,
    pub(super) copy_sigma: Vec<[u32; PRIVATE_NOTE_COPY_WIDTH_V1]>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrivateNoteBaseTraceV1 {
    pub(super) fixed: PrivateNoteFixedTraceV1,
    pub(super) rows: Vec<Vec<F>>,
}
impl core::fmt::Debug for PrivateNoteBaseTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PrivateNoteBaseTraceV1")
            .field("row_count", &self.rows.len())
            .field("witness_columns", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
struct NoteVariablesV1 {
    value: [ByteVariableV1; 16],
    authority: [ByteVariableV1; 32],
    rho: [ByteVariableV1; 32],
    blinding: [ByteVariableV1; 32],
    memo: [ByteVariableV1; 32],
}
#[derive(Clone)]
struct InputVariablesV1 {
    note: NoteVariablesV1,
    secret: [ByteVariableV1; 32],
    position_bits: [ByteVariableV1; 32],
    path: [[ByteVariableV1; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
    commitment: Option<[ByteVariableV1; 32]>,
}
#[derive(Clone)]
struct OutputVariablesV1 {
    note: NoteVariablesV1,
    commitment: Option<[ByteVariableV1; 32]>,
}
struct TraceBuilderV1<'a> {
    statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
    witness: Option<&'a IvmPrivateNoteWitnessV1>,
    assignment: Vec<u8>,
    rows: Vec<Vec<F>>,
    fixed_rows: Vec<PrivateNoteFixedRowV1>,
    copy_cells: Vec<[CopyCellV1; PRIVATE_NOTE_COPY_WIDTH_V1]>,
    hash_invocation_count: usize,
    invocation_oracle: Vec<Sha256InvocationV1>,
    invocation_cursor: usize,
    expected_final_registers: Option<[u128; 8]>,
}
impl<'a> TraceBuilderV1<'a> {
    fn new(
        statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        witness: Option<&'a IvmPrivateNoteWitnessV1>,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteAirErrorV1> {
        let (invocation_oracle, expected_final_registers) = if let Some(witness) = witness {
            let relation =
                validate_private_note_relation_with_profile_v1(statement, witness, profile)
                    .map_err(|_| IvmPrivateNoteAirErrorV1::Relation)?;
            (relation.invocations, Some(relation.final_registers))
        } else {
            (Vec::new(), None)
        };
        Ok(Self {
            statement,
            witness,
            assignment: Vec::new(),
            rows: Vec::new(),
            fixed_rows: Vec::new(),
            copy_cells: Vec::new(),
            hash_invocation_count: 0,
            invocation_oracle,
            invocation_cursor: 0,
            expected_final_registers,
        })
    }
    fn next_oracle_digest(
        &self,
        role: Sha256InvocationRoleV1,
    ) -> Result<[u8; 32], IvmPrivateNoteAirErrorV1> {
        if self.witness.is_none() {
            return Ok([0; 32]);
        }
        self.invocation_oracle
            .get(self.invocation_cursor)
            .filter(|invocation| invocation.role == role)
            .map(|invocation| invocation.digest)
            .ok_or(IvmPrivateNoteAirErrorV1::Topology)
    }
    fn allocate_note(
        &mut self,
        note: Option<super::relation::PrivateNotePlaintextV1>,
    ) -> NoteVariablesV1 {
        let note = note.unwrap_or(super::relation::PrivateNotePlaintextV1 {
            value: 0,
            spending_authority: [0; 32],
            rho: [0; 32],
            blinding: [0; 32],
            memo_digest: [0; 32],
        });
        NoteVariablesV1 {
            value: self.allocate_bytes(note.value.to_be_bytes()),
            authority: self.allocate_bytes(note.spending_authority),
            rho: self.allocate_bytes(note.rho),
            blinding: self.allocate_bytes(note.blinding),
            memo: self.allocate_bytes(note.memo_digest),
        }
    }
    fn push_conditional_membership(
        &mut self,
        input: u8,
        value: [ByteVariableV1; 16],
        root: [ByteVariableV1; 32],
    ) -> Result<(), IvmPrivateNoteAirErrorV1> {
        // Each value byte is already range constrained by its SHA preimage.
        // Requiring v_j (root_k - public_k) = 0 for every j,k enforces
        // membership whenever any byte is nonzero, with no free selector.
        // Three root pairs share each row's value byte and eight copy cells.
        for (value_byte, value_variable) in value.into_iter().enumerate() {
            for root_chunk in 0..32_usize.div_ceil(3) {
                let mut cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
                cells[0] = CopyCellV1::Variable(value_variable);
                for pair in 0..3 {
                    let byte = root_chunk * 3 + pair;
                    if byte < root.len() {
                        cells[1 + pair * 2] = CopyCellV1::Variable(root[byte]);
                        cells[2 + pair * 2] =
                            CopyCellV1::Constant(self.statement.state_root.as_bytes()[byte]);
                    }
                }
                self.push_row(
                    PrivateNoteFixedRowV1::Membership {
                        input,
                        value_byte: u8::try_from(value_byte)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                        root_chunk: u8::try_from(root_chunk)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                    },
                    cells,
                    Self::empty_row(),
                )?;
            }
        }
        Ok(())
    }
    fn push_distinct(
        &mut self,
        comparison: u8,
        left: &[ByteVariableV1],
        right: &[ByteVariableV1],
    ) -> Result<(), IvmPrivateNoteAirErrorV1> {
        const PAIRS_PER_ROW: usize = PRIVATE_NOTE_COPY_WIDTH_V1 / 2;
        if left.is_empty() || left.len() != right.len() || left.len() > 32 {
            return Err(IvmPrivateNoteAirErrorV1::Topology);
        }
        let chunks = left.len().div_ceil(PAIRS_PER_ROW);
        let selected = left
            .iter()
            .zip(right)
            .position(|(left, right)| self.assignment[left.0] != self.assignment[right.0]);
        if self.witness.is_some() && selected.is_none() {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
        let mut running = 0_u8;
        for chunk in 0..chunks {
            let start = chunk * PAIRS_PER_ROW;
            let end = (start + PAIRS_PER_ROW).min(left.len());
            let mut cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
            for pair in start..end {
                let within = pair - start;
                cells[within * 2] = CopyCellV1::Variable(left[pair]);
                cells[within * 2 + 1] = CopyCellV1::Variable(right[pair]);
            }
            let mut row = Self::empty_row();
            row[SCRATCH_RUNNING_BEFORE] = F(u64::from(running));
            if let Some(selected) = selected
                && (start..end).contains(&selected)
            {
                let within = selected - start;
                let left_byte = self.assignment[left[selected].0];
                let right_byte = self.assignment[right[selected].0];
                let selected_bit = (left_byte ^ right_byte).trailing_zeros() as usize;
                row[SCRATCH_NONZERO_BYTE_SELECT_OFFSET + within] = F::ONE;
                row[SCRATCH_NONZERO_BIT_SELECT_OFFSET + selected_bit] = F::ONE;
                for bit in 0..8 {
                    row[SCRATCH_BYTE_BITS_OFFSET + bit] = F(u64::from((left_byte >> bit) & 1));
                    row[SCRATCH_VM_DIFFERENCE_BITS_OFFSET + bit] =
                        F(u64::from((right_byte >> bit) & 1));
                }
                running = 1;
            }
            row[SCRATCH_RUNNING_AFTER] = F(u64::from(running));
            self.push_row(
                PrivateNoteFixedRowV1::Distinct {
                    comparison,
                    chunk: u8::try_from(chunk).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                    chunks: u8::try_from(chunks).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                },
                cells,
                row,
            )?;
        }
        Ok(())
    }
    fn assigned_u128(
        &self,
        variables: &[ByteVariableV1; 16],
    ) -> Result<u128, IvmPrivateNoteAirErrorV1> {
        let bytes = core::array::from_fn(|index| {
            self.assignment
                .get(variables[index].0)
                .copied()
                .unwrap_or_default()
        });
        if variables
            .iter()
            .any(|variable| self.assignment.get(variable.0).is_none())
        {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
        Ok(u128::from_be_bytes(bytes))
    }
    fn push_sum_up_to_three(
        &mut self,
        side: SumSideV1,
        operands: &[[ByteVariableV1; 16]],
        sum: u128,
    ) -> Result<[ByteVariableV1; 16], IvmPrivateNoteAirErrorV1> {
        match operands.len() {
            1 | 2 => self.push_sum(side, operands, sum),
            PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1 => {
                let prefix_sum = self
                    .assigned_u128(&operands[0])?
                    .checked_add(self.assigned_u128(&operands[1])?)
                    .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
                let prefix = self.push_sum(side, &operands[..2], prefix_sum)?;
                self.push_sum(side, &[prefix, operands[2]], sum)
            }
            _ => Err(IvmPrivateNoteAirErrorV1::Topology),
        }
    }
    fn push_conservation(
        &mut self,
        input_sum: [ByteVariableV1; 16],
        output_sum: [ByteVariableV1; 16],
    ) -> Result<(), IvmPrivateNoteAirErrorV1> {
        let (public_in, public_out) = public_balance_sides(self.statement.value_balance);
        let public_in = public_in.to_be_bytes();
        let public_out = public_out.to_be_bytes();
        let mut carry = 0_i16;
        for little_byte in 0..16 {
            let byte = 15 - little_byte;
            let left =
                i16::from(self.assignment[input_sum[byte].0]) + i16::from(public_in[byte]) + carry;
            let right =
                i16::from(self.assignment[output_sum[byte].0]) + i16::from(public_out[byte]);
            let difference = left - right;
            if self.witness.is_some() && difference.rem_euclid(256) != 0 {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
            let next_carry = difference.div_euclid(256);
            if !(-1..=1).contains(&next_carry) {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
            let cells = [
                CopyCellV1::Variable(input_sum[byte]),
                CopyCellV1::Variable(output_sum[byte]),
                CopyCellV1::Constant(public_in[byte]),
                CopyCellV1::Constant(public_out[byte]),
                CopyCellV1::Inactive,
                CopyCellV1::Inactive,
                CopyCellV1::Inactive,
                CopyCellV1::Inactive,
            ];
            let mut row = Self::empty_row();
            row[SCRATCH_RELATION_CARRY_BEFORE] = signed_small_field(carry);
            row[SCRATCH_RELATION_CARRY_AFTER] = signed_small_field(next_carry);
            self.push_row(
                PrivateNoteFixedRowV1::Sum {
                    side: SumSideV1::Conservation,
                    byte: u8::try_from(little_byte)
                        .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                },
                cells,
                row,
            )?;
            carry = next_carry;
        }
        if self.witness.is_some() && carry != 0 {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
        Ok(())
    }
    fn write_vm_scratch(
        row: &mut [F],
        instruction: PrivateInstructionV1,
        halted_before: bool,
        halted_after: bool,
    ) {
        row[SCRATCH_VM_OPCODE_SELECT_OFFSET + instruction.opcode as usize] = F::ONE;
        row[SCRATCH_VM_DESTINATION_SELECT_OFFSET + usize::from(instruction.destination)] = F::ONE;
        row[SCRATCH_VM_LEFT_SELECT_OFFSET + usize::from(instruction.left)] = F::ONE;
        row[SCRATCH_VM_RIGHT_SELECT_OFFSET + usize::from(instruction.right)] = F::ONE;
        for (index, byte) in instruction.immediate.to_be_bytes().into_iter().enumerate() {
            row[SCRATCH_VM_IMMEDIATE_OFFSET + index] = F(u64::from(byte));
        }
        row[SCRATCH_VM_HALTED_BEFORE] = F(u64::from(halted_before));
        row[SCRATCH_VM_HALTED_AFTER] = F(u64::from(halted_after));
    }
    fn execute_vm_states(
        &self,
        instructions: [PrivateInstructionV1; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1],
        input_sum: u128,
        output_sum: u128,
    ) -> Result<Vec<[u128; 8]>, IvmPrivateNoteAirErrorV1> {
        let (public_in, public_out) = public_balance_sides(self.statement.value_balance);
        let mut state = [
            input_sum,
            output_sum,
            public_in,
            public_out,
            0,
            u128::from(self.statement.execution_epoch),
            0,
            1,
        ];
        let mut states = Vec::with_capacity(PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1 + 1);
        states.push(state);
        for instruction in instructions {
            let destination = usize::from(instruction.destination);
            let left = usize::from(instruction.left);
            let right = usize::from(instruction.right);
            match instruction.opcode {
                PrivateOpcodeV1::Halt => {}
                PrivateOpcodeV1::MoveImmediate => {
                    state[destination] = u128::from(instruction.immediate);
                }
                PrivateOpcodeV1::Move => state[destination] = state[left],
                PrivateOpcodeV1::AddChecked => {
                    state[destination] = state[left]
                        .checked_add(state[right])
                        .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
                }
                PrivateOpcodeV1::SubChecked => {
                    state[destination] = state[left]
                        .checked_sub(state[right])
                        .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
                }
                PrivateOpcodeV1::AssertEqual => {
                    if state[left] != state[right] {
                        return Err(IvmPrivateNoteAirErrorV1::Assignment);
                    }
                }
                PrivateOpcodeV1::AssertLessOrEqual => {
                    if state[left] > state[right] {
                        return Err(IvmPrivateNoteAirErrorV1::Assignment);
                    }
                }
                PrivateOpcodeV1::LoadActionLimb => {
                    let start = usize::try_from(instruction.immediate)
                        .map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?
                        .checked_mul(16)
                        .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
                    let limb = self
                        .statement
                        .action_digest
                        .as_bytes()
                        .get(start..start + 16)
                        .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
                    state[destination] = u128::from_be_bytes(
                        limb.try_into()
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?,
                    );
                }
                PrivateOpcodeV1::LoadExecutionEpoch => {
                    state[destination] = u128::from(self.statement.execution_epoch);
                }
            }
            states.push(state);
        }
        Ok(states)
    }
    fn push_vm(
        &mut self,
        program_variables: &[ByteVariableV1; super::codec::PRIVATE_PROGRAM_BYTES_V1],
        input_sum_variables: [ByteVariableV1; 16],
        output_sum_variables: [ByteVariableV1; 16],
        input_sum: u128,
        output_sum: u128,
    ) -> Result<(), IvmPrivateNoteAirErrorV1> {
        let instructions = self.witness.map_or(
            [PrivateInstructionV1::HALT; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1],
            |witness| witness.program.instructions,
        );
        let states = self.execute_vm_states(instructions, input_sum, output_sum)?;
        if self
            .expected_final_registers
            .is_some_and(|expected| states.last().copied() != Some(expected))
        {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
        let (public_in, public_out) = public_balance_sides(self.statement.value_balance);
        let initial_constants = [
            None,
            None,
            Some(public_in.to_be_bytes()),
            Some(public_out.to_be_bytes()),
            Some(0_u128.to_be_bytes()),
            Some(u128::from(self.statement.execution_epoch).to_be_bytes()),
            Some(0_u128.to_be_bytes()),
            Some(1_u128.to_be_bytes()),
        ];
        let mut registers: [[ByteExpressionV1; 16]; 8] = [[ByteExpressionV1::Constant(0); 16]; 8];
        registers[0] = input_sum_variables.map(ByteExpressionV1::Variable);
        registers[1] = output_sum_variables.map(ByteExpressionV1::Variable);
        for register in 2..8 {
            let bytes = initial_constants[register].ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
            registers[register] = bytes.map(ByteExpressionV1::Constant);
        }
        let mut header_cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
        for (cell, variable) in header_cells.iter_mut().zip(&program_variables[..8]) {
            *cell = CopyCellV1::Variable(*variable);
        }
        self.push_row(
            PrivateNoteFixedRowV1::VmHeader,
            header_cells,
            Self::empty_row(),
        )?;
        let mut halted = false;
        for (instruction_index, instruction) in instructions.into_iter().enumerate() {
            let halted_before = halted;
            halted |= instruction.opcode == PrivateOpcodeV1::Halt;
            let program_offset = 8 + instruction_index * 8;
            let mut program_cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
            for (cell, variable) in program_cells
                .iter_mut()
                .zip(&program_variables[program_offset..program_offset + 8])
            {
                *cell = CopyCellV1::Variable(*variable);
            }
            let mut program_row = Self::empty_row();
            Self::write_vm_scratch(&mut program_row, instruction, halted_before, halted);
            self.push_row(
                PrivateNoteFixedRowV1::VmProgram {
                    instruction: u8::try_from(instruction_index)
                        .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                },
                program_cells,
                program_row,
            )?;
            let next_state = states[instruction_index + 1];
            let next_registers: [[ByteVariableV1; 16]; 8] = core::array::from_fn(|register| {
                self.allocate_bytes(next_state[register].to_be_bytes())
            });
            let left_value = states[instruction_index][usize::from(instruction.left)];
            let right_value = states[instruction_index][usize::from(instruction.right)];
            let difference = if instruction.opcode == PrivateOpcodeV1::AssertLessOrEqual {
                right_value
                    .checked_sub(left_value)
                    .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?
            } else {
                0
            };
            let difference_bytes = difference.to_be_bytes();
            let writes = matches!(
                instruction.opcode,
                PrivateOpcodeV1::MoveImmediate
                    | PrivateOpcodeV1::Move
                    | PrivateOpcodeV1::AddChecked
                    | PrivateOpcodeV1::SubChecked
                    | PrivateOpcodeV1::LoadActionLimb
                    | PrivateOpcodeV1::LoadExecutionEpoch
            );
            let mut carry = 0_u16;
            for little_byte in 0..16 {
                let byte = 15 - little_byte;
                let mut previous_cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
                for (cell, register) in previous_cells.iter_mut().zip(&registers) {
                    *cell = match register[byte] {
                        ByteExpressionV1::Constant(value) => CopyCellV1::Constant(value),
                        ByteExpressionV1::Variable(variable) => CopyCellV1::Variable(variable),
                    };
                }
                let mut previous_row = Self::empty_row();
                Self::write_vm_scratch(&mut previous_row, instruction, halted_before, halted);
                let mut previous_bytes = [0_u8; 8];
                for register in 0..8 {
                    previous_bytes[register] = registers[register][byte].value(&self.assignment)?;
                }
                let left_byte = previous_bytes[usize::from(instruction.left)];
                let right_byte = previous_bytes[usize::from(instruction.right)];
                let result = if writes {
                    next_state[usize::from(instruction.destination)].to_be_bytes()[byte]
                } else {
                    0
                };
                let wide = match instruction.opcode {
                    PrivateOpcodeV1::AddChecked => {
                        u16::from(left_byte) + u16::from(right_byte) + carry
                    }
                    PrivateOpcodeV1::SubChecked => {
                        u16::from(result) + u16::from(right_byte) + carry
                    }
                    PrivateOpcodeV1::AssertLessOrEqual => {
                        u16::from(difference_bytes[byte]) + u16::from(left_byte) + carry
                    }
                    _ => u16::from(result),
                };
                let next_carry = match instruction.opcode {
                    PrivateOpcodeV1::AddChecked => wide >> 8,
                    PrivateOpcodeV1::SubChecked => {
                        let left = u16::from(left_byte);
                        if self.witness.is_some() && (wide & 0xff) != left {
                            return Err(IvmPrivateNoteAirErrorV1::Assignment);
                        }
                        wide >> 8
                    }
                    PrivateOpcodeV1::AssertLessOrEqual => {
                        let right = u16::from(right_byte);
                        if self.witness.is_some() && (wide & 0xff) != right {
                            return Err(IvmPrivateNoteAirErrorV1::Assignment);
                        }
                        wide >> 8
                    }
                    _ => 0,
                };
                previous_row[SCRATCH_VM_CARRY_BEFORE] = F(u64::from(carry));
                previous_row[SCRATCH_VM_CARRY_AFTER] = F(u64::from(next_carry));
                previous_row[SCRATCH_VM_DIFFERENCE] = F(u64::from(difference_bytes[byte]));
                previous_row[SCRATCH_VM_RESULT] = F(u64::from(result));
                for bit in 0..8 {
                    previous_row[SCRATCH_VM_DIFFERENCE_BITS_OFFSET + bit] =
                        F(u64::from((difference_bytes[byte] >> bit) & 1));
                    previous_row[SCRATCH_VM_RESULT_BITS_OFFSET + bit] =
                        F(u64::from((result >> bit) & 1));
                }
                self.push_row(
                    PrivateNoteFixedRowV1::VmPrevious {
                        instruction: u8::try_from(instruction_index)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                        byte: u8::try_from(little_byte)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                    },
                    previous_cells,
                    previous_row,
                )?;
                let mut next_cells = [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1];
                for (cell, register) in next_cells.iter_mut().zip(&next_registers) {
                    *cell = CopyCellV1::Variable(register[byte]);
                }
                let mut next_row = Self::empty_row();
                Self::write_vm_scratch(&mut next_row, instruction, halted_before, halted);
                self.push_row(
                    PrivateNoteFixedRowV1::VmNext {
                        instruction: u8::try_from(instruction_index)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                        byte: u8::try_from(little_byte)
                            .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                    },
                    next_cells,
                    next_row,
                )?;
                carry = next_carry;
            }
            if self.witness.is_some()
                && matches!(
                    instruction.opcode,
                    PrivateOpcodeV1::AddChecked
                        | PrivateOpcodeV1::SubChecked
                        | PrivateOpcodeV1::AssertLessOrEqual
                )
                && carry != 0
            {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
            registers = next_registers.map(|register| register.map(ByteExpressionV1::Variable));
        }
        Ok(())
    }
}
fn note_commitment_fields(
    note: &NoteVariablesV1,
    fixed_memo_digest: Option<[u8; 32]>,
) -> Vec<Vec<ByteExpressionV1>> {
    vec![
        variables_as_expressions(&note.value),
        variables_as_expressions(&note.authority),
        variables_as_expressions(&note.rho),
        variables_as_expressions(&note.blinding),
        fixed_memo_digest.map_or_else(
            || variables_as_expressions(&note.memo),
            |memo| constants_as_expressions(&memo),
        ),
    ]
}
fn build_private_note_trace_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: Option<&IvmPrivateNoteWitnessV1>,
    profile: PrivateNoteRelationProfileV1,
) -> Result<PrivateNoteBaseTraceV1, IvmPrivateNoteAirErrorV1> {
    validate_statement_with_profile_v1(statement, profile)
        .map_err(|_| IvmPrivateNoteAirErrorV1::Relation)?;
    let mut builder = TraceBuilderV1::new(statement, witness, profile)?;
    let program_bytes = witness
        .map(|witness| encode_private_program_v1(&witness.program))
        .transpose()
        .map_err(|_| IvmPrivateNoteAirErrorV1::Relation)?
        .unwrap_or([0; super::codec::PRIVATE_PROGRAM_BYTES_V1]);
    let program_variables = builder.allocate_bytes(program_bytes);
    let mut input_variables = Vec::with_capacity(statement.nullifiers.len());
    for index in 0..statement.nullifiers.len() {
        let input = witness.and_then(|witness| witness.inputs.get(index));
        let note = builder.allocate_note(input.map(|input| input.note.clone()));
        let secret = builder.allocate_bytes(input.map_or([0; 32], |input| input.spending_secret));
        let position = input.map_or(0, |input| input.leaf_position);
        let position_bits =
            builder.allocate_bytes(core::array::from_fn(|bit| ((position >> bit) & 1) as u8));
        let path_bytes = input.map_or_else(dummy_path, |input| input.authentication_path);
        let path = core::array::from_fn(|level| builder.allocate_bytes(path_bytes[level]));
        input_variables.push(InputVariablesV1 {
            note,
            secret,
            position_bits,
            path,
            commitment: None,
        });
    }
    let mut output_variables = Vec::with_capacity(statement.output_commitments.len());
    for index in 0..statement.output_commitments.len() {
        let output = witness.and_then(|witness| witness.outputs.get(index));
        output_variables.push(OutputVariablesV1 {
            note: builder.allocate_note(output.map(|output| output.note.clone())),
            commitment: None,
        });
    }
    let program_digest = builder.allocate_bytes(*statement.program_id.as_bytes());
    let program_message = frame_expressions_v1(
        PROGRAM_ID_DOMAIN_V1,
        &[variables_as_expressions(&program_variables)],
    )?;
    builder.push_hash(
        Sha256InvocationRoleV1::Program,
        program_message,
        program_digest,
        Some(*statement.program_id.as_bytes()),
    )?;
    let namespace = norito::to_bytes(&namespace_v1(statement))
        .map_err(|_| IvmPrivateNoteAirErrorV1::Topology)?;
    let mut nonzero_components = Vec::<Vec<ByteVariableV1>>::new();
    for (index, input) in input_variables.iter_mut().enumerate() {
        let input_index = u8::try_from(index).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?;
        let authority_message = frame_expressions_v1(
            NOTE_AUTHORITY_DOMAIN_V1,
            &[variables_as_expressions(&input.secret)],
        )?;
        builder.push_hash(
            Sha256InvocationRoleV1::Authority { input: input_index },
            authority_message,
            input.note.authority,
            None,
        )?;
        let commitment_digest = builder
            .next_oracle_digest(Sha256InvocationRoleV1::InputCommitment { input: input_index })?;
        let commitment_variables = builder.allocate_bytes(commitment_digest);
        let commitment_message = frame_expressions_v1(
            NOTE_COMMITMENT_DOMAIN_V1,
            &note_commitment_fields(&input.note, None),
        )?;
        builder.push_hash(
            Sha256InvocationRoleV1::InputCommitment { input: input_index },
            commitment_message,
            commitment_variables,
            None,
        )?;
        input.commitment = Some(commitment_variables);
        let nullifier_variables = builder.allocate_bytes(*statement.nullifiers[index].as_bytes());
        let nullifier_message = frame_expressions_v1(
            NOTE_NULLIFIER_DOMAIN_V1,
            &[
                variables_as_expressions(&input.secret),
                variables_as_expressions(&input.note.rho),
                variables_as_expressions(&commitment_variables),
                constants_as_expressions(statement.pool_id.as_bytes()),
                constants_as_expressions(statement.program_id.as_bytes()),
            ],
        )?;
        builder.push_hash(
            Sha256InvocationRoleV1::Nullifier { input: input_index },
            nullifier_message,
            nullifier_variables,
            Some(*statement.nullifiers[index].as_bytes()),
        )?;
        let leaf_digest = builder
            .next_oracle_digest(Sha256InvocationRoleV1::AccumulatorLeaf { input: input_index })?;
        let mut current = builder.allocate_bytes(leaf_digest);
        let mut leaf_message = Vec::new();
        leaf_message.extend(constants_as_expressions(ACCUMULATOR_LEAF_DOMAIN_V1));
        leaf_message.extend(constants_as_expressions(
            &u64::try_from(namespace.len())
                .map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?
                .to_be_bytes(),
        ));
        leaf_message.extend(constants_as_expressions(&namespace));
        leaf_message.extend(variables_as_expressions(&commitment_variables));
        builder.push_hash(
            Sha256InvocationRoleV1::AccumulatorLeaf { input: input_index },
            leaf_message,
            current,
            None,
        )?;
        for level in 0..PRIVATE_NOTE_TREE_DEPTH_V1 {
            let level_u8 = u8::try_from(level).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?;
            let (left, right) = builder.push_node_select(
                input_index,
                level_u8,
                input.position_bits[level],
                current,
                input.path[level],
            )?;
            let digest = builder.next_oracle_digest(Sha256InvocationRoleV1::AccumulatorNode {
                input: input_index,
                level: level_u8,
            })?;
            let next = builder.allocate_bytes(digest);
            let mut node_message = Vec::new();
            node_message.extend(constants_as_expressions(ACCUMULATOR_NODE_DOMAIN_V1));
            node_message.push(ByteExpressionV1::Constant(level_u8));
            node_message.extend(variables_as_expressions(&left));
            node_message.extend(variables_as_expressions(&right));
            builder.push_hash(
                Sha256InvocationRoleV1::AccumulatorNode {
                    input: input_index,
                    level: level_u8,
                },
                node_message,
                next,
                (level + 1 == PRIVATE_NOTE_TREE_DEPTH_V1 && !profile.allows_zero_input_values())
                    .then_some(*statement.state_root.as_bytes()),
            )?;
            current = next;
        }
        if profile.allows_zero_input_values() {
            builder.push_conditional_membership(input_index, input.note.value, current)?;
        }
        if !profile.allows_zero_input_values() {
            nonzero_components.push(input.note.value.to_vec());
        }
        nonzero_components.push(input.note.authority.to_vec());
        nonzero_components.push(input.note.rho.to_vec());
        nonzero_components.push(input.note.blinding.to_vec());
        nonzero_components.push(input.secret.to_vec());
        for sibling in input.path {
            nonzero_components.push(sibling.to_vec());
        }
    }
    if let Some(expected) = profile.audit_input_commitment() {
        let fields = input_variables
            .iter()
            .flat_map(|input| note_commitment_fields(&input.note, None))
            .collect::<Vec<_>>();
        let message = frame_expressions_v1(AUDIT_INPUT_OPENINGS_DOMAIN_V1, &fields)?;
        let digest_variables = builder.allocate_bytes(expected);
        builder.push_hash(
            Sha256InvocationRoleV1::AuditInputOpenings,
            message,
            digest_variables,
            Some(expected),
        )?;
    }
    for (index, output) in output_variables.iter_mut().enumerate() {
        let output_index = u8::try_from(index).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?;
        let commitment_variables =
            builder.allocate_bytes(*statement.output_commitments[index].as_bytes());
        let commitment_message = frame_expressions_v1(
            NOTE_COMMITMENT_DOMAIN_V1,
            &note_commitment_fields(&output.note, profile.fixed_output_memo(index)),
        )?;
        builder.push_hash(
            Sha256InvocationRoleV1::OutputCommitment {
                output: output_index,
            },
            commitment_message,
            commitment_variables,
            Some(*statement.output_commitments[index].as_bytes()),
        )?;
        output.commitment = Some(commitment_variables);
        if !profile.allows_zero_output_values() {
            nonzero_components.push(output.note.value.to_vec());
        }
        nonzero_components.push(output.note.authority.to_vec());
        nonzero_components.push(output.note.rho.to_vec());
        nonzero_components.push(output.note.blinding.to_vec());
    }
    let mut comparison = 0_u8;
    if input_variables.len() == 2 {
        let left_commitment = input_variables[0]
            .commitment
            .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
        let right_commitment = input_variables[1]
            .commitment
            .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
        builder.push_distinct(comparison, &left_commitment, &right_commitment)?;
        comparison = comparison
            .checked_add(1)
            .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
        builder.push_distinct(
            comparison,
            &input_variables[0].position_bits,
            &input_variables[1].position_bits,
        )?;
        comparison = comparison
            .checked_add(1)
            .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
    }
    for input in &input_variables {
        let input_commitment = input.commitment.ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
        for output in &output_variables {
            let output_commitment = output
                .commitment
                .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
            builder.push_distinct(comparison, &input_commitment, &output_commitment)?;
            comparison = comparison
                .checked_add(1)
                .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
        }
    }
    for left in 0..output_variables.len() {
        for right in left + 1..output_variables.len() {
            let left_commitment = output_variables[left]
                .commitment
                .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
            let right_commitment = output_variables[right]
                .commitment
                .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
            builder.push_distinct(comparison, &left_commitment, &right_commitment)?;
            comparison = comparison
                .checked_add(1)
                .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
        }
    }
    for (component, variables) in nonzero_components.iter().enumerate() {
        builder.push_nonzero(
            u16::try_from(component).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
            variables,
        )?;
    }
    let input_values = input_variables
        .iter()
        .map(|input| input.note.value)
        .collect::<Vec<_>>();
    let output_values = output_variables
        .iter()
        .map(|output| output.note.value)
        .collect::<Vec<_>>();
    let input_sum = witness.map_or(Ok(0_u128), |witness| {
        witness.inputs.iter().try_fold(0_u128, |sum, input| {
            sum.checked_add(input.note.value)
                .ok_or(IvmPrivateNoteAirErrorV1::Assignment)
        })
    })?;
    let output_sum = witness.map_or(Ok(0_u128), |witness| {
        witness.outputs.iter().try_fold(0_u128, |sum, output| {
            sum.checked_add(output.note.value)
                .ok_or(IvmPrivateNoteAirErrorV1::Assignment)
        })
    })?;
    let input_sum_variables = builder.push_sum(SumSideV1::Inputs, &input_values, input_sum)?;
    let output_sum_variables =
        builder.push_sum_up_to_three(SumSideV1::Outputs, &output_values, output_sum)?;
    builder.push_conservation(input_sum_variables, output_sum_variables)?;
    builder.push_vm(
        &program_variables,
        input_sum_variables,
        output_sum_variables,
        input_sum,
        output_sum,
    )?;
    if witness.is_some() && builder.invocation_cursor != builder.invocation_oracle.len() {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    if builder.rows.len() > PRIVATE_NOTE_TRACE_SIZE_V1 {
        return Err(IvmPrivateNoteAirErrorV1::Resource);
    }
    while builder.rows.len() < PRIVATE_NOTE_TRACE_SIZE_V1 {
        builder.push_row(
            PrivateNoteFixedRowV1::Padding,
            [CopyCellV1::Inactive; PRIVATE_NOTE_COPY_WIDTH_V1],
            TraceBuilderV1::empty_row(),
        )?;
    }
    let copy_sigma = build_copy_sigma_v1(&builder.copy_cells)?;
    Ok(PrivateNoteBaseTraceV1 {
        fixed: PrivateNoteFixedTraceV1 {
            rows: builder.fixed_rows,
            copy_cells: builder.copy_cells,
            copy_sigma,
        },
        rows: builder.rows,
    })
}
/// Compile the complete prover trace after checking the native differential oracle.
#[cfg(test)]
pub(super) fn build_private_note_base_trace_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
) -> Result<PrivateNoteBaseTraceV1, IvmPrivateNoteAirErrorV1> {
    build_private_note_trace_v1(
        statement,
        Some(witness),
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
/// Compile a prover trace under one crate-private relation profile.
pub(super) fn build_private_note_base_trace_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<PrivateNoteBaseTraceV1, IvmPrivateNoteAirErrorV1> {
    build_private_note_trace_v1(statement, Some(witness), profile)
}
/// Compile verifier-fixed topology without requiring wallet material.
#[cfg(test)]
pub(super) fn build_private_note_fixed_trace_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
) -> Result<PrivateNoteFixedTraceV1, IvmPrivateNoteAirErrorV1> {
    build_private_note_fixed_trace_with_profile_v1(
        statement,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
/// Compile verifier-fixed topology under one crate-private relation profile.
pub(super) fn build_private_note_fixed_trace_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<PrivateNoteFixedTraceV1, IvmPrivateNoteAirErrorV1> {
    Ok(build_private_note_trace_v1(statement, None, profile)?.fixed)
}
/// Compile witness-allocation identities into the shared copy-chip policy.
#[cfg(test)]
pub(super) fn build_private_note_copy_schedule_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
) -> Result<
    crate::privacy_engines::proof_managed_note_stark::NoteCopyScheduleV1,
    IvmPrivateNoteAirErrorV1,
> {
    build_private_note_copy_schedule_with_profile_v1(
        statement,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
/// Compile the copy schedule under one crate-private relation profile.
pub(super) fn build_private_note_copy_schedule_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<
    crate::privacy_engines::proof_managed_note_stark::NoteCopyScheduleV1,
    IvmPrivateNoteAirErrorV1,
> {
    use crate::privacy_engines::proof_managed_note_stark::{
        NoteCopyCellPolicyV1, NoteCopyScheduleV1,
    };
    let fixed = build_private_note_fixed_trace_with_profile_v1(statement, profile)?;
    let policies = fixed
        .copy_cells
        .iter()
        .map(|row| {
            row.map(|cell| match cell {
                CopyCellV1::Inactive => NoteCopyCellPolicyV1::Inactive,
                CopyCellV1::Constant(value) => NoteCopyCellPolicyV1::Constant(value),
                CopyCellV1::Variable(_) => NoteCopyCellPolicyV1::Variable,
            })
        })
        .collect();
    Ok(NoteCopyScheduleV1 {
        policies,
        sigma: fixed.copy_sigma,
    })
}
fn ensure_canonical_row(row: &[F]) -> Result<(), IvmPrivateNoteAirErrorV1> {
    if row.len() != PRIVATE_NOTE_BASE_WIDTH_V1
        || row.iter().any(|value| F::canonical(value.0).is_none())
    {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    Ok(())
}
fn ensure_boolean(value: F) -> Result<(), IvmPrivateNoteAirErrorV1> {
    if value.mul(value.sub(F::ONE)) != F::ZERO {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    Ok(())
}
fn pack_bits(bits: &[F]) -> Result<F, IvmPrivateNoteAirErrorV1> {
    bits.iter()
        .copied()
        .enumerate()
        .try_fold(F::ZERO, |sum, (bit, value)| {
            ensure_boolean(value)?;
            let weight = 1_u64
                .checked_shl(u32::try_from(bit).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?)
                .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
            Ok(sum.add(value.mul(F(weight))))
        })
}
fn packed_word_bits(row: &[F], group: usize) -> Result<F, IvmPrivateNoteAirErrorV1> {
    let start = SHA_BITS_OFFSET
        .checked_add(
            group
                .checked_mul(PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1)
                .ok_or(IvmPrivateNoteAirErrorV1::Resource)?,
        )
        .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
    let end = start
        .checked_add(PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
    pack_bits(
        row.get(start..end)
            .ok_or(IvmPrivateNoteAirErrorV1::Topology)?,
    )
}
fn ensure_zero_outside(
    row: &[F],
    allowed: &[(usize, usize)],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    for (index, value) in row.iter().copied().enumerate() {
        if value != F::ZERO
            && !allowed
                .iter()
                .any(|&(start, end)| start <= index && index < end)
        {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    Ok(())
}
fn copy_allowed() -> (usize, usize) {
    (COPY_OFFSET, COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1)
}
fn validate_copy_cells_v1(
    fixed: &PrivateNoteFixedTraceV1,
    rows: &[Vec<F>],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    if fixed.copy_cells.len() != rows.len() || fixed.copy_sigma.len() != rows.len() {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    if build_copy_sigma_v1(&fixed.copy_cells)? != fixed.copy_sigma {
        return Err(IvmPrivateNoteAirErrorV1::Copy);
    }
    let maximum_label = rows
        .len()
        .checked_mul(PRIVATE_NOTE_COPY_WIDTH_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
    let mut values = BTreeMap::<ByteVariableV1, F>::new();
    for (row_index, (cells, row)) in fixed.copy_cells.iter().zip(rows).enumerate() {
        for (column, cell) in cells.iter().copied().enumerate() {
            let value = row[COPY_OFFSET + column];
            match cell {
                CopyCellV1::Inactive if value == F::ZERO => {}
                CopyCellV1::Constant(expected) if value == F(u64::from(expected)) => {}
                CopyCellV1::Variable(variable) => {
                    if value.0 > u64::from(u8::MAX) {
                        return Err(IvmPrivateNoteAirErrorV1::Copy);
                    }
                    match values.entry(variable) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(value);
                        }
                        std::collections::btree_map::Entry::Occupied(entry)
                            if *entry.get() == value => {}
                        std::collections::btree_map::Entry::Occupied(_) => {
                            return Err(IvmPrivateNoteAirErrorV1::Copy);
                        }
                    }
                }
                _ => return Err(IvmPrivateNoteAirErrorV1::Copy),
            }
            let identity = row_index
                .checked_mul(PRIVATE_NOTE_COPY_WIDTH_V1)
                .and_then(|value| value.checked_add(column))
                .and_then(|value| value.checked_add(1))
                .ok_or(IvmPrivateNoteAirErrorV1::Resource)?;
            if fixed.copy_sigma[row_index][column] == 0
                || usize::try_from(fixed.copy_sigma[row_index][column])
                    .map_err(|_| IvmPrivateNoteAirErrorV1::Copy)?
                    > maximum_label
                || u32::try_from(identity).is_err()
            {
                return Err(IvmPrivateNoteAirErrorV1::Copy);
            }
        }
    }
    Ok(())
}
fn field_to_u32(value: F) -> Result<u32, IvmPrivateNoteAirErrorV1> {
    u32::try_from(value.0).map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)
}
fn field_to_u8(value: F) -> Result<u8, IvmPrivateNoteAirErrorV1> {
    u8::try_from(value.0).map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)
}
fn validate_word_group(
    row: &[F],
    group: usize,
    expected: F,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    if packed_word_bits(row, group)? != expected {
        return Err(IvmPrivateNoteAirErrorV1::Sha256);
    }
    Ok(())
}
fn validate_sha_round_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::ShaRound {
        round,
        invocation,
        block,
        block_count,
    } = fixed
    else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    let round = usize::from(*round);
    if round >= 64 || *block >= *block_count || *block_count == 0 {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    ensure_zero_outside(
        row,
        &[
            copy_allowed(),
            (
                SHA_SCHEDULE_OFFSET,
                SHA_SCHEDULE_OFFSET + PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1,
            ),
            (
                SHA_INITIAL_STATE_OFFSET,
                SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1,
            ),
            (
                SHA_STATE_OFFSET,
                SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1,
            ),
            (
                SHA_BITS_OFFSET,
                SHA_BITS_OFFSET + PRIVATE_NOTE_SHA_BIT_COLUMNS_V1,
            ),
            (SHA_T1_OFFSET, SHA_T1_OFFSET + 1),
            (SHA_T2_OFFSET, SHA_T2_OFFSET + 1),
            (SHA_CARRY_OFFSET, SHA_CARRY_OFFSET + SHA_CARRY_WIDTH),
        ],
    )?;
    let schedule = row
        .get(SHA_SCHEDULE_OFFSET..SHA_SCHEDULE_OFFSET + PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let initial = row
        .get(SHA_INITIAL_STATE_OFFSET..SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let state = row
        .get(SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    for value in schedule.iter().chain(initial).chain(state) {
        field_to_u32(*value)?;
    }
    if round == 0 {
        if initial != state {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
        if *block == 0
            && !state
                .iter()
                .copied()
                .eq(SHA256_INITIAL_STATE_V1.map(|value| F(u64::from(value))))
        {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    }
    let a = field_to_u32(state[0])?;
    let b = field_to_u32(state[1])?;
    let c = field_to_u32(state[2])?;
    let d = field_to_u32(state[3])?;
    let e = field_to_u32(state[4])?;
    let f = field_to_u32(state[5])?;
    let g = field_to_u32(state[6])?;
    let h = field_to_u32(state[7])?;
    for (group, value) in [a, b, c, e, f, g].into_iter().enumerate() {
        validate_word_group(row, group, F(u64::from(value)))?;
    }
    let w = field_to_u32(schedule[round])?;
    validate_word_group(row, 6, F(u64::from(w)))?;
    if round < 16 {
        if packed_word_bits(row, 7)? != F::ZERO || packed_word_bits(row, 8)? != F::ZERO {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
        if row[SHA_CARRY_OFFSET + 6..SHA_CARRY_OFFSET + 8]
            .iter()
            .any(|value| *value != F::ZERO)
        {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
        let message_word = u32::from_be_bytes([
            field_to_u8(row[COPY_OFFSET])?,
            field_to_u8(row[COPY_OFFSET + 1])?,
            field_to_u8(row[COPY_OFFSET + 2])?,
            field_to_u8(row[COPY_OFFSET + 3])?,
        ]);
        if message_word != w {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    } else {
        let w_minus_2 = field_to_u32(schedule[round - 2])?;
        let w_minus_15 = field_to_u32(schedule[round - 15])?;
        validate_word_group(row, 7, F(u64::from(w_minus_2)))?;
        validate_word_group(row, 8, F(u64::from(w_minus_15)))?;
        let wide = u64::from(sigma_small_1(w_minus_2))
            + u64::from(field_to_u32(schedule[round - 7])?)
            + u64::from(sigma_small_0(w_minus_15))
            + u64::from(field_to_u32(schedule[round - 16])?);
        let carry =
            field_to_u32(row[SHA_CARRY_OFFSET + 6])? + 2 * field_to_u32(row[SHA_CARRY_OFFSET + 7])?;
        for value in &row[SHA_CARRY_OFFSET + 6..SHA_CARRY_OFFSET + 8] {
            ensure_boolean(*value)?;
        }
        if wide != u64::from(w) + (u64::from(carry) << 32) {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    }
    let t1 = field_to_u32(row[SHA_T1_OFFSET])?;
    let t2 = field_to_u32(row[SHA_T2_OFFSET])?;
    validate_word_group(row, 9, row[SHA_T1_OFFSET])?;
    validate_word_group(row, 10, row[SHA_T2_OFFSET])?;
    let t1_carry = (0..3).try_fold(0_u32, |carry, bit| {
        ensure_boolean(row[SHA_CARRY_OFFSET + bit])?;
        Ok::<_, IvmPrivateNoteAirErrorV1>(
            carry + (field_to_u32(row[SHA_CARRY_OFFSET + bit])? << bit),
        )
    })?;
    let t2_carry = field_to_u32(row[SHA_CARRY_OFFSET + 3])?;
    let a_carry = field_to_u32(row[SHA_CARRY_OFFSET + 4])?;
    let e_carry = field_to_u32(row[SHA_CARRY_OFFSET + 5])?;
    for value in &row[SHA_CARRY_OFFSET + 3..SHA_CARRY_OFFSET + 6] {
        ensure_boolean(*value)?;
    }
    let t1_wide = u64::from(h)
        + u64::from(sigma_big_1(e))
        + u64::from(sha_choose(e, f, g))
        + u64::from(SHA256_ROUND_CONSTANTS_V1[round])
        + u64::from(w);
    let t2_wide = u64::from(sigma_big_0(a)) + u64::from(sha_majority(a, b, c));
    if t1_wide != u64::from(t1) + (u64::from(t1_carry) << 32)
        || t2_wide != u64::from(t2) + (u64::from(t2_carry) << 32)
    {
        return Err(IvmPrivateNoteAirErrorV1::Sha256);
    }
    let new_a_wide = u64::from(t1) + u64::from(t2);
    let new_e_wide = u64::from(d) + u64::from(t1);
    if new_a_wide != u64::from(new_a_wide as u32) + (u64::from(a_carry) << 32)
        || new_e_wide != u64::from(new_e_wide as u32) + (u64::from(e_carry) << 32)
    {
        return Err(IvmPrivateNoteAirErrorV1::Sha256);
    }
    let working_next = [new_a_wide as u32, a, b, c, new_e_wide as u32, e, f, g];
    if row[SHA_CARRY_OFFSET + 16..SHA_CARRY_OFFSET + SHA_CARRY_WIDTH]
        .iter()
        .any(|value| *value != F::ZERO)
    {
        return Err(IvmPrivateNoteAirErrorV1::Sha256);
    }
    if round < 63 {
        if next_fixed
            != &(PrivateNoteFixedRowV1::ShaRound {
                round: u8::try_from(round + 1).map_err(|_| IvmPrivateNoteAirErrorV1::Resource)?,
                invocation: *invocation,
                block: *block,
                block_count: *block_count,
            })
            || &next[SHA_SCHEDULE_OFFSET..SHA_SCHEDULE_OFFSET + PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1]
                != schedule
            || &next[SHA_INITIAL_STATE_OFFSET
                ..SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1]
                != initial
            || !next[SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1]
                .iter()
                .copied()
                .eq(working_next.map(|value| F(u64::from(value))))
            || row[SHA_CARRY_OFFSET + 8..SHA_CARRY_OFFSET + 16]
                .iter()
                .any(|value| *value != F::ZERO)
        {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    } else {
        if !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::ShaEnd {
                invocation: next_invocation,
                block: next_block,
                block_count: next_block_count,
                digest_chunk: 0,
                ..
            } if next_invocation == invocation
                && next_block == block
                && next_block_count == block_count
        ) {
            return Err(IvmPrivateNoteAirErrorV1::Topology);
        }
        for index in 0..8 {
            ensure_boolean(row[SHA_CARRY_OFFSET + 8 + index])?;
            let feed_forward =
                u64::from(field_to_u32(initial[index])?) + u64::from(working_next[index]);
            let expected = u64::from(field_to_u32(next[SHA_STATE_OFFSET + index])?)
                + (row[SHA_CARRY_OFFSET + 8 + index].0 << 32);
            if feed_forward != expected {
                return Err(IvmPrivateNoteAirErrorV1::Sha256);
            }
        }
    }
    Ok(())
}
fn validate_sha_end_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::ShaEnd {
        invocation,
        block,
        block_count,
        digest_chunk,
        public_digest,
    } = fixed
    else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    if *block_count == 0 || *block >= *block_count || usize::from(*digest_chunk) >= 4 {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    ensure_zero_outside(
        row,
        &[
            copy_allowed(),
            (
                SHA_STATE_OFFSET,
                SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1,
            ),
            (
                SHA_BITS_OFFSET,
                SHA_BITS_OFFSET + PRIVATE_NOTE_SHA_BIT_COLUMNS_V1,
            ),
        ],
    )?;
    let state = row
        .get(SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    for (group, value) in state.iter().copied().enumerate() {
        field_to_u32(value)?;
        validate_word_group(row, group, value)?;
    }
    for group in PRIVATE_NOTE_SHA_STATE_WORDS_V1..PRIVATE_NOTE_SHA_BIT_GROUPS_V1 {
        if packed_word_bits(row, group)? != F::ZERO {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    }
    let terminal = usize::from(*block) + 1 == usize::from(*block_count);
    if terminal {
        let first_word = usize::from(*digest_chunk) * 2;
        let expected_bytes = [
            field_to_u32(state[first_word])?.to_be_bytes(),
            field_to_u32(state[first_word + 1])?.to_be_bytes(),
        ]
        .concat();
        for (actual, expected) in row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
            .iter()
            .copied()
            .zip(expected_bytes)
        {
            if field_to_u8(actual)? != expected {
                return Err(IvmPrivateNoteAirErrorV1::Sha256);
            }
        }
        if let Some(public_digest) = public_digest {
            let start = usize::from(*digest_chunk) * PRIVATE_NOTE_COPY_WIDTH_V1;
            if row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
                .iter()
                .copied()
                .map(field_to_u8)
                .collect::<Result<Vec<_>, _>>()?
                .as_slice()
                != &public_digest[start..start + PRIVATE_NOTE_COPY_WIDTH_V1]
            {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
        }
    } else if row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
        .iter()
        .any(|value| *value != F::ZERO)
    {
        return Err(IvmPrivateNoteAirErrorV1::Sha256);
    }
    if *digest_chunk < 3 {
        if !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::ShaEnd {
                invocation: next_invocation,
                block: next_block,
                block_count: next_block_count,
                digest_chunk: next_chunk,
                public_digest: next_public,
            } if next_invocation == invocation
                && next_block == block
                && next_block_count == block_count
                && *next_chunk == digest_chunk + 1
                && next_public == public_digest
        ) || next[SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1] != *state
        {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    } else if !terminal {
        if !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::ShaRound {
                round: 0,
                invocation: next_invocation,
                block: next_block,
                block_count: next_block_count,
            } if next_invocation == invocation
                && usize::from(*next_block) == usize::from(*block) + 1
                && next_block_count == block_count
        ) || next
            [SHA_INITIAL_STATE_OFFSET..SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1]
            != *state
            || next[SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1] != *state
        {
            return Err(IvmPrivateNoteAirErrorV1::Sha256);
        }
    } else if let PrivateNoteFixedRowV1::ShaRound {
        round: 0,
        invocation: next_invocation,
        block: 0,
        ..
    } = next_fixed
    {
        if usize::from(*next_invocation) != usize::from(*invocation) + 1 {
            return Err(IvmPrivateNoteAirErrorV1::Topology);
        }
    }
    Ok(())
}
fn validate_conditional_membership_v1(row: &[F]) -> Result<(), IvmPrivateNoteAirErrorV1> {
    ensure_zero_outside(row, &[copy_allowed()])?;
    for cell in &row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1] {
        field_to_u8(*cell)?;
    }
    for pair in 0..3 {
        if row[COPY_OFFSET]
            .mul(row[COPY_OFFSET + 1 + pair * 2].sub(row[COPY_OFFSET + 2 + pair * 2]))
            != F::ZERO
        {
            return Err(IvmPrivateNoteAirErrorV1::Relation);
        }
    }
    Ok(())
}
fn validate_node_select_v1(row: &[F]) -> Result<(), IvmPrivateNoteAirErrorV1> {
    ensure_zero_outside(row, &[copy_allowed()])?;
    let current = field_to_u8(row[COPY_OFFSET])?;
    let sibling = field_to_u8(row[COPY_OFFSET + 1])?;
    let left = field_to_u8(row[COPY_OFFSET + 2])?;
    let right = field_to_u8(row[COPY_OFFSET + 3])?;
    let direction = row[COPY_OFFSET + 4];
    ensure_boolean(direction)?;
    let expected_left = if direction == F::ZERO {
        current
    } else {
        sibling
    };
    let expected_right = if direction == F::ZERO {
        sibling
    } else {
        current
    };
    if left != expected_left || right != expected_right {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    Ok(())
}
fn validate_running_transition_v1(
    before: F,
    after: F,
    selected: F,
    first: bool,
    last: bool,
    next_before: Option<F>,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    ensure_boolean(before)?;
    ensure_boolean(after)?;
    ensure_boolean(selected)?;
    if (first && before != F::ZERO)
        || after != before.add(selected)
        || (last && after != F::ONE)
        || (!last && next_before != Some(after))
    {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    Ok(())
}
fn validate_nonzero_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::NonZero {
        component,
        chunk,
        chunks,
    } = fixed
    else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    if *chunks == 0 || *chunk >= *chunks {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    ensure_zero_outside(
        row,
        &[
            copy_allowed(),
            (
                SCRATCH_NONZERO_BYTE_SELECT_OFFSET,
                SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1,
            ),
            (
                SCRATCH_NONZERO_BIT_SELECT_OFFSET,
                SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8,
            ),
            (SCRATCH_BYTE_BITS_OFFSET, SCRATCH_BYTE_BITS_OFFSET + 8),
            (SCRATCH_RUNNING_BEFORE, SCRATCH_RUNNING_AFTER + 1),
        ],
    )?;
    let byte_selectors = &row[SCRATCH_NONZERO_BYTE_SELECT_OFFSET
        ..SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1];
    let bit_selectors =
        &row[SCRATCH_NONZERO_BIT_SELECT_OFFSET..SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8];
    let selected_count = byte_selectors
        .iter()
        .copied()
        .try_fold(F::ZERO, |sum, selector| {
            ensure_boolean(selector)?;
            Ok::<_, IvmPrivateNoteAirErrorV1>(sum.add(selector))
        })?;
    ensure_boolean(selected_count)?;
    let bit_count = bit_selectors
        .iter()
        .copied()
        .try_fold(F::ZERO, |sum, selector| {
            ensure_boolean(selector)?;
            Ok::<_, IvmPrivateNoteAirErrorV1>(sum.add(selector))
        })?;
    if bit_count != selected_count {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    let selected_byte = byte_selectors
        .iter()
        .copied()
        .zip(&row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1])
        .fold(F::ZERO, |sum, (selector, byte)| {
            sum.add(selector.mul(*byte))
        });
    let byte_bits = &row[SCRATCH_BYTE_BITS_OFFSET..SCRATCH_BYTE_BITS_OFFSET + 8];
    if pack_bits(byte_bits)? != selected_byte {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    for (selector, bit) in bit_selectors.iter().copied().zip(byte_bits) {
        if selector != F::ZERO && *bit != F::ONE {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    let last = usize::from(*chunk) + 1 == usize::from(*chunks);
    let next_before = (!last).then(|| next[SCRATCH_RUNNING_BEFORE]);
    if !last
        && !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::NonZero {
                component: next_component,
                chunk: next_chunk,
                chunks: next_chunks,
            } if next_component == component
                && usize::from(*next_chunk) == usize::from(*chunk) + 1
                && next_chunks == chunks
        )
    {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    validate_running_transition_v1(
        row[SCRATCH_RUNNING_BEFORE],
        row[SCRATCH_RUNNING_AFTER],
        selected_count,
        *chunk == 0,
        last,
        next_before,
    )
}
fn validate_distinct_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    const PAIRS_PER_ROW: usize = PRIVATE_NOTE_COPY_WIDTH_V1 / 2;
    let PrivateNoteFixedRowV1::Distinct {
        comparison,
        chunk,
        chunks,
    } = fixed
    else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    if *chunks == 0 || *chunk >= *chunks {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    ensure_zero_outside(
        row,
        &[
            copy_allowed(),
            (
                SCRATCH_NONZERO_BYTE_SELECT_OFFSET,
                SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PAIRS_PER_ROW,
            ),
            (
                SCRATCH_NONZERO_BIT_SELECT_OFFSET,
                SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8,
            ),
            (SCRATCH_BYTE_BITS_OFFSET, SCRATCH_BYTE_BITS_OFFSET + 8),
            (SCRATCH_RUNNING_BEFORE, SCRATCH_RUNNING_AFTER + 1),
            (
                SCRATCH_VM_DIFFERENCE_BITS_OFFSET,
                SCRATCH_VM_DIFFERENCE_BITS_OFFSET + 8,
            ),
        ],
    )?;
    let pair_selectors = &row
        [SCRATCH_NONZERO_BYTE_SELECT_OFFSET..SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PAIRS_PER_ROW];
    let bit_selectors =
        &row[SCRATCH_NONZERO_BIT_SELECT_OFFSET..SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8];
    let selected_count = pair_selectors
        .iter()
        .copied()
        .try_fold(F::ZERO, |sum, selector| {
            ensure_boolean(selector)?;
            Ok::<_, IvmPrivateNoteAirErrorV1>(sum.add(selector))
        })?;
    ensure_boolean(selected_count)?;
    let bit_count = bit_selectors
        .iter()
        .copied()
        .try_fold(F::ZERO, |sum, selector| {
            ensure_boolean(selector)?;
            Ok::<_, IvmPrivateNoteAirErrorV1>(sum.add(selector))
        })?;
    if bit_count != selected_count {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    let selected_left = pair_selectors
        .iter()
        .copied()
        .enumerate()
        .fold(F::ZERO, |sum, (pair, selector)| {
            sum.add(selector.mul(row[COPY_OFFSET + pair * 2]))
        });
    let selected_right = pair_selectors
        .iter()
        .copied()
        .enumerate()
        .fold(F::ZERO, |sum, (pair, selector)| {
            sum.add(selector.mul(row[COPY_OFFSET + pair * 2 + 1]))
        });
    let left_bits = &row[SCRATCH_BYTE_BITS_OFFSET..SCRATCH_BYTE_BITS_OFFSET + 8];
    let right_bits = &row[SCRATCH_VM_DIFFERENCE_BITS_OFFSET..SCRATCH_VM_DIFFERENCE_BITS_OFFSET + 8];
    if pack_bits(left_bits)? != selected_left || pack_bits(right_bits)? != selected_right {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    for ((selector, left), right) in bit_selectors.iter().copied().zip(left_bits).zip(right_bits) {
        if selector != F::ZERO && left == right {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    let last = usize::from(*chunk) + 1 == usize::from(*chunks);
    let next_before = (!last).then(|| next[SCRATCH_RUNNING_BEFORE]);
    if !last
        && !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::Distinct {
                comparison: next_comparison,
                chunk: next_chunk,
                chunks: next_chunks,
            } if next_comparison == comparison
                && usize::from(*next_chunk) == usize::from(*chunk) + 1
                && next_chunks == chunks
        )
    {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    validate_running_transition_v1(
        row[SCRATCH_RUNNING_BEFORE],
        row[SCRATCH_RUNNING_AFTER],
        selected_count,
        *chunk == 0,
        last,
        next_before,
    )
}
fn signed_small(value: F) -> Result<i16, IvmPrivateNoteAirErrorV1> {
    if value == F::ZERO {
        Ok(0)
    } else if value == F::ONE {
        Ok(1)
    } else if value == F(GOLDILOCKS_MODULUS_V1 - 1) {
        Ok(-1)
    } else {
        Err(IvmPrivateNoteAirErrorV1::Assignment)
    }
}
fn validate_sum_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::Sum { side, byte } = fixed else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    if usize::from(*byte) >= 16 {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    let last = *byte == 15;
    if !last
        && !matches!(
            next_fixed,
            PrivateNoteFixedRowV1::Sum {
                side: next_side,
                byte: next_byte,
            } if next_side == side && usize::from(*next_byte) == usize::from(*byte) + 1
        )
    {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    match side {
        SumSideV1::Inputs | SumSideV1::Outputs => {
            ensure_zero_outside(
                row,
                &[
                    copy_allowed(),
                    (SCRATCH_BYTE_BITS_OFFSET, SCRATCH_BYTE_BITS_OFFSET + 8),
                    (
                        SCRATCH_RELATION_CARRY_BEFORE,
                        SCRATCH_RELATION_CARRY_AFTER + 1,
                    ),
                    (
                        SCRATCH_RELATION_CARRY_BITS_OFFSET,
                        SCRATCH_RELATION_CARRY_BITS_OFFSET + 2,
                    ),
                ],
            )?;
            let operand_0 = u16::from(field_to_u8(row[COPY_OFFSET])?);
            let operand_1 = u16::from(field_to_u8(row[COPY_OFFSET + 1])?);
            let output = u16::from(field_to_u8(row[COPY_OFFSET + 2])?);
            let carry_before = u16::try_from(row[SCRATCH_RELATION_CARRY_BEFORE].0)
                .map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?;
            ensure_boolean(row[SCRATCH_RELATION_CARRY_BEFORE])?;
            let carry_after_bits =
                &row[SCRATCH_RELATION_CARRY_BITS_OFFSET..SCRATCH_RELATION_CARRY_BITS_OFFSET + 2];
            let carry_after_field = pack_bits(carry_after_bits)?;
            if row[SCRATCH_RELATION_CARRY_AFTER] != carry_after_field {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
            let carry_after = u16::try_from(carry_after_field.0)
                .map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?;
            if pack_bits(&row[SCRATCH_BYTE_BITS_OFFSET..SCRATCH_BYTE_BITS_OFFSET + 8])?
                != F(u64::from(output))
                || operand_0 + operand_1 + carry_before != output + carry_after * 256
                || (*byte == 0 && carry_before != 0)
                || (last && carry_after != 0)
                || (!last
                    && next[SCRATCH_RELATION_CARRY_BEFORE] != row[SCRATCH_RELATION_CARRY_AFTER])
            {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
        }
        SumSideV1::Conservation => {
            ensure_zero_outside(
                row,
                &[
                    copy_allowed(),
                    (
                        SCRATCH_RELATION_CARRY_BEFORE,
                        SCRATCH_RELATION_CARRY_AFTER + 1,
                    ),
                ],
            )?;
            let input = i16::from(field_to_u8(row[COPY_OFFSET])?);
            let output = i16::from(field_to_u8(row[COPY_OFFSET + 1])?);
            let public_in = i16::from(field_to_u8(row[COPY_OFFSET + 2])?);
            let public_out = i16::from(field_to_u8(row[COPY_OFFSET + 3])?);
            let carry_before = signed_small(row[SCRATCH_RELATION_CARRY_BEFORE])?;
            let carry_after = signed_small(row[SCRATCH_RELATION_CARRY_AFTER])?;
            if input + public_in + carry_before != output + public_out + 256 * carry_after
                || (*byte == 0 && carry_before != 0)
                || (last && carry_after != 0)
                || (!last
                    && next[SCRATCH_RELATION_CARRY_BEFORE] != row[SCRATCH_RELATION_CARRY_AFTER])
            {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
        }
    }
    Ok(())
}
fn extract_private_program_v1(
    fixed: &PrivateNoteFixedTraceV1,
    rows: &[Vec<F>],
) -> Result<super::relation::PrivateProgramV1, IvmPrivateNoteAirErrorV1> {
    let mut encoded = [0_u8; PRIVATE_PROGRAM_BYTES_V1];
    let mut header_seen = false;
    let mut instruction_seen = [false; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1];
    for (fixed_row, row) in fixed.rows.iter().zip(rows) {
        match *fixed_row {
            PrivateNoteFixedRowV1::VmHeader => {
                if header_seen {
                    return Err(IvmPrivateNoteAirErrorV1::Topology);
                }
                for (target, value) in encoded[..8]
                    .iter_mut()
                    .zip(&row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1])
                {
                    *target = field_to_u8(*value)?;
                }
                header_seen = true;
            }
            PrivateNoteFixedRowV1::VmProgram { instruction } => {
                let instruction = usize::from(instruction);
                let seen = instruction_seen
                    .get_mut(instruction)
                    .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
                if *seen {
                    return Err(IvmPrivateNoteAirErrorV1::Topology);
                }
                let start = 8 + instruction * PRIVATE_NOTE_COPY_WIDTH_V1;
                for (target, value) in encoded[start..start + PRIVATE_NOTE_COPY_WIDTH_V1]
                    .iter_mut()
                    .zip(&row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1])
                {
                    *target = field_to_u8(*value)?;
                }
                *seen = true;
            }
            _ => {}
        }
    }
    if !header_seen || instruction_seen.iter().any(|seen| !*seen) {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    decode_private_program_v1(&encoded).map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)
}
fn validate_vm_common_v1(
    row: &[F],
    instruction: PrivateInstructionV1,
    halted_before: bool,
    halted_after: bool,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let opcode_selectors =
        &row[SCRATCH_VM_OPCODE_SELECT_OFFSET..SCRATCH_VM_OPCODE_SELECT_OFFSET + 9];
    let destination_selectors =
        &row[SCRATCH_VM_DESTINATION_SELECT_OFFSET..SCRATCH_VM_DESTINATION_SELECT_OFFSET + 8];
    let left_selectors = &row[SCRATCH_VM_LEFT_SELECT_OFFSET..SCRATCH_VM_LEFT_SELECT_OFFSET + 8];
    let right_selectors = &row[SCRATCH_VM_RIGHT_SELECT_OFFSET..SCRATCH_VM_RIGHT_SELECT_OFFSET + 8];
    for (selectors, expected) in [
        (opcode_selectors, instruction.opcode as usize),
        (destination_selectors, usize::from(instruction.destination)),
        (left_selectors, usize::from(instruction.left)),
        (right_selectors, usize::from(instruction.right)),
    ] {
        if selectors
            .iter()
            .copied()
            .enumerate()
            .try_fold(F::ZERO, |sum, (index, selector)| {
                ensure_boolean(selector)?;
                if selector != F::ZERO && index != expected {
                    return Err(IvmPrivateNoteAirErrorV1::Assignment);
                }
                Ok(sum.add(selector))
            })?
            != F::ONE
        {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    for (actual, expected) in row[SCRATCH_VM_IMMEDIATE_OFFSET..SCRATCH_VM_IMMEDIATE_OFFSET + 4]
        .iter()
        .copied()
        .zip(instruction.immediate.to_be_bytes())
    {
        if field_to_u8(actual)? != expected {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    ensure_boolean(row[SCRATCH_VM_HALTED_BEFORE])?;
    ensure_boolean(row[SCRATCH_VM_HALTED_AFTER])?;
    if row[SCRATCH_VM_HALTED_BEFORE] != F(u64::from(halted_before))
        || row[SCRATCH_VM_HALTED_AFTER] != F(u64::from(halted_after))
    {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    Ok(())
}
fn vm_common_ranges() -> [(usize, usize); 6] {
    [
        (
            SCRATCH_VM_OPCODE_SELECT_OFFSET,
            SCRATCH_VM_OPCODE_SELECT_OFFSET + 9,
        ),
        (
            SCRATCH_VM_DESTINATION_SELECT_OFFSET,
            SCRATCH_VM_DESTINATION_SELECT_OFFSET + 8,
        ),
        (
            SCRATCH_VM_LEFT_SELECT_OFFSET,
            SCRATCH_VM_LEFT_SELECT_OFFSET + 8,
        ),
        (
            SCRATCH_VM_RIGHT_SELECT_OFFSET,
            SCRATCH_VM_RIGHT_SELECT_OFFSET + 8,
        ),
        (SCRATCH_VM_IMMEDIATE_OFFSET, SCRATCH_VM_IMMEDIATE_OFFSET + 4),
        (SCRATCH_VM_HALTED_BEFORE, SCRATCH_VM_HALTED_AFTER + 1),
    ]
}
fn vm_halted_flags(
    program: &super::relation::PrivateProgramV1,
    instruction: usize,
) -> Result<(bool, bool), IvmPrivateNoteAirErrorV1> {
    let current = program
        .instructions
        .get(instruction)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let before = program.instructions[..instruction]
        .iter()
        .any(|value| value.opcode == PrivateOpcodeV1::Halt);
    Ok((before, before || current.opcode == PrivateOpcodeV1::Halt))
}
fn validate_vm_header_v1(
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    ensure_zero_outside(row, &[copy_allowed()])?;
    if !matches!(
        next_fixed,
        PrivateNoteFixedRowV1::VmProgram { instruction: 0 }
    ) {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    Ok(())
}
fn validate_vm_program_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    program: &super::relation::PrivateProgramV1,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::VmProgram { instruction } = fixed else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    let instruction_index = usize::from(*instruction);
    let instruction_value = *program
        .instructions
        .get(instruction_index)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let mut allowed = vec![copy_allowed()];
    allowed.extend(vm_common_ranges());
    ensure_zero_outside(row, &allowed)?;
    let encoded = instruction_value.to_bytes();
    for (actual, expected) in row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
        .iter()
        .copied()
        .zip(encoded)
    {
        if field_to_u8(actual)? != expected {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    let (halted_before, halted_after) = vm_halted_flags(program, instruction_index)?;
    validate_vm_common_v1(row, instruction_value, halted_before, halted_after)?;
    if !matches!(
        next_fixed,
        PrivateNoteFixedRowV1::VmPrevious {
            instruction: next_instruction,
            byte: 0,
        } if next_instruction == instruction
    ) {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    Ok(())
}
fn validate_vm_previous_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    next: &[F],
    following: Option<(&PrivateNoteFixedRowV1, &[F])>,
    program: &super::relation::PrivateProgramV1,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::VmPrevious { instruction, byte } = fixed else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    let instruction_index = usize::from(*instruction);
    let little_byte = usize::from(*byte);
    if little_byte >= 16 {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    let instruction_value = *program
        .instructions
        .get(instruction_index)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let mut allowed = vec![
        copy_allowed(),
        (SCRATCH_VM_CARRY_BEFORE, SCRATCH_VM_RESULT + 1),
        (
            SCRATCH_VM_RESULT_BITS_OFFSET,
            SCRATCH_VM_RESULT_BITS_OFFSET + 8,
        ),
        (
            SCRATCH_VM_DIFFERENCE_BITS_OFFSET,
            SCRATCH_VM_DIFFERENCE_BITS_OFFSET + 8,
        ),
    ];
    allowed.extend(vm_common_ranges());
    ensure_zero_outside(row, &allowed)?;
    let (halted_before, halted_after) = vm_halted_flags(program, instruction_index)?;
    validate_vm_common_v1(row, instruction_value, halted_before, halted_after)?;
    if !matches!(
        next_fixed,
        PrivateNoteFixedRowV1::VmNext {
            instruction: next_instruction,
            byte: next_byte,
        } if next_instruction == instruction && next_byte == byte
    ) {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    let previous = row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
        .iter()
        .copied()
        .map(field_to_u8)
        .collect::<Result<Vec<_>, _>>()?;
    let next_registers = next[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1]
        .iter()
        .copied()
        .map(field_to_u8)
        .collect::<Result<Vec<_>, _>>()?;
    let destination = usize::from(instruction_value.destination);
    let left = usize::from(instruction_value.left);
    let right = usize::from(instruction_value.right);
    let byte_index = 15 - little_byte;
    let result = field_to_u8(row[SCRATCH_VM_RESULT])?;
    let difference = field_to_u8(row[SCRATCH_VM_DIFFERENCE])?;
    if pack_bits(&row[SCRATCH_VM_RESULT_BITS_OFFSET..SCRATCH_VM_RESULT_BITS_OFFSET + 8])?
        != F(u64::from(result))
        || pack_bits(
            &row[SCRATCH_VM_DIFFERENCE_BITS_OFFSET..SCRATCH_VM_DIFFERENCE_BITS_OFFSET + 8],
        )? != F(u64::from(difference))
    {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    let writes = matches!(
        instruction_value.opcode,
        PrivateOpcodeV1::MoveImmediate
            | PrivateOpcodeV1::Move
            | PrivateOpcodeV1::AddChecked
            | PrivateOpcodeV1::SubChecked
            | PrivateOpcodeV1::LoadActionLimb
            | PrivateOpcodeV1::LoadExecutionEpoch
    );
    for register in 0..8 {
        if (!writes || register != destination) && previous[register] != next_registers[register] {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
    }
    if writes && next_registers[destination] != result {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    let expected_result = match instruction_value.opcode {
        PrivateOpcodeV1::Halt
        | PrivateOpcodeV1::AssertEqual
        | PrivateOpcodeV1::AssertLessOrEqual => 0,
        PrivateOpcodeV1::MoveImmediate => {
            u128::from(instruction_value.immediate).to_be_bytes()[byte_index]
        }
        PrivateOpcodeV1::Move => previous[left],
        PrivateOpcodeV1::AddChecked | PrivateOpcodeV1::SubChecked => next_registers[destination],
        PrivateOpcodeV1::LoadActionLimb => {
            let limb = usize::try_from(instruction_value.immediate)
                .map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?;
            let index = limb
                .checked_mul(16)
                .and_then(|start| start.checked_add(byte_index))
                .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?;
            *statement
                .action_digest
                .as_bytes()
                .get(index)
                .ok_or(IvmPrivateNoteAirErrorV1::Assignment)?
        }
        PrivateOpcodeV1::LoadExecutionEpoch => {
            u128::from(statement.execution_epoch).to_be_bytes()[byte_index]
        }
    };
    if result != expected_result {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    let carry_before = row[SCRATCH_VM_CARRY_BEFORE];
    let carry_after = row[SCRATCH_VM_CARRY_AFTER];
    let arithmetic = matches!(
        instruction_value.opcode,
        PrivateOpcodeV1::AddChecked
            | PrivateOpcodeV1::SubChecked
            | PrivateOpcodeV1::AssertLessOrEqual
    );
    if arithmetic {
        ensure_boolean(carry_before)?;
        ensure_boolean(carry_after)?;
        let carry_before_u16 =
            u16::try_from(carry_before.0).map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?;
        let carry_after_u16 =
            u16::try_from(carry_after.0).map_err(|_| IvmPrivateNoteAirErrorV1::Assignment)?;
        let valid_equation = match instruction_value.opcode {
            PrivateOpcodeV1::AddChecked => {
                u16::from(previous[left]) + u16::from(previous[right]) + carry_before_u16
                    == u16::from(result) + 256 * carry_after_u16
                    && difference == 0
            }
            PrivateOpcodeV1::SubChecked => {
                u16::from(result) + u16::from(previous[right]) + carry_before_u16
                    == u16::from(previous[left]) + 256 * carry_after_u16
                    && difference == 0
            }
            PrivateOpcodeV1::AssertLessOrEqual => {
                u16::from(difference) + u16::from(previous[left]) + carry_before_u16
                    == u16::from(previous[right]) + 256 * carry_after_u16
            }
            _ => false,
        };
        if !valid_equation
            || (little_byte == 0 && carry_before != F::ZERO)
            || (little_byte == 15 && carry_after != F::ZERO)
        {
            return Err(IvmPrivateNoteAirErrorV1::Assignment);
        }
        if little_byte < 15 {
            let Some((
                PrivateNoteFixedRowV1::VmPrevious {
                    instruction: following_instruction,
                    byte: following_byte,
                },
                following_row,
            )) = following
            else {
                return Err(IvmPrivateNoteAirErrorV1::Topology);
            };
            if following_instruction != instruction
                || usize::from(*following_byte) != little_byte + 1
                || following_row[SCRATCH_VM_CARRY_BEFORE] != carry_after
            {
                return Err(IvmPrivateNoteAirErrorV1::Assignment);
            }
        }
    } else if carry_before != F::ZERO || carry_after != F::ZERO || difference != 0 {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    if instruction_value.opcode == PrivateOpcodeV1::AssertEqual && previous[left] != previous[right]
    {
        return Err(IvmPrivateNoteAirErrorV1::Assignment);
    }
    Ok(())
}
fn validate_vm_next_v1(
    fixed: &PrivateNoteFixedRowV1,
    next_fixed: &PrivateNoteFixedRowV1,
    row: &[F],
    program: &super::relation::PrivateProgramV1,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    let PrivateNoteFixedRowV1::VmNext { instruction, byte } = fixed else {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    };
    let instruction_index = usize::from(*instruction);
    let little_byte = usize::from(*byte);
    if little_byte >= 16 {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    let instruction_value = *program
        .instructions
        .get(instruction_index)
        .ok_or(IvmPrivateNoteAirErrorV1::Topology)?;
    let mut allowed = vec![copy_allowed()];
    allowed.extend(vm_common_ranges());
    ensure_zero_outside(row, &allowed)?;
    for value in &row[COPY_OFFSET..COPY_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1] {
        field_to_u8(*value)?;
    }
    let (halted_before, halted_after) = vm_halted_flags(program, instruction_index)?;
    validate_vm_common_v1(row, instruction_value, halted_before, halted_after)?;
    let topology_valid = if little_byte < 15 {
        matches!(
            next_fixed,
            PrivateNoteFixedRowV1::VmPrevious {
                instruction: next_instruction,
                byte: next_byte,
            } if next_instruction == instruction
                && usize::from(*next_byte) == little_byte + 1
        )
    } else if instruction_index + 1 < PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1 {
        matches!(
            next_fixed,
            PrivateNoteFixedRowV1::VmProgram {
                instruction: next_instruction,
            } if usize::from(*next_instruction) == instruction_index + 1
        )
    } else {
        matches!(next_fixed, PrivateNoteFixedRowV1::Padding)
    };
    if !topology_valid {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    Ok(())
}
/// Evaluate every native private-note AIR constraint against one complete canonical base trace.
/// This is deliberately proof-format neutral; the shared aggregate SHA-256/Goldilocks engine
/// consumes the same fixed and base columns.
#[cfg(test)]
pub(super) fn validate_private_note_base_trace_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    trace: &PrivateNoteBaseTraceV1,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    validate_private_note_base_trace_with_profile_v1(
        statement,
        trace,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
pub(super) fn validate_private_note_base_trace_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    trace: &PrivateNoteBaseTraceV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<(), IvmPrivateNoteAirErrorV1> {
    validate_statement_with_profile_v1(statement, profile)
        .map_err(|_| IvmPrivateNoteAirErrorV1::Relation)?;
    if trace.rows.len() != PRIVATE_NOTE_TRACE_SIZE_V1
        || trace.fixed.rows.len() != PRIVATE_NOTE_TRACE_SIZE_V1
        || trace.fixed.copy_cells.len() != PRIVATE_NOTE_TRACE_SIZE_V1
        || trace.fixed.copy_sigma.len() != PRIVATE_NOTE_TRACE_SIZE_V1
    {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    for row in &trace.rows {
        ensure_canonical_row(row)?;
    }
    let expected_fixed = build_private_note_fixed_trace_with_profile_v1(statement, profile)?;
    if trace.fixed != expected_fixed {
        return Err(IvmPrivateNoteAirErrorV1::Topology);
    }
    validate_copy_cells_v1(&trace.fixed, &trace.rows)?;
    let program = extract_private_program_v1(&trace.fixed, &trace.rows)?;
    for index in 0..PRIVATE_NOTE_TRACE_SIZE_V1 {
        let fixed = &trace.fixed.rows[index];
        let row = &trace.rows[index];
        let next_index = (index + 1).min(PRIVATE_NOTE_TRACE_SIZE_V1 - 1);
        let next_fixed = &trace.fixed.rows[next_index];
        let next = &trace.rows[next_index];
        match fixed {
            PrivateNoteFixedRowV1::ShaRound { .. } => {
                validate_sha_round_v1(fixed, next_fixed, row, next)?;
            }
            PrivateNoteFixedRowV1::ShaEnd { .. } => {
                validate_sha_end_v1(fixed, next_fixed, row, next)?;
            }
            PrivateNoteFixedRowV1::NodeSelect { .. } => {
                validate_node_select_v1(row)?;
            }
            PrivateNoteFixedRowV1::Membership { .. } => {
                validate_conditional_membership_v1(row)?;
            }
            PrivateNoteFixedRowV1::Distinct { .. } => {
                validate_distinct_v1(fixed, next_fixed, row, next)?;
            }
            PrivateNoteFixedRowV1::NonZero { .. } => {
                validate_nonzero_v1(fixed, next_fixed, row, next)?;
            }
            PrivateNoteFixedRowV1::Sum { .. } => {
                validate_sum_v1(fixed, next_fixed, row, next)?;
            }
            PrivateNoteFixedRowV1::VmHeader => {
                validate_vm_header_v1(next_fixed, row)?;
            }
            PrivateNoteFixedRowV1::VmProgram { .. } => {
                validate_vm_program_v1(fixed, next_fixed, row, &program)?;
            }
            PrivateNoteFixedRowV1::VmPrevious { byte, .. } => {
                let following = (usize::from(*byte) < 15)
                    .then(|| {
                        trace
                            .fixed
                            .rows
                            .get(index + 2)
                            .zip(trace.rows.get(index + 2))
                            .map(|(fixed, row)| (fixed, row.as_slice()))
                    })
                    .flatten();
                validate_vm_previous_v1(
                    statement, fixed, next_fixed, row, next, following, &program,
                )?;
            }
            PrivateNoteFixedRowV1::VmNext { .. } => {
                validate_vm_next_v1(fixed, next_fixed, row, &program)?;
            }
            PrivateNoteFixedRowV1::Padding => {
                ensure_zero_outside(row, &[])?;
                if !matches!(next_fixed, PrivateNoteFixedRowV1::Padding) {
                    return Err(IvmPrivateNoteAirErrorV1::Topology);
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::ivm_private_note::{
        derive_note_authority_v1, derive_note_commitment_v1, derive_note_nullifier_v1,
        encrypt_ivm_private_wallet_note_v1, ivm_private_recipient_public_key_v1,
        relation::{
            IvmPrivateNoteInputWitnessV1, IvmPrivateNoteOutputWitnessV1, PrivateNotePlaintextV1,
            accumulator_leaf_invocation_v1, accumulator_node_invocation_v1,
        },
        test_fixtures::{fixture, three_output_fixture},
    };
    use iroha_data_model::privacy::{PrivacyActionDigestV1, PrivacyRootV1};
    use rand_08::{SeedableRng as _, rngs::StdRng};
    use std::collections::BTreeSet;
    fn changed(value: F) -> F {
        if value == F::ZERO { F::ONE } else { F::ZERO }
    }
    fn row_index(
        trace: &PrivateNoteBaseTraceV1,
        predicate: impl Fn(&PrivateNoteFixedRowV1) -> bool,
    ) -> usize {
        trace
            .fixed
            .rows
            .iter()
            .position(predicate)
            .expect("fixture contains requested AIR row")
    }
    fn reject_cell_mutation(
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
        trace: &mut PrivateNoteBaseTraceV1,
        row: usize,
        column: usize,
    ) {
        let original = trace.rows[row][column];
        trace.rows[row][column] = changed(original);
        assert!(
            validate_private_note_base_trace_v1(statement, trace).is_err(),
            "mutation at row {row}, column {column} must fail"
        );
        trace.rows[row][column] = original;
    }
    #[test]
    fn canonical_trace_is_exact_and_keeps_intermediate_hashes_private() {
        let value = fixture();
        let trace = build_private_note_base_trace_v1(&value.statement, &value.witness)
            .expect("canonical trace");
        assert_eq!(trace.rows.len(), PRIVATE_NOTE_TRACE_SIZE_V1);
        assert_eq!(trace.fixed.rows.len(), PRIVATE_NOTE_TRACE_SIZE_V1);
        assert!(
            trace
                .rows
                .iter()
                .all(|row| row.len() == PRIVATE_NOTE_BASE_WIDTH_V1)
        );
        assert_eq!(
            trace.fixed,
            build_private_note_fixed_trace_v1(&value.statement).expect("fixed topology")
        );
        validate_private_note_base_trace_v1(&value.statement, &trace)
            .expect("native AIR evaluator");
        let public_endpoints = trace
            .fixed
            .rows
            .iter()
            .filter_map(|row| match row {
                PrivateNoteFixedRowV1::ShaEnd {
                    public_digest: Some(digest),
                    ..
                } => Some(*digest),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(public_endpoints.len(), 4 * 4);
        let allowed = BTreeSet::from([
            *value.statement.program_id.as_bytes(),
            *value.statement.nullifiers[0].as_bytes(),
            *value.statement.state_root.as_bytes(),
            *value.statement.output_commitments[0].as_bytes(),
        ]);
        assert!(
            public_endpoints
                .iter()
                .all(|digest| allowed.contains(digest))
        );
        assert_eq!(
            public_endpoints.into_iter().collect::<BTreeSet<_>>(),
            allowed
        );
        assert!(trace.fixed.rows.iter().any(|row| {
            matches!(
                row,
                PrivateNoteFixedRowV1::ShaEnd {
                    public_digest: None,
                    ..
                }
            )
        }));
    }
    #[test]
    fn canonical_trace_helpers_select_the_ivm_private_note_profile() {
        let value = fixture();
        let canonical = build_private_note_base_trace_v1(&value.statement, &value.witness)
            .expect("canonical base trace");
        let profiled = build_private_note_base_trace_with_profile_v1(
            &value.statement,
            &value.witness,
            PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
        )
        .expect("explicit IVM private-note base trace");
        assert_eq!(canonical, profiled);
        assert_eq!(
            build_private_note_fixed_trace_v1(&value.statement).expect("canonical fixed trace"),
            build_private_note_fixed_trace_with_profile_v1(
                &value.statement,
                PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
            )
            .expect("explicit IVM private-note fixed trace")
        );
        assert_eq!(
            build_private_note_copy_schedule_v1(&value.statement).expect("canonical copy schedule"),
            build_private_note_copy_schedule_with_profile_v1(
                &value.statement,
                PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
            )
            .expect("explicit IVM private-note copy schedule")
        );
    }
    #[test]
    fn exact_three_output_trace_has_fixed_geometry_and_all_distinct_pairs() {
        let value = three_output_fixture();
        let trace = build_private_note_base_trace_with_profile_v1(
            &value.statement,
            &value.witness,
            value.profile,
        )
        .expect("three-output base trace");
        validate_private_note_base_trace_with_profile_v1(&value.statement, &trace, value.profile)
            .expect("three-output native AIR evaluator");
        assert_eq!(trace.rows.len(), PRIVATE_NOTE_TRACE_SIZE_V1);
        assert_eq!(
            trace.fixed,
            build_private_note_fixed_trace_with_profile_v1(&value.statement, value.profile)
                .expect("three-output fixed trace")
        );
        let comparison_ids = trace
            .fixed
            .rows
            .iter()
            .filter_map(|row| match row {
                PrivateNoteFixedRowV1::Distinct { comparison, .. } => Some(*comparison),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            comparison_ids.len(),
            11,
            "two input comparisons, six input/output pairs, and all three output/output pairs"
        );
        let output_sum_rows = trace
            .fixed
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row,
                    PrivateNoteFixedRowV1::Sum {
                        side: SumSideV1::Outputs,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            output_sum_rows, 32,
            "three outputs must use two chained 16-byte checked sums"
        );
    }

    #[test]
    fn virtual_zero_input_trace_retains_fixed_shape_and_enforces_positive_membership() {
        let mut value = three_output_fixture();
        value.witness.inputs[1].authentication_path = [[0xC7; 32]; PRIVATE_NOTE_TREE_DEPTH_V1];
        let trace = build_private_note_base_trace_with_profile_v1(
            &value.statement,
            &value.witness,
            value.profile,
        )
        .expect("virtual cover trace without a member leaf");
        validate_private_note_base_trace_with_profile_v1(&value.statement, &trace, value.profile)
            .expect("all AIR and copy constraints");
        assert_eq!(
            trace.fixed,
            build_private_note_fixed_trace_with_profile_v1(&value.statement, value.profile)
                .expect("fixed public topology")
        );
        assert_eq!(
            trace
                .fixed
                .rows
                .iter()
                .filter(|row| matches!(row, PrivateNoteFixedRowV1::Membership { .. }))
                .count(),
            2 * 16 * 11
        );
        // Bypass the wallet and trace compiler to exercise the actual equation:
        // a zero value permits a non-member root, but every positive value byte
        // rejects the same root even when an adversary chooses the row directly.
        let mut row = TraceBuilderV1::empty_row();
        row[COPY_OFFSET + 1] = F(1);
        row[COPY_OFFSET + 2] = F(2);
        validate_conditional_membership_v1(&row).expect("zero virtual input");
        for positive_byte in [1_u64, 128, 255] {
            row[COPY_OFFSET] = F(positive_byte);
            assert_eq!(
                validate_conditional_membership_v1(&row),
                Err(IvmPrivateNoteAirErrorV1::Relation)
            );
        }
    }

    #[test]
    fn audited_opening_substitution_fails_air_without_calling_wallet_validation() {
        let value = three_output_fixture();
        let mut trace = build_private_note_base_trace_with_profile_v1(
            &value.statement,
            &value.witness,
            value.profile,
        )
        .expect("honest proved inputs");
        let mut claimed = value
            .witness
            .inputs
            .iter()
            .map(|input| input.note.clone())
            .collect::<Vec<_>>();
        claimed[0].value -= 1;
        claimed[1].value += 1;
        let PrivateNoteRelationProfileV1::ExactThreeOutputBalanced {
            output_memo_digests,
            ..
        } = value.profile
        else {
            unreachable!()
        };
        let target = PrivateNoteRelationProfileV1::exact_three_output_balanced(
            output_memo_digests,
            super::super::derive_private_note_input_openings_commitment_v1(&claimed)
                .expect("false audited openings"),
        );
        // The attacker keeps actual ownership/nullifier/membership rows and
        // substitutes a same-total capsule claim. Use verifier-built topology
        // directly: the wallet's native preflight is deliberately not invoked.
        trace.fixed = build_private_note_fixed_trace_with_profile_v1(&value.statement, target)
            .expect("verifier topology");
        // The SHA rows are internally valid, but their digest disagrees with
        // the verifier-fixed audited-input assignment.
        assert_eq!(
            validate_private_note_base_trace_with_profile_v1(&value.statement, &trace, target),
            Err(IvmPrivateNoteAirErrorV1::Assignment)
        );
    }
    #[test]
    fn mutations_across_every_constraint_family_fail_closed() {
        let value = fixture();
        let mut trace = build_private_note_base_trace_v1(&value.statement, &value.witness)
            .expect("canonical trace");
        validate_private_note_base_trace_v1(&value.statement, &trace)
            .expect("canonical native AIR");
        let sha_round = row_index(&trace, |row| {
            matches!(row, PrivateNoteFixedRowV1::ShaRound { round: 16, .. })
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            sha_round,
            SHA_SCHEDULE_OFFSET + 16,
        );
        reject_cell_mutation(&value.statement, &mut trace, sha_round, SHA_BITS_OFFSET);
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            sha_round,
            SHA_CARRY_OFFSET + 6,
        );
        let sha_end = row_index(&trace, |row| {
            matches!(
                row,
                PrivateNoteFixedRowV1::ShaEnd {
                    digest_chunk: 0,
                    ..
                }
            )
        });
        reject_cell_mutation(&value.statement, &mut trace, sha_end, SHA_STATE_OFFSET);
        let node = row_index(&trace, |row| {
            matches!(row, PrivateNoteFixedRowV1::NodeSelect { .. })
        });
        reject_cell_mutation(&value.statement, &mut trace, node, COPY_OFFSET + 2);
        let distinct = row_index(&trace, |row| {
            matches!(row, PrivateNoteFixedRowV1::Distinct { .. })
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            distinct,
            SCRATCH_RUNNING_AFTER,
        );
        let nonzero = row_index(&trace, |row| {
            matches!(row, PrivateNoteFixedRowV1::NonZero { .. })
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            nonzero,
            SCRATCH_RUNNING_BEFORE,
        );
        let sum = row_index(&trace, |row| {
            matches!(
                row,
                PrivateNoteFixedRowV1::Sum {
                    side: SumSideV1::Inputs,
                    ..
                }
            )
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            sum,
            SCRATCH_RELATION_CARRY_AFTER,
        );
        let vm_program = row_index(&trace, |row| {
            matches!(row, PrivateNoteFixedRowV1::VmProgram { instruction: 0 })
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            vm_program,
            SCRATCH_VM_OPCODE_SELECT_OFFSET,
        );
        let vm_previous = row_index(&trace, |row| {
            matches!(
                row,
                PrivateNoteFixedRowV1::VmPrevious {
                    instruction: 0,
                    byte: 0,
                }
            )
        });
        reject_cell_mutation(
            &value.statement,
            &mut trace,
            vm_previous,
            SCRATCH_VM_RESULT_BITS_OFFSET,
        );
        let padding = row_index(&trace, |row| matches!(row, PrivateNoteFixedRowV1::Padding));
        reject_cell_mutation(&value.statement, &mut trace, padding, SCRATCH_OFFSET);
    }
    #[test]
    fn malformed_shape_fixed_topology_sigma_and_noncanonical_fields_fail() {
        let value = fixture();
        let mut trace = build_private_note_base_trace_v1(&value.statement, &value.witness)
            .expect("canonical trace");
        let removed = trace.rows.pop().expect("fixed trace is nonempty");
        assert!(validate_private_note_base_trace_v1(&value.statement, &trace).is_err());
        trace.rows.push(removed);
        let removed = trace.rows[0].pop().expect("fixed row is nonempty");
        assert!(validate_private_note_base_trace_v1(&value.statement, &trace).is_err());
        trace.rows[0].push(removed);
        let original = trace.rows[0][0];
        trace.rows[0][0] = F(GOLDILOCKS_MODULUS_V1);
        assert!(validate_private_note_base_trace_v1(&value.statement, &trace).is_err());
        trace.rows[0][0] = original;
        let original = trace.fixed.copy_sigma[0][0];
        trace.fixed.copy_sigma[0][0] = 0;
        assert!(validate_private_note_base_trace_v1(&value.statement, &trace).is_err());
        trace.fixed.copy_sigma[0][0] = original;
        let original = trace.fixed.rows[0].clone();
        trace.fixed.rows[0] = PrivateNoteFixedRowV1::Padding;
        assert!(validate_private_note_base_trace_v1(&value.statement, &trace).is_err());
        trace.fixed.rows[0] = original;
        validate_private_note_base_trace_v1(&value.statement, &trace)
            .expect("restored trace remains canonical");
    }
    fn maximum_fixture() -> (IrohaIvmPrivateNoteStarkStatementV1, IvmPrivateNoteWitnessV1) {
        let mut value = fixture();
        let first = value.witness.inputs[0].clone();
        let second_secret = [0x81; 32];
        let second_note = PrivateNotePlaintextV1 {
            value: 10,
            spending_authority: derive_note_authority_v1(&second_secret).expect("second authority"),
            rho: [0x82; 32],
            blinding: [0x83; 32],
            memo_digest: [0x84; 32],
        };
        let second_commitment =
            derive_note_commitment_v1(&second_note).expect("second input commitment");
        let first_commitment =
            derive_note_commitment_v1(&first.note).expect("first input commitment");
        let second_output_secret = [0x91; 32];
        let second_output_note = PrivateNotePlaintextV1 {
            value: 10,
            spending_authority: derive_note_authority_v1(&second_output_secret)
                .expect("second output authority"),
            rho: [0x92; 32],
            blinding: [0x93; 32],
            memo_digest: [0x94; 32],
        };
        let second_output_commitment =
            derive_note_commitment_v1(&second_output_note).expect("second output commitment");
        let recipient_public_key =
            ivm_private_recipient_public_key_v1(&[0x95; 32]).expect("second recipient public key");
        let second_encrypted_output = encrypt_ivm_private_wallet_note_v1(
            &mut StdRng::seed_from_u64(0x49_50_4e_45_02),
            value.statement.pool_id,
            value.statement.program_id,
            &second_output_note,
            recipient_public_key,
        )
        .expect("second canonical encrypted output");
        value
            .statement
            .output_commitments
            .push(second_output_commitment);
        value
            .statement
            .encrypted_outputs
            .push(second_encrypted_output);
        let leaf_0 = accumulator_leaf_invocation_v1(&value.statement, 0, first_commitment)
            .expect("first leaf")
            .digest;
        let leaf_1 = accumulator_leaf_invocation_v1(&value.statement, 1, second_commitment)
            .expect("second leaf")
            .digest;
        let mut path_0 = [[0_u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1];
        let mut path_1 = [[0_u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1];
        path_0[0] = leaf_1;
        path_1[0] = leaf_0;
        for level in 1..PRIVATE_NOTE_TREE_DEPTH_V1 {
            let seed = u8::try_from(level)
                .expect("tree depth fits u8")
                .wrapping_add(0xa0);
            path_0[level] = [seed; 32];
            path_1[level] = [seed; 32];
        }
        let mut root = accumulator_node_invocation_v1(0, 0, &leaf_0, &leaf_1)
            .expect("sibling leaves")
            .digest;
        for (level, sibling) in path_0.iter().enumerate().skip(1) {
            root = accumulator_node_invocation_v1(
                0,
                u8::try_from(level).expect("tree depth fits u8"),
                &root,
                sibling,
            )
            .expect("shared upper path")
            .digest;
        }
        value.statement.state_root = PrivacyRootV1::new(root);
        value.witness.inputs[0].leaf_position = 0;
        value.witness.inputs[0].authentication_path = path_0;
        let second_rho = second_note.rho;
        value.witness.inputs.push(IvmPrivateNoteInputWitnessV1 {
            note: second_note,
            spending_secret: second_secret,
            leaf_position: 1,
            authentication_path: path_1,
        });
        value.witness.outputs.push(IvmPrivateNoteOutputWitnessV1 {
            note: second_output_note,
        });
        value.statement.nullifiers = vec![
            derive_note_nullifier_v1(
                &value.statement,
                &first.spending_secret,
                &first.note.rho,
                first_commitment,
            )
            .expect("first nullifier"),
            derive_note_nullifier_v1(
                &value.statement,
                &second_secret,
                &second_rho,
                second_commitment,
            )
            .expect("second nullifier"),
        ];
        value.statement.action_digest = PrivacyActionDigestV1::new([0; 32]);
        value.statement.action_digest = value
            .statement
            .computed_action_digest()
            .expect("maximum action digest");
        (value.statement, value.witness)
    }
    #[test]
    fn maximum_two_by_two_relation_fits_the_exact_trace_bound() {
        let (statement, witness) = maximum_fixture();
        let trace =
            build_private_note_base_trace_v1(&statement, &witness).expect("maximum trace fits");
        let first_padding = row_index(&trace, |row| matches!(row, PrivateNoteFixedRowV1::Padding));
        assert!(first_padding < PRIVATE_NOTE_TRACE_SIZE_V1);
        assert!(first_padding > PRIVATE_NOTE_TRACE_SIZE_V1 / 2);
        assert!(
            trace.fixed.rows[first_padding..]
                .iter()
                .all(|row| matches!(row, PrivateNoteFixedRowV1::Padding))
        );
        validate_private_note_base_trace_v1(&statement, &trace).expect("maximum native AIR trace");
    }
}
