//! Aggregate fixed-topology AIR for the native PQ-MASP relation.
//!
//! The circuit keeps every intermediate SHA-256 digest private.  A fixed
//! byte-copy permutation connects note fields, hash inputs and outputs,
//! accumulator children, and value arithmetic. Public statement bytes are
//! verifier-derived fixed constraints at their final endpoints.
use super::relation::{
    ACCUMULATOR_LEAF_DOMAIN_V1, ACCUMULATOR_NODE_DOMAIN_V1, HASH_FRAME_DOMAIN_V1,
    NOTE_COMMITMENT_DOMAIN_V1, NOTE_ENCRYPTION_KEYS_DOMAIN_V1, NOTE_NULLIFIER_DOMAIN_V1,
    NULLIFIER_KEY_DOMAIN_V1, PQ_MASP_INPUT_BOUND_V1, PQ_MASP_OUTPUT_BOUND_V1,
    PQ_MASP_TREE_DEPTH_V1, PqMaspNotePlaintextV1, PqMaspSha256InvocationV1, PqMaspSha256RoleV1,
    PqMaspWitnessV1, namespace_v1, validate_pq_masp_relation_v1, validate_statement_v1,
};
use crate::privacy_engines::{
    proof_managed_note_stark::{
        NoteCopyCellPolicyV1, NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1,
    },
    transparent_stark::GoldilocksFieldV1 as F,
};
use iroha_data_model::privacy::PqMaspStarkStatementV1;
use std::collections::BTreeMap;
use thiserror::Error;
pub(super) const PQ_MASP_TRACE_LOG2_V1: u8 = 14;
pub(super) const PQ_MASP_TRACE_SIZE_V1: usize = 1 << PQ_MASP_TRACE_LOG2_V1;
pub(super) const PQ_MASP_COPY_WIDTH_V1: usize = 8;
pub(super) const PQ_MASP_SHA_SCHEDULE_WORDS_V1: usize = 64;
pub(super) const PQ_MASP_SHA_STATE_WORDS_V1: usize = 8;
pub(super) const PQ_MASP_SHA_BIT_GROUPS_V1: usize = 11;
pub(super) const PQ_MASP_SHA_BITS_PER_GROUP_V1: usize = 32;
pub(super) const PQ_MASP_SHA_BIT_COLUMNS_V1: usize =
    PQ_MASP_SHA_BIT_GROUPS_V1 * PQ_MASP_SHA_BITS_PER_GROUP_V1;
pub(super) const COPY_OFFSET: usize = 0;
pub(super) const SHA_SCHEDULE_OFFSET: usize = COPY_OFFSET + PQ_MASP_COPY_WIDTH_V1;
pub(super) const SHA_INITIAL_STATE_OFFSET: usize =
    SHA_SCHEDULE_OFFSET + PQ_MASP_SHA_SCHEDULE_WORDS_V1;
pub(super) const SHA_STATE_OFFSET: usize = SHA_INITIAL_STATE_OFFSET + PQ_MASP_SHA_STATE_WORDS_V1;
pub(super) const SHA_BITS_OFFSET: usize = SHA_STATE_OFFSET + PQ_MASP_SHA_STATE_WORDS_V1;
pub(super) const SHA_T1_OFFSET: usize = SHA_BITS_OFFSET + PQ_MASP_SHA_BIT_COLUMNS_V1;
pub(super) const SHA_T2_OFFSET: usize = SHA_T1_OFFSET + 1;
pub(super) const SHA_CARRY_OFFSET: usize = SHA_T2_OFFSET + 1;
pub(super) const SHA_CARRY_WIDTH: usize = 18;
pub(super) const SCRATCH_OFFSET: usize = SHA_CARRY_OFFSET + SHA_CARRY_WIDTH;
pub(super) const SCRATCH_WIDTH: usize = 96;
pub(super) const PQ_MASP_BASE_WIDTH_V1: usize = SCRATCH_OFFSET + SCRATCH_WIDTH;
pub(super) const SCRATCH_NONZERO_BYTE_SELECT_OFFSET: usize = SCRATCH_OFFSET;
pub(super) const SCRATCH_NONZERO_BIT_SELECT_OFFSET: usize =
    SCRATCH_NONZERO_BYTE_SELECT_OFFSET + PQ_MASP_COPY_WIDTH_V1;
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
// Distinctness rows share the right-hand byte-bit cells with the reserved VM
// difference decomposition. The row selectors are disjoint, so the alias
// preserves the committed V1 layout while naming both consumers explicitly.
pub(super) const SCRATCH_DISTINCT_RIGHT_BITS_OFFSET: usize = SCRATCH_VM_DIFFERENCE_BITS_OFFSET;
const _: () = assert!(SCRATCH_DISTINCT_RIGHT_BITS_OFFSET == SCRATCH_OFFSET + 81);
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
pub const PQ_MASP_AGGREGATE_AIR_DESCRIPTOR_V1: &[u8] = b"pq-masp-aggregate-air-v1:trace=16384:copy-width=8:copy-lanes=3:sha256-wide-round64-private-intermediates:value=u128-checked-byte-carry:tree=depth32-private-direction:public-endpoints=verifier-fixed";
/// Aggregate trace construction or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(super) enum PqMaspAirErrorV1 {
    #[error("PQ-MASP AIR relation is invalid")]
    Relation,
    #[error("PQ-MASP AIR topology is invalid")]
    Topology,
    #[error("PQ-MASP AIR byte assignment is inconsistent")]
    Assignment,
    #[error("PQ-MASP AIR resource bound is exceeded")]
    Resource,
    #[error("PQ-MASP AIR SHA-256 schedule is invalid")]
    Sha256,
    #[error("PQ-MASP AIR copy permutation is invalid")]
    #[cfg_attr(not(test), allow(dead_code))]
    Copy,
}
include!("../shared_note_air.rs");
define_note_air_trace_core_v1! {
    error: PqMaspAirErrorV1,
    role: PqMaspSha256RoleV1,
    fixed_row: PqMaspFixedRowV1,
    base_width: PQ_MASP_BASE_WIDTH_V1,
    copy_width: PQ_MASP_COPY_WIDTH_V1,
    sha_bits_per_group: PQ_MASP_SHA_BITS_PER_GROUP_V1,
    tree_depth: PQ_MASP_TREE_DEPTH_V1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(variant_size_differences)]
pub(super) enum PqMaspFixedRowV1 {
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
    #[cfg_attr(not(test), allow(dead_code))]
    VmHeader,
    #[cfg_attr(not(test), allow(dead_code))]
    VmProgram {
        instruction: u8,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    VmPrevious {
        instruction: u8,
        byte: u8,
    },
    #[cfg_attr(not(test), allow(dead_code))]
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
pub(super) struct PqMaspFixedTraceV1 {
    pub(super) rows: Vec<PqMaspFixedRowV1>,
    copy_cells: Vec<[CopyCellV1; PQ_MASP_COPY_WIDTH_V1]>,
    pub(super) copy_sigma: Vec<[u32; PQ_MASP_COPY_WIDTH_V1]>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PqMaspBaseTraceV1 {
    pub(super) fixed: PqMaspFixedTraceV1,
    pub(super) rows: Vec<Vec<F>>,
}
impl core::fmt::Debug for PqMaspBaseTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PqMaspBaseTraceV1")
            .field("row_count", &self.rows.len())
            .field("witness_columns", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
struct NoteVariablesV1 {
    value: [ByteVariableV1; 16],
    authorization: [ByteExpressionV1; 32],
    authorization_variables: Option<[ByteVariableV1; 32]>,
    recipient: [ByteExpressionV1; 32],
    recipient_variables: Option<[ByteVariableV1; 32]>,
    nullifier_key: [ByteVariableV1; 32],
    rho: [ByteVariableV1; 32],
    blinding: [ByteVariableV1; 32],
    memo: [ByteVariableV1; 32],
}
#[derive(Clone)]
struct InputVariablesV1 {
    note: NoteVariablesV1,
    secret: [ByteVariableV1; 32],
    position_bits: [ByteVariableV1; 32],
    path: [[ByteVariableV1; 32]; PQ_MASP_TREE_DEPTH_V1],
    commitment: Option<[ByteVariableV1; 32]>,
}
#[derive(Clone)]
struct OutputVariablesV1 {
    note: NoteVariablesV1,
    commitment: Option<[ByteVariableV1; 32]>,
}
struct TraceBuilderV1<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    statement: &'a PqMaspStarkStatementV1,
    witness: Option<&'a PqMaspWitnessV1>,
    assignment: Vec<u8>,
    rows: Vec<Vec<F>>,
    fixed_rows: Vec<PqMaspFixedRowV1>,
    copy_cells: Vec<[CopyCellV1; PQ_MASP_COPY_WIDTH_V1]>,
    hash_invocation_count: usize,
    invocation_oracle: Vec<PqMaspSha256InvocationV1>,
    invocation_cursor: usize,
    expected_input_sum: u128,
    expected_output_sum: u128,
}
impl<'a> TraceBuilderV1<'a> {
    fn new(
        statement: &'a PqMaspStarkStatementV1,
        witness: Option<&'a PqMaspWitnessV1>,
    ) -> Result<Self, PqMaspAirErrorV1> {
        let (invocation_oracle, expected_input_sum, expected_output_sum) =
            if let Some(witness) = witness {
                let relation = validate_pq_masp_relation_v1(statement, witness)
                    .map_err(|_| PqMaspAirErrorV1::Relation)?;
                (
                    relation.invocations,
                    relation.input_sum,
                    relation.output_sum,
                )
            } else {
                (Vec::new(), 0, 0)
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
            expected_input_sum,
            expected_output_sum,
        })
    }
    fn next_oracle_digest(&self, role: PqMaspSha256RoleV1) -> Result<[u8; 32], PqMaspAirErrorV1> {
        if self.witness.is_none() {
            return Ok([0; 32]);
        }
        self.invocation_oracle
            .get(self.invocation_cursor)
            .filter(|invocation| invocation.role == role)
            .map(|invocation| invocation.digest)
            .ok_or(PqMaspAirErrorV1::Topology)
    }
    fn allocate_note_field(
        &mut self,
        bytes: [u8; 32],
        verifier_fixed: Option<[u8; 32]>,
    ) -> Result<([ByteExpressionV1; 32], Option<[ByteVariableV1; 32]>), PqMaspAirErrorV1> {
        if let Some(fixed) = verifier_fixed {
            if self.witness.is_some() && bytes != fixed {
                return Err(PqMaspAirErrorV1::Assignment);
            }
            return Ok((fixed.map(ByteExpressionV1::Constant), None));
        }
        let variables = self.allocate_bytes(bytes);
        Ok((variables.map(ByteExpressionV1::Variable), Some(variables)))
    }
    fn allocate_note(
        &mut self,
        note: Option<PqMaspNotePlaintextV1>,
        authorization_fixed: Option<[u8; 32]>,
        recipient_fixed: Option<[u8; 32]>,
    ) -> Result<NoteVariablesV1, PqMaspAirErrorV1> {
        let value = note.as_ref().map_or(0, |note| note.value);
        let authorization = note
            .as_ref()
            .map_or([0; 32], |note| *note.authorization_key_digest.as_bytes());
        let recipient = note
            .as_ref()
            .map_or([0; 32], |note| *note.recipient_key_digest.as_bytes());
        let nullifier_key = note
            .as_ref()
            .map_or([0; 32], |note| note.nullifier_key_digest);
        let rho = note.as_ref().map_or([0; 32], |note| note.rho);
        let blinding = note.as_ref().map_or([0; 32], |note| note.blinding);
        let memo = note.as_ref().map_or([0; 32], |note| note.memo_digest);
        let (authorization, authorization_variables) =
            self.allocate_note_field(authorization, authorization_fixed)?;
        let (recipient, recipient_variables) =
            self.allocate_note_field(recipient, recipient_fixed)?;
        Ok(NoteVariablesV1 {
            value: self.allocate_bytes(value.to_be_bytes()),
            authorization,
            authorization_variables,
            recipient,
            recipient_variables,
            nullifier_key: self.allocate_bytes(nullifier_key),
            rho: self.allocate_bytes(rho),
            blinding: self.allocate_bytes(blinding),
            memo: self.allocate_bytes(memo),
        })
    }
    fn push_distinct(
        &mut self,
        comparison: u8,
        left: &[ByteVariableV1],
        right: &[ByteVariableV1],
    ) -> Result<(), PqMaspAirErrorV1> {
        const PAIRS_PER_ROW: usize = PQ_MASP_COPY_WIDTH_V1 / 2;
        if left.is_empty() || left.len() != right.len() || left.len() > 32 {
            return Err(PqMaspAirErrorV1::Topology);
        }
        let chunks = left.len().div_ceil(PAIRS_PER_ROW);
        let selected = left
            .iter()
            .zip(right)
            .position(|(left, right)| self.assignment[left.0] != self.assignment[right.0]);
        if self.witness.is_some() && selected.is_none() {
            return Err(PqMaspAirErrorV1::Assignment);
        }
        let mut running = 0_u8;
        for chunk in 0..chunks {
            let start = chunk * PAIRS_PER_ROW;
            let end = (start + PAIRS_PER_ROW).min(left.len());
            let mut cells = [CopyCellV1::Inactive; PQ_MASP_COPY_WIDTH_V1];
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
                    row[SCRATCH_DISTINCT_RIGHT_BITS_OFFSET + bit] =
                        F(u64::from((right_byte >> bit) & 1));
                }
                running = 1;
            }
            row[SCRATCH_RUNNING_AFTER] = F(u64::from(running));
            self.push_row(
                PqMaspFixedRowV1::Distinct {
                    comparison,
                    chunk: u8::try_from(chunk).map_err(|_| PqMaspAirErrorV1::Resource)?,
                    chunks: u8::try_from(chunks).map_err(|_| PqMaspAirErrorV1::Resource)?,
                },
                cells,
                row,
            )?;
        }
        Ok(())
    }
    fn push_conservation(
        &mut self,
        input_sum: [ByteVariableV1; 16],
        output_sum: [ByteVariableV1; 16],
    ) -> Result<(), PqMaspAirErrorV1> {
        let public_in = [0_u8; 16];
        let public_out = [0_u8; 16];
        let mut carry = 0_i16;
        for little_byte in 0..16 {
            let byte = 15 - little_byte;
            let left =
                i16::from(self.assignment[input_sum[byte].0]) + i16::from(public_in[byte]) + carry;
            let right =
                i16::from(self.assignment[output_sum[byte].0]) + i16::from(public_out[byte]);
            let difference = left - right;
            if self.witness.is_some() && difference.rem_euclid(256) != 0 {
                return Err(PqMaspAirErrorV1::Assignment);
            }
            let next_carry = difference.div_euclid(256);
            if !(-1..=1).contains(&next_carry) {
                return Err(PqMaspAirErrorV1::Assignment);
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
                PqMaspFixedRowV1::Sum {
                    side: SumSideV1::Conservation,
                    byte: u8::try_from(little_byte).map_err(|_| PqMaspAirErrorV1::Resource)?,
                },
                cells,
                row,
            )?;
            carry = next_carry;
        }
        if self.witness.is_some() && carry != 0 {
            return Err(PqMaspAirErrorV1::Assignment);
        }
        Ok(())
    }
}
fn note_commitment_fields(
    asset: &[u8],
    pool: &[u8],
    note: &NoteVariablesV1,
) -> Vec<Vec<ByteExpressionV1>> {
    vec![
        constants_as_expressions(asset),
        constants_as_expressions(pool),
        variables_as_expressions(&note.value),
        note.authorization.to_vec(),
        note.recipient.to_vec(),
        variables_as_expressions(&note.nullifier_key),
        variables_as_expressions(&note.rho),
        variables_as_expressions(&note.blinding),
        variables_as_expressions(&note.memo),
    ]
}
fn build_pq_masp_trace_v1(
    statement: &PqMaspStarkStatementV1,
    witness: Option<&PqMaspWitnessV1>,
) -> Result<PqMaspBaseTraceV1, PqMaspAirErrorV1> {
    validate_statement_v1(statement).map_err(|_| PqMaspAirErrorV1::Relation)?;
    if statement.nullifiers.is_empty()
        || statement.nullifiers.len() > PQ_MASP_INPUT_BOUND_V1
        || statement.output_commitments.is_empty()
        || statement.output_commitments.len() > PQ_MASP_OUTPUT_BOUND_V1
    {
        return Err(PqMaspAirErrorV1::Topology);
    }
    let mut builder = TraceBuilderV1::new(statement, witness)?;
    let statement = builder.statement;
    let mut input_variables = Vec::with_capacity(statement.nullifiers.len());
    for index in 0..statement.nullifiers.len() {
        let input = witness.and_then(|witness| witness.inputs.get(index));
        let note = builder.allocate_note(
            input.map(|input| input.note.clone()),
            Some(*statement.authorization_key_digest.as_bytes()),
            None,
        )?;
        let secret = builder.allocate_bytes(input.map_or([0; 32], |input| input.nullifier_secret));
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
        let recipient = *statement.encrypted_outputs[index].recipient.as_bytes();
        output_variables.push(OutputVariablesV1 {
            note: builder.allocate_note(
                output.map(|output| output.note.clone()),
                None,
                Some(recipient),
            )?,
            commitment: None,
        });
    }
    let asset =
        norito::to_bytes(&statement.asset_definition_id).map_err(|_| PqMaspAirErrorV1::Topology)?;
    let namespace =
        norito::to_bytes(&namespace_v1(statement)).map_err(|_| PqMaspAirErrorV1::Topology)?;
    let mut nonzero_components = Vec::<Vec<ByteVariableV1>>::new();
    for (index, input) in input_variables.iter_mut().enumerate() {
        let input_index = u8::try_from(index).map_err(|_| PqMaspAirErrorV1::Resource)?;
        let nullifier_key_message = frame_expressions_v1(
            NULLIFIER_KEY_DOMAIN_V1,
            &[variables_as_expressions(&input.secret)],
        )?;
        builder.push_hash(
            PqMaspSha256RoleV1::NullifierKey { input: input_index },
            nullifier_key_message,
            input.note.nullifier_key,
            None,
        )?;
        let commitment_digest = builder
            .next_oracle_digest(PqMaspSha256RoleV1::InputCommitment { input: input_index })?;
        let commitment_variables = builder.allocate_bytes(commitment_digest);
        let commitment_message = frame_expressions_v1(
            NOTE_COMMITMENT_DOMAIN_V1,
            &note_commitment_fields(&asset, statement.pool_id.as_bytes(), &input.note),
        )?;
        builder.push_hash(
            PqMaspSha256RoleV1::InputCommitment { input: input_index },
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
            ],
        )?;
        builder.push_hash(
            PqMaspSha256RoleV1::Nullifier { input: input_index },
            nullifier_message,
            nullifier_variables,
            Some(*statement.nullifiers[index].as_bytes()),
        )?;
        let leaf_digest = builder
            .next_oracle_digest(PqMaspSha256RoleV1::AccumulatorLeaf { input: input_index })?;
        let mut current = builder.allocate_bytes(leaf_digest);
        let mut leaf_message = Vec::new();
        leaf_message.extend(constants_as_expressions(ACCUMULATOR_LEAF_DOMAIN_V1));
        leaf_message.extend(constants_as_expressions(
            &u64::try_from(namespace.len())
                .map_err(|_| PqMaspAirErrorV1::Resource)?
                .to_be_bytes(),
        ));
        leaf_message.extend(constants_as_expressions(&namespace));
        leaf_message.extend(variables_as_expressions(&commitment_variables));
        builder.push_hash(
            PqMaspSha256RoleV1::AccumulatorLeaf { input: input_index },
            leaf_message,
            current,
            None,
        )?;
        for level in 0..PQ_MASP_TREE_DEPTH_V1 {
            let level_u8 = u8::try_from(level).map_err(|_| PqMaspAirErrorV1::Resource)?;
            let (left, right) = builder.push_node_select(
                input_index,
                level_u8,
                input.position_bits[level],
                current,
                input.path[level],
            )?;
            let digest = builder.next_oracle_digest(PqMaspSha256RoleV1::AccumulatorNode {
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
                PqMaspSha256RoleV1::AccumulatorNode {
                    input: input_index,
                    level: level_u8,
                },
                node_message,
                next,
                (level + 1 == PQ_MASP_TREE_DEPTH_V1).then_some(*statement.anchor.as_bytes()),
            )?;
            current = next;
        }
        nonzero_components.push(input.note.value.to_vec());
        nonzero_components.push(
            input
                .note
                .recipient_variables
                .ok_or(PqMaspAirErrorV1::Topology)?
                .to_vec(),
        );
        nonzero_components.push(input.note.nullifier_key.to_vec());
        nonzero_components.push(input.note.rho.to_vec());
        nonzero_components.push(input.note.blinding.to_vec());
        nonzero_components.push(input.secret.to_vec());
    }
    for (index, output) in output_variables.iter_mut().enumerate() {
        let output_index = u8::try_from(index).map_err(|_| PqMaspAirErrorV1::Resource)?;
        let commitment_variables =
            builder.allocate_bytes(*statement.output_commitments[index].as_bytes());
        let commitment_message = frame_expressions_v1(
            NOTE_COMMITMENT_DOMAIN_V1,
            &note_commitment_fields(&asset, statement.pool_id.as_bytes(), &output.note),
        )?;
        builder.push_hash(
            PqMaspSha256RoleV1::OutputCommitment {
                output: output_index,
            },
            commitment_message,
            commitment_variables,
            Some(*statement.output_commitments[index].as_bytes()),
        )?;
        output.commitment = Some(commitment_variables);
        nonzero_components.push(output.note.value.to_vec());
        nonzero_components.push(
            output
                .note
                .authorization_variables
                .ok_or(PqMaspAirErrorV1::Topology)?
                .to_vec(),
        );
        nonzero_components.push(output.note.nullifier_key.to_vec());
        nonzero_components.push(output.note.rho.to_vec());
        nonzero_components.push(output.note.blinding.to_vec());
    }
    let mut key_fields = Vec::with_capacity(
        statement
            .encrypted_outputs
            .len()
            .checked_mul(2)
            .ok_or(PqMaspAirErrorV1::Resource)?,
    );
    for output in &statement.encrypted_outputs {
        key_fields.push(constants_as_expressions(output.recipient.as_bytes()));
        key_fields.push(constants_as_expressions(
            output.ephemeral_public_key.as_bytes(),
        ));
    }
    let encryption_digest =
        builder.allocate_bytes(*statement.note_encryption_key_digest.as_bytes());
    let encryption_message = frame_expressions_v1(NOTE_ENCRYPTION_KEYS_DOMAIN_V1, &key_fields)?;
    builder.push_hash(
        PqMaspSha256RoleV1::EncryptionKeySet,
        encryption_message,
        encryption_digest,
        Some(*statement.note_encryption_key_digest.as_bytes()),
    )?;
    let mut comparison = 0_u8;
    if input_variables.len() == 2 {
        let left_commitment = input_variables[0]
            .commitment
            .ok_or(PqMaspAirErrorV1::Topology)?;
        let right_commitment = input_variables[1]
            .commitment
            .ok_or(PqMaspAirErrorV1::Topology)?;
        builder.push_distinct(comparison, &left_commitment, &right_commitment)?;
        comparison = comparison
            .checked_add(1)
            .ok_or(PqMaspAirErrorV1::Resource)?;
        builder.push_distinct(
            comparison,
            &input_variables[0].secret,
            &input_variables[1].secret,
        )?;
        comparison = comparison
            .checked_add(1)
            .ok_or(PqMaspAirErrorV1::Resource)?;
    }
    for input in &input_variables {
        let input_commitment = input.commitment.ok_or(PqMaspAirErrorV1::Topology)?;
        for output in &output_variables {
            let output_commitment = output.commitment.ok_or(PqMaspAirErrorV1::Topology)?;
            builder.push_distinct(comparison, &input_commitment, &output_commitment)?;
            comparison = comparison
                .checked_add(1)
                .ok_or(PqMaspAirErrorV1::Resource)?;
        }
    }
    if output_variables.len() == 2 {
        let left_commitment = output_variables[0]
            .commitment
            .ok_or(PqMaspAirErrorV1::Topology)?;
        let right_commitment = output_variables[1]
            .commitment
            .ok_or(PqMaspAirErrorV1::Topology)?;
        builder.push_distinct(comparison, &left_commitment, &right_commitment)?;
    }
    for (component, variables) in nonzero_components.iter().enumerate() {
        builder.push_nonzero(
            u16::try_from(component).map_err(|_| PqMaspAirErrorV1::Resource)?,
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
    let input_sum_variables =
        builder.push_sum(SumSideV1::Inputs, &input_values, builder.expected_input_sum)?;
    let output_sum_variables = builder.push_sum(
        SumSideV1::Outputs,
        &output_values,
        builder.expected_output_sum,
    )?;
    builder.push_conservation(input_sum_variables, output_sum_variables)?;
    if witness.is_some() && builder.invocation_cursor != builder.invocation_oracle.len() {
        return Err(PqMaspAirErrorV1::Topology);
    }
    if builder.rows.len() > PQ_MASP_TRACE_SIZE_V1 {
        return Err(PqMaspAirErrorV1::Resource);
    }
    while builder.rows.len() < PQ_MASP_TRACE_SIZE_V1 {
        builder.push_row(
            PqMaspFixedRowV1::Padding,
            [CopyCellV1::Inactive; PQ_MASP_COPY_WIDTH_V1],
            TraceBuilderV1::empty_row(),
        )?;
    }
    let copy_sigma = build_copy_sigma_v1(&builder.copy_cells)?;
    Ok(PqMaspBaseTraceV1 {
        fixed: PqMaspFixedTraceV1 {
            rows: builder.fixed_rows,
            copy_cells: builder.copy_cells,
            copy_sigma,
        },
        rows: builder.rows,
    })
}
/// Compile the complete prover trace after checking the native differential oracle.
pub(super) fn build_pq_masp_base_trace_v1(
    statement: &PqMaspStarkStatementV1,
    witness: &PqMaspWitnessV1,
) -> Result<PqMaspBaseTraceV1, PqMaspAirErrorV1> {
    build_pq_masp_trace_v1(statement, Some(witness))
}
/// Compile verifier-owned fixed topology without requiring wallet material.
pub(super) fn build_pq_masp_fixed_trace_v1(
    statement: &PqMaspStarkStatementV1,
) -> Result<PqMaspFixedTraceV1, PqMaspAirErrorV1> {
    Ok(build_pq_masp_trace_v1(statement, None)?.fixed)
}
fn map_copy_schedule_error_v1(error: ProofManagedNoteStarkErrorV1) -> PqMaspAirErrorV1 {
    match error {
        ProofManagedNoteStarkErrorV1::Copy => PqMaspAirErrorV1::Copy,
        ProofManagedNoteStarkErrorV1::Resource => PqMaspAirErrorV1::Resource,
        ProofManagedNoteStarkErrorV1::InvalidProfile
        | ProofManagedNoteStarkErrorV1::InvalidTrace
        | ProofManagedNoteStarkErrorV1::Constraint
        | ProofManagedNoteStarkErrorV1::ProofWire
        | ProofManagedNoteStarkErrorV1::TraceOpening
        | ProofManagedNoteStarkErrorV1::Composition
        | ProofManagedNoteStarkErrorV1::Fri
        | ProofManagedNoteStarkErrorV1::Transcript
        | ProofManagedNoteStarkErrorV1::Randomness
        | ProofManagedNoteStarkErrorV1::Internal => PqMaspAirErrorV1::Topology,
    }
}
fn validate_copy_schedule_v1(schedule: &NoteCopyScheduleV1) -> Result<(), PqMaspAirErrorV1> {
    schedule
        .validate(PQ_MASP_TRACE_SIZE_V1)
        .map_err(map_copy_schedule_error_v1)
}
/// Compile witness-allocation identities into the shared copy-chip policy.
pub(super) fn build_pq_masp_copy_schedule_v1(
    statement: &PqMaspStarkStatementV1,
) -> Result<NoteCopyScheduleV1, PqMaspAirErrorV1> {
    let fixed = build_pq_masp_fixed_trace_v1(statement)?;
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
    let schedule = NoteCopyScheduleV1 {
        policies,
        sigma: fixed.copy_sigma,
    };
    validate_copy_schedule_v1(&schedule)?;
    Ok(schedule)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copy_schedule_validation_preserves_copy_and_resource_errors() {
        let invalid = NoteCopyScheduleV1 {
            policies: Vec::new(),
            sigma: Vec::new(),
        };
        assert_eq!(
            validate_copy_schedule_v1(&invalid),
            Err(PqMaspAirErrorV1::Copy)
        );
        assert_eq!(
            map_copy_schedule_error_v1(ProofManagedNoteStarkErrorV1::Resource),
            PqMaspAirErrorV1::Resource
        );
    }
}
