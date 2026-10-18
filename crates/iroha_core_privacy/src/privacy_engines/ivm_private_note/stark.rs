//! Extension-domain adapter for the fixed native private-note AIR.
//!
//! The verifier reconstructs every selector and constant column from the
//! public statement. The prover only commits witness-bearing base columns and
//! one carry bridge needed by the alternating VM previous/next row layout.
#[cfg(test)]
use super::air::validate_private_note_base_trace_v1;
use super::{
    air::{
        COPY_OFFSET, IvmPrivateNoteAirErrorV1, PRIVATE_NOTE_BASE_WIDTH_V1,
        PRIVATE_NOTE_COPY_WIDTH_V1, PRIVATE_NOTE_SHA_BIT_COLUMNS_V1,
        PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1, PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1,
        PRIVATE_NOTE_SHA_STATE_WORDS_V1, PRIVATE_NOTE_TRACE_LOG2_V1, PRIVATE_NOTE_TRACE_SIZE_V1,
        PrivateNoteBaseTraceV1, PrivateNoteFixedRowV1, SCRATCH_BYTE_BITS_OFFSET,
        SCRATCH_NONZERO_BIT_SELECT_OFFSET, SCRATCH_NONZERO_BYTE_SELECT_OFFSET,
        SCRATCH_RELATION_CARRY_AFTER, SCRATCH_RELATION_CARRY_BEFORE,
        SCRATCH_RELATION_CARRY_BITS_OFFSET, SCRATCH_RUNNING_AFTER, SCRATCH_RUNNING_BEFORE,
        SCRATCH_VM_CARRY_AFTER, SCRATCH_VM_CARRY_BEFORE, SCRATCH_VM_DESTINATION_SELECT_OFFSET,
        SCRATCH_VM_DIFFERENCE, SCRATCH_VM_DIFFERENCE_BITS_OFFSET, SCRATCH_VM_HALTED_AFTER,
        SCRATCH_VM_HALTED_BEFORE, SCRATCH_VM_IMMEDIATE_OFFSET, SCRATCH_VM_LEFT_SELECT_OFFSET,
        SCRATCH_VM_OPCODE_SELECT_OFFSET, SCRATCH_VM_RESULT, SCRATCH_VM_RESULT_BITS_OFFSET,
        SCRATCH_VM_RIGHT_SELECT_OFFSET, SHA_BITS_OFFSET, SHA_CARRY_OFFSET, SHA_CARRY_WIDTH,
        SHA_INITIAL_STATE_OFFSET, SHA_SCHEDULE_OFFSET, SHA_STATE_OFFSET, SHA_T1_OFFSET,
        SHA_T2_OFFSET, SHA256_INITIAL_STATE_V1, SHA256_ROUND_CONSTANTS_V1, SumSideV1,
        build_private_note_base_trace_with_profile_v1,
        build_private_note_copy_schedule_with_profile_v1,
        build_private_note_fixed_trace_with_profile_v1,
        validate_private_note_base_trace_with_profile_v1,
    },
    relation::{IvmPrivateNoteWitnessV1, PrivateNoteRelationProfileV1},
};
#[cfg(test)]
use crate::privacy_engines::proof_managed_note_stark::proof_managed_note_stark_profile_digest_v1;
use crate::privacy_engines::{
    aggregate_stark as aggregate,
    proof_managed_note_stark::{
        NOTE_COPY_AUX_WIDTH_V1, NOTE_COPY_FIXED_WIDTH_V1, NoteCopyChallengesV1, NoteCopyScheduleV1,
        PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1, PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
        PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1, PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
        PROOF_MANAGED_NOTE_SECURITY_LANES_V1, PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
        PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1, ProofManagedNoteStarkAdapterV1,
        ProofManagedNoteStarkErrorV1, ProofManagedNoteStarkProtocolV1,
        prove_proof_managed_note_stark_v1_with_rng, verify_proof_managed_note_stark_v1,
    },
    transparent_stark::{
        GoldilocksFieldV1 as F, PrivacyOuterDigestV1, TransparentStarkDigestContextV1,
        TransparentTranscriptV1, privacy_outer_digest_frame_v1,
    },
};
use iroha_data_model::privacy::{
    IrohaIvmPrivateNoteStarkStatementV1, PrivacyConsensusLimitsV1,
    PrivacyNativeConsensusBindingDigestV1, PrivacyNativeConsensusBindingV1, PrivacyProtocolIdV1,
};
use rand::TryRngCore;
const TYPE_SHA_ROUND: usize = 0;
const TYPE_SHA_END: usize = 1;
const TYPE_NODE_SELECT: usize = 2;
const TYPE_DISTINCT: usize = 3;
const TYPE_NONZERO: usize = 4;
const TYPE_SUM_IO: usize = 5;
const TYPE_SUM_CONSERVATION: usize = 6;
const TYPE_VM_HEADER: usize = 7;
const TYPE_VM_PROGRAM: usize = 8;
const TYPE_VM_PREVIOUS: usize = 9;
const TYPE_VM_NEXT: usize = 10;
const TYPE_PADDING: usize = 11;
const TYPE_MEMBERSHIP: usize = 12;
const TYPE_COLUMN_COUNT: usize = 13;
const FIXED_ROUND_SELECTOR_OFFSET: usize = TYPE_COLUMN_COUNT;
const FIXED_FIRST_BLOCK_ROUND_ZERO: usize = FIXED_ROUND_SELECTOR_OFFSET + 64;
const FIXED_SHA_END_TERMINAL: usize = FIXED_FIRST_BLOCK_ROUND_ZERO + 1;
const FIXED_SHA_END_CONTINUE: usize = FIXED_SHA_END_TERMINAL + 1;
const FIXED_SHA_END_NEXT_BLOCK: usize = FIXED_SHA_END_CONTINUE + 1;
const FIXED_TERMINAL_CHUNK_OFFSET: usize = FIXED_SHA_END_NEXT_BLOCK + 1;
const FIXED_SHA_END_PUBLIC_SELECTOR: usize = FIXED_TERMINAL_CHUNK_OFFSET + 4;
const FIXED_SHA_END_PUBLIC_BYTE_OFFSET: usize = FIXED_SHA_END_PUBLIC_SELECTOR + 1;
const FIXED_SEQUENCE_FIRST: usize = FIXED_SHA_END_PUBLIC_BYTE_OFFSET + PRIVATE_NOTE_COPY_WIDTH_V1;
const FIXED_SEQUENCE_LAST: usize = FIXED_SEQUENCE_FIRST + 1;
const FIXED_SEQUENCE_TRANSITION: usize = FIXED_SEQUENCE_LAST + 1;
const FIXED_SUM_FIRST: usize = FIXED_SEQUENCE_TRANSITION + 1;
const FIXED_SUM_LAST: usize = FIXED_SUM_FIRST + 1;
const FIXED_SUM_TRANSITION: usize = FIXED_SUM_LAST + 1;
const FIXED_VM_BYTE_SELECTOR_OFFSET: usize = FIXED_SUM_TRANSITION + 1;
const FIXED_VM_PROGRAM_FIRST: usize = FIXED_VM_BYTE_SELECTOR_OFFSET + 16;
const FIXED_VM_PROGRAM_LAST: usize = FIXED_VM_PROGRAM_FIRST + 1;
const FIXED_VM_COMMON_TRANSITION: usize = FIXED_VM_PROGRAM_LAST + 1;
const FIXED_VM_INSTRUCTION_TRANSITION: usize = FIXED_VM_COMMON_TRANSITION + 1;
const FIXED_VM_ACTION_LIMB_ZERO_BYTE: usize = FIXED_VM_INSTRUCTION_TRANSITION + 1;
const FIXED_VM_ACTION_LIMB_ONE_BYTE: usize = FIXED_VM_ACTION_LIMB_ZERO_BYTE + 1;
const FIXED_VM_EXECUTION_EPOCH_BYTE: usize = FIXED_VM_ACTION_LIMB_ONE_BYTE + 1;
pub const PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1: usize = FIXED_VM_EXECUTION_EPOCH_BYTE + 1;
pub const PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1: usize = 1;
pub const PRIVATE_NOTE_PROFILE_CONSTRAINT_COUNT_V1: usize = 1_375;
/// Audited maximum algebraic degree across the complete shared/profile AIR.
pub const PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1: u8 =
    PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1;
const PROFILE_AUX_VM_CARRY_BRIDGE: usize = 0;
/// Relation-local descriptor combined with the shared proof-driver geometry.
pub const IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1: &[u8] = b"iroha-ivm-private-note-stark-v1:relation=proof-managed-note:wire=IPS1-v1:trace=2^14:base=556:profile-aux=1:profile-fixed=123:profile-constraints=1375:constraint-degree=4:max-proof=8388608:sha256-wide-air:public-digest=sha3-384-opaque48(canonical-statement,PrivacyNativeConsensusBindingDigestV1):tree-depth=32:vm=16x8:ciphertext=IPNE-v1:fee=separate:legacy=unrepresentable:governance=typed-lifecycle";
/// Exact first-release proof ceiling enforced by the private-note verifier.
pub const IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1: usize = 8 * 1024 * 1024;
const PRIVATE_NOTE_PARAMETERS_V1: aggregate::AggregateStarkParametersV1 =
    aggregate::AggregateStarkParametersV1 {
        proof_magic: *b"IPS1",
        proof_version: 1,
        fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Scalar,
        security_lanes: PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
        query_count: PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
        blowup_log2: PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
        terminal_log2: PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
        terminal_degree_bound: PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
        composition_degree_chunks: PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
        minimum_trace_log2: PRIVATE_NOTE_TRACE_LOG2_V1,
        maximum_trace_log2: PRIVATE_NOTE_TRACE_LOG2_V1,
        maximum_trace_groups: 1,
        maximum_segment_instances: 1,
        maximum_base_columns_per_instance: PRIVATE_NOTE_BASE_WIDTH_V1,
        maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1
            + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
        maximum_proof_bytes: IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1,
    };
pub const PRIVATE_NOTE_DOMAINS_V1: aggregate::AggregateStarkDomainsV1 =
    aggregate::AggregateStarkDomainsV1 {
        digest_context: TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            b"ivm-private-note-stark-profile-v1",
        ),
        base_leaf: b"ivm-private-note-stark-base-leaf-v1",
        base_node: b"ivm-private-note-stark-base-node-v1",
        aux_leaf: b"ivm-private-note-stark-aux-leaf-v1",
        aux_node: b"ivm-private-note-stark-aux-node-v1",
        composition_leaf: b"ivm-private-note-stark-composition-leaf-v1",
        composition_node: b"ivm-private-note-stark-composition-node-v1",
        fri_leaf: b"ivm-private-note-stark-fri-leaf-v1",
        fri_node: b"ivm-private-note-stark-fri-node-v1",
        layout_label: b"ivm-private-note-stark-layout-v1",
        base_root_label: b"ivm-private-note-stark-base-root-v1",
        aux_root_label: b"ivm-private-note-stark-aux-root-v1",
        composition_root_label: b"ivm-private-note-stark-composition-root-v1",
        fri_root_label: b"ivm-private-note-stark-fri-root-v1",
        fri_beta_label: b"ivm-private-note-stark-fri-beta-v1",
        query_seed: b"ivm-private-note-stark-query-seed-v1",
    };
fn private_note_protocol_v1() -> ProofManagedNoteStarkProtocolV1 {
    ProofManagedNoteStarkProtocolV1 {
        parameters: PRIVATE_NOTE_PARAMETERS_V1,
        domains: PRIVATE_NOTE_DOMAINS_V1,
        maximum_constraint_degree: PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1,
        profile_binding_label: b"ivm-private-note-stark-profile-v1",
        profile_descriptor: IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1,
        relation_layout_domain: b"ivm-private-note-stark-relation-layout-v1",
    }
}
/// Validate the complete compiled proof-system and relation profile.
pub fn validate_ivm_private_note_stark_profile_v1() -> Result<(), ProofManagedNoteStarkErrorV1> {
    private_note_protocol_v1().validate()
}
fn map_air_error_v1(error: IvmPrivateNoteAirErrorV1) -> ProofManagedNoteStarkErrorV1 {
    match error {
        IvmPrivateNoteAirErrorV1::Resource => ProofManagedNoteStarkErrorV1::Resource,
        IvmPrivateNoteAirErrorV1::Copy => ProofManagedNoteStarkErrorV1::Copy,
        IvmPrivateNoteAirErrorV1::Relation
        | IvmPrivateNoteAirErrorV1::Topology
        | IvmPrivateNoteAirErrorV1::Assignment
        | IvmPrivateNoteAirErrorV1::Sha256 => ProofManagedNoteStarkErrorV1::Constraint,
    }
}
fn vm_same_instruction_transition(
    current: &PrivateNoteFixedRowV1,
    next: &PrivateNoteFixedRowV1,
) -> bool {
    match (current, next) {
        (
            PrivateNoteFixedRowV1::VmProgram { instruction },
            PrivateNoteFixedRowV1::VmPrevious {
                instruction: next_instruction,
                byte: 0,
            },
        ) => instruction == next_instruction,
        (
            PrivateNoteFixedRowV1::VmPrevious { instruction, byte },
            PrivateNoteFixedRowV1::VmNext {
                instruction: next_instruction,
                byte: next_byte,
            },
        ) => instruction == next_instruction && byte == next_byte,
        (
            PrivateNoteFixedRowV1::VmNext { instruction, byte },
            PrivateNoteFixedRowV1::VmPrevious {
                instruction: next_instruction,
                byte: next_byte,
            },
        ) => instruction == next_instruction && usize::from(*byte) + 1 == usize::from(*next_byte),
        _ => false,
    }
}
#[cfg(test)]
pub(super) fn private_note_profile_fixed_columns_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    private_note_profile_fixed_columns_with_relation_profile_v1(
        statement,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
fn private_note_profile_fixed_columns_with_relation_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    let fixed = build_private_note_fixed_trace_with_profile_v1(statement, profile)
        .map_err(map_air_error_v1)?;
    if fixed.rows.len() != PRIVATE_NOTE_TRACE_SIZE_V1 {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let mut columns =
        vec![vec![F::ZERO; PRIVATE_NOTE_TRACE_SIZE_V1]; PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1];
    let action = statement.action_digest.as_bytes();
    let epoch = u128::from(statement.execution_epoch).to_be_bytes();
    for (row, current) in fixed.rows.iter().enumerate() {
        let next = fixed
            .rows
            .get((row + 1).min(PRIVATE_NOTE_TRACE_SIZE_V1 - 1))
            .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        match current {
            PrivateNoteFixedRowV1::ShaRound { round, block, .. } => {
                set(&mut columns, TYPE_SHA_ROUND, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_ROUND_SELECTOR_OFFSET + usize::from(*round),
                    row,
                    F::ONE,
                );
                if *round == 0 && *block == 0 {
                    set(&mut columns, FIXED_FIRST_BLOCK_ROUND_ZERO, row, F::ONE);
                }
            }
            PrivateNoteFixedRowV1::ShaEnd {
                block,
                block_count,
                digest_chunk,
                public_digest,
                ..
            } => {
                set(&mut columns, TYPE_SHA_END, row, F::ONE);
                let terminal = usize::from(*block) + 1 == usize::from(*block_count);
                if terminal {
                    set(&mut columns, FIXED_SHA_END_TERMINAL, row, F::ONE);
                    set(
                        &mut columns,
                        FIXED_TERMINAL_CHUNK_OFFSET + usize::from(*digest_chunk),
                        row,
                        F::ONE,
                    );
                }
                if *digest_chunk < 3 {
                    set(&mut columns, FIXED_SHA_END_CONTINUE, row, F::ONE);
                } else if !terminal {
                    set(&mut columns, FIXED_SHA_END_NEXT_BLOCK, row, F::ONE);
                }
                if let Some(public_digest) = public_digest {
                    if !terminal {
                        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
                    }
                    set(&mut columns, FIXED_SHA_END_PUBLIC_SELECTOR, row, F::ONE);
                    let start = usize::from(*digest_chunk)
                        .checked_mul(PRIVATE_NOTE_COPY_WIDTH_V1)
                        .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
                    let public_chunk = public_digest
                        .get(start..start + PRIVATE_NOTE_COPY_WIDTH_V1)
                        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
                    for (cell, byte) in public_chunk.iter().copied().enumerate() {
                        set(
                            &mut columns,
                            FIXED_SHA_END_PUBLIC_BYTE_OFFSET + cell,
                            row,
                            f(byte),
                        );
                    }
                }
            }
            PrivateNoteFixedRowV1::NodeSelect { .. } => {
                set(&mut columns, TYPE_NODE_SELECT, row, F::ONE);
            }
            PrivateNoteFixedRowV1::Membership { .. } => {
                set(&mut columns, TYPE_MEMBERSHIP, row, F::ONE);
            }
            PrivateNoteFixedRowV1::Distinct { chunk, chunks, .. } => {
                set(&mut columns, TYPE_DISTINCT, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_SEQUENCE_FIRST,
                    row,
                    f(u64::from(*chunk == 0)),
                );
                let last = usize::from(*chunk) + 1 == usize::from(*chunks);
                set(&mut columns, FIXED_SEQUENCE_LAST, row, f(u64::from(last)));
                set(
                    &mut columns,
                    FIXED_SEQUENCE_TRANSITION,
                    row,
                    f(u64::from(!last)),
                );
            }
            PrivateNoteFixedRowV1::NonZero { chunk, chunks, .. } => {
                set(&mut columns, TYPE_NONZERO, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_SEQUENCE_FIRST,
                    row,
                    f(u64::from(*chunk == 0)),
                );
                let last = usize::from(*chunk) + 1 == usize::from(*chunks);
                set(&mut columns, FIXED_SEQUENCE_LAST, row, f(u64::from(last)));
                set(
                    &mut columns,
                    FIXED_SEQUENCE_TRANSITION,
                    row,
                    f(u64::from(!last)),
                );
            }
            PrivateNoteFixedRowV1::Sum { side, byte } => {
                let kind = match side {
                    SumSideV1::Inputs | SumSideV1::Outputs => TYPE_SUM_IO,
                    SumSideV1::Conservation => TYPE_SUM_CONSERVATION,
                };
                set(&mut columns, kind, row, F::ONE);
                set(&mut columns, FIXED_SUM_FIRST, row, f(u64::from(*byte == 0)));
                set(&mut columns, FIXED_SUM_LAST, row, f(u64::from(*byte == 15)));
                set(
                    &mut columns,
                    FIXED_SUM_TRANSITION,
                    row,
                    f(u64::from(*byte < 15)),
                );
            }
            PrivateNoteFixedRowV1::VmHeader => {
                set(&mut columns, TYPE_VM_HEADER, row, F::ONE);
            }
            PrivateNoteFixedRowV1::VmProgram { instruction } => {
                set(&mut columns, TYPE_VM_PROGRAM, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_VM_PROGRAM_FIRST,
                    row,
                    f(u64::from(*instruction == 0)),
                );
                set(
                    &mut columns,
                    FIXED_VM_PROGRAM_LAST,
                    row,
                    f(u64::from(usize::from(*instruction) + 1 == 16)),
                );
            }
            PrivateNoteFixedRowV1::VmPrevious { byte, .. } => {
                set(&mut columns, TYPE_VM_PREVIOUS, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_VM_BYTE_SELECTOR_OFFSET + usize::from(*byte),
                    row,
                    F::ONE,
                );
                let byte_index = 15 - usize::from(*byte);
                set(
                    &mut columns,
                    FIXED_VM_ACTION_LIMB_ZERO_BYTE,
                    row,
                    f(action[byte_index]),
                );
                set(
                    &mut columns,
                    FIXED_VM_ACTION_LIMB_ONE_BYTE,
                    row,
                    f(action[16 + byte_index]),
                );
                set(
                    &mut columns,
                    FIXED_VM_EXECUTION_EPOCH_BYTE,
                    row,
                    f(epoch[byte_index]),
                );
            }
            PrivateNoteFixedRowV1::VmNext { byte, .. } => {
                set(&mut columns, TYPE_VM_NEXT, row, F::ONE);
                set(
                    &mut columns,
                    FIXED_VM_BYTE_SELECTOR_OFFSET + usize::from(*byte),
                    row,
                    F::ONE,
                );
                if *byte == 15 && matches!(next, PrivateNoteFixedRowV1::VmProgram { .. }) {
                    set(&mut columns, FIXED_VM_INSTRUCTION_TRANSITION, row, F::ONE);
                }
            }
            PrivateNoteFixedRowV1::Padding => {
                set(&mut columns, TYPE_PADDING, row, F::ONE);
            }
        }
        if vm_same_instruction_transition(current, next) {
            set(&mut columns, FIXED_VM_COMMON_TRANSITION, row, F::ONE);
        }
    }
    Ok(columns)
}
#[cfg(test)]
pub(super) fn private_note_profile_aux_columns_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    base_columns: &[Vec<F>],
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    private_note_profile_aux_columns_with_relation_profile_v1(
        statement,
        base_columns,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
fn private_note_profile_aux_columns_with_relation_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    base_columns: &[Vec<F>],
    profile: PrivateNoteRelationProfileV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if base_columns.len() != PRIVATE_NOTE_BASE_WIDTH_V1
        || base_columns
            .iter()
            .any(|column| column.len() != PRIVATE_NOTE_TRACE_SIZE_V1)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let fixed = build_private_note_fixed_trace_with_profile_v1(statement, profile)
        .map_err(map_air_error_v1)?;
    let mut bridge = vec![F::ZERO; PRIVATE_NOTE_TRACE_SIZE_V1];
    for row in 1..PRIVATE_NOTE_TRACE_SIZE_V1 {
        if matches!(fixed.rows[row], PrivateNoteFixedRowV1::VmNext { .. }) {
            if !matches!(
                fixed.rows[row - 1],
                PrivateNoteFixedRowV1::VmPrevious { .. }
            ) {
                return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
            }
            bridge[row] = base_columns[SCRATCH_VM_CARRY_AFTER][row - 1];
        }
    }
    Ok(vec![bridge])
}
pub(super) fn private_note_base_columns_v1(
    trace: &PrivateNoteBaseTraceV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if trace.rows.len() != PRIVATE_NOTE_TRACE_SIZE_V1
        || trace
            .rows
            .iter()
            .any(|row| row.len() != PRIVATE_NOTE_BASE_WIDTH_V1)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    Ok((0..PRIVATE_NOTE_BASE_WIDTH_V1)
        .map(|column| trace.rows.iter().map(|row| row[column]).collect())
        .collect())
}
include!("../shared_note_sha256_helpers.rs");
fn bits_group(row: &[F], group: usize) -> &[F] {
    let start = SHA_BITS_OFFSET + group * PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1;
    &row[start..start + PRIVATE_NOTE_SHA_BITS_PER_GROUP_V1]
}
fn allowed_selector_for_column(current_fixed: &[F], column: usize) -> F {
    let sha_round = current_fixed[TYPE_SHA_ROUND];
    let sha_end = current_fixed[TYPE_SHA_END];
    let distinct = current_fixed[TYPE_DISTINCT];
    let nonzero = current_fixed[TYPE_NONZERO];
    let sum_io = current_fixed[TYPE_SUM_IO];
    let sum_conservation = current_fixed[TYPE_SUM_CONSERVATION];
    let vm_program = current_fixed[TYPE_VM_PROGRAM];
    let vm_previous = current_fixed[TYPE_VM_PREVIOUS];
    let vm_next = current_fixed[TYPE_VM_NEXT];
    let vm_common = vm_program.add(vm_previous).add(vm_next);
    if (SHA_SCHEDULE_OFFSET..SHA_SCHEDULE_OFFSET + PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1)
        .contains(&column)
        || (SHA_INITIAL_STATE_OFFSET..SHA_INITIAL_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1)
            .contains(&column)
        || (SHA_T1_OFFSET..SHA_CARRY_OFFSET + SHA_CARRY_WIDTH).contains(&column)
    {
        sha_round
    } else if (SHA_STATE_OFFSET..SHA_STATE_OFFSET + PRIVATE_NOTE_SHA_STATE_WORDS_V1)
        .contains(&column)
        || (SHA_BITS_OFFSET..SHA_BITS_OFFSET + PRIVATE_NOTE_SHA_BIT_COLUMNS_V1).contains(&column)
    {
        sha_round.add(sha_end)
    } else if (SCRATCH_NONZERO_BYTE_SELECT_OFFSET..SCRATCH_NONZERO_BYTE_SELECT_OFFSET + 4)
        .contains(&column)
    {
        distinct.add(nonzero)
    } else if (SCRATCH_NONZERO_BYTE_SELECT_OFFSET + 4..SCRATCH_NONZERO_BYTE_SELECT_OFFSET + 8)
        .contains(&column)
    {
        nonzero
    } else if (SCRATCH_NONZERO_BIT_SELECT_OFFSET..SCRATCH_NONZERO_BIT_SELECT_OFFSET + 8)
        .contains(&column)
    {
        distinct.add(nonzero)
    } else if (SCRATCH_BYTE_BITS_OFFSET..SCRATCH_BYTE_BITS_OFFSET + 8).contains(&column) {
        distinct.add(nonzero).add(sum_io)
    } else if (SCRATCH_RUNNING_BEFORE..SCRATCH_RUNNING_AFTER + 1).contains(&column) {
        distinct.add(nonzero)
    } else if (SCRATCH_RELATION_CARRY_BEFORE..SCRATCH_RELATION_CARRY_AFTER + 1).contains(&column) {
        sum_io.add(sum_conservation)
    } else if (SCRATCH_RELATION_CARRY_BITS_OFFSET..SCRATCH_RELATION_CARRY_BITS_OFFSET + 2)
        .contains(&column)
    {
        sum_io
    } else if (SCRATCH_VM_OPCODE_SELECT_OFFSET..SCRATCH_VM_HALTED_AFTER + 1).contains(&column) {
        vm_common
    } else if (SCRATCH_VM_CARRY_BEFORE..SCRATCH_VM_DIFFERENCE_BITS_OFFSET).contains(&column) {
        vm_previous
    } else if (SCRATCH_VM_DIFFERENCE_BITS_OFFSET..SCRATCH_VM_DIFFERENCE_BITS_OFFSET + 8)
        .contains(&column)
    {
        vm_previous.add(distinct)
    } else {
        F::ZERO
    }
}
const BASE_WIDTH: usize = PRIVATE_NOTE_BASE_WIDTH_V1;
const PROFILE_AUX_WIDTH: usize = PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1;
const PROFILE_FIXED_WIDTH: usize = PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1;
const SHA_BIT_COLUMNS: usize = PRIVATE_NOTE_SHA_BIT_COLUMNS_V1;
const SHA_STATE_WORDS: usize = PRIVATE_NOTE_SHA_STATE_WORDS_V1;
const SHA_SCHEDULE_WORDS: usize = PRIVATE_NOTE_SHA_SCHEDULE_WORDS_V1;
const COPY_WIDTH: usize = PRIVATE_NOTE_COPY_WIDTH_V1;
const DISTINCT_RIGHT_BITS_OFFSET: usize = SCRATCH_VM_DIFFERENCE_BITS_OFFSET;
const VM_DIFFERENCE_BITS_OFFSET: usize = SCRATCH_VM_DIFFERENCE_BITS_OFFSET;
include!("../shared_note_profile_constraints.rs");
define_note_profile_constraint_residues_v1!(private_note_shared_constraint_residues_v1);

fn private_note_profile_constraint_residues_inner_v1(
    current: &[F],
    next: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    let mut residues =
        private_note_shared_constraint_residues_v1(current, next, current_aux, next_aux, fixed)?;
    let selector = fixed[NOTE_COPY_FIXED_WIDTH_V1 + TYPE_MEMBERSHIP];
    for pair in 0..3 {
        residues.push(
            selector
                .mul(current[COPY_OFFSET])
                .mul(current[COPY_OFFSET + 1 + pair * 2].sub(current[COPY_OFFSET + 2 + pair * 2])),
        );
    }
    Ok(residues)
}
/// Reusable crate-private bridge from one relation profile to the shared STARK driver.
///
/// A sibling adapter owns its protocol descriptor, profile digest, transcript
/// labels, and public-input digest. This bridge exposes only the invariant IVM
/// private-note geometry, fixed preprocessing, constraint evaluator, and
/// prover-column compiler.
#[derive(Clone, Copy)]
pub struct PrivateNoteStarkRelationV1<'a> {
    statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
    profile: PrivateNoteRelationProfileV1,
}
impl<'a> PrivateNoteStarkRelationV1<'a> {
    /// Bind a public statement to one closed relation profile.
    pub(crate) const fn new(
        statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        profile: PrivateNoteRelationProfileV1,
    ) -> Self {
        Self { statement, profile }
    }

    /// Native trace logarithm shared by both profiles.
    pub(crate) const fn trace_log2_v1(self) -> u8 {
        PRIVATE_NOTE_TRACE_LOG2_V1
    }

    /// Exact base-trace width shared by both profiles.
    pub(crate) const fn base_width_v1(self) -> usize {
        PRIVATE_NOTE_BASE_WIDTH_V1
    }

    /// Exact profile-only auxiliary width.
    pub(crate) const fn profile_aux_width_v1(self) -> usize {
        PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1
    }

    /// Exact profile-only fixed width.
    pub(crate) const fn profile_fixed_width_v1(self) -> usize {
        PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1
    }

    /// Exact profile-only constraint count.
    pub(crate) const fn profile_constraint_count_v1(self) -> usize {
        PRIVATE_NOTE_PROFILE_CONSTRAINT_COUNT_V1
    }

    /// Compile the verifier-fixed copy schedule.
    pub(crate) fn copy_schedule_v1(
        self,
    ) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        build_private_note_copy_schedule_with_profile_v1(self.statement, self.profile)
            .map_err(map_air_error_v1)
    }

    /// Compile relation-specific fixed columns.
    pub(crate) fn profile_fixed_columns_v1(
        self,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        private_note_profile_fixed_columns_with_relation_profile_v1(self.statement, self.profile)
    }

    /// Build the relation-specific auxiliary columns.
    pub(crate) fn profile_aux_columns_v1(
        self,
        base_columns: &[Vec<F>],
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        private_note_profile_aux_columns_with_relation_profile_v1(
            self.statement,
            base_columns,
            self.profile,
        )
    }

    /// Evaluate the extension-domain relation residues.
    pub(crate) fn constraint_residues_v1(
        self,
        current_base: &[F],
        next_base: &[F],
        current_aux: &[F],
        next_aux: &[F],
        fixed: &[F],
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
        private_note_profile_constraint_residues_inner_v1(
            current_base,
            next_base,
            current_aux,
            next_aux,
            fixed,
        )
    }

    /// Compile and natively validate prover base columns.
    pub(crate) fn compile_prover_columns_v1(
        self,
        witness: &IvmPrivateNoteWitnessV1,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        let trace =
            build_private_note_base_trace_with_profile_v1(self.statement, witness, self.profile)
                .map_err(map_air_error_v1)?;
        validate_private_note_base_trace_with_profile_v1(self.statement, &trace, self.profile)
            .map_err(map_air_error_v1)?;
        private_note_base_columns_v1(&trace)
    }
}
/// Statement-and-consensus-binding adapter used by both prover and verifier.
pub(super) struct PrivateNoteStarkAdapterV1<'a> {
    statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
    consensus_binding: &'a PrivacyNativeConsensusBindingV1,
    consensus_limits: &'a PrivacyConsensusLimitsV1,
    relation_profile: PrivateNoteRelationProfileV1,
}
impl<'a> PrivateNoteStarkAdapterV1<'a> {
    pub(super) const fn new(
        statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        consensus_binding: &'a PrivacyNativeConsensusBindingV1,
        consensus_limits: &'a PrivacyConsensusLimitsV1,
    ) -> Self {
        Self {
            statement,
            consensus_binding,
            consensus_limits,
            relation_profile: PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
        }
    }
    #[cfg(test)]
    const fn new_with_relation_profile_v1(
        statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        consensus_binding: &'a PrivacyNativeConsensusBindingV1,
        consensus_limits: &'a PrivacyConsensusLimitsV1,
        relation_profile: PrivateNoteRelationProfileV1,
    ) -> Self {
        Self {
            statement,
            consensus_binding,
            consensus_limits,
            relation_profile,
        }
    }

    const fn relation_v1(&self) -> PrivateNoteStarkRelationV1<'a> {
        PrivateNoteStarkRelationV1::new(self.statement, self.relation_profile)
    }
}
fn private_note_public_input_digest_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    consensus_binding_digest: PrivacyNativeConsensusBindingDigestV1,
) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
    let encoded =
        norito::to_bytes(statement).map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    privacy_outer_digest_frame_v1(
        PRIVATE_NOTE_DOMAINS_V1.digest_context,
        b"ivm-private-note-stark-public-input-with-consensus-binding-v1",
        b"statement-binding",
        0,
        0,
        0,
        &[&encoded, consensus_binding_digest.as_bytes()],
    )
    .map_err(|_| ProofManagedNoteStarkErrorV1::Internal)
}
impl ProofManagedNoteStarkAdapterV1 for PrivateNoteStarkAdapterV1<'_> {
    type ProfileChallenges = ();
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        private_note_protocol_v1()
    }
    fn public_input_digest_v1(&self) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
        self.consensus_binding
            .validate_against_context(&self.statement.context, self.consensus_limits)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        let binding_digest: PrivacyNativeConsensusBindingDigestV1 = self
            .consensus_binding
            .digest()
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        private_note_public_input_digest_v1(self.statement, binding_digest)
    }
    fn trace_log2_v1(&self) -> u8 {
        self.relation_v1().trace_log2_v1()
    }
    fn base_width_v1(&self) -> usize {
        self.relation_v1().base_width_v1()
    }
    fn profile_aux_width_v1(&self) -> usize {
        self.relation_v1().profile_aux_width_v1()
    }
    fn profile_fixed_width_v1(&self) -> usize {
        self.relation_v1().profile_fixed_width_v1()
    }
    fn profile_constraint_count_v1(&self) -> usize {
        self.relation_v1().profile_constraint_count_v1()
    }
    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().copy_schedule_v1()
    }
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().profile_fixed_columns_v1()
    }
    fn derive_profile_challenges_v1(
        &self,
        _transcript: &mut TransparentTranscriptV1,
        _copy_challenges: NoteCopyChallengesV1,
    ) -> Result<Self::ProfileChallenges, ProofManagedNoteStarkErrorV1> {
        Ok(())
    }
    fn build_profile_aux_columns_v1(
        &self,
        base_columns: &[Vec<F>],
        _copy_aux_columns: &[Vec<F>],
        _fixed_columns: &[Vec<F>],
        _copy_challenges: NoteCopyChallengesV1,
        _profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().profile_aux_columns_v1(base_columns)
    }
    fn profile_constraint_residues_v1(
        &self,
        current_base: &[F],
        next_base: &[F],
        current_aux: &[F],
        next_aux: &[F],
        fixed: &[F],
        _copy_challenges: NoteCopyChallengesV1,
        _profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().constraint_residues_v1(
            current_base,
            next_base,
            current_aux,
            next_aux,
            fixed,
        )
    }
}
/// Compile and natively validate one canonical prover base trace.
pub(super) fn compile_private_note_prover_columns_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    PrivateNoteStarkRelationV1::new(statement, PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE)
        .compile_prover_columns_v1(witness)
}
/// Construct the canonical private-note proof with injected masking entropy.
///
/// The witness is compiled and checked by the native interpreter before the shared proof driver
/// sees any columns. The proof driver then checks the same relation algebraically on the native and
/// extension domains. This relation adapter independently verifies its opaque candidate before returning bytes.
pub(super) fn prove_private_note_stark_v1_with_rng<R: TryRngCore>(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    witness: &IvmPrivateNoteWitnessV1,
    rng: &mut R,
) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
    let base_columns = compile_private_note_prover_columns_v1(statement, witness)?;
    prove_proof_managed_note_stark_v1_with_rng(
        &PrivateNoteStarkAdapterV1::new(statement, consensus_binding, consensus_limits),
        &base_columns,
        rng,
    )?
    .verify_into_bytes_v1(&PrivateNoteStarkAdapterV1::new(
        statement,
        consensus_binding,
        consensus_limits,
    ))
}
/// Verify the exact private-note proof against the statement and consensus binding.
pub fn verify_private_note_stark_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    proof_bytes: &[u8],
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    verify_proof_managed_note_stark_v1(
        &PrivateNoteStarkAdapterV1::new(statement, consensus_binding, consensus_limits),
        proof_bytes,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::ivm_private_note::test_fixtures::{fixture, three_output_fixture};
    use crate::privacy_engines::proof_managed_note_stark::fixed_query_audit;
    use iroha_data_model::privacy::{
        PrivacyActionDigestV1, PrivacyEngineManifestDigestV1,
        PrivacyNativeConsensusBindingValidationErrorV1, PrivacyParameterDigestV1,
        PrivacyParameterIdV1, PrivacyStatementContextV1, PrivacyStatementSchemaDigestV1,
        PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
    };
    use rand::{SeedableRng as _, rngs::StdRng};
    fn consensus_material(
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
    ) -> (PrivacyNativeConsensusBindingV1, PrivacyConsensusLimitsV1) {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let binding = PrivacyNativeConsensusBindingV1::new(&statement.context, [0xC1; 32], &limits)
            .expect("valid IVM private-note consensus binding");
        (binding, limits)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ConsensusBindingAxisV1 {
        NetworkId,
        GenesisHash,
        ActionIndex,
        TransactionIntentDigest,
        ParameterId,
        ParameterDigest,
        VerifierDigest,
        StatementSchemaDigest,
        EngineManifestDigest,
    }
    const CONSENSUS_BINDING_AXES_V1: [ConsensusBindingAxisV1; 9] = [
        ConsensusBindingAxisV1::NetworkId,
        ConsensusBindingAxisV1::GenesisHash,
        ConsensusBindingAxisV1::ActionIndex,
        ConsensusBindingAxisV1::TransactionIntentDigest,
        ConsensusBindingAxisV1::ParameterId,
        ConsensusBindingAxisV1::ParameterDigest,
        ConsensusBindingAxisV1::VerifierDigest,
        ConsensusBindingAxisV1::StatementSchemaDigest,
        ConsensusBindingAxisV1::EngineManifestDigest,
    ];
    impl ConsensusBindingAxisV1 {
        fn mutate_binding(self, binding: &mut PrivacyNativeConsensusBindingV1) {
            match self {
                Self::NetworkId => {
                    binding.network_id =
                        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                            iroha_data_model::block::BlockHeader,
                        >::from_untyped_unchecked(
                            iroha_crypto::Hash::prehashed([0xD0; 32]),
                        ));
                    binding.genesis_hash = *binding.network_id.as_bytes();
                }
                Self::GenesisHash => binding.genesis_hash = [0xD0; 32],
                Self::ActionIndex => binding.action_index ^= 1,
                Self::TransactionIntentDigest => {
                    binding.transaction_intent_digest =
                        PrivacyTransactionIntentDigestV1::new([0xD1; 32]);
                }
                Self::ParameterId => {
                    binding.parameter_id = PrivacyParameterIdV1::new([0xD2; 32]);
                }
                Self::ParameterDigest => {
                    binding.parameter_digest = PrivacyParameterDigestV1::new([0xD3; 32]);
                }
                Self::VerifierDigest => {
                    binding.verifier_digest = PrivacyVerifierDigestV1::new([0xD4; 32]);
                }
                Self::StatementSchemaDigest => {
                    binding.statement_schema_digest =
                        PrivacyStatementSchemaDigestV1::new([0xD5; 32]);
                }
                Self::EngineManifestDigest => {
                    binding.engine_manifest_digest = PrivacyEngineManifestDigestV1::new([0xD6; 32]);
                }
            }
        }
        fn mutate_context(self, context: &mut PrivacyStatementContextV1) {
            match self {
                Self::NetworkId => {
                    context.network_id =
                        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                            iroha_data_model::block::BlockHeader,
                        >::from_untyped_unchecked(
                            iroha_crypto::Hash::prehashed([0xD0; 32]),
                        ));
                }
                Self::GenesisHash => {}
                Self::ActionIndex => context.action_index ^= 1,
                Self::TransactionIntentDigest => {
                    context.transaction_intent_digest =
                        PrivacyTransactionIntentDigestV1::new([0xD1; 32]);
                }
                Self::ParameterId => {
                    context.parameter_id = PrivacyParameterIdV1::new([0xD2; 32]);
                }
                Self::ParameterDigest => {
                    context.parameter_digest = PrivacyParameterDigestV1::new([0xD3; 32]);
                }
                Self::VerifierDigest => {
                    context.verifier_digest = PrivacyVerifierDigestV1::new([0xD4; 32]);
                }
                Self::StatementSchemaDigest => {
                    context.statement_schema_digest =
                        PrivacyStatementSchemaDigestV1::new([0xD5; 32]);
                }
                Self::EngineManifestDigest => {
                    context.engine_manifest_digest = PrivacyEngineManifestDigestV1::new([0xD6; 32]);
                }
            }
        }
        fn mismatch_error(self) -> Option<PrivacyNativeConsensusBindingValidationErrorV1> {
            match self {
                Self::NetworkId => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::NetworkIdMismatch)
                }
                Self::GenesisHash => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch)
                }
                Self::ActionIndex => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::ActionIndexMismatch)
                }
                Self::TransactionIntentDigest => Some(
                    PrivacyNativeConsensusBindingValidationErrorV1::TransactionIntentDigestMismatch,
                ),
                Self::ParameterId => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::ParameterIdMismatch)
                }
                Self::ParameterDigest => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::ParameterDigestMismatch)
                }
                Self::VerifierDigest => {
                    Some(PrivacyNativeConsensusBindingValidationErrorV1::VerifierDigestMismatch)
                }
                Self::StatementSchemaDigest => Some(
                    PrivacyNativeConsensusBindingValidationErrorV1::StatementSchemaDigestMismatch,
                ),
                Self::EngineManifestDigest => Some(
                    PrivacyNativeConsensusBindingValidationErrorV1::EngineManifestDigestMismatch,
                ),
            }
        }
    }
    fn redigest_statement_v1(statement: &mut IrohaIvmPrivateNoteStarkStatementV1) {
        statement.action_digest = PrivacyActionDigestV1::new([0; 32]);
        statement.action_digest = statement
            .computed_action_digest()
            .expect("canonical substituted action digest");
    }
    fn coordinated_substitution_v1(
        axis: ConsensusBindingAxisV1,
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
        binding: &PrivacyNativeConsensusBindingV1,
        limits: &PrivacyConsensusLimitsV1,
    ) -> Option<(
        IrohaIvmPrivateNoteStarkStatementV1,
        PrivacyNativeConsensusBindingV1,
    )> {
        if axis == ConsensusBindingAxisV1::GenesisHash {
            // NetworkId is the canonical genesis hash, so there is no valid
            // genesis-only substitution. The NetworkId axis changes both
            // values together and binds the resulting statement context.
            return None;
        }
        if axis == ConsensusBindingAxisV1::ActionIndex {
            // The closed Taira profile admits exactly one action, so there is
            // no second valid action index under the same consensus limits.
            return None;
        }
        let mut substituted_statement = statement.clone();
        axis.mutate_context(&mut substituted_statement.context);
        redigest_statement_v1(&mut substituted_statement);
        let genesis_hash = if axis == ConsensusBindingAxisV1::NetworkId {
            *substituted_statement.context.network_id.as_bytes()
        } else {
            binding.genesis_hash
        };
        let substituted_binding = PrivacyNativeConsensusBindingV1::new(
            &substituted_statement.context,
            genesis_hash,
            limits,
        )
        .expect("coordinated substituted consensus binding");
        Some((substituted_statement, substituted_binding))
    }
    fn assert_proof_equation_rejection_v1(
        axis: &str,
        result: Result<(), ProofManagedNoteStarkErrorV1>,
    ) {
        assert!(
            matches!(
                result,
                Err(ProofManagedNoteStarkErrorV1::Copy
                    | ProofManagedNoteStarkErrorV1::Constraint
                    | ProofManagedNoteStarkErrorV1::TraceOpening
                    | ProofManagedNoteStarkErrorV1::Composition
                    | ProofManagedNoteStarkErrorV1::Fri
                    | ProofManagedNoteStarkErrorV1::Transcript)
            ),
            "{axis} substitution did not reach a cryptographic proof-equation rejection: {result:?}"
        );
    }
    #[test]
    fn private_note_fixed_queries_match_full_lde_at_all_fixture_queries_and_boundaries() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let adapter = PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits);
        fixed_query_audit::assert_profile_matches_full_lde_v1(&adapter);
    }

    #[test]
    fn private_note_malformed_wire_is_rejected_before_fixed_column_construction() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let adapter = PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits);
        fixed_query_audit::assert_malformed_rejected_before_fixed_v1(&adapter);
    }

    #[test]
    fn public_input_digest_commits_the_typed_consensus_binding_on_every_axis() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let canonical_binding_digest: PrivacyNativeConsensusBindingDigestV1 =
            binding.digest().expect("canonical binding digest");
        let expected =
            private_note_public_input_digest_v1(&value.statement, canonical_binding_digest)
                .expect("canonical framed public input");
        assert_eq!(
            PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits)
                .public_input_digest_v1(),
            Ok(expected)
        );
        for axis in CONSENSUS_BINDING_AXES_V1 {
            let mut binding_only = binding.clone();
            axis.mutate_binding(&mut binding_only);
            if let Some(expected_error) = axis.mismatch_error() {
                assert_eq!(
                    binding_only.validate_against_context(&value.statement.context, &limits),
                    Err(expected_error),
                    "{axis:?} binding-only substitution reported the wrong mismatch"
                );
                assert_eq!(
                    PrivateNoteStarkAdapterV1::new(&value.statement, &binding_only, &limits,)
                        .public_input_digest_v1(),
                    Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
                    "{axis:?} binding-only substitution entered the proof transcript"
                );
            }
            let Some((substituted_statement, substituted_binding)) =
                coordinated_substitution_v1(axis, &value.statement, &binding, &limits)
            else {
                let mut invalid_statement = value.statement.clone();
                axis.mutate_context(&mut invalid_statement.context);
                redigest_statement_v1(&mut invalid_statement);
                let mut invalid_binding = binding.clone();
                axis.mutate_binding(&mut invalid_binding);
                assert!(
                    invalid_binding
                        .validate_against_context(&invalid_statement.context, &limits)
                        .is_err(),
                    "{axis:?} admitted an intrinsically invalid consensus binding"
                );
                continue;
            };
            super::super::relation::validate_statement_v1(&substituted_statement).unwrap_or_else(
                |error| panic!("{axis:?} statement substitution is invalid: {error}"),
            );
            substituted_binding
                .validate_against_context(&substituted_statement.context, &limits)
                .unwrap_or_else(|error| {
                    panic!("{axis:?} binding substitution is invalid: {error}")
                });
            let substituted_digest = PrivateNoteStarkAdapterV1::new(
                &substituted_statement,
                &substituted_binding,
                &limits,
            )
            .public_input_digest_v1()
            .unwrap_or_else(|error| panic!("{axis:?} public input could not be derived: {error}"));
            assert_ne!(
                substituted_digest, expected,
                "{axis:?} did not alter the cryptographic public input"
            );
        }
    }
    #[test]
    fn compiled_profile_count_and_digest_are_exact() {
        validate_ivm_private_note_stark_profile_v1()
            .expect("compiled IVM private-note soundness profile");
        let residues = private_note_profile_constraint_residues_inner_v1(
            &vec![F::ZERO; PRIVATE_NOTE_BASE_WIDTH_V1],
            &vec![F::ZERO; PRIVATE_NOTE_BASE_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_FIXED_WIDTH_V1 + PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1],
        )
        .expect("zero rows have the compiled profile shape");
        assert_eq!(residues.len(), PRIVATE_NOTE_PROFILE_CONSTRAINT_COUNT_V1);
        let profile_digest = proof_managed_note_stark_profile_digest_v1(
            &PRIVATE_NOTE_DOMAINS_V1,
            IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1,
        )
        .expect("canonical IVM private-note profile digest");
        assert_ne!(profile_digest, PrivacyOuterDigestV1::default());
        let expected_descriptor = format!(
            "iroha-ivm-private-note-stark-v1:relation=proof-managed-note:wire=IPS1-v1:trace=2^{PRIVATE_NOTE_TRACE_LOG2_V1}:base={PRIVATE_NOTE_BASE_WIDTH_V1}:profile-aux={PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1}:profile-fixed={PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1}:profile-constraints={PRIVATE_NOTE_PROFILE_CONSTRAINT_COUNT_V1}:constraint-degree={PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1}:max-proof={IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1}:sha256-wide-air:public-digest=sha3-384-opaque48(canonical-statement,PrivacyNativeConsensusBindingDigestV1):tree-depth=32:vm=16x8:ciphertext=IPNE-v1:fee=separate:legacy=unrepresentable:governance=typed-lifecycle",
        );
        assert_eq!(
            IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1,
            expected_descriptor.as_bytes()
        );
        assert!(
            IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1
                .starts_with(b"iroha-ivm-private-note-stark-v1:")
        );
        assert!(
            IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1.ends_with(b":governance=typed-lifecycle")
        );
        assert!(
            IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1
                .windows(b":wire=IPS1-v1:".len())
                .any(|window| window == b":wire=IPS1-v1:"),
            "the sole first-release proof wire must use the semantic IPS1 tag"
        );
        assert!(
            !IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1
                .windows(b"IPN2".len())
                .any(|window| window == b"IPN2"),
            "the superseded draft proof magic must not remain in the profile"
        );
    }
    #[test]
    fn declared_constraint_degree_matches_affine_finite_differences() {
        let measured = crate::privacy_engines::proof_managed_note_stark::degree_audit::
            measured_maximum_affine_degree_v1(
                [0xD4; 32],
                [
                    PRIVATE_NOTE_BASE_WIDTH_V1,
                    PRIVATE_NOTE_BASE_WIDTH_V1,
                    NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
                    NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
                    NOTE_COPY_FIXED_WIDTH_V1 + PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1,
                ],
                21,
                PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1,
                private_note_profile_constraint_residues_inner_v1,
            );
        assert_eq!(
            measured,
            usize::from(PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1),
            "the IVM private-note AIR's declared maximum degree must be exact"
        );
    }
    #[test]
    #[ignore = "release gate: generates and verifies the full-domain IVM private-note proof"]
    fn full_domain_stark_roundtrip_and_adversarial_wires_fail_closed() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let mut rng = StdRng::from_seed([0xA9; 32]);
        let proof = super::super::prove_ivm_private_note_v1_with_rng(
            &value.statement,
            &binding,
            &limits,
            &value.witness,
            &mut rng,
        )
        .expect("full-domain private-note facade proof");
        assert!(!proof.is_empty());
        assert!(proof.len() <= PRIVATE_NOTE_PARAMETERS_V1.maximum_proof_bytes);
        super::super::verify_ivm_private_note_v1(&value.statement, &binding, &limits, &proof)
            .expect("full-domain private-note facade verification");
        fixed_query_audit::assert_proof_queries_match_full_lde_v1(
            &PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits),
            &proof,
        );
        let mut rejected_draft_magic = proof.clone();
        rejected_draft_magic[..4].copy_from_slice(b"IPN2");
        assert!(
            verify_private_note_stark_v1(
                &value.statement,
                &binding,
                &limits,
                &rejected_draft_magic,
            )
            .is_err(),
            "the superseded IPN2 draft magic was accepted"
        );
        let proof_digest = privacy_outer_digest_frame_v1(
            PRIVATE_NOTE_DOMAINS_V1.digest_context,
            b"ivm-private-note-stark-proof-kat-v1",
            b"proof-wire",
            0,
            0,
            0,
            &[&proof],
        )
        .expect("canonical proof KAT digest");
        assert_ne!(proof_digest, PrivacyOuterDigestV1::default());
        assert!(
            verify_private_note_stark_v1(
                &value.statement,
                &binding,
                &limits,
                &vec![0; proof.len()],
            )
            .is_err(),
            "same-length all-zero proof wire was accepted"
        );
        assert!(
            verify_private_note_stark_v1(
                &value.statement,
                &binding,
                &limits,
                &vec![0; PRIVATE_NOTE_PARAMETERS_V1.maximum_proof_bytes + 1],
            )
            .is_err(),
            "oversized proof wire was accepted"
        );
        let mut wires = Vec::new();
        wires.push(Vec::new());
        wires.push(proof[..proof.len() - 1].to_vec());
        let mut trailing = proof.clone();
        trailing.push(0);
        wires.push(trailing);
        for offset in [0, 4, proof.len() / 2, proof.len() - 1] {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            wires.push(changed);
        }
        for wire in wires {
            assert!(
                verify_private_note_stark_v1(&value.statement, &binding, &limits, &wire).is_err(),
                "malformed private-note proof wire was accepted"
            );
        }
        let mut changed_statement = value.statement.clone();
        let mut nullifier = *changed_statement.nullifiers[0].as_bytes();
        nullifier[0] ^= 1;
        changed_statement.nullifiers[0] =
            iroha_data_model::privacy::PrivacyNullifierV1::new(nullifier);
        changed_statement.action_digest =
            iroha_data_model::privacy::PrivacyActionDigestV1::new([0; 32]);
        changed_statement.action_digest = changed_statement
            .computed_action_digest()
            .expect("recompute substituted action digest");
        super::super::relation::validate_statement_v1(&changed_statement)
            .expect("substituted public statement remains intrinsically valid");
        binding
            .validate_against_context(&changed_statement.context, &limits)
            .expect("non-context statement substitution preserves consensus binding");
        assert_proof_equation_rejection_v1(
            "public nullifier",
            verify_private_note_stark_v1(&changed_statement, &binding, &limits, &proof),
        );
        let mut other_genesis = binding.clone();
        other_genesis.genesis_hash[0] ^= 1;
        assert_eq!(
            other_genesis.validate_against_context(&value.statement.context, &limits),
            Err(PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch),
            "a nonzero genesis substitution must retain the canonical network identity"
        );
        assert_ne!(
            binding
                .digest()
                .expect("canonical consensus-binding digest"),
            other_genesis
                .digest()
                .expect("changed-genesis consensus-binding digest"),
            "changed nonzero genesis did not change the typed consensus-binding digest"
        );
        assert!(matches!(
            verify_private_note_stark_v1(&value.statement, &other_genesis, &limits, &proof),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        for axis in CONSENSUS_BINDING_AXES_V1 {
            if matches!(
                axis,
                ConsensusBindingAxisV1::GenesisHash | ConsensusBindingAxisV1::ActionIndex
            ) {
                continue;
            }
            let (substituted_statement, substituted_binding) =
                coordinated_substitution_v1(axis, &value.statement, &binding, &limits)
                    .expect("this consensus axis has another valid canonical value");
            super::super::relation::validate_statement_v1(&substituted_statement).unwrap_or_else(
                |error| panic!("{axis:?} coordinated statement substitution is invalid: {error}"),
            );
            substituted_binding
                .validate_against_context(&substituted_statement.context, &limits)
                .unwrap_or_else(|error| {
                    panic!("{axis:?} coordinated binding substitution is invalid: {error}")
                });
            assert_proof_equation_rejection_v1(
                &format!("{axis:?}"),
                verify_private_note_stark_v1(
                    &substituted_statement,
                    &substituted_binding,
                    &limits,
                    &proof,
                ),
            );
        }
    }
    #[test]
    #[ignore = "release gate: generates and verifies the full-domain three-output settlement seam proof"]
    fn three_output_proof_rejects_a_substituted_fixed_output_memo() {
        let value = three_output_fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let relation = PrivateNoteStarkRelationV1::new(&value.statement, value.profile);
        let base_columns = relation
            .compile_prover_columns_v1(&value.witness)
            .expect("three-output prover columns");
        let adapter = PrivateNoteStarkAdapterV1::new_with_relation_profile_v1(
            &value.statement,
            &binding,
            &limits,
            value.profile,
        );
        let mut rng = StdRng::from_seed([0xB7; 32]);
        let proof = prove_proof_managed_note_stark_v1_with_rng(&adapter, &base_columns, &mut rng)
            .expect("three-output seam candidate")
            .verify_into_bytes_v1(&adapter)
            .expect("verified three-output seam proof");
        verify_proof_managed_note_stark_v1(&adapter, &proof)
            .expect("canonical fixed output memos verify");

        let PrivateNoteRelationProfileV1::ExactThreeOutputBalanced {
            output_memo_digests,
            mut audit_input_commitment,
        } = value.profile
        else {
            unreachable!("three-output fixture")
        };
        audit_input_commitment[0] ^= 1;
        let false_audit_profile = PrivateNoteRelationProfileV1::exact_three_output_balanced(
            output_memo_digests,
            audit_input_commitment,
        );
        let false_audit_adapter = PrivateNoteStarkAdapterV1::new_with_relation_profile_v1(
            &value.statement,
            &binding,
            &limits,
            false_audit_profile,
        );
        assert_proof_equation_rejection_v1(
            "verifier-fixed audited input openings",
            verify_proof_managed_note_stark_v1(&false_audit_adapter, &proof),
        );

        let PrivateNoteRelationProfileV1::ExactThreeOutputBalanced {
            mut output_memo_digests,
            audit_input_commitment,
        } = value.profile
        else {
            unreachable!("fixture uses the exact three-output profile")
        };
        output_memo_digests[2][0] ^= 1;
        let substituted_profile = PrivateNoteRelationProfileV1::exact_three_output_balanced(
            output_memo_digests,
            audit_input_commitment,
        );
        let substituted_adapter = PrivateNoteStarkAdapterV1::new_with_relation_profile_v1(
            &value.statement,
            &binding,
            &limits,
            substituted_profile,
        );
        assert_proof_equation_rejection_v1(
            "verifier-fixed output memo",
            verify_proof_managed_note_stark_v1(&substituted_adapter, &proof),
        );
    }
    #[test]
    fn native_rows_satisfy_every_extension_residue_on_the_trace_domain() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let trace =
            super::super::air::build_private_note_base_trace_v1(&value.statement, &value.witness)
                .expect("base trace");
        validate_private_note_base_trace_v1(&value.statement, &trace).expect("native oracle");
        let base = private_note_base_columns_v1(&trace).expect("columns");
        let adapter = PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits);
        let copy_schedule = adapter.copy_schedule_v1().expect("copy schedule");
        let mut transcript = TransparentTranscriptV1::new(
            PRIVATE_NOTE_DOMAINS_V1.digest_context,
            b"private-note-residue-test-v1",
            &PrivacyOuterDigestV1::from_bytes([1; 48]),
            &PrivacyOuterDigestV1::from_bytes([2; 48]),
        )
        .expect("transcript");
        let copy_challenges =
            crate::privacy_engines::proof_managed_note_stark::derive_note_copy_challenges_v1(
                &mut transcript,
            )
            .expect("copy challenges");
        let copy_fixed = copy_schedule
            .fixed_columns_v1(PRIVATE_NOTE_TRACE_SIZE_V1)
            .expect("copy fixed");
        let mut fixed = copy_fixed;
        fixed.extend(
            private_note_profile_fixed_columns_v1(&value.statement).expect("profile fixed"),
        );
        let copy_aux =
            crate::privacy_engines::proof_managed_note_stark::build_note_copy_aux_columns_v1(
                &base,
                &fixed,
                copy_challenges,
                PRIVATE_NOTE_TRACE_SIZE_V1,
            )
            .expect("copy aux");
        let profile_aux =
            private_note_profile_aux_columns_v1(&value.statement, &base).expect("profile aux");
        let mut aux = copy_aux;
        aux.extend(profile_aux);
        let row = |columns: &[Vec<F>], index: usize| {
            columns
                .iter()
                .map(|column| column[index])
                .collect::<Vec<_>>()
        };
        for index in 0..PRIVATE_NOTE_TRACE_SIZE_V1 {
            let next = (index + 1) % PRIVATE_NOTE_TRACE_SIZE_V1;
            let residues = private_note_profile_constraint_residues_inner_v1(
                &row(&base, index),
                &row(&base, next),
                &row(&aux, index),
                &row(&aux, next),
                &row(&fixed, index),
            )
            .expect("residue shape");
            assert_eq!(residues.len(), PRIVATE_NOTE_PROFILE_CONSTRAINT_COUNT_V1);
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "row {index} has nonzero profile residue at {:?}",
                residues.iter().position(|residue| *residue != F::ZERO)
            );
        }
    }
    #[test]
    fn hostile_prover_cannot_substitute_a_statement_nullifier_after_rebuilding_aux() {
        let value = fixture();
        let trace =
            super::super::air::build_private_note_base_trace_v1(&value.statement, &value.witness)
                .expect("honest base trace");
        let base = private_note_base_columns_v1(&trace).expect("honest base columns");
        let honest_nullifier = value.statement.nullifiers[0];
        let public_row = trace
            .fixed
            .rows
            .iter()
            .enumerate()
            .find_map(|(row, fixed)| match fixed {
                PrivateNoteFixedRowV1::ShaEnd {
                    digest_chunk: 0,
                    public_digest: Some(digest),
                    ..
                } if digest == honest_nullifier.as_bytes() => Some(row),
                _ => None,
            })
            .expect("public nullifier SHA endpoint");
        // Model a hostile prover that keeps a valid private relation trace but
        // asks the verifier to admit a different public replay marker. The
        // complete copy auxiliary trace is rebuilt for the fixed target
        // statement, so rejection cannot be attributed to stale products.
        let mut target_statement = value.statement.clone();
        let mut substituted = *honest_nullifier.as_bytes();
        substituted[0] ^= 1;
        target_statement.nullifiers[0] =
            iroha_data_model::privacy::PrivacyNullifierV1::new(substituted);
        target_statement.action_digest =
            iroha_data_model::privacy::PrivacyActionDigestV1::new([0; 32]);
        target_statement.action_digest = target_statement
            .computed_action_digest()
            .expect("recompute target action digest");
        let (binding, limits) = consensus_material(&target_statement);
        let adapter = PrivateNoteStarkAdapterV1::new(&target_statement, &binding, &limits);
        let copy_schedule = adapter.copy_schedule_v1().expect("target copy schedule");
        let mut fixed = copy_schedule
            .fixed_columns_v1(PRIVATE_NOTE_TRACE_SIZE_V1)
            .expect("target copy fixed");
        fixed.extend(
            private_note_profile_fixed_columns_v1(&target_statement).expect("target profile fixed"),
        );
        let mut transcript = TransparentTranscriptV1::new(
            PRIVATE_NOTE_DOMAINS_V1.digest_context,
            b"private-note-hostile-prover-v1",
            &PrivacyOuterDigestV1::from_bytes([5; 48]),
            &PrivacyOuterDigestV1::from_bytes([6; 48]),
        )
        .expect("transcript");
        let copy_challenges =
            crate::privacy_engines::proof_managed_note_stark::derive_note_copy_challenges_v1(
                &mut transcript,
            )
            .expect("copy challenges");
        let copy_aux =
            crate::privacy_engines::proof_managed_note_stark::build_note_copy_aux_columns_v1(
                &base,
                &fixed,
                copy_challenges,
                PRIVATE_NOTE_TRACE_SIZE_V1,
            )
            .expect("hostile prover rebuilds copy auxiliary columns");
        let profile_aux = private_note_profile_aux_columns_v1(&target_statement, &base)
            .expect("hostile prover rebuilds profile auxiliary columns");
        let mut aux = copy_aux;
        aux.extend(profile_aux);
        let row = |columns: &[Vec<F>], index: usize| {
            columns
                .iter()
                .map(|column| column[index])
                .collect::<Vec<_>>()
        };
        let next = (public_row + 1) % PRIVATE_NOTE_TRACE_SIZE_V1;
        let copy_residues =
            crate::privacy_engines::proof_managed_note_stark::note_copy_constraint_residues_v1(
                &row(&base, public_row),
                &row(&aux, public_row),
                &row(&aux, next),
                &row(&fixed, public_row),
                copy_challenges,
            )
            .expect("copy residue shape");
        assert!(
            copy_residues.iter().all(|residue| *residue == F::ZERO),
            "the hostile trace must remain copy-consistent"
        );
        let profile_residues = private_note_profile_constraint_residues_inner_v1(
            &row(&base, public_row),
            &row(&base, next),
            &row(&aux, public_row),
            &row(&aux, next),
            &row(&fixed, public_row),
        )
        .expect("profile residue shape");
        let nonzero = profile_residues
            .iter()
            .copied()
            .filter(|residue| *residue != F::ZERO)
            .collect::<Vec<_>>();
        assert_eq!(
            nonzero,
            vec![F(u64::from(honest_nullifier.as_bytes()[0])).sub(F(u64::from(substituted[0])))],
            "only the verifier-fixed public digest byte binding must reject the rebuilt trace"
        );
    }

    #[test]
    fn virtual_membership_polynomial_rejects_positive_nonmember_inputs() {
        let mut row = vec![F::ZERO; PRIVATE_NOTE_BASE_WIDTH_V1];
        let aux = vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1];
        let mut fixed =
            vec![F::ZERO; NOTE_COPY_FIXED_WIDTH_V1 + PRIVATE_NOTE_PROFILE_FIXED_WIDTH_V1];
        fixed[NOTE_COPY_FIXED_WIDTH_V1 + TYPE_MEMBERSHIP] = F::ONE;
        for pair in 0..3 {
            row[COPY_OFFSET + 1 + pair * 2] = F(11 + pair as u64);
            row[COPY_OFFSET + 2 + pair * 2] = F(22 + pair as u64);
        }
        let residues =
            private_note_profile_constraint_residues_inner_v1(&row, &row, &aux, &aux, &fixed)
                .expect("zero cover residue shape");
        assert!(residues.iter().all(|value| *value == F::ZERO));
        for value in [1_u64, 128, 255] {
            row[COPY_OFFSET] = F(value);
            let residues =
                private_note_profile_constraint_residues_inner_v1(&row, &row, &aux, &aux, &fixed)
                    .expect("positive input residue shape");
            assert_eq!(
                residues.iter().filter(|value| **value != F::ZERO).count(),
                3
            );
        }
    }

    #[test]
    fn audited_opening_substitution_fails_verifier_polynomials() {
        let value = three_output_fixture();
        let trace = build_private_note_base_trace_with_profile_v1(
            &value.statement,
            &value.witness,
            value.profile,
        )
        .expect("actual private inputs");
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
            audit_input_commitment,
        } = value.profile
        else {
            unreachable!()
        };
        let target = PrivateNoteRelationProfileV1::exact_three_output_balanced(
            output_memo_digests,
            super::super::derive_private_note_input_openings_commitment_v1(&claimed)
                .expect("same-total false capsule inputs"),
        );
        let target_fixed =
            private_note_profile_fixed_columns_with_relation_profile_v1(&value.statement, target)
                .expect("verifier-fixed profile");
        let aux = vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1];
        let mut rejected_bytes = 0;
        for (index, row) in trace.fixed.rows.iter().enumerate() {
            if matches!(row, PrivateNoteFixedRowV1::ShaEnd { public_digest: Some(digest), .. } if *digest == audit_input_commitment)
            {
                let mut fixed = vec![F::ZERO; NOTE_COPY_FIXED_WIDTH_V1];
                fixed.extend(target_fixed.iter().map(|column| column[index]));
                let residues = private_note_profile_constraint_residues_inner_v1(
                    &trace.rows[index],
                    &trace.rows[index + 1],
                    &aux,
                    &aux,
                    &fixed,
                )
                .expect("hash endpoint polynomials");
                rejected_bytes += residues.iter().filter(|value| **value != F::ZERO).count();
            }
        }
        assert!(
            rejected_bytes > 0,
            "the verifier must reject the false provenance even with unchanged actual input and output rows"
        );
    }
    fn mutation_is_detected(
        base: &[Vec<F>],
        aux: &[Vec<F>],
        fixed: &[Vec<F>],
        mutated_row: usize,
    ) -> bool {
        let row = |columns: &[Vec<F>], index: usize| {
            columns
                .iter()
                .map(|column| column[index])
                .collect::<Vec<_>>()
        };
        let previous = (mutated_row + PRIVATE_NOTE_TRACE_SIZE_V1 - 1) % PRIVATE_NOTE_TRACE_SIZE_V1;
        [previous, mutated_row].into_iter().any(|index| {
            let next = (index + 1) % PRIVATE_NOTE_TRACE_SIZE_V1;
            private_note_profile_constraint_residues_inner_v1(
                &row(base, index),
                &row(base, next),
                &row(aux, index),
                &row(aux, next),
                &row(fixed, index),
            )
            .expect("mutation preserves row shape")
            .into_iter()
            .any(|residue| residue != F::ZERO)
        })
    }
    fn assert_base_mutation_detected(
        base: &mut [Vec<F>],
        aux: &[Vec<F>],
        fixed: &[Vec<F>],
        row: usize,
        column: usize,
        family: &str,
    ) {
        let original = base[column][row];
        base[column][row] = original.add(F::ONE);
        assert!(
            mutation_is_detected(base, aux, fixed, row),
            "{family} base mutation was accepted"
        );
        base[column][row] = original;
    }
    fn assert_aux_mutation_detected(
        base: &[Vec<F>],
        aux: &mut [Vec<F>],
        fixed: &[Vec<F>],
        row: usize,
        column: usize,
        family: &str,
    ) {
        let original = aux[column][row];
        aux[column][row] = original.add(F::ONE);
        assert!(
            mutation_is_detected(base, aux, fixed, row),
            "{family} auxiliary mutation was accepted"
        );
        aux[column][row] = original;
    }
    #[test]
    fn extension_residues_reject_mutations_across_every_constraint_family() {
        let value = fixture();
        let (binding, limits) = consensus_material(&value.statement);
        let trace =
            super::super::air::build_private_note_base_trace_v1(&value.statement, &value.witness)
                .expect("base trace");
        let row_types = trace.fixed.rows.clone();
        let mut base = private_note_base_columns_v1(&trace).expect("columns");
        let adapter = PrivateNoteStarkAdapterV1::new(&value.statement, &binding, &limits);
        let copy_schedule = adapter.copy_schedule_v1().expect("copy schedule");
        let mut transcript = TransparentTranscriptV1::new(
            PRIVATE_NOTE_DOMAINS_V1.digest_context,
            b"private-note-mutation-test-v1",
            &PrivacyOuterDigestV1::from_bytes([3; 48]),
            &PrivacyOuterDigestV1::from_bytes([4; 48]),
        )
        .expect("transcript");
        let copy_challenges =
            crate::privacy_engines::proof_managed_note_stark::derive_note_copy_challenges_v1(
                &mut transcript,
            )
            .expect("copy challenges");
        let mut fixed = copy_schedule
            .fixed_columns_v1(PRIVATE_NOTE_TRACE_SIZE_V1)
            .expect("copy fixed");
        fixed.extend(
            private_note_profile_fixed_columns_v1(&value.statement).expect("profile fixed"),
        );
        let mut aux =
            crate::privacy_engines::proof_managed_note_stark::build_note_copy_aux_columns_v1(
                &base,
                &fixed,
                copy_challenges,
                PRIVATE_NOTE_TRACE_SIZE_V1,
            )
            .expect("copy aux");
        aux.extend(
            private_note_profile_aux_columns_v1(&value.statement, &base).expect("profile aux"),
        );
        let row_index = |predicate: &dyn Fn(&PrivateNoteFixedRowV1) -> bool| {
            row_types
                .iter()
                .position(predicate)
                .expect("canonical row family")
        };
        let mutations = [
            (
                row_index(&|row| matches!(row, PrivateNoteFixedRowV1::ShaRound { round: 16, .. })),
                SHA_SCHEDULE_OFFSET + 16,
                "SHA schedule",
            ),
            (
                row_index(&|row| {
                    matches!(
                        row,
                        PrivateNoteFixedRowV1::ShaEnd {
                            digest_chunk: 0,
                            ..
                        }
                    )
                }),
                SHA_STATE_OFFSET,
                "SHA endpoint",
            ),
            (
                row_index(&|row| matches!(row, PrivateNoteFixedRowV1::NodeSelect { .. })),
                COPY_OFFSET + 2,
                "Merkle node selection",
            ),
            (
                row_index(&|row| matches!(row, PrivateNoteFixedRowV1::Distinct { .. })),
                SCRATCH_RUNNING_AFTER,
                "distinctness",
            ),
            (
                row_index(&|row| matches!(row, PrivateNoteFixedRowV1::NonZero { .. })),
                SCRATCH_RUNNING_BEFORE,
                "nonzero",
            ),
            (
                row_index(&|row| {
                    matches!(
                        row,
                        PrivateNoteFixedRowV1::Sum {
                            side: SumSideV1::Inputs,
                            ..
                        }
                    )
                }),
                SCRATCH_RELATION_CARRY_AFTER,
                "value sum",
            ),
            (
                row_index(&|row| {
                    matches!(row, PrivateNoteFixedRowV1::VmProgram { instruction: 0 })
                }),
                SCRATCH_VM_OPCODE_SELECT_OFFSET,
                "VM program",
            ),
            (
                row_index(&|row| {
                    matches!(
                        row,
                        PrivateNoteFixedRowV1::VmPrevious {
                            instruction: 0,
                            byte: 0,
                        }
                    )
                }),
                SCRATCH_VM_RESULT_BITS_OFFSET,
                "VM execution",
            ),
            (
                row_index(&|row| matches!(row, PrivateNoteFixedRowV1::Padding)),
                SCRATCH_RUNNING_BEFORE,
                "padding zeroization",
            ),
        ];
        for (row, column, family) in mutations {
            assert_base_mutation_detected(&mut base, &aux, &fixed, row, column, family);
        }
        let vm_next = row_index(&|row| {
            matches!(
                row,
                PrivateNoteFixedRowV1::VmNext {
                    instruction: 0,
                    byte: 0,
                }
            )
        });
        assert_aux_mutation_detected(
            &base,
            &mut aux,
            &fixed,
            vm_next,
            NOTE_COPY_AUX_WIDTH_V1 + PROFILE_AUX_VM_CARRY_BRIDGE,
            "VM carry bridge",
        );
    }
}
