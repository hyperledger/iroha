//! Extension-domain adapter for the fixed native PQ-MASP AIR.
//!
//! The verifier reconstructs every selector and constant column from the public statement. The
//! prover commits only witness-bearing base columns; the sole profile auxiliary column is reserved
//! as a zero bridge so the shared first-release note proof driver has one exact topology.
use super::{
    air::{
        COPY_OFFSET, PQ_MASP_BASE_WIDTH_V1, PQ_MASP_COPY_WIDTH_V1, PQ_MASP_SHA_BIT_COLUMNS_V1,
        PQ_MASP_SHA_BITS_PER_GROUP_V1, PQ_MASP_SHA_SCHEDULE_WORDS_V1, PQ_MASP_SHA_STATE_WORDS_V1,
        PQ_MASP_TRACE_LOG2_V1, PQ_MASP_TRACE_SIZE_V1, PqMaspAirErrorV1, PqMaspBaseTraceV1,
        PqMaspFixedRowV1, SCRATCH_BYTE_BITS_OFFSET, SCRATCH_DISTINCT_RIGHT_BITS_OFFSET,
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
        build_pq_masp_copy_schedule_v1, build_pq_masp_fixed_trace_v1,
    },
    relation::PqMaspWitnessV1,
};
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
    PqMaspStarkStatementV1, PrivacyConsensusLimitsV1, PrivacyNativeConsensusBindingV1,
    PrivacyProtocolIdV1,
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
const TYPE_COLUMN_COUNT: usize = 12;
const FIXED_ROUND_SELECTOR_OFFSET: usize = TYPE_COLUMN_COUNT;
const FIXED_FIRST_BLOCK_ROUND_ZERO: usize = FIXED_ROUND_SELECTOR_OFFSET + 64;
const FIXED_SHA_END_TERMINAL: usize = FIXED_FIRST_BLOCK_ROUND_ZERO + 1;
const FIXED_SHA_END_CONTINUE: usize = FIXED_SHA_END_TERMINAL + 1;
const FIXED_SHA_END_NEXT_BLOCK: usize = FIXED_SHA_END_CONTINUE + 1;
const FIXED_TERMINAL_CHUNK_OFFSET: usize = FIXED_SHA_END_NEXT_BLOCK + 1;
const FIXED_SHA_END_PUBLIC_SELECTOR: usize = FIXED_TERMINAL_CHUNK_OFFSET + 4;
const FIXED_SHA_END_PUBLIC_BYTE_OFFSET: usize = FIXED_SHA_END_PUBLIC_SELECTOR + 1;
const FIXED_SEQUENCE_FIRST: usize = FIXED_SHA_END_PUBLIC_BYTE_OFFSET + PQ_MASP_COPY_WIDTH_V1;
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
pub(super) const PQ_MASP_PROFILE_FIXED_WIDTH_V1: usize = FIXED_VM_EXECUTION_EPOCH_BYTE + 1;
pub(super) const PQ_MASP_PROFILE_AUX_WIDTH_V1: usize = 1;
pub(super) const PQ_MASP_PROFILE_CONSTRAINT_COUNT_V1: usize = 1_372;
/// Audited maximum algebraic degree across the complete shared/profile AIR.
pub(super) const PQ_MASP_PROFILE_CONSTRAINT_DEGREE_V1: u8 =
    PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1;
const PROFILE_AUX_VM_CARRY_BRIDGE: usize = 0;
/// Relation-local descriptor combined with the shared proof-driver geometry.
pub const PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1: &[u8] = b"pq-masp-stark-v1:relation=proof-managed-note:wire=PQA1-outer+PQS1-inner-v1:trace=2^14:base=556:profile-aux=1:profile-fixed=122:profile-constraints=1372:constraint-degree=4:max-inner-proof=9431915:sha256-wide-air:public-digest=sha3-384-opaque48(canonical-statement,PrivacyNativeConsensusBindingDigestV1):tree-depth=32:authorization=ML-DSA-65(statement-digest+native-consensus-binding-digest-v1+inner-proof-digest):encryption=ML-KEM-768+XChaCha20Poly1305:value=u128-checked:fee=separate:legacy=unrepresentable:governance=typed-lifecycle";
const PQ_MASP_PARAMETERS_V1: aggregate::AggregateStarkParametersV1 =
    aggregate::AggregateStarkParametersV1 {
        proof_magic: *b"PQS1",
        proof_version: 1,
        fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Scalar,
        security_lanes: PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
        query_count: PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
        blowup_log2: PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
        terminal_log2: PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
        terminal_degree_bound: PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
        composition_degree_chunks: PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
        minimum_trace_log2: PQ_MASP_TRACE_LOG2_V1,
        maximum_trace_log2: PQ_MASP_TRACE_LOG2_V1,
        maximum_trace_groups: 1,
        maximum_segment_instances: 1,
        maximum_base_columns_per_instance: PQ_MASP_BASE_WIDTH_V1,
        maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1 + PQ_MASP_PROFILE_AUX_WIDTH_V1,
        maximum_proof_bytes: super::wire::PQ_MASP_MAX_STARK_PROOF_BYTES_V1,
    };
pub const PQ_MASP_DOMAINS_V1: aggregate::AggregateStarkDomainsV1 =
    aggregate::AggregateStarkDomainsV1 {
        digest_context: TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::PqMaspStarkV1,
            b"pq-masp-stark-profile-v1",
        ),
        base_leaf: b"pq-masp-stark-base-leaf-v1",
        base_node: b"pq-masp-stark-base-node-v1",
        aux_leaf: b"pq-masp-stark-aux-leaf-v1",
        aux_node: b"pq-masp-stark-aux-node-v1",
        composition_leaf: b"pq-masp-stark-composition-leaf-v1",
        composition_node: b"pq-masp-stark-composition-node-v1",
        fri_leaf: b"pq-masp-stark-fri-leaf-v1",
        fri_node: b"pq-masp-stark-fri-node-v1",
        layout_label: b"pq-masp-stark-layout-v1",
        base_root_label: b"pq-masp-stark-base-root-v1",
        aux_root_label: b"pq-masp-stark-aux-root-v1",
        composition_root_label: b"pq-masp-stark-composition-root-v1",
        fri_root_label: b"pq-masp-stark-fri-root-v1",
        fri_beta_label: b"pq-masp-stark-fri-beta-v1",
        query_seed: b"pq-masp-stark-query-seed-v1",
    };
fn pq_masp_protocol_v1() -> ProofManagedNoteStarkProtocolV1 {
    ProofManagedNoteStarkProtocolV1 {
        parameters: PQ_MASP_PARAMETERS_V1,
        domains: PQ_MASP_DOMAINS_V1,
        maximum_constraint_degree: PQ_MASP_PROFILE_CONSTRAINT_DEGREE_V1,
        profile_binding_label: b"pq-masp-stark-profile-v1",
        profile_descriptor: PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1,
        relation_layout_domain: b"pq-masp-stark-relation-layout-v1",
    }
}
/// Validate the complete compiled proof-system and relation profile.
pub fn validate_pq_masp_stark_profile_v1() -> Result<(), ProofManagedNoteStarkErrorV1> {
    pq_masp_protocol_v1().validate()?;
    validate_reserved_vm_row_contract_v1()
}
fn map_air_error_v1(error: PqMaspAirErrorV1) -> ProofManagedNoteStarkErrorV1 {
    match error {
        PqMaspAirErrorV1::Resource => ProofManagedNoteStarkErrorV1::Resource,
        PqMaspAirErrorV1::Copy => ProofManagedNoteStarkErrorV1::Copy,
        PqMaspAirErrorV1::Relation
        | PqMaspAirErrorV1::Topology
        | PqMaspAirErrorV1::Assignment
        | PqMaspAirErrorV1::Sha256 => ProofManagedNoteStarkErrorV1::Constraint,
    }
}
fn vm_same_instruction_transition(current: &PqMaspFixedRowV1, next: &PqMaspFixedRowV1) -> bool {
    match (current, next) {
        (
            PqMaspFixedRowV1::VmProgram { instruction },
            PqMaspFixedRowV1::VmPrevious {
                instruction: next_instruction,
                byte: 0,
            },
        ) => instruction == next_instruction,
        (
            PqMaspFixedRowV1::VmPrevious { instruction, byte },
            PqMaspFixedRowV1::VmNext {
                instruction: next_instruction,
                byte: next_byte,
            },
        ) => instruction == next_instruction && byte == next_byte,
        (
            PqMaspFixedRowV1::VmNext { instruction, byte },
            PqMaspFixedRowV1::VmPrevious {
                instruction: next_instruction,
                byte: next_byte,
            },
        ) => instruction == next_instruction && usize::from(*byte) + 1 == usize::from(*next_byte),
        _ => false,
    }
}
fn reserved_vm_type_column_v1(row: &PqMaspFixedRowV1) -> Option<usize> {
    match row {
        PqMaspFixedRowV1::VmHeader => Some(TYPE_VM_HEADER),
        PqMaspFixedRowV1::VmProgram { .. } => Some(TYPE_VM_PROGRAM),
        PqMaspFixedRowV1::VmPrevious { .. } => Some(TYPE_VM_PREVIOUS),
        PqMaspFixedRowV1::VmNext { .. } => Some(TYPE_VM_NEXT),
        _ => None,
    }
}
fn validate_reserved_vm_row_contract_v1() -> Result<(), ProofManagedNoteStarkErrorV1> {
    let rows = [
        PqMaspFixedRowV1::VmHeader,
        PqMaspFixedRowV1::VmProgram { instruction: 7 },
        PqMaspFixedRowV1::VmPrevious {
            instruction: 7,
            byte: 0,
        },
        PqMaspFixedRowV1::VmNext {
            instruction: 7,
            byte: 0,
        },
        PqMaspFixedRowV1::VmPrevious {
            instruction: 7,
            byte: 1,
        },
    ];
    let type_columns = [
        reserved_vm_type_column_v1(&rows[0]),
        reserved_vm_type_column_v1(&rows[1]),
        reserved_vm_type_column_v1(&rows[2]),
        reserved_vm_type_column_v1(&rows[3]),
    ];
    if [
        TYPE_VM_HEADER,
        TYPE_VM_PROGRAM,
        TYPE_VM_PREVIOUS,
        TYPE_VM_NEXT,
    ] != [7, 8, 9, 10]
        || type_columns
            != [
                Some(TYPE_VM_HEADER),
                Some(TYPE_VM_PROGRAM),
                Some(TYPE_VM_PREVIOUS),
                Some(TYPE_VM_NEXT),
            ]
        || vm_same_instruction_transition(&rows[0], &rows[1])
        || !vm_same_instruction_transition(&rows[1], &rows[2])
        || !vm_same_instruction_transition(&rows[2], &rows[3])
        || !vm_same_instruction_transition(&rows[3], &rows[4])
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    Ok(())
}
pub(super) fn pq_masp_profile_fixed_columns_v1(
    statement: &PqMaspStarkStatementV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    let fixed = build_pq_masp_fixed_trace_v1(statement).map_err(map_air_error_v1)?;
    if fixed.rows.len() != PQ_MASP_TRACE_SIZE_V1 {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let mut columns = vec![vec![F::ZERO; PQ_MASP_TRACE_SIZE_V1]; PQ_MASP_PROFILE_FIXED_WIDTH_V1];
    for (row, current) in fixed.rows.iter().enumerate() {
        let next = fixed
            .rows
            .get((row + 1).min(PQ_MASP_TRACE_SIZE_V1 - 1))
            .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        match current {
            PqMaspFixedRowV1::ShaRound { round, block, .. } => {
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
            PqMaspFixedRowV1::ShaEnd {
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
                        .checked_mul(PQ_MASP_COPY_WIDTH_V1)
                        .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
                    let public_chunk = public_digest
                        .get(start..start + PQ_MASP_COPY_WIDTH_V1)
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
            PqMaspFixedRowV1::NodeSelect { .. } => {
                set(&mut columns, TYPE_NODE_SELECT, row, F::ONE);
            }
            PqMaspFixedRowV1::Distinct { chunk, chunks, .. } => {
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
            PqMaspFixedRowV1::NonZero { chunk, chunks, .. } => {
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
            PqMaspFixedRowV1::Sum { side, byte } => {
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
            PqMaspFixedRowV1::VmHeader
            | PqMaspFixedRowV1::VmProgram { .. }
            | PqMaspFixedRowV1::VmPrevious { .. }
            | PqMaspFixedRowV1::VmNext { .. } => {
                return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
            }
            PqMaspFixedRowV1::Padding => {
                set(&mut columns, TYPE_PADDING, row, F::ONE);
            }
        }
        if vm_same_instruction_transition(current, next) {
            set(&mut columns, FIXED_VM_COMMON_TRANSITION, row, F::ONE);
        }
    }
    Ok(columns)
}
pub(super) fn pq_masp_profile_aux_columns_v1(
    statement: &PqMaspStarkStatementV1,
    base_columns: &[Vec<F>],
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if base_columns.len() != PQ_MASP_BASE_WIDTH_V1
        || base_columns
            .iter()
            .any(|column| column.len() != PQ_MASP_TRACE_SIZE_V1)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let fixed = build_pq_masp_fixed_trace_v1(statement).map_err(map_air_error_v1)?;
    let mut bridge = vec![F::ZERO; PQ_MASP_TRACE_SIZE_V1];
    for row in 1..PQ_MASP_TRACE_SIZE_V1 {
        if matches!(fixed.rows[row], PqMaspFixedRowV1::VmNext { .. }) {
            if !matches!(fixed.rows[row - 1], PqMaspFixedRowV1::VmPrevious { .. }) {
                return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
            }
            bridge[row] = base_columns[SCRATCH_VM_CARRY_AFTER][row - 1];
        }
    }
    Ok(vec![bridge])
}
pub(super) fn pq_masp_base_columns_v1(
    trace: &PqMaspBaseTraceV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if trace.rows.len() != PQ_MASP_TRACE_SIZE_V1
        || trace
            .rows
            .iter()
            .any(|row| row.len() != PQ_MASP_BASE_WIDTH_V1)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    Ok((0..PQ_MASP_BASE_WIDTH_V1)
        .map(|column| trace.rows.iter().map(|row| row[column]).collect())
        .collect())
}
include!("../shared_note_sha256_helpers.rs");
fn bits_group(row: &[F], group: usize) -> &[F] {
    let start = SHA_BITS_OFFSET + group * PQ_MASP_SHA_BITS_PER_GROUP_V1;
    &row[start..start + PQ_MASP_SHA_BITS_PER_GROUP_V1]
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
    if (SHA_SCHEDULE_OFFSET..SHA_SCHEDULE_OFFSET + PQ_MASP_SHA_SCHEDULE_WORDS_V1).contains(&column)
        || (SHA_INITIAL_STATE_OFFSET..SHA_INITIAL_STATE_OFFSET + PQ_MASP_SHA_STATE_WORDS_V1)
            .contains(&column)
        || (SHA_T1_OFFSET..SHA_CARRY_OFFSET + SHA_CARRY_WIDTH).contains(&column)
    {
        sha_round
    } else if (SHA_STATE_OFFSET..SHA_STATE_OFFSET + PQ_MASP_SHA_STATE_WORDS_V1).contains(&column)
        || (SHA_BITS_OFFSET..SHA_BITS_OFFSET + PQ_MASP_SHA_BIT_COLUMNS_V1).contains(&column)
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
    } else if (SCRATCH_DISTINCT_RIGHT_BITS_OFFSET..SCRATCH_DISTINCT_RIGHT_BITS_OFFSET + 8)
        .contains(&column)
    {
        vm_previous.add(distinct)
    } else {
        F::ZERO
    }
}
const BASE_WIDTH: usize = PQ_MASP_BASE_WIDTH_V1;
const PROFILE_AUX_WIDTH: usize = PQ_MASP_PROFILE_AUX_WIDTH_V1;
const PROFILE_FIXED_WIDTH: usize = PQ_MASP_PROFILE_FIXED_WIDTH_V1;
const SHA_BIT_COLUMNS: usize = PQ_MASP_SHA_BIT_COLUMNS_V1;
const SHA_STATE_WORDS: usize = PQ_MASP_SHA_STATE_WORDS_V1;
const SHA_SCHEDULE_WORDS: usize = PQ_MASP_SHA_SCHEDULE_WORDS_V1;
const COPY_WIDTH: usize = PQ_MASP_COPY_WIDTH_V1;
const DISTINCT_RIGHT_BITS_OFFSET: usize = SCRATCH_DISTINCT_RIGHT_BITS_OFFSET;
const VM_DIFFERENCE_BITS_OFFSET: usize = SCRATCH_VM_DIFFERENCE_BITS_OFFSET;
include!("../shared_note_profile_constraints.rs");
define_note_profile_constraint_residues_v1!(pq_masp_profile_constraint_residues_inner_v1);
/// Statement-and-consensus-binding adapter used by both prover and verifier.
pub(super) struct PqMaspStarkAdapterV1<'a> {
    statement: &'a PqMaspStarkStatementV1,
    consensus_binding: &'a PrivacyNativeConsensusBindingV1,
    consensus_limits: &'a PrivacyConsensusLimitsV1,
}
impl<'a> PqMaspStarkAdapterV1<'a> {
    pub(super) const fn new(
        statement: &'a PqMaspStarkStatementV1,
        consensus_binding: &'a PrivacyNativeConsensusBindingV1,
        consensus_limits: &'a PrivacyConsensusLimitsV1,
    ) -> Self {
        Self {
            statement,
            consensus_binding,
            consensus_limits,
        }
    }
}
impl ProofManagedNoteStarkAdapterV1 for PqMaspStarkAdapterV1<'_> {
    type ProfileChallenges = ();
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        pq_masp_protocol_v1()
    }
    fn public_input_digest_v1(&self) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
        self.consensus_binding
            .validate_against_context(&self.statement.context, self.consensus_limits)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        let encoded = norito::to_bytes(self.statement)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        let binding_digest = self
            .consensus_binding
            .digest()
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        privacy_outer_digest_frame_v1(
            PQ_MASP_DOMAINS_V1.digest_context,
            b"pq-masp-stark-public-input-with-consensus-binding-v1",
            b"statement-binding",
            0,
            0,
            0,
            &[&encoded, binding_digest.as_bytes()],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::Internal)
    }
    fn trace_log2_v1(&self) -> u8 {
        PQ_MASP_TRACE_LOG2_V1
    }
    fn base_width_v1(&self) -> usize {
        PQ_MASP_BASE_WIDTH_V1
    }
    fn profile_aux_width_v1(&self) -> usize {
        PQ_MASP_PROFILE_AUX_WIDTH_V1
    }
    fn profile_fixed_width_v1(&self) -> usize {
        PQ_MASP_PROFILE_FIXED_WIDTH_V1
    }
    fn profile_constraint_count_v1(&self) -> usize {
        PQ_MASP_PROFILE_CONSTRAINT_COUNT_V1
    }
    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        build_pq_masp_copy_schedule_v1(self.statement).map_err(map_air_error_v1)
    }
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        pq_masp_profile_fixed_columns_v1(self.statement)
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
        pq_masp_profile_aux_columns_v1(self.statement, base_columns)
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
        pq_masp_profile_constraint_residues_inner_v1(
            current_base,
            next_base,
            current_aux,
            next_aux,
            fixed,
        )
    }
}
/// Compile and natively validate one canonical prover base trace.
pub(super) fn compile_pq_masp_prover_columns_v1(
    statement: &PqMaspStarkStatementV1,
    witness: &PqMaspWitnessV1,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    let trace =
        super::air::build_pq_masp_base_trace_v1(statement, witness).map_err(map_air_error_v1)?;
    pq_masp_base_columns_v1(&trace)
}
/// Construct the canonical PQ-MASP proof with injected masking entropy.
///
/// The witness is compiled and checked by the native interpreter before the shared proof driver
/// sees any columns. The proof driver then checks the same relation algebraically on the native and
/// extension domains. This relation adapter independently verifies its opaque candidate before returning bytes.
pub(super) fn prove_pq_masp_stark_v1_with_rng<R: TryRngCore>(
    statement: &PqMaspStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    witness: &PqMaspWitnessV1,
    rng: &mut R,
) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
    let base_columns = compile_pq_masp_prover_columns_v1(statement, witness)?;
    prove_proof_managed_note_stark_v1_with_rng(
        &PqMaspStarkAdapterV1::new(statement, consensus_binding, consensus_limits),
        &base_columns,
        rng,
    )?
    .verify_into_bytes_v1(&PqMaspStarkAdapterV1::new(
        statement,
        consensus_binding,
        consensus_limits,
    ))
}
/// Verify the exact PQ-MASP proof against the statement and consensus binding.
pub fn verify_pq_masp_stark_v1(
    statement: &PqMaspStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    proof_bytes: &[u8],
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    verify_proof_managed_note_stark_v1(
        &PqMaspStarkAdapterV1::new(statement, consensus_binding, consensus_limits),
        proof_bytes,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::{
        pq_masp::{
            derive_pq_masp_authorization_key_digest_v1,
            relation::test_fixtures::{
                valid_fixture, valid_fixture_with_authorization_key_digest,
                valid_two_by_two_fixture,
            },
            wire::{
                PqMaspWireErrorV1, authorize_pq_masp_stark_proof_v1,
                decode_pq_masp_authorization_proof_v1, verify_pq_masp_authorization_v1,
            },
        },
        proof_managed_note_stark::{
            NoteCopyCellPolicyV1, build_note_copy_aux_columns_v1, derive_note_copy_challenges_v1,
            note_copy_constraint_residues_v1,
        },
    };
    use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};
    use soranet_pq::{HedgedRngSeed, MlDsaSuite, generate_mldsa_keypair_from_seed};
    fn row(columns: &[Vec<F>], index: usize) -> Vec<F> {
        columns.iter().map(|column| column[index]).collect()
    }
    fn consensus_material(
        statement: &PqMaspStarkStatementV1,
    ) -> (PrivacyNativeConsensusBindingV1, PrivacyConsensusLimitsV1) {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let genesis_hash = iroha_crypto::Hash::prehashed([0xC2; 32]).into();
        let binding =
            PrivacyNativeConsensusBindingV1::new(&statement.context, genesis_hash, &limits)
                .expect("valid PQ-MASP consensus binding");
        (binding, limits)
    }
    fn other_genesis_consensus_material(
        statement: &PqMaspStarkStatementV1,
        limits: &PrivacyConsensusLimitsV1,
    ) -> (PqMaspStarkStatementV1, PrivacyNativeConsensusBindingV1) {
        let mut genesis_bytes = *statement.context.network_id.as_bytes();
        genesis_bytes[0] ^= 1;
        let genesis = iroha_crypto::Hash::prehashed(genesis_bytes);
        let mut other_statement = statement.clone();
        other_statement.context.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                genesis
            ));
        let other_binding =
            PrivacyNativeConsensusBindingV1::new(&other_statement.context, genesis.into(), limits)
                .expect("matched alternate-genesis consensus binding");
        // Use the facade's exact preflight before any expensive proof work.
        super::super::relation::validate_statement_v1(&other_statement)
            .expect("alternate-genesis statement passes facade preflight");
        other_binding
            .validate_against_context(&other_statement.context, limits)
            .expect("alternate-genesis statement and binding agree");
        (other_statement, other_binding)
    }
    #[test]
    fn other_genesis_fixture_passes_outer_preflight_and_changes_inner_public_input() {
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xDC; 32]),
            b"pq-masp-other-genesis-preflight-v1",
        )
        .expect("preflight ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("preflight authorization key digest");
        let (statement, _) = valid_fixture_with_authorization_key_digest(key_digest);
        let (binding, limits) = consensus_material(&statement);
        let (other_statement, other_binding) =
            other_genesis_consensus_material(&statement, &limits);
        assert_ne!(
            other_statement.context.network_id,
            statement.context.network_id
        );
        assert_ne!(other_binding.genesis_hash, binding.genesis_hash);
        let mut restored_statement = other_statement.clone();
        restored_statement.context.network_id = statement.context.network_id;
        assert_eq!(restored_statement, statement);
        let mut restored_binding = other_binding;
        restored_binding.network_id = binding.network_id;
        restored_binding.genesis_hash = binding.genesis_hash;
        assert_eq!(restored_binding, binding);
        assert_ne!(
            PqMaspStarkAdapterV1::new(&statement, &binding, &limits)
                .public_input_digest_v1()
                .expect("original inner public input"),
            PqMaspStarkAdapterV1::new(&other_statement, &other_binding, &limits)
                .public_input_digest_v1()
                .expect("matched alternate-genesis inner public input"),
            "a matched network/genesis substitution must change the inner commitment"
        );
        let statement_digest =
            iroha_data_model::privacy::PrivacyStatementV1::PqMaspStarkV1(other_statement.clone())
                .digest()
                .expect("alternate-genesis statement digest");
        let binding_digest = other_binding
            .digest()
            .expect("alternate-genesis binding digest");
        // These inert bytes exercise only preflight and outer authorization;
        // the ignored full-domain test below retains the real inner-proof gate.
        let inert_inner = b"cross-genesis preflight only; not a STARK";
        let authorized = authorize_pq_masp_stark_proof_v1(
            statement_digest,
            binding_digest,
            key_digest,
            authorization_keys.secret_key(),
            inert_inner,
            HedgedRngSeed::from_entropy([0xDD; 32]),
        )
        .expect("fresh alternate-genesis outer authorization");
        let decoded = verify_pq_masp_authorization_v1(
            statement_digest,
            binding_digest,
            key_digest,
            &authorized,
        )
        .expect("alternate-genesis outer authorization verifies independently");
        assert_eq!(decoded.stark_proof, inert_inner.as_slice());
        assert_eq!(
            super::super::verify_pq_masp_v1(&other_statement, &other_binding, &limits, &authorized,),
            Err(super::super::PqMaspProofErrorV1::InvalidProof),
            "valid statement, binding and outer authorization must reach the inner verifier"
        );
    }
    fn prepared_columns(
        statement: &PqMaspStarkStatementV1,
        witness: &PqMaspWitnessV1,
        transcript_domain: &'static [u8],
    ) -> (
        super::super::air::PqMaspBaseTraceV1,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
        NoteCopyChallengesV1,
    ) {
        let trace = super::super::air::build_pq_masp_base_trace_v1(statement, witness)
            .expect("canonical PQ-MASP trace");
        let base = pq_masp_base_columns_v1(&trace).expect("base columns");
        let (binding, limits) = consensus_material(statement);
        let adapter = PqMaspStarkAdapterV1::new(statement, &binding, &limits);
        let copy_schedule = adapter.copy_schedule_v1().expect("copy schedule");
        let profile = PrivacyOuterDigestV1::from_bytes([1; 48]);
        let public = PrivacyOuterDigestV1::from_bytes([2; 48]);
        let mut transcript = TransparentTranscriptV1::new(
            PQ_MASP_DOMAINS_V1.digest_context,
            transcript_domain,
            &profile,
            &public,
        )
        .expect("test transcript");
        let copy_challenges =
            derive_note_copy_challenges_v1(&mut transcript).expect("copy challenges");
        let mut fixed = copy_schedule
            .fixed_columns_v1(PQ_MASP_TRACE_SIZE_V1)
            .expect("copy fixed columns");
        fixed.extend(pq_masp_profile_fixed_columns_v1(statement).expect("profile fixed columns"));
        let mut aux =
            build_note_copy_aux_columns_v1(&base, &fixed, copy_challenges, PQ_MASP_TRACE_SIZE_V1)
                .expect("copy auxiliary columns");
        aux.extend(
            pq_masp_profile_aux_columns_v1(statement, &base).expect("profile auxiliary columns"),
        );
        (trace, base, aux, fixed, copy_challenges)
    }
    #[test]
    fn reserved_vm_row_contract_pins_selector_and_sequence_mapping() {
        validate_reserved_vm_row_contract_v1().expect("reserved VM row contract");
        assert_eq!(reserved_vm_type_column_v1(&PqMaspFixedRowV1::Padding), None);
        assert!(!vm_same_instruction_transition(
            &PqMaspFixedRowV1::VmProgram { instruction: 7 },
            &PqMaspFixedRowV1::VmPrevious {
                instruction: 8,
                byte: 0,
            }
        ));
    }
    #[test]
    fn compiled_profile_count_digest_and_outer_wire_budget_are_exact() {
        validate_pq_masp_stark_profile_v1().expect("compiled PQ-MASP soundness profile");
        let residues = pq_masp_profile_constraint_residues_inner_v1(
            &vec![F::ZERO; PQ_MASP_BASE_WIDTH_V1],
            &vec![F::ZERO; PQ_MASP_BASE_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PQ_MASP_PROFILE_AUX_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1 + PQ_MASP_PROFILE_AUX_WIDTH_V1],
            &vec![F::ZERO; NOTE_COPY_FIXED_WIDTH_V1 + PQ_MASP_PROFILE_FIXED_WIDTH_V1],
        )
        .expect("zero rows have the compiled profile shape");
        assert_eq!(residues.len(), PQ_MASP_PROFILE_CONSTRAINT_COUNT_V1);
        let profile_digest = crate::privacy_engines::proof_managed_note_stark::proof_managed_note_stark_profile_digest_v1(
            &PQ_MASP_DOMAINS_V1,
            PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1,
        )
        .expect("profile digest");
        assert_ne!(profile_digest, PrivacyOuterDigestV1::default());
        let expected_descriptor = format!(
            "pq-masp-stark-v1:relation=proof-managed-note:wire=PQA1-outer+PQS1-inner-v1:trace=2^{}:base={}:profile-aux={}:profile-fixed={}:profile-constraints={}:constraint-degree={}:max-inner-proof={}:sha256-wide-air:public-digest=sha3-384-opaque48(canonical-statement,PrivacyNativeConsensusBindingDigestV1):tree-depth=32:authorization=ML-DSA-65(statement-digest+native-consensus-binding-digest-v1+inner-proof-digest):encryption=ML-KEM-768+XChaCha20Poly1305:value=u128-checked:fee=separate:legacy=unrepresentable:governance=typed-lifecycle",
            PQ_MASP_TRACE_LOG2_V1,
            PQ_MASP_BASE_WIDTH_V1,
            PQ_MASP_PROFILE_AUX_WIDTH_V1,
            PQ_MASP_PROFILE_FIXED_WIDTH_V1,
            PQ_MASP_PROFILE_CONSTRAINT_COUNT_V1,
            PQ_MASP_PROFILE_CONSTRAINT_DEGREE_V1,
            super::super::wire::PQ_MASP_MAX_STARK_PROOF_BYTES_V1,
        );
        assert_eq!(
            PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1,
            expected_descriptor.as_bytes()
        );
        assert!(
            PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1.starts_with(b"pq-masp-stark-v1:"),
            "the proof profile must use the sole canonical protocol identifier"
        );
        assert!(PQ_MASP_STARK_PROFILE_DESCRIPTOR_V1.ends_with(b":governance=typed-lifecycle"));
        assert_eq!(
            PQ_MASP_PARAMETERS_V1.maximum_proof_bytes,
            super::super::wire::PQ_MASP_MAX_STARK_PROOF_BYTES_V1
        );
    }
    #[test]
    fn declared_constraint_degree_matches_affine_finite_differences() {
        let measured = crate::privacy_engines::proof_managed_note_stark::degree_audit::
            measured_maximum_affine_degree_v1(
                [0xE4; 32],
                [
                    PQ_MASP_BASE_WIDTH_V1,
                    PQ_MASP_BASE_WIDTH_V1,
                    NOTE_COPY_AUX_WIDTH_V1 + PQ_MASP_PROFILE_AUX_WIDTH_V1,
                    NOTE_COPY_AUX_WIDTH_V1 + PQ_MASP_PROFILE_AUX_WIDTH_V1,
                    NOTE_COPY_FIXED_WIDTH_V1 + PQ_MASP_PROFILE_FIXED_WIDTH_V1,
                ],
                21,
                PQ_MASP_PROFILE_CONSTRAINT_DEGREE_V1,
                pq_masp_profile_constraint_residues_inner_v1,
            );
        assert_eq!(
            measured,
            usize::from(PQ_MASP_PROFILE_CONSTRAINT_DEGREE_V1),
            "the PQ-MASP AIR's declared maximum degree must be exact"
        );
    }
    #[test]
    fn authorization_key_mismatch_fails_before_rng_consumption() {
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xB6; 32]),
            b"pq-masp-full-facade-v1",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("authorization key digest");
        let (statement, witness) = valid_fixture_with_authorization_key_digest(key_digest);
        let (binding, limits) = consensus_material(&statement);
        let wrong_authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xB8; 32]),
            b"pq-masp-wrong-facade-key-v1",
        )
        .expect("wrong ML-DSA authorization key");
        let mut untouched_rng = StdRng::from_seed([0xB9; 32]);
        let mut expected_rng = StdRng::from_seed([0xB9; 32]);
        assert_eq!(
            super::super::prove_pq_masp_v1_with_rng(
                &statement,
                &binding,
                &limits,
                &witness,
                wrong_authorization_keys.secret_key(),
                &mut untouched_rng,
            ),
            Err(super::super::PqMaspProofErrorV1::Authorization(
                PqMaspWireErrorV1::AuthorizationKeyMismatch,
            ))
        );
        assert_eq!(
            untouched_rng.next_u64(),
            expected_rng.next_u64(),
            "invalid authorization keys must fail before entropy is consumed"
        );
    }
    #[test]
    #[ignore = "release gate: generates and verifies the full-domain PQ-MASP proof"]
    fn full_domain_authorized_facade_roundtrip_and_adversarial_wires_fail_closed() {
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xB6; 32]),
            b"pq-masp-full-facade-v1",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("authorization key digest");
        let (statement, witness) = valid_fixture_with_authorization_key_digest(key_digest);
        let (binding, limits) = consensus_material(&statement);
        let (other_genesis_statement, matched_other_genesis) =
            other_genesis_consensus_material(&statement, &limits);
        let mut rng = StdRng::from_seed([0xB7; 32]);
        let authorized_proof = super::super::prove_pq_masp_v1_with_rng(
            &statement,
            &binding,
            &limits,
            &witness,
            authorization_keys.secret_key(),
            &mut rng,
        )
        .expect("full-domain authorized PQ-MASP facade proof");
        let decoded = decode_pq_masp_authorization_proof_v1(&authorized_proof)
            .expect("canonical authorization wrapper");
        let proof = decoded.stark_proof.to_vec();
        assert!(!proof.is_empty());
        assert!(proof.len() <= super::super::wire::PQ_MASP_MAX_STARK_PROOF_BYTES_V1);
        let proof_digest = privacy_outer_digest_frame_v1(
            PQ_MASP_DOMAINS_V1.digest_context,
            b"pq-masp-stark-kat-proof-v1",
            b"inner-proof",
            0,
            0,
            0,
            &[&proof],
        )
        .expect("inner proof digest");
        let authorized_proof_digest = privacy_outer_digest_frame_v1(
            PQ_MASP_DOMAINS_V1.digest_context,
            b"pq-masp-stark-kat-proof-v1",
            b"authorized-proof",
            0,
            0,
            0,
            &[&authorized_proof],
        )
        .expect("authorized proof digest");
        assert_ne!(proof_digest, authorized_proof_digest);
        super::super::verify_pq_masp_v1(&statement, &binding, &limits, &authorized_proof)
            .expect("full-domain PQ-MASP facade verification");
        verify_pq_masp_stark_v1(&statement, &binding, &limits, &proof)
            .expect("full-domain PQ-MASP verification");
        assert!(
            verify_pq_masp_stark_v1(&statement, &binding, &limits, &vec![0; proof.len()],).is_err(),
            "same-length all-zero inner proof wire was accepted"
        );
        assert!(
            verify_pq_masp_stark_v1(
                &statement,
                &binding,
                &limits,
                &vec![0; PQ_MASP_PARAMETERS_V1.maximum_proof_bytes + 1],
            )
            .is_err(),
            "oversized inner proof wire was accepted"
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
                verify_pq_masp_stark_v1(&statement, &binding, &limits, &wire).is_err(),
                "malformed inner proof wire was accepted"
            );
        }
        let mut changed_statement = statement.clone();
        let mut nullifier = *changed_statement.nullifiers[0].as_bytes();
        nullifier[0] ^= 1;
        changed_statement.nullifiers[0] =
            iroha_data_model::privacy::PrivacyNullifierV1::new(nullifier);
        assert!(
            verify_pq_masp_stark_v1(&changed_statement, &binding, &limits, &proof).is_err(),
            "proof was replayed under a substituted public statement"
        );
        for offset in [0, 8, authorized_proof.len() / 2, authorized_proof.len() - 1] {
            let mut tampered = authorized_proof.clone();
            tampered[offset] ^= 1;
            assert!(
                super::super::verify_pq_masp_v1(&statement, &binding, &limits, &tampered,).is_err(),
                "tampered complete PQ-MASP proof byte {offset} was accepted"
            );
        }
        let mut wrong_key_statement = statement.clone();
        wrong_key_statement.authorization_key_digest =
            iroha_data_model::privacy::PrivacyAuthorizationKeyDigestV1::new([0xD1; 32]);
        assert_eq!(
            super::super::verify_pq_masp_v1(
                &wrong_key_statement,
                &binding,
                &limits,
                &authorized_proof,
            ),
            Err(super::super::PqMaspProofErrorV1::Authorization(
                PqMaspWireErrorV1::AuthorizationKeyMismatch,
            ))
        );
        assert!(
            super::super::verify_pq_masp_v1(
                &statement,
                &binding,
                &limits,
                &vec![0; super::super::wire::PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1 + 1],
            )
            .is_err()
        );
        let mut context_substitutions = Vec::new();
        macro_rules! push_context_substitution {
            ($axis:literal, $field:ident, $value:expr) => {{
                let mut substituted_statement = statement.clone();
                substituted_statement.context.$field = $value;
                let mut substituted_binding = binding.clone();
                substituted_binding.$field = substituted_statement.context.$field.clone();
                context_substitutions.push(($axis, substituted_statement, substituted_binding));
            }};
        }
        let mut substituted_network_statement = statement.clone();
        substituted_network_statement.context.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xC3; 32]),
            ));
        let mut substituted_network_binding = binding;
        substituted_network_binding.network_id = substituted_network_statement.context.network_id;
        substituted_network_binding.genesis_hash = [0xC3; 32];
        context_substitutions.push((
            "network_id",
            substituted_network_statement,
            substituted_network_binding,
        ));
        push_context_substitution!(
            "transaction_intent_digest",
            transaction_intent_digest,
            iroha_data_model::privacy::PrivacyTransactionIntentDigestV1::new([0xD2; 32])
        );
        push_context_substitution!(
            "parameter_id",
            parameter_id,
            iroha_data_model::privacy::PrivacyParameterIdV1::new([0xD3; 32])
        );
        push_context_substitution!(
            "parameter_digest",
            parameter_digest,
            iroha_data_model::privacy::PrivacyParameterDigestV1::new([0xD4; 32])
        );
        push_context_substitution!(
            "verifier_digest",
            verifier_digest,
            iroha_data_model::privacy::PrivacyVerifierDigestV1::new([0xD5; 32])
        );
        push_context_substitution!(
            "statement_schema_digest",
            statement_schema_digest,
            iroha_data_model::privacy::PrivacyStatementSchemaDigestV1::new([0xD6; 32])
        );
        push_context_substitution!(
            "engine_manifest_digest",
            engine_manifest_digest,
            iroha_data_model::privacy::PrivacyEngineManifestDigestV1::new([0xD7; 32])
        );
        for (axis, substituted_statement, substituted_binding) in context_substitutions {
            assert_eq!(
                super::super::verify_pq_masp_v1(
                    &substituted_statement,
                    &substituted_binding,
                    &limits,
                    &authorized_proof,
                ),
                Err(super::super::PqMaspProofErrorV1::Authorization(
                    PqMaspWireErrorV1::AuthorizationFailed,
                )),
                "matched statement/binding substitution on {axis} was accepted"
            );
        }
        let mut substituted_action_statement = statement.clone();
        substituted_action_statement.context.action_index = statement.context.action_index + 1;
        let mut substituted_action_binding = binding;
        substituted_action_binding.action_index = substituted_action_statement.context.action_index;
        assert_eq!(
            super::super::verify_pq_masp_v1(
                &substituted_action_statement,
                &substituted_action_binding,
                &limits,
                &authorized_proof,
            ),
            Err(super::super::PqMaspProofErrorV1::ConsensusBinding(
                iroha_data_model::privacy::PrivacyNativeConsensusBindingValidationErrorV1::InvalidContext(
                    iroha_data_model::privacy::PrivacyStatementValidationError::ActionIndexOutOfBounds {
                        index: substituted_action_statement.context.action_index,
                        max_actions: limits.max_actions_per_transaction,
                    },
                ),
            )),
            "the only alternate first-release action index escaped its hard ceiling"
        );
        let mut other_genesis = binding;
        other_genesis.genesis_hash[0] ^= 1;
        assert!(
            other_genesis.genesis_hash.iter().any(|byte| *byte != 0),
            "adversarial genesis must remain intrinsically valid"
        );
        assert_eq!(
            super::super::verify_pq_masp_v1(&statement, &other_genesis, &limits, &authorized_proof,),
            Err(super::super::PqMaspProofErrorV1::ConsensusBinding(
                iroha_data_model::privacy::PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch,
            )),
            "an inconsistent network/genesis binding reached proof verification"
        );
        let statement_digest = iroha_data_model::privacy::PrivacyStatementV1::PqMaspStarkV1(
            other_genesis_statement.clone(),
        )
        .digest()
        .expect("canonical alternate-genesis PQ-MASP statement digest");
        let other_genesis_digest = matched_other_genesis
            .digest()
            .expect("canonical matched changed-genesis binding digest");
        let resigned_outer = authorize_pq_masp_stark_proof_v1(
            statement_digest,
            other_genesis_digest,
            key_digest,
            authorization_keys.secret_key(),
            &proof,
            HedgedRngSeed::from_entropy([0xDA; 32]),
        )
        .expect("fresh changed-genesis outer authorization");
        let resigned_authorization = verify_pq_masp_authorization_v1(
            statement_digest,
            other_genesis_digest,
            key_digest,
            &resigned_outer,
        )
        .expect("freshly re-signed outer proof is independently valid");
        assert_eq!(resigned_authorization.stark_proof, proof.as_slice());
        assert_eq!(
            super::super::verify_pq_masp_v1(
                &other_genesis_statement,
                &matched_other_genesis,
                &limits,
                &resigned_outer,
            ),
            Err(super::super::PqMaspProofErrorV1::InvalidProof),
            "fresh outer authorization rescued an inner proof from another genesis"
        );
    }
    #[test]
    fn every_native_row_satisfies_copy_and_profile_residues() {
        let (statement, witness) = valid_fixture();
        let (_trace, base, aux, fixed, copy_challenges) =
            prepared_columns(&statement, &witness, b"pq-masp-residue-test-v1");
        for index in 0..PQ_MASP_TRACE_SIZE_V1 {
            let next = (index + 1) % PQ_MASP_TRACE_SIZE_V1;
            let copy_residues = note_copy_constraint_residues_v1(
                &row(&base, index),
                &row(&aux, index),
                &row(&aux, next),
                &row(&fixed, index),
                copy_challenges,
            )
            .expect("copy residue shape");
            assert!(
                copy_residues.iter().all(|residue| *residue == F::ZERO),
                "row {index} has nonzero copy residue at {:?}",
                copy_residues.iter().position(|residue| *residue != F::ZERO)
            );
            let residues = pq_masp_profile_constraint_residues_inner_v1(
                &row(&base, index),
                &row(&base, next),
                &row(&aux, index),
                &row(&aux, next),
                &row(&fixed, index),
            )
            .expect("profile residue shape");
            assert_eq!(residues.len(), PQ_MASP_PROFILE_CONSTRAINT_COUNT_V1);
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "row {index} has nonzero profile residue at {:?}",
                residues.iter().position(|residue| *residue != F::ZERO)
            );
        }
    }
    #[test]
    fn hostile_prover_cannot_substitute_public_nullifier_after_rebuilding_aux() {
        let (statement, witness) = valid_fixture();
        let trace = super::super::air::build_pq_masp_base_trace_v1(&statement, &witness)
            .expect("honest trace");
        let base = pq_masp_base_columns_v1(&trace).expect("honest base columns");
        let honest_nullifier = statement.nullifiers[0];
        let public_row = trace
            .fixed
            .rows
            .iter()
            .enumerate()
            .find_map(|(row, fixed)| match fixed {
                PqMaspFixedRowV1::ShaEnd {
                    digest_chunk: 0,
                    public_digest: Some(digest),
                    ..
                } if digest == honest_nullifier.as_bytes() => Some(row),
                _ => None,
            })
            .expect("public nullifier endpoint");
        let mut target = statement.clone();
        let mut substituted = *honest_nullifier.as_bytes();
        substituted[0] ^= 1;
        target.nullifiers[0] = iroha_data_model::privacy::PrivacyNullifierV1::new(substituted);
        let (binding, limits) = consensus_material(&target);
        let adapter = PqMaspStarkAdapterV1::new(&target, &binding, &limits);
        let copy_schedule = adapter.copy_schedule_v1().expect("target copy schedule");
        let mut fixed = copy_schedule
            .fixed_columns_v1(PQ_MASP_TRACE_SIZE_V1)
            .expect("target copy fixed");
        fixed.extend(pq_masp_profile_fixed_columns_v1(&target).expect("target profile fixed"));
        let mut transcript = TransparentTranscriptV1::new(
            PQ_MASP_DOMAINS_V1.digest_context,
            b"pq-masp-hostile-prover-v1",
            &PrivacyOuterDigestV1::from_bytes([5; 48]),
            &PrivacyOuterDigestV1::from_bytes([6; 48]),
        )
        .expect("transcript");
        let copy_challenges =
            derive_note_copy_challenges_v1(&mut transcript).expect("copy challenges");
        let mut aux =
            build_note_copy_aux_columns_v1(&base, &fixed, copy_challenges, PQ_MASP_TRACE_SIZE_V1)
                .expect("hostile prover rebuilds copy auxiliary columns");
        aux.extend(
            pq_masp_profile_aux_columns_v1(&target, &base)
                .expect("hostile prover rebuilds profile auxiliary columns"),
        );
        let next = (public_row + 1) % PQ_MASP_TRACE_SIZE_V1;
        let copy_residues = note_copy_constraint_residues_v1(
            &row(&base, public_row),
            &row(&aux, public_row),
            &row(&aux, next),
            &row(&fixed, public_row),
            copy_challenges,
        )
        .expect("copy residue shape");
        assert!(
            copy_residues.iter().all(|residue| *residue == F::ZERO),
            "hostile trace remains copy-consistent"
        );
        let profile_residues = pq_masp_profile_constraint_residues_inner_v1(
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
            "only the verifier-fixed public byte binding rejects this rebuilt trace"
        );
    }
    #[test]
    fn hostile_prover_cannot_substitute_fixed_or_inactive_copy_bytes_after_rebuilding_aux() {
        let (statement, witness) = valid_fixture();
        let trace = super::super::air::build_pq_masp_base_trace_v1(&statement, &witness)
            .expect("honest trace");
        let honest_base = pq_masp_base_columns_v1(&trace).expect("honest base columns");
        let (binding, limits) = consensus_material(&statement);
        let adapter = PqMaspStarkAdapterV1::new(&statement, &binding, &limits);
        let schedule = adapter.copy_schedule_v1().expect("copy schedule");
        let mut fixed = schedule
            .fixed_columns_v1(PQ_MASP_TRACE_SIZE_V1)
            .expect("copy fixed");
        fixed.extend(pq_masp_profile_fixed_columns_v1(&statement).expect("profile fixed"));
        let mut transcript = TransparentTranscriptV1::new(
            PQ_MASP_DOMAINS_V1.digest_context,
            b"pq-masp-fixed-copy-hostile-v1",
            &PrivacyOuterDigestV1::from_bytes([7; 48]),
            &PrivacyOuterDigestV1::from_bytes([8; 48]),
        )
        .expect("transcript");
        let challenges = derive_note_copy_challenges_v1(&mut transcript).expect("copy challenges");
        for policy_kind in [0_u8, 1] {
            let (mutated_row, cell, replacement) = schedule
                .policies
                .iter()
                .enumerate()
                .find_map(|(row, policies)| {
                    policies
                        .iter()
                        .copied()
                        .enumerate()
                        .find_map(|(cell, policy)| match (policy_kind, policy) {
                            (0, NoteCopyCellPolicyV1::Constant(value)) => {
                                Some((row, cell, value ^ 1))
                            }
                            (1, NoteCopyCellPolicyV1::Inactive) => Some((row, cell, 1)),
                            _ => None,
                        })
                })
                .expect("requested fixed policy exists");
            let mut base = honest_base.clone();
            base[COPY_OFFSET + cell][mutated_row] = F(u64::from(replacement));
            let mut aux =
                build_note_copy_aux_columns_v1(&base, &fixed, challenges, PQ_MASP_TRACE_SIZE_V1)
                    .expect("hostile prover rebuilds copy auxiliary columns");
            aux.extend(
                pq_masp_profile_aux_columns_v1(&statement, &base)
                    .expect("hostile prover rebuilds profile auxiliary columns"),
            );
            let next = (mutated_row + 1) % PQ_MASP_TRACE_SIZE_V1;
            let residues = note_copy_constraint_residues_v1(
                &row(&base, mutated_row),
                &row(&aux, mutated_row),
                &row(&aux, next),
                &row(&fixed, mutated_row),
                challenges,
            )
            .expect("copy residue shape");
            assert!(
                residues.iter().any(|residue| *residue != F::ZERO),
                "fixed policy {policy_kind} accepted a rebuilt hostile trace"
            );
        }
    }
    fn profile_mutation_is_detected(
        base: &[Vec<F>],
        aux: &[Vec<F>],
        fixed: &[Vec<F>],
        mutated_row: usize,
    ) -> bool {
        let previous = (mutated_row + PQ_MASP_TRACE_SIZE_V1 - 1) % PQ_MASP_TRACE_SIZE_V1;
        [previous, mutated_row].into_iter().any(|index| {
            let next = (index + 1) % PQ_MASP_TRACE_SIZE_V1;
            pq_masp_profile_constraint_residues_inner_v1(
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
    #[test]
    fn adversarial_mutations_are_rejected_across_every_active_constraint_family() {
        let (statement, witness) = valid_fixture();
        let (trace, mut base, mut aux, fixed, copy_challenges) =
            prepared_columns(&statement, &witness, b"pq-masp-mutation-test-v1");
        let row_types = trace.fixed.rows;
        let row_index = |predicate: &dyn Fn(&PqMaspFixedRowV1) -> bool| {
            row_types
                .iter()
                .position(predicate)
                .expect("canonical row family")
        };
        let mutations = [
            (
                row_index(&|row| matches!(row, PqMaspFixedRowV1::ShaRound { round: 16, .. })),
                SHA_SCHEDULE_OFFSET + 16,
                "SHA schedule",
            ),
            (
                row_index(&|row| {
                    matches!(
                        row,
                        PqMaspFixedRowV1::ShaEnd {
                            digest_chunk: 0,
                            ..
                        }
                    )
                }),
                SHA_STATE_OFFSET,
                "SHA endpoint",
            ),
            (
                row_index(&|row| matches!(row, PqMaspFixedRowV1::NodeSelect { .. })),
                COPY_OFFSET + 2,
                "Merkle direction selection",
            ),
            (
                row_index(&|row| matches!(row, PqMaspFixedRowV1::Distinct { .. })),
                SCRATCH_RUNNING_AFTER,
                "distinctness",
            ),
            (
                row_index(&|row| matches!(row, PqMaspFixedRowV1::NonZero { .. })),
                SCRATCH_RUNNING_BEFORE,
                "nonzero component",
            ),
            (
                row_index(&|row| {
                    matches!(
                        row,
                        PqMaspFixedRowV1::Sum {
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
                    matches!(
                        row,
                        PqMaspFixedRowV1::Sum {
                            side: SumSideV1::Conservation,
                            ..
                        }
                    )
                }),
                SCRATCH_RELATION_CARRY_AFTER,
                "value conservation",
            ),
            (
                row_index(&|row| matches!(row, PqMaspFixedRowV1::Padding)),
                SCRATCH_RUNNING_BEFORE,
                "padding zeroization",
            ),
        ];
        for (mutated_row, column, family) in mutations {
            let original = base[column][mutated_row];
            base[column][mutated_row] = original.add(F::ONE);
            assert!(
                profile_mutation_is_detected(&base, &aux, &fixed, mutated_row),
                "{family} mutation was accepted"
            );
            base[column][mutated_row] = original;
        }
        let profile_aux_column = NOTE_COPY_AUX_WIDTH_V1 + PROFILE_AUX_VM_CARRY_BRIDGE;
        let padding = row_index(&|row| matches!(row, PqMaspFixedRowV1::Padding));
        aux[profile_aux_column][padding] = F::ONE;
        assert!(
            profile_mutation_is_detected(&base, &aux, &fixed, padding),
            "reserved profile auxiliary mutation was accepted"
        );
        aux[profile_aux_column][padding] = F::ZERO;
        let copy_row = row_index(&|row| matches!(row, PqMaspFixedRowV1::NodeSelect { .. }));
        base[COPY_OFFSET][copy_row] = base[COPY_OFFSET][copy_row].add(F::ONE);
        let next = (copy_row + 1) % PQ_MASP_TRACE_SIZE_V1;
        let copy_residues = note_copy_constraint_residues_v1(
            &row(&base, copy_row),
            &row(&aux, copy_row),
            &row(&aux, next),
            &row(&fixed, copy_row),
            copy_challenges,
        )
        .expect("copy residue shape");
        assert!(
            copy_residues.iter().any(|residue| *residue != F::ZERO),
            "copy-permutation mutation was accepted"
        );
    }
    #[test]
    fn maximum_two_by_two_topology_fits_and_satisfies_the_full_domain() {
        let (statement, witness) = valid_two_by_two_fixture();
        let (trace, base, aux, fixed, _copy_challenges) =
            prepared_columns(&statement, &witness, b"pq-masp-max-topology-test-v1");
        assert_eq!(trace.rows.len(), PQ_MASP_TRACE_SIZE_V1);
        let active_rows = trace
            .fixed
            .rows
            .iter()
            .take_while(|row| !matches!(row, PqMaspFixedRowV1::Padding))
            .count();
        assert!(active_rows < PQ_MASP_TRACE_SIZE_V1);
        for index in 0..PQ_MASP_TRACE_SIZE_V1 {
            let next = (index + 1) % PQ_MASP_TRACE_SIZE_V1;
            let residues = pq_masp_profile_constraint_residues_inner_v1(
                &row(&base, index),
                &row(&base, next),
                &row(&aux, index),
                &row(&aux, next),
                &row(&fixed, index),
            )
            .expect("profile residue shape");
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "maximum topology row {index} has nonzero residue at {:?}",
                residues.iter().position(|residue| *residue != F::ZERO)
            );
        }
    }
}
