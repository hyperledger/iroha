//! Standalone source-bound Touring STARK proof, with no ledger/profile registration.
//!
//! The verifier evaluates the complete compiled AIR over the shared native DEEP-ALI/FRI
//! substrate. It reconstructs public columns and checks terminal result projection, but
//! never executes driving physics. Callers must authenticate the expected statement.

use super::super::stark::{
    aggregate_stark::{AggregateStarkDomainsV1, AggregateStarkParametersV1},
    proof_managed_note_stark::{
        NOTE_COPY_AUX_WIDTH_V1, NOTE_COPY_FIXED_WIDTH_V1, NOTE_COPY_WIDTH_V1, NoteCopyCellPolicyV1,
        NoteCopyChallengesV1, NoteCopyScheduleV1, PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
        ProofManagedNoteStarkAdapterV1, ProofManagedNoteStarkErrorV1,
        ProofManagedNoteStarkProtocolV1, prove_proof_managed_note_stark_v1,
        verify_proof_managed_note_stark_v1,
    },
    transparent_stark::{
        GoldilocksDigest384V1, GoldilocksFieldV1 as F, TransparentStarkDigestContextV1,
        TransparentTranscriptV1, goldilocks_digest384_frame_v1,
    },
};
use super::super::{error::ExecutionProofErrorV1, integer_air::field};
use super::{
    admission::{decode_exact, validate_payload},
    reference::{classed_race_result_v1, initial_classed_race_state_v1, replay_classed_race_v1},
    staged_race_air::StagedClassedRaceAirV1,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    classed_race_v1::{ClassedRaceReplayV1, ClassedRaceResultV1, ClassedRaceStateV1},
    execution_proofs::{
        EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1, ExecutionProofEnvelopeV1, ExecutionPublicInputsV1,
    },
    game::{GameAdmissionBodyV1, GameManifestV1},
};
use norito::codec::{Decode, Encode};

/// Canonical complete envelope bound; independent transport/ledger limits still apply.
pub const CLASSED_RACE_MAX_PROOF_BYTES_V1: usize = EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1;
/// Standalone cryptographic wire cap; all geometries are checked against the native wire bound.
pub const CLASSED_RACE_MAX_STARK_BYTES_V1: usize = 3_500_000;
const MIN_TRACE_LOG2: u8 = 13;
const MAX_TRACE_LOG2: u8 = 19;
const MAX_AIR_COLUMNS: usize = 409;
// Parameter selection is explicitly unqualified. These numbers alone are not a soundness claim.
const PROFILE: &[u8] = b"sora-cars:TouringS1:standalone:v1:wire=CLS1/1:Goldilocks-Fp4:Poseidon-x7-Goldilocks-six-independent-lanes-6x64:degree4:base-max417:aux118:trace13..19:query136:blowup3:terminal10/143:composition4:public-replay:generic-game-transcript:retained-native-history:exact-checkpoints-anchors-forced-inputs-epochs-dnf:producer-finish-range-schedule:terminal-only:one-required-kit-per-slot:no-registration:no-security-qualification";
const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"classed-touring-s1-proof-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"execution-classed-touring-s1-base-leaf-v1",
    base_node: b"execution-classed-touring-s1-base-node-v1",
    aux_leaf: b"execution-classed-touring-s1-aux-leaf-v1",
    aux_node: b"execution-classed-touring-s1-aux-node-v1",
    composition_leaf: b"execution-classed-touring-s1-composition-leaf-v1",
    composition_node: b"execution-classed-touring-s1-composition-node-v1",
    fri_leaf: b"execution-classed-touring-s1-fri-leaf-v1",
    fri_node: b"execution-classed-touring-s1-fri-node-v1",
    layout_label: b"execution-classed-touring-s1-layout-v1",
    base_root_label: b"execution-classed-touring-s1-base-root-v1",
    aux_root_label: b"execution-classed-touring-s1-aux-root-v1",
    composition_root_label: b"execution-classed-touring-s1-composition-root-v1",
    fri_root_label: b"execution-classed-touring-s1-fri-root-v1",
    fri_beta_label: b"execution-classed-touring-s1-fri-beta-v1",
    query_seed: b"execution-classed-touring-s1-query-seed-v1",
};

/// Exact production source inventory committed by this isolated verifier identity.
/// Dedicated test files, exports and the parent registry are excluded; no stock identity is reused.
pub(super) const CLASSED_RACE_PROFILE_SOURCES_V1: &[(&str, &[u8])] = &[
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/history.rs",
        include_bytes!("history.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/admission.rs",
        include_bytes!("admission.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/proof.rs",
        include_bytes!("proof.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/reference.rs",
        include_bytes!("reference.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/rules.rs",
        include_bytes!("rules.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/environment.rs",
        include_bytes!("environment.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/environment_air.rs",
        include_bytes!("environment_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/race_air.rs",
        include_bytes!("race_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/classed_race_v1/staged_race_air.rs",
        include_bytes!("staged_race_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/integer_air.rs",
        include_bytes!("../integer_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/checked_integer_air.rs",
        include_bytes!("../checked_integer_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/mod.rs",
        include_bytes!("../stark/mod.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/transparent_stark.rs",
        include_bytes!("../stark/transparent_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/aggregate_stark.rs",
        include_bytes!("../stark/aggregate_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/proof_managed_note_stark.rs",
        include_bytes!("../stark/proof_managed_note_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/proof_managed_note_stark_execution_fixed.rs",
        include_bytes!("../stark/proof_managed_note_stark_execution_fixed.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/privacy_engines/transparent_stark.rs",
        include_bytes!("../../privacy_engines/transparent_stark.rs"),
    ),
    (
        "crates/iroha_data_model/src/classed_race_v1.rs",
        include_bytes!("../../../../iroha_data_model/src/classed_race_v1.rs"),
    ),
    (
        "crates/iroha_data_model/src/game.rs",
        include_bytes!("../../../../iroha_data_model/src/game.rs"),
    ),
    (
        "crates/iroha_data_model/src/game_resources.rs",
        include_bytes!("../../../../iroha_data_model/src/game_resources.rs"),
    ),
    (
        "crates/iroha_data_model/src/execution_proofs.rs",
        include_bytes!("../../../../iroha_data_model/src/execution_proofs.rs"),
    ),
    (
        "crates/fastpq_isi/src/lib.rs",
        include_bytes!("../../../../fastpq_isi/src/lib.rs"),
    ),
    (
        "crates/fastpq_isi/src/params.rs",
        include_bytes!("../../../../fastpq_isi/src/params.rs"),
    ),
    (
        "crates/fastpq_isi/src/poseidon.rs",
        include_bytes!("../../../../fastpq_isi/src/poseidon.rs"),
    ),
    (
        "crates/fastpq_isi/src/poseidon_digest384.rs",
        include_bytes!("../../../../fastpq_isi/src/poseidon_digest384.rs"),
    ),
    (
        "crates/fastpq_isi/src/assets/poseidon_goldilocks_width3_v1.bin",
        include_bytes!("../../../../fastpq_isi/src/assets/poseidon_goldilocks_width3_v1.bin"),
    ),
];

/// Exact compiled source identity; this is not a registered or qualified profile descriptor.
#[must_use]
pub fn classed_race_profile_id_v1() -> Hash {
    static ID: std::sync::OnceLock<Hash> = std::sync::OnceLock::new();
    *ID.get_or_init(|| {
        let mut chunks: Vec<&[u8]> = vec![
            b"iroha:execution:classed-profile:v1\0",
            PROFILE,
            PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
        ];
        for (path, bytes) in CLASSED_RACE_PROFILE_SOURCES_V1 {
            chunks.push(path.as_bytes());
            chunks.push(bytes);
        }
        Hash::new_from_chunks(&chunks)
    })
}

/// Portable public inputs to a self-hosted worker. Contains no custody signing keys.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::execution_proofs::classed_race_v1::proof::ClassedRaceProverRequestV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub struct ClassedRaceProverRequestV1 {
    /// Exact consensus-authenticated session claim, supplied independently by the caller.
    pub statement: ExecutionPublicInputsV1,
    /// Frozen class, track, rules, NFT catalog and session terms.
    pub manifest: GameManifestV1,
    /// Exact original wallets, input keys, wagers and returnable equipment.
    pub admission: GameAdmissionBodyV1,
    /// Complete public controls and consensus-selected removals.
    pub replay: ClassedRaceReplayV1,
    /// Optional retained checkpoint, additionally constrained by the arithmetic proof.
    pub checkpoint_state: Option<ClassedRaceStateV1>,
}

/// Complete canonical application payload inside the generic execution envelope.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::execution_proofs::classed_race_v1::proof::ClassedRaceProofPayloadV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub struct ClassedRaceProofPayloadV1 {
    /// Exact frozen manifest.
    pub manifest: GameManifestV1,
    /// Exact bounded immutable admission facts.
    pub admission: GameAdmissionBodyV1,
    /// Public replay retained for independent availability.
    pub replay: ClassedRaceReplayV1,
    /// Claimed terminal state; every field is constrained by the final AIR boundary.
    pub final_state: ClassedRaceStateV1,
    /// Optional intermediate AIR boundary.
    pub checkpoint_state: Option<ClassedRaceStateV1>,
    /// Complete canonical terminal ranking, derived only from the proven final state.
    pub result: ClassedRaceResultV1,
    /// Native cryptographic wire, without alternate proof or recomputation modes.
    pub stark_bytes: Vec<u8>,
}

fn payload_from_request(
    request: &ClassedRaceProverRequestV1,
) -> Result<ClassedRaceProofPayloadV1, ExecutionProofErrorV1> {
    // Cheap cardinality/encoding validation precedes reference simulation and trace allocation.
    super::admission::validate_manifest(&request.manifest)?;
    request
        .admission
        .validate()
        .map_err(|_| ExecutionProofErrorV1::Statement)?;
    if request.replay.frames.len() > 5400
        || !(2..=8).contains(&request.replay.player_count)
        || request
            .replay
            .frames
            .iter()
            .any(|frame| frame.controls.len() != usize::from(request.replay.player_count))
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    let final_state =
        replay_classed_race_v1(&request.replay).map_err(|_| ExecutionProofErrorV1::Replay)?;
    let result = classed_race_result_v1(&final_state).map_err(|_| ExecutionProofErrorV1::Replay)?;
    let payload = ClassedRaceProofPayloadV1 {
        manifest: request.manifest.clone(),
        admission: request.admission.clone(),
        replay: request.replay.clone(),
        final_state,
        checkpoint_state: request.checkpoint_state.clone(),
        result,
        stark_bytes: vec![],
    };
    validate_payload(&request.statement, &payload)?;
    Ok(payload)
}
struct ClassedRaceAdapterV1<'a> {
    statement: &'a ExecutionPublicInputsV1,
    payload: &'a ClassedRaceProofPayloadV1,
    compiled: StagedClassedRaceAirV1,
}
impl<'a> ClassedRaceAdapterV1<'a> {
    fn new(
        statement: &'a ExecutionPublicInputsV1,
        payload: &'a ClassedRaceProofPayloadV1,
    ) -> Result<Self, ExecutionProofErrorV1> {
        validate_payload(statement, payload)?;
        let compiled = StagedClassedRaceAirV1::compile(
            &payload.replay,
            &payload.final_state,
            payload.checkpoint_state.as_ref(),
        )
        .map_err(|_| ExecutionProofErrorV1::Replay)?;
        if compiled.width() > MAX_AIR_COLUMNS {
            return Err(ExecutionProofErrorV1::Envelope);
        }
        Ok(Self {
            statement,
            payload,
            compiled,
        })
    }
}
impl ProofManagedNoteStarkAdapterV1 for ClassedRaceAdapterV1<'_> {
    type ProfileChallenges = ();
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"CLS1",
                proof_version: 1,
                security_lanes: 1,
                query_count: 136,
                blowup_log2: 3,
                terminal_log2: 10,
                terminal_degree_bound: 143,
                composition_degree_chunks: 4,
                minimum_trace_log2: MIN_TRACE_LOG2,
                maximum_trace_log2: MAX_TRACE_LOG2,
                maximum_trace_groups: 1,
                maximum_segment_instances: 1,
                maximum_base_columns_per_instance: MAX_AIR_COLUMNS + NOTE_COPY_WIDTH_V1,
                maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1,
                maximum_proof_bytes: CLASSED_RACE_MAX_STARK_BYTES_V1,
            },
            domains: DOMAINS,
            maximum_constraint_degree: 4,
            profile_binding_label: b"execution-classed-touring-s1-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"execution-classed-touring-s1-relation-layout-v1",
        }
    }
    fn public_input_digest_v1(
        &self,
    ) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"execution-classed-touring-s1-public-statement-v1",
            b"statement",
            0,
            0,
            0,
            &[
                classed_race_profile_id_v1().as_ref(),
                &self.statement.encode(),
                &self.payload.manifest.encode(),
                &self.payload.admission.encode(),
                &self.payload.replay.encode(),
                &initial_classed_race_state_v1(
                    self.payload.replay.class_id,
                    self.payload.replay.track,
                    self.payload.replay.player_count,
                )
                .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?
                .encode(),
                &self.payload.final_state.encode(),
                &self.payload.checkpoint_state.encode(),
                &self.payload.result.encode(),
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)
    }
    fn trace_log2_v1(&self) -> u8 {
        self.compiled.trace_size().ilog2() as u8
    }
    fn base_width_v1(&self) -> usize {
        NOTE_COPY_WIDTH_V1 + self.compiled.width()
    }
    fn profile_aux_width_v1(&self) -> usize {
        0
    }
    fn profile_fixed_width_v1(&self) -> usize {
        self.compiled.fixed_width()
    }
    fn profile_constraint_count_v1(&self) -> usize {
        self.compiled.constraint_count()
    }
    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        Ok(NoteCopyScheduleV1 {
            policies: vec![
                [NoteCopyCellPolicyV1::Inactive; NOTE_COPY_WIDTH_V1];
                self.compiled.trace_size()
            ],
            sigma: (0..self.compiled.trace_size())
                .map(|row| {
                    std::array::from_fn(|column| (row * NOTE_COPY_WIDTH_V1 + column + 1) as u32)
                })
                .collect(),
        })
    }
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        let mut columns =
            vec![Vec::with_capacity(self.compiled.trace_size()); self.profile_fixed_width_v1()];
        for row in 0..self.compiled.trace_size() {
            for (column, value) in columns.iter_mut().zip(
                self.compiled
                    .fixed_row(row, self.compiled.trace_size())
                    .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?,
            ) {
                column.push(field(value));
            }
        }
        Ok(columns)
    }
    fn derive_profile_challenges_v1(
        &self,
        _: &mut TransparentTranscriptV1,
        _: NoteCopyChallengesV1,
    ) -> Result<(), ProofManagedNoteStarkErrorV1> {
        Ok(())
    }
    fn build_profile_aux_columns_v1(
        &self,
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: NoteCopyChallengesV1,
        (): &(),
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        Ok(vec![])
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
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
        if current.len() != self.base_width_v1()
            || next.len() != self.base_width_v1()
            || fixed.len() != NOTE_COPY_FIXED_WIDTH_V1 + self.profile_fixed_width_v1()
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
        }
        Ok(self.compiled.residues(
            &current[NOTE_COPY_WIDTH_V1..],
            &next[NOTE_COPY_WIDTH_V1..],
            &fixed[NOTE_COPY_FIXED_WIDTH_V1..],
        ))
    }
}

fn witness_columns(
    adapter: &ClassedRaceAdapterV1<'_>,
) -> Result<Vec<Vec<F>>, ExecutionProofErrorV1> {
    let size = adapter.compiled.trace_size();
    let mut carry = adapter.compiled.initial_carry();
    let mut columns = vec![Vec::with_capacity(size); adapter.base_width_v1()];
    for row_index in 0..size {
        let fixed = adapter
            .compiled
            .fixed_row(row_index, size)
            .map_err(|_| ExecutionProofErrorV1::Replay)?;
        let (row, next) = adapter.compiled.witness(&carry, &fixed);
        carry = next;
        for column in &mut columns[..NOTE_COPY_WIDTH_V1] {
            column.push(F::ZERO);
        }
        for (column, value) in columns[NOTE_COPY_WIDTH_V1..].iter_mut().zip(row) {
            column.push(value);
        }
    }
    Ok(columns)
}

/// Generate and self-verify a native Touring proof with fresh local masking entropy.
/// No ledger registry accepts this standalone source identity yet.
///
/// # Errors
/// Rejects invalid manifest/admission facts, replay or statement bindings,
/// trace or envelope limits, and native proof construction or self-verification
/// failures.
pub fn prove_classed_race_v1(
    request: ClassedRaceProverRequestV1,
) -> Result<ExecutionProofEnvelopeV1, ExecutionProofErrorV1> {
    let mut payload = payload_from_request(&request)?;
    let adapter = ClassedRaceAdapterV1::new(&request.statement, &payload)?;
    let columns = witness_columns(&adapter)?;
    payload.stark_bytes = prove_proof_managed_note_stark_v1(&adapter, &columns)?;
    let envelope = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: classed_race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    if envelope.encode().len() > CLASSED_RACE_MAX_PROOF_BYTES_V1 {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    verify_classed_race_proof_v1(&request.statement, &envelope)?;
    Ok(envelope)
}

pub(super) fn decode_payload(
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<ClassedRaceProofPayloadV1, ExecutionProofErrorV1> {
    if envelope.version != 1
        || envelope.profile_id != classed_race_profile_id_v1()
        || envelope.proof_bytes.len() > CLASSED_RACE_MAX_PROOF_BYTES_V1
        || envelope.encode().len() > CLASSED_RACE_MAX_PROOF_BYTES_V1
    {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    let payload: ClassedRaceProofPayloadV1 =
        decode_exact(&envelope.proof_bytes, CLASSED_RACE_MAX_PROOF_BYTES_V1)?;
    if payload.stark_bytes.is_empty() || payload.stark_bytes.len() > CLASSED_RACE_MAX_STARK_BYTES_V1
    {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    Ok(payload)
}

/// Verify the full native relation against an independently authenticated session statement.
/// The expected statement must come from authenticated consensus state, never from the worker's
/// envelope. This function proves computation and commitment binding; it does not authenticate
/// ledger inclusion, NFT ownership/catalog eligibility, accepted input signatures or dispute history.
/// Those gates are required before future ledger settlement can invoke this isolated relation.
///
/// # Errors
/// Rejects a mismatched expected statement, malformed or oversized envelopes,
/// invalid replay/profile bindings, and failed native cryptographic verification.
pub fn verify_classed_race_proof_v1(
    expected: &ExecutionPublicInputsV1,
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<ClassedRaceResultV1, ExecutionProofErrorV1> {
    if &envelope.statement != expected {
        return Err(ExecutionProofErrorV1::Statement);
    }
    let payload = decode_payload(envelope)?;
    let adapter = ClassedRaceAdapterV1::new(expected, &payload)?;
    verify_proof_managed_note_stark_v1(&adapter, &payload.stark_bytes)?;
    Ok(payload.result)
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
