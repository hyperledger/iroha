//! Corrected stock racing proof with eligibility-first awards and one first-release identity.
//!
//! The verifier reconstructs public controls and fixed columns, but never replays vehicle physics.
//! Transition correctness is checked by the degree-four integer AIR and the existing native
//! Goldilocks/Fp4 DEEP-ALI/FRI proof driver. Payout admission additionally binds authenticated
//! checkpoints and every consensus-selected forced control and DNF event.

use super::stark::{
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
use super::{
    error::ExecutionProofErrorV1,
    integer_air::field,
    race::{initial_race_state_v1, race_result_v1, replay_race_v1},
    staged_race_air::StagedRaceAirV1,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    execution_proofs::*,
    game::{
        GameAdmissionBodyV1, GameCheckpointV1, GameDnfEventV1, GameForcedBatchV1, GameManifestV1,
        GameOutcomeV1, GameParticipantV1, GameTranscriptAnchorV1, GameTranscriptBatchV1,
        GameTranscriptV1, game_message_hash_v1, game_roster_hash_v1,
    },
};
use norito::codec::{Decode, Encode};

/// Maximum canonical execution envelope, including this adapter's complete replay.
/// This does not raise any deployment's independent transaction or transport bounds.
pub const RACE_MAX_PROOF_BYTES_V1: usize = EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1;
/// Rounded bound on the cryptographic wire alone, excluding replay and envelope.
/// The current maximum-frontier calculation is 3,166,240 bytes; qualification
/// must additionally record actual generated proof sizes and resource costs.
pub const RACE_MAX_STARK_BYTES_V1: usize = 3_250_000;
const MIN_TRACE_LOG2: u8 = 13;
const MAX_TRACE_LOG2: u8 = 19;
const MAX_AIR_COLUMNS: usize = 384;
const RULES:&[u8]=b"iroha-race-rules-v1:ticks=30:max=5400:players=1..8:multiplayer=2..8:laps=3:batch=6:skins=6:grid-progress=-floor(slot/2)*4000:grid-x=even?-1800:1800:grid-speed=0:grid-vx=0:grid-energy=1000:controls=throttle,brake,left,right,drift,boost:boost=bit5&&energy>=25:energy=boost?-25:min(1000,+4):top=boost?3000:2400:accel=brake?-100:throttle?40:-12:speed=clamp(speed+accel,0,top):steer=right-left:vx=clamp(trunc((vx+steer*(drift?28:18))*7/8),-320,320):curve-cell=floor(remEuclid(oldProgress,length)*12/length):force=trunc(curve*speed/120):x=clamp(x+vx+force,-9000,9000):abs(x)>6000=>speed=max(0,speed-90):progress+=speed:contacts=ascending-i-j,abs(dp)<3600&&abs(dx)<1800,push=ceil((1800-abs(dx))/2),low-x-or-low-slot-tie-goes-left,speed=max(0,speed-120):finish=after-contacts,progress>=3*length,clamp-and-freeze:dnf=before-exact-tick,record-key-inactivity-even-after-finish,preserve-earlier-finish-as-history-only,freeze-and-ghost:finished-ghost:terminal=(tick%6==0&&(all-finished-or-dnf||active-keys<2))||tick5400:ranking=eligible-before-all-dnf,then-finish-time,then-distance,slot-display-only:winners=eligible-earliest-finish-ties-else-sole-eligible-survivor-else-tick5400-max-eligible-progress-ties-else-all-forfeit-refund:environment=12-cell-center-floor((2i+1)*length/24):kinds-tree0-sign1-oil2:Tokyo-kinds=0,1,0,2,0,1,2,0,1,0,2,1:Harbor-kinds=1,2,0,1,0,2,1,0,2,1,0,2:Sakura-kinds=0,0,2,1,0,2,0,1,0,2,0,1:object-x=even-negative-odd-positive,magnitudes7400,5600,1800:rain-patterns=Tokyo0010,Harbor0110,Sakura0001:wind-pattern=0,1,2,1,0,-1,-2,-1:wind-strengths=Tokyo4,Harbor16,Sakura8:tree-radius=1400:tree-loss=600:tree-push=1800-clamp9000:sign-radius=1300:sign-loss=260:oil-half-length=9000:oil-half-width=1400:oil-steer=trunc(steer/2):rain-steer=trunc(steer*3/4):slippery-damping=15/16:rain-vx-limit=280:wind=trunc(public90tick8table*speed/2400):rain=public300tick4table:impact=swept-progress-before-ordered-contacts:tracks=NeonTokyo/2000000/[0,1,2,1,0,-1,-2,-1,0,2,-2,0];Harbor/2400000/[0,-2,-2,0,1,3,1,0,-1,-3,-1,0];Sakura/1800000/[0,1,1,0,-2,-1,0,2,3,1,-2,0]";
const PROFILE:&[u8]=b"iroha-native-execution-race-v1:wire=RCE1/1:eligibility-first-awards:poseidon-x7-goldilocks-six-independent-lanes-6x64:public-replay:trace=2^13..2^19:microcycles=boundary,environment,grip,drive,curve,move,impact,ordered-pair,finish:columns=stage-multiplexed-boolean-radix4-banks:integer-air-degree=4:shared-degree=2:envelope-max=4194304:stark-max=3250000:base-max=392:fri-commitment-error-bits-min=187:aux=118:state=progress,x,speed,vx,energy,finish-tick,dnf-tick-plus-one:all-car-dynamics:all-ordered-contacts:initial-intermediate-final-boundaries";
const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"race-stock-proof-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"execution-race-base-leaf-v1",
    base_node: b"execution-race-base-node-v1",
    aux_leaf: b"execution-race-aux-leaf-v1",
    aux_node: b"execution-race-aux-node-v1",
    composition_leaf: b"execution-race-composition-leaf-v1",
    composition_node: b"execution-race-composition-node-v1",
    fri_leaf: b"execution-race-fri-leaf-v1",
    fri_node: b"execution-race-fri-node-v1",
    layout_label: b"execution-race-layout-v1",
    base_root_label: b"execution-race-base-root-v1",
    aux_root_label: b"execution-race-aux-root-v1",
    composition_root_label: b"execution-race-composition-root-v1",
    fri_root_label: b"execution-race-fri-root-v1",
    fri_beta_label: b"execution-race-fri-beta-v1",
    query_seed: b"execution-race-query-seed-v1",
};

/// Fail-closed release gate. A compiled profile is not funded until cryptographic and resource
/// qualification evidence is reviewed; development prover/verifier APIs remain directly testable.
#[must_use]
pub const fn race_profile_is_qualified_v1() -> bool {
    false
}
/// Reconstruct the sole compiled descriptor; callers cannot supply alternative circuits or bounds.
#[must_use]
pub fn compiled_race_profile_v1() -> ExecutionProofProfileV1 {
    ExecutionProofProfileV1 {
        version: 1,
        profile_id: race_profile_id_v1(),
        rules_hash: race_rules_hash_v1(),
        relation: ExecutionProofRelationV1::RaceV1,
        target_soundness_bits: 128,
        maximum_proof_bytes: RACE_MAX_PROOF_BYTES_V1 as u32,
        qualified: race_profile_is_qualified_v1(),
    }
}
/// Commitment to every immutable gameplay parameter and operation order.
#[must_use]
pub fn race_rules_hash_v1() -> Hash {
    Hash::new(RULES)
}
/// Exact repository-relative source inventory committed by the stock verifier.
/// The browser exporter uses this same inventory to reject stale native binaries even when the
/// driving arithmetic is unchanged but the public admission or proof format has changed.
pub(super) const RACE_PROFILE_SOURCES_V1: &[(&str, &[u8])] = &[
    (
        "crates/iroha_core_privacy/src/execution_proofs/race.rs",
        include_bytes!("race.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/environment.rs",
        include_bytes!("environment.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/environment_air.rs",
        include_bytes!("environment_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/integer_air.rs",
        include_bytes!("integer_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/race_air.rs",
        include_bytes!("race_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/staged_race_air.rs",
        include_bytes!("staged_race_air.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/proof.rs",
        include_bytes!("proof.rs"),
    ),
    (
        "crates/iroha_data_model/src/game.rs",
        include_bytes!("../../../iroha_data_model/src/game.rs"),
    ),
    (
        "crates/iroha_data_model/src/game_resources.rs",
        include_bytes!("../../../iroha_data_model/src/game_resources.rs"),
    ),
    (
        "crates/iroha_data_model/src/execution_proofs.rs",
        include_bytes!("../../../iroha_data_model/src/execution_proofs.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/privacy_engines/transparent_stark.rs",
        include_bytes!("../privacy_engines/transparent_stark.rs"),
    ),
    (
        "crates/fastpq_isi/src/lib.rs",
        include_bytes!("../../../fastpq_isi/src/lib.rs"),
    ),
    (
        "crates/fastpq_isi/src/params.rs",
        include_bytes!("../../../fastpq_isi/src/params.rs"),
    ),
    (
        "crates/fastpq_isi/src/poseidon.rs",
        include_bytes!("../../../fastpq_isi/src/poseidon.rs"),
    ),
    (
        "crates/fastpq_isi/src/poseidon_digest384.rs",
        include_bytes!("../../../fastpq_isi/src/poseidon_digest384.rs"),
    ),
    (
        "crates/fastpq_isi/src/assets/poseidon_goldilocks_width3_v1.bin",
        include_bytes!("../../../fastpq_isi/src/assets/poseidon_goldilocks_width3_v1.bin"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/mod.rs",
        include_bytes!("stark/mod.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/transparent_stark.rs",
        include_bytes!("stark/transparent_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/aggregate_stark.rs",
        include_bytes!("stark/aggregate_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/proof_managed_note_stark.rs",
        include_bytes!("stark/proof_managed_note_stark.rs"),
    ),
    (
        "crates/iroha_core_privacy/src/execution_proofs/stark/proof_managed_note_stark_execution_fixed.rs",
        include_bytes!("stark/proof_managed_note_stark_execution_fixed.rs"),
    ),
];
/// Commitment to the complete frozen `RaceV1` verifier and native outcome semantics.
///
/// The source commitment binds the compiled transition, outcome and verifier implementation.
/// This first release has one implementation; obsolete development drafts have no dispatch entry.
/// The registry and exporters are outside the commitment so unrelated compiled relations do not
/// change this identity. Any change to these committed sources produces a different profile ID.
#[must_use]
pub fn race_profile_id_v1() -> Hash {
    static ID: std::sync::OnceLock<Hash> = std::sync::OnceLock::new();
    *ID.get_or_init(|| {
        let mut chunks: Vec<&[u8]> = vec![
            b"iroha:execution:profile:v1\0".as_slice(),
            PROFILE,
            RULES,
            PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
        ];
        chunks.extend(RACE_PROFILE_SOURCES_V1.iter().map(|(_, bytes)| *bytes));
        Hash::new_from_chunks(&chunks)
    })
}
/// Exact canonical public replay commitment used by peer and ledger certificates.
#[must_use]
pub fn race_transcript_root_v1(network: &NetworkId, replay: &RaceReplayV1) -> Hash {
    game_message_hash_v1(
        network,
        "input-transcript",
        &race_game_transcript_v1(replay),
    )
}
/// Convert the application replay to the generic, opaque canonical session transcript.
#[must_use]
pub fn race_game_transcript_v1(replay: &RaceReplayV1) -> GameTranscriptV1 {
    GameTranscriptV1 {
        batches: replay
            .frames
            .chunks(6)
            .map(|frames| {
                let start_tick = frames[0].tick;
                GameTranscriptBatchV1 {
                    start_tick,
                    inputs: (0..replay.player_count)
                        .map(|slot| {
                            if replay.dnf_events.iter().any(|event| {
                                event.tick <= start_tick && event.slots.contains(&slot)
                            }) {
                                vec![]
                            } else {
                                frames
                                    .iter()
                                    .flat_map(|frame| {
                                        frame.controls[usize::from(slot)].to_le_bytes()
                                    })
                                    .collect()
                            }
                        })
                        .collect(),
                }
            })
            .collect(),
        dnf_events: replay
            .dnf_events
            .iter()
            .map(|event| GameDnfEventV1 {
                tick: event.tick,
                slots: event.slots.clone(),
            })
            .collect(),
    }
}
/// Exact canonical state commitment used by peer and ledger certificates.
#[must_use]
pub fn race_state_root_v1(network: &NetworkId, state: &RaceStateV1) -> Hash {
    game_message_hash_v1(network, "simulation-state", &state.encode())
}

/// Validate application-neutral manifest bounds against its exact compiled relation.
pub fn validate_race_manifest_v1(manifest: &GameManifestV1) -> Result<(), ExecutionProofErrorV1> {
    if manifest.version != 1
        || manifest.profile_id != race_profile_id_v1()
        || manifest.min_participants != 2
        || !(2..=8).contains(&manifest.max_participants)
        || manifest.batch_ticks != 6
        || manifest.max_ticks != 5400
        || manifest.max_input_bytes != 12
        || manifest.max_participant_data_bytes != 1
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    decode_track(manifest)?;
    Ok(())
}
fn decode_track(manifest: &GameManifestV1) -> Result<RaceTrackV1, ExecutionProofErrorV1> {
    let mut bytes = manifest.application_parameters.as_slice();
    let track = RaceTrackV1::decode(&mut bytes).map_err(|_| ExecutionProofErrorV1::Statement)?;
    if !bytes.is_empty() || track.encode() != manifest.application_parameters {
        return Err(ExecutionProofErrorV1::Statement);
    }
    Ok(track)
}
/// Validate opaque application participant data through the compiled adapter.
pub fn validate_race_participant_v1(
    manifest: &GameManifestV1,
    data: &[u8],
) -> Result<(), ExecutionProofErrorV1> {
    validate_race_manifest_v1(manifest)?;
    if data.len() != 1 || data[0] >= RACE_SKIN_COUNT_V1 {
        return Err(ExecutionProofErrorV1::Statement);
    }
    Ok(())
}
/// Validate the complete immutable admission projection before constructing any AIR trace.
/// Stock racing accepts cosmetic data only; resource-enabled adapters need their own compiled
/// relation and exact entitlement checks. NFT metadata never chooses stock physics parameters.
fn validate_race_admission_v1(
    manifest: &GameManifestV1,
    admission: &GameAdmissionBodyV1,
    player_count: u8,
) -> Result<(), ExecutionProofErrorV1> {
    admission
        .validate()
        .map_err(|_| ExecutionProofErrorV1::Statement)?;
    if admission.participants.len() != usize::from(player_count)
        || player_count < manifest.min_participants
        || player_count > manifest.max_participants
        || !admission.resources.is_empty()
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    for participant in &admission.participants {
        validate_race_participant_v1(manifest, &participant.application_data)?;
    }
    Ok(())
}
/// Validate opaque input batches through the compiled adapter, before accepting commitments/reveals.
pub fn validate_race_input_v1(
    manifest: &GameManifestV1,
    input: &[u8],
) -> Result<(), ExecutionProofErrorV1> {
    validate_race_manifest_v1(manifest)?;
    if input.len() != 12
        || input
            .chunks_exact(2)
            .any(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) & !RACE_CONTROL_MASK_V1 != 0)
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    Ok(())
}
/// Compute the compiled application's prescribed initial state commitment.
pub fn initial_race_manifest_state_root_v1(
    network: &NetworkId,
    manifest: &GameManifestV1,
    player_count: u8,
) -> Result<Hash, ExecutionProofErrorV1> {
    validate_race_manifest_v1(manifest)?;
    if player_count < 2 || player_count > manifest.max_participants {
        return Err(ExecutionProofErrorV1::Replay);
    }
    let state = initial_race_state_v1(decode_track(manifest)?, player_count)
        .map_err(|_| ExecutionProofErrorV1::Replay)?;
    Ok(race_state_root_v1(network, &state))
}
fn race_game_outcome_v1(state: &RaceStateV1) -> Result<GameOutcomeV1, ExecutionProofErrorV1> {
    let result = race_result_v1(state).map_err(|_| ExecutionProofErrorV1::Replay)?;
    Ok(GameOutcomeV1 {
        terminal_tick: state.tick,
        winner_slots: result.winners.clone(),
        result: result.encode(),
    })
}
fn race_payload_from_request_v1(
    request: &RaceProverRequestV1,
) -> Result<RaceProofPayloadV1, ExecutionProofErrorV1> {
    let final_state = replay_race_v1(&request.replay).map_err(|_| ExecutionProofErrorV1::Replay)?;
    let outcome = race_game_outcome_v1(&final_state)?;
    let relation_inputs = RacePublicInputsV1 {
        network_id: request.statement.network_id,
        race_id: request.statement.session_id,
        roster_hash: request.statement.roster_hash,
        rules_hash: race_rules_hash_v1(),
        track: request.replay.track,
        transcript_root: request.statement.transcript_root,
        dispute_root: request.statement.dispute_root,
        result: race_result_v1(&final_state).map_err(|_| ExecutionProofErrorV1::Replay)?,
    };
    Ok(RaceProofPayloadV1 {
        manifest: request.manifest.clone(),
        admission: request.admission.clone(),
        outcome,
        relation_inputs,
        replay: request.replay.clone(),
        final_state,
        checkpoint_state: request.checkpoint_state.clone(),
        stark_bytes: vec![],
    })
}
/// Verify a compiled execution envelope and return only the adapter-authenticated generic outcome.
pub fn verify_race_outcome_v1(
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<GameOutcomeV1, ExecutionProofErrorV1> {
    let payload = decode_payload(envelope)?;
    let adapter = RaceAdapterV1::new(&envelope.statement, &payload)?;
    verify_proof_managed_note_stark_v1(&adapter, &payload.stark_bytes)?;
    Ok(payload.outcome)
}

fn validate_payload(
    statement: &ExecutionPublicInputsV1,
    payload: &RaceProofPayloadV1,
) -> Result<(), ExecutionProofErrorV1> {
    validate_race_manifest_v1(&payload.manifest)?;
    validate_race_admission_v1(
        &payload.manifest,
        &payload.admission,
        payload.replay.player_count,
    )?;
    if payload.replay.player_count < 2
        || payload.replay.player_count > 8
        || payload.replay.frames.len() > 5400
        || payload
            .replay
            .frames
            .iter()
            .any(|frame| frame.controls.len() != usize::from(payload.replay.player_count))
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    let relation = &payload.relation_inputs;
    let expected_outcome = race_game_outcome_v1(&payload.final_state)?;
    let race_session_id = relation.race_id;
    if statement.network_id != relation.network_id
        || statement.session_id != race_session_id
        || statement.roster_hash != relation.roster_hash
        || statement.roster_hash
            != game_roster_hash_v1(
                &statement.network_id,
                &statement.session_id,
                &payload.admission,
            )
        || statement.transcript_root != relation.transcript_root
        || statement.dispute_root != relation.dispute_root
        || statement.manifest_hash
            != game_message_hash_v1(&statement.network_id, "session-manifest", &payload.manifest)
        || statement.outcome_hash
            != game_message_hash_v1(&statement.network_id, "session-outcome", &payload.outcome)
        || payload.outcome != expected_outcome
        || payload.replay.track != decode_track(&payload.manifest)?
        || payload.replay.player_count > payload.manifest.max_participants
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    let replay = &payload.replay;
    let final_state = &payload.final_state;
    if !(1..=8).contains(&replay.player_count)
        || replay.frames.len() > RACE_MAX_TICKS_V1 as usize
        || replay.frames.iter().enumerate().any(|(tick, frame)| {
            frame.tick != tick as u32
                || frame.controls.len() != usize::from(replay.player_count)
                || frame
                    .controls
                    .iter()
                    .any(|control| control & !RACE_CONTROL_MASK_V1 != 0)
        })
        || replay
            .dnf_events
            .windows(2)
            .any(|events| events[0].tick >= events[1].tick)
        || replay.dnf_events.iter().any(|event| {
            event.tick > replay.frames.len() as u32
                || event.tick % 6 != 0
                || event.slots.is_empty()
                || event.slots.windows(2).any(|slots| slots[0] >= slots[1])
                || event.slots.iter().any(|slot| *slot >= replay.player_count)
        })
        || final_state.tick % 6 != 0
        || final_state.cars.len() != usize::from(replay.player_count)
        || final_state.track != replay.track
        || final_state.tick != replay.frames.len() as u32
        || (final_state.tick != RACE_MAX_TICKS_V1
            && final_state
                .cars
                .iter()
                .filter(|car| car.dnf_tick.is_none())
                .count()
                >= 2
            && !final_state
                .cars
                .iter()
                .all(|car| car.finish_tick.is_some() || car.dnf_tick.is_some()))
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    let mut removed = [false; 8];
    for event in &replay.dnf_events {
        for slot in &event.slots {
            if std::mem::replace(&mut removed[usize::from(*slot)], true) {
                return Err(ExecutionProofErrorV1::Replay);
            }
        }
    }
    if replay.frames.iter().any(|frame| {
        replay
            .dnf_events
            .iter()
            .filter(|event| event.tick <= frame.tick)
            .any(|event| {
                event
                    .slots
                    .iter()
                    .any(|slot| frame.controls[usize::from(*slot)] != 0)
            })
    }) {
        return Err(ExecutionProofErrorV1::Replay);
    }
    if relation.rules_hash != race_rules_hash_v1()
        || relation.track != replay.track
        || relation.transcript_root != race_transcript_root_v1(&statement.network_id, replay)
        || relation.result
            != race_result_v1(final_state).map_err(|_| ExecutionProofErrorV1::Replay)?
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    if let Some(checkpoint) = &payload.checkpoint_state {
        if checkpoint.tick > final_state.tick
            || checkpoint.track != replay.track
            || checkpoint.cars.len() != final_state.cars.len()
        {
            return Err(ExecutionProofErrorV1::Replay);
        }
        race_result_v1(checkpoint).map_err(|_| ExecutionProofErrorV1::Replay)?;
    }
    Ok(())
}

struct RaceAdapterV1<'a> {
    statement: &'a ExecutionPublicInputsV1,
    payload: &'a RaceProofPayloadV1,
    compiled: StagedRaceAirV1,
}
impl<'a> RaceAdapterV1<'a> {
    fn new(
        statement: &'a ExecutionPublicInputsV1,
        payload: &'a RaceProofPayloadV1,
    ) -> Result<Self, ExecutionProofErrorV1> {
        validate_payload(statement, payload)?;
        let compiled = StagedRaceAirV1::compile(
            &payload.replay,
            &payload.final_state,
            payload.checkpoint_state.as_ref(),
        );
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
impl ProofManagedNoteStarkAdapterV1 for RaceAdapterV1<'_> {
    type ProfileChallenges = ();
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"RCE1",
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
                maximum_proof_bytes: RACE_MAX_STARK_BYTES_V1,
            },
            domains: DOMAINS,
            maximum_constraint_degree: 4,
            profile_binding_label: b"execution-race-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"execution-race-relation-layout-v1",
        }
    }
    fn public_input_digest_v1(
        &self,
    ) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"execution-race-public-statement-v1",
            b"statement",
            0,
            0,
            0,
            &[
                race_profile_id_v1().as_ref(),
                &self.statement.encode(),
                &self.payload.replay.encode(),
                &self.payload.final_state.encode(),
                &self.payload.checkpoint_state.encode(),
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)
    }
    fn trace_log2_v1(&self) -> u8 {
        self.compiled.trace_size(&self.payload.replay).ilog2() as u8
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
                self.compiled.trace_size(&self.payload.replay)
            ],
            sigma: (0..self.compiled.trace_size(&self.payload.replay))
                .map(|row| {
                    std::array::from_fn(|column| (row * NOTE_COPY_WIDTH_V1 + column + 1) as u32)
                })
                .collect(),
        })
    }
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        let mut columns = vec![
            Vec::with_capacity(self.compiled.trace_size(&self.payload.replay));
            self.profile_fixed_width_v1()
        ];
        for row in 0..self.compiled.trace_size(&self.payload.replay) {
            for (column, value) in columns.iter_mut().zip(
                self.compiled.fixed_row(
                    &self.payload.replay,
                    row,
                    self.compiled.trace_size(&self.payload.replay),
                    self.payload
                        .checkpoint_state
                        .as_ref()
                        .map(|state| state.tick),
                ),
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
        Ok(self.compiled.residues(
            &current[NOTE_COPY_WIDTH_V1..],
            &next[NOTE_COPY_WIDTH_V1..],
            &fixed[NOTE_COPY_FIXED_WIDTH_V1..],
        ))
    }
}

/// Generate and self-verify a genuine native transparent execution proof using local entropy.
pub fn prove_race_v1(
    request: RaceProverRequestV1,
) -> Result<ExecutionProofEnvelopeV1, ExecutionProofErrorV1> {
    let mut payload = race_payload_from_request_v1(&request)?;
    let adapter = RaceAdapterV1::new(&request.statement, &payload)?;
    let size = adapter.compiled.trace_size(&payload.replay);
    let mut carry = adapter.compiled.initial_carry();
    let mut columns = vec![Vec::with_capacity(size); adapter.base_width_v1()];
    for row_index in 0..size {
        let fixed = adapter.compiled.fixed_row(
            &payload.replay,
            row_index,
            size,
            payload.checkpoint_state.as_ref().map(|state| state.tick),
        );
        let (row, next) = adapter.compiled.witness(&carry, &fixed);
        carry = next;
        for column in &mut columns[..NOTE_COPY_WIDTH_V1] {
            column.push(F::ZERO);
        }
        for (column, value) in columns[NOTE_COPY_WIDTH_V1..].iter_mut().zip(row) {
            column.push(value);
        }
    }
    payload.stark_bytes = prove_proof_managed_note_stark_v1(&adapter, &columns)?;
    let envelope = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    if envelope.encode().len() > RACE_MAX_PROOF_BYTES_V1 {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    verify_race_proof_v1(&envelope)?;
    Ok(envelope)
}

fn decode_payload(
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<RaceProofPayloadV1, ExecutionProofErrorV1> {
    if envelope.version != 1
        || envelope.profile_id != race_profile_id_v1()
        || envelope.proof_bytes.is_empty()
        || envelope.proof_bytes.len() > RACE_MAX_PROOF_BYTES_V1
        || envelope.encode().len() > RACE_MAX_PROOF_BYTES_V1
    {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    let mut bytes = envelope.proof_bytes.as_slice();
    let payload =
        RaceProofPayloadV1::decode(&mut bytes).map_err(|_| ExecutionProofErrorV1::Envelope)?;
    if !bytes.is_empty()
        || payload.stark_bytes.len() > RACE_MAX_STARK_BYTES_V1
        || payload.encode() != envelope.proof_bytes
    {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    Ok(payload)
}
/// Verify the complete semantic execution relation, with no replay-only or binding-only mode.
pub fn verify_race_proof_v1(
    envelope: &ExecutionProofEnvelopeV1,
) -> Result<(), ExecutionProofErrorV1> {
    let payload = decode_payload(envelope)?;
    let adapter = RaceAdapterV1::new(&envelope.statement, &payload)?;
    verify_proof_managed_note_stark_v1(&adapter, &payload.stark_bytes)?;
    Ok(())
}

/// Verify semantic execution and exact retained checkpoint, forced inputs, and removals.
pub fn verify_race_proof_for_history_v1(
    envelope: &ExecutionProofEnvelopeV1,
    manifest: &GameManifestV1,
    outcome: &GameOutcomeV1,
    checkpoint: Option<&GameCheckpointV1>,
    anchors: &[GameTranscriptAnchorV1],
    batches: &[GameForcedBatchV1],
    participants: &[GameParticipantV1],
    epoch: u64,
) -> Result<(), ExecutionProofErrorV1> {
    let payload = decode_payload(envelope)?;
    validate_payload(&envelope.statement, &payload)?;
    if &payload.manifest != manifest || &payload.outcome != outcome {
        return Err(ExecutionProofErrorV1::History);
    }
    let statement = &envelope.statement;
    let replay = &payload.replay;
    if participants.len() != usize::from(replay.player_count)
        || statement.dispute_root
            != game_message_hash_v1(
                &statement.network_id,
                "dispute-history",
                &(
                    statement.session_id,
                    epoch,
                    checkpoint.cloned(),
                    anchors.to_vec(),
                    batches.to_vec(),
                ),
            )
    {
        return Err(ExecutionProofErrorV1::History);
    }
    // A removal changes the set of future checkpoint signers. Every prefix authenticated before
    // that change remains immutable even when the current checkpoint is later replaced.
    if anchors.len() > 32 {
        return Err(ExecutionProofErrorV1::History);
    }
    for anchor in anchors {
        if anchor.tick > replay.frames.len() as u32 || anchor.tick % 6 != 0 {
            return Err(ExecutionProofErrorV1::History);
        }
        let prefix = RaceReplayV1 {
            track: replay.track,
            player_count: replay.player_count,
            frames: replay.frames[..anchor.tick as usize].to_vec(),
            dnf_events: replay
                .dnf_events
                .iter()
                .filter(|event| event.tick < anchor.tick)
                .cloned()
                .collect(),
        };
        if race_transcript_root_v1(&statement.network_id, &prefix) != anchor.transcript_root {
            return Err(ExecutionProofErrorV1::History);
        }
    }
    let mut expected_dnfs = std::collections::BTreeMap::<u32, Vec<u8>>::new();
    for (slot, participant) in participants.iter().enumerate() {
        if let Some(tick) = participant
            .dnf_at_tick
            .filter(|tick| *tick <= payload.final_state.tick)
        {
            expected_dnfs.entry(tick).or_default().push(slot as u8);
        }
    }
    if replay.dnf_events
        != expected_dnfs
            .into_iter()
            .map(|(tick, slots)| RaceDnfEventV1 { tick, slots })
            .collect::<Vec<_>>()
    {
        return Err(ExecutionProofErrorV1::History);
    }
    let mut tail = 0;
    match (checkpoint, payload.checkpoint_state.as_ref()) {
        (Some(checkpoint), Some(state)) => {
            if checkpoint.session_id != statement.session_id
                || checkpoint.tick > replay.frames.len() as u32
                || state.tick != checkpoint.tick
                || race_state_root_v1(&statement.network_id, state) != checkpoint.state_root
            {
                return Err(ExecutionProofErrorV1::History);
            }
            let prefix = RaceReplayV1 {
                track: replay.track,
                player_count: replay.player_count,
                frames: replay.frames[..checkpoint.tick as usize].to_vec(),
                dnf_events: replay
                    .dnf_events
                    .iter()
                    .filter(|event| event.tick < checkpoint.tick)
                    .cloned()
                    .collect(),
            };
            if race_transcript_root_v1(&statement.network_id, &prefix) != checkpoint.transcript_root
            {
                return Err(ExecutionProofErrorV1::History);
            }
            tail = checkpoint.tick;
        }
        (None, None) => {}
        _ => return Err(ExecutionProofErrorV1::History),
    }
    if batches
        .windows(2)
        .any(|pair| pair[0].start_tick.saturating_add(6) > pair[1].start_tick)
    {
        return Err(ExecutionProofErrorV1::History);
    }
    for batch in batches {
        let extends_tail = batch.start_tick >= tail;
        if (extends_tail && batch.start_tick != tail)
            || batch.inputs.len() != participants.len()
            || batch.epoch > epoch
        {
            return Err(ExecutionProofErrorV1::History);
        }
        let mut controls = Vec::with_capacity(participants.len());
        for (slot, input) in batch.inputs.iter().enumerate() {
            let removed = participants[slot]
                .dnf_at_tick
                .is_some_and(|tick| tick <= batch.start_tick);
            if removed {
                if !input.is_empty() {
                    return Err(ExecutionProofErrorV1::History);
                }
                controls.push([0_u16; 6]);
            } else {
                validate_race_input_v1(manifest, input)?;
                controls.push(std::array::from_fn(|offset| {
                    u16::from_le_bytes([input[offset * 2], input[offset * 2 + 1]])
                }));
            }
        }
        for offset in 0..6 {
            let tick = batch.start_tick + offset;
            if let Some(frame) = replay.frames.get(tick as usize) {
                if frame.controls
                    != controls
                        .iter()
                        .map(|controls| controls[offset as usize])
                        .collect::<Vec<_>>()
                {
                    return Err(ExecutionProofErrorV1::History);
                }
            }
        }
        for slot in &batch.dnf_slots {
            if participants
                .get(usize::from(*slot))
                .and_then(|participant| participant.dnf_at_tick)
                != Some(batch.start_tick)
            {
                return Err(ExecutionProofErrorV1::History);
            }
        }
        if extends_tail {
            tail = tail.saturating_add(6);
        }
    }
    if tail < replay.frames.len() as u32 {
        return Err(ExecutionProofErrorV1::History);
    }
    let adapter = RaceAdapterV1::new(statement, &payload)?;
    verify_proof_managed_note_stark_v1(&adapter, &payload.stark_bytes)?;
    Ok(())
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
