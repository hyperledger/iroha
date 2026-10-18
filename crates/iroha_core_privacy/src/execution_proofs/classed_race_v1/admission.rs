//! Standalone Touring proof-instance admission. This does not authorize NFT custody.

use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    classed_race_v1::*,
    execution_proofs::ExecutionPublicInputsV1,
    game::{
        GameAdmissionBodyV1, GameDnfEventV1, GameManifestV1, GameOutcomeV1, GameTranscriptBatchV1,
        GameTranscriptV1, game_message_hash_v1, game_roster_hash_v1,
    },
    game_resources::GameResourceReturnPolicyV1,
};
use norito::codec::{Decode, Encode};

use super::super::error::ExecutionProofErrorV1;
use super::{
    proof::{ClassedRaceProofPayloadV1, classed_race_profile_id_v1},
    race_air::validate_public_inputs,
    reference::{classed_race_is_terminal_v1, classed_race_result_v1},
    rules::{BATCH_TICKS, MAX_TICKS},
};

/// Frozen application parameters. Catalog eligibility must be authenticated by consensus.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::execution_proofs::classed_race_v1::admission::ClassedRaceParametersV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
pub struct ClassedRaceParametersV1 {
    /// Exactly one.
    pub version: u16,
    /// One global performance class; per-entrant multipliers do not exist.
    pub class_id: ClassedRaceClassV1,
    /// Immutable track selected before admission.
    pub track: ClassedRaceTrackV1,
    /// Exact compiled gameplay rules.
    pub rules_hash: Hash,
    /// Immutable reviewed NFT catalog commitment, never an executable or a role override.
    pub catalog_id: Hash,
}

/// Exact participant data; resource identities live in the typed admission resources.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::execution_proofs::classed_race_v1::admission::ClassedRaceParticipantDataV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)]
pub struct ClassedRaceParticipantDataV1 {
    /// Exactly one.
    pub version: u16,
    /// Must equal the manifest's one global class.
    pub class_id: ClassedRaceClassV1,
    /// One of six equal-performance cosmetic variants.
    pub skin: u8,
}

/// One application-scoped Touring S1 role, shared by all entrants and future ledger admission.
/// This role identifies an immutable required kit; it does not establish NFT eligibility.
#[must_use]
pub fn classed_race_equipment_role_v1() -> Hash {
    Hash::new(b"sora-cars:equipment-role:v1\0TouringS1\0one-kit-return-to-original-owner")
}

fn rules_hash_from_sources(rules: &[u8], environment: &[u8], reference: &[u8]) -> Hash {
    Hash::new_from_chunks(&[
        b"sora-cars:classed-rules:v1\0",
        b"rules.rs\0",
        rules,
        b"environment.rs\0",
        environment,
        b"reference.rs\0",
        reference,
    ])
}

/// Commitment to the exact constants, track tables, environmental schedules and reference
/// operation order. A prose description alone cannot bind every executable numeric rule.
#[must_use]
pub fn classed_race_rules_hash_v1() -> Hash {
    rules_hash_from_sources(
        include_bytes!("rules.rs"),
        include_bytes!("environment.rs"),
        include_bytes!("reference.rs"),
    )
}

/// Canonical generic session inputs. Class, track and rules remain bound by the manifest,
/// state and complete proof statement, so the generic native genesis has the same empty root.
///
/// # Errors
/// Rejects an unsupported replay version, roster or frame shape, incomplete batches,
/// invalid control bits, noncanonical removals or controls submitted after removal.
pub fn classed_race_game_transcript_v1(
    replay: &ClassedRaceReplayV1,
) -> Result<GameTranscriptV1, ExecutionProofErrorV1> {
    if replay.version != 1
        || !(1..=8).contains(&replay.player_count)
        || replay.frames.len() > MAX_TICKS as usize
        || !replay.frames.len().is_multiple_of(BATCH_TICKS as usize)
        || replay.dnf_events.len() > 8
        || replay.frames.iter().enumerate().any(|(tick, frame)| {
            frame.tick as usize != tick
                || frame.controls.len() != usize::from(replay.player_count)
                || frame.controls.iter().any(|control| control & !63 != 0)
        })
        || replay
            .dnf_events
            .windows(2)
            .any(|events| events[0].tick >= events[1].tick)
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    let mut removed = [false; 8];
    for event in &replay.dnf_events {
        if event.tick as usize > replay.frames.len()
            || event.tick % BATCH_TICKS != 0
            || event.slots.is_empty()
            || event.slots.windows(2).any(|slots| slots[0] >= slots[1])
        {
            return Err(ExecutionProofErrorV1::Replay);
        }
        for &slot in &event.slots {
            if slot >= replay.player_count
                || std::mem::replace(&mut removed[usize::from(slot)], true)
                || replay.frames[event.tick as usize..]
                    .iter()
                    .any(|frame| frame.controls[usize::from(slot)] != 0)
            {
                return Err(ExecutionProofErrorV1::Replay);
            }
        }
    }
    Ok(GameTranscriptV1 {
        batches: replay
            .frames
            .chunks(BATCH_TICKS as usize)
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
    })
}

/// Canonical native input transcript commitment, shared by every game adapter and genesis.
///
/// # Errors
/// Rejects any replay that cannot form a canonical classed-race game transcript.
pub fn classed_race_transcript_root_v1(
    network: &NetworkId,
    replay: &ClassedRaceReplayV1,
) -> Result<Hash, ExecutionProofErrorV1> {
    Ok(game_message_hash_v1(
        network,
        "input-transcript",
        &classed_race_game_transcript_v1(replay)?,
    ))
}

/// Canonical opaque state commitment used by the generic native checkpoint protocol.
#[must_use]
pub fn classed_race_state_root_v1(network: &NetworkId, state: &ClassedRaceStateV1) -> Hash {
    game_message_hash_v1(network, "simulation-state", &state.encode())
}

pub(super) fn decode_exact<T: Decode + Encode>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, ExecutionProofErrorV1> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    let mut rest = bytes;
    let value = T::decode(&mut rest).map_err(|_| ExecutionProofErrorV1::Envelope)?;
    if !rest.is_empty() || value.encode() != bytes {
        return Err(ExecutionProofErrorV1::Envelope);
    }
    Ok(value)
}

pub(super) fn validate_manifest(
    manifest: &GameManifestV1,
) -> Result<ClassedRaceParametersV1, ExecutionProofErrorV1> {
    let data_bytes = ClassedRaceParticipantDataV1 {
        version: 1,
        class_id: ClassedRaceClassV1::TouringS1,
        skin: 0,
    }
    .encode()
    .len();
    if manifest.version != 1
        || manifest.profile_id != classed_race_profile_id_v1()
        || manifest.min_participants != 2
        || !(2..=8).contains(&manifest.max_participants)
        || u32::from(manifest.batch_ticks) != BATCH_TICKS
        || manifest.max_ticks != MAX_TICKS
        || u32::from(manifest.max_input_bytes) != BATCH_TICKS * 2
        || usize::from(manifest.max_participant_data_bytes) != data_bytes
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    let parameters: ClassedRaceParametersV1 = decode_exact(&manifest.application_parameters, 256)?;
    if parameters.version != 1 || parameters.rules_hash != classed_race_rules_hash_v1() {
        return Err(ExecutionProofErrorV1::Statement);
    }
    Ok(parameters)
}

pub(super) fn validate_admission(
    manifest: &GameManifestV1,
    parameters: &ClassedRaceParametersV1,
    admission: &GameAdmissionBodyV1,
    players: u8,
) -> Result<(), ExecutionProofErrorV1> {
    admission
        .validate()
        .map_err(|_| ExecutionProofErrorV1::Statement)?;
    if !(manifest.min_participants..=manifest.max_participants).contains(&players)
        || admission.participants.len() != usize::from(players)
        || admission.resources.len() != usize::from(players)
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    for (slot, (participant, resource)) in admission
        .participants
        .iter()
        .zip(&admission.resources)
        .enumerate()
    {
        let data: ClassedRaceParticipantDataV1 = decode_exact(
            &participant.application_data,
            usize::from(manifest.max_participant_data_bytes),
        )?;
        if data.version != 1
            || data.class_id != parameters.class_id
            || data.skin >= 6
            || usize::from(resource.slot) != slot
            || resource.role_id != classed_race_equipment_role_v1()
            || resource.policy != GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal
        {
            return Err(ExecutionProofErrorV1::Statement);
        }
    }
    Ok(())
}

pub(super) fn outcome(result: &ClassedRaceResultV1) -> GameOutcomeV1 {
    GameOutcomeV1 {
        terminal_tick: result.ticks,
        winner_slots: result.winners.clone(),
        result: result.encode(),
    }
}

/// Validate public shapes and commitments, but never execute a vehicle transition.
pub(super) fn validate_payload(
    statement: &ExecutionPublicInputsV1,
    payload: &ClassedRaceProofPayloadV1,
) -> Result<(), ExecutionProofErrorV1> {
    let parameters = validate_manifest(&payload.manifest)?;
    let replay = &payload.replay;
    validate_admission(
        &payload.manifest,
        &parameters,
        &payload.admission,
        replay.player_count,
    )?;
    validate_public_inputs(
        replay,
        &payload.final_state,
        payload.checkpoint_state.as_ref(),
    )
    .map_err(|_| ExecutionProofErrorV1::Replay)?;
    if replay.class_id != parameters.class_id
        || replay.track != parameters.track
        || !payload.final_state.tick.is_multiple_of(BATCH_TICKS)
        || !classed_race_is_terminal_v1(&payload.final_state)
            .map_err(|_| ExecutionProofErrorV1::Replay)?
        || replay
            .dnf_events
            .iter()
            .any(|event| event.tick % BATCH_TICKS != 0)
        || payload
            .checkpoint_state
            .as_ref()
            .is_some_and(|state| state.tick % BATCH_TICKS != 0)
    {
        return Err(ExecutionProofErrorV1::Replay);
    }
    // A removed input key has no accepted controls in later batches. The AIR independently
    // freezes its car, while this admission rule preserves the canonical public transcript.
    for event in &replay.dnf_events {
        for frame in &replay.frames[event.tick as usize..] {
            if event
                .slots
                .iter()
                .any(|slot| frame.controls[usize::from(*slot)] != 0)
            {
                return Err(ExecutionProofErrorV1::Replay);
            }
        }
    }
    let result =
        classed_race_result_v1(&payload.final_state).map_err(|_| ExecutionProofErrorV1::Replay)?;
    if payload.result != result
        || !result.terminal
        || statement.manifest_hash
            != game_message_hash_v1(&statement.network_id, "session-manifest", &payload.manifest)
        || statement.roster_hash
            != game_roster_hash_v1(
                &statement.network_id,
                &statement.session_id,
                &payload.admission,
            )
        || statement.transcript_root
            != classed_race_transcript_root_v1(&statement.network_id, replay)?
        || statement.outcome_hash
            != game_message_hash_v1(&statement.network_id, "session-outcome", &outcome(&result))
    {
        return Err(ExecutionProofErrorV1::Statement);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_identity_commits_numeric_tracks_curves_and_environment() {
        let rules = include_str!("rules.rs");
        let environment = include_str!("environment.rs");
        let reference = include_str!("reference.rs");
        let original = classed_race_rules_hash_v1();
        assert_eq!(
            original,
            rules_hash_from_sources(
                rules.as_bytes(),
                environment.as_bytes(),
                reference.as_bytes()
            )
        );
        for (before, after) in [
            ("2_400_000", "2_400_001"),
            (
                "0, -2, -2, 0, 1, 3, 1, 0, -1, -3, -1, 0",
                "0, -2, -2, 0, 1, 4, 1, 0, -1, -3, -1, 0",
            ),
        ] {
            assert!(rules.contains(before));
            let changed = rules.replacen(before, after, 1);
            assert_ne!(
                original,
                rules_hash_from_sources(
                    changed.as_bytes(),
                    environment.as_bytes(),
                    reference.as_bytes()
                )
            );
        }
        let changed = environment.replacen("300", "301", 1);
        assert_ne!(
            changed, environment,
            "actual numeric weather schedule exists"
        );
        assert_ne!(
            original,
            rules_hash_from_sources(rules.as_bytes(), changed.as_bytes(), reference.as_bytes())
        );
    }

    fn manifest_fixture() -> GameManifestV1 {
        let data = ClassedRaceParticipantDataV1 {
            version: 1,
            class_id: ClassedRaceClassV1::TouringS1,
            skin: 0,
        };
        GameManifestV1 {
            version: 1,
            application_id: Hash::new(b"classed-admission-boundaries"),
            profile_id: classed_race_profile_id_v1(),
            application_parameters: ClassedRaceParametersV1 {
                version: 1,
                class_id: data.class_id,
                track: ClassedRaceTrackV1::Harbor,
                rules_hash: classed_race_rules_hash_v1(),
                catalog_id: Hash::new(b"classed-admission-fixture-catalog"),
            }
            .encode(),
            min_participants: 2,
            max_participants: 8,
            batch_ticks: 6,
            max_ticks: MAX_TICKS,
            max_input_bytes: 12,
            max_participant_data_bytes: u16::try_from(data.encode().len())
                .expect("bounded participant fixture"),
            access: iroha_data_model::game::GameAccessV1::Public,
            payout_policy: iroha_data_model::game::GamePayoutPolicyV1::EqualWinnersOrRefund,
        }
    }

    #[test]
    fn fixed_width_manifest_batch_fields_reject_boundaries_without_narrowing() {
        let canonical = manifest_fixture();
        assert!(validate_manifest(&canonical).is_ok());
        for batch_ticks in [0, 1, 5, 7, 12, u16::MAX] {
            let manifest = GameManifestV1 {
                batch_ticks,
                ..canonical.clone()
            };
            assert!(matches!(
                validate_manifest(&manifest),
                Err(ExecutionProofErrorV1::Statement)
            ));
        }
        for max_input_bytes in [0, 1, 6, 11, 13, u16::MAX] {
            let manifest = GameManifestV1 {
                max_input_bytes,
                ..canonical.clone()
            };
            assert!(matches!(
                validate_manifest(&manifest),
                Err(ExecutionProofErrorV1::Statement)
            ));
        }
        assert!(validate_manifest(&canonical).is_ok());
    }

    #[test]
    fn six_tick_transcript_preserves_exact_control_bytes_and_refuses_partial_batches() {
        let mut replay = ClassedRaceReplayV1 {
            version: 1,
            class_id: ClassedRaceClassV1::TouringS1,
            track: ClassedRaceTrackV1::Harbor,
            player_count: 2,
            frames: (0_u16..6)
                .map(|control| ClassedRaceInputFrameV1 {
                    tick: u32::from(control),
                    controls: vec![control, 63 - control],
                })
                .collect(),
            dnf_events: vec![],
        };
        let transcript = classed_race_game_transcript_v1(&replay).unwrap();
        assert_eq!(transcript.batches.len(), 1);
        assert_eq!(transcript.batches[0].start_tick, 0);
        assert_eq!(
            transcript.batches[0].inputs,
            vec![
                vec![0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0],
                vec![63, 0, 62, 0, 61, 0, 60, 0, 59, 0, 58, 0],
            ]
        );
        assert!(transcript.dnf_events.is_empty());
        replay.frames.push(ClassedRaceInputFrameV1 {
            tick: 6,
            controls: vec![0, 0],
        });
        assert!(matches!(
            classed_race_game_transcript_v1(&replay),
            Err(ExecutionProofErrorV1::Replay)
        ));
        replay.frames.truncate(5);
        assert!(matches!(
            classed_race_game_transcript_v1(&replay),
            Err(ExecutionProofErrorV1::Replay)
        ));
        replay.frames.clear();
        assert!(
            classed_race_game_transcript_v1(&replay)
                .unwrap()
                .batches
                .is_empty()
        );
    }
}
