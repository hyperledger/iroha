//! Focused standalone checks; no registered profile or security qualification is implied.
use super::super::admission::*;
use super::*;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    classed_race_v1::*,
    game::{
        GameAccessV1, GameAdmissionParticipantV1, GameAdmissionResourceV1, GamePayoutPolicyV1,
        game_message_hash_v1, game_roster_hash_v1,
    },
    game_resources::GameResourceReturnPolicyV1,
};

fn request(track: ClassedRaceTrackV1, players: u8, refund: bool) -> ClassedRaceProverRequestV1 {
    let class_id = ClassedRaceClassV1::TouringS1;
    let replay = ClassedRaceReplayV1 {
        version: 1,
        class_id,
        track,
        player_count: players,
        frames: (0..6)
            .map(|tick| ClassedRaceInputFrameV1 {
                tick,
                controls: (0..players)
                    .map(|slot| 1 | 32 | if slot % 2 == 0 { 8 } else { 4 })
                    .collect(),
            })
            .collect(),
        dnf_events: vec![ClassedRaceDnfEventV1 {
            tick: 6,
            slots: (if refund { 0 } else { 1 }..players).collect(),
        }],
    };
    let data = ClassedRaceParticipantDataV1 {
        version: 1,
        class_id,
        skin: 0,
    };
    let admission = GameAdmissionBodyV1 {
        version: 1,
        participants: (0..players)
            .map(|slot| GameAdmissionParticipantV1 {
                account: AccountId::new(
                    KeyPair::try_from_seed(vec![slot + 1; 32], Algorithm::Ed25519)
                        .unwrap()
                        .public_key()
                        .clone(),
                ),
                input_key: KeyPair::try_from_seed(vec![slot + 65; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
                application_data: ClassedRaceParticipantDataV1 {
                    skin: slot % 6,
                    ..data
                }
                .encode(),
            })
            .collect(),
        wagers: vec![],
        resources: (0..players)
            .map(|slot| GameAdmissionResourceV1 {
                slot,
                nft_id: format!("touring{slot}$equipment.universal")
                    .parse()
                    .unwrap(),
                metadata_hash: Hash::new([slot; 32]),
                role_id: classed_race_equipment_role_v1(),
                policy: GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal,
            })
            .collect(),
    };
    let manifest = GameManifestV1 {
        version: 1,
        application_id: Hash::new(b"sora-cars"),
        profile_id: classed_race_profile_id_v1(),
        application_parameters: ClassedRaceParametersV1 {
            version: 1,
            class_id,
            track,
            rules_hash: classed_race_rules_hash_v1(),
            catalog_id: Hash::new(b"reviewed-fixture-catalog"),
        }
        .encode(),
        min_participants: 2,
        max_participants: players,
        batch_ticks: 6,
        max_ticks: 5400,
        max_input_bytes: 12,
        max_participant_data_bytes: data.encode().len() as u16,
        access: GameAccessV1::Public,
        payout_policy: GamePayoutPolicyV1::EqualWinnersOrRefund,
    };
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"classed-proof-test-network"),
    ));
    let session_id = Hash::new(b"classed-proof-test-session");
    let result = classed_race_result_v1(&replay_classed_race_v1(&replay).unwrap()).unwrap();
    let statement = ExecutionPublicInputsV1 {
        network_id,
        session_id,
        manifest_hash: game_message_hash_v1(&network_id, "session-manifest", &manifest),
        roster_hash: game_roster_hash_v1(&network_id, &session_id, &admission),
        transcript_root: classed_race_transcript_root_v1(&network_id, &replay).unwrap(),
        dispute_root: Hash::new(b"externally-authenticated-fixture-dispute-history"),
        outcome_hash: game_message_hash_v1(&network_id, "session-outcome", &outcome(&result)),
    };
    ClassedRaceProverRequestV1 {
        statement,
        manifest,
        admission,
        replay,
        checkpoint_state: None,
    }
}

// A retained-history projection for the bounded six-tick proof fixture. Custody account values
// are test identities; this is not a native ownership/reservation/ledger-finality fixture.
fn retained_session(
    request: &ClassedRaceProverRequestV1,
) -> iroha_data_model::game::GameSessionRecordV1 {
    use iroha_data_model::{asset::AssetDefinitionId, game::*};
    use iroha_model_base::domain::DomainId;
    let replay = &request.replay;
    assert_eq!(replay.frames.len(), 6);
    let checkpoint_state = request.checkpoint_state.as_ref().unwrap();
    let mut empty = replay.clone();
    empty.frames.clear();
    empty.dnf_events.clear();
    let mut checkpoint = GameCheckpointV1 {
        session_id: request.statement.session_id,
        epoch: 0,
        tick: 0,
        terminal: false,
        // Exact current StartGameSessionV1 expression, not an invented adapter genesis root.
        transcript_root: game_message_hash_v1(
            &request.statement.network_id,
            "input-transcript",
            &GameTranscriptV1 {
                batches: vec![],
                dnf_events: vec![],
            },
        ),
        state_root: game_message_hash_v1(
            &request.statement.network_id,
            "simulation-state",
            &checkpoint_state.encode(),
        ),
    };
    assert_eq!(
        checkpoint.transcript_root,
        classed_race_transcript_root_v1(&request.statement.network_id, &empty).unwrap()
    );
    let mut signatures = vec![];
    if checkpoint_state.tick != 0 {
        assert_eq!(checkpoint_state.tick, 6);
        checkpoint.tick = 6;
        checkpoint.epoch = 1;
        let transcript = GameTranscriptV1 {
            batches: vec![GameTranscriptBatchV1 {
                start_tick: 0,
                inputs: (0..replay.player_count)
                    .map(|slot| {
                        replay
                            .frames
                            .iter()
                            .flat_map(|frame| frame.controls[usize::from(slot)].to_le_bytes())
                            .collect()
                    })
                    .collect(),
            }],
            dnf_events: vec![],
        };
        checkpoint.transcript_root = game_message_hash_v1(
            &request.statement.network_id,
            "input-transcript",
            &transcript,
        );
        let hash = game_message_hash_v1(&request.statement.network_id, "checkpoint", &checkpoint);
        signatures = (0..replay.player_count)
            .map(|slot| {
                let key = KeyPair::try_from_seed(vec![slot + 65; 32], Algorithm::Ed25519).unwrap();
                GameSlotSignatureV1 {
                    slot,
                    signature: iroha_crypto::Signature::new(key.private_key(), hash.as_ref()),
                }
            })
            .collect();
    }
    let participants = request
        .admission
        .participants
        .iter()
        .enumerate()
        .map(|(slot, p)| GameParticipantV1 {
            account: p.account.clone(),
            input_key: p.input_key.clone(),
            application_data: p.application_data.clone(),
            dnf_at_tick: replay
                .dnf_events
                .iter()
                .find(|event| event.slots.contains(&(slot as u8)))
                .map(|event| event.tick),
        })
        .collect::<Vec<_>>();
    let mut session = GameSessionRecordV1 {
        version: 1,
        network_id: request.statement.network_id,
        session_id: request.statement.session_id,
        manifest: request.manifest.clone(),
        profile_id: request.manifest.profile_id,
        manifest_hash: request.statement.manifest_hash,
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("session", "universal").unwrap(),
            "xor".parse().unwrap(),
        ),
        stake: 0_u32.into(),
        payout_scale: 0,
        custody: AccountId::new(
            KeyPair::try_from_seed(vec![100; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        ),
        liability: 0_u32.into(),
        payout_claims: vec![],
        item_stakes: vec![],
        resources: request
            .admission
            .resources
            .iter()
            .map(|resource| GameResourceReservationRecordV1 {
                slot: resource.slot,
                nft_id: resource.nft_id.clone(),
                metadata_hash: resource.metadata_hash,
                role_id: resource.role_id,
                policy: resource.policy,
                original_owner: participants[usize::from(resource.slot)].account.clone(),
                custody: AccountId::new(
                    KeyPair::try_from_seed(vec![101 + resource.slot; 32], Algorithm::Ed25519)
                        .unwrap()
                        .public_key()
                        .clone(),
                ),
                reserved_at_height: 2,
                released_at_height: None,
            })
            .collect(),
        participants,
        roster_hash: request.statement.roster_hash,
        phase: GamePhaseV1::AwaitingProof,
        revision: 3,
        epoch: 2,
        deadline_height: 30,
        checkpoint: Some(SignedGameCheckpointV1 {
            checkpoint,
            signatures,
        }),
        pending_certificate: None,
        next_tick: 12,
        input_commitments: vec![None; usize::from(replay.player_count)],
        input_reveals: vec![None; usize::from(replay.player_count)],
        transcript_anchors: vec![GameTranscriptAnchorV1 {
            tick: checkpoint.tick,
            transcript_root: checkpoint.transcript_root,
        }],
        forced_batches: vec![
            GameForcedBatchV1 {
                epoch: 0,
                start_tick: 0,
                inputs: (0..replay.player_count)
                    .map(|slot| {
                        replay
                            .frames
                            .iter()
                            .flat_map(|frame| frame.controls[usize::from(slot)].to_le_bytes())
                            .collect()
                    })
                    .collect(),
                dnf_slots: vec![],
            },
            GameForcedBatchV1 {
                epoch: 1,
                start_tick: 6,
                inputs: (0..replay.player_count)
                    .map(|slot| {
                        if replay.dnf_events[0].slots.contains(&slot) {
                            vec![]
                        } else {
                            vec![0; 12]
                        }
                    })
                    .collect(),
                dnf_slots: replay.dnf_events[0].slots.clone(),
            },
        ],
        dispute_root: Hash::new(b"temporary"),
        verification_id: None,
        terminal_at_height: None,
        result: None,
    };
    session.dispute_root = super::super::history::classed_race_dispute_root_v1(&session);
    session
}

#[test]
fn touring_history_checks_native_genesis_forced_inputs_and_canonical_removals() {
    use super::super::history::{classed_race_dispute_root_v1, validate_history};
    let mut request = request(ClassedRaceTrackV1::Harbor, 2, false);
    request.checkpoint_state = Some(
        initial_classed_race_state_v1(request.replay.class_id, request.replay.track, 2).unwrap(),
    );
    let original = retained_session(&request);
    request.statement.dispute_root = original.dispute_root;
    let payload = payload_from_request(&request).unwrap();
    let result = outcome(&payload.result);
    validate_history(&original, &result, &request.statement, &payload).unwrap();
    for mutation in [
        "checkpoint-missing",
        "checkpoint-prefix",
        "checkpoint-state",
        "checkpoint-epoch",
        "checkpoint-terminal",
        "checkpoint-session",
        "checkpoint-signature",
        "anchor",
        "anchor-tick",
        "controls",
        "input-length",
        "input-mask",
        "removed-input",
        "dnf-list",
        "dnf-marker",
        "late-dnf",
        "batch-epoch",
        "session-epoch",
        "batch-gap",
        "batch-overlap",
        "batch-round",
        "future-batch",
        "next-tick",
        "resource-owner",
        "resource-metadata",
    ] {
        let mut session = original.clone();
        match mutation {
            "checkpoint-missing" => session.checkpoint = None,
            "checkpoint-prefix" => {
                session
                    .checkpoint
                    .as_mut()
                    .unwrap()
                    .checkpoint
                    .transcript_root = Hash::new(b"forged prefix")
            }
            "checkpoint-state" => {
                session.checkpoint.as_mut().unwrap().checkpoint.state_root =
                    Hash::new(b"forged state")
            }
            "checkpoint-epoch" => session.checkpoint.as_mut().unwrap().checkpoint.epoch = 1,
            "checkpoint-terminal" => {
                session.checkpoint.as_mut().unwrap().checkpoint.terminal = true
            }
            "checkpoint-session" => {
                session.checkpoint.as_mut().unwrap().checkpoint.session_id =
                    Hash::new(b"foreign session")
            }
            "checkpoint-signature" => {
                let key = KeyPair::try_from_seed(vec![65; 32], Algorithm::Ed25519).unwrap();
                session.checkpoint.as_mut().unwrap().signatures.push(
                    iroha_data_model::game::GameSlotSignatureV1 {
                        slot: 0,
                        signature: iroha_crypto::Signature::new(key.private_key(), b"wrong"),
                    },
                );
            }
            "anchor" => session.transcript_anchors[0].transcript_root = Hash::new(b"forged anchor"),
            "anchor-tick" => session.transcript_anchors[0].tick = 6,
            "controls" => session.forced_batches[0].inputs[0][0] ^= 1,
            "input-length" => {
                session.forced_batches[0].inputs[0].pop();
            }
            "input-mask" => session.forced_batches[0].inputs[0][0] = 64,
            "removed-input" => session.forced_batches[1].inputs[1] = vec![0; 12],
            "dnf-list" => session.forced_batches[1].dnf_slots.clear(),
            "dnf-marker" => session.participants[1].dnf_at_tick = None,
            "late-dnf" => session.participants[1].dnf_at_tick = Some(12),
            "batch-epoch" => session.forced_batches[0].epoch = 1,
            "session-epoch" => session.epoch = 3,
            "batch-gap" => session.forced_batches[0].start_tick = 6,
            "batch-overlap" => session.forced_batches[1].start_tick = 0,
            "batch-round" => session.forced_batches[1].start_tick = 5,
            "future-batch" => {
                let mut batch = session.forced_batches[1].clone();
                batch.epoch = 2;
                batch.start_tick = 12;
                session.forced_batches.push(batch);
                session.epoch = 3;
                session.next_tick = 18;
            }
            "next-tick" => session.next_tick = 18,
            "resource-owner" => {
                session.resources[0].original_owner = session.participants[1].account.clone()
            }
            "resource-metadata" => {
                session.resources[0].metadata_hash = Hash::new(b"forged resource")
            }
            _ => unreachable!(),
        }
        session.dispute_root = classed_race_dispute_root_v1(&session);
        let mut statement = request.statement;
        statement.dispute_root = session.dispute_root;
        assert!(
            validate_history(&session, &result, &statement, &payload).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn touring_nonzero_checkpoint_requires_every_original_input_key_signature() {
    use super::super::history::{classed_race_dispute_root_v1, validate_history};
    let mut request = request(ClassedRaceTrackV1::Harbor, 2, false);
    let mut prefix = request.replay.clone();
    prefix.dnf_events.clear();
    request.checkpoint_state = Some(replay_classed_race_v1(&prefix).unwrap());
    let original = retained_session(&request);
    request.statement.dispute_root = original.dispute_root;
    let payload = payload_from_request(&request).unwrap();
    let result = outcome(&payload.result);
    validate_history(&original, &result, &request.statement, &payload).unwrap();
    for mutation in [
        "removed-key-missing",
        "signature-order",
        "wrong-signature",
        "wrong-terminal",
        "wrong-prefix",
    ] {
        let mut session = original.clone();
        let signed = session.checkpoint.as_mut().unwrap();
        match mutation {
            "removed-key-missing" => {
                signed.signatures.pop();
            }
            "signature-order" => signed.signatures.swap(0, 1),
            "wrong-signature" => {
                let key = KeyPair::try_from_seed(vec![65; 32], Algorithm::Ed25519).unwrap();
                signed.signatures[0].signature =
                    iroha_crypto::Signature::new(key.private_key(), b"other checkpoint");
            }
            "wrong-terminal" => signed.checkpoint.terminal = true,
            "wrong-prefix" => signed.checkpoint.transcript_root = Hash::new(b"other prefix"),
            _ => unreachable!(),
        }
        session.dispute_root = classed_race_dispute_root_v1(&session);
        let mut statement = request.statement;
        statement.dispute_root = session.dispute_root;
        assert!(
            validate_history(&session, &result, &statement, &payload).is_err(),
            "{mutation}"
        );
    }
}

fn recommit(statement: &mut ExecutionPublicInputsV1, payload: &ClassedRaceProofPayloadV1) {
    statement.manifest_hash =
        game_message_hash_v1(&statement.network_id, "session-manifest", &payload.manifest);
    statement.roster_hash = game_roster_hash_v1(
        &statement.network_id,
        &statement.session_id,
        &payload.admission,
    );
    statement.transcript_root =
        classed_race_transcript_root_v1(&statement.network_id, &payload.replay)
            .unwrap_or_else(|_| Hash::new(b"invalid replay"));
    statement.outcome_hash = game_message_hash_v1(
        &statement.network_id,
        "session-outcome",
        &outcome(&payload.result),
    );
}

#[test]
fn touring_admission_requires_one_exact_role_and_canonical_class_per_slot() {
    let request = request(ClassedRaceTrackV1::Harbor, 2, false);
    let original = payload_from_request(&request).unwrap();
    for mutation in [
        "missing",
        "duplicate",
        "wrong-role",
        "wrong-slot",
        "overlap",
        "class-version",
        "class-tag",
        "skin",
        "class-suffix",
        "rules",
        "parameter-suffix",
        "input-key",
    ] {
        let mut payload = original.clone();
        match mutation {
            "missing" => {
                payload.admission.resources.pop();
            }
            "duplicate" => payload
                .admission
                .resources
                .push(payload.admission.resources[0].clone()),
            "wrong-role" => payload.admission.resources[0].role_id = Hash::new(b"alternate-role"),
            "wrong-slot" => payload.admission.resources[0].slot = 1,
            "overlap" => {
                payload.admission.resources[1].nft_id =
                    payload.admission.resources[0].nft_id.clone()
            }
            "class-version" => {
                payload.admission.participants[0].application_data = ClassedRaceParticipantDataV1 {
                    version: 2,
                    class_id: ClassedRaceClassV1::TouringS1,
                    skin: 0,
                }
                .encode()
            }
            "class-tag" => {
                payload.admission.participants[0].application_data = vec![255; 20];
            }
            "skin" => {
                payload.admission.participants[0].application_data = ClassedRaceParticipantDataV1 {
                    version: 1,
                    class_id: ClassedRaceClassV1::TouringS1,
                    skin: 6,
                }
                .encode()
            }
            "class-suffix" => payload.admission.participants[0].application_data.push(0),
            "rules" => {
                let mut p: ClassedRaceParametersV1 =
                    decode_exact(&payload.manifest.application_parameters, 256).unwrap();
                p.rules_hash = Hash::new(b"wrong rules");
                payload.manifest.application_parameters = p.encode();
            }
            "parameter-suffix" => payload.manifest.application_parameters.push(0),
            "input-key" => {
                payload.admission.participants[1].input_key =
                    payload.admission.participants[0].input_key.clone()
            }
            _ => unreachable!(),
        }
        let mut statement = request.statement;
        recommit(&mut statement, &payload);
        assert!(
            validate_payload(&statement, &payload).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn touring_rejects_prefixes_malformed_inputs_and_incorrect_terminal_rankings() {
    let request = request(ClassedRaceTrackV1::Sakura, 2, false);
    let original = payload_from_request(&request).unwrap();
    for mutation in [
        "prefix",
        "control",
        "control-count",
        "tick-gap",
        "version",
        "dnf-order",
        "dnf-slot",
        "dnf-duplicate",
        "dnf-round",
        "state-overflow",
        "result",
        "winner",
        "finish",
        "checkpoint",
    ] {
        let mut payload = original.clone();
        match mutation {
            "prefix" => {
                payload.replay.dnf_events.clear();
                payload.final_state = replay_classed_race_v1(&payload.replay).unwrap();
                payload.result = classed_race_result_v1(&payload.final_state).unwrap();
            }
            "control" => payload.replay.frames[0].controls[0] = 64,
            "control-count" => {
                payload.replay.frames[0].controls.pop();
            }
            "tick-gap" => payload.replay.frames[0].tick = 1,
            "version" => payload.replay.version = 2,
            "dnf-order" => payload.replay.dnf_events[0].slots = vec![1, 0],
            "dnf-slot" => payload.replay.dnf_events[0].slots = vec![2],
            "dnf-duplicate" => payload
                .replay
                .dnf_events
                .push(payload.replay.dnf_events[0].clone()),
            "dnf-round" => payload.replay.dnf_events[0].tick = 5,
            "state-overflow" => payload.final_state.cars[0].speed_mm_per_tick = 3301,
            "result" => payload.result.standings.reverse(),
            "winner" => payload.result.winners = vec![1],
            "finish" => payload.final_state.cars[0].finish_tick = Some(7),
            "checkpoint" => {
                let mut state =
                    initial_classed_race_state_v1(payload.replay.class_id, payload.replay.track, 2)
                        .unwrap();
                state.tick = 7;
                payload.checkpoint_state = Some(state);
            }
            _ => unreachable!(),
        }
        let mut statement = request.statement;
        recommit(&mut statement, &payload);
        assert!(
            validate_payload(&statement, &payload).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn touring_exact_dimensions_and_native_wire_bounds_cover_all_tracks_rosters_and_logs() {
    use crate::execution_proofs::stark::aggregate_stark::{
        AggregateProofLayoutV1, AggregateTraceGroupLayoutV1,
        maximum_encoded_proof_with_deep_bytes_v1,
    };
    let mut maximum = 0;
    for (track, expected_width) in [
        (ClassedRaceTrackV1::NeonTokyo, 406),
        (ClassedRaceTrackV1::Harbor, 409),
        (ClassedRaceTrackV1::Sakura, 405),
    ] {
        for players in 2..=8 {
            let request = request(track, players, true);
            let payload = payload_from_request(&request).unwrap();
            let adapter = ClassedRaceAdapterV1::new(&request.statement, &payload).unwrap();
            assert!(adapter.compiled.width() <= MAX_AIR_COLUMNS);
            if players == 8 {
                assert_eq!(adapter.compiled.width(), expected_width);
                assert_eq!(adapter.compiled.rows_per_tick(), 85);
            }
            for trace_log in MIN_TRACE_LOG2..=MAX_TRACE_LOG2 {
                let parameters = adapter.protocol_v1().parameters;
                let layout = AggregateProofLayoutV1::new(
                    parameters,
                    vec![AggregateTraceGroupLayoutV1 {
                        native_trace_log2: trace_log,
                        segment_instances: 1,
                        base_width: adapter.base_width_v1(),
                        aux_width: NOTE_COPY_AUX_WIDTH_V1,
                    }],
                )
                .unwrap();
                let bound = maximum_encoded_proof_with_deep_bytes_v1(parameters, &layout).unwrap();
                assert!(bound <= CLASSED_RACE_MAX_STARK_BYTES_V1);
                maximum = maximum.max(bound);
            }
        }
    }
    eprintln!(
        "Touring maximum native cryptographic wire bound={maximum}; no generated maximum-duration proof or soundness claim"
    );
}

#[test]
fn touring_forged_in_bounds_final_state_fails_actual_arithmetic_boundary() {
    let request = request(ClassedRaceTrackV1::NeonTokyo, 2, false);
    let mut payload = payload_from_request(&request).unwrap();
    payload.final_state.cars[0].progress_mm += 1;
    payload.result = classed_race_result_v1(&payload.final_state).unwrap();
    let mut statement = request.statement;
    recommit(&mut statement, &payload);
    // Public shape and all user-supplied hashes are coherent; only the actual physics is false.
    validate_payload(&statement, &payload).unwrap();
    let adapter = ClassedRaceAdapterV1::new(&statement, &payload).unwrap();
    let columns = witness_columns(&adapter).unwrap();
    let size = adapter.compiled.trace_size();
    let final_row = (payload.replay.frames.len() + 1) * adapter.compiled.rows_per_tick();
    let current: Vec<_> = columns
        .iter()
        .skip(NOTE_COPY_WIDTH_V1)
        .map(|column| column[final_row])
        .collect();
    let next: Vec<_> = columns
        .iter()
        .skip(NOTE_COPY_WIDTH_V1)
        .map(|column| column[final_row + 1])
        .collect();
    let fixed: Vec<_> = adapter
        .compiled
        .fixed_row(final_row, size)
        .unwrap()
        .into_iter()
        .map(field)
        .collect();
    assert!(
        adapter
            .compiled
            .residues(&current, &next, &fixed)
            .iter()
            .any(|value| *value != F::ZERO)
    );
}

#[test]
fn touring_maximum_complete_envelope_includes_wagers_equipment_and_both_state_options() {
    use iroha_data_model::game::{
        GAME_ADMISSION_MAX_ACCOUNT_ENCODED_BYTES_V1, GAME_ADMISSION_MAX_NFT_ENCODED_BYTES_V1,
    };
    let request = request(ClassedRaceTrackV1::Harbor, 8, true);
    let mut payload = payload_from_request(&request).unwrap();
    // Saturate codec shapes, not a reachable race. This is an upper bound on every valid
    // state/option combination and every complete 8-car replay, not an accepted proof.
    payload.replay.frames = (0..5400)
        .map(|tick| ClassedRaceInputFrameV1 {
            tick,
            controls: vec![63; 8],
        })
        .collect();
    payload.replay.dnf_events = (0..8)
        .map(|slot| ClassedRaceDnfEventV1 {
            tick: u32::from(slot) * 6,
            slots: vec![slot],
        })
        .collect();
    payload.final_state.tick = 5400;
    for car in &mut payload.final_state.cars {
        car.finish_tick = Some(5400);
        car.dnf_tick = Some(5400);
    }
    payload.checkpoint_state = Some(payload.final_state.clone());
    payload.result.ticks = 5400;
    payload.result.winners = (0..8).collect();
    for standing in &mut payload.result.standings {
        standing.finish_tick = Some(5400);
        standing.dnf_tick = Some(5400);
    }
    // Each field/element gets the full ten-byte u64 framing allowance. This covers
    // canonical compact or fixed lengths without inventing invalid maximum-size accounts.
    let framed = |bytes: usize| bytes + 10;
    let hash = Hash::new(b"bounded hash").encode().len();
    let slot = 0_u8.encode().len();
    let participant_bound = framed(GAME_ADMISSION_MAX_ACCOUNT_ENCODED_BYTES_V1)
        + framed(payload.admission.participants[0].input_key.encode().len())
        + framed(
            payload.admission.participants[0]
                .application_data
                .encode()
                .len(),
        );
    let wager_bound = framed(slot) + framed(GAME_ADMISSION_MAX_NFT_ENCODED_BYTES_V1) + framed(hash);
    let resource_bound = framed(slot)
        + framed(GAME_ADMISSION_MAX_NFT_ENCODED_BYTES_V1)
        + framed(hash)
        + framed(hash)
        + framed(
            GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal
                .encode()
                .len(),
        );
    let admission_bound = framed(1_u16.encode().len())
        + framed(8 + 8 * framed(participant_bound))
        + framed(8 + 8 * framed(wager_bound))
        + framed(8 + 8 * framed(resource_bound));
    assert!(payload.admission.encode().len() <= admission_bound);
    let admission_allowance = admission_bound - payload.admission.encode().len() + 40;
    // Use the admission cap even though the exact native maximum-frontier proof is smaller.
    payload.stark_bytes = vec![0; CLASSED_RACE_MAX_STARK_BYTES_V1];
    let envelope = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: classed_race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    let invitation_allowance = vec![0_u8; iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1]
        .encode()
        .len()
        + 64;
    let envelope_bound = envelope.encode().len() + invitation_allowance + admission_allowance;
    eprintln!(
        "Touring complete envelope cap-bound={envelope_bound}; admission_bound={admission_bound}; invitation_allowance={invitation_allowance}; full replay, 8 wagers, 8 equipment kits, maximum supported account encodings, full checkpoint and terminal options"
    );
    assert!(envelope_bound <= CLASSED_RACE_MAX_PROOF_BYTES_V1);
    // Decoding this deliberately unreachable maximum shape is not verification acceptance.
    assert!(decode_payload(&envelope).is_ok());
    assert!(verify_classed_race_proof_v1(&request.statement, &envelope).is_err());
}

#[test]
fn touring_valid_public_claim_rejects_zero_wire_at_cryptographic_verification() {
    let request = request(ClassedRaceTrackV1::NeonTokyo, 2, false);
    let mut payload = payload_from_request(&request).unwrap();
    payload.stark_bytes = vec![0; 64];
    validate_payload(&request.statement, &payload).unwrap();
    let envelope = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: classed_race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    decode_payload(&envelope).unwrap();
    assert!(matches!(
        verify_classed_race_proof_v1(&request.statement, &envelope),
        Err(ExecutionProofErrorV1::Cryptography(_))
    ));
}

#[test]
fn touring_full_duration_whole_tick_and_staged_states_match_reference() {
    use super::super::{
        race_air::{ClassedRaceAirV1, car_values},
        reference::{apply_classed_race_dnf_v1, step_classed_race_v1},
    };
    for track in [
        ClassedRaceTrackV1::NeonTokyo,
        ClassedRaceTrackV1::Harbor,
        ClassedRaceTrackV1::Sakura,
    ] {
        // The same full-duration controls and removal as the staged residue regression.
        let replay = ClassedRaceReplayV1 {
            version: 1,
            class_id: ClassedRaceClassV1::TouringS1,
            track,
            player_count: 8,
            frames: (0..5400)
                .map(|tick| ClassedRaceInputFrameV1 {
                    tick,
                    controls: (0..8)
                        .map(|slot| ((tick * 17 + slot * 11) % 64) as u16)
                        .collect(),
                })
                .collect(),
            dnf_events: vec![ClassedRaceDnfEventV1 {
                tick: 1200,
                slots: vec![7],
            }],
        };
        let final_state = replay_classed_race_v1(&replay).unwrap();
        let mut prefix = replay.clone();
        prefix.frames.truncate(1200);
        prefix.dnf_events.clear();
        let checkpoint = replay_classed_race_v1(&prefix).unwrap();
        let whole = ClassedRaceAirV1::compile(&replay, &final_state, Some(&checkpoint)).unwrap();
        let staged =
            StagedClassedRaceAirV1::compile(&replay, &final_state, Some(&checkpoint)).unwrap();
        let mut state = initial_classed_race_state_v1(replay.class_id, track, 8).unwrap();
        let mut carry = staged.initial_carry();
        let whole_size = (replay.frames.len() + 2).next_power_of_two();
        for index in 0..staged.trace_size() {
            let tick = index / staged.rows_per_tick();
            if index % staged.rows_per_tick() == 0 {
                let input = state.cars.iter().flat_map(car_values).collect::<Vec<_>>();
                assert_eq!(&carry[..56], &input, "{track:?} carried tick {tick}");
                let fixed = whole.fixed_row(tick, whole_size).unwrap();
                let row = whole.air.witness(&input, &fixed);
                if let Some(event) = replay
                    .dnf_events
                    .iter()
                    .find(|event| event.tick as usize == tick)
                {
                    apply_classed_race_dnf_v1(&mut state, &event.slots).unwrap();
                }
                if let Some(frame) = replay.frames.get(tick) {
                    step_classed_race_v1(&mut state, frame).unwrap();
                }
                assert_eq!(
                    whole.next_inputs(&row),
                    state.cars.iter().flat_map(car_values).collect::<Vec<_>>(),
                    "{track:?} whole tick {tick}"
                );
            }
            let fixed = staged.fixed_row(index, staged.trace_size()).unwrap();
            let (_, next) = staged.witness(&carry, &fixed);
            carry = next;
            if (index + 1) % staged.rows_per_tick() == 0 || index + 1 == staged.trace_size() {
                assert_eq!(
                    &carry[..56],
                    &state.cars.iter().flat_map(car_values).collect::<Vec<_>>(),
                    "{track:?} staged row {index}"
                );
            }
        }
        assert_eq!(state, final_state);
        eprintln!(
            "Touring full whole/staged/reference parity {track:?}: 8 cars, 5400 ticks, {} padded rows, whole columns={}, staged columns={}",
            staged.trace_size(),
            whole.air.width(),
            staged.width()
        );
    }
}

fn residues_are_zero(request: &ClassedRaceProverRequestV1) -> bool {
    let payload = payload_from_request(request).unwrap();
    let adapter = ClassedRaceAdapterV1::new(&request.statement, &payload).unwrap();
    let columns = witness_columns(&adapter).unwrap();
    let size = adapter.compiled.trace_size();
    (0..size).all(|row| {
        let current: Vec<_> = columns
            .iter()
            .skip(NOTE_COPY_WIDTH_V1)
            .map(|column| column[row])
            .collect();
        let next: Vec<_> = columns
            .iter()
            .skip(NOTE_COPY_WIDTH_V1)
            .map(|column| column[(row + 1) % size])
            .collect();
        let fixed: Vec<_> = adapter
            .compiled
            .fixed_row(row, size)
            .unwrap()
            .into_iter()
            .map(field)
            .collect();
        adapter
            .compiled
            .residues(&current, &next, &fixed)
            .iter()
            .all(|value| *value == F::ZERO)
    })
}

fn refresh_request_statement(request: &mut ClassedRaceProverRequestV1) {
    let final_state = replay_classed_race_v1(&request.replay).unwrap();
    request.statement.transcript_root =
        classed_race_transcript_root_v1(&request.statement.network_id, &request.replay).unwrap();
    request.statement.outcome_hash = game_message_hash_v1(
        &request.statement.network_id,
        "session-outcome",
        &outcome(&classed_race_result_v1(&final_state).unwrap()),
    );
}

#[test]
fn touring_zero_tick_and_nonempty_checkpoints_bind_pre_removal_boundaries() {
    let mut request = request(ClassedRaceTrackV1::Harbor, 2, true);
    request.replay.frames.clear();
    request.replay.dnf_events[0].tick = 0;
    refresh_request_statement(&mut request);
    assert!(residues_are_zero(&request));
    request.checkpoint_state = Some(
        initial_classed_race_state_v1(request.replay.class_id, request.replay.track, 2).unwrap(),
    );
    assert!(
        residues_are_zero(&request),
        "zero checkpoint constrains the pre-removal grid"
    );
    request.checkpoint_state = Some(replay_classed_race_v1(&request.replay).unwrap());
    assert!(
        !residues_are_zero(&request),
        "post-removal final state cannot replace the pre-removal checkpoint at tick zero"
    );

    let mut request = self::request(ClassedRaceTrackV1::Harbor, 2, false);
    let mut prefix = request.replay.clone();
    prefix.dnf_events.clear();
    let checkpoint = replay_classed_race_v1(&prefix).unwrap();
    request.checkpoint_state = Some(checkpoint.clone());
    assert!(
        residues_are_zero(&request),
        "same-tick checkpoint preserves the state certified before removal"
    );
    request.checkpoint_state = Some(replay_classed_race_v1(&request.replay).unwrap());
    assert!(
        !residues_are_zero(&request),
        "post-removal checkpoint cannot replace the certified pre-removal state"
    );
    request
        .replay
        .frames
        .extend((6..12).map(|tick| ClassedRaceInputFrameV1 {
            tick,
            controls: vec![1, 1],
        }));
    request.replay.dnf_events[0].tick = 12;
    request.checkpoint_state = Some(checkpoint);
    refresh_request_statement(&mut request);
    assert!(
        residues_are_zero(&request),
        "a nonempty interior checkpoint is constrained through terminal padding"
    );
}

#[test]
#[ignore = "real standalone Touring STARK proofs; run explicitly in a retained native corridor"]
fn touring_native_stark_all_three_tracks_and_adversarial_bindings() {
    for (track, refund) in [
        (ClassedRaceTrackV1::NeonTokyo, false),
        (ClassedRaceTrackV1::Harbor, true),
        (ClassedRaceTrackV1::Sakura, false),
    ] {
        let mut request = request(track, 2, refund);
        request.checkpoint_state =
            Some(initial_classed_race_state_v1(request.replay.class_id, track, 2).unwrap());
        if track == ClassedRaceTrackV1::Harbor {
            let mut prefix = request.replay.clone();
            prefix.dnf_events.clear();
            request.checkpoint_state = Some(replay_classed_race_v1(&prefix).unwrap());
        }
        let session = retained_session(&request);
        request.statement.dispute_root = session.dispute_root;
        let envelope = prove_classed_race_v1(request.clone()).unwrap();
        let result = verify_classed_race_proof_v1(&request.statement, &envelope).unwrap();
        assert_eq!(
            super::super::history::verify_classed_race_proof_for_session_v1(
                &session,
                &outcome(&result),
                &envelope
            )
            .unwrap(),
            result
        );
        let mut changed_history = session.clone();
        changed_history.forced_batches[0].inputs[0][0] ^= 1;
        changed_history.dispute_root =
            super::super::history::classed_race_dispute_root_v1(&changed_history);
        assert!(
            super::super::history::verify_classed_race_proof_for_session_v1(
                &changed_history,
                &outcome(&result),
                &envelope
            )
            .is_err()
        );
        assert_eq!(result.winners, if refund { vec![] } else { vec![0] });
        let original = decode_payload(&envelope).unwrap();
        eprintln!(
            "Touring {:?}: profile={} ticks=6 players=2 columns={} stark_bytes={} envelope_bytes={}",
            track,
            envelope.profile_id,
            ClassedRaceAdapterV1::new(&request.statement, &original)
                .unwrap()
                .base_width_v1(),
            original.stark_bytes.len(),
            envelope.encode().len()
        );
        if let Some(dir) = std::env::var_os("IROHA_CLASSED_STARK_OUTPUT") {
            std::fs::write(
                std::path::PathBuf::from(dir).join(format!("{track:?}.nrt")),
                envelope.encode(),
            )
            .unwrap();
        }
        // All mutations retain the genuine cryptographic wire. Recommitments deliberately
        // satisfy public hash checks so cryptographic instance binding must reject them.
        if track != ClassedRaceTrackV1::NeonTokyo {
            continue;
        }
        for mutation in [
            "network",
            "session",
            "dispute",
            "equipment-metadata",
            "equipment-id",
            "catalog",
            "input-key",
            "controls",
            "state",
            "checkpoint",
            "wire",
            "suffix",
            "profile",
            "envelope-version",
        ] {
            let mut forged = envelope.clone();
            let mut payload = original.clone();
            match mutation {
                "network" => {
                    forged.statement.network_id =
                        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                            Hash::new(b"another-network"),
                        ))
                }
                "session" => forged.statement.session_id = Hash::new(b"another-session"),
                "dispute" => forged.statement.dispute_root = Hash::new(b"another-dispute-history"),
                "equipment-metadata" => {
                    payload.admission.resources[0].metadata_hash = Hash::new(b"forged-metadata")
                }
                "equipment-id" => {
                    payload.admission.resources[0].nft_id =
                        "foreign$equipment.universal".parse().unwrap()
                }
                "catalog" => {
                    let mut p: ClassedRaceParametersV1 =
                        decode_exact(&payload.manifest.application_parameters, 256).unwrap();
                    p.catalog_id = Hash::new(b"foreign-catalog");
                    payload.manifest.application_parameters = p.encode();
                }
                "input-key" => {
                    payload.admission.participants[0].input_key =
                        KeyPair::try_from_seed(vec![99; 32], Algorithm::Ed25519)
                            .unwrap()
                            .public_key()
                            .clone()
                }
                "controls" => payload.replay.frames[0].controls[0] ^= 1,
                "state" => {
                    payload.final_state.cars[0].progress_mm += 1;
                    payload.result = classed_race_result_v1(&payload.final_state).unwrap();
                }
                "checkpoint" => payload.checkpoint_state.as_mut().unwrap().cars[0].lateral_mm += 1,
                "wire" => {
                    let index = payload.stark_bytes.len() / 2;
                    payload.stark_bytes[index] ^= 1;
                }
                "suffix" => payload.stark_bytes.push(0),
                "profile" => forged.profile_id = Hash::new(b"uncompiled-profile"),
                "envelope-version" => forged.version = 2,
                _ => unreachable!(),
            }
            recommit(&mut forged.statement, &payload);
            forged.proof_bytes = payload.encode();
            assert!(
                verify_classed_race_proof_v1(&forged.statement, &forged).is_err(),
                "accepted {mutation}"
            );
        }
        let mut expected = request.statement;
        expected.dispute_root = Hash::new(b"different-ledger-history");
        assert!(verify_classed_race_proof_v1(&expected, &envelope).is_err());
        let mut suffix = envelope.clone();
        suffix.proof_bytes.push(0);
        assert!(verify_classed_race_proof_v1(&request.statement, &suffix).is_err());
    }
}

#[test]
#[ignore = "full eight-car 5400-tick native Touring benchmark; coordinate the memory lane"]
fn touring_native_full_eight_car_timeout_proof_and_separate_verification() {
    use super::super::history::{
        classed_race_dispute_root_v1, verify_classed_race_proof_for_session_v1,
    };
    use iroha_data_model::game::GameForcedBatchV1;
    let output = std::path::PathBuf::from(
        std::env::var_os("IROHA_CLASSED_STARK_OUTPUT")
            .expect("explicit retained proof output directory"),
    );
    let mut request = request(ClassedRaceTrackV1::Harbor, 8, false);
    request.checkpoint_state = Some(
        initial_classed_race_state_v1(request.replay.class_id, request.replay.track, 8).unwrap(),
    );
    let mut session = retained_session(&request);
    request.replay.frames = (0..5400)
        .map(|tick| ClassedRaceInputFrameV1 {
            tick,
            controls: (0..8)
                .map(|slot| {
                    // Each 360-tick cycle drives for120 ticks, then brakes for240. Even bounding
                    // all120 ticks at3300 plus a full braking tail gives <7.2km over15 cycles;
                    // every car therefore remains eligible until the exact5400-tick timeout.
                    let drive = if tick % 360 < 120 { 1 | 32 } else { 2 };
                    let steer = match (tick / 45 + slot) % 4 {
                        0 => 4,
                        1 => 8,
                        _ => 0,
                    };
                    drive | steer | if (tick + slot * 7) % 90 < 20 { 16 } else { 0 }
                })
                .collect(),
        })
        .collect();
    request.replay.dnf_events.clear();
    refresh_request_statement(&mut request);
    for participant in &mut session.participants {
        participant.dnf_at_tick = None;
    }
    session.transcript_anchors.clear();
    session.forced_batches = request
        .replay
        .frames
        .chunks(6)
        .enumerate()
        .map(|(epoch, frames)| GameForcedBatchV1 {
            epoch: epoch as u64,
            start_tick: frames[0].tick,
            dnf_slots: vec![],
            inputs: (0..8)
                .map(|slot| {
                    frames
                        .iter()
                        .flat_map(|frame| frame.controls[slot].to_le_bytes())
                        .collect()
                })
                .collect(),
        })
        .collect();
    session.epoch = 900;
    session.next_tick = 5400;
    session.dispute_root = classed_race_dispute_root_v1(&session);
    request.statement.dispute_root = session.dispute_root;
    let reference = replay_classed_race_v1(&request.replay).unwrap();
    assert_eq!(reference.tick, 5400);
    assert!(
        reference
            .cars
            .iter()
            .all(|car| car.finish_tick.is_none() && car.dnf_tick.is_none())
    );
    let expected_result = classed_race_result_v1(&reference).unwrap();
    std::fs::write(output.join("request.nrt"), request.encode()).unwrap();
    std::fs::write(output.join("session.nrt"), session.encode()).unwrap();
    let started = std::time::Instant::now();
    let envelope = prove_classed_race_v1(request).unwrap();
    let prove_seconds = started.elapsed().as_secs_f64();
    std::fs::write(output.join("proof.nrt"), envelope.encode()).unwrap();
    let verification = std::time::Instant::now();
    assert_eq!(
        verify_classed_race_proof_for_session_v1(&session, &outcome(&expected_result), &envelope)
            .unwrap(),
        expected_result
    );
    let verify_seconds = verification.elapsed().as_secs_f64();
    let payload = decode_payload(&envelope).unwrap();
    let adapter = ClassedRaceAdapterV1::new(&envelope.statement, &payload).unwrap();
    let metrics = format!(
        "{{\"profile_id\":\"{}\",\"players\":8,\"ticks\":5400,\"track\":\"harbor\",\"trace_rows\":{},\"base_columns\":{},\"stark_bytes\":{},\"envelope_bytes\":{},\"prove_and_self_verify_seconds\":{prove_seconds},\"separate_history_and_proof_verify_seconds\":{verify_seconds},\"qualified\":false,\"registry_activated\":false}}\n",
        envelope.profile_id,
        adapter.compiled.trace_size(),
        adapter.base_width_v1(),
        payload.stark_bytes.len(),
        envelope.encode().len()
    );
    std::fs::write(output.join("metrics.json"), &metrics).unwrap();
    eprintln!("{metrics}");
}
