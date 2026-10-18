//! Qualification tests for the canonical stock adapter and its native engine.

use super::*;

#[test]
fn borrowed_execution_domains_preserve_refusal_order_and_exact_transcript_framing() {
    use crate::execution_proofs::stark::aggregate_stark as aggregate;

    let domains = DOMAINS;
    let original = domains;
    let profile = GoldilocksDigest384V1::default();
    let make_transcript = || {
        TransparentTranscriptV1::new(
            domains.digest_context,
            b"borrowed-execution-domain-test-v1",
            &profile,
            &profile,
        )
        .unwrap()
    };
    let mut actual = make_transcript();
    let initial_state = actual.state();
    let mut invalid = domains;
    invalid.digest_context =
        TransparentStarkDigestContextV1::execution_v1(b"borrowed-domain-other-profile-v1");
    invalid.query_seed = invalid.base_leaf;
    assert_eq!(
        aggregate::absorb_base_roots_v1(&mut actual, &invalid, &[]),
        Err(aggregate::AggregateStarkErrorV1::InvalidLayout)
    );
    assert_eq!(actual.state(), initial_state);
    invalid.query_seed = domains.query_seed;
    assert_eq!(
        aggregate::absorb_base_roots_v1(&mut actual, &invalid, &[]),
        Err(aggregate::AggregateStarkErrorV1::TranscriptMismatch)
    );
    assert_eq!(actual.state(), initial_state);
    let root = GoldilocksDigest384V1::from_le_bytes([11; 48]).unwrap();
    let group = aggregate::AggregateTraceGroupProofV1 {
        base_root: root,
        aux_root: GoldilocksDigest384V1::default(),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    };
    aggregate::absorb_base_roots_v1(&mut actual, &domains, &[group]).unwrap();
    let mut expected = make_transcript();
    expected
        .absorb(
            domains.base_root_label,
            &[&0_u16.to_be_bytes(), &root.to_le_bytes()],
        )
        .unwrap();
    assert_eq!(actual.state(), expected.state());
    assert_eq!(domains, original);
}

fn admission(players: u8) -> GameAdmissionBodyV1 {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{account::AccountId, game::GameAdmissionParticipantV1};
    GameAdmissionBodyV1 {
        version: 1,
        participants: (0..players)
            .map(|slot| {
                let wallet = KeyPair::try_from_seed(vec![slot + 1; 32], Algorithm::Ed25519)
                    .expect("deterministic fixture wallet");
                let input = KeyPair::try_from_seed(vec![slot + 65; 32], Algorithm::Ed25519)
                    .expect("deterministic fixture input key");
                GameAdmissionParticipantV1 {
                    account: AccountId::new(wallet.public_key().clone()),
                    input_key: input.public_key().clone(),
                    application_data: vec![slot % RACE_SKIN_COUNT_V1],
                }
            })
            .collect(),
        wagers: vec![],
        resources: vec![],
    }
}

fn late_finisher_forfeit_request(all_forfeit: bool) -> RaceProverRequestV1 {
    let mut request = request(2);
    let mut state = initial_race_state_v1(request.replay.track, 2).unwrap();
    let mut frames = Vec::new();
    while state.cars[0].finish_tick.is_none() || state.tick % 6 != 0 {
        let frame = RaceInputFrameV1 {
            tick: state.tick,
            controls: vec![1 | 32, 0],
        };
        crate::execution_proofs::race::step_race_v1(&mut state, &frame).unwrap();
        frames.push(frame);
    }
    request.replay.frames = frames;
    request.replay.dnf_events = vec![RaceDnfEventV1 {
        tick: state.tick,
        slots: if all_forfeit { vec![0, 1] } else { vec![0] },
    }];
    request.statement.transcript_root =
        race_transcript_root_v1(&request.statement.network_id, &request.replay);
    let payload = race_payload_from_request_v1(&request).unwrap();
    request.statement.outcome_hash = game_message_hash_v1(
        &request.statement.network_id,
        "session-outcome",
        &payload.outcome,
    );
    request
}

#[test]
fn corrected_binding_rejects_consistently_committed_forfeited_late_finisher_awards() {
    for all_forfeit in [false, true] {
        let mut request = late_finisher_forfeit_request(all_forfeit);
        let mut payload = race_payload_from_request_v1(&request).unwrap();
        assert_eq!(
            payload.outcome.winner_slots,
            if all_forfeit { vec![] } else { vec![1] }
        );
        validate_payload(&request.statement, &payload)
            .expect("real reference replay with corrected awards");
        let mut legacy =
            crate::execution_proofs::race::race_result_v1(&payload.final_state).unwrap();
        legacy.winners = vec![0];
        payload.outcome.winner_slots = legacy.winners.clone();
        payload.outcome.result = legacy.encode();
        payload.relation_inputs.result = legacy;
        request.statement.outcome_hash = game_message_hash_v1(
            &request.statement.network_id,
            "session-outcome",
            &payload.outcome,
        );
        assert!(matches!(
            validate_payload(&request.statement, &payload),
            Err(ExecutionProofErrorV1::Statement)
        ));
    }
}

#[test]
#[ignore = "genuine corrected late-finisher proof qualification; records a multi-thousand-tick native proof"]
fn late_finisher_full_native_proof_verifies_and_wrong_profile_is_rejected() {
    let request = late_finisher_forfeit_request(true);
    let output = std::env::var_os("SORA_CARS_NATIVE_PROOF_OUTPUT").map(std::path::PathBuf::from);
    if let Some(output) = &output {
        std::fs::create_dir_all(output).unwrap();
        std::fs::write(output.join("request.nrt"), request.encode()).unwrap();
    }
    let ticks = request.replay.frames.len();
    let started = std::time::Instant::now();
    let proof = prove_race_v1(request).expect("genuine corrected proof");
    eprintln!(
        "corrected stock proof: profile={} players=2 ticks={ticks} envelope_bytes={} prove_seconds={:.3}",
        proof.profile_id,
        proof.encode().len(),
        started.elapsed().as_secs_f64()
    );
    if let Some(output) = &output {
        std::fs::write(output.join("proof.nrt"), proof.encode()).unwrap();
    }
    assert!(
        verify_race_outcome_v1(&proof)
            .unwrap()
            .winner_slots
            .is_empty()
    );
    let mut wrong_profile = proof.clone();
    wrong_profile.profile_id = Hash::new(b"uncompiled-profile");
    assert!(crate::execution_proofs::verify_execution_proof_v1(&wrong_profile).is_err());
}

/// Test-only entry point. Production proving continues to use `OsRng`; the full
/// native driver already accepts injected masking entropy internally.
fn prove_with_test_entropy(request: &RaceProverRequestV1) -> ExecutionProofEnvelopeV1 {
    use super::super::stark::proof_managed_note_stark::prove_proof_managed_note_stark_v1_with_rng;
    use rand::{SeedableRng as _, rngs::StdRng};
    let mut payload = race_payload_from_request_v1(request).expect("canonical reference payload");
    let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("compiled adapter");
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
    payload.stark_bytes = prove_proof_managed_note_stark_v1_with_rng(
        &adapter,
        &columns,
        &mut StdRng::from_seed([0x53; 32]),
    )
    .expect("genuine deterministic native proof");
    let envelope = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    assert!(envelope.encode().len() <= RACE_MAX_PROOF_BYTES_V1);
    verify_race_proof_v1(&envelope).expect("independent native verification");
    envelope
}

#[test]
#[ignore = "genuine CPU parity proofs; set IROHA_EXECUTION_PARITY_REQUEST for a retained full request"]
fn complete_proof_bytes_are_identical_across_cpu_thread_counts() {
    use std::{fs, path::PathBuf, time::Instant};
    let request = if let Some(path) = std::env::var_os("IROHA_EXECUTION_PARITY_REQUEST") {
        let bytes = fs::read(path).expect("retained request");
        assert!(bytes.len() <= RACE_MAX_PROOF_BYTES_V1);
        let mut remaining = bytes.as_slice();
        let request = RaceProverRequestV1::decode(&mut remaining).expect("canonical request");
        assert!(remaining.is_empty());
        assert_eq!(request.encode(), bytes);
        assert_eq!(request.manifest.profile_id, race_profile_id_v1());
        request
    } else {
        request(2)
    };
    let output = std::env::var_os("IROHA_EXECUTION_PARITY_OUTPUT").map(PathBuf::from);
    if let Some(output) = &output {
        fs::create_dir_all(output).expect("qualification output");
    }
    let mut baseline = None;
    for requested_width in [1, 2, 0] {
        let start = Instant::now();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(requested_width)
            .build()
            .expect("bounded CPU pool");
        let width = pool.current_num_threads();
        eprintln!(
            "CPU parity proving: requested_width={requested_width} actual_width={width} players={} ticks={}",
            request.replay.player_count,
            request.replay.frames.len()
        );
        let proof = pool.install(|| prove_with_test_entropy(&request));
        let bytes = proof.encode();
        if let Some(baseline) = &baseline {
            assert_eq!(
                &bytes, baseline,
                "every proof byte, including roots, FRI folds and queries, must agree"
            );
        } else {
            baseline = Some(bytes.clone());
        }
        if let Some(output) = &output {
            fs::write(
                output.join(format!("threads-{requested_width}.nrt")),
                &bytes,
            )
            .expect("retained parity proof");
        }
        eprintln!(
            "CPU parity verified: requested_width={requested_width} actual_width={width} bytes={} elapsed_seconds={:.3}",
            bytes.len(),
            start.elapsed().as_secs_f64()
        );
    }
}

fn request(players: u8) -> RaceProverRequestV1 {
    let replay = RaceReplayV1 {
        track: RaceTrackV1::NeonTokyo,
        player_count: players,
        frames: (0..6)
            .map(|tick| RaceInputFrameV1 {
                tick,
                controls: (0..players)
                    .map(|slot| 1 | if slot % 2 == 0 { 8 } else { 4 })
                    .collect(),
            })
            .collect(),
        dnf_events: vec![RaceDnfEventV1 {
            tick: 6,
            slots: (0..players).collect(),
        }],
    };
    let state = replay_race_v1(&replay).expect("reference replay");
    let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(Hash::new(
        b"race-proof-test-network",
    )));
    let manifest = GameManifestV1 {
        version: 1,
        application_id: Hash::new(b"test-game"),
        profile_id: race_profile_id_v1(),
        application_parameters: replay.track.encode(),
        min_participants: 2,
        max_participants: players,
        batch_ticks: 6,
        max_ticks: 5400,
        max_input_bytes: 12,
        max_participant_data_bytes: 1,
        access: iroha_data_model::game::GameAccessV1::Public,
        payout_policy: iroha_data_model::game::GamePayoutPolicyV1::EqualWinnersOrRefund,
    };
    let outcome = race_game_outcome_v1(&state).expect("outcome");
    let admission = admission(players);
    RaceProverRequestV1 {
        statement: ExecutionPublicInputsV1 {
            network_id,
            session_id: Hash::new(b"race"),
            manifest_hash: game_message_hash_v1(&network_id, "session-manifest", &manifest),
            roster_hash: game_roster_hash_v1(&network_id, &Hash::new(b"race"), &admission),
            transcript_root: race_transcript_root_v1(&network_id, &replay),
            dispute_root: Hash::new(b"history"),
            outcome_hash: game_message_hash_v1(&network_id, "session-outcome", &outcome),
        },
        manifest,
        admission,
        replay,
        checkpoint_state: None,
    }
}
#[test]
fn funding_profile_is_fail_closed_before_release_qualification() {
    assert!(!race_profile_is_qualified_v1());
}

#[test]
fn immutable_admission_is_recomputed_and_stock_entitlements_are_exact() {
    use iroha_data_model::{
        game::{GameAdmissionResourceV1, GameAdmissionWagerV1},
        game_resources::GameResourceReturnPolicyV1,
    };
    let request = request(2);
    let payload = race_payload_from_request_v1(&request).expect("canonical payload");
    validate_payload(&request.statement, &payload).expect("valid immutable admission");
    for mutation in [
        "wallet",
        "key",
        "skin",
        "missing",
        "duplicate",
        "version",
        "equipment",
        "wager-slot",
    ] {
        let mut altered = payload.clone();
        match mutation {
            "wallet" => {
                altered.admission.participants[0].account =
                    admission(8).participants[7].account.clone()
            }
            "key" => {
                altered.admission.participants[0].input_key =
                    admission(8).participants[7].input_key.clone()
            }
            "skin" => altered.admission.participants[0].application_data = vec![RACE_SKIN_COUNT_V1],
            "missing" => {
                altered.admission.participants.pop();
            }
            "duplicate" => {
                altered.admission.participants[1] = altered.admission.participants[0].clone()
            }
            "version" => altered.admission.version = 2,
            "equipment" => altered.admission.resources.push(GameAdmissionResourceV1 {
                slot: 0,
                nft_id: "kit$equipment.universal".parse().unwrap(),
                metadata_hash: Hash::new(b"complete kit metadata"),
                role_id: Hash::new(b"uncompiled kit role"),
                policy: GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal,
            }),
            "wager-slot" => altered.admission.wagers.push(GameAdmissionWagerV1 {
                slot: 2,
                nft_id: "prize$equipment.universal".parse().unwrap(),
                metadata_hash: Hash::new(b"complete prize metadata"),
            }),
            _ => unreachable!(),
        }
        assert!(
            validate_payload(&request.statement, &altered).is_err(),
            "unbound {mutation}"
        );
        let mut statement = request.statement;
        statement.roster_hash = game_roster_hash_v1(
            &statement.network_id,
            &statement.session_id,
            &altered.admission,
        );
        altered.relation_inputs.roster_hash = statement.roster_hash;
        if matches!(mutation, "wallet" | "key") {
            // Different valid public claims remain structurally valid but require a new proof.
            validate_payload(&statement, &altered).expect("valid alternate public statement");
        } else {
            assert!(
                validate_payload(&statement, &altered).is_err(),
                "invalid committed {mutation}"
            );
        }
    }
    let mut wagered = payload;
    wagered.admission.wagers.push(GameAdmissionWagerV1 {
        slot: 0,
        nft_id: "prize$equipment.universal".parse().unwrap(),
        metadata_hash: Hash::new(b"complete prize metadata"),
    });
    let mut statement = request.statement;
    statement.roster_hash = game_roster_hash_v1(
        &statement.network_id,
        &statement.session_id,
        &wagered.admission,
    );
    wagered.relation_inputs.roster_hash = statement.roster_hash;
    validate_payload(&statement, &wagered).expect("explicit wager is allowed by stock relation");
    wagered.admission.wagers[0].metadata_hash = Hash::new(b"substituted metadata");
    assert!(validate_payload(&statement, &wagered).is_err());
}

#[test]
fn profile_validates_conditional_fri_geometry() {
    assert_ne!(race_profile_id_v1(), race_rules_hash_v1());
    DOMAINS.validate().expect("execution domains are unique");
    let request = request(8);
    let payload = race_payload_from_request_v1(&request).expect("reference payload");
    let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("compiled adapter");
    adapter
        .protocol_v1()
        .validate()
        .expect("validated conditional FRI geometry");
}

#[test]
fn fri_certificate_binds_every_actual_binary_fold() {
    use crate::execution_proofs::stark::aggregate_stark::{
        AggregateFriTheorem2CertificateV1, AggregateProofLayoutV1, AggregateTraceGroupLayoutV1,
        validate_affine_batched_fri_theorem2_v1,
    };
    let request = request(8);
    let payload = race_payload_from_request_v1(&request).expect("payload");
    let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("adapter");
    for native_log in MIN_TRACE_LOG2..=MAX_TRACE_LOG2 {
        let mut parameters = adapter.protocol_v1().parameters;
        parameters.maximum_trace_log2 = native_log;
        let layout = AggregateProofLayoutV1::new(
            parameters,
            vec![AggregateTraceGroupLayoutV1 {
                native_trace_log2: native_log,
                segment_instances: 1,
                base_width: parameters.maximum_base_columns_per_instance,
                aux_width: parameters.maximum_aux_columns_per_instance,
            }],
        )
        .expect("compiled layout");
        let folds = layout.fri_rounds(parameters).expect("fold count");
        let certificate = AggregateFriTheorem2CertificateV1 {
            l_minus_one_numerator: 3,
            l_minus_one_denominator: 2,
            batching_parameter_m: 3,
            rho_numerator: 1,
            rho_denominator: 7,
            affine_arities: vec![2; folds],
            domain_log2: layout.common_lde_log2(),
            extension_field_lower_bound_bits: 252,
            base_field_two_adicity: 32,
            trace_domains_are_smooth_subgroups: true,
            evaluation_domain_is_smooth_generator_coset: true,
            evaluation_domain_is_disjoint_from_trace_domains: true,
            fold_count: folds as u8,
            terminal_log2: 10,
            terminal_degree_bound: 143,
            query_count: 136,
            distinct_queries_without_replacement: true,
            uniform_rejection_sampling: true,
            claimed_query_error_bits: 160,
        };
        let bound =
            validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate.clone())
                .expect("every complete schedule qualifies the numeric theorem terms");
        assert_eq!(bound.query_error_bits, 160);
        assert_eq!(
            bound.commitment_error_bits,
            252 - 2 * u16::from(native_log + 3) - 21
        );
        for arities in [
            vec![2; 3],
            vec![2; folds - 1],
            vec![2; folds + 1],
            vec![3; folds],
        ] {
            let mut malformed = certificate.clone();
            malformed.affine_arities = arities;
            assert!(
                validate_affine_batched_fri_theorem2_v1(parameters, &layout, malformed).is_err()
            );
        }
    }
}

#[test]
fn staged_proof_wire_shape_has_explicit_admission_bounds() {
    use crate::execution_proofs::stark::aggregate_stark::{
        AggregateProofLayoutV1, AggregateTraceGroupLayoutV1,
        maximum_encoded_proof_with_deep_bytes_v1,
    };
    for (players, trace_log, expected) in [(2, 13, 1_821_312), (8, 19, 3_161_760)] {
        let request = request(players);
        let payload = race_payload_from_request_v1(&request).expect("payload");
        let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("adapter");
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
        .expect("layout");
        assert_eq!(
            maximum_encoded_proof_with_deep_bytes_v1(parameters, &layout)
                .expect("canonical wire bound"),
            expected
        );
        assert!(
            expected > 1_048_576,
            "current native proof is not qualified for a one-MiB corridor"
        );
        assert!(expected <= RACE_MAX_STARK_BYTES_V1);
    }
}

#[test]
fn maximum_duration_replay_and_typed_settlement_fit_the_execution_cap() {
    use crate::execution_proofs::stark::aggregate_stark::{
        AggregateProofLayoutV1, AggregateTraceGroupLayoutV1,
        maximum_encoded_proof_with_deep_bytes_v1,
    };
    use iroha_data_model::game::{
        GAME_ADMISSION_MAX_ACCOUNT_ENCODED_BYTES_V1, GAME_ADMISSION_MAX_NFT_ENCODED_BYTES_V1,
    };
    use iroha_data_model::isi::game::SettleGameSessionV1;

    // This is a codec-dimension bound, deliberately not a generated proof.
    // Saturate every variable-length RaceV1 field, including both Option
    // variants and eight individually recorded removals. The resulting
    // shape need not be reachable: it bounds every reachable transcript.
    let request = request(8);
    let mut payload = race_payload_from_request_v1(&request).expect("payload");
    let mut maximum_crypto_bytes = 0;
    for track in [
        RaceTrackV1::NeonTokyo,
        RaceTrackV1::Harbor,
        RaceTrackV1::Sakura,
    ] {
        for players in 2..=8 {
            let compiled = StagedRaceAirV1::compile(
                &RaceReplayV1 {
                    track,
                    player_count: players,
                    frames: vec![],
                    dnf_events: vec![],
                },
                &initial_race_state_v1(track, players).expect("grid"),
                None,
            );
            let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("adapter");
            let parameters = adapter.protocol_v1().parameters;
            for native_trace_log2 in MIN_TRACE_LOG2..=MAX_TRACE_LOG2 {
                let layout = AggregateProofLayoutV1::new(
                    parameters,
                    vec![AggregateTraceGroupLayoutV1 {
                        native_trace_log2,
                        segment_instances: 1,
                        base_width: compiled.width() + NOTE_COPY_WIDTH_V1,
                        aux_width: NOTE_COPY_AUX_WIDTH_V1,
                    }],
                )
                .expect("validated conditional geometry");
                maximum_crypto_bytes = maximum_crypto_bytes.max(
                    maximum_encoded_proof_with_deep_bytes_v1(parameters, &layout)
                        .expect("wire bound"),
                );
            }
        }
    }
    assert_eq!(maximum_crypto_bytes, 3_166_240);
    assert!(maximum_crypto_bytes <= RACE_MAX_STARK_BYTES_V1);
    payload.replay.frames = (0..RACE_MAX_TICKS_V1)
        .map(|tick| RaceInputFrameV1 {
            tick,
            controls: vec![RACE_CONTROL_MASK_V1; 8],
        })
        .collect();
    payload.replay.dnf_events = (0..8)
        .map(|slot| RaceDnfEventV1 {
            tick: u32::from(slot) * 6,
            slots: vec![slot],
        })
        .collect();
    payload.final_state.tick = RACE_MAX_TICKS_V1;
    for car in &mut payload.final_state.cars {
        car.finish_tick = Some(RACE_MAX_TICKS_V1);
        car.dnf_tick = Some(RACE_MAX_TICKS_V1);
    }
    payload.checkpoint_state = Some(payload.final_state.clone());
    payload.relation_inputs.result = RaceResultV1 {
        ticks: RACE_MAX_TICKS_V1,
        standings: (0..8)
            .map(|slot| RaceStandingV1 {
                slot,
                finish_tick: Some(RACE_MAX_TICKS_V1),
                dnf_tick: Some(RACE_MAX_TICKS_V1),
                progress_mm: 7_200_000,
            })
            .collect(),
        winners: (0..8).collect(),
    };
    payload.outcome = GameOutcomeV1 {
        terminal_tick: RACE_MAX_TICKS_V1,
        winner_slots: (0..8).collect(),
        result: payload.relation_inputs.result.encode(),
    };
    // Each native struct/sequence field needs at most a ten-byte u64 length prefix
    // (covering both compact and fixed-length framing). Accounts and NFT IDs have
    // independently enforced encoded bounds; their display lengths are not wire bounds.
    // Ed25519 keys have fixed codec geometry. Stock admission allows one cosmetic
    // byte and one wager per car, and no equipment. This conservatively covers
    // eight maximal controllers and eight maximal NFT identifiers without inventing
    // an invalid account or omitting public admission from the envelope calculation.
    let framed = |bytes: usize| bytes + 10;
    let participant_bound = framed(GAME_ADMISSION_MAX_ACCOUNT_ENCODED_BYTES_V1)
        + framed(payload.admission.participants[0].input_key.encode().len())
        + framed(vec![0_u8].encode().len());
    let wager_bound = framed(0_u8.encode().len())
        + framed(GAME_ADMISSION_MAX_NFT_ENCODED_BYTES_V1)
        + framed(Hash::new(b"bounded hash").encode().len());
    let admission_bound = framed(1_u16.encode().len())
        + framed(8 + 8 * framed(participant_bound))
        + framed(8 + 8 * framed(wager_bound))
        + framed(8);
    assert!(payload.admission.encode().len() <= admission_bound);
    // Account for growth of both the payload's admission-field prefix and its
    // enclosing byte-vector lengths as the bounded body replaces the fixture body.
    let admission_allowance = admission_bound - payload.admission.encode().len() + 40;
    payload.stark_bytes = vec![0; maximum_crypto_bytes];
    let proof = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: payload.encode(),
    };
    // PublicKey serializes a compact tag + bounded byte payload. Reserve
    // the feature-independent largest supported key and 64 bytes for its
    // enum/field framing; this replaces the smaller Public access variant.
    let invitation_allowance = vec![0_u8; iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1]
        .encode()
        .len()
        + 64;
    let envelope_bound = proof.encode().len() + invitation_allowance + admission_allowance;
    // Build canonical field bytes without depending on the instruction's constructor API,
    // then decode and re-encode the real registered native ISI.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::execution_proofs::proof::tests::maximum_duration_replay_and_typed_settlement_fit_the_execution_cap::SettlementFields"
    )]
    #[derive(Encode)]
    struct SettlementFields {
        session_id: Hash,
        proof: ExecutionProofEnvelopeV1,
        outcome: GameOutcomeV1,
    }
    let fields = SettlementFields {
        session_id: request.statement.session_id,
        proof,
        outcome: payload.outcome,
    }
    .encode();
    let mut encoded_fields = fields.as_slice();
    let settlement =
        SettleGameSessionV1::decode(&mut encoded_fields).expect("canonical typed settlement shape");
    assert!(encoded_fields.is_empty());
    assert_eq!(settlement.encode(), fields);
    let settlement_bound = settlement.encode().len() + invitation_allowance + admission_allowance;
    eprintln!(
        "RaceV1 codec bounds: crypto={maximum_crypto_bytes} envelope={envelope_bound} typed_settlement={settlement_bound} invitation_allowance={invitation_allowance} admission_bound={admission_bound}"
    );
    assert!(envelope_bound <= RACE_MAX_PROOF_BYTES_V1);
    assert!(settlement_bound <= EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1);
    // Four MiB is the smallest whole-MiB ceiling covering this closed
    // maximum-frontier proof shape plus its retained public transcript.
    assert!(envelope_bound > 3 * 1024 * 1024);
    assert!(!compiled_race_profile_v1().qualified);
}

#[test]
fn proof_admission_counts_envelope_framing_and_separate_stark_cap() {
    let request = request(2);
    let mut proof = ExecutionProofEnvelopeV1 {
        version: 1,
        profile_id: race_profile_id_v1(),
        statement: request.statement,
        proof_bytes: vec![0; RACE_MAX_PROOF_BYTES_V1],
    };
    assert!(proof.encode().len() > RACE_MAX_PROOF_BYTES_V1);
    assert!(matches!(
        decode_payload(&proof),
        Err(ExecutionProofErrorV1::Envelope)
    ));
    let mut payload = race_payload_from_request_v1(&request).expect("payload");
    payload.stark_bytes = vec![0; RACE_MAX_STARK_BYTES_V1 + 1];
    proof.proof_bytes = payload.encode();
    assert!(proof.encode().len() < RACE_MAX_PROOF_BYTES_V1);
    assert!(matches!(
        decode_payload(&proof),
        Err(ExecutionProofErrorV1::Envelope)
    ));
    payload.stark_bytes.truncate(RACE_MAX_STARK_BYTES_V1);
    proof.proof_bytes = payload.encode();
    // Decoding a bounded shape is not cryptographic acceptance.
    assert!(decode_payload(&proof).is_ok());
    assert!(!race_profile_is_qualified_v1());
}

#[test]
fn execution_queries_match_full_native_race_fixed_lde() {
    for players in [2, 8] {
        let request = request(players);
        let payload = race_payload_from_request_v1(&request).expect("payload");
        let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("adapter");
        let lde_size = 1_usize << (adapter.trace_log2_v1() + 3);
        let queries = [0, 1, 7, 61, 127, 1_023, lde_size / 2, lde_size - 1];
        assert!(
            crate::execution_proofs::stark::proof_managed_note_stark::execution_fixed_query_parity_v1(
                &adapter, &queries
            )
            .expect("exact public polynomial parity")
        );
    }
}

#[test]
fn timeout_outcome_binding_rejects_refund_and_false_distance_winner() {
    let mut request = request(8);
    request.replay.frames = (0..RACE_MAX_TICKS_V1)
        .map(|tick| RaceInputFrameV1 {
            tick,
            controls: vec![0; 8],
        })
        .collect();
    request.replay.dnf_events.clear();
    request.statement.transcript_root =
        race_transcript_root_v1(&request.statement.network_id, &request.replay);
    let mut payload =
        race_payload_from_request_v1(&request).expect("maximum-duration reference payload");
    request.statement.outcome_hash = game_message_hash_v1(
        &request.statement.network_id,
        "session-outcome",
        &payload.outcome,
    );
    assert_eq!(payload.outcome.winner_slots, vec![0, 1]);
    validate_payload(&request.statement, &payload).expect("distance winner binding");
    for winners in [vec![], vec![7], vec![0]] {
        payload.relation_inputs.result.winners = winners.clone();
        payload.outcome.winner_slots = winners;
        payload.outcome.result = payload.relation_inputs.result.encode();
        request.statement.outcome_hash = game_message_hash_v1(
            &request.statement.network_id,
            "session-outcome",
            &payload.outcome,
        );
        assert!(matches!(
            validate_payload(&request.statement, &payload),
            Err(ExecutionProofErrorV1::Statement)
        ));
    }
}

#[test]
fn complete_relation_has_exact_degree_four_on_arbitrary_field_lines() {
    let request = request(8);
    let payload = race_payload_from_request_v1(&request).expect("reference payload");
    let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("compiled adapter");
    let width = adapter.compiled.width();
    let fixed_width = adapter.profile_fixed_width_v1();
    let degree=crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1([47;32],[width,width,0,0,fixed_width],8,4,|current,next,_,_,fixed|Ok::<_,()>(adapter.compiled.residues(current,next,fixed)));
    assert_eq!(degree, 4);
}

#[test]
fn recomputed_successor_witness_cannot_forge_carry_transitions_or_padding() {
    let request = request(8);
    let payload = race_payload_from_request_v1(&request).expect("reference payload");
    let adapter = RaceAdapterV1::new(&request.statement, &payload).expect("compiled adapter");
    let compiled = &adapter.compiled;
    let size = compiled.trace_size(&payload.replay);
    let steps = compiled.rows_per_tick();
    let first_contact = 1 + 3 * 8;
    let first_finish = first_contact + 8 * 7 / 2;
    let final_boundary = (payload.replay.frames.len() + 1) * steps;
    // Offset fields are progress, lateral, speed, vx, energy, finish, DNF;
    // the last carry cell is the per-car curvature force.
    for (name, row_index, offset, delta) in [
        ("boundary progress", 0, 0, 1),
        ("acceleration", 1, 2, 1),
        ("curvature", 2, 7 * 8, 1),
        ("checkpoint skipping", 3, 0, 1_000_000),
        ("invented collision", first_contact, 1, 900),
        ("forged finish", first_finish, 5, 1),
        ("inactive car movement", final_boundary + 3, 0, 1),
        ("padding movement", size - 2, 1, 1),
    ] {
        let mut carry = compiled.initial_carry();
        for row in 0..row_index {
            let fixed = compiled.fixed_row(&payload.replay, row, size, None);
            carry = compiled.witness(&carry, &fixed).1;
        }
        let fixed = compiled.fixed_row(&payload.replay, row_index, size, None);
        let (current, mut next_carry) = compiled.witness(&carry, &fixed);
        let next_fixed = compiled.fixed_row(&payload.replay, row_index + 1, size, None);
        let (honest_next, _) = compiled.witness(&next_carry, &next_fixed);
        let fixed = fixed.into_iter().map(field).collect::<Vec<_>>();
        assert!(
            compiled
                .residues(&current, &honest_next, &fixed)
                .iter()
                .all(|value| *value == F::ZERO),
            "honest {name}"
        );
        next_carry[offset] += delta;
        // Recompute every dependent successor selector, inverse and packed
        // arithmetic cell from the altered state, rather than flipping only
        // an isolated byte or leaving a trivially inconsistent witness bank.
        let (forged_next, _) = compiled.witness(&next_carry, &next_fixed);
        assert!(
            compiled
                .residues(&current, &forged_next, &fixed)
                .iter()
                .any(|value| *value != F::ZERO),
            "accepted forged {name}"
        );
    }
}

#[test]
#[ignore = "expensive native cryptographic qualification; run explicitly and record peak RSS/proof bytes"]
fn real_native_proof_roundtrip_and_statement_adversaries() {
    let start = std::time::Instant::now();
    let proof = prove_race_v1(request(2)).expect("genuine native execution proof");
    eprintln!(
        "race proof bytes={} proving_seconds={:.3}",
        proof.proof_bytes.len(),
        start.elapsed().as_secs_f64()
    );
    verify_race_proof_v1(&proof).expect("verify independent envelope");
    // Keep each forged public statement internally consistent. Rejection must
    // therefore come from the actual STARK transcript/opening binding, rather
    // than merely mismatched duplicate metadata in the envelope and payload.
    for mutation in [
        "network",
        "session",
        "roster",
        "dispute",
        "application",
        "checkpoint",
    ] {
        let mut corrupted = proof.clone();
        let mut payload = decode_payload(&proof).expect("canonical payload");
        match mutation {
            "network" => {
                corrupted.statement.network_id =
                    NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                        iroha_data_model::block::BlockHeader,
                    >::from_untyped_unchecked(
                        Hash::new(b"a different finalized genesis")
                    ));
                payload.relation_inputs.network_id = corrupted.statement.network_id;
                corrupted.statement.transcript_root =
                    race_transcript_root_v1(&corrupted.statement.network_id, &payload.replay);
                payload.relation_inputs.transcript_root = corrupted.statement.transcript_root;
            }
            "session" => {
                corrupted.statement.session_id = Hash::new(b"another game session");
                payload.relation_inputs.race_id = corrupted.statement.session_id;
            }
            "roster" => {
                payload.admission.participants[0].input_key =
                    admission(8).participants[7].input_key.clone();
            }
            "dispute" => {
                corrupted.statement.dispute_root =
                    Hash::new(b"other checkpoint epoch and forced inputs");
                payload.relation_inputs.dispute_root = corrupted.statement.dispute_root;
            }
            "application" => payload.manifest.application_id = Hash::new(b"other game application"),
            "checkpoint" => {
                payload.checkpoint_state = Some(
                    initial_race_state_v1(payload.replay.track, payload.replay.player_count)
                        .expect("valid alternate checkpoint"),
                );
            }
            _ => unreachable!(),
        }
        corrupted.statement.manifest_hash = game_message_hash_v1(
            &corrupted.statement.network_id,
            "session-manifest",
            &payload.manifest,
        );
        corrupted.statement.outcome_hash = game_message_hash_v1(
            &corrupted.statement.network_id,
            "session-outcome",
            &payload.outcome,
        );
        corrupted.statement.roster_hash = game_roster_hash_v1(
            &corrupted.statement.network_id,
            &corrupted.statement.session_id,
            &payload.admission,
        );
        payload.relation_inputs.roster_hash = corrupted.statement.roster_hash;
        validate_payload(&corrupted.statement, &payload)
            .expect("internally consistent forged statement");
        corrupted.proof_bytes = payload.encode();
        assert!(
            verify_race_proof_v1(&corrupted).is_err(),
            "unbound {mutation}"
        );
    }
    let mut corrupted = proof.clone();
    corrupted.proof_bytes.push(0);
    assert!(verify_race_proof_v1(&corrupted).is_err());
    let mut corrupted = proof.clone();
    corrupted.statement.session_id = Hash::new(b"foreign race");
    let mut foreign_payload = decode_payload(&proof).expect("payload");
    foreign_payload.relation_inputs.race_id = corrupted.statement.session_id;
    corrupted.proof_bytes = foreign_payload.encode();
    assert!(verify_race_proof_v1(&corrupted).is_err());
    let mut payload = decode_payload(&proof).expect("payload");
    payload.replay.frames[0].controls[0] ^= 32;
    let mut corrupted = proof.clone();
    corrupted.statement.transcript_root =
        race_transcript_root_v1(&corrupted.statement.network_id, &payload.replay);
    payload.relation_inputs.transcript_root = corrupted.statement.transcript_root;
    corrupted.proof_bytes = payload.encode();
    assert!(verify_race_proof_v1(&corrupted).is_err());
    let mut payload = decode_payload(&proof).expect("payload");
    payload.final_state.cars[0].progress_mm += 1;
    let mut corrupted = proof.clone();
    payload.relation_inputs.result =
        race_result_v1(&payload.final_state).expect("bounded forged result");
    payload.outcome = race_game_outcome_v1(&payload.final_state).expect("forged outcome");
    corrupted.statement.outcome_hash = game_message_hash_v1(
        &corrupted.statement.network_id,
        "session-outcome",
        &payload.outcome,
    );
    corrupted.proof_bytes = payload.encode();
    assert!(verify_race_proof_v1(&corrupted).is_err());
    let mut corrupted = proof.clone();
    let middle = corrupted.proof_bytes.len() / 2;
    corrupted.proof_bytes[middle] ^= 1;
    assert!(verify_race_proof_v1(&corrupted).is_err());
}
