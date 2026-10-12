//! Actual four-validator registration-deadline failure, fresh private retry and restore.
//!
//! This scenario uses the ordinary signed lifecycle entry and real finalized
//! state. It does not submit a ballot proof or claim a positive aggregate opening;
//! the sibling policy-jury corridor retains that separate cryptographic coverage.

use super::*;
use iroha::data_model::isi::governance::ParliamentFailBallotNoResultV1;
use iroha_core::governance::parliament::{ParliamentReducerEntityV1, ParliamentReducerErrorV1};
use iroha_sumeragi::availability::recommended_data_availability_layout;

#[test]
fn four_validator_private_ballot_deadline_retry_exhaustion_and_restore() -> Result<()> {
    let name = stringify!(four_validator_private_ballot_deadline_retry_exhaustion_and_restore);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator private retry runtime")
                .block_on(private_ballot_deadline_retry_impl())
        })
        .expect("spawn four-validator private retry thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn private_ballot_deadline_retry_impl() -> Result<()> {
    let keys = citizen_keys();
    let citizens = citizen_accounts(&keys);
    let address = ContractAddress::from_str(NO_RESULT_RETRY_CONTRACT_ADDRESS)?;
    let abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let builder = certified_terminal_builder(&citizens, &address, abi).with_config_layer(|layer| {
        // Two exact attempts: sequence zero, then one fresh retry. Preserve all
        // other source-owned schedules, three private seats and consensus rules.
        layer.write(["gov", "parliament_timed_ovn", "max_ballot_retries"], 1_i64);
    });
    let context = stringify!(four_validator_private_ballot_deadline_retry_exhaustion_and_restore);
    let started = sandbox::start_network_async_or_skip(builder, context).await?;
    let network =
        sandbox::enforce_network_start_requirement(started, context)?.ok_or_else(|| {
            eyre!("private deadline/retry qualification requires four running validators")
        })?;
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    let client = network.client();
    let sessions = install_threshold_sessions(&network, &client).await?;
    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal: ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: client.client().account().clone(),
            contract_address: address.clone(),
            code_hash,
            abi_hash,
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(create),
        ],
    )
    .await?;
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;
    let bodies = draw_and_seal_failure_path_bodies(
        &network,
        &client,
        attempt_id,
        &citizens,
        &keys,
        sessions.logical_beacon,
        TERMINAL_POLICY_SEATS,
    )
    .await?;
    complete_failure_path_public_findings(&client, &keys, attempt_id, &bodies).await?;
    let body_id = bodies[&ParliamentBody::PolicyJury];
    submit_transitions(
        &client,
        attempt_id,
        [
            DeliberationPhaseV1::Orientation,
            DeliberationPhaseV1::Evidence,
            DeliberationPhaseV1::Questions,
            DeliberationPhaseV1::Responses,
            DeliberationPhaseV1::Deliberation,
            DeliberationPhaseV1::Reflection,
            DeliberationPhaseV1::Vote,
        ]
        .into_iter()
        .map(|target| {
            ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                body_instance_id: body_id,
                target,
            })
        }),
    )
    .await?;

    let mut previous = None;
    for sequence in 0..=1 {
        let ballot_id = BallotAttemptId::derive_v1(body_id, sequence);
        if let Some((old_id, old_session, _)) = previous {
            let at = next_execution_height(&client, 0, "retired private session").await?;
            let mut replay = private_registration(body_id, sequence, &sessions, at)?;
            replay.tle_session_id = old_session;
            assert_private_transition_rejected(
                &client,
                attempt_id,
                ParliamentLifecycleTransitionV1::RegisterBallotAttempt(replay),
                ParliamentReducerErrorV1::TleSessionAlreadyConsumed,
                "a private retry cannot reuse its predecessor TLE session",
            )
            .await?;
            assert_eq!(
                read_attempt(&client, attempt_id)
                    .await?
                    .ballot(&old_id)
                    .unwrap()
                    .attempt()
                    .status,
                BallotAttemptStatusV1::NoResult
            );
        }
        let registered_at = next_execution_height(&client, 0, "fresh private ballot").await?;
        let registration = private_registration(body_id, sequence, &sessions, registered_at)?;
        let tle_session = registration.tle_session_id;
        let release_height = registration.release_height;
        if let Some((old_id, old_session, _)) = previous {
            assert_ne!(ballot_id, old_id);
            assert_ne!(tle_session, old_session);
        }
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::RegisterBallotAttempt(registration),
        )
        .await?;
        assert_eq!(current_height(&client).await?, registered_at);
        let active = read_attempt(&client, attempt_id).await?;
        let ballot = active
            .ballot(&ballot_id)
            .expect("real registered private ballot");
        assert_eq!(ballot.attempt().status, BallotAttemptStatusV1::Registration);
        assert_eq!(ballot.attempt().original_seats, TERMINAL_POLICY_SEATS);
        assert_eq!(ballot.registered_at_height(), registered_at);
        assert_eq!(ballot.release_height(), Some(release_height));
        assert_eq!(ballot.tle_session_id(), Some(tle_session));
        assert_eq!(
            ballot.tle_key_session_id(),
            Some(sessions.tle_public_state.key_session_id)
        );
        if let Some((old_id, _, old_failure_height)) = previous {
            let old = active.ballot(&old_id).expect("retained predecessor ballot");
            assert_eq!(old.attempt().status, BallotAttemptStatusV1::Superseded);
            assert_eq!(old.failure_height(), Some(old_failure_height));
            assert_eq!(
                old.failure_kind(),
                Some(ParliamentBallotFailureKindV1::RegistrationDeadlineExpired)
            );
        }
        let close = registered_at
            .checked_add(TERMINAL_REGISTRATION_BLOCKS)
            .ok_or_else(|| eyre!("private registration close overflow"))?;
        // The deadline itself is inclusive for failure rejection: the reducer
        // permits this objective failure only after registration close.
        advance_to_execution_predecessor(
            &network,
            &client,
            close,
            "private failure at the inclusive registration boundary",
        )
        .await?;
        assert_private_transition_rejected(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::FailBallotNoResult(ParliamentFailBallotNoResultV1 {
                ballot_attempt_id: ballot_id,
            }),
            ParliamentReducerErrorV1::BallotFailureKindMismatch,
            "registration failure must reject at its exact close height",
        )
        .await?;
        assert_eq!(current_height(&client).await?, close);
        let first_late_height = close
            .checked_add(1)
            .ok_or_else(|| eyre!("private deadline overflow"))?;
        let failure_height = next_execution_height(
            &client,
            first_late_height,
            "private registration deadline failure",
        )
        .await?;
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::FailBallotNoResult(ParliamentFailBallotNoResultV1 {
                ballot_attempt_id: ballot_id,
            }),
        )
        .await?;
        assert_eq!(current_height(&client).await?, failure_height);
        let failed = read_attempt(&client, attempt_id).await?;
        failed
            .validate()
            .wrap_err("validate real failed private ballot transcript")?;
        let ballot = failed.ballot(&ballot_id).expect("retained failed ballot");
        assert_eq!(ballot.attempt().status, BallotAttemptStatusV1::NoResult);
        assert_eq!(
            ballot.failure_kind(),
            Some(ParliamentBallotFailureKindV1::RegistrationDeadlineExpired)
        );
        assert_eq!(ballot.failure_height(), Some(failure_height));
        assert!(ballot.registered_voters().is_none());
        assert!(ballot.accepted_ballots().is_none());
        assert!(ballot.corpus_root().is_none());
        assert!(failed.certificate().is_none());
        assert_eq!(
            failed.body(&body_id).unwrap().instance().status,
            BodyInstanceStatusV1::NoResult
        );
        assert_eq!(
            failed.attempt().status,
            if sequence == 0 {
                GovernanceAttemptStatusV1::Active
            } else {
                GovernanceAttemptStatusV1::Rejected
            }
        );
        assert_private_transition_rejected(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::FailBallotNoResult(ParliamentFailBallotNoResultV1 {
                ballot_attempt_id: ballot_id,
            }),
            if sequence == 0 {
                ParliamentReducerErrorV1::InvalidLifecycleTransition(
                    ParliamentReducerEntityV1::BallotAttempt,
                )
            } else {
                ParliamentReducerErrorV1::AttemptNotActive
            },
            "a private deadline result cannot be replayed or reclassified",
        )
        .await?;
        assert_private_retry_state_and_restore(&network, &client, attempt_id, &address).await?;
        previous = Some((ballot_id, tle_session, failure_height));
    }
    let at = next_execution_height(&client, 0, "exhausted private retry").await?;
    assert_private_transition_rejected(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterBallotAttempt(private_registration(
            body_id, 2, &sessions, at,
        )?),
        ParliamentReducerErrorV1::AttemptNotActive,
        "the final permitted private failure terminalizes the governance attempt",
    )
    .await?;
    network.shutdown().await;
    Ok(())
}

fn private_registration(
    body_id: BodyInstanceId,
    sequence: u32,
    sessions: &ThresholdSessionsV1,
    registered_at: u64,
) -> Result<ParliamentRegisterBallotAttemptV1> {
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_id, sequence);
    let release_height = [
        TERMINAL_REGISTRATION_BLOCKS,
        TERMINAL_SURVIVOR_FREEZE_PHASE_BLOCKS,
        BALLOT_COMMITMENT_PHASE_BLOCKS,
        CONFIRMATION_RELEASE_DELAY_BLOCKS,
    ]
    .into_iter()
    .try_fold(registered_at, |height, phase| height.checked_add(phase))
    .ok_or_else(|| eyre!("private ballot schedule overflow"))?;
    Ok(ParliamentRegisterBallotAttemptV1 {
        body_instance_id: body_id,
        ballot_attempt_id,
        sequence,
        tle_session_id: TleSessionId::derive_v1(
            ballot_attempt_id,
            sessions.tle_public_state.key_session_id,
            sessions.logical_beacon,
            release_height,
        ),
        tle_key_session_id: sessions.tle_public_state.key_session_id,
        release_beacon_session_id: sessions.logical_beacon,
        release_height,
    })
}

async fn assert_private_retry_state_and_restore(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    attempt_id: GovernanceAttemptId,
    address: &ContractAddress,
) -> Result<()> {
    let height = current_height(client).await?;
    network.ensure_blocks(height).await?;
    let expected = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?
    .state_payload_hex;
    let block_hash = exact_block(client, height, &network).await?.hash();
    for peer in network.peers() {
        let peer_client = peer.client();
        assert_eq!(
            read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let attempt_id = (attempt_id).clone();
                move || client.get_parliament_attempt(attempt_id)
            })
            .await?
            .state_payload_hex,
            expected
        );
        assert_governed_contract_absent(
            &peer_client,
            address,
            "private retry must not enact an effect",
        )
        .await?;
        let (proof, verified) = finality::certified_block(network, &peer_client, height).await?;
        assert_eq!(verified.block().hash(), block_hash);
        assert_eq!(verified.height(), height);
        assert_eq!(proof.committee.len(), VALIDATOR_COUNT);
        assert_eq!(
            verified.commitment().schedule.current.committee.len(),
            VALIDATOR_COUNT
        );
        // The shared contiguous verifier enforces exactly three equal native
        // votes for every successor before exposing this authenticated result.
        assert_eq!(
            verified.commitment().schedule.current.da_layout,
            recommended_data_availability_layout()
        );
    }
    let peer = network.peers().last().expect("fourth validator").clone();
    let layers = network.config_layers().collect::<Vec<_>>();
    assert!(peer.shutdown_if_started().await);
    tokio::time::timeout(OPERATION_TIMEOUT, peer.start_checked(layers.iter(), None))
        .await
        .map_err(|_| eyre!("private retry restore startup deadline"))??;
    tokio::time::timeout(OPERATION_TIMEOUT, peer.once_block(height))
        .await
        .map_err(|_| eyre!("private retry restore finalized-height deadline"))?;
    assert_eq!(
        read_on_dedicated_thread({
            let client = peer.client().client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?
        .state_payload_hex,
        expected
    );
    assert_eq!(
        exact_block(&peer.client(), height, &network).await?.hash(),
        block_hash
    );
    let status = read_on_dedicated_thread({
        let client = peer.client().client().clone();
        move || client.get_sumeragi_status()
    })
    .await?;
    assert!(!status.is_halted());
    assert!(status.applied_height <= status.committed_height);
    assert_governed_contract_absent(
        &peer.client(),
        address,
        "restored private retry effect isolation",
    )
    .await?;
    Ok(())
}

async fn assert_private_transition_rejected(
    client: &Client,
    attempt_id: GovernanceAttemptId,
    transition: ParliamentLifecycleTransitionV1,
    expected: ParliamentReducerErrorV1,
    label: &str,
) -> Result<()> {
    let before = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?
    .state_payload_hex;
    let error = submit_parliament_instructions(
        &client,
        [SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: attempt_id,
            transition,
        }],
    )
    .await
    .expect_err("invalid private-ballot transition must fail");
    let rendered = format!("{error:#}");
    let canonical_error = format!("Parliament lifecycle transition rejected: {expected}");
    assert!(
        rendered.contains(&canonical_error),
        "{label}: expected native {canonical_error}, got {rendered}"
    );
    assert_eq!(
        read_on_dedicated_thread({
            let client = client.client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?
        .state_payload_hex,
        before,
        "{label}: rejected transition must retain every reducer byte"
    );
    Ok(())
}
