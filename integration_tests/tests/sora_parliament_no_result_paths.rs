//! Public-finding NoResult retry and restart coverage for the Parliament lifecycle corridor.

use super::*;

pub(super) async fn exercise_public_finding_no_result_retries_and_restore(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    citizens: &[AccountId],
    citizen_keys: &[KeyPair],
    contract_address: &ContractAddress,
    code_hash: ContractCodeHash,
    abi_hash: ContractAbiHash,
    logical_beacon: BeaconSessionId,
) -> Result<()> {
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal: proposal.clone(),
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
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
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;

    let expected_bodies = [
        ParliamentBody::RulesCommittee,
        ParliamentBody::AgendaCouncil,
        ParliamentBody::InterestPanel,
        ParliamentBody::ReviewPanel,
        ParliamentBody::OversightCommittee,
        ParliamentBody::PolicyJury,
    ];
    let request_height =
        next_execution_height(client, 0, "no-result sortition registration").await?;
    let sortition_pulse_height =
        expected_sortition_slot(network, client, attempt_id, request_height, None).await?;
    let mut election_ids = BTreeMap::new();
    let mut request_ids = Vec::new();
    let mut registrations = Vec::new();
    for body in expected_bodies {
        let election_id = BodyElectionAttemptId::derive_v1(attempt_id, body, 0);
        let request = SortitionRequestV1::try_new_canonical(
            attempt_id,
            election_id,
            body,
            parliament_candidate_root_v1(attempt_id, body, citizens),
            u32::try_from(citizens.len())?,
            BODY_SEATS,
            request_height,
            sortition_pulse_height,
            logical_beacon,
            None,
        )
        .map_err(|error| eyre!("construct no-result sortition request: {error}"))?;
        election_ids.insert(body, election_id);
        request_ids.push(request.id);
        registrations.push(ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request,
        });
    }
    request_ids.sort_unstable();
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
            ParliamentRegisterSortitionRequestV1 {
                requests: registrations,
            },
        ),
    )
    .await?;
    assert_eq!(current_height(client).await?, request_height);
    // Governance-local wait for the consensus-native pre-boundary pulse at the slot;
    // the draw is consumed after the epoch boundary that the same pulse scheduled.
    let pulse = await_native_sortition_pulse(
        network,
        client,
        sortition_pulse_height,
        "no-result retry sortition pulse",
    )
    .await?;
    cross_native_boundary_after_pulse(network, client, &pulse, "no-result retry sortition pulse")
        .await?;
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
            ParliamentConsumeSortitionPulseBatchV1 {
                request_ids,
                beacon_session_id: logical_beacon,
                pulse_height: sortition_pulse_height,
                pulse_id: BeaconPulseId::new(pulse.pulse_id),
            },
        ),
    )
    .await?;

    submit_transitions(
        client,
        attempt_id,
        expected_bodies.into_iter().map(|body| {
            ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id: election_ids[&body],
                },
            )
        }),
    )
    .await?;
    let invitation_state = read_attempt(client, attempt_id).await?;
    let invitation_close_height = expected_bodies
        .into_iter()
        .map(|body| {
            invitation_state
                .election(&election_ids[&body])
                .and_then(|election| election.invitation_close_height())
                .expect("no-result invitation deadline is frozen")
        })
        .reduce(|left, right| {
            assert_eq!(left, right);
            left
        })
        .expect("the no-result attempt requires Parliament bodies");
    let mut invitations_by_member =
        BTreeMap::<AccountId, Vec<(ParliamentBody, BodyElectionAttemptId)>>::new();
    for body in expected_bodies {
        let election = invitation_state
            .election(&election_ids[&body])
            .expect("no-result body election");
        for assignment in election.primary_assignments() {
            invitations_by_member
                .entry(assignment.member.clone())
                .or_default()
                .push((body, election_ids[&body]));
        }
    }
    for (member, invitations) in invitations_by_member {
        submit_transitions(
            &client_for(client, &member, citizen_keys),
            attempt_id,
            invitations.into_iter().map(|(body, election_attempt_id)| {
                ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                    ParliamentRecordInvitationResponseV1 {
                        election_attempt_id,
                        body,
                        decision: ParliamentInvitationDecisionV1::Accept,
                    },
                )
            }),
        )
        .await?;
    }
    assert!(current_height(client).await? <= invitation_close_height);
    let roster_seal_height = invitation_close_height
        .checked_add(1)
        .ok_or_else(|| eyre!("no-result roster-seal height overflow"))?;
    advance_to_execution_predecessor(
        network,
        client,
        roster_seal_height,
        "no-result retry roster sealing",
    )
    .await?;
    submit_transitions(
        client,
        attempt_id,
        expected_bodies.into_iter().map(|body| {
            ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                election_attempt_id: election_ids[&body],
            })
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, roster_seal_height);

    let rules_body_id = read_attempt(client, attempt_id)
        .await?
        .sealed_body_for_role(ParliamentBody::RulesCommittee)
        .expect("no-result Rules Committee is sealed")
        .instance()
        .id;
    submit_transitions(
        client,
        attempt_id,
        [
            DeliberationPhaseV1::Orientation,
            DeliberationPhaseV1::Evidence,
            DeliberationPhaseV1::Questions,
            DeliberationPhaseV1::Responses,
            DeliberationPhaseV1::Deliberation,
            DeliberationPhaseV1::Reflection,
        ]
        .into_iter()
        .map(|target| {
            ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                body_instance_id: rules_body_id,
                target,
            })
        }),
    )
    .await?;
    let reflecting = read_attempt(client, attempt_id).await?;
    let rules = reflecting
        .body(&rules_body_id)
        .expect("reflecting no-result Rules Committee");
    let public_finding_deadline = rules
        .public_finding_deadline_height()
        .expect("no-result public-finding deadline is frozen");
    let absent_assignments = rules.assignments()[..2].to_vec();
    for (index, assignment) in absent_assignments.iter().enumerate() {
        submit_transition(
            &client_for(client, &assignment.member, citizen_keys),
            attempt_id,
            ParliamentLifecycleTransitionV1::RecordAttemptAbsence(
                ParliamentRecordAttemptAbsenceV1 {
                    body_instance_id: rules_body_id,
                    assignment_id: assignment.assignment_id,
                },
            ),
        )
        .await?;
        let observed = read_attempt(client, attempt_id).await?;
        let observed_rules = observed
            .body(&rules_body_id)
            .expect("no-result Rules Committee survives projection");
        assert_eq!(observed_rules.excluded_assignments().len(), index + 1);
        if index == 0 {
            assert_eq!(observed.attempt().status, GovernanceAttemptStatusV1::Active);
            assert_eq!(
                observed_rules.instance().status,
                BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection),
            );
        }
    }
    let failed_height = current_height(client).await?;
    assert!(
        failed_height < public_finding_deadline,
        "objective quorum impossibility must terminate before the frozen deadline",
    );
    let rejected = read_attempt(client, attempt_id).await?;
    let rejected_rules = rejected
        .body(&rules_body_id)
        .expect("rejected Rules Committee remains auditable");
    assert_eq!(
        rejected.attempt().status,
        GovernanceAttemptStatusV1::Rejected,
    );
    assert_eq!(
        rejected_rules.instance().status,
        BodyInstanceStatusV1::NoResult
    );
    assert_eq!(
        rejected_rules.public_finding_no_result_kind(),
        Some(ParliamentNoResultKindV1::PublicFindingQuorumUnreachable),
    );
    assert_eq!(
        rejected_rules.public_finding_no_result_height(),
        Some(failed_height),
    );
    assert_governed_contract_absent(
        client,
        contract_address,
        "public-finding quorum-unreachable effect isolation",
    )
    .await?;

    let retry = CreateParliamentGovernanceAttemptV1 {
        proposal: proposal.clone(),
        attempt_sequence: 1,
    };
    let retry_id = retry.governance_attempt_id();
    submit_parliament_instructions(&client, [retry]).await?;
    let retry_height = current_height(client).await?;
    network.ensure_blocks(retry_height).await?;
    let retry_state = read_attempt(client, retry_id).await?;
    assert_eq!(retry_state.attempt().sequence, 1);
    assert_eq!(
        retry_state.attempt().status,
        GovernanceAttemptStatusV1::Active
    );
    assert_eq!(
        retry_state.attempt().stage,
        GovernanceStageV1::Qualification
    );

    submit_transition(
        client,
        retry_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;
    let retry_request_height =
        next_execution_height(client, 0, "deadline retry sortition registration").await?;
    // A fresh governance attempt starts its own generation history, so its first slot is
    // again the first native pulse height at or after its own request plus the frozen delay.
    let retry_pulse_height =
        expected_sortition_slot(network, client, retry_id, retry_request_height, None).await?;
    assert!(
        retry_pulse_height > sortition_pulse_height,
        "a later attempt cannot draw from the boundary pulse an earlier attempt consumed",
    );
    let mut retry_election_ids = BTreeMap::new();
    let mut retry_request_ids = Vec::new();
    let mut retry_registrations = Vec::new();
    for body in expected_bodies {
        let election_id = BodyElectionAttemptId::derive_v1(retry_id, body, 0);
        let request = SortitionRequestV1::try_new_canonical(
            retry_id,
            election_id,
            body,
            parliament_candidate_root_v1(retry_id, body, citizens),
            u32::try_from(citizens.len())?,
            BODY_SEATS,
            retry_request_height,
            retry_pulse_height,
            logical_beacon,
            None,
        )
        .map_err(|error| eyre!("construct deadline retry sortition request: {error}"))?;
        retry_election_ids.insert(body, election_id);
        retry_request_ids.push(request.id);
        retry_registrations.push(ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request,
        });
    }
    retry_request_ids.sort_unstable();
    submit_transition(
        client,
        retry_id,
        ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
            ParliamentRegisterSortitionRequestV1 {
                requests: retry_registrations,
            },
        ),
    )
    .await?;
    assert_eq!(current_height(client).await?, retry_request_height);
    let retry_pulse = await_native_sortition_pulse(
        network,
        client,
        retry_pulse_height,
        "deadline retry sortition pulse",
    )
    .await?;
    assert_ne!(retry_pulse.pulse_id, pulse.pulse_id);
    cross_native_boundary_after_pulse(
        network,
        client,
        &retry_pulse,
        "deadline retry sortition pulse",
    )
    .await?;
    submit_transition(
        client,
        retry_id,
        ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
            ParliamentConsumeSortitionPulseBatchV1 {
                request_ids: retry_request_ids,
                beacon_session_id: logical_beacon,
                pulse_height: retry_pulse_height,
                pulse_id: BeaconPulseId::new(retry_pulse.pulse_id),
            },
        ),
    )
    .await?;
    submit_transitions(
        client,
        retry_id,
        expected_bodies.into_iter().map(|body| {
            ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id: retry_election_ids[&body],
                },
            )
        }),
    )
    .await?;
    let retry_invitations = read_attempt(client, retry_id).await?;
    let retry_invitation_close = expected_bodies
        .into_iter()
        .map(|body| {
            retry_invitations
                .election(&retry_election_ids[&body])
                .and_then(|election| election.invitation_close_height())
                .expect("deadline retry invitation deadline is frozen")
        })
        .reduce(|left, right| {
            assert_eq!(left, right);
            left
        })
        .expect("deadline retry requires Parliament bodies");
    let mut retry_invitations_by_member =
        BTreeMap::<AccountId, Vec<(ParliamentBody, BodyElectionAttemptId)>>::new();
    for body in expected_bodies {
        let election = retry_invitations
            .election(&retry_election_ids[&body])
            .expect("deadline retry body election");
        for assignment in election.primary_assignments() {
            retry_invitations_by_member
                .entry(assignment.member.clone())
                .or_default()
                .push((body, retry_election_ids[&body]));
        }
    }
    for (member, invitations) in retry_invitations_by_member {
        submit_transitions(
            &client_for(client, &member, citizen_keys),
            retry_id,
            invitations.into_iter().map(|(body, election_attempt_id)| {
                ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                    ParliamentRecordInvitationResponseV1 {
                        election_attempt_id,
                        body,
                        decision: ParliamentInvitationDecisionV1::Accept,
                    },
                )
            }),
        )
        .await?;
    }
    let retry_roster_seal_height = retry_invitation_close
        .checked_add(1)
        .ok_or_else(|| eyre!("deadline retry roster-seal height overflow"))?;
    advance_to_execution_predecessor(
        network,
        client,
        retry_roster_seal_height,
        "deadline retry roster sealing",
    )
    .await?;
    submit_transitions(
        client,
        retry_id,
        expected_bodies.into_iter().map(|body| {
            ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                election_attempt_id: retry_election_ids[&body],
            })
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, retry_roster_seal_height);

    let retry_rules_body_id = read_attempt(client, retry_id)
        .await?
        .sealed_body_for_role(ParliamentBody::RulesCommittee)
        .expect("deadline retry Rules Committee is sealed")
        .instance()
        .id;
    submit_transitions(
        client,
        retry_id,
        [
            DeliberationPhaseV1::Orientation,
            DeliberationPhaseV1::Evidence,
            DeliberationPhaseV1::Questions,
            DeliberationPhaseV1::Responses,
            DeliberationPhaseV1::Deliberation,
            DeliberationPhaseV1::Reflection,
        ]
        .into_iter()
        .map(|target| {
            ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                body_instance_id: retry_rules_body_id,
                target,
            })
        }),
    )
    .await?;
    let retry_reflecting = read_attempt(client, retry_id).await?;
    let retry_rules = retry_reflecting
        .body(&retry_rules_body_id)
        .expect("deadline retry Rules Committee is reflecting");
    let retry_public_finding_deadline = retry_rules
        .public_finding_deadline_height()
        .expect("deadline retry public-finding deadline is frozen");
    let retry_members = retry_rules
        .assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    let deadline_relayer = citizens
        .iter()
        .find(|candidate| !retry_members.contains(candidate))
        .ok_or_else(|| eyre!("deadline retry has no nonmember permissionless relayer"))?;
    let deadline_relayer_client = client_for(client, deadline_relayer, citizen_keys);
    let first_root = public_finding_root(retry_id, ParliamentBody::RulesCommittee);
    let competing_root: [u8; 32] = Hash::new_from_chunks(&[
        b"iroha.integration.parliament.competing-public-finding.v1\0",
        retry_id.as_bytes(),
    ])
    .into();
    assert_ne!(first_root, competing_root);
    submit_transition(
        &client_for(client, &retry_members[0], citizen_keys),
        retry_id,
        ParliamentLifecycleTransitionV1::EndorsePublicFinding(ParliamentEndorsePublicFindingV1 {
            body_instance_id: retry_rules_body_id,
            result_root: first_root,
        }),
    )
    .await?;
    submit_transition(
        &client_for(client, &retry_members[1], citizen_keys),
        retry_id,
        ParliamentLifecycleTransitionV1::EndorsePublicFinding(ParliamentEndorsePublicFindingV1 {
            body_instance_id: retry_rules_body_id,
            result_root: competing_root,
        }),
    )
    .await?;
    let split = read_attempt(client, retry_id).await?;
    let split_rules = split
        .body(&retry_rules_body_id)
        .expect("split public finding remains auditable");
    assert_eq!(split.attempt().status, GovernanceAttemptStatusV1::Active);
    assert_eq!(split_rules.public_finding_endorsements().len(), 2);
    assert!(
        split_rules
            .public_finding_endorsements()
            .values()
            .any(|root| *root == first_root)
    );
    assert!(
        split_rules
            .public_finding_endorsements()
            .values()
            .any(|root| *root == competing_root)
    );
    assert_transition_rejected_without_state_change(
        &deadline_relayer_client,
        retry_id,
        ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
            ParliamentFailPublicFindingNoResultV1 {
                body_instance_id: retry_rules_body_id,
            },
        ),
        "public-finding deadline failure before the frozen deadline",
    )
    .await?;

    let first_post_deadline_execution = retry_public_finding_deadline
        .checked_add(1)
        .ok_or_else(|| eyre!("deadline retry public-finding height overflow"))?;
    advance_to_execution_predecessor(
        network,
        client,
        first_post_deadline_execution,
        "public-finding frozen deadline",
    )
    .await?;
    assert_transition_rejected_without_state_change(
        &client_for(client, &retry_members[2], citizen_keys),
        retry_id,
        ParliamentLifecycleTransitionV1::EndorsePublicFinding(ParliamentEndorsePublicFindingV1 {
            body_instance_id: retry_rules_body_id,
            result_root: first_root,
        }),
        "public-finding endorsement after the inclusive frozen deadline",
    )
    .await?;
    submit_transition(
        &deadline_relayer_client,
        retry_id,
        ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
            ParliamentFailPublicFindingNoResultV1 {
                body_instance_id: retry_rules_body_id,
            },
        ),
    )
    .await?;
    let deadline_failed_height = current_height(client).await?;
    assert!(deadline_failed_height > retry_public_finding_deadline);
    let deadline_rejected = read_attempt(client, retry_id).await?;
    let deadline_rules = deadline_rejected
        .body(&retry_rules_body_id)
        .expect("deadline-rejected Rules Committee remains auditable");
    assert_eq!(
        deadline_rejected.attempt().status,
        GovernanceAttemptStatusV1::Rejected
    );
    assert_eq!(
        deadline_rules.instance().status,
        BodyInstanceStatusV1::NoResult
    );
    assert_eq!(
        deadline_rules.public_finding_no_result_kind(),
        Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired)
    );
    assert_eq!(
        deadline_rules.public_finding_no_result_height(),
        Some(deadline_failed_height)
    );
    assert_eq!(deadline_rules.public_finding_endorsements().len(), 2);

    let second_retry = CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 2,
    };
    let second_retry_id = second_retry.governance_attempt_id();
    submit_parliament_instructions(&client, [second_retry]).await?;
    let second_retry_height = current_height(client).await?;
    network.ensure_blocks(second_retry_height).await?;
    let second_retry_state = read_attempt(client, second_retry_id).await?;
    assert_eq!(second_retry_state.attempt().sequence, 2);
    assert_eq!(
        second_retry_state.attempt().status,
        GovernanceAttemptStatusV1::Active
    );
    assert_eq!(
        second_retry_state.attempt().stage,
        GovernanceStageV1::Qualification
    );

    let rejected_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    let retry_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (retry_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    let second_retry_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (second_retry_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    for peer in network.peers() {
        let peer_client = peer.client();
        let peer_rejected = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        let peer_retry = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let attempt_id = (retry_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        let peer_second_retry = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let attempt_id = (second_retry_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(
            peer_rejected.state_payload_hex,
            rejected_response.state_payload_hex
        );
        assert_eq!(
            peer_retry.state_payload_hex,
            retry_response.state_payload_hex
        );
        assert_eq!(
            peer_second_retry.state_payload_hex,
            second_retry_response.state_payload_hex
        );
        assert_governed_contract_absent(
            &peer_client,
            contract_address,
            "public-finding peer effect isolation",
        )
        .await?;
    }

    let restart_peer = network
        .peers()
        .last()
        .expect("four-validator network has a restore peer")
        .clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(
        restart_peer.shutdown_if_started().await,
        "deadline-retry restore peer must be running",
    );
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("public-finding restore exceeded {OPERATION_TIMEOUT:?}"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(second_retry_height),
    )
    .await
    .map_err(|_| eyre!("public-finding restore did not recover finalized state"))?;
    let restored_rejected = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    let restored_retry = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (retry_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    let restored_second_retry = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (second_retry_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_eq!(
        restored_rejected.state_payload_hex,
        rejected_response.state_payload_hex
    );
    assert_eq!(
        restored_retry.state_payload_hex,
        retry_response.state_payload_hex
    );
    assert_eq!(
        restored_second_retry.state_payload_hex,
        second_retry_response.state_payload_hex
    );
    assert_governed_contract_absent(
        &restart_peer.client(),
        contract_address,
        "public-finding restart effect isolation",
    )
    .await?;
    let restored_status = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        move || client.get_sumeragi_status()
    })
    .await?;
    assert!(!restored_status.is_halted());
    assert!(restored_status.applied_height <= restored_status.committed_height);
    Ok(())
}
