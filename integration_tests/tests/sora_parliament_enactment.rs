//! Shared real four-validator threshold beacon, timed-OVN ballot and certificate enactment.
//! All transitions are submitted as signed transactions; there is no direct certificate/state setup.
use super::*;
use iroha::data_model::prelude::AssetId;

pub struct EnactedFixture {
    pub(crate) attempt_id: GovernanceAttemptId,
    pub(crate) height: u64,
    /// Exact network-bound beacon used by callers that continue the enacted lifecycle.
    pub(crate) logical_beacon: BeaconSessionId,
}

/// Positive corridor genesis: proof-valid beacon custody and the short signed `NPoS` epoch
/// whose native pre-boundary pulses are the only sortition slots.
pub fn builder(builder: NetworkBuilder) -> NetworkBuilder {
    with_signed_npos_epoch(
        builder_with_signer_modes(builder, POSITIVE_BEACON_SIGNER_MODES),
        CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS,
    )
}

/// The same citizen and governance genesis with caller-selected beacon custody and no
/// explicit `NPoS` snapshot, so the network signs the default epoch length.
pub fn builder_with_signer_modes(
    builder: NetworkBuilder,
    signer_modes: [ParliamentBeaconSignerMode; VALIDATOR_COUNT],
) -> NetworkBuilder {
    let citizens = citizen_accounts(&citizen_keys());
    let mut builder = builder
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(signer_modes)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(|layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                // Keep mandatory SoraNet admission enabled while bounding the
                // localhost-only puzzle cost so this corridor measures
                // Parliament/consensus liveness rather than Argon2 contention.
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(["nexus", "lane_count"], 1_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["gov", "citizenship_bond_amount"], "0")
                .write(
                    ["gov", "min_enactment_delay"],
                    i64::try_from(MIN_ENACTMENT_DELAY)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(["gov", "parliament_alternate_size"], 0_i64)
                .write(
                    ["gov", "parliament_invitation_phase_blocks"],
                    i64::try_from(INVITATION_PHASE_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(["gov", "parliament_public_finding_phase_blocks"], 20_i64)
                .write(["gov", "rules_committee_size"], i64::from(BODY_SEATS))
                .write(["gov", "agenda_council_size"], i64::from(BODY_SEATS))
                .write(["gov", "interest_panel_size"], i64::from(BODY_SEATS))
                .write(["gov", "review_panel_size"], i64::from(BODY_SEATS))
                .write(["gov", "oversight_committee_size"], i64::from(BODY_SEATS))
                .write(["gov", "policy_jury_size"], i64::from(BODY_SEATS))
                .write(["gov", "confirmation_jury_size"], i64::from(BODY_SEATS))
                .write(
                    ["gov", "parliament_timed_ovn", "registration_phase_blocks"],
                    i64::try_from(REGISTRATION_PHASE_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(
                    [
                        "gov",
                        "parliament_timed_ovn",
                        "survivor_freeze_phase_blocks",
                    ],
                    i64::try_from(SURVIVOR_PHASE_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(
                    ["gov", "parliament_timed_ovn", "commitment_phase_blocks"],
                    i64::try_from(COMMITMENT_PHASE_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(
                    ["gov", "parliament_timed_ovn", "release_delay_blocks"],
                    i64::try_from(RELEASE_DELAY_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(
                    ["gov", "parliament_timed_ovn", "opening_phase_blocks"],
                    i64::try_from(OPENING_PHASE_BLOCKS)
                        .expect("fixture phase length fits TOML integer"),
                )
                .write(["gov", "parliament_timed_ovn", "max_ballot_retries"], 0_i64)
                .write(["gov", "parliament_timed_ovn", "max_corpus_entries"], 8_i64);
        });
    for citizen in &citizens {
        builder = builder
            .with_genesis_instruction(Register::account(Account::new(citizen.clone())))
            .with_genesis_instruction(RegisterCitizen {
                owner: citizen.clone(),
                amount: 0_u64.into(),
            });
    }

    builder
}

// Caller-registered citizens are absent from the network's fee bootstrap. Fund them with
// ordinary signed transfers using the exact XOR definition in the signed NPoS parameters.
pub async fn fund_citizen_fees(
    network: &iroha_test_network::Network,
    client: &Client,
    citizens: &[AccountId],
) -> Result<()> {
    let mut snapshots = network
        .genesis_isi()
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set| match set.inner() {
            Parameter::Custom(custom) if custom.id() == &SumeragiNposParameters::parameter_id() => {
                Some(custom)
            }
            _ => None,
        });
    let parameters = snapshots
        .next()
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("citizen fee funding requires signed canonical NPoS parameters"))?;
    if snapshots.next().is_some() {
        return Err(eyre!(
            "citizen fee funding refuses duplicate NPoS snapshots"
        ));
    }
    let source = AssetId::of(
        parameters.xor_asset_definition_id,
        client.client().account().clone(),
    );
    submit_parliament_instructions(
        client,
        citizens.iter().map(|citizen| {
            iroha_data_model::isi::Transfer::asset_quantity(
                source.clone(),
                10_000_u32,
                citizen.clone(),
            )
        }),
    )
    .await
}

pub async fn enact(
    network: &iroha_test_network::Network,
    proposal: ProposalKind,
    preliminary: Vec<InstructionBox>,
    proposer: Option<Client>,
) -> Result<EnactedFixture> {
    let citizen_keys = citizen_keys();
    let citizens = citizen_accounts(&citizen_keys);
    let client = network.client();
    fund_citizen_fees(network, &client, &citizens).await?;
    let ordered_roster = ordered_validator_roster(network, &client).await?;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let beacon_record = deterministic_parliament_beacon_key_record_v1(
        network.network_id(),
        &ordered_roster,
        &beacon_budget,
    )
    .wrap_err("derive exact public beacon fixture")?;
    let beacon_binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: beacon_record.session.network_id,
        session_id: beacon_record.session.session_id,
        roster_hash: beacon_record.session.roster_hash,
        transcript_hash: beacon_record.session.transcript_hash,
    };
    let validated_beacon_session = validate_global_threshold_beacon_session_v1(
        &beacon_record.session,
        &beacon_binding,
        &beacon_budget,
    )
    .wrap_err("replay the exact public beacon transcript")?;
    let tle_public_state =
        deterministic_parliament_tle_key_public_state_v1(network.network_id(), &ordered_roster)
            .wrap_err("derive exact public TLE fixture")?;
    let install_height = next_execution_height(
        &client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "threshold-key installation",
    )
    .await?;
    let lifecycle_certificates = [
        InstructionBox::from(lifecycle_certificate(
            network,
            &ordered_roster,
            ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            beacon_record.session.session_id,
            beacon_record.session.transcript_hash,
            norito::encode_canonical(&beacon_record)?,
            install_height,
        )?),
        InstructionBox::from(lifecycle_certificate(
            network,
            &ordered_roster,
            ThresholdKeyLifecycleActionV1::InstallParliamentTleKey,
            *tle_public_state.key_session_id.as_bytes(),
            tle_public_state.transcript_hash,
            norito::encode_canonical(&tle_public_state)?,
            install_height,
        )?),
    ];
    let submission_authority_height = current_height(&client).await?;
    let submission_roster = ordered_validator_roster(network, &client).await?;
    if submission_roster != ordered_roster {
        return Err(eyre!(
            "threshold-key installation roster changed between fixture derivation and submission"
        ));
    }
    eprintln!(
        "SORA_PARLIAMENT_LIFECYCLE submit_lifecycle authority_height={submission_authority_height} install_height={install_height} roster_hash={}",
        hex::encode(global_threshold_beacon_roster_hash_v1(&ordered_roster)),
    );
    submit_parliament_instructions(&client, lifecycle_certificates).await?;
    assert_eq!(current_height(&client).await?, install_height);
    let activation_height = install_height
        .checked_add(1)
        .ok_or_else(|| eyre!("threshold-key activation height overflow"))?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry Parliament threshold-key activation".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(activation_height).await?;
    assert_eq!(current_height(&client).await?, activation_height);

    let expected_body_roles = match &proposal {
        ProposalKind::DeployContract(_) => vec![
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
            ParliamentBody::InterestPanel,
            ParliamentBody::ReviewPanel,
            ParliamentBody::OversightCommittee,
            ParliamentBody::PolicyJury,
        ],
        ProposalKind::SorafsProviderGovernance(_) => vec![
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
            ParliamentBody::InterestPanel,
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
            ParliamentBody::OversightCommittee,
            ParliamentBody::PolicyJury,
        ],
        _ => {
            return Err(eyre!(
                "fixture supports contract and provider governance corridors"
            ));
        }
    };
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    let mut instructions = preliminary;
    instructions.push(create.into());
    submit_parliament_instructions(proposer.as_ref().unwrap_or(&client), instructions).await?;
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;

    let initial = read_attempt(&client, attempt_id).await?;
    let expected_bodies = initial
        .required_bodies()
        .iter()
        .map(|required| required.body)
        .collect::<Vec<_>>();
    assert_eq!(expected_bodies, expected_body_roles);
    assert_eq!(initial.attempt().stage, GovernanceStageV1::Rules);
    let request_height =
        next_execution_height(&client, 0, "canonical sortition registration").await?;
    let sortition_pulse_height =
        expected_sortition_slot(network, &client, attempt_id, request_height, None).await?;
    let logical_beacon = BeaconSessionId::for_network_v1(&network.network_id());
    let mut election_ids = BTreeMap::new();
    let mut request_ids = Vec::new();
    let mut request_registrations = Vec::new();
    for &body in &expected_bodies {
        let election_id = BodyElectionAttemptId::derive_v1(attempt_id, body, 0);
        let request = SortitionRequestV1::try_new_canonical(
            attempt_id,
            election_id,
            body,
            parliament_candidate_root_v1(attempt_id, body, &citizens),
            u32::try_from(citizens.len())?,
            BODY_SEATS,
            request_height,
            sortition_pulse_height,
            logical_beacon,
            None,
        )
        .map_err(|error| eyre!("construct canonical sortition request: {error}"))?;
        election_ids.insert(body, election_id);
        request_ids.push(request.id);
        request_registrations.push(ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request,
        });
    }
    request_ids.sort_unstable();
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
            ParliamentRegisterSortitionRequestV1 {
                requests: request_registrations,
            },
        ),
    )
    .await?;
    assert_eq!(current_height(&client).await?, request_height);
    // Governance-local wait: the request demands nothing from consensus. The slot is the
    // native pre-boundary pulse height, which the NPoS chain finalizes for its own schedule.
    let sortition_pulse =
        await_native_sortition_pulse(network, &client, sortition_pulse_height, "sortition pulse")
            .await?;
    assert_eq!(sortition_pulse.height, sortition_pulse_height);
    assert_eq!(sortition_pulse.network_id, network.network_id());
    assert_eq!(sortition_pulse.session_id, beacon_record.session.session_id);
    assert_eq!(
        sortition_pulse.roster_hash,
        beacon_record.session.roster_hash
    );
    assert_eq!(
        sortition_pulse.transcript_hash,
        beacon_record.session.transcript_hash,
    );
    assert_eq!(sortition_pulse.round, 0, "V1 pulses are view-independent");
    assert_eq!(
        sortition_pulse.finalized_chain_anchor.height.checked_add(1),
        Some(sortition_pulse_height),
    );
    assert_eq!(
        exact_block(
            &client,
            sortition_pulse.finalized_chain_anchor.height,
            network
        )
        .await?
        .header()
        .hash(),
        sortition_pulse.finalized_chain_anchor.block_hash,
    );
    let (expected_anchor, expected_context) = finality::certified_pulse_context(
        network,
        &client,
        sortition_pulse_height,
        &sortition_pulse,
    )
    .await?;
    verify_finalized_global_threshold_beacon_pulse_v1(
        &validated_beacon_session,
        &sortition_pulse,
        expected_anchor,
        &expected_context,
    )
    .wrap_err("independently verify the sortition pulse threshold signature")?;
    cross_native_boundary_after_pulse(network, &client, &sortition_pulse, "sortition pulse")
        .await?;
    let sortition_governance_seed =
        global_threshold_beacon_governance_seed_v1(&sortition_pulse, sortition_pulse_height);
    assert_ne!(
        sortition_governance_seed, sortition_pulse.seed,
        "Parliament sortition must consume domain-separated governance entropy, not the raw beacon seed",
    );
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
            ParliamentConsumeSortitionPulseBatchV1 {
                request_ids: request_ids.clone(),
                beacon_session_id: logical_beacon,
                pulse_height: sortition_pulse_height,
                pulse_id: BeaconPulseId::new(sortition_pulse.pulse_id),
            },
        ),
    )
    .await?;
    let drawn = read_attempt(&client, attempt_id).await?;
    for body in &expected_bodies {
        let election = drawn
            .election(election_ids.get(body).expect("body election id"))
            .expect("simultaneous body election exists");
        assert_eq!(
            election.pulse_id(),
            Some(BeaconPulseId::new(sortition_pulse.pulse_id))
        );
        assert_eq!(election.pulse_output(), Some(sortition_governance_seed));
        assert_eq!(election.primary_assignments().len(), BODY_SEATS as usize);
        assert!(election.alternate_assignments().is_empty());
    }

    submit_transitions(
        &client,
        attempt_id,
        expected_bodies.iter().copied().map(|body| {
            ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id: election_ids[&body],
                },
            )
        }),
    )
    .await?;
    let invitation_state = read_attempt(&client, attempt_id).await?;
    let common_invitation_close = expected_bodies
        .iter()
        .copied()
        .map(|body| {
            invitation_state
                .election(&election_ids[&body])
                .and_then(iroha_core::governance::parliament::ParliamentElectionStateV1::invitation_close_height)
                .expect("invitation deadline is frozen")
        })
        .collect::<Vec<_>>();
    assert!(
        common_invitation_close
            .windows(2)
            .all(|pair| pair[0] == pair[1])
    );
    let mut invitations_by_member =
        BTreeMap::<AccountId, Vec<(ParliamentBody, BodyElectionAttemptId)>>::new();
    for &body in &expected_bodies {
        let election = invitation_state
            .election(&election_ids[&body])
            .expect("drawn election");
        for assignment in election.primary_assignments() {
            invitations_by_member
                .entry(assignment.member.clone())
                .or_default()
                .push((body, election_ids[&body]));
        }
    }
    for (member, invitations) in invitations_by_member {
        let member_client = client_for(&client, &member, &citizen_keys);
        submit_transitions(
            &member_client,
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
    assert!(current_height(&client).await? <= common_invitation_close[0]);
    let roster_seal_height = common_invitation_close[0]
        .checked_add(1)
        .ok_or_else(|| eyre!("invitation close height overflow"))?;
    advance_to_execution_predecessor(
        network,
        &client,
        roster_seal_height,
        "canonical Parliament roster sealing",
    )
    .await?;
    submit_transitions(
        &client,
        attempt_id,
        expected_bodies.iter().copied().map(|body| {
            ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                election_attempt_id: election_ids[&body],
            })
        }),
    )
    .await?;
    assert_eq!(current_height(&client).await?, roster_seal_height);
    let sealed = read_attempt(&client, attempt_id).await?;
    let mut body_ids = BTreeMap::<ParliamentBody, BodyInstanceId>::new();
    for &body in &expected_bodies {
        let instance = sealed
            .sealed_body_for_role(body)
            .expect("every simultaneous draw seals one body");
        assert_eq!(
            instance.instance().status,
            BodyInstanceStatusV1::RosterSealed
        );
        assert_eq!(instance.instance().original_seats, BODY_SEATS);
        assert_eq!(instance.assignments().len(), BODY_SEATS as usize);
        assert_eq!(
            sealed
                .election(&election_ids[&body])
                .expect("election")
                .accepted_assignments()
                .len(),
            BODY_SEATS as usize,
        );
        body_ids.insert(body, instance.instance().id);
    }

    let public_bodies = expected_bodies
        .iter()
        .copied()
        .filter(|body| *body != ParliamentBody::PolicyJury)
        .collect::<Vec<_>>();
    let deliberation_phases = [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
    ];
    for body in public_bodies {
        let body_id = body_ids[&body];
        submit_transitions(
            &client,
            attempt_id,
            deliberation_phases.into_iter().map(|target| {
                ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                    body_instance_id: body_id,
                    target,
                })
            }),
        )
        .await?;
        let reflecting = read_attempt(&client, attempt_id).await?;
        let body_state = reflecting.body(&body_id).expect("reflecting public body");
        assert_eq!(
            body_state.instance().status,
            BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection),
        );
        assert_eq!(
            body_state.public_finding_deadline_height(),
            Some(
                body_state
                    .public_finding_opened_at_height()
                    .expect("reflection height")
                    + 20,
            ),
        );
        let members = body_state
            .assignments()
            .iter()
            .map(|assignment| assignment.member.clone())
            .collect::<Vec<_>>();
        let result_root = public_finding_root(attempt_id, body);
        for member in &members[..2] {
            submit_transition(
                &client_for(&client, member, &citizen_keys),
                attempt_id,
                ParliamentLifecycleTransitionV1::EndorsePublicFinding(
                    ParliamentEndorsePublicFindingV1 {
                        body_instance_id: body_id,
                        result_root,
                    },
                ),
            )
            .await?;
        }
        let completed = read_attempt(&client, attempt_id).await?;
        let body_state = completed.body(&body_id).expect("completed public body");
        assert_eq!(body_state.result_root(), Some(result_root));
        assert_eq!(body_state.instance().status, BodyInstanceStatusV1::Approved);
        assert_eq!(body_state.public_finding_endorsements().len(), 2);
    }

    let policy_body_id = body_ids[&ParliamentBody::PolicyJury];
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
                body_instance_id: policy_body_id,
                target,
            })
        }),
    )
    .await?;
    let ballot_attempt_id = BallotAttemptId::derive_v1(policy_body_id, 0);
    let registered_at_height =
        next_execution_height(&client, 0, "timed-OVN ballot registration").await?;
    let registration_close_height = registered_at_height + REGISTRATION_PHASE_BLOCKS;
    let survivor_freeze_height = registration_close_height + SURVIVOR_PHASE_BLOCKS;
    let commitment_close_height = survivor_freeze_height + COMMITMENT_PHASE_BLOCKS;
    let release_height = commitment_close_height + RELEASE_DELAY_BLOCKS;
    let opening_deadline_height = release_height + OPENING_PHASE_BLOCKS;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_public_state.key_session_id,
        logical_beacon,
        release_height,
    );
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterBallotAttempt(ParliamentRegisterBallotAttemptV1 {
            body_instance_id: policy_body_id,
            ballot_attempt_id,
            sequence: 0,
            tle_session_id,
            tle_key_session_id: tle_public_state.key_session_id,
            release_beacon_session_id: logical_beacon,
            release_height,
        }),
    )
    .await?;
    assert_eq!(current_height(&client).await?, registered_at_height);
    let registered_response = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await?;
    let registered_archive = casting_archive(&registered_response, ballot_attempt_id)?;
    assert_eq!(
        registered_archive.phase(),
        ParliamentTimedOvnCastingPhaseV1::Registered
    );
    assert!(registered_archive.registration_records().is_empty());
    assert_eq!(registered_archive.target_finalized_height(), release_height);
    let registered_validated = registered_archive
        .validate_v1()
        .wrap_err("validate initial registration archive")?;
    let policy_members = read_attempt(&client, attempt_id)
        .await?
        .body(&policy_body_id)
        .expect("Policy Jury body")
        .assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    assert_eq!(policy_members.len(), BODY_SEATS as usize);
    let mut registration_secrets = BTreeMap::<[u8; 32], TimedOvnRegistrationSecretV1>::new();
    for (index, member) in policy_members.iter().enumerate() {
        let participant_hash = parliament_ballot_participant_hash_v1(ballot_attempt_id, member);
        let mut rng = StdRng::from_seed(
            Hash::new_from_chunks(&[
                b"iroha.integration.parliament.registration-rng.v1\0",
                attempt_id.as_bytes(),
                &[u8::try_from(index)?],
            ])
            .into(),
        );
        let (secret, registration) = TimedOvnRegistrationSecretV1::generate_with_rng(
            registered_validated.timed_ovn_session(),
            participant_hash,
            &mut rng,
        )
        .wrap_err("generate proof-valid timed-OVN registration")?;
        submit_transition(
            &client_for(&client, member, &citizen_keys),
            attempt_id,
            ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                ParliamentRegisterBallotParticipantV1 {
                    ballot_attempt_id,
                    registration_record: registration.to_bytes(),
                },
            ),
        )
        .await?;
        assert!(
            registration_secrets
                .insert(participant_hash, secret)
                .is_none()
        );
    }
    assert!(current_height(&client).await? < registration_close_height);
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CloseBallotRegistration(
            ParliamentCloseBallotRegistrationV1 { ballot_attempt_id },
        ),
        "registration close before the frozen exact height",
    )
    .await?;
    advance_to_execution_predecessor(
        network,
        &client,
        registration_close_height,
        "timed-OVN registration close",
    )
    .await?;
    assert_eq!(
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::CloseBallotRegistration(
                ParliamentCloseBallotRegistrationV1 { ballot_attempt_id },
            ),
        )
        .await?,
        registration_close_height,
    );
    let registration_closed = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await?;
    let registration_closed_archive = casting_archive(&registration_closed, ballot_attempt_id)?;
    assert_eq!(
        registration_closed_archive.phase(),
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed,
    );
    assert_eq!(
        registration_closed_archive.registration_records().len(),
        BODY_SEATS as usize,
    );
    assert_eq!(
        read_attempt(&client, attempt_id)
            .await?
            .ballot(&ballot_attempt_id)
            .expect("registered ballot")
            .registered_voters(),
        Some(BODY_SEATS),
    );
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CloseBallotRegistration(
            ParliamentCloseBallotRegistrationV1 { ballot_attempt_id },
        ),
        "replayed registration close",
    )
    .await?;
    assert!(current_height(&client).await? < survivor_freeze_height);
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(ParliamentFreezeBallotSurvivorsV1 {
            ballot_attempt_id,
        }),
        "survivor freeze before the frozen exact height",
    )
    .await?;
    advance_to_execution_predecessor(
        network,
        &client,
        survivor_freeze_height,
        "timed-OVN survivor freeze",
    )
    .await?;
    assert_eq!(
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(
                ParliamentFreezeBallotSurvivorsV1 { ballot_attempt_id },
            ),
        )
        .await?,
        survivor_freeze_height,
    );
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(ParliamentFreezeBallotSurvivorsV1 {
            ballot_attempt_id,
        }),
        "replayed survivor freeze",
    )
    .await?;
    let survivors_response = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await?;
    let survivors_archive = casting_archive(&survivors_response, ballot_attempt_id)?;
    assert_eq!(
        survivors_archive.phase(),
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen,
    );
    let survivor_ids = survivors_archive
        .survivor_participant_hashes()
        .expect("survivor freeze exposes exact public identifiers");
    assert_eq!(survivor_ids.len(), BODY_SEATS as usize);
    let survivors_validated = survivors_archive
        .validate_v1()
        .wrap_err("replay survivor-frozen casting archive")?;
    let prepared = survivors_validated
        .prepared_attempt()
        .expect("survivor-frozen archive prepares the exact ballot roster");
    let mut ballot_records = Vec::with_capacity(survivor_ids.len());
    for (index, participant_hash) in survivor_ids.iter().enumerate() {
        let choice = if index < 2 {
            TimedOvnChoiceV1::Aye
        } else {
            TimedOvnChoiceV1::Nay
        };
        let mut rng = StdRng::from_seed(
            Hash::new_from_chunks(&[
                b"iroha.integration.parliament.ballot-rng.v1\0",
                attempt_id.as_bytes(),
                &[u8::try_from(index)?],
            ])
            .into(),
        );
        let record = registration_secrets
            .get(participant_hash)
            .ok_or_else(|| eyre!("frozen survivor has no locally retained secret"))?
            .cast_ballot_with_rng(prepared.survivor_roster(), choice, &mut rng)
            .wrap_err("generate proof-valid masked timed-OVN ballot")?
            .to_bytes();
        assert_eq!(record.len(), TIMED_OVN_BALLOT_RECORD_BYTES_V1);
        ballot_records.push(record);
    }
    assert!(current_height(&client).await? < commitment_close_height);
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(ParliamentFreezeTimedOvnCorpusV1 {
            ballot_attempt_id,
            ballot_records: ballot_records.clone(),
        }),
        "timed-OVN corpus freeze before the frozen exact height",
    )
    .await?;
    advance_to_execution_predecessor(
        network,
        &client,
        commitment_close_height,
        "timed-OVN commitment close",
    )
    .await?;
    assert_eq!(
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                ParliamentFreezeTimedOvnCorpusV1 {
                    ballot_attempt_id,
                    ballot_records: ballot_records.clone(),
                },
            ),
        )
        .await?,
        commitment_close_height,
    );
    let committed_attempt = read_attempt(&client, attempt_id).await?;
    let committed_ballot = committed_attempt
        .ballot(&ballot_attempt_id)
        .expect("committed hidden ballot");
    assert_eq!(committed_ballot.accepted_ballots(), Some(BODY_SEATS));
    assert!(committed_ballot.corpus_root().is_some());
    assert_eq!(
        committed_ballot.attempt().status,
        BallotAttemptStatusV1::AwaitingRelease,
    );
    assert_timed_ovn_casting_context_not_castable(
        &client,
        ballot_attempt_id,
        "a sealed corpus is no longer a cast-capable context",
    )
    .await?;
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(ParliamentFreezeTimedOvnCorpusV1 {
            ballot_attempt_id,
            ballot_records,
        }),
        "replayed timed-OVN corpus freeze",
    )
    .await?;
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
            ParliamentBeginBallotOpeningBatchV1 {
                ballot_attempt_ids: vec![ballot_attempt_id],
                release_beacon_session_id: logical_beacon,
                release_height,
                pulse_id: BeaconPulseId::new([0xE1; 32]),
            },
        ),
        "ballot opening before the frozen release height and authoritative pulse",
    )
    .await?;

    // TODO: the timed-OVN release slot is no longer consensus demand, so no pulse is
    // finalized at `release_height` unless it coincides with a native pre-boundary height
    // and the wait below never ends. Replace everything from the ballot registration to the
    // final release with the anonymous ballot (specs/parliament_private_ballot_design.md
    // 12.2 step 4); every caller of this fixture is ignored until then.
    advance_to_autonomous_predecessor(network, &client, release_height, "timed-OVN release pulse")
        .await?;
    network.ensure_blocks(release_height).await?;
    assert_eq!(
        current_height(&client).await?,
        release_height,
        "the demanded ballot-release threshold-beacon effect must autonomously finalize its exact height",
    );
    let mut release_pulses = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        release_pulses.push(pulse_at(&peer.client(), release_height, network).await?);
    }
    assert!(release_pulses.windows(2).all(|pair| pair[0] == pair[1]));
    let release_pulse = release_pulses[0];
    assert_eq!(release_pulse.height, release_height);
    assert_eq!(release_pulse.session_id, beacon_record.session.session_id);
    assert_eq!(release_pulse.roster_hash, beacon_record.session.roster_hash);
    assert_eq!(
        release_pulse.transcript_hash,
        beacon_record.session.transcript_hash,
    );
    assert_eq!(release_pulse.round, 0, "V1 pulses are view-independent");
    assert_eq!(
        release_pulse.finalized_chain_anchor.height.checked_add(1),
        Some(release_height),
    );
    assert_eq!(
        exact_block(
            &client,
            release_pulse.finalized_chain_anchor.height,
            network
        )
        .await?
        .header()
        .hash(),
        release_pulse.finalized_chain_anchor.block_hash,
    );
    let (expected_anchor, expected_context) =
        finality::certified_pulse_context(network, &client, release_height, &release_pulse).await?;
    verify_finalized_global_threshold_beacon_pulse_v1(
        &validated_beacon_session,
        &release_pulse,
        expected_anchor,
        &expected_context,
    )
    .wrap_err("independently verify the ballot-release pulse threshold signature")?;
    assert_ne!(release_pulse.pulse_id, sortition_pulse.pulse_id);
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
            ParliamentBeginBallotOpeningBatchV1 {
                ballot_attempt_ids: vec![ballot_attempt_id],
                release_beacon_session_id: logical_beacon,
                release_height,
                pulse_id: BeaconPulseId::new(release_pulse.pulse_id),
            },
        ),
    )
    .await?;
    let opening_height = current_height(&client).await?;
    assert!(opening_height <= opening_deadline_height);
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
            ParliamentBeginBallotOpeningBatchV1 {
                ballot_attempt_ids: vec![ballot_attempt_id],
                release_beacon_session_id: logical_beacon,
                release_height,
                pulse_id: BeaconPulseId::new(release_pulse.pulse_id),
            },
        ),
        "replayed ballot opening",
    )
    .await?;
    network.ensure_blocks(opening_height).await?;
    let release_context = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_tle_release_context(ballot_attempt_id)
    })
    .await?;
    let validated_release = release_projection(&release_context)?
        .validate()
        .wrap_err("replay full public TLE transcript and release identity")?;
    assert_eq!(release_context.release_height, release_height);
    assert_eq!(
        release_context.opening_deadline_height,
        opening_deadline_height
    );
    assert_eq!(release_context.status, BallotAttemptStatusV1::Opening);
    assert_eq!(
        release_context.tle_key_session.threshold, 2,
        "the four-validator test fixture uses an independently verified 2-of-4 release threshold",
    );
    let mut verified_partials = BTreeMap::<u16, TlePartialReleaseShareV1>::new();
    for peer in network.peers() {
        let peer_client = peer.client();
        let peer_context = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            move || client.get_parliament_tle_release_context(ballot_attempt_id)
        })
        .await?;
        assert_eq!(peer_context, release_context);
        let partial = release_partial(
            &read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let release_context = (peer_context).clone();
                move || client.post_parliament_tle_partial_release(&release_context)
            })
            .await?,
        );
        validated_release
            .session()
            .verify_partial_release(
                validated_release.identity(),
                validated_release.finalized_height(),
                &partial,
            )
            .wrap_err("independently verify one proof-carrying validator release share")?;
        let participant_index = partial.participant_index;
        if let Some(previous) = verified_partials.insert(participant_index, partial.clone()) {
            assert_eq!(previous, partial, "a validator seat may not equivocate");
        }
    }
    assert_eq!(verified_partials.len(), VALIDATOR_COUNT);
    let canonical_threshold = verified_partials
        .into_values()
        .take(usize::from(release_context.tle_key_session.threshold))
        .collect::<Vec<_>>();
    let final_release = validated_release
        .session()
        .combine_partial_releases(
            validated_release.identity(),
            validated_release.finalized_height(),
            &canonical_threshold,
        )
        .wrap_err("combine canonical threshold of verified release shares")?;
    validated_release
        .session()
        .verify_final_release(
            validated_release.identity(),
            validated_release.finalized_height(),
            &final_release,
        )
        .wrap_err("independently verify combined final release")?;
    let parliament_final_release = ParliamentTleFinalReleaseSignatureV1 {
        key_session_id: final_release.key_session_id,
        identity_digest: final_release.identity_digest,
        signature: final_release.signature,
    };
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(ParliamentFinalizeOpenedBallotV1 {
            ballot_attempt_id,
            final_release: parliament_final_release,
        }),
    )
    .await?;
    let certified = read_attempt(&client, attempt_id).await?;
    let certificate = certified
        .certificate()
        .cloned()
        .expect("Core constructs a certificate atomically with the approved final aggregate");
    certificate
        .validate()
        .wrap_err("revalidate the complete Core-constructed Parliament certificate")?;
    assert_eq!(
        certified.attempt().status,
        GovernanceAttemptStatusV1::Certified
    );
    assert_eq!(certified.attempt().stage, GovernanceStageV1::Enactment);
    assert_eq!(
        certificate.certified_at_height,
        current_height(&client).await?
    );
    assert_eq!(
        certificate.enact_at_height,
        certificate.certified_at_height + MIN_ENACTMENT_DELAY,
    );
    assert_eq!(certificate.body_bindings.len(), expected_bodies.len());
    let policy_binding = certificate
        .body_bindings
        .iter()
        .find(|binding| binding.body == ParliamentBody::PolicyJury)
        .expect("certificate carries exactly one Policy Jury binding");
    let ballot_binding = policy_binding
        .ballot
        .expect("Policy Jury certificate binding is mandatory and private");
    assert_eq!(ballot_binding.ballot_attempt_id, ballot_attempt_id);
    assert_eq!(ballot_binding.registered_at_height, registered_at_height);
    assert_eq!(
        ballot_binding.registration_close_height,
        registration_close_height
    );
    assert_eq!(
        ballot_binding.survivor_freeze_height,
        survivor_freeze_height
    );
    assert_eq!(
        ballot_binding.commitment_close_height,
        commitment_close_height
    );
    assert_eq!(
        ballot_binding.registration_closed_at_height,
        registration_close_height,
    );
    assert_eq!(
        ballot_binding.survivors_frozen_at_height,
        survivor_freeze_height,
    );
    assert_eq!(
        ballot_binding.commitment_closed_at_height,
        commitment_close_height,
    );
    assert_eq!(ballot_binding.release_height, release_height);
    assert_eq!(
        ballot_binding.opening_deadline_height,
        opening_deadline_height,
    );
    assert_eq!(ballot_binding.max_ballot_retries, 0);
    assert_eq!(ballot_binding.max_corpus_entries, 8);
    assert_eq!(ballot_binding.tally.accepted_ballots, BODY_SEATS);
    assert_eq!(ballot_binding.tally.aye, 2);
    assert_eq!(ballot_binding.tally.nay, 1);
    assert_eq!(ballot_binding.tally.abstain, 0);
    assert_eq!(
        ballot_binding.outcome,
        ParliamentAggregateOutcomeV1::Approved
    );
    assert_eq!(ballot_binding.opening_height, opening_height);
    assert_eq!(
        ballot_binding.release_pulse_id,
        BeaconPulseId::new(release_pulse.pulse_id),
    );
    assert!(
        certificate
            .body_bindings
            .iter()
            .filter(|binding| binding.body != ParliamentBody::PolicyJury)
            .all(|binding| {
                binding.public_finding.as_ref().is_some_and(|finding| {
                    finding.endorsements == 2
                        && finding.quorum == 2
                        && finding.endorsing_assignments.len() == 2
                }) && binding.ballot.is_none()
            }),
    );
    assert_transition_rejected_without_state_change(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(ParliamentFinalizeOpenedBallotV1 {
            ballot_attempt_id,
            final_release: parliament_final_release,
        }),
        "replayed aggregate ballot finalization",
    )
    .await?;

    advance_to_autonomous_predecessor(
        network,
        &client,
        certificate.enact_at_height,
        "automatic exact-height Parliament enactment",
    )
    .await?;
    let enacted_height = certificate.enact_at_height;
    network.ensure_blocks(enacted_height).await?;
    assert_eq!(current_height(&client).await?, enacted_height);
    let enacted = read_attempt(&client, attempt_id).await?;
    assert_eq!(enacted.attempt().status, GovernanceAttemptStatusV1::Enacted);
    assert_eq!(enacted.attempt().stage, GovernanceStageV1::Enactment);
    assert_eq!(enacted.terminal_height(), Some(enacted_height));
    assert_eq!(enacted.certificate(), Some(&certificate));
    Ok(EnactedFixture {
        attempt_id,
        height: enacted_height,
        logical_beacon,
    })
}
