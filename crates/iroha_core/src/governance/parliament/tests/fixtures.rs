/// Consensus-native epoch length frozen by the reducer fixtures: with the fixtures' ten-block
/// delay, a request at height 10 targets the native pulse height 20 and one at height 40
/// targets 50.
const FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS: u64 = 3;

fn root(tag: u8) -> [u8; 32] {
    [tag.max(1); 32]
}

fn proposal_id(tag: u8) -> ProposalContentId {
    ProposalContentId::new(root(tag))
}

fn beacon_session(tag: u8) -> BeaconSessionId {
    BeaconSessionId::new(root(tag))
}

fn pulse_id(tag: u8) -> BeaconPulseId {
    BeaconPulseId::new(root(tag))
}

fn tle_key_session(tag: u8) -> TleKeySessionId {
    TleKeySessionId::new(root(tag))
}

fn account(tag: u8) -> AccountId {
    let key = KeyPair::try_from_seed(vec![tag.max(1); 32], Algorithm::Ed25519)
        .expect("derive Parliament reducer fixture key");
    AccountId::new(key.public_key().clone())
}

fn network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"parliament-reducer-fixture",
    )))
}

fn casting_tle_key(network_id: [u8; 32], tag: u8) -> ValidatedTleKeySessionV1 {
    let threshold_session = ThresholdBlsSession::<TleReleasePurpose>::new(
        network_id,
        root(tag),
        root(tag.wrapping_add(1)),
        4,
        2,
    )
    .expect("casting fixture threshold session");
    let parameters =
        AdaptiveThresholdBlsParameters::derive(&threshold_session).expect("parameters");
    let mut rng = StdRng::from_seed([tag.wrapping_add(2); 32]);
    let dealers = (1_u16..=3)
        .map(|index| {
            DasRenDealerSecret::generate_with_rng(&parameters, index, &mut rng)
                .expect("dealer")
                .1
        })
        .collect::<Vec<_>>();
    ValidatedTleKeySessionV1::from_qualified_dealers(
        threshold_session,
        &dealers,
        &[1, 2, 3],
        root(tag.wrapping_add(3)),
    )
    .expect("casting fixture TLE session")
}

/// Complete enacted attempt state plus the exact timed-OVN stores required by restore.
pub(crate) struct EnactedParliamentRestoreFixtureV1 {
    pub(crate) attempt: ParliamentAttemptStateV1,
    pub(crate) tle_key_sessions: Vec<TleKeySessionPublicStateV1>,
    pub(crate) tle_key_session_rosters: Vec<(TleKeySessionId, Vec<iroha_model_base::peer::PeerId>)>,
    pub(crate) tle_key_session_lifecycles: Vec<(TleKeySessionId, TleKeySessionLifecycleV1)>,
    pub(crate) timed_ovn_evidence: Vec<(BallotAttemptId, TimedOvnLifecycleStateV1)>,
}

fn complete_enacted_fixture_hidden_body_with_evidence(
    attempt: &mut ParliamentAttemptStateV1,
    requirement: RequiredParliamentBodyV1,
    election_attempt_id: BodyElectionAttemptId,
    network_id: &NetworkId,
    tle_key_sessions: &mut Vec<TleKeySessionPublicStateV1>,
    tle_key_session_rosters: &mut Vec<(TleKeySessionId, Vec<iroha_model_base::peer::PeerId>)>,
    tle_key_session_lifecycles: &mut Vec<(TleKeySessionId, TleKeySessionLifecycleV1)>,
    timed_ovn_evidence: &mut Vec<(BallotAttemptId, TimedOvnLifecycleStateV1)>,
) {
    assert_eq!(
        requirement.decision_mode,
        ParliamentDecisionModeV1::HiddenBindingBallot
    );
    let governance_attempt_id = attempt.attempt().id;
    let (body_instance_id, members) =
        prepare_enacted_fixture_body(attempt, requirement, election_attempt_id);
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, 0);
    let release_beacon_session_id = BeaconSessionId::new(root(0xD0));
    let release_height = 12;

    let ordered_roster = (0_u8..4)
        .map(|index| {
            let keypair = KeyPair::from_seed(vec![0xE0 + index; 32], Algorithm::Ed25519);
            iroha_model_base::peer::PeerId::new(keypair.public_key().clone())
        })
        .collect::<Vec<_>>();
    let threshold_session = ThresholdBlsSession::<TleReleasePurpose>::new(
        *network_id.as_bytes(),
        root(0xD1),
        crate::beacon::global_threshold_beacon_roster_hash_v1(&ordered_roster),
        4,
        2,
    )
    .expect("restore fixture threshold session");
    let parameters =
        AdaptiveThresholdBlsParameters::derive(&threshold_session).expect("parameters");
    let mut rng = StdRng::from_seed([0xDB; 32]);
    let mut dealer_secrets = Vec::new();
    let mut dealers = Vec::new();
    for index in 1_u16..=3 {
        let (secret, dealer) = DasRenDealerSecret::generate_with_rng(&parameters, index, &mut rng)
            .expect("restore fixture TLE dealer");
        dealer_secrets.push(secret);
        dealers.push(dealer);
    }
    let tle_key = ValidatedTleKeySessionV1::from_qualified_dealers(
        threshold_session,
        &dealers,
        &[1, 2, 3],
        root(0xDC),
    )
    .expect("restore fixture TLE key session");
    let tle_key_session_id = tle_key.public_state().key_session_id;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    let session = TimedOvnSessionPublicV1 {
        network_id: *network_id.as_bytes(),
        proposal_content_id: *attempt.proposal_content_id().as_bytes(),
        governance_attempt_id: *governance_attempt_id.as_bytes(),
        body_instance_id: *body_instance_id.as_bytes(),
        ballot_attempt_id: *ballot_attempt_id.as_bytes(),
        parameter_hash: timed_ovn_parameter_hash_v1(),
        tle_key_session_id,
        tle_key_transcript_hash: tle_key.public_state().transcript_hash,
        tle_master_public_key: *tle_key.master_public_key().as_bytes(),
    };
    let crypto_session = session
        .rebuild(&tle_key)
        .expect("restore timed-OVN session");
    let mut registrations = members
        .iter()
        .map(|member| {
            let participant_hash = parliament_ballot_participant_hash_v1(ballot_attempt_id, member);
            let (secret, registration) = TimedOvnRegistrationSecretV1::generate_with_rng(
                &crypto_session,
                participant_hash,
                &mut rng,
            )
            .expect("restore fixture timed-OVN registration");
            (participant_hash, secret, registration.to_bytes())
        })
        .collect::<Vec<_>>();
    registrations.sort_unstable_by_key(|(participant_hash, _, _)| *participant_hash);
    let mut lifecycle =
        TimedOvnLifecycleStateV1::open_registration(session, 3, release_height, &tle_key)
            .expect("open restore fixture timed-OVN registration");
    for (participant_hash, _, registration) in &registrations {
        lifecycle = lifecycle
            .register_participant(*participant_hash, registration.clone(), &tle_key)
            .expect("retain restore fixture timed-OVN registration");
    }
    lifecycle = lifecycle
        .close_registration(&tle_key)
        .expect("close restore fixture timed-OVN registration");
    lifecycle = lifecycle
        .freeze_survivors(&tle_key)
        .expect("freeze restore fixture timed-OVN survivors");
    let TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) = &lifecycle else {
        unreachable!("survivor freeze returns the exact frozen phase");
    };
    let prepared = frozen
        .validate(&tle_key)
        .expect("validate restore fixture timed-OVN survivors");
    let choices = [
        TimedOvnChoiceV1::Aye,
        TimedOvnChoiceV1::Aye,
        TimedOvnChoiceV1::Nay,
    ];
    let ballots = registrations
        .iter()
        .zip(choices)
        .map(|((_, secret, _), choice)| {
            secret
                .cast_ballot_with_rng(prepared.survivor_roster(), choice, &mut rng)
                .expect("cast restore fixture timed-OVN ballot")
                .to_bytes()
        })
        .collect();
    lifecycle = lifecycle
        .seal_ballots(ballots, &tle_key)
        .expect("seal restore fixture timed-OVN ballots");
    let TimedOvnLifecycleStateV1::Sealed(sealed_state) = &lifecycle else {
        unreachable!("complete ballot corpus returns the sealed phase");
    };
    let sealed = sealed_state
        .clone()
        .validate(&tle_key)
        .expect("validate restore fixture sealed timed-OVN evidence");
    let release_identity = sealed.release_identity();
    let release_parameters = *tle_key.transcript().parameters();
    let mut partial_records = Vec::new();
    for recipient in 1_u16..=2 {
        let contributions = dealer_secrets
            .iter()
            .zip(&dealers)
            .map(|(secret, dealer)| {
                secret
                    .private_share(&release_parameters, dealer, recipient)
                    .expect("restore fixture private TLE contribution")
            })
            .collect::<Vec<_>>();
        let signing_share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            tle_key.transcript(),
            &contributions,
        )
        .expect("restore fixture TLE signing share");
        let partial = signing_share
            .sign_payload_with_rng(
                tle_key.transcript(),
                &release_identity.payload_bytes(),
                &mut rng,
            )
            .expect("restore fixture partial TLE release");
        partial_records.push(
            tle_key
                .encode_partial_release(release_identity, release_height, &partial)
                .expect("encode restore fixture partial TLE release"),
        );
    }
    let final_release = tle_key
        .combine_partial_releases(release_identity, release_height, &partial_records)
        .expect("combine restore fixture TLE release");
    lifecycle = lifecycle
        .finalize_release(&tle_key, release_height, final_release)
        .expect("release restore fixture timed-OVN evidence");
    let (binding, _) = lifecycle
        .validated_parliament_reducer_binding(&tle_key)
        .expect("derive exact restore fixture reducer binding");
    assert_eq!(binding.tally_counts, Some([2, 1, 0]));

    attempt
        .register_ballot_attempt(
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            3,
            ParliamentTimedOvn {
                registration_phase_blocks: 4,
                survivor_freeze_phase_blocks: 3,
                commitment_phase_blocks: 1,
                release_delay_blocks: 1,
                opening_phase_blocks: 1,
                max_ballot_retries: 2,
                max_corpus_entries: 3,
            },
            release_height,
        )
        .expect("register exact restore fixture ballot");
    attempt
        .close_ballot_registration(
            governance_attempt_id,
            ballot_attempt_id,
            binding.registration_root.expect("registration root"),
            binding.registered_voters.expect("registered voter count"),
            7,
        )
        .expect("close exact restore fixture ballot registration");
    attempt
        .freeze_ballot_survivors(
            governance_attempt_id,
            ballot_attempt_id,
            binding.dropout_root.expect("dropout root"),
            binding.survivor_root.expect("survivor root"),
            binding.survivors.expect("survivor count"),
            binding.no_recovery_root.expect("no-recovery root"),
            10,
        )
        .expect("freeze exact restore fixture ballot survivors");
    attempt
        .freeze_timed_ovn_corpus(
            governance_attempt_id,
            ballot_attempt_id,
            binding.corpus_root.expect("ballot corpus root"),
            binding.survivor_root.expect("survivor root"),
            binding.accepted_ballots.expect("accepted ballot count"),
            binding
                .timed_commitment_root
                .expect("timed commitment root"),
            11,
        )
        .expect("freeze exact restore fixture timed corpus");
    attempt
        .begin_ballot_opening_batch(
            governance_attempt_id,
            vec![ballot_attempt_id],
            release_beacon_session_id,
            release_height,
            release_height,
            BeaconPulseId::new(root(0xD8)),
        )
        .expect("open exact restore fixture ballot");
    let outcome = attempt
        .finalize_opened_ballot(
            governance_attempt_id,
            ballot_attempt_id,
            binding.corpus_root.expect("ballot corpus root"),
            binding.no_recovery_root.expect("no-recovery root"),
            tle_session_id,
            binding.opening_root.expect("opening root"),
            binding.accepted_ballots.expect("accepted ballot count"),
            ParliamentAggregateTallyV1 {
                original_seats: 3,
                accepted_ballots: 3,
                aye: 2,
                nay: 1,
                abstain: 0,
            },
            2,
            release_height,
        )
        .expect("finalize exact restore fixture ballot");
    assert_eq!(outcome, ParliamentAggregateOutcomeV1::Approved);
    if let Some(existing) = tle_key_sessions
        .iter()
        .find(|state| state.key_session_id == tle_key_session_id)
    {
        assert_eq!(
            existing,
            tle_key.public_state(),
            "shared restore fixture TLE key identifiers must retain byte-identical public state"
        );
    } else {
        tle_key_sessions.push(tle_key.public_state().clone());
    }
    if let Some((_, existing)) = tle_key_session_rosters
        .iter()
        .find(|(key_session_id, _)| *key_session_id == tle_key_session_id)
    {
        assert_eq!(
            existing, &ordered_roster,
            "shared restore fixture TLE keys retain one exact frozen roster"
        );
    } else {
        tle_key_session_rosters.push((tle_key_session_id, ordered_roster));
    }
    if let Some((_, existing)) = tle_key_session_lifecycles
        .iter_mut()
        .find(|(key_session_id, _)| *key_session_id == tle_key_session_id)
    {
        existing
            .consume_fresh_ballot(3)
            .expect("shared restore TLE key remains within its fixture use budget");
    } else {
        let mut lifecycle =
            TleKeySessionLifecycleV1::new(tle_key_session_id, 1, u64::MAX, u32::MAX)
                .expect("construct restore fixture TLE lifecycle");
        lifecycle
            .consume_fresh_ballot(3)
            .expect("consume restore fixture TLE use");
        tle_key_session_lifecycles.push((tle_key_session_id, lifecycle));
    }
    timed_ovn_evidence.push((ballot_attempt_id, lifecycle));
}

/// Build an enacted attempt with every exact cross-store restore dependency.
pub(crate) fn enacted_parliament_attempt_restore_fixture_v1(
    proposal: &ProposalKind,
    candidates: Vec<AccountId>,
    network_id: &NetworkId,
    enact_at_height: u64,
) -> EnactedParliamentRestoreFixtureV1 {
    let mut tle_key_sessions = Vec::new();
    let mut tle_key_session_rosters = Vec::new();
    let mut tle_key_session_lifecycles = Vec::new();
    let mut timed_ovn_evidence = Vec::new();
    let mut attempt = build_certified_parliament_attempt_for_testing(
        proposal,
        candidates,
        network_id,
        enact_at_height,
        |attempt, requirement, election_attempt_id, result_tag| match requirement.decision_mode {
            ParliamentDecisionModeV1::PublicFinding => {
                complete_enacted_fixture_body(attempt, requirement, election_attempt_id, result_tag)
            }
            ParliamentDecisionModeV1::HiddenBindingBallot => {
                complete_enacted_fixture_hidden_body_with_evidence(
                    attempt,
                    requirement,
                    election_attempt_id,
                    network_id,
                    &mut tle_key_sessions,
                    &mut tle_key_session_rosters,
                    &mut tle_key_session_lifecycles,
                    &mut timed_ovn_evidence,
                );
            }
        },
    );
    let governance_attempt_id = attempt.attempt().id;
    attempt
        .mark_enacted(governance_attempt_id, enact_at_height)
        .expect("mark restore fixture enacted");
    EnactedParliamentRestoreFixtureV1 {
        attempt,
        tle_key_sessions,
        tle_key_session_rosters,
        tle_key_session_lifecycles,
        timed_ovn_evidence,
    }
}

fn casting_state_at_height(
    attempt: ParliamentAttemptStateV1,
    lifecycle: TimedOvnLifecycleStateV1,
    tle_key: Option<&ValidatedTleKeySessionV1>,
    stored_key: Option<TleKeySessionId>,
    height: u64,
) -> State {
    let mut world = World::new();
    world
        .parliament_attempts
        .insert(attempt.attempt().id, attempt);
    if let (Some(key), Some(storage_id)) = (tle_key, stored_key) {
        world
            .tle_key_sessions
            .insert(storage_id, key.public_state().clone());
    }
    world.timed_ovn_evidence.insert(
        BallotAttemptId::new(lifecycle.ballot_attempt_id()),
        lifecycle,
    );
    world
        .rebuild_governance_read_indexes_for_testing()
        .expect("rebuild casting candidates from the authoritative fixture attempt");
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    for index in 0..height {
        state.push_block_hash_for_testing(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(index.to_be_bytes()),
        ));
    }
    state
}

fn governance_for_pending_draws(state: &ParliamentAttemptStateV1) -> Governance {
    let mut governance = Governance {
        parliament_alternate_size: 16,
        ..Governance::default()
    };
    for election in state
        .elections
        .values()
        .filter(|election| election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse)
    {
        let target = usize::try_from(election.attempt.request.target_seats)
            .expect("fixture target fits usize");
        match election.attempt.request.body {
            ParliamentBody::RulesCommittee => governance.rules_committee_size = target,
            ParliamentBody::AgendaCouncil => governance.agenda_council_size = target,
            ParliamentBody::InterestPanel => governance.interest_panel_size = target,
            ParliamentBody::ReviewPanel => governance.review_panel_size = target,
            ParliamentBody::CoordinationCouncil => {
                governance.coordination_council_size = target;
            }
            ParliamentBody::MpcCommittee => governance.mpc_committee_size = target,
            ParliamentBody::FmaCommittee => governance.fma_committee_size = target,
            ParliamentBody::OversightCommittee => {
                governance.oversight_committee_size = target;
            }
            ParliamentBody::PolicyJury => governance.policy_jury_size = target,
            ParliamentBody::ConfirmationJury => governance.confirmation_jury_size = target,
        }
    }
    governance
}

fn consume_sortition(
    state: &mut ParliamentAttemptStateV1,
    governance_attempt_id: GovernanceAttemptId,
    request_ids: Vec<SortitionRequestId>,
    beacon_session_id: BeaconSessionId,
    pulse_height: u64,
    pulse_id: BeaconPulseId,
) -> Result<(), ParliamentReducerErrorV1> {
    let governance = governance_for_pending_draws(state);
    let pulse_output = *pulse_id.as_bytes();
    state.consume_sortition_pulse_batch(
        governance_attempt_id,
        request_ids,
        beacon_session_id,
        pulse_height,
        pulse_id,
        pulse_output,
        &network_id(),
        &governance,
    )
}

/// Reach `NoRoster` for the generation of `election_attempt_id` through the only remaining
/// path: consume the pulse of its exact slot, open invitations and let them close empty.
fn fail_generation_with_empty_roster(
    state: &mut ParliamentAttemptStateV1,
    election_attempt_id: BodyElectionAttemptId,
    pulse_id: BeaconPulseId,
    failure_height: u64,
) {
    let governance = governance_for_pending_draws(state);
    state
        .fail_sortition_generation_with_empty_roster_for_tests(
            election_attempt_id,
            pulse_id,
            &network_id(),
            &governance,
            failure_height,
        )
        .expect("the consumed pulse left an empty roster when invitations closed");
}

fn candidates(first_tag: u8, count: u32) -> Vec<AccountId> {
    let mut candidates: Vec<_> = (0..count)
        .map(|offset| {
            let tag = first_tag
                .checked_add(u8::try_from(offset).expect("fixture candidate count fits u8"))
                .expect("fixture candidate tags do not overflow");
            account(tag)
        })
        .collect();
    candidates.sort_unstable();
    candidates
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the immutable request preimage"
)]
fn sortition_request(
    governance_attempt_id: GovernanceAttemptId,
    sequence: u32,
    body: ParliamentBody,
    candidate_first_tag: u8,
    candidate_count: u32,
    target_seats: u32,
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
    last_consumed_pulse_height: Option<u64>,
) -> (SortitionRequestV1, Vec<AccountId>) {
    let election_attempt_id =
        BodyElectionAttemptId::derive_v1(governance_attempt_id, body, sequence);
    let candidate_snapshot = candidates(candidate_first_tag, candidate_count);
    let candidate_root =
        parliament_candidate_root_v1(governance_attempt_id, body, &candidate_snapshot);
    let request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        election_attempt_id,
        body,
        candidate_root,
        candidate_count,
        target_seats,
        request_height,
        pulse_height,
        beacon_session_id,
        last_consumed_pulse_height,
    )
    .expect("canonical reducer sortition request");
    (request, candidate_snapshot)
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the pre-request capacity evidence binding"
)]
fn sortition_request_intent(
    governance_attempt_id: GovernanceAttemptId,
    sequence: u32,
    body: ParliamentBody,
    candidate_snapshot: Vec<AccountId>,
    target_seats: u32,
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
) -> SortitionRequestV1 {
    let candidate_count =
        u32::try_from(candidate_snapshot.len()).expect("fixture candidate count fits u32");
    let mut request = SortitionRequestV1 {
        id: SortitionRequestId::new([0; 32]),
        governance_attempt_id,
        body_election_attempt_id: BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            body,
            sequence,
        ),
        body,
        candidate_root: parliament_candidate_root_v1(
            governance_attempt_id,
            body,
            &candidate_snapshot,
        ),
        candidate_count,
        target_seats,
        request_height,
        pulse_height,
        beacon_session_id,
    };
    request.id = request.canonical_id();
    request
}

/// Return the pulse slot a fresh fixture generation requested at `request_height` targets.
fn generation_slot(
    state: &ParliamentAttemptStateV1,
    request_height: u64,
    beacon_session_id: BeaconSessionId,
) -> u64 {
    state
        .next_sortition_generation_pulse_height_v1(request_height, beacon_session_id)
        .expect("fixture generation slot fits u64")
}

fn attempt_with_proposal_tag(proposal_tag: u8) -> GovernanceAttemptV1 {
    let proposal_content_id = proposal_id(proposal_tag);
    GovernanceAttemptV1 {
        id: GovernanceAttemptId::derive_v1(proposal_content_id, 0),
        proposal_content_id,
        sequence: 0,
        risk_tier: RiskTierV1::Standard,
        stage: GovernanceStageV1::Qualification,
        status: GovernanceAttemptStatusV1::Active,
    }
}

fn attempt() -> GovernanceAttemptV1 {
    attempt_with_proposal_tag(2)
}

fn state_with_proposal_tag(
    required_bodies: Vec<RequiredParliamentBodyV1>,
    proposal_tag: u8,
) -> ParliamentAttemptStateV1 {
    ParliamentAttemptStateV1::try_new(
        attempt_with_proposal_tag(proposal_tag),
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        required_bodies,
    )
    .expect("valid reducer fixture")
}

fn state(required_bodies: Vec<RequiredParliamentBodyV1>) -> ParliamentAttemptStateV1 {
    state_with_proposal_tag(required_bodies, 2)
}

fn policy_only_state() -> ParliamentAttemptStateV1 {
    policy_only_state_with_proposal_tag(2)
}

fn policy_only_state_with_proposal_tag(proposal_tag: u8) -> ParliamentAttemptStateV1 {
    state_with_proposal_tag(
        vec![RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        }],
        proposal_tag,
    )
}

/// Build a semantically plausible attempt whose canonical frame necessarily exceeds 16 MiB.
pub(crate) fn oversized_attempt_state_fixture_v1(proposal_tag: u8) -> ParliamentAttemptStateV1 {
    let mut state = policy_only_state_with_proposal_tag(proposal_tag);
    // Every entry emits two nonempty enum discriminants. Even without counting the
    // sequence length and per-element framing, this exceeds the protocol byte bound.
    let oversized_entry_count = MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1 / 2 + 1;
    state.required_bodies = vec![
        RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        };
        oversized_entry_count
    ];
    state
}

#[test]
fn attempt_state_encoded_size_bound_accepts_small_and_rejects_oversized() {
    let small = policy_only_state();
    small
        .validate_encoded_size_v1()
        .expect("ordinary Parliament attempt fits the authoritative frame bound");
    small.validate().expect("ordinary attempt remains valid");

    let oversized = oversized_attempt_state_fixture_v1(0xF1);
    assert_eq!(
        oversized.validate(),
        Err(ParliamentReducerErrorV1::AttemptStateSizeLimitExceeded),
        "the exact frame bound must run before semantic pipeline validation"
    );
}

fn deploy_contract_proposal() -> ProposalKind {
    ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: account(40),
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("canonical contract address"),
        code_hash: ContractCodeHash::new(root(41)),
        abi_hash: ContractAbiHash::new(root(42)),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    })
}

fn contract_emergency_hold_proposal() -> ProposalKind {
    ProposalKind::ContractEmergencyHold(ContractEmergencyHoldProposalV1 {
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("canonical contract address"),
        expected_revision: 7,
        expected_code_hash: ContractCodeHash::new(root(41)),
        incident_digest: root(42),
        reason: "bounded incident containment".to_owned(),
        duration_blocks: 3_600,
    })
}

fn validation_fee_asset(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("validation-fee test domain"),
        name.parse::<Name>()
            .expect("validation-fee test asset name"),
    )
}

pub(crate) fn validation_fee_policy_proposal() -> ProposalKind {
    let lifecycle = validation_fee_payout_lifecycle_proposal();
    let ProposalKind::ValidationFeePayoutLifecycle(ref lifecycle_proposal) = lifecycle else {
        unreachable!()
    };
    let binding = lifecycle_proposal.payout_binding.clone();
    ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: account(43),
        policy: ValidationFeePolicyV1 {
            retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
            effective_from_ms: 1793451600000,
            notice_published_at_ms: 1790859600000,
            schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            network_id: network_id(),
            policy_version: 1,
            previous_policy_hash: None,
            ds_asset_id: validation_fee_asset("fee_token"),
            ds_scale: VALIDATION_FEE_DS_SCALE,
            fee: initial_validation_fee_amount(),
            treasury_account_id: binding.treasury_account_id.clone(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
            exemption_classes: vec![
                iroha_data_model::validation_fee::VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS
                    .to_owned(),
            ],
            reward_custody: binding.custody(),
        },
    })
}

fn validation_fee_payout_lifecycle_proposal() -> ProposalKind {
    let contract_address = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
        .parse::<iroha_data_model::smart_contract::ContractAddress>()
        .expect("canonical validation-fee contract address");
    let pool_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &network_id(),
        &account(48),
        48,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("pool address");
    let payout_binding = ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract_address.subject_id(),
        contract_address,
        code_hash: root(46),
        entrypoint: "autonomous_validation_fee_tick"
            .parse()
            .expect("canonical validation-fee entrypoint"),
        ds_asset_id: validation_fee_asset("fee_token"),
        xor_asset_id: iroha_data_model::parameter::system::SumeragiNposParameters::default()
            .xor_asset_definition_id,
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: root(48),
        reward_pool_account_id: account(49),
        reference_feed_id: "xor_per_sbd".parse().expect("feed"),
        reference_feed_config_version: 1,
        reference_provider_accounts: (60..65).map(account).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100000,
        min_interval_ms: 60000,
        max_source_age_ms: 300000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    };
    assert_eq!(payout_binding.invariant_error(), None);
    ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
        proposal_operator: account(45),
        payout_binding,
    })
}

fn public_requirements(bodies: &[ParliamentBody]) -> Vec<RequiredParliamentBodyV1> {
    bodies
        .iter()
        .copied()
        .map(|body| RequiredParliamentBodyV1 {
            body,
            decision_mode: if body == ParliamentBody::PolicyJury {
                ParliamentDecisionModeV1::HiddenBindingBallot
            } else {
                ParliamentDecisionModeV1::PublicFinding
            },
        })
        .collect()
}

#[test]
fn validation_fee_proposals_bind_committed_global_network_xor() {
    use iroha_data_model::{
        Registrable as _,
        asset::{AssetBalancePolicy, AssetDefinition},
        parameter::{Parameter, system::SumeragiNposParameters},
    };
    use iroha_primitives::numeric::NumericSpec;

    let ProposalKind::ValidationFeePayoutLifecycle(lifecycle) =
        validation_fee_payout_lifecycle_proposal()
    else {
        unreachable!()
    };
    let binding = lifecycle.payout_binding;
    let parameters = SumeragiNposParameters::default();
    assert_eq!(binding.xor_asset_id, parameters.xor_asset_definition_id);
    assert_ne!(binding.ds_asset_id, binding.xor_asset_id);
    let owner = account(43);
    let definitions = [
        (
            binding.ds_asset_id.clone(),
            "fee_token",
            u32::from(VALIDATION_FEE_DS_SCALE),
        ),
        (binding.xor_asset_id.clone(), "xor", 9),
    ]
    .map(|(id, name, scale)| {
        AssetDefinition::new(
            id,
            name.to_owned(),
            NumericSpec::fractional(scale),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&owner)
    });
    let world = World::with([], [], definitions);
    {
        let mut committed = world.parameters.block();
        committed
            .set_parameter(Parameter::Custom(parameters.into_custom_parameter()))
            .expect("valid fixture parameters");
        committed.commit();
    }
    crate::state::validate_network_xor_asset(&world.view(), &binding.xor_asset_id)
        .expect("Parliament fee proposal uses committed global scale-nine XOR");
    assert!(crate::state::validate_network_xor_asset(&world.view(), &binding.ds_asset_id).is_err());
    let ProposalKind::ValidationFeePolicy(policy) = validation_fee_policy_proposal() else {
        unreachable!()
    };
    assert_eq!(policy.policy.reward_custody, binding.custody());
}

#[test]
fn validation_fee_proposals_require_mpc_immediately_before_fma() {
    let expected = public_requirements(VALIDATION_FEE_REQUIRED_BODIES_V1);
    for proposal in [
        validation_fee_policy_proposal(),
        validation_fee_payout_lifecycle_proposal(),
    ] {
        let (risk_tier, requirements) = parliament_attempt_policy_v1(&proposal);
        assert_eq!(risk_tier, RiskTierV1::Constitutional);
        assert_eq!(requirements, expected);
        assert!(required_pipeline_is_canonical(&requirements));

        let mpc = requirements
            .iter()
            .position(|entry| entry.body == ParliamentBody::MpcCommittee)
            .expect("validation-fee pipeline contains MPC");
        let fma = requirements
            .iter()
            .position(|entry| entry.body == ParliamentBody::FmaCommittee)
            .expect("validation-fee pipeline contains FMA");
        assert_eq!(fma, mpc + 1, "MPC must immediately precede FMA");

        let mut weakened = proposal_bound_state(&proposal);
        weakened
            .required_bodies
            .retain(|entry| entry.body != ParliamentBody::MpcCommittee);
        weakened
            .validate()
            .expect("the weakened order is structurally canonical");
        assert_eq!(
            weakened.validate_proposal_bindings_v1(&proposal),
            Err(ParliamentReducerErrorV1::ProposalBindingMismatch),
            "proposal semantics must reject an MPC-free validation-fee pipeline"
        );

        let mut reversed = requirements;
        reversed.swap(mpc, fma);
        assert!(
            !required_pipeline_is_canonical(&reversed),
            "the canonical stage order must reject FMA before MPC"
        );
    }
}

#[test]
fn contract_emergency_hold_uses_full_lifecycle_pipeline() {
    let expected = public_requirements(CONTRACT_LIFECYCLE_REQUIRED_BODIES_V1);
    assert_eq!(
        CONTRACT_LIFECYCLE_REQUIRED_BODIES_V1,
        &[
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
            ParliamentBody::InterestPanel,
            ParliamentBody::ReviewPanel,
            ParliamentBody::OversightCommittee,
            ParliamentBody::PolicyJury,
        ]
    );
    let (risk_tier, requirements) =
        parliament_attempt_policy_v1(&contract_emergency_hold_proposal());
    assert_eq!(risk_tier, RiskTierV1::Emergency);
    assert_eq!(requirements, expected);
    assert!(required_pipeline_is_canonical(&requirements));
}

#[test]
fn sccp_pipeline_remains_fma_only() {
    assert_eq!(
        SCCP_ROUTE_GOVERNANCE_REQUIRED_BODIES_V1,
        &[
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
            ParliamentBody::InterestPanel,
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
            ParliamentBody::FmaCommittee,
            ParliamentBody::OversightCommittee,
            ParliamentBody::PolicyJury,
        ]
    );
    assert!(!SCCP_ROUTE_GOVERNANCE_REQUIRED_BODIES_V1.contains(&ParliamentBody::MpcCommittee));
    assert!(required_pipeline_is_canonical(&public_requirements(
        SCCP_ROUTE_GOVERNANCE_REQUIRED_BODIES_V1
    )));
}

fn proposal_bound_state(proposal: &ProposalKind) -> ParliamentAttemptStateV1 {
    let proposal_content_id = ProposalContentId::new(proposal.fingerprint());
    let (risk_tier, required_bodies) = parliament_attempt_policy_v1(proposal);
    ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: GovernanceAttemptId::derive_v1(proposal_content_id, 0),
            proposal_content_id,
            sequence: 0,
            risk_tier,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        proposal.effect_preimage_hash_v1(),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: proposal
                .governed_subject_id_v1()
                .expect("derive proposal subject"),
        }),
        required_bodies,
    )
    .expect("canonical proposal-bound reducer state")
}

#[test]
fn governance_attempt_retry_bound_is_enforced_at_construction_and_restore() {
    let required = vec![RequiredParliamentBodyV1 {
        body: ParliamentBody::PolicyJury,
        decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
    }];
    let mut final_attempt = attempt();
    final_attempt.sequence = MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1;
    final_attempt.id =
        GovernanceAttemptId::derive_v1(final_attempt.proposal_content_id, final_attempt.sequence);
    let final_state = ParliamentAttemptStateV1::try_new(
        final_attempt,
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        required.clone(),
    )
    .expect("the final bounded governance attempt is admissible");
    final_state
        .validate()
        .expect("the final bounded governance attempt restores");

    let mut over_limit = attempt();
    over_limit.sequence = MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 + 1;
    over_limit.id =
        GovernanceAttemptId::derive_v1(over_limit.proposal_content_id, over_limit.sequence);
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            over_limit,
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: root(4),
            }),
            required,
        ),
        Err(ParliamentReducerErrorV1::GovernanceAttemptRetryLimitExceeded)
    );

    let mut corrupted = final_state;
    corrupted.attempt.sequence = MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 + 1;
    corrupted.attempt.id = GovernanceAttemptId::derive_v1(
        corrupted.attempt.proposal_content_id,
        corrupted.attempt.sequence,
    );
    assert_eq!(
        corrupted.validate(),
        Err(ParliamentReducerErrorV1::GovernanceAttemptRetryLimitExceeded)
    );
}

#[test]
fn successor_attempt_inherits_exact_proposal_redraw_prefix() {
    let mut first = policy_only_state();
    let first_id = first.attempt.id;
    first
        .complete_qualification(first_id)
        .expect("enter first Policy Jury stage");
    let (initial_request, initial_candidates) = sortition_request(
        first_id,
        0,
        ParliamentBody::PolicyJury,
        150,
        3,
        3,
        10,
        20,
        beacon_session(151),
        None,
    );
    let initial_election_id = initial_request.body_election_attempt_id;
    first
        .register_sortition_request(first_id, 0, initial_request, initial_candidates)
        .expect("register the proposal baseline draw");
    fail_generation_with_empty_roster(&mut first, initial_election_id, pulse_id(156), 21);
    let (retry_request, retry_candidates) = sortition_request(
        first_id,
        1,
        ParliamentBody::PolicyJury,
        152,
        3,
        3,
        21,
        32,
        beacon_session(153),
        None,
    );
    first
        .register_sortition_request(first_id, 1, retry_request, retry_candidates)
        .expect("register one fresh roster/pulse generation");
    assert_eq!(first.randomness_redraws_used_v1(), Ok(1));

    let mut successor_attempt = attempt();
    successor_attempt.sequence = 1;
    successor_attempt.id = GovernanceAttemptId::derive_v1(
        successor_attempt.proposal_content_id,
        successor_attempt.sequence,
    );
    let required = vec![RequiredParliamentBodyV1 {
        body: ParliamentBody::PolicyJury,
        decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
    }];
    let mut successor = ParliamentAttemptStateV1::try_new_with_randomness_redraws_before_attempt(
        successor_attempt,
        first.randomness_redraws_used_v1().expect("bounded prefix"),
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        required.clone(),
    )
    .expect("construct successor with exact prefix");
    let successor_id = successor.attempt.id;
    successor
        .complete_qualification(successor_id)
        .expect("enter successor Policy Jury stage");
    let (successor_request, successor_candidates) = sortition_request(
        successor_id,
        0,
        ParliamentBody::PolicyJury,
        154,
        3,
        3,
        40,
        50,
        beacon_session(155),
        None,
    );
    successor
        .register_sortition_request(successor_id, 0, successor_request, successor_candidates)
        .expect("successor initial sortition is proposal-wide fresh randomness");
    assert_eq!(successor.randomness_redraws_used_v1(), Ok(2));
    validate_parliament_randomness_redraw_lineage_v1([&first, &successor])
        .expect("exact inherited redraw lineage");
    validate_parliament_randomness_redraw_lineage_v1([&successor, &first])
        .expect("lineage validation is independent of hashed storage-key order");

    let reset = ParliamentAttemptStateV1::try_new_with_randomness_redraws_before_attempt(
        successor_attempt,
        0,
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        required,
    )
    .expect("an isolated attempt cannot prove its predecessor prefix");
    assert_eq!(
        validate_parliament_randomness_redraw_lineage_v1([&first, &reset]),
        Err(ParliamentReducerErrorV1::RandomnessRedrawLineageMismatch),
        "a terminal attempt must not reset the proposal-wide grinding budget"
    );
}

#[test]
fn proposal_attempt_lineage_requires_exact_contiguous_sequences() {
    let first = policy_only_state();
    assert_eq!(
        validate_parliament_randomness_redraw_lineage_v1([&first, &first]),
        Err(ParliamentReducerErrorV1::RetrySequenceMismatch),
        "a duplicate sequence must not masquerade as another zero-cost generation"
    );

    let mut skipped_attempt = attempt();
    skipped_attempt.sequence = 2;
    skipped_attempt.id = GovernanceAttemptId::derive_v1(
        skipped_attempt.proposal_content_id,
        skipped_attempt.sequence,
    );
    let skipped = ParliamentAttemptStateV1::try_new_with_randomness_redraws_before_attempt(
        skipped_attempt,
        0,
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        10,
        FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        vec![RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        }],
    )
    .expect("an isolated reducer cannot prove that its predecessor exists");
    assert_eq!(
        validate_parliament_randomness_redraw_lineage_v1([&first, &skipped]),
        Err(ParliamentReducerErrorV1::RetrySequenceMismatch),
        "proposal history must not omit sequence one"
    );
}

#[test]
fn proposal_binding_validation_rejects_weakened_persisted_policy() {
    let proposal = deploy_contract_proposal();
    let state = proposal_bound_state(&proposal);
    state
        .validate_proposal_bindings_v1(&proposal)
        .expect("canonical proposal bindings");

    let mut escalated = state.clone();
    escalated.attempt.risk_tier = RiskTierV1::Constitutional;
    escalated
        .validate_proposal_bindings_v1(&proposal)
        .expect("upward-only risk escalation remains valid");

    let mut downgraded = state.clone();
    downgraded.attempt.risk_tier = RiskTierV1::Routine;
    assert_eq!(
        downgraded.validate_proposal_bindings_v1(&proposal),
        Err(ParliamentReducerErrorV1::ProposalBindingMismatch)
    );

    let mut substituted_effect = state.clone();
    substituted_effect.effect_preimage_hash = root(99);
    substituted_effect
        .validate()
        .expect("an internally valid effect still needs its proposal binding");
    assert_eq!(
        substituted_effect.validate_proposal_bindings_v1(&proposal),
        Err(ParliamentReducerErrorV1::ProposalBindingMismatch)
    );

    let mut substituted_subject = state.clone();
    substituted_subject.expected_head =
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(100),
        });
    substituted_subject
        .validate()
        .expect("an internally valid subject still needs its proposal binding");
    assert_eq!(
        substituted_subject.validate_proposal_bindings_v1(&proposal),
        Err(ParliamentReducerErrorV1::ProposalBindingMismatch)
    );

    let mut weakened_pipeline = state;
    weakened_pipeline.required_bodies.remove(0);
    weakened_pipeline
        .validate()
        .expect("an ordered subset still needs the proposal's exact base policy");
    assert_eq!(
        weakened_pipeline.validate_proposal_bindings_v1(&proposal),
        Err(ParliamentReducerErrorV1::ProposalBindingMismatch)
    );
}

struct BodyFixture {
    state: ParliamentAttemptStateV1,
    body_id: BodyInstanceId,
    election_id: BodyElectionAttemptId,
    request_id: SortitionRequestId,
}

fn sealed_policy_body_with_proposal_tag(seats: u32, proposal_tag: u8) -> BodyFixture {
    let mut state = policy_only_state_with_proposal_tag(proposal_tag);
    let attempt_id = state.attempt.id;
    state
        .complete_qualification(attempt_id)
        .expect("enter Policy Jury stage");
    let (request, candidate_snapshot) = sortition_request(
        attempt_id,
        0,
        ParliamentBody::PolicyJury,
        12,
        seats,
        seats,
        10,
        20,
        beacon_session(13),
        None,
    );
    let election_id = request.body_election_attempt_id;
    let request_id = request.id;
    state
        .register_sortition_request(attempt_id, 0, request, candidate_snapshot)
        .expect("register policy sortition");
    consume_sortition(
        &mut state,
        attempt_id,
        vec![request_id],
        beacon_session(13),
        20,
        pulse_id(14),
    )
    .expect("consume policy pulse");
    state
        .begin_invitation_acceptance(attempt_id, election_id, 20, 1)
        .expect("begin invitation acceptance");
    let selected: Vec<_> = state
        .election(&election_id)
        .expect("drawn election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect();
    for member in selected {
        state
            .record_invitation_response(attempt_id, election_id, &member, true, 20)
            .expect("accept policy invitation");
    }
    let body_id = state
        .seal_body_roster(attempt_id, election_id, 21)
        .expect("seal policy roster");
    BodyFixture {
        state,
        body_id,
        election_id,
        request_id,
    }
}

fn sealed_policy_body(seats: u32) -> BodyFixture {
    sealed_policy_body_with_proposal_tag(seats, 2)
}

fn advance_to_vote(state: &mut ParliamentAttemptStateV1, body_id: BodyInstanceId) {
    let attempt_id = state.attempt.id;
    for phase in [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
        DeliberationPhaseV1::Vote,
    ] {
        state
            .advance_body_phase(attempt_id, body_id, phase, 22, 10)
            .expect("advance one exact deliberation phase");
    }
}

fn timed_ovn_policy() -> ParliamentTimedOvn {
    ParliamentTimedOvn {
        registration_phase_blocks: 4,
        survivor_freeze_phase_blocks: 3,
        commitment_phase_blocks: 2,
        release_delay_blocks: 4,
        opening_phase_blocks: 2,
        max_ballot_retries: 2,
        max_corpus_entries: 3,
    }
}

/// Build one validated active timed-OVN ballot with a caller-selected schedule.
pub(crate) fn active_timed_ovn_reservation_attempt_fixture_v1(
    proposal_tag: u8,
    key_session_tag: u8,
    registered_at_height: u64,
) -> ParliamentAttemptStateV1 {
    active_timed_ovn_attempt_awaiting_release_fixture_v1(
        proposal_tag,
        key_session_tag,
        registered_at_height,
        beacon_session(key_session_tag.wrapping_add(1)),
    )
}

/// The same active timed-OVN ballot, still in registration, whose frozen release slot is on
/// the caller's logical beacon session. Its release height is whatever the fixture policy
/// derives from `registered_at_height`; read it from `required_beacon_pulse_slots_v1`.
pub(crate) fn active_timed_ovn_attempt_awaiting_release_fixture_v1(
    proposal_tag: u8,
    key_session_tag: u8,
    registered_at_height: u64,
    release_beacon_session_id: BeaconSessionId,
) -> ParliamentAttemptStateV1 {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body_with_proposal_tag(3, proposal_tag);
    advance_to_vote(&mut state, body_id);
    let governance_attempt_id = state.attempt.id;
    let policy = timed_ovn_policy();
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_id, 0);
    let tle_key_session_id = tle_key_session(key_session_tag);
    let release_height = timed_ballot_schedule(registered_at_height, policy)
        .expect("reservation fixture schedule")
        .3;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            ballot_attempt_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            registered_at_height,
            policy,
            release_height,
        )
        .expect("register active reservation fixture ballot");
    state
}

#[test]
fn timed_ovn_schedule_reserves_one_maximum_chunk_block_per_corpus_slice() {
    let maximum_policy = ParliamentTimedOvn {
        registration_phase_blocks: 1_001,
        survivor_freeze_phase_blocks: 1_000,
        commitment_phase_blocks: 32,
        max_corpus_entries: 1_000,
        ..timed_ovn_policy()
    };
    assert!(timed_ballot_schedule(10, maximum_policy).is_ok());
    assert_eq!(
        timed_ballot_schedule(
            10,
            ParliamentTimedOvn {
                commitment_phase_blocks: 31,
                ..maximum_policy
            },
        ),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule)
    );
    assert_eq!(
        timed_ballot_schedule(
            10,
            ParliamentTimedOvn {
                registration_phase_blocks: 1_000,
                ..maximum_policy
            },
        ),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule)
    );
    assert_eq!(
        timed_ballot_schedule(
            10,
            ParliamentTimedOvn {
                survivor_freeze_phase_blocks: 999,
                ..maximum_policy
            },
        ),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule)
    );
}

#[test]
fn awaited_beacon_slots_are_exact_for_sortition_and_frozen_ballot_release() {
    let mut sortition = policy_only_state();
    let governance_attempt_id = sortition.attempt.id;
    sortition
        .complete_qualification(governance_attempt_id)
        .expect("enter Policy Jury stage");
    let session_id = beacon_session(81);
    let (request, candidate_snapshot) = sortition_request(
        governance_attempt_id,
        0,
        ParliamentBody::PolicyJury,
        82,
        3,
        3,
        10,
        20,
        session_id,
        None,
    );
    let election_attempt_id = request.body_election_attempt_id;
    let request_id = request.id;
    sortition
        .register_sortition_request(governance_attempt_id, 0, request, candidate_snapshot)
        .expect("register immutable sortition pulse slot");
    assert!(sortition.requires_beacon_pulse_at(session_id, 20));
    assert!(!sortition.requires_beacon_pulse_at(beacon_session(83), 20));
    assert_eq!(
        sortition.required_beacon_pulse_slots_v1(),
        BTreeSet::from([(session_id, 20)])
    );
    assert!(sortition.unavailable_release_pulse_slots_v1().is_empty());

    // The wait never expires: at the slot, just past it and arbitrarily far past it the
    // election still awaits exactly its frozen slot and no sortition slot is classified.
    for height in [20, 21, 1_000_000, u64::MAX] {
        let mut waiting = sortition.clone();
        assert_eq!(
            waiting.fail_body_election_no_roster(
                governance_attempt_id,
                election_attempt_id,
                height,
            ),
            Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection
            ))
        );
        assert_eq!(
            waiting, sortition,
            "a rejected failure must not mutate state"
        );
    }
    assert_eq!(
        sortition
            .election(&election_attempt_id)
            .expect("pending election")
            .attempt
            .status,
        BodyElectionAttemptStatusV1::AwaitingPulse
    );
    assert!(sortition.requires_beacon_pulse_at(session_id, 20));
    assert!(sortition.unavailable_release_pulse_slots_v1().is_empty());
    sortition
        .validate()
        .expect("an election awaiting its pulse is canonical persisted state");
    for restored_height in [10, 20, 21, 1_000_000] {
        sortition
            .validate_restored_height_v1(restored_height)
            .expect("an awaited slot far below the restored height restores cleanly");
    }

    // Consuming the pulse of exactly that slot is the only way out of the wait.
    consume_sortition(
        &mut sortition,
        governance_attempt_id,
        vec![request_id],
        session_id,
        20,
        pulse_id(86),
    )
    .expect("the exact slot pulse still draws, however late it is consumed");
    assert!(!sortition.requires_beacon_pulse_at(session_id, 20));
    assert!(sortition.required_beacon_pulse_slots_v1().is_empty());

    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let governance_attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let release_session_id = beacon_session(84);
    let release_height = 40;
    let tle_key_session_id = tle_key_session(85);
    let tle_session_id = TleSessionId::derive_v1(
        ballot_id,
        tle_key_session_id,
        release_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            ballot_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register arbitrary frozen ballot release slot");
    assert!(state.requires_beacon_pulse_at(release_session_id, release_height));
    assert!(state.requires_beacon_pulse_at(release_session_id, release_height));
    assert!(!state.requires_beacon_pulse_at(release_session_id, release_height - 1));
}

struct OpeningFixture {
    state: ParliamentAttemptStateV1,
    body_id: BodyInstanceId,
    ballot_id: BallotAttemptId,
    tle_id: TleSessionId,
    accepted: u32,
}

fn opened_policy_ballot(seats: u32, accepted: u32) -> OpeningFixture {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(seats);
    advance_to_vote(&mut state, body_id);
    let attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let release_beacon_session_id = beacon_session(24);
    let tle_key_session_id = tle_key_session(23);
    let max_corpus_entries = seats.max(accepted);
    let policy = ParliamentTimedOvn {
        registration_phase_blocks: u64::from(max_corpus_entries)
            .checked_add(1)
            .expect("fixture corpus capacity fits the height domain"),
        survivor_freeze_phase_blocks: u64::from(max_corpus_entries),
        commitment_phase_blocks: parliament_timed_ovn_required_chunk_blocks_v1(max_corpus_entries)
            .max(2),
        max_corpus_entries,
        ..timed_ovn_policy()
    };
    let registered_at_height = 27;
    let (
        registration_close_height,
        survivor_freeze_height,
        commitment_close_height,
        release_height,
        _,
    ) = timed_ballot_schedule(registered_at_height, policy).expect("valid fixture schedule");
    let tle_id = TleSessionId::derive_v1(
        ballot_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            attempt_id,
            body_id,
            ballot_id,
            0,
            tle_id,
            tle_key_session_id,
            release_beacon_session_id,
            registered_at_height,
            policy,
            release_height,
        )
        .expect("register private ballot");
    state
        .close_ballot_registration(
            attempt_id,
            ballot_id,
            root(19),
            accepted,
            registration_close_height,
        )
        .expect("freeze registration");
    state
        .freeze_ballot_survivors(
            attempt_id,
            ballot_id,
            root(21),
            root(29),
            accepted,
            root(22),
            survivor_freeze_height,
        )
        .expect("freeze survivor roster");
    state
        .freeze_timed_ovn_corpus(
            attempt_id,
            ballot_id,
            root(20),
            root(29),
            accepted,
            root(25),
            commitment_close_height,
        )
        .expect("freeze complete timed OVN corpus");
    assert_eq!(
        state.begin_ballot_opening_batch(
            attempt_id,
            vec![ballot_id],
            beacon_session(24),
            release_height,
            release_height - 1,
            pulse_id(26),
        ),
        Err(ParliamentReducerErrorV1::ReleaseHeightNotReached)
    );
    state
        .begin_ballot_opening_batch(
            attempt_id,
            vec![ballot_id],
            beacon_session(24),
            release_height,
            release_height,
            pulse_id(26),
        )
        .expect("begin timed opening");
    OpeningFixture {
        state,
        body_id,
        ballot_id,
        tle_id,
        accepted,
    }
}

fn finalize_policy(
    fixture: &mut OpeningFixture,
    aye: u32,
    nay: u32,
    abstain: u32,
) -> ParliamentAggregateOutcomeV1 {
    finalize_policy_with_confirmation_capacity(
        fixture,
        aye,
        nay,
        abstain,
        MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
    )
}

fn finalize_policy_with_confirmation_capacity(
    fixture: &mut OpeningFixture,
    aye: u32,
    nay: u32,
    abstain: u32,
    eligible_confirmation_candidates: u32,
) -> ParliamentAggregateOutcomeV1 {
    let attempt_id = fixture.state.attempt.id;
    let result_height = fixture
        .state
        .ballot(&fixture.ballot_id)
        .and_then(|ballot| ballot.opening_height)
        .expect("fixture ballot opening height");
    fixture
        .state
        .finalize_opened_ballot(
            attempt_id,
            fixture.ballot_id,
            root(20),
            root(22),
            fixture.tle_id,
            root(27),
            fixture.accepted,
            ParliamentAggregateTallyV1 {
                original_seats: fixture
                    .state
                    .body(&fixture.body_id)
                    .expect("fixture body")
                    .instance
                    .original_seats,
                accepted_ballots: fixture.accepted,
                aye,
                nay,
                abstain,
            },
            eligible_confirmation_candidates,
            result_height,
        )
        .expect("finalize policy aggregate")
}
