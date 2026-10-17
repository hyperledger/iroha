/// Driver plans over fixture attempts.
mod planner_tests {
    use super::*;
    use iroha_data_model::isi::governance::{
        ParliamentBeginInvitationAcceptanceV1, ParliamentCloseBallotRegistrationV1,
        ParliamentConsumeSortitionPulseBatchV1, ParliamentFailBallotNoResultV1,
        ParliamentFailBodyElectionNoRosterV1, ParliamentLifecycleTransitionV1,
        ParliamentRegisterSortitionRequestV1,
    };

    /// World inputs of a driver plan served from fixed maps.
    #[derive(Default)]
    struct FixedPlanWorld {
        pulses: BTreeMap<(BeaconSessionId, u64), (BeaconPulseId, [u8; 32])>,
        key_session: Option<TleKeySessionId>,
        candidates: Option<Vec<AccountId>>,
    }

    impl ParliamentPlanWorldV1 for FixedPlanWorld {
        fn verified_pulse(
            &self,
            session: BeaconSessionId,
            height: u64,
        ) -> Option<(BeaconPulseId, [u8; 32])> {
            self.pulses.get(&(session, height)).copied()
        }

        fn fresh_ballot_tle_key_session(&self, _height: u64) -> Option<TleKeySessionId> {
            self.key_session
        }

        fn eligible_parliament_candidates(
            &self,
            _governance: &Governance,
        ) -> Option<Vec<AccountId>> {
            self.candidates.clone()
        }
    }

    /// Apply `plan` as a driver would at `height` (the due batch, then that height's exact
    /// transitions) through the reducer, asserting that persistence accepts every successor.
    fn replay_plan(
        state: &ParliamentAttemptStateV1,
        plan: &ParliamentDriverPlanV1,
        world: &FixedPlanWorld,
        governance: &Governance,
        height: u64,
    ) -> ParliamentAttemptStateV1 {
        let mut state = state.clone();
        let id = state.attempt.id;
        let exact = plan
            .exact
            .iter()
            .filter(|exact| exact.height == height)
            .map(|exact| &exact.transition);
        for transition in plan.due.iter().chain(exact) {
            let applied = match transition {
                ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(payload) => {
                    state.fail_body_election_no_roster(id, payload.election_attempt_id, height)
                }
                ParliamentLifecycleTransitionV1::SealBodyRoster(payload) => state
                    .seal_body_roster(id, payload.election_attempt_id, height)
                    .map(drop),
                ParliamentLifecycleTransitionV1::AdvanceBodyPhase(payload) => state
                    .advance_body_phase(
                        id,
                        payload.body_instance_id,
                        payload.target,
                        height,
                        governance.parliament_public_finding_phase_blocks,
                    ),
                ParliamentLifecycleTransitionV1::RegisterSortitionRequest(payload) => {
                    // The executor's admission: a hidden body below the anonymity floor
                    // records capacity evidence for the whole generation.
                    let snapshot = world.candidates.clone().expect("planned snapshot");
                    let hidden_body_requested = payload.requests.iter().any(|entry| {
                        state.required_bodies().iter().any(|required| {
                            required.body == entry.request.body
                                && required.decision_mode
                                    == ParliamentDecisionModeV1::HiddenBindingBallot
                        })
                    });
                    if hidden_body_requested
                        && !hidden_ballot_population_meets_anonymity_floor_v1(snapshot.len())
                    {
                        state.record_hidden_sortition_capacity_failure_batch(
                            id,
                            payload.requests.clone(),
                            snapshot,
                        )
                    } else {
                        state.register_sortition_request_batch(
                            id,
                            payload.requests.clone(),
                            snapshot,
                        )
                    }
                }
                other => panic!("transition outside this replay: {other:?}"),
            };
            applied.expect("the reducer accepts every planned transition");
            state
                .validate()
                .expect("persistence accepts every planned successor");
        }
        state
    }

    fn register_sortition(
        requests: Vec<ParliamentSortitionRequestRegistrationV1>,
    ) -> ParliamentLifecycleTransitionV1 {
        ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
            ParliamentRegisterSortitionRequestV1 { requests },
        )
    }

    fn plan_governance() -> Governance {
        Governance {
            parliament_invitation_phase_blocks: 1,
            parliament_public_finding_phase_blocks: 10,
            parliament_timed_ovn: timed_ovn_policy(),
            ..Governance::default()
        }
    }

    fn policy_sortition_registered() -> (
        ParliamentAttemptStateV1,
        BodyElectionAttemptId,
        SortitionRequestId,
    ) {
        let mut state = policy_only_state();
        let attempt_id = state.attempt.id;
        state
            .complete_qualification(attempt_id)
            .expect("enter Policy Jury stage");
        let (request, candidate_snapshot) = sortition_request(
            attempt_id,
            0,
            ParliamentBody::PolicyJury,
            12,
            3,
            3,
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
        (state, election_id, request_id)
    }

    #[test]
    fn planner_completes_qualification_then_defers_to_the_initial_sortition() {
        let state = policy_only_state();
        let plan = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            7,
            10,
        );
        assert_eq!(
            plan.due,
            vec![
                ParliamentLifecycleTransitionV1::CompleteQualification,
                ParliamentLifecycleTransitionV1::RegisterInitialSortition,
            ]
        );
        assert!(plan.exact.is_empty());
    }

    #[test]
    fn planner_consumes_the_exact_slot_pulse_and_never_fails_a_missing_one() {
        let (state, election_id, request_id) = policy_sortition_registered();
        let mut governance = governance_for_pending_draws(&state);
        governance.parliament_invitation_phase_blocks = 1;
        let world = FixedPlanWorld {
            pulses: [(
                (beacon_session(13), 20),
                (pulse_id(14), *pulse_id(14).as_bytes()),
            )]
            .into(),
            ..FixedPlanWorld::default()
        };
        // The pulse height is not committed yet: nothing is due and nothing fails.
        let early = state.plan_driver_v1(&world, &network_id(), &governance, 19, 22);
        assert!(early.due.is_empty(), "{early:?}");
        let plan = state.plan_driver_v1(&world, &network_id(), &governance, 20, 23);
        assert_eq!(
            plan.due,
            vec![
                ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
                    ParliamentConsumeSortitionPulseBatchV1 {
                        request_ids: vec![request_id],
                        beacon_session_id: beacon_session(13),
                        pulse_height: 20,
                        pulse_id: pulse_id(14),
                    }
                ),
                ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                    ParliamentBeginInvitationAcceptanceV1 {
                        election_attempt_id: election_id,
                    }
                ),
            ]
        );
        // The same pulse is still consumed however late the driver observes it.
        let late = state.plan_driver_v1(&world, &network_id(), &governance, 9_000, 9_003);
        assert_eq!(late.due, plan.due);

        // No pulse at the frozen slot: nothing is due and nothing is scheduled, at the slot,
        // just past it and arbitrarily far past it. A live electorate does not turn the wait
        // into a retry generation either.
        let electorate = FixedPlanWorld {
            candidates: Some(candidates(40, 4)),
            ..FixedPlanWorld::default()
        };
        // Pulses of another height or of another beacon session never substitute the draw.
        let substituted = FixedPlanWorld {
            pulses: [
                (
                    (beacon_session(13), 23),
                    (pulse_id(15), *pulse_id(15).as_bytes()),
                ),
                (
                    (beacon_session(99), 20),
                    (pulse_id(16), *pulse_id(16).as_bytes()),
                ),
            ]
            .into(),
            candidates: Some(candidates(40, 4)),
            ..FixedPlanWorld::default()
        };
        for missing_world in [&FixedPlanWorld::default(), &electorate, &substituted] {
            for (committed_height, execution_height) in [
                (20, 21),
                (20, 23),
                (23, 24),
                (1_000_000, 1_000_001),
                (u64::MAX - 1, u64::MAX),
            ] {
                let missing = state.plan_driver_v1(
                    missing_world,
                    &network_id(),
                    &governance,
                    committed_height,
                    execution_height,
                );
                assert_eq!(
                    missing,
                    ParliamentDriverPlanV1::default(),
                    "an election awaiting its pulse yields no transition at height \
                     {committed_height}"
                );
            }
        }
        assert_eq!(
            state
                .election(&election_id)
                .expect("pending election")
                .attempt
                .request
                .pulse_height,
            20
        );
    }

    #[test]
    fn planner_deliberates_to_vote_and_registers_the_ballot_at_the_execution_height() {
        let BodyFixture { state, body_id, .. } = sealed_policy_body(3);
        let world = FixedPlanWorld {
            key_session: Some(tle_key_session(5)),
            ..FixedPlanWorld::default()
        };
        let plan = state.plan_driver_v1(&world, &network_id(), &plan_governance(), 19, 22);
        let phases: Vec<_> = plan
            .due
            .iter()
            .map(|transition| match transition {
                ParliamentLifecycleTransitionV1::AdvanceBodyPhase(advance) => {
                    assert_eq!(advance.body_instance_id, body_id);
                    advance.target
                }
                other => panic!("unexpected transition {other:?}"),
            })
            .collect();
        assert_eq!(
            phases,
            vec![
                DeliberationPhaseV1::Orientation,
                DeliberationPhaseV1::Evidence,
                DeliberationPhaseV1::Questions,
                DeliberationPhaseV1::Responses,
                DeliberationPhaseV1::Deliberation,
                DeliberationPhaseV1::Reflection,
                DeliberationPhaseV1::Vote,
            ]
        );
        let [exact] = plan.exact.as_slice() else {
            panic!("one ballot registration: {:?}", plan.exact);
        };
        assert_eq!(exact.height, 22);
        let ParliamentLifecycleTransitionV1::RegisterBallotAttempt(register) = &exact.transition
        else {
            panic!("a ballot registration: {exact:?}");
        };
        let release_height = timed_ballot_schedule(22, timed_ovn_policy())
            .expect("schedule")
            .3;
        let logical = BeaconSessionId::for_network_v1(&network_id());
        assert_eq!(register.sequence, 0);
        assert_eq!(
            register.ballot_attempt_id,
            BallotAttemptId::derive_v1(body_id, 0)
        );
        assert_eq!(register.release_height, release_height);
        assert_eq!(register.release_beacon_session_id, logical);
        assert_eq!(
            register.tle_session_id,
            TleSessionId::derive_v1(
                register.ballot_attempt_id,
                tle_key_session(5),
                logical,
                release_height
            )
        );
        // Without a selectable TLE key session no ballot can be registered.
        let keyless = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            19,
            22,
        );
        assert!(keyless.exact.is_empty());
    }

    #[test]
    fn planner_times_ballot_checkpoints_and_fails_missed_ones() {
        let state = active_timed_ovn_reservation_attempt_fixture_v1(2, 5, 30);
        let (&body_id, &ballot_id) = state.active_ballots.iter().next().expect("active ballot");
        let close = state.ballots[&ballot_id].registration_close_height;
        let plan = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            29,
            32,
        );
        assert!(plan.due.is_empty(), "{plan:?}");
        assert_eq!(
            plan.exact,
            vec![ParliamentExactTransitionV1 {
                height: close,
                transition: ParliamentLifecycleTransitionV1::CloseBallotRegistration(
                    ParliamentCloseBallotRegistrationV1 {
                        ballot_attempt_id: ballot_id,
                    }
                ),
            }]
        );
        let missed = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            close,
            close + 3,
        );
        assert_eq!(
            missed.due,
            vec![ParliamentLifecycleTransitionV1::FailBallotNoResult(
                ParliamentFailBallotNoResultV1 {
                    ballot_attempt_id: ballot_id,
                }
            )]
        );
        assert!(missed.exact.is_empty());
        assert_ne!(body_id, BodyInstanceId::new([0; 32]));
    }

    #[test]
    fn committed_plan_targets_the_next_native_candidate_without_skipping_its_checkpoint() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

        let governance = plan_governance();
        let mut config = TestChainConfig::new(crate::state::World::new(), 1_000);
        config.governance = Some(governance.clone());
        let mut prepared = CertifiedTestChain::prepare(config).expect("original native genesis");
        let network_id = *prepared.state.network_id_ref();
        let roster = prepared
            .validator_keys
            .iter()
            .map(|key| iroha_model_base::peer::PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let threshold = ThresholdBlsSession::<TleReleasePurpose>::new(
            *network_id.as_bytes(),
            root(5),
            crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
            4,
            2,
        )
        .unwrap();
        let parameters = AdaptiveThresholdBlsParameters::derive(&threshold).unwrap();
        let mut rng = StdRng::from_seed([0xA5; 32]);
        let dealers = (1..=3)
            .map(|index| {
                DasRenDealerSecret::generate_with_rng(&parameters, index, &mut rng)
                    .unwrap()
                    .1
            })
            .collect::<Vec<_>>();
        let key = ValidatedTleKeySessionV1::from_qualified_dealers(
            threshold,
            &dealers,
            &[1, 2, 3],
            root(6),
        )
        .unwrap();
        let key_id = key.public_state().key_session_id;
        // The validated body enters Vote at height 22. Seed the complete matching
        // registration/key owners before original genesis, then execute every height.
        let BodyFixture {
            state: mut attempt,
            body_id,
            ..
        } = sealed_policy_body(3);
        advance_to_vote(&mut attempt, body_id);
        let attempt_id = attempt.attempt.id;
        let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
        let release = timed_ballot_schedule(23, timed_ovn_policy()).unwrap().3;
        let beacon = beacon_session(6);
        attempt
            .register_ballot_attempt(
                attempt_id,
                body_id,
                ballot_id,
                0,
                TleSessionId::derive_v1(ballot_id, key_id, beacon, release),
                key_id,
                beacon,
                23,
                timed_ovn_policy(),
                release,
            )
            .unwrap();
        let close = attempt.ballots[&ballot_id].registration_close_height;
        let session = TimedOvnSessionPublicV1 {
            network_id: *network_id.as_bytes(),
            proposal_content_id: *attempt.proposal_content_id().as_bytes(),
            governance_attempt_id: *attempt_id.as_bytes(),
            body_instance_id: *body_id.as_bytes(),
            ballot_attempt_id: *ballot_id.as_bytes(),
            parameter_hash: timed_ovn_parameter_hash_v1(),
            tle_key_session_id: key_id,
            tle_key_transcript_hash: key.public_state().transcript_hash,
            tle_master_public_key: *key.master_public_key().as_bytes(),
        };
        let lifecycle = TimedOvnLifecycleStateV1::open_registration(session, 23, release, &key)
            .expect("real TLE registration owns its empty corpus commitment");
        let mut key_lifecycle = TleKeySessionLifecycleV1::new(key_id, 1, u64::MAX, 1).unwrap();
        key_lifecycle.consume_fresh_ballot(23).unwrap();
        let state = std::sync::Arc::get_mut(&mut prepared.state).expect("unshared initial State");
        state.world.parliament_attempts.insert(attempt_id, attempt);
        state
            .world
            .tle_key_sessions
            .insert(key_id, key.public_state().clone());
        state.world.tle_key_session_rosters.insert(key_id, roster);
        state
            .world
            .tle_key_session_lifecycles
            .insert(key_id, key_lifecycle);
        state
            .world
            .tle_active_key_session
            .insert(crate::state::TLE_KEY_SESSION_SINGLETON_KEY, key_id);
        state.world.timed_ovn_evidence.insert(ballot_id, lifecycle);
        state
            .world
            .rebuild_governance_read_indexes_for_testing()
            .unwrap();
        let mut chain =
            CertifiedTestChain::from_prepared(prepared).expect("original native genesis");
        while chain.height() + 1 < close {
            chain.commit(Vec::new());
        }
        let (committed, candidate, plan) = plan_parliament_attempt_v1(
            &chain.state().view(),
            chain.state().network_id_ref(),
            &governance,
            attempt_id,
        )
        .expect("retained attempt at the original committed tip");
        assert_eq!(committed, chain.height());
        assert_eq!(candidate, committed + 1);
        assert_eq!(candidate, close);
        assert!(
            plan.due.is_empty(),
            "a reachable checkpoint must not fail early"
        );
        assert_eq!(
            plan.exact,
            vec![ParliamentExactTransitionV1 {
                height: close,
                transition: ParliamentLifecycleTransitionV1::CloseBallotRegistration(
                    ParliamentCloseBallotRegistrationV1 {
                        ballot_attempt_id: ballot_id,
                    },
                ),
            }]
        );
        chain.commit(Vec::new());
        assert_eq!(
            chain.committed(candidate).block().header().height().get(),
            close
        );
        let (_, next_candidate, expired) = plan_parliament_attempt_v1(
            &chain.state().view(),
            chain.state().network_id_ref(),
            &governance,
            attempt_id,
        )
        .unwrap();
        assert_eq!(next_candidate, close + 1);
        assert!(expired.exact.is_empty());
        assert_eq!(
            expired.due,
            vec![ParliamentLifecycleTransitionV1::FailBallotNoResult(
                ParliamentFailBallotNoResultV1 {
                    ballot_attempt_id: ballot_id,
                },
            )]
        );
        assert!(
            plan_parliament_attempt_v1(
                &chain.state().view(),
                chain.state().network_id_ref(),
                &governance,
                GovernanceAttemptId::new([0xfe; 32]),
            )
            .is_none()
        );
    }

    #[test]
    fn planner_retries_a_no_roster_election_with_the_exact_next_generation() {
        // An attempt without a manager (SCCP) has nobody else to submit the retry, so the plan
        // carries the exact next generation in the block of the failure it follows.
        let mut state = policy_only_state();
        let id = state.attempt.id;
        state
            .complete_qualification(id)
            .expect("enter Policy Jury stage");
        let logical = BeaconSessionId::for_network_v1(&network_id());
        let (request, snapshot) = sortition_request(
            id,
            0,
            ParliamentBody::PolicyJury,
            12,
            3,
            3,
            10,
            20,
            logical,
            None,
        );
        let election_id = request.body_election_attempt_id;
        let request_id = request.id;
        state
            .register_sortition_request(id, 0, request, snapshot)
            .expect("register policy sortition");
        // The election consumes the pulse of its exact slot and nobody accepts before the
        // one-block invitation window closes: the only way an election ends `NoRoster`.
        consume_sortition(&mut state, id, vec![request_id], logical, 20, pulse_id(14))
            .expect("consume the exact slot pulse");
        state
            .begin_invitation_acceptance(id, election_id, 20, 1)
            .expect("open the invitation window");
        let governance = Governance {
            policy_jury_size: 3,
            ..plan_governance()
        };
        let retry_snapshot = candidates(40, 4);
        let world = FixedPlanWorld {
            candidates: Some(retry_snapshot.clone()),
            ..FixedPlanWorld::default()
        };

        let plan = state.plan_driver_v1(&world, &network_id(), &governance, 20, 23);
        assert_eq!(
            plan.due,
            vec![ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(
                ParliamentFailBodyElectionNoRosterV1 {
                    election_attempt_id: election_id,
                }
            )]
        );
        let retry = sortition_request_intent(
            id,
            1,
            ParliamentBody::PolicyJury,
            retry_snapshot,
            3,
            23,
            // The first native pulse height at or after 23 plus the ten-block delay.
            35,
            logical,
        );
        assert_eq!(
            plan.exact,
            vec![ParliamentExactTransitionV1 {
                height: 23,
                transition: register_sortition(vec![ParliamentSortitionRequestRegistrationV1 {
                    sequence: 1,
                    request: retry,
                }]),
            }]
        );
        let replayed = replay_plan(&state, &plan, &world, &governance, 23);
        assert_eq!(replayed.attempt.status, GovernanceAttemptStatusV1::Active);
        assert_eq!(
            replayed
                .election(&retry.body_election_attempt_id)
                .expect("redrawn election")
                .attempt
                .status,
            BodyElectionAttemptStatusV1::AwaitingPulse
        );

        // Without the live electorate the generation cannot be derived.
        let blind = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &governance,
            20,
            23,
        );
        assert_eq!(blind.due, plan.due);
        assert!(blind.exact.is_empty());
    }

    #[test]
    fn planner_retries_hidden_capacity_evidence_in_the_next_block() {
        let mut state = policy_only_state();
        let id = state.attempt.id;
        state
            .complete_qualification(id)
            .expect("enter Policy Jury stage");
        let logical = BeaconSessionId::for_network_v1(&network_id());
        let single = candidates(12, 1);
        state
            .record_hidden_sortition_capacity_failure_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 {
                    sequence: 0,
                    request: sortition_request_intent(
                        id,
                        0,
                        ParliamentBody::PolicyJury,
                        single.clone(),
                        3,
                        10,
                        20,
                        logical,
                    ),
                }],
                single,
            )
            .expect("record sub-floor capacity evidence");
        let governance = Governance {
            policy_jury_size: 3,
            ..plan_governance()
        };
        let grown = candidates(40, 3);
        let world = FixedPlanWorld {
            candidates: Some(grown.clone()),
            ..FixedPlanWorld::default()
        };

        let same_block = state.plan_driver_v1(&world, &network_id(), &governance, 9, 10);
        assert!(
            same_block.exact.is_empty(),
            "capacity evidence is retried only in a later block"
        );
        let plan = state.plan_driver_v1(&world, &network_id(), &governance, 10, 11);
        assert!(plan.due.is_empty(), "{plan:?}");
        let retry = sortition_request_intent(
            id,
            1,
            ParliamentBody::PolicyJury,
            grown,
            3,
            11,
            // The evidence generation holds slot 20; height 21 is not a native pulse height.
            23,
            logical,
        );
        assert_eq!(
            plan.exact,
            vec![ParliamentExactTransitionV1 {
                height: 11,
                transition: register_sortition(vec![ParliamentSortitionRequestRegistrationV1 {
                    sequence: 1,
                    request: retry,
                }]),
            }]
        );
        let replayed = replay_plan(&state, &plan, &world, &governance, 11);
        assert_eq!(
            replayed
                .election(&retry.body_election_attempt_id)
                .expect("drawn retry")
                .attempt
                .status,
            BodyElectionAttemptStatusV1::AwaitingPulse
        );
    }

    #[test]
    fn planner_waits_for_the_hidden_floor_before_retrying_capacity_evidence() {
        // A retry that a hidden body's sub-floor electorate would only record as capacity
        // evidence again cannot draw; it would spend a sortition sequence and a redraw unit,
        // and a driver submitting it every block would exhaust the proposal while the
        // electorate grows. The plan waits; any submitter may still record the evidence.
        let mut state = policy_only_state();
        let id = state.attempt.id;
        state
            .complete_qualification(id)
            .expect("enter Policy Jury stage");
        let logical = BeaconSessionId::for_network_v1(&network_id());
        let single = candidates(12, 1);
        state
            .record_hidden_sortition_capacity_failure_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 {
                    sequence: 0,
                    request: sortition_request_intent(
                        id,
                        0,
                        ParliamentBody::PolicyJury,
                        single.clone(),
                        3,
                        10,
                        20,
                        logical,
                    ),
                }],
                single,
            )
            .expect("record sub-floor capacity evidence");
        let governance = Governance {
            policy_jury_size: 3,
            ..plan_governance()
        };
        let still_small = candidates(40, 2);
        let world = FixedPlanWorld {
            candidates: Some(still_small.clone()),
            ..FixedPlanWorld::default()
        };

        let plan = state.plan_driver_v1(&world, &network_id(), &governance, 10, 11);
        assert_eq!(plan, ParliamentDriverPlanV1::default());
        let mut manual = state.clone();
        manual
            .record_hidden_sortition_capacity_failure_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 {
                    sequence: 1,
                    request: sortition_request_intent(
                        id,
                        1,
                        ParliamentBody::PolicyJury,
                        still_small.clone(),
                        3,
                        11,
                        23,
                        logical,
                    ),
                }],
                still_small,
            )
            .expect("a submitter may still record the unchanged shortfall");
    }

    #[test]
    fn planner_retries_every_failed_body_as_one_generation() {
        let (mut state, failed) =
            rules_and_policy_invitations_open(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 - 1);
        for election_id in failed {
            respond_to_every_invitation(&mut state, election_id, false, 20);
        }
        let governance = Governance {
            rules_committee_size: 3,
            policy_jury_size: 3,
            ..plan_governance()
        };
        let snapshot = candidates(90, 12);
        let world = FixedPlanWorld {
            candidates: Some(snapshot.clone()),
            ..FixedPlanWorld::default()
        };

        let plan = state.plan_driver_v1(&world, &network_id(), &governance, 21, 22);
        let mut failures = plan.due.clone();
        failures.sort();
        let mut expected_failures = failed
            .map(|election_attempt_id| {
                ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(
                    ParliamentFailBodyElectionNoRosterV1 {
                        election_attempt_id,
                    },
                )
            })
            .to_vec();
        expected_failures.sort();
        assert_eq!(failures, expected_failures);
        let logical = BeaconSessionId::for_network_v1(&network_id());
        let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
        assert_eq!(
            plan.exact,
            vec![ParliamentExactTransitionV1 {
                height: 22,
                transition: register_sortition(sortition_generation(
                    &state, &bodies, 1, &snapshot, 22, logical,
                )),
            }]
        );
        let replayed = replay_plan(&state, &plan, &world, &governance, 22);
        assert_eq!(replayed.attempt.status, GovernanceAttemptStatusV1::Active);
        assert_eq!(
            replayed.randomness_redraws_used_v1(),
            Ok(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1)
        );
    }

    #[test]
    fn planner_terminalizes_a_later_stage_body_at_the_redraw_ceiling() {
        // The Rules Committee deliberates while the later-stage Policy Jury's roster comes
        // back empty with no redraw left. The plan rejects the attempt and every planned step
        // persists.
        let (mut state, [rules, policy]) =
            rules_and_policy_invitations_open(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1);
        let id = state.attempt.id;
        respond_to_every_invitation(&mut state, rules, true, 20);
        respond_to_every_invitation(&mut state, policy, false, 20);
        let rules_body = state
            .seal_body_roster(id, rules, 21)
            .expect("seal the Rules roster");
        state
            .advance_body_phase(id, rules_body, DeliberationPhaseV1::Orientation, 21, 10)
            .expect("the Rules Committee deliberates");
        let world = FixedPlanWorld {
            candidates: Some(candidates(90, 12)),
            ..FixedPlanWorld::default()
        };

        let plan = state.plan_driver_v1(&world, &network_id(), &plan_governance(), 21, 22);
        assert!(
            plan.due
                .contains(&ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(
                    ParliamentFailBodyElectionNoRosterV1 {
                        election_attempt_id: policy,
                    }
                )),
            "{plan:?}"
        );
        assert!(plan.exact.is_empty(), "no redraw is left: {plan:?}");
        let replayed = replay_plan(&state, &plan, &world, &plan_governance(), 22);
        assert_eq!(replayed.attempt.status, GovernanceAttemptStatusV1::Rejected);
    }

    #[test]
    fn planner_omits_transitions_that_persistence_would_reject() {
        // The due batch executes as one transaction, so one step whose successor fails the
        // persistence audit would abort every other step. The plan carries only steps whose
        // successor `validate` accepts.
        let mut state = policy_only_state();
        // An impossible persisted shape: the risk tier is locked without Policy sortition.
        state.risk_locked = true;
        assert!(state.validate().is_err());
        let plan = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            7,
            10,
        );
        assert_eq!(plan, ParliamentDriverPlanV1::default());
    }

    #[test]
    fn planner_is_empty_for_terminal_attempts() {
        let mut state = policy_only_state();
        state.attempt.status = GovernanceAttemptStatusV1::Rejected;
        let plan = state.plan_driver_v1(
            &FixedPlanWorld::default(),
            &network_id(),
            &plan_governance(),
            7,
            10,
        );
        assert_eq!(plan, ParliamentDriverPlanV1::default());
    }
}
