//! Actual pulse execution, refusal rollback and cold replay over an exact certified prefix.
//!
//! Demand is consensus-native: the NPoS pre-boundary height 9 of the shared fixture. The
//! undemanded source is the same chain one block earlier, whose next height 8 is ordinary.
//! Governance state creates no demand: pending Parliament slots neither require a pulse nor
//! block a block, and the native obligation is the same with or without them.

use super::*;
use crate::sumeragi::{
    block_store::Staging,
    certified_chain::CertifiedChain,
    driver::traits::Executor as _,
    executor::{ExecutorContext, StateExecutor},
    payload,
    test_chain::Signers,
};
use iroha_data_model::governance::types::{
    BallotAttemptStatusV1, BodyElectionAttemptId, BodyElectionAttemptStatusV1, GovernanceAttemptId,
    ParliamentBody,
};
use iroha_sumeragi::{api::ExecOutcome, availability::AvailableBody, preimage::payload_hash};

fn completed() -> (Fixture, ControlWitness) {
    complete(fixture())
}

/// Drive every seat of `fixture` at its applied parent 8 and build the finalized witness.
fn complete(mut fixture: Fixture) -> (Fixture, ControlWitness) {
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    let messages = fixture
        .producers
        .iter_mut()
        .map(|producer| ApplicationControl {
            context: fixture.context,
            bytes: producer
                .drive(&source, &fixture.context, applied)
                .unwrap()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    for (key, message) in fixture.keys.iter().zip(&messages) {
        fixture.producers[0]
            .accept(&source, applied, key, message)
            .unwrap();
    }
    let witness = fixture.producers[0]
        .build(&build_context(&fixture.context, 0))
        .unwrap();
    drop(source);
    (fixture, witness)
}

/// Another physical State over the fixture's exact certified prefix and seeded session.
///
/// With `demand` the prefix ends at the fixture's predecessor 8, so the next height is the
/// NPoS pre-boundary height 9 and the pulse is mandatory. Without it the prefix ends one block
/// earlier at 7: the next height 8 is an ordinary height of the same epoch, the same session is
/// active, and the only difference is that consensus demands no pulse there.
fn same_predecessor(fixture: &Fixture, demand: bool) -> CertifiedTestChain {
    let tip = if demand { 8 } else { 7 };
    let chain = npos_prefix(tip);
    assert_eq!(chain.height(), tip);
    assert_eq!(chain.instance(), fixture.chain.instance());
    for height in 2..=tip {
        assert_eq!(
            chain.committed(height).core_hash(),
            fixture.chain.committed(height).core_hash()
        );
        assert_eq!(
            chain.committed(height).result(),
            fixture.chain.committed(height).result()
        );
    }
    if demand {
        assert_eq!(chain.committed(8).core_hash(), fixture.context.parent_hash);
        assert_eq!(chain.committed(8).result(), fixture.context.parent_result);
    }
    let view = fixture.chain.state().view();
    let (id, mut record) = view
        .world()
        .global_beacon_key_sessions()
        .iter()
        .next()
        .map(|(id, record)| (*id, record.clone()))
        .unwrap();
    // The replay is another physical State: admit its own immutable graph from
    // that State's original pool while keeping the exact authenticated source.
    let binding = crate::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.session.network_id,
        session_id: id,
        roster_hash: record.session.roster_hash,
        transcript_hash: record.session.transcript_hash,
    };
    record.session = crate::beacon::validate_global_threshold_beacon_session_v1(
        record.session.record(),
        &binding,
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    assert!(
        record.session.adaptive_dkg.finalized_at_height <= tip && record.is_active_at(tip + 1),
        "the seeded session covers the next height with and without demand"
    );
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_key_sessions
            .insert(id, record);
        transaction
            .world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
    });
    {
        let view = chain.state().view();
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(tip + 1).unwrap().epoch;
        assert_eq!(current.mode, ConsensusMode::Npos);
        assert_eq!(
            super::super::super::required(
                SumeragiRootScope::Global,
                view.world(),
                current,
                tip + 1
            )
            .unwrap(),
            demand,
            "only the NPoS pre-boundary height demands the pulse"
        );
    }
    chain
}

/// A genuine threshold pulse of the fixture's session for the height after `chain`'s tip.
/// Nothing but consensus demand distinguishes it from the pulse the fixture transports at 9.
fn genuine_pulse_at_next_height(fixture: &Fixture, chain: &CertifiedTestChain) -> Pulse {
    let parent = chain.committed(chain.height());
    let height = chain.height() + 1;
    let view = chain.state().view();
    let id = view.world().active_global_beacon_key_session().unwrap();
    // Sign under the fixture's own admitted session graph: it is the custody the fixture's
    // signers were prepared for, and the same public session `chain` retains under `id`.
    let source = fixture.chain.state().view();
    assert_eq!(source.world().active_global_beacon_key_session(), Some(id));
    let session = source
        .world()
        .global_beacon_key_sessions()
        .get(&id)
        .unwrap()
        .session
        .clone();
    let epoch = schedule::core_epoch(
        &view
            .world()
            .consensus_schedule()
            .ready(height)
            .unwrap()
            .epoch,
    )
    .unwrap()
    .id;
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: chain.height(),
        block_hash: parent.block_hash(),
    };
    let context = pulse_context(&ApplicationControlContext {
        instance: chain.instance(),
        epoch,
        height,
        parent_hash: parent.core_hash(),
        parent_result: parent.result(),
    });
    let mut aggregator =
        GlobalThresholdBeaconPulseAggregatorV1::new(session.clone(), height, anchor, context)
            .unwrap();
    for producer in fixture.producers.iter().take(2) {
        let partial = producer
            .signer
            .as_ref()
            .unwrap()
            .sign_partial(&session, aggregator.payload())
            .unwrap();
        aggregator.accept_partial(partial).unwrap();
    }
    let pulse = aggregator.finalize().unwrap();
    crate::beacon::verify_finalized_global_threshold_beacon_pulse_v1(
        &session, &pulse, anchor, &context,
    )
    .unwrap();
    pulse
}

fn executor(chain: &CertifiedTestChain) -> StateExecutor {
    executor_in(chain, ConsensusMode::Npos)
}

/// A separate cold worker over `chain`'s published State in the chain's own consensus mode.
fn executor_in(chain: &CertifiedTestChain, consensus_mode: ConsensusMode) -> StateExecutor {
    StateExecutor::spawn(ExecutorContext {
        time_source: iroha_primitives::time::TimeSource::new_system(),
        state: Arc::clone(chain.state()),
        native_context_archive: Arc::new(
            crate::query::native_context_archive::NativeContextArchive::open(
                chain.state().kura(),
                chain.state().ivm_execution_budget(),
                chain.state().kura().native_context_archive_max_bytes(),
            )
            .expect("original-pool native context archive"),
        ),
        queue: None,
        staging: Staging::new(),
        events: tokio::sync::broadcast::channel(16).0,
        genesis_account: chain.genesis_account().clone(),
        consensus_mode,
        root_scope: chain.root_scope(),
        applied: (chain.height(), chain.committed(chain.height()).core_hash()),
        // Replay verifies each certified CommitQC; the worker admits the scheduled committee
        // from its authenticated proofs of possession, as the node's executor does.
        crypto: Some(Arc::new(crate::sumeragi::crypto::BlsCrypto::new())),
        applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(
            chain.height(),
            Some(chain.committed(chain.height()).block_hash()),
        )),
        lane_blocks: Arc::new(crate::sumeragi::lanes::merge::NoLanes),
    })
    .unwrap()
}

fn invalid(executor: &mut StateExecutor, chain: &CertifiedTestChain, candidate: &AvailableBody) {
    let hash = candidate
        .header()
        .hash(&crate::sumeragi::crypto::BlsCrypto::new());
    assert!(matches!(
        executor.execute(candidate, &hash, false),
        Some(ExecOutcome::Invalid)
    ));
    // The fixture chain's own tip never moves through this separate worker: a refusal leaves
    // the published State on exactly that predecessor.
    let view = chain.state().view();
    assert_eq!(u64::try_from(view.height()).unwrap(), chain.height());
    assert!(view.world().global_beacon_pulses().is_empty());
    assert!(view.world().global_beacon_pulse_slots().is_empty());
}

#[test]
fn transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result() {
    let (mut fixture, witness) = completed();
    let replay = same_predecessor(&fixture, true);
    assert_eq!(replay.height(), 8);
    let pulse = control::decode(&witness).unwrap().unwrap();
    fixture
        .chain
        .commit_with_control(Some(50_000), Vec::new(), Signers::Quorum, witness);
    let stored = fixture.chain.committed(9);
    assert!(stored.block().has_consensus_work());
    assert!(stored.block().global_beacon_pulse().is_none());
    assert_eq!(stored.commitment().beacon, Some(pulse));
    assert_eq!(
        control::decode(&stored.header().unwrap().control_witness).unwrap(),
        Some(pulse)
    );
    let view = fixture.chain.state().view();
    let certified = CertifiedChain::new(&view).unwrap().certified(9).unwrap();
    let original_qc = certified.commit_qc().unwrap().clone();
    drop(view);
    let proposal = stored
        .block()
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    let mut worker = executor(&replay);
    // A correctly decoded control witness is still obligatory at this exact source.
    let mut missing_header = stored.header().unwrap().clone();
    missing_header.control_witness = ControlWitness::empty();
    let missing = replay.author_payload(missing_header, payload::encode(&proposal).unwrap());
    invalid(&mut worker, &replay, &missing);
    replay.kura().store_block(stored.block().clone()).unwrap();
    let (block, qc) = replay
        .committed_body(9)
        .unwrap()
        .expect("restore the original signed certificate in the replay State pool");
    assert_eq!(qc, original_qc);
    worker
        .replay(&block, &qc)
        .expect("cold executor reproduces the original certified pulse writes");
    // Repeated completion is idempotent; no pulse or event is applied a second time.
    worker
        .replay(&block, &qc)
        .expect("completed publication is idempotent");
    let view = replay.state().view();
    assert_eq!(view.height(), 9);
    assert_eq!(
        view.world().global_beacon_pulses().get(&pulse.pulse_id),
        Some(&pulse)
    );
    assert_eq!(view.world().global_beacon_pulse_slots().len(), 1);
    assert_eq!(
        crate::sumeragi::certified_chain::committed_block(&view, 9)
            .unwrap()
            .result(),
        stored.result()
    );
}

#[test]
fn native_pulse_refusals_preserve_the_exact_predecessor_and_require_actual_work() {
    let (mut fixture, witness) = completed();
    let predecessor = same_predecessor(&fixture, true);
    let unrequested = same_predecessor(&fixture, false);
    assert_eq!((predecessor.height(), unrequested.height()), (8, 7));
    let pulse = control::decode(&witness).unwrap().unwrap();
    fixture
        .chain
        .commit_with_control(Some(50_000), Vec::new(), Signers::Quorum, witness);
    let stored = fixture.chain.committed(9);
    let proposal = stored
        .block()
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    let header = stored.header().unwrap().clone();
    let proposal_bytes = payload::encode(&proposal).unwrap();
    let mut worker = executor(&predecessor);
    for field in 0..15 {
        let mut wrong = pulse;
        match field {
            0 => wrong.signature[0] ^= 1,
            1 => wrong.session_id[0] ^= 1,
            2 => wrong.roster_hash[0] ^= 1,
            3 => wrong.transcript_hash[0] ^= 1,
            4 => wrong.height += 1,
            5 => wrong.round += 1,
            6 => {
                wrong.finalized_chain_anchor.block_hash =
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign parent"))
            }
            7 => wrong.seed[0] ^= 1,
            8 => wrong.pulse_id[0] ^= 1,
            9 => {
                wrong.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign genesis")),
                )
            }
            10 => wrong.context.instance[0] ^= 1,
            11 => wrong.context.epoch += 1,
            12 => wrong.context.epoch_context_id[0] ^= 1,
            13 => wrong.context.parent_consensus_hash[0] ^= 1,
            _ => wrong.context.parent_result[0] ^= 1,
        }
        let mut candidate_header = header.clone();
        candidate_header.control_witness = control::encode(Some(wrong)).unwrap();
        let candidate = predecessor.author_payload(candidate_header, proposal_bytes.clone());
        invalid(&mut worker, &predecessor, &candidate);
    }
    let mut duplicate = proposal.clone();
    duplicate.set_global_beacon_pulse(Some(pulse));
    let duplicate_bytes = payload::encode(&duplicate).unwrap();
    let mut candidate_header = header.clone();
    candidate_header.payload_len = u32::try_from(duplicate_bytes.len()).unwrap();
    candidate_header.payload_hash =
        payload_hash(&crate::sumeragi::crypto::BlsCrypto::new(), &duplicate_bytes);
    let candidate = predecessor.author_payload(candidate_header, duplicate_bytes);
    invalid(&mut worker, &predecessor, &candidate);
    let mut empty = proposal;
    empty.set_external_entrypoints(Vec::new());
    empty.set_execution_context(None);
    assert!(
        payload::encode(&empty).is_err(),
        "control cannot substitute transaction work"
    );
    // The fixture's own certified height 8 is ordinary work without control. Carrying a genuine
    // pulse of the active session there is refused only because consensus did not request it:
    // the identical body with its original empty witness executes on the same source.
    let ordinary = fixture.chain.committed(8);
    let ordinary_header = ordinary.header().unwrap().clone();
    assert!(ordinary_header.control_witness.is_empty());
    let ordinary_bytes = payload::encode(
        &ordinary
            .block()
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
    )
    .unwrap();
    let mut unrequested_header = ordinary_header.clone();
    unrequested_header.control_witness =
        control::encode(Some(genuine_pulse_at_next_height(&fixture, &unrequested))).unwrap();
    let unrequested_body = unrequested.author_payload(unrequested_header, ordinary_bytes.clone());
    invalid(&mut executor(&unrequested), &unrequested, &unrequested_body);
    let requested_nothing = unrequested.author_payload(ordinary_header, ordinary_bytes);
    let hash = requested_nothing
        .header()
        .hash(&crate::sumeragi::crypto::BlsCrypto::new());
    assert!(
        matches!(
            executor(&unrequested).execute(&requested_nothing, &hash, false),
            Some(ExecOutcome::Valid { .. })
        ),
        "without the unrequested witness the same ordinary body is valid"
    );
}

fn roster(chain: &CertifiedTestChain) -> Vec<iroha_model_base::peer::PeerId> {
    chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect()
}

fn logical_session(chain: &CertifiedTestChain) -> BeaconSessionId {
    BeaconSessionId::for_network_v1(&chain.network_id())
}

/// Admit one canonical Parliament attempt into `chain`'s World outside consensus.
fn admit(
    chain: &CertifiedTestChain,
    attempt: crate::governance::parliament::ParliamentAttemptStateV1,
) {
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .put_parliament_attempt(attempt)
            .expect("admit the pending governance attempt");
    });
}

/// The complete governance-local slot index of `chain`.
fn slot_index(
    chain: &CertifiedTestChain,
) -> Vec<((BeaconSessionId, u64), BTreeSet<GovernanceAttemptId>)> {
    chain
        .state()
        .view()
        .world()
        .parliament_required_beacon_pulse_slots()
        .iter()
        .map(|(slot, attempts)| (*slot, attempts.clone()))
        .collect()
}

/// Both elections of the pending generation still await exactly `(logical session, slot)`.
fn assert_sortition_awaits(chain: &CertifiedTestChain, attempt_id: GovernanceAttemptId, slot: u64) {
    let view = chain.state().view();
    let attempt = view
        .world()
        .parliament_attempts()
        .get(&attempt_id)
        .expect("the pending attempt is retained");
    for body in [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury] {
        let election = attempt
            .election(&BodyElectionAttemptId::derive_v1(attempt_id, body, 0))
            .expect("the pending election is retained")
            .attempt();
        assert_eq!(election.status, BodyElectionAttemptStatusV1::AwaitingPulse);
        assert_eq!(
            (
                election.request.beacon_session_id,
                election.request.pulse_height
            ),
            (logical_session(chain), slot),
            "the request stays on its original frozen slot"
        );
    }
}

/// No consensus pulse was stored on `chain`.
fn assert_no_pulse(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    assert!(view.world().global_beacon_pulses().iter().next().is_none());
    assert!(
        view.world()
            .global_beacon_pulse_slots()
            .iter()
            .next()
            .is_none()
    );
    assert!(
        view.world()
            .global_beacon_latest_pulse()
            .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
            .is_none()
    );
}

/// Consensus demands nothing at `chain`'s next height, and a validator that holds no beacon
/// custody at all opens no round, returns no error and builds the empty control witness.
fn assert_no_demand_at_next_height(chain: &CertifiedTestChain) {
    let height = chain.height() + 1;
    let view = chain.state().view();
    {
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(height).unwrap().epoch;
        assert_eq!(current.mode, ConsensusMode::Permissioned);
        assert!(
            !super::super::super::required(
                SumeragiRootScope::Global,
                view.world(),
                current,
                height
            )
            .unwrap(),
            "a pending governance slot at {height} is not consensus demand"
        );
    }
    let context = context(chain);
    let applied = (chain.height(), context.parent_hash);
    let key: [u8; 48] = chain.validators()[0]
        .0
        .public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap();
    let mut producer = NativeBeaconProducer::new(chain.instance(), Some(key), None);
    assert!(
        producer
            .drive(&view, &context, applied)
            .expect("a governance slot is no source failure")
            .is_none()
    );
    assert!(producer.active.is_none(), "no signing round is opened");
    assert!(
        producer
            .build(&build_context(&context, 0))
            .expect("no demand builds immediately")
            .is_empty()
    );
}

/// Commit one block of ordinary signed work with the empty control witness and return it.
fn commit_unrelated_work(
    chain: &mut CertifiedTestChain,
) -> crate::sumeragi::certified_chain::CommittedBlock {
    // The harness signs one ordinary `Log` transaction of its clock account: work that reads
    // and writes no governance state. `commit` panics unless the block executes `Valid`.
    chain.commit(Vec::new());
    let stored = chain.committed(chain.height());
    assert!(stored.block().has_consensus_work());
    assert_eq!(stored.block().external_transactions().len(), 1);
    assert!(
        stored
            .block()
            .network_output_at(0)
            .is_some_and(|(_, output)| output.result.is_ok()),
        "the unrelated transaction executed successfully"
    );
    assert!(stored.header().unwrap().control_witness.is_empty());
    assert_eq!(stored.commitment().beacon, None);
    stored
}

/// Spec §13.4 HC224. Governance state creates no consensus pulse obligation.
///
/// A Permissioned Global chain has no consensus-native pulse. Its World holds a Parliament
/// sortition generation awaiting the pulse of slot 9 and, at the end, a timed-OVN ballot whose
/// frozen release height is another ordinary height. Neither slot is consensus demand: no
/// producer signs or fails, every block of unrelated work with the empty control witness
/// executes and commits far past the sortition slot, a block that carries a pulse there is
/// refused as not requested, no pulse row ever appears, the request stays pending on exactly
/// its original slot, and a cold replay of the certified suffix reproduces the same results.
#[test]
fn pending_parliament_slots_create_no_native_control_demand_and_never_block_unrelated_work() {
    const SLOT: u64 = 9;
    const BALLOT_REGISTERED_AT: u64 = 30;
    // `custody` additionally holds an active beacon session and its signers; `chain` and its
    // cold `replay` twin hold no beacon session at all.
    let mut custody = seeded(prefix());
    let mut chain = prefix();
    let mut replay = prefix();
    let (attempt_id, _, attempt) = crate::beacon::tests::pending_batched_sortition_attempt(
        &chain.network_id(),
        &roster(&chain),
        SLOT,
    );
    for other in [&custody.chain, &replay] {
        assert_eq!(other.instance(), chain.instance());
        assert_eq!(
            other.committed(8).core_hash(),
            chain.committed(8).core_hash()
        );
        assert_eq!(other.committed(8).result(), chain.committed(8).result());
    }
    for target in [&custody.chain, &chain, &replay] {
        admit(target, attempt.clone());
        assert_eq!(
            slot_index(target),
            vec![(
                (logical_session(target), SLOT),
                BTreeSet::from([attempt_id])
            )],
            "admission derives the governance-local index row"
        );
        assert_sortition_awaits(target, attempt_id, SLOT);
    }
    assert!(
        chain
            .state()
            .view()
            .world()
            .active_global_beacon_key_session()
            .is_none()
            && chain
                .state()
                .view()
                .world()
                .global_beacon_key_sessions()
                .iter()
                .next()
                .is_none(),
        "the committing chain has no beacon session"
    );

    // Slot 9 is the next height. Without any session the producer has nothing to do and
    // reports no failure; with a session and real custody no seat signs.
    assert_no_demand_at_next_height(&chain);
    {
        let view = custody.chain.state().view();
        let applied = (8, custody.context.parent_hash);
        for producer in &mut custody.producers {
            assert!(
                producer
                    .drive(&view, &custody.context, applied)
                    .unwrap()
                    .is_none()
            );
            assert!(producer.active.is_none());
            assert!(
                producer
                    .build(&build_context(&custody.context, 0))
                    .unwrap()
                    .is_empty()
            );
        }
    }
    assert!(
        custody
            .counts
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0),
        "no seat signs a partial for a governance slot"
    );

    // Block 9 carries unrelated work and the empty witness, and commits.
    let index = slot_index(&chain);
    let ninth = commit_unrelated_work(&mut chain);
    assert_eq!(chain.height(), SLOT);
    assert_no_pulse(&chain);
    assert_sortition_awaits(&chain, attempt_id, SLOT);
    assert_eq!(slot_index(&chain), index);

    // The two-sided rule is preserved at the slot. The same certified body is valid on the
    // custody chain with its empty witness and refused there once it carries a genuine pulse of
    // the active session for height 9: consensus did not request one.
    let header = ninth.header().unwrap().clone();
    let bytes = payload::encode(
        &ninth
            .block()
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
    )
    .unwrap();
    let mut with_pulse = header.clone();
    with_pulse.control_witness =
        control::encode(Some(genuine_pulse_at_next_height(&custody, &custody.chain))).unwrap();
    let unrequested = custody.chain.author_payload(with_pulse, bytes.clone());
    invalid(
        &mut executor_in(&custody.chain, ConsensusMode::Permissioned),
        &custody.chain,
        &unrequested,
    );
    let requested_nothing = custody.chain.author_payload(header, bytes);
    let hash = requested_nothing
        .header()
        .hash(&crate::sumeragi::crypto::BlsCrypto::new());
    assert!(
        matches!(
            executor_in(&custody.chain, ConsensusMode::Permissioned).execute(
                &requested_nothing,
                &hash,
                false
            ),
            Some(ExecOutcome::Valid { .. })
        ),
        "without the unrequested witness the same body is valid at the governance slot"
    );
    assert_sortition_awaits(&custody.chain, attempt_id, SLOT);

    // A timed-OVN ballot registered at height 30 freezes a later release height on the same
    // logical beacon. That height is ordinary too.
    let ballot_attempt =
        crate::governance::parliament::tests::active_timed_ovn_attempt_awaiting_release_fixture_v1(
            2,
            5,
            BALLOT_REGISTERED_AT,
            logical_session(&chain),
        );
    let ballot_attempt_id = ballot_attempt.attempt().id;
    assert_ne!(ballot_attempt_id, attempt_id);
    let release = {
        let slots = ballot_attempt.required_beacon_pulse_slots_v1();
        assert_eq!(slots.len(), 1, "one frozen release slot: {slots:?}");
        let (session, height) = slots.into_iter().next().unwrap();
        assert_eq!(session, logical_session(&chain));
        height
    };
    assert!(release > BALLOT_REGISTERED_AT + 1);

    // Consecutive blocks far past the unserved slot, up to the parent of the release height.
    while chain.height() + 1 < release {
        assert_no_demand_at_next_height(&chain);
        commit_unrelated_work(&mut chain);
        assert_no_pulse(&chain);
        assert_sortition_awaits(&chain, attempt_id, SLOT);
        assert_eq!(slot_index(&chain), index);
    }
    assert!(chain.height() - SLOT >= 12 && chain.height() >= BALLOT_REGISTERED_AT);

    // Cold replay of the certified suffix onto the twin holding the same pending request:
    // the original certificates verify, so every result is reproduced.
    replay
        .replay_from(&chain)
        .expect("cold replay of the suffix over the same pending request");
    assert_eq!(replay.height(), chain.height());
    for height in SLOT..=chain.height() {
        assert_eq!(
            replay.committed(height).core_hash(),
            chain.committed(height).core_hash()
        );
        assert_eq!(
            replay.committed(height).result(),
            chain.committed(height).result()
        );
    }
    assert_no_pulse(&replay);
    assert_sortition_awaits(&replay, attempt_id, SLOT);
    assert_eq!(slot_index(&replay), index);

    // The ballot's release slot is the next height. Its index row exists, and it is no more
    // consensus demand than the sortition slot: nothing is required, and a validator without
    // any beacon session opens no round and reports no failure.
    // Executing a block over a committed timed-OVN ballot needs that ballot's complete TLE
    // evidence, which is fixture scaffolding of a path that is being retired, so the release
    // slot is checked at the demand and producer boundary on this real chain state.
    // TODO: drop the ballot half with the timed-OVN ballot itself
    // (specs/parliament_private_ballot_design.md 12.2 step 4).
    admit(&chain, ballot_attempt);
    assert_eq!(chain.height() + 1, release);
    assert_eq!(
        slot_index(&chain),
        vec![
            (
                (logical_session(&chain), SLOT),
                BTreeSet::from([attempt_id])
            ),
            (
                (logical_session(&chain), release),
                BTreeSet::from([ballot_attempt_id])
            ),
        ]
    );
    assert_no_demand_at_next_height(&chain);
    assert_no_pulse(&chain);
    assert_sortition_awaits(&chain, attempt_id, SLOT);
    let view = chain.state().view();
    let stored = view
        .world()
        .parliament_attempts()
        .get(&ballot_attempt_id)
        .expect("the ballot attempt is retained");
    let mut ballots = stored.ballot_attempts();
    let (_, ballot) = ballots.next().expect("the registered ballot");
    assert!(ballots.next().is_none());
    assert_eq!(ballot.attempt().status, BallotAttemptStatusV1::Registration);
    assert!(stored.requires_beacon_pulse_at(logical_session(&chain), release));
}

/// The consensus-native obligation is the same with or without Parliament state.
///
/// On the ten-block NPoS fixture a sortition requested at height 3 with a three-block delay
/// freezes the first native pulse height at or after 6, which is 9. The ordinary heights
/// before it, including 6, commit with the empty control witness. At 9 the native pulse is
/// mandatory exactly as on the chain without any governance row: a block without the witness
/// is invalid and the block with it commits. The stored pulse is then the one the waiting
/// election can consume; storing it does not move the election.
#[test]
fn npos_boundary_pulse_stays_mandatory_with_or_without_pending_parliament_slots() {
    fn mandatory_at_nine(fixture: Fixture) -> (Fixture, Pulse) {
        let (mut fixture, witness) = complete(fixture);
        let pulse = control::decode(&witness).unwrap().unwrap();
        let proposal = fixture.chain.proposal(Some(50_000), Vec::new());
        let refusal = match fixture
            .chain
            .begin_proposal(proposal, ControlWitness::empty())
        {
            Ok(_) => panic!("height 9 without the native pulse witness must not execute"),
            Err(refusal) => refusal,
        };
        assert!(refusal.contains("Invalid"), "{refusal}");
        assert_eq!(fixture.chain.height(), 8);
        fixture
            .chain
            .commit_with_control(Some(50_000), Vec::new(), Signers::Quorum, witness);
        let stored = fixture.chain.committed(9);
        assert_eq!(stored.commitment().beacon, Some(pulse));
        {
            let view = fixture.chain.state().view();
            assert_eq!(
                view.world()
                    .global_beacon_pulse_slots()
                    .get(&(logical_session(&fixture.chain), 9)),
                Some(&pulse.pulse_id)
            );
            assert_eq!(view.world().global_beacon_pulse_slots().len(), 1);
        }
        (fixture, pulse)
    }

    // Parliament state absent.
    let (plain, _) = mandatory_at_nine(fixture());
    assert!(slot_index(&plain.chain).is_empty());

    // Parliament state present from height 4.
    let mut chain = npos_prefix(4);
    let (attempt_id, _, attempt, slot) =
        crate::beacon::tests::pending_batched_sortition_attempt_with_schedule(
            &chain.network_id(),
            &roster(&chain),
            3,
            3,
            NPOS_EPOCH_LENGTH_BLOCKS,
        );
    assert_eq!(slot, 9, "the first native pulse height at or after 3 + 3");
    admit(&chain, attempt);
    let index = slot_index(&chain);
    assert_eq!(
        index,
        vec![((logical_session(&chain), 9), BTreeSet::from([attempt_id]))]
    );
    while chain.height() < 8 {
        let height = chain.height() + 1;
        {
            let view = chain.state().view();
            let retained = view.world().consensus_schedule();
            let current = &retained.ready(height).unwrap().epoch;
            assert_eq!(current.mode, ConsensusMode::Npos);
            assert!(
                !super::super::super::required(
                    SumeragiRootScope::Global,
                    view.world(),
                    current,
                    height
                )
                .unwrap(),
                "height {height} before the native pulse height demands nothing"
            );
        }
        commit_unrelated_work(&mut chain);
        assert_no_pulse(&chain);
        assert_sortition_awaits(&chain, attempt_id, 9);
        assert_eq!(slot_index(&chain), index);
    }
    let (present, pulse) = mandatory_at_nine(seeded(chain));
    assert_sortition_awaits(&present.chain, attempt_id, 9);
    assert_eq!(slot_index(&present.chain), index);
    // The governance-local wait is now served by exactly that consensus-native pulse.
    use crate::governance::parliament::ParliamentPlanWorldV1 as _;
    let view = present.chain.state().view();
    let network_id = present.chain.network_id();
    assert_eq!(
        crate::governance::parliament::WorldPlanInputsV1 {
            world: view.world(),
            network_id: &network_id,
        }
        .verified_pulse(logical_session(&present.chain), 9),
        Some((
            iroha_data_model::governance::types::BeaconPulseId::new(pulse.pulse_id),
            crate::beacon::global_threshold_beacon_governance_seed_v1(&pulse, 9),
        ))
    );
}
