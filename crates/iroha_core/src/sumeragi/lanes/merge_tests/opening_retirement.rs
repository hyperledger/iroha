//! Proposal discovery owns no historical retry after its applied incarnation retires.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError as Attempt,
    sumeragi::{
        availability_schedule::AvailabilitySchedule,
        lanes::{registry::LaneStoreAuthorities as _, store::FileLaneBlockStore},
        test_chain::{Signers, TestLaneStoreAuthorities},
    },
};
use iroha_data_model::isi::SetParameter;
use iroha_sumeragi::types::ControlWitness;
use std::{fs, path::PathBuf};

struct ClosedLane {
    request: crate::sumeragi::lanes::ProposalReadScope,
    fixture: Fixture,
    record: SumeragiLaneRecord,
    hash: Hash32,
    transaction: SignedTransaction,
    path: PathBuf,
    frame: Vec<u8>,
    schedule: Arc<dyn AvailabilitySchedule>,
}

fn closed_lane() -> ClosedLane {
    let key = OnceLock::new();
    let mut fixture = Fixture::start_with_policy_and_configure(policy(), |config| {
        key.set(config.genesis_key.clone()).unwrap();
        config.genesis_instructions.push(
            iroha_data_model::isi::Grant::account_permission(
                iroha_executor_data_model::permission::parameter::CanSetParameters,
                AccountId::new(config.genesis_key.public_key().clone()),
            )
            .into(),
        );
    });
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let mut without = policy();
    without.fixed.clear();
    without.routes.clear();
    let close = fixture.chain.sign(
        key.get().unwrap(),
        [SetParameter::new(Parameter::Custom(without.into_custom_parameter())).into()],
        GENESIS_MS + 3,
    );
    assert_eq!(fixture.chain.commit(vec![close]), vec![true]);
    let record = fixture.record();
    assert_eq!(record.closing, Some(fixture.chain.height() + 1));
    let transaction = fixture.log(
        &lane_user(),
        "original closing-lane backlog",
        GENESIS_MS + 4,
    );
    // The actual closing record still admits the last pre-closing anchor.
    let hash = fixture.certify(1, fixture.chain.height(), vec![transaction.clone()]);
    let instance = fixture.stores.instance(LANE, &record.incarnation);
    let schedule = TestLaneStoreAuthorities::new(
        Arc::clone(fixture.chain.state()),
        Arc::new(BlsCrypto::new()),
    )
    .authority(LANE, &record.incarnation, instance)
    .unwrap()
    .unwrap()
    .schedule;
    let path = fixture
        .stores
        .root()
        .join(hex::encode(instance.0))
        .join("00000000000000000001.frame");
    let frame = fs::read(&path).unwrap();
    // This node has no LaneRunner or Ready lane driver. The fixture publisher ends
    // naturally before proposal discovery reopens the actual certified disk history.
    drop(fixture.publication.take().unwrap());
    fixture.stores.release(LANE, &record.incarnation);
    ClosedLane {
        request: crate::sumeragi::lanes::ProposalReadScope::new(),
        fixture,
        record,
        hash,
        transaction,
        path,
        frame,
        schedule,
    }
}

fn refuse_original_tip(closed: &mut ClosedLane) {
    let budget = closed.fixture.chain.state().ivm_execution_budget();
    let view = closed.fixture.chain.state().view();
    closed.request.admit(&budget).unwrap();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let occupied = budget
        .try_reserve_bytes(
            ceiling
                .checked_sub(baseline)
                .unwrap()
                .checked_sub(closed.frame.len())
                .unwrap(),
        )
        .unwrap();
    let error = propose(
        &view,
        &*closed.fixture.stores,
        closed.fixture.chain.height() + 1,
        &mut closed.request,
    )
    .expect_err("the real proposal tip must retain its original local read refusal");
    assert!(matches!(error, Attempt::Deferred(_)));
    assert_eq!(budget.reserved_bytes(), ceiling);
    closed
        .fixture
        .stores
        .release_retired(view.world().sumeragi_lanes());
    assert_eq!(
        budget.reserved_bytes(),
        ceiling,
        "closing backlog still belongs to the applied incarnation"
    );
    let locked = FileLaneBlockStore::begin_open(
        closed.fixture.stores.root(),
        &closed
            .fixture
            .stores
            .instance(LANE, &closed.record.incarnation),
        closed.fixture.crypto.clone(),
        budget.clone(),
        closed.schedule.clone(),
    );
    assert!(
        locked.is_err(),
        "the refused original recovery retains its acquired writer lock"
    );
    drop((locked, error, occupied, view));
    assert_eq!(budget.reserved_bytes(), baseline + closed.frame.len());
}

// Another certified global proposal can retire a lane while this node's own
// refused merge proposal is abandoned. Use real signed work and the production
// assembler/executor/QC path, without querying the abandoned local lane tip.
fn commit_independent_global_work(fixture: &mut Fixture) {
    let view = fixture.chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let config = view
        .world()
        .consensus_schedule()
        .ready(fixture.chain.height() + 1)
        .cloned()
        .unwrap();
    let cadence = Duration::from_millis(config.params.block_time_ms);
    let created = u64::try_from(parent.header().creation_time().as_millis()).unwrap();
    let transaction = fixture.log(&other_user(), "independent certified global work", created);
    let block_time = (parent.header().creation_time() + cadence)
        .max(transaction.creation_time() + Duration::from_millis(1));
    let (_, time_source) = iroha_primitives::time::TimeSource::new_mock(block_time);
    let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
        transaction,
        &fixture.chain.network_id(),
        Duration::from_secs(1),
        view.world().parameters().transaction(),
        view.world()
            .parameters()
            .crypto_policy()
            .expect("original committed admission policy"),
        &time_source,
    )
    .unwrap();
    let proposal = payload::assemble(
        fixture.chain.state(),
        Assembly {
            parent: &parent,
            view: 0,
            cadence,
            proposed_time: Duration::ZERO,
        },
        &[accepted],
    )
    .unwrap();
    drop((parent, view));
    let committed =
        fixture
            .chain
            .commit_proposal(proposal, Signers::Quorum, ControlWitness::empty());
    assert_eq!(committed.block().merged_entrypoint_count(), 0);
    assert!(
        committed
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
}
#[test]
fn closed_unhosted_lane_proposal_retries_original_opening_and_preserves_certified_backlog() {
    // Keep retired fixture allocations stable during exact capacity accounting.
    let _epoch = crossbeam_epoch::pin();
    let mut closed = closed_lane();
    refuse_original_tip(&mut closed);
    let merges = {
        let view = closed.fixture.chain.state().view();
        propose(
            &view,
            &*closed.fixture.stores,
            closed.fixture.chain.height() + 1,
            &mut closed.request,
        )
        .unwrap()
    };
    assert_eq!(merges.merges.len(), 1);
    assert_eq!(merges.merges[0].incarnation, closed.record.incarnation);
    assert_eq!(merges.merges[0].from, 1);
    assert_eq!(merges.merges[0].to, 1);
    assert_eq!(merges.merges[0].tip_hash, closed.hash.0);
    assert_eq!(fs::read(&closed.path).unwrap(), closed.frame);
    let proposal = closed
        .fixture
        .proposal(&merges.merges, merges.time_floor_ms);
    closed
        .fixture
        .chain
        .commit_proposal(proposal, Signers::Quorum, ControlWitness::empty());
    assert_eq!(closed.fixture.record().merged.height, 1);
    assert_eq!(closed.fixture.record().merged.block_hash, closed.hash.0);
    // Closing routing can discard the stale-route transaction; the exact certified
    // frame and frontier still merge, instead of falsely reporting no backlog.
    assert_eq!(fs::read(&closed.path).unwrap(), closed.frame);
    assert_eq!(closed.fixture.record().closing, closed.record.closing);
}

#[test]
fn abandoned_proposal_tip_releases_original_opening_after_certified_retirement() {
    // The final zero-balance assertion needs exclusive access to epoch collection.
    if crate::unit_test_support::run_in_isolated_harness(
        "sumeragi::lanes::merge::tests::opening_retirement::abandoned_proposal_tip_releases_original_opening_after_certified_retirement",
    ) {
        return;
    }
    // Keep retired fixture allocations stable during exact capacity accounting.
    let epoch = crossbeam_epoch::pin();
    let mut closed = closed_lane();
    refuse_original_tip(&mut closed);
    closed.request = crate::sumeragi::lanes::ProposalReadScope::new();
    closed.fixture.stores.release_cancelled_proposal_reads();
    let retirement = closed.record.retirement_height().unwrap();
    while closed.fixture.chain.height() < retirement {
        commit_independent_global_work(&mut closed.fixture);
        let view = closed.fixture.chain.state().view();
        if closed.fixture.chain.height() < retirement {
            assert!(view.world().sumeragi_lanes().lane(LANE).is_some());
            closed
                .fixture
                .stores
                .release_retired(view.world().sumeragi_lanes());
        } else {
            assert!(view.world().sumeragi_lanes().lane(LANE).is_none());
        }
    }
    let budget = closed.fixture.chain.state().ivm_execution_budget();
    let before_release = budget.reserved_bytes();
    {
        let view = closed.fixture.chain.state().view();
        closed
            .fixture
            .stores
            .release_retired(view.world().sumeragi_lanes());
    }
    let refunded = before_release.checked_sub(budget.reserved_bytes()) == Some(closed.frame.len());
    let probe = FileLaneBlockStore::begin_open(
        closed.fixture.stores.root(),
        &closed
            .fixture
            .stores
            .instance(LANE, &closed.record.incarnation),
        closed.fixture.crypto.clone(),
        budget.clone(),
        closed.schedule.clone(),
    );
    let released_lock = probe.is_ok();
    drop(probe);
    // Preserve the causal verdict before naturally completing a mutant's held
    // original recovery, so no assertion leaks its file owner or skips cleanup.
    if !released_lock {
        assert_eq!(
            closed
                .fixture
                .stores
                .tip(LANE, &closed.record.incarnation)
                .unwrap(),
            Some(1)
        );
        let original = closed
            .fixture
            .stores
            .block(LANE, &closed.record.incarnation, 1)
            .unwrap()
            .unwrap();
        assert_eq!(original.block_hash, closed.hash);
        drop(original);
        let view = closed.fixture.chain.state().view();
        closed
            .fixture
            .stores
            .release_retired(view.world().sumeragi_lanes());
    }
    let replay = FileLaneBlockStore::begin_open(
        closed.fixture.stores.root(),
        &closed
            .fixture
            .stores
            .instance(LANE, &closed.record.incarnation),
        closed.fixture.crypto.clone(),
        budget.clone(),
        closed.schedule.clone(),
    )
    .unwrap()
    .complete()
    .unwrap_or_else(|(_, error)| panic!("original retired history: {error}"));
    let (body, certificate) = replay.committed_body(1).unwrap().unwrap();
    assert_eq!(certificate.block_hash, closed.hash);
    assert_eq!(body.hash(&*closed.fixture.crypto), closed.hash);
    assert!(body.admitted_to(&budget));
    assert_eq!(fs::read(&closed.path).unwrap(), closed.frame);
    assert!(!closed.fixture.committed(&closed.transaction));
    drop((body, certificate, replay, closed, epoch));
    // State's existing EBR protocol runs only after every native result and owner
    // above has been consumed; a retained native cycle cannot be collected here.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        refunded && released_lock,
        "an abandoned proposal tip must release its original opening after certified retirement"
    );
}
