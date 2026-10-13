//! Retained lane encoding keeps the actual Queue admission through local clock waits.

use super::{tests::*, *};
use crate::{
    queue::Queue,
    state::{World, WorldReadOnly},
    sumeragi::{
        lanes::global::QueueLaneTransactions,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    isi::{InstructionBox, Log, Register},
    parameter::{Parameter, system::SumeragiParameters},
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
    },
};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::time::{MockTimeHandle, TimeSource};
use std::sync::atomic::AtomicU64;

type RetainedLane = LaneExecutor<Global, Accept, QueueLaneTransactions>;

struct Fixture {
    chain: CertifiedTestChain,
    queue: Arc<Queue>,
    accepted: AcceptedTransaction<'static>,
    source: Arc<QueueLaneTransactions>,
    queue_clock: MockTimeHandle,
    lane_clock: MockTimeHandle,
    lane: RetainedLane,
}

impl Fixture {
    fn new() -> Self {
        let key = KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519);
        let account = AccountId::new(key.public_key().clone());
        let lane_id = LaneId::new(16);
        let mut committee = (0x61..=0x64)
            .map(|seed| {
                let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
                SumeragiLaneMember {
                    peer: PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                }
            })
            .collect::<Vec<_>>();
        committee.sort();
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 16,
            max_merge_blocks: 8,
            stall_window: 1000,
            lane_params: SumeragiParameters::default(),
            fixed: vec![SumeragiFixedLane {
                lane: lane_id,
                dataspace: DataSpaceId::UNIVERSAL,
                committee,
            }],
            routes: vec![SumeragiLaneRoute {
                lane: lane_id,
                account: Some(account.to_string()),
                instruction: None,
            }],
            autoscale: None,
        };
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config
            .genesis_instructions
            .push(Register::account(Account::new(account)).into());
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.into_custom_parameter()));
        let mut chain = CertifiedTestChain::start(config).unwrap();
        chain.commit_at(2_000, Vec::new());
        chain.commit_at(3_000, Vec::new());
        let (lane_clock, lane_time) = TimeSource::new_mock(Duration::from_millis(4_999));
        // Queue residence and proposer pacing observe the same injected local clock.
        let queue_clock = lane_clock.clone();
        let queue_time = lane_time.clone();
        let mut configuration = iroha_config::parameters::actual::Queue::default();
        configuration.transaction_time_to_live = Duration::from_secs(3);
        let queue = Arc::new(Queue::test(configuration, &queue_time));
        let signed = chain.sign(
            &key,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "lane original admission".into(),
            ))],
            3_000,
        );
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed,
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &queue_time,
        )
        .unwrap();
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        let source = Arc::new(QueueLaneTransactions::new(
            lane_id,
            queue.clone(),
            chain.state().clone(),
            lane_time.clone(),
        ));
        let anchors = Arc::new(Global {
            applied: AtomicU64::new(5),
        });
        let lane = executor_with_clock(&anchors, Some(source.clone()), lane_time);
        Self {
            chain,
            queue,
            accepted,
            source,
            queue_clock,
            lane_clock,
            lane,
        }
    }

    fn wait_for_clock(&mut self) {
        assert!(
            matches!(self.lane.build(1, 0, 1 << 20, 1_000), Err(PublicationError::Retryable(reason)) if reason == "ClockAhead")
        );
        assert!(self.lane.payload_build.is_some());
        assert_eq!(self.queue.queued_len(), 1);
    }

    fn unrelated(&self, created_ms: u64) -> AcceptedTransaction<'static> {
        AcceptedTransaction::accept_with_time_source(
            self.chain.tick(created_ms),
            &self.chain.network_id(),
            Duration::from_secs(1),
            self.chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &self.queue_clock.source(),
        )
        .unwrap()
    }
}

#[test]
fn lane_original_queue_lease_survives_unrelated_admissions_without_recapture() {
    let mut fixture = Fixture::new();
    fixture.wait_for_clock();
    fixture.lane_clock.set(Duration::from_millis(5_000));
    let original = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    let funded = fixture.lane.budget.reserved_bytes();
    for created in 3_001..=3_016 {
        let unrelated = fixture.unrelated(created);
        let hash = unrelated.hash_as_entrypoint();
        fixture
            .queue
            .push(unrelated, fixture.chain.state().view())
            .unwrap();
        let retained = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().expect(
            "unrelated Queue admissions must not retire the original completed lane payload",
        );
        assert_eq!(
            retained.as_slice().as_ptr(),
            original.as_slice().as_ptr(),
            "unrelated Queue admissions must not replace the original completed lane payload"
        );
        assert_eq!(retained.as_slice(), original.as_slice());
        assert_eq!(fixture.lane.budget.reserved_bytes(), funded);
        assert_eq!(fixture.queue.remove_committed_hashes([hash], None), 1);
        let retained = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
        assert_eq!(retained.as_slice().as_ptr(), original.as_slice().as_ptr());
    }
    fixture.queue.clear_all();
    fixture
        .queue
        .push(fixture.accepted.clone(), fixture.chain.state().view())
        .unwrap();
    let replacement = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    assert_eq!(replacement.as_slice(), original.as_slice());
    assert_ne!(
        replacement.as_slice().as_ptr(),
        original.as_slice().as_ptr()
    );
}

#[test]
fn lane_original_queue_lease_survives_unrelated_admission_during_actual_encoding() {
    let mut fixture = Fixture::new();
    fixture.wait_for_clock();
    fixture.lane_clock.set(Duration::from_millis(5_000));
    let unrelated = fixture.unrelated(3_001);
    let queue = fixture.queue.clone();
    let state = fixture.chain.state().clone();
    let result = fixture
        .lane
        .finish_payload_with_encoder(|batch, mut writer| {
            norito::codec::encode_adaptive_into(batch, &mut writer)?;
            queue.push(unrelated, state.view()).unwrap();
            Ok(())
        });
    assert!(
        result.is_ok(),
        "unrelated Queue admissions during encoding must preserve the original lane payload"
    );
    let original = result.unwrap().unwrap();
    assert_eq!(fixture.queue.queued_len(), 2);
    let retained = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    assert_eq!(retained.as_slice().as_ptr(), original.as_slice().as_ptr());
}

#[test]
fn lane_original_queue_lease_keeps_exact_capacity_refusal_until_original_pool_release() {
    let mut fixture = Fixture::new();
    let budget = fixture.lane.budget.clone();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let expected = budget
        .try_reserve(Queue::pending_payload_lease_layout_for_test(1))
        .unwrap_err();
    let Err(PublicationError::Deferred(
        crate::sumeragi::driver::traits::PublicationDeferral::Execution(original),
    )) = fixture.lane.build(1, 0, 1 << 20, 1_000)
    else {
        panic!("lane Queue lease funding must preserve its original typed allocation refusal");
    };
    assert_eq!(original.allocation_refusal(), Some(&expected));
    assert!(fixture.lane.payload_build.is_none());
    assert_eq!(fixture.queue.queued_len(), 1);
    drop(occupied);
    fixture.wait_for_clock();
    fixture.lane_clock.set(Duration::from_millis(5_000));
    assert!(fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().is_some());
}

#[test]
fn lane_original_queue_lease_retires_expiry_and_withdrawal_during_clock_wait() {
    for expire in [false, true] {
        let mut fixture = Fixture::new();
        fixture.wait_for_clock();
        let before = fixture.lane.budget.reserved_bytes();
        fixture.lane_clock.set(Duration::from_millis(5_000));
        if expire {
            fixture.queue_clock.set(Duration::from_millis(6_001));
        } else {
            fixture.queue.clear_all();
        }
        assert!(
            matches!(fixture.lane.finish_payload(), Err(PublicationError::Retryable(reason)) if reason == "lane Queue admission retired"),
            "lane clock retry must retire expired or withdrawn original Queue admission"
        );
        assert!(fixture.lane.payload_build.is_none());
        assert!(
            fixture.lane.budget.reserved_bytes() < before,
            "retired lane lease and encoding release their original backing"
        );
        fixture.queue.cull_expired_entries_if_due();
        assert_eq!(fixture.queue.queued_len(), 0);
        fixture.queue_clock.set(Duration::from_millis(5_000));
        assert!(fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().is_none());
        // Only a fresh real admission can grant a replacement lease after retirement.
        fixture
            .queue
            .push(fixture.accepted.clone(), fixture.chain.state().view())
            .unwrap();
        assert!(fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().is_some());
    }
}

#[test]
fn lane_original_queue_lease_rechecks_withdrawal_after_actual_encoding() {
    let mut fixture = Fixture::new();
    fixture.wait_for_clock();
    fixture.lane_clock.set(Duration::from_millis(5_000));
    let queue = fixture.queue.clone();
    let result = fixture
        .lane
        .finish_payload_with_encoder(|batch, mut writer| {
            norito::codec::encode_adaptive_into(batch, &mut writer)?;
            queue.clear_all();
            Ok(())
        });
    assert!(
        matches!(result, Err(PublicationError::Retryable(reason)) if reason == "lane Queue admission retired"),
        "lane retained output must not outlive its original Queue admission"
    );
    assert!(fixture.lane.payload_build.is_none());
    assert!(fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().is_none());
}

#[test]
fn lane_original_queue_lease_preserves_same_output_across_clock_rewind_and_retires_readmission() {
    let mut fixture = Fixture::new();
    fixture.wait_for_clock();
    fixture.lane_clock.set(Duration::from_millis(5_000));
    let original = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    let reserved = fixture.lane.budget.reserved_bytes();
    fixture.lane_clock.rewind(Duration::from_millis(1));
    assert!(
        matches!(fixture.lane.build(1, 0, 1 << 20, 1_000), Err(PublicationError::Retryable(reason)) if reason == "ClockAhead")
    );
    assert_eq!(fixture.lane.budget.reserved_bytes(), reserved);
    fixture.lane_clock.advance(Duration::from_millis(1));
    let retried = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    assert_eq!(original.as_slice().as_ptr(), retried.as_slice().as_ptr());
    let lease = &fixture.lane.payload_build.as_ref().unwrap().lease;
    assert!(
        fixture
            .source
            .lease_is_current(lease, &fixture.lane.budget)
            .unwrap()
    );
    assert!(
        !fixture
            .source
            .lease_is_current(lease, &AllocationBudget::new(1 << 20))
            .unwrap()
    );
    fixture.queue.clear_all();
    fixture
        .queue
        .push(fixture.accepted.clone(), fixture.chain.state().view())
        .unwrap();
    assert!(
        matches!(fixture.lane.finish_payload(), Err(PublicationError::Retryable(reason)) if reason == "lane Queue admission retired"),
        "same-hash readmission must not revive the retained lane Queue lease"
    );
    let replacement = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
    assert_eq!(original.as_slice(), replacement.as_slice());
    assert_ne!(
        original.as_slice().as_ptr(),
        replacement.as_slice().as_ptr()
    );
}

#[test]
fn lane_original_queue_lease_preserves_sealed_carriers_and_retires_readmission() {
    use iroha_data_model::transaction::signed::{
        SealedTransactionCommitmentPayload, SealedTransactionReveal,
        SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
    };

    for reveal in [false, true] {
        let mut fixture = Fixture::new();
        let key = KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519);
        let signed = fixture.accepted.external().unwrap().clone();
        let salt = [0x72; 32];
        let network = fixture.chain.network_id();
        let digest = compute_sealed_transaction_commitment(&network, &signed, salt, 9);
        let carrier = if reveal {
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(digest, signed, salt))
        } else {
            TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
                SealedTransactionCommitmentPayload::new(
                    network,
                    signed.authority().clone(),
                    digest,
                    2,
                    9,
                    None,
                ),
                key.private_key(),
            ))
        };
        let accepted = AcceptedTransaction::accept_entrypoint_at_time(
            carrier.clone(),
            &network,
            Duration::from_secs(1),
            fixture
                .chain
                .state()
                .view()
                .world()
                .parameters()
                .transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            Duration::from_millis(4_999),
        )
        .unwrap();
        fixture.queue.clear_all();
        fixture
            .queue
            .push(accepted.clone(), fixture.chain.state().view())
            .unwrap();
        fixture.wait_for_clock();
        fixture.lane_clock.set(Duration::from_millis(5_000));
        let original = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
        let batch = LaneBatch::from_payload(original.as_slice()).unwrap();
        assert_eq!(batch.transactions, vec![carrier]);

        fixture.queue.clear_all();
        fixture
            .queue
            .push(accepted, fixture.chain.state().view())
            .unwrap();
        assert!(
            matches!(fixture.lane.finish_payload(), Err(PublicationError::Retryable(reason)) if reason == "lane Queue admission retired"),
            "same sealed carrier readmission must not revive its original Queue lease"
        );
        let replacement = fixture.lane.build(1, 0, 1 << 20, 1_000).unwrap().unwrap();
        assert_eq!(replacement.as_slice(), original.as_slice());
        assert_ne!(
            replacement.as_slice().as_ptr(),
            original.as_slice().as_ptr()
        );
    }
}
