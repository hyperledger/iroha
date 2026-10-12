//! Follower stage of the resource contract (`specs/zk_resource_contract.json`): the block the
//! proposer assembles around the largest includable transaction fits the committed payload
//! limit and executes through the production payload decoder and executor. A transaction
//! routed to a native lane is admitted and selected within that lane's committed budget.
use super::*;
use crate::{
    state::World,
    sumeragi::{
        lanes::{executor::LaneTransactions, global::QueueLaneTransactions},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    isi::{InstructionBox, Log, Register},
    level::Level,
    parameter::{
        Parameter,
        system::{
            BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, LANE_BATCH_FRAMING_RESERVE_BYTES,
            SumeragiParameter, SumeragiParameters,
        },
    },
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
    },
    transaction::SignedTransaction,
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use std::sync::Arc;

/// Transaction bytes the fixture chain's global proposer can select.
const INCLUDABLE: u32 = 16 * 1024;
/// The committed payload limit of the fixture chain.
const MAX_BLOCK_BYTES: u32 = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + INCLUDABLE;

fn chain() -> (CertifiedTestChain, KeyPair) {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config
        .genesis_parameters
        .push(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            std::num::NonZeroU32::new(MAX_BLOCK_BYTES).unwrap(),
        )));
    let prepared = CertifiedTestChain::prepare(config).unwrap();
    let clock = prepared.clock.clone();
    (CertifiedTestChain::from_prepared(prepared).unwrap(), clock)
}

/// The framed length admission measures for `transaction`.
fn framed_len(chain: &CertifiedTestChain, transaction: &SignedTransaction) -> usize {
    let (_, clock) = TimeSource::new_mock(transaction.creation_time() + Duration::from_millis(1));
    let view = chain.state().view();
    AcceptedTransaction::accept_with_time_source(
        transaction.clone(),
        &chain.network_id(),
        Duration::from_secs(1),
        view.world().parameters().transaction(),
        &iroha_config::parameters::actual::Crypto::default(),
        &clock,
    )
    .expect("the fixture transaction is accepted")
    .encoded_len()
}

/// A `Log` transaction of the clock account whose framed length is exactly `target`.
fn sized(
    chain: &CertifiedTestChain,
    clock: &KeyPair,
    target: u32,
    created_ms: u64,
) -> SignedTransaction {
    let sign = |message_len: usize| {
        chain.sign(
            clock,
            [InstructionBox::from(Log::new(
                Level::DEBUG,
                "x".repeat(message_len),
            ))],
            created_ms,
        )
    };
    let target = usize::try_from(target).unwrap();
    let slack = 1_024;
    let probe = framed_len(chain, &sign(target - slack));
    let transaction = sign(target - slack + (target - probe));
    assert_eq!(framed_len(chain, &transaction), target);
    transaction
}

/// The proposer's assembled maximum is a valid block for the follower, and the reserve is
/// packing policy: a block around a transaction one byte over the includable bound still
/// fits the payload limit and executes, although admission never lets such a transaction
/// reach a proposer.
#[test]
fn follower_accepts_the_assembled_maximum_and_the_reserve_is_packing_policy() {
    let (mut chain, clock) = chain();
    let parameters = chain.state().view().world().parameters().clone();
    assert_eq!(parameters.sumeragi().max_block_bytes.get(), MAX_BLOCK_BYTES);
    assert_eq!(
        parameters.max_includable_transaction_bytes(TransactionInclusionRoute::Global),
        u64::from(INCLUDABLE)
    );
    let limit = usize::try_from(MAX_BLOCK_BYTES).unwrap();
    let admission = |chain: &CertifiedTestChain, transaction: &SignedTransaction| {
        let view = chain.state().view();
        let (_, time) =
            TimeSource::new_mock(transaction.creation_time() + Duration::from_millis(1));
        let accepted = AcceptedTransaction::accept_with_time_source(
            transaction.clone(),
            &chain.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .expect("within the transaction cap");
        check_includable_transaction(
            view.world(),
            &view.nexus().dataspace_catalog,
            0,
            chain.height() + 1,
            &accepted,
        )
    };

    // Height 2: the largest includable transaction.
    let largest = sized(&chain, &clock, INCLUDABLE, 1_500);
    assert_eq!(admission(&chain, &largest), Ok(()));
    let wire = chain
        .proposal(None, vec![largest.clone()])
        .resultless_proposal_wire_len()
        .unwrap();
    // The block wire adds its header fields, the version byte and the Norito header to the
    // transaction; the proposer's reserve covers that framing.
    let framing = wire - usize::try_from(INCLUDABLE).unwrap();
    assert!(wire <= limit, "the assembled maximum fits: {wire}");
    assert!(
        framing > 1 + norito::core::Header::SIZE
            && framing <= BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES as usize,
        "block framing of one transaction: {framing} bytes"
    );
    assert_eq!(chain.commit(vec![largest]), vec![true]);
    assert_eq!(chain.height(), 2);

    // Height 3: one byte over the includable bound. Admission refuses it; a block around it
    // is still within the payload limit and valid, so block validity is unchanged.
    let window = sized(&chain, &clock, INCLUDABLE + 1, 2_500);
    assert_eq!(
        admission(&chain, &window),
        Err(ExecutionAttemptError::Rejected(
            TransactionNeverIncludable {
                encoded_bytes: u64::from(INCLUDABLE) + 1,
                max_bytes: u64::from(INCLUDABLE),
            }
        ))
    );
    let wire = chain
        .proposal(None, vec![window.clone()])
        .resultless_proposal_wire_len()
        .unwrap();
    assert!(wire > usize::try_from(INCLUDABLE).unwrap() + 1 && wire <= limit);
    assert_eq!(chain.commit(vec![window]), vec![true]);
    assert_eq!(chain.height(), 3);

    // A transaction as large as the payload limit cannot be assembled within it; the signed
    // header rule of the consensus core (`Defect::PayloadTooLarge`) rejects such a block on
    // every validator.
    let oversized = sized(&chain, &clock, MAX_BLOCK_BYTES, 3_500);
    assert!(admission(&chain, &oversized).is_err());
    let wire = chain
        .proposal(None, vec![oversized])
        .resultless_proposal_wire_len()
        .unwrap();
    assert!(
        wire > limit,
        "a payload-sized transaction cannot be assembled: {wire}"
    );
}

/// Transaction bytes the lane fixture chain's global proposer can select.
const LANE_FIXTURE_GLOBAL: u32 = 8 * 1024;
/// Transaction bytes the fixture lane's proposer can select: above the global budget.
const LANE_FIXTURE_LANE: u32 = 24 * 1024;
/// The fixture's native lane.
const LANE_FIXTURE_ID: LaneId = LaneId::new(2);

/// A certified chain whose signed genesis commits a native lane with a larger payload limit
/// than the global chain, and routes one account to it. Returns the chain, the clock key
/// (routed to lane zero) and the routed account's key.
fn lane_chain() -> (CertifiedTestChain, KeyPair, KeyPair) {
    let user = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let account = AccountId::new(user.public_key().clone());
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
    let mut lane_params = SumeragiParameters::default();
    lane_params.max_block_bytes =
        std::num::NonZeroU32::new(LANE_FIXTURE_LANE + LANE_BATCH_FRAMING_RESERVE_BYTES).unwrap();
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 8,
        stall_window: 1000,
        lane_params,
        fixed: vec![SumeragiFixedLane {
            lane: LANE_FIXTURE_ID,
            dataspace: DataSpaceId::UNIVERSAL,
            committee,
        }],
        routes: vec![SumeragiLaneRoute {
            lane: LANE_FIXTURE_ID,
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
        .push(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            std::num::NonZeroU32::new(
                BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + LANE_FIXTURE_GLOBAL,
            )
            .unwrap(),
        )));
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
    let prepared = CertifiedTestChain::prepare(config).unwrap();
    let clock = prepared.clock.clone();
    let mut chain = CertifiedTestChain::from_prepared(prepared).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    (chain, clock, user)
}

/// A transaction routed to a native lane has that lane's budget at admission, in the queue
/// and at the lane's proposer: it is admitted above the global budget up to the lane budget,
/// refused one byte over, and selected within exactly the budget the lane builder uses. A
/// transaction routed to lane zero keeps the global budget whatever the lane would carry.
#[test]
fn lane_routed_transaction_is_admitted_and_selected_within_its_lane_budget() {
    let (chain, clock, user) = lane_chain();
    let global = u64::from(LANE_FIXTURE_GLOBAL);
    let lane = u64::from(LANE_FIXTURE_LANE);
    {
        let view = chain.state().view();
        let record = view
            .world()
            .sumeragi_lanes()
            .lane(LANE_FIXTURE_ID)
            .expect("the signed policy creates the fixed lane");
        assert!(record.admits_anchor(chain.height()));
        let lane_payload = record.params.max_block_bytes;
        assert_eq!(
            lane_payload.get(),
            LANE_FIXTURE_LANE + LANE_BATCH_FRAMING_RESERVE_BYTES
        );
        let parameters = view.world().parameters();
        assert_eq!(
            parameters.max_includable_transaction_bytes(TransactionInclusionRoute::Global),
            global
        );
        assert_eq!(
            parameters.max_includable_transaction_bytes(TransactionInclusionRoute::NativeLane {
                max_block_bytes: lane_payload,
            }),
            lane
        );
    }
    let (_, time) = TimeSource::new_mock(Duration::from_millis(3_001));
    let accept = |transaction: SignedTransaction| {
        AcceptedTransaction::accept_with_time_source(
            transaction,
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .expect("within the transaction cap")
    };
    let height = chain.height() + 1;
    let admission = |accepted: &AcceptedTransaction<'static>| {
        let view = chain.state().view();
        check_includable_transaction(
            view.world(),
            &view.nexus().dataspace_catalog,
            view.authenticated_query_ledger_time_ms().unwrap_or(0),
            height,
            accepted,
        )
    };
    let never = |encoded_bytes: u64, max_bytes: u64| TransactionNeverIncludable {
        encoded_bytes,
        max_bytes,
    };
    // Routed to the lane: above the global budget, at the lane budget and one byte over.
    let above_global = accept(sized(&chain, &user, LANE_FIXTURE_GLOBAL + 1, 3_000));
    let at_lane = accept(sized(&chain, &user, LANE_FIXTURE_LANE, 3_000));
    let over_lane = accept(sized(&chain, &user, LANE_FIXTURE_LANE + 1, 3_000));
    // Routed to lane zero: the global budget and one byte over.
    let at_global = accept(sized(&chain, &clock, LANE_FIXTURE_GLOBAL, 3_000));
    let over_global = accept(sized(&chain, &clock, LANE_FIXTURE_GLOBAL + 1, 3_000));
    {
        let view = chain.state().view();
        let routing = super::super::lanes::routing::RoutingSnapshot::of(&view).unwrap();
        let inputs = routing.inputs(view.world());
        for routed in [&above_global, &at_lane, &over_lane] {
            assert_eq!(inputs.route(routed, height).unwrap(), Some(LANE_FIXTURE_ID));
        }
        for direct in [&at_global, &over_global] {
            assert_eq!(inputs.route(direct, height).unwrap(), Some(GLOBAL_LANE));
        }
    }
    assert_eq!(admission(&above_global), Ok(()));
    assert_eq!(admission(&at_lane), Ok(()));
    assert_eq!(
        admission(&over_lane),
        Err(ExecutionAttemptError::Rejected(never(lane + 1, lane)))
    );
    assert_eq!(admission(&at_global), Ok(()));
    assert_eq!(
        admission(&over_global),
        Err(ExecutionAttemptError::Rejected(never(global + 1, global)))
    );

    // Queue admission makes the same decisions and retains nothing it refuses.
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    for (refused, reason) in [
        (&over_lane, never(lane + 1, lane).to_string()),
        (&over_global, never(global + 1, global).to_string()),
    ] {
        let failure = queue
            .push(refused.clone(), chain.state().view())
            .expect_err("no proposer on the route can select it");
        assert!(
            matches!(
                &failure.err,
                crate::queue::Error::UnsupportedTransactionAdmission { reason: actual }
                    if *actual == reason
            ),
            "{:?}",
            failure.err
        );
    }
    assert_eq!(queue.queued_len(), 0);
    queue
        .push(at_lane.clone(), chain.state().view())
        .expect("the lane budget itself is includable on the lane route");
    assert_eq!(queue.queued_len(), 1);

    // The lane's proposer reads the queue with the budget its builder passes: the committed
    // lane payload limit less the batch framing reserve. One byte less cannot carry it.
    let source = QueueLaneTransactions::new(
        LANE_FIXTURE_ID,
        Arc::clone(&queue),
        Arc::clone(chain.state()),
    );
    let budget = usize::try_from(LANE_FIXTURE_LANE).unwrap();
    let skip = std::collections::BTreeSet::new();
    let selected = source.candidates(height, budget, &skip).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].hash_as_entrypoint(),
        at_lane.hash_as_entrypoint()
    );
    assert!(
        source
            .candidates(height, budget - 1, &skip)
            .unwrap()
            .is_empty()
    );
    // The global proposer leaves a fresh lane input to its lane, and could not carry it.
    assert!(
        select(
            &chain.state().view(),
            &queue,
            usize::try_from(LANE_FIXTURE_GLOBAL).unwrap(),
            &MergeProposal::default()
        )
        .unwrap()
        .is_empty()
    );
}

/// The largest number of its own transactions a global proposer puts in one block is the
/// smaller of `max_transactions` and the Network input cap of the committed FASTPQ source
/// policy (eleven under the default policies, not 512). Merged lane transactions reserve
/// their share of the same cap.
#[test]
fn proposer_selection_is_capped_by_the_fastpq_network_input_bound() {
    let (chain, clock) = chain();
    let cap = {
        let view = chain.state().view();
        let block = view.world().parameters().block();
        let cap = block
            .fastpq_source()
            .maximum_network_inputs(block.execution_output())
            .expect("the committed policies are valid");
        assert_eq!(cap, 11, "the default FASTPQ source policy");
        assert_eq!(block.max_transactions().get(), 512);
        usize::try_from(cap).unwrap()
    };
    let (_, time) = TimeSource::new_mock(Duration::from_millis(1_501));
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    for index in 0..cap + 2 {
        let transaction = chain.sign(
            &clock,
            [InstructionBox::from(Log::new(
                Level::DEBUG,
                format!("network input {index}"),
            ))],
            1_500,
        );
        let accepted = AcceptedTransaction::accept_with_time_source(
            transaction,
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .expect("a small transaction is accepted");
        queue
            .push(accepted, chain.state().view())
            .expect("a small transaction is admitted");
    }
    assert_eq!(queue.queued_len(), cap + 2);
    let budget = usize::try_from(INCLUDABLE).unwrap();
    assert_eq!(
        select(
            &chain.state().view(),
            &queue,
            budget,
            &MergeProposal::default()
        )
        .unwrap()
        .len(),
        cap
    );
    assert_eq!(
        select(
            &chain.state().view(),
            &queue,
            budget,
            &MergeProposal {
                transactions: 3,
                ..MergeProposal::default()
            }
        )
        .unwrap()
        .len(),
        cap - 3
    );
    assert!(
        select(
            &chain.state().view(),
            &queue,
            budget,
            &MergeProposal {
                transactions: cap,
                ..MergeProposal::default()
            }
        )
        .unwrap()
        .is_empty()
    );
}

/// The global chain rescues an input whose lane has not carried it for `2A` global block
/// times, and only within the global selection budget. A lane-routed transaction above that
/// budget was includable for its lane at admission, and no global proposer ever selects it:
/// if its lane stalls or closes it stays queued until it expires.
#[test]
fn global_rescue_carries_a_stalled_lane_transaction_only_within_the_global_budget() {
    let (mut chain, _clock, user) = lane_chain();
    let (_, time) = TimeSource::new_mock(Duration::from_millis(3_001));
    let (within, above) = {
        let accept = |transaction: SignedTransaction| {
            AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
                &time,
            )
            .expect("within the transaction cap")
        };
        (
            accept(sized(&chain, &user, LANE_FIXTURE_GLOBAL, 3_000)),
            accept(sized(&chain, &user, LANE_FIXTURE_GLOBAL + 1, 3_000)),
        )
    };
    let queue_of = |transactions: &[&AcceptedTransaction<'static>]| {
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        for transaction in transactions {
            queue
                .push((*transaction).clone(), chain.state().view())
                .expect("includable on the lane route at admission");
        }
        queue
    };
    let both = queue_of(&[&within, &above]);
    let only_above = queue_of(&[&above]);
    let budget = usize::try_from(LANE_FIXTURE_GLOBAL).unwrap();
    // Fresh lane inputs are left to their lane.
    assert!(
        select(
            &chain.state().view(),
            &both,
            budget,
            &MergeProposal::default()
        )
        .unwrap()
        .is_empty()
    );

    // The lane carries neither input for more than `2A` global block times (A = 4 here).
    let cadence = chain
        .state()
        .view()
        .world()
        .parameters()
        .sumeragi()
        .block_cadence_ms
        .get();
    chain.commit_at(3_000 + 2 * 4 * cadence + 1_000, Vec::new());

    // The rescue takes the input the global budget carries and skips the larger one.
    let rescued = select(
        &chain.state().view(),
        &both,
        budget,
        &MergeProposal::default(),
    )
    .unwrap();
    assert_eq!(rescued.len(), 1);
    assert_eq!(rescued[0].hash_as_entrypoint(), within.hash_as_entrypoint());
    // Its size alone keeps the larger input out: alone in the queue it is still skipped
    // within the global budget, and one more byte of budget would carry it.
    assert!(
        select(
            &chain.state().view(),
            &only_above,
            budget,
            &MergeProposal::default()
        )
        .unwrap()
        .is_empty()
    );
    let carried = select(
        &chain.state().view(),
        &only_above,
        budget + 1,
        &MergeProposal::default(),
    )
    .unwrap();
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].hash_as_entrypoint(), above.hash_as_entrypoint());
}
