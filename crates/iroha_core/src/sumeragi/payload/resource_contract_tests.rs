//! Follower stage of the resource contract (`specs/zk_resource_contract.json`): the block the
//! proposer assembles around the largest includable transaction fits the committed payload
//! limit and executes through the production payload decoder and executor. A transaction
//! routed to a native lane is admitted under the coherent transaction cap and selected
//! within the lane's separate committed budget.
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
    isi::{InstructionBox, Log, Register, privacy::SchedulePrivacyConsensusPolicyTighteningV1},
    level::Level,
    parameter::{
        Parameter,
        system::{
            BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, LANE_BATCH_FRAMING_RESERVE_BYTES,
            SumeragiParameter, SumeragiParameters, TransactionParameter,
            resource_coherence::maximal_action_transaction_bytes,
        },
    },
    privacy::PrivacyConsensusLimitsV1,
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
    },
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use std::sync::Arc;

/// Transaction bytes the fixture chain's global proposer can select.
const INCLUDABLE: u32 = 32 * 1024;
/// The committed payload limit of the fixture chain.
const MAX_BLOCK_BYTES: u32 = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + INCLUDABLE;

/// Small limits installed by the original signed genesis, including an actual governed
/// privacy tightening at height two. No decoded World policy bypasses final coherence.
/// One maximal privacy action with its required context (one signer) fits the cap; the
/// transaction and block privacy budgets keep the cap itself.
fn bounded_config(cap: u32) -> TestChainConfig {
    let signatures = std::num::NonZeroU64::MIN;
    let context = maximal_action_transaction_bytes(0, signatures).unwrap();
    let action = u32::try_from(u64::from(cap) - context).unwrap();
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.genesis_parameters.extend([
        Parameter::Transaction(TransactionParameter::MaxTxBytes(
            std::num::NonZeroU64::new(u64::from(cap)).unwrap(),
        )),
        Parameter::Transaction(TransactionParameter::MaxSignatures(signatures)),
        Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            std::num::NonZeroU32::new(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + cap).unwrap(),
        )),
    ]);
    config.genesis_instructions.push(
        SchedulePrivacyConsensusPolicyTighteningV1::new(
            2,
            PrivacyConsensusLimitsV1 {
                max_proof_bytes_per_action: action,
                max_action_bytes: action,
                max_privacy_bytes_per_transaction: cap,
                max_privacy_bytes_per_block: cap,
                max_statement_and_encrypted_output_bytes_per_transaction: action,
                ..PrivacyConsensusLimitsV1::taira_default()
            },
        )
        .into(),
    );
    config
}

fn chain() -> (CertifiedTestChain, KeyPair) {
    let prepared = CertifiedTestChain::prepare(bounded_config(INCLUDABLE)).unwrap();
    let clock = prepared.clock.clone();
    (CertifiedTestChain::from_prepared(prepared).unwrap(), clock)
}

/// Canonical framed bytes, measured independently of admission so refused inputs can be sized.
fn framed_len(transaction: &SignedTransaction) -> usize {
    norito::to_bytes(transaction)
        .expect("canonical signed frame")
        .len()
}

/// Both real envelope admission and the follower reject the same over-cap bytes/reason.
fn assert_cap_rejected(chain: &CertifiedTestChain, transaction: &SignedTransaction, cap: u32) {
    let (_, time) = TimeSource::new_mock(transaction.creation_time() + Duration::from_millis(1));
    let view = chain.state().view();
    let limits = view.world().parameters().transaction();
    let crypto = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
        iroha_crypto::Algorithm::Ed25519,
        iroha_crypto::Algorithm::Secp256k1,
    ])
    .expect("explicit payload fixture policy");
    let admission = AcceptedTransaction::accept_with_time_source(
        transaction.clone(),
        &chain.network_id(),
        Duration::from_secs(1),
        limits,
        &crypto,
        &time,
    );
    let follower = AcceptedTransaction::validate_with_now(
        transaction,
        &chain.network_id(),
        Duration::from_secs(1),
        limits,
        &crypto,
        transaction.creation_time(),
    );
    let reason = format!(
        "Transaction size {} bytes exceeds limit {cap} bytes",
        framed_len(transaction)
    );
    let Err(crate::tx::AcceptTransactionFail::TransactionLimit(admission)) = admission else {
        panic!("admission must reject the exact transaction cap violation");
    };
    let Err(crate::tx::AcceptTransactionFail::TransactionLimit(follower)) = follower else {
        panic!("follower must reject the exact transaction cap violation");
    };
    assert_eq!(admission.reason, reason);
    assert_eq!(follower.reason, reason);
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
    let probe = framed_len(&sign(target - slack));
    let transaction = sign(target - slack + (target - probe));
    assert_eq!(framed_len(&transaction), target);
    transaction
}

/// A carrier sized independently of the inner signed admission limit.
fn sized_lane_carrier(
    chain: &CertifiedTestChain,
    clock: &KeyPair,
    target: u32,
    created_ms: u64,
) -> SignedTransaction {
    let probe = sized(chain, clock, target, created_ms);
    let carrier_len = norito::encode_canonical(&TransactionEntrypoint::External(probe.clone()))
        .unwrap()
        .len();
    let overhead = carrier_len.checked_sub(framed_len(&probe)).unwrap();
    let signed_target = target
        .checked_sub(u32::try_from(overhead).unwrap())
        .unwrap();
    let transaction = sized(chain, clock, signed_target, created_ms);
    assert_eq!(
        norito::encode_canonical(&TransactionEntrypoint::External(transaction.clone()))
            .unwrap()
            .len(),
        usize::try_from(target).unwrap()
    );
    transaction
}

/// The proposer's assembled maximum is a valid block for the follower, and the reserve is
/// packing policy: two cap-valid transactions whose aggregate exceeds the selection budget
/// can still fit the actual block payload and execute. An individual over-cap transaction
/// is rejected by both admission and the follower under the coherent committed policy.
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
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
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
    assert_eq!(
        (admission(&chain, &largest)).expect("completed fixture operation"),
        ()
    );
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

    // An individual cap+1 transaction is invalid at both real entrypoints. Canonical byte
    // measurement grants no proposal authority; the actual proposal helper also rejects it.
    let one_over = sized(&chain, &clock, INCLUDABLE + 1, 2_500);
    assert_cap_rejected(&chain, &one_over, INCLUDABLE);

    // Height 3: two individually cap-valid inputs exceed the proposer's total selection
    // budget by one byte. Selection skips one, but an actually fitting block is still valid.
    let window = vec![
        sized(&chain, &clock, INCLUDABLE / 2, 2_500),
        sized(&chain, &clock, INCLUDABLE / 2 + 1, 2_501),
    ];
    assert_eq!(
        window.iter().map(framed_len).sum::<usize>(),
        INCLUDABLE as usize + 1
    );
    let (_, time) = TimeSource::new_mock(Duration::from_millis(2_502));
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    for transaction in &window {
        assert_eq!(admission(&chain, transaction).unwrap(), ());
        let accepted = AcceptedTransaction::accept_with_time_source(
            transaction.clone(),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("explicit current admission fixture policy"),
            &time,
        )
        .expect("each input is below the committed cap");
        assert_eq!(accepted.encoded_len(), framed_len(transaction));
        queue
            .push(accepted, chain.state().view())
            .expect("cap-valid queue admission");
    }
    assert_eq!(
        select(
            &chain.state().view(),
            &queue,
            INCLUDABLE as usize,
            &MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
        )
        .unwrap()
        .len(),
        1
    );
    let wire = chain
        .proposal(None, window.clone())
        .resultless_proposal_wire_len()
        .unwrap();
    assert!(wire > INCLUDABLE as usize + 1 && wire <= limit);
    assert_eq!(chain.commit(window), vec![true, true]);
    assert_eq!(chain.height(), 3);

    // Six distinct, individually valid cap-sized inputs exceed the actual payload limit.
    // This isolates the signed header size rule from the independent transaction cap.
    let oversized = (0..6)
        .map(|index| sized(&chain, &clock, INCLUDABLE, 3_500 + index))
        .collect::<Vec<_>>();
    for transaction in &oversized {
        assert_eq!(admission(&chain, transaction).unwrap(), ());
    }
    let wire = chain
        .proposal(None, oversized)
        .resultless_proposal_wire_len()
        .unwrap();
    assert!(
        wire > limit,
        "valid inputs cannot be assembled beyond the payload cap: {wire}"
    );
}

/// Transaction bytes the lane fixture chain's global proposer can select.
const LANE_FIXTURE_GLOBAL: u32 = 32 * 1024;
/// Remaining global selection bytes after other proposal contents have reserved space.
const RESIDUAL_GLOBAL_BUDGET: u32 = 8 * 1024;
/// Transaction bytes the fixture lane's proposer can select: below the committed global cap.
const LANE_FIXTURE_LANE: u32 = 24 * 1024;
/// The fixture's native lane.
const LANE_FIXTURE_ID: LaneId = LaneId::new(2);

/// A certified chain whose signed genesis commits a smaller native lane selection budget
/// than the coherent global transaction cap, and routes one account to it. Returns the chain,
/// the clock key (routed to lane zero) and the routed account's key.
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
    let lane_params = SumeragiParameters {
        max_block_bytes: std::num::NonZeroU32::new(
            LANE_FIXTURE_LANE + LANE_BATCH_FRAMING_RESERVE_BYTES,
        )
        .unwrap(),
        ..Default::default()
    };
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
    let mut config = bounded_config(LANE_FIXTURE_GLOBAL);
    config
        .genesis_instructions
        .push(Register::account(Account::new(account)).into());
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

#[test]
fn proposer_clock_selection_retains_future_signed_inputs_until_the_exact_time() {
    let (chain, signer) = chain();
    let (clock, time) = TimeSource::new_mock(Duration::from_millis(3_000));
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let due = sized(&chain, &signer, 4_096, 3_000);
    let future = sized(&chain, &signer, 4_096, 3_001);
    for original in [&future, &due] {
        let accepted = AcceptedTransaction::accept_with_time_source(
            original.clone(),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("explicit current admission fixture policy"),
            &time,
        )
        .unwrap();
        queue.push(accepted, chain.state().view()).unwrap();
        if queue.queued_len() == 1 {
            assert!(
                matches!(
                    select(
                        &chain.state().view(),
                        &queue,
                        INCLUDABLE as usize,
                        &MergeProposal::default(),
                        time.now(),
                    ),
                    Err(PayloadError::ClockAhead)
                ),
                "global proposer must leave future signed input queued"
            );
        }
    }
    let selected = select(
        &chain.state().view(),
        &queue,
        INCLUDABLE as usize,
        &MergeProposal::default(),
        time.now(),
    )
    .unwrap();
    assert_eq!(
        selected.len(),
        1,
        "global proposer must leave future signed input queued"
    );
    assert_eq!(selected[0].hash_as_entrypoint(), due.hash_as_entrypoint());
    assert_eq!(queue.queued_len(), 2);
    clock.advance(Duration::from_millis(1));
    let selected = select(
        &chain.state().view(),
        &queue,
        INCLUDABLE as usize,
        &MergeProposal::default(),
        time.now(),
    )
    .unwrap();
    assert_eq!(selected.len(), 2);
    assert!(
        selected
            .iter()
            .any(|input| input.hash_as_entrypoint() == future.hash_as_entrypoint())
    );
    assert_eq!(
        queue.queued_len(),
        2,
        "selection does not consume original queue custody"
    );
    clock.rewind(Duration::from_millis(1));
    assert_eq!(
        select(
            &chain.state().view(),
            &queue,
            INCLUDABLE as usize,
            &MergeProposal::default(),
            time.now()
        )
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn lane_proposer_clock_selection_preserves_future_inputs_and_resumes_after_advance() {
    use crate::sumeragi::lanes::executor::LaneSelectionError;
    let (chain, _, signer) = lane_chain();
    let (clock, time) = TimeSource::new_mock(Duration::from_millis(3_000));
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let future = sized(&chain, &signer, 4_096, 3_001);
    let accepted = AcceptedTransaction::accept_with_time_source(
        future.clone(),
        &chain.network_id(),
        Duration::from_secs(1),
        chain.state().view().world().parameters().transaction(),
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("explicit current admission fixture policy"),
        &time,
    )
    .unwrap();
    queue.push(accepted, chain.state().view()).unwrap();
    let source =
        QueueLaneTransactions::new(LANE_FIXTURE_ID, queue.clone(), chain.state().clone(), time);
    let height = chain.height() + 1;
    let skip = std::collections::BTreeSet::new();
    assert!(
        matches!(
            source.candidates(
                height,
                LANE_FIXTURE_LANE as usize,
                &skip,
                &chain.state().ivm_execution_budget()
            ),
            Err(LaneSelectionError::ClockAhead)
        ),
        "lane proposer must leave future signed input queued"
    );
    assert_eq!(queue.queued_len(), 1);
    clock.advance(Duration::from_millis(1));
    let selected = source
        .candidates(
            height,
            LANE_FIXTURE_LANE as usize,
            &skip,
            &chain.state().ivm_execution_budget(),
        )
        .unwrap()
        .0;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash(), future.hash_as_entrypoint());
    assert_eq!(queue.queued_len(), 1);
    clock.rewind(Duration::from_millis(1));
    assert!(matches!(
        source.candidates(
            height,
            LANE_FIXTURE_LANE as usize,
            &skip,
            &chain.state().ivm_execution_budget()
        ),
        Err(LaneSelectionError::ClockAhead)
    ));
}

/// Admission uses the coherent transaction cap on either route. The lane proposer obeys
/// its smaller budget: it carries the exact lane maximum and skips a queued cap-valid input
/// one byte larger. Such an input remains eligible for later global rescue.
#[test]
fn lane_routed_transaction_is_admitted_and_selected_within_its_lane_budget() {
    let (chain, clock, user) = lane_chain();
    let global = u64::from(LANE_FIXTURE_GLOBAL);
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
            global
        );
    }
    let (_, time) = TimeSource::new_mock(Duration::from_millis(3_001));
    let accept = |transaction: SignedTransaction| {
        AcceptedTransaction::accept_with_time_source(
            transaction,
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
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
    // All these lane inputs fit the committed cap; the first exceeds only a residual budget.
    let above_residual = accept(sized(&chain, &user, RESIDUAL_GLOBAL_BUDGET + 1, 3_000));
    let at_lane = accept(sized_lane_carrier(&chain, &user, LANE_FIXTURE_LANE, 3_000));
    let over_lane = accept(sized_lane_carrier(
        &chain,
        &user,
        LANE_FIXTURE_LANE + 1,
        3_000,
    ));
    // The committed transaction cap is inclusive on both routes, with exact +1 refusal.
    let at_global = accept(sized(&chain, &clock, LANE_FIXTURE_GLOBAL, 3_000));
    let at_cap_lane = accept(sized(&chain, &user, LANE_FIXTURE_GLOBAL, 3_000));
    for key in [&clock, &user] {
        assert_cap_rejected(
            &chain,
            &sized(&chain, key, LANE_FIXTURE_GLOBAL + 1, 3_000),
            LANE_FIXTURE_GLOBAL,
        );
    }
    {
        let view = chain.state().view();
        let routing = super::super::lanes::routing::RoutingSnapshot::of(&view).unwrap();
        let inputs = routing.inputs(view.world());
        for routed in [&above_residual, &at_lane, &over_lane, &at_cap_lane] {
            assert_eq!(inputs.route(routed, height).unwrap(), Some(LANE_FIXTURE_ID));
        }
        assert_eq!(inputs.route(&at_global, height).unwrap(), Some(GLOBAL_LANE));
    }
    for accepted in [
        &above_residual,
        &at_lane,
        &over_lane,
        &at_cap_lane,
        &at_global,
    ] {
        assert_eq!(admission(accepted).unwrap(), ());
    }

    // Queue custody retains valid inputs even when the lane alone cannot carry them.
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    assert_eq!(queue.queued_len(), 0);
    queue
        .push(over_lane.clone(), chain.state().view())
        .expect("global rescue can carry it");
    queue
        .push(at_lane.clone(), chain.state().view())
        .expect("the lane budget itself is includable on the lane route");
    assert_eq!(queue.queued_len(), 2);

    // The lane's proposer reads the queue with the budget its builder passes: the committed
    // lane payload limit less the batch framing reserve. One byte less cannot carry it.
    let source = QueueLaneTransactions::new(
        LANE_FIXTURE_ID,
        Arc::clone(&queue),
        Arc::clone(chain.state()),
        time.clone(),
    );
    let budget = usize::try_from(LANE_FIXTURE_LANE).unwrap();
    let skip = std::collections::BTreeSet::new();
    let selected = source
        .candidates(height, budget, &skip, &chain.state().ivm_execution_budget())
        .unwrap()
        .0;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash(), at_lane.hash_as_entrypoint());
    assert!(
        source
            .candidates(
                height,
                budget - 1,
                &skip,
                &chain.state().ivm_execution_budget()
            )
            .unwrap()
            .0
            .is_empty()
    );
    // The global proposer leaves fresh lane inputs to their lane even with enough capacity.
    assert!(
        select(
            &chain.state().view(),
            &queue,
            usize::try_from(LANE_FIXTURE_GLOBAL).unwrap(),
            &MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
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
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
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
            &MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
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
            },
            iroha_primitives::time::TimeSource::new_system().now()
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
            },
            iroha_primitives::time::TimeSource::new_system().now()
        )
        .unwrap()
        .is_empty()
    );
}

/// The global chain rescues an input whose lane has not carried it for `2A` global block
/// times, and only within the remaining global selection budget. Both inputs fit the
/// committed global cap; a budget reduced by other proposal contents can defer one until
/// another proposal leaves enough room. No valid policy admits an input above the full cap.
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
                &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                ])
                .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
                &time,
            )
            .expect("within the transaction cap")
        };
        (
            accept(sized(&chain, &user, RESIDUAL_GLOBAL_BUDGET, 3_000)),
            accept(sized(&chain, &user, RESIDUAL_GLOBAL_BUDGET + 1, 3_000)),
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
    let budget = usize::try_from(RESIDUAL_GLOBAL_BUDGET).unwrap();
    // Fresh lane inputs are left to their lane.
    assert!(
        select(
            &chain.state().view(),
            &both,
            budget,
            &MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
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
        iroha_primitives::time::TimeSource::new_system().now(),
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
            &MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
        )
        .unwrap()
        .is_empty()
    );
    let carried = select(
        &chain.state().view(),
        &only_above,
        budget + 1,
        &MergeProposal::default(),
        iroha_primitives::time::TimeSource::new_system().now(),
    )
    .unwrap();
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].hash_as_entrypoint(), above.hash_as_entrypoint());
}
