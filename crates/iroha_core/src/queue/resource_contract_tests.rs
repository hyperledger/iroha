// Exact-limit and one-over checks of the transaction bounds in `specs/zk_resource_contract.json`:
// admission, queue custody, proposer selection and block validation read the same committed
// parameters and make the same decision.

/// One signed `Log` transaction whose message is `message_len` bytes long.
fn resource_contract_signed_log(
    time: &TimeSource,
    message_len: usize,
) -> iroha_data_model::transaction::SignedTransaction {
    TransactionBuilder::new_with_time_source(
        queue_test_network_id(),
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        time,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(vec![InstructionBox::from(iroha_data_model::isi::Log::new(
        iroha_data_model::level::Level::INFO,
        "x".repeat(message_len),
    ))])
    .sign(ALICE_KEYPAIR.private_key())
}

/// Governed limits whose transaction byte cap is `max_tx_bytes`.
fn resource_contract_limits(max_tx_bytes: u64) -> TransactionParameters {
    let defaults = TransactionParameters::default();
    TransactionParameters::with_max_signatures(
        defaults.max_signatures(),
        defaults.max_instructions(),
        defaults.ivm_bytecode_size(),
        std::num::NonZeroU64::new(max_tx_bytes).expect("nonzero transaction cap"),
        defaults.max_decompressed_bytes(),
        defaults.max_metadata_depth(),
    )
}

/// Admit `transaction` under `limits` at the mock clock of `time`.
fn resource_contract_accept(
    transaction: iroha_data_model::transaction::SignedTransaction,
    limits: TransactionParameters,
    time: &TimeSource,
) -> Result<AcceptedTransaction<'static>, crate::tx::AcceptTransactionFail> {
    AcceptedTransaction::accept_with_time_source(
        transaction,
        &queue_test_network_id(),
        Duration::from_millis(10),
        limits,
        &iroha_config::parameters::actual::Crypto::default(),
        time,
    )
}

/// A queue fixture whose committed global payload limit is `max_block_bytes`.
fn resource_contract_state(max_block_bytes: u32) -> State {
    let world = world_with_test_domains();
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::Sumeragi(
                iroha_data_model::parameter::system::SumeragiParameter::MaxBlockBytes(
                    std::num::NonZeroU32::new(max_block_bytes).expect("nonzero payload limit"),
                ),
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let mut state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    install_single_validator_topology_for_queue_test(&mut state, 0xB7);
    state
}

/// The committed transaction cap is inclusive, and the admission entry and the block
/// validation entry reject the same first oversize byte with the same reason.
#[test]
fn transaction_cap_is_exact_at_admission_and_block_validation() {
    let (_, time) = TimeSource::new_mock(Duration::default());
    let at_limit = resource_contract_signed_log(&time, 3_000);
    let one_over = resource_contract_signed_log(&time, 3_001);
    let limit =
        resource_contract_accept(at_limit.clone(), resource_contract_limits(1 << 20), &time)
            .expect("transaction fits a 1 MiB cap")
            .encoded_len();
    let over = resource_contract_accept(one_over.clone(), resource_contract_limits(1 << 20), &time)
        .expect("transaction fits a 1 MiB cap")
        .encoded_len();
    assert_eq!(
        over,
        limit + 1,
        "one more message byte is one more framed byte"
    );
    // Norito framing is part of the measured length: header, alignment and bare payload.
    assert!(limit > norito::core::Header::SIZE + 3_000);
    let limit = u64::try_from(limit).unwrap();
    let limits = resource_contract_limits(limit);
    let reason = format!(
        "Transaction size {} bytes exceeds limit {limit} bytes",
        limit + 1
    );
    // SDK preflight over committed parameters whose block payload leaves room for the cap.
    let mut parameters = iroha_data_model::parameter::Parameters::default();
    parameters.transaction = limits;
    assert_eq!(
        parameters.max_includable_transaction_bytes(
            iroha_data_model::parameter::system::TransactionInclusionRoute::Global
        ),
        limit
    );
    assert_eq!(
        parameters.check_signed_transaction_bytes(
            limit,
            iroha_data_model::parameter::system::TransactionInclusionRoute::Global
        ),
        Ok(())
    );
    assert!(
        parameters
            .check_signed_transaction_bytes(
                limit + 1,
                iroha_data_model::parameter::system::TransactionInclusionRoute::Global
            )
            .is_err()
    );
    // Admission (Torii and gossip ingress share this entry).
    assert!(resource_contract_accept(at_limit.clone(), limits, &time).is_ok());
    let Err(crate::tx::AcceptTransactionFail::TransactionLimit(admission)) =
        resource_contract_accept(one_over.clone(), limits, &time)
    else {
        panic!("admission rejects one byte over the cap as a transaction limit");
    };
    assert_eq!(admission.reason, reason);
    // Block validation (the follower and lane-merge entry).
    let crypto = iroha_config::parameters::actual::Crypto::default();
    let follower = |transaction: &iroha_data_model::transaction::SignedTransaction| {
        AcceptedTransaction::validate_with_now(
            transaction,
            &queue_test_network_id(),
            Duration::from_millis(10),
            limits,
            &crypto,
            transaction.creation_time(),
        )
    };
    follower(&at_limit).expect("block validation accepts the cap itself");
    let Err(crate::tx::AcceptTransactionFail::TransactionLimit(validation)) = follower(&one_over)
    else {
        panic!("block validation rejects one byte over the cap as a transaction limit");
    };
    assert_eq!(validation.reason, reason);
}

/// Queue admission refuses exactly the transactions the proposer can never select: both read
/// the committed block payload limit less the reserve the data model owns.
#[test]
fn queue_admission_and_proposer_selection_share_the_includable_bound() {
    let (_, time) = TimeSource::new_mock(Duration::default());
    let limits = TransactionParameters::default();
    let at_limit =
        resource_contract_accept(resource_contract_signed_log(&time, 3_000), limits, &time)
            .expect("accepted under the default cap");
    let one_over =
        resource_contract_accept(resource_contract_signed_log(&time, 3_001), limits, &time)
            .expect("accepted under the default cap");
    let limit = at_limit.encoded_len();
    assert_eq!(one_over.encoded_len(), limit + 1);
    let reserve = iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
    let max_block_bytes = reserve + u32::try_from(limit).unwrap();
    let mut state = resource_contract_state(max_block_bytes);
    register_accepted_tx_authority_for_queue_test(&mut state, &at_limit);
    let bound = state
        .view()
        .world()
        .parameters()
        .max_includable_transaction_bytes(
            iroha_data_model::parameter::system::TransactionInclusionRoute::Global,
        );
    assert_eq!(bound, limit as u64);
    // The proposer's selection budget is the same number (`sumeragi::executor`).
    let budget = usize::try_from(max_block_bytes - reserve).unwrap();
    assert_eq!(budget, limit);

    // Every queue boundary admits the transaction at the bound and refuses one byte over.
    let reason = iroha_data_model::parameter::system::TransactionNeverIncludable {
        encoded_bytes: limit as u64 + 1,
        max_bytes: limit as u64,
    }
    .to_string();
    for boundary in 0..3 {
        let queue = Arc::new(Queue::test(config_factory(), &time));
        let push = |transaction: AcceptedTransaction<'static>| match boundary {
            0 => queue.push(transaction, state.view()).map(|_| ()),
            1 => queue
                .push_with_lane_with_state(transaction, &state)
                .map(|_| ()),
            _ => {
                let plan = queue.route_plan_with_state(&transaction, &state).unwrap();
                queue
                    .push_batch_with_lane_with_state_and_routing_plans(
                        vec![(transaction, plan)],
                        &state,
                    )
                    .map(|_| ())
            }
        };
        let failure = push(one_over.clone()).expect_err("one byte over is never includable");
        let Error::UnsupportedTransactionAdmission { reason: actual } = failure.err else {
            panic!("unexpected queue error: {:?}", failure.err);
        };
        assert_eq!(actual, reason);
        assert_eq!(
            queue.active_len(),
            0,
            "a refused transaction takes no custody"
        );
        push(at_limit.clone()).expect("the bound itself is includable");
        assert_eq!(queue.active_len(), 1);
        // The proposer selects what the queue admitted, within the same budget.
        let selected = crate::sumeragi::payload::select(&state, &queue, budget, 0).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].hash_as_entrypoint(),
            at_limit.hash_as_entrypoint()
        );
        assert!(
            crate::sumeragi::payload::select(&state, &queue, budget - 1, 0)
                .unwrap()
                .is_empty(),
            "one byte less budget cannot carry the transaction"
        );
    }

    // Under a larger committed payload limit the same transaction is admitted, and the
    // proposer still skips it for exactly the budget that cannot carry it.
    let mut roomy = resource_contract_state(max_block_bytes + 1);
    register_accepted_tx_authority_for_queue_test(&mut roomy, &one_over);
    let queue = Arc::new(Queue::test(config_factory(), &time));
    queue
        .push(one_over.clone(), roomy.view())
        .expect("one more payload byte admits one more transaction byte");
    assert!(
        crate::sumeragi::payload::select(&roomy, &queue, budget, 0)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        crate::sumeragi::payload::select(&roomy, &queue, budget + 1, 0)
            .unwrap()
            .len(),
        1
    );
}

/// The bound follows the transaction's route. A lane's larger budget is available only to a
/// transaction routed to that lane, and an unreadable committed policy defers the assessment
/// at the function and at the queue: it neither admits nor rejects, and takes no custody.
#[test]
fn includable_bound_follows_the_route_and_an_unreadable_policy_defers() {
    use crate::{
        execution_attempt::ExecutionAttemptError,
        sumeragi::{
            lanes::routing::GLOBAL_LANE,
            payload::{check_includable_transaction, max_includable_transaction_bytes_on_route},
        },
    };
    use iroha_data_model::{
        parameter::{Parameter, Parameters, system::TransactionNeverIncludable},
        sumeragi_lanes::{
            SumeragiLaneFrontier, SumeragiLanePolicy, SumeragiLaneRecord, SumeragiLaneState,
        },
    };
    let (_, time) = TimeSource::new_mock(Duration::default());
    let limits = TransactionParameters::default();
    let transaction =
        resource_contract_accept(resource_contract_signed_log(&time, 3_000), limits, &time)
            .expect("accepted under the default cap");
    let length = u32::try_from(transaction.encoded_len()).unwrap();
    let reserve = iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
    let lane_reserve = iroha_data_model::parameter::system::LANE_BATCH_FRAMING_RESERVE_BYTES;
    // The global payload leaves room for one byte less than the transaction; the lane payload
    // carries it exactly.
    let global = reserve + length - 1;
    let mut lane_params = Parameters::default().sumeragi().clone();
    lane_params.max_block_bytes = std::num::NonZeroU32::new(length + lane_reserve).unwrap();
    let policy = SumeragiLanePolicy::for_chain(
        lane_params.clone(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.validate().expect("valid lane policy");
    let never = TransactionNeverIncludable {
        encoded_bytes: u64::from(length),
        max_bytes: u64::from(length) - 1,
    };

    // The budget of each route, from committed parameters and the committed lane record: the
    // record pins the payload limit the lane's proposer builds within.
    let mut state = resource_contract_state(global);
    register_accepted_tx_authority_for_queue_test(&mut state, &transaction);
    let parameters = state.view().world().parameters().clone();
    let native = iroha_model_base::topology::LaneId::new(1);
    let lanes_with = |max_block_bytes: u32| {
        let mut params = lane_params.clone();
        params.max_block_bytes = std::num::NonZeroU32::new(max_block_bytes).unwrap();
        let mut lanes = SumeragiLaneState::default();
        lanes.upsert(SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: native,
            dataspace: DataSpaceId::UNIVERSAL,
            incarnation: [1; 32],
            params,
            committee: Vec::new(),
            created_at: 0,
            active_from: 0,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 0,
            rescued: 0,
        });
        lanes
    };
    let carrying = lanes_with(length + lane_reserve);
    let on_route = |lanes: &SumeragiLaneState, lane| {
        max_includable_transaction_bytes_on_route(&parameters, lanes, lane)
    };
    assert_eq!(on_route(&carrying, Some(native)), u64::from(length));
    assert_eq!(on_route(&carrying, Some(GLOBAL_LANE)), never.max_bytes);
    assert_eq!(on_route(&carrying, None), never.max_bytes);
    // A lane without a committed record has no proposer: the global budget decides.
    assert_eq!(
        on_route(&SumeragiLaneState::default(), Some(native)),
        never.max_bytes
    );
    // One byte less lane payload cannot carry the transaction.
    assert_eq!(
        on_route(&lanes_with(length + lane_reserve - 1), Some(native)),
        never.max_bytes
    );

    let check = |state: &State| {
        let view = state.view();
        check_includable_transaction(
            view.world(),
            &view.nexus.dataspace_catalog,
            view.query_ledger_time_ms(),
            2,
            &transaction,
        )
    };
    let refused_by = |queue: &Queue, state: &State| {
        let failure = queue
            .push(transaction.clone(), state.view())
            .expect_err("the transaction is not admitted");
        assert_eq!(queue.active_len(), 0, "a refusal takes no custody");
        assert_eq!(queue.queued_len(), 0, "a refusal takes no custody");
        assert_eq!(queue.retained_bytes(), 0, "a refusal takes no custody");
        failure.err
    };
    let refused_by_queue = |state: &State| refused_by(&Queue::test(config_factory(), &time), state);

    // No lane policy: the global budget decides.
    assert!(
        matches!(check(&state), Err(ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (never))
    );
    assert!(matches!(
        refused_by_queue(&state),
        Error::UnsupportedTransactionAdmission { reason } if reason == never.to_string()
    ));

    // A committed lane policy whose budget would carry the transaction does not help a
    // transaction routed to lane zero.
    {
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(policy.into_custom_parameter()))
            .expect("valid fixture parameters");
        world.commit();
    }
    assert!(
        matches!(check(&state), Err(ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (never))
    );
    assert!(matches!(
        refused_by_queue(&state),
        Error::UnsupportedTransactionAdmission { reason } if reason == never.to_string()
    ));

    // Local decode capacity refuses the committed policy read: the assessment is deferred,
    // and the completed read of the same State gives the deterministic verdict again.
    let starved_limits = || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let starved = norito::with_decode_limits_scope(starved_limits(), || check(&state));
    assert!(
        matches!(starved, Err(ExecutionAttemptError::Deferred(_))),
        "a local refusal is neither an admission nor a rejection: {starved:?}"
    );
    // Queue admission maps the same local refusal to a deferral, never to the permanent
    // `UnsupportedTransactionAdmission`, and retains nothing.
    let Err(ExecutionAttemptError::Deferred(local_refusal)) = starved else {
        unreachable!("checked above");
    };
    let queue = Queue::test(config_factory(), &time);
    let starved_push =
        norito::with_decode_limits_scope(starved_limits(), || refused_by(&queue, &state));
    let Error::Deferred(queued_refusal) = starved_push else {
        panic!("a starved policy read must defer queue admission: {starved_push:?}");
    };
    assert_eq!(queued_refusal.reason(), local_refusal.reason());
    assert_eq!(queued_refusal.phase(), local_refusal.phase());
    assert!(queued_refusal.allocation_refusal().is_none());
    assert!(local_refusal.allocation_refusal().is_none());
    assert!(queued_refusal.verification_refusal().is_none());
    assert!(local_refusal.verification_refusal().is_none());
    let payload_cause = local_refusal
        .decode_refusal()
        .expect("actual payload policy read");
    let queued_cause = queued_refusal
        .decode_refusal()
        .expect("actual queue policy/root read");
    // The actual operations may first inspect different committed JSON owners. Both
    // preserve their real zero-budget refusal; unrelated attempts never share identity.
    for cause in [payload_cause, queued_cause] {
        assert_eq!(
            cause.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert!(matches!(cause.resource_error(),
            norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
            if attempted > 0));
    }
    assert_ne!(payload_cause, queued_cause);
    let observed = queued_cause.clone();
    let moved = crate::execution_attempt::ExecutionDeferred::try_from_vm_error(
        queued_refusal.into_vm_error(),
    )
    .unwrap();
    assert_eq!(moved.decode_refusal(), Some(&observed));
    // The same queue admits nothing and rejects nothing because of the deferral: once the
    // read completes it gives the deterministic verdict.
    assert!(
        matches!(check(&state), Err(ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (never))
    );
    assert!(matches!(
        refused_by_queue(&state),
        Error::UnsupportedTransactionAdmission { reason } if reason == never.to_string()
    ));

    // A transaction within the global budget needs no policy read, so nothing defers it.
    let roomy = resource_contract_state(global + 1);
    let within = norito::with_decode_limits_scope(starved_limits(), || check(&roomy));
    assert_eq!(
        (within)
            .as_ref()
            .expect("the operation must complete successfully"),
        &(())
    );
}

/// The default 16 MiB block policy admits and selects the full 10 MiB transaction cap.
/// Admission and block validation both reject the next byte. The same cap-sized
/// transaction is refused without queue custody under an explicitly smaller route,
/// preserving the independent includability boundary.
#[test]
fn default_limits_admit_and_select_the_largest_includable_transaction() {
    let (_, time) = TimeSource::new_mock(Duration::default());
    let limits = TransactionParameters::default();
    let parameters = iroha_data_model::parameter::Parameters::default();
    assert_eq!(
        parameters.sumeragi.max_block_bytes().get(),
        16 * 1024 * 1024
    );
    let includable = parameters.max_includable_transaction_bytes(
        iroha_data_model::parameter::system::TransactionInclusionRoute::Global,
    );
    let cap = limits.max_tx_bytes().get();
    assert_eq!(cap, 10_485_760);
    assert_eq!(
        includable, cap,
        "the default block carries the full transaction cap"
    );
    // A signed transaction of exactly `target` framed bytes, measured by admission itself.
    let measure = |message_len: usize| {
        let signed = resource_contract_signed_log(&time, message_len);
        let length =
            resource_contract_accept(signed.clone(), resource_contract_limits(1 << 26), &time)
                .expect("measured under a generous cap")
                .encoded_len();
        (signed, length)
    };
    let sized = |target: u64| {
        let target = usize::try_from(target).unwrap();
        let slack = 8_192;
        let (_, probe) = measure(target - slack);
        let (signed, length) = measure(target - slack + (target - probe));
        assert_eq!(
            length, target,
            "the framed length is linear in the message length"
        );
        signed
    };
    let largest = sized(includable);
    let at_cap = sized(cap);
    let over_cap = sized(cap + 1);

    // Transaction validation: the cap is inclusive at admission and in block validation.
    let crypto = iroha_config::parameters::actual::Crypto::default();
    let follower = |transaction: &iroha_data_model::transaction::SignedTransaction| {
        AcceptedTransaction::validate_with_now(
            transaction,
            &queue_test_network_id(),
            Duration::from_millis(10),
            limits,
            &crypto,
            transaction.creation_time(),
        )
    };
    let largest = resource_contract_accept(largest, limits, &time).expect("includable");
    follower(&at_cap).expect("block validation accepts the cap itself");
    let at_cap = resource_contract_accept(at_cap, limits, &time).expect("the cap itself");
    assert!(matches!(
        follower(&over_cap),
        Err(crate::tx::AcceptTransactionFail::TransactionLimit(_))
    ));
    assert!(matches!(
        resource_contract_accept(over_cap, limits, &time),
        Err(crate::tx::AcceptTransactionFail::TransactionLimit(_))
    ));

    // Queue admission under the default committed parameters.
    let mut state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    install_single_validator_topology_for_queue_test(&mut state, 0xB7);
    register_accepted_tx_authority_for_queue_test(&mut state, &largest);
    assert_eq!(
        state
            .view()
            .world()
            .parameters()
            .max_includable_transaction_bytes(
                iroha_data_model::parameter::system::TransactionInclusionRoute::Global
            ),
        includable
    );
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let reserve = iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
    let smaller_block = reserve + u32::try_from(includable).unwrap() - 1;
    let mut smaller_state = resource_contract_state(smaller_block);
    register_accepted_tx_authority_for_queue_test(&mut smaller_state, &at_cap);
    let smaller_queue = Arc::new(Queue::test(config_factory(), &time));
    let failure = smaller_queue
        .push(at_cap, smaller_state.view())
        .expect_err("one byte above this route's includable bound takes no custody");
    let expected = iroha_data_model::parameter::system::TransactionNeverIncludable {
        encoded_bytes: cap,
        max_bytes: cap - 1,
    }
    .to_string();
    assert!(
        matches!(failure.err, Error::UnsupportedTransactionAdmission { ref reason } if reason == &expected)
    );
    assert_eq!(smaller_queue.active_len(), 0);
    assert_eq!(queue.active_len(), 0);
    queue
        .push(largest.clone(), state.view())
        .expect("the largest includable transaction is admitted");
    // A cap-sized proposal budget selects the full accepted transaction.
    let budget = usize::try_from(includable).unwrap();
    let selected = crate::sumeragi::payload::select(&state, &queue, budget, 0).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].hash_as_entrypoint(),
        largest.hash_as_entrypoint()
    );
    assert_eq!(selected[0].encoded_len(), budget);
}

/// Admission state whose includable assessment is one fixed local refusal. Every later
/// admission step panics: a deferred assessment ends admission before any custody is taken.
struct DeferredInclusionAccess(Option<crate::execution_attempt::ExecutionDeferred>);

impl QueueAdmissionStateAccess for DeferredInclusionAccess {
    fn authority_exists(&mut self, _authority: &AccountId) -> bool {
        panic!("admission continued after a deferred includable assessment")
    }
    fn verification_gas(&mut self) -> iroha_config::parameters::actual::ConfidentialGas {
        panic!("admission continued after a deferred includable assessment")
    }
    fn check_includable_transaction(
        &mut self,
        _transaction: &AcceptedTransaction<'_>,
    ) -> Result<
        (),
        crate::execution_attempt::ExecutionAttemptError<
            iroha_data_model::parameter::system::TransactionNeverIncludable,
        >,
    > {
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
            self.0
                .take()
                .expect("one includable assessment transfers the original once"),
        ))
    }
    fn sccp_exempt_admission(
        &mut self,
        _transaction: &SignedTransaction,
    ) -> Result<Option<SccpAdmissionKeysV1>, SccpAdmissionRejectV1> {
        panic!("admission continued after a deferred includable assessment")
    }
    fn manifest_authority_eligible_lanes(
        &mut self,
        _lane_id: LaneId,
        _dataspace_id: DataSpaceId,
    ) -> BTreeSet<LaneId> {
        panic!("admission continued after a deferred includable assessment")
    }
    fn recheck_external_nexus_fee_admission(
        &mut self,
        _queue: &Queue,
        _tx: &AcceptedTransaction<'static>,
        _route_dataspace_id: Option<DataSpaceId>,
    ) -> Result<Option<FeeAdmissionReservation>, Error> {
        panic!("admission continued after a deferred includable assessment")
    }
    fn extract_lane_identity_metadata(
        &mut self,
        _authority: &AccountId,
        _dataspace_id: DataSpaceId,
        _lane_alias: &str,
    ) -> Result<(Option<UniversalAccountId>, Vec<String>), Error> {
        panic!("admission continued after a deferred includable assessment")
    }
    fn extract_lane_authority_domains(
        &mut self,
        _authority: &AccountId,
        _lane_alias: &str,
    ) -> Result<Vec<iroha_model_base::domain::DomainId>, Error> {
        panic!("admission continued after a deferred includable assessment")
    }
}

/// Queue admission maps a local refusal of the includable assessment to `Error::Deferred`
/// with the original refusal: it is not the permanent `UnsupportedTransactionAdmission`, no
/// later admission step runs and the queue retains nothing. The same transaction is admitted
/// once the assessment completes.
#[test]
fn deferred_includable_assessment_defers_queue_admission_without_custody() {
    let (_, time) = TimeSource::new_mock(Duration::default());
    let transaction = resource_contract_accept(
        resource_contract_signed_log(&time, 64),
        TransactionParameters::default(),
        &time,
    )
    .expect("accepted under the default cap");
    let mut state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    install_single_validator_topology_for_queue_test(&mut state, 0xB7);
    register_accepted_tx_authority_for_queue_test(&mut state, &transaction);
    let queue = Queue::test(config_factory(), &time);
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget
        .try_reserve_bytes(8)
        .expect("occupy the original pool");
    let original = budget
        .try_reserve_bytes(1)
        .expect_err("actual capacity refusal");
    let observation = original.clone();
    let plan = queue
        .route_plan_with_state(&transaction, &state)
        .expect("the fixture transaction has a route");
    {
        let view = state.view();
        let Err(failure) = queue.prepare_checked_for_enqueue(
            CheckedTransaction::new_unchecked(transaction.clone()),
            plan,
            &mut DeferredInclusionAccess(Some(original.into())),
            None,
            #[cfg(feature = "telemetry")]
            view.telemetry,
        ) else {
            panic!("a deferred assessment is not an admission");
        };
        drop(view);
        let Error::Deferred(reason) = failure.err else {
            panic!(
                "a deferred assessment is not a rejection: {:?}",
                failure.err
            );
        };
        assert_eq!(
            reason.allocation_refusal(),
            Some(&observation),
            "the original local refusal is retained"
        );
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(reason.decode_refusal().is_none());
        assert!(reason.verification_refusal().is_none());
        assert!(reason.phase().is_none());
        assert_eq!(
            failure.tx.hash_as_entrypoint(),
            transaction.hash_as_entrypoint(),
            "the caller keeps the transaction for its retry"
        );
    }
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.queued_len(), 0);
    assert_eq!(queue.retained_bytes(), 0);
    drop(occupied);
    assert!(budget.try_reserve_bytes(1).is_ok());
    queue
        .push(transaction, state.view())
        .expect("the completed assessment admits the same transaction");
    assert_eq!(queue.active_len(), 1);
}

/// A queue fixture whose chain commits `policy` and whose node installed `node`.
fn committed_zk_policy_state(
    policy: &iroha_data_model::zk_validity_policy::ZkValidityPolicyV1,
    node: Option<iroha_config::parameters::actual::Zk>,
) -> State {
    let world = world_with_test_domains();
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                policy.clone().into_custom_parameter(),
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let mut state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    if let Some(node) = node {
        state
            .install_node_zk(node)
            .expect("node ZK resources install");
    }
    state
}

/// Queue admission prices a proof-bearing instruction with the verification gas schedule of
/// the committed ZK validity policy its admission view holds: not with the protocol default,
/// and not with a schedule the node installed.
#[test]
fn queue_admission_prices_a_proof_instruction_with_the_committed_gas_schedule() {
    use iroha_data_model::{
        isi::zk::VerifyProof,
        proof::{ProofAttachment, VerifyingKeyId},
        zk_validity_policy::ZkValidityPolicyV1,
    };
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.gas.proof_base += 17;
    policy.gas.per_public_input += 5;
    policy.gas.per_proof_byte += 3;
    policy
        .validate()
        .expect("a policy that differs in gas is valid");
    let committed = iroha_config::parameters::actual::ConfidentialGas {
        proof_base: policy.gas.proof_base,
        per_public_input: policy.gas.per_public_input,
        per_proof_byte: policy.gas.per_proof_byte,
        per_nullifier: policy.gas.per_nullifier,
        per_commitment: policy.gas.per_commitment,
    };
    // A node that installed another schedule: admission must not read it.
    let mut divergent = crate::state::default_zk_config();
    divergent.gas.proof_base = 1;
    divergent.gas.per_proof_byte = 1_000;

    let fixture = crate::zk::test_utils::native_framing_fixture_envelope(
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        [0u8; 32],
    );
    let proof_box = fixture.proof_box("pipa-r/pasta");
    let attachment = ProofAttachment::new_ref(
        proof_box.backend.clone(),
        proof_box,
        VerifyingKeyId::new("pipa-r/pasta", "vk-queue-admission"),
    );
    let proof_bytes = attachment.proof.bytes.len() as u64;
    // The outer field identifies the schema; the native proof owns the public column.
    let envelope: iroha_data_model::zk::OpenVerifyEnvelope =
        norito::decode_canonical(&fixture.proof_bytes).expect("native outer frame");
    let proof: iroha_data_model::zk::NativePipaRProofV1 =
        norito::decode_canonical(&envelope.proof_bytes).expect("native public column");
    let public_inputs = proof.public_inputs.len() as u64;
    assert_eq!(public_inputs, 9);
    let instruction: InstructionBox = VerifyProof::new(attachment).into();
    let delta = 17 + 5 * public_inputs + 3 * proof_bytes;
    assert_eq!(
        gas::meter_instruction(&instruction, &committed).expect("completed proof gas quote")
            - gas::meter_instruction(&instruction, &gas::DEFAULT_ZK_GAS)
                .expect("completed proof gas quote"),
        delta
    );

    for node in [None, Some(divergent)] {
        let state = committed_zk_policy_state(&policy, node);
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let tx = accepted_tx_with(
            AccountId::new(ALICE_KEYPAIR.public_key().clone()),
            &ALICE_KEYPAIR,
            &time_source,
            vec![instruction.clone()],
            Metadata::default(),
        );
        let hash = tx.hash_as_entrypoint();
        let under_default = Queue::compute_proposal_gas_cost(&tx, &gas::DEFAULT_ZK_GAS)
            .expect("the default schedule prices the transaction");
        let under_committed = Queue::compute_proposal_gas_cost(&tx, &committed)
            .expect("the committed schedule prices the transaction");
        assert_eq!(under_committed - under_default, delta);
        queue
            .push(tx, state.view())
            .expect("the proof-bearing transaction is admitted");
        assert_eq!(
            *queue
                .tx_gas_cost
                .get(&hash)
                .expect("admission stored a cost"),
            under_committed,
            "admission priced the proof with the committed schedule"
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            queue.tx_teu.get(&hash).expect("admitted TEU").teu,
            under_committed,
            "telemetry uses the same admitted quote and never independently re-decodes"
        );
    }
    // A chain that commits no policy prices the same transaction with the protocol default.
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (_, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let tx = accepted_tx_with(
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        &ALICE_KEYPAIR,
        &time_source,
        vec![instruction],
        Metadata::default(),
    );
    let hash = tx.hash_as_entrypoint();
    let under_default = Queue::compute_proposal_gas_cost(&tx, &gas::DEFAULT_ZK_GAS)
        .expect("the default schedule prices the transaction");
    queue.push(tx, state.view()).expect("admitted");
    assert_eq!(
        *queue.tx_gas_cost.get(&hash).expect("stored"),
        under_default
    );
}

#[test]
fn proposal_gas_quote_preserves_actual_canonical_refusal_and_retries_original_transaction() {
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_data_model::{
        isi::zk::VerifyProof,
        proof::{ProofAttachment, VerifyingKeyId},
    };
    let fixture = crate::zk::test_utils::native_framing_fixture_envelope(
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        [0; 32],
    );
    let proof = fixture.proof_box("pipa-r/pasta");
    let instruction: InstructionBox = VerifyProof::new(ProofAttachment::new_ref(
        proof.backend.clone(),
        proof,
        VerifyingKeyId::new("pipa-r/pasta", "quote-owner"),
    ))
    .into();
    let (_, time) = TimeSource::new_mock(Duration::default());
    let transaction = accepted_tx_with(
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        &ALICE_KEYPAIR,
        &time,
        vec![instruction],
        Metadata::default(),
    );
    let source = transaction.entrypoint_bytes();
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || Queue::compute_proposal_gas_cost(&transaction, &gas::DEFAULT_ZK_GAS),
    )
    .unwrap_err();
    let ExecutionAttemptError::Deferred(original) = refused else {
        panic!("an unfinished quote cannot reject signed gas metadata");
    };
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(original.verification_refusal().is_some());
    assert!(original.decode_refusal().is_some());
    assert!(original.allocation_refusal().is_none());
    let observation = original.decode_refusal().cloned();
    let returned =
        crate::execution_attempt::ExecutionDeferred::try_from_vm_error(original.into_vm_error())
            .unwrap();
    assert_eq!(returned.decode_refusal(), observation.as_ref());
    assert!(Queue::compute_proposal_gas_cost(&transaction, &gas::DEFAULT_ZK_GAS).unwrap() > 0);
    assert_eq!(source.as_slice(), transaction.entrypoint_bytes().as_slice());
}

#[cfg(feature = "telemetry")]
#[test]
fn route_refresh_keeps_admitted_quote_and_missing_cache_faults_before_teu_publication() {
    use iroha_data_model::zk_validity_policy::ZkValidityPolicyV1;
    let policy = ZkValidityPolicyV1::protocol_default();
    let state = committed_zk_policy_state(&policy, None);
    let (_, time) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let fixture = crate::zk::test_utils::native_framing_fixture_envelope(
        crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        [0; 32],
    );
    let proof = fixture.proof_box("pipa-r/pasta");
    let instruction: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(
        iroha_data_model::proof::ProofAttachment::new_ref(
            proof.backend.clone(),
            proof,
            iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "route-quote"),
        ),
    )
    .into();
    let transaction = accepted_tx_with(
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        &ALICE_KEYPAIR,
        &time,
        vec![instruction],
        Metadata::default(),
    );
    let hash = transaction.hash_as_entrypoint();
    queue.push(transaction.clone(), state.view()).unwrap();
    let admitted = queue.admitted_proposal_gas_cost(&hash).unwrap();
    assert_eq!(queue.tx_teu.get(&hash).unwrap().teu, admitted);
    let mut changed_policy = policy;
    changed_policy.gas.proof_base += 37;
    let changed_state = committed_zk_policy_state(&changed_policy, None);
    let view = changed_state.view();
    assert!(
        Queue::compute_proposal_gas_cost(&transaction, &view.zk.gas).unwrap() > admitted,
        "the new committed schedule would reprice this proof if the refresh decoded it again"
    );
    let router = queue.router.read().clone();
    queue.revalidate_pending_transactions(
        &router,
        &view,
        &view.nexus.lane_catalog,
        &view.nexus.dataspace_catalog,
        true,
    );
    assert_eq!(queue.admitted_proposal_gas_cost(&hash).unwrap(), admitted);
    assert_eq!(queue.tx_teu.get(&hash).unwrap().teu, admitted);
    assert!(!queue.accepted_work_validation_faulted());
    let before_plan = queue.routing_plans.get(&hash).unwrap().clone();
    let before_teu = *queue.tx_teu.get(&hash).unwrap();
    queue.tx_gas_cost.remove(&hash);
    let invariant = queue.admitted_proposal_gas_cost(&hash).unwrap_err();
    assert_eq!(
        invariant.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    queue.revalidate_pending_transactions(
        &router,
        &view,
        &view.nexus.lane_catalog,
        &view.nexus.dataspace_catalog,
        true,
    );
    assert!(queue.accepted_work_validation_faulted());
    assert_eq!(
        queue.routing_plans.get(&hash).unwrap().value(),
        &before_plan
    );
    let after_teu = *queue.tx_teu.get(&hash).unwrap();
    assert_eq!(
        (after_teu.lane_id, after_teu.dataspace_id, after_teu.teu),
        (before_teu.lane_id, before_teu.dataspace_id, before_teu.teu)
    );
    assert_eq!(
        queue.active_len(),
        1,
        "an internal fault cannot evict accepted original work"
    );
}
