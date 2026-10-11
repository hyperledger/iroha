//! Genuine generated funding composition with exact child wallets and original native carriers.
//! The component serves real fee/query HTTP and commits one original per carrier directly. It
//! does not qualify the complete HTTP bootstrap, Queue, live peers or service readiness. Parent
//! selections and child preparation are exposed only through purpose-local cfg(test) helpers.
use super::tests::{fixture, options};
use super::*;
use crate::managed::native_operation::{Terms, now_ms};
use crate::managed::{
    native_operation::{
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions},
        },
        verify_carrier,
    },
    reserve_top_up::native_tests::registered_native,
};
use iroha_core::state::State;
use iroha_data_model::{
    asset::AssetId,
    isi::sorafs::RequestSorafsReserveMovement,
    sorafs::reserve::{ReserveMovementKindV1, account_proof::ReserveAccountProofExpectedV1},
    transaction::SignedTransaction,
};
use iroha_primitives::numeric::{Quantity, XorQuantity};
use std::{sync::Arc, time::Duration};

fn current(
    native: &NativeFixture,
    owner: &ProviderFundingBootstrap,
    policy: &ReserveAuthorityPolicyV1,
    verifier: &FinalityVerifier,
) -> VerifiedReserveAccountStateV1 {
    let operator = owner.authority.issuer_operator_config().unwrap();
    let chain = owner.authority.config.chain.to_string();
    native
        .account_proof(
            &policy.operations_authority,
            owner.authority.provider_id().unwrap(),
        )
        .verify(
            &ReserveAccountProofExpectedV1 {
                chain: &chain,
                network_id: owner.authority.config.network_id,
                operator: &policy.operations_authority,
                provider_id: owner.authority.provider_id().unwrap(),
                owner: &operator.account,
                policy,
                schema: State::native_world_schema_hash_v1().unwrap(),
            },
            &verifier.verified_tip().unwrap(),
        )
        .unwrap()
}
fn commit(
    native: &mut NativeFixture,
    owner: &ProviderFundingBootstrap,
    signed: &SignedTransaction,
    height: u64,
) -> FinalityVerifier {
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let verifier = native.observe(&owner.authority);
    let tip = verifier.verified_tip().unwrap();
    assert_eq!(tip.height(), height);
    assert_eq!(tip.block().network_entrypoint_count(), 1);
    assert_eq!(
        tip.block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        signed.encode_wire_v1().unwrap()
    );
    assert_eq!(verify_carrier(&verifier, signed).unwrap().height, height);
    verifier
}
fn maximum(http: &NativeReadHttp) -> Quantity {
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    assert_eq!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path == "/v1/fees/quote")
            .count(),
        1
    );
    quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            sum.checked_add(&component.max_amount).unwrap()
        })
}
fn unprepared(report: ProviderFundingProgress, expected: FundingStep, status: OperationStatus) {
    match report {
        ProviderFundingProgress::Unprepared {
            step,
            status: actual,
        } => {
            assert_eq!(step, expected);
            assert_eq!(actual, status)
        }
        _ => panic!("expected original unprepared stage"),
    }
}
fn registered(
    prepared: &PreparedLocalnet,
    owner: &ProviderFundingBootstrap,
) -> (NativeFixture, ReserveAuthorityPolicyV1, FinalityVerifier) {
    let request =
        ManagedReserveTopUpRequest::open(prepared, owner.authority.provider_id().unwrap()).unwrap();
    let manager = owner.authority.config.clone();
    let operator = owner.authority.issuer_operator_config().unwrap();
    let (native, policy, _, verifier, _) =
        registered_native(prepared, &request, &manager, &operator);
    (native, policy, verifier)
}

#[test]
fn automatic_original_amounts_drive_exact_paid_children_and_recover_each_crash_boundary() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, mut owner) = fixture();
    let (mut native, policy, h4) = registered(&prepared, &owner);
    let plan = owner.plan().unwrap();
    let mut opts = options();
    opts.deadline = Instant::now() + Duration::from_secs(600);
    opts.max_total_fees
        .insert(policy.asset_definition.clone(), Quantity::from(1_000u64));
    let at4 = current(&native, &owner, &policy, &h4);
    let original = Original::select(
        &plan,
        &policy,
        &at4,
        &h4,
        Fees::from_options(&opts).unwrap(),
    )
    .unwrap();
    owner.validate_original(&plan, &original).unwrap();
    assert_eq!(
        original.economics.top_up,
        "24".parse::<XorQuantity>().unwrap()
    );
    assert_eq!(
        original.economics.price_bond,
        "0.75".parse::<Quantity>().unwrap()
    );
    let utc = Terms::new(now_ms().unwrap() + 1_200_000, &opts)
        .unwrap()
        .signing_deadline_unix_ms;
    let opts = original.fees.options(opts.deadline);
    let directory = owner.authority.directory.ensure_child("funding").unwrap();
    original::publish(&directory, &plan, &original).unwrap();
    let bytes = std::fs::read(directory.path().join("economic-original.nrt")).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Request,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let manager = owner.authority.config.clone();
    let operator = owner.authority.issuer_operator_config().unwrap();
    let manager_asset = AssetId::new(policy.asset_definition.clone(), manager.account.clone());
    let operator_asset = AssetId::new(policy.asset_definition.clone(), operator.account.clone());
    let custody_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.custody_account.clone(),
    );
    let intent = original.top_up().unwrap();
    let request = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let signed_request = request
        .funding_prepare(&intent, utc, &opts, &at4, &h4)
        .unwrap();
    http.finish();
    let max = maximum(&http);
    let issuer_before = balance(native.chain.state(), &operator_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    let h5 = commit(&mut native, &owner, &signed_request, 5);
    let fee = issuer_before
        .checked_sub(&balance(native.chain.state(), &operator_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= max);
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    request.funding_retain(&h5, opts.deadline).unwrap();
    drop(request);
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Approval,
        OperationStatus::Absent,
    );
    let mut request = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let request_progress = request
        .recover_selected_if_present(&intent, &original.fees, opts.deadline)
        .unwrap()
        .unwrap();
    let history = request_progress.historical().unwrap().clone();
    assert_eq!(history.amount(), &original.economics.top_up);
    drop(request);
    // A different full original cannot adopt the existing manually named child journal.
    let mut wrong = intent.clone();
    wrong.amount = "25".parse().unwrap();
    let mut request = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    assert!(
        request
            .recover_selected_if_present(&wrong, &original.fees, opts.deadline)
            .is_err()
    );
    drop(request);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let at5 = current(&native, &owner, &policy, &h5);
    let approval_stage = SelectedStage::select(Stage::Approval, &original, &at5, &h5, 5).unwrap();
    owner
        .validate_stage(&approval_stage, Stage::Approval, &original, 5)
        .unwrap();
    stage::publish(&directory, Stage::Approval, &original, &approval_stage).unwrap();
    let approval_bytes = std::fs::read(directory.path().join("approval-selection.nrt")).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Approval,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let approval = ManagedReserveTopUpApproval::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let approval_intent = approval_stage.approval(&original).unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    let signed_approval = approval
        .funding_prepare(&history, &approval_intent, utc, &opts, &at5, &h5)
        .unwrap();
    http.finish();
    let max = maximum(&http);
    let issuer_before = balance(native.chain.state(), &operator_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    let h6 = commit(&mut native, &owner, &signed_approval, 6);
    assert_eq!(
        issuer_before
            .checked_sub(&balance(native.chain.state(), &operator_asset))
            .unwrap(),
        Quantity::from(24u64)
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        Quantity::from(24u64)
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= max);
    approval
        .funding_retain(&history, &h6, opts.deadline)
        .unwrap();
    drop(approval);
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Credit,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let at6 = current(&native, &owner, &policy, &h6);
    // A newly selected already-funded genuine cut takes the zero-principal branch without
    // manufacturing a Request/approval revision. These are selection checks, not a second run.
    let already_funded = Original::select(
        &plan,
        &policy,
        &at6,
        &h6,
        Fees::from_options(&opts).unwrap(),
    )
    .unwrap();
    assert!(already_funded.top_up().is_none());
    let zero_credit = SelectedStage::select(Stage::Credit, &already_funded, &at6, &h6, 6).unwrap();
    assert_eq!(zero_credit.partition, *at6.current().unwrap());
    assert_eq!(
        zero_credit.credit(&already_funded).unwrap().record.bonded,
        Quantity::from(24u64)
    );
    assert!(SelectedStage::select(Stage::Approval, &already_funded, &at6, &h6, 6).is_err());
    let credit_stage = SelectedStage::select(Stage::Credit, &original, &at6, &h6, 6).unwrap();
    stage::publish(&directory, Stage::Credit, &original, &credit_stage).unwrap();
    let credit_bytes = std::fs::read(directory.path().join("credit-selection.nrt")).unwrap();
    let credit_intent = credit_stage.credit(&original).unwrap();
    assert_eq!(credit_intent.record.bonded, Quantity::from(24u64));
    assert_eq!(
        credit_intent.record.onboarding_epoch,
        original.economics.onboarding_epoch
    );
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Credit,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let credit = ManagedInitialProviderCredit::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    let signed_credit = credit
        .funding_prepare(&credit_intent, utc, &opts, &at6, &h6)
        .unwrap();
    http.finish();
    let max = maximum(&http);
    let manager_before = balance(native.chain.state(), &manager_asset);
    let issuer_before = balance(native.chain.state(), &operator_asset);
    let h7 = commit(&mut native, &owner, &signed_credit, 7);
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= max);
    assert_eq!(
        balance(native.chain.state(), &operator_asset),
        issuer_before
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        Quantity::from(24u64)
    );
    credit.funding_retain(&h7, opts.deadline).unwrap();
    drop(credit);
    let mut peers = UnavailablePeers::start(&prepared);
    unprepared(
        owner.run(opts.deadline, Mode::Recover, None).unwrap(),
        FundingStep::Capacity,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let at7 = current(&native, &owner, &policy, &h7);
    assert_eq!(at7.credit(), Some(&credit_intent.record));
    let capacity = ManagedProviderCapacity::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    // The actual H7 cut is authenticated. Wrong parent intent cannot make the child silently
    // adopt that cut: reject before original publication, wallet preparation or any HTTP.
    let capacity_path = directory
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("provider-capacity-declaration/declare");
    let mut peers = UnavailablePeers::start(&prepared);
    for mismatch in 0..3 {
        let mut selected_partition = credit_stage.partition.clone();
        let mut selected_credit = credit_intent.record.clone();
        let floor = if mismatch == 2 { 8 } else { 7 };
        if mismatch == 0 {
            selected_partition = at5.current().unwrap().clone();
        } else if mismatch == 1 {
            selected_credit.available_credit = Quantity::zero();
        }
        let error = capacity
            .funding_retain_selected(
                &policy,
                &selected_partition,
                &selected_credit,
                floor,
                utc,
                &opts,
                &at7,
                &h7,
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "capacity original differs from automatic funding selection"
        );
        assert!(!capacity_path.join("original.nrt").exists());
        assert!(!capacity_path.join("attempts").exists());
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let signed_capacity = capacity
        .funding_prepare(
            &policy,
            &credit_stage.partition,
            &credit_intent.record,
            7,
            utc,
            &opts,
            &at7,
            &h7,
        )
        .unwrap();
    http.finish();
    let max = maximum(&http);
    let issuer_before = balance(native.chain.state(), &operator_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    let h8 = commit(&mut native, &owner, &signed_capacity, 8);
    let fee = issuer_before
        .checked_sub(&balance(native.chain.state(), &operator_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= max);
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        Quantity::from(24u64)
    );
    capacity.funding_retain(&h8, opts.deadline).unwrap();
    let at8 = current(&native, &owner, &policy, &h8);
    assert!(at8.capacity().is_some());
    assert_eq!(at8.current(), Some(&credit_stage.partition));
    assert_eq!(at8.credit(), Some(&credit_intent.record));
    let retained_capacity = std::fs::read(capacity_path.join("original.nrt")).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    let error = capacity
        .funding_retain_selected(
            &policy,
            &credit_stage.partition,
            &credit_intent.record,
            7,
            utc,
            &opts,
            &at8,
            &h8,
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "capacity original differs from automatic funding selection"
    );
    assert_eq!(
        std::fs::read(capacity_path.join("original.nrt")).unwrap(),
        retained_capacity
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    drop(capacity);
    // Even a later genuine request changing the current partition cannot rewrite original
    // completed economics or turn completion into a claim that current funding is unchanged.
    let later = quote_instructions(
        &native,
        &operator,
        [RequestSorafsReserveMovement::new(
            [0xE3; 32],
            plan.provider_id(),
            ReserveMovementKindV1::TopUp,
            "1".parse().unwrap(),
            credit_stage.partition.revision,
            policy.digest().unwrap(),
        )
        .into()],
    );
    let h9 = commit(&mut native, &owner, &later, 9);
    let changed = current(&native, &owner, &policy, &h9);
    assert!(SelectedStage::select(Stage::Credit, &original, &changed, &h9, 6).is_err());
    drop(owner);
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        let mut owner = ProviderFundingBootstrap::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let selected_options = original
            .fees
            .options(Instant::now() + Duration::from_secs(15));
        let mut changed = policy.clone();
        changed.grace_period_days += 1;
        assert!(
            owner
                .recover_selected_if_present(&changed, &original.fees, selected_options.deadline)
                .is_err()
        );
        let mut changed_fees = selected_options.clone();
        changed_fees
            .max_total_fees
            .insert(policy.asset_definition.clone(), Quantity::from(999u64));
        assert!(
            owner
                .recover_selected_if_present(
                    &policy,
                    &Fees::from_options(&changed_fees).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        let mut changed_options = original.fees.options(selected_options.deadline);
        changed_options.max_total_fees.clear();
        assert!(
            owner
                .recover_selected_if_present(
                    &policy,
                    &Fees::from_options(&changed_options).unwrap(),
                    changed_options.deadline
                )
                .is_err()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        for report in [
            owner
                .recover_selected_if_present(&policy, &original.fees, selected_options.deadline)
                .unwrap()
                .unwrap(),
            owner
                .run(
                    Instant::now() + Duration::from_secs(15),
                    Mode::Recover,
                    None,
                )
                .unwrap(),
            owner
                .recover_local_selected_if_present(
                    &policy,
                    &original.fees,
                    Instant::now() + Duration::from_secs(15),
                )
                .unwrap()
                .unwrap(),
        ] {
            let ProviderFundingProgress::Complete {
                request,
                approval,
                credit,
                capacity,
            } = report
            else {
                panic!("original completed economic operations")
            };
            assert_eq!(request.unwrap().movement_id(), original.movement_id);
            assert_eq!(approval.unwrap().original().height, 6);
            assert_eq!(credit.height, 7);
            assert_eq!(capacity.height, 8);
        }
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    peers.finish();
    assert_eq!(
        std::fs::read(directory.path().join("economic-original.nrt")).unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::read(directory.path().join("approval-selection.nrt")).unwrap(),
        approval_bytes
    );
    assert_eq!(
        std::fs::read(directory.path().join("credit-selection.nrt")).unwrap(),
        credit_bytes
    );
}

#[test]
fn genuine_economic_intent_never_authorizes_first_child_under_fresh_io_deadlines() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, owner) = fixture();
    let (native, policy, h4) = registered(&prepared, &owner);
    let plan = owner.plan().unwrap();
    let current = current(&native, &owner, &policy, &h4);
    let opts = options();
    let utc = now_ms().unwrap() + 500;
    let original = Original::select(
        &plan,
        &policy,
        &current,
        &h4,
        Fees::from_options(&opts).unwrap(),
    )
    .unwrap();
    let directory = owner.authority.directory.ensure_child("funding").unwrap();
    original::publish(&directory, &plan, &original).unwrap();
    let bytes = std::fs::read(directory.path().join("economic-original.nrt")).unwrap();
    let limit = Instant::now() + Duration::from_secs(2);
    while now_ms().unwrap() < utc {
        assert!(Instant::now() < limit);
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(owner);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut owner = ProviderFundingBootstrap::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    unprepared(
        owner
            .run(
                Instant::now() + Duration::from_secs(15),
                Mode::Recover,
                None,
            )
            .unwrap(),
        FundingStep::Request,
        OperationStatus::Absent,
    );
    assert!(
        owner
            .run(
                Instant::now() + Duration::from_secs(15),
                Mode::Advance,
                None
            )
            .is_err()
    );
    unprepared(
        owner
            .recover_local_selected_if_present(
                &policy,
                &original.fees,
                Instant::now() + Duration::from_secs(15),
            )
            .unwrap()
            .unwrap(),
        FundingStep::Request,
        OperationStatus::Absent,
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    assert_eq!(
        std::fs::read(directory.path().join("economic-original.nrt")).unwrap(),
        bytes
    );
    assert!(!directory.path().join("approval-selection.nrt").exists());
    assert!(!directory.path().join("credit-selection.nrt").exists());
    let request = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    drop(request);
    assert!(
        !owner
            .authority
            .directory
            .path()
            .parent()
            .unwrap()
            .join("reserve-top-up-request/request")
            .exists()
    );
}

#[test]
fn approval_tail_keeps_original_request_custody_and_restores_after_held_approval() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, mut owner) = fixture();
    let (mut native, policy, h4) = registered(&prepared, &owner);
    let plan = owner.plan().unwrap();
    let mut options = options();
    options
        .max_total_fees
        .insert(policy.asset_definition.clone(), Quantity::from(1_000u64));
    let at4 = current(&native, &owner, &policy, &h4);
    let original = Original::select(
        &plan,
        &policy,
        &at4,
        &h4,
        Fees::from_options(&options).unwrap(),
    )
    .unwrap();
    owner.validate_original(&plan, &original).unwrap();
    let directory = owner.authority.directory.ensure_child("funding").unwrap();
    original::publish(&directory, &plan, &original).unwrap();
    let provider = owner.authority.provider_id().unwrap();
    let intent = original.top_up().unwrap();
    let mut request = ManagedReserveTopUpRequest::open(&prepared, provider).unwrap();
    let operator = owner.authority.issuer_operator_config().unwrap();
    let options = original.fees.options(options.deadline);
    let utc = Terms::new(now_ms().unwrap() + 1_200_000, &options)
        .unwrap()
        .signing_deadline_unix_ms;
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let signed = request
        .funding_prepare(&intent, utc, &options, &at4, &h4)
        .unwrap();
    http.finish();
    let h5 = commit(&mut native, &owner, &signed, 5);
    request.funding_retain(&h5, options.deadline).unwrap();
    let report = request
        .recover_local_selected_if_present(&intent, &original.fees, options.deadline)
        .unwrap()
        .unwrap();
    let history = report.historical().unwrap();
    owner.validate_request(&original, history).unwrap();
    let request_path = directory
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("reserve-top-up-request/request");
    let request_bytes = std::fs::read(request_path.join("original.nrt")).unwrap();
    let phase = FundingPhase {
        directory: &directory,
        original: &original,
        provider,
        deadline: options.deadline,
        mode: Mode::Local,
        authorization: None,
    };
    let mut minimum_height = history.original().height;
    let mut approval_history = None;
    let mut peers = UnavailablePeers::start(&prepared);
    let absent = owner
        .run_approval(phase, &mut minimum_height, &mut approval_history, history)
        .unwrap()
        .unwrap();
    unprepared(
        absent.into_progress(),
        FundingStep::Approval,
        OperationStatus::Absent,
    );
    assert_eq!(minimum_height, 5);
    assert!(approval_history.is_none());
    assert_eq!(
        ManagedReserveTopUpRequest::open_existing(&prepared, provider)
            .err()
            .expect("original request owner remains held")
            .to_string(),
        "another managed native operation holds this generation"
    );

    let at5 = current(&native, &owner, &policy, &h5);
    let selection = SelectedStage::select(Stage::Approval, &original, &at5, &h5, 5).unwrap();
    owner
        .validate_stage(&selection, Stage::Approval, &original, 5)
        .unwrap();
    stage::publish(&directory, Stage::Approval, &original, &selection).unwrap();
    let selection_bytes = std::fs::read(directory.path().join("approval-selection.nrt")).unwrap();
    let approval = ManagedReserveTopUpApproval::open(&prepared, provider).unwrap();
    assert_eq!(
        owner
            .run_approval(phase, &mut minimum_height, &mut approval_history, history)
            .err()
            .expect("held approval purpose refuses")
            .to_string(),
        "another managed native operation holds this generation"
    );
    assert_eq!(minimum_height, 5);
    assert!(approval_history.is_none());
    assert!(ManagedReserveTopUpRequest::open_existing(&prepared, provider).is_err());
    drop(approval);
    let restored = owner
        .run_approval(phase, &mut minimum_height, &mut approval_history, history)
        .unwrap()
        .unwrap();
    unprepared(
        restored.into_progress(),
        FundingStep::Approval,
        OperationStatus::Absent,
    );
    assert_eq!(
        std::fs::read(request_path.join("original.nrt")).unwrap(),
        request_bytes
    );
    assert_eq!(
        std::fs::read(directory.path().join("approval-selection.nrt")).unwrap(),
        selection_bytes
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(request);

    let mut request_history = None;
    let incomplete = owner
        .run_request_approval(
            phase,
            &mut minimum_height,
            &mut request_history,
            &mut approval_history,
        )
        .unwrap()
        .unwrap();
    unprepared(
        incomplete.into_progress(),
        FundingStep::Approval,
        OperationStatus::Absent,
    );
    assert_eq!(
        request_history.unwrap().movement_id(),
        history.movement_id()
    );
    assert_eq!(minimum_height, 5);
    assert!(approval_history.is_none());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
