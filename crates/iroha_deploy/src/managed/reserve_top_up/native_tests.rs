//! Exact wallet top-up request execution over the shared generated-profile native fixture.
//!
//! The component commits original signed envelopes directly. It proves historical request
//! inclusion separately from current provider facts; it does not qualify Queue, complete
//! coordinator HTTP success, current movement status, approval, funding or service readiness.

use super::*;
use crate::managed::native_operation::test_support::{
    UnavailablePeers,
    native_fixture::{NativeFixture, NativeReadHttp, balance, policy, quote_instructions},
};
use iroha_core::{
    execution_attempt::ExecutionAttemptError, smartcontracts::ValidSingularQuery, state::State,
};
use iroha_data_model::{
    asset::AssetId,
    executor::ValidationFail,
    isi::{
        InstructionBox, Log,
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{RegisterSorafsReserveAccount, SetSorafsReservePolicy},
    },
    query::{
        asset::FindAssetById,
        error::{FindError, QueryExecutionFail},
    },
    sorafs::{
        pin_registry::StorageClass,
        reserve::{
            ReserveDuration, ReserveLifecycleStage, ReserveProviderTermsV1, ReserveTier,
            account_proof::ReserveAccountProofExpectedV1,
        },
    },
    transaction::{FeePaymentIntent, error::TransactionRejectionReason},
};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn assert_only_original(verifier: &FinalityVerifier, original: &SignedTransaction, height: u64) {
    let block = verifier.verified_tip().unwrap();
    assert_eq!(block.height(), height);
    assert_eq!(block.block().network_entrypoint_count(), 1);
    assert_eq!(
        block
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        original.encode_wire_v1().unwrap(),
        "one exact original envelope, with no hidden clock Log",
    );
}

fn assert_unfunded(state: &State, asset: &AssetId) {
    assert_eq!(
        FindAssetById::new(asset.clone())
            .execute(&state.view())
            .unwrap_err(),
        ExecutionAttemptError::Rejected(QueryExecutionFail::Find(FindError::Asset(Box::new(
            asset.clone()
        )))),
        "the generated non-signing reserve account remains unfunded",
    );
}

fn original(
    coordinator: &ManagedReserveTopUpRequest,
    intent: &ManagedReserveTopUpIntent,
    checkpoint: &FinalityVerifier,
) -> Original {
    let original = Original {
        selection: coordinator.selection(intent).unwrap(),
        policy: intent.policy.clone(),
        partition: intent.partition.clone(),
        movement_id: intent.movement_id,
        amount: intent.amount.clone(),
        checkpoint: checkpoint_bytes(checkpoint).unwrap(),
    };
    coordinator.validate_original(&original).unwrap();
    original
}

pub(in crate::managed) fn registered_native(
    prepared: &PreparedLocalnet,
    coordinator: &ManagedReserveTopUpRequest,
    manager: &iroha::config::Config,
    operator: &iroha::config::Config,
) -> (
    NativeFixture,
    ReserveAuthorityPolicyV1,
    ReserveProviderTermsV1,
    FinalityVerifier,
    SignedTransaction,
) {
    let mut native = NativeFixture::from_generated(prepared, &coordinator.authority);
    let log = quote_instructions(
        &native,
        manager,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "native top-up prerequisite".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log.clone()]), vec![true]);
    assert_only_original(&native.observe(&coordinator.authority), &log, 2);

    let policy = policy(&coordinator.authority);
    let set = quote_instructions(
        &native,
        manager,
        [SetSorafsReservePolicy::new(policy.clone()).into()],
    );
    assert_eq!(native.chain.commit(vec![set.clone()]), vec![true]);
    assert_only_original(&native.observe(&coordinator.authority), &set, 3);
    let terms = ReserveProviderTermsV1 {
        provider_id: coordinator.authority.provider_id().unwrap(),
        provider_account: operator.account.clone(),
        tier: ReserveTier::TierA,
        storage_class: StorageClass::Hot,
        duration: ReserveDuration::Monthly,
        capacity_gib: 1,
    };
    let register = quote_instructions(
        &native,
        &coordinator.authority.reserve_operations_config().unwrap(),
        [RegisterSorafsReserveAccount::new(terms.clone(), policy.digest().unwrap()).into()],
    );
    assert_eq!(native.chain.commit(vec![register.clone()]), vec![true]);
    let registered = native.observe(&coordinator.authority);
    assert_only_original(&registered, &register, 4);
    assert_eq!(verify_carrier(&registered, &register).unwrap().height, 4);
    (native, policy, terms, registered, register)
}

/// Genuine request-owner component fixture for sibling managed approval tests.
/// The opaque history is minted only by the unchanged private original-carrier verifier.
/// Its original wallet wire is committed directly; this does not qualify Queue or full HTTP flow.
pub(in crate::managed) struct NativeRequestedTopUp {
    pub(in crate::managed) native: NativeFixture,
    pub(in crate::managed) policy: ReserveAuthorityPolicyV1,
    pub(in crate::managed) history: ManagedHistoricalReserveTopUp,
    pub(in crate::managed) signed: SignedTransaction,
}

/// Execute generated Set/Register and the exact wallet-prepared TopUp before exporting history.
/// The caller owns the ordinary native test guard and releases the reserved loopback ports first.
pub(in crate::managed) fn native_requested_top_up(
    prepared: &PreparedLocalnet,
    provider: ProviderId,
) -> NativeRequestedTopUp {
    let mut coordinator = ManagedReserveTopUpRequest::open(prepared, provider).unwrap();
    let manager = coordinator.authority.config.clone();
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    assert_ne!(manager.account, operator.account);
    let (mut native, policy, terms, registered, _) =
        registered_native(prepared, &coordinator, &manager, &operator);
    let chain = manager.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: manager.network_id,
        operator: &policy.operations_authority,
        provider_id: terms.provider_id,
        owner: &operator.account,
        policy: &policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    let current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &registered.verified_tip().unwrap())
        .unwrap();
    let intent = ManagedReserveTopUpIntent {
        policy: policy.clone(),
        partition: current.current().unwrap().clone(),
        expected_provider_revision: 1,
        movement_id: [0x61; 32],
        amount: XorQuantity::try_from_micro(1_000_000).unwrap(),
    };
    assert_eq!(intent.partition.revision, 1);
    assert_eq!(intent.partition.pending_movements, 0);
    assert!(intent.partition.reserve_balance.is_zero());
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    let retained = original(&coordinator, &intent, &registered);
    let directory = coordinator
        .authority
        .directory
        .ensure_child("request")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let transaction_path = retained.directory().path().join("transaction");
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    AccountService::new(operator.clone())
        .unwrap()
        .prepare_reserve_top_up(
            &retained.request(retained.terms.signing_deadline(options.deadline).unwrap()),
            &transaction_path,
        )
        .unwrap();
    let requests_before = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(retained.directory(), &retained, options.deadline)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), requests_before);
    http.finish();
    let partial_request = retained.request(options.deadline);
    let partial_account = &AccountService::new(operator.clone()).unwrap();
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &transaction_path,
        || {
            partial_account
                .inspect_reserve_top_up_preparation(&transaction_path, &partial_request)
                .unwrap()
        },
        |advance| {
            coordinator
                .advance_original(
                    options.deadline,
                    if advance {
                        Advance::SubmitOriginal
                    } else {
                        Advance::ObserveOnly
                    },
                    false,
                )
                .map(|value| {
                    assert!(value.finalized.is_none() && value.current.is_none());
                    value.transaction_status
                })
        },
        || {
            partial_account
                .prepare_reserve_top_up(&partial_request, &transaction_path)
                .unwrap();
        },
    );
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    let maximum_fee = quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(component.asset_definition_id, policy.asset_definition);
            sum.checked_add(&component.max_amount).unwrap()
        });
    assert_eq!(signed.authority(), &operator.account);
    let operator_asset = AssetId::new(policy.asset_definition.clone(), operator.account.clone());
    let manager_asset = AssetId::new(policy.asset_definition.clone(), manager.account.clone());
    let custody_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.custody_account.clone(),
    );
    let operator_before = balance(native.chain.state(), &operator_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let fee = operator_before
        .checked_sub(&balance(native.chain.state(), &operator_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum_fee);
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    assert_unfunded(native.chain.state(), &custody_asset);
    assert!(!transaction_path.join("submission.json").exists());
    let committed = native.observe(&coordinator.authority);
    assert_only_original(&committed, &signed, 5);
    let history = coordinator
        .historical_binding(&retained, &signed, &committed)
        .unwrap();
    assert_eq!(
        history.original(),
        &verify_carrier(&committed, &signed).unwrap()
    );
    assert_eq!(history.movement_id(), intent.movement_id);
    assert_eq!(history.amount(), &intent.amount);
    assert_eq!(history.requested_provider_revision(), 1);
    let current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &committed.verified_tip().unwrap())
        .unwrap();
    assert_eq!(current.current().unwrap().revision, 2);
    assert_eq!(current.current().unwrap().pending_movements, 1);
    assert!(current.current().unwrap().reserve_balance.is_zero());
    retained
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&committed).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    NativeRequestedTopUp {
        native,
        policy,
        history,
        signed,
    }
}

#[test]
fn generated_native_top_up_binds_only_exact_successful_original_request() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-reserve-top-up",
        &temporary.path().join("generation"),
        &ports,
    )
    .unwrap();
    let mut coordinator = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let manager = coordinator.authority.config.clone();
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    assert_ne!(manager.account, operator.account);
    assert_eq!(
        &operator.account,
        coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
    );
    assert_eq!(
        operator.account.try_signatory(),
        Some(operator.key_pair.public_key())
    );
    let (mut native, policy, terms, registered, register) =
        registered_native(&prepared, &coordinator, &manager, &operator);
    let chain = manager.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: manager.network_id,
        operator: &policy.operations_authority,
        provider_id: terms.provider_id,
        owner: &operator.account,
        policy: &policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    let pre_current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &registered.verified_tip().unwrap())
        .unwrap();
    let partition = pre_current.current().unwrap().clone();
    assert_eq!(partition.terms, terms);
    assert_eq!(partition.revision, 1);
    assert_eq!(partition.pending_movements, 0);
    assert!(partition.reserve_balance.is_zero());
    let intent = ManagedReserveTopUpIntent {
        policy: policy.clone(),
        partition,
        expected_provider_revision: 1,
        movement_id: [0x41; 32],
        amount: XorQuantity::try_from_micro(1_000_000).unwrap(),
    };
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    let retained = original(&coordinator, &intent, &registered);
    let directory = coordinator
        .authority
        .directory
        .ensure_child("request")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 96 * 1024)
        .unwrap();
    let transaction_path = retained.directory().path().join("transaction");
    drop(ports);

    // The checkpoint/partition are genuine. An unavailable predecessor cannot cause preparation.
    let mut unavailable = UnavailablePeers::start(&prepared);
    let recovered = coordinator
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Absent);
    assert!(
        recovered.historical().is_none()
            && recovered.finalized.is_none()
            && recovered.current.is_none()
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let refusal = coordinator
        .advance(Instant::now() + Duration::from_secs(30))
        .unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("fresh exact reserve predecessor unavailable"),
        "{refusal}"
    );
    assert!(
        !transaction_path.join("payload.json").exists()
            && !transaction_path.join("operation.json").exists()
    );
    assert_eq!(
        directory
            .read("original.nrt", original_bytes.len())
            .unwrap()
            .as_slice(),
        original_bytes.as_slice()
    );
    unavailable.finish();
    assert!(!unavailable.requests.lock().unwrap().is_empty());
    assert!(
        unavailable
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"
                && matches!(
                    request.path.as_str(),
                    "/v1/node/capabilities" | "/v1/bridge/finality/1"
                ))
    );

    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let wallet = AccountService::new(operator.clone()).unwrap();
    wallet
        .prepare_reserve_top_up(
            &retained.request(retained.terms.signing_deadline(options.deadline).unwrap()),
            &transaction_path,
        )
        .unwrap();
    let requests_before = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(retained.directory(), &retained, options.deadline)
        .unwrap();
    assert_eq!(
        http.requests.lock().unwrap().len(),
        requests_before,
        "journal verification stays offline"
    );
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &operator.account);
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("one native instruction")
    };
    assert_eq!(instructions.len(), 1);
    let request = instructions[0]
        .as_any()
        .downcast_ref::<RequestSorafsReserveMovement>()
        .unwrap();
    assert_eq!(request.kind, ReserveMovementKindV1::TopUp);
    assert_eq!(request.movement_id, intent.movement_id);
    assert_eq!(request.provider_id, terms.provider_id);
    assert_eq!(request.amount, intent.amount);
    assert_eq!(request.expected_provider_revision, 1);
    assert_eq!(request.policy_digest, policy.digest().unwrap());
    http.finish();
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
    assert!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, path)| path == "/v1/query")
    );
    let maximum_fee = quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(component.asset_definition_id, policy.asset_definition);
            sum.checked_add(&component.max_amount).unwrap()
        });
    let operator_asset = AssetId::new(policy.asset_definition.clone(), operator.account.clone());
    let manager_asset = AssetId::new(policy.asset_definition.clone(), manager.account.clone());
    let custody_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.custody_account.clone(),
    );
    let treasury_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.treasury_account.clone(),
    );
    let issuer_before = balance(native.chain.state(), &operator_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_unfunded(native.chain.state(), &treasury_asset);
    let wire = signed.encode_wire_v1().unwrap();
    let wallet_bytes = std::fs::read(transaction_path.join("operation.json")).unwrap();
    assert!(!transaction_path.join("submission.json").exists());
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let debit = issuer_before
        .checked_sub(&balance(native.chain.state(), &operator_asset))
        .unwrap();
    assert!(
        !debit.is_zero() && debit <= maximum_fee,
        "the original issuer pays only the actual native fee"
    );
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_unfunded(native.chain.state(), &treasury_asset);
    let committed = native.observe(&coordinator.authority);
    assert_only_original(&committed, &signed, 5);
    let historical = coordinator
        .historical_binding(&retained, &signed, &committed)
        .unwrap();
    assert_eq!(
        historical.original(),
        &verify_carrier(&committed, &signed).unwrap()
    );
    assert_eq!(historical.network_id(), operator.network_id);
    assert_eq!(historical.provider_id(), terms.provider_id);
    assert_eq!(historical.provider_account(), &operator.account);
    assert_eq!(historical.movement_id(), intent.movement_id);
    assert_eq!(historical.amount(), &intent.amount);
    assert_eq!(historical.requested_provider_revision(), 1);
    assert_eq!(historical.policy_digest(), policy.digest().unwrap());

    let current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &committed.verified_tip().unwrap())
        .unwrap();
    let after_request = current.current().unwrap().clone();
    assert_eq!(after_request.revision, 2);
    assert_eq!(
        after_request.pending_movements, 1,
        "a provider counter is separate from current movement status"
    );
    assert!(
        after_request.reserve_balance.is_zero()
            && after_request.debt_principal.is_zero()
            && after_request.accrued_interest.is_zero()
    );
    assert_eq!(
        after_request.lifecycle_stage,
        ReserveLifecycleStage::Warning
    );
    let stale_current = progress(
        OperationStatus::Applied,
        Some(historical.clone()),
        Some(pre_current),
    );
    assert!(stale_current.historical().is_some());
    assert!(
        stale_current.current.is_none(),
        "H4 cannot describe current state after an H5 request"
    );
    let mut current_only = progress(OperationStatus::Applied, None, Some(current));
    current_only.finalized = Some(*historical.original());
    assert!(
        current_only.historical().is_none(),
        "even a copied genuine public report cannot mint the private binding"
    );
    assert!(current_only.current.unwrap().current().is_some());

    assert!(
        coordinator
            .historical_binding(&retained, &signed, &registered)
            .is_err()
    );
    assert!(
        coordinator
            .historical_binding(&retained, &register, &committed)
            .is_err()
    );
    let mut after_origin = retained.clone();
    after_origin.checkpoint = checkpoint_bytes(&committed).unwrap();
    assert!(
        coordinator
            .historical_binding(&after_origin, &signed, &committed)
            .unwrap_err()
            .to_string()
            .contains("predates original intent")
    );
    let mut wrong_amount = retained.clone();
    wrong_amount.amount = XorQuantity::try_from_micro(2_000_000).unwrap();
    coordinator.validate_original(&wrong_amount).unwrap();
    assert!(
        coordinator
            .historical_binding(&wrong_amount, &signed, &committed)
            .unwrap_err()
            .to_string()
            .contains("differs from original top-up intent")
    );
    let mut wrong_provider = retained.clone();
    wrong_provider.selection.provider_id = ProviderId::new([0x82; 32]);
    wrong_provider.partition.terms.provider_id = wrong_provider.selection.provider_id;
    assert!(
        coordinator
            .historical_binding(&wrong_provider, &signed, &committed)
            .unwrap_err()
            .to_string()
            .contains("original generated provider or roles")
    );
    let different_wire = quote_instructions(
        &native,
        &operator,
        [RequestSorafsReserveMovement::new(
            [0x83; 32],
            terms.provider_id,
            ReserveMovementKindV1::TopUp,
            intent.amount.clone(),
            1,
            policy.digest().unwrap(),
        )
        .into()],
    );
    assert_ne!(different_wire.encode_wire_v1().unwrap(), wire);
    assert!(
        coordinator
            .historical_binding(&retained, &different_wire, &committed)
            .is_err()
    );
    let carrier_bytes = checkpoint_bytes(&committed).unwrap();
    retained
        .directory()
        .write_atomic("carrier.nrt", &carrier_bytes, PublishMode::CreateNew)
        .unwrap();
    let stored = coordinator
        .retained_historical(retained.directory(), &retained, &signed)
        .unwrap()
        .unwrap();
    assert_eq!(stored.original(), historical.original());

    // A second exact wallet envelope retains the real H4 partition CAS. It now fails natively,
    // not merely because its signature/wire differs from a successful carrier.
    let failed_intent = ManagedReserveTopUpIntent {
        movement_id: [0x42; 32],
        ..intent.clone()
    };
    let failed_original = original(&coordinator, &failed_intent, &registered);
    let failed_directory = coordinator
        .authority
        .directory
        .ensure_child("failed-control")
        .unwrap();
    let failed_original = super::tests::retain_explicit_request(
        &coordinator,
        &failed_directory,
        &failed_original,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let failed_path = failed_original.directory().path().join("transaction");
    let mut failed_http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    wallet
        .prepare_reserve_top_up(
            &failed_original.request(
                failed_original
                    .terms
                    .signing_deadline(options.deadline)
                    .unwrap(),
            ),
            &failed_path,
        )
        .unwrap();
    let failed = coordinator
        .verify_wallet(
            failed_original.directory(),
            &failed_original,
            options.deadline,
        )
        .unwrap();
    failed_http.finish();
    assert_eq!(native.chain.commit(vec![failed.clone()]), vec![false]);
    let refused = native.observe(&coordinator.authority);
    assert_only_original(&refused, &failed, 6);
    let block = refused.verified_tip().unwrap();
    assert_eq!(
        block
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .as_ref()
            .unwrap_err(),
        &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "reserve provider revision conflict: expected 1, current 2".into(),
            )),
        )),
    );
    assert!(verify_carrier(&refused, &failed).is_err());
    assert!(
        coordinator
            .historical_binding(&failed_original, &failed, &refused)
            .is_err()
    );
    let refused_current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &refused.verified_tip().unwrap())
        .unwrap();
    assert_eq!(refused_current.current().unwrap(), &after_request);
    assert!(!failed_path.join("submission.json").exists());

    // The closed wallet cannot plan Withdrawal. A genuine separately signed successful native
    // Withdrawal request proves the historical constructor still enforces the TopUp purpose.
    let withdrawal_intent = ManagedReserveTopUpIntent {
        partition: refused_current.current().unwrap().clone(),
        expected_provider_revision: 2,
        movement_id: [0x43; 32],
        ..intent.clone()
    };
    let withdrawal_original = original(&coordinator, &withdrawal_intent, &refused);
    let withdrawal = quote_instructions(
        &native,
        &operator,
        [RequestSorafsReserveMovement::new(
            withdrawal_intent.movement_id,
            terms.provider_id,
            ReserveMovementKindV1::Withdrawal,
            withdrawal_intent.amount.clone(),
            2,
            policy.digest().unwrap(),
        )
        .into()],
    );
    assert_eq!(native.chain.commit(vec![withdrawal.clone()]), vec![true]);
    let wrong_kind = native.observe(&coordinator.authority);
    assert_only_original(&wrong_kind, &withdrawal, 7);
    assert!(verify_carrier(&wrong_kind, &withdrawal).is_ok());
    assert!(
        coordinator
            .historical_binding(&withdrawal_original, &withdrawal, &wrong_kind)
            .unwrap_err()
            .to_string()
            .contains("differs from original top-up intent")
    );
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_unfunded(native.chain.state(), &treasury_asset);
    assert_eq!(coordinator.authority.config.account, manager.account);
    assert!(
        coordinator
            .authority
            .peers
            .iter()
            .all(|(_, client)| client.to_builder().account == manager.account)
    );

    drop(wallet);
    drop(failed_directory);
    drop(directory);
    drop(coordinator);
    let mut outage = UnavailablePeers::start(&prepared);
    let mut reopened = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    crate::managed::native_operation::test_support::assert_optional_current(
        &outage,
        &committed,
        |verifier| {
            reopened.read_current(&policy, verifier, Instant::now() + Duration::from_secs(30))
        },
    );
    let recovered = reopened
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(
        recovered.historical().unwrap().original(),
        historical.original()
    );
    assert_eq!(
        recovered.historical().unwrap().movement_id(),
        historical.movement_id()
    );
    assert_eq!(
        recovered.historical().unwrap().amount(),
        historical.amount()
    );
    assert!(
        recovered.current.is_none(),
        "outage is not current movement or reserve evidence"
    );
    let directory = reopened.authority.directory.open_child("request").unwrap();
    assert_eq!(
        directory
            .read("original.nrt", original_bytes.len())
            .unwrap()
            .as_slice(),
        original_bytes.as_slice()
    );
    assert_eq!(
        retained
            .directory()
            .read("carrier.nrt", carrier_bytes.len())
            .unwrap()
            .as_slice(),
        carrier_bytes.as_slice()
    );
    assert_eq!(
        std::fs::read(transaction_path.join("operation.json")).unwrap(),
        wallet_bytes
    );
    assert_eq!(
        reopened
            .verify_wallet(
                retained.directory(),
                &retained,
                Instant::now() + Duration::from_secs(30)
            )
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert!(!transaction_path.join("submission.json").exists());
    outage.finish();
    assert!(
        outage
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"
                && matches!(
                    request.path.as_str(),
                    "/v1/node/capabilities" | "/v1/bridge/finality/1"
                ))
    );
}

#[test]
fn genuinely_expired_unprepared_top_up_recovers_without_http_or_new_authorization() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-expired-top-up",
        &temporary.path().join("generation"),
        &ports,
    )
    .unwrap();
    let mut coordinator = ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let manager = coordinator.authority.config.clone();
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    let (native, policy, terms, registered, _) =
        registered_native(&prepared, &coordinator, &manager, &operator);
    let chain = manager.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: manager.network_id,
        operator: &policy.operations_authority,
        provider_id: terms.provider_id,
        owner: &operator.account,
        policy: &policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    let current = native
        .account_proof(&policy.operations_authority, terms.provider_id)
        .verify(&expected, &registered.verified_tip().unwrap())
        .unwrap();
    let intent = ManagedReserveTopUpIntent {
        policy: policy.clone(),
        partition: current.current().unwrap().clone(),
        expected_provider_revision: 1,
        movement_id: [0x51; 32],
        amount: XorQuantity::try_from_micro(1_000_000).unwrap(),
    };
    let selection = coordinator.selection(&intent).unwrap();
    let checkpoint = checkpoint_bytes(&registered).unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    // Create a genuinely future finite authorization through the production owner. Let real
    // time expire it; neither its retained fields nor native checkpoint/timestamps are changed.
    let retained = Original {
        selection,
        policy,
        partition: intent.partition,
        movement_id: intent.movement_id,
        amount: intent.amount,
        checkpoint,
    };
    coordinator.validate_original(&retained).unwrap();
    let directory = coordinator
        .authority
        .directory
        .ensure_child("request")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 500,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 96 * 1024)
        .unwrap();
    let retained_names = [
        "authorization.nrt",
        "observation.nrt",
        "committed.nrt",
        "transaction/preparation.json",
    ];
    let request_only_bytes =
        retained_names.map(|name| std::fs::read(retained.directory().path().join(name)).unwrap());
    let wait_until = Instant::now() + Duration::from_secs(2);
    while now_ms().unwrap() < retained.terms.signing_deadline_unix_ms {
        assert!(
            Instant::now() < wait_until,
            "finite real UTC expiry did not arrive"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(ports);
    let mut unavailable = UnavailablePeers::start(&prepared);
    for submit in [false, true] {
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = if submit {
            coordinator.advance(deadline)
        } else {
            coordinator.recover(deadline)
        }
        .unwrap();
        assert_eq!(result.transaction_status, OperationStatus::Expired);
        assert_eq!(
            retained_names
                .map(|name| { std::fs::read(retained.directory().path().join(name)).unwrap() }),
            request_only_bytes,
            "expired recovery preserves the exact committed request-only epoch"
        );

        assert!(
            result.historical().is_none() && result.finalized.is_none() && result.current.is_none()
        );
        assert!(
            !retained
                .directory()
                .path()
                .join("transaction/payload.json")
                .exists()
                && !retained
                    .directory()
                    .path()
                    .join("transaction/operation.json")
                    .exists()
        );
        assert_eq!(
            directory
                .read("original.nrt", original_bytes.len())
                .unwrap()
                .as_slice(),
            original_bytes.as_slice()
        );
    }
    unavailable.finish();
    assert!(
        unavailable.requests.lock().unwrap().is_empty(),
        "a new monotonic deadline cannot renew the expired UTC intent or trigger reads/quotes/sends"
    );
}
