//! Genuine generated reserve funding and exact wallet initial-credit native execution.
//!
//! This component commits original signed envelopes directly and authenticates original carriers
//! and current projections separately. It qualifies no full coordinator HTTP workflow, Queue,
//! process startup, capacity, provider admission or service eligibility.

use super::*;
use crate::managed::{
    native_operation::{
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions},
        },
        verify_carrier,
    },
    reserve_top_up::native_tests::native_requested_top_up,
};
use iroha_core::state::State;
use iroha_data_model::{
    asset::AssetId,
    executor::ValidationFail,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{DecideSorafsReserveMovement, UpsertProviderCredit},
    },
    sorafs::reserve::account_proof::ReserveAccountProofExpectedV1,
    transaction::{Executable, FeePaymentIntent, error::TransactionRejectionReason},
};
use iroha_fs::PublishMode;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::{ReserveMovementDecisionRequest, ReserveMovementDecisionSelection};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn assert_only_original(verifier: &FinalityVerifier, signed: &SignedTransaction, height: u64) {
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
        signed.encode_wire_v1().unwrap(),
        "one exact original envelope with no hidden clock Log"
    );
}

fn current(
    native: &NativeFixture,
    coordinator: &ManagedInitialProviderCredit,
    policy: &ReserveAuthorityPolicyV1,
    verifier: &FinalityVerifier,
) -> VerifiedReserveAccountStateV1 {
    let chain = coordinator.authority.config.chain.to_string();
    let provider = coordinator.authority.provider_id().unwrap();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: coordinator.authority.config.network_id,
        operator: &policy.operations_authority,
        provider_id: provider,
        owner: coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap(),
        policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    native
        .account_proof(&policy.operations_authority, provider)
        .verify(&expected, &verifier.verified_tip().unwrap())
        .unwrap()
}

fn options(policy: &ReserveAuthorityPolicyV1) -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    }
}

fn maximum_fee(http: &NativeReadHttp, policy: &ReserveAuthorityPolicyV1) -> Quantity {
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    let calls = http.requests.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|(_, path)| path == "/v1/fees/quote")
            .count(),
        1
    );
    assert!(calls.iter().any(|(_, path)| path == "/v1/query"));
    assert!(calls.iter().all(|(_, path)| matches!(
        path.as_str(),
        "/v1/node/capabilities" | "/v1/fees/quote" | "/v1/query"
    )));
    quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(component.asset_definition_id, policy.asset_definition);
            sum.checked_add(&component.max_amount).unwrap()
        })
}

struct Funded {
    native: NativeFixture,
    coordinator: ManagedInitialProviderCredit,
    intent: ManagedInitialProviderCreditIntent,
    checkpoint: FinalityVerifier,
    approval: SignedTransaction,
}

/// Reuse the sole generated H2 Log/H3 Set/H4 Register/H5 wallet Request fixture, then obtain
/// H6 funding through the actual generic manager Decision wallet and native transfer owner.
fn funded(prepared: &PreparedLocalnet) -> Funded {
    let request = native_requested_top_up(
        prepared,
        crate::managed::native_operation::test_support::provider_id(prepared, 0),
    );
    let mut native = request.native;
    let policy = request.policy;
    let history = request.history;
    let coordinator = ManagedInitialProviderCredit::open(
        prepared,
        crate::managed::native_operation::test_support::provider_id(prepared, 0),
    )
    .unwrap();
    let manager = coordinator.authority.config.clone();
    let checkpoint = native.observe(&coordinator.authority);
    assert_only_original(&checkpoint, &request.signed, 5);
    assert_eq!(
        history.original(),
        &verify_carrier(&checkpoint, &request.signed).unwrap()
    );
    let before = current(&native, &coordinator, &policy, &checkpoint);
    assert!(before.credit().is_none());
    let partition = before.current().unwrap().clone();
    assert_eq!(partition.revision, 2);
    assert_eq!(partition.pending_movements, 1);
    assert!(partition.reserve_balance.is_zero());
    let options = options(&policy);
    let decision = ReserveMovementDecisionRequest {
        selection: ReserveMovementDecisionSelection {
            chain_id: manager.chain.to_string(),
            network_id: manager.network_id,
            provider_id: history.provider_id(),
            provider_account: history.provider_account().clone(),
            expected_provider_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: manager.account.clone(),
        },
        policy: policy.clone(),
        partition,
        movement_id: history.movement_id(),
        approve: true,
        rationale: "Fund the original generated provider reserve before governed projection."
            .into(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options: options.clone(),
    };
    let directory = coordinator
        .authority
        .directory
        .ensure_child("funding-decision")
        .unwrap();
    let path = directory.path().join("transaction");
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    let wallet = AccountService::new(manager.clone()).unwrap();
    wallet
        .prepare_reserve_movement_decision(&decision, &path)
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = wallet
        .verify_reserve_movement_decision_journal(&path, &decision)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("native decision")
    };
    assert_eq!(instructions.len(), 1);
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<DecideSorafsReserveMovement>()
        .unwrap();
    assert!(instruction.approve);
    assert_eq!(instruction.movement_id, history.movement_id());
    assert_eq!(instruction.expected_provider_revision, 2);
    http.finish();
    let limit = maximum_fee(&http, &policy);
    let provider_asset = AssetId::new(
        policy.asset_definition.clone(),
        history.provider_account().clone(),
    );
    let manager_asset = AssetId::new(policy.asset_definition.clone(), manager.account.clone());
    let custody_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.custody_account.clone(),
    );
    let provider_before = balance(native.chain.state(), &provider_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let checkpoint = native.observe(&coordinator.authority);
    assert_only_original(&checkpoint, &signed, 6);
    assert_eq!(verify_carrier(&checkpoint, &signed).unwrap().height, 6);
    let principal = history.amount().clone().into_quantity();
    assert_eq!(
        provider_before
            .checked_sub(&balance(native.chain.state(), &provider_asset))
            .unwrap(),
        principal
    );
    assert_eq!(balance(native.chain.state(), &custody_asset), principal);
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= limit);
    assert!(!path.join("submission.json").exists());
    let current = current(&native, &coordinator, &policy, &checkpoint);
    assert!(current.credit().is_none());
    let partition = current.current().unwrap().clone();
    assert_eq!(partition.revision, 3);
    assert_eq!(partition.pending_movements, 0);
    assert_eq!(&partition.reserve_balance, history.amount());
    assert!(partition.debt_principal.is_zero());
    let epoch = verify_carrier(&checkpoint, &signed).unwrap().block_time_ms / 1_000;
    // Explicit governed nominal fields are not a pricing quote or a readiness assertion.
    let record = ProviderCreditRecord::new(
        history.provider_id(),
        Quantity::zero(),
        partition
            .reserve_balance
            .checked_sub(&partition.debt_principal)
            .unwrap()
            .into_quantity(),
        Quantity::zero(),
        Quantity::zero(),
        epoch,
        epoch,
        Metadata::default(),
    );
    let intent = ManagedInitialProviderCreditIntent {
        policy,
        partition,
        record,
    };
    coordinator.validate_intent(&intent).unwrap();
    Funded {
        native,
        coordinator,
        intent,
        checkpoint,
        approval: signed,
    }
}

fn original(
    coordinator: &ManagedInitialProviderCredit,
    intent: &ManagedInitialProviderCreditIntent,
    checkpoint: &FinalityVerifier,
) -> Original {
    let original = Original {
        selection: coordinator.selection(intent).unwrap(),
        policy: intent.policy.clone(),
        partition: intent.partition.clone(),
        record: intent.record.clone(),
        checkpoint: checkpoint_bytes(checkpoint).unwrap(),
    };
    coordinator.validate_original(&original).unwrap();
    original
}

fn prepare_wallet(
    native: &NativeFixture,
    coordinator: &ManagedInitialProviderCredit,
    directory: &PrivateDirectory,
    original: &Selected<Original>,
    deadline: Instant,
) -> (SignedTransaction, Quantity) {
    assert_eq!(directory.path(), original.directory().path());
    let manager = &coordinator.authority.config;
    let mut http = NativeReadHttp::start_config(manager, Arc::clone(native.chain.state()));
    AccountService::new(manager.clone())
        .unwrap()
        .prepare_provider_credit_upsert(
            &original.request(original.terms.signing_deadline(deadline).unwrap()),
            &directory.path().join("transaction"),
        )
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(directory, original, deadline)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("native upsert")
    };
    assert_eq!(instructions.len(), 1);
    let upsert = instructions[0]
        .as_any()
        .downcast_ref::<UpsertProviderCredit>()
        .unwrap();
    assert_eq!(upsert.expected_current, None);
    assert_eq!(upsert.record, original.record);
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    (signed, maximum_fee(&http, &original.policy))
}

#[test]
fn generated_native_initial_credit_preserves_funding_and_original_carrier_during_outage() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-initial-credit",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let Funded {
        mut native,
        mut coordinator,
        intent,
        checkpoint,
        approval,
    } = funded(&prepared);
    let options = options(&intent.policy);
    let retained = original(&coordinator, &intent, &checkpoint);
    let directory = coordinator
        .authority
        .directory
        .ensure_child("install")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 176 * 1024)
        .unwrap();
    let path = retained.directory().path().join("transaction");
    let before_proof = native.account_proof(
        &intent.policy.operations_authority,
        intent.record.provider_id,
    );
    let before = current(&native, &coordinator, &intent.policy, &checkpoint);
    assert!(matches_predecessor(
        before.current(),
        before.credit(),
        &intent.partition
    ));
    let mut unavailable = UnavailablePeers::start(&prepared);
    let recovered = coordinator
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Absent);
    assert!(recovered.finalized.is_none() && recovered.current.is_none());
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let error = coordinator
        .advance(Instant::now() + Duration::from_secs(30))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fresh initial credit absence/predecessor unavailable")
    );
    assert!(!path.join("payload.json").exists() && !path.join("operation.json").exists());
    unavailable.finish();
    assert!(
        unavailable
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    let (signed, maximum) = prepare_wallet(
        &native,
        &coordinator,
        retained.directory(),
        &retained,
        options.deadline,
    );
    let partial_request = retained.request(options.deadline);
    let partial_account = AccountService::new(coordinator.authority.config.clone()).unwrap();
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &path,
        || {
            partial_account
                .inspect_provider_credit_upsert_preparation(&path, &partial_request)
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
                .prepare_provider_credit_upsert(&partial_request, &path)
                .unwrap();
        },
    );
    let wire = signed.encode_wire_v1().unwrap();
    let wallet_bytes = std::fs::read(path.join("operation.json")).unwrap();
    let manager_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        coordinator.authority.config.account.clone(),
    );
    let provider_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        intent.partition.terms.provider_account.clone(),
    );
    let custody_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        intent.policy.custody_account.clone(),
    );
    let manager_before = balance(native.chain.state(), &manager_asset);
    let provider_before = balance(native.chain.state(), &provider_asset);
    let custody_before = balance(native.chain.state(), &custody_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let committed = native.observe(&coordinator.authority);
    assert_only_original(&committed, &signed, 7);
    let finalized = verify_carrier(&committed, &signed).unwrap();
    coordinator.validate_carrier(&retained, &finalized).unwrap();
    assert_eq!(before.height(), 6);
    assert_eq!(finalized.height, 7);
    let older_current = progress(OperationStatus::Applied, Some(finalized), Some(before));
    assert_eq!(older_current.finalized, Some(finalized));
    assert!(older_current.current.is_none());
    assert_eq!(
        balance(native.chain.state(), &provider_asset),
        provider_before
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        custody_before
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(
        !fee.is_zero() && fee <= maximum,
        "native projection charges only the manager fee and creates no principal"
    );
    let after = current(&native, &coordinator, &intent.policy, &committed);
    assert_eq!(after.current(), Some(&intent.partition));
    assert_eq!(after.credit(), Some(&intent.record));
    assert!(!matches_predecessor(
        after.current(),
        after.credit(),
        &intent.partition
    ));
    let current_only = progress(OperationStatus::Applied, None, Some(after));
    assert!(current_only.finalized.is_none());
    assert_eq!(current_only.current.unwrap().credit(), Some(&intent.record));
    let chain = coordinator.authority.config.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: coordinator.authority.config.network_id,
        operator: &intent.policy.operations_authority,
        provider_id: intent.record.provider_id,
        owner: &intent.partition.terms.provider_account,
        policy: &intent.policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    assert!(
        before_proof
            .verify(&expected, &committed.verified_tip().unwrap())
            .is_err()
    );
    assert!(verify_carrier(&checkpoint, &signed).is_err());
    assert!(verify_carrier(&committed, &approval).is_err());
    assert!(
        coordinator
            .validate_carrier(&retained, &verify_carrier(&checkpoint, &approval).unwrap())
            .is_err()
    );
    let mut altered = retained.clone();
    altered.record.available_credit = Quantity::from(99u32);
    assert!(
        AccountService::new(coordinator.authority.config.clone())
            .unwrap()
            .verify_provider_credit_upsert_journal(
                &path,
                &altered.request(&retained.terms, options.deadline)
            )
            .is_err()
    );
    let carrier_bytes = checkpoint_bytes(&committed).unwrap();
    retained
        .directory()
        .write_atomic("carrier.nrt", &carrier_bytes, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        coordinator
            .authority
            .retained_finality(retained.directory(), &signed)
            .unwrap(),
        Some(finalized)
    );
    assert!(!path.join("submission.json").exists());
    drop(directory);
    drop(coordinator);
    let mut outage = UnavailablePeers::start(&prepared);
    let mut reopened = ManagedInitialProviderCredit::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    crate::managed::native_operation::test_support::assert_optional_current(
        &outage,
        &committed,
        |verifier| {
            reopened.read_current(
                &intent.policy,
                verifier,
                Instant::now() + Duration::from_secs(30),
            )
        },
    );
    let recovered = reopened
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(recovered.finalized, Some(finalized));
    assert!(
        recovered.current.is_none(),
        "an original successful projection is not current backing/readiness evidence"
    );
    let directory = reopened.authority.directory.open_child("install").unwrap();
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
        std::fs::read(path.join("operation.json")).unwrap(),
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
    assert!(!path.join("submission.json").exists());
    outage.finish();
    assert!(
        outage
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET"
                && matches!(
                    r.path.as_str(),
                    "/v1/node/capabilities" | "/v1/bridge/finality/1"
                ))
    );
}

#[test]
fn native_concurrent_initial_credit_cannot_replace_original_absence_guard() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-credit-collision",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let Funded {
        mut native,
        mut coordinator,
        intent,
        checkpoint,
        ..
    } = funded(&prepared);
    let options = options(&intent.policy);
    let retained = original(&coordinator, &intent, &checkpoint);
    let directory = coordinator
        .authority
        .directory
        .ensure_child("install")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 176 * 1024)
        .unwrap();
    let path = retained.directory().path().join("transaction");
    let (signed, maximum) = prepare_wallet(
        &native,
        &coordinator,
        retained.directory(),
        &retained,
        options.deadline,
    );
    let wire = signed.encode_wire_v1().unwrap();
    let wallet_bytes = std::fs::read(path.join("operation.json")).unwrap();
    let mut competing_record = intent.record.clone();
    competing_record.available_credit = Quantity::from(2u32);
    let competing = quote_instructions(
        &native,
        &coordinator.authority.config,
        [UpsertProviderCredit::new(None, competing_record.clone()).into()],
    );
    assert_ne!(competing.encode_wire_v1().unwrap(), wire);
    assert_eq!(native.chain.commit(vec![competing.clone()]), vec![true]);
    let installed = native.observe(&coordinator.authority);
    assert_only_original(&installed, &competing, 7);
    assert_eq!(verify_carrier(&installed, &competing).unwrap().height, 7);
    let current_before = current(&native, &coordinator, &intent.policy, &installed);
    assert_eq!(current_before.credit(), Some(&competing_record));
    assert!(!matches_predecessor(
        current_before.current(),
        current_before.credit(),
        &intent.partition
    ));
    let manager_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        coordinator.authority.config.account.clone(),
    );
    let provider_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        intent.partition.terms.provider_account.clone(),
    );
    let custody_asset = AssetId::new(
        intent.policy.asset_definition.clone(),
        intent.policy.custody_account.clone(),
    );
    let manager_before = balance(native.chain.state(), &manager_asset);
    let provider_before = balance(native.chain.state(), &provider_asset);
    let custody_before = balance(native.chain.state(), &custody_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![false]);
    let rejected = native.observe(&coordinator.authority);
    assert_only_original(&rejected, &signed, 8);
    assert_eq!(
        rejected
            .verified_tip()
            .unwrap()
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .as_ref()
            .unwrap_err(),
        &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "provider credit expected current record does not match".into()
            ))
        ))
    );
    assert!(verify_carrier(&rejected, &signed).is_err());
    let after = current(&native, &coordinator, &intent.policy, &rejected);
    assert_eq!(after.credit(), Some(&competing_record));
    assert_eq!(after.current(), Some(&intent.partition));
    assert_eq!(
        balance(native.chain.state(), &provider_asset),
        provider_before
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        custody_before
    );
    // Canonical native rejection follows normal fee settlement, not a local no-fee deferral.
    let rejection_fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(rejection_fee <= maximum);
    assert_eq!(
        coordinator
            .verify_wallet(retained.directory(), &retained, options.deadline)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        wallet_bytes
    );
    assert!(!path.join("submission.json").exists());
    assert!(!retained.directory().path().join("carrier.nrt").exists());
    let mut outage = UnavailablePeers::start(&prepared);
    assert!(
        coordinator
            .advance(Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    assert_eq!(
        directory
            .read("original.nrt", original_bytes.len())
            .unwrap()
            .as_slice(),
        original_bytes.as_slice()
    );
    assert_eq!(
        coordinator
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
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        wallet_bytes
    );
    assert_eq!(retained.selection.expected_current, None);
    assert!(!path.join("submission.json").exists());
    outage.finish();
    assert!(
        outage
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET"),
        "outage cannot turn a retained None into an update or dispatch a replacement"
    );
}

#[test]
fn genuinely_expired_unprepared_initial_credit_retains_original_without_http() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-expired-credit",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let Funded {
        native,
        mut coordinator,
        intent,
        checkpoint,
        ..
    } = funded(&prepared);
    let current = current(&native, &coordinator, &intent.policy, &checkpoint);
    assert!(matches_predecessor(
        current.current(),
        current.credit(),
        &intent.partition
    ));
    let mut unavailable = UnavailablePeers::start(&prepared);
    assert!(
        coordinator
            .recover(Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    assert!(
        !coordinator
            .authority
            .directory
            .path()
            .join("install")
            .exists()
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let selection = coordinator.selection(&intent).unwrap();
    let checkpoint = checkpoint_bytes(&checkpoint).unwrap();
    let options = options(&intent.policy);
    // Actual future UTC through the production owner; no timestamp or protocol clock mutation.
    let retained = Original {
        selection,
        policy: intent.policy,
        partition: intent.partition,
        record: intent.record,
        checkpoint,
    };
    coordinator.validate_original(&retained).unwrap();
    let directory = coordinator
        .authority
        .directory
        .ensure_child("install")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 500,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 176 * 1024)
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

        assert!(result.finalized.is_none() && result.current.is_none());
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
        "fresh I/O deadlines do not renew UTC or authorize quote/dispatch"
    );
}
