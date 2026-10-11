//! Genuine generated-provider request and exact manager-wallet approval, using the sole fixture.
//!
//! Native envelopes are committed directly, never through Queue or a simulated status response.
//! This component proves historical native transfer separately from current partition facts. It
//! does not qualify the complete coordinator HTTP workflow, consensus startup or service readiness.

use super::*;
use crate::managed::{
    native_operation::test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions},
    },
    reserve_top_up::native_tests::native_requested_top_up,
};
use iroha_core::{
    execution_attempt::ExecutionAttemptError, smartcontracts::ValidSingularQuery, state::State,
};
use iroha_data_model::{
    asset::AssetId,
    executor::ValidationFail,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::SetSorafsReservePolicy,
    },
    query::{
        asset::FindAssetById,
        error::{FindError, QueryExecutionFail},
    },
    sorafs::reserve::account_proof::ReserveAccountProofExpectedV1,
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
        "one exact wallet/native envelope, with no hidden clock Log",
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
    );
}

fn current(
    native: &NativeFixture,
    coordinator: &ManagedReserveTopUpApproval,
    history: &ManagedHistoricalReserveTopUp,
    policy: &ReserveAuthorityPolicyV1,
    verifier: &FinalityVerifier,
) -> VerifiedReserveAccountStateV1 {
    let config = &coordinator.authority.config;
    let chain = config.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: config.network_id,
        operator: &policy.operations_authority,
        provider_id: history.provider_id(),
        owner: history.provider_account(),
        policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    native
        .account_proof(&policy.operations_authority, history.provider_id())
        .verify(&expected, &verifier.verified_tip().unwrap())
        .unwrap()
}

fn original(
    coordinator: &ManagedReserveTopUpApproval,
    history: &ManagedHistoricalReserveTopUp,
    intent: &ManagedReserveTopUpApprovalIntent,
    checkpoint: &FinalityVerifier,
) -> Original {
    let original = Original {
        history: journal::HistoryClaim::from_history(history).unwrap(),
        selection: coordinator.selection(history, intent).unwrap(),
        policy: intent.policy.clone(),
        partition: intent.partition.clone(),
        rationale: intent.rationale.clone(),
        checkpoint: checkpoint_bytes(checkpoint).unwrap(),
    };
    coordinator.validate_original(history, &original).unwrap();
    original
}

/// The exact shared Core fee/query HTTP owner supplies one real quote and manager funding query.
fn prepare_wallet(
    native: &NativeFixture,
    coordinator: &ManagedReserveTopUpApproval,
    directory: &PrivateDirectory,
    original: &Selected<Original>,
    deadline: Instant,
) -> (SignedTransaction, Quantity) {
    assert_eq!(directory.path(), original.directory().path());
    let manager = &coordinator.authority.config;
    let mut http = NativeReadHttp::start_config(manager, Arc::clone(native.chain.state()));
    AccountService::new(manager.clone())
        .unwrap()
        .prepare_reserve_movement_decision(
            &original.request(original.terms.signing_deadline(deadline).unwrap()),
            &directory.path().join("transaction"),
        )
        .unwrap();
    let before = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(directory, original, deadline)
        .unwrap();
    assert_eq!(
        http.requests.lock().unwrap().len(),
        before,
        "exact wallet verification is offline"
    );
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("one native decision")
    };
    assert_eq!(instructions.len(), 1);
    let decision = instructions[0]
        .as_any()
        .downcast_ref::<DecideSorafsReserveMovement>()
        .unwrap();
    assert!(decision.approve);
    assert_eq!(decision.policy_digest, original.selection.policy_digest);
    assert_eq!(
        decision.expected_provider_revision,
        original.selection.expected_provider_revision
    );
    assert_eq!(decision.rationale, original.rationale);
    http.finish();
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
    let maximum_fee = quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(
                component.asset_definition_id,
                original.policy.asset_definition
            );
            sum.checked_add(&component.max_amount).unwrap()
        });
    assert!(!maximum_fee.is_zero());
    (signed, maximum_fee)
}

#[test]
fn generated_native_approval_joins_exact_request_and_manager_decision_with_separate_current_facts()
{
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-reserve-approval",
        &temporary.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    // Only the request owner's private verifier can create this authentic capability. Its helper
    // uses the same generated genesis/fee/HTTP owners, never a fieldwise history reconstruction.
    let fixture = native_requested_top_up(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    );
    let mut native = fixture.native;
    let policy = fixture.policy;
    let history = fixture.history;
    let request_wire = fixture.signed;
    let mut coordinator = ManagedReserveTopUpApproval::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let manager = coordinator.authority.config.clone();
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    assert_ne!(manager.account, operator.account);
    assert_eq!(history.provider_account(), &operator.account);
    assert_eq!(history.policy_digest(), policy.digest().unwrap());
    assert_eq!(history.requested_provider_revision(), 1);
    let requested = native.observe(&coordinator.authority);
    assert_only_original(&requested, &request_wire, 5);
    assert_eq!(
        history.original(),
        &verify_carrier(&requested, &request_wire).unwrap()
    );
    let before_rotation = current(&native, &coordinator, &history, &policy, &requested);
    let partition = before_rotation.current().unwrap().clone();
    assert_eq!(partition.revision, 2);
    assert_eq!(partition.pending_movements, 1);
    assert!(partition.reserve_balance.is_zero());
    let intent = ManagedReserveTopUpApprovalIntent {
        policy: policy.clone(),
        partition: partition.clone(),
        expected_provider_revision: 2,
        rationale: "Approve original provider TopUp é.".into(),
    };
    let mut request_cas = intent.clone();
    request_cas.expected_provider_revision = history.requested_provider_revision();
    request_cas.partition.revision = history.requested_provider_revision();
    assert!(
        coordinator.validate_intent(&history, &request_cas).is_err(),
        "approval requires a post-request CAS"
    );
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    // Retain an exact wallet approval under policy 1. A later genuine policy rotation must cause
    // native rejection, not rewrite this immutable signed decision to use a newer policy.
    let stale_original = original(&coordinator, &history, &intent, &requested);
    let stale_directory = coordinator
        .authority
        .directory
        .ensure_child("stale-approval")
        .unwrap();
    let stale_original = super::tests::retain_explicit_request(
        &coordinator,
        &stale_directory,
        &stale_original,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let (stale_signed, _) = prepare_wallet(
        &native,
        &coordinator,
        stale_original.directory(),
        &stale_original,
        options.deadline,
    );
    let stale_wire = stale_signed.encode_wire_v1().unwrap();
    let mut rotated_policy = policy.clone();
    rotated_policy.revision += 1;
    rotated_policy.predecessor_policy_digest = Some(policy.digest().unwrap());
    rotated_policy.grace_period_days += 1;
    let rotation = quote_instructions(
        &native,
        &manager,
        [SetSorafsReservePolicy::new(rotated_policy.clone()).into()],
    );
    assert_eq!(native.chain.commit(vec![rotation.clone()]), vec![true]);
    let rotated = native.observe(&coordinator.authority);
    assert_only_original(&rotated, &rotation, 6);
    let after_rotation = current(&native, &coordinator, &history, &rotated_policy, &rotated);
    assert_eq!(after_rotation.current(), Some(&partition));
    assert_ne!(
        partition.policy_digest,
        rotated_policy.digest().unwrap(),
        "native provider policy projection remains lazy"
    );

    let provider_asset = AssetId::new(policy.asset_definition.clone(), operator.account.clone());
    let manager_asset = AssetId::new(policy.asset_definition.clone(), manager.account.clone());
    let custody_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.custody_account.clone(),
    );
    let treasury_asset = AssetId::new(
        policy.asset_definition.clone(),
        policy.treasury_account.clone(),
    );
    let provider_before_failure = balance(native.chain.state(), &provider_asset);
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_eq!(native.chain.commit(vec![stale_signed.clone()]), vec![false]);
    let failed = native.observe(&coordinator.authority);
    assert_only_original(&failed, &stale_signed, 7);
    assert_eq!(
        failed
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
                format!(
                    "reserve policy digest mismatch: supplied {}, active {}",
                    hex::encode(policy.digest().unwrap()),
                    hex::encode(rotated_policy.digest().unwrap()),
                )
            )),
        )),
    );
    assert!(verify_carrier(&failed, &stale_signed).is_err());
    assert!(
        coordinator
            .historical_binding(&history, &stale_original, &stale_signed, &failed)
            .is_err()
    );
    assert_eq!(
        balance(native.chain.state(), &provider_asset),
        provider_before_failure
    );
    assert_unfunded(native.chain.state(), &custody_asset);
    let fresh_current = current(&native, &coordinator, &history, &rotated_policy, &failed);
    assert_eq!(fresh_current.current(), Some(&partition));
    assert_eq!(
        coordinator
            .verify_wallet(
                stale_original.directory(),
                &stale_original,
                options.deadline
            )
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        stale_wire
    );

    // The new approval explicitly selects the authenticated current policy and unchanged CAS2.
    // The original request policy digest remains policy1 as historical data.
    let intent = ManagedReserveTopUpApprovalIntent {
        policy: rotated_policy.clone(),
        partition: fresh_current.current().unwrap().clone(),
        expected_provider_revision: 2,
        rationale: "Approve original TopUp under active policy 2.".into(),
    };
    let retained = original(&coordinator, &history, &intent, &failed);
    assert_ne!(history.policy_digest(), retained.selection.policy_digest);
    assert_eq!(
        retained.selection.partition_policy_digest,
        history.policy_digest()
    );
    let directory = coordinator
        .authority
        .directory
        .ensure_child("approval")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
        .unwrap();
    let transaction_path = retained.directory().path().join("transaction");

    let mut unavailable = UnavailablePeers::start(&prepared);
    journal::assert_history_claim_mutations_refuse(&history, |claim| {
        let mut changed = retained.clone();
        changed.history = claim;
        assert!(coordinator.validate_original(&history, &changed).is_err());
    });
    assert!(
        unavailable.requests.lock().unwrap().is_empty(),
        "history substitutions refuse before HTTP"
    );
    let recovery = coordinator
        .recover(&history, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovery.transaction_status, OperationStatus::Absent);
    assert!(
        recovery.historical().is_none()
            && recovery.finalized.is_none()
            && recovery.current.is_none()
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let error = coordinator
        .advance(&history, Instant::now() + Duration::from_secs(30))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fresh exact reserve predecessor unavailable")
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
    assert!(
        unavailable
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );

    let (signed, maximum_fee) = prepare_wallet(
        &native,
        &coordinator,
        retained.directory(),
        &retained,
        options.deadline,
    );
    let partial_request = retained.request(options.deadline);
    let partial_account = AccountService::new(manager.clone()).unwrap();
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &transaction_path,
        || {
            partial_account
                .inspect_reserve_movement_decision_preparation(&transaction_path, &partial_request)
                .unwrap()
        },
        |advance| {
            coordinator
                .advance_original(
                    &history,
                    options.deadline,
                    if advance {
                        Advance::SubmitOriginal
                    } else {
                        Advance::ObserveOnly
                    },
                    false,
                )
                .map(|value| {
                    assert!(
                        value.finalized.is_none()
                            && value.current.is_none()
                            && value.historical().is_none()
                    );
                    value.transaction_status
                })
        },
        || {
            partial_account
                .prepare_reserve_movement_decision(&partial_request, &transaction_path)
                .unwrap();
        },
    );
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("one native decision")
    };
    let decision = instructions[0]
        .as_any()
        .downcast_ref::<DecideSorafsReserveMovement>()
        .unwrap();
    assert_eq!(decision.movement_id, history.movement_id());
    assert_eq!(decision.expected_provider_revision, 2);
    assert_eq!(signed.authority(), &manager.account);
    let wire = signed.encode_wire_v1().unwrap();
    let wallet_bytes = std::fs::read(transaction_path.join("operation.json")).unwrap();
    let provider_before = balance(native.chain.state(), &provider_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_unfunded(native.chain.state(), &custody_asset);
    assert_unfunded(native.chain.state(), &treasury_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let approved = native.observe(&coordinator.authority);
    assert_only_original(&approved, &signed, 8);
    let principal = history.amount().clone().into_quantity();
    assert_eq!(
        provider_before
            .checked_sub(&balance(native.chain.state(), &provider_asset))
            .unwrap(),
        principal
    );
    assert_eq!(balance(native.chain.state(), &custody_asset), principal);
    let manager_fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(
        !manager_fee.is_zero() && manager_fee <= maximum_fee,
        "manager pays native fees only; provider pays exact principal separately"
    );
    assert_unfunded(native.chain.state(), &treasury_asset);
    let historical = coordinator
        .historical_binding(&history, &retained, &signed, &approved)
        .unwrap();
    assert_eq!(
        historical.original(),
        &verify_carrier(&approved, &signed).unwrap()
    );
    assert_eq!(historical.original().height, 8);
    assert_eq!(historical.request().original(), history.original());
    assert_eq!(historical.request().movement_id(), history.movement_id());
    assert_eq!(historical.request().amount(), history.amount());
    assert_eq!(historical.requested_provider_revision(), 2);
    assert_eq!(historical.policy_digest(), rotated_policy.digest().unwrap());
    assert_eq!(historical.rationale(), retained.rationale);
    let after = current(&native, &coordinator, &history, &rotated_policy, &approved);
    let row = after.current().unwrap();
    assert_eq!(row.revision, 3);
    assert_eq!(row.pending_movements, 0);
    assert_eq!(&row.reserve_balance, history.amount());
    assert_eq!(row.policy_digest, rotated_policy.digest().unwrap());
    assert!(row.debt_principal.is_zero() && row.accrued_interest.is_zero());
    assert_eq!(history.requested_provider_revision(), 1);
    assert_eq!(
        history.original().height,
        5,
        "request history never turns into current funding"
    );

    let stale_current = progress(
        OperationStatus::Applied,
        Some(historical.clone()),
        Some(fresh_current),
    );
    assert!(stale_current.historical().is_some() && stale_current.current.is_none());
    let mut current_only = progress(OperationStatus::Applied, None, Some(after));
    current_only.finalized = Some(*historical.original());
    assert!(
        current_only.historical().is_none(),
        "even a genuine public carrier DTO cannot mint private approval evidence"
    );
    assert!(
        coordinator
            .historical_binding(&history, &retained, &signed, &failed)
            .is_err()
    );
    assert!(
        coordinator
            .historical_binding(&history, &retained, &request_wire, &approved)
            .is_err()
    );
    assert!(
        coordinator
            .historical_binding(&history, &retained, &stale_signed, &approved)
            .is_err()
    );
    let mut altered = retained.clone();
    altered.rationale.push('!');
    assert!(
        coordinator
            .historical_binding(&history, &altered, &signed, &approved)
            .is_err()
    );
    let mut altered = retained.clone();
    altered.partition.revision += 1;
    altered.selection.expected_provider_revision += 1;
    assert!(
        coordinator
            .historical_binding(&history, &altered, &signed, &approved)
            .is_err()
    );
    let mut after_carrier = retained.clone();
    after_carrier.checkpoint = checkpoint_bytes(&approved).unwrap();
    assert!(
        coordinator
            .historical_binding(&history, &after_carrier, &signed, &approved)
            .is_err()
    );
    let carrier_bytes = checkpoint_bytes(&approved).unwrap();
    retained
        .directory()
        .write_atomic("carrier.nrt", &carrier_bytes, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        coordinator
            .retained_historical(&history, retained.directory(), &retained, &signed)
            .unwrap()
            .unwrap()
            .original(),
        historical.original()
    );
    assert!(!transaction_path.join("submission.json").exists());
    assert!(
        coordinator
            .authority
            .peers
            .iter()
            .all(|(_, client)| client.to_builder().account == manager.account)
    );
    drop(stale_directory);
    drop(directory);
    drop(coordinator);

    let mut outage = UnavailablePeers::start(&prepared);
    let mut reopened = ManagedReserveTopUpApproval::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    crate::managed::native_operation::test_support::assert_optional_current(
        &outage,
        &approved,
        |verifier| {
            reopened.read_current(
                &rotated_policy,
                verifier,
                Instant::now() + Duration::from_secs(30),
            )
        },
    );
    let recovered = reopened
        .recover(&history, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(
        recovered.historical().unwrap().original(),
        historical.original()
    );
    assert_eq!(
        recovered.historical().unwrap().request().original(),
        history.original()
    );
    assert!(
        recovered.current.is_none(),
        "historical transfer survives outage without claiming current funding"
    );
    let directory = reopened.authority.directory.open_child("approval").unwrap();
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
    assert!(!outage.requests.lock().unwrap().is_empty());
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
fn genuinely_expired_unprepared_approval_recovers_without_http_or_new_authorization() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-expired-approval",
        &temporary.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let fixture = native_requested_top_up(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    );
    let native = fixture.native;
    let history = fixture.history;
    let policy = fixture.policy;
    let mut coordinator = ManagedReserveTopUpApproval::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let requested = native.observe(&coordinator.authority);
    assert_only_original(&requested, &fixture.signed, 5);
    let current = current(&native, &coordinator, &history, &policy, &requested);
    let intent = ManagedReserveTopUpApprovalIntent {
        policy,
        partition: current.current().unwrap().clone(),
        expected_provider_revision: 2,
        rationale: "Approve only under the original finite deadline.".into(),
    };
    let mut unavailable = UnavailablePeers::start(&prepared);
    assert!(
        coordinator
            .recover(&history, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    assert!(
        !coordinator
            .authority
            .directory
            .path()
            .join("approval")
            .exists()
    );
    assert!(
        unavailable.requests.lock().unwrap().is_empty(),
        "missing original recovery never prepares or observes work"
    );

    // Derive every slow authenticated input before issuing the short finite UTC authorization.
    let selection = coordinator.selection(&history, &intent).unwrap();
    let claims = journal::HistoryClaim::from_history(&history).unwrap();
    let checkpoint = checkpoint_bytes(&requested).unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            intent.policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let retained = Original {
        history: claims,
        selection,
        policy: intent.policy,
        partition: intent.partition,
        rationale: intent.rationale,
        checkpoint,
    };
    coordinator.validate_original(&history, &retained).unwrap();
    let directory = coordinator
        .authority
        .directory
        .ensure_child("approval")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 500,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
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
            coordinator.advance(&history, deadline)
        } else {
            coordinator.recover(&history, deadline)
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
        "fresh monotonic deadlines cannot renew the original UTC authorization or trigger HTTP"
    );
}
