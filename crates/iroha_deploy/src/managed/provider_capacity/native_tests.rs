//! Genuine generated plan, owner-funded reserve and exact wallet capacity replacement.
//!
//! This component commits sole original envelopes and separately verifies their carriers and
//! current native projections. It does not qualify full coordinator HTTP, Queue, four-process
//! startup, provider admission, retrieval or service activation. No protocol clock is rewritten.

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
use iroha_crypto::HashOf;
use iroha_data_model::{
    asset::AssetId,
    isi::sorafs::{
        DecideSorafsReserveMovement, RegisterCapacityDeclaration, RequestSorafsReserveMovement,
        UpsertProviderCredit,
    },
    sorafs::reserve::{ReserveMovementKindV1, account_proof::ReserveAccountProofExpectedV1},
    transaction::{Executable, FeePaymentIntent},
};
use iroha_fs::PublishMode;
use iroha_model_base::{metadata::Metadata, name::Name};
use iroha_primitives::numeric::{Quantity, XorQuantity};
use iroha_wallet::operations::{
    ProviderCreditUpsertRequest, ProviderCreditUpsertSelection, ReserveMovementDecisionRequest,
    ReserveMovementDecisionSelection, ReserveTopUpRequest, ReserveTopUpSelection,
};
use sorafs_manifest::capacity::CapacityMetadataEntry;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

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

fn only_original(verifier: &FinalityVerifier, signed: &SignedTransaction, height: u64) {
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
        signed.encode_wire_v1().unwrap(),
        "each carrier contains exactly its wallet original, with no hidden clock Log"
    );
}

fn current(
    native: &NativeFixture,
    coordinator: &ManagedProviderCapacity,
    policy: &ReserveAuthorityPolicyV1,
    verifier: &FinalityVerifier,
) -> VerifiedReserveAccountStateV1 {
    let chain = coordinator.authority.config.chain.to_string();
    native
        .account_proof(
            &policy.operations_authority,
            coordinator.authority.provider_id().unwrap(),
        )
        .verify(
            &ReserveAccountProofExpectedV1 {
                chain: &chain,
                network_id: coordinator.authority.config.network_id,
                operator: &policy.operations_authority,
                provider_id: coordinator.authority.provider_id().unwrap(),
                owner: coordinator
                    .authority
                    .provider_role(StreamTokenAuthorityRole::IssuerOperator)
                    .unwrap(),
                policy,
                schema: State::native_world_schema_hash_v1().unwrap(),
            },
            &verifier.verified_tip().unwrap(),
        )
        .unwrap()
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
    quote.components.iter().fold(Quantity::zero(), |sum, item| {
        assert_eq!(item.asset_definition_id, policy.asset_definition);
        sum.checked_add(&item.max_amount).unwrap()
    })
}

fn asset(
    policy: &ReserveAuthorityPolicyV1,
    account: &iroha_data_model::account::AccountId,
) -> AssetId {
    AssetId::new(policy.asset_definition.clone(), account.clone())
}

/// Prepare one actual manager wallet decision, then let native execution move owner principal.
fn approve(
    native: &mut NativeFixture,
    coordinator: &ManagedProviderCapacity,
    policy: &ReserveAuthorityPolicyV1,
    movement_id: [u8; 32],
    principal: &XorQuantity,
    child: &str,
    height: u64,
) {
    let manager = &coordinator.authority.config;
    let before = current(
        native,
        coordinator,
        policy,
        &native.observe(&coordinator.authority),
    );
    let partition = before.current().unwrap().clone();
    let request = ReserveMovementDecisionRequest {
        selection: ReserveMovementDecisionSelection {
            chain_id: manager.chain.to_string(),
            network_id: manager.network_id,
            provider_id: partition.terms.provider_id,
            provider_account: partition.terms.provider_account.clone(),
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
        partition: partition.clone(),
        movement_id,
        approve: true,
        rationale: "Fund the exact generated provider plan from its native owner.".into(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options: options(policy),
    };
    let directory = coordinator.authority.directory.ensure_child(child).unwrap();
    let path = directory.path().join("transaction");
    let mut http = NativeReadHttp::start_config(manager, Arc::clone(native.chain.state()));
    let wallet = AccountService::new(manager.clone()).unwrap();
    wallet
        .prepare_reserve_movement_decision(&request, &path)
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = wallet
        .verify_reserve_movement_decision_journal(&path, &request)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    let maximum = maximum_fee(&http, policy);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("native decision")
    };
    assert_eq!(items.len(), 1);
    let decision = items[0]
        .as_any()
        .downcast_ref::<DecideSorafsReserveMovement>()
        .unwrap();
    assert_eq!(decision.movement_id, movement_id);
    assert_eq!(decision.expected_provider_revision, partition.revision);
    assert!(decision.approve);
    let owner_asset = asset(policy, &partition.terms.provider_account);
    let manager_asset = asset(policy, &manager.account);
    let custody_asset = asset(policy, &policy.custody_account);
    let owner_before = balance(native.chain.state(), &owner_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    // The first custody account does not yet have an Asset row; its real reserve balance is zero.
    let custody_before = if partition.reserve_balance.is_zero() {
        Quantity::zero()
    } else {
        balance(native.chain.state(), &custody_asset)
    };
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let committed = native.observe(&coordinator.authority);
    only_original(&committed, &signed, height);
    assert_eq!(verify_carrier(&committed, &signed).unwrap().height, height);
    assert_eq!(
        owner_before
            .checked_sub(&balance(native.chain.state(), &owner_asset))
            .unwrap(),
        *principal.as_quantity()
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset)
            .checked_sub(&custody_before)
            .unwrap(),
        *principal.as_quantity()
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    let after = current(native, coordinator, policy, &committed);
    assert_eq!(after.current().unwrap().revision, partition.revision + 1);
    assert_eq!(after.current().unwrap().pending_movements, 0);
    assert_eq!(
        after.current().unwrap().reserve_balance,
        partition.reserve_balance.checked_add(principal).unwrap()
    );
    assert!(!path.join("submission.json").exists());
}

struct Funded {
    native: NativeFixture,
    coordinator: ManagedProviderCapacity,
    policy: ReserveAuthorityPolicyV1,
    checkpoint: FinalityVerifier,
    credit_signed: SignedTransaction,
}

fn funded(prepared: &PreparedLocalnet) -> Funded {
    // Preserve the existing genuine helper and its exact one-XOR assertions unchanged.
    let initial = native_requested_top_up(
        prepared,
        crate::managed::native_operation::test_support::provider_id(prepared, 0),
    );
    let mut native = initial.native;
    let policy = initial.policy;
    let coordinator = ManagedProviderCapacity::open(
        prepared,
        crate::managed::native_operation::test_support::provider_id(prepared, 0),
    )
    .unwrap();
    let plan = coordinator.plan().unwrap();
    let original_request = native.observe(&coordinator.authority);
    only_original(&original_request, &initial.signed, 5);
    assert_eq!(
        initial.history.original(),
        &verify_carrier(&original_request, &initial.signed).unwrap()
    );
    approve(
        &mut native,
        &coordinator,
        &policy,
        initial.history.movement_id(),
        initial.history.amount(),
        "first-funding",
        6,
    );
    let before = current(
        &native,
        &coordinator,
        &policy,
        &native.observe(&coordinator.authority),
    );
    assert_eq!(&before.current().unwrap().terms, plan.reserve_terms());
    assert_eq!(before.pricing(), plan.pricing());
    assert!(before.capacity().is_none() && before.credit().is_none());
    let economics = provider_economics::derive(&plan, &before).unwrap();
    assert_eq!(
        economics.target_reserve.as_quantity(),
        &Quantity::from(24_u32)
    );
    assert_eq!(economics.top_up.as_quantity(), &Quantity::from(23_u32));
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    let manager = coordinator.authority.config.clone();
    assert_ne!(operator.account, manager.account);
    let partition = before.current().unwrap().clone();
    let request = ReserveTopUpRequest {
        selection: ReserveTopUpSelection {
            chain_id: operator.chain.to_string(),
            network_id: operator.network_id,
            provider_id: partition.terms.provider_id,
            provider_account: operator.account.clone(),
            expected_provider_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy: policy.clone(),
        partition: partition.clone(),
        movement_id: [0x75; 32],
        amount: economics.top_up.clone(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options: options(&policy),
    };
    let directory = coordinator
        .authority
        .directory
        .ensure_child("remaining-funding")
        .unwrap();
    let path = directory.path().join("transaction");
    let wallet = AccountService::new(operator.clone()).unwrap();
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    wallet.prepare_reserve_top_up(&request, &path).unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = wallet
        .verify_reserve_top_up_journal(&path, &request)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    let maximum = maximum_fee(&http, &policy);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &operator.account);
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("native request")
    };
    assert_eq!(items.len(), 1);
    let instruction = items[0]
        .as_any()
        .downcast_ref::<RequestSorafsReserveMovement>()
        .unwrap();
    assert_eq!(instruction.kind, ReserveMovementKindV1::TopUp);
    assert_eq!(instruction.amount, economics.top_up);
    assert_eq!(instruction.expected_provider_revision, partition.revision);
    let owner_asset = asset(&policy, &operator.account);
    let custody_asset = asset(&policy, &policy.custody_account);
    let manager_asset = asset(&policy, &manager.account);
    let owner_before = balance(native.chain.state(), &owner_asset);
    let custody_before = balance(native.chain.state(), &custody_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let pending = native.observe(&coordinator.authority);
    only_original(&pending, &signed, 7);
    assert!(verify_carrier(&pending, &signed).is_ok());
    let fee = owner_before
        .checked_sub(&balance(native.chain.state(), &owner_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        custody_before
    );
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    assert!(!path.join("submission.json").exists());
    approve(
        &mut native,
        &coordinator,
        &policy,
        request.movement_id,
        &request.amount,
        "remaining-approval",
        8,
    );
    let funded = current(
        &native,
        &coordinator,
        &policy,
        &native.observe(&coordinator.authority),
    );
    let amounts = provider_economics::derive(&plan, &funded).unwrap();
    assert!(amounts.top_up.is_zero());
    let partition = funded.current().unwrap().clone();
    assert_eq!(partition.reserve_balance, amounts.target_reserve);
    assert!(partition.debt_principal.is_zero());
    let record = ProviderCreditRecord::new(
        partition.terms.provider_id,
        amounts.available_credit.clone(),
        partition.reserve_balance.clone().into_quantity(),
        amounts.price_bond.clone(),
        amounts.expected_settlement.clone(),
        amounts.onboarding_epoch,
        amounts.observed_epoch,
        Metadata::default(),
    );
    let credit = ProviderCreditUpsertRequest {
        selection: ProviderCreditUpsertSelection {
            chain_id: manager.chain.to_string(),
            network_id: manager.network_id,
            credit_authority: manager.account.clone(),
            provider_id: partition.terms.provider_id,
            provider_account: operator.account.clone(),
            expected_current: None,
            desired_record_hash: HashOf::try_new(&record).unwrap(),
            partition_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: manager.account.clone(),
        },
        policy: policy.clone(),
        partition: partition.clone(),
        current_credit: None,
        record: record.clone(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options: options(&policy),
    };
    let directory = coordinator
        .authority
        .directory
        .ensure_child("initial-credit")
        .unwrap();
    let path = directory.path().join("transaction");
    let wallet = AccountService::new(manager.clone()).unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    wallet
        .prepare_provider_credit_upsert(&credit, &path)
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = wallet
        .verify_provider_credit_upsert_journal(&path, &credit)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    let maximum = maximum_fee(&http, &policy);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("native credit")
    };
    assert_eq!(items.len(), 1);
    let upsert = items[0]
        .as_any()
        .downcast_ref::<UpsertProviderCredit>()
        .unwrap();
    assert_eq!(upsert.expected_current, None);
    assert_eq!(upsert.record, record);
    let owner_before = balance(native.chain.state(), &owner_asset);
    let custody_before = balance(native.chain.state(), &custody_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let checkpoint = native.observe(&coordinator.authority);
    only_original(&checkpoint, &signed, 9);
    assert_eq!(verify_carrier(&checkpoint, &signed).unwrap().height, 9);
    assert_eq!(balance(native.chain.state(), &owner_asset), owner_before);
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        custody_before
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    let after = current(&native, &coordinator, &policy, &checkpoint);
    assert_eq!(after.current(), Some(&partition));
    assert_eq!(after.credit(), Some(&record));
    assert!(after.capacity().is_none());
    assert!(
        provider_economics::derive(&plan, &after)
            .unwrap()
            .top_up
            .is_zero()
    );
    assert!(!path.join("submission.json").exists());
    Funded {
        native,
        coordinator,
        policy,
        checkpoint,
        credit_signed: signed,
    }
}

fn original(fixture: &Funded) -> Original {
    let Funded {
        native,
        coordinator,
        policy,
        checkpoint,
        ..
    } = fixture;
    let current = current(native, coordinator, policy, checkpoint);
    let plan = coordinator.plan().unwrap();
    let partition = current.current().unwrap();
    let credit = current.credit().unwrap();
    let result = Original {
        selection: coordinator
            .selection(policy, partition, credit, plan.declaration())
            .unwrap(),
        policy: policy.clone(),
        partition: partition.clone(),
        credit: credit.clone(),
        declaration: plan.declaration().clone(),
        pricing: current.pricing().clone(),
        previous_capacity: current.capacity().cloned(),
        observed_block_time_ms: current.block_time_ms(),
        economics: provider_economics::derive(&plan, &current).unwrap(),
        checkpoint: checkpoint_bytes(checkpoint).unwrap(),
    };
    coordinator.validate_original(&result).unwrap();
    assert!(matches_predecessor(&current, &result));
    result
}

#[test]
fn generated_capacity_uses_real_economics_and_exact_replacement_carrier_during_outage() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-capacity",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let fixture = funded(&prepared);
    let options = options(&fixture.policy);
    let retained = original(&fixture);
    let Funded {
        mut native,
        mut coordinator,
        policy,
        checkpoint,
        credit_signed,
    } = fixture;
    let directory = coordinator
        .authority
        .directory
        .ensure_child("declare")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024)
        .unwrap();
    let path = retained.directory().path().join("transaction");
    let before = current(&native, &coordinator, &policy, &checkpoint);
    let before_proof =
        native.account_proof(&policy.operations_authority, retained.selection.provider_id);
    let mut unavailable = UnavailablePeers::start(&prepared);
    let report = coordinator
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(report.transaction_status, OperationStatus::Absent);
    assert!(report.finalized.is_none() && report.current.is_none());
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let error = coordinator
        .advance(Instant::now() + Duration::from_secs(30))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fresh capacity declaration predecessor unavailable")
    );
    assert!(!path.join("payload.json").exists() && !path.join("operation.json").exists());
    unavailable.finish();
    assert!(
        unavailable
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );

    let operator = coordinator.authority.issuer_operator_config().unwrap();
    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let wallet = AccountService::new(operator.clone()).unwrap();
    let partial_request =
        retained.request(retained.terms.signing_deadline(options.deadline).unwrap());
    wallet
        .prepare_provider_capacity_declaration(&partial_request, &path)
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(retained.directory(), &retained, options.deadline)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &path,
        || {
            wallet
                .inspect_provider_capacity_declaration_preparation(&path, &partial_request)
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
            wallet
                .prepare_provider_capacity_declaration(&partial_request, &path)
                .unwrap();
        },
    );
    let maximum = maximum_fee(&http, &policy);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &operator.account);
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("native capacity")
    };
    assert_eq!(items.len(), 1);
    let declaration = items[0]
        .as_any()
        .downcast_ref::<RegisterCapacityDeclaration>()
        .unwrap();
    let exact_payload = norito::encode_canonical(&retained.declaration).unwrap();
    assert_eq!(declaration.declaration, exact_payload);
    let wire = signed.encode_wire_v1().unwrap();
    let wallet_bytes = std::fs::read(path.join("operation.json")).unwrap();

    // Native capacity is replacement, not absence CAS. A real concurrent valid row changes the
    // managed predecessor, while the already signed original remains exactly the same transaction.
    let mut competing = retained.declaration.clone();
    competing.metadata.push(CapacityMetadataEntry {
        key: "native.test".into(),
        value: "concurrent declaration".into(),
    });
    let competitor = quote_instructions(
        &native,
        &operator,
        [RegisterCapacityDeclaration::new(norito::encode_canonical(&competing).unwrap()).into()],
    );
    assert_eq!(native.chain.commit(vec![competitor.clone()]), vec![true]);
    let replaced = native.observe(&coordinator.authority);
    only_original(&replaced, &competitor, 10);
    assert!(verify_carrier(&replaced, &competitor).is_ok());
    let competing_current = current(&native, &coordinator, &policy, &replaced);
    assert_eq!(
        competing_current.capacity().unwrap().declaration,
        norito::encode_canonical(&competing).unwrap()
    );
    assert!(!matches_predecessor(&competing_current, &retained));
    let owner_asset = asset(&policy, &operator.account);
    let manager_asset = asset(&policy, &coordinator.authority.config.account);
    let custody_asset = asset(&policy, &policy.custody_account);
    let owner_before = balance(native.chain.state(), &owner_asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    let custody_before = balance(native.chain.state(), &custody_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let committed = native.observe(&coordinator.authority);
    only_original(&committed, &signed, 11);
    let finalized = verify_carrier(&committed, &signed).unwrap();
    coordinator.validate_carrier(&retained, &finalized).unwrap();
    let fee = owner_before
        .checked_sub(&balance(native.chain.state(), &owner_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    assert_eq!(
        balance(native.chain.state(), &manager_asset),
        manager_before
    );
    assert_eq!(
        balance(native.chain.state(), &custody_asset),
        custody_before
    );
    let after = current(&native, &coordinator, &policy, &committed);
    assert_eq!(after.current(), Some(&retained.partition));
    assert_eq!(after.credit(), Some(&retained.credit));
    assert_eq!(after.pricing(), &retained.pricing);
    let row = after.capacity().unwrap();
    assert_eq!(row.provider_id, retained.selection.provider_id);
    assert_eq!(row.declaration, exact_payload);
    assert_eq!(
        row.committed_capacity_gib,
        retained.declaration.committed_capacity_gib
    );
    assert_eq!(row.valid_from_epoch, retained.declaration.valid_from);
    assert_eq!(row.valid_until_epoch, retained.declaration.valid_until);
    assert_eq!(row.registered_epoch, finalized.block_time_ms / 1000);
    for metadata in &retained.declaration.metadata {
        assert_eq!(
            row.metadata.get(&metadata.key.parse::<Name>().unwrap()),
            Some(&iroha_primitives::json::Json::new(metadata.value.clone()))
        );
    }
    assert!(!matches_predecessor(&after, &retained));
    assert_eq!(before.height(), 9);
    let old = progress(OperationStatus::Applied, Some(finalized), Some(before));
    assert_eq!(old.finalized, Some(finalized));
    assert!(old.current.is_none());
    let current_only = progress(OperationStatus::Applied, None, Some(after));
    assert!(current_only.finalized.is_none());
    assert!(current_only.current.unwrap().capacity().is_some());
    let chain = coordinator.authority.config.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain,
        network_id: coordinator.authority.config.network_id,
        operator: &policy.operations_authority,
        provider_id: retained.selection.provider_id,
        owner: &operator.account,
        policy: &policy,
        schema: State::native_world_schema_hash_v1().unwrap(),
    };
    assert!(
        before_proof
            .verify(&expected, &committed.verified_tip().unwrap())
            .is_err()
    );
    assert!(verify_carrier(&checkpoint, &signed).is_err());
    assert!(verify_carrier(&committed, &credit_signed).is_err());
    assert!(
        coordinator
            .validate_carrier(
                &retained,
                &verify_carrier(&checkpoint, &credit_signed).unwrap()
            )
            .is_err()
    );
    let mut altered = retained.clone();
    altered.declaration.metadata.push(CapacityMetadataEntry {
        key: "native.changed".into(),
        value: "different signed claim".into(),
    });
    assert!(
        AccountService::new(coordinator.authority.issuer_operator_config().unwrap())
            .unwrap()
            .verify_provider_capacity_declaration_journal(
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
    let mut reopened = ManagedProviderCapacity::open(
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
    assert_eq!(recovered.finalized, Some(finalized));
    assert!(
        recovered.current.is_none(),
        "retained inclusion cannot claim current service or capacity"
    );
    let directory = reopened.authority.directory.open_child("declare").unwrap();
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
            .all(|request| request.method == "GET"
                && matches!(
                    request.path.as_str(),
                    "/v1/node/capabilities" | "/v1/bridge/finality/1"
                ))
    );
}

#[test]
fn genuinely_expired_unprepared_capacity_never_renews_authorization_or_performs_http() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-expired-capacity",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let mut fixture = funded(&prepared);
    let mut unavailable = UnavailablePeers::start(&prepared);
    assert!(
        fixture
            .coordinator
            .recover(Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    assert!(
        !fixture
            .coordinator
            .authority
            .directory
            .path()
            .join("declare")
            .exists()
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let options = options(&fixture.policy);
    let retained = original(&fixture);
    let directory = fixture
        .coordinator
        .authority
        .directory
        .ensure_child("declare")
        .unwrap();
    let retained = super::tests::retain_explicit_request(
        &fixture.coordinator,
        &directory,
        &retained,
        now_ms().unwrap() + 500,
        &options,
    );
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024)
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
            fixture.coordinator.advance(deadline)
        } else {
            fixture.coordinator.recover(deadline)
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
    assert!(unavailable.requests.lock().unwrap().is_empty());
}
