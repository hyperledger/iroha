//! Generated original custody, real native fees and exact provider registration execution.
//!
//! Wallet fee/funding reads use real loopback HTTP over the same executed State. The component
//! fixture commits the exact wallet envelope directly; it does not qualify Queue, four-process
//! consensus or a complete coordinator register/advance HTTP success. All current proofs and
//! carrier checkpoints come from actual original native execution, on ordinary stacks.

use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::{
    retained_carrier,
    test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, NativeReadHttp, balance, policy, quote_instructions},
    },
    verify_carrier,
};
use iroha_core::state::State;
use iroha_data_model::{
    asset::AssetId,
    isi::{
        InstructionBox, Log,
        sorafs::{RegisterSorafsReserveAccount, SetSorafsReservePolicy},
    },
    sorafs::reserve::{ReserveLifecycleStage, account_proof::ReserveAccountProofExpectedV1},
    transaction::{Executable, FeePaymentIntent},
};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn assert_original_carrier(verifier: &FinalityVerifier, original: &SignedTransaction, height: u64) {
    let carrier = verifier.verified_tip().unwrap();
    assert_eq!(carrier.height(), height);
    assert_eq!(carrier.block().network_entrypoint_count(), 1);
    assert_eq!(
        carrier
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        original.encode_wire_v1().unwrap(),
        "one original envelope, with no hidden clock Log or replacement signature",
    );
}

#[test]
fn generated_native_registration_retains_exact_reserve_operator_wallet_and_distinct_owner() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-reserve-account",
        &temporary.path().join("generation"),
        &ports,
    )
    .unwrap();
    let mut coordinator = ManagedReserveAccountRegistration::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let manager = coordinator.authority.config.clone();
    let operator = coordinator.authority.reserve_operations_config().unwrap();
    assert_ne!(operator.account, manager.account);
    assert_eq!(
        &operator.account,
        coordinator
            .authority
            .network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)
            .unwrap(),
    );
    assert_eq!(
        operator.account.try_signatory(),
        Some(operator.key_pair.public_key())
    );
    assert_eq!(operator.chain, manager.chain);
    assert_eq!(operator.network_id, manager.network_id);
    assert_eq!(operator.torii_api_url, manager.torii_api_url);

    let mut native = NativeFixture::from_generated(&prepared, &coordinator.authority);
    let log = quote_instructions(
        &native,
        &manager,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "native reserve account prerequisite".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log.clone()]), vec![true]);
    assert_original_carrier(&native.observe(&coordinator.authority), &log, 2);

    let policy = policy(&coordinator.authority);
    // The existing policy test covers wallet Set planning; this shared component commits an
    // actual quoted manager Set before preparing the shared reserve operator's exact wallet Register envelope.
    let set = quote_instructions(
        &native,
        &manager,
        [SetSorafsReservePolicy::new(policy.clone()).into()],
    );
    assert_eq!(set.authority(), &manager.account);
    assert_eq!(native.chain.commit(vec![set.clone()]), vec![true]);
    let before = native.observe(&coordinator.authority);
    assert_original_carrier(&before, &set, 3);
    let set_finality = verify_carrier(&before, &set).unwrap();
    let schema = State::native_world_schema_hash_v1().unwrap();
    let policy_proof = native.policy_proof(&manager.account);
    let selected_policy = policy_proof
        .verify(
            &manager.chain.to_string(),
            manager.network_id,
            &manager.account,
            &policy,
            schema,
            &before.verified_tip().unwrap(),
        )
        .unwrap();
    assert_eq!(selected_policy.current().unwrap().policy, policy);
    assert_eq!(
        selected_policy.current().unwrap().policy_digest,
        policy.digest().unwrap()
    );

    let underwriting = super::tests::underwriting(&coordinator);
    assert_eq!(
        underwriting.provider_id,
        coordinator.authority.provider_id().unwrap()
    );
    assert_ne!(underwriting.provider_account, operator.account);
    assert_eq!(
        &underwriting.provider_account,
        coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
    );
    let chain_name = manager.chain.to_string();
    let expected = ReserveAccountProofExpectedV1 {
        chain: &chain_name,
        network_id: manager.network_id,
        operator: &operator.account,
        provider_id: underwriting.provider_id,
        owner: &underwriting.provider_account,
        policy: &policy,
        schema,
    };
    let absent = native.account_proof(&operator.account, underwriting.provider_id);
    assert!(
        absent
            .verify(&expected, &before.verified_tip().unwrap())
            .unwrap()
            .current()
            .is_none()
    );
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    let original = Original {
        selection: coordinator.selection(&policy, &underwriting).unwrap(),
        policy: policy.clone(),
        underwriting: underwriting.clone(),
        checkpoint: checkpoint_bytes(&before).unwrap(),
    };
    coordinator.validate_original(&original).unwrap();
    let directory = coordinator
        .authority
        .directory
        .ensure_child("register")
        .unwrap();
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory.read("original.nrt", 33 * 1024 * 1024).unwrap();
    let path = original.directory().path().join("transaction");
    drop(ports);

    // This is a genuine independently verified original checkpoint, not a codec-only fixture.
    // ObserveOnly on the unprepared intent is positive read-only recovery with zero HTTP.
    let mut unprepared_peers = UnavailablePeers::start(&prepared);
    let selected_recovery = coordinator
        .recover_selected_if_present(
            &policy,
            &underwriting,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_recovery.transaction_status,
        OperationStatus::Absent
    );
    assert!(selected_recovery.finalized.is_none() && selected_recovery.current.is_none());
    let unprepared = coordinator
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(unprepared.transaction_status, OperationStatus::Absent);
    assert!(unprepared.finalized.is_none() && unprepared.current.is_none());
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(unprepared_peers.requests.lock().unwrap().is_empty());
    unprepared_peers.finish();

    let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
    let account = AccountService::new(operator.clone()).unwrap();
    account
        .prepare_reserve_account_registration(
            &original.request(original.terms.signing_deadline(options.deadline).unwrap()),
            &path,
        )
        .unwrap();
    let before_offline_verify = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(original.directory(), &original, options.deadline)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), before_offline_verify);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &operator.account);
    assert_eq!(
        signed.authority().try_signatory(),
        Some(operator.key_pair.public_key())
    );
    assert_eq!(signed.network_id(), Some(&operator.network_id));
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("one direct native registration")
    };
    assert_eq!(instructions.len(), 1);
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<RegisterSorafsReserveAccount>()
        .unwrap();
    assert_eq!(instruction.terms, underwriting);
    assert_eq!(
        instruction.policy_digest,
        selected_policy.current().unwrap().policy_digest
    );
    let wire = signed.encode_wire_v1().unwrap();
    let operation_bytes = std::fs::read(path.join("operation.json")).unwrap();
    assert!(
        !path.join("submission.json").exists(),
        "component fixture has not sent a transaction through Torii"
    );
    http.finish();
    let partial_request = original.request(options.deadline);
    let partial_account = &account;
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &path,
        || {
            partial_account
                .inspect_reserve_account_registration_preparation(&path, &partial_request)
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
                .prepare_reserve_account_registration(&partial_request, &path)
                .unwrap();
        },
    );
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    assert!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, path)| path == "/v1/query")
    );
    assert_eq!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path == "/v1/fees/quote")
            .count(),
        1
    );
    let maximum_fee = quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(component.asset_definition_id, policy.asset_definition);
            sum.checked_add(&component.max_amount).unwrap()
        });
    let holding = AssetId::new(policy.asset_definition.clone(), operator.account.clone());
    let before_balance = balance(native.chain.state(), &holding);
    let owner_holding = AssetId::new(
        policy.asset_definition.clone(),
        underwriting.provider_account.clone(),
    );
    let owner_before = balance(native.chain.state(), &owner_holding);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let debit = before_balance
        .checked_sub(&balance(native.chain.state(), &holding))
        .unwrap();
    assert!(
        !debit.is_zero() && debit <= maximum_fee,
        "exact generated reserve operator paid its actual native fee"
    );
    assert_eq!(balance(native.chain.state(), &owner_holding), owner_before);
    let committed = native.observe(&coordinator.authority);
    assert_original_carrier(&committed, &signed, 4);
    let finalized = verify_carrier(&committed, &signed).unwrap();
    coordinator.validate_carrier(&original, &finalized).unwrap();
    assert_eq!(finalized.height, 4);
    assert!(verify_carrier(&before, &signed).is_err());
    assert!(verify_carrier(&committed, &set).is_err());
    assert!(
        coordinator
            .validate_carrier(&original, &set_finality)
            .is_err()
    );

    let proof = native.account_proof(&operator.account, underwriting.provider_id);
    let carrier = committed.verified_tip().unwrap();
    let current = proof.verify(&expected, &carrier).unwrap();
    assert!(
        proof
            .verify(
                &ReserveAccountProofExpectedV1 {
                    chain: &chain_name,
                    network_id: manager.network_id,
                    operator: &operator.account,
                    provider_id: underwriting.provider_id,
                    owner: &operator.account,
                    policy: &policy,
                    schema,
                },
                &carrier
            )
            .is_err()
    );
    let row = current.current().unwrap();
    assert_eq!(row.terms, underwriting);
    assert_eq!(row.policy_digest, policy.digest().unwrap());
    assert_eq!(row.revision, 1);
    assert!(
        row.reserve_balance.is_zero()
            && row.debt_principal.is_zero()
            && row.accrued_interest.is_zero()
    );
    assert_eq!(row.lifecycle_stage, ReserveLifecycleStage::Warning);
    assert_eq!(row.days_past_due, 0);
    assert_eq!(row.pending_movements, 0);
    assert_eq!(row.open_appeals, 0);
    for time in [
        row.rent_charged_through_unix,
        row.interest_accrued_at_unix,
        row.updated_at_unix,
    ] {
        assert_eq!(time, finalized.block_time_ms / 1_000);
    }
    assert_eq!(current.policy(), selected_policy.current().unwrap());
    assert_eq!(current.height(), finalized.height);
    assert!(absent.verify(&expected, &carrier).is_err());
    assert!(
        proof
            .verify(&expected, &before.verified_tip().unwrap())
            .is_err()
    );
    let current_only = progress(OperationStatus::Applied, None, Some(current));
    assert!(
        current_only.finalized.is_none(),
        "current facts cannot manufacture original inclusion"
    );
    assert!(current_only.current.unwrap().current().is_some());

    let mut wrong_terms = underwriting.clone();
    wrong_terms.capacity_gib += 1;
    let different_wire = quote_instructions(
        &native,
        &operator,
        [RegisterSorafsReserveAccount::new(wrong_terms, policy.digest().unwrap()).into()],
    );
    assert!(verify_carrier(&committed, &different_wire).is_err());
    let mut hidden = proof.clone();
    hidden.current = None;
    assert!(hidden.verify(&expected, &carrier).is_err());
    let carrier_bytes = checkpoint_bytes(&committed).unwrap();
    original
        .directory()
        .write_atomic("carrier.nrt", &carrier_bytes, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        retained_carrier(
            original.directory(),
            operator.network_id,
            &chain_name,
            &signed
        )
        .unwrap(),
        Some(finalized)
    );

    // Native policy rotation changes current facts without erasing the original successful
    // Register. The existing native owner lazily preserves the provider's previous digest.
    let rotated = ReserveAuthorityPolicyV1 {
        revision: 2,
        predecessor_policy_digest: Some(policy.digest().unwrap()),
        grace_period_days: policy.grace_period_days + 1,
        ..policy.clone()
    };
    let rotate = quote_instructions(
        &native,
        &manager,
        [SetSorafsReservePolicy::new(rotated.clone()).into()],
    );
    assert_eq!(native.chain.commit(vec![rotate.clone()]), vec![true]);
    let later = native.observe(&coordinator.authority);
    assert_original_carrier(&later, &rotate, 5);
    let later_proof = native.account_proof(&operator.account, underwriting.provider_id);
    assert!(
        later_proof
            .verify(&expected, &later.verified_tip().unwrap())
            .is_err()
    );
    let rotated_expected = ReserveAccountProofExpectedV1 {
        policy: &rotated,
        ..expected
    };
    let later_current = later_proof
        .verify(&rotated_expected, &later.verified_tip().unwrap())
        .unwrap();
    assert_eq!(later_current.current().unwrap().terms, underwriting);
    assert_eq!(later_current.current().unwrap().revision, 1);
    assert_eq!(
        later_current.current().unwrap().policy_digest,
        policy.digest().unwrap()
    );
    assert_eq!(
        later_current.policy().policy_digest,
        rotated.digest().unwrap()
    );
    assert_eq!(
        retained_carrier(
            original.directory(),
            operator.network_id,
            &chain_name,
            &signed
        )
        .unwrap(),
        Some(finalized)
    );
    assert_eq!(coordinator.authority.config.account, manager.account);
    assert_eq!(
        coordinator.authority.config.key_pair.public_key(),
        manager.key_pair.public_key()
    );
    assert!(
        coordinator
            .authority
            .peers
            .iter()
            .all(|(_, client)| client.to_builder().account == manager.account)
    );

    drop(account);
    drop(directory);
    drop(coordinator);
    let mut unavailable = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        let mut recovered_coordinator = ManagedReserveAccountRegistration::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        crate::managed::native_operation::test_support::assert_optional_current(
            &unavailable,
            &committed,
            |verifier| {
                recovered_coordinator.read_current(
                    &policy,
                    verifier,
                    Instant::now() + Duration::from_secs(30),
                )
            },
        );
        let selected_options = original
            .terms
            .options(Instant::now() + Duration::from_secs(30));
        let selected_utc = original.terms.requested_deadline_unix_ms;
        let before_selected = unavailable.requests.lock().unwrap().len();
        let selected = recovered_coordinator
            .recover_selected_if_present(
                &policy,
                &underwriting,
                &Fees::from_options(&selected_options).unwrap(),
                selected_options.deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.transaction_status, OperationStatus::Applied);
        assert_eq!(selected.finalized, Some(finalized));
        assert!(selected.current.is_none());
        let mut changed_policy = policy.clone();
        changed_policy.grace_period_days += 1;
        assert!(
            recovered_coordinator
                .recover_selected_if_present(
                    &changed_policy,
                    &underwriting,
                    &Fees::from_options(&selected_options).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        assert!(
            original
                .matches(&policy, &underwriting, selected_utc + 1, &selected_options)
                .is_err()
        );
        let mut changed_options = original.terms.options(selected_options.deadline);
        changed_options.max_total_fees.clear();
        assert!(
            recovered_coordinator
                .recover_selected_if_present(
                    &policy,
                    &underwriting,
                    &Fees::from_options(&changed_options).unwrap(),
                    changed_options.deadline
                )
                .is_err()
        );
        assert_eq!(unavailable.requests.lock().unwrap().len(), before_selected);
        let mut changed_underwriting = underwriting.clone();
        changed_underwriting.capacity_gib += 1;
        assert!(
            recovered_coordinator
                .recover_selected_if_present(
                    &policy,
                    &changed_underwriting,
                    &Fees::from_options(&selected_options).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        assert_eq!(unavailable.requests.lock().unwrap().len(), before_selected);
        let recovered = recovered_coordinator
            .recover(Instant::now() + Duration::from_secs(30))
            .unwrap();
        assert_eq!(recovered.transaction_status, OperationStatus::Applied);
        assert_eq!(recovered.finalized, Some(finalized));
        assert!(
            recovered.current.is_none(),
            "503 is unavailable current evidence, never fresh absence or readiness"
        );
        let directory = recovered_coordinator
            .authority
            .directory
            .open_child("register")
            .unwrap();
        assert_eq!(
            directory
                .read("original.nrt", original_bytes.len())
                .unwrap()
                .as_slice(),
            original_bytes.as_slice()
        );
        let recovered_original = journal::required_original(&directory).unwrap();
        assert_eq!(
            recovered_original.directory().identity().unwrap(),
            original.directory().identity().unwrap(),
            "offline recovery must retain the exact committed attempt directory"
        );
        assert_eq!(
            recovered_original
                .directory()
                .read("carrier.nrt", carrier_bytes.len())
                .unwrap()
                .as_slice(),
            carrier_bytes.as_slice()
        );
        assert_eq!(
            std::fs::read(path.join("operation.json")).unwrap(),
            operation_bytes
        );
        assert!(!path.join("submission.json").exists());
        let retained = recovered_coordinator
            .verify_wallet(
                original.directory(),
                &original,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(retained.encode_wire_v1().unwrap(), wire);
    }
    unavailable.finish();
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
}
