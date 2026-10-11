//! Original generated genesis, actual wallet wire and native reserve execution evidence.
//! The shared owner retains exact custody; these remain component execution controls only.

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
    isi::{InstructionBox, Log},
    sorafs::reserve::{history::ReserveStateV1, proof::ReservePolicyProofV1},
    transaction::FeePaymentIntent,
};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[test]
fn generated_native_reserve_activation_joins_exact_wallet_carrier_and_current_policy() {
    let _resources = crate::managed::native_test_guard();
    native_activation();
}
fn native_activation() {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "native-reserve",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut coordinator = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &coordinator.authority);
    let log = quote_instructions(
        &native,
        &coordinator.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "native reserve prerequisite".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log.clone()]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    let policy = policy(&coordinator.authority);
    let manager = coordinator.authority.config.account.clone();
    let observed = native.observe(&coordinator.authority);
    let before_carrier = observed.verified_tip().unwrap();
    assert_eq!(before_carrier.block().network_entrypoint_count(), 1);
    assert_eq!(
        before_carrier
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        log.encode_wire_v1().unwrap()
    );
    let before_proof = native.policy_proof(&manager);
    let schema = State::native_world_schema_hash_v1().unwrap();
    let before = before_proof
        .verify(
            &coordinator.authority.config.chain.to_string(),
            native.chain.network_id(),
            &manager,
            &policy,
            schema,
            &observed.verified_tip().unwrap(),
        )
        .unwrap();
    assert!(
        before.current().is_none(),
        "singleton absence alone is not activation"
    );
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            policy.asset_definition.clone(),
            Quantity::from(1_000_u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    // Release the empty Reserve owner while the actual startup graph admits its own child.
    // Reopening must retain both original native identities; no paid transaction is added.
    let reserve_directory_identity = coordinator.authority.directory.identity().unwrap();
    let reserve_lock_identity = iroha_fs::FileIdentity::of(&coordinator.authority._lock).unwrap();
    drop(coordinator);
    let mut bootstrap =
        crate::managed::service_bootstrap::ManagedServiceBootstrap::open(&prepared).unwrap();
    let authorization = bootstrap.authorize_test_startup(&options).unwrap().unwrap();
    let child = authorization.test_child(Purpose::ReservePolicy).unwrap();
    coordinator = ManagedInitialReservePolicy::open(&prepared).unwrap();
    assert_eq!(
        coordinator.authority.directory.identity().unwrap(),
        reserve_directory_identity
    );
    assert_eq!(
        iroha_fs::FileIdentity::of(&coordinator.authority._lock).unwrap(),
        reserve_lock_identity
    );
    let original = Original {
        selection: coordinator.selection(&policy).unwrap(),
        policy: policy.clone(),
        checkpoint: checkpoint_bytes(&observed).unwrap(),
    };
    coordinator.validate_original(&original).unwrap();
    let directory = coordinator.authority.directory.ensure_child("set").unwrap();
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 1_200_000,
        &options,
    );
    let original_bytes = directory
        .read(
            "original.nrt",
            super::super::native_operation::MAX_CHECKPOINT_BYTES + 64 * 1024,
        )
        .unwrap();
    drop(ports);
    let mut unavailable = UnavailablePeers::start(&prepared);
    let selected = coordinator
        .recover_selected_if_present(
            &policy,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap();
    assert_eq!(selected.transaction_status, OperationStatus::Absent);
    assert!(selected.finalized.is_none() && selected.current.is_none());
    assert!(selected.activation().is_none());
    assert!(
        !original
            .directory()
            .path()
            .join("transaction/payload.json")
            .exists()
    );
    assert!(
        !original
            .directory()
            .path()
            .join("transaction/operation.json")
            .exists()
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    unavailable.finish();
    let path = original.directory().path().join("transaction");
    let account = AccountService::new(coordinator.authority.config.clone()).unwrap();
    let request = original.request(original.terms.signing_deadline(options.deadline).unwrap());
    // The epoch commit already requires a genuine RequestOnly. Failing fee preflight may
    // neither replace that exact request nor permit read-only recovery to sign or use HTTP.
    let mut fee_failure = UnavailablePeers::start(&prepared);
    let request_directory = iroha_fs::PrivateDirectory::open_exact(&path).unwrap();
    let request_bytes = request_directory
        .read("preparation.json", 4 * 1024 * 1024)
        .unwrap();
    let request_inventory = request_directory.entries(8).unwrap();
    assert_eq!(
        account
            .inspect_initial_reserve_policy_preparation(&path, &request)
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    assert!(fee_failure.requests.lock().unwrap().is_empty());
    assert!(
        account
            .prepare_initial_reserve_policy(&request, &path)
            .is_err()
    );
    assert_eq!(
        request_directory
            .read("preparation.json", 4 * 1024 * 1024)
            .unwrap(),
        request_bytes
    );
    fee_failure.requests.lock().unwrap().clear();
    for _ in 0..2 {
        let recovered = coordinator
            .recover_selected_if_present(
                &policy,
                &Fees::from_options(&options).unwrap(),
                options.deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(recovered.transaction_status, OperationStatus::Absent);
        assert!(
            recovered.finalized.is_none()
                && recovered.current.is_none()
                && recovered.activation().is_none()
        );
        let inspection = account
            .inspect_initial_reserve_policy_preparation(&path, &request)
            .unwrap();
        assert_eq!(
            inspection.phase(),
            iroha_wallet::operations::NativePreparationPhase::RequestOnly
        );
        assert_eq!(
            inspection.unprepared_status(),
            Some(OperationStatus::Absent)
        );
        assert!(inspection.signed_transaction().is_none());
        assert_eq!(request_directory.entries(8).unwrap(), request_inventory);
        assert_eq!(
            request_directory
                .read("preparation.json", 4 * 1024 * 1024)
                .unwrap(),
            request_bytes
        );
        assert!(!path.join("payload.json").exists());
        assert!(!path.join("operation.json").exists());
        assert!(!path.join("submission.json").exists());
        assert!(fee_failure.requests.lock().unwrap().is_empty());
    }
    fee_failure.finish();
    let mut http = NativeReadHttp::start_config(
        &coordinator.authority.config,
        Arc::clone(native.chain.state()),
    );
    account
        .prepare_initial_reserve_policy(
            &original.request(original.terms.signing_deadline(options.deadline).unwrap()),
            &path,
        )
        .unwrap();
    let signed = ManagedInitialReservePolicy::verify_wallet(
        &account,
        original.directory(),
        &original,
        options.deadline,
    )
    .unwrap();
    let wire = signed.encode_wire_v1().unwrap();
    let operation_bytes = std::fs::read(path.join("operation.json")).unwrap();
    assert!(
        !path.join("submission.json").exists(),
        "component fixture has not submitted through a node"
    );
    http.finish();
    // The supplied prepared account must reach the existing mode binding, rather than be
    // discarded for a new client. A foreign cancellation signal refuses before any HTTP.
    let mut refused_http = UnavailablePeers::start(&prepared);
    let journal = iroha_fs::PrivateDirectory::open_exact(&path).unwrap();
    let journal_names = journal.entries(8).unwrap();
    let preparation_bytes = journal.read("preparation.json", 4 * 1024 * 1024).unwrap();
    let payload_bytes = journal.read("payload.json", 4 * 1024 * 1024).unwrap();
    let supplied = account
        .with_deadline(options.deadline)
        .unwrap()
        .with_cancellation(Arc::new(std::sync::atomic::AtomicBool::new(true)))
        .unwrap();
    let error = coordinator
        .advance_original(
            options.deadline,
            Advance::SubmitAuthorized(&child),
            false,
            Some(supplied),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        crate::managed::Error::Invalid(ref reason)
            if reason == "generated wallet cancellation binding changed"
    ));
    assert!(refused_http.requests.lock().unwrap().is_empty());
    assert_eq!(journal.entries(8).unwrap(), journal_names);
    assert_eq!(
        journal.read("preparation.json", 4 * 1024 * 1024).unwrap(),
        preparation_bytes
    );
    assert_eq!(
        journal.read("payload.json", 4 * 1024 * 1024).unwrap(),
        payload_bytes
    );
    assert_eq!(
        journal
            .read("operation.json", 4 * 1024 * 1024)
            .unwrap()
            .as_slice(),
        operation_bytes.as_slice()
    );
    assert_eq!(
        ManagedInitialReservePolicy::verify_wallet(
            &account,
            original.directory(),
            &original,
            options.deadline
        )
        .unwrap()
        .encode_wire_v1()
        .unwrap(),
        wire,
    );
    assert!(!path.join("submission.json").exists());
    refused_http.finish();
    drop(journal);
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &path,
        || {
            account
                .inspect_initial_reserve_policy_preparation(&path, &request)
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
                    None,
                )
                .map(|value| {
                    assert!(
                        value.finalized.is_none()
                            && value.current.is_none()
                            && value.activation().is_none()
                    );
                    value.transaction_status
                })
        },
        || {
            account
                .prepare_initial_reserve_policy(&request, &path)
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
            .any(|(_, path)| path == "/v1/query"),
        "wallet funding used actual native reads"
    );
    let max_fee = quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(component.asset_definition_id, policy.asset_definition);
            sum.checked_add(&component.max_amount).unwrap()
        });
    let holding = AssetId::new(policy.asset_definition.clone(), manager.clone());
    let before_balance = balance(native.chain.state(), &holding);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    assert_eq!(native.chain.height(), 3);
    let debit = before_balance
        .checked_sub(&balance(native.chain.state(), &holding))
        .unwrap();
    assert!(
        !debit.is_zero() && debit <= max_fee,
        "native Set pays its actual retained fee policy"
    );
    let current_verifier = native.observe(&coordinator.authority);
    let finalized = verify_carrier(&current_verifier, &signed).unwrap();
    assert_eq!(finalized.height, 3);
    assert!(
        verify_carrier(&current_verifier, &log).is_err(),
        "different successful envelope cannot prove the Set"
    );
    let carrier = current_verifier.verified_tip().unwrap();
    assert_eq!(carrier.block().network_entrypoint_count(), 1);
    assert_eq!(
        carrier
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    let proof = native.policy_proof(&manager);
    let verify = |proof: &ReservePolicyProofV1| {
        proof.verify(
            &coordinator.authority.config.chain.to_string(),
            native.chain.network_id(),
            &manager,
            &policy,
            schema,
            &carrier,
        )
    };
    let current = verify(&proof).unwrap();
    let singleton = ReserveStateV1::decode_frame(proof.current.as_ref().unwrap()).unwrap();
    assert_eq!(singleton.journal_head.last_sequence, 1);
    assert_eq!(singleton.journal_head.last_target_block_height, 3);
    assert_eq!(singleton.policy.activated_by, manager);
    assert_eq!(
        singleton.policy.activated_at_unix,
        finalized.block_time_ms / 1_000
    );
    assert_eq!(singleton.policy.policy, policy);
    let current_only = progress(&original, OperationStatus::Applied, None, Some(current));
    assert!(
        current_only.activation().is_none(),
        "matching native policy never substitutes exact original inclusion"
    );
    let joined = progress(
        &original,
        OperationStatus::Applied,
        Some(finalized),
        Some(verify(&proof).unwrap()),
    );
    let activation = joined.activation().unwrap();
    assert_eq!(activation.original().transaction_hash, signed.hash());
    assert_eq!(activation.policy_digest(), policy.digest().unwrap());
    assert_eq!(activation.network_id(), native.chain.network_id());
    assert_eq!(activation.current_height(), 3);
    assert_eq!(activation.current_context(), carrier.context_id());
    assert!(
        verify(&before_proof).is_err(),
        "stale genuine H2 absence is not a current H3 proof"
    );
    let mut substituted = proof.clone();
    let mut altered = singleton;
    altered.policy.activated_at_unix += 1;
    substituted.current = Some(norito::encode_canonical(&altered).unwrap());
    assert!(
        verify(&substituted).is_err(),
        "uncommitted activation provenance cannot replace the original native row"
    );
    let mut different_policy = policy.clone();
    different_policy.grace_period_days += 1;
    assert!(
        proof
            .verify(
                &coordinator.authority.config.chain.to_string(),
                native.chain.network_id(),
                &manager,
                &different_policy,
                schema,
                &carrier
            )
            .is_err()
    );
    original
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&current_verifier).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let retained = retained_carrier(
        original.directory(),
        native.chain.network_id(),
        &coordinator.authority.config.chain.to_string(),
        &signed,
    )
    .unwrap()
    .unwrap();
    assert_eq!(retained, finalized);
    // The same-bound deadline view can be handed into the actual advance boundary. Its
    // exact signed journal and genuine retained carrier remain recoverable without HTTP.
    let mut handoff_http = UnavailablePeers::start(&prepared);
    let supplied = child
        .bind_account(account.with_deadline(options.deadline).unwrap())
        .unwrap();
    let handoff = coordinator
        .advance_original(
            options.deadline,
            Advance::SubmitAuthorized(&child),
            false,
            Some(supplied),
        )
        .unwrap();
    assert_eq!(handoff.transaction_status, OperationStatus::Applied);
    assert_eq!(handoff.finalized, Some(finalized));
    assert!(handoff.current.is_none() && handoff.activation().is_none());
    assert!(handoff_http.requests.lock().unwrap().is_empty());
    assert_eq!(
        std::fs::read(path.join("preparation.json"))
            .unwrap()
            .as_slice(),
        preparation_bytes.as_slice()
    );
    assert_eq!(
        std::fs::read(path.join("payload.json")).unwrap().as_slice(),
        payload_bytes.as_slice()
    );
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        operation_bytes
    );
    assert_eq!(
        ManagedInitialReservePolicy::verify_wallet(
            &account,
            original.directory(),
            &original,
            options.deadline
        )
        .unwrap()
        .encode_wire_v1()
        .unwrap(),
        wire,
    );
    assert!(!path.join("submission.json").exists());
    handoff_http.finish();
    drop(authorization);
    drop(bootstrap);
    drop(account);
    drop(directory);
    drop(coordinator);
    coordinator = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let mut unavailable = UnavailablePeers::start(&prepared);
    crate::managed::native_operation::test_support::assert_optional_current(
        &unavailable,
        &current_verifier,
        |verifier| {
            coordinator.read_current(&policy, verifier, Instant::now() + Duration::from_secs(30))
        },
    );
    let selected_options = original
        .terms
        .options(Instant::now() + Duration::from_secs(30));
    let selected_utc = original.terms.requested_deadline_unix_ms;
    let before_selected = unavailable.requests.lock().unwrap().len();
    let selected = coordinator
        .recover_selected_if_present(
            &policy,
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
        coordinator
            .recover_selected_if_present(
                &changed_policy,
                &Fees::from_options(&selected_options).unwrap(),
                selected_options.deadline
            )
            .is_err()
    );
    assert!(
        original
            .matches(&policy, selected_utc + 1, &selected_options)
            .is_err()
    );
    let mut changed_options = original.terms.options(selected_options.deadline);
    changed_options.max_total_fees.clear();
    assert!(
        coordinator
            .recover_selected_if_present(
                &policy,
                &Fees::from_options(&changed_options).unwrap(),
                changed_options.deadline
            )
            .is_err()
    );
    assert_eq!(unavailable.requests.lock().unwrap().len(), before_selected);
    assert!(selected.activation().is_none());
    let recovered = coordinator
        .recover(Instant::now() + Duration::from_secs(30))
        .unwrap();
    unavailable.finish();
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(recovered.finalized, Some(finalized));
    assert!(
        recovered.current.is_none() && recovered.activation().is_none(),
        "historical success is not fresh current activation during an outage"
    );
    assert!(
        !path.join("submission.json").exists(),
        "read-only coordinator recovery never dispatches"
    );
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        operation_bytes
    );
    let directory = coordinator.authority.directory.open_child("set").unwrap();
    assert_eq!(
        directory
            .read("original.nrt", original_bytes.len())
            .unwrap()
            .as_slice(),
        original_bytes.as_slice()
    );
    assert_eq!(
        ManagedInitialReservePolicy::verify_wallet(
            &AccountService::new(coordinator.authority.config.clone()).unwrap(),
            original.directory(),
            &original,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .encode_wire_v1()
        .unwrap(),
        wire
    );
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
