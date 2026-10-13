//! Actual bounded HTTP refusal and original wallet recovery; no mock response proves native facts.

use super::tests::{codec_original, fixture, options, policy};
use super::*;
use crate::managed::native_operation::attempts::metadata;
use crate::managed::native_operation::test_support::{UnavailablePeers, wallet_http::WalletHttp};
use iroha_data_model::transaction::FeePaymentIntent;
use std::{io, time::Duration};

#[test]
fn missing_capacity_original_recovery_reopens_without_http_or_journal_creation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        assert!(
            coordinator
                .recover(Instant::now() + Duration::from_secs(15))
                .is_err()
        );
        assert_eq!(
            coordinator
                .authority
                .directory
                .open_child("declare")
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        drop(coordinator);
        coordinator = ManagedProviderCapacity::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    peers.finish();
}

#[test]
fn invalid_capacity_policy_and_unavailable_finality_never_publish_or_quote() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let selected = policy(&coordinator);
    let mut wrong = selected.clone();
    wrong.decision_authority = wrong.operations_authority.clone();
    assert!(
        coordinator
            .declare(&wrong, now_ms().unwrap() + 600_000, &options())
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(
        coordinator
            .authority
            .directory
            .open_child("declare")
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    for _ in 0..2 {
        let error = coordinator
            .declare(&selected, now_ms().unwrap() + 600_000, &options())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot read original genesis result")
        );
        let directory = coordinator
            .authority
            .directory
            .open_child("declare")
            .unwrap();
        metadata::require_unselected(&directory).unwrap();
        assert_eq!(
            directory.open_child("transaction").err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert!(
            read_optional(
                &coordinator.authority.directory,
                "current-checkpoint.nrt",
                MAX_CHECKPOINT_BYTES
            )
            .unwrap()
            .is_none()
        );
        drop(coordinator);
        coordinator = ManagedProviderCapacity::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    assert!(requests.iter().all(|request| request.method == "GET"
        && matches!(
            request.path.as_str(),
            "/v1/node/capabilities" | "/v1/bridge/finality/1"
        )));
    for peer in 0..4 {
        for path in ["/v1/node/capabilities", "/v1/bridge/finality/1"] {
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.peer == peer && request.path == path)
                    .count(),
                2
            );
        }
    }
}

#[test]
fn unproved_capacity_checkpoint_refuses_before_http_and_preserves_original() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let original = codec_original(&coordinator);
    let directory =
        metadata::ensure_operation(&coordinator.authority.directory, "declare").unwrap();
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 600_000,
        &options(),
    );
    let bytes = directory.read("original.nrt", 512 * 1024).unwrap();
    for mode in [Advance::ObserveOnly, Advance::SubmitOriginal] {
        assert!(
            coordinator
                .advance_original(Instant::now() + Duration::from_secs(15), mode, true)
                .unwrap_err()
                .to_string()
                .contains("invalid retained native operation checkpoint")
        );
        assert_eq!(
            std::fs::metadata(original.directory().path().join("transaction/payload.json"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            directory
                .read("original.nrt", 512 * 1024)
                .unwrap()
                .as_slice(),
            bytes.as_slice()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    peers.finish();
}

#[test]
fn capacity_wallet503_reopen_preserves_original_wire_and_single_dispatch() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let directory =
        metadata::ensure_operation(&coordinator.authority.directory, "declare").unwrap();
    let original = codec_original(&coordinator);
    let options = options();
    // This codec-only original exercises wallet custody; no fake checkpoint enters advance.
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 600_000,
        &options,
    );
    let original_bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let path = original.directory().path().join("transaction");
    let owner = coordinator.authority.issuer_operator_config().unwrap();
    let mut http = WalletHttp::start_config(&owner, path.clone());
    let account = AccountService::new(owner).unwrap();
    let request = original.request(original.terms.signing_deadline(options.deadline).unwrap());
    assert_eq!(
        account
            .prepare_provider_capacity_declaration(&request, &path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let operation_bytes = std::fs::read(path.join("operation.json")).unwrap();
    let before = http.requests.lock().unwrap().len();
    let signed = coordinator
        .verify_wallet(original.directory(), &original, request.options.deadline)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), before);
    assert_eq!(signed.authority(), &original.selection.provider_account);
    assert_ne!(signed.authority(), &coordinator.authority.config.account);
    assert_ne!(signed.authority(), &original.selection.operations_authority);
    let wire = signed.encode_wire_v1().unwrap();
    assert_eq!(
        account
            .resume_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("submission.json").exists());
    // Changed requested spending terms must fail through the held exact journal before I/O.
    let before = http.requests.lock().unwrap().len();
    let mut changed = request.clone();
    changed.options.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        iroha_primitives::numeric::Quantity::from(1_u64),
    );
    assert!(
        account
            .submit_provider_capacity_declaration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.options.fee_payment =
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        account
            .submit_provider_capacity_declaration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.declaration.valid_until += 1;
    assert!(
        account
            .submit_provider_capacity_declaration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        account
            .submit_provider_capacity_declaration(&path, &changed)
            .is_err()
    );
    assert_eq!(http.requests.lock().unwrap().len(), before);
    assert!(!path.join("submission.json").exists());
    drop(account);
    drop(directory);
    let mut marker = None;
    for _ in 0..2 {
        drop(coordinator);
        coordinator = ManagedProviderCapacity::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let directory = coordinator
            .authority
            .directory
            .open_child("declare")
            .unwrap();
        let restored = journal::required_original(&directory).unwrap();
        let request = restored.request(Instant::now() + Duration::from_secs(900));
        assert_eq!(
            request.deadline_unix_ms,
            original.terms.signing_deadline_unix_ms
        );
        let before = http.requests.lock().unwrap().len();
        assert_eq!(
            coordinator
                .verify_wallet(restored.directory(), &restored, request.options.deadline)
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            wire
        );
        assert_eq!(http.requests.lock().unwrap().len(), before);
        let account =
            AccountService::new(coordinator.authority.issuer_operator_config().unwrap()).unwrap();
        assert_eq!(
            account
                .submit_provider_capacity_declaration(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            account
                .resume_provider_capacity_declaration(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        let retained_marker = std::fs::read(path.join("submission.json")).unwrap();
        if let Some(previous) = &marker {
            assert_eq!(previous, &retained_marker);
        } else {
            marker = Some(retained_marker);
        }
        assert_eq!(
            std::fs::read(path.join("operation.json")).unwrap(),
            operation_bytes
        );
        assert_eq!(
            directory
                .read("original.nrt", 256 * 1024)
                .unwrap()
                .as_slice(),
            original_bytes.as_slice()
        );
    }
    http.finish();
    let requests = http.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.path() == "/v1/fees/quote")
            .count(),
        1
    );
    let submissions: Vec<_> = requests
        .iter()
        .filter(|request| {
            request.target.path() == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path()
        })
        .collect();
    assert_eq!(submissions.len(), 1, "ambiguous dispatch must never resend");
    assert_eq!(submissions[0].body, wire);
    for request in requests
        .iter()
        .filter(|request| request.target.path() == "/v1/pipeline/transactions/status")
    {
        assert_eq!(
            request
                .target
                .query_pairs()
                .find(|(key, _)| key == "hash")
                .unwrap()
                .1
                .parse::<iroha_crypto::HashOf<SignedTransaction>>()
                .unwrap(),
            signed.hash()
        );
    }
}
