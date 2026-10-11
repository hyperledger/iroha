//! Real HTTP refusal and wallet journal recovery; no synthetic response establishes native state.

use super::tests::{fixture, options, policy, underwriting};
use super::*;
use crate::managed::native_operation::{
    MAX_CHECKPOINT_BYTES,
    test_support::{UnavailablePeers, wallet_http::WalletHttp},
};
use iroha_data_model::{
    account::AccountId, sorafs::capacity::ProviderId, transaction::FeePaymentIntent,
};
use std::{io, time::Duration};

fn unprepared_absent(coordinator: &ManagedReserveAccountRegistration) {
    assert_eq!(
        coordinator
            .authority
            .directory
            .open_child("register")
            .err()
            .unwrap()
            .kind(),
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
}

#[test]
fn missing_registration_original_recovery_reopens_without_http_or_journal_creation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        assert!(
            coordinator
                .recover(Instant::now() + Duration::from_secs(15))
                .is_err()
        );
        unprepared_absent(&coordinator);
        assert!(peers.requests.lock().unwrap().is_empty());
        drop(coordinator);
        coordinator = ManagedReserveAccountRegistration::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    peers.finish();
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn invalid_generated_registration_binding_refuses_before_http_or_original_publication() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let selected_policy = policy(&coordinator);
    let selected_terms = underwriting(&coordinator);
    let other = AccountId::new(
        iroha_crypto::KeyPair::try_from_seed(vec![81; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    for field in 0..9 {
        let mut policy = selected_policy.clone();
        let mut terms = selected_terms.clone();
        match field {
            0 => policy.operations_authority = other.clone(),
            1 => policy.decision_authority = other.clone(),
            2 => policy.custody_account = other.clone(),
            3 => policy.treasury_account = other.clone(),
            4 => {
                policy.asset_definition = AssetDefinitionId::from_uuid_bytes([
                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x48, 0x99, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ])
                .unwrap()
            }
            5 => terms.provider_id = ProviderId::new([82; 32]),
            6 => terms.provider_account = other.clone(),
            7 => terms.capacity_gib = 0,
            _ => {
                policy.revision = 2;
                policy.predecessor_policy_digest = None;
            }
        }
        assert!(
            coordinator
                .register(&policy, &terms, now_ms().unwrap() + 600_000, &options())
                .is_err(),
            "binding {field}"
        );
        unprepared_absent(&coordinator);
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    peers.finish();
}

#[test]
fn unavailable_registration_finality_never_prepares_quotes_or_dispatches() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let policy = policy(&coordinator);
    let terms = underwriting(&coordinator);
    let deadline = now_ms().unwrap() + 600_000;
    for _ in 0..2 {
        let error = coordinator
            .register(&policy, &terms, deadline, &options())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot read original genesis result")
        );
        let directory = coordinator
            .authority
            .directory
            .open_child("register")
            .unwrap();
        require_empty(&directory).unwrap();
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
        let count = peers.requests.lock().unwrap().len();
        assert!(
            coordinator
                .recover(Instant::now() + Duration::from_secs(15))
                .is_err()
        );
        assert_eq!(peers.requests.lock().unwrap().len(), count);
        require_empty(&directory).unwrap();
        drop(directory);
        drop(coordinator);
        coordinator = ManagedReserveAccountRegistration::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    for request in requests.iter() {
        assert_eq!(request.method, "GET");
        assert!(matches!(
            request.path.as_str(),
            "/v1/node/capabilities" | "/v1/bridge/finality/1"
        ));
    }
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
fn unproved_registration_checkpoint_cannot_advance_or_recover_a_wallet() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let policy = policy(&coordinator);
    let underwriting = underwriting(&coordinator);
    let original = Original {
        selection: coordinator.selection(&policy, &underwriting).unwrap(),
        policy,
        underwriting,
        checkpoint: vec![0x5a; 16 * 1024],
    };
    // This is a local canonical record only: the fake checkpoint must fail before any HTTP.
    let directory = coordinator
        .authority
        .directory
        .ensure_child("register")
        .unwrap();
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 600_000,
        &options(),
    );
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    for mode in [Advance::ObserveOnly, Advance::SubmitOriginal] {
        let error = coordinator
            .advance_original(Instant::now() + Duration::from_secs(15), mode, true)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid retained native operation checkpoint")
        );
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
        assert_eq!(
            directory
                .read("original.nrt", 256 * 1024)
                .unwrap()
                .as_slice(),
            bytes.as_slice()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    for changed_network in [false, true] {
        let mut changed = original.clone();
        if changed_network {
            changed.selection.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"different actual genesis digest",
                )),
            );
        } else {
            changed.selection.chain_id.push_str("-different");
        }
        assert!(
            coordinator
                .validate_original(&changed)
                .unwrap_err()
                .to_string()
                .contains("original reserve registration differs from authenticated generation")
        );
    }
    peers.finish();
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn registration_wallet503_reopen_preserves_original_wire_and_single_dispatch() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, mut coordinator) = fixture();
    let directory = coordinator
        .authority
        .directory
        .ensure_child("register")
        .unwrap();
    let policy = policy(&coordinator);
    let underwriting = underwriting(&coordinator);
    let options = options();
    let original = Original {
        selection: coordinator.selection(&policy, &underwriting).unwrap(),
        policy,
        underwriting,

        // Codec-only checkpoint: this test exercises the real journal and HTTP wallet, never
        // coordinator advance or any native registration/finality/partition claim.
        checkpoint: vec![1],
    };
    let original = super::tests::retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 600_000,
        &options,
    );
    let original_bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let path = original.directory().path().join("transaction");
    let operator = coordinator.authority.reserve_operations_config().unwrap();
    let mut http = WalletHttp::start_config(&operator, path.clone());
    let account = AccountService::new(operator).unwrap();
    let request = original.request(original.terms.signing_deadline(options.deadline).unwrap());
    assert_eq!(
        account
            .prepare_reserve_account_registration(&request, &path)
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
    assert_eq!(signed.authority(), &original.selection.operations_authority);
    assert_ne!(signed.authority(), &coordinator.authority.config.account);
    let wire = signed.encode_wire_v1().unwrap();
    assert_eq!(
        account
            .resume_reserve_account_registration(&path, &request)
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
            .submit_reserve_account_registration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.options.fee_payment =
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        account
            .submit_reserve_account_registration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.underwriting.capacity_gib += 1;
    assert!(
        account
            .submit_reserve_account_registration(&path, &changed)
            .is_err()
    );
    changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        account
            .submit_reserve_account_registration(&path, &changed)
            .is_err()
    );
    assert_eq!(http.requests.lock().unwrap().len(), before);
    assert!(!path.join("submission.json").exists());
    drop(account);
    drop(directory);
    let mut marker = None;
    for _ in 0..2 {
        drop(coordinator);
        coordinator = ManagedReserveAccountRegistration::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let directory = coordinator
            .authority
            .directory
            .open_child("register")
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
            AccountService::new(coordinator.authority.reserve_operations_config().unwrap())
                .unwrap();
        assert_eq!(
            account
                .submit_reserve_account_registration(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            account
                .resume_reserve_account_registration(&path, &request)
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

#[test]
fn generated_registration_retains_underwriting_and_refuses_drift_without_profile_reparse() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, coordinator) = fixture();
    let provider = coordinator.authority.provider_id().unwrap();
    // The real startup issuer must inspect child custody without another owner holding its lock.
    drop(coordinator);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut parent =
        crate::managed::service_bootstrap::ManagedServiceBootstrap::open(&prepared).unwrap();
    let options = options();
    let authorization = parent.authorize_test_startup(&options).unwrap().unwrap();
    let child = authorization
        .test_child(Purpose::ReserveAccount(provider))
        .unwrap();
    let policy = child.policies().network.reserve.clone();
    let mut coordinator = ManagedReserveAccountRegistration::open(&prepared, provider).unwrap();
    let underwriting = coordinator
        .authority
        .provider_plan()
        .unwrap()
        .reserve_terms()
        .clone();
    let mut changed = underwriting.clone();
    changed.capacity_gib += 1;
    let (error, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        coordinator
            .advance_selected(&policy, &changed, &child, options.deadline)
            .unwrap_err()
    });
    assert_eq!(parses, 0);
    assert!(
        error
            .to_string()
            .contains("reserve registration differs from authorized policy or underwriting")
    );
    unprepared_absent(&coordinator);
    assert!(peers.requests.lock().unwrap().is_empty());

    let generation =
        iroha_fs::PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = original.clone();
    changed.extend_from_slice(b"\n# changed original before selected registration\n");
    generation
        .write_atomic("peer3.toml", &changed, iroha_fs::PublishMode::Replace)
        .unwrap();
    let (result, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        coordinator.advance_selected(&policy, &underwriting, &child, options.deadline)
    });
    assert!(result.is_err());
    assert_eq!(parses, 0);
    unprepared_absent(&coordinator);
    assert!(peers.requests.lock().unwrap().is_empty());
    generation
        .write_atomic("peer3.toml", &original, iroha_fs::PublishMode::Replace)
        .unwrap();
    coordinator.authority.validate_profile().unwrap();
    assert_eq!(
        coordinator
            .authority
            .provider_plan()
            .unwrap()
            .reserve_terms(),
        &underwriting
    );
    peers.finish();
    assert!(peers.requests.lock().unwrap().is_empty());
}
