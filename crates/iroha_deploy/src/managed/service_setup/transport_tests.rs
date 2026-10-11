//! Real bounded loopback refusals before signing; no transport response invents native proof.
use super::tests::{fixture, gateway, ingest, options, reputation, reputation_labels};
use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::test_support::UnavailablePeers;
use std::{io, time::Duration};

#[test]
fn missing_original_recovery_for_both_purposes_is_offline_and_noncreating() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut gateway_owner = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut recorder_owner = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        assert!(
            gateway_owner
                .recover(Instant::now() + Duration::from_secs(15))
                .is_err()
        );
        assert!(
            recorder_owner
                .recover(Instant::now() + Duration::from_secs(15))
                .is_err()
        );
        for owner in [&gateway_owner.inner, &recorder_owner.inner] {
            assert_eq!(
                owner
                    .authority
                    .directory
                    .open_child("setup")
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotFound
            );
        }
        assert!(peers.requests.lock().unwrap().is_empty());
        drop(gateway_owner);
        drop(recorder_owner);
        gateway_owner = ManagedInitialGatewaySetup::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        recorder_owner = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    }
    peers.finish();
}

#[test]
fn unavailable_native_finality_prevents_both_originals_quotes_and_dispatch() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut gateway_owner = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut recorder_owner = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    let gateway = gateway(
        &gateway_owner.inner.authority,
        crate::managed::native_operation::test_support::provider_id(
            &gateway_owner.inner.authority.prepared,
            0,
        ),
    );
    let recorder = reputation(
        &recorder_owner.inner.authority,
        &reputation_labels(&prepared),
    );
    let mut peers = UnavailablePeers::start(&prepared);
    for result in [
        gateway_owner.configure(&gateway, now_ms().unwrap() + 120_000, &options()),
        recorder_owner.set_initial(
            &reputation_labels(&prepared),
            &recorder,
            now_ms().unwrap() + 120_000,
            &options(),
        ),
    ] {
        let error = result.err().expect("native finality missing");
        assert!(
            error
                .to_string()
                .contains("cannot read original genesis result"),
            "{error}"
        );
    }
    for owner in [&gateway_owner.inner, &recorder_owner.inner] {
        let directory = owner.authority.directory.open_child("setup").unwrap();
        require_empty(&directory).unwrap();
        assert_eq!(
            directory.open_child("transaction").err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
    }
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    assert!(requests.iter().any(|r| r.path == "/v1/bridge/finality/1"));
    assert!(
        requests.iter().all(|r| r.method == "GET"
            && r.path != "/v1/fees/quote"
            && r.path != "/v1/transaction")
    );
}

#[test]
fn changed_generated_roles_refuse_before_http_or_original_publication() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut owner = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut policy = gateway(
        &owner.inner.authority,
        crate::managed::native_operation::test_support::provider_id(
            &owner.inner.authority.prepared,
            0,
        ),
    );
    policy.operators =
        std::collections::BTreeSet::from([owner.inner.authority.config.account.clone()]);
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    assert!(
        owner
            .configure(&policy, now_ms().unwrap() + 60_000, &options())
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(
        owner
            .inner
            .authority
            .directory
            .open_child("setup")
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    peers.finish();
}

#[test]
fn all_closed_wallet_dispatches_keep_exact_wire_once_only_after_ambiguous_http_and_reopen() {
    use crate::managed::native_operation::test_support::wallet_http::WalletHttp;
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    for kind in [Kind::Gateway, Kind::Reputation, Kind::ProviderIngest] {
        let mut owner = match kind {
            Kind::Reputation => Setup::open_reputation(&prepared),
            Kind::Gateway | Kind::ProviderIngest => Setup::open_provider(
                &prepared,
                crate::managed::native_operation::test_support::provider_id(&prepared, 0),
                kind,
            ),
        }
        .unwrap();
        let gateway = gateway(
            &owner.authority,
            crate::managed::native_operation::test_support::provider_id(
                &owner.authority.prepared,
                0,
            ),
        );
        let intent = match kind {
            Kind::ProviderIngest => {
                Intent::provider_ingest(&owner.authority, &ingest(&owner.authority)).unwrap()
            }
            Kind::Gateway => Intent::gateway(&owner.authority, &gateway).unwrap(),
            Kind::Reputation => Intent::reputation(
                &owner.authority,
                &reputation_labels(&prepared),
                &reputation(&owner.authority, &reputation_labels(&prepared)),
            )
            .unwrap(),
        };
        let opts = options();
        // Codec-only intent exercises exact wallet conversion and custody. This intentionally
        // invalid checkpoint is never accepted as native authority or passed to coordinator advance.
        let original = Original {
            intent,
            checkpoint: vec![1],
        };
        let directory = owner.authority.directory.ensure_child("setup").unwrap();
        let utc = now_ms().unwrap() + 600_000;
        let original =
            super::tests::retain_explicit_request(&owner, &directory, &original, || utc, &opts);
        let original_bytes = std::fs::read(directory.path().join("original.nrt")).unwrap();
        let path = original.directory().path().join("transaction");
        let mut http = WalletHttp::start_config(&owner.wallet_config().unwrap(), path.clone());
        let account = owner.wallet().unwrap();
        let request = original.request(original.terms.signing_deadline(opts.deadline).unwrap());
        assert_eq!(
            request.prepare(&account, &path).unwrap().status,
            OperationStatus::Prepared
        );
        let operation = std::fs::read(path.join("operation.json")).unwrap();
        let count = http.requests.lock().unwrap().len();
        let inspected = request.inspect(&account, &path).unwrap();
        assert_eq!(
            inspected.phase(),
            iroha_wallet::operations::NativePreparationPhase::Signed
        );
        let inspected_wire = inspected
            .into_signed_transaction()
            .unwrap()
            .encode_wire_v1()
            .unwrap();
        assert_eq!(http.requests.lock().unwrap().len(), count);
        let signed = owner
            .verify_wallet(original.directory(), &original, opts.deadline)
            .unwrap();
        assert_eq!(http.requests.lock().unwrap().len(), count);
        let wire = signed.encode_wire_v1().unwrap();
        assert_eq!(inspected_wire, wire);
        assert_eq!(
            request.resume(&account, &path).unwrap().status,
            OperationStatus::Absent
        );
        assert!(!path.join("submission.json").exists());
        drop(account);
        let mut marker = None;
        for _ in 0..2 {
            drop(owner);
            owner = match kind {
                Kind::Reputation => Setup::open_reputation(&prepared),
                Kind::Gateway | Kind::ProviderIngest => Setup::open_provider(
                    &prepared,
                    crate::managed::native_operation::test_support::provider_id(&prepared, 0),
                    kind,
                ),
            }
            .unwrap();
            let original =
                journal::required_original(&directory, owner.purpose().unwrap()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(300);
            assert_eq!(
                owner
                    .verify_wallet(original.directory(), &original, deadline)
                    .unwrap()
                    .encode_wire_v1()
                    .unwrap(),
                wire
            );
            let request = original.request(deadline);
            let account = owner.wallet().unwrap();
            assert_eq!(
                request.submit(&account, &path).unwrap().status,
                OperationStatus::Pending
            );
            assert_eq!(
                request.resume(&account, &path).unwrap().status,
                OperationStatus::Pending
            );
            let retained = std::fs::read(path.join("submission.json")).unwrap();
            if let Some(before) = &marker {
                assert_eq!(before, &retained)
            } else {
                marker = Some(retained)
            };
            assert_eq!(
                std::fs::read(path.join("operation.json")).unwrap(),
                operation
            );
            assert_eq!(
                std::fs::read(directory.path().join("original.nrt")).unwrap(),
                original_bytes
            );
        }
        http.finish();
        let requests = http.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.target.path() == "/v1/fees/quote")
                .count(),
            1
        );
        let posted: Vec<_> = requests
            .iter()
            .filter(|r| {
                r.target.path() == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path()
            })
            .collect();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].body, wire);
        for r in requests
            .iter()
            .filter(|r| r.target.path() == "/v1/pipeline/transactions/status")
        {
            assert_eq!(
                r.target
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
}

#[test]
fn provider_ingest_missing_original_and_wrong_roles_are_offline_but_finality_refuses_before_quote()
{
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut owner = ManagedInitialProviderIngestAuthority::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let selected = ingest(&owner.inner.authority);
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        assert!(owner.recover(options().deadline).is_err());
        assert!(
            owner
                .recover_selected_if_present(
                    &selected,
                    &Fees::from_options(&options()).unwrap(),
                    options().deadline
                )
                .unwrap()
                .is_none()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        assert!(owner.inner.authority.directory.open_child("setup").is_err());
        drop(owner);
        owner = ManagedInitialProviderIngestAuthority::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    for field in 0..2 {
        let mut changed = selected.clone();
        if field == 0 {
            changed.provider_owner = owner.inner.authority.config.account.clone();
        } else {
            changed.completion_signer = changed.provider_owner.clone();
        }
        assert!(
            owner
                .set_initial(&changed, now_ms().unwrap() + 60_000, &options())
                .is_err()
        );
        assert!(owner.inner.authority.directory.open_child("setup").is_err());
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    assert!(
        owner
            .set_initial(&selected, now_ms().unwrap() + 60_000, &options())
            .unwrap_err()
            .to_string()
            .contains("cannot read original genesis result")
    );
    let directory = owner.inner.authority.directory.open_child("setup").unwrap();
    require_empty(&directory).unwrap();
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    assert!(requests.iter().any(|r| r.path == "/v1/bridge/finality/1"));
    assert!(
        requests.iter().all(|r| r.method == "GET"
            && r.path != "/v1/fees/quote"
            && r.path != "/v1/transaction")
    );
    assert!(directory.open_child("transaction").is_err());
}
