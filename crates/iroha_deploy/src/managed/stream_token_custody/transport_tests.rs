//! Real HTTP refusal before initial intent publication; this is not recovery/finality qualification.

use super::*;
use crate::managed::native_operation::attempts::metadata;
use crate::managed::native_operation::test_support::UnavailablePeers;
use iroha_data_model::transaction::FeePaymentIntent;
use sorafs_manifest::signer::{
    custody::SignerCustodyAuthorityV1,
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};
use std::{collections::BTreeMap, io};
const FINALITY_PATH: &str = "/v1/bridge/finality/1";

pub(super) fn policy(coordinator: &ManagedStreamTokenCustody) -> SignerCustodyPolicyV1 {
    let now = now_ms().unwrap();
    SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: coordinator.authority.config.chain.to_string(),
            network_id: *coordinator.authority.config.network_id.as_bytes(),
            runtime_handle: "software://stream/runtime".into(),
            key_handle: "software://stream/key".into(),
            service_id: "stream-service".into(),
            administrator_id: "stream-admin".into(),
            role: SignerRoleV1::StreamToken,
            purpose: SignerPurposeBindingV1::StreamToken {
                provider_id: *coordinator.authority.provider_id().unwrap().as_bytes(),
            },
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: coordinator
                .authority
                .provider_role(StreamTokenAuthorityRole::TokenSigner)
                .unwrap()
                .try_signatory()
                .unwrap()
                .clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [4; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: "custody-service".into(),
            administrator_id: "custody-admin".into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [5; 32],
        },
        attester_public_key: coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::CustodyAttester)
            .unwrap()
            .try_signatory()
            .unwrap()
            .clone(),
        active_from_unix_ms: now - 1_000,
        active_until_unix_ms: now + 300_000,
        max_validity_ms: 60_000,
        max_anchor_age_ms: 30_000,
    }
}

#[test]
fn unavailable_finality_over_http_cannot_publish_intent_quote_or_dispatch() {
    let _resources = crate::managed::native_test_guard();
    // Respect the validation runner's private temporary directory on every platform.
    let temporary = tempfile::Builder::new()
        .prefix(".custody-http-")
        .tempdir()
        .unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "custody-http",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut coordinator = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let policy = policy(&coordinator);
    coordinator.validate_policy(&policy).unwrap();
    drop(ports);
    let mut peers = UnavailablePeers::start(&prepared);
    let utc_deadline = now_ms().unwrap() + 60_000;
    for _ in 0..2 {
        let options = BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(15),
        };
        let error = coordinator
            .configure(&policy, utc_deadline, &options)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot read original genesis result")
        );
        let directory = coordinator
            .authority
            .directory
            .open_child("configure")
            .unwrap();
        assert!(journal::read_original(&directory).unwrap().is_none());
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
        coordinator = ManagedStreamTokenCustody::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
    }
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    for request in requests.iter() {
        assert_eq!(
            request.method, "GET",
            "no transaction or quote POST is allowed"
        );
        assert!(
            matches!(
                request.path.as_str(),
                "/v1/node/capabilities" | FINALITY_PATH
            ),
            "no wallet quote, status, dispatch or custody read before finality: {}",
            request.path
        );
    }
    for peer in 0..4 {
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.peer == peer && request.path == FINALITY_PATH)
                .count(),
            2,
            "each refusal must try every independently selected original peer"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.peer == peer && request.path == "/v1/node/capabilities")
                .count(),
            2,
            "each reopened client must admit the real capabilities response before requesting finality"
        );
    }
}

#[test]
fn selected_custody_recovery_distinguishes_absent_empty_and_dirty_without_http() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "custody-selected",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut owner = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let policy = policy(&owner);
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    drop(ports);
    let mut peers = UnavailablePeers::start(&prepared);
    for dirty in 0..4 {
        let configure = owner.recover_configure_selected_if_present(
            &policy,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        );
        let enroll = owner.recover_enroll_selected_if_present(
            &policy,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        );
        if dirty == 3 {
            assert!(configure.is_err() && enroll.is_err());
        } else if dirty == 1 || dirty == 2 {
            if dirty == 1 {
                assert!(
                    matches!(configure, Err(crate::managed::Error::Invalid(message))
                    if message == "operation metadata image is absent")
                );
            } else {
                assert!(configure.unwrap().is_none());
            }
            // Enroll publishes its root with the original selection and anchor atomically.
            // An existing empty root is custody loss, never a fresh preflight directory.
            assert!(matches!(
                enroll,
                Err(crate::managed::Error::Bootstrap(
                    ManagedBootstrapFailure::RetainedMaterial
                ))
            ));
        } else {
            assert!(configure.unwrap().is_none() && enroll.unwrap().is_none());
        }
        for name in ["configure", "enroll"] {
            if dirty == 0 {
                assert!(!owner.authority.directory.path().join(name).exists());
                owner.authority.directory.ensure_child(name).unwrap();
            } else {
                let directory = owner.authority.directory.open_child(name).unwrap();
                assert!(!directory.path().join("transaction").exists());
                if dirty == 1 {
                    crate::managed::native_operation::require_empty(&directory).unwrap();
                    if name == "configure" {
                        let path = directory.path().to_path_buf();
                        drop(directory);
                        std::fs::remove_dir(&path).unwrap();
                        metadata::ensure_operation(&owner.authority.directory, name).unwrap();
                    }
                } else if dirty == 2 {
                    if name == "configure" {
                        metadata::require_unselected(&directory).unwrap();
                    } else {
                        crate::managed::native_operation::require_empty(&directory).unwrap();
                    }
                    directory
                        .write_atomic("incomplete.nrt", &[1], PublishMode::CreateNew)
                        .unwrap();
                } else {
                    assert_eq!(
                        directory.read("incomplete.nrt", 1).unwrap().as_slice(),
                        &[1]
                    );
                }
            }
        }
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
