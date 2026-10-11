//! Original service plans reuse one canonical parse while every access rechecks complete custody.

use super::*;
use iroha_fs::PublishMode;

#[test]
fn retained_service_plans_parse_once_and_refuse_original_byte_drift_on_every_access() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = super::super::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "retained-plan",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let [plan, _, _] = prepared.provider_service_plans().unwrap().unwrap();
    let provider = plan.provider_id();
    let (authority, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ServiceAuthority::open_provider(&prepared, provider, ProviderPurpose::Custody).unwrap()
        });
    assert_eq!(parses, 1);
    let (_, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        for _ in 0..3 {
            authority.validate_profile().unwrap();
            assert!(authority.provider_plans().is_err());
            assert!(authority.publication_plan().is_err());
            assert!(authority.gateway_compliance_plan(provider).is_ok());
            assert!(
                authority
                    .gateway_compliance_plan(authority.manifest.providers[1].provider_id)
                    .is_err()
            );
            let retained = authority.provider_plan().unwrap();
            assert_eq!(retained.provider_id(), provider);
            assert_eq!(retained.network_id(), plan.network_id());
            assert_eq!(
                retained.original_profile_commitment(),
                plan.original_profile_commitment()
            );
            assert_eq!(retained.admission_material(), plan.admission_material());
            assert_eq!(retained.declaration(), plan.declaration());
            assert_eq!(retained.pricing(), plan.pricing());
            assert_eq!(
                authority.issuer_operator_config().unwrap().account,
                *authority
                    .provider_role(StreamTokenAuthorityRole::IssuerOperator)
                    .unwrap()
            );
        }
        let generation =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# semantic no-op still changes exact original image\n");
        generation
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
        assert!(authority.validate_profile().is_err());
        assert!(authority.provider_plan().is_err());
        assert!(authority.issuer_operator_config().is_err());
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        authority.validate_profile().unwrap();
        assert_eq!(
            authority
                .provider_plan()
                .unwrap()
                .original_profile_commitment(),
            plan.original_profile_commitment()
        );
    });
    assert_eq!(parses, 0);
}

#[test]
fn retained_network_plans_refuse_complete_input_and_native_custody_drift_without_reparse() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = super::super::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "retained-network-plan",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let expected = prepared.provider_service_plans().unwrap().unwrap();
    let provider = expected[0].provider_id();
    let expected_compliance = prepared.gateway_compliance_plan(provider).unwrap().unwrap();
    let expected_publication = prepared.publication_service_plan().unwrap().unwrap();
    let (mut authority, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap()
        });
    assert_eq!(parses, 1);
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let runtime = generation.open_child("runtime").unwrap();
    let keys = runtime
        .open_child("stream-token-authorities")
        .unwrap()
        .open_child("providers")
        .unwrap()
        .open_child("2")
        .unwrap();
    // A mutable SDK client projection is not the retained original publication intent.
    let original_chain = authority.config.chain.clone();
    let original_discriminant = authority.config.account_chain_discriminant;
    authority.config.chain = "different-publication-projection".parse().unwrap();
    authority.config.account_chain_discriminant ^= 1;
    let (publication, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            authority.publication_plan().unwrap()
        });
    assert_eq!(parses, 0);
    assert_eq!(publication.chain_id(), expected_publication.chain_id());
    assert_eq!(
        publication.configuration_table().unwrap(),
        expected_publication.configuration_table().unwrap()
    );
    authority.config.chain = original_chain;
    authority.config.account_chain_discriminant = original_discriminant;
    let accept = || {
        let plans = authority.provider_plans().unwrap();
        for (selected, expected) in plans.iter().zip(&expected) {
            assert_eq!(selected.provider_id(), expected.provider_id());
            assert_eq!(selected.network_id(), expected.network_id());
            assert_eq!(selected.slot(), expected.slot());
            assert_eq!(
                selected.original_profile_commitment(),
                expected.original_profile_commitment()
            );
            assert_eq!(selected.admission_material(), expected.admission_material());
            assert_eq!(selected.reserve_terms(), expected.reserve_terms());
            assert_eq!(selected.declaration(), expected.declaration());
            assert_eq!(selected.pricing(), expected.pricing());
        }
        let publication = authority.publication_plan().unwrap();
        assert_eq!(publication.network_id(), expected_publication.network_id());
        assert_eq!(publication.chain_id(), expected_publication.chain_id());
        assert_eq!(
            publication.seed_provider(),
            expected_publication.seed_provider()
        );
        assert_eq!(publication.session_id(), expected_publication.session_id());
        assert_eq!(
            publication.provider_admission_material(),
            expected_publication.provider_admission_material()
        );
        assert_eq!(
            publication.configuration_table().unwrap(),
            expected_publication.configuration_table().unwrap()
        );
        let compliance = authority.gateway_compliance_plan(provider).unwrap();
        assert_eq!(compliance.network_id(), expected_compliance.network_id());
        assert_eq!(
            compliance.original_commitment(),
            expected_compliance.original_commitment()
        );
        assert_eq!(
            compliance.trust_policy(),
            expected_compliance.trust_policy()
        );
        assert_eq!(compliance.gateway_id(), expected_compliance.gateway_id());
        assert_eq!(
            compliance.gateway_label(),
            expected_compliance.gateway_label()
        );
        assert_eq!(
            compliance.issued_at_unix(),
            expected_compliance.issued_at_unix()
        );
        assert_eq!(
            compliance.expires_at_unix(),
            expected_compliance.expires_at_unix()
        );
    };
    let refuse = || {
        assert!(authority.provider_plans().is_err());
        assert!(authority.gateway_compliance_plan(provider).is_err());
        assert!(authority.publication_plan().is_err());
    };
    let (_, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        accept();
        let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# exact original bytes changed\n");
        generation
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
        refuse();
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        accept();

        // Loss of an unrelated transitive private input must not reuse the old positive image.
        let key = runtime.read("onboarding-signer.key", 4096).unwrap();
        std::fs::remove_file(runtime.path().join("onboarding-signer.key")).unwrap();
        refuse();
        runtime
            .write_atomic("onboarding-signer.key", &key, PublishMode::CreateNew)
            .unwrap();
        accept();

        keys.write_atomic(
            "unexpected.key",
            b"closed namespace changed",
            PublishMode::CreateNew,
        )
        .unwrap();
        refuse();
        std::fs::remove_file(keys.path().join("unexpected.key")).unwrap();
        accept();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = runtime.path().join("onboarding-signer.key");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            refuse();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            accept();

            // Returning identical public paths cannot replace an original native directory.
            let moved = temporary.path().join("displaced-generation");
            std::fs::rename(generation.path(), &moved).unwrap();
            std::fs::create_dir(generation.path()).unwrap();
            refuse();
            std::fs::remove_dir(generation.path()).unwrap();
            std::fs::rename(&moved, generation.path()).unwrap();
            accept();
        }
        #[cfg(unix)]
        {
            // A different inode with the exact same lock bytes does not retain operation custody.
            authority
                .directory
                .write_atomic("operation.lock", b"", PublishMode::Replace)
                .unwrap();
            refuse();
        }
        #[cfg(windows)]
        {
            // Native sharing denies replacement while the original lock is held.
            let original = iroha_fs::FileIdentity::of(&authority._lock).unwrap();
            assert!(
                authority
                    .directory
                    .write_atomic("operation.lock", b"", PublishMode::Replace)
                    .is_err()
            );
            assert_eq!(
                iroha_fs::FileIdentity::of(&authority._lock).unwrap(),
                original
            );
            assert_eq!(
                iroha_fs::FileIdentity::of(
                    &authority.directory.open_read("operation.lock").unwrap()
                )
                .unwrap(),
                original
            );
            accept();
        }
    });
    assert_eq!(parses, 0);
}
