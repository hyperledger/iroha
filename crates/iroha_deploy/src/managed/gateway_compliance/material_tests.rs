//! Fixed original ACK material and opaque local observation bindings; no native serving claim.

use super::*;
use crate::localnet::{LocalnetServiceProfile, prepare_localnet_at};

fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "compliance-ack-material",
        &directory.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (directory, prepared)
}

fn observation(
    plan: &RetainedGatewayCompliancePlan,
    catalog: &GatewayComplianceCatalogV1,
    time: u64,
) -> ObservedGatewayCatalog {
    // Only this unit fixture manufactures the private observation. The production constructor
    // remains inside advance, after owned-child validation and exact staged-candidate readback.
    ObservedGatewayCatalog {
        network: plan.network_id(),
        policy: plan.trust_policy().canonical_digest().unwrap(),
        catalog: catalog.payload.catalog_digest().unwrap(),
        observed_at: time,
    }
}

#[test]
fn acknowledgement_binds_original_gateway_key_catalog_network_policy_and_live_interval() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let originals = prepared.stream_token_authorities().unwrap().unwrap();
    for original in &originals.providers {
        let provider = original.provider_id;
        let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
        let authority = &publisher.authority;
        let plan = authority.gateway_compliance_plan(provider).unwrap();
        let now = now_ms().unwrap() / 1_000;
        let catalog = authority
            .sign_gateway_compliance_catalog(None, now)
            .unwrap();
        authority
            .validate_generated_gateway_catalog(&catalog)
            .unwrap();
        let observed = observation(&plan, &catalog, now);
        let ack = authority
            .sign_observed_gateway_catalog(&observed, &catalog)
            .unwrap();
        assert_eq!(ack.payload.gateway_id, plan.gateway_label());
        assert_eq!(ack.payload.observed_at_unix, now);
        assert!(ack.payload.accepted);
        assert!(ack.payload.rejection_code.is_none());
        ack.verify(plan.trust_policy(), observed.catalog(), now, 0)
            .unwrap();
        assert_eq!(
            encode(&ack, MAX_RECORD_BYTES).unwrap(),
            encode(
                &authority
                    .sign_observed_gateway_catalog(&observed, &catalog)
                    .unwrap(),
                MAX_RECORD_BYTES,
            )
            .unwrap()
        );
        assert_eq!(observed.network(), plan.network_id());
        assert_eq!(
            observed.policy(),
            plan.trust_policy().canonical_digest().unwrap()
        );
        assert_eq!(observed.observed_at(), now);
        // The observation can expire while the genuine original catalog remains valid. This
        // pure check exercises that independent limit without replacing the signing clock.
        assert!(observed.is_fresh_at(now));
        assert!(observed.is_fresh_at(now + 30));
        assert!(now + 31 < catalog.payload.valid_until_unix);
        assert!(!observed.is_fresh_at(now + 31));
        assert!(!observed.is_fresh_at(now - 1));

        let mut changed = observation(&plan, &catalog, now);
        changed.policy[0] ^= 1;
        assert!(
            authority
                .sign_observed_gateway_catalog(&changed, &catalog)
                .is_err()
        );
        let mut changed = observation(&plan, &catalog, now);
        changed.catalog[0] ^= 1;
        assert!(
            authority
                .sign_observed_gateway_catalog(&changed, &catalog)
                .is_err()
        );
        let mut changed = observation(&plan, &catalog, now);
        changed.network =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"another generated genesis"),
            ));
        assert!(
            authority
                .sign_observed_gateway_catalog(&changed, &catalog)
                .is_err()
        );
        let future = observation(&plan, &catalog, now_ms().unwrap() / 1_000 + 60);
        assert!(
            authority
                .sign_observed_gateway_catalog(&future, &catalog)
                .is_err()
        );
        let stale = observation(&plan, &catalog, now.saturating_sub(31));
        assert!(
            authority
                .sign_observed_gateway_catalog(&stale, &catalog)
                .is_err()
        );

        let mut broken = catalog.clone();
        broken.approvals[0].signature[0] ^= 1;
        assert!(
            authority
                .validate_generated_gateway_catalog(&broken)
                .is_err()
        );
        assert!(
            authority
                .sign_observed_gateway_catalog(&observed, &broken)
                .is_err()
        );
        let mut oversized = catalog.clone();
        oversized.approvals = vec![catalog.approvals[0].clone(); MAX_RECORD_BYTES / 64 + 1];
        assert!(
            authority
                .validate_generated_gateway_catalog(&oversized)
                .is_err()
        );
        assert!(
            authority
                .sign_observed_gateway_catalog(&observed, &oversized)
                .is_err()
        );
        assert_eq!(
            prepared
                .gateway_compliance_plan(provider)
                .unwrap()
                .unwrap()
                .expires_at_unix(),
            plan.expires_at_unix()
        );
        let other = originals.providers[(usize::from(original.slot) + 1) % 3].provider_id;
        let other_publisher = ManagedGatewayCompliance::open(&prepared, other).unwrap();
        assert!(
            other_publisher
                .authority
                .validate_generated_gateway_catalog(&catalog)
                .is_err()
        );
        assert!(
            other_publisher
                .authority
                .sign_observed_gateway_catalog(&observed, &catalog)
                .is_err()
        );
    }
}

#[test]
fn acknowledgement_refuses_substituted_original_private_material() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[2]
        .provider_id;
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let authority = &publisher.authority;
    let plan = authority.gateway_compliance_plan(provider).unwrap();
    let now = now_ms().unwrap() / 1_000;
    let catalog = authority
        .sign_gateway_compliance_catalog(None, now)
        .unwrap();
    let observed = observation(&plan, &catalog, now);
    let root =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let keys = root
        .open_child("runtime")
        .unwrap()
        .open_child("stream-token-authorities")
        .unwrap()
        .open_child("providers")
        .unwrap()
        .open_child("2")
        .unwrap();
    let ack = keys.read("compliance-gateway.key", 4096).unwrap().to_vec();
    let governance = keys.read("compliance-catalog-0.key", 4096).unwrap();
    keys.write_atomic("compliance-gateway.key", &governance, PublishMode::Replace)
        .unwrap();
    assert!(
        authority
            .sign_observed_gateway_catalog(&observed, &catalog)
            .is_err()
    );
    keys.write_atomic("compliance-gateway.key", &ack, PublishMode::Replace)
        .unwrap();
    let observed = observation(&plan, &catalog, now_ms().unwrap() / 1_000);
    authority
        .sign_observed_gateway_catalog(&observed, &catalog)
        .unwrap();
}

/// A generated catalog signed through the real held provider owner for lower pure checks.
pub(crate) fn generated_catalog_fixture() -> (
    tempfile::TempDir,
    RetainedGatewayCompliancePlan,
    GatewayComplianceCatalogV1,
) {
    let (temporary, prepared) = fixture();
    let provider = provider_for(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let plan = publisher
        .authority
        .gateway_compliance_plan(provider)
        .unwrap();
    let catalog = publisher
        .authority
        .sign_gateway_compliance_catalog(None, plan.issued_at_unix())
        .unwrap();
    (temporary, plan, catalog)
}

fn provider_for(prepared: &PreparedLocalnet) -> iroha_data_model::sorafs::capacity::ProviderId {
    prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[0]
        .provider_id
}
fn catalog_test_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("private"))
        .unwrap()
        .path()
        .to_path_buf();
    (temporary, root)
}
fn catalog_prepared(root: &std::path::Path, label: &str) -> PreparedLocalnet {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    prepare_localnet_at(
        label,
        root,
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap()
}

#[test]
fn generated_catalogs_sign_exact_successors_without_extending_original_material() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, root) = catalog_test_root();
    let prepared = catalog_prepared(&root.join("generation"), "catalog-signing");
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[0]
        .provider_id;
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let authority = &publisher.authority;
    let plan = authority.gateway_compliance_plan(provider).unwrap();
    let start = plan.issued_at_unix();
    let first = authority
        .sign_gateway_compliance_catalog(None, start)
        .unwrap();
    first.verify(plan.trust_policy(), start, 0).unwrap();
    assert_eq!(first.approvals.len(), 2);
    assert_eq!(first.approvals[0].signer_id, "managed-compliance-catalog-0");
    assert_eq!(first.approvals[1].signer_id, "managed-compliance-catalog-1");
    assert_eq!(first.payload.sequence, 1);
    assert!(first.payload.predecessor_digest.is_none());
    assert_eq!(
        first.payload.valid_until_unix,
        start + plan.catalog_validity_seconds()
    );
    assert_eq!(
        encode(&first, MAX_RECORD_BYTES).unwrap(),
        encode(
            &authority
                .sign_gateway_compliance_catalog(None, start)
                .unwrap(),
            MAX_RECORD_BYTES,
        )
        .unwrap()
    );
    let next_time = first.payload.valid_until_unix;
    assert!(first.verify(plan.trust_policy(), next_time, 0).is_err());
    let second = authority
        .sign_gateway_compliance_catalog(Some(&first), next_time)
        .unwrap();
    second.verify(plan.trust_policy(), next_time, 0).unwrap();
    validate_catalog_transition(Some(&first), &second).unwrap();
    assert_eq!(second.payload.sequence, 2);
    assert_eq!(
        second.payload.predecessor_digest,
        Some(first.payload.catalog_digest().unwrap())
    );
    let last = authority
        .sign_gateway_compliance_catalog(Some(&second), plan.expires_at_unix() - 1)
        .unwrap();
    assert_eq!(last.payload.valid_until_unix, plan.expires_at_unix());
    assert!(
        authority
            .sign_gateway_compliance_catalog(None, start - 1)
            .is_err()
    );
    assert!(
        authority
            .sign_gateway_compliance_catalog(Some(&second), start)
            .is_err()
    );
    assert!(
        authority
            .sign_gateway_compliance_catalog(Some(&last), plan.expires_at_unix())
            .is_err()
    );
    assert!(
        authority
            .sign_gateway_compliance_catalog(None, u64::MAX)
            .is_err()
    );
    assert_eq!(
        prepared
            .gateway_compliance_plan(provider)
            .unwrap()
            .unwrap()
            .expires_at_unix(),
        plan.expires_at_unix()
    );
}

#[test]
fn catalog_signing_refuses_foreign_predecessors_substituted_keys_and_standard_profiles() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, root) = catalog_test_root();
    let one = catalog_prepared(&root.join("one"), "catalog-one");
    let two = catalog_prepared(&root.join("two"), "catalog-two");
    let provider = one.stream_token_authorities().unwrap().unwrap().providers[0].provider_id;
    let other_provider = two.stream_token_authorities().unwrap().unwrap().providers[0].provider_id;
    let first_publisher = ManagedGatewayCompliance::open(&one, provider).unwrap();
    let first_authority = &first_publisher.authority;
    let second_publisher = ManagedGatewayCompliance::open(&two, other_provider).unwrap();
    let second_authority = &second_publisher.authority;
    let plan = first_authority.gateway_compliance_plan(provider).unwrap();
    let other = two
        .gateway_compliance_plan(other_provider)
        .unwrap()
        .unwrap();
    assert_ne!(plan.network_id(), other.network_id());
    let now = plan.issued_at_unix().max(other.issued_at_unix());
    let original = first_authority
        .sign_gateway_compliance_catalog(None, now)
        .unwrap();
    assert!(
        second_authority
            .sign_gateway_compliance_catalog(Some(&original), now)
            .is_err()
    );
    let mut changed = original.clone();
    changed.approvals[0].signature[0] ^= 1;
    assert!(
        first_authority
            .sign_gateway_compliance_catalog(Some(&changed), now)
            .is_err()
    );
    let mut oversized = original.clone();
    oversized.approvals = vec![original.approvals[0].clone(); MAX_RECORD_BYTES / 64 + 1];
    assert!(encode(&oversized, MAX_RECORD_BYTES).is_err());
    assert!(
        first_authority
            .sign_gateway_compliance_catalog(Some(&oversized), now)
            .is_err()
    );
    let directory = PrivateDirectory::open_exact(
        one.context
            .client_config
            .parent()
            .unwrap()
            .join("runtime")
            .join("stream-token-authorities"),
    )
    .unwrap();
    let directory = directory
        .open_child("providers")
        .unwrap()
        .open_child("0")
        .unwrap();
    let original_key = directory.read("compliance-catalog-0.key", 256).unwrap();
    let ack_key = directory.read("compliance-gateway.key", 256).unwrap();
    directory
        .write_atomic("compliance-catalog-0.key", &ack_key, PublishMode::Replace)
        .unwrap();
    assert!(
        first_authority
            .sign_gateway_compliance_catalog(None, now)
            .is_err()
    );
    directory
        .write_atomic(
            "compliance-catalog-0.key",
            &original_key,
            PublishMode::Replace,
        )
        .unwrap();
    assert_eq!(
        first_authority
            .sign_gateway_compliance_catalog(None, now)
            .unwrap(),
        original
    );

    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let standard = prepare_localnet_at(
        "catalog-standard",
        &root.join("standard"),
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    assert!(ManagedGatewayCompliance::open(&standard, provider).is_err());
}

#[test]
fn retained_compliance_signers_refuse_profile_and_operation_custody_drift_without_reparse() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let provider = provider_for(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let authority = &publisher.authority;
    let plan = authority.gateway_compliance_plan(provider).unwrap();
    let (catalog, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        authority
            .sign_gateway_compliance_catalog(None, now_ms().unwrap() / 1_000)
            .unwrap()
    });
    assert_eq!(parses, 0);
    let accept = || {
        authority
            .validate_generated_gateway_catalog(&catalog)
            .unwrap();
        let observed = observation(&plan, &catalog, now_ms().unwrap() / 1_000);
        let ack = authority
            .sign_observed_gateway_catalog(&observed, &catalog)
            .unwrap();
        ack.verify(
            plan.trust_policy(),
            observed.catalog(),
            observed.observed_at(),
            0,
        )
        .unwrap();
        let repeated = authority
            .sign_gateway_compliance_catalog(None, catalog.payload.generated_at_unix)
            .unwrap();
        assert_eq!(repeated, catalog);
    };
    let refuse = || {
        assert!(
            authority
                .sign_gateway_compliance_catalog(None, catalog.payload.generated_at_unix)
                .is_err()
        );
        assert!(
            authority
                .validate_generated_gateway_catalog(&catalog)
                .is_err()
        );
        let observed = observation(&plan, &catalog, now_ms().unwrap() / 1_000);
        assert!(
            authority
                .sign_observed_gateway_catalog(&observed, &catalog)
                .is_err()
        );
    };
    let (_, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        accept();
        let generation =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# original source changed between signing calls\n");
        generation
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
        refuse();
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        accept();
        let runtime = generation.open_child("runtime").unwrap();
        let key = runtime.read("onboarding-signer.key", 4096).unwrap();
        std::fs::remove_file(runtime.path().join("onboarding-signer.key")).unwrap();
        refuse();
        runtime
            .write_atomic("onboarding-signer.key", &key, PublishMode::CreateNew)
            .unwrap();
        accept();
        #[cfg(unix)]
        {
            authority
                .directory
                .write_atomic("operation.lock", b"", PublishMode::Replace)
                .unwrap();
            refuse();
        }
        #[cfg(windows)]
        {
            let original_lock = iroha_fs::FileIdentity::of(&authority._lock).unwrap();
            assert!(
                authority
                    .directory
                    .write_atomic("operation.lock", b"", PublishMode::Replace)
                    .is_err()
            );
            assert_eq!(
                iroha_fs::FileIdentity::of(&authority._lock).unwrap(),
                original_lock
            );
            assert_eq!(
                iroha_fs::FileIdentity::of(
                    &authority.directory.open_read("operation.lock").unwrap()
                )
                .unwrap(),
                original_lock
            );
            accept();
        }
    });
    assert_eq!(parses, 0);

    // A network-scoped owner cannot select the provider's signing material.
    let network = ServiceAuthority::open_network(
        &prepared,
        crate::managed::service_authority::NetworkPurpose::InitialReputationPolicy,
    )
    .unwrap();
    assert!(
        network
            .sign_gateway_compliance_catalog(None, catalog.payload.generated_at_unix)
            .is_err()
    );
    assert!(
        network
            .validate_generated_gateway_catalog(&catalog)
            .is_err()
    );
    let observed = observation(&plan, &catalog, now_ms().unwrap() / 1_000);
    assert!(
        network
            .sign_observed_gateway_catalog(&observed, &catalog)
            .is_err()
    );
}
