//! Genuine generated-profile policy intent controls; codec values are never native authority.

use super::*;
use crate::{
    localnet::{LocalnetServiceProfile, prepare_localnet_at},
    managed::{PreparedLocalnet, service_authority::NetworkPurpose},
};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{io, net::TcpListener};

fn fixture(name: &str) -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        name,
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (temporary, prepared)
}

fn interval(authority: &ServiceAuthority) -> (u64, u64) {
    let plan = authority
        .prepared
        .provider_service_plan(authority.manifest.providers[0].provider_id)
        .unwrap()
        .unwrap();
    (
        plan.admission_material()
            .issued_at
            .checked_mul(1_000)
            .unwrap(),
        plan.admission_material()
            .retention_epoch
            .checked_mul(1_000)
            .unwrap(),
    )
}

fn selected(authority: &ServiceAuthority) -> GeneratedServicePolicies {
    GeneratedServicePolicies::select(authority).unwrap()
}

fn claim_roundtrip(value: &GeneratedServicePolicies) -> GeneratedServicePolicies {
    let bytes = encode(value, MAX_BYTES).unwrap();
    norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(MAX_BYTES, MAX_BYTES, MAX_BYTES, MAX_BYTES * 8, 40),
    )
    .unwrap()
}

fn quiet_peers(prepared: &PreparedLocalnet) -> Vec<TcpListener> {
    prepared
        .peers
        .iter()
        .map(|peer| {
            let url: url::Url = peer.torii_url.parse().unwrap();
            assert_eq!(url.host_str(), Some("127.0.0.1"));
            let listener = TcpListener::bind(("127.0.0.1", url.port().unwrap())).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .collect()
}

fn assert_no_http(peers: &[TcpListener]) {
    for listener in peers {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn generated_policies_bind_exact_roles_native_policies_and_purpose_separated_commitments() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-policy-selection");
    let peers = quiet_peers(&prepared);
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let policies = selected(&authority);
    let plan = prepared
        .provider_service_plan(authority.manifest.providers[0].provider_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        policies.providers[0].custody.binding.network_id,
        *authority.config.network_id.as_bytes()
    );
    assert_eq!(
        policies.providers[0].custody.binding.chain_id,
        authority.config.chain.as_str()
    );
    assert_eq!(
        policies.providers[0].custody.binding.role,
        SignerRoleV1::StreamToken
    );
    assert_eq!(
        policies.providers[0].custody.binding.purpose,
        SignerPurposeBindingV1::StreamToken {
            provider_id: *plan.provider_id().as_bytes()
        }
    );
    assert_eq!(
        &policies.providers[0].custody.binding.public_key,
        authority.manifest.providers[0]
            .authority(Role::TokenSigner)
            .map(|v| &v.account)
            .unwrap()
            .try_signatory()
            .unwrap()
    );
    assert_eq!(
        &policies.providers[0].custody.attester_public_key,
        authority.manifest.providers[0]
            .authority(Role::CustodyAttester)
            .map(|v| &v.account)
            .unwrap()
            .try_signatory()
            .unwrap()
    );
    assert_ne!(
        policies.providers[0].custody.binding.public_key,
        policies.providers[0].custody.attester_public_key
    );
    assert_eq!(
        policies.network.reserve.operations_authority,
        *authority
            .network_role(NetworkRole::ReserveOperations)
            .unwrap()
    );
    assert_eq!(
        policies.network.reserve.decision_authority,
        authority.config.account
    );
    assert_eq!(
        policies.network.reserve.custody_account,
        authority.manifest.network.reserve_accounts.custody
    );
    assert_eq!(
        policies.network.reserve.treasury_account,
        authority.manifest.network.reserve_accounts.treasury
    );
    assert_eq!(
        policies.providers[0].gateway.compliance_gateway_id,
        "managed-provider-gateway-0"
    );
    let gateway_id = derive_stream_token_gateway_id_v1(
        &authority.config.network_id,
        "managed-provider-gateway-0",
    )
    .unwrap();
    assert_eq!(
        policies.providers[0].gateway.qualification.gateway_id,
        gateway_id
    );
    assert_eq!(
        policies
            .network
            .reputation
            .stream_token_delivery
            .allowed_gateways,
        {
            let mut ids: Vec<_> = policies
                .providers
                .iter()
                .map(|p| p.gateway.qualification.gateway_id)
                .collect();
            ids.sort_unstable();
            ids
        }
    );
    assert_eq!(
        policies.providers[0].gateway.operators,
        BTreeSet::from([authority.manifest.providers[0]
            .authority(Role::GatewayOperator)
            .map(|v| &v.account)
            .unwrap()
            .clone()])
    );
    assert_eq!(
        policies.providers[0].gateway.observers,
        BTreeSet::from([authority.manifest.providers[0]
            .authority(Role::GatewayObserver)
            .map(|v| &v.account)
            .unwrap()
            .clone()])
    );
    for recorder in [
        &policies.network.reputation.por_recorder_authority,
        &policies.network.reputation.dispute_recorder_authority,
        &policies.network.reputation.token_recorder_authority,
    ] {
        assert_eq!(
            recorder,
            authority
                .network_role(NetworkRole::ReputationRecorder)
                .unwrap()
        );
    }
    let digests = [
        policies.providers[0].custody.binding.policy_digest,
        policies.providers[0]
            .custody
            .attester_authority
            .policy_digest,
        policies.providers[0].observer_authority.policy_digest,
    ];
    assert!(digests.iter().all(|digest| *digest != [0; 32]));
    assert_eq!(digests.into_iter().collect::<BTreeSet<_>>().len(), 3);
    policies.providers[0].custody.validate().unwrap();
    policies.network.reserve.validate().unwrap();
    policies.providers[0].gateway.validate().unwrap();
    policies.network.reputation.validate().unwrap();
    policies.validate(&authority).unwrap();
    let decoded_claim = claim_roundtrip(&policies);
    decoded_claim.validate(&authority).unwrap();
    assert_eq!(
        encode(&decoded_claim, MAX_BYTES).unwrap(),
        encode(&policies, MAX_BYTES).unwrap()
    );
    assert_eq!(authority.directory.entries(8).unwrap(), ["operation.lock"]);
    assert_no_http(&peers);
}

#[test]
fn generated_policy_intervals_are_finite_original_and_capped_by_admitted_retention() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-policy-interval");
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let (start, end) = interval(&authority);
    let policies = selected(&authority);
    let provider = &policies.providers[0];
    assert_eq!(provider.custody.active_from_unix_ms, start);
    assert_eq!(provider.custody.active_until_unix_ms, end);
    assert_eq!(provider.custody.max_validity_ms, DAY_MS);
    let enrollment = provider.initial_enrollment(start, start + 60_000).unwrap();
    assert_eq!(enrollment.issued_at_unix_ms, start);
    assert_eq!(enrollment.expires_at_unix_ms, start + DAY_MS);
    assert_eq!(enrollment.deadline_unix_ms, start + 60_000);
    assert!(start + DAY_MS < end);
    for (selected_at, deadline) in [
        (start - 1, start + 1),
        (end, end + 1),
        (start, start),
        (start, start + DAY_MS),
        (start, end),
        (u64::MAX, u64::MAX),
    ] {
        assert!(provider.initial_enrollment(selected_at, deadline).is_err());
    }
    let near_end = provider
        .initial_enrollment(end - 2_000, end - 1_000)
        .unwrap();
    assert_eq!(near_end.expires_at_unix_ms, end);
    assert_eq!(near_end.issued_at_unix_ms, end - 2_000);
    let other = provider.initial_enrollment(start, start + 60_001).unwrap();
    assert_ne!(other.deadline_unix_ms, enrollment.deadline_unix_ms);
    // UTC affects only the explicit separately retained authorization, never semantic identities.
    let same = selected(&authority);
    assert_eq!(
        encode(&same, MAX_BYTES).unwrap(),
        encode(&policies, MAX_BYTES).unwrap()
    );
    let wire = encode(&policies, MAX_BYTES).unwrap();
    drop(authority);
    let reopened =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let original = claim_roundtrip(&policies);
    original.validate(&reopened).unwrap();
    assert_eq!(
        original.providers[0]
            .initial_enrollment(start, start + 60_000)
            .unwrap(),
        enrollment
    );
    assert_eq!(encode(&original, MAX_BYTES).unwrap(), wire);
    assert_eq!(reopened.directory.entries(8).unwrap(), ["operation.lock"]);
}

type PolicyMutation = (&'static str, fn(&mut GeneratedServicePolicies));

#[test]
fn generated_policy_validation_refuses_every_original_policy_family_substitution() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-policy-substitution");
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let original = selected(&authority);
    let mutations: &[PolicyMutation] = &[
        ("custody handle", |p| {
            p.providers[0]
                .custody
                .binding
                .runtime_handle
                .push_str("-other")
        }),
        ("custody key purpose", |p| {
            p.providers[0].custody.binding.policy_digest[0] ^= 1
        }),
        ("attester identity", |p| {
            p.providers[0].custody.attester_authority.policy_digest[0] ^= 1
        }),
        ("custody authority interval", |p| {
            p.providers[0].custody.active_until_unix_ms -= 1
        }),
        ("custody maximum interval", |p| {
            p.providers[0].custody.max_validity_ms -= 1
        }),
        ("reserve operations", |p| {
            p.network.reserve.operations_authority = p.network.reserve.decision_authority.clone()
        }),
        ("ingest signer", |p| {
            p.providers[0].provider_ingest.completion_signer =
                p.providers[0].provider_ingest.provider_owner.clone()
        }),
        ("ingest owner", |p| {
            p.providers[0].provider_ingest.provider_owner =
                p.providers[0].provider_ingest.completion_signer.clone()
        }),
        ("ingest policy identity", |p| {
            p.providers[0].provider_ingest.signer_policy.policy_id[0] ^= 1
        }),
        ("ingest policy commitment", |p| {
            p.providers[0].provider_ingest.signer_policy.policy_digest[0] ^= 1
        }),
        ("reserve debt", |p| {
            p.network.reserve.max_provider_debt = XorQuantity::try_from_micro(999_999_999).unwrap()
        }),
        ("reserve appeal bound", |p| {
            p.network.reserve.max_open_appeals_per_provider += 1
        }),
        ("gateway limits", |p| {
            p.providers[0].gateway.qualification.max_pending -= 1;
            p.providers[0].gateway.qualification.policy_digest =
                p.providers[0].gateway.calculate_policy_digest().unwrap();
        }),
        ("gateway activation intent", |p| {
            p.providers[0].gateway.admission_enabled = false;
            p.providers[0].gateway.qualification.policy_digest =
                p.providers[0].gateway.calculate_policy_digest().unwrap();
        }),
        ("recorder source freshness", |p| {
            p.network.reputation.max_source_age_ms -= 1
        }),
        ("recorder delivery fees", |p| {
            p.network.reputation.stream_token_delivery.fee_payment =
                FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1))
        }),
        ("recorder delivery interval", |p| {
            p.network.reputation.stream_token_delivery.time_to_live_ms -= 1
        }),
        ("observer identity", |p| {
            p.providers[0]
                .observer_authority
                .service_id
                .push_str("-other")
        }),
    ];
    for (name, mutate) in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        // Codec-valid public claims must still be compared to the authenticated original profile.
        assert!(
            claim_roundtrip(&changed).validate(&authority).is_err(),
            "{name}"
        );
    }
    let mut oversized = original.clone();
    oversized.providers[0].observer_authority.service_id = "x".repeat(MAX_BYTES + 1);
    assert!(encode(&oversized, MAX_BYTES).is_err());
    assert!(oversized.validate(&authority).is_err());
    original.validate(&authority).unwrap();
}

#[test]
fn generated_policy_claim_cannot_move_to_another_original_network_or_replace_selection() {
    let _resources = crate::managed::native_test_guard();
    let (_first_root, first) = fixture("service-policy-first");
    let (_second_root, second) = fixture("service-policy-second");
    let first = ServiceAuthority::open_network(&first, NetworkPurpose::ServiceBootstrap).unwrap();
    let second = ServiceAuthority::open_network(&second, NetworkPurpose::ServiceBootstrap).unwrap();
    assert_ne!(first.config.network_id, second.config.network_id);
    assert_ne!(first.genesis.genesis.hash(), second.genesis.genesis.hash());
    let first_policy = selected(&first);
    let second_policy = selected(&second);
    assert!(first_policy.validate(&second).is_err());
    assert!(second_policy.validate(&first).is_err());
    assert_ne!(
        first_policy.providers[0].custody.binding.policy_digest,
        second_policy.providers[0].custody.binding.policy_digest
    );
    assert_ne!(
        first_policy.providers[0].observer_authority.policy_digest,
        second_policy.providers[0].observer_authority.policy_digest
    );
    assert!(
        ServiceAuthority::open_network(&first.prepared, NetworkPurpose::ServiceBootstrap).is_err()
    );
    first_policy.validate(&first).unwrap();
    second_policy.validate(&second).unwrap();
}

#[test]
fn generated_policy_selection_rechecks_original_files_and_refuses_standard_profile() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-policy-original");
    let peers = quiet_peers(&prepared);
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let original = selected(&authority);
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let retained = generation.read("peer0.toml", 1024 * 1024).unwrap();
    generation
        .write_atomic("peer0.toml", b"invalid original peer", PublishMode::Replace)
        .unwrap();
    assert!(original.validate(&authority).is_err());
    assert!(GeneratedServicePolicies::select(&authority).is_err());
    generation
        .write_atomic("peer0.toml", &retained, PublishMode::Replace)
        .unwrap();
    original.validate(&authority).unwrap();
    assert_no_http(&peers);
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let standard = prepare_localnet_at(
        "plain-profile",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    assert!(
        standard
            .provider_service_plan(authority.manifest.providers[0].provider_id)
            .unwrap()
            .is_none()
    );
    assert!(ServiceAuthority::open_network(&standard, NetworkPurpose::ServiceBootstrap).is_err());
}

#[test]
fn runtime_fee_intent_is_one_xor_per_native_transaction_and_rejects_every_substitution() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-runtime-fees");
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let policies = selected(&authority);
    assert_eq!(
        policies.network.runtime_fee_payment,
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                policies.network.reserve.asset_definition.clone(),
                Quantity::from(1_u64)
            )],
            None
        )
    );
    assert_eq!(
        policies
            .network
            .reputation
            .stream_token_delivery
            .fee_payment,
        policies.network.runtime_fee_payment
    );
    let mut other_asset = [7; 16];
    other_asset[6] = 0x40;
    other_asset[8] = 0x80;
    let wrong_asset = AssetDefinitionId::from_uuid_bytes(other_asset).unwrap();
    let mut values = vec![
        FeePaymentIntent::authority(Vec::new(), None),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                wrong_asset,
                Quantity::from(1_u64),
            )],
            None,
        ),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::PipelineGas,
                policies.network.reserve.asset_definition.clone(),
                Quantity::from(1_u64),
            )],
            None,
        ),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                policies.network.reserve.asset_definition.clone(),
                Quantity::from(2_u64),
            )],
            None,
        ),
        FeePaymentIntent::authority(
            policies
                .network
                .runtime_fee_payment
                .charge_limits()
                .to_vec(),
            std::num::NonZeroU64::new(1),
        ),
    ];
    values.push(FeePaymentIntent::sponsor(
        iroha_data_model::nexus::FeeSponsorProgramId::new(
            authority.config.account.clone(),
            "runtime".parse().unwrap(),
        ),
        1,
        policies
            .network
            .runtime_fee_payment
            .charge_limits()
            .to_vec(),
        None,
    ));
    for replacement in values {
        let mut changed = policies.clone();
        changed.network.runtime_fee_payment = replacement.clone();
        assert!(claim_roundtrip(&changed).validate(&authority).is_err());
        changed.network.reputation.stream_token_delivery.fee_payment = replacement;
        assert!(claim_roundtrip(&changed).validate(&authority).is_err());
    }
}

#[test]
fn generated_ingest_binding_keeps_owner_and_dedicated_signer_in_original_policy_commitment() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-ingest-policy");
    let peers = quiet_peers(&prepared);
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let policies = selected(&authority);
    let binding = &policies.providers[0].provider_ingest;
    assert_eq!(
        &binding.provider_owner,
        authority.manifest.providers[0]
            .authority(Role::IssuerOperator)
            .map(|v| &v.account)
            .unwrap()
    );
    assert_eq!(
        &binding.completion_signer,
        authority.manifest.providers[0]
            .authority(Role::ProviderIngest)
            .map(|v| &v.account)
            .unwrap()
    );
    assert_ne!(binding.provider_owner, binding.completion_signer);
    assert!(binding.is_valid());
    assert_eq!(binding.signer_policy.revision, 1);
    assert!(binding.signer_policy.predecessor_digest.is_none());
    let commitments = [
        binding.signer_policy.policy_id,
        binding.signer_policy.policy_digest,
        policies.providers[0].custody.binding.policy_digest,
        policies.providers[0]
            .custody
            .attester_authority
            .policy_digest,
        policies.providers[0].observer_authority.policy_digest,
    ];
    assert_eq!(commitments.into_iter().collect::<BTreeSet<_>>().len(), 5);
    assert!(!commitments.contains(&[0; 32]));
    claim_roundtrip(&policies).validate(&authority).unwrap();
    let later = GeneratedServicePolicies::select(&authority).unwrap();
    assert_eq!(
        later.providers[0]
            .provider_ingest
            .signer_policy
            .policy_digest,
        binding.signer_policy.policy_digest
    );
    assert_no_http(&peers);
}

#[test]
fn all_three_provider_scopes_are_distinct_and_the_single_network_policy_binds_all_gateways() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("service-three-scopes");
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    let selected = GeneratedServicePolicies::select(&authority).unwrap();
    let mut purposes = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for (slot, p) in selected.providers.iter().enumerate() {
        assert_eq!(usize::from(p.slot), slot);
        assert_eq!(
            p.provider_id,
            authority.manifest.providers[slot].provider_id
        );
        assert_eq!(selected.provider(p.provider_id).unwrap().slot, p.slot);
        assert!(ids.insert(p.provider_id));
        for digest in [
            p.custody.binding.policy_digest,
            p.custody.attester_authority.policy_digest,
            p.observer_authority.policy_digest,
            p.provider_ingest.signer_policy.policy_id,
            p.provider_ingest.signer_policy.policy_digest,
        ] {
            assert!(purposes.insert(digest));
        }
        assert_ne!(
            p.provider_ingest.provider_owner,
            selected.network.reserve.operations_authority
        );
        assert_eq!(
            p.gateway.compliance_gateway_id,
            format!("managed-provider-gateway-{slot}")
        );
        let mut wrong = selected.clone();
        wrong.providers[slot].custody.binding.public_key = p.custody.attester_public_key.clone();
        assert!(wrong.validate(&authority).is_err());
    }
    assert_eq!(purposes.len(), 15);
    assert_eq!(
        selected
            .network
            .reputation
            .stream_token_delivery
            .allowed_gateways
            .len(),
        3
    );
    let labels = selected.gateway_labels();
    let derived: Vec<_> = labels
        .iter()
        .map(|label| {
            derive_stream_token_gateway_id_v1(&authority.config.network_id, label).unwrap()
        })
        .collect();
    assert_eq!(
        derived,
        selected
            .network
            .reputation
            .stream_token_delivery
            .allowed_gateways
    );
    let mut wrong = selected.clone();
    wrong.providers.swap(0, 1);
    assert!(wrong.validate(&authority).is_err());
    let mut wrong = selected.clone();
    wrong.providers[2] = wrong.providers[0].clone();
    assert!(wrong.validate(&authority).is_err());
}
