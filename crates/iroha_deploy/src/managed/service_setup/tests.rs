//! Structural intent and immutable journal controls. Codec checkpoint bytes are not native proof.

use super::*;
use crate::managed::native_operation::Fees;
use iroha_data_model::{
    sorafs::{
        reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1,
        stream_token_gateway::StreamTokenGatewayAdmissionQualificationV1,
    },
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::Quantity;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

pub(super) fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "managed-services",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    (root, prepared)
}
pub(super) fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(180),
    }
}
pub(super) fn gateway(
    authority: &ServiceAuthority,
    provider: ProviderId,
) -> StreamTokenGatewayPolicyV1 {
    let label = "generated-managed-services".to_owned();
    let gateway_id =
        derive_stream_token_gateway_id_v1(&authority.config.network_id, &label).unwrap();
    let start = now_ms().unwrap();
    let mut policy = StreamTokenGatewayPolicyV1 {
        network_id: authority.config.network_id,
        compliance_gateway_id: label,
        qualification: StreamTokenGatewayAdmissionQualificationV1 {
            gateway_id,
            revision: 1,
            policy_digest: [0; 32],
            max_pending: 64,
            max_tracked_tokens: 128,
            lease_ttl_ms: 30_000,
        },
        operators: BTreeSet::from([authority
            .provider_inventory(provider)
            .unwrap()
            .authority(StreamTokenAuthorityRole::GatewayOperator)
            .unwrap()
            .account
            .clone()]),
        observers: BTreeSet::from([authority
            .provider_inventory(provider)
            .unwrap()
            .authority(StreamTokenAuthorityRole::GatewayObserver)
            .unwrap()
            .account
            .clone()]),
        valid_from_unix_ms: start,
        valid_until_unix_ms: start + 1_200_000,
        max_observation_age_ms: 30_000,
        admission_enabled: true,
    };
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    policy
}
pub(super) fn reputation_labels(prepared: &PreparedLocalnet) -> Vec<String> {
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let mut labels: Vec<_> = manifest
        .providers
        .iter()
        .map(|p| {
            let plan = prepared
                .gateway_compliance_plan(p.provider_id)
                .unwrap()
                .unwrap();
            let label = plan.gateway_label().to_owned();
            (
                derive_stream_token_gateway_id_v1(&manifest.network_id, &label).unwrap(),
                label,
            )
        })
        .collect();
    labels.sort_by_key(|(id, _)| *id);
    labels.into_iter().map(|(_, label)| label).collect()
}

pub(super) fn reputation(
    authority: &ServiceAuthority,
    labels: &[String],
) -> ReputationJournalAuthorityPolicyV1 {
    let recorder = authority
        .network_role(
            crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReputationRecorder,
        )
        .unwrap();
    ReputationJournalAuthorityPolicyV1 {
        version: 1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: recorder.clone(),
        dispute_recorder_authority: recorder.clone(),
        token_recorder_authority: recorder.clone(),
        stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
            allowed_gateways: labels
                .iter()
                .map(|label| {
                    derive_stream_token_gateway_id_v1(&authority.config.network_id, label).unwrap()
                })
                .collect(),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            time_to_live_ms: 60_000,
            height_ttl: 128,
        },
        max_source_age_ms: 3_600_000,
    }
}
fn codec_original(intent: Intent) -> Original {
    Original {
        intent,
        checkpoint: vec![0xA5; 16 * 1024],
    }
}

#[test]
fn exact_generated_roles_and_separate_purposes_are_required() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let gateway_owner = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let recorder_owner = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    assert!(
        ManagedInitialGatewaySetup::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    assert!(ManagedInitialReputationPolicy::open(&prepared).is_err());
    let policy = gateway(
        &gateway_owner.inner.authority,
        crate::managed::native_operation::test_support::provider_id(
            &gateway_owner.inner.authority.prepared,
            0,
        ),
    );
    let intent = Intent::gateway(&gateway_owner.inner.authority, &policy).unwrap();
    gateway_owner.inner.validate_intent(&intent).unwrap();
    assert!(recorder_owner.inner.validate_intent(&intent).is_err());
    let mut wrong = policy.clone();
    wrong.operators = BTreeSet::from([gateway_owner.inner.authority.config.account.clone()]);
    wrong.qualification.policy_digest = wrong.calculate_policy_digest().unwrap();
    assert!(Intent::gateway(&gateway_owner.inner.authority, &wrong).is_err());
    let mut wrong = policy.clone();
    wrong.observers = BTreeSet::from([gateway_owner.inner.authority.config.account.clone()]);
    wrong.qualification.policy_digest = wrong.calculate_policy_digest().unwrap();
    assert!(Intent::gateway(&gateway_owner.inner.authority, &wrong).is_err());
    let recorder = reputation(
        &recorder_owner.inner.authority,
        &reputation_labels(&prepared),
    );
    let intent = Intent::reputation(
        &recorder_owner.inner.authority,
        &reputation_labels(&prepared),
        &recorder,
    )
    .unwrap();
    recorder_owner.inner.validate_intent(&intent).unwrap();
    assert!(gateway_owner.inner.validate_intent(&intent).is_err());
    for slot in 0..3 {
        let mut changed = recorder.clone();
        let field = match slot {
            0 => &mut changed.por_recorder_authority,
            1 => &mut changed.dispute_recorder_authority,
            _ => &mut changed.token_recorder_authority,
        };
        *field = recorder_owner.inner.authority.config.account.clone();
        assert!(
            Intent::reputation(
                &recorder_owner.inner.authority,
                &reputation_labels(&prepared),
                &changed
            )
            .is_err()
        );
    }
    assert!(
        Intent::reputation(
            &recorder_owner.inner.authority,
            &["other-gateway".to_owned()],
            &recorder
        )
        .is_err()
    );
}

#[test]
fn full_intent_terms_and_selection_cannot_change_and_large_checkpoint_is_codec_only() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let owner = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let opts = options();
    let terms = Terms::new(now_ms().unwrap() + 120_000, &opts).unwrap();
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
    let policy = gateway(
        &owner.inner.authority,
        crate::managed::native_operation::test_support::provider_id(
            &owner.inner.authority.prepared,
            0,
        ),
    );
    let original = codec_original(Intent::gateway(&owner.inner.authority, &policy).unwrap());
    let directory = owner
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let retained = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(retained.checkpoint, original.checkpoint);
    assert!(
        owner.inner.validate_original(&retained).is_err(),
        "codec-only bytes are no authenticated checkpoint"
    );
    retained
        .matches_intent(&original.intent)
        .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &opts))
        .unwrap();
    let mut replacement = original.clone();
    replacement.checkpoint.push(0x6b);
    assert!(journal::publish_intent(&directory, &replacement).is_err());
    let mut policy = policy;
    policy.max_observation_age_ms += 1;
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    let changed = Intent::gateway(&owner.inner.authority, &policy).unwrap();
    assert!(
        retained
            .matches_intent(&changed)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &opts))
            .is_err()
    );
    assert!(
        retained
            .matches_intent(&original.intent)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms + 1, &opts))
            .is_err()
    );
    let mut fees = opts.clone();
    let asset = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    fees.max_total_fees.insert(asset, Quantity::from(1u64));
    assert!(
        retained
            .matches_intent(&original.intent)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &fees))
            .is_err()
    );
    for field in 0..3 {
        let mut changed = original.intent.clone();
        let Intent::Gateway { selection, .. } = &mut changed else {
            unreachable!()
        };
        match field {
            0 => selection.chain_id.push_str("-other"),
            1 => selection.manager = selection.operator.clone(),
            _ => selection.policy_digest[0] ^= 1,
        };
        assert!(owner.inner.validate_intent(&changed).is_err());
    }
    let bytes = std::fs::read(directory.path().join("original.nrt")).unwrap();
    let mut corrupt = bytes;
    corrupt.push(0);
    std::fs::write(directory.path().join("original.nrt"), corrupt).unwrap();
    assert!(journal::read_intent(&directory).is_err());
}

#[test]
fn recorder_full_delivery_policy_and_bounds_are_retained() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let owner = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    let labels = reputation_labels(&prepared);
    let label = labels.as_slice();
    let policy = reputation(&owner.inner.authority, label);
    let opts = options();
    let terms = Terms::new(now_ms().unwrap() + 120_000, &opts).unwrap();
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
    let (intent, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        Intent::reputation(&owner.inner.authority, label, &policy).unwrap()
    });
    assert_eq!(parses, 0);
    let original = codec_original(intent);
    let directory = owner
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let retained = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(retained.checkpoint.len(), 16 * 1024);
    let mut changed = policy.clone();
    changed.stream_token_delivery.height_ttl += 1;
    let changed = Intent::reputation(&owner.inner.authority, label, &changed).unwrap();
    assert!(
        retained
            .matches_intent(&changed)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &opts))
            .is_err()
    );
    let mut changed = policy;
    changed.revision = 2;
    assert!(Intent::reputation(&owner.inner.authority, label, &changed).is_err());
    assert!(
        Intent::reputation(
            &owner.inner.authority,
            &["x".repeat(16 * 1024 + 1), "b".into(), "c".into()],
            &reputation(&owner.inner.authority, label)
        )
        .is_err()
    );
    let report = progress(OperationStatus::Applied, None);
    assert!(
        report.finalized.is_none(),
        "node Applied never constructs successful carrier evidence"
    );
}

#[test]
fn selected_setup_recovery_distinguishes_absent_empty_and_dirty_without_http() {
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
    let options = options();
    let mut peers =
        crate::managed::native_operation::test_support::UnavailablePeers::start(&prepared);
    for dirty in 0..3 {
        let gateway_result = gateway_owner.recover_selected_if_present(
            &gateway,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        );
        let recorder_result = recorder_owner.recover_selected_if_present(
            &reputation_labels(&prepared),
            &recorder,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        );
        if dirty == 2 {
            assert!(gateway_result.is_err() && recorder_result.is_err());
        } else {
            assert!(gateway_result.unwrap().is_none() && recorder_result.unwrap().is_none());
        }
        for owner in [&gateway_owner.inner, &recorder_owner.inner] {
            if dirty == 0 {
                assert!(!owner.authority.directory.path().join("setup").exists());
                owner.authority.directory.ensure_child("setup").unwrap();
            } else {
                let directory = owner.authority.directory.open_child("setup").unwrap();
                assert!(!directory.path().join("transaction").exists());
                if dirty == 1 {
                    require_empty(&directory).unwrap();
                    directory
                        .write_atomic("incomplete.nrt", &[1], iroha_fs::PublishMode::CreateNew)
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

pub(super) fn ingest(authority: &ServiceAuthority) -> ProviderIngestCompletionAuthorityV1 {
    ProviderIngestCompletionAuthorityV1::new(
        authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
            .clone(),
        authority
            .provider_role(StreamTokenAuthorityRole::ProviderIngest)
            .unwrap()
            .clone(),
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0x41; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0x42; 32],
        },
    )
}

#[test]
fn distinct_provider_setup_locks_and_policies_cannot_cross_scopes() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let providers = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers;
    let owners: Vec<_> = providers
        .iter()
        .map(|provider| ManagedInitialGatewaySetup::open(&prepared, provider.provider_id).unwrap())
        .collect();
    let policies: Vec<_> = owners
        .iter()
        .zip(&providers)
        .map(|(owner, provider)| gateway(&owner.inner.authority, provider.provider_id))
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        assert!(Intent::gateway(&owner.inner.authority, &policies[index]).is_ok());
        assert!(Intent::gateway(&owner.inner.authority, &policies[(index + 1) % 3]).is_err());
        assert!(ManagedInitialGatewaySetup::open(&prepared, providers[index].provider_id).is_err());
        assert!(
            owner
                .inner
                .authority
                .provider_inventory(providers[(index + 1) % 3].provider_id)
                .is_err()
        );
    }
    let first =
        ManagedInitialProviderIngestAuthority::open(&prepared, providers[0].provider_id).unwrap();
    let second =
        ManagedInitialProviderIngestAuthority::open(&prepared, providers[1].provider_id).unwrap();
    let selected = ingest(&first.inner.authority);
    assert!(Intent::provider_ingest(&first.inner.authority, &selected).is_ok());
    assert!(Intent::provider_ingest(&second.inner.authority, &selected).is_err());
}

#[test]
fn provider_ingest_retains_exact_roles_owner_wallet_and_full_original_claims() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let owner = ManagedInitialProviderIngestAuthority::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    assert!(
        ManagedInitialProviderIngestAuthority::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    let selected = ingest(&owner.inner.authority);
    assert_ne!(selected.provider_owner, selected.completion_signer);
    let config = owner.inner.wallet_config().unwrap();
    assert_eq!(config.account, selected.provider_owner);
    assert_ne!(config.account, owner.inner.authority.config.account);
    assert_eq!(config.network_id, owner.inner.authority.config.network_id);
    assert_eq!(
        config.torii_api_url,
        owner.inner.authority.config.torii_api_url
    );
    let intent = Intent::provider_ingest(&owner.inner.authority, &selected).unwrap();
    owner.inner.validate_intent(&intent).unwrap();
    let gateway = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    assert!(gateway.inner.validate_intent(&intent).is_err());
    let opts = options();
    let terms = Terms::new(now_ms().unwrap() + 120_000, &opts).unwrap();
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
    let original = codec_original(intent);
    let directory = owner
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = std::fs::read(directory.path().join("original.nrt")).unwrap();
    let retained = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(retained.checkpoint.len(), 16 * 1024);
    assert!(
        owner.inner.validate_original(&retained).is_err(),
        "codec-only checkpoint is not native authority"
    );
    let Request::ProviderIngest(request) = retained.request(&terms, opts.deadline) else {
        panic!("purpose");
    };
    assert_eq!(request.authority, selected);
    assert_eq!(
        request.provider_id,
        owner.inner.authority.provider_id().unwrap()
    );
    assert_eq!(request.deadline_unix_ms, terms.signing_deadline_unix_ms);
    for field in 0..7 {
        let mut changed = original.intent.clone();
        let Intent::ProviderIngest {
            chain_id,
            network_id,
            provider_id,
            authority,
        } = &mut changed
        else {
            unreachable!()
        };
        match field {
            0 => chain_id.push('x'),
            1 => {
                *network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                        b"other-ingest-network",
                    )),
                )
            }
            2 => *provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0x43; 32]),
            3 => authority.provider_owner = owner.inner.authority.config.account.clone(),
            4 => authority.completion_signer = authority.provider_owner.clone(),
            5 => authority.signer_policy.policy_id[0] ^= 1,
            _ => authority.signer_policy.policy_digest[0] ^= 1,
        }
        assert!(
            retained
                .matches_intent(&changed)
                .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &opts))
                .is_err()
        );
        if field < 5 {
            assert!(owner.inner.validate_intent(&changed).is_err());
        }
    }
    let mut wrong = selected.clone();
    wrong.signer_policy.revision = 2;
    wrong.signer_policy.predecessor_digest = Some([8; 32]);
    assert!(Intent::provider_ingest(&owner.inner.authority, &wrong).is_err());
    let mut wrong = selected;
    wrong.signer_policy.policy_digest = [0; 32];
    assert!(Intent::provider_ingest(&owner.inner.authority, &wrong).is_err());
    let mut changed = opts.clone();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        retained
            .matches_intent(&original.intent)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    assert!(
        retained
            .matches_intent(&original.intent)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms + 1, &opts))
            .is_err()
    );
    assert_eq!(
        std::fs::read(directory.path().join("original.nrt")).unwrap(),
        bytes
    );
    assert!(progress(OperationStatus::Applied, None).finalized.is_none());
}

// The sole wallet owner retains the real request before the epoch commit; this does not sign.
pub(super) fn retain_explicit_request(
    owner: &Setup,
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
) -> Selected<Original> {
    journal::publish_intent(directory, original).unwrap();
    assert_eq!(
        directory.entries(3).unwrap(),
        vec![std::ffi::OsString::from("original.nrt")]
    );
    assert!(
        journal::required_original(directory, owner.purpose().unwrap()).is_err(),
        "semantic bytes alone are not a committed dispatch"
    );
    let wallet = owner.wallet().unwrap();
    journal::explicit(
        directory,
        owner.purpose().unwrap(),
        original,
        utc,
        options,
        &wallet,
    )
    .unwrap();
    let selected = journal::required_original(directory, owner.purpose().unwrap()).unwrap();
    assert_eq!(
        selected
            .request(options.deadline)
            .inspect(&wallet, &selected.directory().path().join("transaction"))
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    selected
}
