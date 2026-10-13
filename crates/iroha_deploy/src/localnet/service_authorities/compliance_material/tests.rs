//! Original generated trust, native profile custody and network replay separation controls.
use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};
use sorafs_manifest::gateway_compliance::{
    GATEWAY_COMPLIANCE_ACK_VERSION_V1, GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
    GATEWAY_COMPLIANCE_CATALOG_VERSION_V1, GatewayComplianceAcknowledgementPayloadV1,
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogApprovalV1,
    GatewayComplianceCatalogPayloadV1, GatewayComplianceCatalogV1, GatewayComplianceProtocolError,
};

fn prepared(root: &Path) -> PreparedLocalnet {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    prepare_localnet_at(
        "compliance-profile",
        root,
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap()
}
fn directory(prepared: &PreparedLocalnet) -> PrivateDirectory {
    PrivateDirectory::open_exact(
        prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(DIRECTORY),
    )
    .unwrap()
}
fn first_compliance(
    prepared: &PreparedLocalnet,
) -> crate::managed::Result<Option<RetainedGatewayCompliancePlan>> {
    let Some(manifest) = prepared.stream_token_authorities()? else {
        return Ok(None);
    };
    prepared.gateway_compliance_plan(manifest.providers[0].provider_id)
}
fn publish(directory: &PrivateDirectory, manifest: &StreamTokenAuthorityManifest) {
    let bytes = norito::json::to_vec(manifest).unwrap();
    assert!(bytes.len() <= MAX_MANIFEST);
    directory
        .write_atomic(MANIFEST, &bytes, PublishMode::Replace)
        .unwrap();
}
fn signature(directory: &PrivateDirectory, filename: &str, payload: &[u8]) -> [u8; 64] {
    let pair = read_service_private_key(directory, filename).unwrap();
    iroha_crypto::Signature::try_new(pair.private_key(), payload)
        .unwrap()
        .payload()
        .try_into()
        .unwrap()
}

#[test]
fn original_compliance_plan_has_disjoint_threshold_keys_and_finite_unchanged_interval() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let original = first_compliance(&prepared).unwrap().unwrap();
    let provider = prepared
        .provider_service_plans()
        .map(|plans| plans.map(|[first, _, _]| first))
        .unwrap()
        .unwrap();
    let root_directory = directory(&prepared);
    let directory = open_provider_directory(&root_directory, 0).unwrap();
    assert_eq!(original.network_id(), manifest.network_id);
    assert_eq!(original.provider_id(), manifest.providers[0].provider_id);
    assert_eq!(original.manager(), &manifest.manager);
    assert_eq!(original.gateway_label(), gateway_label(0));
    assert_eq!(
        original.gateway_id(),
        derive_stream_token_gateway_id_v1(&manifest.network_id, &gateway_label(0)).unwrap()
    );
    assert_eq!(
        original.issued_at_unix(),
        provider.admission_material().issued_at
    );
    assert_eq!(
        original.expires_at_unix(),
        provider.admission_material().retention_epoch
    );
    assert_eq!(
        original.expires_at_unix() - original.issued_at_unix(),
        provider_material::VALIDITY_SECONDS
    );
    assert!(original.issued_at_unix() > 0 && original.expires_at_unix() < u64::MAX);
    assert_eq!(
        original.original_commitment(),
        Hash::new(&manifest.providers[0].compliance_plan)
    );
    assert_eq!(
        original.empty_feed_transport_digest(),
        gateway_compliance_feed_transport_policy_digest(&std::collections::BTreeMap::new())
            .unwrap()
    );
    let trust = original.trust_policy();
    assert_eq!(
        (trust.catalog_threshold, trust.gateway_ack_threshold),
        (2, 1)
    );
    assert_eq!(
        (trust.catalog_signers.len(), trust.gateway_signers.len()),
        (3, 1)
    );
    trust.validate().unwrap();
    let mut keys = manifest
        .providers
        .iter()
        .flat_map(|provider| &provider.authorities)
        .map(|a| a.account.try_signatory().unwrap().clone())
        .chain(std::iter::once(
            manifest.manager.try_signatory().unwrap().clone(),
        ))
        .collect::<BTreeSet<_>>();
    for name in ["provider-advert.key", "provider-por-vrf.key"] {
        let pair = read_service_private_key(&directory, name).unwrap();
        assert!(keys.insert(pair.public_key().clone()));
    }
    let network_directory = root_directory.open_child(NETWORK_DIRECTORY).unwrap();
    for name in network_material::COUNCIL_KEYS {
        assert!(
            keys.insert(
                read_service_private_key(&network_directory, name)
                    .unwrap()
                    .public_key()
                    .clone()
            )
        );
    }
    for role in &manifest.network.authorities {
        assert!(keys.insert(role.account.try_signatory().unwrap().clone()));
    }
    let public_text = norito::json::to_json(&manifest).unwrap();
    for (filename, signer) in
        filenames().zip(trust.catalog_signers.iter().chain(&trust.gateway_signers))
    {
        let pair = read_service_private_key(&directory, filename).unwrap();
        assert_eq!(public32(pair.public_key()).unwrap(), signer.public_key);
        assert!(
            keys.insert(pair.public_key().clone()),
            "every compliance key has one purpose"
        );
        let bytes = directory.read(filename, 256).unwrap();
        let secret = std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(!public_text.contains(secret));
    }
    let recovered = first_compliance(&prepared).unwrap().unwrap();
    assert_eq!(recovered.trust_policy(), trust);
    assert_eq!(
        recovered.original_commitment(),
        original.original_commitment()
    );
    assert_eq!(recovered.issued_at_unix(), original.issued_at_unix());
    assert_eq!(recovered.expires_at_unix(), original.expires_at_unix());
    for peer in &prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
        let config = parse_localnet_peer_config(
            std::str::from_utf8(&bytes).unwrap(),
            Some(&peer.config_path),
        )
        .unwrap();
        assert!(!config.torii.sorafs_storage.enabled);
        assert!(!config.torii.sorafs_storage.stream_tokens.enabled);
        assert!(config.torii.sorafs_gateway.compliance.is_none());
    }
}

#[test]
fn retained_compliance_rejects_cross_purpose_malformed_and_missing_credentials_without_secrets() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let root_directory = directory(&prepared);
    let directory = open_provider_directory(&root_directory, 0).unwrap();
    for (target, substitute) in [
        (CATALOG_KEYS[0], ACK_KEYS[0]),
        (ACK_KEYS[0], CATALOG_KEYS[0]),
        (CATALOG_KEYS[1], "provider-advert.key"),
        (ACK_KEYS[0], ROLES[0].credential_filename()),
    ] {
        let before = directory.read(target, 256).unwrap();
        let other = directory.read(substitute, 256).unwrap();
        directory
            .write_atomic(target, &other, PublishMode::Replace)
            .unwrap();
        let error = format!("{}", first_compliance(&prepared).unwrap_err());
        assert!(!error.contains(std::str::from_utf8(other.strip_suffix(b"\n").unwrap()).unwrap()));
        directory
            .write_atomic(target, &before, PublishMode::Replace)
            .unwrap();
    }
    let before = directory.read(CATALOG_KEYS[0], 256).unwrap();
    for malformed in [
        before[..before.len() - 1].to_vec(),
        [before.as_slice(), b"\n"].concat(),
        vec![b'x'; 257],
    ] {
        directory
            .write_atomic(CATALOG_KEYS[0], &malformed, PublishMode::Replace)
            .unwrap();
        assert!(first_compliance(&prepared).is_err());
    }
    directory
        .write_atomic(CATALOG_KEYS[0], &before, PublishMode::Replace)
        .unwrap();
    std::fs::remove_file(directory.path().join(ACK_KEYS[0])).unwrap();
    assert!(first_compliance(&prepared).is_err());
    // Missing files are not regenerated by a read-only reopen.
    assert!(!directory.path().join(ACK_KEYS[0]).exists());
}

#[test]
fn compliance_plan_is_required_bounded_and_exactly_committed_by_original_genesis() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let original = prepared.stream_token_authorities().unwrap().unwrap();
    let root_directory = directory(&prepared);
    let plan = decode(&original.providers[0].compliance_plan).unwrap();
    assert_eq!(
        encode(&plan).unwrap(),
        original.providers[0].compliance_plan
    );
    for which in 0..9 {
        let mut changed = original.clone();
        let mut selection = plan.clone();
        match which {
            0 => selection.creation_time_ms += 1,
            1 => selection.expires_at_unix += 1,
            2 => selection.expires_at_unix = u64::MAX,
            3 => selection.gateway_label = "other-gateway".into(),
            4 => selection.trust_template.catalog_threshold = 1,
            5 => selection
                .trust_template
                .revoked_catalog_signer_ids
                .push(CATALOG_IDS[2].into()),
            6 => selection.empty_feed_transport_digest[0] ^= 1,
            7 => selection.manager = original.providers[0].authorities[0].account.clone(),
            _ => {
                // Valid trust and exact selections, but a different key-to-id assignment cannot
                // replace the signed original commitment even if credentials are also exchanged.
                let a = selection.trust_template.catalog_signers[0].public_key;
                selection.trust_template.catalog_signers[0].public_key =
                    selection.trust_template.catalog_signers[1].public_key;
                selection.trust_template.catalog_signers[1].public_key = a;
                selection
                    .validate(
                        0,
                        original.providers[0].provider_id,
                        &original.manager,
                        plan.creation_time_ms,
                    )
                    .unwrap();
            }
        }
        changed.providers[0].compliance_plan = encode(&selection).unwrap();
        publish(&root_directory, &changed);
        assert!(first_compliance(&prepared).is_err());
    }
    let mut missing = norito::json::to_value(&original).unwrap();
    assert!(
        missing
            .as_object_mut()
            .unwrap()
            .get_mut("providers")
            .unwrap()
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()
            .remove("compliance_plan")
            .is_some()
    );
    assert!(norito::json::from_value::<StreamTokenAuthorityManifest>(missing).is_err());
    let mut extra = norito::json::to_value(&original).unwrap();
    extra
        .as_object_mut()
        .unwrap()
        .insert("compliance_plan_override".into(), norito::json::Value::Null);
    assert!(norito::json::from_value::<StreamTokenAuthorityManifest>(extra).is_err());
    for bytes in [
        vec![],
        vec![0],
        vec![0; PLAN_MAX_BYTES + 1],
        [original.providers[0].compliance_plan.as_slice(), &[0]].concat(),
    ] {
        let mut malformed = original.clone();
        malformed.providers[0].compliance_plan = bytes;
        publish(&root_directory, &malformed);
        assert!(first_compliance(&prepared).is_err());
    }
    publish(&root_directory, &original);
    assert!(first_compliance(&prepared).unwrap().is_some());
}

#[test]
fn same_original_template_bound_to_distinct_actual_networks_refuses_catalog_and_ack_replay() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let first = prepared(&temporary.path().join("first"));
    let second = prepared(&temporary.path().join("second"));
    let first_manifest = first.stream_token_authorities().unwrap().unwrap();
    let second_manifest = second.stream_token_authorities().unwrap().unwrap();
    assert_ne!(
        first_manifest.network_id, second_manifest.network_id,
        "different actual signed genesis"
    );
    let original = decode(&first_manifest.providers[0].compliance_plan).unwrap();
    // Exercise the private binding algebra with the SAME material and two genuinely generated
    // network IDs. This deliberately constructed second binding is not retained-profile proof.
    let a = original.clone().bind(first_manifest.network_id).unwrap();
    let b = original.bind(second_manifest.network_id).unwrap();
    assert_eq!(a.original_commitment(), b.original_commitment());
    assert_ne!(a.gateway_id(), b.gateway_id());
    assert_ne!(a.trust_policy().policy_id, b.trust_policy().policy_id);
    assert_ne!(
        a.trust_policy().canonical_digest().unwrap(),
        b.trust_policy().canonical_digest().unwrap()
    );
    let directory = open_provider_directory(&directory(&first), 0).unwrap();
    let payload = GatewayComplianceCatalogPayloadV1 {
        version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
        sequence: 1,
        predecessor_digest: None,
        policy_digest: a.trust_policy().canonical_digest().unwrap(),
        generated_at_unix: a.issued_at_unix(),
        valid_until_unix: a.issued_at_unix() + 3600,
        source_anchors: vec![],
        baseline_rules: vec![],
        appeal_overrides: vec![],
        legal_safety_holds: vec![],
        toggles: vec![],
    }
    .normalize()
    .unwrap();
    let signed = payload.signing_digest().unwrap();
    let catalog = GatewayComplianceCatalogV1 {
        payload,
        approvals: (0..2)
            .map(|i| GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: CATALOG_IDS[i].into(),
                signature: signature(&directory, CATALOG_KEYS[i], &signed),
            })
            .collect(),
    };
    let digest_a = catalog
        .verify(a.trust_policy(), a.issued_at_unix() + 1, 300)
        .unwrap();
    assert!(matches!(
        catalog.verify(b.trust_policy(), b.issued_at_unix() + 1, 300),
        Err(GatewayComplianceProtocolError::PolicyDigestMismatch)
    ));
    let mut other_payload = catalog.payload.clone();
    other_payload.policy_digest = b.trust_policy().canonical_digest().unwrap();
    let digest_b = other_payload.catalog_digest().unwrap();
    assert_ne!(digest_a, digest_b);
    let mut rebound = catalog.clone();
    rebound.payload = other_payload;
    assert!(matches!(
        rebound.verify(b.trust_policy(), b.issued_at_unix() + 1, 300),
        Err(GatewayComplianceProtocolError::InvalidSignature { .. })
    ));
    let ack_payload = GatewayComplianceAcknowledgementPayloadV1 {
        version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
        gateway_id: gateway_label(0),
        catalog_digest: digest_a,
        observed_at_unix: a.issued_at_unix() + 1,
        accepted: true,
        rejection_code: None,
    };
    let ack = GatewayComplianceAcknowledgementV1 {
        signature: signature(
            &directory,
            ACK_KEYS[0],
            &ack_payload.signing_digest().unwrap(),
        ),
        payload: ack_payload,
    };
    ack.verify(a.trust_policy(), digest_a, a.issued_at_unix() + 1, 300)
        .unwrap();
    assert!(matches!(
        ack.verify(b.trust_policy(), digest_b, b.issued_at_unix() + 1, 300),
        Err(GatewayComplianceProtocolError::InvalidAcknowledgement(_))
    ));
}

#[test]
fn standard_profile_has_no_compliance_plan_and_refuses_added_private_inventory() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let root = temporary.path().join("standard");
    let prepared = prepare_localnet_at(
        "standard",
        &root,
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    assert!(first_compliance(&prepared).unwrap().is_none());
    let extra = root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY);
    iroha_fs::PrivateDirectory::open_or_create(&extra).unwrap();
    assert!(first_compliance(&prepared).is_err());
}
