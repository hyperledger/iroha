//! Generated original publication image, native namespace and refusal controls.
//! These tests do not install a service or claim a paid namespace binding already exists.

use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};

fn prepare(root: &Path, profile: LocalnetServiceProfile) -> PreparedLocalnet {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    prepare_localnet_at("publication-client", root, &ports, profile, None).unwrap()
}

#[test]
fn retained_publication_preserves_the_signed_custom_chain_prefix() {
    use crate::managed::{ManagedContext, ManagedPeer};

    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let root = temporary.path().join("custom-prefix");
    let prefix = 369;
    let default_prefix = iroha_config::parameters::defaults::common::chain_discriminant();
    assert_ne!(prefix, default_prefix);
    let profile = LocalnetServiceProfile::StreamTokenAuthorities;
    let options = LocalnetOptions {
        service_profile: profile,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: "127.0.0.1".into(),
        public_host: "127.0.0.1".into(),
        base_api_port: ports.base_api,
        base_p2p_port: ports.base_p2p,
        out_dir: root.clone(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    // The existing managed generator supports an explicit prefix on the local chain.
    crate::localnet::generate_localnet_runtime(
        &options,
        &mut BufWriter::new(std::io::sink()),
        Some(DEFAULT_CHAIN_ID),
        Some(prefix),
        true,
        None,
    )
    .unwrap();
    let root = root.canonicalize().unwrap();
    let client_config = root.join("client.toml");
    let original_bytes = iroha_fs::read_private(&client_config, MAX_CLIENT_BYTES).unwrap();
    let (client, _) =
        iroha::config::Config::load_bytes_with_musubi_publication(&client_config, &original_bytes)
            .unwrap();
    assert_eq!(client.account_chain_discriminant, prefix);
    let _address = ChainDiscriminantGuard::enter(prefix);
    let prepared = PreparedLocalnet {
        service_profile: profile,
        context: ManagedContext {
            name: "publication-custom-prefix".into(),
            chain_id: client.chain.to_string(),
            network_id: client.network_id.to_string(),
            account_id: client.account.to_string(),
            dataspace_id: 0,
            dataspace_alias: "universal".into(),
            torii_url: client.torii_api_url.to_string(),
            client_config,
        },
        peers: (0..4)
            .map(|index| ManagedPeer {
                config_path: root.join(format!("peer{index}.toml")),
                torii_url: format!("http://127.0.0.1:{}/", ports.base_api + index),
                log_name: format!("peer{index}.log"),
            })
            .collect(),
    };
    let retained = prepared.publication_client_config().unwrap().unwrap();
    assert_eq!(retained.client_config_image(), original_bytes.as_slice());
    assert_eq!(retained.publisher(), &client.account);

    let changed = Zeroizing::new(std::str::from_utf8(&original_bytes).unwrap().replace(
        &format!("chain_discriminant = {prefix}"),
        &format!("chain_discriminant = {default_prefix}"),
    ));
    assert_ne!(changed.as_bytes(), original_bytes.as_slice());
    PrivateDirectory::open_exact(&root)
        .unwrap()
        .write_atomic("client.toml", changed.as_bytes(), PublishMode::Replace)
        .unwrap();
    assert!(prepared.publication_client_config().is_err());
}

#[test]
fn native_publication_projection_requires_exact_staged_bound_genesis_manifest() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepare(
        &temporary.path().join("generation"),
        LocalnetServiceProfile::StreamTokenAuthorities,
    );
    let root = prepared.context.client_config.parent().unwrap();
    let directory = PrivateDirectory::open_exact(root).unwrap();
    let bytes = directory
        .read(
            "genesis.json",
            iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
        )
        .unwrap();
    validate_genesis_manifest_json(&bytes).unwrap();
    let bound =
        RawGenesisTransaction::from_json_slice_at_path(&bytes, root.join("genesis.json")).unwrap();
    let signed = directory
        .read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)
        .unwrap();
    let peer_bytes = directory.read("peer0.toml", MAX_CLIENT_BYTES).unwrap();
    let peer = parse_localnet_peer_config(
        std::str::from_utf8(&peer_bytes).unwrap(),
        Some(&prepared.peers[0].config_path),
    )
    .unwrap();
    let developer = prepared.context.load_client_config().unwrap().account;
    let (policy, binding) = native_original(&bound, &signed, &peer, &developer).unwrap();
    assert_eq!(policy.mode, MusubiRegistryAdmissionModeV1::Open);
    assert_eq!(binding.namespace.to_string(), NAMESPACE);
    let unbound = bound
        .clone()
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .with_consensus_meta()
        .unwrap();
    assert_ne!(
        bound.consensus_fingerprint(),
        unbound.consensus_fingerprint()
    );
    assert!(native_original(&unbound, &signed, &peer, &developer).is_err());
}

#[test]
fn generated_client_uses_native_original_namespace_policy_and_exact_three_origins() {
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent};
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepare(
        &temporary.path().join("generation"),
        LocalnetServiceProfile::StreamTokenAuthorities,
    );
    let original = prepared.publication_client_config().unwrap().unwrap();
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let client = prepared.context.load_client_config().unwrap();
    assert_eq!(original.publisher(), &client.account);
    assert_eq!(original.publication_namespace().to_string(), NAMESPACE);
    assert_eq!(
        original.namespace_binding().home_dataspace,
        DataSpaceId::UNIVERSAL
    );
    assert_eq!(
        original.namespace_binding().scope,
        MusubiPackageScopeV1::Domain("dev".parse().unwrap())
    );
    assert!(original.namespace_binding().generation > 0);
    assert_eq!(
        original.registry_policy().mode,
        MusubiRegistryAdmissionModeV1::Open
    );
    let config = original.configuration();
    assert_eq!(
        config.expected_policy_revision,
        Some(original.registry_policy().revision)
    );
    assert_eq!(config.request_timeout_ms, Some(REQUEST_TIMEOUT_MS));
    assert_eq!(config.provider_gateways.len(), 3);
    let root = format!("{}/", original.service_plan().https_origin());
    assert_eq!(config.seed_ingress_url.as_deref(), Some(root.as_str()));
    assert_eq!(
        config.storage_coordinator_url.as_deref(),
        Some(root.as_str())
    );
    assert_eq!(
        config.seed_provider.as_deref(),
        Some(hex::encode(manifest.providers[0].provider_id.as_bytes()).as_str())
    );
    let _address = ChainDiscriminantGuard::enter(client.account_chain_discriminant);
    assert_eq!(
        config.ingress_broker.as_deref(),
        Some(
            original
                .service_plan()
                .ingress_broker()
                .to_string()
                .as_str()
        )
    );
    assert_ne!(
        original.publisher(),
        original.service_plan().ingress_broker()
    );
    assert_ne!(
        original.publisher(),
        original.service_plan().pin_authority()
    );
    for (index, provider) in config.provider_gateways.iter().enumerate() {
        assert_eq!(
            provider.provider_id,
            hex::encode(manifest.providers[index].provider_id.as_bytes())
        );
        assert_eq!(provider.url, root);
        assert_eq!(provider.attestation_url, prepared.peers[index].torii_url);
        assert_ne!(provider.attestation_url, provider.url);
    }
    assert_eq!(
        config
            .provider_gateways
            .iter()
            .map(|provider| &provider.attestation_url)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    assert!(config.namespace_delegation_file.is_none());
    let installation = original.service_plan().installation_config();
    let selected = installation.installation.as_ref().unwrap();

    assert_eq!(
        original.namespace_fee_payment(),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                selected.pin_fee_asset.clone(),
                selected.pin_per_transaction_fee_limit.clone(),
            )],
            None
        )
    );
    assert_eq!(
        original
            .publication_transport()
            .unwrap()
            .base_url()
            .as_str(),
        root
    );
    assert_eq!(
        original.client_config_path(),
        prepared.context.client_config
    );
    assert_eq!(
        original.client_config_image(),
        iroha_fs::read_private(&prepared.context.client_config, MAX_CLIENT_BYTES)
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        format!("{original:?}"),
        "RetainedPublicationClientConfig { validated: true, .. }"
    );
    assert_eq!(
        original.namespace_journal_root(),
        prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(NAMESPACE_JOURNAL_DIRECTORY)
    );
    assert!(
        !original
            .namespace_journal_root()
            .starts_with(&installation.custody_root)
    );
    let publication_root = prepared
        .context
        .client_config
        .parent()
        .unwrap()
        .join(LOCALNET_RUNTIME_DIRECTORY)
        .join("publication-client");
    assert_eq!(
        original.publication_state_root(),
        publication_root.join("operations")
    );
    assert_eq!(
        original.publication_cache_root(),
        publication_root.join("cache")
    );
    assert_ne!(
        original.publication_state_root(),
        original.namespace_journal_root()
    );
    let operations = PrivateDirectory::open_exact(original.publication_state_root()).unwrap();
    let operations_identity = operations.identity().unwrap();
    let journal =
        iroha_musubi_service::publication_client_journal::open_existing(operations.path()).unwrap();
    let journal_identity = journal.identity().unwrap();
    assert!(journal.entries(1).unwrap().is_empty());
    drop(journal);
    assert_eq!(
        operations.entries(1).unwrap(),
        vec![std::ffi::OsString::from(
            iroha_musubi_service::publication_client_journal::DIRECTORY_NAME
        )]
    );
    assert!(!original.publication_cache_root().exists());
    drop(operations);
    let namespace_directory =
        PrivateDirectory::open_exact(original.namespace_journal_root()).unwrap();
    let parent_bytes = namespace_directory
        .read("operation.json", MAX_CLIENT_BYTES)
        .unwrap();
    let wallet = iroha_wallet::operations::AccountService::new(client.clone()).unwrap();
    let namespace_selection = iroha_wallet::operations::MusubiNamespaceBindingSelection {
        chain_id: client.chain.to_string(),
        network_id: client.network_id,
        owner: client.account.clone(),
        binding: original.namespace_binding().clone(),
        expected_policy_revision: original.registry_policy().revision,
    };
    let _held_parent = wallet
        .open_musubi_namespace_binding_parent(
            original.namespace_journal_root(),
            &namespace_selection,
            &original.namespace_fee_payment(),
        )
        .unwrap();
    // A profile handoff must remain possible while the sole wallet owner holds its parent lock.
    // The real genesis native projection within the handoff already checked both Domain and
    // active SNS ownership, unchanged admin namespaces, and complete temporary-role removal.
    let again = prepared.publication_client_config().unwrap().unwrap();
    assert_eq!(again.namespace_binding(), original.namespace_binding());
    assert_eq!(again.registry_policy(), original.registry_policy());
    assert_eq!(again.client_config_image(), original.client_config_image());
    assert_eq!(
        again.publication_state_root(),
        original.publication_state_root()
    );
    assert_eq!(
        again.publication_cache_root(),
        original.publication_cache_root()
    );
    let operations = PrivateDirectory::open_exact(again.publication_state_root()).unwrap();
    assert_eq!(operations.identity().unwrap(), operations_identity);
    let journal =
        iroha_musubi_service::publication_client_journal::open_existing(operations.path()).unwrap();
    assert_eq!(journal.identity().unwrap(), journal_identity);
    assert!(journal.entries(1).unwrap().is_empty());
    drop(journal);
    assert_eq!(
        operations.entries(1).unwrap(),
        vec![std::ffi::OsString::from(
            iroha_musubi_service::publication_client_journal::DIRECTORY_NAME
        )]
    );
    assert!(!again.publication_cache_root().exists());
    drop(operations);
    // Profile observation never repairs either part of original journal custody.
    std::fs::remove_dir(
        again
            .publication_state_root()
            .join(iroha_musubi_service::publication_client_journal::DIRECTORY_NAME),
    )
    .unwrap();
    let after_inner_loss = prepared.publication_client_config().unwrap().unwrap();
    let retained_outer =
        PrivateDirectory::open_exact(after_inner_loss.publication_state_root()).unwrap();
    assert_eq!(retained_outer.identity().unwrap(), operations_identity);
    assert!(retained_outer.entries(1).unwrap().is_empty());
    assert!(
        iroha_musubi_service::publication_client_journal::open_existing(retained_outer.path())
            .is_err()
    );
    assert!(
        !retained_outer
            .path()
            .join(iroha_musubi_service::publication_client_journal::DIRECTORY_NAME)
            .exists()
    );
    drop(retained_outer);
    std::fs::remove_dir(again.publication_state_root()).unwrap();
    let after_loss = prepared.publication_client_config().unwrap().unwrap();
    assert_eq!(
        after_loss.publication_state_root(),
        original.publication_state_root()
    );
    assert!(PrivateDirectory::open_exact(after_loss.publication_state_root()).is_err());
    assert!(!after_loss.publication_state_root().exists());
    assert!(!after_loss.publication_cache_root().exists());
    assert_eq!(
        namespace_directory
            .read("operation.json", MAX_CLIENT_BYTES)
            .unwrap()
            .as_slice(),
        parent_bytes.as_slice()
    );
}

fn replace_exact(text: &str, from: &str, to: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "fixture target must be unique"
    );
    text.replacen(from, to, 1)
}

#[test]
fn publication_client_refuses_each_endpoint_provider_policy_and_image_substitution_then_restores() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepare(
        &temporary.path().join("generation"),
        LocalnetServiceProfile::StreamTokenAuthorities,
    );
    let original = prepared.publication_client_config().unwrap().unwrap();
    let directory =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let bytes = directory.read("client.toml", MAX_CLIENT_BYTES).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let config = original.configuration();
    let first = &config.provider_gateways[0].provider_id;
    let second = &config.provider_gateways[1].provider_id;
    let first_line = format!("provider_id = \"{first}\"");
    let second_line = format!("provider_id = \"{second}\"");
    let swapped = replace_exact(text, &first_line, "provider_id = \"SWAP\"");
    let swapped = replace_exact(&swapped, &second_line, &first_line);
    let swapped = replace_exact(&swapped, "provider_id = \"SWAP\"", &second_line);
    let candidates = [
        replace_exact(
            text,
            &format!(
                "seed_ingress_url = \"{}\"",
                config.seed_ingress_url.as_deref().unwrap()
            ),
            "seed_ingress_url = \"https://foreign.invalid:7443/\"",
        ),
        replace_exact(
            text,
            &format!(
                "storage_coordinator_url = \"{}\"",
                config.storage_coordinator_url.as_deref().unwrap()
            ),
            "storage_coordinator_url = \"https://foreign.invalid:7444/\"",
        ),
        replace_exact(
            text,
            &format!(
                "attestation_url = \"{}\"",
                config.provider_gateways[1].attestation_url
            ),
            &format!(
                "attestation_url = \"{}\"",
                config.provider_gateways[0].attestation_url
            ),
        ),
        replace_exact(
            text,
            &format!(
                "expected_policy_revision = {}",
                original.registry_policy().revision
            ),
            &format!(
                "expected_policy_revision = {}",
                original.registry_policy().revision + 1
            ),
        ),
        replace_exact(
            text,
            "request_timeout_ms = 30000",
            "request_timeout_ms = 30001",
        ),
        swapped,
        replace_exact(
            text,
            "web_login = \"mad_hatter\"",
            "web_login = \"changed\"",
        ),
        format!("{text}\n# changed original image\n"),
    ];
    for changed in candidates {
        let changed = Zeroizing::new(changed);
        directory
            .write_atomic("client.toml", changed.as_bytes(), PublishMode::Replace)
            .unwrap();
        assert!(prepared.publication_client_config().is_err());
        assert_eq!(
            directory
                .read("client.toml", MAX_CLIENT_BYTES)
                .unwrap()
                .as_slice(),
            changed.as_bytes(),
            "refusal cannot repair or normalize the original"
        );
    }
    directory
        .write_atomic("client.toml", &bytes, PublishMode::Replace)
        .unwrap();
    let restored = prepared.publication_client_config().unwrap().unwrap();
    assert_eq!(restored.client_config_image(), bytes.as_slice());
    assert_eq!(restored.registry_policy(), original.registry_policy());
    assert_eq!(restored.namespace_binding(), original.namespace_binding());
    let mut mismatched = prepared.clone();
    mismatched.peers.swap(1, 2);
    assert!(mismatched.publication_client_config().is_err());
    let mut changed_origin = prepared.clone();
    changed_origin.peers[1].torii_url = "http://127.0.0.1:1/".into();
    assert!(changed_origin.publication_client_config().is_err());
}

#[test]
fn standard_and_private_profiles_keep_publication_absent_and_reject_inserted_section() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let standard = prepare(
        &temporary.path().join("standard"),
        LocalnetServiceProfile::Standard,
    );
    assert!(standard.publication_client_config().unwrap().is_none());
    let name = "publicationprivate";
    let selector = iroha_data_model::sns::NameSelectorV1::new(
        iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID,
        name,
    )
    .unwrap();
    let spec = PrivateRootSpec {
        parent_network_id: standard.context.network_id.parse().unwrap(),
        dataspace_id: DataSpaceId::from_hash(&selector.name_hash()),
        dataspace_alias: name.into(),
    };
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let private = prepare_private_root(
        "publication-private",
        &temporary.path().join("private"),
        &ports,
        &spec,
    )
    .unwrap();
    for prepared in [&standard, &private] {
        assert!(prepared.publication_client_config().unwrap().is_none());
        let directory =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let original = directory.read("client.toml", MAX_CLIENT_BYTES).unwrap();
        let mut changed = Zeroizing::new(original.to_vec());
        changed.extend_from_slice(b"\n[musubi.publication]\nrequest_timeout_ms = 30000\n");
        directory
            .write_atomic("client.toml", &changed, PublishMode::Replace)
            .unwrap();
        assert!(prepared.publication_client_config().is_err());
        directory
            .write_atomic("client.toml", &original, PublishMode::Replace)
            .unwrap();
        assert!(prepared.publication_client_config().unwrap().is_none());
    }
}

#[test]
fn generated_inventory_origin_requires_exact_nonzero_numeric_loopback_root() {
    assert_eq!(loopback_port("http://127.0.0.1:8080/").unwrap(), 8080);
    for value in [
        "http://127.0.0.1:0/",
        "http://localhost:8080/",
        "http://[::1]:8080/",
        "https://127.0.0.1:8080/",
        "http://127.0.0.1:8080/private",
        "http://127.0.0.1:8080/?query",
        "http://user@127.0.0.1:8080/",
        "http://127.0.0.1:8080/#fragment",
        "http://192.0.2.1:8080/",
    ] {
        assert!(loopback_port(value).is_err(), "{value}");
    }
}
