//! Explicit generated command/namespace integration controls. HTTP pages are transport specimens;
//! genuine paid namespace execution is covered by the generated deploy native component.
use super::*;
use crate::{
    generated_publication::{
        Execution, GeneratedPublishAction, GeneratedPublishRequest, OutputFormat, ensure_namespace,
        publish_generated,
    },
    publication_runtime::tests::serve_json_once,
};
use iroha_data_model::musubi::{
    MusubiOrderedPackagePageV1, MusubiOrderedPrefixQueryV1, MusubiOrderedPrefixV1,
    MusubiPageRequestV1, MusubiRegistrySnapshotV1,
};
use iroha_storage_client::musubi_archive_fetch::{
    GeneratedLocalProviderTransportV1, MusubiArchiveDiscoveryErrorV1,
    PreparedMusubiArchiveFetchConfigV1,
};
use iroha_wallet::operations::{AccountService, MusubiNamespaceBindingSelection};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
fn config(fixture: &Fixture) -> iroha::config::Config {
    iroha::config::Config::load_bytes_with_musubi_publication(&fixture.path, &fixture.bytes)
        .unwrap()
        .0
}
fn set_torii(fixture: &mut Fixture, url: &str) {
    let text = String::from_utf8(fixture.bytes.clone()).unwrap();
    fixture.bytes = text.replace("http://127.0.0.1:8181/", url).into_bytes();
    std::fs::write(&fixture.path, &fixture.bytes).unwrap();
}
fn no_http_fixture() -> (Fixture, TcpListener) {
    let mut fixture = Fixture::new();
    let torii = TcpListener::bind("127.0.0.1:0").unwrap();
    torii.set_nonblocking(true).unwrap();
    set_torii(
        &mut fixture,
        &format!("http://{}/", torii.local_addr().unwrap()),
    );
    (fixture, torii)
}
fn initialize_parent(fixture: &Fixture) {
    let config = config(fixture);
    let selection = MusubiNamespaceBindingSelection {
        chain_id: config.chain.to_string(),
        network_id: config.network_id,
        owner: fixture.namespace.publisher.clone(),
        binding: fixture.namespace.binding.clone(),
        expected_policy_revision: fixture.namespace.policy.revision,
    };
    AccountService::new(config)
        .unwrap()
        .initialize_musubi_namespace_binding_parent(
            &fixture.namespace.journal_root,
            &selection,
            &fixture.namespace.fee_payment,
        )
        .unwrap();
}
fn archive_transport(
    config: iroha::config::Config,
    calls: &Arc<AtomicUsize>,
    local: bool,
) -> PreparedMusubiArchiveFetchConfigV1 {
    let count = calls.clone();
    let discovery = Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        Err(MusubiArchiveDiscoveryErrorV1::Rejected)
    });
    if !local {
        return PreparedMusubiArchiveFetchConfigV1::from_account_registry(
            config,
            discovery,
            Duration::from_secs(1),
        )
        .unwrap();
    }
    let originals = std::array::from_fn(|index| {
        // Original intent construction only; this fixture never constructs native discovery.
        let selected = ProviderId::new([0x21 + u8::try_from(index).unwrap(); 32]);
        let encoded = hex::encode(selected.as_bytes());
        let hostname = format!("{}.{}.localhost", &encoded[..32], &encoded[32..]);
        let mut original = material(&Identity::for_host(hostname.clone()), 8444);
        original.proposal.endpoints[0].endpoint.host_pattern = hostname.clone();
        let read = RegisteredAccountReadV1 {
            https_host: hostname,
            https_port: 8444,
            ttl_secs: 60,
            max_streams: 1,
            rate_limit_bytes: 1024,
            requests_per_minute: 60,
        };
        original.proposal.capabilities[1] = read.to_capability().unwrap();
        original.advert_body.capabilities = original.proposal.capabilities.clone();
        original.advert_body.endpoints = vec![original.proposal.endpoints[0].endpoint.clone()];
        original.proposal.provider_id = *selected.as_bytes();
        original.advert_body.provider_id = *selected.as_bytes();
        GeneratedLocalProviderTransportV1::select(
            config.network_id,
            config.chain.as_str(),
            selected,
            &config.account,
            &original,
        )
        .unwrap()
    });
    PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
        config,
        discovery,
        originals,
        Duration::from_secs(1),
    )
    .unwrap()
}
fn request(
    fixture: &Fixture,
    transport: PreparedMusubiArchiveFetchConfigV1,
) -> GeneratedPublishRequest {
    GeneratedPublishRequest {
        manifest_path: fixture.temporary.path().join("Musubi.toml"),
        state_root: fixture.temporary.path().join("publication-state"),
        cache_root: fixture.temporary.path().join("archive-cache"),
        archive_transport: transport,
        action: GeneratedPublishAction::Begin {
            package: None,
            detach: false,
        },
    }
}
fn page(fixture: &Fixture) -> MusubiOrderedPackagePageV1 {
    MusubiOrderedPackagePageV1 {
        query: MusubiOrderedPrefixQueryV1 {
            prefix: MusubiOrderedPrefixV1::new("dev.universal/").unwrap(),
            page: MusubiPageRequestV1 {
                limit: 1,
                cursor: None,
            },
        },
        network_id: config(fixture).network_id,
        namespace_binding: fixture.namespace.binding.clone(),
        items: vec![],
        next_cursor: None,
        snapshot: MusubiRegistrySnapshotV1 {
            finalized_height: 2,
            finalized_block_hash: [0x71; 32],
            index_revision: 1,
        },
    }
}
fn parent_image(fixture: &Fixture) -> Vec<(String, Vec<u8>)> {
    let mut entries = std::fs::read_dir(&fixture.namespace.journal_root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}
#[test]
fn generated_publish_rejects_remote_or_different_transport_identity_before_io() {
    let (fixture, torii) = no_http_fixture();
    let context = fixture.context().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    for kind in 0..4 {
        let mut selected = config(&fixture);
        match kind {
            1 => selected.chain = "different-original".parse().unwrap(),
            2 => selected.network_id = crate::publication_runtime::tests::test_network_id(0x7d),
            3 => {
                selected.key_pair = KeyPair::from_seed(vec![0x63; 32], Algorithm::Ed25519);
                selected.account = AccountId::new(selected.key_pair.public_key().clone());
            }
            _ => {}
        }
        let request = request(&fixture, archive_transport(selected, &calls, kind != 0));
        let outcome = publish_generated(&context, &request);
        assert_ne!(outcome.exit_code(), 0);
        let rendered = outcome.render(OutputFormat::Json).unwrap();
        assert!(rendered.stdout().contains("musubi-cli-output"));
        assert!(!rendered.stdout().contains(
            &ExposedPrivateKey(config(&fixture).key_pair.private_key().clone()).to_string()
        ));
        assert!(!request.state_root.exists());
        assert!(!request.cache_root.exists());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!fixture.namespace.journal_root.exists());
    assert_eq!(
        torii.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    fixture.no_http();
}
#[test]
fn generated_execution_requires_original_image_and_explicit_absolute_storage_paths() {
    let (fixture, torii) = no_http_fixture();
    let context = fixture.context().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut request = request(&fixture, archive_transport(config(&fixture), &calls, true));
    let execution = |request: &GeneratedPublishRequest| {
        Execution {
            context: &context,
            state_root: &request.state_root,
            cache_root: &request.cache_root,
            archive_transport: &request.archive_transport,
        }
        .validate()
    };
    execution(&request).unwrap();
    request.cache_root = PathBuf::from("relative-cache");
    assert!(execution(&request).is_err());
    request.cache_root = fixture.temporary.path().join("archive-cache");
    request.state_root = PathBuf::from("relative-state");
    assert!(execution(&request).is_err());
    request.state_root = fixture.temporary.path().join("publication-state");
    std::fs::write(
        &fixture.path,
        [fixture.bytes.as_slice(), b"\n# replaced original\n"].concat(),
    )
    .unwrap();
    assert!(execution(&request).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        torii.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    fixture.no_http();
}
#[test]
fn namespace_mismatch_missing_parent_and_missing_anchor_refuse_before_http() {
    let mut fixture = Fixture::new();
    let torii = TcpListener::bind("127.0.0.1:0").unwrap();
    torii.set_nonblocking(true).unwrap();
    set_torii(
        &mut fixture,
        &format!("http://{}/", torii.local_addr().unwrap()),
    );
    let context = fixture.context().unwrap();
    assert!(ensure_namespace(&context, &"other.universal".parse().unwrap(), true).is_err());
    assert!(ensure_namespace(&context, &fixture.namespace.binding.namespace, true).is_err());
    assert!(!fixture.namespace.journal_root.exists());
    initialize_parent(&fixture);
    std::fs::remove_file(fixture.namespace.journal_root.join("custody-anchor.nrt")).unwrap();
    assert!(ensure_namespace(&context, &fixture.namespace.binding.namespace, true).is_err());
    assert_eq!(
        torii.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    fixture.no_http();
}
#[test]
fn exact_current_namespace_skips_writing_only_after_original_custody_validation() {
    let mut fixture = Fixture::new();
    let response = page(&fixture);
    response.validate().unwrap();
    let (url, server) = serve_json_once("200 OK", norito::json::to_vec(&response).unwrap());
    set_torii(&mut fixture, url.as_str());
    initialize_parent(&fixture);
    let original = parent_image(&fixture);
    let context = fixture.context().unwrap();
    ensure_namespace(&context, &fixture.namespace.binding.namespace, false).unwrap();
    let observed: MusubiOrderedPrefixQueryV1 =
        norito::json::from_slice(&server.join().unwrap()).unwrap();
    assert_eq!(observed, response.query);
    assert_eq!(parent_image(&fixture), original);
    assert_eq!(original.len(), 3); // lock, original and mandatory empty anchor; no attempt created.
    fixture.no_http();
}
#[test]
fn changed_current_binding_and_readonly_absence_cannot_create_namespace_attempt() {
    for missing in [false, true] {
        let mut fixture = Fixture::new();
        let mut response = page(&fixture);
        response.namespace_binding.generation += 1;
        response.validate().unwrap();
        let (url, server) = if missing {
            serve_json_once("404 Not Found", vec![])
        } else {
            serve_json_once("200 OK", norito::json::to_vec(&response).unwrap())
        };
        set_torii(&mut fixture, url.as_str());
        initialize_parent(&fixture);
        let original = parent_image(&fixture);
        let context = fixture.context().unwrap();
        assert!(ensure_namespace(&context, &fixture.namespace.binding.namespace, false).is_err());
        server.join().unwrap();
        assert_eq!(parent_image(&fixture), original);
        fixture.no_http();
    }
}

#[test]
fn generated_recovery_joins_complete_original_request_before_network_observation() {
    let (fixture, torii) = no_http_fixture();
    let context = fixture.context().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = archive_transport(config(&fixture), &calls, true);
    let state = fixture.temporary.path().join("state");
    let cache = fixture.temporary.path().join("cache");
    let execution = Execution {
        context: &context,
        state_root: &state,
        cache_root: &cache,
        archive_transport: &transport,
    };
    // A structural retained-request specimen, never native finality or a publication success.
    let mut original = crate::publication_runtime::tests::original_request_fixture();
    original.network_id = config(&fixture).network_id;
    original.publisher = fixture.namespace.publisher.clone();
    original.namespace = fixture.namespace.binding.namespace.clone();
    original.publication.manifest.release.package.home_dataspace =
        fixture.namespace.binding.home_dataspace;
    original.publication.manifest.release.package.scope = fixture.namespace.binding.scope.clone();
    original.expected_policy_revision = fixture.namespace.policy.revision;
    original.seed_provider = fixture.transport.provider_id();
    original.ingress_broker = fixture.transport.provider_owner().clone();
    original.namespace_delegation = None;
    execution.validate_journal(&original).unwrap();
    for kind in 0..8 {
        let mut changed = original.clone();
        match kind {
            0 => changed.network_id = crate::publication_runtime::tests::test_network_id(0x7d),
            1 => {
                changed.publisher = AccountId::new(
                    KeyPair::from_seed(vec![0x69; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            }
            2 => changed.namespace = "other.universal".parse().unwrap(),
            3 => changed.publication.manifest.release.package.home_dataspace = DataSpaceId::new(1),
            4 => {
                changed.publication.manifest.release.package.scope =
                    MusubiPackageScopeV1::DataspaceRoot
            }
            5 => changed.expected_policy_revision += 1,
            6 => changed.seed_provider = ProviderId::new([0x99; 32]),
            7 => changed.ingress_broker = fixture.namespace.publisher.clone(),
            _ => unreachable!(),
        }
        assert!(execution.validate_journal(&changed).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!state.exists());
    assert!(!cache.exists());
    assert_eq!(
        torii.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    fixture.no_http();
}

#[test]
fn generated_begin_reaches_original_namespace_custody_before_graph_or_user_cache() {
    use std::ffi::OsString;
    let (fixture, torii) = no_http_fixture();
    let context = fixture.context().unwrap();
    let package_root = fixture.temporary.path().join("demo");
    let created = crate::command::invoke([
        OsString::from("musubi"),
        OsString::from("new"),
        package_root.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("library"),
        OsString::from("--namespace"),
        OsString::from("dev.universal"),
        OsString::from("--export"),
        OsString::from("run"),
    ]);
    assert_eq!(created.output.exit_code(), 0);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut request = request(&fixture, archive_transport(config(&fixture), &calls, true));
    request.manifest_path = package_root.join("Musubi.toml");
    let outer = iroha_fs::PrivateDirectory::open_or_create(&request.state_root).unwrap();
    let original =
        iroha_musubi_service::publication_client_journal::initialize(outer.path()).unwrap();
    let original_identity = original.identity().unwrap();
    let outcome = publish_generated(&context, &request);
    assert_ne!(outcome.exit_code(), 0);
    assert!(
        outcome
            .render(OutputFormat::Human)
            .unwrap()
            .stderr()
            .contains("generated namespace preflight")
    );
    assert_eq!(original.identity().unwrap(), original_identity);
    assert!(original.entries(1).unwrap().is_empty());
    assert_eq!(
        outer.entries(1).unwrap(),
        vec![std::ffi::OsString::from(
            iroha_musubi_service::publication_client_journal::DIRECTORY_NAME,
        )]
    );
    assert!(!request.cache_root.exists());
    assert!(!fixture.namespace.journal_root.exists());
    assert!(
        !package_root
            .join("target/package/Musubi.publish.lock")
            .exists()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        torii.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    fixture.no_http();
}

#[test]
fn generated_actions_refuse_lost_original_client_history_before_any_http() {
    use crate::publish::PublicationJournalStore;
    use iroha_musubi_service::publication_client_journal;
    use std::ffi::OsString;

    for lose_outer in [false, true] {
        let (fixture, torii) = no_http_fixture();
        initialize_parent(&fixture);
        let namespace_before = parent_image(&fixture);
        let context = fixture.context().unwrap();
        let package_root = fixture.temporary.path().join("lost-history-package");
        let created = crate::command::invoke([
            OsString::from("musubi"),
            OsString::from("new"),
            package_root.as_os_str().to_owned(),
            OsString::from("--template"),
            OsString::from("library"),
            OsString::from("--namespace"),
            OsString::from("dev.universal"),
            OsString::from("--export"),
            OsString::from("run"),
        ]);
        assert_eq!(created.output.exit_code(), 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut request = request(&fixture, archive_transport(config(&fixture), &calls, true));
        request.manifest_path = package_root.join("Musubi.toml");
        let outer = iroha_fs::PrivateDirectory::open_or_create(&request.state_root).unwrap();
        drop(publication_client_journal::initialize(outer.path()).unwrap());
        // Durable canonical client intent only. No native completion or readiness is fabricated.
        let mut original = crate::publication_runtime::tests::original_request_fixture();
        original.network_id = config(&fixture).network_id;
        original.publisher = fixture.namespace.publisher.clone();
        original.namespace = fixture.namespace.binding.namespace.clone();
        original.publication.manifest.release.package.home_dataspace =
            fixture.namespace.binding.home_dataspace;
        original.publication.manifest.release.package.scope =
            fixture.namespace.binding.scope.clone();
        original.publication.resolution.lock.root = original.publication.manifest.release.clone();
        original.publication.manifest.verification_lock_digest =
            original.publication.resolution.lock.digest();
        original.expected_policy_revision = fixture.namespace.policy.revision;
        original.seed_provider = fixture.transport.provider_id();
        original.ingress_broker = fixture.transport.provider_owner().clone();
        original.namespace_delegation = None;
        original.validate().unwrap();
        Execution {
            context: &context,
            state_root: &request.state_root,
            cache_root: &request.cache_root,
            archive_transport: &request.archive_transport,
        }
        .validate_journal(&original)
        .unwrap();
        let operation_id = original.operation_id();
        {
            let store = PublicationJournalStore::open_existing(outer.path()).unwrap();
            store.create(original.clone()).unwrap();
            assert_eq!(store.load(operation_id).unwrap().request, original);
        }
        let inner_path = request
            .state_root
            .join(publication_client_journal::DIRECTORY_NAME);
        std::fs::remove_dir_all(&inner_path).unwrap();
        assert!(outer.entries(1).unwrap().is_empty());
        drop(outer);
        if lose_outer {
            std::fs::remove_dir(&request.state_root).unwrap();
        }
        for action in [
            GeneratedPublishAction::Begin {
                package: None,
                detach: false,
            },
            GeneratedPublishAction::Resume { operation_id },
            GeneratedPublishAction::Recover { operation_id },
        ] {
            request.action = action;
            let outcome = publish_generated(&context, &request);
            assert_ne!(outcome.exit_code(), 0);
            assert!(
                outcome
                    .render(OutputFormat::Json)
                    .unwrap()
                    .stdout()
                    .contains("PUBLICATION_JOURNAL_IO")
            );
            assert_eq!(request.state_root.exists(), !lose_outer);
            assert!(!inner_path.exists());
            assert!(!request.cache_root.exists());
            assert!(
                !package_root
                    .join("target/package/Musubi.publish.lock")
                    .exists()
            );
            assert_eq!(parent_image(&fixture), namespace_before);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                torii.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            fixture.no_http();
        }
    }
}

#[test]
fn generated_publish_entry_refuses_foreign_member_before_journals_namespace_or_http() {
    let (fixture, torii) = no_http_fixture();
    let context = fixture.context().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut request = request(&fixture, archive_transport(config(&fixture), &calls, true));
    let root = fixture.temporary.path().join("member-workspace");
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::create_dir(root.join("other")).unwrap();
    std::fs::write(root.join("Musubi.toml"), "manifest-version = 1\n[workspace]\nmembers = [\"app\", \"other\"]\ndefault-members = [\"other\"]\n").unwrap();
    for name in ["app", "other"] {
        std::fs::write(root.join(name).join("Musubi.toml"), format!("manifest-version = 1\n[package]\nnamespace = \"dev.universal\"\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n")).unwrap();
    }
    Execution {
        context: &context,
        state_root: &request.state_root,
        cache_root: &request.cache_root,
        archive_transport: &request.archive_transport,
    }
    .validate()
    .unwrap();
    for input in [root.join("app/Musubi.toml"), root.join("app")] {
        request.manifest_path = input;
        request.action = GeneratedPublishAction::Begin {
            package: Some("dev.universal/other".parse().unwrap()),
            detach: false,
        };
        let outcome = publish_generated(&context, &request);
        assert_eq!(
            outcome.exit_code(),
            crate::output::ErrorCode::Usage.exit_code()
        );
        let rendered = outcome.render(OutputFormat::Json).unwrap();
        assert!(
            rendered
                .stdout()
                .contains("selected member manifest cannot select another package")
        );
        assert!(!request.state_root.exists());
        assert!(!request.cache_root.exists());
        assert!(!fixture.namespace.journal_root.exists());
        assert!(!root.join("Musubi.lock").exists());
        assert!(!root.join("target").exists());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            torii.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    fixture.no_http();
}
