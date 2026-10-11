//! Managed generation, custody, lifecycle selection and resource regression tests.

use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    net::{Ipv4Addr, TcpListener},
    path::Path,
};

#[path = "attachment_installed_tests.rs"]
mod attachment_installed;
#[path = "installed_tests.rs"]
mod installed;

#[test]
fn global_and_private_requests_select_only_their_original_scope_prerequisites() {
    use crate::localnet::LocalnetServiceProfile;
    let launcher = PathBuf::from("installed-kagami");
    let daemon = PathBuf::from("installed-iroha3d");
    let global = LocalnetRequest::new(launcher.clone(), daemon.clone());
    let private = LocalnetRequest::private_root(launcher.clone(), daemon.clone());
    assert_eq!(
        global.service_profile,
        LocalnetServiceProfile::StreamTokenAuthorities
    );
    assert_eq!(private.service_profile, LocalnetServiceProfile::Standard);
    assert_eq!(
        LocalnetServiceProfile::default(),
        LocalnetServiceProfile::Standard
    );
    for request in [&global, &private] {
        assert_eq!(request.name, "local");
        assert_eq!(request.launcher, launcher);
        assert_eq!(request.daemon, daemon);
        assert_eq!(request.startup_timeout, Duration::from_secs(30));
    }
}

// These lifecycle fixtures reuse only immutable public bytes from genuine executed genesis.
// They do not cache any runtime authority, current-state observation or finalized proof.
fn standard_fixture_genesis() -> &'static (Vec<u8>, String, String) {
    static GENESIS: std::sync::OnceLock<(Vec<u8>, String, String)> = std::sync::OnceLock::new();
    GENESIS.get_or_init(|| {
        let temporary = tempfile::tempdir().unwrap();
        let ports = LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "fixture-genesis",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::Standard,
            None,
        )
        .unwrap();
        assert!(prepared.stream_token_authorities().unwrap().is_none());
        let genesis = iroha_fs::read_private(
            prepared
                .context
                .client_config
                .parent()
                .unwrap()
                .join("genesis.signed.nrt"),
            iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
        )
        .unwrap();
        // Only the public signed block is retained; the private reader zeroizes its buffer.
        (
            genesis.to_vec(),
            prepared.context.network_id,
            prepared.context.account_id,
        )
    })
}

pub(super) fn fixture(
    root: &Path,
    name: &str,
) -> (ManagedStore, PrivateDirectory, PreparedLocalnet) {
    let store = ManagedStore::open(root).unwrap();
    let networks = PrivateDirectory::open(root.join("networks")).unwrap();
    let directory = networks.create_child(name).unwrap();
    let bundle = directory.create_child("generation").unwrap();
    let (genesis, network_id, account_id) = standard_fixture_genesis();
    bundle
        .write_atomic("genesis.signed.nrt", genesis, PublishMode::CreateNew)
        .unwrap();
    bundle
        .write_atomic("client.toml", b"private config", PublishMode::CreateNew)
        .unwrap();
    let mut peers = Vec::new();
    for index in 0..4 {
        let config_name = format!("peer{index}.toml");
        bundle
            .write_atomic(&config_name, b"private node", PublishMode::CreateNew)
            .unwrap();
        peers.push(ManagedPeer {
            config_path: bundle.path().join(config_name),
            torii_url: format!("http://127.0.0.1:{}/", 19080 + index),
            log_name: format!("peer{index}.log"),
        });
    }
    let prepared = PreparedLocalnet {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        context: ManagedContext {
            name: name.into(),
            chain_id: "local".into(),
            network_id: network_id.clone(),
            account_id: account_id.clone(),
            dataspace_id: 0,
            dataspace_alias: "universal".into(),
            torii_url: peers[0].torii_url.clone(),
            client_config: bundle.path().join("client.toml"),
        },
        peers,
    };
    let pin = store::pin_binary(&std::env::current_exe().unwrap()).unwrap();
    let retained = RetainedLocalnet {
        root_kind: RootKind::Global,
        prepared: prepared.clone(),
        launcher: pin.clone(),
        daemon: pin,
        startup_timeout_ms: 30000,
    };
    bundle
        .write_atomic(
            MANIFEST,
            &encode(&retained).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    (store, directory, prepared)
}

#[test]
fn names_cannot_escape_the_context_root() {
    let _resources = super::native_test_guard();
    for name in [
        "",
        ".",
        "..",
        "../other",
        "foo/bar",
        "foo\\bar",
        "/tmp",
        "-bad",
        "local net",
        "日本",
    ] {
        assert!(validate_name(name).is_err(), "{name:?}");
    }
    for name in ["local", "Acme_2", "private-test"] {
        validate_name(name).unwrap();
    }
    for length in [48, 49, 63] {
        validate_name(&"x".repeat(length)).unwrap();
    }
    assert!(validate_name(&"x".repeat(64)).is_err());
}

#[test]
fn full_length_dataspace_names_retain_distinct_native_directory_identity() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    for length in [49, 63] {
        let prefix = "a".repeat(length - 1);
        let names = [format!("{prefix}b"), format!("{prefix}c")];
        assert_eq!(&names[0][..48], &names[1][..48]);
        for name in &names {
            iroha_wallet::namespace::resolve_private_owner_alias(name, "admin").unwrap();
            let network = networks.ensure_child(name).unwrap();
            network
                .write_atomic("identity", name.as_bytes(), PublishMode::CreateNew)
                .unwrap();
            let attachment = store
                .publish_attachment(name, &[("identity", name.as_bytes())])
                .unwrap();
            assert_eq!(attachment.path().file_name().unwrap(), name.as_str());
        }
        for name in &names {
            let reopened = store.directory(name).unwrap();
            assert_eq!(reopened.path().file_name().unwrap(), name.as_str());
            assert_eq!(
                reopened.read("identity", 64).unwrap().as_slice(),
                name.as_bytes()
            );
            let attachment = store
                .attachments_directory()
                .unwrap()
                .unwrap()
                .open_child(name)
                .unwrap();
            assert_eq!(
                attachment.read("identity", 64).unwrap().as_slice(),
                name.as_bytes()
            );
        }
    }
    let invalid = "a".repeat(64);
    assert!(iroha_wallet::namespace::resolve_private_owner_alias(&invalid, "admin").is_err());
    assert!(store.directory(&invalid).is_err());
    assert!(
        store
            .publish_attachment(&invalid, &[("identity", b"invalid")])
            .is_err()
    );
    assert!(!store.root().join("attachments").join(&invalid).exists());
}

#[test]
fn retained_root_kind_is_mandatory_and_private_identity_cannot_replace_global() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, _) = fixture(&temporary.path().join("managed"), "local");
    let bytes = encode(&generation::read(&directory).unwrap()).unwrap();
    let mut value: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("root_kind");
    assert!(decode::<RetainedLocalnet>(&norito::json::to_vec(&value).unwrap()).is_err());
    let spec = private_spec();
    let binary = std::env::current_exe().unwrap();
    let request = LocalnetRequest::private_root(binary.clone(), binary);
    let error = store.up_private_root(&request, &spec).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("different immutable root identity")
    );
    assert!(!directory.path().join(WORKER).exists());
    assert_eq!(
        encode(&generation::read(&directory).unwrap()).unwrap(),
        bytes
    );
}

pub(super) fn private_spec() -> crate::localnet::PrivateRootSpec {
    use iroha_data_model::sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1};
    let alias = "privateapp";
    let name_hash = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
        .unwrap()
        .name_hash();
    crate::localnet::PrivateRootSpec {
        parent_network_id:
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                .parse()
                .unwrap(),
        dataspace_id: iroha_model_base::topology::DataSpaceId::from_hash(&name_hash),
        dataspace_alias: alias.into(),
    }
}

#[test]
fn incomplete_managed_preparation_never_creates_a_replacement_generation() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("private").unwrap();
    let generation = directory.create_child("generation").unwrap();
    generation
        .write_atomic(
            "original-owner.key",
            b"retained owner custody",
            PublishMode::CreateNew,
        )
        .unwrap();
    let binary = std::env::current_exe().unwrap();
    let mut request = LocalnetRequest::private_root(binary.clone(), binary);
    request.name = "private".into();
    assert!(store.up_private_root(&request, &private_spec()).is_err());
    assert!(store.create_localnet(&request).is_err());
    assert_eq!(
        &*generation.read("original-owner.key", MAX_METADATA).unwrap(),
        b"retained owner custody"
    );
    assert!(
        !directory
            .path()
            .join(generation::DIRECTORY)
            .join(MANIFEST)
            .exists()
    );
    let generations = std::fs::read_dir(directory.path())
        .unwrap()
        .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
        .count();
    assert_eq!(generations, 1);
}

#[test]
fn managed_private_preparation_retains_owner_scope_and_listener_token_after_spawn_failure() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(&temporary.path().join("managed")).unwrap();
    let binary = std::env::current_exe().unwrap();
    let store = ManagedStore::open(directory.path()).unwrap();
    let mut request = LocalnetRequest::private_root(binary.clone(), binary);
    request.name = "private".into();
    request.startup_timeout = Duration::from_secs(120);
    let spec = private_spec();
    let error = store.up_private_root(&request, &spec).unwrap_err();
    assert!(
        matches!(error, Error::Timeout(timeout) if timeout == request.startup_timeout),
        "expected original-budget worker-start failure after genuine preparation: {error}"
    );
    let prepared = store
        .prepared("private")
        .expect("genuine private preparation retained before spawn");
    assert_eq!(prepared.context.dataspace_id, spec.dataspace_id.as_u64());
    assert!(
        prepared
            .context
            .load_client_config()
            .unwrap()
            .api_token
            .is_some()
    );
    let original_config =
        iroha_fs::read_private(&prepared.context.client_config, MAX_METADATA).unwrap();
    assert!(
        store
            .up(&request)
            .unwrap_err()
            .to_string()
            .contains("different immutable root identity")
    );
    assert!(store.up_retained(&request, &prepared.context).is_err());
    assert_eq!(store.prepared("private").unwrap(), prepared);
    assert_eq!(
        &*iroha_fs::read_private(&prepared.context.client_config, MAX_METADATA).unwrap(),
        &*original_config
    );
    let mut foreign = spec;
    foreign.parent_network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"different parent")),
    );
    assert!(
        store
            .up_private_root(&request, &foreign)
            .unwrap_err()
            .to_string()
            .contains("different immutable root identity")
    );
}

#[test]
fn port_reservations_are_live_disjoint_and_released_on_drop() {
    let _resources = super::native_test_guard();
    let ports = LocalnetPorts::reserve().unwrap();
    assert_eq!(ports.reserved_count(), 8);
    let bases = [ports.base_api, ports.base_p2p];
    assert!((i32::from(bases[0]) - i32::from(bases[1])).abs() >= 4);
    for base in bases {
        for offset in 0..4 {
            assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, base + offset)).is_err());
        }
    }
    drop(ports);
    for base in bases {
        for offset in 0..4 {
            TcpListener::bind((Ipv4Addr::LOCALHOST, base + offset)).unwrap();
        }
    }
}

#[test]
fn stopped_context_selection_retains_identity_and_never_exposes_keys() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, _, prepared) = fixture(&temporary.path().join("managed"), "local");
    let selected = store.select("local").unwrap();
    assert_eq!(selected, prepared.context);
    assert_eq!(store.prepared("local").unwrap(), prepared);
    assert_eq!(store.context(None).unwrap(), selected);
    assert_eq!(store.contexts().unwrap(), [selected.clone()]);
    let status = store.status("local").unwrap();
    assert_eq!(status.phase, ManagedPhase::Stopped);
    assert_eq!(store.down("local").unwrap(), status);
    let receipt = String::from_utf8(encode(&status).unwrap()).unwrap();
    assert!(!receipt.contains("private config"));
    assert!(!receipt.contains("private_key"));
    assert!(!receipt.contains("token"));
    let restored = ManagedStore::open(store.root()).unwrap();
    assert_eq!(restored.context(None).unwrap(), selected);
}

// These selection-only controls supply a status DTO, not native readiness evidence. The
// deadline/identity observer itself is exercised by the dedicated startup-selection tests.
fn selection_ready(context: &ManagedContext) -> ManagedStatus {
    ManagedStatus {
        context: context.clone(),
        phase: ManagedPhase::Ready,
        running_peers: 4,
        failure: None,
    }
}

#[test]
fn explicit_deployment_startup_preserves_absent_and_existing_workspace_selection() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("managed");
    let (store, _, a) = fixture(&root, "a");
    let (_, _, b) = fixture(&root, "b");
    let private = PrivateDirectory::open(store.root()).unwrap();

    // Exercise the actual selection owner used after either startup Ready exit. These
    // retained contexts do not claim live validators or substitute a readiness proof.
    let target = store::StartupSelection::for_requested_context(Some("b"));
    target
        .apply(&store, &b.context, || Ok(selection_ready(&b.context)))
        .unwrap();
    assert!(matches!(store.context(None), Err(Error::NoSelection)));
    assert!(!store.root().join("active.json").exists());

    store.select("a").unwrap();
    let original = private.read("active.json", MAX_METADATA).unwrap();
    for _ in 0..2 {
        // A fresh deployment and exact-journal resume use the same explicit-target policy.
        target
            .apply(&store, &b.context, || Ok(selection_ready(&b.context)))
            .unwrap();
        assert_eq!(private.read("active.json", MAX_METADATA).unwrap(), original);
        assert_eq!(store.context(None).unwrap(), a.context);
    }
    assert_eq!(store.prepared("a").unwrap(), a);
    assert_eq!(store.prepared("b").unwrap(), b);
    assert_eq!(
        ManagedStore::open(&root).unwrap().context(None).unwrap(),
        a.context
    );

    // Selection can change after target resolution. Preserve never restores a stale value.
    let target = store::StartupSelection::for_requested_context(Some("a"));
    store.select("b").unwrap();
    let current = private.read("active.json", MAX_METADATA).unwrap();
    target
        .apply(&store, &a.context, || Ok(selection_ready(&a.context)))
        .unwrap();
    assert_eq!(private.read("active.json", MAX_METADATA).unwrap(), current);
    assert_eq!(store.context(None).unwrap(), b.context);
}

#[test]
fn ordinary_and_default_startup_still_select_the_ready_environment() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("managed");
    let (store, _, a) = fixture(&root, "a");
    let (_, _, b) = fixture(&root, "b");
    // Default auto-creation has no previous selection and must persist its ready context.
    store::StartupSelection::for_requested_context(None)
        .apply(&store, &a.context, || Ok(selection_ready(&a.context)))
        .unwrap();
    assert_eq!(store.context(None).unwrap(), a.context);
    // Ordinary local/private up and explicit up_retained use Select, independently of the
    // deployment override. These checks concern selection, not native startup qualification.
    store::StartupSelection::Select
        .apply(&store, &b.context, || Ok(selection_ready(&b.context)))
        .unwrap();
    assert_eq!(store.context(None).unwrap(), b.context);
    store::StartupSelection::for_requested_context(None)
        .apply(&store, &a.context, || Ok(selection_ready(&a.context)))
        .unwrap();
    assert_eq!(store.context(None).unwrap(), a.context);
}

#[test]
fn create_only_rejects_retained_global_and_private_names_under_the_operation_lock() {
    let _resources = super::native_test_guard();
    for private_root in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("managed");
        let (store, _, selected) = fixture(&root, "selected");
        store.select("selected").unwrap();
        let owner = PrivateDirectory::open(store.root()).unwrap();
        let active = owner.read("active.json", MAX_METADATA).unwrap();
        // A frontend's snapshot predates a second frontend publishing the same requested name.
        assert_eq!(store.contexts().unwrap(), [selected.context.clone()]);
        let directory = if private_root {
            let networks = PrivateDirectory::open(root.join("networks")).unwrap();
            let directory = networks.create_child("concurrent").unwrap();
            let binary = std::env::current_exe().unwrap();
            let mut request = LocalnetRequest::private_root(binary.clone(), binary);
            request.name = "concurrent".into();
            let _operation = store::acquire(&directory, "operation.lock", &request.name).unwrap();
            let ports = LocalnetPorts::reserve().unwrap();
            generation::prepare(
                &directory,
                &request,
                RootKind::Private {
                    spec: private_spec(),
                },
                store::pin_binary(&request.launcher).unwrap(),
                store::pin_binary(&request.daemon).unwrap(),
                &ports,
            )
            .unwrap();
            drop(_operation);
            directory
        } else {
            fixture(&root, "concurrent").1
        };
        let retained = generation::read(&directory).unwrap();
        let original = encode(&retained).unwrap();
        let config =
            iroha_fs::read_private(&retained.prepared.context.client_config, MAX_METADATA).unwrap();
        let mut request =
            LocalnetRequest::new(retained.launcher.path.clone(), retained.daemon.path.clone());
        request.name = "concurrent".into();
        let operation = store::acquire(&directory, "operation.lock", &request.name).unwrap();
        assert!(
            matches!(store.create_localnet(&request), Err(Error::Busy(name)) if name == request.name)
        );
        drop(operation);
        assert!(matches!(
            store.create_localnet(&request),
            Err(Error::Invalid(message)) if message.contains("already exists")
        ));
        assert_eq!(
            encode(&generation::read(&directory).unwrap()).unwrap(),
            original
        );
        assert_eq!(store.prepared(&request.name).unwrap(), retained.prepared);
        assert_eq!(
            &*iroha_fs::read_private(&retained.prepared.context.client_config, MAX_METADATA)
                .unwrap(),
            &*config
        );
        assert_eq!(owner.read("active.json", MAX_METADATA).unwrap(), active);
        assert_eq!(store.context(None).unwrap(), selected.context);
        // No control record, status, log or worker was created by either refusal.
        for name in [WORKER, STATUS, "runtime.lock", "supervisor.log"] {
            assert!(!directory.path().join(name).exists(), "unexpected {name}");
        }
        assert!(!directory.path().join(".preparing").exists());
    }
}

#[test]
fn unreadable_worker_with_held_lock_is_not_reported_stopped_or_reset() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, _) = fixture(&temporary.path().join("managed"), "local");
    let _owned = store::acquire(&directory, "runtime.lock", "local").unwrap();
    assert!(matches!(store.status("local"), Err(Error::Busy(_))));
    assert!(matches!(store.reset("local"), Err(Error::Busy(_))));
    assert!(
        directory
            .path()
            .join(generation::DIRECTORY)
            .join(MANIFEST)
            .exists()
    );
}

#[test]
fn stopped_controller_cannot_leave_a_saved_ready_status() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    directory
        .write_atomic(
            STATUS,
            &encode(&ManagedStatus {
                context: prepared.context,
                phase: ManagedPhase::Ready,
                running_peers: 4,
                failure: None,
            })
            .unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let status = store.status("local").unwrap();
    assert_eq!(status.phase, ManagedPhase::Failed);
    assert_eq!(status.running_peers, 0);
    assert!(status.failure.unwrap().contains("unexpectedly"));
}

#[test]
fn live_foreground_start_is_distinguished_from_a_crashed_handoff() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    directory
        .write_atomic(
            STATUS,
            &encode(&ManagedStatus {
                context: prepared.context,
                phase: ManagedPhase::Starting,
                running_peers: 0,
                failure: None,
            })
            .unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let operation = store::acquire(&directory, "operation.lock", "local").unwrap();
    assert_eq!(store.status("local").unwrap().phase, ManagedPhase::Starting);
    drop(operation);
    assert_eq!(store.status("local").unwrap().phase, ManagedPhase::Failed);
}

#[cfg(any(unix, windows))]
#[test]
fn foreground_expiry_uses_failed_startup_action_and_rejects_late_ready_or_other_identity() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    let token = "d".repeat(64);
    directory
        .write_atomic(
            WORKER,
            &encode(&WorkerRecord {
                token: token.clone(),
            })
            .unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let listener = transport::Listener::bind(&directory).unwrap();
    let failed = ManagedStatus {
        context: prepared.context.clone(),
        phase: ManagedPhase::Failed,
        running_peers: 0,
        failure: Some("startup readiness deadline expired while confirming the complete four-validator peer mesh".into()),
    };
    let mut late = failed.clone();
    late.phase = ManagedPhase::Ready;
    late.running_peers = 4;
    late.failure = None;
    let mut foreign = failed.clone();
    foreign.context.network_id.push('x');
    let expected = failed.clone();
    let late_observation = late.clone();
    let server = std::thread::spawn(move || {
        for reply in [failed, late, foreign] {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(mut connection) = listener.accept().unwrap() {
                    let request = connection.receive().unwrap();
                    assert_eq!(request.token, token);
                    assert_eq!(request.action, "startup_expired");
                    connection.reply(&reply).unwrap();
                    break;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });
    let timeout = Duration::from_secs(30);
    let expired_start = std::time::Instant::now() - Duration::from_secs(31);
    // This first call must perform no control exchange: a late idempotent observation
    // neither selects nor stops a network that was already ready when `up` began.
    assert!(matches!(
        store::observe_startup_status(
            &directory,
            &prepared.context,
            late_observation.clone(),
            expired_start,
            timeout,
            0,
            true,
        ),
        Err(Error::Timeout(value)) if value == timeout
    ));
    assert!(matches!(
        store::observe_startup_status(&directory, &prepared.context, late_observation.clone(),
            std::time::Instant::now(), timeout, 0, true),
        Err(Error::Timeout(value)) if value == timeout
    ));
    // The same late proof during this invocation's actual startup must cancel that
    // attempt, preserving its closed failure phase rather than returning late Ready.
    assert_eq!(
        store::observe_startup_status(
            &directory,
            &prepared.context,
            late_observation,
            std::time::Instant::now(),
            timeout,
            0,
            false,
        )
        .unwrap(),
        expected
    );
    assert!(matches!(
        store::expire_startup(&directory, &prepared.context, timeout),
        Err(Error::Timeout(value)) if value == timeout
    ));
    assert!(matches!(
        store::expire_startup(&directory, &prepared.context, timeout),
        Err(Error::Invalid(_))
    ));
    server.join().unwrap();
}

#[test]
fn reset_deletes_only_a_stopped_named_context_and_preserves_selection_failure() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("managed");
    let (store, directory, _) = fixture(&root, "local");
    let (_, other, _) = fixture(&root, "other");
    store.select("local").unwrap();
    store.reset("local").unwrap();
    assert!(
        !directory
            .path()
            .join(generation::DIRECTORY)
            .join(MANIFEST)
            .exists()
    );
    assert!(directory.path().join("operation.lock").exists());
    assert!(
        other
            .path()
            .join(generation::DIRECTORY)
            .join(MANIFEST)
            .exists()
    );
    assert!(
        matches!(store.context(None), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    assert_eq!(store.contexts().unwrap().len(), 1);
}

#[test]
fn missing_selection_is_distinct_from_a_lost_retained_generation() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    assert!(matches!(store.context(None), Err(Error::NoSelection)));
    assert!(
        matches!(store.context(Some("unknown")), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
}

#[test]
fn prepared_bundle_rejects_remote_endpoints_missing_peers_and_path_escape() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    store::validate_prepared("local", directory.path(), &prepared, &RootKind::Global).unwrap();
    let mut changed = prepared.clone();
    changed.peers.pop();
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    let mut changed = prepared.clone();
    changed.context.dataspace_id = 2;
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    changed.context.dataspace_id = 0;
    changed.context.dataspace_alias = "foreign".into();
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    let mut changed = prepared.clone();
    changed.peers[0].torii_url = "https://taira.sora.org/".into();
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    let mut changed = prepared.clone();
    changed.peers[0].config_path = temporary.path().join("foreign.toml");
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    let mut changed = prepared.clone();
    changed.peers[0].config_path = directory.path().join("generation/../generation/peer0.toml");
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
    let mut changed = prepared;
    changed.peers[0].log_name = "../outside.log".into();
    assert!(
        store::validate_prepared("local", directory.path(), &changed, &RootKind::Global).is_err()
    );
}

#[test]
fn lifecycle_phases_have_strict_stable_json_spelling() {
    let _resources = super::native_test_guard();
    for phase in [
        ManagedPhase::Stopped,
        ManagedPhase::Starting,
        ManagedPhase::Ready,
        ManagedPhase::Failed,
    ] {
        let bytes = encode(&phase).unwrap();
        assert_eq!(bytes, format!("\"{}\"", phase.as_str()).as_bytes());
        assert_eq!(decode::<ManagedPhase>(&bytes).unwrap(), phase);
    }
    assert!(decode::<ManagedPhase>(b"\"running\"").is_err());
}

#[test]
fn changed_binary_is_rejected_before_launch() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("daemon");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let pin = store::pin_binary(&binary).unwrap();
    store::verify_binary(&pin).unwrap();
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(binary)
        .unwrap()
        .write_all(b"changed native contents")
        .unwrap();
    assert!(store::verify_binary(&pin).is_err());
}

#[test]
fn logs_return_only_the_requested_bounded_tail() {
    let _resources = super::native_test_guard();
    use std::io::Write as _;
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, _) = fixture(&temporary.path().join("managed"), "local");
    directory
        .open_append("peer0.log")
        .unwrap()
        .write_all(b"line-one\nline-two\n")
        .unwrap();
    assert_eq!(store.logs("local", Some(0), 9).unwrap(), "line-two\n");
    assert!(store.logs("local", Some(4), 10).is_err());
    assert!(store.logs("local", None, 1024 * 1024 + 1).is_err());
    assert!(store.logs("local", None, 100).is_err());
    assert!(!directory.path().join("supervisor.log").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_generation_config_is_rejected() {
    let _resources = super::native_test_guard();
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    let path = &prepared.peers[0].config_path;
    std::fs::remove_file(path).unwrap();
    symlink(&prepared.peers[1].config_path, path).unwrap();
    assert!(
        store::validate_prepared("local", directory.path(), &prepared, &RootKind::Global).is_err()
    );
}

#[test]
fn retained_service_profile_mismatch_and_private_selection_refuse_before_generation() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    let manifest = directory
        .open_child("generation")
        .unwrap()
        .read(MANIFEST, MAX_METADATA)
        .unwrap();
    let binary = std::env::current_exe().unwrap();
    let mut request = LocalnetRequest::new(binary.clone(), binary);
    request.service_profile = crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities;
    assert!(
        matches!(store.up(&request), Err(Error::Invalid(message)) if message.contains("service profile"))
    );
    assert_eq!(store.prepared("local").unwrap(), prepared);
    assert_eq!(
        directory
            .open_child("generation")
            .unwrap()
            .read(MANIFEST, MAX_METADATA)
            .unwrap()
            .as_slice(),
        manifest.as_slice()
    );
    assert!(!directory.path().join(".preparing").exists());
    request.name = "private-service".into();
    assert!(
        matches!(store.up_private_root(&request, &private_spec()), Err(Error::Invalid(message)) if message.contains("global managed root"))
    );
    assert!(!store.root().join("networks/private-service").exists());
}

#[test]
fn retained_standard_profile_requires_original_signed_genesis_and_identity() {
    let _resources = super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, prepared) = fixture(&temporary.path().join("managed"), "local");
    let _parent_profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    assert!(prepared.stream_token_authorities().unwrap().is_none());
    for literal in [
        format!(" {}", prepared.context.account_id),
        format!("{} ", prepared.context.account_id),
    ] {
        let mut noncanonical = prepared.clone();
        noncanonical.context.account_id = literal;
        assert!(noncanonical.stream_token_authorities().is_err());
    }
    let mut substituted = prepared.clone();
    substituted.context.network_id.push('x');
    assert!(substituted.stream_token_authorities().is_err());
    substituted = prepared.clone();
    substituted.context.account_id = iroha_test_samples::BOB_ID.to_string();
    assert!(substituted.stream_token_authorities().is_err());
    let bundle = directory.open_child("generation").unwrap();
    let genesis = bundle
        .read(
            "genesis.signed.nrt",
            iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
        )
        .unwrap();
    std::fs::remove_file(bundle.path().join("genesis.signed.nrt")).unwrap();
    assert!(
        prepared.stream_token_authorities().is_err(),
        "no absent-genesis fallback"
    );
    bundle
        .write_atomic("genesis.signed.nrt", &genesis, PublishMode::CreateNew)
        .unwrap();
    assert!(prepared.stream_token_authorities().unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn optional_store_selection_refuses_lost_parent_and_restores_original_absence() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("managed");
    let store = ManagedStore::open(&path).unwrap();
    assert!(matches!(store.context(None), Err(Error::NoSelection)));
    let displaced = temporary.path().join("original-managed");
    std::fs::rename(&path, &displaced).unwrap();
    assert!(
        matches!(store.context(None), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    std::fs::rename(&displaced, &path).unwrap();
    assert!(matches!(store.context(None), Err(Error::NoSelection)));
    assert!(!path.join("active.json").exists());
}
