//! Genuine generated custody and local-only refusal tests; no provider authority is fabricated.

use super::*;
use crate::managed::native_operation::test_support::UnavailablePeers;
use iroha_fs::{PrivateDirectory, PublishMode};

fn fixture(profile: LocalnetServiceProfile) -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "registry",
        &temporary.path().join("generation"),
        &ports,
        profile,
        None,
    )
    .unwrap();
    (temporary, prepared)
}

#[test]
fn generated_registry_preparation_is_lazy_and_retains_lock_through_materialized_client() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    assert!(prepare(&prepared, Instant::now()).is_err());
    assert!(
        !prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime/service-operations/network/build-registry")
            .exists()
    );
    let original = prepared.context.load_client_config().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let ((config, transport), parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            prepare(&prepared, deadline).unwrap().unwrap()
        });
    assert_eq!(parses, 1);
    assert_eq!(config.chain, original.chain);
    assert_eq!(config.network_id, original.network_id);
    assert_eq!(config.account, original.account);
    assert_eq!(config.key_pair.public_key(), original.key_pair.public_key());
    assert_eq!(config.torii_api_url, original.torii_api_url);
    assert_eq!(transport.network_id(), original.network_id);
    let cloned = transport.clone();
    let client = transport.build_client().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    assert!(ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).is_err());
    drop(transport);
    drop(cloned);
    assert!(ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).is_err());
    drop(client);
    let reopened =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    assert!(
        !reopened
            .directory
            .entries(8)
            .unwrap()
            .iter()
            .any(|entry| entry == "current-checkpoint.nrt")
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn generated_discovery_rejects_wrong_provider_expiry_and_replaced_profile_before_http() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut owner =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let provider = owner.manifest.providers[0].provider_id;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut other = *provider.as_bytes();
    other[0] ^= 1;
    assert!(matches!(
        discover(&mut owner, ProviderId::new(other), deadline),
        Err(MusubiArchiveDiscoveryErrorV1::Rejected)
    ));
    assert!(matches!(
        discover(&mut owner, provider, Instant::now()),
        Err(MusubiArchiveDiscoveryErrorV1::Deadline)
    ));
    for selected in owner.manifest.providers.each_ref().map(|p| p.provider_id) {
        assert!(matches!(
            discover(&mut owner, selected, Instant::now()),
            Err(MusubiArchiveDiscoveryErrorV1::Deadline)
        ));
    }
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let bytes = generation.read("peer0.toml", 1024 * 1024).unwrap();
    generation
        .write_atomic(
            "peer0.toml",
            b"not a peer configuration",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        discover(&mut owner, provider, deadline),
        Err(MusubiArchiveDiscoveryErrorV1::Rejected)
    ));
    generation
        .write_atomic("peer0.toml", &bytes, PublishMode::Replace)
        .unwrap();
    owner.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn unavailable_native_finality_is_not_generated_provider_authority() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut owner =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    for provider in owner.manifest.providers.each_ref().map(|p| p.provider_id) {
        assert!(matches!(
            discover(
                &mut owner,
                provider,
                Instant::now() + Duration::from_secs(5)
            ),
            Err(MusubiArchiveDiscoveryErrorV1::Unavailable)
        ));
    }
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|request| request.method == "GET"
        && (request.path == "/v1/node/capabilities" || request.path == "/v1/bridge/finality/1")));
    assert!(
        !owner
            .directory
            .entries(8)
            .unwrap()
            .iter()
            .any(|entry| entry == "current-checkpoint.nrt")
    );
}

#[test]
fn standard_generation_has_no_implicit_local_registry_and_expired_prepare_makes_no_owner() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::Standard);
    assert!(
        prepare(&prepared, Instant::now() + Duration::from_secs(30))
            .unwrap()
            .is_none()
    );
    assert!(prepare(&prepared, Instant::now()).is_err());
    assert!(
        !prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime/service-operations/network/build-registry")
            .exists()
    );
}

#[test]
fn managed_factory_selects_published_generated_registry_without_parent_profile_or_worker() {
    use crate::managed::{RootKind, generation, store};
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let bundle = PrivateDirectory::open_or_create(temporary.path().join("bundle")).unwrap();
    for name in ["kagami", "iroha3d"] {
        std::fs::copy(
            std::env::current_exe().unwrap(),
            bundle
                .path()
                .join(format!("{name}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    let runtime = InstalledRuntime::from_directory(bundle.path()).unwrap();
    let request = runtime.localnet_request("registry", Duration::from_secs(30));
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("registry").unwrap();
    let operation = store::acquire(&directory, "operation.lock", "registry").unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let retained = generation::prepare(
        &directory,
        &request,
        RootKind::Global,
        store::pin_binary(&request.launcher).unwrap(),
        store::pin_binary(&request.daemon).unwrap(),
        &ports,
    )
    .unwrap();
    drop(ports);
    drop(operation);
    let manifest_before = generation::read(&directory).unwrap();
    let original_bytes = crate::managed::encode(&manifest_before).unwrap();
    let mut peers = UnavailablePeers::start(&retained.prepared);
    let (config, transport) = store
        .build_registry(
            &runtime,
            &retained.prepared,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        config.account,
        retained
            .prepared
            .context
            .load_client_config()
            .unwrap()
            .account
    );
    assert_eq!(transport.network_id(), config.network_id);
    assert_eq!(
        crate::managed::encode(&generation::read(&directory).unwrap()).unwrap(),
        original_bytes
    );
    assert!(matches!(
        store.context(None),
        Err(crate::managed::Error::NoSelection)
    ));
    assert!(!store.root().join("attachments").join("registry").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(transport);

    // A real Some transport is created before this mutation. The shared owner must still
    // close its complete original preparation, and dropping the refused result releases its
    // registry lock so restoring the original manifest allows the exact same lookup again.
    let generation = directory.open_child(generation::DIRECTORY).unwrap();
    let mut changed = manifest_before.clone();
    changed.prepared.peers[0].log_name = "changed-peer.log".into();
    assert_eq!(changed.prepared.context, retained.prepared.context);
    let changed_bytes = crate::managed::encode(&changed).unwrap();
    let path = generation.path().to_path_buf();
    let _hook = super::super::tests::on_resolution(move |kind| {
        assert_eq!(kind, super::super::tests::ResolutionKind::Some);
        PrivateDirectory::open(path)
            .unwrap()
            .write_atomic(
                crate::managed::MANIFEST,
                &changed_bytes,
                PublishMode::Replace,
            )
            .unwrap();
    });
    let error = store
        .build_registry(
            &runtime,
            &retained.prepared,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap_err();
    assert!(
        matches!(error, crate::managed::Error::Invalid(message) if message ==
            "selected build registry generation changed")
    );
    assert_eq!(store.prepared("registry").unwrap(), changed.prepared);
    generation
        .write_atomic(
            crate::managed::MANIFEST,
            &original_bytes,
            PublishMode::Replace,
        )
        .unwrap();
    let (retried, transport) = store
        .build_registry(
            &runtime,
            &retained.prepared,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .unwrap();
    assert_eq!(retried.network_id, config.network_id);
    assert_eq!(transport.network_id(), config.network_id);
    assert_eq!(store.prepared("registry").unwrap(), retained.prepared);
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(transport);

    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = reached.clone();
    let deadline = Instant::now() + Duration::from_secs(2);
    let _expiry = super::super::tests::on_resolution(move |kind| {
        assert_eq!(kind, super::super::tests::ResolutionKind::Some);
        observed.set(true);
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        assert!(Instant::now() >= deadline);
    });
    assert!(matches!(
        store.build_registry(&runtime, &retained.prepared, deadline),
        Err(crate::managed::Error::NativeDeadline)
    ));
    assert!(reached.get(), "the transport reached its closing boundary");
    let (retried, transport) = store
        .build_registry(
            &runtime,
            &retained.prepared,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap()
        .unwrap();
    assert_eq!(retried.network_id, config.network_id);
    assert_eq!(transport.network_id(), config.network_id);
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(transport);
    peers.finish();
}
