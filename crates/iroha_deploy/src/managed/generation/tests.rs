//! Interrupted preparation is disposable until one complete generation is atomically published.

use super::*;

#[test]
fn interrupted_unpublished_stage_is_discarded_under_operation_ownership() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("context")).unwrap();
    let _operation = store::acquire(&root, "operation.lock", "local").unwrap();
    let stage = fresh_stage(&root).unwrap();
    let nested = stage.create_child("keys").unwrap();
    nested
        .write_atomic(
            "owner.key",
            b"unexposed old custody",
            PublishMode::CreateNew,
        )
        .unwrap();
    drop(nested);
    drop(stage);
    assert!(
        matches!(read(&root), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    let stage = fresh_stage(&root).unwrap();
    assert!(!stage.path().join("keys").exists());
    assert!(!root.path().join(DIRECTORY).exists());
    assert!(std::fs::read_dir(stage.path()).unwrap().next().is_none());
}

#[test]
fn visible_generation_without_manifest_is_never_preparable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("context")).unwrap();
    let generation = root.create_child(DIRECTORY).unwrap();
    generation
        .write_atomic("owner.key", b"published custody", PublishMode::CreateNew)
        .unwrap();
    assert!(matches!(read(&root), Err(Error::Invalid(_))));
    assert_eq!(
        generation.read("owner.key", 64).unwrap().as_slice(),
        b"published custody"
    );
}

#[test]
fn published_generation_survives_retry_with_an_unpublished_leftover() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) =
        super::super::tests::fixture(&temporary.path().join("managed"), "local");
    let before = encode(&read(&directory).unwrap()).unwrap();
    let stage = fresh_stage(&directory).unwrap();
    stage
        .write_atomic("owner.key", b"unused candidate", PublishMode::CreateNew)
        .unwrap();
    drop(stage);
    let pin = read(&directory).unwrap().launcher;
    let mut request = LocalnetRequest::new(pin.path.clone(), pin.path);
    request.service_profile = prepared.service_profile;
    assert!(matches!(
        store.up(&request),
        Err(Error::Timeout(timeout)) if timeout == request.startup_timeout
    ));
    assert_eq!(encode(&read(&directory).unwrap()).unwrap(), before);
    assert_eq!(store.prepared("local").unwrap(), prepared);
}

#[test]
fn uncertain_publication_reopens_only_the_exact_complete_generation() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, _) =
        super::super::tests::fixture(&temporary.path().join("managed"), "local");
    let expected = read(&directory).unwrap();
    reconcile_publication(&directory, &expected).unwrap();
    let mut foreign = expected.clone();
    foreign.prepared.context.network_id = "another identity".into();
    assert!(reconcile_publication(&directory, &foreign).is_err());
    assert_eq!(
        encode(&read(&directory).unwrap()).unwrap(),
        encode(&expected).unwrap()
    );
}

#[test]
fn staged_private_generation_publishes_exact_final_paths_and_original_identity() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("private").unwrap();
    let binary = std::env::current_exe().unwrap();
    let pin = store::pin_binary(&binary).unwrap();
    let mut request = LocalnetRequest::private_root(binary.clone(), binary);
    request.name = "private".into();
    let _operation = store::acquire(&directory, "operation.lock", "private").unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let spec = super::super::tests::private_spec();
    let staged = fresh_stage(&directory).unwrap();
    let abandoned =
        crate::localnet::prepare_private_root("private", staged.path(), &ports, &spec).unwrap();
    let abandoned_owner = abandoned.context.account_id;
    drop(staged);
    let retained = prepare(
        &directory,
        &request,
        RootKind::Private { spec: spec.clone() },
        pin.clone(),
        pin,
        &ports,
    )
    .unwrap();
    assert_ne!(retained.prepared.context.account_id, abandoned_owner);
    assert_eq!(
        retained.prepared.service_profile,
        crate::localnet::LocalnetServiceProfile::Standard
    );
    assert!(
        !directory
            .path()
            .join(DIRECTORY)
            .join("runtime/stream-token-authorities")
            .exists()
    );
    assert!(!directory.path().join(STAGING).exists());
    assert!(!directory.path().join(MANIFEST).exists());
    assert_eq!(
        encode(&read(&directory).unwrap()).unwrap(),
        encode(&retained).unwrap()
    );
    assert_eq!(
        store.context(Some("private")).unwrap(),
        retained.prepared.context
    );
    let registration = retained.prepared.load_private_registration().unwrap();
    assert_eq!(registration.scope, spec.scope());
    for peer in &retained.prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, MAX_METADATA).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains(STAGING),
            "no staged storage or credential path may survive publication"
        );
        let table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(text, "published peer").unwrap(),
        );
        assert!(
            table["data_dir"]
                .as_str()
                .unwrap()
                .starts_with(directory.path().join(DIRECTORY).to_str().unwrap())
        );
    }
}

#[cfg(unix)]
#[test]
fn replaced_parent_cannot_authorize_generation_reads_or_stage_cleanup() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, _) =
        super::super::tests::fixture(&temporary.path().join("managed"), "local");
    let expected = read(&directory).unwrap();
    std::fs::rename(
        directory.path(),
        directory.path().with_file_name("displaced"),
    )
    .unwrap();
    let replacement = PrivateDirectory::open_or_create(directory.path()).unwrap();
    let replacement_stage = replacement.create_child(STAGING).unwrap();
    replacement_stage
        .write_atomic("owner.key", b"different custody", PublishMode::CreateNew)
        .unwrap();
    assert!(read(&directory).is_err());
    assert!(fresh_stage(&directory).is_err());
    assert!(reconcile_publication(&directory, &expected).is_err());
    assert_eq!(
        replacement_stage.read("owner.key", 64).unwrap().as_slice(),
        b"different custody"
    );
}

#[test]
fn staged_global_generation_publishes_all_runtime_paths_and_custody() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("local").unwrap();
    let binary = std::env::current_exe().unwrap();
    let pin = store::pin_binary(&binary).unwrap();
    let request = LocalnetRequest::new(binary.clone(), binary);
    let _operation = store::acquire(&directory, "operation.lock", "local").unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let retained = prepare(
        &directory,
        &request,
        RootKind::Global,
        pin.clone(),
        pin,
        &ports,
    )
    .unwrap();
    assert!(!directory.path().join(STAGING).exists());
    assert!(!directory.path().join(MANIFEST).exists());
    assert_eq!(store.prepared("local").unwrap(), retained.prepared);
    retained.prepared.load_operator_key_pair().unwrap();
    retained.prepared.context.load_client_config().unwrap();
    for peer in &retained.prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, MAX_METADATA).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(STAGING));
        assert!(text.contains(directory.path().join(DIRECTORY).to_str().unwrap()));
    }
}

#[cfg(unix)]
#[test]
fn stage_cleanup_rejects_symlink_substitution() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("context")).unwrap();
    let outside = PrivateDirectory::open_or_create(temporary.path().join("outside")).unwrap();
    outside
        .write_atomic("owner.key", b"unrelated custody", PublishMode::CreateNew)
        .unwrap();
    symlink(outside.path(), root.path().join(STAGING)).unwrap();
    assert!(fresh_stage(&root).is_err());
    assert_eq!(
        outside.read("owner.key", 64).unwrap().as_slice(),
        b"unrelated custody"
    );
}

#[test]
fn staged_service_authorities_publish_exact_identity_and_private_custody() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("native-authorities").unwrap();
    let binary = std::env::current_exe().unwrap();
    let pin = store::pin_binary(&binary).unwrap();
    let mut request = LocalnetRequest::new(binary.clone(), binary);
    request.name = "native-authorities".into();
    assert_eq!(
        request.service_profile,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities
    );
    let _operation = store::acquire(&directory, "operation.lock", &request.name).unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let retained = prepare(
        &directory,
        &request,
        RootKind::Global,
        pin.clone(),
        pin,
        &ports,
    )
    .unwrap();
    let original = encode(&retained).unwrap();
    assert_eq!(retained.prepared.service_profile, request.service_profile);
    let manifest = retained
        .prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap();
    assert_eq!(
        manifest.network_id.to_string(),
        retained.prepared.context.network_id
    );
    assert_eq!(store.prepared(&request.name).unwrap(), retained.prepared);
    assert!(!directory.path().join(STAGING).exists());
    reconcile_publication(&directory, &retained).unwrap();
    assert_eq!(encode(&read(&directory).unwrap()).unwrap(), original);
    assert_eq!(
        read(&directory)
            .unwrap()
            .prepared
            .stream_token_authorities()
            .unwrap(),
        Some(manifest)
    );
}

#[test]
fn optional_generation_requires_initial_absence_and_keeps_visible_manifest_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("context")).unwrap();
    assert!(read_optional(&root).unwrap().is_none());
    assert!(
        matches!(read(&root), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    let generation = root.create_child(DIRECTORY).unwrap();
    generation
        .write_atomic(
            "owner.key",
            b"published original custody",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(matches!(read_optional(&root), Err(Error::Invalid(_))));
    assert!(matches!(read(&root), Err(Error::Invalid(_))));
    assert_eq!(
        generation.read("owner.key", 64).unwrap().as_slice(),
        b"published original custody"
    );
}

#[cfg(unix)]
#[test]
fn optional_generation_parent_refusal_cannot_authorize_preparation_and_original_retry() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, root, _) = super::super::tests::fixture(&temporary.path().join("managed"), "local");
    let original = encode(&read(&root).unwrap()).unwrap();
    assert_eq!(
        encode(&read_optional(&root).unwrap().unwrap()).unwrap(),
        original
    );
    let displaced = root.path().with_file_name("displaced");
    std::fs::rename(root.path(), &displaced).unwrap();
    assert!(read_optional(&root).is_err());
    assert!(fresh_stage(&root).is_err());
    let replacement = PrivateDirectory::open_or_create(root.path()).unwrap();
    assert!(read_optional(&root).is_err());
    assert!(fresh_stage(&root).is_err());
    assert!(replacement.entries(1).unwrap().is_empty());
    drop(replacement);
    std::fs::remove_dir(root.path()).unwrap();
    std::fs::rename(&displaced, root.path()).unwrap();
    assert_eq!(
        encode(&read_optional(&root).unwrap().unwrap()).unwrap(),
        original
    );
}
