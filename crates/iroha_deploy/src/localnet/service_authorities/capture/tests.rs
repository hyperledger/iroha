//! Genuine original-profile capture, complete byte custody and closed transitive-source controls.

use super::*;
use iroha_fs::PublishMode;

struct Fixture {
    profile: ValidatedServiceProfile,
    prepared: PreparedLocalnet,
    _temporary: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = prepare_localnet_at(
            "captured-profile",
            &temporary.path().join("generation"),
            &ports,
            LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let (profile, parses) =
            count_semantic_validations(|| capture_retained(&prepared).unwrap().unwrap());
        assert_eq!(parses, 1);
        Self {
            profile,
            prepared,
            _temporary: temporary,
        }
    }
}

#[test]
fn complete_original_capture_rechecks_every_input_and_only_closed_static_names() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let image = &fixture.profile.retained.image;
    assert_eq!(image.directories.len(), DIRECTORY_COUNT);
    assert_eq!(
        image
            .directories
            .iter()
            .map(|entry| entry.inputs.len())
            .sum::<usize>(),
        77
    );
    let maximum = image
        .directories
        .iter()
        .flat_map(|entry| &entry.inputs)
        .map(|input| input.maximum)
        .sum::<usize>();
    assert_eq!(maximum, 73_160_704);
    assert!(maximum <= MAX_TOTAL);
    let (_, parses) = count_semantic_validations(|| {
        for directory in &image.directories {
            for input in &directory.inputs {
                assert!(!input.bytes.is_empty());
                let mut changed = input.bytes.clone();
                changed[0] ^= 1;
                directory
                    .directory
                    .write_atomic(input.name, &changed, PublishMode::Replace)
                    .unwrap();
                assert!(
                    image.revalidate().is_err(),
                    "changed original {}",
                    input.name
                );
                directory
                    .directory
                    .write_atomic(input.name, &input.bytes, PublishMode::Replace)
                    .unwrap();
                image.revalidate().unwrap();
            }
            if directory.inventory.is_some() {
                directory
                    .directory
                    .write_atomic("unexpected.nrt", b"unknown", PublishMode::CreateNew)
                    .unwrap();
                assert!(image.revalidate().is_err());
                std::fs::remove_file(directory.directory.path().join("unexpected.nrt")).unwrap();
                image.revalidate().unwrap();
            }
        }
        for provider in &fixture.profile.retained.manifest.providers {
            let retained = fixture
                .profile
                .retained
                .original_plan(provider.provider_id)
                .unwrap();
            let original = provider_material::retained(
                &fixture.profile.retained.manifest,
                provider.provider_id,
            )
            .unwrap();
            assert_eq!(retained.provider_id(), original.provider_id());
            assert_eq!(retained.slot(), original.slot());
            assert_eq!(
                retained.original_profile_commitment(),
                original.original_profile_commitment()
            );
            assert_eq!(retained.admission_material(), original.admission_material());
            assert_eq!(retained.declaration(), original.declaration());
            assert_eq!(retained.pricing(), original.pricing());
        }
        // Derived launch configurations and ordinary runtime journals remain legal additions.
        image
            .generation()
            .directory
            .write_atomic("derived-peer0.toml", b"derived", PublishMode::CreateNew)
            .unwrap();
        let derived = image
            .runtime()
            .create_child("captured-profile-test-operation")
            .unwrap();
        derived
            .write_atomic("operation.nrt", b"derived", PublishMode::CreateNew)
            .unwrap();
        image.revalidate().unwrap();
        fixture
            .profile
            .retained
            .revalidate(&fixture.prepared, fixture.profile.retained.manifest())
            .unwrap();
    });
    assert_eq!(parses, 0);
}

#[test]
fn captured_source_has_exact_transitive_paths_access_and_extent_without_disk_fallback() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let image = &fixture.profile.retained.image;
    for (slot, name, access) in [
        (
            GENERATION,
            "genesis.expected_hash",
            ConfigFileAccess::Public,
        ),
        (RUNTIME, "onboarding-signer.key", ConfigFileAccess::Private),
        (RUNTIME, "ledger-signer.key", ConfigFileAccess::Private),
        (TABLES, "rans_seed0.toml", ConfigFileAccess::Public),
    ] {
        let directory = &image.directories[slot];
        let input = directory
            .inputs
            .iter()
            .find(|input| input.name == name)
            .unwrap();
        let path = directory.directory.path().join(name);
        let request = ConfigFileRequest {
            access,
            maximum: input.maximum,
        };
        assert!(ConfigFileSource::read(image, &path, request).unwrap() == input.bytes);
        let wrong_access = if access == ConfigFileAccess::Private {
            ConfigFileAccess::Public
        } else {
            ConfigFileAccess::Private
        };
        assert!(
            ConfigFileSource::read(
                image,
                &path,
                ConfigFileRequest {
                    access: wrong_access,
                    maximum: input.maximum
                }
            )
            .is_err()
        );
        assert!(
            ConfigFileSource::read(
                image,
                &path,
                ConfigFileRequest {
                    access,
                    maximum: input.bytes.len() - 1
                }
            )
            .is_err()
        );
        directory
            .directory
            .write_atomic(name, b"changed on disk", PublishMode::Replace)
            .unwrap();
        // Parsing uses the original image; the mandatory complete validation rejects disk drift.
        assert!(ConfigFileSource::read(image, &path, request).unwrap() == input.bytes);
        assert!(image.revalidate().is_err());
        directory
            .directory
            .write_atomic(name, &input.bytes, PublishMode::Replace)
            .unwrap();
        image.revalidate().unwrap();
    }
    let request = ConfigFileRequest {
        access: ConfigFileAccess::Public,
        maximum: MAX_CONFIG,
    };
    assert!(ConfigFileSource::read(image, Path::new("genesis.expected_hash"), request).is_err());
    let unknown = image.generation().directory.path().join("unlisted.txt");
    image
        .generation()
        .directory
        .write_atomic(
            "unlisted.txt",
            b"present but not captured",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(ConfigFileSource::read(image, &unknown, request).is_err());
    // Both actual canonical parsers succeed using the one original image and its transitives.
    image
        .parse_peer(&fixture.prepared.peers[0].config_path, "peer0.toml")
        .unwrap();
    let (client, _) = iroha::config::Config::load_bytes_with_musubi_publication_and_file_source(
        &fixture.prepared.context.client_config,
        image.client_bytes().unwrap(),
        image,
    )
    .unwrap();
    fixture
        .prepared
        .context
        .validate_client_config(&client)
        .unwrap();
}

#[test]
fn generated_flat_config_preflight_refuses_external_profile_and_inheritance_forms() {
    for text in [
        "profile = 'unread-profile.toml'\n",
        "profile = { name = 'unread-profile' }\n",
        "[profile]\nname = 'unread-profile'\n",
        "extends = 'unread-parent.toml'\n",
        "extends = ['unread-parent.toml']\n",
    ] {
        assert!(flat_table(text.as_bytes()).is_err());
    }
    assert!(flat_table(b"chain = 'original'\n").is_ok());
}

#[test]
fn retained_directory_identity_cannot_be_replaced_by_identical_original_bytes() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let image = &fixture.profile.retained.image;
    let directory = &image.directories[FIRST_PROVIDER];
    let original = directory.directory.path();
    let moved = original.with_file_name("retained-provider");
    #[cfg(unix)]
    {
        std::fs::rename(original, &moved).unwrap();
        let replacement = PrivateDirectory::open_or_create(original).unwrap();
        for input in &directory.inputs {
            replacement
                .write_atomic(input.name, &input.bytes, PublishMode::CreateNew)
                .unwrap();
        }
        assert!(image.revalidate().is_err());
        drop(replacement);
        std::fs::remove_dir_all(original).unwrap();
        std::fs::rename(&moved, original).unwrap();
        image.revalidate().unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(original, &moved).is_err());
        assert!(!moved.exists());
        image.revalidate().unwrap();
    }
}

#[test]
fn standard_profile_authenticates_genesis_without_service_capture() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "standard-profile",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    let (_, parses) = count_semantic_validations(|| {
        assert!(capture_retained(&prepared).unwrap().is_none());
    });
    assert_eq!(parses, 0);
    assert!(
        !prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime")
            .join(DIRECTORY)
            .exists()
    );
    let root =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original = root
        .read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)
        .unwrap();
    root.write_atomic(
        "genesis.signed.nrt",
        b"invalid signed genesis",
        PublishMode::Replace,
    )
    .unwrap();
    assert!(capture_retained(&prepared).is_err());
    root.write_atomic("genesis.signed.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert!(capture_retained(&prepared).unwrap().is_none());
}

#[test]
fn fresh_capture_refuses_external_lane_sources_even_when_the_directory_is_empty() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let image = &fixture.profile.retained.image;
    let generation = &image.generation().directory;
    let original = generation.read("peer0.toml", MAX_CONFIG).unwrap();
    let empty = generation.create_child("uncaptured-lane-source").unwrap();
    assert!(empty.entries(0).unwrap().is_empty());
    for field in ["manifest_directory", "cache_directory"] {
        let mut table = flat_table(&original).unwrap();
        let nexus = table.get_mut("nexus").unwrap().as_table_mut().unwrap();
        let registry = nexus
            .entry("registry".to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .unwrap();
        registry.insert(
            field.to_owned(),
            toml::Value::String(empty.path().to_str().unwrap().to_owned()),
        );
        let changed = Zeroizing::new(toml::to_string(&*table).unwrap());
        generation
            .write_atomic("peer0.toml", changed.as_bytes(), PublishMode::Replace)
            .unwrap();
        assert!(
            capture_retained(&fixture.prepared).is_err(),
            "external {field}"
        );
        generation
            .write_atomic("peer0.toml", &original, PublishMode::Replace)
            .unwrap();
        image.revalidate().unwrap();
    }
}

#[test]
fn directory_boundary_preserves_closed_names_and_live_custody_for_both_policies() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    for closed in [false, true] {
        let directory = root
            .create_child(if closed { "closed" } else { "open" })
            .unwrap();
        directory
            .write_atomic("original.nrt", b"original", PublishMode::CreateNew)
            .unwrap();
        let inventory = closed.then(|| vec![OsString::from("original.nrt")]);
        let captured = CapturedDirectory::new(directory, inventory).unwrap();
        let identity = captured.directory.identity().unwrap();
        captured
            .directory
            .write_atomic("derived.nrt", b"derived", PublishMode::CreateNew)
            .unwrap();
        assert_eq!(captured.revalidate().is_ok(), !closed);
        std::fs::remove_file(captured.directory.path().join("derived.nrt")).unwrap();
        captured.revalidate().unwrap();

        let original = captured.directory.path();
        let moved = original.with_file_name(if closed { "held-closed" } else { "held-open" });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(original, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(captured.revalidate().is_err());
            std::fs::set_permissions(original, std::fs::Permissions::from_mode(0o700)).unwrap();
            captured.revalidate().unwrap();

            std::fs::rename(original, &moved).unwrap();
            let replacement = PrivateDirectory::open_or_create(original).unwrap();
            replacement
                .write_atomic("original.nrt", b"original", PublishMode::CreateNew)
                .unwrap();
            assert!(captured.revalidate().is_err());
            drop(replacement);
            std::fs::remove_dir_all(original).unwrap();
            std::fs::rename(&moved, original).unwrap();
        }
        #[cfg(windows)]
        {
            assert!(std::fs::rename(original, &moved).is_err());
            assert!(!moved.exists());
        }
        assert_eq!(captured.directory.identity().unwrap(), identity);
        captured.revalidate().unwrap();
        assert_eq!(
            captured
                .directory
                .read("original.nrt", 8)
                .unwrap()
                .as_slice(),
            b"original"
        );
    }
}
