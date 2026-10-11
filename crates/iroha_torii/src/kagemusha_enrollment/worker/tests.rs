//! Real retained-file refusal tests; no private-process or platform qualification from fixtures.
use super::*;

fn file(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/qualification/enrollment-service/worker-tests");
    std::fs::create_dir_all(&root).unwrap();
    let temp = tempfile::tempdir_in(root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = PrivateDirectory::open(temp.path()).unwrap();
    directory
        .write_atomic("original", bytes, iroha_fs::PublishMode::CreateNew)
        .unwrap();
    let path = temp.path().join("original");
    (temp, path)
}
#[test]
fn original_admission_binds_exact_bytes_pin_extent_and_lifetime() {
    let (_temp, path) = file(b"configured original DATA");
    let pin = Sha256::digest(b"configured original DATA").into();
    let (owner, bytes) = Original::open(&path, true, 64, Some(pin)).unwrap();
    assert_eq!(&*bytes, b"configured original DATA");
    owner.revalidate().unwrap();
    assert!(Original::open(&path, true, 1, Some(pin)).is_err());
    assert!(Original::open(&path, true, 64, Some([99; 32])).is_err());
    assert!(Original::open(&path, true, 64, Some([0; 32])).is_err());
    std::fs::write(&path, b"replaced content original").unwrap();
    assert!(owner.revalidate().is_err());
}
#[test]
fn original_loss_truncation_and_namespace_replacement_remain_unavailable() {
    for action in 0..3 {
        let (_temp, path) = file(b"configured original DATA");
        let (owner, _) = Original::open(&path, true, 64, None).unwrap();
        match action {
            0 => std::fs::remove_file(&path).unwrap(),
            1 => std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(0)
                .unwrap(),
            _ => {
                std::fs::rename(&path, path.with_extension("old")).unwrap();
                std::fs::write(&path, b"configured original DATA").unwrap();
            }
        }
        assert!(owner.revalidate().is_err());
    }
    let (_temp, path) = file(b"");
    assert!(Original::open(&path, true, 64, None).is_err());
}
#[cfg(unix)]
#[test]
fn private_original_refuses_shared_mode_links_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let (_temp, path) = file(b"secret DATA");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Original::open(&path, true, 64, None).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = path.with_extension("linked");
    std::fs::hard_link(&path, &linked).unwrap();
    assert!(Original::open(&path, true, 64, None).is_err());
    std::fs::remove_file(linked).unwrap();
    let symbolic = path.with_extension("symbolic");
    symlink(&path, &symbolic).unwrap();
    assert!(Original::open(&symbolic, true, 64, None).is_err());
}

#[cfg(unix)]
fn synthetic_configuration_owner() -> (tempfile::TempDir, PrivateVerifier) {
    // This intentionally unadmitted test owner exercises configuration retention only.
    // Its fake executable/archive DATA are never launched as a private verifier.
    let (temp, path) = file(b"test-only retained original DATA");
    let mut provider = super::super::test_fixture::provider(path.clone());
    provider.worker.store_directory = temp.path().to_path_buf();
    let directory = PrivateDirectory::open(temp.path()).unwrap();
    directory
        .write_atomic(
            "wallet-e1.generation",
            b"test-only generation DATA",
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    directory
        .write_atomic(
            "wallet-e1.sqlite3",
            b"test-only existing counter DATA",
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    let (generation, _) =
        Original::open(&temp.path().join("wallet-e1.generation"), true, 128, None).unwrap();
    generation.file.file().try_lock().unwrap();
    let root_bytes = Zeroizing::new(b"test-only retained original DATA".to_vec());
    provider.enrollment.platform =
        iroha_data_model::kagemusha::KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: Sha256::digest(&*root_bytes).into(),
        };
    let original = || Original::open(&path, true, 128, None).unwrap().0;
    let owner = PrivateVerifier {
        selected: provider,
        python: original(),
        archive: original(),
        openssl: original(),
        apple_root: Some((original(), root_bytes)),
        directory,
        generation,
        configuration: None,
        process: None,
    };
    (temp, owner)
}

#[cfg(unix)]
#[test]
fn serial_asset_configuration_switch_retains_store_generation_and_exact_originals() {
    let (temp, mut owner) = synthetic_configuration_owner();
    let provider = owner.selected.clone();
    let a = super::super::test_fixture::asset(31, 0);
    let b = super::super::test_fixture::asset(32, 28);
    let first = owner.configuration(&provider, &a).unwrap();
    let second = owner.configuration(&provider, &b).unwrap();
    assert_ne!(first.digest(), second.digest());
    assert_eq!(
        owner.configuration(&provider, &a).unwrap().original(),
        first.original()
    );
    for config in [&first, &second] {
        assert_eq!(
            std::fs::read(temp.path().join(format!(
                "native-config-{}.json",
                hex::encode(config.digest())
            )))
            .unwrap(),
            config.original()
        );
    }
    assert_eq!(
        std::fs::read(temp.path().join("wallet-e1.generation")).unwrap(),
        b"test-only generation DATA"
    );
    assert_eq!(
        std::fs::read(temp.path().join("wallet-e1.sqlite3")).unwrap(),
        b"test-only existing counter DATA"
    );
    let other = std::fs::File::open(temp.path().join("wallet-e1.generation")).unwrap();
    assert!(other.try_lock().is_err()); // Same exclusive owner through A→B→A.
    owner.revalidate(&provider).unwrap();
}

#[cfg(unix)]
#[test]
fn refused_configuration_publication_does_not_reset_store_or_reinterpret_old_configuration() {
    let (temp, mut owner) = synthetic_configuration_owner();
    let provider = owner.selected.clone();
    let a = super::super::test_fixture::asset(31, 0);
    let b = super::super::test_fixture::asset(32, 28);
    let first = owner.configuration(&provider, &a).unwrap();
    let blocked = derive_configuration(
        &provider,
        &b,
        owner.apple_root.as_ref().map(|(_, bytes)| bytes.as_slice()),
    )
    .unwrap();
    let name = format!("native-config-{}.json", hex::encode(blocked.digest()));
    owner
        .directory
        .write_atomic(
            &name,
            b"foreign configuration DATA",
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    assert!(owner.configuration(&provider, &b).is_err());
    assert!(owner.configuration.is_none());
    assert!(owner.process.is_none());
    assert_eq!(
        owner.configuration(&provider, &a).unwrap().original(),
        first.original()
    );
    assert_eq!(
        std::fs::read(temp.path().join(name)).unwrap(),
        b"foreign configuration DATA"
    );
    assert_eq!(
        std::fs::read(temp.path().join("wallet-e1.sqlite3")).unwrap(),
        b"test-only existing counter DATA"
    );
    assert_eq!(
        std::fs::read(temp.path().join("wallet-e1.generation")).unwrap(),
        b"test-only generation DATA"
    );
}
