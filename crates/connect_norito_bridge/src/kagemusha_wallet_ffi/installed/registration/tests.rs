//! DATA relocation tests; no proof files or ledger admission are manufactured here.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::RegistrationInventoryV1;

fn source() -> RegistrationSourceV1 {
    RegistrationSourceV1 {
        version: 1,
        originals_root: r"C:\operator\registration\originals".into(),
        inventory: RegistrationInventoryV1 {
            version: 1,
            asset_digest: [1; 32],
            instruction_index: 7,
            committed: BlobV1::of(b"unverified committed DATA"),
            first: BlobV1::of(b"unverified first link DATA"),
            proof_count: 123,
        },
    }
}
fn private() -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = temp
        .path()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (temp, path)
}
fn original(source: &RegistrationSourceV1) -> Vec<u8> {
    norito::encode_canonical(source).unwrap()
}

#[test]
fn foreign_platform_path_is_relocated_without_changing_unverified_inventory() {
    let (_temp, root) = private();
    let before = source();
    let reply = relocate_registration_source(&original(&before), root.as_bytes()).unwrap();
    assert_eq!(reply.kind, 12);
    let after = RegistrationSourceV1::decode_canonical(&reply.bytes).unwrap();
    assert_eq!(after.inventory, before.inventory);
    assert_eq!(after.version, before.version);
    assert_eq!(after.originals_root, root);
    assert_eq!(
        relocate_registration_source(&reply.bytes, root.as_bytes())
            .unwrap()
            .bytes,
        reply.bytes
    );
    // The directory remains empty: success reports only canonical DATA, never copied evidence.
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn relocation_refuses_noncanonical_bounded_data_or_invalid_new_scope() {
    let (_temp, root) = private();
    let original = original(&source());
    let mut trailing = original.clone();
    trailing.push(0);
    for bytes in [Vec::new(), trailing, vec![0; REGISTRATION_MAX + 1]] {
        assert_eq!(
            relocate_registration_source(&bytes, root.as_bytes())
                .unwrap_err()
                .status,
            INVALID
        );
    }
    for root in ["", "relative", "/../foreign", "/nul\0root"] {
        assert_eq!(
            relocate_registration_source(&original, root.as_bytes())
                .unwrap_err()
                .status,
            INVALID
        );
    }
    assert_eq!(
        relocate_registration_source(&original, &vec![b'a'; ROOT_MAX + 1])
            .unwrap_err()
            .status,
        INVALID
    );
    for variant in 0..4 {
        let mut changed = source();
        match variant {
            0 => changed.version = 2,
            1 => changed.inventory.version = 2,
            2 => changed.inventory.proof_count = 1,
            _ => changed.inventory.first.sha256 = [0; 32],
        }
        assert_eq!(
            relocate_registration_source(
                &norito::encode_canonical(&changed).unwrap(),
                root.as_bytes()
            )
            .unwrap_err()
            .status,
            INVALID
        );
    }
}

#[test]
fn relocation_retains_private_no_follow_directory_custody() {
    let (_temp, root) = private();
    let source = original(&source());
    let missing = std::path::Path::new(&root).join("absent");
    assert_eq!(
        relocate_registration_source(&source, missing.to_str().unwrap().as_bytes())
            .unwrap_err()
            .status,
        ARTIFACTS_UNAVAILABLE
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for errno in [libc::ELOOP, libc::ENOTDIR] {
            assert_eq!(
                storage(std::io::Error::from_raw_os_error(errno)).status,
                CUSTODY_LOST
            );
        }
        assert_eq!(
            storage(std::io::Error::from_raw_os_error(libc::EIO)).status,
            ARTIFACTS_UNAVAILABLE
        );
        let link = std::path::Path::new(&root).join("alias");
        symlink(&root, &link).unwrap();
        assert_eq!(
            relocate_registration_source(&source, link.to_str().unwrap().as_bytes())
                .unwrap_err()
                .status,
            CUSTODY_LOST
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            relocate_registration_source(&source, root.as_bytes())
                .unwrap_err()
                .status,
            CUSTODY_LOST
        );
    }
}

#[test]
fn c_relocation_initializes_failures_and_returns_owned_canonical_data() {
    use super::super::exports::connect_norito_kagemusha_wallet_registration_source_relocate_v1 as relocate;
    let (_temp, root) = private();
    let source = original(&source());
    let mut out = WalletResult::default();
    // SAFETY: buffers are live and exactly sized; each successful owned output is freed once.
    unsafe {
        assert_eq!(
            relocate(
                source.as_ptr(),
                source.len(),
                root.as_ptr(),
                root.len(),
                std::ptr::null_mut()
            ),
            INVALID
        );
        assert_eq!(
            relocate(std::ptr::null(), 1, root.as_ptr(), root.len(), &mut out),
            INVALID
        );
        assert_eq!(out.status, INVALID);
        assert!(out.bytes.is_null());
        assert_eq!(out.length, 0);
        assert_eq!(
            relocate(
                source.as_ptr(),
                source.len(),
                root.as_ptr(),
                root.len(),
                &mut out
            ),
            0
        );
        assert_eq!(
            (out.status, out.sequence_low, out.sequence_high, out.detail),
            (12, 0, 0, 0)
        );
        assert!(!out.bytes.is_null());
        assert_eq!(
            RegistrationSourceV1::decode_canonical(std::slice::from_raw_parts(
                out.bytes, out.length
            ))
            .unwrap()
            .originals_root,
            root
        );
        crate::connect_norito_free(out.bytes);
    }
}
