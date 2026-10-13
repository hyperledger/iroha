//! Bounded, zeroizing supervisor credential reads shared by daemon runtime providers.
use std::{
    io::ErrorKind,
    path::{Component, Path},
};
use zeroize::Zeroizing;

/// Read one bounded secret credential through the shared native custody boundary.
///
/// The returned allocation is zeroized on every exit path. Callers decode it immediately
/// into secret-owning types whose `Drop` implementation also scrubs private fields.
pub fn load_bounded_runtime_credential_v1(
    path: &Path,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, RuntimeCredentialErrorV1> {
    if minimum_bytes == 0 || minimum_bytes > maximum_bytes {
        return Err(RuntimeCredentialErrorV1::InvalidLength);
    }
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(RuntimeCredentialErrorV1::InvalidSource);
    }
    let bytes =
        iroha_fs::read_private(path, maximum_bytes).map_err(|error| match error.kind() {
            ErrorKind::InvalidInput => RuntimeCredentialErrorV1::InvalidLength,
            ErrorKind::NotFound => RuntimeCredentialErrorV1::Unavailable,
            _ => RuntimeCredentialErrorV1::InvalidSource,
        })?;
    if bytes.len() < minimum_bytes {
        return Err(RuntimeCredentialErrorV1::InvalidLength);
    }
    Ok(bytes)
}
/// Decode the sole canonical newline-terminated software key and require its exact public key.
/// This grants key custody only; every consumer retains its native role/permission checks.
pub fn load_bound_software_key_v1(
    path: &Path,
    expected: &iroha_crypto::PublicKey,
) -> Result<iroha_crypto::KeyPair, RuntimeCredentialErrorV1> {
    let invalid = RuntimeCredentialErrorV1::InvalidSource;
    let bytes = load_bounded_runtime_credential_v1(path, 2, 16 * 1024 + 256)?;
    let text = bytes
        .strip_suffix(b"\n")
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or(invalid)?;
    let private: iroha_crypto::ExposedPrivateKey = text.parse().map_err(|_| invalid)?;
    let canonical = Zeroizing::new(private.try_to_multihash_string().map_err(|_| invalid)?);
    if canonical.as_str() != text {
        return Err(invalid);
    }
    let key = iroha_crypto::KeyPair::from_private_key(private.0).map_err(|_| invalid)?;
    if key.public_key() != expected {
        return Err(invalid);
    }
    Ok(key)
}

/// Payload-free bounded runtime-credential source failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCredentialErrorV1 {
    /// Descriptor or credential path/metadata is not trusted.
    InvalidSource,
    /// Credential length is outside the caller's admitted bounds.
    InvalidLength,
    /// Credential could not be read.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
    };

    fn fixture(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        // Keep the fixture below the checkout so writable global temporary
        // ancestors cannot weaken the production credential-path policy.
        let directory = tempfile::Builder::new()
            .prefix(".runtime-credential-test-")
            .tempdir_in(std::env::current_dir().expect("checkout directory"))
            .expect("private credential directory");
        let private = iroha_fs::PrivateDirectory::open_or_create(directory.path().join("private"))
            .expect("private runtime credentials");
        private
            .write_atomic("runtime-secret", bytes, iroha_fs::PublishMode::CreateNew)
            .expect("private credential");
        let path = private.path().join("runtime-secret");
        (directory, path)
    }

    #[test]
    fn bound_software_key_requires_canonical_original_and_exact_public_key() {
        let key =
            iroha_crypto::KeyPair::from_seed(vec![0x93; 32], iroha_crypto::Algorithm::Ed25519);
        let text = format!(
            "{}\n",
            iroha_crypto::ExposedPrivateKey(key.private_key().clone())
                .try_to_multihash_string()
                .unwrap()
        );
        let (_root, path) = fixture(text.as_bytes());
        assert_eq!(
            load_bound_software_key_v1(&path, key.public_key())
                .unwrap()
                .public_key(),
            key.public_key()
        );
        let foreign =
            iroha_crypto::KeyPair::from_seed(vec![0x94; 32], iroha_crypto::Algorithm::Ed25519);
        assert!(load_bound_software_key_v1(&path, foreign.public_key()).is_err());
        let (_root, missing_newline) = fixture(text.trim_end().as_bytes());
        assert!(load_bound_software_key_v1(&missing_newline, key.public_key()).is_err());
        let (_root, extra) = fixture(format!("{text}\n").as_bytes());
        assert!(load_bound_software_key_v1(&extra, key.public_key()).is_err());
    }

    #[test]
    fn bounded_runtime_credential_reads_exact_bytes_and_checks_limits() {
        let (_directory, path) = fixture(&[0xA7; 64]);
        assert_eq!(
            load_bounded_runtime_credential_v1(&path, 32, 64)
                .expect("admitted runtime credential")
                .as_slice(),
            &[0xA7; 64]
        );
        for (minimum, maximum) in [(0, 64), (65, 64), (1, 63), (65, 128)] {
            assert!(matches!(
                load_bounded_runtime_credential_v1(&path, minimum, maximum),
                Err(RuntimeCredentialErrorV1::InvalidLength)
            ));
        }
        let (_empty_directory, empty) = fixture(&[]);
        assert!(matches!(
            load_bounded_runtime_credential_v1(&empty, 1, 64),
            Err(RuntimeCredentialErrorV1::InvalidLength)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_credential_rejects_links_public_modes_and_unsafe_ancestors() {
        let (directory, path) = fixture(&[0xB7; 32]);
        let symbolic = path.with_file_name("symbolic");
        symlink(&path, &symbolic).expect("credential symlink fixture");
        assert!(matches!(
            load_bounded_runtime_credential_v1(&symbolic, 32, 32),
            Err(RuntimeCredentialErrorV1::InvalidSource)
        ));
        let hard = path.with_file_name("hard");
        fs::hard_link(&path, &hard).expect("credential hardlink fixture");
        assert!(matches!(
            load_bounded_runtime_credential_v1(&path, 32, 32),
            Err(RuntimeCredentialErrorV1::InvalidSource)
        ));
        fs::remove_file(hard).expect("remove fixture hardlink");
        for mode in [0o644, 0o440, 0o004, 0o1400] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("unsafe mode");
            assert!(matches!(
                load_bounded_runtime_credential_v1(&path, 32, 32),
                Err(RuntimeCredentialErrorV1::InvalidSource)
            ));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("restore mode");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770))
            .expect("writable parent fixture");
        assert!(matches!(
            load_bounded_runtime_credential_v1(&path, 32, 32),
            Err(RuntimeCredentialErrorV1::InvalidSource)
        ));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restore private parent");
        assert!(matches!(
            load_bounded_runtime_credential_v1(Path::new("runtime-secret"), 32, 32),
            Err(RuntimeCredentialErrorV1::InvalidSource)
        ));
        assert!(matches!(
            load_bounded_runtime_credential_v1(directory.path(), 32, 32),
            Err(RuntimeCredentialErrorV1::InvalidSource)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_credential_rejects_mode_and_length_changes() {
        let (_directory, path) = fixture(&[0xC7; 32]);
        let retained = iroha_fs::RetainedFile::open_private(&path).expect("retained credential");
        retained.revalidate().expect("original credential");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("mode change");
        assert!(retained.revalidate().is_err());
        let retained = iroha_fs::RetainedFile::open_private(&path).expect("read-only credential");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("writable credential");
        fs::write(&path, [0xC7; 33]).expect("length change");
        assert!(retained.revalidate().is_err());
    }
}
