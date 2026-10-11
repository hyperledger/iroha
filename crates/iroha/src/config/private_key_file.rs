//! Native private-key file admission: one bounded, private, immutable descriptor observation.

use eyre::{Result, bail, eyre};
use iroha_crypto::{ExposedPrivateKey, PrivateKey};
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
const MAX_BYTES: usize = 4096;

#[cfg(test)]
pub(super) fn read(path: &Path) -> Result<PrivateKey> {
    use iroha_config_base::file_source::{ConfigFileAccess, ConfigFileRequest, read_checked};
    let encoded = read_checked(
        &super::user::NativeConfigFiles,
        path,
        ConfigFileRequest {
            access: ConfigFileAccess::Private,
            maximum: MAX_BYTES,
        },
    )?;
    parse(&encoded)
}

pub(super) fn parse(encoded: &[u8]) -> Result<PrivateKey> {
    let text =
        std::str::from_utf8(encoded).map_err(|_| eyre!("private-key file must contain UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains(['\r', '\n']) {
        bail!("private-key file must contain one canonical private key and optional final LF");
    }
    let key = text
        .parse::<PrivateKey>()
        .map_err(|_| eyre!("private-key file does not contain a canonical private key"))?;
    if ExposedPrivateKey(key.clone()).to_string() != text {
        bail!("private-key file does not contain a canonical private key");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, PrivateKey) {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        let path = directory.path().join("private.key");
        let key =
            iroha_crypto::KeyPair::try_from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .private_key()
                .clone();
        directory
            .write_atomic(
                "private.key",
                format!("{}\n", ExposedPrivateKey(key.clone())).as_bytes(),
                iroha_fs::PublishMode::CreateNew,
            )
            .unwrap();
        (temporary, path, key)
    }

    #[cfg(unix)]
    #[test]
    fn native_key_reader_accepts_only_private_canonical_single_link_files() {
        let (temporary, path, key) = fixture();
        assert_eq!(read(&path).unwrap(), key);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read(&path).unwrap(), key);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temporary.path().join("linked");
        symlink(&path, &link).unwrap();
        assert!(read(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(read(&path).is_err());
        fs::remove_file(&link).unwrap();
        for mode in [0o644, 0o660, 0o700, 0o1600] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(read(&path).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![b'x'; MAX_BYTES + 1]).unwrap();
        assert!(read(&path).is_err());
        fs::remove_file(&path).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(read(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_key_reader_rejects_path_replacement_while_holding_original_file() {
        let (temporary, path, _) = fixture();
        let retained = iroha_fs::RetainedFile::open_private(&path).unwrap();
        fs::rename(&path, temporary.path().join("original.key")).unwrap();
        fs::write(&path, "not-the-opened-file").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(retained.revalidate().is_err());
    }

    #[test]
    fn canonical_private_key_loads_on_every_native_platform() {
        let (_temporary, path, key) = fixture();
        assert_eq!(read(&path).unwrap(), key);
        let linked = path.with_file_name("hardlink");
        fs::hard_link(&path, &linked).unwrap();
        assert!(read(&path).is_err());
        fs::remove_file(linked).unwrap();
    }

    #[test]
    fn native_key_parse_errors_never_echo_key_material() {
        for input in [
            b"private-marker-must-not-leak".as_slice(),
            b"one\ntwo",
            b"key\r\n",
            &[0xff],
            b"",
        ] {
            let error = parse(input).unwrap_err();
            assert!(!format!("{error:#}").contains("private-marker-must-not-leak"));
        }
    }
}
