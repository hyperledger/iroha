//! The generated role parser is bounded, canonical, role-bound and secret-redacted.

use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};

fn fixture_key(seed: u8, algorithm: iroha_crypto::Algorithm) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], algorithm).unwrap()
}

fn encoded(key: &KeyPair) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(
        ExposedPrivateKey(key.private_key().clone())
            .try_to_multihash_string()
            .unwrap()
            .into_bytes(),
    );
    bytes.push(b'\n');
    bytes
}

fn assert_redacted(error: Error) {
    // Equality with a closed diagnostic proves no key text, arbitrary path or parser error escapes.
    match error {
        Error::Invalid(message) => assert_eq!(message, "invalid original service role credential"),
        _ => panic!("credential failure must use the closed redacted error"),
    }
}

#[test]
fn role_credential_requires_exact_bounded_canonical_ed25519_line() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("roles")).unwrap();
    // Retained Ed25519 seed bytes must include alphabetic hex for the case-only variant below.
    let key = fixture_key(0xab, iroha_crypto::Algorithm::Ed25519);
    let authority = StreamTokenAuthority {
        role: StreamTokenAuthorityRole::IssuerOperator,
        account: AccountId::new(key.public_key().clone()),
    };
    let canonical = encoded(&key);
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &canonical,
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(read_role_key(&directory, &authority).unwrap() == key);
    let text = std::str::from_utf8(&canonical[..canonical.len() - 1]).unwrap();
    // Case-only alternate text is noncanonical even when the hexadecimal digit values agree.
    let alternate = if text.to_ascii_lowercase() == text {
        text.to_ascii_uppercase()
    } else {
        text.to_ascii_lowercase()
    };
    assert!(alternate != text);
    let malformed = [
        canonical[..canonical.len() - 1].to_vec(),
        [canonical.as_slice(), b"\n"].concat(),
        [text.as_bytes(), b"\r\n"].concat(),
        [b" ", canonical.as_slice()].concat(),
        [text.as_bytes(), b" \n"].concat(),
        [alternate.as_bytes(), b"\n"].concat(),
        vec![0xff, b'\n'],
        vec![b'x'; MAX_ROLE_CREDENTIAL_BYTES + 1],
        b"sensitive malformed credential\n".to_vec(),
    ];
    for bytes in malformed {
        let bytes = Zeroizing::new(bytes);
        directory
            .write_atomic(
                authority.role.credential_filename(),
                &bytes,
                PublishMode::Replace,
            )
            .unwrap();
        assert_redacted(read_role_key(&directory, &authority).unwrap_err());
    }
    let other = fixture_key(20, iroha_crypto::Algorithm::Secp256k1);
    let other_authority = StreamTokenAuthority {
        role: authority.role,
        account: AccountId::new(other.public_key().clone()),
    };
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &encoded(&other),
            PublishMode::Replace,
        )
        .unwrap();
    assert_redacted(read_role_key(&directory, &other_authority).unwrap_err());
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &canonical,
            PublishMode::Replace,
        )
        .unwrap();
    assert!(read_role_key(&directory, &authority).unwrap() == key);
}

#[test]
fn role_credential_replacement_cannot_select_another_role_or_account() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("roles")).unwrap();
    let operator = fixture_key(31, iroha_crypto::Algorithm::Ed25519);
    let observer = fixture_key(32, iroha_crypto::Algorithm::Ed25519);
    let authority = StreamTokenAuthority {
        role: StreamTokenAuthorityRole::IssuerOperator,
        account: AccountId::new(operator.public_key().clone()),
    };
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &encoded(&operator),
            PublishMode::CreateNew,
        )
        .unwrap();
    directory
        .write_atomic(
            StreamTokenAuthorityRole::IssuerObserver.credential_filename(),
            &encoded(&observer),
            PublishMode::CreateNew,
        )
        .unwrap();
    let wrong_role = StreamTokenAuthority {
        role: StreamTokenAuthorityRole::IssuerObserver,
        account: authority.account.clone(),
    };
    assert_redacted(read_role_key(&directory, &wrong_role).unwrap_err());
    let wrong_account = StreamTokenAuthority {
        role: authority.role,
        account: AccountId::new(observer.public_key().clone()),
    };
    assert_redacted(read_role_key(&directory, &wrong_account).unwrap_err());
    // Replace the original inode with a private, canonical credential for another registered role.
    let original = directory
        .open_read(authority.role.credential_filename())
        .unwrap();
    let identity = iroha_fs::FileIdentity::of(&original).unwrap();
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &encoded(&observer),
            PublishMode::Replace,
        )
        .unwrap();
    assert_ne!(
        identity,
        iroha_fs::FileIdentity::of(
            &directory
                .open_read(authority.role.credential_filename())
                .unwrap()
        )
        .unwrap()
    );
    assert_redacted(read_role_key(&directory, &authority).unwrap_err());
    drop(original);
    directory
        .write_atomic(
            authority.role.credential_filename(),
            &encoded(&operator),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(read_role_key(&directory, &authority).unwrap() == operator);
}

#[cfg(unix)]
#[test]
fn role_credential_symlink_substitution_is_redacted_and_refused() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("roles")).unwrap();
    let key = fixture_key(41, iroha_crypto::Algorithm::Ed25519);
    let authority = StreamTokenAuthority {
        role: StreamTokenAuthorityRole::IssuerOperator,
        account: AccountId::new(key.public_key().clone()),
    };
    let observer = StreamTokenAuthorityRole::IssuerObserver.credential_filename();
    directory
        .write_atomic(observer, &encoded(&key), PublishMode::CreateNew)
        .unwrap();
    symlink(
        directory.path().join(observer),
        directory.path().join(authority.role.credential_filename()),
    )
    .unwrap();
    assert_redacted(read_role_key(&directory, &authority).unwrap_err());
}
