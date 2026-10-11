//! Cross-platform registration locator DATA rebinding, before any runtime or wallet exists.
//! This reads no proof and copies no file. Ordinary installation still authenticates every
//! original, the complete native finality prefix and successful Global Register execution.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::RegistrationSourceV1;

fn storage(error: std::io::Error) -> Failure {
    use std::io::ErrorKind;
    // O_NOFOLLOW/O_DIRECTORY refusal identifies a different object kind, not a
    // transient storage outage. Darwin and Linux can return either of these.
    #[cfg(unix)]
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        return Failure::code(CUSTODY_LOST);
    }
    Failure::code(match error.kind() {
        ErrorKind::NotFound => ARTIFACTS_UNAVAILABLE,
        ErrorKind::InvalidInput | ErrorKind::InvalidData | ErrorKind::PermissionDenied => {
            CUSTODY_LOST
        }
        _ if error.raw_os_error().is_none() => CUSTODY_LOST,
        _ => ARTIFACTS_UNAVAILABLE,
    })
}

pub(crate) fn relocate_registration_source(original: &[u8], root: &[u8]) -> Result<Response> {
    if original.is_empty()
        || original.len() > REGISTRATION_MAX
        || root.is_empty()
        || root.len() > ROOT_MAX
    {
        return Err(Failure::code(INVALID));
    }
    let root = std::str::from_utf8(root).map_err(|_| Failure::code(INVALID))?;
    // Canonical transport decoding precedes only the *new* platform's path validation.
    // In particular a Windows producer's C:\ path need not be absolute on this device.
    let mut source: RegistrationSourceV1 = norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    )
    .map_err(|_| Failure::code(INVALID))?;
    if source.originals_root.is_empty()
        || source.originals_root.len() > ROOT_MAX
        || source.originals_root.contains('\0')
    {
        return Err(Failure::code(INVALID));
    }
    source.originals_root = root.to_owned();
    source.validate().map_err(|_| Failure::code(INVALID))?;
    let directory = iroha_fs::PrivateDirectory::open_exact(root).map_err(storage)?;
    let bytes = source
        .encode_canonical()
        .map_err(|_| Failure::code(INVALID))?;
    directory.revalidate().map_err(storage)?;
    Ok(Response {
        kind: 12,
        bytes,
        ..Response::default()
    })
}

#[cfg(test)]
mod tests;
