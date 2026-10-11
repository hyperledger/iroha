//! Android-only stock-OS ancestry policy. Ownership is supplied solely by native fstat.
//! This private helper never accepts a path, caller trust flag or offered identity.

use std::io;

const ANDROID_SYSTEM: u32 = 1000;

pub(super) fn validate_permissions(
    owner: u32,
    group: u32,
    mode: u32,
    euid: u32,
    private: bool,
) -> io::Result<()> {
    let denied = |message| io::Error::new(io::ErrorKind::PermissionDenied, message);
    if private {
        if owner != euid || mode & 0o7777 != 0o700 {
            return Err(denied(
                "private directory requires current ownership and mode 0700",
            ));
        }
        return Ok(());
    }
    let privileged_owner = owner == 0 || owner == ANDROID_SYSTEM;
    if !privileged_owner && owner != euid {
        return Err(denied("directory ancestor has foreign ownership"));
    }
    // Android application-private ancestry must never rely on sticky world-writable custody.
    if mode & 0o002 != 0 {
        return Err(denied("directory ancestor is writable by other users"));
    }
    // /data and user roots are system:system 0771. Only the stock OS privileged owner
    // may use that exact trusted system group for writes; app/shared groups never qualify.
    if mode & 0o020 != 0 && !(privileged_owner && group == ANDROID_SYSTEM) {
        return Err(denied("directory ancestor has an untrusted writable group"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "android_ancestry_policy_tests.rs"]
mod tests;
