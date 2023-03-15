//! Runtime Permission Validator which allows any operation done by `admin@admin` account.
//! If authority is not `admin@admin` then `iroha_default_validator` is used.

#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::{parse, prelude::*};

/// Allow operation if authority is `admin@admin` and fallback to
/// [`iroha_default_validator::validate()`] if not.
#[entrypoint(params = "[authority, operation]")]
pub fn validate(
    authority: <Account as Identifiable>::Id,
    operation: NeedsPermissionBox,
) -> Verdict {
    pass_if!(authority == parse!("admin@admin" as <Account as Identifiable>::Id));
    iroha_default_validator::validate(authority, operation)
}
