//! This module contains permissions related Iroha functionality.

use crate::prelude::*;
use iroha_data_model::prelude::*;

/// Reason for prohibiting the execution of the particular instruction.
pub type DenialReason = String;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait PermissionsValidator {
    /// Checks if the `authority` is allowed to perform `instruction` given the current state of `wsv`.
    fn check_instruction(
        &self,
        authority: <Account as Identifiable>::Id,
        instruction: InstructionBox,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason>;
}

/// Box with `PermissionChecker`
pub type PermissionsValidatorBox = Box<dyn PermissionsValidator + Send + Sync>;

/// Allows all ISI to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl PermissionsValidator for AllowAll {
    fn check_instruction(
        &self,
        _authority: <Account as Identifiable>::Id,
        _instruction: InstructionBox,
        _wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

impl From<AllowAll> for PermissionsValidatorBox {
    fn from(_: AllowAll) -> Self {
        Box::new(AllowAll)
    }
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{AllowAll, DenialReason, PermissionsValidatorBox};
}
