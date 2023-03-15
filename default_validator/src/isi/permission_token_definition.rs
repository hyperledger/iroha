//! Validation of operations related to permission token definition.

use super::*;

impl DefaultValidate for Register<PermissionTokenDefinition> {
    fn default_validate<Q>(
        &self,
        _authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        deny!("Registering new permission token definitions is allowed only in genesis")
    }
}

// `PermissionTokenDefinition` unregistration is probably useless now and should be removed.
// Or we can keep it for future migration purposes.
impl DefaultValidate for Unregister<PermissionTokenDefinition> {
    fn default_validate<Q>(
        &self,
        _authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        deny!("Can't unregister permission token definition")
    }
}
