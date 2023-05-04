//! Validation and tokens related to parameter operations.

use super::*;

declare_tokens!(
    crate::isi::parameter::tokens::CanGrantPermissionToCreateParameters,
    crate::isi::parameter::tokens::CanRevokePermissionToCreateParameters,
    crate::isi::parameter::tokens::CanCreateParameters,
    crate::isi::parameter::tokens::CanGrantPermissionToSetParameters,
    crate::isi::parameter::tokens::CanRevokePermissionToSetParameters,
    crate::isi::parameter::tokens::CanSetParameters,
);

pub mod tokens {
    //! Permission tokens for asset definition operations

    use super::*;

    /// Strongly-typed representation of `can_grant_permission_to_create_parameters` permission token.
    #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
    #[validate(pass_conditions::OnlyGenesis)]
    pub struct CanGrantPermissionToCreateParameters;

    /// Strongly-typed representation of `can_revoke_permission_to_create_parameters` permission token.
    #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
    #[validate(pass_conditions::OnlyGenesis)]
    pub struct CanRevokePermissionToCreateParameters;

    /// Strongly-typed representation of `can_create_parameters` permission token.
    #[derive(Token, Clone, Copy)]
    pub struct CanCreateParameters;

    impl ValidateGrantRevoke for CanCreateParameters {
        fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
            pass_if!(CanGrantPermissionToCreateParameters.is_owned_by(authority));
            deny!("Can't grant permission to create new configuration parameters without permission from genesis")
        }

        fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
            pass_if!(CanRevokePermissionToCreateParameters.is_owned_by(authority));
            deny!("Can't revoke permission to create new configuration parameters without permission from genesis")
        }
    }

    /// Strongly-typed representation of `can_grant_permission_to_set_parameters` permission token.
    #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
    #[validate(pass_conditions::OnlyGenesis)]
    pub struct CanGrantPermissionToSetParameters;

    /// Strongly-typed representation of `can_revoke_permission_to_set_parameters` permission token.
    #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
    #[validate(pass_conditions::OnlyGenesis)]
    pub struct CanRevokePermissionToSetParameters;

    /// Strongly-typed representation of `can_set_parameters` permission token.
    #[derive(Token, Clone, Copy)]
    pub struct CanSetParameters;

    impl ValidateGrantRevoke for CanSetParameters {
        fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
            pass_if!(CanGrantPermissionToSetParameters.is_owned_by(authority));
            deny!("Can't grant permission to set configuration parameters without permission from genesis")
        }

        fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
            pass_if!(CanRevokePermissionToSetParameters.is_owned_by(authority));
            deny!("Can't revoke permission to set configuration parameters without permission from genesis")
        }
    }
}

impl DefaultValidate for NewParameter {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass_if!(tokens::CanCreateParameters.is_owned_by(authority));

        deny!("Can't create new configuration parameters without permission")
    }
}

impl DefaultValidate for SetParameter {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass_if!(tokens::CanSetParameters.is_owned_by(authority));

        deny!("Can't set configuration parameters without permission")
    }
}
