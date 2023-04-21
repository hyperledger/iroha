//! Validation and tokens related to role operations.

use super::*;

tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke)]
        #[validate(pass_conditions::OnlyGenesis)]
        pub struct _ {}
    },
    role::tokens: [
        CanUnregisterAnyRole,
    ]
);

impl DefaultValidate for Register<Role> {
    fn default_validate<Q>(
        &self,
        _authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass!()
    }
}

// TODO: Need to allow role creator to unregister it somehow
impl DefaultValidate for Unregister<Role> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass_if!(tokens::CanUnregisterAnyRole {}.is_owned_by(authority));
        deny!("Can't unregister role")
    }
}

macro_rules! impl_validate {
    ($self:ident, $authority:ident, $method:ident) => {
        let role_id = $self.object();

        let find_role_query_res = QueryBox::from(FindRoleByRoleId::new(role_id.clone())).execute();
        let role = Role::try_from(find_role_query_res)
            .dbg_expect("Failed to convert `FindRoleByRoleId` query result to `Role`");

        for token in role.permissions() {
            macro_rules! validate_internal {
                ($token_ty:ty) => {
                    if let Ok(concrete_token) =
                        <$token_ty as ::core::convert::TryFrom<_>>::try_from(
                            <
                                ::iroha_validator::data_model::permission::PermissionToken as
                                ::core::clone::Clone
                            >::clone(token)
                        )
                    {
                        let verdict = <$token_ty as ::iroha_validator::traits::ValidateGrantRevoke>::$method(
                            &concrete_token,
                            $authority,
                        );
                        if verdict.is_deny() {
                            return verdict;
                        }
                        // Continue because token can corresponds to only one concrete token
                        continue;
                    }
                };
            }

            map_all_crate_tokens!(validate_internal);

            // In normal situation we either did early return or continue before reaching this line
            dbg_panic("Role contains unknown permission token, this should never happen");
        }

        pass!()
    };
}

impl DefaultValidate for Grant<Account, RoleId> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        impl_validate!(self, authority, validate_grant);
    }
}

impl DefaultValidate for Revoke<Account, RoleId> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        impl_validate!(self, authority, validate_revoke);
    }
}
