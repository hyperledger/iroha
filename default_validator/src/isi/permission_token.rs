//! Validation of operations related to permission token.

use super::*;

macro_rules! impl_validate {
    ($self:ident, $authority:ident, $method:ident) => {
        let token = $self.object();

        macro_rules! validate_internal {
                    ($token_ty:ty) => {
                        if let Ok(concrete_token) =
                            <$token_ty as ::core::convert::TryFrom<_>>::try_from(
                                <
                                    ::iroha_validator::data_model::permission::token::PermissionToken as
                                    ::core::clone::Clone
                                >::clone(token)
                            )
                        {
                            return <$token_ty as ::iroha_validator::traits::ValidateGrantRevoke>::$method(
                                &concrete_token,
                                $authority
                            );
                        }
                    };
                }

        map_all_crate_tokens!(validate_internal);
        deny!("Unknown permission token")
    };
}

impl DefaultValidate for Grant<Account, PermissionToken> {
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

impl DefaultValidate for Revoke<Account, PermissionToken> {
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
