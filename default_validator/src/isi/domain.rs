//! Validation and tokens related to domain operations.

use super::*;

// TODO: We probably need a better way to allow accounts to modify domains.
tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke)]
        #[validate(pass_conditions::OnlyGenesis)]
        pub struct _ {
            pub domain_id: <Domain as Identifiable>::Id,
        }
    },
    domain::tokens: [
        CanUnregisterDomain,
        CanSetKeyValueInDomain,
        CanRemoveKeyValueInDomain,
    ]
);

impl DefaultValidate for Register<Domain> {
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

impl DefaultValidate for Unregister<Domain> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let domain_id = self.object_id().clone();

        pass_if!(tokens::CanUnregisterDomain { domain_id }.is_owned_by(authority));
        deny!("Can't unregister domain")
    }
}

impl DefaultValidate for SetKeyValue<Domain, Name, Value> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let domain_id = self.object_id().clone();

        pass_if!(tokens::CanSetKeyValueInDomain { domain_id }.is_owned_by(authority));
        deny!("Can't set key value in domain metadata")
    }
}

impl DefaultValidate for RemoveKeyValue<Domain, Name> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let domain_id = self.object_id().clone();

        pass_if!(tokens::CanRemoveKeyValueInDomain { domain_id }.is_owned_by(authority));
        deny!("Can't remove key value in domain metadata")
    }
}
