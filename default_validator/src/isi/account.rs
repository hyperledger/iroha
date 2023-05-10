//! Validation and tokens related to account operations.

use super::*;

tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::account::Owner)]
        #[validate(pass_conditions::account::Owner)]
        pub struct _ {
            pub account_id: <Account as Identifiable>::Id,
        }
    },
    account::tokens: [
        CanUnregisterAccount,
        CanMintUserPublicKeys,
        CanBurnUserPublicKeys,
        CanMintUserSignatureCheckConditions,
        CanSetKeyValueInUserAccount,
        CanRemoveKeyValueInUserAccount,
    ]
);

impl DefaultValidate for Register<Account> {
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

impl DefaultValidate for Unregister<Account> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.object_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanUnregisterAccount { account_id }.is_owned_by(authority));

        deny!("Can't unregister another account")
    }
}

impl DefaultValidate for Mint<Account, PublicKey> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.destination_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanMintUserPublicKeys { account_id }.is_owned_by(authority));

        deny!("Can't mint public keys of another account")
    }
}

impl DefaultValidate for Burn<Account, PublicKey> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.destination_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanBurnUserPublicKeys { account_id }.is_owned_by(authority));

        deny!("Can't burn public keys of another account")
    }
}

impl DefaultValidate for Mint<Account, SignatureCheckCondition> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.destination_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanMintUserSignatureCheckConditions { account_id }.is_owned_by(authority));

        deny!("Can't mint signature check conditions of another account")
    }
}

impl DefaultValidate for SetKeyValue<Account, Name, Value> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.object_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanSetKeyValueInUserAccount { account_id }.is_owned_by(authority));

        deny!("Can't set value to the metadata of another account")
    }
}

impl DefaultValidate for RemoveKeyValue<Account, Name> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let account_id = self.object_id().clone();

        pass_if!(&account_id == authority);
        pass_if!(tokens::CanRemoveKeyValueInUserAccount { account_id }.is_owned_by(authority));

        deny!("Can't remove value from the metadata of another account")
    }
}
