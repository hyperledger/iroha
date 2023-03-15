//! Validation and tokens related to asset definition operations.

use iroha_validator::utils;

use super::*;

tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner)]
        #[validate(pass_conditions::asset_definition::Owner)]
        pub struct _ {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }
    },
    asset_definition::tokens: [
        CanUnregisterAssetDefinition,
        CanSetKeyValueInAssetDefinition,
        CanRemoveKeyValueInAssetDefinition,
    ]
);

impl DefaultValidate for Register<AssetDefinition> {
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

impl DefaultValidate for Unregister<AssetDefinition> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_definition_id = self.object_id();

        pass_if!(utils::is_asset_definition_owner(
            asset_definition_id,
            authority
        ));
        pass_if!(tokens::CanUnregisterAssetDefinition {
            asset_definition_id: asset_definition_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't unregister assets registered by other accounts")
    }
}

impl DefaultValidate for Transfer<Account, AssetDefinition, Account> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let source_account_id = self.source_id();
        let asset_definition = self.object();

        pass_if!(source_account_id == authority);
        pass_if!(utils::is_asset_definition_owner(
            asset_definition.id(),
            authority
        ));

        deny!("Can't transfer asset definition of another account")
    }
}

impl DefaultValidate for SetKeyValue<AssetDefinition, Name, Value> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_definition_id = self.object_id();

        pass_if!(utils::is_asset_definition_owner(
            asset_definition_id,
            authority
        ));
        pass_if!(tokens::CanSetKeyValueInAssetDefinition {
            asset_definition_id: asset_definition_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't set value to the asset definition metadata created by another account")
    }
}

impl DefaultValidate for RemoveKeyValue<AssetDefinition, Name> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_definition_id = self.object_id();

        pass_if!(utils::is_asset_definition_owner(
            asset_definition_id,
            authority
        ));
        pass_if!(tokens::CanRemoveKeyValueInAssetDefinition {
            asset_definition_id: asset_definition_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't remove value from the asset definition metadata created by another account")
    }
}
