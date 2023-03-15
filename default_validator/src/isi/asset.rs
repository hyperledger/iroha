//! Validation and tokens related to asset operations.

use iroha_validator::utils;
use marker::AssetValueMarker;

use super::*;

declare_tokens!(
    crate::isi::asset::tokens::CanRegisterAssetsWithDefinition,
    crate::isi::asset::tokens::CanUnregisterAssetsWithDefinition,
    crate::isi::asset::tokens::CanUnregisterUserAsset,
    crate::isi::asset::tokens::CanBurnAssetsWithDefinition,
    crate::isi::asset::tokens::CanBurnUserAsset,
    crate::isi::asset::tokens::CanMintAssetsWithDefinition,
    crate::isi::asset::tokens::CanTransferAssetsWithDefinition,
    crate::isi::asset::tokens::CanTransferUserAsset,
    crate::isi::asset::tokens::CanSetKeyValueInUserAsset,
    crate::isi::asset::tokens::CanRemoveKeyValueInUserAsset,
);

pub mod tokens {
    //! Permission tokens for asset operations

    use super::*;

    /// Strongly-typed representation of `can_register_assets_with_definition` permission token.
    #[derive(
        Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner,
    )]
    #[validate(pass_conditions::asset_definition::Owner)]
    pub struct CanRegisterAssetsWithDefinition {
        pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_unregister_assets_with_definition` permission token.
    #[derive(
        Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner,
    )]
    #[validate(pass_conditions::asset_definition::Owner)]
    pub struct CanUnregisterAssetsWithDefinition {
        pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_unregister_user_asset` permission token.
    #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset::Owner)]
    #[validate(pass_conditions::asset::Owner)]
    pub struct CanUnregisterUserAsset {
        pub asset_id: <Asset as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_burn_assets_with_definition` permission token.
    #[derive(
        Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner,
    )]
    #[validate(pass_conditions::asset_definition::Owner)]
    pub struct CanBurnAssetsWithDefinition {
        pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
    }

    /// Strong-typed representation of `can_burn_user_asset` permission token.
    #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset::Owner)]
    #[validate(pass_conditions::asset::Owner)]
    pub struct CanBurnUserAsset {
        pub asset_id: <Asset as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_mint_assets_with_definition` permission token.
    #[derive(
        Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner,
    )]
    #[validate(pass_conditions::asset_definition::Owner)]
    pub struct CanMintAssetsWithDefinition {
        pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_transfer_assets_with_definition` permission token.
    #[derive(
        Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset_definition::Owner,
    )]
    #[validate(pass_conditions::asset_definition::Owner)]
    pub struct CanTransferAssetsWithDefinition {
        pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_transfer_user_asset` permission token.
    #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset::Owner)]
    #[validate(pass_conditions::asset::Owner)]
    pub struct CanTransferUserAsset {
        pub asset_id: <Asset as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_set_key_value_in_user_asset` permission token.
    #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset::Owner)]
    #[validate(pass_conditions::asset::Owner)]
    pub struct CanSetKeyValueInUserAsset {
        pub asset_id: <Asset as Identifiable>::Id,
    }

    /// Strongly-typed representation of `can_remove_key_value_in_user_asset` permission token.
    #[derive(Token, ValidateGrantRevoke, pass_conditions::derive_conversions::asset::Owner)]
    #[validate(pass_conditions::asset::Owner)]
    pub struct CanRemoveKeyValueInUserAsset {
        pub asset_id: <Asset as Identifiable>::Id,
    }
}

mod marker {
    use super::*;

    pub trait AssetValueMarker: Into<Value> {}

    impl AssetValueMarker for u32 {}
    impl AssetValueMarker for u128 {}
    impl AssetValueMarker for Fixed {}
}

impl DefaultValidate for Register<Asset> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset = self.object();

        pass_if!(utils::is_asset_definition_owner(
            asset.id().definition_id(),
            authority
        ));
        pass_if!(tokens::CanRegisterAssetsWithDefinition {
            asset_definition_id: asset.id().definition_id().clone()
        }
        .is_owned_by(authority));

        deny!("Can't register assets with definitions registered by other accounts")
    }
}

impl DefaultValidate for Unregister<Asset> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.object_id();

        pass_if!(asset_id.account_id() == authority);
        pass_if!(utils::is_asset_definition_owner(
            asset_id.definition_id(),
            authority
        ));
        pass_if!(tokens::CanUnregisterAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone()
        }
        .is_owned_by(authority));
        pass_if!(tokens::CanUnregisterUserAsset {
            asset_id: asset_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't unregister asset from another account")
    }
}

impl<V: AssetValueMarker> DefaultValidate for Burn<Asset, V> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.destination_id();

        pass_if!(asset_id.account_id() == authority);
        pass_if!(utils::is_asset_definition_owner(
            asset_id.definition_id(),
            authority
        ));
        pass_if!(tokens::CanBurnAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone()
        }
        .is_owned_by(authority));
        pass_if!(tokens::CanBurnUserAsset {
            asset_id: asset_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't burn assets from another account")
    }
}

impl<V: AssetValueMarker> DefaultValidate for Mint<Asset, V> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.destination_id();

        pass_if!(utils::is_asset_definition_owner(
            asset_id.definition_id(),
            authority
        ));
        pass_if!(tokens::CanMintAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone()
        }
        .is_owned_by(authority));

        deny!("Can't mint assets with definitions registered by other accounts")
    }
}

impl<V: AssetValueMarker> DefaultValidate for Transfer<Asset, V, Asset> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.source_id();

        pass_if!(asset_id.account_id() == authority);
        pass_if!(tokens::CanTransferAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone()
        }
        .is_owned_by(authority));
        pass_if!(tokens::CanTransferUserAsset {
            asset_id: asset_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't transfer assets of another account")
    }
}

impl DefaultValidate for SetKeyValue<Asset, Name, Value> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.object_id();

        pass_if!(asset_id.account_id() == authority);
        pass_if!(tokens::CanSetKeyValueInUserAsset {
            asset_id: asset_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't set value to the asset metadata of another account")
    }
}

impl DefaultValidate for RemoveKeyValue<Asset, Name> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let asset_id = self.object_id();

        pass_if!(asset_id.account_id() == authority);
        pass_if!(tokens::CanRemoveKeyValueInUserAsset {
            asset_id: asset_id.clone()
        }
        .is_owned_by(authority));

        deny!("Can't remove value from the asset metadata of another account")
    }
}
