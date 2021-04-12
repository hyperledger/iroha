//! Out of box implementations for common permission checks.

#![allow(clippy::module_name_repetitions)]

use std::{collections::BTreeMap, convert::TryInto};

use iroha::{
    expression::Evaluate,
    permissions::{
        prelude::*, GrantedTokenValidator, PermissionsValidator, PermissionsValidatorBuilder,
        ValidatorApplyOr,
    },
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

macro_rules! impl_from_item_for_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_granted_token_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for GrantedTokenValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                let validator: GrantedTokenValidatorBox = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_grant_instruction_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for GrantInstructionValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                let validator: GrantInstructionValidatorBox = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! try_into_or_exit {
    ( $ident:ident ) => {
        if let Ok(into) = $ident.try_into() {
            into
        } else {
            return Ok(());
        }
    };
}

/// Permission checks asociated with use cases that can be summarized as private blockchains (e.g. CBDC).
pub mod private_blockchain {

    use super::*;

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions() -> PermissionsValidatorBox {
        PermissionsValidatorBuilder::new()
            .with_recursive_validator(
                register::ProhibitRegisterDomains.or(register::GrantedAllowedRegisterDomains),
            )
            .all_should_succeed()
    }

    /// Prohibits using `Grant` instruction at runtime.
    /// This means `Grant` instruction will only be used in genesis to specify rights.
    #[derive(Debug, Copy, Clone)]
    pub struct ProhibitGrant;

    impl_from_item_for_grant_instruction_validator_box!(ProhibitGrant);

    impl GrantInstructionValidator for ProhibitGrant {
        fn check_grant(
            &self,
            _authority: &AccountId,
            _instruction: &GrantBox,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            Err("Granting at runtime is prohibited.".to_string())
        }
    }

    pub mod register {
        //! Module with permissions for registering.

        use std::collections::BTreeMap;

        use super::*;

        /// Can register domains permission token name.
        pub const CAN_REGISTER_DOMAINS_TOKEN: &str = "can_register_domains";

        /// Prohibits registering domains.
        #[derive(Debug, Copy, Clone)]
        pub struct ProhibitRegisterDomains;

        impl_from_item_for_validator_box!(ProhibitRegisterDomains);

        impl PermissionsValidator for ProhibitRegisterDomains {
            fn check_instruction(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                _wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let _register_box = if let Instruction::Register(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                Err("Domain registration is prohibited.".to_string())
            }
        }

        /// Validator that allows to register domains for accounts with the corresponding permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedAllowedRegisterDomains;

        impl_from_item_for_granted_token_validator_box!(GrantedAllowedRegisterDomains);

        impl GrantedTokenValidator for GrantedAllowedRegisterDomains {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                _instruction: &Instruction,
                _wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                Ok(PermissionToken::new(
                    CAN_REGISTER_DOMAINS_TOKEN,
                    BTreeMap::new(),
                ))
            }
        }
    }
}

/// Permission checks asociated with use cases that can be summarized as public blockchains.
pub mod public_blockchain {
    use super::*;

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions() -> PermissionsValidatorBox {
        // Grant instruction checks are or unioned, so that if one permission validator approves this Grant it will succeed.
        let grant_instruction_validator = PermissionsValidatorBuilder::new()
            .with_validator(transfer::GrantMyAssetAccess)
            .any_should_succeed("Grant instruction validator.");
        PermissionsValidatorBuilder::new()
            .with_recursive_validator(grant_instruction_validator)
            .with_recursive_validator(transfer::OnlyOwnedAssets.or(transfer::GrantedAssets))
            .with_recursive_validator(unregister::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(mint::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(burn::OnlyOwnedAssets)
            .with_recursive_validator(burn::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(keyvalue::AccountSetOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AccountRemoveOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AssetSetOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AssetRemoveOnlyForSignerAccount)
            .all_should_succeed()
    }

    pub mod transfer {
        //! Module with permission for transfering

        use super::*;

        /// Can transfer user's assets permission token name.
        pub const CAN_TRANSFER_USER_ASSETS_TOKEN: &str = "can_transfer_user_assets";
        /// Origin asset id param for the [`CAN_TRANSFER_USER_ASSETS_TOKEN`] permission.
        pub const ASSET_ID_TOKEN_PARAM_NAME: &str = "asset_id";

        /// Checks that account transfers only the assets that he owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_validator_box!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let transfer_box = if let Instruction::Transfer(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = try_into_or_exit!(source_id);

                if &source_id.account_id != authority {
                    return Err("Can't transfer assets of the other account.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows transfering user's assets from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedAssets;

        impl_from_item_for_granted_token_validator_box!(GrantedAssets);

        impl GrantedTokenValidator for GrantedAssets {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let transfer_box = if let Instruction::Transfer(transfer_box) = instruction {
                    transfer_box
                } else {
                    return Err("Instruction is not transfer.".to_string());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = if let Ok(source_id) = source_id.try_into() {
                    source_id
                } else {
                    return Err("Source id is not an AssetId.".to_string());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_string(), source_id.into());
                Ok(PermissionToken::new(CAN_TRANSFER_USER_ASSETS_TOKEN, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

        impl GrantInstructionValidator for GrantMyAssetAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id = if let Value::Id(IdBox::AssetId(asset_id)) = permission_token
                    .params
                    .get(ASSET_ID_TOKEN_PARAM_NAME)
                    .ok_or(format!(
                        "Failed to find permission param {}.",
                        ASSET_ID_TOKEN_PARAM_NAME
                    ))? {
                    asset_id
                } else {
                    return Err(format!(
                        "Permission param {} is not an AssetId.",
                        ASSET_ID_TOKEN_PARAM_NAME
                    ));
                };
                if &asset_id.account_id != authority {
                    return Err("Can not grant asset access for another account.".to_string());
                }
                Ok(())
            }
        }
    }

    pub mod unregister {
        //! Module with permission for unregistering

        use super::*;

        /// Checks that account can unregister only the assets which were registered by this account in the first place.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Unregister(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_definition_id: AssetDefinitionId = try_into_or_exit!(object_id);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by != authority
                    });

                if low_authority {
                    return Err("Can't unregister assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod mint {
        //! Module with permission for minting

        use super::*;

        /// Checks that account can mint only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Mint(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by != authority
                    });

                if low_authority {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod burn {
        //! Module with permission for burning

        use super::*;

        /// Checks that account can burn only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Burn(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by != authority
                    });
                if low_authority {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Checks that account can burn only the assets that he currently owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_validator_box!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Burn(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);
                if &asset_id.account_id != authority {
                    return Err("Can't burn assets from another account.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod keyvalue {
        //! Module with permission for burning

        use super::*;

        /// Checks that account can set keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetSetOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AssetSetOnlyForSignerAccount);

        impl PermissionsValidator for AssetSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                        Err("Can't set value to asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can set keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountSetOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AccountSetOnlyForSignerAccount);

        impl PermissionsValidator for AccountSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match &object_id {
                    IdBox::AccountId(account_id) if account_id != authority => {
                        Err("Can't set value to account store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can remove keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetRemoveOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AssetRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AssetRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                match object_id {
                    IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                        Err("Can't remove value from asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can remove keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountRemoveOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AccountRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AccountRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AccountId(account_id) if &account_id != authority => Err(
                        "Can't remove value from account store from another account.".to_owned(),
                    ),
                    _ => Ok(()),
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use maplit::{btreemap, btreeset};

        use super::*;

        #[test]
        fn transfer_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let wsv = WorldStateView::new(World::new());
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(&alice_id, &transfer, &wsv)
                .is_ok());
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(&bob_id, &transfer, &wsv)
                .is_err());
        }

        #[test]
        fn transfer_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                btreemap! {
                    transfer::ASSET_ID_TOKEN_PARAM_NAME.to_string() => alice_xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let domains = btreemap! {
                "test".to_string() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            let validator: PermissionsValidatorBox =
                transfer::OnlyOwnedAssets.or(transfer::GrantedAssets).into();
            assert!(validator
                .check_instruction(&alice_id, &transfer, &wsv)
                .is_ok());
            assert!(validator
                .check_instruction(&bob_id, &transfer, &wsv)
                .is_ok());
        }

        #[test]
        fn grant_transfer_of_my_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let permission_token_to_alice = PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                btreemap! {
                    transfer::ASSET_ID_TOKEN_PARAM_NAME.to_string() => alice_xor_id.into(),
                },
            );
            let wsv = WorldStateView::new(World::new());
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            let validator: PermissionsValidatorBox = transfer::GrantMyAssetAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn unregister_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let unregister =
                Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &unregister, &wsv)
                .is_ok());
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &unregister, &wsv)
                .is_err());
        }

        #[test]
        fn mint_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let mint = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &mint, &wsv)
                .is_ok());
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &mint, &wsv)
                .is_err());
        }

        #[test]
        fn burn_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &burn, &wsv)
                .is_ok());
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &burn, &wsv)
                .is_err());
        }

        #[test]
        fn burn_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyOwnedAssets
                .check_instruction(&alice_id, &burn, &wsv)
                .is_ok());
            assert!(burn::OnlyOwnedAssets
                .check_instruction(&bob_id, &burn, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(keyvalue::AssetSetOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(keyvalue::AssetSetOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
            ));
            assert!(keyvalue::AssetRemoveOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(keyvalue::AssetRemoveOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(keyvalue::AccountSetOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(keyvalue::AccountSetOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
            ));
            assert!(keyvalue::AccountRemoveOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(keyvalue::AccountRemoveOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }
    }
}
