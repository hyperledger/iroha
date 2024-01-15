//! Visitor that visits every node in Iroha syntax tree
#![allow(missing_docs, clippy::missing_errors_doc)]

use iroha_crypto::PublicKey;

use crate::{isi::Log, prelude::*};

macro_rules! delegate {
    ( $($visitor:ident $(<$param:ident $(: $bound:path)?>)?($operation:ty)),+ $(,)? ) => { $(
        fn $visitor$(<$param $(: $bound)?>)?(&mut self, authority: &AccountId, operation: $operation) {
            $visitor(self, authority, operation);
        } )+
    };
}

/// Trait to validate Iroha entities.
/// Default implementation of non-leaf visitors runs `visit_` functions for leafs.
/// Default implementation for leaf visitors is blank.
///
/// This trait is based on the visitor pattern.
pub trait Visit {
    delegate! {
        // Visit SignedTransaction
        visit_transaction(&SignedTransaction),
        visit_instruction(&InstructionBox),
        visit_wasm(&WasmSmartContract),
        visit_query(&QueryBox),

        // Visit InstructionBox
        visit_burn(&BurnBox),
        visit_fail(&Fail),
        visit_grant(&GrantBox),
        visit_mint(&MintBox),
        visit_register(&RegisterBox),
        visit_remove_key_value(&RemoveKeyValueBox),
        visit_revoke(&RevokeBox),
        visit_set_key_value(&SetKeyValueBox),
        visit_transfer(&TransferBox),
        visit_unregister(&UnregisterBox),
        visit_upgrade(&Upgrade),

        visit_execute_trigger(&ExecuteTrigger),
        visit_new_parameter(&NewParameter),
        visit_set_parameter(&SetParameter),
        visit_log(&Log),

        // Visit QueryBox
        visit_find_account_by_id(&FindAccountById),
        visit_find_account_key_value_by_id_and_key(&FindAccountKeyValueByIdAndKey),
        visit_find_accounts_by_domain_id(&FindAccountsByDomainId),
        visit_find_accounts_by_name(&FindAccountsByName),
        visit_find_accounts_with_asset(&FindAccountsWithAsset),
        visit_find_all_accounts(&FindAllAccounts),
        visit_find_all_active_trigger_ids(&FindAllActiveTriggerIds),
        visit_find_all_assets(&FindAllAssets),
        visit_find_all_assets_definitions(&FindAllAssetsDefinitions),
        visit_find_all_block_headers(&FindAllBlockHeaders),
        visit_find_all_blocks(&FindAllBlocks),
        visit_find_all_domains(&FindAllDomains),
        visit_find_all_parameters(&FindAllParameters),
        visit_find_all_peers(&FindAllPeers),
        visit_find_permission_token_schema(&FindPermissionTokenSchema),
        visit_find_all_role_ids(&FindAllRoleIds),
        visit_find_all_roles(&FindAllRoles),
        visit_find_all_transactions(&FindAllTransactions),
        visit_find_asset_by_id(&FindAssetById),
        visit_find_asset_definition_by_id(&FindAssetDefinitionById),
        visit_find_asset_definition_key_value_by_id_and_key(&FindAssetDefinitionKeyValueByIdAndKey),
        visit_find_asset_key_value_by_id_and_key(&FindAssetKeyValueByIdAndKey),
        visit_find_asset_quantity_by_id(&FindAssetQuantityById),
        visit_find_assets_by_account_id(&FindAssetsByAccountId),
        visit_find_assets_by_asset_definition_id(&FindAssetsByAssetDefinitionId),
        visit_find_assets_by_domain_id(&FindAssetsByDomainId),
        visit_find_assets_by_domain_id_and_asset_definition_id(&FindAssetsByDomainIdAndAssetDefinitionId),
        visit_find_assets_by_name(&FindAssetsByName),
        visit_find_block_header_by_hash(&FindBlockHeaderByHash),
        visit_find_domain_by_id(&FindDomainById),
        visit_find_domain_key_value_by_id_and_key(&FindDomainKeyValueByIdAndKey),
        visit_find_permission_tokens_by_account_id(&FindPermissionTokensByAccountId),
        visit_find_role_by_role_id(&FindRoleByRoleId),
        visit_find_roles_by_account_id(&FindRolesByAccountId),
        visit_find_total_asset_quantity_by_asset_definition_id(&FindTotalAssetQuantityByAssetDefinitionId),
        visit_find_transaction_by_hash(&FindTransactionByHash),
        visit_find_transactions_by_account_id(&FindTransactionsByAccountId),
        visit_find_trigger_by_id(&FindTriggerById),
        visit_find_trigger_key_value_by_id_and_key(&FindTriggerKeyValueByIdAndKey),
        visit_find_triggers_by_domain_id(&FindTriggersByDomainId),

        // Visit RegisterBox
        visit_register_peer(&Register<Peer>),
        visit_register_domain(&Register<Domain>),
        visit_register_account(&Register<Account>),
        visit_register_asset_definition(&Register<AssetDefinition>),
        visit_register_asset(&Register<Asset>),
        visit_register_role(&Register<Role>),
        visit_register_trigger(&Register<Trigger<TriggeringFilterBox>>),

        // Visit UnregisterBox
        visit_unregister_peer(&Unregister<Peer>),
        visit_unregister_domain(&Unregister<Domain>),
        visit_unregister_account(&Unregister<Account>),
        visit_unregister_asset_definition(&Unregister<AssetDefinition>),
        visit_unregister_asset(&Unregister<Asset>),
        // TODO: Need to allow role creator to unregister it somehow
        visit_unregister_role(&Unregister<Role>),
        visit_unregister_trigger(&Unregister<Trigger<TriggeringFilterBox>>),

        // Visit MintBox
        visit_mint_asset_quantity(&Mint<u32, Asset>),
        visit_mint_asset_big_quantity(&Mint<u128, Asset>),
        visit_mint_asset_fixed(&Mint<Fixed, Asset>),
        visit_mint_account_public_key(&Mint<PublicKey, Account>),
        visit_mint_account_signature_check_condition(&Mint<SignatureCheckCondition, Account>),
        visit_mint_trigger_repetitions(&Mint<u32, Trigger<TriggeringFilterBox>>),

        // Visit BurnBox
        visit_burn_account_public_key(&Burn<PublicKey, Account>),
        visit_burn_asset_quantity(&Burn<u32, Asset>),
        visit_burn_asset_big_quantity(&Burn<u128, Asset>),
        visit_burn_asset_fixed(&Burn<Fixed, Asset>),
        visit_burn_trigger_repetitions(&Burn<u32, Trigger<TriggeringFilterBox>>),

        // Visit TransferBox
        visit_transfer_asset_definition(&Transfer<Account, AssetDefinitionId, Account>),
        visit_transfer_asset_quantity(&Transfer<Asset, u32, Account>),
        visit_transfer_asset_big_quantity(&Transfer<Asset, u128, Account>),
        visit_transfer_asset_fixed(&Transfer<Asset, Fixed, Account>),
        visit_transfer_domain(&Transfer<Account, DomainId, Account>),

        // Visit SetKeyValueBox
        visit_set_domain_key_value(&SetKeyValue<Domain>),
        visit_set_account_key_value(&SetKeyValue<Account>),
        visit_set_asset_definition_key_value(&SetKeyValue<AssetDefinition>),
        visit_set_asset_key_value(&SetKeyValue<Asset>),

        // Visit RemoveKeyValueBox
        visit_remove_domain_key_value(&RemoveKeyValue<Domain>),
        visit_remove_account_key_value(&RemoveKeyValue<Account>),
        visit_remove_asset_definition_key_value(&RemoveKeyValue<AssetDefinition>),
        visit_remove_asset_key_value(&RemoveKeyValue<Asset>),

        // Visit GrantBox
        visit_grant_account_permission(&Grant<PermissionToken>),
        visit_grant_account_role(&Grant<RoleId>),

        // Visit RevokeBox
        visit_revoke_account_permission(&Revoke<PermissionToken>),
        visit_revoke_account_role(&Revoke<RoleId>),
    }
}

pub fn visit_transaction<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    transaction: &SignedTransaction,
) {
    match transaction.payload().instructions() {
        Executable::Wasm(wasm) => visitor.visit_wasm(authority, wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                visitor.visit_instruction(authority, isi);
            }
        }
    }
}

/// Default validation for [`QueryBox`].
pub fn visit_query<V: Visit + ?Sized>(visitor: &mut V, authority: &AccountId, query: &QueryBox) {
    macro_rules! query_visitors {
        ( $($visitor:ident($query:ident)),+ $(,)? ) => {
            match query { $(
                QueryBox::$query(query) => visitor.$visitor(authority, &query), )+
            }
        };
    }

    query_visitors! {
        visit_find_account_by_id(FindAccountById),
        visit_find_account_key_value_by_id_and_key(FindAccountKeyValueByIdAndKey),
        visit_find_accounts_by_domain_id(FindAccountsByDomainId),
        visit_find_accounts_by_name(FindAccountsByName),
        visit_find_accounts_with_asset(FindAccountsWithAsset),
        visit_find_all_accounts(FindAllAccounts),
        visit_find_all_active_trigger_ids(FindAllActiveTriggerIds),
        visit_find_all_assets(FindAllAssets),
        visit_find_all_assets_definitions(FindAllAssetsDefinitions),
        visit_find_all_block_headers(FindAllBlockHeaders),
        visit_find_all_blocks(FindAllBlocks),
        visit_find_all_domains(FindAllDomains),
        visit_find_all_parameters(FindAllParameters),
        visit_find_all_peers(FindAllPeers),
        visit_find_permission_token_schema(FindPermissionTokenSchema),
        visit_find_all_role_ids(FindAllRoleIds),
        visit_find_all_roles(FindAllRoles),
        visit_find_all_transactions(FindAllTransactions),
        visit_find_asset_by_id(FindAssetById),
        visit_find_asset_definition_by_id(FindAssetDefinitionById),
        visit_find_asset_definition_key_value_by_id_and_key(FindAssetDefinitionKeyValueByIdAndKey),
        visit_find_asset_key_value_by_id_and_key(FindAssetKeyValueByIdAndKey),
        visit_find_asset_quantity_by_id(FindAssetQuantityById),
        visit_find_assets_by_account_id(FindAssetsByAccountId),
        visit_find_assets_by_asset_definition_id(FindAssetsByAssetDefinitionId),
        visit_find_assets_by_domain_id(FindAssetsByDomainId),
        visit_find_assets_by_domain_id_and_asset_definition_id(FindAssetsByDomainIdAndAssetDefinitionId),
        visit_find_assets_by_name(FindAssetsByName),
        visit_find_block_header_by_hash(FindBlockHeaderByHash),
        visit_find_domain_by_id(FindDomainById),
        visit_find_domain_key_value_by_id_and_key(FindDomainKeyValueByIdAndKey),
        visit_find_permission_tokens_by_account_id(FindPermissionTokensByAccountId),
        visit_find_role_by_role_id(FindRoleByRoleId),
        visit_find_roles_by_account_id(FindRolesByAccountId),
        visit_find_total_asset_quantity_by_asset_definition_id(FindTotalAssetQuantityByAssetDefinitionId),
        visit_find_transaction_by_hash(FindTransactionByHash),
        visit_find_transactions_by_account_id(FindTransactionsByAccountId),
        visit_find_trigger_by_id(FindTriggerById),
        visit_find_trigger_key_value_by_id_and_key(FindTriggerKeyValueByIdAndKey),
        visit_find_triggers_by_domain_id(FindTriggersByDomainId),
    }
}

pub fn visit_wasm<V: Visit + ?Sized>(
    _visitor: &mut V,
    _authority: &AccountId,
    _wasm: &WasmSmartContract,
) {
}

/// Default validation for [`InstructionBox`].
///
/// # Warning
///
/// Instruction is executed following successful validation
pub fn visit_instruction<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &InstructionBox,
) {
    match isi {
        InstructionBox::NewParameter(variant_value) => {
            visitor.visit_new_parameter(authority, variant_value)
        }
        InstructionBox::SetParameter(variant_value) => {
            visitor.visit_set_parameter(authority, variant_value)
        }
        InstructionBox::ExecuteTrigger(variant_value) => {
            visitor.visit_execute_trigger(authority, variant_value)
        }
        InstructionBox::Log(variant_value) => visitor.visit_log(authority, variant_value),
        InstructionBox::Burn(variant_value) => visitor.visit_burn(authority, variant_value),
        InstructionBox::Fail(variant_value) => visitor.visit_fail(authority, variant_value),
        InstructionBox::Grant(variant_value) => visitor.visit_grant(authority, variant_value),
        InstructionBox::Mint(variant_value) => visitor.visit_mint(authority, variant_value),
        InstructionBox::Register(variant_value) => visitor.visit_register(authority, variant_value),
        InstructionBox::RemoveKeyValue(variant_value) => {
            visitor.visit_remove_key_value(authority, variant_value)
        }
        InstructionBox::Revoke(variant_value) => visitor.visit_revoke(authority, variant_value),
        InstructionBox::SetKeyValue(variant_value) => {
            visitor.visit_set_key_value(authority, variant_value)
        }
        InstructionBox::Transfer(variant_value) => visitor.visit_transfer(authority, variant_value),
        InstructionBox::Unregister(variant_value) => {
            visitor.visit_unregister(authority, variant_value)
        }
        InstructionBox::Upgrade(variant_value) => visitor.visit_upgrade(authority, variant_value),
    }
}

pub fn visit_register<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &RegisterBox,
) {
    match isi {
        RegisterBox::Peer(obj) => visitor.visit_register_peer(authority, obj),
        RegisterBox::Domain(obj) => visitor.visit_register_domain(authority, obj),
        RegisterBox::Account(obj) => visitor.visit_register_account(authority, obj),
        RegisterBox::AssetDefinition(obj) => {
            visitor.visit_register_asset_definition(authority, obj)
        }
        RegisterBox::Asset(obj) => visitor.visit_register_asset(authority, obj),
        RegisterBox::Role(obj) => visitor.visit_register_role(authority, obj),
        RegisterBox::Trigger(obj) => visitor.visit_register_trigger(authority, obj),
    }
}

pub fn visit_unregister<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &UnregisterBox,
) {
    match isi {
        UnregisterBox::Peer(obj) => visitor.visit_unregister_peer(authority, obj),
        UnregisterBox::Domain(obj) => visitor.visit_unregister_domain(authority, obj),
        UnregisterBox::Account(obj) => visitor.visit_unregister_account(authority, obj),
        UnregisterBox::AssetDefinition(obj) => {
            visitor.visit_unregister_asset_definition(authority, obj)
        }
        UnregisterBox::Asset(obj) => visitor.visit_unregister_asset(authority, obj),
        UnregisterBox::Role(obj) => visitor.visit_unregister_role(authority, obj),
        UnregisterBox::Trigger(obj) => visitor.visit_unregister_trigger(authority, obj),
    }
}

pub fn visit_mint<V: Visit + ?Sized>(visitor: &mut V, authority: &AccountId, isi: &MintBox) {
    match isi {
        MintBox::Account(mint_account) => match mint_account {
            AccountMintBox::PublicKey(obj) => visitor.visit_mint_account_public_key(authority, obj),
            AccountMintBox::SignatureCheckCondition(obj) => {
                visitor.visit_mint_account_signature_check_condition(authority, obj)
            }
        },
        MintBox::Asset(mint_asset) => match mint_asset {
            AssetMintBox::Quantity(obj) => visitor.visit_mint_asset_quantity(authority, obj),
            AssetMintBox::BigQuantity(obj) => visitor.visit_mint_asset_big_quantity(authority, obj),
            AssetMintBox::Fixed(obj) => visitor.visit_mint_asset_fixed(authority, obj),
        },
        MintBox::TriggerRepetitions(obj) => visitor.visit_mint_trigger_repetitions(authority, obj),
    }
}

pub fn visit_burn<V: Visit + ?Sized>(visitor: &mut V, authority: &AccountId, isi: &BurnBox) {
    match isi {
        BurnBox::AccountPublicKey(obj) => visitor.visit_burn_account_public_key(authority, obj),
        BurnBox::Asset(burn_asset) => match burn_asset {
            AssetBurnBox::Quantity(obj) => visitor.visit_burn_asset_quantity(authority, obj),
            AssetBurnBox::BigQuantity(obj) => visitor.visit_burn_asset_big_quantity(authority, obj),
            AssetBurnBox::Fixed(obj) => visitor.visit_burn_asset_fixed(authority, obj),
        },
        BurnBox::TriggerRepetitions(obj) => visitor.visit_burn_trigger_repetitions(authority, obj),
    }
}

pub fn visit_transfer<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &TransferBox,
) {
    match isi {
        TransferBox::Domain(obj) => visitor.visit_transfer_domain(authority, obj),
        TransferBox::AssetDefinition(obj) => {
            visitor.visit_transfer_asset_definition(authority, obj)
        }
        TransferBox::Asset(transfer_asset) => match transfer_asset {
            AssetTransferBox::Quantity(obj) => {
                visitor.visit_transfer_asset_quantity(authority, obj)
            }
            AssetTransferBox::BigQuantity(obj) => {
                visitor.visit_transfer_asset_big_quantity(authority, obj)
            }
            AssetTransferBox::Fixed(obj) => visitor.visit_transfer_asset_fixed(authority, obj),
        },
    }
}

pub fn visit_set_key_value<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &SetKeyValueBox,
) {
    match isi {
        SetKeyValueBox::Domain(obj) => visitor.visit_set_domain_key_value(authority, obj),
        SetKeyValueBox::Account(obj) => visitor.visit_set_account_key_value(authority, obj),
        SetKeyValueBox::AssetDefinition(obj) => {
            visitor.visit_set_asset_definition_key_value(authority, obj)
        }
        SetKeyValueBox::Asset(obj) => visitor.visit_set_asset_key_value(authority, obj),
    }
}

pub fn visit_remove_key_value<V: Visit + ?Sized>(
    visitor: &mut V,
    authority: &AccountId,
    isi: &RemoveKeyValueBox,
) {
    match isi {
        RemoveKeyValueBox::Domain(obj) => visitor.visit_remove_domain_key_value(authority, obj),
        RemoveKeyValueBox::Account(obj) => visitor.visit_remove_account_key_value(authority, obj),
        RemoveKeyValueBox::AssetDefinition(obj) => {
            visitor.visit_remove_asset_definition_key_value(authority, obj)
        }
        RemoveKeyValueBox::Asset(obj) => visitor.visit_remove_asset_key_value(authority, obj),
    }
}

pub fn visit_grant<V: Visit + ?Sized>(visitor: &mut V, authority: &AccountId, isi: &GrantBox) {
    match isi {
        GrantBox::PermissionToken(obj) => visitor.visit_grant_account_permission(authority, obj),
        GrantBox::Role(obj) => visitor.visit_grant_account_role(authority, obj),
    }
}

pub fn visit_revoke<V: Visit + ?Sized>(visitor: &mut V, authority: &AccountId, isi: &RevokeBox) {
    match isi {
        RevokeBox::PermissionToken(obj) => visitor.visit_revoke_account_permission(authority, obj),
        RevokeBox::Role(obj) => visitor.visit_revoke_account_role(authority, obj),
    }
}

macro_rules! leaf_visitors {
    ( $($visitor:ident($operation:ty)),+ $(,)? ) => { $(
        pub fn $visitor<V: Visit + ?Sized>(_visitor: &mut V, _authority: &AccountId, _operation: $operation) {

        } )+
    };
}

leaf_visitors! {
    // Instruction visitors
    visit_register_account(&Register<Account>),
    visit_unregister_account(&Unregister<Account>),
    visit_mint_account_public_key(&Mint<PublicKey, Account>),
    visit_burn_account_public_key(&Burn<PublicKey, Account>),
    visit_mint_account_signature_check_condition(&Mint<SignatureCheckCondition, Account>),
    visit_set_account_key_value(&SetKeyValue<Account>),
    visit_remove_account_key_value(&RemoveKeyValue<Account>),
    visit_register_asset(&Register<Asset>),
    visit_unregister_asset(&Unregister<Asset>),
    visit_mint_asset_quantity(&Mint<u32, Asset>),
    visit_burn_asset_quantity(&Burn<u32, Asset>),
    visit_mint_asset_big_quantity(&Mint<u128, Asset>),
    visit_burn_asset_big_quantity(&Burn<u128, Asset>),
    visit_mint_asset_fixed(&Mint<Fixed, Asset>),
    visit_burn_asset_fixed(&Burn<Fixed, Asset>),
    visit_transfer_asset_quantity(&Transfer<Asset, u32, Account>),
    visit_transfer_asset_big_quantity(&Transfer<Asset, u128, Account>),
    visit_transfer_asset_fixed(&Transfer<Asset, Fixed, Account>),
    visit_set_asset_key_value(&SetKeyValue<Asset>),
    visit_remove_asset_key_value(&RemoveKeyValue<Asset>),
    visit_register_asset_definition(&Register<AssetDefinition>),
    visit_unregister_asset_definition(&Unregister<AssetDefinition>),
    visit_transfer_asset_definition(&Transfer<Account, AssetDefinitionId, Account>),
    visit_set_asset_definition_key_value(&SetKeyValue<AssetDefinition>),
    visit_remove_asset_definition_key_value(&RemoveKeyValue<AssetDefinition>),
    visit_register_domain(&Register<Domain>),
    visit_unregister_domain(&Unregister<Domain>),
    visit_transfer_domain(&Transfer<Account, DomainId, Account>),
    visit_set_domain_key_value(&SetKeyValue<Domain>),
    visit_remove_domain_key_value(&RemoveKeyValue<Domain>),
    visit_register_peer(&Register<Peer>),
    visit_unregister_peer(&Unregister<Peer>),
    visit_grant_account_permission(&Grant<PermissionToken>),
    visit_revoke_account_permission(&Revoke<PermissionToken>),
    visit_register_role(&Register<Role>),
    visit_unregister_role(&Unregister<Role>),
    visit_grant_account_role(&Grant<RoleId>),
    visit_revoke_account_role(&Revoke<RoleId>),
    visit_register_trigger(&Register<Trigger<TriggeringFilterBox>>),
    visit_unregister_trigger(&Unregister<Trigger<TriggeringFilterBox>>),
    visit_mint_trigger_repetitions(&Mint<u32, Trigger<TriggeringFilterBox>>),
    visit_burn_trigger_repetitions(&Burn<u32, Trigger<TriggeringFilterBox>>),
    visit_upgrade(&Upgrade),
    visit_new_parameter(&NewParameter),
    visit_set_parameter(&SetParameter),
    visit_execute_trigger(&ExecuteTrigger),
    visit_fail(&Fail),
    visit_log(&Log),

    // Query visitors
    visit_find_account_by_id(&FindAccountById),
    visit_find_account_key_value_by_id_and_key(&FindAccountKeyValueByIdAndKey),
    visit_find_accounts_by_domain_id(&FindAccountsByDomainId),
    visit_find_accounts_by_name(&FindAccountsByName),
    visit_find_accounts_with_asset(&FindAccountsWithAsset),
    visit_find_all_accounts(&FindAllAccounts),
    visit_find_all_active_trigger_ids(&FindAllActiveTriggerIds),
    visit_find_all_assets(&FindAllAssets),
    visit_find_all_assets_definitions(&FindAllAssetsDefinitions),
    visit_find_all_block_headers(&FindAllBlockHeaders),
    visit_find_all_blocks(&FindAllBlocks),
    visit_find_all_domains(&FindAllDomains),
    visit_find_all_parameters(&FindAllParameters),
    visit_find_all_peers(&FindAllPeers),
    visit_find_permission_token_schema(&FindPermissionTokenSchema),
    visit_find_all_role_ids(&FindAllRoleIds),
    visit_find_all_roles(&FindAllRoles),
    visit_find_all_transactions(&FindAllTransactions),
    visit_find_asset_by_id(&FindAssetById),
    visit_find_asset_definition_by_id(&FindAssetDefinitionById),
    visit_find_asset_definition_key_value_by_id_and_key(&FindAssetDefinitionKeyValueByIdAndKey),
    visit_find_asset_key_value_by_id_and_key(&FindAssetKeyValueByIdAndKey),
    visit_find_asset_quantity_by_id(&FindAssetQuantityById),
    visit_find_assets_by_account_id(&FindAssetsByAccountId),
    visit_find_assets_by_asset_definition_id(&FindAssetsByAssetDefinitionId),
    visit_find_assets_by_domain_id(&FindAssetsByDomainId),
    visit_find_assets_by_domain_id_and_asset_definition_id(&FindAssetsByDomainIdAndAssetDefinitionId),
    visit_find_assets_by_name(&FindAssetsByName),
    visit_find_block_header_by_hash(&FindBlockHeaderByHash),
    visit_find_domain_by_id(&FindDomainById),
    visit_find_domain_key_value_by_id_and_key(&FindDomainKeyValueByIdAndKey),
    visit_find_permission_tokens_by_account_id(&FindPermissionTokensByAccountId),
    visit_find_role_by_role_id(&FindRoleByRoleId),
    visit_find_roles_by_account_id(&FindRolesByAccountId),
    visit_find_total_asset_quantity_by_asset_definition_id(&FindTotalAssetQuantityByAssetDefinitionId),
    visit_find_transaction_by_hash(&FindTransactionByHash),
    visit_find_transactions_by_account_id(&FindTransactionsByAccountId),
    visit_find_trigger_by_id(&FindTriggerById),
    visit_find_trigger_key_value_by_id_and_key(&FindTriggerKeyValueByIdAndKey),
    visit_find_triggers_by_domain_id(&FindTriggersByDomainId),
}
