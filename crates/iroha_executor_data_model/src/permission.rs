//! Definition of Iroha default permission tokens.
//!
//! Exact tokens are normally delegable capabilities unless their type is a genesis-only bootstrap
//! root. Exact asset-definition-alias tokens are deliberately different: their grant lifecycle is
//! rooted in the active asset owner and alias namespace, not possession of the leaf token.
//! Resource-scoped tokens may also define a native use-time ownership root or an explicit wider
//! parent token; ownership of an adjacent component of the scope is never sufficient.
#![allow(clippy::missing_errors_doc)]
use iroha_data_model::prelude::*;
pub use iroha_executor_data_model_derive::Permission;
use iroha_model_base::name::Name;
use iroha_schema::{Ident, IntoSchema};
use norito::json::{JsonDeserializeOwned, JsonSerialize};
use std::{format, string::String, vec::Vec};
/// Used to check if the permission token is owned by the account.
pub trait Permission: JsonSerialize + JsonDeserializeOwned + IntoSchema {
    /// Permission id, according to [`IntoSchema`].
    fn name() -> Ident {
        Self::type_name()
    }
}
macro_rules! permission {
    ($item:item) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Permission,
            crate::json_macros::JsonSerialize,
            crate::json_macros::JsonDeserialize,
            iroha_schema::IntoSchema,
        )]
        $item
    };
}
/// Permission tokens related to peer management.
pub mod peer {
    use super::*;
    permission! {
        /// Permission allowing the peer manager to add or remove peers.
        #[derive(Copy)]
        pub struct CanManagePeers;
    }
}
/// Permission tokens scoped to domains.
pub mod domain {
    use super::*;
    use iroha_model_base::domain::DomainId;
    permission! {
        /// Permission to register a new domain.
        #[derive(Copy)]
        pub struct CanRegisterDomain;
    }
    permission! {
        /// Permission to unregister the specified domain.
        pub struct CanUnregisterDomain {
            /// Domain identifier governed by this permission.
            pub domain: DomainId,
        }
    }
    permission! {
        /// Permission to modify metadata for the specified domain.
        pub struct CanModifyDomainMetadata {
            /// Domain identifier whose metadata may be changed.
            pub domain: DomainId,
        }
    }
}
/// Permission tokens scoped to asset definitions.
pub mod asset_definition {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    /// Scope carried by asset-definition-alias management permissions.
    #[derive(Debug, Clone, PartialEq, Eq, iroha_schema::IntoSchema)]
    #[allow(variant_size_differences)]
    #[norito(tag = "scope", content = "value", rename_all = "snake_case")]
    pub enum AssetDefinitionAliasPermissionScope {
        /// Permission scoped to a specific dataspace-qualified domain.
        Domain(DomainId),
        /// Permission scoped to a dataspace-root alias namespace.
        Dataspace(DataSpaceId),
        /// Permission scoped to one catalog-pinned alias and exact asset definition.
        Alias(ResolvedAssetDefinitionAliasV1),
    }
    impl norito::json::JsonSerialize for AssetDefinitionAliasPermissionScope {
        fn json_serialize(&self, out: &mut String) {
            out.push_str("{\"scope\":\"");
            match self {
                Self::Domain(value) => {
                    out.push_str("domain\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
                Self::Dataspace(value) => {
                    out.push_str("dataspace\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
                Self::Alias(value) => {
                    out.push_str("alias\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
            }
            out.push('}');
        }
    }
    impl norito::json::JsonDeserialize for AssetDefinitionAliasPermissionScope {
        fn json_deserialize(p: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
            let value =
                <norito::json::Value as norito::json::JsonDeserialize>::json_deserialize(p)?;
            Self::json_from_value(&value)
        }
        fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
            let object = value.as_object().ok_or_else(|| {
                norito::json::Error::Message(
                    "expected asset-definition alias permission scope object".into(),
                )
            })?;
            let scope = object
                .get("scope")
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| {
                    norito::json::Error::Message(
                        "missing asset-definition alias permission scope discriminator".into(),
                    )
                })?;
            let value = object.get("value").ok_or_else(|| {
                norito::json::Error::Message(
                    "missing asset-definition alias permission scope value".into(),
                )
            })?;
            match scope {
                "domain" => Ok(Self::Domain(
                    <DomainId as norito::json::JsonDeserialize>::json_from_value(value)?,
                )),
                "dataspace" => Ok(Self::Dataspace(
                    <DataSpaceId as norito::json::JsonDeserialize>::json_from_value(value)?,
                )),
                "alias" => Ok(Self::Alias(
                    <ResolvedAssetDefinitionAliasV1 as norito::json::JsonDeserialize>::json_from_value(value)?,
                )),
                other => Err(norito::json::Error::Message(format!(
                    "unknown asset-definition alias permission scope `{other}`"
                ))),
            }
        }
    }
    permission! {
        /// Permission to unregister the specified asset definition.
        pub struct CanUnregisterAssetDefinition {
            /// Identifier of the asset definition targeted by the permission.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to modify metadata for the specified asset definition.
        pub struct CanModifyAssetDefinitionMetadata {
            /// Identifier of the asset definition whose metadata may be changed.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to register a KAGEMUSHA scheme reserve for this asset definition.
        /// The registering authority must also be the reserve account; this token cannot
        /// capture another account's balance. Registration is permanent.
        pub struct CanManageKagemushaWallet {
            /// Exact governed asset definition.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to manage confidential policy and verifier roles for the specified asset definition.
        pub struct CanManageAssetDefinitionConfidentialPolicy {
            /// Identifier of the asset definition whose confidential policy may be changed.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to register, bind, clear, or replace asset-definition aliases in one scope.
        ///
        /// This capability is intentionally independent from account-alias management.
        pub struct CanManageAssetDefinitionAlias {
            /// Asset-definition alias namespace governed by this permission.
            pub scope: AssetDefinitionAliasPermissionScope,
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use iroha_schema::{IntoSchema, Metadata};
        #[test]
        fn asset_alias_scope_serializes_as_snake_case() {
            let json = norito::json::to_json(&AssetDefinitionAliasPermissionScope::Dataspace(
                DataSpaceId::UNIVERSAL,
            ))
            .expect("serialize asset alias scope");
            assert_eq!(json, "{\"scope\":\"dataspace\",\"value\":0}");
        }
        #[test]
        fn asset_alias_scope_schema_uses_independent_tags() {
            let schema = AssetDefinitionAliasPermissionScope::schema();
            let Some(Metadata::Enum(meta)) = schema.get::<AssetDefinitionAliasPermissionScope>()
            else {
                panic!("asset alias scope schema must be an enum");
            };
            let tags = meta
                .variants
                .iter()
                .map(|variant| variant.tag.as_str())
                .collect::<Vec<_>>();
            assert_eq!(tags, vec!["domain", "dataspace", "alias"]);
        }
        #[test]
        fn exact_asset_alias_scope_roundtrips() {
            let scope =
                AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
                    "usd#banka.paynet"
                        .parse()
                        .expect("canonical asset-definition alias"),
                    DataSpaceId::new(7),
                    AssetDefinitionId::derive_from_components(
                        DomainId::try_new("banka", "paynet").expect("domain"),
                        "usd".parse().expect("asset name"),
                    ),
                ));
            let json = norito::json::to_json(&scope).expect("serialize exact asset alias scope");
            let decoded: AssetDefinitionAliasPermissionScope =
                norito::json::from_str(&json).expect("deserialize exact asset alias scope");
            assert_eq!(decoded, scope);
            assert!(json.contains("usd#banka.paynet"));
            assert!(json.contains("\"dataspace_id\":7"));
            assert!(json.contains("\"asset_definition_id\""));
        }
        #[test]
        fn confidential_policy_permission_is_exactly_asset_definition_scoped() {
            let pkr = AssetDefinitionId::derive_from_components(
                DomainId::try_new("currency", "paynet").expect("asset domain"),
                "pkr".parse().expect("asset name"),
            );
            let usd = AssetDefinitionId::derive_from_components(
                DomainId::try_new("currency", "paynet").expect("asset domain"),
                "usd".parse().expect("asset name"),
            );
            let permission = CanManageAssetDefinitionConfidentialPolicy {
                asset_definition: pkr.clone(),
            };
            let json = norito::json::to_json(&permission)
                .expect("serialize confidential policy permission");
            let decoded: CanManageAssetDefinitionConfidentialPolicy =
                norito::json::from_str(&json).expect("deserialize confidential policy permission");
            assert_eq!(decoded, permission);
            assert_eq!(decoded.asset_definition, pkr);
            assert_ne!(decoded.asset_definition, usd);
        }
    }
}
/// Permission tokens scoped to accounts.
pub mod account {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    /// Scope carried by account-alias permissions.
    #[derive(Debug, Clone, PartialEq, Eq, iroha_schema::IntoSchema)]
    #[allow(variant_size_differences)]
    #[norito(tag = "scope", content = "value", rename_all = "snake_case")]
    pub enum AccountAliasPermissionScope {
        /// Permission scoped to a specific dataspace-qualified domain.
        Domain(DomainId),
        /// Permission scoped to a dataspace alias segment.
        Dataspace(DataSpaceId),
        /// Permission scoped to one exact resolved account alias.
        Alias(ResolvedAccountAliasV1),
    }
    impl norito::json::JsonSerialize for AccountAliasPermissionScope {
        fn json_serialize(&self, out: &mut String) {
            out.push_str("{\"scope\":\"");
            match self {
                Self::Domain(value) => {
                    out.push_str("domain\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
                Self::Dataspace(value) => {
                    out.push_str("dataspace\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
                Self::Alias(value) => {
                    out.push_str("alias\",\"value\":");
                    norito::json::JsonSerialize::json_serialize(value, out);
                }
            }
            out.push('}');
        }
    }
    impl norito::json::JsonDeserialize for AccountAliasPermissionScope {
        fn json_deserialize(p: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
            let value =
                <norito::json::Value as norito::json::JsonDeserialize>::json_deserialize(p)?;
            Self::json_from_value(&value)
        }
        fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
            let object = value.as_object().ok_or_else(|| {
                norito::json::Error::Message("expected alias permission scope object".into())
            })?;
            let scope = object
                .get("scope")
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| {
                    norito::json::Error::Message(
                        "missing alias permission scope discriminator".into(),
                    )
                })?;
            let value = object.get("value").ok_or_else(|| {
                norito::json::Error::Message("missing alias permission scope value".into())
            })?;
            match scope {
                "domain" => Ok(Self::Domain(
                    <DomainId as norito::json::JsonDeserialize>::json_from_value(value)?,
                )),
                "dataspace" => Ok(Self::Dataspace(
                    <DataSpaceId as norito::json::JsonDeserialize>::json_from_value(value)?,
                )),
                "alias" => Ok(Self::Alias(
                    <ResolvedAccountAliasV1 as norito::json::JsonDeserialize>::json_from_value(
                        value,
                    )?,
                )),
                other => Err(norito::json::Error::Message(format!(
                    "unknown alias permission scope `{other}`"
                ))),
            }
        }
    }
    permission! {
        /// Permission to register an account within the provided domain.
        pub struct CanRegisterAccount {
            /// Domain in which the account may be registered.
            pub domain: DomainId,
        }
    }
    permission! {
        /// Permission to unregister the specified account.
        pub struct CanUnregisterAccount {
            /// Identifier of the account targeted by the permission.
            pub account: AccountId,
        }
    }
    permission! {
        /// Permission to modify metadata for the specified account.
        pub struct CanModifyAccountMetadata {
            /// Identifier of the account whose metadata may be changed.
            pub account: AccountId,
        }
    }
    permission! {
        /// Permission to replace the controller for the specified account.
        pub struct CanReplaceAccountController {
            /// Identifier of the account whose controller may be replaced.
            pub account: AccountId,
        }
    }
    permission! {
        /// Permission to resolve account aliases in the specified scope.
        ///
        /// An alias scope authorizes one exact alias. A domain scope authorizes only that
        /// fully-qualified domain, while a dataspace scope authorizes only dataspace-root aliases;
        /// the three scope kinds are independent. Exact possession authorizes resolution only;
        /// delegation remains controlled by the matching [`CanDelegateAccountAliasResolution`]
        /// token or the scope owner.
        pub struct CanResolveAccountAlias {
            /// Alias permission scope.
            pub scope: AccountAliasPermissionScope,
        }
    }
    permission! {
        /// Permission to grant or revoke alias-resolution access in the specified scope.
        ///
        /// Only the corresponding alias, domain, or dataspace-alias owner may grant or
        /// revoke this delegation token. Holding it authorizes delegation of
        /// [`CanResolveAccountAlias`] and further delegation of this token for the exact same
        /// scope; it never authorizes alias mutation or delegation to a wider scope.
        pub struct CanDelegateAccountAliasResolution {
            /// Exact alias scope whose resolution access may be delegated.
            pub scope: AccountAliasPermissionScope,
        }
    }
    permission! {
        /// Permission to register, bind, or update account aliases in the specified scope.
        pub struct CanManageAccountAlias {
            /// Alias permission scope.
            pub scope: AccountAliasPermissionScope,
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use iroha_schema::{IntoSchema, Metadata};
        #[test]
        fn alias_scope_serializes_as_snake_case() {
            let json = norito::json::to_json(&AccountAliasPermissionScope::Dataspace(
                DataSpaceId::UNIVERSAL,
            ))
            .expect("serialize alias scope");
            assert_eq!(json, "{\"scope\":\"dataspace\",\"value\":0}");
        }
        #[test]
        fn alias_scope_deserializes_snake_case() {
            let scope: AccountAliasPermissionScope =
                norito::json::from_str("{\"scope\":\"dataspace\",\"value\":0}")
                    .expect("deserialize alias scope");
            assert_eq!(
                scope,
                AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL)
            );
        }
        #[test]
        fn alias_scope_schema_uses_snake_case_tags() {
            let schema = AccountAliasPermissionScope::schema();
            let Some(Metadata::Enum(meta)) = schema.get::<AccountAliasPermissionScope>() else {
                panic!("alias scope schema must be an enum");
            };
            let tags = meta
                .variants
                .iter()
                .map(|variant| variant.tag.as_str())
                .collect::<Vec<_>>();
            assert_eq!(tags, vec!["domain", "dataspace", "alias"]);
        }
        #[test]
        fn alias_scope_roundtrips_exact_resolved_alias() {
            let scope = AccountAliasPermissionScope::Alias(ResolvedAccountAliasV1::new(
                "merchant@banka.paynet"
                    .parse::<AccountAliasName>()
                    .expect("canonical account alias"),
                DataSpaceId::new(7),
            ));
            let json = norito::json::to_json(&scope).expect("serialize exact alias scope");
            let decoded: AccountAliasPermissionScope =
                norito::json::from_str(&json).expect("deserialize exact alias scope");
            assert_eq!(decoded, scope);
            assert!(json.contains("merchant"));
            assert!(json.contains("\"dataspace_id\":7"));
        }
        #[test]
        fn exact_alias_scope_matches_shared_alias_setup_fixture() {
            use norito::json::JsonDeserialize;
            let fixture: norito::json::Value = norito::json::from_str(include_str!(
                "../../../fixtures/norito_rpc/alias_setup_v1/alias_setup_v1.json"
            ))
            .expect("decode shared alias setup fixture");
            let raw_scope = fixture
                .as_object()
                .and_then(|object| object.get("permission_scope_json_vector"))
                .expect("shared exact alias permission scope");
            let scope = AccountAliasPermissionScope::json_from_value(raw_scope)
                .expect("decode shared exact alias permission scope");
            let expected = AccountAliasPermissionScope::Alias(ResolvedAccountAliasV1::new(
                "merchant@banka.paynet"
                    .parse::<AccountAliasName>()
                    .expect("canonical account alias"),
                DataSpaceId::new(7),
            ));
            assert_eq!(scope, expected);
            let encoded = norito::json::to_json(&scope).expect("encode shared exact alias scope");
            let encoded: norito::json::Value =
                norito::json::from_str(&encoded).expect("decode encoded exact alias scope");
            assert_eq!(&encoded, raw_scope);
        }
        #[test]
        fn alias_resolution_delegation_roundtrips_with_an_exact_scope() {
            let permission = CanDelegateAccountAliasResolution {
                scope: AccountAliasPermissionScope::Domain(
                    DomainId::try_new("hbl", "sbp").expect("canonical HBL domain"),
                ),
            };
            let encoded = norito::json::to_json(&permission)
                .expect("serialize alias-resolution delegation permission");
            let decoded: CanDelegateAccountAliasResolution = norito::json::from_str(&encoded)
                .expect("deserialize alias-resolution delegation permission");
            assert_eq!(decoded, permission);
            assert!(encoded.contains("hbl.sbp"));
        }
    }
}
/// Permission tokens governing reads from ledger state.
pub mod query {
    use super::*;
    use iroha_model_base::topology::DataSpaceId;
    permission! {
        /// Permission to read ledger-wide state, including account rosters,
        /// balances, transactions, blocks, and other global records.
        ///
        /// This is a genesis-issued root capability. Account-scoped data should
        /// use [`CanReadAccountData`] instead.
        #[derive(Copy)]
        pub struct CanReadAllLedgerData;
    }
    permission! {
        /// Permission to read private data belonging to one exact account.
        pub struct CanReadAccountData {
            /// Exact account whose private data may be read.
            pub account: AccountId,
        }
    }
    permission! {
        /// Permission to read non-public ledger data from one exact dataspace.
        ///
        /// The token does not authorize writes, reads from any other dataspace,
        /// or account-alias resolution without its separate exact permission.
        #[derive(Copy)]
        pub struct CanReadRestrictedDataspace {
            /// Exact restricted dataspace whose ledger data may be read.
            pub dataspace: DataSpaceId,
        }
    }
}
/// Permission tokens covering asset operations.
pub mod asset {
    use super::*;
    permission! {
        /// Permission to mint assets belonging to the specified definition.
        pub struct CanMintAssetWithDefinition {
            /// Definition identifier whose assets may be minted.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to burn assets belonging to the specified definition.
        pub struct CanBurnAssetWithDefinition {
            /// Definition identifier whose assets may be burned.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to transfer assets belonging to the specified definition.
        pub struct CanTransferAssetWithDefinition {
            /// Definition identifier whose assets may be transferred.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to mint one asset definition into one exact account.
        ///
        /// Mint authority belongs to the asset-definition owner. Keeping the
        /// destination account separate from the definition makes both the
        /// authority root and the least-privilege scope explicit.
        pub struct CanMintAssetToAccount {
            /// Definition whose supply may be minted.
            pub asset_definition: AssetDefinitionId,
            /// Exact account that may receive the minted supply.
            pub account: AccountId,
        }
    }
    permission! {
        /// Permission to burn the specified asset instance.
        pub struct CanBurnAsset {
            /// Identifier of the asset instance that may be burned.
            pub asset: AssetId,
        }
    }
    permission! {
        /// Permission to transfer the specified asset instance.
        pub struct CanTransferAsset {
            /// Identifier of the asset instance that may be transferred.
            pub asset: AssetId,
        }
    }
    permission! {
        /// Permission to modify metadata for assets belonging to the specified definition.
        pub struct CanModifyAssetMetadataWithDefinition {
            /// Definition identifier whose asset metadata may be changed.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to modify metadata for the specified asset instance.
        pub struct CanModifyAssetMetadata {
            /// Identifier of the asset instance whose metadata may be changed.
            pub asset: AssetId,
        }
    }
    permission! {
        /// Permission to set directional transfer availability for one exact account and asset.
        pub struct CanSetAssetTransferAvailability {
            /// Exact account whose transfer availability may be managed.
            pub account: AccountId,
            /// Exact asset definition whose availability state may be managed.
            pub asset_definition: AssetDefinitionId,
        }
    }
    permission! {
        /// Permission to set the daily transfer limit for one asset definition.
        pub struct CanSetAssetTransferDailyLimit {
            /// Asset definition whose daily account limits may be managed.
            pub asset_definition: AssetDefinitionId,
            /// Canonical on-chain alias domain of accounts whose daily limit may be managed.
            pub account_domain: iroha_data_model::account::rekey::AccountAliasDomain,
            /// Exact dataspace containing the canonical on-chain account alias.
            pub account_dataspace: iroha_model_base::topology::DataSpaceId,
        }
    }
    permission! {
        /// Permission to set a native holding limit for one exact account and asset.
        pub struct CanSetAssetHoldingLimit {
            /// Exact account whose holding limit may be managed.
            pub account: AccountId,
            /// Exact asset definition whose holding limit may be managed.
            pub asset_definition: AssetDefinitionId,
        }
    }
}
/// Permission tokens covering native asset escrow operations.
pub mod escrow {
    use super::*;
    permission! {
        /// Permission to resolve a disputed native asset escrow.
        #[derive(Copy)]
        pub struct CanResolveEscrowDispute;
    }
}
/// Permission tokens covering NFT operations.
pub mod nft {
    use super::*;
    use iroha_model_base::domain::DomainId;
    permission! {
        /// Permission to register an NFT for the given domain.
        pub struct CanRegisterNft {
            /// Domain in which an NFT may be registered.
            pub domain: DomainId,
        }
    }
    permission! {
        /// Permission to unregister the specified NFT.
        pub struct CanUnregisterNft {
            /// Identifier of the NFT that may be unregistered.
            pub nft: NftId,
        }
    }
    permission! {
        /// Permission to transfer the specified NFT.
        pub struct CanTransferNft {
            /// Identifier of the NFT that may be transferred.
            pub nft: NftId,
        }
    }
    permission! {
        /// Permission to modify metadata for the specified NFT.
        pub struct CanModifyNftMetadata {
            /// Identifier of the NFT whose metadata may be changed.
            pub nft: NftId,
        }
    }
}
/// Permission tokens covering trigger management.
pub mod trigger {
    use super::*;
    permission! {
        /// Permission to register a data trigger outside the trigger authority's
        /// exact, owned subject scope.
        ///
        /// Core checks this capability directly on the submitting account so a
        /// role assignment cannot silently turn an ordinary trigger into a
        /// ledger-wide policy hook.
        pub struct CanRegisterGlobalDataTrigger {
            /// Exact trigger authority for which global data-event scope is allowed.
            pub authority: AccountId,
        }
    }
    permission! {
        /// Permission to register triggers on behalf of the provided authority.
        pub struct CanRegisterTrigger {
            /// Authority on whose behalf the trigger may be registered.
            pub authority: AccountId,
        }
    }
    permission! {
        /// Permission to unregister the specified trigger.
        pub struct CanUnregisterTrigger {
            /// Identifier of the trigger that may be removed.
            pub trigger: TriggerId,
        }
    }
    permission! {
        /// Permission to modify the configuration of a trigger.
        pub struct CanModifyTrigger {
            /// Identifier of the trigger that may be modified.
            pub trigger: TriggerId,
        }
    }
    permission! {
        /// Permission to execute a trigger manually.
        pub struct CanExecuteTrigger {
            /// Identifier of the trigger that may be executed.
            pub trigger: TriggerId,
        }
    }
    permission! {
        /// Permission to modify metadata of the specified trigger.
        pub struct CanModifyTriggerMetadata {
            /// Identifier of the trigger whose metadata may be changed.
            pub trigger: TriggerId,
        }
    }
}
/// Permission tokens for configuration parameters.
pub mod parameter {
    use super::*;
    permission! {
        /// Permission to set configuration parameters.
        #[derive(Copy)]
        pub struct CanSetParameters;
    }
    permission! {
        /// Permission to update the consensus-owned Hijiri fee policy and account-risk records.
        #[derive(Copy)]
        pub struct CanSetHijiriParameters;
    }
}
/// Permission tokens for SCCP governance (`specs/sccp.md` §4.19).
pub mod sccp {
    use super::*;
    permission! {
        /// Permission to put SCCP governance proposals before the SORA Parliament.
        ///
        /// It only allows proposing; it is granted and revoked only in genesis.
        #[derive(Copy)]
        pub struct CanProposeSccpRouteGovernance;
    }
}
/// Permission tokens affecting role lifecycle.
pub mod role {
    use super::*;
    permission! {
        /// Permission to manage role lifecycle.
        #[derive(Copy)]
        pub struct CanManageRoles;
    }
}
/// Permission tokens affecting executor upgrades.
pub mod executor {
    use super::*;
    permission! {
        /// Permission to upgrade the executor implementation.
        #[derive(Copy)]
        pub struct CanUpgradeExecutor;
    }
}
/// Smart contract related permissions
pub mod smart_contract {
    use super::*;
    permission! {
        /// Genesis-rooted authority to grant and revoke privileged contract-code management.
        ///
        /// This capability does not itself authorize deployment or alias management. An approved
        /// code-management grant authority may authorize privileged artifact administration without
        /// allowing code managers to grant that authority onward. Public immutable artifact
        /// creation needs neither token.
        #[derive(Copy)]
        pub struct CanGrantSmartContractCodeManagement;
    }
    permission! {
        /// Privileged unreferenced-artifact removal and contract-entrypoint delegation authority.
        ///
        /// Registered accounts may create immutable verified artifacts without this capability.
        #[derive(Copy)]
        pub struct CanManageSmartContractCode;
    }
    permission! {
        /// Permission declared by the current code of one deployed contract instance.
        /// Only its current account lifecycle owner or an exact holder may delegate it.
        pub struct CanUseContractPermission {
            /// Immutable deployed contract address.
            pub contract: ContractAddress,
            /// Exact source-level instance permission declaration.
            pub permission: Name,
        }
    }
    permission! {
        /// Permission to invoke one exact runtime lifecycle hook of one deployed instance.
        ///
        /// Its current account lifecycle owner may explicitly grant or revoke this token
        /// without a global code-management capability. Ownership alone does not authorize
        /// invocation; callers still need this exact address and selector token.
        pub struct CanInvokeContractEntrypoint {
            /// Immutable deployed contract address.
            pub contract: ContractAddress,
            /// Exact case-sensitive lifecycle selector (`hajimari`/`始まり` or `kaizen`/`改善`).
            pub entrypoint: String,
        }
    }
}
/// Permission tokens governing native FX corridors.
pub mod settlement {
    use super::*;
    use iroha_data_model::isi::SettlementId;
    permission! {
        /// Exact consent from a debited counterparty for one bilateral settlement intent.
        ///
        /// Only the account named by `debited_asset` may delegate or revoke this token. The intent
        /// hash commits to the complete domain-separated `DvP`, `PvP`, or repo phase, so changing
        /// any economic term or the settlement identifier requires fresh consent. Repo initiation
        /// requires distinct cash-debit and maturity-collateral consents before any asset moves.
        pub struct CanExecuteSettlement {
            /// Exact balance bucket the authorized settlement may debit.
            pub debited_asset: AssetId,
            /// One-shot settlement identifier bound by the consent.
            pub settlement_id: SettlementId,
            /// Domain-separated commitment to the complete settlement instruction.
            pub intent_hash: Hash,
        }
    }
    permission! {
        /// Root permission for delegating native FX corridor governance.
        #[derive(Copy)]
        pub struct CanManageFxCorridors;
    }
    permission! {
        /// Permission to publish the next revision of one FX corridor policy.
        ///
        /// Only a [`CanManageFxCorridors`] holder may delegate or revoke this scoped permission.
        pub struct CanSetFxCorridorPolicy {
            /// Stable corridor policy identifier.
            pub policy_id: Name,
        }
    }
}
/// NEVO DPN application-role and scoped enrollment permissions.
///
/// The application-role markers carry exactly the JSON `null` payload emitted by a unit struct.
/// Their lifecycle requires a direct [`DpnAdmin`] after genesis, except the narrowly scoped
/// enrollment capability below can grant only [`DpnUser`]. The capability carries an exact domain.
/// Its issuance requires a direct administrator who owns that live domain. A direct administrator
/// or the current live domain owner can revoke it, including after ownership transfer.
pub mod dpn {
    use super::*;
    use iroha_model_base::domain::DomainId;
    permission! {
        /// Grant only `DpnUser` to a registered UAID account with an active alias in this domain.
        ///
        /// Also permits the exact native account and direct-permission queries needed to verify
        /// that enrollment. Balances, assets, aliases, rosters and other account queries remain
        /// separately protected. Only a direct `DpnAdmin` who owns the live domain may issue
        /// this capability. A direct administrator or current live domain owner may revoke
        /// it; possession does not permit redelegation or role grants.
        pub struct CanGrantDpnUserForAccountDomain {
            /// Exact account-alias domain, including its dataspace name.
            pub domain: DomainId,
        }
    }
    permission! {
        /// NEVO DPN contract administrator authority.
        #[derive(Copy)]
        pub struct DpnAdmin;
    }
    permission! {
        /// NEVO DPN application participant authority.
        #[derive(Copy)]
        pub struct DpnUser;
    }
    permission! {
        /// NEVO DPN Inori workflow authority.
        #[derive(Copy)]
        pub struct DpnInori;
    }
    permission! {
        /// NEVO DPN settlement signer authority.
        #[derive(Copy)]
        pub struct DpnSettlement;
    }
    permission! {
        /// NEVO DPN EPR source-guard authority.
        #[derive(Copy)]
        pub struct DpnEprGuard;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use iroha_data_model::permission::Permission as PermissionObject;

        macro_rules! assert_null_marker_permission {
            ($value:expr, $ty:ty, $name:literal) => {{
                let permission = PermissionObject::from($value);
                assert_eq!(permission.name().to_string(), $name);
                assert_eq!(permission.payload().as_ref(), "null");
                assert!(<$ty>::try_from(&permission).is_ok());

                for malformed in ["{}", "[]", "true", "\"unexpected\""] {
                    let malformed = PermissionObject::new(
                        permission.name().to_owned(),
                        Json::from_raw_json(malformed.to_owned())
                            .expect("valid malformed-payload fixture"),
                    );
                    assert!(
                        <$ty>::try_from(&malformed).is_err(),
                        "{} must reject payload {malformed:?}",
                        $name,
                    );
                }
            }};
        }

        #[test]
        fn dpn_permissions_are_exact_null_payload_markers() {
            assert_null_marker_permission!(DpnAdmin, DpnAdmin, "DpnAdmin");
            assert_null_marker_permission!(DpnUser, DpnUser, "DpnUser");
            assert_null_marker_permission!(DpnInori, DpnInori, "DpnInori");
            assert_null_marker_permission!(DpnSettlement, DpnSettlement, "DpnSettlement");
            assert_null_marker_permission!(DpnEprGuard, DpnEprGuard, "DpnEprGuard");
        }
    }
}
/// Nexus / Space Directory permissions.
pub mod nexus {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    permission! {
        /// Permission to publish capability manifests for a dataspace.
        #[derive(Copy)]
        pub struct CanPublishSpaceDirectoryManifest {
            /// Dataspace identifier governed by the manifest.
            pub dataspace: DataSpaceId,
        }
    }
    permission! {
        /// Permission to publish, replace, revoke, or expire one exact UAID manifest.
        #[derive(Copy)]
        pub struct CanPublishSpaceDirectoryManifestForUaid {
            /// Dataspace identifier governed by the manifest.
            pub dataspace: DataSpaceId,
            /// Exact universal account identifier governed by this permission.
            pub uaid: iroha_data_model::nexus::UniversalAccountId,
        }
    }
    permission! {
        /// Permission to manage manifests for accounts bound to one exact account-alias domain.
        pub struct CanPublishSpaceDirectoryManifestForAccountDomain {
            /// Dataspace identifier governed by the manifest.
            pub dataspace: DataSpaceId,
            /// Exact account-alias domain whose bound accounts may be managed.
            pub domain: DomainId,
        }
    }
    permission! {
        /// Permission to manage fee sponsor programs owned by one sponsor account.
        ///
        /// Only the sponsor account may delegate or revoke this management permission.
        pub struct CanManageFeeSponsorProgram {
            /// Sponsor account whose programs may be created and revised.
            pub sponsor: AccountId,
        }
    }
    permission! {
        /// Permission to enroll or unenroll beneficiaries in one exact sponsor program.
        pub struct CanEnrollFeeSponsorProgram {
            /// Exact program whose enrollment set may be managed.
            pub program_id: FeeSponsorProgramId,
        }
    }
}
/// Governance-related permissions
pub mod governance {
    use super::*;
    permission! {
        /// Allow proposing deployment of a smart contract via governance
        pub struct CanProposeContractDeployment {
            /// Canonical contract address targeted by the proposal.
            pub contract_address: ContractAddress,
        }
    }
    permission! {
        /// Allow proposing a runtime upgrade for one exact ABI target.
        #[derive(Copy)]
        pub struct CanProposeRuntimeUpgrade {
            /// Exact ABI version targeted by the proposed runtime upgrade.
            pub abi_version: u16,
            /// Exact canonical ABI hash targeted by the proposed runtime upgrade.
            pub abi_hash: [u8; 32],
        }
    }
    permission! {
        /// Allow submitting a governance ballot to a referendum/election
        pub struct CanSubmitGovernanceBallot {
            /// Canonical governance selector V1 identifying the referendum or election.
            pub referendum_id: String,
        }
    }
    permission! {
        /// Allow enacting an approved referendum
        #[derive(Copy)]
        pub struct CanEnactGovernance;
    }
    permission! {
        /// Allow managing sortition parliament parameters/membership
        #[derive(Copy)]
        pub struct CanManageParliament;
    }
    permission! {
        /// Allow registering and rotating ledger verifying keys.
        #[derive(Copy)]
        pub struct CanManageVerifyingKeys;
    }
    permission! {
        /// Allow activating and cancelling runtime upgrades.
        #[derive(Copy)]
        pub struct CanManageRuntimeUpgrades;
    }
    permission! {
        /// Allow managing consensus keys and endorsement committees.
        #[derive(Copy)]
        pub struct CanManageConsensusKeys;
    }
    permission! {
        /// Allow publishing and changing lifecycle state for confidential parameters.
        #[derive(Copy)]
        pub struct CanManageConfidentialParams;
    }
    permission! {
        /// Allow slashing governance bond locks for a referendum.
        pub struct CanSlashGovernanceLock {
            /// Canonical governance selector V1 identifying the referendum.
            pub referendum_id: String,
        }
    }
    permission! {
        /// Allow restituting governance bond locks after appeal.
        pub struct CanRestituteGovernanceLock {
            /// Canonical governance selector V1 identifying the referendum.
            pub referendum_id: String,
        }
    }
}
/// Permission tokens governing `SoraFS` operations.
pub mod sorafs {
    use super::*;
    use iroha_data_model::sorafs::prelude::ProviderId;
    permission! {
        /// Permission to bind or update a `SoraFS` manifest alias.
        #[derive(Copy)]
        pub struct CanBindSorafsAlias;
    }
    permission! {
        /// Permission to declare storage capacity for a `SoraFS` provider.
        #[derive(Copy)]
        pub struct CanDeclareSorafsCapacity;
    }
    permission! {
        /// Permission to submit capacity telemetry for a `SoraFS` provider.
        #[derive(Copy)]
        pub struct CanSubmitSorafsTelemetry;
    }
    permission! {
        /// Permission to file a `SoraFS` capacity dispute.
        #[derive(Copy)]
        pub struct CanFileSorafsCapacityDispute;
    }
    permission! {
        /// Permission to issue `SoraFS` replication orders.
        #[derive(Copy)]
        pub struct CanIssueSorafsReplicationOrder;
    }
    permission! {
        /// Permission to complete native replication assignments for one exact provider.
        #[derive(Copy)]
        #[norito(deny_unknown_fields)]
        pub struct CanCompleteSorafsReplicationOrder {
            /// Nonzero governed provider identity whose assignments may be completed.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Permission to set `SoraFS` pricing schedules.
        #[derive(Copy)]
        pub struct CanSetSorafsPricing;
    }
    permission! {
        /// Permission to govern the authoritative `SoraFS` reserve and rent ledger.
        #[derive(Copy)]
        pub struct CanSetSorafsReservePolicy;
    }
    permission! {
        /// Permission to configure, open, resolve, and finalize authoritative `SoraFS` moderation ballots.
        #[derive(Copy)]
        pub struct CanManageSorafsModeration;
    }
    permission! {
        /// Permission to activate or rotate the authoritative `SoraFS` `PoP` issuer policy.
        #[derive(Copy)]
        pub struct CanManageSorafsPopRegistry;
    }
    permission! {
        /// Permission to publish authoritative `SoraFS` `PoP` credential and revocation state.
        #[derive(Copy)]
        pub struct CanOperateSorafsPopIssuer;
    }
    permission! {
        /// Permission to upsert `SoraFS` provider credit records.
        #[derive(Copy)]
        pub struct CanUpsertSorafsProviderCredit;
    }
    permission! {
        /// Govern native stream-token gateway policies and bootstrap exact gateway operators.
        ///
        /// Genesis seeds this global administrator: gateway IDs depend on the genesis-derived
        /// network identity and therefore cannot be embedded as scoped bootstrap permissions.
        #[derive(Copy)]
        pub struct CanManageSorafsStreamTokenGateway;
    }
    permission! {
        /// Attest admissions and discharge retained obligations for one native gateway.
        #[derive(Copy)]
        #[norito(deny_unknown_fields)]
        pub struct CanOperateSorafsStreamTokenGateway {
            /// Exact nonzero network-derived gateway identifier; never a wildcard.
            pub gateway_id: [u8; 32],
        }
    }
    permission! {
        /// Independently challenge exact native readback for one stream-token gateway.
        ///
        /// This capability never grants operation authority or independently proves serving
        /// eligibility. The native Check also requires current governed observer membership.
        #[derive(Copy)]
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsStreamTokenGateway {
            /// Exact nonzero network-derived gateway identifier; never a wildcard.
            pub gateway_id: [u8; 32],
        }
    }
    permission! {
        /// Permission to configure, enroll, or revoke stream-token custody for one provider.
        #[derive(Copy)]
        pub struct CanManageSorafsStreamTokenCustody {
            /// Provider identifier governed by this permission.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Permission for the registered owner to reserve, complete or expire one provider's stream-token operations.
        #[derive(Copy)]
        #[norito(deny_unknown_fields)]
        pub struct CanOperateSorafsStreamToken {
            /// Provider whose operation journal this permission may mutate.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Separate read-only permission to submit a challenged stream-token Check for one provider.
        #[derive(Copy)]
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsStreamToken {
            /// Provider whose operation journal this permission may observe.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Permission to configure, enroll, or revoke final-promotion custody for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanManageSorafsFinalPromotionCustody {
            /// Stable deployment identifier governed by this permission.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to reserve, complete, or expire final-promotion operations for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanOperateSorafsFinalPromotion {
            /// Stable deployment identifier governed by this permission.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission for an independent observer to check receipt signing eligibility for one deployment.
        /// This grants no custody mutation or operation authority.
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsFinalPromotion {
            /// Stable deployment identifier observed with this read-only capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to configure, enroll, or revoke topology signer custody for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanManageSorafsTopologyCustody {
            /// Stable topology deployment governed by this capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to reserve, complete, or expire topology approval for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanOperateSorafsTopologyApproval {
            /// Stable topology deployment governed by this capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission for an independent observer to check topology approval for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsTopologyApproval {
            /// Stable topology deployment observed by this read-only capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to configure, enroll, or revoke the transaction-account custody of one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanManageSorafsFinalPromotionAccountCustody {
            /// Stable deployment identifier governed by this management capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission for an independent observer to check transaction-account custody for one deployment.
        /// This grants no custody mutation or release transaction authority.
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsFinalPromotionAccountCustody {
            /// Stable deployment identifier observed with this read-only capability.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to configure, enroll or revoke release-manifest custody for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanManageSorafsReleaseManifestCustody {
            /// Stable role-13 deployment governed by this permission.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to reserve, complete or expire release-manifest operations for one deployment.
        #[norito(deny_unknown_fields)]
        pub struct CanOperateSorafsReleaseManifest {
            /// Stable role-13 deployment governed by this permission.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission for an independent observer to Check release-manifest authority.
        /// This grants no protected-key operation or custody mutation.
        #[norito(deny_unknown_fields)]
        pub struct CanCheckSorafsReleaseManifest {
            /// Stable role-13 deployment observed by this permission.
            pub deployment_id: String,
        }
    }
    permission! {
        /// Permission to operate `SoraFS` repair tickets for a provider.
        #[derive(Copy)]
        pub struct CanOperateSorafsRepair {
            /// Provider identifier governed by this permission.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Permission to activate or rotate governed PDP/PoTR validation keys.
        #[derive(Copy)]
        pub struct CanManageSorafsProofOutcomePolicy;
    }
    permission! {
        /// Permission to record unsigned scheduler-only proof outcomes for a provider.
        #[derive(Copy)]
        pub struct CanRecordSorafsProofOutcome {
            /// Provider identifier governed by this permission.
            pub provider_id: ProviderId,
        }
    }
    permission! {
        /// Permission to activate or rotate the authoritative reputation recorder policy.
        #[derive(Copy)]
        pub struct CanManageSorafsReputationJournalPolicy;
    }
    permission! {
        /// Permission to submit policy-authorized `PoR` or stream-token reputation entries.
        #[derive(Copy)]
        pub struct CanRecordSorafsReputationJournal;
    }
    permission! {
        /// Permission to commit the terminal outcome of an authoritative capacity dispute.
        #[derive(Copy)]
        pub struct CanResolveSorafsCapacityDispute;
    }
}
/// Permission tokens governing `SoraNet` services.
pub mod soranet {
    use super::*;
    permission! {
        /// Permission to authorize accounts and roles that may issue `SoraNet` VPN quotes.
        #[derive(Copy)]
        pub struct CanManageSoranetVpnQuoteIssuers;
    }
    permission! {
        /// Permission to issue operator-signed `SoraNet` VPN lease quotes.
        #[derive(Copy)]
        pub struct CanIssueSoranetVpnQuote;
    }
    permission! {
        /// Permission to ingest `SoraNet` privacy events or shares.
        #[derive(Copy)]
        pub struct CanIngestSoranetPrivacy;
    }
}
/// Permission tokens governing operator-managed oracle state.
pub mod oracle {
    use super::*;
    use iroha_data_model::oracle::OracleChangeStage;
    permission! {
        /// Permission to register oracle feed configurations.
        #[derive(Copy)]
        pub struct CanRegisterOracleFeed;
    }
    permission! {
        /// Permission to propose oracle feed governance changes.
        #[derive(Copy)]
        pub struct CanProposeOracleChange;
    }
    permission! {
        /// Permission to vote in a specific oracle change stage.
        #[derive(Copy)]
        pub struct CanVoteOracleChangeStage {
            /// Stage in which the holder may vote.
            pub stage: OracleChangeStage,
        }
    }
    permission! {
        /// Permission to roll back oracle change proposals.
        #[derive(Copy)]
        pub struct CanRollbackOracleChange;
    }
    permission! {
        /// Permission to resolve oracle disputes.
        #[derive(Copy)]
        pub struct CanResolveOracleDispute;
    }
    permission! {
        /// Permission to record or revoke oracle-backed Twitter bindings.
        #[derive(Copy)]
        pub struct CanManageTwitterBindings;
    }
}
#[cfg(test)]
mod tests {
    use super::account::CanRegisterAccount;
    use super::asset::{
        CanSetAssetHoldingLimit, CanSetAssetTransferAvailability, CanSetAssetTransferDailyLimit,
    };
    use super::escrow::CanResolveEscrowDispute;
    use super::governance::{
        CanManageConfidentialParams, CanManageConsensusKeys, CanManageRuntimeUpgrades,
        CanManageVerifyingKeys, CanProposeRuntimeUpgrade,
    };
    use super::oracle::{
        CanManageTwitterBindings, CanRegisterOracleFeed, CanVoteOracleChangeStage,
    };
    use super::query::{CanReadAccountData, CanReadAllLedgerData, CanReadRestrictedDataspace};
    use super::trigger::CanRegisterGlobalDataTrigger;
    use crate::permission::Permission as _;
    use iroha_crypto::KeyPair;
    use iroha_data_model::oracle::OracleChangeStage;
    use iroha_data_model::{
        AccountId, account::rekey::AccountAliasDomain, asset::AssetDefinitionId,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    #[test]
    fn can_register_account_serializes_as_json_string_field() {
        let perm = CanRegisterAccount {
            domain: DomainId::try_new("fixture", "universal").expect("valid domain"),
        };
        let json = norito::json::to_json(&perm).expect("serialize to JSON");
        assert_eq!(json, "{\"domain\":\"fixture.universal\"}");
        let value = norito::json::to_value(&perm).expect("serialize to JSON value");
        assert_eq!(
            value,
            norito::json!({
                "domain": "fixture.universal",
            })
        );
    }
    #[test]
    fn transfer_control_permissions_use_exact_availability_target_and_scoped_daily_limit() {
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("currency", "sbp").expect("asset domain"),
            "pkr".parse().expect("asset name"),
        );
        let account = AccountId::new(KeyPair::random().public_key().clone());
        let account_domain = AccountAliasDomain::new("hbl".parse().expect("account domain"));
        let account_dataspace = DataSpaceId::new(10);
        let availability = CanSetAssetTransferAvailability {
            account: account.clone(),
            asset_definition: asset_definition.clone(),
        };
        let holding_limit = CanSetAssetHoldingLimit {
            account: account.clone(),
            asset_definition: asset_definition.clone(),
        };
        let daily_limit = CanSetAssetTransferDailyLimit {
            asset_definition,
            account_domain,
            account_dataspace,
        };
        let availability_value =
            norito::json::to_value(&availability).expect("availability permission JSON");
        let availability_object = availability_value
            .as_object()
            .expect("availability permission object");
        assert_eq!(
            availability_object.len(),
            2,
            "availability permission must bind only its two exact identifiers"
        );
        let account_literal = account.to_string();
        assert_eq!(
            availability_object["account"].as_str(),
            Some(account_literal.as_str())
        );
        let holding_value =
            norito::json::to_value(&holding_limit).expect("holding-limit permission JSON");
        let holding_object = holding_value
            .as_object()
            .expect("holding-limit permission object");
        assert_eq!(holding_object.len(), 2);
        assert_eq!(
            holding_object["account"].as_str(),
            Some(account_literal.as_str())
        );
        let daily_limit_value =
            norito::json::to_value(&daily_limit).expect("daily-limit permission JSON");
        let daily_limit_object = daily_limit_value
            .as_object()
            .expect("daily-limit permission object");
        assert_eq!(daily_limit_object.len(), 3);
        assert_eq!(daily_limit_object["account_domain"], norito::json!(["hbl"]));
        assert_eq!(daily_limit_object["account_dataspace"].as_u64(), Some(10));
        let broad_legacy_scope = norito::json!({
            "asset_definition": (availability.asset_definition.to_string()),
            "account_domain": "hbl",
            "account_dataspace": 10,
        });
        assert!(
            norito::json::from_value::<CanSetAssetTransferAvailability>(broad_legacy_scope)
                .is_err(),
            "availability permission must not accept a broad domain/dataspace scope",
        );
        let missing_account = norito::json!({
            "asset_definition": (availability.asset_definition.to_string()),
        });
        assert!(
            norito::json::from_value::<CanSetAssetTransferAvailability>(missing_account).is_err(),
            "availability permission must require an exact account",
        );
        assert!(
            norito::json::from_value::<CanSetAssetHoldingLimit>(norito::json!({
                "asset_definition": (holding_limit.asset_definition.to_string()),
            }))
            .is_err(),
            "holding-limit permission must require an exact account",
        );
    }
    #[test]
    fn escrow_court_permission_uses_expected_name() {
        assert_eq!(
            CanResolveEscrowDispute::name().as_str(),
            "CanResolveEscrowDispute"
        );
    }
    #[test]
    fn manage_verifying_keys_is_an_exact_unit_capability() {
        let canonical: iroha_data_model::permission::Permission = CanManageVerifyingKeys.into();
        assert_eq!(canonical.name(), "CanManageVerifyingKeys");
        assert_eq!(
            CanManageVerifyingKeys::try_from(&canonical).expect("decode canonical unit payload"),
            CanManageVerifyingKeys
        );
        let malformed = iroha_data_model::permission::Permission::new(
            "CanManageVerifyingKeys".into(),
            norito::json!({"circuit_id": "not-a-scope"}),
        );
        assert!(
            CanManageVerifyingKeys::try_from(&malformed).is_err(),
            "the global capability must not accept an invented resource scope"
        );
    }
    #[test]
    fn operational_governance_permissions_are_exact_unit_capabilities() {
        macro_rules! assert_exact_unit_capability {
            ($permission:ty, $value:expr, $name:literal) => {{
                let canonical: iroha_data_model::permission::Permission =
                    $value.into();
                assert_eq!(canonical.name(), $name);
                assert_eq!(
                    <$permission>::try_from(&canonical).expect("decode canonical unit payload"),
                    $value,
                );
                let malformed = iroha_data_model::permission::Permission::new(
                    $name.into(),
                    norito::json!({"invented_scope": "must-not-authorize"}),
                );
                assert!(
                    <$permission>::try_from(&malformed).is_err(),
                    "{} must reject an invented resource scope",
                    $name,
                );
            }};
        }

        assert_exact_unit_capability!(
            CanManageRuntimeUpgrades,
            CanManageRuntimeUpgrades,
            "CanManageRuntimeUpgrades"
        );
        assert_exact_unit_capability!(
            CanManageConsensusKeys,
            CanManageConsensusKeys,
            "CanManageConsensusKeys"
        );
        assert_exact_unit_capability!(
            CanManageConfidentialParams,
            CanManageConfidentialParams,
            "CanManageConfidentialParams"
        );
    }
    #[test]
    fn runtime_upgrade_proposal_permission_binds_the_exact_abi_target() {
        let expected = CanProposeRuntimeUpgrade {
            abi_version: 1,
            abi_hash: [0xA5; 32],
        };
        let canonical: iroha_data_model::permission::Permission = expected.into();
        assert_eq!(canonical.name(), "CanProposeRuntimeUpgrade");
        assert_eq!(
            CanProposeRuntimeUpgrade::try_from(&canonical)
                .expect("decode exact runtime-upgrade proposal scope"),
            expected
        );
        let other_target: iroha_data_model::permission::Permission = CanProposeRuntimeUpgrade {
            abi_version: 1,
            abi_hash: [0x5A; 32],
        }
        .into();
        assert_ne!(canonical, other_target);
        let other_version: iroha_data_model::permission::Permission = CanProposeRuntimeUpgrade {
            abi_version: 2,
            abi_hash: [0xA5; 32],
        }
        .into();
        assert_ne!(canonical, other_version);
        let malformed = iroha_data_model::permission::Permission::new(
            "CanProposeRuntimeUpgrade".into(),
            norito::json!({"abi_version": 1}),
        );
        assert!(
            CanProposeRuntimeUpgrade::try_from(&malformed).is_err(),
            "runtime-upgrade permission must require the exact ABI hash"
        );
    }
    #[test]
    fn restricted_dataspace_read_permission_is_exact_and_typed() {
        let permission = CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(10),
        };
        let json = norito::json::to_json(&permission).expect("serialize permission");
        assert_eq!(
            CanReadRestrictedDataspace::name().as_str(),
            "CanReadRestrictedDataspace"
        );
        assert_eq!(json, "{\"dataspace\":10}");
        assert!(
            norito::json::from_str::<CanReadRestrictedDataspace>("{\"dataspace\":\"sbp\"}")
                .is_err(),
            "restricted read grants must carry a numeric DataSpaceId"
        );
    }
    #[test]
    fn global_data_trigger_permission_binds_one_exact_authority() {
        let authority = AccountId::new(KeyPair::random().public_key().clone());
        let other = AccountId::new(KeyPair::random().public_key().clone());
        let exact = CanRegisterGlobalDataTrigger {
            authority: authority.clone(),
        };
        let canonical: iroha_data_model::permission::Permission = exact.clone().into();
        assert_eq!(canonical.name(), "CanRegisterGlobalDataTrigger");
        assert_eq!(
            CanRegisterGlobalDataTrigger::try_from(&canonical)
                .expect("decode exact global-trigger scope"),
            exact
        );
        let other_scope: iroha_data_model::permission::Permission =
            CanRegisterGlobalDataTrigger { authority: other }.into();
        assert_ne!(canonical, other_scope);
        let malformed = iroha_data_model::permission::Permission::new(
            "CanRegisterGlobalDataTrigger".into(),
            norito::json!({}),
        );
        assert!(CanRegisterGlobalDataTrigger::try_from(&malformed).is_err());
    }
    #[test]
    fn ledger_read_permissions_are_exact_and_typed() {
        let account = AccountId::new(KeyPair::random().public_key().clone());
        let account_read = CanReadAccountData {
            account: account.clone(),
        };
        let account_json =
            norito::json::to_json(&account_read).expect("serialize account-read permission");
        assert_eq!(CanReadAllLedgerData::name(), "CanReadAllLedgerData");
        assert_eq!(CanReadAccountData::name(), "CanReadAccountData");
        assert_eq!(
            account_json,
            format!("{{\"account\":\"{account}\"}}"),
            "account-read permission must bind exactly one universal account"
        );
        let global: iroha_data_model::permission::Permission = CanReadAllLedgerData.into();
        assert_eq!(
            CanReadAllLedgerData::try_from(&global).expect("decode canonical global read token"),
            CanReadAllLedgerData
        );
        let malformed_global = iroha_data_model::permission::Permission::new(
            "CanReadAllLedgerData".into(),
            norito::json!({"account": (account.to_string())}),
        );
        assert!(
            CanReadAllLedgerData::try_from(&malformed_global).is_err(),
            "the global read root must not accept an invented account scope"
        );
        assert!(
            norito::json::from_str::<CanReadAccountData>("{}").is_err(),
            "account reads must require an exact account"
        );
    }
    #[test]
    fn oracle_permissions_use_expected_names_and_payloads() {
        assert_eq!(
            CanRegisterOracleFeed::name().as_str(),
            "CanRegisterOracleFeed"
        );
        assert_eq!(
            CanManageTwitterBindings::name().as_str(),
            "CanManageTwitterBindings"
        );
        let stage_vote = CanVoteOracleChangeStage {
            stage: OracleChangeStage::PolicyJury,
        };
        let json = norito::json::to_json(&stage_vote).expect("serialize to JSON");
        assert!(json.contains("PolicyJury"));
    }
    #[test]
    fn account_domain_manifest_permission_json_uses_dot_fqn() {
        use super::nexus::CanPublishSpaceDirectoryManifestForAccountDomain;
        let token = CanPublishSpaceDirectoryManifestForAccountDomain {
            dataspace: DataSpaceId::new(10),
            domain: DomainId::try_new("hbl", "sbp").expect("HBL domain"),
        };
        let payload = norito::json::to_json(&token).expect("serialize publisher permission");
        assert_eq!(payload, r#"{"dataspace":10,"domain":"hbl.sbp"}"#);
        assert_eq!(
            norito::json::from_str::<CanPublishSpaceDirectoryManifestForAccountDomain>(&payload)
                .expect("deserialize publisher permission"),
            token,
        );
    }
    #[test]
    fn sponsor_program_permissions_json_use_exact_program_id() {
        use super::nexus::CanEnrollFeeSponsorProgram;
        use iroha_data_model::nexus::FeeSponsorProgramId;
        let sponsor = AccountId::new(KeyPair::random().public_key().clone());
        let token = CanEnrollFeeSponsorProgram {
            program_id: FeeSponsorProgramId::new(
                sponsor,
                "retail".parse().expect("fee sponsor program name"),
            ),
        };
        let payload = norito::json::to_json(&token).expect("serialize enrollment permission");
        assert_eq!(
            payload,
            format!(
                r#"{{"program_id":{{"sponsor":"{}","name":"{}"}}}}"#,
                token.program_id.sponsor, token.program_id.name,
            ),
        );
        assert_eq!(
            norito::json::from_str::<CanEnrollFeeSponsorProgram>(&payload)
                .expect("deserialize enrollment permission"),
            token,
        );
    }
}

#[cfg(test)]
#[path = "final_promotion_permission_tests.rs"]
mod final_promotion_permission_tests;
#[cfg(test)]
#[path = "release_manifest_permission_tests.rs"]
mod release_manifest_permission_tests;
#[cfg(test)]
#[path = "stream_token_gateway_permission_tests.rs"]
mod stream_token_gateway_permission_tests;
#[cfg(test)]
#[path = "stream_token_permission_tests.rs"]
mod stream_token_permission_tests;
