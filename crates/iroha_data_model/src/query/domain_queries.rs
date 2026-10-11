pub mod role {
    //! Role-related query definitions.
    //!
    //! Queries related to [`crate::role`].
    use std::{format, string::String, vec::Vec};
    // prelude not needed here; keep imports minimal
    use derive_more::Display;
    // Bring required IDs into scope for queries! items
    use crate::AccountId;
    queries! {
            /// [`FindRoles`] Iroha Query finds all `Role`s presented.
            #[derive(Copy, Display)]
            #[display("Find all roles")]
            #[norito_schema(name = "iroha_data_model::query::role::model::FindRoles")]
            pub struct FindRoles;
            /// [`FindRoleIds`] Iroha Query finds `RoleId`s of
            /// all `Role`s presented.
            #[derive(Copy, Display)]
            #[display("Find all role ids")]
            #[norito_schema(name = "iroha_data_model::query::role::model::FindRoleIds")]
            pub struct FindRoleIds;
            /// [`FindRolesByAccountId`] Iroha Query finds all `Role`s for a specified account.
            #[derive(Display)]
            #[display("Find all roles for `{id}` account")]
            #[repr(transparent)]
            // SAFETY: `FindRolesByAccountId` has no trap representation in `AccountId`
    /// Query for roles associated with a given account.
            #[norito_schema(name = "iroha_data_model::query::role::model::FindRolesByAccountId")]
            pub struct FindRolesByAccountId {
                /// `Id` of an account to find.
                pub id: AccountId,
            }
        }
    impl FindRolesByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &AccountId {
            &self.id
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this module.
        pub use super::{FindRoleIds, FindRoles, FindRolesByAccountId};
    }
}
pub mod permission {
    //! Permission-related query definitions.
    //!
    //! Queries related to [`crate::permission`].
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    // Bring required IDs into scope for queries! items
    use crate::AccountId;
    queries! {
            /// [`FindPermissionsByAccountId`] Iroha Query finds all [`crate::permission::Permission`] values
            /// for a specified account.
            #[derive(Display)]
            #[display("Find permission tokens specified for `{id}` account")]
            #[repr(transparent)]
            // SAFETY: `FindPermissionsByAccountId` has no trap representation in `AccountId`
    /// Query for permissions associated with a given account.
            #[norito_schema(name = "iroha_data_model::query::permission::model::FindPermissionsByAccountId")]
            pub struct FindPermissionsByAccountId {
                /// `Id` of an account to find.
                pub id: AccountId,
            }
        }
    impl FindPermissionsByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &AccountId {
            &self.id
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this module.
        pub use super::FindPermissionsByAccountId;
    }
}
pub mod account {
    //! Account-related query definitions.
    //!
    //! Queries related to [`crate::account`].
    use derive_more::Display;
    use norito::codec::{Decode, Encode};
    use std::{format, string::String, vec::Vec};
    // Bring required IDs into scope for queries! items
    use crate::prelude::AssetDefinitionId;
    /// API-facing record describing one alias bound to an account.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(no_fast_from_json)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::account::AccountAliasBindingRecord")]
    pub struct AccountAliasBindingRecord {
        /// Canonical account identifier that owns the binding.
        pub account_id: crate::account::AccountId,
        /// Canonical alias literal such as `merchant@banka.centralbank`.
        pub alias: String,
        /// Dataspace alias such as `centralbank`.
        pub dataspace: String,
        /// Optional domain qualifier such as `banka`.
        #[norito(default)]
        pub domain: Option<String>,
        /// Whether this alias is the account's primary label.
        #[norito(default)]
        pub is_primary: bool,
        /// Effective SNS lifecycle status for the alias.
        pub status: crate::sns::NameStatus,
        /// Lease expiry timestamp (unix ms) when the alias ceases to be active.
        #[norito(default)]
        pub lease_expiry_ms: Option<u64>,
        /// End of the grace period (unix ms) after expiry.
        #[norito(default)]
        pub grace_until_ms: Option<u64>,
        /// Timestamp (unix ms) when the current lease term started.
        #[norito(default)]
        pub bound_at_ms: u64,
    }
    queries! {
            /// [`FindAccountById`] Iroha Query finds an `Account` by its identifier.
            #[derive(Display)]
            #[display("Find account `{id}`")]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountById")]
            pub struct FindAccountById {
                /// Domainless account identifier to resolve.
                pub id: crate::account::AccountId,
            }
            /// [`FindAccountByAlias`] Iroha Query finds an `Account` by its stable alias.
            #[derive(Display)]
            #[display("Find account by alias `{alias:?}`")]
            #[repr(transparent)]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountByAlias")]
            pub struct FindAccountByAlias {
                /// Stable account alias whose bound account should be resolved.
                pub alias: crate::account::AccountAlias,
            }
            /// [`FindAccounts`] Iroha Query finds all `Account`s presented.
            #[derive(Copy, Display)]
            #[display("Find all accounts")]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccounts")]
            pub struct FindAccounts;
            /// [`FindAccountIds`] Iroha Query finds identifiers of all `Account`s presented.
            #[derive(Copy, Display)]
            #[display("Find all account ids")]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountIds")]
            pub struct FindAccountIds;
            /// [`FindAccountsWithAsset`] Iroha Query gets [`crate::asset::definition::AssetDefinition`] ids as input and
            /// finds all [`crate::account::Account`]s storing [`crate::asset::value::Asset`] with such definition.
            #[derive(Display)]
            #[display("Find accounts with `{asset_definition}` asset")]
            #[repr(transparent)]
            // SAFETY: `FindAccountsWithAsset` has no trap representation in `AssetDefinitionId`
    /// Query for accounts that hold a specific asset.
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountsWithAsset")]
            pub struct FindAccountsWithAsset {
                /// `Id` of the definition of the asset which should be stored in founded accounts.
                pub asset_definition: AssetDefinitionId,
            }
            /// [`FindAliasesByAccountId`] query lists aliases bound to the account subject.
            #[derive(Display)]
            #[display("Find aliases bound to account `{id}`")]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAliasesByAccountId")]
            pub struct FindAliasesByAccountId {
                /// Domainless account identifier whose alias bindings should be resolved.
                pub id: crate::account::AccountId,
                /// Optional dataspace alias filter such as `centralbank`.
                #[norito(default)]
                pub dataspace: Option<String>,
                /// Optional exact domain filter such as `banka`.
                #[norito(default)]
                pub domain: Option<String>,
            }
            /// [`FindAccountRecoveryPolicyByAlias`] query resolves the alias-keyed recovery policy.
            #[derive(Display)]
            #[display("Find recovery policy for alias `{alias:?}`")]
            #[repr(transparent)]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountRecoveryPolicyByAlias")]
            pub struct FindAccountRecoveryPolicyByAlias {
                /// Stable account alias whose recovery policy should be loaded.
                pub alias: crate::account::AccountAlias,
            }
            /// [`FindAccountRecoveryRequestByAlias`] query resolves the alias-keyed recovery request.
            #[derive(Display)]
            #[display("Find recovery request for alias `{alias:?}`")]
            #[repr(transparent)]
            #[norito_schema(name = "iroha_data_model::query::account::model::FindAccountRecoveryRequestByAlias")]
            pub struct FindAccountRecoveryRequestByAlias {
                /// Stable account alias whose recovery request should be loaded.
                pub alias: crate::account::AccountAlias,
            }
        }
    impl FindAccountsWithAsset {
        /// Return the queried asset definition identifier.
        pub fn asset_definition_id(&self) -> &AssetDefinitionId {
            &self.asset_definition
        }
    }
    impl FindAccountById {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &crate::account::AccountId {
            &self.id
        }
    }
    impl FindAccountByAlias {
        /// Return the queried stable alias.
        pub fn alias(&self) -> &crate::account::AccountAlias {
            &self.alias
        }
    }
    impl FindAliasesByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &crate::account::AccountId {
            &self.id
        }
        /// Return the optional dataspace alias filter.
        pub fn dataspace(&self) -> Option<&str> {
            self.dataspace.as_deref()
        }
        /// Return the optional domain filter.
        pub fn domain(&self) -> Option<&str> {
            self.domain.as_deref()
        }
    }
    impl FindAccountRecoveryPolicyByAlias {
        /// Return the queried stable alias.
        pub fn alias(&self) -> &crate::account::AccountAlias {
            &self.alias
        }
    }
    impl FindAccountRecoveryRequestByAlias {
        /// Return the queried stable alias.
        pub fn alias(&self) -> &crate::account::AccountAlias {
            &self.alias
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{
            AccountAliasBindingRecord, FindAccountByAlias, FindAccountById, FindAccountIds,
            FindAccountRecoveryPolicyByAlias, FindAccountRecoveryRequestByAlias, FindAccounts,
            FindAccountsWithAsset, FindAliasesByAccountId,
        };
    }

    #[cfg(test)]
    mod captured_domain_queries_schema_tests;
}
pub mod asset {
    //! Asset-related query definitions.
    //!
    //! Queries related to [`crate::asset`].
    #![allow(clippy::missing_inline_in_public_items)]
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    // Bring required IDs into scope for queries! items
    use crate::{AccountId, AssetId, asset::AssetDefinitionId};
    queries! {
        /// [`FindAssets`] Iroha Query finds all `Asset`s presented.
        #[derive(Copy, Display)]
        #[display("Find all assets")]
        #[norito_schema(name = "iroha_data_model::query::asset::model::FindAssets")]
        pub struct FindAssets;
        /// [`FindAssetDefinitions`] Iroha Query finds all `AssetDefinition`s presented.
        #[derive(Copy, Display)]
        #[display("Find all asset definitions")]
        #[norito_schema(name = "iroha_data_model::query::asset::model::FindAssetDefinitions")]
        pub struct FindAssetDefinitions;
        /// [`FindAssetsByAccountId`] Iroha Query finds all `Asset`s owned by an account.
        #[derive(Display)]
        #[display("Find assets owned by `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::asset::model::FindAssetsByAccountId")]
        pub struct FindAssetsByAccountId {
            /// Identifier of the account that owns the assets.
            pub id: AccountId,
        }
        /// [`FindAssetById`] Iroha Query finds a specific `Asset` by identifier.
        #[derive(Display)]
        #[display("Find asset `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::asset::model::FindAssetById")]
        pub struct FindAssetById {
            /// Identifier of the asset to look up.
            pub id: AssetId,
        }
        /// [`FindAssetDefinitionById`] Iroha Query finds a specific `AssetDefinition` by identifier.
        #[derive(Display)]
        #[display("Find asset definition `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::asset::model::FindAssetDefinitionById")]
        pub struct FindAssetDefinitionById {
            /// Identifier of the asset definition to look up.
            pub id: AssetDefinitionId,
        }
        /// [`FindAssetDefinitionDirectHome`] Iroha Query finds the immutable direct dataspace
        /// home row of one live asset definition incarnation.
        #[derive(Display)]
        #[display("Find direct home of asset definition `{id}`")]
        #[repr(transparent)]
        #[norito_schema(
            name = "iroha_data_model::query::asset::model::FindAssetDefinitionDirectHome"
        )]
        pub struct FindAssetDefinitionDirectHome {
            /// Identifier of the directly homed asset definition.
            pub id: AssetDefinitionId,
        }
    }
    impl FindAssetById {
        /// Return the queried asset identifier.
        pub fn asset_id(&self) -> &AssetId {
            &self.id
        }
    }
    impl FindAssetDefinitionById {
        /// Return the queried asset definition identifier.
        pub fn asset_definition_id(&self) -> &AssetDefinitionId {
            &self.id
        }
    }
    impl FindAssetDefinitionDirectHome {
        /// Return the queried asset definition identifier.
        pub fn asset_definition_id(&self) -> &AssetDefinitionId {
            &self.id
        }
    }
    impl FindAssetsByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &AccountId {
            &self.id
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{
            FindAssetById, FindAssetDefinitionById, FindAssetDefinitionDirectHome,
            FindAssetDefinitions, FindAssets, FindAssetsByAccountId,
        };
    }
}
pub mod repo {
    //! Repository-related query definitions.
    //!
    //! Queries related to [`crate::repo`].
    use derive_more::Display;
    queries! {
        /// [`FindRepoAgreements`] Iroha Query finds all repo agreements stored on-chain.
        #[derive(Copy, Display)]
        #[display("Find all repo agreements")]
        #[norito_schema(name = "iroha_data_model::query::repo::model::FindRepoAgreements")]
        pub struct FindRepoAgreements;
    }
    pub mod prelude {
        //! Prelude re-export for repo queries.
        pub use super::FindRepoAgreements;
    }
}
pub mod escrow {
    //! Native asset escrow query definitions.
    use crate::{
        account::AccountId,
        escrow::{AssetEscrowStatus, EscrowId},
    };
    use derive_more::Display;
    queries! {
        /// Find all native asset escrow records.
        #[derive(Copy, Display)]
        #[display("Find all asset escrows")]
        #[norito_schema(name = "iroha_data_model::query::escrow::model::FindAssetEscrows")]
        pub struct FindAssetEscrows;
        /// Find a native asset escrow by identifier.
        #[derive(Display)]
        #[display("Find asset escrow `{escrow_id:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::escrow::model::FindAssetEscrowById")]
        pub struct FindAssetEscrowById {
            /// Escrow identifier.
            pub escrow_id: EscrowId,
        }
        /// Find native asset escrows opened by a seller.
        #[derive(Display)]
        #[display("Find asset escrows by seller `{seller}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::escrow::model::FindAssetEscrowsBySeller")]
        pub struct FindAssetEscrowsBySeller {
            /// Seller account identifier.
            pub seller: AccountId,
        }
        /// Find native asset escrows accepted by a buyer.
        #[derive(Display)]
        #[display("Find asset escrows by buyer `{buyer}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::escrow::model::FindAssetEscrowsByBuyer")]
        pub struct FindAssetEscrowsByBuyer {
            /// Buyer account identifier.
            pub buyer: AccountId,
        }
        /// Find native asset escrows by lifecycle status.
        #[derive(Display)]
        #[display("Find asset escrows by status `{status:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::escrow::model::FindAssetEscrowsByStatus")]
        pub struct FindAssetEscrowsByStatus {
            /// Lifecycle status filter.
            pub status: AssetEscrowStatus,
        }
    }
    pub mod prelude {
        //! Prelude re-exports for native asset escrow queries.
        pub use super::{
            FindAssetEscrowById, FindAssetEscrows, FindAssetEscrowsByBuyer,
            FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
        };
    }
}
pub mod oracle {
    //! Oracle-specific query definitions.
    use crate::{
        nexus::UniversalAccountId,
        oracle::{
            DefiOracleAttestationKey, FeedId, KeyedHash, OracleChangeId, OracleDisputeId,
            OracleProviderKey,
        },
    };
    use derive_more::Display;
    queries! {
        /// Find all registered oracle feeds.
        #[derive(Copy, Display)]
        #[display("Find oracle feeds")]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleFeeds")]
        pub struct FindOracleFeeds;
        /// Find a registered oracle feed by id.
        #[derive(Display)]
        #[display("Find oracle feed `{feed_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleFeedById")]
        pub struct FindOracleFeedById {
            /// Feed identifier to look up.
            pub feed_id: FeedId,
        }
        /// Find retained oracle history for a feed.
        #[derive(Display)]
        #[display("Find oracle history for feed `{feed_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleHistoryByFeedId")]
        pub struct FindOracleHistoryByFeedId {
            /// Feed identifier whose history should be returned.
            pub feed_id: FeedId,
        }
        /// Find provider statistics for one feed.
        #[derive(Display)]
        #[display("Find oracle provider stats for feed `{feed_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleProviderStatsByFeedId")]
        pub struct FindOracleProviderStatsByFeedId {
            /// Feed identifier whose provider stats should be returned.
            pub feed_id: FeedId,
        }
        /// Find provider statistics by exact feed/provider key.
        #[derive(Display)]
        #[display("Find oracle provider stats `{key:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleProviderStatsByKey")]
        pub struct FindOracleProviderStatsByKey {
            /// Provider statistics key.
            pub key: OracleProviderKey,
        }
        /// Find all oracle disputes.
        #[derive(Copy, Display)]
        #[display("Find oracle disputes")]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleDisputes")]
        pub struct FindOracleDisputes;
        /// Find an oracle dispute by id.
        #[derive(Display)]
        #[display("Find oracle dispute `{dispute_id:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleDisputeById")]
        pub struct FindOracleDisputeById {
            /// Dispute identifier to look up.
            pub dispute_id: OracleDisputeId,
        }
        /// Find oracle disputes for a feed.
        #[derive(Display)]
        #[display("Find oracle disputes for feed `{feed_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleDisputesByFeedId")]
        pub struct FindOracleDisputesByFeedId {
            /// Feed identifier whose disputes should be returned.
            pub feed_id: FeedId,
        }
        /// Find all oracle change proposals.
        #[derive(Copy, Display)]
        #[display("Find oracle changes")]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleChanges")]
        pub struct FindOracleChanges;
        /// Find an oracle change proposal by id.
        #[derive(Display)]
        #[display("Find oracle change `{change_id:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindOracleChangeById")]
        pub struct FindOracleChangeById {
            /// Oracle change identifier to look up.
            pub change_id: OracleChangeId,
        }
        /// Find twitter binding records by universal account id.
        #[derive(Display)]
        #[display("Find twitter bindings for `{uaid:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindTwitterBindingsByUaid")]
        pub struct FindTwitterBindingsByUaid {
            /// Universal account id to look up.
            pub uaid: UniversalAccountId,
        }
        /// Find a twitter binding by keyed hash.
        #[derive(Display)]
        #[display("Find twitter binding `{binding_hash:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindTwitterBindingByHash")]
        pub struct FindTwitterBindingByHash {
            /// Pseudonymous keyed hash used to look up the binding.
            pub binding_hash: KeyedHash,
        }
        /// Find retained `DeFi` oracle attestations for a domain and subject id.
        #[derive(Display)]
        #[display("Find DeFi oracle attestations for `{key:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindDefiOracleAttestationsByKey")]
        pub struct FindDefiOracleAttestationsByKey {
            /// Domain and subject id key.
            pub key: DefiOracleAttestationKey,
        }
        /// Find the latest `DeFi` oracle attestation for a domain and subject id.
        #[derive(Display)]
        #[display("Find latest DeFi oracle attestation for `{key:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::oracle::model::FindLatestDefiOracleAttestation")]
        pub struct FindLatestDefiOracleAttestation {
            /// Domain and subject id key.
            pub key: DefiOracleAttestationKey,
        }
    }
    impl FindTwitterBindingByHash {
        /// Return the keyed hash identifying the binding.
        pub fn binding_hash(&self) -> &KeyedHash {
            &self.binding_hash
        }
    }
    pub mod prelude {
        //! Prelude re-exports for oracle queries.
        pub use super::{
            FindDefiOracleAttestationsByKey, FindLatestDefiOracleAttestation, FindOracleChangeById,
            FindOracleChanges, FindOracleDisputeById, FindOracleDisputes,
            FindOracleDisputesByFeedId, FindOracleFeedById, FindOracleFeeds,
            FindOracleHistoryByFeedId, FindOracleProviderStatsByFeedId,
            FindOracleProviderStatsByKey, FindTwitterBindingByHash, FindTwitterBindingsByUaid,
        };
    }
}
pub mod da {
    //! Data availability pin intent query definitions.
    //!
    //! Queries for retrieving DA pin intents stored in the `SoraFS` registry surface.
    use crate::{da::types::StorageTicketId, sorafs::pin_registry::ManifestDigest};
    use iroha_model_base::topology::LaneId;
    queries! {
        /// Fetch a DA pin intent by its storage ticket.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::da::model::FindDaPinIntentByTicket")]
        pub struct FindDaPinIntentByTicket {
            /// Storage ticket to look up.
            pub storage_ticket: StorageTicketId,
        }
        /// Fetch a DA pin intent by its manifest digest.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::da::model::FindDaPinIntentByManifest")]
        pub struct FindDaPinIntentByManifest {
            /// Manifest digest to look up.
            pub manifest_hash: ManifestDigest,
        }
        /// Fetch a DA pin intent by its alias.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::da::model::FindDaPinIntentByAlias")]
        pub struct FindDaPinIntentByAlias {
            /// Alias to look up.
            pub alias: String,
        }
        /// Fetch a DA pin intent by lane/epoch/sequence tuple.
        #[norito_schema(name = "iroha_data_model::query::da::model::FindDaPinIntentByLaneEpochSequence")]
        pub struct FindDaPinIntentByLaneEpochSequence {
            /// Lane identifier associated with the intent.
            pub lane_id: LaneId,
            /// Epoch containing the intent.
            pub epoch: u64,
            /// Sequence number within the lane/epoch.
            pub sequence: u64,
        }
    }
    pub mod prelude {
        //! Prelude re-exports for DA pin intent queries.
        pub use super::{
            FindDaPinIntentByAlias, FindDaPinIntentByLaneEpochSequence, FindDaPinIntentByManifest,
            FindDaPinIntentByTicket,
        };
    }
}
pub mod settlement {
    //! Native settlement query definitions.
    use crate::isi::SettlementId;
    use iroha_model_base::name::Name;
    queries! {
        /// Fetch an immutable native settlement receipt by its business identifier.
        ///
        /// The native executor requires ledger-wide read permission because a receipt
        /// can contain movements belonging to multiple accounts and dataspaces.
        #[repr(transparent)]
        #[norito(deny_unknown_fields)]
        #[norito_schema(name = "iroha_data_model::query::settlement::model::FindSettlementReceiptById")]
        pub struct FindSettlementReceiptById {
            /// Exact committed business settlement identifier.
            pub id: SettlementId,
        }
        /// Fetch the complete protected native FX corridor policy registry.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::settlement::model::FindFxCorridorPolicyRegistry")]
        pub struct FindFxCorridorPolicyRegistry;
        /// Fetch one native FX corridor policy by its stable identifier.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::settlement::model::FindFxCorridorPolicyById")]
        pub struct FindFxCorridorPolicyById {
            /// Policy identifier to look up.
            pub policy_id: Name,
        }
    }
    impl FindFxCorridorPolicyById {
        /// Return the queried policy identifier.
        pub fn policy_id(&self) -> &Name {
            &self.policy_id
        }
    }
    pub mod prelude {
        //! Prelude re-exports for native settlement queries.
        pub use super::{
            FindFxCorridorPolicyById, FindFxCorridorPolicyRegistry, FindSettlementReceiptById,
        };
    }
}
pub mod nexus {
    //! Nexus query definitions.
    use crate::{AccountId, nexus::FeeSponsorProgramId};
    queries! {
        /// Find all fee sponsor programs.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::nexus::model::FindFeeSponsorPrograms")]
        pub struct FindFeeSponsorPrograms;
        /// Find all fee sponsor program identifiers.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::nexus::model::FindFeeSponsorProgramIds")]
        pub struct FindFeeSponsorProgramIds;
        /// Find all fee sponsor programs owned by a sponsor account.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::nexus::model::FindFeeSponsorProgramsBySponsor")]
        pub struct FindFeeSponsorProgramsBySponsor {
            /// Sponsor account identifier.
            pub sponsor: AccountId,
        }
        /// Fetch one fee sponsor program by identifier.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::nexus::model::FindFeeSponsorProgramById")]
        pub struct FindFeeSponsorProgramById {
            /// Program identifier to look up.
            pub id: FeeSponsorProgramId,
        }
    }
    impl FindFeeSponsorProgramsBySponsor {
        /// Return the sponsor account identifier.
        pub fn sponsor(&self) -> &AccountId {
            &self.sponsor
        }
    }
    impl FindFeeSponsorProgramById {
        /// Return the queried program identifier.
        pub fn id(&self) -> &FeeSponsorProgramId {
            &self.id
        }
    }
    pub mod prelude {
        //! Prelude re-exports for Nexus queries.
        pub use super::{
            FindFeeSponsorProgramById, FindFeeSponsorProgramIds, FindFeeSponsorPrograms,
            FindFeeSponsorProgramsBySponsor,
        };
    }
}
pub mod nft {
    //! NFT-related query definitions.
    //!
    //! Queries related to [`crate::nft`].
    use crate::{AccountId, NftId};
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindNftById`] finds one `Nft` by its canonical identifier.
        #[derive(Display)]
        #[display("Find NFT `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::nft::model::FindNftById")]
        pub struct FindNftById {
            /// Canonical identifier of the NFT to find.
            pub id: NftId,
        }
        /// [`FindNfts`] Iroha Query finds all `Nft`s presented.
        #[derive(Copy, Display)]
        #[display("Find all NFTs")]
        #[norito_schema(name = "iroha_data_model::query::nft::model::FindNfts")]
        pub struct FindNfts;
        /// [`FindNftsByAccountId`] Iroha Query finds all `Nft`s owned by an account.
        #[derive(Display)]
        #[display("Find NFTs owned by `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::nft::model::FindNftsByAccountId")]
        pub struct FindNftsByAccountId {
            /// Identifier of the account that owns the NFTs.
            pub id: AccountId,
        }
    }
    impl FindNftById {
        /// Return the queried NFT identifier.
        pub fn nft_id(&self) -> &NftId {
            &self.id
        }
    }
    impl FindNftsByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &AccountId {
            &self.id
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{FindNftById, FindNfts, FindNftsByAccountId};
    }
}
pub mod rwa {
    //! RWA-related query definitions.
    //!
    //! Queries related to [`crate::rwa`].
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindRwas`] finds all registered RWA lots.
        #[derive(Copy, Display)]
        #[display("Find all RWAs")]
        #[norito_schema(name = "iroha_data_model::query::rwa::model::FindRwas")]
        pub struct FindRwas;
    }
    pub mod prelude {
        //! Prelude re-exports for RWA queries.
        pub use super::FindRwas;
    }
}
pub mod domain {
    //! Domain-related query definitions.
    //!
    //! Queries related to [`crate::domain`].
    #![allow(clippy::missing_inline_in_public_items)]
    use crate::AccountId;
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindDomainById`] Iroha Query finds a `Domain` by its identifier.
        #[derive(Display)]
        #[display("Find domain `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::domain::model::FindDomainById")]
        pub struct FindDomainById {
            /// Fully qualified domain identifier to resolve.
            pub id: iroha_model_base::domain::DomainId,
        }
        /// [`FindDomains`] Iroha Query finds all `Domain`s presented.
        #[derive(Copy, Display)]
        #[display("Find all domains")]
        #[norito_schema(name = "iroha_data_model::query::domain::model::FindDomains")]
        pub struct FindDomains;
        /// [`FindDomainsByAccountId`] Iroha Query finds all `Domain`s owned by an account.
        #[derive(Display)]
        #[display("Find domains owned by `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::domain::model::FindDomainsByAccountId")]
        pub struct FindDomainsByAccountId {
            /// Identifier of the account that owns the domains.
            pub id: AccountId,
        }
    }
    impl FindDomainById {
        /// Return the queried domain identifier.
        pub fn domain_id(&self) -> &iroha_model_base::domain::DomainId {
            &self.id
        }
    }
    impl FindDomainsByAccountId {
        /// Return the queried account identifier.
        pub fn account_id(&self) -> &AccountId {
            &self.id
        }
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{FindDomainById, FindDomains, FindDomainsByAccountId};
    }
}
pub mod endorsement {
    //! Domain endorsement-related query definitions.
    //!
    //! Queries related to domain endorsement committees and policies.
    use derive_more::Display;
    use iroha_model_base::domain::DomainId;
    queries! {
        /// Fetch all recorded endorsements for a given domain.
        #[derive(Display)]
        #[display("Find endorsements for domain `{domain_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::endorsement::model::FindDomainEndorsements")]
        pub struct FindDomainEndorsements {
            /// Domain identifier to filter by.
            pub domain_id: DomainId,
        }
        /// Fetch the configured endorsement policy for a domain.
        #[derive(Display)]
        #[display("Find endorsement policy for domain `{domain_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::endorsement::model::FindDomainEndorsementPolicy")]
        pub struct FindDomainEndorsementPolicy {
            /// Domain identifier to fetch the policy for.
            pub domain_id: DomainId,
        }
        /// Fetch a domain endorsement committee by identifier.
        #[derive(Display)]
        #[display("Find domain committee `{committee_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::endorsement::model::FindDomainCommittee")]
        pub struct FindDomainCommittee {
            /// Committee identifier.
            pub committee_id: String,
        }
    }
    /// Prelude re-exports for endorsement queries.
    pub mod prelude {
        pub use super::{FindDomainCommittee, FindDomainEndorsementPolicy, FindDomainEndorsements};
    }
}
pub mod peer {
    //! Peer-related query definitions.
    //!
    //! Queries related to [`crate::peer`].
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindPeers`] Iroha Query finds all trusted peers presented.
        #[derive(Copy, Display)]
        #[display("Find all peers")]
        #[norito_schema(name = "iroha_data_model::query::peer::model::FindPeers")]
        pub struct FindPeers;
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::FindPeers;
    }
}
pub mod executor {
    //! Executor-related query definitions.
    //!
    //! Queries related to [`crate::executor`].
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindExecutorDataModel`] Iroha Query finds the data model of the current executor.
        #[derive(Copy, Display)]
        #[display("Find executor data model")]
        #[norito_schema(name = "iroha_data_model::query::executor::model::FindExecutorDataModel")]
        pub struct FindExecutorDataModel;
        /// [`FindParameters`] Iroha Query finds all defined executor configuration parameters.
        #[derive(Copy, Display)]
        #[display("Find all peers parameters")]
        #[norito_schema(name = "iroha_data_model::query::executor::model::FindParameters")]
        pub struct FindParameters;
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{FindExecutorDataModel, FindParameters};
    }
}
pub mod runtime {
    //! Runtime inspector query definitions.
    //!
    //! Queries related to runtime/ABI.
    use derive_more::Display;
    queries! {
        /// Find the active ABI version.
        #[derive(Copy, Display)]
        #[display("Find active ABI version")]
        #[norito_schema(name = "iroha_data_model::query::runtime::model::FindAbiVersion")]
        pub struct FindAbiVersion;
    }
    /// Response type for `FindAbiVersion` query.
    ///
    /// Query for the ABI version currently active on the chain.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        norito::codec::Decode,
        norito::codec::Encode,
        iroha_schema::IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::query::runtime::AbiVersion")]
    pub struct AbiVersion {
        /// The ABI version currently active on the node.
        pub abi_version: u16,
    }
    pub mod prelude {
        //! Prelude re-exports.
        pub use super::FindAbiVersion;
    }

    #[cfg(test)]
    mod captured_domain_queries_schema_tests;
}
pub mod proof {
    //! Proof-related query definitions.
    //!
    //! Queries related to zero-knowledge proofs and records.
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// Find a proof verification record by its identifier.
        #[derive(Display)]
        #[display("Find proof record by `{id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::proof::model::FindProofRecordById")]
        pub struct FindProofRecordById {
            /// Proof identifier (backend + proof hash).
            pub id: crate::proof::ProofId,
        }
        /// Find all proof verification records.
        #[derive(Copy, Display)]
        #[display("Find all proof records")]
        #[norito_schema(name = "iroha_data_model::query::proof::model::FindProofRecords")]
        pub struct FindProofRecords;
        /// Find all proof verification records for a given backend identifier.
        #[derive(Display)]
        #[display("Find proof records for backend `{backend}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::proof::model::FindProofRecordsByBackend")]
        pub struct FindProofRecordsByBackend {
            /// Backend identifier (e.g., "halo2/ipa").
            pub backend: iroha_schema::Ident,
        }
        /// Find all proof verification records for a given status.
        #[derive(Display)]
        #[display("Find proof records with status `{status:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::proof::model::FindProofRecordsByStatus")]
        pub struct FindProofRecordsByStatus {
            /// Proof verification status to filter by.
            pub status: crate::proof::ProofStatus,
        }
    }
    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{
            FindProofRecordById, FindProofRecords, FindProofRecordsByBackend,
            FindProofRecordsByStatus,
        };
    }
}
pub mod sorafs {
    //! `SoraFS` query definitions.
    //!
    //! Queries related to `SoraFS` provider metadata.
    use crate::{
        account::AccountId,
        sorafs::{
            capacity::ProviderId,
            moderation_ledger::{
                ModerationFinalizedCursorV1, ModerationFinalizedEventCursorV1,
                RepairFinalizedCursorV1, RepairFinalizedEventCursorV1,
            },
            orderbook::{
                OrderbookFinalizedCursorV1, OrderbookFinalizedEventCursorV1,
                OrderbookOrderStatusV1, OrderbookSettlementChannelStatusV1,
            },
            pin_registry::{ManifestDigest, PinManifestFinalizedCursorV1, PinStatusKindV1},
            proof_ledger::{
                ProofOutcomeFinalizedCursorV1, ProofOutcomeFinalizedEventCursorV1,
                ProofOutcomeKindV1,
            },
            reputation::{
                ReputationJournalFinalizedCursorV1, ReputationJournalFinalizedEventCursorV1,
                ReputationJournalSourceIdV1,
            },
            reserve::{ReserveFinalizedCursorV1, ReserveFinalizedEventCursorV1},
        },
    };
    use hex;
    use std::{fmt, string::String};
    queries! {
        /// Fetch the registered owner for a `SoraFS` provider.
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsProviderOwner")]
        pub struct FindSorafsProviderOwner {
            /// Provider identifier to resolve.
            pub provider_id: ProviderId,
        }
        /// Fetch one chain-authoritative pin manifest at a finalized state anchor.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPinManifest")]
        pub struct FindSorafsPinManifest {
            /// Canonical manifest digest to resolve.
            pub digest: ManifestDigest,
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<PinManifestFinalizedCursorV1>,
        }
        /// Fetch a finalized exclusive-keyset page of bounded pin-manifest summaries.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPinManifests")]
        pub struct FindSorafsPinManifests {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<PinManifestFinalizedCursorV1>,
            /// Optional closed lifecycle filter backed by a consensus-maintained index.
            pub status: Option<PinStatusKindV1>,
            /// Exclusive manifest-digest cursor.
            pub after_digest: Option<ManifestDigest>,
            /// Requested row count, checked against the hard query ceiling.
            pub limit: u32,
            /// Requested encoded-page byte ceiling, checked against the hard query ceiling.
            pub max_bytes: u32,
        }
        /// Fetch the active authoritative `SoraFS` orderbook policy.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookPolicy")]
        pub struct FindSorafsOrderbookPolicy;
        /// Fetch an authoritative `SoraFS` order by its identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookOrderById")]
        pub struct FindSorafsOrderbookOrderById {
            /// Canonical order identifier.
            pub order_id: [u8; 32],
        }
        /// Fetch an admitted cancellation by the cancelled order identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookCancellationByOrderId")]
        pub struct FindSorafsOrderbookCancellationByOrderId {
            /// Canonical cancelled order identifier.
            pub order_id: [u8; 32],
        }
        /// Fetch an authoritative settlement receipt by its identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookReceiptById")]
        pub struct FindSorafsOrderbookReceiptById {
            /// Canonical settlement receipt identifier.
            pub receipt_id: [u8; 32],
        }
        /// Fetch an authoritative trade by its identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookTradeById")]
        pub struct FindSorafsOrderbookTradeById {
            /// Canonical trade identifier.
            pub trade_id: [u8; 32],
        }
        /// Fetch an authoritative settlement channel by its identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookChannelById")]
        pub struct FindSorafsOrderbookChannelById {
            /// Canonical settlement channel identifier.
            pub channel_id: [u8; 32],
        }
        /// Fetch constant-time authoritative orderbook counters.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookStatus")]
        pub struct FindSorafsOrderbookStatus;
        /// Fetch an exclusive-cursor, status-filtered page of authoritative orders.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookOrders")]
        pub struct FindSorafsOrderbookOrders {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<OrderbookFinalizedCursorV1>,
            /// Optional lifecycle filter.
            pub status: Option<OrderbookOrderStatusV1>,
            /// Exclusive order-id cursor.
            pub after_order_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-cursor page of authoritative settlement receipts.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookReceipts")]
        pub struct FindSorafsOrderbookReceipts {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<OrderbookFinalizedCursorV1>,
            /// Optional exact channel filter.
            pub channel_id: Option<[u8; 32]>,
            /// Exclusive receipt-id cursor.
            pub after_receipt_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-cursor page of authoritative trades.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookTrades")]
        pub struct FindSorafsOrderbookTrades {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<OrderbookFinalizedCursorV1>,
            /// Exclusive trade-id cursor.
            pub after_trade_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-cursor, status-filtered page of settlement channels.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookChannels")]
        pub struct FindSorafsOrderbookChannels {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<OrderbookFinalizedCursorV1>,
            /// Optional lifecycle filter.
            pub status: Option<OrderbookSettlementChannelStatusV1>,
            /// Exclusive channel-id cursor.
            pub after_channel_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-cursor page of committed orderbook events.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsOrderbookEvents")]
        pub struct FindSorafsOrderbookEvents {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<OrderbookFinalizedCursorV1>,
            /// Exclusive committed-event cursor.
            pub after: Option<OrderbookFinalizedEventCursorV1>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch the active authoritative reserve/rent policy.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReservePolicy")]
        pub struct FindSorafsReservePolicy;
        /// Fetch one provider reserve account.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveProviderById")]
        pub struct FindSorafsReserveProviderById {
            /// Provider registry identifier.
            pub provider_id: ProviderId,
        }
        /// Fetch one reserve movement by identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveMovementById")]
        pub struct FindSorafsReserveMovementById {
            /// Canonical movement identifier.
            pub movement_id: [u8; 32],
        }
        /// Fetch one reserve appeal by identifier.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveAppealById")]
        pub struct FindSorafsReserveAppealById {
            /// Canonical appeal identifier.
            pub appeal_id: [u8; 32],
        }
        /// Fetch an exclusive-provider-id page of authoritative reserve accounts.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveProviders")]
        pub struct FindSorafsReserveProviders {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReserveFinalizedCursorV1>,
            /// Exclusive provider-id cursor.
            pub after_provider_id: Option<ProviderId>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-movement-id page of authoritative reserve movements.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveMovements")]
        pub struct FindSorafsReserveMovements {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReserveFinalizedCursorV1>,
            /// Exclusive movement-id cursor.
            pub after_movement_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-appeal-id page of authoritative reserve appeals.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveAppeals")]
        pub struct FindSorafsReserveAppeals {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReserveFinalizedCursorV1>,
            /// Exclusive appeal-id cursor.
            pub after_appeal_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch an exclusive-cursor page of committed reserve-ledger events.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReserveEvents")]
        pub struct FindSorafsReserveEvents {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReserveFinalizedCursorV1>,
            /// Exclusive committed-event cursor.
            pub after: Option<ReserveFinalizedEventCursorV1>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch the active authoritative `PoP` issuer policy.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopIssuerPolicy")]
        pub struct FindSorafsPopIssuerPolicy;
        /// Fetch a payload-free credential record by its exact commitment.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopCredentialCommitmentByDigest")]
        pub struct FindSorafsPopCredentialCommitmentByDigest {
            /// Canonical signed-credential commitment.
            pub credential_commitment: [u8; 32],
        }
        /// Fetch a commitment-root publication by monotonic tree version.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopCommitmentRootByVersion")]
        pub struct FindSorafsPopCommitmentRootByVersion {
            /// Monotonic tree version.
            pub tree_version: u64,
        }
        /// Fetch a revocation publication by monotonic list version.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopRevocationPublicationByVersion")]
        pub struct FindSorafsPopRevocationPublicationByVersion {
            /// Monotonic revocation-list version.
            pub list_version: u64,
        }
        /// Fetch a revocation by the domain-separated private nonce commitment.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopRevocationByNonceCommitment")]
        pub struct FindSorafsPopRevocationByNonceCommitment {
            /// Domain-separated revocation-nonce commitment.
            pub revocation_nonce_commitment: [u8; 32],
        }
        /// Fetch one registry audit link by monotonic sequence.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopAuditDigestBySequence")]
        pub struct FindSorafsPopAuditDigestBySequence {
            /// Monotonic audit sequence.
            pub sequence: u64,
        }
        /// Fetch constant-time authoritative `PoP` registry anchors and counters.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsPopRegistryStatus")]
        pub struct FindSorafsPopRegistryStatus;
        /// Fetch one commitment-only citizen bond by its immutable serial commitment.
        #[derive(Copy)]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsCitizenBondBySerialCommitment")]
        pub struct FindSorafsCitizenBondBySerialCommitment {
            /// Immutable hidden bond serial commitment.
            pub serial_commitment: [u8; 32],
        }
        /// Fetch the current frozen citizen-bond membership snapshot.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsCitizenBondSnapshot")]
        pub struct FindSorafsCitizenBondSnapshot;
        /// Fetch one chain-authoritative repair task by canonical ticket identifier.
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsRepairTask")]
        pub struct FindSorafsRepairTask {
            /// Canonical repair ticket identifier.
            pub ticket_id: String,
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<RepairFinalizedCursorV1>,
        }
        /// Fetch an exclusive-cursor page of chain-authoritative repair tasks.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsRepairTasks")]
        pub struct FindSorafsRepairTasks {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<RepairFinalizedCursorV1>,
            /// Exclusive immutable task-id cursor.
            pub after_task_id: Option<[u8; 32]>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch constant-time chain-authoritative repair-ledger counters.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsRepairStatus")]
        pub struct FindSorafsRepairStatus {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<RepairFinalizedCursorV1>,
        }
        /// Fetch an exclusive-cursor page of committed repair-ledger events.
        ///
        /// A clean namespace with no repair status or events returns an empty
        /// page bound to the selected finalized cursor. Statusless orphaned
        /// repair state remains an error and fails closed.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsRepairEvents")]
        pub struct FindSorafsRepairEvents {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<RepairFinalizedCursorV1>,
            /// Exclusive committed-event cursor.
            pub after: Option<RepairFinalizedEventCursorV1>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch one finalized chain-authoritative PDP or `PoTR` proof outcome.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsProofOutcome")]
        pub struct FindSorafsProofOutcome {
            /// Proof protocol namespace for the exactly-once identity.
            pub kind: ProofOutcomeKindV1,
            /// Protocol-scoped challenge or request identity.
            pub identity_digest: [u8; 32],
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ProofOutcomeFinalizedCursorV1>,
        }
        /// Fetch an exclusive-cursor page of finalized PDP/PoTR proof-outcome events.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsProofOutcomeEvents")]
        pub struct FindSorafsProofOutcomeEvents {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ProofOutcomeFinalizedCursorV1>,
            /// Exclusive committed-event cursor.
            pub after: Option<ProofOutcomeFinalizedEventCursorV1>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch the active authoritative reputation-journal authority policy.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReputationJournalAuthorityPolicy")]
        pub struct FindSorafsReputationJournalAuthorityPolicy;
        /// Fetch one finalized reputation-journal event by authoritative source identifier.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReputationJournalEventBySourceId")]
        pub struct FindSorafsReputationJournalEventBySourceId {
            /// Domain-separated native source identifier.
            pub source_id: ReputationJournalSourceIdV1,
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReputationJournalFinalizedCursorV1>,
        }
        /// Fetch an exclusive-cursor page from the one global reputation journal.
        ///
        /// Each event exposes the authenticated source time and the distinct
        /// consensus-stamped recorded time.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsReputationJournalEvents")]
        pub struct FindSorafsReputationJournalEvents {
            /// Optional finalized anchor; absent selects the latest committed view.
            pub expected_finalized_cursor: Option<ReputationJournalFinalizedCursorV1>,
            /// Exclusive globally sequenced committed-event cursor.
            pub after: Option<ReputationJournalFinalizedEventCursorV1>,
            /// Requested page size; validated against the hard query ceiling.
            pub limit: u32,
        }
        /// Fetch the active authoritative moderation policy.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationPolicy")]
        pub struct FindSorafsModerationPolicy;
        /// Fetch one authoritative appeal-intake and sortition record.
        #[allow(
            clippy::struct_field_names,
            reason = "query model expansion cannot fulfill lint expectations; case and round are distinct keys"
        )]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationAppeal")]
        pub struct FindSorafsModerationAppeal {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
        }
        /// Fetch one payload-free `PoP` eligibility record.
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationJurorEligibility")]
        pub struct FindSorafsModerationJurorEligibility {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
            /// Canonical juror account.
            pub juror: AccountId,
        }
        /// Fetch one authoritative moderation case by case and round id.
        #[allow(
            clippy::struct_field_names,
            reason = "query model expansion cannot fulfill lint expectations; case and round are distinct keys"
        )]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationCase")]
        pub struct FindSorafsModerationCase {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
        }
        /// Fetch one authoritative juror commitment.
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationCommit")]
        pub struct FindSorafsModerationCommit {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
            /// Canonical juror account.
            pub juror: AccountId,
        }
        /// Fetch one authoritative juror reveal.
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationReveal")]
        pub struct FindSorafsModerationReveal {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
            /// Canonical juror account.
            pub juror: AccountId,
        }
        /// Fetch one authoritative challenge by case, round, and challenge id.
        #[allow(
            clippy::struct_field_names,
            reason = "query model expansion cannot fulfill lint expectations; case, round, and challenge are distinct keys"
        )]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationChallenge")]
        pub struct FindSorafsModerationChallenge {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
            /// Challenge identifier.
            pub challenge_id: String,
        }
        /// Fetch the terminal outcome for one case and round.
        #[allow(
            clippy::struct_field_names,
            reason = "query model expansion cannot fulfill lint expectations; case and round are distinct keys"
        )]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationOutcome")]
        pub struct FindSorafsModerationOutcome {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
        }
        /// Fetch one derived no-show penalty record.
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationNoShow")]
        pub struct FindSorafsModerationNoShow {
            /// Moderation case identifier.
            pub case_id: String,
            /// Ballot round identifier.
            pub round_id: String,
            /// Canonical juror account.
            pub juror: AccountId,
        }
        /// Fetch constant-time authoritative moderation-ledger counters.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationStatus")]
        pub struct FindSorafsModerationStatus;
        /// Fetch a complete bounded moderation projection at one finalized block.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationSnapshot")]
        pub struct FindSorafsModerationSnapshot {
            /// Maximum appeals and activated cases accepted in the projection.
            pub max_cases: u32,
            /// Maximum latest committed events accepted in the projection.
            pub max_events: u32,
        }
        /// Fetch a cursor-bounded page of committed moderation events.
        #[derive(Copy)]
        #[norito_schema(name = "iroha_data_model::query::sorafs::model::FindSorafsModerationEvents")]
        pub struct FindSorafsModerationEvents {
            /// Finalized anchor that must still identify the immutable state view.
            pub expected_finalized_cursor: ModerationFinalizedCursorV1,
            /// Exclusive committed-event cursor, when continuing a page.
            pub after: Option<ModerationFinalizedEventCursorV1>,
            /// Requested page size, checked against the hard query ceiling.
            pub limit: u32,
        }
    }
    impl fmt::Display for FindSorafsProviderOwner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS provider owner for `{}`",
                hex::encode(self.provider_id.as_bytes())
            )
        }
    }
    impl fmt::Display for FindSorafsPinManifest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find finalized SoraFS pin manifest `{}`",
                hex::encode(self.digest.as_bytes())
            )
        }
    }
    impl fmt::Display for FindSorafsPinManifests {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find finalized SoraFS pin manifests with row limit {} and byte limit {}",
                self.limit, self.max_bytes
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookPolicy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find active SoraFS orderbook policy")
        }
    }
    impl fmt::Display for FindSorafsOrderbookOrderById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook order `{}`",
                hex::encode(self.order_id)
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookCancellationByOrderId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook cancellation for `{}`",
                hex::encode(self.order_id)
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookReceiptById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook receipt `{}`",
                hex::encode(self.receipt_id)
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookTradeById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook trade `{}`",
                hex::encode(self.trade_id)
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookChannelById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook channel `{}`",
                hex::encode(self.channel_id)
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find SoraFS orderbook status")
        }
    }
    impl fmt::Display for FindSorafsOrderbookOrders {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS orderbook orders with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsOrderbookReceipts {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook receipts with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookTrades {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS orderbook trades with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsOrderbookChannels {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS orderbook settlement channels with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsOrderbookEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find committed SoraFS orderbook events with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsReservePolicy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find active SoraFS reserve policy")
        }
    }
    impl fmt::Display for FindSorafsReserveProviderById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS reserve provider `{}`", self.provider_id)
        }
    }
    impl fmt::Display for FindSorafsReserveMovementById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS reserve movement `{}`",
                hex::encode(self.movement_id)
            )
        }
    }
    impl fmt::Display for FindSorafsReserveAppealById {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS reserve appeal `{}`",
                hex::encode(self.appeal_id)
            )
        }
    }
    impl fmt::Display for FindSorafsReserveProviders {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS reserve providers with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsReserveMovements {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS reserve movements with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsReserveAppeals {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS reserve appeals with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsReserveEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find committed SoraFS reserve events with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsPopIssuerPolicy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find active SoraFS PoP issuer policy")
        }
    }
    impl fmt::Display for FindSorafsPopCredentialCommitmentByDigest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS PoP credential commitment `{}`",
                hex::encode(self.credential_commitment)
            )
        }
    }
    impl fmt::Display for FindSorafsPopCommitmentRootByVersion {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS PoP commitment root version {}",
                self.tree_version
            )
        }
    }
    impl fmt::Display for FindSorafsPopRevocationPublicationByVersion {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS PoP revocation publication version {}",
                self.list_version
            )
        }
    }
    impl fmt::Display for FindSorafsPopRevocationByNonceCommitment {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS PoP revocation commitment `{}`",
                hex::encode(self.revocation_nonce_commitment)
            )
        }
    }
    impl fmt::Display for FindSorafsPopAuditDigestBySequence {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS PoP registry audit sequence {}",
                self.sequence
            )
        }
    }
    impl fmt::Display for FindSorafsPopRegistryStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find SoraFS PoP registry status")
        }
    }
    impl fmt::Display for FindSorafsCitizenBondBySerialCommitment {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS citizen bond `{}`",
                hex::encode(self.serial_commitment)
            )
        }
    }
    impl fmt::Display for FindSorafsCitizenBondSnapshot {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find SoraFS citizen-bond snapshot")
        }
    }
    impl fmt::Display for FindSorafsRepairTask {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS repair task `{}`", self.ticket_id)
        }
    }
    impl fmt::Display for FindSorafsRepairTasks {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Find SoraFS repair tasks with limit {}", self.limit)
        }
    }
    impl fmt::Display for FindSorafsRepairStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find SoraFS repair ledger status")
        }
    }
    impl fmt::Display for FindSorafsRepairEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find committed SoraFS repair-ledger events with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsProofOutcome {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS {:?} proof outcome `{}`",
                self.kind,
                hex::encode(self.identity_digest)
            )
        }
    }
    impl fmt::Display for FindSorafsProofOutcomeEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find committed SoraFS proof-outcome events with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsReputationJournalAuthorityPolicy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find active SoraFS reputation-journal authority policy")
        }
    }
    impl FindSorafsReputationJournalEventBySourceId {
        /// Return the exact domain-separated source identifier.
        #[must_use]
        pub const fn source_id(&self) -> ReputationJournalSourceIdV1 {
            self.source_id
        }
        /// Return the optional immutable finalized-view anchor.
        #[must_use]
        pub const fn expected_finalized_cursor(
            &self,
        ) -> Option<ReputationJournalFinalizedCursorV1> {
            self.expected_finalized_cursor
        }
    }
    impl fmt::Display for FindSorafsReputationJournalEventBySourceId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find finalized SoraFS reputation-journal event for source `{}`",
                hex::encode(self.source_id.as_bytes())
            )
        }
    }
    impl fmt::Display for FindSorafsReputationJournalEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find committed SoraFS reputation-journal events with limit {}",
                self.limit
            )
        }
    }
    impl fmt::Display for FindSorafsModerationPolicy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find active SoraFS moderation policy")
        }
    }
    macro_rules! impl_moderation_case_display {
        ($ty:ty, $label:literal) => {
            impl fmt::Display for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(
                        f,
                        concat!($label, " `{}` round `{}`"),
                        self.case_id, self.round_id
                    )
                }
            }
        };
    }
    impl_moderation_case_display!(FindSorafsModerationCase, "Find SoraFS moderation case");
    impl_moderation_case_display!(FindSorafsModerationAppeal, "Find SoraFS moderation appeal");
    impl_moderation_case_display!(
        FindSorafsModerationOutcome,
        "Find SoraFS moderation outcome"
    );
    impl fmt::Display for FindSorafsModerationCommit {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation commit `{}` round `{}` juror `{}`",
                self.case_id, self.round_id, self.juror
            )
        }
    }
    impl fmt::Display for FindSorafsModerationJurorEligibility {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation eligibility `{}` round `{}` juror `{}`",
                self.case_id, self.round_id, self.juror
            )
        }
    }
    impl fmt::Display for FindSorafsModerationReveal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation reveal `{}` round `{}` juror `{}`",
                self.case_id, self.round_id, self.juror
            )
        }
    }
    impl fmt::Display for FindSorafsModerationChallenge {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation challenge `{}` for `{}` round `{}`",
                self.challenge_id, self.case_id, self.round_id
            )
        }
    }
    impl fmt::Display for FindSorafsModerationNoShow {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation no-show `{}` round `{}` juror `{}`",
                self.case_id, self.round_id, self.juror
            )
        }
    }
    impl fmt::Display for FindSorafsModerationStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Find SoraFS moderation ledger status")
        }
    }
    impl fmt::Display for FindSorafsModerationSnapshot {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation snapshot with at most {} cases and {} events",
                self.max_cases, self.max_events
            )
        }
    }
    impl fmt::Display for FindSorafsModerationEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Find SoraFS moderation events at finalized height {} with limit {}",
                self.expected_finalized_cursor.height, self.limit
            )
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn reputation_source_query_exposes_typed_fields() {
            let source_id = ReputationJournalSourceIdV1([0xA5; 32]);
            let cursor = ReputationJournalFinalizedCursorV1 {
                height: 7,
                block_hash: [0x5A; 32],
                finalized_at_unix_ms: 11,
            };
            let query = FindSorafsReputationJournalEventBySourceId::new(source_id, Some(cursor));
            assert_eq!(query.source_id(), source_id);
            assert_eq!(query.expected_finalized_cursor(), Some(cursor));
        }
    }
    /// Prelude re-exports for `SoraFS` queries.
    pub mod prelude {
        pub use super::{
            FindSorafsCitizenBondBySerialCommitment, FindSorafsCitizenBondSnapshot,
            FindSorafsModerationAppeal, FindSorafsModerationCase, FindSorafsModerationChallenge,
            FindSorafsModerationCommit, FindSorafsModerationEvents,
            FindSorafsModerationJurorEligibility, FindSorafsModerationNoShow,
            FindSorafsModerationOutcome, FindSorafsModerationPolicy, FindSorafsModerationReveal,
            FindSorafsModerationSnapshot, FindSorafsModerationStatus,
            FindSorafsOrderbookCancellationByOrderId, FindSorafsOrderbookChannelById,
            FindSorafsOrderbookChannels, FindSorafsOrderbookEvents, FindSorafsOrderbookOrderById,
            FindSorafsOrderbookOrders, FindSorafsOrderbookPolicy, FindSorafsOrderbookReceiptById,
            FindSorafsOrderbookReceipts, FindSorafsOrderbookStatus, FindSorafsOrderbookTradeById,
            FindSorafsOrderbookTrades, FindSorafsPinManifest, FindSorafsPinManifests,
            FindSorafsPopAuditDigestBySequence, FindSorafsPopCommitmentRootByVersion,
            FindSorafsPopCredentialCommitmentByDigest, FindSorafsPopIssuerPolicy,
            FindSorafsPopRegistryStatus, FindSorafsPopRevocationByNonceCommitment,
            FindSorafsPopRevocationPublicationByVersion, FindSorafsProofOutcome,
            FindSorafsProofOutcomeEvents, FindSorafsProviderOwner, FindSorafsRepairEvents,
            FindSorafsRepairStatus, FindSorafsRepairTask, FindSorafsRepairTasks,
            FindSorafsReputationJournalAuthorityPolicy, FindSorafsReputationJournalEventBySourceId,
            FindSorafsReputationJournalEvents, FindSorafsReserveAppealById,
            FindSorafsReserveAppeals, FindSorafsReserveEvents, FindSorafsReserveMovementById,
            FindSorafsReserveMovements, FindSorafsReservePolicy, FindSorafsReserveProviderById,
            FindSorafsReserveProviders,
        };
    }
}
impl seal::SingularQuery for sorafs::prelude::FindSorafsProviderOwner {}
impl SingularQuery for sorafs::prelude::FindSorafsProviderOwner {
    type Output = crate::account::AccountId;
    fn dyn_encode(&self) -> Vec<u8> {
        self.encode()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl seal::SingularQuery for sorafs::prelude::FindSorafsPinManifest {}
impl SingularQuery for sorafs::prelude::FindSorafsPinManifest {
    type Output = crate::sorafs::pin_registry::PinManifestFinalizedRecordV1;
    fn dyn_encode(&self) -> Vec<u8> {
        self.encode()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl seal::SingularQuery for sorafs::prelude::FindSorafsPinManifests {}
impl SingularQuery for sorafs::prelude::FindSorafsPinManifests {
    type Output = crate::sorafs::pin_registry::PinManifestPageV1;
    fn dyn_encode(&self) -> Vec<u8> {
        self.encode()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
macro_rules! impl_sorafs_orderbook_singular_query {
    ($query:ty => $output:ty) => {
        impl seal::SingularQuery for $query {}
        impl SingularQuery for $query {
            type Output = $output;
            fn dyn_encode(&self) -> Vec<u8> {
                self.encode()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
    };
}
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookPolicy
        => crate::sorafs::orderbook::OrderbookAdmissionPolicyRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookOrderById
        => crate::sorafs::orderbook::OrderbookOrderRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookCancellationByOrderId
        => crate::sorafs::orderbook::OrderbookCancellationRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookReceiptById
        => crate::sorafs::orderbook::OrderbookSettlementReceiptRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookTradeById
        => crate::sorafs::orderbook::OrderbookTradeRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookChannelById
        => crate::sorafs::orderbook::OrderbookSettlementChannelRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookStatus
        => crate::sorafs::orderbook::OrderbookLedgerStatusV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookOrders
        => crate::sorafs::orderbook::OrderbookOrderPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookReceipts
        => crate::sorafs::orderbook::OrderbookSettlementReceiptPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookTrades
        => crate::sorafs::orderbook::OrderbookTradePageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookChannels
        => crate::sorafs::orderbook::OrderbookSettlementChannelPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsOrderbookEvents
        => crate::sorafs::orderbook::OrderbookFinalizedEventPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReservePolicy
        => crate::sorafs::reserve::ReserveAuthorityPolicyRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveProviderById
        => crate::sorafs::reserve::ReserveProviderAccountV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveMovementById
        => crate::sorafs::reserve::ReserveMovementRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveAppealById
        => crate::sorafs::reserve::ReserveAppealRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveProviders
        => crate::sorafs::reserve::ReserveProviderAccountPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveMovements
        => crate::sorafs::reserve::ReserveMovementPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveAppeals
        => crate::sorafs::reserve::ReserveAppealPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReserveEvents
        => crate::sorafs::reserve::ReserveFinalizedEventPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopIssuerPolicy
        => crate::sorafs::pop_registry::PopIssuerPolicyRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopCredentialCommitmentByDigest
        => crate::sorafs::pop_registry::PopCredentialCommitmentRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopCommitmentRootByVersion
        => crate::sorafs::pop_registry::PopCommitmentRootRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopRevocationPublicationByVersion
        => crate::sorafs::pop_registry::PopRevocationPublicationRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopRevocationByNonceCommitment
        => crate::sorafs::pop_registry::PopRevocationRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopAuditDigestBySequence
        => crate::sorafs::pop_registry::PopRegistryAuditDigestRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsPopRegistryStatus
        => crate::sorafs::pop_registry::PopRegistryStatusV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsCitizenBondBySerialCommitment
        => crate::sorafs::anonymity::SorafsCitizenBondV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsCitizenBondSnapshot
        => crate::sorafs::anonymity::SorafsCitizenBondSnapshotV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsRepairTask
        => crate::sorafs::moderation_ledger::RepairFinalizedTaskV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsRepairTasks
        => crate::sorafs::moderation_ledger::RepairLedgerTaskPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsRepairStatus
        => crate::sorafs::moderation_ledger::RepairFinalizedStatusV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsRepairEvents
        => crate::sorafs::moderation_ledger::RepairFinalizedEventPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsProofOutcome
        => crate::sorafs::proof_ledger::ProofOutcomeFinalizedRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsProofOutcomeEvents
        => crate::sorafs::proof_ledger::ProofOutcomeFinalizedEventPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy
        => crate::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReputationJournalEventBySourceId
        => crate::sorafs::reputation::ReputationJournalFinalizedEventV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsReputationJournalEvents
        => crate::sorafs::reputation::ReputationJournalFinalizedEventPageV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationPolicy
        => crate::sorafs::moderation_ledger::ModerationLedgerPolicyRecord
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationAppeal
        => crate::sorafs::moderation_ledger::ModerationAppealRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationJurorEligibility
        => crate::sorafs::moderation_ledger::ModerationJurorEligibilityRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationCase
        => crate::sorafs::moderation_ledger::ModerationCaseRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationCommit
        => crate::sorafs::moderation_ledger::ModerationCommitRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationReveal
        => crate::sorafs::moderation_ledger::ModerationRevealRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationChallenge
        => crate::sorafs::moderation_ledger::ModerationChallengeRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationOutcome
        => crate::sorafs::moderation_ledger::ModerationOutcomeRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationNoShow
        => crate::sorafs::moderation_ledger::ModerationNoShowRecordV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationStatus
        => crate::sorafs::moderation_ledger::ModerationLedgerStatusV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationSnapshot
        => crate::sorafs::moderation_ledger::ModerationFinalizedLedgerSnapshotV1
);
impl_sorafs_orderbook_singular_query!(
    sorafs::prelude::FindSorafsModerationEvents
        => crate::sorafs::moderation_ledger::ModerationFinalizedEventPageV1
);

/// Generic game session query definitions.
pub mod game {
    use derive_more::Display;
    queries! {
        /// Read one session including certified frontier and terminal receipt.
        #[derive(Display)]
        #[display("Find native game session `{session_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::game::model::FindGameSessionById")]
        pub struct FindGameSessionById {
            /// Immutable session identifier.
            pub session_id: iroha_crypto::Hash,
        }
        /// Read one compact receipt identifying a proof in a finalized block.
        #[derive(Display)]
        #[display("Find execution proof verification `{verification_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::game::model::FindExecutionProofVerificationById")]
        pub struct FindExecutionProofVerificationById {
            /// Network-bound profile and statement receipt identifier.
            pub verification_id: iroha_crypto::Hash,
        }
    }
    /// Generic game session and proof-receipt query exports.
    pub mod prelude {
        pub use super::{FindExecutionProofVerificationById, FindGameSessionById};
    }
}

/// Native exact-price NFT offer lookups.
pub mod nft_market {
    use derive_more::Display;
    queries! {
        /// Read complete immutable sale terms and the retained terminal decision.
        #[derive(Display)]
        #[display("Find native NFT offer `{offer_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::nft_market::model::FindNftSaleOfferById")]
        pub struct FindNftSaleOfferById {
            /// Exact permanent offer identifier.
            pub offer_id: iroha_crypto::Hash,
        }
    }
    /// Native NFT marketplace query exports.
    pub mod prelude {
        pub use super::FindNftSaleOfferById;
    }
}
