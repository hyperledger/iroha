//! Data event definitions used across the Iroha ledger.
pub use self::model::*;
use super::*;
use getset::Getters;
use iroha_data_model_derive::{EventSet, HasOrigin, model};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use norito::json::{self, JsonDeserialize, JsonSerialize};
use std::{fmt, string::String, vec::Vec};
macro_rules! data_event {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($body:tt)* }) => {
        iroha_data_model_derive::model_single! {
            #[derive(
                Debug,
                Clone,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                HasOrigin,
                EventSet,
                Decode,
                Encode,
                norito::NoritoSchema,
                iroha_schema::IntoSchema,
            )]
            $(#[$meta])* $vis enum $name { $($body)* }
        }

        impl_json_via_norito_bytes!($name);
    };
}
// NOTE: if adding/editing events here, make sure to update the corresponding event filter in [`super::filter`]
#[model]
mod model {
    use super::*;
    /// Generic [`MetadataChanged`] struct.
    /// Contains the changed metadata (`(key, value)` pair), either inserted or removed, which is determined by the wrapping event.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, Getters)]
    #[getset(get = "pub")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::events::data::events::model::MetadataChanged")]
    pub struct MetadataChanged<Id> {
        pub target: Id,
        pub key: Name,
        pub value: Json,
    }
    /// Ledger data event with feature-independent wire discriminants.
    ///
    /// Optional capabilities reserve their discriminants even when disabled.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::events::model::DataEvent")]
    pub enum DataEvent {
        /// Peer event
        #[codec(index = 0)]
        Peer(peer::PeerEvent),
        /// Domain event
        #[codec(index = 1)]
        Domain(domain::DomainEvent),
        /// Account event without fabricated domain routing context.
        #[codec(index = 2)]
        Account(account::AccountEvent),
        /// Asset event without domain routing context.
        #[codec(index = 3)]
        Asset(asset::AssetEvent),
        /// Asset-definition event without domain routing context.
        #[codec(index = 4)]
        AssetDefinition(asset::AssetDefinitionEvent),
        /// Trigger event
        #[codec(index = 5)]
        Trigger(trigger::TriggerEvent),
        /// Role event
        #[codec(index = 6)]
        Role(role::RoleEvent),
        /// Configuration event
        #[codec(index = 7)]
        Configuration(config::ConfigurationEvent),
        /// Executor event
        #[codec(index = 8)]
        Executor(executor::ExecutorEvent),
        /// Zero-knowledge proof verification event
        #[codec(index = 9)]
        Proof(proof::ProofEvent),
        /// Verifying key registry lifecycle events
        #[codec(index = 10)]
        VerifyingKey(super::verifying_keys::VerifyingKeyEvent),
        /// Runtime upgrade lifecycle events
        #[codec(index = 11)]
        RuntimeUpgrade(super::runtime_upgrade::RuntimeUpgradeEvent),
        /// Smart contract registry events
        #[codec(index = 12)]
        SmartContract(super::smart_contract::SmartContractEvent),
        /// Resolver attestation directory governance events
        #[codec(index = 13)]
        Soradns(super::soradns::SoradnsDirectoryEvent),
        /// `SoraFS` gateway compliance events
        #[codec(index = 14)]
        Sorafs(super::sorafs::SorafsGatewayEvent),
        /// Musubi package-registry and archive lifecycle events
        #[codec(index = 15)]
        Musubi(super::musubi::MusubiEvent),
        /// Space Directory manifest lifecycle events
        #[codec(index = 16)]
        SpaceDirectory(super::space_directory::SpaceDirectoryEvent),
        /// Native asset escrow lifecycle events
        #[codec(index = 17)]
        Escrow(super::escrow::EscrowEvent),
        /// Oracle feed aggregation lifecycle events
        #[codec(index = 18)]
        Oracle(super::oracle::OracleEvent),
        #[cfg(feature = "governance")]
        /// Governance lifecycle events
        #[codec(index = 19)]
        Governance(super::governance::GovernanceEvent),
        /// Viral incentive lifecycle events
        #[codec(index = 20)]
        Social(super::social::SocialEvent),
        /// Bridge event
        #[codec(index = 21)]
        Bridge(bridge::BridgeEvent),
        /// Native race lifecycle transition.
        #[codec(index = 22)]
        GameSession(super::game::GameSessionEventV1),
        /// SCCP v1 cross-chain events (`specs/sccp.md` §4.17).
        #[codec(index = 23)]
        Sccp(crate::sccp::events::SccpEvent),
        /// Successful ordinary Load execution. Finality comes from the
        /// authenticated execution-result event commitment and its `CommitQC`.
        #[codec(index = 24)]
        KagemushaLoadCommitted(super::kagemusha::KagemushaLoadCommittedV1),
    }
}

impl<Id> JsonSerialize for MetadataChanged<Id>
where
    Id: JsonSerialize,
{
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("target", out);
        out.push(':');
        <Id as JsonSerialize>::json_serialize(&self.target, out);
        out.push(',');
        json::write_json_string("key", out);
        out.push(':');
        <Name as JsonSerialize>::json_serialize(&self.key, out);
        out.push(',');
        json::write_json_string("value", out);
        out.push(':');
        <Json as JsonSerialize>::json_serialize(&self.value, out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"target\":")?;
            <Id as JsonSerialize>::json_serialize_to(&self.target, out)?;
            out.push_str(",\"key\":")?;
            <Name as JsonSerialize>::json_serialize_to(&self.key, out)?;
            out.push_str(",\"value\":")?;
            <Json as JsonSerialize>::json_serialize_to(&self.value, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl<Id> JsonDeserialize for MetadataChanged<Id>
where
    Id: JsonDeserialize,
{
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut target: Option<Id> = None;
        let mut key: Option<Name> = None;
        let mut value: Option<Json> = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let field = parser.parse_key()?;
            match field.as_str() {
                "target" => {
                    if target.is_some() {
                        return Err(json::Error::duplicate_field("target"));
                    }
                    target = Some(<Id as JsonDeserialize>::json_deserialize(parser)?);
                }
                "key" => {
                    if key.is_some() {
                        return Err(json::Error::duplicate_field("key"));
                    }
                    key = Some(<Name as JsonDeserialize>::json_deserialize(parser)?);
                }
                "value" => {
                    if value.is_some() {
                        return Err(json::Error::duplicate_field("value"));
                    }
                    value = Some(<Json as JsonDeserialize>::json_deserialize(parser)?);
                }
                other => {
                    return Err(json::Error::unknown_field(other.to_owned()));
                }
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Ok(MetadataChanged {
            target: target.ok_or_else(|| json::Error::missing_field("target"))?,
            key: key.ok_or_else(|| json::Error::missing_field("key"))?,
            value: value.ok_or_else(|| json::Error::missing_field("value"))?,
        })
    }
}

impl_json_via_norito_bytes!(DataEvent);
mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls
    pub use self::model::*;
    use super::*;
    use iroha_data_model_derive::model;
    /// Metadata update associated with a specific asset instance.
    pub type AssetMetadataChanged = MetadataChanged<AssetId>;
    type AssetDefinitionMetadataChanged = MetadataChanged<AssetDefinitionId>;
    data_event! {
        #[has_origin(origin = Asset)]
        /// Event describing changes to an individual asset.
        #[norito_schema(name = "iroha_data_model::events::data::events::asset::AssetEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::asset::AssetEventSet")]
        pub enum AssetEvent {
            #[has_origin(asset => asset.id())]
            /// Asset instance was created.
            Created(Asset),
            /// Asset instance was deleted.
            Deleted(AssetId),
            #[has_origin(asset_changed => &asset_changed.asset)]
            /// Asset quantity increased.
            Added(AssetChanged),
            #[has_origin(asset_changed => &asset_changed.asset)]
            /// Asset quantity decreased.
            Removed(AssetChanged),
            #[has_origin(transfer => &transfer.source)]
            /// Asset quantity moved between two accounts.
            Transferred(AssetTransferred),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(AssetMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(AssetMetadataChanged),
            #[has_origin(outcome => &outcome.asset)]
            /// One ordered leg outcome from a native batch-transfer receipt.
            BatchTransferOutcome(AssetBatchTransferOutcome),
        }
    }
    data_event! {
        #[has_origin(origin = AssetDefinition)]
        /// Event describing lifecycle of an asset definition.
        #[norito_schema(name = "iroha_data_model::events::data::events::asset::AssetDefinitionEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::asset::AssetDefinitionEventSet")]
        pub enum AssetDefinitionEvent {
            #[has_origin(asset_definition => asset_definition.id())]
            /// Asset definition was registered.
            Created(AssetDefinition),
            /// Asset definition was deleted.
            Deleted(AssetDefinitionId),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(AssetDefinitionMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(AssetDefinitionMetadataChanged),
            /// Mintability flag toggled.
            MintabilityChanged(AssetDefinitionId),
            /// Mintability flipped from `Once` to `Not` on first mint with details.
            #[has_origin(mintability_changed => &mintability_changed.asset_definition)]
            MintabilityChangedDetailed(AssetDefinitionMintabilityChanged),
            #[has_origin(total_quantity_changed => &total_quantity_changed.asset_definition)]
            /// Total quantity value changed.
            TotalQuantityChanged(AssetDefinitionTotalQuantityChanged),
            #[has_origin(ownership_changed => &ownership_changed.asset_definition)]
            /// Owner field changed.
            OwnerChanged(AssetDefinitionOwnerChanged),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Depending on the wrapping event, [`Self`] represents the added or removed asset quantity.
        #[allow(clippy::ref_option)]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetChanged"
        )]
        pub struct AssetChanged {
            pub asset: AssetId,
            pub amount: Quantity,
        }
        /// One successful transparent asset movement between two account balances.
        ///
        /// Unlike [`AssetChanged`], this payload binds both sides of the movement,
        /// so consumers can distinguish transfers from minting and burning without
        /// inferring intent from separate balance-delta events.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetTransferred"
        )]
        pub struct AssetTransferred {
            /// Debited asset balance.
            pub source: AssetId,
            /// Credited asset balance.
            pub destination: AssetId,
            /// Exact quantity moved.
            pub amount: Quantity,
        }
        /// Stable rejection classification for one independently settled batch leg.
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "code", content = "value")]
        #[repr(u8)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetBatchTransferRejectionCode"
        )]
        pub enum AssetBatchTransferRejectionCode {
            /// The source balance cannot cover the requested quantity.
            InsufficientFunds,
            /// The destination balance would exceed its configured holding limit.
            HoldingLimitExceeded,
            /// Incoming asset movement is disabled for the destination account.
            IncomingDisabled,
            /// Outgoing asset movement is disabled for the source account.
            OutgoingDisabled,
            /// The source account is blacklisted for the asset.
            Blacklisted,
            /// Another deterministic business policy rejected the leg.
            PolicyRejected,
        }
        /// Final status for one native batch-transfer leg.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[norito(tag = "status", content = "value")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetBatchTransferLegStatus"
        )]
        pub enum AssetBatchTransferLegStatus {
            /// The leg changed balances and committed.
            Applied,
            /// The leg made no state change.
            Rejected(AssetBatchTransferRejection),
        }
        /// Stable rejection detail for one independent batch leg.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetBatchTransferRejection"
        )]
        pub struct AssetBatchTransferRejection {
            /// Stable machine-readable rejection code.
            pub code: AssetBatchTransferRejectionCode,
            /// Deterministic human-readable detail.
            pub message: String,
        }
        /// Consensus-bound receipt row for one ordered native batch-transfer leg.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetBatchTransferOutcome"
        )]
        pub struct AssetBatchTransferOutcome {
            /// Zero-based position within the batch instruction.
            pub leg_index: u32,
            /// Caller-selected leg correlation identifier.
            pub leg_id: String,
            /// Source asset whose balance was evaluated.
            pub asset: AssetId,
            /// Destination account.
            pub destination: AccountId,
            /// Requested amount.
            pub amount: Quantity,
            /// Final leg status.
            pub status: AssetBatchTransferLegStatus,
        }
        /// [`Self`] represents updated total asset quantity.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetDefinitionTotalQuantityChanged"
        )]
        pub struct AssetDefinitionTotalQuantityChanged {
            pub asset_definition: AssetDefinitionId,
            pub total_amount: Quantity,
        }
        /// [`Self`] represents updated total asset quantity.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetDefinitionOwnerChanged"
        )]
        pub struct AssetDefinitionOwnerChanged {
            /// Id of asset definition being updated
            pub asset_definition: AssetDefinitionId,
            /// Id of new owning account
            pub new_owner: AccountId,
        }
        /// Emitted together with [`AssetDefinitionEvent::MintabilityChanged`]
        /// when a limited asset definition (either `Mintable::Once` or `Mintable::Limited`)
        /// exhausts its mintability budget and flips to `Mintable::Not`.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::asset::model::AssetDefinitionMintabilityChanged"
        )]
        pub struct AssetDefinitionMintabilityChanged {
            /// Id of the asset definition that flipped to `Not`.
            pub asset_definition: AssetDefinitionId,
            /// Amount minted in the flipping transaction.
            pub minted_amount: Quantity,
            /// Account that performed the mint.
            pub authority: AccountId,
        }
    }
}

impl_json_via_norito_bytes!(
    AssetChanged,
    AssetDefinitionTotalQuantityChanged,
    AssetDefinitionOwnerChanged,
    AssetDefinitionMintabilityChanged,
);
pub mod bridge {
    //! Bridge events
    use super::*;
    use iroha_model_base::topology::LaneId;

    data_event! {
        /// Bridge lane events
        #[has_origin(origin = LaneId)]
        #[norito_schema(name = "iroha_data_model::events::data::events::bridge::BridgeEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::bridge::BridgeEventSet")]
        pub enum BridgeEvent {
            /// Emitted when a bridge receipt is recorded
            #[has_origin(receipt => &receipt.lane)]
            Emitted(crate::bridge::BridgeReceipt),
        }
    }
}
mod nft {
    //! This module contains `NftEvent` and its impls
    pub use self::model::*;
    use super::*;
    use iroha_data_model_derive::model;
    /// Metadata change captured for a specific NFT instance.
    type NftMetadataChanged = MetadataChanged<NftId>;
    data_event! {
        #[has_origin(origin = Nft)]
        /// Event describing lifecycle changes for a single NFT.
        #[norito_schema(name = "iroha_data_model::events::data::events::nft::NftEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::nft::NftEventSet")]
        pub enum NftEvent {
            #[has_origin(nft => nft.id())]
            /// NFT was created.
            Created(Nft),
            /// NFT was deleted.
            Deleted(NftId),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(NftMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(NftMetadataChanged),
            #[has_origin(ownership_changed => &ownership_changed.nft)]
            /// NFT ownership changed.
            OwnerChanged(NftOwnerChanged),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Event indicates that owner of the [`Nft`] is changed
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::nft::model::NftOwnerChanged"
        )]
        pub struct NftOwnerChanged {
            /// Id of NFT being updated
            pub nft: NftId,
            /// Id of new owning account
            pub new_owner: AccountId,
        }
    }
}

impl_json_via_norito_bytes!(NftOwnerChanged);
mod rwa {
    //! This module contains `RwaEvent` and its impls.
    pub use self::model::*;
    use super::*;
    use iroha_data_model_derive::model;
    /// Metadata change captured for a specific RWA lot.
    type RwaMetadataChanged = MetadataChanged<RwaId>;
    data_event! {
        #[has_origin(origin = Rwa)]
        /// Event describing lifecycle changes for a single RWA lot.
        #[norito_schema(name = "iroha_data_model::events::data::events::rwa::RwaEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::rwa::RwaEventSet")]
        pub enum RwaEvent {
            #[has_origin(rwa => rwa.id())]
            /// Lot was created.
            Created(Rwa),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(RwaMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(RwaMetadataChanged),
            #[has_origin(owner_changed => &owner_changed.rwa)]
            /// Full-lot ownership changed in place.
            OwnerChanged(RwaOwnerChanged),
            #[has_origin(split => &split.source)]
            /// A partial transfer split quantity out of the source lot.
            Split(RwaSplit),
            #[has_origin(merged => &merged.child)]
            /// A new derived lot was created from parent lots.
            Merged(RwaMerged),
            #[has_origin(quantity_changed => &quantity_changed.rwa)]
            /// Quantity was redeemed from the lot.
            Redeemed(RwaQuantityChanged),
            #[has_origin(id => id)]
            /// Lot was frozen.
            Frozen(RwaId),
            #[has_origin(id => id)]
            /// Lot was unfrozen.
            Unfrozen(RwaId),
            #[has_origin(hold_changed => &hold_changed.rwa)]
            /// Quantity was placed on hold.
            Held(RwaHoldChanged),
            #[has_origin(hold_changed => &hold_changed.rwa)]
            /// Held quantity was released.
            Released(RwaHoldChanged),
            #[has_origin(force_transfer => &force_transfer.source)]
            /// Controller-driven transfer split quantity out of the source lot.
            ForceTransferred(RwaSplit),
            #[has_origin(controls_changed => &controls_changed.rwa)]
            /// Control policy changed.
            ControlsChanged(RwaControlsChanged),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Event emitted when full-lot ownership changes in place.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::rwa::model::RwaOwnerChanged"
        )]
        pub struct RwaOwnerChanged {
            /// Lot whose owner changed.
            pub rwa: RwaId,
            /// New owner of the lot.
            pub new_owner: AccountId,
        }
        /// Event emitted when quantity is split out of a source lot into a child lot.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::events::data::events::rwa::model::RwaSplit")]
        pub struct RwaSplit {
            /// Source lot reduced in place.
            pub source: RwaId,
            /// New child lot receiving the transferred quantity.
            pub child: RwaId,
            /// Quantity moved into the child lot.
            pub quantity: Quantity,
            /// Owner of the child lot.
            pub new_owner: AccountId,
        }
        /// Event emitted when a derived lot is created from parent contributions.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::events::data::events::rwa::model::RwaMerged")]
        pub struct RwaMerged {
            /// Child lot created by the merge.
            pub child: RwaId,
            /// Quantitative parent contributions.
            pub parents: Vec<RwaParentRef>,
        }
        /// Event emitted when lot quantity changes due to redemption.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::rwa::model::RwaQuantityChanged"
        )]
        pub struct RwaQuantityChanged {
            /// Lot whose quantity changed.
            pub rwa: RwaId,
            /// Quantity affected by the operation.
            pub quantity: Quantity,
        }
        /// Event emitted when held quantity changes.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::rwa::model::RwaHoldChanged"
        )]
        pub struct RwaHoldChanged {
            /// Lot whose held quantity changed.
            pub rwa: RwaId,
            /// Quantity affected by the hold or release.
            pub quantity: Quantity,
        }
        /// Event emitted when a lot's control policy changes.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::rwa::model::RwaControlsChanged"
        )]
        pub struct RwaControlsChanged {
            /// Lot whose controls changed.
            pub rwa: RwaId,
            /// Full replacement control policy.
            pub controls: RwaControlPolicy,
        }
    }
}

impl_json_via_norito_bytes!(
    RwaOwnerChanged,
    RwaSplit,
    RwaMerged,
    RwaQuantityChanged,
    RwaHoldChanged,
    RwaControlsChanged
);
mod peer {
    //! This module contains `PeerEvent` and its impls
    use super::*;
    use iroha_model_base::peer::PeerId;
    data_event! {
        #[has_origin(origin = Peer)]
        /// Event emitted when peers join or leave the network view.
        #[norito_schema(name = "iroha_data_model::events::data::events::peer::PeerEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::peer::PeerEventSet")]
        pub enum PeerEvent {
            /// A peer joined the topology.
            Added(PeerId),
            /// A peer was removed from the topology.
            Removed(PeerId),
        }
    }
}
mod role {
    //! This module contains `RoleEvent` and its impls
    pub use self::model::*;
    use super::*;
    use iroha_data_model_derive::model;
    data_event! {
        #[has_origin(origin = Role)]
        /// Event describing role lifecycle and permissions.
        #[norito_schema(name = "iroha_data_model::events::data::events::role::RoleEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::role::RoleEventSet")]
        pub enum RoleEvent {
            #[has_origin(role => role.id())]
            /// Role was created.
            Created(Role),
            /// Role was deleted.
            Deleted(RoleId),
            /// [`Permission`] were added to the role.
            #[has_origin(permission_added => &permission_added.role)]
            PermissionAdded(RolePermissionChanged),
            /// [`Permission`] were removed from the role.
            #[has_origin(permission_removed => &permission_removed.role)]
            PermissionRemoved(RolePermissionChanged),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Depending on the wrapping event, [`RolePermissionChanged`] role represents the added or removed role's permission
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::role::model::RolePermissionChanged"
        )]
        pub struct RolePermissionChanged {
            pub role: RoleId,
            pub permission: Permission,
        }
    }
}

impl_json_via_norito_bytes!(RolePermissionChanged);
impl RolePermissionChanged {
    /// Create a new [`RolePermissionChanged`] event payload.
    #[must_use]
    pub fn new(role: RoleId, permission: Permission) -> Self {
        Self { role, permission }
    }
    /// Permission that was added to or removed from the role.
    #[must_use]
    pub fn permission(&self) -> &Permission {
        &self.permission
    }
    /// Role whose permission changed.
    #[must_use]
    pub fn role(&self) -> &RoleId {
        &self.role
    }
}
mod account {
    //! This module contains `AccountEvent` and its impls
    pub use self::model::*;
    use super::{repo_account::RepoAccountEvent, *};
    use iroha_data_model_derive::model;
    /// Metadata change associated with a specific account.
    type AccountMetadataChanged = MetadataChanged<AccountId>;
    data_event! {
        #[has_origin(origin = Account)]
        /// Event describing changes applied to an account.
        #[norito_schema(name = "iroha_data_model::events::data::events::account::AccountEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::account::AccountEventSet")]
        pub enum AccountEvent {
            #[has_origin(account => account.account.id())]
            /// Account was created.
            Created(AccountCreated),
            /// Account was deleted.
            Deleted(AccountId),
            #[has_origin(controller_replaced => &controller_replaced.account)]
            /// Account controller was replaced while preserving linked state.
            ControllerReplaced(AccountControllerReplaced),
            #[has_origin(permission_changed => &permission_changed.account)]
            /// Permission was granted to the account.
            PermissionAdded(AccountPermissionChanged),
            #[has_origin(permission_changed => &permission_changed.account)]
            /// Permission was revoked from the account.
            PermissionRemoved(AccountPermissionChanged),
            #[has_origin(role_changed => &role_changed.account)]
            /// Role was granted to the account.
            RoleGranted(AccountRoleChanged),
            #[has_origin(role_changed => &role_changed.account)]
            /// Role was revoked from the account.
            RoleRevoked(AccountRoleChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(AccountMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(AccountMetadataChanged),
            #[has_origin(recovery_event => recovery_event.origin())]
            /// Social recovery lifecycle event scoped to this account.
            Recovery(AccountRecoveryEvent),
            #[has_origin(repo_event => repo_event.origin())]
            /// Repo agreement lifecycle event scoped to this account.
            Repo(RepoAccountEvent),
        }
    }
    data_event! {
        #[has_origin(origin = Account)]
        /// Account social-recovery lifecycle event.
        #[norito_schema(name = "iroha_data_model::events::data::events::account::AccountRecoveryEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::account::AccountRecoveryEventSet")]
        pub enum AccountRecoveryEvent {
            #[has_origin(event => &event.account)]
            /// Recovery policy was set or replaced.
            PolicySet(AccountRecoveryPolicySet),
            #[has_origin(event => &event.account)]
            /// Recovery policy was cleared.
            PolicyCleared(AccountRecoveryPolicyCleared),
            #[has_origin(event => &event.account)]
            /// Recovery request was proposed.
            Proposed(AccountRecoveryProposed),
            #[has_origin(event => &event.account)]
            /// Recovery request approval was recorded.
            Approved(AccountRecoveryApproved),
            #[has_origin(event => &event.account)]
            /// Independent guardian cancellation approval was recorded.
            CancellationApproved(AccountRecoveryCancellationApproved),
            #[has_origin(event => &event.account)]
            /// Recovery request was cancelled.
            Cancelled(AccountRecoveryCancelled),
            #[has_origin(event => &event.account)]
            /// Recovery request was finalized.
            Finalized(AccountRecoveryFinalized),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Account creation payload.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountCreated"
        )]
        pub struct AccountCreated {
            pub account: Account,
        }
        /// Depending on the wrapping event, [`AccountPermissionChanged`] role represents the added or removed account role
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountPermissionChanged"
        )]
        pub struct AccountPermissionChanged {
            pub account: AccountId,
            pub permission: Permission,
        }
        /// Payload emitted when an account controller is replaced.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountControllerReplaced"
        )]
        pub struct AccountControllerReplaced {
            /// New canonical account identifier after replacement.
            pub account: AccountId,
            /// Previous canonical account identifier before replacement.
            pub previous_account: AccountId,
            /// Previous controller attached to the account.
            pub previous_controller: crate::account::AccountController,
            /// New controller attached to the account.
            pub new_controller: crate::account::AccountController,
        }
        /// Depending on the wrapping event, [`AccountRoleChanged`] represents the granted or revoked role
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRoleChanged"
        )]
        pub struct AccountRoleChanged {
            pub account: AccountId,
            pub role: RoleId,
        }
        /// Recovery-policy update payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryPolicySet"
        )]
        pub struct AccountRecoveryPolicySet {
            /// Account whose stable alias policy was updated.
            pub account: AccountId,
            /// Stable alias targeted by the policy.
            pub alias: crate::account::AccountAlias,
            /// Recovery policy that was persisted.
            pub policy: crate::account::AccountRecoveryPolicy,
        }
        /// Recovery-policy removal payload.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryPolicyCleared"
        )]
        pub struct AccountRecoveryPolicyCleared {
            /// Account whose stable alias policy was cleared.
            pub account: AccountId,
            /// Stable alias whose policy was removed.
            pub alias: crate::account::AccountAlias,
        }
        /// Recovery-request proposal payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryProposed"
        )]
        pub struct AccountRecoveryProposed {
            /// Account currently active behind the alias.
            pub account: AccountId,
            /// Stable alias targeted by the request.
            pub alias: crate::account::AccountAlias,
            /// Request persisted in world state.
            pub request: crate::account::AccountRecoveryRequest,
        }
        /// Recovery-request approval payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryApproved"
        )]
        pub struct AccountRecoveryApproved {
            /// Account currently active behind the alias.
            pub account: AccountId,
            /// Stable alias targeted by the request.
            pub alias: crate::account::AccountAlias,
            /// Guardian that recorded the approval.
            pub approver: AccountId,
            /// Updated request after approval was recorded.
            pub request: crate::account::AccountRecoveryRequest,
        }
        /// Recovery-request cancellation approval payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryCancellationApproved"
        )]
        pub struct AccountRecoveryCancellationApproved {
            /// Account currently active behind the alias.
            pub account: AccountId,
            /// Stable alias targeted by the request.
            pub alias: crate::account::AccountAlias,
            /// Guardian that voted for cancellation.
            pub approver: AccountId,
            /// Pending request after the cancellation vote was recorded.
            pub request: crate::account::AccountRecoveryRequest,
        }
        /// Recovery-request cancellation payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryCancelled"
        )]
        pub struct AccountRecoveryCancelled {
            /// Account currently active behind the alias.
            pub account: AccountId,
            /// Stable alias targeted by the request.
            pub alias: crate::account::AccountAlias,
            /// Authority that cancelled the request.
            pub cancelled_by: AccountId,
            /// Updated request after cancellation.
            pub request: crate::account::AccountRecoveryRequest,
        }
        /// Recovery-request finalization payload.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
        #[norito(no_fast_from_json)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::account::model::AccountRecoveryFinalized"
        )]
        pub struct AccountRecoveryFinalized {
            /// New account active behind the alias after finalization.
            pub account: AccountId,
            /// Previous account active behind the alias before finalization.
            pub previous_account: AccountId,
            /// Stable alias targeted by the request.
            pub alias: crate::account::AccountAlias,
            /// Finalized request snapshot.
            pub request: crate::account::AccountRecoveryRequest,
        }
    }
    impl AccountPermissionChanged {
        /// Create a new [`AccountPermissionChanged`] event payload.
        #[must_use]
        pub fn new(account: AccountId, permission: Permission) -> Self {
            Self {
                account,
                permission,
            }
        }
        /// Permission that was added to or removed from the account.
        #[must_use]
        pub fn permission(&self) -> &Permission {
            &self.permission
        }
        /// Account whose permission changed.
        #[must_use]
        pub fn account(&self) -> &AccountId {
            &self.account
        }
    }
    impl AccountCreated {
        /// Construct a new account-created payload.
        #[must_use]
        pub fn new(account: Account) -> Self {
            Self { account }
        }
    }
}

impl_json_via_norito_bytes!(
    AccountPermissionChanged,
    AccountRoleChanged,
    AccountControllerReplaced,
    AccountRecoveryPolicySet,
    AccountRecoveryPolicyCleared,
    AccountRecoveryProposed,
    AccountRecoveryApproved,
    AccountRecoveryCancellationApproved,
    AccountRecoveryCancelled,
    AccountRecoveryFinalized
);
mod repo_account {
    //! Repo lifecycle events scoped to individual accounts.
    pub use self::model::*;
    use super::*;
    use crate::{
        account::AccountId,
        repo::{RepoAgreement, RepoAgreementId, RepoCashLeg, RepoCollateralLeg},
    };
    use iroha_data_model_derive::model;
    data_event! {
        #[has_origin(origin = Account)]
        /// Repo agreement lifecycle event emitted for a specific account perspective.
        #[norito_schema(name = "iroha_data_model::events::data::events::repo_account::RepoAccountEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::repo_account::RepoAccountEventSet")]
        pub enum RepoAccountEvent {
            #[has_origin(initiated => &initiated.account)]
            /// The account participated in a newly initiated repo agreement.
            Initiated(RepoAccountInitiated),
            #[has_origin(settled => &settled.account)]
            /// The account participated in a repo settlement.
            Settled(RepoAccountSettled),
            #[has_origin(margin_called => &margin_called.account)]
            /// The account received a margin call notification.
            MarginCalled(RepoAccountMarginCalled),
        }
    }
    /// Role played by the account within a repo agreement lifecycle event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    /// Role carried by accounts participating in the repository subsystem.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::events::data::events::repo_account::RepoAccountRole")]
    pub enum RepoAccountRole {
        /// Account initiated the agreement (borrower).
        Initiator,
        /// Account acted as counterparty (lender).
        Counterparty,
        /// Account served as the collateral custodian in a tri-party agreement.
        Custodian,
    }
    #[model]
    mod model {
        use super::*;
        /// Repo initiation payload for a particular participant.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::repo_account::model::RepoAccountInitiated"
        )]
        pub struct RepoAccountInitiated {
            /// Account receiving the event.
            pub account: AccountId,
            /// Counterparty involved in the agreement.
            pub counterparty: AccountId,
            /// Full agreement record captured on initiation.
            pub agreement: RepoAgreement,
            /// Whether the account initiated or accepted the agreement.
            pub role: RepoAccountRole,
        }
        /// Repo settlement payload for a particular participant.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::repo_account::model::RepoAccountSettled"
        )]
        pub struct RepoAccountSettled {
            /// Account receiving the event.
            pub account: AccountId,
            /// Counterparty in the agreement.
            pub counterparty: AccountId,
            /// Identifier of the settled agreement.
            pub agreement_id: RepoAgreementId,
            /// Cash leg repaid on settlement (principal plus any accrued interest).
            pub cash_leg: RepoCashLeg,
            /// Collateral returned to this account.
            pub collateral_leg: RepoCollateralLeg,
            /// Timestamp (milliseconds since epoch) recorded for settlement.
            pub settled_timestamp_ms: u64,
            /// Whether the account was the initiator or counterparty.
            pub role: RepoAccountRole,
        }
        /// Repo margin call payload for a particular participant.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::repo_account::model::RepoAccountMarginCalled"
        )]
        pub struct RepoAccountMarginCalled {
            /// Account receiving the margin call event.
            pub account: AccountId,
            /// Counterparty in the agreement (borrower vs lender).
            pub counterparty: AccountId,
            /// Identifier of the agreement subject to the margin check.
            pub agreement_id: RepoAgreementId,
            /// Timestamp (milliseconds since epoch) recorded for the margin call.
            pub margin_timestamp_ms: u64,
            /// Role the account held in the agreement.
            pub role: RepoAccountRole,
        }
    }
    impl RepoAccountInitiated {
        /// Create an account-scoped initiation payload.
        #[must_use]
        pub fn new(
            account: AccountId,
            counterparty: AccountId,
            agreement: RepoAgreement,
            role: RepoAccountRole,
        ) -> Self {
            Self {
                account,
                counterparty,
                agreement,
                role,
            }
        }
    }
    impl RepoAccountSettled {
        /// Create an account-scoped settlement payload.
        #[allow(clippy::too_many_arguments)]
        #[must_use]
        pub fn new(
            account: AccountId,
            counterparty: AccountId,
            agreement_id: RepoAgreementId,
            cash_leg: RepoCashLeg,
            collateral_leg: RepoCollateralLeg,
            settled_timestamp_ms: u64,
            role: RepoAccountRole,
        ) -> Self {
            Self {
                account,
                counterparty,
                agreement_id,
                cash_leg,
                collateral_leg,
                settled_timestamp_ms,
                role,
            }
        }
    }
    impl RepoAccountMarginCalled {
        /// Create an account-scoped margin call payload.
        #[must_use]
        pub fn new(
            account: AccountId,
            counterparty: AccountId,
            agreement_id: RepoAgreementId,
            margin_timestamp_ms: u64,
            role: RepoAccountRole,
        ) -> Self {
            Self {
                account,
                counterparty,
                agreement_id,
                margin_timestamp_ms,
                role,
            }
        }
    }
}

impl_json_via_norito_bytes!(
    repo_account::RepoAccountInitiated,
    repo_account::RepoAccountSettled
);
mod domain {
    //! This module contains `DomainEvent` and its impls
    pub use self::model::*;
    use super::*;
    /// Metadata change associated with a specific domain.
    type DomainMetadataChanged = MetadataChanged<DomainId>;
    data_event! {
        #[has_origin(origin = Domain)]
        /// Event describing changes within a domain.
        #[norito_schema(name = "iroha_data_model::events::data::events::domain::DomainEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::domain::DomainEventSet")]
        pub enum DomainEvent {
            #[has_origin(domain => domain.id())]
            /// Domain was created.
            Created(Domain),
            /// Domain was deleted.
            Deleted(DomainId),
            #[has_origin(scoped => &scoped.domain)]
            /// Asset-definition event occurred in the domain scope.
            AssetDefinition(ScopedAssetDefinition),
            #[has_origin(scoped => &scoped.domain)]
            /// Asset event occurred in the domain scope.
            Asset(ScopedAsset),
            #[has_origin(nft_event => &nft_event.origin().domain)]
            /// NFT event occurred in the domain scope.
            Nft(NftEvent),
            #[has_origin(rwa_event => &rwa_event.origin().domain)]
            /// RWA event occurred in the domain scope.
            Rwa(RwaEvent),
            #[has_origin(scoped => &scoped.domain)]
            /// Account event occurred in the domain scope.
            Account(ScopedAccount),
            #[has_origin(link_changed => &link_changed.domain)]
            /// Account subject was linked to the domain.
            AccountLinked(AccountDomainLinkChanged),
            #[has_origin(link_changed => &link_changed.domain)]
            /// Account subject was unlinked from the domain.
            AccountUnlinked(AccountDomainLinkChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(DomainMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(DomainMetadataChanged),
            #[has_origin(owner_changed => &owner_changed.domain)]
            /// Domain owner changed.
            OwnerChanged(DomainOwnerChanged),
            #[has_origin(summary => &summary.call.domain_id)]
            /// Aggregated Kaigi roster metrics were recorded.
            KaigiRosterSummary(KaigiRosterSummary),
            #[has_origin(summary => &summary.domain)]
            /// Kaigi relay registration summary emitted.
            KaigiRelayRegistered(model::KaigiRelayRegistrationSummary),
            #[has_origin(summary => &summary.call.domain_id)]
            /// Kaigi relay manifest updated.
            KaigiRelayManifestUpdated(KaigiRelayManifestSummary),
            #[has_origin(summary => &summary.call.domain_id)]
            /// Kaigi usage metrics recorded.
            KaigiUsageSummary(KaigiUsageSummary),
            #[has_origin(summary => &summary.domain)]
            /// Kaigi relay health status changed.
            KaigiRelayHealthUpdated(KaigiRelayHealthSummary),
            #[has_origin(ticket_ready => &ticket_ready.domain)]
            /// Privacy streaming ticket became available.
            StreamingTicketReady(StreamingTicketReady),
            #[has_origin(ticket_revoked => &ticket_revoked.domain)]
            /// Privacy streaming ticket was revoked.
            StreamingTicketRevoked(StreamingTicketRevoked),
            #[has_origin(summary => &summary.domain)]
            /// Kaigi relay descriptor and retained feedback were removed.
            KaigiRelayUnregistered(model::KaigiRelayUnregistrationSummary),
            #[has_origin(summary => &summary.call.domain_id)]
            /// Kaigi lifecycle status changed.
            KaigiStatusChanged(model::KaigiStatusSummary),
        }
    }
    #[model]
    mod model {
        use super::*;
        use crate::{
            account::AccountId,
            kaigi::{KaigiId, KaigiPrivacyMode, KaigiRelayHealthStatus, KaigiStatus},
            soranet::ticket::TicketEnvelopeV1,
        };
        use iroha_crypto::Hash;
        use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
        use norito::streaming::{
            Multiaddr, PrivacyCapabilities, PrivacyRelay, PrivacyRoute, SoranetAccessKind,
            SoranetChannelId, SoranetRoute, SoranetStreamTag,
        };
        /// Event indicate that owner of the [`Domain`] is changed
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::DomainOwnerChanged"
        )]
        pub struct DomainOwnerChanged {
            pub domain: DomainId,
            pub new_owner: AccountId,
        }
        /// Account event paired with an explicit, authoritative routing domain.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::ScopedAccount"
        )]
        pub struct ScopedAccount {
            /// Authoritative domain routing context.
            pub domain: DomainId,
            /// Account event payload.
            pub event: AccountEvent,
        }
        /// Asset event paired with an explicit, authoritative routing domain.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::ScopedAsset"
        )]
        pub struct ScopedAsset {
            /// Authoritative asset-definition domain context.
            pub domain: DomainId,
            /// Asset event payload.
            pub event: AssetEvent,
        }
        /// Asset-definition event paired with an explicit, authoritative routing domain.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::ScopedAssetDefinition"
        )]
        pub struct ScopedAssetDefinition {
            /// Authoritative asset-definition domain context.
            pub domain: DomainId,
            /// Asset-definition event payload.
            pub event: AssetDefinitionEvent,
        }
        /// Account-domain link payload emitted when membership links change.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::AccountDomainLinkChanged"
        )]
        pub struct AccountDomainLinkChanged {
            /// Domain where the link mutation happened.
            pub domain: DomainId,
            /// Domainless account identifier whose membership link changed.
            pub account: AccountId,
        }
        /// Aggregated Kaigi roster counts without exposing individual identities.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiRosterSummary"
        )]
        pub struct KaigiRosterSummary {
            /// Call identifier.
            pub call: KaigiId,
            /// Privacy mode currently applied to the session.
            pub privacy_mode: KaigiPrivacyMode,
            /// Number of visible participants.
            pub participant_count: u32,
            /// Number of registered roster commitments.
            pub commitment_count: u32,
            /// Total nullifiers logged for the session.
            pub nullifier_count: u32,
            /// Current roster Merkle root (only populated in privacy mode).
            pub roster_root: Option<Hash>,
        }
        impl KaigiRosterSummary {
            /// Construct a new roster summary payload.
            #[must_use]
            pub fn new(
                call: KaigiId,
                privacy_mode: KaigiPrivacyMode,
                participant_count: u32,
                commitment_count: u32,
                nullifier_count: u32,
                roster_root: Option<Hash>,
            ) -> Self {
                Self {
                    call,
                    privacy_mode,
                    participant_count,
                    commitment_count,
                    nullifier_count,
                    roster_root,
                }
            }
        }
        /// Registration snapshot for a Kaigi relay.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiRelayRegistrationSummary"
        )]
        pub struct KaigiRelayRegistrationSummary {
            /// Domain where the relay registration was recorded.
            pub domain: DomainId,
            /// Relay identifier.
            pub relay: AccountId,
            /// Relay bandwidth class advertised during registration.
            pub bandwidth_class: u8,
            /// Fingerprint of the published HPKE public key.
            pub hpke_fingerprint: Hash,
        }
        impl KaigiRelayRegistrationSummary {
            /// Construct a new relay registration summary payload.
            #[must_use]
            pub fn new(
                domain: DomainId,
                relay: AccountId,
                bandwidth_class: u8,
                hpke_fingerprint: Hash,
            ) -> Self {
                Self {
                    domain,
                    relay,
                    bandwidth_class,
                    hpke_fingerprint,
                }
            }
        }
        /// Compact identity of a removed Kaigi relay descriptor.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiRelayUnregistrationSummary"
        )]
        pub struct KaigiRelayUnregistrationSummary {
            /// Domain from which the relay descriptor was removed.
            pub domain: DomainId,
            /// Relay identifier whose descriptor was removed.
            pub relay: AccountId,
        }
        impl KaigiRelayUnregistrationSummary {
            /// Construct a relay unregistration summary payload.
            #[must_use]
            pub fn new(domain: DomainId, relay: AccountId) -> Self {
                Self { domain, relay }
            }
        }
        /// Compact Kaigi lifecycle status snapshot.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiStatusSummary"
        )]
        pub struct KaigiStatusSummary {
            /// Call identifier.
            pub call: KaigiId,
            /// Current lifecycle status.
            pub status: KaigiStatus,
            /// End timestamp in milliseconds, populated only after the call ends.
            pub ended_at_ms: Option<u64>,
        }
        impl KaigiStatusSummary {
            /// Construct a lifecycle status summary payload.
            #[must_use]
            pub fn new(call: KaigiId, status: KaigiStatus, ended_at_ms: Option<u64>) -> Self {
                Self {
                    call,
                    status,
                    ended_at_ms,
                }
            }
        }
        /// Snapshot describing the active relay manifest.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiRelayManifestSummary"
        )]
        pub struct KaigiRelayManifestSummary {
            /// Call identifier.
            pub call: KaigiId,
            /// Number of hops advertised in the manifest.
            pub hop_count: u32,
            /// Manifest expiry timestamp in milliseconds.
            pub expiry_ms: u64,
        }
        impl KaigiRelayManifestSummary {
            /// Construct a new relay manifest summary payload.
            #[must_use]
            pub fn new(call: KaigiId, hop_count: u32, expiry_ms: u64) -> Self {
                Self {
                    call,
                    hop_count,
                    expiry_ms,
                }
            }
        }
        /// Health update emitted when a relay status changes.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiRelayHealthSummary"
        )]
        pub struct KaigiRelayHealthSummary {
            /// Domain that owns the reported relay registration.
            pub domain: DomainId,
            /// Call identifier where the health update originated.
            pub call: KaigiId,
            /// Relay account being reported.
            pub relay: AccountId,
            /// Observed health status.
            pub status: KaigiRelayHealthStatus,
            /// Timestamp (milliseconds since epoch) when the report was recorded.
            pub reported_at_ms: u64,
        }
        impl KaigiRelayHealthSummary {
            /// Domain containing the relay health record.
            #[must_use]
            pub fn domain(&self) -> &DomainId {
                &self.domain
            }
            /// Call associated with this health report.
            #[must_use]
            pub fn call(&self) -> &KaigiId {
                &self.call
            }
            /// Relay whose health was reported.
            #[must_use]
            pub fn relay(&self) -> &AccountId {
                &self.relay
            }
            /// Reported relay health status.
            #[must_use]
            pub fn status(&self) -> &KaigiRelayHealthStatus {
                &self.status
            }
            /// Construct a new relay health summary payload.
            #[must_use]
            pub fn new(
                domain: DomainId,
                call: KaigiId,
                relay: AccountId,
                status: KaigiRelayHealthStatus,
                reported_at_ms: u64,
            ) -> Self {
                Self {
                    domain,
                    call,
                    relay,
                    status,
                    reported_at_ms,
                }
            }
        }
        /// Aggregated usage totals for a Kaigi session.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::KaigiUsageSummary"
        )]
        pub struct KaigiUsageSummary {
            /// Call identifier.
            pub call: KaigiId,
            /// Total duration recorded (milliseconds).
            pub total_duration_ms: u64,
            /// Total billed gas across all segments.
            pub total_billed_gas: u64,
            /// Number of segments recorded.
            pub segments_recorded: u32,
        }
        impl KaigiUsageSummary {
            /// Construct a new usage summary payload.
            #[must_use]
            pub fn new(
                call: KaigiId,
                total_duration_ms: u64,
                total_billed_gas: u64,
                segments_recorded: u32,
            ) -> Self {
                Self {
                    call,
                    total_duration_ms,
                    total_billed_gas,
                    segments_recorded,
                }
            }
        }
        /// Relay descriptor emitted alongside streaming ticket events.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingPrivacyRelay"
        )]
        pub struct StreamingPrivacyRelay {
            pub relay_id: [u8; 32],
            pub endpoint: Multiaddr,
            pub key_fingerprint: [u8; 32],
            pub capabilities_bits: u32,
        }
        impl StreamingPrivacyRelay {
            /// Construct a new relay descriptor.
            #[must_use]
            pub fn new(
                relay_id: [u8; 32],
                endpoint: Multiaddr,
                key_fingerprint: [u8; 32],
                capabilities_bits: u32,
            ) -> Self {
                Self {
                    relay_id,
                    endpoint,
                    key_fingerprint,
                    capabilities_bits,
                }
            }
        }
        impl From<PrivacyRelay> for StreamingPrivacyRelay {
            fn from(relay: PrivacyRelay) -> Self {
                Self {
                    relay_id: relay.relay_id,
                    endpoint: relay.endpoint,
                    key_fingerprint: relay.key_fingerprint,
                    capabilities_bits: relay.capabilities.bits(),
                }
            }
        }
        impl From<&StreamingPrivacyRelay> for PrivacyRelay {
            fn from(relay: &StreamingPrivacyRelay) -> Self {
                PrivacyRelay {
                    relay_id: relay.relay_id,
                    endpoint: relay.endpoint.clone(),
                    key_fingerprint: relay.key_fingerprint,
                    capabilities: PrivacyCapabilities::from_bits(relay.capabilities_bits),
                }
            }
        }
        /// Access posture advertised by `SoraNet` exit relays.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
        )]
        #[norito(reuse_archived, decode_from_slice)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingSoranetAccessKind"
        )]
        pub enum StreamingSoranetAccessKind {
            ReadOnly,
            Authenticated,
        }
        impl From<SoranetAccessKind> for StreamingSoranetAccessKind {
            fn from(kind: SoranetAccessKind) -> Self {
                match kind {
                    SoranetAccessKind::ReadOnly => Self::ReadOnly,
                    SoranetAccessKind::Authenticated => Self::Authenticated,
                }
            }
        }
        impl From<StreamingSoranetAccessKind> for SoranetAccessKind {
            fn from(kind: StreamingSoranetAccessKind) -> Self {
                match kind {
                    StreamingSoranetAccessKind::ReadOnly => Self::ReadOnly,
                    StreamingSoranetAccessKind::Authenticated => Self::Authenticated,
                }
            }
        }
        /// Stream tags advertised by `SoraNet` relays for exit bridges.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, Default,
        )]
        #[norito(reuse_archived, decode_from_slice)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingSoranetStreamTag"
        )]
        pub enum StreamingSoranetStreamTag {
            #[default]
            NoritoStream,
            Kaigi,
        }
        impl From<SoranetStreamTag> for StreamingSoranetStreamTag {
            fn from(tag: SoranetStreamTag) -> Self {
                match tag {
                    SoranetStreamTag::NoritoStream => Self::NoritoStream,
                    SoranetStreamTag::Kaigi => Self::Kaigi,
                }
            }
        }
        impl From<StreamingSoranetStreamTag> for SoranetStreamTag {
            fn from(tag: StreamingSoranetStreamTag) -> Self {
                match tag {
                    StreamingSoranetStreamTag::NoritoStream => Self::NoritoStream,
                    StreamingSoranetStreamTag::Kaigi => Self::Kaigi,
                }
            }
        }
        /// Privacy route metadata for `SoraNet` transport.
        #[allow(clippy::ref_option)]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[norito(reuse_archived, decode_from_slice)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingSoranetRoute"
        )]
        pub struct StreamingSoranetRoute {
            pub channel_id: [u8; 32],
            pub exit_multiaddr: Multiaddr,
            #[getset(skip)]
            pub padding_budget_ms: Option<u16>,
            pub access_kind: StreamingSoranetAccessKind,
            #[getset(skip)]
            pub stream_tag: StreamingSoranetStreamTag,
        }
        impl StreamingSoranetRoute {
            /// Construct a new descriptor from raw fields.
            #[must_use]
            pub fn new(
                channel_id: [u8; 32],
                exit_multiaddr: Multiaddr,
                padding_budget_ms: Option<u16>,
                access_kind: StreamingSoranetAccessKind,
                stream_tag: StreamingSoranetStreamTag,
            ) -> Self {
                Self {
                    channel_id,
                    exit_multiaddr,
                    padding_budget_ms,
                    access_kind,
                    stream_tag,
                }
            }
            /// Returns optional padding budget (milliseconds).
            #[must_use]
            pub fn padding_budget_ms(&self) -> Option<u16> {
                self.padding_budget_ms
            }
            /// Replace the padding budget (milliseconds).
            pub fn set_padding_budget_ms(&mut self, value: Option<u16>) {
                self.padding_budget_ms = value;
            }
            /// Replace the exit relay multiaddr.
            pub fn set_exit_multiaddr(&mut self, exit: Multiaddr) {
                self.exit_multiaddr = exit;
            }
            /// Replace the advertised access posture.
            pub fn set_access_kind(&mut self, access: StreamingSoranetAccessKind) {
                self.access_kind = access;
            }
            /// Replace the advertised stream tag.
            pub fn set_stream_tag(&mut self, tag: StreamingSoranetStreamTag) {
                self.stream_tag = tag;
            }
            /// Returns the stream tag advertised by the exit.
            #[must_use]
            pub fn stream_tag(&self) -> StreamingSoranetStreamTag {
                self.stream_tag
            }
        }
        impl From<SoranetRoute> for StreamingSoranetRoute {
            fn from(route: SoranetRoute) -> Self {
                Self {
                    channel_id: <[u8; 32]>::from(route.channel_id),
                    exit_multiaddr: route.exit_multiaddr,
                    padding_budget_ms: route.padding_budget_ms,
                    access_kind: StreamingSoranetAccessKind::from(route.access_kind),
                    stream_tag: StreamingSoranetStreamTag::from(route.stream_tag),
                }
            }
        }
        impl From<&StreamingSoranetRoute> for SoranetRoute {
            fn from(route: &StreamingSoranetRoute) -> Self {
                Self {
                    channel_id: SoranetChannelId::new(route.channel_id),
                    exit_multiaddr: route.exit_multiaddr.clone(),
                    padding_budget_ms: route.padding_budget_ms,
                    access_kind: SoranetAccessKind::from(route.access_kind),
                    stream_tag: SoranetStreamTag::from(route.stream_tag),
                }
            }
        }
        /// Privacy route description mirrored from the manifest schema.
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema)]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingPrivacyRoute"
        )]
        pub struct StreamingPrivacyRoute {
            pub route_id: [u8; 32],
            pub entry: StreamingPrivacyRelay,
            pub exit: StreamingPrivacyRelay,
            pub ticket_entry: Vec<u8>,
            pub ticket_exit: Vec<u8>,
            pub expiry_segment: u64,
            #[getset(skip)]
            pub soranet: Option<StreamingSoranetRoute>,
            #[getset(skip)]
            pub ticket: Option<TicketEnvelopeV1>,
        }
        impl fmt::Debug for StreamingPrivacyRoute {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct("StreamingPrivacyRoute")
                    .field("route_id", &self.route_id)
                    .field("entry", &self.entry)
                    .field("exit", &self.exit)
                    .field(
                        "ticket_entry",
                        &format_args!("<redacted:{} bytes>", self.ticket_entry.len()),
                    )
                    .field(
                        "ticket_exit",
                        &format_args!("<redacted:{} bytes>", self.ticket_exit.len()),
                    )
                    .field("expiry_segment", &self.expiry_segment)
                    .field("soranet", &self.soranet)
                    .field(
                        "ticket",
                        &self.ticket.as_ref().map(|_| "<redacted attached ticket>"),
                    )
                    .finish()
            }
        }
        impl StreamingPrivacyRoute {
            /// Construct a new relay path descriptor (no ticket attached).
            #[must_use]
            pub fn new(
                route_id: [u8; 32],
                entry: StreamingPrivacyRelay,
                exit: StreamingPrivacyRelay,
                ticket_entry: Vec<u8>,
                ticket_exit: Vec<u8>,
                expiry_segment: u64,
            ) -> Self {
                Self {
                    route_id,
                    entry,
                    exit,
                    ticket_entry,
                    ticket_exit,
                    expiry_segment,
                    soranet: None,
                    ticket: None,
                }
            }
            /// Attach a privacy ticket envelope to the route.
            #[must_use]
            pub fn with_ticket(mut self, ticket: TicketEnvelopeV1) -> Self {
                self.ticket = Some(ticket);
                self
            }
            /// Attach `SoraNet` metadata to the route.
            #[must_use]
            pub fn with_soranet(mut self, soranet: StreamingSoranetRoute) -> Self {
                self.soranet = Some(soranet);
                self
            }
            /// Returns the attached ticket envelope, if present.
            #[must_use]
            pub fn ticket_envelope(&self) -> Option<&TicketEnvelopeV1> {
                self.ticket.as_ref()
            }
            /// Returns the attached `SoraNet` metadata, if present.
            #[must_use]
            pub fn soranet(&self) -> Option<&StreamingSoranetRoute> {
                self.soranet.as_ref()
            }
            /// Replace the attached `SoraNet` metadata.
            pub fn set_soranet(&mut self, value: Option<StreamingSoranetRoute>) {
                self.soranet = value;
            }
            /// Replace the attached ticket envelope.
            pub fn set_ticket(&mut self, value: Option<TicketEnvelopeV1>) {
                self.ticket = value;
            }
            /// Construct a streaming route from a Norito privacy route and optional ticket.
            #[must_use]
            pub fn from_parts(route: PrivacyRoute, ticket: Option<TicketEnvelopeV1>) -> Self {
                Self::from(route).with_optional_ticket(ticket)
            }
            /// Split the route into the Norito representation and an optional ticket envelope.
            #[must_use]
            pub fn into_parts(self) -> (PrivacyRoute, Option<TicketEnvelopeV1>) {
                let StreamingPrivacyRoute {
                    route_id,
                    entry,
                    exit,
                    ticket_entry,
                    ticket_exit,
                    expiry_segment,
                    soranet,
                    ticket,
                } = self;
                let privacy_route = PrivacyRoute {
                    route_id,
                    entry: PrivacyRelay::from(&entry),
                    exit: PrivacyRelay::from(&exit),
                    ticket_entry,
                    ticket_exit,
                    expiry_segment,
                    soranet: soranet.as_ref().map(SoranetRoute::from),
                };
                (privacy_route, ticket)
            }
            fn with_optional_ticket(mut self, ticket: Option<TicketEnvelopeV1>) -> Self {
                self.ticket = ticket;
                self
            }
        }
        impl From<PrivacyRoute> for StreamingPrivacyRoute {
            fn from(route: PrivacyRoute) -> Self {
                Self {
                    route_id: route.route_id,
                    entry: route.entry.into(),
                    exit: route.exit.into(),
                    ticket_entry: route.ticket_entry,
                    ticket_exit: route.ticket_exit,
                    expiry_segment: route.expiry_segment,
                    soranet: route.soranet.map(StreamingSoranetRoute::from),
                    ticket: None,
                }
            }
        }
        impl From<&StreamingPrivacyRoute> for PrivacyRoute {
            fn from(route: &StreamingPrivacyRoute) -> Self {
                PrivacyRoute {
                    route_id: route.route_id,
                    entry: PrivacyRelay::from(&route.entry),
                    exit: PrivacyRelay::from(&route.exit),
                    ticket_entry: route.ticket_entry.clone(),
                    ticket_exit: route.ticket_exit.clone(),
                    expiry_segment: route.expiry_segment,
                    soranet: route.soranet.as_ref().map(SoranetRoute::from),
                }
            }
        }
        /// Association between a privacy route and its provisioning window.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingRouteBinding"
        )]
        pub struct StreamingRouteBinding {
            /// Route descriptor (entry/exit relays, HPKE tokens, expiry segment).
            pub route: StreamingPrivacyRoute,
            /// First segment (inclusive) covered by the provisioning window.
            pub valid_from_segment: u64,
            /// Last segment (inclusive) covered by the provisioning window.
            pub valid_until_segment: u64,
            /// Whether the exit relay has acknowledged provisioning.
            pub acknowledged: bool,
        }
        impl StreamingRouteBinding {
            /// Construct a new route binding descriptor.
            #[must_use]
            pub fn new(
                route: StreamingPrivacyRoute,
                valid_from_segment: u64,
                valid_until_segment: u64,
                acknowledged: bool,
            ) -> Self {
                Self {
                    route,
                    valid_from_segment,
                    valid_until_segment,
                    acknowledged,
                }
            }
            /// Convert the route descriptor into the Norito representation.
            #[must_use]
            pub fn as_privacy_route(&self) -> PrivacyRoute {
                PrivacyRoute::from(&self.route)
            }
        }
        /// Optional policy constraints embedded in streaming capability tickets.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[norito(reuse_archived, decode_from_slice)]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingTicketPolicy"
        )]
        pub struct StreamingTicketPolicy {
            /// Maximum number of relays allowed to serve this ticket concurrently.
            pub max_relays: u16,
            /// Geographic regions permitted to serve the ticket (ISO-style codes).
            pub allowed_regions: Vec<String>,
            /// Optional bandwidth ceiling in kilobits per second.
            #[getset(skip)]
            pub max_bandwidth_kbps: Option<u32>,
        }
        impl StreamingTicketPolicy {
            /// Construct a new streaming ticket policy descriptor.
            #[must_use]
            pub fn new(
                max_relays: u16,
                allowed_regions: Vec<String>,
                max_bandwidth_kbps: Option<u32>,
            ) -> Self {
                Self {
                    max_relays,
                    allowed_regions,
                    max_bandwidth_kbps,
                }
            }
            /// Returns the optional bandwidth ceiling in kilobits per second.
            #[must_use]
            pub fn max_bandwidth_kbps(&self) -> Option<u32> {
                self.max_bandwidth_kbps
            }
        }
        /// Capability bitfield advertised by streaming tickets.
        #[derive(
            Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
        )]
        #[repr(transparent)]
        #[norito(reuse_archived)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingTicketCapabilities"
        )]
        pub struct StreamingTicketCapabilities(u32);
        impl StreamingTicketCapabilities {
            /// Capability flag allowing live streaming access.
            pub const LIVE: u32 = 1 << 0;
            /// Capability flag allowing video-on-demand playback.
            pub const VOD: u32 = 1 << 1;
            /// Capability flag unlocking premium rendering profiles.
            pub const PREMIUM_PROFILE: u32 = 1 << 2;
            /// Capability flag enabling HDR ladders.
            pub const HDR: u32 = 1 << 3;
            /// Capability flag enabling spatial audio playback.
            pub const SPATIAL_AUDIO: u32 = 1 << 4;
            /// Construct capabilities from raw bits.
            #[must_use]
            pub const fn from_bits(bits: u32) -> Self {
                Self(bits)
            }
            /// Expose the underlying bit representation.
            #[must_use]
            pub const fn bits(self) -> u32 {
                self.0
            }
            /// Check whether all bits in `mask` are present.
            #[must_use]
            pub const fn contains(self, mask: u32) -> bool {
                (self.0 & mask) == mask
            }
            /// Return a new capability set with `mask` inserted.
            #[must_use]
            pub const fn insert(self, mask: u32) -> Self {
                Self(self.0 | mask)
            }
            /// Return a new capability set with `mask` removed.
            #[must_use]
            pub const fn remove(self, mask: u32) -> Self {
                Self(self.0 & !mask)
            }
        }
        impl<'a> norito::core::DecodeFromSlice<'a> for StreamingTicketCapabilities {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let (bits, used) =
                    <u32 as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
                Ok((StreamingTicketCapabilities::from_bits(bits), used))
            }
        }
        /// Streaming capability ticket metadata emitted with readiness events.
        #[allow(clippy::ref_option)]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[norito(reuse_archived, decode_from_slice)]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingTicketRecord"
        )]
        pub struct StreamingTicketRecord {
            /// Capability ticket identifier.
            #[getset(skip)]
            pub ticket_id: Hash,
            /// Account that owns the ticket.
            pub owner: AccountId,
            /// Data space the ticket belongs to.
            pub dsid: DataSpaceId,
            /// Execution lane scoped by the ticket.
            pub lane_id: LaneId,
            /// Settlement bucket for prepaid fan-out.
            pub settlement_bucket: u64,
            /// Slot number when the ticket becomes valid.
            pub start_slot: u64,
            /// Slot number when the ticket expires.
            pub expire_slot: u64,
            /// Prepaid traffic entitlement units.
            pub prepaid_teu: u128,
            /// Entitlement units consumed per chunk.
            pub chunk_teu: u32,
            /// Relay fan-out quota.
            pub fanout_quota: u16,
            /// Commitment to the access key.
            pub key_commitment: Hash,
            /// Ticket nonce for uniqueness.
            pub nonce: u64,
            /// Contract-level signature authorising the ticket.
            pub contract_signature: [u8; 64],
            /// Zero-knowledge commitment bound to the viewer.
            pub commitment: Hash,
            /// Nullifier preventing replay.
            #[getset(skip)]
            pub nullifier: Hash,
            /// Identifier of the verifier entry for the proof.
            pub proof_id: [u8; 32],
            /// Timestamp when the ticket was issued.
            pub issued_at: u64,
            /// Timestamp when the ticket expires.
            pub expires_at: u64,
            /// Optional policy constraints.
            #[getset(skip)]
            pub policy: Option<StreamingTicketPolicy>,
            /// Playback capabilities granted by the ticket.
            pub capabilities: StreamingTicketCapabilities,
        }
        impl StreamingTicketRecord {
            /// Construct a new ticket metadata record.
            #[allow(clippy::too_many_arguments)]
            #[must_use]
            pub fn new(
                ticket_id: Hash,
                owner: AccountId,
                dsid: DataSpaceId,
                lane_id: LaneId,
                settlement_bucket: u64,
                start_slot: u64,
                expire_slot: u64,
                prepaid_teu: u128,
                chunk_teu: u32,
                fanout_quota: u16,
                key_commitment: Hash,
                nonce: u64,
                contract_signature: [u8; 64],
                commitment: Hash,
                nullifier: Hash,
                proof_id: [u8; 32],
                issued_at: u64,
                expires_at: u64,
                policy: Option<StreamingTicketPolicy>,
                capabilities: StreamingTicketCapabilities,
            ) -> Self {
                Self {
                    ticket_id,
                    owner,
                    dsid,
                    lane_id,
                    settlement_bucket,
                    start_slot,
                    expire_slot,
                    prepaid_teu,
                    chunk_teu,
                    fanout_quota,
                    key_commitment,
                    nonce,
                    contract_signature,
                    commitment,
                    nullifier,
                    proof_id,
                    issued_at,
                    expires_at,
                    policy,
                    capabilities,
                }
            }
            /// Hash of the nullifier associated with this ticket.
            #[must_use]
            pub fn nullifier(&self) -> &Hash {
                &self.nullifier
            }
            /// Capability ticket identifier.
            #[must_use]
            pub fn ticket_id(&self) -> &Hash {
                &self.ticket_id
            }
        }
        /// Event announcing that a streaming capability ticket is ready for use.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingTicketReady"
        )]
        pub struct StreamingTicketReady {
            /// Domain identifier the stream belongs to.
            pub domain: DomainId,
            /// Stream identifier the ticket applies to.
            pub stream_id: Hash,
            /// Capability ticket metadata.
            pub ticket: StreamingTicketRecord,
            /// Provisioned privacy routes bundled with the ticket.
            pub routes: Vec<StreamingRouteBinding>,
        }
        impl StreamingTicketReady {
            /// Construct a new ticket readiness event payload.
            #[must_use]
            pub fn new(
                domain: DomainId,
                stream_id: Hash,
                ticket: StreamingTicketRecord,
                routes: Vec<StreamingRouteBinding>,
            ) -> Self {
                Self {
                    domain,
                    stream_id,
                    ticket,
                    routes,
                }
            }
            /// Convenience accessor returning the ticket identifier.
            #[must_use]
            pub fn ticket_id(&self) -> &Hash {
                self.ticket.ticket_id()
            }
        }
        /// Event indicating that a streaming capability ticket is no longer valid.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, IntoSchema,
        )]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::domain::model::StreamingTicketRevoked"
        )]
        pub struct StreamingTicketRevoked {
            /// Domain identifier the stream belongs to.
            pub domain: DomainId,
            /// Stream identifier the ticket applied to.
            pub stream_id: Hash,
            /// Capability ticket identifier.
            #[getset(skip)]
            pub ticket_id: Hash,
            /// Nullifier associated with the revoked ticket.
            pub nullifier: Hash,
            /// Reason code for revocation.
            pub reason_code: u16,
            /// Signature authorising the revocation.
            pub revocation_signature: [u8; 64],
        }
        impl StreamingTicketRevoked {
            /// Construct a new ticket revocation payload.
            #[must_use]
            pub fn new(
                domain: DomainId,
                stream_id: Hash,
                ticket_id: Hash,
                nullifier: Hash,
                reason_code: u16,
                revocation_signature: [u8; 64],
            ) -> Self {
                Self {
                    domain,
                    stream_id,
                    ticket_id,
                    nullifier,
                    reason_code,
                    revocation_signature,
                }
            }
            /// Returns the identifier of the revoked ticket.
            #[must_use]
            pub fn ticket_id(&self) -> &Hash {
                &self.ticket_id
            }
        }
    }
}

impl_json_via_norito_bytes!(
    DomainOwnerChanged,
    domain::KaigiRosterSummary,
    domain::KaigiRelayRegistrationSummary,
    domain::KaigiRelayUnregistrationSummary,
    domain::KaigiRelayManifestSummary,
    domain::KaigiRelayHealthSummary,
    domain::KaigiStatusSummary,
    domain::KaigiUsageSummary,
    domain::StreamingSoranetRoute,
    domain::StreamingPrivacyRelay,
    domain::StreamingPrivacyRoute,
    domain::StreamingRouteBinding,
    domain::StreamingTicketReady,
    domain::StreamingTicketRevoked
);
mod trigger {
    //! This module contains `TriggerEvent` and its impls
    pub use self::model::*;
    use super::*;
    use iroha_data_model_derive::model;
    /// Metadata change associated with a trigger instance.
    type TriggerMetadataChanged = MetadataChanged<TriggerId>;
    data_event! {
        #[has_origin(origin = Trigger)]
        /// Event describing trigger lifecycle updates.
        #[norito_schema(name = "iroha_data_model::events::data::events::trigger::TriggerEvent")]
        #[event_set(schema_name = "iroha_data_model::events::data::events::trigger::TriggerEventSet")]
        pub enum TriggerEvent {
            /// Trigger was created.
            Created(TriggerId),
            /// Trigger was deleted.
            Deleted(TriggerId),
            #[has_origin(number_of_executions_changed => &number_of_executions_changed.trigger)]
            /// Trigger execution window was extended.
            Extended(TriggerNumberOfExecutionsChanged),
            #[has_origin(number_of_executions_changed => &number_of_executions_changed.trigger)]
            /// Trigger execution window was shortened.
            Shortened(TriggerNumberOfExecutionsChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was inserted or updated.
            MetadataInserted(TriggerMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target)]
            /// Metadata entry was removed.
            MetadataRemoved(TriggerMetadataChanged),
        }
    }
    #[model]
    mod model {
        use super::*;
        /// Depending on the wrapping event, [`Self`] represents the increased or decreased number of event executions.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::trigger::model::TriggerNumberOfExecutionsChanged"
        )]
        pub struct TriggerNumberOfExecutionsChanged {
            pub trigger: TriggerId,
            pub by: u32,
        }
    }
}

impl_json_via_norito_bytes!(TriggerNumberOfExecutionsChanged);
mod config {
    pub use self::model::*;
    use super::*;
    use crate::parameter::Parameter;
    #[model]
    mod model {
        use super::*;
        /// Changed parameter event
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::config::model::ParameterChanged"
        )]
        pub struct ParameterChanged {
            /// Previous value for the parameter
            pub old_value: Parameter,
            /// Next value for the parameter
            pub new_value: Parameter,
        }
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            EventSet,
            FromVariant,
            Decode,
            Encode,
            IntoSchema,
        )]
        /// Event emitted when a configuration parameter changes.
        #[event_set(
            schema_name = "iroha_data_model::events::data::events::config::model::ConfigurationEventSet"
        )]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::config::model::ConfigurationEvent"
        )]
        pub enum ConfigurationEvent {
            /// Configuration parameter value changed.
            Changed(ParameterChanged),
        }
    }
}

impl_json_via_norito_bytes!(ParameterChanged, ConfigurationEvent,);
mod executor {
    pub use self::model::*;
    use iroha_data_model_derive::model;
    // Keep super-module imports available for generated code paths.
    use super::*;
    #[model]
    mod model {
        use iroha_data_model_derive::EventSet;
        // Keep super-module imports available for generated code paths.
        use super::*;
        use crate::executor::ExecutorDataModel;
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            iroha_schema::IntoSchema,
            EventSet,
        )]
        #[repr(transparent)]
        /// Event emitted when the executor data model is upgraded.
        #[event_set(
            schema_name = "iroha_data_model::events::data::events::executor::model::ExecutorEventSet"
        )]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::executor::model::ExecutorEvent"
        )]
        pub enum ExecutorEvent {
            /// Executor data model was upgraded.
            Upgraded(ExecutorUpgrade),
        }
        /// Information about the updated executor data model.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, Getters,
        )]
        #[repr(transparent)]
        #[getset(get = "pub")]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::events::data::events::executor::model::ExecutorUpgrade"
        )]
        pub struct ExecutorUpgrade {
            /// Updated data model
            pub new_data_model: ExecutorDataModel,
        }
    }
}

impl_json_via_norito_bytes!(ExecutorEvent, ExecutorUpgrade);
/// Trait for events originating from [`HasOrigin::Origin`].
pub trait HasOrigin {
    /// Type of the origin.
    type Origin: Identifiable;
    /// Identification of the origin.
    fn origin(&self) -> &<Self::Origin as Identifiable>::Id;
}
impl From<NftEvent> for DataEvent {
    fn from(value: NftEvent) -> Self {
        DomainEvent::Nft(value).into()
    }
}
impl From<RwaEvent> for DataEvent {
    fn from(value: RwaEvent) -> Self {
        DomainEvent::Rwa(value).into()
    }
}
impl DataEvent {
    /// Route an account event under a real domain context carried by the emitting operation.
    #[must_use]
    pub fn account_in_domain(event: AccountEvent, domain: DomainId) -> Self {
        Self::Domain(DomainEvent::Account(domain::ScopedAccount {
            domain,
            event,
        }))
    }
    /// Route an asset event using its authoritative persisted definition domain.
    #[must_use]
    pub fn asset(event: AssetEvent, domain: Option<DomainId>) -> Self {
        match domain {
            Some(domain) => Self::Domain(DomainEvent::Asset(domain::ScopedAsset { domain, event })),
            None => event.into(),
        }
    }
    /// Route an asset-definition event using its authoritative persisted domain.
    #[must_use]
    pub fn asset_definition(event: AssetDefinitionEvent, domain: Option<DomainId>) -> Self {
        match domain {
            Some(domain) => Self::Domain(DomainEvent::AssetDefinition(
                domain::ScopedAssetDefinition { domain, event },
            )),
            None => event.into(),
        }
    }
    /// Return the domain id of [`DataEvent`]
    pub fn domain(&self) -> Option<&DomainId> {
        match self {
            Self::Domain(event) => Some(event.origin()),
            Self::Account(_) | Self::Asset(_) | Self::AssetDefinition(_) => None,
            #[cfg(feature = "governance")]
            Self::Governance(_) => None,
            _ => None,
        }
    }
}
#[cfg(test)]
mod event_routing_tests {
    use super::{
        DataEvent,
        asset::{AssetChanged, AssetDefinitionEvent, AssetEvent},
        domain::{DomainEvent, ScopedAsset, ScopedAssetDefinition},
    };
    use crate::{
        PublicKey,
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
    };
    use iroha_model_base::domain::DomainId;
    #[test]
    fn opaque_asset_definition_events_route_without_domain_wrapper() {
        let domain_id: DomainId = DomainId::try_new("reward", "universal").expect("domain");
        let scoped_definition = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "fee".parse().expect("asset name"),
        );
        let opaque_definition: AssetDefinitionId = scoped_definition
            .to_string()
            .parse()
            .expect("opaque canonical asset definition id");
        let opaque_event = AssetDefinitionEvent::Deleted(opaque_definition.clone());
        assert!(matches!(
            DataEvent::from(opaque_event.clone()),
            DataEvent::AssetDefinition(AssetDefinitionEvent::Deleted(id))
                if id == opaque_definition
        ));
        assert!(DataEvent::from(opaque_event).domain().is_none());
        let scoped_event = AssetDefinitionEvent::Deleted(scoped_definition);
        assert!(matches!(
            DataEvent::asset_definition(scoped_event, Some(domain_id.clone())),
            DataEvent::Domain(DomainEvent::AssetDefinition(ScopedAssetDefinition {
                domain,
                ..
            })) if domain == domain_id
        ));
    }
    #[test]
    fn opaque_asset_events_route_without_domain_wrapper() {
        let domain_id: DomainId = DomainId::try_new("reward", "universal").expect("domain");
        let scoped_definition = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "fee".parse().expect("asset name"),
        );
        let opaque_definition: AssetDefinitionId = scoped_definition
            .to_string()
            .parse()
            .expect("opaque canonical asset definition id");
        let public_key: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let account_id = AccountId::new(public_key);
        let asset_id = AssetId::of(opaque_definition, account_id);
        let opaque_event = AssetEvent::Added(AssetChanged {
            asset: asset_id.clone(),
            amount: 1_u32.into(),
        });
        assert!(matches!(
            DataEvent::from(opaque_event.clone()),
            DataEvent::Asset(AssetEvent::Added(change)) if change.asset == asset_id
        ));
        assert!(DataEvent::from(opaque_event).domain().is_none());
        let scoped = DataEvent::asset(
            AssetEvent::Added(AssetChanged {
                asset: asset_id,
                amount: 1_u32.into(),
            }),
            Some(domain_id.clone()),
        );
        assert!(matches!(
            &scoped,
            DataEvent::Domain(DomainEvent::Asset(ScopedAsset { domain, .. }))
                if domain == &domain_id
        ));
        let encoded = norito::codec::Encode::encode(&scoped);
        let decoded = <DataEvent as norito::codec::Decode>::decode(&mut encoded.as_slice())
            .expect("decode explicitly scoped opaque asset event");
        assert_eq!(decoded, scoped);
        assert_eq!(decoded.domain(), Some(&domain_id));
    }
    #[test]
    fn domainless_account_event_roundtrips_without_domain_wrapper() {
        let public_key: PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let account_id = AccountId::new(public_key);
        let event = DataEvent::from(super::account::AccountEvent::Deleted(account_id));
        assert!(matches!(event, DataEvent::Account(_)));
        assert!(event.domain().is_none());
        let encoded = norito::codec::Encode::encode(&event);
        let decoded = <DataEvent as norito::codec::Decode>::decode(&mut encoded.as_slice())
            .expect("decode domainless account event");
        assert_eq!(decoded, event);
        assert!(decoded.domain().is_none());
    }
}
#[cfg(test)]
mod tests {
    use super::MetadataChanged;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::json::Json;
    #[test]
    fn metadata_changed_json_roundtrip() {
        let changed = MetadataChanged {
            target: DomainId::try_new("default", "universal").expect("valid domain"),
            key: "metadata_key".parse().expect("valid name"),
            value: Json::from("metadata_value"),
        };
        let json = norito::json::to_json(&changed).expect("serialize");
        let decoded: MetadataChanged<DomainId> =
            norito::json::from_str(&json).expect("deserialize");
        assert_eq!(changed, decoded);
        assert_eq!(
            norito::json::to_json_bounded(&changed, json.len()).expect("serialize at exact bound"),
            json
        );
        assert_eq!(
            norito::json::to_json_bounded(&changed, json.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
    }
}
pub mod prelude {
    pub use super::model::{DataEvent, MetadataChanged};
    pub use super::{
        HasOrigin,
        account::{
            AccountControllerReplaced, AccountCreated, AccountEvent, AccountEventSet,
            AccountPermissionChanged, AccountRecoveryApproved, AccountRecoveryCancellationApproved,
            AccountRecoveryCancelled, AccountRecoveryEvent, AccountRecoveryEventSet,
            AccountRecoveryFinalized, AccountRecoveryPolicyCleared, AccountRecoveryPolicySet,
            AccountRecoveryProposed, AccountRoleChanged,
        },
        asset::{
            AssetBatchTransferLegStatus, AssetBatchTransferOutcome, AssetBatchTransferRejection,
            AssetBatchTransferRejectionCode, AssetChanged, AssetDefinitionEvent,
            AssetDefinitionEventSet, AssetDefinitionMintabilityChanged,
            AssetDefinitionOwnerChanged, AssetDefinitionTotalQuantityChanged, AssetEvent,
            AssetEventSet, AssetMetadataChanged, AssetTransferred,
        },
        bridge::{BridgeEvent, BridgeEventSet},
        config::{ConfigurationEvent, ConfigurationEventSet, ParameterChanged},
        domain::{
            AccountDomainLinkChanged, DomainEvent, DomainEventSet, DomainOwnerChanged,
            KaigiRelayHealthSummary, KaigiRelayManifestSummary, KaigiRelayRegistrationSummary,
            KaigiRelayUnregistrationSummary, KaigiRosterSummary, KaigiStatusSummary,
            KaigiUsageSummary, ScopedAccount, ScopedAsset, ScopedAssetDefinition,
            StreamingPrivacyRelay, StreamingPrivacyRoute, StreamingRouteBinding,
            StreamingSoranetAccessKind, StreamingSoranetRoute, StreamingSoranetStreamTag,
            StreamingTicketCapabilities, StreamingTicketPolicy, StreamingTicketReady,
            StreamingTicketRecord, StreamingTicketRevoked,
        },
        executor::{ExecutorEvent, ExecutorEventSet, ExecutorUpgrade},
        nft::{NftEvent, NftEventSet, NftOwnerChanged},
        peer::{PeerEvent, PeerEventSet},
        repo_account::{
            RepoAccountEvent, RepoAccountEventSet, RepoAccountInitiated, RepoAccountMarginCalled,
            RepoAccountRole, RepoAccountSettled,
        },
        role::{RoleEvent, RoleEventSet, RolePermissionChanged},
        rwa::{
            RwaControlsChanged, RwaEvent, RwaEventSet, RwaHoldChanged, RwaMerged, RwaOwnerChanged,
            RwaQuantityChanged, RwaSplit,
        },
        trigger::{TriggerEvent, TriggerEventSet, TriggerNumberOfExecutionsChanged},
    };
}

#[cfg(test)]
mod captured_event_boundary_identity_tests;

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::{account, audit};

    #[test]
    fn original_metadata_event_checked_container_retains_borrowed_json_and_depth() {
        audit(&MetadataChanged {
            target: account(61),
            key: "original".parse().unwrap(),
            value: iroha_primitives::json::Json::new(vec![1_u64, 2]),
        });
    }
}
