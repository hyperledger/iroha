//! This module contains filters for data events.
//!
//! For each event in [`super::events`], there's a corresponding filter type in this module. It can filter the events by origin id and event type.
//!
//! Event types are filtered with an `EventSet` type, allowing to filter for multiple event types at once.
pub use self::model::*;
use super::*;
pub use bridge_filters_model::BridgeEventFilter;
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use std::fmt::Debug;
#[model]
mod model {
    use super::*;
    #[derive(
        Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, Decode, Encode, IntoSchema,
    )]
    /// Canonical data-event selectors. Capability-specific variants keep their assigned wire tags.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::DataEventFilter")]
    pub enum DataEventFilter {
        /// Matches any data events ([`DataEvent`])
        #[codec(index = 0)]
        Any,
        /// Matches [`PeerEvent`]s
        #[codec(index = 1)]
        Peer(PeerEventFilter),
        /// Matches [`DomainEvent`]s
        #[codec(index = 2)]
        Domain(DomainEventFilter),
        /// Matches [`AccountEvent`]s
        #[codec(index = 3)]
        Account(AccountEventFilter),
        /// Matches [`AssetEvent`]s
        #[codec(index = 4)]
        Asset(AssetEventFilter),
        /// Matches [`AssetDefinitionEvent`]s
        #[codec(index = 5)]
        AssetDefinition(AssetDefinitionEventFilter),
        /// Matches [`NftEvent`]s
        #[codec(index = 6)]
        Nft(NftEventFilter),
        /// Matches [`RwaEvent`]s
        #[codec(index = 7)]
        Rwa(RwaEventFilter),
        /// Matches [`TriggerEvent`]s
        #[codec(index = 8)]
        Trigger(TriggerEventFilter),
        /// Matches [`RoleEvent`]s
        #[codec(index = 9)]
        Role(RoleEventFilter),
        /// Matches [`ConfigurationEvent`]s
        #[codec(index = 10)]
        Configuration(ConfigurationEventFilter),
        /// Matches [`ExecutorEvent`]s
        #[codec(index = 11)]
        Executor(ExecutorEventFilter),
        /// Matches proof verification events
        #[codec(index = 12)]
        Proof(ProofEventFilter),
        /// Matches verifying key registry lifecycle events
        #[codec(index = 13)]
        VerifyingKey(VerifyingKeyEventFilter),
        /// Matches runtime upgrade lifecycle events
        #[codec(index = 14)]
        RuntimeUpgrade(RuntimeUpgradeEventFilter),
        /// Matches resolver directory governance events
        #[codec(index = 15)]
        Soradns(SoradnsDirectoryEventFilter),
        /// Matches `SoraFS` gateway compliance events
        #[codec(index = 16)]
        Sorafs(SorafsGatewayEventFilter),
        /// Matches Musubi package-registry and archive lifecycle events
        #[codec(index = 17)]
        Musubi(MusubiEventFilter),
        /// Matches Space Directory manifest lifecycle events
        #[codec(index = 18)]
        SpaceDirectory(SpaceDirectoryEventFilter),
        /// Matches native asset escrow lifecycle events
        #[codec(index = 19)]
        Escrow(EscrowEventFilter),
        /// Matches oracle feed lifecycle events
        #[codec(index = 20)]
        Oracle(OracleEventFilter),
        /// Matches viral incentive lifecycle events
        #[codec(index = 21)]
        Social(SocialEventFilter),
        /// Matches [`BridgeEvent`]s
        #[codec(index = 22)]
        Bridge(BridgeEventFilter),
        /// Matches governance lifecycle events
        #[cfg(feature = "governance")]
        #[codec(index = 23)]
        Governance(GovernanceEventFilter),
        /// Native race events, optionally restricted to one race identifier.
        #[codec(index = 24)]
        GameSession(Option<iroha_crypto::Hash>),
        /// Matches SCCP v1 cross-chain events.
        #[codec(index = 25)]
        Sccp(SccpEventFilter),
        /// Ordinary Load execution events, optionally matching one receipt digest.
        #[codec(index = 26)]
        KagemushaLoadCommitted(Option<[u8; 32]>),
    }
    /// An event filter for [`crate::sccp::events::SccpEvent`] values (`specs/sccp.md` §4.17).
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::SccpEventFilter")]
    pub struct SccpEventFilter {
        /// If specified, matches only events that name this external network.
        pub(super) network_matcher: Option<crate::bridge::SccpNetworkV1>,
        /// Matches only events from this set.
        pub(super) event_set: crate::sccp::events::SccpEventSet,
    }
    /// An event filter for [`super::proof::ProofEvent`] values.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::ProofEventFilter")]
    pub struct ProofEventFilter {
        /// If specified, matches only events for this proof id
        pub(super) id_matcher: Option<crate::proof::ProofId>,
        /// Matches only events from this set
        pub(super) event_set: super::proof::ProofEventSet,
    }
    /// An event filter for [`super::verifying_keys::VerifyingKeyEvent`] values.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::VerifyingKeyEventFilter"
    )]
    pub struct VerifyingKeyEventFilter {
        /// If specified, matches only events for this verifying key id (backend + name)
        pub(super) id_matcher: Option<crate::proof::VerifyingKeyId>,
        /// Matches only events from this set
        pub(super) event_set: super::verifying_keys::VerifyingKeyEventSet,
    }
    /// An event filter for [`super::runtime_upgrade::RuntimeUpgradeEvent`] values.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::RuntimeUpgradeEventFilter"
    )]
    pub struct RuntimeUpgradeEventFilter {
        /// If specified, matches only events for this runtime upgrade id
        pub(super) id_matcher: Option<crate::runtime::RuntimeUpgradeId>,
        /// Matches only events from this set
        pub(super) event_set: super::runtime_upgrade::RuntimeUpgradeEventSet,
    }
    /// An event filter for viral incentive lifecycle events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::SocialEventFilter")]
    pub struct SocialEventFilter {
        /// If specified, matches only events for this binding hash.
        pub(super) binding_matcher: Option<crate::oracle::KeyedHash>,
    }
    /// An event filter for [`super::soradns::SoradnsDirectoryEvent`] values.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::SoradnsDirectoryEventFilter"
    )]
    pub struct SoradnsDirectoryEventFilter {
        /// If specified, matches only events for this directory identifier.
        pub(super) directory_matcher: Option<crate::soradns::DirectoryId>,
        /// If specified, matches only events for this resolver identifier.
        pub(super) resolver_matcher: Option<crate::soradns::ResolverId>,
        /// Matches only events from this set.
        pub(super) event_set: super::soradns::SoradnsDirectoryEventSet,
    }
    /// An event filter for [`super::sorafs::SorafsGatewayEvent`] values.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::SorafsGatewayEventFilter"
    )]
    pub struct SorafsGatewayEventFilter {
        /// If specified, matches only events for this provider id.
        pub(super) provider_matcher: Option<crate::sorafs::capacity::ProviderId>,
        /// If specified, matches only events for this manifest digest.
        pub(super) manifest_digest_matcher: Option<crate::sorafs::pin_registry::ManifestDigest>,
        /// If specified, matches only events for this policy classification.
        pub(super) policy_matcher: Option<super::sorafs::SorafsGarPolicy>,
        /// If specified, matches only events for this detailed outcome.
        pub(super) detail_matcher: Option<super::sorafs::SorafsGarPolicyDetail>,
        /// Matches only events from this set.
        pub(super) event_set: super::sorafs::SorafsGatewayEventSet,
    }
    /// Exact structural filter for Musubi registry events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::MusubiEventFilter")]
    pub struct MusubiEventFilter {
        /// If set, match only events structurally associated with this package.
        pub(super) package_matcher: Option<crate::musubi::MusubiPackageIdV1>,
        /// If set, match only events structurally associated with this archive.
        pub(super) archive_matcher: Option<crate::musubi::ArchiveId>,
        /// If set, match only events structurally associated with this permanent alias.
        pub(super) alias_matcher: Option<crate::musubi::MusubiAliasNameV1>,
        /// Closed set of accepted Musubi transition variants.
        pub(super) event_set: super::musubi::MusubiEventSet,
    }
    /// Filter for Space Directory manifest lifecycle events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::SpaceDirectoryEventFilter"
    )]
    pub struct SpaceDirectoryEventFilter {
        /// If specified, matches only events originating from this dataspace.
        pub(super) dataspace_matcher: Option<iroha_model_base::topology::DataSpaceId>,
        /// If specified, matches only events associated with this UAID.
        pub(super) uaid_matcher: Option<crate::nexus::UniversalAccountId>,
        /// Matches only events from this set.
        pub(super) event_set: super::space_directory::SpaceDirectoryEventSet,
    }
    /// Filter for native asset escrow lifecycle events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::EscrowEventFilter")]
    pub struct EscrowEventFilter {
        /// If specified, matches only events for this escrow identifier.
        pub(super) escrow_matcher: Option<crate::escrow::EscrowId>,
        /// If specified, matches only events for escrows opened by this seller.
        pub(super) seller_matcher: Option<crate::account::AccountId>,
        /// If specified, matches only events for escrows accepted by this buyer.
        pub(super) buyer_matcher: Option<crate::account::AccountId>,
        /// If specified, matches only events whose carried record has this status.
        pub(super) status_matcher: Option<crate::escrow::AssetEscrowStatus>,
        /// Matches only events from this set.
        pub(super) event_set: super::escrow::EscrowEventSet,
    }
    #[cfg(feature = "governance")]
    /// An event filter for [`super::governance::GovernanceEvent`] values.
    ///
    /// Scope selectors are intersected. Because proposal and referendum event
    /// families are disjoint, setting both selectors matches no events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::GovernanceEventFilter")]
    pub struct GovernanceEventFilter {
        /// If specified, matches only proposal-family events that carry this proposal id.
        pub(super) proposal_id: Option<[u8; 32]>,
        /// If specified, matches only referendum-family events that carry this referendum id.
        pub(super) referendum_id: Option<String>,
        /// Matches only events from this set
        pub(super) event_set: super::governance::GovernanceEventSet,
    }
    /// An event filter for [`PeerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::PeerEventFilter")]
    pub struct PeerEventFilter {
        /// If specified matches only events originating from this peer
        pub(super) id_matcher: Option<iroha_model_base::peer::PeerId>,
        /// Matches only event from this set
        pub(super) event_set: PeerEventSet,
    }
    /// An event filter for [`DomainEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::DomainEventFilter")]
    pub struct DomainEventFilter {
        /// If specified matches only events originating from this domain
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<iroha_model_base::domain::DomainId>,
        /// Matches only event from this set
        pub(super) event_set: DomainEventSet,
    }
    /// An event filter for [`AccountEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::AccountEventFilter")]
    pub struct AccountEventFilter {
        /// If specified matches only events originating from this account
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<super::AccountId>,
        /// Matches only event from this set
        pub(super) event_set: AccountEventSet,
    }
    /// An event filter for [`AssetEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::AssetEventFilter")]
    pub struct AssetEventFilter {
        /// If specified matches only events originating from this asset
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<super::AssetId>,
        /// If specified matches only events for assets belonging to this asset definition
        #[getset(get = "pub")]
        pub(super) asset_definition_matcher: Option<super::AssetDefinitionId>,
        /// If specified matches only transfer events debiting this account.
        #[getset(get = "pub")]
        pub(super) transfer_source_account_matcher: Option<super::AccountId>,
        /// If specified matches only transfer events crediting this account.
        #[getset(get = "pub")]
        pub(super) transfer_destination_account_matcher: Option<super::AccountId>,
        /// Matches only event from this set
        pub(super) event_set: AssetEventSet,
    }
    /// An event filter for [`AssetDefinitionEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::AssetDefinitionEventFilter"
    )]
    pub struct AssetDefinitionEventFilter {
        /// If specified matches only events originating from this asset definition
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<super::AssetDefinitionId>,
        /// Matches only event from this set
        pub(super) event_set: AssetDefinitionEventSet,
    }
    /// An event filter for [`NftEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::NftEventFilter")]
    pub struct NftEventFilter {
        /// If specified matches only events originating from this NFT
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<NftId>,
        /// Matches only event from this set
        pub(super) event_set: NftEventSet,
    }
    /// An event filter for [`RwaEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::RwaEventFilter")]
    pub struct RwaEventFilter {
        /// If specified matches only events originating from this RWA lot.
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<RwaId>,
        /// Matches only events from this set.
        pub(super) event_set: RwaEventSet,
    }
    /// An event filter for [`TriggerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::TriggerEventFilter")]
    pub struct TriggerEventFilter {
        /// If specified matches only events originating from this trigger
        #[getset(get = "pub")]
        pub(super) id_matcher: Option<super::TriggerId>,
        /// Matches only event from this set
        pub(super) event_set: TriggerEventSet,
    }
    /// An event filter for [`RoleEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::RoleEventFilter")]
    pub struct RoleEventFilter {
        /// If specified matches only events originating from this role
        pub(super) id_matcher: Option<super::RoleId>,
        /// Matches only event from this set
        pub(super) event_set: RoleEventSet,
    }
    /// An event filter for [`ConfigurationEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::filters::model::ConfigurationEventFilter"
    )]
    pub struct ConfigurationEventFilter {
        /// Matches only event from this set
        pub(super) event_set: ConfigurationEventSet,
    }
    /// An event filter for [`ExecutorEvent`].
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_data_model::events::data::filters::model::ExecutorEventFilter")]
    pub struct ExecutorEventFilter {
        // executor is a global entity, so no id here
        /// Matches only event from this set
        pub(super) event_set: ExecutorEventSet,
    }
}

impl_json_via_norito_bytes!(
    DataEventFilter,
    ProofEventFilter,
    VerifyingKeyEventFilter,
    RuntimeUpgradeEventFilter,
    MusubiEventFilter,
    PeerEventFilter,
    DomainEventFilter,
    AccountEventFilter,
    AssetEventFilter,
    AssetDefinitionEventFilter,
    NftEventFilter,
    RwaEventFilter,
    TriggerEventFilter,
    RoleEventFilter,
    ConfigurationEventFilter,
    ExecutorEventFilter,
    EscrowEventFilter,
);
#[cfg(feature = "governance")]
impl_json_via_norito_bytes!(GovernanceEventFilter);
impl PeerEventFilter {
    /// Creates a new [`PeerEventFilter`] accepting all [`PeerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: PeerEventSet::all(),
        }
    }
    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_peer(mut self, id_matcher: PeerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: PeerEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl ProofEventFilter {
    /// Creates a new [`ProofEventFilter`] accepting all [`super::proof::ProofEvent`] values.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: super::proof::ProofEventSet::all(),
        }
    }
    /// Filter by proof identifier.
    #[must_use]
    pub fn for_proof(mut self, id: crate::proof::ProofId) -> Self {
        self.id_matcher = Some(id);
        self
    }
    /// Filter by event kinds.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::proof::ProofEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl VerifyingKeyEventFilter {
    /// Creates a new [`VerifyingKeyEventFilter`] accepting all [`super::verifying_keys::VerifyingKeyEvent`] values.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: super::verifying_keys::VerifyingKeyEventSet::all(),
        }
    }
    /// Filter by verifying key identifier.
    #[must_use]
    pub fn for_verifying_key(mut self, id: crate::proof::VerifyingKeyId) -> Self {
        self.id_matcher = Some(id);
        self
    }
    /// Filter by event kinds.
    #[must_use]
    pub const fn for_events(
        mut self,
        event_set: super::verifying_keys::VerifyingKeyEventSet,
    ) -> Self {
        self.event_set = event_set;
        self
    }
}
impl RuntimeUpgradeEventFilter {
    /// Creates a new [`RuntimeUpgradeEventFilter`] accepting all runtime upgrade events.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: super::runtime_upgrade::RuntimeUpgradeEventSet::all(),
        }
    }
    /// Filter by runtime upgrade identifier.
    #[must_use]
    pub fn for_runtime(mut self, id: crate::runtime::RuntimeUpgradeId) -> Self {
        self.id_matcher = Some(id);
        self
    }
    /// Filter by runtime upgrade event kinds.
    #[must_use]
    pub const fn for_events(
        mut self,
        event_set: super::runtime_upgrade::RuntimeUpgradeEventSet,
    ) -> Self {
        self.event_set = event_set;
        self
    }
}
impl SorafsGatewayEventFilter {
    /// Creates a new [`SorafsGatewayEventFilter`] accepting all gateway events.
    pub const fn new() -> Self {
        Self {
            provider_matcher: None,
            manifest_digest_matcher: None,
            policy_matcher: None,
            detail_matcher: None,
            event_set: super::sorafs::SorafsGatewayEventSet::all(),
        }
    }
    /// Filter by provider identifier.
    #[must_use]
    pub fn for_provider(mut self, provider: crate::sorafs::capacity::ProviderId) -> Self {
        self.provider_matcher = Some(provider);
        self
    }
    /// Filter by manifest digest.
    #[must_use]
    pub fn for_manifest_digest(
        mut self,
        digest: crate::sorafs::pin_registry::ManifestDigest,
    ) -> Self {
        self.manifest_digest_matcher = Some(digest);
        self
    }
    /// Filter by policy classification.
    #[must_use]
    pub fn for_policy(mut self, policy: super::sorafs::SorafsGarPolicy) -> Self {
        self.policy_matcher = Some(policy);
        self
    }
    /// Filter by detailed outcome.
    #[must_use]
    pub fn for_detail(mut self, detail: super::sorafs::SorafsGarPolicyDetail) -> Self {
        self.detail_matcher = Some(detail);
        self
    }
    /// Filter by event variant set.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::sorafs::SorafsGatewayEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl MusubiEventFilter {
    /// Create a filter accepting every Musubi transition.
    pub const fn new() -> Self {
        Self {
            package_matcher: None,
            archive_matcher: None,
            alias_matcher: None,
            event_set: super::musubi::MusubiEventSet::all(),
        }
    }
    /// Match only events structurally associated with `package`.
    #[must_use]
    pub fn for_package(mut self, package: crate::musubi::MusubiPackageIdV1) -> Self {
        self.package_matcher = Some(package);
        self
    }
    /// Match only events structurally associated with `archive`.
    #[must_use]
    pub const fn for_archive(mut self, archive: crate::musubi::ArchiveId) -> Self {
        self.archive_matcher = Some(archive);
        self
    }
    /// Match only events structurally associated with `alias`.
    #[must_use]
    pub fn for_alias(mut self, alias: crate::musubi::MusubiAliasNameV1) -> Self {
        self.alias_matcher = Some(alias);
        self
    }
    /// Match only transition variants contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::musubi::MusubiEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl SoradnsDirectoryEventFilter {
    /// Creates a new [`SoradnsDirectoryEventFilter`] accepting all directory events.
    pub const fn new() -> Self {
        Self {
            directory_matcher: None,
            resolver_matcher: None,
            event_set: super::soradns::SoradnsDirectoryEventSet::all(),
        }
    }
    /// Constrains the filter to a specific directory identifier.
    #[must_use]
    pub const fn for_directory(mut self, directory_id: crate::soradns::DirectoryId) -> Self {
        self.directory_matcher = Some(directory_id);
        self
    }
    /// Constrains the filter to a specific resolver identifier.
    #[must_use]
    pub const fn for_resolver(mut self, resolver_id: crate::soradns::ResolverId) -> Self {
        self.resolver_matcher = Some(resolver_id);
        self
    }
    /// Restricts the filter to the supplied set of events.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::soradns::SoradnsDirectoryEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl SpaceDirectoryEventFilter {
    /// Creates a new [`SpaceDirectoryEventFilter`] accepting all events.
    pub const fn new() -> Self {
        Self {
            dataspace_matcher: None,
            uaid_matcher: None,
            event_set: super::space_directory::SpaceDirectoryEventSet::all(),
        }
    }
    /// Filter by dataspace identifier.
    #[must_use]
    pub fn for_dataspace(mut self, dataspace: iroha_model_base::topology::DataSpaceId) -> Self {
        self.dataspace_matcher = Some(dataspace);
        self
    }
    /// Filter by UAID.
    #[must_use]
    pub fn for_uaid(mut self, uaid: crate::nexus::UniversalAccountId) -> Self {
        self.uaid_matcher = Some(uaid);
        self
    }
    /// Filter by event variants.
    #[must_use]
    pub const fn for_events(
        mut self,
        event_set: super::space_directory::SpaceDirectoryEventSet,
    ) -> Self {
        self.event_set = event_set;
        self
    }
}
impl EscrowEventFilter {
    /// Creates a new [`EscrowEventFilter`] accepting all escrow events.
    pub const fn new() -> Self {
        Self {
            escrow_matcher: None,
            seller_matcher: None,
            buyer_matcher: None,
            status_matcher: None,
            event_set: super::escrow::EscrowEventSet::all(),
        }
    }
    /// Restricts matches to a specific escrow identifier.
    #[must_use]
    pub const fn for_escrow(mut self, escrow_id: crate::escrow::EscrowId) -> Self {
        self.escrow_matcher = Some(escrow_id);
        self
    }
    /// Restricts matches to escrows opened by the provided seller.
    #[must_use]
    pub fn for_seller(mut self, seller: crate::account::AccountId) -> Self {
        self.seller_matcher = Some(seller);
        self
    }
    /// Restricts matches to escrows accepted by the provided buyer.
    #[must_use]
    pub fn for_buyer(mut self, buyer: crate::account::AccountId) -> Self {
        self.buyer_matcher = Some(buyer);
        self
    }
    /// Restricts matches to records in the provided escrow status.
    #[must_use]
    pub const fn for_status(mut self, status: crate::escrow::AssetEscrowStatus) -> Self {
        self.status_matcher = Some(status);
        self
    }
    /// Restricts matches to the provided event-set.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::escrow::EscrowEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for RuntimeUpgradeEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for VerifyingKeyEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for ProofEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for SorafsGatewayEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for MusubiEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for SoradnsDirectoryEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for SpaceDirectoryEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for EscrowEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for OracleEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
/// Filter for oracle feed aggregation events.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::events::data::filters::OracleEventFilter")]
pub struct OracleEventFilter {
    /// Optional feed identifier matcher.
    pub(super) feed_matcher: Option<crate::oracle::FeedId>,
    /// Matched event-set.
    pub(super) event_set: super::oracle::OracleEventSet,
}
impl OracleEventFilter {
    /// Creates a new [`OracleEventFilter`] accepting all events.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            feed_matcher: None,
            event_set: super::oracle::OracleEventSet::all(),
        }
    }
    /// Restricts matches to the provided feed identifier.
    #[must_use]
    pub fn for_feed(mut self, feed_id: crate::oracle::FeedId) -> Self {
        self.feed_matcher = Some(feed_id);
        self
    }
    /// Restricts matches to the provided oracle event set.
    #[must_use]
    pub const fn for_events(mut self, event_set: super::oracle::OracleEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl SocialEventFilter {
    /// Creates a new [`SocialEventFilter`] accepting all viral incentive events.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            binding_matcher: None,
        }
    }
    /// Restricts matches to the provided binding hash.
    #[must_use]
    pub fn for_binding(mut self, binding: crate::oracle::KeyedHash) -> Self {
        self.binding_matcher = Some(binding);
        self
    }
}
impl Default for SocialEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl SccpEventFilter {
    /// Creates a new [`SccpEventFilter`] accepting every SCCP event.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            network_matcher: None,
            event_set: crate::sccp::events::SccpEventSet::all(),
        }
    }
    /// Restricts matches to events that name `network` (events without a network never match).
    #[must_use]
    pub const fn for_network(mut self, network: crate::bridge::SccpNetworkV1) -> Self {
        self.network_matcher = Some(network);
        self
    }
    /// Restricts matches to the provided event set.
    #[must_use]
    pub const fn for_events(mut self, event_set: crate::sccp::events::SccpEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for SccpEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
/// Return the external network an SCCP event names, if any.
///
/// Block commitments and native finality/generation events concern Taira itself and name no
/// external network; the governance event names the subjects it changed instead.
#[cfg(feature = "transparent_api")]
fn sccp_event_network(
    event: &crate::sccp::events::SccpEvent,
) -> Option<crate::bridge::SccpNetworkV1> {
    use crate::sccp::events::SccpEvent;
    match event {
        SccpEvent::MessageRecorded(ev) => Some(ev.network),
        SccpEvent::InboundProven(ev) => Some(ev.network),
        SccpEvent::RecipientRegistered(ev) => Some(ev.network),
        SccpEvent::InboundReleased(ev) => Some(ev.network),
        SccpEvent::InboundBounced(ev) => Some(ev.network),
        SccpEvent::InboundLiabilityShortfall(ev) => Some(ev.network),
        SccpEvent::OutboundVoided(ev) => Some(ev.network),
        SccpEvent::OutboundRefunded(ev) => Some(ev.network),
        SccpEvent::OutboundStranded(ev) => Some(ev.network),
        SccpEvent::StrandedReleased(ev) => Some(ev.network),
        SccpEvent::LightClientAdvanced(ev) => Some(ev.network),
        SccpEvent::LightClientFrozen(ev) => Some(ev.network),
        SccpEvent::LightClientInitialized(ev) => Some(ev.network),
        SccpEvent::TrustedCheckpointInstalled(ev) => Some(ev.network),
        SccpEvent::RevisionActivationChanged(ev) => Some(ev.network),
        SccpEvent::ControlRecorded(ev) => Some(ev.network),
        SccpEvent::BlockCommitted(_)
        | SccpEvent::GovernanceEnacted(_)
        | SccpEvent::FinalityDegraded(_)
        | SccpEvent::CommitteeGenerationCreated(_)
        | SccpEvent::CommitteeResync(_)
        | SccpEvent::GenerationMemberUnslashable(_)
        | SccpEvent::GenerationDestinationCleared(_) => None,
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for SccpEventFilter {
    type Event = crate::sccp::events::SccpEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.event_set.matches(event)
            && self
                .network_matcher
                .is_none_or(|network| sccp_event_network(event) == Some(network))
    }
}
impl Default for PeerEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for ProofEventFilter {
    type Event = super::proof::ProofEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        let id_ok = self
            .id_matcher
            .as_ref()
            .is_none_or(|id_matcher| match event {
                super::proof::ProofEvent::Verified(v) => id_matcher == &v.id,
                super::proof::ProofEvent::Rejected(r) => id_matcher == &r.id,
                super::proof::ProofEvent::Pruned(p) => {
                    p.removed.iter().any(|rid| id_matcher == rid)
                }
            });
        id_ok && self.event_set.matches(event)
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for VerifyingKeyEventFilter {
    type Event = super::verifying_keys::VerifyingKeyEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        let id_ok = self
            .id_matcher
            .as_ref()
            .is_none_or(|id_matcher| match event {
                super::verifying_keys::VerifyingKeyEvent::Registered(e) => id_matcher == &e.id,
                super::verifying_keys::VerifyingKeyEvent::Updated(e) => id_matcher == &e.id,
            });
        id_ok && self.event_set.matches(event)
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for RuntimeUpgradeEventFilter {
    type Event = super::runtime_upgrade::RuntimeUpgradeEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        let id_ok = self
            .id_matcher
            .as_ref()
            .is_none_or(|id_matcher| match event {
                super::runtime_upgrade::RuntimeUpgradeEvent::Proposed(e) => id_matcher == &e.id,
                super::runtime_upgrade::RuntimeUpgradeEvent::Activated(e) => id_matcher == &e.id,
                super::runtime_upgrade::RuntimeUpgradeEvent::Canceled(e) => id_matcher == &e.id,
            });
        id_ok && self.event_set.matches(event)
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for OracleEventFilter {
    type Event = super::oracle::OracleEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(feed_id) = self.feed_matcher.as_ref() {
            let feed_matches = match event {
                super::oracle::OracleEvent::FeedProcessed(record) => {
                    &record.event.feed_id == feed_id
                }
                super::oracle::OracleEvent::PenaltyApplied(penalty) => &penalty.feed_id == feed_id,
                super::oracle::OracleEvent::RewardApplied(reward) => &reward.feed_id == feed_id,
                super::oracle::OracleEvent::DisputeOpened(dispute)
                | super::oracle::OracleEvent::DisputeResolved(dispute) => {
                    &dispute.feed_id == feed_id
                }
                super::oracle::OracleEvent::ChangeProposed(change) => &change.feed_id == feed_id,
                super::oracle::OracleEvent::TwitterBindingRecorded(record) => {
                    &record.record.feed_id == feed_id
                }
                super::oracle::OracleEvent::DefiAttestationRecorded(record) => record
                    .attestation
                    .source_events
                    .iter()
                    .any(|source| &source.feed_id == feed_id),
                super::oracle::OracleEvent::ChangeStageUpdated(_)
                | super::oracle::OracleEvent::TwitterBindingRevoked(_) => false,
            };
            if !feed_matches {
                return false;
            }
        }
        self.event_set.matches(event)
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for SoradnsDirectoryEventFilter {
    type Event = super::soradns::SoradnsDirectoryEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        if !self.event_set.matches(event) {
            return false;
        }
        if let Some(directory_id) = self.directory_matcher.as_ref() {
            let matches_directory = match event {
                super::soradns::SoradnsDirectoryEvent::DraftSubmitted(payload) => {
                    &payload.directory_id == directory_id
                }
                super::soradns::SoradnsDirectoryEvent::Published(payload) => {
                    &payload.directory_id == directory_id
                }
                _ => false,
            };
            if !matches_directory {
                return false;
            }
        }
        if let Some(resolver_id) = self.resolver_matcher.as_ref() {
            let matches_resolver = match event {
                super::soradns::SoradnsDirectoryEvent::Revoked(payload) => {
                    &payload.resolver_id == resolver_id
                }
                super::soradns::SoradnsDirectoryEvent::Unrevoked(payload) => {
                    &payload.resolver_id == resolver_id
                }
                _ => false,
            };
            if !matches_resolver {
                return false;
            }
        }
        true
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for SorafsGatewayEventFilter {
    type Event = super::sorafs::SorafsGatewayEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        if !self.event_set.matches(event) {
            return false;
        }
        match event {
            super::sorafs::SorafsGatewayEvent::GarViolation(payload) => {
                let provider_ok = self
                    .provider_matcher
                    .as_ref()
                    .is_none_or(|expected| payload.provider_id.as_ref() == Some(expected));
                if !provider_ok {
                    return false;
                }
                let digest_ok = self
                    .manifest_digest_matcher
                    .as_ref()
                    .is_none_or(|expected| payload.manifest_digest.as_ref() == Some(expected));
                if !digest_ok {
                    return false;
                }
                let policy_ok = self
                    .policy_matcher
                    .as_ref()
                    .is_none_or(|expected| &payload.policy == expected);
                if !policy_ok {
                    return false;
                }
                self.detail_matcher
                    .as_ref()
                    .is_none_or(|expected| &payload.detail == expected)
            }
            super::sorafs::SorafsGatewayEvent::ProofHealth(payload) => {
                if self.manifest_digest_matcher.is_some()
                    || self.policy_matcher.is_some()
                    || self.detail_matcher.is_some()
                {
                    return false;
                }
                self.provider_matcher
                    .as_ref()
                    .is_none_or(|expected| &payload.provider_id == expected)
            }
            super::sorafs::SorafsGatewayEvent::RepairLedger(payload) => {
                if self.policy_matcher.is_some() || self.detail_matcher.is_some() {
                    return false;
                }
                let provider_ok = self
                    .provider_matcher
                    .as_ref()
                    .is_none_or(|expected| &payload.provider_id == expected);
                let manifest_ok = self
                    .manifest_digest_matcher
                    .as_ref()
                    .is_none_or(|expected| &payload.manifest_digest == expected);
                provider_ok && manifest_ok
            }
            super::sorafs::SorafsGatewayEvent::ModerationLedger(_) => {
                self.provider_matcher.is_none()
                    && self.manifest_digest_matcher.is_none()
                    && self.policy_matcher.is_none()
                    && self.detail_matcher.is_none()
            }
            super::sorafs::SorafsGatewayEvent::OrderbookLedger(payload) => {
                if self.manifest_digest_matcher.is_some()
                    || self.policy_matcher.is_some()
                    || self.detail_matcher.is_some()
                {
                    return false;
                }
                self.provider_matcher
                    .as_ref()
                    .is_none_or(|expected| payload.provider_id.as_ref() == Some(expected))
            }
            super::sorafs::SorafsGatewayEvent::ReserveLedger(payload) => {
                if self.manifest_digest_matcher.is_some()
                    || self.policy_matcher.is_some()
                    || self.detail_matcher.is_some()
                {
                    return false;
                }
                self.provider_matcher
                    .as_ref()
                    .is_none_or(|expected| payload.provider_id.as_ref() == Some(expected))
            }
            super::sorafs::SorafsGatewayEvent::ReputationJournal(payload) => {
                if self.manifest_digest_matcher.is_some()
                    || self.policy_matcher.is_some()
                    || self.detail_matcher.is_some()
                {
                    return false;
                }
                match payload {
                    super::sorafs::SorafsReputationJournalEvent::PolicyActivated(_) => {
                        self.provider_matcher.is_none()
                    }
                    super::sorafs::SorafsReputationJournalEvent::EntryCommitted(event) => self
                        .provider_matcher
                        .as_ref()
                        .is_none_or(|expected| &event.provider_id == expected),
                }
            }
        }
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for MusubiEventFilter {
    type Event = super::musubi::MusubiEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.event_set.matches(event)
            && self
                .package_matcher
                .as_ref()
                .is_none_or(|package| event.package() == Some(package))
            && self
                .archive_matcher
                .is_none_or(|archive| event.archive() == Some(archive))
            && self
                .alias_matcher
                .as_ref()
                .is_none_or(|alias| event.alias() == Some(alias))
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for SpaceDirectoryEventFilter {
    type Event = super::space_directory::SpaceDirectoryEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        if !self.event_set.matches(event) {
            return false;
        }
        let (dataspace, uaid) = match event {
            super::space_directory::SpaceDirectoryEvent::ManifestActivated(payload) => {
                (payload.dataspace, payload.uaid)
            }
            super::space_directory::SpaceDirectoryEvent::ManifestExpired(payload) => {
                (payload.dataspace, payload.uaid)
            }
            super::space_directory::SpaceDirectoryEvent::ManifestRevoked(payload) => {
                (payload.dataspace, payload.uaid)
            }
        };
        if let Some(expected) = self.dataspace_matcher
            && dataspace != expected
        {
            return false;
        }
        if let Some(expected) = self.uaid_matcher
            && uaid != expected
        {
            return false;
        }
        true
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for EscrowEventFilter {
    type Event = super::escrow::EscrowEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        if !self.event_set.matches(event) {
            return false;
        }
        let escrow = event.escrow();
        if let Some(expected) = self.escrow_matcher
            && escrow.id != expected
        {
            return false;
        }
        if let Some(expected) = self.seller_matcher.as_ref()
            && &escrow.seller != expected
        {
            return false;
        }
        if let Some(expected) = self.buyer_matcher.as_ref()
            && escrow.buyer.as_ref() != Some(expected)
        {
            return false;
        }
        if let Some(expected) = self.status_matcher
            && escrow.status != expected
        {
            return false;
        }
        true
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for SocialEventFilter {
    type Event = super::social::SocialEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        let binding_hash = match event {
            super::social::SocialEvent::RewardPaid(ev) => &ev.binding_hash,
            super::social::SocialEvent::EscrowCreated(ev) => &ev.escrow.binding_hash,
            super::social::SocialEvent::EscrowReleased(ev) => &ev.escrow.binding_hash,
            super::social::SocialEvent::EscrowCancelled(ev) => &ev.escrow.binding_hash,
        };
        self.binding_matcher
            .as_ref()
            .is_none_or(|expected| expected == binding_hash)
    }
}
#[cfg(feature = "transparent_api")]
impl EventFilter for PeerEventFilter {
    type Event = super::PeerEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl DomainEventFilter {
    /// Creates a new [`DomainEventFilter`] accepting all [`DomainEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: DomainEventSet::all(),
        }
    }
    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_domain(mut self, id_matcher: DomainId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: DomainEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for DomainEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl EventFilter for DomainEventFilter {
    type Event = super::DomainEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl AccountEventFilter {
    /// Creates a new [`AccountEventFilter`] accepting all [`AccountEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: AccountEventSet::all(),
        }
    }
    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_account(mut self, id_matcher: AccountId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AccountEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for AccountEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for AccountEventFilter {
    type Event = super::AccountEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl AssetEventFilter {
    /// Creates a new [`AssetEventFilter`] accepting all [`AssetEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            asset_definition_matcher: None,
            transfer_source_account_matcher: None,
            transfer_destination_account_matcher: None,
            event_set: AssetEventSet::all(),
        }
    }
    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_asset(mut self, id_matcher: AssetId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies an [`AssetEventFilter`] to accept only [`AssetEvent`]s whose assets belong to `asset_definition_matcher`.
    #[must_use]
    pub fn for_asset_definition(mut self, asset_definition_matcher: AssetDefinitionId) -> Self {
        self.asset_definition_matcher = Some(asset_definition_matcher);
        self
    }
    /// Match only transfer events whose source belongs to `account`.
    #[must_use]
    pub fn for_transfer_source_account(mut self, account: AccountId) -> Self {
        self.transfer_source_account_matcher = Some(account);
        self
    }
    /// Match only transfer events whose destination belongs to `account`.
    #[must_use]
    pub fn for_transfer_destination_account(mut self, account: AccountId) -> Self {
        self.transfer_destination_account_matcher = Some(account);
        self
    }
    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AssetEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for AssetEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetEventFilter {
    type Event = super::AssetEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self
                .asset_definition_matcher
                .as_ref()
                .is_none_or(|definition| definition == &event.origin().definition)
            && self
                .transfer_source_account_matcher
                .as_ref()
                .is_none_or(|account| {
                    matches!(
                        event,
                        AssetEvent::Transferred(transfer) if transfer.source().account() == account
                    )
                })
            && self
                .transfer_destination_account_matcher
                .as_ref()
                .is_none_or(|account| {
                    matches!(
                        event,
                        AssetEvent::Transferred(transfer)
                            if transfer.destination().account() == account
                    )
                })
            && self.event_set.matches(event)
    }
}
impl AssetDefinitionEventFilter {
    /// Creates a new [`AssetDefinitionEventFilter`] accepting all [`AssetDefinitionEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: AssetDefinitionEventSet::all(),
        }
    }
    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_asset_definition(mut self, id_matcher: AssetDefinitionId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AssetDefinitionEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for AssetDefinitionEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetDefinitionEventFilter {
    type Event = super::AssetDefinitionEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl NftEventFilter {
    /// Creates a new [`NftEventFilter`] accepting all [`NftEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: NftEventSet::all(),
        }
    }
    /// Modifies a [`NftEventFilter`] to accept only [`NftEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_nft(mut self, id_matcher: NftId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`NftEventFilter`] to accept only [`NftEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: NftEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for NftEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl EventFilter for NftEventFilter {
    type Event = NftEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl RwaEventFilter {
    /// Creates a new [`RwaEventFilter`] accepting all [`RwaEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: RwaEventSet::all(),
        }
    }
    /// Modifies a [`RwaEventFilter`] to accept only events originating from `id_matcher`.
    #[must_use]
    pub fn for_rwa(mut self, id_matcher: RwaId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`RwaEventFilter`] to accept only [`RwaEvent`]s in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: RwaEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for RwaEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl EventFilter for RwaEventFilter {
    type Event = RwaEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl TriggerEventFilter {
    /// Creates a new [`TriggerEventFilter`] accepting all [`TriggerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: TriggerEventSet::all(),
        }
    }
    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_trigger(mut self, id_matcher: TriggerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: TriggerEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for TriggerEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for TriggerEventFilter {
    type Event = super::TriggerEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl RoleEventFilter {
    /// Creates a new [`RoleEventFilter`] accepting all [`RoleEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: RoleEventSet::all(),
        }
    }
    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_role(mut self, id_matcher: RoleId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }
    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: RoleEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for RoleEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for RoleEventFilter {
    type Event = super::RoleEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.id_matcher
            .as_ref()
            .is_none_or(|id| id == event.origin())
            && self.event_set.matches(event)
    }
}
impl ConfigurationEventFilter {
    /// Creates a new [`ConfigurationEventFilter`] accepting all [`ConfigurationEvent`]s.
    pub const fn new() -> Self {
        Self {
            event_set: ConfigurationEventSet::all(),
        }
    }
    /// Modifies a [`ConfigurationEventFilter`] to accept only [`ConfigurationEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: ConfigurationEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for ConfigurationEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for ConfigurationEventFilter {
    type Event = super::ConfigurationEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.event_set.matches(event)
    }
}
impl ExecutorEventFilter {
    /// Creates a new [`ExecutorEventFilter`] accepting all [`ExecutorEvent`]s.
    pub const fn new() -> Self {
        Self {
            event_set: ExecutorEventSet::all(),
        }
    }
    /// Modifies a [`ExecutorEventFilter`] to accept only [`ExecutorEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: ExecutorEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}
impl Default for ExecutorEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for ExecutorEventFilter {
    type Event = super::ExecutorEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.event_set.matches(event)
    }
}
#[cfg(feature = "transparent_api")]
impl super::EventFilter for BridgeEventFilter {
    type Event = crate::events::data::events::bridge::BridgeEvent;
    fn matches(&self, event: &Self::Event) -> bool {
        self.matches_event(event)
    }
}
#[cfg(feature = "governance")]
impl GovernanceEventFilter {
    /// Creates a new [`GovernanceEventFilter`] accepting all governance events.
    pub fn new() -> Self {
        Self {
            proposal_id: None,
            referendum_id: None,
            event_set: super::governance::GovernanceEventSet::all(),
        }
    }
    /// Match only the provided event set.
    #[must_use]
    pub fn for_events(mut self, set: super::governance::GovernanceEventSet) -> Self {
        self.event_set = set;
        self
    }
    /// Restrict the filter to proposal-family events carrying `id`.
    ///
    /// Events without a proposal id, including referendum-family events, do not match.
    #[must_use]
    pub fn for_proposal(mut self, id: [u8; 32]) -> Self {
        self.proposal_id = Some(id);
        self
    }
    /// Restrict the filter to referendum-family events carrying `rid`.
    ///
    /// Events without a referendum id, including proposal-family events, do not match.
    #[must_use]
    pub fn for_referendum(mut self, rid: String) -> Self {
        self.referendum_id = Some(rid);
        self
    }
}
#[cfg(feature = "governance")]
impl Default for GovernanceEventFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl DataEventFilter {
    /// Replace every exact account selector that refers to `old` with `new`.
    ///
    /// Account controller changes replace the canonical [`AccountId`] while
    /// preserving the logical account. Trigger filters are durable state, so
    /// leaving an old selector behind would silently disable the trigger after
    /// a legitimate controller migration.
    pub fn replace_account_id(&mut self, old: &AccountId, new: &AccountId) -> bool {
        if old == new {
            return false;
        }
        let mut updated = false;
        let replace_selector = |selector: &mut Option<AccountId>| {
            if selector.as_ref() == Some(old) {
                *selector = Some(new.clone());
                true
            } else {
                false
            }
        };
        match self {
            Self::Account(filter) => {
                updated |= replace_selector(&mut filter.id_matcher);
            }
            Self::Asset(filter) => {
                if let Some(asset_id) = filter.id_matcher.as_ref()
                    && asset_id.account() == old
                {
                    filter.id_matcher = Some(crate::asset::AssetId::with_scope(
                        asset_id.definition().clone(),
                        new.clone(),
                        *asset_id.scope(),
                    ));
                    updated = true;
                }
                updated |= replace_selector(&mut filter.transfer_source_account_matcher);
                updated |= replace_selector(&mut filter.transfer_destination_account_matcher);
            }
            Self::Escrow(filter) => {
                updated |= replace_selector(&mut filter.seller_matcher);
                updated |= replace_selector(&mut filter.buyer_matcher);
            }
            Self::GameSession(_)
            | Self::KagemushaLoadCommitted(_)
            | Self::Sccp(_)
            | Self::Any
            | Self::Peer(_)
            | Self::Domain(_)
            | Self::AssetDefinition(_)
            | Self::Nft(_)
            | Self::Rwa(_)
            | Self::Trigger(_)
            | Self::Role(_)
            | Self::Configuration(_)
            | Self::Executor(_)
            | Self::Proof(_)
            | Self::VerifyingKey(_)
            | Self::RuntimeUpgrade(_)
            | Self::Soradns(_)
            | Self::Sorafs(_)
            | Self::Musubi(_)
            | Self::SpaceDirectory(_)
            | Self::Oracle(_)
            | Self::Social(_)
            | Self::Bridge(_) => {}
            #[cfg(feature = "governance")]
            Self::Governance(_) => {}
        }
        updated
    }
}
#[cfg(feature = "transparent_api")]
impl EventFilter for DataEventFilter {
    type Event = DataEvent;
    fn matches(&self, event: &DataEvent) -> bool {
        match (self, event) {
            (DataEventFilter::Any, _) => true,
            (DataEventFilter::Peer(filter), DataEvent::Peer(peer_event)) => {
                filter.matches(peer_event)
            }
            (DataEventFilter::Domain(filter), DataEvent::Domain(domain_event)) => {
                filter.matches(domain_event)
            }
            (
                DataEventFilter::Account(filter),
                DataEvent::Domain(DomainEvent::Account(account_event)),
            ) => filter.matches(&account_event.event),
            (DataEventFilter::Account(filter), DataEvent::Account(account_event)) => {
                filter.matches(account_event)
            }
            (
                DataEventFilter::Asset(filter),
                DataEvent::Domain(DomainEvent::Asset(asset_event)),
            ) => filter.matches(&asset_event.event),
            (DataEventFilter::Asset(filter), DataEvent::Asset(asset_event)) => {
                filter.matches(asset_event)
            }
            (
                DataEventFilter::AssetDefinition(filter),
                DataEvent::Domain(DomainEvent::AssetDefinition(asset_definition_event)),
            ) => filter.matches(&asset_definition_event.event),
            (
                DataEventFilter::AssetDefinition(filter),
                DataEvent::AssetDefinition(asset_definition_event),
            ) => filter.matches(asset_definition_event),
            (DataEventFilter::Nft(filter), DataEvent::Domain(DomainEvent::Nft(nft_event))) => {
                filter.matches(nft_event)
            }
            (DataEventFilter::Rwa(filter), DataEvent::Domain(DomainEvent::Rwa(rwa_event))) => {
                filter.matches(rwa_event)
            }
            (DataEventFilter::Trigger(filter), DataEvent::Trigger(trigger_event)) => {
                filter.matches(trigger_event)
            }
            (DataEventFilter::Role(filter), DataEvent::Role(role_event)) => {
                filter.matches(role_event)
            }
            (
                DataEventFilter::Configuration(filter),
                DataEvent::Configuration(configuration_event),
            ) => filter.matches(configuration_event),
            (DataEventFilter::Executor(filter), DataEvent::Executor(executor_event)) => {
                filter.matches(executor_event)
            }
            (DataEventFilter::Proof(filter), DataEvent::Proof(proof_event)) => {
                filter.matches(proof_event)
            }
            (
                DataEventFilter::VerifyingKey(filter),
                DataEvent::VerifyingKey(verifying_key_event),
            ) => filter.matches(verifying_key_event),
            (
                DataEventFilter::RuntimeUpgrade(filter),
                DataEvent::RuntimeUpgrade(runtime_upgrade_event),
            ) => filter.matches(runtime_upgrade_event),
            (DataEventFilter::Soradns(filter), DataEvent::Soradns(soradns_event)) => {
                filter.matches(soradns_event)
            }
            (DataEventFilter::Sorafs(filter), DataEvent::Sorafs(sorafs_event)) => {
                filter.matches(sorafs_event)
            }
            (DataEventFilter::Musubi(filter), DataEvent::Musubi(musubi_event)) => {
                filter.matches(musubi_event)
            }
            (DataEventFilter::SpaceDirectory(filter), DataEvent::SpaceDirectory(space_event)) => {
                filter.matches(space_event)
            }
            (DataEventFilter::GameSession(id), DataEvent::GameSession(event)) => {
                id.as_ref().is_none_or(|id| id == &event.session_id)
            }
            (DataEventFilter::Sccp(filter), DataEvent::Sccp(sccp_event)) => {
                filter.matches(sccp_event)
            }
            (
                DataEventFilter::KagemushaLoadCommitted(digest),
                DataEvent::KagemushaLoadCommitted(event),
            ) => digest
                .as_ref()
                .is_none_or(|digest| digest == &event.receipt_digest),
            (DataEventFilter::Escrow(filter), DataEvent::Escrow(escrow_event)) => {
                filter.matches(escrow_event)
            }
            (DataEventFilter::Oracle(filter), DataEvent::Oracle(oracle_event)) => {
                filter.matches(oracle_event)
            }
            (DataEventFilter::Social(filter), DataEvent::Social(social_event)) => {
                filter.matches(social_event)
            }
            (DataEventFilter::Bridge(filter), DataEvent::Bridge(bridge_event)) => {
                filter.matches_event(bridge_event)
            }
            #[cfg(feature = "governance")]
            (DataEventFilter::Governance(filter), DataEvent::Governance(governance_event)) => {
                governance_matches(filter, governance_event)
            }
            _ => false,
        }
    }
}
#[cfg(all(feature = "transparent_api", feature = "governance"))]
fn governance_matches(
    filter: &GovernanceEventFilter,
    event: &super::governance::GovernanceEvent,
) -> bool {
    use super::governance::GovernanceEvent;
    if !filter.event_set.matches(event) {
        return false;
    }
    let proposal_matches = |candidate: &[u8; 32]| {
        filter.referendum_id.is_none()
            && filter.proposal_id.as_ref().is_none_or(|id| candidate == id)
    };
    let referendum_matches = |candidate: &str| {
        filter.proposal_id.is_none()
            && filter
                .referendum_id
                .as_ref()
                .is_none_or(|rid| candidate == rid)
    };
    let unscoped_matches = filter.proposal_id.is_none() && filter.referendum_id.is_none();
    match event {
        GovernanceEvent::ProposalSubmitted(p) => proposal_matches(&p.id),
        GovernanceEvent::ProposalRejected(p) => proposal_matches(&p.id),
        GovernanceEvent::ProposalEnacted(p) => proposal_matches(&p.id),
        GovernanceEvent::LockCreated(lock) => referendum_matches(&lock.referendum_id),
        GovernanceEvent::LockExtended(lock) => referendum_matches(&lock.referendum_id),
        GovernanceEvent::BallotAccepted(ballot) => referendum_matches(&ballot.referendum_id),
        GovernanceEvent::BallotRejected(ballot) => referendum_matches(&ballot.referendum_id),
        GovernanceEvent::ReferendumOpened(referendum) => referendum_matches(&referendum.id),
        GovernanceEvent::ReferendumClosed(referendum) => referendum_matches(&referendum.id),
        GovernanceEvent::LockUnlocked(lock) => referendum_matches(&lock.referendum_id),
        GovernanceEvent::LockSlashed(lock) => referendum_matches(&lock.referendum_id),
        GovernanceEvent::LockRestituted(lock) => referendum_matches(&lock.referendum_id),
        GovernanceEvent::ReferendumDecided(decision) => referendum_matches(&decision.referendum_id),
        GovernanceEvent::CitizenRegistered(_)
        | GovernanceEvent::CitizenRevoked(_)
        | GovernanceEvent::ThresholdKeyLifecycleApplied(_) => unscoped_matches,
        GovernanceEvent::ParliamentAttemptCreated(ev) => {
            proposal_matches(ev.proposal_content_id.as_bytes())
        }
        GovernanceEvent::ParliamentLifecycleTransitionApplied(ev) => {
            proposal_matches(ev.proposal_content_id.as_bytes())
        }
    }
}
pub mod prelude {
    #[cfg(feature = "governance")]
    pub use super::model::GovernanceEventFilter;
    pub use super::model::{
        AccountEventFilter, AssetDefinitionEventFilter, AssetEventFilter, ConfigurationEventFilter,
        DataEventFilter, DomainEventFilter, EscrowEventFilter, ExecutorEventFilter,
        MusubiEventFilter, NftEventFilter, PeerEventFilter, ProofEventFilter, RoleEventFilter,
        RuntimeUpgradeEventFilter, RwaEventFilter, SccpEventFilter, SocialEventFilter,
        SoradnsDirectoryEventFilter, SorafsGatewayEventFilter, SpaceDirectoryEventFilter,
        TriggerEventFilter, VerifyingKeyEventFilter,
    };
    pub use super::{BridgeEventFilter, OracleEventFilter};
}
#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    use super::*;
    use crate::nexus::UniversalAccountId;
    use iroha_crypto::{Hash, KeyPair};
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::Quantity;
    fn checked_random_account_id() -> AccountId {
        AccountId::new(
            KeyPair::try_random()
                .expect("test fixture random key generation should succeed")
                .into_parts()
                .0,
        )
    }

    #[test]
    fn data_event_filter_rekeys_every_exact_account_selector() {
        let old = checked_random_account_id();
        let new = checked_random_account_id();
        let definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("rekey_filter", "universal").expect("valid domain id"),
            "asset".parse().expect("valid asset name"),
        );

        let mut account =
            DataEventFilter::Account(AccountEventFilter::new().for_account(old.clone()));
        assert!(account.replace_account_id(&old, &new));
        let DataEventFilter::Account(account) = account else {
            unreachable!("fixture remains an account filter")
        };
        assert_eq!(account.id_matcher, Some(new.clone()));

        let mut asset = DataEventFilter::Asset(
            AssetEventFilter::new()
                .for_asset(AssetId::new(definition, old.clone()))
                .for_transfer_source_account(old.clone())
                .for_transfer_destination_account(old.clone()),
        );
        assert!(asset.replace_account_id(&old, &new));
        let DataEventFilter::Asset(asset) = asset else {
            unreachable!("fixture remains an asset filter")
        };
        assert_eq!(asset.id_matcher.as_ref().map(AssetId::account), Some(&new));
        assert_eq!(asset.transfer_source_account_matcher, Some(new.clone()));
        assert_eq!(
            asset.transfer_destination_account_matcher,
            Some(new.clone())
        );

        let mut escrow = DataEventFilter::Escrow(
            EscrowEventFilter::new()
                .for_seller(old.clone())
                .for_buyer(old.clone()),
        );
        assert!(escrow.replace_account_id(&old, &new));
        let DataEventFilter::Escrow(escrow) = escrow else {
            unreachable!("fixture remains an escrow filter")
        };
        assert_eq!(escrow.seller_matcher, Some(new.clone()));
        assert_eq!(escrow.buyer_matcher, Some(new));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_scopes_match_only_their_id_bearing_event_family() {
        use crate::events::data::governance::{
            GovernanceCitizenRegistered, GovernanceEvent, GovernanceProposalRejected,
            GovernanceReferendumOpened,
        };

        let proposal_id = [0x11; 32];
        let other_proposal_id = [0x12; 32];
        let referendum_id = "referendum-11".to_owned();
        let other_referendum_id = "referendum-12".to_owned();
        let matching_proposal =
            GovernanceEvent::ProposalRejected(GovernanceProposalRejected { id: proposal_id });
        let other_proposal = GovernanceEvent::ProposalRejected(GovernanceProposalRejected {
            id: other_proposal_id,
        });
        let matching_referendum = GovernanceEvent::ReferendumOpened(GovernanceReferendumOpened {
            id: referendum_id.clone(),
            h_start: 10,
            h_end: 20,
        });
        let other_referendum = GovernanceEvent::ReferendumOpened(GovernanceReferendumOpened {
            id: other_referendum_id,
            h_start: 10,
            h_end: 20,
        });
        let unscoped = GovernanceEvent::CitizenRegistered(GovernanceCitizenRegistered {
            owner: checked_random_account_id(),
            amount: Quantity::from(1_u32),
        });

        let proposal_filter = GovernanceEventFilter::new().for_proposal(proposal_id);
        assert!(governance_matches(&proposal_filter, &matching_proposal));
        assert!(!governance_matches(&proposal_filter, &other_proposal));
        assert!(!governance_matches(&proposal_filter, &matching_referendum));
        assert!(!governance_matches(&proposal_filter, &unscoped));

        let referendum_filter = GovernanceEventFilter::new().for_referendum(referendum_id.clone());
        assert!(governance_matches(&referendum_filter, &matching_referendum));
        assert!(!governance_matches(&referendum_filter, &other_referendum));
        assert!(!governance_matches(&referendum_filter, &matching_proposal));
        assert!(!governance_matches(&referendum_filter, &unscoped));

        let disjoint_filter = GovernanceEventFilter::new()
            .for_proposal(proposal_id)
            .for_referendum(referendum_id);
        assert!(!governance_matches(&disjoint_filter, &matching_proposal));
        assert!(!governance_matches(&disjoint_filter, &matching_referendum));
        assert!(!governance_matches(&disjoint_filter, &unscoped));

        assert!(governance_matches(&GovernanceEventFilter::new(), &unscoped));
    }

    #[test]
    #[cfg(feature = "transparent_api")]
    fn entity_scope() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let account_id = checked_random_account_id();
        let definition_id: crate::asset::AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::new(definition_id, account_id.clone());
        let domain_owner_id = checked_random_account_id();
        let domain = Domain {
            id: domain_id.clone(),
            logo: None,
            metadata: Metadata::default(),
            owned_by: domain_owner_id,
        };
        let account = Account::new(account_id.clone()).into_account();
        let asset = Asset::new(asset_id.clone(), 0_u32);
        // Explicit domain routing is carried by the scoped wrappers, never inferred from ids.
        let domain_created = DomainEvent::Created(domain).into();
        let account_created = DataEvent::account_in_domain(
            AccountEvent::Created(AccountCreated { account }),
            domain_id.clone(),
        );
        let asset_created = DataEvent::asset(AssetEvent::Created(asset), Some(domain_id.clone()));
        // test how the differently nested filters with with the events
        let domain_filter =
            DataEventFilter::Domain(DomainEventFilter::new().for_domain(domain_id.clone()));
        let account_filter =
            DataEventFilter::Account(AccountEventFilter::new().for_account(account_id));
        let asset_filter = DataEventFilter::Asset(AssetEventFilter::new().for_asset(asset_id));
        // domain filter matches all of those, because all of those events happened in the same domain
        assert!(domain_filter.matches(&domain_created));
        assert!(domain_filter.matches(&account_created));
        assert!(domain_filter.matches(&asset_created));
        // account event does not match the domain created event, as it is not an account event
        assert!(!account_filter.matches(&domain_created));
        assert!(account_filter.matches(&account_created));
        assert!(!account_filter.matches(&asset_created));
        // asset event matches only the domain->account->asset event
        assert!(!asset_filter.matches(&domain_created));
        assert!(!asset_filter.matches(&account_created));
        assert!(asset_filter.matches(&asset_created));
    }
    #[test]
    fn asset_filter_matches_by_asset_definition_only() {
        let account_id = checked_random_account_id();
        let matching_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let other_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "tulip".parse().unwrap(),
        );
        let matching_asset = AssetId::new(matching_definition.clone(), account_id.clone());
        let other_asset = AssetId::new(other_definition, account_id);
        let matching_event = AssetEvent::Added(AssetChanged {
            asset: matching_asset,
            amount: 10_u32.into(),
        });
        let other_event = AssetEvent::Added(AssetChanged {
            asset: other_asset,
            amount: 10_u32.into(),
        });
        let filter = AssetEventFilter::new()
            .for_events(AssetEventSet::Added)
            .for_asset_definition(matching_definition);
        assert!(filter.matches(&matching_event));
        assert!(!filter.matches(&other_event));
    }
    #[test]
    fn asset_filter_matches_by_asset_id_only() {
        let account_id = checked_random_account_id();
        let definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let matching_asset = AssetId::new(definition.clone(), account_id.clone());
        let other_asset = AssetId::new(definition, checked_random_account_id());
        let matching_event = AssetEvent::Added(AssetChanged {
            asset: matching_asset.clone(),
            amount: 5_u32.into(),
        });
        let other_event = AssetEvent::Added(AssetChanged {
            asset: other_asset,
            amount: 5_u32.into(),
        });
        let filter = AssetEventFilter::new()
            .for_events(AssetEventSet::Added)
            .for_asset(matching_asset);
        assert!(filter.matches(&matching_event));
        assert!(!filter.matches(&other_event));
    }
    #[test]
    fn asset_filter_matches_with_asset_and_asset_definition_matchers() {
        let account_id = checked_random_account_id();
        let matching_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let other_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "tulip".parse().unwrap(),
        );
        let matching_asset = AssetId::new(matching_definition.clone(), account_id.clone());
        let mismatched_asset = AssetId::new(other_definition, account_id);
        let matching_event = AssetEvent::Added(AssetChanged {
            asset: matching_asset.clone(),
            amount: 3_u32.into(),
        });
        let mismatched_event = AssetEvent::Added(AssetChanged {
            asset: mismatched_asset,
            amount: 3_u32.into(),
        });
        let filter = AssetEventFilter::new()
            .for_events(AssetEventSet::Added)
            .for_asset(matching_asset)
            .for_asset_definition(matching_definition);
        assert!(filter.matches(&matching_event));
        assert!(!filter.matches(&mismatched_event));
    }
    #[test]
    fn asset_filter_behavior_is_unchanged_without_asset_definition_matcher() {
        let account_id = checked_random_account_id();
        let definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(definition.clone(), account_id);
        let added = AssetEvent::Added(AssetChanged {
            asset: asset_id,
            amount: 7_u32.into(),
        });
        let created = AssetEvent::Created(Asset::new(
            AssetId::new(definition, checked_random_account_id()),
            0_u32,
        ));
        let filter = AssetEventFilter::new().for_events(AssetEventSet::Added);
        assert!(filter.matches(&added));
        assert!(!filter.matches(&created));
    }
    #[test]
    fn asset_transfer_filter_matches_both_exact_participants() {
        let source = checked_random_account_id();
        let destination = checked_random_account_id();
        let other = checked_random_account_id();
        let definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let event = AssetEvent::Transferred(AssetTransferred {
            source: AssetId::new(definition.clone(), source.clone()),
            destination: AssetId::new(definition.clone(), destination.clone()),
            amount: 7_u32.into(),
        });
        let matching = AssetEventFilter::new()
            .for_events(AssetEventSet::Transferred)
            .for_asset_definition(definition)
            .for_transfer_source_account(source)
            .for_transfer_destination_account(destination);
        assert!(matching.matches(&event));
        assert!(
            !AssetEventFilter::new()
                .for_events(AssetEventSet::Transferred)
                .for_transfer_destination_account(other)
                .matches(&event)
        );
        assert!(
            !AssetEventFilter::new()
                .for_transfer_source_account(event.origin().account().clone())
                .matches(&AssetEvent::Added(AssetChanged {
                    asset: event.origin().clone(),
                    amount: 7_u32.into(),
                }))
        );
    }
    #[test]
    fn escrow_filter_matches_by_scope_status_and_event_kind() {
        let seller = checked_random_account_id();
        let buyer = checked_random_account_id();
        let asset_definition = crate::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
        let escrow_id = crate::escrow::EscrowId::new(Hash::new("escrow-filter"));
        let record = crate::escrow::AssetEscrowRecord {
            id: escrow_id,
            seller: seller.clone(),
            buyer: Some(buyer.clone()),
            asset_definition,
            amount: Quantity::from(7_u32),
            custody: checked_random_account_id(),
            status: crate::escrow::AssetEscrowStatus::PaymentSent,
            kind: crate::escrow::AssetEscrowKind::Marketplace,
            remaining_amount: Quantity::from(7_u32),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: vec![Hash::new("paid")],
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: Some(2),
            payment_sent_at_ms: Some(3),
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        let event = DataEvent::Escrow(crate::events::data::escrow::EscrowEvent::PaymentSent(
            record,
        ));
        let filter = DataEventFilter::Escrow(
            EscrowEventFilter::new()
                .for_escrow(escrow_id)
                .for_seller(seller)
                .for_buyer(buyer)
                .for_status(crate::escrow::AssetEscrowStatus::PaymentSent)
                .for_events(crate::events::data::escrow::EscrowEventSet::PaymentSent),
        );
        assert!(filter.matches(&event));
        let wrong_kind = DataEventFilter::Escrow(
            EscrowEventFilter::new()
                .for_events(crate::events::data::escrow::EscrowEventSet::Released),
        );
        assert!(!wrong_kind.matches(&event));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn verifying_key_filter_matches_by_id() {
        use crate::{
            confidential::ConfidentialStatus,
            events::data::verifying_keys::{VerifyingKeyEvent, VerifyingKeyRegistered},
            proof::VerifyingKeyRecord,
            zk::BackendTag,
        };
        let id = crate::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_test");
        let mut rec = VerifyingKeyRecord::new(
            1,
            "vk_transfer",
            BackendTag::NativePipaRPasta,
            "pallas",
            [0u8; 32],
            [0u8; 32],
        );
        rec.status = ConfidentialStatus::Active;
        let ev = DataEvent::VerifyingKey(VerifyingKeyEvent::Registered(VerifyingKeyRegistered {
            id: id.clone(),
            record: rec,
        }));
        let ok_filter = DataEventFilter::VerifyingKey(
            VerifyingKeyEventFilter::new().for_verifying_key(id.clone()),
        );
        assert!(ok_filter.matches(&ev));
        let other_id = crate::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_other");
        let bad_filter = DataEventFilter::VerifyingKey(
            VerifyingKeyEventFilter::new().for_verifying_key(other_id),
        );
        assert!(!bad_filter.matches(&ev));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn proof_event_filter_matches_by_id_and_preset() {
        use crate::events::data::proof::{ProofEvent, ProofEventSet, ProofRejected, ProofVerified};
        // Build a fixed proof id
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        let pid = crate::proof::ProofId {
            backend: "pipa-r/pasta".into(),
            proof_hash: h,
        };
        // Event: Verified with this id
        let ev_verified = DataEvent::Proof(ProofEvent::Verified(ProofVerified {
            id: pid.clone(),
            vk_ref: None,
            vk_commitment: None,
            call_hash: None,
            envelope_hash: None,
        }));
        // Event: Rejected with this id
        let ev_rejected = DataEvent::Proof(ProofEvent::Rejected(ProofRejected {
            id: pid.clone(),
            vk_ref: None,
            vk_commitment: None,
            call_hash: None,
            envelope_hash: None,
        }));
        // Filter by id, only verified
        let f_only_verified = DataEventFilter::Proof(
            ProofEventFilter::new()
                .for_proof(pid.clone())
                .for_events(ProofEventSet::only_verified()),
        );
        assert!(f_only_verified.matches(&ev_verified));
        assert!(!f_only_verified.matches(&ev_rejected));
        // Filter by id, only rejected
        let f_only_rejected = DataEventFilter::Proof(
            ProofEventFilter::new()
                .for_proof(pid.clone())
                .for_events(ProofEventSet::only_rejected()),
        );
        assert!(f_only_rejected.matches(&ev_rejected));
        assert!(!f_only_rejected.matches(&ev_verified));
        // Filter with different id should not match
        let mut h2 = [0u8; 32];
        h2[0] = 0xCD;
        let other = crate::proof::ProofId {
            backend: "pipa-r/pasta".into(),
            proof_hash: h2,
        };
        let f_other = DataEventFilter::Proof(
            ProofEventFilter::new()
                .for_proof(other)
                .for_events(ProofEventSet::only_verified()),
        );
        assert!(!f_other.matches(&ev_verified));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn nft_filter_matches_nested_events() {
        let domain_id: DomainId = DomainId::try_new("genesis", "universal").unwrap();
        let domain_label = domain_id.to_string();
        let nft_id: NftId = format!("dragon${domain_label}").parse().unwrap();
        let other_nft_id: NftId = format!("phoenix${domain_label}").parse().unwrap();
        let nft_event = DataEvent::Domain(DomainEvent::Nft(NftEvent::Deleted(nft_id.clone())));
        let matching_filter = DataEventFilter::Nft(NftEventFilter::new().for_nft(nft_id.clone()));
        assert!(matching_filter.matches(&nft_event));
        let mismatching_filter =
            DataEventFilter::Nft(NftEventFilter::new().for_nft(other_nft_id.clone()));
        assert!(!mismatching_filter.matches(&nft_event));
        // Domain-level filter should still match the nested NFT event.
        let domain_filter =
            DataEventFilter::Domain(DomainEventFilter::new().for_domain(domain_id.clone()));
        assert!(domain_filter.matches(&nft_event));
    }
    #[test]
    fn asset_definition_filter_matches_standalone_opaque_event() {
        let domain_id: DomainId = DomainId::try_new("reward", "universal").unwrap();
        let scoped_definition = AssetDefinitionId::derive_from_components(
            domain_id,
            "fee".parse().expect("asset name"),
        );
        let opaque_definition: AssetDefinitionId = scoped_definition
            .to_string()
            .parse()
            .expect("opaque canonical id");
        let event = DataEvent::from(AssetDefinitionEvent::Deleted(opaque_definition.clone()));
        let filter = DataEventFilter::AssetDefinition(
            AssetDefinitionEventFilter::new().for_asset_definition(opaque_definition),
        );
        assert!(filter.matches(&event));
        assert!(matches!(event, DataEvent::AssetDefinition(_)));
    }
    #[test]
    fn asset_filter_matches_standalone_opaque_event() {
        let domain_id: DomainId = DomainId::try_new("reward", "universal").unwrap();
        let scoped_definition = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "fee".parse().expect("asset name"),
        );
        let opaque_definition: AssetDefinitionId = scoped_definition
            .to_string()
            .parse()
            .expect("opaque canonical id");
        let public_key: crate::PublicKey =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
                .parse()
                .expect("public key");
        let account_id = AccountId::new(public_key);
        let asset_id = AssetId::of(opaque_definition.clone(), account_id);
        let event = DataEvent::from(AssetEvent::Added(AssetChanged {
            asset: asset_id.clone(),
            amount: 1_u32.into(),
        }));
        let asset_filter =
            DataEventFilter::Asset(AssetEventFilter::new().for_asset(asset_id.clone()));
        assert!(asset_filter.matches(&event));
        assert!(matches!(&event, DataEvent::Asset(_)));
        let domain_filter =
            DataEventFilter::Domain(DomainEventFilter::new().for_domain(domain_id.clone()));
        assert!(!domain_filter.matches(&event));
        assert!(event.domain().is_none());
        let scoped_event = DataEvent::asset(
            AssetEvent::Added(AssetChanged {
                asset: asset_id,
                amount: 1_u32.into(),
            }),
            Some(domain_id.clone()),
        );
        let domain_filter = DataEventFilter::Domain(DomainEventFilter::new().for_domain(domain_id));
        assert!(domain_filter.matches(&scoped_event));
        assert!(asset_filter.matches(&scoped_event));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn runtime_upgrade_filter_matches_by_id() {
        use crate::events::data::runtime_upgrade::{RuntimeUpgradeEvent, RuntimeUpgradeProposed};
        let upgrade_id = crate::runtime::RuntimeUpgradeId([0xAB; 32]);
        let event =
            DataEvent::RuntimeUpgrade(RuntimeUpgradeEvent::Proposed(RuntimeUpgradeProposed {
                id: upgrade_id,
                abi_version: 1,
                start_height: 10,
                end_height: 20,
            }));
        let matching_filter = DataEventFilter::RuntimeUpgrade(
            RuntimeUpgradeEventFilter::new().for_runtime(upgrade_id),
        );
        assert!(matching_filter.matches(&event));
        let other_filter = DataEventFilter::RuntimeUpgrade(
            RuntimeUpgradeEventFilter::new()
                .for_runtime(crate::runtime::RuntimeUpgradeId([0xAC; 32])),
        );
        assert!(!other_filter.matches(&event));
        let event_set_filter = DataEventFilter::RuntimeUpgrade(
            RuntimeUpgradeEventFilter::new()
                .for_events(crate::events::data::runtime_upgrade::RuntimeUpgradeEventSet::all()),
        );
        assert!(event_set_filter.matches(&event));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn space_directory_filter_matches_scope() {
        use crate::events::data::space_directory::{
            SpaceDirectoryEvent, SpaceDirectoryManifestActivated,
        };
        let dataspace = DataSpaceId::new(42);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid:test"));
        let manifest_hash = Hash::new(b"manifest:test");
        let event = DataEvent::SpaceDirectory(SpaceDirectoryEvent::ManifestActivated(
            SpaceDirectoryManifestActivated {
                dataspace,
                uaid,
                manifest_hash,
                activation_epoch: 10,
                expiry_epoch: Some(20),
            },
        ));
        let matching = DataEventFilter::SpaceDirectory(
            SpaceDirectoryEventFilter::new().for_dataspace(dataspace),
        );
        assert!(matching.matches(&event));
        let mismatching = DataEventFilter::SpaceDirectory(
            SpaceDirectoryEventFilter::new().for_dataspace(DataSpaceId::new(7)),
        );
        assert!(!mismatching.matches(&event));
    }
    #[test]
    #[cfg(feature = "transparent_api")]
    fn oracle_filter_matches_feed_id() {
        use crate::{
            events::data::oracle::OracleEvent,
            oracle::{FeedConfigVersion, FeedEvent, FeedEventOutcome},
        };
        let feed_id: crate::oracle::FeedId = "price_xor_usd".parse().unwrap();
        let event = DataEvent::Oracle(OracleEvent::FeedProcessed(
            crate::events::data::oracle::FeedEventRecord {
                event: FeedEvent {
                    feed_id: feed_id.clone(),
                    feed_config_version: FeedConfigVersion(1),
                    slot: 10,
                    request_hash: Hash::new(b"oracle-filter-request"),
                    outcome: FeedEventOutcome::Missing,
                },
                recorded_at_ms: 1,
                evidence_hashes: Vec::new(),
            },
        ));
        let matching = DataEventFilter::Oracle(OracleEventFilter::new().for_feed(feed_id.clone()));
        assert!(matching.matches(&event));
        let mismatching = DataEventFilter::Oracle(
            OracleEventFilter::new().for_feed("other_feed".parse().unwrap()),
        );
        assert!(!mismatching.matches(&event));
    }
    #[test]
    fn musubi_filter_matches_structural_package_and_archive() {
        use crate::{
            events::data::musubi::{MusubiEvent, MusubiReleasePublishedEventV1},
            musubi::{
                ArchiveId, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseDigestV1,
                MusubiReleaseIdV1,
            },
        };
        use iroha_model_base::topology::DataSpaceId;
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "codec".parse().expect("package name"),
        );
        let archive = ArchiveId::new([0x22; 32]);
        let event = DataEvent::Musubi(MusubiEvent::ReleasePublished(
            MusubiReleasePublishedEventV1 {
                release: MusubiReleaseIdV1::new(package.clone(), "1.2.3".parse().expect("version")),
                release_digest: MusubiReleaseDigestV1::new([0x11; 32]),
                archive_id: archive,
                published_by: checked_random_account_id(),
                finalized_height: 9,
            },
        ));
        let matching = DataEventFilter::Musubi(
            MusubiEventFilter::new()
                .for_package(package.clone())
                .for_archive(archive),
        );
        assert!(matching.matches(&event));
        let other_package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "other".parse().expect("package name"),
        );
        assert!(
            !DataEventFilter::Musubi(MusubiEventFilter::new().for_package(other_package))
                .matches(&event)
        );
        assert!(
            !DataEventFilter::Musubi(
                MusubiEventFilter::new().for_archive(ArchiveId::new([0x33; 32]))
            )
            .matches(&event)
        );
    }
}
mod bridge_filters_model {
    use crate::events::data::events::HasOrigin;
    use iroha_data_model_derive::model;
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};
    #[model]
    mod model {
        use super::*;
        /// An event filter for `BridgeEvent`
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            getset::Getters,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
            norito::NoritoSchema,
        )]
        #[norito_schema(
            name = "iroha_data_model::events::data::filters::bridge_filters_model::model::BridgeEventFilter"
        )]
        pub struct BridgeEventFilter {
            pub(super) id_matcher: Option<iroha_model_base::topology::LaneId>,
            pub(super) event_set: crate::events::data::events::bridge::BridgeEventSet,
        }
    }
    pub use model::BridgeEventFilter;
    impl BridgeEventFilter {
        /// Creates a new [`BridgeEventFilter`] accepting all bridge events.
        pub fn new() -> Self {
            Self {
                id_matcher: None,
                event_set: crate::events::data::events::bridge::BridgeEventSet::all(),
            }
        }
        /// Restrict the filter to events originating from the provided lane id.
        #[must_use]
        pub fn for_lane(mut self, lane: iroha_model_base::topology::LaneId) -> Self {
            self.id_matcher = Some(lane);
            self
        }
        /// Restrict the filter to specific bridge event kinds.
        #[must_use]
        pub fn for_events(
            mut self,
            event_set: crate::events::data::events::bridge::BridgeEventSet,
        ) -> Self {
            self.event_set = event_set;
            self
        }
        /// Check if a bridge event matches this filter.
        pub fn matches_event(
            &self,
            event: &crate::events::data::events::bridge::BridgeEvent,
        ) -> bool {
            let origin_ok = self
                .id_matcher
                .as_ref()
                .is_none_or(|lane| lane == event.origin());
            origin_ok && self.event_set.matches(event)
        }
    }
    impl Default for BridgeEventFilter {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tag_tests;

#[cfg(test)]
mod captured_event_boundary_identity_tests;

#[cfg(all(test, feature = "transparent_api"))]
mod sccp_filter_tests {
    use super::*;
    use crate::{
        bridge::SccpNetworkV1,
        sccp::events::{SccpBlockCommittedV1, SccpEvent, SccpEventSet, SccpMessageRecordedV1},
    };

    fn recorded(network: SccpNetworkV1) -> SccpEvent {
        SccpEvent::MessageRecorded(SccpMessageRecordedV1 {
            message_id: [1; 32],
            network,
            revision: 1,
            nonce: 0,
            height: 9,
            commitment_index: 0,
            deadline_ms: 1,
        })
    }

    fn committed() -> SccpEvent {
        SccpEvent::BlockCommitted(SccpBlockCommittedV1 {
            height: 9,
            root: [2; 32],
            count: 1,
            history_size: 1,
        })
    }

    #[test]
    fn sccp_filter_matches_by_event_set_and_network() {
        let any = SccpEventFilter::default();
        assert!(any.matches(&recorded(SccpNetworkV1::TonMainnet)));
        assert!(any.matches(&committed()));
        let ton = SccpEventFilter::new().for_network(SccpNetworkV1::TonMainnet);
        assert!(ton.matches(&recorded(SccpNetworkV1::TonMainnet)));
        assert!(!ton.matches(&recorded(SccpNetworkV1::EthereumMainnet)));
        assert!(
            !ton.matches(&committed()),
            "events without a network never match a network filter"
        );
        let blocks = SccpEventFilter::new().for_events(SccpEventSet::BlockCommitted);
        assert!(blocks.matches(&committed()));
        assert!(!blocks.matches(&recorded(SccpNetworkV1::TonMainnet)));
    }

    #[test]
    fn native_generation_events_are_global_and_keep_exact_event_filters() {
        use crate::sccp::{committee::SccpGenerationCauseV1, events::*};

        let events = [
            SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
                height: 9,
                reason: SccpFinalityDegradedReasonV1::MissingHeightInputs,
            }),
            SccpEvent::CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1 {
                generation: 2,
                cause: SccpGenerationCauseV1::Heartbeat,
                committee_root: [3; 32],
                start_height: 10,
                deadline_ms: 1_758_604_800_000,
            }),
            SccpEvent::CommitteeResync(SccpCommitteeResyncV1 {
                generation: 3,
                committee_root: [4; 32],
                start_height: 11,
            }),
            SccpEvent::GenerationMemberUnslashable(SccpGenerationMemberUnslashableV1 {
                generation: 3,
                index: 30,
            }),
            SccpEvent::GenerationDestinationCleared(SccpGenerationDestinationClearedV1 {
                generation: 2,
                lc: 1_758_604_800_001,
            }),
        ];
        let selected = SccpEventFilter::new().for_events(SccpEventSet::CommitteeResync);
        for (index, event) in events.into_iter().enumerate() {
            assert!(SccpEventFilter::new().matches(&event));
            assert_eq!(selected.matches(&event), index == 2);
            for network in [
                SccpNetworkV1::EthereumMainnet,
                SccpNetworkV1::BscMainnet,
                SccpNetworkV1::TonMainnet,
            ] {
                assert!(!SccpEventFilter::new().for_network(network).matches(&event));
            }
            assert!(DataEventFilter::Sccp(SccpEventFilter::new()).matches(&DataEvent::Sccp(event)));
        }
    }

    #[test]
    fn data_event_filter_routes_sccp_events_to_the_sccp_filter() {
        let event = DataEvent::Sccp(recorded(SccpNetworkV1::BscMainnet));
        assert!(DataEventFilter::Any.matches(&event));
        assert!(DataEventFilter::Sccp(SccpEventFilter::new()).matches(&event));
        assert!(
            !DataEventFilter::Sccp(SccpEventFilter::new().for_network(SccpNetworkV1::TonMainnet))
                .matches(&event)
        );
        assert!(!DataEventFilter::GameSession(None).matches(&event));
        let mut filter = DataEventFilter::Sccp(SccpEventFilter::new());
        let account = |seed: u8| {
            AccountId::new(
                iroha_crypto::KeyPair::try_from_seed(
                    vec![seed; 32],
                    iroha_crypto::Algorithm::Ed25519,
                )
                .expect("deterministic seed")
                .into_parts()
                .0,
            )
        };
        assert!(
            !filter.replace_account_id(&account(1), &account(2)),
            "SCCP filters carry no account selector"
        );
    }
}
