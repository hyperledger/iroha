//! This module contains data events

use iroha_data_model_derive::Filter;
use iroha_primitives::small::SmallVec;

use super::*;

/// Generic [`MetadataChanged`] struct.
/// Depending on wrapping event could mean inserted or removed metadata `(key, value)` pair.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[allow(missing_docs)]
pub struct MetadataChanged<ID> {
    pub origin_id: ID,
    pub key: Name,
    pub value: Box<Value>,
}

mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls

    use super::*;

    type AssetMetadataChanged = MetadataChanged<AssetId>;
    type AssetDefinitionMetadataChanged = MetadataChanged<AssetDefinitionId>;

    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetEvent {
        Created(AssetId),
        Deleted(AssetId),
        Added(AssetAdded),
        Removed(AssetRemoved),
        MetadataInserted(AssetMetadataChanged),
        MetadataRemoved(AssetMetadataChanged),
    }

    impl HasOrigin for AssetEvent {
        type Origin = Asset;

        fn origin_id(&self) -> &<Asset as Identifiable>::Id {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Added(AssetAdded { asset_id: id, .. })
                | Self::Removed(AssetRemoved { asset_id: id, .. })
                | Self::MetadataInserted(MetadataChanged { origin_id: id, .. })
                | Self::MetadataRemoved(MetadataChanged { origin_id: id, .. }) => id,
            }
        }
    }

    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetDefinitionEvent {
        Created(AssetDefinitionId),
        MintabilityChanged(AssetDefinitionId),
        Deleted(AssetDefinitionId),
        MetadataInserted(AssetDefinitionMetadataChanged),
        MetadataRemoved(AssetDefinitionMetadataChanged),
    }
    // NOTE: Whenever you add a new event here, please also update the
    // AssetDefinitionEventFilter enum and its `impl Filter for
    // AssetDefinitionEventFilter`.

    impl HasOrigin for AssetDefinitionEvent {
        type Origin = AssetDefinition;

        fn origin_id(&self) -> &<AssetDefinition as Identifiable>::Id {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MintabilityChanged(id)
                | Self::MetadataInserted(MetadataChanged { origin_id: id, .. })
                | Self::MetadataRemoved(MetadataChanged { origin_id: id, .. }) => id,
            }
        }
    }

    /// [`AssetAdded`] event
    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[allow(missing_docs)]
    pub struct AssetAdded {
        pub asset_id: AssetId,
        pub amount: AssetValue,
    }

    /// [`AssetRemoved`] event
    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[allow(missing_docs)]
    pub struct AssetRemoved {
        pub asset_id: AssetId,
        pub amount: AssetValue,
    }
}

mod peer {
    //! This module contains `PeerEvent` and its impls

    use super::*;

    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum PeerEvent {
        Added(PeerId),
        Removed(PeerId),
    }

    impl HasOrigin for PeerEvent {
        type Origin = Peer;

        fn origin_id(&self) -> &<Peer as Identifiable>::Id {
            match self {
                Self::Added(id) | Self::Removed(id) => id,
            }
        }
    }
}

mod role {
    //! This module contains `RoleEvent` and its impls

    use super::*;

    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum RoleEvent {
        Created(RoleId),
        Deleted(RoleId),
        /// [`PermissionToken`]s with particular [`Id`](crate::permission::token::Id) were
        /// removed from the role.
        PermissionRemoved(PermissionRemoved),
    }

    /// Information about permissions removed from [`Role`]
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct PermissionRemoved {
        /// Role id
        pub role_id: RoleId,
        /// [`PermissionTokenDefinition`] id. All [`PermissionToken`]s with this definition id were removed.
        pub permission_definition_id: <PermissionTokenDefinition as Identifiable>::Id,
    }

    impl HasOrigin for RoleEvent {
        type Origin = Role;

        fn origin_id(&self) -> &<Role as Identifiable>::Id {
            match self {
                Self::Created(role_id)
                | Self::Deleted(role_id)
                | Self::PermissionRemoved(PermissionRemoved { role_id, .. }) => role_id,
            }
        }
    }
}

mod permission {
    //! This module contains [`PermissionTokenEvent`], [`PermissionValidatorEvent`] and their impls

    use super::*;
    use crate::permission::validator::{Id as ValidatorId, Validator};

    #[derive(
        Clone,
        Hash,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum PermissionTokenEvent {
        DefinitionCreated(PermissionTokenDefinition),
        DefinitionDeleted(PermissionTokenDefinition),
    }

    impl HasOrigin for PermissionTokenEvent {
        type Origin = PermissionTokenDefinition;

        fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id {
            match self {
                PermissionTokenEvent::DefinitionCreated(definition)
                | PermissionTokenEvent::DefinitionDeleted(definition) => definition.id(),
            }
        }
    }

    #[derive(
        Clone,
        Hash,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum PermissionValidatorEvent {
        Added(ValidatorId),
        Removed(ValidatorId),
    }

    impl HasOrigin for PermissionValidatorEvent {
        type Origin = Validator;

        fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id {
            match self {
                PermissionValidatorEvent::Added(id) | PermissionValidatorEvent::Removed(id) => id,
            }
        }
    }
}

mod account {
    //! This module contains `AccountEvent` and its impls

    use super::*;

    type AccountMetadataChanged = MetadataChanged<AccountId>;

    /// Account event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AccountEvent {
        Asset(AssetEvent),
        Created(AccountId),
        Deleted(AccountId),
        AuthenticationAdded(AccountId),
        AuthenticationRemoved(AccountId),
        PermissionAdded(AccountPermissionAdded),
        PermissionRemoved(AccountPermissionRemoved),
        RoleRevoked(AccountRoleRevoked),
        RoleGranted(AccountRoleGranted),
        MetadataInserted(AccountMetadataChanged),
        MetadataRemoved(AccountMetadataChanged),
    }

    impl HasOrigin for AccountEvent {
        type Origin = Account;

        fn origin_id(&self) -> &<Account as Identifiable>::Id {
            match self {
                Self::Asset(asset) => &asset.origin_id().account_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::AuthenticationAdded(id)
                | Self::AuthenticationRemoved(id)
                | Self::PermissionAdded(AccountPermissionAdded { account_id: id, .. })
                | Self::PermissionRemoved(AccountPermissionRemoved { account_id: id, .. })
                | Self::RoleRevoked(AccountRoleRevoked { account_id: id, .. })
                | Self::RoleGranted(AccountRoleGranted { account_id: id, .. })
                | Self::MetadataInserted(MetadataChanged { origin_id: id, .. })
                | Self::MetadataRemoved(MetadataChanged { origin_id: id, .. }) => id,
            }
        }
    }

    /// [`AccountPermissionAdded`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct AccountPermissionAdded {
        pub account_id: AccountId,
        pub permission_id: PermissionTokenId,
    }

    /// [`AccountPermissionRemoved`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct AccountPermissionRemoved {
        pub account_id: AccountId,
        pub permission_id: PermissionTokenId,
    }

    /// [`AccountRoleGranted`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct AccountRoleGranted {
        pub account_id: AccountId,
        pub role_id: RoleId,
    }

    /// [`AccountRoleRevoked`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct AccountRoleRevoked {
        pub account_id: AccountId,
        pub role_id: RoleId,
    }
}

mod domain {
    //! This module contains `DomainEvent` and its impls

    use super::*;

    type DomainMetadataChanged = MetadataChanged<DomainId>;

    /// Domain Event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    // TODO: fix variant size differences
    #[allow(missing_docs, variant_size_differences)]
    pub enum DomainEvent {
        Account(AccountEvent),
        AssetDefinition(AssetDefinitionEvent),
        Created(DomainId),
        Deleted(DomainId),
        MetadataInserted(DomainMetadataChanged),
        MetadataRemoved(DomainMetadataChanged),
    }

    impl HasOrigin for DomainEvent {
        type Origin = Domain;

        fn origin_id(&self) -> &<Domain as Identifiable>::Id {
            match self {
                Self::Account(account) => &account.origin_id().domain_id,
                Self::AssetDefinition(asset_definition) => &asset_definition.origin_id().domain_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MetadataInserted(MetadataChanged { origin_id: id, .. })
                | Self::MetadataRemoved(MetadataChanged { origin_id: id, .. }) => id,
            }
        }
    }
}

mod trigger {
    //! This module contains `TriggerEvent` and its impls

    use super::*;

    /// Trigger Event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum TriggerEvent {
        Created(TriggerId),
        Deleted(TriggerId),
        Extended(TriggerExtended),
        Shortened(TriggerShortened),
    }

    impl HasOrigin for TriggerEvent {
        type Origin = Trigger<FilterBox>;

        fn origin_id(&self) -> &<Trigger<FilterBox> as Identifiable>::Id {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Extended(TriggerExtended { trigger_id: id, .. })
                | Self::Shortened(TriggerShortened { trigger_id: id, .. }) => id,
            }
        }
    }

    /// [`TriggerShortened`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct TriggerShortened {
        pub trigger_id: TriggerId,
        pub by: u32,
    }

    /// [`TriggerExtended`] event
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Debug,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(missing_docs)]
    pub struct TriggerExtended {
        pub trigger_id: TriggerId,
        pub by: u32,
    }
}

/// Trait for events originating from [`HasOrigin::Origin`].
pub trait HasOrigin {
    /// Type of the origin.
    type Origin: Identifiable;
    /// Identification of the origin.
    fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id;
}

/// World event
///
/// Does not participate in `Event`, but useful for events warranties when modifying `wsv`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
#[allow(missing_docs)]
pub enum WorldEvent {
    Peer(peer::PeerEvent),
    Domain(domain::DomainEvent),
    Role(role::RoleEvent),
    Trigger(trigger::TriggerEvent),
    PermissionToken(permission::PermissionTokenEvent),
    PermissionValidator(permission::PermissionValidatorEvent),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Peer event
    Peer(peer::PeerEvent),
    /// Domain event
    Domain(domain::DomainEvent),
    /// Account event
    Account(account::AccountEvent),
    /// Asset definition event
    AssetDefinition(asset::AssetDefinitionEvent),
    /// Asset event
    Asset(asset::AssetEvent),
    /// Trigger event
    Trigger(trigger::TriggerEvent),
    /// Role event
    Role(role::RoleEvent),
    /// Permission token event
    PermissionToken(permission::PermissionTokenEvent),
    /// Permission validator event
    PermissionValidator(permission::PermissionValidatorEvent),
}

impl Event {
    /// Return the domain id of [`Event`]
    pub fn domain_id(&self) -> Option<&<Domain as Identifiable>::Id> {
        match self {
            Self::Domain(event) => Some(event.origin_id()),
            Self::Account(event) => Some(&event.origin_id().domain_id),
            Self::AssetDefinition(event) => Some(&event.origin_id().domain_id),
            Self::Asset(event) => Some(&event.origin_id().definition_id.domain_id),
            Self::Trigger(event) => event.origin_id().domain_id.as_ref(),
            Self::Peer(_)
            | Self::Role(_)
            | Self::PermissionToken(_)
            | Self::PermissionValidator(_) => None,
        }
    }
}

impl From<WorldEvent> for SmallVec<[Event; 3]> {
    fn from(world_event: WorldEvent) -> Self {
        let mut events = SmallVec::new();

        match world_event {
            WorldEvent::Domain(domain_event) => {
                match &domain_event {
                    DomainEvent::Account(account_event) => {
                        if let AccountEvent::Asset(asset_event) = account_event {
                            events.push(DataEvent::Asset(asset_event.clone()));
                        }
                        events.push(DataEvent::Account(account_event.clone()));
                    }
                    DomainEvent::AssetDefinition(asset_definition_event) => {
                        events.push(DataEvent::AssetDefinition(asset_definition_event.clone()));
                    }
                    _ => (),
                }
                events.push(DataEvent::Domain(domain_event));
            }
            WorldEvent::Peer(peer_event) => {
                events.push(DataEvent::Peer(peer_event));
            }
            WorldEvent::Role(role_event) => {
                events.push(DataEvent::Role(role_event));
            }
            WorldEvent::Trigger(trigger_event) => {
                events.push(DataEvent::Trigger(trigger_event));
            }
            WorldEvent::PermissionToken(token_event) => {
                events.push(DataEvent::PermissionToken(token_event));
            }
            WorldEvent::PermissionValidator(validator_event) => {
                events.push(DataEvent::PermissionValidator(validator_event));
            }
        }

        events
    }
}

pub mod prelude {
    pub use super::{
        account::{
            AccountEvent, AccountEventFilter, AccountFilter, AccountPermissionAdded,
            AccountPermissionRemoved, AccountRoleGranted, AccountRoleRevoked,
        },
        asset::{
            AssetAdded, AssetDefinitionEvent, AssetDefinitionEventFilter, AssetDefinitionFilter,
            AssetEvent, AssetEventFilter, AssetFilter, AssetRemoved,
        },
        domain::{DomainEvent, DomainEventFilter, DomainFilter},
        peer::{PeerEvent, PeerEventFilter, PeerFilter},
        permission::{PermissionTokenEvent, PermissionValidatorEvent},
        role::{PermissionRemoved, RoleEvent, RoleEventFilter, RoleFilter},
        trigger::{
            TriggerEvent, TriggerEventFilter, TriggerExtended, TriggerFilter, TriggerShortened,
        },
        Event as DataEvent, HasOrigin, MetadataChanged, WorldEvent,
    };
}
