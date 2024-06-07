//! This module contains data events
#![allow(missing_docs)]

use getset::Getters;
use iroha_data_model_derive::{model, Filter, HasOrigin};
use iroha_primitives::small::SmallVec;

pub use self::model::*;
use super::*;

macro_rules! data_event {
    ($item:item) => {
        iroha_data_model_derive::model_single! {
            #[derive(
                Debug,
                Clone,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Filter,
                HasOrigin,
                parity_scale_codec::Decode,
                parity_scale_codec::Encode,
                serde::Deserialize,
                serde::Serialize,
                iroha_schema::IntoSchema,
            )]
            #[non_exhaustive]
            #[ffi_type]
            $item
        }
    };
}

#[model]
pub mod model {
    use super::*;

    /// Generic [`MetadataChanged`] struct.
    /// Contains the changed metadata (`(key, value)` pair), either inserted or removed, which is determined by the wrapping event.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    // TODO: Generics are not supported. Figure out what to do
    //#[getset(get = "pub")]
    #[ffi_type]
    pub struct MetadataChanged<Id> {
        pub target_id: Id,
        pub key: Name,
        pub value: Box<Value>,
    }

    /// World event
    ///
    /// Does not participate in `Event`, but useful for events warranties when modifying `wsv`
    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    pub enum WorldEvent {
        Peer(peer::PeerEvent),
        Domain(domain::DomainEvent),
        Role(role::RoleEvent),
        Trigger(trigger::TriggerEvent),
        PermissionTokenSchemaUpdate(permission::PermissionTokenSchemaUpdateEvent),
        Configuration(config::ConfigurationEvent),
        Executor(executor::ExecutorEvent),
    }

    /// Event
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
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub enum DataEvent {
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
        PermissionToken(permission::PermissionTokenSchemaUpdateEvent),
        /// Configuration event
        Configuration(config::ConfigurationEvent),
        /// Executor event
        Executor(executor::ExecutorEvent),
    }
}

mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;

    // type alias required by `Filter` macro
    type AssetMetadataChanged = MetadataChanged<AssetId>;
    type AssetDefinitionMetadataChanged = MetadataChanged<AssetDefinitionId>;

    data_event! {
        #[has_origin(origin = Asset)]
        pub enum AssetEvent {
            #[has_origin(asset => asset.id())]
            Created(Asset),
            Deleted(AssetId),
            #[has_origin(asset_changed => &asset_changed.asset_id)]
            Added(AssetChanged),
            #[has_origin(asset_changed => &asset_changed.asset_id)]
            Removed(AssetChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataInserted(AssetMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataRemoved(AssetMetadataChanged),
        }
    }

    data_event! {
        #[has_origin(origin = AssetDefinition)]
        pub enum AssetDefinitionEvent {
            #[has_origin(asset_definition => asset_definition.id())]
            Created(AssetDefinition),
            MintabilityChanged(AssetDefinitionId),
            #[has_origin(ownership_changed => &ownership_changed.asset_definition_id)]
            OwnerChanged(AssetDefinitionOwnerChanged),
            Deleted(AssetDefinitionId),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataInserted(AssetDefinitionMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataRemoved(AssetDefinitionMetadataChanged),
            #[has_origin(total_quantity_changed => &total_quantity_changed.asset_definition_id)]
            TotalQuantityChanged(AssetDefinitionTotalQuantityChanged),
        }
    }

    #[model]
    pub mod model {
        use super::*;

        /// Depending on the wrapping event, [`Self`] represents the added or removed asset quantity.
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct AssetChanged {
            pub asset_id: AssetId,
            pub amount: AssetValue,
        }

        /// [`Self`] represents updated total asset quantity.
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct AssetDefinitionTotalQuantityChanged {
            pub asset_definition_id: AssetDefinitionId,
            pub total_amount: NumericValue,
        }

        /// [`Self`] represents updated total asset quantity.
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct AssetDefinitionOwnerChanged {
            /// Id of asset definition being updated
            pub asset_definition_id: AssetDefinitionId,
            /// Id of new owning account
            pub new_owner: AccountId,
        }
    }
}

mod peer {
    //! This module contains `PeerEvent` and its impls

    use super::*;

    data_event! {
        #[has_origin(origin = Peer)]
        pub enum PeerEvent {
            Added(PeerId),
            Removed(PeerId),
        }
    }
}

mod role {
    //! This module contains `RoleEvent` and its impls

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;

    data_event! {
        #[has_origin(origin = Role)]
        pub enum RoleEvent {
            #[has_origin(role => role.id())]
            Created(Role),
            Deleted(RoleId),
            /// [`PermissionToken`]s with particular [`Id`](crate::permission::token::PermissionTokenId)
            /// were removed from the role.
            #[has_origin(permission_removed => &permission_removed.role_id)]
            PermissionRemoved(PermissionRemoved),
        }
    }

    #[model]
    pub mod model {
        use super::*;

        /// Information about permissions removed from [`Role`]
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct PermissionRemoved {
            pub role_id: RoleId,
            // TODO: Skipped temporarily because of FFI
            #[getset(skip)]
            pub permission_token_id: PermissionTokenId,
        }
    }
}

mod permission {
    //! This module contains [`PermissionTokenSchemaUpdateEvent`]

    pub use self::model::*;
    use super::*;
    use crate::permission::PermissionTokenSchema;

    #[model]
    pub mod model {
        use super::*;

        /// Information about permission tokens update.
        /// Only happens when registering new executor
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct PermissionTokenSchemaUpdateEvent {
            /// Previous set of permission tokens
            pub old_schema: PermissionTokenSchema,
            /// New set of permission tokens
            pub new_schema: PermissionTokenSchema,
        }
    }
}

mod account {
    //! This module contains `AccountEvent` and its impls

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;
    use crate::name::Name;

    // type alias required by `Filter` macro
    type AccountMetadataChanged = MetadataChanged<AccountId>;

    data_event! {
        #[has_origin(origin = Account)]
        pub enum AccountEvent {
            #[has_origin(asset_event => &asset_event.origin_id().account_id)]
            Asset(AssetEvent),
            #[has_origin(account => account.id())]
            Created(Account),
            Deleted(AccountId),
            AuthenticationAdded(AccountId),
            AuthenticationRemoved(AccountId),
            #[has_origin(permission_changed => &permission_changed.account_id)]
            PermissionAdded(AccountPermissionChanged),
            #[has_origin(permission_changed => &permission_changed.account_id)]
            PermissionRemoved(AccountPermissionChanged),
            #[has_origin(role_changed => &role_changed.account_id)]
            RoleRevoked(AccountRoleChanged),
            #[has_origin(role_changed => &role_changed.account_id)]
            RoleGranted(AccountRoleChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataInserted(AccountMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataRemoved(AccountMetadataChanged),
        }
    }

    #[model]
    pub mod model {
        use super::*;

        /// Depending on the wrapping event, [`AccountPermissionChanged`] role represents the added or removed account role
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct AccountPermissionChanged {
            pub account_id: AccountId,
            // TODO: Skipped temporarily because of FFI
            #[getset(skip)]
            pub permission_id: PermissionTokenId,
        }

        /// Depending on the wrapping event, [`AccountRoleChanged`] represents the granted or revoked role
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct AccountRoleChanged {
            pub account_id: AccountId,
            pub role_id: RoleId,
        }
    }

    impl AccountPermissionChanged {
        /// Get permission id
        pub fn permission_id(&self) -> &Name {
            &self.permission_id
        }
    }
}

mod domain {
    //! This module contains `DomainEvent` and its impls

    pub use self::model::*;
    use super::*;

    // type alias required by `Filter` macro
    type DomainMetadataChanged = MetadataChanged<DomainId>;

    data_event! {
        #[has_origin(origin = Domain)]
        pub enum DomainEvent {
            #[has_origin(account_event => &account_event.origin_id().domain_id)]
            Account(AccountEvent),
            #[has_origin(asset_definition_event => &asset_definition_event.origin_id().domain_id)]
            AssetDefinition(AssetDefinitionEvent),
            #[has_origin(domain => domain.id())]
            Created(Domain),
            Deleted(DomainId),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataInserted(DomainMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataRemoved(DomainMetadataChanged),
            #[has_origin(owner_changed => &owner_changed.domain_id)]
            OwnerChanged(DomainOwnerChanged),
        }
    }

    #[model]
    pub mod model {
        use super::*;

        /// Event indicate that owner of the [`Domain`] is changed
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct DomainOwnerChanged {
            pub domain_id: DomainId,
            pub new_owner: AccountId,
        }
    }
}

mod trigger {
    //! This module contains `TriggerEvent` and its impls

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;

    // type alias required by `Filter` macro
    type TriggerMetadataChanged = MetadataChanged<TriggerId>;

    data_event! {
        #[has_origin(origin = Trigger<TriggeringFilterBox>)]
        pub enum TriggerEvent {
            Created(TriggerId),
            Deleted(TriggerId),
            #[has_origin(number_of_executions_changed => &number_of_executions_changed.trigger_id)]
            Extended(TriggerNumberOfExecutionsChanged),
            #[has_origin(number_of_executions_changed => &number_of_executions_changed.trigger_id)]
            Shortened(TriggerNumberOfExecutionsChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataInserted(TriggerMetadataChanged),
            #[has_origin(metadata_changed => &metadata_changed.target_id)]
            MetadataRemoved(TriggerMetadataChanged),
        }
    }

    #[model]
    pub mod model {
        use super::*;

        /// Depending on the wrapping event, [`Self`] represents the increased or decreased number of event executions.
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
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct TriggerNumberOfExecutionsChanged {
            pub trigger_id: TriggerId,
            pub by: u32,
        }
    }
}

mod config {
    use super::*;

    data_event! {
        #[has_origin(origin = Parameter)]
        pub enum ConfigurationEvent {
            Changed(ParameterId),
            Created(ParameterId),
            Deleted(ParameterId),
        }
    }
}

mod executor {
    use iroha_data_model_derive::model;

    pub use self::model::*;

    #[model]
    pub mod model {
        #[cfg(not(feature = "std"))]
        use alloc::{format, string::String, vec::Vec};

        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            parity_scale_codec::Decode,
            parity_scale_codec::Encode,
            serde::Deserialize,
            serde::Serialize,
            iroha_schema::IntoSchema,
        )]
        #[non_exhaustive]
        #[ffi_type]
        #[serde(untagged)] // Unaffected by #3330, as single unit variant
        #[repr(transparent)]
        pub enum ExecutorEvent {
            Upgraded,
        }

        /// Filter for [`ExecutorEvent`].
        pub enum ExecutorFilter {
            Upgraded,
        }
    }

    #[cfg(feature = "transparent_api")]
    impl super::Filter for ExecutorFilter {
        type Event = ExecutorEvent;

        fn matches(&self, event: &Self::Event) -> bool {
            match (self, event) {
                (Self::Upgraded, Self::Event::Upgraded) => true,
            }
        }
    }
}

/// Trait for events originating from [`HasOrigin::Origin`].
pub trait HasOrigin {
    /// Type of the origin.
    type Origin: Identifiable;
    /// Identification of the origin.
    fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id;
}

impl WorldEvent {
    /// Unfold [`Self`] and return vector of [`Event`]s in the expanding scope order: from specific to general.
    /// E.g [`AssetEvent`] -> [`AccountEvent`] -> [`DomainEvent`]
    pub fn flatten(self) -> SmallVec<[DataEvent; 3]> {
        let mut events = SmallVec::new();

        match self {
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
            WorldEvent::PermissionTokenSchemaUpdate(token_event) => {
                events.push(DataEvent::PermissionToken(token_event));
            }
            WorldEvent::Configuration(config_event) => {
                events.push(DataEvent::Configuration(config_event));
            }
            WorldEvent::Executor(executor_event) => {
                events.push(DataEvent::Executor(executor_event));
            }
        }

        events
    }
}

impl From<AccountEvent> for WorldEvent {
    fn from(value: AccountEvent) -> Self {
        DomainEvent::Account(value).into()
    }
}

impl From<AssetDefinitionEvent> for WorldEvent {
    fn from(value: AssetDefinitionEvent) -> Self {
        DomainEvent::AssetDefinition(value).into()
    }
}

impl From<AssetEvent> for WorldEvent {
    fn from(value: AssetEvent) -> Self {
        AccountEvent::Asset(value).into()
    }
}

impl DataEvent {
    /// Return the domain id of [`Event`]
    pub fn domain_id(&self) -> Option<&DomainId> {
        match self {
            Self::Domain(event) => Some(event.origin_id()),
            Self::Account(event) => Some(&event.origin_id().domain_id),
            Self::AssetDefinition(event) => Some(&event.origin_id().domain_id),
            Self::Asset(event) => Some(&event.origin_id().definition_id.domain_id),
            Self::Trigger(event) => event.origin_id().domain_id.as_ref(),
            Self::Peer(_)
            | Self::Configuration(_)
            | Self::Role(_)
            | Self::PermissionToken(_)
            | Self::Executor(_) => None,
        }
    }
}

impl<Id> MetadataChanged<Id> {
    /// Getter for `target_id`
    pub fn target_id(&self) -> &Id {
        &self.target_id
    }

    /// Getter for `target_id`
    pub fn key(&self) -> &Name {
        &self.key
    }

    /// Getter for `value`
    pub fn value(&self) -> &Value {
        &self.value
    }
}

pub mod prelude {
    pub use super::{
        account::{
            AccountEvent, AccountEventFilter, AccountFilter, AccountPermissionChanged,
            AccountRoleChanged,
        },
        asset::{
            AssetChanged, AssetDefinitionEvent, AssetDefinitionEventFilter, AssetDefinitionFilter,
            AssetDefinitionOwnerChanged, AssetDefinitionTotalQuantityChanged, AssetEvent,
            AssetEventFilter, AssetFilter,
        },
        config::ConfigurationEvent,
        domain::{DomainEvent, DomainEventFilter, DomainFilter, DomainOwnerChanged},
        executor::{ExecutorEvent, ExecutorFilter},
        peer::{PeerEvent, PeerEventFilter, PeerFilter},
        permission::PermissionTokenSchemaUpdateEvent,
        role::{PermissionRemoved, RoleEvent, RoleEventFilter, RoleFilter},
        trigger::{
            TriggerEvent, TriggerEventFilter, TriggerFilter, TriggerNumberOfExecutionsChanged,
        },
        DataEvent, HasOrigin, MetadataChanged, WorldEvent,
    };
}
