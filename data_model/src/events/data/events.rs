//! This module contains data events
#![allow(missing_docs)]

use getset::Getters;
use iroha_data_model_derive::{model, EventSet, HasOrigin};
use iroha_primitives::numeric::Numeric;

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
                HasOrigin,
                EventSet,
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

// NOTE: if adding/editing events here, make sure to update the corresponding event filter in [`super::filter`]

#[model]
mod model {
    use super::*;
    use crate::metadata::MetadataValueBox;

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
    pub struct MetadataChanged<ID> {
        pub target_id: ID,
        pub key: Name,
        pub value: MetadataValueBox,
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
        /// Trigger event
        Trigger(trigger::TriggerEvent),
        /// Role event
        Role(role::RoleEvent),
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
    mod model {
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
            pub total_amount: Numeric,
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
            /// [`Permission`]s with particular [`PermissionId`]
            /// were removed from the role.
            #[has_origin(permission_removed => &permission_removed.role_id)]
            PermissionRemoved(RolePermissionChanged),
            /// [`Permission`]s with particular [`PermissionId`]
            /// were removed added to the role.
            #[has_origin(permission_added => &permission_added.role_id)]
            PermissionAdded(RolePermissionChanged),
        }
    }

    #[model]
    mod model {
        use super::*;

        /// Depending on the wrapping event, [`RolePermissionChanged`] role represents the added or removed role's permission
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
        pub struct RolePermissionChanged {
            pub role_id: RoleId,
            // TODO: Skipped temporarily because of FFI
            #[getset(skip)]
            pub permission_id: PermissionId,
        }
    }
}

mod account {
    //! This module contains `AccountEvent` and its impls

    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;

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
    mod model {
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
            pub permission_id: PermissionId,
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
        pub fn permission_id(&self) -> &PermissionId {
            &self.permission_id
        }
    }
}

mod domain {
    //! This module contains `DomainEvent` and its impls

    pub use self::model::*;
    use super::*;

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
    mod model {
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

    type TriggerMetadataChanged = MetadataChanged<TriggerId>;

    data_event! {
        #[has_origin(origin = Trigger)]
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
    // this is used in no_std
    #[allow(unused)]
    use super::*;

    #[model]
    mod model {

        use iroha_data_model_derive::EventSet;

        // this is used in no_std
        #[allow(unused)]
        use super::*;
        use crate::executor::ExecutorDataModel;

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
            EventSet,
        )]
        #[non_exhaustive]
        #[ffi_type(opaque)]
        #[serde(untagged)] // Unaffected by #3330, as single unit variant
        #[repr(transparent)]
        pub enum ExecutorEvent {
            Upgraded(ExecutorUpgrade),
        }

        /// Information about the updated executor data model.
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
            Getters,
        )]
        #[ffi_type]
        #[repr(transparent)]
        #[getset(get = "pub")]
        pub struct ExecutorUpgrade {
            /// Updated data model
            pub new_data_model: ExecutorDataModel,
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

impl From<AccountEvent> for DataEvent {
    fn from(value: AccountEvent) -> Self {
        DomainEvent::Account(value).into()
    }
}

impl From<AssetDefinitionEvent> for DataEvent {
    fn from(value: AssetDefinitionEvent) -> Self {
        DomainEvent::AssetDefinition(value).into()
    }
}

impl From<AssetEvent> for DataEvent {
    fn from(value: AssetEvent) -> Self {
        AccountEvent::Asset(value).into()
    }
}

impl DataEvent {
    /// Return the domain id of [`Event`]
    pub fn domain_id(&self) -> Option<&DomainId> {
        match self {
            Self::Domain(event) => Some(event.origin_id()),
            Self::Trigger(event) => event.origin_id().domain_id.as_ref(),
            Self::Peer(_) | Self::Configuration(_) | Self::Role(_) | Self::Executor(_) => None,
        }
    }
}

pub mod prelude {
    pub use super::{
        account::{AccountEvent, AccountEventSet, AccountPermissionChanged, AccountRoleChanged},
        asset::{
            AssetChanged, AssetDefinitionEvent, AssetDefinitionEventSet,
            AssetDefinitionOwnerChanged, AssetDefinitionTotalQuantityChanged, AssetEvent,
            AssetEventSet,
        },
        config::{ConfigurationEvent, ConfigurationEventSet},
        domain::{DomainEvent, DomainEventSet, DomainOwnerChanged},
        executor::{ExecutorEvent, ExecutorEventSet, ExecutorUpgrade},
        peer::{PeerEvent, PeerEventSet},
        role::{RoleEvent, RoleEventSet, RolePermissionChanged},
        trigger::{TriggerEvent, TriggerEventSet, TriggerNumberOfExecutionsChanged},
        DataEvent, HasOrigin, MetadataChanged,
    };
}
