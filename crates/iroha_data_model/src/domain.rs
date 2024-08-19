//! This module contains [`Domain`](`crate::domain::Domain`) structure
//! and related implementations and trait implementations.
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::{Constructor, Display, FromStr};
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    ipfs::IpfsPath, metadata::Metadata, prelude::*, HasMetadata, Identifiable, Name, Registered,
};

#[model]
mod model {
    use getset::Getters;

    use super::*;

    /// Identification of a [`Domain`].
    #[derive(
        Debug,
        Display,
        FromStr,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[display(fmt = "{name}")]
    #[getset(get = "pub")]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct DomainId {
        /// [`Name`] unique to a [`Domain`] e.g. company name
        pub name: Name,
    }

    /// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(clippy::multiple_inherent_impl)]
    #[display(fmt = "[{id}]")]
    #[ffi_type]
    pub struct Domain {
        /// Identification of this [`Domain`].
        pub id: DomainId,
        /// IPFS link to the [`Domain`] logo.
        #[getset(get = "pub")]
        pub logo: Option<IpfsPath>,
        /// [`Metadata`] of this `Domain` as a key-value store.
        pub metadata: Metadata,
        /// The account that owns this domain. Usually the [`Account`] that registered it.
        #[getset(get = "pub")]
        pub owned_by: AccountId,
    }

    /// Builder which can be submitted in a transaction to create a new [`Domain`]
    #[derive(
        Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[serde(rename = "Domain")]
    #[display(fmt = "[{id}]")]
    #[ffi_type]
    pub struct NewDomain {
        /// The identification associated with the domain builder.
        pub id: DomainId,
        /// The (IPFS) link to the logo of this domain.
        pub logo: Option<IpfsPath>,
        /// Metadata associated with the domain builder.
        pub metadata: Metadata,
    }
}

impl HasMetadata for NewDomain {
    #[inline]
    fn metadata(&self) -> &crate::metadata::Metadata {
        &self.metadata
    }
}

impl NewDomain {
    /// Create a [`NewDomain`], reserved for internal use.
    #[must_use]
    fn new(id: DomainId) -> Self {
        Self {
            id,
            logo: None,
            metadata: Metadata::default(),
        }
    }

    /// Add [`logo`](IpfsPath) to the domain replacing previously defined value
    #[must_use]
    pub fn with_logo(mut self, logo: IpfsPath) -> Self {
        self.logo = Some(logo);
        self
    }

    /// Add [`Metadata`] to the domain replacing previously defined value
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

impl HasMetadata for Domain {
    #[inline]
    fn metadata(&self) -> &crate::metadata::Metadata {
        &self.metadata
    }
}

impl Registered for Domain {
    type With = NewDomain;
}

impl Domain {
    /// Construct builder for [`Domain`] identifiable by [`Id`].
    #[inline]
    pub fn new(id: DomainId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id)
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Domain, DomainId};
}
