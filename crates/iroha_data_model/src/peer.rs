//! This module contains [`Peer`] structure and related implementations and traits implementations.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{borrow::Borrow, hash::Hash};

use derive_more::Display;
use iroha_data_model_derive::model;
use iroha_primitives::addr::SocketAddr;

pub use self::model::*;
use crate::{Identifiable, PublicKey, Registered};

#[model]
mod model {
    use getset::Getters;
    use iroha_data_model_derive::IdEqOrdHash;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::*;

    /// Peer's identification.
    ///
    /// Equality is tested by `public_key` field only.
    /// Each peer should have a unique public key.
    #[derive(
        Debug,
        Display,
        Clone,
        Ord,
        PartialOrd,
        Eq,
        PartialEq,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Getters,
    )]
    #[display(fmt = "{public_key}")]
    #[getset(get = "pub")]
    #[serde(transparent)]
    #[repr(transparent)]
    // TODO: Make it transparent in FFI?
    #[ffi_type(opaque)]
    pub struct PeerId {
        /// Public Key of the [`Peer`].
        pub public_key: PublicKey,
    }

    /// Representation of other Iroha Peer instances running in separate processes.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Getters,
    )]
    #[display(fmt = "{id}@@{address}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct Peer {
        /// Address of the [`Peer`]'s entrypoint.
        pub address: SocketAddr,
        #[serde(rename = "public_key")]
        /// Peer Identification.
        pub id: PeerId,
    }
}

impl PeerId {
    /// Construct [`PeerId`] given `public_key`.
    #[inline]
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }
}

impl From<PublicKey> for PeerId {
    fn from(public_key: PublicKey) -> Self {
        Self { public_key }
    }
}

impl Peer {
    /// Construct `Peer` given `id` and `address`.
    #[inline]
    pub fn new(address: SocketAddr, id: impl Into<PeerId>) -> Self {
        Self {
            address,
            id: id.into(),
        }
    }

    /// Get peer public key
    pub fn public_key(&self) -> &PublicKey {
        &self.id.public_key
    }
}

impl Borrow<PeerId> for Peer {
    fn borrow(&self) -> &PeerId {
        &self.id
    }
}

impl Registered for Peer {
    type With = PeerId;
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Peer, PeerId};
}
