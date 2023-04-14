//! This module contains [`Peer`] structure and related implementations and traits implementations.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use derive_more::Display;
use getset::Getters;
use iroha_data_model_derive::IdEqOrdHash;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{model, Identifiable, PublicKey, Registered, Value};

model! {
    /// Peer's identification.
    ///
    /// Equality is tested by `public_key` field only.
    /// Each peer should have a unique public key.
    #[derive(Debug, Display, Clone, Eq, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "{public_key}@@{address}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct PeerId {
        /// Address of the [`Peer`]'s entrypoint.
        pub address: String,
        /// Public Key of the [`Peer`].
        pub public_key: PublicKey,
    }

    /// Representation of other Iroha Peer instances running in separate processes.
    #[derive(Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "@@{}", "id.address")]
    #[serde(transparent)]
    #[repr(transparent)]
    // TODO: Make it transparent in FFI?
    #[ffi_type(opaque)]
    pub struct Peer {
        /// Peer Identification.
        pub id: PeerId,
    }
}

impl PeerId {
    /// Construct `Id` given `public_key` and `address`.
    #[inline]
    pub fn new(address: &str, public_key: &PublicKey) -> Self {
        Self {
            address: String::from(address),
            public_key: public_key.clone(),
        }
    }
}

impl Peer {
    /// Construct `Peer` given `id`.
    #[inline]
    pub const fn new(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        Self { id }
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        // Comparison is done by public key only.
        // It is a system invariant that each peer has a unique public key.
        // Also it helps to handle peer id comparison without domain name resolution.
        self.public_key == other.public_key
    }
}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
    }
}

impl Borrow<PublicKey> for PeerId {
    fn borrow(&self) -> &PublicKey {
        &self.public_key
    }
}

impl Registered for Peer {
    type With = Self;
}

impl FromIterator<PeerId> for Value {
    fn from_iter<T: IntoIterator<Item = PeerId>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Value>>()
            .into()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Peer, PeerId};
}
