//! This module contains [`Peer`] structure and related implementations and traits implementations.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{hash::Hash, str::FromStr};

use derive_more::{Constructor, DebugCustom, Display};
use iroha_crypto::PublicKey;
use iroha_data_model_derive::model;
use iroha_primitives::addr::SocketAddr;

pub use self::model::*;
use crate::{Identifiable, ParseError, Registered};

#[model]
mod model {
    use getset::Getters;
    use iroha_data_model_derive::IdEqOrdHash;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde_with::{DeserializeFromStr, SerializeDisplay};

    use super::*;

    /// Peer's identification.
    ///
    /// Equality is tested by `public_key` field only.
    /// Each peer should have a unique public key.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        Constructor,
        Ord,
        PartialOrd,
        Eq,
        PartialEq,
        Hash,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
        Getters,
    )]
    #[display(fmt = "{public_key}")]
    #[debug(fmt = "{public_key}")]
    #[getset(get = "pub")]
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
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
        Getters,
    )]
    #[display(fmt = "{id}@{address}")]
    #[ffi_type]
    pub struct Peer {
        /// Address of the [`Peer`]'s entrypoint.
        #[getset(get = "pub")]
        pub address: SocketAddr,
        /// Peer Identification.
        pub id: PeerId,
    }
}

impl FromStr for PeerId {
    type Err = iroha_crypto::error::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_str(s).map(Self::new)
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
}

impl FromStr for Peer {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once("@") {
            None => Err(ParseError {
                reason: "Peer should have format `public_key@address`",
            }),
            Some(("", _)) => Err(ParseError {
                reason: "Empty `public_key` part in `public_key@address`",
            }),
            Some((_, "")) => Err(ParseError {
                reason: "Empty `address` part in `public_key@address`",
            }),
            Some((public_key_candidate, address_candidate)) => {
                let public_key: PublicKey = public_key_candidate.parse().map_err(|_| ParseError {
                    reason: r#"Failed to parse `public_key` part in `public_key@address`. `public_key` should have multihash format e.g. "ed0120...""#,
                })?;
                let address = address_candidate.parse().map_err(|_| ParseError {
                    reason: "Failed to parse `address` part in `public_key@address`",
                })?;
                Ok(Self::new(address, public_key))
            }
        }
    }
}

impl Registered for Peer {
    type With = PeerId;
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Peer, PeerId};
}
