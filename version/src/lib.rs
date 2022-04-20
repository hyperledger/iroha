//! Structures, traits and impls related to versioning.
//!
//! For usage examples see [`iroha_version_derive::declare_versioned`].

#![allow(clippy::module_name_repetitions)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// TODO: #1854, CI doesn't catch errors with unused imports in this block.
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::{fmt, ops::Range};

use iroha_schema::IntoSchema;
#[cfg(feature = "derive")]
pub use iroha_version_derive::*;
#[cfg(feature = "scale")]
pub use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Module which contains error and result for versioning
pub mod error {
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};
    use core::fmt;

    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    #[cfg(feature = "scale")]
    use parity_scale_codec::{Decode, Encode};

    use super::UnsupportedVersion;

    /// Versioning errors
    #[derive(Debug, Clone, FromVariant, IntoSchema)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[cfg_attr(feature = "scale", derive(Encode, Decode))]
    pub enum Error {
        /// This is not a versioned object
        NotVersioned,
        /// Cannot encode unsupported version from JSON to Parity SCALE
        UnsupportedJsonEncode,
        /// Expected JSON object
        ExpectedJson,
        /// Cannot encode unsupported version from Parity SCALE to JSON
        UnsupportedScaleEncode,
        /// JSON (de)serialization issue
        #[cfg(feature = "json")]
        Serde,
        /// Parity SCALE (de)serialization issue
        #[cfg(feature = "scale")]
        ParityScale,
        /// Problem with parsing integers
        ParseInt,
        /// Input version unsupported
        UnsupportedVersion(UnsupportedVersion),
    }

    #[cfg(feature = "json")]
    impl From<serde_json::Error> for Error {
        fn from(_: serde_json::Error) -> Self {
            Self::Serde
        }
    }

    #[cfg(feature = "scale")]
    impl From<parity_scale_codec::Error> for Error {
        fn from(_: parity_scale_codec::Error) -> Self {
            Self::ParityScale
        }
    }

    impl From<core::num::ParseIntError> for Error {
        fn from(_: core::num::ParseIntError) -> Self {
            Self::ParseInt
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match self {
                Self::NotVersioned => "Not a versioned object",
                Self::UnsupportedJsonEncode => {
                    "Cannot encode unsupported version from JSON to SCALE"
                }
                Self::ExpectedJson => "Expected JSON object",
                Self::UnsupportedScaleEncode => {
                    "Cannot encode unsupported version from SCALE to JSON"
                }
                #[cfg(feature = "json")]
                Self::Serde => "JSON (de)serialization issue",
                #[cfg(feature = "scale")]
                Self::ParityScale => "Parity SCALE (de)serialization issue",
                Self::ParseInt => "Problem with parsing integers",
                Self::UnsupportedVersion(_) => "Input version unsupported",
            };

            write!(f, "{}", msg)
        }
    }

    #[cfg(feature = "warp")]
    impl Error {
        /// Returns status code for this error
        #[allow(clippy::unused_self)]
        pub const fn status_code(&self) -> warp::http::StatusCode {
            warp::http::StatusCode::BAD_REQUEST
        }
    }
    #[cfg(feature = "warp")]
    impl warp::Reply for Error {
        fn into_response(self) -> warp::reply::Response {
            #[cfg(not(feature = "std"))]
            use alloc::string::ToString as _;

            warp::reply::with_status(self.to_string(), self.status_code()).into_response()
        }
    }
    #[cfg(feature = "warp")]
    impl warp::reject::Reject for Error {}

    /// Result type for versioning
    pub type Result<T, E = Error> = core::result::Result<T, E>;
}

/// General trait describing if this is a versioned container.
pub trait Version {
    /// Version of the data contained inside.
    fn version(&self) -> u8;

    /// Supported versions.
    fn supported_versions() -> Range<u8>;

    /// If the contents' version is currently supported.
    fn is_supported(&self) -> bool {
        Self::supported_versions().contains(&self.version())
    }
}

/// Structure describing a container content which version is not supported.
#[derive(Debug, Clone, IntoSchema)]
#[cfg_attr(feature = "scale", derive(Encode, Decode))]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct UnsupportedVersion {
    /// Version of the content.
    pub version: u8,
    /// Raw content.
    pub raw: RawVersioned,
}

impl fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unsupported version: {}", self.version)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedVersion {}

impl UnsupportedVersion {
    /// Constructs [`UnsupportedVersion`].
    #[must_use]
    #[inline]
    pub const fn new(version: u8, raw: RawVersioned) -> Self {
        Self { version, raw }
    }
}

/// Raw versioned content, serialized.
#[derive(Debug, Clone, IntoSchema)]
#[cfg_attr(feature = "scale", derive(Encode, Decode))]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub enum RawVersioned {
    /// In JSON format.
    Json(String),
    /// In Parity Scale Codec format.
    ScaleBytes(Vec<u8>),
}

/// Scale related versioned (de)serialization traits.
#[cfg(feature = "scale")]
pub mod scale {
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use parity_scale_codec::{Decode, Encode};

    use super::{error::Result, Version};

    /// [`Decode`] versioned analog.
    pub trait DecodeVersioned: Decode + Version {
        /// Use this function for versioned objects instead of `decode`.
        ///
        /// # Errors
        /// Will return error if version is unsupported or if input won't have enough bytes for decoding.
        fn decode_versioned(input: &[u8]) -> Result<Self>;
    }

    /// [`Encode`] versioned analog.
    pub trait EncodeVersioned: Encode + Version {
        /// Use this function for versioned objects instead of `encode`.
        fn encode_versioned(&self) -> Vec<u8>;
    }
}

/// JSON related versioned (de)serialization traits.
#[cfg(feature = "json")]
pub mod json {
    #[cfg(not(feature = "std"))]
    use alloc::string::String;

    use serde::{Deserialize, Serialize};

    use super::{error::Result, Version};

    /// [`Serialize`] versioned analog, specifically for JSON.
    pub trait DeserializeVersioned<'de>: Deserialize<'de> + Version {
        /// Use this function for versioned objects instead of [`serde_json::from_str`].
        ///
        /// # Errors
        /// Return error if:
        /// * serde fails to decode json
        /// * if json is not an object
        /// * if json is has no version field
        fn from_versioned_json_str(input: &str) -> Result<Self>;
    }

    /// [`Deserialize`] versioned analog, specifically for JSON.
    pub trait SerializeVersioned: Serialize + Version {
        /// Use this function for versioned objects instead of [`serde_json::to_string`].
        ///
        /// # Errors
        /// Return error if serde fails to decode json
        fn to_versioned_json_str(&self) -> Result<String>;
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[cfg(feature = "json")]
    pub use super::json::*;
    #[cfg(feature = "scale")]
    pub use super::scale::*;
    pub use super::*;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    use super::*;

    pub struct VersionedContainer(pub u8);

    impl Version for VersionedContainer {
        fn version(&self) -> u8 {
            let VersionedContainer(version) = self;
            *version
        }

        fn supported_versions() -> Range<u8> {
            1..10
        }
    }

    #[test]
    fn supported_version() {
        assert!(!VersionedContainer(0).is_supported());
        assert!(VersionedContainer(1).is_supported());
        assert!(VersionedContainer(5).is_supported());
        assert!(!VersionedContainer(10).is_supported());
        assert!(!VersionedContainer(11).is_supported());
    }
}
