//! Structures, traits and impls related to versioning.
//!
//! For usage examples see [`iroha_version_derive::declare_versioned`].

#![warn(
    missing_docs,
    private_doc_tests,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(
    clippy::use_self,
    clippy::implicit_return,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::enum_glob_use,
    clippy::wildcard_imports
)]

#[cfg(feature = "derive")]
pub use iroha_version_derive::*;
#[cfg(feature = "scale")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Module which contains error and result for versioning
pub mod error {
    use super::UnsupportedVersion;
    use iroha_derive::FromVariant;
    use iroha_error::derive::Error;
    #[cfg(feature = "http_error")]
    use iroha_http_server::http::{HttpResponseError, StatusCode, HTTP_CODE_BAD_REQUEST};

    /// Versioning errors
    #[derive(Error, Debug, FromVariant)]
    pub enum Error {
        /// This is not a versioned object. No version information found.
        #[error("This is not a versioned object. No version information found.")]
        NotVersioned,
        /// Can not encode unsupported version from json to scale.
        #[error("Can not encode unsupported version from json to scale.")]
        UnsupportedJsonEncode,
        /// Expected json object.
        #[error("Expected json object.")]
        ExpectedJson,
        /// Can not encode unsupported version from scale to json
        #[error("Can not encode unsupported version from scale to json.")]
        UnsupportedScaleEncode,
        /// Problem with serialization/deserialization of json
        #[error("Problem with serialization/deserialization of json.")]
        Serde(#[source] serde_json::Error),
        /// Problem with serialization/deserialization of parity scale.
        #[error("Problem with serialization/deserialization of parity scale.")]
        ParityScale(#[source] parity_scale_codec::Error),
        /// Problem with parsing integers.
        #[error("Problem with parsing integers.")]
        ParseInt(#[source] std::num::ParseIntError),
        /// Version of input is unsupported
        #[error("Version of input is unsupported")]
        UnsupportedVersion(UnsupportedVersion),
    }

    #[cfg(feature = "http_error")]
    impl HttpResponseError for Error {
        fn status_code(&self) -> StatusCode {
            HTTP_CODE_BAD_REQUEST
        }
        fn error_body(&self) -> Vec<u8> {
            self.to_string().into()
        }
    }

    /// Result type for versioning
    pub type Result<T, E = Error> = std::result::Result<T, E>;
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
#[cfg_attr(feature = "scale", derive(Encode, Decode))]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct UnsupportedVersion {
    /// Version of the content.
    pub version: u8,
    /// Raw content.
    pub raw: RawVersioned,
}

impl UnsupportedVersion {
    /// Constructs [`UnsupportedVersion`].
    #[must_use]
    pub const fn new(version: u8, raw: RawVersioned) -> Self {
        Self { version, raw }
    }
}

/// Raw versioned content, serialized.
#[cfg_attr(feature = "scale", derive(Encode, Decode))]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub enum RawVersioned {
    /// In JSON format.
    Json(String),
    /// In Parity Scale Codec format.
    ScaleBytes(Vec<u8>),
}

/// Scale related versioned (de)serialization traits.
#[cfg(feature = "scale")]
pub mod scale {
    use super::error::Result;
    use super::Version;
    use parity_scale_codec::{Decode, Encode};

    /// `Decode` versioned analog.
    pub trait DecodeVersioned: Decode + Version {
        /// Use this function for versioned objects instead of `decode`.
        ///
        /// # Errors
        /// Will return error if version is unsupported or if input won't have enough bytes for decoding.
        fn decode_versioned(input: &[u8]) -> Result<Self>;
    }

    /// `Encode` versioned analog.
    pub trait EncodeVersioned: Encode + Version {
        #[allow(clippy::missing_errors_doc)]
        /// Use this function for versioned objects instead of `encode`.
        fn encode_versioned(&self) -> Result<Vec<u8>>;
    }
}

/// JSON related versioned (de)serialization traits.
#[cfg(feature = "json")]
pub mod json {
    use super::error::Result;
    use super::Version;
    use serde::{Deserialize, Serialize};

    /// `Serialize` versioned analog, specifically for JSON.
    pub trait DeserializeVersioned<'a>: Deserialize<'a> + Version {
        /// Use this function for versioned objects instead of `serde_json::from_str`.
        ///
        /// # Errors
        /// Return error if:
        /// * serde fails to decode json
        /// * if json is not an object
        /// * if json is has no version field
        fn from_versioned_json_str(input: &str) -> Result<Self>;
    }

    /// `Deserialize` versioned analog, specifically for JSON.
    pub trait SerializeVersioned: Serialize + Version {
        /// Use this function for versioned objects instead of `serde_json::to_string`.
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
