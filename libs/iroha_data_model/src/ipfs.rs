//! Module with [`IpfsPath`] and related impls.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::str::FromStr;

use iroha_data_model_derive::model;
use iroha_primitives::conststr::ConstString;
use parity_scale_codec::{Decode, Encode, Input};

pub use self::model::*;
use crate::ParseError;

#[model]
mod model {
    use derive_more::Display;
    use iroha_schema::IntoSchema;
    use serde_with::{DeserializeFromStr, SerializeDisplay};

    use super::*;

    /// Represents path in IPFS. Performs checks to ensure path validity.
    /// Construct using [`FromStr::from_str`] method.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct IpfsPath(pub(super) ConstString);
}

impl IpfsPath {
    /// Superficially checks IPFS `cid` (Content Identifier)
    #[inline]
    const fn check_cid(cid: &str) -> Result<(), ParseError> {
        if cid.len() < 2 {
            return Err(ParseError {
                reason: "IPFS cid is too short",
            });
        }

        Ok(())
    }
}

impl FromStr for IpfsPath {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut subpath = string.split('/');
        let path_segment = subpath
            .next()
            .expect("First value of str::split() always has value");

        if path_segment.is_empty() {
            let root_type = subpath.next().ok_or(ParseError {
                reason: "Expected root type, but nothing found",
            })?;
            let key = subpath.next().ok_or(ParseError {
                reason: "Expected at least one content id",
            })?;

            match root_type {
                "ipfs" | "ipld" => Self::check_cid(key)?,
                "ipns" => (),
                _ => {
                    return Err(ParseError {
                        reason: "Unexpected root type, expected `ipfs`, `ipld` or `ipns`",
                    })
                }
            }
        } else {
            // by default if there is no prefix it's an ipfs or ipld path
            Self::check_cid(path_segment)?;
        }

        for path in subpath {
            Self::check_cid(path)?;
        }

        Ok(IpfsPath(ConstString::from(string)))
    }
}

impl AsRef<str> for IpfsPath {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Decode for IpfsPath {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let name = ConstString::decode(input)?;
        Self::from_str(&name).map_err(|error| error.reason.into())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString as _;

    use parity_scale_codec::DecodeAll as _;

    use super::*;

    const INVALID_IPFS: [&str; 4] = [
        "",
        "/ipld",
        "/ipfs/a",
        "/ipfsssss/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE",
    ];

    #[test]
    fn test_invalid_ipfs_path() {
        assert!(matches!(
            IpfsPath::from_str(INVALID_IPFS[0]),
            Err(err) if err.to_string() == "Expected root type, but nothing found"
        ));
        assert!(matches!(
            IpfsPath::from_str(INVALID_IPFS[1]),
            Err(err) if err.to_string() == "Expected at least one content id"
        ));
        assert!(matches!(
            IpfsPath::from_str(INVALID_IPFS[2]),
            Err(err) if err.to_string() == "IPFS cid is too short"
        ));
        assert!(matches!(
            IpfsPath::from_str(INVALID_IPFS[3]),
            Err(err) if err.to_string() == "Unexpected root type, expected `ipfs`, `ipld` or `ipns`"
        ));
    }

    #[test]
    fn test_valid_ipfs_path() {
        // Valid paths
        IpfsPath::from_str("QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path without root should be valid");
        IpfsPath::from_str("/ipfs/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path with ipfs root should be valid");
        IpfsPath::from_str("/ipld/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path with ipld root should be valid");
        IpfsPath::from_str("/ipns/QmSrPmbaUKA3ZodhzPWZnpFgcPMFWF4QsxXbkWfEptTBJd")
            .expect("Path with ipns root should be valid");
        IpfsPath::from_str("/ipfs/SomeFolder/SomeImage")
            .expect("Path with folders should be valid");
    }

    #[test]
    fn deserialize_ipfs() {
        for invalid_ipfs in INVALID_IPFS {
            let invalid_ipfs = IpfsPath(invalid_ipfs.into());
            let serialized = serde_json::to_string(&invalid_ipfs).expect("Valid");
            let ipfs = serde_json::from_str::<IpfsPath>(serialized.as_str());

            assert!(ipfs.is_err());
        }
    }

    #[test]
    fn decode_ipfs() {
        for invalid_ipfs in INVALID_IPFS {
            let invalid_ipfs = IpfsPath(invalid_ipfs.into());
            let bytes = invalid_ipfs.encode();
            let ipfs = IpfsPath::decode_all(&mut &bytes[..]);

            assert!(ipfs.is_err());
        }
    }
}
