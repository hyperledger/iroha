//! Canonical logical paths used by durable smart-contract and native ledger state.
pub use self::model::*;
use crate::{error::ParseError, name::Name};
use iroha_data_model_derive::model;
use iroha_primitives::conststr::ConstString;
use norito::core::{DecodeFromSlice, Error as NoritoError};
use std::{borrow::Borrow, str::FromStr, string::String};
/// Maximum UTF-8 byte length of a canonical [`StatePath`].
///
/// The limit covers a canonical `StateMap` base (`Name`, at most 255 UTF-8 bytes), one separator,
/// and the lowercase-hex expansion of a canonical key of at most 4 KiB, with framing slack.
pub const MAX_STATE_PATH_BYTES: usize = 16 * 1024;
#[model]
mod model {
    use super::*;
    use derive_more::{Debug, Display};
    use iroha_schema::IntoSchema;
    /// Canonical logical path for durable smart-contract and native ledger state.
    ///
    /// Unlike [`Name`], this nominal type is sized for composite state paths and
    /// must not be used as an ordinary business identifier.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::state_path::model::StatePath")]
    pub struct StatePath(pub(super) ConstString);
}
impl StatePath {
    fn validate_str(candidate: &str) -> Result<(), ParseError> {
        const FORBIDDEN_CHARS: [char; 3] = ['@', '#', '$'];
        if candidate.is_empty() {
            return Err(ParseError::new("Empty `StatePath`"));
        }
        if candidate.len() > MAX_STATE_PATH_BYTES {
            return Err(ParseError::new(
                "`StatePath` exceeds the 16384-byte UTF-8 limit",
            ));
        }
        if candidate.chars().any(char::is_control) {
            return Err(ParseError::new(
                "Unicode control characters are not allowed in `StatePath` constructs",
            ));
        }
        if candidate.chars().any(crate::name::is_bidi_control) {
            return Err(ParseError::new(
                "Unicode bidirectional control characters are not allowed in `StatePath` constructs",
            ));
        }
        if candidate.chars().any(char::is_whitespace) {
            return Err(ParseError::new(
                "White space not allowed in `StatePath` constructs",
            ));
        }
        if candidate.chars().any(|ch| FORBIDDEN_CHARS.contains(&ch)) {
            return Err(ParseError::new(
                "The `@` character is reserved for scoped alias/public-key constructs, \
                 `#` for alias separators, and `$` for NFT identifiers",
            ));
        }
        Ok(())
    }
    /// Validate borrowed path text using the original syntax and exact NFC policy.
    ///
    /// No replacement string or `StatePath` is retained. A funded execution caller
    /// must admit [`Self::canonical_validation_scratch_bytes`] before validation.
    ///
    /// # Errors
    /// Returns the same syntax, profile and noncanonical-spelling errors as parsing.
    pub fn validate_canonical(candidate: &str) -> Result<(), ParseError> {
        Self::validate_str(candidate)?;
        Name::require_exact_nfc(
            candidate,
            "StatePath must already use the exact NFC spelling",
        )
    }

    /// Bound cumulative allocator requests for one borrowed NFC comparison.
    ///
    /// Syntax-invalid and ASCII inputs require no normalization scratch. Other
    /// inputs include both ICU growth and long-run stable-sort storage under the
    /// pinned profile/toolchain audit. Reserve before validation; this calculation
    /// neither validates NFC nor grants allocation capacity.
    #[must_use]
    pub fn canonical_validation_scratch_bytes(candidate: &str) -> usize {
        if Self::validate_str(candidate).is_err() || candidate.is_ascii() {
            return 0;
        }
        crate::name::nfc_scratch::request_bytes(candidate.chars().count())
    }

    fn parse(candidate: &str) -> Result<Self, ParseError> {
        Self::validate_canonical(candidate)?;
        Ok(Self(ConstString::from(candidate)))
    }

    /// Parse canonical JSON text with bounded NFC and final-owner accounting.
    fn parse_for_json_decode(candidate: &str) -> Result<Self, norito::json::Error> {
        Self::validate_str(candidate)
            .map_err(|error| norito::json::Error::Message(error.reason().into()))?;
        Name::ensure_nfc_for_json_decode(candidate)?;
        let value = ConstString::try_from_str_for_decode(candidate)
            .map_err(norito::json::Error::from_decode_resource)?;
        Ok(Self(value))
    }
    fn decode_wire(bytes: &[u8]) -> Result<(Self, usize), NoritoError> {
        let (value, end) = norito::core::borrow_text_payload(bytes, |len| {
            if len > MAX_STATE_PATH_BYTES {
                return Err(NoritoError::Message(
                    "`StatePath` exceeds the 16384-byte UTF-8 limit".into(),
                ));
            }
            Ok(())
        })?;
        let len = value.len();
        norito::core::reserve_decode_allocation(len)?;
        norito::core::reserve_decode_allocation(Self::canonical_validation_scratch_bytes(value))?;
        let path =
            Self::parse(value).map_err(|error| NoritoError::Message(error.reason().into()))?;
        norito::core::note_payload_access(bytes, end);
        Ok((path, end))
    }
}

impl norito::core::NominalText for StatePath {
    const MAX_TEXT_BYTES: usize = MAX_STATE_PATH_BYTES;
}

impl norito::core::SerializePayload for StatePath {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        <&str as norito::core::SerializePayload>::serialize(&self.as_ref(), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_hint(&self.as_ref())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        <&str as norito::core::SerializePayload>::encoded_len_exact(&self.as_ref())
    }
}

impl<'a> norito::core::DeserializePayload<'a> for StatePath {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("StatePath deserialization must succeed for valid archives")
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let payload = norito::core::payload_slice_from_ptr(ptr)?;
        Self::decode_wire(payload).map(|(path, _)| path)
    }
}
impl AsRef<str> for StatePath {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl Borrow<str> for StatePath {
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}
impl FromStr for StatePath {
    type Err = ParseError;
    fn from_str(candidate: &str) -> Result<Self, Self::Err> {
        Self::parse(candidate)
    }
}
impl TryFrom<String> for StatePath {
    type Error = ParseError;
    fn try_from(candidate: String) -> Result<Self, Self::Error> {
        Self::parse(&candidate)
    }
}
impl From<Name> for StatePath {
    fn from(name: Name) -> Self {
        Self::from(&name)
    }
}
impl From<&Name> for StatePath {
    fn from(name: &Name) -> Self {
        Self(ConstString::from(name.as_ref()))
    }
}
impl<'a> DecodeFromSlice<'a> for StatePath {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), NoritoError> {
        Self::decode_wire(bytes)
    }
}

impl norito::json::FastJsonWrite for StatePath {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.as_ref(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_ref(), out)
    }
}

impl norito::json::JsonDeserialize for StatePath {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        Self::parse_for_json_decode(&value)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let candidate = value.as_str().ok_or(norito::json::Error::WithPos {
            msg: "StatePath must be a JSON string",
            byte: 0,
            line: 1,
            col: 1,
        })?;
        Self::parse_for_json_decode(candidate)
    }
}
impl norito::json::JsonKeyCodec for StatePath {
    fn encode_json_key(&self, out: &mut String) {
        norito::json::write_json_string(self.as_ref(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, norito::json::Error> {
        Self::parse_for_json_decode(encoded)
    }
}

impl norito::json::JsonObjectKey for StatePath {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(self.as_ref())
    }
}

impl norito::json::JsonObjectKeyOwned for StatePath {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        StatePath::parse_for_json_decode(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::{
        codec::{Decode, Encode},
        json::{self, JsonObjectKeyOwned},
    };
    use std::vec::Vec;
    #[test]
    fn accepts_long_paths_and_enforces_utf8_byte_limit() {
        let long = format!("balances/{}", "a".repeat(4 * 1024));
        let parsed = StatePath::from_str(&long).expect("path longer than Name remains valid");
        assert_eq!(parsed.as_ref(), long.as_str());
        let boundary = "a".repeat(MAX_STATE_PATH_BYTES);
        assert!(StatePath::from_str(&boundary).is_ok());
        assert!(StatePath::try_from(boundary).is_ok());
        let over_limit = "a".repeat(MAX_STATE_PATH_BYTES + 1);
        assert!(StatePath::from_str(&over_limit).is_err());
        assert!(StatePath::try_from(over_limit).is_err());
        let unicode_boundary = "é".repeat(MAX_STATE_PATH_BYTES / "é".len());
        assert_eq!(unicode_boundary.len(), MAX_STATE_PATH_BYTES);
        assert!(StatePath::from_str(&unicode_boundary).is_ok());
        assert!(StatePath::from_str(&format!("{unicode_boundary}é")).is_err());
    }
    #[test]
    fn rejects_alternate_nfc_spelling_and_preserves_lexical_order() {
        assert!(
            StatePath::from_str("root/e\u{301}").is_err(),
            "decomposed state path must not be rewritten",
        );
        let composed = StatePath::from_str("root/é").expect("valid composed path");
        assert_eq!(composed.as_ref(), "root/é");
        let mut paths = [
            StatePath::from_str("root/10").unwrap(),
            StatePath::from_str("root/02").unwrap(),
            StatePath::from_str("root/2").unwrap(),
        ];
        paths.sort();
        assert_eq!(
            paths.map(|path| path.as_ref().to_owned()),
            ["root/02", "root/10", "root/2"]
        );
    }
    #[test]
    fn rejects_empty_whitespace_controls_bidi_and_reserved_identifier_separators() {
        for invalid in [
            "",
            "root/has space",
            "root/\0suffix",
            "root/\u{001F}",
            "root/\u{007F}",
            "root/\u{0080}",
            "root/\u{061C}",
            "root/\u{200E}",
            "root/\u{200F}",
            "root/\u{202E}",
            "root/\u{2066}",
            "root/\u{2069}",
            "root/alice@domain",
            "root/asset#domain",
            "root/nft$domain",
        ] {
            assert!(
                StatePath::from_str(invalid).is_err(),
                "unsafe state path was accepted: {invalid:?}"
            );
        }
    }
    #[test]
    fn from_name_is_infallible_and_nominal() {
        let name = Name::from_str("native_record").expect("valid Name");
        let path = StatePath::from(&name);
        assert_eq!(path.as_ref(), "native_record");
        assert_eq!(StatePath::from(name), path);
        assert_ne!(
            <StatePath as iroha_schema::TypeId>::id(),
            <Name as iroha_schema::TypeId>::id(),
            "StatePath and Name must remain nominally distinct in the public schema"
        );
        let schema = <StatePath as iroha_schema::IntoSchema>::schema();
        assert!(schema.contains_key::<StatePath>());
        assert!(!schema.contains_key::<Name>());
    }
    #[test]
    fn norito_roundtrip_and_decoders_enforce_validation() {
        let path =
            StatePath::from_str(&format!("root/{}", "ab".repeat(1024))).expect("valid long path");
        let encoded = path.encode();
        let mut cursor = encoded.as_slice();
        let decoded = StatePath::decode(&mut cursor).expect("decode StatePath");
        assert_eq!(decoded, path);
        assert!(cursor.is_empty());
        for invalid in [
            "root/\0suffix".to_owned(),
            "root/\u{202E}suffix".to_owned(),
            "root/e\u{301}".to_owned(),
            "x".repeat(MAX_STATE_PATH_BYTES + 1),
        ] {
            let forged = StatePath(ConstString::from(invalid.as_str()));
            let encoded = forged.encode();
            let mut cursor = encoded.as_slice();
            assert!(StatePath::decode(&mut cursor).is_err());
            assert!(StatePath::decode_from_slice(&encoded).is_err());
            let framed = norito::to_bytes(&forged).expect("encode forged fixture");
            assert!(norito::decode_from_bytes::<StatePath>(&framed).is_err());
        }
    }
    #[test]
    fn slice_decoder_rejects_declared_oversize_before_body_access() {
        let mut declared_oversize = Vec::new();
        norito::core::write_len_to_vec(
            &mut declared_oversize,
            u64::try_from(MAX_STATE_PATH_BYTES + 1).expect("path limit fits u64"),
        );
        let error = StatePath::decode_from_slice(&declared_oversize)
            .expect_err("oversized declaration must fail before reading a missing body");
        assert!(error.to_string().contains("16384-byte"));
    }

    #[test]
    fn json_roundtrip_and_decoder_enforce_validation() {
        let path =
            StatePath::from_str(&format!("root/{}", "c".repeat(1024))).expect("valid long path");
        let json = norito::json::to_json(&path).expect("serialize StatePath");
        let decoded = norito::json::from_str::<StatePath>(&json).expect("deserialize StatePath");
        assert_eq!(decoded, path);
        for invalid in [
            "\"root/\\u0000suffix\"".to_owned(),
            "\"root/\\u202Esuffix\"".to_owned(),
            "\"root/e\\u0301\"".to_owned(),
            format!("\"{}\"", "x".repeat(MAX_STATE_PATH_BYTES + 1)),
        ] {
            assert!(norito::json::from_str::<StatePath>(&invalid).is_err());
        }
    }

    #[test]
    fn storage_json_requires_exact_nfc_keys() {
        type StateStorage = mv::storage::Storage<StatePath, Vec<u8>>;
        let decomposed = r#"{"revert":{},"blocks":{"root/e\u0301":[1]}}"#;
        assert!(
            norito::json::from_str::<StateStorage>(decomposed).is_err(),
            "storage key decoder must not rewrite decomposed text",
        );
        let exact = r#"{"revert":{},"blocks":{"root/é":[1]}}"#;
        let storage = norito::json::from_str::<StateStorage>(exact).expect("decode exact NFC key");
        let canonical = norito::json::to_json(&storage).expect("encode canonical storage");
        assert!(canonical.contains("\"root/é\""));
        let duplicate = r#"{"revert":{},"blocks":{"root/e\u0301":[1],"root/é":[2]}}"#;
        assert!(
            norito::json::from_str::<StateStorage>(duplicate).is_err(),
            "alternate StatePath spelling must fail closed"
        );
    }

    #[test]
    fn state_path_key_accounts_nfc_scratch_before_normalization() {
        fn allocation_limit(bytes: usize) -> norito::core::DecodeLimits {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        }

        let key = "root/é".repeat(4);
        // Twenty-four scalars have a 96-scalar audited decomposition bound.
        // Growing through 32, 64 and 128 u32 elements requests 896 bytes.
        let normalization_allocation = 896;
        let expected_allocation = key.len() + normalization_allocation;

        let (decoded, usage) = norito::core::with_decode_limits_measured(
            allocation_limit(expected_allocation),
            || <StatePath as JsonObjectKeyOwned>::from_json_key_text(&key),
        );
        assert_eq!(
            decoded
                .expect("canonical state path at exact allocation bound")
                .as_ref(),
            key
        );
        assert_eq!(usage.total_allocated_bytes(), expected_allocation);

        let (rejected, usage) = norito::core::with_decode_limits_measured(
            allocation_limit(expected_allocation - 1),
            || <StatePath as JsonObjectKeyOwned>::from_json_key_text(&key),
        );
        assert!(matches!(
            rejected,
            Err(json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), normalization_allocation);

        let decomposed = "root/e\u{301}".repeat(4);
        let (rejected, usage) =
            norito::core::with_decode_limits_measured(allocation_limit(usize::MAX), || {
                <StatePath as JsonObjectKeyOwned>::from_json_key_text(&decomposed)
            });
        assert!(rejected.is_err());
        assert_eq!(usage.total_allocated_bytes(), normalization_allocation);

        let (inline, usage) =
            norito::core::with_decode_limits_measured(allocation_limit(0), || {
                <StatePath as JsonObjectKeyOwned>::from_json_key_text("root/a")
            });
        assert_eq!(
            inline.expect("inline path needs no heap").as_ref(),
            "root/a"
        );
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
}
