//! JSON helpers for custom (de)serialization in data-model types.
//!
//! These helpers are intended for app-facing DTOs and are used with Norito's
//! checked `#[norito(json = "...")]` attribute.
//! For base64 encoding, select `crate::json_helpers::base64_vec` on `Vec<u8>` fields.

use crate::soranet::privacy_metrics::SoranetPrivacyModeV1;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use norito::json::{
    self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser,
    write_base64_json_to,
};

use std::collections::BTreeMap;
use std::{format, string::String, vec::Vec};

fn write_u128_decimal_string(
    mut value: u128,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    let mut digits = [0_u8; 39];
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(value % 10).expect("decimal digit fits u8");
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.push('"')?;
    for digit in &digits[cursor..] {
        out.push(char::from(*digit))?;
    }
    out.push('"')
}

fn write_i128_decimal_string(
    value: i128,
    out: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    let mut digits = [0_u8; 39];
    let mut magnitude = value.unsigned_abs();
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(magnitude % 10).expect("decimal digit fits u8");
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    out.push('"')?;
    if value.is_negative() {
        out.push('-')?;
    }
    for digit in &digits[cursor..] {
        out.push(char::from(*digit))?;
    }
    out.push('"')
}
/// Serialize a `Vec<u8>` as a base64 string and deserialize from base64.
pub mod base64_vec {
    use super::*;
    pub fn serialize(bytes: &[u8], out: &mut String) {
        JsonSerialize::json_serialize(&B64.encode(bytes), out);
    }
    pub fn serialize_bounded(
        bytes: &[u8],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        write_base64_json_to(bytes, out)
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<u8>, norito::json::Error> {
        let encoded = parser.parse_string()?;
        B64.decode(encoded.as_bytes())
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
    pub mod option {
        use super::*;
        #[allow(clippy::ref_option)] // Required by Norito serializer signature.
        pub fn serialize(value: &Option<Vec<u8>>, out: &mut String) {
            match value.as_deref() {
                Some(bytes) => super::serialize(bytes, out),
                None => out.push_str("null"),
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "Norito bounded serializers receive optional fields by shared reference"
        )]
        pub fn serialize_bounded(
            value: &Option<Vec<u8>>,
            out: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            match value.as_deref() {
                Some(bytes) => super::serialize_bounded(bytes, out),
                None => out.push_str("null"),
            }
        }
        pub fn deserialize(
            parser: &mut Parser<'_>,
        ) -> Result<Option<Vec<u8>>, norito::json::Error> {
            parser.skip_ws();
            if parser.try_consume_null()? {
                return Ok(None);
            }
            super::deserialize(parser).map(Some)
        }
    }
}
/// Serialize signed 128-bit integers as decimal strings to satisfy JSON codec expectations.
pub mod i128_string {
    use super::*;
    pub fn serialize(value: &i128, out: &mut String) {
        JsonSerialize::json_serialize(&value.to_string(), out);
    }
    pub fn serialize_bounded(
        value: &i128,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        write_i128_decimal_string(*value, out)
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<i128, norito::json::Error> {
        let raw = parser.parse_string()?;
        raw.parse::<i128>().map_err(|_| {
            norito::json::Error::Message(format!("invalid i128 string representation: {raw}"))
        })
    }
}
/// Serialize unsigned 64-bit integers as canonical decimal strings and reject
/// every non-canonical spelling on input.
pub mod u64_string {
    use super::*;
    fn parse_canonical(raw: &str) -> Result<u64, norito::json::Error> {
        if raw.is_empty()
            || (raw.len() > 1 && raw.starts_with('0'))
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(norito::json::Error::Message(format!(
                "invalid canonical u64 decimal string: {raw}"
            )));
        }
        raw.parse::<u64>().map_err(|_| {
            norito::json::Error::Message(format!("u64 decimal string is out of range: {raw}"))
        })
    }
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Norito `with` serializers receive fields by shared reference"
    )]
    pub fn serialize(value: &u64, out: &mut String) {
        JsonSerialize::json_serialize(&value.to_string(), out);
    }
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Norito bounded serializers receive fields by shared reference"
    )]
    pub fn serialize_bounded(
        value: &u64,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        write_u128_decimal_string(u128::from(*value), out)
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<u64, norito::json::Error> {
        parse_canonical(&parser.parse_string()?)
    }
}
/// Serialize unsigned 128-bit integers as canonical decimal strings and reject
/// every non-canonical spelling on input.
pub mod u128_string {
    use super::*;
    fn parse_canonical(raw: &str) -> Result<u128, norito::json::Error> {
        if raw.is_empty()
            || (raw.len() > 1 && raw.starts_with('0'))
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(norito::json::Error::Message(format!(
                "invalid canonical u128 decimal string: {raw}"
            )));
        }
        raw.parse::<u128>().map_err(|_| {
            norito::json::Error::Message(format!("u128 decimal string is out of range: {raw}"))
        })
    }
    pub fn serialize(value: &u128, out: &mut String) {
        JsonSerialize::json_serialize(&value.to_string(), out);
    }
    pub fn serialize_bounded(
        value: &u128,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        write_u128_decimal_string(*value, out)
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<u128, norito::json::Error> {
        parse_canonical(&parser.parse_string()?)
    }
}
/// Helpers for fixed-size byte arrays (`[u8; N]`) and their container variants.
pub mod fixed_bytes {
    use super::*;
    pub fn serialize<const N: usize>(bytes: &[u8; N], out: &mut String) {
        // Encode as a JSON array of byte values to match the historical Serde layout.
        let tmp: Vec<u8> = bytes.as_slice().to_vec();
        JsonSerialize::json_serialize(&tmp, out);
    }
    pub fn serialize_bounded<const N: usize>(
        bytes: &[u8; N],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, byte) in bytes.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                byte.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result
    }
    pub fn deserialize<const N: usize>(parser: &mut Parser<'_>) -> Result<[u8; N], json::Error> {
        let values = Vec::<u8>::json_deserialize(parser)?;
        vec_to_array::<N>(&values)
    }
    pub mod option {
        use super::*;
        #[allow(clippy::ref_option)] // Norito serializer interface requires `&Option<T>` signature
        pub fn serialize<const N: usize>(value: &Option<[u8; N]>, out: &mut String) {
            match value.as_ref() {
                Some(bytes) => super::serialize(bytes, out),
                None => out.push_str("null"),
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "Norito bounded serializers receive optional fields by shared reference"
        )]
        pub fn serialize_bounded<const N: usize>(
            value: &Option<[u8; N]>,
            out: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            match value.as_ref() {
                Some(bytes) => super::serialize_bounded(bytes, out),
                None => out.push_str("null"),
            }
        }
        pub fn deserialize<const N: usize>(
            parser: &mut Parser<'_>,
        ) -> Result<Option<[u8; N]>, json::Error> {
            parser.skip_ws();
            if parser.try_consume_null()? {
                return Ok(None);
            }
            super::deserialize(parser).map(Some)
        }
    }
    pub mod vec {
        use super::*;
        pub fn serialize<const N: usize>(value: &[[u8; N]], out: &mut String) {
            let tmp: Vec<Vec<u8>> = value
                .iter()
                .map(|bytes| bytes.as_slice().to_vec())
                .collect();
            JsonSerialize::json_serialize(&tmp, out);
        }
        pub fn serialize_bounded<const N: usize>(
            value: &[[u8; N]],
            out: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                out.push('[')?;
                for (index, bytes) in value.iter().enumerate() {
                    if index != 0 {
                        out.push(',')?;
                    }
                    super::serialize_bounded(bytes, out)?;
                }
                out.push(']')?;
                Ok(())
            })();
            out.end_container();
            result
        }
        pub fn deserialize<const N: usize>(
            parser: &mut Parser<'_>,
        ) -> Result<Vec<[u8; N]>, json::Error> {
            let raw = Vec::<Vec<u8>>::json_deserialize(parser)?;
            raw.into_iter()
                .map(|values| vec_to_array::<N>(&values))
                .collect()
        }
    }
    #[cfg(any(test, feature = "http"))]
    pub mod option_vec {
        use super::*;
        #[allow(clippy::ref_option)] // Norito serializer interface requires `&Option<T>` signature
        pub fn serialize<const N: usize>(value: &Option<Vec<[u8; N]>>, out: &mut String) {
            match value.as_deref() {
                Some(items) => vec::serialize(items, out),
                None => out.push_str("null"),
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "Norito bounded serializers receive optional fields by shared reference"
        )]
        pub fn serialize_bounded<const N: usize>(
            value: &Option<Vec<[u8; N]>>,
            out: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            match value.as_deref() {
                Some(items) => vec::serialize_bounded(items, out),
                None => out.push_str("null"),
            }
        }
        pub fn deserialize<const N: usize>(
            parser: &mut Parser<'_>,
        ) -> Result<Option<Vec<[u8; N]>>, json::Error> {
            parser.skip_ws();
            if parser.try_consume_null()? {
                return Ok(None);
            }
            vec::deserialize(parser).map(Some)
        }
    }
    fn vec_to_array<const N: usize>(values: &[u8]) -> Result<[u8; N], json::Error> {
        if values.len() != N {
            return Err(json::Error::Message(format!(
                "expected {N} bytes, got {}",
                values.len()
            )));
        }
        let mut array = [0_u8; N];
        array.copy_from_slice(values);
        Ok(array)
    }
}
/// Serialize and deserialize fixed-size byte arrays as hex strings.
pub mod fixed_bytes_hex {
    use super::*;
    pub fn serialize<const N: usize>(bytes: &[u8; N], out: &mut String) {
        let encoded = hex::encode(bytes);
        JsonSerialize::json_serialize(&encoded, out);
    }
    pub fn serialize_bounded<const N: usize>(
        bytes: &[u8; N],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push('"')?;
        for byte in bytes {
            out.push(char::from(HEX[usize::from(byte >> 4)]))?;
            out.push(char::from(HEX[usize::from(byte & 0x0f)]))?;
        }
        out.push('"')
    }
    pub fn deserialize<const N: usize>(parser: &mut Parser<'_>) -> Result<[u8; N], json::Error> {
        let raw = parser.parse_string()?;
        parse_hex_bytes::<N>(&raw)
    }
    #[cfg(any(test, feature = "governance"))]
    pub mod option {
        use super::*;
        #[allow(clippy::ref_option)] // Norito serializer interface requires `&Option<T>` signature
        pub fn serialize<const N: usize>(value: &Option<[u8; N]>, out: &mut String) {
            match value.as_ref() {
                Some(bytes) => super::serialize(bytes, out),
                None => out.push_str("null"),
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "Norito bounded serializers receive optional fields by shared reference"
        )]
        pub fn serialize_bounded<const N: usize>(
            value: &Option<[u8; N]>,
            out: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            match value.as_ref() {
                Some(bytes) => super::serialize_bounded(bytes, out),
                None => out.push_str("null"),
            }
        }
        pub fn deserialize<const N: usize>(
            parser: &mut Parser<'_>,
        ) -> Result<Option<[u8; N]>, json::Error> {
            parser.skip_ws();
            if parser.try_consume_null()? {
                return Ok(None);
            }
            super::deserialize(parser).map(Some)
        }
    }
    fn parse_hex_bytes<const N: usize>(raw: &str) -> Result<[u8; N], json::Error> {
        let without_scheme = if let Some((scheme, rest)) = raw.split_once(':') {
            if scheme.eq_ignore_ascii_case("blake2b32") {
                rest
            } else {
                return Err(json::Error::Message("expected hex string".to_string()));
            }
        } else {
            raw
        };
        let mut body = without_scheme;
        if let Some(stripped) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            body = stripped;
        }
        if body.len() != N * 2 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(json::Error::Message(format!(
                "expected {N}-byte hex string"
            )));
        }
        let mut out = [0_u8; N];
        hex::decode_to_slice(body, &mut out)
            .map_err(|err| json::Error::Message(err.to_string()))?;
        Ok(out)
    }
}
/// Serialize and deserialize a `SoraNet` privacy collector ID as one canonical lowercase hex value.
pub mod soranet_privacy_collector_id {
    use super::*;
    const COLLECTOR_ID_BYTES: usize = 32;
    /// Serialize a collector ID as exactly 64 lowercase hexadecimal characters.
    pub fn serialize(bytes: &[u8; COLLECTOR_ID_BYTES], out: &mut String) {
        fixed_bytes_hex::serialize(bytes, out);
    }
    /// Stream a collector ID as exactly 64 lowercase hexadecimal characters.
    pub fn serialize_bounded(
        bytes: &[u8; COLLECTOR_ID_BYTES],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        fixed_bytes_hex::serialize_bounded(bytes, out)
    }
    /// Decode only the canonical 64-character lowercase hexadecimal spelling.
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<[u8; COLLECTOR_ID_BYTES], json::Error> {
        let raw = parser.parse_string()?;
        if raw.len() != COLLECTOR_ID_BYTES * 2
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(json::Error::Message(
                "expected exactly 64 lowercase hexadecimal characters".to_owned(),
            ));
        }
        let mut out = [0_u8; COLLECTOR_ID_BYTES];
        hex::decode_to_slice(raw, &mut out)
            .map_err(|error| json::Error::Message(error.to_string()))?;
        Ok(out)
    }
}
/// Serialize and deserialize [`SoranetPrivacyModeV1`] values as their label strings.
pub mod privacy_mode {
    use super::*;
    #[allow(clippy::trivially_copy_pass_by_ref)] // Norito interface requires `&T` signature.
    pub fn serialize(value: &SoranetPrivacyModeV1, out: &mut String) {
        JsonSerialize::json_serialize(value.as_label(), out);
    }
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Norito bounded serializers receive fields by shared reference"
    )]
    pub fn serialize_bounded(
        value: &SoranetPrivacyModeV1,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        value.as_label().json_serialize_to(out)
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<SoranetPrivacyModeV1, json::Error> {
        let label = parser.parse_string()?;
        match label.as_str() {
            "entry" => Ok(SoranetPrivacyModeV1::Entry),
            "middle" => Ok(SoranetPrivacyModeV1::Middle),
            "exit" => Ok(SoranetPrivacyModeV1::Exit),
            other => Err(json::Error::unknown_field(other)),
        }
    }
}
/// Serialize a map keyed by [`AccountId`] into a string-keyed JSON object.
pub mod account_metadata_map {
    use super::*;
    use crate::account::AccountId;
    use iroha_model_base::metadata::Metadata;
    pub fn serialize(value: &BTreeMap<AccountId, Metadata>, out: &mut String) {
        let string_keyed: BTreeMap<String, Metadata> = value
            .iter()
            .map(|(account, metadata)| (account.to_string(), metadata.clone()))
            .collect();
        JsonSerialize::json_serialize(&string_keyed, out);
    }
    pub fn serialize_bounded(
        value: &BTreeMap<AccountId, Metadata>,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            // `AccountId::Ord` is not the JSON key order. Select one canonical
            // key at a time so byte parity does not require cloning the full map.
            let mut previous_key: Option<String> = None;
            let mut wrote_entry = false;
            loop {
                let mut next: Option<(String, &Metadata)> = None;
                for (account, metadata) in value {
                    let candidate = account
                        .canonical_i105()
                        .map_err(|_| BoundedJsonError::Unsupported)?;
                    if previous_key
                        .as_ref()
                        .is_some_and(|key| candidate.as_str() <= key.as_str())
                        || next
                            .as_ref()
                            .is_some_and(|(key, _)| candidate.as_str() >= key.as_str())
                    {
                        continue;
                    }
                    next = Some((candidate, metadata));
                }
                let Some((key, metadata)) = next else {
                    break;
                };
                if wrote_entry {
                    out.push(',')?;
                }
                norito::json::write_json_string_to(&key, out)?;
                out.push(':')?;
                metadata.json_serialize_to(out)?;
                previous_key = Some(key);
                wrote_entry = true;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
    pub fn deserialize(
        parser: &mut Parser<'_>,
    ) -> Result<BTreeMap<AccountId, Metadata>, norito::json::Error> {
        BTreeMap::<AccountId, Metadata>::json_deserialize(parser).map_err(|error| {
            if cfg!(all(test, sumeragi_model_mutation = "DM27"))
                && matches!(
                    error,
                    norito::json::Error::ScopedDecodeResource(_)
                        | norito::json::Error::DecodeResource(_)
                )
            {
                return norito::json::Error::Message(error.to_string());
            }
            error
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::json;

    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    struct Base64Wrapper {
        #[norito(
            with = "crate::json_helpers::base64_vec",
            bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
        )]
        data: Vec<u8>,
    }
    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    struct FixedBytesWrapper {
        #[norito(
            with = "crate::json_helpers::fixed_bytes",
            bounded_with = "crate::json_helpers::fixed_bytes::serialize_bounded"
        )]
        data: [u8; 4],
        #[norito(
            with = "crate::json_helpers::fixed_bytes::option",
            bounded_with = "crate::json_helpers::fixed_bytes::option::serialize_bounded"
        )]
        optional: Option<[u8; 2]>,
    }
    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    struct ContainerHelpersWrapper {
        #[norito(
            with = "crate::json_helpers::base64_vec::option",
            bounded_with = "crate::json_helpers::base64_vec::option::serialize_bounded"
        )]
        encoded: Option<Vec<u8>>,
        #[norito(
            with = "crate::json_helpers::fixed_bytes::vec",
            bounded_with = "crate::json_helpers::fixed_bytes::vec::serialize_bounded"
        )]
        fixed: Vec<[u8; 2]>,
        #[norito(
            with = "crate::json_helpers::fixed_bytes::option_vec",
            bounded_with = "crate::json_helpers::fixed_bytes::option_vec::serialize_bounded"
        )]
        optional_fixed: Option<Vec<[u8; 2]>>,
    }
    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    struct ScalarHelpersWrapper {
        #[norito(
            with = "crate::json_helpers::u64_string",
            bounded_with = "crate::json_helpers::u64_string::serialize_bounded"
        )]
        count: u64,
        #[norito(
            with = "crate::json_helpers::u128_string",
            bounded_with = "crate::json_helpers::u128_string::serialize_bounded"
        )]
        total: u128,
        #[norito(
            with = "crate::json_helpers::fixed_bytes_hex",
            bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
        )]
        digest: [u8; 4],
        #[norito(
            with = "crate::json_helpers::fixed_bytes_hex::option",
            bounded_with = "crate::json_helpers::fixed_bytes_hex::option::serialize_bounded"
        )]
        optional_digest: Option<[u8; 2]>,
        #[norito(
            with = "crate::json_helpers::privacy_mode",
            bounded_with = "crate::json_helpers::privacy_mode::serialize_bounded"
        )]
        mode: SoranetPrivacyModeV1,
    }
    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct SoranetCollectorIdWrapper {
        #[norito(
            with = "crate::json_helpers::soranet_privacy_collector_id",
            bounded_with = "crate::json_helpers::soranet_privacy_collector_id::serialize_bounded"
        )]
        collector_id: [u8; 32],
    }
    #[test]
    fn soranet_collector_id_requires_one_canonical_json_spelling() {
        let wrapper = SoranetCollectorIdWrapper {
            collector_id: [0xab; 32],
        };
        let canonical = "ab".repeat(32);
        let encoded = json::to_json(&wrapper).expect("serialize collector ID");
        assert_eq!(encoded, format!(r#"{{"collector_id":"{canonical}"}}"#));
        assert_eq!(
            json::from_str::<SoranetCollectorIdWrapper>(&encoded).expect("decode collector ID"),
            wrapper
        );
        for noncanonical in [canonical.to_uppercase(), format!("0x{canonical}")] {
            let payload = format!(r#"{{"collector_id":"{noncanonical}"}}"#);
            json::from_str::<SoranetCollectorIdWrapper>(&payload)
                .expect_err("noncanonical collector ID must fail closed");
        }
        let unknown = format!(r#"{{"collector_id":"{canonical}","extra":true}}"#);
        json::from_str::<SoranetCollectorIdWrapper>(&unknown)
            .expect_err("unknown collector ID fields must fail closed");
    }
    #[test]
    fn base64_vec_roundtrip_serialization() {
        let wrapper = Base64Wrapper {
            data: vec![0_u8, 1, 2, 3, 255],
        };
        let json = json::to_json(&wrapper).expect("serialize to JSON");
        assert_eq!(json, "{\"data\":\"AAECA/8=\"}");
        let decoded: Base64Wrapper = json::from_str(&json).expect("decode from JSON");
        assert_eq!(decoded, wrapper);
        assert_eq!(
            json::to_json_bounded(&wrapper, json.len()).expect("exact bounded base64 output"),
            json
        );
        assert_eq!(
            json::to_json_bounded(&wrapper, json.len() - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
    }
    #[test]
    fn fixed_bytes_checked_writer_matches_legacy_bytes_and_exact_bound() {
        let wrapper = FixedBytesWrapper {
            data: [0, 1, 42, 255],
            optional: Some([7, 8]),
        };
        let legacy = json::to_json(&wrapper).expect("legacy fixed-byte JSON");
        assert_eq!(legacy, r#"{"data":[0,1,42,255],"optional":[7,8]}"#);
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len()).expect("exact fixed-byte JSON"),
            legacy
        );
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len() - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
    }
    #[test]
    fn checked_container_helpers_match_legacy_bytes_at_exact_bound() {
        let wrapper = ContainerHelpersWrapper {
            encoded: Some(vec![0, 1, 2, 255]),
            fixed: vec![[1, 2], [3, 4]],
            optional_fixed: Some(vec![[5, 6]]),
        };
        let legacy = json::to_json(&wrapper).expect("legacy container-helper JSON");
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len()).expect("exact container-helper JSON"),
            legacy
        );
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len() - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
    }
    #[test]
    fn scalar_checked_helpers_match_legacy_bytes_at_exact_bound() {
        let wrapper = ScalarHelpersWrapper {
            count: u64::MAX,
            total: u128::MAX,
            digest: [0x01, 0x23, 0xab, 0xcd],
            optional_digest: Some([0xef, 0x42]),
            mode: SoranetPrivacyModeV1::Entry,
        };
        let legacy = json::to_json(&wrapper).expect("legacy scalar-helper JSON");
        assert!(legacy.contains(r#""count":"18446744073709551615""#));
        assert!(legacy.contains(r#""total":"340282366920938463463374607431768211455""#));
        assert!(legacy.contains(r#""digest":"0123abcd""#));
        assert!(legacy.contains(r#""mode":"entry""#));
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len()).expect("exact bounded scalar JSON"),
            legacy
        );
        assert_eq!(
            json::to_json_bounded(&wrapper, legacy.len() - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
    }
    #[test]
    fn base64_vec_rejects_invalid_input() {
        let json = "{\"data\":\"not-base64@@\"}";
        let err = json::from_str::<Base64Wrapper>(json).expect_err("invalid base64 must fail");
        match err {
            norito::json::Error::Message(message) => {
                let msg = message.to_ascii_lowercase();
                assert!(msg.contains("invalid"), "unexpected message: {message}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
    #[derive(Debug, PartialEq, Eq, JsonSerialize, crate::DeriveJsonDeserialize)]
    struct I128Wrapper {
        #[norito(
            with = "crate::json_helpers::i128_string",
            bounded_with = "crate::json_helpers::i128_string::serialize_bounded"
        )]
        value: i128,
    }
    #[test]
    fn i128_string_roundtrip_serialization() {
        let wrapper = I128Wrapper {
            value: -1_234_567_890_123_456_789,
        };
        let json = json::to_json(&wrapper).expect("serialize to JSON");
        assert_eq!(json, "{\"value\":\"-1234567890123456789\"}");
        let decoded: I128Wrapper = json::from_str(&json).expect("decode from JSON");
        assert_eq!(decoded, wrapper);
        assert_eq!(
            json::to_json_bounded(&wrapper, json.len()).expect("exact bounded i128 JSON"),
            json
        );
    }
    #[test]
    fn i128_string_rejects_invalid_input() {
        let json = "{\"value\":\"not-a-number\"}";
        let err = json::from_str::<I128Wrapper>(json).expect_err("invalid integer must fail");
        match err {
            norito::json::Error::Message(message) => assert!(
                message.contains("invalid i128 string representation"),
                "unexpected message: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::{account, audit_write};

    #[test]
    fn original_account_metadata_map_checked_container_retains_order_and_depth() {
        let mut values = std::collections::BTreeMap::new();
        values.insert(account(61), iroha_model_base::metadata::Metadata::default());
        values.insert(account(62), iroha_model_base::metadata::Metadata::default());
        let pointer = std::ptr::from_ref(&values);
        let mut ordinary = String::new();
        account_metadata_map::serialize(&values, &mut ordinary);
        audit_write(&ordinary, |out| {
            account_metadata_map::serialize_bounded(&values, out)
        });
        assert_eq!(std::ptr::from_ref(&values), pointer);
    }
}
