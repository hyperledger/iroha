//! SCCP (SORA Cross-Chain Protocol) primitives for Iroha (`specs/sccp.md`).
//!
//! [`v1`] holds the network-free contract-visible encodings, [`light_client`] the stateless
//! inbound light-client checks and [`api`] the Torii read-API records. The Ethereum consensus
//! primitives (`ethereum_native`, re-exported at the crate root) and the Ethereum wire and
//! execution-layer primitives ([`ethereum_source`]) back [`light_client::ethereum`] and the
//! receipt openings of [`light_client::bsc`]. The TON module (`ton_native`, re-exported at the
//! crate root) holds the native `BoC`, cell, TL, signature and transaction primitives behind
//! [`light_client::ton`] and the `iroha_sccp_rpc` TON builders. `test_support` (under
//! `cfg(test)` and the `test-fixtures` feature) holds deterministic synthetic source chains.
//!
//! The crate targets the Rust standard library unconditionally, and BLS verification is not
//! feature-gated, so Cargo feature selection cannot change consensus admission results.
extern crate alloc;
/// Torii read-API records for SCCP v1.
pub mod api;
mod ethereum_native;
pub mod ethereum_source;
pub mod light_client;
mod native_memory;
pub mod v1;
pub use ethereum_native::*;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_support;
mod ton_cell_hash;
mod ton_native;
pub use ton_native::watch as ton_watch;
// Explicit list of the public `ton_native` primitives. The raw `BoC`/cell types and the
// block-opening helpers are `pub` inside this private module for crate-internal use only.
pub use ton_native::{
    TonBlockIdExtV1, TonBlockSignaturesV1, TonComputedCell, TonNativeSourceError,
    TonOrdinaryBlockSignaturesV1, TonSimplexBlockSignaturesV1, TonValidatorConfigV1,
    TonValidatorSetV1, TonValidatorSignatureV1, TonValidatorV1, encode_canonical_ton_boc,
    parse_ton_boc, ton_block_id_tl_bytes, ton_boc_cell_hashes, ton_boc_single_root_hash_v1,
    ton_canonical_boc_single_root_hash_v1, ton_canonical_boc_v1, ton_cell_serialized_bit_len,
    ton_header_key_block_v1, ton_masterchain_generation_time_seconds, ton_sccp_transfer_payload_v1,
    ton_validator_list_hash_short_v1, ton_validator_node_id_short_v1,
};
#[cfg(test)]
#[path = "test_fixtures/finality_descendant_tests.rs"]
mod native_finality_tests;
use alloc::vec::Vec;

/// Fixed 256-bit protocol hash or word.
pub type H256 = [u8; 32];

fn decode_ascii_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
/// Decode an even-length canonical lowercase `0x`-prefixed hex string.
fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    let raw = value.strip_prefix("0x")?.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.chunks_exact(2) {
        let hi = decode_ascii_lower_hex_nibble(chunk[0])?;
        let lo = decode_ascii_lower_hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}
/// Decode a canonical lowercase `0x`-prefixed hex string of exactly `N` bytes.
fn decode_canonical_0x_lower_hex_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let raw = value.strip_prefix("0x")?.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (index, chunk) in raw.chunks_exact(2).enumerate() {
        let high = decode_ascii_lower_hex_nibble(chunk[0])?;
        let low = decode_ascii_lower_hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}
mod json_utils {
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };
    use norito::json::{self, Error, JsonDeserialize, Parser};
    fn encode_hex(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        for byte in bytes {
            out.push(LUT[usize::from(byte >> 4)] as char);
            out.push(LUT[usize::from(byte & 0x0f)] as char);
        }
        out
    }
    fn decode_hex_vec(value: &str) -> Result<Vec<u8>, Error> {
        super::decode_hex_bytes(value).ok_or_else(|| {
            Error::Message("expected canonical lowercase 0x-prefixed hex byte string".into())
        })
    }
    fn decode_hex_fixed<const N: usize>(value: &str) -> Result<[u8; N], Error> {
        super::decode_canonical_0x_lower_hex_fixed::<N>(value).ok_or_else(|| {
            Error::Message(format!(
                "expected canonical lowercase 0x-prefixed {N}-byte hex string"
            ))
        })
    }
    fn unsigned_decimal_string_is_canonical(value: &str) -> bool {
        !value.is_empty()
            && value.as_bytes().iter().all(u8::is_ascii_digit)
            && (value == "0" || !value.starts_with('0'))
    }
    fn parse_canonical_decimal_u64_string(value: &str) -> Result<u64, Error> {
        if !unsigned_decimal_string_is_canonical(value) {
            return Err(Error::Message(
                "expected canonical unsigned u64 decimal string".into(),
            ));
        }
        value
            .parse::<u64>()
            .map_err(|err| Error::Message(format!("failed to parse u64 string: {err}")))
    }
    fn parse_decimal_u64(parser: &mut Parser<'_>) -> Result<u64, Error> {
        parser.skip_ws();
        if parser.peek() == Some(b'"') {
            return parse_canonical_decimal_u64_string(&parser.parse_string()?);
        }
        parser.parse_u64()
    }
    pub mod hex32 {
        use super::{Error, Parser, decode_hex_fixed, encode_hex, json};
        pub fn serialize(value: &[u8; 32], out: &mut String) {
            json::write_json_string(&encode_hex(value), out);
        }
        pub fn deserialize(parser: &mut Parser<'_>) -> Result<[u8; 32], Error> {
            let value = parser.parse_string()?;
            decode_hex_fixed::<32>(&value)
        }
    }
    pub mod bytes_hex {
        use super::{Error, Parser, Vec, decode_hex_vec, encode_hex, json};
        pub fn serialize(value: &[u8], out: &mut String) {
            json::write_json_string(&encode_hex(value), out);
        }
        pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<u8>, Error> {
            let value = parser.parse_string()?;
            decode_hex_vec(&value)
        }
    }
    pub mod vec_bytes_hex {
        use super::{
            Error, JsonDeserialize, Parser, String, Vec, decode_hex_vec, encode_hex, json,
        };
        pub fn serialize(value: &[Vec<u8>], out: &mut String) {
            out.push('[');
            for (index, item) in value.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                json::write_json_string(&encode_hex(item), out);
            }
            out.push(']');
        }
        pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<Vec<u8>>, Error> {
            let values = <Vec<String> as JsonDeserialize>::json_deserialize(parser)?;
            values
                .into_iter()
                .map(|value| decode_hex_vec(&value))
                .collect()
        }
    }
    pub mod u64_string {
        use super::{Error, Parser, ToString, json, parse_decimal_u64};
        #[expect(
            clippy::trivially_copy_pass_by_ref,
            reason = "norito field serializers receive values by reference"
        )]
        pub fn serialize(value: &u64, out: &mut String) {
            json::write_json_string(&value.to_string(), out);
        }
        pub fn deserialize(parser: &mut Parser<'_>) -> Result<u64, Error> {
            parse_decimal_u64(parser)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hex_helpers_accept_only_lowercase_prefixed_input() {
        assert_eq!(decode_hex_bytes("0x"), Some(Vec::new()));
        assert_eq!(decode_hex_bytes("0x00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex_bytes("00ff"), None);
        assert_eq!(decode_hex_bytes("0x00FF"), None);
        assert_eq!(decode_hex_bytes("0x0"), None);
        assert_eq!(
            decode_canonical_0x_lower_hex_fixed::<2>("0xabcd"),
            Some([0xab, 0xcd])
        );
        assert_eq!(decode_canonical_0x_lower_hex_fixed::<2>("0xabc"), None);
        assert_eq!(decode_canonical_0x_lower_hex_fixed::<2>("0xabcdef"), None);
        assert_eq!(decode_canonical_0x_lower_hex_fixed::<1>("0xAB"), None);
    }

    #[test]
    fn json_field_hooks_roundtrip_canonical_values() {
        let mut out = String::new();
        json_utils::hex32::serialize(&[0x5a; 32], &mut out);
        let mut parser = norito::json::Parser::new(&out);
        assert_eq!(
            json_utils::hex32::deserialize(&mut parser).expect("hex32 decodes"),
            [0x5a; 32]
        );
        let mut out = String::new();
        json_utils::u64_string::serialize(&42, &mut out);
        assert_eq!(out, "\"42\"");
        let mut parser = norito::json::Parser::new(&out);
        assert_eq!(
            json_utils::u64_string::deserialize(&mut parser).expect("u64 decodes"),
            42
        );
        let mut parser = norito::json::Parser::new("\"042\"");
        assert!(json_utils::u64_string::deserialize(&mut parser).is_err());
        let mut out = String::new();
        json_utils::vec_bytes_hex::serialize(&[vec![1, 2], Vec::new()], &mut out);
        assert_eq!(out, "[\"0x0102\",\"0x\"]");
        let mut parser = norito::json::Parser::new(&out);
        assert_eq!(
            json_utils::vec_bytes_hex::deserialize(&mut parser).expect("byte vectors decode"),
            vec![vec![1, 2], Vec::new()]
        );
    }
}
