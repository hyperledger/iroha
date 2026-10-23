//! Module with multihash implementation
use crate::{Algorithm, ParseError, hex_decode, varint};
use std::{
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use zeroize::Zeroizing;
pub fn decode_public_key(bytes: &[u8]) -> Result<(Algorithm, Vec<u8>), ParseError> {
    let (digest_function, payload) = decode_multihash(bytes)?;
    let algorithm = digest_function_public::decode(digest_function)?;
    Ok((algorithm, payload.to_vec()))
}
pub fn decode_private_key(bytes: &[u8]) -> Result<(Algorithm, Vec<u8>), ParseError> {
    let (digest_function, payload) = decode_multihash(bytes)?;
    let algorithm = digest_function_private::decode(digest_function)?;
    Ok((algorithm, payload.to_vec()))
}
pub fn encode_private_key_string(algorithm: Algorithm, payload: &[u8]) -> String {
    format_multihash_hex(digest_function_private::encode(algorithm), payload)
}
fn format_multihash_hex(digest_function: DigestFunction, payload: &[u8]) -> String {
    let mut output = String::with_capacity(multihash_hex_len(digest_function, payload.len()));
    push_lower_varint_hex(digest_function, &mut output);
    push_lower_varint_hex(payload.len() as u64, &mut output);
    push_hex_bytes(payload, b"0123456789ABCDEF", &mut output);
    output
}

fn multihash_hex_len(mut digest_function: DigestFunction, payload_len: usize) -> usize {
    let mut header_bytes = 2_usize;
    while digest_function >= 0x80 {
        digest_function >>= 7;
        header_bytes += 1;
    }
    let mut encoded_len = payload_len as u64;
    while encoded_len >= 0x80 {
        encoded_len >>= 7;
        header_bytes += 1;
    }
    (header_bytes + payload_len) * 2
}

fn push_lower_varint_hex(mut value: u64, output: &mut String) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        push_hex_byte(byte, b"0123456789abcdef", output);
        if value == 0 {
            return;
        }
    }
}

fn push_hex_bytes(bytes: &[u8], alphabet: &[u8; 16], output: &mut String) {
    for &byte in bytes {
        push_hex_byte(byte, alphabet, output);
    }
}

fn push_hex_byte(byte: u8, alphabet: &[u8; 16], output: &mut String) {
    output.push(char::from(alphabet[usize::from(byte >> 4)]));
    output.push(char::from(alphabet[usize::from(byte & 0x0f)]));
}

/// Encode a public key into an algorithm-prefixed multihash hex string, e.g. "ed25519:...".
pub fn encode_public_key_prefixed(algorithm: Algorithm, payload: &[u8]) -> String {
    encode_key_prefixed(
        algorithm,
        digest_function_public::encode(algorithm),
        payload,
    )
}
/// Encode a private key into an algorithm-prefixed multihash hex string, e.g. "ml-dsa:...".
pub fn encode_private_key_prefixed(algorithm: Algorithm, payload: &[u8]) -> String {
    encode_key_prefixed(
        algorithm,
        digest_function_private::encode(algorithm),
        payload,
    )
}

fn encode_key_prefixed(
    algorithm: Algorithm,
    digest_function: DigestFunction,
    payload: &[u8],
) -> String {
    let prefix = algorithm.as_static_str();
    let mut output =
        String::with_capacity(prefix.len() + 1 + multihash_hex_len(digest_function, payload.len()));
    output.push_str(prefix);
    output.push(':');
    push_lower_varint_hex(digest_function, &mut output);
    push_lower_varint_hex(payload.len() as u64, &mut output);
    push_hex_bytes(payload, b"0123456789ABCDEF", &mut output);
    output
}
/// Decode a public key from either a bare multihash hex string or an
/// algorithm-prefixed form like "ed25519:<multihash-hex>".
/// Input must be canonical multihash hex (varint bytes lowercase, payload uppercase);
/// `0x` prefixes are rejected.
pub fn decode_public_key_str(s: &str) -> Result<(Algorithm, Vec<u8>), ParseError> {
    if let Some((alg_str, rest)) = s.split_once(':') {
        let algorithm = alg_str
            .parse::<Algorithm>()
            .map_err(|_| ParseError::Invalid(format!("Unknown algorithm prefix: {alg_str}")))?;
        let bytes = decode_multihash_hex_bytes(rest)?;
        let (alg_from_mh, payload) = decode_public_key(&bytes)?;
        if alg_from_mh != algorithm {
            return Err(ParseError::Invalid(
                "Algorithm prefix does not match multihash".to_string(),
            ));
        }
        Ok((algorithm, payload))
    } else {
        let bytes = decode_multihash_hex_bytes(s)?;
        decode_public_key(&bytes)
    }
}
/// Borrowed, allocation-free canonical public-key multihash components.
pub struct BorrowedPublicKeyHex<'a> {
    pub(super) algorithm: Algorithm,
    pub(super) payload_hex: &'a str,
}
/// Longest canonical public-key literal accepted by the current protocol.
pub const MAX_PUBLIC_KEY_LITERAL_BYTES: usize =
    28 + 1 + 2 * (2 + 2 + crate::MAX_PUBLIC_KEY_PAYLOAD_BYTES);
/// Parse canonical bare public-key multihash text without allocating payload or diagnostics.
pub fn decode_public_key_str_borrowed(encoded: &str) -> Option<BorrowedPublicKeyHex<'_>> {
    if encoded.len() > MAX_PUBLIC_KEY_LITERAL_BYTES {
        return None;
    }
    if encoded.len() < 4 || !encoded.len().is_multiple_of(2) {
        return None;
    }
    let mut cursor = 0;
    let digest_function = decode_canonical_header_varint(encoded, &mut cursor)?;
    let payload_len =
        usize::try_from(decode_canonical_header_varint(encoded, &mut cursor)?).ok()?;
    if payload_len > crate::MAX_PUBLIC_KEY_PAYLOAD_BYTES
        || encoded.len().checked_sub(cursor)? != payload_len.checked_mul(2)?
    {
        return None;
    }
    let algorithm = digest_function_public::decode_option(digest_function)?;
    let payload_hex = encoded.get(cursor..)?;
    if !payload_hex
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    Some(BorrowedPublicKeyHex {
        algorithm,
        payload_hex,
    })
}
fn decode_canonical_header_varint(encoded: &str, cursor: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for index in 0..10 {
        let end = cursor.checked_add(2)?;
        let pair = encoded.as_bytes().get(*cursor..end)?;
        let byte = decode_hex_pair(pair, false)?;
        *cursor = end;
        let low = u64::from(byte & 0x7f);
        if shift == 63 && low > 1 {
            return None;
        }
        value |= low.checked_shl(shift)?;
        if byte & 0x80 == 0 {
            if index != 0 && low == 0 {
                return None;
            }
            return Some(value);
        }
        shift = shift.checked_add(7)?;
    }
    None
}
fn decode_hex_pair(pair: &[u8], uppercase: bool) -> Option<u8> {
    if pair.len() != 2 {
        return None;
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' if uppercase => Some(byte - b'A' + 10),
        b'a'..=b'f' if !uppercase => Some(byte - b'a' + 10),
        _ => None,
    };
    Some((nibble(pair[0])? << 4) | nibble(pair[1])?)
}
/// Decode one canonical uppercase public-key payload byte.
pub fn decode_public_key_payload_byte(pair: &[u8]) -> Option<u8> {
    decode_hex_pair(pair, true)
}
/// Return the public-key multicodec value without constructing a multihash.
pub fn public_key_digest_function(algorithm: Algorithm) -> u64 {
    digest_function_public::encode(algorithm)
}
/// Decode a private key from either a bare multihash hex string or an
/// algorithm-prefixed form like "ml-dsa:<multihash-hex>".
/// Input must be canonical multihash hex (varint bytes lowercase, payload uppercase);
/// `0x` prefixes are rejected.
pub fn decode_private_key_str(s: &str) -> Result<(Algorithm, Vec<u8>), ParseError> {
    if let Some((alg_str, rest)) = s.split_once(':') {
        let algorithm = alg_str
            .parse::<Algorithm>()
            .map_err(|_| ParseError::Invalid(format!("Unknown algorithm prefix: {alg_str}")))?;
        let bytes = decode_private_multihash_hex_bytes(rest)?;
        let (alg_from_mh, payload) = decode_private_key(bytes.as_slice())?;
        if alg_from_mh != algorithm {
            return Err(ParseError::Invalid(
                "Algorithm prefix does not match multihash".to_string(),
            ));
        }
        Ok((algorithm, payload))
    } else {
        let bytes = decode_private_multihash_hex_bytes(s)?;
        decode_private_key(bytes.as_slice())
    }
}
fn decode_multihash_hex_bytes(s: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = hex_decode(s)?;
    let (digest_function, payload) = decode_multihash(&bytes)?;
    let canonical = format_multihash_hex(digest_function, payload);
    if s != canonical {
        return Err(ParseError::Invalid(
            "Non-canonical multihash hex".to_string(),
        ));
    }
    Ok(bytes)
}
fn decode_private_multihash_hex_bytes(s: &str) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    let bytes = Zeroizing::new(hex_decode(s)?);
    let (digest_function, payload) = decode_multihash(bytes.as_slice())?;
    let canonical = Zeroizing::new(format_multihash_hex(digest_function, payload));
    if s != canonical.as_str() {
        return Err(ParseError::Invalid(
            "Non-canonical multihash hex".to_string(),
        ));
    }
    Ok(bytes)
}
/// Value of byte code corresponding to algorithm.
/// See [official multihash table](https://github.com/multiformats/multicodec/blob/master/table.csv)
type DigestFunction = u64;
mod digest_function_public {
    use crate::{Algorithm, error::ParseError, multihash::DigestFunction};
    use std::string::String;
    const ED_25519: DigestFunction = 0xed;
    const SECP_256_K1: DigestFunction = 0xe7;
    // Provisional multicodec for ML‑DSA (Dilithium3) public keys; align with upstream when assigned.
    const ML_DSA_DILITHIUM3_PK: DigestFunction = 0xee;
    // Provisional multicodec assignments for TC26 parameter sets; replace with canonical codes once allocated.
    const GOST_3410_2012_256_A: DigestFunction = 0x1200;
    const GOST_3410_2012_256_B: DigestFunction = 0x1201;
    const GOST_3410_2012_256_C: DigestFunction = 0x1202;
    const GOST_3410_2012_512_A: DigestFunction = 0x1203;
    const GOST_3410_2012_512_B: DigestFunction = 0x1204;
    const BLS12_381_G1: DigestFunction = 0xea;
    const BLS12_381_G2: DigestFunction = 0xeb;
    // Provisional multicodec assignment; replace once canonical code is allocated.
    const SM2_PUB: DigestFunction = 0x1306;
    pub fn decode_option(digest_function: DigestFunction) -> Option<Algorithm> {
        Some(match digest_function {
            ED_25519 => Algorithm::Ed25519,
            SECP_256_K1 => Algorithm::Secp256k1,
            BLS12_381_G1 => Algorithm::BlsNormal,
            BLS12_381_G2 => Algorithm::BlsSmall,
            ML_DSA_DILITHIUM3_PK => Algorithm::MlDsa,
            GOST_3410_2012_256_A => Algorithm::Gost3410_2012_256ParamSetA,
            GOST_3410_2012_256_B => Algorithm::Gost3410_2012_256ParamSetB,
            GOST_3410_2012_256_C => Algorithm::Gost3410_2012_256ParamSetC,
            GOST_3410_2012_512_A => Algorithm::Gost3410_2012_512ParamSetA,
            GOST_3410_2012_512_B => Algorithm::Gost3410_2012_512ParamSetB,
            SM2_PUB => Algorithm::Sm2,
            _ => return None,
        })
    }
    pub fn decode(digest_function: DigestFunction) -> Result<Algorithm, ParseError> {
        decode_option(digest_function)
            .ok_or_else(|| ParseError::Invalid(String::from("No such algorithm")))
    }
    pub fn encode(algorithm: Algorithm) -> u64 {
        match algorithm {
            Algorithm::Ed25519 => ED_25519,
            Algorithm::Secp256k1 => SECP_256_K1,
            Algorithm::MlDsa => ML_DSA_DILITHIUM3_PK,
            Algorithm::Gost3410_2012_256ParamSetA => GOST_3410_2012_256_A,
            Algorithm::Gost3410_2012_256ParamSetB => GOST_3410_2012_256_B,
            Algorithm::Gost3410_2012_256ParamSetC => GOST_3410_2012_256_C,
            Algorithm::Gost3410_2012_512ParamSetA => GOST_3410_2012_512_A,
            Algorithm::Gost3410_2012_512ParamSetB => GOST_3410_2012_512_B,
            Algorithm::BlsNormal => BLS12_381_G1,
            Algorithm::BlsSmall => BLS12_381_G2,
            Algorithm::Sm2 => SM2_PUB,
        }
    }
}
mod digest_function_private {
    use crate::{Algorithm, error::ParseError, multihash::DigestFunction};
    use std::string::String;
    const ED_25519: DigestFunction = 0x1300;
    const SECP_256_K1: DigestFunction = 0x1301;
    // Provisional multicodec for ML‑DSA (Dilithium3) private keys; align with upstream when assigned.
    const ML_DSA_DILITHIUM3_SK: DigestFunction = 0x130b;
    // Provisional multicodec assignments for TC26 private keys.
    const GOST_3410_2012_256_A: DigestFunction = 0x130c;
    const GOST_3410_2012_256_B: DigestFunction = 0x130d;
    const GOST_3410_2012_256_C: DigestFunction = 0x130e;
    const GOST_3410_2012_512_A: DigestFunction = 0x130f;
    const GOST_3410_2012_512_B: DigestFunction = 0x1310;
    const BLS12_381_G1: DigestFunction = 0x1309;
    const BLS12_381_G2: DigestFunction = 0x130a;
    // Provisional multicodec assignment; replace once canonical code is allocated.
    const SM2_PRIV: DigestFunction = 0x1311;
    pub fn decode(digest_function: DigestFunction) -> Result<Algorithm, ParseError> {
        let algorithm = match digest_function {
            ED_25519 => Algorithm::Ed25519,
            SECP_256_K1 => Algorithm::Secp256k1,
            BLS12_381_G1 => Algorithm::BlsNormal,
            BLS12_381_G2 => Algorithm::BlsSmall,
            ML_DSA_DILITHIUM3_SK => Algorithm::MlDsa,
            GOST_3410_2012_256_A => Algorithm::Gost3410_2012_256ParamSetA,
            GOST_3410_2012_256_B => Algorithm::Gost3410_2012_256ParamSetB,
            GOST_3410_2012_256_C => Algorithm::Gost3410_2012_256ParamSetC,
            GOST_3410_2012_512_A => Algorithm::Gost3410_2012_512ParamSetA,
            GOST_3410_2012_512_B => Algorithm::Gost3410_2012_512ParamSetB,
            SM2_PRIV => Algorithm::Sm2,
            _ => return Err(ParseError::Invalid(String::from("No such algorithm"))),
        };
        Ok(algorithm)
    }
    pub fn encode(algorithm: Algorithm) -> u64 {
        match algorithm {
            Algorithm::Ed25519 => ED_25519,
            Algorithm::Secp256k1 => SECP_256_K1,
            Algorithm::MlDsa => ML_DSA_DILITHIUM3_SK,
            Algorithm::Gost3410_2012_256ParamSetA => GOST_3410_2012_256_A,
            Algorithm::Gost3410_2012_256ParamSetB => GOST_3410_2012_256_B,
            Algorithm::Gost3410_2012_256ParamSetC => GOST_3410_2012_256_C,
            Algorithm::Gost3410_2012_512ParamSetA => GOST_3410_2012_512_A,
            Algorithm::Gost3410_2012_512ParamSetB => GOST_3410_2012_512_B,
            Algorithm::BlsNormal => BLS12_381_G1,
            Algorithm::BlsSmall => BLS12_381_G2,
            Algorithm::Sm2 => SM2_PRIV,
        }
    }
}
fn decode_multihash(bytes: &[u8]) -> Result<(DigestFunction, &[u8]), ParseError> {
    // Parse varint-encoded function code
    let idx_fn_end = bytes
        .iter()
        .enumerate()
        .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
        .ok_or_else(|| {
            ParseError::Invalid(String::from("Failed to find end of function code varint"))
        })?
        .0;
    let (fn_varint, rest) = bytes.split_at(idx_fn_end + 1);
    let digest_function: u64 = varint::VarUint::new(fn_varint)
        .map_err(|err| ParseError::Invalid(err.to_string()))?
        .try_into()
        .map_err(|err: varint::ConvertError| ParseError::Invalid(err.to_string()))?;
    // Parse varint-encoded digest length
    let idx_len_end = rest
        .iter()
        .enumerate()
        .find(|&(_, &byte)| (byte & 0b1000_0000) == 0)
        .ok_or_else(|| ParseError::Invalid(String::from("Digest size not found")))?
        .0;
    let (len_varint, payload) = rest.split_at(idx_len_end + 1);
    let digest_size: u64 = varint::VarUint::new(len_varint)
        .map_err(|err| ParseError::Invalid(err.to_string()))?
        .try_into()
        .map_err(|err: varint::ConvertError| ParseError::Invalid(err.to_string()))?;
    if payload.len() as u64 != digest_size {
        return Err(ParseError::Invalid(String::from(
            "Digest size not equal to actual length",
        )));
    }
    Ok((digest_function, payload))
}
#[cfg(test)]
mod tests {
    #[test]
    fn all_canonical_multihash_identities_round_trip_without_backend_selection() {
        let bytes = [0x53; 32];
        for &algorithm in Algorithm::ALL {
            let public = encode_public_key_prefixed(algorithm, &bytes);
            assert_eq!(
                decode_public_key_str(&public).unwrap(),
                (algorithm, bytes.to_vec())
            );
            let bare = public.split_once(':').unwrap().1;
            let decoded = decode_public_key_str_borrowed(bare).unwrap();
            assert_eq!(decoded.algorithm, algorithm);
            let private = encode_private_key_prefixed(algorithm, &bytes);
            assert_eq!(
                decode_private_key_str(&private).unwrap(),
                (algorithm, bytes.to_vec())
            );
        }
    }

    use super::*;
    use crate::hex_decode;
    #[cfg(feature = "sm")]
    use crate::sm::encode_sm2_public_key_payload;
    #[test]
    fn public_key_string_encoding_is_canonical() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4").unwrap();
        assert_eq!(
            format_multihash_hex(digest_function_public::encode(algorithm), &payload),
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
    }
    #[test]
    fn borrowed_public_key_decoder_matches_owned_and_rejects_noncanonical_text() {
        let encoded = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let borrowed = decode_public_key_str_borrowed(encoded).expect("borrowed decode");
        let (algorithm, payload) = decode_public_key_str(encoded).expect("owned decode");
        assert_eq!(borrowed.algorithm, algorithm);
        assert_eq!(
            borrowed.payload_hex,
            "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
        assert_eq!(hex::encode_upper(payload), borrowed.payload_hex);
        for invalid in [
            "ED01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "ed8120001509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "ed01201509a611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "ed25519:ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "secp256k1:ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
        ] {
            assert!(decode_public_key_str_borrowed(invalid).is_none());
        }
    }
    #[cfg(feature = "sm")]
    #[test]
    fn test_encode_sm2_public_key() {
        let algorithm = Algorithm::Sm2;
        let distid = "ALICE123@YAHOO.COM";
        let sec1 = hex_decode("040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857").unwrap();
        let payload = encode_sm2_public_key_payload(distid, &sec1).expect("sm2 payload");
        assert_eq!(
            format_multihash_hex(digest_function_public::encode(algorithm), &payload),
            "8626550012414C494345313233405941484F4F2E434F4D040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857"
        );
    }
    #[test]
    fn test_decode_public_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4").unwrap();
        let multihash =
            hex_decode("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
                .unwrap();
        assert_eq!(decode_public_key(&multihash).unwrap(), (algorithm, payload));
    }
    #[test]
    fn multihash_decoder_borrows_payload() {
        let payload = [1_u8, 2, 3, 4];
        let encoded = hex_decode("ed010401020304").expect("fixture");
        let (_, decoded) = decode_multihash(&encoded).expect("decode multihash");
        assert_eq!(decoded, payload);
        assert_eq!(
            decoded.as_ptr(),
            encoded[encoded.len() - payload.len()..].as_ptr()
        );
    }
    #[test]
    fn multihash_decoder_rejects_truncated_input() {
        assert!(decode_multihash(&[]).is_err());
        assert!(decode_multihash(&[0x01]).is_err());
    }
    #[test]
    fn decode_public_key_str_rejects_non_canonical_hex() {
        let canonical = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let lower = canonical.to_lowercase();
        assert!(decode_public_key_str(&lower).is_err());
        let upper = canonical.to_uppercase();
        assert!(decode_public_key_str(&upper).is_err());
        let prefixed = format!("0x{canonical}");
        assert!(decode_public_key_str(&prefixed).is_err());
    }
    #[test]
    fn borrowed_public_key_hex_rejects_truncated_or_extended_literals() {
        let canonical = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
        let decoded = decode_public_key_str_borrowed(canonical).expect("canonical public key");
        assert_eq!(decoded.algorithm, Algorithm::Ed25519);
        assert_eq!(decoded.payload_hex, &canonical[6..]);
        for length in 0..canonical.len() {
            assert!(
                decode_public_key_str_borrowed(&canonical[..length]).is_none(),
                "truncated literal of {length} bytes"
            );
        }
        for suffix in ["0", "00"] {
            assert!(decode_public_key_str_borrowed(&format!("{canonical}{suffix}")).is_none());
        }
    }
    #[test]
    fn decode_private_key_str_rejects_non_canonical_hex() {
        let canonical = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F";
        let lower = canonical.to_lowercase();
        assert!(decode_private_key_str(&lower).is_err());
    }
    #[test]
    fn private_key_prefixed_string_roundtrip() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F").unwrap();
        let encoded = encode_private_key_prefixed(algorithm, &payload);
        assert_eq!(
            encoded,
            "ed25519:8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
        );
        assert_eq!(
            decode_private_key_str(&encoded).unwrap(),
            (algorithm, payload)
        );
    }
    #[test]
    fn decode_public_key_str_rejects_non_canonical_varint() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xed, 0x01]);
        bytes.extend_from_slice(&[0xa0, 0x00]);
        bytes.extend_from_slice(&[0u8; 32]);
        let input = hex::encode(bytes);
        assert!(decode_public_key_str(&input).is_err());
    }
    #[test]
    fn private_key_string_encoding_is_canonical() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F").unwrap();
        assert_eq!(
            encode_private_key_string(algorithm, &payload),
            "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
        );
    }
    #[test]
    fn test_decode_private_key() {
        let algorithm = Algorithm::Ed25519;
        let payload =
            hex_decode("8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F").unwrap();
        let multihash =
            hex_decode("8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F")
                .unwrap();
        assert_eq!(
            decode_private_key(&multihash).unwrap(),
            (algorithm, payload)
        );
    }
    #[cfg(feature = "gost")]
    #[test]
    fn test_gost_public_key_multihash_roundtrip() {
        let cases = [
            (Algorithm::Gost3410_2012_256ParamSetA, 32usize),
            (Algorithm::Gost3410_2012_256ParamSetB, 32),
            (Algorithm::Gost3410_2012_256ParamSetC, 32),
            (Algorithm::Gost3410_2012_512ParamSetA, 64),
            (Algorithm::Gost3410_2012_512ParamSetB, 64),
        ];
        for (index, (algorithm, len)) in cases.into_iter().enumerate() {
            let mut payload = vec![0u8; len];
            for (offset, byte) in payload.iter_mut().enumerate() {
                *byte = u8::try_from((index + offset) % 256).expect("value fits into u8");
            }
            let encoded = encode_public_key_prefixed(algorithm, &payload);
            let (decoded_alg, decoded_payload) =
                decode_public_key_str(&encoded).expect("decode public key");
            assert_eq!(algorithm, decoded_alg);
            assert_eq!(payload, decoded_payload);
        }
    }
    #[cfg(feature = "gost")]
    #[test]
    fn test_gost_private_key_multihash_roundtrip() {
        let cases = [
            (Algorithm::Gost3410_2012_256ParamSetA, 32usize),
            (Algorithm::Gost3410_2012_256ParamSetB, 32),
            (Algorithm::Gost3410_2012_256ParamSetC, 32),
            (Algorithm::Gost3410_2012_512ParamSetA, 64),
            (Algorithm::Gost3410_2012_512ParamSetB, 64),
        ];
        for (index, (algorithm, len)) in cases.into_iter().enumerate() {
            let mut payload = vec![0u8; len];
            for (offset, byte) in payload.iter_mut().enumerate() {
                *byte = u8::try_from((index * 3 + offset) % 256).expect("value fits into u8");
            }
            let encoded = encode_private_key_prefixed(algorithm, &payload);
            let (decoded_alg, decoded_payload) =
                decode_private_key_str(&encoded).expect("decode private key");
            assert_eq!(algorithm, decoded_alg);
            assert_eq!(payload, decoded_payload);
        }
    }
    #[cfg(feature = "sm")]
    #[test]
    fn test_sm2_public_key_multihash_roundtrip() {
        let algorithm = Algorithm::Sm2;
        let distid = "sm2-multihash-test";
        let mut sec1 = vec![0u8; 65];
        for (idx, byte) in sec1.iter_mut().enumerate() {
            *byte = u8::try_from(idx % 256).expect("value fits into u8");
        }
        let payload =
            crate::sm::encode_sm2_public_key_payload(distid, &sec1).expect("encode SM2 payload");
        let encoded = encode_public_key_prefixed(algorithm, &payload);
        let (decoded_alg, decoded_payload) =
            decode_public_key_str(&encoded).expect("decode sm2 pk");
        assert_eq!(decoded_alg, algorithm);
        assert_eq!(decoded_payload, payload);
    }
}
