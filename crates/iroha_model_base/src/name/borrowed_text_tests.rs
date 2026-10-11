//! Owned/borrowed nominal framing, exact NFC and decode-allocation parity.

use super::*;
use crate::state_path::StatePath;
use norito::core::{
    DecodeFlagsGuard, DecodeLimits, NominalText, borrow_canonical_text, default_encode_flags,
    frame_bare_with_header_flags, serialize_to_buffer, supported_header_flags,
    validate_header_flags, with_decode_limits_measured,
};

fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn frame<T: NominalText>(raw: &str) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(default_encode_flags());
    let mut payload = Vec::new();
    serialize_to_buffer(&raw, &mut payload).unwrap();
    frame_bare_with_header_flags::<T>(&payload, default_encode_flags()).unwrap()
}

fn layout_parity<T>(value: &T)
where
    T: NominalText + AsRef<str>,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let canonical = norito::encode_canonical(value).unwrap();
    assert_eq!(
        borrow_canonical_text::<T>(&canonical).unwrap(),
        value.as_ref()
    );
    for flags in 0..=supported_header_flags() {
        if validate_header_flags(flags).is_err() {
            continue;
        }
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = norito::to_bytes(value).unwrap();
        let owned = norito::decode_canonical::<T>(&bytes);
        let borrowed = borrow_canonical_text::<T>(&bytes);
        assert_eq!(owned.is_ok(), bytes == canonical, "owned flags {flags}");
        assert_eq!(borrowed.is_ok(), owned.is_ok(), "borrowed flags {flags}");
        if let (Ok(owned), Ok(borrowed)) = (owned, borrowed) {
            assert_eq!(owned.as_ref(), borrowed);
        }
    }
    let mut shifted = vec![0];
    shifted.extend_from_slice(&canonical);
    let borrowed = borrow_canonical_text::<T>(&shifted[1..]).unwrap();
    let payload_offset = borrowed.as_ptr() as usize - shifted.as_ptr() as usize;
    assert_eq!(borrowed, value.as_ref());
    assert_eq!(borrowed.as_ptr(), shifted[payload_offset..].as_ptr());
}

#[test]
fn nominal_models_preserve_all_layout_flags_identity_and_unaligned_borrowing() {
    for raw in ["Map", "é", "q\u{301}"] {
        layout_parity(&raw.parse::<Name>().unwrap());
        layout_parity(&raw.parse::<StatePath>().unwrap());
    }
    layout_parity(&"q\u{301}".repeat(4096).parse::<StatePath>().unwrap());
    let name = frame::<Name>("Map");
    let path = frame::<StatePath>("Map");
    assert!(matches!(
        borrow_canonical_text::<Name>(&path),
        Err(NoritoError::SchemaMismatch)
    ));
    assert!(matches!(
        borrow_canonical_text::<StatePath>(&name),
        Err(NoritoError::SchemaMismatch)
    ));
}

#[test]
fn borrowed_semantic_validation_matches_owned_rejection_without_rewriting() {
    for raw in [
        String::new(),
        "valid".to_owned(),
        "é".to_owned(),
        "e\u{301}".to_owned(),
        "a\0b".to_owned(),
        "a@b".to_owned(),
        "a\u{202e}b".to_owned(),
        "x".repeat(MAX_NAME_BYTES + 1),
        "x".repeat(crate::state_path::MAX_STATE_PATH_BYTES + 1),
    ] {
        let name = frame::<Name>(&raw);
        let owned = norito::decode_canonical::<Name>(&name);
        let view = borrow_canonical_text::<Name>(&name);
        let accepted = view.is_ok_and(|text| Name::validate_canonical(text).is_ok());
        assert_eq!(accepted, owned.is_ok(), "Name {raw:?}");
        let path = frame::<StatePath>(&raw);
        let owned = norito::decode_canonical::<StatePath>(&path);
        let view = borrow_canonical_text::<StatePath>(&path);
        let accepted = view.is_ok_and(|text| StatePath::validate_canonical(text).is_ok());
        assert_eq!(accepted, owned.is_ok(), "StatePath {raw:?}");
    }
}

fn decode_scratch<T>(raw: &str, scratch: usize)
where
    T: AsRef<str>,
    for<'de> T: DecodeFromSlice<'de>,
{
    let _flags = DecodeFlagsGuard::enter(default_encode_flags());
    let mut payload = Vec::new();
    serialize_to_buffer(&raw, &mut payload).unwrap();
    let demand = raw.len() + scratch;
    assert!(scratch > 0);
    let (refused, usage) =
        with_decode_limits_measured(limits(demand - 1), || T::decode_from_slice(&payload));
    assert!(matches!(
        refused,
        Err(NoritoError::TotalAllocationExceeded { .. })
    ));
    assert_eq!(
        usage.total_allocated_bytes(),
        raw.len(),
        "NFC admission refuses before its first allocation"
    );
    let (retried, usage) =
        with_decode_limits_measured(limits(demand), || T::decode_from_slice(&payload));
    let (decoded, consumed) = retried.expect("exact original demand");
    assert_eq!(decoded.as_ref(), raw);
    assert_eq!(consumed, payload.len());
    assert_eq!(usage.total_allocated_bytes(), demand);
}

#[test]
fn binary_name_and_long_path_charge_nfc_scratch_before_owned_validation() {
    let name = format!("q{}", "\u{301}".repeat(100));
    decode_scratch::<Name>(&name, Name::canonical_validation_scratch_bytes(&name));
    let path = format!("\u{1e08}{}", "\u{323}".repeat(1200)).repeat(6);
    decode_scratch::<StatePath>(&path, StatePath::canonical_validation_scratch_bytes(&path));
    let value = norito::json::Value::String(path.clone());
    let scratch = StatePath::canonical_validation_scratch_bytes(&path);
    let (refused, usage) = with_decode_limits_measured(limits(scratch - 1), || {
        <StatePath as norito::json::JsonDeserialize>::json_from_value(&value)
    });
    assert!(matches!(
        refused,
        Err(norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
    let (retried, usage) = with_decode_limits_measured(limits(scratch + path.len()), || {
        <StatePath as norito::json::JsonDeserialize>::json_from_value(&value)
    });
    assert_eq!(retried.unwrap().as_ref(), path);
    assert_eq!(usage.total_allocated_bytes(), scratch + path.len());
}

type JsonKeyDecoder<T> = fn(&str) -> Result<T, norito::json::Error>;

fn json_key_scratch<T>(raw: &str, scratch: usize)
where
    T: AsRef<str> + norito::json::JsonKeyCodec + norito::json::JsonObjectKeyOwned,
{
    let decoders: [JsonKeyDecoder<T>; 2] = [
        <T as norito::json::JsonKeyCodec>::decode_json_key,
        <T as norito::json::JsonObjectKeyOwned>::from_json_key_text,
    ];
    for decode in decoders {
        for (capacity, charged) in [(scratch - 1, 0), (scratch + raw.len() - 1, scratch)] {
            let (refused, usage) = with_decode_limits_measured(limits(capacity), || decode(raw));
            assert!(matches!(
                refused,
                Err(norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                ))
            ));
            assert_eq!(usage.total_allocated_bytes(), charged);
        }
        let (retried, usage) =
            with_decode_limits_measured(limits(scratch + raw.len()), || decode(raw));
        assert_eq!(retried.expect("original JSON-key demand").as_ref(), raw);
        assert_eq!(usage.total_allocated_bytes(), scratch + raw.len());
    }
}

#[test]
fn both_public_json_key_decoders_keep_exact_nfc_and_retained_text_admission() {
    let name = format!("q{}", "\u{301}".repeat(100));
    json_key_scratch::<Name>(&name, Name::canonical_validation_scratch_bytes(&name));
    let path = format!("\u{1e08}{}", "\u{323}".repeat(1200)).repeat(6);
    json_key_scratch::<StatePath>(&path, StatePath::canonical_validation_scratch_bytes(&path));
}

fn archived_context_errors<T>()
where
    T: NominalText,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let _flags = DecodeFlagsGuard::enter(default_encode_flags());
    let mut payload = Vec::new();
    serialize_to_buffer(&"a".repeat(64), &mut payload).unwrap();
    let archived = norito::core::archived_from_slice::<T>(&payload).unwrap();
    // The guard restores the caller's prior context after both error probes.
    let _context = norito::core::PayloadCtxGuard::enter(&[]);
    assert!(matches!(
        T::try_deserialize(&archived),
        Err(NoritoError::LengthMismatch)
    ));
    norito::core::clear_payload_ctx();
    assert!(matches!(
        T::try_deserialize(&archived),
        Err(NoritoError::MissingPayloadContext)
    ));
}

#[test]
fn archived_nominal_decoders_reject_missing_or_foreign_context_without_fallback() {
    archived_context_errors::<Name>();
    archived_context_errors::<StatePath>();
}
