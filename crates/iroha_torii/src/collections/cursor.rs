//! Opaque keyset cursors.
//!
//! A cursor is `base64url(version | collection tag | query digest[16] |
//! canonical JSON array of the last row's sort values)`. Account history may
//! instead use `[public_block_height, null, null]` after completely scanning a
//! block; it never exposes hidden transaction or movement coordinates. The digest binds the
//! collection path (account or asset definition), filter, sort and aggregate
//! so a cursor cannot be replayed against another query; positions are plain keyset values, so cursors never expire and need
//! no server state. A forged position only moves the caller within rows the
//! caller is already allowed to see.
use super::{CollectionError, memory};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_torii_shared::list_query::CURSOR_MAX_BYTES;
use norito::json::{self, JsonSerialize, Value};

const VERSION: u8 = 1;
const HEADER_BYTES: usize = 2 + DIGEST_BYTES;
/// Bytes of the query digest embedded in each cursor.
pub(super) const DIGEST_BYTES: usize = 16;

/// Borrowed key values encoded directly into the checked cursor frame.
struct CursorKeyValues<'a, T>(&'a [T]);

impl<T: JsonSerialize> json::FastJsonWrite for CursorKeyValues<'_, T> {
    fn write_json(&self, output: &mut String) {
        json::write_json_unbounded(self, output);
    }

    fn write_json_to(
        &self,
        output: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push('[')?;
            for (index, value) in self.0.iter().enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                value.json_serialize_to(output)?;
            }
            output.push(']')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}

/// Why a cursor was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CursorError {
    /// Not a cursor produced by this server.
    Malformed,
    /// Produced for another collection.
    OtherCollection,
    /// Produced for another path, filter, sort or aggregate.
    OtherQuery,
}

impl CursorError {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::Malformed => "`cursor` is not a `next_cursor` value returned by this endpoint",
            Self::OtherCollection => "`cursor` was issued by a different collection",
            Self::OtherQuery => {
                "`cursor` was issued for a different path, filter, sort or aggregate; repeat the original query or start without a cursor"
            }
        }
    }
}

/// Digest of the order-defining parts of a query.
pub(super) fn digest(
    parts: &[&str],
    max_bytes: usize,
) -> Result<[u8; DIGEST_BYTES], CollectionError> {
    let length = parts
        .iter()
        .try_fold(0, |sum, part| memory::add(sum, memory::add(8, part.len())?))?;
    let mut material = memory::vector(length, max_bytes, "query digest")?;
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    let hash = iroha_crypto::Hash::new(&material);
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(&hash.as_ref()[..DIGEST_BYTES]);
    Ok(out)
}

/// Encode the keyset position after a row.
pub(super) fn encode<T: JsonSerialize>(
    tag: u8,
    digest: &[u8; DIGEST_BYTES],
    key: &[T],
    scratch_bytes: usize,
) -> Result<String, CollectionError> {
    let frame_limit = CURSOR_MAX_BYTES / 4 * 3;
    let key_json = json::to_json_bounded_boxed(
        &CursorKeyValues(key),
        (frame_limit - HEADER_BYTES).min(scratch_bytes),
    )
    .map_err(|_| {
        CollectionError::new(
            "invalid_sort",
            "sort",
            "a row's sort values exceed the cursor byte bound",
        )
        .with_hint("sort by fields with shorter values")
    })?;
    let frame_len = memory::add(HEADER_BYTES, key_json.len())?;
    memory::ensure(
        memory::add(key_json.len(), frame_len)?,
        scratch_bytes,
        "cursor JSON and frame",
    )?;
    let mut frame = memory::vector(frame_len, frame_limit, "cursor frame")?;
    frame.push(VERSION);
    frame.push(tag);
    frame.extend_from_slice(digest);
    frame.extend_from_slice(&key_json);
    drop(key_json);
    let encoded_len =
        base64::encoded_len(frame_len, false).ok_or_else(|| memory::capacity("cursor encoding"))?;
    memory::ensure(
        memory::add(frame_len, encoded_len)?,
        scratch_bytes,
        "cursor frame and encoding",
    )?;
    let mut encoded = memory::vector(encoded_len, CURSOR_MAX_BYTES, "cursor encoding")?;
    encoded.resize(encoded_len, 0);
    let written = URL_SAFE_NO_PAD
        .encode_slice(frame, &mut encoded)
        .map_err(|_| memory::capacity("cursor encoding"))?;
    debug_assert_eq!(written, encoded_len);
    String::from_utf8(encoded).map_err(|_| memory::capacity("cursor encoding"))
}

/// Decode a keyset position, checking that it belongs to this query.
pub(super) fn decode(
    cursor: &str,
    tag: u8,
    digest: &[u8; DIGEST_BYTES],
    arity: usize,
    allocation_bytes: usize,
) -> Result<Vec<Value>, CursorError> {
    if cursor.is_empty() || cursor.len() > CURSOR_MAX_BYTES {
        return Err(CursorError::Malformed);
    }
    let frame = URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .map_err(|_| CursorError::Malformed)?;
    if frame.len() < HEADER_BYTES || frame[0] != VERSION {
        return Err(CursorError::Malformed);
    }
    if frame[1] != tag {
        return Err(CursorError::OtherCollection);
    }
    if frame[2..HEADER_BYTES] != digest[..] {
        return Err(CursorError::OtherQuery);
    }
    let key_json = &frame[HEADER_BYTES..];
    let limits = norito::DecodeLimits::new(
        key_json.len(),
        allocation_bytes,
        allocation_bytes,
        allocation_bytes,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );
    json::preflight_slice(
        key_json,
        json::JsonPreflightLimits::from_decode_limits(key_json.len(), limits),
    )
    .map_err(|_| CursorError::Malformed)?;
    let (values, usage) = norito::core::with_decode_limits_measured(limits, || {
        json::from_slice::<Vec<Value>>(key_json)
    });
    match values {
        Ok(values)
            if values.len() == arity && usage.total_allocated_bytes() <= allocation_bytes =>
        {
            let charge = values
                .iter()
                .try_fold(
                    memory::slots::<Value>(values.capacity())
                        .map_err(|_| CursorError::Malformed)?,
                    |sum, value| memory::add(sum, memory::value_heap_bytes(value)?),
                )
                .map_err(|_| CursorError::Malformed)?;
            if charge > allocation_bytes {
                return Err(CursorError::Malformed);
            }
            Ok(values)
        }
        _ => Err(CursorError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_cursor_keys_preserve_json_and_exact_byte_limit() {
        let values = [Value::from("quoted \""), Value::from(7_u64), Value::Null];
        let key = CursorKeyValues(&values);
        let expected = json::to_json(&Value::Array(values.to_vec())).unwrap();
        assert_eq!(json::to_json(&key).unwrap(), expected);
        assert_eq!(
            json::to_json_bounded_boxed(&key, expected.len())
                .unwrap()
                .as_ref(),
            expected.as_bytes()
        );
        assert!(json::to_json_bounded_boxed(&key, expected.len() - 1).is_err());
        assert_eq!(json::to_json(&CursorKeyValues::<Value>(&[])).unwrap(), "[]");
    }

    #[test]
    fn roundtrip_and_binding() {
        let digest = digest(&["domains", "id = 1", ""], 1024).unwrap();
        let key = vec![Value::from("wonderland"), Value::from(7u64)];
        let cursor = encode(1, &digest, &key, 16 * 1024).unwrap();
        assert!(
            cursor
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(
            decode(&cursor, 1, &digest, 2, 16 * 1024).expect("decode"),
            key
        );
        assert_eq!(
            decode(&cursor, 2, &digest, 2, 16 * 1024),
            Err(CursorError::OtherCollection)
        );
        let other = super::digest(&["domains", "id = 2", ""], 1024).unwrap();
        assert_eq!(
            decode(&cursor, 1, &other, 2, 16 * 1024),
            Err(CursorError::OtherQuery)
        );
        assert_eq!(
            decode(&cursor, 1, &digest, 3, 16 * 1024),
            Err(CursorError::Malformed)
        );
        assert_eq!(
            decode("not-a-cursor", 1, &digest, 2, 16 * 1024),
            Err(CursorError::Malformed)
        );
        assert_eq!(
            decode("", 1, &digest, 2, 16 * 1024),
            Err(CursorError::Malformed)
        );
    }

    #[test]
    fn cursor_encoder_charges_frame_and_base64_overlap_at_exact_boundary() {
        let digest = digest(&["domains", "", ""], 1024).unwrap();
        let key = [Value::from("alpha")];
        // ["alpha"] is nine bytes; the 18-byte header yields a 27-byte
        // frame and its unpadded base64 output is 36 bytes. They coexist.
        let token = encode(1, &digest, &key, 63).unwrap();
        assert_eq!(token.len(), 36);
        assert_eq!(decode(&token, 1, &digest, 1, 1024).unwrap(), key);
        assert_eq!(
            encode(1, &digest, &key, 62).unwrap_err().code,
            "query_capacity_exceeded"
        );
    }

    #[test]
    fn bounded_cursor_preserves_wire_and_refuses_nested_expansion() {
        let digest = digest(&["domains", "metadata.key", ""], 1024).unwrap();
        let key = vec![
            Value::from("quoted \\\""),
            norito::json!({"nested":[1,null,true]}),
        ];
        let key_json = json::to_json(&Value::Array(key.clone())).unwrap();
        let mut frame = vec![VERSION, 1];
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(key_json.as_bytes());
        let token = encode(1, &digest, &key, 16 * 1024).unwrap();
        assert_eq!(token, URL_SAFE_NO_PAD.encode(frame));
        assert_eq!(decode(&token, 1, &digest, 2, 16 * 1024).unwrap(), key);
        let dense = vec![Value::Array(vec![Value::Null; 100])];
        let token = encode(1, &digest, &dense, 16 * 1024).unwrap();
        assert_eq!(
            decode(&token, 1, &digest, 1, 256),
            Err(CursorError::Malformed)
        );
        let huge = vec![Value::Array(vec![Value::Null; CURSOR_MAX_BYTES])];
        assert_eq!(
            encode(1, &digest, &huge, 16 * 1024).unwrap_err().code,
            "invalid_sort"
        );
    }

    #[test]
    fn digest_separates_parts() {
        assert_ne!(
            digest(&["ab", "c"], 1024).unwrap(),
            digest(&["a", "bc"], 1024).unwrap()
        );
    }
}

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{RefusingLeaf, audit, byte_refusal, error};
    use norito::json::{BoundedJsonError, FastJsonWrite};

    #[test]
    fn original_cursor_keys_keep_borrowed_non_fast_leaf_and_refusal_depth() {
        let values = [1_u64, 7];
        let source = CursorKeyValues(&values);
        audit("[1,7]", |sink| source.write_json_to(sink));
        assert_eq!(source.0.as_ptr(), values.as_ptr());
        let values = [RefusingLeaf {
            visits: std::cell::Cell::new(0),
        }];
        let source = CursorKeyValues(&values);
        byte_refusal(|sink| source.write_json_to(sink));
        assert_eq!(values[0].visits.get(), 0);
        error(BoundedJsonError::Unsupported, |sink| {
            source.write_json_to(sink)
        });
        assert_eq!(values[0].visits.get(), 1);
    }
}
