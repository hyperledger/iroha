//! Regression tests covering truncated and tampered Norito decode inputs.
use norito::core::{self, Error};
#[test]
fn aos_bytes_decode_truncation() {
    let rows = vec![(42u64, b"abc".as_slice(), true)];
    let payload = norito::aos::encode_rows_u64_bytes_bool(&rows);
    let mut truncated = payload.clone();
    truncated.pop();
    let err = norito::aos::decode_rows_u64_bytes_bool(&truncated).expect_err("should fail");
    assert!(matches!(err, Error::LengthMismatch | Error::Message(_)));
}
#[cfg(feature = "columnar")]
#[test]
fn ncb_str_view_truncation_and_offset_tamper() {
    let rows = vec![(1u64, "alice", true), (2u64, "bob", false)];
    let payload = norito::columnar::encode_ncb_u64_str_bool(&rows);
    // Truncate the final byte and ensure the view rejects it.
    let mut truncated = payload.clone();
    truncated.pop();
    let err = norito::columnar::view_ncb_u64_str_bool(&truncated)
        .err()
        .expect("truncation");
    assert!(matches!(err, Error::LengthMismatch));
    // Tamper with the string offsets to point past the end of the blob.
    let mut tampered = payload.clone();
    let n = rows.len();
    let desc = tampered[4];
    let mut off = 5usize;
    // Align to 8 before id column.
    if off & 7 != 0 {
        off += 8 - (off & 7);
    }
    match desc {
        // Plain ids are stored as `[u64; n]`.
        0x13 => {
            off += 8 * n;
        }
        // Delta-coded ids store the first id verbatim then varint zigzag deltas.
        0x53 => {
            off += 8;
            let mut cursor = off;
            for _ in 1..n {
                // Skip little-endian varint continuation bytes (max 10 for u64).
                loop {
                    let byte = *tampered
                        .get(cursor)
                        .expect("varint delta should stay within payload");
                    cursor += 1;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
            }
            off = cursor;
        }
        other => panic!("unexpected descriptor: {other:#x}"),
    }
    // Align to 4 and locate the offsets table.
    if off & 3 != 0 {
        off += 4 - (off & 3);
    }
    let offs_start = off;
    // Original last offset is the blob length; push it forward by 4 bytes.
    let last_off_pos = offs_start + 4 * n;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&tampered[last_off_pos..last_off_pos + 4]);
    let bumped = u32::from_le_bytes(buf).saturating_add(4);
    tampered[last_off_pos..last_off_pos + 4].copy_from_slice(&bumped.to_le_bytes());
    let err = norito::columnar::view_ncb_u64_str_bool(&tampered)
        .err()
        .expect("tamper");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn header_decode_accepts_payload_at_any_address() {
    let value = vec![1_u64, 2, 3, 5, 8];
    let bytes = norito::to_bytes(&value).expect("encode header payload");
    let mut padded = Vec::with_capacity(bytes.len() + 1);
    padded.push(0xAA);
    padded.extend_from_slice(&bytes);
    // The wire padding is unchanged; only the buffer address differs.
    let shifted = &padded[1..padded.len()];
    let archived = core::from_bytes::<Vec<u64>>(shifted).expect("address-independent frame");
    let decoded = <Vec<u64> as norito::DeserializePayload>::try_deserialize(archived)
        .expect("decode shifted payload");
    assert_eq!(decoded, value);
    core::reset_decode_state();
}
