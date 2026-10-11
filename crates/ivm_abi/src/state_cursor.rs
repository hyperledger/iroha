//! Exact pointer-boundary validation for opaque durable-map cursors.
use iroha_data_model::smart_contract::state_cursor::StateCursorV1;

use crate::{
    VMError,
    pointer_abi::{self, PointerType},
};

/// Validate an exact NoritoBytes envelope and its canonical, key-bound cursor frame.
///
/// # Errors
/// Returns an error for a malformed envelope, cursor, or mismatched complete key schema.
pub fn validate_cursor_envelope(
    key_schema_hash: [u8; 32],
    envelope: &[u8],
) -> Result<StateCursorV1, VMError> {
    let tlv = pointer_abi::validate_tlv_bytes(envelope)?;
    if tlv.type_id != PointerType::NoritoBytes {
        return Err(VMError::NoritoInvalid);
    }
    let cursor = StateCursorV1::decode_frame(tlv.payload).map_err(|_| VMError::NoritoInvalid)?;
    if cursor.key_schema_hash != key_schema_hash {
        return Err(VMError::NoritoInvalid);
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn envelope(kind: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut out = (kind as u16).to_be_bytes().to_vec();
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
        out
    }
    #[test]
    fn rejects_mismatched_kind_and_non_cursor_envelopes() {
        let cursor = StateCursorV1 {
            instance: "local::test".into(),
            map: "balances".parse().unwrap(),
            schema_hash: [0; 32],
            key_schema_hash: [1; 32],
            last_key: "balances/00".parse().unwrap(),
        };
        let payload = cursor.encode_frame().unwrap();
        let frame = envelope(PointerType::NoritoBytes, &payload);
        assert_eq!(validate_cursor_envelope([1; 32], &frame).unwrap(), cursor);
        assert!(validate_cursor_envelope([2; 32], &frame).is_err());
        let wrong = envelope(PointerType::Blob, &payload);
        assert!(validate_cursor_envelope([1; 32], &wrong).is_err());
    }
}
