//! Bounded, canonical continuation records for live durable-map pagination.
use iroha_schema::IntoSchema;
use norito::{Decode, Encode};

use iroha_model_base::{name::Name, state_path::StatePath};

/// Maximum canonical encoded durable-map key record size.
pub const MAX_STATE_MAP_KEY_BYTES_V1: usize = 4096;
/// Maximum complete canonical Norito cursor frame accepted by V1 boundaries.
pub const MAX_STATE_CURSOR_BYTES_V1: usize = 64 * 1024;
/// Maximum UTF-8 byte length of the host-provided contract instance identity.
pub const MAX_STATE_CURSOR_INSTANCE_BYTES_V1: usize = 1024;
/// Domain separating the complete durable-map schema bound into a cursor.
pub const STATE_CURSOR_SCHEMA_HASH_DOMAIN_V1: &[u8] = b"KOTODAMA_STATE_MAP_CURSOR_SCHEMA_V1\0";

/// Opaque continuation position in the current contents of one durable map.
///
/// This is a position, not an authorization token or a snapshot. A host must bind the instance,
/// map, complete map schema, and canonical encoded key before using the continuation.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::smart_contract::state_cursor::StateCursorV1")]
pub struct StateCursorV1 {
    /// Exact host-provided contract instance identity.
    pub instance: String,
    /// Bare durable map name.
    pub map: StatePath,
    /// Hash of the complete key/value map schema.
    pub schema_hash: [u8; 32],
    /// Domain-separated hash of the complete scalar or tuple key schema.
    pub key_schema_hash: [u8; 32],
    /// Last examined canonical map path, resumed strictly after this key.
    pub last_key: StatePath,
}

impl StateCursorV1 {
    /// Check the bounded structural contract without granting access to any map.
    #[must_use]
    pub fn validate(&self) -> bool {
        let map = self.map.as_ref();
        if self.instance.is_empty()
            || self.instance.len() > MAX_STATE_CURSOR_INSTANCE_BYTES_V1
            || map.len() > 255
            || map.contains('/')
            || map.parse::<Name>().is_err()
        {
            return false;
        }
        let Some(hex) = self
            .last_key
            .as_ref()
            .strip_prefix(map)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            return false;
        };
        !hex.is_empty()
            && hex.len() <= MAX_STATE_MAP_KEY_BYTES_V1 * 2
            && hex.len().is_multiple_of(2)
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    /// Encode a structurally valid cursor using the canonical V1 Norito frame.
    ///
    /// # Errors
    /// Returns an error for an invalid cursor or a frame exceeding the V1 byte bound.
    pub fn encode_frame(&self) -> Result<Vec<u8>, norito::Error> {
        if !self.validate() {
            return Err(norito::Error::Message("invalid V1 state cursor".into()));
        }
        let frame = norito::encode_canonical(self)?;
        if frame.len() > MAX_STATE_CURSOR_BYTES_V1 {
            return Err(norito::Error::Message(
                "V1 state cursor exceeds 64 KiB".into(),
            ));
        }
        Ok(frame)
    }

    /// Decode one bounded canonical frame and enforce the structural cursor contract.
    ///
    /// # Errors
    /// Returns an error for an oversized, noncanonical, malformed, or structurally invalid cursor.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, norito::Error> {
        if frame.len() > MAX_STATE_CURSOR_BYTES_V1 {
            return Err(norito::Error::Message(
                "V1 state cursor exceeds 64 KiB".into(),
            ));
        }
        let cursor: Self = norito::decode_canonical_with_limits(
            frame,
            norito::core::DecodeLimits::new(
                MAX_STATE_CURSOR_BYTES_V1,
                MAX_STATE_CURSOR_BYTES_V1,
                MAX_STATE_CURSOR_BYTES_V1,
                MAX_STATE_CURSOR_BYTES_V1 * 8,
                16,
            ),
        )?;
        if !cursor.validate() {
            return Err(norito::Error::Message("invalid V1 state cursor".into()));
        }
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> StateCursorV1 {
        StateCursorV1 {
            instance: "example::金庫".into(),
            map: "balances".parse().unwrap(),
            schema_hash: [7; 32],
            key_schema_hash: [3; 32],
            last_key: "balances/0010abcdef".parse().unwrap(),
        }
    }

    #[test]
    fn canonical_frame_roundtrips_and_rejects_trailing_or_oversized_bytes() {
        let expected = cursor();
        let mut frame = expected.encode_frame().unwrap();
        assert_eq!(StateCursorV1::decode_frame(&frame).unwrap(), expected);
        frame.push(0);
        assert!(StateCursorV1::decode_frame(&frame).is_err());
        assert!(StateCursorV1::decode_frame(&vec![0; MAX_STATE_CURSOR_BYTES_V1 + 1]).is_err());
    }

    #[test]
    fn structural_utf8_and_path_limits_are_inclusive() {
        let mut boundary = cursor();
        boundary.instance = format!("{}x", "界".repeat(341));
        assert_eq!(boundary.instance.len(), MAX_STATE_CURSOR_INSTANCE_BYTES_V1);
        let map = "a".repeat(255);
        boundary.map = map.parse().unwrap();
        boundary.last_key = format!("{map}/{}", "ab".repeat(MAX_STATE_MAP_KEY_BYTES_V1))
            .parse()
            .unwrap();
        assert_eq!(
            boundary.last_key.as_ref().len(),
            256 + MAX_STATE_MAP_KEY_BYTES_V1 * 2
        );
        let frame = boundary.encode_frame().unwrap();
        assert!(frame.len() <= MAX_STATE_CURSOR_BYTES_V1);
        assert_eq!(StateCursorV1::decode_frame(&frame).unwrap(), boundary);
        boundary.instance.push('x');
        assert!(!boundary.validate());
        boundary = cursor();
        boundary.map = "a".repeat(256).parse().unwrap();
        assert!(!boundary.validate());
    }

    #[test]
    fn cursor_frames_reject_alternate_layout_and_ignore_ambient_flags() {
        let value = cursor();
        let canonical = value.encode_frame().unwrap();
        let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(flags);
        let alternative = norito::to_bytes(&value).unwrap();
        assert_ne!(alternative, canonical);
        assert!(StateCursorV1::decode_frame(&alternative).is_err());
        assert_eq!(value.encode_frame().unwrap(), canonical);
        assert_eq!(StateCursorV1::decode_frame(&canonical).unwrap(), value);
        assert_eq!(norito::to_bytes(&value).unwrap(), alternative);
    }

    #[test]
    fn validation_rejects_wrong_map_noncanonical_hex_and_oversized_key() {
        for path in [
            "other/00",
            "balances/AB",
            "balances/0",
            "balances/",
            "balances/00/11",
        ] {
            let mut invalid = cursor();
            invalid.last_key = path.parse().unwrap();
            assert!(!invalid.validate(), "{path}");
            assert!(
                StateCursorV1::decode_frame(&norito::encode_canonical(&invalid).unwrap()).is_err()
            );
        }
        let mut invalid = cursor();
        invalid.instance.clear();
        assert!(!invalid.validate());
        invalid.instance = "a".repeat(MAX_STATE_CURSOR_INSTANCE_BYTES_V1 + 1);
        assert!(!invalid.validate());
        invalid = cursor();
        invalid.last_key = format!("balances/{}", "ab".repeat(MAX_STATE_MAP_KEY_BYTES_V1 + 1))
            .parse()
            .unwrap();
        assert!(invalid.encode_frame().is_err());
        invalid = cursor();
        invalid.map = "balances/child".parse().unwrap();
        assert!(!invalid.validate());
    }
}

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<super::StateCursorV1>(
            "iroha_data_model::smart_contract::state_cursor::StateCursorV1",
        );
    }
}
