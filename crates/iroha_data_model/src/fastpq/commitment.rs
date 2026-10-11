//! Exact raw SHA3-256 commitment wire owner for the compact FASTPQ candidate.
//!
//! This type has no field-element interpretation or Iroha hash marker. Its
//! addition does not change a production proof DTO or advertise qualification.

use iroha_schema::IntoSchema;

/// Opaque SHA3-256 commitment encoded as exactly 32 raw Norito payload bytes.
#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqCommitmentV1")]
pub struct FastpqCommitmentV1([u8; 32]);

impl FastpqCommitmentV1 {
    /// Exact fixed payload length, independent of Norito layout flags.
    pub const BYTES: usize = 32;
    /// Preserve every SHA3 output bit; there is no canonical field-word filter.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::BYTES]) -> Self {
        Self(bytes)
    }
    /// Borrow the fixed opaque output in SHA3 byte order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }
    /// Consume the public commitment without changing its representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::BYTES] {
        self.0
    }
    /// Convert to the shared primitive digest without field reduction.
    #[must_use]
    pub const fn as_fastpq(self) -> fastpq_isi::keccak256::Sha3Digest256V1 {
        fastpq_isi::keccak256::Sha3Digest256V1::from_bytes(self.0)
    }
}
impl From<fastpq_isi::keccak256::Sha3Digest256V1> for FastpqCommitmentV1 {
    fn from(digest: fastpq_isi::keccak256::Sha3Digest256V1) -> Self {
        Self(digest.into_bytes())
    }
}
impl norito::core::SerializePayload for FastpqCommitmentV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}
impl<'de> norito::core::DeserializePayload<'de> for FastpqCommitmentV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical FASTPQ commitment decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::BYTES }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Ok(Self(bytes))
    }
}
impl<'de> norito::core::DecodeFromSlice<'de> for FastpqCommitmentV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let raw = bytes
            .get(..Self::BYTES)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut digest = [0; Self::BYTES];
        digest.copy_from_slice(raw);
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((Self(digest), Self::BYTES))
    }
}
impl norito::json::FastJsonWrite for FastpqCommitmentV1 {
    fn write_json(&self, out: &mut String) {
        crate::json_helpers::fixed_bytes::serialize(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        crate::json_helpers::fixed_bytes::serialize_bounded(&self.0, out)
    }
}
impl norito::json::JsonDeserialize for FastpqCommitmentV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        crate::json_helpers::fixed_bytes::deserialize(parser).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_all_bit_patterns_roundtrip_exact_32_byte_payloads() {
        for bytes in [[0; 32], [0xff; 32], [0x80; 32]] {
            let value = FastpqCommitmentV1::from_bytes(bytes);
            assert_eq!(value.as_fastpq().into_bytes(), bytes);
            assert_eq!(FastpqCommitmentV1::from(value.as_fastpq()), value);
            assert_eq!(value.as_bytes(), &bytes);
            assert_eq!(value.into_bytes(), bytes);
            for flags in
                (u8::MIN..=u8::MAX).filter(|&f| norito::core::validate_header_flags(f).is_ok())
            {
                let _flags = norito::core::DecodeFlagsGuard::enter(flags);
                let encoded = norito::codec::encode_with_header_flags(&value).0;
                assert_eq!(encoded, bytes);
                let (decoded, consumed) =
                    norito::core::decode_field_canonical::<FastpqCommitmentV1>(&encoded).unwrap();
                assert_eq!(decoded, value);
                assert_eq!(consumed, 32);
            }
            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(
                norito::json::from_str::<FastpqCommitmentV1>(&json).unwrap(),
                value
            );
        }
    }
    #[test]
    fn exact_field_decoder_rejects_truncation_and_extra_bytes() {
        for length in [0, 1, 31, 33, 48] {
            assert!(
                norito::core::decode_field_canonical::<FastpqCommitmentV1>(&vec![0xff; length])
                    .is_err()
            );
        }
        let bytes = [0xff; 33];
        let (value, consumed) =
            <FastpqCommitmentV1 as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
                .unwrap();
        assert_eq!(value.into_bytes(), [0xff; 32]);
        assert_eq!(
            consumed, 32,
            "slice decoder explicitly reports its exact prefix to the enclosing codec"
        );
    }
}

#[cfg(test)]
mod fastpq_commitment_raw_wire_tests {
    use super::*;

    #[test]
    fn fastpq_commitment_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = FastpqCommitmentV1::from_bytes([0xff; 32]);
        let raw = value.into_bytes();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded = norito::core::decode_field_canonical::<FastpqCommitmentV1>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<FastpqCommitmentV1>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
