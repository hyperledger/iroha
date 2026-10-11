//! Canonical Pasta Fp bytes for final Kaigi authorization outputs.
//!
//! Commitments, nullifiers and action authorizations retain their exact field
//! encoding. These public values do not use Iroha's Blake2b hash marker, field
//! reduction, or a nonzero restriction.

use iroha_schema::IntoSchema;

// Pasta Fp, the base field of Pallas and scalar field of Vesta:
// 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
const PASTA_FP_MODULUS_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

/// One canonical little-endian Pasta Fp output of Kaigi authorization.
///
/// All constructors and decoders reject values at or above the field modulus.
/// Zero is valid; any relation-specific nonzero rule belongs to that relation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1")]
pub struct KaigiAuthorizationScalarV1([u8; 32]);

impl KaigiAuthorizationScalarV1 {
    /// Exact encoded width, without a field-reduction or hash-marker step.
    pub const BYTES: usize = 32;

    /// Check and retain a canonical little-endian Pasta Fp encoding.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; Self::BYTES]) -> Option<Self> {
        (bytes
            .iter()
            .rev()
            .cmp(PASTA_FP_MODULUS_LE.iter().rev())
            .is_lt())
        .then_some(Self(bytes))
    }

    /// Borrow every byte of the validated field encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }

    /// Return the exact canonical bytes supplied at construction.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; Self::BYTES] {
        self.0
    }
}

impl AsRef<[u8; KaigiAuthorizationScalarV1::BYTES]> for KaigiAuthorizationScalarV1 {
    fn as_ref(&self) -> &[u8; Self::BYTES] {
        self.as_bytes()
    }
}

impl norito::core::SerializePayload for KaigiAuthorizationScalarV1 {
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

impl<'de> norito::core::DeserializePayload<'de> for KaigiAuthorizationScalarV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical Kaigi authorization scalar decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::BYTES }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_le_bytes(bytes).ok_or_else(|| {
            norito::core::Error::Message("noncanonical Kaigi authorization Pasta Fp scalar".into())
        })
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for KaigiAuthorizationScalarV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let prefix = bytes
            .get(..Self::BYTES)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut encoded = [0; Self::BYTES];
        encoded.copy_from_slice(prefix);
        let scalar = Self::from_le_bytes(encoded).ok_or_else(|| {
            norito::core::Error::Message("noncanonical Kaigi authorization Pasta Fp scalar".into())
        })?;
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((scalar, Self::BYTES))
    }
}

impl norito::json::FastJsonWrite for KaigiAuthorizationScalarV1 {
    fn write_json(&self, out: &mut String) {
        crate::json_helpers::fixed_bytes::serialize(self.as_bytes(), out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        crate::json_helpers::fixed_bytes::serialize_bounded(self.as_bytes(), out)
    }
}

impl norito::json::JsonDeserialize for KaigiAuthorizationScalarV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        // Fixed storage and exact count: never collect an unbounded JSON array.
        parser.expect(b'[')?;
        let mut bytes = [0; Self::BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            if index != 0 {
                parser.expect(b',')?;
            }
            *byte = <u8 as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        }
        parser.expect(b']')?;
        Self::from_le_bytes(bytes).ok_or_else(|| {
            norito::json::Error::Message("noncanonical Kaigi authorization Pasta Fp scalar".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::{
        codec::{Decode, Encode},
        core::DecodeFromSlice,
    };

    #[test]
    fn construction_preserves_zero_full_width_and_modulus_boundaries() {
        assert_eq!(KaigiAuthorizationScalarV1::default().to_le_bytes(), [0; 32]);
        let mut maximum = PASTA_FP_MODULUS_LE;
        maximum[0] -= 1;
        for bytes in [[0; 32], maximum, [0x24; 32]] {
            let scalar = KaigiAuthorizationScalarV1::from_le_bytes(bytes).unwrap();
            assert_eq!(scalar.to_le_bytes(), bytes);
            assert_eq!(scalar.as_bytes(), &bytes);
            assert_eq!(AsRef::<[u8; 32]>::as_ref(&scalar), &bytes);
        }
        // Changing the bit reserved by Hash is a real field-value change.
        let unmarked = KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap();
        let mut marked = unmarked.to_le_bytes();
        marked[31] |= 1;
        assert_ne!(
            KaigiAuthorizationScalarV1::from_le_bytes(marked),
            Some(unmarked)
        );
        let mut above = PASTA_FP_MODULUS_LE;
        above[0] += 1;
        for bytes in [PASTA_FP_MODULUS_LE, above, [0xff; 32]] {
            assert!(KaigiAuthorizationScalarV1::from_le_bytes(bytes).is_none());
        }
    }

    #[test]
    fn raw_and_framed_norito_reject_noncanonical_and_truncated_scalar_bytes() {
        let bytes = [0x24; 32];
        let scalar = KaigiAuthorizationScalarV1::from_le_bytes(bytes).unwrap();
        assert_eq!(scalar.encode(), bytes);
        assert_eq!(
            KaigiAuthorizationScalarV1::decode(&mut bytes.as_slice()).unwrap(),
            scalar
        );
        let frame = norito::to_bytes(&scalar).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<KaigiAuthorizationScalarV1>(&frame).unwrap(),
            scalar
        );
        let mut suffix = bytes.to_vec();
        suffix.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            KaigiAuthorizationScalarV1::decode_from_slice(&suffix).unwrap(),
            (scalar, 32)
        );
        for length in 0..32 {
            assert!(KaigiAuthorizationScalarV1::decode_from_slice(&bytes[..length]).is_err());
            assert!(KaigiAuthorizationScalarV1::decode(&mut &bytes[..length]).is_err());
        }
        let mut above = PASTA_FP_MODULUS_LE;
        above[0] += 1;
        for invalid in [PASTA_FP_MODULUS_LE, above, [0xff; 32]] {
            assert!(KaigiAuthorizationScalarV1::decode_from_slice(&invalid).is_err());
            assert!(KaigiAuthorizationScalarV1::decode(&mut invalid.as_slice()).is_err());
            // A valid frame checksum must not make an invalid field value legal.
            let frame = norito::to_bytes(&KaigiAuthorizationScalarV1(invalid)).unwrap();
            assert!(norito::decode_from_bytes::<KaigiAuthorizationScalarV1>(&frame).is_err());
        }
    }

    #[test]
    fn json_requires_exact_canonical_byte_array_and_preserves_nested_values() {
        let scalar = KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap();
        let expected = norito::json::to_json(&vec![0x24_u8; 32]).unwrap();
        assert_eq!(norito::json::to_json(&scalar).unwrap(), expected);
        assert_eq!(
            norito::json::to_json_bounded(&scalar, expected.len()).unwrap(),
            expected
        );
        assert!(norito::json::to_json_bounded(&scalar, expected.len() - 1).is_err());
        assert_eq!(
            norito::json::from_str::<KaigiAuthorizationScalarV1>(&expected).unwrap(),
            scalar
        );
        let nested = vec![
            Some(scalar),
            None,
            Some(KaigiAuthorizationScalarV1::default()),
        ];
        let json = norito::json::to_json(&nested).unwrap();
        assert_eq!(
            norito::json::from_str::<Vec<Option<KaigiAuthorizationScalarV1>>>(&json).unwrap(),
            nested
        );
        for invalid in [
            "null".to_owned(),
            "\"00\"".to_owned(),
            "{}".to_owned(),
            norito::json::to_json(&vec![0_u8; 31]).unwrap(),
            norito::json::to_json(&vec![0_u8; 33]).unwrap(),
            norito::json::to_json(&PASTA_FP_MODULUS_LE.to_vec()).unwrap(),
            format!("[256,{}]", vec!["0"; 31].join(",")),
            format!("[-1,{}]", vec!["0"; 31].join(",")),
        ] {
            assert!(
                norito::json::from_str::<KaigiAuthorizationScalarV1>(&invalid).is_err(),
                "{invalid}"
            );
        }
        assert!(
            norito::json::from_str::<KaigiAuthorizationScalarV1>(&format!("{expected} 0")).is_err()
        );
    }
}

#[cfg(test)]
mod kaigi_authorization_scalar_raw_wire_tests {
    use super::*;

    #[test]
    fn kaigi_authorization_scalar_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap();
        let raw = value.to_le_bytes();
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
                let decoded =
                    norito::core::decode_field_canonical::<KaigiAuthorizationScalarV1>(bytes)?;
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
                    norito::core::decode_field_canonical::<KaigiAuthorizationScalarV1>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
