//! Canonical signed RS16 geometry for global and lane consensus instances.
//!
//! This owns layout validation and the single genesis-builder profile. Transport,
//! authenticated shards and availability custody are separate required integration work.
mod artifact;
mod json;
pub use artifact::{
    AcquisitionError, AuthoredBody, AuthoringError, AvailabilityError, AvailabilityFrame,
    AvailabilitySource, AvailableBody, BodyRestoration, MAX_AVAILABILITY_FRAME_BYTES,
    PayloadAcquisition, PayloadAuthoring, PayloadBytes, RestorationError, RowBytes,
    VerifiedAvailability, VerifiedManifest, VerifiedMaterial, content_digest, row_digest,
    verify_availability, verify_manifest,
};

use core::fmt;
use iroha_primitives::erasure::rs16::compact::CompactShape;
use norito::codec::{Decode, Encode};
/// Protocol-wide upper bound for one authenticated RS16 chunk.
pub const MAX_DA_CHUNK_SIZE_BYTES: u32 = 256 * 1024;
/// Protocol-wide upper bound for data shards in one RS16 stripe.
pub const MAX_DA_DATA_SHARDS: u16 = 16;
/// Protocol-wide upper bound for parity shards in one RS16 stripe.
pub const MAX_DA_PARITY_SHARDS: u16 = 16;
/// Protocol-wide upper bound for total shards in one RS16 stripe.
pub const MAX_DA_STRIPE_WIDTH: u16 = MAX_DA_DATA_SHARDS + MAX_DA_PARITY_SHARDS;
/// Protocol-wide upper bound for one canonical consensus payload.
pub const MAX_DA_PAYLOAD_SIZE_BYTES: u64 = MAX_DA_PAYLOAD_SIZE as u64;
const MAX_DA_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
/// Protocol-wide upper bound for all encoded shards of one maximum payload.
pub const MAX_DA_ENCODED_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;
/// Protocol-wide upper bound for encoded chunks committed by one manifest.
pub const MAX_DA_CHUNK_COUNT: u32 = 1024;
/// Payload chunking parameters frozen for one block height.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sumeragi::availability::DataAvailabilityLayout")]
pub struct DataAvailabilityLayout {
    /// Payload encoding used before chunk dissemination.
    pub encoding: PayloadEncoding,
    /// Maximum encoded chunk size in bytes.
    pub chunk_size_bytes: u32,
    /// Data shards per RS16 stripe.
    pub data_shards: u16,
    /// Parity shards per RS16 stripe.
    pub parity_shards: u16,
    /// Maximum canonical body size accepted at this height.
    pub max_payload_size_bytes: u64,
    /// Maximum number of encoded chunks accepted for one body.
    pub max_chunk_count: u32,
}
/// Payload encoding used by RS16 data dissemination.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito(
    tag = "encoding",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sumeragi::availability::PayloadEncoding")]
pub enum PayloadEncoding {
    /// Encode payload stripes with the deterministic RS16 layout.
    ReedSolomon16,
}
/// Recommended deterministic data-availability layout.
#[must_use]
pub const fn recommended_data_availability_layout() -> DataAvailabilityLayout {
    DataAvailabilityLayout {
        encoding: PayloadEncoding::ReedSolomon16,
        chunk_size_bytes: MAX_DA_CHUNK_SIZE_BYTES,
        data_shards: 4,
        parity_shards: 2,
        max_payload_size_bytes: MAX_DA_PAYLOAD_SIZE_BYTES,
        max_chunk_count: MAX_DA_CHUNK_COUNT,
    }
}

/// A malformed layout or unrepresentable canonical RS16 geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// A signed dimension or its encoded capacity violates a protocol bound.
    InvalidLayout,
    /// Consensus bodies must be nonempty and within the signed payload maximum.
    InvalidPayloadLength,
}
impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLayout => "invalid data-availability layout",
            Self::InvalidPayloadLength => "invalid nonempty consensus payload length",
        })
    }
}
impl std::error::Error for LayoutError {}

impl DataAvailabilityLayout {
    /// Check the signed dimensions and the largest permitted compact codeword.
    ///
    /// # Errors
    /// Rejects dimensions or maximum resource products outside protocol bounds.
    pub fn validate(&self) -> Result<(), LayoutError> {
        if !(2..=MAX_DA_CHUNK_SIZE_BYTES).contains(&self.chunk_size_bytes)
            || !self.chunk_size_bytes.is_multiple_of(2)
            || !(1..=MAX_DA_DATA_SHARDS).contains(&self.data_shards)
            || !(1..=MAX_DA_PARITY_SHARDS).contains(&self.parity_shards)
            || !(1..=MAX_DA_PAYLOAD_SIZE_BYTES).contains(&self.max_payload_size_bytes)
            || !(1..=MAX_DA_CHUNK_COUNT).contains(&self.max_chunk_count)
        {
            return Err(LayoutError::InvalidLayout);
        }
        let maximum = self.codec_shape(self.max_payload_size_bytes)?;
        if maximum.chunk_count() > self.max_chunk_count as usize
            || maximum.encoded_bytes() as u64 > MAX_DA_ENCODED_PAYLOAD_BYTES
        {
            return Err(LayoutError::InvalidLayout);
        }
        Ok(())
    }

    /// Derive the sole compact final-stripe representation of a nonempty payload.
    /// Every complete stripe uses the maximum width; the final stripe uses
    /// 2*ceil(remaining/(2*k)) bytes per row, with only terminal zero padding.
    ///
    /// # Errors
    /// Rejects invalid layouts and empty or oversized payloads.
    pub fn shape(&self, payload_bytes: u64) -> Result<CompactShape, LayoutError> {
        self.validate()?;
        if !(1..=self.max_payload_size_bytes).contains(&payload_bytes) {
            return Err(LayoutError::InvalidPayloadLength);
        }
        self.codec_shape(payload_bytes)
    }

    // Shared checked codec geometry follows explicit protocol-cap validation above.
    fn codec_shape(&self, payload_bytes: u64) -> Result<CompactShape, LayoutError> {
        CompactShape::new(
            usize::try_from(payload_bytes).map_err(|_| LayoutError::InvalidLayout)?,
            self.data_shards as usize,
            self.parity_shards as usize,
            self.chunk_size_bytes as usize,
        )
        .map_err(|_| LayoutError::InvalidLayout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::DecodeAll as _;
    #[test]
    fn payload_encoding_uses_natural_zero_tag_and_rejects_retired_tag_one() {
        let canonical = PayloadEncoding::ReedSolomon16.encode();
        assert_eq!(canonical, 0_u32.to_le_bytes());
        assert_eq!(
            PayloadEncoding::decode_all(&mut canonical.as_slice())
                .expect("decode canonical RS16 payload encoding"),
            PayloadEncoding::ReedSolomon16
        );
        let retired_tag = 1_u32.to_le_bytes();
        assert!(
            PayloadEncoding::decode_all(&mut retired_tag.as_slice()).is_err(),
            "retired payload-encoding tag 1 must fail closed"
        );
    }
    #[test]
    fn payload_encoding_json_rejects_retired_plain_variant() {
        let canonical = norito::json::to_value(&PayloadEncoding::ReedSolomon16)
            .expect("serialize canonical RS16 payload encoding");
        assert_eq!(
            norito::json::from_value::<PayloadEncoding>(canonical.clone())
                .expect("decode canonical RS16 payload encoding"),
            PayloadEncoding::ReedSolomon16
        );
        let mut retired = canonical;
        let encoding = retired
            .as_object_mut()
            .expect("adjacently tagged payload encoding")
            .get_mut("encoding")
            .expect("payload encoding tag");
        assert_eq!(encoding.as_str(), Some("reed_solomon16"));
        *encoding = norito::json::Value::String("plain".to_owned());
        assert!(
            norito::json::from_value::<PayloadEncoding>(retired).is_err(),
            "retired Plain payload encoding must fail closed"
        );
    }
    #[test]
    fn data_availability_layout_enforces_protocol_resource_caps() {
        let maximum = DataAvailabilityLayout {
            encoding: PayloadEncoding::ReedSolomon16,
            chunk_size_bytes: MAX_DA_CHUNK_SIZE_BYTES,
            data_shards: MAX_DA_DATA_SHARDS,
            parity_shards: MAX_DA_PARITY_SHARDS,
            max_payload_size_bytes: MAX_DA_PAYLOAD_SIZE_BYTES,
            max_chunk_count: MAX_DA_CHUNK_COUNT,
        };
        assert_eq!(maximum.validate(), Ok(()));
        let mut invalid_layouts = Vec::new();
        invalid_layouts.push(DataAvailabilityLayout {
            chunk_size_bytes: MAX_DA_CHUNK_SIZE_BYTES + 2,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            data_shards: MAX_DA_DATA_SHARDS + 1,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            parity_shards: MAX_DA_PARITY_SHARDS + 1,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            max_payload_size_bytes: MAX_DA_PAYLOAD_SIZE_BYTES + 1,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            max_chunk_count: MAX_DA_CHUNK_COUNT + 1,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            data_shards: 1,
            parity_shards: 15,
            ..maximum
        });
        invalid_layouts.push(DataAvailabilityLayout {
            data_shards: 1_024,
            parity_shards: 1_024,
            max_chunk_count: u32::MAX,
            ..maximum
        });
        for invalid in invalid_layouts {
            assert_eq!(invalid.validate(), Err(LayoutError::InvalidLayout));
        }
    }

    #[test]
    fn compact_final_stripe_has_one_bounded_width() {
        let layout = recommended_data_availability_layout();
        let capacity = u64::from(layout.data_shards) * u64::from(layout.chunk_size_bytes);
        for (bytes, stripes, final_width) in [
            (1, 1, 2),
            (7, 1, 2),
            (8, 1, 2),
            (9, 1, 4),
            (capacity - 1, 1, u64::from(layout.chunk_size_bytes)),
            (capacity, 1, u64::from(layout.chunk_size_bytes)),
            (capacity + 1, 2, 2),
            (23_572, 1, 5_894),
            (
                layout.max_payload_size_bytes,
                16,
                u64::from(layout.chunk_size_bytes),
            ),
        ] {
            let shape = layout.shape(bytes).unwrap();
            assert_eq!(shape.stripe_count() as u64, stripes);
            assert_eq!(shape.terminal_row_bytes() as u64, final_width);
            assert_eq!(shape.chunk_count(), shape.stripe_count() * 6);
            assert!(shape.encoded_bytes() as u64 <= MAX_DA_ENCODED_PAYLOAD_BYTES);
        }
        assert_eq!(layout.shape(23_572).unwrap().encoded_bytes(), 35_364);
        for bytes in [0, layout.max_payload_size_bytes + 1, u64::MAX] {
            assert_eq!(layout.shape(bytes), Err(LayoutError::InvalidPayloadLength));
        }
    }
    #[test]
    fn bounded_geometry_matches_independent_wide_integer_resource_reference() {
        for k in 1..=MAX_DA_DATA_SHARDS {
            for m in 1..=MAX_DA_PARITY_SHARDS {
                for chunk in [2, 4, 1024, MAX_DA_CHUNK_SIZE_BYTES] {
                    for maximum in [
                        1,
                        7,
                        1024,
                        MAX_DA_PAYLOAD_SIZE_BYTES - 1,
                        MAX_DA_PAYLOAD_SIZE_BYTES,
                    ] {
                        let layout = DataAvailabilityLayout {
                            data_shards: k,
                            parity_shards: m,
                            chunk_size_bytes: chunk,
                            max_payload_size_bytes: maximum,
                            ..recommended_data_availability_layout()
                        };
                        let reference = |payload: u64| {
                            let capacity = u128::from(k) * u128::from(chunk);
                            let full = (u128::from(payload) - 1) / capacity;
                            let tail = u128::from(payload) - full * capacity;
                            let row = 2 * ((tail - 1) / (2 * u128::from(k)) + 1);
                            let width = u128::from(k) + u128::from(m);
                            (
                                (full + 1) * width,
                                (full * u128::from(chunk) + row) * width,
                                row,
                            )
                        };
                        let (count, encoded, _) = reference(maximum);
                        let valid = count <= u128::from(layout.max_chunk_count)
                            && encoded <= u128::from(MAX_DA_ENCODED_PAYLOAD_BYTES);
                        assert_eq!(layout.validate().is_ok(), valid, "{layout:?}");
                        if valid {
                            for payload in [1, maximum.div_ceil(2), maximum] {
                                let shape = layout.shape(payload).unwrap();
                                let (count, encoded, row) = reference(payload);
                                assert_eq!(shape.chunk_count() as u128, count);
                                assert_eq!(shape.encoded_bytes() as u128, encoded);
                                assert_eq!(shape.terminal_row_bytes() as u128, row);
                                assert!(shape.terminal_row_bytes().is_multiple_of(2));
                                assert!(shape.terminal_row_bytes() <= chunk as usize);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn raw_extreme_dimensions_reject_before_bounded_arithmetic() {
        let base = recommended_data_availability_layout();
        for malformed in [
            DataAvailabilityLayout {
                chunk_size_bytes: 0,
                ..base
            },
            DataAvailabilityLayout {
                chunk_size_bytes: 1,
                ..base
            },
            DataAvailabilityLayout {
                chunk_size_bytes: u32::MAX,
                ..base
            },
            DataAvailabilityLayout {
                data_shards: 0,
                ..base
            },
            DataAvailabilityLayout {
                data_shards: u16::MAX,
                ..base
            },
            DataAvailabilityLayout {
                parity_shards: 0,
                ..base
            },
            DataAvailabilityLayout {
                parity_shards: u16::MAX,
                ..base
            },
            DataAvailabilityLayout {
                max_payload_size_bytes: 0,
                ..base
            },
            DataAvailabilityLayout {
                max_payload_size_bytes: u64::MAX,
                ..base
            },
            DataAvailabilityLayout {
                max_chunk_count: 0,
                ..base
            },
            DataAvailabilityLayout {
                max_chunk_count: u32::MAX,
                ..base
            },
        ] {
            assert_eq!(malformed.validate(), Err(LayoutError::InvalidLayout));
            assert_eq!(malformed.shape(1), Err(LayoutError::InvalidLayout));
        }
        let compact_maximum = DataAvailabilityLayout {
            data_shards: 3,
            parity_shards: 3,
            max_payload_size_bytes: MAX_DA_PAYLOAD_SIZE_BYTES - 4,
            ..base
        };
        assert_eq!(compact_maximum.validate(), Ok(()));
        assert_eq!(
            compact_maximum
                .shape(MAX_DA_PAYLOAD_SIZE_BYTES - 4)
                .unwrap()
                .encoded_bytes() as u64,
            2 * (MAX_DA_PAYLOAD_SIZE_BYTES - 4)
        );
    }
}
