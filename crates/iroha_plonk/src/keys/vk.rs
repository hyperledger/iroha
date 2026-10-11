//! The verifying key and its `0x02` byte layout (spec section 5).
//!
//! ```text
//! 0x02 || u32_le(k) || u8 compress (0 or 1) || u32_le(F_c)
//!      || F_c fixed commitments || m permutation commitments (sigma_j)
//!      || [compress] n_sel activation bitmaps of ceil(n/8) bytes each
//! ```
//!
//! The bytes are identical to the vendored `VerifyingKey::write` (Processed
//! format). Bit `i` of bitmap byte `j` is row `8j + i`.
//!
//! [`VerifyingKey::read`] decodes against a [`DescriptorBinding`] and is
//! stricter than the vendored `read_checked`:
//!
//! - `k`, the compress flag and `F_c` must equal the descriptor's;
//! - every commitment is a canonical, on-curve, non-identity point;
//! - bitmap padding bits are zero;
//! - no byte follows the last field;
//! - with compression, rerunning selector compression on the bitmaps with the
//!   descriptor's `max_degree` entries must reproduce the descriptor's
//!   selector map (the registration rule).
//!
//! # Transcript binding
//!
//! `transcript_repr = F::from_uniform_bytes(BLAKE2b(64, "Iroha-PlonkVK-v1",
//! descriptor_digest || vk_bytes))` binds the relation, the params digest, the
//! instance shape and the keys. It replaces the vendored hash of the `Debug`
//! rendering. Unit tests may inject the
//! vendored value with `VerifyingKey::with_transcript_repr_for_oracle`.

use core::fmt;

use ff::PrimeField;
use iroha_pasta::{PastaAffine, PastaCurve, poseidon::hash_with_domain};

use super::DescriptorBinding;
use crate::{
    cs::{CurveV1, TranscriptV2},
    pcs::curve_v1,
    transcript::TranscriptRepr,
    transcript::{MESSAGE_BYTES, TranscriptError, decode_point, encode_point},
};

/// The version byte of the layout.
pub const VK_VERSION: u8 = 0x02;
/// Bytes before the commitments: version, `k`, compress flag and `F_c`.
pub const VK_HEADER_BYTES: usize = 10;

/// A verifying key could not be decoded against its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VkError {
    /// The caller cancelled key construction or decoding.
    Cancelled,
    /// The descriptor names another curve.
    CurveMismatch {
        /// The descriptor's curve.
        descriptor: CurveV1,
    },
    /// The encoding has the wrong length.
    Length {
        /// The length the descriptor implies.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// The version byte is not `0x02`.
    Version {
        /// The encoded byte.
        found: u8,
    },
    /// `k` differs from the descriptor's.
    K {
        /// The descriptor's `k`.
        expected: u32,
        /// The encoded `k`.
        found: u32,
    },
    /// The compress byte is not 0 or 1, or differs from the descriptor's.
    Compress {
        /// The descriptor's flag.
        expected: bool,
        /// The encoded byte.
        found: u8,
    },
    /// `F_c` differs from the descriptor's fixed-column count.
    FixedCount {
        /// The descriptor's count.
        expected: u32,
        /// The encoded count.
        found: u32,
    },
    /// A commitment failed canonical decoding.
    Point {
        /// Its index in encoding order (fixed, then permutation).
        index: usize,
        /// Why.
        error: TranscriptError,
    },
    /// A selector bitmap has a nonzero padding bit.
    BitmapPadding {
        /// The selector.
        selector: usize,
    },
    /// The bitmaps do not reproduce the descriptor's selector map.
    SelectorPlan,
    /// The key is not bound to this V2 PIPA-R descriptor.
    Binding,
    /// Key parts do not match the descriptor's shape (construction only).
    Shape,
}

impl fmt::Display for VkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("verifying key operation cancelled"),
            Self::CurveMismatch { descriptor } => {
                write!(f, "the descriptor is for {descriptor:?}")
            }
            Self::Length { expected, actual } => {
                write!(f, "verifying key has {actual} bytes, expected {expected}")
            }
            Self::Version { found } => write!(f, "verifying key version byte {found:#04x}"),
            Self::K { expected, found } => {
                write!(f, "verifying key k = {found}, descriptor k = {expected}")
            }
            Self::Compress { expected, found } => write!(
                f,
                "verifying key compress byte {found}, descriptor compress = {expected}"
            ),
            Self::FixedCount { expected, found } => write!(
                f,
                "verifying key has {found} fixed commitments, descriptor has {expected}"
            ),
            Self::Point { index, error } => write!(f, "verifying key point {index}: {error}"),
            Self::BitmapPadding { selector } => {
                write!(f, "selector bitmap {selector} has nonzero padding")
            }
            Self::SelectorPlan => {
                f.write_str("selector bitmaps do not reproduce the descriptor's selector map")
            }
            Self::Shape => f.write_str("key parts do not match the descriptor"),
            Self::Binding => f.write_str("key does not match the PIPA-R descriptor binding"),
        }
    }
}

impl std::error::Error for VkError {}
impl From<iroha_pasta::Cancelled> for VkError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}
impl VkError {
    /// Whether this error is cooperative cancellation, never malformed key input.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// A verifying key bound to its descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<C: PastaCurve> {
    k: u32,
    compress_selectors: bool,
    fixed_commitments: Vec<C::AffineExt>,
    permutation_commitments: Vec<C::AffineExt>,
    selectors: Vec<Vec<bool>>,
    bytes: Vec<u8>,
    descriptor_digest: [u8; 32],
    transcript_repr: TranscriptRepr<C>,
}

/// The bytes of one bitmap of `n` rows.
fn bitmap_bytes(n: usize) -> usize {
    n.div_ceil(8)
}

/// The exact encoding length a descriptor implies.
pub(super) fn expected_len(binding: &DescriptorBinding) -> Option<usize> {
    let descriptor = binding.descriptor();
    let points =
        (descriptor.num_fixed_columns as usize).checked_add(descriptor.permutation.len())?;
    let bitmaps = if descriptor.selectors.compress {
        descriptor
            .selectors
            .entries
            .len()
            .checked_mul(bitmap_bytes(binding.n()))?
    } else {
        0
    };
    points
        .checked_mul(MESSAGE_BYTES)?
        .checked_add(VK_HEADER_BYTES)?
        .checked_add(bitmaps)
}

/// Checks that the descriptor is for curve `C`.
fn check_curve<C: PastaCurve>(binding: &DescriptorBinding) -> Result<(), VkError> {
    let descriptor = binding.descriptor().curve;
    if curve_v1::<C>() == Some(descriptor) {
        Ok(())
    } else {
        Err(VkError::CurveMismatch { descriptor })
    }
}

impl<C: PastaCurve> VerifyingKey<C> {
    /// The KAGEMUSHA verifying-key digest in the proof curve's base field.
    ///
    /// This is `P_B(kgwvkey1; 1, curve, k, fixed_count, permutation_count,
    /// transcript_repr, descriptor_digest_lo128, descriptor_digest_hi128,
    /// fixed_x, fixed_y, ..., permutation_x, permutation_y, ...)`. The domain
    /// uses little-endian ASCII and the usual domain/arity framing. Curve
    /// codes are Pallas = 0 and Vesta = 1. Commitments retain wire order.
    ///
    /// # Errors
    /// [`VkError::Binding`] unless the key belongs to the supplied V2 PIPA-R
    /// descriptor, or [`VkError::Point`] for an identity commitment.
    pub fn kagemusha_digest(&self, binding: &DescriptorBinding) -> Result<C::Base, VkError> {
        let descriptor = binding.descriptor();
        if !binding.is_v2()
            || descriptor.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || binding.digest() != &self.descriptor_digest
        {
            return Err(VkError::Binding);
        }
        let TranscriptRepr::Base(repr) = self.transcript_repr else {
            return Err(VkError::Binding);
        };
        let curve = match descriptor.curve {
            CurveV1::Pallas => 0,
            CurveV1::Vesta => 1,
        };
        let mut low = [0; 16];
        let mut high = [0; 16];
        low.copy_from_slice(&self.descriptor_digest[..16]);
        high.copy_from_slice(&self.descriptor_digest[16..]);
        let mut fields = vec![
            C::Base::from(1),
            C::Base::from(curve),
            C::Base::from(u64::from(self.k)),
            C::Base::from(u64::from(descriptor.num_fixed_columns)),
            C::Base::from(
                u64::try_from(self.permutation_commitments.len()).map_err(|_| VkError::Shape)?,
            ),
            repr,
            C::Base::from_u128(u128::from_le_bytes(low)),
            C::Base::from_u128(u128::from_le_bytes(high)),
        ];
        for (index, point) in self
            .fixed_commitments
            .iter()
            .chain(&self.permutation_commitments)
            .enumerate()
        {
            let (x, y) = Option::from(point.coordinates()).ok_or(VkError::Point {
                index,
                error: TranscriptError::IdentityPoint,
            })?;
            fields.extend([x, y]);
        }
        Ok(hash_with_domain(u64::from_le_bytes(*b"kgwvkey1"), &fields))
    }

    /// Assembles a key from its parts (key generation).
    ///
    /// # Errors
    ///
    /// [`VkError::CurveMismatch`] or [`VkError::Shape`] when the parts do not
    /// match the descriptor; [`VkError::Point`] for an identity commitment;
    /// [`VkError::SelectorPlan`] when the activations do not reproduce the
    /// selector map.
    pub fn from_parts(
        binding: &DescriptorBinding,
        fixed_commitments: Vec<C::AffineExt>,
        permutation_commitments: Vec<C::AffineExt>,
        selectors: Vec<Vec<bool>>,
    ) -> Result<Self, VkError> {
        Self::from_parts_cancellable(
            binding,
            fixed_commitments,
            permutation_commitments,
            selectors,
            None,
        )
    }

    /// Assemble identical key parts with cancellation through encoding and selector admission.
    ///
    /// # Errors
    /// As [`Self::from_parts`], or [`VkError::Cancelled`].
    pub fn from_parts_cancellable(
        binding: &DescriptorBinding,
        fixed_commitments: Vec<C::AffineExt>,
        permutation_commitments: Vec<C::AffineExt>,
        selectors: Vec<Vec<bool>>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, VkError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        check_curve::<C>(binding)?;
        let descriptor = binding.descriptor();
        let n = binding.n();
        let compress = descriptor.selectors.compress;
        let expected_selectors = if compress {
            descriptor.selectors.entries.len()
        } else {
            0
        };
        if fixed_commitments.len() != descriptor.num_fixed_columns as usize
            || permutation_commitments.len() != descriptor.permutation.len()
            || selectors.len() != expected_selectors
            || selectors.iter().any(|rows| rows.len() != n)
        {
            return Err(VkError::Shape);
        }
        let mut bytes = Vec::with_capacity(expected_len(binding).ok_or(VkError::Shape)?);
        bytes.push(VK_VERSION);
        bytes.extend_from_slice(&u32::from(descriptor.k).to_le_bytes());
        bytes.push(u8::from(compress));
        bytes.extend_from_slice(&descriptor.num_fixed_columns.to_le_bytes());
        for (index, point) in fixed_commitments
            .iter()
            .chain(&permutation_commitments)
            .enumerate()
        {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            let encoded = encode_point::<C>(point);
            if encoded == [0_u8; MESSAGE_BYTES] {
                return Err(VkError::Point {
                    index,
                    error: TranscriptError::IdentityPoint,
                });
            }
            bytes.extend_from_slice(&encoded);
        }
        for rows in &selectors {
            for (index, chunk) in rows.chunks(8).enumerate() {
                if index % 512 == 0 {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                }
                let mut byte = 0_u8;
                for (bit, active) in chunk.iter().enumerate() {
                    byte |= u8::from(*active) << bit;
                }
                bytes.push(byte);
            }
        }
        if compress {
            descriptor
                .check_selector_plan_cancellable(&selectors, cancellation)
                .map_err(|error| {
                    if error.is_cancelled() {
                        VkError::Cancelled
                    } else {
                        VkError::SelectorPlan
                    }
                })?;
        }
        Self::bind(
            binding,
            fixed_commitments,
            permutation_commitments,
            selectors,
            bytes,
            cancellation,
        )
    }

    /// Computes `transcript_repr` and stores the parts.
    fn bind(
        binding: &DescriptorBinding,
        fixed_commitments: Vec<C::AffineExt>,
        permutation_commitments: Vec<C::AffineExt>,
        selectors: Vec<Vec<bool>>,
        bytes: Vec<u8>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, VkError> {
        let descriptor = binding.descriptor();
        Ok(Self {
            k: u32::from(descriptor.k),
            compress_selectors: descriptor.selectors.compress,
            fixed_commitments,
            permutation_commitments,
            selectors,
            transcript_repr: TranscriptRepr::derive_cancellable(
                binding.is_v2(),
                descriptor.transcript,
                binding.digest(),
                &bytes,
                cancellation,
            )?,
            bytes,
            descriptor_digest: *binding.digest(),
        })
    }

    /// Decodes `bytes` strictly against `binding` (see the module
    /// documentation).
    ///
    /// # Errors
    ///
    /// The first failed [`VkError`] rule.
    pub fn read(bytes: &[u8], binding: &DescriptorBinding) -> Result<Self, VkError> {
        Self::read_cancellable(bytes, binding, None)
    }

    /// Strictly decode a key with cancellation through point and selector admission.
    ///
    /// # Errors
    /// As [`Self::read`], or [`VkError::Cancelled`].
    pub fn read_cancellable(
        bytes: &[u8],
        binding: &DescriptorBinding,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, VkError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        check_curve::<C>(binding)?;
        let descriptor = binding.descriptor();
        let expected = expected_len(binding).ok_or(VkError::Length {
            expected: usize::MAX,
            actual: bytes.len(),
        })?;
        let length_error = VkError::Length {
            expected,
            actual: bytes.len(),
        };
        let header: &[u8; VK_HEADER_BYTES] = bytes
            .get(..VK_HEADER_BYTES)
            .and_then(|header| header.try_into().ok())
            .ok_or(length_error)?;
        if header[0] != VK_VERSION {
            return Err(VkError::Version { found: header[0] });
        }
        let k = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        if k != u32::from(descriptor.k) {
            return Err(VkError::K {
                expected: u32::from(descriptor.k),
                found: k,
            });
        }
        let compress = descriptor.selectors.compress;
        if header[5] != u8::from(compress) {
            return Err(VkError::Compress {
                expected: compress,
                found: header[5],
            });
        }
        let fixed = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);
        if fixed != descriptor.num_fixed_columns {
            return Err(VkError::FixedCount {
                expected: descriptor.num_fixed_columns,
                found: fixed,
            });
        }
        if bytes.len() != expected {
            return Err(length_error);
        }
        let point_count = descriptor.num_fixed_columns as usize + descriptor.permutation.len();
        let mut points = Vec::with_capacity(point_count);
        for index in 0..point_count {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            let offset = VK_HEADER_BYTES + MESSAGE_BYTES * index;
            let mut message = [0_u8; MESSAGE_BYTES];
            message.copy_from_slice(&bytes[offset..offset + MESSAGE_BYTES]);
            points.push(
                decode_point::<C>(&message).map_err(|error| VkError::Point { index, error })?,
            );
        }
        let permutation_commitments = points.split_off(descriptor.num_fixed_columns as usize);
        let fixed_commitments = points;

        let n = binding.n();
        let width = bitmap_bytes(n);
        let mut selectors = Vec::new();
        if compress {
            let start = VK_HEADER_BYTES + MESSAGE_BYTES * point_count;
            for (selector, chunk) in bytes[start..].chunks(width).enumerate() {
                let mut rows = Vec::with_capacity(n);
                for (byte_index, byte) in chunk.iter().enumerate() {
                    if byte_index % 512 == 0 {
                        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                    }
                    for bit in 0..8 {
                        let row = 8 * byte_index + bit;
                        let active = (byte >> bit) & 1 == 1;
                        if row < n {
                            rows.push(active);
                        } else if active {
                            return Err(VkError::BitmapPadding { selector });
                        }
                    }
                }
                selectors.push(rows);
            }
            descriptor
                .check_selector_plan_cancellable(&selectors, cancellation)
                .map_err(|error| {
                    if error.is_cancelled() {
                        VkError::Cancelled
                    } else {
                        VkError::SelectorPlan
                    }
                })?;
        }
        Self::bind(
            binding,
            fixed_commitments,
            permutation_commitments,
            selectors,
            bytes.to_vec(),
            cancellation,
        )
    }

    /// Replaces `transcript_repr` with the vendored value (unit tests
    /// only, spec 6.4). Never compiled into shipping binaries.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_transcript_repr_for_oracle(mut self, transcript_repr: C::ScalarExt) -> Self {
        self.transcript_repr = TranscriptRepr::Scalar(transcript_repr);
        self
    }

    /// `log2` of the domain size.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Whether selector compression ran.
    #[must_use]
    pub fn compress_selectors(&self) -> bool {
        self.compress_selectors
    }

    /// The fixed-column commitments (selector columns included).
    #[must_use]
    pub fn fixed_commitments(&self) -> &[C::AffineExt] {
        &self.fixed_commitments
    }

    /// The permutation commitments `sigma_j`.
    #[must_use]
    pub fn permutation_commitments(&self) -> &[C::AffineExt] {
        &self.permutation_commitments
    }

    /// The selector activations (present only with compression).
    #[must_use]
    pub fn selectors(&self) -> &[Vec<bool>] {
        &self.selectors
    }

    /// The `0x02` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The digest of the descriptor this key is bound to.
    #[must_use]
    pub fn descriptor_digest(&self) -> &[u8; 32] {
        &self.descriptor_digest
    }

    /// `transcript_repr`, absorbed first by every proof (spec 6.3).
    #[must_use]
    pub fn transcript_repr(&self) -> &TranscriptRepr<C> {
        &self.transcript_repr
    }

    /// The canonical encoding of `transcript_repr`.
    #[must_use]
    pub fn transcript_repr_bytes(&self) -> [u8; 32] {
        self.transcript_repr.to_repr()
    }
}
