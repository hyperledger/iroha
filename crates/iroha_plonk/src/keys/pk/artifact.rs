//! Canonical original proving-key material for explicit V2 native circuits.
//!
//! The artifact contains the descriptor-bound original VK, copy digest and exact
//! fixed/permutation evaluation tables. Import checks the installed circuit's
//! witnessless layout and every VK commitment before deriving FFT/cache data.
//! It generates no verifying key, descriptor choice or proof. Authentication of
//! the complete artifact bytes remains the signed native package owner's duty.

use core::fmt;

use ff::PrimeField;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};

use super::{CosetCachePolicy, ProvingKey};
use crate::{
    DescriptorBinding,
    frontend::Circuit,
    keys::{KeyError, VerifyingKey, keygen, vk},
    pcs::ipa::PinnedParams,
};

/// The sole original artifact version: `PIPAPK01`.
pub const MAGIC: [u8; 8] = *b"PIPAPK01";
const HEADER: usize = 8 + 32 + 4;
const COPY_BYTES: usize = 32;

/// Native installation allocation and cache choices, never taken from witnesses.
/// These bound original/domain admission, not total circuit-synthesis heap use.
/// The package owner pins exact circuit dimensions and selects `OnDemand` for
/// bounded mobile mounting; eager caches and full synthesis need separate budgets.
#[derive(Clone, Copy, Debug)]
pub struct ReadConfig {
    /// Largest accepted original, checked before synthesis or allocation.
    pub maximum_bytes: usize,
    /// Largest permitted FFT domain, checked before synthesis or allocation.
    pub maximum_rows: usize,
    /// Derived coset cache policy; caches are not serialized authority.
    pub coset_cache: CosetCachePolicy,
    /// Process-wide MSM admission for checking original commitments.
    pub msm_budget: MemoryBudget,
}

/// Original proving-key admission failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The explicit operation signal cancelled admission.
    Cancelled,
    /// Not an explicit V2 descriptor or a mismatching pinned curve/domain/profile.
    Profile,
    /// An original length, arithmetic or caller allocation bound failed.
    Length,
    /// Wrong magic, descriptor digest or a noncanonical scalar.
    Encoding,
    /// Actual installed circuit tables, copy mapping or selectors differ.
    Source,
    /// An imported column does not commit to its original VK point.
    Commitment,
    /// Native circuit, descriptor, FFT, MSM or key assembly failure.
    Key(KeyError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::Profile => f.write_str("proving-key artifact profile differs"),
            Self::Length => f.write_str("proving-key artifact length or allocation bound failed"),
            Self::Encoding => f.write_str("noncanonical proving-key artifact"),
            Self::Source => f.write_str("proving-key artifact differs from installed circuit"),
            Self::Commitment => f.write_str("proving-key artifact commitment differs"),
            Self::Key(error) => write!(f, "proving-key artifact: {error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<KeyError> for Error {
    fn from(error: KeyError) -> Self {
        if error.is_cancelled() {
            Self::Cancelled
        } else {
            Self::Key(error)
        }
    }
}

impl Error {
    /// Whether admission was cancelled rather than rejected as invalid material.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled) || matches!(self, Self::Key(error) if error.is_cancelled())
    }
}
impl From<iroha_pasta::Cancelled> for Error {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

fn dimensions(binding: &DescriptorBinding) -> Result<(usize, usize, usize), Error> {
    if !binding.is_v2() {
        return Err(Error::Profile);
    }
    let d = binding.descriptor();
    let vk_bytes = vk::expected_len(binding).ok_or(Error::Length)?;
    let columns = (d.num_fixed_columns as usize)
        .checked_add(d.permutation.len())
        .ok_or(Error::Length)?;
    let table_bytes = columns
        .checked_mul(binding.n())
        .and_then(|n| n.checked_mul(32))
        .ok_or(Error::Length)?;
    let bytes = HEADER
        .checked_add(vk_bytes)
        .and_then(|n| n.checked_add(COPY_BYTES))
        .and_then(|n| n.checked_add(table_bytes))
        .ok_or(Error::Length)?;
    Ok((vk_bytes, columns, bytes))
}

/// Validate all length/allocation bounds before slicing or allocating key material.
fn bounded_dimensions(
    original: &[u8],
    binding: &DescriptorBinding,
    config: ReadConfig,
) -> Result<(usize, usize), Error> {
    let (vk_bytes, columns, expected) = dimensions(binding)?;
    if original.len() != expected
        || expected > config.maximum_bytes
        || binding.n() > config.maximum_rows
    {
        return Err(Error::Length);
    }
    Ok((vk_bytes, columns))
}

struct OriginalParts<'a, C: PastaCurve> {
    key: VerifyingKey<C>,
    copy_digest: [u8; 32],
    evaluations: &'a [u8],
}

/// Only called after `bounded_dimensions` checked the exact complete span.
fn original_parts<'a, C: PastaCurve>(
    original: &'a [u8],
    binding: &DescriptorBinding,
    vk_bytes: usize,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<OriginalParts<'a, C>, Error> {
    if original[..8] != MAGIC || original[8..40] != *binding.digest() {
        return Err(Error::Encoding);
    }
    let encoded_vk_bytes = u32::from_le_bytes(
        original[40..HEADER]
            .try_into()
            .map_err(|_| Error::Encoding)?,
    ) as usize;
    if encoded_vk_bytes != vk_bytes {
        return Err(Error::Length);
    }
    let vk_end = HEADER + vk_bytes;
    let key = VerifyingKey::<C>::read_cancellable(&original[HEADER..vk_end], binding, cancellation)
        .map_err(|error| Error::Key(KeyError::VerifyingKey(error)))?;
    let copy_digest = original[vk_end..vk_end + COPY_BYTES]
        .try_into()
        .map_err(|_| Error::Encoding)?;
    Ok(OriginalParts {
        key,
        copy_digest,
        evaluations: &original[vk_end + COPY_BYTES..],
    })
}

/// Read an untrusted original's lookup fingerprint without reconstructing a key.
///
/// Exact bounds, descriptor framing, canonical processed VK/selector encodings
/// and every scalar are checked. Scalars are streamed, without retaining their
/// evaluation tables or loading parameter arrays. The fingerprint excludes VK
/// commitments: an attacker can preserve it while changing a valid commitment.
/// It grants no authentication or source qualification. Matching only selects a
/// candidate for mandatory [`ProvingKey::from_artifact_v2_cancellable`] admission.
///
/// # Errors
/// Incorrect profile, bounds, framing, points or scalars, or explicit cancellation.
pub fn source_fingerprint_v2<C: PastaCurve>(
    original: &[u8],
    binding: &DescriptorBinding,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<crate::keys::SourceFingerprintV2, Error> {
    use iroha_pasta::CancellationToken;
    CancellationToken::checkpoint(cancellation)?;
    let (vk_bytes, _) = bounded_dimensions(original, binding, config)?;
    let parts = original_parts::<C>(original, binding, vk_bytes, cancellation)?;
    let mut hash = crate::keys::source_fingerprint::SourceHasher::new(
        binding,
        &parts.copy_digest,
        parts.key.selectors(),
        cancellation,
    )?;
    for (index, bytes) in parts.evaluations.chunks_exact(32).enumerate() {
        if index % 1024 == 0 {
            CancellationToken::checkpoint(cancellation)?;
        }
        let mut repr = <C::ScalarExt as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        Option::<C::ScalarExt>::from(C::ScalarExt::from_repr(repr)).ok_or(Error::Encoding)?;
        hash.scalar(bytes);
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(hash.finish(binding.clone()))
}

impl<C: PastaCurve> ProvingKey<C> {
    /// Encode the complete original V2 proving material. Derived caches, masks,
    /// coefficients and commitment tables are reconstructed, not serialized.
    ///
    /// Layout: `PIPAPK01 || descriptor_digest32 || LE32 vk_bytes || vk ||
    /// copy_digest32 || fixed columns || permutation columns`, with exactly
    /// `2^k` canonical little-endian 32-byte scalars per column.
    ///
    /// # Errors
    /// Wrong descriptor version, invalid shape or size arithmetic overflow.
    pub fn artifact_bytes_v2(&self) -> Result<Vec<u8>, Error> {
        let (vk_bytes, _, bytes) = dimensions(self.binding())?;
        let vk_len = u32::try_from(vk_bytes).map_err(|_| Error::Length)?;
        let original_vk = self.vk().to_bytes();
        if original_vk.len() != vk_bytes {
            return Err(Error::Length);
        }
        let mut out = Vec::with_capacity(bytes);
        out.extend(MAGIC);
        out.extend(self.binding().digest());
        out.extend(vk_len.to_le_bytes());
        out.extend(original_vk);
        out.extend(self.copy_digest());
        for column in self.fixed_values().iter().chain(self.permutation_values()) {
            if column.len() != self.binding().n() {
                return Err(Error::Length);
            }
            for value in column {
                out.extend(value.to_repr());
            }
        }
        if out.len() != bytes {
            return Err(Error::Length);
        }
        Ok(out)
    }

    /// Import original material against an already installed native circuit.
    /// The caller first authenticates its complete bytes and fixed descriptor.
    /// This method rejects V1 and never chooses an alternate layout or runs key
    /// generation. Witnessless synthesis checks the fixed native relation; all
    /// original VK commitments are checked before deriving runtime FFT data.
    ///
    /// # Errors
    /// Allocation/encoding, installed source, curve/domain or commitment mismatch.
    pub fn from_artifact_v2<Ci: Circuit<C::ScalarExt>>(
        original: &[u8],
        binding: &DescriptorBinding,
        params: &PinnedParams<C>,
        circuit: &Ci,
        config: ReadConfig,
    ) -> Result<Self, Error> {
        Self::from_artifact_v2_cancellable(original, binding, params, circuit, config, None)
    }

    /// Import original key material with cooperative cancellation at synthesis,
    /// decoding, commitment and transform boundaries. No partial key escapes.
    /// # Errors
    /// As [`Self::from_artifact_v2`], or explicit cancellation.
    pub fn from_artifact_v2_cancellable<Ci: Circuit<C::ScalarExt>>(
        original: &[u8],
        binding: &DescriptorBinding,
        params: &PinnedParams<C>,
        circuit: &Ci,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let (vk_bytes, columns) = bounded_dimensions(original, binding, config)?;
        if params.k() != u32::from(binding.descriptor().k) {
            return Err(Error::Profile);
        }
        let OriginalParts {
            key,
            copy_digest,
            evaluations,
        } = original_parts::<C>(original, binding, vk_bytes, cancellation)?;
        let width = binding.n().checked_mul(32).ok_or(Error::Length)?;
        let mut values = Vec::with_capacity(columns);
        for column in evaluations.chunks_exact(width) {
            let mut scalars = Vec::with_capacity(binding.n());
            for (index, bytes) in column.chunks_exact(32).enumerate() {
                if index % 1024 == 0 {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                }
                let mut repr = <C::ScalarExt as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(bytes);
                scalars.push(
                    Option::<C::ScalarExt>::from(C::ScalarExt::from_repr(repr))
                        .ok_or(Error::Encoding)?,
                );
            }
            values.push(scalars);
        }
        let permutation = values.split_off(binding.descriptor().num_fixed_columns as usize);
        keygen::import_artifact_v2(
            params,
            circuit,
            binding,
            key,
            values,
            permutation,
            copy_digest,
            config,
            cancellation,
        )
    }
}
