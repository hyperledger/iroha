//! Canonical original proving-key material for explicit V2 native circuits.
//!
//! The artifact contains the descriptor-bound original VK, copy digest and exact
//! source fingerprint. Import reconstructs the fixed/permutation tables from the
//! installed circuit's witnessless layout, checks their fingerprint and every VK
//! commitment. Full PK import then derives FFT/cache data; metadata admission
//! drops source tables without constructing proving buffers. No evaluation tables
//! are downloaded.
//! It generates no verifying key, descriptor choice or proof. Authentication of
//! the complete artifact bytes remains the signed native package owner's duty.

use core::fmt;

use iroha_pasta::{PastaCurve, msm::MemoryBudget};

use super::{CosetCachePolicy, ProvingKey};
use crate::{
    DescriptorBinding,
    frontend::Circuit,
    keys::{KeyError, SourceBoundVerifyingKeyV2, VerifyingKey, keygen, vk},
    pcs::ipa::PinnedParams,
};

/// The sole compact original artifact version: `PIPACPK1`.
pub const MAGIC: [u8; 8] = *b"PIPACPK1";
const HEADER: usize = 8 + 32 + 4;
const COPY_BYTES: usize = 32;
const SOURCE_BYTES: usize = 32;

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
    /// Derived coset cache policy for full PK import; metadata admission constructs
    /// no cache. Caches are not serialized authority.
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
    /// Wrong magic or descriptor digest.
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

fn dimensions(binding: &DescriptorBinding) -> Result<(usize, usize), Error> {
    if !binding.is_v2() {
        return Err(Error::Profile);
    }
    let vk_bytes = vk::expected_len(binding).ok_or(Error::Length)?;
    let bytes = HEADER
        .checked_add(vk_bytes)
        .and_then(|n| n.checked_add(COPY_BYTES))
        .and_then(|n| n.checked_add(SOURCE_BYTES))
        .ok_or(Error::Length)?;
    Ok((vk_bytes, bytes))
}

/// Validate all length/allocation bounds before slicing or allocating key material.
fn bounded_dimensions(
    original: &[u8],
    binding: &DescriptorBinding,
    config: ReadConfig,
) -> Result<usize, Error> {
    let (vk_bytes, expected) = dimensions(binding)?;
    if original.len() != expected
        || expected > config.maximum_bytes
        || binding.n() > config.maximum_rows
    {
        return Err(Error::Length);
    }
    Ok(vk_bytes)
}

pub(in crate::keys) struct OriginalParts<C: PastaCurve> {
    pub(in crate::keys) key: VerifyingKey<C>,
    pub(in crate::keys) copy_digest: [u8; 32],
    pub(in crate::keys) source_digest: [u8; 32],
}

/// Canonical bounded DATA parsing, with no source authority or seal construction.
pub(in crate::keys) fn read_bounded_original_v2<C: PastaCurve>(
    original: &[u8],
    binding: &DescriptorBinding,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<OriginalParts<C>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let vk_bytes = bounded_dimensions(original, binding, config)?;
    original_parts(original, binding, vk_bytes, cancellation)
}

/// Compare the embedded VK to an existing canonical typed value after the same
/// bounded framing checks. This helper returns DATA, never a source capability.
pub(in crate::keys) fn read_bounded_original_with_key_v2<C: PastaCurve>(
    original: &[u8],
    binding: &DescriptorBinding,
    key: &VerifyingKey<C>,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<OriginalParts<C>, Error> {
    use iroha_pasta::CancellationToken;
    CancellationToken::checkpoint(cancellation)?;
    let vk_bytes = bounded_dimensions(original, binding, config)?;
    let vk_end = framed_vk_end(original, binding, vk_bytes)?;
    if key.descriptor_digest() != binding.digest() {
        return Err(Error::Profile);
    }
    let encoded = key.to_bytes();
    if encoded.len() != vk_bytes {
        return Err(Error::Length);
    }
    for (actual, expected) in original[HEADER..vk_end]
        .chunks(4096)
        .zip(encoded.chunks(4096))
    {
        CancellationToken::checkpoint(cancellation)?;
        if actual != expected {
            return Err(Error::Encoding);
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(OriginalParts {
        key: key.clone(),
        copy_digest: original[vk_end..vk_end + COPY_BYTES]
            .try_into()
            .map_err(|_| Error::Encoding)?,
        source_digest: original[vk_end + COPY_BYTES..]
            .try_into()
            .map_err(|_| Error::Length)?,
    })
}

/// Only called after `bounded_dimensions` checked the exact complete span.
fn framed_vk_end(
    original: &[u8],
    binding: &DescriptorBinding,
    vk_bytes: usize,
) -> Result<usize, Error> {
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
    Ok(vk_end)
}

/// Only called after `bounded_dimensions` checked the exact complete span.
fn original_parts<C: PastaCurve>(
    original: &[u8],
    binding: &DescriptorBinding,
    vk_bytes: usize,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<OriginalParts<C>, Error> {
    let vk_end = framed_vk_end(original, binding, vk_bytes)?;
    let key = VerifyingKey::<C>::read_cancellable(&original[HEADER..vk_end], binding, cancellation)
        .map_err(|error| Error::Key(KeyError::VerifyingKey(error)))?;
    let copy_digest = original[vk_end..vk_end + COPY_BYTES]
        .try_into()
        .map_err(|_| Error::Encoding)?;
    Ok(OriginalParts {
        key,
        copy_digest,
        source_digest: original[vk_end + COPY_BYTES..]
            .try_into()
            .map_err(|_| Error::Length)?,
    })
}

/// Read an untrusted original's lookup fingerprint without reconstructing a key.
///
/// Exact bounds, descriptor framing and canonical processed VK/selector encodings
/// are checked. The declared fingerprint is untrusted DATA: an attacker can keep
/// it while changing any other field, including a valid VK commitment.
/// It grants no authentication or source qualification. Matching only selects a
/// candidate for mandatory strict original admission, either to a full proving key
/// or through [`SourceBoundVerifyingKeyV2::from_artifact_v2_cancellable`].
///
/// # Errors
/// Incorrect profile, bounds, framing, points or selectors, or explicit cancellation.
pub fn source_fingerprint_v2<C: PastaCurve>(
    original: &[u8],
    binding: &DescriptorBinding,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<crate::keys::SourceFingerprintV2, Error> {
    use iroha_pasta::CancellationToken;
    CancellationToken::checkpoint(cancellation)?;
    let vk_bytes = bounded_dimensions(original, binding, config)?;
    let parts = original_parts::<C>(original, binding, vk_bytes, cancellation)?;
    CancellationToken::checkpoint(cancellation)?;
    Ok(crate::keys::SourceFingerprintV2::from_original(
        binding.clone(),
        parts.source_digest,
    ))
}

impl<C: PastaCurve> ProvingKey<C> {
    /// Encode the compact original V2 proving identity. Native source recreates
    /// tables, caches, masks and coefficients; import checks every original VK
    /// commitment before any source-admission capability can be minted.
    ///
    /// Layout: `PIPACPK1 || descriptor_digest32 || LE32 vk_bytes || vk ||
    /// copy_digest32 || source_fingerprint32`. There is no dense-format fallback.
    ///
    /// # Errors
    /// Wrong descriptor version, invalid shape or size arithmetic overflow.
    pub fn artifact_bytes_v2(&self) -> Result<Vec<u8>, Error> {
        let (vk_bytes, bytes) = dimensions(self.binding())?;
        let vk_len = u32::try_from(vk_bytes).map_err(|_| Error::Length)?;
        let original_vk = self.vk().to_bytes();
        if original_vk.len() != vk_bytes {
            return Err(Error::Length);
        }
        if self.fixed_values().len() != self.binding().descriptor().num_fixed_columns as usize
            || self.permutation_values().len() != self.binding().descriptor().permutation.len()
            || self
                .fixed_values()
                .iter()
                .chain(self.permutation_values())
                .any(|column| column.len() != self.binding().n())
        {
            return Err(Error::Length);
        }
        let fingerprint = crate::keys::source_fingerprint::from_tables(
            self.binding(),
            self.copy_digest(),
            self.vk().selectors().into(),
            self.fixed_values(),
            self.permutation_values(),
            None,
        )?;
        let mut out = Vec::with_capacity(bytes);
        out.extend(MAGIC);
        out.extend(self.binding().digest());
        out.extend(vk_len.to_le_bytes());
        out.extend(original_vk);
        out.extend(self.copy_digest());
        out.extend(fingerprint.digest());
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
        let vk_bytes = bounded_dimensions(original, binding, config)?;
        if params.k() != u32::from(binding.descriptor().k) {
            return Err(Error::Profile);
        }
        let OriginalParts {
            key,
            copy_digest,
            source_digest,
        } = original_parts::<C>(original, binding, vk_bytes, cancellation)?;
        keygen::import_artifact_v2(
            params,
            circuit,
            binding,
            key,
            copy_digest,
            source_digest,
            config,
            cancellation,
        )
    }
}

impl<C: PastaCurve> SourceBoundVerifyingKeyV2<C> {
    /// Admit exact native source and every original VK commitment, retaining only
    /// descriptor, verifier and opaque source authority. The caller authenticates
    /// the complete original bytes and fixes the installed descriptor first.
    ///
    /// This uses the same strict source and commitment checks as full PK import,
    /// but does not construct proving-only FFT coefficients, masks or coset caches.
    /// Actual proving reconstructs those buffers through the admitted source view.
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

    /// Strict metadata admission with cancellation; no partial capability escapes.
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
        let vk_bytes = bounded_dimensions(original, binding, config)?;
        if params.k() != u32::from(binding.descriptor().k) {
            return Err(Error::Profile);
        }
        let OriginalParts {
            key,
            copy_digest,
            source_digest,
        } = original_parts::<C>(original, binding, vk_bytes, cancellation)?;
        keygen::import_artifact_metadata_v2(
            params,
            circuit,
            binding,
            key,
            copy_digest,
            source_digest,
            config,
            cancellation,
        )
    }
}
