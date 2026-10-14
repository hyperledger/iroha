//! Lookup DATA for locating untrusted original keys, never source qualification.

use crate::pcs::ipa::HashedPublicColumn;
use iroha_pasta::CancellationToken;
use sha2::{Digest as _, Sha256};

use super::{DescriptorBinding, vk::SelectorBitmaps};

/// The same selector stream, from native synthesis or an admitted packed VK.
#[derive(Clone, Copy)]
pub(super) enum SelectorSource<'a> {
    Expanded(&'a [Vec<bool>]),
    Packed(SelectorBitmaps<'a>),
}

impl<'a> From<&'a [Vec<bool>]> for SelectorSource<'a> {
    fn from(rows: &'a [Vec<bool>]) -> Self {
        Self::Expanded(rows)
    }
}

impl<'a> From<SelectorBitmaps<'a>> for SelectorSource<'a> {
    fn from(rows: SelectorBitmaps<'a>) -> Self {
        Self::Packed(rows)
    }
}

/// An engineering lookup identity for exact witnessless V2 source tables.
///
/// Equality only selects an untrusted candidate. It does not authenticate a key,
/// check its commitments, or grant a compiled/source-qualified capability. The
/// caller must still strictly admit the complete original against its installed
/// source using [`super::SourceBoundVerifyingKeyV2::from_artifact_v2_cancellable`]
/// or [`super::ProvingKey::from_artifact_v2_cancellable`]. Both validate native
/// source and every original commitment; fingerprint equality grants neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFingerprintV2 {
    binding: DescriptorBinding,
    digest: [u8; 32],
}

impl SourceFingerprintV2 {
    /// Decode lookup DATA only; no source or commitment admission follows.
    pub(super) fn from_original(binding: DescriptorBinding, digest: [u8; 32]) -> Self {
        Self { binding, digest }
    }

    /// The exact descriptor used for lookup; its presence does not authenticate a key.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }

    /// The framed public-source hash, usable only as an untrusted candidate index.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Hash exact native tables using the same framing for export, import and rebuild.
pub(super) fn from_tables<F: iroha_pasta::PastaField>(
    binding: &DescriptorBinding,
    copy_digest: &[u8; 32],
    selectors: SelectorSource<'_>,
    fixed: &[Vec<F>],
    sigma: &[Vec<F>],
    cancellation: Option<&CancellationToken>,
) -> Result<SourceFingerprintV2, super::KeyError> {
    let mut hash = SourceHasher::new(binding, copy_digest, selectors, cancellation)?;
    for column in fixed.iter().chain(sigma) {
        for (index, value) in column.iter().enumerate() {
            if index % 1024 == 0 {
                CancellationToken::checkpoint(cancellation)?;
            }
            hash.scalar(value.to_repr().as_ref());
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(hash.finish(binding.clone()))
}

/// Hash source and column streams from one canonicalization of immutable tables.
/// Handles are ephemeral DATA; only subsequent commitment checks admit source.
pub(super) fn from_tables_with_columns<'a, F: iroha_pasta::PastaField>(
    binding: &DescriptorBinding,
    copy_digest: &[u8; 32],
    selectors: SelectorSource<'_>,
    fixed: &'a [Vec<F>],
    sigma: &'a [Vec<F>],
    cancellation: Option<&CancellationToken>,
) -> Result<(SourceFingerprintV2, Vec<HashedPublicColumn<'a, F>>), super::KeyError> {
    let mut hash = SourceHasher::new(binding, copy_digest, selectors, cancellation)?;
    let columns = fixed
        .iter()
        .chain(sigma)
        .map(|values| {
            HashedPublicColumn::with_canonical_sink(
                values,
                |bytes| hash.scalar(bytes),
                cancellation,
            )
            .map_err(super::KeyError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    CancellationToken::checkpoint(cancellation)?;
    Ok((hash.finish(binding.clone()), columns))
}

/// Both producers stream the same canonical table bytes after this public prefix.
pub(super) struct SourceHasher(Sha256);

impl SourceHasher {
    pub(super) fn new(
        binding: &DescriptorBinding,
        copy_digest: &[u8; 32],
        selectors: SelectorSource<'_>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, iroha_pasta::Cancelled> {
        CancellationToken::checkpoint(cancellation)?;
        let mut hash = Sha256::new();
        hash.update(b"iroha:pipa:source-lookup:v1\0");
        hash.update((binding.encoded().len() as u64).to_le_bytes());
        hash.update(binding.encoded());
        hash.update(copy_digest);
        hash.update(u64::from(binding.descriptor().num_fixed_columns).to_le_bytes());
        hash.update((binding.descriptor().permutation.len() as u64).to_le_bytes());
        hash.update((binding.n() as u64).to_le_bytes());
        match selectors {
            SelectorSource::Expanded(selectors) => {
                hash.update((selectors.len() as u64).to_le_bytes());
                for rows in selectors {
                    hash.update((rows.len() as u64).to_le_bytes());
                    for (index, chunk) in rows.chunks(8).enumerate() {
                        if index % 128 == 0 {
                            CancellationToken::checkpoint(cancellation)?;
                        }
                        let byte = chunk.iter().enumerate().fold(0_u8, |byte, (bit, enabled)| {
                            byte | (u8::from(*enabled) << bit)
                        });
                        hash.update([byte]);
                    }
                }
            }
            SelectorSource::Packed(selectors) => {
                hash.update((selectors.len() as u64).to_le_bytes());
                for rows in selectors.iter() {
                    hash.update((rows.len() as u64).to_le_bytes());
                    for chunk in rows.packed_bytes().chunks(128) {
                        CancellationToken::checkpoint(cancellation)?;
                        hash.update(chunk);
                    }
                }
            }
        }
        Ok(Self(hash))
    }

    pub(super) fn scalar(&mut self, canonical: &[u8]) {
        self.0.update(canonical);
    }

    pub(super) fn finish(self, binding: DescriptorBinding) -> SourceFingerprintV2 {
        SourceFingerprintV2 {
            binding,
            digest: self.0.finalize().into(),
        }
    }
}

#[cfg(test)]
mod tests;
