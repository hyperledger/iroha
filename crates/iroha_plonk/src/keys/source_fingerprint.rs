//! Lookup DATA for locating untrusted original keys, never source qualification.

use iroha_pasta::CancellationToken;
use sha2::{Digest as _, Sha256};

use super::DescriptorBinding;

/// An engineering lookup identity for exact witnessless V2 source tables.
///
/// Equality only selects an untrusted candidate. It does not authenticate a key,
/// check its commitments, or grant a compiled/source-qualified capability. The
/// caller must still strictly import the complete original against its installed
/// source using [`super::ProvingKey::from_artifact_v2_cancellable`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFingerprintV2 {
    binding: DescriptorBinding,
    digest: [u8; 32],
}

impl SourceFingerprintV2 {
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

/// Both producers stream the same canonical table bytes after this public prefix.
pub(super) struct SourceHasher(Sha256);

impl SourceHasher {
    pub(super) fn new(
        binding: &DescriptorBinding,
        copy_digest: &[u8; 32],
        selectors: &[Vec<bool>],
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
