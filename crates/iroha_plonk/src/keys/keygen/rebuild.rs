//! Rebuild exact source-bound V2 proving buffers without repeating commitment MSMs.
//!
//! A decoded VK or lookup fingerprint cannot authorize this path. The opaque
//! capability is minted only from a completed native key or strictly imported
//! original. It retains public identity, never proving polynomials or witnesses.
//! Original artifact admission remains unchanged and mandatory for untrusted DATA.

use super::*;
use sha2::{Digest as _, Sha256};

/// Exact-source proving-key reconstruction failed; no partial key is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildError {
    /// Native synthesis, hashing, transform or cancellation failure.
    Key(KeyError),
    /// The V2 descriptor, canonical VK or pinned parameter identity differs.
    Profile,
    /// The exact fixed, selector, copy or permutation source differs.
    Source,
}

impl RebuildError {
    /// Whether reconstruction ended on cooperative cancellation.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Key(error) if error.is_cancelled())
    }
}
impl From<KeyError> for RebuildError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}
impl From<iroha_pasta::Cancelled> for RebuildError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Key(KeyError::Cancelled)
    }
}
impl core::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Key(error) => write!(f, "proving-key reconstruction: {error}"),
            Self::Profile => f.write_str("proving-key reconstruction identity mismatch"),
            Self::Source => f.write_str("proving-key reconstruction source mismatch"),
        }
    }
}
impl std::error::Error for RebuildError {}

/// Compact exact-source authority minted only from a completed proving key.
///
/// This seal retains three digests and no descriptor, verifier, parameter arrays,
/// polynomial or witness. It is not serializable and has no raw-parts constructor.
/// Native key generation, strict original import and exact reconstruction are all
/// completed-key authorities; deployment and installed-source custody are separate.
#[derive(Clone, Debug)]
pub struct SourceAdmissionSealV2<C: PastaCurve> {
    descriptor_digest: [u8; 32],
    key_sha256: [u8; 32],
    source_digest: [u8; 32],
    curve: core::marker::PhantomData<C>,
}

/// Exact public metadata borrowed after checking it against its opaque seal.
/// Private fields prevent raw public metadata from authorizing reconstruction.
#[derive(Clone, Copy, Debug)]
pub struct SourceBoundViewV2<'a, C: PastaCurve> {
    seal: &'a SourceAdmissionSealV2<C>,
    binding: &'a DescriptorBinding,
    key: &'a VerifyingKey<C>,
}
impl<'a, C: PastaCurve> SourceBoundViewV2<'a, C> {
    /// Exact descriptor bound to this admitted source.
    #[must_use]
    pub const fn binding(&self) -> &'a DescriptorBinding {
        self.binding
    }
    /// Exact canonical verifier bound to this admitted source.
    #[must_use]
    pub const fn verifying_key(&self) -> &'a VerifyingKey<C> {
        self.key
    }
}

/// Standalone public metadata owner with compact exact-source authority.
/// Installed callers can consume this value and retain its seal beside existing
/// public metadata instead of cloning descriptor/verifier graphs per stage.
#[derive(Clone, Debug)]
pub struct SourceBoundVerifyingKeyV2<C: PastaCurve> {
    binding: DescriptorBinding,
    key: VerifyingKey<C>,
    seal: SourceAdmissionSealV2<C>,
}

fn key_digest<C: PastaCurve>(
    key: &VerifyingKey<C>,
    cancellation: Option<&CancellationToken>,
) -> Result<[u8; 32], KeyError> {
    let mut hash = Sha256::new();
    for chunk in key.to_bytes().chunks(4096) {
        CancellationToken::checkpoint(cancellation)?;
        hash.update(chunk);
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(hash.finalize().into())
}

fn source_digest<F: PastaField>(
    binding: &DescriptorBinding,
    copy_digest: &[u8; 32],
    selectors: &[Vec<bool>],
    fixed: &[Vec<F>],
    sigma: &[Vec<F>],
    cancellation: Option<&CancellationToken>,
) -> Result<[u8; 32], KeyError> {
    let mut hash = super::super::source_fingerprint::SourceHasher::new(
        binding,
        copy_digest,
        selectors,
        cancellation,
    )?;
    for column in fixed.iter().chain(sigma) {
        for (index, value) in column.iter().enumerate() {
            if index % 1024 == 0 {
                CancellationToken::checkpoint(cancellation)?;
            }
            hash.scalar(value.to_repr().as_ref());
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(*hash.finish(binding.clone()).digest())
}

impl<C: PastaCurve> SourceAdmissionSealV2<C> {
    /// Mint exact source authority from a fully constructed V2 proving key.
    /// No proving buffers, descriptor or verifier are cloned or retained.
    /// # Errors
    /// A non-V2/inconsistent key, or cancellation while hashing source tables.
    pub fn from_proving_key(
        key: &ProvingKey<C>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, RebuildError> {
        CancellationToken::checkpoint(cancellation)?;
        if !key.binding().is_v2() || key.vk().descriptor_digest() != key.binding().digest() {
            return Err(RebuildError::Profile);
        }
        let source_digest = source_digest(
            key.binding(),
            key.copy_digest(),
            key.vk().selectors(),
            key.fixed_values(),
            key.permutation_values(),
            cancellation,
        )?;
        Ok(Self {
            descriptor_digest: *key.binding().digest(),
            key_sha256: key_digest(key.vk(), cancellation)?,
            source_digest,
            curve: core::marker::PhantomData,
        })
    }

    /// Borrow existing metadata only after exact V2 descriptor and VK checks.
    /// This authenticates engine source identity, not an installation or file store.
    /// # Errors
    /// Non-V2/foreign descriptor or verifier, or cooperative cancellation.
    pub fn bind<'a>(
        &'a self,
        binding: &'a DescriptorBinding,
        key: &'a VerifyingKey<C>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, C>, RebuildError> {
        CancellationToken::checkpoint(cancellation)?;
        if !binding.is_v2()
            || binding.digest() != &self.descriptor_digest
            || key.descriptor_digest() != binding.digest()
            || key_digest(key, cancellation)? != self.key_sha256
        {
            return Err(RebuildError::Profile);
        }
        Ok(SourceBoundViewV2 {
            seal: self,
            binding,
            key,
        })
    }
}

impl<C: PastaCurve> SourceBoundVerifyingKeyV2<C> {
    /// Own exact public metadata from a completed validated proving key.
    /// # Errors
    /// A non-V2/inconsistent key, or cancellation while hashing source tables.
    pub fn from_proving_key(
        key: &ProvingKey<C>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, RebuildError> {
        let seal = SourceAdmissionSealV2::from_proving_key(key, cancellation)?;
        Ok(Self {
            binding: key.binding().clone(),
            key: key.vk().clone(),
            seal,
        })
    }
    /// Exact descriptor retained from the validated proving key.
    #[must_use]
    pub const fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }
    /// Exact verifier retained from the validated proving key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey<C> {
        &self.key
    }
    /// Borrow this owner's immutable metadata without cloning public graphs.
    /// The infallible view preserves the privately minted immutable D/V/seal
    /// invariant; it cannot wrap arbitrary metadata. Reconstruction rechecks it.
    #[must_use]
    pub fn view(&self) -> SourceBoundViewV2<'_, C> {
        SourceBoundViewV2 {
            seal: &self.seal,
            binding: &self.binding,
            key: &self.key,
        }
    }
    /// Move exact public metadata and its seal into an installed owner's storage.
    #[must_use]
    pub fn into_parts(self) -> (DescriptorBinding, VerifyingKey<C>, SourceAdmissionSealV2<C>) {
        (self.binding, self.key, self.seal)
    }
}

/// Rebuild V2 proving polynomials from the same witnessless compiled source.
///
/// This performs synthesis, selector finalization, copy/sigma reconstruction,
/// source hashing and FFTs, but no commitment MSMs and no commitment-table build.
/// The caller owns the buffers and must drop them at its memory/preemption boundary.
///
/// # Errors
/// Another source or parameter identity, native preparation/FFT errors.
pub fn keygen_pk_from_vk_v2<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    params: &PinnedParams<C>,
    circuit: &Ci,
    verifier: &SourceBoundViewV2<'_, C>,
    coset_cache: CosetCachePolicy,
) -> Result<ProvingKey<C>, RebuildError> {
    keygen_pk_from_vk_v2_cancellable(params, circuit, verifier, coset_cache, None)
}

/// Rebuild with cancellation at synthesis, source hashing and transform boundaries.
/// Untrusted original bytes must still enter the ordinary strict artifact importer.
///
/// # Errors
/// As [`keygen_pk_from_vk_v2`], or cancellation without a partial key/capability.
pub fn keygen_pk_from_vk_v2_cancellable<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    params: &PinnedParams<C>,
    circuit: &Ci,
    verifier: &SourceBoundViewV2<'_, C>,
    coset_cache: CosetCachePolicy,
    cancellation: Option<&CancellationToken>,
) -> Result<ProvingKey<C>, RebuildError> {
    CancellationToken::checkpoint(cancellation)?;
    let descriptor = verifier.binding.descriptor();
    // PinnedParams has only transparent derivation or exact pinned-byte admission;
    // its immutable curve/k select the one parameter set named by the descriptor.
    // No serialization/re-hash of multi-MiB parameter arrays is necessary here.
    if !verifier.binding.is_v2()
        || verifier.binding.digest() != &verifier.seal.descriptor_digest
        || params.curve() != descriptor.curve
        || params.k() != u32::from(descriptor.k)
        || crate::cs::descriptor::pinned_params_digest(params.curve(), params.k())
            != Some(descriptor.params_digest)
        || verifier.key.descriptor_digest() != verifier.binding.digest()
        || key_digest(verifier.key, cancellation)? != verifier.seal.key_sha256
    {
        return Err(RebuildError::Profile);
    }
    let profile = KeygenConfigV2 {
        transcript: descriptor.transcript,
        instance_mode: descriptor.instance_mode,
        proof_suffix: descriptor.proof_suffix,
        instance_types: descriptor
            .instance_types
            .clone()
            .ok_or(RebuildError::Profile)?,
        compress_selectors: descriptor.selectors.compress,
        coset_cache,
        table_budget: None,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let synthesized = crate::frontend::synthesize_cancellable(
        &circuit.without_witnesses(),
        params.k(),
        None,
        cancellation,
    )
    .map_err(KeyError::from)?;
    let (fixed, selectors, permutation) = synthesized.tables.into_keygen_parts();
    let prepared = prepare_cancellable(
        params,
        synthesized.cs,
        fixed,
        selectors,
        &permutation,
        &profile.layout_options(),
        Some(&profile),
        cancellation,
    )?;
    drop(permutation);
    if prepared.binding != *verifier.binding {
        return Err(RebuildError::Profile);
    }
    if prepared.vk_selectors != verifier.key.selectors()
        || source_digest(
            &prepared.binding,
            &prepared.copy_digest,
            &prepared.vk_selectors,
            &prepared.fixed,
            &prepared.sigma,
            cancellation,
        )? != verifier.seal.source_digest
    {
        return Err(RebuildError::Source);
    }
    CancellationToken::checkpoint(cancellation)?;
    ProvingKey::new_cancellable(
        (*verifier.key).clone(),
        prepared.binding,
        prepared.constraint_system,
        prepared.fixed,
        prepared.sigma,
        prepared.copy_digest,
        coset_cache,
        CommitmentTables::none(),
        cancellation,
    )
    .map_err(RebuildError::from)
}

#[cfg(test)]
mod tests;
