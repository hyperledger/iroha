//! One-synthesis preparation under an already admitted exact V2 source.

use iroha_pasta::{CancellationToken, PastaCurve};

use super::{ProverError, Witness, check_instances};
use crate::{
    frontend::{self, Circuit},
    keys::{
        CosetCachePolicy, ProvingKey, RebuildError, SourceBoundViewV2,
        keygen::{
            keygen_pk_from_synthesized_v2_cancellable, validate_rebuild_profile_v2_cancellable,
        },
    },
    pcs::ipa::PinnedParams,
    secret::SecretColumns,
    work_metrics::{WorkPhase, WorkTimer},
};

/// Failure to prepare a key and witness; neither partial owner is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildWitnessError {
    /// Opaque admission, exact source or proving-buffer reconstruction failed.
    Rebuild(RebuildError),
    /// Instance validation, actual synthesis or witness shape validation failed.
    Witness(ProverError),
}
impl RebuildWitnessError {
    /// Whether this is cooperative cancellation, not an invalid-proof verdict.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Rebuild(error) => error.is_cancelled(),
            Self::Witness(error) => error.is_cancelled(),
        }
    }
}
impl From<RebuildError> for RebuildWitnessError {
    fn from(error: RebuildError) -> Self {
        Self::Rebuild(error)
    }
}
impl From<ProverError> for RebuildWitnessError {
    fn from(error: ProverError) -> Self {
        Self::Witness(error)
    }
}
impl core::fmt::Display for RebuildWitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rebuild(error) => core::fmt::Display::fmt(error, f),
            Self::Witness(error) => core::fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for RebuildWitnessError {}

/// Prepare a source-bound V2 key and its witness with one actual synthesis.
///
/// The borrowed opaque source seal must already come from strict admission or
/// fresh exact compiled-source admission. Its descriptor, verifier and pinned
/// parameter identities are checked before synthesis. Exact instance lengths
/// and types are checked before witness allocation. The actual synthesis's
/// fixed values, selectors, copy mapping and permutation tables must match the
/// complete sealed source; witness-dependent public-source changes are rejected.
///
/// Advice moves immediately to a zeroizing owner before instance copying or
/// fallible source reconstruction. No witness or proving key is cached. Callers
/// must drop both at their existing memory and preemption boundaries. This does
/// not check circuit satisfiability or accept a proof: normal proof generation,
/// full self-verification, custody and durable-commit obligations still apply.
/// The separate witnessless reconstruction API retains its existing contract.
///
/// # Errors
/// [`RebuildWitnessError::Rebuild`] for admission/source/parameter mismatches or
/// reconstruction failures, and [`RebuildWitnessError::Witness`] for instance,
/// synthesis and witness-shape failures. Cancellation returns no partial owner.
pub fn rebuild_key_and_witness_v2_cancellable<C, Ci>(
    params: &PinnedParams<C>,
    circuit: &Ci,
    verifier: &SourceBoundViewV2<'_, C>,
    instances: &[Vec<C::ScalarExt>],
    coset_cache: CosetCachePolicy,
    cancellation: Option<&CancellationToken>,
) -> Result<(ProvingKey<C>, Witness<C::ScalarExt>), RebuildWitnessError>
where
    C: PastaCurve,
    Ci: Circuit<C::ScalarExt>,
{
    {
        let _timer = WorkTimer::start(WorkPhase::KeyRebuild);
        validate_rebuild_profile_v2_cancellable(params, verifier, coset_cache, cancellation)?;
    }
    {
        let _timer = WorkTimer::start(WorkPhase::Witness);
        check_instances(verifier.binding().descriptor(), instances)?;
    }
    let (synthesized, witness) = {
        let _timer = WorkTimer::start(WorkPhase::Witness);
        let mut synthesized =
            frontend::synthesize_cancellable(circuit, params.k(), Some(instances), cancellation)
                .map_err(ProverError::from)?;
        let advice = SecretColumns::new(
            synthesized
                .tables
                .take_advice()
                .ok_or_else(|| ProverError::from(frontend::Error::WitnessRequired))?,
        );
        // Keep `advice` guarded if allocation of the public instance copy unwinds.
        let instances = instances.to_vec();
        let witness = Witness {
            advice: advice.into_vec(),
            instances,
        };
        (synthesized, witness)
    };
    finish_rebuild(
        params,
        synthesized,
        witness,
        verifier,
        coset_cache,
        cancellation,
    )
}

fn finish_rebuild<C: PastaCurve>(
    params: &PinnedParams<C>,
    synthesized: frontend::Synthesized<C::ScalarExt>,
    witness: Witness<C::ScalarExt>,
    verifier: &SourceBoundViewV2<'_, C>,
    coset_cache: CosetCachePolicy,
    cancellation: Option<&CancellationToken>,
) -> Result<(ProvingKey<C>, Witness<C::ScalarExt>), RebuildWitnessError> {
    let key = keygen_pk_from_synthesized_v2_cancellable(
        params,
        synthesized,
        verifier,
        coset_cache,
        cancellation,
    )?;
    {
        let _timer = WorkTimer::start(WorkPhase::Witness);
        witness.check_shape(&key)?;
        CancellationToken::checkpoint(cancellation).map_err(ProverError::from)?;
    }
    Ok((key, witness))
}

// Test-only post-wipe observations never retain a field value, pointer or witness.
#[cfg(test)]
thread_local! {
    static WIPED_WITNESS: std::cell::Cell<Option<(usize, bool)>> = const {
        std::cell::Cell::new(None)
    };
}
#[cfg(test)]
pub(super) fn observe_wiped_witness<F: iroha_pasta::PastaField>(advice: &[Vec<F>]) {
    WIPED_WITNESS.with(|state| {
        if let Some((count, all_zero)) = state.get() {
            state.set(Some((
                count + advice.iter().map(Vec::len).sum::<usize>(),
                all_zero && advice.iter().flatten().all(|value| *value == F::ZERO),
            )));
        }
    });
}

#[cfg(test)]
mod tests;
