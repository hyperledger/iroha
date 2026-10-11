//! Temporary source-bound proving buffers for native A/W owners.
//!
//! Strict original admission remains in each family importer. The live circuit's
//! witnessless value is DATA: reconstruction must match the previously admitted
//! descriptor, verifier and full fixed/selector/copy/sigma source commitment.
//! No proving buffers survive this call, including on cancellation or failure.

use iroha_pasta::{CancellationToken, PastaCurve};
use iroha_plonk::{
    ProverConfig, ProverOutput, ProverRandomness, Witness, create_proof_owned_with_claim,
    frontend::Circuit,
    keys::{CosetCachePolicy, SourceBoundViewV2, keygen_pk_from_vk_v2_cancellable},
    pcs::ipa::PinnedParams,
};

/// Native family classification; no failure becomes a soft incoming verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Cooperative cancellation before a completed proof.
    Cancelled,
    /// Reconstruction does not match the strictly admitted source identity.
    Artifact,
    /// Actual witness assignment or proof generation failed.
    Prover,
}

/// Rebuild the exact admitted source, consume its witness, and release the PK.
/// Family owners perform their unchanged full verification and decisions only
/// after this returns. No caller-owned PK can extend through that verification.
pub(super) fn prove<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    params: &PinnedParams<C>,
    metadata: &SourceBoundViewV2<'_, C>,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<ProverOutput<C>, Error> {
    CancellationToken::checkpoint(config.cancellation).map_err(|_| Error::Cancelled)?;
    let source = circuit.without_witnesses();
    let key = keygen_pk_from_vk_v2_cancellable(
        params,
        &source,
        metadata,
        CosetCachePolicy::OnDemand,
        config.cancellation,
    )
    .map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Artifact
        }
    })?;
    drop(source);
    let witness = Witness::from_circuit_cancellable(&key, circuit, instances, config.cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Prover
            }
        })?;
    let output = create_proof_owned_with_claim(params, &key, witness, randomness, config).map_err(
        |error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Prover
            }
        },
    )?;
    drop(key);
    Ok(output)
}
