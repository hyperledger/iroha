//! Instances and advice (spec 6.3 and section 7, row 1; `BlindingScheduleV1`
//! item 1).
//!
//! - Instance columns are zero-padded to `n` rows. In Committed mode each is
//!   committed in evaluation form with the default blind (`... + W`) and
//!   absorbed as a common point; in Direct mode every value is absorbed as a
//!   common scalar, column-major. Both forms keep the coefficient form for
//!   the quotient and the openings.
//! - Advice columns get random values on rows `u..n` (column by column),
//!   then one random blind per column, and are committed in evaluation form
//!   with the secret MSM posture and written to the proof in column order.

use iroha_pasta::CancellationToken;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};
use rand_core_06::RngCore;
use rayon::prelude::*;

use super::{ProverError, random_values, write_point};
use crate::{
    keys::ProvingKey,
    pcs::ipa::{PinnedParams, commit::Secrecy},
    protocol::Shape,
    transcript::{Transcript, TranscriptWrite},
};

// Public shape only: at k >= 8, four rows use at most 4n products, while
// the current coset FFT uses nk/2 + 1. Smaller domains keep the dense path.
const SHORT_INSTANCE_PREFIX_MAX: usize = 4;
const SHORT_INSTANCE_MIN_N: usize = 1 << 8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ShortInstancePrefix<F> {
    values: [F; SHORT_INSTANCE_PREFIX_MAX],
    len: usize,
}

/// The instance columns in both forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InstanceColumns<F> {
    /// Zero-padded evaluation form (`n` rows each).
    pub(super) values: Vec<Vec<F>>,
    /// Coefficient form.
    polys: Vec<Vec<F>>,
    // Captured from the same immutable input used to interpolate `polys`.
    // No n-row evaluation buffer is retained for this optimization.
    short_prefixes: Vec<Option<ShortInstancePrefix<F>>>,
    /// The unpadded lengths.
    lengths: Vec<usize>,
}

/// Interpolates public prefixes of length at most two into the existing
/// coefficient buffer. Longer or oversized prefixes leave it untouched and
/// retain the caller's dense IFFT. The constructor supplies the same original
/// input that produced its padded column; this is not a public coefficient API.
///
/// c_i = n^-1 sum_j a_j omega^(-ij). A one-element prefix is constant;
/// a two-element prefix adds one geometric sequence. Shape, never values,
/// selects the path. All Rayon work joins before cancellation is returned.
fn interpolate_short_instance<F: iroha_pasta::PastaField>(
    domain: &iroha_pasta::fft::FftDomain<F>,
    prefix: &[F],
    coefficients: &mut [F],
    cancellation: Option<&CancellationToken>,
) -> Result<bool, iroha_pasta::fft::FftError> {
    use iroha_pasta::fft::FftError;
    CancellationToken::checkpoint(cancellation)?;
    if coefficients.len() != domain.n() {
        return Err(FftError::WrongLength {
            expected: domain.n(),
            actual: coefficients.len(),
        });
    }
    if prefix.len() > 2 || prefix.len() > domain.n() {
        return Ok(false);
    }
    let constant = prefix.first().copied().unwrap_or(F::ZERO) * domain.n_inv();
    let linear = prefix
        .get(1)
        .map(|value| (*value * domain.n_inv(), domain.omega_inv()));
    coefficients
        .par_chunks_mut(1024)
        .enumerate()
        .try_for_each(|(chunk, output)| {
            interpolate_short_instance_chunk(output, chunk * 1024, constant, linear, cancellation)
        })?;
    CancellationToken::checkpoint(cancellation)?;
    Ok(true)
}

/// Each bounded chunk checks cancellation before modifying its output.
fn interpolate_short_instance_chunk<F: iroha_pasta::PastaField>(
    output: &mut [F],
    start: usize,
    constant: F,
    linear: Option<(F, F)>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), iroha_pasta::fft::FftError> {
    CancellationToken::checkpoint(cancellation)?;
    if let Some((scale, step)) = linear {
        let mut term = scale * step.pow_vartime([start as u64]);
        for value in output {
            *value = constant + term;
            term *= step;
        }
    } else {
        output.fill(constant);
    }
    Ok(())
}

impl<F: iroha_pasta::PastaField> InstanceColumns<F> {
    /// Pads and interpolates the instance columns of a witness.
    ///
    /// # Errors
    ///
    /// [`ProverError::Fft`] on a transform failure.
    pub(super) fn new<C: PastaCurve<ScalarExt = F>>(
        pk: &ProvingKey<C>,
        instances: &[Vec<F>],
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, ProverError> {
        let n = pk.binding().n();
        let short_prefixes = if n >= SHORT_INSTANCE_MIN_N
            && instances
                .iter()
                .any(|column| column.len() <= SHORT_INSTANCE_PREFIX_MAX)
        {
            instances
                .iter()
                .map(|column| {
                    (column.len() <= SHORT_INSTANCE_PREFIX_MAX).then(|| {
                        let mut values = [F::ZERO; SHORT_INSTANCE_PREFIX_MAX];
                        values[..column.len()].copy_from_slice(column);
                        ShortInstancePrefix {
                            values,
                            len: column.len(),
                        }
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let values: Vec<Vec<F>> = instances
            .iter()
            .map(|column| {
                let mut padded = column.clone();
                padded.resize(n, F::ZERO);
                padded
            })
            .collect();
        let polys = values
            .iter()
            .zip(instances)
            .map(|(column, prefix)| {
                let mut coeffs = column.clone();
                if !interpolate_short_instance(pk.domain(), prefix, &mut coeffs, cancellation)? {
                    pk.domain().ifft_cancellable(&mut coeffs, cancellation)?;
                }
                Ok(coeffs)
            })
            .collect::<Result<Vec<_>, ProverError>>()?;
        Ok(Self {
            values,
            polys,
            short_prefixes,
            lengths: instances.iter().map(Vec::len).collect(),
        })
    }

    /// The original coefficients, also used by every instance opening.
    pub(super) fn polys(&self) -> &[Vec<F>] {
        &self.polys
    }

    pub(super) fn has_short_prefixes(&self) -> bool {
        !self.short_prefixes.is_empty()
    }

    /// Only this owner can pair a retained prefix with its interpolated polynomial.
    pub(super) fn short_prefix(&self, column: usize) -> Option<&[F]> {
        self.short_prefixes
            .get(column)
            .and_then(Option::as_ref)
            .map(|prefix| &prefix.values[..prefix.len])
    }

    /// Absorbs the instances (spec 6.3 step 3).
    ///
    /// # Errors
    ///
    /// [`ProverError::IdentityInstanceCommitment`] for an identity
    /// commitment (negligible: the default blind adds `W`).
    pub(super) fn absorb<C, T>(
        &self,
        params: &PinnedParams<C>,
        shape: &Shape,
        transcript: &mut T,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
        T: Transcript<C>,
    {
        CancellationToken::checkpoint(cancellation)?;
        if shape.committed_instances {
            for (column, (values, length)) in self.values.iter().zip(&self.lengths).enumerate() {
                CancellationToken::checkpoint(cancellation)?;
                let commitment = crate::protocol::instance_commitment_cancellable(
                    params,
                    &values[..*length],
                    budget,
                    cancellation,
                )?;
                transcript
                    .common_point(&commitment)
                    .map_err(|_| ProverError::IdentityInstanceCommitment { column })?;
            }
        } else {
            for (values, length) in self.values.iter().zip(&self.lengths) {
                for (index, value) in values[..*length].iter().enumerate() {
                    if index % 1024 == 0 {
                        CancellationToken::checkpoint(cancellation)?;
                    }
                    transcript.common_scalar(value);
                }
            }
        }
        Ok(())
    }
}

/// The committed advice columns.
pub(super) struct Advice<F: iroha_pasta::PastaField> {
    /// Evaluation form with the blinding rows (`n` rows each).
    pub(super) values: Vec<Vec<F>>,
    /// Coefficient form.
    pub(super) polys: Vec<Vec<F>>,
    /// The commitment blinds.
    pub(super) blinds: Vec<F>,
}

impl<F: iroha_pasta::PastaField> Drop for Advice<F> {
    fn drop(&mut self) {
        for value in self
            .values
            .iter_mut()
            .chain(self.polys.iter_mut())
            .flatten()
            .chain(self.blinds.iter_mut())
        {
            value.zeroize();
        }
    }
}

impl<F: iroha_pasta::PastaField> Advice<F> {
    /// Reuses the evaluation buffers for coefficients once all products
    /// have consumed the evaluations. The zeroizing owner retains every
    /// column even if a transform fails partway through.
    pub(super) fn interpolate_in_place<C: PastaCurve<ScalarExt = F>>(
        &mut self,
        pk: &ProvingKey<C>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), ProverError> {
        self.polys = core::mem::take(&mut self.values);
        self.polys
            .par_iter_mut()
            .try_for_each(|column| pk.domain().ifft_cancellable(column, cancellation))?;
        Ok(())
    }
}

/// Blinds, commits and writes the advice columns (`BlindingScheduleV1` item
/// 1).
///
/// # Errors
///
/// [`ProverError::Msm`] or [`ProverError::Transcript`].
#[allow(clippy::too_many_arguments)]
pub(super) fn commit<C, T, R>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    shape: &Shape,
    values: Vec<Vec<C::ScalarExt>>,
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Advice<C::ScalarExt>, ProverError>
where
    C: PastaCurve,
    T: TranscriptWrite<C>,
    R: RngCore,
{
    let mut advice = Advice {
        values,
        polys: Vec::new(),
        blinds: Vec::new(),
    };
    let blinding_rows = shape.n - shape.usable_rows;
    for column in &mut advice.values {
        CancellationToken::checkpoint(cancellation)?;
        let random = crate::secret::SecretPolynomial::new(random_values::<C::ScalarExt, _>(
            rng,
            blinding_rows,
        ));
        column[shape.usable_rows..].copy_from_slice(&random);
    }
    advice.blinds = random_values(rng, shape.num_advice);
    let tables = pk.commitment_tables();
    let commitments = advice
        .values
        .par_iter()
        .zip(advice.blinds.par_iter())
        .map(|(values, blind)| {
            tables
                .commit_lagrange_cancellable(
                    params.params(),
                    values,
                    blind,
                    Secrecy::Secret,
                    budget,
                    cancellation,
                )
                .map(|point| point.to_affine())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for commitment in &commitments {
        write_point(transcript, commitment)?;
    }
    Ok(advice)
}

#[cfg(test)]
#[path = "advice/short_instance_coefficients_tests.rs"]
mod short_instance_coefficients_tests;
