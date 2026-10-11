//! The evaluations and the opening (spec section 7 rows 7-16, section 9).
//!
//! After `x` the prover writes, in order: the instance evaluations
//! (Committed mode only), the advice and fixed evaluations in query order,
//! `R(x)`, every `sigma_j(x)`, per permutation set `z_s(x)`, `z_s(omega x)`
//! and (all but the last set) `z_s(omega^{-(b+1)} x)`, and per lookup `z(x)`,
//! `z(omega x)`, `A'(x)`, `A'(omega^{-1} x)`, `S'(x)`.
//!
//! The opening then runs the multiopen over the static plan of
//! [`crate::protocol::Protocol`]: every plan slot is mapped to its
//! polynomial and blind by kind and index, never by commitment value (S1).
//! Fixed, `sigma` and instance polynomials carry the default blind (one),
//! as their commitments do. The IPA returns the folded generator `G'_0`.

use iroha_pasta::CancellationToken;
use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget};
use rand_core_06::{CryptoRng, RngCore};

use super::{
    ProverError,
    advice::{Advice, InstanceColumns},
    lookup::Committed as LookupCommitted,
    permutation::ProductSet,
    vanishing::{CombinedQuotient, RandomPoly},
};
use crate::{
    keys::{KeyError, ProvingKey},
    pcs::{
        ipa::{PinnedParams, evaluate_polynomial},
        multiopen::{
            Slot, SlotKind,
            prover::{SlotPolynomial, create_proof_with_claim_cancellable},
        },
    },
    protocol::{Protocol, rotate},
    transcript::TranscriptWrite,
};

/// Every committed polynomial of a proof, ready to be evaluated and opened.
pub(super) struct Opened<'a, F: PastaField> {
    /// The instance columns.
    pub(super) instance: &'a InstanceColumns<F>,
    /// The advice columns.
    pub(super) advice: &'a Advice<F>,
    /// The permutation products.
    pub(super) products: &'a [ProductSet<F>],
    /// The lookups.
    pub(super) lookups: &'a [LookupCommitted<F>],
    /// `R`.
    pub(super) random: &'a RandomPoly<F>,
    /// `h` combined at `x^n`.
    pub(super) quotient: CombinedQuotient<F>,
}

/// A polynomial by `u32` index.
fn indexed<T>(items: &[T], index: impl TryInto<usize>) -> Result<&T, ProverError> {
    index
        .try_into()
        .ok()
        .and_then(|index| items.get(index))
        .ok_or(ProverError::Key(KeyError::CosetIndex))
}

impl<F: PastaField> Opened<'_, F> {
    /// Writes the evaluations of spec section 7 rows 7-11.
    ///
    /// # Errors
    ///
    /// [`ProverError::Key`] for a polynomial the descriptor names but the
    /// proof does not have.
    pub(super) fn write_evaluations<C, T>(
        &self,
        pk: &ProvingKey<C>,
        protocol: &Protocol,
        x: F,
        transcript: &mut T,
    ) -> Result<(), ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
        T: TranscriptWrite<C>,
    {
        let descriptor = pk.binding().descriptor();
        let shape = protocol.shape();
        let omega = pk.domain().omega();
        let omega_inv = pk.domain().omega_inv();
        let at = |rotation: i32| rotate(x, omega, omega_inv, rotation);
        let mut write = |poly: &[F], rotation: i32| {
            transcript.write_scalar(&evaluate_polynomial(poly, at(rotation)));
        };
        if shape.committed_instances {
            for query in &descriptor.instance_queries {
                write(indexed(&self.instance.polys, query.column)?, query.rotation);
            }
        }
        for query in &descriptor.advice_queries {
            write(indexed(&self.advice.polys, query.column)?, query.rotation);
        }
        for query in &descriptor.fixed_queries {
            write(indexed(pk.fixed_polys(), query.column)?, query.rotation);
        }
        write(&self.random.coeffs, 0);
        for sigma in pk.permutation_polys() {
            write(sigma, 0);
        }
        let last = shape.last_rotation()?;
        for (set, product) in self.products.iter().enumerate() {
            write(&product.poly, 0);
            write(&product.poly, 1);
            if set + 1 < self.products.len() {
                write(&product.poly, last);
            }
        }
        for lookup in self.lookups {
            write(&lookup.product_poly, 0);
            write(&lookup.product_poly, 1);
            write(&lookup.input_poly, 0);
            write(&lookup.input_poly, -1);
            write(&lookup.table_poly, 0);
        }
        Ok(())
    }

    /// The polynomial and blind of a plan slot.
    fn slot_polynomial<'s, C: PastaCurve<ScalarExt = F>>(
        &'s self,
        pk: &'s ProvingKey<C>,
        slot: Slot,
    ) -> Result<SlotPolynomial<'s, F>, ProverError> {
        let default = |coeffs: &'s [F]| SlotPolynomial {
            coeffs,
            blind: F::ONE,
        };
        Ok(match slot.kind {
            SlotKind::Instance => default(indexed(&self.instance.polys, slot.index)?),
            SlotKind::Advice => SlotPolynomial {
                coeffs: indexed(&self.advice.polys, slot.index)?,
                blind: *indexed(&self.advice.blinds, slot.index)?,
            },
            SlotKind::Fixed => default(indexed(pk.fixed_polys(), slot.index)?),
            SlotKind::PermutationSigma => default(indexed(pk.permutation_polys(), slot.index)?),
            SlotKind::PermutationProduct => {
                let set = indexed(self.products, slot.index)?;
                SlotPolynomial {
                    coeffs: &set.poly,
                    blind: set.blind,
                }
            }
            SlotKind::LookupProduct => {
                let lookup = indexed(self.lookups, slot.index)?;
                SlotPolynomial {
                    coeffs: &lookup.product_poly,
                    blind: lookup.product_blind,
                }
            }
            SlotKind::LookupPermutedInput => {
                let lookup = indexed(self.lookups, slot.index)?;
                SlotPolynomial {
                    coeffs: &lookup.input_poly,
                    blind: lookup.input_blind,
                }
            }
            SlotKind::LookupPermutedTable => {
                let lookup = indexed(self.lookups, slot.index)?;
                SlotPolynomial {
                    coeffs: &lookup.table_poly,
                    blind: lookup.table_blind,
                }
            }
            SlotKind::Vanishing => SlotPolynomial {
                coeffs: &self.quotient.coeffs,
                blind: self.quotient.blind,
            },
            SlotKind::Random => SlotPolynomial {
                coeffs: &self.random.coeffs,
                blind: self.random.blind,
            },
        })
    }

    /// Runs the multiopen and its IPA (`BlindingScheduleV1` items 7 and 8) and
    /// returns the folded generator `G'_0`.
    ///
    /// # Errors
    ///
    /// [`ProverError::Multiopen`] or [`ProverError::Key`].
    #[allow(clippy::too_many_arguments)]
    pub(super) fn open<C, T, R>(
        &self,
        params: &PinnedParams<C>,
        pk: &ProvingKey<C>,
        protocol: &Protocol,
        x: F,
        rng: &mut R,
        transcript: &mut T,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<crate::pcs::ipa::GeneratorClaim<C>, ProverError>
    where
        C: PastaCurve<ScalarExt = F>,
        T: TranscriptWrite<C>,
        R: RngCore + CryptoRng,
    {
        let plan = protocol.plan();
        let points = plan.points(x, pk.domain().omega());
        let polys = plan
            .slots()
            .iter()
            .map(|slot| self.slot_polynomial(pk, slot.slot))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(create_proof_with_claim_cancellable(
            params.params(),
            plan,
            &points,
            &polys,
            rng,
            transcript,
            budget,
            cancellation,
        )?)
    }
}
