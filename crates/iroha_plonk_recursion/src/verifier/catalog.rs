//! Circuit-fixed key catalogs with opaque selected-key provenance.
//!
//! Each catalog entry is a complete checked native key for one descriptor.
//! A one-hot selection binds its representation, every commitment coordinate
//! and the already computed complete key digest. Consequently verification
//! may reuse that digest without rehashing witness-controlled key material.

use super::*;
use iroha_pasta::{PastaAffine, PastaField};

/// Preserve the original one-row source for up to three terms, then carry the
/// constrained total through two further terms per row. Catalog width is fixed
/// source metadata; no term is omitted or chosen by the witness.
fn catalog_linear<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    terms: &[(F, &Word<F>)],
) -> Result<Word<F>, Error> {
    let (head, tail) = terms.split_at(terms.len().min(3));
    let mut total = glue.linear(region, head, F::ZERO)?;
    for next in tail.chunks(2) {
        let mut row = vec![(F::ONE, &total)];
        row.extend_from_slice(next);
        total = glue.linear(region, &row, F::ZERO)?;
    }
    Ok(total)
}

/// An immutable, nonempty catalog of distinct complete PIPA-R keys.
#[derive(Clone, Debug)]
pub struct PinnedKeyCatalog<C: PastaCurve> {
    binding: [u8; 32],
    keys: Vec<VerifyingKey<C>>,
    digests: Vec<C::Base>,
}
impl<C: PastaCurve> PinnedKeyCatalog<C> {
    /// Checks all keys against this exact verifier program.
    ///
    /// # Errors
    /// Empty/oversized catalog, duplicate digest, foreign descriptor, invalid
    /// key profile or identity commitment. At most32 entries are supported.
    pub fn new(plan: &VerifierPlan<C>, keys: Vec<VerifyingKey<C>>) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > 32 {
            return Err(Error::Synthesis);
        }
        let mut digests = Vec::with_capacity(keys.len());
        for key in &keys {
            if key.descriptor_digest() != plan.binding.digest()
                || key.fixed_commitments().len() != plan.protocol.shape().num_fixed
                || key.permutation_commitments().len() != plan.protocol.shape().permutation_columns
                || key
                    .fixed_commitments()
                    .iter()
                    .chain(key.permutation_commitments())
                    .any(|point| bool::from(point.coordinates().is_none()))
            {
                return Err(Error::Synthesis);
            }
            let digest = key
                .kagemusha_digest(&plan.binding)
                .map_err(|_| Error::Synthesis)?;
            if digests.contains(&digest) {
                return Err(Error::Synthesis);
            }
            digests.push(digest);
        }
        Ok(Self {
            binding: *plan.binding.digest(),
            keys,
            digests,
        })
    }
    /// Complete key digests in the fixed catalog order.
    #[must_use]
    pub fn digests(&self) -> &[C::Base] {
        &self.digests
    }
}

/// Key cells and digest selected together from a fixed checked catalog.
/// There is no public constructor or mutable access to its members.
#[derive(Clone, Debug)]
pub struct PinnedKeyCells<C: PastaCurve> {
    pub(super) key: VerifierKeyCells<C>,
    pub(super) digest: Word<C::Base>,
    pub(super) binding: [u8; 32],
}

impl<C: PastaCurve> VerifierChip<C> {
    /// Selects one complete catalog entry using a constrained one-hot index.
    /// An index outside the catalog is unsatisfiable, including in soft mode:
    /// key authorization belongs to the owning relation, not proof validity.
    ///
    /// # Errors
    /// The catalog belongs to another descriptor, or layout fails.
    pub fn select_catalog_key(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &VerifierPlan<C>,
        catalog: &PinnedKeyCatalog<C>,
        index: Value<usize>,
    ) -> Result<PinnedKeyCells<C>, Error> {
        if catalog.binding != *plan.binding.digest() {
            return Err(Error::Synthesis);
        }
        let choices = (0..catalog.keys.len())
            .map(|i| {
                self.glue
                    .boolean(region, index.map(|selected| selected == i))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let terms: Vec<_> = choices
            .iter()
            .map(|bit| (C::Base::ONE, bit.word()))
            .collect();
        let sum = catalog_linear(&mut self.glue, region, &terms)?;
        self.glue.enforce_constant(region, &sum, C::Base::ONE)?;
        let mut selected = |values: Vec<C::Base>| -> Result<Word<C::Base>, Error> {
            let terms: Vec<_> = values
                .into_iter()
                .zip(choices.iter().map(Bit::word))
                .collect();
            catalog_linear(&mut self.glue, region, &terms)
        };
        let representations = catalog
            .keys
            .iter()
            .map(|key| match key.transcript_repr() {
                TranscriptRepr::Base(value) => Ok(*value),
                TranscriptRepr::Scalar(_) => Err(Error::Synthesis),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let representation = selected(representations)?;
        let digest = selected(catalog.digests.clone())?;
        let mut coordinates = Vec::new();
        for i in 0..plan.protocol.shape().num_fixed + plan.protocol.shape().permutation_columns {
            let points = catalog
                .keys
                .iter()
                .map(|key| {
                    key.fixed_commitments()
                        .iter()
                        .chain(key.permutation_commitments())
                        .nth(i)
                        .and_then(|point| Option::from(point.coordinates()))
                        .ok_or(Error::Synthesis)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let x = selected(points.iter().map(|(x, _)| *x).collect())?;
            let y = selected(points.iter().map(|(_, y)| *y).collect())?;
            coordinates.push((x, y));
        }
        let mut points = coordinates
            .into_iter()
            .map(|(x, y)| self.ecc.constrain_non_identity(region, &x, &y))
            .collect::<Result<Vec<_>, _>>()?;
        let permutation = points.split_off(plan.protocol.shape().num_fixed);
        Ok(PinnedKeyCells {
            key: VerifierKeyCells {
                representation,
                fixed: points,
                permutation,
            },
            digest,
            binding: catalog.binding,
        })
    }
}

#[cfg(test)]
#[path = "catalog_linear_tests.rs"]
mod linear_tests;
