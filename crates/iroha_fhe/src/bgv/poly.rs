//! Limb-major residue polynomials in a clearing owner.
//!
//! An [`RnsPoly`] is `limbs * degree` words, limb `i` holding the residues
//! modulo the `i`-th prime of whatever basis its user fixes. The buffer is
//! allocated once at its final size and cleared when the owner is dropped, so
//! a polynomial that held secret-dependent data leaves nothing behind on
//! success, on an error return or on unwind. Public polynomials use the same
//! owner; clearing them costs one pass and removes the need to classify every
//! temporary.
use super::BgvError;
use crate::{automorphism, constant_time::FixedModulus, ntt_plan::NegacyclicPlan};
use zeroize::Zeroize as _;

/// Append `words` to `bytes`, each as eight little-endian bytes.
pub(super) fn extend_le_bytes(bytes: &mut Vec<u8>, words: &[u64]) {
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
}

/// The little-endian words of `bytes`; a trailing partial word is ignored.
pub(super) fn words_from_le_bytes(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            u64::from_le_bytes(word)
        })
        .collect()
}

/// A residue polynomial that clears its words on drop.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RnsPoly {
    words: Vec<u64>,
    degree: usize,
}

impl Drop for RnsPoly {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

impl std::fmt::Debug for RnsPoly {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Contents may be secret-dependent; only the shape is printed.
        formatter
            .debug_struct("RnsPoly")
            .field("limbs", &self.limbs())
            .field("degree", &self.degree)
            .finish_non_exhaustive()
    }
}

impl RnsPoly {
    /// The zero polynomial of `limbs` limbs.
    pub(super) fn zero(limbs: usize, degree: usize) -> Self {
        Self {
            words: vec![0_u64; limbs * degree],
            degree,
        }
    }

    /// Take ownership of limb-major words.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`] when the length is not a multiple of the degree.
    pub(super) fn from_words(words: Vec<u64>, degree: usize) -> Result<Self, BgvError> {
        if degree == 0 || !words.len().is_multiple_of(degree) {
            let found = words.len();
            // The rejected words may be secret-dependent.
            let mut words = words;
            words.zeroize();
            return Err(BgvError::LengthMismatch {
                expected: degree,
                found,
            });
        }
        Ok(Self { words, degree })
    }

    /// Number of limbs.
    pub(super) fn limbs(&self) -> usize {
        self.words.len().checked_div(self.degree).unwrap_or(0)
    }

    /// All words, limb-major.
    pub(super) fn words(&self) -> &[u64] {
        &self.words
    }

    /// All words, limb-major.
    pub(super) fn words_mut(&mut self) -> &mut [u64] {
        &mut self.words
    }

    /// The residues of limb `index`.
    pub(super) fn limb(&self, index: usize) -> &[u64] {
        &self.words[index * self.degree..(index + 1) * self.degree]
    }

    /// The residues of limb `index`.
    pub(super) fn limb_mut(&mut self, index: usize) -> &mut [u64] {
        &mut self.words[index * self.degree..(index + 1) * self.degree]
    }

    /// A copy of the first `limbs` limbs.
    pub(super) fn prefix(&self, limbs: usize) -> Self {
        Self {
            words: self.words[..limbs * self.degree].to_vec(),
            degree: self.degree,
        }
    }

    /// Transform every limb to evaluation form; limb `i` uses `plan_of(i)`.
    pub(super) fn forward<'plan>(
        &mut self,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<(), BgvError> {
        for (index, limb) in self.words.chunks_exact_mut(self.degree).enumerate() {
            let plan: &NegacyclicPlan = plan_of(index);
            plan.forward(limb)?;
        }
        Ok(())
    }

    /// Transform every limb back to coefficient form; limb `i` uses `plan_of(i)`.
    pub(super) fn inverse<'plan>(
        &mut self,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<(), BgvError> {
        for (index, limb) in self.words.chunks_exact_mut(self.degree).enumerate() {
            let plan: &NegacyclicPlan = plan_of(index);
            plan.inverse(limb)?;
        }
        Ok(())
    }

    /// `self += rhs` limb by limb over canonical residues.
    pub(super) fn add_assign<'plan>(
        &mut self,
        rhs: &Self,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<(), BgvError> {
        self.check_same_shape(rhs)?;
        for (index, (limb, other)) in self
            .words
            .chunks_exact_mut(self.degree)
            .zip(rhs.words.chunks_exact(self.degree))
            .enumerate()
        {
            let fixed: FixedModulus = plan_of(index).fixed();
            for (left, &right) in limb.iter_mut().zip(other) {
                *left = fixed.add_canonical(*left, right);
            }
        }
        Ok(())
    }

    /// `self -= rhs` limb by limb over canonical residues.
    pub(super) fn sub_assign<'plan>(
        &mut self,
        rhs: &Self,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<(), BgvError> {
        self.check_same_shape(rhs)?;
        for (index, (limb, other)) in self
            .words
            .chunks_exact_mut(self.degree)
            .zip(rhs.words.chunks_exact(self.degree))
            .enumerate()
        {
            let fixed: FixedModulus = plan_of(index).fixed();
            for (left, &right) in limb.iter_mut().zip(other) {
                *left = fixed.sub_canonical(*left, right);
            }
        }
        Ok(())
    }

    /// `self = -self` limb by limb over canonical residues.
    pub(super) fn negate<'plan>(&mut self, plan_of: impl Fn(usize) -> &'plan NegacyclicPlan) {
        for (index, limb) in self.words.chunks_exact_mut(self.degree).enumerate() {
            let fixed: FixedModulus = plan_of(index).fixed();
            for value in limb {
                *value = fixed.sub_canonical(0, *value);
            }
        }
    }

    /// `self[i] *= rhs[i]` in evaluation form.
    pub(super) fn pointwise_mul_assign<'plan>(
        &mut self,
        rhs: &Self,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<(), BgvError> {
        self.check_same_shape(rhs)?;
        for (index, (limb, other)) in self
            .words
            .chunks_exact_mut(self.degree)
            .zip(rhs.words.chunks_exact(self.degree))
            .enumerate()
        {
            let plan: &NegacyclicPlan = plan_of(index);
            plan.pointwise_mul_assign(limb, other)?;
        }
        Ok(())
    }

    /// The image under `X -> X^power` in coefficient form; `power` is already validated.
    pub(super) fn automorphism<'plan>(
        &self,
        power: usize,
        plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
    ) -> Result<Self, BgvError> {
        let mut output = Self::zero(self.limbs(), self.degree);
        for (index, (source, target)) in self
            .words
            .chunks_exact(self.degree)
            .zip(output.words.chunks_exact_mut(self.degree))
            .enumerate()
        {
            automorphism::apply_into_with(source, power, &plan_of(index).fixed(), target)?;
        }
        Ok(output)
    }

    fn check_same_shape(&self, rhs: &Self) -> Result<(), BgvError> {
        if self.words.len() == rhs.words.len() && self.degree == rhs.degree {
            Ok(())
        } else {
            Err(BgvError::LengthMismatch {
                expected: self.words.len(),
                found: rhs.words.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{modular, polynomial};

    const PRIMES: [u64; 2] = [12_289, 40_961];

    fn plans() -> Vec<NegacyclicPlan> {
        PRIMES
            .iter()
            .map(|&prime| {
                let psi = modular::primitive_root_of_order_with_candidate_limit(prime, 16, 1 << 12)
                    .expect("root");
                NegacyclicPlan::new(8, prime, psi).expect("plan")
            })
            .collect()
    }

    fn sample(seed: u64) -> RnsPoly {
        let mut poly = RnsPoly::zero(2, 8);
        for (limb, &prime) in PRIMES.iter().enumerate() {
            for (index, value) in poly.limb_mut(limb).iter_mut().enumerate() {
                *value = (seed * 7919 + (index as u64 + 1) * 104_729 + limb as u64) % prime;
            }
        }
        poly
    }

    #[test]
    fn shape_accessors_and_construction() {
        let poly = sample(3);
        assert_eq!(poly.limbs(), 2);
        assert_eq!(poly.words().len(), 16);
        assert_eq!(poly.limb(1), &poly.words()[8..]);
        assert_eq!(poly.prefix(1).words(), poly.limb(0));
        assert_eq!(RnsPoly::zero(3, 4).words(), &[0; 12]);
        assert_eq!(
            RnsPoly::from_words(vec![1; 7], 4).err(),
            Some(BgvError::LengthMismatch {
                expected: 4,
                found: 7
            })
        );
        assert_eq!(
            RnsPoly::from_words(vec![1; 8], 0).err(),
            Some(BgvError::LengthMismatch {
                expected: 0,
                found: 8
            })
        );
        let owned = RnsPoly::from_words(vec![5; 8], 4).expect("poly");
        assert_eq!(owned.limbs(), 2);
        let mut edited = owned.clone();
        edited.words_mut()[0] = 6;
        assert_ne!(edited, owned);
        // The debug form shows the shape and never a residue.
        assert_eq!(format!("{owned:?}"), "RnsPoly { limbs: 2, degree: 4, .. }");
    }

    #[test]
    fn arithmetic_matches_the_word_references() {
        let plans = plans();
        let plan_of = |index: usize| &plans[index];
        let lhs = sample(1);
        let rhs = sample(2);
        let mut sum = lhs.clone();
        sum.add_assign(&rhs, plan_of).expect("sum");
        let mut difference = lhs.clone();
        difference.sub_assign(&rhs, plan_of).expect("difference");
        let mut negated = lhs.clone();
        negated.negate(plan_of);
        let mut product = lhs.clone();
        let mut rhs_eval = rhs.clone();
        product.forward(plan_of).expect("forward");
        rhs_eval.forward(plan_of).expect("forward");
        product
            .pointwise_mul_assign(&rhs_eval, plan_of)
            .expect("product");
        product.inverse(plan_of).expect("inverse");
        let rotated = lhs.automorphism(5, plan_of).expect("automorphism");
        for (limb, &prime) in PRIMES.iter().enumerate() {
            assert_eq!(
                sum.limb(limb),
                polynomial::add_mod(lhs.limb(limb), rhs.limb(limb), prime)
            );
            assert_eq!(
                difference.limb(limb),
                polynomial::sub_mod(lhs.limb(limb), rhs.limb(limb), prime)
            );
            assert_eq!(
                negated.limb(limb),
                polynomial::neg_mod(lhs.limb(limb), prime)
            );
            assert_eq!(
                product.limb(limb),
                polynomial::negacyclic_mul_mod_schoolbook(lhs.limb(limb), rhs.limb(limb), 8, prime)
            );
            let mut expected = vec![0_u64; 8];
            automorphism::apply_into(lhs.limb(limb), 5, prime, &mut expected).expect("reference");
            assert_eq!(rotated.limb(limb), expected);
        }
    }

    #[test]
    fn words_and_little_endian_bytes_convert_both_ways() {
        let words = [1_u64, 0x0102_0304_0506_0708, u64::MAX];
        let mut bytes = vec![0xEE_u8];
        extend_le_bytes(&mut bytes, &words);
        assert_eq!(bytes.len(), 1 + 24);
        assert_eq!(&bytes[1..9], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[9..17], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(words_from_le_bytes(&bytes[1..]), words);
        // A trailing partial word is not a word.
        assert_eq!(words_from_le_bytes(&bytes[1..24]), &words[..2]);
        assert!(words_from_le_bytes(&[]).is_empty());
    }

    #[test]
    fn mismatched_shapes_are_rejected() {
        let plans = plans();
        let plan_of = |index: usize| &plans[index];
        let mut poly = sample(1);
        let short = poly.prefix(1);
        let mismatch = Err(BgvError::LengthMismatch {
            expected: 16,
            found: 8,
        });
        assert_eq!(poly.add_assign(&short, plan_of), mismatch);
        assert_eq!(poly.sub_assign(&short, plan_of), mismatch);
        assert_eq!(poly.pointwise_mul_assign(&short, plan_of), mismatch);
        assert_eq!(poly, sample(1));
        // A degree that differs from the plan is a kernel error.
        let mut wrong = RnsPoly::zero(2, 4);
        assert_eq!(wrong.forward(plan_of), Err(BgvError::Kernel));
        assert_eq!(wrong.inverse(plan_of), Err(BgvError::Kernel));
    }
}
