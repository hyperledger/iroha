//! The prover's evaluator: constraints as polynomials over `GF(2^lambda)`.

use core::fmt;

use zeroize::Zeroize;

use super::{ConstraintSystem, DEGREE, Degree, MASKS, QuickSilverError, Stream};
use crate::{field::LambdaField, universal_hash::ZkHasher};

/// Number of coefficients of a polynomial of degree [`DEGREE`].
const COEFFICIENTS: usize = DEGREE + 1;

/// A prover value: the coefficients, lowest first, of a polynomial in `X` of the
/// tracked degree. The coefficient at the degree is the value itself (for a
/// witness coordinate, the witness bit); the ones below it come from the tags.
/// **Secret.**
#[derive(Clone, Copy)]
pub struct Polynomial<F> {
    /// Coefficients `0 ..= degree`; the rest are zero.
    coefficients: [F; COEFFICIENTS],
    degree: Degree,
}

impl<F> fmt::Debug for Polynomial<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Polynomial")
            .field("degree", &self.degree)
            .finish_non_exhaustive()
    }
}

impl<F: Zeroize> Zeroize for Polynomial<F> {
    /// Erase every coefficient and reset the degree: the constant 0 remains.
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
        self.degree = Degree::ZERO;
    }
}

impl<F: LambdaField> Polynomial<F> {
    /// A polynomial that carries only a mark.
    fn marked(degree: Degree) -> Self {
        Self {
            coefficients: [F::ZERO; COEFFICIENTS],
            degree,
        }
    }
}

/// The prover's constraint system: one `ZKHash` state per coefficient.
pub(super) struct Prover<'a, F: LambdaField> {
    /// Witness bits: bit `i` at bit `i mod 8` of byte `i / 8`.
    witness: &'a [u8],
    /// `V[0] || ... || V[ell - 1]`.
    tags: &'a [u8],
    /// Arbitrary field elements in the place of the witness bits, to test the
    /// polynomial identities.
    #[cfg(test)]
    elements: Option<&'a [F]>,
    hashers: [ZkHasher<F>; DEGREE],
    stream: Stream,
    #[cfg(test)]
    recorded: Option<Vec<[F; COEFFICIENTS]>>,
}

impl<'a, F: LambdaField> Prover<'a, F> {
    /// A prover for a stream of `total` constraints hashed under `challenge_2`.
    pub(super) fn new(
        witness: &'a [u8],
        tags: &'a [u8],
        total: usize,
        challenge_2: &[u8],
    ) -> Result<Self, QuickSilverError> {
        let hasher = ZkHasher::<F>::new(challenge_2)?;
        Ok(Self {
            witness,
            tags,
            #[cfg(test)]
            elements: None,
            hashers: core::array::from_fn(|_| hasher.clone()),
            stream: Stream::new(total),
            #[cfg(test)]
            recorded: None,
        })
    }

    /// A prover whose witness values are the field elements `elements`.
    #[cfg(test)]
    pub(super) fn with_elements(
        elements: &'a [F],
        tags: &'a [u8],
        total: usize,
        challenge_2: &[u8],
    ) -> Result<Self, QuickSilverError> {
        let mut prover = Self::new(&[], tags, total, challenge_2)?;
        prover.elements = Some(elements);
        Ok(prover)
    }

    /// Number of witness coordinates.
    fn len(&self) -> usize {
        self.tags.len() / F::BYTES
    }

    /// The tag and the value of coordinate `index`.
    fn coordinate(&self, index: usize) -> Option<(F, F)> {
        let start = index.checked_mul(F::BYTES)?;
        let tag = self.tags.get(start..start.checked_add(F::BYTES)?)?;
        let tag = F::from_bytes(tag).ok()?;
        #[cfg(test)]
        if let Some(elements) = self.elements {
            return Some((tag, *elements.get(index)?));
        }
        let value = F::from_bit(*self.witness.get(index / 8)? >> (index % 8));
        Some((tag, value))
    }

    /// Emit the Booleanity constraint `w * (w + 1)` of every coordinate, in order:
    /// `(V + w X)(V + (w + 1) X) = V^2 + V X + (w^2 + w) X^2`.
    pub(super) fn booleanity(&mut self) {
        for index in 0..self.len() {
            let mut polynomial = Polynomial::marked(Degree::BadIndex);
            if let Some((tag, value)) = self.coordinate(index) {
                polynomial.coefficients[0] = tag.square();
                polynomial.coefficients[1] = tag;
                polynomial.coefficients[2] = value.square() + value;
                polynomial.degree = Degree::TWO;
            }
            self.constrain(polynomial);
        }
    }

    /// Mask each hash with `p_j` and return `a~_0 .. a~_{d_zk-1}`.
    pub(super) fn finish(
        self,
        mask_values: &[u8],
        mask_tags: &[u8],
    ) -> Result<[F; DEGREE], QuickSilverError> {
        self.stream.finish()?;
        let mut values = [F::ZERO; MASKS];
        let mut tags = [F::ZERO; MASKS];
        for (slot, bytes) in values.iter_mut().zip(mask_values.chunks_exact(F::BYTES)) {
            *slot = F::from_bytes(bytes)?;
        }
        for (slot, bytes) in tags.iter_mut().zip(mask_tags.chunks_exact(F::BYTES)) {
            *slot = F::from_bytes(bytes)?;
        }
        let mut out = [F::ZERO; DEGREE];
        for (j, (slot, hasher)) in out.iter_mut().zip(&self.hashers).enumerate() {
            // p_0 = vbar_0, p_j = ubar_{j-1} + vbar_j, p_{d-1} = ubar_{d-2}.
            let mut mask = F::ZERO;
            if j > 0 {
                mask += values[j - 1];
            }
            if j < DEGREE - 1 {
                mask += tags[j];
            }
            *slot = hasher.finalize(mask);
            mask.zeroize();
        }
        values.zeroize();
        tags.zeroize();
        Ok(out)
    }

    /// Keep every lifted constraint polynomial for inspection.
    #[cfg(test)]
    pub(super) fn record(&mut self) {
        self.recorded = Some(Vec::new());
    }

    /// The lifted polynomials kept since [`Self::record`].
    #[cfg(test)]
    pub(super) fn recorded(&self) -> &[[F; COEFFICIENTS]] {
        self.recorded.as_deref().unwrap_or(&[])
    }
}

impl<F: LambdaField> ConstraintSystem for Prover<'_, F> {
    type Field = F;
    type Value = Polynomial<F>;

    fn witness(&self, index: usize) -> Polynomial<F> {
        let Some((tag, value)) = self.coordinate(index) else {
            return Polynomial::marked(Degree::BadIndex);
        };
        let mut polynomial = Polynomial::marked(Degree::ONE);
        polynomial.coefficients[0] = tag;
        polynomial.coefficients[1] = value;
        polynomial
    }

    fn constant(&self, value: F) -> Polynomial<F> {
        let mut polynomial = Polynomial::marked(Degree::ZERO);
        polynomial.coefficients[0] = value;
        polynomial
    }

    fn add(&self, a: Polynomial<F>, b: Polynomial<F>) -> Polynomial<F> {
        let (degree, Some((left, right))) = a.degree.sum(b.degree) else {
            return Polynomial::marked(a.degree.sum(b.degree).0);
        };
        // The operand of lower degree is multiplied by the missing power of X.
        let (high, low, low_degree) = if left >= right {
            (a, b, right)
        } else {
            (b, a, left)
        };
        let shift = left.max(right) - low_degree;
        let mut out = high;
        out.degree = degree;
        for (slot, coefficient) in out
            .coefficients
            .iter_mut()
            .skip(shift)
            .zip(&low.coefficients[..=low_degree])
        {
            *slot += *coefficient;
        }
        out
    }

    fn mul(&self, a: Polynomial<F>, b: Polynomial<F>) -> Polynomial<F> {
        let (degree, Some((left, right))) = a.degree.product(b.degree) else {
            return Polynomial::marked(a.degree.product(b.degree).0);
        };
        let mut out = Polynomial::marked(degree);
        for (i, x) in a.coefficients[..=left].iter().enumerate() {
            for (slot, y) in out.coefficients[i..]
                .iter_mut()
                .zip(&b.coefficients[..=right])
            {
                *slot += *x * *y;
            }
        }
        out
    }

    fn scale(&self, a: Polynomial<F>, scalar: F) -> Polynomial<F> {
        let Some(degree) = a.degree.get() else {
            return a;
        };
        let mut out = a;
        for slot in &mut out.coefficients[..=degree] {
            *slot *= scalar;
        }
        out
    }

    fn constrain(&mut self, value: Polynomial<F>) {
        let Some(lift) = self.stream.admit(value.degree) else {
            return;
        };
        // Coefficient j of X^lift * value; the coefficient of X^d_zk, zero for a
        // satisfied constraint, is not hashed.
        let mut lifted = [F::ZERO; COEFFICIENTS];
        for (slot, coefficient) in lifted.iter_mut().skip(lift).zip(&value.coefficients) {
            *slot = *coefficient;
        }
        for (hasher, coefficient) in self.hashers.iter_mut().zip(&lifted) {
            hasher.update(*coefficient);
        }
        #[cfg(test)]
        if let Some(recorded) = &mut self.recorded {
            recorded.push(lifted);
        }
        lifted.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryField, Gf128};

    type F = Gf128;

    fn element(seed: u64) -> F {
        super::super::tests::element::<F>(seed)
    }

    fn prover<'a>(values: &'a [F], tags: &'a [u8]) -> Prover<'a, F> {
        Prover::with_elements(values, tags, 4, &[7u8; 56]).expect("valid challenge")
    }

    fn evaluate(polynomial: &Polynomial<F>, point: F) -> F {
        polynomial
            .coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coefficient| acc * point + *coefficient)
    }

    #[test]
    fn operations_are_the_polynomial_operations_with_degree_alignment() {
        let values = [element(1), element(2), element(3)];
        let tags: Vec<u8> = (10..13).flat_map(|seed| element(seed).to_bytes()).collect();
        let system = prover(&values, &tags);
        let x = element(99);
        let w: Vec<Polynomial<F>> = (0..3).map(|i| system.witness(i)).collect();
        for (i, polynomial) in w.iter().enumerate() {
            assert_eq!(polynomial.degree, Degree::ONE);
            assert_eq!(polynomial.coefficients[0], element(10 + i as u64));
            assert_eq!(polynomial.coefficients[1], values[i]);
        }
        let at = |polynomial: &Polynomial<F>| evaluate(polynomial, x);
        let c = system.constant(element(50));
        assert_eq!((c.degree, at(&c)), (Degree::ZERO, element(50)));

        let product = system.mul(w[0], w[1]);
        assert_eq!(product.degree, Degree::TWO);
        assert_eq!(at(&product), at(&w[0]) * at(&w[1]));
        assert_eq!(product.coefficients[2], values[0] * values[1]);

        // Lower degrees are lifted: (deg 2) + (deg 1) * X + (deg 0) * X^2.
        for sum in [
            system.add(system.add(product, w[2]), c),
            system.add(c, system.add(w[2], product)),
        ] {
            assert_eq!(sum.degree, Degree::TWO);
            assert_eq!(at(&sum), at(&product) + at(&w[2]) * x + element(50) * x * x);
            assert_eq!(
                sum.coefficients[2],
                values[0] * values[1] + values[2] + element(50)
            );
        }
        let scaled = system.scale(product, element(60));
        assert_eq!(scaled.degree, Degree::TWO);
        assert_eq!(at(&scaled), at(&product) * element(60));
        // A product with a constant keeps the degree.
        let same = system.mul(c, w[0]);
        assert_eq!(same.degree, Degree::ONE);
        assert_eq!(at(&same), element(50) * at(&w[0]));
        assert!(format!("{product:?}").contains("degree"));
    }

    #[test]
    fn erasing_a_polynomial_leaves_the_constant_zero() {
        let values = [element(1), element(2)];
        let tags: Vec<u8> = (10..12).flat_map(|seed| element(seed).to_bytes()).collect();
        let system = prover(&values, &tags);
        let mut product = system.mul(system.witness(0), system.witness(1));
        assert!(!product.coefficients[..3].iter().any(BinaryField::is_zero));
        product.zeroize();
        assert_eq!(product.degree, Degree::ZERO);
        assert!(product.coefficients.iter().all(BinaryField::is_zero));
        // A mark is erased with the rest.
        let mut missing = system.witness(2);
        missing.zeroize();
        assert_eq!(missing.degree, Degree::ZERO);
        // The erased value is usable as the constant 0.
        let sum = system.add(product, system.witness(0));
        assert_eq!(sum.coefficients, system.witness(0).coefficients);
        // Buffers of values are erased through the same implementation.
        let mut scratch = zeroize::Zeroizing::new(vec![system.witness(1); 4]);
        scratch.zeroize();
        assert!(scratch.is_empty());
    }

    #[test]
    fn marks_propagate_through_every_operation() {
        let values = [element(1)];
        let tags = element(2).to_bytes();
        let system = prover(&values, &tags);
        let missing = system.witness(1);
        assert_eq!(missing.degree, Degree::BadIndex);
        let w = system.witness(0);
        assert_eq!(system.add(w, missing).degree, Degree::BadIndex);
        assert_eq!(system.mul(missing, w).degree, Degree::BadIndex);
        assert_eq!(system.scale(missing, F::ONE).degree, Degree::BadIndex);
        let mut power = w;
        for _ in 0..6 {
            power = system.mul(power, w);
        }
        assert_eq!(power.degree, Degree::Of(7));
        let over = system.mul(power, w);
        assert_eq!(over.degree, Degree::Overflow);
        assert_eq!(system.add(over, w).degree, Degree::Overflow);
        assert_eq!(
            system.mul(over, system.constant(F::ONE)).degree,
            Degree::Overflow
        );
        assert_eq!(system.len(), 1);
        assert_eq!(system.coordinate(0), Some((element(2), element(1))));
        assert_eq!(system.coordinate(1), None);
    }

    #[test]
    fn constraints_are_lifted_and_hashed_coefficient_by_coefficient() {
        let values = [element(1), element(2)];
        let tags: Vec<u8> = (10..12).flat_map(|seed| element(seed).to_bytes()).collect();
        let challenge = [0x42u8; 56];
        let mut system =
            Prover::with_elements(&values, &tags, 4, &challenge).expect("valid challenge");
        system.record();
        system.booleanity();
        let product = system.mul(system.witness(0), system.witness(1));
        system.constrain(product);
        system.constrain(system.constant(element(5)));
        let recorded = system.recorded().to_vec();
        assert_eq!(recorded.len(), 4);
        // Degree 2 is lifted by 5, degree 0 by 7.
        assert!(recorded[2][..5].iter().all(BinaryField::is_zero));
        assert_eq!(recorded[2][5], element(10) * element(11));
        assert_eq!(recorded[2][7], values[0] * values[1]);
        assert!(recorded[3][..7].iter().all(BinaryField::is_zero));
        assert_eq!(recorded[3][7], element(5));
        assert_eq!(recorded[0][5], element(10).square());
        assert_eq!(recorded[0][6], element(10));
        assert_eq!(recorded[0][7], values[0].square() + values[0]);

        let mask_values: Vec<u8> = (20..30).flat_map(|seed| element(seed).to_bytes()).collect();
        let mask_tags: Vec<u8> = (30..40).flat_map(|seed| element(seed).to_bytes()).collect();
        let out = system
            .finish(&mask_values, &mask_tags)
            .expect("complete stream");
        for (j, coefficient) in out.iter().enumerate() {
            let column: Vec<F> = recorded.iter().map(|polynomial| polynomial[j]).collect();
            let mut mask = F::ZERO;
            if j > 0 {
                mask += element(20 + j as u64 - 1);
            }
            if j < 6 {
                mask += element(30 + j as u64);
            }
            assert_eq!(
                *coefficient,
                crate::universal_hash::zk_hash(&challenge, &column, mask).expect("valid seed")
            );
        }
    }
}
