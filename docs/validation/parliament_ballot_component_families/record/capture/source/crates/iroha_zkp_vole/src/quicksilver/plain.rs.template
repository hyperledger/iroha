//! The plain evaluator: constraints as values on the witness itself.

use zeroize::Zeroize;

use super::{ConstraintSystem, Degree, QuickSilverError, Stream};
use crate::field::LambdaField;

/// A plain value: the constraint polynomial evaluated on the witness, with the
/// degree the other evaluators track. **Secret** when the witness is.
#[derive(Clone, Copy)]
pub struct PlainValue<F> {
    value: F,
    degree: Degree,
}

impl<F> core::fmt::Debug for PlainValue<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlainValue")
            .field("degree", &self.degree)
            .finish_non_exhaustive()
    }
}

impl<F: Zeroize> Zeroize for PlainValue<F> {
    /// Erase the value and reset the degree: the constant 0 remains.
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.degree = Degree::ZERO;
    }
}

/// The plain constraint system.
pub(super) struct Plain<'a, F: LambdaField> {
    /// Witness bits: bit `i` at bit `i mod 8` of byte `i / 8`.
    witness: &'a [u8],
    /// Arbitrary field elements in the place of the witness bits, to test the
    /// polynomial identities.
    #[cfg(test)]
    elements: Option<&'a [F]>,
    field: core::marker::PhantomData<F>,
    stream: Stream,
    /// Whether any constraint so far was non-zero.
    violated: bool,
    /// The indices of the non-zero constraints, when asked for.
    indices: Option<Vec<usize>>,
    #[cfg(test)]
    recorded: Vec<F>,
}

impl<'a, F: LambdaField> Plain<'a, F> {
    /// An evaluator of a stream of `total` constraints on the bits of `witness`.
    /// With `collect` it also lists the violated constraints, which makes its
    /// control flow depend on the witness.
    pub(super) fn new(witness: &'a [u8], total: usize, collect: bool) -> Self {
        Self {
            witness,
            #[cfg(test)]
            elements: None,
            field: core::marker::PhantomData,
            stream: Stream::new(total),
            violated: false,
            indices: collect.then(Vec::new),
            #[cfg(test)]
            recorded: Vec::new(),
        }
    }

    /// An evaluator on arbitrary field elements.
    #[cfg(test)]
    pub(super) fn with_elements(elements: &'a [F], total: usize) -> Self {
        let mut plain = Self::new(&[], total, false);
        plain.elements = Some(elements);
        plain
    }

    /// Number of witness coordinates.
    fn len(&self) -> usize {
        #[cfg(test)]
        if let Some(elements) = self.elements {
            return elements.len();
        }
        8 * self.witness.len()
    }

    /// The value of coordinate `index`.
    fn coordinate(&self, index: usize) -> Option<F> {
        #[cfg(test)]
        if let Some(elements) = self.elements {
            return elements.get(index).copied();
        }
        Some(F::from_bit(*self.witness.get(index / 8)? >> (index % 8)))
    }

    /// Emit the Booleanity constraint `w * (w + 1)` of every coordinate, in order.
    pub(super) fn booleanity(&mut self) {
        for index in 0..self.len() {
            let value = self.coordinate(index).map_or(
                PlainValue {
                    value: F::ZERO,
                    degree: Degree::BadIndex,
                },
                |value| PlainValue {
                    value: value.square() + value,
                    degree: Degree::TWO,
                },
            );
            self.constrain(value);
        }
    }

    /// Whether every constraint was zero, and the violated indices if they were
    /// collected.
    pub(super) fn finish(self) -> Result<(bool, Vec<usize>), QuickSilverError> {
        self.stream.finish()?;
        Ok((!self.violated, self.indices.unwrap_or_default()))
    }

    /// The value of every constraint so far.
    #[cfg(test)]
    pub(super) fn recorded(&self) -> &[F] {
        &self.recorded
    }

    /// The field value inside `value`.
    #[cfg(test)]
    pub(super) fn value_of(value: PlainValue<F>) -> F {
        value.value
    }
}

impl<F: LambdaField> ConstraintSystem for Plain<'_, F> {
    type Field = F;
    type Value = PlainValue<F>;

    fn witness(&self, index: usize) -> PlainValue<F> {
        self.coordinate(index).map_or(
            PlainValue {
                value: F::ZERO,
                degree: Degree::BadIndex,
            },
            |value| PlainValue {
                value,
                degree: Degree::ONE,
            },
        )
    }

    fn constant(&self, value: F) -> PlainValue<F> {
        PlainValue {
            value,
            degree: Degree::ZERO,
        }
    }

    fn add(&self, a: PlainValue<F>, b: PlainValue<F>) -> PlainValue<F> {
        PlainValue {
            value: a.value + b.value,
            degree: a.degree.sum(b.degree).0,
        }
    }

    fn mul(&self, a: PlainValue<F>, b: PlainValue<F>) -> PlainValue<F> {
        PlainValue {
            value: a.value * b.value,
            degree: a.degree.product(b.degree).0,
        }
    }

    fn scale(&self, a: PlainValue<F>, scalar: F) -> PlainValue<F> {
        PlainValue {
            value: a.value * scalar,
            degree: a.degree,
        }
    }

    fn constrain(&mut self, value: PlainValue<F>) {
        let index = self.stream.emitted;
        if self.stream.admit(value.degree).is_none() {
            return;
        }
        let non_zero = !value.value.is_zero();
        self.violated |= non_zero;
        if let Some(indices) = &mut self.indices
            && non_zero
        {
            indices.push(index);
        }
        #[cfg(test)]
        self.recorded.push(value.value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryField, Gf192};

    type F = Gf192;

    #[test]
    fn bits_are_read_low_bit_first_and_embedded_in_the_field() {
        let system = Plain::<F>::new(&[0b0000_0110, 0x80], 16, false);
        assert_eq!(system.len(), 16);
        for index in 0..16 {
            let expected = F::from_bit(u8::from([1, 2, 15].contains(&index)));
            assert_eq!(system.coordinate(index), Some(expected));
            assert_eq!(Plain::<F>::value_of(system.witness(index)), expected);
            assert_eq!(system.witness(index).degree, Degree::ONE);
        }
        assert_eq!(system.coordinate(16), None);
        assert_eq!(system.witness(16).degree, Degree::BadIndex);
        assert!(format!("{:?}", system.witness(0)).contains("degree"));
    }

    #[test]
    fn erasing_a_plain_value_leaves_the_constant_zero() {
        let elements = [F::from_u64(3), F::from_u64(5)];
        let system = Plain::<F>::with_elements(&elements, 2);
        let mut product = system.mul(system.witness(0), system.witness(1));
        assert_eq!(product.value, F::from_u64(15));
        product.zeroize();
        assert_eq!((product.value, product.degree), (F::ZERO, Degree::ZERO));
        let mut missing = system.witness(2);
        missing.zeroize();
        assert_eq!(missing.degree, Degree::ZERO);
    }

    #[test]
    fn operations_are_field_operations_with_the_tracked_degree() {
        let elements = [F::from_u64(3), F::from_u64(5)];
        let system = Plain::<F>::with_elements(&elements, 2);
        let (a, b) = (system.witness(0), system.witness(1));
        let product = system.mul(a, b);
        assert_eq!(
            (product.value, product.degree),
            (F::from_u64(15), Degree::TWO)
        );
        let sum = system.add(product, a);
        assert_eq!((sum.value, sum.degree), (F::from_u64(12), Degree::TWO));
        let scaled = system.scale(sum, F::from_u64(2));
        assert_eq!(
            (scaled.value, scaled.degree),
            (F::from_u64(24), Degree::TWO)
        );
        let mut power = a;
        for _ in 0..7 {
            power = system.mul(power, a);
        }
        assert_eq!(power.degree, Degree::Overflow);
    }

    #[test]
    fn violations_are_flagged_and_listed_by_stream_index() {
        for collect in [false, true] {
            let mut system = Plain::<F>::new(&[0b0000_0010], 11, collect);
            system.booleanity();
            system.constrain(system.witness(0));
            system.constrain(system.witness(1));
            system.constrain(system.add(system.witness(1), system.one()));
            assert_eq!(system.recorded().len(), 11);
            assert_eq!(
                system.finish(),
                Ok((false, if collect { vec![9] } else { Vec::new() }))
            );
        }
        let mut system = Plain::<F>::new(&[0], 8, true);
        system.booleanity();
        assert_eq!(system.finish(), Ok((true, Vec::new())));
        // Non-Boolean values violate Booleanity.
        let elements = [F::ZERO, F::ONE, F::from_u64(2)];
        let mut system = Plain::<F>::with_elements(&elements, 3);
        system.booleanity();
        assert_eq!(system.recorded()[..2], [F::ZERO, F::ZERO]);
        assert_eq!(system.finish(), Ok((false, Vec::new())));
    }
}
