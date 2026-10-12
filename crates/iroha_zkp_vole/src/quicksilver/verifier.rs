//! The verifier's evaluator: constraints as values at `Delta`.

use super::{ConstraintSystem, DEGREE, Degree, MASKS, QuickSilverError, Stream};
use crate::{field::LambdaField, universal_hash::ZkHasher};

/// A verifier value: the prover's polynomial of the tracked degree evaluated at
/// `Delta`. Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<F> {
    key: F,
    degree: Degree,
}

impl<F: LambdaField> Key<F> {
    /// A key that carries only a mark.
    fn marked(degree: Degree) -> Self {
        Self {
            key: F::ZERO,
            degree,
        }
    }
}

/// The verifier's constraint system.
pub(super) struct Verifier<'a, F: LambdaField> {
    /// The masked witness `d`: bit `i` at bit `i mod 8` of byte `i / 8`.
    masked: &'a [u8],
    /// `Q[0] || ... || Q[ell - 1]`: the key of coordinate `i` is
    /// `Q[i] + d_i * Delta`.
    keys: &'a [u8],
    /// The witness keys themselves, to test the polynomial identities.
    #[cfg(test)]
    plain: Option<&'a [F]>,
    /// `Delta^0 ..= Delta^d_zk`.
    powers: [F; DEGREE + 1],
    hasher: ZkHasher<F>,
    stream: Stream,
    #[cfg(test)]
    recorded: Option<Vec<F>>,
}

impl<'a, F: LambdaField> Verifier<'a, F> {
    /// A verifier for a stream of `total` constraints hashed under `challenge_2`.
    pub(super) fn new(
        masked: &'a [u8],
        keys: &'a [u8],
        delta: F,
        total: usize,
        challenge_2: &[u8],
    ) -> Result<Self, QuickSilverError> {
        let mut powers = [F::ONE; DEGREE + 1];
        for index in 1..=DEGREE {
            powers[index] = powers[index - 1] * delta;
        }
        Ok(Self {
            masked,
            keys,
            #[cfg(test)]
            plain: None,
            powers,
            hasher: ZkHasher::new(challenge_2)?,
            stream: Stream::new(total),
            #[cfg(test)]
            recorded: None,
        })
    }

    /// A verifier whose witness keys are `keys`.
    #[cfg(test)]
    pub(super) fn with_keys(
        keys: &'a [F],
        delta: F,
        total: usize,
        challenge_2: &[u8],
    ) -> Result<Self, QuickSilverError> {
        let mut verifier = Self::new(&[], &[], delta, total, challenge_2)?;
        verifier.plain = Some(keys);
        Ok(verifier)
    }

    /// Number of witness coordinates.
    fn len(&self) -> usize {
        #[cfg(test)]
        if let Some(keys) = self.plain {
            return keys.len();
        }
        self.keys.len() / F::BYTES
    }

    /// The key of coordinate `index`.
    fn coordinate(&self, index: usize) -> Option<F> {
        #[cfg(test)]
        if let Some(keys) = self.plain {
            return keys.get(index).copied();
        }
        let start = index.checked_mul(F::BYTES)?;
        let key = self.keys.get(start..start.checked_add(F::BYTES)?)?;
        let bit = *self.masked.get(index / 8)? >> (index % 8);
        Some(F::from_bytes(key).ok()? + self.powers[1].mul_bit(bit))
    }

    /// Emit the Booleanity constraint `w * (w + 1)` of every coordinate, in order:
    /// `k * (k + Delta)` of degree 2.
    pub(super) fn booleanity(&mut self) {
        for index in 0..self.len() {
            let value = self.coordinate(index).map_or_else(
                || Key::marked(Degree::BadIndex),
                |key| Key {
                    key: key * (key + self.powers[1]),
                    degree: Degree::TWO,
                },
            );
            self.constrain(value);
        }
    }

    /// `a~_0 = ZKHash(values, q*) + sum_{j >= 1} a~_j * Delta^j` with
    /// `q* = sum_{j < d_zk - 1} qbar_j * Delta^j`.
    pub(super) fn finish(
        self,
        mask_keys: &[u8],
        coefficients: &[u8],
    ) -> Result<F, QuickSilverError> {
        self.stream.finish()?;
        let mut mask = F::ZERO;
        for (bytes, power) in mask_keys
            .chunks_exact(F::BYTES)
            .take(MASKS)
            .zip(&self.powers[..DEGREE - 1])
        {
            mask += F::from_bytes(bytes)? * *power;
        }
        let mut out = self.hasher.finalize(mask);
        for (bytes, power) in coefficients
            .chunks_exact(F::BYTES)
            .zip(&self.powers[1..DEGREE])
        {
            out += F::from_bytes(bytes)? * *power;
        }
        Ok(out)
    }

    /// Keep every lifted constraint value for inspection.
    #[cfg(test)]
    pub(super) fn record(&mut self) {
        self.recorded = Some(Vec::new());
    }

    /// The lifted values kept since [`Self::record`].
    #[cfg(test)]
    pub(super) fn recorded(&self) -> &[F] {
        self.recorded.as_deref().unwrap_or(&[])
    }
}

impl<F: LambdaField> ConstraintSystem for Verifier<'_, F> {
    type Field = F;
    type Value = Key<F>;

    fn witness(&self, index: usize) -> Key<F> {
        self.coordinate(index).map_or_else(
            || Key::marked(Degree::BadIndex),
            |key| Key {
                key,
                degree: Degree::ONE,
            },
        )
    }

    fn constant(&self, value: F) -> Key<F> {
        Key {
            key: value,
            degree: Degree::ZERO,
        }
    }

    fn add(&self, a: Key<F>, b: Key<F>) -> Key<F> {
        let (degree, Some((left, right))) = a.degree.sum(b.degree) else {
            return Key::marked(a.degree.sum(b.degree).0);
        };
        // The operand of lower degree is multiplied by the missing power of Delta.
        let key = match left.cmp(&right) {
            core::cmp::Ordering::Equal => a.key + b.key,
            core::cmp::Ordering::Less => a.key * self.powers[right - left] + b.key,
            core::cmp::Ordering::Greater => a.key + b.key * self.powers[left - right],
        };
        Key { key, degree }
    }

    fn mul(&self, a: Key<F>, b: Key<F>) -> Key<F> {
        let (degree, Some(_)) = a.degree.product(b.degree) else {
            return Key::marked(a.degree.product(b.degree).0);
        };
        Key {
            key: a.key * b.key,
            degree,
        }
    }

    fn scale(&self, a: Key<F>, scalar: F) -> Key<F> {
        Key {
            key: a.key * scalar,
            degree: a.degree,
        }
    }

    fn constrain(&mut self, value: Key<F>) {
        let Some(lift) = self.stream.admit(value.degree) else {
            return;
        };
        let lifted = value.key * self.powers[lift];
        self.hasher.update(lifted);
        #[cfg(test)]
        if let Some(recorded) = &mut self.recorded {
            recorded.push(lifted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryField, Gf256};

    type F = Gf256;

    fn element(seed: u64) -> F {
        super::super::tests::element::<F>(seed)
    }

    #[test]
    fn witness_keys_add_the_masked_bit_times_delta() {
        let delta = element(1);
        let keys: Vec<u8> = (10..26).flat_map(|seed| element(seed).to_bytes()).collect();
        let masked = [0b0000_0101u8, 0x80];
        let system =
            Verifier::<F>::new(&masked, &keys, delta, 16, &[1u8; 104]).expect("valid challenge");
        assert_eq!(system.len(), 16);
        for index in 0..16u64 {
            let bit = [0u64, 2, 15].contains(&index);
            let expected = element(10 + index) + delta.mul_bit(u8::from(bit));
            let at = usize::try_from(index).expect("small");
            assert_eq!(system.coordinate(at), Some(expected));
            assert_eq!(
                system.witness(at),
                Key {
                    key: expected,
                    degree: Degree::ONE
                }
            );
        }
        assert_eq!(system.coordinate(16), None);
        assert_eq!(system.witness(16).degree, Degree::BadIndex);
        assert_eq!(system.powers[0], F::ONE);
        assert_eq!(
            system.powers[7],
            delta.square().square() * delta.square() * delta
        );
    }

    #[test]
    fn operations_align_degrees_with_powers_of_delta() {
        let delta = element(2);
        let keys = [element(3), element(4), element(5)];
        let system =
            Verifier::<F>::with_keys(&keys, delta, 3, &[1u8; 104]).expect("valid challenge");
        let w: Vec<Key<F>> = (0..3).map(|i| system.witness(i)).collect();
        let product = system.mul(w[0], w[1]);
        assert_eq!(
            (product.key, product.degree),
            (keys[0] * keys[1], Degree::TWO)
        );
        let c = system.constant(element(6));
        for sum in [
            system.add(system.add(product, w[2]), c),
            system.add(c, system.add(w[2], product)),
        ] {
            assert_eq!(sum.degree, Degree::TWO);
            assert_eq!(
                sum.key,
                keys[0] * keys[1] + keys[2] * delta + element(6) * delta * delta
            );
        }
        assert_eq!(system.add(w[0], w[1]).key, keys[0] + keys[1]);
        let scaled = system.scale(product, element(7));
        assert_eq!(
            (scaled.key, scaled.degree),
            (product.key * element(7), Degree::TWO)
        );
        let missing = system.witness(3);
        assert_eq!(system.add(w[0], missing).degree, Degree::BadIndex);
        assert_eq!(system.mul(missing, w[0]).degree, Degree::BadIndex);
        assert_eq!(system.scale(missing, F::ONE).degree, Degree::BadIndex);
        let mut power = w[0];
        for _ in 0..7 {
            power = system.mul(power, w[0]);
        }
        assert_eq!(power.degree, Degree::Overflow);
    }

    #[test]
    fn the_stream_is_lifted_hashed_and_closed_with_the_transmitted_coefficients() {
        let delta = element(2);
        let keys = [element(3), element(4)];
        let challenge = [0x24u8; 104];
        let mut system =
            Verifier::<F>::with_keys(&keys, delta, 4, &challenge).expect("valid challenge");
        system.record();
        system.booleanity();
        system.constrain(system.mul(system.witness(0), system.witness(1)));
        system.constrain(system.constant(element(8)));
        let powers = system.powers;
        let recorded = system.recorded().to_vec();
        assert_eq!(
            recorded,
            [
                keys[0] * (keys[0] + delta) * powers[5],
                keys[1] * (keys[1] + delta) * powers[5],
                keys[0] * keys[1] * powers[5],
                element(8) * powers[7],
            ]
        );
        let mask_keys: Vec<u8> = (20..30).flat_map(|seed| element(seed).to_bytes()).collect();
        let tail: Vec<u8> = (40..46).flat_map(|seed| element(seed).to_bytes()).collect();
        let out = system.finish(&mask_keys, &tail).expect("complete stream");
        let mut mask = F::ZERO;
        for j in 0..6u64 {
            mask += element(20 + j) * powers[usize::try_from(j).expect("small")];
        }
        let mut expected =
            crate::universal_hash::zk_hash(&challenge, &recorded, mask).expect("valid seed");
        for j in 1..7u64 {
            expected += element(40 + j - 1) * powers[usize::try_from(j).expect("small")];
        }
        assert_eq!(out, expected);
    }
}
