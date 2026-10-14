//! Polynomials over `GF(2)` of arbitrary degree, as [`Bits`] (bit `i` is the
//! coefficient of `x^i`): product, division, modular product, modular inverse and
//! powers. All operands are public table-construction data.

use super::{bits::Bits, error::CrtError};

/// Carry-less product `left * right`.
pub fn mul(left: &Bits, right: &Bits) -> Bits {
    let mut out = Bits::zero();
    for position in right.ones() {
        out.xor_shifted(left, position);
    }
    out
}

/// Quotient and remainder of `value` by `divisor`.
pub fn divmod(value: &Bits, divisor: &Bits) -> Result<(Bits, Bits), CrtError> {
    let divisor_degree = divisor.degree().ok_or(CrtError::DivisionByZero)?;
    let mut quotient = Bits::zero();
    let mut remainder = value.clone();
    while let Some(shift) = remainder
        .degree()
        .and_then(|degree| degree.checked_sub(divisor_degree))
    {
        quotient.set(shift);
        remainder.xor_shifted(divisor, shift);
    }
    Ok((quotient, remainder))
}

/// Remainder of `value` by `modulus`.
pub fn rem(value: &Bits, modulus: &Bits) -> Result<Bits, CrtError> {
    Ok(divmod(value, modulus)?.1)
}

/// `left * right mod modulus`.
pub fn mulmod(left: &Bits, right: &Bits, modulus: &Bits) -> Result<Bits, CrtError> {
    rem(&mul(left, right), modulus)
}

/// Inverse of `value` modulo `modulus` by the extended Euclidean algorithm, reduced
/// modulo `modulus`.
pub fn invmod(value: &Bits, modulus: &Bits) -> Result<Bits, CrtError> {
    let mut previous = modulus.clone();
    let mut current = rem(value, modulus)?;
    let mut previous_coefficient = Bits::zero();
    let mut coefficient = Bits::from_u64(1);
    while !current.is_zero() {
        let (quotient, remainder) = divmod(&previous, &current)?;
        previous = std::mem::replace(&mut current, remainder);
        let mut next = previous_coefficient;
        next.xor_assign(&mul(&quotient, &coefficient));
        previous_coefficient = std::mem::replace(&mut coefficient, next);
    }
    if previous != Bits::from_u64(1) {
        return Err(CrtError::NotInvertible);
    }
    rem(&previous_coefficient, modulus)
}

/// `base` raised to `exponent`, without reduction.
pub fn pow(base: &Bits, exponent: usize) -> Bits {
    let mut out = Bits::from_u64(1);
    for _ in 0..exponent {
        out = mul(&out, base);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random(state: &mut u64, words: usize) -> Bits {
        let values: Vec<u64> = (0..words).map(|_| next(state)).collect();
        Bits::from_words(&values)
    }

    #[test]
    fn mul_matches_small_cases_and_is_commutative() {
        // (x + 1)(x^2 + x + 1) = x^3 + 1.
        assert_eq!(
            mul(&Bits::from_u64(0b11), &Bits::from_u64(0b111)),
            Bits::from_u64(0b1001)
        );
        assert!(mul(&Bits::zero(), &Bits::from_u64(7)).is_zero());
        let mut state = 0x1234_5678_9abc_def1;
        for _ in 0..20 {
            let left = random(&mut state, 3);
            let right = random(&mut state, 2);
            assert_eq!(mul(&left, &right), mul(&right, &left));
        }
    }

    #[test]
    fn divmod_inverts_mul_and_rejects_zero() {
        let mut state = 0x0fed_cba9_8765_4321;
        for _ in 0..20 {
            let value = random(&mut state, 4);
            let divisor = random(&mut state, 2);
            let (quotient, remainder) = divmod(&value, &divisor).expect("non-zero divisor");
            assert!(remainder.degree() < divisor.degree());
            let mut back = mul(&quotient, &divisor);
            back.xor_assign(&remainder);
            assert_eq!(back, value);
            assert_eq!(rem(&value, &divisor), Ok(remainder));
        }
        assert_eq!(
            divmod(&Bits::from_u64(5), &Bits::zero()),
            Err(CrtError::DivisionByZero)
        );
        assert_eq!(
            rem(&Bits::from_u64(5), &Bits::zero()),
            Err(CrtError::DivisionByZero)
        );
        // x^8 mod (x^8 + x^4 + x^3 + x + 1).
        assert_eq!(
            rem(&Bits::from_u64(0x100), &Bits::from_u64(0x11b)),
            Ok(Bits::from_u64(0x1b))
        );
    }

    #[test]
    fn mulmod_and_invmod_agree() {
        let modulus = Bits::from_u64(0x11b);
        for value in 1..=255u64 {
            let element = Bits::from_u64(value);
            let inverse = invmod(&element, &modulus).expect("field element");
            assert_eq!(
                mulmod(&element, &inverse, &modulus),
                Ok(Bits::from_u64(1)),
                "{value}"
            );
        }
        // The AES inverse of 0x53 is 0xca.
        assert_eq!(
            invmod(&Bits::from_u64(0x53), &modulus),
            Ok(Bits::from_u64(0xca))
        );
        assert_eq!(
            invmod(&Bits::from_u64(0b11), &Bits::from_u64(0b101)),
            Err(CrtError::NotInvertible)
        );
        assert_eq!(
            invmod(&Bits::zero(), &modulus),
            Err(CrtError::NotInvertible)
        );
        assert_eq!(
            invmod(&Bits::from_u64(1), &Bits::zero()),
            Err(CrtError::DivisionByZero)
        );
    }

    #[test]
    fn pow_is_repeated_multiplication() {
        assert_eq!(pow(&Bits::from_u64(0b11), 0), Bits::from_u64(1));
        assert_eq!(pow(&Bits::from_u64(0b11), 1), Bits::from_u64(0b11));
        // (x + 1)^4 = x^4 + 1.
        assert_eq!(pow(&Bits::from_u64(0b11), 4), Bits::from_u64(0b1_0001));
        assert_eq!(pow(&Bits::from_u64(0b10), 70), Bits::unit(70));
    }
}
