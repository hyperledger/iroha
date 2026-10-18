#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::table_assets::{read_u16_le, read_u32_le};
// ========================================================================
// Low-level computations modulo a small prime.
// ========================================================================
// All mp_*() functions deal with integers modulo a prime p, such that
// 1.34*2^30 < p < 2^31.
//
// The "unsigned representation" of an integer x modulo p is the unique
// matching integer in the [0, p-1] range, with the u32 type.
//
// The "signed representation" of an integer x modulo p is the unique
// matching integer in the [-p/2, p/2] range, with the i32 type.
//
// "Montgomery representation" of x modulo p is the unsigned representation
// of x*2^32 mod p (hence in the [0, p-1] range, and using the u32 type).
//
// Unless otherwise specified:
//   - When a function uses an integer modulo p as operand, it expects it
//     to be provided in unsigned representation. Such operands MUST be in
//     the proper range; overflows are not checked but may lead to incorrect
//     results.
//   - When a function outputs an integer modulo p, it returns it in unsigned
//     representation (and, in particular, in the proper [0, p-1] range).
//
// Montgomery multiplication, given a and b in unsigned representation,
// computes and returns (a*b)/2^32 mod p in unsigned representation. The
// following properties hold:
//   - If a and b are really the Montgomery representations of x and y,
//     respectively, then the returned value is the Mongomery representation
//     of x*y mod p.
//   - If a is the Montgomery representation of x, then the returned value
//     is the unsigned representation of x*b mod p.
//   - If b is the Montgomery representation of b, then the returned value
//     is the unsigned representation of a*y mod p.
//
// For a given value with unsigned representation x, its Montgomery
// representation can be obtained with a Montgomery multiplication of
// x with R2 = 2^64 mod p. In the other direction, if x is the Montgomery
// reprensentation of y, then the unsigned representation of y can be
// obtained by computing the Montgomery multiplication of y with 1.
// Return 0xFFFFFFFF if the top bit of x is 1, 0x00000000 otherwise.
#[inline]
pub const fn tbmask(x: u32) -> u32 {
    (x.cast_signed() >> 31).cast_unsigned()
}
// Given v in the [-(p-1), +(p-1)] range (signed), return x = v mod p.
#[inline]
pub fn mp_set(v: i32, p: u32) -> u32 {
    let w = v.cast_unsigned();
    w.wrapping_add(p & tbmask(w))
}
// Given v in the [0, 2*p-1] range (unsigned), return x = v mod p.
#[inline]
pub fn mp_set_u(v: u32, p: u32) -> u32 {
    let w = v.wrapping_sub(p);
    w.wrapping_add(p & tbmask(w))
}
// Given x (integer modulo p), return its signed normalized value
// (in [-p/2, +p/2]).
#[inline]
pub fn mp_norm(x: u32, p: u32) -> i32 {
    let c = tbmask(x.wrapping_sub((p + 1) >> 1));
    x.wrapping_sub(p & !c).cast_signed()
}
// Compute R = 2^32 mod p.
#[inline]
pub fn mp_R(p: u32) -> u32 {
    // Since we assume that 1.34*2^30 < p < 2^31, we have:
    //    2*p < 2^32 < 3*p
    // Hence, 2^32 = 2*p + R with 0 <= R < p.
    // We compute and return R = 2^32 - 2*p
    p.wrapping_neg() << 1
}
// Compute hR = 2^31 mod p.
#[inline]
pub fn mp_hR(p: u32) -> u32 {
    // Since we assume that 1.34*2^30 < p < 2^31, we have:
    //    p < 2^31 < 2*p
    // Hence, 2^31 = p + hR with 0 <= R < p.
    // We compute and return hR = 2^31 - p
    0x8000_0000 - p
}
// Compute a + b mod p.
// This function is compatible with Montgomery representation: if a and b
// are the Montgomery representations of x and y, respectively, then this
// returns the Montgomery representation of x + y mod p.
#[inline]
pub fn mp_add(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_add(b).wrapping_sub(p);
    d.wrapping_add(p & tbmask(d))
}
// Compute a - b mod p.
// This function is compatible with Montgomery representation: if a and b
// are the Montgomery representations of x and y, respectively, then this
// returns the Montgomery representation of x - y mod p.
#[inline]
pub fn mp_sub(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_sub(b);
    d.wrapping_add(p & tbmask(d))
}
// Compute a / 2 mod p.
// This function is compatible with Montgomery representation: if a is the
// Montgomery representation of x, then this returns the Montgomery
// representation of x/2 mod p.
#[inline]
pub fn mp_half(a: u32, p: u32) -> u32 {
    a.wrapping_add(p & (a & 1).wrapping_neg()) >> 1
}
// Compute a*b/2^32 mod p; parameter p0i is equal to -1/p mod 2^32.
// This is the "Montgomery multiplication".
#[inline]
pub fn mp_mmul(left: u32, right: u32, modulus: u32, p0i: u32) -> u32 {
    let product = u64::from(left) * u64::from(right);
    let correction = read_u32_le(&product.to_le_bytes(), 0).wrapping_mul(p0i);
    let reduced = (product + u64::from(correction) * u64::from(modulus)) >> 32;
    let difference = read_u32_le(&reduced.to_le_bytes(), 0).wrapping_sub(modulus);
    difference.wrapping_add(modulus & tbmask(difference))
}
// Compute 2^(31*e) mod p.
// Exponent e is considered non-secret.
#[inline]
pub fn mp_Rx31(e: u32, p: u32, p0i: u32, R2: u32) -> u32 {
    // Set x <- 2^63 mod p
    let mut x = mp_half(R2, p);
    let mut d = 1;
    let mut e = e;
    loop {
        if (e & 1) != 0 {
            d = mp_mmul(d, x, p, p0i);
        }
        e >>= 1;
        if e == 0 {
            return d;
        }
        x = mp_mmul(x, x, p, p0i);
    }
}
// ========================================================================
// Pre-computed moduli and NTT.
// ========================================================================
// Each modulus is p < 2^31 such that p = 1 mod 2048. The moduli are in
// decreasing order.
//
// Since p = 1 mod 2048, there are 1024 primitive 2048-th roots of 1 modulo
// p, i.e. integers g such that g^1024 = -1 mod p. Value g is one of them,
// and ig is its inverse modulo p. It does not really matter which precise
// root is used here (this does not impact the value of the generated keys);
// in the PRIMES table, value g is obtained by taking x^((p-1)/2048) for the
// smallest x (as an integer in [0, p-1]) which is not a square modulo p.
// Values g and ig are in Montgomery representation.
//
// For each prime p_j = PRIMES[j].p, value s = PRIMES[j].s is the inverse
// of \prod_{i<j} p_i mod p. Value s is used to convert big integers from
// RNS representation to normal representation. s is in Montgomery
// representation.
//
// (The PRIMES table is later on in this file.)
#[derive(Copy, Clone, Debug)]
pub struct SmallPrime {
    pub(crate) p: u32,   // modulus
    pub(crate) p0i: u32, // -1/p mod 2^32
    pub(crate) R2: u32,  // 2^64 mod p
    pub(crate) g: u32,   // g^1024 = -1 mod p (Mont.)
    pub(crate) ig: u32,  // 1/g mod p (Mont.)
    pub(crate) s: u32,   // inverse mod p of the product of previous primes (Mont.)
}
// The first prime in PRIMES[] has a dedicated name because it is
// used directly in some functions.
pub const P0: SmallPrime = PRIMES[0];
// REV10[] contains the precomputed "bit-reversal" function over 10 bits.
const MP31_TABLE_BYTES: &[u8; 9_440] = include_bytes!("../assets/kgen_mp31_tables_le_v1.bin");
const fn decode_rev10(bytes: &[u8; 9_440]) -> [u16; 1024] {
    let mut table = [0_u16; 1024];
    let mut index = 0;
    while index < table.len() {
        table[index] = read_u16_le(bytes, index * 2);
        index += 1;
    }
    table
}
const fn decode_primes(bytes: &[u8; 9_440]) -> [SmallPrime; 308] {
    let mut table = [SmallPrime {
        p: 0,
        p0i: 0,
        R2: 0,
        g: 0,
        ig: 0,
        s: 0,
    }; 308];
    let mut index = 0;
    while index < table.len() {
        let offset = 2_048 + index * 24;
        table[index] = SmallPrime {
            p: read_u32_le(bytes, offset),
            p0i: read_u32_le(bytes, offset + 4),
            R2: read_u32_le(bytes, offset + 8),
            g: read_u32_le(bytes, offset + 12),
            ig: read_u32_le(bytes, offset + 16),
            s: read_u32_le(bytes, offset + 20),
        };
        index += 1;
    }
    table
}
pub const REV10: [u16; 1024] = decode_rev10(MP31_TABLE_BYTES);
pub const PRIMES: [SmallPrime; 308] = decode_primes(MP31_TABLE_BYTES);

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    fn power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let mut result = 1;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result * base % modulus;
            }
            base = base * base % modulus;
            exponent >>= 1;
        }
        result
    }

    #[test]
    fn signed_boundaries_and_modular_operations_match_integer_remainders() {
        for value in [0, 1, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
            assert_eq!(tbmask(value), if value >= 1 << 31 { u32::MAX } else { 0 });
        }
        for prime in PRIMES {
            let modulus = i64::from(prime.p);
            for value in [
                1 - modulus,
                -modulus / 2,
                -1,
                0,
                1,
                modulus / 2,
                modulus - 1,
            ] {
                let residue = mp_set(i32::try_from(value).expect("signed coefficient"), prime.p);
                assert_eq!(i64::from(residue), value.rem_euclid(modulus));
                let expected = if i64::from(residue) > modulus / 2 {
                    i64::from(residue) - modulus
                } else {
                    i64::from(residue)
                };
                assert_eq!(i64::from(mp_norm(residue, prime.p)), expected);
            }
            for value in [0, 1, modulus - 1, modulus, modulus + 1, 2 * modulus - 1] {
                assert_eq!(
                    i64::from(mp_set_u(
                        u32::try_from(value).expect("unsigned coefficient"),
                        prime.p
                    )),
                    value % modulus
                );
            }
            let values = [0, 1, prime.p / 2, prime.p - 2, prime.p - 1];
            for left in values {
                for right in values {
                    assert_eq!(
                        i64::from(mp_add(left, right, prime.p)),
                        (i64::from(left) + i64::from(right)) % modulus
                    );
                    assert_eq!(
                        i64::from(mp_sub(left, right, prime.p)),
                        (i64::from(left) - i64::from(right)).rem_euclid(modulus)
                    );
                }
                assert_eq!(
                    i64::from(mp_half(left, prime.p)),
                    i64::from(left) * ((modulus + 1) / 2) % modulus
                );
            }
        }
    }

    #[test]
    fn montgomery_products_and_public_powers_match_independent_modular_arithmetic() {
        for prime in PRIMES {
            let modulus = u64::from(prime.p);
            let radix = (1u64 << 32) % modulus;
            let inverse_radix = power(radix, modulus - 2, modulus);
            assert_eq!(u64::from(mp_R(prime.p)), radix);
            assert_eq!(u64::from(mp_hR(prime.p)), (1u64 << 31) % modulus);
            assert_eq!(u128::from(prime.R2), (1u128 << 64) % u128::from(modulus));
            let values = [0, 1, 2, prime.p / 2, prime.p - 2, prime.p - 1, prime.R2];
            for left in values {
                for right in values {
                    let expected =
                        (u64::from(left) * u64::from(right) % modulus) * inverse_radix % modulus;
                    assert_eq!(
                        u64::from(mp_mmul(left, right, prime.p, prime.p0i)),
                        expected
                    );
                }
            }
            for exponent in [0, 1, 2, 3, 31, 32, 63, 1024, u32::MAX] {
                assert_eq!(
                    u64::from(mp_Rx31(exponent, prime.p, prime.p0i, prime.R2)),
                    power(2, 31 * u64::from(exponent), modulus)
                );
            }
        }
    }
}
