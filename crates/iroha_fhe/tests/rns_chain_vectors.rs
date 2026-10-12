//! Arbitrary-chain RNS against pinned vectors and an independent arbitrary-precision oracle.
//!
//! The pinned answers come from `tests/vectors/bgv_reference.py` (Python
//! integers). Every test also re-derives its expectation at run time with the
//! `num-bigint` oracle of `tests/support`, which lifts residues with the
//! constructive Chinese remainder formula and applies each rounding rule from
//! its definition. The chains here are far beyond the 128-bit reconstruction
//! limit of `iroha_fhe::rns`: eighteen 50-bit primes (883 bits), six 60-bit
//! primes, and random chains of up to 64 primes of 50 to 62 bits.
mod support;

use iroha_fhe::{
    natural::Natural,
    rns_chain::{CongruentScaleDown, ConversionTarget, MAX_BASIS_PRIMES, RnsBasis},
};
use num_bigint::{BigInt, Sign};
use support::{
    kat::Kat,
    oracle::{big, centered, inverse, lift, product, rem, word_mod, words},
};

/// A deterministic 64-bit generator for test inputs.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 ^ (self.0 >> 29)
    }
}

/// Miller-Rabin with the seven bases that decide every 64-bit integer; independent of the crate.
fn is_prime(candidate: u64) -> bool {
    if candidate < 2 {
        return false;
    }
    for small in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if candidate.is_multiple_of(small) {
            return candidate == small;
        }
    }
    let power = |mut base: u128, mut exponent: u64| {
        let modulus = u128::from(candidate);
        let mut result = 1_u128;
        base %= modulus;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result * base % modulus;
            }
            base = base * base % modulus;
            exponent >>= 1;
        }
        result
    };
    let twos = (candidate - 1).trailing_zeros();
    let odd = (candidate - 1) >> twos;
    'bases: for base in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        if base % candidate == 0 {
            continue;
        }
        let mut witness = power(u128::from(base), odd);
        if witness == 1 || witness == u128::from(candidate - 1) {
            continue;
        }
        for _ in 1..twos {
            witness = witness * witness % u128::from(candidate);
            if witness == u128::from(candidate - 1) {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

/// `count` distinct primes with bit lengths cycling through 50 to 62.
fn random_primes(generator: &mut Generator, count: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(count);
    while primes.len() < count {
        let bits = 50 + u32::try_from(primes.len() % 13).expect("below 13");
        let mut candidate = (1_u64 << (bits - 1)) | (generator.next() >> (65 - bits)) | 1;
        while !is_prime(candidate) || primes.contains(&candidate) {
            candidate += 2;
        }
        assert_eq!(64 - candidate.leading_zeros(), bits);
        primes.push(candidate);
    }
    primes
}

fn natural_to_bigint(value: &Natural) -> BigInt {
    let bytes: Vec<u8> = value
        .words_le()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

fn targets_for(basis: &RnsBasis, moduli: &[u64]) -> Vec<ConversionTarget> {
    moduli
        .iter()
        .map(|&modulus| basis.conversion_target(modulus).expect("target"))
        .collect()
}

#[test]
fn conversion_reproduces_the_pinned_vectors_over_eighteen_fifty_bit_primes() {
    let kat = Kat::load();
    let section = kat.section("rns_chain");
    let main = section.numbers("main");
    let target_moduli = section.numbers("targets");
    let values = section.integers("values");
    let source = section.words("source_words");
    assert_eq!(main.len(), 18);
    assert!(main.iter().all(|prime| 64 - prime.leading_zeros() == 50));
    let modulus = product(&main);
    // Eighteen primes just above 2^49: the product is just above 2^882.
    assert_eq!(modulus.bits(), 883);
    let degree = values.len();
    // The pinned source words are the residues of the pinned integers.
    let reduced: Vec<BigInt> = values.iter().map(|value| rem(value, &modulus)).collect();
    assert_eq!(source, words(&reduced, &main));
    let basis = RnsBasis::new(&main).expect("basis");
    assert_eq!(natural_to_bigint(&basis.product()), modulus);
    assert_eq!(natural_to_bigint(&basis.half_product()), (&modulus - 1) / 2);
    let targets = targets_for(&basis, &target_moduli);
    let mut centered_out = vec![0_u64; targets.len() * degree];
    basis
        .convert_centered(&source, degree, &targets, &mut centered_out)
        .expect("centered");
    assert_eq!(centered_out, section.words("centered_words"));
    let mut canonical_out = vec![0_u64; targets.len() * degree];
    basis
        .convert_canonical(&source, degree, &targets, &mut canonical_out)
        .expect("canonical");
    assert_eq!(canonical_out, section.words("canonical_words"));
    // The oracle re-derives both from the lifted integers, and the reconstruction agrees.
    let lifted = lift(&source, &main);
    for (index, value) in lifted.iter().enumerate() {
        let residues: Vec<u64> = (0..main.len())
            .map(|limb| source[limb * degree + index])
            .collect();
        assert_eq!(
            natural_to_bigint(&basis.reconstruct_canonical(&residues).expect("natural")),
            *value
        );
        let (negative, magnitude) = basis.reconstruct_centered(&residues).expect("centered");
        let signed = centered(value, &modulus);
        assert_eq!(signed, values[index]);
        assert_eq!(negative, signed.sign() == Sign::Minus);
        assert_eq!(
            natural_to_bigint(&magnitude),
            BigInt::from(signed.magnitude().clone())
        );
        for (limb, &target) in target_moduli.iter().enumerate() {
            assert_eq!(
                centered_out[limb * degree + index],
                word_mod(&signed, target)
            );
            assert_eq!(
                canonical_out[limb * degree + index],
                word_mod(value, target)
            );
        }
    }
}

#[test]
fn scale_down_reproduces_the_pinned_vectors() {
    let kat = Kat::load();
    let section = kat.section("rns_chain");
    let main = section.numbers("main");
    let special = section.numbers("special");
    assert!(special.iter().all(|prime| 64 - prime.leading_zeros() == 60));
    let cases: [(&str, &[u64], &[u64]); 2] = [
        ("drop_last", &main[..17], &main[17..]),
        ("drop_special", &main, &special),
    ];
    for (name, kept, dropped) in cases {
        for scale in [257_u64, 1] {
            let prefix = format!("{name}_scale{scale}");
            let mut kept_words = section.words(&format!("{prefix}_kept_in"));
            let dropped_words = section.words(&format!("{prefix}_dropped_in"));
            let degree = dropped_words.len() / dropped.len();
            // The oracle computes (c - t*w) / D from the lifted integer.
            let all_primes: Vec<u64> = kept.iter().chain(dropped).copied().collect();
            let mut all_words = kept_words.clone();
            all_words.extend_from_slice(&dropped_words);
            let total = product(&all_primes);
            let dropped_product = product(dropped);
            let scale_inverse = inverse(&big(scale), &dropped_product);
            let expected: Vec<BigInt> = lift(&all_words, &all_primes)
                .iter()
                .map(|value| {
                    let value = centered(value, &total);
                    let correction =
                        big(scale) * centered(&(&value * &scale_inverse), &dropped_product);
                    let numerator = &value - correction;
                    assert_eq!(rem(&numerator, &dropped_product), BigInt::from(0));
                    let quotient = numerator / &dropped_product;
                    // The scale residue is preserved up to the factor D, and the error is <= t/2.
                    assert_eq!(
                        rem(&(&quotient * &dropped_product - &value), &big(scale)),
                        BigInt::from(0)
                    );
                    let error: BigInt = &quotient * &dropped_product - &value;
                    assert!(
                        BigInt::from(error.magnitude().clone()) * 2
                            <= big(scale) * &dropped_product
                    );
                    quotient
                })
                .collect();
            let plan = CongruentScaleDown::new(kept, dropped, scale).expect("plan");
            plan.apply(&mut kept_words, &dropped_words, degree)
                .expect("apply");
            assert_eq!(
                kept_words,
                section.words(&format!("{prefix}_kept_out")),
                "{prefix}"
            );
            assert_eq!(kept_words, words(&expected, kept), "{prefix}");
        }
    }
}

#[test]
fn random_chains_of_fifty_to_sixty_two_bit_primes_convert_exactly() {
    let mut generator = Generator(0x5EED_0001);
    for limbs in [1_usize, 2, 3, 5, 8, 13, 22, 34, MAX_BASIS_PRIMES] {
        let primes = random_primes(&mut generator, limbs);
        let modulus = product(&primes);
        let basis = RnsBasis::new(&primes).expect("basis");
        let target_moduli = [257_u64, 65_537, 786_433, primes[0], (1 << 62) + 1, 3];
        let targets = targets_for(&basis, &target_moduli);
        let degree = 12;
        let half: BigInt = (&modulus - 1) / 2;
        // Random residues plus the ends of the centered range and the values next to them.
        let one = BigInt::from(1);
        let mut values: Vec<BigInt> = vec![
            BigInt::from(0),
            one.clone(),
            &modulus - &one,
            half.clone(),
            &half + &one,
            &half - &one,
        ];
        while values.len() < degree {
            let bytes: Vec<u8> = (0..limbs * 8 + 8)
                .flat_map(|_| generator.next().to_le_bytes())
                .collect();
            values.push(rem(&BigInt::from_bytes_le(Sign::Plus, &bytes), &modulus));
        }
        let source = words(&values, &primes);
        let mut centered_out = vec![0_u64; targets.len() * degree];
        basis
            .convert_centered(&source, degree, &targets, &mut centered_out)
            .expect("centered");
        let mut canonical_out = vec![0_u64; targets.len() * degree];
        basis
            .convert_canonical(&source, degree, &targets, &mut canonical_out)
            .expect("canonical");
        for (index, value) in values.iter().enumerate() {
            let signed = centered(value, &modulus);
            for (limb, &target) in target_moduli.iter().enumerate() {
                assert_eq!(
                    centered_out[limb * degree + index],
                    word_mod(&signed, target),
                    "limbs {limbs} value {index} target {target}"
                );
                assert_eq!(
                    canonical_out[limb * degree + index],
                    word_mod(value, target)
                );
            }
            // The half itself is non-negative and the next value is negative.
            let residues: Vec<u64> = primes.iter().map(|&prime| word_mod(value, prime)).collect();
            let mut digits = residues.clone();
            basis.mixed_radix_in_place(&mut digits).expect("digits");
            assert_eq!(
                basis.exceeds_half_bit(&digits),
                u64::from(*value > half),
                "limbs {limbs} value {index}"
            );
            // Mixed-radix digits are the digits of the canonical representative.
            let mut rest = value.clone();
            for (&digit, &prime) in digits.iter().zip(&primes) {
                assert_eq!(digit, word_mod(&rest, prime));
                rest /= prime;
            }
            assert_eq!(rest, BigInt::from(0));
        }
    }
}

#[test]
fn random_scale_downs_divide_exactly_for_every_basis_split() {
    let mut generator = Generator(0x5EED_0002);
    for (kept_count, dropped_count) in
        [(1_usize, 1_usize), (4, 1), (9, 2), (21, 2), (30, 4), (0, 3)]
    {
        let primes = random_primes(&mut generator, kept_count + dropped_count);
        let (kept, dropped) = primes.split_at(kept_count);
        for scale in [1_u64, 257, 65_537, 786_433] {
            let total = product(&primes);
            let dropped_product = product(dropped);
            let kept_product = product(kept);
            let degree = 10;
            let half: BigInt = (&total - 1) / 2;
            let one = BigInt::from(1);
            let two = BigInt::from(2);
            let mut values: Vec<BigInt> = vec![
                BigInt::from(0),
                half.clone(),
                -half.clone(),
                dropped_product.clone(),
                (&dropped_product - &one) / &two,
                (&dropped_product + &one) / &two,
            ];
            while values.len() < degree {
                let bytes: Vec<u8> = (0..primes.len() * 8 + 8)
                    .flat_map(|_| generator.next().to_le_bytes())
                    .collect();
                values.push(centered(&BigInt::from_bytes_le(Sign::Plus, &bytes), &total));
            }
            let reduced: Vec<BigInt> = values.iter().map(|value| rem(value, &total)).collect();
            let mut kept_words = words(&reduced, kept);
            let dropped_words = words(&reduced, dropped);
            let plan = CongruentScaleDown::new(kept, dropped, scale).expect("plan");
            plan.apply(&mut kept_words, &dropped_words, degree)
                .expect("apply");
            let scale_inverse = inverse(&big(scale), &dropped_product);
            let expected: Vec<BigInt> = values
                .iter()
                .map(|value| {
                    let correction =
                        big(scale) * centered(&(value * &scale_inverse), &dropped_product);
                    let numerator: BigInt = value - correction;
                    assert_eq!(rem(&numerator, &dropped_product), BigInt::from(0));
                    rem(&(numerator / &dropped_product), &kept_product)
                })
                .collect();
            assert_eq!(
                kept_words,
                words(&expected, kept),
                "kept {kept_count} dropped {dropped_count} scale {scale}"
            );
        }
    }
}
