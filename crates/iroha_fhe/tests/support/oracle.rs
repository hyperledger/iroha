//! Independent arbitrary-precision reference of the RNS-BGV scheme.
//!
//! The oracle never touches residues except to read and write the canonical
//! words of a test: every polynomial is a vector of integers modulo the full
//! modulus, products are schoolbook (or Kronecker substitution over one big
//! integer product for large degrees), residue polynomials are lifted with the
//! constructive Chinese remainder formula, and every rounding rule is written
//! from its definition. It re-implements the coin derivation and the samplers
//! over the `blake3` crate directly. It shares no code with `iroha_fhe`.
use num_bigint::{BigInt, BigUint, Sign};

/// A polynomial with integer coefficients.
pub type Poly = Vec<BigInt>;

/// A word as an integer.
pub fn big(value: u64) -> BigInt {
    BigInt::from(value)
}

/// The product of words.
pub fn product(values: &[u64]) -> BigInt {
    values
        .iter()
        .fold(BigInt::from(1), |acc, &value| acc * value)
}

/// The least non-negative residue.
pub fn rem(value: &BigInt, modulus: &BigInt) -> BigInt {
    let remainder = value % modulus;
    if remainder.sign() == Sign::Minus {
        remainder + modulus
    } else {
        remainder
    }
}

/// The centered representative in `[-(m-1)/2, (m-1)/2]` for odd `m`.
pub fn centered(value: &BigInt, modulus: &BigInt) -> BigInt {
    let residue = rem(value, modulus);
    if &residue * 2 > modulus - 1 {
        residue - modulus
    } else {
        residue
    }
}

/// The inverse modulo any modulus coprime to the value, by the extended Euclidean algorithm.
pub fn inverse(value: &BigInt, modulus: &BigInt) -> BigInt {
    let (mut old_r, mut r) = (rem(value, modulus), modulus.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));
    while r.sign() != Sign::NoSign {
        let quotient = &old_r / &r;
        let next_r = &old_r - &quotient * &r;
        old_r = std::mem::replace(&mut r, next_r);
        let next_s = &old_s - &quotient * &s;
        old_s = std::mem::replace(&mut s, next_s);
    }
    assert_eq!(old_r, BigInt::from(1), "value is not invertible");
    rem(&old_s, modulus)
}

/// The least non-negative word of an integer modulo a word.
pub fn word_mod(value: &BigInt, modulus: u64) -> u64 {
    rem(value, &big(modulus))
        .to_u64_digits()
        .1
        .first()
        .copied()
        .unwrap_or(0)
}

/// The constructive Chinese remainder formula for one coefficient.
pub fn crt(residues: &[u64], primes: &[u64]) -> BigInt {
    let modulus = product(primes);
    let mut total = BigInt::from(0);
    for (&residue, &prime) in residues.iter().zip(primes) {
        let partial = &modulus / prime;
        let partial_inverse = inverse(&partial, &big(prime));
        total += big(residue) * &partial * partial_inverse;
    }
    rem(&total, &modulus)
}

/// Limb-major canonical words to integer coefficients modulo the product of `primes`.
pub fn lift(words: &[u64], primes: &[u64]) -> Poly {
    let degree = words.len() / primes.len();
    assert_eq!(words.len(), degree * primes.len());
    // The partial products and their inverses are the same for every coefficient.
    let modulus = product(primes);
    let basis: Vec<BigInt> = primes
        .iter()
        .map(|&prime| {
            let partial = &modulus / prime;
            let partial_inverse = inverse(&partial, &big(prime));
            partial * partial_inverse
        })
        .collect();
    (0..degree)
        .map(|index| {
            let total = basis
                .iter()
                .enumerate()
                .fold(BigInt::from(0), |acc, (limb, element)| {
                    acc + element * words[limb * degree + index]
                });
            rem(&total, &modulus)
        })
        .collect()
}

/// Limb-major canonical words of an integer polynomial.
pub fn words(poly: &[BigInt], primes: &[u64]) -> Vec<u64> {
    primes
        .iter()
        .flat_map(|&prime| poly.iter().map(move |value| word_mod(value, prime)))
        .collect()
}

/// Largest degree multiplied by the schoolbook rule.
const SCHOOLBOOK_DEGREE: usize = 64;

/// The negacyclic product modulo `modulus`.
pub fn poly_mul(lhs: &[BigInt], rhs: &[BigInt], modulus: &BigInt) -> Poly {
    let degree = lhs.len();
    assert_eq!(rhs.len(), degree);
    if degree <= SCHOOLBOOK_DEGREE {
        let mut out = vec![BigInt::from(0); degree];
        for (i, a) in lhs.iter().enumerate() {
            for (j, b) in rhs.iter().enumerate() {
                if i + j >= degree {
                    out[i + j - degree] -= a * b;
                } else {
                    out[i + j] += a * b;
                }
            }
        }
        return out.iter().map(|value| rem(value, modulus)).collect();
    }
    // Kronecker substitution: one integer product of the packed non-negative operands.
    let modulus_bits = usize::try_from(modulus.bits()).expect("bit length fits");
    let slot_bytes = (2 * modulus_bits + degree.ilog2() as usize + 2).div_ceil(8);
    let pack = |poly: &[BigInt]| {
        let mut bytes = vec![0_u8; slot_bytes * degree];
        for (index, value) in poly.iter().enumerate() {
            let (_, digits) = rem(value, modulus).to_bytes_le();
            bytes[index * slot_bytes..index * slot_bytes + digits.len()].copy_from_slice(&digits);
        }
        BigUint::from_bytes_le(&bytes)
    };
    let mut packed = (pack(lhs) * pack(rhs)).to_bytes_le();
    packed.resize(slot_bytes * 2 * degree, 0);
    let linear: Vec<BigInt> = packed
        .chunks_exact(slot_bytes)
        .map(|chunk| BigInt::from_bytes_le(Sign::Plus, chunk))
        .collect();
    (0..degree)
        .map(|index| rem(&(&linear[index] - &linear[index + degree]), modulus))
        .collect()
}

/// Coefficient-wise sum modulo `modulus`.
pub fn poly_add(lhs: &[BigInt], rhs: &[BigInt], modulus: &BigInt) -> Poly {
    lhs.iter()
        .zip(rhs)
        .map(|(a, b)| rem(&(a + b), modulus))
        .collect()
}

/// Coefficient-wise difference modulo `modulus`.
pub fn poly_sub(lhs: &[BigInt], rhs: &[BigInt], modulus: &BigInt) -> Poly {
    lhs.iter()
        .zip(rhs)
        .map(|(a, b)| rem(&(a - b), modulus))
        .collect()
}

/// The image under `X -> X^power` over the integers.
pub fn poly_automorphism(poly: &[BigInt], power: usize) -> Poly {
    let degree = poly.len();
    let mut out = vec![BigInt::from(0); degree];
    for (index, value) in poly.iter().enumerate() {
        let exponent = index * power % (2 * degree);
        if exponent >= degree {
            out[exponent - degree] -= value;
        } else {
            out[exponent] += value;
        }
    }
    out
}

/// Small signed coefficients as integers.
pub fn small(values: &[i64]) -> Poly {
    values.iter().map(|&value| BigInt::from(value)).collect()
}

/// Coin-stream purposes, re-declared from the specification.
pub mod purpose {
    /// The ternary secret key.
    pub const SECRET_KEY: u8 = 1;
    /// The uniform polynomial of the public key.
    pub const PUBLIC_KEY_MASK: u8 = 2;
    /// The error of the public key.
    pub const PUBLIC_KEY_ERROR: u8 = 3;
    /// The ternary mask of an encryption.
    pub const ENCRYPTION_MASK: u8 = 4;
    /// The error added to `c0`.
    pub const ENCRYPTION_ERROR0: u8 = 5;
    /// The error added to `c1`.
    pub const ENCRYPTION_ERROR1: u8 = 6;
    /// The uniform polynomial of a switching-key digit.
    pub const SWITCHING_KEY_MASK: u8 = 7;
    /// The error of a switching-key digit.
    pub const SWITCHING_KEY_ERROR: u8 = 8;
}

/// Seed `index` of the fixture entropy with the given master seed.
pub fn fixture_seed(master: &[u8; 64], index: u32) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new_derive_key("iroha_fhe bgv v1 fixture entropy");
    hasher.update(master);
    hasher.update(&index.to_le_bytes());
    let mut seed = [0_u8; 64];
    hasher.finalize_xof().fill(&mut seed);
    seed
}

/// The public parameters of one profile, as plain numbers.
#[derive(Clone, Debug)]
pub struct Oracle {
    /// `log2` of the ring degree.
    pub log_degree: u32,
    /// The ring degree.
    pub degree: usize,
    /// The plaintext modulus.
    pub t: u64,
    /// Main primes.
    pub main: Vec<u64>,
    /// Roots of the main primes.
    pub main_roots: Vec<u64>,
    /// Special primes.
    pub special: Vec<u64>,
    /// Roots of the special primes.
    pub special_roots: Vec<u64>,
    /// Main primes per key-switching digit.
    pub digit_primes: usize,
    /// Centered binomial parameter.
    pub eta: u32,
}

/// A ciphertext of the oracle: integer components modulo `Q_level` and a bound.
#[derive(Clone, Debug)]
pub struct OracleCiphertext {
    /// The level.
    pub level: usize,
    /// Two or three components.
    pub components: Vec<Poly>,
    /// The public noise bound.
    pub bound: BigInt,
}

/// A switching key of the oracle: `(b_j, a_j)` modulo `Q_L * P` per digit.
pub type OracleSwitchingKey = Vec<(Poly, Poly)>;

impl Oracle {
    /// The top level.
    pub fn top(&self) -> usize {
        self.main.len() - 1
    }

    /// `Q_level`.
    pub fn modulus(&self, level: usize) -> BigInt {
        product(&self.main[..=level])
    }

    /// The special modulus `P`.
    pub fn special_product(&self) -> BigInt {
        product(&self.special)
    }

    /// Main primes followed by special primes.
    pub fn full_primes(&self) -> Vec<u64> {
        self.main.iter().chain(&self.special).copied().collect()
    }

    /// The identity, from the documented byte layout.
    pub fn identity(&self) -> [u8; 32] {
        let mut bytes = vec![1_u8];
        bytes.extend_from_slice(&self.log_degree.to_le_bytes());
        bytes.extend_from_slice(&self.t.to_le_bytes());
        for (primes, roots) in [
            (&self.main, &self.main_roots),
            (&self.special, &self.special_roots),
        ] {
            bytes.extend_from_slice(
                &u32::try_from(primes.len())
                    .expect("few primes")
                    .to_le_bytes(),
            );
            for (prime, root) in primes.iter().zip(roots) {
                bytes.extend_from_slice(&prime.to_le_bytes());
                bytes.extend_from_slice(&root.to_le_bytes());
            }
        }
        bytes.push(1);
        bytes.extend_from_slice(
            &u32::try_from(self.digit_primes)
                .expect("small digit size")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&[1, 1, 1]);
        bytes.extend_from_slice(&self.eta.to_le_bytes());
        bytes.push(1);
        blake3::derive_key("iroha_fhe bgv v1 profile identity", &bytes)
    }

    /// The digit groups present at `level`, as main-prime indices.
    pub fn digits(&self, level: usize) -> Vec<Vec<usize>> {
        let mut groups = Vec::new();
        let mut first = 0;
        while first <= level {
            groups.push((first..(first + self.digit_primes).min(level + 1)).collect());
            first += self.digit_primes;
        }
        groups
    }

    // Public noise bounds, from the formulas of the specification.

    /// `(t-1)/2 + t*B*(2N+1)`.
    pub fn fresh_noise(&self) -> BigInt {
        big((self.t - 1) / 2)
            + big(self.t) * big(u64::from(self.eta)) * big(2 * self.degree as u64 + 1)
    }

    /// `floor((t*N*B*sum floor(Q_j/2) + t*(P-1)/2*(1+N)) / P)`.
    pub fn key_switch_noise(&self, level: usize) -> BigInt {
        let halves: BigInt = self
            .digits(level)
            .iter()
            .map(|group| {
                let primes: Vec<u64> = group.iter().map(|&index| self.main[index]).collect();
                product(&primes) / 2
            })
            .sum();
        let special = self.special_product();
        let numerator = big(self.t) * big(self.degree as u64) * big(u64::from(self.eta)) * halves
            + big(self.t) * ((&special - 1) / 2) * big(1 + self.degree as u64);
        numerator / special
    }

    /// `floor((V + t*(q-1)/2*(1+N)) / q)` for the last prime of `level`.
    pub fn switch_down_noise(&self, bound: &BigInt, level: usize) -> BigInt {
        let prime = self.main[level];
        (bound + big(self.t) * big((prime - 1) / 2) * big(1 + self.degree as u64)) / prime
    }

    /// `(Q_level - 1) / 2`.
    pub fn capacity(&self, level: usize) -> BigInt {
        (self.modulus(level) - 1) / 2
    }

    // Coins.

    /// The coin stream of one sampled object.
    pub fn stream(
        &self,
        seed: &[u8; 64],
        purpose: u8,
        key_tag: u32,
        digit: u32,
    ) -> blake3::OutputReader {
        let mut material = Vec::with_capacity(32 + 1 + 4 + 4 + 64);
        material.extend_from_slice(&self.identity());
        material.push(purpose);
        material.extend_from_slice(&key_tag.to_le_bytes());
        material.extend_from_slice(&digit.to_le_bytes());
        material.extend_from_slice(seed);
        let mut hasher = blake3::Hasher::new_derive_key("iroha_fhe bgv v1 coin stream");
        hasher.update(&material);
        hasher.finalize_xof()
    }

    /// Uniform ternary coefficients: reject byte 255, else `byte mod 3 - 1`.
    pub fn ternary(&self, mut reader: blake3::OutputReader) -> Vec<i64> {
        let mut out = Vec::with_capacity(self.degree);
        while out.len() < self.degree {
            let mut byte = [0_u8; 1];
            reader.fill(&mut byte);
            if byte[0] != 255 {
                out.push(i64::from(byte[0] % 3) - 1);
            }
        }
        out
    }

    /// Centered binomial coefficients from six bytes each.
    pub fn error(&self, mut reader: blake3::OutputReader) -> Vec<i64> {
        (0..self.degree)
            .map(|_| {
                let mut bytes = [0_u8; 8];
                reader.fill(&mut bytes[..6]);
                let bits = u64::from_le_bytes(bytes);
                let mask = (1_u64 << self.eta) - 1;
                i64::from((bits & mask).count_ones())
                    - i64::from(((bits >> self.eta) & mask).count_ones())
            })
            .collect()
    }

    /// Uniform residues limb by limb, lifted to integers modulo the product of `primes`.
    pub fn uniform(&self, mut reader: blake3::OutputReader, primes: &[u64]) -> Poly {
        let mut residues = Vec::with_capacity(primes.len() * self.degree);
        for &prime in primes {
            // Primes are below 2^62, so the shift is below 64.
            let mask = (1_u64 << (64 - prime.leading_zeros())) - 1;
            let mut accepted = 0;
            while accepted < self.degree {
                let mut bytes = [0_u8; 8];
                reader.fill(&mut bytes);
                let candidate = u64::from_le_bytes(bytes) & mask;
                if candidate < prime {
                    residues.push(candidate);
                    accepted += 1;
                }
            }
        }
        lift(&residues, primes)
    }

    // Keys.

    /// The secret key of a seed.
    pub fn secret(&self, seed: &[u8; 64]) -> Vec<i64> {
        self.ternary(self.stream(seed, purpose::SECRET_KEY, 0, 0))
    }

    /// The public key `(b, a)` modulo `Q_L` of a seed.
    pub fn public_key(&self, seed: &[u8; 64], secret: &[i64]) -> (Poly, Poly) {
        let a = self.uniform(
            self.stream(seed, purpose::PUBLIC_KEY_MASK, 0, 0),
            &self.main,
        );
        let e = self.error(self.stream(seed, purpose::PUBLIC_KEY_ERROR, 0, 0));
        (self.public_key_from_coins(secret, &a, &e), a)
    }

    /// `b = -a*s + t*e` modulo `Q_L`.
    pub fn public_key_from_coins(&self, secret: &[i64], a: &[BigInt], e: &[i64]) -> Poly {
        let modulus = self.modulus(self.top());
        let a_s = poly_mul(a, &small(secret), &modulus);
        e.iter()
            .zip(&a_s)
            .map(|(&error, product)| rem(&(big(self.t) * error - product), &modulus))
            .collect()
    }

    /// The source `s^2` (tag zero) or `s(X^tag)` of a switching key, over the integers.
    pub fn switching_source(&self, secret: &[i64], tag: u32) -> Poly {
        let secret = small(secret);
        if tag == 0 {
            poly_mul(
                &secret,
                &secret,
                &(self.modulus(self.top()) * self.special_product()),
            )
        } else {
            poly_automorphism(&secret, tag as usize)
        }
    }

    /// The switching key of a seed; `tag` is zero for relinearization, else the Galois element.
    pub fn switching_key(&self, seed: &[u8; 64], secret: &[i64], tag: u32) -> OracleSwitchingKey {
        let full = self.full_primes();
        let coins: Vec<(Poly, Vec<i64>)> = (0..self.digits(self.top()).len())
            .map(|digit| {
                let digit = u32::try_from(digit).expect("few digits");
                (
                    self.uniform(
                        self.stream(seed, purpose::SWITCHING_KEY_MASK, tag, digit),
                        &full,
                    ),
                    self.error(self.stream(seed, purpose::SWITCHING_KEY_ERROR, tag, digit)),
                )
            })
            .collect();
        self.switching_key_from_coins(secret, tag, &coins)
    }

    /// `b_j = -a_j*s + t*e_j + g_j*s'` modulo `Q_L * P` for every digit.
    pub fn switching_key_from_coins(
        &self,
        secret: &[i64],
        tag: u32,
        coins: &[(Poly, Vec<i64>)],
    ) -> OracleSwitchingKey {
        let top_modulus = self.modulus(self.top());
        let special = self.special_product();
        let full_modulus = &top_modulus * &special;
        let source = self.switching_source(secret, tag);
        self.digits(self.top())
            .iter()
            .zip(coins)
            .map(|(group, (a, e))| {
                let primes: Vec<u64> = group.iter().map(|&index| self.main[index]).collect();
                let digit_modulus = product(&primes);
                let complement = &top_modulus / &digit_modulus;
                // P * (Q / Q_j) * ((Q / Q_j)^-1 mod Q_j): P modulo the digit, zero elsewhere.
                let gadget = &special * &complement * inverse(&complement, &digit_modulus);
                let a_s = poly_mul(a, &small(secret), &full_modulus);
                let b = (0..self.degree)
                    .map(|index| {
                        rem(
                            &(big(self.t) * e[index] - &a_s[index] + &gadget * &source[index]),
                            &full_modulus,
                        )
                    })
                    .collect();
                (b, a.clone())
            })
            .collect()
    }

    /// The centered lift of a plaintext coefficient list.
    pub fn centered_message(&self, message: &[u64]) -> Poly {
        message
            .iter()
            .map(|&value| centered(&big(value), &big(self.t)))
            .collect()
    }

    /// Encrypt with the coins of a seed.
    pub fn encrypt(
        &self,
        seed: &[u8; 64],
        public: &(Poly, Poly),
        message: &[u64],
    ) -> OracleCiphertext {
        let u = self.ternary(self.stream(seed, purpose::ENCRYPTION_MASK, 0, 0));
        let e0 = self.error(self.stream(seed, purpose::ENCRYPTION_ERROR0, 0, 0));
        let e1 = self.error(self.stream(seed, purpose::ENCRYPTION_ERROR1, 0, 0));
        self.encrypt_from_coins(public, message, &u, &e0, &e1)
    }

    /// `c0 = b*u + t*e0 + m`, `c1 = a*u + t*e1` modulo `Q_L`.
    pub fn encrypt_from_coins(
        &self,
        public: &(Poly, Poly),
        message: &[u64],
        u: &[i64],
        e0: &[i64],
        e1: &[i64],
    ) -> OracleCiphertext {
        let modulus = self.modulus(self.top());
        let b_u = poly_mul(&public.0, &small(u), &modulus);
        let a_u = poly_mul(&public.1, &small(u), &modulus);
        let message = self.centered_message(message);
        let c0 = (0..self.degree)
            .map(|index| {
                rem(
                    &(&b_u[index] + big(self.t) * e0[index] + &message[index]),
                    &modulus,
                )
            })
            .collect();
        let c1 = (0..self.degree)
            .map(|index| rem(&(&a_u[index] + big(self.t) * e1[index]), &modulus))
            .collect();
        OracleCiphertext {
            level: self.top(),
            components: vec![c0, c1],
            bound: self.fresh_noise(),
        }
    }

    /// A ciphertext of the oracle from canonical words.
    pub fn ciphertext(
        &self,
        level: usize,
        components: usize,
        canonical: &[u64],
        bound: BigInt,
    ) -> OracleCiphertext {
        let per_component = canonical.len() / components;
        OracleCiphertext {
            level,
            components: canonical
                .chunks_exact(per_component)
                .map(|chunk| lift(chunk, &self.main[..=level]))
                .collect(),
            bound,
        }
    }

    /// Canonical words of a ciphertext of the oracle.
    pub fn ciphertext_words(&self, ciphertext: &OracleCiphertext) -> Vec<u64> {
        ciphertext
            .components
            .iter()
            .flat_map(|component| words(component, &self.main[..=ciphertext.level]))
            .collect()
    }

    // Decryption and exact noise.

    /// The centered value of `c0 + c1*s + c2*s^2` modulo `Q_level`.
    pub fn inner(&self, secret: &[i64], ciphertext: &OracleCiphertext) -> Poly {
        let modulus = self.modulus(ciphertext.level);
        let secret = small(secret);
        let mut accumulator = vec![BigInt::from(0); self.degree];
        let mut power: Poly = (0..self.degree)
            .map(|index| big(u64::from(index == 0)))
            .collect();
        for component in &ciphertext.components {
            accumulator = poly_add(
                &accumulator,
                &poly_mul(component, &power, &modulus),
                &modulus,
            );
            power = poly_mul(&power, &secret, &modulus);
        }
        accumulator
            .iter()
            .map(|value| centered(value, &modulus))
            .collect()
    }

    /// The plaintext: the centered inner product modulo `t`.
    pub fn decrypt(&self, secret: &[i64], ciphertext: &OracleCiphertext) -> Vec<u64> {
        self.inner(secret, ciphertext)
            .iter()
            .map(|value| word_mod(value, self.t))
            .collect()
    }

    /// The exact noise: the infinity norm of the centered inner product.
    pub fn exact_noise(&self, secret: &[i64], ciphertext: &OracleCiphertext) -> BigInt {
        self.inner(secret, ciphertext)
            .iter()
            .map(|value| value.magnitude().clone())
            .max()
            .map_or_else(|| BigInt::from(0), BigInt::from)
    }

    // Homomorphic operations.

    fn with_components(
        ciphertext: &OracleCiphertext,
        components: Vec<Poly>,
        bound: BigInt,
    ) -> OracleCiphertext {
        OracleCiphertext {
            level: ciphertext.level,
            components,
            bound,
        }
    }

    /// Component-wise sum.
    pub fn add(&self, lhs: &OracleCiphertext, rhs: &OracleCiphertext) -> OracleCiphertext {
        let modulus = self.modulus(lhs.level);
        let components = lhs
            .components
            .iter()
            .zip(&rhs.components)
            .map(|(a, b)| poly_add(a, b, &modulus))
            .collect();
        Self::with_components(lhs, components, &lhs.bound + &rhs.bound)
    }

    /// Component-wise difference.
    pub fn sub(&self, lhs: &OracleCiphertext, rhs: &OracleCiphertext) -> OracleCiphertext {
        let modulus = self.modulus(lhs.level);
        let components = lhs
            .components
            .iter()
            .zip(&rhs.components)
            .map(|(a, b)| poly_sub(a, b, &modulus))
            .collect();
        Self::with_components(lhs, components, &lhs.bound + &rhs.bound)
    }

    /// Plaintext addition with a declared infinity-norm bound.
    pub fn add_plain(
        &self,
        ciphertext: &OracleCiphertext,
        message: &[u64],
        linf: u64,
    ) -> OracleCiphertext {
        let modulus = self.modulus(ciphertext.level);
        let mut components = ciphertext.components.clone();
        components[0] = poly_add(&components[0], &self.centered_message(message), &modulus);
        Self::with_components(ciphertext, components, &ciphertext.bound + linf)
    }

    /// Plaintext multiplication with a declared `l1` bound.
    pub fn mul_plain(
        &self,
        ciphertext: &OracleCiphertext,
        message: &[u64],
        l1: u64,
    ) -> OracleCiphertext {
        let modulus = self.modulus(ciphertext.level);
        let message = self.centered_message(message);
        let components = ciphertext
            .components
            .iter()
            .map(|component| poly_mul(component, &message, &modulus))
            .collect();
        Self::with_components(ciphertext, components, &ciphertext.bound * l1)
    }

    /// The tensor product of two two-component ciphertexts.
    pub fn tensor(&self, lhs: &OracleCiphertext, rhs: &OracleCiphertext) -> OracleCiphertext {
        let modulus = self.modulus(lhs.level);
        let (a0, a1) = (&lhs.components[0], &lhs.components[1]);
        let (b0, b1) = (&rhs.components[0], &rhs.components[1]);
        let d1 = poly_add(
            &poly_mul(a0, b1, &modulus),
            &poly_mul(a1, b0, &modulus),
            &modulus,
        );
        let components = vec![poly_mul(a0, b0, &modulus), d1, poly_mul(a1, b1, &modulus)];
        Self::with_components(
            lhs,
            components,
            &lhs.bound * &rhs.bound * big(self.degree as u64),
        )
    }

    /// Hybrid key switch of one component at `level`.
    pub fn key_switch(
        &self,
        level: usize,
        component: &[BigInt],
        key: &OracleSwitchingKey,
    ) -> (Poly, Poly) {
        let level_modulus = self.modulus(level);
        let special = self.special_product();
        let extended = &level_modulus * &special;
        let mut accumulators = [
            vec![BigInt::from(0); self.degree],
            vec![BigInt::from(0); self.degree],
        ];
        for (group, (key_b, key_a)) in self.digits(level).iter().zip(key) {
            let primes: Vec<u64> = group.iter().map(|&index| self.main[index]).collect();
            let digit_modulus = product(&primes);
            let digit: Poly = component
                .iter()
                .map(|value| rem(&centered(value, &digit_modulus), &extended))
                .collect();
            for (accumulator, key_part) in accumulators.iter_mut().zip([key_b, key_a]) {
                let reduced: Poly = key_part.iter().map(|value| rem(value, &extended)).collect();
                *accumulator = poly_add(
                    accumulator,
                    &poly_mul(&digit, &reduced, &extended),
                    &extended,
                );
            }
        }
        let inverse_t = inverse(&big(self.t), &special);
        let divide = |accumulator: &Poly| -> Poly {
            accumulator
                .iter()
                .map(|value| {
                    let correction = big(self.t) * centered(&(value * &inverse_t), &special);
                    let numerator = value - correction;
                    assert_eq!(&numerator % &special, BigInt::from(0));
                    rem(&(numerator / &special), &level_modulus)
                })
                .collect()
        };
        (divide(&accumulators[0]), divide(&accumulators[1]))
    }

    /// Relinearize a three-component ciphertext.
    pub fn relinearize(
        &self,
        ciphertext: &OracleCiphertext,
        key: &OracleSwitchingKey,
    ) -> OracleCiphertext {
        let modulus = self.modulus(ciphertext.level);
        let (k0, k1) = self.key_switch(ciphertext.level, &ciphertext.components[2], key);
        let components = vec![
            poly_add(&ciphertext.components[0], &k0, &modulus),
            poly_add(&ciphertext.components[1], &k1, &modulus),
        ];
        Self::with_components(
            ciphertext,
            components,
            &ciphertext.bound + self.key_switch_noise(ciphertext.level),
        )
    }

    /// Apply `X -> X^element` and switch back to the secret key.
    pub fn apply_galois(
        &self,
        ciphertext: &OracleCiphertext,
        element: u32,
        key: &OracleSwitchingKey,
    ) -> OracleCiphertext {
        let modulus = self.modulus(ciphertext.level);
        let rotate = |component: &Poly| -> Poly {
            poly_automorphism(component, element as usize)
                .iter()
                .map(|value| rem(value, &modulus))
                .collect()
        };
        let rotated0 = rotate(&ciphertext.components[0]);
        let rotated1 = rotate(&ciphertext.components[1]);
        let (k0, k1) = self.key_switch(ciphertext.level, &rotated1, key);
        Self::with_components(
            ciphertext,
            vec![poly_add(&rotated0, &k0, &modulus), k1],
            &ciphertext.bound + self.key_switch_noise(ciphertext.level),
        )
    }

    /// Drop the last prime with the congruence-preserving rule.
    pub fn switch_down(&self, ciphertext: &OracleCiphertext) -> OracleCiphertext {
        let dropped = big(self.main[ciphertext.level]);
        let lower = self.modulus(ciphertext.level - 1);
        let inverse_t = inverse(&big(self.t), &dropped);
        let components = ciphertext
            .components
            .iter()
            .map(|component| {
                component
                    .iter()
                    .map(|value| {
                        let correction = big(self.t) * centered(&(value * &inverse_t), &dropped);
                        let numerator = value - correction;
                        assert_eq!(&numerator % &dropped, BigInt::from(0));
                        rem(&(numerator / &dropped), &lower)
                    })
                    .collect()
            })
            .collect();
        OracleCiphertext {
            level: ciphertext.level - 1,
            components,
            bound: self.switch_down_noise(&ciphertext.bound, ciphertext.level),
        }
    }
}
