//! The public noise bound against the exact noise, at the boundary and over random sequences.
//!
//! The exact noise of a ciphertext is the infinity norm of the centered value
//! of `c0 + c1*s` modulo `Q_l`. It is secret-derived, so the implementation
//! never computes it; here the independent oracle of `tests/support` computes
//! it from the canonical words and the secret coefficients, which only the
//! fixture feature exposes. The tests establish four things:
//!
//! - the fresh bound is attained exactly by worst-case coins, and such a
//!   ciphertext decrypts;
//! - a ciphertext whose noise equals the capacity decrypts, one step beyond
//!   it decrypts wrongly, and a claimed bound above the capacity is refused;
//! - the modulus-switch bound is attained within one unit by aligned inputs;
//! - over random admitted operation sequences the exact noise never exceeds
//!   the public bound, the bound equals the oracle's independent formula, the
//!   plaintext is the expected one, and every refusal coincides with the
//!   oracle's bound exceeding the capacity.
mod support;

use iroha_fhe::{
    bgv::{
        BgvError, BgvParameters, BgvProfile, Ciphertext, EvaluationKeys, NoiseBound, Plaintext,
        PlaintextBound, SecretKey,
        fixtures::{self, FixtureEntropy},
    },
    natural::Natural,
};
use num_bigint::{BigInt, Sign};
use support::oracle::{
    Oracle, OracleCiphertext, big, centered, lift, poly_add, poly_automorphism, poly_mul, poly_sub,
    rem, small, word_mod, words,
};

fn natural_to_bigint(value: &Natural) -> BigInt {
    let bytes: Vec<u8> = value
        .words_le()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

fn bigint_to_natural(value: &BigInt) -> Natural {
    let (sign, digits) = value.to_u64_digits();
    assert_ne!(sign, Sign::Minus);
    Natural::from_words_le(&digits)
}

fn oracle_of(profile: &BgvProfile) -> Oracle {
    let parameters = profile.parameters();
    Oracle {
        log_degree: parameters.log_degree,
        degree: parameters.degree(),
        t: parameters.plaintext_modulus,
        main: parameters.main_primes.clone(),
        main_roots: parameters.main_roots.clone(),
        special: parameters.special_primes.clone(),
        special_roots: parameters.special_roots.clone(),
        digit_primes: parameters.digit_primes,
        eta: parameters.error_eta,
    }
}

fn profile(shape: (u32, u64, (u32, usize), (u32, usize), usize)) -> BgvProfile {
    let (log_degree, plaintext_modulus, main, special, digit_primes) = shape;
    BgvProfile::new(
        BgvParameters::derive(log_degree, plaintext_modulus, main, special, digit_primes)
            .expect("parameters"),
    )
    .expect("profile")
}

fn master(tag: u8) -> [u8; 64] {
    std::array::from_fn(|index| {
        tag.wrapping_mul(59)
            .wrapping_add(u8::try_from(index).expect("index below 64").wrapping_mul(3))
    })
}

/// A deterministic generator for test choices.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 ^ (self.0 >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("below a usize bound")
    }
}

/// The exact noise of a production ciphertext, computed by the oracle.
fn exact_noise(oracle: &Oracle, secret: &SecretKey, ciphertext: &Ciphertext) -> BigInt {
    let lifted = oracle.ciphertext(
        ciphertext.level(),
        ciphertext.component_count(),
        &ciphertext.canonical_words(),
        BigInt::from(0),
    );
    oracle.exact_noise(&fixtures::secret_coefficients(secret), &lifted)
}

#[test]
fn worst_case_coins_attain_the_fresh_bound_exactly_and_still_decrypt() {
    for shape in [
        (
            4_u32,
            257_u64,
            (30_u32, 3_usize),
            (31_u32, 2_usize),
            2_usize,
        ),
        (3, 257, (50, 3), (60, 2), 2),
        (5, 65_537, (55, 3), (60, 2), 2),
    ] {
        let profile = profile(shape);
        let oracle = oracle_of(&profile);
        let degree = profile.degree();
        let bound = i64::try_from(profile.error_bound()).expect("bound");
        // s = 1 - X - X^2 - ...: coefficient zero of e*s is the sum of |e_i| for e = (B, ..., B).
        let aligned: Vec<i64> = (0..degree)
            .map(|index| if index == 0 { 1 } else { -1 })
            .collect();
        let errors = vec![bound; degree];
        let secret = fixtures::secret_key_from_coefficients(&profile, &aligned).expect("secret");
        let mask: Vec<u64> = oracle
            .main
            .iter()
            .flat_map(|&prime| (0..degree as u64).map(move |index| (index * 77 + 5) % prime))
            .collect();
        let public =
            fixtures::public_key_from_coins(&profile, &secret, &mask, &errors).expect("public");
        // The largest centered plaintext coefficient in position zero.
        let half = (profile.plaintext_modulus() - 1) / 2;
        let mut message = vec![3_u64; degree];
        message[0] = half;
        let plaintext = Plaintext::new(&profile, message.clone()).expect("plaintext");
        let ciphertext =
            fixtures::encrypt_from_coins(&profile, &public, &plaintext, &aligned, &errors, &errors)
                .expect("ciphertext");
        let fresh = natural_to_bigint(profile.fresh_noise());
        assert_eq!(fresh, oracle.fresh_noise());
        assert_eq!(
            natural_to_bigint(ciphertext.noise_bound().as_natural()),
            fresh
        );
        // (t-1)/2 + t*B*(N + 1 + N): the bound is attained, not merely respected.
        assert_eq!(exact_noise(&oracle, &secret, &ciphertext), fresh);
        assert_eq!(
            secret
                .decrypt(&profile, &ciphertext)
                .expect("plaintext")
                .coefficients(),
            message
        );
        // With the opposite error signs the same magnitude is attained on the negative side.
        let negated: Vec<i64> = errors.iter().map(|error| -error).collect();
        let negative_public =
            fixtures::public_key_from_coins(&profile, &secret, &mask, &negated).expect("public");
        message[0] = half + 1;
        let plaintext = Plaintext::new(&profile, message.clone()).expect("plaintext");
        let ciphertext = fixtures::encrypt_from_coins(
            &profile,
            &negative_public,
            &plaintext,
            &aligned,
            &negated,
            &negated,
        )
        .expect("ciphertext");
        assert_eq!(exact_noise(&oracle, &secret, &ciphertext), fresh);
        assert_eq!(
            secret
                .decrypt(&profile, &ciphertext)
                .expect("plaintext")
                .coefficients(),
            message
        );
    }
}

/// Build `(c0, c1)` at `level` with `c0 + c1*s = value` modulo `Q_level`, as canonical words.
fn ciphertext_words_with_inner(
    oracle: &Oracle,
    secret: &[i64],
    level: usize,
    value: &[BigInt],
    generator: &mut Generator,
) -> Vec<u64> {
    let primes = &oracle.main[..=level];
    let modulus = oracle.modulus(level);
    let mask_words: Vec<u64> = primes
        .iter()
        .flat_map(|&prime| {
            (0..oracle.degree)
                .map(|_| generator.next() % prime)
                .collect::<Vec<_>>()
        })
        .collect();
    let c1 = lift(&mask_words, primes);
    let c1_s = poly_mul(&c1, &small(secret), &modulus);
    let c0 = poly_sub(
        &value
            .iter()
            .map(|coefficient| rem(coefficient, &modulus))
            .collect::<Vec<_>>(),
        &c1_s,
        &modulus,
    );
    let mut canonical = words(&c0, primes);
    canonical.extend(words(&c1, primes));
    canonical
}

#[test]
fn noise_equal_to_the_capacity_decrypts_and_one_step_beyond_does_not() {
    for shape in [
        (
            4_u32,
            257_u64,
            (30_u32, 3_usize),
            (31_u32, 2_usize),
            2_usize,
        ),
        (3, 257, (50, 4), (60, 2), 2),
    ] {
        let profile = profile(shape);
        let oracle = oracle_of(&profile);
        let mut entropy = FixtureEntropy::new(master(1));
        let secret = fixtures::secret_key(&profile, &mut entropy).expect("secret");
        let coefficients = fixtures::secret_coefficients(&secret);
        let mut generator = Generator(0xB0B0);
        for level in 0..=profile.top_level() {
            let capacity = oracle.capacity(level);
            assert_eq!(
                natural_to_bigint(profile.capacity(level).expect("capacity")),
                capacity
            );
            // Coefficients at +capacity, -capacity and just inside; the rest small.
            let mut value: Vec<BigInt> = (0..profile.degree())
                .map(|index| BigInt::from(index as u64) * 1000 - 3000)
                .collect();
            value[0] = capacity.clone();
            value[1] = -capacity.clone();
            value[2] = &capacity - 1;
            let canonical =
                ciphertext_words_with_inner(&oracle, &coefficients, level, &value, &mut generator);
            let expected: Vec<u64> = value
                .iter()
                .map(|coefficient| word_mod(coefficient, oracle.t))
                .collect();
            let at_capacity = Ciphertext::from_canonical_words(
                &profile,
                level,
                2,
                &canonical,
                &NoiseBound::new(bigint_to_natural(&capacity)),
            )
            .expect("a bound equal to the capacity is admitted");
            assert_eq!(exact_noise(&oracle, &secret, &at_capacity), capacity);
            assert_eq!(
                secret
                    .decrypt(&profile, &at_capacity)
                    .expect("plaintext")
                    .coefficients(),
                expected,
                "level {level}"
            );
            // A claimed bound one above the capacity is refused.
            assert_eq!(
                Ciphertext::from_canonical_words(
                    &profile,
                    level,
                    2,
                    &canonical,
                    &NoiseBound::new(bigint_to_natural(&(&capacity + 1))),
                )
                .err(),
                Some(BgvError::NoiseBudgetExceeded { level })
            );
            // One step beyond: the true value capacity + 1 wraps to -capacity and the
            // plaintext of that coefficient is wrong, exactly as the failure condition states.
            value[0] = &capacity + 1;
            let canonical =
                ciphertext_words_with_inner(&oracle, &coefficients, level, &value, &mut generator);
            let beyond = Ciphertext::from_canonical_words(
                &profile,
                level,
                2,
                &canonical,
                &NoiseBound::new(bigint_to_natural(&capacity)),
            )
            .expect("the claim, not the truth, is checked");
            let opened = secret.decrypt(&profile, &beyond).expect("plaintext");
            let intended = word_mod(&value[0], oracle.t);
            assert_ne!(opened.coefficients()[0], intended, "level {level}");
            assert_eq!(
                opened.coefficients()[0],
                word_mod(&-capacity.clone(), oracle.t)
            );
            assert_eq!(&opened.coefficients()[1..], &expected[1..]);
        }
    }
}

#[test]
fn a_sum_that_lands_exactly_on_the_capacity_is_admitted_and_decrypts() {
    let profile = profile((4, 257, (30, 3), (31, 2), 2));
    let oracle = oracle_of(&profile);
    let mut entropy = FixtureEntropy::new(master(2));
    let secret = fixtures::secret_key(&profile, &mut entropy).expect("secret");
    let coefficients = fixtures::secret_coefficients(&secret);
    let mut generator = Generator(0xC0DE);
    let level = 1;
    let capacity = oracle.capacity(level);
    let share = big(123_456_789);
    let mut lhs_value = vec![BigInt::from(5); profile.degree()];
    let mut rhs_value = vec![BigInt::from(-9); profile.degree()];
    lhs_value[0] = &capacity - &share;
    rhs_value[0] = share.clone();
    lhs_value[3] = -(&capacity - &share);
    rhs_value[3] = -share.clone();
    let build = |value: &[BigInt], bound: &BigInt, generator: &mut Generator| {
        Ciphertext::from_canonical_words(
            &profile,
            level,
            2,
            &ciphertext_words_with_inner(&oracle, &coefficients, level, value, generator),
            &NoiseBound::new(bigint_to_natural(bound)),
        )
        .expect("ciphertext")
    };
    let lhs_bound: BigInt = &capacity - &share;
    let lhs = build(&lhs_value, &lhs_bound, &mut generator);
    let rhs = build(&rhs_value, &share, &mut generator);
    let sum = profile
        .add(&lhs, &rhs)
        .expect("a sum bound equal to the capacity is admitted");
    assert_eq!(natural_to_bigint(sum.noise_bound().as_natural()), capacity);
    assert_eq!(exact_noise(&oracle, &secret, &sum), capacity);
    let expected: Vec<u64> = lhs_value
        .iter()
        .zip(&rhs_value)
        .map(|(a, b)| word_mod(&(a + b), oracle.t))
        .collect();
    assert_eq!(
        secret
            .decrypt(&profile, &sum)
            .expect("plaintext")
            .coefficients(),
        expected
    );
    // One more unit of declared bound on either operand and the sum is refused.
    let rhs_above = build(&rhs_value, &(&share + 1), &mut generator);
    assert_eq!(
        profile.add(&lhs, &rhs_above).err(),
        Some(BgvError::NoiseBudgetExceeded { level })
    );
    assert_eq!(
        profile.sub(&lhs, &rhs_above).err(),
        Some(BgvError::NoiseBudgetExceeded { level })
    );
}

#[test]
fn the_modulus_switch_bound_is_attained_within_one_unit() {
    for shape in [
        (
            4_u32,
            257_u64,
            (30_u32, 3_usize),
            (31_u32, 2_usize),
            2_usize,
        ),
        (3, 257, (50, 3), (60, 2), 2),
    ] {
        let profile = profile(shape);
        let oracle = oracle_of(&profile);
        let degree = profile.degree();
        // s = 1 - X - X^2 - ...: coefficient zero of d*s is N*d for d = (d, ..., d).
        let aligned: Vec<i64> = (0..degree)
            .map(|index| if index == 0 { 1 } else { -1 })
            .collect();
        let secret = fixtures::secret_key_from_coefficients(&profile, &aligned).expect("secret");
        let level = profile.top_level();
        let modulus = oracle.modulus(level);
        let dropped = big(oracle.main[level]);
        let t = big(oracle.t);
        // c1 = t * (q-1)/2 in every coefficient: its correction is the largest possible.
        let largest_correction: BigInt = &t * ((&dropped - 1) / 2);
        let c1: Vec<BigInt> = vec![rem(&largest_correction, &modulus); degree];
        let c1_s = poly_mul(&c1, &small(&aligned), &modulus);
        // c0 = t*(q-1)/2 modulo q, and c0 + c1*s as negative as the declared bound allows.
        let declared: BigInt = oracle.capacity(level) / 1000;
        let target: BigInt = -declared.clone();
        let mut c0_zero = rem(&(&target - &c1_s[0]), &modulus);
        // Move up to the residue t*(q-1)/2 modulo q; that lowers the magnitude by less than q.
        let shift = rem(&(&largest_correction - &c0_zero), &dropped);
        c0_zero = rem(&(&c0_zero + &shift), &modulus);
        let mut c0 = vec![rem(&largest_correction, &modulus); degree];
        c0[0] = c0_zero;
        let primes = &oracle.main[..=level];
        let mut canonical = words(&c0, primes);
        canonical.extend(words(&c1, primes));
        let before = OracleCiphertext {
            level,
            components: vec![c0, c1],
            bound: declared.clone(),
        };
        // The other coefficients are far inside the bound; coefficient zero is within q of it.
        let noise_before = oracle.exact_noise(&aligned, &before);
        assert!(noise_before <= declared);
        assert!(&declared - &noise_before < dropped);
        let ciphertext = Ciphertext::from_canonical_words(
            &profile,
            level,
            2,
            &canonical,
            &NoiseBound::new(bigint_to_natural(&declared)),
        )
        .expect("ciphertext");
        let switched = profile.switch_down(&ciphertext).expect("switched");
        let bound = natural_to_bigint(switched.noise_bound().as_natural());
        assert_eq!(bound, oracle.switch_down_noise(&declared, level));
        let noise = exact_noise(&oracle, &secret, &switched);
        assert!(noise <= bound);
        assert!(
            &bound - &noise <= BigInt::from(1),
            "bound {bound} noise {noise}"
        );
        // The plaintext is unchanged by the switch.
        let plain_before = oracle.decrypt(&aligned, &before);
        assert_eq!(
            secret
                .decrypt(&profile, &switched)
                .expect("plaintext")
                .coefficients(),
            plain_before
        );
    }
}

/// One tracked ciphertext: the production value, the oracle's bound and the expected plaintext.
struct Tracked {
    ciphertext: Ciphertext,
    bound: BigInt,
    plain: Vec<BigInt>,
}

struct Sequence<'a> {
    profile: &'a BgvProfile,
    oracle: Oracle,
    secret: SecretKey,
    keys: EvaluationKeys,
    elements: Vec<u32>,
    generator: Generator,
    admitted: usize,
    refused: usize,
}

impl Sequence<'_> {
    fn t(&self) -> BigInt {
        big(self.oracle.t)
    }

    /// Check an operation result against the oracle's bound, exact noise and plaintext.
    fn settle(
        &mut self,
        label: &str,
        result: Result<Ciphertext, BgvError>,
        level: usize,
        bound: BigInt,
        plain: Vec<BigInt>,
    ) -> Option<Tracked> {
        if bound > self.oracle.capacity(level) {
            assert_eq!(
                result.err(),
                Some(BgvError::NoiseBudgetExceeded { level }),
                "{label}: a bound above the capacity must be refused"
            );
            self.refused += 1;
            return None;
        }
        let ciphertext = result.unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(ciphertext.level(), level, "{label}");
        assert_eq!(
            natural_to_bigint(ciphertext.noise_bound().as_natural()),
            bound,
            "{label}: public bound"
        );
        let noise = exact_noise(&self.oracle, &self.secret, &ciphertext);
        assert!(
            noise <= bound,
            "{label}: exact noise {noise} above the bound {bound}"
        );
        let opened = self
            .secret
            .decrypt(self.profile, &ciphertext)
            .expect("plaintext");
        let expected: Vec<u64> = plain
            .iter()
            .map(|value| word_mod(value, self.oracle.t))
            .collect();
        assert_eq!(opened.coefficients(), expected, "{label}: plaintext");
        self.admitted += 1;
        Some(Tracked {
            ciphertext,
            bound,
            plain,
        })
    }

    fn random_plaintext(&mut self) -> (Plaintext, Vec<BigInt>, PlaintextBound) {
        let degree = self.profile.degree();
        let t = self.oracle.t;
        match self.generator.below(3) {
            // Any polynomial, with the worst-case bound.
            0 => {
                let values: Vec<u64> = (0..degree).map(|_| self.generator.next() % t).collect();
                let plaintext = Plaintext::new(self.profile, values.clone()).expect("plaintext");
                let bound = plaintext.bound();
                (
                    plaintext,
                    values.iter().map(|&value| big(value)).collect(),
                    bound,
                )
            }
            // A constant, with the bound of every constant.
            1 => {
                let value = self.generator.next() % t;
                let plaintext = Plaintext::constant(self.profile, value).expect("plaintext");
                let mut values = vec![BigInt::from(0); degree];
                values[0] = big(value);
                let bound = plaintext.bound();
                (plaintext, values, bound)
            }
            // A sparse polynomial with a tight declared public bound.
            _ => {
                let mut values = vec![0_u64; degree];
                values[self.generator.below(degree)] = 2;
                let position = self.generator.below(degree);
                values[position] = t - 3;
                let l1 = values
                    .iter()
                    .map(|&value| {
                        if value > (t - 1) / 2 {
                            t - value
                        } else {
                            value
                        }
                    })
                    .sum();
                let bound = PlaintextBound { linf: 3, l1 };
                let plaintext = Plaintext::with_public_bound(self.profile, values.clone(), bound)
                    .expect("plaintext");
                (
                    plaintext,
                    values.iter().map(|&value| big(value)).collect(),
                    bound,
                )
            }
        }
    }

    /// Bring two pool entries to a common level through production switches, checking each.
    fn align(&mut self, pool: &mut [Tracked], first: usize, second: usize) -> bool {
        loop {
            let (high, low) = match pool[first]
                .ciphertext
                .level()
                .cmp(&pool[second].ciphertext.level())
            {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Greater => (first, second),
                std::cmp::Ordering::Less => (second, first),
            };
            let _ = low;
            if !self.switch(pool, high) {
                return false;
            }
        }
    }

    fn switch(&mut self, pool: &mut [Tracked], index: usize) -> bool {
        let level = pool[index].ciphertext.level();
        if level == 0 {
            assert_eq!(
                self.profile.switch_down(&pool[index].ciphertext).err(),
                Some(BgvError::NoLevelLeft)
            );
            return false;
        }
        let bound = self.oracle.switch_down_noise(&pool[index].bound, level);
        let result = self.profile.switch_down(&pool[index].ciphertext);
        let plain = pool[index].plain.clone();
        let settled = self.settle("switch down", result, level - 1, bound, plain);
        let admitted = settled.is_some();
        if let Some(tracked) = settled {
            pool[index] = tracked;
        }
        admitted
    }

    fn step(&mut self, pool: &mut Vec<Tracked>) {
        let t = self.t();
        let degree = self.profile.degree();
        let first = self.generator.below(pool.len());
        let second = self.generator.below(pool.len());
        let target = self.generator.below(pool.len());
        let produced = match self.generator.below(9) {
            0 | 1 => {
                if !self.align(pool, first, second) {
                    return;
                }
                let subtract = self.generator.below(2) == 1;
                let (lhs, rhs) = (&pool[first], &pool[second]);
                let result = if subtract {
                    self.profile.sub(&lhs.ciphertext, &rhs.ciphertext)
                } else {
                    self.profile.add(&lhs.ciphertext, &rhs.ciphertext)
                };
                let plain = if subtract {
                    poly_sub(&lhs.plain, &rhs.plain, &t)
                } else {
                    poly_add(&lhs.plain, &rhs.plain, &t)
                };
                let bound = &lhs.bound + &rhs.bound;
                let level = lhs.ciphertext.level();
                self.settle("add or sub", result, level, bound, plain)
            }
            2 => {
                let source = &pool[first];
                let result = self.profile.negate(&source.ciphertext);
                let plain = source
                    .plain
                    .iter()
                    .map(|value| rem(&-value.clone(), &t))
                    .collect();
                let (level, bound) = (source.ciphertext.level(), source.bound.clone());
                self.settle("negate", result, level, bound, plain)
            }
            3 => {
                let (plaintext, values, declared) = self.random_plaintext();
                let subtract = self.generator.below(2) == 1;
                let source = &pool[first];
                let result = if subtract {
                    self.profile.sub_plain(&source.ciphertext, &plaintext)
                } else {
                    self.profile.add_plain(&source.ciphertext, &plaintext)
                };
                let plain = if subtract {
                    poly_sub(&source.plain, &values, &t)
                } else {
                    poly_add(&source.plain, &values, &t)
                };
                let bound = &source.bound + declared.linf;
                let level = source.ciphertext.level();
                self.settle("plain add or sub", result, level, bound, plain)
            }
            4 => {
                let (plaintext, values, declared) = self.random_plaintext();
                let source = &pool[first];
                let result = self.profile.mul_plain(&source.ciphertext, &plaintext);
                let plain = poly_mul(&source.plain, &values, &t);
                let bound = &source.bound * declared.l1;
                let level = source.ciphertext.level();
                self.settle("plain product", result, level, bound, plain)
            }
            5 | 6 => {
                if !self.align(pool, first, second) {
                    return;
                }
                let (lhs, rhs) = (&pool[first], &pool[second]);
                let level = lhs.ciphertext.level();
                let tensor_bound = &lhs.bound * &rhs.bound * big(degree as u64);
                let plain = poly_mul(&lhs.plain, &rhs.plain, &t);
                let result = self.profile.multiply(
                    &lhs.ciphertext,
                    &rhs.ciphertext,
                    self.keys.relinearization(),
                );
                // The tensor is refused first when its own bound exceeds the capacity.
                let bound = if tensor_bound > self.oracle.capacity(level) {
                    tensor_bound
                } else {
                    tensor_bound + self.oracle.key_switch_noise(level)
                };
                self.settle("product", result, level, bound, plain)
            }
            7 => {
                let element = self.elements[self.generator.below(self.elements.len())];
                let source = &pool[first];
                let level = source.ciphertext.level();
                let result = self
                    .profile
                    .apply_galois(&source.ciphertext, self.keys.galois(element).expect("key"));
                let plain = poly_automorphism(&source.plain, element as usize)
                    .iter()
                    .map(|value| rem(value, &t))
                    .collect();
                let bound = &source.bound + self.oracle.key_switch_noise(level);
                self.settle("automorphism", result, level, bound, plain)
            }
            _ => {
                self.switch(pool, first);
                return;
            }
        };
        if let Some(tracked) = produced {
            if pool.len() < 6 {
                pool.push(tracked);
            } else {
                pool[target] = tracked;
            }
        }
    }
}

fn run_random_sequences(
    shape: (u32, u64, (u32, usize), (u32, usize), usize),
    seeds: u8,
    steps: usize,
) {
    let profile = profile(shape);
    let oracle = oracle_of(&profile);
    let order = 2_u32 << shape.0;
    let elements = vec![3_u32, 5, order - 1];
    let mut admitted = 0;
    let mut refused = 0;
    for seed_tag in 0..seeds {
        let mut entropy = FixtureEntropy::new(master(seed_tag + 10));
        let key_set = fixtures::key_set(&profile, &elements, &mut entropy).expect("keys");
        let mut sequence = Sequence {
            profile: &profile,
            oracle: oracle.clone(),
            secret: key_set.secret,
            keys: key_set.evaluation,
            elements: elements.clone(),
            generator: Generator(0xFACE_0000 + u64::from(seed_tag)),
            admitted: 0,
            refused: 0,
        };
        let mut pool = Vec::new();
        for _ in 0..3 {
            let values: Vec<u64> = (0..profile.degree())
                .map(|_| sequence.generator.next() % oracle.t)
                .collect();
            let plaintext = Plaintext::new(&profile, values.clone()).expect("plaintext");
            let result = fixtures::encrypt(&profile, &key_set.public, &plaintext, &mut entropy);
            let tracked = sequence
                .settle(
                    "fresh",
                    result,
                    profile.top_level(),
                    oracle.fresh_noise(),
                    values.iter().map(|&value| big(value)).collect(),
                )
                .expect("fresh ciphertext");
            pool.push(tracked);
        }
        for _ in 0..steps {
            sequence.step(&mut pool);
        }
        // Every surviving ciphertext still satisfies the invariant at the end.
        for tracked in &pool {
            let noise = exact_noise(&oracle, &sequence.secret, &tracked.ciphertext);
            assert!(noise <= tracked.bound);
            assert!(tracked.bound <= oracle.capacity(tracked.ciphertext.level()));
        }
        admitted += sequence.admitted;
        refused += sequence.refused;
    }
    // The sequences reach both outcomes: many admitted operations and some refusals.
    assert!(admitted > 20 * usize::from(seeds), "admitted {admitted}");
    assert!(refused > 0, "no sequence reached the capacity");
}

#[test]
fn random_admitted_sequences_never_exceed_the_public_bound_on_a_toy_chain() {
    run_random_sequences((4, 257, (30, 6), (31, 2), 2), 6, 70);
}

#[test]
fn random_admitted_sequences_never_exceed_the_public_bound_on_wide_primes() {
    run_random_sequences((3, 257, (50, 5), (60, 2), 2), 4, 60);
    run_random_sequences((3, 257, (55, 4), (60, 3), 3), 3, 50);
}

#[test]
fn random_admitted_sequences_never_exceed_the_public_bound_for_a_batching_modulus() {
    run_random_sequences((4, 97, (40, 5), (41, 2), 1), 4, 60);
    run_random_sequences((5, 65_537, (55, 4), (60, 2), 2), 2, 40);
}

#[test]
fn centered_helper_matches_its_definition() {
    // The helpers used above are the oracle's; pin the convention they rely on.
    assert_eq!(centered(&big(128), &big(257)), big(128));
    assert_eq!(centered(&big(129), &big(257)), BigInt::from(-128));
    assert_eq!(bigint_to_natural(&big(7)), Natural::from_u64(7));
}
