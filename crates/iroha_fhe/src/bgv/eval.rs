//! Homomorphic operations.
//!
//! Every operation is a method of [`BgvProfile`], takes its operands by
//! reference and returns a new ciphertext. The level, the component count and
//! the public noise bound of the result are those the matching `plan_*`
//! method of [`super::plan`] gives for the shapes of the operands, so an
//! operation whose bound would exceed the capacity of its level returns
//! [`BgvError::NoiseBudgetExceeded`] and produces nothing. Binary operations
//! require both operands at the same level; [`BgvProfile::switch_to_level`]
//! aligns them. No operation reads a secret.
use super::{
    BgvError, BgvProfile, Ciphertext, Plaintext, SwitchingKey, SwitchingKeyKind,
    keys::galois_power, poly::RnsPoly,
};
use crate::{
    ntt_plan::NegacyclicPlan,
    rns_chain::{CongruentScaleDown, RnsBasis},
};

impl BgvProfile {
    fn combine(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        subtract: bool,
    ) -> Result<Ciphertext, BgvError> {
        lhs.check_profile(self)?;
        rhs.check_profile(self)?;
        let shape = self.plan_add(&lhs.shape(), &rhs.shape())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let mut components = lhs.components().to_vec();
        for (component, other) in components.iter_mut().zip(rhs.components()) {
            if subtract {
                component.sub_assign(other, plan_of)?;
            } else {
                component.add_assign(other, plan_of)?;
            }
        }
        Ok(Ciphertext::from_shape(self, shape, components))
    }

    /// `lhs + rhs`. Bound: `V_lhs + V_rhs`.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::LevelMismatch`],
    /// [`BgvError::ComponentCount`] when the component counts differ, or
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.combine(lhs, rhs, false)
    }

    /// `lhs - rhs`. Bound: `V_lhs + V_rhs`.
    ///
    /// # Errors
    /// As [`Self::add`].
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.combine(lhs, rhs, true)
    }

    /// `-ciphertext`. The bound is unchanged.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn negate(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        let mut components = ciphertext.components().to_vec();
        for component in &mut components {
            component.negate(|limb| self.main_plan(limb));
        }
        Ok(Ciphertext::from_shape(self, ciphertext.shape(), components))
    }

    fn combine_plain(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
        subtract: bool,
    ) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        plaintext.check_profile(self)?;
        let shape = self.plan_add_plain(&ciphertext.shape(), plaintext.bound())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let message = plaintext.centered_residues(self, ciphertext.level() + 1);
        let mut components = ciphertext.components().to_vec();
        if subtract {
            components[0].sub_assign(&message, plan_of)?;
        } else {
            components[0].add_assign(&message, plan_of)?;
        }
        Ok(Ciphertext::from_shape(self, shape, components))
    }

    /// `ciphertext + plaintext`. Bound: `V + linf` of the declared plaintext bound.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn add_plain(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext, BgvError> {
        self.combine_plain(ciphertext, plaintext, false)
    }

    /// `ciphertext - plaintext`. Bound: `V + linf` of the declared plaintext bound.
    ///
    /// # Errors
    /// As [`Self::add_plain`].
    pub fn sub_plain(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext, BgvError> {
        self.combine_plain(ciphertext, plaintext, true)
    }

    /// `ciphertext * plaintext`. Bound: `V * l1` of the declared plaintext bound.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn mul_plain(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        plaintext.check_profile(self)?;
        let level = ciphertext.level();
        let shape = self.plan_mul_plain(&ciphertext.shape(), plaintext.bound())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let mut multiplier = plaintext.centered_residues(self, level + 1);
        multiplier.forward(plan_of)?;
        let mut components = ciphertext.components().to_vec();
        for component in &mut components {
            component.forward(plan_of)?;
            component.pointwise_mul_assign(&multiplier, plan_of)?;
            component.inverse(plan_of)?;
        }
        Ok(Ciphertext::from_shape(self, shape, components))
    }

    /// The tensor product `(a0*b0, a0*b1 + a1*b0, a1*b1)` of two two-component ciphertexts.
    ///
    /// The result has three components and decrypts under `(1, s, s^2)`.
    /// Bound: `N * V_lhs * V_rhs`.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::LevelMismatch`],
    /// [`BgvError::ComponentCount`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn tensor(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, BgvError> {
        lhs.check_profile(self)?;
        rhs.check_profile(self)?;
        let shape = self.plan_tensor(&lhs.shape(), &rhs.shape())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let evaluation = |component: &RnsPoly| -> Result<RnsPoly, BgvError> {
            let mut evaluation = component.clone();
            evaluation.forward(plan_of)?;
            Ok(evaluation)
        };
        let a0 = evaluation(&lhs.components()[0])?;
        let a1 = evaluation(&lhs.components()[1])?;
        let b0 = evaluation(&rhs.components()[0])?;
        let b1 = evaluation(&rhs.components()[1])?;
        let mut d0 = a0.clone();
        d0.pointwise_mul_assign(&b0, plan_of)?;
        let mut d1 = a0;
        d1.pointwise_mul_assign(&b1, plan_of)?;
        let mut cross = a1.clone();
        cross.pointwise_mul_assign(&b0, plan_of)?;
        d1.add_assign(&cross, plan_of)?;
        let mut d2 = a1;
        d2.pointwise_mul_assign(&b1, plan_of)?;
        let mut components = vec![d0, d1, d2];
        for component in &mut components {
            component.inverse(plan_of)?;
        }
        Ok(Ciphertext::from_shape(self, shape, components))
    }

    /// Hybrid key switch of one coefficient-form polynomial at `level`.
    ///
    /// Returns `(k0, k1)` over `q_0, ..., q_level` with
    /// `k0 + k1*s = component * s' + t*E`, `||E||_inf` within the key-switch
    /// bound of the level.
    fn key_switch(
        &self,
        level: usize,
        component: &RnsPoly,
        key: &SwitchingKey,
    ) -> Result<(RnsPoly, RnsPoly), BgvError> {
        key.check_profile(self)?;
        let context = self.level(level)?;
        let degree = self.degree();
        let main_limbs = self.top_level() + 1;
        let extended_limbs = level + 1 + self.special_count();
        let plan_of = |limb: usize| self.extended_plan(level, limb);
        let mut accumulator0 = RnsPoly::zero(extended_limbs, degree);
        let mut accumulator1 = RnsPoly::zero(extended_limbs, degree);
        for (digit_index, digit) in context.digits.iter().enumerate() {
            let (key_b, key_a) = key.digit(digit_index).ok_or(BgvError::WrongSwitchingKey)?;
            let mut extended = RnsPoly::zero(extended_limbs, degree);
            let own = digit.first..digit.first + digit.len;
            for limb in own.clone() {
                extended
                    .limb_mut(limb)
                    .copy_from_slice(component.limb(limb));
            }
            let mut converted = RnsPoly::zero(digit.targets.len(), degree);
            let digit_basis: &RnsBasis = &digit.basis;
            digit_basis.convert_centered(
                &component.words()[own.start * degree..own.end * degree],
                degree,
                &digit.targets,
                converted.words_mut(),
            )?;
            for (index, &limb) in digit.target_limbs.iter().enumerate() {
                extended
                    .limb_mut(limb)
                    .copy_from_slice(converted.limb(index));
            }
            extended.forward(plan_of)?;
            for limb in 0..extended_limbs {
                let key_limb = if limb <= level {
                    limb
                } else {
                    main_limbs + (limb - level - 1)
                };
                let plan: &NegacyclicPlan = plan_of(limb);
                plan.pointwise_mul_add_assign(
                    accumulator0.limb_mut(limb),
                    extended.limb(limb),
                    key_b.limb(key_limb),
                )?;
                plan.pointwise_mul_add_assign(
                    accumulator1.limb_mut(limb),
                    extended.limb(limb),
                    key_a.limb(key_limb),
                )?;
            }
        }
        let drop_special: &CongruentScaleDown = &context.drop_special;
        let mut outputs = Vec::with_capacity(2);
        for mut accumulator in [accumulator0, accumulator1] {
            accumulator.inverse(plan_of)?;
            let (kept, dropped) = accumulator.words_mut().split_at_mut((level + 1) * degree);
            drop_special.apply(kept, dropped, degree)?;
            outputs.push(accumulator.prefix(level + 1));
        }
        let k1 = outputs.pop().ok_or(BgvError::Kernel)?;
        let k0 = outputs.pop().ok_or(BgvError::Kernel)?;
        Ok((k0, k1))
    }

    /// Relinearize a three-component product to two components. Bound: `V + E_ks(level)`.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::ComponentCount`],
    /// [`BgvError::WrongSwitchingKey`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn relinearize(
        &self,
        ciphertext: &Ciphertext,
        key: &SwitchingKey,
    ) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        key.check_profile(self)?;
        if ciphertext.component_count() != 3 {
            return Err(BgvError::ComponentCount {
                found: ciphertext.component_count(),
            });
        }
        if key.kind() != SwitchingKeyKind::Relinearization {
            return Err(BgvError::WrongSwitchingKey);
        }
        let level = ciphertext.level();
        let shape = self.plan_relinearize(&ciphertext.shape())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let components = ciphertext.components();
        let (mut c0, mut c1) = self.key_switch(level, &components[2], key)?;
        c0.add_assign(&components[0], plan_of)?;
        c1.add_assign(&components[1], plan_of)?;
        Ok(Ciphertext::from_shape(self, shape, vec![c0, c1]))
    }

    /// `lhs * rhs`, relinearized. Bound: `N * V_lhs * V_rhs + E_ks(level)`.
    ///
    /// # Errors
    /// The errors of [`Self::tensor`] and [`Self::relinearize`].
    pub fn multiply(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        key: &SwitchingKey,
    ) -> Result<Ciphertext, BgvError> {
        self.relinearize(&self.tensor(lhs, rhs)?, key)
    }

    /// Apply `X -> X^k` for the Galois element of `key`. Bound: `V + E_ks(level)`.
    ///
    /// The result encrypts the image of the plaintext polynomial under the
    /// same automorphism.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::ComponentCount`],
    /// [`BgvError::WrongSwitchingKey`] for a relinearization key,
    /// [`BgvError::InvalidGaloisElement`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn apply_galois(
        &self,
        ciphertext: &Ciphertext,
        key: &SwitchingKey,
    ) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        key.check_profile(self)?;
        if ciphertext.component_count() != 2 {
            return Err(BgvError::ComponentCount {
                found: ciphertext.component_count(),
            });
        }
        let SwitchingKeyKind::Galois(element) = key.kind() else {
            return Err(BgvError::WrongSwitchingKey);
        };
        let power = galois_power(self, element)?;
        let level = ciphertext.level();
        let shape = self.plan_galois(&ciphertext.shape())?;
        let plan_of = |limb: usize| self.main_plan(limb);
        let components = ciphertext.components();
        let rotated1 = components[1].automorphism(power, plan_of)?;
        let (mut c0, c1) = self.key_switch(level, &rotated1, key)?;
        c0.add_assign(&components[0].automorphism(power, plan_of)?, plan_of)?;
        Ok(Ciphertext::from_shape(self, shape, vec![c0, c1]))
    }

    /// Drop the last prime of the level with the congruence-preserving rule.
    ///
    /// Bound: `floor((V + t*(q_l-1)/2*(1+N)) / q_l)`. The plaintext is unchanged.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::ComponentCount`],
    /// [`BgvError::NoLevelLeft`] at level zero or
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn switch_down(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        let shape = self.plan_switch_down(&ciphertext.shape())?;
        let level = ciphertext.level();
        let context = self.level(level)?;
        let drop_last: &CongruentScaleDown =
            context.drop_last.as_ref().ok_or(BgvError::NoLevelLeft)?;
        let degree = self.degree();
        let mut components = Vec::with_capacity(2);
        for component in ciphertext.components() {
            let mut kept = component.prefix(level);
            drop_last.apply(kept.words_mut(), component.limb(level), degree)?;
            components.push(kept);
        }
        Ok(Ciphertext::from_shape(self, shape, components))
    }

    /// Switch down until the ciphertext is at `level`; a ciphertext already there is copied.
    ///
    /// # Errors
    /// [`BgvError::LevelMismatch`] when `level` is above the current level,
    /// and the errors of [`Self::switch_down`].
    pub fn switch_to_level(
        &self,
        ciphertext: &Ciphertext,
        level: usize,
    ) -> Result<Ciphertext, BgvError> {
        ciphertext.check_profile(self)?;
        if level > ciphertext.level() {
            return Err(BgvError::LevelMismatch {
                lhs: ciphertext.level(),
                rhs: level,
            });
        }
        let mut current = ciphertext.clone();
        while current.level() > level {
            current = self.switch_down(&current)?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::{
            BgvParameters, EvaluationKeys, NoiseBound, PublicKey, SecretKey,
            coins::tests::{ScriptedEntropy, seed},
            noise,
        },
        natural::Natural,
    };

    struct Fixture {
        profile: BgvProfile,
        secret: SecretKey,
        public: PublicKey,
        keys: EvaluationKeys,
    }

    fn entropy(first: u8, count: u8) -> ScriptedEntropy {
        ScriptedEntropy {
            results: (0..count).map(|index| Some(seed(first + index))).collect(),
            calls: 0,
        }
    }

    /// Five 30-bit primes: enough room for one multiplication and switches.
    fn fixture() -> Fixture {
        let profile = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 5), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        let secret = SecretKey::generate_with(&profile, &mut entropy(1, 1)).expect("secret");
        let public =
            PublicKey::generate_with(&profile, &secret, &mut entropy(2, 1)).expect("public");
        let keys =
            EvaluationKeys::generate_with(&profile, &secret, &[3, 5, 31], &mut entropy(3, 4))
                .expect("keys");
        Fixture {
            profile,
            secret,
            public,
            keys,
        }
    }

    fn message(seed: u64) -> Vec<u64> {
        (0..16_u64)
            .map(|index| (index * 53 + seed * 97 + 3) % 257)
            .collect()
    }

    impl Fixture {
        fn encrypt(&self, values: &[u64], tag: u8) -> Ciphertext {
            let plaintext = Plaintext::new(&self.profile, values.to_vec()).expect("plaintext");
            self.public
                .encrypt_with(&self.profile, &plaintext, &mut entropy(tag, 1))
                .expect("ciphertext")
        }

        fn decrypt(&self, ciphertext: &Ciphertext) -> Vec<u64> {
            self.secret
                .decrypt(&self.profile, ciphertext)
                .expect("plaintext")
                .coefficients()
                .to_vec()
        }
    }

    /// Negacyclic product of two plaintext polynomials modulo 257.
    fn plain_product(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
        crate::polynomial::negacyclic_mul_mod_schoolbook(lhs, rhs, 16, 257)
    }

    fn plain_automorphism(values: &[u64], power: usize) -> Vec<u64> {
        let mut output = vec![0_u64; 16];
        crate::automorphism::apply_into(values, power, 257, &mut output).expect("automorphism");
        output
    }

    #[test]
    fn linear_operations_decrypt_to_the_plaintext_results() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let (a, b) = (message(1), message(2));
        let (ca, cb) = (fixture.encrypt(&a, 10), fixture.encrypt(&b, 11));
        let fresh = profile.fresh_noise().clone();
        let sum = profile.add(&ca, &cb).expect("sum");
        assert_eq!(
            fixture.decrypt(&sum),
            crate::polynomial::add_mod(&a, &b, 257)
        );
        assert_eq!(sum.noise_bound().as_natural(), &fresh.add(&fresh));
        let difference = profile.sub(&ca, &cb).expect("difference");
        assert_eq!(
            fixture.decrypt(&difference),
            crate::polynomial::sub_mod(&a, &b, 257)
        );
        assert_eq!(difference.noise_bound().as_natural(), &fresh.add(&fresh));
        let negated = profile.negate(&ca).expect("negated");
        assert_eq!(
            fixture.decrypt(&negated),
            crate::polynomial::neg_mod(&a, 257)
        );
        assert_eq!(negated.noise_bound().as_natural(), &fresh);
        let plaintext = Plaintext::new(profile, b.clone()).expect("plaintext");
        let plain_sum = profile.add_plain(&ca, &plaintext).expect("plain sum");
        assert_eq!(
            fixture.decrypt(&plain_sum),
            crate::polynomial::add_mod(&a, &b, 257)
        );
        assert_eq!(plain_sum.noise_bound().as_natural(), &fresh.add_u64(128));
        let plain_difference = profile
            .sub_plain(&ca, &plaintext)
            .expect("plain difference");
        assert_eq!(
            fixture.decrypt(&plain_difference),
            crate::polynomial::sub_mod(&a, &b, 257)
        );
        let plain_product = profile.mul_plain(&ca, &plaintext).expect("plain product");
        assert_eq!(
            fixture.decrypt(&plain_product),
            super::tests::plain_product(&a, &b)
        );
        assert_eq!(
            plain_product.noise_bound().as_natural(),
            &fresh.mul_u64(128 * 16)
        );
        // A constant multiplies by its value with the bound of every constant.
        let constant = Plaintext::constant(profile, 256).expect("constant");
        let scaled = profile.mul_plain(&ca, &constant).expect("scaled");
        assert_eq!(
            fixture.decrypt(&scaled),
            crate::polynomial::neg_mod(&a, 257)
        );
        assert_eq!(scaled.noise_bound().as_natural(), &fresh.mul_u64(128));
    }

    #[test]
    fn multiplication_relinearizes_to_the_plaintext_product() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let (a, b) = (message(3), message(4));
        let (ca, cb) = (fixture.encrypt(&a, 12), fixture.encrypt(&b, 13));
        let expected = plain_product(&a, &b);
        let tensor = profile.tensor(&ca, &cb).expect("tensor");
        assert_eq!(tensor.component_count(), 3);
        assert_eq!(fixture.decrypt(&tensor), expected);
        let fresh = profile.fresh_noise();
        assert_eq!(
            tensor.noise_bound().as_natural(),
            &fresh.mul(fresh).mul_u64(16)
        );
        let key = fixture.keys.relinearization();
        let product = profile.relinearize(&tensor, key).expect("relinearized");
        assert_eq!(product.component_count(), 2);
        assert_eq!(fixture.decrypt(&product), expected);
        assert_eq!(
            product.noise_bound().as_natural(),
            &tensor
                .noise_bound()
                .as_natural()
                .add(profile.key_switch_noise(4).expect("noise"))
        );
        assert_eq!(profile.multiply(&ca, &cb, key).expect("product"), product);
        // Squaring and a product at a lower level also decrypt correctly.
        let low_a = profile.switch_to_level(&ca, 3).expect("low");
        let low_b = profile.switch_to_level(&cb, 3).expect("low");
        let low = profile.multiply(&low_a, &low_b, key).expect("low product");
        assert_eq!(low.level(), 3);
        assert_eq!(fixture.decrypt(&low), expected);
        let square = profile.multiply(&ca, &ca, key).expect("square");
        assert_eq!(fixture.decrypt(&square), plain_product(&a, &a));
    }

    #[test]
    fn modulus_switching_preserves_the_plaintext_and_shrinks_the_bound() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let a = message(5);
        let ciphertext = fixture.encrypt(&a, 14);
        let mut current = ciphertext.clone();
        for level in (0..4).rev() {
            let next = profile.switch_down(&current).expect("switched");
            assert_eq!(next.level(), level);
            assert_eq!(fixture.decrypt(&next), a);
            assert_eq!(
                next.noise_bound().as_natural(),
                &noise::switch_down_noise(
                    current.noise_bound().as_natural(),
                    16,
                    257,
                    profile.main_plan(level + 1).prime()
                )
            );
            current = next;
        }
        // At the floor the bound is t * (1 + N) / 2 rounded down.
        assert_eq!(
            current.noise_bound().as_natural(),
            &Natural::from_u64(257 * 17 / 2)
        );
        assert_eq!(
            profile.switch_down(&current).err(),
            Some(BgvError::NoLevelLeft)
        );
        assert_eq!(
            profile.switch_to_level(&ciphertext, 0).expect("level 0"),
            current
        );
        assert_eq!(
            profile.switch_to_level(&ciphertext, 4).expect("same level"),
            ciphertext
        );
        assert_eq!(
            profile.switch_to_level(&current, 1).err(),
            Some(BgvError::LevelMismatch { lhs: 0, rhs: 1 })
        );
        // A product switched down still decrypts, at every remaining level.
        let b = message(6);
        let product = profile
            .multiply(
                &ciphertext,
                &fixture.encrypt(&b, 15),
                fixture.keys.relinearization(),
            )
            .expect("product");
        for level in 1..4 {
            let lowered = profile.switch_to_level(&product, level).expect("lowered");
            assert_eq!(
                fixture.decrypt(&lowered),
                plain_product(&a, &b),
                "level {level}"
            );
        }
    }

    #[test]
    fn automorphisms_permute_the_plaintext() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let a = message(7);
        let ciphertext = fixture.encrypt(&a, 16);
        for element in [3_u32, 5, 31] {
            let key = fixture.keys.galois(element).expect("key");
            for level in [4_usize, 2, 0] {
                let lowered = profile
                    .switch_to_level(&ciphertext, level)
                    .expect("lowered");
                let rotated = profile.apply_galois(&lowered, key).expect("rotated");
                assert_eq!(
                    fixture.decrypt(&rotated),
                    plain_automorphism(&a, element as usize),
                    "element {element} level {level}"
                );
                assert_eq!(
                    rotated.noise_bound().as_natural(),
                    &lowered
                        .noise_bound()
                        .as_natural()
                        .add(profile.key_switch_noise(level).expect("noise"))
                );
            }
        }
    }

    #[test]
    fn operations_refuse_mismatched_operands_and_keys() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let ciphertext = fixture.encrypt(&message(8), 17);
        let lowered = profile.switch_down(&ciphertext).expect("lowered");
        let tensor = profile.tensor(&ciphertext, &ciphertext).expect("tensor");
        let relinearization = fixture.keys.relinearization();
        let galois = fixture.keys.galois(5).expect("key");
        let mismatch = Some(BgvError::LevelMismatch { lhs: 4, rhs: 3 });
        assert_eq!(profile.add(&ciphertext, &lowered).err(), mismatch);
        assert_eq!(profile.sub(&ciphertext, &lowered).err(), mismatch);
        assert_eq!(profile.tensor(&ciphertext, &lowered).err(), mismatch);
        let three = Some(BgvError::ComponentCount { found: 3 });
        assert_eq!(profile.add(&ciphertext, &tensor).err(), three);
        assert_eq!(profile.tensor(&tensor, &ciphertext).err(), three);
        assert_eq!(profile.tensor(&ciphertext, &tensor).err(), three);
        assert_eq!(profile.switch_down(&tensor).err(), three);
        assert_eq!(profile.apply_galois(&tensor, galois).err(), three);
        assert_eq!(
            profile.relinearize(&ciphertext, relinearization).err(),
            Some(BgvError::ComponentCount { found: 2 })
        );
        assert_eq!(
            profile.relinearize(&tensor, galois).err(),
            Some(BgvError::WrongSwitchingKey)
        );
        assert_eq!(
            profile.apply_galois(&ciphertext, relinearization).err(),
            Some(BgvError::WrongSwitchingKey)
        );
        // Three-component sums are allowed and decrypt.
        let doubled = profile.add(&tensor, &tensor).expect("sum of tensors");
        assert_eq!(doubled.component_count(), 3);
        // Objects of another profile are refused by every operation.
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 4), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        let foreign_plaintext = Plaintext::new(&other, message(1)).expect("plaintext");
        let foreign = Some(BgvError::ProfileMismatch);
        assert_eq!(other.add(&ciphertext, &ciphertext).err(), foreign);
        assert_eq!(other.negate(&ciphertext).err(), foreign);
        assert_eq!(other.switch_down(&ciphertext).err(), foreign);
        assert_eq!(other.switch_to_level(&ciphertext, 0).err(), foreign);
        assert_eq!(other.tensor(&ciphertext, &ciphertext).err(), foreign);
        assert_eq!(other.relinearize(&tensor, relinearization).err(), foreign);
        assert_eq!(other.apply_galois(&ciphertext, galois).err(), foreign);
        assert_eq!(
            profile.add_plain(&ciphertext, &foreign_plaintext).err(),
            foreign
        );
        assert_eq!(
            profile.sub_plain(&ciphertext, &foreign_plaintext).err(),
            foreign
        );
        assert_eq!(
            profile.mul_plain(&ciphertext, &foreign_plaintext).err(),
            foreign
        );
        // Every operation reports the shape its plan gives for the shapes of its operands.
        let sum = profile.add(&ciphertext, &ciphertext).expect("sum");
        assert_eq!(
            Ok(sum.shape()),
            profile.plan_add(&ciphertext.shape(), &ciphertext.shape())
        );
        assert_eq!(
            Ok(tensor.shape()),
            profile.plan_tensor(&ciphertext.shape(), &ciphertext.shape())
        );
        let product = profile
            .relinearize(&tensor, relinearization)
            .expect("product");
        assert_eq!(
            Ok(product.shape()),
            profile.plan_multiply(&ciphertext.shape(), &ciphertext.shape())
        );
        assert_eq!(
            Ok(profile
                .apply_galois(&ciphertext, galois)
                .expect("image")
                .shape()),
            profile.plan_galois(&ciphertext.shape())
        );
        assert_eq!(
            Ok(profile.switch_down(&product).expect("lower").shape()),
            profile.plan_switch_down(&product.shape())
        );
        assert_eq!(Ok(ciphertext.shape()), profile.plan_fresh());
        assert_eq!(
            profile.negate(&product).expect("negated").shape(),
            product.shape()
        );
        let plaintext = Plaintext::constant(profile, 3).expect("constant");
        assert_eq!(
            Ok(profile
                .mul_plain(&product, &plaintext)
                .expect("scaled")
                .shape()),
            profile.plan_mul_plain(&product.shape(), plaintext.bound())
        );
        assert_eq!(
            Ok(profile
                .sub_plain(&product, &plaintext)
                .expect("shifted")
                .shape()),
            profile.plan_add_plain(&product.shape(), plaintext.bound())
        );
        assert_eq!(
            Ok(Ciphertext::trivial(profile, &plaintext, 2)
                .expect("trivial")
                .shape()),
            profile.plan_trivial(2)
        );
    }

    #[test]
    fn operations_refuse_a_result_above_the_capacity() {
        let fixture = fixture();
        let profile = &fixture.profile;
        let ciphertext = fixture.encrypt(&message(9), 18);
        let words = ciphertext.canonical_words();
        let at = |bound: Natural| {
            Ciphertext::from_canonical_words(profile, 4, 2, &words, &NoiseBound::new(bound))
                .expect("ciphertext")
        };
        let capacity = profile.capacity(4).expect("capacity").clone();
        let exceeded = Some(BgvError::NoiseBudgetExceeded { level: 4 });
        let full = at(capacity.clone());
        let one = at(Natural::one());
        let zero = at(Natural::zero());
        // Addition: capacity + 0 is admitted, capacity + 1 is not.
        assert!(profile.add(&full, &zero).is_ok());
        assert_eq!(profile.add(&full, &one).err(), exceeded);
        assert_eq!(profile.sub(&full, &one).err(), exceeded);
        let plaintext = Plaintext::constant(profile, 1).expect("constant");
        assert_eq!(profile.add_plain(&full, &plaintext).err(), exceeded);
        assert_eq!(profile.sub_plain(&full, &plaintext).err(), exceeded);
        assert_eq!(profile.mul_plain(&full, &plaintext).err(), exceeded);
        // Tensor: N * V * 1 with V the largest admitted value, and one above it.
        let largest = capacity.div_floor_u64(16).expect("quotient");
        assert!(profile.tensor(&at(largest.clone()), &one).is_ok());
        assert_eq!(
            profile.tensor(&at(largest.add_u64(1)), &one).err(),
            exceeded
        );
        // Key switching adds its bound: exactly at the capacity is admitted.
        let key_noise = profile.key_switch_noise(4).expect("noise").clone();
        let room = capacity.checked_sub(&key_noise).expect("room");
        let galois = fixture.keys.galois(5).expect("key");
        assert!(profile.apply_galois(&at(room.clone()), galois).is_ok());
        assert_eq!(
            profile.apply_galois(&at(room.add_u64(1)), galois).err(),
            exceeded
        );
        let tensor = profile.tensor(&one, &one).expect("tensor");
        let tensor_words = tensor.canonical_words();
        let tensor_at = |bound: Natural| {
            Ciphertext::from_canonical_words(profile, 4, 3, &tensor_words, &NoiseBound::new(bound))
                .expect("ciphertext")
        };
        let relinearization = fixture.keys.relinearization();
        assert!(
            profile
                .relinearize(&tensor_at(room.clone()), relinearization)
                .is_ok()
        );
        assert_eq!(
            profile
                .relinearize(&tensor_at(room.add_u64(1)), relinearization)
                .err(),
            exceeded
        );
        // A switch from the full capacity lands t*(1+N)/2 above the lower capacity and is
        // refused at the lower level; with that much room it is admitted.
        assert_eq!(
            profile.switch_down(&full).err(),
            Some(BgvError::NoiseBudgetExceeded { level: 3 })
        );
        let half = at(capacity.half_floor());
        let switched = profile.switch_down(&half).expect("switched");
        assert!(switched.noise_bound().as_natural() <= profile.capacity(3).expect("capacity"));
    }
}
