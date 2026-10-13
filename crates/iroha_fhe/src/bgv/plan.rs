//! Public shapes of ciphertexts and the admission of every operation on them.
//!
//! A [`CiphertextShape`] is what an evaluator may reveal about a ciphertext
//! without a key: its level, its number of components and its public noise
//! bound. The `plan_*` methods of [`BgvProfile`] map the shapes of the
//! operands of an operation to the shape of its result by the transfer rules
//! of [`super::noise`], and refuse a result whose bound exceeds the capacity
//! of its level.
//!
//! The homomorphic operations of the evaluation module call these methods for
//! the level, the component count and the bound of what they return. A plan is
//! therefore not a model of the evaluator: it is the part of the evaluator
//! that decides admission, run without the residues. A sequence of operations
//! is admitted on ciphertexts exactly when it is admitted on their shapes,
//! and both end with the same bound.
//!
//! Planning needs the public profile only. It takes no key, no plaintext value
//! and no coin; a plaintext operand enters through its declared
//! [`PlaintextBound`].
use super::{BgvError, BgvProfile, Ciphertext, PlaintextBound, noise};
use crate::natural::Natural;

/// The public shape of a ciphertext: level, component count and noise bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextShape {
    level: usize,
    components: usize,
    bound: Natural,
}

impl CiphertextShape {
    /// The level: the index of the last main prime of the modulus.
    #[must_use]
    pub const fn level(&self) -> usize {
        self.level
    }

    /// Number of components: two, or three for an unrelinearized product.
    #[must_use]
    pub const fn components(&self) -> usize {
        self.components
    }

    /// The public noise bound.
    #[must_use]
    pub const fn bound(&self) -> &Natural {
        &self.bound
    }

    /// Bit length of the noise bound.
    #[must_use]
    pub fn bound_bits(&self) -> usize {
        self.bound.bit_len()
    }

    pub(super) fn into_bound(self) -> Natural {
        self.bound
    }
}

impl Ciphertext {
    /// The public shape of this ciphertext.
    #[must_use]
    pub fn shape(&self) -> CiphertextShape {
        CiphertextShape {
            level: self.level(),
            components: self.component_count(),
            bound: self.noise_bound().as_natural().clone(),
        }
    }
}

impl BgvProfile {
    /// Admit a shape: the bound must not exceed the capacity of the level.
    fn admit(
        &self,
        level: usize,
        components: usize,
        bound: Natural,
    ) -> Result<CiphertextShape, BgvError> {
        if bound > *self.capacity(level)? {
            return Err(BgvError::NoiseBudgetExceeded { level });
        }
        Ok(CiphertextShape {
            level,
            components,
            bound,
        })
    }

    fn check_two_components(shape: &CiphertextShape) -> Result<(), BgvError> {
        if shape.components == 2 {
            Ok(())
        } else {
            Err(BgvError::ComponentCount {
                found: shape.components,
            })
        }
    }

    fn check_same_level(lhs: &CiphertextShape, rhs: &CiphertextShape) -> Result<(), BgvError> {
        if lhs.level == rhs.level {
            Ok(())
        } else {
            Err(BgvError::LevelMismatch {
                lhs: lhs.level,
                rhs: rhs.level,
            })
        }
    }

    /// The shape a caller claims for a ciphertext it did not compute.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`], [`BgvError::ComponentCount`] for a count
    /// other than two or three, or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_claimed(
        &self,
        level: usize,
        components: usize,
        bound: Natural,
    ) -> Result<CiphertextShape, BgvError> {
        self.level(level)?;
        if !(2..=3).contains(&components) {
            return Err(BgvError::ComponentCount { found: components });
        }
        self.admit(level, components, bound)
    }

    /// Shape of a fresh public-key encryption: the top level and the fresh bound.
    ///
    /// # Errors
    /// [`BgvError::NoiseBudgetExceeded`] when the chain cannot hold a fresh ciphertext.
    pub fn plan_fresh(&self) -> Result<CiphertextShape, BgvError> {
        self.admit(self.top_level(), 2, self.fresh_noise().clone())
    }

    /// Shape of the noiseless embedding of a plaintext at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_trivial(&self, level: usize) -> Result<CiphertextShape, BgvError> {
        self.admit(level, 2, noise::plaintext_noise(self.plaintext_modulus()))
    }

    /// Shape of a sum or a difference. Bound: `V_lhs + V_rhs`.
    ///
    /// # Errors
    /// [`BgvError::LevelMismatch`], [`BgvError::ComponentCount`] when the
    /// component counts differ, or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_add(
        &self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        Self::check_same_level(lhs, rhs)?;
        if lhs.components != rhs.components {
            return Err(BgvError::ComponentCount {
                found: rhs.components,
            });
        }
        self.admit(lhs.level, lhs.components, lhs.bound.add(&rhs.bound))
    }

    /// Shape of a plaintext sum or difference. Bound: `V + linf` of the plaintext bound.
    ///
    /// # Errors
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_add_plain(
        &self,
        shape: &CiphertextShape,
        plaintext: PlaintextBound,
    ) -> Result<CiphertextShape, BgvError> {
        self.admit(
            shape.level,
            shape.components,
            shape.bound.add_u64(plaintext.linf),
        )
    }

    /// Shape of a plaintext product. Bound: `V * l1` of the plaintext bound.
    ///
    /// # Errors
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_mul_plain(
        &self,
        shape: &CiphertextShape,
        plaintext: PlaintextBound,
    ) -> Result<CiphertextShape, BgvError> {
        self.admit(
            shape.level,
            shape.components,
            shape.bound.mul_u64(plaintext.l1),
        )
    }

    /// Shape of the tensor product of two two-component ciphertexts.
    /// Bound: `N * V_lhs * V_rhs`; three components.
    ///
    /// # Errors
    /// [`BgvError::LevelMismatch`], [`BgvError::ComponentCount`] or
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_tensor(
        &self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        Self::check_same_level(lhs, rhs)?;
        Self::check_two_components(lhs)?;
        Self::check_two_components(rhs)?;
        self.admit(
            lhs.level,
            3,
            noise::product_noise(&lhs.bound, &rhs.bound, self.degree()),
        )
    }

    /// Shape after one key switch at the level of `shape`. Bound: `V + E_ks(level)`.
    fn plan_key_switch(&self, shape: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        let bound = shape.bound.add(self.key_switch_noise(shape.level)?);
        self.admit(shape.level, 2, bound)
    }

    /// Shape of a relinearized three-component product. Bound: `V + E_ks(level)`.
    ///
    /// # Errors
    /// [`BgvError::ComponentCount`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_relinearize(&self, shape: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        if shape.components != 3 {
            return Err(BgvError::ComponentCount {
                found: shape.components,
            });
        }
        self.plan_key_switch(shape)
    }

    /// Shape of a relinearized product. Bound: `N * V_lhs * V_rhs + E_ks(level)`.
    ///
    /// # Errors
    /// The errors of [`Self::plan_tensor`] and [`Self::plan_relinearize`].
    pub fn plan_multiply(
        &self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<CiphertextShape, BgvError> {
        self.plan_relinearize(&self.plan_tensor(lhs, rhs)?)
    }

    /// Shape of the image under an automorphism. Bound: `V + E_ks(level)`.
    ///
    /// # Errors
    /// [`BgvError::ComponentCount`] or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_galois(&self, shape: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        Self::check_two_components(shape)?;
        self.plan_key_switch(shape)
    }

    /// Shape after dropping the last prime of the level.
    /// Bound: `floor((V + t*(q_l-1)/2*(1+N)) / q_l)`.
    ///
    /// # Errors
    /// [`BgvError::ComponentCount`], [`BgvError::NoLevelLeft`] at level zero
    /// or [`BgvError::NoiseBudgetExceeded`].
    pub fn plan_switch_down(&self, shape: &CiphertextShape) -> Result<CiphertextShape, BgvError> {
        Self::check_two_components(shape)?;
        self.level(shape.level)?;
        if shape.level == 0 {
            return Err(BgvError::NoLevelLeft);
        }
        let bound = noise::switch_down_noise(
            &shape.bound,
            self.degree(),
            self.plaintext_modulus(),
            self.parameters().main_primes[shape.level],
        );
        self.admit(shape.level - 1, 2, bound)
    }

    /// Shape after switching down to `level`; a shape already there is returned unchanged.
    ///
    /// # Errors
    /// [`BgvError::LevelMismatch`] when `level` is above the current level,
    /// and the errors of [`Self::plan_switch_down`].
    pub fn plan_switch_to_level(
        &self,
        shape: &CiphertextShape,
        level: usize,
    ) -> Result<CiphertextShape, BgvError> {
        if level > shape.level {
            return Err(BgvError::LevelMismatch {
                lhs: shape.level,
                rhs: level,
            });
        }
        let mut current = shape.clone();
        while current.level > level {
            current = self.plan_switch_down(&current)?;
        }
        Ok(current)
    }

    /// Whether multiplying one level lower leaves more room than multiplying here.
    ///
    /// For two operands at one level the relinearized product has the bound
    /// `P = N*V_lhs*V_rhs + E_ks` under the capacity `C` of that level.
    /// Returns the operands switched down by one prime when that strictly
    /// increases `C / P`, compared exactly as `C' * P > C * P'`; otherwise
    /// `None`. It also returns `None` at level zero and when a switch is
    /// refused. Neither product has to be admitted: operands whose product
    /// exceeds the capacity here are lowered as long as the ratio improves,
    /// and the product is admitted, or refused, where the lowering stops.
    ///
    /// A schedule that applies this rule until it returns `None` multiplies at
    /// the level with the largest remaining capacity ratio that single-prime
    /// steps can reach. The decision reads public bounds only.
    ///
    /// # Errors
    /// [`BgvError::LevelMismatch`] or [`BgvError::ComponentCount`] for
    /// operands that cannot be multiplied.
    pub fn plan_lower_multiplication(
        &self,
        lhs: &CiphertextShape,
        rhs: &CiphertextShape,
    ) -> Result<Option<(CiphertextShape, CiphertextShape)>, BgvError> {
        Self::check_same_level(lhs, rhs)?;
        Self::check_two_components(lhs)?;
        Self::check_two_components(rhs)?;
        let level = lhs.level;
        if level == 0 {
            return Ok(None);
        }
        let (Ok(lower_lhs), Ok(lower_rhs)) =
            (self.plan_switch_down(lhs), self.plan_switch_down(rhs))
        else {
            return Ok(None);
        };
        // The unadmitted product bounds; either may exceed the capacity of its level.
        let product = noise::product_noise(&lhs.bound, &rhs.bound, self.degree())
            .add(self.key_switch_noise(level)?);
        let lower_product = noise::product_noise(&lower_lhs.bound, &lower_rhs.bound, self.degree())
            .add(self.key_switch_noise(level - 1)?);
        let gain = self.capacity(level - 1)?.mul(&product);
        let cost = self.capacity(level)?.mul(&lower_product);
        Ok((gain > cost).then_some((lower_lhs, lower_rhs)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::BgvParameters;

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 5), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    fn shape(level: usize, components: usize, bound: u64) -> CiphertextShape {
        CiphertextShape {
            level,
            components,
            bound: Natural::from_u64(bound),
        }
    }

    #[test]
    fn shapes_report_their_parts() {
        let shape = shape(3, 2, 1000);
        assert_eq!(shape.level(), 3);
        assert_eq!(shape.components(), 2);
        assert_eq!(shape.bound(), &Natural::from_u64(1000));
        assert_eq!(shape.bound_bits(), 10);
        assert_eq!(shape.clone().into_bound(), Natural::from_u64(1000));
    }

    #[test]
    fn fresh_trivial_and_claimed_shapes_are_admitted_within_the_capacity() {
        let profile = profile();
        let fresh = profile.plan_fresh().expect("fresh");
        assert_eq!(fresh.level(), 4);
        assert_eq!(fresh.components(), 2);
        assert_eq!(fresh.bound(), profile.fresh_noise());
        let trivial = profile.plan_trivial(2).expect("trivial");
        assert_eq!(trivial, shape(2, 2, 128));
        assert_eq!(
            profile.plan_trivial(5),
            Err(BgvError::LevelOutOfRange { level: 5, top: 4 })
        );
        let capacity = profile.capacity(1).expect("capacity").clone();
        assert!(profile.plan_claimed(1, 3, capacity.clone()).is_ok());
        assert_eq!(
            profile.plan_claimed(1, 2, capacity.add_u64(1)),
            Err(BgvError::NoiseBudgetExceeded { level: 1 })
        );
        for components in [0, 1, 4] {
            assert_eq!(
                profile.plan_claimed(1, components, Natural::zero()),
                Err(BgvError::ComponentCount { found: components })
            );
        }
        assert_eq!(
            profile.plan_claimed(5, 2, Natural::zero()),
            Err(BgvError::LevelOutOfRange { level: 5, top: 4 })
        );
        // One 17-bit prime (74,017) cannot hold a fresh ciphertext, whose bound is 178,229.
        let narrow = BgvProfile::new(
            BgvParameters::derive(4, 257, (17, 1), (18, 1), 1).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(
            narrow.plan_fresh(),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
    }

    #[test]
    fn linear_plans_follow_the_transfer_rules() {
        let profile = profile();
        let lhs = shape(3, 2, 1000);
        let rhs = shape(3, 2, 50);
        assert_eq!(profile.plan_add(&lhs, &rhs), Ok(shape(3, 2, 1050)));
        assert_eq!(
            profile.plan_add(&lhs, &shape(2, 2, 50)),
            Err(BgvError::LevelMismatch { lhs: 3, rhs: 2 })
        );
        assert_eq!(
            profile.plan_add(&lhs, &shape(3, 3, 50)),
            Err(BgvError::ComponentCount { found: 3 })
        );
        let plaintext = PlaintextBound { linf: 7, l1: 90 };
        assert_eq!(
            profile.plan_add_plain(&lhs, plaintext),
            Ok(shape(3, 2, 1007))
        );
        assert_eq!(
            profile.plan_mul_plain(&lhs, plaintext),
            Ok(shape(3, 2, 90_000))
        );
        // Three components pass through the linear plans unchanged.
        assert_eq!(
            profile.plan_mul_plain(&shape(3, 3, 2), plaintext),
            Ok(shape(3, 3, 180))
        );
        // A bound on the capacity is admitted, one above it is not.
        let capacity = profile
            .capacity(0)
            .expect("capacity")
            .to_u64()
            .expect("word");
        let full = shape(0, 2, capacity - 7);
        assert_eq!(
            profile.plan_add_plain(&full, plaintext),
            Ok(shape(0, 2, capacity))
        );
        assert_eq!(
            profile.plan_add_plain(&shape(0, 2, capacity - 6), plaintext),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
        assert_eq!(
            profile.plan_mul_plain(&full, plaintext),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
        assert_eq!(
            profile.plan_add(&full, &shape(0, 2, 8)),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
    }

    #[test]
    fn multiplication_plans_follow_the_transfer_rules() {
        let profile = profile();
        let lhs = shape(4, 2, 1000);
        let rhs = shape(4, 2, 7);
        let tensor = profile.plan_tensor(&lhs, &rhs).expect("tensor");
        assert_eq!(tensor, shape(4, 3, 16 * 7000));
        let key_switch = profile.key_switch_noise(4).expect("bound").clone();
        let relinearized = profile.plan_relinearize(&tensor).expect("relinearized");
        assert_eq!(relinearized.components(), 2);
        assert_eq!(
            relinearized.bound(),
            &Natural::from_u64(112_000).add(&key_switch)
        );
        assert_eq!(profile.plan_multiply(&lhs, &rhs), Ok(relinearized));
        let rotated = profile.plan_galois(&lhs).expect("rotated");
        assert_eq!(rotated.bound(), &Natural::from_u64(1000).add(&key_switch));
        assert_eq!(
            profile.plan_tensor(&lhs, &shape(3, 2, 7)),
            Err(BgvError::LevelMismatch { lhs: 4, rhs: 3 })
        );
        assert_eq!(
            profile.plan_tensor(&tensor, &rhs),
            Err(BgvError::ComponentCount { found: 3 })
        );
        assert_eq!(
            profile.plan_tensor(&lhs, &tensor),
            Err(BgvError::ComponentCount { found: 3 })
        );
        assert_eq!(
            profile.plan_relinearize(&lhs),
            Err(BgvError::ComponentCount { found: 2 })
        );
        assert_eq!(
            profile.plan_galois(&tensor),
            Err(BgvError::ComponentCount { found: 3 })
        );
        // A product above the capacity of one prime.
        let wide = shape(0, 2, 1 << 20);
        assert_eq!(
            profile.plan_tensor(&wide, &wide),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
    }

    #[test]
    fn switch_plans_follow_the_transfer_rule_and_stop_at_level_zero() {
        let profile = profile();
        let prime = profile.parameters().main_primes[3];
        let start = shape(3, 2, 1 << 40);
        let expected = noise::switch_down_noise(&Natural::from_u64(1 << 40), 16, 257, prime);
        let lower = profile.plan_switch_down(&start).expect("lower");
        assert_eq!(lower.level(), 2);
        assert_eq!(lower.bound(), &expected);
        assert_eq!(profile.plan_switch_to_level(&start, 3), Ok(start.clone()));
        let lowest = profile.plan_switch_to_level(&start, 0).expect("lowest");
        assert_eq!(lowest.level(), 0);
        assert_eq!(
            profile.plan_switch_to_level(&start, 4),
            Err(BgvError::LevelMismatch { lhs: 3, rhs: 4 })
        );
        assert_eq!(
            profile.plan_switch_down(&lowest),
            Err(BgvError::NoLevelLeft)
        );
        assert_eq!(
            profile.plan_switch_down(&shape(3, 3, 5)),
            Err(BgvError::ComponentCount { found: 3 })
        );
        assert_eq!(
            profile.plan_switch_down(&shape(5, 2, 5)),
            Err(BgvError::LevelOutOfRange { level: 5, top: 4 })
        );
        // A bound on the capacity of two primes rounds above the capacity of one.
        let full = CiphertextShape {
            level: 1,
            components: 2,
            bound: profile.capacity(1).expect("capacity").clone(),
        };
        assert_eq!(
            profile.plan_switch_down(&full),
            Err(BgvError::NoiseBudgetExceeded { level: 0 })
        );
    }

    #[test]
    fn multiplication_is_lowered_exactly_while_the_capacity_ratio_grows() {
        let profile = profile();
        // A large operand: dropping a prime divides both factors of the product.
        let large = shape(4, 2, 1 << 50);
        let (lower_lhs, lower_rhs) = profile
            .plan_lower_multiplication(&large, &large)
            .expect("plan")
            .expect("lowering helps");
        assert_eq!(lower_lhs, profile.plan_switch_down(&large).expect("lower"));
        assert_eq!(lower_lhs, lower_rhs);
        // An operand at the rounding floor: another switch only costs capacity.
        let floor = profile
            .plan_switch_to_level(&large, 1)
            .expect("at the floor");
        assert_eq!(profile.plan_lower_multiplication(&floor, &floor), Ok(None));
        // The decision is the exact comparison of the two capacity ratios, whether or not
        // either product is admitted.
        let mut lowered = 0;
        for bits in 10..63_u32 {
            let operand = shape(4, 2, 1 << bits);
            let here = noise::product_noise(operand.bound(), operand.bound(), 16)
                .add(profile.key_switch_noise(4).expect("bound"));
            let lower = profile.plan_switch_down(&operand).expect("lower");
            let there = noise::product_noise(lower.bound(), lower.bound(), 16)
                .add(profile.key_switch_noise(3).expect("bound"));
            let helps = profile.capacity(3).expect("capacity").mul(&here)
                > profile.capacity(4).expect("capacity").mul(&there);
            let decision = profile
                .plan_lower_multiplication(&operand, &operand)
                .expect("plan");
            assert_eq!(decision.is_some(), helps, "{bits} bits");
            lowered += usize::from(helps);
        }
        assert!((1..53).contains(&lowered), "both outcomes occur: {lowered}");
        // Operands whose product fits nowhere near their level are still lowered. The primes
        // are just above 2^29: the product of two 2^100 bounds exceeds the capacity here and
        // one level lower, and is admitted three levels lower.
        let huge = CiphertextShape {
            level: 4,
            components: 2,
            bound: Natural::from_u128(1 << 100),
        };
        assert!(profile.plan_multiply(&huge, &huge).is_err());
        let (lower, _) = profile
            .plan_lower_multiplication(&huge, &huge)
            .expect("plan")
            .expect("lowering helps");
        assert!(profile.plan_multiply(&lower, &lower).is_err());
        let lowest = profile.plan_switch_to_level(&huge, 1).expect("lower");
        assert!(profile.plan_multiply(&lowest, &lowest).is_ok());
        // Level zero, a refused switch and operands that cannot be multiplied.
        let lowest = shape(0, 2, 100);
        assert_eq!(
            profile.plan_lower_multiplication(&lowest, &lowest),
            Ok(None)
        );
        let full = CiphertextShape {
            level: 1,
            components: 2,
            bound: profile.capacity(1).expect("capacity").clone(),
        };
        assert_eq!(profile.plan_lower_multiplication(&full, &full), Ok(None));
        assert_eq!(
            profile.plan_lower_multiplication(&large, &lowest),
            Err(BgvError::LevelMismatch { lhs: 4, rhs: 0 })
        );
        assert_eq!(
            profile.plan_lower_multiplication(&shape(4, 3, 5), &large),
            Err(BgvError::ComponentCount { found: 3 })
        );
        assert_eq!(
            profile.plan_lower_multiplication(&large, &shape(4, 3, 5)),
            Err(BgvError::ComponentCount { found: 3 })
        );
    }
}
