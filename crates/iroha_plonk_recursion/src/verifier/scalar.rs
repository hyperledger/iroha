//! Bounded foreign-scalar arithmetic and exact S6/87-bit limb bridges.
//!
//! The bridge checks three bounded integer equalities. It never identifies a
//! foreign scalar by its residue in the circuit field, which would alias the
//! two Pasta moduli. Internal values may be unreduced integers congruent to the
//! scalar; comparisons and transfer to ECC/transcript cells canonicalize them.
//! Zero denominators select one before
//! inversion and return a separately constrained nonzero bit.
//!
//! Delaying normalization does not widen any FF gate's proven envelope. The
//! existing FF add/sub/neg routines track nonnegative limb bounds, reduce before
//! a result would exceed `2^94 - 1`, and subtraction pads by a fixed multiple of
//! the scalar modulus that dominates each subtrahend limb. Multiplication calls
//! `make_admissible`: it reduces until both limbs remain in that envelope and
//! `max(a) max(b) < m 2^261`. Division similarly checks its existing padding and
//! quotient bound. Thus every actual fused block still satisfies the original
//! carry and quotient preconditions; no wider carry bound is assumed here.
//!
//! More explicitly, for each limb with tracked bounds `A_i,B_i`, addition has
//! bound `A_i+B_i`. Subtraction chooses a structural multiple `K=t*m` with
//! limbs `K_i>=B_i`, so `0<=a_i+K_i-b_i<=A_i+K_i`; negation has
//! `0<=K_i-b_i<=K_i`. Each accepted bound is at most `2^94-1`, far below
//! either native modulus, so those glue equations cannot wrap. Selection takes
//! the componentwise maximum of the two bounds. Reduction writes a Proper
//! result before retrying an otherwise inadmissible operation. Serialized reduction separately proves
//! `x=c+q*m` with q17 and one offset17/range18 carry; its 87/87/81 output
//! for Pasta moduli is still Proper, not Canonical. The integer may differ from
//! its canonical scalar by a multiple of `m`; its native-field residue must
//! therefore never be used as the scalar value. Only the canonical integer
//! bridge exports to S6, ECC scalar bits, transcript absorption or public cells.

use crate::codec::ScalarCells;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use iroha_pasta::{PastaCurve, PastaField};
use iroha_plonk::frontend::{Cell, Error, Region};
use iroha_plonk_gadgets::{
    Bit,
    ff::{FfChip, FfValue, ForeignModulus, Nat},
    range::u128::UintChip,
};
use std::collections::BTreeMap;

pub type Scalar<C> = FfValue<<C as PastaCurve>::Base>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Operation {
    Add([Cell; 3], [Cell; 3]),
    Sub([Cell; 3], [Cell; 3]),
    Neg([Cell; 3]),
    Mul([Cell; 3], [Cell; 3]),
    Proper([Cell; 3]),
}

#[cfg(test)]
mod bridge_cache_tests;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Arithmetic<C: PastaCurve> {
    pub ff: FfChip<C::Base>,
    constants: BTreeMap<C::ScalarExt, Scalar<C>>,
    imports: BTreeMap<[Cell; 2], Scalar<C>>,
    canonical: BTreeMap<[Cell; 3], Scalar<C>>,
    exports: BTreeMap<[Cell; 3], ScalarCells<C>>,
    operations: BTreeMap<Operation, Scalar<C>>,
    marker: PhantomData<C>,
}

impl<C: PastaCurve> Arithmetic<C> {
    pub fn new(ff: FfChip<C::Base>) -> Self {
        Self {
            ff,
            constants: BTreeMap::new(),
            imports: BTreeMap::new(),
            canonical: BTreeMap::new(),
            exports: BTreeMap::new(),
            operations: BTreeMap::new(),
            marker: PhantomData,
        }
    }
    pub fn modulus() -> ForeignModulus {
        if C::ScalarExt::MODULUS == iroha_pasta::Fp::MODULUS {
            ForeignModulus::PASTA_FP
        } else {
            ForeignModulus::PASTA_FQ
        }
    }
    fn cells(value: &Scalar<C>) -> [Cell; 3] {
        value
            .limbs()
            .each_ref()
            .map(iroha_plonk_gadgets::Word::cell)
    }
    fn constant_value(&self, value: &Scalar<C>) -> Option<C::ScalarExt> {
        let key = Self::cells(value);
        self.constants
            .iter()
            .find_map(|(constant, scalar)| (Self::cells(scalar) == key).then_some(*constant))
    }
    fn admitted(values: &[&Scalar<C>]) -> Result<(), Error> {
        if values
            .iter()
            .any(|value| value.modulus() != Self::modulus())
        {
            Err(Error::Synthesis)
        } else {
            Ok(())
        }
    }
    fn commutative(a: &Scalar<C>, b: &Scalar<C>) -> ([Cell; 3], [Cell; 3]) {
        let a = Self::cells(a);
        let b = Self::cells(b);
        if a <= b { (a, b) } else { (b, a) }
    }
    pub fn constant(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: C::ScalarExt,
    ) -> Result<Scalar<C>, Error> {
        if let Some(cached) = self.constants.get(&value) {
            return Ok(cached.clone());
        }
        let scalar = self.ff.constant(
            uint.glue(),
            region,
            Self::modulus(),
            &Nat::from_words(value.to_canonical_limbs()),
        )?;
        self.constants.insert(value, scalar.clone());
        Ok(scalar)
    }
    pub fn import(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &ScalarCells<C>,
    ) -> Result<Scalar<C>, Error> {
        let key = [value.lo().cell(), value.hi().cell()];
        if let Some(cached) = self.imports.get(&key) {
            return Ok(cached.clone());
        }
        let scalar = self.ff.import_s6(uint, region, value.canonical())?;
        // The exact integer bridge already proves that these canonical FF
        // cells are the supplied S6 cells. Retain both directions of that
        // certificate; never synthesize a second split for the same cells.
        self.exports.insert(Self::cells(&scalar), value.clone());
        self.imports.insert(key, scalar.clone());
        Ok(scalar)
    }
    pub fn export(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<ScalarCells<C>, Error> {
        if value.modulus() != Self::modulus() {
            return Err(Error::Synthesis);
        }
        let key = value
            .limbs()
            .each_ref()
            .map(iroha_plonk_gadgets::Word::cell);
        if let Some(cached) = self.exports.get(&key) {
            return Ok(cached.clone());
        }
        let canonical = self.canonicalize(region, value)?;
        let canonical_key = Self::cells(&canonical);
        if let Some(cells) = self.exports.get(&canonical_key).cloned() {
            self.exports.insert(key, cells.clone());
            return Ok(cells);
        }
        let value = self.ff.export_s6(uint, region, &canonical)?;
        let cells = ScalarCells::from_canonical(uint, region, value)?;
        // Export may reduce a lazy source. Its inverse map must point only to
        // that canonical result, never to the original unreduced integer.
        self.imports
            .insert([cells.lo().cell(), cells.hi().cell()], canonical);
        self.exports.insert(canonical_key, cells.clone());
        self.exports.insert(key, cells.clone());
        Ok(cells)
    }
    // Reuse is keyed by exact proving-cell identities, never by witness value.
    // The earlier constraint stays in the same lane, so a cache hit retains
    // its range, modulus and congruence proof in both known/unknown synthesis.
    fn canonicalize(
        &mut self,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        if value.modulus() != Self::modulus() {
            return Err(Error::Synthesis);
        }
        let key = value
            .limbs()
            .each_ref()
            .map(iroha_plonk_gadgets::Word::cell);
        if let Some(cached) = self.canonical.get(&key) {
            return Ok(cached.clone());
        }
        let normalized = self.ff.assert_canonical(region, value)?;
        self.canonical.insert(key, normalized.clone());
        Ok(normalized)
    }
    pub fn add(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        a: &Scalar<C>,
        b: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        Self::admitted(&[a, b])?;
        let ca = self.constant_value(a);
        let cb = self.constant_value(b);
        if let (Some(a), Some(b)) = (ca, cb) {
            return self.constant(uint, region, a + b);
        }
        if ca == Some(C::ScalarExt::ZERO) {
            return Ok(b.clone());
        }
        if cb == Some(C::ScalarExt::ZERO) {
            return Ok(a.clone());
        }
        let (a_key, b_key) = Self::commutative(a, b);
        let key = Operation::Add(a_key, b_key);
        if let Some(cached) = self.operations.get(&key) {
            return Ok(cached.clone());
        }
        let value = self.ff.add(uint.glue(), region, a, b)?;
        self.operations.insert(key, value.clone());
        Ok(value)
    }
    pub fn sub(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        a: &Scalar<C>,
        b: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        Self::admitted(&[a, b])?;
        let ca = self.constant_value(a);
        let cb = self.constant_value(b);
        if let (Some(a), Some(b)) = (ca, cb) {
            return self.constant(uint, region, a - b);
        }
        if Self::cells(a) == Self::cells(b) {
            return self.constant(uint, region, C::ScalarExt::ZERO);
        }
        if cb == Some(C::ScalarExt::ZERO) {
            return Ok(a.clone());
        }
        if ca == Some(C::ScalarExt::ZERO) {
            return self.neg(uint, region, b);
        }
        let key = Operation::Sub(Self::cells(a), Self::cells(b));
        if let Some(cached) = self.operations.get(&key) {
            return Ok(cached.clone());
        }
        let value = self.ff.sub(uint.glue(), region, a, b)?;
        self.operations.insert(key, value.clone());
        Ok(value)
    }
    pub fn neg(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        Self::admitted(&[value])?;
        if let Some(constant) = self.constant_value(value) {
            return self.constant(uint, region, -constant);
        }
        let key = Operation::Neg(Self::cells(value));
        if let Some(cached) = self.operations.get(&key) {
            return Ok(cached.clone());
        }
        let value = self.ff.neg(uint.glue(), region, value)?;
        self.operations.insert(key, value.clone());
        Ok(value)
    }
    pub fn mul(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        a: &Scalar<C>,
        b: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        Self::admitted(&[a, b])?;
        let ca = self.constant_value(a);
        let cb = self.constant_value(b);
        if let (Some(a), Some(b)) = (ca, cb) {
            return self.constant(uint, region, a * b);
        }
        if ca == Some(C::ScalarExt::ZERO) || cb == Some(C::ScalarExt::ZERO) {
            return self.constant(uint, region, C::ScalarExt::ZERO);
        }
        if ca == Some(C::ScalarExt::ONE) {
            return Ok(b.clone());
        }
        if cb == Some(C::ScalarExt::ONE) {
            return Ok(a.clone());
        }
        if ca == Some(-C::ScalarExt::ONE) {
            return self.neg(uint, region, b);
        }
        if cb == Some(-C::ScalarExt::ONE) {
            return self.neg(uint, region, a);
        }
        let (a_key, b_key) = Self::commutative(a, b);
        let key = Operation::Mul(a_key, b_key);
        if let Some(cached) = self.operations.get(&key) {
            return Ok(cached.clone());
        }
        let value = if let Some((constant, other)) = ca
            .map(|constant| (constant, b))
            .or_else(|| cb.map(|constant| (constant, a)))
        {
            let words = constant.to_canonical_limbs();
            if words[1..] == [0, 0, 0] && words[0] <= 128 {
                self.ff.scale(uint.glue(), region, other, words[0])?
            } else {
                self.ff.mul(region, a, b)?
            }
        } else {
            self.ff.mul(region, a, b)?
        };
        self.operations.insert(key, value.clone());
        Ok(value)
    }
    // An explicit shared-layout operation. Every batched input is reduced to
    // a proven Proper representative before invoking the unsigned kernel.
    pub fn dot(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        pairs: &[(&Scalar<C>, &Scalar<C>)],
    ) -> Result<Scalar<C>, Error> {
        if pairs.is_empty() || pairs.len() > 8 {
            return Err(Error::Synthesis);
        }
        Self::admitted(&pairs.iter().flat_map(|(a, b)| [*a, *b]).collect::<Vec<_>>())?;
        if let [(left, right)] = pairs {
            return self.mul(uint, region, left, right);
        }
        let mut sum = self.constant(uint, region, C::ScalarExt::ZERO)?;
        let mut products = Vec::new();
        for (a, b) in pairs {
            let (left, right) = Self::commutative(a, b);
            let cached = self.operations.get(&Operation::Mul(left, right)).cloned();
            if let Some(product) = cached {
                sum = self.add(uint, region, &sum, &product)?;
            } else if self.ff.config().is_some() || self.cheap_product(a, b) {
                let product = self.mul(uint, region, a, b)?;
                sum = self.add(uint, region, &sum, &product)?;
            } else {
                products.push((self.proper(region, a)?, self.proper(region, b)?));
            }
        }
        if !products.is_empty() {
            let pairs = products.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();
            let product = self.ff.dot_proper(region, &pairs)?;
            sum = self.add(uint, region, &sum, &product)?;
        }
        Ok(sum)
    }
    // Preserve the structural constant fast paths from `mul`. A full-field
    // coefficient with no cheap lowering belongs in the unsigned batch.
    fn cheap_product(&self, a: &Scalar<C>, b: &Scalar<C>) -> bool {
        let ca = self.constant_value(a);
        let cb = self.constant_value(b);
        (ca.is_some() && cb.is_some())
            || ca.into_iter().chain(cb).any(|constant| {
                let words = constant.to_canonical_limbs();
                constant == -C::ScalarExt::ONE || (words[1..] == [0, 0, 0] && words[0] <= 128)
            })
    }
    fn proper(
        &mut self,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        let key = Operation::Proper(Self::cells(value));
        if let Some(cached) = self.operations.get(&key) {
            return Ok(cached.clone());
        }
        let result = self.ff.reduce(region, value)?;
        self.operations.insert(key, result.clone());
        Ok(result)
    }

    pub fn square(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        self.mul(uint, region, value, value)
    }
    pub fn select(
        &self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        bit: &Bit<C::Base>,
        a: &Scalar<C>,
        b: &Scalar<C>,
    ) -> Result<Scalar<C>, Error> {
        self.ff.select(uint.glue(), region, bit, a, b)
    }
    pub fn equal(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        a: &Scalar<C>,
        b: &Scalar<C>,
    ) -> Result<Bit<C::Base>, Error> {
        let a = self.canonicalize(region, a)?;
        let b = self.canonicalize(region, b)?;
        let mut matches = uint.glue().is_equal(region, &a.limbs()[0], &b.limbs()[0])?;
        for (a, b) in a.limbs().iter().zip(b.limbs()).skip(1) {
            let next = uint.glue().is_equal(region, a, b)?;
            matches = uint.glue().and(region, &matches, &next)?;
        }
        Ok(matches)
    }
    pub fn nonzero(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<Bit<C::Base>, Error> {
        let zero = self.constant(uint, region, C::ScalarExt::ZERO)?;
        let is_zero = self.equal(uint, region, value, &zero)?;
        uint.glue().not(region, &is_zero)
    }
    pub fn inverse(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
    ) -> Result<(Scalar<C>, Bit<C::Base>), Error> {
        // The zero test already requires this exact canonical representative.
        // Reuse it for the guarded division rather than reducing the original
        // lazy representative a second time under the divisor admission rule.
        let value = self.canonicalize(region, value)?;
        let nonzero = self.nonzero(uint, region, &value)?;
        let one = self.constant(uint, region, C::ScalarExt::ONE)?;
        let safe = self.select(uint, region, &nonzero, &value, &one)?;
        let out = self.ff.inverse(region, &safe)?;
        Ok((out, nonzero))
    }
    pub fn pow(
        &mut self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: &Scalar<C>,
        exponent: u64,
    ) -> Result<Scalar<C>, Error> {
        let mut out = self.constant(uint, region, C::ScalarExt::ONE)?;
        let mut power = value.clone();
        let mut exponent = exponent;
        while exponent != 0 {
            if exponent & 1 != 0 {
                out = self.mul(uint, region, &out, &power)?;
            }
            exponent >>= 1;
            if exponent != 0 {
                power = self.square(uint, region, &power)?;
            }
        }
        Ok(out)
    }
}
