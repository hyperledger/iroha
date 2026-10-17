//! Bilinear multiplication algorithms over `GF(2)`.
//!
//! An [`Alg`] for operands `a` and `b` is a list of gates, each the AND of a linear
//! form of `a` with a linear form of `b`, and a list of outputs, each the XOR of the
//! gates in a mask. [`AlgBuilder`] builds the algorithms the cost search selected,
//! and the algorithm of a place of a CRT portfolio together with the linear forms
//! that read the same residue coordinates off the product.

use std::collections::BTreeMap;

use super::{
    bits::{Bits, index},
    cost::{CostTable, FullPlan, Place, PlaceKind, ShortPlan, degree_u32, tower_cost},
    error::CrtError,
    f4, gf2poly,
    linalg::{combine, left_inverse, pascal_rows, reduction_rows, row},
};

/// Input forms of Montgomery's five-term algorithm; both operands use the same.
const MONT5_GATES: [u64; 13] = [
    0b11111, 0b11101, 0b10111, 0b11011, 0b01101, 0b10110, 0b11000, 0b00011, 0b10001, 0b10000,
    0b01000, 0b00010, 0b00001,
];

/// Gates summed into each of the nine product coefficients of Montgomery's
/// algorithm.
const MONT5_OUTPUTS: [&[usize]; 9] = [
    &[12],
    &[7, 11, 12],
    &[2, 5, 7, 8, 9, 12],
    &[0, 1, 3, 6, 8, 9],
    &[0, 4, 5, 6, 7, 9, 10, 11, 12],
    &[0, 2, 3, 7, 8, 12],
    &[1, 4, 6, 8, 9, 12],
    &[6, 9, 10],
    &[9],
];

/// A bilinear algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alg {
    /// The gates: a form of the first operand and a form of the second.
    pub gates: Vec<(Bits, Bits)>,
    /// The outputs, each a mask over the gates.
    pub outputs: Vec<Bits>,
}

/// The algorithm of one place and the forms that evaluate the product there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceAlg {
    /// Gates on the operands and the residue coordinates as masks over them.
    pub alg: Alg,
    /// The same residue coordinates as forms of the product coefficients.
    pub evaluation: Vec<Bits>,
}

/// The one-gate algorithm for one coefficient.
fn base_alg() -> Alg {
    Alg {
        gates: vec![(Bits::from_u64(1), Bits::from_u64(1))],
        outputs: vec![Bits::from_u64(1)],
    }
}

/// Montgomery's algorithm for five coefficients.
fn mont5_alg() -> Alg {
    Alg {
        gates: MONT5_GATES
            .iter()
            .map(|form| (Bits::from_u64(*form), Bits::from_u64(*form)))
            .collect(),
        outputs: MONT5_OUTPUTS
            .iter()
            .map(|gates| {
                let mut mask = Bits::zero();
                for gate in *gates {
                    mask.set(*gate);
                }
                mask
            })
            .collect(),
    }
}

/// Feed `alg` with forms of outer operands: input bit `i` of its first operand is
/// the form `left[i]`, and of its second operand the form `right[i]`.
fn precompose(alg: &Alg, left: &[Bits], right: &[Bits]) -> Result<Alg, CrtError> {
    let gates = alg
        .gates
        .iter()
        .map(|(first, second)| Ok((combine(first, left)?, combine(second, right)?)))
        .collect::<Result<_, CrtError>>()?;
    Ok(Alg {
        gates,
        outputs: alg.outputs.clone(),
    })
}

/// The unit forms `e_start, e_start + 1, ...`, `count` of them.
fn units(start: usize, count: usize) -> Vec<Bits> {
    (0..count)
        .map(|position| Bits::unit(start + position))
        .collect()
}

/// Multiply the pair `(low, high)`, read as `low + high * w`, by an element of
/// `F_4`, and add it to `acc`.
fn add_scaled(acc: &mut (Bits, Bits), factor: u8, low: &Bits, high: &Bits) {
    if factor & 1 != 0 {
        acc.0.xor_assign(low);
        acc.1.xor_assign(high);
    }
    if factor & 2 != 0 {
        // w * (low + high w) = high + (low + high) w.
        acc.0.xor_assign(high);
        acc.1.xor_assign(low);
        acc.1.xor_assign(high);
    }
}

/// Builder of multiplication algorithms, with the memo tables of one construction.
#[derive(Debug, Default)]
pub struct AlgBuilder {
    /// The cost search that selects the plans.
    pub costs: CostTable,
    full: BTreeMap<usize, Alg>,
    short: BTreeMap<usize, Alg>,
}

impl AlgBuilder {
    /// The algorithm for all `2 * size - 1` coefficients of the product of two
    /// polynomials of `size` coefficients.
    pub fn full_alg(&mut self, size: usize) -> Result<Alg, CrtError> {
        if let Some(found) = self.full.get(&size) {
            return Ok(found.clone());
        }
        let alg = match self.costs.full_cost(size)?.1 {
            FullPlan::Base => base_alg(),
            FullPlan::Mont5 => mont5_alg(),
            FullPlan::Split { outer, inner } => self.split_alg(size, outer, inner)?,
            FullPlan::Crt(places) => {
                let mut gates = Vec::new();
                let mut residues = Vec::new();
                let mut evaluation = Vec::new();
                for place in places {
                    let part = self.checked_place(place, size, size)?;
                    let offset = gates.len();
                    gates.extend(part.alg.gates);
                    residues.extend(part.alg.outputs.iter().map(|mask| mask.shl(offset)));
                    evaluation.extend(part.evaluation);
                }
                let inverse = left_inverse(&evaluation, 2 * size - 1)?;
                let outputs = inverse
                    .iter()
                    .map(|mask| combine(mask, &residues))
                    .collect::<Result<_, _>>()?;
                Alg { gates, outputs }
            }
        };
        self.full.insert(size, alg.clone());
        Ok(alg)
    }

    /// The nested algorithm: `outer` blocks of `inner` coefficients. The gates of
    /// the outer algorithm form the outer loop.
    fn split_alg(&mut self, size: usize, outer: usize, inner: usize) -> Result<Alg, CrtError> {
        let outer_alg = self.full_alg(outer)?;
        let inner_alg = self.full_alg(inner)?;
        let inner_gates = inner_alg.gates.len();
        let spread = |form: &Bits| -> Vec<Bits> {
            (0..inner)
                .map(|position| {
                    let mut out = Bits::zero();
                    for block in form.ones() {
                        if block * inner + position < size {
                            out.set(block * inner + position);
                        }
                    }
                    out
                })
                .collect()
        };
        let mut gates = Vec::with_capacity(outer_alg.gates.len() * inner_gates);
        for (first, second) in &outer_alg.gates {
            let left = spread(first);
            let right = spread(second);
            for (inner_first, inner_second) in &inner_alg.gates {
                gates.push((combine(inner_first, &left)?, combine(inner_second, &right)?));
            }
        }
        let mut outputs = Vec::with_capacity(2 * size - 1);
        for coefficient in 0..2 * size - 1 {
            let mut mask = Bits::zero();
            for block in 0..2 * outer - 1 {
                let Some(position) = coefficient.checked_sub(block * inner) else {
                    continue;
                };
                if position <= 2 * inner - 2 {
                    let inner_mask = row(&inner_alg.outputs, position)?;
                    for gate in row(&outer_alg.outputs, block)?.ones() {
                        mask.xor_shifted(inner_mask, gate * inner_gates);
                    }
                }
            }
            outputs.push(mask);
        }
        Ok(Alg { gates, outputs })
    }

    /// The algorithm for the low `size` coefficients of the product of two
    /// polynomials of `size` coefficients.
    ///
    /// Under the plan [`ShortPlan::Full`] this is the full algorithm unchanged, with
    /// `2 * size - 1` outputs; see [`Self::checked_place`].
    pub fn short_alg(&mut self, size: usize) -> Result<Alg, CrtError> {
        if let Some(found) = self.short.get(&size) {
            return Ok(found.clone());
        }
        let alg = match self.costs.short_cost(size)?.1 {
            ShortPlan::Base => base_alg(),
            ShortPlan::Full => self.full_alg(size)?,
            ShortPlan::ShortSplit(low) => {
                let rest = size - low;
                let low_forms = units(0, low);
                let first = precompose(&self.full_alg(low)?, &low_forms, &low_forms)?;
                let nested = self.short_alg(rest)?;
                let low_rest = units(0, rest);
                let high_rest = units(low, rest);
                let second = precompose(&nested, &low_rest, &high_rest)?;
                let third = precompose(&nested, &high_rest, &low_rest)?;
                let second_offset = first.gates.len();
                let third_offset = second_offset + second.gates.len();
                let mut outputs = Vec::with_capacity(size);
                for coefficient in 0..size {
                    let mut mask = Bits::zero();
                    if coefficient <= 2 * low - 2 {
                        mask.xor_assign(row(&first.outputs, coefficient)?);
                    }
                    if let Some(position) = coefficient.checked_sub(low) {
                        mask.xor_shifted(row(&second.outputs, position)?, second_offset);
                        mask.xor_shifted(row(&third.outputs, position)?, third_offset);
                    }
                    outputs.push(mask);
                }
                let mut gates = first.gates;
                gates.extend(second.gates);
                gates.extend(third.gates);
                Alg { gates, outputs }
            }
        };
        self.short.insert(size, alg.clone());
        Ok(alg)
    }

    /// [`Self::place_alg`] plus the invariant the reference relies on silently: one
    /// gate mask per evaluation row.
    ///
    /// Both callers append every mask and every evaluation row, so a mismatch would
    /// misalign all later residue coordinates. It can only arise for a place at
    /// infinity, `x` or `x + 1` of multiplicity two, whose short plan is the full
    /// algorithm with three outputs for two evaluation rows; no profile selects one.
    ///
    /// # Errors
    /// [`CrtError::PlaceRowMismatch`] on a mismatch; nothing is truncated.
    pub fn checked_place(
        &mut self,
        place: Place,
        left_len: usize,
        right_len: usize,
    ) -> Result<PlaceAlg, CrtError> {
        let part = self.place_alg(place, left_len, right_len)?;
        if part.alg.outputs.len() != part.evaluation.len() {
            return Err(CrtError::PlaceRowMismatch {
                mask_rows: part.alg.outputs.len(),
                evaluation_rows: part.evaluation.len(),
            });
        }
        Ok(part)
    }

    /// The algorithm of one place for operands of `left_len` and `right_len`
    /// coefficients, without the row check of [`Self::checked_place`].
    pub fn place_alg(
        &mut self,
        place: Place,
        left_len: usize,
        right_len: usize,
    ) -> Result<PlaceAlg, CrtError> {
        let multiplicity = index(place.multiplicity);
        if left_len == 0 || right_len == 0 || multiplicity == 0 {
            return Err(CrtError::Construction {
                what: "an empty operand or a place of multiplicity zero",
            });
        }
        let product_len = left_len + right_len - 1;
        match place.kind {
            PlaceKind::Infinity => {
                if multiplicity > left_len.min(right_len) {
                    return Err(CrtError::Construction {
                        what: "the place at infinity exceeds an operand",
                    });
                }
                let top = |length: usize| -> Vec<Bits> {
                    (0..multiplicity)
                        .map(|position| Bits::unit(length - 1 - position))
                        .collect()
                };
                Ok(PlaceAlg {
                    alg: precompose(
                        &self.short_alg(multiplicity)?,
                        &top(left_len),
                        &top(right_len),
                    )?,
                    evaluation: top(product_len),
                })
            }
            PlaceKind::Linear => {
                let modulus = gf2poly::pow(&Bits::from_u64(u64::from(place.poly)), multiplicity);
                let mut left = reduction_rows(&modulus, left_len)?;
                let mut right = reduction_rows(&modulus, right_len)?;
                let mut evaluation = reduction_rows(&modulus, product_len)?;
                if place.poly != 0b10 {
                    // Taylor shift to the expansion around the root of `x + 1`.
                    let shift = pascal_rows(multiplicity);
                    let apply = |rows: &[Bits]| -> Result<Vec<Bits>, CrtError> {
                        shift.iter().map(|mask| combine(mask, rows)).collect()
                    };
                    left = apply(&left)?;
                    right = apply(&right)?;
                    evaluation = apply(&evaluation)?;
                }
                Ok(PlaceAlg {
                    alg: precompose(&self.short_alg(multiplicity)?, &left, &right)?,
                    evaluation,
                })
            }
            PlaceKind::Irreducible => {
                let base_degree = degree_u32(place.poly);
                let tower = tower_cost(base_degree);
                if multiplicity == 1 && tower != 0 && tower < self.costs.full_cost(base_degree)?.0 {
                    return tower_place_alg(place.poly, left_len, right_len);
                }
                let modulus = gf2poly::pow(&Bits::from_u64(u64::from(place.poly)), multiplicity);
                let degree = modulus.degree().ok_or(CrtError::DivisionByZero)?;
                let inner = precompose(
                    &self.full_alg(degree)?,
                    &reduction_rows(&modulus, left_len)?,
                    &reduction_rows(&modulus, right_len)?,
                )?;
                let reduce = reduction_rows(&modulus, 2 * degree - 1)?;
                let outputs = reduce
                    .iter()
                    .map(|mask| combine(mask, &inner.outputs))
                    .collect::<Result<_, _>>()?;
                Ok(PlaceAlg {
                    alg: Alg {
                        gates: inner.gates,
                        outputs,
                    },
                    evaluation: reduction_rows(&modulus, product_len)?,
                })
            }
        }
    }
}

/// The `F_4` form `form` of a tower element whose coordinates are the forms
/// `tower_rows` (`2j` the `1` part and `2j + 1` the `w` part of the coefficient of
/// `y^j`), as its `1` part and its `w` part.
fn tower_form(form: &[u8], tower_rows: &[Bits]) -> Result<(Bits, Bits), CrtError> {
    let mut acc = (Bits::zero(), Bits::zero());
    for (position, factor) in form.iter().enumerate() {
        if *factor != 0 {
            add_scaled(
                &mut acc,
                *factor,
                row(tower_rows, 2 * position)?,
                row(tower_rows, 2 * position + 1)?,
            );
        }
    }
    Ok(acc)
}

/// The first element of `F_4[y] / (modulus)`, in tuple order, that is a root of the
/// binary polynomial `poly`.
fn tower_root(poly: u32, modulus: &[u8]) -> Result<Vec<u8>, CrtError> {
    let size = modulus.len().saturating_sub(1);
    let degree = degree_u32(poly);
    f4::tuples(size)
        .into_iter()
        .find(|candidate| {
            let mut acc = vec![0u8; size];
            for position in (0..=degree).rev() {
                acc = f4::poly_rem(&f4::poly_mul(&acc, candidate), modulus);
                if (poly >> position) & 1 == 1
                    && let Some(constant) = acc.first_mut()
                {
                    *constant ^= 1;
                }
            }
            acc.iter().all(|value| *value == 0)
        })
        .ok_or(CrtError::Construction {
            what: "the place has no root in the tower field",
        })
}

/// The place `GF(2)[x] / (poly)` of degree 6 or 8 computed as `F_4[y] / (T)` with
/// `deg T` half the degree: each `F_4` gate costs three binary gates.
pub fn tower_place_alg(poly: u32, left_len: usize, right_len: usize) -> Result<PlaceAlg, CrtError> {
    let degree = degree_u32(poly);
    let size = degree / 2;
    if !degree.is_multiple_of(2) || !(2..=4).contains(&size) || left_len == 0 || right_len == 0 {
        return Err(CrtError::Construction {
            what: "the tower construction needs a place of degree 4, 6 or 8",
        });
    }
    let tower_modulus =
        f4::irreducibles(size)
            .into_iter()
            .next()
            .ok_or(CrtError::Construction {
                what: "no tower modulus",
            })?;
    let (gates4, outputs4) = f4::full_product_alg(size)?;

    // Outputs of the F_4 product reduced modulo the tower modulus.
    let reduce = f4::xpow_cols(&tower_modulus, 2 * size - 1);
    let mut reduced = vec![vec![0u8; gates4.len()]; size];
    for (coefficient, line) in reduced.iter_mut().enumerate() {
        for (column, output) in reduce.iter().zip(&outputs4) {
            let factor = column.get(coefficient).copied().unwrap_or(0);
            for (target, value) in line.iter_mut().zip(output) {
                *target ^= f4::mul(factor, *value);
            }
        }
    }

    // Change of basis from powers of x to the tower: column i is rho^i.
    let root = tower_root(poly, &tower_modulus)?;
    let mut basis = vec![Bits::zero(); degree];
    let mut power = vec![1u8];
    for column in 0..degree {
        for (position, value) in power.iter().enumerate() {
            for part in 0..2 {
                if (value >> part) & 1 == 1
                    && let Some(target) = basis.get_mut(2 * position + part)
                {
                    target.set(column);
                }
            }
        }
        power = f4::poly_rem(&f4::poly_mul(&power, &root), &tower_modulus);
    }
    let basis_inverse = left_inverse(&basis, degree)?;

    let modulus = Bits::from_u64(u64::from(poly));
    let to_tower = |length: usize| -> Result<Vec<Bits>, CrtError> {
        let reduction = reduction_rows(&modulus, length)?;
        basis.iter().map(|mask| combine(mask, &reduction)).collect()
    };
    let left = to_tower(left_len)?;
    let right = to_tower(right_len)?;

    let mut gates = Vec::with_capacity(3 * gates4.len());
    let mut products = Vec::with_capacity(gates4.len());
    for form in &gates4 {
        let (left_low, left_high) = tower_form(form, &left)?;
        let (right_low, right_high) = tower_form(form, &right)?;
        let first = gates.len();
        let mut left_sum = left_low.clone();
        left_sum.xor_assign(&left_high);
        let mut right_sum = right_low.clone();
        right_sum.xor_assign(&right_high);
        gates.push((left_low, right_low));
        gates.push((left_high, right_high));
        gates.push((left_sum, right_sum));
        // Karatsuba in F_4: the product is `low + high * w`.
        let mut low = Bits::unit(first);
        low.set(first + 1);
        let mut high = Bits::unit(first);
        high.set(first + 2);
        products.push((low, high));
    }
    let mut tower_outputs = Vec::with_capacity(degree);
    for line in &reduced {
        let mut acc = (Bits::zero(), Bits::zero());
        for (factor, (low, high)) in line.iter().zip(&products) {
            add_scaled(&mut acc, *factor, low, high);
        }
        tower_outputs.push(acc.0);
        tower_outputs.push(acc.1);
    }
    let outputs = basis_inverse
        .iter()
        .map(|mask| combine(mask, &tower_outputs))
        .collect::<Result<_, _>>()?;
    Ok(PlaceAlg {
        alg: Alg { gates, outputs },
        evaluation: reduction_rows(&modulus, left_len + right_len - 1)?,
    })
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

    /// Outputs of `alg` on the operands, as a bit vector.
    fn run(alg: &Alg, left: &Bits, right: &Bits) -> Bits {
        let mut gates = Bits::zero();
        for (position, (first, second)) in alg.gates.iter().enumerate() {
            if first.parity_and(left) && second.parity_and(right) {
                gates.set(position);
            }
        }
        let mut out = Bits::zero();
        for (position, mask) in alg.outputs.iter().enumerate() {
            if mask.parity_and(&gates) {
                out.set(position);
            }
        }
        out
    }

    /// The forms applied to a vector.
    fn apply(forms: &[Bits], value: &Bits) -> Bits {
        let mut out = Bits::zero();
        for (position, form) in forms.iter().enumerate() {
            if form.parity_and(value) {
                out.set(position);
            }
        }
        out
    }

    fn operand(state: &mut u64, length: usize) -> Bits {
        let mut out = Bits::zero();
        for position in 0..length {
            if next(state) & 1 == 1 {
                out.set(position);
            }
        }
        out
    }

    #[test]
    fn fixed_algorithms_multiply() {
        assert_eq!(base_alg().gates.len(), 1);
        let mont = mont5_alg();
        assert_eq!((mont.gates.len(), mont.outputs.len()), (13, 9));
        for left in 0..32u64 {
            for right in 0..32u64 {
                let (left, right) = (Bits::from_u64(left), Bits::from_u64(right));
                assert_eq!(run(&mont, &left, &right), gf2poly::mul(&left, &right));
            }
        }
    }

    #[test]
    fn precompose_and_units() {
        assert_eq!(units(3, 2), vec![Bits::unit(3), Bits::unit(4)]);
        // Feed the one-gate algorithm with the top coefficients.
        let alg = precompose(&base_alg(), &units(4, 1), &units(2, 1)).expect("in range");
        assert_eq!(alg.gates, vec![(Bits::unit(4), Bits::unit(2))]);
        assert_eq!(alg.outputs, base_alg().outputs);
        assert!(precompose(&mont5_alg(), &units(0, 4), &units(0, 5)).is_err());
    }

    #[test]
    fn add_scaled_multiplies_in_f4() {
        // (low, high) = (e0, e1) stands for the element e0 + e1 w.
        for factor in 0..4u8 {
            for value in 0..4u8 {
                let low = Bits::from_u64(u64::from(value & 1));
                let high = Bits::from_u64(u64::from(value >> 1));
                let mut acc = (Bits::zero(), Bits::zero());
                add_scaled(&mut acc, factor, &low, &high);
                let product = f4::mul(factor, value);
                assert_eq!(acc.0, Bits::from_u64(u64::from(product & 1)));
                assert_eq!(acc.1, Bits::from_u64(u64::from(product >> 1)));
            }
        }
    }

    #[test]
    fn full_algorithms_multiply_and_have_the_planned_size() {
        let mut builder = AlgBuilder::default();
        let mut state = 0x9e37_79b9_7f4a_7c15;
        for size in 1..=12usize {
            let alg = builder.full_alg(size).expect("plan");
            let cost = builder.costs.full_cost(size).expect("cost").0;
            assert_eq!(wide_len(&alg), cost, "n = {size}");
            assert_eq!(alg.outputs.len(), 2 * size - 1);
            for _ in 0..40 {
                let left = operand(&mut state, size);
                let right = operand(&mut state, size);
                assert_eq!(run(&alg, &left, &right), gf2poly::mul(&left, &right));
            }
            // Memoised.
            assert_eq!(builder.full_alg(size), Ok(alg));
        }
    }

    fn wide_len(alg: &Alg) -> u64 {
        u64::try_from(alg.gates.len()).expect("small")
    }

    #[test]
    fn split_alg_multiplies() {
        let mut builder = AlgBuilder::default();
        let mut state = 0x0123_4567_89ab_cdef;
        // 3 blocks of 2 coefficients cover the 5 coefficients of each operand.
        let alg = builder.split_alg(5, 3, 2).expect("split");
        assert_eq!(alg.gates.len(), 6 * 3);
        for _ in 0..60 {
            let left = operand(&mut state, 5);
            let right = operand(&mut state, 5);
            assert_eq!(run(&alg, &left, &right), gf2poly::mul(&left, &right));
        }
    }

    #[test]
    fn short_algorithms_give_the_low_half() {
        let mut builder = AlgBuilder::default();
        let mut state = 0xfeed_face_cafe_beef;
        for size in 1..=12usize {
            let alg = builder.short_alg(size).expect("plan");
            assert_eq!(
                wide_len(&alg),
                builder.costs.short_cost(size).expect("cost").0
            );
            // Plan Full (only n = 2) keeps all 2n - 1 outputs.
            let expected_outputs = if size == 2 { 3 } else { size };
            assert_eq!(alg.outputs.len(), expected_outputs, "n = {size}");
            for _ in 0..40 {
                let left = operand(&mut state, size);
                let right = operand(&mut state, size);
                let product = gf2poly::mul(&left, &right);
                let got = run(&alg, &left, &right);
                for position in 0..size {
                    assert_eq!(got.bit(position), product.bit(position));
                }
            }
        }
    }

    /// Every residue coordinate computed from the operands equals the coordinate
    /// read off the product.
    fn check_place(part: &PlaceAlg, left_len: usize, right_len: usize, state: &mut u64) {
        assert_eq!(part.alg.outputs.len(), part.evaluation.len());
        for _ in 0..40 {
            let left = operand(state, left_len);
            let right = operand(state, right_len);
            let product = gf2poly::mul(&left, &right);
            assert_eq!(
                run(&part.alg, &left, &right),
                apply(&part.evaluation, &product)
            );
        }
    }

    #[test]
    fn places_evaluate_the_product() {
        let mut builder = AlgBuilder::default();
        let mut state = 0x1357_9bdf_0246_8ace;
        let list = [
            (Place::infinity(1), 1),
            (Place::infinity(3), 5),
            (Place::linear(0b10, 5), 11),
            (Place::linear(0b11, 3), 5),
            (Place::linear(0b11, 5), 11),
            (Place::irreducible(0b111, 2), 9),
            (Place::irreducible(0xb, 1), 6),
            (Place::irreducible(0x25, 1), 13),
            (Place::irreducible(0x43, 1), 15),
            (Place::irreducible(0x11b, 1), 24),
            (Place::irreducible(0x83, 1), 22),
        ];
        for (place, gates) in list {
            let part = builder.checked_place(place, 20, 17).expect("place");
            assert_eq!(part.alg.gates.len(), gates, "{place:?}");
            check_place(&part, 20, 17, &mut state);
        }
        assert!(builder.place_alg(Place::infinity(4), 3, 9).is_err());
        assert!(builder.place_alg(Place::infinity(0), 3, 9).is_err());
        assert!(builder.place_alg(Place::infinity(1), 0, 9).is_err());
    }

    #[test]
    fn a_multiplicity_two_linear_place_breaks_the_row_invariant() {
        let mut builder = AlgBuilder::default();
        for place in [
            Place::infinity(2),
            Place::linear(0b10, 2),
            Place::linear(0b11, 2),
        ] {
            // The unchecked construction returns three masks for two rows.
            let part = builder.place_alg(place, 8, 8).expect("constructible");
            assert_eq!((part.alg.outputs.len(), part.evaluation.len()), (3, 2));
            assert_eq!(
                builder.checked_place(place, 8, 8),
                Err(CrtError::PlaceRowMismatch {
                    mask_rows: 3,
                    evaluation_rows: 2
                })
            );
        }
    }

    #[test]
    fn tower_helpers() {
        let rows = units(0, 4);
        let (low, high) = tower_form(&[1, 2], &rows).expect("in range");
        // e0 + e1 w, plus w (e2 + e3 w) = e3 + (e2 + e3) w.
        assert_eq!(low.ones().collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(high.ones().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert!(tower_form(&[0, 0, 1], &rows).is_err());

        let modulus = [1, 0, 1, 1];
        let root = tower_root(0x43, &modulus).expect("degree 6 splits in the tower");
        assert_eq!(root.len(), 3);
        // x^2 + x + 1 has its roots in F_4 itself: the first is w.
        assert_eq!(tower_root(0b111, &modulus), Ok(vec![2, 0, 0]));
        // x^5 + x^2 + 1 has no root in a field of 64 elements.
        assert!(tower_root(0x25, &modulus).is_err());
    }

    #[test]
    fn tower_places_evaluate_the_product() {
        let mut state = 0x2468_ace0_1357_9bdf;
        for (poly, gates) in [
            (0x13u32, 9usize),
            (0x43, 15),
            (0x75, 15),
            (0x11b, 24),
            (0x1f9, 24),
        ] {
            let part = tower_place_alg(poly, 23, 16).expect("tower");
            assert_eq!(part.alg.gates.len(), gates);
            check_place(&part, 23, 16, &mut state);
        }
        assert!(tower_place_alg(0x25, 8, 8).is_err());
        assert!(tower_place_alg(0b111, 8, 8).is_err());
        assert!(tower_place_alg(0x43, 0, 8).is_err());
    }
}
