//! The ECC chip tests: the M3 named tests of the Λ/Ω design (§10), native
//! parity on both curves, adversarial witnesses (alternative splits, digit
//! sequences that reach exceptional cases in the complete tail, halves out
//! of range), per-cell tamper suites, a real proof and the G3.5 inventory.

use core::cmp::Ordering;
use std::convert::Infallible;

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness,
    check::{CheckFailure, CheckMode, CheckReport, check, check_circuit},
    cs::{Advice, Any, Column, ConstraintSystem, Fixed, Instance, Selector, TranscriptV1},
    frontend::{
        Assembly, Assigned, Assignment, Circuit, Error, FloorPlanner, Layouter, Region,
        SimpleFloorPlanner, Value, configure, synthesize,
    },
    keys::{KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::{native::*, *};
use crate::{
    MAX_GATE_DEGREE,
    arith::GlueConfig,
    cells::{U128, Uint},
    range::{
        LimbBits, RangeShape, RunningSumChip, RunningSumConfig, UintChip, running_sum_witness,
    },
    tamper::{Tamper, check_tampered},
};

// ---------------------------------------------------------------------------
// Test circuit
// ---------------------------------------------------------------------------

/// Advice column indices: the chip's ten, then the glue chip's four, then
/// the running-sum column.
const ECC_COLUMNS: core::ops::Range<usize> = 0..10;
const RANGE_COLUMN: usize = 14;

/// The chips a program drives.
struct Chips<C: PastaCurve> {
    ecc: EccChip<C>,
    glue: GlueChip<C::Base>,
    range: RunningSumChip<C::Base>,
}

/// The witness inputs of a program; `fixed` bases are circuit constants.
#[derive(Clone, Debug)]
struct Inputs<C: PastaCurve> {
    points: Vec<C>,
    scalars: Vec<[u128; 2]>,
    halves: Vec<GlvHalves>,
    fixed: Vec<C>,
    known: bool,
}

impl<C: PastaCurve> Inputs<C> {
    fn new(points: Vec<C>, scalars: Vec<[u128; 2]>) -> Self {
        Self {
            points,
            scalars,
            halves: Vec::new(),
            fixed: Vec::new(),
            known: true,
        }
    }

    fn point(&self, index: usize) -> Value<C> {
        match self.points.get(index) {
            Some(point) if self.known => Value::known(*point),
            _ => Value::unknown(),
        }
    }

    fn scalar(&self, index: usize) -> Value<[u128; 2]> {
        match self.scalars.get(index) {
            Some(scalar) if self.known => Value::known(*scalar),
            _ => Value::unknown(),
        }
    }

    fn halves(&self, index: usize) -> Value<GlvHalves> {
        match self.halves.get(index) {
            Some(halves) if self.known => Value::known(*halves),
            _ => Value::unknown(),
        }
    }
}

/// A program over the chips; its words become the public instance.
type Program<C> = fn(
    &mut Chips<C>,
    &mut Region<'_, <C as PastaCurve>::Base>,
    &Inputs<C>,
) -> Result<Vec<Word<<C as PastaCurve>::Base>>, Error>;

/// The configuration-time shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Shape {
    limb_bits: usize,
    public: usize,
    fixed_base: bool,
}

/// The columns of [`TestCircuit`].
#[derive(Clone, Debug)]
struct TestConfig<C: PastaCurve> {
    ecc: EccConfig<C>,
    glue: GlueConfig,
    range: RunningSumConfig,
    instance: Column<Instance>,
}

/// A circuit running `program` over the ECC, glue and range chips.
struct TestCircuit<C: PastaCurve> {
    shape: Shape,
    program: Program<C>,
    inputs: Inputs<C>,
}

impl<C: PastaCurve> Clone for TestCircuit<C> {
    fn clone(&self) -> Self {
        Self {
            shape: self.shape,
            program: self.program,
            inputs: self.inputs.clone(),
        }
    }
}

impl<C: PastaCurve> TestCircuit<C> {
    fn new(program: Program<C>, inputs: Inputs<C>, public: usize) -> Self {
        Self {
            shape: Shape {
                limb_bits: 8,
                public,
                fixed_base: !inputs.fixed.is_empty(),
            },
            program,
            inputs,
        }
    }
}

impl<C: PastaCurve> Circuit<C::Base> for TestCircuit<C> {
    type Config = TestConfig<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        let mut circuit = self.clone();
        circuit.inputs.known = false;
        circuit
    }

    fn params(&self) -> Shape {
        self.shape
    }

    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        Self::configure_with_params(meta, Shape::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<C::Base>, shape: Shape) -> Self::Config {
        let ecc_advice: [Column<Advice>; ECC_ADVICE_COLUMNS] =
            core::array::from_fn(|_| meta.advice_column());
        let ecc = if shape.fixed_base {
            EccConfig::configure_with_fixed_base(meta, ecc_advice)
        } else {
            EccConfig::configure(meta, ecc_advice)
        };
        let glue_advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, glue_advice, constants);
        let z = meta.advice_column();
        let limb_bits = LimbBits::new(shape.limb_bits)
            .or_else(|| LimbBits::new(8))
            .unwrap_or_else(|| unreachable!("8 is a valid limb width"));
        let range = RunningSumConfig::configure(meta, z, limb_bits);
        let instance = meta.instance_column(shape.public);
        meta.enable_equality(instance);
        TestConfig {
            ecc,
            glue,
            range,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chips = Chips {
            ecc: EccChip::new(&config.ecc),
            glue: GlueChip::new(config.glue),
            range: RunningSumChip::new(config.range),
        };
        chips.range.load_table(&mut layouter)?;
        let program = self.program;
        let outputs = layouter.assign_region(
            || "ecc",
            |mut region| program(&mut chips, &mut region, &self.inputs),
        )?;
        if outputs.len() != self.shape.public {
            return Err(Error::Synthesis);
        }
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// The strict checker report.
fn check_report<C: PastaCurve>(
    circuit: &TestCircuit<C>,
    k: u32,
    public: &[C::Base],
) -> CheckReport<C::Base> {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict).expect("synthesis")
}

/// Asserts the strict checker accepts `circuit`.
fn assert_accepts<C: PastaCurve>(circuit: &TestCircuit<C>, k: u32, public: &[C::Base]) {
    let report = check_report(circuit, k, public);
    assert!(report.is_satisfied(), "{report}");
}

/// The coordinates of `points`, flattened (the public instance of the
/// programs).
fn public_of<C: PastaCurve>(points: &[C]) -> Vec<C::Base> {
    points
        .iter()
        .flat_map(|point| {
            let (x, y) = coordinates(point);
            [x, y]
        })
        .collect()
}

/// A point's cells as public words.
fn expose<F: PastaField>(point: &AssignedPoint<F>) -> [Word<F>; 2] {
    [point.x().clone(), point.y().clone()]
}

/// The limb cells of a scalar.
type Limbs<F> = (U128<F>, Uint<F, 127>);

/// Assigns the limbs of a scalar (`lo` 128 bits, `hi` 127 bits).
fn scalar_limbs<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    value: Value<[u128; 2]>,
) -> Result<Limbs<C::Base>, Error> {
    let mut uint = UintChip::new(&mut chips.glue, &mut chips.range);
    let lo = uint.assign::<128>(region, value.map(|[lo, _]| lo))?;
    let hi = uint.assign::<127>(region, value.map(|[_, hi]| hi))?;
    Ok((lo, hi))
}

/// The identity of `C`.
fn identity<C: PastaCurve>() -> C {
    C::identity()
}

/// The generator of `C`.
fn generator<C: PastaCurve>() -> C {
    C::generator()
}

fn random_point<C: PastaCurve>(rng: &mut ChaCha20Rng) -> C {
    C::generator() * C::ScalarExt::random(rng)
}

fn random_limbs<C: PastaCurve>(rng: &mut ChaCha20Rng) -> [u128; 2] {
    limbs_of(&C::ScalarExt::random(rng))
}

/// The limbs of the scalar-field modulus `r` (`W = r` reads as zero).
fn modulus_as_limbs<S: PastaField>() -> [u128; 2] {
    let [lo, hi] = limbs_of(&-S::ONE);
    [lo + 1, hi]
}

/// The largest limbs (`W = 2^255 - 1`).
const MAX_LIMBS: [u128; 2] = [u128::MAX, (1 << 127) - 1];

// ---------------------------------------------------------------------------
// Programs
// ---------------------------------------------------------------------------

/// Scalar 0: a guarded multiplication of point 0 (may be `O`), then the
/// same split on point 1 (non-identity, unguarded).
fn mul_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let (lo, hi) = scalar_limbs(chips, region, inputs.scalar(0))?;
    let scalar = ScalarLimbs::new(&lo, &hi);
    let p = chips.ecc.witness_point(region, inputs.point(0))?;
    let (out, split) = chips.ecc.mul(region, &mut chips.range, scalar, &p)?;
    let q = chips.ecc.witness_non_identity(region, inputs.point(1))?;
    let out_q = chips.ecc.mul_non_identity_with(region, &split, &q)?;
    Ok([expose(&out), expose(&out_q)].concat())
}

/// Scalar 0 with the split forced to halves 0, on non-identity point 0.
fn forced_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let (lo, hi) = scalar_limbs(chips, region, inputs.scalar(0))?;
    let p = chips.ecc.witness_non_identity(region, inputs.point(0))?;
    let (out, _) = chips.ecc.mul_split(
        region,
        &mut chips.range,
        ScalarLimbs::new(&lo, &hi),
        p.point(),
        false,
        inputs.halves(0),
    )?;
    Ok(expose(&out).to_vec())
}

/// Scalar 0 with an honest split on non-identity point 0.
fn mul_non_identity_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let (lo, hi) = scalar_limbs(chips, region, inputs.scalar(0))?;
    let p = chips.ecc.witness_non_identity(region, inputs.point(0))?;
    let (out, _) =
        chips
            .ecc
            .mul_non_identity(region, &mut chips.range, ScalarLimbs::new(&lo, &hi), &p)?;
    Ok(expose(&out).to_vec())
}

/// Pairwise sums `p_{2i} + p_{2i+1}`, then the sum of every point.
fn add_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let values: Vec<_> = (0..inputs.points.len()).map(|i| inputs.point(i)).collect();
    let points = chips.ecc.witness_points(region, &values)?;
    let mut out = Vec::new();
    for pair in points.chunks(2) {
        if let [p, q] = pair {
            out.extend(expose(&chips.ecc.add(region, p, q)?));
        }
    }
    out.extend(expose(&chips.ecc.sum(region, &points)?));
    Ok(out)
}

/// The Horner chain of every point with scalar 0.
fn horner_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let (lo, hi) = scalar_limbs(chips, region, inputs.scalar(0))?;
    let values: Vec<_> = (0..inputs.points.len()).map(|i| inputs.point(i)).collect();
    let points = chips.ecc.witness_points(region, &values)?;
    let out = chips.ecc.horner(
        region,
        &mut chips.range,
        ScalarLimbs::new(&lo, &hi),
        &points,
    )?;
    Ok(expose(&out).to_vec())
}

/// `sum_i [W_i] P_i`.
fn msm_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let mut limbs = Vec::new();
    for index in 0..inputs.scalars.len() {
        limbs.push(scalar_limbs(chips, region, inputs.scalar(index))?);
    }
    let values: Vec<_> = (0..inputs.points.len()).map(|i| inputs.point(i)).collect();
    let points = chips.ecc.witness_points(region, &values)?;
    let terms: Vec<_> = limbs
        .iter()
        .zip(&points)
        .map(|((lo, hi), point)| (ScalarLimbs::new(lo, hi), point))
        .collect();
    let out = chips.ecc.msm(region, &mut chips.range, &terms)?;
    Ok(expose(&out).to_vec())
}

/// `[W_i] B` for every scalar and fixed base 0.
fn fixed_base_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let base = inputs
        .fixed
        .first()
        .and_then(FixedBase::new)
        .ok_or(Error::Synthesis)?;
    let mut out = Vec::new();
    for index in 0..inputs.scalars.len() {
        let (lo, hi) = scalar_limbs(chips, region, inputs.scalar(index))?;
        let product = chips
            .ecc
            .fixed_base_mul(region, &base, ScalarLimbs::new(&lo, &hi))?;
        out.extend(expose(&product));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Witness overrides (adversarial assignments)
// ---------------------------------------------------------------------------

/// An [`Assignment`] backend that forwards to `inner` and replaces the
/// listed advice cells.
struct Overriding<'o, F, A> {
    inner: A,
    overrides: &'o [(usize, usize, F)],
}

impl<F: PastaField, A: Assignment<F>> Assignment<F> for Overriding<'_, F, A> {
    fn enter_region(&mut self, name: String) -> Result<(), Error> {
        self.inner.enter_region(name)
    }

    fn exit_region(&mut self) -> Result<(), Error> {
        self.inner.exit_region()
    }

    fn annotate_column(&mut self, name: String, column: Column<Any>) {
        self.inner.annotate_column(name, column);
    }

    fn enable_selector(&mut self, selector: Selector, row: usize) -> Result<(), Error> {
        self.inner.enable_selector(selector, row)
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<F>, Error> {
        self.inner.query_instance(column, row)
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        let value = self
            .overrides
            .iter()
            .find(|(c, r, _)| *c == column.index() && *r == row)
            .map_or(value, |(_, _, forced)| {
                Value::known(Assigned::from(*forced))
            });
        self.inner.assign_advice(column, row, value)
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: Assigned<F>,
    ) -> Result<(), Error> {
        self.inner.assign_fixed(column, row, value)
    }

    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error> {
        self.inner.expect_fixed(column, row, value)
    }
    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.inner.reserve_advice(column, row)
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        self.inner
            .copy(left_column, left_row, right_column, right_row)
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.inner.fill_from_row(column, from_row, value)
    }

    fn push_namespace(&mut self, name: String) {
        self.inner.push_namespace(name);
    }

    fn pop_namespace(&mut self) {
        self.inner.pop_namespace();
    }
}

/// Checks `circuit` strictly with the listed advice cells replaced.
fn check_overridden<C: PastaCurve>(
    circuit: &TestCircuit<C>,
    k: u32,
    public: &[C::Base],
    overrides: &[(usize, usize, C::Base)],
) -> CheckReport<C::Base> {
    let (cs, config) = configure(circuit).expect("configure");
    let instances = [public.to_vec()];
    let mut backend = Overriding {
        inner: Assembly::new(&cs, k, Some(&instances[..])).expect("assembly"),
        overrides,
    };
    SimpleFloorPlanner::synthesize(&mut backend, circuit, config, cs.constants().to_vec())
        .expect("synthesis");
    let tables = backend.inner.finish().expect("tables");
    check(&cs, &tables, CheckMode::Strict).expect("check")
}

/// The gates (by name) with a failing or poisoned polynomial.
fn failing_gates<F: PastaField>(report: &CheckReport<F>) -> Vec<String> {
    let mut names: Vec<String> = report
        .failures()
        .iter()
        .filter_map(|failure| match failure {
            CheckFailure::ConstraintNotSatisfied { gate_name, .. }
            | CheckFailure::ConstraintPoisoned { gate_name, .. } => Some(gate_name.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The `+1` tampers of `cells` the strict checker misses (in parallel; the
/// result does not depend on the thread count).
fn undetected_among<C: PastaCurve>(
    circuit: &TestCircuit<C>,
    k: u32,
    public: &[C::Base],
    cells: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .max(1);
    let chunk = cells.len().div_ceil(threads).max(1);
    let instances = [public.to_vec()];
    let mut undetected: Vec<(usize, usize)> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in cells.chunks(chunk) {
            let instances = &instances;
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .copied()
                    .filter(|(column, row)| {
                        let tamper = Tamper {
                            column: *column,
                            row: *row,
                            delta: C::Base::ONE,
                        };
                        check_tampered(circuit, k, instances, Some(tamper))
                            .expect("tampered synthesis")
                            .is_satisfied()
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let mut found = Vec::new();
        for handle in handles {
            found.extend(handle.join().expect("tamper thread"));
        }
        found
    });
    undetected.sort_unstable();
    undetected
}

/// The assigned advice cells of `circuit` in `rows` (all columns).
fn assigned_in_rows<C: PastaCurve>(
    circuit: &TestCircuit<C>,
    k: u32,
    public: &[C::Base],
    rows: &[usize],
) -> Vec<(usize, usize)> {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    let flags = synthesized.tables.advice_assigned();
    let mut cells = Vec::new();
    for (column, assigned) in flags.iter().enumerate() {
        for row in rows {
            if assigned.get(*row).copied().unwrap_or(false) {
                cells.push((column, *row));
            }
        }
    }
    cells
}

// ---------------------------------------------------------------------------
// Exact integers for the lattice KAT
// ---------------------------------------------------------------------------

/// Limbs of the magnitude of [`Int`] (576 bits).
const INT_LIMBS: usize = 9;

/// A signed integer (sign and 576-bit magnitude) for the exact Gauss
/// reduction of the GLV lattices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Int {
    negative: bool,
    magnitude: [u64; INT_LIMBS],
}

/// The low 64 bits of `value`.
fn low_word(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(0)
}

/// `value` as an [`Int`].
fn int(value: u128) -> Int {
    Int::from_limbs([low_word(value), low_word(value >> 64), 0, 0])
}

fn magnitude_cmp(a: &[u64; INT_LIMBS], b: &[u64; INT_LIMBS]) -> Ordering {
    for (x, y) in a.iter().zip(b).rev() {
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

fn magnitude_add(a: &[u64; INT_LIMBS], b: &[u64; INT_LIMBS]) -> [u64; INT_LIMBS] {
    let mut out = [0; INT_LIMBS];
    let mut carry = 0_u128;
    for ((out, x), y) in out.iter_mut().zip(a).zip(b) {
        let sum = u128::from(*x) + u128::from(*y) + carry;
        *out = low_word(sum);
        carry = sum >> 64;
    }
    assert_eq!(carry, 0, "Int overflow");
    out
}

/// `a - b` for `a >= b`.
fn magnitude_sub(a: &[u64; INT_LIMBS], b: &[u64; INT_LIMBS]) -> [u64; INT_LIMBS] {
    let mut out = [0; INT_LIMBS];
    let mut borrow = false;
    for ((out, x), y) in out.iter_mut().zip(a).zip(b) {
        let (difference, first) = x.overflowing_sub(*y);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *out = difference;
        borrow = first || second;
    }
    assert!(!borrow, "magnitude underflow");
    out
}

fn magnitude_mul(a: &[u64; INT_LIMBS], b: &[u64; INT_LIMBS]) -> [u64; INT_LIMBS] {
    let mut wide = [0_u64; 2 * INT_LIMBS];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0_u128;
        for (j, y) in b.iter().enumerate() {
            let cell = u128::from(wide[i + j]) + u128::from(*x) * u128::from(*y) + carry;
            wide[i + j] = low_word(cell);
            carry = cell >> 64;
        }
        wide[i + INT_LIMBS] = low_word(carry);
    }
    assert!(
        wide[INT_LIMBS..].iter().all(|limb| *limb == 0),
        "Int overflow"
    );
    core::array::from_fn(|i| wide[i])
}

fn magnitude_bit(a: &[u64; INT_LIMBS], bit: usize) -> bool {
    (a[bit / 64] >> (bit % 64)) & 1 == 1
}

/// `(floor(a / b), a mod b)` for `b > 0` (shift and subtract).
fn magnitude_divrem(
    a: &[u64; INT_LIMBS],
    b: &[u64; INT_LIMBS],
) -> ([u64; INT_LIMBS], [u64; INT_LIMBS]) {
    let mut quotient = [0_u64; INT_LIMBS];
    let mut remainder = [0_u64; INT_LIMBS];
    for bit in (0..64 * INT_LIMBS).rev() {
        // remainder = 2 remainder + bit
        let mut carry = u64::from(magnitude_bit(a, bit));
        for limb in &mut remainder {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if magnitude_cmp(&remainder, b) != Ordering::Less {
            remainder = magnitude_sub(&remainder, b);
            quotient[bit / 64] |= 1 << (bit % 64);
        }
    }
    (quotient, remainder)
}

impl Int {
    const ZERO: Self = Self {
        negative: false,
        magnitude: [0; INT_LIMBS],
    };

    fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut magnitude = [0; INT_LIMBS];
        magnitude[..4].copy_from_slice(&limbs);
        Self {
            negative: false,
            magnitude,
        }
    }

    fn small(value: i64) -> Self {
        let mut magnitude = [0; INT_LIMBS];
        magnitude[0] = value.unsigned_abs();
        Self {
            negative: value < 0,
            magnitude,
        }
        .normalized()
    }

    fn normalized(self) -> Self {
        if self.magnitude == [0; INT_LIMBS] {
            Self::ZERO
        } else {
            self
        }
    }

    fn is_zero(&self) -> bool {
        self.magnitude == [0; INT_LIMBS]
    }

    fn neg(self) -> Self {
        Self {
            negative: !self.negative,
            magnitude: self.magnitude,
        }
        .normalized()
    }

    fn add(self, other: Self) -> Self {
        if self.negative == other.negative {
            return Self {
                negative: self.negative,
                magnitude: magnitude_add(&self.magnitude, &other.magnitude),
            }
            .normalized();
        }
        match magnitude_cmp(&self.magnitude, &other.magnitude) {
            Ordering::Less => Self {
                negative: other.negative,
                magnitude: magnitude_sub(&other.magnitude, &self.magnitude),
            },
            _ => Self {
                negative: self.negative,
                magnitude: magnitude_sub(&self.magnitude, &other.magnitude),
            },
        }
        .normalized()
    }

    fn sub(self, other: Self) -> Self {
        self.add(other.neg())
    }

    fn mul(self, other: Self) -> Self {
        Self {
            negative: self.negative != other.negative,
            magnitude: magnitude_mul(&self.magnitude, &other.magnitude),
        }
        .normalized()
    }

    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => magnitude_cmp(&self.magnitude, &other.magnitude),
            (true, true) => magnitude_cmp(&other.magnitude, &self.magnitude),
        }
    }

    /// `floor(self / divisor)` for `divisor > 0`.
    fn floor_div(self, divisor: Self) -> Self {
        assert!(!divisor.negative && !divisor.is_zero());
        let (quotient, remainder) = magnitude_divrem(&self.magnitude, &divisor.magnitude);
        let quotient = Self {
            negative: false,
            magnitude: quotient,
        };
        if self.negative {
            let quotient = quotient.neg();
            if remainder == [0; INT_LIMBS] {
                quotient
            } else {
                quotient.sub(Self::small(1))
            }
        } else {
            quotient
        }
    }

    /// The magnitude when it fits a `u128`.
    fn magnitude_u128(&self) -> Option<u128> {
        self.magnitude[2..]
            .iter()
            .all(|limb| *limb == 0)
            .then(|| u128::from(self.magnitude[0]) | (u128::from(self.magnitude[1]) << 64))
    }

    /// The low 256 bits of the magnitude.
    fn low_limbs(&self) -> [u64; 4] {
        [
            self.magnitude[0],
            self.magnitude[1],
            self.magnitude[2],
            self.magnitude[3],
        ]
    }

    /// `self` as an element of `F` (signed).
    fn to_field<F: PastaField>(self) -> F {
        assert!(self.magnitude[4..].iter().all(|limb| *limb == 0));
        let value = F::from_raw_reduced(self.low_limbs());
        if self.negative { -value } else { value }
    }

    fn shr(self, bits: usize) -> Self {
        assert!(!self.negative);
        let mut magnitude = [0_u64; INT_LIMBS];
        for bit in bits..64 * INT_LIMBS {
            if magnitude_bit(&self.magnitude, bit) {
                magnitude[(bit - bits) / 64] |= 1 << ((bit - bits) % 64);
            }
        }
        Self {
            negative: false,
            magnitude,
        }
        .normalized()
    }

    fn is_odd(&self) -> bool {
        self.magnitude[0] & 1 == 1
    }
}

type Vector = (Int, Int);

fn dot(u: &Vector, v: &Vector) -> Int {
    u.0.mul(v.0).add(u.1.mul(v.1))
}

/// A Gauss/Lagrange-reduced basis of `{(x, y) : x + lambda y = 0 mod r}`.
fn reduced_basis(r: [u64; 4], lambda: [u64; 4]) -> (Vector, Vector) {
    let r = Int::from_limbs(r);
    let lambda = Int::from_limbs(lambda);
    let mut u = (r, Int::ZERO);
    let mut v = (r.sub(lambda), Int::small(1));
    loop {
        if dot(&u, &u).cmp(&dot(&v, &v)) == Ordering::Greater {
            core::mem::swap(&mut u, &mut v);
        }
        let numerator = dot(&u, &v);
        let denominator = dot(&u, &u);
        // m = round(numerator / denominator)
        let m = numerator
            .mul(Int::small(2))
            .add(denominator)
            .floor_div(denominator.mul(Int::small(2)));
        if m.is_zero() {
            return (u, v);
        }
        v = (v.0.sub(m.mul(u.0)), v.1.sub(m.mul(u.1)));
    }
}

/// The lattice vectors `a u + b v` for `|a|, |b| <= span`, nonzero.
fn small_combinations(basis: &(Vector, Vector), span: i64) -> Vec<Vector> {
    let (u, v) = basis;
    let mut out = Vec::new();
    for a in -span..=span {
        for b in -span..=span {
            if a == 0 && b == 0 {
                continue;
            }
            let (a, b) = (Int::small(a), Int::small(b));
            out.push((a.mul(u.0).add(b.mul(v.0)), a.mul(u.1).add(b.mul(v.1))));
        }
    }
    out
}

fn sup_norm(vector: &Vector) -> u128 {
    let x = vector.0.magnitude_u128().unwrap_or(u128::MAX);
    let y = vector.1.magnitude_u128().unwrap_or(u128::MAX);
    x.max(y)
}

fn scalar_modulus<S: PastaField>() -> [u64; 4] {
    let mut limbs = (-S::ONE).to_canonical_limbs();
    limbs[0] += 1;
    limbs
}

/// The GLV lattice basis of curve `C` (for its `zeta`).
fn glv_basis<C: PastaCurve>() -> (Vector, Vector) {
    reduced_basis(
        scalar_modulus::<C::ScalarExt>(),
        zeta::<C>().to_canonical_limbs(),
    )
}

/// The exact sup-norm minimum of the GLV lattice of `C` (a reduced basis has
/// its sup-norm minimum among combinations with coefficients of size at most
/// 2; the search spans 4).
fn sup_norm_minimum<C: PastaCurve>() -> u128 {
    let basis = glv_basis::<C>();
    for vector in [&basis.0, &basis.1] {
        let value =
            vector.0.to_field::<C::ScalarExt>() + zeta::<C>() * vector.1.to_field::<C::ScalarExt>();
        assert_eq!(value, C::ScalarExt::ZERO, "basis vector in the lattice");
    }
    small_combinations(&basis, 4)
        .iter()
        .map(sup_norm)
        .min()
        .expect("vectors")
}

// ---------------------------------------------------------------------------
// M3 named tests
// ---------------------------------------------------------------------------

/// The sup-norm minima computed by `glv_lattice.py` (Gauss reduction).
const SUP_NORM_MINIMUM_FP: u128 = 98_231_058_071_186_745_657_228_807_397_848_383_488;
const SUP_NORM_MINIMUM_FQ: u128 = 98_231_058_071_186_745_657_228_807_397_848_383_489;

#[test]
fn glv_lattice_sup_norm_minimum_pallas_vesta() {
    // Vesta points have Fp scalars (Q, Omega); Pallas points Fq scalars (A).
    let vesta = sup_norm_minimum::<Eq>();
    let pallas = sup_norm_minimum::<Ep>();
    assert_eq!(vesta, SUP_NORM_MINIMUM_FP);
    assert_eq!(pallas, SUP_NORM_MINIMUM_FQ);
    for minimum in [vesta, pallas] {
        // 1.1484 2^126 < s < 1.15625 2^126, so log2(s) is 126.21 to two
        // decimals (126.2075).
        assert!(minimum > (1 << 126) + (1 << 123) + (1 << 120) + (1 << 119));
        assert!(minimum < (1 << 126) + (1 << 123) + (1 << 121));
        // The chip's incomplete iterations are exactly those the bound
        // allows: iteration j is safe iff 6 2^j - 1 < s.
        let last = GLV_INCOMPLETE_ITERATIONS - 1;
        assert!(6 * (1_u128 << last) - 1 < minimum);
        assert!(6 * (1_u128 << GLV_INCOMPLETE_ITERATIONS) > minimum);
    }
    // The other cube root gives the same lattice (up to the sign of y).
    let other = reduced_basis(
        scalar_modulus::<Fp>(),
        (zeta::<Eq>() * zeta::<Eq>()).to_canonical_limbs(),
    );
    assert_eq!(
        small_combinations(&other, 4).iter().map(sup_norm).min(),
        Some(SUP_NORM_MINIMUM_FP)
    );
}

fn glv_mul_parity<C: PastaCurve>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let k = 10;
    let g = C::generator();
    let scalars = [
        random_limbs::<C>(&mut rng),
        [0, 0],
        [1, 0],
        limbs_of(&-C::ScalarExt::ONE),
        limbs_of(&zeta::<C>()),
        [0, 1],
        modulus_as_limbs::<C::ScalarExt>(),
        MAX_LIMBS,
        limbs_of(&-C::Base::ONE),
    ];
    let bases = [
        (random_point::<C>(&mut rng), random_point::<C>(&mut rng)),
        (C::identity(), g),
        (g, g.endo()),
        (-g.endo().endo(), random_point::<C>(&mut rng)),
    ];
    for (index, scalar) in scalars.iter().enumerate() {
        let (p, q) = bases[index % bases.len()];
        let inputs = Inputs::new(vec![p, q], vec![*scalar]);
        let expected = [mul_native(&p, *scalar), mul_native(&q, *scalar)];
        let public = public_of(&expected);
        let circuit = TestCircuit::new(mul_program::<C>, inputs, public.len());
        assert_accepts(&circuit, k, &public);
        // A wrong public result is rejected.
        let mut wrong = public.clone();
        wrong[1] += C::Base::ONE;
        assert!(!check_report(&circuit, k, &wrong).is_satisfied());
    }
}

#[test]
fn glv_mul_matches_native_pallas() {
    glv_mul_parity::<Ep>(1);
}

#[test]
fn glv_mul_matches_native_vesta() {
    glv_mul_parity::<Eq>(2);
}

/// Positions of the forced-split program's cells (ECC rows: the point at
/// row 0, the split at rows 1..=3, the chain from row 4).
struct ForcedLayout {
    split: usize,
    chain: usize,
    /// First rows of the split's range checks of `u_lo`, `u_hi`, `v`.
    range_rows: [usize; 3],
}

fn forced_layout() -> ForcedLayout {
    let limb_bits = LimbBits::new(8).expect("limb bits");
    let rows = |bits: usize| RangeShape::new(bits, limb_bits).expect("shape").rows;
    // Scalar limbs (128 and 127 bits), then h0 and h1.
    let u_low = rows(128) + rows(127) + rows(8) + rows(119);
    let u_high = u_low + rows(64);
    let v = u_high + rows(66);
    ForcedLayout {
        split: 1,
        chain: 4,
        range_rows: [u_low, u_high, v],
    }
}

/// The overrides that lay out the split `K1, K2` (integers, possibly out of
/// range) consistently in the split rows, the range checks of `u` and `v`
/// and the chain's running sums (`Y_0` kept at zero when `keep_start`); the
/// chain's points stay those of the honest digits.
fn split_overrides<C: PastaCurve>(
    limbs: [u128; 2],
    k: [Int; 2],
    keep_start: bool,
) -> Vec<(usize, usize, C::Base)> {
    let layout = forced_layout();
    let [k1, k2] = k;
    let b = [k1.shr(1), k2.shr(1)];
    let f = [k1.is_odd(), k2.is_odd()].map(|bit| if bit { C::Base::ONE } else { C::Base::ZERO });
    let b2_high = b[1].shr(63).to_field::<C::Base>();
    let witness = split_witness_fields::<C>(limbs, [k1.to_field(), k2.to_field()], b2_high);
    let mut out = vec![
        (0, layout.split, f[0]),
        (1, layout.split, b[0].to_field()),
        (2, layout.split, f[1]),
        (3, layout.split, b[1].to_field()),
        (0, layout.split + 1, witness.b2_high),
        (1, layout.split + 2, witness.u_low),
        (2, layout.split + 2, witness.u_high),
        (3, layout.split + 2, witness.v_shifted),
    ];
    let limb_bits = LimbBits::new(8).expect("limb bits");
    for ((value, bits), start) in [
        (witness.u_low, 64),
        (witness.u_high, 66),
        (witness.v_shifted, 68),
    ]
    .into_iter()
    .zip(layout.range_rows)
    {
        let shape = RangeShape::new(bits, limb_bits).expect("shape");
        for (offset, entry) in running_sum_witness(&value, shape).into_iter().enumerate() {
            out.push((RANGE_COLUMN, start + offset, entry));
        }
    }
    for (column, half) in [(2, b[0]), (3, b[1])] {
        for j in 0..=GLV_ITERATIONS {
            let prefix = if j == 0 && keep_start {
                C::Base::ZERO
            } else {
                half.shr(GLV_ITERATIONS - j).to_field()
            };
            out.push((column, layout.chain + 1 + j, prefix));
        }
    }
    out.push((2, layout.chain + GLV_ITERATIONS + 2, f[0]));
    out.push((3, layout.chain + GLV_ITERATIONS + 2, f[1]));
    out
}

/// A lattice vector with both components positive (the shortest such).
fn positive_lattice_vector<C: PastaCurve>() -> (u128, u128) {
    small_combinations(&glv_basis::<C>(), 4)
        .iter()
        .filter(|(x, y)| !x.negative && !y.negative && !x.is_zero() && !y.is_zero())
        .filter_map(|(x, y)| Some((x.magnitude_u128()?, y.magnitude_u128()?)))
        .min_by_key(|(x, y)| (*x).max(*y))
        .expect("positive lattice vector")
}

fn halves_out_of_range<C: PastaCurve>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    // Natively, the split's halves are always below 2^128 in magnitude.
    for _ in 0..500 {
        let halves = glv_halves::<C>(&C::ScalarExt::random(&mut rng)).expect("split");
        let signed = halves.signed_halves().expect("|k| < 2^128");
        assert!(
            signed
                .iter()
                .all(|(_, magnitude)| *magnitude < (1 << 127) + (1 << 126))
        );
    }
    let k = 10;
    let point = random_point::<C>(&mut rng);
    let limbs = random_limbs::<C>(&mut rng);
    let halves = glv_halves::<C>(&scalar_from_limbs(limbs)).expect("split");
    let mut inputs = Inputs::new(vec![point], vec![limbs]);
    inputs.halves.push(halves);
    let public = public_of(&[mul_native(&point, limbs)]);
    let circuit = TestCircuit::new(forced_program::<C>, inputs, public.len());
    assert_accepts(&circuit, k, &public);
    // The honest split laid out through the overrides is accepted too.
    let half = |b: u128, f: bool| int(b).mul(Int::small(2)).add(Int::small(i64::from(f)));
    let honest = [half(halves.b1, halves.f1), half(halves.b2, halves.f2)];
    let report = check_overridden(
        &circuit,
        k,
        &public,
        &split_overrides::<C>(limbs, honest, true),
    );
    assert!(report.is_satisfied(), "{report}");
    // K' = K + t w for a positive lattice vector w is another split of the
    // same scalar; take t so that a half reaches 2^128 (K' >= 2^129).
    let (w1, w2) = positive_lattice_vector::<C>();
    let w = [int(w1), int(w2)];
    let limit = Int::from_limbs([0, 0, 2, 0]); // 2^129
    let mut wide = honest;
    while wide[0].cmp(&limit) == Ordering::Less && wide[1].cmp(&limit) == Ordering::Less {
        wide = [wide[0].add(w[0]), wide[1].add(w[1])];
    }
    // Same scalar modulo r.
    let value = |k: [Int; 2]| {
        let two_128 = two_pow_128::<C::ScalarExt>();
        (two_128 + k[0].to_field::<C::ScalarExt>())
            + zeta::<C>() * (two_128 + k[1].to_field::<C::ScalarExt>())
    };
    assert_eq!(value(wide), value(honest));
    for keep_start in [false, true] {
        let report = check_overridden(
            &circuit,
            k,
            &public,
            &split_overrides::<C>(limbs, wide, keep_start),
        );
        assert!(!report.is_satisfied(), "a half >= 2^128 was accepted");
        let gates = failing_gates(&report);
        // The split identity itself holds (the CRT check accepts the
        // alternative split); the chain's 128-bit running sums reject it.
        assert!(
            !gates.iter().any(|gate| gate == "ecc glv split"),
            "{gates:?}"
        );
        let expected = if keep_start {
            "ecc glv incomplete double-and-add"
        } else {
            "ecc glv init"
        };
        assert!(gates.iter().any(|gate| gate == expected), "{gates:?}");
    }
    // A forced in-range split of a different scalar is rejected by the
    // split check.
    let mut other = halves;
    other.b1 ^= 1 << 40;
    let mut inputs = Inputs::new(vec![point], vec![limbs]);
    inputs.halves.push(other);
    let circuit = TestCircuit::new(forced_program::<C>, inputs, public.len());
    let public_other = public_of(&[point * other.scalar::<C>()]);
    let report = check_report(&circuit, k, &public_other);
    assert!(
        failing_gates(&report)
            .iter()
            .any(|gate| gate == "ecc glv split"),
        "{report}"
    );
}

#[test]
fn glv_split_rejects_halves_ge_2_128() {
    halves_out_of_range::<Ep>(3);
    halves_out_of_range::<Eq>(4);
}

/// The lattice vector with both components odd and in
/// `[2^126 + 1, 3 2^126 - 1]`: the values `2 a_125 + d` can take, so the
/// one vector that makes iteration 125 exceptional (`2 acc + T = O`).
fn exceptional_vector<C: PastaCurve>() -> (u128, u128) {
    let low = (1_u128 << 126) + 1;
    let high = 3 * (1_u128 << 126) - 1;
    let hits: Vec<(u128, u128)> = small_combinations(&glv_basis::<C>(), 8)
        .iter()
        .filter(|(x, y)| !x.negative && !y.negative && x.is_odd() && y.is_odd())
        .filter_map(|(x, y)| Some((x.magnitude_u128()?, y.magnitude_u128()?)))
        .filter(|(x, y)| (low..=high).contains(x) && (low..=high).contains(y))
        .collect();
    assert_eq!(hits.len(), 1, "{hits:?}");
    hits[0]
}

/// Digit words that steer the accumulator to the exceptional case of
/// iteration 125 for the component `w` of [`exceptional_vector`]:
/// `a_125 = (w - d) / 2` odd, `Y_125 = (a_125 - 2^125 - 1) / 2` (the top
/// 125 bits) and the digit `d` of iteration 125 (bit 2).
fn exceptional_digits(w: u128, low: u128) -> u128 {
    let (a, d) = if ((w - 1) / 2) % 2 == 1 {
        ((w - 1) / 2, 1)
    } else {
        (w.div_ceil(2), -1)
    };
    let prefix = (a - (1 << 125) - 1) / 2;
    let bit = u128::from(d == 1);
    (prefix << 3) | (bit << 2) | (low & 0b11)
}

fn adversarial_bases<C: PastaCurve>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g = C::generator();
    let bases = [
        g,
        -g,
        g.endo(),
        g.endo().endo(),
        g.double(),
        g + g.endo(),
        g - g.endo(),
        random_point::<C>(&mut rng),
        random_point::<C>(&mut rng),
    ];
    let mut digit_words = vec![
        0_u128,
        u128::MAX,
        0x5555_5555_5555_5555_5555_5555_5555_5555,
        0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
        1 << 127,
        (1 << 127) - 1,
    ];
    digit_words.extend((0..6).map(|_| random_limbs::<C>(&mut rng)[0]));
    // Every incomplete iteration of every base and digit sequence is
    // exception-free (`chain_witness` fails on a zero denominator), and the
    // chain computes the split's scalar.
    for base in &bases {
        for (index, b1) in digit_words.iter().enumerate() {
            let b2 = digit_words[(index * 5 + 3) % digit_words.len()];
            for (f1, f2) in [(false, false), (true, false), (false, true), (true, true)] {
                let halves = GlvHalves {
                    b1: *b1,
                    f1,
                    b2,
                    f2,
                };
                let witness = chain_witness::<C>(coordinates(base), &halves)
                    .expect("no exceptional incomplete step");
                assert_eq!(witness.output, coordinates(&(*base * halves.scalar::<C>())));
            }
        }
    }
    // The bound is tight in kind: digits steered by the shortest positive
    // lattice vector make iteration 125 (complete) exceptional, `2 acc + T =
    // O`; the complete tail absorbs it.
    let (w1, w2) = exceptional_vector::<C>();
    let steered = GlvHalves {
        b1: exceptional_digits(w1, 0b01),
        f1: true,
        b2: exceptional_digits(w2, 0b10),
        f2: false,
    };
    let k = 10;
    for base in [bases[0], bases[7]] {
        let witness = chain_witness::<C>(coordinates(&base), &steered).expect("chain");
        // Iteration 125 is the second complete iteration: adds 2 and 3.
        assert_eq!(
            witness.adds[3].output,
            (C::Base::ZERO, C::Base::ZERO),
            "2 acc_125 + T_125 = O"
        );
        let expected = base * steered.scalar::<C>();
        assert_eq!(witness.output, coordinates(&expected));
        let limbs = limbs_of(&steered.scalar::<C>());
        let mut inputs = Inputs::new(vec![base], vec![limbs]);
        inputs.halves.push(steered);
        let public = public_of(&[expected]);
        let circuit = TestCircuit::new(forced_program::<C>, inputs, public.len());
        assert_accepts(&circuit, k, &public);
    }
    // Adversarial (valid, non-canonical) splits are accepted in circuit.
    for (base, b1) in bases.iter().zip(&digit_words).take(4) {
        let halves = GlvHalves {
            b1: *b1,
            f1: b1 & 1 == 0,
            b2: b1.rotate_left(17),
            f2: true,
        };
        let limbs = limbs_of(&halves.scalar::<C>());
        let mut inputs = Inputs::new(vec![*base], vec![limbs]);
        inputs.halves.push(halves);
        let public = public_of(&[*base * halves.scalar::<C>()]);
        let circuit = TestCircuit::new(forced_program::<C>, inputs, public.len());
        assert_accepts(&circuit, k, &public);
    }
}

#[test]
fn glv_incomplete_iterations_never_exceptional_on_adversarial_bases() {
    // The analytic bound: iteration j reads vectors of sup-norm at most
    // 6 2^j - 1, below the sup-norm minimum for j <= 123.
    for minimum in [sup_norm_minimum::<Ep>(), sup_norm_minimum::<Eq>()] {
        for j in 0..GLV_INCOMPLETE_ITERATIONS {
            assert!(6 * (1_u128 << j) - 1 < minimum, "iteration {j}");
        }
    }
    adversarial_bases::<Ep>(5);
    adversarial_bases::<Eq>(6);
}

fn add_cases<C: PastaCurve>(seed: u64) -> (TestCircuit<C>, Vec<C::Base>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let o = C::identity();
    let p = random_point::<C>(&mut rng);
    let q = random_point::<C>(&mut rng);
    let pairs = [
        (o, o),
        (o, p),
        (p, o),
        (p, p),
        (p, -p),
        (p, q),
        (p, p.endo()),
        (p, -p.endo()),
    ];
    let points: Vec<C> = pairs.iter().flat_map(|(a, b)| [*a, *b]).collect();
    let mut expected: Vec<C> = pairs.iter().map(|(a, b)| *a + *b).collect();
    expected.push(points.iter().fold(o, |acc, point| acc + *point));
    let public = public_of(&expected);
    let circuit = TestCircuit::new(
        add_program::<C>,
        Inputs::new(points, Vec::new()),
        public.len(),
    );
    (circuit, public)
}

#[test]
fn complete_add_handles_identity_equal_opposite() {
    let k = 9;
    let (pallas, public) = add_cases::<Ep>(7);
    assert_accepts(&pallas, k, &public);
    let (vesta, public_vesta) = add_cases::<Eq>(8);
    assert_accepts(&vesta, k, &public_vesta);
    // Every cell of every case is pinned (the inverse witnesses and the
    // slope included).
    let cells = crate::tamper::assigned_advice_cells(&pallas, k, core::slice::from_ref(&public))
        .expect("cells");
    assert_eq!(
        undetected_among(&pallas, k, &public, &cells),
        Vec::<(usize, usize)>::new()
    );
}

fn horner_cases<C: PastaCurve>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let o = C::identity();
    let [p0, p1, p2] = [(); 3].map(|()| random_point::<C>(&mut rng));
    let x = random_limbs::<C>(&mut rng);
    let cases = [
        (vec![p0, p1, p2], x),
        (vec![o, p1, p2], x),
        (vec![p0, o, p2], x),
        (vec![p0, p1, o], x),
        (vec![o, o, o], x),
        (vec![p0, -p1, p1], [1, 0]),
        (vec![p0, p1, p2], [0, 0]),
        (vec![p2], x),
    ];
    for (points, x) in cases {
        let expected = horner_native(&points, x);
        // Independently: sum_i P_i x^i.
        let scalar = scalar_from_limbs::<C::ScalarExt>(x);
        let mut power = C::ScalarExt::ONE;
        let mut msm = o;
        for point in &points {
            msm += *point * power;
            power *= scalar;
        }
        assert_eq!(expected, msm);
        let public = public_of(&[expected]);
        let circuit = TestCircuit::new(
            horner_program::<C>,
            Inputs::new(points, vec![x]),
            public.len(),
        );
        assert_accepts(&circuit, 10, &public);
    }
}

#[test]
fn identity_guarded_horner_matches_native_msm() {
    horner_cases::<Ep>(9);
    horner_cases::<Eq>(10);
}

fn fixed_base_cases<C: PastaCurve>(seed: u64) -> (TestCircuit<C>, Vec<C::Base>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let base = random_point::<C>(&mut rng);
    let scalars = vec![
        random_limbs::<C>(&mut rng),
        [0, 0],
        [1, 0],
        MAX_LIMBS,
        limbs_of(&-C::ScalarExt::ONE),
        modulus_as_limbs::<C::ScalarExt>(),
        [u128::MAX, 0],
        [0, 1],
    ];
    let expected: Vec<C> = scalars
        .iter()
        .map(|limbs| mul_native(&base, *limbs))
        .collect();
    let public = public_of(&expected);
    let mut inputs = Inputs::new(Vec::new(), scalars);
    inputs.fixed.push(base);
    (
        TestCircuit::new(fixed_base_program::<C>, inputs, public.len()),
        public,
    )
}

#[test]
fn fixed_base_mul_matches_native() {
    let k = 10;
    let (pallas, public) = fixed_base_cases::<Ep>(11);
    assert_accepts(&pallas, k, &public);
    let (vesta, public) = fixed_base_cases::<Eq>(12);
    assert_accepts(&vesta, k, &public);
    let mut wrong = public.clone();
    wrong[0] += Fq::ONE;
    assert!(!check_report(&vesta, k, &wrong).is_satisfied());
}

// ---------------------------------------------------------------------------
// Further tests
// ---------------------------------------------------------------------------

#[test]
fn identity_encoding_is_sound() {
    // 5 is not a square in either field: no curve point has x = 0.
    assert!(bool::from(Fp::from(5).sqrt().is_none()));
    assert!(bool::from(Fq::from(5).sqrt().is_none()));
    assert!(!on_curve::<Ep>((Fp::ZERO, Fp::ZERO)));
    assert!(on_curve::<Eq>(coordinates(&generator::<Eq>())));
}

fn endomorphism_case<C: PastaCurve>() {
    let g = C::generator();
    assert_eq!(g.endo(), g * zeta::<C>());
    let (x, y) = coordinates(&g);
    assert_eq!(coordinates(&g.endo()), (beta::<C>() * x, y));
    // S+ = P + phi(P) = (beta^2 x, -y).
    assert_eq!(coordinates(&(g + g.endo())), (beta::<C>().square() * x, -y));
}

#[test]
fn endomorphism_constants_match_zeta() {
    endomorphism_case::<Ep>();
    endomorphism_case::<Eq>();
}

fn split_constants_case<C: PastaCurve>() {
    let constants = SplitConstants::<C::Base>::new::<C>();
    let lambda = limbs_of(&zeta::<C>());
    assert_eq!(
        constants.lambda_72,
        C::Base::from_u128(lambda[0] & ((1 << 72) - 1))
    );
    assert_eq!(
        constants.lambda_136,
        C::Base::from_u128(lambda[0])
            + C::Base::from_u128(lambda[1] & 0xff) * two_pow_128::<C::Base>()
    );
    let modulus = modulus_as_limbs::<C::ScalarExt>();
    assert_eq!(
        constants.modulus,
        C::Base::from_u128(modulus[0]) + C::Base::from_u128(modulus[1]) * two_pow_128::<C::Base>()
    );
}

#[test]
fn split_constants_are_the_low_limbs() {
    split_constants_case::<Ep>();
    split_constants_case::<Eq>();
}

#[test]
fn ecc_gates_have_degree_at_most_six() {
    for fixed_base in [false, true] {
        let mut meta = ConstraintSystem::<Fp>::new();
        let advice = core::array::from_fn(|_| meta.advice_column());
        let _ = if fixed_base {
            EccConfig::<Ep>::configure_with_fixed_base(&mut meta, advice)
        } else {
            EccConfig::<Ep>::configure(&mut meta, advice)
        };
        assert!(meta.degree() <= MAX_GATE_DEGREE, "degree {}", meta.degree());
        let mut meta = ConstraintSystem::<Fq>::new();
        let advice = core::array::from_fn(|_| meta.advice_column());
        let _ = EccConfig::<Eq>::configure_with_fixed_base(&mut meta, advice);
        assert!(meta.degree() <= MAX_GATE_DEGREE);
    }
}

#[test]
fn on_curve_checks_reject_off_curve_points() {
    let k = 9;
    let (circuit, public) = add_cases::<Ep>(12);
    // Row 0 holds the pair (O, O) in a0, a1 and a2, a3: shifting the second
    // y makes (0, 1), neither on the curve nor the identity.
    let synthesized = synthesize(&circuit, k, Some(&[public.clone()][..])).expect("synthesis");
    let advice = synthesized.tables.advice().expect("advice").to_vec();
    let y = advice[3][0];
    let report = check_overridden(&circuit, k, &public, &[(3, 0, y + Fp::ONE)]);
    assert!(
        failing_gates(&report)
            .iter()
            .any(|gate| gate == "ecc on curve or identity")
    );
    // A non-identity witness of the identity has no satisfying assignment.
    let inputs = Inputs::new(vec![identity::<Eq>()], vec![[5, 0]]);
    let circuit = TestCircuit::new(mul_non_identity_program::<Eq>, inputs, 2);
    let public = public_of(&[identity::<Eq>()]);
    let report = check_report(&circuit, 10, &public);
    assert!(
        failing_gates(&report)
            .iter()
            .any(|gate| gate == "ecc on curve"),
        "{report}"
    );
}

/// The rows of one guarded multiplication of `mul_program` worth tampering:
/// the split, the init row, the first incomplete rows, the `B2_hi` row, the
/// last incomplete rows, the complete iterations, the correction, every
/// addition and the guard.
fn sampled_glv_rows() -> Vec<usize> {
    // Row 0: the input point; rows 1..=3: the split; the chain from row 4.
    let chain = 4;
    let mut rows = vec![
        1,
        2,
        3,
        chain,
        chain + 1,
        chain + 2,
        chain + 1 + GLV_B2_HIGH_PREFIX,
    ];
    rows.extend(chain + GLV_INCOMPLETE_ITERATIONS..=chain + GLV_GUARDED_CHAIN_ROWS);
    rows
}

#[test]
fn every_sampled_glv_cell_is_pinned() {
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let k = 10;
    let p = random_point::<Eq>(&mut rng);
    let q = random_point::<Eq>(&mut rng);
    let limbs = random_limbs::<Eq>(&mut rng);
    let public = public_of(&[mul_native(&p, limbs), mul_native(&q, limbs)]);
    let circuit = TestCircuit::new(
        mul_program::<Eq>,
        Inputs::new(vec![p, q], vec![limbs]),
        public.len(),
    );
    assert_accepts(&circuit, k, &public);
    let mut rows = sampled_glv_rows();
    // The split's range checks (u and v) in the range column.
    rows.sort_unstable();
    let cells: Vec<_> = assigned_in_rows(&circuit, k, &public, &rows)
        .into_iter()
        .filter(|(column, _)| ECC_COLUMNS.contains(column))
        .collect();
    assert!(cells.len() > 150, "{}", cells.len());
    assert_eq!(
        undetected_among(&circuit, k, &public, &cells),
        Vec::<(usize, usize)>::new()
    );
}

#[test]
fn every_identity_guard_cell_is_pinned() {
    let mut rng = ChaCha20Rng::seed_from_u64(14);
    let k = 10;
    let q = random_point::<Ep>(&mut rng);
    let limbs = random_limbs::<Ep>(&mut rng);
    let public = public_of(&[identity::<Ep>(), mul_native(&q, limbs)]);
    let circuit = TestCircuit::new(
        mul_program::<Ep>,
        Inputs::new(vec![identity::<Ep>(), q], vec![limbs]),
        public.len(),
    );
    assert_accepts(&circuit, k, &public);
    let chain = 4;
    let rows = [
        0,
        chain,
        chain + 1,
        chain + GLV_CHAIN_ROWS,
        chain + GLV_GUARDED_CHAIN_ROWS,
    ];
    let cells: Vec<_> = assigned_in_rows(&circuit, k, &public, &rows)
        .into_iter()
        .filter(|(column, _)| ECC_COLUMNS.contains(column))
        .collect();
    assert_eq!(
        undetected_among(&circuit, k, &public, &cells),
        Vec::<(usize, usize)>::new()
    );
}

#[test]
fn every_sampled_fixed_base_cell_is_pinned() {
    let k = 10;
    let (circuit, public) = fixed_base_cases::<Ep>(15);
    // The first multiplication starts at row 0: link rows 0, 1; windows at
    // rows 2..=86; the addition at 87 and the result at 88.
    let rows = [0, 1, 2, 3, 4, 2 + 42, 2 + 43, 2 + 83, 2 + 84, 87, 88];
    let cells: Vec<_> = assigned_in_rows(&circuit, k, &public, &rows)
        .into_iter()
        .filter(|(column, _)| ECC_COLUMNS.contains(column))
        .collect();
    assert!(cells.len() > 40);
    assert_eq!(
        undetected_among(&circuit, k, &public, &cells),
        Vec::<(usize, usize)>::new()
    );
}

#[test]
fn msm_matches_native() {
    let mut rng = ChaCha20Rng::seed_from_u64(16);
    let points = vec![
        random_point::<Eq>(&mut rng),
        identity::<Eq>(),
        random_point::<Eq>(&mut rng),
    ];
    let scalars = vec![
        random_limbs::<Eq>(&mut rng),
        random_limbs::<Eq>(&mut rng),
        [0, 0],
    ];
    let expected = points
        .iter()
        .zip(&scalars)
        .fold(identity::<Eq>(), |acc, (point, limbs)| {
            acc + mul_native(point, *limbs)
        });
    let public = public_of(&[expected]);
    let circuit = TestCircuit::new(
        msm_program::<Eq>,
        Inputs::new(points, scalars),
        public.len(),
    );
    assert_accepts(&circuit, 10, &public);
}

#[test]
fn glv_chain_rejects_a_wrong_slope_and_a_wrong_digit() {
    let mut rng = ChaCha20Rng::seed_from_u64(17);
    let k = 10;
    let point = random_point::<Ep>(&mut rng);
    let limbs = random_limbs::<Ep>(&mut rng);
    let halves = glv_halves::<Ep>(&scalar_from_limbs(limbs)).expect("split");
    let mut inputs = Inputs::new(vec![point], vec![limbs]);
    inputs.halves.push(halves);
    let public = public_of(&[mul_native(&point, limbs)]);
    let circuit = TestCircuit::new(forced_program::<Ep>, inputs, public.len());
    assert_accepts(&circuit, k, &public);
    let synthesized = synthesize(&circuit, k, Some(&[public.clone()][..])).expect("synthesis");
    let advice = synthesized.tables.advice().expect("advice").to_vec();
    let row = forced_layout().chain + 50;
    // A wrong lambda_1.
    let report = check_overridden(&circuit, k, &public, &[(4, row, advice[4][row] + Fp::ONE)]);
    assert!(
        failing_gates(&report)
            .iter()
            .any(|gate| gate == "ecc glv incomplete double-and-add")
    );
    // Flipping one digit everywhere consistently changes the result: a
    // different split fails the split check against the scalar.
    let mut flipped = halves;
    flipped.b2 ^= 1 << 77;
    let mut inputs = Inputs::new(vec![point], vec![limbs]);
    inputs.halves.push(flipped);
    let circuit = TestCircuit::new(forced_program::<Ep>, inputs, public.len());
    let public_flipped = public_of(&[point * flipped.scalar::<Ep>()]);
    let report = check_report(&circuit, k, &public_flipped);
    assert_eq!(failing_gates(&report), vec!["ecc glv split".to_owned()]);
}

// ---------------------------------------------------------------------------
// Real proof and inventory
// ---------------------------------------------------------------------------

/// Proves and verifies `circuit` (over `P::ScalarExt = C::Base`) at `k`.
fn prove_and_verify<C: PastaCurve, P: PastaCurve<ScalarExt = C::Base>>(
    circuit: &TestCircuit<C>,
    public: &[C::Base],
    k: u32,
) -> usize
where
    C::Base: iroha_pasta::poseidon::PoseidonField,
{
    let params = PinnedParams::<P>::derive(k).expect("params");
    let config = KeygenConfig::new(TranscriptV1::Blake2bChallenge255);
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("proving key");
    let randomness = ProverRandomness::recovery(move |_context: &[u8; 32]| {
        Ok::<_, Infallible>(ChaCha20Rng::from_seed([7; 32]))
    });
    let proof = prove_circuit(
        &params,
        &pk,
        circuit,
        &[public.to_vec()],
        randomness,
        ProverConfig::default(),
    )
    .expect("proof");
    assert_eq!(
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &[public.to_vec()],
            &proof,
            MemoryBudget::DEFAULT
        ),
        Ok(())
    );
    let mut wrong = public.to_vec();
    wrong[0] += C::Base::ONE;
    assert!(
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &[wrong],
            &proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    proof.len()
}

#[test]
fn ecc_circuit_proves_and_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(18);
    let p = random_point::<Ep>(&mut rng);
    let q = random_point::<Ep>(&mut rng);
    let limbs = random_limbs::<Ep>(&mut rng);
    let public = public_of(&[mul_native(&p, limbs), mul_native(&q, limbs)]);
    let circuit = TestCircuit::new(
        mul_program::<Ep>,
        Inputs::new(vec![p, q], vec![limbs]),
        public.len(),
    );
    let bytes = prove_and_verify::<Ep, Eq>(&circuit, &public, 10);
    assert!(bytes > 0);
}

/// One measured operation: rows of the ECC columns, assigned ECC cells, and
/// range-column rows, of a program run alone.
#[derive(Clone, Copy, Debug)]
struct Measured {
    ecc_rows: usize,
    ecc_cells: usize,
    range_rows: usize,
    glue_rows: usize,
}

fn measure<C: PastaCurve>(circuit: &TestCircuit<C>, k: u32, public: &[C::Base]) -> Measured {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    let flags = synthesized.tables.advice_assigned();
    let extent = |column: usize| {
        flags[column]
            .iter()
            .rposition(|flag| *flag)
            .map_or(0, |row| row + 1)
    };
    let count = |column: usize| flags[column].iter().filter(|flag| **flag).count();
    Measured {
        ecc_rows: ECC_COLUMNS.map(extent).max().unwrap_or(0),
        ecc_cells: ECC_COLUMNS.map(count).sum(),
        range_rows: count(RANGE_COLUMN),
        glue_rows: (10..14).map(extent).max().unwrap_or(0),
    }
}

/// Measures the operations at the gate shape (k = 16, 15-bit limbs) and
/// checks G3.5: one GLV multiplication (chain, complete tail and split,
/// footprint over the chip's 10 columns plus split range rows) <= 1.6k
/// cells.
#[test]
fn glv_inventory_at_the_gate_shape() {
    let k = 16;
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let with_shape = |mut circuit: TestCircuit<Eq>| {
        circuit.shape.limb_bits = 15;
        circuit
    };
    let p = random_point::<Eq>(&mut rng);
    let limbs = random_limbs::<Eq>(&mut rng);
    // The scalar limbs alone (the input encoding, not part of the gate).
    let limb_rows = {
        let shape = |bits| {
            RangeShape::new(bits, LimbBits::new(15).expect("b"))
                .expect("shape")
                .rows
        };
        shape(128) + shape(127)
    };
    let public = public_of(&[mul_native(&p, limbs)]);
    let single = with_shape(TestCircuit::new(
        mul_non_identity_program::<Eq>,
        Inputs::new(vec![p], vec![limbs]),
        2,
    ));
    assert_accepts(&single, k, &public);
    let m = measure(&single, k, &public);
    // Rows: the witnessed point (1), the split (3), the chain with its
    // result row (141).
    assert_eq!(m.ecc_rows, 1 + GLV_SPLIT_ROWS + GLV_CHAIN_ROWS + 1);
    let split_range_rows = m.range_rows - limb_rows;
    let chain_footprint = (GLV_CHAIN_ROWS + 1) * ECC_ADVICE_COLUMNS;
    let split_footprint = GLV_SPLIT_ROWS * ECC_ADVICE_COLUMNS + split_range_rows;
    let chain_cells = m.ecc_cells - 2 - 12;
    println!(
        "ECC_INVENTORY op=glv_mul_non_identity k={k} limb_bits=15 ecc_columns={ECC_ADVICE_COLUMNS} \
         chain_rows={} chain_footprint_cells={chain_footprint} chain_assigned_cells={chain_cells} \
         split_rows={GLV_SPLIT_ROWS} split_assigned_cells=12 split_range_rows={split_range_rows} \
         total_footprint_cells={} total_assigned_cells={} scalar_limb_range_rows={limb_rows}",
        GLV_CHAIN_ROWS + 1,
        chain_footprint + split_footprint,
        chain_cells + 12 + split_range_rows,
    );
    assert!(chain_footprint + split_footprint <= 1600, "G3.5");
    assert_eq!(split_range_rows, 29);
    // Guarded multiplication and a reuse of the split.
    let q = random_point::<Eq>(&mut rng);
    let public = public_of(&[mul_native(&p, limbs), mul_native(&q, limbs)]);
    let pair = with_shape(TestCircuit::new(
        mul_program::<Eq>,
        Inputs::new(vec![p, q], vec![limbs]),
        4,
    ));
    assert_accepts(&pair, k, &public);
    let m = measure(&pair, k, &public);
    println!(
        "ECC_INVENTORY op=glv_mul_guarded_plus_mul_with ecc_rows={} ecc_assigned_cells={} \
         guarded_chain_rows={} reuse_chain_rows={}",
        m.ecc_rows,
        m.ecc_cells,
        GLV_GUARDED_CHAIN_ROWS + 1,
        GLV_CHAIN_ROWS + 1
    );
    // Horner over three points: two guarded multiplications sharing a split
    // and two joins read in place.
    let points = vec![p, q, random_point::<Eq>(&mut rng)];
    let public = public_of(&[horner_native(&points, limbs)]);
    let horner = with_shape(TestCircuit::new(
        horner_program::<Eq>,
        Inputs::new(points, vec![limbs]),
        2,
    ));
    assert_accepts(&horner, k, &public);
    let m = measure(&horner, k, &public);
    println!(
        "ECC_INVENTORY op=horner_3_points ecc_rows={} ecc_assigned_cells={} footprint_cells={} \
         per_term_rows={}",
        m.ecc_rows,
        m.ecc_cells,
        m.ecc_rows * ECC_ADVICE_COLUMNS,
        GLV_GUARDED_CHAIN_ROWS + 1
    );
    // Fixed base.
    let (fixed, public) = fixed_base_cases::<Eq>(20);
    let fixed = with_shape(fixed);
    assert_accepts(&fixed, k, &public);
    let m = measure(&fixed, k, &public);
    let per = m.ecc_cells / 8;
    println!(
        "ECC_INVENTORY op=fixed_base_mul rows={} footprint_cells={} assigned_cells={per} \
         fixed_columns={ECC_FIXED_BASE_COLUMNS}",
        FIXED_BASE_ROWS + 1,
        (FIXED_BASE_ROWS + 1) * ECC_ADVICE_COLUMNS,
    );
    // Complete addition and on-curve checks.
    let (adds, public) = add_cases::<Eq>(21);
    let adds = with_shape(adds);
    assert_accepts(&adds, k, &public);
    let m = measure(&adds, k, &public);
    println!(
        "ECC_INVENTORY op=complete_add rows=1 (+1 result row, shared in chains) assigned_cells=9 (+2 result) \
         on_curve_rows_per_two_points=1 add_program_ecc_rows={} glue_rows={}",
        m.ecc_rows, m.glue_rows
    );
    let (cs, _) = configure(&single).expect("configure");
    println!(
        "ECC_INVENTORY gate_degree={} advice_queries_ecc={} selectors={}",
        cs.degree(),
        cs.advice_queries()
            .iter()
            .filter(|(column, _)| ECC_COLUMNS.contains(&column.index()))
            .count(),
        cs.num_selectors()
    );
}

// ---------------------------------------------------------------------------
// Point utilities and scalar encodings
// ---------------------------------------------------------------------------

/// Constants, copies of glue words into points, negation, selection, the
/// identity test, `assert_non_identity`, `assert_equal`, the empty sum and
/// the accessors; outputs `[-p, select(1, p, G), [p = O] as (bit, 0), O]`.
fn utilities_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let config = *chips.ecc.config();
    if config.advice().len() != ECC_ADVICE_COLUMNS || config.has_fixed_base() {
        return Err(Error::Synthesis);
    }
    let start = chips.ecc.next_row();
    let coordinates = inputs.point(0).map(|point| coordinates(&point));
    let x = chips.glue.witness(region, coordinates.map(|(x, _)| x))?;
    let y = chips.glue.witness(region, coordinates.map(|(_, y)| y))?;
    let p = chips.ecc.constrain_point(region, &x, &y)?;
    let strict = chips.ecc.constrain_non_identity(region, &x, &y)?;
    EccChip::<C>::assert_equal(region, &p, strict.point())?;
    let checked = EccChip::<C>::assert_non_identity(&mut chips.glue, region, &p)?;
    EccChip::<C>::assert_equal(region, checked.point(), &AssignedPoint::from(strict))?;
    let negated = EccChip::<C>::neg(&mut chips.glue, region, &p)?;
    let g = chips.ecc.constant_point(region, &C::generator())?;
    let one = chips.glue.boolean(region, Value::known(true))?;
    let selected = EccChip::<C>::select(&mut chips.glue, region, &one, &p, &g)?;
    let empty = chips.ecc.sum(region, &[])?;
    let is_identity = EccChip::<C>::is_identity(&mut chips.glue, region, &empty)?;
    let not_identity = EccChip::<C>::is_identity(&mut chips.glue, region, &p)?;
    if chips.ecc.next_row() <= start {
        return Err(Error::Synthesis);
    }
    if inputs.known && point_value::<C>(&negated) != inputs.points.first().map(|point| -*point) {
        return Err(Error::Synthesis);
    }
    Ok([
        expose(&negated).to_vec(),
        expose(&selected).to_vec(),
        vec![is_identity.word().clone(), not_identity.word().clone()],
        expose(&empty).to_vec(),
    ]
    .concat())
}

#[test]
fn point_utilities_match_native() {
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    let p = random_point::<Ep>(&mut rng);
    let (x, y) = coordinates(&-p);
    let (px, py) = coordinates(&p);
    let public = vec![x, y, px, py, Fp::ONE, Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let circuit = TestCircuit::new(
        utilities_program::<Ep>,
        Inputs::new(vec![p], Vec::new()),
        public.len(),
    );
    assert_accepts(&circuit, 9, &public);
    // The identity fails the strict copy check.
    let circuit = TestCircuit::new(
        utilities_program::<Ep>,
        Inputs::new(vec![identity::<Ep>()], Vec::new()),
        public.len(),
    );
    assert!(!check_report(&circuit, 9, &public).is_satisfied());
    // Off-curve coordinates fail both point checks.
    assert!(point::<Ep>((Fp::ONE, Fp::ONE)).is_none());
    // A chip shares rows with users above it.
    let mut meta = ConstraintSystem::<Fp>::new();
    let advice = core::array::from_fn(|_| meta.advice_column());
    let config = EccConfig::<Ep>::configure(&mut meta, advice);
    assert_eq!(EccChip::starting_at(&config, 7).next_row(), 7);
    assert!(FixedBase::new(&identity::<Ep>()).is_none());
    let base = FixedBase::new(&generator::<Ep>()).expect("table");
    assert_eq!(*base.point(), generator::<Ep>());
    assert_eq!(base.table().points.len(), FIXED_BASE_WINDOWS);
}

/// The canonical limbs of a circuit word (`assign_canonical_limbs`) as the
/// scalar: `[w mod r] P`, the PIPA-R challenge map.
fn word_scalar_program<C: PastaCurve>(
    chips: &mut Chips<C>,
    region: &mut Region<'_, C::Base>,
    inputs: &Inputs<C>,
) -> Result<Vec<Word<C::Base>>, Error> {
    let value = inputs
        .scalar(0)
        .map(|[lo, hi]| C::Base::from_u128(lo) + C::Base::from_u128(hi) * two_pow_128::<C::Base>());
    let word = chips.glue.witness(region, value)?;
    let mut uint = UintChip::new(&mut chips.glue, &mut chips.range);
    let limbs = crate::statement::assign_canonical_limbs(&mut uint, region, &word)?;
    let p = chips.ecc.witness_non_identity(region, inputs.point(0))?;
    let (out, _) =
        chips
            .ecc
            .mul_non_identity(region, &mut chips.range, ScalarLimbs::from(&limbs), &p)?;
    Ok(expose(&out).to_vec())
}

fn word_scalar_case<C: PastaCurve>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let p = random_point::<C>(&mut rng);
    for word in [C::Base::random(&mut rng), -C::Base::ONE, C::Base::ZERO] {
        let limbs = limbs_of(&word);
        let public = public_of(&[mul_native(&p, limbs)]);
        let circuit = TestCircuit::new(
            word_scalar_program::<C>,
            Inputs::new(vec![p], vec![limbs]),
            public.len(),
        );
        assert_accepts(&circuit, 10, &public);
    }
}

#[test]
fn canonical_word_scalars_follow_the_challenge_map() {
    // Pallas in Fp: w < p < q, the identity map; Vesta in Fq: w mod p.
    word_scalar_case::<Ep>(23);
    word_scalar_case::<Eq>(24);
    // A word above the Vesta scalar modulus reduces.
    let w = -Fq::ONE;
    assert_ne!(scalar_from_limbs::<Fp>(limbs_of(&w)).to_repr(), w.to_repr());
}

#[test]
fn fixed_base_needs_the_fixed_base_columns() {
    let (mut circuit, public) = fixed_base_cases::<Eq>(25);
    circuit.shape.fixed_base = false;
    assert_eq!(
        synthesize(&circuit, 10, Some(&[public][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
}
