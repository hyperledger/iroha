//! Tests of the FF-CRT chip: the M3 named tests (`ff_mul_matches_bigint_*`,
//! `ff_carry_bound_overflow_is_unsatisfiable`, `ff_noncanonical_limbs_rejected`,
//! `ff_canonical_compare_at_m_minus_1_m_m_plus_1`), native parity of every
//! operation against `num-bigint`, adversarial witnesses laid out through the
//! production block code, the executable carry memo, the per-cell tamper
//! suites, and the inventory and release measurement of the gate shape.
//!
//! Every circuit runs at `k = 16` (the range table has `2^15` rows).

use std::{convert::Infallible, time::Instant};

use ::ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness,
    check::{CheckFailure, CheckMode, CheckReport, check_circuit},
    cs::{Instance, InstanceModeV1, ProofSuffixV1, TranscriptV1},
    frontend::{Circuit, SimpleFloorPlanner, configure, synthesize},
    keys::{KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use num_bigint::{BigInt, BigUint};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

use super::*;
use crate::{arith::GlueConfig, q_leaf::QLeafConfig, tamper::undetected_tampers};

/// The circuit size of every test.
const K: u32 = 16;

/// The moduli by test index.
const MODULI: [ForeignModulus; 4] = [
    ForeignModulus::PASTA_FP,
    ForeignModulus::PASTA_FQ,
    ForeignModulus::P256_BASE,
    ForeignModulus::P256_ORDER,
];

const FP_INDEX: u64 = 0;
const FQ_INDEX: u64 = 1;
const P256_P_INDEX: u64 = 2;
const P256_N_INDEX: u64 = 3;

fn modulus_at(index: u64) -> Result<ForeignModulus, Error> {
    usize::try_from(index)
        .ok()
        .and_then(|index| MODULI.get(index).copied())
        .ok_or(Error::Synthesis)
}

// ---------------------------------------------------------------------------
// Integer helpers (num-bigint is the independent oracle).
// ---------------------------------------------------------------------------

fn big_of_words(words: [u64; 4]) -> BigUint {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    BigUint::from_bytes_le(&bytes)
}

fn big_of_nat(value: &Nat) -> BigUint {
    let bytes: Vec<u8> = value
        .words()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    BigUint::from_bytes_le(&bytes)
}

fn nat_of_big(value: &BigUint) -> Nat {
    let mut words = [0_u64; 9];
    for (index, digit) in value.to_u64_digits().into_iter().enumerate() {
        words[index] = digit;
    }
    Nat(words)
}

fn words_of_big(value: &BigUint) -> [u64; 4] {
    nat_of_big(value).to_words().expect("below 2^256")
}

fn modulus_big(modulus: ForeignModulus) -> BigUint {
    big_of_words(modulus.words())
}

fn field_of_big<F: PastaField>(value: &BigUint) -> F {
    nat_of_big(value).to_field()
}

/// The limbs of a value below `2^302`.
fn limbs_big(value: &BigUint) -> [BigUint; LIMBS] {
    let mask = (BigUint::from(1_u8) << LIMB_BITS) - 1_u8;
    [
        value & &mask,
        (value >> LIMB_BITS) & &mask,
        value >> (2 * LIMB_BITS),
    ]
}

/// The public words of a value's limbs.
fn limb_fields_big<F: PastaField>(value: &BigUint) -> Vec<F> {
    limbs_big(value).iter().map(field_of_big).collect()
}

/// Deterministic 256-bit values.
fn random_words(rng: &mut ChaCha20Rng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

/// A deterministic value below `m`.
fn random_below(rng: &mut ChaCha20Rng, modulus: ForeignModulus) -> [u64; 4] {
    let value = big_of_words(random_words(rng)) % modulus_big(modulus);
    words_of_big(&value)
}

// ---------------------------------------------------------------------------
// The test circuit.
// ---------------------------------------------------------------------------

/// A program over the chips; its words become the public instance in order.
type Program<F> = fn(
    &mut FfChip<F>,
    &mut GlueChip<F>,
    &mut Region<'_, F>,
    &[Value<[u64; 4]>],
    &[u64],
) -> Result<Vec<Word<F>>, Error>;

/// Configuration-time parameters.
#[derive(Clone, Debug, Default)]
struct Params {
    moduli: Vec<ForeignModulus>,
    public: usize,
    /// The chip on the Q leaf's shared table (P-256 moduli), its `c_0` and
    /// `u_0` range arguments carrying the SHA-256 and window lookups.
    leaf: bool,
}

/// FF columns `0..10`, glue columns `10..14`, one instance column.
#[derive(Clone)]
struct FfCircuit<F: PastaField> {
    params: Params,
    program: Program<F>,
    inputs: Vec<[u64; 4]>,
    args: Vec<u64>,
    known: bool,
}

impl<F: PastaField> FfCircuit<F> {
    fn new(
        moduli: &[ForeignModulus],
        public: usize,
        program: Program<F>,
        inputs: Vec<[u64; 4]>,
        args: &[u64],
    ) -> Self {
        Self {
            params: Params {
                moduli: moduli.to_vec(),
                public,
                leaf: false,
            },
            program,
            inputs,
            args: args.to_vec(),
            known: true,
        }
    }
}

impl<F: PastaField> FfCircuit<F> {
    /// The same circuit in the Q-leaf layout (the shared table, with the
    /// SHA-256, fixed-base and dynamic rows of the guests loaded; the chip
    /// from row 0).
    fn in_leaf(mut self) -> Self {
        self.params.leaf = true;
        self
    }
}

impl<F: PastaField> Circuit<F> for FfCircuit<F> {
    type Config = (FfConfig, GlueConfig, Column<Instance>, Option<QLeafConfig>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Params;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> Params {
        self.params.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, Params::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Params) -> Self::Config {
        if params.leaf {
            let advice = core::array::from_fn(|_| meta.advice_column());
            let constants = meta.fixed_column();
            let leaf = QLeafConfig::configure(meta, advice, constants, &[]);
            let instance = meta.instance_column(params.public);
            meta.enable_equality(instance);
            return (leaf.ff().clone(), *leaf.glue(), instance, Some(leaf));
        }
        let columns = core::array::from_fn(|_| meta.advice_column());
        let ff = FfConfig::configure(meta, columns, &params.moduli);
        let glue_advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, glue_advice, constants);
        let instance = meta.instance_column(params.public);
        meta.enable_equality(instance);
        (ff, glue, instance, None)
    }

    fn synthesize(
        &self,
        (ff, glue, instance, leaf): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let (mut ff, mut glue) = if let Some(leaf) = &leaf {
            leaf.load_tables(&mut layouter)?;
            let chips = leaf.chips::<F>(0)?;
            (chips.ff, chips.glue)
        } else {
            let ff = FfChip::new(ff);
            ff.load_table(&mut layouter)?;
            (ff, GlueChip::new(glue))
        };
        let inputs: Vec<Value<[u64; 4]>> = self
            .inputs
            .iter()
            .map(|value| {
                if self.known {
                    Value::known(*value)
                } else {
                    Value::unknown()
                }
            })
            .collect();
        let program = self.program;
        let args = self.args.clone();
        let outputs = layouter.assign_region(
            || "ff",
            |mut region| program(&mut ff, &mut glue, &mut region, &inputs, &args),
        )?;
        if outputs.len() != self.params.public {
            return Err(Error::Synthesis);
        }
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), instance, row)?;
        }
        Ok(())
    }
}

fn check<F: PastaField>(circuit: &FfCircuit<F>, public: &[F]) -> CheckReport<F> {
    check_circuit(circuit, K, &[public.to_vec()], CheckMode::Strict).expect("synthesis")
}

fn assert_accepts<F: PastaField>(circuit: &FfCircuit<F>, public: &[F], what: &str) {
    let report = check(circuit, public);
    assert!(report.is_satisfied(), "{what}: {report}");
}

/// The names of the failing lookups, when every failure is a missing lookup
/// input (a range rejection, with every gate satisfied).
fn range_rejections<F: PastaField>(report: &CheckReport<F>) -> Option<Vec<String>> {
    if report.is_satisfied() {
        return None;
    }
    let mut names = Vec::new();
    for failure in report.failures() {
        match failure {
            CheckFailure::LookupInputMissing { name, .. } => {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            _ => return None,
        }
    }
    Some(names)
}

/// Asserts that `circuit` is rejected by range lookups only, and only by
/// lookups whose names start with one of `expected`.
fn assert_range_rejected<F: PastaField>(
    circuit: &FfCircuit<F>,
    public: &[F],
    expected: &[&str],
    what: &str,
) {
    let report = check(circuit, public);
    let names = range_rejections(&report)
        .unwrap_or_else(|| panic!("{what}: not a pure range rejection: {report}"));
    assert!(
        names
            .iter()
            .all(|name| expected.iter().any(|prefix| name.starts_with(prefix))),
        "{what}: unexpected lookups {names:?}"
    );
}

fn limb_words<F: PastaField>(value: &FfValue<F>) -> Vec<Word<F>> {
    value.limbs().to_vec()
}

// ---------------------------------------------------------------------------
// Programs.
// ---------------------------------------------------------------------------

/// `args = [modulus]`: proper witnesses of every input pair and their
/// products; outputs the product limbs.
fn mul_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let mut out = Vec::new();
    for pair in inputs.chunks(2) {
        let a = ff.witness(region, modulus, pair[0])?;
        let b = ff.witness(region, modulus, pair[1])?;
        let c = ff.mul(region, &a, &b)?;
        out.extend(limb_words(&c));
    }
    Ok(out)
}

fn mul_case<F: PastaField>(modulus_index: u64, seed: u8) {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    let m = modulus_big(modulus);
    let one = BigUint::from(1_u8);
    let top = (BigUint::from(1_u8) << 256_usize) - 1_u8;
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut pairs: Vec<(BigUint, BigUint)> = vec![
        (BigUint::from(0_u8), m.clone() - 1_u8),
        (one.clone(), m.clone() - 1_u8),
        (m.clone() - 1_u8, m.clone() - 1_u8),
        (m.clone() - 2_u8, BigUint::from(2_u8)),
        (top.clone(), top.clone()),
        (m.clone(), m.clone() + 1_u8),
        (
            (BigUint::from(1_u8) << 174_usize) - 1_u8,
            BigUint::from(1_u8) << 87_usize,
        ),
    ];
    for _ in 0..4 {
        pairs.push((
            big_of_words(random_words(&mut rng)),
            big_of_words(random_words(&mut rng)),
        ));
    }
    // Native parity of the reference arithmetic over many values.
    for _ in 0..64 {
        let (a, b) = (random_words(&mut rng), random_words(&mut rng));
        let expected = (big_of_words(a) * big_of_words(b)) % &m;
        let product = modulus.mul(&Nat::from_words(a), &Nat::from_words(b));
        assert_eq!(big_of_nat(&product), expected);
    }
    let mut inputs = Vec::new();
    let mut public = Vec::new();
    for (a, b) in &pairs {
        inputs.push(words_of_big(a));
        inputs.push(words_of_big(b));
        public.extend(limb_fields_big::<F>(&((a * b) % &m)));
    }
    let circuit = FfCircuit::new(
        &[modulus],
        public.len(),
        mul_program::<F>,
        inputs,
        &[modulus_index],
    );
    assert_accepts(&circuit, &public, "products");
}

#[test]
fn ff_mul_matches_bigint_fq_in_fp() {
    mul_case::<Fp>(FQ_INDEX, 1);
    // The Pasta field implementation agrees with the reference reduction.
    let mut rng = ChaCha20Rng::from_seed([11; 32]);
    for _ in 0..32 {
        let a = random_below(&mut rng, ForeignModulus::PASTA_FQ);
        let b = random_below(&mut rng, ForeignModulus::PASTA_FQ);
        let product = ForeignModulus::PASTA_FQ.mul(&Nat::from_words(a), &Nat::from_words(b));
        let field = Fq::from_canonical_limbs(a).unwrap() * Fq::from_canonical_limbs(b).unwrap();
        assert_eq!(product.low_words(), field.to_canonical_limbs());
    }
}

#[test]
fn ff_mul_matches_bigint_fp_in_fq() {
    mul_case::<Fq>(FP_INDEX, 2);
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    for _ in 0..32 {
        let a = random_below(&mut rng, ForeignModulus::PASTA_FP);
        let b = random_below(&mut rng, ForeignModulus::PASTA_FP);
        let product = ForeignModulus::PASTA_FP.mul(&Nat::from_words(a), &Nat::from_words(b));
        let field = Fp::from_canonical_limbs(a).unwrap() * Fp::from_canonical_limbs(b).unwrap();
        assert_eq!(product.low_words(), field.to_canonical_limbs());
    }
}

#[test]
fn ff_mul_matches_bigint_p256_p() {
    mul_case::<Fq>(P256_P_INDEX, 3);
}

#[test]
fn ff_mul_matches_bigint_p256_n() {
    mul_case::<Fq>(P256_N_INDEX, 4);
}

#[test]
fn ff_mul_output_is_bound_to_the_public_limbs() {
    let modulus = ForeignModulus::P256_BASE;
    let m = modulus_big(modulus);
    let (a, b) = (m.clone() - 5_u8, m.clone() - 7_u8);
    let expected = (&a * &b) % &m;
    let mut public = limb_fields_big::<Fp>(&expected);
    let circuit = FfCircuit::new(
        &[modulus],
        3,
        mul_program::<Fp>,
        vec![words_of_big(&a), words_of_big(&b)],
        &[P256_P_INDEX],
    );
    // P-256 inside an Fp circuit, then a wrong claimed product.
    assert_accepts(&circuit, &public, "P-256 p in Fp");
    public[0] += Fp::ONE;
    assert!(!check(&circuit, &public).is_satisfied());
}

// ---------------------------------------------------------------------------
// Adversarial fused blocks.
// ---------------------------------------------------------------------------

/// Field solutions of the four carry equations for given cells.
fn solve_carries<F: PastaField>(
    left: &[F; LIMBS],
    right: &[F; LIMBS],
    subtracted: &[F; LIMBS],
    quotient: &[F; LIMBS],
    modulus: &[u128; LIMBS],
) -> [F; CARRIES] {
    let radix_inv = F::from_u128(1 << LIMB_BITS).invert().unwrap();
    let mut out = [F::ZERO; CARRIES];
    let mut carry = F::ZERO;
    for (column, out) in out.iter_mut().enumerate() {
        let mut t = carry;
        for i in 0..LIMBS {
            if let Some(j) = column.checked_sub(i).filter(|j| *j < LIMBS) {
                t += left[i] * right[j] - quotient[i] * F::from_u128(modulus[j]);
            }
        }
        if column < LIMBS {
            t -= subtracted[column];
        }
        carry = t * radix_inv;
        *out = carry + F::from_u128(1 << CARRY_OFFSET_BITS);
    }
    out
}

/// `args = [modulus, attack]`: two proper witnesses `a, b` (attacks 6 and
/// 7 use free operand cells instead) and one multiplication block whose
/// witness the attack rewrites; outputs nothing.
fn attack_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let attack = args[1];
    let gates = ff.gates_of(modulus, &[])?;
    let m = modulus.limbs();
    let radix = Nat::pow2(LIMB_BITS);
    let witnesses;
    let (a_value, b_value, slots_a, slots_b) = if attack == 6 || attack == 7 {
        // Free operands outside (6) or at the edge of (7) the envelope.
        let limb = if attack == 6 {
            Nat::pow2(96)
        } else {
            Nat::from_u128(OPERAND_LIMB_MAX)
        };
        let limbs = [limb, limb, Nat::ZERO];
        let fields = limbs.map(|limb| Value::known(limb.to_field::<F>()));
        (
            Value::known(limbs),
            Value::known(limbs),
            fields.map(Slot::Free),
            fields.map(Slot::Free),
        )
    } else {
        witnesses = [
            ff.witness(region, modulus, inputs[0])?,
            ff.witness(region, modulus, inputs[1])?,
        ];
        let [a, b] = &witnesses;
        let [a0, a1, a2] = a.limbs();
        let [b0, b1, b2] = b.limbs();
        (
            a.limb_values(),
            b.limb_values(),
            [Slot::Copy(a0), Slot::Copy(a1), Slot::Copy(a2)],
            [Slot::Copy(b0), Slot::Copy(b1), Slot::Copy(b2)],
        )
    };
    let witness = a_value.zip(b_value).map(|(a, b)| {
        let product = recompose_nat(&a).wrapping_mul(&recompose_nat(&b));
        let (quotient, remainder) = product.div_rem(&modulus.nat()).unwrap();
        let mut c = nat_limbs(&remainder);
        let mut q = nat_limbs(&quotient);
        match attack {
            // Low limb pushed past 2^87 (same integer).
            1 => {
                c[0] = c[0].wrapping_add(&radix);
                c[1] = c[1].wrapping_sub(&Nat::ONE);
            }
            // Middle limb pushed past 2^87 (same integer).
            2 => {
                c[1] = c[1].wrapping_add(&radix);
                c[2] = c[2].wrapping_sub(&Nat::ONE);
            }
            // The congruent c + m, with top limb past 2^82 for P-256.
            3 => {
                c = nat_limbs(&remainder.wrapping_add(&modulus.nat()));
                q = nat_limbs(&quotient.wrapping_sub(&Nat::ONE));
            }
            // Quotient low limb past 2^87 (same integer).
            4 => {
                q[0] = q[0].wrapping_add(&radix);
                q[1] = q[1].wrapping_sub(&Nat::ONE);
            }
            _ => {}
        }
        if attack == 5 {
            // A wrong product c + 1 with every gate polynomial satisfied
            // in the field: q_0 and the carries solve the equations.
            let af = a.map(Nat::to_field::<F>);
            let bf = b.map(Nat::to_field::<F>);
            let mut cf = c.map(Nat::to_field::<F>);
            cf[0] += F::ONE;
            let mut qf = q.map(Nat::to_field::<F>);
            let radix_f = F::from_u128(1 << LIMB_BITS);
            let recompose_f =
                |limbs: &[F; LIMBS]| limbs[0] + (limbs[1] + limbs[2] * radix_f) * radix_f;
            let total = (recompose_f(&af) * recompose_f(&bf) - recompose_f(&cf))
                * modulus.nat().to_field::<F>().invert().unwrap();
            qf[0] = total - (qf[1] + qf[2] * radix_f) * radix_f;
            let u = solve_carries(&af, &bf, &cf, &qf, &m);
            return FusedWitness { c: cf, q: qf, u };
        }
        let u = carries(&a, &b, &c, &[0; LIMBS], &q, &m);
        fused_witness_fields::<F>(&c, &q, &u)
    });
    ff.fused_block(
        region,
        gates,
        Mode::Mul,
        (slots_a, slots_b),
        witness,
        CarryLayout::Full,
    )?;
    Ok(Vec::new())
}

fn attack_circuit<F: PastaField>(
    modulus_index: u64,
    attack: u64,
    a: &BigUint,
    b: &BigUint,
) -> FfCircuit<F> {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    FfCircuit::new(
        &[modulus],
        0,
        attack_program::<F>,
        vec![words_of_big(a), words_of_big(b)],
        &[modulus_index, attack],
    )
}

#[test]
fn ff_carry_bound_overflow_is_unsatisfiable() {
    let m = modulus_big(ForeignModulus::P256_BASE);
    let (a, b) = (m.clone() - 3_u8, m.clone() - 11_u8);
    // Control: the honest block.
    assert_accepts(
        &attack_circuit::<Fq>(P256_P_INDEX, 0, &a, &b),
        &[],
        "honest",
    );
    // Operand limbs at the envelope edge 2^94 - 1: every carry fits.
    assert_accepts(
        &attack_circuit::<Fq>(P256_P_INDEX, 7, &a, &b),
        &[],
        "envelope edge",
    );
    // Operand limbs 2^96: the integer carries exceed 2^104 and no carry
    // assignment passes the carry range checks (the result and quotient are
    // in range, so only carry lookups fail).
    assert_range_rejected(
        &attack_circuit::<Fq>(P256_P_INDEX, 6, &a, &b),
        &[],
        &["ff u_"],
        "carry overflow",
    );
    // A wrong product whose gate polynomials all vanish in the field: only
    // the range checks of the quotient and the carries stop the wraparound.
    for (index, native) in [(P256_P_INDEX, "Fq"), (FQ_INDEX, "Fp")] {
        let modulus = MODULI[usize::try_from(index).expect("index")];
        let m = modulus_big(modulus);
        let (a, b) = (m.clone() - 3_u8, m.clone() - 11_u8);
        if native == "Fq" {
            assert_range_rejected(
                &attack_circuit::<Fq>(index, 5, &a, &b),
                &[],
                &["ff q_", "ff u_"],
                "wraparound in Fq",
            );
        } else {
            assert_range_rejected(
                &attack_circuit::<Fp>(index, 5, &a, &b),
                &[],
                &["ff q_", "ff u_"],
                "wraparound in Fp",
            );
        }
    }
}

/// The limbs of the raw witness forms: `2^87` (low limb, top sublimb
/// `2^12`), `2^82` (top limb, top sublimb `2^7`), `2^90 - 1` (low limb, top
/// sublimb `2^15 - 1`: in the table, but not below `2^12`) and `2^89 - 1`
/// (top limb, top sublimb `2^14 - 1`).
fn raw_limbs<F: PastaField>(form: u64) -> [F; LIMBS] {
    match form {
        0 => [F::from_u128(1 << LIMB_BITS), F::ZERO, F::ZERO],
        1 => [F::ZERO, F::ZERO, F::from_u128(1 << TOP_LIMB_BITS)],
        2 => [F::from_u128((1 << 90) - 1), F::ZERO, F::ZERO],
        _ => [F::ZERO, F::ZERO, F::from_u128((1 << 89) - 1)],
    }
}

/// `args = [modulus, form]`: a witness block whose limbs are set directly
/// ([`raw_limbs`]), copied into a multiplication by one; outputs nothing.
fn raw_witness_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    _inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let limbs = raw_limbs::<F>(args[1]);
    let start = ff.block(&[Group::C])?;
    ff.activate(region, start, Group::C)?;
    let words = ff.value_running_sums(region, start, Value::known(limbs))?;
    let value = FfValue {
        limbs: words,
        bounds: PROPER_BOUNDS,
        modulus,
        form: Form::Proper,
    };
    let gates = ff.gates_of(modulus, &[])?;
    ff.fused_mul(
        region,
        gates,
        Operand::value(&value),
        Operand::constant([1, 0, 0]),
    )?;
    Ok(Vec::new())
}

#[test]
fn ff_noncanonical_limbs_rejected() {
    let modulus = ForeignModulus::P256_BASE;
    let m = modulus_big(modulus);
    // Deterministic operands whose product c = a b mod m has nonzero
    // middle and top limbs, c + m >= 2^256 and a quotient with q_1 > 0.
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let (a, b) = loop {
        let a = big_of_words(random_below(&mut rng, modulus));
        let b = big_of_words(random_below(&mut rng, modulus));
        let c = (&a * &b) % &m;
        let limbs = limbs_big(&c);
        let q_limbs = limbs_big(&((&a * &b) / &m));
        let zero = BigUint::from(0_u8);
        if limbs[1] > zero
            && limbs[2] > zero
            && q_limbs[1] > zero
            && &c + &m >= BigUint::from(1_u8) << 256_usize
        {
            break (a, b);
        }
    };
    for (attack, lookup) in [(1, "ff c_0"), (2, "ff c_1"), (3, "ff c_2"), (4, "ff q_0")] {
        assert_range_rejected(
            &attack_circuit::<Fq>(P256_P_INDEX, attack, &a, &b),
            &[],
            &[lookup],
            &format!("attack {attack}"),
        );
    }
    // A proper witness whose low limb is 2^87 or 2^90 - 1, or whose top limb
    // is 2^82 or 2^89 - 1: each top sublimb is a 15-bit table value, so only
    // the scaled membership `2^(15 - w) z_top` (on the block's operand row)
    // rejects it.
    for form in 0..4 {
        let circuit = FfCircuit::new(
            &[modulus],
            0,
            raw_witness_program::<Fq>,
            Vec::new(),
            &[P256_P_INDEX, form],
        );
        let lookup = if form % 2 == 0 { "ff c_0" } else { "ff c_2" };
        assert_range_rejected(&circuit, &[], &[lookup], "raw witness");
        let rows: Vec<usize> = check(&circuit, &[])
            .failures()
            .iter()
            .filter_map(|failure| match failure {
                CheckFailure::LookupInputMissing { location, .. } => Some(location.row),
                _ => None,
            })
            .collect();
        // The witness block starts at row 0: its operand row.
        assert_eq!(rows, vec![OPERAND_ROW], "form {form}");
    }
    // Native: the limb split of canonical values is the proper split.
    let x = Nat::from_words([u64::MAX; 4]);
    assert_eq!(
        to_limbs(&x),
        Some([mask(LIMB_BITS), mask(LIMB_BITS), mask(TOP_LIMB_BITS)])
    );
    assert_eq!(from_limbs(&PROPER_BOUNDS), x);
}

/// The adversarial blocks of `ff_carry_bound_overflow_is_unsatisfiable` and
/// `ff_noncanonical_limbs_rejected` on the Q leaf's shared table, whose
/// `c_0` and `u_0` range arguments also carry the SHA-256 spread and window
/// lookups and whose table holds their rows: a foreign-field tuple
/// `(0, .., 0, R)` still matches only a 15-bit range row, so every attack is
/// rejected by the same range lookups, and the leaf keeps the shared-table
/// conditions.
#[test]
fn ff_adversarial_blocks_rejected_on_the_shared_table() {
    let modulus = ForeignModulus::P256_BASE;
    let m = modulus_big(modulus);
    let (a, b) = (m.clone() - 3_u8, m.clone() - 11_u8);
    let leaf = |attack| attack_circuit::<Fq>(P256_P_INDEX, attack, &a, &b).in_leaf();
    let honest = leaf(0);
    assert_accepts(&honest, &[], "honest");
    let (_, config) = configure(&honest).expect("configure");
    let audit = config.3.expect("leaf");
    let tables = synthesize(&honest, K, Some(&[Vec::new()][..])).expect("synthesis");
    assert_eq!(audit.audit(&tables.tables), Ok(()));
    assert_accepts(&leaf(7), &[], "envelope edge");
    assert_range_rejected(&leaf(6), &[], &["ff u_"], "carry overflow");
    assert_range_rejected(&leaf(5), &[], &["ff q_", "ff u_"], "wraparound");
    // Attacks 1-4 need a product with nonzero middle and top limbs.
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let (a, b) = loop {
        let a = big_of_words(random_below(&mut rng, modulus));
        let b = big_of_words(random_below(&mut rng, modulus));
        let c = (&a * &b) % &m;
        let limbs = limbs_big(&c);
        let q_limbs = limbs_big(&((&a * &b) / &m));
        let zero = BigUint::from(0_u8);
        if limbs[1] > zero
            && limbs[2] > zero
            && q_limbs[1] > zero
            && &c + &m >= BigUint::from(1_u8) << 256_usize
        {
            break (a, b);
        }
    };
    for (attack, lookup) in [(1, "ff c_0"), (2, "ff c_1"), (3, "ff c_2"), (4, "ff q_0")] {
        assert_range_rejected(
            &attack_circuit::<Fq>(P256_P_INDEX, attack, &a, &b).in_leaf(),
            &[],
            &[lookup],
            &format!("attack {attack}"),
        );
    }
    for form in 0..4 {
        let circuit = FfCircuit::new(
            &[modulus],
            0,
            raw_witness_program::<Fq>,
            Vec::new(),
            &[P256_P_INDEX, form],
        )
        .in_leaf();
        let lookup = if form % 2 == 0 { "ff c_0" } else { "ff c_2" };
        assert_range_rejected(&circuit, &[], &[lookup], "raw witness");
    }
}

/// `args = [modulus, mode]`: every input as a canonical witness (`mode 0`)
/// or as a proper witness proven canonical (`mode 1`); outputs the limbs.
fn canonical_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let mut out = Vec::new();
    for input in inputs {
        let value = if args[1] == 0 {
            ff.witness_canonical(region, modulus, *input)?
        } else {
            let proper = ff.witness(region, modulus, *input)?;
            ff.assert_canonical(region, &proper)?
        };
        assert_eq!(value.form(), Form::Canonical);
        out.extend(limb_words(&value));
    }
    Ok(out)
}

fn compare_case<F: PastaField>(modulus_index: u64) {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    let m = modulus_big(modulus);
    for mode in [0, 1] {
        let accepted = [m.clone() - 1_u8, BigUint::from(0_u8), m.clone() - 2_u8];
        let public: Vec<F> = accepted.iter().flat_map(limb_fields_big::<F>).collect();
        let circuit = FfCircuit::new(
            &[modulus],
            public.len(),
            canonical_program::<F>,
            accepted.iter().map(words_of_big).collect(),
            &[modulus_index, mode],
        );
        assert_accepts(&circuit, &public, "m - 1, 0, m - 2");
        for rejected in [m.clone(), m.clone() + 1_u8] {
            let public = limb_fields_big::<F>(&rejected);
            let circuit = FfCircuit::new(
                &[modulus],
                3,
                canonical_program::<F>,
                vec![words_of_big(&rejected)],
                &[modulus_index, mode],
            );
            // The difference m - 1 - x is negative: its top limb fails the
            // range check while both comparison polynomials vanish.
            assert_range_rejected(&circuit, &public, &["ff q_2"], "x >= m");
        }
    }
    // Native canonicity at the boundary.
    assert!(modulus.is_canonical(&nat_of_big(&(m.clone() - 1_u8))));
    assert!(!modulus.is_canonical(&nat_of_big(&m)));
    assert!(!modulus.is_canonical(&nat_of_big(&(m + 1_u8))));
}

#[test]
fn ff_canonical_compare_at_m_minus_1_m_m_plus_1() {
    compare_case::<Fp>(FQ_INDEX);
    compare_case::<Fq>(FP_INDEX);
    compare_case::<Fq>(P256_P_INDEX);
    compare_case::<Fq>(P256_N_INDEX);
}

// ---------------------------------------------------------------------------
// Division, inversion and linear operations.
// ---------------------------------------------------------------------------

/// `args = [modulus]`: inputs `(a, b)` pairs; outputs `a / b`, `b^-1`.
fn div_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let mut out = Vec::new();
    for pair in inputs.chunks(2) {
        let a = ff.witness(region, modulus, pair[0])?;
        let b = ff.witness(region, modulus, pair[1])?;
        let quotient = ff.div(region, &a, &b)?;
        let inverse = ff.inverse(region, &b)?;
        out.extend(limb_words(&quotient));
        out.extend(limb_words(&inverse));
    }
    Ok(out)
}

fn div_case<F: PastaField>(modulus_index: u64, seed: u8) {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    let m = modulus_big(modulus);
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let top = (BigUint::from(1_u8) << 256_usize) - 1_u8;
    let pairs = vec![
        (m.clone() - 1_u8, m.clone() - 1_u8),
        (BigUint::from(0_u8), BigUint::from(1_u8)),
        (top.clone(), m.clone() + 2_u8),
        (
            big_of_words(random_words(&mut rng)),
            big_of_words(random_below(&mut rng, modulus)) + 1_u8,
        ),
    ];
    let mut inputs = Vec::new();
    let mut public = Vec::new();
    for (a, b) in &pairs {
        inputs.push(words_of_big(a));
        inputs.push(words_of_big(b));
        let inverse = b.modpow(&(m.clone() - 2_u8), &m);
        assert_eq!((b * &inverse) % &m, BigUint::from(1_u8));
        let quotient = (a * &inverse) % &m;
        public.extend(limb_fields_big::<F>(&quotient));
        public.extend(limb_fields_big::<F>(&inverse));
        // Native references.
        assert_eq!(
            modulus
                .inverse(&nat_of_big(b))
                .map(|value| big_of_nat(&value)),
            Some(inverse)
        );
        assert_eq!(
            modulus
                .div(&nat_of_big(a), &nat_of_big(b))
                .map(|value| big_of_nat(&value)),
            Some(quotient)
        );
    }
    assert_eq!(modulus.inverse(&Nat::ZERO), None);
    assert_eq!(modulus.inverse(&modulus.nat()), None);
    assert_eq!(modulus.fermat_inverse(&modulus.nat()), Nat::ZERO);
    assert_eq!(
        modulus.fermat_inverse(&Nat::from_u64(2)),
        modulus.inverse(&Nat::from_u64(2)).expect("invertible")
    );
    let circuit = FfCircuit::new(
        &[modulus],
        public.len(),
        div_program::<F>,
        inputs,
        &[modulus_index],
    );
    assert_accepts(&circuit, &public, "divisions and inverses");
}

#[test]
fn ff_div_and_inverse_match_bigint() {
    div_case::<Fp>(FQ_INDEX, 21);
    div_case::<Fq>(FP_INDEX, 22);
    div_case::<Fq>(P256_P_INDEX, 23);
    div_case::<Fq>(P256_N_INDEX, 24);
}

#[test]
fn ff_inverse_of_zero_is_unsatisfiable() {
    let modulus = ForeignModulus::P256_ORDER;
    let m = modulus_big(modulus);
    for zero in [BigUint::from(0_u8), m] {
        // `div_program` computes `1 / 0` and `0^-1`; no output can satisfy
        // the division gate. The claimed public outputs are zeros.
        let circuit = FfCircuit::new(
            &[modulus],
            6,
            div_program::<Fq>,
            vec![[1, 0, 0, 0], words_of_big(&zero)],
            &[P256_N_INDEX],
        );
        assert!(!check(&circuit, &[Fq::ZERO; 6]).is_satisfied());
    }
}

/// `args = [modulus]`: inputs `x, y, k, bit`; outputs, in order: `x + y`,
/// `x - y`, `-y`, `5 x`, `(x - y)(x + y)`, `x^2`, `x k`, `bit ? x : y`,
/// a long chain `((x + y) + (x + y)) ...` reduced, the native residue of
/// `x`, a canonical constant `k mod m` checked equal to the canonical `k`,
/// and `sum` of eight `x - y` (auto-reduced).
fn linear_program<F: PastaField>(
    ff: &mut FfChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let x = ff.witness(region, modulus, inputs[0])?;
    let y = ff.witness(region, modulus, inputs[1])?;
    let bit_value = inputs[3].map(|value| value[0] & 1 == 1);
    let bit = glue.boolean(region, bit_value)?;
    let sum = ff.add(glue, region, &x, &y)?;
    let difference = ff.sub(glue, region, &x, &y)?;
    let negation = ff.neg(glue, region, &y)?;
    let scaled = ff.scale(glue, region, &x, 5)?;
    let product = ff.mul(region, &difference, &sum)?;
    let square = ff.square(region, &x)?;
    let k = Nat::from_words([args[1], args[2], args[3], args[4]]);
    let by_constant = ff.mul_constant(region, &x, &k)?;
    let selected = ff.select(glue, region, &bit, &x, &y)?;
    let mut chain = sum.clone();
    for _ in 0..6 {
        chain = ff.add(glue, region, &chain, &chain)?;
    }
    let chain = ff.reduce(region, &chain)?;
    let native = FfChip::native(glue, region, &x)?;
    let k_canonical = ff.witness_canonical(region, modulus, inputs[2])?;
    let constant = ff.constant(glue, region, modulus, &modulus.reduce(&k))?;
    FfChip::assert_equal(region, &constant, &k_canonical)?;
    let mut total = difference.clone();
    for _ in 0..7 {
        total = ff.add(glue, region, &total, &difference)?;
    }
    let total = ff.reduce(region, &total)?;
    let mut out = Vec::new();
    for value in [
        &sum,
        &difference,
        &negation,
        &scaled,
        &product,
        &square,
        &by_constant,
        &selected,
        &chain,
        &total,
    ] {
        out.extend(limb_words(value));
    }
    out.push(native);
    Ok(out)
}

/// The exact public outputs of `linear_program`: limb-wise results from
/// the chip's bound rules, canonical residues for products and reductions.
fn linear_case<F: PastaField>(modulus_index: u64, seed: u8) {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    let m = modulus_big(modulus);
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (_, padding) = modulus.padding(&PROPER_BOUNDS).expect("padding");
    let padding: Vec<BigUint> = padding.iter().map(|limb| BigUint::from(*limb)).collect();
    let padding_value = &padding[0] + (&padding[1] << LIMB_BITS) + (&padding[2] << (2 * LIMB_BITS));
    assert_eq!(&padding_value % &m, BigUint::from(0_u8));
    for bit in [0_u64, 1] {
        let x = big_of_words(random_words(&mut rng));
        let y = big_of_words(random_words(&mut rng));
        let k = big_of_words(random_below(&mut rng, modulus));
        let k_words = words_of_big(&k);
        let (xl, yl) = (limbs_big(&x), limbs_big(&y));
        let limbwise = |f: &dyn Fn(usize) -> BigUint| -> Vec<F> {
            (0..LIMBS)
                .map(|index| field_of_big::<F>(&f(index)))
                .collect()
        };
        let (xm, ym) = (&x % &m, &y % &m);
        let sum = (&xm + &ym) % &m;
        let difference = (&xm + &m - &ym) % &m;
        let mut public = Vec::new();
        public.extend(limbwise(&|i| &xl[i] + &yl[i]));
        public.extend(limbwise(&|i| &xl[i] + &padding[i] - &yl[i]));
        public.extend(limbwise(&|i| &padding[i] - &yl[i]));
        public.extend(limbwise(&|i| &xl[i] * 5_u8));
        public.extend(limb_fields_big::<F>(&((&difference * &sum) % &m)));
        public.extend(limb_fields_big::<F>(&((&xm * &xm) % &m)));
        public.extend(limb_fields_big::<F>(&((&xm * &k) % &m)));
        public.extend(limbwise(&|i| {
            if bit == 1 {
                xl[i].clone()
            } else {
                yl[i].clone()
            }
        }));
        public.extend(limb_fields_big::<F>(&((&sum * 64_u8) % &m)));
        public.extend(limb_fields_big::<F>(&((&difference * 8_u8) % &m)));
        public.push(field_of_big::<F>(&x));
        let circuit = FfCircuit::new(
            &[modulus],
            public.len(),
            linear_program::<F>,
            vec![words_of_big(&x), words_of_big(&y), k_words, [bit, 0, 0, 0]],
            &[
                modulus_index,
                k_words[0],
                k_words[1],
                k_words[2],
                k_words[3],
            ],
        );
        assert_accepts(&circuit, &public, "linear operations");
    }
}

#[test]
fn ff_linear_operations_match_bigint() {
    linear_case::<Fp>(FQ_INDEX, 31);
    linear_case::<Fq>(P256_P_INDEX, 32);
}

// ---------------------------------------------------------------------------
// Moduli, padding, admissibility and the executable carry memo.
// ---------------------------------------------------------------------------

#[test]
fn ff_moduli_match_their_references() {
    let parse = |hex: &str| BigUint::parse_bytes(hex.as_bytes(), 16).expect("hex");
    let field_order = |modulus: &str| parse(modulus.trim_start_matches("0x"));
    assert_eq!(
        modulus_big(ForeignModulus::PASTA_FP),
        field_order(Fp::MODULUS)
    );
    assert_eq!(
        modulus_big(ForeignModulus::PASTA_FQ),
        field_order(Fq::MODULUS)
    );
    assert_eq!(
        modulus_big(ForeignModulus::P256_BASE),
        parse("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    );
    assert_eq!(
        modulus_big(ForeignModulus::P256_ORDER),
        parse("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    );
    for modulus in MODULI {
        assert_eq!(ForeignModulus::new(modulus.words()), Some(modulus));
        let m = modulus_big(modulus);
        let limbs = modulus.limbs();
        assert_eq!(limbs.map(BigUint::from).to_vec(), limbs_big(&m).to_vec());
        assert!(limbs[2] < 1 << TOP_LIMB_BITS);
        assert_eq!(
            modulus.limbs_minus_one().map(BigUint::from).to_vec(),
            limbs_big(&(m - 1_u8)).to_vec()
        );
    }
    // Even moduli and moduli below 2^252 are rejected.
    assert_eq!(ForeignModulus::new([2, 0, 0, 1 << 62]), None);
    assert_eq!(ForeignModulus::new([1, 0, 0, 1 << 59]), None);
    assert!(ForeignModulus::new([1, 0, 0, 1 << 60]).is_some());
}

#[test]
fn ff_padding_is_a_dominating_multiple() {
    let floors_cases = [
        PROPER_BOUNDS,
        [0, 0, 0],
        [OPERAND_LIMB_MAX; 3],
        [1 << 90, 3, 1 << 85],
    ];
    for modulus in MODULI {
        let m = modulus_big(modulus);
        for floors in floors_cases {
            let (k, limbs) = modulus.padding(&floors).expect("padding");
            let value = from_limbs(&limbs);
            assert_eq!(big_of_nat(&value), big_of_nat(&k) * &m);
            for (limb, floor) in limbs.iter().zip(floors) {
                assert!(*limb >= floor);
            }
            // The low limbs exceed their floors by less than B.
            assert!(limbs[0] - floors[0] < 1 << LIMB_BITS);
            assert!(limbs[1] - floors[1] < 1 << LIMB_BITS);
        }
        let (k, limbs) = modulus.division_padding().expect("division padding");
        // The division padding dominates every operand limb.
        assert!(limbs.iter().all(|limb| *limb >= OPERAND_LIMB_MAX));
        assert!(big_of_nat(&k) < BigUint::from(1_u8) << 20_usize);
        assert!(big_of_nat(&from_limbs(&limbs)) < BigUint::from(1_u8) << 270_usize);
    }
}

#[test]
fn ff_admissibility_matches_the_quotient_bound() {
    for modulus in MODULI {
        // Proper by proper is always admissible (m >= 2^252).
        assert!(FfChip::<Fq>::mul_admissible(
            modulus,
            &PROPER_BOUNDS,
            &PROPER_BOUNDS
        ));
        assert!(FfChip::<Fq>::div_admissible(
            modulus,
            &PROPER_BOUNDS,
            &PROPER_BOUNDS
        ));
        // Sums of two proper values (limbs < 2^88) multiply.
        let doubled = add_bounds(&PROPER_BOUNDS, &PROPER_BOUNDS).expect("bounds");
        assert!(FfChip::<Fq>::mul_admissible(modulus, &doubled, &doubled));
        // Scaling a proper value stays in the envelope up to k = 128.
        assert!(scale_bounds(&PROPER_BOUNDS, 128).is_some_and(|bounds| within_envelope(&bounds)));
        assert!(!scale_bounds(&PROPER_BOUNDS, 129).is_some_and(|bounds| within_envelope(&bounds)));
        assert_eq!(scale_bounds(&[u128::MAX, 0, 0], 2), None);
        assert_eq!(add_bounds(&[u128::MAX, 0, 0], &[1, 0, 0]), None);
        // A limb past the envelope is never admissible.
        let wide = [OPERAND_LIMB_MAX + 1, 0, 0];
        assert!(!FfChip::<Fq>::mul_admissible(modulus, &wide, &[1, 0, 0]));
        assert!(!FfChip::<Fq>::div_admissible(modulus, &[1, 0, 0], &wide));
        // Envelope-wide values are too large to multiply.
        let envelope = [OPERAND_LIMB_MAX; 3];
        assert!(!FfChip::<Fq>::mul_admissible(modulus, &envelope, &envelope));
        assert!(!FfChip::<Fq>::div_admissible(
            modulus,
            &[1, 0, 0],
            &envelope
        ));
        // The threshold is the quotient bound m 2^261: a = 2^256 times
        // b = 32 m - 1 is admissible, times 32 m is not.
        let m = modulus_big(modulus);
        let exact_limbs = |value: &BigUint| -> [u128; LIMBS] {
            limbs_big(value).map(|limb| u128::try_from(&limb).expect("limb"))
        };
        let a = exact_limbs(&(BigUint::from(1_u8) << 256_usize));
        let below = exact_limbs(&(&m * 32_u8 - 1_u8));
        let at = exact_limbs(&(&m * 32_u8));
        assert!(FfChip::<Fq>::mul_admissible(modulus, &a, &below));
        assert!(!FfChip::<Fq>::mul_admissible(modulus, &a, &at));
    }
}

/// Exact signed carry intervals of `P R - S + K - q m` for limb bounds.
fn carry_intervals(
    p: &[BigUint; LIMBS],
    r: &[BigUint; LIMBS],
    s: &[BigUint; LIMBS],
    padding: &[BigUint; LIMBS],
    quotient: &[BigUint; LIMBS],
    modulus: &[BigUint; LIMBS],
) -> Vec<(BigInt, BigInt, BigUint)> {
    let radix = BigInt::from(1_u8) << LIMB_BITS;
    let (mut low, mut high) = (BigInt::from(0_u8), BigInt::from(0_u8));
    let mut out = Vec::new();
    for column in 0..CARRIES {
        let mut positive = BigUint::from(0_u8);
        let mut negative = BigUint::from(0_u8);
        for i in 0..LIMBS {
            if let Some(j) = column.checked_sub(i).filter(|j| *j < LIMBS) {
                positive += &p[i] * &r[j];
                negative += &quotient[i] * &modulus[j];
            }
        }
        if column < LIMBS {
            positive += &padding[column];
            negative += &s[column];
        }
        let new_high = (BigInt::from(positive.clone()) + &high).div_floor_big(&radix);
        let new_low = -(BigInt::from(negative.clone()) - &low).div_ceil_big(&radix);
        low = new_low;
        high = new_high;
        out.push((low.clone(), high.clone(), positive + negative));
    }
    out
}

trait DivBig {
    fn div_floor_big(&self, divisor: &BigInt) -> BigInt;
    fn div_ceil_big(&self, divisor: &BigInt) -> BigInt;
}

impl DivBig for BigInt {
    fn div_floor_big(&self, divisor: &BigInt) -> BigInt {
        let quotient = self / divisor;
        if (self % divisor) < BigInt::from(0_u8) {
            quotient - 1_u8
        } else {
            quotient
        }
    }

    fn div_ceil_big(&self, divisor: &BigInt) -> BigInt {
        -((-self).div_floor_big(divisor))
    }
}

/// The carry-bound memo (M3 gate G3.4, re-established for the one-column
/// range table of M3 decision D1), recomputed exactly for every modulus in
/// both native fields:
///
/// 0. Lemma 1: a top sublimb of `w < 15` bits looked up as `v` and as
///    `2^(15-w) v` in the 15-bit table is an integer below `2^w` (the
///    scaled value of a table entry is below `2^30 < N`, so it cannot
///    wrap), and the running sums give exactly the documented limb widths
///    (`87, 87, 82` for values, `87` for quotients, `105` for offset
///    carries), all far below `N`;
/// 1. honest carries of envelope operands (limbs below `2^94`) fit
///    `[-2^104, 2^104)`, for multiplication and division;
/// 2. no carry equation can wrap modulo `N` for any range-checked
///    assignment (so each is an integer equation);
/// 3. `|a b - c - q m| < N 2^348` for every range-checked assignment
///    (so the CRT conclusion `a b = c + q m` holds);
/// 4. the comparison equations cannot wrap.
#[test]
fn ff_carry_memo_bounds_hold_for_every_modulus() {
    let one = BigUint::from(1_u8);
    let natives = [
        modulus_big(ForeignModulus::PASTA_FP),
        modulus_big(ForeignModulus::PASTA_FQ),
    ];
    // Lemma 1, two-membership tops: exhaustively, `v < 2^15` and
    // `2^(15 - w) v < 2^15` iff `v < 2^w`; the scaled entry cannot wrap.
    let table = 1_u64 << SUBLIMB_BITS;
    for native in &natives {
        assert!((&one << (2 * SUBLIMB_BITS)) < *native);
    }
    for width in VALUE_TOPS.iter().chain(&QUOTIENT_TOPS) {
        assert!(*width < SUBLIMB_BITS);
        let scale = 1_u64 << (SUBLIMB_BITS - width);
        for v in 0..table {
            assert_eq!(v * scale < table, v < 1 << width, "width {width} value {v}");
        }
    }
    // Lemma 1, running sums: `L - 1` full sublimbs and a top of `w` bits.
    let running = |sublimbs: usize, top: usize| SUBLIMB_BITS * (sublimbs - 1) + top;
    assert_eq!(
        VALUE_TOPS.map(|top| running(LIMB_SUBLIMBS, top)),
        [LIMB_BITS, LIMB_BITS, TOP_LIMB_BITS]
    );
    assert_eq!(
        QUOTIENT_TOPS.map(|top| running(LIMB_SUBLIMBS, top)),
        [LIMB_BITS; LIMBS]
    );
    assert_eq!(QUOTIENT_BITS, LIMBS * LIMB_BITS);
    assert_eq!(running(CARRY_SUBLIMBS, SUBLIMB_BITS), CARRY_OFFSET_BITS + 1);
    for native in &natives {
        // Every intermediate `z_j = s_j + 2^15 z_{j+1}` is below 2^105.
        assert!((&one << (CARRY_OFFSET_BITS + 1)) < *native);
    }
    // The block geometry the gates read: operands on row 0, `C`/`Q` roots on
    // row 1 (their six entries end on the top row 6), `U` roots on row 0
    // (seven entries).
    assert_eq!(OPERAND_ROW, 0);
    assert_eq!(ROOT_ROW + LIMB_SUBLIMBS, BLOCK_ROWS);
    assert_eq!(CARRY_SUBLIMBS, BLOCK_ROWS);
    assert_eq!(
        TOP_ROTATION,
        Rotation(i32::try_from(BLOCK_ROWS - 1).expect("rows"))
    );
    let proper = PROPER_BOUNDS.map(BigUint::from);
    let envelope: [BigUint; LIMBS] = core::array::from_fn(|_| BigUint::from(OPERAND_LIMB_MAX));
    let quotient: [BigUint; LIMBS] = core::array::from_fn(|_| (&one << LIMB_BITS) - 1_u8);
    let zero: [BigUint; LIMBS] = core::array::from_fn(|_| BigUint::from(0_u8));
    let carry_limit = BigInt::from(1_u8) << CARRY_OFFSET_BITS;
    let radix = &one << LIMB_BITS;
    for modulus in MODULI {
        let m_limbs = modulus.limbs().map(BigUint::from);
        let (_, padding) = modulus.division_padding().expect("padding");
        let padding = padding.map(BigUint::from);
        let cases = [
            ("mul", &envelope, &envelope, &proper, &zero),
            ("div", &envelope, &proper, &envelope, &padding),
        ];
        for (name, p, r, s, k) in cases {
            for (column, (low, high, spread)) in carry_intervals(p, r, s, k, &quotient, &m_limbs)
                .into_iter()
                .enumerate()
            {
                assert!(
                    -&carry_limit <= low && high < carry_limit,
                    "{modulus:?} {name} carry {column}: [{low}, {high}]"
                );
                // |t_k + u_{k-1} - u_k B| <= spread + 2^104 + 2^104 B < N.
                let worst = spread + (&one << CARRY_OFFSET_BITS) * (&radix + 1_u8);
                for native in &natives {
                    assert!(&worst < native, "{modulus:?} {name} column {column} wraps");
                }
            }
        }
        // CRT: every range-checked assignment has |X| < N 2^348.
        let value = |limbs: &[BigUint; LIMBS]| {
            &limbs[0] + (&limbs[1] << LIMB_BITS) + (&limbs[2] << (2 * LIMB_BITS))
        };
        let m = modulus_big(modulus);
        let positive = value(&envelope) * value(&envelope) + value(&padding);
        let negative = value(&envelope) + value(&quotient) * &m;
        for native in &natives {
            let limit = native << (4 * LIMB_BITS);
            assert!(positive < limit && negative < limit, "{modulus:?} CRT");
        }
        // Comparison: |x + d - (m-1) - beta B^2| on the low limbs < N.
        let compare_worst = (&radix * 4_u8) + (&radix * &radix * 4_u8);
        for native in &natives {
            assert!(&compare_worst < native);
        }
    }
}

// ---------------------------------------------------------------------------
// Misuse, multiple moduli and the gate shape.
// ---------------------------------------------------------------------------

/// `args = [first modulus, second modulus]`: a product in each modulus;
/// mixing the two is an error the program checks.
fn two_moduli_program<F: PastaField>(
    ff: &mut FfChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let first = modulus_at(args[0])?;
    let second = modulus_at(args[1])?;
    let a = ff.witness(region, first, inputs[0])?;
    let b = ff.witness(region, second, inputs[1])?;
    if ff.mul(region, &a, &b).is_ok()
        || ff.add(glue, region, &a, &b).is_ok()
        || FfChip::assert_equal(region, &a, &b).is_ok()
        || ff
            .witness(region, ForeignModulus::PASTA_FP, inputs[0])
            .is_ok()
    {
        return Err(Error::Synthesis);
    }
    let a2 = ff.square(region, &a)?;
    let b2 = ff.square(region, &b)?;
    let mut out = limb_words(&a2);
    out.extend(limb_words(&b2));
    Ok(out)
}

#[test]
fn ff_two_moduli_share_the_columns_and_misuse_is_rejected() {
    let (p, n) = (ForeignModulus::P256_BASE, ForeignModulus::P256_ORDER);
    let a = BigUint::from(0x1234_5678_u64) << 200_usize;
    let b = modulus_big(n) - 1_u8;
    let mut public = limb_fields_big::<Fq>(&((&a * &a) % modulus_big(p)));
    public.extend(limb_fields_big::<Fq>(&((&b * &b) % modulus_big(n))));
    let circuit = FfCircuit::new(
        &[p, n, p],
        6,
        two_moduli_program::<Fq>,
        vec![words_of_big(&a), words_of_big(&b)],
        &[P256_P_INDEX, P256_N_INDEX],
    );
    let (cs, config) = configure(&circuit).expect("configure");
    assert_eq!(config.0.moduli(), vec![p, n]);
    // Two moduli: 8 gates of the chip plus the 4 glue gates.
    assert_eq!(cs.gates().len(), 12);
    assert_accepts(&circuit, &public, "P-256 p and n");
}

#[test]
fn ff_gate_shape_and_degree() {
    let circuit = FfCircuit::new(
        &[ForeignModulus::P256_BASE],
        3,
        mul_program::<Fq>,
        vec![[3, 0, 0, 0], [5, 0, 0, 0]],
        &[P256_P_INDEX],
    );
    let (cs, config) = configure(&circuit).expect("configure");
    let (ff, _, _, _) = config;
    // Gates have degree 3; the `C`/`Q` lookups (degree-3 inputs from the
    // ternary patterns) have degree 6 and the `U` lookups degree 5: within
    // the crate policy of 6.
    assert_eq!(cs.degree(), 6);
    assert!(cs.degree() <= crate::MAX_GATE_DEGREE);
    for gate in cs.gates() {
        for polynomial in gate.polynomials() {
            assert!(polynomial.degree() <= 3, "{}", gate.name());
        }
    }
    assert_eq!(cs.lookups().len(), FF_ADVICE_COLUMNS);
    for (index, lookup) in cs.lookups().iter().enumerate() {
        // One width-1 argument per column, into `V`.
        assert_eq!(lookup.width(), 1);
        let expected = if index < 2 * LIMBS { 6 } else { 5 };
        assert_eq!(lookup.required_degree(), expected, "{}", lookup.name());
    }
    // Three queries per operand column (rotations 0, 1, 6): no extra
    // blinding rows.
    assert_eq!(cs.blinding_factors(), 5);
    assert_eq!(ff.advice_columns().len(), FF_ADVICE_COLUMNS);
    // Four pattern columns and the table column; the glue chip adds its six
    // coefficient columns and the constants column.
    assert_eq!(ff.pattern_columns().len(), 4);
    assert_eq!(cs.num_fixed_columns(), FF_PATTERN_COLUMNS + 1 + 6 + 1);
    assert!(cs.usable_rows(K).expect("usable") > RANGE_TABLE_ROWS);
    assert_eq!(RANGE_TABLE_ROWS, 32_768);
}

/// The range table holds exactly the 15-bit values, and a running sum's
/// lookups are active on exactly the block rows the layout documents: `C`
/// and `Q` steps on rows 1..=5, their tops on row 6 (plain) and row 0
/// (scaled, through rotation 6), `U` steps on rows 0..=5 and its top on
/// row 6. The patterns are fixed: the same for every witness.
#[test]
fn ff_range_patterns_follow_the_block_layout() {
    let circuit = FfCircuit::new(
        &[ForeignModulus::P256_BASE],
        3,
        mul_program::<Fq>,
        vec![[3, 0, 0, 0], [5, 0, 0, 0]],
        &[P256_P_INDEX],
    );
    let public = limb_fields_big::<Fq>(&BigUint::from(15_u8));
    let (_, config) = configure(&circuit).expect("configure");
    let (ff, _, _, _) = config;
    let synthesized = synthesize(&circuit, K, Some(&[public][..])).expect("synthesis");
    let fixed = synthesized.tables.fixed();
    let value = &fixed[ff.value_column().index()];
    for (row, entry) in value.iter().enumerate().take(RANGE_TABLE_ROWS) {
        assert_eq!(*entry, Fq::from(u64::try_from(row).expect("row")));
    }
    assert!(
        value[RANGE_TABLE_ROWS..]
            .iter()
            .all(|entry| *entry == Fq::ZERO)
    );
    let [h_c, h_q, s_u, t_u] = ff.pattern_columns().map(|column| &fixed[column.index()]);
    // Three blocks: two witnesses (C only) and one product (C, Q, U).
    let two = Fq::from(2_u64);
    for block in 0..3 {
        let start = block * BLOCK_ROWS;
        let h_expected = [Fq::ZERO, Fq::ONE, Fq::ONE, Fq::ONE, Fq::ONE, Fq::ONE, two];
        for (offset, expected) in h_expected.iter().enumerate() {
            assert_eq!(h_c[start + offset], *expected, "block {block} row {offset}");
            let q_expected = if block == 2 { *expected } else { Fq::ZERO };
            assert_eq!(
                h_q[start + offset],
                q_expected,
                "block {block} row {offset}"
            );
            let (s, t) = if block == 2 {
                (
                    Fq::from(u64::from(offset < BLOCK_ROWS - 1)),
                    Fq::from(u64::from(offset == BLOCK_ROWS - 1)),
                )
            } else {
                (Fq::ZERO, Fq::ZERO)
            };
            assert_eq!((s_u[start + offset], t_u[start + offset]), (s, t));
        }
    }
    // Nothing else: a top value 2 six rows below a nonzero pattern would
    // enable two terms of one residual on that row.
    for column in [h_c, h_q] {
        for row in 0..column.len() - 6 {
            if column[row + 6] == two {
                assert_eq!(column[row], Fq::ZERO, "row {row}");
            }
        }
        assert!(
            column[3 * BLOCK_ROWS..]
                .iter()
                .all(|entry| *entry == Fq::ZERO)
        );
    }
}

/// Runs the existing fused-block attack at an explicitly chosen final row.
/// `args = [modulus, attack, first_row]`.
fn terminal_attack_program<F: PastaField>(
    ff: &mut FfChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    *ff = FfChip::starting_at(
        ff.fused_config()?.clone(),
        usize::try_from(args[2]).map_err(|_| Error::Synthesis)?,
    );
    attack_program(ff, glue, region, inputs, args)
}

/// Runs either canonical-comparison binding at a chosen final block.
/// `args = [modulus, mode, first_row]`.
fn terminal_canonical_program<F: PastaField>(
    ff: &mut FfChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    *ff = FfChip::starting_at(
        ff.fused_config()?.clone(),
        usize::try_from(args[2]).map_err(|_| Error::Synthesis)?,
    );
    canonical_program(ff, glue, region, inputs, args)
}

/// Checks the final `+6` lookup, arithmetic roots and comparison copies,
/// including a one-row overflow beyond the usable domain.
fn final_usable_row_case<F: PastaField>(modulus_index: u64, leaf: bool) {
    let modulus = modulus_at(modulus_index).expect("modulus");
    let m = modulus_big(modulus);
    let mut circuit = FfCircuit::new(
        &[modulus],
        0,
        terminal_attack_program::<F>,
        vec![words_of_big(&(&m - 3_u8)), words_of_big(&(&m - 11_u8))],
        &[modulus_index, 0, 0],
    );
    circuit.params.leaf = leaf;
    let (cs, (config, _, _, audit)) = configure(&circuit).expect("configure");
    let usable = cs.usable_rows(K).expect("usable rows");
    // Two proper witnesses followed by a fused multiplication block.
    circuit.args[2] = u64::try_from(usable - 3 * BLOCK_ROWS).expect("row");
    assert_accepts(&circuit, &[], "honest product at final usable row");
    let synthesized = synthesize(&circuit, K, Some(&[Vec::new()][..])).expect("synthesis");
    for column in config.advice_columns() {
        assert!(synthesized.tables.advice_assigned()[column.index()][usable - 1]);
    }
    if let Some(audit) = audit {
        assert_eq!(audit.audit(&synthesized.tables), Ok(()));
    }
    // The overflowing quotient digit passes plain membership at the final
    // row, but the scaled membership six rows earlier must still reject it.
    circuit.args[1] = 4;
    let rejected = check(&circuit, &[]);
    assert_eq!(
        range_rejections(&rejected),
        Some(vec!["ff q_0 range".into()])
    );
    assert!(rejected.failures().iter().all(|failure| matches!(
        failure,
        CheckFailure::LookupInputMissing { location, .. }
            if location.row == usable - BLOCK_ROWS
    )));
    circuit.args[1] = 0;
    circuit.args[2] += 1;
    assert!(matches!(
        synthesize(&circuit, K, Some(&[Vec::new()][..])),
        Err(Error::RowOutOfRange { row, usable_rows }) if row == usable && usable_rows == usable
    ));

    // Both a canonical witness and a copied proper witness bind their
    // comparison difference to the last row's Q running sum.
    for mode in [0, 1] {
        let mut canonical = FfCircuit::new(
            &[modulus],
            3,
            terminal_canonical_program::<F>,
            vec![words_of_big(&(&m - 1_u8))],
            &[
                modulus_index,
                mode,
                u64::try_from(usable - BLOCK_ROWS).expect("row"),
            ],
        );
        canonical.params.leaf = leaf;
        assert_accepts(
            &canonical,
            &limb_fields_big::<F>(&(&m - 1_u8)),
            "canonical comparison at final usable row",
        );
        canonical.inputs[0] = words_of_big(&m);
        let rejected = check(&canonical, &limb_fields_big::<F>(&m));
        assert_eq!(
            range_rejections(&rejected),
            Some(vec!["ff q_2 range".into()])
        );
        assert!(rejected.failures().iter().any(|failure| matches!(
            failure,
            CheckFailure::LookupInputMissing { location, .. } if location.row == usable - 1
        )));
    }
}

#[test]
fn ff_final_usable_row_binds_fused_and_comparison_blocks() {
    // The private range-table configuration supports all four moduli in
    // either native field, including a modulus equal to the native order.
    for modulus in [FP_INDEX, FQ_INDEX, P256_P_INDEX, P256_N_INDEX] {
        final_usable_row_case::<Fp>(modulus, false);
        final_usable_row_case::<Fq>(modulus, false);
    }
    // QLeafConfig configures exactly P-256 p and n; the shared-table
    // matrix therefore contains only those supported moduli.
    for modulus in [P256_P_INDEX, P256_N_INDEX] {
        final_usable_row_case::<Fp>(modulus, true);
        final_usable_row_case::<Fq>(modulus, true);
    }
}

/// Isolates all four carry range arguments from the arithmetic equations.
/// `args = [outside, first_row]`; the valid signed carries are the two
/// endpoints and their adjacent interior values. The invalid values sit one
/// and two beyond either endpoint, represented after adding the offset.
fn carry_endpoints_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    _inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    *ff = FfChip::starting_at(
        ff.fused_config()?.clone(),
        usize::try_from(args[1]).map_err(|_| Error::Synthesis)?,
    );
    let start = ff.block(&[Group::U])?;
    ff.activate(region, start, Group::U)?;
    let limit = F::from_u128(1 << (CARRY_OFFSET_BITS + 1));
    let two = F::from(2_u64);
    let entries = if args[0] == 0 {
        [F::ZERO, F::ONE, limit - two, limit - F::ONE]
    } else {
        [-F::ONE, -two, limit, limit + F::ONE]
    };
    for (column, entry) in ff.fused_config()?.u.iter().zip(entries) {
        FfChip::running_sum(region, *column, start, CARRY_SUBLIMBS, Value::known(entry))?;
    }
    Ok(Vec::new())
}

/// Carry bounds are modulus-independent; exercise both native fields and
/// both the private range table and the Q leaf's merged `u_0` argument.
fn carry_endpoints_case<F: PastaField>(leaf: bool) {
    let mut circuit = FfCircuit::new(
        &[ForeignModulus::P256_BASE],
        0,
        carry_endpoints_program::<F>,
        Vec::new(),
        &[0, 0],
    );
    circuit.params.leaf = leaf;
    let (cs, _) = configure(&circuit).expect("configure");
    let usable = cs.usable_rows(K).expect("usable rows");
    circuit.args[1] = u64::try_from(usable - BLOCK_ROWS).expect("row");
    assert_accepts(&circuit, &[], "carry endpoints are inclusive");
    circuit.args[0] = 1;
    let rejected = check(&circuit, &[]);
    let names = range_rejections(&rejected).expect("only carry ranges reject");
    assert_eq!(names.len(), CARRIES);
    for index in 0..CARRIES {
        assert!(
            names
                .iter()
                .any(|name| name.starts_with(&format!("ff u_{index} range")))
        );
    }
    assert!(rejected.failures().iter().all(|failure| matches!(
        failure,
        CheckFailure::LookupInputMissing { location, .. } if location.row == usable - 1
    )));
}

#[test]
fn ff_carry_endpoints_are_range_checked_through_the_final_row() {
    carry_endpoints_case::<Fp>(false);
    carry_endpoints_case::<Fq>(false);
    carry_endpoints_case::<Fp>(true);
    carry_endpoints_case::<Fq>(true);
}

/// `args = [modulus, op, count]`: two proper witnesses, then `count`
/// operations `op` (0 multiply, 1 divide, 2 assert canonical, 3 canonical
/// witness); outputs the last result's limbs.
fn inventory_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let mut x = ff.witness(region, modulus, inputs[0])?;
    let y = ff.witness(region, modulus, inputs[1])?;
    for _ in 0..args[2] {
        x = match args[1] {
            0 => ff.mul(region, &x, &y)?,
            1 => ff.div(region, &x, &y)?,
            2 => {
                let proper = ff.witness(region, modulus, inputs[0])?;
                ff.assert_canonical(region, &proper)?
            }
            _ => ff.witness_canonical(region, modulus, inputs[0])?,
        };
    }
    Ok(limb_words(&x))
}

/// Assigned cells and rows of the chip's columns for `count` operations.
fn inventory(op: u64, count: u64) -> (usize, usize, usize) {
    let modulus = ForeignModulus::P256_BASE;
    let m = modulus_big(modulus);
    let (x, y) = (m.clone() - 3_u8, m.clone() - 5_u8);
    let mut value = x.clone();
    for _ in 0..count {
        value = match op {
            0 => (&value * &y) % &m,
            1 => (&value * y.modpow(&(m.clone() - 2_u8), &m)) % &m,
            _ => x.clone(),
        };
    }
    let public = limb_fields_big::<Fq>(&value);
    let circuit = FfCircuit::new(
        &[modulus],
        3,
        inventory_program::<Fq>,
        vec![words_of_big(&x), words_of_big(&y)],
        &[P256_P_INDEX, op, count],
    );
    let synthesized = synthesize(&circuit, K, Some(&[public][..])).expect("synthesis");
    let flags = synthesized.tables.advice_assigned();
    let cells: usize = flags[..FF_ADVICE_COLUMNS]
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .sum();
    // Rows in whole blocks (a witness block leaves its operand row empty).
    let rows = flags[..FF_ADVICE_COLUMNS]
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|flag| *flag)
                .map_or(0, |row| row + 1)
        })
        .max()
        .unwrap_or(0)
        .next_multiple_of(BLOCK_ROWS);
    let glue: usize = flags[FF_ADVICE_COLUMNS..]
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .sum();
    (cells, rows, glue)
}

#[test]
fn ff_inventory_per_operation() {
    // Two proper witnesses take group C of two blocks.
    let (base_cells, base_rows, _) = inventory(0, 0);
    assert_eq!((base_cells, base_rows), (2 * WITNESS_CELLS, 2 * BLOCK_ROWS));
    for (op, cells) in [(0, MUL_CELLS), (1, MUL_CELLS)] {
        let (one, one_rows, glue) = inventory(op, 1);
        let (four, four_rows, _) = inventory(op, 4);
        assert_eq!(one - base_cells, cells, "op {op}");
        assert_eq!((four - one) / 3, cells, "op {op}");
        assert_eq!((four_rows - one_rows) / 3, BLOCK_ROWS, "op {op}");
        assert_eq!(glue, 0, "op {op}");
    }
    // An extra proper witness (group C) and its comparison (group Q) share
    // a block.
    let (one, one_rows, _) = inventory(2, 1);
    assert_eq!(one - base_cells, WITNESS_CELLS + COMPARE_CELLS);
    assert_eq!(one_rows - base_rows, BLOCK_ROWS);
    let (one, one_rows, _) = inventory(3, 1);
    assert_eq!(one - base_cells, CANONICAL_WITNESS_CELLS);
    assert_eq!(one_rows - base_rows, BLOCK_ROWS);
    // Gate G3.4: at most 100 cells per multiplication.
    const { assert!(MUL_CELLS <= 100) };
    assert_eq!(MUL_CELLS, BLOCK_ROWS * FF_ADVICE_COLUMNS);
}

// ---------------------------------------------------------------------------
// Per-cell tamper suites (every assigned advice cell is pinned).
// ---------------------------------------------------------------------------

/// `args = [modulus]`: a product, a quotient, an inverse, a canonical
/// witness, a comparison and the linear operations; outputs every result.
fn tamper_program<F: PastaField>(
    ff: &mut FfChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let a = ff.witness(region, modulus, inputs[0])?;
    let b = ff.witness(region, modulus, inputs[1])?;
    let product = ff.mul(region, &a, &b)?;
    let quotient = ff.div(region, &a, &b)?;
    let inverse = ff.inverse(region, &b)?;
    let canonical = ff.witness_canonical(region, modulus, inputs[2])?;
    let compared = ff.assert_canonical(region, &product)?;
    let bit = glue.boolean(region, Value::known(true))?;
    let sum = ff.add(glue, region, &a, &b)?;
    let difference = ff.sub(glue, region, &a, &b)?;
    let negation = ff.neg(glue, region, &b)?;
    let scaled = ff.scale(glue, region, &a, 3)?;
    let selected = ff.select(glue, region, &bit, &sum, &difference)?;
    let constant = ff.constant(glue, region, modulus, &Nat::from_u64(7))?;
    let by_constant = ff.mul_constant(region, &negation, &Nat::from_u64(9))?;
    let native = FfChip::native(glue, region, &scaled)?;
    let mut out = Vec::new();
    for value in [
        &compared,
        &quotient,
        &inverse,
        &canonical,
        &selected,
        &constant,
        &by_constant,
    ] {
        out.extend(limb_words(value));
    }
    out.push(native);
    Ok(out)
}

fn tamper_case<F: PastaField>(modulus_index: u64) {
    let modulus = MODULI[usize::try_from(modulus_index).expect("index")];
    let m = modulus_big(modulus);
    let (a, b, c) = (m.clone() - 3_u8, m.clone() - 5_u8, m.clone() - 1_u8);
    let inverse = b.modpow(&(m.clone() - 2_u8), &m);
    let al = limbs_big(&a);
    let bl = limbs_big(&b);
    let (_, padding) = modulus.padding(&PROPER_BOUNDS).expect("padding");
    let padding = padding.map(BigUint::from);
    let selected: Vec<F> = (0..LIMBS)
        .map(|i| field_of_big(&(&al[i] + &bl[i])))
        .collect();
    let negation = &padding[0] + (&padding[1] << LIMB_BITS) + (&padding[2] << (2 * LIMB_BITS)) - &b;
    let scaled = &a * 3_u8;
    let mut public = Vec::new();
    public.extend(limb_fields_big::<F>(&((&a * &b) % &m)));
    public.extend(limb_fields_big::<F>(&((&a * &inverse) % &m)));
    public.extend(limb_fields_big::<F>(&inverse));
    public.extend(limb_fields_big::<F>(&c));
    public.extend(selected);
    public.extend(limb_fields_big::<F>(&BigUint::from(7_u8)));
    public.extend(limb_fields_big::<F>(&((negation * 9_u8) % &m)));
    public.push(field_of_big(&scaled));
    let circuit = FfCircuit::new(
        &[modulus],
        public.len(),
        tamper_program::<F>,
        vec![words_of_big(&a), words_of_big(&b), words_of_big(&c)],
        &[modulus_index],
    );
    assert_accepts(&circuit, &public, "tamper circuit");
    let undetected = undetected_tampers(&circuit, K, &[public]).expect("tamper sweep");
    assert_eq!(undetected, Vec::new(), "unpinned cells");
}

#[test]
#[ignore = "every assigned cell of a k = 16 circuit; run in release"]
fn ff_every_cell_is_pinned_p256_in_fq() {
    tamper_case::<Fq>(P256_P_INDEX);
}

#[test]
#[ignore = "every assigned cell of a k = 16 circuit; run in release"]
fn ff_every_cell_is_pinned_fq_in_fp() {
    tamper_case::<Fp>(FQ_INDEX);
}

// ---------------------------------------------------------------------------
// Release measurement of the gate shape.
// ---------------------------------------------------------------------------

/// `args = [modulus, count]`: `count` chained products.
fn chain_program<F: PastaField>(
    ff: &mut FfChip<F>,
    _glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    inputs: &[Value<[u64; 4]>],
    args: &[u64],
) -> Result<Vec<Word<F>>, Error> {
    let modulus = modulus_at(args[0])?;
    let mut x = ff.witness(region, modulus, inputs[0])?;
    let y = ff.witness(region, modulus, inputs[1])?;
    for _ in 0..args[1] {
        x = ff.mul(region, &x, &y)?;
    }
    Ok(limb_words(&x))
}

/// M3 gate G3.4: cells, rows and columns per multiplication, and a full
/// k = 16 P-256 `p` circuit (9,000 chained products in `Fq`) proved and
/// verified with the KAGEMUSHA transcript on Pallas.
#[test]
#[ignore = "k = 16 proof of 9,000 foreign multiplications; run in release"]
fn ff_gate_shape_measurement_release() {
    const COUNT: u64 = 9_000;
    let modulus = ForeignModulus::P256_BASE;
    let m = modulus_big(modulus);
    let (x, y) = (m.clone() - 3_u8, m.clone() - 5_u8);
    let expected = (&x * y.modpow(&BigUint::from(COUNT), &m)) % &m;
    let public = limb_fields_big::<Fq>(&expected);
    let circuit = FfCircuit::new(
        &[modulus],
        3,
        chain_program::<Fq>,
        vec![words_of_big(&x), words_of_big(&y)],
        &[P256_P_INDEX, COUNT],
    );
    let (cs, _) = configure(&circuit).expect("configure");
    let synthesized =
        synthesize(&circuit, K, Some(core::slice::from_ref(&public))).expect("synthesis");
    let flags = synthesized.tables.advice_assigned();
    let cells: usize = flags[..FF_ADVICE_COLUMNS]
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .sum();
    let rows = flags[..FF_ADVICE_COLUMNS]
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|flag| *flag)
                .map_or(0, |row| row + 1)
        })
        .max()
        .unwrap_or(0);
    let count = usize::try_from(COUNT).expect("count");
    assert_eq!(cells, 2 * WITNESS_CELLS + count * MUL_CELLS);
    assert_eq!(rows, (count + 2) * BLOCK_ROWS);
    let started = Instant::now();
    let report = check_circuit(
        &circuit,
        K,
        core::slice::from_ref(&public),
        CheckMode::Strict,
    )
    .expect("check");
    let check_ms = started.elapsed().as_millis();
    assert!(report.is_satisfied(), "{report}");
    let params = PinnedParams::<Ep>::derive(K).expect("params");
    let mut config = KeygenConfig::new(TranscriptV1::KagemushaPoseidonRp57);
    config.instance_mode = InstanceModeV1::Direct;
    config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    let started = Instant::now();
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("keys");
    let keygen_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let randomness = ProverRandomness::recovery(move |_context: &[u8; 32]| {
        Ok::<_, Infallible>(ChaCha20Rng::from_seed([9; 32]))
    });
    let proof = prove_circuit(
        &params,
        &pk,
        &circuit,
        core::slice::from_ref(&public),
        randomness,
        ProverConfig::default(),
    )
    .expect("proof");
    let prove_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let verified = verify_full(
        &params,
        pk.binding(),
        pk.vk(),
        &[public],
        &proof,
        MemoryBudget::DEFAULT,
    );
    let verify_ms = started.elapsed().as_millis();
    assert_eq!(verified, Ok(()));
    println!(
        "FF_GATE_SHAPE modulus=P256_BASE native=Fq k={K} muls={COUNT} cells_per_mul={MUL_CELLS} \
         rows_per_mul={BLOCK_ROWS} ff_advice_columns={FF_ADVICE_COLUMNS} \
         circuit_advice_columns={} fixed_columns={} lookups={} degree={} ff_cells={cells} \
         ff_rows={rows} usable_rows={} proof_bytes={} check_ms={check_ms} keygen_ms={keygen_ms} \
         prove_ms={prove_ms} verify_ms={verify_ms} available_parallelism={} rayon_threads_env={:?}",
        cs.num_advice_columns(),
        cs.num_fixed_columns(),
        cs.lookups().len(),
        cs.degree(),
        cs.usable_rows(K).expect("usable"),
        proof.len(),
        std::thread::available_parallelism().map_or(0, usize::from),
        std::env::var("RAYON_NUM_THREADS").ok(),
    );
}
