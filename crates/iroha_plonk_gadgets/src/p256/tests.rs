//! Tests of the P-256 chip: the native reference against the `p256` crate,
//! the window layouts and fixed tables, the exception-freeness inequalities
//! of the scalar chains, and circuits in hard and soft modes (the M3 named
//! tests `p256_soft_bit_equals_native_on_wycheproof_prehashed`,
//! `p256_rejects_high_s_r_ge_n_zero` and
//! `p256_complete_for_native_accepted_edge_keys`), messages hashed
//! in-circuit, forged soft-test witnesses, per-cell tamper suites, the
//! degree, the inventory against gates G3.1 and G3.2, and a real proof
//! (release).

use std::time::Instant;

use ::ff::{Field as _, PrimeField as _};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, CheckReport, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, configure, synthesize},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

use super::{
    native::{
        Affine, B, BASE, FixedTable, GX, GY, HALF_N, Jacobian, N, ORDER, P, verify_prehashed,
        windows, words_cmp, words_from_be, words_is_zero, words_lt, words_to_be,
    },
    *,
};
use crate::{
    arith::GlueConfig,
    ff::{FF_ADVICE_COLUMNS, FfConfig},
    q_leaf::{self, QLeafConfig},
    sha256::{SHA256_ADVICE_COLUMNS, Sha256Config},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};

/// The circuit size of every circuit test (the FF range table needs 16).
const K: u32 = 16;

// ---------------------------------------------------------------------------
// Native helpers.
// ---------------------------------------------------------------------------

fn random_words(rng: &mut ChaCha20Rng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

fn random_scalar(rng: &mut ChaCha20Rng) -> [u64; 4] {
    loop {
        let words = random_words(rng);
        if words_lt(&words, &N) && !words_is_zero(&words) {
            return words;
        }
    }
}

/// `-s mod n` when `s` is high.
fn low_s(s: &[u64; 4]) -> [u64; 4] {
    if words_cmp(s, &HALF_N) == core::cmp::Ordering::Greater {
        ORDER.neg(s)
    } else {
        *s
    }
}

/// A signature with nonce `nonce` under the secret key `secret` over the
/// message `message` (not normalized).
fn sign(secret: &[u64; 4], nonce: &[u64; 4], message: &[u64; 4]) -> Option<([u64; 4], [u64; 4])> {
    let point = native::mul(&Affine::GENERATOR, nonce)?;
    let r = ORDER.reduce_once(&point.x);
    if words_is_zero(&r) {
        return None;
    }
    let message = ORDER.reduce_once(message);
    let s = ORDER.mul(
        &ORDER.inverse(nonce),
        &ORDER.add(&message, &ORDER.mul(&r, secret)),
    );
    (!words_is_zero(&s)).then_some((r, s))
}

fn public_key(d: &[u64; 4]) -> Affine {
    native::mul(&Affine::GENERATOR, d).expect("nonzero key")
}

/// The `p256` crate's prehash verdict (any `s`; inputs it cannot
/// represent, such as an invalid key or `r >= n`, are rejected).
fn oracle_verify(e: &[u64; 4], r: &[u64; 4], s: &[u64; 4], key: &Affine) -> bool {
    let mut sec1 = vec![4_u8];
    sec1.extend_from_slice(&words_to_be(&key.x));
    sec1.extend_from_slice(&words_to_be(&key.y));
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&words_to_be(r));
    bytes[32..].copy_from_slice(&words_to_be(s));
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    verifying
        .verify_prehash(&words_to_be(e), &signature)
        .is_ok()
}

/// The KAGEMUSHA verdict from the oracle: standard ECDSA plus low-S.
fn oracle_kagemusha(e: &[u64; 4], r: &[u64; 4], s: &[u64; 4], key: &Affine) -> bool {
    oracle_verify(e, r, s, key) && words_cmp(s, &HALF_N) != core::cmp::Ordering::Greater
}

// ---------------------------------------------------------------------------
// Native tests.
// ---------------------------------------------------------------------------

#[test]
fn native_constants_and_field_arithmetic() {
    assert!(Affine::GENERATOR.is_valid());
    assert!(native::on_curve(&GX, &GY));
    assert!(!native::on_curve(&GX, &BASE.add(&GY, &[1, 0, 0, 0])));
    // n G = O and (n - 1) G = -G.
    assert!(native::mul(&Affine::GENERATOR, &N).is_none());
    let minus_one = ORDER.neg(&[1, 0, 0, 0]);
    assert_eq!(
        native::mul(&Affine::GENERATOR, &minus_one),
        Some(Affine::GENERATOR.neg())
    );
    // (n - 1) / 2.
    let doubled = ORDER.add(&HALF_N, &HALF_N);
    assert_eq!(doubled, minus_one);
    // Montgomery arithmetic against Nat.
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for (mont, modulus) in [
        (&BASE, ForeignModulus::P256_BASE),
        (&ORDER, ForeignModulus::P256_ORDER),
    ] {
        for _ in 0..64 {
            let a = modulus
                .reduce(&Nat::from_words(random_words(&mut rng)))
                .low_words();
            let b = modulus
                .reduce(&Nat::from_words(random_words(&mut rng)))
                .low_words();
            let (na, nb) = (Nat::from_words(a), Nat::from_words(b));
            assert_eq!(mont.mul(&a, &b), modulus.mul(&na, &nb).low_words());
            assert_eq!(mont.add(&a, &b), modulus.add(&na, &nb).low_words());
            assert_eq!(mont.sub(&a, &b), modulus.sub(&na, &nb).low_words());
            assert_eq!(mont.inverse(&a), modulus.fermat_inverse(&na).low_words());
        }
        assert_eq!(mont.inverse(&[0; 4]), [0; 4]);
        assert_eq!(mont.modulus(), modulus.words());
    }
    assert_eq!(words_from_be(&words_to_be(&GX)), GX);
    assert_eq!(
        B,
        words_from_be(&{
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(&words_to_be(&B));
            bytes
        })
    );
    assert_eq!(
        (P, N),
        (
            ForeignModulus::P256_BASE.words(),
            ForeignModulus::P256_ORDER.words()
        )
    );
}

#[test]
fn native_group_law_matches_the_p256_crate() {
    use p256::{
        ProjectivePoint, Scalar,
        elliptic_curve::{PrimeField as _, sec1::ToEncodedPoint as _},
    };
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for _ in 0..8 {
        let k = random_scalar(&mut rng);
        let mine = native::mul(&Affine::GENERATOR, &k).expect("nonzero");
        let scalar =
            Option::<Scalar>::from(Scalar::from_repr(words_to_be(&k).into())).expect("canonical");
        let theirs = (ProjectivePoint::GENERATOR * scalar).to_affine();
        let encoded = theirs.to_encoded_point(false);
        assert_eq!(
            encoded.x().map(|x| x.as_slice().to_vec()),
            Some(words_to_be(&mine.x).to_vec())
        );
        assert_eq!(
            encoded.y().map(|y| y.as_slice().to_vec()),
            Some(words_to_be(&mine.y).to_vec())
        );
        // Jacobian doubling and addition agree with scalar multiplication.
        let point = Jacobian::from_affine(&mine);
        let three = point.double().add(&point).to_affine();
        assert_eq!(three, native::mul(&mine, &[3, 0, 0, 0]));
        assert!(point.add(&point.neg()).is_identity());
    }
}

#[test]
fn native_verdict_matches_the_p256_crate_with_low_s() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for round in 0..24 {
        let secret = random_scalar(&mut rng);
        let key = public_key(&secret);
        let e = random_words(&mut rng);
        let nonce = random_scalar(&mut rng);
        let (r, s) = sign(&secret, &nonce, &e).expect("signature");
        let low = low_s(&s);
        let high = ORDER.neg(&low);
        assert!(verify_prehashed(&e, &r, &low, &key), "round {round}");
        assert!(!verify_prehashed(&e, &r, &high, &key), "round {round}");
        assert!(oracle_kagemusha(&e, &r, &low, &key));
        assert!(!oracle_kagemusha(&e, &r, &high, &key));
        assert!(oracle_verify(&e, &r, &high, &key));
        // A wrong message, key or r.
        let other = ORDER.add(&ORDER.reduce_once(&e), &[1, 0, 0, 0]);
        assert!(!verify_prehashed(&other, &r, &low, &key));
        assert!(!oracle_kagemusha(&other, &r, &low, &key));
        let wrong_key = public_key(&random_scalar(&mut rng));
        assert!(!verify_prehashed(&e, &r, &low, &wrong_key));
        assert!(!verify_prehashed(
            &e,
            &ORDER.add(&r, &[1, 0, 0, 0]),
            &low,
            &key
        ));
    }
}

#[test]
fn native_helpers_match_their_definitions() {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    // Word comparisons.
    let (a, b) = (random_words(&mut rng), random_words(&mut rng));
    assert_eq!(
        words_cmp(&a, &b),
        Nat::from_words(a).cmp_vartime(&Nat::from_words(b))
    );
    assert_eq!(
        words_lt(&a, &b),
        words_cmp(&a, &b) == core::cmp::Ordering::Less
    );
    assert!(words_is_zero(&[0; 4]) && !words_is_zero(&[0, 0, 0, 1]));
    // Limbs recompose, powers of two.
    let limbs = native::limbs_of(&a);
    assert_eq!(crate::ff::from_limbs(&limbs).low_words(), a);
    for bits in [0_usize, 63, 64, 200, 255] {
        let width = u32::try_from(bits).expect("bits");
        assert_eq!(native::pow2_words(width), Nat::pow2(bits).low_words());
    }
    // Batch normalization and the joint multiple.
    let points: Vec<Jacobian> = (1..=5_u64)
        .map(|k| native::mul_jacobian(&Jacobian::from_affine(&Affine::GENERATOR), &[k, 0, 0, 0]))
        .collect();
    let batch = native::batch_to_affine(&points).expect("finite points");
    for (point, affine) in points.iter().zip(&batch) {
        assert_eq!(point.to_affine(), Some(*affine));
    }
    assert!(native::batch_to_affine(&[points[0], Jacobian::IDENTITY]).is_none());
    let (u, v) = (random_scalar(&mut rng), random_scalar(&mut rng));
    let key = public_key(&random_scalar(&mut rng));
    let joint = native::mul_add(&Affine::GENERATOR, &u, &key, &v);
    let separate = Jacobian::from_affine(&native::mul(&Affine::GENERATOR, &u).expect("uG"))
        .add(&Jacobian::from_affine(&native::mul(&key, &v).expect("vQ")))
        .to_affine();
    assert_eq!(joint, separate);
    // Fixed-base tags are distinct and below the dynamic tags (2^32).
    let mut tags: Vec<u64> = (0..8)
        .flat_map(|base| (0..33).map(move |window| window::fixed_tag(base, window)))
        .collect();
    let count = tags.len();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), count);
    assert!(tags.iter().all(|tag| *tag > 0 && *tag < 1 << 32));
}

#[test]
fn window_layouts_cover_the_limbs() {
    let four = windows(4);
    let eight = windows(8);
    assert_eq!((four.len(), eight.len()), (65, 33));
    for layout in [&four, &eight] {
        let mut covered = 0_u32;
        for window in layout {
            let limb = u32::try_from(window.limb).expect("limb");
            assert_eq!(window.position, 87 * limb + window.offset);
            assert!(window.bits > 0);
            covered += window.bits;
        }
        assert_eq!(covered, 256);
    }
    let shifts: Vec<u32> = four
        .windows(2)
        .map(|pair| pair[1].position - pair[0].position)
        .collect();
    assert_eq!(shifts.iter().filter(|shift| **shift == 3).count(), 2);
    assert!(shifts.iter().all(|shift| *shift == 3 || *shift == 4));
    assert_eq!(four.last().map(|w| (w.position, w.bits)), Some((254, 2)));
    assert_eq!(eight.last().map(|w| (w.position, w.bits)), Some((254, 2)));
    // Digits recompose the value.
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    for layout in [&four, &eight] {
        let value = random_words(&mut rng);
        let digits = native::window_digits(&value, layout);
        let total = layout
            .iter()
            .zip(&digits)
            .fold(Nat::ZERO, |acc, (window, digit)| {
                acc.wrapping_add(&Nat::from_u64(*digit).shl(window.position as usize))
            });
        assert_eq!(total.low_words(), value);
    }
}

#[test]
fn fixed_tables_hold_the_offset_multiples() {
    let table = generator_table().expect("generator table");
    assert_eq!(table.rows(), 7940);
    let top = table.windows.len() - 1;
    let offset_sum = table.windows[..top].iter().fold(Nat::ZERO, |acc, window| {
        acc.wrapping_add(&Nat::pow2(window.position as usize))
    });
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    for _ in 0..6 {
        let count = u64::try_from(table.windows.len()).expect("count");
        let index = usize::try_from(rng.next_u64() % count).expect("index");
        let window = table.windows[index];
        let digit = rng.next_u64() % (1 << window.bits);
        let scalar = if index == top {
            let positive = Nat::from_u64(digit).shl(window.position as usize);
            ForeignModulus::P256_ORDER.sub(&positive, &offset_sum.wrapping_add(&offset_sum))
        } else {
            ForeignModulus::P256_ORDER
                .reduce(&Nat::from_u64(digit + 2).shl(window.position as usize))
        };
        let expected = native::mul(&Affine::GENERATOR, &scalar.low_words());
        let position = usize::try_from(digit).expect("digit");
        assert_eq!(
            Some(table.entries[index][position]),
            expected,
            "window {index} digit {digit}"
        );
    }
    // A sum of window entries is the scalar multiple.
    let k = random_scalar(&mut rng);
    let digits = native::window_digits(&k, &table.windows);
    let total = digits
        .iter()
        .enumerate()
        .fold(Jacobian::IDENTITY, |acc, (index, digit)| {
            let position = usize::try_from(*digit).expect("digit");
            acc.add(&Jacobian::from_affine(&table.entries[index][position]))
        });
    assert_eq!(total.to_affine(), native::mul(&Affine::GENERATOR, &k));
    // A fixed key's table.
    let key = public_key(&random_scalar(&mut rng));
    let key_table = FixedTable::new(&key, 8).expect("key table");
    assert_eq!(key_table.rows(), 7940);
}

/// The exception-freeness inequalities of the fixed-base sums (module
/// documentation): for every window below the top, the largest partial sum
/// is below twice the window weight, and the largest sum below `n`.
#[test]
fn fixed_base_partial_sums_are_exception_free() {
    let layout = windows(8);
    let top = layout.len() - 1;
    let n = Nat::from_words(N);
    let mut max_partial = Nat::ZERO;
    for (index, window) in layout.iter().enumerate().take(top) {
        let weight = Nat::pow2(window.position as usize);
        if index > 0 {
            // A_w <= max partial sum < 2 W_w <= (d_w + 2) W_w.
            assert_eq!(
                max_partial.cmp_vartime(&weight.wrapping_add(&weight)),
                core::cmp::Ordering::Less,
                "window {index}"
            );
            // A_w >= 2 sum W_v > 0.
        }
        let largest = Nat::from_u64((1 << window.bits) + 1).wrapping_mul(&weight);
        max_partial = max_partial.wrapping_add(&largest);
        assert_eq!(max_partial.cmp_vartime(&n), core::cmp::Ordering::Less);
    }
    // The 4-bit layout (fixed-key tables are 8-bit, but the inequality also
    // holds for narrower windows).
    let layout = windows(4);
    let mut max_partial = Nat::ZERO;
    for (index, window) in layout.iter().enumerate().take(layout.len() - 1) {
        let weight = Nat::pow2(window.position as usize);
        if index > 0 {
            assert_eq!(
                max_partial.cmp_vartime(&weight.wrapping_add(&weight)),
                core::cmp::Ordering::Less
            );
        }
        max_partial =
            max_partial.wrapping_add(&Nat::from_u64((1 << window.bits) + 1).wrapping_mul(&weight));
    }
}

/// The inequalities of the variable-base chain (module documentation).
#[test]
fn variable_base_chain_is_exception_free() {
    let layout = windows(4);
    let top = layout.len() - 1;
    let n = Nat::from_words(N);
    let offset = variable_offset();
    // C < k'' < 2^256 + C < 2n - 16.
    let k_max = Nat::pow2(256).wrapping_add(&offset);
    let two_n = n.wrapping_add(&n);
    assert_eq!(
        k_max.cmp_vartime(&two_n.wrapping_sub(&Nat::from_u64(16))),
        core::cmp::Ordering::Less
    );
    // Every window's multiple is at most k'' / 2^pos: below n for all but
    // the last window, and (shift / 2) a_{w+1} <= k'' / 2 < n.
    for (index, window) in layout.iter().enumerate() {
        let bound = k_max.shr(window.position as usize);
        if index > 0 {
            assert_eq!(
                bound.cmp_vartime(&n),
                core::cmp::Ordering::Less,
                "window {index}"
            );
        }
    }
    assert_eq!(k_max.shr(1).cmp_vartime(&n), core::cmp::Ordering::Less);
    // The top multiple is at least 3 (offset 3), so (shift / 2) a >= 24 > 16
    // in the first step, and every later accumulator is at least 48.
    assert_eq!(layout[top].bits, 2);
    assert_eq!(layout[top].position - layout[top - 1].position, 4);
    // Small multiples of the table are distinct and nonzero mod n.
    let entries: Vec<Affine> = (1..=16_u64)
        .map(|e| native::mul(&Affine::GENERATOR, &[e, 0, 0, 0]).expect("small multiple"))
        .collect();
    for (i, a) in entries.iter().enumerate() {
        for b in &entries[..i] {
            assert_ne!(a.x, b.x);
        }
    }
}

// ---------------------------------------------------------------------------
// The test circuit.
// ---------------------------------------------------------------------------

/// The key of a test case: witness coordinates (any 256-bit words), or the
/// configured fixed key `fixed` (whose coordinates are then ignored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyCase {
    x: [u64; 4],
    y: [u64; 4],
    fixed: Option<usize>,
}

impl KeyCase {
    const fn variable(x: [u64; 4], y: [u64; 4]) -> Self {
        Self { x, y, fixed: None }
    }

    const fn fixed(index: usize) -> Self {
        Self {
            x: [0; 4],
            y: [0; 4],
            fixed: Some(index),
        }
    }
}

/// The message of a test case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageCase {
    /// The 256-bit integer `e` (SHA-256 output).
    Prehashed([u64; 4]),
    /// A Poseidon digest (an `Fp` value) hashed in-circuit.
    Digest(Fp),
}

/// One verification.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Case {
    mode: VerifyMode,
    key: KeyCase,
    message: MessageCase,
    r: [u64; 4],
    s: [u64; 4],
}

impl Case {
    fn prehashed(mode: VerifyMode, key: &Affine, e: [u64; 4], r: [u64; 4], s: [u64; 4]) -> Self {
        Self {
            mode,
            key: KeyCase::variable(key.x, key.y),
            message: MessageCase::Prehashed(e),
            r,
            s,
        }
    }

    /// The native verdict.
    fn native(&self, fixed_keys: &[Affine]) -> bool {
        let e = match self.message {
            MessageCase::Prehashed(e) => e,
            MessageCase::Digest(m) => words_from_be(&crate::sha256::native::sha256_of_digest(&m)),
        };
        let witness = Affine {
            x: self.key.x,
            y: self.key.y,
        };
        let key = self.key.fixed.map_or(witness, |index| fixed_keys[index]);
        verify_prehashed(&e, &self.r, &self.s, &key)
    }
}

/// Where the SHA-256 chip of digest messages sits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ShaLayout {
    /// No digest message.
    #[default]
    None,
    /// On thirteen columns of its own (31 advice columns in all).
    Own,
    /// The Q-leaf layout ([`crate::q_leaf`]): 17 advice columns, the
    /// shared table, the SHA rows below the foreign-field rows.
    Leaf,
}

#[derive(Clone, Debug, Default)]
struct Params {
    fixed_keys: Vec<Affine>,
    sha: ShaLayout,
    cases: usize,
}

#[derive(Clone, Debug)]
struct P256Circuit {
    params: Params,
    cases: Vec<Case>,
    known: bool,
}

impl P256Circuit {
    fn new(fixed_keys: &[Affine], cases: Vec<Case>) -> Self {
        let sha = if cases
            .iter()
            .any(|case| matches!(case.message, MessageCase::Digest(_)))
        {
            ShaLayout::Own
        } else {
            ShaLayout::None
        };
        Self {
            params: Params {
                fixed_keys: fixed_keys.to_vec(),
                sha,
                cases: cases.len(),
            },
            cases,
            known: true,
        }
    }

    /// The same circuit in the Q-leaf layout (every message hashed in
    /// circuit).
    fn in_leaf(mut self) -> Self {
        if self.params.sha == ShaLayout::Own {
            self.params.sha = ShaLayout::Leaf;
        }
        self
    }

    /// The digest messages (SHA-256 blocks) of the circuit.
    fn digests(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| matches!(case.message, MessageCase::Digest(_)))
            .count()
    }

    fn expected(&self) -> Vec<Fq> {
        self.cases
            .iter()
            .map(|case| Fq::from(u64::from(case.native(&self.params.fixed_keys))))
            .collect()
    }
}

type Config = (
    FfConfig,
    GlueConfig,
    P256Config,
    Option<Sha256Config>,
    Column<Instance>,
    Option<QLeafConfig>,
);

impl Circuit<Fq> for P256Circuit {
    type Config = Config;
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

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, Params::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, params: Params) -> Self::Config {
        if params.sha == ShaLayout::Leaf {
            let advice = core::array::from_fn(|_| meta.advice_column());
            let constants = meta.fixed_column();
            let leaf = QLeafConfig::configure(meta, advice, constants, &params.fixed_keys);
            let instance = meta.instance_column(params.cases);
            meta.enable_equality(instance);
            return (
                leaf.ff().clone(),
                *leaf.glue(),
                leaf.p256().clone(),
                Some(*leaf.sha()),
                instance,
                Some(leaf),
            );
        }
        let ff_columns = core::array::from_fn(|_| meta.advice_column());
        let ff = FfConfig::configure(meta, ff_columns, &P256_MODULI);
        let glue_columns: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, glue_columns, constants);
        let window_columns = core::array::from_fn(|_| meta.advice_column());
        let p256 = P256Config::configure(meta, window_columns, &params.fixed_keys);
        let sha = match params.sha {
            ShaLayout::None | ShaLayout::Leaf => None,
            ShaLayout::Own => {
                let columns: [Column<Advice>; SHA256_ADVICE_COLUMNS] =
                    core::array::from_fn(|_| meta.advice_column());
                Some(Sha256Config::configure(meta, columns, constants))
            }
        };
        let instance = meta.instance_column(params.cases);
        meta.enable_equality(instance);
        (ff, glue, p256, sha, instance, None)
    }

    fn synthesize(
        &self,
        (ff, glue, p256, sha, instance, leaf): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        // The chips: in the Q-leaf layout from the leaf's row plan (SHA rows
        // and window lookups below the split, foreign-field and glue rows
        // above it), otherwise each from row 0 (window rows above the fixed
        // tables).
        let (mut sha, mut ff, mut glue, mut chip) = if let Some(leaf) = &leaf {
            leaf.load_tables(&mut layouter)?;
            let chips = leaf.chips::<Fq>(q_leaf::sha_rows(self.digests()))?;
            (Some(chips.sha), chips.ff, chips.glue, chips.p256)
        } else {
            let sha = sha.map(|config| Sha256Chip::new(&config));
            if let Some(sha) = &sha {
                sha.load_table(&mut layouter)?;
            }
            let ff = FfChip::new(ff);
            ff.load_table(&mut layouter)?;
            (sha, ff, GlueChip::new(glue), P256Chip::new(p256))
        };
        let known = self.known;
        let value = |words: [u64; 4]| {
            if known {
                Value::known(words)
            } else {
                Value::unknown()
            }
        };
        let order = ForeignModulus::P256_ORDER;
        let base = ForeignModulus::P256_BASE;
        let in_leaf = leaf.is_some();
        let bits = layouter.assign_region(
            || "p256",
            |mut region| {
                if !in_leaf {
                    chip.load_tables(&mut region)?;
                }
                // Digest messages are hashed first.
                let mut digests = Vec::with_capacity(self.cases.len());
                for case in &self.cases {
                    digests.push(match case.message {
                        MessageCase::Prehashed(_) => None,
                        MessageCase::Digest(m) => {
                            let cell = Fq::from_repr(m.to_repr())
                                .into_option()
                                .ok_or(Error::Synthesis)?;
                            let cell = if known {
                                Value::known(cell)
                            } else {
                                Value::unknown()
                            };
                            let digest = glue.witness(&mut region, cell)?;
                            let sha = sha.as_mut().ok_or(Error::Synthesis)?;
                            Some(sha.hash_digest::<Fp>(&mut region, &digest)?)
                        }
                    });
                }
                let mut bits = Vec::with_capacity(self.cases.len());
                for (case, digest) in self.cases.iter().zip(&digests) {
                    let r = ff.witness(&mut region, order, value(case.r))?;
                    let s = ff.witness(&mut region, order, value(case.s))?;
                    let e = match (case.message, digest) {
                        (MessageCase::Prehashed(e), _) => {
                            ff.witness(&mut region, order, value(e))?
                        }
                        (MessageCase::Digest(_), Some(digest)) => {
                            chip.message_scalar(&mut ff, &mut glue, &mut region, digest)?
                        }
                        (MessageCase::Digest(_), None) => return Err(Error::Synthesis),
                    };
                    let key_values = match case.key.fixed {
                        None => Some((
                            ff.witness(&mut region, base, value(case.key.x))?,
                            ff.witness(&mut region, base, value(case.key.y))?,
                        )),
                        Some(_) => None,
                    };
                    let key = match (case.key.fixed, &key_values) {
                        (Some(index), _) => P256Key::Fixed(index),
                        (None, Some((key_x, key_y))) => P256Key::Variable { x: key_x, y: key_y },
                        (None, None) => return Err(Error::Synthesis),
                    };
                    bits.push(chip.verify(
                        &mut ff,
                        &mut glue,
                        &mut region,
                        case.mode,
                        key,
                        &e,
                        &r,
                        &s,
                    )?);
                }
                Ok(bits)
            },
        )?;
        for (row, bit) in bits.iter().enumerate() {
            layouter.constrain_instance(bit.cell(), instance, row)?;
        }
        Ok(())
    }
}

fn check(circuit: &P256Circuit, public: &[Fq]) -> CheckReport<Fq> {
    check_circuit(circuit, K, &[public.to_vec()], CheckMode::Strict).expect("synthesis")
}

/// Asserts that the circuit is satisfied exactly with the native verdicts as
/// its public bits (and not with any one bit flipped).
fn assert_matches_native(circuit: &P256Circuit, what: &str) {
    let expected = circuit.expected();
    let report = check(circuit, &expected);
    assert!(report.is_satisfied(), "{what}: {report}");
    // Flipping the first bit must fail.
    if let Some(first) = expected.first() {
        let mut flipped = expected.clone();
        flipped[0] = Fq::ONE - first;
        assert!(
            !check(circuit, &flipped).is_satisfied(),
            "{what}: flipped bit accepted"
        );
    }
}

/// Rows and assigned cells per column group of a synthesized circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Inventory {
    ff_rows: usize,
    ff_cells: usize,
    glue_rows: usize,
    glue_cells: usize,
    window_rows: usize,
    window_cells: usize,
    sha_rows: usize,
    sha_cells: usize,
    /// The first row above every assigned advice cell.
    span: usize,
}

impl Inventory {
    fn of(circuit: &P256Circuit) -> Self {
        let synthesized =
            synthesize(circuit, K, Some(&[circuit.expected()][..])).expect("synthesis");
        let flags = synthesized.tables.advice_assigned();
        let group = |range: core::ops::Range<usize>| -> (usize, usize) {
            let columns = &flags[range];
            let cells = columns
                .iter()
                .map(|column| column.iter().filter(|flag| **flag).count())
                .sum();
            let first = columns
                .iter()
                .filter_map(|column| column.iter().position(|flag| *flag))
                .min()
                .unwrap_or(0);
            let last = columns
                .iter()
                .filter_map(|column| column.iter().rposition(|flag| *flag))
                .max()
                .map_or(0, |row| row + 1);
            (last.saturating_sub(first), cells)
        };
        // The Q leaf: SHA-256 on the foreign-field columns and three of its
        // own, the window lookup on the glue columns.
        let leaf = circuit.params.sha == ShaLayout::Leaf;
        // Foreign-field rows in whole blocks from the chip's first row (a
        // witness block leaves its operand row 0 empty).
        let ff_start = if leaf {
            q_leaf::sha_rows(circuit.digests())
        } else {
            0
        };
        let (_, ff_cells) = group(0..FF_ADVICE_COLUMNS);
        let ff_rows = flags[..FF_ADVICE_COLUMNS]
            .iter()
            .filter_map(|column| column.iter().rposition(|flag| *flag))
            .max()
            .map_or(0, |row| row + 1 - ff_start);
        let (glue_rows, glue_cells) = group(FF_ADVICE_COLUMNS..FF_ADVICE_COLUMNS + 4);
        let (window_rows, window_cells) = if leaf {
            (0, 0)
        } else {
            group(FF_ADVICE_COLUMNS + 4..FF_ADVICE_COLUMNS + 8)
        };
        let sha_first = FF_ADVICE_COLUMNS + if leaf { 4 } else { 8 };
        let (sha_rows, sha_cells) = if flags.len() > sha_first {
            group(sha_first..flags.len())
        } else {
            (0, 0)
        };
        let span = flags
            .iter()
            .filter_map(|column| column.iter().rposition(|flag| *flag))
            .max()
            .map_or(0, |row| row + 1);
        Self {
            ff_rows,
            ff_cells,
            glue_rows,
            glue_cells,
            window_rows,
            window_cells,
            sha_rows,
            sha_cells,
            span,
        }
    }

    fn cells(&self) -> usize {
        self.ff_cells + self.glue_cells + self.window_cells + self.sha_cells
    }

    fn rows(&self) -> usize {
        self.ff_rows
            .max(self.glue_rows)
            .max(self.window_rows)
            .max(self.sha_rows)
    }
}

/// A valid low-S signature under a random key.
fn valid_case(rng: &mut ChaCha20Rng, mode: VerifyMode) -> (Case, [u64; 4]) {
    let d = random_scalar(rng);
    let key = public_key(&d);
    let e = random_words(rng);
    loop {
        let k = random_scalar(rng);
        if let Some((r, s)) = sign(&d, &k, &e) {
            return (Case::prehashed(mode, &key, e, r, low_s(&s)), d);
        }
    }
}

#[test]
fn p256_valid_signature_soft_and_hard() {
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    let (soft, _) = valid_case(&mut rng, VerifyMode::Soft);
    let (hard, _) = valid_case(&mut rng, VerifyMode::Hard);
    let start = Instant::now();
    let circuit = P256Circuit::new(&[], vec![soft, hard]);
    assert_eq!(circuit.expected(), vec![Fq::ONE, Fq::ONE]);
    assert_matches_native(&circuit, "valid");
    eprintln!("p256 valid soft+hard check: {:?}", start.elapsed());
}

/// The advice columns of the test circuit without and with the SHA chip.
fn advice_columns(circuit: &P256Circuit) -> usize {
    let (cs, _) = configure(circuit).expect("configure");
    cs.num_advice_columns()
}

/// Gates G3.1 and G3.2: rows and assigned advice cells of one verification
/// (inputs included), pinned exactly. The layout depends only on the mode
/// and the key kind, not on the witness.
#[test]
fn p256_inventory_per_verification() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (variable, d) = valid_case(&mut rng, VerifyMode::Soft);
    let variable_circuit = P256Circuit::new(&[], vec![variable.clone()]);
    let variable_inventory = Inventory::of(&variable_circuit);
    // Another signature, hard mode and an invalid signature: the same layout.
    let (other, _) = valid_case(&mut rng, VerifyMode::Hard);
    assert_eq!(
        Inventory::of(&P256Circuit::new(&[], vec![other])),
        variable_inventory
    );
    let invalid = Case {
        r: [0; 4],
        ..variable.clone()
    };
    assert_eq!(
        Inventory::of(&P256Circuit::new(&[], vec![invalid])),
        variable_inventory
    );
    // Fixed key: the same signature under the configured key.
    let key = public_key(&d);
    let fixed = Case {
        key: KeyCase::fixed(0),
        ..variable.clone()
    };
    let fixed_circuit = P256Circuit::new(&[key], vec![fixed]);
    let fixed_inventory = Inventory::of(&fixed_circuit);
    // With the message: SHA-256 of a Poseidon digest in-circuit.
    let digest = Fp::random(&mut rng);
    let e = words_from_be(&crate::sha256::native::sha256_of_digest(&digest));
    let (r, s) = loop {
        if let Some((r, s)) = sign(&d, &random_scalar(&mut rng), &e) {
            break (r, low_s(&s));
        }
    };
    let hashed = Case {
        mode: VerifyMode::Soft,
        key: KeyCase::variable(key.x, key.y),
        message: MessageCase::Digest(digest),
        r,
        s,
    };
    let hashed_circuit = P256Circuit::new(&[], vec![hashed]);
    assert_eq!(hashed_circuit.expected(), vec![Fq::ONE]);
    let hashed_inventory = Inventory::of(&hashed_circuit);
    // The Q-leaf layout: the SHA chip on the foreign-field columns below the
    // foreign-field rows, the window lookup on the glue columns.
    let shared_circuit = hashed_circuit.clone().in_leaf();
    let shared_inventory = Inventory::of(&shared_circuit);
    let columns = advice_columns(&variable_circuit);
    let columns_with_sha = advice_columns(&hashed_circuit);
    let columns_shared = advice_columns(&shared_circuit);
    eprintln!(
        "P256_INVENTORY variable+sha leaf: cells={} ff_rows={} span={} advice={columns_shared}",
        shared_inventory.cells(),
        shared_inventory.ff_rows,
        shared_inventory.span
    );
    eprintln!(
        "P256_INVENTORY variable={variable_inventory:?} cells={} rows={} advice={columns}",
        variable_inventory.cells(),
        variable_inventory.rows()
    );
    eprintln!(
        "P256_INVENTORY fixed={fixed_inventory:?} cells={} rows={} advice={columns}",
        fixed_inventory.cells(),
        fixed_inventory.rows()
    );
    eprintln!(
        "P256_INVENTORY variable+sha={hashed_inventory:?} cells={} rows={} advice={columns_with_sha}",
        hashed_inventory.cells(),
        hashed_inventory.rows()
    );
    // G3.1: at most 0.30M cells and 14k rows at at most 22 advice columns.
    assert!(variable_inventory.cells() <= 300_000);
    assert!(variable_inventory.rows() <= 14_000);
    assert!(columns <= 22);
    // G3.2: at most 0.12M cells.
    assert!(fixed_inventory.cells() <= 120_000);
    // Pinned (a change here is a layout change: update the module
    // documentation and the design record's measurements).
    assert_eq!(
        (variable_inventory.cells(), variable_inventory.rows()),
        (VARIABLE_CELLS, VARIABLE_ROWS)
    );
    assert_eq!(
        (fixed_inventory.cells(), fixed_inventory.rows()),
        (FIXED_CELLS, FIXED_ROWS)
    );
    assert_eq!(columns, 18);
    // With the message's SHA block in the 17-column Q-leaf layout: the same
    // cells, the SHA rows below the foreign-field rows.
    assert_eq!(columns_with_sha, 31);
    assert_eq!(columns_shared, q_leaf::Q_LEAF_ADVICE_COLUMNS);
    assert_eq!(shared_inventory.cells(), hashed_inventory.cells());
    let leaf_rows = q_leaf::sha_rows(1) + shared_inventory.ff_rows;
    assert_eq!(
        (hashed_inventory.cells(), leaf_rows),
        (VARIABLE_SHA_CELLS, VARIABLE_SHA_SHARED_ROWS)
    );
    assert!(leaf_rows <= 14_000);
    // Only the dynamic table (32 rows on the glue columns above the shared
    // table's fixed rows) lies above the foreign-field rows.
    let tables_end = q_leaf::WINDOW_TABLE_START + 7_940;
    assert_eq!(
        shared_inventory.span,
        tables_end + 2 * window::DYNAMIC_ENTRIES
    );
}

/// A witness-key verification of a digest hashed in circuit (soft) and the
/// same signature under the configured fixed key (hard), in the Q-leaf
/// layout.
fn leaf_circuit(seed: u64) -> P256Circuit {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let d = random_scalar(&mut rng);
    let key = public_key(&d);
    let digest = Fp::random(&mut rng);
    let e = words_from_be(&crate::sha256::native::sha256_of_digest(&digest));
    let (r, s) = loop {
        if let Some((r, s)) = sign(&d, &random_scalar(&mut rng), &e) {
            break (r, low_s(&s));
        }
    };
    let hashed = Case {
        mode: VerifyMode::Soft,
        key: KeyCase::variable(key.x, key.y),
        message: MessageCase::Digest(digest),
        r,
        s,
    };
    let fixed = Case {
        mode: VerifyMode::Hard,
        key: KeyCase::fixed(0),
        ..hashed.clone()
    };
    P256Circuit::new(&[key], vec![hashed, fixed]).in_leaf()
}

/// The Q-leaf layout keeps the shared-table conditions ([`crate::table`],
/// [`QLeafConfig::audit`]) on the key-generation tables and on a proving
/// synthesis: every `V` entry below `2^15`, every table row in its tag
/// namespace, and the SHA-256 and window lookups row-disjoint from the
/// foreign-field range lookups that carry them.
#[test]
fn p256_leaf_keeps_the_shared_table_conditions() {
    let circuit = leaf_circuit(13);
    let public = circuit.expected();
    assert_eq!(public, vec![Fq::ONE, Fq::ONE]);
    let (_, config) = configure(&circuit).expect("configure");
    let leaf = config.5.expect("leaf layout");
    let keygen = synthesize(&circuit, K, None).expect("synthesis");
    assert_eq!(leaf.audit(&keygen.tables), Ok(()));
    let proving = synthesize(&circuit, K, Some(core::slice::from_ref(&public))).expect("synthesis");
    assert_eq!(leaf.audit(&proving.tables), Ok(()));
    assert_eq!(keygen.tables.fixed(), proving.tables.fixed());
    // The window lookups and SHA-256 units are below the split, the
    // foreign-field blocks above it.
    let split = q_leaf::sha_rows(2);
    let flags = proving.tables.advice_assigned();
    let glue = FF_ADVICE_COLUMNS..FF_ADVICE_COLUMNS + 4;
    let window_rows = flags[glue.clone()]
        .iter()
        .filter_map(|column| column[..split].iter().rposition(|flag| *flag))
        .max()
        .map_or(0, |row| row + 1);
    assert!(window_rows > 0 && window_rows <= split, "{window_rows}");
    let sha_end = flags[..FF_ADVICE_COLUMNS]
        .iter()
        .chain(&flags[FF_ADVICE_COLUMNS + 4..])
        .filter_map(|column| column[..split].iter().rposition(|flag| *flag))
        .max()
        .map_or(0, |row| row + 1);
    assert_eq!(sha_end, split);
    let report = check(&circuit, &public);
    assert!(report.is_satisfied(), "{report}");
}

/// Assigned advice cells of one variable-key verification.
const VARIABLE_CELLS: usize = 115_787;
/// FF rows of one variable-key verification.
const VARIABLE_ROWS: usize = 10_003;
/// Assigned advice cells of one fixed-key verification.
const FIXED_CELLS: usize = 20_057;
/// FF rows of one fixed-key verification.
const FIXED_ROWS: usize = 1_659;
/// Assigned advice cells of one variable-key verification with its message
/// (the SHA-256 block of a Poseidon digest).
const VARIABLE_SHA_CELLS: usize = 139_208;
/// Rows of one variable-key verification with its message in the 17-column
/// Q-leaf layout.
const VARIABLE_SHA_SHARED_ROWS: usize = 12_097;

/// Every gate and lookup of a P-256 circuit (with the SHA chip) has degree
/// at most [`crate::MAX_GATE_DEGREE`]; the window lookup is the widest.
#[test]
fn p256_gate_degree_at_most_six() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let (case, _) = valid_case(&mut rng, VerifyMode::Soft);
    let plain = P256Circuit::new(&[], vec![case.clone()]);
    let hashed = P256Circuit::new(
        &[],
        vec![Case {
            message: MessageCase::Digest(Fp::ONE),
            ..case
        }],
    );
    for circuit in [&plain, &hashed] {
        let (cs, _) = configure(circuit).expect("configure");
        assert!(
            cs.degree() <= crate::MAX_GATE_DEGREE,
            "degree {}",
            cs.degree()
        );
        let window = cs
            .lookups()
            .iter()
            .find(|lookup| lookup.name() == "p256 window")
            .expect("window lookup");
        assert_eq!(window.required_degree(), crate::MAX_GATE_DEGREE);
    }
}

// ---------------------------------------------------------------------------
// Batched circuit checks.
// ---------------------------------------------------------------------------

/// Verifications per `k = 16` circuit (about 10,000 FF rows each).
const PER_CIRCUIT: usize = 6;
/// Circuits checked concurrently.
const THREADS: usize = 4;

/// Checks every case against its native verdict, `PER_CIRCUIT` cases per
/// circuit and `THREADS` circuits at a time; returns the number of circuits.
fn assert_cases_match_native(fixed_keys: &[Affine], cases: &[Case], what: &str) -> usize {
    let chunks: Vec<&[Case]> = cases.chunks(PER_CIRCUIT).collect();
    for group in chunks.chunks(THREADS) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = group
                .iter()
                .enumerate()
                .map(|(index, chunk)| {
                    scope.spawn(move || {
                        let circuit = P256Circuit::new(fixed_keys, chunk.to_vec());
                        let expected = circuit.expected();
                        let report = check(&circuit, &expected);
                        (index, report.is_satisfied(), format!("{report}"))
                    })
                })
                .collect();
            for handle in handles {
                let (index, satisfied, report) = handle.join().expect("check thread");
                assert!(satisfied, "{what}: chunk {index}: {report}");
            }
        });
    }
    chunks.len()
}

/// Asserts that a single-case circuit is unsatisfiable (hard mode on an
/// invalid signature) with the bit claimed to be 1.
fn assert_unsatisfiable(fixed_keys: &[Affine], case: &Case, what: &str) {
    let circuit = P256Circuit::new(fixed_keys, vec![case.clone()]);
    assert!(
        !check(&circuit, &[Fq::ONE]).is_satisfied(),
        "{what}: accepted"
    );
}

// ---------------------------------------------------------------------------
// Wycheproof.
// ---------------------------------------------------------------------------

/// One Wycheproof vector: key, `e = SHA-256(msg)`, `(r, s)` and the
/// Wycheproof result.
#[derive(Clone, Debug)]
struct Vector {
    id: u64,
    comment: String,
    key: Affine,
    e: [u64; 4],
    r: [u64; 4],
    s: [u64; 4],
    valid: bool,
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn words_of_be_slice(bytes: &[u8]) -> [u64; 4] {
    let mut padded = [0_u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    words_from_be(&padded)
}

fn wycheproof_vectors() -> Vec<Vector> {
    use norito::json::Value as Json;
    use sha2::{Digest as _, Sha256};
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wycheproof_ecdsa_secp256r1_sha256_p1363.json");
    let text = std::fs::read_to_string(&path).expect("read the Wycheproof fixture");
    let json = norito::json::parse_value(&text).expect("parse the Wycheproof fixture");
    let text_of = |value: &Json, key: &str| -> String {
        value.get(key).and_then(Json::as_str).expect(key).to_owned()
    };
    let mut out = Vec::new();
    let groups = json
        .get("testGroups")
        .and_then(Json::as_array)
        .expect("groups");
    for group in groups {
        let key_hex = text_of(group.get("key").expect("key"), "uncompressed");
        let key_bytes = hex_bytes(&key_hex);
        assert_eq!((key_bytes.len(), key_bytes[0]), (65, 4));
        let key = Affine {
            x: words_of_be_slice(&key_bytes[1..33]),
            y: words_of_be_slice(&key_bytes[33..]),
        };
        for test in group.get("tests").and_then(Json::as_array).expect("tests") {
            let sig = hex_bytes(&text_of(test, "sig"));
            assert_eq!(sig.len(), 64);
            let digest: [u8; 32] = Sha256::digest(hex_bytes(&text_of(test, "msg"))).into();
            out.push(Vector {
                id: test.get("tcId").and_then(Json::as_u64).expect("tcId"),
                comment: text_of(test, "comment"),
                key,
                e: words_from_be(&digest),
                r: words_of_be_slice(&sig[..32]),
                s: words_of_be_slice(&sig[32..]),
                valid: text_of(test, "result") == "valid",
            });
        }
    }
    assert_eq!(
        json.get("numberOfTests").and_then(Json::as_u64),
        Some(out.len() as u64)
    );
    out
}

#[test]
fn p256_soft_bit_equals_native_on_wycheproof_prehashed() {
    let vectors = wycheproof_vectors();
    assert_eq!(vectors.len(), 210);
    let mut accepted = 0;
    let mut cases = Vec::with_capacity(vectors.len());
    for vector in &vectors {
        // The fixture, the oracle and the reference agree: Wycheproof's
        // verdict is plain ECDSA (any s); KAGEMUSHA adds low-S.
        let plain = oracle_verify(&vector.e, &vector.r, &vector.s, &vector.key);
        assert_eq!(
            plain, vector.valid,
            "tcId {} ({})",
            vector.id, vector.comment
        );
        assert_eq!(
            native::verify_prehashed_any_s(&vector.e, &vector.r, &vector.s, &vector.key),
            vector.valid,
            "tcId {}",
            vector.id
        );
        let verdict = verify_prehashed(&vector.e, &vector.r, &vector.s, &vector.key);
        assert_eq!(
            verdict,
            oracle_kagemusha(&vector.e, &vector.r, &vector.s, &vector.key),
            "tcId {}",
            vector.id
        );
        accepted += usize::from(verdict);
        cases.push(Case::prehashed(
            VerifyMode::Soft,
            &vector.key,
            vector.e,
            vector.r,
            vector.s,
        ));
    }
    // Every Wycheproof-valid vector with s <= (n - 1) / 2 is accepted.
    assert!(accepted > 0 && accepted < vectors.iter().filter(|v| v.valid).count() + 1);
    let start = Instant::now();
    let circuits = assert_cases_match_native(&[], &cases, "wycheproof");
    eprintln!(
        "wycheproof: {} vectors, {accepted} accepted under low-S, {circuits} circuits, {:?}",
        vectors.len(),
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Rejections.
// ---------------------------------------------------------------------------

/// A signature with `s = (n - 1) / 2` exactly: `e = s k - r d (mod n)`.
fn boundary_low_s(rng: &mut ChaCha20Rng) -> (Affine, [u64; 4], [u64; 4], [u64; 4]) {
    let d = random_scalar(rng);
    let key = public_key(&d);
    loop {
        let k = random_scalar(rng);
        let point = native::mul(&Affine::GENERATOR, &k).expect("nonzero nonce");
        let r = ORDER.reduce_once(&point.x);
        if words_is_zero(&r) {
            continue;
        }
        let e = ORDER.sub(&ORDER.mul(&HALF_N, &k), &ORDER.mul(&r, &d));
        return (key, e, r, HALF_N);
    }
}

#[test]
fn p256_rejects_high_s_r_ge_n_zero() {
    let mut rng = ChaCha20Rng::seed_from_u64(20);
    let (key, e, r, s) = boundary_low_s(&mut rng);
    assert!(verify_prehashed(&e, &r, &s, &key));
    // s = (n - 1) / 2 + 1 with the matching message is the high twin of a
    // valid signature: (r, n - s) verifies e under plain ECDSA.
    let high = ORDER.neg(&s);
    assert!(native::verify_prehashed_any_s(&e, &r, &high, &key));
    let n_plus = |value: &[u64; 4]| -> [u64; 4] {
        Nat::from_words(*value)
            .wrapping_add(&Nat::from_words(N))
            .low_words()
    };
    let small_r = [5, 0, 0, 0];
    let invalid: Vec<(&str, [u64; 4], [u64; 4], Affine)> = vec![
        ("high s", r, high, key),
        ("s = (n - 1) / 2 + 1", r, ORDER.add(&s, &[1, 0, 0, 0]), key),
        ("s = n - 1", r, ORDER.neg(&[1, 0, 0, 0]), key),
        ("s = n", r, N, key),
        ("s = n + 1", r, n_plus(&[1, 0, 0, 0]), key),
        ("s = 0", r, [0; 4], key),
        ("r = 0", [0; 4], s, key),
        ("r = n", N, s, key),
        ("r = n + 5", n_plus(&small_r), s, key),
        ("r = 2^256 - 1", [u64::MAX; 4], s, key),
        ("r = s = 0", [0; 4], [0; 4], key),
        (
            "key off the curve",
            r,
            s,
            Affine {
                x: key.x,
                y: BASE.add(&key.y, &[1, 0, 0, 0]),
            },
        ),
        (
            "key x not canonical",
            r,
            s,
            Affine {
                x: Nat::from_words(key.x)
                    .wrapping_add(&Nat::from_words(P))
                    .low_words(),
                y: key.y,
            },
        ),
        (
            "zero key",
            r,
            s,
            Affine {
                x: [0; 4],
                y: [0; 4],
            },
        ),
    ];
    let mut soft = vec![Case::prehashed(VerifyMode::Soft, &key, e, r, s)];
    for (what, r, s, key) in &invalid {
        assert!(!verify_prehashed(&e, r, s, key), "{what}");
        soft.push(Case::prehashed(VerifyMode::Soft, key, e, *r, *s));
    }
    // r + n has the same x(R) mod n as r only if r + n < 2^256; here r is
    // a full-width residue, so test r = 5 + n separately above.
    let circuit = P256Circuit::new(&[], soft[..1].to_vec());
    assert_eq!(circuit.expected(), vec![Fq::ONE]);
    assert_cases_match_native(&[], &soft, "soft rejections");
    // Hard mode: the valid boundary signature is accepted, each invalid one
    // is unsatisfiable.
    let accepted = Case::prehashed(VerifyMode::Hard, &key, e, r, s);
    assert!(check(&P256Circuit::new(&[], vec![accepted]), &[Fq::ONE]).is_satisfied());
    for (what, r, s, key) in &invalid {
        assert_unsatisfiable(
            &[],
            &Case::prehashed(VerifyMode::Hard, key, e, *r, *s),
            what,
        );
    }
}

// ---------------------------------------------------------------------------
// Edge keys and edge scalars.
// ---------------------------------------------------------------------------

/// A square root modulo `p` (`p = 3 mod 4`), or `None` for a non-residue.
fn sqrt_mod_p(a: &[u64; 4]) -> Option<[u64; 4]> {
    let exponent = Nat::from_words(P)
        .wrapping_add(&Nat::ONE)
        .shr(2)
        .low_words();
    let root = BASE.standard_form(&BASE.pow(&BASE.montgomery_form(a), &exponent));
    (BASE.mul(&root, &root) == *a).then_some(root)
}

/// A curve point with the canonical `x` (either root), or `None`.
fn point_at(x: &[u64; 4]) -> Option<Affine> {
    if !words_lt(x, &P) {
        return None;
    }
    let cube = BASE.mul(&BASE.mul(x, x), x);
    let rhs = BASE.add(&BASE.sub(&cube, &BASE.add(&BASE.add(x, x), x)), &B);
    let point = Affine {
        x: *x,
        y: sqrt_mod_p(&rhs)?,
    };
    point.is_valid().then_some(point)
}

/// The first curve point with `x = start + i` for `i >= 0` (`start - i`
/// when `descending`).
fn first_point(start: &[u64; 4], descending: bool) -> Affine {
    let mut x = Nat::from_words(*start);
    loop {
        if let Some(point) = point_at(&x.low_words()) {
            return point;
        }
        x = if descending {
            x.wrapping_sub(&Nat::ONE)
        } else {
            x.wrapping_add(&Nat::ONE)
        };
    }
}

/// A uniformly random `s` in `[1, (n - 1) / 2]`.
fn low_scalar(rng: &mut ChaCha20Rng) -> [u64; 4] {
    loop {
        let s = random_scalar(rng);
        if words_cmp(&s, &HALF_N) != core::cmp::Ordering::Greater {
            return s;
        }
    }
}

fn random_point(rng: &mut ChaCha20Rng) -> Affine {
    public_key(&random_scalar(rng))
}

/// `(e, r, s)` with `u1 = e / s` and `u2 = r / s` under `key`; `None` when
/// `R = [u1] G + [u2] key` is the identity, `r = 0`, `u2 = 0` or `s` is
/// high.
fn signature_for(
    key: &Affine,
    u1: &[u64; 4],
    u2: &[u64; 4],
) -> Option<([u64; 4], [u64; 4], [u64; 4])> {
    let point = native::mul_add(&Affine::GENERATOR, u1, key, u2)?;
    let r = ORDER.reduce_once(&point.x);
    if words_is_zero(&r) || words_is_zero(u2) {
        return None;
    }
    let s = ORDER.mul(&r, &ORDER.inverse(u2));
    if words_cmp(&s, &HALF_N) == core::cmp::Ordering::Greater {
        return None;
    }
    Some((ORDER.mul(u1, &s), r, s))
}

/// The key under which `(e, r, s)` verifies with the point `R` (for
/// `x(R) = r (mod n)`): `Q = [s / r] (R - [e / s] G)`.
fn key_for(point: &Affine, e: &[u64; 4], r: &[u64; 4], s: &[u64; 4]) -> Option<Affine> {
    let w = ORDER.inverse(s);
    let u1 = ORDER.mul(&ORDER.reduce_once(e), &w);
    let u2 = ORDER.mul(r, &w);
    let generator = native::mul_jacobian(&Jacobian::from_affine(&Affine::GENERATOR), &u1);
    let shifted = Jacobian::from_affine(point).add(&generator.neg());
    native::mul_jacobian(&shifted, &ORDER.inverse(&u2)).to_affine()
}

/// One edge case: a label, the key and the signature.
#[derive(Clone, Copy, Debug)]
struct Edge {
    what: &'static str,
    key: Affine,
    e: [u64; 4],
    r: [u64; 4],
    s: [u64; 4],
}

impl Edge {
    fn new(what: &'static str, key: Affine, (e, r, s): ([u64; 4], [u64; 4], [u64; 4])) -> Self {
        Self { what, key, e, r, s }
    }

    fn native(&self) -> bool {
        verify_prehashed(&self.e, &self.r, &self.s, &self.key)
    }

    fn case(&self, mode: VerifyMode) -> Case {
        Case::prehashed(mode, &self.key, self.e, self.r, self.s)
    }

    fn fixed(&self, mode: VerifyMode, index: usize) -> Case {
        Case {
            key: KeyCase::fixed(index),
            ..self.case(mode)
        }
    }
}

/// A signature under `key` with random `u1` and `u2`.
fn random_signature(rng: &mut ChaCha20Rng, key: &Affine) -> ([u64; 4], [u64; 4], [u64; 4]) {
    loop {
        if let Some(signature) = signature_for(key, &random_scalar(rng), &random_scalar(rng)) {
            return signature;
        }
    }
}

/// A key and a signature through the point `R` with a random low `s` (or
/// `s` itself) and a random message.
fn through_point(
    rng: &mut ChaCha20Rng,
    what: &'static str,
    point: &Affine,
    s: Option<[u64; 4]>,
) -> Edge {
    let r = ORDER.reduce_once(&point.x);
    assert!(!words_is_zero(&r), "{what}");
    loop {
        let s = s.unwrap_or_else(|| low_scalar(rng));
        let e = random_words(rng);
        if let Some(key) = key_for(point, &e, &r, &s) {
            return Edge { what, key, e, r, s };
        }
    }
}

/// A key and a signature with `u2 = target` (random `R` and message).
fn with_u2(rng: &mut ChaCha20Rng, what: &'static str, target: &[u64; 4]) -> Edge {
    loop {
        let point = random_point(rng);
        let r = ORDER.reduce_once(&point.x);
        let s = ORDER.mul(&r, &ORDER.inverse(target));
        if words_is_zero(&s) || words_cmp(&s, &HALF_N) == core::cmp::Ordering::Greater {
            continue;
        }
        let e = random_words(rng);
        if let Some(key) = key_for(&point, &e, &r, &s) {
            return Edge { what, key, e, r, s };
        }
    }
}

/// A key and a signature with `u1 = target` (random `R` and low `s`).
fn with_u1(rng: &mut ChaCha20Rng, what: &'static str, target: &[u64; 4]) -> Edge {
    loop {
        let point = random_point(rng);
        let r = ORDER.reduce_once(&point.x);
        let s = low_scalar(rng);
        let e = ORDER.mul(target, &s);
        if let Some(key) = key_for(&point, &e, &r, &s) {
            return Edge { what, key, e, r, s };
        }
    }
}

/// A key `Q = [u1 / u2] G` and a signature with `[u1] G = [u2] Q`: the
/// final join is a doubling.
fn doubling_join(rng: &mut ChaCha20Rng) -> Edge {
    loop {
        let (u1, u2) = (random_scalar(rng), random_scalar(rng));
        let key = public_key(&ORDER.mul(&u1, &ORDER.inverse(&u2)));
        if let Some(signature) = signature_for(&key, &u1, &u2) {
            return Edge::new("[u1] G = [u2] Q (doubling join)", key, signature);
        }
    }
}

/// A signature with `[u1] G = -[u2] Q`, so `R` is the identity: every
/// verifier rejects it. `d` is the key's discrete logarithm.
fn identity_join(rng: &mut ChaCha20Rng, d: &[u64; 4]) -> Edge {
    let r = random_scalar(rng);
    let s = low_scalar(rng);
    // u1 = -d u2, so e = u1 s = -d r.
    let e = ORDER.neg(&ORDER.mul(d, &r));
    Edge {
        what: "[u1] G = -[u2] Q (identity join)",
        key: public_key(d),
        e,
        r,
        s,
    }
}

/// Every natively accepted edge case of the variable-key test.
fn accepted_edges(rng: &mut ChaCha20Rng) -> Vec<Edge> {
    let generator = Affine::GENERATOR;
    let half = ORDER.inverse(&[2, 0, 0, 0]);
    let smallest_x = first_point(&[0; 4], false);
    let p_minus_one = BASE.neg(&[1, 0, 0, 0]);
    let n_minus_one = ORDER.neg(&[1, 0, 0, 0]);
    let mut edges = Vec::new();
    for (what, key) in [
        ("key G", generator),
        ("key -G", generator.neg()),
        ("key 2G", public_key(&[2, 0, 0, 0])),
        ("key G / 2", public_key(&half)),
        ("key with the smallest x", smallest_x),
        ("its negation", smallest_x.neg()),
        (
            "key with the largest x below p",
            first_point(&p_minus_one, true),
        ),
        ("key with x >= n", first_point(&N, false)),
    ] {
        let signature = random_signature(rng, &key);
        edges.push(Edge::new(what, key, signature));
    }
    edges.push(doubling_join(rng));
    // u1 = 0: e = 0, and e = n (the same scalar as a 256-bit message).
    loop {
        let key = random_point(rng);
        if let Some((e, r, s)) = signature_for(&key, &[0; 4], &random_scalar(rng)) {
            assert!(words_is_zero(&e));
            edges.push(Edge::new("u1 = 0 (e = 0)", key, (e, r, s)));
            edges.push(Edge::new("u1 = 0 (e = n)", key, (N, r, s)));
            break;
        }
    }
    // A message integer e + n >= n (below 2^256) for a small e.
    let point = random_point(rng);
    let small_e = [rng.next_u64(), rng.next_u64(), 0, 0];
    let r = ORDER.reduce_once(&point.x);
    let s = low_scalar(rng);
    let key = key_for(&point, &small_e, &r, &s).expect("a key through a random point");
    let e = Nat::from_words(small_e)
        .wrapping_add(&Nat::from_words(N))
        .low_words();
    edges.push(Edge {
        what: "message e >= n",
        key,
        e,
        r,
        s,
    });
    // x(R) >= n, so r = x(R) - n is small.
    edges.push(through_point(
        rng,
        "x(R) >= n",
        &first_point(&N, false),
        None,
    ));
    // A small x(R), so a small r.
    edges.push(through_point(
        rng,
        "small r",
        &first_point(&[1, 0, 0, 0], false),
        None,
    ));
    // r close to n - 1.
    edges.push(through_point(
        rng,
        "r close to n - 1",
        &first_point(&n_minus_one, true),
        None,
    ));
    // s at both ends of the low-S range.
    for (what, s) in [("s = 1", [1, 0, 0, 0]), ("s = (n - 1) / 2", HALF_N)] {
        let point = random_point(rng);
        edges.push(through_point(rng, what, &point, Some(s)));
    }
    // u2 at the ends of the variable-base digits: k* = u2 - C = 0 and n - 1.
    let offset = ForeignModulus::P256_ORDER
        .reduce(&variable_offset())
        .low_words();
    let below_offset = ORDER.sub(&offset, &[1, 0, 0, 0]);
    edges.push(with_u2(rng, "u2 = 1", &[1, 0, 0, 0]));
    edges.push(with_u2(rng, "u2 = n - 1", &n_minus_one));
    edges.push(with_u2(rng, "u2 = C (k* = 0)", &offset));
    edges.push(with_u2(rng, "u2 = C - 1 (k* = n - 1)", &below_offset));
    // u1 at the ends of the fixed-base digits.
    let top = native::pow2_words(254);
    let below_top = ORDER.sub(&top, &[1, 0, 0, 0]);
    edges.push(with_u1(rng, "u1 = 1", &[1, 0, 0, 0]));
    edges.push(with_u1(rng, "u1 = n - 1", &n_minus_one));
    edges.push(with_u1(rng, "u1 = 2^254", &top));
    edges.push(with_u1(rng, "u1 = 2^254 - 1", &below_top));
    edges
}

#[test]
fn p256_complete_for_native_accepted_edge_keys() {
    let mut rng = ChaCha20Rng::seed_from_u64(40);
    let edges = accepted_edges(&mut rng);
    for edge in &edges {
        assert!(edge.native(), "{}", edge.what);
        assert!(
            oracle_kagemusha(&edge.e, &edge.r, &edge.s, &edge.key),
            "oracle: {}",
            edge.what
        );
    }
    // The constructions reach their targets.
    let x_large = edges
        .iter()
        .find(|edge| edge.what == "x(R) >= n")
        .expect("edge");
    assert!(words_lt(&x_large.r, &[0, 0, 1, 0]), "r = x(R) - n is small");
    // Variable keys, soft: every bit is 1.
    let soft: Vec<Case> = edges
        .iter()
        .map(|edge| edge.case(VerifyMode::Soft))
        .collect();
    let start = Instant::now();
    let circuits = assert_cases_match_native(&[], &soft, "edge keys (soft)");
    // Hard: satisfiable with the bit 1.
    let hard: Vec<Case> = edges
        .iter()
        .filter(|edge| {
            matches!(
                edge.what,
                "[u1] G = [u2] Q (doubling join)" | "x(R) >= n" | "u1 = 0 (e = n)" | "key -G"
            )
        })
        .map(|edge| edge.case(VerifyMode::Hard))
        .collect();
    assert_eq!(hard.len(), 4);
    assert_cases_match_native(&[], &hard, "edge keys (hard)");
    // Fixed keys: G, -G, the doubling-join key and the smallest-x key.
    let generator = Affine::GENERATOR;
    let doubling = doubling_join(&mut rng);
    let smallest_x = first_point(&[0; 4], false);
    let fixed_keys = [generator, generator.neg(), doubling.key, smallest_x];
    let mut fixed = Vec::new();
    for (index, key) in fixed_keys.iter().enumerate() {
        let edge = Edge::new("fixed key", *key, random_signature(&mut rng, key));
        fixed.push(edge.fixed(VerifyMode::Soft, index));
    }
    fixed.push(doubling.fixed(VerifyMode::Hard, 2));
    // u1 = 0 under -G, with e = n; u2 = 1 under G.
    loop {
        if let Some((_, r, s)) = signature_for(&generator.neg(), &[0; 4], &random_scalar(&mut rng))
        {
            fixed.push(
                Edge::new("u1 = 0 (e = n), key -G", generator.neg(), (N, r, s))
                    .fixed(VerifyMode::Soft, 1),
            );
            break;
        }
    }
    loop {
        if let Some(signature) = signature_for(&generator, &random_scalar(&mut rng), &[1, 0, 0, 0])
        {
            fixed.push(Edge::new("u2 = 1, key G", generator, signature).fixed(VerifyMode::Soft, 0));
            break;
        }
    }
    let circuit = P256Circuit::new(&fixed_keys, fixed.clone());
    assert!(circuit.expected().iter().all(|bit| *bit == Fq::ONE));
    assert_cases_match_native(&fixed_keys, &fixed, "edge keys (fixed)");
    // The identity join (rejected by every verifier): the soft bit is 0
    // and the circuit stays satisfiable; hard mode is unsatisfiable.
    let d = random_scalar(&mut rng);
    let identity = identity_join(&mut rng, &d);
    assert!(!identity.native());
    assert!(
        native::mul_add(
            &generator,
            &ORDER.mul(&identity.e, &ORDER.inverse(&identity.s)),
            &identity.key,
            &ORDER.mul(&identity.r, &ORDER.inverse(&identity.s)),
        )
        .is_none()
    );
    let generator_identity = identity_join(&mut rng, &[1, 0, 0, 0]);
    let rejected = vec![
        identity.case(VerifyMode::Soft),
        generator_identity.fixed(VerifyMode::Soft, 0),
    ];
    assert_cases_match_native(&fixed_keys, &rejected, "identity join (soft)");
    assert_unsatisfiable(
        &[],
        &identity.case(VerifyMode::Hard),
        "identity join (hard)",
    );
    assert_unsatisfiable(
        &fixed_keys,
        &generator_identity.fixed(VerifyMode::Hard, 0),
        "identity join, fixed key (hard)",
    );
    eprintln!(
        "edge keys: {} variable, {} fixed, {circuits} soft circuits, {:?}",
        edges.len(),
        fixed.len(),
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// The message: SHA-256 of a Poseidon digest.
// ---------------------------------------------------------------------------

/// `e` is SHA-256 of the 32-byte canonical encoding of a Poseidon digest
/// (one compression in-circuit), read as a big-endian integer: signatures
/// over it verify exactly when the native verifier accepts them.
#[test]
fn p256_message_from_poseidon_digest_matches_native() {
    let mut rng = ChaCha20Rng::seed_from_u64(30);
    let d = random_scalar(&mut rng);
    let key = public_key(&d);
    let digest = Fp::random(&mut rng);
    let message = crate::sha256::native::sha256_of_digest(&digest);
    // The chip's message is the standard SHA-256 of the 32 bytes.
    {
        use sha2::{Digest as _, Sha256};
        let bytes = crate::sha256::native::digest_message(&digest);
        let standard: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(standard, message);
    }
    let e = words_from_be(&message);
    let (r, s) = loop {
        if let Some((r, s)) = sign(&d, &random_scalar(&mut rng), &e) {
            break (r, low_s(&s));
        }
    };
    assert!(verify_prehashed(&e, &r, &s, &key));
    let hashed = |mode, digest| Case {
        mode,
        key: KeyCase::variable(key.x, key.y),
        message: MessageCase::Digest(digest),
        r,
        s,
    };
    // Valid (soft and hard), a different digest (soft: 0), and the same
    // signature under the fixed key.
    let cases = vec![
        hashed(VerifyMode::Soft, digest),
        hashed(VerifyMode::Hard, digest),
        hashed(VerifyMode::Soft, digest + Fp::ONE),
        Case {
            key: KeyCase::fixed(0),
            ..hashed(VerifyMode::Soft, digest)
        },
    ];
    let circuit = P256Circuit::new(&[key], cases.clone());
    assert_eq!(
        circuit.expected(),
        vec![Fq::ONE, Fq::ONE, Fq::ZERO, Fq::ONE]
    );
    assert_matches_native(&circuit, "digest messages");
    assert_matches_native(&circuit.in_leaf(), "digest messages, Q-leaf layout");
    assert_unsatisfiable(
        &[key],
        &hashed(VerifyMode::Hard, -digest),
        "wrong digest (hard)",
    );
}

// ---------------------------------------------------------------------------
// Forged witnesses of the soft tests.
// ---------------------------------------------------------------------------

/// A witness choice for one soft test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forgery {
    /// `is_zero_mod` of the proper witness `v` modulo `n` with the bit
    /// `zero` and the inverse witness `inverse`.
    IsZero {
        v: [u64; 4],
        zero: bool,
        inverse: [u64; 4],
    },
    /// `soft_le(x, bound)` with the difference `d`, the low carry `k1` and
    /// the verdict `c`.
    Le {
        x: [u64; 4],
        bound: [u64; 4],
        d: [u64; 4],
        k1: bool,
        c: bool,
    },
}

impl Forgery {
    /// The honest `is_zero_mod` witness of `v`.
    fn honest_is_zero(v: [u64; 4]) -> Self {
        let residue = ORDER.reduce_once(&v);
        Self::IsZero {
            v,
            zero: words_is_zero(&residue),
            inverse: ORDER.inverse(&residue),
        }
    }

    /// The honest `soft_le` witness of `x <= bound`.
    fn honest_le(x: [u64; 4], bound: [u64; 4]) -> Self {
        let (d, borrow) = Nat::from_words(bound).overflowing_sub(&Nat::from_words(x));
        let d = d.low_words();
        let low = |words: &[u64; 4]| {
            let value = Nat::from_words(*words);
            value.wrapping_sub(&value.shr(174).shl(174))
        };
        let k1 = low(&x).wrapping_add(&low(&d)).bit(174);
        Self::Le {
            x,
            bound,
            d,
            k1,
            c: !borrow,
        }
    }

    /// The bit the witness claims.
    const fn bit(&self) -> bool {
        match self {
            Self::IsZero { zero, .. } => *zero,
            Self::Le { c, .. } => *c,
        }
    }
}

#[derive(Clone, Debug)]
struct ForgeryCircuit {
    forgery: Forgery,
}

impl Circuit<Fq> for ForgeryCircuit {
    type Config = (FfConfig, GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let ff_columns = core::array::from_fn(|_| meta.advice_column());
        let ff = FfConfig::configure(meta, ff_columns, &P256_MODULI);
        let glue_columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, glue_columns, constants);
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        (ff, glue, instance)
    }

    fn synthesize(
        &self,
        (ff, glue, instance): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut ff = FfChip::new(ff);
        ff.load_table(&mut layouter)?;
        let mut glue = GlueChip::new(glue);
        let mut constants = Constants::default();
        let bit = layouter.assign_region(
            || "forgery",
            |mut region| {
                let mut arith = Arith {
                    ff: &mut ff,
                    glue: &mut glue,
                    constants: &mut constants,
                };
                match self.forgery {
                    Forgery::IsZero { v, zero, inverse } => {
                        let v = arith.ff.witness(
                            &mut region,
                            ForeignModulus::P256_ORDER,
                            Value::known(v),
                        )?;
                        arith.is_zero_mod_witnessed(
                            &mut region,
                            &v,
                            Value::known(zero),
                            Value::known(inverse),
                        )
                    }
                    Forgery::Le { x, bound, d, k1, c } => {
                        let x = arith.ff.witness(
                            &mut region,
                            ForeignModulus::P256_ORDER,
                            Value::known(x),
                        )?;
                        arith.soft_le_witnessed(
                            &mut region,
                            &x,
                            &bound,
                            Value::known(d),
                            Value::known(k1),
                            Value::known(c),
                        )
                    }
                }
            },
        )?;
        layouter.constrain_instance(bit.cell(), instance, 0)
    }
}

/// Whether the witness satisfies the circuit with its claimed bit public.
fn forgery_accepted(forgery: Forgery) -> bool {
    let circuit = ForgeryCircuit { forgery };
    let public = vec![Fq::from(u64::from(forgery.bit()))];
    check_circuit(&circuit, K, &[public], CheckMode::Strict)
        .expect("synthesis")
        .is_satisfied()
}

/// The forgeries among `forgeries` the checker accepts (in parallel).
fn accepted_forgeries(forgeries: &[Forgery]) -> Vec<Forgery> {
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 8);
    let chunk = forgeries.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        // Spawn every worker before joining any.
        let mut handles = Vec::new();
        for chunk in forgeries.chunks(chunk) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .copied()
                    .filter(|forgery| forgery_accepted(*forgery))
                    .collect::<Vec<_>>()
            }));
        }
        let mut accepted = Vec::new();
        for handle in handles {
            accepted.extend(handle.join().expect("forgery thread"));
        }
        accepted
    })
}

/// Every soft test's bit is a function of its input: the honest witness is
/// accepted, and no witness for the other bit is (the inverse, difference
/// and carry candidates include the honest ones, zero, one and wrapped
/// values).
#[test]
fn p256_soft_tests_reject_forged_witnesses() {
    let mut rng = ChaCha20Rng::seed_from_u64(50);
    let random = random_scalar(&mut rng);
    let n_minus_one = ORDER.neg(&[1, 0, 0, 0]);
    let mut honest = Vec::new();
    let mut forged = Vec::new();
    // is_zero_mod: zero as 0 and as n, nonzero values.
    for v in [[0; 4], N, [1, 0, 0, 0], n_minus_one, random, [u64::MAX; 4]] {
        let truth = Forgery::honest_is_zero(v);
        honest.push(truth);
        let Forgery::IsZero { zero, inverse, .. } = truth else {
            unreachable!()
        };
        for candidate in [inverse, [0; 4], [1, 0, 0, 0], random_scalar(&mut rng)] {
            forged.push(Forgery::IsZero {
                v,
                zero: !zero,
                inverse: candidate,
            });
        }
    }
    // soft_le at the verifier's bounds, on both sides of each bound.
    let p_minus_one = BASE.neg(&[1, 0, 0, 0]);
    for bound in [n_minus_one, HALF_N, p_minus_one] {
        let above = Nat::from_words(bound).wrapping_add(&Nat::ONE).low_words();
        for x in [bound, above, [0; 4], [u64::MAX; 4]] {
            let truth = Forgery::honest_le(x, bound);
            honest.push(truth);
            let Forgery::Le { d, c, .. } = truth else {
                unreachable!()
            };
            let wrapped = Nat::from_words(bound)
                .wrapping_sub(&Nat::from_words(x))
                .low_words();
            let next = Nat::from_words(d).wrapping_add(&Nat::ONE).low_words();
            for k1 in [false, true] {
                // The other verdict with every candidate difference.
                for candidate in [d, wrapped, [0; 4], [u64::MAX; 4]] {
                    forged.push(Forgery::Le {
                        x,
                        bound,
                        d: candidate,
                        k1,
                        c: !c,
                    });
                }
                // The honest verdict with a wrong difference.
                forged.push(Forgery::Le {
                    x,
                    bound,
                    d: next,
                    k1,
                    c,
                });
            }
        }
    }
    for truth in &honest {
        assert!(forgery_accepted(*truth), "honest {truth:?}");
    }
    assert_eq!(accepted_forgeries(&forged), Vec::new());
}

// ---------------------------------------------------------------------------
// Per-cell tamper suites.
// ---------------------------------------------------------------------------

/// The `+1` tampers among `cells` that the strict checker accepts (in
/// parallel; the result does not depend on the thread count).
fn undetected_among<C: Circuit<Fq> + Sync>(
    circuit: &C,
    public: &[Fq],
    cells: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .max(1);
    let chunk = cells.len().div_ceil(threads).max(1);
    let instances = [public.to_vec()];
    let mut undetected: Vec<(usize, usize)> = std::thread::scope(|scope| {
        // Spawn every worker before joining any.
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
                            delta: Fq::ONE,
                        };
                        check_tampered(circuit, K, instances, Some(tamper))
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

/// Every assigned cell of the soft tests (honest witnesses on both sides of
/// each test) is pinned.
#[test]
fn p256_soft_tests_every_cell_is_pinned() {
    let mut rng = ChaCha20Rng::seed_from_u64(60);
    let cases = [
        Forgery::honest_is_zero([0; 4]),
        Forgery::honest_is_zero(random_scalar(&mut rng)),
        Forgery::honest_le(HALF_N, HALF_N),
        Forgery::honest_le(random_words(&mut rng), HALF_N),
    ];
    for forgery in cases {
        let circuit = ForgeryCircuit { forgery };
        let public = vec![Fq::from(u64::from(forgery.bit()))];
        let cells =
            assigned_advice_cells(&circuit, K, core::slice::from_ref(&public)).expect("cells");
        assert!(!cells.is_empty());
        assert_eq!(
            undetected_among(&circuit, &public, &cells),
            Vec::new(),
            "{forgery:?}"
        );
    }
}

/// Every window cell, every `glue_stride`-th glue cell and every
/// `ff_stride`-th foreign-field cell (column-major order) of `cells`.
///
/// A strict check of a `k = 16` circuit takes seconds, so the release
/// suites tamper every cell of the window lookup (the chip's own argument)
/// and evenly spaced samples of the glue rows (the chip's linear
/// combinations, soft tests and selections) and of the foreign-field blocks
/// (whose own every-cell suite is `ff_every_cell_is_pinned_p256_in_fq`).
fn sampled_cells(
    cells: &[(usize, usize)],
    glue_stride: usize,
    ff_stride: usize,
) -> Vec<(usize, usize)> {
    let glue = FF_ADVICE_COLUMNS..FF_ADVICE_COLUMNS + 4;
    let window = FF_ADVICE_COLUMNS + 4..FF_ADVICE_COLUMNS + 8;
    let (mut glue_index, mut ff_index) = (0_usize, 0_usize);
    let mut out = Vec::new();
    for cell in cells {
        let keep = if window.contains(&cell.0) {
            true
        } else if glue.contains(&cell.0) {
            glue_index += 1;
            (glue_index - 1) % glue_stride == 0
        } else {
            ff_index += 1;
            (ff_index - 1) % ff_stride == 0
        };
        if keep {
            out.push(*cell);
        }
    }
    out
}

/// The window cells and samples of the other cells of a fixed-key circuit
/// with an accepted and a rejected (defaulted) soft verification are
/// pinned.
#[test]
#[ignore = "about 2,700 tampered k = 16 checks; run in release"]
fn p256_window_and_sampled_cells_are_pinned_fixed_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(61);
    let (valid, d) = valid_case(&mut rng, VerifyMode::Soft);
    let key = public_key(&d);
    let accepted = Case {
        key: KeyCase::fixed(0),
        ..valid.clone()
    };
    let rejected = Case {
        r: [0; 4],
        ..accepted.clone()
    };
    let circuit = P256Circuit::new(&[key], vec![accepted, rejected]);
    let public = circuit.expected();
    assert_eq!(public, vec![Fq::ONE, Fq::ZERO]);
    let all = assigned_advice_cells(&circuit, K, core::slice::from_ref(&public)).expect("cells");
    let cells = sampled_cells(&all, 6, 60);
    let start = Instant::now();
    assert_eq!(undetected_among(&circuit, &public, &cells), Vec::new());
    eprintln!(
        "fixed-key tamper: {} of {} cells, {:?}",
        cells.len(),
        all.len(),
        start.elapsed()
    );
}

/// The window cells and samples of the other cells of an accepted and a
/// rejected (key off the curve) variable-key soft verification are pinned.
#[test]
#[ignore = "about 3,700 tampered k = 16 checks; run in release"]
fn p256_window_and_sampled_cells_are_pinned_variable_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(62);
    let (accepted, _) = valid_case(&mut rng, VerifyMode::Soft);
    // Off the curve: the key and the scalars take their defaults.
    let rejected = Case {
        key: KeyCase::variable(accepted.key.x, BASE.add(&accepted.key.y, &[1, 0, 0, 0])),
        ..accepted.clone()
    };
    let circuit = P256Circuit::new(&[], vec![accepted, rejected]);
    let public = circuit.expected();
    assert_eq!(public, vec![Fq::ONE, Fq::ZERO]);
    let all = assigned_advice_cells(&circuit, K, core::slice::from_ref(&public)).expect("cells");
    let cells = sampled_cells(&all, 24, 240);
    let start = Instant::now();
    assert_eq!(undetected_among(&circuit, &public, &cells), Vec::new());
    eprintln!(
        "variable-key tamper: {} of {} cells, {:?}",
        cells.len(),
        all.len(),
        start.elapsed()
    );
}

/// The Q-leaf layout of [`leaf_circuit`]: every window cell (glue columns
/// below the split), every 8th SHA-256 cell, every 24th glue cell and every
/// 240th foreign-field cell is pinned. The SHA-256 and window lookups ride
/// on foreign-field range arguments here, so this is their tamper suite on
/// the shared table.
#[test]
#[ignore = "about 7,000 tampered k = 16 checks; run in release"]
fn p256_leaf_window_sha_and_sampled_cells_are_pinned() {
    let circuit = leaf_circuit(14);
    let public = circuit.expected();
    let all = assigned_advice_cells(&circuit, K, core::slice::from_ref(&public)).expect("cells");
    let split = q_leaf::sha_rows(2);
    let glue = FF_ADVICE_COLUMNS..FF_ADVICE_COLUMNS + 4;
    let (mut sha_index, mut glue_index, mut ff_index) = (0_usize, 0_usize, 0_usize);
    let every = |index: &mut usize, stride: usize| {
        *index += 1;
        (*index - 1).is_multiple_of(stride)
    };
    let cells: Vec<(usize, usize)> = all
        .iter()
        .copied()
        .filter(
            |(column, row)| match (glue.contains(column), *row < split) {
                (true, true) => true,
                (true, false) => every(&mut glue_index, 24),
                (false, true) => every(&mut sha_index, 8),
                (false, false) => every(&mut ff_index, 240),
            },
        )
        .collect();
    let start = Instant::now();
    assert_eq!(undetected_among(&circuit, &public, &cells), Vec::new());
    eprintln!(
        "leaf tamper: {} of {} cells, {:?}",
        cells.len(),
        all.len(),
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Release measurement: a real proof.
// ---------------------------------------------------------------------------

/// One witness-key verification with its message (SHA-256 of a Poseidon
/// digest) and one fixed-key verification in the 17-column Q-leaf layout,
/// proved at `k = 16` with the KAGEMUSHA transcript on Pallas and verified.
#[test]
#[ignore = "k = 16 proof; run in release"]
fn p256_proof_measurement_release() {
    use std::convert::Infallible;

    use iroha_pasta::{Ep, msm::MemoryBudget};
    use iroha_plonk::{
        ProverConfig, ProverRandomness,
        cs::{InstanceModeV1, ProofSuffixV1, TranscriptV1},
        keys::{KeygenConfig, keygen_pk},
        pcs::ipa::PinnedParams,
        prove_circuit, verify_full,
    };

    let circuit = leaf_circuit(70);
    let public = circuit.expected();
    assert_eq!(public, vec![Fq::ONE, Fq::ONE]);
    let (cs, _) = configure(&circuit).expect("configure");
    let inventory = Inventory::of(&circuit);
    let started = Instant::now();
    let report = check(&circuit, &public);
    let check_ms = started.elapsed().as_millis();
    assert!(report.is_satisfied(), "{report}");
    let params = PinnedParams::<Ep>::derive(K).expect("params");
    let mut config = KeygenConfig::new(TranscriptV1::KagemushaPoseidonRp57);
    config.instance_mode = InstanceModeV1::Direct;
    config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    let started = Instant::now();
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("keys");
    let keygen_ms = started.elapsed().as_millis();
    let randomness = ProverRandomness::recovery(move |_context: &[u8; 32]| {
        Ok::<_, Infallible>(ChaCha20Rng::from_seed([7; 32]))
    });
    let started = Instant::now();
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
        "P256_PROOF k={K} advice={} fixed={} lookups={} degree={} cells={} ff_rows={} span={} \
         proof_bytes={} check_ms={check_ms} keygen_ms={keygen_ms} prove_ms={prove_ms} \
         verify_ms={verify_ms} available_parallelism={}",
        cs.num_advice_columns(),
        cs.num_fixed_columns(),
        cs.lookups().len(),
        cs.degree(),
        inventory.cells(),
        inventory.ff_rows,
        inventory.span,
        proof.len(),
        std::thread::available_parallelism().map_or(0, usize::from),
    );
}

// ---------------------------------------------------------------------------
// Dynamic tables of separate window chips.
// ---------------------------------------------------------------------------

/// Two window chips on one configuration (as two [`P256Chip`]s, or a cloned
/// chip, would lay them out), each with the dynamic table of its own key;
/// chip A decomposes `k` and selects its window points from the multiples of
/// `keys[selected]` under A's tag.
#[derive(Clone, Debug)]
struct TwoTablesCircuit {
    keys: [Affine; 2],
    k: [u64; 4],
    selected: usize,
}

impl Circuit<Fq> for TwoTablesCircuit {
    type Config = (FfConfig, P256Config);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let ff_columns = core::array::from_fn(|_| meta.advice_column());
        let ff = FfConfig::configure(meta, ff_columns, &P256_MODULI);
        let window_columns = core::array::from_fn(|_| meta.advice_column());
        let p256 = P256Config::configure(meta, window_columns, &[]);
        (ff, p256)
    }

    fn synthesize(
        &self,
        (ff, p256): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut ff = FfChip::new(ff);
        ff.load_table(&mut layouter)?;
        layouter.assign_region(
            || "two dynamic tables",
            |mut region| {
                // Disjoint rows of the same four window columns.
                let mut chips = [
                    WindowChip::starting_at(*p256.window(), 0),
                    WindowChip::starting_at(*p256.window(), 1_000),
                ];
                let mut tables = Vec::with_capacity(2);
                let mut tags = Vec::with_capacity(2);
                for (key, chip) in self.keys.iter().zip(chips.iter_mut()) {
                    let mut table = Vec::with_capacity(window::DYNAMIC_ENTRIES);
                    for e in 1..=window::DYNAMIC_ENTRIES {
                        let e = u64::try_from(e).map_err(|_| Error::Synthesis)?;
                        let point = native::mul(key, &[e, 0, 0, 0]).ok_or(Error::Synthesis)?;
                        let base = ForeignModulus::P256_BASE;
                        let x = ff.witness(&mut region, base, Value::known(point.x))?;
                        let y = ff.witness(&mut region, base, Value::known(point.y))?;
                        table.push((x, y));
                    }
                    tags.push(chip.dynamic_table(&mut region, &table)?);
                    tables.push(table);
                }
                let k = ff.witness(
                    &mut region,
                    ForeignModulus::P256_ORDER,
                    Value::known(self.k),
                )?;
                let [chip_a, _] = &mut chips;
                chip_a.decompose(
                    &mut region,
                    &k,
                    &windows(window::VARIABLE_WINDOW_BITS),
                    TableSource::Dynamic {
                        tag: tags[0],
                        entries: &tables[self.selected],
                    },
                    3,
                )?;
                Ok(())
            },
        )
    }
}

/// A dynamic table's tag is unique in the circuit, not per chip: window
/// lookups under one key's tag cannot select another key's multiples, even
/// when two chips (two [`P256Chip`]s on one configuration, or a clone) lay
/// out dynamic tables on the same columns. With a per-chip counter both
/// tables got tag `2^32`, and a chain could run on a key the prover chose.
#[test]
fn p256_dynamic_tables_of_separate_chips_do_not_alias() {
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let keys = [random_point(&mut rng), random_point(&mut rng)];
    let k = random_scalar(&mut rng);
    let satisfied = |selected| {
        check_circuit(
            &TwoTablesCircuit { keys, k, selected },
            K,
            &[],
            CheckMode::Strict,
        )
        .expect("synthesis")
        .is_satisfied()
    };
    assert!(satisfied(0), "the chip's own multiples");
    assert!(
        !satisfied(1),
        "another chip's multiples under this chip's tag"
    );
}

/// Dynamic tags follow their table's first row; fixed tags are accepted
/// only below the per-base stride and below `2^32`, so no two tables share a
/// tag.
#[test]
fn p256_window_tags_are_unique_by_construction() {
    assert_eq!(window::dynamic_tag(0), Ok(1 << 32));
    assert_eq!(window::dynamic_tag(7_940), Ok((1 << 32) + 7_940));
    assert_eq!(window::checked_fixed_tag(0, 0), Ok(1));
    assert_eq!(
        window::checked_fixed_tag(2, 32),
        Ok(window::fixed_tag(2, 32))
    );
    // Window 64 of base 0 would be window 0 of base 1.
    assert_eq!(window::fixed_tag(0, 64), window::fixed_tag(1, 0));
    assert_eq!(window::checked_fixed_tag(0, 64), Err(Error::Synthesis));
    // The last fixed tag below 2^32, and the first one that would reach it.
    let base = (1_usize << 26) - 1;
    assert_eq!(window::checked_fixed_tag(base, 62), Ok((1 << 32) - 1));
    assert_eq!(window::checked_fixed_tag(base, 63), Err(Error::Synthesis));
}

// ---------------------------------------------------------------------------
// The protocol's own signatures.
// ---------------------------------------------------------------------------

/// One signature of `fixtures/kagemusha/wallet_v1_vectors.json`: the signing
/// message `m` (a Poseidon digest), the key, `(r, s)` and the consumer
/// verdict.
struct ProtocolSignature {
    object: String,
    message: [u8; 32],
    key: Affine,
    r: [u64; 4],
    s: [u64; 4],
    accepted: bool,
}

fn protocol_signatures() -> Vec<ProtocolSignature> {
    use norito::json::Value as Json;
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_v1_vectors.json");
    let text = std::fs::read_to_string(&path).expect("read the wallet vectors");
    let json = norito::json::parse_value(&text).expect("parse the wallet vectors");
    let text_of = |value: &Json, key: &str| -> String {
        value.get(key).and_then(Json::as_str).expect(key).to_owned()
    };
    let flag = |value: &Json, key: &str| value.get(key).and_then(Json::as_bool).expect(key);
    json.get("signatures")
        .and_then(Json::as_array)
        .expect("signatures")
        .iter()
        .map(|vector| {
            let message: [u8; 32] = hex_bytes(&text_of(vector, "message_hex"))
                .try_into()
                .expect("32-byte message");
            let key = hex_bytes(&text_of(vector, "public_key_hex"));
            assert_eq!((key.len(), key[0]), (65, 4));
            let signature = hex_bytes(&text_of(vector, "signature_hex"));
            assert_eq!(signature.len(), 64);
            ProtocolSignature {
                object: text_of(vector, "object"),
                message,
                key: Affine {
                    x: words_of_be_slice(&key[1..33]),
                    y: words_of_be_slice(&key[33..]),
                },
                r: words_of_be_slice(&signature[..32]),
                s: words_of_be_slice(&signature[32..]),
                accepted: flag(vector, "codec_ok") && flag(vector, "verify_ok"),
            }
        })
        .collect()
}

/// The in-circuit message path reproduces the protocol's signatures: every
/// signing message of the shared wallet vectors (ECDSA-P256-SHA256 over the
/// 32-byte canonical little-endian encoding of `P_bytes(domain,
/// transcript)`, `kagemusha_wallet_signing_message_v1`) is the codec's
/// encoding of its digest, and each signature verifies in circuit from the
/// digest cell, while another object's message does not. Reading the 32
/// bytes big-endian instead would not even give an `Fp` value for most of
/// them.
#[test]
fn p256_protocol_signature_fixtures_verify_from_the_digest() {
    let vectors = protocol_signatures();
    assert_eq!(
        vectors
            .iter()
            .map(|vector| vector.object.as_str())
            .collect::<Vec<_>>(),
        [
            "payer issuer certificate",
            "payer credential",
            "Offer",
            "Request",
            "Send receipt",
            "Receive receipt binding the Payment digest",
            "Close session control",
            "scheme policy",
            "fee schedule",
            "blacklist",
            "quota share",
            "time anchor",
            "Activate ledger control",
            "renewal possession",
            "Android renewal key binding",
            "artifact manifest",
            "load charge quote",
        ]
    );
    let mut cases = Vec::with_capacity(vectors.len() + 1);
    let mut big_endian_out_of_range = 0;
    for vector in &vectors {
        let m = Fp::from_repr(vector.message)
            .into_option()
            .expect("a canonical little-endian Fp encoding");
        assert_eq!(
            crate::sha256::native::digest_message(&m),
            vector.message,
            "{}",
            vector.object
        );
        let mut reversed = vector.message;
        reversed.reverse();
        big_endian_out_of_range += usize::from(bool::from(Fp::from_repr(reversed).is_none()));
        let case = Case {
            mode: VerifyMode::Soft,
            key: KeyCase::variable(vector.key.x, vector.key.y),
            message: MessageCase::Digest(m),
            r: vector.r,
            s: vector.s,
        };
        assert!(vector.accepted, "{}", vector.object);
        assert_eq!(case.native(&[]), vector.accepted, "{}", vector.object);
        cases.push(case);
    }
    assert!(big_endian_out_of_range > 0);
    // The first signature over the second object's message.
    let mut swapped = cases[0].clone();
    swapped.message = cases[1].message;
    assert!(!swapped.native(&[]));
    cases.push(swapped);
    assert_cases_match_native(&[], &cases, "protocol signatures");
}
