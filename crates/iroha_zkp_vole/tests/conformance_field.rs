//! Field conformance: every entry of the official `field_tvs` vectors (binary
//! polynomial multiplication by `M_tree` and reduction modulo the first tree
//! modulus) and the field known answers of the upstream `tests/fields.cpp`.

mod common;

use common::Fixture;
use iroha_zkp_vole::{
    field::{
        BinaryField, FieldError, Gf128, Gf192, Gf256, LambdaField,
        poly::{poly_mul, poly_reduce, smallest_irreducibles},
    },
    params::{FAEST_PARAMETER_SETS, VoleParams},
};

/// Fixture namespaces in the order of `FAEST_PARAMETER_SETS`.
const SET_NAMES: [&str; 12] = [
    "FAEST_128S",
    "FAEST_128F",
    "FAEST_192S",
    "FAEST_192F",
    "FAEST_256S",
    "FAEST_256F",
    "FAEST_EM_128S",
    "FAEST_EM_128F",
    "FAEST_EM_192S",
    "FAEST_EM_192F",
    "FAEST_EM_256S",
    "FAEST_EM_256F",
];

/// The encoding of an integer polynomial with `bits` coefficients.
fn encode(poly: u32, bits: usize) -> Vec<u8> {
    poly.to_le_bytes()[..bits.div_ceil(8)].to_vec()
}

/// The tree moduli of FAEST v3.0 Appendix B: for the `tau_1` instances of bit length
/// `k` the smallest irreducible polynomials of degree `k`, then for the `tau_0`
/// instances of bit length `k - 1` the smallest of degree `k - 1`.
///
/// The reference implementation reads these from its generated CRT tables
/// (`params.TREE_MODULI`), which belong to the CRT stage of this crate. Until that
/// stage lands they are derived here from the rule of the specification; the
/// official vectors below confirm both the rule and the integer ordering.
fn tree_moduli(vole: &VoleParams) -> Vec<(u32, usize)> {
    let degree = |d: usize| u32::try_from(d).expect("small degree");
    let mut moduli = Vec::new();
    for poly in smallest_irreducibles(degree(vole.k()), vole.tau1()).expect("enough moduli") {
        moduli.push((poly, vole.k()));
    }
    for poly in smallest_irreducibles(degree(vole.k() - 1), vole.tau0()).expect("enough moduli") {
        moduli.push((poly, vole.k() - 1));
    }
    moduli
}

/// `M_tree`, the product of the tree moduli, with `n_Delta + 1` coefficients.
fn m_tree(vole: &VoleParams) -> Vec<u8> {
    let mut product = vec![1u8];
    let mut bits = 1;
    for (poly, degree) in tree_moduli(vole) {
        let mut next = vec![0u8; (bits + degree).div_ceil(8)];
        poly_mul(
            &mut next,
            &product,
            bits,
            &encode(poly, degree + 1),
            degree + 1,
        )
        .expect("valid lengths");
        product = next;
        bits += degree;
    }
    assert_eq!(bits, vole.n_delta() + 1);
    product
}

#[test]
fn every_field_vector_is_reproduced() {
    let fixture = Fixture::load("field_tvs");
    for (set, name) in FAEST_PARAMETER_SETS.iter().zip(SET_NAMES) {
        let vole = set.vole();
        let entry = |field: &str| format!("field_tvs.{name}.{field}");

        // res = bf2_poly_mul(lhs, w_grind, M_TREE, lambda - w_grind + 1).
        let lhs = fixture.bytes(&entry("lhs"));
        let expected = fixture.bytes(&entry("res"));
        assert_eq!(lhs.len(), vole.w_grind().div_ceil(8));
        assert_eq!(expected.len(), vole.lambda().bytes());
        let modulus = m_tree(vole);
        let mut res = vec![0u8; expected.len()];
        poly_mul(&mut res, &lhs, vole.w_grind(), &modulus, vole.n_delta() + 1)
            .expect("valid lengths");
        assert_eq!(res, expected, "{name} res");

        // deg = bavc_max_node_depth(0, tau1, k) = d_0.
        let deg = usize::try_from(fixture.integer(&entry("deg"))).expect("small");
        assert_eq!(deg, vole.d0(), "{name} deg");
        assert_eq!(vole.depth(0), Some(deg));

        // reduced = bf2_poly_reduce(unreduced, 2 * deg, TREE_MODULI[0], deg + 1).
        // Upstream writes the remainder into a buffer as long as the input; here the
        // remainder has ceil(deg / 8) bytes and the rest of the vector must be zero.
        let unreduced = fixture.bytes(&entry("unreduced"));
        let expected = fixture.bytes(&entry("reduced"));
        let (first, first_degree) = tree_moduli(vole)[0];
        assert_eq!(first_degree, deg);
        let mut reduced = vec![0u8; deg.div_ceil(8)];
        poly_reduce(
            &mut reduced,
            &unreduced,
            2 * deg,
            &encode(first, deg + 1),
            deg + 1,
        )
        .expect("valid lengths");
        assert_eq!(reduced[..], expected[..reduced.len()], "{name} reduced");
        assert!(expected[reduced.len()..].iter().all(|byte| *byte == 0));
    }
    fixture.assert_consumed("");
}

fn element<F: BinaryField>(bytes: &[u8], index: usize) -> F {
    F::from_bytes(&bytes[index * F::BYTES..(index + 1) * F::BYTES]).expect("exact length")
}

fn upstream_field_vectors<F: LambdaField>(fixture: &Fixture) {
    const TEST_VEC_LEN: usize = 16;
    let bits = F::BITS;

    // test_bf<L>_test_vectors.
    let name = |field: &str| format!("fields.test_bf{bits}_test_vectors.{field}");
    let lhs: F = element(&fixture.bytes(&name("lhs")), 0);
    let rhs: F = element(&fixture.bytes(&name("rhs")), 0);
    let expected: F = element(&fixture.bytes(&name("expected")), 0);
    assert_eq!(lhs * rhs, expected);
    let swapped = rhs * lhs;
    assert_eq!(swapped, expected);

    // test_bf<L>_test_vectors_with64: the right operand has 64 coefficients.
    let name = |field: &str| format!("fields.test_bf{bits}_test_vectors_with64.{field}");
    let lhs: F = element(&fixture.bytes(&name("lhs")), 0);
    let rhs = u64::from_le_bytes(fixture.bytes(&name("rhs")).try_into().expect("8 bytes"));
    let expected: F = element(&fixture.bytes(&name("expected")), 0);
    assert_eq!(lhs.mul_u64(rhs), expected);
    assert_eq!(lhs * F::from_u64(rhs), expected);

    // test_bf<L>_tv: sixteen products.
    let xs = fixture.bytes(&format!("fields.enc_poly{bits}_vec_xs"));
    let ys = fixture.bytes(&format!("fields.enc_poly{bits}_vec_ys"));
    let products = fixture.bytes(&format!("fields.enc_poly{bits}_vec_products"));
    assert_eq!(xs.len(), TEST_VEC_LEN * F::BYTES);
    for i in 0..TEST_VEC_LEN {
        let (x, y, product): (F, F, F) = (element(&xs, i), element(&ys, i), element(&products, i));
        assert_eq!(x * y, product, "GF(2^{bits}) product {i}");
        // Division: the inverse recovers each factor from the product.
        if !y.is_zero() {
            assert_eq!(product * y.invert_or_zero(), x, "GF(2^{bits}) quotient {i}");
        }
    }

    // test_bf<L>_byte_combine_bits.
    let inputs = fixture.bytes(&format!("fields.poly{bits}_from_8_poly1_input"));
    let outputs = fixture.bytes(&format!("fields.poly{bits}_from_8_poly1_output"));
    assert_eq!(inputs.len(), TEST_VEC_LEN);
    for (i, byte) in inputs.iter().enumerate() {
        assert_eq!(
            F::byte_combine_bits(*byte),
            element::<F>(&outputs, i),
            "GF(2^{bits}) ByteCombine of bits {i}"
        );
    }

    // test_bf<L>_byte_combine.
    let inputs = fixture.bytes(&format!("fields.poly{bits}_from_8_poly{bits}_input"));
    let outputs = fixture.bytes(&format!("fields.poly{bits}_from_8_poly{bits}_output"));
    assert_eq!(inputs.len(), 8 * TEST_VEC_LEN * F::BYTES);
    for i in 0..TEST_VEC_LEN {
        let mut x = [F::ZERO; 8];
        for (b, slot) in x.iter_mut().enumerate() {
            *slot = element(&inputs, 8 * i + b);
        }
        assert_eq!(
            F::byte_combine(&x),
            element::<F>(&outputs, i),
            "GF(2^{bits}) ByteCombine {i}"
        );
    }

    // test_bf<L>_sum_poly: element `b mod 128` is the coefficient of x^b.
    let expected: F = element(
        &fixture.bytes(&format!("fields.poly{bits}_sum_poly_output")),
        0,
    );
    let coefficients: Vec<F> = (0..bits).map(|b| element(&inputs, b % 128)).collect();
    assert_eq!(F::sum_poly(&coefficients), Ok(expected));
}

#[test]
fn upstream_field_known_answers() {
    let fixture = Fixture::load_extracted();
    upstream_field_vectors::<Gf128>(&fixture);
    upstream_field_vectors::<Gf192>(&fixture);
    upstream_field_vectors::<Gf256>(&fixture);
    fixture.assert_consumed("fields.");
}

/// Deterministic pseudo-random bytes (`xorshift64*`) for the property tests.
struct Xorshift(u64);

impl Xorshift {
    fn element<F: BinaryField>(&mut self) -> F {
        let bytes: Vec<u8> = (0..F::BYTES)
            .map(|_| {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                self.0.wrapping_mul(0x2545_f491_4f6c_dd1d).to_be_bytes()[0]
            })
            .collect();
        F::from_bytes(&bytes).expect("exact length")
    }
}

fn field_axioms<F: LambdaField>(seed: u64) {
    let mut rng = Xorshift(seed);
    for _ in 0..40 {
        let (a, b, c): (F, F, F) = (rng.element(), rng.element(), rng.element());
        let (sum, swapped) = (a + b, b + a);
        assert_eq!(sum, swapped);
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!(a + a, F::ZERO);
        let (product, swapped) = (a * b, b * a);
        assert_eq!(product, swapped);
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
        assert_eq!(a * F::ONE, a);
        assert_eq!(a.square(), a * a);
        // The Frobenius map is additive and multiplicative.
        assert_eq!((a + b).square(), a.square() + b.square());
        assert_eq!((a * b).square(), a.square() * b.square());
        // The tripled field contains the products of widened elements only up to
        // reduction: widening is additive.
        assert_eq!((a + b).widen(), a.widen() + b.widen());
        let wide: F::Tripled = rng.element();
        assert_eq!(
            (a + b).mul_tripled(wide),
            a.mul_tripled(wide) + b.mul_tripled(wide)
        );
    }
    for _ in 0..4 {
        let a: F = rng.element();
        let b: F = rng.element();
        if a.is_zero() || b.is_zero() {
            continue;
        }
        assert_eq!(a * a.invert_or_zero(), F::ONE);
        assert_eq!(
            (a * b).invert_or_zero(),
            a.invert_or_zero() * b.invert_or_zero()
        );
    }
}

#[test]
fn field_axioms_on_pseudo_random_elements() {
    field_axioms::<Gf128>(0x1111_2222_3333_4444);
    field_axioms::<Gf192>(0x5555_6666_7777_8888);
    field_axioms::<Gf256>(0x9999_aaaa_bbbb_cccc);
}

#[test]
fn wrong_lengths_are_rejected_with_typed_errors() {
    assert_eq!(
        Gf128::from_bytes(&[0; 17]),
        Err(FieldError::InvalidLength {
            expected: 16,
            actual: 17
        })
    );
    assert_eq!(
        Gf192::vec_from_bytes(&[0; 25]),
        Err(FieldError::InvalidLength {
            expected: 48,
            actual: 25
        })
    );
    assert_eq!(
        Gf256::sum_poly(&[Gf256::ONE; 255]),
        Err(FieldError::InvalidCount {
            expected: 256,
            actual: 255
        })
    );
    let mut out = [0u8; 16];
    assert_eq!(poly_mul(&mut out, &[0x61], 7, &[0; 16], 122), Ok(()));
    assert_eq!(
        poly_mul(&mut out, &[0x61], 7, &[0; 16], 123),
        Err(FieldError::InvalidLength {
            expected: 17,
            actual: 16
        })
    );
    assert_eq!(
        poly_reduce(&mut out[..2], &[0; 3], 22, &[0x05, 0x00], 12),
        Err(FieldError::InvalidModulus)
    );
}
