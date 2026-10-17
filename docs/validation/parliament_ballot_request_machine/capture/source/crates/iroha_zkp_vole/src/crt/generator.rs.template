//! The deterministic construction of a CRT table set from `(lambda, tau, w_grind)`.
//! It follows the table generator of the FAEST v3.0.2 reference implementation
//! (MIT licence; see the attribution in the [module root](super)).
//!
//! The product of a `lambda`-bit field element with the `n_delta`-bit challenge is
//! recovered by the Chinese remainder theorem from its residues modulo the tree
//! moduli, which the small VOLEs provide for free, and modulo a portfolio of extra
//! places covering the remaining `lambda - 1` coordinates, each of which costs
//! multiplication gates. The generator picks the cheapest portfolio, builds the
//! gates, and expresses the product reduced modulo the field polynomial in terms
//! of the tree residues (`W_TREE`) and the gates (`W_GATE`).
//!
//! Only integer and bit operations are used, all inputs are public, every search
//! visits its candidates in a fixed ascending order, and there is no state outside
//! one call: the same triple gives the same tables on every platform.
//!
//! Two properties the reference relies on without checking are checked here and
//! reported as errors: every place returns one gate mask per evaluation row
//! ([`CrtError::PlaceRowMismatch`]), and every linear system that is inverted is
//! square ([`CrtError::NotSquare`]). Both hold for the eight standard profiles.

use std::collections::BTreeMap;

use super::{
    algo::AlgBuilder,
    bits::{Bits, index},
    cost::Place,
    error::CrtError,
    gf2poly,
    linalg::{combine, left_inverse, reduction_rows, row},
    matrix::BitMatrix,
    tables::{CrtTables, Profile, TableWords},
};
use crate::field::poly::smallest_irreducibles;

/// Largest multiplicity of the place at infinity and of the linear places.
const MAX_LINEAR_MULTIPLICITY: usize = 10;

/// Largest degree of an extra irreducible place, and the cap on the degree of a
/// power of `x^2 + x + 1`.
const MAX_EXTRA_DEGREE: usize = 10;

/// The outcome of a table construction, with the choices that led to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// The tables.
    pub tables: CrtTables<'static>,
    /// The extra places of the portfolio, in the order their gates appear.
    pub places: Vec<Place>,
    /// Gate count the portfolio search arrived at.
    pub search_cost: u64,
    /// Number of gates before duplicate and unused gates are removed; `n_mult` is
    /// the number after.
    pub raw_gates: u32,
}

/// The field polynomial of `GF(2^lambda)`, for the three supported sizes.
fn field_modulus(lambda: u32) -> Option<Bits> {
    let low = match lambda {
        128 | 192 => 0b1000_0111,
        256 => 0b100_0010_0101,
        _ => return None,
    };
    let mut modulus = Bits::from_u64(low);
    modulus.set(index(lambda));
    Some(modulus)
}

/// The tree moduli as `(degree, count)` groups: with `n_delta = lambda - w_grind`,
/// `k = n_delta / tau + 1` and `tau_1 = n_delta mod tau`, there are `tau_1` moduli
/// of degree `k` (omitted if none) followed by `tau - tau_1` of degree `k - 1`.
///
/// # Errors
/// [`CrtError::UnsupportedParameters`] unless `0 < w_grind < lambda` and
/// `1 <= tau <= lambda - w_grind`.
pub fn tree_spec(lambda: u32, tau: u32, w_grind: u32) -> Result<Vec<(u32, u32)>, CrtError> {
    let unsupported = CrtError::UnsupportedParameters {
        lambda,
        tau,
        w_grind,
    };
    if w_grind == 0 || w_grind >= lambda || tau == 0 || tau > lambda - w_grind {
        return Err(unsupported);
    }
    let n_delta = lambda - w_grind;
    let upper = n_delta / tau + 1;
    let upper_count = n_delta % tau;
    let mut spec = Vec::with_capacity(2);
    if upper_count != 0 {
        spec.push((upper, upper_count));
    }
    spec.push((upper - 1, tau - upper_count));
    Ok(spec)
}

/// The CRT lift: `M_TREE`, the product of the moduli, and for every residue
/// coordinate the polynomial of degree below `deg M_TREE` that is `x^b` modulo its
/// own modulus and zero modulo the others.
fn crt_lift_cols(moduli: &[Bits]) -> Result<(Bits, Vec<Bits>), CrtError> {
    let m_tree = moduli.iter().fold(Bits::from_u64(1), |acc, modulus| {
        gf2poly::mul(&acc, modulus)
    });
    let mut columns = Vec::new();
    for modulus in moduli {
        let (cofactor, remainder) = gf2poly::divmod(&m_tree, modulus)?;
        if !remainder.is_zero() {
            return Err(CrtError::Construction {
                what: "a tree modulus does not divide their product",
            });
        }
        let idempotent =
            gf2poly::mulmod(&cofactor, &gf2poly::invmod(&cofactor, modulus)?, &m_tree)?;
        for power in 0..modulus.degree().unwrap_or(0) {
            columns.push(gf2poly::mulmod(&idempotent, &Bits::unit(power), &m_tree)?);
        }
    }
    Ok((m_tree, columns))
}

/// The gate lists after pruning: `F`, `G` and `W_GATE`.
type Pruned = (Vec<Bits>, Vec<Bits>, Vec<Bits>);

/// Merge gates with equal forms, drop gates with a zero form and gates no output
/// uses, and renumber the rest in ascending order of their old position.
fn prune(f: &[Bits], g: &[Bits], w_gate: &[Bits]) -> Result<Pruned, CrtError> {
    if f.len() != g.len() {
        return Err(CrtError::Shape {
            what: "gate forms",
            expected: f.len(),
            actual: g.len(),
        });
    }
    let mut canonical: BTreeMap<(&Bits, &Bits), usize> = BTreeMap::new();
    let mut target: Vec<Option<usize>> = Vec::with_capacity(f.len());
    for (position, (left, right)) in f.iter().zip(g).enumerate() {
        target.push(if left.is_zero() || right.is_zero() {
            None
        } else {
            Some(*canonical.entry((left, right)).or_insert(position))
        });
    }
    let missing = CrtError::Construction {
        what: "an output uses a gate that does not exist",
    };
    let mut merged = Vec::with_capacity(w_gate.len());
    let mut used = Bits::zero();
    for mask in w_gate {
        let mut out = Bits::zero();
        for gate in mask.ones() {
            if let Some(kept) = target.get(gate).ok_or(missing)? {
                out.toggle(*kept);
            }
        }
        used.or_assign(&out);
        merged.push(out);
    }
    let mut renumbered: BTreeMap<usize, usize> = BTreeMap::new();
    let mut kept_f = Vec::new();
    let mut kept_g = Vec::new();
    for gate in used.ones() {
        renumbered.insert(gate, kept_f.len());
        kept_f.push(row(f, gate)?.clone());
        kept_g.push(row(g, gate)?.clone());
    }
    let kept_w = merged
        .iter()
        .map(|mask| {
            let mut out = Bits::zero();
            for gate in mask.ones() {
                out.set(*renumbered.get(&gate).ok_or(missing)?);
            }
            Ok(out)
        })
        .collect::<Result<_, CrtError>>()?;
    Ok((kept_f, kept_g, kept_w))
}

/// Pack rows of at most `cols` bits into a matrix.
fn to_matrix(rows: &[Bits], cols: usize) -> Result<BitMatrix<'static>, CrtError> {
    let words_per_row = cols.div_ceil(64);
    let mut data = Vec::with_capacity(rows.len() * words_per_row);
    for bits in rows {
        if bits.bit_len() > cols {
            return Err(CrtError::Construction {
                what: "a table row is wider than its table",
            });
        }
        data.extend(bits.to_words(words_per_row).ok_or(CrtError::Construction {
            what: "a table row is wider than its table",
        })?);
    }
    BitMatrix::from_vec(rows.len(), cols, data)
}

/// Build the tables of a standard profile.
///
/// # Errors
/// As [`generate`]; none occurs for the eight profiles.
pub fn generate_profile(profile: Profile) -> Result<CrtTables<'static>, CrtError> {
    let (lambda, tau, w_grind) = profile.parameters();
    generate(lambda, tau, w_grind)
}

/// Build the tables for `(lambda, tau, w_grind)`.
///
/// # Errors
/// As [`generate_with_report`].
pub fn generate(lambda: u32, tau: u32, w_grind: u32) -> Result<CrtTables<'static>, CrtError> {
    Ok(generate_with_report(lambda, tau, w_grind)?.tables)
}

/// Build the tables for `(lambda, tau, w_grind)` and report the portfolio.
///
/// # Errors
/// * [`CrtError::UnsupportedParameters`] unless `lambda` is 128, 192 or 256,
///   `0 < w_grind < lambda`, `1 <= tau <= lambda - w_grind`, and the tree moduli
///   have degree between 2 and 15;
/// * [`CrtError::Field`] if there are not enough irreducible polynomials for the
///   tree moduli;
/// * [`CrtError::NoPortfolio`] if no set of extra places covers `lambda - 1`
///   coordinates;
/// * [`CrtError::PlaceRowMismatch`] and [`CrtError::NotSquare`] if the construction
///   would leave the regime in which the reference is well defined;
/// * [`CrtError::Singular`], [`CrtError::NotInvertible`] and
///   [`CrtError::Construction`] if an intermediate value is outside its domain.
pub fn generate_with_report(lambda: u32, tau: u32, w_grind: u32) -> Result<Generated, CrtError> {
    let unsupported = CrtError::UnsupportedParameters {
        lambda,
        tau,
        w_grind,
    };
    let field = field_modulus(lambda).ok_or(unsupported)?;
    let spec = tree_spec(lambda, tau, w_grind)?;
    let left_len = index(lambda);
    let right_len = index(lambda - w_grind);
    let product_len = left_len + right_len - 1;

    // Tree moduli: the smallest irreducibles of each degree, the larger degree first.
    let mut tree_moduli: Vec<u16> = Vec::with_capacity(index(tau));
    for (degree, count) in &spec {
        if !(2..=15).contains(degree) {
            return Err(unsupported);
        }
        for poly in smallest_irreducibles(*degree, index(*count))? {
            tree_moduli.push(u16::try_from(poly).map_err(|_| unsupported)?);
        }
    }
    let moduli: Vec<Bits> = tree_moduli
        .iter()
        .map(|modulus| Bits::from_u64(u64::from(*modulus)))
        .collect();

    // Extra places: the cheapest portfolio covering the other coordinates.
    let mut builder = AlgBuilder::default();
    let mut pools = BTreeMap::new();
    for degree in 2..=MAX_EXTRA_DEGREE {
        let pool: Vec<u32> = builder
            .costs
            .irreducibles_of_degree(degree)?
            .into_iter()
            .filter(|poly| {
                !tree_moduli
                    .iter()
                    .any(|modulus| u32::from(*modulus) == *poly)
            })
            .collect();
        if !pool.is_empty() {
            pools.insert(degree, pool);
        }
    }
    let deficit = product_len - right_len;
    let (search_cost, places) = builder
        .costs
        .crt_search(deficit, MAX_LINEAR_MULTIPLICITY, MAX_EXTRA_DEGREE, &pools)?
        .ok_or(CrtError::NoPortfolio { target: deficit })?;

    // Evaluation of the product at the tree moduli and at the extra places.
    let mut evaluation = Vec::with_capacity(product_len);
    for modulus in &moduli {
        evaluation.extend(reduction_rows(modulus, product_len)?);
    }
    if evaluation.len() != right_len {
        return Err(CrtError::Construction {
            what: "the tree moduli do not cover the challenge",
        });
    }
    let mut gates: Vec<(Bits, Bits)> = Vec::new();
    let mut residues = Vec::new();
    for place in &places {
        let part = builder.checked_place(*place, left_len, right_len)?;
        let offset = gates.len();
        gates.extend(part.alg.gates);
        residues.extend(part.alg.outputs.iter().map(|mask| mask.shl(offset)));
        evaluation.extend(part.evaluation);
    }

    // Interpolate, then reduce modulo the field polynomial.
    let inverse = left_inverse(&evaluation, product_len)?;
    let reduction = reduction_rows(&field, product_len)?;
    let mut w_tree = Vec::with_capacity(left_len);
    let mut w_gate = Vec::with_capacity(left_len);
    for form in &reduction {
        let selection = combine(form, &inverse)?;
        let mut tree = Bits::zero();
        let mut gate = Bits::zero();
        for coordinate in selection.ones() {
            match coordinate.checked_sub(right_len) {
                None => tree.set(coordinate),
                Some(extra) => gate.xor_assign(row(&residues, extra)?),
            }
        }
        w_tree.push(tree);
        w_gate.push(gate);
    }

    // The right-hand forms act on the residues of the challenge, through the lift.
    let (m_tree, lift) = crt_lift_cols(&moduli)?;
    let f: Vec<Bits> = gates.iter().map(|(left, _)| left.clone()).collect();
    let g: Vec<Bits> = gates
        .iter()
        .map(|(_, right)| {
            let mut out = Bits::zero();
            for (coordinate, column) in lift.iter().enumerate() {
                if right.parity_and(column) {
                    out.set(coordinate);
                }
            }
            out
        })
        .collect();
    let raw_gates = f.len();
    let (f, g, w_gate) = prune(&f, &g, &w_gate)?;
    let w_crt: Vec<Bits> = (0..left_len)
        .map(|position| {
            let mut out = Bits::zero();
            for (coordinate, column) in lift.iter().enumerate() {
                if column.bit(position) {
                    out.set(coordinate);
                }
            }
            out
        })
        .collect();

    let overflow = CrtError::Construction {
        what: "the gate count does not fit 32 bits",
    };
    let n_mult = f.len();
    let m_tree_words =
        m_tree
            .to_words((right_len + 1).div_ceil(64))
            .ok_or(CrtError::Construction {
                what: "the product of the tree moduli is too long",
            })?;
    let f = to_matrix(&f, left_len)?;
    let g = to_matrix(&g, right_len)?;
    let w_tree = to_matrix(&w_tree, right_len)?;
    let w_gate = to_matrix(&w_gate, n_mult)?;
    let w_crt = to_matrix(&w_crt, right_len)?;
    let tables = CrtTables::from_words(&TableWords {
        lambda,
        tau,
        w_grind,
        n_mult: u32::try_from(n_mult).map_err(|_| overflow)?,
        tree_moduli: &tree_moduli,
        m_tree: &m_tree_words,
        f: f.as_words(),
        g: g.as_words(),
        w_tree: w_tree.as_words(),
        w_gate: w_gate.as_words(),
        w_crt: w_crt.as_words(),
    })?
    .into_owned();
    Ok(Generated {
        tables,
        places,
        search_cost,
        raw_gates: u32::try_from(raw_gates).map_err(|_| overflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masks(values: &[u64]) -> Vec<Bits> {
        values.iter().map(|value| Bits::from_u64(*value)).collect()
    }

    /// Bit `position` of a little-endian word string.
    fn word_bit(words: &[u64], position: usize) -> bool {
        (words[position / 64] >> (position % 64)) & 1 == 1
    }

    #[test]
    fn field_moduli() {
        let modulus = field_modulus(128).expect("supported");
        assert_eq!(modulus.ones().collect::<Vec<_>>(), vec![0, 1, 2, 7, 128]);
        let modulus = field_modulus(192).expect("supported");
        assert_eq!(modulus.ones().collect::<Vec<_>>(), vec![0, 1, 2, 7, 192]);
        let modulus = field_modulus(256).expect("supported");
        assert_eq!(modulus.ones().collect::<Vec<_>>(), vec![0, 2, 5, 10, 256]);
        assert_eq!(field_modulus(64), None);
    }

    #[test]
    fn tree_specs() {
        assert_eq!(tree_spec(128, 11, 7), Ok(vec![(11, 11)]));
        assert_eq!(tree_spec(128, 17, 8), Ok(vec![(8, 1), (7, 16)]));
        assert_eq!(tree_spec(192, 16, 12), Ok(vec![(12, 4), (11, 12)]));
        assert_eq!(tree_spec(192, 24, 8), Ok(vec![(8, 16), (7, 8)]));
        assert_eq!(tree_spec(256, 22, 6), Ok(vec![(12, 8), (11, 14)]));
        assert_eq!(tree_spec(256, 33, 8), Ok(vec![(8, 17), (7, 16)]));
        assert_eq!(tree_spec(192, 16, 8), Ok(vec![(12, 8), (11, 8)]));
        assert_eq!(tree_spec(192, 25, 8), Ok(vec![(8, 9), (7, 16)]));
        for (lambda, tau, w_grind) in [(128, 0, 8), (128, 11, 0), (128, 11, 128), (128, 121, 8)] {
            assert_eq!(
                tree_spec(lambda, tau, w_grind),
                Err(CrtError::UnsupportedParameters {
                    lambda,
                    tau,
                    w_grind
                })
            );
        }
    }

    #[test]
    fn crt_lift_is_the_inverse_of_reduction() {
        let moduli = masks(&[0b111, 0b1011, 0b10]);
        let (m_tree, columns) = crt_lift_cols(&moduli).expect("coprime");
        assert_eq!(m_tree, Bits::from_u64(0b110_0010));
        assert_eq!(columns.len(), 6);
        let mut coordinate = 0;
        for (position, modulus) in moduli.iter().enumerate() {
            for power in 0..modulus.degree().expect("non-zero") {
                let column = &columns[coordinate];
                assert!(column.degree() < m_tree.degree());
                for (other_position, other) in moduli.iter().enumerate() {
                    let expected = if other_position == position {
                        gf2poly::rem(&Bits::unit(power), other).expect("non-zero")
                    } else {
                        Bits::zero()
                    };
                    assert_eq!(gf2poly::rem(column, other), Ok(expected));
                }
                coordinate += 1;
            }
        }
        // Equal moduli are not coprime.
        assert_eq!(
            crt_lift_cols(&masks(&[0b111, 0b111])),
            Err(CrtError::NotInvertible)
        );
    }

    #[test]
    fn prune_merges_drops_and_renumbers() {
        // Gates 0 and 3 are equal, gate 1 has a zero form, gate 4 is unused.
        let f = masks(&[5, 0, 6, 5, 9]);
        let g = masks(&[3, 7, 1, 3, 2]);
        let w_gate = masks(&[0b01001, 0b00110, 0b01100]);
        let (kept_f, kept_g, kept_w) = prune(&f, &g, &w_gate).expect("consistent");
        assert_eq!(kept_f, masks(&[5, 6]));
        assert_eq!(kept_g, masks(&[3, 1]));
        // Row 0 uses the merged gate twice, which cancels.
        assert_eq!(kept_w, masks(&[0b00, 0b10, 0b11]));
        assert!(prune(&f, &g[..4], &w_gate).is_err());
        assert!(prune(&f, &g, &masks(&[0b10_0000])).is_err());
    }

    #[test]
    fn to_matrix_packs_rows() {
        let matrix = to_matrix(&[Bits::unit(69), Bits::zero()], 70).expect("fits");
        assert_eq!(matrix.as_words(), &[0, 1 << 5, 0, 0]);
        assert!(to_matrix(&[Bits::unit(70)], 70).is_err());
        assert!(to_matrix(&[Bits::unit(64)], 64).is_err());
    }

    #[test]
    fn unsupported_parameters_are_typed_errors() {
        for (lambda, tau, w_grind) in [
            (127, 11, 7),
            (128, 0, 8),
            (128, 11, 0),
            (128, 11, 128),
            // Tree moduli of degree 1, and of degree 16 and more.
            (128, 120, 8),
            (128, 7, 8),
            (128, 1, 8),
        ] {
            assert_eq!(
                generate(lambda, tau, w_grind),
                Err(CrtError::UnsupportedParameters {
                    lambda,
                    tau,
                    w_grind
                })
            );
        }
        // Degree 2 has a single irreducible polynomial.
        assert!(matches!(generate(128, 50, 8), Err(CrtError::Field(_))));
    }

    /// The portfolio every profile starts with, as `(kind, poly, multiplicity)`.
    fn common_places() -> Vec<Place> {
        let mut places = vec![
            Place::infinity(3),
            Place::linear(0b10, 5),
            Place::linear(0b11, 5),
            Place::irreducible(0b111, 2),
        ];
        let singles = [
            0xb, 0xd, 0x13, 0x19, 0x1f, 0x25, 0x29, 0x2f, 0x37, 0x3b, 0x3d, 0x43, 0x49, 0x57, 0x5b,
            0x61, 0x67, 0x6d, 0x73, 0x75,
        ];
        places.extend(singles.iter().map(|poly| Place::irreducible(*poly, 1)));
        places
    }

    #[test]
    fn portfolios_match_the_reference() {
        let tails: [&[u32]; 8] = [
            &[0x11b],
            &[0x11d],
            &[
                0x11b, 0x11d, 0x12b, 0x12d, 0x139, 0x13f, 0x14d, 0x15f, 0x163,
            ],
            &[
                0x18d, 0x19f, 0x1a3, 0x1a9, 0x1b1, 0x1bd, 0x1c3, 0x1cf, 0x1d7,
            ],
            &[
                0x11b, 0x11d, 0x12b, 0x12d, 0x139, 0x13f, 0x14d, 0x15f, 0x163, 0x165, 0x169, 0x171,
                0x177, 0x17b, 0x187, 0x18b, 0x18d,
            ],
            &[
                0xf7, 0xfd, 0x19f, 0x1a3, 0x1a9, 0x1b1, 0x1bd, 0x1c3, 0x1cf, 0x1d7, 0x1dd, 0x1e7,
                0x1f3, 0x1f5, 0x1f9, 0x203, 0x211,
            ],
            &[
                0x11b, 0x11d, 0x12b, 0x12d, 0x139, 0x13f, 0x14d, 0x15f, 0x163,
            ],
            &[
                0x165, 0x169, 0x171, 0x177, 0x17b, 0x187, 0x18b, 0x18d, 0x19f,
            ],
        ];
        for (profile, tail) in Profile::ALL.into_iter().zip(tails) {
            let (lambda, tau, w_grind) = profile.parameters();
            let generated = generate_with_report(lambda, tau, w_grind).expect("profile");
            let mut expected = common_places();
            expected.extend(tail.iter().map(|poly| Place::irreducible(*poly, 1)));
            assert_eq!(generated.places, expected, "{}", profile.name());
            assert_eq!(generated.raw_gates, profile.n_mult());
            assert_eq!(generated.search_cost, u64::from(profile.n_mult()));
            assert_eq!(generated.tables.n_mult(), profile.n_mult());
            assert_eq!(generated.tables.profile(), Some(profile));
            assert_eq!(generate_profile(profile), Ok(generated.tables));
        }
    }

    #[test]
    fn tree_moduli_and_first_gates_of_128f() {
        let tables = generate(128, 17, 8).expect("profile");
        assert_eq!(
            tables.tree_moduli(),
            &[
                0x11b, 0x83, 0x89, 0x8f, 0x91, 0x9d, 0xa7, 0xab, 0xb9, 0xbf, 0xc1, 0xcb, 0xd3,
                0xd5, 0xe5, 0xef, 0xf1
            ]
        );
        // The place at infinity of multiplicity 3 comes first.
        let expected: [&[usize]; 5] = [&[126], &[127], &[126, 127], &[127], &[125]];
        for (gate, bits) in expected.iter().enumerate() {
            let row = tables.f().row(gate).expect("gate");
            let set: Vec<usize> = (0..128).filter(|bit| word_bit(row, *bit)).collect();
            assert_eq!(&set, bits);
        }
    }

    /// Specification property: for every field element `u` and challenge residue
    /// vector `d`, `u * lift(d) mod P = W_TREE * tree + W_GATE * gates`, where
    /// `tree` is the residue vector of `u * lift(d)` modulo the tree moduli and
    /// gate `e` is `<F[e], u> AND <G[e], d>`.
    #[test]
    fn tables_multiply_in_the_field() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for profile in [Profile::Faest128s, Profile::Faest256f, Profile::FaestEm192f] {
            let tables = generate_profile(profile).expect("profile");
            let lambda = index(tables.lambda());
            let n_delta = index(tables.n_delta());
            let field = field_modulus(tables.lambda()).expect("supported");
            for _ in 0..4 {
                let mut element = vec![0u64; lambda / 64];
                element.fill_with(&mut next);
                let mut residues = vec![0u64; tables.w_crt().words_per_row()];
                residues.fill_with(&mut next);
                if let Some(last) = residues.last_mut() {
                    *last &= u64::MAX >> residues_unused(n_delta);
                }
                // Delta = W_CRT * residues.
                let mut delta = vec![0u64; lambda / 64];
                tables
                    .w_crt()
                    .mul_vec(&mut delta, &residues)
                    .expect("shape");
                let product = gf2poly::mul(&Bits::from_words(&element), &Bits::from_words(&delta));

                // Tree residues of the unreduced product.
                let mut tree = Bits::zero();
                let mut offset = 0;
                for modulus in tables.tree_moduli() {
                    let modulus = Bits::from_u64(u64::from(*modulus));
                    let residue = gf2poly::rem(&product, &modulus).expect("non-zero");
                    tree.xor_shifted(&residue, offset);
                    offset += modulus.degree().expect("non-zero");
                }
                assert_eq!(offset, n_delta);
                let mut gates = Bits::zero();
                for gate in 0..index(tables.n_mult()) {
                    let left = tables.f().row_dot(gate, &element).expect("shape");
                    let right = tables.g().row_dot(gate, &residues).expect("shape");
                    if left && right {
                        gates.set(gate);
                    }
                }
                let tree_words = tree
                    .to_words(tables.w_tree().words_per_row())
                    .expect("fits");
                let gate_words = gates
                    .to_words(tables.w_gate().words_per_row())
                    .expect("fits");
                let mut from_tree = vec![0u64; lambda / 64];
                let mut from_gates = vec![0u64; lambda / 64];
                tables
                    .w_tree()
                    .mul_vec(&mut from_tree, &tree_words)
                    .expect("shape");
                tables
                    .w_gate()
                    .mul_vec(&mut from_gates, &gate_words)
                    .expect("shape");
                let mut computed = Bits::from_words(&from_tree);
                computed.xor_assign(&Bits::from_words(&from_gates));
                assert_eq!(Ok(computed), gf2poly::rem(&product, &field));
            }
        }
    }

    /// Number of unused high bits in the last word of a vector of `bits` bits.
    fn residues_unused(bits: usize) -> usize {
        (64 - bits % 64) % 64
    }
}
