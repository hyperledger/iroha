//! The field `F_4` and polynomials over it, for the tower construction of the
//! degree-6 and degree-8 places.
//!
//! `F_4 = {0, 1, w, w + 1}` is encoded as `0, 1, 2, 3`: bit 0 is the coefficient of
//! `1` and bit 1 the coefficient of `w`, with `w^2 = w + 1`. Addition is XOR. A
//! polynomial in `F_4[y]` is a coefficient list whose position is the power of `y`.
//! All values are public table-construction data, so table lookups are fine here.

use super::error::CrtError;

/// Multiplication table of `F_4`.
const MUL: [[u8; 4]; 4] = [[0, 0, 0, 0], [0, 1, 2, 3], [0, 2, 3, 1], [0, 3, 1, 2]];

/// Inverses in `F_4`; zero maps to zero.
const INV: [u8; 4] = [0, 1, 3, 2];

/// A bilinear algorithm over `F_4`: the gate forms and the output coefficients.
pub type F4Alg = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Product in `F_4`.
pub fn mul(left: u8, right: u8) -> u8 {
    MUL[usize::from(left & 3)][usize::from(right & 3)]
}

/// Inverse in `F_4`, with zero mapped to zero.
pub fn inv(value: u8) -> u8 {
    INV[usize::from(value & 3)]
}

/// `base` raised to `exponent`, with `0^0 = 1`.
pub fn pow(base: u8, exponent: usize) -> u8 {
    (0..exponent).fold(1, |acc, _| mul(acc, base))
}

/// Product of two polynomials; empty if either is empty.
pub fn poly_mul(left: &[u8], right: &[u8]) -> Vec<u8> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u8; left.len() + right.len() - 1];
    for (shift, coefficient) in left.iter().enumerate() {
        for (target, other) in out.iter_mut().skip(shift).zip(right) {
            *target ^= mul(*coefficient, *other);
        }
    }
    out
}

/// Remainder of `value` by the monic polynomial `modulus`, as `deg modulus`
/// coefficients.
pub fn poly_rem(value: &[u8], modulus: &[u8]) -> Vec<u8> {
    let Some(degree) = modulus.len().checked_sub(1) else {
        return Vec::new();
    };
    let mut work = value.to_vec();
    for position in (degree..work.len()).rev() {
        let factor = work.get(position).copied().unwrap_or(0);
        if factor == 0 {
            continue;
        }
        for (target, coefficient) in work.iter_mut().skip(position - degree).zip(modulus) {
            *target ^= mul(factor, *coefficient);
        }
    }
    work.resize(degree, 0);
    work
}

/// Value of the polynomial at `point`.
pub fn poly_eval(poly: &[u8], point: u8) -> u8 {
    poly.iter()
        .rev()
        .fold(0, |acc, coefficient| mul(acc, point) ^ coefficient)
}

/// Every element of `F_4^length`, in lexicographic order with position 0 varying
/// slowest.
pub fn tuples(length: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![Vec::new()];
    for _ in 0..length {
        out = out
            .into_iter()
            .flat_map(|prefix| {
                (0..4u8).map(move |value| {
                    let mut next = prefix.clone();
                    next.push(value);
                    next
                })
            })
            .collect();
    }
    out
}

/// Whether the polynomial has a root in `F_4`.
pub fn has_roots(poly: &[u8]) -> bool {
    (0..4u8).any(|point| poly_eval(poly, point) == 0)
}

/// The monic irreducible polynomials of degree `degree` in `F_4[y]`, for `degree`
/// in `{2, 3, 4}`, in lexicographic order of their low coefficients.
pub fn irreducibles(degree: usize) -> Vec<Vec<u8>> {
    let monic = |low: Vec<u8>| {
        let mut poly = low;
        poly.push(1);
        poly
    };
    let quadratics: Vec<Vec<u8>> = if degree == 4 {
        tuples(2)
            .into_iter()
            .map(monic)
            .filter(|poly| !has_roots(poly))
            .collect()
    } else {
        Vec::new()
    };
    tuples(degree)
        .into_iter()
        .map(monic)
        .filter(|poly| !has_roots(poly))
        .filter(|poly| {
            quadratics
                .iter()
                .all(|quadratic| poly_rem(poly, quadratic).iter().any(|value| *value != 0))
        })
        .collect()
}

/// `y^j mod modulus` for `j` in `[0, count)`, each as `deg modulus` coefficients.
pub fn xpow_cols(modulus: &[u8], count: usize) -> Vec<Vec<u8>> {
    let degree = modulus.len().saturating_sub(1);
    let mut current = vec![0u8; degree];
    if let Some(first) = current.first_mut() {
        *first = 1;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(current.clone());
        let mut shifted = vec![0u8];
        shifted.extend_from_slice(&current);
        current = poly_rem(&shifted, modulus);
    }
    out
}

/// Inverse of a square matrix over `F_4` by Gauss-Jordan elimination.
pub fn mat_inv(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, CrtError> {
    let size = matrix.len();
    let mut work = Vec::with_capacity(size);
    for (position, source) in matrix.iter().enumerate() {
        if source.len() != size {
            return Err(CrtError::NotSquare {
                rows: size,
                columns: source.len(),
            });
        }
        let mut extended = source.clone();
        extended.extend((0..size).map(|column| u8::from(column == position)));
        work.push(extended);
    }
    for column in 0..size {
        let pivot = (column..size)
            .find(|candidate| {
                work.get(*candidate)
                    .and_then(|line| line.get(column))
                    .is_some_and(|value| *value != 0)
            })
            .ok_or(CrtError::Singular { column })?;
        work.swap(column, pivot);
        let pivot_row: Vec<u8> = {
            let line = work.get(column).ok_or(CrtError::Singular { column })?;
            let scale = inv(line.get(column).copied().unwrap_or(0));
            line.iter().map(|value| mul(scale, *value)).collect()
        };
        for (position, line) in work.iter_mut().enumerate() {
            if position == column {
                line.clone_from(&pivot_row);
                continue;
            }
            let factor = line.get(column).copied().unwrap_or(0);
            if factor != 0 {
                for (target, value) in line.iter_mut().zip(&pivot_row) {
                    *target ^= mul(factor, *value);
                }
            }
        }
    }
    Ok(work
        .into_iter()
        .map(|line| line.into_iter().skip(size).collect())
        .collect())
}

/// A bilinear algorithm over `F_4` for the full product of two polynomials of
/// `size` coefficients in `F_4[y]`.
///
/// Returns `(gates, outputs)`: gate `g` multiplies the form `gates[g]` of one
/// operand by the same form of the other, and product coefficient `k` is the sum
/// over `g` of `outputs[k][g]` times gate `g`. Five gates for `size = 3` and eight
/// for `size = 4`.
pub fn full_product_alg(size: usize) -> Result<F4Alg, CrtError> {
    if size < 2 {
        return Err(CrtError::Construction {
            what: "the F_4 product needs at least two coefficients",
        });
    }
    let outputs_len = 2 * size - 1;
    let mut gates: Vec<Vec<u8>> = Vec::new();
    let mut evaluation: Vec<Vec<u8>> = Vec::new();
    let mut terms: Vec<Vec<(usize, u8)>> = Vec::new();
    let points: u8 = if size == 2 { 2 } else { 4 };
    for point in 0..points {
        terms.push(vec![(gates.len(), 1)]);
        gates.push((0..size).map(|power| pow(point, power)).collect());
        evaluation.push((0..outputs_len).map(|power| pow(point, power)).collect());
    }
    // The place at infinity: the leading coefficients.
    terms.push(vec![(gates.len(), 1)]);
    gates.push((0..size).map(|power| u8::from(power == size - 1)).collect());
    evaluation.push(
        (0..outputs_len)
            .map(|power| u8::from(power == outputs_len - 1))
            .collect(),
    );
    if size == 4 {
        // The quadratic place, with a Karatsuba product modulo the quadratic.
        let quadratic = irreducibles(2)
            .into_iter()
            .next()
            .ok_or(CrtError::Construction {
                what: "no irreducible quadratic over F_4",
            })?;
        let beta = quadratic.first().copied().unwrap_or(0);
        let alpha = quadratic.get(1).copied().unwrap_or(0);
        let low = |column: &Vec<u8>| column.first().copied().unwrap_or(0);
        let high = |column: &Vec<u8>| column.get(1).copied().unwrap_or(0);
        let inputs = xpow_cols(&quadratic, size);
        let base = gates.len();
        gates.push(inputs.iter().map(low).collect());
        gates.push(inputs.iter().map(high).collect());
        gates.push(
            inputs
                .iter()
                .map(|column| low(column) ^ high(column))
                .collect(),
        );
        let products = xpow_cols(&quadratic, outputs_len);
        evaluation.push(products.iter().map(low).collect());
        evaluation.push(products.iter().map(high).collect());
        terms.push(vec![(base, 1), (base + 1, beta)]);
        terms.push(vec![(base, 1), (base + 1, 1 ^ alpha), (base + 2, 1)]);
    }
    let inverse = mat_inv(&evaluation)?;
    let mut outputs = vec![vec![0u8; gates.len()]; outputs_len];
    for (output, line) in outputs.iter_mut().zip(&inverse) {
        for (factor, term) in line.iter().zip(&terms) {
            for (gate, coefficient) in term {
                if let Some(target) = output.get_mut(*gate) {
                    *target ^= mul(*factor, *coefficient);
                }
            }
        }
    }
    Ok((gates, outputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms() {
        for left in 0..4u8 {
            assert_eq!(mul(left, 1), left);
            assert_eq!(mul(left, 0), 0);
            for right in 0..4u8 {
                assert_eq!(mul(left, right), mul(right, left));
                for third in 0..4u8 {
                    assert_eq!(
                        mul(left, right ^ third),
                        mul(left, right) ^ mul(left, third)
                    );
                }
            }
        }
        // w^2 = w + 1.
        assert_eq!(mul(2, 2), 3);
        assert_eq!(inv(0), 0);
        for value in 1..4u8 {
            assert_eq!(mul(value, inv(value)), 1);
        }
        assert_eq!(pow(0, 0), 1);
        assert_eq!(pow(0, 3), 0);
        assert_eq!(pow(2, 2), 3);
        assert_eq!(pow(2, 3), 1);
    }

    #[test]
    fn polynomial_arithmetic() {
        // (y + w)(y + w + 1) = y^2 + y + 1.
        assert_eq!(poly_mul(&[2, 1], &[3, 1]), vec![1, 1, 1]);
        assert_eq!(poly_mul(&[], &[3, 1]), Vec::<u8>::new());
        assert_eq!(poly_rem(&[1, 1, 1], &[2, 1]), vec![0]);
        assert_eq!(poly_rem(&[1, 1, 1], &[1, 1]), vec![1]);
        assert_eq!(poly_rem(&[3], &[1, 2, 1]), vec![3, 0]);
        assert_eq!(poly_rem(&[3], &[]), Vec::<u8>::new());
        assert_eq!(poly_eval(&[1, 1, 1], 2), 0);
        assert_eq!(poly_eval(&[1, 1, 1], 1), 1);
        assert_eq!(poly_eval(&[], 3), 0);
        assert!(has_roots(&[1, 1, 1]));
        assert!(!has_roots(&[1, 2, 1]));
    }

    #[test]
    fn tuples_vary_the_last_position_fastest() {
        assert_eq!(tuples(0), vec![Vec::<u8>::new()]);
        let pairs = tuples(2);
        assert_eq!(pairs.len(), 16);
        assert_eq!(pairs[0], vec![0, 0]);
        assert_eq!(pairs[1], vec![0, 1]);
        assert_eq!(pairs[4], vec![1, 0]);
        assert_eq!(pairs[15], vec![3, 3]);
    }

    #[test]
    fn irreducible_counts_and_first_entries() {
        let quadratics = irreducibles(2);
        let cubics = irreducibles(3);
        let quartics = irreducibles(4);
        assert_eq!(
            (quadratics.len(), cubics.len(), quartics.len()),
            (6, 20, 60)
        );
        assert_eq!(quadratics[0], vec![1, 2, 1]);
        assert_eq!(cubics[0], vec![1, 0, 1, 1]);
        assert_eq!(quartics[0], vec![1, 0, 1, 2, 1]);
    }

    #[test]
    fn xpow_cols_are_powers_of_y() {
        let modulus = [1, 2, 1];
        let columns = xpow_cols(&modulus, 4);
        assert_eq!(columns[0], vec![1, 0]);
        assert_eq!(columns[1], vec![0, 1]);
        // y^2 = w y + 1.
        assert_eq!(columns[2], vec![1, 2]);
        assert_eq!(columns[3], poly_rem(&[0, 0, 0, 1], &modulus));
        assert!(xpow_cols(&modulus, 0).is_empty());
    }

    #[test]
    fn mat_inv_inverts_and_rejects() {
        let matrix = vec![vec![1, 2, 0], vec![0, 3, 1], vec![2, 0, 2]];
        let inverse = mat_inv(&matrix).expect("invertible");
        for (line, row) in matrix.iter().enumerate() {
            let product: Vec<u8> = (0..3)
                .map(|column| {
                    row.iter()
                        .zip(&inverse)
                        .fold(0, |acc, (value, other)| acc ^ mul(*value, other[column]))
                })
                .collect();
            let identity: Vec<u8> = (0..3).map(|column| u8::from(line == column)).collect();
            assert_eq!(product, identity);
        }
        assert_eq!(
            mat_inv(&[vec![1, 2], vec![1, 2]]),
            Err(CrtError::Singular { column: 1 })
        );
        assert_eq!(
            mat_inv(&[vec![1, 2, 3], vec![1, 2, 3]]),
            Err(CrtError::NotSquare {
                rows: 2,
                columns: 3
            })
        );
    }

    #[test]
    fn full_product_alg_matches_the_anchors() {
        let (gates, outputs) = full_product_alg(3).expect("size 3");
        assert_eq!(
            gates,
            vec![
                vec![1, 0, 0],
                vec![1, 1, 1],
                vec![1, 2, 3],
                vec![1, 3, 2],
                vec![0, 0, 1]
            ]
        );
        assert_eq!(
            outputs,
            vec![
                vec![1, 0, 0, 0, 0],
                vec![0, 1, 3, 2, 1],
                vec![0, 1, 2, 3, 0],
                vec![1, 1, 1, 1, 0],
                vec![0, 0, 0, 0, 1]
            ]
        );
        let (gates, outputs) = full_product_alg(4).expect("size 4");
        assert_eq!(
            gates,
            vec![
                vec![1, 0, 0, 0],
                vec![1, 1, 1, 1],
                vec![1, 2, 3, 1],
                vec![1, 3, 2, 1],
                vec![0, 0, 0, 1],
                vec![1, 0, 1, 2],
                vec![0, 1, 2, 2],
                vec![1, 1, 3, 0]
            ]
        );
        assert_eq!(
            outputs,
            vec![
                vec![1, 0, 0, 0, 0, 0, 0, 0],
                vec![2, 3, 3, 1, 1, 3, 3, 0],
                vec![1, 2, 3, 0, 2, 3, 2, 3],
                vec![1, 1, 1, 1, 1, 0, 0, 0],
                vec![2, 2, 0, 3, 1, 3, 3, 0],
                vec![1, 3, 1, 3, 2, 3, 2, 3],
                vec![0, 0, 0, 0, 1, 0, 0, 0]
            ]
        );
        assert!(full_product_alg(1).is_err());
    }

    #[test]
    fn full_product_alg_multiplies() {
        for size in [2usize, 3, 4] {
            let (gates, outputs) = full_product_alg(size).expect("supported size");
            let operands = tuples(size);
            for (left, right) in operands.iter().zip(operands.iter().rev()).step_by(7) {
                let form = |gate: &Vec<u8>, operand: &Vec<u8>| {
                    gate.iter()
                        .zip(operand)
                        .fold(0, |acc, (coefficient, value)| {
                            acc ^ mul(*coefficient, *value)
                        })
                };
                let products: Vec<u8> = gates
                    .iter()
                    .map(|gate| mul(form(gate, left), form(gate, right)))
                    .collect();
                let computed: Vec<u8> = outputs
                    .iter()
                    .map(|line| {
                        line.iter()
                            .zip(&products)
                            .fold(0, |acc, (coefficient, value)| {
                                acc ^ mul(*coefficient, *value)
                            })
                    })
                    .collect();
                assert_eq!(computed, poly_mul(left, right));
            }
        }
    }
}
