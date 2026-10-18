//! Linear algebra over `GF(2)` on rows held as [`Bits`]: row combination, reduction
//! and Taylor-shift matrices, and the inversion of the evaluation systems.

use super::{bits::Bits, error::CrtError};

/// Row `position` of `rows`, or a typed error.
pub fn row(rows: &[Bits], position: usize) -> Result<&Bits, CrtError> {
    rows.get(position).ok_or(CrtError::Construction {
        what: "a mask selects a row that does not exist",
    })
}

/// Sum of the rows of `rows` selected by the set bits of `mask`.
pub fn combine(mask: &Bits, rows: &[Bits]) -> Result<Bits, CrtError> {
    let mut out = Bits::zero();
    for position in mask.ones() {
        out.xor_assign(row(rows, position)?);
    }
    Ok(out)
}

/// The matrix of reduction modulo `modulus` on `columns` coefficients: `deg modulus`
/// rows, and row `i` has bit `j` set iff coefficient `i` of `x^j mod modulus` is one.
pub fn reduction_rows(modulus: &Bits, columns: usize) -> Result<Vec<Bits>, CrtError> {
    let degree = modulus.degree().ok_or(CrtError::DivisionByZero)?;
    let mut rows = vec![Bits::zero(); degree];
    // `x^j mod modulus`, starting from `1 mod modulus`.
    let mut current = if degree == 0 {
        Bits::zero()
    } else {
        Bits::from_u64(1)
    };
    for column in 0..columns {
        for position in current.ones() {
            if let Some(target) = rows.get_mut(position) {
                target.set(column);
            }
        }
        current = current.shl(1);
        if current.bit(degree) {
            current.xor_assign(modulus);
        }
    }
    Ok(rows)
}

/// The Taylor shift from `x` to `x + 1` on `size` coefficients: row `i` has bit `j`
/// set iff `i <= j < size` and the binomial coefficient `(j choose i)` is odd.
pub fn pascal_rows(size: usize) -> Vec<Bits> {
    (0..size)
        .map(|upper| {
            let mut out = Bits::zero();
            for column in (upper..size).filter(|column| upper & column == upper) {
                out.set(column);
            }
            out
        })
        .collect()
}

/// Invert a square system: `rows` is `columns x columns` and the result `X`
/// satisfies `combine(X[c], rows) = e_c`.
///
/// The pivot of column `c` is the lowest-index row not yet used as a pivot with a
/// one in column `c`, and it is eliminated from every other row, as in the
/// reference. For a square system the inverse is unique, so the rule cannot
/// influence the result; a non-square system, where it could, is rejected.
///
/// # Errors
/// [`CrtError::NotSquare`] unless `rows.len() == columns`, and
/// [`CrtError::Singular`] if the system has no inverse.
pub fn left_inverse(rows: &[Bits], columns: usize) -> Result<Vec<Bits>, CrtError> {
    if rows.len() != columns {
        return Err(CrtError::NotSquare {
            rows: rows.len(),
            columns,
        });
    }
    let mut work = rows.to_vec();
    let mut tags: Vec<Bits> = (0..rows.len()).map(Bits::unit).collect();
    let mut used = vec![false; rows.len()];
    let mut pivots = Vec::with_capacity(columns);
    for column in 0..columns {
        let pivot = work
            .iter()
            .zip(&used)
            .position(|(candidate, taken)| !taken && candidate.bit(column))
            .ok_or(CrtError::Singular { column })?;
        if let Some(taken) = used.get_mut(pivot) {
            *taken = true;
        }
        let pivot_row = row(&work, pivot)?.clone();
        let pivot_tag = row(&tags, pivot)?.clone();
        for (position, (target, tag)) in work.iter_mut().zip(tags.iter_mut()).enumerate() {
            if position != pivot && target.bit(column) {
                target.xor_assign(&pivot_row);
                tag.xor_assign(&pivot_tag);
            }
        }
        pivots.push(pivot);
    }
    pivots
        .into_iter()
        .map(|pivot| row(&tags, pivot).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::gf2poly;
    use super::*;

    fn masks(values: &[u64]) -> Vec<Bits> {
        values.iter().map(|value| Bits::from_u64(*value)).collect()
    }

    #[test]
    fn row_and_combine() {
        let rows = masks(&[0b001, 0b011, 0b110]);
        assert_eq!(row(&rows, 1), Ok(&Bits::from_u64(0b011)));
        assert!(matches!(row(&rows, 3), Err(CrtError::Construction { .. })));
        assert_eq!(
            combine(&Bits::from_u64(0b101), &rows),
            Ok(Bits::from_u64(0b111))
        );
        assert_eq!(combine(&Bits::zero(), &rows), Ok(Bits::zero()));
        assert!(combine(&Bits::from_u64(0b1000), &rows).is_err());
    }

    #[test]
    fn reduction_rows_reduce() {
        let modulus = Bits::from_u64(0x11b);
        let rows = reduction_rows(&modulus, 20).expect("non-zero modulus");
        assert_eq!(rows.len(), 8);
        for power in 0..20 {
            let expected = gf2poly::rem(&Bits::unit(power), &modulus).expect("non-zero modulus");
            for (coefficient, form) in rows.iter().enumerate() {
                assert_eq!(form.bit(power), expected.bit(coefficient));
            }
        }
        // Modulo x: only the constant coefficient survives.
        assert_eq!(
            reduction_rows(&Bits::from_u64(0b10), 5),
            Ok(masks(&[0b00001]))
        );
        assert_eq!(reduction_rows(&Bits::from_u64(1), 5), Ok(vec![]));
        assert_eq!(
            reduction_rows(&Bits::zero(), 5),
            Err(CrtError::DivisionByZero)
        );
    }

    #[test]
    fn pascal_rows_are_binomials_mod_two() {
        assert_eq!(pascal_rows(0), vec![]);
        assert_eq!(pascal_rows(1), masks(&[0b1]));
        // (j choose i) mod 2 for j < 4: rows i = 0..3.
        assert_eq!(pascal_rows(4), masks(&[0b1111, 0b1010, 0b1100, 0b1000]));
    }

    #[test]
    fn left_inverse_inverts_square_systems() {
        let rows = masks(&[0b110, 0b011, 0b111]);
        let inverse = left_inverse(&rows, 3).expect("invertible");
        for (column, mask) in inverse.iter().enumerate() {
            assert_eq!(combine(mask, &rows), Ok(Bits::unit(column)));
        }
        assert_eq!(left_inverse(&[], 0), Ok(vec![]));
    }

    #[test]
    fn left_inverse_rejects_non_square_and_singular_systems() {
        // Invariant: a system with spare rows would make the pivot rule observable.
        let tall = masks(&[0b01, 0b10, 0b11]);
        assert_eq!(
            left_inverse(&tall, 2),
            Err(CrtError::NotSquare {
                rows: 3,
                columns: 2
            })
        );
        assert_eq!(
            left_inverse(&masks(&[0b01]), 2),
            Err(CrtError::NotSquare {
                rows: 1,
                columns: 2
            })
        );
        assert_eq!(
            left_inverse(&masks(&[0b01, 0b01]), 2),
            Err(CrtError::Singular { column: 1 })
        );
    }
}
