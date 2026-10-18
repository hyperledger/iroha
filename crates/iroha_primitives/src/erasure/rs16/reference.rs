//! Independent bit-serial GF(2^16) arithmetic and direct RS16 encoders for equality tests.
//!
//! This test-only oracle shares no field tables, matrices or kernels with the production
//! codec. It follows the compact layout text in `specs/sumeragi.md` §12.8 directly.

/// x^16 + x^12 + x^3 + x + 1.
const POLY: u32 = 0x1_100B;

/// Multiply two field elements one bit at a time.
pub(super) fn mul(a: u16, b: u16) -> u16 {
    let mut shifted = u32::from(a);
    let mut remaining = b;
    let mut product = 0u32;
    while remaining != 0 {
        if remaining & 1 == 1 {
            product ^= shifted;
        }
        remaining >>= 1;
        shifted <<= 1;
        if shifted & 0x1_0000 != 0 {
            shifted ^= POLY;
        }
    }
    u16::try_from(product).expect("reduced product fits in 16 bits")
}

/// Raise `base` to `exponent` by square-and-multiply.
pub(super) fn pow(base: u16, exponent: u64) -> u16 {
    let mut result = 1u16;
    let mut square = base;
    let mut exponent = exponent;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul(result, square);
        }
        square = mul(square, square);
        exponent >>= 1;
    }
    result
}

/// Multiplicative inverse `a^(2^16 - 2)` of a nonzero element.
pub(super) fn inv(a: u16) -> u16 {
    assert_ne!(a, 0, "zero has no inverse");
    pow(a, 0xFFFE)
}

fn vandermonde(row: usize, column: usize) -> u16 {
    pow(
        pow(2, u64::try_from(row).expect("row fits u64")),
        u64::try_from(column).expect("column fits u64"),
    )
}

/// Systematic parity coefficients `V[k..k+m] * V[..k]^-1` with `V[r][c] = (2^r)^c`.
pub(super) fn parity_matrix(k: usize, m: usize) -> Vec<Vec<u16>> {
    let mut left: Vec<Vec<u16>> = (0..k)
        .map(|row| (0..k).map(|column| vandermonde(row, column)).collect())
        .collect();
    let mut right: Vec<Vec<u16>> = (0..k)
        .map(|row| (0..k).map(|column| u16::from(row == column)).collect())
        .collect();
    for column in 0..k {
        let pivot = (column..k)
            .find(|row| left[*row][column] != 0)
            .expect("Vandermonde rows are independent");
        left.swap(column, pivot);
        right.swap(column, pivot);
        let scale = inv(left[column][column]);
        for value in left[column].iter_mut().chain(right[column].iter_mut()) {
            *value = mul(*value, scale);
        }
        let (pivot_left, pivot_right) = (left[column].clone(), right[column].clone());
        for row in (0..k).filter(|row| *row != column) {
            let factor = left[row][column];
            for index in 0..k {
                left[row][index] ^= mul(factor, pivot_left[index]);
                right[row][index] ^= mul(factor, pivot_right[index]);
            }
        }
    }
    (0..m)
        .map(|parity| {
            (0..k)
                .map(|column| {
                    (0..k).fold(0, |acc, source| {
                        acc ^ mul(vandermonde(k + parity, source), right[source][column])
                    })
                })
                .collect()
        })
        .collect()
}

/// Parity rows of one stripe of little-endian symbol rows.
pub(super) fn encode_parity(data: &[Vec<u16>], m: usize) -> Vec<Vec<u16>> {
    let matrix = parity_matrix(data.len(), m);
    let symbols = data.first().map_or(0, Vec::len);
    matrix
        .iter()
        .map(|coefficients| {
            (0..symbols)
                .map(|symbol| {
                    coefficients
                        .iter()
                        .zip(data)
                        .fold(0, |acc, (coefficient, row)| {
                            acc ^ mul(*coefficient, row[symbol])
                        })
                })
                .collect()
        })
        .collect()
}

/// Directly encode one compact codeword: full stripes of `maximum_row`-byte rows, then one
/// terminal stripe of `2*ceil(remaining/(2k))`-byte rows with zero data padding.
pub(super) fn compact_encode(payload: &[u8], k: usize, m: usize, maximum_row: usize) -> Vec<u8> {
    let capacity = k * maximum_row;
    let stripes = payload.len().div_ceil(capacity);
    let matrix = parity_matrix(k, m);
    let mut codeword = Vec::new();
    for stripe in 0..stripes {
        let start = stripe * capacity;
        let row = if stripe + 1 == stripes {
            2 * (payload.len() - start).div_ceil(2 * k)
        } else {
            maximum_row
        };
        let byte = |index: usize| payload.get(start + index).copied().unwrap_or(0);
        let symbol = |data_row: usize, position: usize| {
            u16::from_le_bytes([
                byte(data_row * row + 2 * position),
                byte(data_row * row + 2 * position + 1),
            ])
        };
        codeword.extend((0..k * row).map(byte));
        for coefficients in &matrix {
            for position in 0..row / 2 {
                let value =
                    coefficients
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (data_row, coefficient)| {
                            acc ^ mul(*coefficient, symbol(data_row, position))
                        });
                codeword.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    codeword
}

/// Deterministic xorshift64* fixture bytes.
pub(super) fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes()[7]
        })
        .collect()
}

/// Lowercase hexadecimal BLAKE3 digest used to pin codec outputs.
pub(super) fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_field_is_a_field() {
        assert_eq!(mul(0, 0x1234), 0);
        assert_eq!(mul(1, 0xBEEF), 0xBEEF);
        assert_eq!(mul(2, 0x8000), 0x100B);
        assert_eq!(pow(2, 0xFFFF), 1, "2 generates the multiplicative group");
        let mut seen = 1u16;
        for exponent in 1..0xFFFFu64 {
            seen = mul(seen, 2);
            assert_ne!(seen, 1, "2^{exponent} must not return to one early");
        }
        for value in [1u16, 2, 3, 0x100B, 0x8000, 0xFFFF] {
            assert_eq!(mul(value, inv(value)), 1);
        }
    }

    #[test]
    fn reference_parity_matrix_is_systematic_mds_for_small_shapes() {
        let matrix = parity_matrix(1, 3);
        assert_eq!(matrix, vec![vec![1], vec![1], vec![1]]);
        let data = vec![vec![7u16, 0, 0xFFFF], vec![1, 2, 3]];
        let parity = encode_parity(&data, 2);
        assert_eq!(parity.len(), 2);
        assert!(parity.iter().all(|row| row.len() == 3));
    }

    #[test]
    fn fixture_bytes_are_deterministic() {
        assert_eq!(bytes(7, 16), bytes(7, 16));
        assert_ne!(bytes(7, 16), bytes(8, 16));
        assert_eq!(bytes(1, 0), Vec::<u8>::new());
    }
}
