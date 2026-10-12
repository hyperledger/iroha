//! Bit matrices over `GF(2)` and the products the VOLE layer takes with them.
//!
//! A row is a bit vector packed little-endian into `u64` words: bit `c` of a row is
//! bit `c % 64` of word `c / 64`, which on a byte view is bit `c % 8` of byte
//! `c / 8`. Unused high bits of the last word are zero.
//!
//! # Constant-time discipline
//! A [`BitMatrix`] is public data: its dimensions and its entries may drive loops,
//! branches and indices. The vectors and columns a matrix is applied to may be
//! secret. No function in this module branches on, indexes by, or exits early
//! because of a bit of such an operand: operands are only combined with matrix
//! words through AND and XOR, and a parity is taken by a population count. The
//! sequence of operations of every product is fixed by the matrix alone.

use std::borrow::Cow;

use super::error::CrtError;

/// Number of `u64` words that hold `bits` bits.
const fn words_for(bits: usize) -> usize {
    bits.div_ceil(64)
}

/// Parity of the number of set bits of `word`, as zero or one.
fn parity(word: u64) -> u64 {
    u64::from(word.count_ones() & 1)
}

/// A [`CrtError::Shape`] unless `actual == expected`.
fn check_len(what: &'static str, expected: usize, actual: usize) -> Result<(), CrtError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CrtError::Shape {
            what,
            expected,
            actual,
        })
    }
}

/// A matrix over `GF(2)` with rows packed little-endian into `u64` words. It owns
/// its words or borrows them, for example from a static table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitMatrix<'a> {
    rows: usize,
    cols: usize,
    words_per_row: usize,
    data: Cow<'a, [u64]>,
}

/// Check that `data` is the canonical image of a `rows x cols` matrix and return
/// the number of words per row.
fn check_shape(rows: usize, cols: usize, data: &[u64]) -> Result<usize, CrtError> {
    if rows == 0 || cols == 0 {
        return Err(CrtError::Shape {
            what: "matrix dimension",
            expected: 1,
            actual: 0,
        });
    }
    let words_per_row = words_for(cols);
    let expected = rows.checked_mul(words_per_row).ok_or(CrtError::Shape {
        what: "matrix words",
        expected: usize::MAX,
        actual: data.len(),
    })?;
    if data.len() != expected {
        return Err(CrtError::Shape {
            what: "matrix words",
            expected,
            actual: data.len(),
        });
    }
    let unused = words_per_row * 64 - cols;
    if unused != 0 {
        let padding = u64::MAX << (64 - unused);
        let dirty = data
            .chunks_exact(words_per_row)
            .any(|row| row.last().is_some_and(|last| last & padding != 0));
        if dirty {
            return Err(CrtError::NonCanonical {
                what: "a matrix row has bits at or above its width",
            });
        }
    }
    Ok(words_per_row)
}

impl BitMatrix<'static> {
    /// A matrix over the words of an embedded table, built in a constant context.
    ///
    /// Only the word count is checked, and a wrong one fails the build: the caller
    /// is the definition of an embedded static, whose canonical form
    /// (`BitMatrix::borrowed` accepts the same words) is established by the tests of
    /// [`super::generated`].
    pub(super) const fn from_static(rows: usize, cols: usize, data: &'static [u64]) -> Self {
        let words_per_row = words_for(cols);
        assert!(rows != 0 && cols != 0 && data.len() == rows * words_per_row);
        Self {
            rows,
            cols,
            words_per_row,
            data: Cow::Borrowed(data),
        }
    }

    /// The zero matrix.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if a dimension is zero or the size overflows.
    pub fn zero(rows: usize, cols: usize) -> Result<Self, CrtError> {
        let words = rows.checked_mul(words_for(cols)).ok_or(CrtError::Shape {
            what: "matrix words",
            expected: usize::MAX,
            actual: 0,
        })?;
        Self::from_vec(rows, cols, vec![0; words])
    }

    /// A matrix that owns `data`: `rows` rows of `ceil(cols / 64)` words each.
    ///
    /// # Errors
    /// [`CrtError::Shape`] unless both dimensions are non-zero and `data` has
    /// exactly `rows * ceil(cols / 64)` words; [`CrtError::NonCanonical`] if a row
    /// has a bit at or above `cols`.
    pub fn from_vec(rows: usize, cols: usize, data: Vec<u64>) -> Result<Self, CrtError> {
        let words_per_row = check_shape(rows, cols, &data)?;
        Ok(Self {
            rows,
            cols,
            words_per_row,
            data: Cow::Owned(data),
        })
    }
}

impl<'a> BitMatrix<'a> {
    /// A matrix that borrows `data`: `rows` rows of `ceil(cols / 64)` words each.
    ///
    /// # Errors
    /// As [`BitMatrix::from_vec`].
    pub fn borrowed(rows: usize, cols: usize, data: &'a [u64]) -> Result<Self, CrtError> {
        let words_per_row = check_shape(rows, cols, data)?;
        Ok(Self {
            rows,
            cols,
            words_per_row,
            data: Cow::Borrowed(data),
        })
    }

    /// The same matrix owning its words.
    pub fn into_owned(self) -> BitMatrix<'static> {
        BitMatrix {
            rows: self.rows,
            cols: self.cols,
            words_per_row: self.words_per_row,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    /// Number of rows.
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns: the width of a row in bits.
    pub const fn cols(&self) -> usize {
        self.cols
    }

    /// Number of `u64` words per row, `ceil(cols / 64)`.
    pub const fn words_per_row(&self) -> usize {
        self.words_per_row
    }

    /// All rows in order, each as [`Self::words_per_row`] words.
    pub fn as_words(&self) -> &[u64] {
        &self.data
    }

    /// The words of row `row`, or `None` if there is no such row.
    pub fn row(&self, row: usize) -> Option<&[u64]> {
        let start = row.checked_mul(self.words_per_row)?;
        self.data.get(start..start.checked_add(self.words_per_row)?)
    }

    /// The entry in row `row` and column `col`, or `None` outside the matrix.
    pub fn bit(&self, row: usize, col: usize) -> Option<bool> {
        if col >= self.cols {
            return None;
        }
        let word = self.row(row)?.get(col / 64)?;
        Some((word >> (col % 64)) & 1 == 1)
    }

    /// Set the entry in row `row` and column `col`.
    ///
    /// # Errors
    /// [`CrtError::Shape`] outside the matrix.
    pub fn set_bit(&mut self, row: usize, col: usize, value: bool) -> Result<(), CrtError> {
        if row >= self.rows {
            return Err(CrtError::Shape {
                what: "matrix row",
                expected: self.rows,
                actual: row,
            });
        }
        if col >= self.cols {
            return Err(CrtError::Shape {
                what: "matrix column",
                expected: self.cols,
                actual: col,
            });
        }
        let position = row * self.words_per_row + col / 64;
        if let Some(word) = self.data.to_mut().get_mut(position) {
            *word = (*word & !(1 << (col % 64))) | (u64::from(value) << (col % 64));
        }
        Ok(())
    }

    /// Byte `position` of the little-endian byte view of a row.
    fn row_byte(row: &[u64], position: usize) -> u8 {
        row.get(position / 8)
            .map_or(0, |word| word.to_le_bytes()[position % 8])
    }

    /// Inner product over `GF(2)` of row `row` with `vector`, a bit vector of
    /// [`Self::cols`] bits in [`Self::words_per_row`] words. Bits of `vector` at or
    /// above [`Self::cols`] are ignored.
    ///
    /// `vector` may be secret: see the module documentation.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if there is no such row or `vector` has the wrong
    /// number of words.
    pub fn row_dot(&self, row: usize, vector: &[u64]) -> Result<bool, CrtError> {
        let words = self.row(row).ok_or(CrtError::Shape {
            what: "matrix row",
            expected: self.rows,
            actual: row,
        })?;
        check_len("vector words", self.words_per_row, vector.len())?;
        Ok(Self::dot_words(words, vector) == 1)
    }

    /// Inner product of two word strings of equal length, as zero or one.
    fn dot_words(row: &[u64], vector: &[u64]) -> u64 {
        parity(
            row.iter()
                .zip(vector)
                .fold(0, |acc, (left, right)| acc ^ (left & right)),
        )
    }

    /// Matrix times vector over `GF(2)`: bit `r` of `out` is the inner product of
    /// row `r` with `vector`.
    ///
    /// `vector` holds [`Self::cols`] bits in [`Self::words_per_row`] words and `out`
    /// receives [`Self::rows`] bits in `ceil(rows / 64)` words, unused bits zero.
    /// `vector` may be secret: see the module documentation.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if either buffer has the wrong number of words.
    pub fn mul_vec(&self, out: &mut [u64], vector: &[u64]) -> Result<(), CrtError> {
        check_len("vector words", self.words_per_row, vector.len())?;
        check_len("output words", words_for(self.rows), out.len())?;
        out.fill(0);
        for (position, row) in self.data.chunks_exact(self.words_per_row).enumerate() {
            if let Some(word) = out.get_mut(position / 64) {
                *word |= Self::dot_words(row, vector) << (position % 64);
            }
        }
        Ok(())
    }

    /// [`Self::mul_vec`] on byte strings: `vector` holds [`Self::cols`] bits in
    /// `ceil(cols / 8)` bytes and `out` receives [`Self::rows`] bits in
    /// `ceil(rows / 8)` bytes, bit `i` being bit `i % 8` of byte `i / 8`.
    ///
    /// `vector` may be secret: see the module documentation.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if either buffer has the wrong number of bytes.
    pub fn mul_vec_bytes(&self, out: &mut [u8], vector: &[u8]) -> Result<(), CrtError> {
        check_len("vector bytes", self.cols.div_ceil(8), vector.len())?;
        check_len("output bytes", self.rows.div_ceil(8), out.len())?;
        out.fill(0);
        for (position, row) in self.data.chunks_exact(self.words_per_row).enumerate() {
            let folded = vector.iter().enumerate().fold(0u8, |acc, (index, byte)| {
                acc ^ (Self::row_byte(row, index) & byte)
            });
            if let Some(byte) = out.get_mut(position / 8) {
                *byte |= u8::from(folded.count_ones() & 1 == 1) << (position % 8);
            }
        }
        Ok(())
    }

    /// Apply the matrix to a sequence of columns: row `r` of `out` is the XOR of
    /// the columns `c` with a one in row `r`, column `c`.
    ///
    /// `columns` is [`Self::cols`] values of `width` words each, one after the
    /// other, and `out` receives [`Self::rows`] values of `width` words. The width
    /// is free, so the columns may be `lambda` bits or wider.
    ///
    /// The columns may be secret: which columns are added is decided by the matrix
    /// alone, and their contents are only added with XOR.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if `width` is zero or a buffer has the wrong length.
    pub fn apply_to_columns(
        &self,
        out: &mut [u64],
        columns: &[u64],
        width: usize,
    ) -> Result<(), CrtError> {
        self.xor_selected(out, columns, width)
    }

    /// [`Self::apply_to_columns`] for columns of `width` bytes each.
    ///
    /// # Errors
    /// [`CrtError::Shape`] if `width` is zero or a buffer has the wrong length.
    pub fn apply_to_byte_columns(
        &self,
        out: &mut [u8],
        columns: &[u8],
        width: usize,
    ) -> Result<(), CrtError> {
        self.xor_selected(out, columns, width)
    }

    /// The shared body of the column products.
    fn xor_selected<T>(&self, out: &mut [T], columns: &[T], width: usize) -> Result<(), CrtError>
    where
        T: Copy + Default + std::ops::BitXorAssign,
    {
        if width == 0 {
            return Err(CrtError::Shape {
                what: "column width",
                expected: 1,
                actual: 0,
            });
        }
        let overflow = CrtError::Shape {
            what: "column buffer",
            expected: usize::MAX,
            actual: columns.len(),
        };
        check_len(
            "column buffer",
            self.cols.checked_mul(width).ok_or(overflow)?,
            columns.len(),
        )?;
        check_len(
            "output buffer",
            self.rows.checked_mul(width).ok_or(overflow)?,
            out.len(),
        )?;
        out.fill(T::default());
        for (row, target) in self
            .data
            .chunks_exact(self.words_per_row)
            .zip(out.chunks_exact_mut(width))
        {
            // The matrix is public: selecting columns by its entries is allowed.
            for (position, column) in columns.chunks_exact(width).enumerate() {
                let selected = row
                    .get(position / 64)
                    .is_some_and(|word| (word >> (position % 64)) & 1 == 1);
                if selected {
                    for (slot, value) in target.iter_mut().zip(column) {
                        *slot ^= *value;
                    }
                }
            }
        }
        Ok(())
    }
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

    /// A pseudo-random matrix built entry by entry.
    fn random_matrix(state: &mut u64, rows: usize, cols: usize) -> BitMatrix<'static> {
        let mut matrix = BitMatrix::zero(rows, cols).expect("non-empty");
        for row in 0..rows {
            for col in 0..cols {
                matrix
                    .set_bit(row, col, next(state) & 1 == 1)
                    .expect("in range");
            }
        }
        matrix
    }

    fn word_bit(words: &[u64], position: usize) -> bool {
        (words[position / 64] >> (position % 64)) & 1 == 1
    }

    fn byte_bit(bytes: &[u8], position: usize) -> bool {
        (bytes[position / 8] >> (position % 8)) & 1 == 1
    }

    /// Bit-by-bit inner product of a row with a vector given by a bit accessor.
    fn naive_dot(matrix: &BitMatrix<'_>, row: usize, vector: impl Fn(usize) -> bool) -> bool {
        (0..matrix.cols()).fold(false, |acc, col| {
            acc ^ (matrix.bit(row, col).expect("in range") && vector(col))
        })
    }

    const SHAPES: [(usize, usize); 6] =
        [(1, 1), (3, 64), (64, 65), (65, 127), (128, 120), (70, 200)];

    #[test]
    fn a_static_matrix_is_the_borrowed_one() {
        static WORDS: [u64; 4] = [0b101, 0b011, 0b110, 0b000];
        const FIXED: BitMatrix<'static> = BitMatrix::from_static(4, 3, &WORDS);
        assert_eq!(Ok(FIXED), BitMatrix::borrowed(4, 3, &WORDS));
        assert_eq!(FIXED.words_per_row(), 1);
    }

    #[test]
    fn helpers() {
        assert_eq!(words_for(0), 0);
        assert_eq!(words_for(64), 1);
        assert_eq!(words_for(65), 2);
        assert_eq!(parity(0), 0);
        assert_eq!(parity(0b1011), 1);
        assert_eq!(parity(u64::MAX), 0);
        assert_eq!(BitMatrix::row_byte(&[0x0807_0605_0403_0201, 0xff], 2), 3);
        assert_eq!(BitMatrix::row_byte(&[0x0807_0605_0403_0201, 0xff], 8), 0xff);
        assert_eq!(BitMatrix::row_byte(&[1], 8), 0);
        assert_eq!(BitMatrix::dot_words(&[0b110, 1], &[0b011, 1]), 0);
        assert_eq!(BitMatrix::dot_words(&[0b110, 1], &[0b011, 0]), 1);
    }

    #[test]
    fn shape_checks() {
        assert_eq!(check_shape(2, 65, &[0, 1, 0, 0]), Ok(2));
        assert!(matches!(
            check_shape(0, 5, &[]),
            Err(CrtError::Shape { .. })
        ));
        assert!(matches!(
            check_shape(5, 0, &[]),
            Err(CrtError::Shape { .. })
        ));
        assert_eq!(
            check_shape(2, 65, &[0, 1, 0]),
            Err(CrtError::Shape {
                what: "matrix words",
                expected: 4,
                actual: 3
            })
        );
        assert!(matches!(
            check_shape(2, 65, &[0, 1, 0, 2]),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(
            check_shape(usize::MAX, 65, &[]),
            Err(CrtError::Shape { .. })
        ));
        assert!(BitMatrix::zero(usize::MAX, 65).is_err());
        assert!(BitMatrix::zero(0, 65).is_err());
        assert!(BitMatrix::from_vec(1, 3, vec![8]).is_err());
        assert!(BitMatrix::borrowed(1, 3, &[7, 0]).is_err());
    }

    #[test]
    fn accessors_and_ownership() {
        let words = [0b101u64, 1, 0b010, 0];
        let matrix = BitMatrix::borrowed(2, 65, &words).expect("canonical");
        assert_eq!(
            (matrix.rows(), matrix.cols(), matrix.words_per_row()),
            (2, 65, 2)
        );
        assert_eq!(matrix.as_words(), &words);
        assert_eq!(matrix.row(1), Some(&words[2..]));
        assert_eq!(matrix.row(2), None);
        assert_eq!(matrix.row(usize::MAX), None);
        assert_eq!(matrix.bit(0, 0), Some(true));
        assert_eq!(matrix.bit(0, 1), Some(false));
        assert_eq!(matrix.bit(0, 64), Some(true));
        assert_eq!(matrix.bit(0, 65), None);
        assert_eq!(matrix.bit(2, 0), None);
        let mut owned = matrix.clone().into_owned();
        assert_eq!(owned, matrix);
        owned.set_bit(1, 64, true).expect("in range");
        owned.set_bit(0, 0, false).expect("in range");
        owned.set_bit(0, 2, true).expect("in range");
        assert_eq!(owned.as_words(), &[0b100, 1, 0b010, 1]);
        assert!(owned.set_bit(2, 0, true).is_err());
        assert!(owned.set_bit(0, 65, true).is_err());
        assert_eq!(
            BitMatrix::from_vec(2, 65, words.to_vec()),
            Ok(matrix.into_owned())
        );
        assert_eq!(check_len("x", 2, 2), Ok(()));
        assert_eq!(
            check_len("x", 2, 3),
            Err(CrtError::Shape {
                what: "x",
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn word_products_match_the_naive_ones() {
        let mut state = 0x1234_5678_9abc_def1;
        for (rows, cols) in SHAPES {
            let matrix = random_matrix(&mut state, rows, cols);
            for _ in 0..8 {
                // Bits at or above `cols` are set at random and must be ignored.
                let vector: Vec<u64> = (0..matrix.words_per_row())
                    .map(|_| next(&mut state))
                    .collect();
                let mut out = vec![u64::MAX; rows.div_ceil(64)];
                matrix.mul_vec(&mut out, &vector).expect("lengths");
                for row in 0..rows {
                    let expected = naive_dot(&matrix, row, |col| word_bit(&vector, col));
                    assert_eq!(matrix.row_dot(row, &vector), Ok(expected));
                    assert_eq!(word_bit(&out, row), expected);
                }
                for unused in rows..out.len() * 64 {
                    assert!(!word_bit(&out, unused));
                }
            }
        }
    }

    #[test]
    fn byte_product_matches_the_naive_one() {
        let mut state = 0x0fed_cba9_8765_4321;
        for (rows, cols) in SHAPES {
            let matrix = random_matrix(&mut state, rows, cols);
            for _ in 0..8 {
                let vector: Vec<u8> = (0..cols.div_ceil(8))
                    .map(|_| next(&mut state).to_le_bytes()[0])
                    .collect();
                let mut out = vec![0xffu8; rows.div_ceil(8)];
                matrix.mul_vec_bytes(&mut out, &vector).expect("lengths");
                for row in 0..rows {
                    let expected = naive_dot(&matrix, row, |col| byte_bit(&vector, col));
                    assert_eq!(byte_bit(&out, row), expected);
                }
                for unused in rows..out.len() * 8 {
                    assert!(!byte_bit(&out, unused));
                }
            }
        }
    }

    #[test]
    fn column_products_match_the_naive_ones() {
        let mut state = 0x9e37_79b9_7f4a_7c15;
        for (rows, cols) in SHAPES {
            let matrix = random_matrix(&mut state, rows, cols);
            for width in [1usize, 2, 5] {
                let columns: Vec<u64> = (0..cols * width).map(|_| next(&mut state)).collect();
                let mut out = vec![u64::MAX; rows * width];
                matrix
                    .apply_to_columns(&mut out, &columns, width)
                    .expect("lengths");
                let bytes: Vec<u8> = columns.iter().map(|word| word.to_le_bytes()[3]).collect();
                let mut out_bytes = vec![0xffu8; rows * width];
                matrix
                    .apply_to_byte_columns(&mut out_bytes, &bytes, width)
                    .expect("lengths");
                for row in 0..rows {
                    for bit in 0..width * 64 {
                        let expected = naive_dot(&matrix, row, |col| {
                            word_bit(&columns[col * width..(col + 1) * width], bit)
                        });
                        assert_eq!(
                            word_bit(&out[row * width..(row + 1) * width], bit),
                            expected
                        );
                    }
                    for bit in 0..width * 8 {
                        let expected = naive_dot(&matrix, row, |col| {
                            byte_bit(&bytes[col * width..(col + 1) * width], bit)
                        });
                        assert_eq!(
                            byte_bit(&out_bytes[row * width..(row + 1) * width], bit),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn products_reject_wrong_lengths() {
        let matrix = BitMatrix::zero(3, 70).expect("non-empty");
        let mut out = [0u64; 1];
        assert!(matrix.row_dot(3, &[0, 0]).is_err());
        assert!(matrix.row_dot(0, &[0]).is_err());
        assert!(matrix.mul_vec(&mut out, &[0]).is_err());
        assert!(matrix.mul_vec(&mut [0u64; 2], &[0, 0]).is_err());
        assert_eq!(matrix.mul_vec(&mut out, &[0, 0]), Ok(()));
        let mut bytes = [0u8; 1];
        assert!(matrix.mul_vec_bytes(&mut bytes, &[0; 8]).is_err());
        assert!(matrix.mul_vec_bytes(&mut [0u8; 2], &[0; 9]).is_err());
        assert_eq!(matrix.mul_vec_bytes(&mut bytes, &[0; 9]), Ok(()));
        assert!(
            matrix
                .apply_to_columns(&mut [0u64; 3], &[0; 70], 0)
                .is_err()
        );
        assert!(
            matrix
                .apply_to_columns(&mut [0u64; 3], &[0; 69], 1)
                .is_err()
        );
        assert!(
            matrix
                .apply_to_columns(&mut [0u64; 4], &[0; 70], 1)
                .is_err()
        );
        assert!(
            matrix
                .apply_to_columns(&mut [0u64; 3], &[0; 70], usize::MAX)
                .is_err()
        );
        assert_eq!(
            matrix.apply_to_byte_columns(&mut [0u8; 6], &[0; 140], 2),
            Ok(())
        );
    }
}
