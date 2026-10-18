//! Arbitrary-length bit vectors for the table generator.
//!
//! A [`Bits`] value is at once a vector over `GF(2)` (bit `i` is coordinate `i`) and
//! a polynomial over `GF(2)` (bit `i` is the coefficient of `x^i`). The generator
//! only handles public data, so nothing here is constant time.

/// Number of bits in one storage word.
const WORD: usize = 64;

/// Widen a `u32` to an index.
pub fn index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Widen a count to the `u64` the cost arithmetic uses.
pub fn wide(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A bit vector of unbounded length stored as little-endian `u64` words without
/// trailing zero words, so equal vectors compare equal.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bits {
    words: Vec<u64>,
}

impl Bits {
    /// The zero vector.
    pub const fn zero() -> Self {
        Self { words: Vec::new() }
    }

    /// The vector with only bit `position` set.
    pub fn unit(position: usize) -> Self {
        let mut out = Self::zero();
        out.set(position);
        out
    }

    /// The vector whose low 64 bits are `value`.
    pub fn from_u64(value: u64) -> Self {
        Self::from_words(&[value])
    }

    /// The vector with the given little-endian words.
    pub fn from_words(words: &[u64]) -> Self {
        let mut out = Self {
            words: words.to_vec(),
        };
        out.trim();
        out
    }

    /// Drop trailing zero words.
    fn trim(&mut self) {
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
    }

    /// Make room for bit `position`.
    fn grow(&mut self, position: usize) {
        let needed = position / WORD + 1;
        if self.words.len() < needed {
            self.words.resize(needed, 0);
        }
    }

    /// Whether no bit is set.
    pub fn is_zero(&self) -> bool {
        self.words.is_empty()
    }

    /// Bit `position`.
    pub fn bit(&self, position: usize) -> bool {
        self.words
            .get(position / WORD)
            .is_some_and(|word| (word >> (position % WORD)) & 1 == 1)
    }

    /// Set bit `position`.
    pub fn set(&mut self, position: usize) {
        self.grow(position);
        if let Some(word) = self.words.get_mut(position / WORD) {
            *word |= 1 << (position % WORD);
        }
    }

    /// Flip bit `position`.
    pub fn toggle(&mut self, position: usize) {
        self.grow(position);
        if let Some(word) = self.words.get_mut(position / WORD) {
            *word ^= 1 << (position % WORD);
        }
        self.trim();
    }

    /// Number of bits up to and including the highest set bit; zero for the zero
    /// vector.
    pub fn bit_len(&self) -> usize {
        self.words.last().map_or(0, |last| {
            self.words.len() * WORD - index(last.leading_zeros())
        })
    }

    /// Degree as a polynomial; `None` for the zero polynomial.
    pub fn degree(&self) -> Option<usize> {
        self.bit_len().checked_sub(1)
    }

    /// `self ^= other`.
    pub fn xor_assign(&mut self, other: &Self) {
        self.xor_shifted(other, 0);
    }

    /// `self |= other`.
    pub fn or_assign(&mut self, other: &Self) {
        if self.words.len() < other.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (word, value) in self.words.iter_mut().zip(&other.words) {
            *word |= value;
        }
    }

    /// `self ^= other << shift`.
    pub fn xor_shifted(&mut self, other: &Self, shift: usize) {
        if other.is_zero() {
            return;
        }
        let base = shift / WORD;
        let offset = shift % WORD;
        let needed = base + other.words.len() + 1;
        if self.words.len() < needed {
            self.words.resize(needed, 0);
        }
        for (position, value) in other.words.iter().enumerate() {
            if let Some(word) = self.words.get_mut(base + position) {
                *word ^= value << offset;
            }
            if offset != 0
                && let Some(word) = self.words.get_mut(base + position + 1)
            {
                *word ^= value >> (WORD - offset);
            }
        }
        self.trim();
    }

    /// `self << shift`.
    pub fn shl(&self, shift: usize) -> Self {
        let mut out = Self::zero();
        out.xor_shifted(self, shift);
        out
    }

    /// Positions of the set bits in ascending order.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(position, word)| {
            (0..WORD)
                .filter(move |bit| (word >> bit) & 1 == 1)
                .map(move |bit| position * WORD + bit)
        })
    }

    /// Parity of the number of positions set in both vectors: the inner product
    /// over `GF(2)`.
    pub fn parity_and(&self, other: &Self) -> bool {
        let folded = self
            .words
            .iter()
            .zip(&other.words)
            .fold(0u64, |acc, (left, right)| acc ^ (left & right));
        folded.count_ones() & 1 == 1
    }

    /// The vector as exactly `count` little-endian words, or `None` if it has a bit
    /// at or above `64 * count`.
    pub fn to_words(&self, count: usize) -> Option<Vec<u64>> {
        if self.words.len() > count {
            return None;
        }
        let mut out = self.words.clone();
        out.resize(count, 0);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widening_helpers() {
        assert_eq!(index(7), 7);
        assert_eq!(wide(9), 9);
    }

    #[test]
    fn constructors_and_bit_access() {
        assert!(Bits::zero().is_zero());
        assert_eq!(Bits::zero(), Bits::default());
        let unit = Bits::unit(70);
        assert!(unit.bit(70));
        assert!(!unit.bit(69));
        assert!(!unit.bit(700));
        assert_eq!(unit, Bits::from_words(&[0, 1 << 6, 0, 0]));
        assert_eq!(Bits::from_u64(0), Bits::zero());
        assert_eq!(Bits::from_u64(5).ones().collect::<Vec<_>>(), vec![0, 2]);
        assert!(!Bits::from_u64(5).is_zero());
    }

    #[test]
    fn set_toggle_trim_and_grow() {
        let mut value = Bits::zero();
        value.set(3);
        value.set(3);
        value.set(130);
        assert_eq!(value.ones().collect::<Vec<_>>(), vec![3, 130]);
        value.toggle(130);
        assert_eq!(value, Bits::from_u64(8));
        value.toggle(3);
        assert!(value.is_zero());
        let mut raw = Bits {
            words: vec![1, 0, 0],
        };
        raw.trim();
        assert_eq!(raw.words, vec![1]);
        raw.grow(64);
        assert_eq!(raw.words, vec![1, 0]);
    }

    #[test]
    fn lengths_and_degrees() {
        assert_eq!(Bits::zero().bit_len(), 0);
        assert_eq!(Bits::zero().degree(), None);
        assert_eq!(Bits::from_u64(1).degree(), Some(0));
        assert_eq!(Bits::from_u64(0x11b).degree(), Some(8));
        assert_eq!(Bits::unit(64).bit_len(), 65);
        assert_eq!(Bits::unit(127).degree(), Some(127));
    }

    #[test]
    fn xor_or_and_shifts() {
        let mut value = Bits::from_u64(0b1100);
        value.xor_assign(&Bits::from_u64(0b1010));
        assert_eq!(value, Bits::from_u64(0b0110));
        value.or_assign(&Bits::unit(65));
        assert_eq!(value.ones().collect::<Vec<_>>(), vec![1, 2, 65]);
        let mut small = Bits::from_u64(1);
        small.or_assign(&Bits::from_u64(1));
        assert_eq!(small, Bits::from_u64(1));

        let mut shifted = Bits::zero();
        shifted.xor_shifted(&Bits::from_u64(u64::MAX), 60);
        assert_eq!(shifted, Bits::from_words(&[0xf << 60, u64::MAX >> 4]));
        shifted.xor_shifted(&Bits::from_u64(u64::MAX), 60);
        assert!(shifted.is_zero());
        shifted.xor_shifted(&Bits::zero(), 1000);
        assert!(shifted.is_zero());
        assert_eq!(Bits::from_u64(3).shl(64), Bits::from_words(&[0, 3]));
        assert_eq!(Bits::from_u64(3).shl(0), Bits::from_u64(3));
        for shift in [0usize, 1, 63, 64, 65, 200] {
            let positions: Vec<usize> = Bits::from_u64(0x8000_0000_0000_0005)
                .shl(shift)
                .ones()
                .collect();
            assert_eq!(positions, vec![shift, shift + 2, shift + 63]);
        }
    }

    #[test]
    fn parity_and_word_export() {
        let left = Bits::from_words(&[0b1011, 1]);
        let right = Bits::from_words(&[0b0011, 1, 7]);
        assert!(left.parity_and(&right));
        assert!(!left.parity_and(&Bits::from_u64(0b0011)));
        assert!(!left.parity_and(&Bits::zero()));
        assert_eq!(left.to_words(3), Some(vec![0b1011, 1, 0]));
        assert_eq!(left.to_words(2), Some(vec![0b1011, 1]));
        assert_eq!(left.to_words(1), None);
        assert_eq!(Bits::zero().to_words(0), Some(vec![]));
    }
}
