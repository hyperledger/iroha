//! Bit-string helpers of the VOLE layer.
//!
//! Bit `i` of a byte string is bit `i % 8` of byte `i / 8`, and bit `i` of a word
//! string is bit `i % 64` of little-endian word `i / 64`: the two views describe the
//! same bit string.
//!
//! Every helper may be given secret contents. Positions, counts and lengths are
//! public; the contents are only moved with shifts, AND, OR and XOR, and never
//! select a branch or an index.

/// `dst ^= src` over the common prefix of the two strings.
pub(super) fn xor_into(dst: &mut [u8], src: &[u8]) {
    let common = dst.len().min(src.len());
    let (Some(dst), Some(src)) = (dst.get_mut(..common), src.get(..common)) else {
        return;
    };
    // Eight bytes at a time; the two tails line up because the lengths are equal.
    let (dst_words, dst_tail) = dst.as_chunks_mut::<8>();
    let (src_words, src_tail) = src.as_chunks::<8>();
    for (left, right) in dst_words.iter_mut().zip(src_words) {
        *left = (u64::from_ne_bytes(*left) ^ u64::from_ne_bytes(*right)).to_ne_bytes();
    }
    for (left, right) in dst_tail.iter_mut().zip(src_tail) {
        *left ^= *right;
    }
}

/// Bit `position` of `bytes` as zero or one; zero beyond the end.
pub(super) fn bit(bytes: &[u8], position: usize) -> u64 {
    bytes
        .get(position / 8)
        .map_or(0, |byte| u64::from((byte >> (position % 8)) & 1))
}

/// The `count <= 16` bits of `bytes` starting at bit `position`, bit `position`
/// lowest. Bits beyond the end of `bytes` read as zero.
pub(super) fn read_bits(bytes: &[u8], position: usize, count: usize) -> u32 {
    let first = position / 8;
    let mut window = 0u32;
    for (index, shift) in [0u32, 8, 16].into_iter().enumerate() {
        let byte = first
            .checked_add(index)
            .and_then(|at| bytes.get(at))
            .copied()
            .unwrap_or(0);
        window |= u32::from(byte) << shift;
    }
    let mask = (1u32 << count.min(16)) - 1;
    (window >> (position % 8)) & mask
}

/// OR the low `count <= 32` bits of `value` into `words` at bit `position`. Bits
/// that fall beyond the end of `words` are dropped.
pub(super) fn or_bits(words: &mut [u64], position: usize, count: usize, value: u64) {
    let value = value & ((1u64 << count.min(32)) - 1);
    let (word, shift) = (position / 64, position % 64);
    if let Some(slot) = words.get_mut(word) {
        *slot |= value << shift;
    }
    if shift != 0
        && let Some(slot) = word.checked_add(1).and_then(|next| words.get_mut(next))
    {
        *slot |= value >> (64 - shift);
    }
}

/// `out ^= (src << shift) & mask`, with `src` and `out` read as bit strings and
/// `mask` all ones or all zeros. Bits shifted beyond the end of `out` are dropped.
pub(super) fn xor_shifted_masked(out: &mut [u64], src: &[u64], shift: usize, mask: u64) {
    let (words, bits) = (shift / 64, shift % 64);
    for (index, &word) in src.iter().enumerate() {
        let low = word << bits;
        let high = if bits == 0 { 0 } else { word >> (64 - bits) };
        if let Some(slot) = index.checked_add(words).and_then(|at| out.get_mut(at)) {
            *slot ^= low & mask;
        }
        if let Some(slot) = index.checked_add(words + 1).and_then(|at| out.get_mut(at)) {
            *slot ^= high & mask;
        }
    }
}

/// The byte string `bytes` as little-endian words, zero padded to `words.len()`
/// words. Bytes beyond the last word are ignored.
pub(super) fn load_words(words: &mut [u64], bytes: &[u8]) {
    words.fill(0);
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut buffer = [0u8; 8];
        for (slot, byte) in buffer.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        *word = u64::from_le_bytes(buffer);
    }
}

/// The first `out.len()` bytes of the little-endian byte view of `words`; bytes
/// beyond the last word are set to zero.
pub(super) fn store_words(out: &mut [u8], words: &[u64]) {
    out.fill(0);
    for (chunk, word) in out.chunks_mut(8).zip(words) {
        for (slot, byte) in chunk.iter_mut().zip(word.to_le_bytes()) {
            *slot = byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| {
                u8::try_from((index * 37 + 11) % 251)
                    .expect("below 251")
                    .wrapping_mul(seed)
                    ^ seed
            })
            .collect()
    }

    #[test]
    fn xor_into_is_the_bytewise_xor_for_every_length() {
        for len in 0..40 {
            let left = pattern(len, 3);
            let right = pattern(len, 7);
            let expected: Vec<u8> = left.iter().zip(&right).map(|(a, b)| a ^ b).collect();
            let mut actual = left.clone();
            xor_into(&mut actual, &right);
            assert_eq!(actual, expected, "length {len}");
        }
        // Unequal lengths: only the common prefix changes.
        for (long, short) in [(20, 9), (17, 16), (9, 3)] {
            let left = pattern(long, 5);
            let right = pattern(short, 9);
            let mut actual = left.clone();
            xor_into(&mut actual, &right);
            for index in 0..long {
                let expected = left[index] ^ right.get(index).copied().unwrap_or(0);
                assert_eq!(actual[index], expected);
            }
            let mut actual = right.clone();
            xor_into(&mut actual, &left);
            for index in 0..short {
                assert_eq!(actual[index], left[index] ^ right[index]);
            }
        }
    }

    #[test]
    fn single_bits_and_windows_are_little_endian() {
        let bytes = [0b1010_0101u8, 0xff, 0x00, 0x81];
        let expected = [1u64, 0, 1, 0, 0, 1, 0, 1, 1, 1];
        for (position, want) in expected.into_iter().enumerate() {
            assert_eq!(bit(&bytes, position), want);
        }
        assert_eq!(bit(&bytes, 31), 1);
        assert_eq!(bit(&bytes, 32), 0);
        assert_eq!(bit(&bytes, usize::MAX), 0);

        let value = u32::from_le_bytes(bytes);
        for position in 0..40 {
            for count in 0..=16 {
                let mut want = 0u32;
                for offset in 0..count {
                    if position + offset < 32 {
                        want |= ((value >> (position + offset)) & 1) << offset;
                    }
                }
                assert_eq!(read_bits(&bytes, position, count), want);
            }
        }
        assert_eq!(read_bits(&bytes, usize::MAX, 16), 0);
    }

    #[test]
    fn or_bits_places_values_across_word_boundaries() {
        for position in [0, 1, 40, 60, 63, 64, 100, 120] {
            for count in [0, 1, 7, 12, 32] {
                let value = 0xdead_beef_u64;
                let mut words = [0u64; 3];
                or_bits(&mut words, position, count, value | (1 << 40));
                for index in 0..192 {
                    let got = (words[index / 64] >> (index % 64)) & 1;
                    let want = if index >= position && index < position + count {
                        (value >> (index - position)) & 1
                    } else {
                        0
                    };
                    assert_eq!(got, want, "position {position} count {count} bit {index}");
                }
            }
        }
        // Bits beyond the end are dropped without a panic.
        let mut words = [0u64; 1];
        or_bits(&mut words, 60, 12, 0xfff);
        assert_eq!(words, [0xf000_0000_0000_0000]);
        or_bits(&mut words, 640, 12, 0xfff);
        assert_eq!(words, [0xf000_0000_0000_0000]);
    }

    #[test]
    fn shifted_xor_is_a_masked_polynomial_shift() {
        let src = [0x8000_0000_0000_0001u64, 0x3];
        for shift in [0, 1, 5, 63, 64, 65, 100] {
            let mut out = [0u64; 4];
            xor_shifted_masked(&mut out, &src, shift, u64::MAX);
            for index in 0..256 {
                let got = (out[index / 64] >> (index % 64)) & 1;
                let want = if index >= shift && index - shift < 128 {
                    (src[(index - shift) / 64] >> ((index - shift) % 64)) & 1
                } else {
                    0
                };
                assert_eq!(got, want, "shift {shift} bit {index}");
            }
            // A zero mask adds nothing, and adding twice cancels.
            let mut twice = out;
            xor_shifted_masked(&mut twice, &src, shift, 0);
            assert_eq!(twice, out);
            xor_shifted_masked(&mut twice, &src, shift, u64::MAX);
            assert_eq!(twice, [0; 4]);
        }
        // Overflow beyond the output is dropped.
        let mut out = [0u64; 1];
        xor_shifted_masked(&mut out, &src, 63, u64::MAX);
        assert_eq!(out, [0x8000_0000_0000_0000]);
    }

    #[test]
    fn words_and_bytes_are_two_views_of_one_bit_string() {
        let bytes = pattern(19, 13);
        let mut words = [u64::MAX; 4];
        load_words(&mut words, &bytes);
        for position in 0..256 {
            assert_eq!(
                (words[position / 64] >> (position % 64)) & 1,
                bit(&bytes, position)
            );
        }
        let mut back = [0xaau8; 19];
        store_words(&mut back, &words);
        assert_eq!(back.as_slice(), bytes.as_slice());
        // Truncation on both sides.
        let mut short = [0u64; 1];
        load_words(&mut short, &bytes);
        assert_eq!(short[0], words[0]);
        let mut long = [0xaau8; 12];
        store_words(&mut long, &short);
        assert_eq!(&long[..8], &bytes[..8]);
        assert_eq!(&long[8..], &[0; 4]);
    }
}
