//! Scalar `ChaCha20` PRNG layout used by the pinned Falcon reference signer.
//!
//! Adapted from `fn-dsa-sign` 0.3.0 at commit
//! `daf14859b5aa3f8d75c42966ba7de83e6eb59997` (Unlicense).  The unusual
//! word-major eight-block output layout is intentional and matches the Falcon
//! C implementation and its AVX2 path byte for byte.
use super::super::table_assets::read_u32_le;
use super::PRNG;
use zeroize::Zeroize;
pub(in crate::privacy_engines::bootle_lantern::falcon512) struct ChaCha20Prng {
    buffer: [u8; 512],
    state: [u8; 56],
    pointer: usize,
}
const CONSTANT_WORDS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
impl ChaCha20Prng {
    fn refill(&mut self) {
        let mut counter = zeroize::Zeroizing::new(u64::from_le_bytes(
            self.state[48..56]
                .try_into()
                .expect("fixed ChaCha counter slice"),
        ));
        for block in 0..8 {
            let mut working = zeroize::Zeroizing::new([0_u32; 16]);
            working[..4].copy_from_slice(&CONSTANT_WORDS);
            for word in 0..12 {
                working[4 + word] = u32::from_le_bytes(
                    self.state[4 * word..4 * word + 4]
                        .try_into()
                        .expect("fixed ChaCha state word"),
                );
            }
            working[14] ^= read_u32_le(&counter.to_le_bytes(), 0);
            working[15] ^= (*counter >> 32) as u32;
            for _ in 0..10 {
                quarter_round(&mut working, 0, 4, 8, 12);
                quarter_round(&mut working, 1, 5, 9, 13);
                quarter_round(&mut working, 2, 6, 10, 14);
                quarter_round(&mut working, 3, 7, 11, 15);
                quarter_round(&mut working, 0, 5, 10, 15);
                quarter_round(&mut working, 1, 6, 11, 12);
                quarter_round(&mut working, 2, 7, 8, 13);
                quarter_round(&mut working, 3, 4, 9, 14);
            }
            for word in 0..4 {
                working[word] = working[word].wrapping_add(CONSTANT_WORDS[word]);
            }
            for word in 0..10 {
                working[4 + word] = working[4 + word].wrapping_add(u32::from_le_bytes(
                    self.state[4 * word..4 * word + 4]
                        .try_into()
                        .expect("fixed ChaCha feed-forward word"),
                ));
            }
            working[14] = working[14].wrapping_add(
                u32::from_le_bytes(self.state[40..44].try_into().expect("fixed ChaCha IV word"))
                    ^ read_u32_le(&counter.to_le_bytes(), 0),
            );
            working[15] = working[15].wrapping_add(
                u32::from_le_bytes(self.state[44..48].try_into().expect("fixed ChaCha IV word"))
                    ^ (*counter >> 32) as u32,
            );
            *counter = counter.wrapping_add(1);
            for (word, value) in working.iter().copied().enumerate() {
                let offset = 4 * block + 32 * word;
                self.buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        self.state[48..56].copy_from_slice(&counter.to_le_bytes());
        self.pointer = 0;
    }
}
impl core::fmt::Debug for ChaCha20Prng {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FalconChaCha20Prng(<redacted>)")
    }
}
impl Drop for ChaCha20Prng {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl PRNG for ChaCha20Prng {
    fn new(seed: &[u8]) -> Self {
        assert_eq!(seed.len(), 56, "Falcon ChaCha20 seed is exactly 56 bytes");
        let mut output = Self {
            buffer: [0; 512],
            state: [0; 56],
            pointer: 0,
        };
        output.state.copy_from_slice(seed);
        output.refill();
        output
    }
    fn next_u8(&mut self) -> u8 {
        if self.pointer == self.buffer.len() {
            self.refill();
        }
        let output = self.buffer[self.pointer];
        self.pointer += 1;
        output
    }
    fn next_u16(&mut self) -> u16 {
        // Preserve the pinned upstream implementation's (unused by the
        // signer) one-bit shift exactly for differential reproducibility.
        let low = self.next_u8();
        let high = self.next_u8();
        u16::from(low) | (u16::from(high) << 1)
    }
    fn next_u64(&mut self) -> u64 {
        if self.pointer >= self.buffer.len() - 9 {
            self.refill();
        }
        let start = self.pointer;
        self.pointer += 8;
        u64::from_le_bytes(
            self.buffer[start..start + 8]
                .try_into()
                .expect("fixed ChaCha output word"),
        )
    }
    fn zeroize(&mut self) {
        self.buffer.zeroize();
        self.state.zeroize();
        self.pointer.zeroize();
    }
}
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;
    #[test]
    fn pinned_falcon_chacha20_stream_kat() {
        let seed: [u8; 56] = hex::decode(
            "380878a8c753e1e93735a37c7b370eff893fa3fa6f52e40d2975b69926f6107399181118c739177437603fac15d446ebc1bd60587572a37e",
        )
        .expect("hex")
        .try_into()
        .expect("56 bytes");
        let expected = hex::decode(
            "4c69ad3a84301fdb3cb5d5864ec1d9fa9f436cf414f9847f6d6c379a396e6ac489176b8c6fcda54787a97d7079d8851ee7b31d2c6cceb0c77c973d7b539557a6",
        )
        .expect("hex");
        let mut generator = ChaCha20Prng::new(&seed);
        let mut actual = [0_u8; 64];
        for byte in &mut actual {
            *byte = generator.next_u8();
        }
        assert_eq!(actual.as_slice(), expected);
        assert_eq!(
            Sha256::digest(actual).as_slice(),
            hex::decode("7b2df68aaeafbccd7bb5346d4a3f486f292bb0f4927f2d1b74eb5d3fdc533b89")
                .expect("hex")
        );
    }
    #[test]
    fn pinned_falcon_chacha20_two_refill_digest_and_tail_boundary() {
        let seed: [u8; 56] = hex::decode(
            "380878a8c753e1e93735a37c7b370eff893fa3fa6f52e40d2975b69926f6107399181118c739177437603fac15d446ebc1bd60587572a37e",
        )
        .expect("hex")
        .try_into()
        .expect("56 bytes");
        let mut generator = ChaCha20Prng::new(&seed);
        let mut words = Zeroizing::new([0_u8; 128 * 8]);
        for chunk in words.chunks_exact_mut(8) {
            chunk.copy_from_slice(&generator.next_u64().to_le_bytes());
        }
        assert_eq!(
            Sha256::digest(words.as_slice()).as_slice(),
            hex::decode("edc508303c516de4cee4dcd329ce19af316fae7ab396e0bf17932322ece5d81a")
                .expect("hex")
        );
        let mut at_502 = ChaCha20Prng::new(&seed);
        let mut bytewise_502 = ChaCha20Prng::new(&seed);
        for _ in 0..502 {
            let _ = at_502.next_u8();
            let _ = bytewise_502.next_u8();
        }
        let mixed = at_502.next_u64();
        let mut expected = [0_u8; 8];
        for byte in &mut expected {
            *byte = bytewise_502.next_u8();
        }
        assert_eq!(mixed, u64::from_le_bytes(expected));
        let mut at_503 = ChaCha20Prng::new(&seed);
        let mut fresh_refill = ChaCha20Prng::new(&seed);
        for _ in 0..503 {
            let _ = at_503.next_u8();
        }
        for _ in 0..512 {
            let _ = fresh_refill.next_u8();
        }
        assert_eq!(at_503.next_u64(), fresh_refill.next_u64());
    }
}
