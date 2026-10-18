#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
//! # SHAKE Implementation
//!
//! This module retains only the scalar SHAKE256 permutation and buffered
//! single-stream PRNG needed by bounded key generation and ffSampling.
use super::PRNG;
use zeroize::Zeroize;
// Keccak state (25*8 = 200 bytes).
struct KeccakState([u64; 25]);
impl KeccakState {
    const RC: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808A,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808B,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008A,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000A,
        0x0000_0000_8000_808B,
        0x8000_0000_0000_008B,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800A,
        0x8000_0000_8000_000A,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
    // Create a new KeccakState initialized at zero.
    fn new() -> Self {
        Self([0u64; 25])
    }
    fn process(&mut self) {
        let mut A: [u64; 25] = self.0;
        // Invert some words (alternate internal representation, which
        // saves some operations).
        A[1] = !A[1];
        A[2] = !A[2];
        A[8] = !A[8];
        A[12] = !A[12];
        A[17] = !A[17];
        A[20] = !A[20];
        // Compute 24 rounds. The loop is partially unrolled (two rounds
        // per iteration).
        for i in 0..12 {
            let (mut t0, mut t1, mut t2, mut t3, mut t4);
            let (mut tt0, mut tt1, mut tt2, mut tt3);
            let (mut t, mut kt);
            let (mut c0, mut c1, mut c2, mut c3, mut c4, mut bnn);
            tt0 = A[1] ^ A[6];
            tt1 = A[11] ^ A[16];
            tt0 ^= A[21] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[4] ^ A[9];
            tt3 = A[14] ^ A[19];
            tt0 ^= A[24];
            tt2 ^= tt3;
            t0 = tt0 ^ tt2;
            tt0 = A[2] ^ A[7];
            tt1 = A[12] ^ A[17];
            tt0 ^= A[22] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[0] ^ A[5];
            tt3 = A[10] ^ A[15];
            tt0 ^= A[20];
            tt2 ^= tt3;
            t1 = tt0 ^ tt2;
            tt0 = A[3] ^ A[8];
            tt1 = A[13] ^ A[18];
            tt0 ^= A[23] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[1] ^ A[6];
            tt3 = A[11] ^ A[16];
            tt0 ^= A[21];
            tt2 ^= tt3;
            t2 = tt0 ^ tt2;
            tt0 = A[4] ^ A[9];
            tt1 = A[14] ^ A[19];
            tt0 ^= A[24] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[2] ^ A[7];
            tt3 = A[12] ^ A[17];
            tt0 ^= A[22];
            tt2 ^= tt3;
            t3 = tt0 ^ tt2;
            tt0 = A[0] ^ A[5];
            tt1 = A[10] ^ A[15];
            tt0 ^= A[20] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[3] ^ A[8];
            tt3 = A[13] ^ A[18];
            tt0 ^= A[23];
            tt2 ^= tt3;
            t4 = tt0 ^ tt2;
            A[0] ^= t0;
            A[5] ^= t0;
            A[10] ^= t0;
            A[15] ^= t0;
            A[20] ^= t0;
            A[1] ^= t1;
            A[6] ^= t1;
            A[11] ^= t1;
            A[16] ^= t1;
            A[21] ^= t1;
            A[2] ^= t2;
            A[7] ^= t2;
            A[12] ^= t2;
            A[17] ^= t2;
            A[22] ^= t2;
            A[3] ^= t3;
            A[8] ^= t3;
            A[13] ^= t3;
            A[18] ^= t3;
            A[23] ^= t3;
            A[4] ^= t4;
            A[9] ^= t4;
            A[14] ^= t4;
            A[19] ^= t4;
            A[24] ^= t4;
            A[5] = A[5].rotate_right(64 - 36);
            A[10] = A[10].rotate_left(3);
            A[15] = A[15].rotate_right(64 - 41);
            A[20] = A[20].rotate_left(18);
            A[1] = A[1].rotate_left(1);
            A[6] = A[6].rotate_right(64 - 44);
            A[11] = A[11].rotate_left(10);
            A[16] = A[16].rotate_right(64 - 45);
            A[21] = A[21].rotate_left(2);
            A[2] = A[2].rotate_right(64 - 62);
            A[7] = A[7].rotate_left(6);
            A[12] = A[12].rotate_right(64 - 43);
            A[17] = A[17].rotate_left(15);
            A[22] = A[22].rotate_right(64 - 61);
            A[3] = A[3].rotate_left(28);
            A[8] = A[8].rotate_right(64 - 55);
            A[13] = A[13].rotate_left(25);
            A[18] = A[18].rotate_left(21);
            A[23] = A[23].rotate_right(64 - 56);
            A[4] = A[4].rotate_left(27);
            A[9] = A[9].rotate_left(20);
            A[14] = A[14].rotate_right(64 - 39);
            A[19] = A[19].rotate_left(8);
            A[24] = A[24].rotate_left(14);
            bnn = !A[12];
            kt = A[6] | A[12];
            c0 = A[0] ^ kt;
            kt = bnn | A[18];
            c1 = A[6] ^ kt;
            kt = A[18] & A[24];
            c2 = A[12] ^ kt;
            kt = A[24] | A[0];
            c3 = A[18] ^ kt;
            kt = A[0] & A[6];
            c4 = A[24] ^ kt;
            A[0] = c0;
            A[6] = c1;
            A[12] = c2;
            A[18] = c3;
            A[24] = c4;
            bnn = !A[22];
            kt = A[9] | A[10];
            c0 = A[3] ^ kt;
            kt = A[10] & A[16];
            c1 = A[9] ^ kt;
            kt = A[16] | bnn;
            c2 = A[10] ^ kt;
            kt = A[22] | A[3];
            c3 = A[16] ^ kt;
            kt = A[3] & A[9];
            c4 = A[22] ^ kt;
            A[3] = c0;
            A[9] = c1;
            A[10] = c2;
            A[16] = c3;
            A[22] = c4;
            bnn = !A[19];
            kt = A[7] | A[13];
            c0 = A[1] ^ kt;
            kt = A[13] & A[19];
            c1 = A[7] ^ kt;
            kt = bnn & A[20];
            c2 = A[13] ^ kt;
            kt = A[20] | A[1];
            c3 = bnn ^ kt;
            kt = A[1] & A[7];
            c4 = A[20] ^ kt;
            A[1] = c0;
            A[7] = c1;
            A[13] = c2;
            A[19] = c3;
            A[20] = c4;
            bnn = !A[17];
            kt = A[5] & A[11];
            c0 = A[4] ^ kt;
            kt = A[11] | A[17];
            c1 = A[5] ^ kt;
            kt = bnn | A[23];
            c2 = A[11] ^ kt;
            kt = A[23] & A[4];
            c3 = bnn ^ kt;
            kt = A[4] | A[5];
            c4 = A[23] ^ kt;
            A[4] = c0;
            A[5] = c1;
            A[11] = c2;
            A[17] = c3;
            A[23] = c4;
            bnn = !A[8];
            kt = bnn & A[14];
            c0 = A[2] ^ kt;
            kt = A[14] | A[15];
            c1 = bnn ^ kt;
            kt = A[15] & A[21];
            c2 = A[14] ^ kt;
            kt = A[21] | A[2];
            c3 = A[15] ^ kt;
            kt = A[2] & A[8];
            c4 = A[21] ^ kt;
            A[2] = c0;
            A[8] = c1;
            A[14] = c2;
            A[15] = c3;
            A[21] = c4;
            A[0] ^= Self::RC[2 * i];
            tt0 = A[6] ^ A[9];
            tt1 = A[7] ^ A[5];
            tt0 ^= A[8] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[24] ^ A[22];
            tt3 = A[20] ^ A[23];
            tt0 ^= A[21];
            tt2 ^= tt3;
            t0 = tt0 ^ tt2;
            tt0 = A[12] ^ A[10];
            tt1 = A[13] ^ A[11];
            tt0 ^= A[14] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[0] ^ A[3];
            tt3 = A[1] ^ A[4];
            tt0 ^= A[2];
            tt2 ^= tt3;
            t1 = tt0 ^ tt2;
            tt0 = A[18] ^ A[16];
            tt1 = A[19] ^ A[17];
            tt0 ^= A[15] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[6] ^ A[9];
            tt3 = A[7] ^ A[5];
            tt0 ^= A[8];
            tt2 ^= tt3;
            t2 = tt0 ^ tt2;
            tt0 = A[24] ^ A[22];
            tt1 = A[20] ^ A[23];
            tt0 ^= A[21] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[12] ^ A[10];
            tt3 = A[13] ^ A[11];
            tt0 ^= A[14];
            tt2 ^= tt3;
            t3 = tt0 ^ tt2;
            tt0 = A[0] ^ A[3];
            tt1 = A[1] ^ A[4];
            tt0 ^= A[2] ^ tt1;
            tt0 = tt0.rotate_left(1);
            tt2 = A[18] ^ A[16];
            tt3 = A[19] ^ A[17];
            tt0 ^= A[15];
            tt2 ^= tt3;
            t4 = tt0 ^ tt2;
            A[0] ^= t0;
            A[3] ^= t0;
            A[1] ^= t0;
            A[4] ^= t0;
            A[2] ^= t0;
            A[6] ^= t1;
            A[9] ^= t1;
            A[7] ^= t1;
            A[5] ^= t1;
            A[8] ^= t1;
            A[12] ^= t2;
            A[10] ^= t2;
            A[13] ^= t2;
            A[11] ^= t2;
            A[14] ^= t2;
            A[18] ^= t3;
            A[16] ^= t3;
            A[19] ^= t3;
            A[17] ^= t3;
            A[15] ^= t3;
            A[24] ^= t4;
            A[22] ^= t4;
            A[20] ^= t4;
            A[23] ^= t4;
            A[21] ^= t4;
            A[3] = A[3].rotate_right(64 - 36);
            A[1] = A[1].rotate_left(3);
            A[4] = A[4].rotate_right(64 - 41);
            A[2] = A[2].rotate_left(18);
            A[6] = A[6].rotate_left(1);
            A[9] = A[9].rotate_right(64 - 44);
            A[7] = A[7].rotate_left(10);
            A[5] = A[5].rotate_right(64 - 45);
            A[8] = A[8].rotate_left(2);
            A[12] = A[12].rotate_right(64 - 62);
            A[10] = A[10].rotate_left(6);
            A[13] = A[13].rotate_right(64 - 43);
            A[11] = A[11].rotate_left(15);
            A[14] = A[14].rotate_right(64 - 61);
            A[18] = A[18].rotate_left(28);
            A[16] = A[16].rotate_right(64 - 55);
            A[19] = A[19].rotate_left(25);
            A[17] = A[17].rotate_left(21);
            A[15] = A[15].rotate_right(64 - 56);
            A[24] = A[24].rotate_left(27);
            A[22] = A[22].rotate_left(20);
            A[20] = A[20].rotate_right(64 - 39);
            A[23] = A[23].rotate_left(8);
            A[21] = A[21].rotate_left(14);
            bnn = !A[13];
            kt = A[9] | A[13];
            c0 = A[0] ^ kt;
            kt = bnn | A[17];
            c1 = A[9] ^ kt;
            kt = A[17] & A[21];
            c2 = A[13] ^ kt;
            kt = A[21] | A[0];
            c3 = A[17] ^ kt;
            kt = A[0] & A[9];
            c4 = A[21] ^ kt;
            A[0] = c0;
            A[9] = c1;
            A[13] = c2;
            A[17] = c3;
            A[21] = c4;
            bnn = !A[14];
            kt = A[22] | A[1];
            c0 = A[18] ^ kt;
            kt = A[1] & A[5];
            c1 = A[22] ^ kt;
            kt = A[5] | bnn;
            c2 = A[1] ^ kt;
            kt = A[14] | A[18];
            c3 = A[5] ^ kt;
            kt = A[18] & A[22];
            c4 = A[14] ^ kt;
            A[18] = c0;
            A[22] = c1;
            A[1] = c2;
            A[5] = c3;
            A[14] = c4;
            bnn = !A[23];
            kt = A[10] | A[19];
            c0 = A[6] ^ kt;
            kt = A[19] & A[23];
            c1 = A[10] ^ kt;
            kt = bnn & A[2];
            c2 = A[19] ^ kt;
            kt = A[2] | A[6];
            c3 = bnn ^ kt;
            kt = A[6] & A[10];
            c4 = A[2] ^ kt;
            A[6] = c0;
            A[10] = c1;
            A[19] = c2;
            A[23] = c3;
            A[2] = c4;
            bnn = !A[11];
            kt = A[3] & A[7];
            c0 = A[24] ^ kt;
            kt = A[7] | A[11];
            c1 = A[3] ^ kt;
            kt = bnn | A[15];
            c2 = A[7] ^ kt;
            kt = A[15] & A[24];
            c3 = bnn ^ kt;
            kt = A[24] | A[3];
            c4 = A[15] ^ kt;
            A[24] = c0;
            A[3] = c1;
            A[7] = c2;
            A[11] = c3;
            A[15] = c4;
            bnn = !A[16];
            kt = bnn & A[20];
            c0 = A[12] ^ kt;
            kt = A[20] | A[4];
            c1 = bnn ^ kt;
            kt = A[4] & A[8];
            c2 = A[20] ^ kt;
            kt = A[8] | A[12];
            c3 = A[4] ^ kt;
            kt = A[12] & A[16];
            c4 = A[8] ^ kt;
            A[12] = c0;
            A[16] = c1;
            A[20] = c2;
            A[4] = c3;
            A[8] = c4;
            A[0] ^= Self::RC[2 * i + 1];
            t = A[5];
            A[5] = A[18];
            A[18] = A[11];
            A[11] = A[10];
            A[10] = A[6];
            A[6] = A[22];
            A[22] = A[20];
            A[20] = A[12];
            A[12] = A[19];
            A[19] = A[15];
            A[15] = A[24];
            A[24] = A[8];
            A[8] = t;
            t = A[1];
            A[1] = A[9];
            A[9] = A[14];
            A[14] = A[2];
            A[2] = A[13];
            A[13] = A[23];
            A[23] = A[4];
            A[4] = A[21];
            A[21] = A[16];
            A[16] = A[3];
            A[3] = A[17];
            A[17] = A[7];
            A[7] = t;
        }
        // Invert some words back to normal representation.
        A[1] = !A[1];
        A[2] = !A[2];
        A[8] = !A[8];
        A[12] = !A[12];
        A[17] = !A[17];
        A[20] = !A[20];
        self.0 = A;
    }
}
/// Scalar SHAKE sponge parameterized by its security strength in bits.
pub struct Shake<const SZ: usize> {
    state: KeccakState,
    ptr: usize,
    flipped: bool,
}
/// Type specialization for SHAKE256.
pub type SHAKE256 = Shake<256>;
impl<const SZ: usize> Shake<SZ> {
    const RATE: usize = 200 - (SZ >> 2);
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            state: KeccakState::new(),
            ptr: 0,
            flipped: false,
        }
    }
    /// Inject some bytes into the engine.
    ///
    /// This function can be called repeatedly. If the engine is in output
    /// mode, then a panic is triggered.
    pub fn inject(&mut self, src: &[u8]) {
        assert!(!self.flipped);
        let mut ptr = self.ptr;
        let mut i = 0;
        while i < src.len() {
            let clen = core::cmp::min(src.len() - i, Self::RATE - ptr);
            for _ in 0..clen {
                self.state.0[ptr >> 3] ^= u64::from(src[i]) << ((ptr & 7) << 3);
                i += 1;
                ptr += 1;
            }
            if ptr == Self::RATE {
                self.state.process();
                ptr = 0;
            }
        }
        self.ptr = ptr;
    }
    /// Flip the engine from input to output mode.
    ///
    /// If the engine is already in output mode, then a panic is triggered.
    pub fn flip(&mut self) {
        assert!(!self.flipped);
        let i = self.ptr;
        self.state.0[i >> 3] ^= 0x1Fu64 << ((i & 7) << 3);
        let i = Self::RATE - 1;
        self.state.0[i >> 3] ^= 0x80u64 << ((i & 7) << 3);
        self.ptr = Self::RATE;
        self.flipped = true;
    }
    /// Extract some bytes from the engine.
    ///
    /// This function can be called repeatedly. If the engine is in input
    /// mode, then a panic is triggered.
    pub fn extract(&mut self, dst: &mut [u8]) {
        assert!(self.flipped);
        let mut ptr = self.ptr;
        let mut i = 0;
        while i < dst.len() {
            if ptr == Self::RATE {
                self.state.process();
                ptr = 0;
            }
            let clen = core::cmp::min(dst.len() - i, Self::RATE - ptr);
            for _ in 0..clen {
                dst[i] = self.state.0[ptr >> 3].to_le_bytes()[ptr & 7];
                i += 1;
                ptr += 1;
            }
        }
        self.ptr = ptr;
    }
}
/// PRNG based on SHAKE256.
///
/// This is just a wrapper SHAKE256 itself, with an extra buffer to speed
/// up common usage. 16-bit and 64-bit words are obtained from the
/// corresponding number of bytes, interpreted in little-endian order.
pub struct SHAKE256_PRNG {
    sh: SHAKE256,
    buf: [u8; 136],
    ptr: usize,
}
impl SHAKE256_PRNG {
    fn refill(&mut self) {
        self.sh.extract(&mut self.buf);
        self.ptr = 0;
    }
}
impl PRNG for SHAKE256_PRNG {
    fn new(seed: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        sh.flip();
        Self {
            sh,
            buf: [0u8; 136],
            ptr: 136,
        }
    }
    fn next_u8(&mut self) -> u8 {
        if self.ptr == self.buf.len() {
            self.refill();
        }
        let x = self.buf[self.ptr];
        self.ptr += 1;
        x
    }
    fn next_u16(&mut self) -> u16 {
        if self.ptr >= (self.buf.len() - 1) {
            let x = u16::from(self.next_u8());
            return x | (u16::from(self.next_u8()) << 8);
        }
        let x =
            u16::from_le_bytes(*<&[u8; 2]>::try_from(&self.buf[self.ptr..self.ptr + 2]).unwrap());
        self.ptr += 2;
        x
    }
    fn next_u64(&mut self) -> u64 {
        if self.ptr >= (self.buf.len() - 7) {
            let mut x = 0;
            for i in 0..8 {
                x |= u64::from(self.next_u8()) << (i << 3);
            }
            return x;
        }
        let x =
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&self.buf[self.ptr..self.ptr + 8]).unwrap());
        self.ptr += 8;
        x
    }
    fn zeroize(&mut self) {
        self.sh.state.0.zeroize();
        self.sh.ptr = 0;
        self.sh.flipped = false;
        self.buf.zeroize();
        self.ptr = 0;
    }
}
impl Drop for SHAKE256_PRNG {
    fn drop(&mut self) {
        <Self as PRNG>::zeroize(self);
    }
}

#[cfg(test)]
mod tests {
    use super::{PRNG, SHAKE256, SHAKE256_PRNG};
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    #[test]
    fn scalar_shake256_matches_independent_xof_across_rate_and_chunk_boundaries() {
        for length in [0, 1, 135, 136, 137, 271, 272, 273] {
            let input: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let mut reference = sha3::Shake256::default();
            reference.update(&input);
            let mut expected = [0_u8; 425];
            reference.finalize_xof().read(&mut expected);

            let mut whole = SHAKE256::new();
            whole.inject(&input);
            whole.flip();
            let mut actual = [0_u8; 425];
            whole.extract(&mut actual);
            assert_eq!(actual, expected, "whole input length {length}");

            let mut split = SHAKE256::new();
            for chunk in input.chunks(17) {
                split.inject(chunk);
            }
            split.flip();
            for chunk in actual.chunks_mut(13) {
                split.extract(chunk);
            }
            assert_eq!(actual, expected, "split input length {length}");
        }
    }

    #[test]
    fn buffered_prng_matches_independent_xof_at_every_word_and_rate_boundary() {
        let seed = b"Falcon-512 buffered SHAKE256 boundary control";
        let mut reference = sha3::Shake256::default();
        reference.update(seed);
        let mut expected = [0_u8; 2 * SHAKE256::RATE + 11];
        reference.finalize_xof().read(&mut expected);

        for offset in 0..=2 * SHAKE256::RATE {
            let mut generator = SHAKE256_PRNG::new(seed);
            for &byte in &expected[..offset] {
                assert_eq!(generator.next_u8(), byte, "prefix before offset {offset}");
            }
            assert_eq!(
                generator.next_u16(),
                u16::from_le_bytes(expected[offset..offset + 2].try_into().unwrap()),
                "16-bit word at offset {offset}",
            );
            assert_eq!(
                generator.next_u64(),
                u64::from_le_bytes(expected[offset + 2..offset + 10].try_into().unwrap()),
                "64-bit word after offset {offset}",
            );
            assert_eq!(
                generator.next_u8(),
                expected[offset + 10],
                "byte after mixed word reads at offset {offset}",
            );
        }
    }
}
