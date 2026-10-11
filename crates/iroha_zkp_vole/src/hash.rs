//! The random-oracle functions `H_0 .. H_5` of FAEST v3.0 (section 3.3).
//!
//! Every function is SHAKE128 for `lambda = 128` and SHAKE256 for `lambda` of 192 or
//! 256, applied to the message followed by **one domain-separation byte**:
//!
//! | function | domain byte | output bits | use |
//! |---|---|---|---|
//! | `H_0` | `0x00` | `3 * lambda` | leaf-hash key `uhash` from `iv` |
//! | `H_1` | `0x01` | `2 * lambda` | vector commitments |
//! | `H_2^0` | `0x08` | `2 * lambda` | `mu` |
//! | `H_2^1` | `0x09` | `8 * lambda + 64` | `chall_1` |
//! | `H_2^2` | `0x0a` | `3 * lambda + 64` | `chall_2` |
//! | `H_2^3` | `0x0b` | `lambda` | `chall_3` |
//! | `H_3` | `0x03` | `lambda + 128` | signing randomness `(r, iv_pre)` |
//! | `H_4` | `0x04` | `128` | `iv` |
//! | `H_5` | `0x05` | `n_mask` | CRT gate labels |
//!
//! [`Hasher`] absorbs the message in pieces and checks the output length of the
//! selected function; [`h5`] is the one-shot gate-label hash. [`Xof`] is the bare
//! sponge without domain separation.
//!
//! The sponge is implemented here on the Keccak-f\[1600\] permutation of the `keccak`
//! crate. Input is added (XOR) directly into the 200-byte state and output is read directly
//! from it, so there is no separate block buffer: the state is the only copy of
//! absorbed input and of squeezed output, and [`Xof`] and [`XofOutput`] erase it on
//! drop. The permutation has no secret-dependent branches or table lookups.

use core::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::{IV_BYTES, MAX_D_ZK, SecurityLevel};

/// Largest `n_mask` [`h5`] can return in its 16-bit result. It is `MAX_D_ZK + 3`, so
/// every row [`crate::params::VoleParams::new`] accepts can be evaluated.
pub const MAX_H5_BITS: usize = MAX_D_ZK + 3;
const _: () = assert!(MAX_H5_BITS == u16::BITS as usize);

/// Errors of the hash functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HashError {
    /// The output buffer does not have the length the selected function defines.
    #[error("{oracle:?} outputs {expected} bytes at this security level, got a buffer of {actual}")]
    InvalidOutputLength {
        /// The function being finalized.
        oracle: Oracle,
        /// Defined output length in bytes.
        expected: usize,
        /// Supplied buffer length in bytes.
        actual: usize,
    },
    /// An input does not have the length the function defines.
    #[error("expected an input of {expected} bytes, got {actual}")]
    InvalidInputLength {
        /// Defined input length in bytes.
        expected: usize,
        /// Supplied input length in bytes.
        actual: usize,
    },
    /// `H_5` was asked for zero bits or more than [`MAX_H5_BITS`].
    #[error("H_5 output of {bits} bits is outside [1, {MAX_H5_BITS}]")]
    InvalidH5Bits {
        /// Requested output length in bits.
        bits: usize,
    },
}

/// The fixed-output-length random-oracle functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Oracle {
    /// `H_0`: `iv` to the `3 * lambda`-bit leaf-hash key.
    H0,
    /// `H_1`: collision-resistant hash to `2 * lambda` bits.
    H1,
    /// `H_2^0`: `mu`, `2 * lambda` bits.
    H2Mu,
    /// `H_2^1`: `chall_1`, `8 * lambda + 64` bits.
    H2Chall1,
    /// `H_2^2`: `chall_2`, `3 * lambda + 64` bits.
    H2Chall2,
    /// `H_2^3`: `chall_3`, `lambda` bits.
    H2Chall3,
    /// `H_3`: `(r, iv_pre)`, `lambda + 128` bits.
    H3,
    /// `H_4`: `iv`, 128 bits.
    H4,
}

impl Oracle {
    /// All functions, in the order of the module table.
    pub const ALL: [Self; 8] = [
        Self::H0,
        Self::H1,
        Self::H2Mu,
        Self::H2Chall1,
        Self::H2Chall2,
        Self::H2Chall3,
        Self::H3,
        Self::H4,
    ];

    /// The domain-separation byte appended after the message.
    pub const fn domain_byte(self) -> u8 {
        match self {
            Self::H0 => 0,
            Self::H1 => 1,
            Self::H2Mu => 8,
            Self::H2Chall1 => 9,
            Self::H2Chall2 => 10,
            Self::H2Chall3 => 11,
            Self::H3 => 3,
            Self::H4 => 4,
        }
    }

    /// The output length in bytes at `level`.
    pub const fn output_bytes(self, level: SecurityLevel) -> usize {
        let lambda = level.bytes();
        match self {
            Self::H0 => 3 * lambda,
            Self::H1 | Self::H2Mu => 2 * lambda,
            Self::H2Chall1 => 8 * lambda + 8,
            Self::H2Chall2 => 3 * lambda + 8,
            Self::H2Chall3 => lambda,
            Self::H3 => lambda + IV_BYTES,
            Self::H4 => IV_BYTES,
        }
    }
}

/// Domain-separation byte of `H_5`.
pub const H5_DOMAIN_BYTE: u8 = 5;

/// Bytes of the Keccak-f\[1600\] state.
const STATE_LANES: usize = 25;
/// SHAKE128 rate in bytes.
const SHAKE128_RATE: usize = 168;
/// SHAKE256 rate in bytes.
const SHAKE256_RATE: usize = 136;
/// SHAKE domain-separation suffix together with the first padding bit.
const SHAKE_PADDING: u8 = 0x1f;

/// XOR `data` into the rate portion of `state` starting at byte `pos`. The caller
/// keeps `pos + data.len()` within the rate, so every lane index is in range.
fn xor_into(state: &mut [u64; STATE_LANES], pos: usize, data: &[u8]) {
    for (offset, byte) in data.iter().enumerate() {
        let at = pos + offset;
        if let Some(lane) = state.get_mut(at / 8) {
            *lane ^= u64::from(*byte) << (8 * (at % 8));
        }
    }
}

/// Copy `out.len()` bytes of the rate portion of `state` starting at byte `pos`.
fn read_from(state: &[u64; STATE_LANES], pos: usize, out: &mut [u8]) {
    for (offset, byte) in out.iter_mut().enumerate() {
        let at = pos + offset;
        if let Some(lane) = state.get(at / 8) {
            *byte = lane.to_le_bytes()[at % 8];
        }
    }
}

/// SHAKE128 (`lambda = 128`) or SHAKE256 (`lambda` of 192 or 256) without domain
/// separation.
///
/// Input is added (XOR) straight into the Keccak state, so the state is the only copy of
/// absorbed data; it is erased on drop.
#[derive(Clone)]
pub struct Xof {
    state: [u64; STATE_LANES],
    rate: usize,
    /// Bytes absorbed into the current block, always below `rate`.
    pos: usize,
}

impl fmt::Debug for Xof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xof").finish_non_exhaustive()
    }
}

impl Zeroize for Xof {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.pos = 0;
    }
}

impl Drop for Xof {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Xof {}

impl Xof {
    /// An empty sponge for `level`.
    pub fn new(level: SecurityLevel) -> Self {
        let rate = match level {
            SecurityLevel::L128 => SHAKE128_RATE,
            SecurityLevel::L192 | SecurityLevel::L256 => SHAKE256_RATE,
        };
        Self {
            state: [0; STATE_LANES],
            rate,
            pos: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (self.rate - self.pos).min(data.len());
            let (head, tail) = data.split_at(take);
            xor_into(&mut self.state, self.pos, head);
            self.pos += take;
            if self.pos == self.rate {
                keccak::f1600(&mut self.state);
                self.pos = 0;
            }
            data = tail;
        }
    }

    /// Absorb `value` as four little-endian bytes (`BitDec(value, 32)`).
    pub fn update_u32_le(&mut self, value: u32) {
        self.update(&value.to_le_bytes());
    }

    /// Finish absorbing and return the output stream.
    pub fn finalize(mut self) -> XofOutput {
        xor_into(&mut self.state, self.pos, &[SHAKE_PADDING]);
        xor_into(&mut self.state, self.rate - 1, &[0x80]);
        keccak::f1600(&mut self.state);
        XofOutput {
            state: self.state,
            rate: self.rate,
            pos: 0,
        }
    }
}

/// The output stream of a finalized [`Xof`].
///
/// Output is read straight from the Keccak state, which is erased on drop.
pub struct XofOutput {
    state: [u64; STATE_LANES],
    rate: usize,
    /// Bytes already read from the current block, at most `rate`.
    pos: usize,
}

impl fmt::Debug for XofOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XofOutput").finish_non_exhaustive()
    }
}

impl Zeroize for XofOutput {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.pos = 0;
    }
}

impl Drop for XofOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for XofOutput {}

impl XofOutput {
    /// Squeeze the next `out.len()` bytes.
    pub fn squeeze(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.pos == self.rate {
                keccak::f1600(&mut self.state);
                self.pos = 0;
            }
            let take = (self.rate - self.pos).min(out.len());
            let (head, tail) = out.split_at_mut(take);
            read_from(&self.state, self.pos, head);
            self.pos += take;
            out = tail;
        }
    }
}

/// Incremental evaluation of one of the functions of [`Oracle`].
#[derive(Debug, Clone)]
pub struct Hasher {
    xof: Xof,
    oracle: Oracle,
    level: SecurityLevel,
}

impl Hasher {
    /// Start evaluating `oracle` at `level`.
    pub fn new(level: SecurityLevel, oracle: Oracle) -> Self {
        Self {
            xof: Xof::new(level),
            oracle,
            level,
        }
    }

    /// The function being evaluated.
    pub fn oracle(&self) -> Oracle {
        self.oracle
    }

    /// The output length in bytes that [`Self::finalize`] requires.
    pub fn output_bytes(&self) -> usize {
        self.oracle.output_bytes(self.level)
    }

    /// Absorb the next piece of the message.
    pub fn update(&mut self, data: &[u8]) {
        self.xof.update(data);
    }

    /// Absorb `value` as four little-endian bytes (`BitDec(value, 32)`).
    pub fn update_u32_le(&mut self, value: u32) {
        self.xof.update_u32_le(value);
    }

    /// Append the domain byte and write the output of the function to `out`.
    ///
    /// # Errors
    /// Returns [`HashError::InvalidOutputLength`] unless `out` has exactly the
    /// output length of the function at this security level.
    pub fn finalize(self, out: &mut [u8]) -> Result<(), HashError> {
        let expected = self.output_bytes();
        if out.len() != expected {
            return Err(HashError::InvalidOutputLength {
                oracle: self.oracle,
                expected,
                actual: out.len(),
            });
        }
        self.finalize_xof().squeeze(out);
        Ok(())
    }

    /// Append the domain byte and return the unbounded output stream. The protocol
    /// reads exactly [`Self::output_bytes`] bytes of it.
    pub fn finalize_xof(mut self) -> XofOutput {
        self.xof.update(&[self.oracle.domain_byte()]);
        self.xof.finalize()
    }
}

/// One-shot evaluation of `oracle` at `level` on `message`.
///
/// # Errors
/// As [`Hasher::finalize`].
pub fn hash(
    level: SecurityLevel,
    oracle: Oracle,
    message: &[u8],
    out: &mut [u8],
) -> Result<(), HashError> {
    let mut hasher = Hasher::new(level, oracle);
    hasher.update(message);
    hasher.finalize(out)
}

/// `H_5(iv, e, L)`: the `bits`-bit hash of the label `L` of CRT gate `e`.
///
/// The input is `iv || BitDec(e, 32) || L || 0x05` with `L` of `lambda / 8` bytes.
/// Two bytes are squeezed and read as a little-endian integer; output bit `m` (the
/// bit used for mask `m`) is bit `m` of the result, and bits at or above `bits` are
/// zero. The protocol uses `bits = n_mask`.
///
/// # Errors
/// Returns [`HashError::InvalidInputLength`] unless `label` is `lambda / 8` bytes
/// and [`HashError::InvalidH5Bits`] unless `bits` is in `[1, MAX_H5_BITS]`.
pub fn h5(
    level: SecurityLevel,
    iv: &[u8; IV_BYTES],
    gate: u32,
    label: &[u8],
    bits: usize,
) -> Result<u16, HashError> {
    if label.len() != level.bytes() {
        return Err(HashError::InvalidInputLength {
            expected: level.bytes(),
            actual: label.len(),
        });
    }
    if bits == 0 || bits > MAX_H5_BITS {
        return Err(HashError::InvalidH5Bits { bits });
    }
    let mut xof = Xof::new(level);
    xof.update(iv);
    xof.update_u32_le(gate);
    xof.update(label);
    xof.update(&[H5_DOMAIN_BYTE]);
    let mut squeezed = [0u8; 2];
    xof.finalize().squeeze(&mut squeezed);
    let value = u16::from_le_bytes(squeezed) & (u16::MAX >> (u16::BITS as usize - bits));
    squeezed.zeroize();
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(level: SecurityLevel, message: &[u8], len: usize) -> Vec<u8> {
        let mut xof = Xof::new(level);
        xof.update(message);
        let mut out = vec![0u8; len];
        xof.finalize().squeeze(&mut out);
        out
    }

    #[test]
    fn xof_is_shake128_or_shake256_by_level() {
        // FIPS 202 known answers for the empty message.
        assert_eq!(
            raw(SecurityLevel::L128, &[], 16),
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
                0x85, 0x3e
            ]
        );
        let shake256 = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24,
        ];
        assert_eq!(raw(SecurityLevel::L192, &[], 16), shake256);
        assert_eq!(raw(SecurityLevel::L256, &[], 16), shake256);
    }

    fn reference(level: SecurityLevel, message: &[u8], len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut out = vec![0u8; len];
        match level {
            SecurityLevel::L128 => {
                let mut sponge = sha3::Shake128::default();
                sponge.update(message);
                sponge.finalize_xof().read(&mut out);
            }
            SecurityLevel::L192 | SecurityLevel::L256 => {
                let mut sponge = sha3::Shake256::default();
                sponge.update(message);
                sponge.finalize_xof().read(&mut out);
            }
        }
        out
    }

    #[test]
    fn sponge_matches_an_independent_shake_at_every_block_boundary() {
        // Message lengths around zero, one and two rate blocks (the padding byte and
        // the final 0x80 coincide at rate - 1), split and squeezed at odd offsets.
        let message: Vec<u8> = (0..2 * SHAKE128_RATE + 9)
            .map(|i| u8::try_from((i * 151 + 7) % 251).expect("below 251"))
            .collect();
        for level in SecurityLevel::ALL {
            let rate = Xof::new(level).rate;
            for len in 0..message.len() {
                let near_boundary = len % rate <= 2 || len % rate >= rate - 2;
                if !near_boundary && len % 29 != 0 {
                    continue;
                }
                let out_len = 3 * rate + 5;
                let expected = reference(level, &message[..len], out_len);
                assert_eq!(raw(level, &message[..len], out_len), expected, "{len}");

                let mut xof = Xof::new(level);
                for chunk in message[..len].chunks(13) {
                    xof.update(chunk);
                }
                let mut output = xof.finalize();
                let mut pieces = vec![0u8; out_len];
                for chunk in pieces.chunks_mut(rate - 1) {
                    output.squeeze(chunk);
                }
                assert_eq!(pieces, expected, "{len}");
            }
        }
    }

    #[test]
    fn lane_helpers_use_little_endian_byte_order() {
        let mut state = [0u64; STATE_LANES];
        xor_into(&mut state, 7, &[0xab, 0xcd]);
        assert_eq!(state[0], 0xab00_0000_0000_0000);
        assert_eq!(state[1], 0xcd);
        xor_into(&mut state, 7, &[0xab]);
        assert_eq!(state[0], 0);
        let mut out = [0u8; 3];
        read_from(&state, 7, &mut out);
        assert_eq!(out, [0, 0xcd, 0]);
        // Out-of-range positions are ignored instead of panicking.
        xor_into(&mut state, 8 * STATE_LANES, &[1]);
        read_from(&state, 8 * STATE_LANES, &mut out[..1]);
        assert_eq!(out[0], 0);
    }

    #[test]
    fn sponge_state_is_erased() {
        fn erases_on_drop<T: ZeroizeOnDrop>() {}
        for level in SecurityLevel::ALL {
            let mut xof = Xof::new(level);
            xof.update(b"secret key material");
            assert_ne!(xof.state, [0; STATE_LANES]);
            let mut output = xof.clone().finalize();
            xof.zeroize();
            assert_eq!((xof.state, xof.pos), ([0; STATE_LANES], 0));
            let mut block = [0u8; 40];
            output.squeeze(&mut block);
            assert_ne!(output.state, [0; STATE_LANES]);
            output.zeroize();
            assert_eq!((output.state, output.pos), ([0; STATE_LANES], 0));
            erases_on_drop::<Xof>();
            erases_on_drop::<XofOutput>();
        }
    }

    #[test]
    fn xof_absorbs_and_squeezes_incrementally() {
        for level in SecurityLevel::ALL {
            let whole = raw(level, b"abcdefgh\x78\x56\x34\x12", 100);
            let mut xof = Xof::new(level);
            xof.update(b"abc");
            xof.update(b"");
            xof.update(b"defgh");
            xof.update_u32_le(0x1234_5678);
            let mut output = xof.clone().finalize();
            let mut pieces = vec![0u8; 100];
            let (head, tail) = pieces.split_at_mut(37);
            output.squeeze(head);
            output.squeeze(tail);
            assert_eq!(pieces, whole);
            assert_eq!(format!("{xof:?}"), "Xof { .. }");
            assert_eq!(format!("{output:?}"), "XofOutput { .. }");
        }
    }

    #[test]
    fn domain_bytes_and_output_lengths_follow_the_specification() {
        let table: [(Oracle, u8, [usize; 3]); 8] = [
            (Oracle::H0, 0, [48, 72, 96]),
            (Oracle::H1, 1, [32, 48, 64]),
            (Oracle::H2Mu, 8, [32, 48, 64]),
            (Oracle::H2Chall1, 9, [136, 200, 264]),
            (Oracle::H2Chall2, 10, [56, 80, 104]),
            (Oracle::H2Chall3, 11, [16, 24, 32]),
            (Oracle::H3, 3, [32, 40, 48]),
            (Oracle::H4, 4, [16, 16, 16]),
        ];
        for ((oracle, domain, lengths), listed) in table.into_iter().zip(Oracle::ALL) {
            assert_eq!(oracle, listed);
            assert_eq!(oracle.domain_byte(), domain);
            assert_eq!(SecurityLevel::ALL.map(|l| oracle.output_bytes(l)), lengths);
        }
        assert_eq!(H5_DOMAIN_BYTE, 5);
    }

    #[test]
    fn hasher_appends_one_domain_byte_after_the_message() {
        for level in SecurityLevel::ALL {
            for oracle in Oracle::ALL {
                let mut hasher = Hasher::new(level, oracle);
                assert_eq!(hasher.oracle(), oracle);
                assert_eq!(hasher.output_bytes(), oracle.output_bytes(level));
                hasher.update(b"mess");
                hasher.update(b"age");
                hasher.update_u32_le(7);
                let mut out = vec![0u8; hasher.output_bytes()];
                hasher.clone().finalize(&mut out).expect("exact length");
                let mut message = b"message\x07\x00\x00\x00".to_vec();
                message.push(oracle.domain_byte());
                assert_eq!(out, raw(level, &message, out.len()));

                let mut stream = vec![0u8; out.len() + 9];
                hasher.finalize_xof().squeeze(&mut stream);
                assert_eq!(stream[..out.len()], out[..]);

                let mut one_shot = vec![0u8; out.len()];
                hash(level, oracle, b"message\x07\x00\x00\x00", &mut one_shot)
                    .expect("exact length");
                assert_eq!(one_shot, out);
            }
        }
    }

    #[test]
    fn functions_are_domain_separated() {
        for level in SecurityLevel::ALL {
            let mut prefixes: Vec<Vec<u8>> = Oracle::ALL
                .iter()
                .map(|oracle| {
                    let mut stream = [0u8; 16];
                    let mut hasher = Hasher::new(level, *oracle);
                    hasher.update(b"same message");
                    hasher.finalize_xof().squeeze(&mut stream);
                    stream.to_vec()
                })
                .collect();
            prefixes.sort();
            prefixes.dedup();
            assert_eq!(prefixes.len(), Oracle::ALL.len(), "{level:?}");
        }
    }

    #[test]
    fn wrong_output_lengths_are_rejected() {
        for level in SecurityLevel::ALL {
            for oracle in Oracle::ALL {
                let expected = oracle.output_bytes(level);
                for actual in [0, expected - 1, expected + 1] {
                    let mut out = vec![0u8; actual];
                    assert_eq!(
                        hash(level, oracle, b"m", &mut out),
                        Err(HashError::InvalidOutputLength {
                            oracle,
                            expected,
                            actual
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn h5_layout_and_bit_order() {
        let iv = [0x11u8; 16];
        for level in SecurityLevel::ALL {
            let label = vec![0x22u8; level.bytes()];
            let gate = 0x0403_0201;
            let mut message = iv.to_vec();
            message.extend_from_slice(&[1, 2, 3, 4]);
            message.extend_from_slice(&label);
            message.push(5);
            let squeezed = raw(level, &message, 2);
            let full = u16::from_le_bytes([squeezed[0], squeezed[1]]);
            assert_eq!(h5(level, &iv, gate, &label, 16), Ok(full));
            assert_eq!(h5(level, &iv, gate, &label, 10), Ok(full & 0x03ff));
            assert_eq!(h5(level, &iv, gate, &label, 1), Ok(full & 1));
            // Output bit m is bit m mod 8 of squeezed byte m / 8.
            let ten = h5(level, &iv, gate, &label, 10).expect("valid call");
            for m in 0..10 {
                assert_eq!((ten >> m) & 1, u16::from((squeezed[m / 8] >> (m % 8)) & 1));
            }
            assert_ne!(
                h5(level, &iv, gate + 1, &label, 16),
                h5(level, &iv, gate, &label, 16)
            );
        }
    }

    #[test]
    fn h5_rejects_bad_arguments() {
        let iv = [0u8; 16];
        assert_eq!(
            h5(SecurityLevel::L128, &iv, 0, &[0; 24], 10),
            Err(HashError::InvalidInputLength {
                expected: 16,
                actual: 24
            })
        );
        assert_eq!(
            h5(SecurityLevel::L192, &iv, 0, &[0; 24], 0),
            Err(HashError::InvalidH5Bits { bits: 0 })
        );
        assert_eq!(
            h5(SecurityLevel::L256, &iv, 0, &[0; 32], 17),
            Err(HashError::InvalidH5Bits { bits: 17 })
        );
        assert_eq!(MAX_H5_BITS, 16);
        assert!(h5(SecurityLevel::L256, &iv, 0, &[0; 32], MAX_H5_BITS).is_ok());
    }
}
