//! Test-only SHA-256 (FIPS 180-4) for the known-answer response digests.
//!
//! `PQClean` records the SHA-256 of each official known-answer response as
//! `nistkat-sha256`. This crate does not depend on a SHA-2 implementation, so the
//! known-answer tests of ML-KEM and ML-DSA use this module to hash the tracked
//! response files and compare them with those published values. It is compiled
//! for tests only, is not constant time and must not be used outside them.

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut schedule = [0u32; 64];
    for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }
    // Working variables a..h of FIPS 180-4, in that order.
    let mut working = *state;
    for (constant, word) in ROUND_CONSTANTS.iter().zip(schedule) {
        let [first, second, third, fourth, fifth, sixth, seventh, eighth] = working;
        let big_sigma1 = fifth.rotate_right(6) ^ fifth.rotate_right(11) ^ fifth.rotate_right(25);
        let choice = (fifth & sixth) ^ (!fifth & seventh);
        let temporary1 = eighth
            .wrapping_add(big_sigma1)
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(word);
        let big_sigma0 = first.rotate_right(2) ^ first.rotate_right(13) ^ first.rotate_right(22);
        let majority = (first & second) ^ (first & third) ^ (second & third);
        let temporary2 = big_sigma0.wrapping_add(majority);
        working = [
            temporary1.wrapping_add(temporary2),
            first,
            second,
            third,
            fourth.wrapping_add(temporary1),
            fifth,
            sixth,
            seventh,
        ];
    }
    for (value, add) in state.iter_mut().zip(working) {
        *value = value.wrapping_add(add);
    }
}

/// SHA-256 of `message` as 64 lowercase hexadecimal digits.
pub fn sha256_hex(message: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bits = u64::try_from(message.len()).expect("test message length fits u64") * 8;
    padded.extend_from_slice(&bits.to_be_bytes());
    let mut state = INITIAL_STATE;
    for block in padded.chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut out = String::with_capacity(64);
    for word in state {
        write!(out, "{word:08x}").expect("writing to a string cannot fail");
    }
    out
}

/// FIPS 180-4 examples: the empty message, `abc`, the 448-bit message and one
/// million repetitions of `a`, which crosses many blocks.
#[test]
fn sha256_matches_the_fips_180_4_examples() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        sha256_hex(&vec![b'a'; 1_000_000]),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}
