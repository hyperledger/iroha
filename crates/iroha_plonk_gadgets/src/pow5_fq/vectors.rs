//! Pinned RP57 Fq permutation vectors.
//!
//! Each vector is a full width-3 state before and after one RP57 Pow5
//! permutation over Fq, written as canonical 32-byte little-endian hex (the
//! `to_repr` encoding of `fixtures/native_prover/kats_v1.json`).
//!
//! # Provenance
//!
//! The vectors were computed by an independent plain Python implementation
//! of the permutation (four full, 57 partial and four full rounds; add the
//! round constants, `x^5` on every word or on word 0, multiply by the MDS
//! matrix) over the `poseidon_constants.fq` table of `kats_v1.json`, the
//! vendored `halo2-base` `OptimizedPoseidonSpec::<Fq, 3, 2>` constants. The
//! same program first reproduced every challenge of the Pallas (`ep`)
//! `squeeze_only` and `scalars` scripts of `poseidon_transcript` and every
//! `kagemusha_v1_poseidon.fq` domain-hash vector. They are pinned here so
//! that the in-circuit lane, the native [`iroha_pasta::poseidon::permute`]
//! and any later Fq transcript chip are compared with the same known
//! answers at the permutation level, not only through the sponge.
//!
//! The inputs cover the zero state, the raw sponge state `[2^64, 0, 0]`,
//! small words, `q - 1`, the Fp modulus `p` and its neighbours (canonical in
//! Fq because `p < q`), powers of two and three pseudo-random states (SHA-256
//! of `"pow5_fq/<vector>/<word>"`, reduced mod `q`).

use iroha_pasta::{Fq, poseidon::WIDTH};

/// One RP57 Fq permutation known answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rp57FqVector {
    /// What the input exercises.
    pub label: &'static str,
    /// The state entering the permutation (little-endian hex words).
    pub input: [&'static str; WIDTH],
    /// The state leaving the permutation (little-endian hex words).
    pub output: [&'static str; WIDTH],
}

impl Rp57FqVector {
    /// The input and output states, or `None` when a word is not 64 hex
    /// digits of a canonical Fq element.
    #[must_use]
    pub fn decode(&self) -> Option<([Fq; WIDTH], [Fq; WIDTH])> {
        Some((decode_state(&self.input)?, decode_state(&self.output)?))
    }
}

/// Decodes three little-endian hex words.
///
/// Returns `None` when a word is not 64 hex digits of a canonical Fq
/// element.
#[must_use]
pub fn decode_state(words: &[&str; WIDTH]) -> Option<[Fq; WIDTH]> {
    let [a, b, c] = words;
    Some([decode_word(a)?, decode_word(b)?, decode_word(c)?])
}

/// Decodes one little-endian hex word, or `None` when it is not 64 hex
/// digits of a canonical Fq element.
#[must_use]
pub fn decode_word(text: &str) -> Option<Fq> {
    use ff::PrimeField as _;

    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut repr = [0u8; 32];
    for (byte, pair) in repr.iter_mut().zip(digits.chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Option::from(Fq::from_repr(repr))
}

/// The state after eight chained permutations of the zero state.
pub const RP57_FQ_ZERO_CHAIN8: [&str; WIDTH] = [
    "a0e3cee665283c211247a354d7947d8e46133e09e1bc68c565037c6aeab4dd06",
    "4438d967f8584f5c89ac946613cb04cb782a17a36495dd959f159fe6da11e522",
    "27865579bccedd9f0cea4740b4a92a9b20cb85935d6ee04dcec75bdd22afd60d",
];

/// The pinned RP57 Fq permutation known answers (see the module
/// documentation for their provenance).
pub const RP57_FQ_PERMUTATION_VECTORS: [Rp57FqVector; 9] = [
    Rp57FqVector {
        label: "zero state",
        input: [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        output: [
            "17391c34ce2a1d1655cfca308ffa3132712e63566c50f950b1fcb18831301804",
            "74cc3735d1cc77a4e47b4bcc89942a12ed2222a7a6e895b013d2abf02f7d9b08",
            "3b05a7348612134a78c49b89770f10a061245bb50841d0a703e9e8556a867426",
        ],
    },
    Rp57FqVector {
        label: "raw sponge initial state [2^64, 0, 0]",
        input: [
            "0000000000000000010000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        output: [
            "9392a649cb5acb10043c32f06386fd6318212e8c4b49e66792af099d2a2d2b03",
            "116c6330721aa58689a00965c1d1ae0fc42a615bf536a62a80915442b3535336",
            "b36ce51251cd5352ab774192c0a6f9634e08b8eed9ca1adf0a133c921e3e541a",
        ],
    },
    Rp57FqVector {
        label: "small words [1, 2, 3]",
        input: [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0200000000000000000000000000000000000000000000000000000000000000",
            "0300000000000000000000000000000000000000000000000000000000000000",
        ],
        output: [
            "36e2cc1f2bd43be4f611edc651fc89bc706ec5da6fd2a240243ffa4367dc610a",
            "d5b7cd8d20e08c4f78c43191d8a2801e197a852e7569b7b849d12918e0c39621",
            "93211cf2ac1a2523d0dc91915406a1986e78900c46d89fb02ceeb3ceb0899137",
        ],
    },
    Rp57FqVector {
        label: "q - 1 in every word",
        input: [
            "0000000021eb468cdda89409fc98462200000000000000000000000000000040",
            "0000000021eb468cdda89409fc98462200000000000000000000000000000040",
            "0000000021eb468cdda89409fc98462200000000000000000000000000000040",
        ],
        output: [
            "323dfb68fcf0765497592128fb9c93db8a0b0efa7a978f2e41763a00931d160f",
            "026e30c7450fbba8306e605aa1f181067957143f01fcbd009b0394765ac98938",
            "6e0276252f2a7d0a92cf507668af08c9516e9679b435c2c2bbbbc20091d95032",
        ],
    },
    Rp57FqVector {
        label: "the Fp modulus p (canonical in Fq, q > p) and p - 1, p + 1",
        input: [
            "01000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "00000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "02000000ed302d991bf94c09fc98462200000000000000000000000000000040",
        ],
        output: [
            "80ae1b7d3fc515addf44ae894e5fc88b69e0d21d97f3867de2252d7e715b481b",
            "80d4eaf3630f220d89c8d09ebf9df218408b7edd93eba300a0457295168b322b",
            "cc6c68ccffb68d39274799de984c01d9a10196f58c04a826e75e3aaf1fa9da11",
        ],
    },
    Rp57FqVector {
        label: "2^254, 2^128 - 1, 2^64",
        input: [
            "0000000000000000000000000000000000000000000000000000000000000040",
            "ffffffffffffffffffffffffffffffff00000000000000000000000000000000",
            "0000000000000000010000000000000000000000000000000000000000000000",
        ],
        output: [
            "1bc7168c2b4836a2729f200d4124c17a87cd3e4d8b9316c01cf178e385041f2c",
            "f36af48ec48cfd8f6a73a658cb65bbc224fd4dce58a12751ed4ec331c3bc6618",
            "7bdeded82e03258bde06a8a800cf296e1e54f2efba07398097568b0245fcd108",
        ],
    },
    Rp57FqVector {
        label: "sha256 counter words 0",
        input: [
            "18cef412106bea7d27425749e50a668d758894e4b55179c2f9a00baec60a443f",
            "50ee26140ebc970ee9e7c7dc711194d5375a7ffe51c4d144885fa1dd09360a38",
            "933387284d3ce75fa1d8d87e83dd6a19b886e879b1a92e0d427955c3242aca3a",
        ],
        output: [
            "952711e8a22271103db7525d362c2936a8f30e2c89c436c9fb7ed19b530a4e09",
            "e657a4cca619bccd88cc8b88000394614c12c71c11ef17c6c15a5b6c3f4eab02",
            "ffdb7b7946d4ce4af7857443fc216007501c45b000396329958dd92b8f10ca31",
        ],
    },
    Rp57FqVector {
        label: "sha256 counter words 1",
        input: [
            "a5e1137c114c4d48e4c29551f275cc5e791d9204a6edda46926dc4e130162113",
            "cb82675e8905523319a789a4dc34ce3af6327c2d115b65988ce48d39fda1231f",
            "0c93218789b696b081dad5619d4414438ee761fbb7ee20e0d2bbe164b39f941f",
        ],
        output: [
            "5afe5da58bc5cce2e3c26cf2563f865ef071aedfdafa76eecfde0ad4c6bc451c",
            "c546743db028fe267156900117a120fdbdb5646ce191aefb9d36be322b81c501",
            "25282227681353d79debac74238317c9a599cead46a536fbc92ccd2408771f05",
        ],
    },
    Rp57FqVector {
        label: "sha256 counter words 2",
        input: [
            "a4dd64a0503d222ed61b45af66a00bdf9e8ea86181d3e49e6ddb8ba1e3adb307",
            "b0eb3398a5de49ab82e57dc73aaf374017b26cbf7bf3696849847b9aaf43250e",
            "250a9e5523747444082ad667aefeed2d8f81789256a10015e04595bff08a9a25",
        ],
        output: [
            "1fd73be951855a9edeb1c19d3e1dd57fe243104309fb977c24ece757aedecc39",
            "ce37c05d1ab9f07868913c7f183332c38285df461d6428fc4cda3276bfe3f623",
            "722ac6a926d693a261883c99fdde231309a0e5752d5d4f86abb094bcee05d91c",
        ],
    },
];

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use iroha_pasta::poseidon::permute;

    use super::*;

    #[test]
    fn every_vector_decodes_and_is_the_native_permutation() {
        for vector in RP57_FQ_PERMUTATION_VECTORS {
            let (input, output) = vector.decode().expect(vector.label);
            let mut state = input;
            permute(&mut state);
            assert_eq!(state, output, "{}", vector.label);
        }
        let mut state = [Fq::ZERO; WIDTH];
        for _ in 0..8 {
            permute(&mut state);
        }
        assert_eq!(Some(state), decode_state(&RP57_FQ_ZERO_CHAIN8));
    }

    #[test]
    fn decoding_is_strict() {
        let zero = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(decode_word(zero), Some(Fq::ZERO));
        // q itself and the all-ones word are not canonical.
        let q = "0100000021eb468cdda89409fc98462200000000000000000000000000000040";
        assert_eq!(decode_word(q), None);
        assert_eq!(decode_word(&"f".repeat(64)), None);
        // q - 1 is.
        let q_minus_one = "0000000021eb468cdda89409fc98462200000000000000000000000000000040";
        assert_eq!(decode_word(q_minus_one), Some(-Fq::ONE));
        // Wrong lengths and non-hex digits.
        assert_eq!(decode_word(&zero[..62]), None);
        assert_eq!(decode_word(&format!("{zero}00")), None);
        assert_eq!(decode_word(&format!("g{}", &zero[1..])), None);
        assert_eq!(decode_word(&format!("+{}", &zero[1..])), None);
        // Upper-case digits are accepted.
        assert_eq!(
            decode_word(&format!("0A{}", &zero[2..])),
            Some(Fq::from(10u64))
        );
        let bad = Rp57FqVector {
            label: "bad",
            input: [zero, zero, q],
            output: [zero; WIDTH],
        };
        assert_eq!(bad.decode(), None);
        assert_eq!(
            decode_state(&[zero, q_minus_one, zero]),
            Some([Fq::ZERO, -Fq::ONE, Fq::ZERO])
        );
    }
}
