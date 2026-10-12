//! The proof (signature) byte layout of FAEST v3.0 section 9 at an arbitrary
//! witness length.
//!
//! A proof has a fixed length per row and witness length, no header and no length
//! prefixes. With `B = lambda / 8`, the fields in order:
//!
//! | # | field | bytes | encoding |
//! |---|---|---|---|
//! | 1 | `c_1 .. c_{tau-1}` | `(tau - 1) * ell / 8` | each an `ell`-bit string |
//! | 2 | `c_mult` | `n_mask * ceil(n_mult / 8)` | mask row `0` first, gate `e` at bit `e` of its row |
//! | 3 | `u~` | `4B` | four field elements |
//! | 4 | `d` | `ell / 8` | the masked witness |
//! | 5 | `a~_1 .. a~_{d_zk-1}` | `(d_zk - 1) * B` | field elements; `a~_0` is not sent |
//! | 6 | `decom_I` | `(tau * n_leafcom + T_open) * B` | hidden leaf commitments, node keys, zero padding |
//! | 7 | `chall_3` | `B` | top `w_grind` bits zero |
//! | 8 | `iv_pre` | 16 | |
//! | 9 | counter | 4 | little-endian |
//!
//! Bits are low bit first within bytes and field elements are little-endian
//! ([`crate::field`]). [`proof_bytes`] is the total, which equals
//! [`ProofParams::signature_bytes`].
//!
//! # Strict decoding
//!
//! [`decode`] accepts exactly one encoding of each proof:
//!
//! * the length must be exactly [`proof_bytes`]; there is no trailing data and no
//!   row detection;
//! * the bits of each `c_mult` row at or above `n_mult` must be zero;
//! * the top `w_grind` bits of `chall_3` must be zero;
//! * the number of node keys the hidden indices of `chall_3` need
//!   ([`bavc::opening_nodes`]) must not exceed `T_open`, and every byte of the
//!   opening after those keys must be zero.
//!
//! Every byte string of the right length is a field element and every counter is
//! allowed, so nothing else can be non-canonical. Decoding borrows from the input
//! and copies nothing. Everything in a proof is public.

use thiserror::Error;

use crate::{
    bavc::{self, BavcError},
    params::{IV_BYTES, ProofParams},
    vole::{corrections_bytes, mult_corrections_bytes},
};

/// Bytes of the counter at the end of a proof.
pub const COUNTER_BYTES: usize = 4;

/// The fields of a proof, in the order of the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    /// `c_1 .. c_{tau-1}`.
    Corrections,
    /// `c_mult`.
    MultCorrections,
    /// `u~`.
    UTilde,
    /// The masked witness `d`.
    MaskedWitness,
    /// `a~_1 .. a~_{d_zk-1}`.
    Coefficients,
    /// `decom_I`.
    Decommitment,
    /// `chall_3`.
    Challenge,
    /// `iv_pre`.
    IvPre,
    /// The counter.
    Counter,
}

impl Field {
    /// All fields in layout order.
    pub const ALL: [Self; 9] = [
        Self::Corrections,
        Self::MultCorrections,
        Self::UTilde,
        Self::MaskedWitness,
        Self::Coefficients,
        Self::Decommitment,
        Self::Challenge,
        Self::IvPre,
        Self::Counter,
    ];

    /// Length in bytes of the field in a proof for `params`.
    pub const fn bytes(self, params: &ProofParams) -> usize {
        let vole = params.vole();
        let lb = vole.lambda().bytes();
        match self {
            Self::Corrections => corrections_bytes(params),
            Self::MultCorrections => mult_corrections_bytes(vole),
            Self::UTilde => 4 * lb,
            Self::MaskedWitness => params.witness_bytes(),
            Self::Coefficients => (vole.d_zk() - 1) * lb,
            Self::Decommitment => bavc::decommitment_bytes(vole),
            Self::Challenge => lb,
            Self::IvPre => IV_BYTES,
            Self::Counter => COUNTER_BYTES,
        }
    }

    /// Offset in bytes of the field in a proof for `params`.
    pub const fn offset(self, params: &ProofParams) -> usize {
        let mut offset = 0;
        let mut index = 0;
        while index < self as usize {
            offset += Self::ALL[index].bytes(params);
            index += 1;
        }
        offset
    }
}

/// Length in bytes of every proof for `params`.
pub const fn proof_bytes(params: &ProofParams) -> usize {
    Field::Counter.offset(params) + COUNTER_BYTES
}

/// Errors of the proof codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodecError {
    /// The proof does not have the fixed length of the row and witness length.
    #[error("a proof for this row is {expected} bytes long, got {actual}")]
    InvalidLength {
        /// [`proof_bytes`].
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// A field handed to [`encode`] does not have its fixed length.
    #[error("{field:?} must be {expected} bytes long, got {actual}")]
    InvalidFieldLength {
        /// The field concerned.
        field: Field,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// A padding bit of `c_mult` or a padding byte of the opening is not zero.
    #[error("the padding of {field:?} is not zero")]
    NonZeroPadding {
        /// The field concerned.
        field: Field,
    },
    /// `chall_3` has a grinding bit set, or its hidden indices need more than
    /// `T_open` node keys.
    #[error("the challenge of the proof is not acceptable: {0}")]
    Challenge(BavcError),
}

/// The fields of one proof, borrowed from its bytes or from the prover's buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFields<'a> {
    /// `c_1 || ... || c_{tau-1}`.
    pub corrections: &'a [u8],
    /// `c_mult`.
    pub mult_corrections: &'a [u8],
    /// `u~`, four field elements.
    pub u_tilde: &'a [u8],
    /// The masked witness `d`.
    pub masked_witness: &'a [u8],
    /// `a~_1 || ... || a~_{d_zk-1}`.
    pub coefficients: &'a [u8],
    /// `decom_I`.
    pub decommitment: &'a [u8],
    /// `chall_3`.
    pub challenge: &'a [u8],
    /// `iv_pre`.
    pub iv_pre: &'a [u8; IV_BYTES],
    /// The grinding counter.
    pub counter: u32,
}

impl<'a> ProofFields<'a> {
    /// The byte fields in layout order, without the counter.
    fn slices(&self) -> [(Field, &'a [u8]); 8] {
        [
            (Field::Corrections, self.corrections),
            (Field::MultCorrections, self.mult_corrections),
            (Field::UTilde, self.u_tilde),
            (Field::MaskedWitness, self.masked_witness),
            (Field::Coefficients, self.coefficients),
            (Field::Decommitment, self.decommitment),
            (Field::Challenge, self.challenge),
            (Field::IvPre, self.iv_pre),
        ]
    }
}

/// Serialise a proof.
///
/// Only the field lengths are checked: the prover produces canonical padding by
/// construction, and [`decode`] is the strict direction.
///
/// # Errors
/// Returns [`CodecError::InvalidFieldLength`] naming the first field whose length
/// is not the one `params` fixes.
pub fn encode(params: &ProofParams, fields: &ProofFields<'_>) -> Result<Vec<u8>, CodecError> {
    let mut proof = Vec::with_capacity(proof_bytes(params));
    for (field, bytes) in fields.slices() {
        let expected = field.bytes(params);
        if bytes.len() != expected {
            return Err(CodecError::InvalidFieldLength {
                field,
                expected,
                actual: bytes.len(),
            });
        }
        proof.extend_from_slice(bytes);
    }
    proof.extend_from_slice(&fields.counter.to_le_bytes());
    Ok(proof)
}

/// Split the next `len` bytes off `rest`.
fn take<'a>(rest: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(len)?;
    *rest = tail;
    Some(head)
}

/// Parse a proof strictly (see the module documentation).
///
/// This is a verifier entry point: `proof` is untrusted.
///
/// # Errors
/// * [`CodecError::InvalidLength`] unless `proof` is exactly [`proof_bytes`] bytes
///   long;
/// * [`CodecError::NonZeroPadding`] for a non-zero padding bit of `c_mult` or a
///   non-zero byte of the opening after its last node key;
/// * [`CodecError::Challenge`] if `chall_3` has a grinding bit set
///   ([`BavcError::GrindingBitsSet`]) or needs more than `T_open` node keys
///   ([`BavcError::OpeningTooLarge`]).
pub fn decode<'a>(params: &ProofParams, proof: &'a [u8]) -> Result<ProofFields<'a>, CodecError> {
    let invalid = CodecError::InvalidLength {
        expected: proof_bytes(params),
        actual: proof.len(),
    };
    if proof.len() != proof_bytes(params) {
        return Err(invalid);
    }
    let mut rest = proof;
    let mut next = |field: Field| take(&mut rest, field.bytes(params)).ok_or(invalid);
    let corrections = next(Field::Corrections)?;
    let mult_corrections = next(Field::MultCorrections)?;
    let u_tilde = next(Field::UTilde)?;
    let masked_witness = next(Field::MaskedWitness)?;
    let coefficients = next(Field::Coefficients)?;
    let decommitment = next(Field::Decommitment)?;
    let challenge = next(Field::Challenge)?;
    let iv_pre: &[u8; IV_BYTES] = next(Field::IvPre)?.try_into().map_err(|_| invalid)?;
    let counter: [u8; COUNTER_BYTES] = next(Field::Counter)?.try_into().map_err(|_| invalid)?;
    if !rest.is_empty() {
        return Err(invalid);
    }

    let vole = params.vole();
    let n_mult = vole.n_mult();
    let row_bytes = n_mult.div_ceil(8);
    for row in mult_corrections.chunks_exact(row_bytes) {
        let padded = (n_mult..8 * row_bytes).any(|bit| (row[bit / 8] >> (bit % 8)) & 1 != 0);
        if padded {
            return Err(CodecError::NonZeroPadding {
                field: Field::MultCorrections,
            });
        }
    }

    let hidden = bavc::decode_challenge(vole, challenge).map_err(CodecError::Challenge)?;
    let nodes = bavc::opening_nodes(vole, &hidden).map_err(CodecError::Challenge)?;
    if nodes > vole.t_open() {
        return Err(CodecError::Challenge(BavcError::OpeningTooLarge {
            nodes,
            t_open: vole.t_open(),
        }));
    }
    let lb = vole.lambda().bytes();
    let used = (vole.tau() * vole.n_leafcom() + nodes) * lb;
    let padding = decommitment.get(used..).ok_or(invalid)?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(CodecError::NonZeroPadding {
            field: Field::Decommitment,
        });
    }

    Ok(ProofFields {
        corrections,
        mult_corrections,
        u_tilde,
        masked_witness,
        coefficients,
        decommitment,
        challenge,
        iv_pre,
        counter: u32::from_le_bytes(counter),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        FAEST_128F, FAEST_256F, FAEST_256S, FAEST_PARAMETER_SETS, SecurityLevel, VoleParams,
    };

    /// Offsets of `c_mult`, `u~`, `d`, `a~`, the hidden commitments (the start of
    /// `decom_I`), `chall_3`, `iv_pre`, the counter, and the total: the table of
    /// section 10 of the validated protocol description, in the order of
    /// [`FAEST_PARAMETER_SETS`].
    const OFFSETS: [[usize; 9]; 12] = [
        [1200, 1590, 1654, 1774, 1870, 4030, 4046, 4062, 4066],
        [1920, 2310, 2374, 2494, 2590, 5134, 5150, 5166, 5170],
        [3240, 3870, 3966, 4182, 4326, 9366, 9390, 9406, 9410],
        [4968, 5598, 5694, 5910, 6054, 11694, 11718, 11734, 11738],
        [5796, 6666, 6794, 7070, 7262, 16574, 16606, 16622, 16626],
        [8832, 9712, 9840, 10116, 10308, 20804, 20836, 20852, 20856],
        [800, 1190, 1254, 1334, 1430, 3430, 3446, 3462, 3466],
        [1280, 1670, 1734, 1814, 1910, 4134, 4150, 4166, 4170],
        [2160, 2790, 2886, 3030, 3174, 7830, 7854, 7870, 7874],
        [3456, 4086, 4182, 4326, 4470, 9774, 9798, 9814, 9818],
        [4704, 5574, 5702, 5926, 6118, 14502, 14534, 14550, 14554],
        [7168, 8048, 8176, 8400, 8592, 18032, 18064, 18080, 18084],
    ];

    #[test]
    fn the_size_agrees_with_the_signature_formula_on_the_twelve_rows() {
        for (set, offsets) in FAEST_PARAMETER_SETS.iter().zip(OFFSETS) {
            let params = set.proof();
            assert_eq!(proof_bytes(params), set.signature_bytes(), "{}", set.name());
            assert_eq!(proof_bytes(params) * 8, params.signature_bits());
            assert_eq!(Field::Corrections.offset(params), 0);
            let actual: Vec<usize> = Field::ALL[1..]
                .iter()
                .map(|field| field.offset(params))
                .chain([proof_bytes(params)])
                .collect();
            assert_eq!(actual, offsets, "{}", set.name());
            let total: usize = Field::ALL.iter().map(|field| field.bytes(params)).sum();
            assert_eq!(total, proof_bytes(params));
        }
    }

    #[test]
    fn the_size_follows_the_witness_length_on_the_ballot_rows() {
        // Section 6.6 of the ballot profile: fast and small rows at the registration
        // and vote witness lengths.
        for (set, ell, expected) in [
            (FAEST_256F, 35_840, 159_588),
            (FAEST_256F, 35_904, 159_852),
            (FAEST_256S, 35_840, 109_114),
            (FAEST_256S, 35_904, 109_290),
        ] {
            let params = ProofParams::new(*set.vole(), ell, 2 * ell).expect("valid row");
            assert_eq!(proof_bytes(&params), expected);
            assert_eq!(proof_bytes(&params), params.signature_bytes());
        }
    }

    /// A row whose `n_mult` is not a multiple of 8, so `c_mult` has padding bits.
    fn padded_row() -> ProofParams {
        let vole = VoleParams::new(SecurityLevel::L128, 17, 8, 108, 3, 7, 309).expect("valid row");
        ProofParams::new(vole, 256, 300).expect("valid row")
    }

    /// A well-formed proof body: every field filled with a distinct byte, an
    /// all-zero challenge (hidden index 0 in every vector) and an opening with
    /// exactly the node keys that challenge needs.
    fn sample(params: &ProofParams) -> Vec<u8> {
        let vole = params.vole();
        let lb = vole.lambda().bytes();
        let nodes = bavc::opening_nodes(vole, &vec![0u16; vole.tau()]).expect("valid pattern");
        assert!(nodes < vole.t_open(), "the sample needs padding to test");
        let mut decommitment = vec![0x66u8; (vole.tau() * vole.n_leafcom() + nodes) * lb];
        decommitment.resize(Field::Decommitment.bytes(params), 0);
        let mut mult = vec![0u8; Field::MultCorrections.bytes(params)];
        for row in mult.chunks_exact_mut(vole.n_mult().div_ceil(8)) {
            for bit in 0..vole.n_mult() {
                row[bit / 8] |= 1 << (bit % 8);
            }
        }
        encode(
            params,
            &ProofFields {
                corrections: &vec![0x11; Field::Corrections.bytes(params)],
                mult_corrections: &mult,
                u_tilde: &vec![0x33; 4 * lb],
                masked_witness: &vec![0x44; params.witness_bytes()],
                coefficients: &vec![0x55; 6 * lb],
                decommitment: &decommitment,
                challenge: &vec![0u8; lb],
                iv_pre: &[0x88; 16],
                counter: 0x0403_0201,
            },
        )
        .expect("valid fields")
    }

    #[test]
    fn decoding_inverts_encoding_field_by_field() {
        for params in [*FAEST_128F.proof(), *FAEST_256F.proof(), padded_row()] {
            let proof = sample(&params);
            assert_eq!(proof.len(), proof_bytes(&params));
            let fields = decode(&params, &proof).expect("canonical");
            assert_eq!(encode(&params, &fields).expect("valid fields"), proof);
            assert_eq!(fields.counter, 0x0403_0201);
            assert_eq!(proof[proof.len() - 4..], [1, 2, 3, 4]);
            assert_eq!(fields.iv_pre, &[0x88; 16]);
            for (field, bytes) in fields.slices() {
                let offset = field.offset(&params);
                assert_eq!(bytes, &proof[offset..offset + field.bytes(&params)]);
            }
            assert!(fields.corrections.iter().all(|&byte| byte == 0x11));
            assert!(fields.u_tilde.iter().all(|&byte| byte == 0x33));
            assert!(fields.masked_witness.iter().all(|&byte| byte == 0x44));
            assert!(fields.coefficients.iter().all(|&byte| byte == 0x55));
        }
    }

    #[test]
    fn every_other_length_is_rejected() {
        let params = *FAEST_128F.proof();
        let proof = sample(&params);
        let expected = proof.len();
        let mut longer = proof.clone();
        longer.push(0);
        for candidate in [&proof[..expected - 1], &longer[..], &proof[..0]] {
            assert_eq!(
                decode(&params, candidate),
                Err(CodecError::InvalidLength {
                    expected,
                    actual: candidate.len()
                })
            );
        }
        // A proof of another row or witness length is a proof of the wrong length.
        let other = ProofParams::new(*params.vole(), 968, 1200).expect("valid row");
        assert!(matches!(
            decode(&other, &proof),
            Err(CodecError::InvalidLength { .. })
        ));
    }

    #[test]
    fn encoding_checks_every_field_length() {
        let params = *FAEST_128F.proof();
        let proof = sample(&params);
        let fields = decode(&params, &proof).expect("canonical");
        let short = |bytes: &'static [u8]| bytes;
        for field in &Field::ALL[..7] {
            let mut broken = fields;
            let slot = match field {
                Field::Corrections => &mut broken.corrections,
                Field::MultCorrections => &mut broken.mult_corrections,
                Field::UTilde => &mut broken.u_tilde,
                Field::MaskedWitness => &mut broken.masked_witness,
                Field::Coefficients => &mut broken.coefficients,
                Field::Decommitment => &mut broken.decommitment,
                _ => &mut broken.challenge,
            };
            *slot = short(&[0u8; 3]);
            assert_eq!(
                encode(&params, &broken),
                Err(CodecError::InvalidFieldLength {
                    field: *field,
                    expected: field.bytes(&params),
                    actual: 3
                })
            );
        }
    }

    #[test]
    fn non_canonical_padding_and_challenges_are_rejected() {
        let params = padded_row();
        let vole = params.vole();
        let proof = sample(&params);
        let lb = 16;

        // A padding bit of each `c_mult` row.
        let row_bytes = vole.n_mult().div_ceil(8);
        for row in 0..vole.n_mask() {
            for bit in vole.n_mult()..8 * row_bytes {
                let mut broken = proof.clone();
                let at = Field::MultCorrections.offset(&params) + row * row_bytes + bit / 8;
                broken[at] |= 1 << (bit % 8);
                assert_eq!(
                    decode(&params, &broken),
                    Err(CodecError::NonZeroPadding {
                        field: Field::MultCorrections
                    })
                );
            }
        }

        // Every padding byte of the opening, first and last included.
        let nodes = bavc::opening_nodes(vole, &vec![0u16; vole.tau()]).expect("valid pattern");
        let start = Field::Decommitment.offset(&params) + (vole.tau() * 3 + nodes) * lb;
        let end = Field::Challenge.offset(&params);
        assert!(start < end);
        for at in [start, start + 1, end - 1] {
            let mut broken = proof.clone();
            broken[at] = 1;
            assert_eq!(
                decode(&params, &broken),
                Err(CodecError::NonZeroPadding {
                    field: Field::Decommitment
                })
            );
        }
        // The byte before the padding is a node key byte: any value is canonical.
        let mut changed = proof.clone();
        changed[start - 1] ^= 0xff;
        assert!(decode(&params, &changed).is_ok());

        // Each grinding bit.
        for bit in vole.n_delta()..128 {
            let mut broken = proof.clone();
            broken[end + bit / 8] |= 1 << (bit % 8);
            assert_eq!(
                decode(&params, &broken),
                Err(CodecError::Challenge(BavcError::GrindingBitsSet))
            );
        }

        // A challenge whose pattern needs more keys than the row allows.
        let tight = VoleParams::new(SecurityLevel::L128, 17, 8, nodes - 1, 3, 7, 309)
            .and_then(|vole| ProofParams::new(vole, 256, 300))
            .expect("valid row");
        let mut body = sample(&params);
        body.drain(start - lb..end);
        assert_eq!(body.len(), proof_bytes(&tight));
        assert_eq!(
            decode(&tight, &body),
            Err(CodecError::Challenge(BavcError::OpeningTooLarge {
                nodes,
                t_open: nodes - 1
            }))
        );
    }

    #[test]
    fn take_splits_without_panicking() {
        let bytes = [1u8, 2, 3];
        let mut rest = &bytes[..];
        assert_eq!(take(&mut rest, 2), Some(&bytes[..2]));
        assert_eq!(take(&mut rest, 2), None);
        assert_eq!(take(&mut rest, 1), Some(&bytes[2..]));
        assert_eq!(take(&mut rest, 0), Some(&bytes[3..]));
    }
}
