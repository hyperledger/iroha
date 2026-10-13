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
//! Every byte string of the right length is a field element and, in the FAEST
//! construction, every counter is allowed, so nothing else can be non-canonical.
//! Decoding borrows from the input and copies nothing. Everything in a proof is
//! public.
//!
//! # Extended construction
//!
//! The functions ending in `_as` take a [`Construction`]; [`Field::bytes`],
//! [`Field::offset`], [`proof_bytes`], [`encode`] and [`decode`] are the FAEST
//! construction. The extended layout ([`crate::variant`], `lambda = 256` and
//! `n_leafcom = 3` only) differs in three places:
//!
//! * field 6 holds 112-byte leaf commitments: `112 * tau + 32 * T_open` bytes;
//! * a field `salt` of 32 bytes follows `iv_pre` and precedes the counter
//!   ([`Field::Salt`], [`Field::EXTENDED`]);
//! * the counter must not exceed [`crate::variant::EXTENDED_LAST_COUNTER`].
//!   [`decode_as`] checks this right after the length, before any other field
//!   is looked at ([`CodecError::CounterOutOfRange`]).
//!
//! The layouts cannot be mixed: a [`ProofFields`] with a salt encodes in the
//! extended layout only, one without in the FAEST layout only
//! ([`CodecError::SaltMismatch`]), and decoding yields a salt exactly in the
//! extended layout.

use thiserror::Error;

use crate::{
    bavc::{self, BavcError},
    params::{IV_BYTES, ProofParams},
    variant::{Binding, Construction, SALT_BYTES, VariantError},
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
    /// The salt of the extended construction; empty in the FAEST layout.
    Salt,
    /// The counter.
    Counter,
}

impl Field {
    /// The fields of the extended layout in order: those of [`Self::ALL`] with
    /// [`Self::Salt`] before the counter.
    pub const EXTENDED: [Self; 10] = [
        Self::Corrections,
        Self::MultCorrections,
        Self::UTilde,
        Self::MaskedWitness,
        Self::Coefficients,
        Self::Decommitment,
        Self::Challenge,
        Self::IvPre,
        Self::Salt,
        Self::Counter,
    ];

    /// The fields of the FAEST layout in order.
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

    /// The fields of the layout of `construction` in order: [`Self::ALL`] or
    /// [`Self::EXTENDED`].
    pub const fn all(construction: Construction) -> &'static [Self] {
        match construction {
            Construction::Faest => &Self::ALL,
            Construction::Extended => &Self::EXTENDED,
        }
    }

    /// Length in bytes of the field in a FAEST-construction proof for `params`.
    pub const fn bytes(self, params: &ProofParams) -> usize {
        self.bytes_as(Construction::Faest, params)
    }

    /// Offset in bytes of the field in a FAEST-construction proof for `params`.
    pub const fn offset(self, params: &ProofParams) -> usize {
        self.offset_as(Construction::Faest, params)
    }

    /// Length in bytes of the field in a proof of `construction` for `params`.
    /// [`Self::Salt`] is empty in the FAEST layout.
    pub const fn bytes_as(self, construction: Construction, params: &ProofParams) -> usize {
        let vole = params.vole();
        let lb = vole.lambda().bytes();
        match self {
            Self::Corrections => corrections_bytes(params),
            Self::MultCorrections => mult_corrections_bytes(vole),
            Self::UTilde => 4 * lb,
            Self::MaskedWitness => params.witness_bytes(),
            Self::Coefficients => (vole.d_zk() - 1) * lb,
            Self::Decommitment => bavc::decommitment_bytes_as(construction, vole),
            Self::Challenge => lb,
            Self::IvPre => IV_BYTES,
            Self::Salt => construction.salt_bytes(),
            Self::Counter => COUNTER_BYTES,
        }
    }

    /// Offset in bytes of the field in a proof of `construction` for `params`.
    /// In the FAEST layout the empty [`Self::Salt`] sits at the counter's offset.
    pub const fn offset_as(self, construction: Construction, params: &ProofParams) -> usize {
        let mut offset = 0;
        let mut index = 0;
        while index < self as usize {
            offset += Self::EXTENDED[index].bytes_as(construction, params);
            index += 1;
        }
        offset
    }
}

/// Length in bytes of every FAEST-construction proof for `params`.
pub const fn proof_bytes(params: &ProofParams) -> usize {
    proof_bytes_as(Construction::Faest, params)
}

/// Length in bytes of every proof of `construction` for `params`. For the
/// extended construction this is the FAEST length plus 32 bytes of salt and 16
/// bytes per vector (meaningful on the rows [`Construction::check_row`] accepts).
pub const fn proof_bytes_as(construction: Construction, params: &ProofParams) -> usize {
    Field::Counter.offset_as(construction, params) + COUNTER_BYTES
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
    /// The counter is above the last one the construction allows.
    #[error("the counter {counter} is above the last allowed counter {last}")]
    CounterOutOfRange {
        /// The counter of the proof.
        counter: u32,
        /// The last counter the construction allows.
        last: u32,
    },
    /// The fields handed to [`encode_as`] carry a salt in the FAEST layout or
    /// none in the extended layout.
    #[error("the {construction:?} layout was given fields with salt present = {salted}")]
    SaltMismatch {
        /// The layout asked for.
        construction: Construction,
        /// Whether the fields carry a salt.
        salted: bool,
    },
    /// The extended layout was requested on a row where it is not defined.
    #[error(transparent)]
    Variant(#[from] VariantError),
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
    /// The salt: present exactly in the extended layout.
    pub salt: Option<&'a [u8; SALT_BYTES]>,
    /// The grinding counter.
    pub counter: u32,
}

impl<'a> ProofFields<'a> {
    /// The construction of the proof and the salt it binds, as the VOLE and
    /// transcript layers take them.
    pub const fn binding(&self) -> Binding<'a> {
        match self.salt {
            None => Binding::Faest,
            Some(salt) => Binding::Extended { salt },
        }
    }

    /// The byte fields in layout order, without the counter. The salt slot is
    /// empty when there is none.
    fn slices(&self) -> [(Field, &'a [u8]); 9] {
        let salt: &'a [u8] = match self.salt {
            None => &[],
            Some(salt) => salt,
        };
        [
            (Field::Corrections, self.corrections),
            (Field::MultCorrections, self.mult_corrections),
            (Field::UTilde, self.u_tilde),
            (Field::MaskedWitness, self.masked_witness),
            (Field::Coefficients, self.coefficients),
            (Field::Decommitment, self.decommitment),
            (Field::Challenge, self.challenge),
            (Field::IvPre, self.iv_pre),
            (Field::Salt, salt),
        ]
    }
}

/// Serialise a proof in the FAEST layout; see [`encode_as`].
///
/// # Errors
/// As [`encode_as`].
pub fn encode(params: &ProofParams, fields: &ProofFields<'_>) -> Result<Vec<u8>, CodecError> {
    encode_as(Construction::Faest, params, fields)
}

/// Serialise a proof in the layout of `construction`.
///
/// Only the field lengths, the presence of the salt and the counter range are
/// checked: the prover produces canonical padding by construction, and
/// [`decode_as`] is the strict direction.
///
/// # Errors
/// * [`CodecError::Variant`] where the construction is not defined;
/// * [`CodecError::SaltMismatch`] unless `fields` has a salt exactly in the
///   extended layout;
/// * [`CodecError::CounterOutOfRange`] for a counter the construction does not
///   allow;
/// * [`CodecError::InvalidFieldLength`] naming the first field whose length is
///   not the one `params` fixes.
pub fn encode_as(
    construction: Construction,
    params: &ProofParams,
    fields: &ProofFields<'_>,
) -> Result<Vec<u8>, CodecError> {
    construction.check_row(params.vole())?;
    if fields.binding().construction() != construction {
        return Err(CodecError::SaltMismatch {
            construction,
            salted: fields.salt.is_some(),
        });
    }
    check_counter(construction, fields.counter)?;
    let mut proof = Vec::with_capacity(proof_bytes_as(construction, params));
    for (field, bytes) in fields.slices() {
        let expected = field.bytes_as(construction, params);
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

/// The counter rule of `construction`.
const fn check_counter(construction: Construction, counter: u32) -> Result<(), CodecError> {
    let last = construction.last_counter();
    if counter > last {
        return Err(CodecError::CounterOutOfRange { counter, last });
    }
    Ok(())
}

/// Split the next `len` bytes off `rest`.
fn take<'a>(rest: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(len)?;
    *rest = tail;
    Some(head)
}

/// Parse a proof in the FAEST layout strictly; see [`decode_as`].
///
/// # Errors
/// As [`decode_as`].
pub fn decode<'a>(params: &ProofParams, proof: &'a [u8]) -> Result<ProofFields<'a>, CodecError> {
    decode_as(Construction::Faest, params, proof)
}

/// Parse a proof in the layout of `construction` strictly (see the module
/// documentation).
///
/// This is a verifier entry point: `proof` is untrusted. The checks run in the
/// order of the list below, so a proof of the right length whose counter is out
/// of range is rejected for its counter whatever else it contains, and before
/// the opening pattern is examined.
///
/// # Errors
/// * [`CodecError::Variant`] where the construction is not defined;
/// * [`CodecError::InvalidLength`] unless `proof` is exactly [`proof_bytes_as`]
///   bytes long;
/// * [`CodecError::CounterOutOfRange`] if the counter is above
///   [`Construction::last_counter`];
/// * [`CodecError::NonZeroPadding`] for a non-zero padding bit of `c_mult` or a
///   non-zero byte of the opening after its last node key;
/// * [`CodecError::Challenge`] if `chall_3` has a grinding bit set
///   ([`BavcError::GrindingBitsSet`]) or needs more than `T_open` node keys
///   ([`BavcError::OpeningTooLarge`]).
pub fn decode_as<'a>(
    construction: Construction,
    params: &ProofParams,
    proof: &'a [u8],
) -> Result<ProofFields<'a>, CodecError> {
    construction.check_row(params.vole())?;
    let invalid = CodecError::InvalidLength {
        expected: proof_bytes_as(construction, params),
        actual: proof.len(),
    };
    if proof.len() != proof_bytes_as(construction, params) {
        return Err(invalid);
    }
    let mut rest = proof;
    let mut next =
        |field: Field| take(&mut rest, field.bytes_as(construction, params)).ok_or(invalid);
    let corrections = next(Field::Corrections)?;
    let mult_corrections = next(Field::MultCorrections)?;
    let u_tilde = next(Field::UTilde)?;
    let masked_witness = next(Field::MaskedWitness)?;
    let coefficients = next(Field::Coefficients)?;
    let decommitment = next(Field::Decommitment)?;
    let challenge = next(Field::Challenge)?;
    let iv_pre: &[u8; IV_BYTES] = next(Field::IvPre)?.try_into().map_err(|_| invalid)?;
    let salt = next(Field::Salt)?;
    let salt: Option<&[u8; SALT_BYTES]> = match construction {
        Construction::Faest => None,
        Construction::Extended => Some(salt.try_into().map_err(|_| invalid)?),
    };
    let counter: [u8; COUNTER_BYTES] = next(Field::Counter)?.try_into().map_err(|_| invalid)?;
    if !rest.is_empty() {
        return Err(invalid);
    }
    let counter = u32::from_le_bytes(counter);
    check_counter(construction, counter)?;

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
    let used = vole.tau() * bavc::leaf_commitment_bytes(construction, vole) + nodes * lb;
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
        salt,
        counter,
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
                salt: None,
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

    #[test]
    fn the_extended_sizes_are_those_of_the_decision() {
        let extended = Construction::Extended;
        for (set, ell, expected) in [
            (FAEST_256F, 35_840, 160_148),
            (FAEST_256S, 35_840, 109_498),
            (FAEST_256F, 53_504, 233_012),
            (FAEST_256S, 53_504, 158_074),
        ] {
            let params = ProofParams::new(*set.vole(), ell, 2 * ell).expect("valid row");
            assert_eq!(proof_bytes_as(extended, &params), expected);
            let total: usize = Field::EXTENDED
                .iter()
                .map(|field| field.bytes_as(extended, &params))
                .sum();
            assert_eq!(total, expected);
            // 32 bytes of salt and 16 bytes per vector above the FAEST layout.
            assert_eq!(
                expected,
                proof_bytes(&params) + 32 + 16 * params.vole().tau()
            );
            assert_eq!(
                proof_bytes_as(Construction::Faest, &params),
                params.signature_bytes()
            );
        }

        // Field by field on the fast row at the registration witness length.
        let params = ProofParams::new(*FAEST_256F.vole(), 35_840, 72_576).expect("valid row");
        let table = [
            (Field::Corrections, 143_360),
            (Field::MultCorrections, 880),
            (Field::UTilde, 128),
            (Field::MaskedWitness, 4_480),
            (Field::Coefficients, 192),
            (Field::Decommitment, 11_024),
            (Field::Challenge, 32),
            (Field::IvPre, 16),
            (Field::Salt, 32),
            (Field::Counter, 4),
        ];
        let mut offset = 0;
        for ((field, bytes), listed) in table.into_iter().zip(Field::EXTENDED) {
            assert_eq!(field, listed);
            assert_eq!(field.bytes_as(extended, &params), bytes, "{field:?}");
            assert_eq!(field.offset_as(extended, &params), offset, "{field:?}");
            offset += bytes;
        }
        assert_eq!(offset, 160_148);
        // The small row differs in the row-dependent fields only.
        let small = ProofParams::new(*FAEST_256S.vole(), 35_840, 72_576).expect("valid row");
        assert_eq!(Field::Corrections.bytes_as(extended, &small), 94_080);
        assert_eq!(Field::MultCorrections.bytes_as(extended, &small), 870);
        assert_eq!(Field::Decommitment.bytes_as(extended, &small), 9_664);

        assert_eq!(Field::all(Construction::Faest), &Field::ALL[..]);
        assert_eq!(Field::all(extended), &Field::EXTENDED[..]);
        // In the FAEST layout the salt is empty and nothing moves.
        assert_eq!(Field::Salt.bytes(&params), 0);
        assert_eq!(Field::Salt.offset(&params), Field::Counter.offset(&params));
        assert_eq!(Field::Decommitment.bytes(&params), 10_496);
    }

    /// [`sample`] in the layout of `construction`, with `counter`.
    fn sample_as(construction: Construction, params: &ProofParams, counter: u32) -> Vec<u8> {
        let vole = params.vole();
        let lb = vole.lambda().bytes();
        let nodes = bavc::opening_nodes(vole, &vec![0u16; vole.tau()]).expect("valid pattern");
        assert!(nodes < vole.t_open(), "the sample needs padding to test");
        let used = vole.tau() * bavc::leaf_commitment_bytes(construction, vole) + nodes * lb;
        let mut decommitment = vec![0x66u8; used];
        decommitment.resize(Field::Decommitment.bytes_as(construction, params), 0);
        let salt = [0x99u8; SALT_BYTES];
        encode_as(
            construction,
            params,
            &ProofFields {
                corrections: &vec![0x11; Field::Corrections.bytes(params)],
                mult_corrections: &vec![0x22; Field::MultCorrections.bytes(params)],
                u_tilde: &vec![0x33; 4 * lb],
                masked_witness: &vec![0x44; params.witness_bytes()],
                coefficients: &vec![0x55; 6 * lb],
                decommitment: &decommitment,
                challenge: &vec![0u8; lb],
                iv_pre: &[0x88; 16],
                salt: (construction == Construction::Extended).then_some(&salt),
                counter,
            },
        )
        .expect("valid fields")
    }

    #[test]
    fn extended_proofs_round_trip_and_the_layouts_do_not_mix() {
        let extended = Construction::Extended;
        for set in [FAEST_256F, FAEST_256S] {
            let params = ProofParams::new(*set.vole(), 256, 300).expect("valid row");
            let proof = sample_as(extended, &params, 0x000f_0201);
            assert_eq!(proof.len(), proof_bytes_as(extended, &params));
            let fields = decode_as(extended, &params, &proof).expect("canonical");
            assert_eq!(fields.salt, Some(&[0x99u8; SALT_BYTES]));
            assert_eq!(
                fields.binding(),
                Binding::Extended {
                    salt: &[0x99; SALT_BYTES]
                }
            );
            assert_eq!(fields.counter, 0x000f_0201);
            assert_eq!(fields.iv_pre, &[0x88; 16]);
            assert_eq!(
                fields.decommitment.len(),
                112 * params.vole().tau() + 32 * params.vole().t_open()
            );
            assert_eq!(encode_as(extended, &params, &fields), Ok(proof.clone()));
            // The salt field is where the layout says.
            let at = Field::Salt.offset_as(extended, &params);
            assert_eq!(proof[at..at + 32], [0x99; 32]);
            assert_eq!(at + 32, Field::Counter.offset_as(extended, &params));

            // An extended proof is not a FAEST-layout proof and the reverse.
            assert_eq!(
                decode(&params, &proof),
                Err(CodecError::InvalidLength {
                    expected: proof_bytes(&params),
                    actual: proof.len()
                })
            );
            let faest = sample_as(Construction::Faest, &params, 7);
            assert_eq!(
                decode_as(extended, &params, &faest),
                Err(CodecError::InvalidLength {
                    expected: proof.len(),
                    actual: faest.len()
                })
            );
            let plain = decode(&params, &faest).expect("canonical");
            assert_eq!(plain.salt, None);
            assert_eq!(plain.binding(), Binding::Faest);
            assert_eq!(
                encode_as(extended, &params, &plain),
                Err(CodecError::SaltMismatch {
                    construction: extended,
                    salted: false
                })
            );
            assert_eq!(
                encode(&params, &fields),
                Err(CodecError::SaltMismatch {
                    construction: Construction::Faest,
                    salted: true
                })
            );
            // Padding of the 112-byte-commitment opening is still checked.
            let mut padded = proof.clone();
            padded[Field::Challenge.offset_as(extended, &params) - 1] = 1;
            assert_eq!(
                decode_as(extended, &params, &padded),
                Err(CodecError::NonZeroPadding {
                    field: Field::Decommitment
                })
            );
            for cut in [proof.len() - 1, proof.len() + 1] {
                let mut wrong = proof.clone();
                wrong.resize(cut, 0);
                assert!(matches!(
                    decode_as(extended, &params, &wrong),
                    Err(CodecError::InvalidLength { .. })
                ));
            }
        }
        let other = ProofParams::new(*FAEST_128F.vole(), 256, 300).expect("valid row");
        let unsupported = CodecError::Variant(VariantError::UnsupportedLevel { lambda: 128 });
        assert_eq!(decode_as(extended, &other, &[]), Err(unsupported));
        let faest = sample_as(Construction::Faest, &other, 7);
        let fields = decode(&other, &faest).expect("canonical");
        assert_eq!(encode_as(extended, &other, &fields), Err(unsupported));
    }

    #[test]
    fn the_counter_limit_is_checked_before_the_rest_of_the_proof() {
        let extended = Construction::Extended;
        assert_eq!(check_counter(Construction::Faest, u32::MAX), Ok(()));
        assert_eq!(check_counter(extended, 0x000f_ffff), Ok(()));
        let above = |counter| CodecError::CounterOutOfRange {
            counter,
            last: 0x000f_ffff,
        };
        assert_eq!(
            check_counter(extended, 0x0010_0000),
            Err(above(0x0010_0000))
        );

        let params = ProofParams::new(*FAEST_256F.vole(), 256, 300).expect("valid row");
        let at_limit = sample_as(extended, &params, 0x000f_ffff);
        assert_eq!(
            decode_as(extended, &params, &at_limit).map(|fields| fields.counter),
            Ok(0x000f_ffff)
        );
        let set_counter = |proof: &[u8], counter: u32| {
            let mut proof = proof.to_vec();
            let at = proof.len() - COUNTER_BYTES;
            proof[at..].copy_from_slice(&counter.to_le_bytes());
            proof
        };
        for counter in [0x0010_0000, 0x0100_0000, u32::MAX] {
            let proof = set_counter(&at_limit, counter);
            assert_eq!(decode_as(extended, &params, &proof), Err(above(counter)));
        }
        // A body that is rejected for another reason when the counter is in range
        // is rejected for the counter when it is not: the counter comes first.
        let challenge = Field::Challenge.offset_as(extended, &params);
        let mut grinding = at_limit.clone();
        grinding[challenge + 31] = 0x80;
        let mut padding = at_limit;
        padding[challenge - 1] = 1;
        for (body, expected) in [
            (&grinding, CodecError::Challenge(BavcError::GrindingBitsSet)),
            (
                &padding,
                CodecError::NonZeroPadding {
                    field: Field::Decommitment,
                },
            ),
        ] {
            assert_eq!(decode_as(extended, &params, body), Err(expected));
            let late = set_counter(body, 0x0010_0000);
            assert_eq!(decode_as(extended, &params, &late), Err(above(0x0010_0000)));
        }
        // In the FAEST layout every counter is allowed.
        let faest = sample_as(Construction::Faest, &params, u32::MAX);
        assert_eq!(
            decode(&params, &faest).map(|fields| fields.counter),
            Ok(u32::MAX)
        );
        // The prover's side refuses to write such a counter.
        let in_range = sample_as(extended, &params, 5);
        let fields = decode_as(extended, &params, &in_range).expect("canonical");
        let mut late = fields;
        late.counter = 0x0010_0000;
        assert_eq!(encode_as(extended, &params, &late), Err(above(0x0010_0000)));
    }
}
