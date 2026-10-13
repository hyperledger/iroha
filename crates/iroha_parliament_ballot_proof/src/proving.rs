//! What the two relations share on the way to the backend: the 80-byte proving
//! tape, the errors, and the calls into the backend's prover and verifier
//! (evaluation record sections 6.6 and 6.7).
//!
//! ```text
//! r      = tape[0..32]      // backend root seed
//! iv_pre = tape[32..48]
//! pad    = tape[48..80]     // witness positions [0, 256)
//! ```
//!
//! The tape is supplied by the caller, who owns the random-number generator: this
//! crate draws no randomness and has no deterministic, secret-derived or
//! zero-filled fallback. A tape is consumed by one proving call and erased on
//! every path out of it. There is no `H3` call; the prover tries the counters
//! `0 ..= 0xffff_ffff` in order and never wraps.

use iroha_zkp_vole::{
    field::Gf256,
    hash::{Hasher, Oracle},
    proof::{self, ProofError},
    quicksilver::Relation,
    randomness::Tape,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    credential::CredentialSecret,
    framing::FramingError,
    keccak_relation::{STATE_BYTES, evaluate},
    layout::{GROUPS, PERMUTATION_OFFSETS, SECRET_OFFSET},
    profile::{LEVEL, Profile, ProfileError, Role, Row},
    sealed_list::ListError,
};

/// Bytes of a proving tape.
pub const TAPE_BYTES: usize = 80;
/// Bytes of `mu`.
pub const MU_BYTES: usize = 64;
/// Bytes of the backend root seed `r`.
const ROOT_BYTES: usize = 32;
/// Bytes of `iv_pre`.
const IV_PRE_BYTES: usize = 16;
/// Bytes of the pad.
pub const PAD_BYTES: usize = 32;

/// The 80 fresh random bytes of one proof invocation. **Secret.**
///
/// Held on the heap, erased on drop, not `Clone`: a tape proves once. A caller
/// that retries after any error draws an entirely new tape.
pub struct ProvingTape(Box<[u8; TAPE_BYTES]>);

impl core::fmt::Debug for ProvingTape {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProvingTape(<redacted>)")
    }
}

impl Drop for ProvingTape {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ProvingTape {}

impl ProvingTape {
    /// A tape whose 80 bytes `fill` writes in place from the caller's fallible
    /// cryptographic random-number generator.
    ///
    /// # Errors
    /// The error of `fill`: an entropy failure produces no tape and therefore no
    /// proof. The partially written buffer is erased.
    pub fn fill_with<E>(
        fill: impl FnOnce(&mut [u8; TAPE_BYTES]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut tape = Self(Box::new([0u8; TAPE_BYTES]));
        fill(&mut tape.0)?;
        Ok(tape)
    }

    /// The tape with the bytes `bytes`. For reproducible tests: the caller's copy
    /// is not erased by this crate.
    pub fn from_bytes(bytes: &[u8; TAPE_BYTES]) -> Self {
        let mut tape = Self(Box::new([0u8; TAPE_BYTES]));
        tape.0.copy_from_slice(bytes);
        tape
    }

    /// The pad, `tape[48..80]`: witness coordinate `j` is bit `j mod 8` of pad
    /// byte `j div 8`.
    pub(crate) fn pad(&self) -> &[u8] {
        &self.0[ROOT_BYTES + IV_PRE_BYTES..]
    }

    /// The backend tape `(r, iv_pre)`; an erasing copy.
    fn backend(&self) -> Result<Tape, ProveError> {
        let mut iv_pre = [0u8; IV_PRE_BYTES];
        iv_pre.copy_from_slice(&self.0[ROOT_BYTES..ROOT_BYTES + IV_PRE_BYTES]);
        Tape::explicit(LEVEL, &self.0[..ROOT_BYTES], &iv_pre).map_err(|_| {
            ProveError::Backend(ProofError::InvalidLength {
                input: proof::Input::Root,
                expected: LEVEL.bytes(),
                actual: ROOT_BYTES,
            })
        })
    }
}

/// Why a public statement is malformed. Nothing was proved or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StatementError {
    /// The list is not a sealed list.
    #[error(transparent)]
    List(#[from] ListError),
    /// The stated size `S` is not the number of list entries.
    #[error("the statement declares S = {declared} and carries {actual} list entries")]
    ListLength {
        /// `S` of the statement.
        declared: u16,
        /// Entries carried.
        actual: usize,
    },
    /// The stated list digest `R` is not the digest of the list for the stated
    /// body.
    #[error("R is not the digest of the list")]
    ListDigest,
    /// The vote byte is not 0 (Aye), 1 (Nay) or 2 (Abstain).
    #[error("the vote byte must be 0, 1 or 2, got {value}")]
    VoteValue {
        /// The byte supplied.
        value: u8,
    },
    /// A frame could not be built from the statement.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// The row's descriptor could not be compiled (a backend without its tables;
    /// not caused by the statement).
    #[error(transparent)]
    Profile(#[from] ProfileError),
}

/// Errors of the provers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProveError {
    /// The public statement is malformed.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// The secret (with the list position, for a vote) is not a witness of the
    /// statement. Decided before the tape is used.
    #[error("the secret is not a witness of the statement")]
    WitnessRejected,
    /// No counter in `0 ..= 0xffff_ffff` gave an acceptable third challenge. A
    /// later attempt needs an entirely fresh tape.
    #[error("no counter gave an acceptable challenge")]
    GrindingExhausted,
    /// The backend failed for a reason that is not the caller's input.
    #[error(transparent)]
    Backend(ProofError),
}

/// Errors of the verifiers. Every one is a refusal to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// Malformed input: the public statement fails public validation.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// Malformed input: the proof does not have the exact length of the row and
    /// relation. Shorter, longer and trailing bytes all end here.
    #[error("a proof of this row and relation is {expected} bytes long, got {actual}")]
    ProofLength {
        /// The exact length.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The proof has the right length and is not a valid proof of the
    /// statement. One outcome for every such proof: which internal check failed
    /// (a non-canonical field, a rejected opening, a challenge mismatch) is an
    /// implementation detail that another verifier need not share, and is not
    /// reported.
    #[error("the proof is rejected")]
    Rejected,
    /// The backend failed for a reason that is neither the statement nor the
    /// proof.
    #[error(transparent)]
    Backend(ProofError),
}

impl From<ProfileError> for ProveError {
    fn from(error: ProfileError) -> Self {
        Self::Statement(StatementError::Profile(error))
    }
}

impl From<ProfileError> for VerifyError {
    fn from(error: ProfileError) -> Self {
        Self::Statement(StatementError::Profile(error))
    }
}

/// Run the backend prover for `relation` in the role's context, consuming the
/// tape.
///
/// The witness check runs first: a witness that violates the relation returns
/// [`ProveError::WitnessRejected`] before anything is derived from the tape.
pub(crate) fn prove_relation<R: Relation<Gf256> + ?Sized>(
    profile: &Profile,
    role: Role,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8; MU_BYTES],
    witness: &[u8],
    tape: ProvingTape,
) -> Result<Vec<u8>, ProveError> {
    let context = profile.context(role)?;
    let backend_tape = tape.backend()?;
    let result = proof::prove::<Gf256, R>(&context, relation, public, mu, witness, &backend_tape);
    // The tape proves once: both copies are erased here, whatever the outcome.
    drop(backend_tape);
    drop(tape);
    match result {
        Ok(bytes) => Ok(bytes),
        Err(ProofError::WitnessRejected) => Err(ProveError::WitnessRejected),
        Err(ProofError::GrindingExhausted { .. }) => Err(ProveError::GrindingExhausted),
        Err(error) => Err(ProveError::Backend(error)),
    }
}

/// Run the backend verifier for `relation` in the role's context, after the
/// exact-length check (repeated here: the public verifiers make it before they
/// compile the descriptor).
pub(crate) fn verify_relation<R: Relation<Gf256> + ?Sized>(
    profile: &Profile,
    role: Role,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8; MU_BYTES],
    proof_bytes: &[u8],
) -> Result<(), VerifyError> {
    check_proof_length(profile.row(), role, proof_bytes)?;
    let context = profile.context(role)?;
    match proof::verify::<Gf256, R>(&context, relation, public, mu, proof_bytes) {
        Ok(()) => Ok(()),
        Err(ProofError::ChallengeMismatch | ProofError::Codec(_) | ProofError::Vole(_)) => {
            Err(VerifyError::Rejected)
        }
        Err(error) => Err(VerifyError::Backend(error)),
    }
}

/// The exact-length rule: the first check of every verifier. The length is a
/// constant of the row and the relation, so nothing is hashed or allocated
/// before a proof of another length is refused.
pub(crate) fn check_proof_length(
    row: Row,
    role: Role,
    proof_bytes: &[u8],
) -> Result<(), VerifyError> {
    let expected = row.proof_bytes(role);
    if proof_bytes.len() == expected {
        Ok(())
    } else {
        Err(VerifyError::ProofLength {
            expected,
            actual: proof_bytes.len(),
        })
    }
}

/// `mu_R = SHAKE256(PREFIX_R || F_R || 08, 64 bytes)`: the backend's `H_2^0`
/// inside the role's namespace.
pub(crate) fn message_digest(
    profile: &Profile,
    role: Role,
    frame: &[u8],
) -> Result<[u8; MU_BYTES], StatementError> {
    let mut hasher = Hasher::new_in(profile.namespace(role)?, LEVEL, Oracle::H2Mu);
    hasher.update(frame);
    let mut mu = [0u8; MU_BYTES];
    hasher
        .finalize(&mut mu)
        .map_err(|error| StatementError::Profile(ProfileError::Namespace(error)))?;
    Ok(mu)
}

/// The extended witness common to both relations: the pad, the secret and the
/// eleven committed states of the two permutations whose public initial-state
/// parts are `blocks`. Bits beyond them (the selectors of a vote) are zero.
///
/// `pad` is the 32 pad bytes; the buffer is allocated once at its final size and
/// erased on drop.
pub(crate) fn build_witness(
    witness_bits: usize,
    pad: &[u8],
    secret: &CredentialSecret,
    blocks: [&[u8; STATE_BYTES]; 2],
) -> Zeroizing<Vec<u8>> {
    let mut witness = Zeroizing::new(vec![0u8; witness_bits / 8]);
    for (slot, byte) in witness.iter_mut().zip(pad.iter().take(PAD_BYTES)) {
        *slot = *byte;
    }
    for (slot, byte) in witness
        .iter_mut()
        .skip(SECRET_OFFSET / 8)
        .zip(secret.expose_bytes())
    {
        *slot = *byte;
    }
    for (block, offset) in blocks.into_iter().zip(PERMUTATION_OFFSETS) {
        let evaluation = evaluate(block, secret.expose_bytes());
        let states = witness
            .get_mut(offset / 8..offset / 8 + GROUPS * STATE_BYTES)
            .unwrap_or(&mut []);
        for (index, state) in states.chunks_exact_mut(STATE_BYTES).enumerate() {
            evaluation.write_state(index + 1, state);
        }
    }
    witness
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tape_splits_as_the_record_says_and_shows_nothing() {
        let bytes: [u8; TAPE_BYTES] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let tape = ProvingTape::from_bytes(&bytes);
        assert_eq!(tape.pad(), &bytes[48..80]);
        assert_eq!(tape.pad().len(), PAD_BYTES);
        let backend = tape.backend().expect("32-byte root");
        assert_eq!(backend.root(), &bytes[..32]);
        assert_eq!(backend.iv_pre()[..], bytes[32..48]);
        assert_eq!(format!("{tape:?}"), "ProvingTape(<redacted>)");
    }

    #[test]
    fn an_entropy_failure_gives_no_tape() {
        let tape = ProvingTape::fill_with(|buffer| {
            buffer.fill(9);
            Ok::<(), ()>(())
        })
        .expect("filled");
        assert_eq!(tape.pad(), &[9u8; 32]);
        assert_eq!(ProvingTape::fill_with(|_| Err::<(), u8>(3)).err(), Some(3));
    }

    #[test]
    fn the_message_digest_is_shake256_of_prefix_frame_and_the_suffix() {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let profile = Profile::new(Row::Candidate).expect("tables");
        for role in Role::ALL {
            let frame = b"some frame bytes";
            let mut sponge = sha3::Shake256::default();
            sponge.update(profile.prefix(role));
            sponge.update(frame);
            sponge.update(&[0x08]);
            let mut expected = [0u8; MU_BYTES];
            sponge.finalize_xof().read(&mut expected);
            assert_eq!(message_digest(&profile, role, frame), Ok(expected));
        }
    }

    #[test]
    fn the_common_witness_has_the_frozen_layout() {
        use crate::{
            keccak_relation::public_block,
            layout::{REGISTRATION_WITNESS_BITS, VOTE_WITNESS_BITS},
        };
        let secret = CredentialSecret::from_bytes(&[0x3c; 48]);
        let blocks = [
            public_block(*b"PCR1", &[1; 64]),
            public_block(*b"PNF1", &[2; 64]),
        ];
        let pad = [0xd7u8; 32];
        let witness = build_witness(VOTE_WITNESS_BITS, &pad, &secret, [&blocks[0], &blocks[1]]);
        assert_eq!(witness.len(), 4488);
        assert_eq!(witness[..32], pad);
        assert_eq!(witness[32..80], [0x3c; 48]);
        for (block, base) in blocks.iter().zip([80usize, 2280]) {
            let evaluation = evaluate(block, secret.expose_bytes());
            for group in 1..=11 {
                let mut state = [0u8; 200];
                evaluation.write_state(group, &mut state);
                let start = base + 200 * (group - 1);
                assert_eq!(witness[start..start + 200], state);
            }
        }
        assert_eq!(witness[4480..], [0u8; 8]);
        let shorter = build_witness(
            REGISTRATION_WITNESS_BITS,
            &pad,
            &secret,
            [&blocks[0], &blocks[1]],
        );
        assert_eq!(shorter[..], witness[..4480]);
    }

    #[test]
    fn only_the_exact_length_passes_the_length_check() {
        for row in Row::ALL {
            for role in Role::ALL {
                let expected = row.proof_bytes(role);
                assert_eq!(check_proof_length(row, role, &vec![0u8; expected]), Ok(()));
                for actual in [0, expected - 1, expected + 1, expected + 4] {
                    assert_eq!(
                        check_proof_length(row, role, &vec![0u8; actual]),
                        Err(VerifyError::ProofLength { expected, actual })
                    );
                }
            }
        }
        // The other row's length and the other relation's length are wrong lengths.
        assert!(check_proof_length(Row::Candidate, Role::Vote, &vec![0u8; 159_588]).is_err());
        assert!(
            check_proof_length(Row::Candidate, Role::Registration, &vec![0u8; 109_114]).is_err()
        );
    }

    #[test]
    fn profile_errors_convert_into_both_error_types() {
        let error = ProfileError::DescriptorLength { actual: 1 };
        assert_eq!(
            ProveError::from(error),
            ProveError::Statement(StatementError::Profile(error))
        );
        assert_eq!(
            VerifyError::from(error),
            VerifyError::Statement(StatementError::Profile(error))
        );
    }
}
