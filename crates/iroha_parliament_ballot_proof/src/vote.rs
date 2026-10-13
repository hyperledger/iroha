//! The vote relation and its proof (evaluation record section 6.3):
//!
//! ```text
//! R_vote(x; sk, i)  <=>  0 <= i < S
//!                   and  C_i = SHAKE256("PCR1" || P16 || sk || B,     1024 bits)
//!                   and  nf  = SHAKE256("PNF1" || P16 || sk || scope,  512 bits)
//! ```
//!
//! A statement holds exactly the fields of
//!
//! ```text
//! F_VOTE = Frame("PARL/MU/VOTE/v1";
//!     B, scope, R, u16_le(S), concat(L), nf, u8(vote), policy_hash)
//! ```
//!
//! Public validation, before any proof work on either side: the vote byte is 0,
//! 1 or 2; `3 <= S <= 1000`; the list has exactly `S` entries in strictly
//! increasing unsigned bytewise order; `R` is the recomputed list digest. The
//! caller authenticates the expected body and the sealed list. The proof shows
//! that the prover knows the secret behind one list entry and that `nf` is that
//! secret's nullifier for `scope`; it hides which entry. The vote value, the
//! policy hash and the whole list are bound through `mu`. Double-vote detection
//! (nullifier uniqueness) is a check of the caller.
//!
//! Witness (35,904 bits): pad, secret, the eleven committed states of the
//! commitment permutation, the eleven of the nullifier permutation, the selector
//! vectors `a` and `b`. Constraints after Booleanity (36,803): the selector
//! constraints, commitment transitions, commitment output through the public
//! multiplexer (VC), nullifier transitions, nullifier output (VN).

use iroha_zkp_vole::{
    field::Gf256,
    quicksilver::{ConstraintSystem, Relation},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    credential::{COMMITMENT_TAG, CredentialSecret, NULLIFIER_TAG},
    framing::{COMMITMENT_BYTES, Commitment, Digest64, frame_bytes},
    keccak_relation::{STATE_BYTES, Scratch, bit_of, emit_transitions, public_block},
    layout::{
        COMMITMENT_BITS, PERMUTATION_OFFSETS, SELECTOR_A_OFFSET, TAG_BITS,
        VOTE_RELATION_CONSTRAINTS, VOTE_WITNESS_BITS,
    },
    profile::{Profile, Role, Row},
    proving::{
        MU_BYTES, PAD_BYTES, ProveError, ProvingTape, StatementError, VerifyError, build_witness,
        check_proof_length, message_digest, prove_relation, verify_relation,
    },
    sealed_list::{self, MAX_LIST_SIZE, MIN_LIST_SIZE, SealedList},
    selector::{emit_selectors, multiplex, selector_words},
};

/// A vote value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vote {
    /// Byte 0.
    Aye,
    /// Byte 1.
    Nay,
    /// Byte 2.
    Abstain,
}

impl Vote {
    /// The vote byte of the statement.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Aye => 0,
            Self::Nay => 1,
            Self::Abstain => 2,
        }
    }

    /// The vote of a statement byte; `None` for any byte but 0, 1 and 2.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Aye),
            1 => Some(Self::Nay),
            2 => Some(Self::Abstain),
            _ => None,
        }
    }
}

/// The public statement of a vote proof: the fields of `F_VOTE`.
///
/// The fields are public so that a statement received from elsewhere can be
/// represented as it arrived; [`VoteStatement::validate`] is the public
/// validation of the record and runs inside [`prove`] and [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteStatement {
    /// `B`, the digest of the body context.
    pub body_digest: Digest64,
    /// `scope`.
    pub scope: Digest64,
    /// `R`, the digest of the sealed list.
    pub list_digest: Digest64,
    /// `S`, the stated list size.
    pub size: u16,
    /// `L`, the list entries in order.
    pub list: Vec<Commitment>,
    /// `nf`, the nullifier.
    pub nullifier: Digest64,
    /// The vote byte: 0 = Aye, 1 = Nay, 2 = Abstain.
    pub vote: u8,
    /// `policy_hash`.
    pub policy_hash: Digest64,
}

impl VoteStatement {
    /// The statement for the sealed list `list` of the body `body_digest`, with
    /// `S` and `R` computed from the list.
    ///
    /// # Errors
    /// Only if a frame cannot be built, which a sealed list never causes.
    pub fn new(
        body_digest: Digest64,
        scope: Digest64,
        list: &SealedList,
        nullifier: Digest64,
        vote: Vote,
        policy_hash: Digest64,
    ) -> Result<Self, StatementError> {
        Ok(Self {
            body_digest,
            scope,
            list_digest: list.digest(&body_digest)?,
            size: u16::try_from(list.size()).unwrap_or(u16::MAX),
            list: list.entries().to_vec(),
            nullifier,
            vote: vote.byte(),
            policy_hash,
        })
    }

    /// The public validation of the record.
    ///
    /// # Errors
    /// [`StatementError::VoteValue`], [`StatementError::List`],
    /// [`StatementError::ListLength`] or [`StatementError::ListDigest`], in that
    /// order of checking.
    pub fn validate(&self) -> Result<(), StatementError> {
        if Vote::from_byte(self.vote).is_none() {
            return Err(StatementError::VoteValue { value: self.vote });
        }
        sealed_list::validate(&self.list)?;
        if usize::from(self.size) != self.list.len() {
            return Err(StatementError::ListLength {
                declared: self.size,
                actual: self.list.len(),
            });
        }
        if sealed_list::digest_unvalidated(&self.body_digest, &self.list)? != self.list_digest {
            return Err(StatementError::ListDigest);
        }
        Ok(())
    }

    /// `F_VOTE` of the fields as they are; nothing is validated.
    ///
    /// # Errors
    /// [`StatementError::Framing`] if the list is too long for a frame field.
    pub fn frame(&self) -> Result<Vec<u8>, StatementError> {
        Ok(frame_bytes(
            b"PARL/MU/VOTE/v1",
            &[
                self.body_digest.as_bytes(),
                self.scope.as_bytes(),
                self.list_digest.as_bytes(),
                &self.size.to_le_bytes(),
                &sealed_list::concat(&self.list),
                self.nullifier.as_bytes(),
                &[self.vote],
                self.policy_hash.as_bytes(),
            ],
        )?)
    }

    /// The public validation of the record, and what it derives: the relation's
    /// public input and `mu`.
    ///
    /// # Errors
    /// As [`VoteStatement::validate`].
    pub fn instance(&self, profile: &Profile) -> Result<VoteInstance, StatementError> {
        self.validate()?;
        self.instance_unvalidated(profile)
    }

    /// [`VoteStatement::instance`] without the public validation.
    fn instance_unvalidated(&self, profile: &Profile) -> Result<VoteInstance, StatementError> {
        let public = VotePublic {
            commitment_block: public_block(COMMITMENT_TAG, self.body_digest.as_bytes()),
            nullifier_block: public_block(NULLIFIER_TAG, self.scope.as_bytes()),
            list: sealed_list::concat(&self.list),
            nullifier: self.nullifier,
        };
        let mu = message_digest(profile, Role::Vote, &self.frame()?)?;
        Ok(VoteInstance { public, mu })
    }
}

/// What the vote constraints read besides the witness. Public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotePublic {
    /// The public part of the commitment permutation's initial state (`B`).
    commitment_block: [u8; STATE_BYTES],
    /// The public part of the nullifier permutation's initial state (`scope`).
    nullifier_block: [u8; STATE_BYTES],
    /// `concat(L)`.
    list: Vec<u8>,
    nullifier: Digest64,
}

impl VotePublic {
    /// The list size `S`.
    pub fn size(&self) -> usize {
        self.list.len() / COMMITMENT_BYTES
    }

    /// Whether the list has a whole number of entries within the size bounds:
    /// the shape the constraint stream is defined for.
    fn has_valid_shape(&self) -> bool {
        self.list.len().is_multiple_of(COMMITMENT_BYTES)
            && (MIN_LIST_SIZE..=MAX_LIST_SIZE).contains(&self.size())
    }
}

/// A validated vote statement on one row: the relation's public input and `mu`.
/// Public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInstance {
    public: VotePublic,
    mu: [u8; MU_BYTES],
}

impl VoteInstance {
    /// The public input of [`VoteRelation`].
    pub const fn public(&self) -> &VotePublic {
        &self.public
    }

    /// `mu_VOTE`.
    pub const fn mu(&self) -> &[u8; MU_BYTES] {
        &self.mu
    }
}

/// The vote relation on the backend's constraint system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VoteRelation;

impl Relation<Gf256> for VoteRelation {
    type PublicInput = VotePublic;

    fn witness_bits(&self) -> usize {
        VOTE_WITNESS_BITS
    }

    fn constraints(&self) -> usize {
        VOTE_RELATION_CONSTRAINTS
    }

    fn emit<C: ConstraintSystem<Field = Gf256>>(&self, public: &VotePublic, cs: &mut C) {
        // A public input of another shape has no constraint stream: emit nothing
        // and let the backend report the wrong count. Not reachable through the
        // statement types, which validate the list first.
        if !public.has_valid_shape() {
            return;
        }
        let size = public.size();
        let mut products = Zeroizing::new(vec![cs.zero(); size]);
        emit_selectors(cs, size, &mut products);
        let mut scratch = Scratch::new(cs.zero());
        emit_transitions(
            cs,
            &mut scratch,
            &public.commitment_block,
            PERMUTATION_OFFSETS[0],
            COMMITMENT_BITS,
        );
        // (VC): O_C[t] + sum_{i<S} p_i * C_i[t]; the degree-two multiplexer is
        // aligned to the degree of the output by the backend's addition.
        for t in 0..COMMITMENT_BITS {
            let selected = multiplex(cs, &public.list, t, &products);
            let constraint = cs.add(scratch.state()[t], selected);
            cs.constrain(constraint);
        }
        emit_transitions(
            cs,
            &mut scratch,
            &public.nullifier_block,
            PERMUTATION_OFFSETS[1],
            TAG_BITS,
        );
        // (VN): O_N[t] + nf[t].
        for t in 0..TAG_BITS {
            let constraint = cs.add_bit(scratch.state()[t], bit_of(public.nullifier.as_bytes(), t));
            cs.constrain(constraint);
        }
    }
}

/// The extended witness of `secret` at list position `index` for `public` with
/// the pad `pad`, in the frozen layout. **Secret**; erased on drop.
///
/// It is a valid witness exactly if entry `index` of the list is the commitment
/// of `secret` and the statement's nullifier is the secret's. A position of
/// 1,024 or more has no selector encoding and gives an invalid witness.
pub fn witness(
    public: &VotePublic,
    secret: &CredentialSecret,
    index: u16,
    pad: &[u8; PAD_BYTES],
) -> Zeroizing<Vec<u8>> {
    let mut witness = build_witness(
        VOTE_WITNESS_BITS,
        pad,
        secret,
        [&public.commitment_block, &public.nullifier_block],
    );
    let mut words = selector_words(index);
    let selectors = witness.iter_mut().skip(SELECTOR_A_OFFSET / 8);
    for (slot, byte) in selectors.zip(words.iter().flat_map(|word| word.to_le_bytes())) {
        *slot = byte;
    }
    words.zeroize();
    witness
}

/// Prove that `secret` is the secret behind entry `index` of the statement's
/// list and that the statement's nullifier is its nullifier for the scope.
///
/// `index` is secret (it is the voter's anonymity): it is never compared with
/// anything in the clear here, and a wrong position, including one of 1,024 or
/// more, which has no selector encoding, ends in
/// [`ProveError::WitnessRejected`] like a wrong secret.
/// [`SealedList::position`] finds it in constant time. `tape`
/// is 80 fresh random bytes from the caller's generator; it is consumed and
/// erased, as are the witness and every transient copy of the secret, on success
/// and on every error. The proof is exactly [`Row::proof_bytes`] bytes.
///
/// # Errors
/// * [`ProveError::Statement`] if the statement fails public validation
///   (decided before the descriptor is compiled);
/// * [`ProveError::WitnessRejected`] if `(secret, index)` is not a witness;
///   nothing is derived from the tape then;
/// * [`ProveError::GrindingExhausted`] if no counter is acceptable;
/// * [`ProveError::Backend`] for a backend without its tables.
pub fn prove(
    row: Row,
    statement: &VoteStatement,
    secret: &CredentialSecret,
    index: u16,
    tape: ProvingTape,
) -> Result<Vec<u8>, ProveError> {
    statement.validate()?;
    let profile = Profile::new(row)?;
    let instance = statement.instance_unvalidated(&profile)?;
    let mut pad = Zeroizing::new([0u8; PAD_BYTES]);
    for (slot, byte) in pad.iter_mut().zip(tape.pad()) {
        *slot = *byte;
    }
    let witness = witness(&instance.public, secret, index, &pad);
    prove_relation(
        &profile,
        Role::Vote,
        &VoteRelation,
        &instance.public,
        &instance.mu,
        &witness,
        tape,
    )
}

/// Verify a vote proof for `statement` on `row`.
///
/// `proof` and `statement` are untrusted. The row is the caller's choice and is
/// never detected from the bytes.
///
/// # Errors
/// In this order: [`VerifyError::ProofLength`] for any length but the exact one,
/// [`VerifyError::Statement`] for a statement that fails public validation
/// (both before the descriptor is compiled), and [`VerifyError::Rejected`] for a
/// proof that does not verify.
pub fn verify(row: Row, statement: &VoteStatement, proof: &[u8]) -> Result<(), VerifyError> {
    check_proof_length(row, Role::Vote, proof)?;
    statement.validate()?;
    let profile = Profile::new(row)?;
    let instance = statement.instance_unvalidated(&profile)?;
    verify_relation(
        &profile,
        Role::Vote,
        &VoteRelation,
        &instance.public,
        &instance.mu,
        proof,
    )
}

#[cfg(test)]
mod tests {
    use iroha_zkp_vole::quicksilver::{QuickSilverError, is_satisfied, total_constraints};

    use super::*;
    use crate::{layout::SELECTOR_B_OFFSET, sealed_list::ListError};

    fn secret(member: u8) -> CredentialSecret {
        CredentialSecret::from_bytes(&[member; 48])
    }

    /// A list of `size` members and the statement of the member at sorted
    /// position `position`, with that member's secret.
    fn case(size: u8, position: usize) -> (VoteStatement, CredentialSecret) {
        let body = Digest64([0x0b; 64]);
        let scope = Digest64([0x5c; 64]);
        let mut members: Vec<(Commitment, u8)> = (1..=size)
            .map(|member| (secret(member).commitment(&body), member))
            .collect();
        members.sort_unstable();
        let list = SealedList::new(members.iter().map(|(entry, _)| *entry).collect())
            .expect("sorted and distinct");
        let voter = secret(members[position].1);
        let statement = VoteStatement::new(
            body,
            scope,
            &list,
            voter.nullifier(&scope),
            Vote::Nay,
            Digest64([0x70; 64]),
        )
        .expect("statement");
        (statement, voter)
    }

    #[test]
    fn the_relation_has_the_frozen_dimensions() {
        assert_eq!(VoteRelation.witness_bits(), 35_904);
        assert_eq!(Relation::<Gf256>::constraints(&VoteRelation), 36_803);
        assert_eq!(total_constraints::<Gf256, _>(&VoteRelation), Ok(72_707));
        for row in Row::ALL {
            let profile = Profile::new(row).expect("tables");
            let context = profile.context(Role::Vote).expect("context");
            assert_eq!(
                context.proof_bytes::<Gf256, _>(&VoteRelation),
                Ok(row.proof_bytes(Role::Vote))
            );
        }
    }

    #[test]
    fn vote_bytes_are_zero_one_and_two() {
        assert_eq!(
            [Vote::Aye.byte(), Vote::Nay.byte(), Vote::Abstain.byte()],
            [0, 1, 2]
        );
        assert_eq!(Vote::from_byte(0), Some(Vote::Aye));
        assert_eq!(Vote::from_byte(1), Some(Vote::Nay));
        assert_eq!(Vote::from_byte(2), Some(Vote::Abstain));
        for byte in [3u8, 4, 0x80, 0xff] {
            assert_eq!(Vote::from_byte(byte), None);
        }
    }

    #[test]
    fn the_statement_is_the_frame_of_the_record_and_validates() {
        let (statement, _) = case(4, 1);
        assert_eq!(statement.size, 4);
        assert_eq!(statement.vote, 1);
        assert_eq!(statement.validate(), Ok(()));
        let frame = statement.frame().expect("frame");
        // Tag, eight fields, B.
        assert!(frame.starts_with(b"\x0f\x00PARL/MU/VOTE/v1\x08\x00\x40\x00\x00\x00"));
        assert_eq!(
            frame.len(),
            2 + 15 + 2 + 8 * 4 + 64 + 64 + 64 + 2 + 4 * 128 + 64 + 1 + 64
        );
        let profile = Profile::new(Row::Candidate).expect("tables");
        let instance = statement.instance(&profile).expect("valid");
        assert_eq!(instance.public().size(), 4);
        assert_eq!(
            instance.mu(),
            &message_digest(&profile, Role::Vote, &frame).expect("mu")
        );
        assert_eq!(
            statement.instance_unvalidated(&profile).expect("frame"),
            instance
        );
    }

    #[test]
    fn every_malformed_statement_has_its_error() {
        let (valid, _) = case(4, 1);
        let mut statement = valid.clone();
        statement.vote = 3;
        assert_eq!(
            statement.validate(),
            Err(StatementError::VoteValue { value: 3 })
        );
        let mut statement = valid.clone();
        statement.list.truncate(2);
        assert_eq!(
            statement.validate(),
            Err(StatementError::List(ListError::Size { actual: 2 }))
        );
        let mut statement = valid.clone();
        statement.list.swap(2, 3);
        assert_eq!(
            statement.validate(),
            Err(StatementError::List(ListError::Order { index: 3 }))
        );
        let mut statement = valid.clone();
        statement.list[2] = statement.list[1];
        assert_eq!(
            statement.validate(),
            Err(StatementError::List(ListError::Order { index: 2 }))
        );
        let mut statement = valid.clone();
        statement.size = 5;
        assert_eq!(
            statement.validate(),
            Err(StatementError::ListLength {
                declared: 5,
                actual: 4
            })
        );
        let mut statement = valid.clone();
        statement.list_digest.0[0] ^= 1;
        assert_eq!(statement.validate(), Err(StatementError::ListDigest));
        // R is the digest for the stated body: another B invalidates it.
        let mut statement = valid.clone();
        statement.body_digest.0[63] ^= 0x80;
        assert_eq!(statement.validate(), Err(StatementError::ListDigest));
        // One more entry with a stale R and S.
        let mut statement = valid;
        statement.list.push(Commitment([0xff; 128]));
        assert_eq!(
            statement.validate(),
            Err(StatementError::ListLength {
                declared: 4,
                actual: 5
            })
        );
        let profile = Profile::new(Row::Candidate).expect("tables");
        assert_eq!(
            statement.instance(&profile).err(),
            Some(StatementError::ListLength {
                declared: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn the_honest_witness_satisfies_the_relation_at_every_position_of_a_small_list() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        for position in 0..3 {
            let (statement, voter) = case(3, position);
            let instance = statement.instance(&profile).expect("valid");
            let index = u16::try_from(position).expect("small");
            let honest = witness(instance.public(), &voter, index, &[0x11; 32]);
            assert_eq!(honest.len(), 4488);
            assert_eq!(
                honest[SELECTOR_A_OFFSET / 8..SELECTOR_B_OFFSET / 8],
                1u32.to_le_bytes()
            );
            assert_eq!(
                honest[SELECTOR_B_OFFSET / 8..],
                (1u32 << position).to_le_bytes()
            );
            assert_eq!(
                is_satisfied::<Gf256, _>(&VoteRelation, instance.public(), &honest),
                Ok(true)
            );
            // The neighbour's position is not a witness for this secret.
            let wrong = witness(instance.public(), &voter, (index + 1) % 3, &[0x11; 32]);
            assert_eq!(
                is_satisfied::<Gf256, _>(&VoteRelation, instance.public(), &wrong),
                Ok(false)
            );
        }
    }

    /// One full proof: `mu` alone binds the list, its order, `S` and `R`, also
    /// when the public validation of the list is skipped (a test-only path; the
    /// verifier of this crate always validates).
    #[test]
    fn the_message_digest_binds_the_list_without_public_validation() {
        let row = Row::Candidate;
        let profile = Profile::new(row).expect("tables");
        let (statement, voter) = case(3, 1);
        let proof = prove(
            row,
            &statement,
            &voter,
            1,
            ProvingTape::from_bytes(&[0x5a; 80]),
        )
        .expect("honest proof");
        let check = |statement: &VoteStatement| {
            let instance = statement.instance_unvalidated(&profile).expect("frame");
            verify_relation(
                &profile,
                Role::Vote,
                &VoteRelation,
                instance.public(),
                instance.mu(),
                &proof,
            )
        };
        assert_eq!(check(&statement), Ok(()));
        let is_rejected = |result: Result<(), VerifyError>| result == Err(VerifyError::Rejected);
        // Two non-member entries swapped, R stale: the multiplexer selects the
        // same entry, only mu differs.
        let mut swapped = statement.clone();
        swapped.list.swap(0, 2);
        assert!(swapped.validate().is_err());
        assert!(is_rejected(check(&swapped)));
        // The same with R recomputed for the swapped list.
        swapped.list_digest =
            sealed_list::digest_unvalidated(&swapped.body_digest, &swapped.list).expect("frame");
        assert!(is_rejected(check(&swapped)));
        // One bit of R, list unchanged.
        let mut other = statement;
        other.list_digest.0[32] ^= 8;
        assert!(is_rejected(check(&other)));
    }

    #[test]
    fn a_public_input_of_another_shape_emits_nothing() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let (statement, voter) = case(3, 0);
        let instance = statement.instance(&profile).expect("valid");
        let honest = witness(instance.public(), &voter, 0, &[0; 32]);
        for list_bytes in [0usize, 2 * 128, 3 * 128 + 1, 1001 * 128] {
            let mut public = instance.public().clone();
            public.list = vec![0u8; list_bytes];
            assert!(!public.has_valid_shape());
            assert_eq!(
                is_satisfied::<Gf256, _>(&VoteRelation, &public, &honest),
                Err(QuickSilverError::ConstraintCount {
                    expected: 72_707,
                    actual: 35_904
                })
            );
        }
        assert!(instance.public().has_valid_shape());
    }
}
