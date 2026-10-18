//! Complete proofs on the candidate row: completeness, refusal of invalid
//! witnesses, rejection of proofs made from them by the backend's unchecked
//! test-support prover, and rejection of a valid proof under every change of the
//! statement, the row, the role and the proof bytes. Both rows are proved and
//! verified byte for byte in `vectors.rs`.
//!
//! A complete proof takes seconds in a debug build, so every test here makes few
//! of them and the two honest proofs are shared.

mod common;

use std::sync::OnceLock;

use common::{
    Fault, RegCase, VoteCase, flip, fx, reg_case, registration_faults, secret, vote_case,
    vote_faults,
};
use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    framing::{BodyContext, Commitment},
    profile::{Profile, ProofField, Role, Row},
    proving::{ProveError, ProvingTape, StatementError, VerifyError},
    registration::{self, RegistrationRelation, RegistrationStatement},
    sealed_list::{self, ListError, SealedList},
    vote::{self, VoteRelation, VoteStatement},
};
use iroha_zkp_vole::{
    field::Gf256,
    hash::Namespace,
    proof::{self, ProofContext, ProofError},
    randomness::Tape,
};

const ROW: Row = Row::Candidate;

fn reg() -> &'static (RegCase, Vec<u8>) {
    static PROOF: OnceLock<(RegCase, Vec<u8>)> = OnceLock::new();
    PROOF.get_or_init(|| {
        let case = reg_case(ROW);
        let proof = registration::prove(
            ROW,
            &case.statement,
            &secret(&case.secret),
            ProvingTape::from_bytes(&case.tape),
        )
        .expect("honest proof");
        (case, proof)
    })
}

fn vote3() -> &'static (VoteCase, Vec<u8>) {
    static PROOF: OnceLock<(VoteCase, Vec<u8>)> = OnceLock::new();
    PROOF.get_or_init(|| {
        let case = vote_case(ROW, 3, 1);
        let proof = vote::prove(
            ROW,
            &case.statement,
            &secret(&case.secret),
            position(&case),
            ProvingTape::from_bytes(&case.tape),
        )
        .expect("honest proof");
        (case, proof)
    })
}

/// The voter's list position of a case, as the prover takes it.
fn position(case: &VoteCase) -> u16 {
    u16::try_from(case.index).expect("at most 1000")
}

fn is_rejected(result: Result<(), VerifyError>) -> bool {
    result == Err(VerifyError::Rejected)
}

fn backend_tape(tape: &[u8; 112]) -> Tape {
    Tape::extended(
        iroha_parliament_ballot_proof::profile::LEVEL,
        &tape[..32],
        &common::array(&tape[32..48]),
        &common::array(&tape[80..112]),
    )
    .expect("32-byte root")
}

// ---------------------------------------------------------------- completeness

#[test]
fn honest_proofs_verify_with_the_exact_lengths() {
    let (case, proof) = reg();
    assert_eq!(proof.len(), 160_148);
    assert_eq!(registration::verify(ROW, &case.statement, proof), Ok(()));
    let (case, proof) = vote3();
    assert_eq!(proof.len(), 233_012);
    assert_eq!(vote::verify(ROW, &case.statement, proof), Ok(()));
}

#[test]
fn a_vote_proof_at_the_last_position_of_a_list_of_five_hundred_verifies() {
    let case = vote_case(ROW, 500, 499);
    let proof = vote::prove(
        ROW,
        &case.statement,
        &secret(&case.secret),
        position(&case),
        ProvingTape::from_bytes(&case.tape),
    )
    .expect("honest proof");
    assert_eq!(proof.len(), 233_012);
    assert_eq!(vote::verify(ROW, &case.statement, &proof), Ok(()));
    // The same proof is not a proof for the list without its first entry.
    let shorter = SealedList::new(case.list.entries()[1..].to_vec()).expect("sealed");
    let mut other = case.statement.clone();
    other.list = shorter.entries().to_vec();
    other.size = 499;
    other.list_digest = shorter.digest(&other.body_digest).expect("frame");
    assert_eq!(other.validate(), Ok(()));
    assert!(is_rejected(vote::verify(ROW, &other, &proof)));
}

// ----------------------------------------------------------------- determinism

#[test]
fn registration_proofs_are_deterministic_in_the_tape_and_differ_across_tapes() {
    let (case, proof) = reg();
    let prove = |tape: &[u8; 112]| {
        registration::prove(
            ROW,
            &case.statement,
            &secret(&case.secret),
            ProvingTape::from_bytes(tape),
        )
        .expect("honest proof")
    };
    assert_eq!(&prove(&case.tape), proof);
    let other_tape: [u8; 112] = common::array(&fx("tape/reg/other", 112));
    let other = prove(&other_tape);
    assert_ne!(&other, proof);
    assert_eq!(other.len(), proof.len());
    assert_eq!(registration::verify(ROW, &case.statement, &other), Ok(()));
}

#[test]
fn vote_proofs_are_deterministic_in_the_tape_and_differ_across_tapes() {
    let (case, proof) = vote3();
    let prove = |tape: &[u8; 112]| {
        vote::prove(
            ROW,
            &case.statement,
            &secret(&case.secret),
            position(case),
            ProvingTape::from_bytes(tape),
        )
        .expect("honest proof")
    };
    assert_eq!(&prove(&case.tape), proof);
    // Another tape: another proof of the same statement with the same nullifier.
    let other_tape: [u8; 112] = common::array(&fx("tape/vote/other", 112));
    let other = prove(&other_tape);
    assert_ne!(&other, proof);
    assert_eq!(vote::verify(ROW, &case.statement, &other), Ok(()));
}

#[test]
fn another_pad_changes_exactly_the_fields_that_depend_on_the_witness() {
    let (case, proof) = reg();
    let mut tape = case.tape;
    tape[79] ^= 0x80;
    let other = registration::prove(
        ROW,
        &case.statement,
        &secret(&case.secret),
        ProvingTape::from_bytes(&tape),
    )
    .expect("honest proof");
    assert_eq!(registration::verify(ROW, &case.statement, &other), Ok(()));
    for segment in ROW.proof_layout(Role::Registration) {
        let range = segment.offset..segment.offset + segment.len;
        let same = proof[range.clone()] == other[range];
        let depends_on_tape_and_mu_only = matches!(
            segment.field,
            ProofField::Corrections
                | ProofField::MultCorrections
                | ProofField::UTilde
                | ProofField::IvPre
                | ProofField::Salt
        );
        if depends_on_tape_and_mu_only {
            assert!(same, "{:?}", segment.field);
        } else if segment.field != ProofField::Counter {
            assert!(!same, "{:?}", segment.field);
        }
    }
}

// ------------------------------------------------- invalid witnesses, prover

#[test]
fn the_registration_prover_refuses_every_invalid_witness() {
    let (case, _) = reg();
    let profile = Profile::new(ROW).expect("tables");
    let context = profile.context(Role::Registration).expect("context");
    for fault in registration_faults(case) {
        let instance = fault.statement.instance(&profile).expect("valid");
        assert_eq!(
            proof::prove::<Gf256, _>(
                &context,
                &RegistrationRelation,
                instance.public(),
                instance.mu(),
                &fault.witness,
                &backend_tape(&case.tape),
            ),
            Err(ProofError::WitnessRejected),
            "{}",
            fault.name
        );
    }
    // Through the crate's own prover: another secret.
    assert_eq!(
        registration::prove(
            ROW,
            &case.statement,
            &secret(&common::other_secret()),
            ProvingTape::from_bytes(&case.tape),
        ),
        Err(ProveError::WitnessRejected)
    );
}

#[test]
fn the_vote_prover_refuses_every_invalid_witness() {
    let (case, _) = vote3();
    let profile = Profile::new(ROW).expect("tables");
    let context = profile.context(Role::Vote).expect("context");
    for fault in vote_faults(case) {
        let instance = fault.statement.instance(&profile).expect("valid");
        assert_eq!(
            proof::prove::<Gf256, _>(
                &context,
                &VoteRelation,
                instance.public(),
                instance.mu(),
                &fault.witness,
                &backend_tape(&case.tape),
            ),
            Err(ProofError::WitnessRejected),
            "{}",
            fault.name
        );
    }
    // Through the crate's own prover: another secret, and every wrong position.
    let attempt = |who: &CredentialSecret, index: u16| {
        vote::prove(
            ROW,
            &case.statement,
            who,
            index,
            ProvingTape::from_bytes(&case.tape),
        )
    };
    assert_eq!(
        attempt(&secret(&common::other_secret()), position(case)),
        Err(ProveError::WitnessRejected)
    );
    for index in [0u16, 2, 3, 33, 1023, 1024, 65_535] {
        assert_eq!(
            attempt(&secret(&case.secret), index),
            Err(ProveError::WitnessRejected),
            "position {index}"
        );
    }
    // A malformed statement is refused before the witness is looked at.
    let mut statement = case.statement.clone();
    statement.vote = 3;
    assert_eq!(
        vote::prove(
            ROW,
            &statement,
            &secret(&case.secret),
            position(case),
            ProvingTape::from_bytes(&case.tape),
        ),
        Err(ProveError::Statement(StatementError::VoteValue {
            value: 3
        }))
    );
}

// ------------------------------------------------ invalid witnesses, verifier

/// The bytes the honest prover algorithm produces from an invalid witness are
/// rejected by the verifier.
fn registration_fault_is_rejected(index: usize) {
    let case = reg_case(ROW);
    let profile = Profile::new(ROW).expect("tables");
    let context = profile.context(Role::Registration).expect("context");
    let fault: Fault<RegistrationStatement> = registration_faults(&case).swap_remove(index);
    let instance = fault.statement.instance(&profile).expect("valid");
    let forged = proof::prove_without_witness_check::<Gf256, _>(
        &context,
        &RegistrationRelation,
        instance.public(),
        instance.mu(),
        &fault.witness,
        &backend_tape(&case.tape),
    )
    .expect("the unchecked prover runs");
    assert_eq!(forged.len(), 160_148);
    assert_eq!(
        registration::verify(ROW, &fault.statement, &forged),
        Err(VerifyError::Rejected),
        "{}",
        fault.name
    );
    // The check that fails is the final challenge comparison: every field of
    // the forged proof is canonical and every opening is consistent.
    assert_eq!(
        proof::verify::<Gf256, _>(
            &context,
            &RegistrationRelation,
            instance.public(),
            instance.mu(),
            &forged,
        ),
        Err(ProofError::ChallengeMismatch),
        "{}",
        fault.name
    );
}

fn vote_fault_is_rejected(index: usize) {
    let case = vote_case(ROW, 3, 1);
    let profile = Profile::new(ROW).expect("tables");
    let context = profile.context(Role::Vote).expect("context");
    let fault: Fault<VoteStatement> = vote_faults(&case).swap_remove(index);
    let instance = fault.statement.instance(&profile).expect("valid");
    let forged = proof::prove_without_witness_check::<Gf256, _>(
        &context,
        &VoteRelation,
        instance.public(),
        instance.mu(),
        &fault.witness,
        &backend_tape(&case.tape),
    )
    .expect("the unchecked prover runs");
    assert_eq!(forged.len(), 233_012);
    assert_eq!(
        vote::verify(ROW, &fault.statement, &forged),
        Err(VerifyError::Rejected),
        "{}",
        fault.name
    );
    assert_eq!(
        proof::verify::<Gf256, _>(
            &context,
            &VoteRelation,
            instance.public(),
            instance.mu(),
            &forged,
        ),
        Err(ProofError::ChallengeMismatch),
        "{}",
        fault.name
    );
}

macro_rules! fault_tests {
    ($check:ident: $($name:ident = $index:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                $check($index);
            }
        )*
    };
}

fault_tests!(registration_fault_is_rejected:
    forged_registration_proof_0_is_rejected = 0,
    forged_registration_proof_1_is_rejected = 1,
    forged_registration_proof_2_is_rejected = 2,
    forged_registration_proof_3_is_rejected = 3,
    forged_registration_proof_4_is_rejected = 4,
    forged_registration_proof_5_is_rejected = 5,
);

fault_tests!(vote_fault_is_rejected:
    forged_vote_proof_00_is_rejected = 0,
    forged_vote_proof_01_is_rejected = 1,
    forged_vote_proof_02_is_rejected = 2,
    forged_vote_proof_03_is_rejected = 3,
    forged_vote_proof_04_is_rejected = 4,
    forged_vote_proof_05_is_rejected = 5,
    forged_vote_proof_06_is_rejected = 6,
    forged_vote_proof_07_is_rejected = 7,
    forged_vote_proof_08_is_rejected = 8,
    forged_vote_proof_09_is_rejected = 9,
    forged_vote_proof_10_is_rejected = 10,
    forged_vote_proof_11_is_rejected = 11,
    forged_vote_proof_12_is_rejected = 12,
    forged_vote_proof_13_is_rejected = 13,
    forged_vote_authorization_low_half_is_rejected = 14,
    forged_vote_authorization_high_half_is_rejected = 15,
    forged_nullifier_low_half_is_rejected = 16,
    forged_nullifier_high_half_is_rejected = 17,
);

#[test]
fn the_fault_lists_cover_the_prototype_and_all_output_halves() {
    assert_eq!(registration_faults(&reg_case(ROW)).len(), 6);
    assert_eq!(vote_faults(&vote_case(ROW, 3, 1)).len(), 18);
}

// ------------------------------------------------------ statement mutations

/// The registration statement with field `index` changed: the body context
/// (one byte appended), one of the six opaque fields (one bit), `C` (one bit),
/// `auth` (one bit).
fn changed_registration(statement: &RegistrationStatement, index: usize) -> RegistrationStatement {
    let mut body = statement.body_context().as_bytes().to_vec();
    let mut encs: Vec<Vec<u8>> = statement
        .context()
        .fields()
        .iter()
        .map(|field| field.to_vec())
        .collect();
    let mut commitment = *statement.commitment();
    let mut auth = *statement.auth();
    match index {
        0 => body.push(b'!'),
        1..=6 => {
            let field = &mut encs[index - 1];
            let bit = 8 * (field.len() / 2) + 3;
            flip(field, bit);
        }
        7 => flip(&mut commitment.0, 8 * 64 + 3),
        _ => flip(&mut auth.0, 8 * 32 + 3),
    }
    let fields: [&[u8]; 6] = core::array::from_fn(|i| encs[i].as_slice());
    RegistrationStatement::new(
        BodyContext::new(&body).expect("bounded"),
        common::context_of(fields),
        commitment,
        auth,
    )
    .expect("statement")
}

fn registration_changes_are_rejected(indices: core::ops::Range<usize>) {
    let (case, proof) = reg();
    for index in indices {
        let changed = changed_registration(&case.statement, index);
        assert_ne!(changed, case.statement);
        assert!(
            is_rejected(registration::verify(ROW, &changed, proof)),
            "field {index}"
        );
    }
}

#[test]
fn a_registration_proof_is_rejected_under_a_changed_body_context_or_network_or_authority() {
    registration_changes_are_rejected(0..3);
}

#[test]
fn a_registration_proof_is_rejected_under_a_changed_assignment_or_attempt() {
    registration_changes_are_rejected(3..6);
}

#[test]
fn a_registration_proof_is_rejected_under_a_changed_role_commitment_or_auth() {
    registration_changes_are_rejected(6..9);
}

/// The vote statement over `list` for the same body, with `R` and `S` recomputed.
fn with_list(statement: &VoteStatement, list: Vec<Commitment>) -> VoteStatement {
    let mut out = statement.clone();
    out.list_digest = sealed_list::digest_unvalidated(&out.body_digest, &list).expect("frame");
    out.size = u16::try_from(list.len()).expect("small");
    out.list = list;
    out
}

#[test]
fn a_vote_proof_is_rejected_under_a_changed_body_scope_or_nullifier() {
    let (case, proof) = vote3();
    // Another body, with R recomputed for it.
    let mut changed = case.statement.clone();
    flip(&mut changed.body_digest.0, 8 * 32 + 3);
    let changed = with_list(&changed, changed.list.clone());
    assert_eq!(changed.validate(), Ok(()));
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
    let mut changed = case.statement.clone();
    flip(&mut changed.scope.0, 8 * 32 + 3);
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
    let mut changed = case.statement.clone();
    flip(&mut changed.nullifier.0, 8 * 32 + 3);
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
}

#[test]
fn a_vote_proof_is_rejected_under_a_changed_vote_value_or_policy() {
    let (case, proof) = vote3();
    for vote_byte in [1u8, 2] {
        let mut changed = case.statement.clone();
        changed.vote = vote_byte;
        assert!(is_rejected(vote::verify(ROW, &changed, proof)));
    }
    let mut changed = case.statement.clone();
    flip(&mut changed.policy_hash.0, 8 * 32 + 3);
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
}

#[test]
fn a_vote_proof_is_rejected_under_a_changed_list() {
    let (case, proof) = vote3();
    // One more entry, R and S recomputed.
    let extra =
        secret(&common::array(&fx("extra-member", 48))).commitment(&case.statement.body_digest);
    let mut longer = case.statement.list.clone();
    longer.push(extra);
    longer.sort_unstable();
    let changed = with_list(&case.statement, longer);
    assert_eq!(changed.validate(), Ok(()));
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
    // One bit of an entry that is not the member's, R recomputed. The last byte
    // keeps the order of these fixtures.
    let mut entries = case.statement.list.clone();
    let other = (case.index + 1) % 3;
    flip(&mut entries[other].0, 8 * 127);
    let changed = with_list(&case.statement, entries);
    assert_eq!(changed.validate(), Ok(()));
    assert!(is_rejected(vote::verify(ROW, &changed, proof)));
}

#[test]
fn a_vote_statement_that_fails_public_validation_is_malformed_not_rejected() {
    let (case, proof) = vote3();
    let refused = |statement: &VoteStatement| match vote::verify(ROW, statement, proof) {
        Err(VerifyError::Statement(error)) => error,
        other => panic!("expected a malformed statement, got {other:?}"),
    };
    let mut changed = case.statement.clone();
    changed.vote = 3;
    assert_eq!(refused(&changed), StatementError::VoteValue { value: 3 });
    let mut changed = case.statement.clone();
    flip(&mut changed.list_digest.0, 8 * 32 + 3);
    assert_eq!(refused(&changed), StatementError::ListDigest);
    let mut changed = case.statement.clone();
    changed.size += 1;
    assert_eq!(
        refused(&changed),
        StatementError::ListLength {
            declared: 4,
            actual: 3
        }
    );
    // One bit of a list entry with a stale R.
    let mut changed = case.statement.clone();
    flip(&mut changed.list[2].0, 8 * 127);
    assert_eq!(refused(&changed), StatementError::ListDigest);
    // The list order, with a stale and with a recomputed R.
    let mut changed = case.statement.clone();
    changed.list.swap(0, 2);
    assert_eq!(
        refused(&changed),
        StatementError::List(ListError::Order { index: 1 })
    );
    let recomputed = with_list(&changed, changed.list.clone());
    assert_eq!(
        refused(&recomputed),
        StatementError::List(ListError::Order { index: 1 })
    );
    // A duplicate, two entries, a thousand and one entries.
    let mut changed = case.statement.clone();
    changed.list[1] = changed.list[0];
    assert_eq!(
        refused(&changed),
        StatementError::List(ListError::Order { index: 1 })
    );
    let changed = with_list(&case.statement, case.statement.list[..2].to_vec());
    assert_eq!(
        refused(&changed),
        StatementError::List(ListError::Size { actual: 2 })
    );
    let (large, _) = common::member_list(1000);
    let mut entries = large.entries().to_vec();
    entries.push(Commitment([0xff; 128]));
    let changed = with_list(&case.statement, entries);
    assert_eq!(
        refused(&changed),
        StatementError::List(ListError::Size { actual: 1001 })
    );
}

// --------------------------------------------------------------- row and role

#[test]
fn a_wrong_length_and_trailing_bytes_are_malformed() {
    let (reg_case, reg_proof) = reg();
    let (vote_case, vote_proof) = vote3();
    let length_error = |expected: usize, actual: usize| {
        Err::<(), _>(VerifyError::ProofLength { expected, actual })
    };
    let mut longer = reg_proof.clone();
    longer.push(0);
    assert_eq!(
        registration::verify(ROW, &reg_case.statement, &longer),
        length_error(160_148, 160_149)
    );
    assert_eq!(
        registration::verify(ROW, &reg_case.statement, &reg_proof[..160_147]),
        length_error(160_148, 160_147)
    );
    assert_eq!(
        registration::verify(ROW, &reg_case.statement, &[]),
        length_error(160_148, 0)
    );
    let mut longer = vote_proof.clone();
    longer.extend_from_slice(&[0; 4]);
    assert_eq!(
        vote::verify(ROW, &vote_case.statement, &longer),
        length_error(233_012, 233_016)
    );
    // The other relation's proof and the other row are wrong lengths: no row or
    // relation is detected from the bytes.
    assert_eq!(
        vote::verify(ROW, &vote_case.statement, reg_proof),
        length_error(233_012, 160_148)
    );
    assert_eq!(
        registration::verify(ROW, &reg_case.statement, vote_proof),
        length_error(160_148, 233_012)
    );
    #[cfg(feature = "diagnostics")]
    {
        assert_eq!(
            registration::verify(Row::Comparator, &reg_case.statement, reg_proof),
            length_error(109_498, 160_148)
        );
        assert_eq!(
            vote::verify(Row::Comparator, &vote_case.statement, vote_proof),
            length_error(158_074, 233_012)
        );
    }
    // The length is checked before the statement.
    let mut malformed = vote_case.statement.clone();
    malformed.vote = 7;
    assert_eq!(
        vote::verify(ROW, &malformed, &vote_proof[1..]),
        length_error(233_012, 233_011)
    );
    // At the right length the malformed statement has its own error, whatever
    // the proof bytes are.
    assert_eq!(
        vote::verify(ROW, &malformed, vote_proof),
        Err(VerifyError::Statement(StatementError::VoteValue {
            value: 7
        }))
    );
    assert_eq!(
        vote::verify(ROW, &malformed, &vec![0u8; 233_012]),
        Err(VerifyError::Statement(StatementError::VoteValue {
            value: 7
        }))
    );
    let mut malformed = vote_case.statement.clone();
    malformed.list.swap(0, 1);
    assert_eq!(
        vote::verify(ROW, &malformed, &vec![0u8; 233_012]),
        Err(VerifyError::Statement(StatementError::List(
            ListError::Order { index: 1 }
        )))
    );
    assert_eq!(vote::verify(ROW, &malformed, &[]), length_error(233_012, 0));
}

/// At the right length, the role and the row are bound by the prefix: the
/// backend verifier on the candidate row's geometry rejects a valid proof under
/// the other role's prefix and (with the `diagnostics` feature) under the
/// comparator row's prefix.
#[test]
fn a_valid_proof_is_rejected_under_another_role_or_row_prefix() {
    let (case, proof_bytes) = reg();
    let fast = Profile::new(ROW).expect("tables");
    let instance = case.statement.instance(&fast).expect("valid");
    let verify_under = |prefix: &[u8; 77]| {
        let context = ProofContext::extended(Namespace::new(prefix).expect("77 bytes"), ROW.vole())
            .expect("non-empty prefix");
        proof::verify::<Gf256, _>(
            &context,
            &RegistrationRelation,
            instance.public(),
            instance.mu(),
            proof_bytes,
        )
    };
    assert_eq!(verify_under(fast.prefix(Role::Registration)), Ok(()));
    // Nothing but the prefix differs, so nothing but the final challenge
    // comparison can fail.
    assert_eq!(
        verify_under(fast.prefix(Role::Vote)),
        Err(ProofError::ChallengeMismatch)
    );
    #[cfg(feature = "diagnostics")]
    {
        let small = Profile::new(Row::Comparator).expect("tables");
        assert_eq!(
            verify_under(small.prefix(Role::Registration)),
            Err(ProofError::ChallengeMismatch)
        );
        // A statement of the comparator row (another D, hence another D_reg, auth
        // and mu) does not verify the candidate row's proof either.
        let other = small_statement(case);
        assert!(is_rejected(registration::verify(ROW, &other, proof_bytes)));
    }
}

/// The same for the vote proof: it is not a proof under the registration prefix
/// or (with the `diagnostics` feature) under the comparator row's vote prefix.
#[test]
fn a_valid_vote_proof_is_rejected_under_another_role_or_row_prefix() {
    let (case, proof_bytes) = vote3();
    let fast = Profile::new(ROW).expect("tables");
    let instance = case.statement.instance(&fast).expect("valid");
    let verify_under = |prefix: &[u8; 77]| {
        let context = ProofContext::extended(Namespace::new(prefix).expect("77 bytes"), ROW.vole())
            .expect("non-empty prefix");
        proof::verify::<Gf256, _>(
            &context,
            &VoteRelation,
            instance.public(),
            instance.mu(),
            proof_bytes,
        )
    };
    assert_eq!(verify_under(fast.prefix(Role::Vote)), Ok(()));
    assert_eq!(
        verify_under(fast.prefix(Role::Registration)),
        Err(ProofError::ChallengeMismatch)
    );
    #[cfg(feature = "diagnostics")]
    {
        let small = Profile::new(Row::Comparator).expect("tables");
        assert_eq!(
            verify_under(small.prefix(Role::Vote)),
            Err(ProofError::ChallengeMismatch)
        );
    }
}

/// The registration statement of the same secret on the comparator row.
#[cfg(feature = "diagnostics")]
fn small_statement(case: &RegCase) -> RegistrationStatement {
    let small = Profile::new(Row::Comparator).expect("tables");
    RegistrationStatement::for_secret(
        &small,
        &secret(&case.secret),
        common::body_context(),
        common::context_of(common::ENCS),
    )
    .expect("statement")
}

// ------------------------------------------------------------- proof bytes

/// Flip sampled bits of proof field `field` of both honest proofs: the first
/// bit, the last bit and one in between.
fn flips_in_field_are_rejected(field: usize) {
    let (reg_case, reg_proof) = reg();
    let (vote_case, vote_proof) = vote3();
    for role in Role::ALL {
        let segment = ROW.proof_layout(role)[field];
        // Four fixture bytes: the offset ranges over the whole field, also over
        // the 1.15 million bits of the corrections.
        let draw = u32::from_le_bytes(common::array(&fx(
            &format!("proof-flip/{field}/{role:?}"),
            4,
        )));
        let middle = usize::try_from(draw).expect("32 bits fit") % (8 * segment.len);
        for bit in [0, middle, 8 * segment.len - 1] {
            let result = match role {
                Role::Registration => {
                    let mut bytes = reg_proof.clone();
                    flip(&mut bytes, 8 * segment.offset + bit);
                    registration::verify(ROW, &reg_case.statement, &bytes)
                }
                Role::Vote => {
                    let mut bytes = vote_proof.clone();
                    flip(&mut bytes, 8 * segment.offset + bit);
                    vote::verify(ROW, &vote_case.statement, &bytes)
                }
            };
            assert!(
                is_rejected(result),
                "{:?} bit {bit} of {role:?}: {result:?}",
                segment.field
            );
        }
    }
}

/// The corrections field is one witness-sized correction per repetition and is
/// nine tenths of a proof: flip bit 3 of the first byte of the first, the middle
/// and the last correction.
fn a_flip_in_a_correction_is_rejected(role: Role) {
    let segment = ROW.proof_layout(role)[0];
    assert_eq!(segment.field, ProofField::Corrections);
    let stride = match role {
        Role::Registration => 35_840 / 8,
        Role::Vote => 53_504 / 8,
    };
    assert_eq!(segment.len % stride, 0);
    let corrections = segment.len / stride;
    assert_eq!(corrections, 32);
    for k in [0, corrections / 2, corrections - 1] {
        let bit = 8 * (segment.offset + k * stride) + 3;
        let result = match role {
            Role::Registration => {
                let (case, proof) = reg();
                let mut bytes = proof.clone();
                flip(&mut bytes, bit);
                registration::verify(ROW, &case.statement, &bytes)
            }
            Role::Vote => {
                let (case, proof) = vote3();
                let mut bytes = proof.clone();
                flip(&mut bytes, bit);
                vote::verify(ROW, &case.statement, &bytes)
            }
        };
        assert!(
            is_rejected(result),
            "correction {k} of {role:?}: {result:?}"
        );
    }
}

#[test]
fn a_flip_in_the_first_middle_and_last_registration_correction_is_rejected() {
    a_flip_in_a_correction_is_rejected(Role::Registration);
}

#[test]
fn a_flip_in_the_first_middle_and_last_vote_correction_is_rejected() {
    a_flip_in_a_correction_is_rejected(Role::Vote);
}

fault_tests!(flips_in_field_are_rejected:
    flips_in_the_corrections_are_rejected = 0,
    flips_in_the_mult_corrections_are_rejected = 1,
    flips_in_u_tilde_are_rejected = 2,
    flips_in_the_masked_witness_are_rejected = 3,
    flips_in_the_coefficients_are_rejected = 4,
    flips_in_the_hidden_leaf_commitments_are_rejected = 5,
    flips_in_the_node_seeds_are_rejected = 6,
    flips_in_the_challenge_are_rejected = 7,
    flips_in_iv_pre_are_rejected = 8,
    flips_in_the_salt_are_rejected = 9,
    flips_in_the_counter_are_rejected = 10,
);

/// Holding mu fixed isolates the authorization relation from transcript binding.
#[test]
fn a_vote_flip_is_rejected_even_with_the_original_message_digest() {
    let (case, bytes) = vote3();
    let profile = Profile::new(ROW).expect("profile");
    let context = profile.context(Role::Vote).expect("context");
    let original = case.statement.instance(&profile).expect("valid");
    assert_eq!(
        proof::verify::<Gf256, _>(
            &context,
            &VoteRelation,
            original.public(),
            original.mu(),
            bytes
        ),
        Ok(())
    );
    let mut changed = case.statement.clone();
    changed.vote = 1;
    let changed = changed.instance(&profile).expect("valid");
    assert_eq!(
        proof::verify::<Gf256, _>(
            &context,
            &VoteRelation,
            changed.public(),
            original.mu(),
            bytes
        ),
        Err(ProofError::ChallengeMismatch)
    );
}

#[test]
fn retired_descriptors_and_out_of_range_counters_are_refused() {
    let (case, bytes) = vote3();
    for counter in [1u32 << 20, u32::MAX] {
        let mut changed = bytes.clone();
        let end = changed.len();
        changed[end - 4..].copy_from_slice(&counter.to_le_bytes());
        assert_eq!(
            vote::verify(ROW, &case.statement, &changed),
            Err(VerifyError::Rejected)
        );
    }
    let profile = Profile::new(ROW).expect("profile");
    let mut encoded =
        iroha_parliament_ballot_proof::test_codec::encode_vote(&profile, &case.statement)
            .expect("encode");
    let old = common::hex(
        "44028deb664beb1a06a336cd6f622c223a5c15741dfafa72b55e19cbb42f287ba48979a0d6a8342c80034cc88b87fcb055f0db686fe97beffb2197bc7f85e910",
    );
    let offset = 2 + b"PARL/TEST/VOTE/v1".len() + 2 + 4;
    encoded[offset..offset + 64].copy_from_slice(&old);
    assert_eq!(
        iroha_parliament_ballot_proof::test_codec::decode_vote(&profile, &encoded),
        Err(iroha_parliament_ballot_proof::test_codec::TestCodecError::DescriptorDigest)
    );
}
