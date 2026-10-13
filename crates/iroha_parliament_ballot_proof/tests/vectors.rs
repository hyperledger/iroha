//! Cross-implementation vectors: the Rust code reproduces, from the same inputs
//! and tape, every derived public value, the witness digest, the digest of every
//! proof field and of the complete proof, and the accepted counter of the
//! project's own pure-Python prototype. These are not official vectors.

mod common;

use common::{Vector, array, shake256_64};
use iroha_parliament_ballot_proof::{
    credential::{
        AUTHORIZATION_TAG, COMMITMENT_TAG, CredentialSecret, NULLIFIER_TAG, body_digest,
        policy_hash, proposal_digest, registration_digest, scope_digest,
    },
    framing::{BodyContext, Commitment, Digest64},
    keccak_relation::{evaluate, public_block},
    layout::PERMUTATION_OFFSETS,
    profile::{Profile, ProofField, Role, Row},
    proving::ProvingTape,
    registration::{self, RegistrationStatement},
    sealed_list::{self, SealedList},
    test_codec,
    vote::{self, Vote, VoteStatement},
};

/// The vector's names of the proof fields, in layout order.
const FIELD_NAMES: [(ProofField, &str); 11] = [
    (ProofField::Corrections, "c"),
    (ProofField::MultCorrections, "c_mult"),
    (ProofField::UTilde, "u_tilde"),
    (ProofField::MaskedWitness, "d"),
    (ProofField::Coefficients, "a_tilde_1_6"),
    (ProofField::HiddenLeafCommitments, "hidden_leaf_commitments"),
    (ProofField::NodeSeeds, "node_seeds"),
    (ProofField::Challenge, "chall_3"),
    (ProofField::IvPre, "iv_pre"),
    (ProofField::Salt, "salt"),
    (ProofField::Counter, "ctr"),
];

/// The descriptor values every case file carries.
fn check_profile(vector: &Vector, profile: &Profile) {
    assert_eq!(
        vector.get("P16"),
        iroha_parliament_ballot_proof::profile::P16
    );
    assert_eq!(vector.get("T_crt"), profile.table_digest().as_bytes());
    assert_eq!(vector.get("descriptor"), profile.descriptor());
    assert_eq!(vector.get("D"), profile.descriptor_digest().as_bytes());
    assert_eq!(
        vector.get("NS_REG"),
        profile.namespace_digest(Role::Registration).as_bytes()
    );
    assert_eq!(
        vector.get("NS_VOTE"),
        profile.namespace_digest(Role::Vote).as_bytes()
    );
}

/// The proof against the per-field digests, the counter and the total digest.
fn check_proof(vector: &Vector, row: Row, role: Role, proof: &[u8]) {
    assert_eq!(proof.len(), vector.int("proof_len_u32"));
    assert_eq!(proof.len(), row.proof_bytes(role));
    for (segment, (field, name)) in row.proof_layout(role).iter().zip(FIELD_NAMES) {
        assert_eq!(segment.field, field);
        assert_eq!(
            segment.offset,
            vector.int(&format!("field_{name}_offset_u32")),
            "{name}"
        );
        assert_eq!(
            segment.len,
            vector.int(&format!("field_{name}_len_u32")),
            "{name}"
        );
        assert_eq!(
            shake256_64(&proof[segment.offset..segment.offset + segment.len]),
            vector.get(&format!("field_{name}_shake256_64")),
            "proof field {name}"
        );
    }
    let expected: &[u8] = match (row, role) {
        (Row::Candidate, Role::Registration) => include_bytes!("fixtures/reg_fast.proof"),
        (Row::Comparator, Role::Registration) => include_bytes!("fixtures/reg_comparator.proof"),
        (Row::Candidate, Role::Vote) => match vector.int("S_u16") {
            3 => include_bytes!("fixtures/vote_S3_i1_fast.proof"),
            500 => include_bytes!("fixtures/vote_S500_i250_fast.proof"),
            1000 => include_bytes!("fixtures/vote_S1000_i500_fast.proof"),
            _ => panic!("unsupported fixture"),
        },
        (Row::Comparator, Role::Vote) => match vector.int("S_u16") {
            3 => include_bytes!("fixtures/vote_S3_i1_comparator.proof"),
            500 => include_bytes!("fixtures/vote_S500_i250_comparator.proof"),
            1000 => include_bytes!("fixtures/vote_S1000_i500_comparator.proof"),
            _ => panic!("unsupported fixture"),
        },
    };
    assert_eq!(
        proof, expected,
        "complete independently generated proof bytes"
    );
    assert_eq!(proof[proof.len() - 4..], *vector.get("ctr_u32"));
    assert_eq!(shake256_64(proof), vector.get("proof_shake256_64"));
}

/// The SHAKE messages and the first and last Keccak states of the intermediate
/// file, against this crate's [`public_block`] and [`evaluate`].
///
/// For both permutations: bytes `0..4` (tag), `4..20` (`P16`) and `68..132`
/// (public input) of the stored 132-byte message are those of the public block,
/// and bytes `20..68` are the secret; the stored initial state is the public
/// block with the secret added; the stored state after 24 rounds starts with
/// the 136 bytes this crate squeezes, whose first 128 or 64 are the output the
/// relation constrains. The stored prover coefficient vectors
/// (`constraint_*_a*`) are **not** reproduced here: they need the VOLE tags of
/// the run, which this crate's API does not expose; the proof-field digests
/// cover them.
fn check_evaluations(intermediate: &Vector, secret: &[u8; 48], blocks: &[(char, [u8; 200])]) {
    for &(name, block) in blocks {
        let message = intermediate.get(&format!("shake_message_{name}"));
        assert_eq!(message.len(), 132, "message {name}");
        assert_eq!(message[..20], block[..20], "tag and P16 of {name}");
        assert_eq!(message[20..68], *secret, "secret of {name}");
        assert_eq!(message[68..], block[68..132], "public input of {name}");
        assert_eq!(block[20..68], [0u8; 48], "secret positions of {name}");

        let mut initial = block;
        for (slot, byte) in initial[20..68].iter_mut().zip(secret) {
            *slot ^= byte;
        }
        assert_eq!(
            intermediate.get(&format!("state_{name}_round00_initial")),
            initial,
            "initial state of {name}"
        );
        let evaluation = evaluate(&block, secret);
        let mut squeezed = [0u8; 136];
        evaluation.squeeze(&mut squeezed);
        let last = intermediate.get(&format!("state_{name}_round24_final"));
        assert_eq!(last.len(), 200, "final state of {name}");
        assert_eq!(last[..136], squeezed, "squeezed output of {name}");
    }
}

/// The committed states of the witness against the intermediate file.
fn check_states(intermediate: &Vector, witness: &[u8], names: &[char]) {
    for (permutation, offset) in names.iter().copied().zip(PERMUTATION_OFFSETS) {
        for group in 1..=11usize {
            let start = offset + 1600 * (group - 1);
            let name = format!(
                "state_{permutation}_round{:02}_witness_offset_{start}",
                2 * group
            );
            assert_eq!(
                witness[start / 8..start / 8 + 200],
                *intermediate.get(&name),
                "{name}"
            );
        }
    }
}

fn registration_vector(row: Row, text: &str, intermediate: &str) {
    let vector = Vector::parse(text);
    let intermediate = Vector::parse(intermediate);
    let profile = Profile::new(row).expect("tables");
    check_profile(&vector, &profile);

    // The fixture builder of the other tests is the prototype's.
    let case = common::reg_case(row);
    assert_eq!(vector.get("sk"), case.secret);
    assert_eq!(vector.get("tape"), case.tape);
    assert_eq!(vector.get("enc_body_context"), common::ENC_BODY);

    let secret = CredentialSecret::from_bytes(&array(vector.get("sk")));
    let body_context = BodyContext::new(vector.get("enc_body_context")).expect("bounded");
    let context = common::context_of([
        vector.get("enc_network_id"),
        vector.get("enc_authority"),
        vector.get("enc_assignment_id"),
        vector.get("enc_governance_attempt_id"),
        vector.get("enc_election_attempt_id"),
        vector.get("enc_body_role"),
    ]);
    let body = body_digest(&body_context).expect("frame");
    assert_eq!(vector.get("B"), body.as_bytes());
    let commitment = secret.commitment(&body);
    assert_eq!(vector.get("C"), commitment.as_bytes());
    let digest = registration_digest(
        profile.descriptor_digest(),
        &body_context,
        &context,
        &body,
        &commitment,
    )
    .expect("frame");
    assert_eq!(vector.get("D_reg"), digest.as_bytes());
    let auth = secret.authorization(&digest);
    assert_eq!(vector.get("auth"), auth.as_bytes());

    let statement =
        RegistrationStatement::for_secret(&profile, &secret, body_context, context).expect("valid");
    assert_eq!(statement, case.statement);
    assert_eq!(statement.commitment(), &commitment);
    assert_eq!(statement.auth(), &auth);
    assert_eq!(vector.get("PREFIX_REG"), profile.prefix(Role::Registration));
    assert_eq!(vector.get("F_REG"), statement.frame().expect("frame"));
    let instance = statement.instance(&profile).expect("valid");
    assert_eq!(vector.get("mu"), instance.mu());

    assert_eq!(vector.int("witness_bits_u32"), 35_840);
    assert_eq!(vector.int("n_constraints_u32"), 72_576);
    let pad: [u8; 32] = array(vector.get("tape_pad"));
    assert_eq!(vector.get("tape")[48..80], pad);
    let witness = registration::witness(instance.public(), &secret, &pad);
    assert_eq!(shake256_64(&witness), vector.get("witness_shake256_64"));
    check_states(&intermediate, &witness, &['C', 'A']);
    check_evaluations(
        &intermediate,
        &array(vector.get("sk")),
        &[
            ('C', public_block(COMMITMENT_TAG, body.as_bytes())),
            ('A', public_block(AUTHORIZATION_TAG, digest.as_bytes())),
        ],
    );
    // The outputs the relation constrains are the stored final states.
    assert_eq!(
        intermediate.get("state_C_round24_final")[..128],
        *commitment.as_bytes()
    );
    assert_eq!(
        intermediate.get("state_A_round24_final")[..64],
        *auth.as_bytes()
    );

    let encoded = test_codec::encode_registration(&profile, &statement).expect("encodes");
    assert_eq!(
        shake256_64(&encoded),
        vector.get("test_statement_shake256_64")
    );
    assert_eq!(
        test_codec::decode_registration(&profile, &encoded),
        Ok(statement.clone())
    );

    let tape = ProvingTape::from_bytes(&array(vector.get("tape")));
    let proof = registration::prove(row, &statement, &secret, tape).expect("honest proof");
    check_proof(&vector, row, Role::Registration, &proof);
    let record = test_codec::encode_record(&encoded, &proof).expect("encodes");
    assert_eq!(shake256_64(&record), vector.get("test_record_shake256_64"));
    assert_eq!(
        test_codec::decode_record(&profile, Role::Registration, &record),
        Ok((&encoded[..], &proof[..]))
    );
    assert_eq!(registration::verify(row, &statement, &proof), Ok(()));
}

/// The list of a vote case: from its file, or re-derived by the prototype's
/// fixture rule (members `0 .. S`, sorted) when no file is stored.
fn vote_list(vector: &Vector, list_text: Option<&str>) -> SealedList {
    let size = vector.int("S_u16");
    let derived = common::member_list(size).0;
    let list = list_text.map_or_else(
        || derived.clone(),
        |text| {
            let file = Vector::parse(text);
            let entries = (0..size)
                .map(|i| Commitment(array(file.get(&format!("L_{i:04}")))))
                .collect();
            SealedList::new(entries).expect("sealed")
        },
    );
    assert_eq!(list, derived);
    assert_eq!(
        shake256_64(&sealed_list::concat(list.entries())),
        vector.get("list_concat_shake256_64")
    );
    list
}

fn vote_vector(row: Row, text: &str, intermediate: &str, list_text: Option<&str>) {
    let vector = Vector::parse(text);
    let intermediate = Vector::parse(intermediate);
    let profile = Profile::new(row).expect("tables");
    check_profile(&vector, &profile);

    let size = vector.int("S_u16");
    let index = vector.int("index_u16");
    let case = common::vote_case(row, size, index);
    assert_eq!(vector.get("sk"), case.secret);
    assert_eq!(vector.get("tape"), case.tape);

    let secret = CredentialSecret::from_bytes(&array(vector.get("sk")));
    let body = body_digest(&BodyContext::new(vector.get("enc_body_context")).expect("bounded"))
        .expect("frame");
    assert_eq!(vector.get("B"), body.as_bytes());
    let proposal = proposal_digest(vector.get("enc_canonical_proposal_content")).expect("frame");
    assert_eq!(vector.get("proposal_digest"), proposal.as_bytes());
    let scope = scope_digest(
        &common::opaque(vector.get("enc_network_id")),
        &proposal,
        &common::opaque(vector.get("enc_governance_attempt_id")),
        &common::opaque(vector.get("enc_body_instance_id")),
    )
    .expect("frame");
    assert_eq!(vector.get("scope"), scope.as_bytes());
    let policy = policy_hash(vector.get("enc_complete_frozen_policy")).expect("frame");
    assert_eq!(vector.get("policy_hash"), policy.as_bytes());

    let list = vote_list(&vector, list_text);
    assert_eq!(list.size(), size);
    let member = Commitment(array(vector.get("C_member")));
    assert_eq!(secret.commitment(&body), member);
    let position = u16::try_from(index).expect("at most 1000");
    assert_eq!(list.position(&member), Some(position));
    assert_eq!(
        vector.get("R"),
        list.digest(&body).expect("frame").as_bytes()
    );
    let nullifier = secret.nullifier(&scope);
    assert_eq!(vector.get("nf"), nullifier.as_bytes());
    let vote_value = Vote::from_byte(vector.get("vote_u8")[0]).expect("a vote");

    let statement = VoteStatement::new(
        body,
        scope,
        &list,
        nullifier,
        Digest64(array(vector.get("auth_v"))),
        vote_value,
        policy,
    )
    .expect("valid");
    assert_eq!(
        statement
            .authorization_digest(&profile)
            .expect("D_v")
            .as_bytes(),
        vector.get("D_v")
    );
    assert_eq!(
        secret.vote_authorization(&statement.authorization_digest(&profile).expect("D_v")),
        statement.auth_v
    );
    assert_eq!(statement, case.statement);
    assert_eq!(statement.list_digest, Digest64(array(vector.get("R"))));
    assert_eq!(vector.get("PREFIX_VOTE"), profile.prefix(Role::Vote));
    let frame = statement.frame().expect("frame");
    if vector.has("F_VOTE") {
        assert_eq!(vector.get("F_VOTE"), frame);
    }
    assert_eq!(shake256_64(&frame), vector.get("F_VOTE_shake256_64"));
    let instance = statement.instance(&profile).expect("valid");
    assert_eq!(vector.get("mu"), instance.mu());

    assert_eq!(vector.int("witness_bits_u32"), 53_504);
    assert_eq!(vector.int("n_constraints_u32"), 108_931);
    let pad: [u8; 32] = array(vector.get("tape_pad"));
    let witness = vote::witness(instance.public(), &secret, position, &pad);
    assert_eq!(shake256_64(&witness), vector.get("witness_shake256_64"));
    check_states(&intermediate, &witness, &['C', 'N', 'V']);
    check_evaluations(
        &intermediate,
        &array(vector.get("sk")),
        &[
            ('C', public_block(COMMITMENT_TAG, body.as_bytes())),
            ('N', public_block(NULLIFIER_TAG, scope.as_bytes())),
            (
                'V',
                public_block(
                    iroha_parliament_ballot_proof::credential::VOTE_AUTHORIZATION_TAG,
                    statement
                        .authorization_digest(&profile)
                        .expect("D_v")
                        .as_bytes(),
                ),
            ),
        ],
    );
    assert_eq!(
        intermediate.get("state_C_round24_final")[..128],
        *member.as_bytes()
    );
    assert_eq!(
        intermediate.get("state_N_round24_final")[..128],
        *nullifier.as_bytes()
    );
    assert_eq!(witness[6680..6684], *intermediate.get("selector_a_u32"));
    assert_eq!(witness[6684..6688], *intermediate.get("selector_b_u32"));

    let encoded = test_codec::encode_vote(&profile, &statement).expect("encodes");
    assert_eq!(
        shake256_64(&encoded),
        vector.get("test_statement_shake256_64")
    );
    assert_eq!(
        test_codec::decode_vote(&profile, &encoded),
        Ok(statement.clone())
    );

    let tape = ProvingTape::from_bytes(&array(vector.get("tape")));
    let proof = vote::prove(row, &statement, &secret, position, tape).expect("honest proof");
    check_proof(&vector, row, Role::Vote, &proof);
    let record = test_codec::encode_record(&encoded, &proof).expect("encodes");
    assert_eq!(shake256_64(&record), vector.get("test_record_shake256_64"));
    assert_eq!(vote::verify(row, &statement, &proof), Ok(()));
}

#[test]
fn registration_on_the_candidate_row_reproduces_the_prototype() {
    registration_vector(
        Row::Candidate,
        include_str!("fixtures/reg_fast.txt"),
        include_str!("fixtures/reg_fast.intermediate.txt"),
    );
}

#[test]
fn registration_on_the_comparator_row_reproduces_the_prototype() {
    registration_vector(
        Row::Comparator,
        include_str!("fixtures/reg_comparator.txt"),
        include_str!("fixtures/reg_comparator.intermediate.txt"),
    );
}

#[test]
fn vote_with_three_members_on_the_candidate_row_reproduces_the_prototype() {
    vote_vector(
        Row::Candidate,
        include_str!("fixtures/vote_S3_i1_fast.txt"),
        include_str!("fixtures/vote_S3_i1_fast.intermediate.txt"),
        Some(include_str!("fixtures/vote_S3_i1_fast.list.txt")),
    );
}

#[test]
fn vote_with_three_members_on_the_comparator_row_reproduces_the_prototype() {
    vote_vector(
        Row::Comparator,
        include_str!("fixtures/vote_S3_i1_comparator.txt"),
        include_str!("fixtures/vote_S3_i1_comparator.intermediate.txt"),
        Some(include_str!("fixtures/vote_S3_i1_comparator.list.txt")),
    );
}

#[test]
fn vote_with_a_thousand_members_on_the_candidate_row_reproduces_the_prototype() {
    vote_vector(
        Row::Candidate,
        include_str!("fixtures/vote_S1000_i500_fast.txt"),
        include_str!("fixtures/vote_S1000_i500_fast.intermediate.txt"),
        None,
    );
}

#[test]
fn vote_with_five_hundred_members_on_the_candidate_row_reproduces_the_prototype() {
    vote_vector(
        Row::Candidate,
        include_str!("fixtures/vote_S500_i250_fast.txt"),
        include_str!("fixtures/vote_S500_i250_fast.intermediate.txt"),
        None,
    );
}

#[test]
fn vote_with_five_hundred_members_on_the_comparator_row_reproduces_the_prototype() {
    vote_vector(
        Row::Comparator,
        include_str!("fixtures/vote_S500_i250_comparator.txt"),
        include_str!("fixtures/vote_S500_i250_comparator.intermediate.txt"),
        None,
    );
}

#[test]
fn vote_with_a_thousand_members_on_the_comparator_row_reproduces_the_prototype() {
    vote_vector(
        Row::Comparator,
        include_str!("fixtures/vote_S1000_i500_comparator.txt"),
        include_str!("fixtures/vote_S1000_i500_comparator.intermediate.txt"),
        None,
    );
}
