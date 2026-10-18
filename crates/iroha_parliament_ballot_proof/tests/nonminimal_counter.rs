//! Constructive acceptance of a valid counter after the prover's first valid one.
//!
//! The existing independent Python fixtures supply the fixed transcript prefix,
//! all seven `QuickSilver` coefficients, root seed and IV. Only the BAVC opening,
//! challenge and counter change. This tests the verifier's acceptance rule, not
//! a change to the prover's mandatory first-acceptable-counter rule.

mod common;

use common::{Vector, array, shake256_64};
use iroha_parliament_ballot_proof::{
    profile::{LEVEL, Profile, Role, Row},
    proving::VerifyError,
    registration, vote,
};
use iroha_zkp_vole::{
    bavc::{self, BavcError},
    codec::{self, Field, ProofFields},
    params::ProofParams,
    transcript::{Challenge3, derive_iv},
    variant::{Construction, EXTENDED_LAST_COUNTER},
};

/// One unchanged independent fixture and its first later acceptable counter.
struct CounterCase {
    row: Row,
    role: Role,
    text: &'static str,
    proof: &'static [u8],
    later_counter: u32,
    later_digest: &'static str,
}

/// Reopen the same commitment at the pinned later challenge and verify both proofs.
fn check_nonminimal(case: &CounterCase, verify: impl Fn(&[u8]) -> Result<(), VerifyError>) {
    let vector = Vector::parse(case.text);
    let profile = Profile::new(case.row).expect("frozen descriptor");
    let namespace = profile.namespace(case.role).expect("role namespace");
    let vole = case.row.vole();
    let params = ProofParams::new(vole, case.role.witness_bits(), case.role.constraints())
        .expect("frozen relation dimensions");
    let fields = codec::decode_as(Construction::Extended, &params, case.proof)
        .expect("canonical independent proof");
    assert_eq!(
        fields.counter,
        u32::try_from(vector.int("ctr_u32")).expect("counter fits u32")
    );
    assert!(fields.counter < case.later_counter);
    assert!(case.later_counter <= EXTENDED_LAST_COUNTER);
    assert_eq!(verify(case.proof), Ok(()), "original proof accepted");

    let iv = derive_iv(
        namespace,
        LEVEL,
        &array(vector.get("tape_iv_pre")),
        vector.get("mu"),
    )
    .expect("fixed transcript IV");
    assert_eq!(iv.as_slice(), vector.get("iv"));
    let commitment = bavc::commit_as(
        namespace,
        Construction::Extended,
        &vole,
        vector.get("tape_r"),
        &iv,
    )
    .expect("fixture root regenerates the commitment");
    assert_eq!(commitment.commitment(), vector.get("bavc_com"));
    let original_hidden =
        bavc::decode_challenge(&vole, fields.challenge).expect("original indices");
    assert_eq!(
        commitment.open(&original_hidden).expect("original opening"),
        fields.decommitment,
    );

    let mut coefficients = Vec::with_capacity(7 * 32);
    for index in 0..7 {
        coefficients.extend_from_slice(vector.get(&format!("a_tilde_{index}")));
    }
    assert_eq!(&coefficients[32..], fields.coefficients);
    let grinder = Challenge3::new(namespace, &vole, vector.get("chall_2"), &coefficients)
        .expect("fixture challenge prefix");
    let mut challenge = [0u8; 32];
    grinder
        .at(fields.counter, &mut challenge)
        .expect("original challenge");
    assert_eq!(challenge.as_slice(), fields.challenge);

    // Independently establish that the fixture counter is first and the pinned
    // later counter is second. The verifier itself must not perform this search.
    let mut acceptable = Vec::new();
    for counter in 0..=case.later_counter {
        grinder.at(counter, &mut challenge).expect("one counter");
        let hidden = match bavc::decode_challenge(&vole, &challenge) {
            Ok(hidden) => hidden,
            Err(BavcError::GrindingBitsSet) => continue,
            Err(error) => panic!("unexpected challenge error: {error:?}"),
        };
        if bavc::opening_nodes(&vole, &hidden).expect("valid indices") <= vole.t_open() {
            acceptable.push(counter);
        }
    }
    assert_eq!(acceptable, [fields.counter, case.later_counter]);
    let later_hidden = bavc::decode_challenge(&vole, &challenge).expect("later indices");
    let opening = commitment
        .open(&later_hidden)
        .expect("later honest opening");
    let later = codec::encode_as(
        Construction::Extended,
        &params,
        &ProofFields {
            decommitment: &opening,
            challenge: &challenge,
            counter: case.later_counter,
            ..fields
        },
    )
    .expect("later canonical proof");
    let fixed_prefix = Field::Decommitment.offset_as(Construction::Extended, &params);
    assert_eq!(&later[..fixed_prefix], &case.proof[..fixed_prefix]);
    assert_eq!(later.len(), case.proof.len());
    assert_eq!(verify(&later), Ok(()), "valid non-minimal counter accepted");

    let mut changed_counter_only = case.proof.to_vec();
    let at = Field::Counter.offset_as(Construction::Extended, &params);
    changed_counter_only[at..].copy_from_slice(&case.later_counter.to_le_bytes());
    assert_eq!(
        verify(&changed_counter_only),
        Err(VerifyError::Rejected),
        "a later counter requires its own challenge and opening",
    );
    assert_eq!(shake256_64(&later), common::hex(case.later_digest));
    println!(
        "{:?} {:?}: first={} later={} proof_shake256_64={}",
        case.row, case.role, fields.counter, case.later_counter, case.later_digest
    );
}

#[test]
fn candidate_registration_accepts_the_second_valid_counter() {
    let statement = common::reg_case(Row::Candidate).statement;
    check_nonminimal(
        &CounterCase {
            row: Row::Candidate,
            role: Role::Registration,
            text: include_str!("fixtures/reg_fast.txt"),
            proof: include_bytes!("fixtures/reg_fast.proof"),
            later_counter: 336,
            later_digest: "a01b86c27bd82a267f4ab27399ffaccbd4175cb4318eebc47f3eee086ad8bae32c002db72a7cc5d8661e43e773853f5ff9f51cd9bfaaa8f381de6f1258eadb4d",
        },
        |proof| registration::verify(Row::Candidate, &statement, proof),
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn comparator_registration_accepts_the_second_valid_counter() {
    let statement = common::reg_case(Row::Comparator).statement;
    check_nonminimal(
        &CounterCase {
            row: Row::Comparator,
            role: Role::Registration,
            text: include_str!("fixtures/reg_comparator.txt"),
            proof: include_bytes!("fixtures/reg_comparator.proof"),
            later_counter: 563,
            later_digest: "4c837932bc7bb787dc0f871d22e5a694c3fb47ca3b2e8eb54259199d0907f8227f992283d7e6c9a67a3242fb795f6d96d60bf3519b626a83c359d141452ed9ca",
        },
        |proof| registration::verify(Row::Comparator, &statement, proof),
    );
}

#[test]
fn candidate_vote_accepts_the_second_valid_counter() {
    let statement = common::vote_case(Row::Candidate, 3, 1).statement;
    check_nonminimal(
        &CounterCase {
            row: Row::Candidate,
            role: Role::Vote,
            text: include_str!("fixtures/vote_S3_i1_fast.txt"),
            proof: include_bytes!("fixtures/vote_S3_i1_fast.proof"),
            later_counter: 649,
            later_digest: "1b7a3f3e2a8c1c125a76eed23b41d21746e81580ced1110ed7fa4261995b019d55a6f0341560aab9b8f120116f39058ec3d95702d11a83f7fff48958ae76fe5a",
        },
        |proof| vote::verify(Row::Candidate, &statement, proof),
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn comparator_vote_accepts_the_second_valid_counter() {
    let statement = common::vote_case(Row::Comparator, 3, 1).statement;
    check_nonminimal(
        &CounterCase {
            row: Row::Comparator,
            role: Role::Vote,
            text: include_str!("fixtures/vote_S3_i1_comparator.txt"),
            proof: include_bytes!("fixtures/vote_S3_i1_comparator.proof"),
            later_counter: 1837,
            later_digest: "192e2eb45251ad4a0ea5290d57aa3c78a67046df1d1743faca5b64e49b78af82ecf4c844abba5bea3b2c8e9f6ead76f6bdddbb8c70710cce84bfd22c634f433c",
        },
        |proof| vote::verify(Row::Comparator, &statement, proof),
    );
}
