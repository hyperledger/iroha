//! The two relations on the backend's plain evaluator: honest witnesses are
//! accepted, and every sampled single-bit flip and every semantic fault violates
//! exactly the constraint blocks the relation predicts.

mod common;

use std::collections::BTreeSet;

use common::{
    RegCase, VoteCase, flip, fx, output, pad_of, reg_case, registration_faults,
    registration_violations, secret, transition, vote_case, vote_faults, vote_violations,
};
use iroha_parliament_ballot_proof::{
    layout::{BlockKind, Interval, Permutation, WitnessPart, witness_layout},
    profile::{Profile, Role, Row},
    registration::{self, RegistrationInstance, RegistrationRelation},
    vote::{self, VoteInstance, VoteRelation},
};
use iroha_zkp_vole::{field::Gf256, quicksilver::is_satisfied};

fn registration_instance(case: &RegCase) -> (RegistrationInstance, Vec<u8>) {
    let profile = Profile::new(case.row).expect("tables");
    let instance = case.statement.instance(&profile).expect("valid");
    let witness = registration::witness(
        instance.public(),
        &secret(&case.secret),
        &pad_of(&case.tape),
    )
    .to_vec();
    (instance, witness)
}

fn vote_instance(case: &VoteCase) -> (VoteInstance, Vec<u8>) {
    let profile = Profile::new(case.row).expect("tables");
    let instance = case.statement.instance(&profile).expect("valid");
    let witness = vote::witness(
        instance.public(),
        &secret(&case.secret),
        u16::try_from(case.index).expect("small"),
        &pad_of(&case.tape),
    )
    .to_vec();
    (instance, witness)
}

#[test]
fn the_honest_registration_witness_is_accepted() {
    let (instance, witness) = registration_instance(&reg_case(Row::Candidate));
    assert_eq!(witness.len() * 8, 35_840);
    assert_eq!(
        is_satisfied::<Gf256, _>(&RegistrationRelation, instance.public(), &witness),
        Ok(true)
    );
    assert!(registration_violations(&instance, &witness).is_empty());
}

fn honest_votes_are_accepted(size: usize) {
    for index in [0, size / 2, size - 1] {
        let (instance, witness) = vote_instance(&vote_case(Row::Candidate, size, index));
        assert_eq!(witness.len() * 8, 53_504);
        assert_eq!(instance.public().size(), size);
        assert_eq!(
            is_satisfied::<Gf256, _>(&VoteRelation, instance.public(), &witness),
            Ok(true),
            "S = {size}, member at {index}"
        );
    }
}

#[test]
fn honest_vote_witnesses_are_accepted_with_three_members() {
    honest_votes_are_accepted(3);
}

#[test]
fn honest_vote_witnesses_are_accepted_with_five_hundred_members() {
    honest_votes_are_accepted(500);
}

#[test]
fn honest_vote_witnesses_are_accepted_with_a_thousand_members() {
    honest_votes_are_accepted(1000);
}

/// The exact set of blocks a flip of bit `j` of `interval` must violate
/// (the prototype's `expected_flip_sig`). `position` is the honest list
/// position and `size` the list size of a vote.
fn expected_flip(
    role: Role,
    interval: &Interval,
    j: usize,
    position: usize,
    size: usize,
) -> BTreeSet<BlockKind> {
    use BlockKind::{PrefixA, PrefixB, Range, SumA, SumB};
    let second = match role {
        Role::Registration => Permutation::Authorization,
        Role::Vote => Permutation::Nullifier,
    };
    let commitment_output = output(Permutation::Commitment);
    let kinds: Vec<BlockKind> = match interval.part {
        WitnessPart::Pad => vec![],
        WitnessPart::Secret => {
            let mut kinds = vec![
                transition(Permutation::Commitment, 1),
                transition(second, 1),
            ];
            if role == Role::Vote {
                kinds.push(transition(Permutation::VoteAuthorization, 1));
            }
            kinds
        }
        WitnessPart::State { permutation, group } => vec![
            transition(permutation, group),
            if group < 11 {
                transition(permutation, group + 1)
            } else {
                output(permutation)
            },
        ],
        WitnessPart::SelectorA | WitnessPart::SelectorB => {
            let is_a = interval.part == WitnessPart::SelectorA;
            let (a0, b0) = (position / 32, position % 32);
            let (prefix, sum) = if is_a {
                (PrefixA, SumA)
            } else {
                (PrefixB, SumB)
            };
            let (own, extra) = if is_a {
                (a0, 32 * j + b0)
            } else {
                (b0, 32 * a0 + j)
            };
            if j == own {
                // No bit left: nothing is selected.
                vec![sum, Range, commitment_output]
            } else if extra < size {
                // A second list entry is selected.
                vec![prefix, sum, Range, commitment_output]
            } else {
                vec![prefix, sum]
            }
        }
    };
    kinds.into_iter().collect()
}

/// The bits of `interval` to flip: the first, the last and `extra` more chosen
/// by a fixed pseudo-random rule; all of them for a selector vector.
fn sample_bits(interval: &Interval, extra: usize) -> Vec<usize> {
    let len = interval.end - interval.start;
    if matches!(
        interval.part,
        WitnessPart::SelectorA | WitnessPart::SelectorB
    ) {
        return (0..len).collect();
    }
    let seed = fx(&format!("flip/{}/{extra}", interval.start), 2 * extra);
    let mut bits = vec![0, len - 1];
    for pair in seed.chunks_exact(2) {
        bits.push(usize::from(u16::from_le_bytes([pair[0], pair[1]])) % len);
    }
    bits
}

/// Flip sampled bits of the intervals `range` of the registration layout.
fn registration_flips(range: core::ops::Range<usize>) {
    let (instance, witness) = registration_instance(&reg_case(Row::Candidate));
    let layout = witness_layout(Role::Registration);
    for interval in &layout[range] {
        for j in sample_bits(interval, 14) {
            let mut flipped = witness.clone();
            flip(&mut flipped, interval.start + j);
            assert_eq!(
                registration_violations(&instance, &flipped),
                expected_flip(Role::Registration, interval, j, 0, 0),
                "{:?} bit {j}",
                interval.part
            );
        }
    }
}

/// Flip sampled bits of the intervals `range` of the vote layout.
fn vote_flips(range: core::ops::Range<usize>) {
    let case = vote_case(Row::Candidate, 3, 1);
    let (instance, witness) = vote_instance(&case);
    let layout = witness_layout(Role::Vote);
    for interval in &layout[range] {
        for j in sample_bits(interval, 14) {
            let mut flipped = witness.clone();
            flip(&mut flipped, interval.start + j);
            assert_eq!(
                vote_violations(&instance, &flipped),
                expected_flip(Role::Vote, interval, j, case.index, 3),
                "{:?} bit {j}",
                interval.part
            );
        }
    }
}

// The layouts have 24 (registration) and 37 (vote) intervals: pad, secret,
// eleven states of each permutation, and the two selector vectors. The flips are
// split so that the harness runs the slices in parallel.

#[test]
fn a_flipped_pad_bit_is_still_a_valid_witness_and_a_flipped_secret_bit_is_not() {
    registration_flips(0..2);
    vote_flips(0..2);
    // Every pad byte, one bit each: the pad is in no relation constraint.
    let (instance, witness) = registration_instance(&reg_case(Row::Candidate));
    let mut flipped = witness;
    for byte in 0..32 {
        flip(&mut flipped, 8 * byte + byte % 8);
    }
    assert_eq!(
        is_satisfied::<Gf256, _>(&RegistrationRelation, instance.public(), &flipped),
        Ok(true)
    );
}

#[test]
fn flips_in_the_registration_commitment_states_violate_exactly_their_blocks_1() {
    registration_flips(2..8);
}

#[test]
fn flips_in_the_registration_commitment_states_violate_exactly_their_blocks_2() {
    registration_flips(8..13);
}

#[test]
fn flips_in_the_registration_authorization_states_violate_exactly_their_blocks_1() {
    registration_flips(13..19);
}

#[test]
fn flips_in_the_registration_authorization_states_violate_exactly_their_blocks_2() {
    registration_flips(19..24);
}

#[test]
fn flips_in_the_vote_commitment_states_violate_exactly_their_blocks_1() {
    vote_flips(2..8);
}

#[test]
fn flips_in_the_vote_commitment_states_violate_exactly_their_blocks_2() {
    vote_flips(8..13);
}

#[test]
fn flips_in_the_vote_nullifier_states_violate_exactly_their_blocks_1() {
    vote_flips(13..19);
}

#[test]
fn flips_in_the_vote_nullifier_states_violate_exactly_their_blocks_2() {
    vote_flips(19..24);
}

#[test]
fn every_flip_of_selector_a_violates_exactly_its_blocks() {
    vote_flips(35..36);
}

#[test]
fn every_flip_of_selector_b_violates_exactly_its_blocks() {
    vote_flips(36..37);
}

#[test]
fn every_registration_fault_violates_exactly_its_blocks() {
    let case = reg_case(Row::Candidate);
    let profile = Profile::new(case.row).expect("tables");
    let faults = registration_faults(&case);
    assert_eq!(faults.len(), 6);
    for fault in faults {
        let instance = fault.statement.instance(&profile).expect("valid");
        assert_eq!(
            registration_violations(&instance, &fault.witness),
            fault.expected,
            "{}",
            fault.name
        );
    }
}

fn vote_faults_violate_exactly_their_blocks(part: usize) {
    let case = vote_case(Row::Candidate, 3, 1);
    let profile = Profile::new(case.row).expect("tables");
    let faults = vote_faults(&case);
    assert_eq!(faults.len(), 18);
    for fault in faults.into_iter().skip(part).step_by(2) {
        let instance = fault.statement.instance(&profile).expect("valid");
        assert_eq!(
            vote_violations(&instance, &fault.witness),
            fault.expected,
            "{}",
            fault.name
        );
    }
}

#[test]
fn every_vote_fault_violates_exactly_its_blocks_even() {
    vote_faults_violate_exactly_their_blocks(0);
}

#[test]
fn every_vote_fault_violates_exactly_its_blocks_odd() {
    vote_faults_violate_exactly_their_blocks(1);
}

#[test]
fn flips_in_vote_authorization_states_violate_exactly_their_blocks() {
    vote_flips(24..35);
}
