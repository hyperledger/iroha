//! The frozen witness layout and the frozen order of the constraint stream of both
//! relations (evaluation record section 6.3), as tables.
//!
//! The tables are documentation and test support: the relations emit their
//! constraints with the same constants, and the tests check that a fault in a
//! witness interval violates exactly the blocks these tables predict.

use crate::profile::Role;

/// Bits of the fresh pad at the start of every witness.
pub const PAD_BITS: usize = 256;
/// Witness offset of the credential secret.
pub const SECRET_OFFSET: usize = PAD_BITS;
/// Bits of the credential secret.
pub const SECRET_BITS: usize = 384;
/// Bits of one Keccak-f\[1600\] state.
pub const STATE_BITS: usize = 1600;
/// Committed states of one permutation: after 2, 4, ..., 22 rounds.
pub const GROUPS: usize = 11;
/// Witness offsets of the first committed state of the first permutation (the
/// commitment), second (registration authorization or nullifier), and third
/// (vote authorization, vote only).
pub const PERMUTATION_OFFSETS: [usize; 3] = [
    SECRET_OFFSET + SECRET_BITS,
    SECRET_OFFSET + SECRET_BITS + GROUPS * STATE_BITS,
    SECRET_OFFSET + SECRET_BITS + 2 * GROUPS * STATE_BITS,
];
/// Entries of each selector vector.
pub const SELECTOR_BITS: usize = 32;
/// Witness offset of the selector vector `a` (vote only).
pub const SELECTOR_A_OFFSET: usize = PERMUTATION_OFFSETS[2] + GROUPS * STATE_BITS;
/// Witness offset of the selector vector `b` (vote only).
pub const SELECTOR_B_OFFSET: usize = SELECTOR_A_OFFSET + SELECTOR_BITS;
/// Witness length `l_reg` in bits.
pub const REGISTRATION_WITNESS_BITS: usize = PERMUTATION_OFFSETS[2];
/// Witness length `l_vote` in bits.
pub const VOTE_WITNESS_BITS: usize = SELECTOR_B_OFFSET + SELECTOR_BITS;
/// Position of secret bit 0 in the initial state of every permutation.
pub const SECRET_STATE_OFFSET: usize = 160;
/// Constrained output bits of the commitment permutation.
pub const COMMITMENT_BITS: usize = 1024;
/// Constrained output bits of the authorization permutations.
pub const TAG_BITS: usize = 512;
/// Constrained output bits of the nullifier permutation.
pub const NULLIFIER_BITS: usize = 1024;
/// Constraints of one transition block: eleven groups of 1,600.
pub const TRANSITION_CONSTRAINTS: usize = GROUPS * STATE_BITS;
/// Constraints the registration relation emits after Booleanity.
pub const REGISTRATION_RELATION_CONSTRAINTS: usize =
    2 * TRANSITION_CONSTRAINTS + COMMITMENT_BITS + TAG_BITS;
/// Constraints the vote relation emits after Booleanity.
pub const VOTE_RELATION_CONSTRAINTS: usize = 3 * TRANSITION_CONSTRAINTS
    + COMMITMENT_BITS
    + NULLIFIER_BITS
    + TAG_BITS
    + 2 * (SELECTOR_BITS + 1)
    + 1;
/// Total constraint count `M_reg` (`N_c`), Booleanity included.
pub const REGISTRATION_CONSTRAINTS: usize =
    REGISTRATION_WITNESS_BITS + REGISTRATION_RELATION_CONSTRAINTS;
/// Total constraint count `M_vote` (`N_c`), Booleanity included.
pub const VOTE_CONSTRAINTS: usize = VOTE_WITNESS_BITS + VOTE_RELATION_CONSTRAINTS;

/// One of the four SHAKE256 evaluations constrained by the relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permutation {
    /// The credential commitment `C` (both relations).
    Commitment,
    /// The authorization value `auth` (registration).
    Authorization,
    /// The nullifier `nf` (vote).
    Nullifier,
    /// The complete-statement authorization value `auth_v` (vote).
    VoteAuthorization,
}

/// The permutations of `role`, in witness and constraint order.
pub const fn permutations(role: Role) -> &'static [Permutation] {
    match role {
        Role::Registration => &[Permutation::Commitment, Permutation::Authorization],
        Role::Vote => &[
            Permutation::Commitment,
            Permutation::Nullifier,
            Permutation::VoteAuthorization,
        ],
    }
}

/// What a witness interval holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WitnessPart {
    /// The fresh pad.
    Pad,
    /// The credential secret.
    Secret,
    /// The committed state of `permutation` after `2 * group` rounds.
    State {
        /// The permutation.
        permutation: Permutation,
        /// `g` in `1 ..= 11`.
        group: u8,
    },
    /// The selector vector `a`.
    SelectorA,
    /// The selector vector `b`.
    SelectorB,
}

/// A half-open interval `[start, end)` of witness bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interval {
    /// What the interval holds.
    pub part: WitnessPart,
    /// First witness bit.
    pub start: usize,
    /// One past the last witness bit.
    pub end: usize,
}

/// A block of the constraint stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockKind {
    /// (B) Booleanity of every witness coordinate, emitted by the backend.
    Booleanity,
    /// (SP) the prefix constraints of `a`.
    PrefixA,
    /// (SS) the sum constraint of `a`.
    SumA,
    /// (SP) the prefix constraints of `b`.
    PrefixB,
    /// (SS) the sum constraint of `b`.
    SumB,
    /// (SR) the range constraint.
    Range,
    /// (T) the 1,600 transition constraints of one group of `permutation`.
    Transition {
        /// The permutation.
        permutation: Permutation,
        /// `g` in `1 ..= 11`.
        group: u8,
    },
    /// (RC), (RA), (VC) or (VN): the output constraints of `permutation`.
    Output {
        /// The permutation.
        permutation: Permutation,
    },
}

/// A half-open interval `[start, end)` of constraint indices, counted from the
/// first Booleanity constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Block {
    /// What the block constrains.
    pub kind: BlockKind,
    /// First constraint index.
    pub start: usize,
    /// One past the last constraint index.
    pub end: usize,
}

/// `g` as the group tag of the tables; `g` is at most [`GROUPS`].
fn group_tag(group: usize) -> u8 {
    u8::try_from(group).unwrap_or(u8::MAX)
}

/// The witness layout of `role`, in increasing order and without gaps.
pub fn witness_layout(role: Role) -> Vec<Interval> {
    let mut out = vec![
        Interval {
            part: WitnessPart::Pad,
            start: 0,
            end: PAD_BITS,
        },
        Interval {
            part: WitnessPart::Secret,
            start: SECRET_OFFSET,
            end: SECRET_OFFSET + SECRET_BITS,
        },
    ];
    for (permutation, offset) in permutations(role).iter().copied().zip(PERMUTATION_OFFSETS) {
        for group in 1..=GROUPS {
            let start = offset + STATE_BITS * (group - 1);
            out.push(Interval {
                part: WitnessPart::State {
                    permutation,
                    group: group_tag(group),
                },
                start,
                end: start + STATE_BITS,
            });
        }
    }
    if role == Role::Vote {
        out.push(Interval {
            part: WitnessPart::SelectorA,
            start: SELECTOR_A_OFFSET,
            end: SELECTOR_B_OFFSET,
        });
        out.push(Interval {
            part: WitnessPart::SelectorB,
            start: SELECTOR_B_OFFSET,
            end: VOTE_WITNESS_BITS,
        });
    }
    out
}

/// The constraint stream of `role` as blocks, in stream order and without gaps.
pub fn constraint_blocks(role: Role) -> Vec<Block> {
    let witness_bits = match role {
        Role::Registration => REGISTRATION_WITNESS_BITS,
        Role::Vote => VOTE_WITNESS_BITS,
    };
    let mut out = Vec::new();
    let mut next = 0usize;
    let mut push = |kind: BlockKind, len: usize| {
        out.push(Block {
            kind,
            start: next,
            end: next + len,
        });
        next += len;
    };
    push(BlockKind::Booleanity, witness_bits);
    if role == Role::Vote {
        push(BlockKind::PrefixA, SELECTOR_BITS);
        push(BlockKind::SumA, 1);
        push(BlockKind::PrefixB, SELECTOR_BITS);
        push(BlockKind::SumB, 1);
        push(BlockKind::Range, 1);
    }
    for &permutation in permutations(role) {
        for group in 1..=GROUPS {
            push(
                BlockKind::Transition {
                    permutation,
                    group: group_tag(group),
                },
                STATE_BITS,
            );
        }
        let bits = if matches!(
            permutation,
            Permutation::Commitment | Permutation::Nullifier
        ) {
            COMMITMENT_BITS
        } else {
            TAG_BITS
        };
        push(BlockKind::Output { permutation }, bits);
    }
    out
}

/// The block that holds constraint `index`, if any.
pub fn block_of(blocks: &[Block], index: usize) -> Option<BlockKind> {
    blocks
        .iter()
        .find(|block| (block.start..block.end).contains(&index))
        .map(|block| block.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_of(blocks: &[Block], kind: BlockKind) -> (usize, usize) {
        let block = blocks
            .iter()
            .find(|block| block.kind == kind)
            .expect("the block exists");
        (block.start, block.end)
    }

    #[test]
    fn the_dimensions_are_the_frozen_ones() {
        assert_eq!(PERMUTATION_OFFSETS, [640, 18_240, 35_840]);
        assert_eq!(SELECTOR_A_OFFSET, 53_440);
        assert_eq!(SELECTOR_B_OFFSET, 53_472);
        assert_eq!(REGISTRATION_WITNESS_BITS, 35_840);
        assert_eq!(VOTE_WITNESS_BITS, 53_504);
        assert_eq!(REGISTRATION_RELATION_CONSTRAINTS, 36_736);
        assert_eq!(VOTE_RELATION_CONSTRAINTS, 55_427);
        assert_eq!(REGISTRATION_CONSTRAINTS, 72_576);
        assert_eq!(VOTE_CONSTRAINTS, 108_931);
    }

    #[test]
    fn the_witness_layout_is_the_table_of_the_record() {
        for role in [Role::Registration, Role::Vote] {
            let layout = witness_layout(role);
            let mut next = 0;
            for interval in &layout {
                assert_eq!(interval.start, next);
                next = interval.end;
            }
            let total = if role == Role::Vote { 53_504 } else { 35_840 };
            assert_eq!(next, total);
            assert_eq!((layout[0].start, layout[0].end), (0, 256));
            assert_eq!((layout[1].start, layout[1].end), (256, 640));
            // Commitment state g: [640 + 1600 (g - 1), 640 + 1600 g).
            assert_eq!((layout[2].start, layout[12].end), (640, 18_240));
            assert_eq!(
                layout[7],
                Interval {
                    part: WitnessPart::State {
                        permutation: Permutation::Commitment,
                        group: 6
                    },
                    start: 640 + 1600 * 5,
                    end: 640 + 1600 * 6,
                }
            );
            assert_eq!((layout[13].start, layout[23].end), (18_240, 35_840));
            let second = permutations(role)[1];
            assert_eq!(
                layout[23].part,
                WitnessPart::State {
                    permutation: second,
                    group: 11
                }
            );
        }
        let vote = witness_layout(Role::Vote);
        assert_eq!(vote.len(), 37);
        assert_eq!(
            (vote[35].part, vote[35].start, vote[35].end),
            (WitnessPart::SelectorA, 53_440, 53_472)
        );
        assert_eq!(
            (vote[36].part, vote[36].start, vote[36].end),
            (WitnessPart::SelectorB, 53_472, 53_504)
        );
        assert_eq!(witness_layout(Role::Registration).len(), 24);
    }

    #[test]
    fn every_block_starts_at_its_frozen_index() {
        use BlockKind::{Booleanity, Output, PrefixA, PrefixB, Range, SumA, SumB, Transition};
        use Permutation::{Authorization, Commitment, Nullifier};
        let first = |permutation| Transition {
            permutation,
            group: 1,
        };
        let last = |permutation| Transition {
            permutation,
            group: 11,
        };
        let reg = constraint_blocks(Role::Registration);
        assert_eq!(start_of(&reg, Booleanity), (0, 35_840));
        assert_eq!(start_of(&reg, first(Commitment)).0, 35_840);
        assert_eq!(start_of(&reg, last(Commitment)).1, 53_440);
        assert_eq!(
            start_of(
                &reg,
                Output {
                    permutation: Commitment
                }
            ),
            (53_440, 54_464)
        );
        assert_eq!(start_of(&reg, first(Authorization)).0, 54_464);
        assert_eq!(start_of(&reg, last(Authorization)).1, 72_064);
        assert_eq!(
            start_of(
                &reg,
                Output {
                    permutation: Authorization
                }
            ),
            (72_064, 72_576)
        );
        assert_eq!(reg.len(), 25);

        let vote = constraint_blocks(Role::Vote);
        assert_eq!(start_of(&vote, Booleanity), (0, 53_504));
        assert_eq!(start_of(&vote, PrefixA), (53_504, 53_536));
        assert_eq!(start_of(&vote, SumA), (53_536, 53_537));
        assert_eq!(start_of(&vote, PrefixB), (53_537, 53_569));
        assert_eq!(start_of(&vote, SumB), (53_569, 53_570));
        assert_eq!(start_of(&vote, Range), (53_570, 53_571));
        assert_eq!(start_of(&vote, first(Commitment)).0, 53_571);
        assert_eq!(start_of(&vote, last(Commitment)).1, 71_171);
        assert_eq!(
            start_of(
                &vote,
                Output {
                    permutation: Commitment
                }
            ),
            (71_171, 72_195)
        );
        assert_eq!(start_of(&vote, first(Nullifier)).0, 72_195);
        assert_eq!(start_of(&vote, last(Nullifier)).1, 89_795);
        assert_eq!(
            start_of(
                &vote,
                Output {
                    permutation: Nullifier
                }
            ),
            (89_795, 90_819)
        );
        assert_eq!(
            start_of(&vote, first(Permutation::VoteAuthorization)).0,
            90_819
        );
        assert_eq!(
            start_of(&vote, last(Permutation::VoteAuthorization)).1,
            108_419
        );
        assert_eq!(
            start_of(
                &vote,
                Output {
                    permutation: Permutation::VoteAuthorization
                }
            ),
            (108_419, 108_931)
        );
        assert_eq!(vote.len(), 42);
        // Without gaps, and block_of finds every index.
        for blocks in [&reg, &vote] {
            let mut next = 0;
            for block in blocks {
                assert_eq!(block.start, next);
                assert_eq!(block_of(blocks, block.start), Some(block.kind));
                assert_eq!(block_of(blocks, block.end - 1), Some(block.kind));
                next = block.end;
            }
            assert_eq!(block_of(blocks, next), None);
        }
        assert_eq!(group_tag(11), 11);
    }
}
