//! The key gadgets on true and false statements: honest traces are accepted by
//! the reference, and each constraint group is shown to be load-bearing by a
//! forged trace of a false statement that only the relation without that group
//! accepts.

use super::*;
use crate::{
    air::{AirError, NoObserver, ReferenceChallenges, build_reference, check_reference},
    field::GOLDILOCKS_MODULUS_V1,
    state_commitment_prototypes::{critbit::ByteKey, hash::pack_bytes},
};

fn challenges(constraints: usize) -> ReferenceChallenges {
    ReferenceChallenges::derive(&[0x47; 32], constraints)
}

/// Build and check the reference of a trace.
fn accept<A: SemanticAir>(air: &A, columns: Vec<Vec<u64>>, limits: WorkLimits) {
    let challenges = challenges(air.schema().constraints);
    let artifact = build_reference(air, columns, &challenges, limits, &NoObserver)
        .expect("the trace satisfies the relation");
    check_reference(air, &artifact, &challenges, limits, &NoObserver)
        .expect("the checker accepts the artifact");
}

/// The first violated numerator of a trace under a relation.
fn violation<A: SemanticAir>(air: &A, columns: Vec<Vec<u64>>, limits: WorkLimits) -> Option<usize> {
    let challenges = challenges(air.schema().constraints);
    match build_reference(air, columns, &challenges, limits, &NoObserver) {
        Ok(_) => None,
        Err(AirError::ConstraintViolated { constraint, .. }) => Some(constraint),
        Err(other) => panic!("unexpected reference failure: {other}"),
    }
}

/// Numerator slots of [`KeyOrderAir`] after the two scanned strings.
const ORDER_RULES: usize = 2 * LANE_CONSTRAINTS + 10;
const SLOT_PREFIX_START: usize = ORDER_RULES;
const SLOT_PREFIX_STEP: usize = ORDER_RULES + 1;
const SLOT_EQUAL: usize = ORDER_RULES + 2;
const SLOT_DECIDE: usize = ORDER_RULES + 3;
const SLOT_STRICT: usize = ORDER_RULES + 4;
/// Numerator slots of one scanned string.
const SLOT_COUNT_MATCH: usize = 13;
const SLOT_LIMB_MATCH: usize = 15;

#[test]
fn rows_and_limbs_follow_the_sponge_packing() {
    assert_eq!(
        [0, 1, 7, 8, 15, 36, 62, 63, 64, 132].map(rows_for),
        [8, 8, 8, 16, 32, 64, 64, 64, 128, 256]
    );
    // Fifteen bytes need a third limb, which sixteen rows do not complete.
    for length in [0_usize, 1, 6, 7, 8, 36, 49, 50, 132] {
        let bytes: Vec<u8> = (0..length)
            .map(|index| u8::try_from((index * 37 + 5) % 251).expect("below 251"))
            .collect();
        let packed = pack_bytes(&bytes).concat();
        let limbs = limbs(&bytes);
        assert_eq!(packed[0], length as u64);
        assert_eq!(limbs.len(), length.div_ceil(BYTES_PER_ELEMENT));
        assert_eq!(packed[1..=limbs.len()], limbs);
        assert!(packed[limbs.len() + 1..].iter().all(|word| *word == 0));
        // Every limb has its row in the trace, and a row lies past the string.
        let rows = rows_for(length);
        assert!(rows.is_power_of_two() && rows > length);
        assert!(BYTES_PER_ELEMENT * limbs.len() <= rows);
    }
    assert_eq!((KeyOrderAir::WIDTH, KeyOrderAir::PRIVATE_COLUMNS), (42, 32));
    assert_eq!(KeyOrderAir::CONSTRAINTS, 47);
    assert_eq!((KeyBitAir::WIDTH, KeyBitAir::PRIVATE_COLUMNS), (37, 11));
    assert_eq!(KeyBitAir::CONSTRAINTS, 25);
    assert_eq!(
        GadgetUse::default(),
        GadgetUse {
            bit_scans: 0,
            comparisons: 0
        }
    );
}

fn long_key(last: u8) -> Vec<u8> {
    let mut key: Vec<u8> = (0..36_u8)
        .map(|index| index.wrapping_mul(29) ^ 0x5a)
        .collect();
    key[35] = last;
    key
}

#[test]
fn ordered_strings_satisfy_the_order_relation() {
    let (low, high) = (long_key(7), long_key(8));
    let cases: [(&[u8], &[u8], bool); 12] = [
        (b"", b"a", true),
        (b"", b"\0", true),
        (b"a", b"a\0", true),
        (b"a", b"b", true),
        (b"ab", b"b", true),
        (b"\xfe\xff", b"\xff", true),
        (b"\0", b"\xff", true),
        (b"abcdefg", b"abcdefgh", true),
        (b"abcdefgh", b"abcdefh", true),
        (&low, &high, true),
        (b"same", b"same", false),
        (b"", b"", false),
    ];
    for (left, right, strict) in cases {
        assert_eq!(left < right, strict, "the case is what it says");
        for strictness in [strict, false] {
            let air = KeyOrderAir::new(left, right, strictness);
            let schema = air.schema();
            assert_eq!(schema.identity, KeyOrderAir::IDENTITY);
            assert_eq!(schema.trace_rows, rows_for(left.len().max(right.len())));
            assert_eq!(schema.width, 42);
            assert_eq!(schema.constraints, 47);
            assert_eq!(
                schema.numerator_degree_bound,
                4 * (schema.trace_rows - 1) + 1
            );
            accept(
                &air,
                air.witness_columns(left, right),
                air.reference_limits(),
            );
        }
        // The opposite strict statement has no trace that follows the rules,
        // and neither has the strict form of an equality.
        let reversed = KeyOrderAir::new(right, left, true);
        assert!(
            violation(
                &reversed,
                reversed.witness_columns(right, left),
                reversed.reference_limits()
            )
            .is_some()
        );
        if left != right {
            let reversed = KeyOrderAir::new(right, left, false);
            assert_eq!(
                violation(
                    &reversed,
                    reversed.witness_columns(right, left),
                    reversed.reference_limits()
                ),
                Some(SLOT_DECIDE)
            );
        }
    }
    // The statement is bound: the trace of one pair is not a trace of another.
    let air = KeyOrderAir::new(b"a", b"c", true);
    assert_eq!(
        violation(
            &air,
            air.witness_columns(b"a", b"d"),
            air.reference_limits()
        ),
        Some(LANE_CONSTRAINTS + SLOT_LIMB_MATCH)
    );
    assert_ne!(
        air.statement_bytes(),
        KeyOrderAir::new(b"a", b"c", false).statement_bytes()
    );
}

/// A forged trace of a false statement violates exactly one numerator slot
/// and satisfies the relation without that slot's group.
fn order_group(
    group: GadgetGroup,
    slot: usize,
    (left, right, strict): (&[u8], &[u8], bool),
    forge: impl Fn(&KeyOrderAir) -> Vec<Vec<u64>>,
) {
    assert!(
        if strict { left >= right } else { left > right },
        "{group:?}: the statement must be false"
    );
    let air = KeyOrderAir::new(left, right, strict);
    let limits = air.reference_limits();
    let columns = forge(&air);
    assert_eq!(
        violation(&air, columns.clone(), limits),
        Some(slot),
        "{group:?}"
    );
    let weakened = KeyOrderAir::new(left, right, strict).without(group);
    accept(&weakened, columns, limits);
}

#[test]
fn each_group_of_the_order_relation_is_load_bearing() {
    // Equal: the difference on the first row is never flagged.
    order_group(GadgetGroup::Equal, SLOT_EQUAL, (b"b", b"a", false), |air| {
        let mut columns = air.witness_columns(b"b", b"a");
        columns[ORDER_DIFFERENT][0] = 0;
        for bit in 0..8 {
            columns[ORDER_GAP + bit][0] = 0;
        }
        columns[ORDER_PREFIX].fill(1);
        columns
    });
    // Decide: the difference is flagged, but the left symbol is the larger.
    order_group(
        GadgetGroup::Decide,
        SLOT_DECIDE,
        (b"b", b"a", true),
        |air| air.witness_columns(b"b", b"a"),
    );
    // Prefix: the flag is clear from the start, so nothing is compared.
    order_group(
        GadgetGroup::Prefix,
        SLOT_PREFIX_START,
        (b"ba", b"ab", true),
        |air| {
            let mut columns = air.witness_columns(b"ba", b"ab");
            columns[ORDER_PREFIX].fill(0);
            columns[ORDER_DIFFERENT].fill(0);
            for bit in 0..8 {
                columns[ORDER_GAP + bit].fill(0);
            }
            columns
        },
    );
    // Prefix: the flag is dropped before the deciding row without a flag.
    order_group(
        GadgetGroup::Prefix,
        SLOT_PREFIX_STEP,
        (b"ab", b"aa", true),
        |air| {
            let mut columns = air.witness_columns(b"ab", b"aa");
            columns[ORDER_PREFIX].fill(0);
            columns[ORDER_PREFIX][0] = 1;
            columns[ORDER_DIFFERENT].fill(0);
            for bit in 0..8 {
                columns[ORDER_GAP + bit].fill(0);
            }
            columns
        },
    );
    // Strict: equal strings.
    order_group(
        GadgetGroup::Strict,
        SLOT_STRICT,
        (b"a", b"a", true),
        |air| air.witness_columns(b"a", b"a"),
    );
    // Packing: the scanned left string is not the stated one.
    order_group(
        GadgetGroup::Packing,
        SLOT_LIMB_MATCH,
        (b"b", b"ab", true),
        |air| air.witness_columns(b"a", b"ab"),
    );
    // Length: the stated `a ‖ 0` is scanned as `a`; the limbs are equal.
    order_group(
        GadgetGroup::Length,
        SLOT_COUNT_MATCH,
        (b"a\0", b"a", false),
        |air| air.witness_columns(b"a", b"a"),
    );
    // Bits: a difference bit that is not a bit makes `-2` an "eight-bit" gap.
    order_group(
        GadgetGroup::Bits,
        2 * LANE_CONSTRAINTS,
        (b"b", b"a", true),
        |air| {
            let mut columns = air.witness_columns(b"b", b"a");
            for bit in 0..8 {
                columns[ORDER_GAP + bit][0] = 0;
            }
            columns[ORDER_GAP][0] = GOLDILOCKS_MODULUS_V1 - 2;
            columns
        },
    );
}

#[test]
fn encoded_key_bits_satisfy_the_bit_relation() {
    for key in [&b""[..], b"a", b"ab\0", b"\xff\x00\x80", &long_key(1)] {
        // Every bit of the encoding, the terminating bit and bits past it.
        let total = u32::try_from(ENCODED_BITS_PER_BYTE * (key.len() + 2)).unwrap();
        let all: Vec<(u32, bool)> = (0..total)
            .map(|index| (index, ByteKey::encoded_bit(key, index)))
            .collect();
        let air = KeyBitAir::new(key, &all);
        let schema = air.schema();
        assert_eq!(schema.identity, KeyBitAir::IDENTITY);
        assert_eq!((schema.width, schema.constraints), (37, 25));
        assert_eq!(
            schema.numerator_degree_bound,
            3 * (schema.trace_rows - 1) + 1
        );
        assert!(schema.trace_rows > key.len() + 1);
        accept(&air, air.witness_columns(key), air.reference_limits());
        // One false bit: the continuation bit of the first byte, a bit inside
        // the key, the terminating bit and a bit past the end.
        for index in [0, 5, total - 2 * 9, total - 1] {
            let index = index as usize;
            let mut stated = all.clone();
            stated[index].1 = !stated[index].1;
            let air = KeyBitAir::new(key, &stated);
            assert_eq!(
                violation(&air, air.witness_columns(key), air.reference_limits()),
                Some(LANE_CONSTRAINTS + index % ENCODED_BITS_PER_BYTE),
                "bit {index}"
            );
        }
    }
    // No stated bit: the relation still binds the scan to the stated key.
    let air = KeyBitAir::new(b"key", &[]);
    accept(&air, air.witness_columns(b"key"), air.reference_limits());
    assert_eq!(
        violation(&air, air.witness_columns(b"kez"), air.reference_limits()),
        Some(SLOT_LIMB_MATCH)
    );
}

#[test]
fn each_group_of_the_bit_relation_is_load_bearing() {
    let check = |group: GadgetGroup,
                 slot: usize,
                 key: &[u8],
                 bits: &[(u32, bool)],
                 columns: &dyn Fn(&KeyBitAir) -> Vec<Vec<u64>>| {
        let air = KeyBitAir::new(key, bits);
        let limits = air.reference_limits();
        let forged = columns(&air);
        assert_eq!(
            violation(&air, forged.clone(), limits),
            Some(slot),
            "{group:?}"
        );
        accept(&KeyBitAir::new(key, bits).without(group), forged, limits);
    };
    // Select: bit 2 of `a` (0x61) is set, the statement says clear.
    assert!(ByteKey::encoded_bit(b"a", 2));
    check(
        GadgetGroup::Select,
        LANE_CONSTRAINTS + 2,
        b"a",
        &[(2, false)],
        &|air| air.witness_columns(b"a"),
    );
    // Packing: the prover scans `!` (0x21), whose bit 2 is clear.
    assert!(!ByteKey::encoded_bit(b"!", 2));
    check(
        GadgetGroup::Packing,
        SLOT_LIMB_MATCH,
        b"a",
        &[(2, false)],
        &|air| air.witness_columns(b"!"),
    );
    // Length: the key `a` ends at bit 9; the prover scans `a ‖ 0`, whose
    // continuation bit there is set and whose limbs are the same.
    assert!(!ByteKey::encoded_bit(b"a", 9) && ByteKey::encoded_bit(b"a\0", 9));
    check(
        GadgetGroup::Length,
        SLOT_COUNT_MATCH,
        b"a",
        &[(9, true)],
        &|air| air.witness_columns(b"a\0"),
    );
    // Bits: the last encoded bit of 0x63 is set, the statement says clear.
    // The prover clears bit column 0 and puts the missing unit into column 1
    // as a half, which is not a bit: the byte and its limb are unchanged.
    assert!(ByteKey::encoded_bit(b"\x63", 8));
    check(GadgetGroup::Bits, 1, b"\x63", &[(8, false)], &|air| {
        let mut columns = air.witness_columns(b"\x63");
        columns[0][0] = 0;
        columns[1][0] = 1 + GOLDILOCKS_MODULUS_V1.div_ceil(2);
        columns
    });
}

#[test]
fn gadget_relations_refuse_malformed_evaluation_input() {
    let order = KeyOrderAir::new(b"a", b"b", true);
    let width = KeyOrderAir::WIDTH;
    assert!(
        order
            .evaluate(0_u64, &vec![0; width - 1], &vec![0; width])
            .is_err()
    );
    assert!(order.public_value(0, order.schema().trace_rows).is_err());
    assert!(order.public_value(width, 0).is_err());
    assert_eq!(order.public_value(0, 0).unwrap(), 1);
    assert_eq!(order.public_columns().len(), 10);
    let bits = KeyBitAir::new(b"a", &[(0, true)]);
    let width = KeyBitAir::WIDTH;
    assert!(
        bits.evaluate(0_u64, &vec![0; width], &vec![0; width + 1])
            .is_err()
    );
    assert!(bits.public_value(26, 0).is_err());
    assert_eq!(bits.public_columns().len(), 26);
    assert_eq!(bits.reference_limits().max_constraints, 25);
    assert_eq!(order.reference_limits().max_trace_cells, 8 * 42);
}
