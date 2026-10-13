//! Conformance suite of the keyed State contract. Test only.
//!
//! [`check_contract`] drives one candidate construction through rules K1..K12 of
//! `specs/sumeragi.md` §16.4. Ground truth is a plain ordered map held by the suite,
//! never the candidate: the candidate must prove every true statement, refuse to prove
//! a false one, and reject every false statement under every witness it has issued.
//!
//! Task G.2 calls [`check_contract`] on each prototype before measuring it. A
//! prototype that fails is not a candidate.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CELL_KEY, Change, Entry, KeyRange, KeyedStateCommitment, KeyedStateRoot, ProveError, Rejection,
    StateSchema, StatementError, TableDescriptor, UpdateError, Witness, prefix_upper_bound,
};

/// The rule identifiers of `specs/sumeragi.md` §16.4, in the order of its table. Every
/// identifier is checked by this suite, and the suite reports no other.
pub(crate) const RULES: [&str; 12] = [
    "K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8", "K9", "K10", "K11", "K12",
];

/// The first contract rule a candidate violates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    /// Rule identifier of the contract specification, one of [`RULES`].
    pub(crate) rule: &'static str,
    /// What was observed.
    pub(crate) detail: String,
}

impl core::fmt::Display for Violation {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "{}: {}", self.rule, self.detail)
    }
}

macro_rules! require {
    ($condition:expr, $rule:literal, $($detail:tt)*) => {
        if !$condition {
            return Err(Violation { rule: $rule, detail: format!($($detail)*) });
        }
    };
}

const TABLE_A: &str = "t.a";
const TABLE_A_SUB: &str = "t.a.sub";
const TABLE_B: &str = "t.b";
const CELL: &str = "t.cell";
const EMPTY_TABLE: &str = "t.empty";
const UNKNOWN_TABLE: &str = "t.unknown";

type Model = BTreeMap<(&'static str, Vec<u8>), Vec<u8>>;

fn schema() -> StateSchema {
    StateSchema::new(vec![
        TableDescriptor::table(TABLE_B, "norito:key@0.0.2", "norito:value@0.0.2"),
        TableDescriptor::table(TABLE_A, "norito:key@0.0.2", "norito:value@0.0.2"),
        TableDescriptor::cell(CELL, "norito:cell@0.0.2"),
        TableDescriptor::table(TABLE_A_SUB, "norito:key@0.0.2", "norito:value@0.0.2"),
        TableDescriptor::table(EMPTY_TABLE, "norito:key@0.0.2", "norito:value@0.0.2"),
    ])
    .expect("suite schema is valid")
}

/// Keys chosen for byte-order edges: the empty key, prefixes, a `0x00` suffix, an empty
/// value, `0xff` runs and one key shared by tables with different values.
fn base_model() -> Model {
    let rows: [(&'static str, &[u8], &[u8]); 12] = [
        (TABLE_A, b"", b"empty-key"),
        (TABLE_A, b"a", b"1"),
        (TABLE_A, b"ab", b"2"),
        (TABLE_A, b"ab\0", b""),
        (TABLE_A, b"b", b"3"),
        (TABLE_A, b"\xff", b"4"),
        (TABLE_A, b"\xff\xff", b"5"),
        (TABLE_A_SUB, b"a", b"sub"),
        (TABLE_A_SUB, b"only-sub", b"s"),
        (TABLE_B, b"a", b"other"),
        (TABLE_B, b"only-b", b"x"),
        (CELL, CELL_KEY, b"cell-value"),
    ];
    rows.into_iter()
        .map(|(table, key, value)| ((table, key.to_vec()), value.to_vec()))
        .collect()
}

fn probe_keys() -> Vec<Vec<u8>> {
    [
        &b""[..],
        b"\0",
        b"0",
        b"a",
        b"a\0",
        b"aa",
        b"ab",
        b"ab\0",
        b"ab\0\0",
        b"abc",
        b"b",
        b"c",
        b"only-b",
        b"only-sub",
        b"\xfe",
        b"\xff",
        b"\xff\0",
        b"\xff\xff",
        b"\xff\xff\xff",
    ]
    .into_iter()
    .map(<[u8]>::to_vec)
    .collect()
}

fn changes_of(model: &Model) -> Vec<Change<'_>> {
    model
        .iter()
        .map(|((table, key), value)| Change {
            table,
            key,
            value: Some(value),
        })
        .collect()
}

fn build<C: KeyedStateCommitment>(schema: &StateSchema, model: &Model) -> Result<C, Violation> {
    let mut commitment = C::empty(schema);
    let applied = commitment.apply(&changes_of(model));
    require!(
        applied.is_ok(),
        "K10",
        "a valid change set was refused: {applied:?}"
    );
    Ok(commitment)
}

fn in_range<'a>(model: &'a Model, table: &str, range: KeyRange<'_>) -> Vec<Entry<'a>> {
    model
        .iter()
        .filter(|((candidate, key), _)| *candidate == table && range.contains(key))
        .map(|((_, key), value)| Entry { key, value })
        .collect()
}

/// One point statement that is false in the model.
enum FalsePoint {
    Inclusion(&'static str, Vec<u8>, Vec<u8>),
    Absence(&'static str, Vec<u8>),
}

fn rejects_point<C: KeyedStateCommitment>(
    schema: &StateSchema,
    root: &KeyedStateRoot,
    statement: &FalsePoint,
    witness: &Witness,
) -> bool {
    match statement {
        FalsePoint::Inclusion(table, key, value) => {
            C::verify_inclusion(schema, root, table, key, value, witness).is_err()
        }
        FalsePoint::Absence(table, key) => {
            C::verify_absence(schema, root, table, key, witness).is_err()
        }
    }
}

fn schema_binding<C: KeyedStateCommitment>() -> Result<(), Violation> {
    let key = "norito:key@0.0.2";
    let value = "norito:value@0.0.2";
    let variants = [
        vec![TableDescriptor::table("t.a", key, value)],
        vec![TableDescriptor::table("t.b", key, value)],
        vec![TableDescriptor::cell("t.a", value)],
        vec![TableDescriptor::table(
            "t.a",
            "norito:other-key@0.0.2",
            value,
        )],
        vec![TableDescriptor::table(
            "t.a",
            key,
            "norito:other-value@0.0.2",
        )],
        vec![TableDescriptor::table("t.a", key, "semantic:value@0.0.2")],
        vec![
            TableDescriptor::table("t.a", key, value),
            TableDescriptor::table("t.b", key, value),
        ],
    ];
    let mut roots = BTreeMap::new();
    for (index, tables) in variants.into_iter().enumerate() {
        let schema = StateSchema::new(tables).expect("variant schema is valid");
        let root = C::empty(&schema).root();
        require!(
            C::empty(&schema).root() == root,
            "K2",
            "two empty commitments of schema variant {index} have different roots"
        );
        if let Some(other) = roots.insert(root, index) {
            return Err(Violation {
                rule: "K1",
                detail: format!("schema variants {other} and {index} share an empty root"),
            });
        }
    }
    Ok(())
}

fn history_independence<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let batch: C = build(schema, model)?;
    let mut reversed_changes = changes_of(model);
    reversed_changes.reverse();
    let mut reversed = C::empty(schema);
    require!(
        reversed.apply(&reversed_changes).is_ok(),
        "K10",
        "a valid reordered change set was refused"
    );
    require!(
        reversed.root() == batch.root(),
        "K2",
        "the root depends on the order of changes inside one change set"
    );
    let mut stepwise = C::empty(schema);
    for change in reversed_changes {
        let junk = Change {
            table: TABLE_A,
            key: b"junk",
            value: Some(b"junk"),
        };
        let replaced = Change {
            value: Some(b"replaced"),
            ..change
        };
        for step in [
            vec![junk],
            vec![replaced],
            vec![change],
            vec![Change {
                value: None,
                ..junk
            }],
        ] {
            require!(
                stepwise.apply(&step).is_ok(),
                "K10",
                "a valid single-change set was refused"
            );
        }
    }
    require!(
        stepwise.root() == batch.root(),
        "K2",
        "the root depends on the update history of equal content"
    );
    require!(
        stepwise.entries() == batch.entries() && batch.entries() == model.len() as u64,
        "K2",
        "the entry count differs from the committed content"
    );
    Ok(())
}

/// Contents that differ in one value, one table, one empty-valued entry or only in
/// how the same bytes split into key and value have different roots (K3).
fn content_binding<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let base: C = build(schema, model)?;
    let variants: [(&str, &'static str, &[u8], Option<&[u8]>); 5] = [
        ("one replaced value", TABLE_A, b"a", Some(b"9")),
        ("one value emptied", TABLE_A, b"a", Some(b"")),
        ("one removed entry", TABLE_A, b"a", None),
        ("one added empty-valued entry", EMPTY_TABLE, b"", Some(b"")),
        (
            "one entry added to another table",
            TABLE_B,
            b"b",
            Some(b"3"),
        ),
    ];
    let mut roots = BTreeMap::from([(base.root(), "the base content")]);
    for (name, table, key, value) in variants {
        let mut changed: C = build(schema, model)?;
        let applied = changed.apply(&[Change { table, key, value }]);
        require!(applied.is_ok(), "K10", "a valid change set was refused");
        if let Some(other) = roots.insert(changed.root(), name) {
            return Err(Violation {
                rule: "K3",
                detail: format!("{other} and {name} share a root"),
            });
        }
    }
    let split = |key: &[u8], value: &[u8]| {
        let mut commitment = C::empty(schema);
        commitment
            .apply(&[Change {
                table: EMPTY_TABLE,
                key,
                value: Some(value),
            }])
            .map(|()| commitment.root())
    };
    let (left, right) = (split(b"ab", b"c"), split(b"a", b"bc"));
    require!(
        left.is_ok() && right.is_ok() && left != right,
        "K3",
        "the root does not frame key and value bytes: {left:?} {right:?}"
    );
    Ok(())
}

fn atomic_updates<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let mut commitment: C = build(schema, model)?;
    let root = commitment.root();
    let noops: [&[Change<'_>]; 3] = [
        &[],
        &[Change {
            table: TABLE_A,
            key: b"never-present",
            value: None,
        }],
        &[Change {
            table: TABLE_A,
            key: b"a",
            value: Some(b"1"),
        }],
    ];
    for noop in noops {
        require!(
            commitment.apply(noop).is_ok(),
            "K10",
            "a no-op change set was refused"
        );
        require!(
            commitment.root() == root,
            "K10",
            "a no-op change set changed the root"
        );
    }
    let first = Change {
        table: TABLE_A,
        key: b"staged",
        value: Some(b"1"),
    };
    let duplicate = commitment.apply(&[
        first,
        Change {
            value: Some(b"2"),
            ..first
        },
    ]);
    require!(
        duplicate == Err(UpdateError::DuplicateChange),
        "K10",
        "a change set naming one key twice returned {duplicate:?}"
    );
    let refused = commitment.apply(&[
        first,
        Change {
            table: UNKNOWN_TABLE,
            key: b"k",
            value: Some(b"v"),
        },
    ]);
    require!(
        refused == Err(UpdateError::Statement(StatementError::UnknownTable)),
        "K7",
        "a change of an undeclared table returned {refused:?}"
    );
    require!(
        commitment.root() == root && commitment.entries() == model.len() as u64,
        "K10",
        "a refused change set left part of itself applied"
    );
    Ok(())
}

fn cell_rule<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let mut commitment: C = build(schema, model)?;
    let root = commitment.root();
    let refused = commitment.apply(&[Change {
        table: CELL,
        key: b"x",
        value: Some(b"v"),
    }]);
    require!(
        refused == Err(UpdateError::Statement(StatementError::CellKey))
            && commitment.root() == root,
        "K8",
        "a cell accepted a nonempty key: {refused:?}"
    );
    let proof = commitment.prove_inclusion(CELL, b"x");
    require!(
        proof == Err(ProveError::Statement(StatementError::CellKey)),
        "K8",
        "inclusion of a nonempty cell key returned {proof:?}"
    );
    let witness = match commitment.prove_inclusion(CELL, CELL_KEY) {
        Ok(witness) => witness,
        Err(error) => {
            return Err(Violation {
                rule: "K4",
                detail: format!("the committed cell cannot be proven: {error:?}"),
            });
        }
    };
    require!(
        C::verify_inclusion(schema, &root, CELL, CELL_KEY, b"cell-value", &witness).is_ok(),
        "K4",
        "the committed cell does not verify"
    );
    let rejected = C::verify_absence(schema, &root, CELL, b"x", &witness);
    require!(
        rejected == Err(Rejection::Statement(StatementError::CellKey)),
        "K8",
        "absence of a nonempty cell key returned {rejected:?}"
    );
    let empty = C::empty(schema);
    let absent = match empty.prove_absence(CELL, CELL_KEY) {
        Ok(witness) => witness,
        Err(error) => {
            return Err(Violation {
                rule: "K5",
                detail: format!("an absent cell cannot be proven absent: {error:?}"),
            });
        }
    };
    require!(
        C::verify_absence(schema, &empty.root(), CELL, CELL_KEY, &absent).is_ok(),
        "K5",
        "an absent cell does not verify as absent"
    );
    Ok(())
}

fn table_isolation<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let commitment: C = build(schema, model)?;
    let root = commitment.root();
    let unknown = Err(ProveError::Statement(StatementError::UnknownTable));
    require!(
        commitment.prove_inclusion(UNKNOWN_TABLE, b"a") == unknown
            && commitment.prove_absence(UNKNOWN_TABLE, b"a") == unknown
            && commitment.prove_range(UNKNOWN_TABLE, KeyRange::FULL) == unknown,
        "K7",
        "an undeclared table was not refused by the prover"
    );
    let Ok(in_b) = commitment.prove_inclusion(TABLE_B, b"only-b") else {
        return Err(Violation {
            rule: "K4",
            detail: "a committed entry cannot be proven".into(),
        });
    };
    let unknown = Err(Rejection::Statement(StatementError::UnknownTable));
    require!(
        C::verify_inclusion(schema, &root, UNKNOWN_TABLE, b"only-b", b"x", &in_b) == unknown
            && C::verify_absence(schema, &root, UNKNOWN_TABLE, b"only-b", &in_b) == unknown
            && C::verify_range(schema, &root, UNKNOWN_TABLE, KeyRange::FULL, &[], &in_b) == unknown,
        "K7",
        "an undeclared table was not rejected by the verifier"
    );
    let Ok(absent_in_a) = commitment.prove_absence(TABLE_A, b"only-b") else {
        return Err(Violation {
            rule: "K7",
            detail: "a key of another table cannot be proven absent".into(),
        });
    };
    require!(
        C::verify_absence(schema, &root, TABLE_A, b"only-b", &absent_in_a).is_ok(),
        "K7",
        "a key of another table does not verify as absent"
    );
    let Ok(in_sub) = commitment.prove_inclusion(TABLE_A_SUB, b"only-sub") else {
        return Err(Violation {
            rule: "K4",
            detail: "a committed entry cannot be proven".into(),
        });
    };
    for witness in [&in_b, &absent_in_a, &in_sub] {
        require!(
            C::verify_inclusion(schema, &root, TABLE_A, b"only-b", b"x", witness).is_err(),
            "K7",
            "an entry of {TABLE_B} verified inside {TABLE_A}"
        );
        require!(
            C::verify_inclusion(schema, &root, TABLE_A, b"only-sub", b"s", witness).is_err(),
            "K7",
            "an entry of {TABLE_A_SUB} verified inside {TABLE_A}"
        );
        require!(
            C::verify_absence(schema, &root, TABLE_B, b"only-b", witness).is_err(),
            "K7",
            "an entry of {TABLE_B} verified as absent"
        );
    }
    Ok(())
}

/// Honest and false point statements at every probe position (K4, K5).
fn point_statements<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<Vec<Witness>, Violation> {
    let commitment: C = build(schema, model)?;
    let root = commitment.root();
    let mut witnesses = Vec::new();
    let mut false_statements = Vec::new();
    for table in [TABLE_A, TABLE_A_SUB, TABLE_B, EMPTY_TABLE, CELL] {
        let keys = if table == CELL {
            vec![CELL_KEY.to_vec()]
        } else {
            probe_keys()
        };
        for key in keys {
            let inclusion = commitment.prove_inclusion(table, &key);
            let absence = commitment.prove_absence(table, &key);
            if let Some(value) = model.get(&(table, key.clone())) {
                let Ok(witness) = inclusion else {
                    return Err(Violation {
                        rule: "K4",
                        detail: format!("committed {table}/{key:?} cannot be proven"),
                    });
                };
                require!(
                    C::verify_inclusion(schema, &root, table, &key, value, &witness).is_ok(),
                    "K4",
                    "the honest inclusion witness of {table}/{key:?} is rejected"
                );
                require!(
                    absence == Err(ProveError::KeyPresent),
                    "K5",
                    "absence of committed {table}/{key:?} returned {absence:?}"
                );
                let mut longer = value.clone();
                longer.push(0);
                let mut wrong = vec![longer, b"wrong".to_vec()];
                if let Some(first) = value.first() {
                    let mut flipped = value.clone();
                    flipped[0] = first ^ 1;
                    wrong.push(flipped);
                    wrong.push(Vec::new());
                }
                for value in wrong {
                    false_statements.push(FalsePoint::Inclusion(table, key.clone(), value));
                }
                false_statements.push(FalsePoint::Absence(table, key.clone()));
                witnesses.push(witness);
            } else {
                let Ok(witness) = absence else {
                    return Err(Violation {
                        rule: "K5",
                        detail: format!("absent {table}/{key:?} cannot be proven absent"),
                    });
                };
                require!(
                    C::verify_absence(schema, &root, table, &key, &witness).is_ok(),
                    "K5",
                    "the honest absence witness of {table}/{key:?} is rejected"
                );
                require!(
                    inclusion == Err(ProveError::KeyAbsent),
                    "K4",
                    "inclusion of absent {table}/{key:?} returned {inclusion:?}"
                );
                for value in [Vec::new(), b"x".to_vec()] {
                    false_statements.push(FalsePoint::Inclusion(table, key.clone(), value));
                }
                witnesses.push(witness);
            }
        }
    }
    for statement in &false_statements {
        for witness in &witnesses {
            if !rejects_point::<C>(schema, &root, statement, witness) {
                return Err(match statement {
                    FalsePoint::Inclusion(table, key, value) => Violation {
                        rule: "K4",
                        detail: format!("false inclusion {table}/{key:?} = {value:?} verified"),
                    },
                    FalsePoint::Absence(table, key) => Violation {
                        rule: "K5",
                        detail: format!("false absence of {table}/{key:?} verified"),
                    },
                });
            }
        }
    }
    Ok(witnesses)
}

fn ranges() -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let bounded = |lower: &[u8], upper: &[u8]| (lower.to_vec(), Some(upper.to_vec()));
    vec![
        (Vec::new(), None),
        bounded(b"", b"a"),
        bounded(b"a", b"ab"),
        bounded(b"a", b"b"),
        bounded(b"ab", b"ab\0"),
        bounded(b"ab", b"ab\x01"),
        bounded(b"aa", b"ab"),
        bounded(b"c", b"d"),
        (b"b".to_vec(), None),
        (b"\xff".to_vec(), None),
        bounded(b"\xff", b"\xff\xff"),
        (b"a".to_vec(), prefix_upper_bound(b"a")),
        (b"ab".to_vec(), prefix_upper_bound(b"ab")),
        (b"\xff".to_vec(), prefix_upper_bound(b"\xff")),
    ]
}

/// False variants of one true range statement: omission, substitution, addition,
/// reordering and duplication.
fn false_ranges<'a>(
    model: &Model,
    table: &'static str,
    range: KeyRange<'_>,
    honest: &[Entry<'a>],
    fake_key: &'a [u8],
) -> Vec<Vec<Entry<'a>>> {
    let mut variants = Vec::new();
    for skipped in 0..honest.len() {
        let mut omitted = honest.to_vec();
        omitted.remove(skipped);
        variants.push(omitted);
        let mut substituted = honest.to_vec();
        substituted[skipped].value = b"substituted";
        variants.push(substituted);
    }
    if range.contains(fake_key) && !model.contains_key(&(table, fake_key.to_vec())) {
        let mut added = honest.to_vec();
        added.push(Entry {
            key: fake_key,
            value: b"fake",
        });
        added.sort_by(|left, right| left.key.cmp(right.key));
        variants.push(added);
    }
    if honest.len() >= 2 {
        let mut swapped = honest.to_vec();
        swapped.swap(0, 1);
        variants.push(swapped);
    }
    if let Some(first) = honest.first() {
        let mut duplicated = honest.to_vec();
        duplicated.insert(0, *first);
        variants.push(duplicated);
    }
    variants
}

/// Claimed lists that are the honest list of one interval plus one entry outside it:
/// the committed neighbour below `lower`, the committed neighbour at or above `upper`
/// and, for a table, the uncommitted exclusive bound itself. Each list is strictly
/// ascending, so the entry outside the interval is its only defect.
fn outside_claims<'a>(
    model: &'a Model,
    table: &'static str,
    lower: &'a [u8],
    upper: Option<&'a [u8]>,
    honest: &[Entry<'a>],
) -> Vec<Vec<Entry<'a>>> {
    let committed = in_range(model, table, KeyRange::FULL);
    let mut variants = Vec::new();
    if let Some(below) = committed.iter().rev().find(|entry| entry.key < lower) {
        let mut claimed = vec![*below];
        claimed.extend_from_slice(honest);
        variants.push(claimed);
    }
    if let Some(upper) = upper {
        let above = committed.iter().find(|entry| entry.key >= upper);
        let mut bounds = Vec::from_iter(above.copied());
        if table != CELL && above.is_none_or(|entry| entry.key != upper) {
            bounds.push(Entry {
                key: upper,
                value: b"fake",
            });
        }
        for bound in bounds {
            let mut claimed = honest.to_vec();
            claimed.push(bound);
            variants.push(claimed);
        }
    }
    variants
}

fn range_statements<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<Vec<Witness>, Violation> {
    let commitment: C = build(schema, model)?;
    let root = commitment.root();
    let mut issued = Vec::new();
    let mut outside = 0_usize;
    for (lower, upper) in [
        (b"b".to_vec(), b"a".to_vec()),
        (b"a".to_vec(), b"a".to_vec()),
    ] {
        let range = KeyRange::new(&lower, Some(&upper));
        let proof = commitment.prove_range(TABLE_A, range);
        require!(
            proof == Err(ProveError::Statement(StatementError::EmptyRange)),
            "K6",
            "an empty interval returned {proof:?}"
        );
    }
    for table in [TABLE_A, TABLE_A_SUB, TABLE_B, EMPTY_TABLE, CELL] {
        let full = in_range(model, table, KeyRange::FULL);
        for (lower, upper) in ranges() {
            let range = KeyRange::new(&lower, upper.as_deref());
            let honest = in_range(model, table, range);
            let witness = match commitment.prove_range(table, range) {
                Ok(witness) => witness,
                Err(error) => {
                    return Err(Violation {
                        rule: "K6",
                        detail: format!("range {table}/{range:?} cannot be proven: {error:?}"),
                    });
                }
            };
            require!(
                C::verify_range(schema, &root, table, range, &honest, &witness).is_ok(),
                "K6",
                "the honest witness of range {table}/{range:?} is rejected"
            );
            let mut fake_key = lower.clone();
            fake_key.extend_from_slice(b"\0fake");
            for variant in false_ranges(model, table, range, &honest, &fake_key) {
                require!(
                    C::verify_range(schema, &root, table, range, &variant, &witness).is_err(),
                    "K6",
                    "a false entry list verified for range {table}/{range:?}: {variant:?}"
                );
            }
            for variant in outside_claims(model, table, &lower, upper.as_deref(), &honest) {
                let rejected = C::verify_range(schema, &root, table, range, &variant, &witness);
                require!(
                    rejected == Err(Rejection::Statement(StatementError::EntryOutsideRange)),
                    "K6",
                    "a claimed entry outside range {table}/{range:?} returned {rejected:?}: {variant:?}"
                );
                outside += 1;
            }
            if full.len() > honest.len() {
                require!(
                    C::verify_range(schema, &root, table, KeyRange::FULL, &honest, &witness)
                        .is_err(),
                    "K6",
                    "the entries of {table}/{range:?} verified as the complete table"
                );
            }
            for other in [TABLE_A, TABLE_B, EMPTY_TABLE] {
                if in_range(model, other, range) != honest {
                    require!(
                        C::verify_range(schema, &root, other, range, &honest, &witness).is_err(),
                        "K7",
                        "the entries of {table}/{range:?} verified inside {other}"
                    );
                }
            }
            issued.push(witness);
        }
        // Every witness issued so far must also reject each false list of this table.
        for (lower, upper) in ranges() {
            let range = KeyRange::new(&lower, upper.as_deref());
            let honest = in_range(model, table, range);
            let mut fake_key = lower.clone();
            fake_key.extend_from_slice(b"\0fake");
            for variant in false_ranges(model, table, range, &honest, &fake_key) {
                for witness in &issued {
                    require!(
                        C::verify_range(schema, &root, table, range, &variant, witness).is_err(),
                        "K6",
                        "a false entry list verified for range {table}/{range:?} under another witness"
                    );
                }
            }
        }
    }
    let rejected = C::verify_range(
        schema,
        &root,
        TABLE_A,
        KeyRange::new(b"b", Some(b"a")),
        &[],
        &issued[0],
    );
    require!(
        rejected == Err(Rejection::Statement(StatementError::EmptyRange)),
        "K6",
        "verification of an empty interval returned {rejected:?}"
    );
    require!(
        outside > 0,
        "K6",
        "the suite model offers no claimed entry outside an interval"
    );
    Ok(issued)
}

/// Statements that a later State falsifies must be rejected at its root (K12).
fn root_binding<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let old: C = build(schema, model)?;
    let old_root = old.root();
    let range = KeyRange::new(b"a", Some(b"b"));
    let old_range = in_range(model, TABLE_A, range);
    let proofs = (
        old.prove_inclusion(TABLE_A, b"a"),
        old.prove_inclusion(TABLE_A, b"b"),
        old.prove_absence(TABLE_A, b"0"),
        old.prove_range(TABLE_A, range),
    );
    let (Ok(included), Ok(removed), Ok(absent), Ok(ranged)) = proofs else {
        return Err(Violation {
            rule: "K4",
            detail: "true statements of the base State cannot be proven".into(),
        });
    };
    let mut next = old;
    let applied = next.apply(&[
        Change {
            table: TABLE_A,
            key: b"a",
            value: Some(b"changed"),
        },
        Change {
            table: TABLE_A,
            key: b"b",
            value: None,
        },
        Change {
            table: TABLE_A,
            key: b"0",
            value: Some(b"new"),
        },
        Change {
            table: TABLE_A,
            key: b"aa",
            value: Some(b"inside"),
        },
    ]);
    require!(applied.is_ok(), "K10", "a valid change set was refused");
    let root = next.root();
    require!(
        root != old_root,
        "K3",
        "different committed contents share a root"
    );
    require!(
        C::verify_inclusion(schema, &root, TABLE_A, b"a", b"1", &included).is_err(),
        "K12",
        "a replaced value still verifies at the later root"
    );
    require!(
        C::verify_inclusion(schema, &root, TABLE_A, b"b", b"3", &removed).is_err(),
        "K12",
        "a removed entry still verifies at the later root"
    );
    require!(
        C::verify_absence(schema, &root, TABLE_A, b"0", &absent).is_err(),
        "K12",
        "an inserted key still verifies as absent at the later root"
    );
    require!(
        C::verify_range(schema, &root, TABLE_A, range, &old_range, &ranged).is_err(),
        "K12",
        "a range that gained an entry still verifies at the later root"
    );
    require!(
        C::verify_inclusion(schema, &old_root, TABLE_A, b"a", b"1", &included).is_ok()
            && C::verify_absence(schema, &old_root, TABLE_A, b"0", &absent).is_ok()
            && C::verify_range(schema, &old_root, TABLE_A, range, &old_range, &ranged).is_ok(),
        "K12",
        "verification at the earlier root is not a pure function of its inputs"
    );
    let fresh = next.prove_inclusion(TABLE_A, b"a");
    require!(
        fresh.is_ok_and(|witness| {
            C::verify_inclusion(schema, &root, TABLE_A, b"a", b"changed", &witness).is_ok()
        }),
        "K4",
        "the replaced value cannot be proven at the later root"
    );
    Ok(())
}

/// Verification consumes the complete canonical encoding (K9): a truncated encoding and
/// an encoding followed by further bytes are rejected, and no changed witness establishes
/// the false statement `verify_false` checks. A changed witness may still verify the true
/// statement when it is an independently valid witness: proofs need not be non-malleable.
fn canonical_witnesses(
    verify: impl Fn(&Witness) -> Result<(), Rejection>,
    verify_false: impl Fn(&Witness) -> Result<(), Rejection>,
    witness: &Witness,
    statement: &str,
) -> Result<(), Violation> {
    require!(
        verify(witness).is_ok(),
        "K9",
        "the honest witness of {statement} is rejected"
    );
    require!(
        verify_false(witness).is_err(),
        "K9",
        "the honest witness of {statement} establishes a false statement"
    );
    let bytes = witness.as_bytes();
    for length in 0..bytes.len() {
        require!(
            verify(&Witness::new(bytes[..length].to_vec())).is_err(),
            "K9",
            "the witness of {statement} verified after truncation to {length} bytes"
        );
    }
    for extra in [0_u8, 0xff] {
        let mut extended = bytes.to_vec();
        extended.push(extra);
        require!(
            verify(&Witness::new(extended)).is_err(),
            "K9",
            "the witness of {statement} verified with a trailing byte"
        );
    }
    for index in 0..bytes.len() {
        for mask in [0x01_u8, 0x80] {
            let mut changed = bytes.to_vec();
            changed[index] ^= mask;
            require!(
                verify_false(&Witness::new(changed)).is_err(),
                "K9",
                "the witness of {statement} with byte {index} changed established a false statement"
            );
        }
    }
    Ok(())
}

fn witness_canonicality<C: KeyedStateCommitment>(
    schema: &StateSchema,
    model: &Model,
) -> Result<(), Violation> {
    let commitment: C = build(schema, model)?;
    let root = commitment.root();
    let range = KeyRange::new(b"a", Some(b"b"));
    let entries = in_range(model, TABLE_A, range);
    let proofs = (
        commitment.prove_inclusion(TABLE_A, b"ab"),
        commitment.prove_absence(TABLE_A, b"aa"),
        commitment.prove_range(TABLE_A, range),
        commitment.prove_range(EMPTY_TABLE, KeyRange::FULL),
    );
    let (Ok(included), Ok(absent), Ok(ranged), Ok(empty)) = proofs else {
        return Err(Violation {
            rule: "K4",
            detail: "true statements of the base State cannot be proven".into(),
        });
    };
    canonical_witnesses(
        |witness| C::verify_inclusion(schema, &root, TABLE_A, b"ab", b"2", witness),
        |witness| C::verify_inclusion(schema, &root, TABLE_A, b"ab", b"3", witness),
        &included,
        "an inclusion",
    )?;
    canonical_witnesses(
        |witness| C::verify_absence(schema, &root, TABLE_A, b"aa", witness),
        |witness| C::verify_inclusion(schema, &root, TABLE_A, b"aa", b"", witness),
        &absent,
        "an absence",
    )?;
    canonical_witnesses(
        |witness| C::verify_range(schema, &root, TABLE_A, range, &entries, witness),
        |witness| C::verify_range(schema, &root, TABLE_A, range, &entries[1..], witness),
        &ranged,
        "a range",
    )?;
    let fake = [Entry {
        key: b"k",
        value: b"v",
    }];
    canonical_witnesses(
        |witness| C::verify_range(schema, &root, EMPTY_TABLE, KeyRange::FULL, &[], witness),
        |witness| C::verify_range(schema, &root, EMPTY_TABLE, KeyRange::FULL, &fake, witness),
        &empty,
        "an empty range",
    )
}

/// Deterministic pseudo-random workload: xorshift64, fixed seed.
struct Workload(u64);

impl Workload {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

/// Incremental updates equal a cold build of the same content, and distinct
/// contents have distinct roots (K11, K3).
fn incremental_equals_cold<C: KeyedStateCommitment>(
    schema: &StateSchema,
    base: &Model,
) -> Result<(), Violation> {
    const ROUNDS: usize = 96;
    let tables = [TABLE_A, TABLE_A_SUB, TABLE_B];
    let keys = probe_keys();
    let mut workload = Workload(0x9e37_79b9_7f4a_7c15);
    let mut model = base.clone();
    let mut incremental: C = build(schema, &model)?;
    let mut roots: BTreeMap<Vec<((&'static str, Vec<u8>), Vec<u8>)>, KeyedStateRoot> =
        BTreeMap::new();
    for round in 0..ROUNDS {
        let mut touched = BTreeSet::new();
        let mut staged: Vec<(&'static str, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for _ in 0..=workload.next(6) {
            let (table, key) = if workload.next(8) == 0 {
                (CELL, CELL_KEY.to_vec())
            } else {
                let table = tables[usize::try_from(workload.next(tables.len() as u64))
                    .expect("fixture value fits usize")];
                (
                    table,
                    keys[usize::try_from(workload.next(keys.len() as u64))
                        .expect("fixture value fits usize")]
                    .clone(),
                )
            };
            if !touched.insert((table, key.clone())) {
                continue;
            }
            let value = match workload.next(4) {
                0 => None,
                1 => Some(Vec::new()),
                size => Some(vec![
                    u8::try_from(workload.next(251))
                        .expect("fixture value fits u8");
                    usize::try_from(size).expect("fixture value fits usize")
                ]),
            };
            staged.push((table, key, value));
        }
        let changes: Vec<Change<'_>> = staged
            .iter()
            .map(|(table, key, value)| Change {
                table,
                key,
                value: value.as_deref(),
            })
            .collect();
        require!(
            incremental.apply(&changes).is_ok(),
            "K10",
            "a valid change set was refused in round {round}"
        );
        for (table, key, value) in staged {
            match value {
                Some(value) => model.insert((table, key), value),
                None => model.remove(&(table, key)),
            };
        }
        let cold: C = build(schema, &model)?;
        require!(
            incremental.root() == cold.root() && incremental.entries() == model.len() as u64,
            "K11",
            "the incremental root differs from a cold build in round {round}"
        );
        let content: Vec<_> = model.clone().into_iter().collect();
        let root = incremental.root();
        if let Some(known) = roots.insert(content, root) {
            require!(
                known == root,
                "K2",
                "equal contents have different roots in round {round}"
            );
        }
        let (table, key) = (
            tables[usize::try_from(workload.next(tables.len() as u64))
                .expect("fixture value fits usize")],
            keys[usize::try_from(workload.next(keys.len() as u64))
                .expect("fixture value fits usize")]
            .clone(),
        );
        match model.get(&(table, key.clone())) {
            Some(value) => require!(
                incremental
                    .prove_inclusion(table, &key)
                    .is_ok_and(|witness| {
                        C::verify_inclusion(schema, &root, table, &key, value, &witness).is_ok()
                            && C::verify_absence(schema, &root, table, &key, &witness).is_err()
                    }),
                "K4",
                "committed {table}/{key:?} does not verify in round {round}"
            ),
            None => require!(
                incremental.prove_absence(table, &key).is_ok_and(|witness| {
                    C::verify_absence(schema, &root, table, &key, &witness).is_ok()
                        && C::verify_inclusion(schema, &root, table, &key, b"", &witness).is_err()
                }),
                "K5",
                "absent {table}/{key:?} does not verify in round {round}"
            ),
        }
        let honest = in_range(&model, table, KeyRange::FULL);
        require!(
            incremental
                .prove_range(table, KeyRange::FULL)
                .is_ok_and(|witness| {
                    C::verify_range(schema, &root, table, KeyRange::FULL, &honest, &witness).is_ok()
                        && (honest.is_empty()
                            || C::verify_range(
                                schema,
                                &root,
                                table,
                                KeyRange::FULL,
                                &honest[1..],
                                &witness,
                            )
                            .is_err())
                }),
            "K6",
            "the complete table {table} does not verify in round {round}"
        );
    }
    let distinct: BTreeSet<KeyedStateRoot> = roots.values().copied().collect();
    require!(
        distinct.len() == roots.len(),
        "K3",
        "{} distinct contents produced only {} roots",
        roots.len(),
        distinct.len()
    );
    Ok(())
}

/// Check one candidate construction against the complete contract.
///
/// # Errors
/// The first violated rule, with the observation that violates it.
pub(crate) fn check_contract<C: KeyedStateCommitment>() -> Result<(), Violation> {
    let schema = schema();
    let model = base_model();
    schema_binding::<C>()?;
    history_independence::<C>(&schema, &model)?;
    atomic_updates::<C>(&schema, &model)?;
    content_binding::<C>(&schema, &model)?;
    table_isolation::<C>(&schema, &model)?;
    cell_rule::<C>(&schema, &model)?;
    point_statements::<C>(&schema, &model)?;
    range_statements::<C>(&schema, &model)?;
    root_binding::<C>(&schema, &model)?;
    witness_canonicality::<C>(&schema, &model)?;
    incremental_equals_cold::<C>(&schema, &model)
}
