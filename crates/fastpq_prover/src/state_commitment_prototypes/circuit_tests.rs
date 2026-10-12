//! The hash-chain relation on witnesses of the actual tree candidates: honest
//! witnesses of every kind are accepted by the reference and cost exactly the
//! hashes of the native verifier; forged inclusion, absence and range
//! witnesses of every candidate are rejected; and each constraint group is
//! shown to be load-bearing by a forged trace that only the relation without
//! that group accepts.

use std::collections::BTreeMap;

use super::*;
use crate::{
    air::{
        AirError, NoObserver, ReferenceArtifact, ReferenceChallenges, build_reference,
        check_reference,
    },
    state_commitment_prototypes::{
        Change, Engine, KeyedMap,
        critbit::ByteKey,
        entry_leaf,
        fringe::forge::{Role, reemit},
        hash::{HashProfile, take_hash_work},
        key_digest,
        keyed::{TableChange, VerifyError, descriptor_from_rows, normalised_root},
    },
};

const TABLE: &str = "t.a";

fn schema() -> PrototypeSchema {
    PrototypeSchema::from_descriptor(&descriptor_from_rows(&[
        (TABLE, "norito:key@0.0.2", "norito:value@0.0.2"),
        ("t.b", "norito:key@0.0.2", "norito:value@0.0.2"),
        ("t.cell", "", "norito:value@0.0.2"),
    ]))
    .expect("a canonical descriptor")
}

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

/// Eleven entries of one table, one entry of another table and a cell.
fn sample<E: Engine>() -> (PrototypeSchema, u32, Model, KeyedMap<E>) {
    let schema = schema();
    let table = schema.position(TABLE).unwrap();
    let mut model = Model::new();
    for (index, key) in [
        &b"a"[..],
        b"ab",
        b"ab\0",
        b"b",
        b"ba",
        b"c",
        b"k1",
        b"k2",
        b"k3",
        b"x",
        b"\xff",
    ]
    .iter()
    .enumerate()
    {
        let fill = u8::try_from(index + 1).expect("a small sample index");
        model.insert(key.to_vec(), vec![fill; 5]);
    }
    let mut changes: Vec<TableChange<'_>> = model
        .iter()
        .map(|(key, value)| (table, key.as_slice(), Some(value.as_slice())))
        .collect();
    changes.push((schema.position("t.b").unwrap(), b"other", Some(b"o")));
    changes.push((schema.position("t.cell").unwrap(), b"", Some(b"cell")));
    let mut map = KeyedMap::<E>::empty(schema.clone());
    map.apply(&changes).unwrap();
    (schema, table, model, map)
}

fn challenges(constraints: usize) -> ReferenceChallenges {
    ReferenceChallenges::derive(&[0x47; 32], constraints)
}

/// Numerator slots of each group for a register count.
fn slots(group: ConstraintGroup, registers: usize) -> core::ops::RangeInclusive<usize> {
    let saved = 12 + 4 * registers;
    match group {
        ConstraintGroup::Rounds | ConstraintGroup::Link => 0..=11,
        // The rate words of the link numerators hold the sibling terms.
        ConstraintGroup::PublicSibling | ConstraintGroup::SavedSibling => 4..=11,
        ConstraintGroup::Saved => 12..=saved - 1,
        ConstraintGroup::SideBoolean => saved..=saved,
        ConstraintGroup::PublicSide => saved + 1..=saved + 1,
        ConstraintGroup::Anchor => saved + 2..=saved + 5,
    }
}

/// Build and check the reference of a program; returns the artifact.
fn accept<P: AirPermutation + Sync>(program: &Program) -> ReferenceArtifact {
    let air = ChainAir::<P>::new(&program.public_view());
    let registers = program.registers();
    let schema = air.schema();
    let challenges = challenges(schema.constraints);
    let columns = air.witness_columns(program);
    let limits = air.reference_limits();
    let artifact = build_reference(&air, columns, &challenges, limits, &NoObserver)
        .expect("an honest witness satisfies the relation");
    check_reference(&air, &artifact, &challenges, limits, &NoObserver)
        .expect("the checker accepts the honest artifact");
    assert_eq!(schema.trace_rows, ChainAir::<P>::rows_for(program));
    assert_eq!(schema.trace_rows, air.blocks() * P::ROWS);
    assert_eq!(air.registers(), registers);
    // Twelve state columns, the side bit and four words per register are
    // private; twenty fixed and two per register are verifier-known.
    assert_eq!(
        schema.width,
        13 + 4 * registers + 20 + 2 * registers + P::PERIODIC
    );
    assert_eq!(schema.width, ChainAir::<P>::width_with(registers));
    assert_eq!(schema.constraints, 18 + 4 * registers);
    assert_eq!(
        schema.constraints,
        ChainAir::<P>::constraints_with(registers)
    );
    assert!(schema.identity.starts_with(P::RELATION));
    assert!(
        schema
            .identity
            .ends_with(&format!(":registers-{registers}"))
    );
    assert_eq!(
        schema.numerator_degree_bound,
        8 * (schema.trace_rows - 1) + 1
    );
    artifact
}

/// The first violated numerator of a trace under a relation.
fn violation<P: AirPermutation + Sync>(air: &ChainAir<P>, columns: Vec<Vec<u64>>) -> Option<usize> {
    match build_reference(
        air,
        columns,
        &challenges(air.schema().constraints),
        air.reference_limits(),
        &NoObserver,
    ) {
        Ok(_) => None,
        Err(AirError::ConstraintViolated { constraint, .. }) => Some(constraint),
        Err(other) => panic!("unexpected reference failure: {other}"),
    }
}

/// Sponge permutations of one native verification that is known to accept.
fn native_permutations(verify: impl FnOnce() -> core::result::Result<(), VerifyError>) -> usize {
    let _ = take_hash_work();
    verify().expect("the honest witness verifies");
    usize::try_from(take_hash_work().permutations).expect("a small count")
}

/// The program hashes what the native verifier hashes, each hash once: one
/// permutation per native permutation, and one root normalisation per anchor
/// where the native verifier normalises once.
fn assert_hash_count(program: &Program, native: usize) {
    let anchors = program.blocks.iter().filter(|block| block.anchor).count();
    assert_eq!(program.permutations(), native + anchors - 1);
}

fn honest_statements<E, P>(range_anchors_per_leaf: bool)
where
    E: WitnessPrograms<Hash = AlgebraicSponge<P>>,
    P: AirPermutation + Sync,
{
    let (schema, table, model, map) = sample::<E>();
    let root = map.root();
    let entries: Vec<(&[u8], &[u8])> = model
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();

    // Inclusion of a committed entry.
    let (key, value) = entries[3];
    let witness = map.prove_inclusion(table, key).unwrap().unwrap();
    let native = native_permutations(|| {
        KeyedMap::<E>::verify_inclusion(&schema, &root, table, key, value, &witness)
    });
    let inclusion = inclusion_statement::<E>(&schema, &root, table, key, value, &witness).unwrap();
    assert!(inclusion.blocks.last().unwrap().anchor);
    assert_eq!(inclusion.registers(), 1);
    assert_hash_count(&inclusion, native);
    accept::<P>(&inclusion);

    // Absence of a key between two committed keys, below all and above all.
    for absent in [&b"bb"[..], b"", b"\xff\xff"] {
        let witness = map.prove_absence(table, absent).unwrap().unwrap();
        let native = native_permutations(|| {
            KeyedMap::<E>::verify_absence(&schema, &root, table, absent, &witness)
        });
        let program = absence_statement::<E>(&schema, &root, table, absent, &witness).unwrap();
        assert_hash_count(&program, native);
        assert!(program.registers() <= 2);
        accept::<P>(&program);
    }

    // A complete range with two entries, an empty range, a range of six and
    // the complete table.
    for (lower, upper) in [
        (&b"k1"[..], Some(&b"k3"[..])),
        (b"d", Some(b"e")),
        (b"ab", Some(b"k2")),
        (b"", None),
    ] {
        let claimed: Vec<(&[u8], &[u8])> = entries
            .iter()
            .copied()
            .filter(|(key, _)| *key >= lower && upper.is_none_or(|upper| *key < upper))
            .collect();
        let witness = map.prove_range(table, lower, upper).unwrap();
        let native = native_permutations(|| {
            KeyedMap::<E>::verify_range(&schema, &root, table, lower, upper, &claimed, &witness)
        });
        let program =
            range_statement::<E>(&schema, &root, table, lower, upper, &claimed, &witness).unwrap();
        assert_hash_count(&program, native);
        let anchors = program.blocks.iter().filter(|block| block.anchor).count();
        if range_anchors_per_leaf {
            // The bracketing leaf and one leaf per claimed entry.
            assert_eq!(anchors, claimed.len() + 1);
            assert_eq!(program.registers(), 2);
        } else {
            assert_eq!(anchors, 1);
            // The schedule keeps at most one digest per level of a balanced
            // evaluation and the key digest of the leaf being hashed.
            let revealed = claimed.len() + 2;
            assert!(
                program.registers() <= (usize::BITS - revealed.leading_zeros()) as usize + 1,
                "{} registers for {} claimed entries",
                program.registers(),
                claimed.len()
            );
            if claimed.len() >= 2 {
                assert!(
                    program.registers() >= 2,
                    "two claimed entries share a branch"
                );
            }
        }
        accept::<P>(&program);
        // An omitted entry has no program: the native structural rules refuse it.
        if let Some((_, shorter)) = claimed.split_first() {
            assert!(
                range_statement::<E>(&schema, &root, table, lower, upper, shorter, &witness)
                    .is_err()
            );
        }
    }

    // The empty State: absence and the empty complete table.
    let empty = KeyedMap::<E>::empty(schema.clone());
    let witness = empty.prove_absence(table, b"k").unwrap().unwrap();
    accept::<P>(&absence_statement::<E>(&schema, &empty.root(), table, b"k", &witness).unwrap());
    let witness = empty.prove_range(table, b"", None).unwrap();
    accept::<P>(
        &range_statement::<E>(&schema, &empty.root(), table, b"", None, &[], &witness).unwrap(),
    );
}

#[test]
fn radix_witnesses_of_every_kind_satisfy_the_relation() {
    honest_statements::<RadixTree<AlgebraicSponge<Poseidon2Goldilocks12>>, _>(false);
    honest_statements::<RadixTree<AlgebraicSponge<RescuePrime64>>, _>(false);
}

#[test]
fn btree_witnesses_of_every_kind_satisfy_the_relation() {
    honest_statements::<MerkleBTree<AlgebraicSponge<Poseidon2Goldilocks12>>, _>(false);
    honest_statements::<MerkleBTree<AlgebraicSponge<RescuePrime64>>, _>(false);
}

#[test]
fn linked_leaf_witnesses_of_every_kind_satisfy_the_relation() {
    honest_statements::<LinkedLeafMap<AlgebraicSponge<Poseidon2Goldilocks12>>, _>(true);
    honest_statements::<LinkedLeafMap<AlgebraicSponge<RescuePrime64>>, _>(true);
}

type Radix<P> = RadixTree<AlgebraicSponge<P>>;
type BTree<P> = MerkleBTree<AlgebraicSponge<P>>;
type Linked<P> = LinkedLeafMap<AlgebraicSponge<P>>;

/// An honest inclusion program of the radix sample with its statement.
fn radix_inclusion<P: AirPermutation + Sync>(key: &[u8]) -> (Program, Vec<u8>) {
    let (schema, table, model, map) = sample::<Radix<P>>();
    let value = model[key].clone();
    let witness = map.prove_inclusion(table, key).unwrap().unwrap();
    let program =
        inclusion_statement::<Radix<P>>(&schema, &map.root(), table, key, &value, &witness)
            .unwrap();
    (program, value)
}

fn forged_inclusions_are_rejected<P: AirPermutation + Sync>() {
    let (program, _) = radix_inclusion::<P>(b"k2");
    let air = ChainAir::<P>::new(&program.public_view());
    let artifact = accept::<P>(&program);
    let anchor = slots(ConstraintGroup::Anchor, 1);
    let challenges = challenges(air.schema().constraints);

    // A changed private sibling no longer reaches the root.
    let mut forged = program.clone();
    let sibling = forged
        .blocks
        .iter_mut()
        .find_map(|block| match &mut block.input {
            Input::Compress {
                sibling: Sibling::Private(digest),
                ..
            } => Some(digest),
            _ => None,
        })
        .expect("the path has a private sibling");
    sibling[0] ^= 1;
    assert!(
        violation(&air, air.witness_columns(&forged)).is_some_and(|slot| anchor.contains(&slot))
    );

    // The same trace does not satisfy the relation of another root.
    let mut other_root = program.clone();
    other_root.root[2] ^= 1;
    let other_air = ChainAir::<P>::new(&other_root.public_view());
    assert!(
        violation(&other_air, air.witness_columns(&program))
            .is_some_and(|slot| anchor.contains(&slot))
    );

    // The artifact of one statement is not an artifact of another: neither
    // under its own statement bytes nor relabelled with the other's.
    let (schema, table, _, map) = sample::<Radix<P>>();
    let witness = map.prove_inclusion(table, b"k2").unwrap().unwrap();
    let claimed =
        inclusion_statement::<Radix<P>>(&schema, &map.root(), table, b"k2", b"forged", &witness)
            .unwrap();
    let claimed_air = ChainAir::<P>::new(&claimed.public_view());
    let limits = claimed_air.reference_limits();
    assert!(matches!(
        check_reference(&claimed_air, &artifact, &challenges, limits, &NoObserver),
        Err(AirError::StatementMismatch)
    ));
    let (identity, _, columns, quotient) = artifact.clone().into_parts();
    let relabelled = ReferenceArtifact::from_parts(
        identity,
        claimed_air.statement_bytes().to_vec(),
        columns,
        quotient,
    );
    assert!(matches!(
        check_reference(&claimed_air, &relabelled, &challenges, limits, &NoObserver),
        Err(AirError::PublicColumnMismatch { .. })
    ));
    // Executed honestly, the false statement does not reach the root.
    assert!(
        violation(&claimed_air, claimed_air.witness_columns(&claimed))
            .is_some_and(|slot| anchor.contains(&slot))
    );
    // A verifier's view carries no private sibling, and it fixes the relation.
    let view = program.public_view();
    assert_ne!(view, program);
    assert_eq!(
        ChainAir::<P>::new(&view).statement_bytes(),
        air.statement_bytes()
    );
    assert_eq!(view.permutations(), program.permutations());
    assert_eq!(view.private_siblings(), program.private_siblings());
    assert!(program.private_siblings() >= 3);
}

#[test]
fn forged_inclusions_are_rejected_by_both_relations() {
    forged_inclusions_are_rejected::<Poseidon2Goldilocks12>();
    forged_inclusions_are_rejected::<RescuePrime64>();
}

/// A false statement whose program the verifier derives, and the trace of a
/// prover who follows the committed tree instead of the statement: the stated
/// program executed honestly misses the root, the prover's trace violates
/// exactly the binding of `group`, and only the relation without that binding
/// accepts it.
fn assert_binding<P: AirPermutation + Sync>(
    group: ConstraintGroup,
    stated: &Program,
    followed: &Program,
) {
    let registers = stated.registers();
    assert_eq!(stated.public_view().blocks.len(), followed.blocks.len());
    let air = ChainAir::<P>::new(&stated.public_view());
    let challenges = challenges(air.schema().constraints);
    let limits = air.reference_limits();
    let missed = violation(&air, air.witness_columns(stated))
        .expect("the stated program does not reach the root");
    assert!(
        slots(ConstraintGroup::Anchor, registers).contains(&missed),
        "{group:?}: the honest execution violates slot {missed}"
    );
    let columns = air.witness_columns(followed);
    let violated = violation(&air, columns.clone()).expect("the forged trace is rejected");
    assert!(
        slots(group, registers).contains(&violated),
        "{group:?}: the forged trace violates slot {violated}"
    );
    let weakened = ChainAir::<P>::new(&stated.public_view()).without(group);
    let artifact = build_reference(&weakened, columns, &challenges, limits, &NoObserver)
        .unwrap_or_else(|error| panic!("{group:?} still rejects without the group: {error}"));
    check_reference(&weakened, &artifact, &challenges, limits, &NoObserver).unwrap();
    // The complete relation still rejects the artifact of the weakened one.
    assert!(check_reference(&air, &artifact, &challenges, limits, &NoObserver).is_err());
}

/// A fixed schema digest and the normalised root of an engine under it.
fn rooted<E: Engine>(engine: &E) -> (Digest, Digest) {
    let schema = E::Hash::hash_bytes(DOMAIN_KEY, b"a schema of the forgery tests");
    let root = root_digest::<E::Hash>(&normalised_root::<E::Hash>(
        &engine.structure_root(),
        &schema,
    ))
    .expect("a digest of the profile");
    (schema, root)
}

type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// Eight single-byte keys in four sibling pairs of a radix tree.
fn build<E: Engine>() -> (E, Entries) {
    let content: Entries = [0x10_u8, 0x11, 0x20, 0x21, 0x40, 0x41, 0x80, 0x81]
        .iter()
        .map(|key| (vec![*key], vec![*key; 3]))
        .collect();
    let changes: Vec<Change<'_>> = content
        .iter()
        .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
        .collect();
    let mut engine = E::new();
    engine.apply(&changes);
    (engine, content)
}

fn borrowed(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    entries
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect()
}

/// The two engines whose range witness is the postfix tree of `fringe`.
trait FringeEngine: WitnessPrograms {
    fn open(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Opened, Reject>;
}

impl<P: AirPermutation> FringeEngine for Radix<P> {
    fn open(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Opened, Reject> {
        Self::open_range(lower, upper, entries, witness)
    }
}

impl<P: AirPermutation> FringeEngine for BTree<P> {
    fn open(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Opened, Reject> {
        Self::open_range(lower, upper, entries, witness)
    }
}

/// The opened complete tree of an engine, and a branch over two leaves `x`
/// and `x + 1` with a leaf after them.
fn sibling_leaves<E: FringeEngine>(engine: &E, content: &Entries) -> (Opened, usize, usize) {
    let all = borrowed(content);
    let opened = E::open(b"", None, &all, &engine.prove_range(b"", None)).unwrap();
    let (branch, left) = opened
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, (kind, _))| match *kind {
            OpenNode::Branch { left, right, .. } => {
                match (opened.nodes[left].0, opened.nodes[right].0) {
                    (OpenNode::Leaf(x), OpenNode::Leaf(y))
                        if y == x + 1 && y + 1 < content.len() =>
                    {
                        Some((index, x))
                    }
                    _ => None,
                }
            }
            _ => None,
        })
        .expect("a branch over two leaves that are not the last ones");
    (opened, branch, left)
}

/// The stated program with one sibling's side flipped back to the side the
/// committed tree hashes it on.
fn with_side_of(stated: &Program, hidden: &Digest) -> Program {
    let mut followed = stated.clone();
    let mut flipped = 0;
    for block in &mut followed.blocks {
        if let Input::Compress {
            previous_right,
            sibling: Sibling::Private(digest),
            ..
        } = &mut block.input
            && digest == hidden
        {
            *previous_right = !*previous_right;
            flipped += 1;
        }
    }
    assert_eq!(
        flipped, 1,
        "the hidden leaf is the sibling of one compression"
    );
    followed
}

/// A complete range that omits a committed entry by hiding it on the wrong
/// side of its revealed neighbour: `[y, ∞)` without `y`, where the witness
/// shows the hidden `y` on the left of the predecessor `x`. Every shape rule
/// holds; only the side of that one compression is false.
fn forged_range_hides_an_entry<E, P>()
where
    E: FringeEngine<Hash = AlgebraicSponge<P>>,
    P: AirPermutation + Sync,
{
    let (engine, content) = build::<E>();
    let (schema, root) = rooted(&engine);
    let (opened, branch, x) = sibling_leaves(&engine, &content);
    let roles: Vec<Role> = (0..content.len())
        .map(|leaf| match leaf {
            leaf if leaf < x => Role::Hidden,
            leaf if leaf == x => Role::Boundary,
            leaf if leaf == x + 1 => Role::Hidden,
            _ => Role::Claimed,
        })
        .collect();
    let forged = reemit(&opened, &roles, Some(branch));
    let lower = content[x + 1].0.as_slice();
    let claimed = borrowed(&content[x + 2..]);
    // The true statement lists the hidden entry; the forged one does not.
    let honest = engine.prove_range(lower, None);
    assert_eq!(
        E::range_root(lower, None, &borrowed(&content[x + 1..]), &honest),
        Ok(engine.structure_root())
    );
    // Natively the forged witness is well formed and folds to another root.
    let folded = E::range_root(lower, None, &claimed, &forged).expect("every shape rule holds");
    assert_ne!(folded, engine.structure_root());
    let stated = E::range_program(schema, root, lower, None, &claimed, &forged)
        .expect("the verifier derives a program");
    let hidden = entry_leaf::<E::Hash>(&content[x + 1].0, &content[x + 1].1);
    assert_binding::<P>(
        ConstraintGroup::PublicSide,
        &stated,
        &with_side_of(&stated, &hidden),
    );
}

/// The mirror image: `[.., y)` without its last entry `x`, where the witness
/// shows the hidden `x` on the right of the successor `y`.
fn forged_range_hides_its_last_entry<E, P>()
where
    E: FringeEngine<Hash = AlgebraicSponge<P>>,
    P: AirPermutation + Sync,
{
    let (engine, content) = build::<E>();
    let (schema, root) = rooted(&engine);
    let (opened, branch, x) = sibling_leaves(&engine, &content);
    let roles: Vec<Role> = (0..content.len())
        .map(|leaf| match leaf {
            leaf if leaf < x => Role::Claimed,
            leaf if leaf == x + 1 => Role::Boundary,
            _ => Role::Hidden,
        })
        .collect();
    let forged = reemit(&opened, &roles, Some(branch));
    let upper = Some(content[x + 1].0.as_slice());
    let claimed = borrowed(&content[..x]);
    let honest = engine.prove_range(b"", upper);
    assert_eq!(
        E::range_root(b"", upper, &borrowed(&content[..=x]), &honest),
        Ok(engine.structure_root())
    );
    let folded = E::range_root(b"", upper, &claimed, &forged).expect("every shape rule holds");
    assert_ne!(folded, engine.structure_root());
    let stated = E::range_program(schema, root, b"", upper, &claimed, &forged)
        .expect("the verifier derives a program");
    let hidden = entry_leaf::<E::Hash>(&content[x].0, &content[x].1);
    assert_binding::<P>(
        ConstraintGroup::PublicSide,
        &stated,
        &with_side_of(&stated, &hidden),
    );
}

#[test]
fn forged_radix_ranges_are_rejected_by_both_relations() {
    forged_range_hides_an_entry::<Radix<Poseidon2Goldilocks12>, _>();
    forged_range_hides_an_entry::<Radix<RescuePrime64>, _>();
    forged_range_hides_its_last_entry::<Radix<Poseidon2Goldilocks12>, _>();
    forged_range_hides_its_last_entry::<Radix<RescuePrime64>, _>();
}

#[test]
fn forged_btree_ranges_are_rejected_by_both_relations() {
    forged_range_hides_an_entry::<BTree<Poseidon2Goldilocks12>, _>();
    forged_range_hides_an_entry::<BTree<RescuePrime64>, _>();
    forged_range_hides_its_last_entry::<BTree<Poseidon2Goldilocks12>, _>();
    forged_range_hides_its_last_entry::<BTree<RescuePrime64>, _>();
}

/// Absence of a committed key of the B-tree: its two neighbours disclosed as
/// adjacent, the key itself hidden on the left of its predecessor.
fn forged_btree_absence<P: AirPermutation + Sync>() {
    let (engine, content) = build::<BTree<P>>();
    let (schema, root) = rooted(&engine);
    let (opened, branch, x) = sibling_leaves(&engine, &content);
    let roles: Vec<Role> = (0..content.len())
        .map(|leaf| {
            if leaf == x || leaf == x + 2 {
                Role::Boundary
            } else {
                Role::Hidden
            }
        })
        .collect();
    let forged = reemit(&opened, &roles, Some(branch));
    let committed = content[x + 1].0.as_slice();
    assert!(engine.prove_absence(committed).is_none());
    let folded = BTree::<P>::absence_root(committed, &forged).expect("every shape rule holds");
    assert_ne!(folded, engine.structure_root());
    let stated = BTree::<P>::absence_program(schema, root, committed, &forged)
        .expect("the verifier derives a program");
    assert_eq!(stated.registers(), 1);
    let hidden = entry_leaf::<AlgebraicSponge<P>>(committed, &content[x + 1].1);
    assert_binding::<P>(
        ConstraintGroup::PublicSide,
        &stated,
        &with_side_of(&stated, &hidden),
    );
}

#[test]
fn forged_btree_absences_are_rejected_by_both_relations() {
    forged_btree_absence::<Poseidon2Goldilocks12>();
    forged_btree_absence::<RescuePrime64>();
}

/// Absence of a committed key of the radix tree: the prover discloses another
/// leaf with that leaf's real path. The witness is canonical, so the verifier
/// derives a program; its sides are the bits of the stated key.
fn forged_radix_absence<P: AirPermutation + Sync>() {
    let (schema, table, model, map) = sample::<Radix<P>>();
    let root = map.root();
    let (committed, other) = (&b"k2"[..], &b"x"[..]);
    let mut forged = vec![1_u8];
    let disclosed = composite_key(table, other);
    forged.extend_from_slice(&u32::try_from(disclosed.len()).unwrap().to_le_bytes());
    forged.extend_from_slice(&disclosed);
    forged.extend_from_slice(&crate::state_commitment_prototypes::hash::digest_to_bytes(
        &value_digest::<AlgebraicSponge<P>>(&model[other]),
    ));
    forged.extend_from_slice(&map.prove_inclusion(table, other).unwrap().unwrap());
    // The statement-level verdict is the native verifier's root comparison.
    assert_eq!(
        KeyedMap::<Radix<P>>::verify_absence(&schema, &root, table, committed, &forged),
        Err(VerifyError::Witness(Reject::NotProven))
    );
    assert!(map.prove_absence(table, committed).unwrap().is_none());
    let stated = absence_statement::<Radix<P>>(&schema, &root, table, committed, &forged)
        .expect("an off-path leaf reaches relation evaluation");
    // The prover follows the disclosed leaf's own bits.
    let mut followed = stated.clone();
    let mut changed = 0;
    for block in &mut followed.blocks {
        if let Input::Compress {
            capacity,
            previous_right,
            ..
        } = &mut block.input
            && capacity[0] == DOMAIN_BRANCH
        {
            let real = ByteKey::encoded_bit(&disclosed, u32::try_from(capacity[1]).unwrap());
            changed += usize::from(real != *previous_right);
            *previous_right = real;
        }
    }
    assert!(
        changed >= 1,
        "the stated key leaves the disclosed leaf's path"
    );
    assert_binding::<P>(ConstraintGroup::PublicSide, &stated, &followed);
}

#[test]
fn forged_radix_absences_are_rejected_by_both_relations() {
    forged_radix_absence::<Poseidon2Goldilocks12>();
    forged_radix_absence::<RescuePrime64>();
}

/// The stated program with the sibling of its `ordinal`-th successor link
/// replaced by the digest the committed leaf really links to.
fn with_successor(stated: &Program, ordinal: usize, real: Digest) -> Program {
    let mut followed = stated.clone();
    let link = followed
        .blocks
        .iter_mut()
        .filter_map(|block| match &mut block.input {
            Input::Compress {
                capacity, sibling, ..
            } if capacity[0] == DOMAIN_LINK => Some(sibling),
            _ => None,
        })
        .nth(ordinal)
        .expect("the program has that link");
    assert!(matches!(link, Sibling::Saved(_)), "the statement fixes it");
    *link = Sibling::Private(real);
    followed
}

/// Length of an encoded address path at the start of `bytes`.
fn path_bytes(bytes: &[u8]) -> usize {
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    4 + count * (4 + DIGEST_BYTES)
}

/// Absence of a committed key of the linked-leaf map: the leaf of its
/// predecessor with a later key named as its successor.
fn forged_linked_absence<P: AirPermutation + Sync>() {
    type H<P> = AlgebraicSponge<P>;
    let (engine, content) = build::<Linked<P>>();
    let (schema, root) = rooted(&engine);
    let (below, committed, above) = (&content[2].0, &content[3].0, &content[4].0);
    // The honest absence of a key just above `below` carries the leaf of
    // `below`, its real successor and its address path.
    let mut probe = below.clone();
    probe.push(0);
    let honest = engine.prove_absence(&probe).unwrap();
    assert_eq!(
        Linked::<P>::absence_root(&probe, &honest),
        Ok(engine.structure_root())
    );
    let own = 1 + 4 + below.len() + DIGEST_BYTES;
    let next = 1 + 4 + committed.len();
    assert_eq!(honest[own + 5..own + next], committed[..]);
    let mut forged = honest[..own].to_vec();
    forged.push(1);
    forged.extend_from_slice(&u32::try_from(above.len()).unwrap().to_le_bytes());
    forged.extend_from_slice(above);
    forged.extend_from_slice(&honest[own + next..]);
    assert!(engine.prove_absence(committed).is_none());
    let folded = Linked::<P>::absence_root(committed, &forged).expect("the bracket holds");
    assert_ne!(folded, engine.structure_root());
    let stated = Linked::<P>::absence_program(schema, root, committed, &forged)
        .expect("the verifier derives a program");
    assert_eq!(stated.registers(), 2);
    assert_binding::<P>(
        ConstraintGroup::SavedSibling,
        &stated,
        &with_successor(&stated, 0, key_digest::<H<P>>(committed)),
    );
}

/// A complete range of the linked-leaf map without one of its entries: the
/// leaf before the omitted entry is presented as linked to the entry after it.
fn forged_linked_range<P: AirPermutation + Sync>() {
    type H<P> = AlgebraicSponge<P>;
    let (engine, content) = build::<Linked<P>>();
    let (schema, root) = rooted(&engine);
    let (lower, upper) = (content[2].0.as_slice(), content[5].0.as_slice());
    let complete = borrowed(&content[2..5]);
    let honest = engine.prove_range(lower, Some(upper));
    assert_eq!(
        Linked::<P>::range_root(lower, Some(upper), &complete, &honest),
        Ok(engine.structure_root())
    );
    // Bracket, bracket path, then one path per claimed entry: drop the second.
    let bracket = 1 + 4 + content[1].0.len() + DIGEST_BYTES;
    let first = bracket + path_bytes(&honest[bracket..]);
    let second = first + path_bytes(&honest[first..]);
    let third = second + path_bytes(&honest[second..]);
    let mut forged = honest[..second].to_vec();
    forged.extend_from_slice(&honest[third..]);
    let claimed = [complete[0], complete[2]];
    let folded = Linked::<P>::range_root(lower, Some(upper), &claimed, &forged).map(|_| ());
    assert_eq!(
        folded,
        Err(Reject::NotProven),
        "the leaves fold to other roots"
    );
    let stated = Linked::<P>::range_program(schema, root, lower, Some(upper), &claimed, &forged)
        .expect("the verifier derives a program");
    assert_eq!(stated.registers(), 2);
    // Leaves are written last first: the second link is the first entry's.
    assert_binding::<P>(
        ConstraintGroup::SavedSibling,
        &stated,
        &with_successor(&stated, 1, key_digest::<H<P>>(&content[3].0)),
    );
}

#[test]
fn forged_linked_leaf_absences_and_ranges_are_rejected_by_both_relations() {
    forged_linked_absence::<Poseidon2Goldilocks12>();
    forged_linked_absence::<RescuePrime64>();
    forged_linked_range::<Poseidon2Goldilocks12>();
    forged_linked_range::<RescuePrime64>();
}

/// Copy the state rows of blocks `range` from `source` into `target`.
fn copy_states<P: AirPermutation>(
    target: &mut [Vec<u64>],
    source: &[Vec<u64>],
    blocks: core::ops::Range<usize>,
) {
    for column in STATE..STATE + 12 {
        for row in blocks.start * P::ROWS..blocks.end * P::ROWS {
            target[column][row] = source[column][row];
        }
    }
}

/// Each constraint group is needed: a forged trace that violates only that
/// group is rejected by the relation and accepted without the group.
fn each_constraint_group_is_load_bearing<P: AirPermutation + Sync>() {
    let (schema, table, model, map) = sample::<Radix<P>>();
    let root = map.root();
    let profile_schema = schema.digest::<AlgebraicSponge<P>>();
    let assert_group = |group: ConstraintGroup, program: &Program, columns: Vec<Vec<u64>>| {
        let air = ChainAir::<P>::new(&program.public_view());
        let challenges = challenges(air.schema().constraints);
        let violated = violation(&air, columns.clone()).expect("the forged trace is rejected");
        assert!(
            slots(group, program.registers()).contains(&violated),
            "{group:?}: slot {violated}"
        );
        let weakened = ChainAir::<P>::new(&program.public_view()).without(group);
        let limits = weakened.reference_limits();
        let artifact = build_reference(&weakened, columns, &challenges, limits, &NoObserver)
            .unwrap_or_else(|error| panic!("{group:?} still rejects without the group: {error}"));
        check_reference(&weakened, &artifact, &challenges, limits, &NoObserver).unwrap();
        // The complete relation still rejects the artifact of the weakened one.
        assert!(check_reference(&air, &artifact, &challenges, limits, &NoObserver).is_err());
    };

    // A false inclusion: the committed key `k2` with the value of `k3`.
    let false_value = model[&b"k3"[..]].clone();
    let witness = map.prove_inclusion(table, b"k2").unwrap().unwrap();
    let false_inclusion =
        inclusion_statement::<Radix<P>>(&schema, &root, table, b"k2", &false_value, &witness)
            .unwrap();
    let false_air = ChainAir::<P>::new(&false_inclusion.public_view());
    let honest_execution = false_air.witness_columns(&false_inclusion);
    let last = false_inclusion.blocks.len() - 1;

    // Anchor: executed honestly, only the anchor fails.
    assert_group(
        ConstraintGroup::Anchor,
        &false_inclusion,
        honest_execution.clone(),
    );

    // Rounds: the digest of the anchored block is overwritten with the root.
    let mut overwritten = honest_execution.clone();
    for word in 0..4 {
        overwritten[STATE + 4 + word][(last + 1) * P::ROWS - 1] = false_inclusion.root[word];
    }
    assert_group(ConstraintGroup::Rounds, &false_inclusion, overwritten);

    // Link: the anchored block hashes the true root preimage instead of the
    // digest the chain produced.
    let structure = map.engine().structure_root();
    assert_eq!(
        normalised_root::<AlgebraicSponge<P>>(&structure, &profile_schema),
        root
    );
    let mut input = [0_u64; 12];
    input[..4].copy_from_slice(&compress_capacity(DOMAIN_ROOT, 0));
    input[4..8].copy_from_slice(&structure);
    input[8..].copy_from_slice(&profile_schema);
    let mut unlinked = honest_execution.clone();
    for (row, state) in P::states(input).iter().enumerate() {
        for (column, word) in state.iter().enumerate() {
            unlinked[STATE + column][last * P::ROWS + row] = *word;
        }
    }
    assert_group(ConstraintGroup::Link, &false_inclusion, unlinked);

    // The statement names the uncommitted key `k9` with the value of the
    // committed key `k3`. Statement and trace share the block layout: both
    // keys have two bytes.
    assert!(!model.contains_key(&b"k9"[..]));
    let real_witness = map.prove_inclusion(table, b"k3").unwrap().unwrap();
    let real =
        inclusion_statement::<Radix<P>>(&schema, &root, table, b"k3", &false_value, &real_witness)
            .unwrap();
    accept::<P>(&real);
    let mut claimed = real.clone();
    let key_blocks = sponge_blocks(DOMAIN_KEY, &composite_key(table, b"k9"));
    assert_eq!(key_blocks.len(), 1);
    claimed.blocks[0].input = key_blocks[0].input;
    let claimed_air = ChainAir::<P>::new(&claimed.public_view());

    // Saved: the sponge of `k9` runs honestly, but the register holds the key
    // digest of `k3` and the leaf is compressed with it.
    let mut swapped = claimed_air.witness_columns(&real);
    let own_sponge = claimed_air.witness_columns(&claimed);
    copy_states::<P>(&mut swapped, &own_sponge, 0..1);
    assert_group(ConstraintGroup::Saved, &claimed, swapped);

    // Saved sibling: the register holds the key digest of `k9`, as saved, but
    // the leaf is compressed with the key digest of `k3` instead.
    let mut unread = claimed.clone();
    let leaf = unread
        .blocks
        .iter_mut()
        .find_map(|block| match &mut block.input {
            Input::Compress {
                sibling: sibling @ Sibling::Saved(0),
                ..
            } => Some(sibling),
            _ => None,
        })
        .expect("the leaf reads the key digest from the register");
    *leaf = Sibling::Private(key_digest::<AlgebraicSponge<P>>(&composite_key(
        table, b"k3",
    )));
    assert_group(
        ConstraintGroup::SavedSibling,
        &claimed,
        claimed_air.witness_columns(&unread),
    );

    // Public sibling: a true inclusion stated under another schema digest; the
    // prover normalises the root with the committed schema digest.
    let true_value = model[&b"k3"[..]].clone();
    let other_schema = <AlgebraicSponge<P> as HashProfile>::hash_bytes(DOMAIN_KEY, b"other");
    assert_ne!(other_schema, profile_schema);
    let root_words = root_digest::<AlgebraicSponge<P>>(&root).unwrap();
    let key = composite_key(table, b"k3");
    let under_other =
        Radix::<P>::inclusion_program(other_schema, root_words, &key, &true_value, &real_witness)
            .unwrap();
    let under_committed =
        Radix::<P>::inclusion_program(profile_schema, root_words, &key, &true_value, &real_witness)
            .unwrap();
    accept::<P>(&under_committed);
    let other_air = ChainAir::<P>::new(&under_other.public_view());
    assert_group(
        ConstraintGroup::PublicSibling,
        &under_other,
        other_air.witness_columns(&under_committed),
    );

    // Side bit: a compression with a verifier-known sibling and a side the
    // statement leaves open. A side that is not a bit feeds the permutation a
    // mix of the two digests; the root is whatever that mix hashes to, a
    // digest that no hash of the two digests in either order produces.
    let (first, second) = (profile_schema, structure);
    let mut open_side = Program {
        blocks: vec![
            public_compress(DOMAIN_LEAF, 0, &first, &second),
            compress(DOMAIN_BRANCH, 5, false, Sibling::Public(second), false),
        ],
        root: ZERO_DIGEST,
    };
    open_side.blocks[1].anchor = true;
    let previous = digest_of(
        &P::states(match open_side.blocks[0].input {
            Input::Fresh { capacity, message } => {
                let mut state = [0_u64; 12];
                state[..4].copy_from_slice(&capacity);
                state[4..].copy_from_slice(&message);
                state
            }
            _ => unreachable!("a public compression is a fresh block"),
        })[P::ROWS - 1],
    );
    // With side 2: left = 2 * sibling - previous, right = 2 * previous - sibling.
    let mix = |twice: &Digest, once: &Digest| -> Digest {
        core::array::from_fn(|word| {
            crate::field::sub_base(add_base(twice[word], twice[word]), once[word])
        })
    };
    let mut mixed = [0_u64; 12];
    mixed[..4].copy_from_slice(&compress_capacity(DOMAIN_BRANCH, 5));
    mixed[4..8].copy_from_slice(&mix(&second, &previous));
    mixed[8..].copy_from_slice(&mix(&previous, &second));
    let mixed_states = P::states(mixed);
    open_side.root = digest_of(&mixed_states[P::ROWS - 1]);
    for (left, right) in [(previous, second), (second, previous)] {
        assert_ne!(
            <AlgebraicSponge<P> as HashProfile>::compress(DOMAIN_BRANCH, 5, &left, &right),
            open_side.root
        );
    }
    let side_air = ChainAir::<P>::new(&open_side.public_view());
    let mut bent = side_air.witness_columns(&open_side);
    bent[SIDE][P::ROWS - 1] = 2;
    for (row, state) in mixed_states.iter().enumerate() {
        for (column, word) in state.iter().enumerate() {
            bent[STATE + column][P::ROWS + row] = *word;
        }
    }
    assert_group(ConstraintGroup::SideBoolean, &open_side, bent);
}

#[test]
fn each_constraint_group_is_load_bearing_for_poseidon2() {
    each_constraint_group_is_load_bearing::<Poseidon2Goldilocks12>();
}

#[test]
fn each_constraint_group_is_load_bearing_for_rescue_prime() {
    each_constraint_group_is_load_bearing::<RescuePrime64>();
}

/// The register file: a range needs as many registers as its schedule uses,
/// and the count is part of the relation.
#[test]
fn range_programs_use_the_registers_their_schedule_needs() {
    type P = RescuePrime64;
    let (engine, content) = build::<Radix<P>>();
    let (schema, root) = rooted(&engine);
    let all = borrowed(&content);
    let mut seen = Vec::new();
    for claimed in 0..=content.len() {
        let upper = content.get(claimed).map(|(key, _)| key.as_slice());
        let witness = engine.prove_range(b"", upper);
        let program =
            Radix::<P>::range_program(schema, root, b"", upper, &all[..claimed], &witness).unwrap();
        // Every register read follows a save to that register.
        let mut written = vec![false; program.registers()];
        let mut highest = 0;
        for block in &program.blocks {
            if let Input::Compress {
                sibling: Sibling::Saved(register),
                ..
            } = block.input
            {
                assert!(
                    written[register],
                    "register {register} is read before a save"
                );
                highest = highest.max(register);
            }
            if let Some(register) = block.save {
                written[register] = true;
                highest = highest.max(register);
            }
        }
        assert_eq!(program.registers(), highest + 1);
        seen.push(program.registers());
        accept::<P>(&program);
    }
    // No claimed entry: one disclosed successor and no register beyond the
    // one every relation has. A pair of claimed siblings keeps a leaf digest
    // and a key digest; two such pairs under one branch keep a pair digest
    // too. Later pairs are evaluated after the larger subtree and reuse them.
    assert_eq!(seen, [1, 1, 2, 2, 3, 3, 3, 3, 3]);
    // The register count is bound: the identity, the width and the statement
    // bytes of two counts differ, and a trace needs the registers it uses.
    let upper_two: &[u8] = &[0x20];
    let upper_six: &[u8] = &[0x80];
    let two = Radix::<P>::range_program(
        schema,
        root,
        b"",
        Some(upper_two),
        &all[..2],
        &engine.prove_range(b"", Some(upper_two)),
    )
    .unwrap();
    let three = Radix::<P>::range_program(
        schema,
        root,
        b"",
        Some(upper_six),
        &all[..6],
        &engine.prove_range(b"", Some(upper_six)),
    )
    .unwrap();
    let (small, large) = (
        ChainAir::<P>::new(&two.public_view()),
        ChainAir::<P>::new(&three.public_view()),
    );
    assert_eq!((small.registers(), large.registers()), (2, 3));
    assert_ne!(small.schema().identity, large.schema().identity);
    assert_eq!(large.width() - small.width(), 6);
    assert_eq!(large.schema().constraints - small.schema().constraints, 4);
}

#[test]
#[should_panic(expected = "the program uses a register the relation does not have")]
fn a_trace_cannot_use_a_register_the_relation_lacks() {
    type P = RescuePrime64;
    let (program, _) = radix_inclusion::<P>(b"a");
    let air = ChainAir::<P>::new(&program.public_view());
    let mut wider = program.clone();
    wider.blocks[0].save = Some(1);
    let _ = air.witness_columns(&wider);
}

#[test]
#[should_panic(expected = "a program starts with a fresh block")]
fn a_program_cannot_start_inside_a_chain() {
    let program = Program {
        blocks: vec![compress(
            DOMAIN_LEAF,
            0,
            false,
            Sibling::Private(ZERO_DIGEST),
            false,
        )],
        root: ZERO_DIGEST,
    };
    let _ = ChainAir::<RescuePrime64>::new(&program);
}

#[test]
fn gadget_instances_are_declared_per_construction() {
    type P = Poseidon2Goldilocks12;
    let use_of = |bit_scans, comparisons| GadgetUse {
        bit_scans,
        comparisons,
    };
    assert_eq!(Radix::<P>::ABSENCE_GADGETS, use_of(2, 0));
    assert_eq!(Radix::<P>::RANGE_GADGETS, use_of(0, 2));
    assert_eq!(BTree::<P>::ABSENCE_GADGETS, use_of(0, 2));
    assert_eq!(BTree::<P>::RANGE_GADGETS, use_of(0, 2));
    assert_eq!(Linked::<P>::ABSENCE_GADGETS, use_of(0, 2));
    assert_eq!(Linked::<P>::RANGE_GADGETS, use_of(0, 2));
}

#[test]
fn periodic_columns_follow_the_round_schedules() {
    // Poseidon2: the linear row, four full, twenty-two partial, four full, the link row.
    let selectors = |row: usize| -> [u64; 3] {
        core::array::from_fn(|column| Poseidon2Goldilocks12::periodic(row, column))
    };
    assert_eq!(Poseidon2Goldilocks12::ROWS, 32);
    assert_eq!(selectors(0), [1, 0, 0]);
    for row in 1..=30 {
        let full = row <= 4 || row >= 27;
        assert_eq!(
            selectors(row),
            [0, u64::from(full), u64::from(!full)],
            "{row}"
        );
        assert_eq!(
            Poseidon2Goldilocks12::periodic(row, 3),
            poseidon2::round_constants(row - 1)[0]
        );
    }
    assert!(
        (0..Poseidon2Goldilocks12::PERIODIC)
            .all(|column| { Poseidon2Goldilocks12::periodic(31, column) == 0 })
    );
    // Rescue-Prime: seven round rows, then the link row.
    assert_eq!(RescuePrime64::ROWS, 8);
    for row in 0..7 {
        assert_eq!(RescuePrime64::periodic(row, 0), 1);
        assert_eq!(
            RescuePrime64::periodic(row, 1),
            rescue::first_constants(row)[0]
        );
        assert_eq!(
            RescuePrime64::periodic(row, 24),
            rescue::second_constants(row)[11]
        );
    }
    assert!((0..RescuePrime64::PERIODIC).all(|column| RescuePrime64::periodic(7, column) == 0));
    // The round numerators vanish on honest states and not on a changed one.
    for input in [[0_u64; 12], core::array::from_fn(|index| index as u64 + 1)] {
        let states = Poseidon2Goldilocks12::states(input);
        assert_eq!(states.len(), Poseidon2Goldilocks12::ROWS);
        for row in 0..31 {
            let periodic: Vec<u64> = (0..Poseidon2Goldilocks12::PERIODIC)
                .map(|column| Poseidon2Goldilocks12::periodic(row, column))
                .collect();
            let numerators =
                Poseidon2Goldilocks12::round_numerators(&periodic, &states[row], &states[row + 1]);
            assert_eq!(numerators, [0; 12], "row {row}");
            let mut changed = states[row + 1];
            changed[5] = add_base(changed[5], 1);
            assert_ne!(
                Poseidon2Goldilocks12::round_numerators(&periodic, &states[row], &changed),
                [0; 12]
            );
        }
        let states = RescuePrime64::states(input);
        assert_eq!(states.len(), RescuePrime64::ROWS);
        for row in 0..7 {
            let periodic: Vec<u64> = (0..RescuePrime64::PERIODIC)
                .map(|column| RescuePrime64::periodic(row, column))
                .collect();
            assert_eq!(
                RescuePrime64::round_numerators(&periodic, &states[row], &states[row + 1]),
                [0; 12]
            );
            let mut changed = states[row + 1];
            changed[0] = add_base(changed[0], 1);
            assert_ne!(
                RescuePrime64::round_numerators(&periodic, &states[row], &changed),
                [0; 12]
            );
        }
    }
    let (rows, columns, slot) = as_built_blake2b_gadget();
    assert_eq!((rows, columns, slot), (408, 310, 512));
    // One register: 17 private columns, 22 verifier-known ones, the periodic ones.
    assert_eq!(ChainAir::<Poseidon2Goldilocks12>::width_with(1), 39 + 15);
    assert_eq!(ChainAir::<RescuePrime64>::width_with(1), 39 + 25);
    assert_eq!(ChainAir::<RescuePrime64>::width_with(4), 39 + 25 + 18);
    assert_eq!(ChainAir::<RescuePrime64>::constraints_with(1), 22);
    assert_eq!(ChainAir::<RescuePrime64>::constraints_with(4), 34);
}

#[test]
fn relation_refuses_malformed_evaluation_input_and_out_of_range_public_cells() {
    let (program, _) = radix_inclusion::<RescuePrime64>(b"a");
    let air = ChainAir::<RescuePrime64>::new(&program.public_view());
    let width = air.width();
    assert_eq!(width, 39 + 25);
    assert!(
        air.evaluate(0_u64, &vec![0; width - 1], &vec![0; width])
            .is_err()
    );
    assert!(air.public_value(0, air.schema().trace_rows).is_err());
    assert!(air.public_value(width, 0).is_err());
    // The first verifier-known column marks the link rows.
    assert_eq!(air.public_value(0, RescuePrime64::ROWS - 1).unwrap(), 1);
    assert_eq!(air.public_value(0, 0).unwrap(), 0);
    assert_eq!(air.public_columns().len(), width - 17);
    assert_eq!(air.public_columns()[0], 17);
    assert_eq!(air.reference_limits().max_constraints, 22);
    // Padding rounds the block count up to a power of two.
    assert!(air.blocks().is_power_of_two() && air.blocks() >= program.permutations());
    let empty = Program {
        blocks: Vec::new(),
        root: ZERO_DIGEST,
    };
    assert_eq!(
        ChainAir::<RescuePrime64>::rows_for(&empty),
        RescuePrime64::ROWS
    );
    assert_eq!(empty.registers(), 1);
    assert_eq!(empty.private_siblings(), 0);
}
