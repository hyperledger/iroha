//! Indexed-map circuit/native parity, authenticated transitions and adversarial witnesses.

mod common;

use std::collections::BTreeMap;

use common::{Chips, GadgetCircuit, Inputs, Shape, accepts, report};
use ff::Field as _;
use iroha_pasta::{
    Fp, Fq,
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk::frontend::{Circuit, Error, Region, configure, synthesize};
use iroha_plonk_gadgets::{
    UintChip, Word,
    imt::{ImtChip, LEAF_DOMAIN, LeafCells, NODE_DOMAIN, OpeningCells, PathCells},
    tamper::undetected_tampers,
};
use norito::json::Value;

const LESS: u64 = 0;
const MEMBER: u64 = 1;
const ABSENT: u64 = 2;
const INSERT: u64 = 3;
const REMOVE: u64 = 4;
const RECORD: u64 = 5;
const INSERT_IF: u64 = 6;

fn take_path<F: PoseidonField, const D: usize>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    words: &[Word<F>],
    cursor: &mut usize,
) -> Result<PathCells<F, D>, Error> {
    let index = &words[*cursor];
    *cursor += 1;
    let siblings = core::array::from_fn(|offset| words[*cursor + offset].clone());
    *cursor += D;
    PathCells::from_words(
        &mut UintChip::new(&mut chips.glue, &mut chips.range),
        region,
        index,
        siblings,
    )
}

fn take_opening<F: PoseidonField, const D: usize>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    words: &[Word<F>],
    cursor: &mut usize,
) -> Result<OpeningCells<F, D>, Error> {
    let leaf = LeafCells::from_words(core::array::from_fn(|offset| {
        words[*cursor + offset].clone()
    }));
    *cursor += 3;
    Ok(OpeningCells {
        leaf,
        path: take_path(chips, region, words, cursor)?,
    })
}

fn program<F: PoseidonField, const D: usize>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let op = inputs.arg(0);
    if op == LESS {
        let bit = ImtChip::new(&mut chips.glue, &mut chips.range, &mut chips.sponges[0])
            .less(region, &words[0], &words[1])?;
        return Ok(vec![words[0].clone(), words[1].clone(), bit.word().clone()]);
    }
    let mut cursor = match op {
        INSERT | RECORD => 3,
        INSERT_IF => 4,
        ABSENT => 2,
        _ => 1,
    };
    let opening = take_opening::<F, D>(chips, region, &words, &mut cursor)?;
    let slot = if matches!(op, INSERT | RECORD | INSERT_IF) {
        Some(take_path::<F, D>(chips, region, &words, &mut cursor)?)
    } else {
        None
    };
    let removed = if op == REMOVE {
        Some(take_opening::<F, D>(chips, region, &words, &mut cursor)?)
    } else {
        None
    };
    assert_eq!(cursor, words.len(), "all witnesses are consumed");
    let enabled = if op == INSERT_IF {
        Some(chips.glue.assert_bool(region, &words[3])?)
    } else {
        None
    };
    let mut imt = ImtChip::new(&mut chips.glue, &mut chips.range, &mut chips.sponges[0]);
    match op {
        MEMBER => {
            imt.membership(region, &words[0], &opening)?;
            Ok(vec![
                words[0].clone(),
                opening.leaf.key().clone(),
                opening.leaf.value().clone(),
            ])
        }
        ABSENT => {
            let bit = imt.absent(region, &words[0], &words[1], &opening)?;
            Ok(vec![words[0].clone(), words[1].clone(), bit.word().clone()])
        }
        INSERT => {
            let root = imt.insert(
                region,
                &words[0],
                &words[1],
                &words[2],
                &opening,
                slot.as_ref().expect("slot"),
            )?;
            Ok(vec![
                words[0].clone(),
                words[1].clone(),
                words[2].clone(),
                root,
            ])
        }
        REMOVE => {
            let removed = removed.as_ref().expect("removed");
            let root = imt.remove(region, &words[0], &opening, removed)?;
            Ok(vec![
                words[0].clone(),
                removed.leaf.key().clone(),
                removed.leaf.value().clone(),
                root,
            ])
        }
        RECORD => {
            let record = imt.record(
                region,
                &words[0],
                &words[1],
                &words[2],
                &opening,
                slot.as_ref().expect("slot"),
            )?;
            Ok(vec![
                words[0].clone(),
                words[1].clone(),
                words[2].clone(),
                record.root().clone(),
                record.value().clone(),
                record.present().word().clone(),
            ])
        }
        INSERT_IF => {
            let root = imt.insert_if(
                region,
                &words[0],
                [&words[1], &words[2]],
                &opening,
                slot.as_ref().expect("slot"),
                enabled.as_ref().expect("enable"),
            )?;
            Ok(vec![
                words[0].clone(),
                words[1].clone(),
                words[2].clone(),
                words[3].clone(),
                root,
            ])
        }
        _ => Err(Error::Synthesis),
    }
}

fn circuit<F: PoseidonField, const D: usize>(op: u64, inputs: Vec<F>) -> GadgetCircuit<F> {
    let outputs = match op {
        RECORD => 6,
        INSERT_IF => 5,
        INSERT | REMOVE => 4,
        _ => 3,
    };
    GadgetCircuit::new(
        Shape::new(1, 9, outputs)
            .with_args(&[op])
            .folding(&[(LEAF_DOMAIN, 3), (NODE_DOMAIN, 2)]),
        program::<F, D>,
        inputs,
    )
}

/// Independent sparse native tree: recompute every level, rather than
/// reusing the gadget's path-update logic or a mutable cached tree.
#[derive(Clone)]
struct Tree<F, const D: usize> {
    slots: BTreeMap<u32, [F; 3]>,
}

impl<F: PoseidonField, const D: usize> Tree<F, D> {
    fn empty() -> Self {
        Self {
            slots: BTreeMap::from([(0, [F::ZERO; 3])]),
        }
    }

    fn levels(&self) -> (Vec<BTreeMap<u32, F>>, Vec<F>) {
        let mut empty = vec![F::ZERO];
        let mut levels = vec![
            self.slots
                .iter()
                .map(|(slot, leaf)| (*slot, hash_with_domain(LEAF_DOMAIN, leaf)))
                .collect::<BTreeMap<_, _>>(),
        ];
        for height in 0..D {
            let previous = &levels[height];
            let mut next = BTreeMap::new();
            for slot in previous.keys() {
                let left = previous.get(&(slot & !1)).copied().unwrap_or(empty[height]);
                let right = previous.get(&(slot | 1)).copied().unwrap_or(empty[height]);
                next.insert(slot >> 1, hash_with_domain(NODE_DOMAIN, &[left, right]));
            }
            levels.push(next);
            empty.push(hash_with_domain(NODE_DOMAIN, &[empty[height]; 2]));
        }
        (levels, empty)
    }

    fn root(&self) -> F {
        self.levels().0[D][&0]
    }

    fn path(&self, slot: u32) -> Vec<F> {
        let (levels, empty) = self.levels();
        let mut result = vec![F::from(u64::from(slot))];
        for height in 0..D {
            result.push(
                levels[height]
                    .get(&((slot >> height) ^ 1))
                    .copied()
                    .unwrap_or(empty[height]),
            );
        }
        result
    }

    fn opening(&self, slot: u32) -> Vec<F> {
        let mut result = self.slots[&slot].to_vec();
        result.extend(self.path(slot));
        result
    }

    fn insert(&mut self, low_slot: u32, slot: u32, key: F, value: F) -> (GadgetCircuit<F>, Vec<F>) {
        let old = self.root();
        let low = self.slots[&low_slot];
        let mut inputs = vec![old, key, value];
        inputs.extend(self.opening(low_slot));
        self.slots.get_mut(&low_slot).expect("low")[2] = key;
        inputs.extend(self.path(slot));
        self.slots.insert(slot, [key, value, low[2]]);
        (
            circuit::<F, D>(INSERT, inputs),
            vec![old, key, value, self.root()],
        )
    }

    fn remove(&mut self, predecessor: u32, slot: u32) -> (GadgetCircuit<F>, Vec<F>, F) {
        let old = self.root();
        let removed = self.slots[&slot];
        let mut inputs = vec![old];
        inputs.extend(self.opening(predecessor));
        self.slots.get_mut(&predecessor).expect("predecessor")[2] = removed[2];
        inputs.extend(self.opening(slot));
        let uncleared = self.root();
        self.slots.remove(&slot);
        (
            circuit::<F, D>(REMOVE, inputs),
            vec![old, removed[0], removed[1], self.root()],
            uncleared,
        )
    }
}

fn assert_accept<F: PoseidonField>(c: &GadgetCircuit<F>, k: u32, public: &[F]) {
    assert!(accepts(c, k, public), "{}", report(c, k, public));
}

fn comparisons<F: PoseidonField>() {
    let high = F::from_u128(1 << 127).double();
    let cases = [
        F::ZERO,
        F::ONE,
        F::from_u128(u128::MAX),
        high,
        high + F::ONE,
        -F::ONE,
    ];
    for (i, left) in cases.iter().enumerate() {
        for (j, right) in cases.iter().enumerate() {
            let c = circuit::<F, 1>(LESS, vec![*left, *right]);
            let mut public = vec![*left, *right, F::from(u64::from(i < j))];
            assert_accept(&c, 10, &public);
            public[2] = F::ONE - public[2];
            assert!(!accepts(&c, 10, &public));
        }
    }
}

#[test]
fn full_field_integer_order_in_both_fields() {
    comparisons::<Fp>();
    comparisons::<Fq>();
}

fn transitions<F: PoseidonField>() {
    let mut tree = Tree::<F, 3>::empty();
    let (first, first_public) = tree.insert(0, 7, F::from(20), F::from(200));
    assert_accept(&first, 11, &first_public);
    let (second, second_public) = tree.insert(0, 2, F::from(10), F::from(100));
    assert_accept(&second, 11, &second_public);
    let (third, third_public) = tree.insert(7, 1, -F::ONE, F::from(300));
    assert_accept(&third, 11, &third_public);
    let mut member = vec![tree.root()];
    member.extend(tree.opening(7));
    let member = circuit::<F, 3>(MEMBER, member);
    assert_accept(&member, 11, &[tree.root(), F::from(20), F::from(200)]);
    for (key, slot, absent) in [(10, 2, false), (15, 2, true), (20, 7, false), (25, 7, true)] {
        let key = F::from(key);
        let mut gap = vec![tree.root(), key];
        gap.extend(tree.opening(slot));
        let gap = circuit::<F, 3>(ABSENT, gap);
        let public = vec![tree.root(), key, F::from(u64::from(absent))];
        assert_accept(&gap, 11, &public);
        let mut forged = public.clone();
        forged[2] = F::ONE - forged[2];
        assert!(!accepts(&gap, 11, &forged));
        let mut bad_path = gap.clone();
        bad_path.inputs[6] += F::ONE;
        assert!(
            !accepts(&bad_path, 11, &[tree.root(), key, F::ZERO]),
            "bad paths cannot select burn"
        );
        let wrong_slot = if slot == 2 { 7 } else { 2 };
        let mut wrong_route = vec![tree.root(), key];
        wrong_route.extend(tree.opening(wrong_slot));
        assert!(
            !accepts(
                &circuit::<F, 3>(ABSENT, wrong_route),
                11,
                &[tree.root(), key, F::ZERO]
            ),
            "an unrelated authenticated leaf cannot select burn"
        );
    }
    let (remove, public, uncleared) = tree.remove(2, 7);
    assert_accept(&remove, 11, &public);
    let mut wrong = public.clone();
    wrong[3] = uncleared;
    assert!(
        !accepts(&remove, 11, &wrong),
        "removal must clear the unlinked slot"
    );
    for (c, public) in [
        (first, first_public),
        (second, second_public),
        (third, third_public),
        (remove, public),
    ] {
        for input in 0..c.inputs.len() {
            let mut forged = c.clone();
            forged.inputs[input] += F::ONE;
            assert!(
                !accepts(&forged, 11, &public),
                "unbound operation input {input}"
            );
        }
    }
}

#[test]
fn authenticated_insert_remove_membership_and_soft_gap() {
    transitions::<Fp>();
    transitions::<Fq>();
}

fn rejects_bad_maps<F: PoseidonField>() {
    let mut tree = Tree::<F, 3>::empty();
    tree.insert(0, 3, F::from(10), F::from(100));
    let before = tree.clone();
    let (occupied, public) = tree.insert(3, 3, F::from(20), F::from(200));
    assert!(!accepts(&occupied, 11, &public));
    for (key, value) in [
        (F::from(10), F::from(9)),
        (F::ZERO, F::ONE),
        (F::from(20), F::ZERO),
    ] {
        let (c, public) = before.clone().insert(0, 2, key, value);
        assert!(!accepts(&c, 11, &public));
    }
    for leaf in [
        [F::ZERO, F::ONE, F::from(10)],
        [F::from(10), F::from(100), F::from(10)],
        [F::from(10), F::from(100), F::from(9)],
    ] {
        let malformed = Tree::<F, 3> {
            slots: BTreeMap::from([(0, leaf)]),
        };
        let mut inputs = vec![malformed.root(), F::from(12)];
        inputs.extend(malformed.opening(0));
        assert!(!accepts(
            &circuit::<F, 3>(ABSENT, inputs),
            11,
            &[malformed.root(), F::from(12), F::ZERO]
        ));
    }
    let (mut c, public) = before.clone().insert(3, 2, F::from(20), F::from(200));
    // Replacing the intermediate empty-slot path by one from the old tree
    // authenticates the wrong low-leaf link.
    c.inputs.splice(3 + 3 + 1 + 3.., before.path(2));
    assert!(!accepts(&c, 11, &public));
    let empty = Tree::<F, 3>::empty();
    let mut zero_query = vec![empty.root(), F::ZERO];
    zero_query.extend(empty.opening(0));
    assert!(!accepts(
        &circuit::<F, 3>(ABSENT, zero_query),
        11,
        &[empty.root(), F::ZERO, F::ZERO]
    ));
    let mut member = vec![empty.root()];
    member.extend(empty.opening(0));
    assert!(!accepts(
        &circuit::<F, 3>(MEMBER, member),
        11,
        &[empty.root(), F::ZERO, F::ZERO]
    ));
}

#[test]
fn occupied_insertions_duplicates_sentinels_and_invalid_links_reject() {
    rejects_bad_maps::<Fp>();
    rejects_bad_maps::<Fq>();
}

#[test]
fn maximum_production_slot_is_valid_and_overflow_rejects() {
    let (c, public) = Tree::<Fp, 32>::empty().insert(0, u32::MAX, -Fp::ONE, Fp::ONE);
    assert_accept(&c, 14, &public);
    let mut bad = c.clone();
    bad.inputs[3 + 3 + 1 + 32] = Fp::from(1_u64 << 32);
    assert!(!accepts(&bad, 14, &public));
    let assigned = synthesize(&c, 14, Some(&[public][..])).expect("assigned");
    let unknown = synthesize(&c.without_witnesses(), 14, None).expect("unknown");
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert!(configure(&c).expect("configure").0.degree() <= iroha_plonk_gadgets::MAX_GATE_DEGREE);
}

fn field(value: &Value) -> Fp {
    let hex = value.as_str().expect("hex");
    let bytes =
        core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("byte"));
    iroha_plonk_gadgets::statement::canonical_field(&bytes).expect("canonical")
}

fn fixture_path(value: &Value) -> Vec<Fp> {
    let mut result = vec![Fp::from(value["slot"].as_u64().expect("slot"))];
    result.extend(
        value["siblings"]
            .as_array()
            .expect("siblings")
            .iter()
            .map(field),
    );
    assert_eq!(result.len(), 33);
    result
}

fn fixture_opening(value: &Value) -> Vec<Fp> {
    let leaf = &value["leaf"];
    let mut result = ["key_hex", "value_hex", "next_key_hex"]
        .map(|key| field(&leaf[key]))
        .to_vec();
    result.extend(fixture_path(&value["opening"]));
    result
}

#[test]
fn production_depth_matches_rust_g1_cross_language_vectors() {
    let fixtures: Value = norito::json::from_str(include_str!(
        "../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("fixtures");
    let tree = &fixtures["poseidon"]["indexed_tree"];
    for vector in tree["load_redeem_insertions"]
        .as_array()
        .expect("insertions")
    {
        let public =
            ["old_root_hex", "key_hex", "value_hex", "root_hex"].map(|key| field(&vector[key]));
        let mut inputs = public[..3].to_vec();
        inputs.extend(fixture_opening(&vector["low"]));
        inputs.extend(fixture_path(&vector["empty_slot_opening"]["opening"]));
        assert_accept(&circuit::<Fp, 32>(INSERT, inputs), 14, &public);
    }
    let vector = &tree["membership"];
    let mut inputs = vec![field(&vector["root_hex"])];
    inputs.extend(fixture_opening(vector));
    let public = [inputs[0], inputs[1], inputs[2]];
    assert_accept(&circuit::<Fp, 32>(MEMBER, inputs), 14, &public);
    for kind in [
        "non_membership_through_sentinel",
        "non_membership_through_interior_low_leaf",
        "non_membership_above_the_largest_key",
    ] {
        let vector = &tree[kind];
        let mut inputs = vec![
            field(&vector["low"]["root_hex"]),
            field(&vector["absent_key_hex"]),
        ];
        inputs.extend(fixture_opening(&vector["low"]));
        let public = [inputs[0], inputs[1], Fp::ONE];
        assert_accept(&circuit::<Fp, 32>(ABSENT, inputs), 14, &public);
    }
    let vector = &tree["pending_outgoing_removal"];
    let mut inputs = vec![field(&vector["old_root_hex"])];
    inputs.extend(fixture_opening(&vector["predecessor"]));
    inputs.extend(fixture_opening(&vector["removed"]));
    let public = [
        inputs[0],
        field(&vector["removed_key_hex"]),
        field(&vector["removed"]["leaf"]["value_hex"]),
        field(&vector["root_hex"]),
    ];
    assert_accept(&circuit::<Fp, 32>(REMOVE, inputs), 14, &public);
}

#[test]
fn every_advice_cell_of_small_insert_and_remove_is_pinned() {
    let mut tree = Tree::<Fp, 1>::empty();
    let (insert, public) = tree.insert(0, 1, Fp::from(10), Fp::from(100));
    assert!(
        undetected_tampers(&insert, 11, &[public])
            .expect("insert tampers")
            .is_empty()
    );
    let (remove, public, _) = tree.remove(0, 1);
    assert!(
        undetected_tampers(&remove, 11, &[public])
            .expect("remove tampers")
            .is_empty()
    );
}

fn records<F: PoseidonField>() {
    let mut tree = Tree::<F, 1>::empty();
    let (insert, public) = tree.insert(0, 1, F::from(10), F::from(100));
    let record = circuit::<F, 1>(RECORD, insert.inputs.clone());
    let mut inserted_public = public.clone();
    inserted_public.extend([F::from(100), F::ZERO]);
    assert_accept(&record, 11, &inserted_public);

    let mut inputs = vec![tree.root(), F::from(10), F::from(999)];
    inputs.extend(tree.opening(1));
    inputs.extend(tree.path(1));
    let existing = circuit::<F, 1>(RECORD, inputs);
    let existing_public = vec![
        tree.root(),
        F::from(10),
        F::from(999),
        tree.root(),
        F::from(100),
        F::ONE,
    ];
    assert_accept(&existing, 11, &existing_public);
    let mut wrong_value = existing_public.clone();
    wrong_value[4] = F::from(999);
    assert!(
        !accepts(&existing, 11, &wrong_value),
        "first value stays immutable"
    );
    let mut wrong_present = existing_public.clone();
    wrong_present[5] = F::ZERO;
    assert!(!accepts(&existing, 11, &wrong_present));
    let mut changed = tree.clone();
    changed.slots.get_mut(&1).expect("leaf")[1] = F::from(999);
    let mut wrong_root = existing_public.clone();
    wrong_root[3] = changed.root();
    assert!(!accepts(&existing, 11, &wrong_root));
    let known = synthesize(&existing, 11, Some(&[existing_public][..])).expect("present");
    let absent = synthesize(&record, 11, Some(&[inserted_public][..])).expect("absent");
    let unknown = synthesize(&record.without_witnesses(), 11, None).expect("unknown");
    for other in [&absent, &unknown] {
        assert_eq!(known.tables.fixed(), other.tables.fixed());
        assert_eq!(known.tables.selectors(), other.tables.selectors());
        assert_eq!(known.tables.permutation(), other.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            other.tables.advice_assigned()
        );
    }

    let mut inputs = insert.inputs;
    inputs.insert(3, F::ONE);
    let optional = circuit::<F, 1>(INSERT_IF, inputs);
    let optional_public = [public[0], public[1], public[2], F::ONE, public[3]];
    assert_accept(&optional, 11, &optional_public);
    // A full tree still permits a no-op; there is no artificial requirement
    // to exhibit an unused slot when the committed root stayed unchanged.
    let mut inputs = vec![tree.root(), F::ZERO, F::ZERO, F::ZERO];
    inputs.extend(tree.opening(0));
    inputs.extend(tree.path(0));
    let noop = circuit::<F, 1>(INSERT_IF, inputs);
    let noop_public = [tree.root(), F::ZERO, F::ZERO, F::ZERO, tree.root()];
    assert_accept(&noop, 11, &noop_public);
    let mut forged = noop.clone();
    forged.inputs[3] = F::ONE;
    let mut forged_public = noop_public;
    forged_public[3] = F::ONE;
    assert!(!accepts(&forged, 11, &forged_public));
    let mut wrong_root = noop_public;
    wrong_root[4] += F::ONE;
    assert!(!accepts(&noop, 11, &wrong_root));
    let mut nonboolean = noop;
    nonboolean.inputs[3] = F::from(2);
    let mut forged_public = noop_public;
    forged_public[3] = F::from(2);
    assert!(!accepts(&nonboolean, 11, &forged_public));
}

#[test]
fn insert_only_history_and_optional_structural_updates() {
    records::<Fp>();
    records::<Fq>();
}

#[test]
fn every_advice_cell_of_record_and_noop_is_pinned() {
    let mut tree = Tree::<Fq, 1>::empty();
    tree.insert(0, 1, Fq::from(10), Fq::from(100));
    let mut inputs = vec![tree.root(), Fq::from(10), Fq::from(999)];
    inputs.extend(tree.opening(1));
    inputs.extend(tree.path(1));
    let c = circuit::<Fq, 1>(RECORD, inputs);
    let public = vec![
        tree.root(),
        Fq::from(10),
        Fq::from(999),
        tree.root(),
        Fq::from(100),
        Fq::ONE,
    ];
    assert!(
        undetected_tampers(&c, 11, &[public])
            .expect("record tampers")
            .is_empty()
    );
    let mut inputs = vec![tree.root(), Fq::ZERO, Fq::ZERO, Fq::ZERO];
    inputs.extend(tree.opening(0));
    inputs.extend(tree.path(0));
    let c = circuit::<Fq, 1>(INSERT_IF, inputs);
    let public = vec![tree.root(), Fq::ZERO, Fq::ZERO, Fq::ZERO, tree.root()];
    assert!(
        undetected_tampers(&c, 11, &[public])
            .expect("noop tampers")
            .is_empty()
    );
}
