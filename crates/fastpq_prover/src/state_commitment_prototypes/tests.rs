//! Behaviour of every prototype engine under every hash profile, checked
//! against a plain ordered map. The authoritative contract check is the G.1
//! conformance suite, which `iroha_core` runs on the same engines.

use std::collections::BTreeMap;

use super::{
    btree::MerkleBTree,
    chain::SortedHashChain,
    hash::{
        AlgebraicSponge, Blake2bProfile, DIGEST_BYTES, Digest384Comparator, Permutation12,
        Poseidon2Profile, RescuePrimeProfile, digest_from_bytes, digest_to_bytes, pack_bytes,
        take_hash_work,
    },
    keyed::{
        StatementFault, TableChange, VerifyError, composite_key, descriptor_from_rows,
        normalised_root, root_digest,
    },
    linked::LinkedLeafMap,
    radix::RadixTree,
    workload::SplitMix64,
    *,
};

const KEY: &str = "norito:key@0.0.2";
const VALUE: &str = "norito:value@0.0.2";

fn schema() -> PrototypeSchema {
    PrototypeSchema::from_descriptor(&descriptor_from_rows(&[
        ("t.b", KEY, VALUE),
        ("t.a", KEY, VALUE),
        ("t.cell", "", VALUE),
        ("t.a.sub", KEY, VALUE),
        ("t.empty", KEY, VALUE),
    ]))
    .expect("a canonical descriptor")
}

type Model = BTreeMap<(u32, Vec<u8>), Vec<u8>>;

fn changes(model: &Model) -> Vec<TableChange<'_>> {
    model
        .iter()
        .map(|((table, key), value)| (*table, key.as_slice(), Some(value.as_slice())))
        .collect()
}

fn cold<E: Engine>(schema: &PrototypeSchema, model: &Model) -> KeyedMap<E> {
    let mut map = KeyedMap::<E>::empty(schema.clone());
    map.apply(&changes(model)).expect("a valid change set");
    map
}

fn in_range<'a>(
    model: &'a Model,
    table: u32,
    lower: &[u8],
    upper: Option<&[u8]>,
) -> Vec<(&'a [u8], &'a [u8])> {
    model
        .iter()
        .filter(|((candidate, key), _)| {
            *candidate == table
                && key.as_slice() >= lower
                && upper.is_none_or(|upper| key.as_slice() < upper)
        })
        .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
        .collect()
}

fn probe_keys() -> Vec<Vec<u8>> {
    [
        &b""[..],
        b"\0",
        b"a",
        b"a\0",
        b"aa",
        b"ab",
        b"ab\0",
        b"abc",
        b"b",
        b"\xfe",
        b"\xff",
        b"\xff\xff",
    ]
    .iter()
    .map(|key| key.to_vec())
    .collect()
}

fn ranges() -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let bounded = |lower: &[u8], upper: &[u8]| (lower.to_vec(), Some(upper.to_vec()));
    vec![
        (Vec::new(), None),
        bounded(b"", b"a"),
        bounded(b"a", b"ab"),
        bounded(b"a", b"b"),
        bounded(b"ab", b"ab\0"),
        bounded(b"c", b"d"),
        (b"b".to_vec(), None),
        (b"\xff".to_vec(), None),
    ]
}

/// Every true statement verifies and the false variants are rejected.
fn check_statements<E: Engine>(schema: &PrototypeSchema, model: &Model, map: &KeyedMap<E>) {
    let root = map.root();
    assert!(root_digest::<E::Hash>(&root).is_some());
    for table in 0..schema.tables() {
        let cell = schema.is_cell(table).unwrap();
        let keys = if cell { vec![Vec::new()] } else { probe_keys() };
        for key in keys {
            let included = map.prove_inclusion(table, &key).unwrap();
            let absent = map.prove_absence(table, &key).unwrap();
            if let Some(value) = model.get(&(table, key.clone())) {
                let witness = included.expect("a committed entry has a witness");
                assert!(absent.is_none());
                KeyedMap::<E>::verify_inclusion(schema, &root, table, &key, value, &witness)
                    .expect("the honest inclusion witness verifies");
                let mut other = value.clone();
                other.push(0);
                for wrong in [other, Vec::new(), b"wrong".to_vec()] {
                    if wrong != *value {
                        assert!(
                            KeyedMap::<E>::verify_inclusion(
                                schema, &root, table, &key, &wrong, &witness
                            )
                            .is_err()
                        );
                    }
                }
                assert!(
                    KeyedMap::<E>::verify_absence(schema, &root, table, &key, &witness).is_err()
                );
            } else {
                let witness = absent.expect("an absent key has a witness");
                assert!(included.is_none());
                KeyedMap::<E>::verify_absence(schema, &root, table, &key, &witness)
                    .expect("the honest absence witness verifies");
                for wrong in [Vec::new(), b"x".to_vec()] {
                    assert!(
                        KeyedMap::<E>::verify_inclusion(
                            schema, &root, table, &key, &wrong, &witness
                        )
                        .is_err()
                    );
                }
                // The witness says nothing about a committed key.
                for ((other_table, other_key), _) in model.iter().take(3) {
                    assert!(
                        KeyedMap::<E>::verify_absence(
                            schema,
                            &root,
                            *other_table,
                            other_key,
                            &witness
                        )
                        .is_err()
                    );
                }
            }
        }
        for (lower, upper) in ranges() {
            let honest = in_range(model, table, &lower, upper.as_deref());
            let witness = map.prove_range(table, &lower, upper.as_deref()).unwrap();
            let verify = |entries: &[(&[u8], &[u8])]| {
                KeyedMap::<E>::verify_range(
                    schema,
                    &root,
                    table,
                    &lower,
                    upper.as_deref(),
                    entries,
                    &witness,
                )
            };
            verify(&honest).expect("the honest range witness verifies");
            for skipped in 0..honest.len() {
                let mut omitted = honest.clone();
                omitted.remove(skipped);
                assert!(verify(&omitted).is_err(), "omission of entry {skipped}");
                let mut substituted = honest.clone();
                substituted[skipped].1 = b"substituted";
                assert!(verify(&substituted).is_err());
            }
            let mut fake = lower.clone();
            fake.extend_from_slice(b"\0fake");
            if !cell
                && upper.as_deref().is_none_or(|upper| fake.as_slice() < upper)
                && !model.contains_key(&(table, fake.clone()))
            {
                let mut added = honest.clone();
                added.push((&fake, b"fake"));
                added.sort();
                assert!(verify(&added).is_err(), "an added entry");
            }
            // The entries of an interval are not the complete table.
            let full = in_range(model, table, b"", None);
            if full.len() > honest.len() {
                assert!(
                    KeyedMap::<E>::verify_range(schema, &root, table, b"", None, &honest, &witness)
                        .is_err()
                );
            }
        }
    }
}

/// A predicate over witness bytes.
type Check<'a> = Box<dyn Fn(&[u8]) -> bool + 'a>;

/// A changed, truncated or extended witness never establishes a false statement,
/// and a truncated or extended one does not establish the true one either.
fn check_canonical<E: Engine>(schema: &PrototypeSchema, model: &Model, map: &KeyedMap<E>) {
    let root = map.root();
    let table = schema.position("t.a").unwrap();
    let ((_, key), value) = model
        .iter()
        .find(|((candidate, _), _)| *candidate == table)
        .expect("the populated table has an entry");
    let included = map.prove_inclusion(table, key).unwrap().unwrap();
    let absent_key = b"never-committed".to_vec();
    let absent = map.prove_absence(table, &absent_key).unwrap().unwrap();
    let entries = in_range(model, table, b"", None);
    let ranged = map.prove_range(table, b"", None).unwrap();
    let cases: [(&[u8], Check<'_>, Check<'_>); 3] = [
        (
            &included,
            Box::new(|witness| {
                KeyedMap::<E>::verify_inclusion(schema, &root, table, key, value, witness).is_ok()
            }),
            Box::new(|witness| {
                KeyedMap::<E>::verify_inclusion(schema, &root, table, key, b"other", witness)
                    .is_ok()
            }),
        ),
        (
            &absent,
            Box::new(|witness| {
                KeyedMap::<E>::verify_absence(schema, &root, table, &absent_key, witness).is_ok()
            }),
            Box::new(|witness| {
                KeyedMap::<E>::verify_absence(schema, &root, table, key, witness).is_ok()
            }),
        ),
        (
            &ranged,
            Box::new(|witness| {
                KeyedMap::<E>::verify_range(schema, &root, table, b"", None, &entries, witness)
                    .is_ok()
            }),
            Box::new(|witness| {
                KeyedMap::<E>::verify_range(schema, &root, table, b"", None, &entries[1..], witness)
                    .is_ok()
            }),
        ),
    ];
    for (witness, holds, false_holds) in cases {
        assert!(holds(witness) && !false_holds(witness));
        for length in 0..witness.len() {
            assert!(!holds(&witness[..length]), "truncated to {length}");
        }
        let mut extended = witness.to_vec();
        extended.push(0);
        assert!(!holds(&extended));
        for index in 0..witness.len() {
            for mask in [0x01, 0x80] {
                let mut changed = witness.to_vec();
                changed[index] ^= mask;
                assert!(!false_holds(&changed), "byte {index} changed");
            }
        }
    }
}

/// A generated index below `bound`.
fn pick(generator: &mut SplitMix64, bound: usize) -> usize {
    usize::try_from(generator.below(bound as u64)).expect("below a usize bound")
}

fn check_engine<E: Engine>(rounds: usize) {
    let schema = schema();
    let tables: Vec<u32> = ["t.a", "t.a.sub", "t.b"]
        .iter()
        .map(|identity| schema.position(identity).unwrap())
        .collect();
    let cell = schema.position("t.cell").unwrap();
    let keys = probe_keys();
    let mut generator = SplitMix64::new(0x5eed);
    let mut model = Model::new();
    let mut map = KeyedMap::<E>::empty(schema.clone());
    let empty_root = map.root();
    assert_eq!(map.entries(), 0);
    check_statements(&schema, &model, &map);
    for round in 0..rounds {
        let mut staged: BTreeMap<(u32, Vec<u8>), Option<Vec<u8>>> = BTreeMap::new();
        for _ in 0..=generator.below(5) {
            let position = if generator.below(8) == 0 {
                (cell, Vec::new())
            } else {
                (
                    tables[pick(&mut generator, tables.len())],
                    keys[pick(&mut generator, keys.len())].clone(),
                )
            };
            let value = match pick(&mut generator, 4) {
                0 => None,
                1 => Some(Vec::new()),
                size => {
                    let fill = u8::try_from(pick(&mut generator, 251)).expect("below 251");
                    Some(vec![fill; 20 * size])
                }
            };
            staged.insert(position, value);
        }
        let set: Vec<TableChange<'_>> = staged
            .iter()
            .map(|((table, key), value)| (*table, key.as_slice(), value.as_deref()))
            .collect();
        // A clone replays the same change set from the same state.
        let mut replay = map.clone();
        map.apply(&set).expect("a valid change set");
        if round % 4 == 0 {
            replay.apply(&set).expect("a valid change set");
            assert_eq!(replay.root(), map.root(), "replay in round {round}");
            assert_eq!(replay.storage(), map.storage());
        }
        for ((table, key), value) in staged.clone() {
            match value {
                Some(value) => model.insert((table, key), value),
                None => model.remove(&(table, key)),
            };
        }
        assert_eq!(map.entries(), model.len() as u64);
        assert_eq!(map.storage().entries, model.len() as u64);
        assert_eq!(
            map.root(),
            cold::<E>(&schema, &model).root(),
            "incremental root differs from a cold build in round {round}"
        );
        if round % 4 == 0 {
            check_statements(&schema, &model, &map);
        }
    }
    check_statements(&schema, &model, &map);
    if model
        .keys()
        .any(|(table, _)| *table == schema.position("t.a").unwrap())
    {
        check_canonical(&schema, &model, &map);
    }
    // No-op changes leave the root unchanged; ill-formed sets change nothing.
    let root = map.root();
    map.apply(&[(tables[0], b"never-present", None)]).unwrap();
    map.apply(&[]).unwrap();
    assert_eq!(map.root(), root);
    assert_eq!(
        map.apply(&[(tables[0], b"k", Some(b"v")), (99, b"k", Some(b"v"))]),
        Err(StatementFault::UnknownTable)
    );
    assert_eq!(
        map.apply(&[(cell, b"k", Some(b"v"))]),
        Err(StatementFault::CellKey)
    );
    assert_eq!(
        map.apply(&[(tables[0], b"k", Some(b"v")), (tables[0], b"k", None)]),
        Err(StatementFault::DuplicateChange)
    );
    assert_eq!(map.root(), root);
    assert_eq!(
        map.prove_range(tables[0], b"b", Some(b"a")),
        Err(StatementFault::EmptyRange)
    );
    assert_eq!(
        KeyedMap::<E>::verify_absence(&schema, &root, cell, b"x", &[]),
        Err(VerifyError::Statement(StatementFault::CellKey))
    );
    // Removing everything returns to the root of the empty State.
    let removals: Vec<TableChange<'_>> = model
        .keys()
        .map(|(table, key)| (*table, key.as_slice(), None))
        .collect();
    map.apply(&removals).unwrap();
    assert_eq!(map.root(), empty_root);
    assert_eq!(map.storage().entries, 0);

    // The root binds the schema descriptor, also for the empty State.
    let other = PrototypeSchema::from_descriptor(&descriptor_from_rows(&[(
        "t.a",
        KEY,
        "norito:other@0.0.2",
    )]))
    .unwrap();
    let single =
        PrototypeSchema::from_descriptor(&descriptor_from_rows(&[("t.a", KEY, VALUE)])).unwrap();
    assert_ne!(
        KeyedMap::<E>::empty(other).root(),
        KeyedMap::<E>::empty(single).root()
    );
    assert!(E::CONSTRUCTION.ends_with("/v0"));
}

#[test]
fn radix_tree_agrees_with_an_ordered_map() {
    check_engine::<RadixTree<Blake2bProfile>>(48);
    check_engine::<RadixTree<Poseidon2Profile>>(8);
    check_engine::<RadixTree<RescuePrimeProfile>>(4);
    check_engine::<RadixTree<Digest384Comparator>>(2);
}

#[test]
fn merkle_btree_agrees_with_an_ordered_map() {
    check_engine::<MerkleBTree<Blake2bProfile>>(48);
    check_engine::<MerkleBTree<Poseidon2Profile>>(8);
    check_engine::<MerkleBTree<RescuePrimeProfile>>(4);
}

#[test]
fn linked_leaf_map_agrees_with_an_ordered_map() {
    check_engine::<LinkedLeafMap<Blake2bProfile>>(48);
    check_engine::<LinkedLeafMap<Poseidon2Profile>>(8);
    check_engine::<LinkedLeafMap<RescuePrimeProfile>>(4);
}

#[test]
fn sorted_hash_chain_agrees_with_an_ordered_map() {
    check_engine::<SortedHashChain<Blake2bProfile>>(48);
    check_engine::<SortedHashChain<Poseidon2Profile>>(8);
    check_engine::<SortedHashChain<RescuePrimeProfile>>(4);
}

/// Pages form and merge as keys arrive and leave: a few hundred scattered keys
/// give the B-tree several levels, and every prefix of the insertion order and
/// of the removal order equals a cold build.
#[test]
fn merkle_btree_pages_split_and_merge_like_a_cold_build() {
    type Tree = MerkleBTree<Blake2bProfile>;
    let schema = schema();
    let table = schema.position("t.a").unwrap();
    let mut generator = SplitMix64::new(42);
    let mut model = Model::new();
    let mut map = KeyedMap::<Tree>::empty(schema.clone());
    let mut keys = Vec::new();
    for round in 0..40_u8 {
        let mut staged = Vec::new();
        for _ in 0..16 {
            let mut key = [0_u8; 8];
            generator.fill(&mut key);
            staged.push((key.to_vec(), vec![round; 3]));
        }
        let set: Vec<TableChange<'_>> = staged
            .iter()
            .map(|(key, value)| (table, key.as_slice(), Some(value.as_slice())))
            .collect();
        map.apply(&set).unwrap();
        for (key, value) in staged {
            keys.push(key.clone());
            model.insert((table, key), value);
        }
        assert_eq!(
            map.root(),
            cold::<Tree>(&schema, &model).root(),
            "round {round}"
        );
    }
    assert!(map.storage().max_depth >= 8, "640 keys need several levels");
    let lower = keys[7].clone();
    let honest = in_range(&model, table, &lower, None);
    let witness = map.prove_range(table, &lower, None).unwrap();
    KeyedMap::<Tree>::verify_range(&schema, &map.root(), table, &lower, None, &honest, &witness)
        .unwrap();
    assert!(
        KeyedMap::<Tree>::verify_range(
            &schema,
            &map.root(),
            table,
            &lower,
            None,
            &honest[..honest.len() - 1],
            &witness
        )
        .is_err()
    );
    for (round, chunk) in keys.chunks(16).enumerate() {
        let set: Vec<TableChange<'_>> = chunk
            .iter()
            .map(|key| (table, key.as_slice(), None))
            .collect();
        map.apply(&set).unwrap();
        for key in chunk {
            model.remove(&(table, key.clone()));
        }
        assert_eq!(
            map.root(),
            cold::<Tree>(&schema, &model).root(),
            "removal {round}"
        );
    }
    assert_eq!(map.entries(), 0);
}

/// The descriptor is hashed once per profile, not once per verification.
#[test]
fn schema_digest_is_hashed_once_per_profile() {
    let schema = schema();
    let _ = take_hash_work();
    let first = schema.digest::<Blake2bProfile>();
    assert_eq!(take_hash_work().byte_hashes, 1);
    let clone = schema.clone();
    assert_eq!(clone.digest::<Blake2bProfile>(), first);
    assert_eq!(schema.digest::<Blake2bProfile>(), first);
    assert_eq!(take_hash_work().byte_hashes, 0, "the kept digest is reused");
    assert_ne!(schema.digest::<Poseidon2Profile>(), first);
    assert_eq!(take_hash_work().byte_hashes, 1);
    assert_eq!(clone, schema);
    // A verification hashes the statement and the path, never the descriptor.
    let table = schema.position("t.a").unwrap();
    let mut map = KeyedMap::<RadixTree<Blake2bProfile>>::empty(schema.clone());
    map.apply(&[(table, b"k", Some(b"v"))]).unwrap();
    let witness = map.prove_inclusion(table, b"k").unwrap().unwrap();
    let root = map.root();
    let _ = take_hash_work();
    KeyedMap::<RadixTree<Blake2bProfile>>::verify_inclusion(
        &schema, &root, table, b"k", b"v", &witness,
    )
    .unwrap();
    let work = take_hash_work();
    // Key and value digests; the leaf and the root normalisation.
    assert_eq!((work.byte_hashes, work.compressions), (2, 2));
    assert!(work.bytes < 16, "{work:?}");
}

#[test]
fn schema_descriptor_parsing_is_exact() {
    let descriptor = descriptor_from_rows(&[("t.b", KEY, VALUE), ("t.a", "", VALUE)]);
    let schema = PrototypeSchema::from_descriptor(&descriptor).unwrap();
    assert_eq!(schema.tables(), 2);
    assert_eq!(schema.descriptor(), descriptor);
    assert_eq!(schema.identity(0), Some("t.a"));
    assert_eq!(schema.position("t.b"), Some(1));
    assert_eq!(schema.position("t"), None);
    assert_eq!(schema.is_cell(0), Some(true));
    assert_eq!(schema.is_cell(1), Some(false));
    assert_eq!(schema.is_cell(2), None);
    assert!(PrototypeSchema::from_descriptor(&descriptor[..descriptor.len() - 1]).is_none());
    let mut extended = descriptor.clone();
    extended.push(0);
    assert!(PrototypeSchema::from_descriptor(&extended).is_none());
    assert!(PrototypeSchema::from_descriptor(b"another domain").is_none());
    assert_ne!(
        schema.digest::<Blake2bProfile>(),
        schema.digest::<Poseidon2Profile>()
    );
    // Composite keys order by table position first and never cross tables.
    assert!(composite_key(0, b"\xff\xff") < composite_key(1, b""));
    assert_eq!(composite_key(258, b"k"), [0, 0, 1, 2, b'k']);
    let structure = [1, 2, 3, 4];
    assert_ne!(
        normalised_root::<Blake2bProfile>(&structure, &schema.digest::<Blake2bProfile>()),
        normalised_root::<Blake2bProfile>(&structure, &ZERO_DIGEST)
    );
}

fn check_profile<H: HashProfile>() {
    let digest = H::hash_bytes(DOMAIN_KEY, b"abc");
    assert!(H::is_canonical(&digest));
    assert_ne!(digest, ZERO_DIGEST);
    assert_eq!(digest, H::hash_bytes(DOMAIN_KEY, b"abc"));
    // Domain, content, length and split are all bound.
    assert_ne!(digest, H::hash_bytes(DOMAIN_VALUE, b"abc"));
    assert_ne!(digest, H::hash_bytes(DOMAIN_KEY, b"abd"));
    assert_ne!(digest, H::hash_bytes(DOMAIN_KEY, b"abc\0"));
    assert_ne!(
        H::hash_bytes(DOMAIN_KEY, b""),
        H::hash_bytes(DOMAIN_KEY, b"\0")
    );
    let long = vec![0x61_u8; 200];
    assert_ne!(
        H::hash_bytes(DOMAIN_KEY, &long),
        H::hash_bytes(DOMAIN_KEY, &long[..199])
    );
    let (left, right) = (
        H::hash_bytes(DOMAIN_KEY, b"l"),
        H::hash_bytes(DOMAIN_KEY, b"r"),
    );
    let node = H::compress(DOMAIN_BRANCH, 7, &left, &right);
    assert!(H::is_canonical(&node));
    assert_ne!(node, H::compress(DOMAIN_BRANCH, 7, &right, &left));
    assert_ne!(node, H::compress(DOMAIN_BRANCH, 8, &left, &right));
    assert_ne!(node, H::compress(DOMAIN_LEAF, 7, &left, &right));
    // A digest survives its 32-byte encoding.
    assert_eq!(digest_from_bytes(&digest_to_bytes(&node)), node);
    assert_eq!(
        H::ALGEBRAIC,
        H::NAME.contains("goldilocks") || H::NAME.contains("poseidon")
    );
    assert!(!H::NAME.is_empty());
    // Entry leaves frame key and value separately.
    assert_ne!(entry_leaf::<H>(b"ab", b"c"), entry_leaf::<H>(b"a", b"bc"));
    assert_eq!(immediate_successor(b"a"), b"a\0");
}

#[test]
fn every_hash_profile_binds_domain_length_and_order() {
    check_profile::<Blake2bProfile>();
    check_profile::<Poseidon2Profile>();
    check_profile::<RescuePrimeProfile>();
    check_profile::<Digest384Comparator>();
    // Raw BLAKE2b keeps all 256 bits: no marker bit is forced.
    let unmarked = (0..64_u8).any(|seed| {
        digest_to_bytes(&Blake2bProfile::hash_bytes(DOMAIN_KEY, &[seed]))[DIGEST_BYTES - 1] & 1 == 0
    });
    assert!(unmarked, "raw BLAKE2b output is not marker-bearing");
    assert!(!Poseidon2Profile::is_canonical(&[u64::MAX, 0, 0, 0]));
    assert!(Blake2bProfile::is_canonical(&[u64::MAX; 4]));
}

#[test]
fn byte_packing_is_injective_and_canonical() {
    assert_eq!(pack_bytes(b""), vec![[0; 8]]);
    assert_eq!(pack_bytes(b"\x01")[0][..2], [1, 1]);
    // Seven bytes fill one limb; the eighth starts the next.
    let eight = pack_bytes(&[0xff; 8]);
    assert_eq!(eight[0][..3], [8, 0x00ff_ffff_ffff_ffff, 0xff]);
    // 49 bytes are seven limbs plus the length: exactly one block.
    assert_eq!(pack_bytes(&[1; 49]).len(), 1);
    assert_eq!(pack_bytes(&[1; 50]).len(), 2);
    assert_ne!(pack_bytes(b"a"), pack_bytes(b"a\0"));
    assert!(
        pack_bytes(&[0xff; 100])
            .iter()
            .flatten()
            .all(|word| *word < 1 << 56)
    );
}

#[test]
fn hash_work_counts_permutations_and_bytes() {
    let _ = take_hash_work();
    let digest = Poseidon2Profile::hash_bytes(DOMAIN_VALUE, &[7; 256]);
    let _ = Poseidon2Profile::compress(DOMAIN_LEAF, 0, &digest, &digest);
    let work = take_hash_work();
    assert_eq!(work.byte_hashes, 1);
    assert_eq!(work.bytes, 256);
    assert_eq!(work.compressions, 1);
    // 256 bytes are 37 limbs plus the length: five rate blocks, then one compression.
    assert_eq!(work.permutations, 6);
    assert_eq!(take_hash_work(), hash::HashWork::default());
    let _ = Blake2bProfile::compress(DOMAIN_LEAF, 0, &digest, &digest);
    assert_eq!(take_hash_work().permutations, 0);
    let _ = Digest384Comparator::compress(DOMAIN_LEAF, 0, &digest, &digest);
    let comparator = take_hash_work();
    assert_eq!(comparator.compressions, 1);
    assert!(comparator.permutations >= 6 * 8, "{comparator:?}");
}

/// The sponge is the documented sequence of permutations.
#[test]
fn sponge_profile_is_the_documented_permutation_sequence() {
    fn check<P: Permutation12>() {
        let (left, right) = ([1, 2, 3, 4], [5, 6, 7, 8]);
        let mut state = [DOMAIN_BRANCH, 9, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        P::permute(&mut state);
        assert_eq!(
            AlgebraicSponge::<P>::compress(DOMAIN_BRANCH, 9, &left, &right),
            state[4..8]
        );
        let bytes = [0x5a_u8; 60];
        let blocks = pack_bytes(&bytes);
        assert_eq!(blocks.len(), 2);
        let mut state = [0_u64; 12];
        state[0] = DOMAIN_KEY;
        state[4..].copy_from_slice(&blocks[0]);
        P::permute(&mut state);
        for (cell, word) in state[4..].iter_mut().zip(blocks[1]) {
            *cell = crate::field::add_base(*cell, word);
        }
        P::permute(&mut state);
        assert_eq!(
            AlgebraicSponge::<P>::hash_bytes(DOMAIN_KEY, &bytes),
            state[4..8]
        );
    }
    check::<poseidon2::Poseidon2Goldilocks12>();
    check::<rescue::RescuePrime64>();
}
