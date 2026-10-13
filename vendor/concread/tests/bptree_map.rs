//! Ordered-map range, lookup and removal regressions against BTreeMap.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use concread::bptree::BptreeMap;
use rand::{rngs::StdRng, Rng, SeedableRng};

// Iroha patch: the upstream proptest properties run as fixed-seed randomized
// cases so the vendored workspace member does not pull `proptest` into the
// reviewed dependency graph (see IROHA_PATCHES.md).
const CASES: usize = 256;

fn random_set(rng: &mut StdRng, min_len: usize) -> BTreeSet<u8> {
    loop {
        let len = rng.random_range(min_len..256);
        let values: BTreeSet<u8> = (0..len).map(|_| rng.random()).collect();
        if values.len() >= min_len {
            return values;
        }
    }
}

fn random_bound(rng: &mut StdRng) -> Bound<()> {
    match rng.random_range(0..3) {
        0 => Bound::Included(()),
        1 => Bound::Excluded(()),
        _ => Bound::Unbounded,
    }
}

#[test]
fn bptree_range_iter_consistent() {
    let mut rng = StdRng::seed_from_u64(0x6270_7472_6565_0001);
    for _ in 0..CASES {
        let values = random_set(&mut rng, 0);
        let left: u8 = rng.random_range(0..u8::MAX - 1);
        let len: u8 = rng.random_range(1..u8::MAX);
        let bounds = (random_bound(&mut rng), random_bound(&mut rng));
        let range = (
            bounds.0.map(|()| left),
            bounds.1.map(|()| left.saturating_add(len)),
        );
        let btree_map = BTreeMap::from_iter(values.iter().cloned().map(|v| (v, ())));
        let bptree_map = BptreeMap::from_iter(values.iter().cloned().map(|v| (v, ())));
        let bptree_map_read_tx = bptree_map.read();

        let btree_iter = btree_map.range(range);
        let bptree_iter = bptree_map_read_tx.range(range);

        assert!(
            btree_iter.eq(bptree_iter),
            "values={values:?} range={range:?}"
        );
    }
}

#[test]
fn bptree_get_consistent() {
    let mut rng = StdRng::seed_from_u64(0x6270_7472_6565_0002);
    for _ in 0..CASES {
        let values = random_set(&mut rng, 0);
        let btree_map = BTreeMap::from_iter(values.iter().cloned().map(|v| (v, v)));
        let bptree_map = BptreeMap::from_iter(values.iter().cloned().map(|v| (v, v)));
        let bptree_map_read_tx = bptree_map.read();

        for key in u8::MIN..=u8::MAX {
            assert_eq!(
                btree_map.get(&key),
                bptree_map_read_tx.get(&key),
                "values={values:?} key={key}"
            );
        }
    }
}

#[test]
fn bptree_remove_consistent() {
    let mut rng = StdRng::seed_from_u64(0x6270_7472_6565_0003);
    for _ in 0..CASES {
        let values = random_set(&mut rng, 1);
        let indices: Vec<usize> = (0..rng.random_range(0..100))
            .map(|_| rng.random_range(0..values.len()))
            .collect();
        let mut btree_map = BTreeMap::from_iter(
            values
                .iter()
                .cloned()
                .map(|v| (v.to_string(), v.to_string())),
        );
        let bptree_map = BptreeMap::from_iter(
            values
                .iter()
                .cloned()
                .map(|v| (v.to_string(), v.to_string())),
        );
        let mut bptree_map_write_tx = bptree_map.write();

        for index in indices {
            let key = values.iter().nth(index).unwrap().to_string();

            assert_eq!(btree_map.remove(&key), bptree_map_write_tx.remove(&key));

            let btree_value = btree_map.get(&key);
            assert_eq!(btree_value, None);
            let bptree_value = bptree_map_write_tx.get(&key);
            assert_eq!(bptree_value, None);

            assert!(btree_map.iter().eq(bptree_map_write_tx.iter()));
        }
    }
}

#[test]
fn bptree_remove_1() {
    let values = [
        4u8, 9, 12, 27, 34, 40, 59, 81, 89, 100, 142, 183, 189, 196, 218, 241,
    ];

    let to_remove = [9u8, 27, 40, 4].map(|v| v.to_string());

    let bptree_map = BptreeMap::from_iter(
        values
            .iter()
            .cloned()
            .map(|v| (v.to_string(), v.to_string())),
    );
    let mut bptree_map_write_tx = bptree_map.write();

    for key in to_remove {
        assert!(bptree_map_write_tx.remove(&key).is_some());
    }
}
