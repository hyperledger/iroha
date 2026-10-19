//! Transaction copy costs for pair-row indexes versus set-valued indexes.
//!
//! Run the ignored measurement in an optimized build with
//! `cargo test -p mv --release --test flat_index_transactions -- --ignored --nocapture`.
use std::{cell::Cell, collections::BTreeSet, hint::black_box, time::Instant};

use mv::storage::{Storage, StorageReadOnly};

thread_local! {
    static MEMBER_CLONES: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CountedMember([u8; 32]);

impl Clone for CountedMember {
    fn clone(&self) -> Self {
        MEMBER_CLONES.with(|count| count.set(count.get() + 1));
        Self(self.0)
    }
}

fn member(value: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&(value as u64).to_be_bytes());
    bytes
}

fn counted_clones(action: impl FnOnce()) -> usize {
    MEMBER_CLONES.with(|count| count.set(0));
    action();
    MEMBER_CLONES.with(Cell::get)
}

fn transaction_clone_counts(size: usize) -> ((usize, usize), (usize, usize)) {
    // Three adjacent buckets also exercise the neighbouring values copied with
    // the modified leaf. Fixture construction is excluded from clone counting.
    let grouped: Storage<u8, BTreeSet<CountedMember>> = (0..3)
        .map(|key| {
            (
                key,
                (0..size)
                    .map(|value| CountedMember(member(value)))
                    .collect(),
            )
        })
        .collect();
    let flat: Storage<(u8, CountedMember), ()> = (0..3)
        .flat_map(|key| (0..size).map(move |value| ((key, CountedMember(member(value))), ())))
        .collect();
    let mut grouped_block = grouped.block();
    let mut flat_block = flat.block();
    // Populate each block's undo ownership before the measured transactions.
    for insert in [true, false] {
        let mut transaction = grouped_block.transaction();
        let values = transaction.get_mut(&1).unwrap();
        if insert {
            values.insert(CountedMember(member(size)));
        } else {
            values.remove(&CountedMember(member(size)));
        }
        transaction.apply();
        let mut transaction = flat_block.transaction();
        if insert {
            transaction.insert((1, CountedMember(member(size))), ());
        } else {
            transaction.remove((1, CountedMember(member(size))));
        }
        transaction.apply();
    }
    let grouped_insert = counted_clones(|| {
        let mut transaction = grouped_block.transaction();
        transaction
            .get_mut(&1)
            .unwrap()
            .insert(CountedMember(member(size)));
        transaction.apply();
    });
    let grouped_remove = counted_clones(|| {
        let mut transaction = grouped_block.transaction();
        transaction
            .get_mut(&1)
            .unwrap()
            .remove(&CountedMember(member(size)));
        transaction.apply();
    });
    let flat_insert = counted_clones(|| {
        let mut transaction = flat_block.transaction();
        transaction.insert((1, CountedMember(member(size))), ());
        transaction.apply();
    });
    let flat_remove = counted_clones(|| {
        let mut transaction = flat_block.transaction();
        transaction.remove((1, CountedMember(member(size))));
        transaction.apply();
    });
    assert_eq!(grouped_block.get(&1).unwrap().len(), size);
    assert_eq!(flat_block.len(), size * 3);
    assert!(flat_block.get(&(1, CountedMember(member(size)))).is_none());
    ((grouped_insert, grouped_remove), (flat_insert, flat_remove))
}

#[test]
fn member_transactions_copy_tree_paths_instead_of_index_groups() {
    let mut flat_counts = Vec::new();
    for size in [1_000, 10_000, 100_000] {
        let (grouped, flat) = transaction_clone_counts(size);
        eprintln!("members={size} grouped_clones={grouped:?} flat_clones={flat:?}");
        assert!(grouped.0 >= size && grouped.1 >= size);
        // A tree path may gain a level as cardinality grows. Copying hundreds of
        // keys is permitted; copying the whole smallest 1,000-member group is not.
        assert!(flat.0 < 512 && flat.1 < 512, "{size}: {flat:?}");
        flat_counts.push(flat);
    }
    let (small, large) = (flat_counts[0], flat_counts[2]);
    assert!(large.0 <= small.0 + 128 && large.1 <= small.1 + 128);
}

fn median_ns(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn measure_grouped(size: usize) -> (u128, u128) {
    let storage: Storage<u8, BTreeSet<[u8; 32]>> =
        [(0, (0..size).map(member).collect())].into_iter().collect();
    let mut block = storage.block();
    let mut inserts = Vec::new();
    let mut removes = Vec::new();
    for sample in 0..10 {
        let started = Instant::now();
        let mut transaction = block.transaction();
        black_box(transaction.get_mut(&0).unwrap().insert(member(size)));
        transaction.apply();
        let insert_elapsed = started.elapsed().as_nanos();
        let started = Instant::now();
        let mut transaction = block.transaction();
        black_box(transaction.get_mut(&0).unwrap().remove(&member(size)));
        transaction.apply();
        let remove_elapsed = started.elapsed().as_nanos();
        if sample > 0 {
            inserts.push(insert_elapsed);
            removes.push(remove_elapsed);
        }
    }
    black_box(block.get(&0));
    (median_ns(&mut inserts), median_ns(&mut removes))
}

fn measure_flat(size: usize) -> (u128, u128) {
    let storage: Storage<(u8, [u8; 32]), ()> =
        (0..size).map(|value| ((0, member(value)), ())).collect();
    let mut block = storage.block();
    let mut inserts = Vec::new();
    let mut removes = Vec::new();
    for sample in 0..10 {
        let started = Instant::now();
        let mut transaction = block.transaction();
        black_box(transaction.insert((0, member(size)), ()));
        transaction.apply();
        let insert_elapsed = started.elapsed().as_nanos();
        let started = Instant::now();
        let mut transaction = block.transaction();
        black_box(transaction.remove((0, member(size))));
        transaction.apply();
        let remove_elapsed = started.elapsed().as_nanos();
        if sample > 0 {
            inserts.push(insert_elapsed);
            removes.push(remove_elapsed);
        }
    }
    black_box(block.len());
    (median_ns(&mut inserts), median_ns(&mut removes))
}

#[test]
#[ignore = "manual median transaction benchmark; use an optimized build"]
fn measure_pair_row_transaction_cost() {
    println!("members,grouped_insert_ns,grouped_remove_ns,flat_insert_ns,flat_remove_ns");
    for size in [1_000, 10_000, 100_000, 1_000_000] {
        let grouped = measure_grouped(size);
        let flat = measure_flat(size);
        println!("{size},{},{},{},{}", grouped.0, grouped.1, flat.0, flat.1);
    }
}
