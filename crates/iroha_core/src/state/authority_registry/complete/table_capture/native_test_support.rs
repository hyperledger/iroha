//! Reusable populated-table proof controls for typed native persistence fixtures.

use super::LeafLimits;

/// Small operational limits for isolated native table fixtures.
pub(super) fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 2,
        max_payload_bytes: 8 * 1024,
        max_ordered_table_bytes: 32 * 1024,
        max_streamed_value_bytes: 32 * 1024,
    }
}

/// Duplicate a fixture uniformly for Copy and heap-owning native types.
pub(super) fn cloned<T: Clone>(value: &T) -> T {
    value.clone()
}

// Fixture tables use their ordinary storage writer. These controls never
// bypass node admission.
macro_rules! fixture_insert {
    ($state:ident, $storage:ident, $key:expr, $value:expr) => {
        let mut block = $state.world.$storage.block();
        block.insert($key, $value);
        block.commit();
    };
}
macro_rules! fixture_remove {
    ($state:ident, $storage:ident, $key:expr) => {
        let mut block = $state.world.$storage.block();
        block.remove($key);
        block.commit();
    };
}

// Canonical typed fixtures exercise exact persistence. They do not claim
// that an isolated row was admitted by the corresponding governance ISI.
macro_rules! capture_controls {
    ($test:ident, $storage:ident, $capture:ident, $fixture:expr, $change:expr) => {
        #[test]
        fn $test() {
            let (key, value) = $fixture;
            let state = State::new_for_testing(
                World::new(),
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            const TABLE: &str = concat!("world.", stringify!($storage));
            fixture_insert!(state, $storage, cloned(&key), cloned(&value));
            let snapshot = $capture(&state, limits())
                .expect("bounded native table")
                .expect("stable generation");
            assert_eq!(snapshot.table_id(), TABLE);
            assert_eq!(snapshot.row_count(), 1);
            let start = norito::codec::encode_adaptive(&key);
            let mut end = start.clone();
            end.push(0xff);
            let proof = snapshot.prove_raw_range(&start, &end, 1, 4096).unwrap();
            let verified = CanonicalTableLeafSet::verify_paired_raw_range(
                TABLE,
                limits(),
                &snapshot.root(),
                &snapshot.lookup_root(),
                &snapshot.ordered_root(),
                &start,
                &end,
                1,
                4096,
                &proof,
            )
            .expect("exact canonical persisted range");
            CanonicalTableLeafSet::verify_paired_value_preimage(
                TABLE,
                limits(),
                &verified,
                &start,
                &value,
            )
            .expect("full value preimage matches its authenticated digest");
            let mut changed = cloned(&value);
            ($change)(&mut changed);
            assert_eq!(
                CanonicalTableLeafSet::verify_paired_value_preimage(
                    TABLE,
                    limits(),
                    &verified,
                    &start,
                    &changed,
                ),
                Err(LeafError::ValuePreimageMismatch)
            );
            {
                fixture_insert!(state, $storage, cloned(&key), changed);
            }
            let changed = $capture(&state, limits()).unwrap().unwrap();
            assert_ne!(changed.root(), snapshot.root());
            {
                fixture_remove!(state, $storage, key);
            }
            let omitted = $capture(&state, limits()).unwrap().unwrap();
            assert_eq!(omitted.row_count(), 0);
            let omission = omitted.prove_raw_range(&start, &end, 0, 12).unwrap();
            assert!(matches!(
                CanonicalTableLeafSet::verify_paired_raw_range(
                    TABLE,
                    limits(),
                    &snapshot.root(),
                    &omitted.lookup_root(),
                    &omitted.ordered_root(),
                    &start,
                    &end,
                    0,
                    12,
                    &omission,
                ),
                Err(LeafError::RootMismatch)
            ));
        }
    };
}

pub(super) use {capture_controls, fixture_insert, fixture_remove};
