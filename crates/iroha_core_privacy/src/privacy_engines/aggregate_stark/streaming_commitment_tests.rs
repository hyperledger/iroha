//! Scalar-byte parity, malformed topology, deterministic failures and custody.

use super::*;
use std::cell::RefCell;

thread_local! {
    static CLEARS: RefCell<Option<Vec<usize>>> = const { RefCell::new(None) };
}
pub(super) fn observe_clear_v1(values: &[PrivacyOuterDigestV1]) {
    CLEARS.with(|slot| {
        if let Some(observed) = slot.borrow_mut().as_mut() {
            assert!(
                values
                    .iter()
                    .all(|value| *value == PrivacyOuterDigestV1::default())
            );
            observed.push(values.len());
        }
    });
}
struct Census;
impl Census {
    fn begin() -> Self {
        CLEARS.with(|slot| {
            assert!(slot.borrow().is_none(), "nested digest-tile census");
            *slot.borrow_mut() = Some(Vec::new());
        });
        Self
    }
    fn finish(self) -> Vec<usize> {
        CLEARS.with(|slot| slot.borrow_mut().take().unwrap())
    }
}
impl Drop for Census {
    fn drop(&mut self) {
        CLEARS.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn context() -> TransparentStarkDigestContextV1 {
    TransparentStarkDigestContextV1::new(
        iroha_data_model::privacy::PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        b"bounded-commitment-reference",
    )
}
const NODE: &[u8] = b"bounded-commitment-node";
fn leaves(rows: usize) -> Vec<PrivacyOuterDigestV1> {
    (0..rows)
        .map(|i| {
            let mut bytes = [17; 48];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            PrivacyOuterDigestV1::from_bytes(bytes)
        })
        .collect()
}
fn accumulator(rows: usize, queries: &[usize]) -> StreamingMerkleAccumulatorV1 {
    StreamingMerkleAccumulatorV1::new(context(), NODE, rows, queries).unwrap()
}

#[test]
fn bounded_tiles_match_scalar_tree_all_queries_extremes_and_multi_tile_boundaries() {
    for rows in [1, 2, 8, 64, TILE_ROWS, 2 * TILE_ROWS, 4 * TILE_ROWS] {
        let values = leaves(rows);
        let tree = PrivacyOuterMerkleTreeV1::from_leaves(values.clone(), context(), NODE).unwrap();
        let mut queries = vec![0, rows - 1];
        if rows > TILE_ROWS {
            queries.extend([TILE_ROWS - 1, TILE_ROWS, TILE_ROWS + 1]);
        }
        queries.sort_unstable();
        queries.dedup();
        for positions in [
            Vec::new(),
            queries,
            (0..rows).step_by(3).collect(),
            (0..rows).collect(),
        ] {
            for workers in [1, 4] {
                let actual = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap()
                    .install(|| {
                        streaming_merkle_commitment_v1(
                            context(),
                            NODE,
                            rows,
                            &positions,
                            values.iter().copied().map(Ok),
                        )
                    })
                    .unwrap();
                assert_eq!(actual.root, tree.root());
                if positions.is_empty() {
                    assert!(actual.frontier.is_empty());
                } else {
                    assert_eq!(
                        actual.frontier,
                        canonical_multiproof_frontier_v1(&tree, rows, &positions).unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_alignment_missing_duplicate_and_trailing_frontiers_fail_closed() {
    let values = leaves(8);
    for count in [0, 3, 9] {
        let mut acc = accumulator(8, &[0, 7]);
        let mut nodes = vec![values[0]; count];
        assert!(append_tile_v1(&mut acc, &mut nodes).is_err());
        assert_eq!(acc.next_leaf, 0);
    }
    let mut acc = accumulator(8, &[0, 7]);
    acc.append_subtree_v1(0, values[0]).unwrap();
    let mut pair = values[1..3].to_vec();
    assert!(append_tile_v1(&mut acc, &mut pair).is_err());
    assert_eq!(acc.next_leaf, 1);
    assert!(
        acc.append_subtree_v1(usize::BITS as usize, values[0])
            .is_err()
    );
    let mut duplicate = accumulator(8, &[0]);
    let position = duplicate.frontier_positions[&(0, 1)];
    duplicate.frontier[position] = Some(values[1]);
    assert!(append_tile_v1(&mut duplicate, &mut values.clone()).is_err());
    let mut missing = accumulator(8, &[0]);
    append_tile_v1(&mut missing, &mut values.clone()).unwrap();
    missing.frontier[0] = None;
    assert_eq!(
        missing.finish(),
        Err(AggregateStarkErrorV1::InternalInvariant)
    );
    for count in [7, 9] {
        let input = (0..count).map(|i| Ok(values[i % 8]));
        assert_eq!(
            streaming_merkle_commitment_v1(context(), NODE, 8, &[0], input),
            Err(AggregateStarkErrorV1::InvalidProofShape)
        );
    }
}

#[test]
fn digest_tile_clears_success_early_error_and_unwind_and_rejects_nested_census() {
    let census = Census::begin();
    {
        let mut tile = DigestTileV1::new(8).unwrap();
        tile.0.copy_from_slice(&leaves(8));
        tile.clear_v1();
        assert!(tile.0.iter().all(|v| *v == PrivacyOuterDigestV1::default()));
    }
    let mut acc = accumulator(8, &[0]);
    assert_eq!(
        append_leaves_v1(
            &mut acc,
            (0..8).map(|i| if i == 3 {
                Err(AggregateStarkErrorV1::NonCanonicalField)
            } else {
                Ok(leaves(1)[0])
            })
        ),
        Err(AggregateStarkErrorV1::NonCanonicalField)
    );
    let panic = std::panic::catch_unwind(|| {
        let mut tile = DigestTileV1::new(8).unwrap();
        tile.0.copy_from_slice(&leaves(8));
        panic!("synthetic digest tile unwind");
    });
    assert!(panic.is_err());
    assert!(std::panic::catch_unwind(Census::begin).is_err());
    assert_eq!(census.finish(), vec![8, 8, 8]);
}

#[test]
fn worker_errors_choose_lowest_position_and_failed_rows_release_no_commitment() {
    for workers in [1, 4] {
        let actual = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                (0..32)
                    .into_par_iter()
                    .map(|i| match i {
                        3 => Some((i, AggregateStarkErrorV1::NonCanonicalField)),
                        19 => Some((i, AggregateStarkErrorV1::InvalidLayout)),
                        _ => None,
                    })
                    .reduce(|| None, first_error_v1)
            });
        assert_eq!(actual, Some((3, AggregateStarkErrorV1::NonCanonicalField)));
        let catalog = context().catalog_v1();
        let domain = context()
            .domain_v1(&catalog, b"leaf", b"vector-row-leaf", 0, 0, 0)
            .unwrap();
        let prefix = PrivacyOuterDomainPrefixV1::new(domain).unwrap();
        let mut streams = (0..8)
            .map(|i| {
                let mut stream = prefix
                    .last_field_stream_at_with_counter(i, 0, &[], 8)
                    .unwrap();
                if i != 3 {
                    stream.update(&[17; 8]).unwrap();
                }
                stream
            })
            .collect::<Vec<_>>();
        let mut acc = accumulator(8, &[0]);
        let result = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| finish_rows_v1(&mut acc, &mut streams));
        assert!(result.is_err());
        assert_eq!(acc.next_leaf, 0);
        assert!(acc.finish().is_err());
    }
}

#[test]
fn parallel_partial_finalization_clears_tile_on_worker_error_and_worker_panic() {
    for workers in [1, 4] {
        for panic_at_row in [false, true] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap()
                .install(|| {
                    let catalog = context().catalog_v1();
                    let domain = context()
                        .domain_v1(&catalog, b"leaf", b"rows", 0, 0, 0)
                        .unwrap();
                    let prefix = PrivacyOuterDomainPrefixV1::new(domain).unwrap();
                    let mut streams = (0..32)
                        .map(|i| {
                            let mut stream = prefix
                                .last_field_stream_at_with_counter(i, 0, &[], 8)
                                .unwrap();
                            stream.update(&[i as u8; 8]).unwrap();
                            stream
                        })
                        .collect::<Vec<_>>();
                    let census = Census::begin();
                    let mut acc = accumulator(32, &[0, 31]);
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        finish_rows_with_v1(&mut acc, &mut streams, |row, stream| {
                            if row == 3 {
                                assert!(!panic_at_row, "synthetic finalization worker panic");
                                return Err(AggregateStarkErrorV1::NonCanonicalField);
                            }
                            stream
                                .finalize_in_place_v1()
                                .map_err(map_digest_stream_error_v1)
                                .map_err(map_transparent_error_v1)
                        })
                    }));
                    if panic_at_row {
                        assert!(outcome.is_err());
                    } else {
                        assert_eq!(
                            outcome.unwrap(),
                            Err(AggregateStarkErrorV1::NonCanonicalField)
                        );
                    }
                    assert_eq!(acc.next_leaf, 0);
                    assert!(acc.finish().is_err());
                    assert_eq!(census.finish(), vec![32]);
                });
        }
    }
}

#[test]
fn enlarged_row_state_and_prefix_capacities_are_rejected() {
    let mut owner = StreamingRowCommitmentV1::new(context(), b"leaf", NODE, 0, 8, 1, &[]).unwrap();
    owner.absorb_columns_v1(&[vec![F::ONE; 8]]).unwrap();
    owner.digest_streams.reserve(1);
    assert!(owner.digest_streams.capacity() > 8);
    assert_eq!(owner.finish(), Err(AggregateStarkErrorV1::InvalidLayout));
    let mut acc = accumulator(8, &[]);
    acc.node_prefixes.reserve(usize::BITS as usize + 1);
    assert!(acc.node_prefixes.capacity() > usize::BITS as usize);
    assert!(append_tile_v1(&mut acc, &mut leaves(8)).is_err());
    assert_eq!(acc.next_leaf, 0);
}

#[test]
fn bounded_workspace_shape_and_released_replay_reservation_are_explicit() {
    assert_eq!(TILE_ROWS, 4096);
    let bound = payload_bound_v1().unwrap();
    assert!(bound < 8 * 1024 * 1024);
    for rows in [1, 16, TILE_ROWS] {
        let tile = DigestTileV1::new(rows).unwrap();
        assert!(tile.0.capacity() <= TILE_ROWS);
        assert!(tile.0.capacity() * core::mem::size_of::<PrivacyOuterDigestV1>() < bound);
    }
    for rows in [0, 3, TILE_ROWS + 1] {
        assert!(DigestTileV1::new(rows).is_err());
    }
    // MAIN's unchanged eight native22 output columns alone exceed all tile
    // scratch; source, masks, coefficients and runtime remain separately funded.
    assert!(bound < 8 * (1usize << 22) * core::mem::size_of::<F>());
}

#[test]
#[ignore = "native22 byte-exact scalar/tree frontier and row-finalize stage diagnostic; run --release"]
fn native22_streamed_hash_prefix_and_tile_match_scalar_tree_with_stage_timings() {
    crate::test_support::require_no_debug_assertions("run with --release");
    const ROWS: usize = 1 << 22;
    const WIDTH: usize = 8;
    let columns = (0..WIDTH)
        .map(|c| {
            (0..ROWS)
                .map(|r| F((r * 31 + c * 17 + 3) as u64))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let query = [0, 1, TILE_ROWS - 1, TILE_ROWS, ROWS - 1];
    let started = std::time::Instant::now();
    let tree = row_tree_v1(context(), b"native22-tile-leaf", NODE, 2, &columns, ROWS).unwrap();
    eprintln!(
        "native22 scalar byte oracle seconds={:.6}",
        started.elapsed().as_secs_f64()
    );
    let expected = canonical_multiproof_frontier_v1(&tree, ROWS, &query).unwrap();
    for workers in [1, 4] {
        let (result, phases) = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                let started = std::time::Instant::now();
                let mut owner = StreamingRowCommitmentV1::new(
                    context(),
                    b"native22-tile-leaf",
                    NODE,
                    2,
                    ROWS,
                    WIDTH,
                    &query,
                )
                .unwrap();
                let initialized = started.elapsed();
                let started = std::time::Instant::now();
                owner.absorb_columns_v1(&columns).unwrap();
                let absorbed = started.elapsed();
                let started = std::time::Instant::now();
                let result = owner.finish().unwrap();
                let finalized = started.elapsed();
                (result, [initialized, absorbed, finalized])
            });
        assert_eq!(result.commitment.root, tree.root());
        assert_eq!(result.commitment.frontier, expected);
        for row in query {
            assert_eq!(
                result.opened_rows[&row],
                columns.iter().map(|c| c[row]).collect::<Vec<_>>()
            );
        }
        eprintln!(
            "native22 bounded hash phases: workers={workers}, rows={ROWS}, columns={WIDTH}, init={:?}, absorb={:?}, finalize={:?}; exact public synthetic component, no full-proof claim",
            phases[0], phases[1], phases[2]
        );
    }
}
