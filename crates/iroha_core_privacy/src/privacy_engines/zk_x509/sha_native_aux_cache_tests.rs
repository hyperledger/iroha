//! Allocation, projection, malformed-replay and physical erasure controls.

use super::*;
use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
use crate::privacy_engines::zk_x509::private_table::inspection;

fn row(index: usize) -> Row {
    core::array::from_fn(|column| F(u64::try_from(index * 79 + column + 1).unwrap()))
}

fn terminals(segment: usize) -> ZkX509ShaSegmentAirTerminalsV1 {
    let first = ZK_X509_SHA_PHYSICAL_CALL_COUNTS_V1[..segment]
        .iter()
        .sum::<usize>();
    let end = first + ZK_X509_SHA_PHYSICAL_CALL_COUNTS_V1[segment];
    ZkX509ShaSegmentAirTerminalsV1 {
        segment: ZkX509ShaSegmentPrivateEndpointV1 {
            segment: u8::try_from(segment).unwrap(),
            rfc_stream_products: [[F(7); 4]; 4],
        },
        ca_call_boundaries: ZK_X509_SHA_PHYSICAL_CALL_ORDER_V1[first..end]
            .iter()
            .filter(|call| usize::from(**call) >= ZK_X509_SHA_CA_LEAF_CALL_V1)
            .map(|call| ZkX509ShaCallBoundaryTerminalV1 {
                call: *call,
                role: manifest_role_v1(usize::from(*call)).unwrap(),
                source_start_products: [F(11); 4],
                digest_start_products: [F(13); 4],
                source_products: [F(17); 4],
                digest_products: [F(19); 4],
            })
            .collect(),
    }
}

fn cache(rows: usize, segment: usize) -> ShaNativeAuxCacheV1 {
    ShaNativeAuxCacheV1::build_v1(rows, segment, |visitor| {
        for index in 0..rows {
            visitor(index, row(index));
        }
        Ok(terminals(segment))
    })
    .unwrap()
}

#[test]
fn native_aux_cache_exact_forecast_and_all_column_batch_projections() {
    assert!(ShaNativeAuxCacheV1::heap_forecast_v1(0).is_err());
    assert!(ShaNativeAuxCacheV1::heap_forecast_v1(usize::MAX).is_err());
    let all = ZkX509ShaBatchSegmentAuxSourceV1::native_aux_cache_forecast_all_v1().unwrap();
    assert_eq!(
        all,
        1_308_622_848 + 4 * 13 * core::mem::size_of::<ZkX509ShaCallBoundaryTerminalV1>()
    );
    for segment in 0..4 {
        let cache = cache(9, segment);
        assert!(cache.heap_bytes_v1() <= ShaNativeAuxCacheV1::heap_forecast_v1(9).unwrap());
        assert_eq!(cache.copy_terminals_v1().unwrap(), terminals(segment));
        for width in [1, 3, 8] {
            for first in (0..78).step_by(width) {
                let count = width.min(78 - first);
                let mut columns = vec![vec![F(99); 9]; count];
                let mut targets = columns
                    .iter_mut()
                    .map(Vec::as_mut_slice)
                    .collect::<Vec<_>>();
                let mut fills = sha_column_fill_batch_v1(&mut targets).unwrap();
                cache.fill_columns_v1(first, &mut fills).unwrap();
                finish_sha_column_fill_batch_v1(fills).unwrap();
                for (offset, column) in columns.iter().enumerate() {
                    for (index, value) in column.iter().enumerate() {
                        assert_eq!(*value, row(index)[first + offset]);
                    }
                }
            }
        }
    }
}

#[test]
fn native_aux_cache_rejects_missing_extra_reordered_and_noncanonical_rows() {
    for indices in [vec![0, 1], vec![0, 1, 2, 3], vec![0, 2, 1], vec![0, 0, 2]] {
        assert!(
            ShaNativeAuxCacheV1::build_v1(3, 2, |visitor| {
                for index in indices {
                    visitor(index, row(index));
                }
                Ok(terminals(2))
            })
            .is_err()
        );
    }
    assert!(
        ShaNativeAuxCacheV1::build_v1(3, 4, |_| panic!("reject segment before replay")).is_err()
    );
    assert!(ShaNativeAuxCacheV1::build_v1(0, 2, |_| panic!("reject shape before replay")).is_err());
    assert!(
        ShaNativeAuxCacheV1::build_v1(3, 2, |visitor| {
            for index in 0..3 {
                let mut values = row(index);
                if index == 2 {
                    values[77] = F(GOLDILOCKS_MODULUS_V1);
                }
                visitor(index, values);
            }
            Ok(terminals(2))
        })
        .is_err()
    );
}

#[test]
fn native_aux_cache_rejects_wrong_missing_duplicate_and_mutated_terminals() {
    for mutation in 0..6 {
        assert!(
            ShaNativeAuxCacheV1::build_v1(3, 0, |visitor| {
                for index in 0..3 {
                    visitor(index, row(index));
                }
                let mut end = terminals(0);
                match mutation {
                    0 => end.segment.segment = 1,
                    1 => end.segment.rfc_stream_products[3][3] = F(GOLDILOCKS_MODULUS_V1),
                    2 => {
                        end.ca_call_boundaries.pop();
                    }
                    3 => end.ca_call_boundaries[1] = end.ca_call_boundaries[0],
                    4 => end.ca_call_boundaries[0].digest_products[3] = F(GOLDILOCKS_MODULUS_V1),
                    _ => end.ca_call_boundaries[0].role = manifest_role_v1(0).unwrap(),
                }
                Ok(end)
            })
            .is_err()
        );
    }
}

#[test]
fn native_aux_cache_late_invalid_column_clears_the_entire_batch() {
    let mut cache = cache(3, 2);
    cache.rows[2][77] = F(GOLDILOCKS_MODULUS_V1);
    let mut columns = vec![vec![F(99); 3]; 2];
    let mut targets = columns
        .iter_mut()
        .map(Vec::as_mut_slice)
        .collect::<Vec<_>>();
    let mut fills = sha_column_fill_batch_v1(&mut targets).unwrap();
    cache.fill_columns_v1(76, &mut fills).unwrap();
    assert!(finish_sha_column_fill_batch_v1(fills).is_err());
    assert!(columns.iter().flatten().all(|value| *value == F::ZERO));
    for (first, count, rows) in [
        (78, 1, 3),
        (77, 2, 3),
        (usize::MAX, 1, 3),
        (0, 9, 3),
        (0, 1, 2),
    ] {
        let mut columns = vec![vec![F(99); rows]; count];
        let mut targets = columns
            .iter_mut()
            .map(Vec::as_mut_slice)
            .collect::<Vec<_>>();
        let mut fills = sha_column_fill_batch_v1(&mut targets).unwrap();
        assert!(cache.fill_columns_v1(first, &mut fills).is_err());
        drop(fills);
        assert!(columns.iter().flatten().all(|value| *value == F::ZERO));
    }
}

#[test]
fn native_aux_cache_clears_full_rows_and_terminals_on_drop_error_and_unwind() {
    for mode in 0..3 {
        let ((), observations) = inspection::observe_v1(|| {
            if mode == 0 {
                let cache = cache(3, 0);
                let copy = cache.copy_terminals_v1().unwrap();
                drop(cache);
                assert_eq!(copy, terminals(0));
                drop(copy);
            } else {
                let result = std::panic::catch_unwind(|| {
                    ShaNativeAuxCacheV1::build_v1(3, 0, |visitor| {
                        visitor(0, row(0));
                        if mode == 2 {
                            panic!("exercise private cache unwind");
                        }
                        Err(Error::Resource)
                    })
                });
                if mode == 1 {
                    assert!(result.unwrap().is_err());
                } else {
                    assert!(result.is_err());
                }
            }
        });
        assert!(
            observations
                .iter()
                .any(|item| item.cells == 3 * 78 && item.nonzero_before > 0)
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
        if mode == 0 {
            assert!(
                observations
                    .iter()
                    .any(|item| item.cells == 16 && item.nonzero_before == 16)
            );
        }
    }
}
