//! Retained-versus-replayed FRI parity, capacity admission and live-cell erasure.

use super::*;
use crate::privacy_engines::zk_x509::private_table::inspection;
use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};

#[test]
fn retained_fri_copy_fits_original_allowance_and_rejects_capacity_overflow() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let rows = layout.common_lde_size();
    let column = rows * core::mem::size_of::<E>();
    let owner = core::mem::size_of::<Vec<E>>();
    let original = column + owner;
    let mask = column + core::mem::size_of::<aggregate::AggregateFriMaskOracleMaterialV1>();
    let expected = original + mask + column + column / 2 + 2 * owner;
    assert_eq!(
        plan.check_retained_fri_copy_v1(&layout, original, mask, rows)
            .unwrap(),
        expected
    );
    assert!(expected < 4 * column);
    assert_eq!(
        plan.fri_stage,
        main_resources::MainProverBufferPlanV1::new_v1(&layout)
            .unwrap()
            .fri_stage
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original, mask, rows - 1)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original, mask, rows * 2)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original + column, mask, rows)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original, mask + column, rows)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, usize::MAX, mask, rows)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original, usize::MAX, rows)
            .is_err()
    );
    assert!(
        plan.check_retained_fri_copy_v1(&layout, original, mask, usize::MAX)
            .is_err()
    );
}

#[test]
fn retained_fri_owners_clear_original_and_copy_on_success_error_and_unwind() {
    for outcome in 0..3 {
        let (result, records) = inspection::observe_v1(|| {
            std::panic::catch_unwind(|| -> Result<(), ZkX509StarkErrorV1> {
                let mut retained = MainRetainedFriInputsV1::new_v1(vec![vec![E::ONE; 16]], 16)?;
                let copy = retained.copy_lane_v1(0, |_| Ok(()))?;
                assert_eq!(&*copy, &[E::ONE; 16]);
                let original = retained.take_lane_v1(0)?;
                assert_eq!(&*original, &*copy);
                assert!(retained.copy_lane_v1(0, |_| Ok(())).is_err());
                assert!(retained.take_lane_v1(0).is_err());
                match outcome {
                    0 => Ok(()),
                    1 => Err(ZkX509StarkErrorV1::TranscriptMismatch),
                    _ => panic!("synthetic retained FRI unwind"),
                }
            })
        });
        assert_eq!(result.is_err(), outcome == 2);
        if let Ok(inner) = result {
            assert_eq!(inner.is_err(), outcome == 1);
        }
        assert_eq!(records.iter().map(|row| row.cells).sum::<usize>(), 32);
        assert_eq!(
            records.iter().map(|row| row.nonzero_before).sum::<usize>(),
            32
        );
        assert!(records.iter().all(|row| row.nonzero_after == 0));
    }
}

#[test]
fn retained_fri_rejects_shapes_and_copy_admission_without_losing_original() {
    for (width, rows, actual_rows) in [
        (0, 16, 16),
        (2, 16, 16),
        (1, 0, 16),
        (1, 15, 16),
        (1, 16, 15),
    ] {
        let (result, records) = inspection::observe_v1(|| {
            MainRetainedFriInputsV1::new_v1(vec![vec![E::ONE; actual_rows]; width], rows)
        });
        assert!(result.is_err());
        assert_eq!(
            records.iter().map(|row| row.nonzero_before).sum::<usize>(),
            width * actual_rows
        );
        assert!(records.iter().all(|row| row.nonzero_after == 0));
    }
    let mut values = Vec::with_capacity(32);
    values.resize(16, E::ONE);
    let capacity = values.capacity();
    let mut retained = MainRetainedFriInputsV1::new_v1(vec![values], 16).unwrap();
    assert_eq!(
        retained.allocated_payload_bytes_v1().unwrap(),
        capacity * core::mem::size_of::<E>() + core::mem::size_of::<Vec<E>>()
    );
    let mut calls = 0;
    assert!(
        retained
            .copy_lane_v1(1, |_| {
                calls += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls, 0);
    for fail_at in 1..=2 {
        let mut calls = 0;
        assert!(
            retained
                .copy_lane_v1(0, |_| {
                    calls += 1;
                    if calls == fail_at {
                        Err(ZkX509StarkErrorV1::ProofTooLarge)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(calls, fail_at);
    }
    assert_eq!(&*retained.take_lane_v1(0).unwrap(), &[E::ONE; 16]);
}

#[test]
#[allow(clippy::too_many_lines)]
fn retained_fri_seeded_input_matches_two_replays_roots_transcript_and_openings() {
    for commitment in [
        aggregate::AggregateFriCommitmentLayoutV1::Scalar,
        aggregate::AggregateFriCommitmentLayoutV1::Paired,
    ] {
        let parameters = aggregate::AggregateStarkParametersV1 {
            fri_commitment_layout: commitment,
            minimum_trace_log2: 8,
            maximum_trace_log2: 8,
            terminal_log2: 3,
            terminal_degree_bound: 3,
            ..AGGREGATE_PARAMETERS_V1
        };
        let layout = aggregate::AggregateProofLayoutV1::new(
            parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            }],
        )
        .unwrap();
        let rows = layout.common_lde_size();
        let root = goldilocks_primitive_root_v1(layout.common_lde_log2()).unwrap();
        let evaluations = || {
            let mut rng = StdRng::from_seed([73; 32]);
            let coefficients = (0..17)
                .map(|_| {
                    E::from_coefficients([
                        F(rng.next_u64() % 97),
                        F(rng.next_u64() % 97),
                        F(rng.next_u64() % 97),
                        F(rng.next_u64() % 97),
                    ])
                    .unwrap()
                })
                .collect::<Vec<_>>();
            goldilocks_fp4_evaluate_coset_v1(&coefficients, rows, root, F(GOLDILOCKS_GENERATOR_V1))
                .unwrap()
        };
        let masks = aggregate::build_fri_mask_oracles_v1(
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
            &mut StdRng::from_seed([79; 32]),
        )
        .unwrap();
        assert_eq!(
            mask_evaluation_payload_v1(&masks).unwrap(),
            masks.capacity() * core::mem::size_of::<aggregate::AggregateFriMaskOracleMaterialV1>()
                + masks[0].evaluations.capacity() * core::mem::size_of::<E>()
        );
        assert!(mask_evaluation_payload_v1(&Vec::new()).is_err());
        let mut old_calls = 0;
        let mut replay = || {
            old_calls += 1;
            let mut values = evaluations();
            aggregate::add_fri_mask_oracle_v1(&mut values, &masks[0]).unwrap();
            values
        };
        let mut new_calls = 0;
        let mut retained = MainRetainedFriInputsV1::new_v1(
            {
                new_calls += 1;
                vec![evaluations()]
            },
            rows,
        )
        .unwrap();
        aggregate::add_fri_mask_oracle_v1(retained.lanes_mut_v1().next().unwrap(), &masks[0])
            .unwrap();
        let transcript = || {
            TransparentTranscriptV1::new(
                AGGREGATE_DOMAINS_V1.digest_context,
                b"x509-retained-fri-input-test",
                &PrivacyOuterDigestV1::from_bytes([11; 48]),
                &PrivacyOuterDigestV1::from_bytes([19; 48]),
            )
            .unwrap()
        };
        let mut old_transcript = transcript();
        let mut new_transcript = transcript();
        let old_material = aggregate::build_streaming_fri_lane_v1(
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
            0,
            replay(),
            &mut old_transcript,
        )
        .unwrap();
        let mut copy = retained
            .copy_lane_v1(0, |capacity| {
                assert!(capacity <= rows);
                Ok(())
            })
            .unwrap();
        let new_material = aggregate::build_streaming_fri_lane_v1(
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
            0,
            core::mem::take(&mut copy.0),
            &mut new_transcript,
        )
        .unwrap();
        assert_eq!(new_material, old_material);
        assert_eq!(new_transcript.state(), old_transcript.state());
        let old_indices = aggregate::query_indices_v1(
            &old_transcript,
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
        )
        .unwrap();
        let new_indices = aggregate::query_indices_v1(
            &new_transcript,
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
        )
        .unwrap();
        assert_eq!(new_indices, old_indices);
        let old_openings = aggregate::open_streaming_fri_lane_v1(
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
            0,
            replay(),
            &old_material,
            &old_indices,
        )
        .unwrap();
        let mut original = retained.take_lane_v1(0).unwrap();
        let new_openings = aggregate::open_streaming_fri_lane_v1(
            parameters,
            &AGGREGATE_DOMAINS_V1,
            &layout,
            0,
            core::mem::take(&mut original.0),
            &new_material,
            &new_indices,
        )
        .unwrap();
        assert_eq!(new_openings, old_openings);
        assert_eq!(old_calls, 2);
        assert_eq!(new_calls, 1);
    }
}
