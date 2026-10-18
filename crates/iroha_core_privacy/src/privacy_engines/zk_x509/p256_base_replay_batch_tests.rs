//! Base-column parity across immutable phases and transactional replay custody.

use super::super::private_table::inspection;
use super::*;

#[test]
fn base_batch_projects_rows_and_clears_on_error_and_unwind() {
    for width in 1..=8 {
        let mut columns = vec![vec![F(97); 8]; width];
        let mut next = 0;
        let ((), observations) = inspection::observe_v1(|| {
            let mut targets = columns
                .iter_mut()
                .map(Vec::as_mut_slice)
                .collect::<Vec<_>>();
            fill_aggregate_base_columns_v1::<211>(8, 211 - width, &mut targets, |row| {
                assert_eq!(row, next);
                next += 1;
                Ok(core::array::from_fn(|column| {
                    F(1 + (row * 211 + column) as u64)
                }))
            })
            .unwrap();
        });
        assert_eq!(next, 8);
        for (offset, column) in columns.iter().enumerate() {
            for (row, value) in column.iter().enumerate() {
                assert_eq!(*value, F(1 + (row * 211 + 211 - width + offset) as u64));
            }
        }
        assert_eq!(
            observations.iter().filter(|item| item.cells == 211).count(),
            8
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    for unwind in [false, true] {
        let mut columns = vec![vec![F(97); 8]; 8];
        let (result, observations) = inspection::observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut targets = columns
                    .iter_mut()
                    .map(Vec::as_mut_slice)
                    .collect::<Vec<_>>();
                fill_aggregate_base_columns_v1::<34>(8, 26, &mut targets, |row| {
                    if row == 4 {
                        assert!(!unwind, "injected base row unwind");
                        return Err(P256AggregateAdapterErrorV1::Constraint);
                    }
                    Ok([F(83); 34])
                })
            }))
        });
        assert!(matches!(result, Ok(Err(_))) || (unwind && result.is_err()));
        assert!(columns.iter().flatten().all(|value| *value == F::ZERO));
        assert_eq!(
            observations.iter().filter(|item| item.cells == 8).count(),
            8
        );
        assert_eq!(
            observations.iter().filter(|item| item.cells == 34).count(),
            4
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn base_batch_rejects_shape_phase_and_unrelated_adapters() {
    let base = P256MainBaseSourceV1 {
        signatures: None,
        fixed: None,
        bind_attempted: true,
    };
    let bound = P256MainBoundSourceV1 {
        signatures: None,
        fixed: None,
        post_base: None,
        terminal_claims: None,
    };
    for (adapter, local) in [
        (P256MainAdapterV1::Arithmetic, 0),
        (P256MainAdapterV1::ValueBus, 0),
        (P256MainAdapterV1::ValueBus, 1),
    ] {
        let registration = P256MainRegistrationV1::new_v1(0, adapter, local).unwrap();
        let shape = registration.shape_v1().unwrap();
        for (count, first, len) in [
            (0, 0, 8),
            (9, 0, 8),
            (1, usize::MAX, 8),
            (1, shape.base_width, 8),
            (1, 0, 8),
        ] {
            let mut columns = vec![vec![F(97); len]; count];
            let mut targets = columns
                .iter_mut()
                .map(Vec::as_mut_slice)
                .collect::<Vec<_>>();
            assert_eq!(
                base.fill_base_columns_v1(registration, first, &mut targets),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            assert_eq!(
                bound.fill_base_columns_v1(registration, first, &mut targets),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            assert!(columns.iter().flatten().all(|value| *value == F(97)));
        }
        let mut column = zeroize::Zeroizing::new(vec![F(97); shape.trace_size]);
        assert_eq!(
            base.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Phase)
        );
        assert_eq!(
            bound.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Phase)
        );
        assert!(column.iter().all(|value| *value == F(97)));
    }
    for adapter in [
        P256MainAdapterV1::WindowBatch,
        P256MainAdapterV1::BindingSink,
        P256MainAdapterV1::ScalarBitBus,
    ] {
        let registration = P256MainRegistrationV1::new_v1(0, adapter, 0).unwrap();
        let mut column = vec![F(97); 8];
        assert_eq!(
            base.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(
            bound.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert!(column.iter().all(|value| *value == F(97)));
    }
    let scratch = p256_base_replay_scratch_v1();
    assert!(scratch >= core::mem::size_of::<P256AggregateAuxRowScratchV1<34>>());
    assert!(scratch <= P256MainBaseSourceV1::replay_scratch_forecast_v1().unwrap());
    assert!(scratch < super::super::allocation_payload::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1);
}

#[test]
#[ignore = "all five signatures and every full native base column before and after binding"]
fn base_batches_match_every_scalar_column_in_both_phases_and_reject_token_mutation() {
    let mut base = p256_main_base_source_fixture_for_test_v1().unwrap();
    let registrations = base
        .canonical_registrations_v1()
        .unwrap()
        .into_iter()
        .filter(|registration| {
            matches!(
                (registration.adapter_v1(), registration.local_instance_v1()),
                (P256MainAdapterV1::Arithmetic, 0) | (P256MainAdapterV1::ValueBus, 0 | 1)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(registrations.len(), 15);
    let check = |batch: &mut dyn FnMut(
        P256MainRegistrationV1,
        usize,
        &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1>,
                 scalar: &mut dyn FnMut(
        P256MainRegistrationV1,
        usize,
        &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1>| {
        let mut checked = 0;
        for &registration in &registrations {
            let shape = registration.shape_v1().unwrap();
            for first in (0..shape.base_width).step_by(8) {
                let count = (shape.base_width - first).min(8);
                let mut columns =
                    zeroize::Zeroizing::new(vec![vec![F(97); shape.trace_size]; count]);
                let mut targets = columns
                    .iter_mut()
                    .map(Vec::as_mut_slice)
                    .collect::<Vec<_>>();
                batch(registration, first, &mut targets).unwrap();
                drop(targets);
                for (offset, column) in columns.iter().enumerate() {
                    let mut single = zeroize::Zeroizing::new(vec![F(83); shape.trace_size]);
                    scalar(registration, first + offset, &mut single).unwrap();
                    assert_eq!(
                        column.as_slice(),
                        single.as_slice(),
                        "registration={registration:?}, column={}",
                        first + offset
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 5 * (211 + 2 * 34));
    };
    let retained = base.allocated_payload_bytes_v1();
    check(
        &mut |registration, first, columns| base.fill_base_columns_v1(registration, first, columns),
        &mut |registration, column, output| base.fill_base_column_v1(registration, column, output),
    );
    assert_eq!(base.allocated_payload_bytes_v1(), retained);
    let token = super::tests::main_post_base_v1(71);
    let mut bound = base.bind_v1(token).unwrap();
    assert!(base.private_is_zeroized_v1());
    let retained = bound.allocated_payload_bytes_v1();
    check(
        &mut |registration, first, columns| {
            bound.fill_base_columns_v1(registration, first, columns)
        },
        &mut |registration, column, output| bound.fill_base_column_v1(registration, column, output),
    );
    assert_eq!(bound.allocated_payload_bytes_v1(), retained);
    bound.post_base = Some(super::tests::main_post_base_v1(79));
    for registration in registrations {
        let mut column =
            zeroize::Zeroizing::new(vec![F(97); registration.shape_v1().unwrap().trace_size]);
        assert_eq!(
            bound.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Challenge)
        );
        assert_eq!(
            base.fill_base_columns_v1(registration, 0, &mut [&mut column]),
            Err(P256AggregateAdapterErrorV1::Phase)
        );
        assert!(column.iter().all(|value| *value == F(97)));
    }
    bound.post_base = Some(token);
}
