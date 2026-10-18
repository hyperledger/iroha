//! Immutable P-256 arithmetic ownership, rejection, erasure, and replay controls.

use super::super::{
    p256_air::{
        ZkX509P256ArithmeticKindV1, ZkX509P256ArithmeticOperationV1, ZkX509P256ModulusV1,
        build_zk_x509_p256_arithmetic_trace_v1,
    },
    private_table::inspection,
};
use super::*;

std::thread_local! {
    static CHECKED_CONSTRUCTORS_V1: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

pub(super) fn record_checked_constructor_v1() {
    CHECKED_CONSTRUCTORS_V1.with(|count| count.set(count.get() + 1));
}

fn checked_constructors_v1() -> usize {
    CHECKED_CONSTRUCTORS_V1.with(core::cell::Cell::get)
}

fn small_trace_v1() -> ZkX509P256ArithmeticTraceV1 {
    let integer = |value: u8| {
        let mut bytes = [0; 32];
        bytes[31] = value;
        bytes
    };
    build_zk_x509_p256_arithmetic_trace_v1(&[ZkX509P256ArithmeticOperationV1 {
        kind: ZkX509P256ArithmeticKindV1::Add,
        modulus: ZkX509P256ModulusV1::BaseField,
        a: integer(3),
        b: integer(5),
        c: integer(8),
    }])
    .unwrap()
}

#[test]
fn validated_arithmetic_owner_rejects_invalid_constraints_and_clears_input() {
    let mut trace = small_trace_v1();
    trace.base[0][0] = F::canonical(4).expect("canonical wrong A limb");
    assert!(trace.validate().is_err());
    assert!(
        P256ArithmeticAggregateRowsV1::new_v1(P256EcdsaRoleV1::CertificateOrCrl, &trace,).is_err()
    );
    let (result, observations) = inspection::observe_v1(|| {
        P256MainValidatedArithmeticV1::new_v1(P256EcdsaRoleV1::CertificateOrCrl, trace)
    });
    assert!(result.is_err());
    assert!(observations.iter().any(|item| item.nonzero_before > 0));
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn validated_arithmetic_owner_rejects_valid_but_wrong_topology_and_clears_input() {
    for role in [
        P256EcdsaRoleV1::CertificateOrCrl,
        P256EcdsaRoleV1::WalletOwnership,
    ] {
        let trace = small_trace_v1();
        trace.validate().unwrap();
        assert!(matches!(
            P256ArithmeticAggregateRowsV1::new_v1(role, &trace),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        let (result, observations) =
            inspection::observe_v1(|| P256MainValidatedArithmeticV1::new_v1(role, trace));
        assert!(matches!(result, Err(P256AggregateAdapterErrorV1::Topology)));
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn validated_arithmetic_constructor_guard_clears_input_during_unwind() {
    let trace = small_trace_v1();
    let ((), observations) = inspection::observe_v1(|| {
        assert!(
            std::panic::catch_unwind(move || {
                // This is the constructor's first operation, before all fallible
                // constraint, topology, and provider work.
                let guard = P256MainArithmeticGuardV1(Some(trace));
                assert!(
                    guard
                        .as_ref_v1()
                        .unwrap()
                        .base
                        .iter()
                        .flatten()
                        .any(|v| *v != F::ZERO)
                );
                panic!("exercise arithmetic constructor guard unwind");
            })
            .is_err()
        );
    });
    assert!(observations.iter().any(|item| item.nonzero_before > 0));
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
}

#[test]
#[ignore = "full canonical arithmetic allocation and every base/auxiliary cell; run in optimized qualification"]
fn validated_arithmetic_owner_matches_checked_rows_and_aux_without_revalidation() {
    let role = P256EcdsaRoleV1::WalletOwnership;
    let material = super::super::p256_trace::compile_p256_ecdsa_trace_material_v1(
        role,
        p256_main_signed_witness_for_test_v1(113).unwrap(),
    )
    .unwrap();
    let trace = material.build_arithmetic_trace_v1().unwrap();
    drop(material);
    // Retain a separately clearing original matrix as the independent native oracle.
    let oracle = P256MainArithmeticGuardV1(Some(trace.clone()));
    let before = checked_constructors_v1();
    let owner = P256MainValidatedArithmeticV1::new_v1(role, trace).unwrap();
    assert_eq!(checked_constructors_v1(), before + 1);
    assert!(matches!(
        owner.rows_v1(P256EcdsaRoleV1::CertificateOrCrl),
        Err(P256AggregateAdapterErrorV1::Topology)
    ));
    let mut owner_slot = Some(owner);
    let owner = owner_slot.take().unwrap(); // same ownership move used by bind
    assert!(owner_slot.is_none());
    let rows = owner.rows_v1(role).unwrap();
    assert!(
        matches!(&rows.fixed, Cow::Borrowed(fixed) if core::ptr::eq(*fixed, &raw const owner.fixed))
    );
    let checked = P256ArithmeticAggregateRowsV1::new_v1(role, oracle.as_ref_v1().unwrap()).unwrap();
    assert_eq!(checked_constructors_v1(), before + 2);
    for row in 0..P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
        assert_eq!(
            rows.base_row_v1(row).unwrap(),
            checked.base_row_v1(row).unwrap()
        );
        assert_eq!(
            rows.fixed.row_v1(row).unwrap(),
            checked.fixed.row_v1(row).unwrap()
        );
    }
    let mut column = vec![F(97); P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1];
    for index in 0..P256_ARITHMETIC_BASE_WIDTH_V1 {
        rows.fill_base_column_v1(index, &mut column).unwrap();
        for (row, value) in column.iter().enumerate() {
            assert_eq!(
                *value,
                oracle
                    .as_ref_v1()
                    .unwrap()
                    .base
                    .get(row)
                    .map_or(F::ZERO, |cells| cells[index])
            );
        }
    }
    for first in (0..P256_ARITHMETIC_BASE_WIDTH_V1).step_by(8) {
        let width = 8.min(P256_ARITHMETIC_BASE_WIDTH_V1 - first);
        let mut columns = vec![vec![F(101); P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1]; width];
        rows.fill_base_columns_v1(
            first,
            &mut columns
                .iter_mut()
                .map(Vec::as_mut_slice)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for (offset, column) in columns.iter().enumerate() {
            for (row, value) in column.iter().enumerate() {
                assert_eq!(
                    *value,
                    oracle
                        .as_ref_v1()
                        .unwrap()
                        .base
                        .get(row)
                        .map_or(F::ZERO, |cells| cells[first + offset])
                );
            }
        }
        columns
            .iter_mut()
            .for_each(|column| super::super::private_table::zeroize_fields_v1(column));
    }
    assert_eq!(checked_constructors_v1(), before + 2);
    let post_base = super::tests::main_post_base_v1(71);
    assert!(matches!(
        P256ArithmeticAggregateAuxStreamV1::from_validated_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            &owner,
            post_base.p256_scalar(),
            post_base.p256_arithmetic_copy(),
        ),
        Err(P256AggregateAdapterErrorV1::Topology)
    ));
    let mut raw_aux = P256ArithmeticAggregateAuxStreamV1::new_v1(
        role,
        oracle.as_ref_v1().unwrap(),
        post_base.p256_scalar(),
        post_base.p256_arithmetic_copy(),
    )
    .unwrap();
    let mut owner_aux = P256ArithmeticAggregateAuxStreamV1::from_validated_v1(
        role,
        &owner,
        post_base.p256_scalar(),
        post_base.p256_arithmetic_copy(),
    )
    .unwrap();
    assert_eq!(checked_constructors_v1(), before + 3);
    assert_eq!(raw_aux.terminal_v1(), owner_aux.terminal_v1());
    assert_eq!(
        raw_aux.arithmetic_copy_terminal_v1(),
        owner_aux.arithmetic_copy_terminal_v1()
    );
    for _ in 0..P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
        assert_eq!(
            raw_aux.next_aux_row_v1().unwrap(),
            owner_aux.next_aux_row_v1().unwrap()
        );
    }
    assert_eq!(raw_aux.next_aux_row_v1().unwrap(), None);
    assert_eq!(owner_aux.next_aux_row_v1().unwrap(), None);
    assert_eq!(checked_constructors_v1(), before + 3);
    let mut bad = post_base.p256_scalar();
    bad.lanes[0].terms[0] = F::ZERO;
    assert!(matches!(
        P256ArithmeticAggregateAuxStreamV1::new_v1(
            role,
            oracle.as_ref_v1().unwrap(),
            bad,
            post_base.p256_arithmetic_copy()
        ),
        Err(P256AggregateAdapterErrorV1::Challenge)
    ));
    assert!(matches!(
        P256ArithmeticAggregateAuxStreamV1::from_validated_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            &owner,
            bad,
            post_base.p256_arithmetic_copy()
        ),
        Err(P256AggregateAdapterErrorV1::Challenge)
    ));
    assert_eq!(checked_constructors_v1(), before + 3);
    drop((raw_aux, owner_aux, rows, checked));
    let expected = super::super::allocation_payload::sum_v1([
        P256CompactArithmeticTraceV1::payload_forecast_v1(P256_ARITHMETIC_OPERATIONS_V1).unwrap(),
        owner.fixed.allocated_heap_bytes_v1(),
    ]);
    assert_eq!(owner.allocated_heap_bytes_v1(), expected);
    let ((), observations) = inspection::observe_v1(|| {
        assert!(
            std::panic::catch_unwind(move || {
                let _owner = owner;
                panic!("exercise validated owner unwind");
            })
            .is_err()
        );
    });
    assert!(observations.iter().any(|item| item.nonzero_before > 0));
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
}
