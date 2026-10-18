//! Live-cell observations for semantic, serial and temporary RFC owners.

use super::*;
use crate::privacy_engines::zk_x509::private_table::inspection::{
    ErasureObservationV1, observe_v1,
};

fn assert_cleared(observations: &[ErasureObservationV1], minimum_cells: usize) {
    assert!(observations.iter().map(|row| row.cells).sum::<usize>() >= minimum_cells);
    assert!(observations.iter().any(|row| row.nonzero_before > 0));
    assert!(observations.iter().all(|row| row.nonzero_after == 0));
}

#[test]
fn semantic_growth_preserves_values_and_clears_displaced_cells() {
    let mut cells = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    cells.try_reserve_exact(1).unwrap();
    cells.push(ZkX509Rfc5280SourceCellV1 {
        document: 3,
        address: 17,
        value: 0xab,
    });
    let original = cells[0];
    let ((), observations) = observe_v1(|| {
        let capacity = cells.capacity();
        reserve_private_semantic_v1(&mut cells, capacity + 1, zeroize_source_cells_v1).unwrap();
        assert_eq!(cells.as_slice(), &[original]);
        assert!(cells.capacity() >= capacity + 2);
    });
    assert_cleared(&observations, 3);
    let capacity = cells.capacity();
    assert_eq!(
        reserve_private_semantic_v1(&mut cells, usize::MAX, zeroize_source_cells_v1),
        Err(ZkX509Rfc5280StarkErrorV1::Resource)
    );
    assert_eq!(cells.capacity(), capacity);
    assert_eq!(cells.as_slice(), &[original]);
}

#[test]
fn document_and_time_buffers_clear_after_partial_and_semantic_errors() {
    let mut trace = super::super::tests::canonical_trace_v1();
    let last = trace.documents[0].bytes.last_mut().unwrap();
    last.value.value = F(256);
    let (result, observations) = observe_v1(|| document_bytes_v1(&trace, 0));
    assert!(matches!(result, Err(ZkX509Rfc5280StarkErrorV1::Source)));
    assert_cleared(&observations, trace.documents[0].bytes.len() - 1);

    let cells: Vec<_> = b"260932120000Z"
        .iter()
        .enumerate()
        .map(|(offset, &value)| ZkX509Rfc5280SourceCellV1 {
            document: 1,
            address: offset as u16,
            value,
        })
        .collect();
    let (result, observations) = observe_v1(|| parse_time_cells_v1(&cells, 23));
    assert!(matches!(result, Err(ZkX509Rfc5280StarkErrorV1::Semantic)));
    assert_cleared(&observations, cells.len());
    let (result, observations) = observe_v1(|| {
        std::panic::catch_unwind(|| {
            let mut valid = cells.clone();
            valid[4].value = b'2';
            valid[5].value = b'8';
            let (_timestamp, _decimal) = parse_time_cells_v1(&valid, 23).unwrap();
            panic!("injected after decimal ownership transfer");
        })
    });
    assert!(result.is_err());
    assert_cleared(&observations, cells.len() + 12 * 3);
}

#[test]
fn semantic_owner_clears_late_failure_success_and_unwind() {
    let mut trace = super::super::tests::canonical_trace_v1();
    let original = build_zk_x509_rfc5280_semantic_witness_v1(&trace).unwrap();
    assert_eq!(
        format!("{original:?}"),
        "ZkX509Rfc5280SemanticWitnessV1 { <private material redacted> }"
    );
    let minimum = original.fixed_bytes.len() * 3
        + original.equal_bytes.len() * 6
        + original.decimal_cells.len() * 3
        + original.calendar_values.len();
    for unwind in [false, true] {
        let owned = original.clone();
        let (result, observations) = observe_v1(|| {
            std::panic::catch_unwind(move || {
                let _owned = owned;
                if unwind {
                    panic!("injected with complete semantic owner");
                }
            })
        });
        assert_eq!(result.is_err(), unwind);
        assert_cleared(&observations, minimum);
    }
    trace.statement.presentation_not_after_unix_seconds = trace.certificates[0].not_after + 1;
    let (result, observations) = observe_v1(|| build_zk_x509_rfc5280_semantic_witness_v1(&trace));
    assert!(matches!(result, Err(ZkX509Rfc5280StarkErrorV1::Semantic)));
    assert_cleared(&observations, 100);
}

#[test]
fn serial_precursors_and_numeric_outputs_keep_clearing_ownership() {
    let (result, observations) =
        observe_v1(|| canonical_serial_comparisons_v1(&[2], &[vec![1], vec![1]]));
    assert!(matches!(result, Err(ZkX509Rfc5280StarkErrorV1::Semantic)));
    assert_cleared(&observations, 2 * SERIAL_COMPARISON_WIDTH_V1);
    let source = super::super::tests::serial_source_fixture_v1(0, &[0xff]);
    assert_eq!(
        format!("{source:?}"),
        "ZkX509Rfc5280SerialSourceV1 { <private material redacted> }"
    );
    let ((), observations) = observe_v1(|| {
        let rows = build_zk_x509_rfc5280_serial_source_rows_v1(&source).unwrap();
        assert_eq!(rows.len(), SERIAL_COMPARISON_WIDTH_V1);
        let (bytes, nodes) =
            zk_x509_rfc5280_serial_lookup_multiplicities_v1(core::slice::from_ref(&source))
                .unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(nodes.len(), 1);
        drop((rows, bytes, nodes));
    });
    assert_cleared(
        &observations,
        SERIAL_COMPARISON_WIDTH_V1 * ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
    );
    let owned = source.clone();
    let (result, observations) = observe_v1(|| {
        std::panic::catch_unwind(move || {
            let _owned = owned;
            panic!("injected with serial source owner");
        })
    });
    assert!(result.is_err());
    assert_cleared(&observations, SERIAL_COMPARISON_WIDTH_V1 + 6);
}
