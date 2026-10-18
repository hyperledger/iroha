//! Exact event-graph layouts, physical refusal, sharing and original capacity provenance.

use super::*;
use crate::{
    smartcontracts::isi::sccp::test_support::blank_state,
    sumeragi::evidence::record::sccp_storage_claim_for_testing,
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_data_model::block::consensus::RecordedEvidenceV1;

fn record() -> Box<SccpForgeryRecordV1> {
    let RecordedEvidenceV1::SccpForgery(record) = sccp_storage_claim_for_testing().evidence else {
        panic!("SCCP fixture");
    };
    record
}
fn multisig_record() -> Box<SccpForgeryRecordV1> {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    let members = [Algorithm::Ed25519, Algorithm::BlsNormal]
        .into_iter()
        .map(|algorithm| {
            let key = KeyPair::from_seed(vec![0x42; 32], algorithm);
            MultisigMember::new(key.public_key().clone(), 1).unwrap()
        })
        .collect();
    let mut record = record();
    record.offenders[0].validator =
        AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    record
}
fn layouts(record: &SccpForgeryRecordV1) -> Vec<Layout> {
    let mut layouts = vec![
        Layout::array::<DataEvent>(1).unwrap(),
        Layout::array::<SccpForgeryOffenderV1>(record.offenders.len()).unwrap(),
    ];
    for offender in &record.offenders {
        offender
            .validator
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
    }
    layouts.push(Layout::array::<AllocationCharge>(layouts.len()).unwrap());
    layouts.push(ChargedShared::<Graph>::allocation_layout());
    layouts
}

#[test]
fn event_graph_retains_exact_original_layouts_through_publication_and_last_reader() {
    let state = blank_state();
    let view = state.view();
    let record = record();
    let budget = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let expected = layouts(&record);
    let exact: usize = expected.iter().map(Layout::size).sum();
    let mut graph = None;
    let allocations = allocations_during(|| {
        graph = Some(prepare_events(view.world(), [9; 32], 7, &record, 0, &budget).unwrap());
    });
    let graph = graph.unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        exact,
        "event graph retains the original pool"
    );
    assert_eq!(
        allocations,
        expected.iter().filter(|layout| layout.size() != 0).count(),
        "every preparation allocation has an exact retained layout"
    );
    let pointer = graph.as_slice().as_ptr();
    let DataEvent::Sccp(SccpEvent::ForgeryEvidenceRecorded(event)) = &graph.as_slice()[0] else {
        panic!("recorded event");
    };
    let offenders_pointer = event.offenders.as_ptr();
    let account_key_pointer = event.offenders[0]
        .validator
        .expect_single_signatory()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let mut reader = None;
    assert_eq!(
        allocations_during(|| {
            reader = graph.iter().next();
        }),
        0
    );
    let reader = reader.unwrap();
    assert!(reader.belongs_to(&budget));
    assert!(!reader.belongs_to(&foreign));
    assert!(SharedDataEvent::from_funded_batch(&graph.graph, 0, &foreign).is_none());
    assert!(SharedDataEvent::from_funded_batch(&graph.graph, 1, &budget).is_none());
    let wire = norito::to_bytes(&reader).unwrap();
    let transport = SharedDataEvent::from(reader.as_ref().clone());
    assert_eq!(wire, norito::to_bytes(&transport).unwrap());
    let decoded: SharedDataEvent = norito::decode_from_bytes(&wire).unwrap();
    assert_eq!(reader, decoded);
    assert!(!decoded.belongs_to(&budget));
    let last = reader.clone();
    drop(graph);
    drop(reader);
    assert_eq!(std::ptr::from_ref(last.as_ref()), pointer);
    let DataEvent::Sccp(SccpEvent::ForgeryEvidenceRecorded(event)) = last.as_ref() else {
        panic!("same recorded event");
    };
    assert_eq!(event.offenders.as_ptr(), offenders_pointer);
    assert_eq!(
        event.offenders[0]
            .validator
            .expect_single_signatory()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        account_key_pointer
    );
    assert_eq!(budget.reserved_bytes(), exact);
    drop(last);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn event_graph_refuses_every_physical_layout_without_capacity_wait() {
    let state = blank_state();
    let view = state.view();
    let budget = AllocationBudget::new(1 << 20);
    for record in [record(), multisig_record()] {
        for layout in layouts(&record) {
            let (result, refused) = refuse_one_layout_during(layout, || {
                prepare_events(view.world(), [9; 32], 7, &record, 0, &budget)
            });
            assert!(refused, "observe exact event allocation {layout:?}");
            let error = result
                .err()
                .expect("physical refusal must fail preparation");
            assert!(
                matches!(error, Error::Allocator { .. })
                    || matches!(&error, Error::DecodeResource(original)
                    if original.kind() == norito::core::DecodeLocalRefusalKind::Allocator),
                "physical failure must not fabricate capacity wait: {error:?}"
            );
            assert_eq!(
                budget.reserved_bytes(),
                0,
                "partial values retire before refund"
            );
            drop(prepare_events(view.world(), [9; 32], 7, &record, 0, &budget).unwrap());
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn event_graph_capacity_refusal_keeps_original_observation_and_unwind_reclaims() {
    let state = blank_state();
    let view = state.view();
    let record = record();
    let budget = AllocationBudget::new(1 << 20);
    let exact: usize = layouts(&record).iter().map(Layout::size).sum();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - exact + 1)
        .unwrap();
    let expected = budget.try_reserve_bytes(exact).unwrap_err();
    let error = prepare_events(view.world(), [9; 32], 7, &record, 0, &budget)
        .err()
        .unwrap();
    assert!(matches!(error, Error::Admission(actual) if actual == expected));
    let AllocationRefusal::Capacity { release, .. } = expected else {
        panic!("original occupied capacity");
    };
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let mut control = foreign
        .try_reserve(iroha_allocation::release::ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration =
        iroha_allocation::release::ReleaseRegistration::from_reservation(&mut control).unwrap();
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    drop(foreign.try_reserve_bytes(exact).unwrap());
    assert!(
        registration.poll_wait(&release, &mut context).is_pending(),
        "foreign refunds cannot wake the original event pool"
    );
    drop(blocker);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let graph = prepare_events(view.world(), [9; 32], 7, &record, 0, &budget).unwrap();
        let _reader = graph.iter().next().unwrap();
        panic!("retire the original event graph during unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn event_graph_partial_construction_unwind_retires_each_original_owner() {
    let state = blank_state();
    let view = state.view();
    let record = record();
    let budget = AllocationBudget::new(1 << 20);
    for checkpoint in 0..6 {
        UNWIND_AT.with(|selected| selected.set(Some(checkpoint)));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare_events(view.world(), [9; 32], 7, &record, 0, &budget)
        }));
        assert!(
            result.is_err(),
            "must reach construction point {checkpoint}"
        );
        assert_eq!(UNWIND_AT.with(std::cell::Cell::get), None);
        assert_eq!(budget.reserved_bytes(), 0, "original partial graph retires");
        drop(prepare_events(view.world(), [9; 32], 7, &record, 0, &budget).unwrap());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
