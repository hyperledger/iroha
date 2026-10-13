//! Actual trigger inventory reads survive late original-writer refusal and retry.

use super::*;
use mv::PublicationPreparationError;

fn assert_changed_reads(read: &impl SetReadOnly) {
    assert_eq!(
        read.data_triggers().get(&id("data")).unwrap().repeats,
        Repeats::Exactly(0)
    );
    assert!(read.pipeline_triggers().is_empty());
    assert_eq!(
        read.time_triggers().get(&id("time")).unwrap().repeats,
        Repeats::Exactly(7)
    );
    assert_eq!(read.by_call_triggers().len(), 3);
    assert!(read.by_call_triggers().get(&id("call_c")).is_some());
    assert_eq!(read.ids().len(), 5);
    assert!(read.ids().get(&id("pipeline")).is_none());
    assert!(read.active_data_trigger_ids().is_empty());
    assert!(read.active_pipeline_trigger_ids().is_empty());
    assert_eq!(read.active_time_trigger_ids().len(), 1);
    assert_eq!(read.active_by_call_trigger_ids().len(), 3);
    assert_eq!(read.contracts().len(), 1);
    assert_eq!(
        read.contracts()
            .get(&HashOf::new(&blob()))
            .unwrap()
            .count
            .get(),
        3
    );
    // Exercise existing semantic validation on the retained inventory, rather
    // than a fresh Set view or a reconstructed set of trigger rows.
    read.validate_world_contract_rows().unwrap();
}

#[test]
fn frozen_trigger_read_trait_preserves_all_ten_originals_through_late_busy_retry() {
    let target = seeded_set();
    let before = images(&target);
    let mut block = target.block();
    mutate_all(&mut block);
    let data_pointer = std::ptr::from_ref(block.data_triggers.get(&id("data")).unwrap());
    let original = capture(block);
    let identity = original.data_triggers().publication_identity();
    assert_all_writers_released(&target);
    {
        let every_writer = target.block();
        assert_changed_reads(&original);
        assert_eq!(
            std::ptr::from_ref(original.data_triggers().get(&id("data")).unwrap()),
            data_pointer
        );
        drop(every_writer);
    }
    let busy = target.contracts.block();
    let mut slot = original.publication_slot(&target);
    assert!(matches!(
        slot.try_prepare(|_, _| Ok::<_, ()>(())),
        Err(SetPublicationError::Component {
            field: "contracts",
            cause: PublicationPreparationError::Busy(_)
        })
    ));
    let original = slot.recover_original();
    assert_changed_reads(&original);
    assert_eq!(original.data_triggers().publication_identity(), identity);
    assert_eq!(
        std::ptr::from_ref(original.data_triggers().get(&id("data")).unwrap()),
        data_pointer
    );
    let cleanup = slot.into_cleanup();
    drop(busy);
    assert_all_writers_released(&target);
    drop(cleanup);
    assert_eq!(
        images(&target),
        before,
        "frozen reads and refusal do not publish"
    );
    let mut retry = original.publication_slot(&target);
    retry
        .try_prepare(|original, _| {
            assert_changed_reads(original);
            Ok::<_, ()>(())
        })
        .unwrap();
    drop(retry.into_prepared().publish());
    assert_all_writers_released(&target);
    assert_changed_reads(&target.view());
    assert_eq!(
        std::ptr::from_ref(target.view().data_triggers().get(&id("data")).unwrap()),
        data_pointer
    );
}

#[test]
fn frozen_trigger_readable_equal_sources_cannot_replace_original_authority() {
    let target = seeded_set();
    let foreign = seeded_set();
    let mut block = target.block();
    mutate_all(&mut block);
    let original = capture(block);
    let identity = original.ids().publication_identity();
    let (original, refusal, cleanup) = original
        .try_prepare_publication(&foreign, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("equal foreign trigger source refused");
    assert!(matches!(
        refusal,
        SetPublicationError::Component {
            cause: PublicationPreparationError::Changed,
            ..
        }
    ));
    drop(cleanup);
    assert_changed_reads(&original);
    // Rotate original current/undo generations without changing current rows.
    target.block().commit();
    let (original, refusal, cleanup) = original
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("unchanged values cannot repair stale original generation");
    assert!(matches!(
        refusal,
        SetPublicationError::Component {
            cause: PublicationPreparationError::Changed,
            ..
        }
    ));
    drop(cleanup);
    assert_changed_reads(&original);
    assert_eq!(original.ids().publication_identity(), identity);
    assert_all_writers_released(&target);
    assert_all_writers_released(&foreign);
}

#[test]
fn frozen_trigger_replacement_reads_its_original_cut_after_target_is_gone() {
    fn assert_replacement(read: &impl SetReadOnly) {
        assert!(read.data_triggers().is_empty());
        assert!(read.pipeline_triggers().is_empty());
        assert!(read.time_triggers().is_empty());
        assert_eq!(read.by_call_triggers().len(), 1);
        assert!(read.by_call_triggers().get(&id("replacement")).is_some());
        assert_eq!(read.ids().len(), 1);
        assert!(read.active_data_trigger_ids().is_empty());
        assert!(read.active_pipeline_trigger_ids().is_empty());
        assert!(read.active_time_trigger_ids().is_empty());
        assert_eq!(read.active_by_call_trigger_ids().len(), 1);
        assert_eq!(
            read.contracts()
                .get(&HashOf::new(&blob()))
                .unwrap()
                .count
                .get(),
            1
        );
        read.validate_world_contract_rows().unwrap();
    }
    let original = {
        let target = seeded_set();
        let mut block = target.block_and_revert();
        let mut transaction = block.transaction();
        register_call(&mut transaction, "replacement");
        transaction.apply();
        let original = capture(block);
        assert_all_writers_released(&target);
        original
    };
    assert_eq!(original.mode(), mv::BlockMode::Replace);
    assert_replacement(&original);
}
