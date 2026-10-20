// The Changes-only membership route is bounded, paired and tied to its original base.

type MembershipByteTables = BTreeMap<&'static str, BTreeMap<Vec<u8>, Vec<u8>>>;

fn committed_membership_bytes(state: &State) -> MembershipByteTables {
    use crate::state::storage_transactions::authority::TransactionMembershipSide;
    let owner = state.transactions.block();
    let source = owner.membership_authority_cut(usize::MAX).unwrap();
    let frontier = source.frontier_height();
    let mut result = BTreeMap::from([
        ("state.transactions.current", BTreeMap::new()),
        ("state.transactions.rollback", BTreeMap::new()),
        (
            "state.transactions.frontier",
            BTreeMap::from([(vec![], norito::codec::encode_adaptive(&frontier))]),
        ),
    ]);
    source
        .visit(|side, key, height| {
            let id = if side == TransactionMembershipSide::Current {
                "state.transactions.current"
            } else {
                "state.transactions.rollback"
            };
            result.get_mut(id).unwrap().insert(
                norito::codec::encode_adaptive(key),
                norito::codec::encode_adaptive(&height),
            );
            Ok::<_, ()>(())
        })
        .unwrap();
    result
}

fn replay_membership_field(tables: &mut MembershipByteTables, field: &FieldBytes) {
    let map = tables.get_mut(field.id).unwrap();
    assert!(
        !field.replacement,
        "paired delta must not clear a baseline table"
    );
    for before in field.undo.as_slice() {
        let key = before.key.bytes();
        assert_eq!(
            map.get(key).map(Vec::as_slice),
            before.value.as_ref().map(Frame::bytes)
        );
        let index = field
            .current
            .as_slice()
            .binary_search_by(|row| row.key.bytes().cmp(key))
            .unwrap();
        match field.current.as_slice()[index].value.as_ref() {
            Some(value) => {
                map.insert(key.to_vec(), value.bytes().to_vec());
            }
            None => {
                map.remove(key);
            }
        }
    }
}

#[test]
fn change_membership_capture_uses_only_delta_sets_and_recreates_complete_pair() {
    for replacement in [false, true] {
        let state = state();
        for height in 1..=128 {
            commit_membership(&state, height, &[key(height as u8)]);
        }
        let mut before = committed_membership_bytes(&state);
        let mut block = if replacement {
            state.block_and_revert(header(128))
        } else {
            state.block(header(129))
        };
        let height = if replacement { 128 } else { 129 };
        block.transactions.insert_block(
            [key(250)].into_iter().collect(),
            NonZeroUsize::new(height).unwrap(),
        );
        block.transactions.try_prepare_publication().unwrap();
        freeze(&mut block);
        let mut bound = limits();
        bound.max_rows = 6;
        // One count + two passes for each paired table, over two actual source
        // keys, followed by the two original frontier values. History is 127 rows.
        bound.max_source_visits = 12;
        let mut changes =
            Collector::new(state.ivm_execution_budget(), bound, CaptureIntent::Changes).unwrap();
        let result = membership::append(&block, &mut changes);
        assert!(
            result.is_ok(),
            "membership change capture must avoid complete history scans"
        );
        assert_eq!(changes.source_visits, 12);
        let base = changes.membership_delta_base.as_ref().unwrap();
        assert_eq!(base.committed_frontier(), 128);
        assert_eq!(
            base.logical_predecessor_frontier(),
            if replacement { 127 } else { 128 }
        );
        assert_eq!(base.successor_frontier(), height as u64);
        assert_eq!(
            base.surface(),
            &block
                .transactions
                .prepared_membership_writer()
                .unwrap()
                .publication_surface()
        );
        for field in changes.fields.as_slice() {
            replay_membership_field(&mut before, field);
        }
        let mut complete = Collector::new(
            state.ivm_execution_budget(),
            limits(),
            CaptureIntent::Complete,
        )
        .unwrap();
        membership::append(&block, &mut complete).unwrap();
        for id in [
            "state.transactions.current",
            "state.transactions.rollback",
            "state.transactions.frontier",
        ] {
            assert_eq!(before[id], values(find(&complete, id)));
        }
        let pointers: Vec<_> = changes
            .fields
            .as_slice()
            .iter()
            .flat_map(|field| field.current.as_slice())
            .map(|row| row.key.bytes().as_ptr())
            .collect();
        changes.start_traversal();
        membership::append(&block, &mut changes).unwrap();
        assert_eq!(
            changes.source_visits, 0,
            "completed original delta needs no repeated source scan"
        );
        assert_eq!(
            pointers,
            changes
                .fields
                .as_slice()
                .iter()
                .flat_map(|field| field.current.as_slice())
                .map(|row| row.key.bytes().as_ptr())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn membership_delta_base_refusal_precedes_every_change_and_retains_original_retry() {
    // Keep retired fixture generations from refunding the exact State pool
    // while this test measures admission, refusal and capture-only refunds.
    let _retirement_pin = crossbeam_epoch::pin();
    let (state, proposal) = crate::state::publication::musubi_materializer_test_support::fixture();
    let before = committed_membership_bytes(&state);
    let block = validated_original(&state, proposal.header());
    let mut cut = OriginalCut::new(&block, limits(), CaptureIntent::Changes).unwrap();
    cut.advance().unwrap();
    let pointer = cut.collector.fields.as_slice().as_ptr();
    let reserved = state.ivm_execution_budget().reserved_bytes();
    let base_calls = std::cell::Cell::new(0);
    let row_calls = std::cell::Cell::new(0);
    let result = cut.changes(
        |base| {
            base_calls.set(base_calls.get() + 1);
            assert_eq!(
                norito::codec::encode_adaptive(&base.committed_frontier()),
                before["state.transactions.frontier"][&vec![]]
            );
            Err("original authenticated baseline is unavailable")
        },
        |_| {
            row_calls.set(row_calls.get() + 1);
            Ok(())
        },
        |_, _| {
            row_calls.set(row_calls.get() + 1);
            Ok(())
        },
    );
    assert!(
        matches!(
            result,
            Err(VisitError::Consumer(
                "original authenticated baseline is unavailable"
            ))
        ),
        "membership base refusal must precede every original change callback"
    );
    assert_eq!(base_calls.get(), 1);
    assert_eq!(row_calls.get(), 0);
    assert_eq!(cut.collector.fields.as_slice().as_ptr(), pointer);
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), reserved);
    cut.changes(
        |_| {
            base_calls.set(base_calls.get() + 1);
            Ok::<_, ()>(())
        },
        |_| panic!("change-only membership cannot clear its baseline"),
        |_, _| {
            row_calls.set(row_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(base_calls.get(), 2);
    assert!(row_calls.get() > 0);
    assert_eq!(cut.collector.fields.as_slice().as_ptr(), pointer);
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), reserved);
}

#[test]
fn membership_delta_capacity_refusal_keeps_original_key_base_cause_and_refund() {
    // Keep retired fixture generations from refunding the exact State pool
    // while this test measures admission, refusal and capture-only refunds.
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state();
    commit_membership(&state, 1, &[key(1)]);
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header(2));
    block.transactions.insert_block(
        [key(2)].into_iter().collect(),
        NonZeroUsize::new(2).unwrap(),
    );
    block.transactions.try_prepare_publication().unwrap();
    freeze(&mut block);
    let floor = budget.reserved_bytes();
    let mut changes = Collector::new(budget.clone(), limits(), CaptureIntent::Changes).unwrap();
    let initial = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    let key_bytes = norito::codec::encode_adaptive(&key(2));
    let value_bytes = norito::codec::encode_adaptive(&2u64);
    let backing = 2 * std::mem::size_of::<Row>();
    let blocker = budget
        .try_reserve_bytes(
            limit
                .checked_sub(initial + backing + key_bytes.len())
                .unwrap(),
        )
        .unwrap();
    let result = membership::append(&block, &mut changes).unwrap_err();
    let CaptureError::Allocation(ChargedBufferError::Admission(original)) = result else {
        panic!("original value admission must retain typed refusal")
    };
    assert!(
        matches!(&original, AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. }
        if *requested_bytes == value_bytes.len() && *reserved_bytes == limit && *limit_bytes == limit)
    );
    let pending = changes.pending.as_ref().unwrap();
    assert_eq!(pending.id, "state.transactions.current");
    assert_eq!(pending.key.as_ref().unwrap().bytes(), key_bytes);
    let pointer = pending.key.as_ref().unwrap().bytes().as_ptr();
    let original_base = changes.membership_delta_base.clone().unwrap();
    assert_eq!(budget.limit_bytes(), limit);
    changes.start_traversal();
    let repeated = membership::append(&block, &mut changes).unwrap_err();
    let CaptureError::Allocation(ChargedBufferError::Admission(repeated)) = repeated else {
        panic!("retry must retain exact original value refusal")
    };
    assert_eq!(
        original, repeated,
        "membership retry must retain the exact original partial-key capacity cause"
    );
    assert_eq!(
        changes
            .pending
            .as_ref()
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .bytes()
            .as_ptr(),
        pointer
    );
    assert_eq!(changes.membership_delta_base.as_ref(), Some(&original_base));
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), initial + backing + key_bytes.len());
    changes.start_traversal();
    membership::append(&block, &mut changes).unwrap();
    let current = find(&changes, "state.transactions.current");
    assert_eq!(current.current.as_slice()[0].key.bytes().as_ptr(), pointer);
    assert_eq!(
        current.current.as_slice()[0]
            .value
            .as_ref()
            .unwrap()
            .bytes(),
        value_bytes
    );
    assert!(current.undo.as_slice()[0].value.is_none());
    assert_eq!(changes.membership_delta_base.as_ref(), Some(&original_base));
    drop(changes);
    drop(original_base);
    assert_eq!(budget.reserved_bytes(), floor);
    assert_eq!(budget.limit_bytes(), limit);
}

#[test]
fn membership_adapter_preserves_exact_typed_source_and_consumer_refusals() {
    use crate::state::storage_transactions::authority::{
        TransactionMembershipAuthorityError, TransactionMembershipVisitError,
    };
    let source = TransactionMembershipAuthorityError::TraversalRefused {
        required: 19,
        limit: 18,
    };
    let result = membership::visit_error(TransactionMembershipVisitError::Authority(source));
    assert!(matches!(
        result,
        CaptureError::Membership(MembershipCaptureRefusal(
            TransactionMembershipAuthorityError::TraversalRefused {
                required: 19,
                limit: 18
            }
        ))
    ));
    let result = membership::visit_error(TransactionMembershipVisitError::Consumer(
        CaptureError::Changed("original paired table"),
    ));
    assert!(matches!(
        result,
        CaptureError::Changed("original paired table")
    ));
}
