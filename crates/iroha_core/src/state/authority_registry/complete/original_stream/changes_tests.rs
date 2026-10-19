// Change intent retains original native touches without claiming a complete image.

#[test]
fn change_intent_ignores_untouched_native_rows_and_replays_exact_original_changes() {
    let state = state();
    let changed = path("delta/changed");
    let removed = path("delta/removed");
    let equal = path("delta/equal");
    let absent = path("delta/absent");
    {
        let mut seed = state.world.smart_contract_state.block();
        seed.insert(changed.clone(), vec![1]);
        seed.insert(removed.clone(), vec![2]);
        seed.insert(equal.clone(), vec![3]);
        for n in 0..128 {
            seed.insert(path(&format!("untouched/{n}")), vec![41; 1024]);
        }
        seed.commit();
    }
    let mut replay: BTreeMap<_, _> = state
        .world
        .smart_contract_state
        .view()
        .iter()
        .map(|(key, value)| {
            (
                norito::codec::encode_adaptive(key),
                norito::codec::encode_adaptive(value),
            )
        })
        .collect();
    let mut block = state.block(header(1));
    block
        .world
        .smart_contract_state
        .insert(changed.clone(), vec![4]);
    block
        .world
        .smart_contract_state
        .insert(changed.clone(), vec![5]);
    block
        .world
        .smart_contract_state
        .insert(equal.clone(), vec![3]);
    block.world.smart_contract_state.remove(removed.clone());
    block.world.smart_contract_state.remove(absent.clone());
    block.world.smart_contract_state.insert(path("z"), vec![]);
    block
        .world
        .smart_contract_state
        .insert(path("longer/key"), vec![10]);
    freeze(&mut block);
    let touches = block.world.smart_contract_state.touched_entries().len();
    assert_eq!(touches, 6);
    let mut admitted = limits();
    admitted.max_rows = touches * 2;
    admitted.max_source_visits = touches * 2;
    admitted.max_total_payload_bytes = 1024;
    let mut delta = Collector::new(
        state.ivm_execution_budget(),
        admitted,
        CaptureIntent::Changes,
    )
    .unwrap();
    let captured = append_native(&block, &mut delta);
    assert!(
        captured.is_ok(),
        "change capture must inspect only original touched native rows"
    );
    assert_eq!(delta.source_visits, touches * 2);
    let field = find(&delta, "world.smart_contract_state");
    assert_eq!(field.current.as_slice().len(), touches);
    assert_eq!(field.undo.as_slice().len(), touches);
    for rows in [&field.current, &field.undo] {
        assert!(
            rows.as_slice()
                .windows(2)
                .all(|pair| pair[0].key.bytes() < pair[1].key.bytes())
        );
    }
    let changed_key = norito::codec::encode_adaptive(&changed);
    let equal_key = norito::codec::encode_adaptive(&equal);
    let absent_key = norito::codec::encode_adaptive(&absent);
    assert_eq!(
        field
            .undo
            .as_slice()
            .iter()
            .filter(|row| row.key.bytes() == changed_key)
            .count(),
        1
    );
    assert!(
        field
            .undo
            .as_slice()
            .iter()
            .any(|row| row.key.bytes() == equal_key
                && row.value.as_ref().map(Frame::bytes)
                    == Some(norito::codec::encode_adaptive(&vec![3u8]).as_slice()))
    );
    assert!(
        field
            .undo
            .as_slice()
            .iter()
            .any(|row| row.key.bytes() == absent_key && row.value.is_none())
    );
    for before in field.undo.as_slice() {
        let key = before.key.bytes();
        assert_eq!(
            replay.get(key).map(Vec::as_slice),
            before.value.as_ref().map(Frame::bytes)
        );
        let next = field
            .current
            .as_slice()
            .binary_search_by(|row| row.key.bytes().cmp(key))
            .unwrap();
        match field.current.as_slice()[next].value.as_ref() {
            Some(value) => {
                replay.insert(key.to_vec(), value.bytes().to_vec());
            }
            None => {
                replay.remove(key);
            }
        }
    }
    let mut complete = Collector::new(
        state.ivm_execution_budget(),
        limits(),
        CaptureIntent::Complete,
    )
    .unwrap();
    append_native(&block, &mut complete).unwrap();
    assert_eq!(
        replay,
        values(find(&complete, "world.smart_contract_state"))
    );
    let addresses: Vec<_> = field
        .current
        .as_slice()
        .iter()
        .map(|row| row.key.bytes().as_ptr())
        .collect();
    delta.start_traversal();
    append_native(&block, &mut delta).unwrap();
    assert_eq!(delta.source_visits, 0);
    assert_eq!(
        addresses,
        find(&delta, "world.smart_contract_state")
            .current
            .as_slice()
            .iter()
            .map(|row| row.key.bytes().as_ptr())
            .collect::<Vec<_>>()
    );
}

#[test]
fn change_intent_matches_complete_stream_but_cannot_emit_a_snapshot() {
    let (state, proposal) = crate::state::publication::musubi_materializer_test_support::fixture();
    let membership_before = committed_membership_bytes(&state);
    let block = validated_original(&state, proposal.header());
    let mut complete = OriginalCut::new(&block, limits(), CaptureIntent::Complete).unwrap();
    let mut delta = OriginalCut::new(&block, limits(), CaptureIntent::Changes).unwrap();
    let mut observations = Vec::new();
    for cut in [&mut complete, &mut delta] {
        cut.advance().unwrap();
        let mut replacements = Vec::new();
        let mut changes = Vec::new();
        cut.changes(
            |_| Ok(()),
            |id| {
                replacements.push(id);
                Ok::<_, ()>(())
            },
            |id, row| {
                changes.push((
                    id,
                    row.key.to_vec(),
                    row.before.map(<[u8]>::to_vec),
                    row.after.map(<[u8]>::to_vec),
                ));
                Ok(())
            },
        )
        .unwrap();
        observations.push((replacements, changes));
    }
    let ordinary = |entry: &&(&'static str, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)| {
        !entry.0.starts_with("state.transactions.")
    };
    assert_eq!(
        observations[0]
            .1
            .iter()
            .filter(ordinary)
            .collect::<Vec<_>>(),
        observations[1]
            .1
            .iter()
            .filter(ordinary)
            .collect::<Vec<_>>()
    );
    assert!(observations[1].0.is_empty());
    let mut applied = Vec::new();
    for (replacements, changes) in &observations {
        let mut tables = membership_before.clone();
        for id in replacements {
            tables.get_mut(id).unwrap().clear();
        }
        for (id, key, before, after) in changes {
            if let Some(table) = tables.get_mut(id) {
                if !replacements.contains(id) {
                    assert_eq!(table.get(key), before.as_ref());
                }
                match after {
                    Some(value) => {
                        table.insert(key.clone(), value.clone());
                    }
                    None => {
                        table.remove(key);
                    }
                }
            }
        }
        applied.push(tables);
    }
    assert_eq!(applied[0], applied[1]);
    let callbacks = std::cell::Cell::new(0);
    let result = delta.visit(
        |_, _| {
            callbacks.set(callbacks.get() + 1);
            Err("partial field escaped")
        },
        |_, _, _| {
            callbacks.set(callbacks.get() + 1);
            Err("partial row escaped")
        },
    );
    assert!(
        matches!(
            result,
            Err(VisitError::Source(CaptureError::IncompleteSnapshot))
        ),
        "change-only original capture must refuse complete snapshot delivery before callbacks"
    );
    assert_eq!(callbacks.get(), 0);
    let complete_fields = std::cell::Cell::new(0);
    complete
        .visit(
            |_, _| {
                complete_fields.set(complete_fields.get() + 1);
                Ok::<_, ()>(())
            },
            |_, _, _| Ok(()),
        )
        .unwrap();
    assert!(complete_fields.get() > 0);
    // An equal-content owner or a changed target never replaces the retained cut.
    {
        let mut foreign = state.world.smart_contract_state.block();
        foreign.insert(path("delta/foreign"), vec![99]);
        foreign.commit();
    }
    assert!(matches!(
        delta.changes(|_| Ok(()), |_| Ok::<_, ()>(()), |_, _| Ok(())),
        Err(VisitError::Source(CaptureError::Changed(
            "world.smart_contract_state"
        )))
    ));
}

#[test]
fn change_capture_refusal_retains_original_partial_frame_through_retry_and_refund() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header(1));
    block
        .world
        .smart_contract_state
        .insert(path("delta/large"), vec![7; 4096]);
    freeze(&mut block);
    let before_capture = budget.reserved_bytes();
    let mut delta = Collector::new(budget.clone(), limits(), CaptureIntent::Changes).unwrap();
    let original_limit = budget.limit_bytes();
    let initial = budget.reserved_bytes();
    let first = block
        .world
        .smart_contract_state
        .touched_entries()
        .next()
        .unwrap();
    let first_key_bytes = norito::codec::encode_adaptive(first.key);
    let first_key_size = first_key_bytes.len();
    let first_value_bytes = norito::codec::encode_adaptive(first.after.unwrap());
    let first_value_size = first_value_bytes.len();
    let touches = block.world.smart_contract_state.touched_entries().len();
    assert_eq!(touches, 1);
    let backing = touches * 2 * std::mem::size_of::<Row>();
    // Occupy real credit without changing policy. Exactly the original two row
    // arrays and first key fit; the value must refuse on this same finite pool.
    let blocker_bytes = original_limit
        .checked_sub(initial + backing + first_key_size)
        .unwrap();
    assert!(blocker_bytes > first_value_size);
    let blocker = budget.try_reserve_bytes(blocker_bytes).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        original_limit - backing - first_key_size
    );
    let error = append_native(&block, &mut delta).unwrap_err();
    let CaptureError::Allocation(ChargedBufferError::Admission(refusal)) = error else {
        panic!("original value admission must preserve its typed allocation refusal")
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    } = &refusal
    else {
        panic!("retained credit must cause the original value Capacity refusal")
    };
    assert_eq!(*requested_bytes, first_value_size);
    assert_eq!(*reserved_bytes, original_limit);
    assert_eq!(*limit_bytes, original_limit);
    assert_eq!(budget.limit_bytes(), original_limit);
    assert_eq!(budget.reserved_bytes(), original_limit);
    // No owner has released since the failed value admission. A probe of the
    // exact same demand must carry the same pool and release observation, too.
    let original_refusal = budget
        .try_reserve_bytes(first_value_size)
        .err()
        .expect("the actual original pool remains occupied");
    assert_eq!(refusal, original_refusal);
    let pending = delta.pending.as_ref().unwrap();
    let key = pending.key.as_ref().unwrap().bytes().as_ptr();
    let identity = SourceIdentity::Journal(block.world.smart_contract_state.publication_identity());
    assert_eq!(pending.source, identity);
    assert_eq!(pending.key.as_ref().unwrap().bytes(), first_key_bytes);
    assert!(pending.value.is_none());
    assert!(pending.current.as_ref().unwrap().as_slice().is_empty());
    assert!(pending.undo.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(delta.payload_bytes, first_key_size);
    assert_eq!(delta.rows, 2);
    assert_eq!(delta.source_visits, 2);
    drop(blocker);
    assert_eq!(budget.limit_bytes(), original_limit);
    assert_eq!(budget.reserved_bytes(), initial + backing + first_key_size);
    delta.start_traversal();
    append_native(&block, &mut delta).unwrap();
    let retained = find(&delta, "world.smart_contract_state");
    assert_eq!(
        retained.current.as_slice()[0].key.bytes().as_ptr(),
        key,
        "change capture retry must retain its original partial key frame"
    );
    assert_eq!(retained.source, identity);
    assert_eq!(
        retained.current.as_slice()[0]
            .value
            .as_ref()
            .unwrap()
            .bytes(),
        first_value_bytes
    );
    assert!(retained.undo.as_slice()[0].value.is_none());
    assert_eq!(budget.limit_bytes(), original_limit);
    drop(delta);
    assert_eq!(budget.reserved_bytes(), before_capture);
    assert_eq!(budget.limit_bytes(), original_limit);
}
