fn recipient_index_snapshot(world: &World) -> String {
    let mut out = String::new();
    snapshot_storage::serialize(&world.private_settlement_recipient_index, &mut out);
    out
}

// Private-settlement derived indexes must follow canonical output undo history.

#[test]
fn private_settlement_snapshot_recipient_reservations_follow_replacement() {
    let mut world = crate::private_settlement::global_state::tests::finalized_world_fixture();
    // Materialize an actual last-block insertion for every authoritative map.
    // Its predecessor is empty; the terminal fixture remains fully validated.
    macro_rules! insert_as_last_block {
        ($($field:ident),+ $(,)?) => {$(
            let entries = world.$field.view().iter()
                .map(|(key, value)| (key.clone(), value.clone())).collect::<Vec<_>>();
            world.$field = Storage::default();
            let mut block = world.$field.block();
            for (key, value) in entries { block.insert(key, value); }
            block.commit();
        )+};
    }
    insert_as_last_block!(
        private_settlement_governance,
        private_settlement_pools,
        private_settlement_roots,
        private_settlement_nullifiers,
        private_settlement_outputs,
        private_settlement_recipient_index,
        private_settlement_staged_locks,
        private_settlement_receipts,
        private_settlement_aborts,
    );
    let encoded = json::to_json(&world).unwrap();
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    let restored = parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&encoded, "world").unwrap(),
        &seed,
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
    .unwrap();
    assert_eq!(restored.private_settlement_recipient_index.view().len(), 6);
    let restored_index = recipient_index_snapshot(&restored);
    assert_eq!(restored_index, recipient_index_snapshot(&world));
    {
        let replacement = restored.block_and_revert();
        assert!(replacement.private_settlement_outputs.is_empty());
        assert!(
            replacement.private_settlement_recipient_index.is_empty(),
            "recipients inserted at H must not remain reserved in H−1"
        );
        assert!(replacement.private_settlement_receipts.is_empty());
    }
    assert_eq!(
        json::to_json(&restored).unwrap(),
        encoded,
        "abandoning replacement must preserve every source byte and undo preimage"
    );
    assert_eq!(recipient_index_snapshot(&restored), restored_index);
    restored.block_and_revert().commit();
    assert!(restored.private_settlement_outputs.view().is_empty());
    assert!(
        restored
            .private_settlement_recipient_index
            .view()
            .is_empty()
    );
    let replaced = json::to_json(&restored).unwrap();
    let restarted = parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&replaced, "world").unwrap(),
        &seed,
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
    .unwrap();
    assert!(
        restarted
            .private_settlement_recipient_index
            .view()
            .is_empty()
    );
    assert_eq!(json::to_json(&restarted).unwrap(), replaced);
}

#[test]
fn private_settlement_snapshot_rejects_duplicate_recipients_in_prior_outputs() {
    let mut world = crate::private_settlement::global_state::tests::finalized_world_fixture();
    let (current, key, mut prior, recipient) = {
        let outputs = world.private_settlement_outputs.view();
        let mut records = outputs.iter();
        let (_, first) = records.next().unwrap();
        let (key, second) = records.next().unwrap();
        (
            outputs
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            *key,
            second.clone(),
            first.encrypted_output.recipient,
        )
    };
    prior.encrypted_output.recipient = recipient;
    world.private_settlement_outputs =
        Storage::from_snapshot_parts(current, BTreeMap::from([(key, Some(prior))]));
    let encoded = json::to_json(&world).unwrap();
    let ivm = IVM::new(0);
    let result = parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&encoded, "world").unwrap(),
        &IvmSeed {
            ivm: &ivm,
            _marker: PhantomData,
        },
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test);
    let Err(error) = result else {
        panic!("invalid predecessor recipient reuse was accepted")
    };
    assert!(
        error
            .to_string()
            .contains("private-settlement state conflict"),
        "{error}"
    );
    assert_eq!(json::to_json(&world).unwrap(), encoded);
}
