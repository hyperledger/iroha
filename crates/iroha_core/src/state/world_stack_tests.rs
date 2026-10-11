//! Stack bounds for World ownership, State construction, and snapshot restoration.

use super::*;

fn on_default_stack(name: &str, test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_owned())
        // Fix the ordinary libtest budget even when RUST_MIN_STACK is set.
        .stack_size(2 * 1024 * 1024)
        .spawn(test)
        .expect("spawn with the ordinary stack budget")
        .join()
        .expect("World ownership stays within the ordinary stack budget");
}

#[test]
fn world_is_a_compact_heap_owner() {
    assert_eq!(
        size_of::<World>(),
        size_of::<usize>(),
        "passing World between constructor and restore frames must move only its heap owner",
    );
}

#[test]
fn world_json_uses_canonical_fields_and_checked_writer() {
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let fields = <World as json::FastJsonWrite>::json_object_field_order()
        .expect("World has one fixed snapshot schema");
    assert_eq!(fields.first(), Some(&"parameters"));
    assert!(fields.contains(&"accounts"));
    let encoded = json::to_json(&world).expect("serialize World");
    let object = json::from_str::<json::Value>(&encoded).expect("parse World JSON");
    let json::Value::Object(object) = object else {
        panic!("World must serialize as its canonical field object");
    };
    assert_eq!(object.len(), fields.len());
    assert!(fields.iter().all(|field| object.contains_key(*field)));
    assert_eq!(
        json::to_json_bounded(&world, 0),
        Err(json::BoundedJsonError::BodyTooLarge),
        "the checked writer must enforce its budget before writing fields",
    );
    // Storage fields can refuse a checked sink. The World owner must propagate
    // that refusal rather than falling back to an unbounded temporary string.
    assert_eq!(
        json::to_json_bounded(&world, encoded.len()),
        json::to_json_bounded(&*world, encoded.len()),
    );
}

#[test]
fn world_constructor_and_snapshot_restore_preserve_history_on_default_stack() {
    on_default_stack("world-constructor-snapshot-stack", || {
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        for sequence in [7, 9] {
            let mut block = world.block();
            block.tx_sequences.insert(ALICE_ID.clone(), sequence);
            block.commit();
        }
        let storage_owner = std::ptr::from_ref(&*world);
        let kura = Kura::blank_kura_for_testing();
        let state = State::try_new(
            crate::state::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            world,
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
        )
        .expect("construct nonempty State through the production constructor");
        assert_eq!(std::ptr::from_ref(&*state.world), storage_owner);
        let snapshot = json::to_json(&state).expect("serialize canonical State snapshot");
        let restored = deserialize::KuraSeed {
            execution_budget: iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            lane_manifests: state.lane_manifests.read().clone(),
            kura,
            query_handle: LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            telemetry: StateTelemetry::default(),
        }
        .into_state_from_json_str(&snapshot)
        .expect("restore canonical State bytes on the ordinary stack");
        assert!(restored.world.accounts.view().get(&ALICE_ID).is_some());
        assert_eq!(restored.world.tx_sequences.view().get(&ALICE_ID), Some(&9),);
        {
            let previous = restored.world.tx_sequences.block_and_revert();
            assert_eq!(previous.get(&ALICE_ID), Some(&7));
        }
        assert_eq!(
            json::to_json(&restored).expect("serialize restored State"),
            snapshot,
            "restoration and reading the predecessor preserve the canonical snapshot",
        );
    });
}

#[test]
fn approved_pin_snapshot_validation_uses_default_stack() {
    on_default_stack("approved-pin-snapshot-stack", || {
        super::approved_pin_snapshot_requires_its_exact_automatic_replication_order();
    });
}
