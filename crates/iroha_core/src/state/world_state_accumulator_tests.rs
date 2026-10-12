//! World state accumulator algebra, completeness and incremental/cold-capture equivalence.

use super::*;
use crate::{
    smartcontracts::isi::triggers::set::AUTHORITY_FIELDS,
    state::{World, authority_registry::STATE_FIELDS, block_field::BlockField},
};
use iroha_model_base::state_path::StatePath;
use mv::storage::Storage;
use std::{cell::Cell, time::Instant};

fn path(key: &str) -> StatePath {
    key.parse().unwrap()
}

fn sample(index: u8) -> [u8; LANE_BYTES] {
    element(
        &path_hash("world.test", TABLE).unwrap(),
        Some(&Hash::new([index])),
        &Hash::new([index, index]),
    )
}

/// Independent restatement of the documented element formula and lane arithmetic.
fn documented_sum(entries: &[(Hash, Option<Hash>, Hash)]) -> [u16; LANES] {
    let mut lanes = [0_u16; LANES];
    for (path, key, value) in entries {
        let mut input = Vec::new();
        input.extend_from_slice(path.as_ref());
        input.push(u8::from(key.is_some()));
        input.extend_from_slice(key.as_ref().map_or(&[0; 32][..], |key| key.as_ref()));
        input.extend_from_slice(value.as_ref());
        let mut bytes = vec![0_u8; 2 * LANES];
        blake3::Hasher::new_derive_key("iroha 2026-09-30 world-state lthash16 element v1")
            .update(&input)
            .finalize_xof()
            .fill(&mut bytes);
        for (lane, pair) in lanes.iter_mut().zip(bytes.chunks_exact(2)) {
            *lane = lane.wrapping_add(u16::from(pair[0]) | (u16::from(pair[1]) << 8));
        }
    }
    lanes
}

#[test]
fn accumulator_add_and_remove_are_inverse_and_order_independent() {
    let elements: Vec<_> = (0..16).map(sample).collect();
    let mut forward = WorldStateAccumulator::empty();
    for element in &elements {
        forward.add(element);
    }
    let mut backward = WorldStateAccumulator::empty();
    for element in elements.iter().rev() {
        backward.add(element);
    }
    assert_eq!(forward, backward, "the multiset sum ignores entry order");
    assert_eq!(forward.root(), backward.root());
    assert_eq!(forward.entries(), 16);
    let mut interleaved = forward.clone();
    interleaved.remove(&elements[3]);
    interleaved.add(&sample(99));
    interleaved.remove(&sample(99));
    interleaved.add(&elements[3]);
    assert_eq!(interleaved, forward, "remove is the exact inverse of add");
    for element in &elements {
        backward.remove(element);
    }
    assert_eq!(backward, WorldStateAccumulator::empty());
    assert_eq!(backward.root(), WorldStateAccumulator::empty().root());
    // Removing before adding wraps and still cancels: the value is a function of the multiset.
    let mut wrapped = WorldStateAccumulator::empty();
    wrapped.remove(&elements[0]);
    assert_eq!(wrapped.entries(), u64::MAX);
    wrapped.add(&elements[0]);
    assert_eq!(wrapped, WorldStateAccumulator::empty());
    // A duplicate entry is not idempotent: multiplicity is part of the multiset.
    let mut twice = WorldStateAccumulator::empty();
    twice.add(&elements[0]);
    twice.add(&elements[0]);
    let mut once = WorldStateAccumulator::empty();
    once.add(&elements[0]);
    assert_ne!(twice.root(), once.root());
}

#[test]
fn accumulator_matches_the_documented_formula_and_known_vectors() {
    let path = path_hash("world.test", TABLE).unwrap();
    let entries = [
        (path, Some(Hash::new(b"key a")), Hash::new(b"value a")),
        (path, Some(Hash::new(b"key b")), Hash::new(b"value b")),
        (
            path_hash("world.cell", CELL).unwrap(),
            None,
            Hash::new(b"cell"),
        ),
    ];
    let mut accumulator = WorldStateAccumulator::empty();
    for (path, key, value) in &entries {
        accumulator.add(&element(path, key.as_ref(), value));
    }
    assert_eq!(*accumulator.lanes, documented_sum(&entries));
    // The expansion is BLAKE3 in derive-key mode: pin its first lanes so a change of context,
    // input layout, lane order or width is caught.
    let single = WorldStateAccumulator {
        lanes: Box::new(documented_sum(&entries[..1])),
        entries: 1,
    };
    let mut expected = WorldStateAccumulator::empty();
    expected.add(&element(
        &entries[0].0,
        entries[0].1.as_ref(),
        &entries[0].2,
    ));
    assert_eq!(single, expected);
    let first_lanes: Vec<String> = single.lanes[..4]
        .iter()
        .map(|lane| format!("{lane:04x}"))
        .collect();
    assert_eq!(
        first_lanes.join(" "),
        KNOWN_FIRST_LANES,
        "element expansion changed"
    );
    // The root binds the registry schema, the entry count and every lane, little endian.
    let schema = field_index().as_ref().unwrap().schema;
    let mut preimage = b"iroha:world-state:root:v1\0".to_vec();
    preimage.extend_from_slice(schema.as_ref());
    preimage.extend_from_slice(&3_u64.to_le_bytes());
    for lane in documented_sum(&entries) {
        preimage.extend_from_slice(&lane.to_le_bytes());
    }
    assert_eq!(accumulator.root(), Ok(Hash::new(preimage)));
    assert_ne!(
        WorldStateAccumulator::empty().root(),
        accumulator.root(),
        "the empty World has its own root"
    );
}

/// First four lanes of the element of `(world.test, "key a", "value a")`.
const KNOWN_FIRST_LANES: &str = "26e9 19ce b836 2d68";

#[test]
fn snapshot_json_and_norito_forms_roundtrip_exactly() {
    let mut accumulator = WorldStateAccumulator::empty();
    accumulator.add(&sample(1));
    accumulator.add(&sample(2));
    let json = norito::json::to_json(&accumulator).unwrap();
    assert_eq!(json.len(), WorldStateAccumulator::JSON_HEX + 2);
    let restored: WorldStateAccumulator = norito::json::from_str(&json).unwrap();
    assert_eq!(restored, accumulator);
    assert!(norito::json::from_str::<WorldStateAccumulator>("\"00\"").is_err());
    let payload = norito::codec::Encode::encode(&accumulator);
    assert_eq!(payload.len(), WorldStateAccumulator::PAYLOAD_BYTES);
    assert_eq!(payload[..8], 2_u64.to_le_bytes());
    assert_eq!(payload[8..10], accumulator.lanes[0].to_le_bytes());
    assert_eq!(hex::encode(&payload), json.trim_matches('"'));
    let mut other = accumulator.clone();
    other.add(&sample(3));
    assert_ne!(
        hash_value(&accumulator).unwrap(),
        hash_value(&other).unwrap()
    );
}

#[test]
fn registry_index_covers_every_world_field_exactly_once() {
    let index = field_index().as_ref().unwrap();
    let mut flat = Vec::new();
    flatten(WORLD_FIELDS, &mut flat);
    let mut canonical = 0;
    for field in flat {
        let name = field.id.strip_prefix("world.").unwrap_or(field.id);
        match field.role {
            Role::Canonical(Canonical::Owner(_)) => {
                assert!(!index.by_name.contains_key(name), "{}", field.id);
            }
            Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_)) => {
                canonical += 1;
                assert!(
                    matches!(index.by_name[name], Classified::Canonical { .. }),
                    "{}",
                    field.id
                );
            }
            Role::Derived { .. } | Role::Local(_) | Role::History { .. } => {
                assert!(
                    matches!(index.by_name[name], Classified::Excluded),
                    "{}",
                    field.id
                );
            }
        }
    }
    assert_eq!(index.canonical, canonical);
    assert_eq!(
        canonical,
        WORLD_FIELDS
            .iter()
            .filter(|field| matches!(field.role, Role::Canonical(_)) && field.id != "world.triggers")
            .count()
            + AUTHORITY_FIELDS
                .iter()
                .filter(|field| matches!(field.role, Role::Canonical(_)))
                .count()
    );
    // The accumulator itself is derived World state and never commits to itself.
    assert!(matches!(
        index.by_name["state_accumulator"],
        Classified::Excluded
    ));
    assert!(
        STATE_FIELDS.iter().any(|field| field.id == "state.world"),
        "the World owner is registered in the State inventory"
    );
}

#[test]
fn every_pass_visits_exactly_the_canonical_fields() {
    let index = field_index().as_ref().unwrap();
    let world = World::default();
    let block = world.block();
    // A complete pass over the actual overlay inventory succeeds.
    WorldStateAccumulator::capture(&block).unwrap();
    WorldStateAccumulator::empty().apply_block(&block).unwrap();
    // A pass that skips one canonical field, repeats one or meets an unclassified or
    // mistyped name fails instead of committing a partial World.
    let mut builder = Builder {
        index,
        accumulator: WorldStateAccumulator::empty(),
        direction: Direction::Capture,
        visited: vec![false; index.canonical],
        snapshot: None,
        snapshot_field: None,
    };
    assert!(
        builder
            .field("smart_contract_state", TABLE)
            .unwrap()
            .is_some()
    );
    assert!(builder.field("smart_contract_state", TABLE).is_err());
    assert!(builder.field("parameters", TABLE).is_err());
    assert!(builder.field("not_registered", TABLE).is_err());
    assert_eq!(builder.field("domains_by_owner", TABLE), Ok(None));
    assert!(builder.finish().is_err());
}

#[test]
fn capture_binds_untouched_and_snapshot_skipped_values_without_undo_history() {
    let first = World::default();
    let second = World::default();
    let plain = WorldStateAccumulator::capture(&first.block()).unwrap();
    {
        let mut setup = second.block();
        setup
            .smart_contract_state
            .insert(path("untouched/value"), vec![1]);
        *setup.soradns_last_publish_ms.get_mut() = Some(42);
        setup.commit();
    }
    let block = second.block();
    let initial = WorldStateAccumulator::capture(&block).unwrap();
    assert_ne!(plain.root(), initial.root());
    assert_eq!(
        initial.entries(),
        plain.entries() + 1,
        "one new table entry"
    );
    drop(block);
    // A different undo journal with identical current values cannot change the root.
    let mut noop = second.block();
    noop.smart_contract_state
        .insert(path("untouched/value"), vec![9]);
    noop.smart_contract_state
        .insert(path("untouched/value"), vec![1]);
    *noop.soradns_last_publish_ms.get_mut() = Some(42);
    assert_eq!(
        initial.root(),
        WorldStateAccumulator::capture(&noop).unwrap().root()
    );
    assert_eq!(initial.root(), initial.apply_block(&noop).unwrap().root());
}

#[test]
fn incremental_versions_match_cold_capture_across_commit_and_replacement() {
    let world = World::default();
    let parent = WorldStateAccumulator::capture(&world.block()).unwrap();
    let parent_root = parent.root();
    let mut block = world.block();
    block.smart_contract_state.insert(path("app/kept"), vec![1]);
    block
        .smart_contract_state
        .insert(path("app/removed"), vec![]);
    *block.soradns_last_publish_ms.get_mut() = Some(7);
    {
        let mut aborted = block.smart_contract_state.transaction();
        aborted.insert(path("app/aborted"), vec![9]);
    }
    let first = parent.apply_block(&block).unwrap();
    assert_eq!(
        first.root(),
        WorldStateAccumulator::capture(&block).unwrap().root()
    );
    assert_eq!(
        parent.root(),
        WorldStateAccumulator::capture_predecessor(&block)
            .unwrap()
            .root()
    );
    block.commit();
    assert_eq!(
        first.root(),
        WorldStateAccumulator::capture(&world.block())
            .unwrap()
            .root()
    );
    // Opening and dropping the intervening read overlay must preserve the undo
    // needed by replacement; the replacement's before cut is the original parent.
    let mut replacement = world.block_and_revert();
    assert_eq!(
        parent_root,
        WorldStateAccumulator::capture(&replacement).unwrap().root()
    );
    replacement
        .smart_contract_state
        .insert(path("app/replacement"), vec![3]);
    *replacement.soradns_last_publish_ms.get_mut() = Some(8);
    let replaced = parent.apply_block(&replacement).unwrap();
    assert_eq!(
        replaced.root(),
        WorldStateAccumulator::capture(&replacement).unwrap().root()
    );
    assert_eq!(
        parent_root,
        WorldStateAccumulator::capture_predecessor(&replacement)
            .unwrap()
            .root()
    );
    replacement.commit();
    let mut next = world.block();
    next.smart_contract_state.remove(path("app/replacement"));
    *next.soradns_last_publish_ms.get_mut() = None;
    assert_eq!(parent_root, replaced.apply_block(&next).unwrap().root());
    assert_eq!(parent_root, parent.root());
}

#[test]
fn a_foreign_predecessor_yields_a_root_that_differs_from_the_actual_world() {
    let source = World::default();
    let other = World::default();
    {
        let mut setup = other.block();
        setup
            .smart_contract_state
            .insert(path("app/stale"), vec![99]);
        setup.commit();
    }
    let foreign = WorldStateAccumulator::capture(&source.block()).unwrap();
    let mut block = other.block();
    block
        .smart_contract_state
        .insert(path("app/first"), vec![1]);
    block
        .smart_contract_state
        .insert(path("app/stale"), vec![2]);
    // The multiset hash cannot see the missing preimage locally; the certified root does.
    let applied = foreign.apply_block(&block).unwrap();
    let actual = WorldStateAccumulator::capture(&block).unwrap();
    assert_ne!(applied.root(), actual.root());
    let actual_parent = WorldStateAccumulator::capture_predecessor(&block).unwrap();
    assert_eq!(
        actual_parent.apply_block(&block).unwrap().root(),
        actual.root()
    );
}

#[test]
fn incremental_encoding_is_limited_to_touched_values() {
    let index = field_index().as_ref().unwrap();
    let storage: Storage<u64, Vec<u8>> = (0..512).map(|key| (key, vec![key as u8])).collect();
    let mut block = BlockField::new(storage.block());
    let builder = |accumulator, direction| Builder {
        index,
        accumulator,
        direction,
        visited: vec![false; index.canonical],
        snapshot: None,
        snapshot_field: None,
    };
    let mut initial = builder(WorldStateAccumulator::empty(), Direction::Capture);
    initial
        .append_storage_with("smart_contract_state", &block, hash_value)
        .unwrap();
    let initial = initial.accumulator;
    assert_eq!(initial.entries(), 512);
    block.insert(17, vec![9]);
    let calls = Cell::new(0);
    let mut next = builder(initial.clone(), Direction::Forward);
    next.append_storage_with("smart_contract_state", &block, |value| {
        calls.set(calls.get() + 1);
        hash_value(value)
    })
    .unwrap();
    assert_eq!(
        calls.get(),
        2,
        "encode just one before/after pair, not 512 entries"
    );
    let mut cold = builder(WorldStateAccumulator::empty(), Direction::Capture);
    cold.append_storage_with("smart_contract_state", &block, hash_value)
        .unwrap();
    assert_eq!(next.accumulator, cold.accumulator);
    let mut failed = builder(initial.clone(), Direction::Forward);
    assert!(
        failed
            .append_storage_with("smart_contract_state", &block, |_| Err(
                "injected encoding error".into()
            ))
            .is_err()
    );
    assert_ne!(initial, next.accumulator);
}

#[test]
fn field_identity_and_kind_are_bound_into_each_entry() {
    let index = field_index().as_ref().unwrap();
    let storage: Storage<u64, Vec<u8>> = [(1, vec![1])].into_iter().collect();
    let block = BlockField::new(storage.block());
    let mut roots = Vec::new();
    for name in ["smart_contract_state", "contract_code"] {
        let mut builder = Builder {
            index,
            accumulator: WorldStateAccumulator::empty(),
            direction: Direction::Capture,
            visited: vec![false; index.canonical],
            snapshot: None,
            snapshot_field: None,
        };
        builder
            .append_storage_with(name, &block, hash_value)
            .unwrap();
        roots.push(builder.accumulator.root());
    }
    assert_ne!(
        roots[0], roots[1],
        "the same entry in another field differs"
    );
    let cell = mv::cell::Cell::new(Vec::<u8>::new());
    let block = BlockField::new(cell.block());
    let mut builder = Builder {
        index,
        accumulator: WorldStateAccumulator::empty(),
        direction: Direction::Capture,
        visited: vec![false; index.canonical],
        snapshot: None,
        snapshot_field: None,
    };
    assert!(
        builder
            .append_cell_with("smart_contract_state", &block, hash_value)
            .is_err(),
        "a table cannot be projected as a cell"
    );
}

#[test]
fn trigger_stores_share_the_complete_world_visitor() {
    use crate::smartcontracts::isi::triggers::specialized::{
        SpecializedAction, SpecializedTrigger,
    };
    use iroha_data_model::{events::execute_trigger::ExecuteTriggerEventFilter, prelude::*};
    let world = World::default();
    let mut block = world.block();
    let parent = WorldStateAccumulator::capture(&block).unwrap();
    {
        let mut tx = block.triggers.transaction();
        let action = SpecializedAction::new(
            Executable::Instructions(
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    "accumulator".to_owned(),
                ))]
                .into(),
            ),
            Repeats::Exactly(3),
            iroha_test_samples::ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new(),
        )
        .unwrap();
        assert!(
            tx.add_by_call_trigger(SpecializedTrigger::new(
                "accumulator".parse().unwrap(),
                action
            ))
            .unwrap()
        );
        tx.apply();
    }
    let after = parent.apply_block(&block).unwrap();
    assert_eq!(
        after.root(),
        WorldStateAccumulator::capture(&block).unwrap().root()
    );
    assert_ne!(after.root(), parent.root());
    assert_eq!(
        parent.root(),
        WorldStateAccumulator::capture_predecessor(&block)
            .unwrap()
            .root()
    );
    assert_eq!(
        after.entries(),
        parent.entries() + 1,
        "the action is authoritative; its id and active-id indexes are derived"
    );
}

#[test]
fn unwitnessed_role_and_parameter_changes_change_the_root() {
    use iroha_data_model::{
        parameter::{BlockParameter, Parameter},
        prelude::*,
    };
    let world = World::default();
    let mut block = world.block();
    let parent = WorldStateAccumulator::capture(&block).unwrap();
    let role = RoleId::new("auditor".parse().unwrap());
    block.account_roles.insert(
        crate::role::RoleIdWithOwner::new(iroha_test_samples::ALICE_ID.clone(), role),
        (),
    );
    let granted = parent.apply_block(&block).unwrap();
    assert_ne!(granted.root(), parent.root(), "a role grant is committed");
    assert_eq!(
        granted.root(),
        WorldStateAccumulator::capture(&block).unwrap().root()
    );
    block
        .parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::MaxTransactions(
            std::num::NonZeroU64::new(7).unwrap(),
        )))
        .expect("valid fixture parameters");
    let parameterized = parent.apply_block(&block).unwrap();
    assert_ne!(
        parameterized.root(),
        granted.root(),
        "a parameter is committed"
    );
    assert_eq!(
        parameterized.root(),
        WorldStateAccumulator::capture(&block).unwrap().root()
    );
}

#[test]
fn derived_index_changes_do_not_create_independent_world_authority() {
    use iroha_model_base::domain::DomainId;
    use std::collections::BTreeSet;

    let world = World::default();
    let mut block = world.block();
    let parent = WorldStateAccumulator::capture(&block).unwrap();
    block.domains_by_owner.insert(
        iroha_test_samples::ALICE_ID.clone(),
        BTreeSet::from([DomainId::try_new("derived", "only").unwrap()]),
    );
    let current = WorldStateAccumulator::capture(&block).unwrap();
    assert_eq!(current.root(), parent.root());
    assert_eq!(parent.apply_block(&block).unwrap().root(), parent.root());
    // The stored accumulator is derived too: writing it never changes the root it commits.
    *block.state_accumulator.get_mut() = current.clone();
    assert_eq!(
        WorldStateAccumulator::capture(&block).unwrap().root(),
        parent.root()
    );

    block
        .smart_contract_state
        .insert(path("authority/changed"), vec![1]);
    let changed = WorldStateAccumulator::capture(&block).unwrap();
    assert_ne!(changed.root(), parent.root());
    assert_eq!(parent.apply_block(&block).unwrap().root(), changed.root());
}

#[test]
fn schema_binds_declared_codec_and_semantic_identities() {
    use crate::state::authority_registry::{V1_LAYOUT, schema};

    let u32_schema = schema_fingerprint(schema::<u32>()).unwrap();
    let u64_schema = schema_fingerprint(schema::<u64>()).unwrap();
    assert_ne!(u32_schema, u64_schema, "Norito nominal identity is bound");
    let resolver = Schema::Semantic {
        identity: "iroha:state:musubi-resolver-authority:v1",
        encoder: "test",
        layout: V1_LAYOUT,
    };
    let directory = Schema::Semantic {
        identity: "iroha:state:musubi-directory-authority:v1",
        encoder: "test",
        layout: V1_LAYOUT,
    };
    assert_ne!(
        schema_fingerprint(resolver).unwrap(),
        schema_fingerprint(directory).unwrap(),
        "independent semantic identities are bound"
    );
    let altered_layout = Schema::Semantic {
        identity: "iroha:state:musubi-resolver-authority:v1",
        encoder: "test",
        layout: crate::state::authority_registry::CanonicalLayout {
            flags: V1_LAYOUT.flags ^ 1,
            ..V1_LAYOUT
        },
    };
    assert_ne!(
        schema_fingerprint(resolver).unwrap(),
        schema_fingerprint(altered_layout).unwrap(),
        "canonical layout flags are bound"
    );
    assert!(
        schema_fingerprint(Schema::Required {
            identity: "unresolved",
            obligation: "TODO: test refusal",
        })
        .is_err(),
        "an unresolved value schema cannot enter the accumulator"
    );
}

#[test]
fn schema_fingerprint_preserves_wire_identity_across_borrowed_and_owned_names() {
    use crate::state::authority_registry::V1_LAYOUT;
    use std::borrow::Cow;

    const IDENTITY: &str = "world.test.schema.v1";
    let borrowed = Schema::Norito {
        nominal_name: || Cow::Borrowed(IDENTITY),
        layout: V1_LAYOUT,
    };
    let owned = Schema::Norito {
        nominal_name: || Cow::Owned(IDENTITY.to_owned()),
        layout: V1_LAYOUT,
    };
    let semantic = Schema::Semantic {
        identity: IDENTITY,
        encoder: "test-only semantic projection",
        layout: V1_LAYOUT,
    };
    let norito = schema_fingerprint(borrowed).unwrap();
    assert_eq!(norito, schema_fingerprint(owned).unwrap());
    // Independent Python hashlib BLAKE2b-256 vectors include the exact tag,
    // layout, little-endian byte length, identity and canonical hash marker.
    assert_eq!(
        hex::encode(norito.as_ref()),
        "95fc70558378fcd4b3a8e1fd1c5b5177f386375e1ca4144d7b263944c4115ee9"
    );
    assert_eq!(
        hex::encode(schema_fingerprint(semantic).unwrap().as_ref()),
        "c4168c21568c3d022a1d8fb983c148d19ef2491b40762c4012c4511a6b3feedf"
    );
}

#[test]
fn musubi_availability_uses_its_semantic_anchor_while_publication_binds_full_row() {
    use iroha_data_model::musubi::{
        ArchiveId, MusubiArchiveAvailabilityV1, MusubiStorageAvailabilityV1,
    };

    let world = World::default();
    let archive_id = ArchiveId::new([0x41; 32]);
    let original = MusubiArchiveAvailabilityV1 {
        archive_id,
        availability: MusubiStorageAvailabilityV1::Unavailable,
        healthy_replicas: 0,
        active_locations: 0,
        finalized_height: 7,
        finalized_block_hash: [0x42; 32],
        index_revision: 9,
    };
    original.validate().unwrap();
    let mut first = world.block();
    first
        .musubi_archive_availability
        .insert(archive_id, original);
    first.commit();

    let mut second = world.block();
    let accumulator = WorldStateAccumulator::capture(&second).unwrap();
    let before_publication = second.publication_state_delta().unwrap();
    let mut derived_change = original;
    derived_change.availability = MusubiStorageAvailabilityV1::BelowQuorum;
    derived_change.healthy_replicas = 1;
    derived_change.active_locations = 1;
    derived_change.validate().unwrap();
    second
        .musubi_archive_availability
        .insert(archive_id, derived_change);
    let after = WorldStateAccumulator::capture(&second).unwrap();
    assert_eq!(after.root(), accumulator.root());
    assert_eq!(
        accumulator.apply_block(&second).unwrap().root(),
        after.root()
    );
    assert_ne!(
        second.publication_state_delta().unwrap(),
        before_publication
    );

    let mut new_anchor = derived_change;
    new_anchor.index_revision += 1;
    second
        .musubi_archive_availability
        .insert(archive_id, new_anchor);
    assert_ne!(
        WorldStateAccumulator::capture(&second).unwrap().root(),
        accumulator.root()
    );
}

/// Per-block cost is proportional to the change set, not to the World: a block that touches
/// ten entries of a large World updates the accumulator far faster than a cold capture, and
/// only the touched values are encoded.
#[test]
fn per_block_cost_is_proportional_to_the_change_set() {
    const ENTRIES: usize = 20_000;
    const TOUCHED: usize = 10;
    let world = World::default();
    {
        let mut setup = world.block();
        for index in 0..ENTRIES {
            setup
                .smart_contract_state
                .insert(path(&format!("large/{index}")), vec![7; 64]);
        }
        setup.commit();
    }
    let started = Instant::now();
    let parent = WorldStateAccumulator::capture(&world.block()).unwrap();
    let cold = started.elapsed();
    let mut block = world.block();
    for index in 0..TOUCHED {
        block
            .smart_contract_state
            .insert(path(&format!("large/{index}")), vec![8; 64]);
    }
    let started = Instant::now();
    let incremental = parent.apply_block(&block).unwrap();
    let per_block = started.elapsed();
    assert_eq!(
        incremental.root(),
        WorldStateAccumulator::capture(&block).unwrap().root()
    );
    println!(
        "world state accumulator: cold capture of {ENTRIES} entries {cold:?}, \
         block touching {TOUCHED} entries {per_block:?}"
    );
    assert!(
        per_block * 20 < cold,
        "incremental update ({per_block:?}) must not scale with the World ({cold:?})"
    );
}
