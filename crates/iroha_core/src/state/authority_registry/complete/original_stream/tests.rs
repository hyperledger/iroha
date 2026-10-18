//! Real original State journals, complete coverage and exact refusal custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{block::BlockHeader, prelude::TransactionEntrypoint};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly as _;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
};

fn state() -> State {
    State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header(height: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(height).unwrap(), None, None, 1, 0)
}
fn limits() -> CaptureLimits {
    CaptureLimits {
        max_fields: 1024,
        max_rows: 100_000,
        max_payload_bytes: 8 * 1024 * 1024,
        max_total_payload_bytes: 64 * 1024 * 1024,
        max_source_visits: 1_000_000,
    }
}
fn path(value: &str) -> StatePath {
    value.parse().unwrap()
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn find<'a>(output: &'a Collector, id: &str) -> &'a FieldBytes {
    output
        .fields
        .as_slice()
        .iter()
        .find(|field| field.id == id)
        .unwrap()
}
fn values(field: &FieldBytes) -> BTreeMap<Vec<u8>, Vec<u8>> {
    field
        .current
        .as_slice()
        .iter()
        .map(|row| {
            (
                row.key.bytes().to_vec(),
                row.value.as_ref().unwrap().bytes().to_vec(),
            )
        })
        .collect()
}
fn append_native(block: &StateBlock<'_>, output: &mut Collector) -> Result<(), CaptureError> {
    output.storage(
        "world.smart_contract_state",
        &block.world.smart_contract_state,
        &block.state_ref.world.smart_contract_state,
        block.world.parameters.mode(),
        bare,
    )
}

#[test]
fn actual_world_inventory_has_exact_canonical_coverage_including_empty_tables() {
    let state = state();
    let mut block = state.block(header(1));
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    world::append(&block, &mut output).unwrap();
    let mut expected = Vec::new();
    visit(
        crate::state::authority_registry::WORLD_FIELDS,
        &mut |field| {
            if matches!(
                field.role,
                Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_))
            ) {
                expected.push(field.id);
            }
        },
    );
    let mut actual: Vec<_> = output
        .fields
        .as_slice()
        .iter()
        .map(|field| field.id)
        .collect();
    expected.sort_unstable();
    actual.sort_unstable();
    assert_eq!(actual, expected);
    assert!(
        output
            .fields
            .as_slice()
            .iter()
            .any(|field| field.current.as_slice().is_empty())
    );
    assert!(matches!(
        output.require_complete(),
        Err(CaptureError::Missing(_))
    ));
}

#[test]
fn actual_table_insert_delete_noop_and_absent_undo_replay_exactly_once() {
    let state = state();
    let changed = path("stream/changed");
    let removed = path("stream/removed");
    let unchanged = path("stream/unchanged");
    let absent = path("stream/absent");
    {
        let mut original = state.world.smart_contract_state.block();
        original.insert(changed.clone(), vec![1]);
        original.insert(removed.clone(), vec![2]);
        original.insert(unchanged.clone(), vec![3]);
        original.commit();
    }
    let before: BTreeMap<_, _> = state
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
        .insert(unchanged.clone(), vec![3]);
    block.world.smart_contract_state.remove(removed.clone());
    block.world.smart_contract_state.remove(absent.clone());
    block.world.smart_contract_state.insert(path("z"), vec![9]);
    block
        .world
        .smart_contract_state
        .insert(path("longer/key"), vec![10]);
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    append_native(&block, &mut output).unwrap();
    let field = find(&output, "world.smart_contract_state");
    assert!(
        field
            .current
            .as_slice()
            .windows(2)
            .all(|pair| pair[0].key.bytes() < pair[1].key.bytes())
    );
    assert!(
        field
            .undo
            .as_slice()
            .windows(2)
            .all(|pair| pair[0].key.bytes() < pair[1].key.bytes())
    );
    let key = norito::codec::encode_adaptive(&changed);
    let undo = field
        .undo
        .as_slice()
        .iter()
        .filter(|row| row.key.bytes() == key)
        .collect::<Vec<_>>();
    assert_eq!(
        undo.len(),
        1,
        "multiple writes keep one actual original preimage"
    );
    assert_eq!(
        undo[0].value.as_ref().unwrap().bytes(),
        norito::codec::encode_adaptive(&vec![1u8])
    );
    assert!(field.undo.as_slice().iter().any(|row| row.key.bytes()
        == norito::codec::encode_adaptive(&absent)
        && row.value.is_none()));
    let unchanged_key = norito::codec::encode_adaptive(&unchanged);
    assert!(
        field
            .undo
            .as_slice()
            .iter()
            .any(|row| row.key.bytes() == unchanged_key
                && row.value.as_ref().unwrap().bytes()
                    == norito::codec::encode_adaptive(&vec![3u8]))
    );
    let mut replay = before;
    for undo in field.undo.as_slice() {
        let key = undo.key.bytes();
        let existing = replay.get(key).map(Vec::as_slice);
        assert_eq!(existing, undo.value.as_ref().map(Frame::bytes));
        match field
            .current
            .as_slice()
            .binary_search_by(|row| row.key.bytes().cmp(key))
        {
            Ok(index) => {
                replay.insert(
                    key.to_vec(),
                    field.current.as_slice()[index]
                        .value
                        .as_ref()
                        .unwrap()
                        .bytes()
                        .to_vec(),
                );
            }
            Err(_) => {
                replay.remove(key);
            }
        }
    }
    assert_eq!(replay, values(field));
}

#[test]
fn actual_cell_equal_touch_keeps_its_original_preimage() {
    let state = state();
    let mut block = state.block(header(1));
    let before = *block.world.soradns_last_publish_ms.get();
    *block.world.soradns_last_publish_ms.get_mut() = before;
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    output
        .cell(
            "world.soradns_last_publish_ms",
            &block.world.soradns_last_publish_ms,
            &state.world.soradns_last_publish_ms,
            block.world.parameters.mode(),
            bare,
        )
        .unwrap();
    let field = find(&output, "world.soradns_last_publish_ms");
    assert_eq!(field.current.as_slice().len(), 1);
    assert_eq!(field.undo.as_slice().len(), 1);
    assert!(field.current.as_slice()[0].key.bytes().is_empty());
    assert_eq!(
        field.current.as_slice()[0].value.as_ref().unwrap().bytes(),
        field.undo.as_slice()[0].value.as_ref().unwrap().bytes()
    );
    assert_eq!(
        norito::codec::decode_exact_from_slice::<Option<u64>>(
            field.current.as_slice()[0].value.as_ref().unwrap().bytes()
        )
        .unwrap(),
        before
    );
}

#[test]
fn registry_rejects_missing_extra_duplicate_and_changed_original_sources() {
    let other = state();
    let state = state();
    let mut block = state.block(header(1));
    let mut foreign = other.block(header(1));
    freeze(&mut block);
    freeze(&mut foreign);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    append_native(&block, &mut output).unwrap();
    assert!(matches!(
        append_native(&block, &mut output),
        Err(CaptureError::Duplicate("world.smart_contract_state"))
    ));
    output.fields.as_mut_slice()[0].seen = false;
    assert!(matches!(
        append_native(&foreign, &mut output),
        Err(CaptureError::Changed("world.smart_contract_state"))
    ));
    assert!(matches!(
        output.require_complete(),
        Err(CaptureError::Missing(_))
    ));
    assert!(matches!(
        output.begin("world.unknown", SourceIdentity::Policy(0), 0, 0),
        Err(CaptureError::Unexpected("world.unknown"))
    ));
    assert!(matches!(
        output.begin("world.state_accumulator", SourceIdentity::Policy(0), 0, 0),
        Err(CaptureError::Unexpected("world.state_accumulator"))
    ));
}

#[test]
fn allocation_refusal_retains_the_actual_partial_key_and_original_pool_for_retry() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header(1));
    block
        .world
        .smart_contract_state
        .insert(path("stream/large"), vec![7; 4096]);
    freeze(&mut block);
    let mut output = Collector::new(budget.clone(), limits()).unwrap();
    let original_limit = budget.limit_bytes();
    let initial = budget.reserved_bytes();
    let image = block.world.smart_contract_state.frozen_images().unwrap();
    let first_key_size =
        norito::codec::encode_adaptive(image.current_entries().next().unwrap().0).len();
    let backing =
        (image.current_entries().len() + image.undo_entries().len()) * std::mem::size_of::<Row>();
    budget.set_limit_bytes(initial + backing + first_key_size);
    assert!(matches!(
        append_native(&block, &mut output),
        Err(CaptureError::Allocation(ChargedBufferError::Admission(
            AllocationRefusal::ExceedsLimit { .. } | AllocationRefusal::Capacity { .. }
        )))
    ));
    let pending = output.pending.as_ref().unwrap();
    let retained_key = pending.key.as_ref().unwrap().bytes().as_ptr();
    let source = block.world.smart_contract_state.publication_identity();
    assert_eq!(&pending.source, &SourceIdentity::Journal(source));
    budget.set_limit_bytes(original_limit);
    append_native(&block, &mut output).unwrap();
    let field = find(&output, "world.smart_contract_state");
    assert!(
        field
            .current
            .as_slice()
            .iter()
            .any(|row| row.key.bytes().as_ptr() == retained_key)
    );
    drop(output);
    assert_eq!(
        budget.reserved_bytes(),
        initial
            - std::mem::size_of::<FieldBytes>() * {
                let mut count = 0;
                visit(STATE_FIELDS, &mut |field| {
                    if matches!(
                        field.role,
                        Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_))
                    ) {
                        count += 1;
                    }
                });
                count
            }
    );
}

#[test]
fn canonical_frames_roundtrip_under_explicit_v1_flags_and_refuse_changed_bytes() {
    let budget = AllocationBudget::new(1024 * 1024);
    let value = vec!["a".to_owned(), "日本語".to_owned()];
    let frame = Frame::encode(&value, limits(), &budget).unwrap();
    assert_eq!(frame.bytes(), norito::codec::encode_adaptive(&value));
    assert_eq!(
        norito::codec::decode_exact_from_slice::<Vec<String>>(frame.bytes()).unwrap(),
        value
    );
    let calls = std::cell::Cell::new(0);
    let result = Frame::from_writer(8, &budget, |writer| {
        let call = calls.get();
        calls.set(call + 1);
        writer.write_all(if call == 0 { b"ab" } else { b"cd" })?;
        Ok(())
    });
    assert!(matches!(result, Err(CaptureError::EncodingChanged)));
    assert_eq!(calls.get(), 2);
    let result = Frame::from_writer(1, &budget, |writer| {
        writer.write_all(b"ab")?;
        Ok(())
    });
    assert!(matches!(result, Err(CaptureError::PayloadLimit)));
}

fn key(n: u8) -> HashOf<TransactionEntrypoint> {
    HashOf::from_untyped_unchecked(Hash::new([n]))
}
fn commit_membership(state: &State, height: usize, keys: &[HashOf<TransactionEntrypoint>]) {
    let mut writer = state.transactions.block();
    writer.insert_block(
        keys.iter().copied().collect(),
        NonZeroUsize::new(height).unwrap(),
    );
    writer.commit().unwrap();
}
#[test]
fn empty_membership_replacement_clears_every_old_row_and_keeps_pair_separate() {
    let state = state();
    let mut block = state.block(header(1));
    block
        .transactions
        .insert_block(Default::default(), NonZeroUsize::MIN);
    block.transactions.try_prepare_publication().unwrap();
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    membership::append(&block, &mut output).unwrap();
    for id in ["state.transactions.current", "state.transactions.rollback"] {
        let field = find(&output, id);
        assert!(field.replacement);
        assert!(field.current.as_slice().is_empty());
        let mut consumer = BTreeMap::from([(vec![99], vec![99])]);
        if field.replacement {
            consumer.clear();
        }
        consumer.extend(values(field));
        assert!(consumer.is_empty());
    }
    assert!(!find(&output, "state.transactions.frontier").replacement);
}

#[test]
fn repeated_membership_retains_equal_frontier_preimage_once() {
    let state = state();
    commit_membership(&state, 1, &[key(1)]);
    let mut block = state.block(header(1));
    block
        .transactions
        .insert_block([key(1)].into_iter().collect(), NonZeroUsize::MIN);
    block.transactions.try_prepare_publication().unwrap();
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    membership::append(&block, &mut output).unwrap();
    let frontier = find(&output, "state.transactions.frontier");
    assert_eq!(frontier.current.as_slice().len(), 1);
    assert_eq!(frontier.undo.as_slice().len(), 1);
    let current = frontier.current.as_slice()[0]
        .value
        .as_ref()
        .unwrap()
        .bytes();
    let before = frontier.undo.as_slice()[0].value.as_ref().unwrap().bytes();
    assert_eq!(current, before);
    assert_eq!(
        norito::codec::decode_exact_from_slice::<u64>(before).unwrap(),
        1
    );
}

#[test]
fn replacement_membership_shrinks_current_and_retains_exact_distinct_rollback() {
    let state = state();
    commit_membership(&state, 1, &[key(1)]);
    commit_membership(&state, 2, &[key(2)]);
    let mut block = state.block_and_revert(header(2));
    block.transactions.insert_block(
        [key(3)].into_iter().collect(),
        NonZeroUsize::new(2).unwrap(),
    );
    block.transactions.try_prepare_publication().unwrap();
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    membership::append(&block, &mut output).unwrap();
    let current = values(find(&output, "state.transactions.current"));
    let rollback = values(find(&output, "state.transactions.rollback"));
    assert_eq!(current.len(), 2);
    assert_eq!(rollback.len(), 1);
    assert!(current.contains_key(&norito::codec::encode_adaptive(&key(3))));
    assert!(!current.contains_key(&norito::codec::encode_adaptive(&key(2))));
    assert!(rollback.contains_key(&norito::codec::encode_adaptive(&key(1))));
    assert!(!rollback.contains_key(&norito::codec::encode_adaptive(&key(3))));
}

fn validated_original(state: &State, header: BlockHeader) -> Box<StateBlock<'_>> {
    validated_original_with_crypto_source(state, header, false)
}

fn validated_original_with_crypto_source(
    state: &State,
    header: BlockHeader,
    replace_live: bool,
) -> Box<StateBlock<'_>> {
    use crate::state::deserialize::musubi_source_read::ReadFailure;
    use crate::state::publication::{
        RetainedMusubiGroupReadError, RetainedPackageReadError,
        musubi_materializer_test_support::{staged_block, start},
    };
    let mut block = Box::new(staged_block(state, header, false, true));
    let owner = std::ptr::from_ref(block.runtime_policy.static_inputs()) as usize;
    let captured_crypto = std::sync::Arc::clone(&block.crypto);
    if replace_live {
        state.install_crypto_snapshot_for_isolated_replay((*captured_crypto).clone());
        assert!(!std::sync::Arc::ptr_eq(&state.crypto(), &captured_crypto));
        let mut foreign = (*captured_crypto).clone();
        foreign.sm2_distid_default.push_str("-foreign");
        state.install_crypto_snapshot_for_isolated_replay(foreign);
        assert_ne!(
            state.crypto().sm2_distid_default,
            captured_crypto.sm2_distid_default
        );
    }
    assert!(std::sync::Arc::ptr_eq(&block.crypto, &captured_crypto));
    // This complete-State fixture includes the monetary authority that an
    // authenticated genesis installs; bootstrap is only the original undo.
    let fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(iroha_data_model::parameter::Parameter::Custom(
            fees.into_custom_parameter().unwrap(),
        ))
        .unwrap();
    let budget = state.ivm_execution_budget();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        block.try_publish(),
        crate::state::StatePublicationOutcome::Deferred(
            crate::state::storage_transactions::TransactionsBlockError::ExecutionDeferred(_)
        )
    ));
    drop(occupied);
    assert_eq!(
        std::ptr::from_ref(block.runtime_policy.static_inputs()) as usize,
        owner
    );
    assert!(std::sync::Arc::ptr_eq(&block.crypto, &captured_crypto));
    assert!(
        OriginalCut::new(&block, limits()).is_err(),
        "unchecked group never becomes a complete cut"
    );
    start(&mut block, &state.ivm_execution_budget());
    let mut complete = false;
    for _ in 0..256 {
        match block.advance_configured_original_musubi_validation() {
            Ok(()) => {
                complete = true;
                break;
            }
            Err(ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original: RetainedPackageReadError::Work { .. },
                ..
            })) => {}
            Err(error) => panic!("original source validation: {error:?}"),
        }
    }
    assert!(complete);
    block.retire_original_musubi_group_read().unwrap();
    // The first publication attempt already admitted and detached this original
    // membership action. Rejoin its frozen writer exactly as StatePublication
    // does; logical admission is one-shot and must never be repeated.
    assert!(block.transactions.prepared_membership_writer().is_none());
    let membership = &mut block.fields.as_mut().unwrap().transactions;
    membership.install_frozen_publication(&state.transactions);
    membership.try_prepare_frozen_publication().unwrap();
    assert!(
        membership
            .prepared_membership_writer()
            .unwrap()
            .belongs_to(&state.transactions)
    );
    assert_eq!(
        std::ptr::from_ref(block.runtime_policy.static_inputs()) as usize,
        owner
    );
    assert!(std::sync::Arc::ptr_eq(&block.crypto, &captured_crypto));
    block
}

#[test]
fn complete_original_fixture_covers_every_table_and_all_cells() {
    let (state, proposal) = crate::state::publication::musubi_materializer_test_support::fixture();
    let block = validated_original(&state, proposal.header());
    let mut cut = OriginalCut::new(&block, limits()).unwrap();
    cut.advance().unwrap();
    let mut identities = Vec::new();
    cut.visit(
        |id, _| {
            identities.push(id);
            Ok::<_, core::convert::Infallible>(())
        },
        |_, _, _| Ok(()),
    )
    .unwrap();
    let mut expected = Vec::new();
    visit(STATE_FIELDS, &mut |field| {
        if matches!(
            field.role,
            Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_))
        ) {
            expected.push(field.id);
        }
    });
    expected.sort_unstable();
    assert_eq!(identities, expected);
    let addresses: Vec<_> = cut
        .collector
        .fields
        .as_slice()
        .iter()
        .flat_map(|field| {
            field
                .current
                .as_slice()
                .iter()
                .map(|row| row.key.bytes().as_ptr())
        })
        .collect();
    cut.advance().unwrap();
    let retried: Vec<_> = cut
        .collector
        .fields
        .as_slice()
        .iter()
        .flat_map(|field| {
            field
                .current
                .as_slice()
                .iter()
                .map(|row| row.key.bytes().as_ptr())
        })
        .collect();
    assert_eq!(addresses, retried);
    // Consume the real insertion stream, not only the replacement notifications.
    // This registry starts empty in the original State and is populated by the
    // existing validated Musubi fixture before its frozen cut is captured.
    assert!(state.world.musubi_namespace_bindings.view().is_empty());
    let expected_bindings: BTreeMap<_, _> = block
        .world
        .musubi_namespace_bindings
        .iter()
        .map(|(key, value)| {
            (
                norito::codec::encode_adaptive(key),
                norito::codec::encode_adaptive(value),
            )
        })
        .collect();
    assert!(!expected_bindings.is_empty());
    let mut actual_bindings = BTreeMap::new();
    let mut replacements = Vec::new();
    cut.changes(
        |id| {
            replacements.push(id);
            Ok::<_, core::convert::Infallible>(())
        },
        |id, change| {
            if id == "world.musubi_namespace_bindings" {
                assert!(change.before.is_none());
                assert!(
                    actual_bindings
                        .insert(change.key.to_vec(), change.after.unwrap().to_vec())
                        .is_none(),
                    "one original insertion per canonical namespace key"
                );
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(actual_bindings, expected_bindings);
    assert_eq!(
        replacements,
        ["state.transactions.current", "state.transactions.rollback"]
    );
    let row_visits = std::cell::Cell::new(0);
    assert!(matches!(
        cut.visit(
            |_, _| Err("retain field refused"),
            |_, _, _| {
                row_visits.set(row_visits.get() + 1);
                Ok(())
            }
        ),
        Err(VisitError::Consumer("retain field refused"))
    ));
    assert_eq!(row_visits.get(), 0);
    assert!(matches!(
        cut.changes(
            |_| Err("clear refused"),
            |id, _| {
                assert!(!id.starts_with("state.transactions."));
                Ok(())
            }
        ),
        Err(VisitError::Consumer("clear refused"))
    ));
    // Direct target drift cannot turn a retained stream into another original.
    let bytes_before = addresses;
    {
        let mut changed = state.world.smart_contract_state.block();
        changed.insert(path("foreign/write"), vec![99]);
        changed.commit();
    }
    assert!(matches!(
        cut.visit(|_, _| Ok::<_, ()>(()), |_, _, _| Ok(())),
        Err(VisitError::Source(CaptureError::Changed(
            "world.smart_contract_state"
        )))
    ));
    let bytes_after: Vec<_> = cut
        .collector
        .fields
        .as_slice()
        .iter()
        .flat_map(|field| {
            field
                .current
                .as_slice()
                .iter()
                .map(|row| row.key.bytes().as_ptr())
        })
        .collect();
    assert_eq!(bytes_before, bytes_after);
}

#[test]
fn validated_publication_refuses_foreign_manifest_rebinding_and_runtime_target_advance() {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };
    let (state, proposal) = crate::state::publication::musubi_materializer_test_support::fixture();
    let mut block = validated_original(&state, proposal.header());
    let original = Arc::clone(&block.lane_manifests);
    let foreign = Arc::new(original.rebind(&block.nexus.lane_catalog, &block.nexus.governance));
    assert!(!Arc::ptr_eq(&original, &foreign));
    assert_eq!(
        original
            .canonical_materialized_authority_preimage(
                &block.nexus.lane_catalog,
                &block.nexus.governance
            )
            .unwrap(),
        foreign
            .canonical_materialized_authority_preimage(
                &block.nexus.lane_catalog,
                &block.nexus.governance
            )
            .unwrap()
    );
    // The existing publication owner rejects the substitution before any write.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            block.lane_manifests = foreign;
        }))
        .is_err()
    );
    assert!(Arc::ptr_eq(&original, &block.lane_manifests));
    let catalog = block.nexus.lane_catalog.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            block.nexus.lane_catalog = catalog;
        }))
        .is_err()
    );
    let mut cut = OriginalCut::new(&block, limits()).unwrap();
    cut.advance().unwrap();
    let retained = values(find(&cut.collector, "runtime.lanes"));
    // A new publication with equal payload still changes the exact original
    // target identity. A plausible catalog cannot authorize this old cut.
    {
        let mut target = state.canonical_runtime.block();
        let same = target.get().clone();
        *target.get_mut() = same;
        target.commit();
    }
    assert!(matches!(
        cut.advance(),
        Err(CaptureError::Changed("state.canonical_runtime"))
    ));
    assert_eq!(retained, values(find(&cut.collector, "runtime.lanes")));
}

#[test]
fn direct_target_advance_refuses_the_retained_cut_instead_of_recapturing_values() {
    let state = state();
    let mut block = state.block(header(1));
    block
        .world
        .smart_contract_state
        .insert(path("original/value"), vec![1]);
    freeze(&mut block);
    let mut output = Collector::new(state.ivm_execution_budget(), limits()).unwrap();
    append_native(&block, &mut output).unwrap();
    let original = values(find(&output, "world.smart_contract_state"));
    {
        let mut intervening = state.world.smart_contract_state.block();
        intervening.insert(path("different/publication"), vec![2]);
        intervening.commit();
    }
    output.fields.as_mut_slice()[0].seen = false;
    assert!(matches!(
        append_native(&block, &mut output),
        Err(CaptureError::Changed("world.smart_contract_state"))
    ));
    assert_eq!(
        values(find(&output, "world.smart_contract_state")),
        original
    );
}

#[test]
fn field_and_row_admission_precede_canonical_backing() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let mut denied = limits();
    denied.max_fields = 0;
    assert!(matches!(
        Collector::new(budget.clone(), denied),
        Err(CaptureError::CountLimit)
    ));
    assert_eq!(before, budget.reserved_bytes());
    let mut block = state.block(header(1));
    freeze(&mut block);
    denied = limits();
    denied.max_rows = 0;
    let mut output = Collector::new(budget.clone(), denied).unwrap();
    let before = budget.reserved_bytes();
    assert!(matches!(
        append_native(&block, &mut output),
        Err(CaptureError::CountLimit)
    ));
    assert_eq!(before, budget.reserved_bytes());
    assert!(output.pending.is_none());
}

#[test]
fn original_static_input_survives_prepublication_foreign_source_and_deferred_cut_retry() {
    let (state, proposal) = crate::state::publication::musubi_materializer_test_support::fixture();
    let expected = state.crypto();
    let block = validated_original_with_crypto_source(&state, proposal.header(), true);
    let owner = std::ptr::from_ref(block.runtime_policy.static_inputs());
    let mut cut = OriginalCut::new(&block, limits()).unwrap();
    cut.advance().unwrap();
    let field = find(&cut.collector, "state.crypto");
    assert!(field.undo.as_slice().is_empty());
    let bytes = field.current.as_slice()[0]
        .value
        .as_ref()
        .unwrap()
        .bytes()
        .to_vec();
    let expected_policy =
        crate::state::authority_registry::crypto_policy::CryptoAdmissionPolicyV1::from_actual(
            &expected,
        );
    assert_eq!(bytes, norito::codec::encode_adaptive(&expected_policy));
    let foreign_policy =
        crate::state::authority_registry::crypto_policy::CryptoAdmissionPolicyV1::from_actual(
            &state.crypto(),
        );
    assert_ne!(bytes, norito::codec::encode_adaptive(&foreign_policy));
    assert!(std::sync::Arc::ptr_eq(&block.crypto, &expected));
    assert_ne!(
        state.crypto().sm2_distid_default,
        block.crypto.sm2_distid_default
    );
    cut.advance().unwrap();
    assert_eq!(
        std::ptr::from_ref(block.runtime_policy.static_inputs()),
        owner
    );
    assert_eq!(
        find(&cut.collector, "state.crypto").current.as_slice()[0]
            .value
            .as_ref()
            .unwrap()
            .bytes(),
        bytes
    );
}

#[test]
fn world_and_membership_share_physical_traversal_admission_on_first_pass_and_retry() {
    let state = state();
    {
        let mut original = state.world.smart_contract_state.block();
        for n in 0..80 {
            original.insert(path(&format!("physical/{n}")), vec![1]);
        }
        original.commit();
    }
    let mut block = state.block(header(1));
    block
        .transactions
        .insert_block((0..10).map(key).collect(), NonZeroUsize::MIN);
    block.transactions.try_prepare_publication().unwrap();
    freeze(&mut block);
    let native = block.world.smart_contract_state.frozen_images().unwrap();
    let native_visits = native.current_entries().len() + native.undo_entries().len();
    assert!(
        native_visits >= 80,
        "all seeded rows and authoritative defaults remain"
    );
    let mut bound = limits();
    bound.max_source_visits = 100;
    assert!(native_visits + 10 <= bound.max_source_visits);
    assert!(native_visits + 20 > bound.max_source_visits);
    let mut output = Collector::new(state.ivm_execution_budget(), bound).unwrap();
    append_native(&block, &mut output).unwrap();
    assert_eq!(output.source_visits, native_visits);
    assert!(matches!(
        membership::append(&block, &mut output),
        Err(CaptureError::CountLimit)
    ));
    assert_eq!(
        output.source_visits,
        native_visits + 10,
        "current-membership emission was refused before its original scan"
    );
    assert!(
        output.rows < bound.max_rows,
        "physical work, not retained rows, exhausted"
    );
    let retained = find(&output, "world.smart_contract_state")
        .current
        .as_slice()[0]
        .key
        .bytes()
        .as_ptr();
    output.start_traversal();
    append_native(&block, &mut output).unwrap();
    assert_eq!(
        output.source_visits, 0,
        "completed World bytes do not rescan their original rows"
    );
    membership::append(&block, &mut output).unwrap();
    assert_eq!(
        output.source_visits, 32,
        "recount, both pending filtered scans, current/undo frontier"
    );
    assert_eq!(
        find(&output, "world.smart_contract_state")
            .current
            .as_slice()[0]
            .key
            .bytes()
            .as_ptr(),
        retained
    );
    output.start_traversal();
    append_native(&block, &mut output).unwrap();
    membership::append(&block, &mut output).unwrap();
    assert_eq!(
        output.source_visits, 10,
        "even a complete retry admits its membership recount"
    );

    let complete_visits = native_visits + 3 * 10 + 2;
    bound.max_source_visits = complete_visits - 1;
    let mut short = Collector::new(state.ivm_execution_budget(), bound).unwrap();
    append_native(&block, &mut short).unwrap();
    assert!(matches!(
        membership::append(&block, &mut short),
        Err(CaptureError::CountLimit)
    ));
    assert_eq!(
        short.source_visits,
        native_visits + 3 * 10,
        "both frontier values are admitted together before either is encoded"
    );
    bound.max_source_visits = complete_visits;
    let mut exact = Collector::new(state.ivm_execution_budget(), bound).unwrap();
    append_native(&block, &mut exact).unwrap();
    membership::append(&block, &mut exact).unwrap();
    assert_eq!(
        exact.source_visits, complete_visits,
        "all original World rows + three 10-row scans + two frontier values"
    );
}
