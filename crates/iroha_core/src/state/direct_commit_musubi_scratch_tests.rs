//! Direct State commit preserves local Musubi scratch refusal and original retry custody.
//!
//! These controls reuse the real four-validator genesis fixture and the existing
//! validated Musubi publication fixture. They exercise the consuming commit path;
//! they do not fabricate a finality permit or replace consensus/DA validation.

use super::fixture;
use crate::state::{State, StateBlock, WorldBlock, deserialize, storage_transactions};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{block::BlockHeader, musubi::MusubiOrderedPackageEntryV1};
use mv::storage::StorageReadOnly;
use std::{
    collections::HashSet,
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn stage_musubi(world: &mut WorldBlock<'_>) {
    let seeded = deserialize::seeded_musubi_publication_world_for_testing();
    // Copy the existing fixture's complete populated registry, retaining the
    // real State's genesis accounts, runtime catalog and other authority tables.
    macro_rules! copy_rows {
        ($($field:ident),+ $(,)?) => { $(
            for (key, value) in seeded.$field.view().iter() {
                world.$field.insert(key.clone(), value.clone());
            }
        )+ };
    }
    copy_rows!(
        musubi_namespace_bindings,
        musubi_package_members,
        musubi_maintainer_directory,
        musubi_package_metadata,
        musubi_packages,
        musubi_archives,
        musubi_archive_availability,
        musubi_archive_reverse_references,
        musubi_releases,
        musubi_resolver_index,
        musubi_public_directory,
    );
    *world.musubi_resolver_index_revision.get_mut() =
        *seeded.musubi_resolver_index_revision.view().get();
    *world.musubi_replication_shortfall_releases.get_mut() =
        *seeded.musubi_replication_shortfall_releases.view().get();
}

pub(super) fn staged_block(
    state: &State,
    header: BlockHeader,
    replacement: bool,
    populate: bool,
) -> StateBlock<'_> {
    let mut block = if replacement {
        state.block_and_revert_with_pristine_stage(header, |_| Ok::<(), &'static str>(()))
    } else {
        state.block_with_pristine_stage(header, |_| Ok::<(), &'static str>(()))
    }
    .unwrap_or_else(|error| panic!("actual State block start: {error:?}"));
    if populate {
        stage_musubi(&mut block.world);
    }
    // The original direct-commit fixture stages these exact empty membership and
    // header records. None of the production publication guards are bypassed.
    block.finalize_axt_asset_incarnations().unwrap();
    block.transactions.insert_block(
        HashSet::new(),
        NonZeroUsize::new(usize::try_from(header.height().get()).unwrap()).unwrap(),
    );
    block.transactions.validate_commit().unwrap();
    block.block_hashes.push(header.hash());
    block.verify_execution_output_publication().unwrap();
    block.validate_canonical_runtime_projection().unwrap();
    block.verify_sumeragi_lane_state_publication().unwrap();
    block
}

#[test]
fn direct_state_musubi_scratch_refusal_preserves_world_metadata_and_original_retry_owner() {
    // The global EBR collector also protects readers in unrelated parallel tests.
    // Keep this exact retirement accounting independent of their pin lifetimes.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::direct_state_musubi_scratch_refusal_preserves_world_metadata_and_original_retry_owner",
    ) {
        return;
    }
    check_direct_refusal(false);
}

#[test]
fn replacement_state_musubi_scratch_refusal_preserves_published_predecessor_then_retries() {
    // The global EBR collector also protects readers in unrelated parallel tests.
    // Keep this exact retirement accounting independent of their pin lifetimes.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::replacement_state_musubi_scratch_refusal_preserves_published_predecessor_then_retries",
    ) {
        return;
    }
    check_direct_refusal(true);
}

fn check_direct_refusal(replacement: bool) {
    let (state, proposal) = fixture();
    let header = proposal.header();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let initial_reserved = budget.reserved_bytes();
    let successor_bytes = original_cell_successor_bytes(&state);
    let [scalar_current, scalar_undo] =
        mv::cell::Cell::<u64, iroha_allocation::AllocationCharge>::allocation_layouts();
    let [amx_current, amx_undo] = mv::cell::Cell::<
        crate::sumeragi::amx::RetainedNativeAmx,
        iroha_allocation::AllocationCharge,
    >::allocation_layouts();
    let amx_stage = amx_current.size()
        + amx_undo.size()
        + mv::cell::CellPublicationSuccessor::allocation_layout().size();

    if replacement {
        // Establish a genuine published predecessor. The replacement takes the
        // original journals' rollback path, rather than reverting an empty State.
        staged_block(&state, header, false, false)
            .commit()
            .expect("original empty carrier publishes");
        // Empty ordinary publication changes every identity and scalar undo,
        // but keeps the untouched scalar current in its original foreign pool.
        // Settle the retired tip undo before taking the retry baseline.
        collect_original_ebr_until(
            &budget,
            initial_reserved + successor_bytes - amx_stage - scalar_current.size(),
        );
    }
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let before_height = state.transactions.latest_height();
    let before_hash = state.latest_block_hash_fast();
    let before_committed_height = state.committed_height();
    let before_kura_count = state.kura.blocks_count();
    assert!(state.world.musubi_public_directory.view().is_empty());
    let before_reserved = budget.reserved_bytes();
    let block = staged_block(&state, header, replacement, true);
    let original_staged_bytes = budget.reserved_bytes() - before_reserved;
    assert_eq!(
        original_staged_bytes,
        core::mem::size_of::<crate::state::WorldBlockFields<'_>>()
            + successor_bytes
            + original_native_tip_stage_bytes(),
        "the actual World shell, complete Cell tokens and charged native tip generations are retained",
    );
    let requested_bytes = core::mem::size_of::<&MusubiOrderedPackageEntryV1>();
    assert_eq!(block.world.musubi_public_directory.len(), 1);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(occupied.belongs_to(&state.ivm_execution_budget()));
    let expected = budget.try_reserve_bytes(requested_bytes).unwrap_err();
    let result = block.commit();
    let Err(storage_transactions::TransactionsBlockError::ExecutionDeferred(reason)) = result
    else {
        panic!("must reach direct State's local Musubi refusal, got {result:?}");
    };
    let actual = reason.allocation_refusal().expect("typed original refusal");
    // Equality includes the actual release notification owner and generation,
    // not just the numeric demand/limit diagnostics.
    assert_eq!(actual, &expected);
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } = actual else {
        panic!("occupied original pool yields temporary capacity refusal");
    };
    assert_eq!(
        budget.reserved_bytes(),
        before_reserved + occupied.remaining_bytes(),
        "consuming refusal destroys the original shell and all unpublished tokens",
    );
    assert_eq!(
        budget.limit_bytes() - budget.reserved_bytes(),
        original_staged_bytes,
        "only the abandoned original execution allocation is refunded",
    );
    assert_eq!(state.transactions.latest_height(), before_height);
    assert_eq!(state.latest_block_hash_fast(), before_hash);
    assert_eq!(state.committed_height(), before_committed_height);
    assert_eq!(state.kura.blocks_count(), before_kura_count);
    assert!(state.world.musubi_public_directory.view().is_empty());
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
        before
    );
    assert_eq!(state.state_view_generation() % 2, 0);
    drop(
        state
            .state_commit_lock
            .try_lock()
            .expect("commit fence released"),
    );
    drop(
        state
            .state_write_lock
            .try_lock()
            .expect("write fence released"),
    );

    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut context = Context::from_waker(&waker);
    let mut abandoned = release.clone().wait_for_release(&mut registration);
    assert_eq!(
        Pin::new(&mut abandoned).poll(&mut context),
        Poll::Ready(()),
        "consuming commit already returned the actual original allocation capacity",
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    // The consumed owner no longer needs a retry. Probe capacity afresh while
    // the independent occupied reservation still holds this SAME finite pool.
    let fresh_request = budget.limit_bytes() - budget.reserved_bytes() + 1;
    let fresh = budget.try_reserve_bytes(fresh_request).unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity {
        release: fresh_release,
        ..
    } = fresh
    else {
        panic!("the still-occupied original pool refuses more than its free capacity");
    };
    assert_ne!(
        &fresh_release, release,
        "actual abandonment advanced the original source"
    );
    drop(abandoned);
    let mut released = fresh_release.wait_for_release(&mut registration);
    assert_eq!(Pin::new(&mut released).poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(requested_bytes);
    drop(unrelated.try_reserve_bytes(requested_bytes).unwrap());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(Pin::new(&mut released).poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(Pin::new(&mut released).poll(&mut context), Poll::Ready(()));
    assert_eq!(budget.reserved_bytes(), before_reserved);

    // A fresh attempt obtains the real original World/membership writers and
    // completes every semantic/publication guard after the same owner releases.
    let retirement_pin = crossbeam_epoch::pin();
    staged_block(&state, header, replacement, true)
        .commit()
        .expect("retry publishes after original pool release");
    assert_eq!(
        state.transactions.latest_height(),
        header.height().get() as usize
    );
    assert_eq!(state.latest_block_hash_fast(), Some(header.hash()));
    assert_eq!(state.committed_height(), header.height().get() as usize);
    assert_eq!(state.world.musubi_public_directory.view().len(), 1);
    assert_eq!(state.world.musubi_resolver_index.view().len(), 1);
    assert_ne!(
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
        before
    );
    // Populated publication owns both scalar generations in this exact pool.
    // Every untracked Cell adds its funded identity once; native-tip identities
    // and generations replace the already funded initial owners at equal sizes.
    // The native AMX Cell starts in this same pool: its successor replaces the
    // funded identity, and its generations replace the funded initial pair.
    let published_bytes = initial_reserved + successor_bytes - amx_stage;
    let [tip_current, tip_undo] = crate::state::native_execution_tip::TipCell::allocation_layouts();
    let retired_bytes = if replacement {
        // Replace publishes both tip generations. The first empty publication
        // also left its scalar undo in this pool, while its current stayed foreign.
        tip_current.size()
            + tip_undo.size()
            + scalar_undo.size()
            + amx_current.size()
            + amx_undo.size()
    } else {
        // Ordinary unchanged native tip keeps its original current generation.
        tip_undo.size() + amx_undo.size()
    };
    retirement_pin.flush();
    assert_eq!(
        budget.reserved_bytes(),
        published_bytes + retired_bytes,
        "the held epoch prevents refund of every retired original generation",
    );
    drop(retirement_pin);
    collect_original_ebr_until(&budget, published_bytes);
    assert_eq!(
        budget.reserved_bytes(),
        published_bytes,
        "successful publication retains exact identities and current/undo owners after retirement",
    );
    drop(released);
    drop(registration);
    drop(state);
    collect_original_ebr_until(&budget, 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn original_native_tip_stage_bytes() -> usize {
    // The native tip starts with fully funded generations and an identity.
    // Acquisition overlaps two new EBR allocations and one successor token;
    // successful publication replaces equally funded predecessors instead of
    // adding these bytes to the retained first-publication delta below.
    crate::state::native_execution_tip::TipCell::allocation_layouts()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>()
        + mv::cell::CellPublicationSuccessor::allocation_layout().size()
}

fn original_cell_successor_bytes(state: &State) -> usize {
    use crate::state::world_acquisition::OriginalControlSource as _;

    crate::state::world_acquisition::original_world_cell_control_bytes(&state.world)
        + state.canonical_runtime.successor_layout().unwrap().size()
        + state
            .prev_commit_topology
            .successor_layout()
            .unwrap()
            .size()
        + state.commit_topology.successor_layout().unwrap().size()
}

#[test]
fn retained_state_retries_actual_musubi_capacity_without_rebuilding_its_world_tail() {
    use crate::state::StatePublicationOutcome;
    let (state, proposal) = fixture();
    let header = proposal.header();
    let budget = state.ivm_execution_budget();
    let mut block = Box::new(staged_block(&state, header, false, true));
    let owner = std::ptr::from_ref(&*block);
    let original_directory = block
        .world
        .musubi_public_directory
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let mut prepared = None;
    for _ in 0..3 {
        let StatePublicationOutcome::Deferred(
            storage_transactions::TransactionsBlockError::ExecutionDeferred(reason),
        ) = block.try_publish()
        else {
            panic!("real occupied execution pool must defer the original World validator");
        };
        assert!(matches!(
            reason.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::Capacity { .. })
        ));
        assert_eq!(std::ptr::from_ref(&*block), owner);
        let identity = block.publication_identity_for_test();
        assert_ne!(
            identity.0, 0,
            "original World mutation effects retained before pure validation"
        );
        assert_eq!(
            identity.1, 0,
            "snapshot capture follows successful validation"
        );
        assert_eq!(*prepared.get_or_insert(identity), identity);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert!(state.state_commit_lock.try_lock().is_some());
        assert!(state.state_write_lock.try_lock().is_some());
        assert_eq!(
            block
                .world
                .musubi_public_directory
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
            original_directory
        );
        assert!(state.world.musubi_public_directory.view().is_empty());
    }
    // The pending owner cannot admit post-capture writes, even after local deferral.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = &mut block.world;
        }))
        .is_err()
    );
    drop(occupied);
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert!(
        matches!(block.try_publish(), StatePublicationOutcome::Published),
        "completed owner is idempotent"
    );
    drop(block);
    assert_eq!(
        state.transactions.latest_height(),
        header.height().get() as usize
    );
    assert_eq!(state.latest_block_hash_fast(), Some(header.hash()));
    assert_eq!(state.world.musubi_public_directory.view().len(), 1);
}

#[test]
fn retained_state_refuses_changed_publication_generation_without_rebase() {
    use crate::state::StatePublicationOutcome;
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut block = Box::new(staged_block(&state, proposal.header(), false, true));
    let original = std::ptr::from_ref(&*block);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Deferred(_)
    ));
    // Complete an actual State visibility interval under its canonical writer.
    // Its changed generation is not authority to rebase this captured original.
    let mut notice = state.state_view_publication();
    let writer = state.state_write_lock.lock();
    drop(notice.begin());
    drop(writer);
    drop(notice);
    drop(occupied);
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::RecoveryRequired(
            storage_transactions::TransactionsBlockError::SnapshotObservationChanged
        )
    ));
    assert_eq!(std::ptr::from_ref(&*block), original);
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::RecoveryRequired(
            storage_transactions::TransactionsBlockError::PublicationRecoveryRequired
        )
    ));
    drop(block);
    assert!(state.world.musubi_public_directory.view().is_empty());
}

#[test]
fn retained_state_deferred_releases_complete_inventory_while_frozen_reads_keep_originals() {
    use crate::state::StatePublicationOutcome;
    use std::{sync::mpsc, time::Duration};
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        let header = proposal.header();
        if replacement {
            staged_block(&state, header, false, false).commit().unwrap();
        }
        let budget = state.ivm_execution_budget();
        let mut original = Some(Box::new(staged_block(&state, header, replacement, true)));
        let owner = std::ptr::from_ref(&**original.as_ref().unwrap());
        let world_owner =
            std::ptr::from_ref(&**original.as_ref().unwrap().world.fields.as_ref().unwrap());
        let directory = std::ptr::from_ref(
            original
                .as_ref()
                .unwrap()
                .world
                .musubi_public_directory
                .iter()
                .next()
                .unwrap()
                .1,
        );
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        for _ in 0..3 {
            assert!(matches!(
                original.as_mut().unwrap().try_publish(),
                StatePublicationOutcome::Deferred(_)
            ));
            // A separate thread acquires the complete real World inventory plus
            // all runtime Cells and membership. A failed regression is unwound
            // before join, so the assertion cannot strand a blocked writer.
            std::thread::scope(|scope| {
                let (ready, observed) = mpsc::channel();
                let (release, wait) = mpsc::channel();
                let state = &state;
                let probe = scope.spawn(move || {
                    let probe_budget = AllocationBudget::new(16 * 1024 * 1024);
                    let world = state.world.try_block(&probe_budget).unwrap();
                    let runtime = state.canonical_runtime.block();
                    let previous = state.prev_commit_topology.block();
                    let next = state.commit_topology.block();
                    let membership = state.transactions.block();
                    ready.send(()).unwrap();
                    let _ = wait.recv();
                    drop((world, runtime, previous, next, membership));
                });
                let free = observed.recv_timeout(Duration::from_secs(5)).is_ok();
                if !free {
                    drop(original.take());
                }
                let unchanged = original.as_ref().is_some_and(|block| {
                    std::ptr::from_ref(&**block) == owner
                        && std::ptr::from_ref(&**block.world.fields.as_ref().unwrap())
                            == world_owner
                        && std::ptr::from_ref(
                            block.world.musubi_public_directory.iter().next().unwrap().1,
                        ) == directory
                        && block.world.musubi_public_directory.len() == 1
                });
                let _ = release.send(());
                probe.join().unwrap();
                assert!(
                    free,
                    "Deferred must free every original World/Trigger/runtime/membership writer"
                );
                assert!(
                    unchanged,
                    "frozen reads retain exact original storage while other writers are held"
                );
            });
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        }
        drop(occupied);
        let block = original.as_mut().unwrap();
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
        drop(original);
        assert_eq!(state.world.musubi_public_directory.view().len(), 1);
        assert_eq!(
            state.transactions.latest_height(),
            header.height().get() as usize
        );
    }
}

#[test]
fn retained_state_late_world_busy_recovers_all_original_cursors_before_retry() {
    use crate::state::StatePublicationOutcome;
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Deferred(_)
    ));
    drop(occupied);
    let blocker = state.world.merge_global_state_root.block();
    for _ in 0..3 {
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::PublicationBusy(_)
            )
        ));
        assert_eq!(std::ptr::from_ref(&*original), owner);
        assert_eq!(original.world.musubi_public_directory.len(), 1);
        // These actual acquisitions precede the held last World Cell in the
        // publication inventory and must have been recovered after its refusal.
        drop(state.world.parameters.block());
        drop(state.canonical_runtime.block());
        drop(state.transactions.block());
        assert!(state.state_write_lock.try_lock().is_some());
        assert!(state.state_commit_lock.try_lock().is_some());
    }
    drop(blocker);
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    drop(original);
    assert_eq!(state.world.musubi_public_directory.view().len(), 1);
}

#[test]
fn retained_state_equal_value_component_advance_never_rebases_original_predecessor() {
    use crate::state::StatePublicationOutcome;
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Deferred(_)
    ));
    drop(occupied);
    let generation = state.state_view_generation();
    // A component-only test publication keeps its value and State scalar equal,
    // but replaces the exact lower predecessor. Equal values grant no authority.
    let other = state.world.parameters.block();
    other.commit();
    assert_eq!(state.state_view_generation(), generation);
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::RecoveryRequired(
            storage_transactions::TransactionsBlockError::SnapshotObservationChanged
        )
    ));
    assert_eq!(std::ptr::from_ref(&*original), owner);
    drop(original);
    assert!(state.world.musubi_public_directory.view().is_empty());
}

#[test]
fn retained_state_da_capacity_refusal_keeps_original_bundle_and_all_writers_free() {
    use crate::state::{PendingDaCommitmentBundle, StatePublicationOutcome};
    use iroha_data_model::{
        da::{
            commitment::{
                DaCommitmentBundle, DaCommitmentKey, DaCommitmentRecord, DaProofScheme,
                RetentionClass,
            },
            types::{BlobDigest, StorageTicketId},
        },
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::topology::LaneId;
    let (state, proposal) = fixture();
    let header = proposal.header();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, header, false, false));
    // Component input for the publication owner: this is a real signature, but
    // this resource test does not assert DA service authorization or block finality.
    let key = iroha_crypto::KeyPair::from_seed(vec![31; 32], iroha_crypto::Algorithm::Ed25519);
    let record = DaCommitmentRecord::new(
        LaneId::SINGLE,
        1,
        0,
        BlobDigest::new([3; 32]),
        ManifestDigest::new([4; 32]),
        DaProofScheme::MerkleSha256,
        iroha_crypto::Hash::prehashed([5; 32]),
        None,
        RetentionClass::default(),
        StorageTicketId::new([6; 32]),
        iroha_crypto::Signature::new(key.private_key(), b"DA publication custody component"),
    );
    let bundle = DaCommitmentBundle::new(vec![record]);
    let bundle_backing = bundle.commitments().as_ptr();
    let signature_backing = bundle.commitments()[0]
        .acknowledgement_sig
        .payload()
        .as_ptr();
    original.pending_da_commitments = Some(PendingDaCommitmentBundle {
        block_height: header.height().get(),
        bundle,
    });
    let owner = std::ptr::from_ref(&*original);
    let world_owner = std::ptr::from_ref(&**original.world.fields.as_ref().unwrap());
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let demand = 2
        * (std::alloc::Layout::array::<DaCommitmentKey>(1)
            .unwrap()
            .size()
            + std::alloc::Layout::array::<usize>(1).unwrap().size());
    let mut prepared_identity = None;
    for _ in 0..3 {
        let StatePublicationOutcome::Deferred(
            storage_transactions::TransactionsBlockError::ExecutionDeferred(reason),
        ) = original.try_publish()
        else {
            panic!("the original DA projection must retain typed capacity refusal");
        };
        assert_eq!(
            reason.allocation_refusal(),
            Some(&budget.try_reserve_bytes(demand).unwrap_err())
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert_eq!(std::ptr::from_ref(&*original), owner);
        assert_eq!(
            std::ptr::from_ref(&**original.world.fields.as_ref().unwrap()),
            world_owner
        );
        let pending = original.pending_da_commitments.as_ref().unwrap();
        assert_eq!(pending.bundle.commitments().as_ptr(), bundle_backing);
        assert_eq!(
            pending.bundle.commitments()[0]
                .acknowledgement_sig
                .payload()
                .as_ptr(),
            signature_backing
        );
        let identity = original.publication_identity_for_test();
        assert!(
            !identity.2,
            "DA preparation must complete before effects capture is sealed"
        );
        assert_eq!(*prepared_identity.get_or_insert(identity), identity);
        assert!(
            state
                .da_commitments
                .read()
                .bundle_at(header.height().get())
                .is_none()
        );
        assert!(state.state_commit_lock.try_lock().is_some());
        assert!(state.state_write_lock.try_lock().is_some());
        // The other thread must acquire every real writer. A failing control
        // drops the original before joining, so a regression cannot deadlock.
        let mut retained = Some(original);
        std::thread::scope(|scope| {
            let (ready, observed) = std::sync::mpsc::channel();
            let state = &state;
            let probe = scope.spawn(move || {
                let probe_budget = AllocationBudget::new(16 * 1024 * 1024);
                let world = state.world.try_block(&probe_budget).unwrap();
                let runtime = state.canonical_runtime.block();
                let previous = state.prev_commit_topology.block();
                let next = state.commit_topology.block();
                let membership = state.transactions.block();
                ready.send(()).unwrap();
                drop((world, runtime, previous, next, membership));
            });
            let free = observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok();
            if !free {
                drop(retained.take());
            }
            probe.join().unwrap();
            assert!(free, "DA capacity refusal must free every original writer");
        });
        original = retained.take().unwrap();
    }
    drop(occupied);
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    drop(original);
    let commitments = state.da_commitments.read();
    let published = commitments.bundle_at(header.height().get()).unwrap();
    assert_eq!(published.commitments().as_ptr(), bundle_backing);
    assert_eq!(
        published.commitments()[0]
            .acknowledgement_sig
            .payload()
            .as_ptr(),
        signature_backing
    );
    assert_eq!(
        state.transactions.latest_height(),
        header.height().get() as usize
    );
}

fn collect_original_ebr_until(budget: &iroha_allocation::AllocationBudget, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while budget.reserved_bytes() != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "original EBR custody {} != {expected}",
            budget.reserved_bytes(),
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}

#[path = "publication/retained_musubi/tests.rs"]
mod retained_package_read_tests;

#[path = "publication/retained_musubi_group/tests.rs"]
mod retained_musubi_group_tests;

#[test]
fn retained_state_successful_musubi_validation_survives_late_writer_refusal() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    let row = std::ptr::from_ref(
        original
            .world
            .musubi_public_directory
            .iter()
            .next()
            .unwrap()
            .1,
    );
    validation_observer::observe(|| {
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::ExecutionDeferred(reason)
            ) if matches!(reason.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::Capacity { .. }))
        ));
        let refused_prefix = validation_observer::counts();
        drop(occupied);
        // This actual last World writer refuses only after both pure validators
        // complete. Earlier writers must be recovered on every attempt return.
        let blocker = state.world.merge_global_state_root.block();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::PublicationBusy(_)
            )
        ));
        let completed = validation_observer::counts();
        assert_eq!(completed, [refused_prefix[0] + 1, refused_prefix[1] + 1]);
        let prepared = original.publication_identity_for_test();
        assert_ne!(prepared.0, 0);
        assert!(prepared.2);
        for _ in 0..3 {
            assert!(matches!(
                original.try_publish(),
                StatePublicationOutcome::Deferred(
                    storage_transactions::TransactionsBlockError::PublicationBusy(_)
                )
            ));
            assert_eq!(
                validation_observer::counts(),
                completed,
                "successful Musubi validation must survive a later original writer refusal",
            );
            assert_eq!(std::ptr::from_ref(&*original), owner);
            assert_eq!(original.publication_identity_for_test(), prepared);
            assert_eq!(
                std::ptr::from_ref(
                    original
                        .world
                        .musubi_public_directory
                        .iter()
                        .next()
                        .unwrap()
                        .1,
                ),
                row,
                "retry must retain the original staged canonical row",
            );
            assert!(budget.same_pool(&state.ivm_execution_budget()));
            assert!(state.state_write_lock.try_lock().is_some());
            assert!(state.state_commit_lock.try_lock().is_some());
            assert!(state.world.musubi_public_directory.view().is_empty());
            assert_eq!(state.transactions.latest_height(), 0);
            drop(state.world.parameters.block());
            drop(state.canonical_runtime.block());
            drop(state.transactions.block());
        }
        drop(blocker);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert_eq!(validation_observer::counts(), completed);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert_eq!(validation_observer::counts(), completed);
    });
    drop(original);
    assert_eq!(state.world.musubi_public_directory.view().len(), 1);
    assert_eq!(
        state.latest_block_hash_fast(),
        Some(proposal.header().hash())
    );
}

#[test]
fn retained_state_validated_musubi_refuses_changed_visibility_before_retry() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    validation_observer::observe(|| {
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(_)
        ));
        drop(occupied);
        let blocker = state.world.merge_global_state_root.block();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::PublicationBusy(_)
            )
        ));
        let completed = validation_observer::counts();
        assert!(completed.iter().all(|calls| *calls > 0));
        let generation = state.state_view_generation();
        let mut notice = state.state_view_publication();
        let writer = state.state_write_lock.lock();
        drop(notice.begin());
        drop(writer);
        drop(notice);
        assert_eq!(state.state_view_generation(), generation + 2);
        drop(blocker);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                storage_transactions::TransactionsBlockError::SnapshotObservationChanged
            )
        ));
        assert_eq!(validation_observer::counts(), completed);
        assert_eq!(std::ptr::from_ref(&*original), owner);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                storage_transactions::TransactionsBlockError::PublicationRecoveryRequired
            )
        ));
        assert_eq!(validation_observer::counts(), completed);
    });
    drop(original);
    assert!(state.world.musubi_public_directory.view().is_empty());
    assert_eq!(state.transactions.latest_height(), 0);
}

#[test]
fn retained_state_validated_musubi_refuses_equal_predecessor_advance() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    validation_observer::observe(|| {
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(_)
        ));
        drop(occupied);
        let blocker = state.world.merge_global_state_root.block();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::PublicationBusy(_)
            )
        ));
        let completed = validation_observer::counts();
        assert!(completed.iter().all(|calls| *calls > 0));
        drop(blocker);
        let generation = state.state_view_generation();
        // The component-only publication changes the actual original Musubi
        // predecessor even though its values and State visibility remain equal.
        assert!(state.world.musubi_packages.view().is_empty());
        let other = state.world.musubi_packages.block();
        other.commit();
        assert!(state.world.musubi_packages.view().is_empty());
        assert_eq!(state.state_view_generation(), generation);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                storage_transactions::TransactionsBlockError::SnapshotObservationChanged
            )
        ));
        assert_eq!(validation_observer::counts(), completed);
        assert_eq!(std::ptr::from_ref(&*original), owner);
    });
    drop(original);
    assert!(state.world.musubi_public_directory.view().is_empty());
    assert_eq!(state.transactions.latest_height(), 0);
}

#[test]
fn retained_state_unchanged_musubi_skips_both_validators() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, false));
    validation_observer::observe(|| {
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert_eq!(validation_observer::counts(), [0, 0]);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert_eq!(validation_observer::counts(), [0, 0]);
    });
    drop(original);
    assert!(state.world.musubi_public_directory.view().is_empty());
    assert_eq!(
        state.latest_block_hash_fast(),
        Some(proposal.header().hash())
    );
}

#[test]
fn retained_state_live_musubi_success_survives_universal_capacity_refusal() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    let row = std::ptr::from_ref(
        original
            .world
            .musubi_public_directory
            .iter()
            .next()
            .unwrap()
            .1,
    );
    validation_observer::observe(|| {
        // Freeze and release the original writers through the existing actual
        // scratch-capacity seam before constraining only the later validator.
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(_)
        ));
        drop(occupied);
        let refused_prefix = validation_observer::counts();
        let live_bytes = original.world.musubi_public_directory.len()
            * std::mem::size_of::<&MusubiOrderedPackageEntryV1>();
        assert!(live_bytes > 0);
        let remaining = budget.limit_bytes() - budget.reserved_bytes();
        assert!(remaining > live_bytes);
        // This same physical pool fits the live directory-reference array but
        // cannot fit the universal per-package accumulator. No limit is changed.
        let held = budget.try_reserve_bytes(remaining - live_bytes).unwrap();
        let StatePublicationOutcome::Deferred(
            storage_transactions::TransactionsBlockError::ExecutionDeferred(reason),
        ) = original.try_publish()
        else {
            panic!("original universal scratch must refuse after the live pass succeeds");
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            limit_bytes,
            ..
        }) = reason.allocation_refusal()
        else {
            panic!("universal refusal must retain the actual original pool cause: {reason:?}");
        };
        let universal_bytes = *requested_bytes;
        assert!(universal_bytes > live_bytes);
        assert_eq!(*limit_bytes, budget.limit_bytes());
        drop(reason);
        let completed_live = validation_observer::counts();
        assert_eq!(
            completed_live,
            [refused_prefix[0] + 1, refused_prefix[1] + 1]
        );
        let prepared = original.publication_identity_for_test();
        assert_ne!(prepared.0, 0);
        assert_eq!(
            prepared.1, 0,
            "snapshot still follows both completed validators"
        );
        assert!(!prepared.2);
        let original_reserved = budget.reserved_bytes();
        for retry in 1..=3 {
            let StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::ExecutionDeferred(reason),
            ) = original.try_publish()
            else {
                panic!("same original universal accumulator still has no capacity");
            };
            assert!(matches!(reason.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, limit_bytes, .. })
                if *requested_bytes == universal_bytes && *limit_bytes == budget.limit_bytes()
            ));
            drop(reason);
            assert_eq!(
                validation_observer::counts(),
                [completed_live[0], completed_live[1] + retry],
                "successful live Musubi pass must survive original universal capacity refusal",
            );
            assert_eq!(budget.reserved_bytes(), original_reserved);
            assert!(budget.same_pool(&state.ivm_execution_budget()));
            assert_eq!(std::ptr::from_ref(&*original), owner);
            assert_eq!(original.publication_identity_for_test(), prepared);
            assert_eq!(
                std::ptr::from_ref(
                    original
                        .world
                        .musubi_public_directory
                        .iter()
                        .next()
                        .unwrap()
                        .1,
                ),
                row
            );
            assert!(state.world.musubi_public_directory.view().is_empty());
            assert_eq!(state.transactions.latest_height(), 0);
            assert!(state.state_write_lock.try_lock().is_some());
            assert!(state.state_commit_lock.try_lock().is_some());
        }
        drop(held);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        let completed = validation_observer::counts();
        assert_eq!(completed, [completed_live[0], completed_live[1] + 4]);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert_eq!(validation_observer::counts(), completed);
    });
    drop(original);
    assert_eq!(state.world.musubi_public_directory.view().len(), 1);
    assert_eq!(
        state.latest_block_hash_fast(),
        Some(proposal.header().hash())
    );
}

#[test]
fn retained_state_partial_musubi_validation_refuses_changed_visibility() {
    use crate::state::{StatePublicationOutcome, world_commit::validation_observer};
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    let owner = std::ptr::from_ref(&*original);
    validation_observer::observe(|| {
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(_)
        ));
        drop(occupied);
        let before = validation_observer::counts();
        let live_bytes = original.world.musubi_public_directory.len()
            * std::mem::size_of::<&MusubiOrderedPackageEntryV1>();
        assert!(live_bytes > 0);
        let remaining = budget.limit_bytes() - budget.reserved_bytes();
        let held = budget.try_reserve_bytes(remaining - live_bytes).unwrap();
        assert!(matches!(original.try_publish(),
            StatePublicationOutcome::Deferred(
                storage_transactions::TransactionsBlockError::ExecutionDeferred(reason)
            ) if matches!(reason.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })
                if *requested_bytes > live_bytes)
        ));
        let partial = validation_observer::counts();
        assert_eq!(partial, [before[0] + 1, before[1] + 1]);
        let generation = state.state_view_generation();
        let mut notice = state.state_view_publication();
        let writer = state.state_write_lock.lock();
        drop(notice.begin());
        drop(writer);
        drop(notice);
        assert_eq!(state.state_view_generation(), generation + 2);
        drop(held);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                storage_transactions::TransactionsBlockError::SnapshotObservationChanged
            )
        ));
        assert_eq!(validation_observer::counts(), partial);
        assert_eq!(std::ptr::from_ref(&*original), owner);
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                storage_transactions::TransactionsBlockError::PublicationRecoveryRequired
            )
        ));
        assert_eq!(validation_observer::counts(), partial);
    });
    drop(original);
    assert!(state.world.musubi_public_directory.view().is_empty());
    assert_eq!(state.transactions.latest_height(), 0);
}
