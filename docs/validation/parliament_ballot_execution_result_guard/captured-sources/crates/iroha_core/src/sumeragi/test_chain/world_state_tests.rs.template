// Complete World state and event roots of certified results (`specs/sumeragi.md` Appendix E,
// E51), through real genesis, execution, publication and replay.

use crate::state::world_projection::WorldStateAccumulator;
use iroha_data_model::{events::EventBox, role::RoleId};

fn fixture() -> (CertifiedTestChain, KeyPair) {
    let key = KeyPair::from_seed(vec![0x5A; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let domain = Domain::new(
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").unwrap(),
    )
    .build(&account);
    let world = World::with(
        [domain],
        [Account::new(account.clone()).build(&account)],
        [],
    );
    let chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
    (chain, key)
}

fn log(chain: &CertifiedTestChain, key: &KeyPair, text: &str, time_ms: u64) -> SignedTransaction {
    chain.sign(
        key,
        [Log::new(Level::INFO, text.to_owned()).into()],
        time_ms,
    )
}

/// An account no block of these tests reads or writes.
fn bystander() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![0x77; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn auditor_grant(account: &AccountId) -> crate::role::RoleIdWithOwner {
    let role: RoleId = "auditor".parse().unwrap();
    crate::role::RoleIdWithOwner::new(account.clone(), role)
}

fn stored_root(chain: &CertifiedTestChain) -> iroha_crypto::Hash {
    chain
        .state()
        .world
        .state_accumulator
        .view()
        .get()
        .root()
        .unwrap()
}

#[test]
fn certified_results_bind_the_complete_world_and_the_emitted_events() {
    let (mut chain, key) = fixture();
    let genesis = chain.committed(1);
    assert_eq!(
        genesis.commitment().execution.parent_world_state_root,
        WorldStateAccumulator::empty().root().unwrap(),
        "genesis starts from the empty World"
    );
    let after_genesis = chain.state().verify_world_state_accumulator().unwrap();
    assert_eq!(after_genesis, stored_root(&chain));
    chain.take_events().unwrap();

    let first = log(&chain, &key, "first", 2_000);
    assert_eq!(chain.commit_at(2_000, vec![first]), [true]);
    let second = chain.committed(2);
    let execution = second.commitment().execution;
    assert_eq!(
        execution.parent_world_state_root, after_genesis,
        "the parent root is the published World of the parent"
    );
    assert_ne!(
        execution.world_state_root,
        execution.parent_world_state_root
    );
    // The event root commits exactly the events execution emitted, in delivery order;
    // pipeline status notifications are delivery, not results.
    let emitted: Vec<EventBox> = chain
        .take_events()
        .unwrap()
        .into_iter()
        .filter(|event| !matches!(event, EventBox::Pipeline(_) | EventBox::PipelineBatch(_)))
        .collect();
    assert!(!emitted.is_empty());
    assert_eq!(
        execution.event_commitment,
        crate::sumeragi::commitment::event_commitment(&emitted).unwrap()
    );
    let after_second = chain.state().verify_world_state_accumulator().unwrap();

    let next = log(&chain, &key, "second", 3_000);
    assert_eq!(chain.commit_at(3_000, vec![next]), [true]);
    assert_eq!(
        chain
            .committed(3)
            .commitment()
            .execution
            .parent_world_state_root,
        after_second
    );
    chain.state().verify_world_state_accumulator().unwrap();
}

#[test]
fn unwitnessed_world_divergence_changes_the_certified_result() {
    let (mut honest, key) = fixture();
    let (mut diverged, _) = fixture();
    // A role grant the block never reads or writes: before S9 only the witnessed write set
    // entered `R`, so both chains certified the same result.
    let grant = auditor_grant(&bystander());
    diverged.setup_world_at(2_000, |transaction| {
        transaction.world.account_roles.insert(grant, ());
    });
    let transaction = log(&honest, &key, "same", 2_000);
    assert_eq!(honest.commit_at(2_000, vec![transaction.clone()]), [true]);
    assert_eq!(diverged.commit_at(2_000, vec![transaction]), [true]);
    let (honest, diverged) = (honest.committed(2), diverged.committed(2));
    assert_eq!(honest.core_hash(), diverged.core_hash(), "the same block");
    let (a, b) = (
        honest.commitment().execution,
        diverged.commitment().execution,
    );
    assert_eq!(
        (
            a.parent_state_root,
            a.post_state_root,
            a.ordinary_writes_root
        ),
        (
            b.parent_state_root,
            b.post_state_root,
            b.ordinary_writes_root
        ),
        "the witnessed roots cannot see the grant"
    );
    assert_eq!(a.event_commitment, b.event_commitment);
    assert_ne!(a.parent_world_state_root, b.parent_world_state_root);
    assert_ne!(a.world_state_root, b.world_state_root);
    assert_ne!(
        honest.result(),
        diverged.result(),
        "R binds the complete World"
    );
}

#[test]
fn replay_rejects_a_tampered_world_and_startup_rejects_a_stale_accumulator() {
    let (mut source, key) = fixture();
    let first = log(&source, &key, "one", 2_000);
    assert_eq!(source.commit_at(2_000, vec![first]), [true]);
    let second = log(&source, &key, "two", 3_000);
    assert_eq!(source.commit_at(3_000, vec![second]), [true]);
    source.state().verify_world_state_accumulator().unwrap();

    // A World edit that keeps its accumulator consistent (a forged snapshot) changes the
    // parent World root of the next block: replay of the certified journal rejects it.
    let (mut tampered, _) = fixture();
    let grant = auditor_grant(&bystander());
    tampered.setup_world_at(2_000, |transaction| {
        transaction.world.account_roles.insert(grant.clone(), ());
    });
    let error = tampered.replay_from(&source).unwrap_err();
    assert!(error.contains("diverges"), "{error}");

    // A World edit behind the accumulator is invisible to incremental replay of blocks that
    // never touch it; the startup cold capture rejects the stale accumulator.
    let (mut stale, _) = fixture();
    {
        let mut world = stale.state().world.block();
        world.account_roles.insert(grant, ());
        world.commit();
    }
    stale.replay_from(&source).unwrap();
    let error = stale.state().verify_world_state_accumulator().unwrap_err();
    let crate::state::WorldStateVerificationError::Mismatch {
        stored_root,
        stored_entries,
        captured_root,
        captured_entries,
    } = error
    else {
        panic!("the actual stale World must fail its independent root comparison: {error}");
    };
    assert_ne!(stored_root, captured_root);
    assert_eq!(captured_entries, stored_entries + 1);
}

#[test]
fn replay_from_scratch_reproduces_the_world_state_accumulator() {
    let (mut source, key) = fixture();
    for time_ms in [2_000, 3_000, 4_000] {
        let transaction = log(&source, &key, "replayed", time_ms);
        assert_eq!(source.commit_at(time_ms, vec![transaction]), [true]);
    }
    let (mut replica, _) = fixture();
    replica.replay_from(&source).unwrap();
    assert_eq!(replica.height(), source.height());
    let source_root = source.state().verify_world_state_accumulator().unwrap();
    let replica_root = replica.state().verify_world_state_accumulator().unwrap();
    assert_eq!(source_root, replica_root);
    assert_eq!(
        *source.state().world.state_accumulator.view().get(),
        *replica.state().world.state_accumulator.view().get()
    );
}

#[test]
fn world_root_verification_preserves_original_writer_refusal_and_exact_retry() {
    use crate::{
        state::WorldStateVerificationError,
        sumeragi::node::{NodeError, ReplayError},
    };
    use mv::storage::AdmittedStorageError;
    use std::task::{Context, Waker};

    let (chain, _) = fixture();
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let mut context = Context::from_waker(Waker::noop());
    let expected_root = state.verify_world_state_accumulator().unwrap();
    let expected_tip = state.view().native_execution_tip();
    let original = state.world.try_block(&budget).unwrap();
    let expected = state
        .world
        .try_block(&budget)
        .err()
        .expect("the actual original World writer remains held");
    assert!(matches!(expected, AdmittedStorageError::Busy { .. }));
    let error = NodeError::Replay {
        height: chain.height(),
        reason: ReplayError::StateRoot(state.verify_world_state_accumulator().unwrap_err()),
    };
    let NodeError::Replay {
        reason: ReplayError::StateRoot(WorldStateVerificationError::Acquisition(error)),
        ..
    } = error
    else {
        panic!("the actual original World refusal must survive startup: {error}");
    };
    assert_eq!(error, expected);
    let release = error.release_wait().unwrap();
    assert!(registration.poll_wait(release, &mut context).is_pending());
    // Actual unrelated capacity retirement cannot unlock the World writer.
    drop(budget.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    assert_eq!(stored_root(&chain), expected_root);
    assert_eq!(state.view().native_execution_tip(), expected_tip);
    drop(original);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    assert_eq!(
        state.verify_world_state_accumulator().unwrap(),
        expected_root
    );
    assert_eq!(state.view().native_execution_tip(), expected_tip);
}

#[test]
fn world_root_verification_preserves_original_capacity_refusal_and_exact_retry() {
    use crate::{
        state::WorldStateVerificationError,
        sumeragi::node::{NodeError, ReplayError},
    };
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use mv::storage::AdmittedStorageError;
    use std::task::{Context, Waker};

    let (chain, _) = fixture();
    // Keep earlier EBR retirement from changing the actual occupied source mid-check.
    let _epoch = crossbeam_epoch::pin();
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let mut context = Context::from_waker(Waker::noop());
    let expected_root = state.verify_world_state_accumulator().unwrap();
    let expected_tip = state.view().native_execution_tip();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let error = NodeError::Replay {
        height: chain.height(),
        reason: ReplayError::StateRoot(state.verify_world_state_accumulator().unwrap_err()),
    };
    let NodeError::Replay {
        reason:
            ReplayError::StateRoot(WorldStateVerificationError::Acquisition(
                AdmittedStorageError::Allocation(refusal),
            )),
        ..
    } = error
    else {
        panic!("the complete World shell must retain its actual original pool: {error}");
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    } = &refusal
    else {
        panic!("actual occupied State execution pool: {refusal}");
    };
    assert_eq!(
        refusal,
        budget.try_reserve_bytes(*requested_bytes).unwrap_err()
    );
    assert!(registration.poll_wait(release, &mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    assert_eq!(stored_root(&chain), expected_root);
    assert_eq!(state.view().native_execution_tip(), expected_tip);
    drop(occupied);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    assert_eq!(
        state.verify_world_state_accumulator().unwrap(),
        expected_root
    );
    assert_eq!(state.view().native_execution_tip(), expected_tip);
}
