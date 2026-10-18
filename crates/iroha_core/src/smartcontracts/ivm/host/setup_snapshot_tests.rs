//! Host-setup snapshots equal the eager World projections they replace.
//!
//! Each test compares the bounded, borrowed or deferred hydration against the
//! complete eager projection over the same State, including the syscall gas a
//! guest observes.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, State, World, ZkAssetState},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{AccountDetails, AccountValue},
    block::BlockHeader,
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1},
    parameter::{Parameter, system::SumeragiNposParameters},
};
use ivm::{IVM, IVMHost, syscalls as ivm_sys};

/// Accounts in the fixture World; more than one `CREATE_NFTS_FOR_ALL_USERS` call reads.
const FIXTURE_ACCOUNTS: u32 = 300;
/// Epoch length of the VRF fixture: pulses at heights `3k - 1` close epoch `k`.
const FIXTURE_EPOCH_LENGTH: u64 = 3;

fn seeded_account(index: u32) -> AccountId {
    // Hashing the index yields a distinct, never all-zero Ed25519 seed.
    let seed = Hash::new(index.to_le_bytes()).as_ref().to_vec();
    let (public_key, _) = KeyPair::from_seed(seed, Algorithm::Ed25519).into_parts();
    AccountId::new(public_key)
}

fn insert_fixture_accounts(world: &mut World) {
    for index in 0..FIXTURE_ACCOUNTS {
        world.accounts.insert(
            seeded_account(index),
            AccountValue::new(AccountDetails::default()),
        );
    }
}

fn complete_account_snapshot(world: &impl WorldReadOnly) -> Vec<AccountId> {
    world
        .accounts_iter()
        .map(|entry| entry.id().clone())
        .collect()
}

fn queued_instructions<QS>(host: &CoreHostImpl<QS>) -> Vec<InstructionBox> {
    QueuedEffect::instructions(&host.queued).cloned().collect()
}

#[test]
fn create_nfts_recipient_prefix_reproduces_the_complete_account_snapshot() {
    let mut world = World::default();
    insert_fixture_accounts(&mut world);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let complete = complete_account_snapshot(view.world());
    assert_eq!(complete.len(), FIXTURE_ACCOUNTS as usize);
    let prefix = create_nfts_for_all_recipient_snapshot(view.world());
    assert_eq!(
        prefix.as_slice(),
        &complete[..CREATE_NFTS_FOR_ALL_MAX_RECIPIENTS]
    );
    assert_eq!(view.accounts_snapshot(), prefix);

    let authority = seeded_account(FIXTURE_ACCOUNTS + 1);
    for nft_seq in [0, 1_000, u64::MAX - 300, u64::MAX - 1, u64::MAX] {
        let mut eager = CoreHost::with_accounts(authority.clone(), Arc::new(complete.clone()));
        let mut bounded = CoreHost::with_accounts(authority.clone(), Arc::clone(&prefix));
        eager.set_nft_seq_base(nft_seq);
        bounded.set_nft_seq_base(nft_seq);
        assert_eq!(
            eager.create_nfts_for_all_preview(),
            bounded.create_nfts_for_all_preview()
        );
        let mut eager_vm = IVM::new(u64::MAX);
        let mut bounded_vm = IVM::new(u64::MAX);
        assert_eq!(
            eager
                .prepare_syscall(ivm_sys::SYSCALL_CREATE_NFTS_FOR_ALL_USERS, &eager_vm)
                .expect("quote the complete snapshot"),
            bounded
                .prepare_syscall(ivm_sys::SYSCALL_CREATE_NFTS_FOR_ALL_USERS, &bounded_vm)
                .expect("quote the bounded snapshot"),
        );
        assert_eq!(
            eager
                .syscall(ivm_sys::SYSCALL_CREATE_NFTS_FOR_ALL_USERS, &mut eager_vm)
                .expect("run on the complete snapshot"),
            bounded
                .syscall(ivm_sys::SYSCALL_CREATE_NFTS_FOR_ALL_USERS, &mut bounded_vm)
                .expect("run on the bounded snapshot"),
        );
        assert_eq!(eager.next_nft_sequence(), bounded.next_nft_sequence());
        assert_eq!(queued_instructions(&eager), queued_instructions(&bounded));
    }
}

#[test]
fn transaction_account_snapshot_stays_bounded_and_pinned_to_its_first_setup() {
    let mut world = World::default();
    insert_fixture_accounts(&mut world);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    assert_eq!(
        block.accounts_snapshot(),
        create_nfts_for_all_recipient_snapshot(&block.world)
    );
    let mut transaction = block.transaction();
    let pinned = transaction.accounts_snapshot();
    assert_eq!(
        pinned.as_slice(),
        &complete_account_snapshot(&transaction.world)[..CREATE_NFTS_FOR_ALL_MAX_RECIPIENTS]
    );
    // An account that sorts into the observable prefix after the first host
    // setup of this transaction stays invisible to its later setups, exactly
    // as with the complete snapshot cache.
    let late = (FIXTURE_ACCOUNTS..)
        .map(seeded_account)
        .find(|candidate| candidate < pinned.last().expect("bounded prefix"))
        .expect("a fresh account sorts into the prefix");
    transaction
        .world
        .accounts
        .insert(late.clone(), AccountValue::new(AccountDetails::default()));
    assert!(Arc::ptr_eq(&transaction.accounts_snapshot(), &pinned));
    let fresh = create_nfts_for_all_recipient_snapshot(&transaction.world);
    assert!(fresh.contains(&late));
    assert_eq!(fresh.len(), CREATE_NFTS_FOR_ALL_MAX_RECIPIENTS);
}

#[test]
fn axt_hydration_installs_policy_without_projecting_assets() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    super::pointer_abi_tests::establish_authenticated_axt_ledger_time(&state, 1);
    let view = state.view();
    let mut host = CoreHost::new(seeded_account(1));
    host.hydrate_axt_state(&view)
        .expect("canonical AXT policy snapshot");
    let expected = view
        .axt_execution_policy_snapshot()
        .unwrap_or_else(|| view.axt_policy_snapshot());
    assert_eq!(host.axt_policy_snapshot.as_ref(), Some(&expected));
    assert_eq!(host.axt_timing, view.nexus().axt);
    assert!(host.axt_issuer_keys.is_empty());
}

#[test]
fn zk_root_snapshot_reads_trees_in_place_like_the_owned_projection() {
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("setupzk", "universal").expect("fixture domain"),
        "asset".parse().expect("fixture asset name"),
    );
    let mut zk_state = ZkAssetState::default();
    zk_state
        .push_commitments(
            &[[0x21; 32], [0x22; 32], [0x23; 32]],
            NonZeroUsize::new(2).expect("non-zero root history cap"),
        )
        .expect("canonical confidential tree");
    zk_state.nullifiers.insert([0x31; 32]);
    let mut world = World::new();
    world.zk_assets.insert(asset.clone(), zk_state.clone());
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut borrowed = CoreHost::new(seeded_account(1));
    borrowed
        .set_zk_snapshots_from_world(view.world(), &view.zk)
        .expect("hydrate ZK snapshots");
    let mut owned = CoreHost::new(seeded_account(1));
    owned
        .set_zk_roots_snapshot(BTreeMap::from([(asset.clone(), zk_state.clone())]))
        .expect("owned root snapshot");
    assert_eq!(borrowed.zk_roots, owned.zk_roots);
    let snapshot = &borrowed.zk_roots[&asset];
    assert_eq!(snapshot.root_history, zk_state.root_history);
    assert_eq!(snapshot.commitment_count, zk_state.commitments.len());
}

fn fixture_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([0x93; 32])))
}

fn fixture_block_hash(height: u64) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::new(height.to_be_bytes()))
}

fn beacon_signing_keys() -> Vec<KeyPair> {
    let mut keys = (1_u8..=4)
        .map(|marker| {
            KeyPair::try_from_seed(vec![marker; 32], Algorithm::BlsNormal)
                .expect("deterministic fixture BLS key")
        })
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    keys
}

/// Signed pulses keyed by height: every listed height anchors to the canonical
/// block one height earlier, except `bad_anchor_height`.
fn signed_fixture_pulses(
    heights: &[u64],
    bad_anchor_height: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> (
    crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    BTreeMap<u64, FinalizedGlobalThresholdBeaconPulseV1>,
) {
    let anchors = heights
        .iter()
        .map(|height| {
            let anchor_height = height - 1;
            let block_hash = if *height == bad_anchor_height {
                fixture_block_hash(anchor_height + 1_000)
            } else {
                fixture_block_hash(anchor_height)
            };
            (
                GlobalThresholdBeaconChainAnchorV1 {
                    height: anchor_height,
                    block_hash,
                },
                crate::beacon::pulse_context_fixture_v1(),
            )
        })
        .collect::<Vec<_>>();
    let (key_record, pulses) = crate::beacon::signed_pulses_fixture_for_roster_and_anchors(
        fixture_network_id(),
        &beacon_signing_keys(),
        &anchors,
        budget,
    );
    let pulses = pulses
        .into_iter()
        .map(|pulse| (pulse.height, pulse))
        .collect();
    (key_record, pulses)
}

/// A committed State holding `pulses`, canonical hashes up to `height` and
/// NPoS epochs of [`FIXTURE_EPOCH_LENGTH`] blocks.
fn vrf_fixture_state(
    key_record: &crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    pulses: impl IntoIterator<Item = FinalizedGlobalThresholdBeaconPulseV1>,
    height: u64,
) -> State {
    let mut world = World::new();
    insert_fixture_accounts(&mut world);
    let session_id = key_record.session.session_id;
    world
        .global_beacon_key_sessions
        .insert(session_id, key_record.clone());
    world
        .global_beacon_active_session
        .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, session_id);
    let mut latest = None;
    for pulse in pulses {
        // A deliberately corrupted signature has no canonical link; the cursor
        // keeps the latest well-formed pulse, which the projection never reads.
        if let Ok(link) = crate::beacon::validate_persisted_global_threshold_beacon_pulse_v1(&pulse)
        {
            latest = Some(link);
        }
        world.global_beacon_pulses.insert(pulse.pulse_id, pulse);
    }
    if let Some(latest) = latest {
        world
            .global_beacon_latest_pulse
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, latest);
    }
    world
        .rebuild_global_beacon_pulse_slots()
        .expect("unique fixture pulse slots");
    {
        let mut parameters = world.parameters.block();
        parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters {
                    epoch_length_blocks: NonZeroU64::new(FIXTURE_EPOCH_LENGTH)
                        .expect("non-zero fixture epoch"),
                    // The evidence and slashing windows must fit three epochs.
                    evidence_horizon_blocks: FIXTURE_EPOCH_LENGTH,
                    slashing_delay_blocks: 1,
                    ..SumeragiNposParameters::default()
                }
                .into_custom_parameter(),
            ))
            .expect("valid fixture NPoS parameters");
        parameters.commit();
    }
    let mut state = State::new_with_chain_and_network_id_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "vrf-setup-snapshot".parse().expect("fixture chain id"),
        fixture_network_id(),
    );
    for block_height in 1..=height {
        state.push_block_hash_for_testing(fixture_block_hash(block_height));
    }
    state
}

/// The eager projection the host used before deferring verification, kept
/// verbatim as the oracle.
fn eager_vrf_epoch_seed_oracle(state: &impl StateReadOnly) -> BTreeMap<u64, [u8; 32]> {
    let Some(epoch_length) = state
        .world()
        .sumeragi_npos_parameters()
        .expect("canonical NPoS parameters")
        .map(|params| params.epoch_length_blocks().get())
    else {
        return BTreeMap::new();
    };
    let maximum_height = u64::try_from(state.height()).unwrap_or(u64::MAX);
    let mut projected = BTreeMap::new();
    let mut conflicted = BTreeSet::new();
    for (_, candidate) in state.world().global_beacon_pulses().iter() {
        let Some(boundary_height) = candidate.height.checked_add(1) else {
            continue;
        };
        if candidate.height > maximum_height
            || boundary_height % epoch_length != 0
            || candidate.finalized_chain_anchor.height.checked_add(1) != Some(candidate.height)
        {
            continue;
        }
        let Some(anchor_index) = candidate
            .finalized_chain_anchor
            .height
            .checked_sub(1)
            .and_then(|height| usize::try_from(height).ok())
        else {
            continue;
        };
        if state.block_hashes().get(anchor_index)
            != Some(&candidate.finalized_chain_anchor.block_hash)
        {
            continue;
        }
        let Ok(pulse) = crate::beacon::verified_persisted_global_threshold_beacon_pulse_v1(
            state.world(),
            state.network_id(),
            candidate,
        ) else {
            continue;
        };
        let successor_epoch = boundary_height / epoch_length;
        let seed = crate::beacon::global_threshold_beacon_npos_successor_seed_v1(
            &pulse,
            boundary_height,
            successor_epoch,
        );
        if projected.insert(successor_epoch, seed).is_some() {
            conflicted.insert(successor_epoch);
        }
    }
    for epoch in conflicted {
        projected.remove(&epoch);
    }
    projected
}

/// Read one epoch through the syscall pair, returning quote, gas and seed.
fn read_vrf_epoch_seed<QS: QueryStateAccess + Default>(
    host: &mut CoreHostImpl<QS>,
    epoch: u64,
) -> (u64, u64, Option<[u8; 32]>) {
    let mut vm = IVM::new(10_000);
    vm.set_register(10, epoch);
    let quote = host
        .prepare_syscall(ivm_sys::SYSCALL_VRF_EPOCH_SEED, &vm)
        .expect("quote VRF epoch seed");
    let gas = host
        .syscall(ivm_sys::SYSCALL_VRF_EPOCH_SEED, &mut vm)
        .expect("read VRF epoch seed");
    let seed = match vm.register(10) {
        0 => None,
        pointer => Some(
            <[u8; 32]>::try_from(vm.validate_tlv(pointer).expect("seed TLV").payload)
                .expect("32-byte seed"),
        ),
    };
    (quote, gas, seed)
}

const PROBED_EPOCHS: [u64; 9] = [0, 1, 2, 3, 4, 5, 6, 7, u64::MAX];

/// Check eager hydration, deferred hydration and the oracle agree on `state`.
fn assert_vrf_projection_matches_oracle<S>(
    state: &S,
    expected_epochs: &[u64],
) -> BTreeMap<u64, [u8; 32]>
where
    S: QueryStateSource + StateReadOnly,
{
    let oracle = eager_vrf_epoch_seed_oracle(state);
    assert_eq!(
        oracle.keys().copied().collect::<Vec<_>>(),
        expected_epochs,
        "fixture epochs"
    );
    let mut eager = CoreHost::new(seeded_account(1));
    eager
        .set_vrf_epoch_seeds_from_state(state)
        .expect("eager VRF hydration");
    let VrfEpochSeedSource::Scanned(projection) = &eager.vrf_epoch_seeds else {
        panic!("state hydration installs a scanned projection");
    };
    assert_eq!(projection.resolved_seeds(), oracle);
    let mut deferred = CoreHostImpl::new(seeded_account(1));
    deferred.set_query_state_with_vrf_epoch_seeds(
        state,
        vrf_epoch_length_from_state(state).expect("committed NPoS parameters"),
    );
    for epoch in PROBED_EPOCHS {
        let expected = oracle.get(&epoch).copied();
        let gas = ivm::vrf::epoch_seed_gas(expected.is_some());
        assert_eq!(read_vrf_epoch_seed(&mut eager, epoch), (gas, gas, expected));
        assert_eq!(
            read_vrf_epoch_seed(&mut deferred, epoch),
            (gas, gas, expected),
            "deferred epoch {epoch}"
        );
    }
    oracle
}

#[test]
fn vrf_epoch_seed_projection_matches_eager_verification_across_state_changes() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    // Heights 5, 8, 11 and 17 close epochs 2, 3, 4 and 6; 6 is no boundary and
    // the boundary pulse at 14 anchors to a noncanonical block.
    let (key_record, pulses) = signed_fixture_pulses(&[5, 6, 8, 11, 14, 17], 14, &budget);
    let earlier = pulses
        .iter()
        .filter(|(height, _)| **height < 17)
        .map(|(_, pulse)| *pulse);
    let first = vrf_fixture_state(&key_record, earlier, 16);
    let view = first.view();
    let first_oracle = assert_vrf_projection_matches_oracle(&view, &[2, 3, 4]);

    // A later State adds epoch 6 and carries a pulse whose stored signature no
    // longer verifies, although every State check still accepts it.
    let mut tampered = pulses[&8];
    tampered.signature[0] ^= 0x01;
    let later_pulses = pulses
        .iter()
        .map(|(height, pulse)| if *height == 8 { tampered } else { *pulse });
    let later = vrf_fixture_state(&key_record, later_pulses, 18);
    let later_view = later.view();
    assert!(
        crate::beacon::persisted_global_threshold_beacon_pulse_session_v1(
            later_view.world(),
            later_view.network_id(),
            &tampered,
        )
        .is_ok()
    );
    let later_oracle = assert_vrf_projection_matches_oracle(&later_view, &[2, 4, 6]);
    assert_eq!(first_oracle[&2], later_oracle[&2]);
    assert_eq!(first_oracle[&4], later_oracle[&4]);
    drop(later_view);

    // The same comparison holds for a host bound to an executing transaction.
    let header = BlockHeader::new(
        NonZeroU64::new(19).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = later.block(header);
    let transaction = block.transaction();
    assert_vrf_projection_matches_oracle(&transaction, &[2, 4, 6]);
}

#[test]
fn persisted_pulse_halves_compose_to_complete_verification() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let (key_record, pulses) = signed_fixture_pulses(&[5, 8], 0, &budget);
    let mut tampered = pulses[&8];
    tampered.signature[0] ^= 0x01;
    let state = vrf_fixture_state(&key_record, [pulses[&5], tampered], 9);
    let view = state.view();
    let network_id = view.network_id();
    let session = crate::beacon::persisted_global_threshold_beacon_pulse_session_v1(
        view.world(),
        network_id,
        &pulses[&5],
    )
    .expect("stored pulse binds its active session");
    assert!(
        crate::beacon::verify_persisted_global_threshold_beacon_pulse_signature_v1(
            session,
            &pulses[&5],
        )
        .is_ok()
    );
    assert_eq!(
        crate::beacon::verified_persisted_global_threshold_beacon_pulse_v1(
            view.world(),
            network_id,
            &pulses[&5],
        ),
        Ok(pulses[&5])
    );
    let session = crate::beacon::persisted_global_threshold_beacon_pulse_session_v1(
        view.world(),
        network_id,
        &tampered,
    )
    .expect("a stored tampered pulse still passes the State checks");
    assert!(
        crate::beacon::verify_persisted_global_threshold_beacon_pulse_signature_v1(
            session, &tampered,
        )
        .is_err()
    );
    assert!(
        crate::beacon::verified_persisted_global_threshold_beacon_pulse_v1(
            view.world(),
            network_id,
            &tampered,
        )
        .is_err()
    );
    assert!(
        crate::beacon::persisted_global_threshold_beacon_pulse_session_v1(
            view.world(),
            network_id,
            &pulses[&8],
        )
        .is_err(),
        "a pulse that differs from its stored row fails the State checks"
    );
}

#[test]
fn deferred_host_setup_charges_a_representative_contract_identically() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let (key_record, pulses) = signed_fixture_pulses(&[5, 8], 0, &budget);
    let state = vrf_fixture_state(&key_record, pulses.values().copied(), 9);
    let view = state.view();
    let oracle = eager_vrf_epoch_seed_oracle(&view);
    assert_eq!(oracle.keys().copied().collect::<Vec<_>>(), [2, 3]);
    let code = [
        ivm_sys::SYSCALL_VRF_EPOCH_SEED,
        ivm_sys::SYSCALL_CREATE_NFTS_FOR_ALL_USERS,
    ]
    .into_iter()
    .flat_map(|number| {
        ivm::encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(number).expect("syscall id fits in u8"),
        )
        .to_le_bytes()
    })
    .chain(ivm::encoding::wide::encode_halt().to_le_bytes())
    .collect::<Vec<_>>();
    let program = build_program(&code, 0);
    let authority = seeded_account(FIXTURE_ACCOUNTS + 1);
    for epoch in [2, 3, 4] {
        // The host as hydrated before: the complete account list and every
        // epoch seed verified up front.
        let mut eager = CoreHost::with_accounts(
            authority.clone(),
            Arc::new(complete_account_snapshot(view.world())),
        );
        for (seed_epoch, seed) in &oracle {
            eager.vrf_epoch_seeds.insert(*seed_epoch, *seed);
        }
        let mut deferred = CoreHostImpl::with_accounts(authority.clone(), view.accounts_snapshot());
        deferred.set_query_state_with_vrf_epoch_seeds(
            &view,
            vrf_epoch_length_from_state(&view).expect("committed NPoS parameters"),
        );
        let mut eager_vm = IVM::new(u64::MAX);
        eager_vm
            .load_program(&program)
            .expect("load fixture program");
        eager_vm.set_register(10, epoch);
        eager_vm
            .run_with_host(&mut eager)
            .expect("run with the eager host");
        let mut deferred_vm = IVM::new(u64::MAX);
        deferred_vm
            .load_program(&program)
            .expect("load fixture program");
        deferred_vm.set_register(10, epoch);
        deferred_vm
            .run_with_host(&mut deferred)
            .expect("run with the deferred host");
        assert_eq!(eager_vm.remaining_gas(), deferred_vm.remaining_gas());
        assert_eq!(queued_instructions(&eager), queued_instructions(&deferred));
        assert_eq!(eager.next_nft_sequence(), deferred.next_nft_sequence());
    }
}
