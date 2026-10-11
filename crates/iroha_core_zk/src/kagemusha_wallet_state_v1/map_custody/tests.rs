//! Real G1 map/array witnesses; these storage tests confer no proof or custody authority.

use super::super::tests::{MemoryArchive, fixture};
use super::*;
use KagemushaWalletOperationKindV1 as K;
use KagemushaWalletPolicyUpdateKindV1 as R;

fn field(x: u128) -> [u8; 32] {
    kagemusha_wallet_field_from_u128_v1(x)
}
fn state() -> KagemushaWalletStateV1 {
    KagemushaWalletStateV1::bootstrap(&fixture("KagemushaWalletCredentialV1"), field(7)).unwrap()
}
fn set_root(state: &mut KagemushaWalletStateV1, role: PreparationMapV1, root: [u8; 32]) {
    match role {
        PreparationMapV1::Consumed => state.core.consumed_credit_root = root,
        PreparationMapV1::Pending => state.core.pending_outgoing_root = root,
        PreparationMapV1::Recovery => state.core.load_redeem_recovery_root = root,
        PreparationMapV1::Fee => state.core.fee_claim_root = root,
        PreparationMapV1::BlacklistHistory => state.rest.blacklist_history_root = root,
    }
}

#[test]
fn exact_state_roots_and_canonical_snapshot_survive_restart() {
    let maps = SourceMapsV1::default();
    let state = state();
    maps.require(&state).unwrap();
    let encoded = archive::encode(&maps).unwrap();
    let decoded: SourceMapsV1 = archive::decode(&encoded).unwrap();
    decoded.require(&state).unwrap();
    assert_eq!(archive::encode(&decoded).unwrap(), encoded);
    for role in PreparationMapV1::ALL {
        let mut wrong = state;
        set_root(&mut wrong, role, field(9));
        assert!(decoded.require(&wrong).is_err());
    }
    let mut wrong = state;
    wrong.core.quota_usage_root = field(9);
    assert!(decoded.require(&wrong).is_err());
    let mut wrong = decoded;
    wrong.version = 2;
    assert!(wrong.require(&state).is_err());
}

#[test]
fn every_operation_can_only_mutate_its_fixed_map_roles() {
    for kind in K::ALL {
        let refresh = (kind == K::RefreshPolicy).then_some(R::Blacklist);
        for role in PreparationMapV1::ALL {
            let mut store = MemoryArchive::new();
            let original = SourceMapsV1::default();
            let state = state();
            let mut view =
                PreparationMapsV1::new(&mut store, &original, &state, kind, refresh).unwrap();
            let allowed = matches!(
                (kind, role),
                (K::Receive, PreparationMapV1::Consumed)
                    | (K::Send, PreparationMapV1::Pending | PreparationMapV1::Fee)
                    | (K::Load | K::Unload, PreparationMapV1::Recovery)
                    | (K::RefreshPolicy, PreparationMapV1::BlacklistHistory)
            );
            let insertion = view.insert(role, field(3), field(4));
            assert_eq!(insertion.is_ok(), allowed, "{kind:?} {role:?}");
            if let Ok(insertion) = insertion {
                let mut successor = state;
                set_root(
                    &mut successor,
                    role,
                    insertion
                        .verify(&role.state_root(&state), &field(3), &field(4))
                        .unwrap(),
                );
                let (leaf, opening) = view.membership(role, &field(3)).unwrap();
                assert_eq!(
                    opening.leaf_root(&leaf).unwrap(),
                    role.state_root(&successor)
                );
                assert!(view.non_membership(role, &field(3)).is_err());
                view.non_membership(role, &field(8)).unwrap();
                view.finish(&successor).unwrap();
                original.require(&state).unwrap();
            } else {
                view.finish(&state).unwrap();
            }
        }
    }
}

#[test]
fn abandoned_draft_never_changes_source_and_wrong_successor_cannot_be_published() {
    let mut store = MemoryArchive::new();
    let original = SourceMapsV1::default();
    let state = state();
    let before = archive::encode(&original).unwrap();
    let mut draft =
        PreparationMapsV1::new(&mut store, &original, &state, K::Receive, None).unwrap();
    draft
        .insert(PreparationMapV1::Consumed, field(3), field(4))
        .unwrap();
    assert!(draft.finish(&state).is_err());
    assert_eq!(archive::encode(&original).unwrap(), before);
    let mut restored =
        PreparationMapsV1::new(&mut store, &original, &state, K::Receive, None).unwrap();
    restored
        .non_membership(PreparationMapV1::Consumed, &field(3))
        .unwrap();
    restored
        .insert(PreparationMapV1::Consumed, field(3), field(4))
        .unwrap();
    drop(restored);
    assert_eq!(archive::encode(&original).unwrap(), before);
}

#[test]
fn only_archive_can_clear_pending_and_its_removed_slot_is_not_reused() {
    let mut store = MemoryArchive::new();
    let maps = SourceMapsV1::default();
    let initial = state();
    let mut send = PreparationMapsV1::new(&mut store, &maps, &initial, K::Send, None).unwrap();
    let insertion = send
        .insert(PreparationMapV1::Pending, field(3), field(4))
        .unwrap();
    let mut sent = initial;
    sent.core.pending_outgoing_root = insertion
        .verify(&initial.core.pending_outgoing_root, &field(3), &field(4))
        .unwrap();
    let maps = send.finish(&sent).unwrap();
    for kind in K::ALL {
        let mut view = PreparationMapsV1::new(
            &mut store,
            &maps,
            &sent,
            kind,
            (kind == K::RefreshPolicy).then_some(R::Blacklist),
        )
        .unwrap();
        assert!(view.remove(PreparationMapV1::Recovery, &field(3)).is_err());
        let removal = view.remove(PreparationMapV1::Pending, &field(3));
        assert_eq!(removal.is_ok(), kind == K::ArchiveSent);
        if let Ok(removal) = removal {
            let mut removed = sent;
            removed.core.pending_outgoing_root = removal
                .verify(&sent.core.pending_outgoing_root, &field(3))
                .unwrap();
            let removed_maps = view.finish(&removed).unwrap();
            let mut next =
                PreparationMapsV1::new(&mut store, &removed_maps, &removed, K::Send, None).unwrap();
            assert_eq!(
                next.insert(PreparationMapV1::Pending, field(3), field(4))
                    .unwrap()
                    .slot_opening
                    .slot,
                2
            );
        }
    }
}

#[test]
fn quota_is_exactly_sixty_four_slots_and_only_send_or_share_refresh_can_change_it() {
    let mut slots = [None; 64];
    slots[0] = Some(KagemushaWalletQuotaUsageLeafV1 {
        window_kind: KagemushaWalletQuotaWindowKindV1::Daily,
        window_start_ms: 10,
        window_end_ms: 20,
        used: 11,
    });
    let usage = KagemushaWalletQuotaUsageArrayV1::from_slots(slots).unwrap();
    for kind in K::ALL {
        let mut store = MemoryArchive::new();
        let maps = SourceMapsV1::default();
        let state = state();
        let mut view = PreparationMapsV1::new(
            &mut store,
            &maps,
            &state,
            kind,
            (kind == K::RefreshPolicy).then_some(R::QuotaShare),
        )
        .unwrap();
        assert_eq!(
            view.quota_usage().unwrap(),
            KagemushaWalletQuotaUsageArrayV1::empty()
        );
        let changed = view.set_quota_usage(&usage);
        assert_eq!(changed.is_ok(), matches!(kind, K::Send | K::RefreshPolicy));
        if changed.is_ok() {
            assert_eq!(view.quota_usage().unwrap(), usage);
            let mut successor = state;
            successor.core.quota_usage_root = usage.root();
            let updated = view.finish(&successor).unwrap();
            let restored: SourceMapsV1 =
                archive::decode(&archive::encode(&updated).unwrap()).unwrap();
            restored.require(&successor).unwrap();
        }
    }
    let mut malformed = SourceMapsV1::default();
    malformed.quota_slots[1] = slots[0];
    assert!(malformed.quota_usage().is_err());
}

#[test]
fn source_snapshot_preserves_all_quota_slots_and_binds_the_complete_root() {
    let slots = core::array::from_fn(|i| {
        Some(KagemushaWalletQuotaUsageLeafV1 {
            window_kind: KagemushaWalletQuotaWindowKindV1::Daily,
            window_start_ms: i as u64 * 100,
            window_end_ms: i as u64 * 100 + 99,
            used: i as u128 * 19,
        })
    });
    let usage = KagemushaWalletQuotaUsageArrayV1::from_slots(slots).unwrap();
    let mut store = MemoryArchive::new();
    let original = SourceMapsV1::default();
    let before = state();
    let mut draft = PreparationMapsV1::new(&mut store, &original, &before, K::Send, None).unwrap();
    draft.set_quota_usage(&usage).unwrap();
    let mut after = before;
    after.core.quota_usage_root = usage.root();
    let selected = draft.finish(&after).unwrap();
    let encoded = archive::encode(&selected).unwrap();
    let restored: SourceMapsV1 = archive::decode(&encoded).unwrap();
    restored.require(&after).unwrap();
    assert_eq!(restored.quota_usage().unwrap(), usage);
    assert_eq!(restored.quota_slots, slots);
    assert_eq!(archive::encode(&restored).unwrap(), encoded);
    let mut changed = restored;
    changed.quota_slots[63].as_mut().unwrap().used += 1;
    assert_ne!(changed.quota_usage().unwrap().root(), usage.root());
    assert!(changed.require(&after).is_err());
}

#[test]
fn malformed_source_or_refresh_selector_is_rejected_before_map_access() {
    let mut store = MemoryArchive::new();
    let maps = SourceMapsV1::default();
    let mut state = state();
    assert!(
        PreparationMapsV1::new(&mut store, &maps, &state, K::Send, Some(R::Blacklist)).is_err()
    );
    assert!(PreparationMapsV1::new(&mut store, &maps, &state, K::RefreshPolicy, None).is_err());
    state.core.consumed_credit_root = field(1);
    assert!(PreparationMapsV1::new(&mut store, &maps, &state, K::Receive, None).is_err());
}

#[derive(Clone, Copy)]
enum ReadFault {
    None,
    Missing,
    Corrupt,
    Unavailable,
    Protected,
}

struct StorageProbe {
    inner: MemoryArchive,
    read_fault: ReadFault,
    writes_before_failure: Option<usize>,
    reads: usize,
    writes: usize,
}

impl StorageProbe {
    fn new() -> Self {
        Self {
            inner: MemoryArchive::new(),
            read_fault: ReadFault::None,
            writes_before_failure: None,
            reads: 0,
            writes: 0,
        }
    }
}

impl ArchiveStore for StorageProbe {
    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        self.inner.binding()
    }

    fn get(&mut self, key: ArchiveKey, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        self.reads += 1;
        match self.read_fault {
            ReadFault::None => self.inner.get(key, maximum),
            ReadFault::Missing => Ok(None),
            ReadFault::Corrupt => {
                let mut bytes = self.inner.get(key, maximum)?.unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                Ok(Some(bytes))
            }
            ReadFault::Unavailable => Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
            ReadFault::Protected => Err(Error::Provider(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                    crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
                ),
            )),
        }
    }

    fn put(&mut self, key: ArchiveKey, original: &[u8]) -> Result<(), Error> {
        self.writes += 1;
        if let Some(remaining) = &mut self.writes_before_failure {
            if *remaining == 0 {
                return Err(Error::Storage(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                )));
            }
            *remaining -= 1;
        }
        self.inner.put(key, original)
    }

    fn remove(&mut self, _: ArchiveKey) -> Result<(), Error> {
        panic!("unpublished preparation does not authorize archive collection")
    }
}

fn nonempty_sources(store: &mut StorageProbe) -> (SourceMapsV1, KagemushaWalletStateV1) {
    let maps = SourceMapsV1::default();
    let initial = state();
    let mut draft = PreparationMapsV1::new(store, &maps, &initial, K::Send, None).unwrap();
    let insertion = draft
        .insert(PreparationMapV1::Pending, field(3), field(4))
        .unwrap();
    let mut selected = initial;
    selected.core.pending_outgoing_root = insertion
        .verify(&initial.core.pending_outgoing_root, &field(3), &field(4))
        .unwrap();
    (draft.finish(&selected).unwrap(), selected)
}

#[test]
fn invalid_state_with_identical_map_and_quota_roots_is_refused_before_storage_access() {
    let maps = SourceMapsV1::default();
    for changed in [
        KagemushaWalletStateV1 {
            version: 2,
            ..state()
        },
        {
            let mut changed = state();
            changed.core.state_nonce = [0; 32];
            changed
        },
        {
            let mut changed = state();
            changed.core.enabled_controls = 8;
            changed
        },
    ] {
        assert!(changed.validate().is_err());
        let mut store = StorageProbe::new();
        assert!(matches!(
            PreparationMapsV1::new(&mut store, &maps, &changed, K::Send, None),
            Err(Error::WitnessLost("source map state"))
        ));
        assert_eq!(store.reads, 0);
        assert_eq!(store.writes, 0);
    }
}

#[test]
fn selected_missing_or_corrupt_objects_never_produce_absence_openings() {
    let mut store = StorageProbe::new();
    let (maps, selected) = nonempty_sources(&mut store);
    let original = archive::encode(&maps).unwrap();
    for fault in [ReadFault::Missing, ReadFault::Corrupt] {
        store.read_fault = fault;
        let mut view = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
        assert!(matches!(
            view.non_membership(PreparationMapV1::Pending, &field(9)),
            Err(Error::WitnessLost(_))
        ));
        assert!(matches!(
            view.membership(PreparationMapV1::Pending, &field(3)),
            Err(Error::WitnessLost(_))
        ));
        assert!(
            view.insert(PreparationMapV1::Pending, field(9), field(10))
                .is_err()
        );
        drop(view);
        assert_eq!(archive::encode(&maps).unwrap(), original);
    }
    store.read_fault = ReadFault::None;
    let mut restored = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    assert_eq!(
        restored
            .membership(PreparationMapV1::Pending, &field(3))
            .unwrap()
            .0
            .value,
        field(4)
    );
    restored
        .non_membership(PreparationMapV1::Pending, &field(9))
        .unwrap();
}

#[test]
fn unavailable_or_locked_selected_storage_remains_retryable_without_any_write() {
    let mut store = StorageProbe::new();
    let (maps, selected) = nonempty_sources(&mut store);
    let writes = store.writes;
    store.read_fault = ReadFault::Unavailable;
    let mut view = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    match view.non_membership(PreparationMapV1::Pending, &field(9)) {
        Err(Error::Storage(error)) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        other => panic!("temporary storage failure cannot mean nonmembership: {other:?}"),
    }
    drop(view);
    store.read_fault = ReadFault::Protected;
    let mut view = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    assert!(matches!(
        view.membership(PreparationMapV1::Pending, &field(3)),
        Err(Error::Provider(
            crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
            )
        ))
    ));
    drop(view);
    assert_eq!(store.writes, writes);
    store.read_fault = ReadFault::None;
    let mut view = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    view.membership(PreparationMapV1::Pending, &field(3))
        .unwrap();
}

#[test]
fn partial_insert_or_remove_publication_keeps_the_exact_selected_source() {
    let mut store = StorageProbe::new();
    let (maps, selected) = nonempty_sources(&mut store);
    let original = archive::encode(&maps).unwrap();
    let mut control = StorageProbe {
        inner: store.inner.clone(),
        ..StorageProbe::new()
    };
    let mut expected =
        PreparationMapsV1::new(&mut control, &maps, &selected, K::Send, None).unwrap();
    let insertion = expected
        .insert(PreparationMapV1::Pending, field(9), field(10))
        .unwrap();
    drop(expected);
    store.writes_before_failure = Some(7);
    let mut view = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    assert!(matches!(
        view.insert(PreparationMapV1::Pending, field(9), field(10)),
        Err(Error::Storage(_))
    ));
    view.finish(&selected).unwrap();
    assert_eq!(archive::encode(&maps).unwrap(), original);
    store.writes_before_failure = None;
    let mut retry = PreparationMapsV1::new(&mut store, &maps, &selected, K::Send, None).unwrap();
    assert_eq!(
        retry
            .insert(PreparationMapV1::Pending, field(9), field(10))
            .unwrap(),
        insertion
    );
    drop(retry);
    store.writes_before_failure = Some(7);
    let mut view =
        PreparationMapsV1::new(&mut store, &maps, &selected, K::ArchiveSent, None).unwrap();
    assert!(matches!(
        view.remove(PreparationMapV1::Pending, &field(3)),
        Err(Error::Storage(_))
    ));
    view.finish(&selected).unwrap();
    store.writes_before_failure = None;
    let mut retry =
        PreparationMapsV1::new(&mut store, &maps, &selected, K::ArchiveSent, None).unwrap();
    let removal = retry.remove(PreparationMapV1::Pending, &field(3)).unwrap();
    assert_eq!(
        removal
            .verify(&selected.core.pending_outgoing_root, &field(3))
            .unwrap(),
        kagemusha_wallet_empty_map_root_v1()
    );
    assert_eq!(archive::encode(&maps).unwrap(), original);
}

#[test]
fn invalid_state_cannot_construct_or_finish_a_matching_map_draft() {
    let source = state();
    let maps = SourceMapsV1::default();
    for fault in 0..6 {
        let mut invalid = source;
        match fault {
            0 => invalid.version = 2,
            1 => invalid.core.wallet_id = [0; 32],
            2 => invalid.core.state_nonce = [0; 32],
            3 => invalid.core.state_nonce = [255; 32],
            4 => invalid.rest.scheme_policy = field(2),
            _ => invalid.core.blacklist_version = 1,
        }
        assert!(invalid.validate().is_err());
        // Every role/array root is unchanged: equality alone cannot admit this source.
        for role in PreparationMapV1::ALL {
            assert_eq!(role.state_root(&invalid), role.state_root(&source));
        }
        assert!(matches!(
            maps.require(&invalid),
            Err(Error::WitnessLost("source map state"))
        ));
        let mut store = MemoryArchive::new();
        assert!(PreparationMapsV1::new(&mut store, &maps, &invalid, K::Send, None).is_err());
        let draft = PreparationMapsV1::new(&mut store, &maps, &source, K::Send, None).unwrap();
        assert!(draft.finish(&invalid).is_err());
        maps.require(&source).unwrap();
    }
}
