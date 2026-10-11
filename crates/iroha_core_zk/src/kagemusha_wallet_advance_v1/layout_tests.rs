//! Custody layout tests: strict names, directories, root sentinel and the NOREPLACE probe.

use std::io;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletProbeV1, KagemushaWalletRemoveOutcomeV1, KagemushaWalletSimFaultV1,
    KagemushaWalletSimFsV1, KagemushaWalletSimPowerLossV1, KagemushaWalletSimStagedFileV1,
    test_support::sim_store,
};

#[test]
fn wallet_advance_v1_layout_entry_names_are_strict() {
    for valid in [
        "a",
        "root.norito",
        ".tmp-0",
        "m-1.mk",
        "x_y-z.0",
        &"a".repeat(128),
    ] {
        assert!(kagemusha_wallet_valid_entry_name_v1(valid), "{valid}");
        assert_eq!(
            KagemushaWalletEntryNameV1::new(valid).map(|name| name.as_str().to_owned()),
            Some(valid.to_owned())
        );
    }
    for invalid in ["", ".", "..", "A", "a/b", "a\0", "é", " ", &"a".repeat(129)] {
        assert!(
            !kagemusha_wallet_valid_entry_name_v1(invalid),
            "{invalid:?}"
        );
        assert!(KagemushaWalletEntryNameV1::new(invalid).is_none());
    }
    assert!(kagemusha_wallet_is_staging_name_v1(
        ".tmp-0123456789abcdef0123456789abcdef"
    ));
    for not_staging in [
        ".tmp-0123456789abcdef0123456789abcde",
        ".tmp-0123456789ABCDEF0123456789abcdef",
        "tmp-0123456789abcdef0123456789abcdef",
        ".tmp-0123456789abcdef0123456789abcdef0",
    ] {
        assert!(
            !kagemusha_wallet_is_staging_name_v1(not_staging),
            "{not_staging}"
        );
    }
}

#[test]
fn wallet_advance_v1_layout_dirs() {
    let slot = KagemushaWalletSlotIdV1([0xab; 32]);
    let hex = "ab".repeat(32);
    assert_eq!(KagemushaWalletCustodyDirV1::root().label(), ".");
    assert_eq!(kagemusha_wallet_probe_dir_v1().components(), ["probe"]);
    assert_eq!(kagemusha_wallet_slots_dir_v1().label(), "slots");
    assert_eq!(
        kagemusha_wallet_slot_dir_v1(&slot).label(),
        format!("slots/{hex}")
    );
    for (dir, leaf) in [
        (kagemusha_wallet_markers_dir_v1(&slot), "markers"),
        (kagemusha_wallet_capsules_dir_v1(&slot), "capsules"),
        (kagemusha_wallet_completion_dir_v1(&slot), "completion"),
        (kagemusha_wallet_ops_dir_v1(&slot), "ops"),
        (kagemusha_wallet_archive_dir_v1(&slot), "archive"),
    ] {
        assert_eq!(dir.components(), ["slots", hex.as_str(), leaf]);
    }
    assert_eq!(
        kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_INTENT_NAME_V1).as_str(),
        "intent.norito"
    );
}

#[test]
fn wallet_advance_v1_layout_slot_ids() {
    let first = KagemushaWalletSlotIdV1::generate().expect("slot");
    let second = KagemushaWalletSlotIdV1::generate().expect("slot");
    assert_ne!(first, second);
    assert_ne!(first.0, [0; 32]);
    assert_eq!(
        KagemushaWalletSlotIdV1::parse(first.dir_name().as_str()),
        Some(first)
    );
    assert_eq!(KagemushaWalletSlotIdV1::parse(&"00".repeat(32)), None);
    assert_eq!(KagemushaWalletSlotIdV1::parse(&"AB".repeat(32)), None);
    assert_eq!(KagemushaWalletSlotIdV1::parse(&"ab".repeat(31)), None);
    assert_eq!(KagemushaWalletSlotIdV1::parse(&"zz".repeat(32)), None);
}

#[test]
fn wallet_advance_v1_layout_marker_names() {
    for generation in [0, 1, 2, 0xfeed, u128::MAX] {
        let name = kagemusha_wallet_marker_name_v1(generation);
        assert_eq!(name.as_str().len(), 37);
        assert_eq!(
            kagemusha_wallet_parse_marker_name_v1(name.as_str()),
            Some(generation)
        );
    }
    assert_eq!(
        kagemusha_wallet_marker_name_v1(2).as_str(),
        "m-00000000000000000000000000000002.mk"
    );
    for invalid in [
        "m-0000000000000000000000000000002.mk",
        "m-0000000000000000000000000000000A.mk",
        "m-00000000000000000000000000000002.mk.r",
        "n-00000000000000000000000000000002.mk",
        "m-00000000000000000000000000000002",
        "m-+0000000000000000000000000000002.mk",
    ] {
        assert_eq!(
            kagemusha_wallet_parse_marker_name_v1(invalid),
            None,
            "{invalid}"
        );
    }
}

#[test]
fn wallet_advance_v1_layout_capsule_completion_tombstone_names() {
    let digest = [0x5a; 32];
    for copy in KagemushaWalletCopyV1::BOTH {
        let name = kagemusha_wallet_capsule_name_v1(7, &digest, copy);
        assert_eq!(
            kagemusha_wallet_parse_capsule_name_v1(name.as_str()),
            Some(KagemushaWalletCapsuleNameV1 {
                selected_generation: 7,
                capsule_digest: digest,
                copy,
            })
        );
        let name = kagemusha_wallet_completion_name_v1(&digest, copy);
        assert_eq!(
            kagemusha_wallet_parse_completion_name_v1(name.as_str()),
            Some(KagemushaWalletCompletionNameV1 {
                operation_id: digest,
                copy,
            })
        );
    }
    assert!(
        kagemusha_wallet_capsule_name_v1(7, &digest, KagemushaWalletCopyV1::Replica)
            .as_str()
            .ends_with(".cap.r")
    );
    let tombstone = kagemusha_wallet_tombstone_name_v1(&digest);
    assert_eq!(
        kagemusha_wallet_parse_tombstone_name_v1(tombstone.as_str()),
        Some(digest)
    );
    let hex = "5a".repeat(32);
    for invalid in [
        format!("c-00000000000000000000000000000007-{hex}.cap.r.r"),
        format!("c-00000000000000000000000000000007_{hex}.cap"),
        format!("c-00000000000000000000000000000007-{}.cap", "5A".repeat(32)),
        format!("c-7-{hex}.cap"),
        format!("{hex}.cap"),
    ] {
        assert_eq!(
            kagemusha_wallet_parse_capsule_name_v1(&invalid),
            None,
            "{invalid}"
        );
    }
    for invalid in [
        format!("{hex}.cr.r.r"),
        format!("{hex}.crr"),
        format!("{}.cr", "5a".repeat(31)),
    ] {
        assert_eq!(
            kagemusha_wallet_parse_completion_name_v1(&invalid),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        kagemusha_wallet_parse_tombstone_name_v1(&format!("{hex}.tt")),
        None
    );
}

#[test]
fn wallet_advance_v1_layout_credential_names() {
    for index in [0, 1, 42, u32::MAX] {
        let name = kagemusha_wallet_credential_name_v1(index);
        assert_eq!(
            kagemusha_wallet_parse_credential_name_v1(name.as_str()),
            Some(index)
        );
    }
    for invalid in [
        "credential-.norito",
        "credential-01.norito",
        "credential--1.norito",
        "credential-4294967296.norito",
        "credential-1.nor",
    ] {
        assert_eq!(
            kagemusha_wallet_parse_credential_name_v1(invalid),
            None,
            "{invalid}"
        );
    }
}

#[test]
fn wallet_advance_v1_layout_lower_hex() {
    assert_eq!(lower_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    assert_eq!(lower_hex(&[]), "");
    assert_eq!(parse_hex_32(&lower_hex(&[0xc3; 32])), Some([0xc3; 32]));
    assert_eq!(
        parse_hex_u128(&format!("{:032x}", u128::MAX)),
        Some(u128::MAX)
    );
}

#[test]
fn wallet_advance_v1_layout_root_sentinel_codec() {
    let sentinel = KagemushaWalletRootSentinelV1 {
        version: 1,
        root_nonce: [3; 32],
    };
    let bytes = sentinel.encode().expect("encode");
    assert_eq!(KagemushaWalletRootSentinelV1::decode(&bytes), Ok(sentinel));
    for invalid in [
        KagemushaWalletRootSentinelV1 {
            version: 2,
            ..sentinel
        },
        KagemushaWalletRootSentinelV1 {
            root_nonce: [0; 32],
            ..sentinel
        },
    ] {
        assert!(invalid.encode().is_err());
        let bytes = norito::encode_canonical(&invalid).expect("raw");
        assert!(KagemushaWalletRootSentinelV1::decode(&bytes).is_err());
    }
}

#[test]
fn wallet_advance_v1_layout_prepare_root_is_durable_and_idempotent() {
    let (fs, store) = sim_store();
    assert_eq!(kagemusha_wallet_read_root_sentinel_v1(&store), Ok(None));
    let sentinel = kagemusha_wallet_prepare_root_v1(&store).expect("prepare");
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(
        kagemusha_wallet_read_root_sentinel_v1(&store),
        Ok(Some(sentinel))
    );
    assert_eq!(kagemusha_wallet_prepare_root_v1(&store), Ok(sentinel));
    assert!(fs.visible_dir(&kagemusha_wallet_probe_dir_v1()));
    assert!(fs.visible_dir(&kagemusha_wallet_slots_dir_v1()));
    assert_eq!(kagemusha_wallet_list_slots_v1(&store), Ok(Some(Vec::new())));
}

#[test]
fn wallet_advance_v1_layout_read_root_sentinel_fails_closed() {
    let (fs, store) = sim_store();
    let root = KagemushaWalletCustodyDirV1::root();
    let sentinel = kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1);
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_read_root_sentinel_v1(&store),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    fs.inject(
        fs.steps(),
        KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        kagemusha_wallet_prepare_root_v1(&store),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    assert_eq!(
        fs.visible_names(&root),
        Vec::<String>::new(),
        "nothing created on error"
    );
    store.write_new(&root, &sentinel, b"garbage");
    assert_eq!(
        kagemusha_wallet_read_root_sentinel_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "root sentinel"
        })
    );
    assert!(
        kagemusha_wallet_prepare_root_v1(&store).is_err(),
        "never replaced"
    );
    assert_eq!(
        store.remove_file(&root, &sentinel),
        KagemushaWalletRemoveOutcomeV1::Removed
    );
    store.write_new(
        &root,
        &sentinel,
        &vec![0_u8; KAGEMUSHA_WALLET_ROOT_SENTINEL_MAX_BYTES_V1 + 1],
    );
    assert_eq!(
        kagemusha_wallet_read_root_sentinel_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "root sentinel"
        })
    );
}

#[test]
fn wallet_advance_v1_layout_prepare_slot_and_list_slots() {
    let (fs, store) = sim_store();
    assert_eq!(kagemusha_wallet_list_slots_v1(&store), Ok(None));
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    let slot = KagemushaWalletSlotIdV1([0x21; 32]);
    kagemusha_wallet_prepare_slot_dirs_v1(&store, &slot).expect("slot");
    kagemusha_wallet_prepare_slot_dirs_v1(&store, &slot).expect("idempotent");
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    for dir in [
        kagemusha_wallet_markers_dir_v1(&slot),
        kagemusha_wallet_capsules_dir_v1(&slot),
        kagemusha_wallet_completion_dir_v1(&slot),
        kagemusha_wallet_ops_dir_v1(&slot),
        kagemusha_wallet_archive_dir_v1(&slot),
    ] {
        assert!(fs.visible_dir(&dir), "{}", dir.label());
    }
    fs.place_unsynced(
        &kagemusha_wallet_slots_dir_v1(),
        ".tmp-000000000000000000000000000000ff",
        b"",
    );
    assert_eq!(kagemusha_wallet_list_slots_v1(&store), Ok(Some(vec![slot])));
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_list_slots_v1(&store),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    fs.place_unsynced(&kagemusha_wallet_slots_dir_v1(), "stray", b"");
    assert_eq!(
        kagemusha_wallet_list_slots_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slots" })
    );
    assert_eq!(
        kagemusha_wallet_list_dir_v1(
            &store,
            &kagemusha_wallet_slots_dir_v1()
                .child(&KagemushaWalletEntryNameV1::new("absent").expect("name"))
        ),
        Ok(None)
    );
}

#[test]
fn wallet_advance_v1_layout_outcome_mappings() {
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletNotPublishedV1 as N, KagemushaWalletPublishOutcomeV1 as P,
        KagemushaWalletUnavailableV1 as U,
    };
    assert_eq!(kagemusha_wallet_require_published_v1(P::Published), Ok(()));
    assert_eq!(
        kagemusha_wallet_require_published_v1(P::Uncertain(U::Io(5))),
        Err(KagemushaWalletProviderErrorV1::Uncertain(U::Io(5)))
    );
    for (reason, error) in [
        (N::NoSpace, KagemushaWalletProviderErrorV1::NoSpace),
        (
            N::NoReplaceUnsupported,
            KagemushaWalletProviderErrorV1::NoReplaceUnsupported,
        ),
        (
            N::DestinationExists,
            KagemushaWalletProviderErrorV1::Unavailable(U::Busy),
        ),
        (
            N::DestinationAbsent,
            KagemushaWalletProviderErrorV1::Unavailable(U::Busy),
        ),
        (
            N::ContentMismatch,
            KagemushaWalletProviderErrorV1::Invalid {
                field: "rewrite content",
            },
        ),
        (
            N::Failed(U::Locked),
            KagemushaWalletProviderErrorV1::Unavailable(U::Locked),
        ),
    ] {
        assert_eq!(
            kagemusha_wallet_require_published_v1(P::NotPublished(reason)),
            Err(error)
        );
    }
    assert_eq!(
        kagemusha_wallet_require_dir_v1(P::NotPublished(N::DestinationExists)),
        Ok(())
    );
    assert_eq!(
        kagemusha_wallet_require_dir_v1(P::NotPublished(N::NoSpace)),
        Err(KagemushaWalletProviderErrorV1::NoSpace)
    );
    assert_eq!(
        kagemusha_wallet_require_removed_v1(KagemushaWalletRemoveOutcomeV1::Removed),
        Ok(())
    );
    assert_eq!(
        kagemusha_wallet_require_removed_v1(KagemushaWalletRemoveOutcomeV1::NotRemoved(U::Io(1))),
        Err(KagemushaWalletProviderErrorV1::Unavailable(U::Io(1)))
    );
    assert_eq!(
        kagemusha_wallet_require_removed_v1(KagemushaWalletRemoveOutcomeV1::Uncertain(U::Io(1))),
        Err(KagemushaWalletProviderErrorV1::Uncertain(U::Io(1)))
    );
}

/// Filesystem whose create-new rename silently replaces, as a broken filesystem would.
struct ReplacingFsV1(KagemushaWalletSimFsV1);

impl KagemushaWalletFsV1 for ReplacingFsV1 {
    type StagedFile = KagemushaWalletSimStagedFileV1;
    type Lock = <KagemushaWalletSimFsV1 as KagemushaWalletFsV1>::Lock;

    fn create_new(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
    ) -> io::Result<Self::StagedFile> {
        self.0.create_new(dir, name)
    }
    fn write_all(&self, file: &mut Self::StagedFile, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(file, bytes)
    }
    fn sync_staged(&self, file: &Self::StagedFile) -> io::Result<()> {
        self.0.sync_staged(file)
    }
    fn sync_named(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.0.sync_named(dir, name)
    }
    fn rename_noreplace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()> {
        self.0.rename_replace(dir, from, to)
    }
    fn rename_replace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()> {
        self.0.rename_replace(dir, from, to)
    }
    fn unlink(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.0.unlink(dir, name)
    }
    fn sync_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> io::Result<()> {
        self.0.sync_dir(dir)
    }
    fn mkdir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.0.mkdir(parent, name)
    }
    fn remove_dir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.0.remove_dir(parent, name)
    }
    fn read(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
        limit: usize,
    ) -> io::Result<Vec<u8>> {
        self.0.read(dir, name, limit)
    }
    fn list(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> io::Result<Vec<KagemushaWalletListedEntryV1>> {
        self.0.list(dir)
    }
    fn available_bytes(&self) -> io::Result<u64> {
        self.0.available_bytes()
    }
    fn try_lock(&self) -> io::Result<Self::Lock> {
        self.0.try_lock()
    }
    fn staging_name(&self) -> io::Result<String> {
        self.0.staging_name()
    }
}

#[test]
fn wallet_advance_v1_layout_noreplace_probe() {
    let (fs, store) = sim_store();
    assert_eq!(kagemusha_wallet_probe_noreplace_v1(&store), Ok(()));
    assert_eq!(
        kagemusha_wallet_probe_noreplace_v1(&store),
        Ok(()),
        "repeatable"
    );
    assert_eq!(
        fs.visible_names(&kagemusha_wallet_probe_dir_v1()),
        Vec::<String>::new()
    );
    fs.set_noreplace_supported(false);
    assert_eq!(
        kagemusha_wallet_probe_noreplace_v1(&store),
        Err(KagemushaWalletProviderErrorV1::NoReplaceUnsupported)
    );
    let replacing =
        KagemushaWalletDurableStoreV1::new(ReplacingFsV1(KagemushaWalletSimFsV1::new()));
    assert_eq!(
        kagemusha_wallet_probe_noreplace_v1(&replacing),
        Err(KagemushaWalletProviderErrorV1::NoReplaceUnsupported)
    );
    let (fs, store) = sim_store();
    fs.inject(fs.steps() + 2, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_probe_noreplace_v1(&store),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_)
            | KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    assert!(matches!(
        store.list(&kagemusha_wallet_probe_dir_v1()),
        KagemushaWalletProbeV1::Present(_)
    ));
}

/// Bytes in use on `fs`, so a capacity of this plus `room` leaves exactly `room` free.
fn used(fs: &KagemushaWalletSimFsV1) -> u64 {
    let probe = fs.fork();
    probe.set_capacity(Some(u64::MAX / 4));
    let store = KagemushaWalletDurableStoreV1::new(probe);
    u64::MAX / 4 - store.available_bytes().expect("free")
}

#[test]
fn wallet_advance_v1_layout_noreplace_probe_full_disk_is_a_capacity_retry() {
    // Regression: a full disk at the second probe write used to be reported as the permanent
    // "filesystem lacks create-new rename" diagnostic.
    let (fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    // Room for the first probe file (5 bytes) but not for the second staging write.
    fs.set_capacity(Some(used(&fs) + 10));
    assert_eq!(
        kagemusha_wallet_probe_noreplace_v1(&store),
        Err(KagemushaWalletProviderErrorV1::NoSpace)
    );
    fs.set_capacity(None);
    assert_eq!(kagemusha_wallet_probe_noreplace_v1(&store), Ok(()));
}

#[test]
fn wallet_advance_v1_layout_existing_non_directories_are_refused() {
    // Regression: an existing file named like a custody directory used to pass preparation
    // and fail every later operation with ENOTDIR.
    let (fs, store) = sim_store();
    fs.place_unsynced(
        &KagemushaWalletCustodyDirV1::root(),
        KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1,
        b"x",
    );
    assert_eq!(
        kagemusha_wallet_prepare_root_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "." })
    );
    let (fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    let slot = KagemushaWalletSlotIdV1([0x23; 32]);
    fs.place_unsynced(
        &kagemusha_wallet_slots_dir_v1(),
        slot.dir_name().as_str(),
        b"x",
    );
    assert_eq!(
        kagemusha_wallet_prepare_slot_dirs_v1(&store, &slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slots" })
    );
    let other = KagemushaWalletSlotIdV1([0x24; 32]);
    kagemusha_wallet_ensure_dir_v1(&store, &kagemusha_wallet_slots_dir_v1(), &other.dir_name())
        .expect("slot");
    fs.place_other(
        &kagemusha_wallet_slot_dir_v1(&other),
        KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1,
    );
    assert_eq!(
        kagemusha_wallet_prepare_slot_dirs_v1(&store, &other),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slot" })
    );
    // An existing directory is adopted.
    kagemusha_wallet_ensure_dir_v1(&store, &kagemusha_wallet_slots_dir_v1(), &other.dir_name())
        .expect("existing directory");
    assert_eq!(dir_label(&kagemusha_wallet_probe_dir_v1()), "probe");
    assert_eq!(
        dir_label(&kagemusha_wallet_markers_dir_v1(&other)),
        "custody"
    );
}

#[test]
fn wallet_advance_v1_layout_sentinel_is_the_commit_point_of_the_skeleton() {
    // Regression: after a first open whose root sync lost its writeback, the skeleton was
    // adopted on the evidence of a vacuous sync and could vanish at the next power loss.
    let root = KagemushaWalletCustodyDirV1::root();
    let base = KagemushaWalletSimFsV1::new();
    let probe = base.fork();
    let start = probe.steps();
    kagemusha_wallet_prepare_root_v1(&KagemushaWalletDurableStoreV1::new(probe.clone()))
        .expect("probe");
    let syncs: Vec<u64> = probe
        .trace_since(start)
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            **step == crate::kagemusha_wallet_advance_v1::KagemushaWalletSimStepV1::SyncDir
        })
        .map(|(index, _)| u64::try_from(index).expect("index"))
        .collect();
    assert!(syncs.len() >= 3, "{syncs:?}");
    for sync in syncs {
        let fs = base.fork();
        let store = KagemushaWalletDurableStoreV1::new(fs.clone());
        fs.inject(fs.steps() + sync, KagemushaWalletSimFaultV1::LostWriteback);
        assert!(matches!(
            kagemusha_wallet_prepare_root_v1(&store),
            Err(KagemushaWalletProviderErrorV1::Uncertain(_))
        ));
        // Same boot: prepared again (the lost entries are recreated), then power is lost.
        let sentinel = kagemusha_wallet_prepare_root_v1(&store).expect("same-boot reopen");
        fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
        assert_eq!(
            kagemusha_wallet_read_root_sentinel_v1(&store),
            Ok(Some(sentinel)),
            "sync {sync}"
        );
        assert!(
            fs.visible_dir(&kagemusha_wallet_slots_dir_v1()),
            "sync {sync}"
        );
        assert_eq!(kagemusha_wallet_prepare_root_v1(&store), Ok(sentinel));
    }
    // Every open adopts the sentinel on a fresh inode.
    let (fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    let inode = fs.inode_of(&root, KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1);
    kagemusha_wallet_prepare_root_v1(&store).expect("adopt");
    assert_ne!(
        fs.inode_of(&root, KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1),
        inode
    );
    // A sentinel without `slots/` is refused, never answered with an empty wallet.
    assert_eq!(
        store.remove_dir(&root, &fixed(KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1)),
        KagemushaWalletRemoveOutcomeV1::Removed
    );
    assert_eq!(
        kagemusha_wallet_prepare_root_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "custody root"
        })
    );
    assert!(
        !fs.visible_dir(&kagemusha_wallet_slots_dir_v1()),
        "not recreated"
    );
    // Without a sentinel, skeleton directories must be empty.
    let (fs, store) = sim_store();
    kagemusha_wallet_ensure_dir_v1(&store, &root, &fixed(KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1))
        .expect("slots");
    fs.place_unsynced(&kagemusha_wallet_slots_dir_v1(), "leftover", b"x");
    assert_eq!(
        kagemusha_wallet_prepare_root_v1(&store),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "custody root"
        })
    );
    // A full disk at adoption draws the ballast once.
    let (fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    store.write_new(&root, &fixed(KAGEMUSHA_WALLET_BALLAST_NAME_V1), &[7; 1_024]);
    fs.set_capacity(Some(used(&fs)));
    kagemusha_wallet_prepare_root_v1(&store).expect("adopted after drawing the ballast");
    assert_eq!(
        fs.visible_file(&root, KAGEMUSHA_WALLET_BALLAST_NAME_V1),
        None
    );
    assert_eq!(kagemusha_wallet_draw_ballast_v1(&store), Ok(false));
}
