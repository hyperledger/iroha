//! Selected enrollment inventory adoption fails closed on storage faults and replacements.

use std::{cell::RefCell, io};

use iroha_data_model::kagemusha::{
    KagemushaWalletCompletionRecordV1, KagemushaWalletRecoveryCapsuleV1,
};

use super::test_support::{DeviceV1, SCHEME, enrolled_device, test_options};
use super::*;

fn selected_fixture(seed: u8) -> (DeviceV1, KagemushaWalletSlotIdV1) {
    let (device, _, slot) = enrolled_device(KagemushaWalletAnchorPolicyV1::Keychain, seed);
    (device, slot)
}

#[test]
fn selected_enrollment_inventory_adoption_faults_never_publish_a_verified_cache() {
    use KagemushaWalletSimFaultV1 as Fault;
    use KagemushaWalletSimStepV1 as Step;

    let (base, slot) = selected_fixture(193);
    let trace = {
        let d = base.fork();
        let provider = d.open();
        let from = d.fs.steps();
        assert!(provider.enrollment_phase_for_slot(&slot).unwrap().is_some());
        d.fs.trace_since(from)
    };
    assert_eq!(
        trace
            .iter()
            .filter(|step| **step == Step::RenameReplace)
            .count(),
        4,
        "fresh provider adopts exactly Phase, Client, Accepted and Slot"
    );
    let mut cases = 0;
    for (offset, step) in trace.iter().enumerate() {
        if !matches!(
            step,
            Step::Read
                | Step::List
                | Step::CreateNew
                | Step::Write
                | Step::SyncFile
                | Step::RenameReplace
                | Step::SyncDir
        ) {
            continue;
        }
        for fault in [Fault::Error, Fault::LostWriteback] {
            if fault == Fault::LostWriteback && !matches!(step, Step::SyncFile | Step::SyncDir) {
                continue;
            }
            let d = base.fork();
            let provider = d.open();
            let key = d.platform.key_of(&slot);
            d.fs.inject(d.fs.steps() + u64::try_from(offset).unwrap(), fault);
            assert!(
                provider.enrollment_phase_for_slot(&slot).is_err(),
                "step {offset} {step:?} {fault:?} cannot admit selected originals"
            );
            assert!(
                !provider.slot_phases.borrow().contains_key(&slot),
                "a failed adoption cannot publish a verified phase cache"
            );
            d.fs.clear_faults();
            assert!(
                provider.enrollment_phase_for_slot(&slot).unwrap().is_some(),
                "retry must durably adopt unchanged originals"
            );
            assert_eq!(d.platform.key_of(&slot), key);
            d.platform.with(|s| {
                assert_eq!(s.generate_calls, 1);
                assert_eq!(s.delete_calls, 0);
                assert!(s.violations.is_empty());
            });
            cases += 1;
        }
    }
    assert!(
        cases > 20,
        "exercise selected-original reads and all four adoptions"
    );
}

struct Mutation {
    trigger: String,
    target: String,
    replacement: Vec<u8>,
}

/// Replace one original immediately after a selected original's adoption rename succeeds.
/// The rest of the filesystem is the existing durability simulator.
struct ReplacingDuringAdoption {
    inner: KagemushaWalletSimFsV1,
    mutation: RefCell<Option<Mutation>>,
}

impl KagemushaWalletFsV1 for ReplacingDuringAdoption {
    type StagedFile = KagemushaWalletSimStagedFileV1;
    type Lock = <KagemushaWalletSimFsV1 as KagemushaWalletFsV1>::Lock;

    fn create_new(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
    ) -> io::Result<Self::StagedFile> {
        self.inner.create_new(dir, name)
    }
    fn write_all(&self, file: &mut Self::StagedFile, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(file, bytes)
    }
    fn sync_staged(&self, file: &Self::StagedFile) -> io::Result<()> {
        self.inner.sync_staged(file)
    }
    fn sync_named(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.inner.sync_named(dir, name)
    }
    fn rename_noreplace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()> {
        self.inner.rename_noreplace(dir, from, to)
    }
    fn rename_replace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()> {
        self.inner.rename_replace(dir, from, to)?;
        let matches = self
            .mutation
            .borrow()
            .as_ref()
            .is_some_and(|m| m.trigger == to);
        if matches {
            let mutation = self.mutation.borrow_mut().take().unwrap();
            self.inner.unlink(dir, &mutation.target)?;
            self.inner
                .place_unsynced(dir, &mutation.target, &mutation.replacement);
        }
        Ok(())
    }
    fn rename_entry_noreplace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()> {
        self.inner.rename_entry_noreplace(dir, from, to)
    }
    fn unlink(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.inner.unlink(dir, name)
    }
    fn sync_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> io::Result<()> {
        self.inner.sync_dir(dir)
    }
    fn mkdir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.inner.mkdir(parent, name)
    }
    fn remove_dir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
        self.inner.remove_dir(parent, name)
    }
    fn read(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
        limit: usize,
    ) -> io::Result<Vec<u8>> {
        self.inner.read(dir, name, limit)
    }
    fn list(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> io::Result<Vec<KagemushaWalletListedEntryV1>> {
        self.inner.list(dir)
    }
    fn available_bytes(&self) -> io::Result<u64> {
        self.inner.available_bytes()
    }
    fn try_lock(&self) -> io::Result<Self::Lock> {
        self.inner.try_lock()
    }
    fn staging_name(&self) -> io::Result<String> {
        self.inner.staging_name()
    }
}

#[test]
fn selected_enrollment_inventory_rejects_every_original_changed_during_adoption() {
    for (index, role) in ["phase", "client", "accepted", "slot"]
        .into_iter()
        .enumerate()
    {
        let (d, slot) = selected_fixture(194 + u8::try_from(index).unwrap());
        let root = KagemushaWalletCustodyDirV1::root();
        let name = |role: &str| {
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.ends_with(&format!("-{role}.norito")))
                .unwrap()
        };
        let target = name(role);
        let original = d.fs.visible_file(&root, &target).unwrap();
        // Phase was already adopted when Slot is adopted. The final four-original check
        // must still catch its replacement; the other originals change after their own rename.
        let trigger = if role == "phase" {
            name("slot")
        } else {
            target.clone()
        };
        let fs = ReplacingDuringAdoption {
            inner: d.fs.clone(),
            mutation: RefCell::new(Some(Mutation {
                trigger,
                target: target.clone(),
                replacement: b"changed during adoption".to_vec(),
            })),
        };
        let provider = KagemushaWalletProviderV1::<
            _,
            _,
            KagemushaWalletRecoveryCapsuleV1,
            KagemushaWalletCompletionRecordV1,
        >::open(fs, d.platform.clone(), SCHEME, test_options())
        .unwrap();
        assert_eq!(
            provider.enrollment_phase_for_slot(&slot),
            Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy
            )),
            "{role}: changed original cannot be returned or cached"
        );
        assert!(!provider.slot_phases.borrow().contains_key(&slot));
        assert_eq!(
            d.fs.visible_file(&root, &target).unwrap(),
            b"changed during adoption"
        );
        drop(provider);
        // Restoring the exact test fixture lets a new process adopt the original again.
        d.fs.unlink(&root, &target).unwrap();
        d.fs.place_unsynced(&root, &target, &original);
        let recovered = d.open();
        assert!(
            recovered
                .enrollment_phase_for_slot(&slot)
                .unwrap()
                .is_some()
        );
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 1);
            assert_eq!(s.delete_calls, 0);
            assert!(s.violations.is_empty());
        });
    }
}
