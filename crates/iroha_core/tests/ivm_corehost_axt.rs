//! First-release `CoreHost` AXT ABI and fail-closed envelope controls.
//!
//! Remote spends are signed anchored-spend records admitted by Core after
//! finalized-source verification. The retired raw-handle syscall is absent.

use std::sync::Arc;

use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId,
    nexus::{
        AxtPolicyBinding, AxtPolicyEntry, AxtPolicySnapshot, AxtPolicySnapshotValidationError,
        AxtRejectReason,
    },
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use ivm::{IVM, IVMHost, PointerType, VMError, axt, syscalls};

fn authority() -> AccountId {
    let key = "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
        .parse()
        .expect("canonical AXT authority public key");
    AccountId::new(key)
}

fn snapshot(dsid: DataSpaceId) -> AxtPolicySnapshot {
    let entries = vec![AxtPolicyBinding {
        dsid,
        policy: AxtPolicyEntry {
            manifest_root: [0x51; 32],
            target_lane: LaneId::new(0),
            active_handle_era: 1,
            next_handle_counter: 1,
            current_slot: 5,
        },
    }];
    AxtPolicySnapshot {
        version: AxtPolicySnapshot::compute_version(&entries),
        entries,
    }
}

fn store_norito<T: norito::NoritoSerialize>(vm: &mut IVM, ty: PointerType, value: &T) -> u64 {
    let payload = norito::to_bytes(value).expect("canonical AXT fixture encoding");
    store_tlv_payload(vm, ty, &payload)
}

fn store_tlv_payload(vm: &mut IVM, ty: PointerType, payload: &[u8]) -> u64 {
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(ty as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("bounded payload")
            .to_be_bytes(),
    );
    tlv.extend_from_slice(payload);
    tlv.extend_from_slice(Hash::new(payload).as_ref());
    vm.alloc_host_tlv(&tlv).expect("allocate public AXT TLV")
}

fn descriptor(dsid: DataSpaceId) -> axt::AxtDescriptor {
    axt::AxtDescriptor {
        dsids: vec![dsid],
        touches: vec![axt::AxtTouchSpec {
            dsid,
            read: vec!["orders".into()],
            write: vec!["ledger".into()],
        }],
    }
}

fn begin(host: &mut CoreHost, vm: &mut IVM, descriptor: &axt::AxtDescriptor) {
    let descriptor_ptr = store_norito(vm, PointerType::AxtDescriptor, descriptor);
    vm.set_register(10, descriptor_ptr);
    assert!(host.syscall(syscalls::SYSCALL_AXT_BEGIN, vm).unwrap() > 0);
}

#[test]
fn core_host_rejects_noncanonical_policy_snapshot() {
    let mut stale = snapshot(DataSpaceId::new(91));
    let expected = stale.version;
    stale.version = stale.version.wrapping_add(1);
    let result = CoreHost::new(authority()).with_axt_policy_snapshot(&stale);
    assert!(matches!(
        result,
        Err(AxtPolicySnapshotValidationError::VersionMismatch {
            expected: computed,
            actual: advertised,
        }) if computed == expected && advertised == stale.version
    ));
}

#[test]
fn core_host_rejects_invalid_descriptor_before_envelope_creation() {
    let mut vm = IVM::try_new(1_000_000).expect("fixture VM allocation");
    let mut host = CoreHost::new(authority());
    let dsid = DataSpaceId::new(7);
    let invalid = axt::AxtDescriptor {
        dsids: vec![dsid, dsid],
        touches: Vec::new(),
    };
    let descriptor_ptr = store_norito(&mut vm, PointerType::AxtDescriptor, &invalid);
    vm.set_register(10, descriptor_ptr);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_AXT_BEGIN, &mut vm),
        Err(VMError::PermissionDenied)
    ));
    let reject = host
        .take_axt_reject_for_tests()
        .expect("descriptor refusal");
    assert_eq!(reject.reason, AxtRejectReason::Descriptor);
    assert!(!reject.detail.is_empty());
    assert!(
        matches!(
            host.syscall(syscalls::SYSCALL_AXT_COMMIT, &mut vm),
            Err(VMError::PermissionDenied)
        ),
        "failed descriptor admission cannot create an envelope"
    );
}

struct DenyTouchPolicy(DataSpaceId);

impl axt::AxtPolicy for DenyTouchPolicy {
    fn allow_touch(
        &self,
        dsid: DataSpaceId,
        _manifest: &axt::TouchManifest,
    ) -> Result<(), VMError> {
        if dsid == self.0 {
            Err(VMError::PermissionDenied)
        } else {
            Ok(())
        }
    }
}

#[test]
fn core_host_rejects_touch_denied_by_current_policy() {
    let dsid = DataSpaceId::new(50);
    let policy = snapshot(dsid);
    let mut host = CoreHost::new(authority())
        .with_axt_policy(Arc::new(DenyTouchPolicy(dsid)))
        .with_axt_policy_snapshot(&policy)
        .expect("canonical AXT policy snapshot");
    let mut vm = IVM::try_new(1_000_000).expect("fixture VM allocation");
    begin(&mut host, &mut vm, &descriptor(dsid));
    let dsid_ptr = store_norito(&mut vm, PointerType::DataSpaceId, &dsid);
    let manifest = axt::TouchManifest {
        read: vec!["orders/0".into()],
        write: vec!["ledger/0".into()],
    };
    let manifest_ptr = store_norito(&mut vm, PointerType::NoritoBytes, &manifest);
    vm.set_register(10, dsid_ptr);
    vm.set_register(11, manifest_ptr);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_AXT_TOUCH, &mut vm),
        Err(VMError::PermissionDenied)
    ));
    let reject = host.take_axt_reject_for_tests().expect("touch refusal");
    assert_eq!(reject.reason, AxtRejectReason::PolicyDenied);
    assert_eq!(reject.dataspace, Some(dsid));
}

#[test]
fn core_host_requires_proof_before_completing_current_envelope() {
    let dsid = DataSpaceId::new(51);
    let policy = snapshot(dsid);
    let mut host = CoreHost::new(authority())
        .with_axt_policy_snapshot(&policy)
        .expect("canonical AXT policy snapshot");
    let mut vm = IVM::try_new(1_000_000).expect("fixture VM allocation");
    begin(&mut host, &mut vm, &descriptor(dsid));
    let dsid_ptr = store_norito(&mut vm, PointerType::DataSpaceId, &dsid);
    let manifest = axt::TouchManifest {
        read: vec!["orders/0".into()],
        write: vec!["ledger/0".into()],
    };
    let manifest_ptr = store_norito(&mut vm, PointerType::NoritoBytes, &manifest);
    vm.set_register(10, dsid_ptr);
    vm.set_register(11, manifest_ptr);
    assert!(host.syscall(syscalls::SYSCALL_AXT_TOUCH, &mut vm).unwrap() > 0);
    assert!(
        matches!(
            host.syscall(syscalls::SYSCALL_AXT_COMMIT, &mut vm),
            Err(VMError::PermissionDenied)
        ),
        "touches without an authenticated finalized-source proof cannot complete"
    );
}

#[test]
fn malformed_anchored_spend_stage_cannot_complete_an_envelope() {
    let dsid = DataSpaceId::new(52);
    let policy = snapshot(dsid);
    let mut host = CoreHost::new(authority())
        .with_axt_policy_snapshot(&policy)
        .expect("canonical AXT policy snapshot");
    let mut vm = IVM::try_new(1_000_000).expect("fixture VM allocation");
    let malformed = store_tlv_payload(&mut vm, PointerType::AxtAnchoredSpendV1, &[0xFF]);
    vm.set_register(10, malformed);
    assert!(
        matches!(
            host.syscall(syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND, &mut vm),
            Err(VMError::PermissionDenied)
        ),
        "staging requires an active AXT descriptor"
    );
    begin(&mut host, &mut vm, &descriptor(dsid));
    let dsid_ptr = store_norito(&mut vm, PointerType::DataSpaceId, &dsid);
    let manifest = axt::TouchManifest {
        read: vec!["orders/0".into()],
        write: vec!["ledger/0".into()],
    };
    let manifest_ptr = store_norito(&mut vm, PointerType::NoritoBytes, &manifest);
    vm.set_register(10, dsid_ptr);
    vm.set_register(11, manifest_ptr);
    assert!(host.syscall(syscalls::SYSCALL_AXT_TOUCH, &mut vm).unwrap() > 0);
    vm.set_register(10, malformed);
    assert!(
        matches!(
            host.syscall(syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND, &mut vm),
            Err(VMError::NoritoInvalid)
        ),
        "malformed signed-spend bytes cannot enter the staged envelope"
    );
    assert!(
        matches!(
            host.syscall(syscalls::SYSCALL_AXT_COMMIT, &mut vm),
            Err(VMError::PermissionDenied)
        ),
        "failed staging cannot supply the missing signed spend or source proof"
    );
}

#[test]
fn retired_raw_handle_syscall_is_unassigned_in_core_host() {
    let mut vm = IVM::try_new(1_000_000).expect("fixture VM allocation");
    let mut host = CoreHost::new(authority());
    assert!(
        matches!(host.syscall(0xB4, &mut vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xB4))
    );
}
