//! Typed contract-bound native lock effects. Authority comes only from the admitted frame.

use super::*;
use iroha_data_model::{
    escrow::control::{AssetLockControlV1, controlled_asset_lock_id},
    isi::{
        escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock, OpenAssetLock},
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
            ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
        },
    },
};
use std::num::NonZeroU64;

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    fn controlled_lock_key(
        vm: &IVM,
        pointer: u64,
        controller: &iroha_data_model::smart_contract::ContractAddress,
    ) -> Result<EscrowId, ivm::VMError> {
        let key = Self::decode_pointer_tlv(vm, pointer, PointerType::Blob)?;
        if key.payload.is_empty() || key.payload.len() > 4096 {
            return Err(ivm::VMError::DecodeError);
        }
        Ok(controlled_asset_lock_id(controller, key.payload))
    }

    fn controlled_asset_lock(
        &mut self,
        vm: &IVM,
        number: u32,
    ) -> Result<u64, ivm::VMError> {
        // Never accept a controller supplied by the guest, an account alias, or metadata.
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        let controller = context.contract_address.clone();
        if context.contract_subject != controller.subject_id() {
            return Err(ivm::VMError::PermissionDenied);
        }
        vm.ensure_public_register(10)?;
        let instruction = match number {
            ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN => {
                let base = vm.register(10);
                if !base.is_multiple_of(8) {
                    return Err(ivm::VMError::DecodeError);
                }
                vm.ensure_owned_heap_range(base, 64)?;
                vm.ensure_public_memory(base, 64)?;
                let mut words = [0_u64; 8];
                for (index, word) in words.iter_mut().enumerate() {
                    *word = vm.load_u64(base + index as u64 * 8)?;
                }
                let escrow_id = Self::controlled_lock_key(vm, words[0], &controller)?;
                let source: AccountId =
                    Self::decode_tlv_typed(vm, words[1], PointerType::AccountId)?;
                let destination: AccountId =
                    Self::decode_tlv_typed(vm, words[2], PointerType::AccountId)?;
                let asset_definition: AssetDefinitionId =
                    Self::decode_tlv_typed(vm, words[3], PointerType::AssetDefinitionId)?;
                let amount = Self::decode_quantity(vm, words[4])?;
                InstructionBox::from(OpenControlledAssetLockV1 {
                    source,
                    lock: OpenAssetLock::with_options(
                        escrow_id,
                        asset_definition,
                        destination,
                        amount,
                        Some(controller.subject_id()),
                        NonZeroU64::new(words[7]).map(NonZeroU64::get),
                        vec![],
                    ),
                    control: AssetLockControlV1 {
                        controller,
                        release_until_ms: NonZeroU64::new(words[5]),
                        cancel_not_before_ms: NonZeroU64::new(words[6]),
                    },
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN => {
                vm.ensure_public_register(11)?;
                vm.ensure_public_register(12)?;
                let escrow_id = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                        Self::decode_quantity(vm, vm.register(12))?,
                    ),
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL => {
                vm.ensure_public_register(11)?;
                let escrow_id = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                    ),
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE => {
                let escrow_id = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(escrow_id),
                })
            }
            _ => return Err(ivm::VMError::UnknownSyscall(number)),
        };
        // Full gas preflight precedes publication; the queued effect retains the
        // authenticated context for native executor permission/controller checks.
        self.queue_instruction_after_preflight(vm, instruction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{norito_blob, store_quantity, store_tlv};
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use ivm::host::IVMHost;

    fn host() -> CoreHost {
        let caller = ALICE_ID.clone();
        let controller = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &caller,
            92,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let mut host = CoreHost::new(caller);
        host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
            contract_subject: controller.subject_id(),
            contract_address: controller,
            contract_alias: None,
            entrypoint: "lock".to_owned(),
        }));
        host
    }

    #[test]
    fn opening_preserves_payer_beneficiary_and_independent_deadlines_in_queued_effect() {
        let mut host = host();
        let mut vm = IVM::new(100_000);
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrow", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let words = [
            store_tlv(&mut vm, PointerType::Blob, b"ns:1/lock"),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*ALICE_ID)),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*BOB_ID)),
            store_tlv(&mut vm, PointerType::AssetDefinitionId, &norito_blob(&asset)),
            store_quantity(&mut vm, &100_u32.into()),
            300,
            701,
            701,
        ];
        let table = vm.alloc_heap(64).unwrap();
        for (index, word) in words.iter().enumerate() {
            vm.store_u64(table + index as u64 * 8, *word).unwrap();
        }
        vm.set_register(10, table);
        host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm)
            .unwrap();
        assert_eq!(host.queued.len(), 1);
        let effect = &host.queued[0];
        let opening = effect.instruction().unwrap().as_any()
            .downcast_ref::<OpenControlledAssetLockV1>().unwrap();
        assert_eq!(opening.source, *ALICE_ID);
        assert_eq!(opening.lock.destination, *BOB_ID);
        assert_eq!(opening.lock.amount, 100_u32.into());
        assert_eq!(opening.control.release_until_ms.unwrap().get(), 300);
        assert_eq!(opening.control.cancel_not_before_ms.unwrap().get(), 701);
        assert_eq!(opening.lock.expires_at_ms, Some(701));
        assert_eq!(effect.authority, opening.control.controller.subject_id());
        assert_ne!(effect.authority, opening.source);
        assert_eq!(
            effect.contract_runtime_context.as_ref().unwrap().contract_address,
            opening.control.controller
        );
    }

    #[test]
    fn draw_cancel_expire_reuse_controller_scoped_identity_and_cas_amounts() {
        let mut host = host();
        let mut vm = IVM::new(100_000);
        let key = store_tlv(&mut vm, PointerType::Blob, b"ns:1/lock");
        let amount = store_quantity(&mut vm, &20_u32.into());
        let remaining = store_quantity(&mut vm, &100_u32.into());
        let controller = host.current_contract_runtime_context.as_ref().unwrap().contract_address.clone();
        let id = controlled_asset_lock_id(&controller, b"ns:1/lock");
        for (number, expected, second, third) in [
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN,
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(id, 20_u32, 100_u32),
                }),
                amount, remaining,
            ),
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL,
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(id, 100_u32),
                }),
                remaining, 0,
            ),
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE,
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(id),
                }),
                0, 0,
            ),
        ] {
            vm.set_register(10, key);
            vm.set_register(11, second);
            vm.set_register(12, third);
            host.syscall(number, &mut vm).unwrap();
            assert_eq!(host.queued.last().unwrap().instruction(), Some(&expected));
        }
    }

    #[test]
    fn lock_calls_reject_missing_frame_bad_key_and_unowned_table_without_effects() {
        let mut vm = IVM::new(100_000);
        let mut plain = CoreHost::new(ALICE_ID.clone());
        for number in [
            ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN,
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN,
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL,
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE,
        ] {
            assert!(plain.syscall(number, &mut vm).is_err());
            assert!(plain.queued.is_empty());
        }
        let mut host = host();
        for bytes in [vec![], vec![1; 4097]] {
            let key = store_tlv(&mut vm, PointerType::Blob, &bytes);
            vm.set_register(10, key);
            assert!(host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE, &mut vm).is_err());
            assert!(host.queued.is_empty());
        }
        // INPUT cannot impersonate a compiler-owned mutable argument table.
        let input = store_tlv(&mut vm, PointerType::Blob, &[0; 64]);
        vm.set_register(10, input);
        assert!(host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm).is_err());
        assert!(host.queued.is_empty());
    }
}
