//! Explicit contract-controlled settlement through the payout owner's approved FI.

use super::*;
use iroha_data_model::{
    escrow::control::AssetLockWaterfallSettlementV1,
    isi::{
        escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock},
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1, ExpireControlledAssetLockV1,
        },
    },
};

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn controlled_asset_lock_with_waterfall(
        &mut self,
        vm: &IVM,
        number: u32,
    ) -> Result<u64, ivm::VMError> {
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        let controller = &context.contract_address;
        if context.contract_subject != controller.subject_id() {
            return Err(ivm::VMError::PermissionDenied);
        }
        let (last_register, revision_register) = match number {
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL => (14, 13),
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL_WATERFALL => (13, 12),
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL => (12, 11),
            _ => return Err(ivm::VMError::UnknownSyscall(number)),
        };
        for register in 10..=last_register {
            vm.ensure_public_register(register)?;
        }
        let (escrow_id, _) = Self::controlled_lock_key(vm, vm.register(10), controller)?;
        // The compiler checks the full unsigned-u64 range for both int fields.
        // No caller-provided recipient, FI, amount split or authorization flag.
        let waterfall = Some(AssetLockWaterfallSettlementV1 {
            expected_policy_revision: vm.register(revision_register),
            expected_link_revision: vm.register(revision_register + 1),
        });
        let instruction = match number {
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL => {
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                        Self::decode_quantity(vm, vm.register(12))?,
                    ),
                    waterfall,
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL_WATERFALL => {
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                    ),
                    waterfall,
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL => {
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(escrow_id),
                    waterfall,
                })
            }
            _ => return Err(ivm::VMError::UnknownSyscall(number)),
        };
        // Native application rechecks authority, revision pins, expiry or CAS,
        // current excess and both source balances before its single decrement.
        // Plain cancellation/expiry remain separate and never require an FI link.
        self.queue_instruction_after_preflight(vm, instruction)
    }
}
