//! Allocation-free semantic trap snapshots borrowing their original metadata owner.
//!
//! The returned VMError remains the only error owner. Rendering at Core/CLI/HTTP
//! boundaries is separate output work and is not funded by this snapshot.

use super::IVM;
use crate::error::{
    VMError, VmBudgetSnapshot, VmExecutionContext, VmExecutionDiagnostic, VmSourceLocation,
    VmTrapKind,
};
use iroha_data_model::executor::fault::{
    IvmFaultPositionV1, IvmFaultSiteV1, IvmFaultV1, IvmInvocationSelectorV1,
};

/// Inline trap-time values. The source index resolves only against this VM's debug owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TrapSnapshot {
    pub(super) fault: Option<IvmFaultV1>,
    pub(super) propagated: bool,
    pub(super) trap_kind: VmTrapKind,
    pub(super) pc: u64,
    pub(super) source_index: Option<usize>,
    pub(super) budget: VmBudgetSnapshot,
    pub(super) entrypoint_pc: Option<u64>,
    pub(super) opcode: Option<u16>,
    pub(super) syscall: Option<u32>,
    pub(super) predecoded_loaded: bool,
    pub(super) predecoded_hit: Option<bool>,
}

impl IVM {
    /// Borrow the last semantic trap's context without formatting or allocating.
    ///
    /// Success, local refusal and a new run/load/reset clear this context. Supply
    /// the original returned error separately when rendering a semantic failure.
    pub fn last_diagnostic(&self) -> Option<VmExecutionDiagnostic<'_>> {
        let trap = self.last_diagnostic?;
        let source = trap.source_index.and_then(|index| {
            let entry = self.contract_debug.as_ref()?.source_map.get(index)?;
            Some(VmSourceLocation {
                function: Some(entry.function_name.as_str()),
                path: entry.source.source_path.as_deref(),
                line: Some(entry.source.line),
                column: Some(entry.source.column),
            })
        });
        Some(VmExecutionDiagnostic {
            fault: trap.fault,
            trap_kind: trap.trap_kind,
            pc: trap.pc,
            source,
            budget: trap.budget,
            context: VmExecutionContext {
                entrypoint_pc: trap.entrypoint_pc,
                current_function: source.and_then(|source| source.function),
                opcode: trap.opcode,
                syscall: trap.syscall,
                predecoded_loaded: trap.predecoded_loaded,
                predecoded_hit: trap.predecoded_hit,
            },
        })
    }

    pub(super) fn capture_trap(&mut self, error: &VMError) {
        self.capture_trap_at(
            error,
            IvmFaultPositionV1::Execute {
                pc_offset: self.pc.saturating_sub(self.program_prefix_len),
            },
        );
    }

    pub(super) fn capture_trap_at(&mut self, error: &VMError, position: IvmFaultPositionV1) {
        let inherited = self
            .last_diagnostic
            .filter(|snapshot| snapshot.propagated)
            .and_then(|snapshot| snapshot.fault);
        self.last_diagnostic = None;
        if error.execution_deferral().is_some() {
            return;
        }
        // Read diagnostics outside the guest register transcript.
        let _mask = crate::zk::RegLoggerGuard::mask();
        let fault = inherited.or_else(|| self.execution_fault(error, position));
        let relative_pc = match fault {
            Some(fault) if fault.site.code_hash.as_ref() != &self.code_hash => None,
            Some(IvmFaultV1 {
                site:
                    IvmFaultSiteV1 {
                        position: IvmFaultPositionV1::Execute { pc_offset },
                        ..
                    },
                ..
            }) => Some(pc_offset),
            Some(_) => None,
            None => self.pc.checked_sub(self.program_prefix_len),
        };
        let source_index = relative_pc.and_then(|pc| {
            self.contract_debug
                .as_ref()?
                .source_map
                .iter()
                .position(|entry| pc >= entry.pc_start && pc < entry.pc_end)
        });
        let stack_top = self.memory.stack_top();
        let stack_bytes_used = stack_top.saturating_sub(self.registers.get(31));
        let predecoded_loaded = self.prepared.is_some();
        self.last_diagnostic = Some(TrapSnapshot {
            fault,
            propagated: false,
            trap_kind: Self::classify_trap(error),
            pc: self.pc,
            source_index,
            budget: VmBudgetSnapshot {
                gas_limit: self.gas_limit,
                gas_remaining: self.gas_remaining,
                gas_used: self.gas_limit.saturating_sub(self.gas_remaining),
                cycles: self.cycles,
                max_cycles: self.max_cycles,
                stack_limit_bytes: self.memory.stack_limit(),
                stack_bytes_used,
            },
            entrypoint_pc: self.entrypoint_pc,
            opcode: match error.as_unmetered() {
                VMError::InvalidOpcode(op) => Some(*op),
                _ => None,
            },
            syscall: match error.as_unmetered() {
                VMError::UnknownSyscall(syscall) | VMError::NotImplemented { syscall } => {
                    Some(*syscall)
                }
                _ => None,
            },
            predecoded_loaded,
            predecoded_hit: Some(predecoded_loaded && self.prepared_contains_pc(self.pc)),
        });
    }

    /// Record a deterministic failure at a trusted host boundary outside the run loop.
    ///
    /// The selected entrypoint must already be installed. Local execution refusals
    /// clear the snapshot and never acquire a consensus fault value.
    pub fn record_boundary_fault(&mut self, error: &VMError, position: IvmFaultPositionV1) {
        self.capture_trap_at(error, position);
    }

    /// Return the bounded deterministic fault without copying diagnostic strings.
    ///
    /// The exact child origin already captured by a nested call wins over this
    /// VM's call-site coordinates. Application rejections and local refusals do
    /// not have a fault value. `position` applies only without a trap snapshot.
    pub fn execution_fault(
        &self,
        error: &VMError,
        position: IvmFaultPositionV1,
    ) -> Option<IvmFaultV1> {
        let kind = error.fault_kind()?;
        if let Some(fault) = self.last_diagnostic.and_then(|snapshot| snapshot.fault) {
            return Some(fault);
        }
        let selector = match self.contract_interface() {
            None => IvmInvocationSelectorV1::Generic,
            Some(interface) => {
                let pc = self.entrypoint_pc?.checked_sub(self.program_prefix_len)?;
                let index = interface
                    .entrypoints
                    .iter()
                    .position(|entry| entry.entry_pc == pc)?;
                IvmInvocationSelectorV1::Entrypoint(u32::try_from(index).ok()?)
            }
        };
        Some(IvmFaultV1 {
            kind,
            site: IvmFaultSiteV1 {
                code_hash: iroha_crypto::Hash::prehashed(self.code_hash),
                selector,
                position,
            },
        })
    }

    /// Retain a child's authenticated origin before its VM is released.
    ///
    /// Only the fixed fault value crosses this boundary. Child source indices,
    /// source text and allocation owners never become parent diagnostic owners.
    pub fn inherit_execution_fault(
        &mut self,
        child: &IVM,
        error: &VMError,
        position: IvmFaultPositionV1,
    ) {
        let Some(fault) = child.execution_fault(error, position) else {
            return;
        };
        self.capture_trap(error);
        if let Some(snapshot) = self.last_diagnostic.as_mut() {
            snapshot.fault = Some(fault);
            snapshot.propagated = true;
            snapshot.source_index = None;
        }
    }

    pub(crate) fn classify_trap(err: &VMError) -> VmTrapKind {
        match err.as_unmetered() {
            VMError::OutOfGas | VMError::SyscallOutOfGas { .. } => VmTrapKind::OutOfGas,
            VMError::OutOfMemory => VmTrapKind::OutOfMemory,
            VMError::MemoryAccessViolation { .. }
            | VMError::MisalignedAccess { .. }
            | VMError::MemoryOutOfBounds => VmTrapKind::MemoryFault,
            VMError::DecodeError => VmTrapKind::DecodeError,
            VMError::InvalidOpcode(_) => VmTrapKind::InvalidOpcode,
            VMError::UnknownSyscall(_) => VmTrapKind::UnknownSyscall,
            VMError::HostUnavailable | VMError::NotImplemented { .. } => VmTrapKind::NotImplemented,
            VMError::SyscallGasQuoteExceeded { .. } => VmTrapKind::SyscallGasQuoteExceeded,
            VMError::SyscallMeteringModeMismatch { .. } => VmTrapKind::SyscallMeteringModeMismatch,
            VMError::GasCostOverflow => VmTrapKind::GasCostOverflow,
            VMError::NumericFault(_) => VmTrapKind::NumericFault,
            VMError::PointerAbiFault(_) => VmTrapKind::PointerAbiFault,
            VMError::AssertionFailed => VmTrapKind::AssertionFailed,
            VMError::ContractAbort { .. } => VmTrapKind::ContractAbort,
            VMError::ExceededMaxCycles => VmTrapKind::ExceededMaxCycles,
            VMError::InvalidMetadata => VmTrapKind::InvalidMetadata,
            VMError::UnsupportedProgramVersion { .. } => VmTrapKind::UnsupportedProgramVersion,
            VMError::UnsupportedProgramFeatureBits { .. } => {
                VmTrapKind::UnsupportedProgramFeatureBits
            }
            VMError::UnsupportedProgramAbiVersion { .. } => {
                VmTrapKind::UnsupportedProgramAbiVersion
            }
            VMError::ProgramVectorLengthTooLarge { .. } => VmTrapKind::ProgramVectorLengthTooLarge,
            VMError::ArtifactAbiHashMismatch { .. } => VmTrapKind::ArtifactAbiHashMismatch,
            VMError::GenericSyscallNotAllowed { .. } => VmTrapKind::GenericSyscallNotAllowed,
            VMError::InvalidVectorLength { .. } => VmTrapKind::InvalidVectorLength,
            VMError::MissingHalt => VmTrapKind::MissingHalt,
            VMError::VectorExtensionDisabled
            | VMError::ZkExtensionDisabled
            | VMError::NullifierAlreadyUsed
            | VMError::PermissionDenied
            | VMError::ReentrantCall
            | VMError::CallDepthExceeded => VmTrapKind::PermissionDenied,
            VMError::PrivacyViolation => VmTrapKind::PrivacyViolation,
            VMError::RegisterOutOfBounds => VmTrapKind::RegisterOutOfBounds,
            VMError::NoritoInvalid => VmTrapKind::NoritoInvalid,
            VMError::AbiTypeNotAllowed { .. } => VmTrapKind::AbiTypeNotAllowed,
            VMError::HostOutputBudgetExceeded { .. } => VmTrapKind::HostOutputBudgetExceeded,
            VMError::AmxBudgetExceeded { .. } => VmTrapKind::AmxBudgetExceeded,
            VMError::ExecutionDeferred(_) | VMError::AllocationDeferred(_) => VmTrapKind::Other,
            VMError::Metered { .. } => unreachable!("as_unmetered peels metered wrappers"),
        }
    }
}
#[cfg(test)]
mod tests;
