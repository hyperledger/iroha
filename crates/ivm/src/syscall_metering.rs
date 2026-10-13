//! Syscall metering modes and staged-call accounting.
//!
//! Existing host calls retain their prepare/reserve/execute/refund lifecycle. Kotodama V1 numeric
//! calls instead debit deterministic phases immediately before the associated work. An unaffordable
//! phase leaves remaining gas intact; charges for earlier completed phases are never refunded.
use crate::VMError;
/// Fixed entry charge for a staged syscall lifecycle.
pub(crate) const STAGED_SYSCALL_ENTRY_GAS: u64 = crate::numeric_gas::NUMERIC_ENTRY_GAS;
/// Consensus-visible syscall metering lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallMetering {
    /// Side-effect-free preparation returns an upper bound, which the VM
    /// reserves and later reconciles against actual reported gas.
    Reserved,
    /// The handler debits each bounded work phase immediately before it begins.
    Staged,
}
/// Stable completion state for a staged syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallCompletion {
    /// The syscall produced its normal result.
    Success,
    /// A recoverable failure was returned through status registers.
    RecoverableFailure,
    /// The syscall trapped after zero or more completed phases.
    Trap,
}
/// Stable phase tags for staged deterministic work.
///
/// Operand-validation phases may repeat in register order. The tag identifies
/// the kind of work, not a requirement that tags occur monotonically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SyscallMeteringPhase {
    /// Fixed syscall entry work.
    Entry = 0,
    /// Read and validate one pointer/TLV header and capped length.
    PointerHeader = 1,
    /// Snapshot/read the declared frame portion of a canonical pointer envelope.
    PointerEnvelope = 2,
    /// Read and validate the fixed pointer payload digest.
    PayloadHash = 3,
    /// Decode the complete nested Norito frame.
    NoritoDecode = 4,
    /// Validate a canonical value representation and domain bounds.
    CanonicalValidation = 5,
    /// Perform one deterministic logical arithmetic phase.
    Arithmetic = 6,
    /// Canonicalize or reduce decimal scale.
    Normalization = 7,
    /// Size, debit, allocate, and serialize the output envelope.
    OutputSerialization = 8,
}
impl SyscallMeteringPhase {
    /// Number of stable staged-metering phase tags in ABI V1.
    pub const COUNT: usize = 9;
    /// Every ABI V1 phase in stable tag order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Entry,
        Self::PointerHeader,
        Self::PointerEnvelope,
        Self::PayloadHash,
        Self::NoritoDecode,
        Self::CanonicalValidation,
        Self::Arithmetic,
        Self::Normalization,
        Self::OutputSerialization,
    ];
    /// Return the stable numeric tag used in diagnostics and gas vectors.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
    /// Return the stable descriptor name bound by the gas-schedule hash.
    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::Entry => "Entry",
            Self::PointerHeader => "PointerHeader",
            Self::PointerEnvelope => "PointerEnvelope",
            Self::PayloadHash => "PayloadHash",
            Self::NoritoDecode => "NoritoDecode",
            Self::CanonicalValidation => "CanonicalValidation",
            Self::Arithmetic => "Arithmetic",
            Self::Normalization => "Normalization",
            Self::OutputSerialization => "OutputSerialization",
        }
    }
}
/// Accounting snapshot for the active or most recently completed staged call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedSyscallContext {
    syscall: u32,
    charged: u64,
    phase_charges: [u64; SyscallMeteringPhase::COUNT],
    completion: Option<SyscallCompletion>,
}
impl StagedSyscallContext {
    pub(crate) const fn new(syscall: u32) -> Self {
        Self {
            syscall,
            charged: 0,
            phase_charges: [0; SyscallMeteringPhase::COUNT],
            completion: None,
        }
    }
    /// Syscall number associated with this context.
    #[must_use]
    pub const fn syscall(&self) -> u32 {
        self.syscall
    }
    /// Gas charged by all completed stages.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charged
    }
    /// Gas charged for one stable phase tag, including repeated occurrences.
    #[must_use]
    pub const fn phase_charge(&self, phase: SyscallMeteringPhase) -> u64 {
        self.phase_charges[phase as usize]
    }
    /// Completion state, or `None` while the call remains active.
    #[must_use]
    pub const fn completion(&self) -> Option<SyscallCompletion> {
        self.completion
    }
    pub(crate) fn record_charge(
        &mut self,
        phase: SyscallMeteringPhase,
        gas: u64,
    ) -> Result<(), VMError> {
        if self.completion.is_some() {
            return Err(VMError::SyscallMeteringModeMismatch {
                syscall: self.syscall,
            });
        }
        let phase_index = phase as usize;
        let phase_total = self.phase_charges[phase_index]
            .checked_add(gas)
            .ok_or(VMError::GasCostOverflow)?;
        let total = self
            .charged
            .checked_add(gas)
            .ok_or(VMError::GasCostOverflow)?;
        self.phase_charges[phase_index] = phase_total;
        self.charged = total;
        Ok(())
    }
    pub(crate) fn finish(&mut self, completion: SyscallCompletion) {
        self.completion = Some(completion);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn phase_tags_are_contiguous_and_stable() {
        assert_eq!(SyscallMeteringPhase::ALL.len(), SyscallMeteringPhase::COUNT);
        for (expected, phase) in SyscallMeteringPhase::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(phase.tag()), expected);
            assert!(!phase.descriptor_name().is_empty());
        }
    }
    #[test]
    fn context_accumulates_repeated_phase_charges() {
        let mut context = StagedSyscallContext::new(0x01_0105);
        context
            .record_charge(SyscallMeteringPhase::PointerHeader, 4)
            .expect("first charge");
        context
            .record_charge(SyscallMeteringPhase::PointerHeader, 7)
            .expect("second charge");
        context
            .record_charge(SyscallMeteringPhase::Arithmetic, 12)
            .expect("arithmetic charge");
        context.finish(SyscallCompletion::RecoverableFailure);
        assert_eq!(context.charged(), 23);
        assert_eq!(
            context.phase_charge(SyscallMeteringPhase::PointerHeader),
            11
        );
        assert_eq!(
            context.completion(),
            Some(SyscallCompletion::RecoverableFailure)
        );
    }
    #[test]
    fn context_rejects_gas_domain_overflow() {
        let mut context = StagedSyscallContext::new(0x01_0105);
        context
            .record_charge(SyscallMeteringPhase::Arithmetic, u64::MAX)
            .expect("maximum first charge");
        assert!(matches!(
            context.record_charge(SyscallMeteringPhase::Arithmetic, 1),
            Err(VMError::GasCostOverflow)
        ));
    }
}
