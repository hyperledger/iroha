//! Owner-bound public synthetic costs for the qualified Metal AES families.

pub(super) mod exact;

pub(super) const BATCH_FAMILIES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CalibrationFailure {
    /// Public samples exceeded their bounded wall-time budget.
    Deadline,
    /// Synthetic AES sample allocation failed.
    Allocation,
    /// A qualified Metal operation could not complete this attempt.
    BackendUnavailable,
    /// Timing samples varied too much for a reliable path decision.
    Overloaded,
    /// The actual CPU fallback changed during a public sample.
    CpuChanged,
    /// A completed Metal result disagreed with the CPU reference.
    ParityMismatch,
}

/// A distinct, qualified pipeline family. The round count is public call
/// geometry; no signature, key, state byte, or witness value enters selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetalBatchWork {
    Encrypt,
    Decrypt,
    EncryptRounds(usize),
    DecryptRounds(usize),
}

impl MetalBatchWork {
    pub(super) const fn decrypt(self) -> bool {
        matches!(self, Self::Decrypt | Self::DecryptRounds(_))
    }

    pub(super) const fn fused(self) -> bool {
        matches!(self, Self::EncryptRounds(_) | Self::DecryptRounds(_))
    }

    pub(super) const fn rounds(self) -> usize {
        match self {
            Self::Encrypt | Self::Decrypt => 1,
            Self::EncryptRounds(rounds) | Self::DecryptRounds(rounds) => rounds,
        }
    }

    pub(super) const fn direction(self) -> crate::aes::cpu::Direction {
        if self.decrypt() {
            crate::aes::cpu::Direction::Decrypt
        } else {
            crate::aes::cpu::Direction::Encrypt
        }
    }

    pub(super) const fn family_index(self) -> usize {
        match self {
            Self::Encrypt => 0,
            Self::Decrypt => 1,
            Self::EncryptRounds(_) => 2,
            Self::DecryptRounds(_) => 3,
        }
    }

    pub(super) fn geometry_supported(self, items: usize) -> bool {
        exact::Geometry::new(self, items).is_some()
    }
}

/// Identity of the implementation used by the actual ordinary CPU fallback.
fn batch_cpu_identity(work: MetalBatchWork) -> crate::aes::cpu::Backend {
    crate::aes::cpu::backend(work.direction())
}

/// One CPU comparison identity captured before scanning physical GPU profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AesCpuBaseline {
    work: MetalBatchWork,
    cpu: crate::aes::cpu::Backend,
}

impl AesCpuBaseline {
    pub(super) fn capture(work: MetalBatchWork) -> Self {
        Self {
            work,
            cpu: batch_cpu_identity(work),
        }
    }

    pub(super) const fn work(self) -> MetalBatchWork {
        self.work
    }

    pub(super) fn is_current(self) -> bool {
        self.cpu == batch_cpu_identity(self.work)
    }
}

#[cfg(test)]
mod aes_tests;
