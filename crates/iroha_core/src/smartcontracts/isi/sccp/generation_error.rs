//! Original local SCCP custody failures, kept outside deterministic instruction results.

use super::committee_owner::CommitteeOwnerError;

/// Exact local refusal retained by the enclosing execution attempt for retry or repair.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SccpGenerationLocalError {
    /// Original finite-pool refusal, including its original release observation.
    #[error(transparent)]
    Admission(iroha_allocation::AllocationRefusal),
    /// The allocator did not supply the already prepaid byte count.
    #[error("SCCP generation allocator refused {requested_bytes} prepaid bytes")]
    Allocator {
        /// Exact requested byte count; no invented alignment or layout is inferred.
        requested_bytes: usize,
    },
    /// Original decoder resource category and custody provenance.
    #[error("SCCP generation decoder resource refusal: {0}")]
    DecodeResource(norito::core::DecodeResourceError),
    /// Original ownership/cut consistency failed locally; this is not a peer verdict.
    #[error("SCCP generation ownership invariant: {0}")]
    Invariant(&'static str),
}

impl SccpGenerationLocalError {
    /// Preserve a local owner error without relabeling a completed structural rejection.
    pub fn from_owner(error: &CommitteeOwnerError) -> Option<Self> {
        Some(match error {
            CommitteeOwnerError::Invalid(_) => return None,
            CommitteeOwnerError::Admission(original) => Self::Admission(original.clone()),
            CommitteeOwnerError::Allocator { requested_bytes } => Self::Allocator {
                requested_bytes: *requested_bytes,
            },
            CommitteeOwnerError::DecodeResource(original) => match original.decode_resource_error()
            {
                Some(original) => Self::DecodeResource(original),
                None => Self::Invariant("decode refusal lost its resource category"),
            },
            CommitteeOwnerError::Invariant(reason) => Self::Invariant(reason),
        })
    }

    /// A wait exists only for the exact original releasable pool-capacity refusal.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::Admission(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
                Some(release)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_error_keeps_exact_original_refusal_and_allocator_count() {
        let pool = iroha_allocation::AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let local =
            SccpGenerationLocalError::from_owner(&CommitteeOwnerError::Admission(original.clone()))
                .unwrap();
        assert_eq!(local, SccpGenerationLocalError::Admission(original));
        assert!(local.release_wait().is_some());
        let allocator = SccpGenerationLocalError::from_owner(&CommitteeOwnerError::Allocator {
            requested_bytes: 123,
        })
        .unwrap();
        assert_eq!(
            allocator,
            SccpGenerationLocalError::Allocator {
                requested_bytes: 123
            }
        );
        assert!(allocator.release_wait().is_none());
        assert!(
            SccpGenerationLocalError::from_owner(&CommitteeOwnerError::Invalid(
                iroha_data_model::sccp::committee::SccpGenerationError::Field("keys")
            ))
            .is_none()
        );
        drop(occupied);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
