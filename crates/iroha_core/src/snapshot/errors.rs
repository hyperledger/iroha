//! Snapshot read and write error types.

use super::*;

/// Error variants for snapshot reading
#[derive(thiserror::Error, Debug, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum TryReadError {
    /// The snapshot was not found
    NotFound,
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Error (de)serializing state snapshot
    Serialization(#[source] norito::json::Error),
    /// Local State history allocation refused restore; this is not evidence of snapshot corruption: {0}
    StateAdmission(#[source] crate::state::StateAdmissionError),
    /// The original State reader or publication is locally unavailable during snapshot restore
    StateRead(#[source] crate::state::StateViewError),
    /// The local State VM image could not be constructed during snapshot restore
    StateVmInitialization(#[source] ivm::VMError),
    /// Local State execution resources were unavailable during snapshot restore
    StateExecutionDeferred(#[source] crate::execution_attempt::ExecutionDeferred),
    /// Local original-pool admission of restored lane signer/sample custody failed: {0}
    StateNativeLaneCustody(#[source] iroha_data_model::sumeragi_lanes::LaneStateAdmissionError),
    /// Local original-pool admission of the restored native schedule failed: {0}
    StateNativeSchedule(#[source] crate::sumeragi::schedule::ScheduleError),
    /// Local original-pool admission of restored beacon session custody failed: {0}
    StateBeaconSession(#[source] crate::beacon::GlobalThresholdBeaconSessionError),
    /// Local original-pool admission of the restored native participant failed: {0}
    StateNativeAmx(#[source] crate::sumeragi::amx::NativeAmxAdmissionError),
    /// Signed snapshot payload is not the single canonical first-release JSON encoding
    NonCanonicalSnapshotPayload,
    /// Snapshot exceeds a configured typed decode or transient resource boundary: {0}
    SnapshotResourceLimit(String),
    /// Local snapshot read-buffer allocation admission refused: {0}
    PayloadAllocation(#[source] iroha_allocation::AllocationRefusal),
    /// The allocator could not supply {requested_bytes} prepaid snapshot payload bytes
    PayloadAllocatorFailure {
        /// Exact requested byte allocation; no buffer was installed.
        requested_bytes: usize,
    },
    /// Snapshot artifact or directory binding changed at {0:?}
    SnapshotBindingChanged(PathBuf),
    /// Immutable snapshot generation at {path:?} is invalid: {reason}
    SnapshotGenerationInvalid {
        /// Invalid pointer, directory, or artifact path.
        path: PathBuf,
        /// Exact fail-closed integrity violation.
        reason: String,
    },
    /// Snapshot digest file missing at {0:?}
    ChecksumMissing(PathBuf),
    /// Snapshot digest mismatch (expected `{expected}`, got `{actual}`)
    ChecksumMismatch {
        /// Expected digest from the `.sha256` sidecar.
        expected: String,
        /// Actual digest computed from the snapshot payload.
        actual: String,
    },
    /// Snapshot signature file missing at {0:?}
    SignatureMissing(PathBuf),
    /// Snapshot signature malformed (`{0}`)
    SignatureMalformed(String),
    /// Snapshot signature invalid (`{0}`)
    SignatureInvalid(String),
    /// Snapshot Merkle metadata missing at {0:?}
    MerkleMissing(PathBuf),
    /// Snapshot Merkle metadata parse error
    MerkleMetadata(#[source] norito::json::Error),
    /// Snapshot Merkle metadata malformed (`{0}`)
    MerkleMetadataMalformed(String),
    /// Snapshot Merkle root mismatch (expected `{expected}`, got `{actual}`)
    MerkleMismatch {
        /// Root recorded in metadata.
        expected: String,
        /// Root derived from the snapshot payload.
        actual: String,
    },
    /// Snapshot Merkle chunk size mismatch (expected `{expected}`, got `{actual}`)
    MerkleChunkSizeMismatch {
        /// Chunk size requested by the caller.
        expected: NonZeroUsize,
        /// Chunk size recorded in metadata.
        actual: NonZeroUsize,
    },
    /// Snapshot length mismatch (expected `{expected}` bytes, got `{actual}` bytes)
    MerkleLengthMismatch {
        /// Length recorded in metadata.
        expected: u64,
        /// Length derived from the snapshot payload.
        actual: u64,
    },
    /// Snapshot Merkle proof invalid for chunk `{chunk}` (`{reason}`)
    MerkleProofInvalid {
        /// Index of the chunk that failed verification.
        chunk: usize,
        /// Reason the Merkle verification failed.
        reason: String,
    },
    /// Snapshot native chain instance mismatch (expected `{expected}`, got `{actual}`)
    ChainIdMismatch {
        /// Configured chain identity used by native consensus signatures.
        expected: ChainId,
        /// Claimed chain identity in the authenticated snapshot envelope.
        actual: ChainId,
    },
    /// A committed snapshot requires original signed-genesis and certified-history execution on fresh State
    NativeExecutionReplayRequired,
    /// Snapshot exact network id mismatch (expected `{expected}`, got `{actual}`)
    NetworkIdMismatch {
        /// Expected genesis-derived network id from configuration.
        expected: NetworkId,
        /// Exact network id recorded in the snapshot payload.
        actual: NetworkId,
    },
    /// Snapshot boundary identity is invalid (`{0}`)
    InvalidSnapshotBoundary(String),
    /// Original finite resources refused immutable native evidence restore: {0}
    StateEvidence(#[source] crate::sumeragi::evidence::record::EvidenceRecordRestoreError),
    /// Snapshot state is incompatible with runtime ZK configuration: {0}
    ZkConfigInstall(#[source] ZkConfigInstallError),
    /// Snapshot is in a non-consistent state. Snapshot has greater height (`{snapshot_height}`) than kura block store (`{kura_height}`)
    MismatchedHeight {
        /// The amount of block hashes stored by snapshot
        snapshot_height: usize,
        /// The amount of blocks stored by [`Kura`]
        kura_height: usize,
    },
    /// Snapshot is in a non-consistent state. Hash of the block at height `{height}` is different between snapshot (`{snapshot_block_hash}`) and kura (`{kura_block_hash}`)
    MismatchedHash {
        /// Height at which block hashes differs between snapshot and [`Kura`]
        height: usize,
        /// Hash of the block stored in snapshot
        snapshot_block_hash: HashOf<BlockHeader>,
        /// Hash of the block stored in kura
        kura_block_hash: HashOf<BlockHeader>,
    },
    /// Snapshot is in a non-consistent state. Kura is missing block {height}.
    MissingBlock {
        /// Height of the missing block in [`Kura`].
        height: usize,
    },
    /// Snapshot at height `{snapshot_height}` is missing the durable Space Directory manifest section
    MissingSpaceDirectoryManifestSection {
        /// Height recorded by the malformed snapshot.
        snapshot_height: usize,
    },
    /// Failed to reconcile snapshot block hashes with Kura
    Kura(#[source] KuraError),
}
impl From<crate::state::deserialize::StateRestoreError> for TryReadError {
    fn from(error: crate::state::deserialize::StateRestoreError) -> Self {
        match error {
            crate::state::deserialize::StateRestoreError::NativeExecutionReplayRequired => {
                Self::NativeExecutionReplayRequired
            }
            crate::state::deserialize::StateRestoreError::Serialization(error) => {
                Self::Serialization(error)
            }
            crate::state::deserialize::StateRestoreError::Admission(error) => {
                Self::StateAdmission(error)
            }
            crate::state::deserialize::StateRestoreError::StateRead(error) => {
                Self::StateRead(error)
            }
            crate::state::deserialize::StateRestoreError::VmInitialization(error) => {
                Self::StateVmInitialization(error)
            }
            crate::state::deserialize::StateRestoreError::ExecutionDeferred(error) => {
                Self::StateExecutionDeferred(error)
            }
            crate::state::deserialize::StateRestoreError::NativeLaneCustody(error) => {
                Self::StateNativeLaneCustody(error)
            }
            crate::state::deserialize::StateRestoreError::NativeSchedule(error) => {
                Self::StateNativeSchedule(error)
            }
            crate::state::deserialize::StateRestoreError::BeaconSession(error) => {
                Self::StateBeaconSession(error)
            }
            crate::state::deserialize::StateRestoreError::NativeAmx(error) => {
                Self::StateNativeAmx(error)
            }
            crate::state::deserialize::StateRestoreError::Evidence(error) => {
                Self::StateEvidence(error)
            }
        }
    }
}
/// Error variants for snapshot writing
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub(super) enum TryWriteError {
    /// Local snapshot read-buffer allocation admission refused: {0}
    PayloadAllocation(#[source] iroha_allocation::AllocationRefusal),
    /// The allocator could not supply {requested_bytes} prepaid snapshot payload bytes
    PayloadAllocatorFailure {
        /// Exact requested byte allocation; original generation evidence remains valid.
        requested_bytes: usize,
    },
    /// One stable snapshot observation could not be captured: {0}
    Capture(#[source] SnapshotCaptureError),
    /// Failed reading/writing {1:?} from disk
    IO(#[source] std::io::Error, PathBuf),
    /// Error (de)serializing World State View snapshot
    Serialization(norito::json::Error),
    /// Generated snapshot is not admissible through the restart reader: {0}
    RestartValidation(#[source] TryReadError),
    /// Error (de)serializing snapshot Merkle metadata
    MerkleSerialization(norito::json::Error),
    /// Error signing snapshot digest
    Signing(#[source] iroha_crypto::Error),
    /// Snapshot publication failed its stable-file or stable-directory integrity check: {0}
    PublicationIntegrity(String),
    /// Canonical snapshot payload is `{actual}` bytes; configured maximum is `{maximum}`
    PayloadTooLarge {
        /// Canonical payload length.
        actual: usize,
        /// Configured reader/writer limit.
        maximum: NonZeroUsize,
    },
    /// Failed to read the exact durable Kura boundary
    ExactKuraBoundary(#[source] KuraError),
    /// Refusing to write snapshot at state height `{state_height}` because durable Kura height is `{kura_height}`
    StateAheadOfKura {
        /// Height recorded by state/block-hash journal.
        state_height: usize,
        /// Height durably indexed by Kura.
        kura_height: usize,
    },
    /// Refusing to write snapshot at height `{height}` because latest state hash `{state_hash:?}` does not match Kura hash `{kura_hash:?}`
    LatestBlockHashMismatch {
        /// Height being snapshotted.
        height: usize,
        /// Latest block hash recorded by state.
        state_hash: Option<HashOf<BlockHeader>>,
        /// Block hash recorded by Kura at the same height.
        kura_hash: Option<HashOf<BlockHeader>>,
    },
    /// Refusing to publish snapshot at height `{height}` because durable commit evidence is incomplete or inconsistent: {reason}
    CommitEvidence {
        /// Height encoded by the serialized snapshot itself.
        height: u64,
        /// Exact fail-closed evidence violation.
        reason: String,
    },
    /// Snapshot at height `{height}` could not read commit evidence under its original local resources: {reason}
    CommitEvidenceResourceDeferred {
        /// Height encoded by the serialized snapshot itself.
        height: u64,
        /// Exact original local retry owner; this is not evidence of an invalid snapshot.
        #[source]
        reason: crate::execution_attempt::ExecutionDeferred,
    },
    /// Snapshot at height `{height}` is waiting for its in-flight durable commit tuple: {reason}
    CommitEvidenceDeferred {
        /// Height encoded by the serialized snapshot itself.
        height: u64,
        /// Missing publication step that a later snapshot interval must retry.
        reason: String,
    },
}

#[cfg(test)]
mod native_schedule_tests {
    use super::*;

    #[test]
    fn restore_schedule_refusal_keeps_original_typed_local_error() {
        use crate::{state::deserialize::StateRestoreError, sumeragi::schedule::ScheduleError};
        let budget = iroha_allocation::AllocationBudget::new(64);
        let occupied = budget.try_reserve_bytes(64).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let converted = TryReadError::from(StateRestoreError::NativeSchedule(
            ScheduleError::Admission(refusal),
        ));
        assert!(matches!(
            converted,
            TryReadError::StateNativeSchedule(ScheduleError::Admission(
                iroha_allocation::AllocationRefusal::Capacity { .. }
            ))
        ));
        assert_eq!(
            budget.reserved_bytes(),
            64,
            "conversion cannot replace or refund the source owner"
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(matches!(
            TryReadError::from(StateRestoreError::NativeSchedule(
                ScheduleError::Allocator {
                    requested_bytes: 128
                }
            )),
            TryReadError::StateNativeSchedule(ScheduleError::Allocator {
                requested_bytes: 128
            })
        ));
    }
}

#[cfg(test)]
mod native_lane_custody_tests;

#[cfg(test)]
mod native_lane_sample_tests;

#[cfg(test)]
mod beacon_session_tests;

#[cfg(test)]
mod evidence_restore_tests {
    use super::TryReadError;
    use crate::{
        state::{EvidencePreparationError, deserialize::StateRestoreError},
        sumeragi::evidence::record::EvidenceRecordRestoreError,
    };
    use iroha_allocation::AllocationBudget;

    #[test]
    fn original_evidence_restore_error_retains_typed_capacity_through_snapshot_boundary() {
        let budget = AllocationBudget::new(64);
        let original = budget.try_reserve_bytes(64).unwrap();
        let expected = budget
            .try_reserve(std::alloc::Layout::array::<u8>(8).unwrap())
            .unwrap_err();
        let error = TryReadError::from(StateRestoreError::Evidence(
            EvidencePreparationError::Admission(expected).into(),
        ));
        assert!(matches!(&error, TryReadError::StateEvidence(
            EvidenceRecordRestoreError::Preparation(EvidencePreparationError::Admission(actual))
        ) if matches!(actual, iroha_allocation::AllocationRefusal::Capacity {..})));
        let TryReadError::StateEvidence(EvidenceRecordRestoreError::Preparation(
            EvidencePreparationError::Admission(actual),
        )) = error
        else {
            panic!("local original funding is not snapshot syntax or protocol invalidity");
        };
        let observed = budget
            .try_reserve(std::alloc::Layout::array::<u8>(8).unwrap())
            .unwrap_err();
        assert_eq!(actual, observed);
        assert_eq!(budget.reserved_bytes(), 64);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
