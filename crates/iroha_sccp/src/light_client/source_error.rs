//! Typed source-retry classification shared by callers of the native verifier.

use super::{BscLcError, EthereumLcError, SccpLcError, TonLcError};
use crate::{
    ethereum_native::EthereumLightClientError, ethereum_source::EthereumExecutionError,
    ton_native::TonNativeSourceError,
};

impl SccpLcError {
    /// Whether rebuilding from another source can repair invalid evidence.
    ///
    /// This is a retry hint, never evidence of an endpoint offence. Missing or unusable
    /// committed state, profile support, caller event selection and local resource refusal
    /// do not blame source data. Callers must preserve the original state/profile observation.
    #[must_use]
    pub fn is_invalid_source_data(&self) -> bool {
        match self {
            Self::UnsupportedNetwork(_)
            | Self::CheckpointsUnused(_)
            | Self::NotInstalled(_)
            | Self::UnexpectedLightClientState { .. }
            | Self::Frozen(_)
            | Self::InvalidParams(_)
            | Self::UnknownSigningSet { .. }
            | Self::StaleSigningSet { .. }
            | Self::ForkBeyondSupported { .. }
            | Self::SourceTimeInFuture { .. }
            | Self::ConflictsWithStoredData(_)
            | Self::UnknownCheckpoint { .. }
            | Self::EvidenceNotConflicting => false,
            Self::NetworkMismatch { .. }
            | Self::MalformedFrame(_)
            | Self::FrameTooLarge { .. }
            | Self::TooManyItems { .. }
            | Self::TooFewItems { .. } => true,
            Self::Ethereum(error) => ethereum(error),
            Self::Bsc(error) => match error {
                BscLcError::UnsupportedFork { .. }
                | BscLcError::MalformedStoredSet { .. }
                | BscLcError::ResourceLimit
                | BscLcError::SetDoesNotCover { .. }
                | BscLcError::UnlearnedTransition { .. } => false,
                BscLcError::Receipt(error) => ethereum(error),
                BscLcError::MalformedHeader
                | BscLcError::MalformedExtra
                | BscLcError::InvalidRoster
                | BscLcError::MalformedAttestation
                | BscLcError::InsufficientQuorum { .. }
                | BscLcError::InvalidAggregateSignature
                | BscLcError::AncestryBroken { .. }
                | BscLcError::FinalityMismatch
                | BscLcError::CheckpointMismatch { .. }
                | BscLcError::InvalidTransition { .. }
                | BscLcError::InvalidBootstrap
                | BscLcError::Overflow => true,
            },
            Self::Ton(error) => match error {
                TonLcError::UnsupportedFork { .. }
                | TonLcError::MalformedStoredSet { .. }
                | TonLcError::MalformedEvent => false,
                TonLcError::NotNextKeyBlock { .. }
                | TonLcError::BrokenShardWalk { .. }
                | TonLcError::InvalidBackLink => true,
                TonLcError::Native(error) => match error {
                    TonNativeSourceError::ResourceLimit
                    | TonNativeSourceError::UnsuccessfulTransaction
                    | TonNativeSourceError::InvalidOutboundMessage => false,
                    TonNativeSourceError::WrongNetwork
                    | TonNativeSourceError::InvalidBoc
                    | TonNativeSourceError::BrokenMasterchainLink
                    | TonNativeSourceError::InvalidValidatorSet
                    | TonNativeSourceError::InvalidValidatorTransition
                    | TonNativeSourceError::InvalidSignatures
                    | TonNativeSourceError::InvalidSimplexTranscript
                    | TonNativeSourceError::ShardNotFinalized
                    | TonNativeSourceError::InvalidTransaction => true,
                },
            },
        }
    }
}

fn ethereum(error: &EthereumLcError) -> bool {
    match error {
        EthereumLcError::MalformedStoredSet { .. }
        | EthereumLcError::HistoryContractUnavailable
        | EthereumLcError::HistoryWindow { .. }
        | EthereumLcError::FailedReceipt
        | EthereumLcError::LogIndexOutOfRange { .. }
        | EthereumLcError::Event(_)
        | EthereumLcError::VoidRangeInvalid
        | EthereumLcError::MissingExecutionPayload => false,
        EthereumLcError::Consensus(error) => consensus(error),
        EthereumLcError::Execution(error) => match error {
            EthereumExecutionError::ResourceLimit => false,
            EthereumExecutionError::LightClient(error) => consensus(error),
            EthereumExecutionError::MalformedWire(_)
            | EthereumExecutionError::EmptyTrieRoot(_)
            | EthereumExecutionError::MptProofBounds(_)
            | EthereumExecutionError::DuplicateMptNode(_)
            | EthereumExecutionError::MptNodeReferenceMismatch(_)
            | EthereumExecutionError::NonCanonicalMpt(_)
            | EthereumExecutionError::MptKeyMismatch(_)
            | EthereumExecutionError::UnusedMptNodes(_)
            | EthereumExecutionError::MalformedAccount
            | EthereumExecutionError::MalformedStorageValue
            | EthereumExecutionError::MalformedReceipt
            | EthereumExecutionError::MalformedHeader => true,
        },
        EthereumLcError::TimeOverflow
        | EthereumLcError::AncestryBroken { .. }
        | EthereumLcError::AncestryAnchorMismatch
        | EthereumLcError::BackfillAnchorMismatch { .. }
        | EthereumLcError::HistoryCodeHashMismatch
        | EthereumLcError::HistoryValueMismatch
        | EthereumLcError::ExecutionAfterSignature { .. } => true,
    }
}

fn consensus(error: &EthereumLightClientError) -> bool {
    match error {
        EthereumLightClientError::InvalidForkSchedule(_)
        | EthereumLightClientError::ZeroGenesisValidatorsRoot
        | EthereumLightClientError::UnsupportedSlot(_) => false,
        EthereumLightClientError::HeaderForkMismatch { .. }
        | EthereumLightClientError::ExtraDataTooLong(_)
        | EthereumLightClientError::InvalidExecutionBranch
        | EthereumLightClientError::CurrentCommitteeBranchForkMismatch
        | EthereumLightClientError::InvalidCurrentCommitteeBranch
        | EthereumLightClientError::FinalityBranchForkMismatch
        | EthereumLightClientError::InvalidFinalityBranch
        | EthereumLightClientError::NextCommitteeBranchForkMismatch
        | EthereumLightClientError::InvalidNextCommitteeBranch
        | EthereumLightClientError::NextCommitteePeriodMismatch
        | EthereumLightClientError::InvalidCommitteePublicKey(_)
        | EthereumLightClientError::InvalidCommitteeAggregatePublicKey
        | EthereumLightClientError::InvalidSlotOrder
        | EthereumLightClientError::InsufficientParticipation(_)
        | EthereumLightClientError::InvalidSyncCommitteeSignature => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::bridge::SccpNetworkV1;

    #[test]
    fn invalid_remote_proofs_retry_but_state_profile_selection_and_resources_do_not() {
        let positive = [
            SccpLcError::MalformedFrame("advance"),
            SccpLcError::Ethereum(EthereumLcError::Consensus(
                EthereumLightClientError::InvalidSyncCommitteeSignature,
            )),
            SccpLcError::Ethereum(EthereumLcError::Execution(
                EthereumExecutionError::MalformedHeader,
            )),
            SccpLcError::Bsc(BscLcError::InvalidAggregateSignature),
            SccpLcError::Bsc(BscLcError::Receipt(EthereumLcError::AncestryAnchorMismatch)),
            SccpLcError::Ton(TonLcError::Native(TonNativeSourceError::InvalidSignatures)),
        ];
        for error in positive {
            assert!(error.is_invalid_source_data(), "{error:?}");
        }
        let negative = [
            SccpLcError::Frozen(SccpNetworkV1::TonMainnet),
            SccpLcError::UnknownCheckpoint { source_height: 7 },
            SccpLcError::UnknownSigningSet { set_id: 7 },
            SccpLcError::StaleSigningSet {
                set_id: 7,
                stale_from_ms: 1,
            },
            SccpLcError::ForkBeyondSupported {
                epoch: 7,
                supported_until: 6,
            },
            SccpLcError::SourceTimeInFuture {
                source_ms: 2,
                taira_now_ms: 1,
            },
            SccpLcError::Ethereum(EthereumLcError::MalformedStoredSet { set_id: 7 }),
            SccpLcError::Ethereum(EthereumLcError::Execution(
                EthereumExecutionError::ResourceLimit,
            )),
            SccpLcError::Ethereum(EthereumLcError::Consensus(
                EthereumLightClientError::InvalidForkSchedule("local"),
            )),
            SccpLcError::Ethereum(EthereumLcError::FailedReceipt),
            SccpLcError::Bsc(BscLcError::ResourceLimit),
            SccpLcError::Bsc(BscLcError::MalformedStoredSet { set_id: 7 }),
            SccpLcError::Ton(TonLcError::MalformedStoredSet { set_id: 7 }),
            SccpLcError::Ton(TonLcError::Native(TonNativeSourceError::ResourceLimit)),
            SccpLcError::Ton(TonLcError::Native(
                TonNativeSourceError::UnsuccessfulTransaction,
            )),
        ];
        for error in negative {
            assert!(!error.is_invalid_source_data(), "{error:?}");
        }
    }
}
