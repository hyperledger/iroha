//! Canonical Torii status response and capability snapshots.
//!
//! Named Norito schema identifiers are explicit protocol identities, independent
//! of the private module grouping used to maintain these DTOs.
mod common;
mod consensus;
mod failure;
mod gossip;
mod governance;
mod nexus;
mod taikai;

pub use common::{BuildStatus, CryptoStatus, DiagnosticTraceStatus, StackStatus, Status, Uptime};
pub use consensus::SumeragiConsensusStatus;
pub use failure::StatusFailureReason;
pub use gossip::{DaReceiptCursorStatus, TxGossipCaps, TxGossipSnapshot, TxGossipStatus};
pub use governance::{
    GovernanceManifestActivation, GovernanceManifestAdmissionCounters,
    GovernanceManifestQuorumCounters, GovernanceProposalCounters,
    GovernanceProtectedNamespaceCounters, GovernanceStatus,
};
pub use nexus::{
    NexusDataspaceCatalogStatus, NexusDataspaceTeuStatus, NexusLaneManifestValidatorBindingStatus,
    NexusLaneRuntimeUpgradeHookStatus, NexusLaneTeuBuckets, NexusLaneTeuDeferrals,
    NexusLaneTeuStatus, NexusRoutingMatcherStatus, NexusRoutingPolicyStatus,
    NexusRoutingRuleStatus, NexusStatus, SchedulerLayerWidthBuckets,
};
pub use taikai::{TaikaiAliasRotationStatus, TaikaiIngestErrorCounter, TaikaiIngestStatus};

#[cfg(test)]
mod manifest_tests;
