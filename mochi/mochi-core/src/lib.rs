//! Desktop observations and composition over the shared Kagami developer workspace.
//!
//! `iroha_deploy` owns all generated configuration and native process lifecycle;
//! Musubi and `iroha_contract_deploy` own compilation and durable deployment.
pub mod accounts;
pub mod compose;
pub mod dashboard;
pub mod developer;
pub mod state;
pub mod torii;
pub use accounts::{GeneratedAccount, asset_literal};
#[cfg(any(test, feature = "test"))]
pub use compose::development_signing_authorities;
pub use compose::{
    ComposeError, InstructionDraft, InstructionPermission, SigningAuthority,
    TransactionComposeOptions, TransactionPreview, compose_preview_with_options,
    drafts_from_json_str, drafts_to_pretty_json,
};
pub use dashboard::{
    DashboardAccountCard, DashboardAccountInput, DashboardAssetBalance, DashboardRecentBlock,
    DashboardSnapshot, fetch_dashboard_snapshot,
};
pub use state::{
    StateCursor, StateEntry, StatePage, StateQueryError, StateQueryKind, run_state_query,
};
pub use torii::{
    BlockDecodeStage, BlockStream, BlockStreamDecodeError, BlockStreamEvent, BlockSummary,
    EventCategory, EventDecodeStage, EventStream, EventStreamDecodeError, EventStreamEvent,
    EventSummary, LocalMcpProbeResult, ManagedBlockStream, ManagedEventStream,
    ManagedPeerGenesisFailure, ManagedPeerGenesisReadinessError, ManagedStatusStream,
    OperatorSigningContext, ReadinessOptions, ReadinessSmokeBuildError, ReadinessSmokeOutcome,
    ReadinessSmokePlan, SmokeCommitOptions, SmokeCommitSnapshot, StatusMetrics, StatusStreamEvent,
    ToriiClient, ToriiError, ToriiErrorInfo, ToriiErrorKind, ToriiMetricsSnapshot, ToriiResult,
    ToriiStatusSnapshot, decode_norito, wait_for_all_managed_peers_genesis,
};
