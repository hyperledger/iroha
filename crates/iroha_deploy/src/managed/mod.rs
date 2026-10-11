//! Persistent local developer networks shared by Kagami and Mochi.
//!
//! [`ManagedStore::up`] creates canonical artifacts through the shared localnet generator. This
//! module retains those files and identities across starts, owns the native processes, and
//! advertises readiness only after all four peers serve genesis and a signed smoke commits.
//! Secrets stay in the private store; public receipts contain only connection metadata.

mod bootstrap_failure;
mod build_registry;
mod bundle;
mod contracts;
mod program;
pub use program::{admit_native_build_input, admit_native_program};
mod deployment_report;
pub(crate) mod gateway_compliance;
mod generated_service_runtime;
mod generation;
pub(crate) mod native_operation;
mod provider_advert;
mod provider_capacity;
mod provider_credit;
mod provider_economics;
mod provider_funding;
mod provider_round;
mod remote;
mod remote_failure;
mod remote_status;
mod reserve_account;
mod reserve_policy;
mod reserve_top_up;
mod reserve_top_up_approval;
mod runtime;
mod service_authority;
mod service_bootstrap;
mod service_policies;
mod service_setup;
mod store;
pub(crate) mod stream_token_custody;
mod transport;
mod workspace;

use std::{path::PathBuf, sync::Arc, time::Duration};

// Observation may await an already-dispatched task through its original maximum budget.
// These bounds never extend task execution, signing authority or a retained transaction.
const WORKER_STARTUP_MAXIMUM: Duration = Duration::from_secs(600);
const OWNED_PEER_STOP_GRACE: Duration = Duration::from_secs(5);
const STOP_REPLY_ALLOWANCE: Duration = Duration::from_secs(5);
const STOP_OBSERVATION_MAXIMUM: Duration = WORKER_STARTUP_MAXIMUM
    .saturating_add(OWNED_PEER_STOP_GRACE)
    .saturating_add(STOP_REPLY_ALLOWANCE);

use norito::json::{JsonDeserialize, JsonSerialize};

pub use bootstrap_failure::ManagedBootstrapFailure;
pub use bundle::{KagamiBundleLayout, MOCHI_APPLICATION_ID, NativeBundleLayout, macos_info_plist};
pub use contracts::{
    ManagedContractCallOptions, ManagedContractCallReport, ManagedContractView,
    ManagedContractViewRequest,
};
pub use deployment_report::{
    ManagedDeploymentExecution, ManagedDeploymentReport, ManagedDeploymentTarget,
    ManagedParentObservation, ManagedParentReport,
};
pub use native_operation::ManagedTransactionFinality;
pub use provider_advert::{ManagedProviderAdvertisement, ManagedProviderAdvertisementReport};
pub use provider_capacity::{ManagedProviderCapacity, ManagedProviderCapacityProgress};
pub use provider_credit::{
    ManagedInitialProviderCredit, ManagedInitialProviderCreditIntent,
    ManagedInitialProviderCreditProgress,
};
pub use remote::ManagedAmxRegistrationOptions;
pub use remote_failure::ManagedAttachmentFailure;
pub use remote_status::{
    DataspaceRequest, ManagedAttachmentPhase, ManagedAttachmentStatus, ManagedConfirmedAnchor,
    ManagedDataspaceStatus,
};
pub use reserve_account::{ManagedReserveAccountProgress, ManagedReserveAccountRegistration};
pub use reserve_policy::{
    ManagedInitialReservePolicy, ManagedReservePolicyActivation, ManagedReservePolicyProgress,
};
pub use reserve_top_up::{
    ManagedHistoricalReserveTopUp, ManagedReserveTopUpIntent, ManagedReserveTopUpProgress,
    ManagedReserveTopUpRequest,
};
pub use reserve_top_up_approval::{
    ManagedHistoricalReserveTopUpApproval, ManagedReserveTopUpApproval,
    ManagedReserveTopUpApprovalIntent, ManagedReserveTopUpApprovalProgress,
};
pub use runtime::run_worker;
pub use service_setup::{
    ManagedInitialGatewaySetup, ManagedInitialProviderIngestAuthority,
    ManagedInitialReputationPolicy, ManagedInitialServiceSetupProgress,
};
pub use store::{LocalnetPorts, ManagedStore};
pub use stream_token_custody::{
    ManagedCustodyEnrollmentInterval, ManagedCustodyProgress, ManagedStreamTokenCustody,
    RetainedCustodyEnrollment,
};
pub use workspace::{InstalledRuntime, default_state_root, workspace_state_root};

/// Result of one managed developer-network operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A managed operation that could not safely complete.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A closed retained-bootstrap condition that cannot renew an original signed intent.
    #[error(transparent)]
    Bootstrap(#[from] ManagedBootstrapFailure),
    /// This workspace has never selected a managed environment.
    #[error("no developer environment is selected in this workspace")]
    NoSelection,
    /// A filesystem, socket or process operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Stored metadata or caller input is invalid.
    #[error("{0}")]
    Invalid(String),
    /// Native call work failed or remains unresolved; its original journal and cause survive.
    #[error("{source}\nCall journal: {journal:?}")]
    ContractCall {
        /// Exact original owner-private recovery location.
        journal: PathBuf,
        /// Unmodified native call or journal error, including exact pending hashes.
        #[source]
        source: color_eyre::eyre::Report,
    },
    /// Another operation or process still owns this network.
    #[error("managed network `{0}` is already owned; inspect its status before retrying")]
    Busy(String),
    /// Startup could not prove readiness within the requested budget.
    #[error("localnet startup did not complete within {0:?}")]
    Timeout(Duration),
    /// The original native I/O budget elapsed; retained custody remains unresolved.
    #[error("native operation I/O deadline elapsed; retain original journals")]
    NativeDeadline,
    /// A local worker failure occurred, and owned cleanup or status publication also failed.
    #[error("{failure}{}", worker_failure_followup(cleanup, publication))]
    WorkerFailure {
        /// Original local startup or service cause, including native I/O diagnostics.
        /// Retained status uses a separate closed classification, never this cause's text.
        failure: String,
        /// Exact error from stopping owned validators or joining owned background tasks.
        cleanup: Option<Box<Error>>,
        /// Exact error from retaining the failed status after cleanup was attempted.
        publication: Option<Box<Error>>,
    },
    /// Parent attachment or its independent registry work exhausted the caller's finite budget.
    #[error(
        "parent operation deadline expired; inspect `kagami dataspace status` and retry the same retained context"
    )]
    ParentDeadline,
    /// Foreground attachment time elapsed; the last safe stage and classification are retained.
    #[error(
        "parent attachment deadline expired during {stage}: {failure}; inspect `kagami dataspace status` and retry the same retained context"
    )]
    ParentProgressDeadline {
        /// Last observed operation stage, distinct from local validator readiness.
        stage: ManagedAttachmentPhase,
        /// Closed classification containing no request, response or custody text.
        failure: ManagedAttachmentFailure,
    },
}

fn worker_failure_followup(
    cleanup: &Option<Box<Error>>,
    publication: &Option<Box<Error>>,
) -> String {
    let mut details = String::new();
    if let Some(error) = cleanup {
        details.push_str(&format!("\nOwned worker cleanup failed: {error}"));
    }
    if let Some(error) = publication {
        details.push_str(&format!(
            "\nFailed to retain startup failure status: {error}"
        ));
    }
    details
}

/// Selected, secret-free client context backed by owner-private generated configuration.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ManagedContext {
    /// Store-local name, such as `local`.
    pub name: String,
    /// Canonical chain label.
    pub chain_id: String,
    /// Canonical checked network identity derived from signed genesis.
    pub network_id: String,
    /// Canonical public account identity of the developer signer.
    pub account_id: String,
    /// Physical dataspace selected for default contract deployment.
    pub dataspace_id: u64,
    /// Leased dataspace namespace used for deployment aliases.
    pub dataspace_alias: String,
    /// Preferred loopback Torii URL.
    pub torii_url: String,
    /// Owner-private generated client configuration; never supplied by the user.
    pub client_config: PathBuf,
}

/// One canonical node configuration and its public connection metadata.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ManagedPeer {
    /// Absolute canonical generated node configuration.
    pub config_path: PathBuf,
    /// Loopback Torii URL served by this validator.
    pub torii_url: String,
    /// Plain filename for retained node logs, such as `peer0.log`.
    pub log_name: String,
}

/// The output of canonical genesis/configuration preparation.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PreparedLocalnet {
    /// Exact closed genesis service-authority profile; never inferred from optional files.
    pub service_profile: crate::localnet::LocalnetServiceProfile,
    /// Client identity and connection information generated with this genesis.
    pub context: ManagedContext,
    /// Exactly four independent validators, in stable order.
    pub peers: Vec<ManagedPeer>,
}

/// A localnet startup request. Omitted CLI settings should use [`Self::new`].
#[derive(Debug, Clone)]
pub struct LocalnetRequest {
    /// Explicit internal preparation profile; an existing generation must match exactly.
    pub service_profile: crate::localnet::LocalnetServiceProfile,
    /// Store-local network name.
    pub name: String,
    /// Installed Kagami executable, used to start the native background worker.
    pub launcher: PathBuf,
    /// Matching installed daemon executable; no source builds or PATH fallback occur here.
    pub daemon: PathBuf,
    /// Total readiness budget, including generation.
    pub startup_timeout: Duration,
    // Discovery retains its original files through startup; callers cannot substitute paths
    // beneath that selection. Manual constructors admit their explicit paths on startup.
    installed_programs: Option<Arc<program::RuntimePrograms>>,
}

impl LocalnetRequest {
    /// Construct a global localnet with original service-authority prerequisites and a thirty-second budget.
    ///
    /// The generated authorities do not enable services or establish provider admission.
    #[must_use]
    pub fn new(launcher: PathBuf, daemon: PathBuf) -> Self {
        Self {
            service_profile: crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            name: "local".into(),
            launcher,
            daemon,
            startup_timeout: Duration::from_secs(30),
            installed_programs: None,
        }
    }

    /// Construct a private-root request without global service-authority prerequisites.
    ///
    /// The exact parent and private scope are supplied separately to `up_private_root`.
    #[must_use]
    pub fn private_root(launcher: PathBuf, daemon: PathBuf) -> Self {
        Self {
            service_profile: crate::localnet::LocalnetServiceProfile::Standard,
            ..Self::new(launcher, daemon)
        }
    }

    fn admit_programs(&self) -> Result<Arc<program::RuntimePrograms>> {
        match &self.installed_programs {
            Some(programs) => {
                programs.require_paths(&self.launcher, &self.daemon)?;
                Ok(Arc::clone(programs))
            }
            None => Ok(Arc::new(program::RuntimePrograms::capture(
                &self.launcher,
                &self.daemon,
            )?)),
        }
    }
}

/// Current lifecycle observation, never inferred solely from a saved PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPhase {
    /// No worker owns this prepared generation.
    Stopped,
    /// The worker is proving node and transaction readiness.
    Starting,
    /// Readiness was proved and every supervised validator is still alive.
    Ready,
    /// Startup or an active validator failed.
    Failed,
}

impl ManagedPhase {
    /// Stable phase spelling used in CLI JSON and retained status metadata.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }
}

impl JsonSerialize for ManagedPhase {
    fn json_serialize(&self, output: &mut String) {
        self.as_str().json_serialize(output);
    }
}

impl JsonDeserialize for ManagedPhase {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> std::result::Result<Self, norito::json::Error> {
        match parser.parse_string()?.as_str() {
            "stopped" => Ok(Self::Stopped),
            "starting" => Ok(Self::Starting),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            _ => Err(norito::json::Error::Message(
                "invalid managed lifecycle phase".into(),
            )),
        }
    }
}

/// Secret-free status returned to CLI and desktop clients.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ManagedStatus {
    /// Retained client context.
    pub context: ManagedContext,
    /// Current worker observation.
    pub phase: ManagedPhase,
    /// Number of still-running owned validator processes.
    /// When `failure` reports unconfirmed cleanup, this is an upper bound from retained handles.
    pub running_peers: usize,
    /// Public reason for a failed operation, without child output or credentials.
    pub failure: Option<String>,
}

#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct BinaryPin {
    // Persistent generations bind path and contents across separately admitted process starts.
    // Native object identity belongs only to live discovery/startup owners, not this record.
    path: PathBuf,
    blake3: String,
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedLocalnet {
    root_kind: RootKind,
    prepared: PreparedLocalnet,
    launcher: BinaryPin,
    daemon: BinaryPin,
    startup_timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum RootKind {
    Global,
    Private {
        spec: crate::localnet::PrivateRootSpec,
    },
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct WorkerRecord {
    token: String,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ControlRequest {
    token: String,
    action: String,
}

const MANIFEST: &str = "localnet.json";
const WORKER: &str = "worker.json";
const STATUS: &str = "status.json";
const MAX_METADATA: usize = 1024 * 1024;
const POLL: Duration = Duration::from_millis(50);

fn encode(value: &impl JsonSerialize) -> Result<Vec<u8>> {
    norito::json::to_vec(value).map_err(|_| Error::Invalid("cannot encode managed metadata".into()))
}

fn decode<T: JsonDeserialize>(bytes: &[u8]) -> Result<T> {
    norito::json::from_slice(bytes)
        .map_err(|_| Error::Invalid("managed control or context metadata is invalid".into()))
}

fn validate_name(name: &str) -> Result<()> {
    // A canonical private DNS label can occupy all 63 bytes. Keep the exact alias usable as
    // the default context name; IPC bounds the complete path independently of this component.
    if name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Invalid("managed names must contain 1..63 ASCII letters, digits, `-` or `_`, starting with a letter or digit".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn native_test_guard() -> std::sync::MutexGuard<'static, ()> {
    // Resource tests intentionally share the preferred loopback ports. Serializing them also
    // keeps parallel private-directory ancestor custody within macOS's default 256-FD budget.
    static NATIVE_RESOURCES: std::sync::Mutex<()> = std::sync::Mutex::new(());
    NATIVE_RESOURCES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
