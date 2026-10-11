//! "Actual" layer of Iroha configuration parameters. It contains strongly-typed validated
//! structures in a way that is efficient for Iroha internally.
#![allow(
    clippy::doc_markdown,
    clippy::doc_link_with_quotes,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::cast_lossless,
    clippy::manual_abs_diff,
    clippy::cast_possible_truncation,
    clippy::struct_field_names,
    clippy::missing_fields_in_debug,
    clippy::struct_excessive_bools,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]
use error_stack::{Report, ResultExt};
use iroha_config_base::{WithOrigin, read::ConfigReader, toml::TomlSource, util::Bytes};
use iroha_crypto::{
    Algorithm, Hash, HashOf, KeyPair, PrivateKey, PublicKey, RamLfeSecret,
    soranet::handshake::{
        DEFAULT_CLIENT_CAPABILITIES, DEFAULT_DESCRIPTOR_COMMIT, DEFAULT_RELAY_CAPABILITIES,
    },
    streaming::StreamingKeyMaterial,
};
use iroha_data_model::{
    account::AccountId,
    asset::prelude::AssetDefinitionId,
    block::{BlockHeader, consensus::GenesisActiveNexusLaneRecord},
    compute::{
        ComputeAuthPolicy, ComputeFeeSplit, ComputeGovernanceError, ComputePriceAmplifiers,
        ComputePriceDeltaBounds, ComputePriceRiskClass, ComputePriceWeights, ComputeResourceBudget,
        ComputeSandboxRules, ComputeSponsorPolicy,
    },
    content::ContentAuthMode,
    da::{
        commitment::DaProofScheme,
        confidential_compute::ConfidentialComputePolicy,
        prelude::DaStripeLayout,
        types::{BlobClass, DaRentPolicyV1, RetentionPolicy},
    },
    jurisdiction::JdgSignatureScheme,
    nexus::{
        DataSpaceCatalog, DataSpaceMetadata, FeeSponsorProgramId, LaneCatalog,
        LaneConfig as LaneConfigMetadata, LaneSchedulerPolicy, LaneSettlementBufferPolicy,
        LaneStorageProfile, LaneVisibility, UniversalAccountId,
    },
    peer::Peer,
    privacy::{PrivacyIssuerIdV1, PrivacyPolicyIdV1},
    soracloud::SoraPublishedInrouGuestImageArtifactV1,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ProviderIngestCompletionSignerPolicyV1, StorageClass as SorafsStorageClass,
        },
        pricing::PricingScheduleRecord,
    },
    taikai::TaikaiAvailabilityClass,
    transaction::FeePaymentIntent,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId, topology::ShardId};
use iroha_primitives::{
    addr::SocketAddr,
    numeric::{Numeric, Quantity, XorQuantity},
    unique_vec::UniqueVec,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
#[path = "actual_soranet_handshake_debug.rs"]
mod actual_soranet_handshake_debug;
mod kagemusha_enrollment;
pub use kagemusha_enrollment::{
    KagemushaEnrollmentIssuer, KagemushaEnrollmentProvider, KagemushaEnrollmentWorker,
};
mod sccp;
#[path = "actual_sorafs_reputation.rs"]
mod sorafs_reputation;
use crate::{
    kura::{FsyncMode, InitMode},
    parameters::{defaults, user, user::ParseError},
};
pub use iroha_data_model::nexus::DaManifestPolicy;
use norito::{
    codec::{Decode, Encode},
    streaming::EntropyMode,
};
pub use sccp::{
    SCCP_MAX_SECRET_HEADER_NAME_BYTES, SCCP_RESERVED_SECRET_HEADER_NAMES, SccpEndpointError,
    SccpKeeper, SccpLightClientKeeper, SccpLightClientKeeperEndpoints, SccpNode, SccpSecretHeader,
    SccpTonLiteserver, compiled_http_endpoints, compiled_ton_liteservers, derived_keeper_key_dir,
    parse_sccp_http_endpoint, parse_sccp_secret_header_name,
};
pub use sorafs_reputation::{
    SorafsReputationFinalizedArchiveRetentionAuthority, SorafsReputationRuntime,
    SorafsReserveTransparencyRuntime,
};
use thiserror::Error;
use url::Url;
pub use user::{DevTelemetry, Logger, SnapshotResourcePolicy};
// Snapshot is the same validated representation at both configuration layers;
// its explicit max_read_buffer_bytes reaches startup without another default.
pub use user::Snapshot;
type Result<T, E> = core::result::Result<T, Report<E>>;
macro_rules! impl_default {
    ($(#[$attr:meta])* $type:ty => $body:block) => {
        $(#[$attr])*
        impl Default for $type {
            fn default() -> Self $body
        }
    };
}
/// Parsed configuration root used internally by Iroha services.
#[derive(Debug, Clone)]
pub struct Root<G = Genesis> {
    /// Common options shared across components.
    pub common: Common,
    /// Authenticated local runtime-provider broker endpoint.
    pub runtime_provider_broker: RuntimeProviderBroker,
    /// Network configuration.
    pub network: Network,
    /// Genesis configuration.
    pub genesis: G,
    /// Torii API configuration.
    pub torii: Torii,
    /// Embedded Soracloud runtime-manager configuration.
    pub soracloud_runtime: SoracloudRuntime,
    /// Non-secret local custody root for the injected private Musubi publisher.
    pub musubi_publication: MusubiPublication,
    /// Block storage (Kura) configuration.
    pub kura: Kura,
    /// Consensus (Sumeragi) configuration.
    pub sumeragi: Sumeragi,
    /// Block synchronization parameters.
    pub block_sync: BlockSync,
    /// Transaction gossiping parameters.
    pub transaction_gossiper: TransactionGossiper,
    /// Live query store configuration.
    pub live_query_store: LiveQueryStore,
    /// Logger configuration.
    pub logger: Logger,
    /// Queue settings.
    pub queue: Queue,
    /// Nexus lane/data-space configuration.
    pub nexus: Nexus,
    /// Snapshot configuration.
    pub snapshot: Snapshot,
    /// Active telemetry profile describing available capabilities.
    pub telemetry_profile: TelemetryProfile,
    /// Telemetry destination (if enabled).
    pub telemetry: Option<Telemetry>,
    /// Telemetry integrity policy.
    pub telemetry_integrity: TelemetryIntegrity,
    /// Developer telemetry settings.
    pub dev_telemetry: DevTelemetry,
    /// Pipeline execution settings.
    pub pipeline: Pipeline,
    /// Tiered state backend configuration.
    pub tiered_state: crate::parameters::actual::TieredState,
    /// Compute lane configuration.
    pub compute: Compute,
    /// Content lane configuration.
    pub content: Content,
    /// Oracle aggregation configuration.
    pub oracle: Oracle,
    /// IVM-related configuration (banner/beep).
    pub ivm: Ivm,
    /// Norito codec settings (serialization/compression heuristics).
    pub norito: Norito,
    /// Fraud monitoring configuration.
    pub fraud_monitoring: FraudMonitoring,
    /// Zero-knowledge proof system settings.
    pub zk: Zk,
    /// Governance settings (voting keys, policies).
    pub gov: Governance,
    /// Network Time Service parameters.
    pub nts: Nts,
    /// Hardware acceleration settings for IVM and helpers.
    pub accel: Acceleration,
    /// Concurrency settings for thread pools.
    pub concurrency: Concurrency,
    /// Confidential asset/verifier configuration.
    pub confidential: Confidential,
    /// Cryptography feature toggles and defaults.
    pub crypto: Crypto,
    /// Settlement conversion-routing configuration.
    pub settlement: Settlement,
    /// Streaming configuration (control-plane key material).
    pub streaming: Streaming,
    /// Node-local SCCP keeper and its light-client duty.
    pub sccp: SccpNode,
    /// Node data directory, when the configuration uses the fixed `data_dir` layout.
    pub data_dir: Option<DataDir>,
    /// Node process lifecycle settings.
    pub lifecycle: Lifecycle,
}
/// Public endpoint of the authenticated local runtime-provider broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProviderBroker {
    /// Absolute server observer-operation allowance; nonzero and at most 15 seconds.
    ///
    /// It starts before provider dispatch and bounds reply publication. A synchronous
    /// provider already running cannot be forcibly cancelled by this allowance.
    pub observer_operation_timeout: Duration,
    /// Aggregate memory retained by one local consensus credential registry.
    pub credential_max_memory_bytes: NonZeroUsize,
    /// Lexically validated absolute Unix socket path.
    pub endpoint_path: RuntimeProviderBrokerEndpointPath,
}

impl RuntimeProviderBroker {
    /// Read only a broker policy table, without loading node credentials or files.
    ///
    /// Pass the contents of `[runtime_provider_broker]`, or an empty table for
    /// the canonical defaults. Ambient environment variables are ignored.
    /// The same fields and endpoint validation are used by [`Root`].
    ///
    /// # Errors
    ///
    /// Rejects unknown fields, a zero memory bound, an invalid endpoint, or an
    /// observer-operation duration outside 1..=15_000 milliseconds.
    pub fn from_toml_source(src: TomlSource) -> Result<Self, FromTomlSourceError> {
        ConfigReader::new()
            .without_env()
            .with_toml_source(src)
            .read_and_complete::<user::RuntimeProviderBroker>()
            .change_context(FromTomlSourceError)?
            .parse()
            .change_context(FromTomlSourceError)
    }
}

/// An absolute, bounded broker socket path with the canonical socket basename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProviderBrokerEndpointPath(PathBuf);

/// Invalid public runtime-provider broker endpoint path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "runtime-provider broker endpoint must be an absolute, canonical UTF-8 Unix socket path of at most 103 bytes ending in runtime-provider-broker-v1.sock"
)]
pub struct RuntimeProviderBrokerEndpointPathError;

impl RuntimeProviderBrokerEndpointPath {
    /// Validate a public endpoint path without requiring the broker to be running.
    ///
    /// Ownership, mode, ancestor, and peer-UID checks are performed again at
    /// the authenticated transport boundary when the socket is used.
    ///
    /// # Errors
    ///
    /// Rejects a non-UTF-8, relative, ambiguous, oversized, or wrongly named path.
    pub fn try_new(
        path: PathBuf,
    ) -> core::result::Result<Self, RuntimeProviderBrokerEndpointPathError> {
        let raw = path
            .as_os_str()
            .to_str()
            .ok_or(RuntimeProviderBrokerEndpointPathError)?;
        if !raw.starts_with('/')
            || raw.len() > 103
            || raw.rsplit('/').next() != Some("runtime-provider-broker-v1.sock")
            || raw.split('/').skip(1).any(|component| {
                component.is_empty()
                    || matches!(component, "." | "..")
                    || component.contains('\\')
                    || component.chars().any(char::is_control)
            })
        {
            return Err(RuntimeProviderBrokerEndpointPathError);
        }
        Ok(Self(path))
    }

    /// Return the validated public Unix socket path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl FromStr for RuntimeProviderBrokerEndpointPath {
    type Err = RuntimeProviderBrokerEndpointPathError;

    fn from_str(path: &str) -> core::result::Result<Self, Self::Err> {
        Self::try_new(PathBuf::from(path))
    }
}
/// Node process lifecycle settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifecycle {
    /// Exit when standard input reaches end-of-file (set by a supervising parent).
    pub exit_on_stdin_close: bool,
}
impl_default!(Lifecycle => {
        Self {
            exit_on_stdin_close: defaults::lifecycle::EXIT_ON_STDIN_CLOSE,
        }
});
/// Owner-only secret file with a fixed name under `<data_dir>/secrets/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeSecretFile {
    /// Validator BLS private key.
    Validator,
    /// SoraNet transport Ed25519 private key.
    Transport,
    /// Streaming identity Ed25519 private key.
    Streaming,
    /// Soracloud runtime mutation-signer private key.
    RuntimeSigner,
    /// Global beacon partial-signer credential.
    BeaconCredential,
    /// Faucet authority private key.
    FaucetAuthority,
    /// Onboarding authority private key.
    OnboardingAuthority,
    /// SoraFS council authority private key.
    ///
    /// TODO(P2): reserved for the deploy engine's network-authority keys (spec §7.2); no
    /// configuration key reads it yet, so the node never opens it.
    SorafsCouncilAuthority,
}
impl NodeSecretFile {
    /// Every fixed secret file, in a stable order.
    pub const ALL: [Self; 8] = [
        Self::Validator,
        Self::Transport,
        Self::Streaming,
        Self::RuntimeSigner,
        Self::BeaconCredential,
        Self::FaucetAuthority,
        Self::OnboardingAuthority,
        Self::SorafsCouncilAuthority,
    ];
    /// Path of this file relative to `<data_dir>/secrets/`.
    #[must_use]
    pub const fn relative_path(self) -> &'static str {
        use defaults::data_dir as names;
        match self {
            Self::Validator => names::VALIDATOR_KEY,
            Self::Transport => names::TRANSPORT_KEY,
            Self::Streaming => names::STREAMING_KEY,
            Self::RuntimeSigner => names::RUNTIME_SIGNER_KEY,
            Self::BeaconCredential => names::BEACON_CREDENTIAL,
            Self::FaucetAuthority => names::FAUCET_AUTHORITY_KEY,
            Self::OnboardingAuthority => names::ONBOARDING_AUTHORITY_KEY,
            Self::SorafsCouncilAuthority => names::SORAFS_COUNCIL_AUTHORITY_KEY,
        }
    }
}
/// Fixed node directory layout rooted at `data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDir {
    root: PathBuf,
}
impl DataDir {
    /// Wrap an already resolved data directory.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    /// The data directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// `<data_dir>/state`, the parent of every derived state path.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join(defaults::data_dir::STATE_DIR)
    }
    /// `<data_dir>/secrets`, the parent of every fixed secret file.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join(defaults::data_dir::SECRETS_DIR)
    }
    /// Path of one fixed secret file.
    #[must_use]
    pub fn secret(&self, file: NodeSecretFile) -> PathBuf {
        self.secrets_dir().join(file.relative_path())
    }
}
/// Public binding of the file-backed Soracloud runtime signer.
///
/// `iroha3d` loads this signer from [`NodeSecretFile::RuntimeSigner`] (`irohad::node_secrets`)
/// and admits a configured `soracloud_runtime.submission.signer` only when it carries exactly
/// [`handle_v1`], [`REVISION_V1`] and [`policy_digest_v1`]. Deployment renderers emit the same
/// values, so they live here rather than in the daemon.
pub mod node_runtime_signer {
    use iroha_crypto::{Algorithm, Hash, PublicKey};

    /// Exact adapter and public-policy revision of the file-backed runtime signer.
    pub const REVISION_V1: u64 = 1;
    /// Handle prefix; the lowercase hex of the raw Ed25519 public key follows.
    pub const HANDLE_PREFIX_V1: &str = "software://iroha/node-secrets/runtime-signer/";
    /// Exact size of `runtime_signer.key`: one canonical Ed25519 private multihash and a newline.
    pub const KEY_FILE_BYTES_V1: usize = 71;
    /// Domain of [`policy_digest_v1`].
    const POLICY_DIGEST_DOMAIN_V1: &[u8] =
        b"iroha.node-secrets.runtime-signer.compiled-policy.digest.v1\0";
    /// Compiled public policy the digest commits to.
    pub const COMPILED_POLICY_V1: &[u8] = b"algorithm=ed25519;credential=data-dir-secrets/runtime_signer.key;custody=nofollow-regular-nlink-1-owner-root-or-euid-owner-only-mode-size-71-trusted-ancestors;key=canonical-private-multihash-plus-newline;handle=software://iroha/node-secrets/runtime-signer/<lowercase-raw-public-key-hex>;authority=account-id(public-key);transactions=exact-authority-payload;provenance=canonical-soracloud-v1-domain-version-purpose-preimage;qualification=active-nontest;";

    /// Public-policy digest the configured binding must carry (`policy_digest_hex`):
    /// `Hash(domain ‖ revision ‖ len(policy) ‖ policy)` with big-endian integers.
    #[must_use]
    pub fn policy_digest_v1() -> [u8; 32] {
        let mut preimage =
            Vec::with_capacity(POLICY_DIGEST_DOMAIN_V1.len() + 16 + COMPILED_POLICY_V1.len());
        preimage.extend_from_slice(POLICY_DIGEST_DOMAIN_V1);
        preimage.extend_from_slice(&REVISION_V1.to_be_bytes());
        preimage.extend_from_slice(
            &u64::try_from(COMPILED_POLICY_V1.len())
                .expect("compiled signer policy length fits u64")
                .to_be_bytes(),
        );
        preimage.extend_from_slice(COMPILED_POLICY_V1);
        Hash::new(preimage).into()
    }

    /// Handle the configured binding must carry for `public_key`, or `None` for a key that is
    /// not Ed25519.
    #[must_use]
    pub fn handle_v1(public_key: &PublicKey) -> Option<String> {
        match public_key.try_to_bytes() {
            Ok((Algorithm::Ed25519, payload)) if payload.len() == 32 => {
                Some(format!("{HANDLE_PREFIX_V1}{}", hex::encode(payload)))
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use iroha_crypto::KeyPair;

        #[test]
        fn policy_digest_is_stable_and_bound_to_the_policy() {
            let digest = policy_digest_v1();
            assert_eq!(digest, policy_digest_v1());
            assert_ne!(digest, [0; 32]);
            assert!(
                core::str::from_utf8(COMPILED_POLICY_V1)
                    .expect("ASCII policy")
                    .contains(HANDLE_PREFIX_V1.trim_end_matches('/'))
            );
        }

        #[test]
        fn handle_names_the_raw_ed25519_key_only() {
            let key_pair = KeyPair::from_seed(b"node-runtime-signer".to_vec(), Algorithm::Ed25519);
            let (_, raw) = key_pair.public_key().to_bytes();
            assert_eq!(
                handle_v1(key_pair.public_key()),
                Some(format!("{HANDLE_PREFIX_V1}{}", hex::encode(raw)))
            );
            let secp = KeyPair::from_seed(b"node-runtime-signer".to_vec(), Algorithm::Secp256k1);
            assert_eq!(handle_v1(secp.public_key()), None);
        }
    }
}
#[cfg(test)]
mod data_dir_tests {
    use super::*;

    #[test]
    fn data_dir_layout_uses_fixed_names() {
        let data_dir = DataDir::new(PathBuf::from("/var/lib/iroha/taira/v1"));
        assert_eq!(data_dir.root(), Path::new("/var/lib/iroha/taira/v1"));
        assert_eq!(
            data_dir.state_dir(),
            PathBuf::from("/var/lib/iroha/taira/v1/state")
        );
        assert_eq!(
            data_dir.secrets_dir(),
            PathBuf::from("/var/lib/iroha/taira/v1/secrets")
        );
        let names: Vec<&str> = NodeSecretFile::ALL
            .iter()
            .map(|file| file.relative_path())
            .collect();
        assert_eq!(
            names,
            [
                "validator.key",
                "transport.key",
                "streaming.key",
                "runtime_signer.key",
                "beacon.cred",
                "authority/faucet.key",
                "authority/onboarding.key",
                "authority/sorafs_council.key",
            ]
        );
        assert_eq!(
            data_dir.secret(NodeSecretFile::OnboardingAuthority),
            PathBuf::from("/var/lib/iroha/taira/v1/secrets/authority/onboarding.key")
        );
    }

    #[test]
    fn lifecycle_defaults_keep_running_on_stdin_close() {
        assert!(!Lifecycle::default().exit_on_stdin_close);
    }
}
/// Non-secret private Musubi publication custody and TLS listener settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiPublication {
    /// Complete explicit runtime selection; absence installs no publication service.
    pub installation: Option<MusubiPublicationInstallation>,
    /// Parent directory for the separately locked journal, seed and clock owners.
    pub custody_root: PathBuf,
    /// Private TLS bind address; no certificate or key material is stored here.
    pub private_tls_bind: std::net::SocketAddr,
    /// Maximum simultaneously admitted private TLS requests.
    pub max_inflight_requests: u16,
    /// Lifetime operation capacity of the durable publication journal.
    pub journal_max_operations: u32,
    /// Unexpired authorization capacity of the durable publication journal.
    pub journal_max_authorizations: u32,
    /// Total durable response bytes, including in-flight terminal reservations.
    pub journal_max_total_response_bytes: u64,
    /// Maximum complete canonical journal snapshot size.
    pub journal_max_snapshot_bytes: u64,
    /// Maximum number of exact CAR seed records retained in local custody.
    pub max_seed_records: u32,
    /// Maximum total bytes of exact CAR seed records retained in local custody.
    pub max_seed_bytes: u64,
    /// Maximum publisher-clock lead accepted by publication authorization.
    pub max_future_clock_skew_ms: u64,
    /// Lifetime assigned to a broker-signed seed-ingress receipt.
    pub receipt_lifetime_ms: u64,
    /// Exact paid-pin storage tier selected by the operator.
    pub pin_storage_class: SorafsStorageClass,
    /// Requested paid-pin lifetime beyond submission, in seconds.
    pub pin_retention_horizon_secs: u64,
    /// Public identity expected to sign and pay for the pin transaction.
    pub pin_transaction_authority: MusubiPinTransactionAuthority,
}
/// Complete public identity and bounded authorization for an explicitly installed publisher.
///
/// Parsing this intent provides no native authority or initialization permission. Runtime must
/// open the already initialized original custody and independently verify keys, TLS and State.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiPublicationInstallation {
    /// Exact original genesis-derived network.
    pub network_id: iroha_data_model::NetworkId,
    /// Admitted provider whose owner signs seed receipts.
    pub seed_provider: ProviderId,
    /// Exact provider owner; never inferred from the daemon validator key.
    pub ingress_broker: AccountId,
    /// Original nonzero authority-wide pin session, retained across every restart.
    pub pin_session: [u8; 32],
    /// Native private credential for the exact ingress broker.
    pub broker_key_file: PathBuf,
    /// Native private credential for the independently configured paid-pin account.
    pub pin_key_file: PathBuf,
    /// Exact original DNS name checked by the TLS identity owner.
    pub tls_server_name: String,
    /// Original server certificate in bounded DER form.
    pub tls_certificate_file: PathBuf,
    /// Original certificate's private key in bounded DER form.
    pub tls_private_key_file: PathBuf,
    /// Original private trust root, used without modifying global trust stores.
    pub tls_root_certificate_file: PathBuf,
    /// Finite budget for each fresh native provider discovery, independent of pin authorization.
    pub readback_request_timeout_ms: u64,
    /// Maximum authorization interval of a new operation, also capped by its signed caller expiry.
    pub pin_authorization_window_ms: u64,
    /// Maximum fresh native Checks under one immutable operation authorization.
    pub pin_max_check_rounds: u16,
    /// Exact Nexus fee asset for the original per-operation spending authorization.
    pub pin_fee_asset: AssetDefinitionId,
    /// Per-transaction Nexus ceiling; public pin principal remains native-priced separately.
    pub pin_per_transaction_fee_limit: Quantity,
    /// Aggregate Nexus ceiling across every retained pin/control payload in that operation.
    pub pin_total_fee_limit: Quantity,
}
/// First-release selection of the public account expected to sign and fund a Musubi paid pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MusubiPinTransactionAuthority {
    /// Resolve to the runtime-qualified seed-ingress broker account.
    IngressBroker,
    /// Use one exact canonical domainless account identity.
    Account(AccountId),
}
/// Non-secret paid-pin inputs resolved against the live publication service identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiPublicationPaidPinPolicy {
    /// Storage tier in the canonical SoraFS manifest.
    pub storage_class: SorafsStorageClass,
    /// Lifetime beyond the finalized submission epoch, in seconds.
    pub retention_horizon_secs: u64,
    /// Exact account whose runtime signer and fee balance must be qualified before submission.
    pub transaction_authority: AccountId,
}
impl MusubiPublication {
    /// Resolve the configured public pin account against the live broker identity.
    #[must_use]
    pub fn paid_pin_policy(&self, ingress_broker: &AccountId) -> MusubiPublicationPaidPinPolicy {
        let transaction_authority = match &self.pin_transaction_authority {
            MusubiPinTransactionAuthority::IngressBroker => ingress_broker.clone(),
            MusubiPinTransactionAuthority::Account(account) => account.clone(),
        };
        MusubiPublicationPaidPinPolicy {
            storage_class: self.pin_storage_class,
            retention_horizon_secs: self.pin_retention_horizon_secs,
            transaction_authority,
        }
    }
}
impl_default!(MusubiPublication => {
    Self {
        installation: None,
        custody_root: PathBuf::from(defaults::musubi_publication::CUSTODY_ROOT),
        private_tls_bind: defaults::musubi_publication::private_tls_bind(),
        max_inflight_requests: defaults::musubi_publication::MAX_INFLIGHT_REQUESTS,
        journal_max_operations: defaults::musubi_publication::JOURNAL_MAX_OPERATIONS,
        journal_max_authorizations: defaults::musubi_publication::JOURNAL_MAX_AUTHORIZATIONS,
        journal_max_total_response_bytes: defaults::musubi_publication::JOURNAL_MAX_TOTAL_RESPONSE_BYTES,
        journal_max_snapshot_bytes: defaults::musubi_publication::JOURNAL_MAX_SNAPSHOT_BYTES,
        max_seed_records: defaults::musubi_publication::MAX_SEED_RECORDS,
        max_seed_bytes: defaults::musubi_publication::MAX_SEED_BYTES,
        max_future_clock_skew_ms: defaults::musubi_publication::MAX_FUTURE_CLOCK_SKEW_MS,
        receipt_lifetime_ms: defaults::musubi_publication::RECEIPT_LIFETIME_MS,
        pin_storage_class: SorafsStorageClass::Hot,
        pin_retention_horizon_secs: defaults::musubi_publication::PIN_RETENTION_HORIZON_SECS,
        pin_transaction_authority: MusubiPinTransactionAuthority::IngressBroker,
    }
});
/// Embedded Soracloud runtime-manager configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoracloudRuntime {
    /// Whether production posture checks are enabled for Soracloud runtime startup.
    pub production_mode: bool,
    /// Root directory for node-local Soracloud runtime state.
    pub state_dir: PathBuf,
    /// Reconciliation cadence against authoritative world state.
    pub reconcile_interval: Duration,
    /// Maximum concurrent artifact hydration workers, independent of Inrou guest concurrency.
    pub hydration_concurrency: NonZeroUsize,
    /// Maximum idle prepared IVM runtimes retained independently of hydration workers.
    pub prepared_runtime_cache_capacity: NonZeroUsize,
    /// Cache budgets for hydrated Soracloud artifacts.
    pub cache_budgets: SoracloudRuntimeCacheBudgets,
    /// Inrou microVM hosting limits.
    pub inrou: SoracloudRuntimeInrou,
    /// Runtime-originated transaction submission settings.
    pub submission: SoracloudRuntimeSubmission,
    /// Outbound egress policy enforced by the embedded runtime manager.
    pub egress: SoracloudRuntimeEgress,
}
impl_default!(SoracloudRuntime => {
        Self {
            production_mode: defaults::soracloud_runtime::PRODUCTION_MODE,
            state_dir: defaults::soracloud_runtime::state_dir(),
            reconcile_interval: Duration::from_millis(
                defaults::soracloud_runtime::RECONCILE_INTERVAL_MS,
            ),
            hydration_concurrency: defaults::soracloud_runtime::HYDRATION_CONCURRENCY,
            prepared_runtime_cache_capacity:
                defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY,
            cache_budgets: SoracloudRuntimeCacheBudgets::default(),
            inrou: SoracloudRuntimeInrou::default(),
            submission: SoracloudRuntimeSubmission::default(),
            egress: SoracloudRuntimeEgress::default(),
        }
});
impl SoracloudRuntime {
    /// Assert release-wide hosting admission and production-only runtime settings.
    ///
    /// This method is intentionally available on the parsed `actual` config so
    /// callers that construct runtime settings directly cannot bypass the
    /// runtime posture checks performed by user-config parsing.
    pub fn assert_runtime_posture(&self) {
        assert!(
            self.hydration_concurrency.get()
                <= defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX,
            "soracloud_runtime.hydration_concurrency exceeds the first-release worker limit"
        );
        assert!(
            self.prepared_runtime_cache_capacity.get()
                <= defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX,
            "soracloud_runtime.prepared_runtime_cache_capacity exceeds the first-release idle-runtime limit"
        );
        self.inrou.assert_archive_resource_bounds();
        self.inrou.assert_lifecycle_grace_bounds();
        self.inrou.assert_portable_vm_v1_shape();
        assert!(
            !self.inrou.enabled || self.production_mode,
            "soracloud_runtime.inrou.enabled requires soracloud_runtime.production_mode = true"
        );
        if !self.production_mode {
            return;
        }
        assert!(
            !self.egress.default_allow,
            "soracloud_runtime.production_mode requires soracloud_runtime.egress.default_allow = false"
        );
        assert!(
            self.egress.rate_per_minute.is_some(),
            "soracloud_runtime.production_mode requires soracloud_runtime.egress.rate_per_minute"
        );
        assert!(
            self.egress.max_bytes_per_minute.is_some(),
            "soracloud_runtime.production_mode requires soracloud_runtime.egress.max_bytes_per_minute"
        );
        assert!(
            self.submission.signer.is_some(),
            "soracloud_runtime.production_mode requires soracloud_runtime.submission.signer"
        );
    }
}
/// Cache budgets for hydrated Soracloud runtime artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoracloudRuntimeCacheBudgets {
    /// Cache budget for executable service bundles.
    pub bundle_bytes: NonZeroU64,
    /// Cache budget for hydrated static assets.
    pub static_asset_bytes: NonZeroU64,
    /// Cache budget for runtime journals.
    pub journal_bytes: NonZeroU64,
    /// Cache budget for runtime checkpoints.
    pub checkpoint_bytes: NonZeroU64,
    /// Cache budget for model artifacts.
    pub model_artifact_bytes: NonZeroU64,
    /// Cache budget for model weights.
    pub model_weight_bytes: NonZeroU64,
}
impl_default!(SoracloudRuntimeCacheBudgets => {
        Self {
            bundle_bytes: defaults::soracloud_runtime::BUNDLE_CACHE_BUDGET_BYTES,
            static_asset_bytes: defaults::soracloud_runtime::STATIC_ASSET_CACHE_BUDGET_BYTES,
            journal_bytes: defaults::soracloud_runtime::JOURNAL_CACHE_BUDGET_BYTES,
            checkpoint_bytes: defaults::soracloud_runtime::CHECKPOINT_CACHE_BUDGET_BYTES,
            model_artifact_bytes: defaults::soracloud_runtime::MODEL_ARTIFACT_CACHE_BUDGET_BYTES,
            model_weight_bytes: defaults::soracloud_runtime::MODEL_WEIGHT_CACHE_BUDGET_BYTES,
        }
});
/// Resource ceilings for mutable Inrou microVM workloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoracloudRuntimeInrou {
    /// Whether this node advertises and materializes local Inrou workloads.
    pub enabled: bool,
    /// Canonical slot uid of the locked local `iroha-inrou-{slot}` service account.
    pub portable_vm_uid: Option<NonZeroU32>,
    /// Canonical slot gid of the locked local `iroha-inrou-{slot}` primary group.
    pub portable_vm_gid: Option<NonZeroU32>,
    /// Exact operator-approved guest artifact accepted by this host.
    pub trusted_guest_artifact: Option<SoraPublishedInrouGuestImageArtifactV1>,
    /// Maximum immutable guest-image bytes materialized from the operator-preseed store.
    pub guest_image_max_bytes: NonZeroU64,
    /// Maximum aggregate physical host CPU reservation, including VMM overhead, in millicores.
    pub max_cpu_millis: NonZeroU32,
    /// Maximum aggregate physical host memory reservation, including VMM overhead, in bytes.
    pub max_memory_bytes: NonZeroU64,
    /// Maximum aggregate hosted writable-storage budget in bytes.
    pub max_storage_bytes: NonZeroU64,
    /// Maximum compressed size accepted for one bundle archive.
    pub bundle_archive_max_compressed_bytes: NonZeroU64,
    /// Maximum decoded size accepted for one bundle archive.
    pub bundle_archive_max_decoded_bytes: NonZeroU64,
    /// Maximum number of entries accepted from one bundle archive.
    pub bundle_archive_max_entries: NonZeroU32,
    /// Maximum decoded size accepted for one file in a bundle archive.
    pub bundle_archive_max_file_bytes: NonZeroU64,
    /// Maximum aggregate decoded file size accepted from one bundle archive.
    pub bundle_archive_max_total_file_bytes: NonZeroU64,
    /// Operator minimum startup grace before the manager treats the VM as failed.
    ///
    /// The effective worker grace is the maximum of this value and the workload manifest value.
    pub start_grace: Duration,
    /// Operator minimum shutdown grace before the manager force-stops the VMM process.
    ///
    /// The effective worker grace is the maximum of this value and the workload manifest value.
    pub stop_grace: Duration,
}
impl_default!(SoracloudRuntimeInrou => {
        Self {
            enabled: defaults::soracloud_runtime::INROU_ENABLED,
            portable_vm_uid: defaults::soracloud_runtime::INROU_PORTABLE_VM_UID,
            portable_vm_gid: defaults::soracloud_runtime::INROU_PORTABLE_VM_GID,
            trusted_guest_artifact: None,
            guest_image_max_bytes: defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES,
            max_cpu_millis: defaults::soracloud_runtime::INROU_MAX_CPU_MILLIS,
            max_memory_bytes: defaults::soracloud_runtime::INROU_MAX_MEMORY_BYTES,
            max_storage_bytes: defaults::soracloud_runtime::INROU_MAX_STORAGE_BYTES,
            bundle_archive_max_compressed_bytes:
                defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES,
            bundle_archive_max_decoded_bytes:
                defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES,
            bundle_archive_max_entries:
                defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_ENTRIES,
            bundle_archive_max_file_bytes:
                defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES,
            bundle_archive_max_total_file_bytes:
                defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES,
            start_grace: Duration::from_millis(defaults::soracloud_runtime::INROU_START_GRACE_MS),
            stop_grace: Duration::from_millis(defaults::soracloud_runtime::INROU_STOP_GRACE_MS),
        }
});
impl SoracloudRuntimeInrou {
    fn assert_portable_vm_v1_shape(&self) {
        assert!(
            self.guest_image_max_bytes.get()
                <= defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT,
            "soracloud_runtime.inrou.guest_image_max_bytes exceeds its hard ceiling"
        );
        if !self.enabled {
            assert!(
                self.portable_vm_uid.is_none()
                    && self.portable_vm_gid.is_none()
                    && self.trusted_guest_artifact.is_none(),
                "disabled soracloud_runtime.inrou must not retain a PortableVM identity or trusted guest artifact"
            );
            return;
        }
        let uid = self
            .portable_vm_uid
            .expect("enabled soracloud_runtime.inrou requires portable_vm_uid")
            .get();
        let gid = self
            .portable_vm_gid
            .expect("enabled soracloud_runtime.inrou requires portable_vm_gid")
            .get();
        assert!(
            defaults::soracloud_runtime::inrou_portable_vm_identity_slot(uid, gid).is_some(),
            "soracloud_runtime.inrou PortableVM uid/gid must be one equal canonical slot pair in {}..{} (upper bound exclusive)",
            defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_BASE,
            defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_MAX_EXCLUSIVE,
        );
        self.trusted_guest_artifact
            .as_ref()
            .expect("enabled soracloud_runtime.inrou requires trusted_guest_artifact")
            .validate()
            .expect("enabled soracloud_runtime.inrou requires a valid trusted guest artifact");
    }

    fn assert_archive_resource_bounds(&self) {
        assert!(
            self.bundle_archive_max_compressed_bytes.get()
                <= defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT,
            "soracloud_runtime.inrou.bundle_archive_max_compressed_bytes exceeds its hard ceiling"
        );
        assert!(
            self.bundle_archive_max_decoded_bytes.get()
                <= defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT,
            "soracloud_runtime.inrou.bundle_archive_max_decoded_bytes exceeds its hard ceiling"
        );
        assert!(
            self.bundle_archive_max_entries.get()
                <= defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_ENTRIES_LIMIT,
            "soracloud_runtime.inrou.bundle_archive_max_entries exceeds its hard ceiling"
        );
        assert!(
            self.bundle_archive_max_file_bytes.get()
                <= defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT,
            "soracloud_runtime.inrou.bundle_archive_max_file_bytes exceeds its hard ceiling"
        );
        assert!(
            self.bundle_archive_max_total_file_bytes.get()
                <= defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT,
            "soracloud_runtime.inrou.bundle_archive_max_total_file_bytes exceeds its hard ceiling"
        );
        assert!(
            self.bundle_archive_max_file_bytes <= self.bundle_archive_max_total_file_bytes,
            "soracloud_runtime.inrou.bundle_archive_max_file_bytes must not exceed bundle_archive_max_total_file_bytes"
        );
        assert!(
            self.bundle_archive_max_total_file_bytes <= self.bundle_archive_max_decoded_bytes,
            "soracloud_runtime.inrou.bundle_archive_max_total_file_bytes must not exceed bundle_archive_max_decoded_bytes"
        );
    }

    fn assert_lifecycle_grace_bounds(&self) {
        let minimum =
            Duration::from_millis(defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MIN_MS);
        let maximum =
            Duration::from_millis(defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS);
        for (field, value) in [
            ("start_grace", self.start_grace),
            ("stop_grace", self.stop_grace),
        ] {
            assert!(
                (minimum..=maximum).contains(&value),
                "soracloud_runtime.inrou.{field} must be between {} and {} milliseconds inclusive",
                defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MIN_MS,
                defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS,
            );
        }
    }
}
/// Runtime-originated transaction submission settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SoracloudRuntimeSubmission {
    /// Exact fee payer used for runtime-originated control-plane submissions.
    pub fee_payer: SoracloudRuntimeFeePayer,
    /// Exact public binding for the deployment-owned mutation and provenance signer.
    pub signer: Option<SoracloudRuntimeMutationSignerBinding>,
}
/// Public identity and qualification of the Soracloud runtime mutation signer.
///
/// The opaque handle is resolved through deployment-owned runtime injection.
/// Private keys, credentials, tokens, PINs, and vendor connection material are
/// intentionally absent from this configuration boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoracloudRuntimeMutationSignerBinding {
    /// Stable opaque production provider handle.
    pub handle: String,
    /// Canonical transaction authority derived from `public_key`.
    pub authority: AccountId,
    /// Exact signature algorithm exposed by the runtime provider.
    pub algorithm: Algorithm,
    /// Exact public key exposed by the runtime provider.
    pub public_key: PublicKey,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Signature-bound fee source for runtime-originated Soracloud transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SoracloudRuntimeFeePayer {
    /// Debit the validator authority after deterministic quoting.
    #[default]
    Authority,
    /// Debit one exact immutable sponsor-program revision.
    Sponsor {
        /// Canonical sponsor/program identifier.
        program_id: FeeSponsorProgramId,
        /// Exact immutable program revision.
        program_revision: u64,
    },
}
impl SoracloudRuntimeSubmission {
    /// Build the empty-limit fee intent that Core must quote before signing.
    #[must_use]
    pub fn fee_payment_intent(&self) -> FeePaymentIntent {
        match &self.fee_payer {
            SoracloudRuntimeFeePayer::Authority => FeePaymentIntent::authority(Vec::new(), None),
            SoracloudRuntimeFeePayer::Sponsor {
                program_id,
                program_revision,
            } => FeePaymentIntent::sponsor(program_id.clone(), *program_revision, Vec::new(), None),
        }
    }
}
/// Outbound egress policy for embedded Soracloud runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoracloudRuntimeEgress {
    /// Whether egress is allowed by default when a destination is not explicitly listed.
    pub default_allow: bool,
    /// Explicit destination allowlist applied when `default_allow` is false.
    pub allowed_hosts: Vec<String>,
    /// Optional outbound request-rate cap per service/minute.
    pub rate_per_minute: Option<NonZeroU32>,
    /// Optional outbound byte budget per service/minute.
    pub max_bytes_per_minute: Option<NonZeroU64>,
}
impl_default!(SoracloudRuntimeEgress => {
        Self {
            default_allow: defaults::soracloud_runtime::EGRESS_DEFAULT_ALLOW,
            allowed_hosts: defaults::soracloud_runtime::egress_allowed_hosts(),
            rate_per_minute: defaults::soracloud_runtime::EGRESS_RATE_PER_MINUTE
                .and_then(NonZeroU32::new),
            max_bytes_per_minute: defaults::soracloud_runtime::EGRESS_MAX_BYTES_PER_MINUTE
                .and_then(NonZeroU64::new),
        }
});
/// See [`Root::from_toml_source`]
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Failed to read configuration from a given TOML source")]
pub struct FromTomlSourceError;
impl Root {
    /// Read config from exactly one provided TOML source.
    ///
    /// Ambient process environment variables are deliberately ignored. This
    /// constructor is used by offline signing, bundle admission, and tests,
    /// where allowing the caller's shell to rewrite the supplied artifact
    /// would make validation non-reproducible.
    /// # Errors
    /// If config reading/parsing fails.
    pub fn from_toml_source(src: TomlSource) -> Result<Self, FromTomlSourceError> {
        ConfigReader::new()
            .without_env()
            .with_toml_source(src)
            .read_and_complete::<user::Root>()
            .change_context(FromTomlSourceError)?
            .parse()
            .change_context(FromTomlSourceError)
    }
}
impl<G> Root<G> {
    fn map_genesis<H>(self, transform: impl FnOnce(G) -> H) -> Root<H> {
        let Self {
            common,
            runtime_provider_broker,
            network,
            genesis,
            torii,
            soracloud_runtime,
            musubi_publication,
            kura,
            sumeragi,
            block_sync,
            transaction_gossiper,
            live_query_store,
            logger,
            queue,
            nexus,
            snapshot,
            telemetry_profile,
            telemetry,
            telemetry_integrity,
            dev_telemetry,
            pipeline,
            tiered_state,
            compute,
            content,
            oracle,
            ivm,
            norito,
            fraud_monitoring,
            zk,
            gov,
            nts,
            accel,
            concurrency,
            confidential,
            crypto,
            settlement,
            streaming,
            sccp,
            data_dir,
            lifecycle,
        } = self;
        Root {
            common,
            runtime_provider_broker,
            network,
            genesis: transform(genesis),
            torii,
            soracloud_runtime,
            musubi_publication,
            kura,
            sumeragi,
            block_sync,
            transaction_gossiper,
            live_query_store,
            logger,
            queue,
            nexus,
            snapshot,
            telemetry_profile,
            telemetry,
            telemetry_integrity,
            dev_telemetry,
            pipeline,
            tiered_state,
            compute,
            content,
            oracle,
            ivm,
            norito,
            fraud_monitoring,
            zk,
            gov,
            nts,
            accel,
            concurrency,
            confidential,
            crypto,
            settlement,
            streaming,
            sccp,
            data_dir,
            lifecycle,
        }
    }
    /// Check whether the configuration already enables Sora/Nexus-only features.
    #[cfg(test)]
    #[must_use]
    pub fn uses_sora_features(&self) -> bool {
        let sorafs = self.torii.sorafs_storage.enabled
            || self.torii.sorafs_discovery.discovery_enabled
            || self.torii.sorafs_repair.enabled
            || self.torii.sorafs_gc.enabled;
        let nexus = self.uses_multilane_catalogs() || self.nexus.has_lane_overrides();
        sorafs || nexus
    }
    /// Detect whether the configuration declares multiple lanes/dataspaces or non-default routing.
    #[must_use]
    pub fn uses_multilane_catalogs(&self) -> bool {
        self.nexus.uses_multilane_catalogs()
    }
    /// Apply safe SoraFS defaults without changing the parsed Nexus geometry.
    ///
    /// Discovery requires a parsed admission trust policy. This does not
    /// manufacture trust roots or an embedded storage-provider role.
    pub fn apply_sora_service_defaults(&mut self) {
        self.torii.sorafs_discovery.discovery_enabled =
            self.torii.sorafs_discovery.admission.is_some();
        if self.tiered_state.da_store_root.is_none() {
            self.tiered_state.da_store_root =
                Some(PathBuf::from(defaults::tiered_state::DEFAULT_DA_STORE_ROOT));
        }
    }
    /// Apply the bundled Sora Nexus geometry and safe SoraFS defaults.
    ///
    /// Existing non-default geometry remains intact. TOML-backed callers must
    /// use [`crate::sora_profile::SoraProfileSelection`] to also preserve explicit
    /// default-valued geometry and service settings.
    pub fn apply_sora_profile(&mut self) {
        self.apply_sora_service_defaults();
        // Apply bundled geometry only to the exact untouched default. A lane
        // can remain SINGLE/"default" while carrying security- or
        // storage-relevant overrides (for example a pinned shard); treating
        // that as pristine would silently discard explicit operator policy.
        if !self.nexus.has_lane_overrides() {
            let lane_catalog = sora_lane_catalog();
            self.nexus.configured_lane_catalog = lane_catalog.clone();
            self.nexus.lane_catalog = lane_catalog;
            self.nexus.lane_config = LaneConfig::from_catalog(&self.nexus.lane_catalog);
            let dataspace_catalog = sora_dataspace_catalog();
            self.nexus.configured_dataspace_catalog = dataspace_catalog.clone();
            self.nexus.dataspace_catalog = dataspace_catalog;
            self.nexus.routing_policy = sora_routing_policy();
        }
    }
    /// Apply an operator-configured Nexus storage budget to component-level caps.
    ///
    /// When the aggregate budget is omitted, `irohad` derives a filesystem-aware budget at
    /// runtime and applies it with [`Self::apply_derived_storage_budget`].
    pub fn apply_storage_budget(&mut self) {
        self.apply_storage_memory_budget();
        let Some(max_disk) = self.nexus.storage.local_budget_bytes.map(Bytes::get) else {
            return;
        };
        debug_assert!(max_disk > 0, "parsed storage budgets are non-zero");
        self.nexus.storage.effective_local_budget_bytes = Some(Bytes(max_disk));
        let derived_caps = derive_global_nexus_storage_component_caps(
            max_disk,
            self.nexus.storage.disk_budget_weights,
        );
        self.apply_storage_component_caps(derived_caps);
    }
    /// Apply a runtime-derived, filesystem-aware Nexus storage budget.
    ///
    /// `irohad` computes these groups from live storage roots without persisting them back to the
    /// operator configuration. The effective aggregate is recomputed from the groups here so a
    /// caller cannot supply inconsistent aggregate metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the group list is empty or its checked aggregate exceeds `u64`.
    pub fn apply_derived_storage_budget(
        &mut self,
        filesystem_budgets: &[NexusStorageFilesystemBudget],
    ) -> core::result::Result<NonZeroU64, NexusStorageBudgetApplicationError> {
        validate_filesystem_storage_budgets(
            filesystem_budgets,
            self.nexus.storage.disk_budget_weights,
        )?;
        let aggregate_budget_bytes =
            filesystem_budgets
                .iter()
                .try_fold(0_u64, |aggregate, filesystem| {
                    aggregate
                        .checked_add(filesystem.budget_bytes.get())
                        .ok_or(NexusStorageBudgetApplicationError::AggregateOverflow)
                })?;
        let aggregate_budget_bytes = NonZeroU64::new(aggregate_budget_bytes)
            .ok_or(NexusStorageBudgetApplicationError::NoFilesystemBudgets)?;
        self.apply_storage_memory_budget();
        self.nexus.storage.effective_local_budget_bytes = Some(Bytes(aggregate_budget_bytes.get()));
        let derived_caps = derive_filesystem_nexus_storage_component_caps(
            filesystem_budgets,
            self.nexus.storage.disk_budget_weights,
        );
        self.apply_storage_component_caps(derived_caps);
        Ok(aggregate_budget_bytes)
    }
    fn apply_storage_memory_budget(&mut self) {
        let max_wsv_mem = self.nexus.storage.max_wsv_memory_bytes.get();
        if max_wsv_mem > 0 {
            self.tiered_state.hot_retained_bytes =
                min_nonzero_bytes(self.tiered_state.hot_retained_bytes, max_wsv_mem);
            if !self.tiered_state.enabled {
                self.tiered_state.enabled = true;
            }
            if self.tiered_state.cold_store_root.is_none()
                && self.tiered_state.da_store_root.is_none()
            {
                self.tiered_state.cold_store_root = Some(PathBuf::from(
                    defaults::tiered_state::DEFAULT_COLD_STORE_ROOT,
                ));
            }
        }
    }
    fn apply_storage_component_caps(&mut self, derived_caps: NexusStorageComponentCaps) {
        let configured_caps = if let Some(caps) = self.nexus.storage.configured_component_caps {
            caps
        } else {
            let caps = NexusStorageConfiguredComponentCaps::capture(self);
            self.nexus.storage.configured_component_caps = Some(caps);
            caps
        };
        self.kura.max_disk_usage_bytes = min_nonzero_bytes(
            configured_caps.kura_max_disk_usage_bytes,
            derived_caps.kura_bytes,
        );
        self.tiered_state.max_cold_bytes = min_nonzero_bytes(
            configured_caps.wsv_cold_max_bytes,
            derived_caps.wsv_cold_bytes,
        );
        self.torii.sorafs_storage.max_capacity_bytes = min_nonzero_bytes(
            configured_caps.sorafs_max_capacity_bytes,
            derived_caps.sorafs_bytes,
        );
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NexusStorageComponentCaps {
    kura_bytes: u64,
    wsv_cold_bytes: u64,
    sorafs_bytes: u64,
}
impl NexusStorageComponentCaps {
    fn add_budget(&mut self, component: NexusStorageBudgetComponent, budget_bytes: u64) {
        let target = match component {
            NexusStorageBudgetComponent::Kura => &mut self.kura_bytes,
            NexusStorageBudgetComponent::WsvCold => &mut self.wsv_cold_bytes,
            NexusStorageBudgetComponent::Sorafs => &mut self.sorafs_bytes,
        };
        *target = target
            .checked_add(budget_bytes)
            .expect("validated storage component budgets cannot overflow");
    }
    fn budget_for(self, component: NexusStorageBudgetComponent) -> u64 {
        match component {
            NexusStorageBudgetComponent::Kura => self.kura_bytes,
            NexusStorageBudgetComponent::WsvCold => self.wsv_cold_bytes,
            NexusStorageBudgetComponent::Sorafs => self.sorafs_bytes,
        }
    }
    fn total(self) -> u64 {
        NexusStorageBudgetComponent::ORDER
            .into_iter()
            .map(|component| self.budget_for(component))
            .try_fold(0_u64, u64::checked_add)
            .expect("proportional component shares cannot exceed their source budget")
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct NexusStorageConfiguredComponentCaps {
    kura_max_disk_usage_bytes: Bytes,
    wsv_cold_max_bytes: Bytes,
    sorafs_max_capacity_bytes: Bytes,
}
impl NexusStorageConfiguredComponentCaps {
    fn capture<G>(root: &Root<G>) -> Self {
        Self {
            kura_max_disk_usage_bytes: root.kura.max_disk_usage_bytes,
            wsv_cold_max_bytes: root.tiered_state.max_cold_bytes,
            sorafs_max_capacity_bytes: root.torii.sorafs_storage.max_capacity_bytes,
        }
    }
}
fn derive_global_nexus_storage_component_caps(
    max_disk_bytes: u64,
    weights: NexusStorageWeights,
) -> NexusStorageComponentCaps {
    let total_bps = u64::from(weights.total_bps().max(1));
    let budget = |bps: u16| proportional_budget_bytes(max_disk_bytes, bps, total_bps);
    let mut caps = NexusStorageComponentCaps {
        kura_bytes: budget(weights.kura_blocks_bps),
        wsv_cold_bytes: budget(weights.wsv_snapshots_bps),
        sorafs_bytes: budget(weights.sorafs_bps),
    };
    let allocated = caps.total();
    caps.add_budget(
        NexusStorageBudgetComponent::Kura,
        max_disk_bytes
            .checked_sub(allocated)
            .expect("proportional component shares cannot exceed the source budget"),
    );
    caps
}
fn proportional_budget_bytes(total_bytes: u64, weight: u16, total_weight: u64) -> u64 {
    if total_weight == 0 {
        return 0;
    }
    let share = u128::from(total_bytes) * u128::from(weight) / u128::from(total_weight);
    u64::try_from(share).expect("a proportional share cannot exceed its u64 source budget")
}
fn derive_filesystem_nexus_storage_component_caps(
    filesystem_budgets: &[NexusStorageFilesystemBudget],
    weights: NexusStorageWeights,
) -> NexusStorageComponentCaps {
    let mut caps = NexusStorageComponentCaps::default();
    for filesystem_group in filesystem_budgets {
        let group_caps = split_filesystem_budget_across_components(
            filesystem_group.budget_bytes.get(),
            &filesystem_group.components,
            weights,
        );
        for component in NexusStorageBudgetComponent::ORDER {
            caps.add_budget(component, group_caps.budget_for(component));
        }
    }
    caps
}
fn split_filesystem_budget_across_components(
    budget_bytes: u64,
    components: &[NexusStorageBudgetComponent],
    weights: NexusStorageWeights,
) -> NexusStorageComponentCaps {
    let mut caps = NexusStorageComponentCaps::default();
    let total_bps: u64 = components
        .iter()
        .map(|component| u64::from(component.weight_bps(weights)))
        .sum();
    let divisor = total_bps.max(1);
    let mut allocated = 0_u64;
    for component in components {
        let budget =
            proportional_budget_bytes(budget_bytes, component.weight_bps(weights), divisor);
        caps.add_budget(*component, budget);
        allocated = allocated
            .checked_add(budget)
            .expect("proportional component shares cannot exceed their source budget");
    }
    let remainder = budget_bytes
        .checked_sub(allocated)
        .expect("proportional component shares cannot exceed their source budget");
    if remainder == 0 {
        return caps;
    }
    if let Some(first_component) = NexusStorageBudgetComponent::ORDER
        .into_iter()
        .find(|component| components.contains(component))
    {
        caps.add_budget(first_component, remainder);
    }
    caps
}
fn validate_filesystem_storage_budgets(
    filesystem_budgets: &[NexusStorageFilesystemBudget],
    weights: NexusStorageWeights,
) -> core::result::Result<(), NexusStorageBudgetApplicationError> {
    if filesystem_budgets.is_empty() {
        return Err(NexusStorageBudgetApplicationError::NoFilesystemBudgets);
    }
    let mut seen_components = BTreeSet::new();
    for (group_index, filesystem_group) in filesystem_budgets.iter().enumerate() {
        if filesystem_group.components.is_empty() {
            return Err(NexusStorageBudgetApplicationError::EmptyComponentSet { group_index });
        }
        if let Some(window) = filesystem_group
            .components
            .windows(2)
            .find(|window| window[0] == window[1])
        {
            return Err(NexusStorageBudgetApplicationError::DuplicateComponent {
                component: window[0],
            });
        }
        if let Some(window) = filesystem_group
            .components
            .windows(2)
            .find(|window| window[0] > window[1])
        {
            return Err(
                NexusStorageBudgetApplicationError::NonCanonicalComponentOrder {
                    group_index,
                    previous: window[0],
                    current: window[1],
                },
            );
        }
        for component in &filesystem_group.components {
            if !seen_components.insert(*component) {
                return Err(NexusStorageBudgetApplicationError::DuplicateComponent {
                    component: *component,
                });
            }
        }
        let caps = split_filesystem_budget_across_components(
            filesystem_group.budget_bytes.get(),
            &filesystem_group.components,
            weights,
        );
        if let Some(component) = filesystem_group
            .components
            .iter()
            .copied()
            .find(|component| caps.budget_for(*component) == 0)
        {
            return Err(
                NexusStorageBudgetApplicationError::ZeroComponentAllocation {
                    group_index,
                    component,
                },
            );
        }
    }
    Ok(())
}
fn min_nonzero_bytes(current: Bytes, limit: u64) -> Bytes {
    if limit == 0 {
        return current;
    }
    let current_val = current.get();
    if current_val == 0 {
        Bytes(limit)
    } else {
        Bytes(current_val.min(limit))
    }
}
pub(crate) fn sora_lane_catalog() -> LaneCatalog {
    let lane_count = NonZeroU32::new(3).expect("three lanes are non-zero");
    // LaneCatalog requires one visibility per dataspace; universal lanes must be public.
    let lanes = vec![
        LaneConfigMetadata {
            id: LaneId::new(0),
            shard_id: None,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "core".to_string(),
            description: Some("Primary execution lane".to_string()),
            visibility: LaneVisibility::Public,
            lane_type: Some("default_public".to_string()),
            governance: None,
            settlement: None,
            storage: LaneStorageProfile::FullReplica,
            proof_scheme: DaProofScheme::default(),
            manifest_policy: DaManifestPolicy::default(),
            confidential_compute: None,
            scheduler: None,
            settlement_buffer: None,
            metadata: BTreeMap::new(),
        },
        LaneConfigMetadata {
            id: LaneId::new(1),
            shard_id: None,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "governance".to_string(),
            description: Some("Governance & parliament traffic".to_string()),
            visibility: LaneVisibility::Public,
            lane_type: Some("governance".to_string()),
            governance: None,
            settlement: None,
            storage: LaneStorageProfile::FullReplica,
            proof_scheme: DaProofScheme::default(),
            manifest_policy: DaManifestPolicy::default(),
            confidential_compute: None,
            scheduler: None,
            settlement_buffer: None,
            metadata: BTreeMap::new(),
        },
        LaneConfigMetadata {
            id: LaneId::new(2),
            shard_id: None,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "zk".to_string(),
            description: Some("Zero-knowledge attachments".to_string()),
            visibility: LaneVisibility::Public,
            lane_type: Some("attachments".to_string()),
            governance: None,
            settlement: None,
            storage: LaneStorageProfile::FullReplica,
            proof_scheme: DaProofScheme::default(),
            manifest_policy: DaManifestPolicy::default(),
            confidential_compute: None,
            scheduler: None,
            settlement_buffer: None,
            metadata: BTreeMap::new(),
        },
    ];
    LaneCatalog::new(lane_count, lanes).expect("static Sora lane catalog is valid")
}
pub(crate) fn sora_dataspace_catalog() -> DataSpaceCatalog {
    let entries = vec![DataSpaceMetadata {
        id: DataSpaceId::UNIVERSAL,
        alias: defaults::nexus::DEFAULT_DATASPACE_ALIAS.to_string(),
        description: Some(
            "Shared public data space for core, governance, and zero-knowledge lanes".to_string(),
        ),
        fault_tolerance: defaults::nexus::dataspace::FAULT_TOLERANCE,
    }];
    DataSpaceCatalog::new(entries).expect("static Sora dataspace catalog is valid")
}
pub(crate) fn sora_routing_policy() -> LaneRoutingPolicy {
    LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![
            LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("governance".to_string()),
                    description: Some(
                        "Route governance instructions to the governance lane in the universal data space"
                            .to_string(),
                    ),
                },
            },
            LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("smartcontract::deploy".to_string()),
                    description: Some(
                        "Route contract deployments to the zk lane in the universal data space"
                            .to_string(),
                    ),
                },
            },
        ],
    }
}
/// Common options shared between multiple components.
#[derive(Debug, Clone)]
pub struct Common {
    /// Unique chain identifier.
    pub chain: ChainId,
    /// Key pair for signing transactions and blocks.
    pub key_pair: KeyPair,
    /// Dedicated Ed25519 key pair for the SoraNet transport handshake.
    pub soranet_transport_key_pair: KeyPair,
    /// Local peer description.
    pub peer: Peer,
    /// Trusted peers including self.
    pub trusted_peers: WithOrigin<TrustedPeers>,
    /// I105 chain discriminant / network prefix applied when encoding addresses.
    pub chain_discriminant: WithOrigin<u16>,
}
/// Intrinsic dispatch policy applied to SM acceleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmIntrinsicsPolicy {
    /// Runtime decides at startup based on hardware support (default).
    Auto,
    /// Intrinsics forced on by configuration.
    ForceEnable,
    /// Intrinsics forcibly disabled by configuration.
    ForceDisable,
}
impl SmIntrinsicsPolicy {
    /// Returns the string identifier used in configuration files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ForceEnable => "force-enable",
            Self::ForceDisable => "force-disable",
        }
    }
}
/// Cryptography defaults surfaced via configuration.
#[derive(Debug, Clone)]
pub struct Crypto {
    /// Toggle for optional OpenSSL SM3/SM4 helpers; SM2 uses its canonical portable verifier.
    pub enable_sm_openssl_preview: bool,
    /// Intrinsic dispatch policy applied to SM acceleration.
    pub sm_intrinsics: SmIntrinsicsPolicy,
    /// Default hash algorithm identifier (e.g., `blake2b-256`, `sm3-256`).
    pub default_hash: String,
    /// Signing algorithms allowed for transaction admission.
    pub allowed_signing: Vec<Algorithm>,
    /// Default distinguishing identifier applied when SM2 signatures omit it.
    pub sm2_distid_default: String,
    /// Curve identifiers (per the account curve registry) allowed for controllers.
    pub allowed_curve_ids: Vec<u8>,
}
impl_default!(Crypto => {
        Self {
            enable_sm_openssl_preview: defaults::crypto::enable_sm_openssl_preview(),
            sm_intrinsics: SmIntrinsicsPolicy::Auto,
            default_hash: defaults::crypto::default_hash(),
            allowed_signing: defaults::crypto::allowed_signing(),
            sm2_distid_default: defaults::crypto::sm2_distid_default(),
            allowed_curve_ids: defaults::crypto::allowed_curve_ids(),
        }
});
impl Crypto {
    /// Determine whether SM helper syscalls should be enabled for this configuration.
    #[must_use]
    pub fn sm_helpers_enabled(&self) -> bool {
        #[cfg(feature = "sm")]
        {
            self.allowed_signing
                .iter()
                .any(|algo| matches!(algo, Algorithm::Sm2))
        }
        #[cfg(not(feature = "sm"))]
        {
            let _ = self;
            false
        }
    }
}
/// Parsed SoraNet handshake configuration.
#[derive(Clone)]
pub struct SoranetHandshake {
    /// Descriptor commitment advertised by the node (32 bytes).
    pub descriptor_commit: WithOrigin<Vec<u8>>,
    /// Client capability TLVs serialized into bytes.
    pub client_capabilities: WithOrigin<Vec<u8>>,
    /// Relay capability TLVs serialized into bytes.
    pub relay_capabilities: WithOrigin<Vec<u8>>,
    /// Whether this node supports trust gossip exchange.
    pub trust_gossip: bool,
    /// Negotiated ML-KEM identifier.
    pub kem_id: u8,
    /// Negotiated signature suite identifier.
    pub sig_id: u8,
    /// Optional resume hash advertised to peers.
    pub resume_hash: Option<WithOrigin<Vec<u8>>>,
    /// PoW parameters for circuit admission.
    pub pow: SoranetPow,
}
/// Runtime knobs controlling the SoraNet privacy telemetry pipeline.
#[derive(Debug, Clone, Copy)]
pub struct SoranetPrivacy {
    /// Duration of each telemetry bucket in seconds.
    pub bucket_secs: u64,
    /// Minimum number of contributing handshakes required before publishing a bucket.
    pub min_handshakes: u64,
    /// Number of buckets to delay publication after the first contributor arrives.
    pub flush_delay_buckets: u64,
    /// Forced flush interval expressed in buckets.
    pub force_flush_buckets: u64,
    /// Per-queue cap for completed, open-event, and incomplete-share buckets.
    pub max_completed_buckets: usize,
    /// Maximum bucket lag tolerated for collector shares before suppression.
    pub max_share_lag_buckets: u64,
    /// Expected number of collector shares contributing to a bucket.
    pub expected_shares: u16,
    /// Capacity for the in-memory event buffer feeding the aggregator.
    pub event_buffer_capacity: usize,
}
impl SoranetPrivacy {
    /// First-release upper bound for flush and collector-retention windows.
    pub const MAX_BUCKET_WINDOW_V1: u64 = 256;
    /// First-release upper bound for each in-memory privacy bucket queue.
    pub const MAX_BUCKET_BACKLOG_V1: usize = 256;
    /// First-release upper bound for collectors contributing to one bucket.
    pub const MAX_EXPECTED_SHARES_V1: u16 = 16;
    /// First-release upper bound for the relay privacy event queue.
    pub const MAX_EVENT_BUFFER_CAPACITY_V1: usize = 16_384;
    /// Default telemetry bucket width in seconds.
    pub const DEFAULT_BUCKET_SECS: u64 = defaults::soranet::privacy::BUCKET_SECS;
    /// Default minimum handshake contributors required before publishing.
    pub const DEFAULT_MIN_HANDSHAKES: u64 = defaults::soranet::privacy::MIN_HANDSHAKES;
    /// Default bucket delay before attempting a standard flush.
    pub const DEFAULT_FLUSH_DELAY_BUCKETS: u64 = defaults::soranet::privacy::FLUSH_DELAY_BUCKETS;
    /// Default forced flush interval expressed in buckets.
    pub const DEFAULT_FORCE_FLUSH_BUCKETS: u64 = defaults::soranet::privacy::FORCE_FLUSH_BUCKETS;
    /// Default per-queue bucket capacity.
    pub const DEFAULT_MAX_COMPLETED_BUCKETS: usize =
        defaults::soranet::privacy::MAX_COMPLETED_BUCKETS;
    /// Default maximum bucket lag tolerated for collector shares before suppression.
    pub const DEFAULT_MAX_SHARE_LAG_BUCKETS: u64 =
        defaults::soranet::privacy::MAX_SHARE_LAG_BUCKETS;
    /// Default expected PRIO share count.
    pub const DEFAULT_EXPECTED_SHARES: u16 = defaults::soranet::privacy::EXPECTED_SHARES;
    /// Default capacity of the in-memory privacy event buffer.
    pub const DEFAULT_EVENT_BUFFER_CAPACITY: usize =
        defaults::soranet::privacy::EVENT_BUFFER_CAPACITY;
}
impl_default!(SoranetPrivacy => {
        Self {
            bucket_secs: defaults::soranet::privacy::BUCKET_SECS,
            min_handshakes: defaults::soranet::privacy::MIN_HANDSHAKES,
            flush_delay_buckets: defaults::soranet::privacy::FLUSH_DELAY_BUCKETS,
            force_flush_buckets: defaults::soranet::privacy::FORCE_FLUSH_BUCKETS,
            max_completed_buckets: defaults::soranet::privacy::MAX_COMPLETED_BUCKETS,
            max_share_lag_buckets: defaults::soranet::privacy::MAX_SHARE_LAG_BUCKETS,
            expected_shares: defaults::soranet::privacy::EXPECTED_SHARES,
            event_buffer_capacity: defaults::soranet::privacy::EVENT_BUFFER_CAPACITY,
        }
});
/// Derived VPN configuration for the native SoraNet tunnel.
#[derive(Clone)]
pub struct SoranetVpn {
    /// Whether the VPN surface is enabled.
    pub enabled: bool,
    /// Fixed cell size (bytes).
    pub cell_size_bytes: u16,
    /// Flow label width (bits).
    pub flow_label_bits: u8,
    /// Cover-to-data ratio (permille).
    pub cover_to_data_per_mille: u16,
    /// Maximum burst of consecutive cover cells.
    pub max_cover_burst: u16,
    /// Heartbeat cadence for keepalive cells (milliseconds).
    pub heartbeat_ms: u16,
    /// Maximum jitter applied to scheduled slots (milliseconds).
    pub jitter_ms: u16,
    /// Padding budget carried in cell headers (milliseconds).
    pub padding_budget_ms: u16,
    /// Guard/exit refresh cadence.
    pub guard_refresh: Duration,
    /// Control-plane lease duration.
    pub lease: Duration,
    /// DNS push interval.
    pub dns_push_interval: Duration,
    /// Exit class label used for billing/telemetry.
    pub exit_class: String,
    /// Meter family identifier for billing receipts.
    pub meter_family: String,
    /// Relay operator account eligible for receipt settlement.
    pub operator_account_id: AccountId,
    /// Dedicated Ed25519 signer for VPN quotes and helper tickets.
    pub operator_key_pair: Option<KeyPair>,
    /// Fixed prepaid XOR lease fee.
    pub lease_fee: Quantity,
    /// Grace window after disconnect before unearned escrow can be refunded.
    pub settlement_grace: Duration,
    /// Routes pushed to VPN clients.
    pub route_pushes: Vec<String>,
    /// Routes explicitly excluded from the VPN tunnel.
    pub excluded_routes: Vec<String>,
    /// DNS servers pushed to VPN clients.
    pub dns_servers: Vec<String>,
    /// Relay Ed25519 identity selected from the authenticated guard directory.
    pub relay_id: Option<[u8; 32]>,
    /// Path to the exact Norito guard-directory snapshot used for VPN trust.
    pub guard_directory_path: Option<PathBuf>,
    /// Externally provisioned digest authenticating the exact snapshot bytes.
    pub guard_directory_digest: Option<[u8; 32]>,
}
struct RedactedVpnOperatorSigner(bool);
impl fmt::Debug for RedactedVpnOperatorSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.0 { "Some([REDACTED])" } else { "None" })
    }
}
impl fmt::Debug for SoranetVpn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoranetVpn")
            .field("enabled", &self.enabled)
            .field("cell_size_bytes", &self.cell_size_bytes)
            .field("flow_label_bits", &self.flow_label_bits)
            .field("cover_to_data_per_mille", &self.cover_to_data_per_mille)
            .field("max_cover_burst", &self.max_cover_burst)
            .field("heartbeat_ms", &self.heartbeat_ms)
            .field("jitter_ms", &self.jitter_ms)
            .field("padding_budget_ms", &self.padding_budget_ms)
            .field("guard_refresh", &self.guard_refresh)
            .field("lease", &self.lease)
            .field("dns_push_interval", &self.dns_push_interval)
            .field("exit_class", &self.exit_class)
            .field("meter_family", &self.meter_family)
            .field("operator_account_id", &self.operator_account_id)
            .field(
                "operator_signer",
                &RedactedVpnOperatorSigner(self.operator_key_pair.is_some()),
            )
            .field("lease_fee", &self.lease_fee)
            .field("settlement_grace", &self.settlement_grace)
            .field("route_pushes", &self.route_pushes)
            .field("excluded_routes", &self.excluded_routes)
            .field("dns_servers", &self.dns_servers)
            .field("relay_id", &self.relay_id)
            .field("guard_directory_path", &self.guard_directory_path)
            .field("guard_directory_digest", &self.guard_directory_digest)
            .finish()
    }
}
impl_default!(SoranetVpn => {
        Self {
            enabled: defaults::soranet::vpn::ENABLED,
            cell_size_bytes: defaults::soranet::vpn::CELL_SIZE_BYTES,
            flow_label_bits: defaults::soranet::vpn::FLOW_LABEL_BITS,
            cover_to_data_per_mille: defaults::soranet::vpn::COVER_TO_DATA_PER_MILLE,
            max_cover_burst: defaults::soranet::vpn::MAX_COVER_BURST,
            heartbeat_ms: defaults::soranet::vpn::HEARTBEAT_MS,
            jitter_ms: defaults::soranet::vpn::JITTER_MS,
            padding_budget_ms: defaults::soranet::vpn::PADDING_BUDGET_MS,
            guard_refresh: defaults::soranet::vpn::guard_refresh_secs(),
            lease: defaults::soranet::vpn::lease_secs(),
            dns_push_interval: defaults::soranet::vpn::dns_push_interval_secs(),
            exit_class: defaults::soranet::vpn::EXIT_CLASS.to_string(),
            meter_family: defaults::soranet::vpn::METER_FAMILY.to_string(),
            operator_account_id: AccountId::parse_encoded(
                &defaults::soranet::vpn::operator_account_id(),
            )
            .expect("default vpn operator account id"),
            operator_key_pair: None,
            lease_fee: defaults::soranet::vpn::lease_fee(),
            settlement_grace: Duration::from_secs(defaults::soranet::vpn::SETTLEMENT_GRACE_SECS),
            route_pushes: defaults::soranet::vpn::route_pushes(),
            excluded_routes: defaults::soranet::vpn::excluded_routes(),
            dns_servers: defaults::soranet::vpn::dns_servers(),
            relay_id: None,
            guard_directory_path: None,
            guard_directory_digest: None,
        }
});
/// Mandatory Argon2 admission parameters shared with peers.
#[derive(Debug, Clone)]
pub struct SoranetPow {
    /// Required number of leading zero bits in the ticket digest.
    pub difficulty: u8,
    /// Maximum allowed ticket expiry skew relative to the relay clock.
    pub max_future_skew: Duration,
    /// Minimum lifetime a ticket must remain valid.
    pub min_ticket_ttl: Duration,
    /// Target lifetime used when minting tickets locally.
    pub ticket_ttl: Duration,
    /// Maximum concurrent local Argon2 ticket mints.
    pub outbound_mint_capacity: NonZeroUsize,
    /// Maximum concurrent remote Argon2 ticket verifications.
    ///
    /// At most `(outbound_mint_capacity + inbound_verify_capacity) * memory_kib`
    /// KiB is owned by active puzzle jobs in a production process.
    pub inbound_verify_capacity: NonZeroUsize,
    /// Maximum revoked ticket entries to retain on disk.
    pub revocation_store_capacity: usize,
    /// Maximum TTL enforced for revoked entries.
    pub revocation_max_ttl: Duration,
    /// Filesystem path for the revocation snapshot.
    pub revocation_store_path: Cow<'static, str>,
    /// Puzzle parameters for mandatory Argon2-based challenges.
    pub puzzle: SoranetPuzzle,
}
/// Argon2 puzzle parameters shared with peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoranetPuzzle {
    /// Memory cost expressed in kibibytes.
    pub memory_kib: NonZeroU32,
    /// Time cost (number of iterations).
    pub time_cost: NonZeroU32,
    /// Argon2 parallelism lanes.
    pub lanes: NonZeroU32,
}
impl SoranetPuzzle {
    /// Construct a puzzle with explicit parameters.
    pub const fn new(memory_kib: NonZeroU32, time_cost: NonZeroU32, lanes: NonZeroU32) -> Self {
        Self {
            memory_kib,
            time_cost,
            lanes,
        }
    }
    /// Default Argon2 puzzle used for handshake PoW challenges.
    pub const fn default_const() -> Self {
        Self {
            memory_kib: NonZeroU32::new(64 * 1024).unwrap(),
            time_cost: NonZeroU32::new(2).unwrap(),
            lanes: NonZeroU32::new(1).unwrap(),
        }
    }
}
impl_default!(SoranetPuzzle => {
        Self::default_const()
});
impl SoranetPow {
    /// Hard ceiling for either direction's puzzle-work capacity.
    pub const MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION: usize = 8;
    /// Default capacity in each direction.
    ///
    /// Three concurrent jobs let every peer in the canonical four-validator
    /// committee authenticate directly without serializing topology formation.
    pub const DEFAULT_PUZZLE_WORK_CAPACITY_PER_DIRECTION: NonZeroUsize =
        NonZeroUsize::new(3).unwrap();
    /// Construct a PoW policy with explicit parameters.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        difficulty: u8,
        max_future_skew: Duration,
        min_ticket_ttl: Duration,
        ticket_ttl: Duration,
        revocation_store_capacity: usize,
        revocation_max_ttl: Duration,
        revocation_store_path: Cow<'static, str>,
        puzzle: SoranetPuzzle,
    ) -> Self {
        Self {
            difficulty,
            max_future_skew,
            min_ticket_ttl,
            ticket_ttl,
            outbound_mint_capacity: Self::DEFAULT_PUZZLE_WORK_CAPACITY_PER_DIRECTION,
            inbound_verify_capacity: Self::DEFAULT_PUZZLE_WORK_CAPACITY_PER_DIRECTION,
            revocation_store_capacity,
            revocation_max_ttl,
            revocation_store_path,
            puzzle,
        }
    }
    /// Default admission policy applied when no override is supplied.
    pub const fn default_const() -> Self {
        Self {
            difficulty: iroha_crypto::soranet::puzzle::DEFAULT_DIFFICULTY,
            max_future_skew: Duration::from_secs(300),
            min_ticket_ttl: Duration::from_secs(30),
            ticket_ttl: Duration::from_secs(300),
            outbound_mint_capacity: Self::DEFAULT_PUZZLE_WORK_CAPACITY_PER_DIRECTION,
            inbound_verify_capacity: Self::DEFAULT_PUZZLE_WORK_CAPACITY_PER_DIRECTION,
            revocation_store_capacity: 8_192,
            revocation_max_ttl: Duration::from_secs(900),
            revocation_store_path: Cow::Borrowed("./storage/soranet/ticket_revocations.norito"),
            puzzle: SoranetPuzzle::default_const(),
        }
    }
}
impl_default!(SoranetPow => {
        Self::default_const()
});
impl_default!(SoranetHandshake => {
        Self {
            descriptor_commit: WithOrigin::inline(DEFAULT_DESCRIPTOR_COMMIT.to_vec()),
            client_capabilities: WithOrigin::inline(DEFAULT_CLIENT_CAPABILITIES.to_vec()),
            relay_capabilities: WithOrigin::inline(DEFAULT_RELAY_CAPABILITIES.to_vec()),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            pow: SoranetPow::default(),
        }
});
/// Lane profile presets for shaping p2p behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneProfile {
    /// Datacenter/validator profile with generous defaults.
    Core,
    /// Constrained/home profile with tighter caps.
    Home,
}
impl LaneProfile {
    /// Resolve an exact first-release profile label into a typed variant.
    #[must_use]
    pub fn parse_label(label: &str) -> Option<Self> {
        match label {
            "core" => Some(Self::Core),
            "home" => Some(Self::Home),
            _ => None,
        }
    }
    /// Return the baked-in defaults for the profile.
    #[must_use]
    pub fn defaults(self) -> LaneProfileDefaults {
        match self {
            Self::Core => LaneProfileDefaults {
                tick_ms: defaults::network::lane_profile::CORE_TICK_MS,
                mtu_bytes: defaults::network::lane_profile::CORE_MTU_BYTES,
                uplink_bps: defaults::network::lane_profile::CORE_UPLINK_BPS,
                constant_neighbors: defaults::network::lane_profile::CORE_CONSTANT_NEIGHBORS,
                max_total_connections: defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
                max_incoming: defaults::network::lane_profile::CORE_MAX_INCOMING,
            },
            Self::Home => LaneProfileDefaults {
                tick_ms: defaults::network::lane_profile::HOME_TICK_MS,
                mtu_bytes: defaults::network::lane_profile::HOME_MTU_BYTES,
                uplink_bps: defaults::network::lane_profile::HOME_UPLINK_BPS,
                constant_neighbors: defaults::network::lane_profile::HOME_CONSTANT_NEIGHBORS,
                max_total_connections: defaults::network::lane_profile::HOME_MAX_TOTAL_CONNECTIONS,
                max_incoming: defaults::network::lane_profile::HOME_MAX_INCOMING,
            },
        }
    }
    /// Render the canonical profile label.
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Home => "home",
        }
    }
    /// Derived shaping limits for the profile (caps applied only when present).
    #[must_use]
    pub fn derived_limits(self) -> LaneProfileLimits {
        match self {
            Self::Core => LaneProfileLimits {
                max_incoming: None,
                max_total_connections: None,
                low_priority_bytes_per_sec: None,
                low_priority_rate_per_sec: None,
            },
            Self::Home => {
                let defaults = self.defaults();
                let per_peer_bytes = defaults.per_peer_bytes_per_sec();
                let per_packet = defaults.mtu_payload_bytes();
                let rate = u64::from(per_peer_bytes).div_ceil(per_packet);
                let capped_rate = rate.clamp(1, u64::from(u32::MAX));
                LaneProfileLimits {
                    max_incoming: NonZeroUsize::new(defaults.max_incoming),
                    max_total_connections: NonZeroUsize::new(defaults.max_total_connections),
                    low_priority_bytes_per_sec: NonZeroU32::new(per_peer_bytes),
                    low_priority_rate_per_sec: NonZeroU32::new(
                        u32::try_from(capped_rate).expect("clamped to u32 range"),
                    ),
                }
            }
        }
    }
}
/// Resolved constants for a lane profile.
#[derive(Debug, Clone, Copy)]
pub struct LaneProfileDefaults {
    /// Scheduling tick used for shaping calculations.
    pub tick_ms: u16,
    /// MTU (bytes) assumed when computing message cadence.
    pub mtu_bytes: u16,
    /// Target uplink budget (bits per second).
    pub uplink_bps: u64,
    /// Constant-rate neighbor budget.
    pub constant_neighbors: usize,
    /// Soft cap for total connections.
    pub max_total_connections: usize,
    /// Soft cap for inbound connections.
    pub max_incoming: usize,
}
impl LaneProfileDefaults {
    /// Compute the per-peer byte budget per second based on the uplink split.
    #[must_use]
    pub fn per_peer_bytes_per_sec(self) -> u32 {
        let peers = u64::try_from(self.constant_neighbors.max(1)).expect("peer count fits in u64");
        let bytes = self.uplink_bps.saturating_div(8).saturating_div(peers);
        let capped_bytes = bytes.clamp(1, u64::from(u32::MAX));
        u32::try_from(capped_bytes).expect("clamped to u32 range")
    }
    /// Conservative payload size (bytes) after accounting for headers.
    #[must_use]
    pub fn mtu_payload_bytes(self) -> u64 {
        // Leave ~80 bytes for IP/UDP/TCP headers and crypto framing.
        u64::from(self.mtu_bytes.saturating_sub(80).max(512))
    }
}
/// Derived lane profile caps applied to networking defaults.
#[derive(Debug, Clone, Copy)]
pub struct LaneProfileLimits {
    /// Optional cap on inbound connections.
    pub max_incoming: Option<NonZeroUsize>,
    /// Optional cap on total connections.
    pub max_total_connections: Option<NonZeroUsize>,
    /// Optional per-peer low-priority byte budget.
    pub low_priority_bytes_per_sec: Option<NonZeroU32>,
    /// Optional per-peer low-priority message rate.
    pub low_priority_rate_per_sec: Option<NonZeroU32>,
}
/// Network options.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Network {
    /// Listening socket address.
    pub address: WithOrigin<SocketAddr>,
    /// Publicly advertised socket address.
    pub public_address: WithOrigin<SocketAddr>,
    /// Relay role (disabled/hub/spoke/assist) for constrained topologies.
    pub relay_mode: RelayMode,
    /// Relay hub addresses to dial when in `spoke` or `assist` mode.
    ///
    /// When multiple hubs are supplied, the node may pick one that is reachable
    /// and fall back to others if connectivity changes.
    pub relay_hub_addresses: Vec<SocketAddr>,
    /// Hop limit for relayed frames.
    pub relay_ttl: u8,
    /// SoraNet handshake capabilities to advertise.
    pub soranet_handshake: SoranetHandshake,
    /// Privacy telemetry configuration advertised to collectors.
    pub soranet_privacy: SoranetPrivacy,
    /// VPN tunnel configuration for the native SoraNet bridge.
    pub soranet_vpn: SoranetVpn,
    /// Lane profile preset controlling connection and throttle defaults.
    pub lane_profile: LaneProfile,
    /// Whether peers must match SM helper availability during handshake.
    pub require_sm_handshake_match: bool,
    /// Whether peers must match the OpenSSL preview toggle during handshake.
    pub require_sm_openssl_preview_match: bool,
    /// Idle connection timeout.
    pub idle_timeout: Duration,
    /// Maximum total tenure for an accepted transport to authenticate.
    pub preauth_timeout: Duration,
    /// Maximum concurrent pre-authentication transports admitted from one source IP.
    pub preauth_max_connections_per_ip: NonZeroUsize,
    /// Base deadline for an exact reply to await one peer writer's full flush.
    pub reply_writer_flush_timeout: Duration,
    /// Delay outbound peer dials after startup.
    pub connect_startup_delay: Duration,
    /// Timeout applied to an individual outbound dial attempt (TCP/TLS/QUIC/WS).
    pub dial_timeout: Duration,
    /// Maximum age for deferred outbound frames queued while the peer session is missing.
    pub deferred_send_ttl: Duration,
    /// Maximum deferred outbound frames retained per peer while session is missing.
    pub deferred_send_max_per_peer: usize,
    /// Maximum stream-wire bytes retained per peer by deferred outbound frames.
    pub deferred_send_max_bytes_per_peer: usize,
    /// Maximum stream-wire bytes retained across every deferred outbound peer queue.
    pub deferred_send_max_bytes_total: usize,
    /// Interval between peer gossip batches.
    pub peer_gossip_period: Duration,
    /// Maximum interval between peer gossip batches (idle backoff ceiling).
    pub peer_gossip_max_period: Duration,
    /// Whether to advertise and accept signed trust gossip frames.
    pub trust_gossip: bool,
    /// Half-life for peer trust decay (toward zero).
    pub trust_decay_half_life: Duration,
    /// Penalty applied for invalid/bad trust gossip.
    pub trust_penalty_bad_gossip: i32,
    /// Penalty applied when gossip mentions unknown/invalid peers.
    pub trust_penalty_unknown_peer: i32,
    /// Minimum score before trust gossip is ignored.
    pub trust_min_score: i32,
    /// Optional DNS hostname refresh interval (None disables).
    pub dns_refresh_interval: Option<Duration>,
    /// Optional TTL-based refresh for hostname-based peers.
    pub dns_refresh_ttl: Option<Duration>,
    /// Optional outbound proxy URL for TCP-based dials (e.g., `http://user:pass@host:port`,
    /// `https://host:port`, `socks5://user:pass@host:port`, or `socks5h://host:port`).
    ///
    /// The mandatory P2P TLS stack also wraps `https://` proxy hops in pinned TLS.
    pub p2p_proxy: Option<String>,
    /// Require that outbound TCP-based dials use `p2p_proxy`.
    ///
    /// Note: QUIC bypasses the proxy; set `quic_enabled=false` when requiring a proxy.
    pub p2p_proxy_required: bool,
    /// Proxy bypass list (suffix match, similar to `NO_PROXY` semantics).
    ///
    /// Note: this list must be empty when `p2p_proxy_required=true`.
    pub p2p_no_proxy: Vec<String>,
    /// CIDR ranges that outbound peer and proxy dials may resolve to.
    ///
    /// An empty list leaves IP ranges unrestricted. Deny entries take precedence.
    pub outbound_dial_allow_cidrs: Vec<String>,
    /// CIDR ranges that outbound peer and proxy dials must never reach.
    pub outbound_dial_deny_cidrs: Vec<String>,
    /// DNS suffixes allowed for outbound peer and proxy dials.
    ///
    /// An empty list leaves DNS names unrestricted. Matching is at DNS label boundaries.
    pub outbound_dial_allow_dns_suffixes: Vec<String>,
    /// DNS suffixes denied for outbound peer and proxy dials.
    pub outbound_dial_deny_dns_suffixes: Vec<String>,
    /// Whether to verify an `https://` proxy hop.
    ///
    /// HTTPS proxy dials require this to remain enabled and require an exact leaf-certificate
    /// pin in `p2p_proxy_tls_pinned_cert_der_base64`; invalid settings fail before connecting.
    pub p2p_proxy_tls_verify: bool,
    /// Optional pinned end-entity certificate for `https://` proxies (DER, base64).
    ///
    /// Every HTTPS proxy dial pins the proxy leaf certificate to this value.
    pub p2p_proxy_tls_pinned_cert_der_base64: Option<String>,
    /// Request QUIC transport (feature-gated).
    ///
    /// Runtime startup rejects `true` before binding pending transport requalification
    /// with locked `quinn 0.11.12` / `quinn-proto 0.11.18`. TLS-over-TCP remains available.
    pub quic_enabled: bool,
    /// Request QUIC DATAGRAM support for best-effort topics (gossip/health).
    ///
    /// Runtime startup rejects `true` until quinn-proto 0.11.18 or later is
    /// locked and requalified. The disabled path uses reliable streams.
    pub quic_datagrams_enabled: bool,
    /// Upper bound (bytes) for QUIC datagram payloads.
    pub quic_datagram_max_payload_bytes: usize,
    /// Receive buffer reserved for QUIC datagrams per active QUIC connection (bytes).
    pub quic_datagram_receive_buffer_bytes: usize,
    /// Send buffer reserved for QUIC datagrams per active QUIC connection (bytes).
    pub quic_datagram_send_buffer_bytes: usize,
    /// Capacity for the high-priority network message queue and inbound peer dispatch buffer
    /// (bounded mode only).
    pub p2p_queue_cap_high: NonZeroUsize,
    /// Capacity for the low-priority network message queue and inbound peer dispatch buffer
    /// (bounded mode only).
    pub p2p_queue_cap_low: NonZeroUsize,
    /// Capacity for the per-peer post queue (bounded mode only).
    pub p2p_post_queue_cap: NonZeroUsize,
    /// Maximum high-priority stream wire bytes (prefix plus AEAD body) retained by each
    /// connected sender queue and by the process-wide connected-post owner, and the
    /// ordinary-high actor byte subcap. Inbound readers mirror the value as separate
    /// process-wide source and alignment-scratch pools and decrypt inside the source allocation.
    /// The actor adds disjoint maximum safety and route-qualified semantic-progress frame
    /// charges; each authenticated peer separately gets one such progress charge, bounded by
    /// `max_total_connections` and shared by replacement sessions.
    pub p2p_outbound_frame_queue_max_high_bytes: NonZeroUsize,
    /// Maximum low-priority stream wire bytes retained by each connected sender queue and by
    /// the process-wide connected-post owner, including frame prefixes. Inbound readers mirror
    /// the value as separate process-wide source and alignment-scratch pools.
    pub p2p_outbound_frame_queue_max_low_bytes: NonZeroUsize,
    /// Maximum encrypted high-priority outbound frames retained per peer.
    pub p2p_outbound_frame_queue_max_high_frames: NonZeroUsize,
    /// Maximum encrypted low-priority outbound frames retained per peer.
    pub p2p_outbound_frame_queue_max_low_frames: NonZeroUsize,
    /// Capacity for the inbound P2P subscriber queue feeding the node relay.
    pub p2p_subscriber_queue_cap: NonZeroUsize,
    /// Optional per-peer consensus ingress rate (msgs/sec). When None, ingress limiting is disabled.
    pub consensus_ingress_rate_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst for consensus ingress rate limiting. Defaults to `rate` when None.
    pub consensus_ingress_burst: Option<std::num::NonZeroU32>,
    /// Optional per-peer consensus ingress bytes/sec budget. When None, bytes limiting is disabled.
    pub consensus_ingress_bytes_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst (bytes) for consensus ingress bytes limiting. Defaults to `bytes_per_sec` when None.
    pub consensus_ingress_bytes_burst: Option<std::num::NonZeroU32>,
    /// Optional per-peer critical consensus ingress rate (msgs/sec). When None, critical limiting is disabled.
    pub consensus_ingress_critical_rate_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst for critical consensus ingress rate limiting. Defaults to `rate` when None.
    pub consensus_ingress_critical_burst: Option<std::num::NonZeroU32>,
    /// Optional per-peer critical consensus ingress bytes/sec budget. When None, bytes limiting is disabled.
    pub consensus_ingress_critical_bytes_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst (bytes) for critical consensus ingress bytes limiting. Defaults to `bytes_per_sec` when None.
    pub consensus_ingress_critical_bytes_burst: Option<std::num::NonZeroU32>,
    /// Drop threshold (per window) before temporarily suppressing consensus ingress.
    pub consensus_ingress_penalty_threshold: u32,
    /// Window for consensus ingress penalty tracking.
    pub consensus_ingress_penalty_window: Duration,
    /// Cooldown applied after consensus ingress penalties trigger.
    pub consensus_ingress_penalty_cooldown: Duration,
    /// Stagger between parallel dial attempts for multi-address peers.
    pub happy_eyeballs_stagger: Duration,
    /// Prefer IPv6 addresses over hostnames/IPv4 when dialing.
    pub addr_ipv6_first: bool,
    /// Maximum number of simultaneously accepted incoming connections.
    /// When `None`, incoming connections are not capped by count.
    pub max_incoming: Option<NonZeroUsize>,
    /// Maximum total number of connections (incoming + outgoing + in-flight accepts).
    /// The P2P runtime interprets `None` as the core-profile hard cap so its
    /// per-peer progress-frame assembly reserve remains process-bounded.
    pub max_total_connections: Option<NonZeroUsize>,
    /// Optional per-IP(/24 for IPv4, /64 for IPv6) accept throttle, in accepts per second.
    /// When `None`, per-IP throttling is disabled.
    pub accept_rate_per_ip_per_sec: Option<std::num::NonZeroU32>,
    /// Optional accept token-bucket burst size per IP bucket.
    /// If `None`, a conservative burst equal to `accept_rate_per_ip_per_sec` is used.
    pub accept_burst_per_ip: Option<std::num::NonZeroU32>,
    /// Maximum number of accept throttle buckets retained (prefix + per-IP).
    pub max_accept_buckets: NonZeroUsize,
    /// Idle timeout before expiring accept throttle buckets.
    pub accept_bucket_idle: Duration,
    /// Prefix length applied to IPv4 prefix buckets.
    pub accept_prefix_v4_bits: u8,
    /// Prefix length applied to IPv6 prefix buckets.
    pub accept_prefix_v6_bits: u8,
    /// Optional prefix-level accept throttle, in accepts per second.
    pub accept_rate_per_prefix_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst size for prefix-level accept limiter.
    pub accept_burst_per_prefix: Option<std::num::NonZeroU32>,
    /// Optional per-peer Low-priority message rate (msgs/sec). When None, Low-priority rate limiting is disabled.
    pub low_priority_rate_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst for Low-priority token bucket. Defaults internally to `rate` if None.
    pub low_priority_burst: Option<std::num::NonZeroU32>,
    /// Optional per-peer Low-priority bytes budget (bytes/sec). When None, disabled.
    pub low_priority_bytes_per_sec: Option<std::num::NonZeroU32>,
    /// Optional burst in bytes for Low-priority bytes token bucket.
    pub low_priority_bytes_burst: Option<std::num::NonZeroU32>,
    /// Optional: Only allow connections (outbound/inbound) to peers whose public keys are explicitly listed.
    pub allowlist_only: bool,
    /// Optional allowlist of peer public keys.
    pub allow_keys: Vec<iroha_crypto::PublicKey>,
    /// Optional denylist of peer public keys.
    pub deny_keys: Vec<iroha_crypto::PublicKey>,
    /// Optional CIDR allowlist (IPv4/IPv6), e.g., "192.168.1.0/24", "`2001:db8::/32`".
    pub allow_cidrs: Vec<String>,
    /// Optional CIDR denylist.
    pub deny_cidrs: Vec<String>,
    /// Disconnect on per-peer post overflow (bounded per-topic channels)
    pub disconnect_on_post_overflow: bool,
    /// Maximum encrypted P2P frame-body size in bytes (at most 2,147,483,643).
    pub max_frame_bytes: usize,
    /// `TCP_NODELAY` setting for TCP sockets
    pub tcp_nodelay: bool,
    /// TCP keepalive duration for sockets (if any)
    pub tcp_keepalive: Option<Duration>,
    /// Per-topic frame caps (bytes) for Consensus messages.
    pub max_frame_bytes_consensus: usize,
    /// Per-topic frame caps (bytes) for Control messages.
    pub max_frame_bytes_control: usize,
    /// Per-topic frame caps (bytes) for `BlockSync` messages.
    pub max_frame_bytes_block_sync: usize,
    /// Per-topic frame caps (bytes) for `TxGossip` messages.
    pub max_frame_bytes_tx_gossip: usize,
    /// Per-topic frame caps (bytes) for `PeerGossip` messages.
    pub max_frame_bytes_peer_gossip: usize,
    /// Per-topic frame caps (bytes) for Health messages.
    pub max_frame_bytes_health: usize,
    /// Per-topic frame cap for authenticated Connect relay traffic.
    pub max_frame_bytes_connect: usize,
    /// Per-topic frame caps (bytes) for Other messages.
    pub max_frame_bytes_other: usize,
    /// QUIC max idle timeout for stream inactivity (if QUIC is enabled).
    pub quic_max_idle_timeout: Option<Duration>,
}
/// P2P relay role for constrained deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Relay disabled; nodes connect directly to each other (default).
    Disabled,
    /// Relay hub; accept spokes and forward traffic.
    Hub,
    /// Relay spoke; dial only the hub and rely on forwarding.
    Spoke,
    /// Relay assist; connect directly when possible but keep a hub connection for relay fallback.
    ///
    /// This mode is intended for mixed deployments where some peers are behind
    /// NAT/firewalls/censorship and run in `Spoke` mode. Nodes in `Assist` mode
    /// can communicate with those spokes via the configured hub without forcing
    /// every peer to use a relay.
    Assist,
}
/// Hardware acceleration settings (actual layer).
#[derive(Debug, Clone, Copy)]
pub struct Acceleration {
    /// Enable SIMD acceleration (NEON/AVX/SSE) when available; when false, force scalar execution.
    pub enable_simd: bool,
    /// Enable CUDA backend when compiled and available.
    pub enable_cuda: bool,
    /// Enable Metal backend when compiled and available (macOS).
    pub enable_metal: bool,
    /// Maximum number of GPUs to initialize (None = auto/no cap).
    pub max_gpus: Option<usize>,
    /// Minimum number of leaves to use GPU for Merkle leaf hashing.
    pub merkle_min_leaves_gpu: usize,
    /// Backend-specific thresholds (None = inherit generic GPU threshold).
    pub merkle_min_leaves_metal: Option<usize>,
    /// Minimum leaves for CUDA to be used for Merkle leaf hashing (None = inherit GPU default).
    pub merkle_min_leaves_cuda: Option<usize>,
    /// Prefer CPU SHA2 for trees up to this many leaves (per-arch). If None, use defaults.
    pub prefer_cpu_sha2_max_leaves_aarch64: Option<usize>,
    /// Prefer CPU SHA2 threshold (`x86/x86_64`). If None, use defaults.
    pub prefer_cpu_sha2_max_leaves_x86: Option<usize>,
    /// Finite file-only process attempt envelope shared by physical backends.
    /// Resource limits do not assert benchmark qualification or driver-private byte accounting.
    pub resource_limits: iroha_accel::RegistryLimits,
}
/// Execution mode for the FASTPQ prover backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastpqExecutionMode {
    /// Force CPU execution even if accelerators are present.
    Cpu,
    /// Force GPU execution; startup fails if kernels or preflight are unavailable.
    Gpu,
}
/// Poseidon pipeline override for the FASTPQ prover backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastpqPoseidonMode {
    /// Force CPU hashing even if FFT/LDE use the GPU.
    Cpu,
    /// Force GPU hashing; startup fails if kernels or preflight are unavailable.
    Gpu,
}
/// FASTPQ prover configuration.
#[derive(Debug, Clone)]
pub struct Fastpq {
    /// Execution mode used when initialising the prover backend.
    pub execution_mode: FastpqExecutionMode,
    /// Poseidon pipeline override.
    pub poseidon_mode: FastpqPoseidonMode,
    /// Maximum queued FASTPQ proof sidecar attachments.
    pub proof_sidecar_queue_cap: NonZeroUsize,
    /// Maximum encoded FASTPQ proof snapshot accepted for sidecar persistence.
    pub proof_sidecar_max_bytes: Bytes,
    /// Maximum merge attempts for a FASTPQ proof snapshot while the pipeline sidecar is pending.
    pub proof_sidecar_max_retries: NonZeroUsize,
    /// Optional telemetry label describing the host/device class.
    pub device_class: Option<String>,
    /// Optional chip-family label used for telemetry slicing.
    pub chip_family: Option<String>,
    /// Optional GPU kind label (integrated vs. discrete) exposed via telemetry.
    pub gpu_kind: Option<String>,
    /// Optional Metal queue fan-out override (1–4 queues).
    pub metal_queue_fanout: Option<usize>,
    /// Optional Metal queue column threshold override (positive total columns).
    pub metal_queue_column_threshold: Option<u32>,
    /// Optional cap on concurrent Metal command buffers (None = heuristic).
    pub metal_max_in_flight: Option<usize>,
    /// Optional override for Metal threadgroup width (None = pipeline default).
    pub metal_threadgroup_width: Option<u64>,
    /// Enable per-dispatch Metal tracing (developer diagnostic; defaults off).
    pub metal_trace: bool,
    /// Emit verbose Metal device enumeration logs (developer diagnostic; defaults off).
    pub metal_debug_enum: bool,
}
/// Reference to a verifying key by backend and name.
#[derive(Debug, Clone)]
pub struct VerifyingKeyRef {
    /// Backend identifier of the verifying key backend.
    ///
    /// Examples: "pipa-r/pasta", "stark/fri/poseidon-x7-goldilocks-6x64-v1". This string selects the
    /// verification scheme and the curve/domain parameters to use when
    /// validating proofs.
    pub backend: String,
    /// Human‑readable verifying‑key name within the backend namespace.
    ///
    /// This is a logical identifier (e.g., "`ballot_v1`") that maps to an
    /// on‑chain or out‑of‑band provisioned verifying key record for the given
    /// `backend`.
    pub name: String,
}
/// Viral incentive policy governing social reward flows.
#[derive(Debug, Clone)]
pub struct ViralIncentives {
    /// Account supplying reward payouts and sender bonuses.
    pub incentive_pool_account: AccountId,
    /// Account used to hold pending escrows for unbound handles.
    pub escrow_account: AccountId,
    /// Asset definition used for rewards/escrows.
    pub reward_asset_definition_id: AssetDefinitionId,
    /// Amount paid for a valid follow binding.
    pub follow_reward_amount: Quantity,
    /// Bonus paid back to the sender on first delivery.
    pub sender_bonus_amount: Quantity,
    /// Maximum rewards a UAID may claim per day.
    pub max_daily_claims_per_uaid: u32,
    /// Maximum rewards allowed per binding (lifetime).
    pub max_claims_per_binding: u32,
    /// Daily reward budget (spent + bonuses) in reward units.
    pub daily_budget: Quantity,
    /// When true, reward/escrow flows are halted.
    pub halt: bool,
    /// Denied UAIDs that cannot receive payouts.
    pub deny_uaids: Vec<UniversalAccountId>,
    /// Denied binding digests that cannot be rewarded.
    pub deny_binding_digests: Vec<Hash>,
    /// Optional promotion window start (Unix timestamp ms). `None` = always on.
    pub promo_starts_at_ms: Option<u64>,
    /// Optional promotion window end (Unix timestamp ms). `None` = unbounded.
    pub promo_ends_at_ms: Option<u64>,
    /// Aggregate campaign budget cap across the promo window (0 = unlimited).
    pub campaign_cap: Quantity,
}
impl_default!(ViralIncentives => {
        let default_pool_account = defaults::governance::slash_receiver_account_id();
        Self {
            incentive_pool_account: default_pool_account.clone(),
            escrow_account: default_pool_account,
            reward_asset_definition_id: defaults::governance::viral_reward_asset_id()
                .parse()
                .expect("default viral reward asset id"),
            follow_reward_amount: defaults::governance::viral_follow_reward_amount(),
            sender_bonus_amount: defaults::governance::viral_sender_bonus_amount(),
            max_daily_claims_per_uaid: defaults::governance::VIRAL_MAX_DAILY_CLAIMS_PER_UAID,
            max_claims_per_binding: defaults::governance::VIRAL_MAX_CLAIMS_PER_BINDING,
            daily_budget: defaults::governance::viral_daily_budget(),
            halt: false,
            deny_uaids: Vec::new(),
            deny_binding_digests: Vec::new(),
            promo_starts_at_ms: defaults::governance::viral_promo_start_ms(),
            promo_ends_at_ms: defaults::governance::viral_promo_end_ms(),
            campaign_cap: defaults::governance::viral_campaign_cap(),
        }
});
/// Runtime-upgrade provenance enforcement modes (actual layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeUpgradeProvenanceMode {
    /// Provenance is optional; when provided it is verified.
    Optional,
    /// Provenance is required for runtime upgrade manifests.
    Required,
}
impl RuntimeUpgradeProvenanceMode {
    /// Return whether provenance is required.
    #[inline]
    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}
impl From<user::RuntimeUpgradeProvenanceMode> for RuntimeUpgradeProvenanceMode {
    fn from(mode: user::RuntimeUpgradeProvenanceMode) -> Self {
        match mode {
            user::RuntimeUpgradeProvenanceMode::Optional => Self::Optional,
            user::RuntimeUpgradeProvenanceMode::Required => Self::Required,
        }
    }
}
/// Runtime-upgrade provenance policy (actual layer).
#[derive(Debug, Clone)]
pub struct RuntimeUpgradeProvenancePolicy {
    /// Enforcement mode for provenance.
    pub mode: RuntimeUpgradeProvenanceMode,
    /// Require at least one SBOM digest entry when provenance is present/required.
    pub require_sbom: bool,
    /// Require a non-empty SLSA attestation when provenance is present/required.
    pub require_slsa: bool,
    /// Trusted signer public keys.
    pub trusted_signers: BTreeSet<PublicKey>,
    /// Minimum number of trusted signatures required.
    pub signature_threshold: usize,
}
impl_default!(RuntimeUpgradeProvenancePolicy => {
        Self {
            mode: RuntimeUpgradeProvenanceMode::Optional,
            require_sbom: defaults::governance::RUNTIME_UPGRADE_PROVENANCE_REQUIRE_SBOM,
            require_slsa: defaults::governance::RUNTIME_UPGRADE_PROVENANCE_REQUIRE_SLSA,
            trusted_signers: BTreeSet::new(),
            signature_threshold:
                defaults::governance::RUNTIME_UPGRADE_PROVENANCE_SIGNATURE_THRESHOLD,
        }
});
/// Consensus-critical deterministic block-height and resource policy for private Parliament ballots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParliamentTimedOvn {
    /// Consensus block-height span allotted to proof-validated registration submissions.
    pub registration_phase_blocks: u64,
    /// Consensus block-height span allotted to freezing pre-ballot dropouts and survivors.
    pub survivor_freeze_phase_blocks: u64,
    /// Consensus block-height span allotted to the exact masked-ballot commitment corpus.
    pub commitment_phase_blocks: u64,
    /// Consensus block-height span between commitment close and the earliest timed release.
    pub release_delay_blocks: u64,
    /// Consensus block-height grace window for aggregate opening after release begins.
    pub opening_phase_blocks: u64,
    /// Retry attempts permitted after the initial private ballot attempt, capped at 16.
    pub max_ballot_retries: u32,
    /// Maximum entries retained in any registration, survivor, or ballot corpus, capped at 1,000.
    pub max_corpus_entries: u32,
}
impl ParliamentTimedOvn {
    /// Return the complete sequential ballot-attempt span when it fits in `u64`.
    #[must_use]
    pub fn checked_attempt_span_blocks(&self) -> Option<u64> {
        self.registration_phase_blocks
            .checked_add(self.survivor_freeze_phase_blocks)?
            .checked_add(self.commitment_phase_blocks)?
            .checked_add(self.release_delay_blocks)?
            .checked_add(self.opening_phase_blocks)
    }

    /// Return the maximum sequential lifecycle span, including every permitted retry.
    #[must_use]
    pub fn checked_max_lifecycle_span_blocks(&self) -> Option<u64> {
        self.checked_attempt_span_blocks()?
            .checked_mul(u64::from(self.max_ballot_retries).checked_add(1)?)
    }

    /// Fail closed unless all phase durations and first-release bounds are valid.
    pub fn assert_valid(&self) {
        for (name, blocks) in [
            ("registration_phase_blocks", self.registration_phase_blocks),
            (
                "survivor_freeze_phase_blocks",
                self.survivor_freeze_phase_blocks,
            ),
            ("commitment_phase_blocks", self.commitment_phase_blocks),
            ("release_delay_blocks", self.release_delay_blocks),
            ("opening_phase_blocks", self.opening_phase_blocks),
        ] {
            assert!(
                blocks > 0,
                "governance.parliament_timed_ovn.{name} must be non-zero"
            );
        }
        assert!(
            self.checked_attempt_span_blocks().is_some(),
            "governance.parliament_timed_ovn phase schedule must fit in u64 blocks"
        );
        assert!(
            self.max_ballot_retries
                <= defaults::governance::parliament_timed_ovn::MAX_BALLOT_RETRIES_LIMIT,
            "governance.parliament_timed_ovn.max_ballot_retries must be within 0..={}",
            defaults::governance::parliament_timed_ovn::MAX_BALLOT_RETRIES_LIMIT
        );
        assert!(
            self.checked_max_lifecycle_span_blocks().is_some(),
            "governance.parliament_timed_ovn retry schedule must fit in u64 blocks"
        );
        let crypto_corpus_limit =
            u32::try_from(iroha_crypto::timed_ovn::TIMED_OVN_MAX_PARTICIPANTS_V1)
                .expect("timed-OVN participant limit fits u32");
        assert_eq!(
            defaults::governance::parliament_timed_ovn::MAX_CORPUS_ENTRIES_LIMIT,
            crypto_corpus_limit,
            "governance timed-OVN corpus limit must match the crypto decoder"
        );
        assert!(
            (iroha_data_model::governance::types::MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                ..=crypto_corpus_limit)
                .contains(&self.max_corpus_entries),
            "governance.parliament_timed_ovn.max_corpus_entries must be within {}..={crypto_corpus_limit}",
            iroha_data_model::governance::types::MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
        );
        let required_single_record_blocks = u64::from(self.max_corpus_entries);
        let required_registration_blocks = required_single_record_blocks
            .checked_add(1)
            .expect("bounded timed-OVN corpus plus admission slack fits u64");
        assert!(
            self.registration_phase_blocks >= required_registration_blocks,
            "governance.parliament_timed_ovn.registration_phase_blocks must be at least {required_registration_blocks} for max_corpus_entries={} and one V1 admission-boundary slack block",
            self.max_corpus_entries
        );
        assert!(
            self.survivor_freeze_phase_blocks >= required_single_record_blocks,
            "governance.parliament_timed_ovn.survivor_freeze_phase_blocks must be at least {required_single_record_blocks} for max_corpus_entries={} and the V1 authenticated-dropout transition",
            self.max_corpus_entries
        );
        let required_chunk_blocks =
            iroha_data_model::governance::types::parliament_timed_ovn_required_chunk_blocks_v1(
                self.max_corpus_entries,
            );
        assert!(
            self.commitment_phase_blocks >= required_chunk_blocks,
            "governance.parliament_timed_ovn.commitment_phase_blocks must be at least {required_chunk_blocks} for max_corpus_entries={} and the V1 ballot chunk bound",
            self.max_corpus_entries
        );
    }
}
impl_default!(ParliamentTimedOvn => {
    let policy = Self {
        registration_phase_blocks:
            defaults::governance::parliament_timed_ovn::REGISTRATION_PHASE_BLOCKS,
        survivor_freeze_phase_blocks:
            defaults::governance::parliament_timed_ovn::SURVIVOR_FREEZE_PHASE_BLOCKS,
        commitment_phase_blocks:
            defaults::governance::parliament_timed_ovn::COMMITMENT_PHASE_BLOCKS,
        release_delay_blocks:
            defaults::governance::parliament_timed_ovn::RELEASE_DELAY_BLOCKS,
        opening_phase_blocks:
            defaults::governance::parliament_timed_ovn::OPENING_PHASE_BLOCKS,
        max_ballot_retries:
            defaults::governance::parliament_timed_ovn::MAX_BALLOT_RETRIES,
        max_corpus_entries:
            defaults::governance::parliament_timed_ovn::MAX_CORPUS_ENTRIES,
    };
    policy.assert_valid();
    policy
});
/// Consensus-critical lifecycle bounds for adaptive Parliament TLE keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParliamentTleKeyLifecycle {
    /// Inclusive number of blocks during which the session may admit fresh ballots.
    pub session_lifetime_blocks: u64,
    /// Maximum committed fresh ballot attempts that may select one session.
    pub max_fresh_ballots_per_session: u32,
}
impl ParliamentTleKeyLifecycle {
    /// Fail closed unless both adaptive-corruption bounds are non-zero.
    pub fn assert_valid(self) {
        assert!(
            self.session_lifetime_blocks > 0,
            "governance.parliament_tle_key_lifecycle.session_lifetime_blocks must be non-zero"
        );
        assert!(
            self.max_fresh_ballots_per_session > 0,
            "governance.parliament_tle_key_lifecycle.max_fresh_ballots_per_session must be non-zero"
        );
    }
}
impl_default!(ParliamentTleKeyLifecycle => {
    let policy = Self {
        session_lifetime_blocks:
            defaults::governance::parliament_tle_key_lifecycle::SESSION_LIFETIME_BLOCKS,
        max_fresh_ballots_per_session:
            defaults::governance::parliament_tle_key_lifecycle::MAX_FRESH_BALLOTS_PER_SESSION,
    };
    policy.assert_valid();
    policy
});
/// Governance configuration (actual layer).
#[derive(Debug, Clone)]
pub struct Governance {
    /// Optional default verifying key for ZK ballots (backend + name).
    pub vk_ballot: Option<VerifyingKeyRef>,
    /// Optional default verifying key for ZK tallies (backend + name).
    pub vk_tally: Option<VerifyingKeyRef>,
    /// Asset definition used to denominate governance bonds and voting locks.
    pub voting_asset_id: AssetDefinitionId,
    /// Asset definition used to denominate citizenship bonds.
    pub citizenship_asset_id: AssetDefinitionId,
    /// Exact minimum amount required to register as a citizen.
    pub citizenship_bond_amount: Quantity,
    /// Escrow account that custody citizenship bonds until expiry or revocation.
    pub citizenship_escrow_account: AccountId,
    /// Exact minimum amount required to submit a ballot.
    pub min_bond_amount: Quantity,
    /// Escrow account that custody governance bonds until expiry or slash.
    pub bond_escrow_account: AccountId,
    /// Account that receives slashed governance bonds (may mirror escrow).
    pub slash_receiver_account: AccountId,
    /// Slash percentage for double-vote attempts (basis points, 0–10_000).
    pub slash_double_vote_bps: u16,
    /// Slash percentage applied when ballot proofs are invalid (basis points).
    pub slash_invalid_proof_bps: u16,
    /// Slash percentage applied when eligibility proofs do not match (basis points).
    pub slash_ineligible_proof_bps: u16,
    /// Exact minimum TEU balance required to accept alias attestations.
    pub alias_teu_minimum: Quantity,
    /// Emit alias frontier telemetry and stats.
    pub alias_frontier_telemetry: bool,
    /// Emit debug tracing for governance pipeline progression.
    pub debug_trace_pipeline: bool,
    /// Allowed JDG signature schemes for attestation validation.
    pub jdg_signature_schemes: BTreeSet<JdgSignatureScheme>,
    /// Runtime upgrade provenance enforcement policy.
    pub runtime_upgrade_provenance: RuntimeUpgradeProvenancePolicy,
    /// Viral incentive policy for social rewards.
    pub viral_incentives: ViralIncentives,
    /// SoraFS pin policy constraints enforced during manifest admission.
    pub sorafs_pin_policy: SorafsPinPolicyConstraints,
    /// Asset definition used to collect public SoraFS pin fees.
    pub sorafs_pin_fee_asset_id: AssetDefinitionId,
    /// Treasury account that receives public SoraFS pin fees.
    pub sorafs_pin_fee_treasury_account: AccountId,
    /// SoraFS pricing schedule and credit policy.
    pub sorafs_pricing: PricingScheduleRecord,
    /// SoraFS under-delivery penalty policy applied to provider credits.
    pub sorafs_penalty: SorafsPenaltyPolicy,
    /// SoraFS telemetry authentication/replay safeguards.
    pub sorafs_telemetry: SorafsTelemetryPolicy,
    /// Trusted provider→owner bindings seeded only before the first block.
    pub sorafs_provider_owners: BTreeMap<ProviderId, AccountId>,
    /// Nonzero conviction step in blocks for plain (non‑ZK) voting. Duration/step yields extra weight.
    pub conviction_step_blocks: u64,
    /// Nonzero maximum conviction multiplier allowed in plain (non‑ZK) voting.
    pub max_conviction: u64,
    /// Minimum enactment delay (in blocks) for generating referendum windows.
    pub min_enactment_delay: u64,
    /// Referendum window span (in blocks); `h_end = h_start + span - 1`.
    pub window_span: u64,
    /// Maximum number of non-closed governance referenda retained at once.
    pub max_active_referenda: NonZeroU32,
    /// Maximum distinct governance-lock owners retained for one referendum.
    pub max_lock_owners_per_referendum: NonZeroU32,
    /// Allow non‑ZK quadratic voting (plain ballots). If false, plain ballots are rejected.
    pub plain_voting_enabled: bool,
    /// Approval threshold numerator (Q-format): approve / (approve + reject) >= num/den.
    pub approval_threshold_q_num: u64,
    /// Approval threshold denominator (Q-format).
    pub approval_threshold_q_den: u64,
    /// Minimum turnout required (approve + reject + abstain) to consider the referendum.
    pub min_turnout: u128,
    /// Alternates retained for each attempt-local Parliament body draw.
    pub parliament_alternate_size: usize,
    /// Minimum future-beacon delay frozen into Parliament attempts. A sortition request targets
    /// the first consensus-native `NPoS` pulse height at or after its request height plus this
    /// delay.
    pub parliament_sortition_pulse_delay_blocks: u64,
    /// Consensus block-height span for immutable Parliament invitation responses.
    pub parliament_invitation_phase_blocks: u64,
    /// Consensus block-height span for public-finding endorsements after Reflection begins.
    pub parliament_public_finding_phase_blocks: u64,
    /// Consensus-critical timed-OVN phase and resource policy.
    pub parliament_timed_ovn: ParliamentTimedOvn,
    /// Consensus-critical activation, expiry, and fresh-use policy for TLE keys.
    pub parliament_tle_key_lifecycle: ParliamentTleKeyLifecycle,
    /// Public deployment binding for the runtime-only Parliament TLE release-share signer.
    pub parliament_tle_partial_release_signer_provider_handle: Option<String>,
    /// Exact non-zero provider contract revision paired with the TLE signer handle.
    pub parliament_tle_partial_release_signer_provider_revision: Option<u64>,
    /// Exact non-zero public policy commitment paired with the TLE signer binding.
    pub parliament_tle_partial_release_signer_provider_policy_digest: Option<[u8; 32]>,
    /// Rules Committee size.
    pub rules_committee_size: usize,
    /// Agenda Council size.
    pub agenda_council_size: usize,
    /// Interest Panel size.
    pub interest_panel_size: usize,
    /// Review Panel size.
    pub review_panel_size: usize,
    /// Coordination Council size.
    pub coordination_council_size: usize,
    /// Policy Jury size (at least the hidden-ballot anonymity floor).
    pub policy_jury_size: usize,
    /// Confirmation Jury target/cap (at least the hidden-ballot anonymity floor).
    pub confirmation_jury_size: usize,
    /// Oversight Committee size.
    pub oversight_committee_size: usize,
    /// MPC Committee size.
    pub mpc_committee_size: usize,
    /// FMA Committee size.
    pub fma_committee_size: usize,
}
impl_default!(Governance => {
        Self {
            vk_ballot: None,
            vk_tally: None,
            voting_asset_id: defaults::governance::voting_asset_id()
                .parse()
                .expect("valid default voting asset id"),
            citizenship_asset_id: defaults::governance::citizenship_asset_id()
                .parse()
                .expect("valid default citizenship asset id"),
            citizenship_bond_amount: defaults::governance::citizenship_bond_amount(),
            citizenship_escrow_account: defaults::governance::citizenship_escrow_account_id(),
            min_bond_amount: defaults::governance::min_bond_amount(),
            bond_escrow_account: defaults::governance::bond_escrow_account_id(),
            slash_receiver_account: defaults::governance::slash_receiver_account_id(),
            slash_double_vote_bps: defaults::governance::slash_policy::DOUBLE_VOTE_BPS,
            slash_invalid_proof_bps: defaults::governance::slash_policy::MISCONDUCT_BPS,
            slash_ineligible_proof_bps: defaults::governance::slash_policy::INELIGIBLE_PROOF_BPS,
            alias_teu_minimum: defaults::governance::alias_teu_minimum(),
            alias_frontier_telemetry: defaults::governance::alias_frontier_telemetry(),
            debug_trace_pipeline: defaults::governance::DEBUG_TRACE_PIPELINE,
            jdg_signature_schemes: defaults::governance::jdg_signature_schemes()
                .into_iter()
                .map(|scheme| {
                    scheme
                        .parse::<JdgSignatureScheme>()
                        .expect("valid default JDG signature scheme")
                })
                .collect(),
            runtime_upgrade_provenance: RuntimeUpgradeProvenancePolicy::default(),
            viral_incentives: ViralIncentives::default(),
            sorafs_pin_policy: SorafsPinPolicyConstraints::default(),
            sorafs_pin_fee_asset_id: defaults::governance::sorafs_pin_fee::asset_id()
                .parse()
                .expect("default SoraFS pin fee asset id"),
            sorafs_pin_fee_treasury_account:
                defaults::governance::sorafs_pin_fee::treasury_account_id(),
            sorafs_pricing: PricingScheduleRecord::launch_default(),
            sorafs_penalty: SorafsPenaltyPolicy::default(),
            sorafs_telemetry: SorafsTelemetryPolicy::default(),
            sorafs_provider_owners: BTreeMap::new(),
            conviction_step_blocks: 100,
            max_conviction: 6,
            min_enactment_delay: 20,
            window_span: 100,
            max_active_referenda: defaults::governance::MAX_ACTIVE_REFERENDA,
            max_lock_owners_per_referendum:
                defaults::governance::MAX_LOCK_OWNERS_PER_REFERENDUM,
            plain_voting_enabled: defaults::governance::PLAIN_VOTING_ENABLED,
            approval_threshold_q_num: 1,
            approval_threshold_q_den: 2,
            min_turnout: 0,
            parliament_alternate_size: defaults::governance::PARLIAMENT_ALTERNATE_SIZE,
            parliament_sortition_pulse_delay_blocks:
                defaults::governance::PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS,
            parliament_invitation_phase_blocks:
                defaults::governance::PARLIAMENT_INVITATION_PHASE_BLOCKS,
            parliament_public_finding_phase_blocks:
                defaults::governance::PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS,
            parliament_timed_ovn: ParliamentTimedOvn::default(),
            parliament_tle_key_lifecycle: ParliamentTleKeyLifecycle::default(),
            parliament_tle_partial_release_signer_provider_handle: None,
            parliament_tle_partial_release_signer_provider_revision: None,
            parliament_tle_partial_release_signer_provider_policy_digest: None,
            rules_committee_size: defaults::governance::PARLIAMENT_RULES_COMMITTEE_SIZE,
            agenda_council_size: defaults::governance::PARLIAMENT_AGENDA_COUNCIL_SIZE,
            interest_panel_size: defaults::governance::PARLIAMENT_INTEREST_PANEL_SIZE,
            review_panel_size: defaults::governance::PARLIAMENT_REVIEW_PANEL_SIZE,
            coordination_council_size:
                defaults::governance::PARLIAMENT_COORDINATION_COUNCIL_SIZE,
            policy_jury_size: defaults::governance::PARLIAMENT_POLICY_JURY_SIZE,
            confirmation_jury_size: defaults::governance::PARLIAMENT_CONFIRMATION_JURY_SIZE,
            oversight_committee_size: defaults::governance::PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE,
            mpc_committee_size: defaults::governance::PARLIAMENT_MPC_COMMITTEE_SIZE,
            fma_committee_size: defaults::governance::PARLIAMENT_FMA_COMMITTEE_SIZE,
        }
});
/// Concurrency controls for internal thread pools.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct Concurrency {
    /// Minimum scheduler worker threads (0 = auto/physical cores)
    pub scheduler_min_threads: usize,
    /// Maximum scheduler worker threads (0 = auto/physical cores)
    pub scheduler_max_threads: usize,
    /// Global Rayon thread pool size (0 = auto/physical cores)
    pub rayon_global_threads: usize,
    /// Stack size (bytes) for Tokio runtime and blocking threads.
    pub tokio_stack_bytes: usize,
    /// Stack size (bytes) for scheduler worker threads.
    pub scheduler_stack_bytes: usize,
    /// Stack size (bytes) for prover worker threads.
    pub prover_stack_bytes: usize,
    /// Stack size (bytes) for Sumeragi helper threads.
    pub sumeragi_stack_bytes: usize,
}
impl Concurrency {
    /// Construct a concurrency configuration from repository defaults.
    #[must_use]
    pub const fn from_defaults() -> Self {
        Self {
            scheduler_min_threads: defaults::concurrency::SCHEDULER_MIN,
            scheduler_max_threads: defaults::concurrency::SCHEDULER_MAX,
            rayon_global_threads: defaults::concurrency::RAYON_GLOBAL,
            tokio_stack_bytes: defaults::concurrency::TOKIO_STACK_BYTES,
            scheduler_stack_bytes: defaults::concurrency::SCHEDULER_STACK_BYTES,
            prover_stack_bytes: defaults::concurrency::PROVER_STACK_BYTES,
            sumeragi_stack_bytes: defaults::concurrency::SUMERAGI_STACK_BYTES,
        }
    }
    /// Validate stack sizes to ensure they are non-zero and within sane bounds.
    pub fn validate(&self) -> core::result::Result<(), Report<ParseError>> {
        if self.tokio_stack_bytes < defaults::concurrency::TOKIO_STACK_BYTES_MIN
            || self.tokio_stack_bytes > defaults::concurrency::TOKIO_STACK_BYTES_MAX
        {
            return Err(
                Report::new(ParseError::InvalidConcurrencyConfig).attach(format!(
                    "tokio_stack_bytes must be in [{}, {}], got {}",
                    defaults::concurrency::TOKIO_STACK_BYTES_MIN,
                    defaults::concurrency::TOKIO_STACK_BYTES_MAX,
                    self.tokio_stack_bytes
                )),
            );
        }
        if self.scheduler_stack_bytes == 0 || self.prover_stack_bytes == 0 {
            return Err(Report::new(ParseError::InvalidConcurrencyConfig)
                .attach("scheduler_stack_bytes and prover_stack_bytes must be non-zero"));
        }
        if self.sumeragi_stack_bytes < defaults::concurrency::SUMERAGI_STACK_BYTES_MIN
            || self.sumeragi_stack_bytes > defaults::concurrency::SUMERAGI_STACK_BYTES_MAX
        {
            return Err(
                Report::new(ParseError::InvalidConcurrencyConfig).attach(format!(
                    "sumeragi_stack_bytes must be in [{}, {}], got {}",
                    defaults::concurrency::SUMERAGI_STACK_BYTES_MIN,
                    defaults::concurrency::SUMERAGI_STACK_BYTES_MAX,
                    self.sumeragi_stack_bytes
                )),
            );
        }
        Ok(())
    }
}
/// Governance configuration (actual layer).
/// Parsed genesis configuration
#[derive(Debug, Clone)]
pub struct Genesis {
    /// Genesis account public key
    pub public_key: PublicKey,
    /// Path to the operator-provisioned signed `GenesisBlock`.
    pub file: Option<WithOrigin<PathBuf>>,
    /// Optional path to genesis manifest JSON for validation at startup.
    pub manifest_json: Option<WithOrigin<PathBuf>>,
    /// Exact genesis consensus-header hash used as the startup trust anchor.
    ///
    /// Configuration normalization requires this value independently of the signed artifact.
    pub expected_hash: HashOf<BlockHeader>,
}
/// Complete validated node policy before a genesis identity exists.
///
/// This authoring context has no runtime decoder or implicit conversion to [`Root`]. Every
/// ordinary schema, policy and required private-custody validator still runs. Binding requires
/// an original signed genesis block; daemon startup independently authenticates its final
/// expected hash against the prepared bundle.
#[derive(Debug)]
pub struct GenesisSigningContext {
    policy: Root<GenesisForSigning>,
}
/// Genesis public identity in an unpublished signing context. No expected hash is fabricated.
#[derive(Debug)]
pub(crate) struct GenesisForSigning {
    pub(crate) public_key: PublicKey,
    pub(crate) file: Option<WithOrigin<PathBuf>>,
    pub(crate) manifest_json: Option<WithOrigin<PathBuf>>,
}
impl GenesisSigningContext {
    pub(crate) fn new(policy: Root<GenesisForSigning>) -> Self {
        Self { policy }
    }
    /// Read complete unpublished policy with the canonical validators and native private files.
    /// Ambient environment variables cannot replace these authoring inputs.
    /// # Errors
    /// Refuses a claimed runtime identity, invalid policy, or missing required private custody.
    pub fn from_toml_source(src: TomlSource) -> Result<Self, FromTomlSourceError> {
        ConfigReader::new()
            .without_env()
            .with_toml_source(src)
            .read_and_complete::<user::Root>()
            .change_context(FromTomlSourceError)?
            .parse_for_genesis_signing()
            .change_context(FromTomlSourceError)
    }
    /// Exact validated Nexus policy used by native genesis execution.
    pub fn nexus(&self) -> &Nexus {
        &self.policy.nexus
    }
    /// Exact validated confidential-verifier policy used by native genesis execution.
    pub fn zk(&self) -> &Zk {
        &self.policy.zk
    }
    /// Bind this authoring policy to a genuine signed genesis-header identity.
    ///
    /// A provisional block may be used only for local policy execution. The final generator
    /// must parse every final config against the final network before publication; a
    /// provisional context is never a deployment admission receipt.
    /// # Errors
    /// Refuses a non-genesis block, missing or extra signatures, a wrong signer, or invalid
    /// original block and transaction signatures.
    pub fn bind_signed_genesis(
        self,
        block: &iroha_data_model::block::SignedBlock,
    ) -> core::result::Result<Root, &'static str> {
        if block.header().height().get() != 1 {
            return Err("signing context requires an original signed genesis block");
        }
        let mut signatures = block.signatures();
        let signature = signatures
            .next()
            .ok_or("signing context genesis has no signature")?;
        if signature.index() != 0 || signatures.next().is_some() {
            return Err("signing context genesis must have one signature at index zero");
        }
        signature
            .signature()
            .verify_hash(&self.policy.genesis.public_key, block.hash())
            .map_err(|_| "signing context genesis signature does not match its public key")?;
        for transaction in block.external_transactions() {
            transaction
                .verify_signature()
                .map_err(|_| "signing context genesis has an invalid transaction signature")?;
        }
        Ok(self.policy.map_genesis(|genesis| Genesis {
            public_key: genesis.public_key,
            file: genesis.file,
            manifest_json: genesis.manifest_json,
            expected_hash: block.hash(),
        }))
    }
}
/// Transaction queue settings.
#[derive(Debug, Clone, Copy)]
pub struct Queue {
    /// Maximum number of transactions allowed in the queue.
    pub capacity: NonZeroUsize,
    /// Per-user transaction limit in the queue.
    pub capacity_per_user: NonZeroUsize,
    /// Estimated maximum retained queue memory budget in bytes.
    pub max_retained_bytes: NonZeroU64,
    /// Transaction time-to-live.
    pub transaction_time_to_live: Duration,
    /// Minimum interval between expired-transaction sweeps.
    pub expired_cull_interval: Duration,
    /// Maximum number of entries scanned per expired-transaction sweep.
    pub expired_cull_batch: NonZeroUsize,
}
/// Nexus staking configuration (public lanes).
#[derive(Debug, Clone)]
pub struct NexusStaking {
    /// Validator activation policy for public lanes.
    pub public_validator_mode: LaneValidatorMode,
    /// Validator activation policy for restricted/permissioned lanes.
    pub restricted_validator_mode: LaneValidatorMode,
    /// Minimum bonded stake required to register or bond as a validator.
    pub min_validator_stake: Quantity,
    /// Maximum number of validators allowed per lane.
    pub max_validators: NonZeroU32,
    /// Maximum number of stake-share rows retained for one validator.
    pub max_stake_shares_per_validator: NonZeroU32,
    /// Maximum number of pending unbond requests retained in one stake share.
    pub max_pending_unbonds_per_share: NonZeroU32,
    /// Minimum delay between scheduling and finalising an unbond (milliseconds).
    pub unbonding_delay: Duration,
    /// Maximum slash ratio allowed (basis points, 10_000 = 100%).
    pub max_slash_bps: u16,
    /// Asset definition used for staking bonds (string form).
    pub stake_asset_id: String,
    /// Escrow account that holds bonded stake (string form).
    pub stake_escrow_account_id: String,
    /// Account that receives slashed stake (string form).
    pub slash_sink_account_id: String,
}
impl_default!(NexusStaking => {
        Self {
            public_validator_mode: LaneValidatorMode::StakeElected,
            restricted_validator_mode: LaneValidatorMode::AdminManaged,
            min_validator_stake: defaults::nexus::staking::min_validator_stake(),
            max_validators: defaults::nexus::staking::MAX_VALIDATORS,
            max_stake_shares_per_validator:
                defaults::nexus::staking::MAX_STAKE_SHARES_PER_VALIDATOR,
            max_pending_unbonds_per_share:
                defaults::nexus::staking::MAX_PENDING_UNBONDS_PER_SHARE,
            unbonding_delay: defaults::nexus::staking::UNBONDING_DELAY,
            max_slash_bps: defaults::nexus::staking::MAX_SLASH_BPS,
            stake_asset_id: defaults::nexus::staking::stake_asset_id(),
            stake_escrow_account_id: defaults::nexus::staking::stake_escrow_account_id(),
            slash_sink_account_id: defaults::nexus::staking::slash_sink_account_id(),
        }
});
impl NexusStaking {
    /// Resolve the validator activation policy for a lane using its configured visibility.
    #[must_use]
    pub fn validator_mode(&self, lane: LaneId, catalog: &LaneCatalog) -> LaneValidatorMode {
        let visibility = catalog
            .lanes()
            .iter()
            .find(|lane_meta| lane_meta.id == lane)
            .map_or(LaneVisibility::Public, |lane_meta| lane_meta.visibility);
        match visibility {
            LaneVisibility::Public => self.public_validator_mode,
            LaneVisibility::Restricted => self.restricted_validator_mode,
        }
    }
}
/// Nexus fee schedule for universal XOR-denominated charges.
/// The default anchor is `1 TransferAsset = 1 TEU = 0.01 XOR`.
#[derive(Debug, Clone)]
pub struct NexusFees {
    /// Asset definition used to collect fees (e.g., `61CtjvNd9T3THAR65GsMVHr82Bjc`).
    pub fee_asset_id: String,
    /// Account that receives collected fees.
    pub fee_sink_account_id: String,
    /// Base fee charged per transaction.
    pub base_fee: Quantity,
    /// Per-byte fee charged over the signed transaction payload.
    pub per_byte_fee: Quantity,
    /// Per-instruction fee charged for native ISI batches.
    pub per_instruction_fee: Quantity,
    /// Per-gas-unit fee multiplier applied to measured gas usage.
    pub per_gas_unit_fee: Quantity,
    /// Protocol account that physically custodies isolated sponsor-program vault assets.
    pub sponsor_vault_custody_account_id: AccountId,
    /// How fees are settled after they are computed.
    pub settlement_mode: NexusFeeSettlementMode,
    /// Canonical authorities allowed to submit fee-free successful SORA v2 XOR claim mint
    /// transactions.
    pub successful_claim_fee_exempt_authorities: BTreeSet<AccountId>,
}
/// Settlement mode for Nexus fee debits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexusFeeSettlementMode {
    /// Fees are debited in the same chain transaction execution path.
    Direct,
    /// Fees are committed into lane receipts and burned during Nexus merge settlement.
    LaneRelayBurn,
}
impl_default!(NexusFees => {
        Self {
            fee_asset_id: defaults::nexus::fees::fee_asset_id(),
            fee_sink_account_id: defaults::nexus::fees::FEE_SINK_ACCOUNT_ID.to_string(),
            base_fee: defaults::nexus::fees::base_fee(),
            per_byte_fee: defaults::nexus::fees::per_byte_fee(),
            per_instruction_fee: defaults::nexus::fees::per_instruction_fee(),
            per_gas_unit_fee: defaults::nexus::fees::per_gas_unit_fee(),
            sponsor_vault_custody_account_id:
                defaults::nexus::fees::sponsor_vault_custody_account_id(),
            settlement_mode: NexusFeeSettlementMode::Direct,
            successful_claim_fee_exempt_authorities: BTreeSet::new(),
        }
});
/// Asynchronous worker that proves DPN lane relays and sponsor fee budgets.
#[derive(Debug, Clone)]
pub struct NexusRelayWorker {
    /// Whether the protocol worker is active.
    pub enabled: bool,
    /// Optional account id that must match the node signing key's account id.
    pub authority_account_id: Option<String>,
    /// Hard per-kind cap for durable relay/allocation work and verified-relay announcement history.
    pub max_pending_relays: NonZeroUsize,
    /// Delay between proof/submission retry passes.
    pub retry_backoff: Duration,
    /// Maximum proof/submission attempts before local worker retry stops.
    pub max_retry_attempts: NonZeroU32,
}
impl_default!(NexusRelayWorker => {
        Self {
            enabled: defaults::nexus::relay_worker::ENABLED,
            authority_account_id: defaults::nexus::relay_worker::AUTHORITY_ACCOUNT_ID
                .map(str::to_owned),
            max_pending_relays: NonZeroUsize::new(
                defaults::nexus::relay_worker::MAX_PENDING_RELAYS,
            )
            .expect("default Nexus relay worker max_pending_relays is non-zero"),
            retry_backoff: Duration::from_millis(defaults::nexus::relay_worker::RETRY_BACKOFF_MS),
            max_retry_attempts: NonZeroU32::new(defaults::nexus::relay_worker::MAX_RETRY_ATTEMPTS)
                .expect("default Nexus relay worker max_retry_attempts is non-zero"),
        }
});
/// Shared Hugging Face lease policy for Soracloud pool draining.
#[derive(Debug, Clone, Copy)]
pub struct NexusHfSharedLeases {
    /// Drain grace window applied after the last member leaves a shared lease pool.
    pub drain_grace: Duration,
}
impl_default!(NexusHfSharedLeases => {
        Self {
            drain_grace: Duration::from_millis(defaults::nexus::hf_shared_leases::DRAIN_GRACE_MS),
        }
});
/// Encrypted uploaded-model registry quota policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NexusUploadedModels {
    /// Maximum plaintext bytes admitted for one uploaded model.
    pub max_plaintext_bytes_per_model: u64,
    /// Maximum encrypted chunk count admitted for one uploaded model.
    pub max_chunk_count_per_model: u32,
}
impl_default!(NexusUploadedModels => {
        Self {
            max_plaintext_bytes_per_model:
                defaults::nexus::uploaded_models::MAX_PLAINTEXT_BYTES_PER_MODEL,
            max_chunk_count_per_model: defaults::nexus::uploaded_models::MAX_CHUNK_COUNT_PER_MODEL,
        }
});
/// Committee and quorum settings for protected-domain endorsements.
#[derive(Debug, Clone)]
pub struct NexusEndorsement {
    /// Canonical committee public keys allowed to sign endorsements.
    pub committee_keys: BTreeSet<PublicKey>,
    /// Quorum required to accept an endorsement (0 disables enforcement).
    pub quorum: u16,
}
impl_default!(NexusEndorsement => {
        let committee_keys: BTreeSet<PublicKey> = defaults::nexus::endorsement::committee_keys()
            .into_iter()
            .enumerate()
            .map(|(index, raw_key)| {
                PublicKey::from_str(raw_key.trim()).unwrap_or_else(|error| {
                    panic!("invalid default nexus.endorsement.committee_keys[{index}]: {error}")
                })
            })
            .collect();
        let quorum = defaults::nexus::endorsement::QUORUM;
        assert!(
            quorum == 0 || usize::from(quorum) <= committee_keys.len(),
            "default nexus.endorsement.quorum exceeds the unique default committee size"
        );
        Self {
            committee_keys,
            quorum,
        }
});
/// Nexus configuration for AXT execution and expiry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NexusAxt {
    /// Slot length used when deriving AXT expiry slots from block timestamps.
    pub slot_length_ms: NonZeroU64,
    /// Maximum wall-clock skew tolerated when enforcing AXT expiry.
    pub max_clock_skew_ms: u64,
    /// Number of slots to retain cached proofs (accepted or rejected) for reuse/replay rejection.
    pub proof_cache_ttl_slots: NonZeroU64,
    /// Number of slots to retain handle usage for replay protection across restarts/peers.
    pub replay_retention_slots: NonZeroU64,
}
impl_default!(NexusAxt => {
        Self {
            slot_length_ms: NonZeroU64::new(defaults::nexus::axt::SLOT_LENGTH_MS)
                .expect("default AXT slot length must be non-zero"),
            max_clock_skew_ms: defaults::nexus::axt::CLOCK_SKEW_MS_DEFAULT,
            proof_cache_ttl_slots: NonZeroU64::new(defaults::nexus::axt::PROOF_CACHE_TTL_SLOTS)
                .expect("proof cache TTL must be non-zero"),
            replay_retention_slots: NonZeroU64::new(defaults::nexus::axt::REPLAY_RETENTION_SLOTS)
                .expect("replay retention window must be non-zero"),
        }
});
/// Governed atomic private cross-dataspace settlement configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NexusAtomicPrivateSettlement {
    /// Whether admission is enabled, subject to the governed activation height.
    pub enabled: bool,
    /// First block height at which the path may be admitted.
    pub activation_height: Option<u64>,
    /// Minimum notice required between governance approval and activation.
    pub minimum_activation_notice_blocks: NonZeroU64,
    /// Audited fixed-shape private-note proof profile version.
    pub proof_profile_version: NonZeroU16,
    /// Maximum number of ordered dataspace legs in one bundle.
    pub max_participants: NonZeroU16,
    /// Maximum admission-to-expiry distance, in blocks.
    pub max_expiry_blocks: NonZeroU64,
    /// Maximum auditor-approval phase duration, in blocks.
    pub audit_timeout_blocks: NonZeroU64,
    /// Maximum Prepare-QC phase duration, in blocks.
    pub prepare_timeout_blocks: NonZeroU64,
    /// Maximum Commit-QC phase duration, in blocks.
    pub commit_timeout_blocks: NonZeroU64,
    /// Strictly increasing canonical padded-plaintext classes, in bytes.
    ///
    /// The authenticated ciphertext is exactly 16 bytes larger; configuration
    /// also reserves canonical AAD, nonce, vector, and wrapped-DEK framing.
    pub capsule_padding_classes_bytes: Vec<NonZeroU32>,
    /// Maximum proof sidecar size per leg.
    pub max_proof_bytes: NonZeroU64,
    /// Maximum encrypted audit capsule size per leg.
    pub max_capsule_bytes: NonZeroU64,
    /// Maximum canonical sponsor-signed direct carrier transaction size.
    pub max_carrier_bytes: NonZeroU64,
    /// Minimum durable sidecar retention after admission, in blocks.
    pub sidecar_retention_blocks: NonZeroU64,
    /// Maximum encrypted settlement records retained by one local sidecar store.
    pub sidecar_max_records: NonZeroU32,
    /// Maximum canonical bytes retained by one local sidecar store.
    pub sidecar_max_total_bytes: NonZeroU64,
    /// Governed minimum online auditor threshold accepted for new policies.
    pub default_min_auditor_approvals: NonZeroU16,
    /// Audit-policy schema versions accepted by this deployment.
    pub permitted_policy_versions: BTreeSet<u16>,
}
impl_default!(NexusAtomicPrivateSettlement => {
        Self {
            enabled: defaults::nexus::atomic_private_settlement::ENABLED,
            activation_height: None,
            minimum_activation_notice_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::MINIMUM_ACTIVATION_NOTICE_BLOCKS,
            )
            .expect("private-settlement activation notice must be non-zero"),
            proof_profile_version: NonZeroU16::new(
                defaults::nexus::atomic_private_settlement::PROOF_PROFILE_VERSION,
            )
            .expect("private-settlement proof profile must be non-zero"),
            max_participants: NonZeroU16::new(
                defaults::nexus::atomic_private_settlement::MAX_PARTICIPANTS,
            )
            .expect("private-settlement participant bound must be non-zero"),
            max_expiry_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::MAX_EXPIRY_BLOCKS,
            )
            .expect("private-settlement expiry bound must be non-zero"),
            audit_timeout_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::AUDIT_TIMEOUT_BLOCKS,
            )
            .expect("private-settlement audit timeout must be non-zero"),
            prepare_timeout_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::PREPARE_TIMEOUT_BLOCKS,
            )
            .expect("private-settlement prepare timeout must be non-zero"),
            commit_timeout_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::COMMIT_TIMEOUT_BLOCKS,
            )
            .expect("private-settlement commit timeout must be non-zero"),
            capsule_padding_classes_bytes:
                defaults::nexus::atomic_private_settlement::CAPSULE_PADDING_CLASSES_BYTES
                    .into_iter()
                    .map(|bytes| NonZeroU32::new(bytes).expect("padding class must be non-zero"))
                    .collect(),
            max_proof_bytes: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::MAX_PROOF_BYTES,
            )
            .expect("private-settlement proof bound must be non-zero"),
            max_capsule_bytes: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::MAX_CAPSULE_BYTES,
            )
            .expect("private-settlement capsule bound must be non-zero"),
            max_carrier_bytes: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::MAX_CARRIER_BYTES,
            )
            .expect("private-settlement carrier bound must be non-zero"),
            sidecar_retention_blocks: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::SIDECAR_RETENTION_BLOCKS,
            )
            .expect("private-settlement sidecar retention must be non-zero"),
            sidecar_max_records: NonZeroU32::new(
                defaults::nexus::atomic_private_settlement::SIDECAR_MAX_RECORDS,
            )
            .expect("private-settlement sidecar record bound must be non-zero"),
            sidecar_max_total_bytes: NonZeroU64::new(
                defaults::nexus::atomic_private_settlement::SIDECAR_MAX_TOTAL_BYTES,
            )
            .expect("private-settlement sidecar byte bound must be non-zero"),
            default_min_auditor_approvals: NonZeroU16::new(
                defaults::nexus::atomic_private_settlement::DEFAULT_MIN_AUDITOR_APPROVALS,
            )
            .expect("private-settlement auditor threshold must be non-zero"),
            permitted_policy_versions:
                defaults::nexus::atomic_private_settlement::PERMITTED_POLICY_VERSIONS.into(),
        }
});
/// Storage component participating in Nexus disk budgeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NexusStorageBudgetComponent {
    /// Kura block storage.
    Kura,
    /// Tiered-state cold or DA-backed cold storage.
    WsvCold,
    /// SoraFS storage root.
    Sorafs,
}
impl NexusStorageBudgetComponent {
    /// Components in the deterministic split and remainder order.
    pub const ORDER: [Self; 3] = [Self::Kura, Self::WsvCold, Self::Sorafs];
    /// Stable string label used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kura => "kura",
            Self::WsvCold => "wsv_cold",
            Self::Sorafs => "sorafs",
        }
    }
    fn weight_bps(self, weights: NexusStorageWeights) -> u16 {
        match self {
            Self::Kura => weights.kura_blocks_bps,
            Self::WsvCold => weights.wsv_snapshots_bps,
            Self::Sorafs => weights.sorafs_bps,
        }
    }
}
impl fmt::Display for NexusStorageBudgetComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
/// One runtime-derived filesystem group inside the Nexus storage budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NexusStorageFilesystemBudget {
    /// Non-zero absolute budget derived for this filesystem group.
    pub budget_bytes: NonZeroU64,
    /// Components that share the filesystem, ordered deterministically.
    pub components: Vec<NexusStorageBudgetComponent>,
}
/// Failure to validate and aggregate runtime-derived filesystem storage budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NexusStorageBudgetApplicationError {
    /// Runtime derivation did not produce any filesystem budget group.
    #[error("runtime Nexus storage derivation produced no filesystem budget groups")]
    NoFilesystemBudgets,
    /// The checked sum of per-filesystem budgets exceeded `u64`.
    #[error("aggregate runtime Nexus storage budget overflowed u64")]
    AggregateOverflow,
    /// A filesystem group contains no managed storage components.
    #[error("runtime Nexus storage filesystem group {group_index} has no components")]
    EmptyComponentSet {
        /// Zero-based filesystem group index.
        group_index: usize,
    },
    /// Components within one filesystem group are not in strict canonical order.
    #[error(
        "runtime Nexus storage filesystem group {group_index} is not canonically ordered: {previous} precedes {current}"
    )]
    NonCanonicalComponentOrder {
        /// Zero-based filesystem group index.
        group_index: usize,
        /// Component immediately before the ordering violation.
        previous: NexusStorageBudgetComponent,
        /// Component at the ordering violation.
        current: NexusStorageBudgetComponent,
    },
    /// A component appears in more than one filesystem budget group.
    #[error("runtime Nexus storage component {component} appears in multiple filesystem groups")]
    DuplicateComponent {
        /// Repeated storage component.
        component: NexusStorageBudgetComponent,
    },
    /// A non-zero filesystem budget is too small to constrain one of its components.
    #[error(
        "runtime Nexus storage filesystem group {group_index} allocates zero bytes to {component}"
    )]
    ZeroComponentAllocation {
        /// Zero-based filesystem group index.
        group_index: usize,
        /// Component whose weighted cap would be zero (which means unlimited downstream).
        component: NexusStorageBudgetComponent,
    },
}
/// Storage budget configuration for Nexus nodes.
#[derive(Clone, Copy)]
pub struct NexusStorage {
    /// Operator-configured aggregate on-disk storage budget (bytes).
    ///
    /// `None` requests filesystem-aware runtime derivation by `irohad`.
    pub local_budget_bytes: Option<Bytes>,
    /// Effective aggregate on-disk storage budget enforced by this process (bytes).
    ///
    /// This actual-layer field is initialized from [`Self::local_budget_bytes`] when configured
    /// and otherwise populated from runtime filesystem probes by `irohad`.
    pub effective_local_budget_bytes: Option<Bytes>,
    /// Block interval between disk budget enforcement scans (0 = every block).
    pub budget_enforce_interval_blocks: u64,
    /// WSV hot-tier deterministic encoded-key plus measured-value budget (bytes).
    pub max_wsv_memory_bytes: Bytes,
    /// Finite shared pool for retained carrier World shells, effects and service descriptors.
    /// This is not an aggregate RAM or nested execution-payload limit; zero admits none.
    pub retained_carrier_shell_bytes: usize,
    /// Process-local prune-key and pending-penalty backing pool, distinct from carrier shells.
    pub consensus_evidence_preparation_bytes: usize,
    /// Process-local flat stake-index share-key backing pool.
    pub consensus_stake_index_bytes: usize,
    /// Budget weights for dividing the disk cap across subsystems.
    pub disk_budget_weights: NexusStorageWeights,
    pub(crate) configured_component_caps: Option<NexusStorageConfiguredComponentCaps>,
}
impl NexusStorage {
    /// Return the resolved source SoraFS capacity before Nexus budget clamping.
    ///
    /// `None` means no aggregate Nexus storage budget has captured component caps yet. This
    /// source value can be an explicit operator value or the generic default. The accessor lets
    /// fixed deployment profiles distinguish an exact source cap from a default, zero, or
    /// oversized value that normalizes to the same effective cap.
    #[must_use]
    pub fn configured_sorafs_max_capacity_bytes(&self) -> Option<Bytes> {
        self.configured_component_caps
            .map(|caps| caps.sorafs_max_capacity_bytes)
    }
}
impl fmt::Debug for NexusStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NexusStorage")
            .field("local_budget_bytes", &self.local_budget_bytes)
            .field(
                "effective_local_budget_bytes",
                &self.effective_local_budget_bytes,
            )
            .field(
                "budget_enforce_interval_blocks",
                &self.budget_enforce_interval_blocks,
            )
            .field("max_wsv_memory_bytes", &self.max_wsv_memory_bytes)
            .field(
                "retained_carrier_shell_bytes",
                &self.retained_carrier_shell_bytes,
            )
            .field(
                "consensus_evidence_preparation_bytes",
                &self.consensus_evidence_preparation_bytes,
            )
            .field(
                "consensus_stake_index_bytes",
                &self.consensus_stake_index_bytes,
            )
            .field("disk_budget_weights", &self.disk_budget_weights)
            .finish()
    }
}
impl_default!(NexusStorage => {
        Self {
            local_budget_bytes: None,
            effective_local_budget_bytes: None,
            budget_enforce_interval_blocks:
                defaults::nexus::storage::BUDGET_ENFORCE_INTERVAL_BLOCKS,
            max_wsv_memory_bytes: defaults::nexus::storage::MAX_WSV_MEMORY_BYTES,
            retained_carrier_shell_bytes: defaults::nexus::storage::RETAINED_CARRIER_SHELL_BYTES,
            consensus_evidence_preparation_bytes:
                defaults::nexus::storage::CONSENSUS_EVIDENCE_PREPARATION_BYTES,
            consensus_stake_index_bytes: defaults::nexus::storage::CONSENSUS_STAKE_INDEX_BYTES,
            disk_budget_weights: NexusStorageWeights::default(),
            configured_component_caps: None,
        }
});
/// Basis-point budget weights for Nexus storage subsystems.
#[derive(Debug, Clone, Copy)]
pub struct NexusStorageWeights {
    /// Budget share for Kura block storage (basis points).
    pub kura_blocks_bps: u16,
    /// Budget share for tiered-state cold snapshots (basis points).
    pub wsv_snapshots_bps: u16,
    /// Budget share for SoraFS storage (basis points).
    pub sorafs_bps: u16,
}
impl NexusStorageWeights {
    /// Total basis points across all weights.
    #[must_use]
    pub const fn total_bps(self) -> u32 {
        self.kura_blocks_bps as u32 + self.wsv_snapshots_bps as u32 + self.sorafs_bps as u32
    }
}
impl_default!(NexusStorageWeights => {
        Self {
            kura_blocks_bps: defaults::nexus::storage::KURA_BLOCKS_BPS,
            wsv_snapshots_bps: defaults::nexus::storage::WSV_SNAPSHOTS_BPS,
            sorafs_bps: defaults::nexus::storage::SORAFS_BPS,
        }
});
/// Nexus configuration describing lanes, data spaces, and routing policy.
#[derive(Debug, Clone)]
pub struct Nexus {
    /// Storage budget configuration for Nexus nodes.
    pub storage: NexusStorage,
    /// Staking guardrails for public lanes.
    pub staking: NexusStaking,
    /// Universal fee schedule for Nexus transactions.
    pub fees: NexusFees,
    /// Asynchronous lane-relay proof and sponsor-budget worker.
    pub relay_worker: NexusRelayWorker,
    /// Shared Hugging Face lease policy.
    pub hf_shared_leases: NexusHfSharedLeases,
    /// Uploaded-model registry quota policy.
    pub uploaded_models: NexusUploadedModels,
    /// Domain endorsement controls.
    pub endorsement: NexusEndorsement,
    /// AXT execution and expiry configuration.
    pub axt: NexusAxt,
    /// Governed atomic private cross-dataspace settlement policy.
    pub atomic_private_settlement: NexusAtomicPrivateSettlement,
    /// Validated lane catalog.
    pub lane_catalog: LaneCatalog,
    /// Immutable lane catalog loaded from configuration before runtime lifecycle replay.
    ///
    /// Runtime lane additions/removals mutate [`Self::lane_catalog`] but must never
    /// mutate this baseline, which is bound into the static consensus-policy digest.
    pub configured_lane_catalog: LaneCatalog,
    /// Derived storage/configuration geometry for lanes.
    pub lane_config: LaneConfig,
    /// Validated catalog of physical execution, storage, and validator boundaries.
    pub dataspace_catalog: DataSpaceCatalog,
    /// Immutable dataspace catalog loaded from configuration before committed catalog replay.
    ///
    /// Ledger-authorized additions mutate [`Self::dataspace_catalog`] without changing this
    /// baseline. The execution-policy digest binds this catalog; the per-height Nexus/AMX
    /// context binds the effective catalog and its committed authorization.
    pub configured_dataspace_catalog: DataSpaceCatalog,
    /// Default fee sponsor program for each data space.
    pub dataspace_fee_sponsor_program_ids: BTreeMap<DataSpaceId, FeeSponsorProgramId>,
    /// Lane routing policy.
    pub routing_policy: LaneRoutingPolicy,
    /// Lane manifest registry configuration.
    pub registry: LaneRegistry,
    /// Governance module catalog.
    pub governance: GovernanceCatalog,
    /// Lane compliance policy configuration.
    pub compliance: LaneCompliance,
    /// Lane-fusion tuning.
    pub fusion: Fusion,
    /// Deterministic lane autoscaling tuning.
    pub autoscale: Autoscale,
    /// Proof/commit deadline configuration.
    pub commit: Commit,
    /// Data-availability sampling configuration.
    pub da: Da,
}
impl_default!(#[allow(clippy::derivable_impls)] Nexus => {
        Self {
            storage: NexusStorage::default(),
            staking: NexusStaking::default(),
            fees: NexusFees::default(),
            relay_worker: NexusRelayWorker::default(),
            hf_shared_leases: NexusHfSharedLeases::default(),
            uploaded_models: NexusUploadedModels::default(),
            endorsement: NexusEndorsement::default(),
            axt: NexusAxt::default(),
            atomic_private_settlement: NexusAtomicPrivateSettlement::default(),
            lane_catalog: LaneCatalog::default(),
            configured_lane_catalog: LaneCatalog::default(),
            lane_config: LaneConfig::default(),
            dataspace_catalog: DataSpaceCatalog::default(),
            configured_dataspace_catalog: DataSpaceCatalog::default(),
            dataspace_fee_sponsor_program_ids: BTreeMap::new(),
            routing_policy: LaneRoutingPolicy::default(),
            registry: LaneRegistry::default(),
            governance: GovernanceCatalog::default(),
            compliance: LaneCompliance::default(),
            fusion: Fusion::default(),
            autoscale: Autoscale::default(),
            commit: Commit::default(),
            da: Da::default(),
        }
});
impl Nexus {
    /// Returns true when the catalog or routing policy deviates from the single-lane defaults.
    #[must_use]
    pub fn uses_multilane_catalogs(&self) -> bool {
        let policy = &self.routing_policy;
        let policy_is_default = policy.rules.is_empty()
            && policy.default_lane == LaneId::SINGLE
            && policy.default_dataspace == DataSpaceId::UNIVERSAL;
        let catalog_is_default = self.lane_catalog.lane_count().get() == 1
            && matches!(self.lane_catalog.lanes(), [lane] if lane.id == LaneId::SINGLE);
        let dataspace_is_default = matches!(
            self.dataspace_catalog.entries(),
            [entry] if entry.id == DataSpaceId::UNIVERSAL
        );
        !(policy_is_default && catalog_is_default && dataspace_is_default)
    }
    /// Validate the physical geometry of a single independently authenticated private root.
    ///
    /// This checks the actual/configured catalogs, derived storage geometry, routing and
    /// autoscale state only. The caller must separately authenticate its signed root scope
    /// and consensus mode; local configuration never supplies either authority.
    ///
    /// # Errors
    /// Rejects any geometry other than the exact restricted, fully replicated lane zero of
    /// `dataspace_id`, with no foreign physical catalog, route or elastic-lane state.
    pub fn validate_private_root_geometry(
        &self,
        dataspace_id: DataSpaceId,
    ) -> core::result::Result<(), &'static str> {
        if self.lane_catalog != self.configured_lane_catalog
            || self.dataspace_catalog != self.configured_dataspace_catalog
            || !self.lane_config.matches_catalog(&self.lane_catalog)
        {
            return Err("private root requires unchanged configured execution geometry");
        }
        if !matches!(self.dataspace_catalog.entries(), [entry] if entry.id == dataspace_id) {
            return Err(
                "private root requires exactly its signed dataspace in the physical catalog",
            );
        }
        let [lane] = self.lane_catalog.lanes() else {
            return Err("private root requires exactly one physical lane zero");
        };
        if self.lane_catalog.lane_count().get() != 1
            || lane.id != LaneId::SINGLE
            || lane.dataspace_id != dataspace_id
            || lane.visibility != LaneVisibility::Restricted
            || lane.storage != LaneStorageProfile::FullReplica
        {
            return Err(
                "private root requires its own restricted, fully replicated physical lane zero",
            );
        }
        let routing = &self.routing_policy;
        if routing.default_lane != LaneId::SINGLE
            || routing.default_dataspace != dataspace_id
            || routing.rules.iter().any(|rule| {
                rule.lane != LaneId::SINGLE
                    || rule.dataspace.is_some_and(|target| target != dataspace_id)
            })
        {
            return Err(
                "private root routing must remain inside its signed dataspace and lane zero",
            );
        }
        if self.autoscale.enabled
            || self.autoscale.last_transition_height != 0
            || [
                iroha_data_model::nexus::AUTOSCALE_META_MANAGED,
                iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT,
                iroha_data_model::nexus::AUTOSCALE_META_DRAIN_STATE,
                iroha_data_model::nexus::AUTOSCALE_META_COMMITTEE,
            ]
            .iter()
            .any(|key| lane.metadata.contains_key(*key))
        {
            return Err("private root cannot contain autoscale or elastic-lane state");
        }
        Ok(())
    }
    /// Returns true when any lane/dataspace/routing overrides are present (even in single-lane mode).
    #[must_use]
    pub fn has_lane_overrides(&self) -> bool {
        self.lane_catalog != LaneCatalog::default()
            || self.configured_lane_catalog != LaneCatalog::default()
            || self.dataspace_catalog != DataSpaceCatalog::default()
            || self.configured_dataspace_catalog != DataSpaceCatalog::default()
            || !self.dataspace_fee_sponsor_program_ids.is_empty()
            || self.routing_policy != LaneRoutingPolicy::default()
    }
}
/// Error returned when a Nexus consensus-policy digest cannot be constructed safely.
#[derive(Debug, Clone, Copy, PartialEq, Error)]
pub enum NexusConsensusPolicyDigestError {
    /// A floating-point policy input was not a finite, positive number.
    #[error(
        "Nexus consensus-policy field `{field}` must be finite and greater than zero, got {value}"
    )]
    InvalidRatio {
        /// Configuration field containing the invalid value.
        field: &'static str,
        /// Invalid floating-point value.
        value: f64,
    },
    /// A floating-point policy input was not finite.
    #[error("Nexus consensus-policy field `{field}` must be finite, got {value}")]
    NonFinite {
        /// Configuration field containing the invalid value.
        field: &'static str,
        /// Invalid floating-point value.
        value: f64,
    },
    /// A floating-point policy input was outside the inclusive unit interval.
    #[error("Nexus consensus-policy field `{field}` must be within [0, 1], got {value}")]
    InvalidUnitRatio {
        /// Configuration field containing the invalid value.
        field: &'static str,
        /// Invalid floating-point value.
        value: f64,
    },
    /// Compliance enforcement was enabled without binding the loaded policy set.
    #[error("Nexus compliance is enabled but no loaded policy-set digest was supplied")]
    MissingCompliancePolicyDigest,
}
#[derive(Encode)]
struct NexusConsensusPolicyPreimageV1 {
    version: u8,
    configured_lane_catalog_hash: [u8; 32],
    dataspaces: Vec<NexusConsensusDataspaceV1>,
    dataspace_fee_sponsor_program_ids: Vec<(u64, FeeSponsorProgramId)>,
    routing: NexusConsensusRoutingV1,
    staking: NexusConsensusStakingV1,
    fees: NexusConsensusFeesV1,
    hf_shared_leases: NexusConsensusHfSharedLeasesV1,
    uploaded_models: NexusConsensusUploadedModelsV1,
    endorsement: NexusConsensusEndorsementV1,
    axt: NexusConsensusAxtV1,
    atomic_private_settlement: NexusConsensusAtomicPrivateSettlementV1,
    governance: NexusConsensusGovernanceV1,
    compliance_enabled: bool,
    compliance_audit_only: bool,
    compliance_policy_digest: Option<[u8; 32]>,
    lane_manifest_policy_digest: Option<[u8; 32]>,
    fusion: NexusConsensusFusionV1,
    autoscale: NexusConsensusAutoscaleV1,
    commit_window_slots: u16,
    da: NexusConsensusDaV1,
}
#[derive(Encode)]
struct NexusConsensusDataspaceV1 {
    id: u64,
    alias: String,
    fault_tolerance: u32,
}
#[derive(Encode)]
struct NexusConsensusRoutingV1 {
    default_lane: u32,
    default_dataspace: u64,
    rules: Vec<NexusConsensusRoutingRuleV1>,
}
#[derive(Encode)]
struct NexusConsensusRoutingRuleV1 {
    lane: u32,
    dataspace: Option<u64>,
    account: Option<String>,
    instruction: Option<String>,
}
#[derive(Encode)]
struct NexusConsensusDurationV1 {
    seconds: u64,
    nanoseconds: u32,
}
#[derive(Encode)]
struct NexusConsensusStakingV1 {
    public_validator_mode: u8,
    restricted_validator_mode: u8,
    min_validator_stake: Quantity,
    max_validators: u32,
    max_stake_shares_per_validator: u32,
    max_pending_unbonds_per_share: u32,
    unbonding_delay: NexusConsensusDurationV1,
    max_slash_bps: u16,
    stake_asset_id: String,
    stake_escrow_account_id: String,
    slash_sink_account_id: String,
}
#[derive(Encode)]
struct NexusConsensusFeesV1 {
    fee_asset_id: String,
    fee_sink_account_id: String,
    base_fee: Quantity,
    per_byte_fee: Quantity,
    per_instruction_fee: Quantity,
    per_gas_unit_fee: Quantity,
    sponsor_vault_custody_account_id: AccountId,
    settlement_mode: u8,
    successful_claim_fee_exempt_authorities: Vec<String>,
}
#[derive(Encode)]
struct NexusConsensusHfSharedLeasesV1 {
    drain_grace: NexusConsensusDurationV1,
}
#[derive(Encode)]
struct NexusConsensusUploadedModelsV1 {
    max_plaintext_bytes_per_model: u64,
    max_chunk_count_per_model: u32,
}
#[derive(Encode)]
struct NexusConsensusEndorsementV1 {
    committee_keys: Vec<String>,
    quorum: u16,
}
#[derive(Encode)]
struct NexusConsensusAxtV1 {
    slot_length_ms: u64,
    max_clock_skew_ms: u64,
    proof_cache_ttl_slots: u64,
    replay_retention_slots: u64,
}
#[derive(Encode)]
struct NexusConsensusAtomicPrivateSettlementV1 {
    enabled: bool,
    activation_height: Option<u64>,
    minimum_activation_notice_blocks: u64,
    proof_profile_version: u16,
    max_participants: u16,
    max_expiry_blocks: u64,
    audit_timeout_blocks: u64,
    prepare_timeout_blocks: u64,
    commit_timeout_blocks: u64,
    capsule_padding_classes_bytes: Vec<u32>,
    max_proof_bytes: u64,
    max_capsule_bytes: u64,
    max_carrier_bytes: u64,
    sidecar_retention_blocks: u64,
    sidecar_max_records: u32,
    sidecar_max_total_bytes: u64,
    default_min_auditor_approvals: u16,
    permitted_policy_versions: Vec<u16>,
}
#[derive(Encode)]
struct NexusConsensusGovernanceV1 {
    default_module: Option<String>,
    modules: Vec<NexusConsensusGovernanceModuleV1>,
}
#[derive(Encode)]
struct NexusConsensusGovernanceModuleV1 {
    name: String,
    module_type: Option<String>,
    params: Vec<(String, String)>,
}
#[derive(Encode)]
struct NexusConsensusFusionV1 {
    floor_teu: u32,
    exit_teu: u32,
    observation_slots: u16,
    max_window_slots: u16,
}
#[derive(Encode)]
struct NexusConsensusAutoscaleV1 {
    enabled: bool,
    min_lane_id: u32,
    max_lane_id_exclusive: u32,
    target_block_ms: u64,
    scale_out_latency_ratio_bits: u64,
    scale_in_latency_ratio_bits: u64,
    scale_out_utilization_ratio_bits: u64,
    scale_in_utilization_ratio_bits: u64,
    scale_out_window_blocks: u16,
    scale_in_window_blocks: u16,
    cooldown_blocks: u16,
    per_lane_target_tps: u32,
}
#[derive(Encode)]
struct NexusConsensusDaV1 {
    q_in_slot_total: u32,
    q_in_slot_per_ds_min: u16,
    sample_size_base: u16,
    sample_size_max: u16,
    threshold_base: u16,
    per_attester_shards: u16,
    ingest_quota_window_blocks: u64,
    ingest_quota_max_count_per_account: u64,
    ingest_quota_max_bytes_per_account: u64,
    audit_sample_size: u16,
    audit_window_count: u16,
    audit_interval: NexusConsensusDurationV1,
    recovery_request_timeout: NexusConsensusDurationV1,
    rotation_max_hits_per_window: u16,
    rotation_window_slots: u16,
    rotation_seed_tag: String,
    rotation_latency_decay_bits: u64,
}
impl From<Duration> for NexusConsensusDurationV1 {
    fn from(value: Duration) -> Self {
        Self {
            seconds: value.as_secs(),
            nanoseconds: value.subsec_nanos(),
        }
    }
}
const fn lane_validator_mode_tag(mode: LaneValidatorMode) -> u8 {
    match mode {
        LaneValidatorMode::StakeElected => 0,
        LaneValidatorMode::AdminManaged => 1,
    }
}
const fn nexus_fee_settlement_mode_tag(mode: NexusFeeSettlementMode) -> u8 {
    match mode {
        NexusFeeSettlementMode::Direct => 0,
        NexusFeeSettlementMode::LaneRelayBurn => 1,
    }
}
fn nexus_consensus_ratio_bits(
    field: &'static str,
    value: f64,
) -> core::result::Result<u64, NexusConsensusPolicyDigestError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(NexusConsensusPolicyDigestError::InvalidRatio { field, value });
    }
    Ok(value.to_bits())
}
fn nexus_consensus_finite_bits(
    field: &'static str,
    value: f64,
) -> core::result::Result<u64, NexusConsensusPolicyDigestError> {
    if !value.is_finite() {
        return Err(NexusConsensusPolicyDigestError::NonFinite { field, value });
    }
    Ok(value.to_bits())
}
fn nexus_consensus_unit_ratio_bits(
    field: &'static str,
    value: f64,
) -> core::result::Result<u64, NexusConsensusPolicyDigestError> {
    let bits = nexus_consensus_finite_bits(field, value)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(NexusConsensusPolicyDigestError::InvalidUnitRatio { field, value });
    }
    Ok(bits)
}
/// Compute the canonical digest of deterministic, locally configured Nexus policy.
///
/// The preimage is Norito-encoded, explicitly versioned, and domain-separated. Floating-point
/// autoscale inputs are admitted only when finite and positive, then committed by their exact IEEE
/// 754 bit patterns. The consensus-replayed lane catalog and
/// [`Autoscale::last_transition_height`] are deliberately excluded: peers at different committed
/// heights must be able to connect and synchronize those dynamic values. The immutable configured
/// lane-catalog baseline is committed separately from that runtime topology. The statically
/// configured dataspace catalog (including committee fault tolerance), routing, staking, fees, AXT,
/// governance, fusion, autoscale, commit-window, and DA policy remain committed. Local storage
/// budgets, relay-worker scheduling, manifest filesystem paths, and compliance filesystem
/// locations are intentionally excluded because path placement is not a protocol input; loaded
/// compliance and lane-manifest policy-set digests are bound separately.
#[cfg(test)]
pub fn nexus_consensus_policy_digest(
    nexus: &Nexus,
) -> core::result::Result<[u8; 32], NexusConsensusPolicyDigestError> {
    nexus_consensus_policy_digest_with_compliance(nexus, None)
}
/// Compute the canonical Nexus policy digest while binding the loaded compliance policy set.
///
/// `compliance_policy_digest` is required whenever [`LaneCompliance::enabled`] is true so two
/// validators cannot execute the same transaction against different filesystem policy bundles.
#[cfg(test)]
pub fn nexus_consensus_policy_digest_with_compliance(
    nexus: &Nexus,
    compliance_policy_digest: Option<[u8; 32]>,
) -> core::result::Result<[u8; 32], NexusConsensusPolicyDigestError> {
    nexus_consensus_policy_digest_with_runtime_policies(nexus, compliance_policy_digest, None)
}
/// Compute the canonical Nexus digest with loaded compliance and lane-manifest policy sets.
///
/// Passing `None` for a policy set commits that absence, so it cannot match a validator that loaded
/// a concrete registry digest. Runtime callers should always pass the installed lane-manifest
/// digest, including for an empty registry.
pub fn nexus_consensus_policy_digest_with_runtime_policies(
    nexus: &Nexus,
    compliance_policy_digest: Option<[u8; 32]>,
    lane_manifest_policy_digest: Option<[u8; 32]>,
) -> core::result::Result<[u8; 32], NexusConsensusPolicyDigestError> {
    const DOMAIN: &[u8] = b"iroha:nexus:consensus-policy:v1\0";
    let encoded = nexus_consensus_policy_preimage_with_runtime_policies(
        nexus,
        compliance_policy_digest,
        lane_manifest_policy_digest,
    )?;
    Ok(Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()]).into())
}
/// Return the exact bare Norito V1 preimage used by the Nexus consensus-policy digest.
///
/// This makes the complete static policy value available to the State authority
/// owner without duplicating the digest's field selection. Encoding fixes the
/// V1 flags, so ambient codec settings cannot alter peer policy identity.
/// Dynamic effective lanes, committed dataspaces, and autoscale history remain
/// separate canonical runtime/World authority.
///
/// # Errors
/// Rejects invalid floating-point policy or an enabled compliance policy with
/// no authenticated policy-set digest.
pub fn nexus_consensus_policy_preimage_with_runtime_policies(
    nexus: &Nexus,
    compliance_policy_digest: Option<[u8; 32]>,
    lane_manifest_policy_digest: Option<[u8; 32]>,
) -> core::result::Result<Vec<u8>, NexusConsensusPolicyDigestError> {
    const CONFIGURED_LANE_CATALOG_DOMAIN: &[u8] = b"iroha:nexus:configured-lane-catalog:v1\0";
    const VERSION: u8 = 1;
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    if nexus.compliance.enabled && compliance_policy_digest.is_none() {
        return Err(NexusConsensusPolicyDigestError::MissingCompliancePolicyDigest);
    }
    let rules = nexus
        .routing_policy
        .rules
        .iter()
        .map(|rule| NexusConsensusRoutingRuleV1 {
            lane: rule.lane.as_u32(),
            dataspace: rule.dataspace.map(DataSpaceId::as_u64),
            account: rule.matcher.account.clone(),
            instruction: rule.matcher.instruction.clone(),
        })
        .collect();
    let mut dataspaces = nexus
        .configured_dataspace_catalog
        .entries()
        .iter()
        .map(|entry| NexusConsensusDataspaceV1 {
            id: entry.id.as_u64(),
            alias: entry.alias.clone(),
            fault_tolerance: entry.fault_tolerance,
        })
        .collect::<Vec<_>>();
    dataspaces.sort_unstable_by_key(|entry| entry.id);
    let dataspace_fee_sponsor_program_ids = nexus
        .dataspace_fee_sponsor_program_ids
        .iter()
        .map(|(id, program_id)| (id.as_u64(), program_id.clone()))
        .collect();
    let successful_claim_fee_exempt_authorities = nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .iter()
        .map(|authority| {
            authority
                .canonical_i105()
                .expect("validated Nexus fee-exempt authority must encode as canonical I105")
        })
        .collect();
    let endorsement_committee_keys = nexus
        .endorsement
        .committee_keys
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let governance_modules = nexus
        .governance
        .modules
        .iter()
        .map(|(name, module)| NexusConsensusGovernanceModuleV1 {
            name: name.clone(),
            module_type: module.module_type.clone(),
            params: module
                .params
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        })
        .collect();
    let autoscale = &nexus.autoscale;
    let configured_lane_catalog = nexus
        .configured_lane_catalog
        .consensus_projection()
        .encode();
    let preimage = NexusConsensusPolicyPreimageV1 {
        version: VERSION,
        configured_lane_catalog_hash: Hash::new_from_chunks(&[
            CONFIGURED_LANE_CATALOG_DOMAIN,
            configured_lane_catalog.as_slice(),
        ])
        .into(),
        dataspaces,
        dataspace_fee_sponsor_program_ids,
        routing: NexusConsensusRoutingV1 {
            default_lane: nexus.routing_policy.default_lane.as_u32(),
            default_dataspace: nexus.routing_policy.default_dataspace.as_u64(),
            rules,
        },
        staking: NexusConsensusStakingV1 {
            public_validator_mode: lane_validator_mode_tag(nexus.staking.public_validator_mode),
            restricted_validator_mode: lane_validator_mode_tag(
                nexus.staking.restricted_validator_mode,
            ),
            min_validator_stake: nexus.staking.min_validator_stake.clone(),
            max_validators: nexus.staking.max_validators.get(),
            max_stake_shares_per_validator: nexus.staking.max_stake_shares_per_validator.get(),
            max_pending_unbonds_per_share: nexus.staking.max_pending_unbonds_per_share.get(),
            unbonding_delay: nexus.staking.unbonding_delay.into(),
            max_slash_bps: nexus.staking.max_slash_bps,
            stake_asset_id: nexus.staking.stake_asset_id.clone(),
            stake_escrow_account_id: nexus.staking.stake_escrow_account_id.clone(),
            slash_sink_account_id: nexus.staking.slash_sink_account_id.clone(),
        },
        fees: NexusConsensusFeesV1 {
            fee_asset_id: nexus.fees.fee_asset_id.clone(),
            fee_sink_account_id: nexus.fees.fee_sink_account_id.clone(),
            base_fee: nexus.fees.base_fee.clone(),
            per_byte_fee: nexus.fees.per_byte_fee.clone(),
            per_instruction_fee: nexus.fees.per_instruction_fee.clone(),
            per_gas_unit_fee: nexus.fees.per_gas_unit_fee.clone(),
            sponsor_vault_custody_account_id: nexus.fees.sponsor_vault_custody_account_id.clone(),
            settlement_mode: nexus_fee_settlement_mode_tag(nexus.fees.settlement_mode),
            successful_claim_fee_exempt_authorities,
        },
        hf_shared_leases: NexusConsensusHfSharedLeasesV1 {
            drain_grace: nexus.hf_shared_leases.drain_grace.into(),
        },
        uploaded_models: NexusConsensusUploadedModelsV1 {
            max_plaintext_bytes_per_model: nexus.uploaded_models.max_plaintext_bytes_per_model,
            max_chunk_count_per_model: nexus.uploaded_models.max_chunk_count_per_model,
        },
        endorsement: NexusConsensusEndorsementV1 {
            committee_keys: endorsement_committee_keys,
            quorum: nexus.endorsement.quorum,
        },
        axt: NexusConsensusAxtV1 {
            slot_length_ms: nexus.axt.slot_length_ms.get(),
            max_clock_skew_ms: nexus.axt.max_clock_skew_ms,
            proof_cache_ttl_slots: nexus.axt.proof_cache_ttl_slots.get(),
            replay_retention_slots: nexus.axt.replay_retention_slots.get(),
        },
        atomic_private_settlement: NexusConsensusAtomicPrivateSettlementV1 {
            enabled: nexus.atomic_private_settlement.enabled,
            activation_height: nexus.atomic_private_settlement.activation_height,
            minimum_activation_notice_blocks: nexus
                .atomic_private_settlement
                .minimum_activation_notice_blocks
                .get(),
            proof_profile_version: nexus.atomic_private_settlement.proof_profile_version.get(),
            max_participants: nexus.atomic_private_settlement.max_participants.get(),
            max_expiry_blocks: nexus.atomic_private_settlement.max_expiry_blocks.get(),
            audit_timeout_blocks: nexus.atomic_private_settlement.audit_timeout_blocks.get(),
            prepare_timeout_blocks: nexus.atomic_private_settlement.prepare_timeout_blocks.get(),
            commit_timeout_blocks: nexus.atomic_private_settlement.commit_timeout_blocks.get(),
            capsule_padding_classes_bytes: nexus
                .atomic_private_settlement
                .capsule_padding_classes_bytes
                .iter()
                .map(|bytes| bytes.get())
                .collect(),
            max_proof_bytes: nexus.atomic_private_settlement.max_proof_bytes.get(),
            max_capsule_bytes: nexus.atomic_private_settlement.max_capsule_bytes.get(),
            max_carrier_bytes: nexus.atomic_private_settlement.max_carrier_bytes.get(),
            sidecar_retention_blocks: nexus
                .atomic_private_settlement
                .sidecar_retention_blocks
                .get(),
            sidecar_max_records: nexus.atomic_private_settlement.sidecar_max_records.get(),
            sidecar_max_total_bytes: nexus
                .atomic_private_settlement
                .sidecar_max_total_bytes
                .get(),
            default_min_auditor_approvals: nexus
                .atomic_private_settlement
                .default_min_auditor_approvals
                .get(),
            permitted_policy_versions: nexus
                .atomic_private_settlement
                .permitted_policy_versions
                .iter()
                .copied()
                .collect(),
        },
        governance: NexusConsensusGovernanceV1 {
            default_module: nexus.governance.default_module.clone(),
            modules: governance_modules,
        },
        compliance_enabled: nexus.compliance.enabled,
        compliance_audit_only: nexus.compliance.audit_only,
        compliance_policy_digest,
        lane_manifest_policy_digest,
        fusion: NexusConsensusFusionV1 {
            floor_teu: nexus.fusion.floor_teu,
            exit_teu: nexus.fusion.exit_teu,
            observation_slots: nexus.fusion.observation_slots.get(),
            max_window_slots: nexus.fusion.max_window_slots.get(),
        },
        autoscale: NexusConsensusAutoscaleV1 {
            enabled: autoscale.enabled,
            min_lane_id: autoscale.min_lane_id.get(),
            max_lane_id_exclusive: autoscale.max_lane_id_exclusive.get(),
            target_block_ms: autoscale.target_block_ms.get(),
            scale_out_latency_ratio_bits: nexus_consensus_ratio_bits(
                "nexus.autoscale.scale_out_latency_ratio",
                autoscale.scale_out_latency_ratio,
            )?,
            scale_in_latency_ratio_bits: nexus_consensus_ratio_bits(
                "nexus.autoscale.scale_in_latency_ratio",
                autoscale.scale_in_latency_ratio,
            )?,
            scale_out_utilization_ratio_bits: nexus_consensus_ratio_bits(
                "nexus.autoscale.scale_out_utilization_ratio",
                autoscale.scale_out_utilization_ratio,
            )?,
            scale_in_utilization_ratio_bits: nexus_consensus_ratio_bits(
                "nexus.autoscale.scale_in_utilization_ratio",
                autoscale.scale_in_utilization_ratio,
            )?,
            scale_out_window_blocks: autoscale.scale_out_window_blocks.get(),
            scale_in_window_blocks: autoscale.scale_in_window_blocks.get(),
            cooldown_blocks: autoscale.cooldown_blocks.get(),
            per_lane_target_tps: autoscale.per_lane_target_tps.get(),
        },
        commit_window_slots: nexus.commit.window_slots.get(),
        da: NexusConsensusDaV1 {
            q_in_slot_total: nexus.da.q_in_slot_total.get(),
            q_in_slot_per_ds_min: nexus.da.q_in_slot_per_ds_min.get(),
            sample_size_base: nexus.da.sample_size_base.get(),
            sample_size_max: nexus.da.sample_size_max.get(),
            threshold_base: nexus.da.threshold_base.get(),
            per_attester_shards: nexus.da.per_attester_shards.get(),
            ingest_quota_window_blocks: nexus.da.ingest_quota_window_blocks.get(),
            ingest_quota_max_count_per_account: nexus.da.ingest_quota_max_count_per_account.get(),
            ingest_quota_max_bytes_per_account: nexus.da.ingest_quota_max_bytes_per_account.get(),
            audit_sample_size: nexus.da.audit.sample_size.get(),
            audit_window_count: nexus.da.audit.window_count.get(),
            audit_interval: nexus.da.audit.interval.into(),
            recovery_request_timeout: nexus.da.recovery.request_timeout.into(),
            rotation_max_hits_per_window: nexus.da.rotation.max_hits_per_window.get(),
            rotation_window_slots: nexus.da.rotation.window_slots.get(),
            rotation_seed_tag: nexus.da.rotation.seed_tag.clone(),
            rotation_latency_decay_bits: nexus_consensus_unit_ratio_bits(
                "nexus.da.rotation.latency_decay",
                nexus.da.rotation.latency_decay,
            )?,
        },
    };
    Ok(preimage.encode())
}
#[derive(Encode)]
struct ExecutionPolicyFieldV1 {
    name: String,
    value: Vec<u8>,
}
#[derive(Encode)]
struct ExecutionPolicyPreimageV1 {
    version: u16,
    fields: Vec<ExecutionPolicyFieldV1>,
}
#[derive(Default)]
struct ExecutionPolicyFieldsV1 {
    fields: Vec<ExecutionPolicyFieldV1>,
}
impl ExecutionPolicyFieldsV1 {
    fn push<T: Encode>(&mut self, name: &'static str, value: &T) {
        self.fields.push(ExecutionPolicyFieldV1 {
            name: name.to_owned(),
            value: value.encode(),
        });
    }
}
fn execution_policy_usize(value: usize) -> u64 {
    u64::try_from(value)
        .expect("Iroha execution policy requires a pointer width of at most 64 bits")
}
fn execution_policy_duration(value: Duration) -> (u64, u32) {
    (value.as_secs(), value.subsec_nanos())
}
fn execution_policy_canonical_set<'a, T: Encode + 'a>(
    values: impl IntoIterator<Item = &'a T>,
) -> Vec<Vec<u8>> {
    let mut encoded = values.into_iter().map(Encode::encode).collect::<Vec<_>>();
    encoded.sort_unstable();
    encoded.dedup();
    encoded
}
/// Compute the canonical first-release identity of process-local execution policy.
///
/// The digest covers every boot-snapshot value which can change transaction admission,
/// deterministic execution effects, trigger behavior, or block replay. Loaded policy bundles are
/// supplied as canonical digests so filesystem placement never becomes consensus state.
///
/// Deliberately excluded values are limited to operational implementations which must preserve
/// identical results: worker and cache sizing, parallel/GPU selection, signature batch sizing,
/// tracing and telemetry, service endpoints and request timeouts, gateway-only content limits,
/// filesystem paths, and settlement artifact locations. Quarantine execution has no wall-clock
/// validity setting because consensus execution is cycle-bounded and must never branch on elapsed
/// host time.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn execution_policy_digest_v1(
    pipeline: &Pipeline,
    oracle: &Oracle,
    crypto: &Crypto,
    fraud_monitoring: &FraudMonitoring,
    governance: &Governance,
    content: &Content,
    settlement: &Settlement,
    nexus_policy_digest: [u8; 32],
    zk_policy_digest: [u8; 32],
) -> [u8; 32] {
    const DOMAIN: &[u8] = b"iroha:execution-policy:v1\0";
    const VERSION: u16 = 1;
    let mut policy = ExecutionPolicyFieldsV1::default();
    // Pipeline validity and deterministic-effect boundaries. Parallelism, caches, tracing,
    // acceleration selection, and exact signature batching are implementation details.
    policy.push("pipeline.dynamic_prepass", &pipeline.dynamic_prepass);
    policy.push(
        "pipeline.overlay_max_instructions",
        &execution_policy_usize(pipeline.overlay_max_instructions),
    );
    policy.push("pipeline.overlay_max_bytes", &pipeline.overlay_max_bytes);
    policy.push(
        "pipeline.overlay_chunk_instructions",
        &execution_policy_usize(pipeline.overlay_chunk_instructions),
    );
    policy.push(
        "pipeline.gas.tech_account_id",
        &pipeline.gas.tech_account_id,
    );
    policy.push(
        "pipeline.gas.accepted_assets",
        &execution_policy_canonical_set(pipeline.gas.accepted_assets.iter()),
    );
    let gas_rates = pipeline
        .gas
        .units_per_gas
        .iter()
        .map(|rate| {
            (
                rate.asset.clone(),
                rate.units_per_gas,
                rate.twap_local_per_xor.clone(),
                match rate.liquidity {
                    GasLiquidity::Tier1 => 1_u8,
                    GasLiquidity::Tier2 => 2,
                    GasLiquidity::Tier3 => 3,
                },
                match rate.volatility {
                    GasVolatility::Stable => 1_u8,
                    GasVolatility::Elevated => 2,
                    GasVolatility::Dislocated => 3,
                },
            )
        })
        .collect::<Vec<_>>();
    policy.push("pipeline.gas.units_per_gas", &gas_rates);
    policy.push(
        "pipeline.ivm_max_cycles_upper_bound",
        &pipeline.ivm_max_cycles_upper_bound.get(),
    );
    policy.push(
        "pipeline.ivm_max_decoded_instructions",
        &pipeline.ivm_max_decoded_instructions,
    );
    policy.push(
        "pipeline.ivm_max_decoded_bytes",
        &pipeline.ivm_max_decoded_bytes,
    );
    policy.push(
        "pipeline.quarantine_max_txs_per_block",
        &execution_policy_usize(pipeline.quarantine_max_txs_per_block),
    );
    policy.push(
        "pipeline.quarantine_tx_max_cycles",
        &pipeline.quarantine_tx_max_cycles,
    );
    policy.push(
        "pipeline.query_max_fetch_size",
        &pipeline.query_max_fetch_size,
    );
    policy.push(
        "pipeline.query_stored_min_gas_units",
        &pipeline.query_stored_min_gas_units,
    );
    policy.push(
        "pipeline.amx_per_dataspace_budget_ms",
        &pipeline.amx_per_dataspace_budget_ms,
    );
    policy.push(
        "pipeline.amx_group_budget_ms",
        &pipeline.amx_group_budget_ms,
    );
    policy.push(
        "pipeline.amx_per_instruction_ns",
        &pipeline.amx_per_instruction_ns,
    );
    policy.push(
        "pipeline.amx_per_memory_access_ns",
        &pipeline.amx_per_memory_access_ns,
    );
    policy.push("pipeline.amx_per_syscall_ns", &pipeline.amx_per_syscall_ns);
    // Cryptographic admission and host-surface policy. Backend selection is operational.
    policy.push("crypto.default_hash", &crypto.default_hash);
    policy.push(
        "crypto.allowed_signing",
        &execution_policy_canonical_set(crypto.allowed_signing.iter()),
    );
    policy.push("crypto.sm2_distid_default", &crypto.sm2_distid_default);
    let mut allowed_curve_ids = crypto.allowed_curve_ids.clone();
    allowed_curve_ids.sort_unstable();
    allowed_curve_ids.dedup();
    policy.push("crypto.allowed_curve_ids", &allowed_curve_ids);
    // Oracle state transitions, economics, governance, and binding admission.
    policy.push(
        "oracle.history_depth",
        &execution_policy_usize(oracle.history_depth.get()),
    );
    let economics = &oracle.economics;
    policy.push("oracle.economics.reward_asset", &economics.reward_asset);
    policy.push("oracle.economics.reward_pool", &economics.reward_pool);
    policy.push("oracle.economics.reward_amount", &economics.reward_amount);
    policy.push("oracle.economics.slash_asset", &economics.slash_asset);
    policy.push("oracle.economics.slash_receiver", &economics.slash_receiver);
    policy.push(
        "oracle.economics.slash_outlier_amount",
        &economics.slash_outlier_amount,
    );
    policy.push(
        "oracle.economics.slash_error_amount",
        &economics.slash_error_amount,
    );
    policy.push(
        "oracle.economics.slash_no_show_amount",
        &economics.slash_no_show_amount,
    );
    policy.push(
        "oracle.economics.dispute_bond_asset",
        &economics.dispute_bond_asset,
    );
    policy.push(
        "oracle.economics.dispute_bond_amount",
        &economics.dispute_bond_amount,
    );
    policy.push(
        "oracle.economics.dispute_reward_amount",
        &economics.dispute_reward_amount,
    );
    policy.push(
        "oracle.economics.frivolous_slash_amount",
        &economics.frivolous_slash_amount,
    );
    let oracle_governance = oracle.governance;
    policy.push(
        "oracle.governance.intake_sla_blocks",
        &oracle_governance.intake_sla_blocks,
    );
    policy.push(
        "oracle.governance.rules_sla_blocks",
        &oracle_governance.rules_sla_blocks,
    );
    policy.push(
        "oracle.governance.cop_sla_blocks",
        &oracle_governance.cop_sla_blocks,
    );
    policy.push(
        "oracle.governance.technical_sla_blocks",
        &oracle_governance.technical_sla_blocks,
    );
    policy.push(
        "oracle.governance.policy_jury_sla_blocks",
        &oracle_governance.policy_jury_sla_blocks,
    );
    policy.push(
        "oracle.governance.enact_sla_blocks",
        &oracle_governance.enact_sla_blocks,
    );
    policy.push(
        "oracle.governance.intake_min_votes",
        &execution_policy_usize(oracle_governance.intake_min_votes.get()),
    );
    policy.push(
        "oracle.governance.rules_min_votes",
        &execution_policy_usize(oracle_governance.rules_min_votes.get()),
    );
    policy.push(
        "oracle.governance.cop_min_votes",
        &(
            execution_policy_usize(oracle_governance.cop_min_votes.low.get()),
            execution_policy_usize(oracle_governance.cop_min_votes.medium.get()),
            execution_policy_usize(oracle_governance.cop_min_votes.high.get()),
        ),
    );
    policy.push(
        "oracle.governance.technical_min_votes",
        &execution_policy_usize(oracle_governance.technical_min_votes.get()),
    );
    policy.push(
        "oracle.governance.policy_jury_min_votes",
        &(
            execution_policy_usize(oracle_governance.policy_jury_min_votes.low.get()),
            execution_policy_usize(oracle_governance.policy_jury_min_votes.medium.get()),
            execution_policy_usize(oracle_governance.policy_jury_min_votes.high.get()),
        ),
    );
    let twitter = &oracle.twitter_binding;
    policy.push("oracle.twitter_binding.feed_id", &twitter.feed_id);
    policy.push("oracle.twitter_binding.pepper_id", &twitter.pepper_id);
    policy.push("oracle.twitter_binding.max_ttl_ms", &twitter.max_ttl_ms);
    policy.push("oracle.twitter_binding.min_ttl_ms", &twitter.min_ttl_ms);
    policy.push(
        "oracle.twitter_binding.min_update_spacing_ms",
        &twitter.min_update_spacing_ms,
    );
    // Fraud transport and timeout settings only obtain assessments. Consensus binds the
    // deterministic metadata gate, its grace semantics, and the attester trust set.
    policy.push("fraud.enabled", &fraud_monitoring.enabled);
    policy.push(
        "fraud.required_minimum_band",
        &fraud_monitoring
            .required_minimum_band
            .map(|band| match band {
                FraudRiskBand::Low => 1_u8,
                FraudRiskBand::Medium => 2,
                FraudRiskBand::High => 3,
                FraudRiskBand::Critical => 4,
            }),
    );
    policy.push(
        "fraud.missing_assessment_permitted",
        &(!fraud_monitoring.missing_assessment_grace.is_zero()),
    );
    let fraud_attesters = fraud_monitoring
        .attesters
        .iter()
        .map(|attester| (attester.engine_id.clone(), attester.public_key.clone()))
        .collect::<Vec<_>>();
    policy.push(
        "fraud.attesters",
        &execution_policy_canonical_set(fraud_attesters.iter()),
    );
    // Governance fields that drive admission, tallying, slashing, on-chain policy and triggers.
    policy.push(
        "governance.vk_ballot",
        &governance
            .vk_ballot
            .as_ref()
            .map(|vk| (vk.backend.clone(), vk.name.clone())),
    );
    policy.push(
        "governance.vk_tally",
        &governance
            .vk_tally
            .as_ref()
            .map(|vk| (vk.backend.clone(), vk.name.clone())),
    );
    policy.push("governance.voting_asset_id", &governance.voting_asset_id);
    policy.push(
        "governance.citizenship_asset_id",
        &governance.citizenship_asset_id,
    );
    policy.push(
        "governance.citizenship_bond_amount",
        &governance.citizenship_bond_amount,
    );
    policy.push(
        "governance.citizenship_escrow_account",
        &governance.citizenship_escrow_account,
    );
    policy.push("governance.min_bond_amount", &governance.min_bond_amount);
    policy.push(
        "governance.bond_escrow_account",
        &governance.bond_escrow_account,
    );
    policy.push(
        "governance.slash_receiver_account",
        &governance.slash_receiver_account,
    );
    policy.push(
        "governance.slash_double_vote_bps",
        &governance.slash_double_vote_bps,
    );
    policy.push(
        "governance.slash_invalid_proof_bps",
        &governance.slash_invalid_proof_bps,
    );
    policy.push(
        "governance.slash_ineligible_proof_bps",
        &governance.slash_ineligible_proof_bps,
    );
    policy.push(
        "governance.alias_teu_minimum",
        &governance.alias_teu_minimum,
    );
    policy.push(
        "governance.jdg_signature_schemes",
        &governance
            .jdg_signature_schemes
            .iter()
            .map(|scheme| scheme.scheme_id())
            .collect::<Vec<_>>(),
    );
    let provenance = &governance.runtime_upgrade_provenance;
    policy.push(
        "governance.runtime_upgrade_provenance.mode",
        &match provenance.mode {
            RuntimeUpgradeProvenanceMode::Optional => 1_u8,
            RuntimeUpgradeProvenanceMode::Required => 2,
        },
    );
    policy.push(
        "governance.runtime_upgrade_provenance.require_sbom",
        &provenance.require_sbom,
    );
    policy.push(
        "governance.runtime_upgrade_provenance.require_slsa",
        &provenance.require_slsa,
    );
    policy.push(
        "governance.runtime_upgrade_provenance.trusted_signers",
        &execution_policy_canonical_set(provenance.trusted_signers.iter()),
    );
    policy.push(
        "governance.runtime_upgrade_provenance.signature_threshold",
        &execution_policy_usize(provenance.signature_threshold),
    );
    let viral = &governance.viral_incentives;
    policy.push(
        "governance.viral.incentive_pool_account",
        &viral.incentive_pool_account,
    );
    policy.push("governance.viral.escrow_account", &viral.escrow_account);
    policy.push(
        "governance.viral.reward_asset_definition_id",
        &viral.reward_asset_definition_id,
    );
    policy.push(
        "governance.viral.follow_reward_amount",
        &viral.follow_reward_amount,
    );
    policy.push(
        "governance.viral.sender_bonus_amount",
        &viral.sender_bonus_amount,
    );
    policy.push(
        "governance.viral.max_daily_claims_per_uaid",
        &viral.max_daily_claims_per_uaid,
    );
    policy.push(
        "governance.viral.max_claims_per_binding",
        &viral.max_claims_per_binding,
    );
    policy.push("governance.viral.daily_budget", &viral.daily_budget);
    policy.push("governance.viral.halt", &viral.halt);
    policy.push(
        "governance.viral.deny_uaids",
        &execution_policy_canonical_set(viral.deny_uaids.iter()),
    );
    policy.push(
        "governance.viral.deny_binding_digests",
        &execution_policy_canonical_set(viral.deny_binding_digests.iter()),
    );
    policy.push(
        "governance.viral.promo_starts_at_ms",
        &viral.promo_starts_at_ms,
    );
    policy.push("governance.viral.promo_ends_at_ms", &viral.promo_ends_at_ms);
    policy.push("governance.viral.campaign_cap", &viral.campaign_cap);
    let pin = &governance.sorafs_pin_policy;
    policy.push(
        "governance.sorafs_pin.min_replicas_floor",
        &pin.min_replicas_floor,
    );
    policy.push(
        "governance.sorafs_pin.max_replicas_ceiling",
        &pin.max_replicas_ceiling,
    );
    policy.push(
        "governance.sorafs_pin.max_retention_epoch",
        &pin.max_retention_epoch,
    );
    policy.push(
        "governance.sorafs_pin.allowed_storage_classes",
        &pin.allowed_storage_classes,
    );
    policy.push(
        "governance.sorafs_pin.require_council_signatures",
        &pin.require_council_signatures,
    );
    policy.push(
        "governance.sorafs_pin.approval_quorum",
        &pin.approval_quorum,
    );
    let pin_signers = pin
        .approval_signers
        .iter()
        .map(|signer| {
            (
                signer.signer_id.clone(),
                signer.public_key.clone(),
                signer.valid_from_block_height,
                signer.revoked_at_block_height,
            )
        })
        .collect::<Vec<_>>();
    policy.push("governance.sorafs_pin.approval_signers", &pin_signers);
    policy.push(
        "governance.sorafs_pin.max_global_manifests",
        &pin.max_global_manifests,
    );
    policy.push(
        "governance.sorafs_pin.max_global_bytes",
        &pin.max_global_bytes,
    );
    policy.push(
        "governance.sorafs_pin.max_manifests_per_authority",
        &pin.max_manifests_per_authority,
    );
    policy.push(
        "governance.sorafs_pin.max_bytes_per_authority",
        &pin.max_bytes_per_authority,
    );
    policy.push(
        "governance.sorafs_pin.max_lineage_depth",
        &pin.max_lineage_depth,
    );
    policy.push(
        "governance.sorafs_pin.max_successor_fanout",
        &pin.max_successor_fanout,
    );
    policy.push(
        "governance.sorafs_pin_fee_asset_id",
        &governance.sorafs_pin_fee_asset_id,
    );
    policy.push(
        "governance.sorafs_pin_fee_treasury_account",
        &governance.sorafs_pin_fee_treasury_account,
    );
    policy.push("governance.sorafs_pricing", &governance.sorafs_pricing);
    let penalty = governance.sorafs_penalty;
    policy.push(
        "governance.sorafs_penalty",
        &(
            penalty.utilisation_floor_bps,
            penalty.uptime_floor_bps,
            penalty.por_success_floor_bps,
            penalty.strike_threshold,
            penalty.penalty_bond_bps,
            penalty.cooldown_windows,
            penalty.max_pdp_failures,
            penalty.max_potr_breaches,
        ),
    );
    let sorafs_telemetry = &governance.sorafs_telemetry;
    policy.push(
        "governance.sorafs_telemetry.require_submitter",
        &sorafs_telemetry.require_submitter,
    );
    policy.push(
        "governance.sorafs_telemetry.require_nonce",
        &sorafs_telemetry.require_nonce,
    );
    policy.push(
        "governance.sorafs_telemetry.max_window_gap",
        &execution_policy_duration(sorafs_telemetry.max_window_gap),
    );
    policy.push(
        "governance.sorafs_telemetry.reject_zero_capacity",
        &sorafs_telemetry.reject_zero_capacity,
    );
    policy.push(
        "governance.sorafs_telemetry.submitters",
        &execution_policy_canonical_set(sorafs_telemetry.submitters.iter()),
    );
    let per_provider_submitters = sorafs_telemetry
        .per_provider_submitters
        .iter()
        .map(|(provider, accounts)| (*provider, execution_policy_canonical_set(accounts.iter())))
        .collect::<Vec<_>>();
    policy.push(
        "governance.sorafs_telemetry.per_provider_submitters",
        &per_provider_submitters,
    );
    policy.push(
        "governance.sorafs_provider_owners",
        &governance.sorafs_provider_owners,
    );
    policy.push(
        "governance.conviction_step_blocks",
        &governance.conviction_step_blocks,
    );
    policy.push("governance.max_conviction", &governance.max_conviction);
    policy.push(
        "governance.min_enactment_delay",
        &governance.min_enactment_delay,
    );
    policy.push("governance.window_span", &governance.window_span);
    policy.push(
        "governance.max_active_referenda",
        &governance.max_active_referenda.get(),
    );
    policy.push(
        "governance.max_lock_owners_per_referendum",
        &governance.max_lock_owners_per_referendum.get(),
    );
    policy.push(
        "governance.plain_voting_enabled",
        &governance.plain_voting_enabled,
    );
    policy.push(
        "governance.approval_threshold_q_num",
        &governance.approval_threshold_q_num,
    );
    policy.push(
        "governance.approval_threshold_q_den",
        &governance.approval_threshold_q_den,
    );
    policy.push("governance.min_turnout", &governance.min_turnout);
    policy.push(
        "governance.parliament_alternate_size",
        &execution_policy_usize(governance.parliament_alternate_size),
    );
    policy.push(
        "governance.parliament_sortition_pulse_delay_blocks",
        &governance.parliament_sortition_pulse_delay_blocks,
    );
    policy.push(
        "governance.parliament_invitation_phase_blocks",
        &governance.parliament_invitation_phase_blocks,
    );
    policy.push(
        "governance.parliament_public_finding_phase_blocks",
        &governance.parliament_public_finding_phase_blocks,
    );
    let timed_ovn = governance.parliament_timed_ovn;
    policy.push(
        "governance.parliament_timed_ovn.registration_phase_blocks",
        &timed_ovn.registration_phase_blocks,
    );
    policy.push(
        "governance.parliament_timed_ovn.survivor_freeze_phase_blocks",
        &timed_ovn.survivor_freeze_phase_blocks,
    );
    policy.push(
        "governance.parliament_timed_ovn.commitment_phase_blocks",
        &timed_ovn.commitment_phase_blocks,
    );
    policy.push(
        "governance.parliament_timed_ovn.release_delay_blocks",
        &timed_ovn.release_delay_blocks,
    );
    policy.push(
        "governance.parliament_timed_ovn.opening_phase_blocks",
        &timed_ovn.opening_phase_blocks,
    );
    policy.push(
        "governance.parliament_timed_ovn.max_ballot_retries",
        &timed_ovn.max_ballot_retries,
    );
    policy.push(
        "governance.parliament_timed_ovn.max_corpus_entries",
        &timed_ovn.max_corpus_entries,
    );
    for (name, size) in [
        (
            "governance.rules_committee_size",
            governance.rules_committee_size,
        ),
        (
            "governance.agenda_council_size",
            governance.agenda_council_size,
        ),
        (
            "governance.interest_panel_size",
            governance.interest_panel_size,
        ),
        ("governance.review_panel_size", governance.review_panel_size),
        (
            "governance.coordination_council_size",
            governance.coordination_council_size,
        ),
        ("governance.policy_jury_size", governance.policy_jury_size),
        (
            "governance.confirmation_jury_size",
            governance.confirmation_jury_size,
        ),
        (
            "governance.oversight_committee_size",
            governance.oversight_committee_size,
        ),
        (
            "governance.mpc_committee_size",
            governance.mpc_committee_size,
        ),
        (
            "governance.fma_committee_size",
            governance.fma_committee_size,
        ),
    ] {
        policy.push(name, &execution_policy_usize(size));
    }
    // Content execution policy. Gateway quotas/SLOs/PoW are deliberately not ledger policy.
    policy.push("content.max_bundle_bytes", &content.max_bundle_bytes);
    policy.push("content.max_files", &content.max_files);
    policy.push("content.max_path_len", &content.max_path_len);
    policy.push(
        "content.max_retention_blocks",
        &content.max_retention_blocks,
    );
    policy.push("content.chunk_size_bytes", &content.chunk_size_bytes);
    policy.push(
        "content.publish_allow_accounts",
        &execution_policy_canonical_set(content.publish_allow_accounts.iter()),
    );
    policy.push(
        "content.default_cache_max_age_secs",
        &content.default_cache_max_age_secs,
    );
    policy.push(
        "content.max_cache_max_age_secs",
        &content.max_cache_max_age_secs,
    );
    policy.push("content.immutable_bundles", &content.immutable_bundles);
    policy.push("content.default_auth_mode", &content.default_auth_mode);
    policy.push("content.stripe_layout", &content.stripe_layout);
    policy.push(
        "settlement.router.twap_window",
        &execution_policy_duration(settlement.router.twap_window),
    );
    policy.push(
        "settlement.router.epsilon_bps",
        &settlement.router.epsilon_bps,
    );
    policy.push(
        "settlement.router.buffer_alert_pct",
        &settlement.router.buffer_alert_pct,
    );
    policy.push(
        "settlement.router.buffer_throttle_pct",
        &settlement.router.buffer_throttle_pct,
    );
    policy.push(
        "settlement.router.buffer_xor_only_pct",
        &settlement.router.buffer_xor_only_pct,
    );
    policy.push(
        "settlement.router.buffer_halt_pct",
        &settlement.router.buffer_halt_pct,
    );
    policy.push(
        "settlement.router.buffer_horizon_hours",
        &settlement.router.buffer_horizon_hours,
    );
    // These sections already have independently audited canonical digests.
    policy.push("nexus.policy_digest", &nexus_policy_digest);
    policy.push("zk.policy_digest", &zk_policy_digest);
    let encoded = ExecutionPolicyPreimageV1 {
        version: VERSION,
        fields: policy.fields,
    }
    .encode();
    Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()]).into()
}
/// Lane manifest registry configuration.
#[derive(Debug, Clone)]
pub struct LaneRegistry {
    /// Optional directory containing lane manifest files.
    pub manifest_directory: Option<PathBuf>,
    /// Optional path used to cache downloaded manifests.
    pub cache_directory: Option<PathBuf>,
    /// Poll interval for refreshing manifests and governance data.
    pub poll_interval: Duration,
}
impl_default!(LaneRegistry => {
        Self {
            manifest_directory: None,
            cache_directory: None,
            poll_interval: defaults::nexus::registry::POLL_INTERVAL,
        }
});
/// Lane compliance policy configuration.
#[derive(Debug, Clone)]
pub struct LaneCompliance {
    /// Whether lane-level compliance checks are enabled.
    pub enabled: bool,
    /// When true, decisions are logged but not enforced.
    pub audit_only: bool,
    /// Optional directory containing Norito-encoded policy bundles.
    pub policy_dir: Option<PathBuf>,
}
impl_default!(LaneCompliance => {
        Self {
            enabled: defaults::nexus::compliance::ENABLED,
            audit_only: defaults::nexus::compliance::AUDIT_ONLY,
            policy_dir: None,
        }
});
/// Governance module catalog for lanes.
#[derive(Debug, Clone, Default)]
pub struct GovernanceCatalog {
    /// Default governance module identifier applied when a lane omits an override.
    pub default_module: Option<String>,
    /// Registered governance modules keyed by name.
    pub modules: BTreeMap<String, GovernanceModule>,
}
/// Governance module definition.
#[derive(Debug, Clone, Default)]
pub struct GovernanceModule {
    /// Module type (e.g., `parliament`, `stake_weighted`, `council_multisig`).
    pub module_type: Option<String>,
    /// Additional parameters defined by the module.
    pub params: BTreeMap<String, String>,
}
/// Confidential asset and verifier configuration.
#[derive(Debug, Clone)]
pub struct Confidential {
    /// Enables confidential asset features for this node.
    pub enabled: bool,
    /// Allows observer mode acceptance without verification.
    pub assume_valid: bool,
    /// Preferred verifier backend identifier.
    pub verifier_backend: String,
    /// Maximum proof size accepted from a single confidential operation.
    pub max_proof_size_bytes: u32,
    /// Maximum number of nullifiers per transaction.
    pub max_nullifiers_per_tx: u32,
    /// Maximum number of commitments per transaction.
    pub max_commitments_per_tx: u32,
    /// Maximum confidential operations per block.
    pub max_confidential_ops_per_block: u32,
    /// Verifier timeout.
    pub verify_timeout: Duration,
    /// Maximum anchor age in blocks.
    pub max_anchor_age_blocks: u64,
    /// Aggregate proof bytes allowed per block.
    pub max_proof_bytes_block: u64,
    /// Maximum verification calls per transaction.
    pub max_verify_calls_per_tx: u32,
    /// Maximum verification calls per block.
    pub max_verify_calls_per_block: u32,
    /// Maximum public inputs per proof.
    pub max_public_inputs: u32,
    /// Configured reorg depth bound.
    pub reorg_depth_bound: u64,
    /// Minimum delay between policy change request and activation.
    pub policy_transition_delay_blocks: u64,
    /// Grace window around policy activation.
    pub policy_transition_window_blocks: u64,
    /// Maximum confidential-policy transitions that may share one effective height.
    pub policy_transition_max_per_height: NonZeroU32,
    /// Non-zero commitment tree root history length.
    pub tree_roots_history_len: NonZeroUsize,
    /// Frontier checkpoint interval.
    pub tree_frontier_checkpoint_interval: u64,
    /// Maximum verifier entries allowed in registry.
    pub registry_max_vk_entries: u32,
    /// Maximum parameter entries allowed in registry.
    pub registry_max_params_entries: u32,
    /// Maximum registry mutations per block.
    pub registry_max_delta_per_block: u32,
    /// Gas schedule applied to confidential proof verification.
    pub gas: ConfidentialGas,
}
/// Confidential verification gas schedule parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConfidentialGas {
    /// Base cost charged for initiating a proof verification.
    pub proof_base: u64,
    /// Cost per public input included in the proof envelope.
    pub per_public_input: u64,
    /// Cost per proof byte.
    pub per_proof_byte: u64,
    /// Cost per nullifier consumed by the proof.
    pub per_nullifier: u64,
    /// Cost per commitment emitted by the proof.
    pub per_commitment: u64,
}
/// Declarative routing policy derived from configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaneRoutingPolicy {
    /// Lane used when no rule matches.
    pub default_lane: LaneId,
    /// Dataspace used when a rule does not override it explicitly.
    pub default_dataspace: DataSpaceId,
    /// Ordered list of routing rules.
    pub rules: Vec<LaneRoutingRule>,
}
/// Individual routing rule targeting a lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneRoutingRule {
    /// Lane assigned when the matcher is satisfied.
    pub lane: LaneId,
    /// Optional dataspace override when the matcher is satisfied.
    pub dataspace: Option<DataSpaceId>,
    /// Selection criteria.
    pub matcher: LaneRoutingMatcher,
}
/// Matcher describing which transactions fall under a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaneRoutingMatcher {
    /// Optional authority/account string match.
    pub account: Option<String>,
    /// Optional instruction path match.
    pub instruction: Option<String>,
    /// Optional descriptive text.
    pub description: Option<String>,
}
/// Derived per-lane configuration used by state storage and tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneConfig {
    entries: Vec<LaneConfigEntry>,
    by_id: BTreeMap<LaneId, usize>,
}
impl_default!(LaneConfig => {
        Self::from_catalog(&LaneCatalog::default())
});
impl LaneConfig {
    /// Derive lane configuration metadata from the validated catalog.
    #[must_use]
    pub fn from_catalog(catalog: &LaneCatalog) -> Self {
        let mut entries = Vec::with_capacity(catalog.lanes().len());
        let mut by_id = BTreeMap::new();
        for lane in catalog.lanes() {
            let entry = LaneConfigEntry::from_metadata(lane);
            by_id.insert(entry.lane_id, entries.len());
            entries.push(entry);
        }
        Self { entries, by_id }
    }
    /// Check the complete derived catalog and its exact lookup index without allocating.
    ///
    /// This preserves equality with [`Self::from_catalog`] while borrowing every
    /// original field. It also rejects missing, extra, reordered or rebound index
    /// entries, so callers do not reconstruct an unadmitted configuration graph.
    #[must_use]
    pub fn matches_catalog(&self, catalog: &LaneCatalog) -> bool {
        let lanes = catalog.lanes();
        self.entries.len() == lanes.len()
            && self.by_id.len() == lanes.len()
            && self
                .entries
                .iter()
                .zip(lanes)
                .enumerate()
                .all(|(index, (entry, metadata))| {
                    entry.matches_metadata(metadata) && self.by_id.get(&metadata.id) == Some(&index)
                })
    }
    /// Iterate over all derived lane entries in catalog order.
    #[must_use]
    pub fn entries(&self) -> &[LaneConfigEntry] {
        &self.entries
    }
    /// Resolve the derived configuration entry for a specific lane.
    #[must_use]
    pub fn entry(&self, id: LaneId) -> Option<&LaneConfigEntry> {
        self.by_id.get(&id).and_then(|&idx| self.entries.get(idx))
    }
    /// Return the first catalog entry, representing the default/primary lane.
    ///
    /// # Panics
    /// Panics when the derived catalog is empty (should never happen because
    /// [`LaneCatalog::default`] always contains the primary lane).
    #[must_use]
    pub fn primary(&self) -> &LaneConfigEntry {
        self.entries
            .first()
            .expect("lane catalog must contain at least one entry")
    }
    /// Resolve the manifest enforcement policy for a lane.
    #[must_use]
    pub fn manifest_policy(&self, id: LaneId) -> DaManifestPolicy {
        self.entry(id)
            .map(|entry| entry.manifest_policy)
            .unwrap_or_default()
    }
    /// Resolve the shard mapping for all configured lanes.
    #[must_use]
    pub fn shard_mapping(&self) -> BTreeMap<LaneId, ShardId> {
        self.entries
            .iter()
            .map(|entry| (entry.lane_id, ShardId::new(entry.shard_id)))
            .collect()
    }
    /// Resolve the shard identifier for a lane (defaulting to the lane id).
    #[must_use]
    pub fn shard_id(&self, id: LaneId) -> u32 {
        self.entry(id)
            .map_or_else(|| id.as_u32(), |entry| entry.shard_id)
    }
    /// Resolve the confidential compute policy for a lane if configured.
    #[must_use]
    pub fn confidential_compute_policy(&self, id: LaneId) -> Option<&ConfidentialComputePolicy> {
        self.entry(id)
            .and_then(|entry| entry.confidential_compute.as_ref())
    }
    /// Canonically ordered access audience labels for a confidential-compute lane.
    #[must_use]
    pub fn confidential_access(&self, id: LaneId) -> Option<&BTreeSet<String>> {
        self.entry(id)
            .and_then(|entry| entry.confidential_compute.as_ref())
            .map(|policy| &policy.allowed_audiences)
    }
}
/// Derived configuration for a single lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneConfigEntry {
    /// Lane identifier.
    pub lane_id: LaneId,
    /// Shard identifier this lane maps to (defaults to the lane id).
    pub shard_id: u32,
    /// Dataspace identifier the lane belongs to.
    pub dataspace_id: DataSpaceId,
    /// Declarative visibility profile.
    pub visibility: LaneVisibility,
    /// Storage profile applied to the lane.
    pub storage_profile: LaneStorageProfile,
    /// Proof scheme expected for DA commitments on this lane.
    pub proof_scheme: DaProofScheme,
    /// Lane alias copied from metadata.
    pub alias: String,
    /// Normalised slug used for file names/metrics.
    pub slug: String,
    /// Kura segment namespace used for lane-local ledger storage.
    pub kura_segment: String,
    /// Kura segment name used for merge-ledger metadata.
    pub merge_segment: String,
    /// Deterministic key prefix applied to MV storage keys.
    pub key_prefix: [u8; 4],
    /// Manifest availability enforcement policy for this lane.
    pub manifest_policy: DaManifestPolicy,
    /// Typed confidential-compute policy, absent for ordinary lanes.
    pub confidential_compute: Option<ConfidentialComputePolicy>,
    /// Positive scheduler overrides, absent when global fallbacks apply.
    pub scheduler: Option<LaneSchedulerPolicy>,
    /// Typed settlement reserve policy, absent when the lane has no reserve.
    pub settlement_buffer: Option<LaneSettlementBufferPolicy>,
}
impl LaneConfigEntry {
    /// Check this derived entry against its catalog metadata without allocating.
    ///
    /// Every derived field is checked, including normalized namespace strings and
    /// complete confidential-compute and settlement policies. This is suitable
    /// for borrowed validation of an immutable execution snapshot.
    #[must_use]
    pub fn matches_metadata(&self, meta: &LaneConfigMetadata) -> bool {
        use std::fmt::Write as _;
        self.lane_id == meta.id
            && self.shard_id == meta.effective_shard_id().as_u32()
            && self.dataspace_id == meta.dataspace_id
            && self.visibility == meta.visibility
            && self.storage_profile == meta.storage
            && self.proof_scheme == meta.proof_scheme
            && self.alias == meta.alias
            && lane_rendering_matches(&self.slug, |out| {
                Self::write_slug(&meta.alias, meta.id, out)
            })
            && lane_rendering_matches(&self.kura_segment, |out| {
                write!(out, "lane_{:03}_{}", meta.id.as_u32(), self.slug)
            })
            && lane_rendering_matches(&self.merge_segment, |out| {
                write!(out, "lane_{:03}_{}_merge", meta.id.as_u32(), self.slug)
            })
            && self.key_prefix == meta.id.as_u32().to_be_bytes()
            && self.manifest_policy == meta.manifest_policy
            && self.confidential_compute == meta.confidential_compute
            && self.scheduler == meta.scheduler
            && self.settlement_buffer == meta.settlement_buffer
    }
    fn from_metadata(meta: &LaneConfigMetadata) -> Self {
        let slug = Self::slugify(&meta.alias, meta.id);
        let lane_numeric = meta.id.as_u32();
        let key_prefix = lane_numeric.to_be_bytes();
        let kura_segment = format!("lane_{lane_numeric:03}_{slug}");
        let merge_segment = format!("lane_{lane_numeric:03}_{slug}_merge");
        let manifest_policy = meta.manifest_policy;
        let shard_id = meta.effective_shard_id().as_u32();
        Self {
            lane_id: meta.id,
            shard_id,
            dataspace_id: meta.dataspace_id,
            visibility: meta.visibility,
            storage_profile: meta.storage,
            proof_scheme: meta.proof_scheme,
            alias: meta.alias.clone(),
            slug,
            kura_segment,
            merge_segment,
            key_prefix,
            manifest_policy,
            confidential_compute: meta.confidential_compute.clone(),
            scheduler: meta.scheduler,
            settlement_buffer: meta.settlement_buffer.clone(),
        }
    }
    fn slugify(alias: &str, lane_id: LaneId) -> String {
        let mut slug = String::with_capacity(alias.len());
        Self::write_slug(alias, lane_id, &mut slug).expect("String writes are infallible");
        slug
    }
    fn write_slug(
        alias: &str,
        lane_id: LaneId,
        out: &mut impl std::fmt::Write,
    ) -> std::fmt::Result {
        let mut written = false;
        let mut separator = false;
        for ch in alias.chars() {
            if ch.is_ascii_alphanumeric() {
                if separator {
                    out.write_char('_')?;
                }
                out.write_char(ch.to_ascii_lowercase())?;
                written = true;
                separator = false;
            } else if written {
                separator = true;
            }
        }
        if !written {
            write!(out, "lane{}", lane_id.as_u32())?;
        }
        Ok(())
    }
    // Lane aliases and cache labels do not identify consensus storage. Core owns
    // physical addresses derived from authenticated network/route/incarnation/activation.
}
// Streaming comparison shares the exact renderer with construction. The writer
// only advances through borrowed expected bytes and never builds a second string.
struct LaneRenderingComparison<'a>(&'a str);
impl std::fmt::Write for LaneRenderingComparison<'_> {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0 = self.0.strip_prefix(value).ok_or(std::fmt::Error)?;
        Ok(())
    }
}
fn lane_rendering_matches(
    expected: &str,
    render: impl FnOnce(&mut LaneRenderingComparison<'_>) -> std::fmt::Result,
) -> bool {
    let mut out = LaneRenderingComparison(expected);
    render(&mut out).is_ok() && out.0.is_empty()
}
#[cfg(test)]
#[path = "actual/lane_metadata_tests.rs"]
mod lane_metadata_tests;
/// Lane-fusion tuning parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fusion {
    /// Sustained TEU floor (per lane) that triggers fusion when demand stays below it.
    pub floor_teu: u32,
    /// TEU threshold that forces fused lanes to split back to independent operation.
    pub exit_teu: u32,
    /// Number of consecutive slots that must satisfy the floor condition before fusing.
    pub observation_slots: NonZeroU16,
    /// Maximum number of slots a fused window can persist without re-evaluating load.
    pub max_window_slots: NonZeroU16,
}
impl_default!(Fusion => {
        Self {
            floor_teu: defaults::nexus::fusion::FLOOR_TEU,
            exit_teu: defaults::nexus::fusion::EXIT_TEU,
            observation_slots: NonZeroU16::new(defaults::nexus::fusion::OBSERVATION_SLOTS)
                .expect("default observation slots > 0"),
            max_window_slots: NonZeroU16::new(defaults::nexus::fusion::MAX_WINDOW_SLOTS)
                .expect("default max window slots > 0"),
        }
});
/// Deterministic lane autoscaling parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Autoscale {
    /// Whether consensus-driven lane autoscaling is enabled.
    pub enabled: bool,
    /// Inclusive lower lane-id bound reserved for autoscale-managed elastic lanes.
    pub min_lane_id: NonZeroU32,
    /// Exclusive upper lane-id bound reserved for autoscale-managed elastic lanes.
    pub max_lane_id_exclusive: NonZeroU32,
    /// Target block interval used by the autoscaler (milliseconds).
    pub target_block_ms: NonZeroU64,
    /// Scale-out latency ratio threshold versus target block interval.
    pub scale_out_latency_ratio: f64,
    /// Scale-in latency ratio threshold versus target block interval.
    pub scale_in_latency_ratio: f64,
    /// Scale-out utilization ratio threshold.
    pub scale_out_utilization_ratio: f64,
    /// Scale-in utilization ratio threshold.
    pub scale_in_utilization_ratio: f64,
    /// Number of recent blocks used for scale-out decisions.
    pub scale_out_window_blocks: NonZeroU16,
    /// Number of recent blocks used for scale-in decisions.
    pub scale_in_window_blocks: NonZeroU16,
    /// Cooldown period in blocks after each transition.
    pub cooldown_blocks: NonZeroU16,
    /// Per-lane throughput target used to compute utilization (tx/s).
    pub per_lane_target_tps: NonZeroU32,
    /// Last block height where a scale transition was applied.
    pub last_transition_height: u64,
}
impl Autoscale {
    /// Return whether `lane` is inside the autoscaler-owned elastic lane-id range.
    ///
    /// The range is half-open: `min_lane_id <= lane < max_lane_id_exclusive`. Callers that may
    /// receive programmatically constructed runtime state must validate that
    /// `min_lane_id < max_lane_id_exclusive` separately.
    #[must_use]
    pub fn contains_elastic_lane_id(&self, lane: LaneId) -> bool {
        let lane = lane.as_u32();
        lane >= self.min_lane_id.get() && lane < self.max_lane_id_exclusive.get()
    }
}
impl_default!(Autoscale => {
        Self {
            enabled: defaults::nexus::autoscale::ENABLED,
            min_lane_id: NonZeroU32::new(defaults::nexus::autoscale::MIN_LANE_ID)
                .expect("default autoscale min_lane_id > 0"),
            max_lane_id_exclusive: NonZeroU32::new(defaults::nexus::autoscale::MAX_LANE_ID_EXCLUSIVE)
                .expect("default autoscale max_lane_id_exclusive > 0"),
            target_block_ms: NonZeroU64::new(defaults::nexus::autoscale::TARGET_BLOCK_MS)
                .expect("default autoscale target_block_ms > 0"),
            scale_out_latency_ratio: defaults::nexus::autoscale::SCALE_OUT_LATENCY_RATIO,
            scale_in_latency_ratio: defaults::nexus::autoscale::SCALE_IN_LATENCY_RATIO,
            scale_out_utilization_ratio: defaults::nexus::autoscale::SCALE_OUT_UTILIZATION_RATIO,
            scale_in_utilization_ratio: defaults::nexus::autoscale::SCALE_IN_UTILIZATION_RATIO,
            scale_out_window_blocks: NonZeroU16::new(
                defaults::nexus::autoscale::SCALE_OUT_WINDOW_BLOCKS,
            )
            .expect("default autoscale scale_out_window_blocks > 0"),
            scale_in_window_blocks: NonZeroU16::new(
                defaults::nexus::autoscale::SCALE_IN_WINDOW_BLOCKS,
            )
            .expect("default autoscale scale_in_window_blocks > 0"),
            cooldown_blocks: NonZeroU16::new(defaults::nexus::autoscale::COOLDOWN_BLOCKS)
                .expect("default autoscale cooldown_blocks > 0"),
            per_lane_target_tps: NonZeroU32::new(defaults::nexus::autoscale::PER_LANE_TARGET_TPS)
                .expect("default autoscale per_lane_target_tps > 0"),
            last_transition_height: 0,
        }
});
/// Proof/commit deadline configuration (Δ window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
    /// Number of slots available for proofs/DA bundles to arrive before a transaction aborts.
    pub window_slots: NonZeroU16,
}
impl_default!(Commit => {
        Self {
            window_slots: NonZeroU16::new(defaults::nexus::commit::WINDOW_SLOTS)
                .expect("default commit window > 0"),
        }
});
/// Data-availability sampling configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Da {
    /// Total in-slot DA signatures budget per lane.
    pub q_in_slot_total: NonZeroU32,
    /// Minimum in-slot DA signatures per dataspace.
    pub q_in_slot_per_ds_min: NonZeroU16,
    /// Baseline attester sample size (S).
    pub sample_size_base: NonZeroU16,
    /// Maximum attester sample size when scaling up coverage.
    pub sample_size_max: NonZeroU16,
    /// Threshold `T` applied off-path for DA certificates.
    pub threshold_base: NonZeroU16,
    /// Number of shards each attester must verify per slot.
    pub per_attester_shards: NonZeroU16,
    /// Number of consecutive block heights in one deterministic ingest quota window.
    pub ingest_quota_window_blocks: NonZeroU64,
    /// Maximum accepted DA ingests per account in one quota window.
    pub ingest_quota_max_count_per_account: NonZeroU64,
    /// Maximum canonical DA payload bytes per account in one quota window.
    pub ingest_quota_max_bytes_per_account: NonZeroU64,
    /// Rolling audit configuration.
    pub audit: DaAudit,
    /// Recovery deadline configuration.
    pub recovery: DaRecovery,
    /// Temporal diversity / attester rotation configuration.
    pub rotation: DaRotation,
}
impl_default!(Da => {
        Self {
            q_in_slot_total: NonZeroU32::new(defaults::nexus::da::Q_IN_SLOT_TOTAL)
                .expect("default q_in_slot_total > 0"),
            q_in_slot_per_ds_min: NonZeroU16::new(defaults::nexus::da::Q_IN_SLOT_PER_DS_MIN)
                .expect("default q_in_slot_per_ds_min > 0"),
            sample_size_base: NonZeroU16::new(defaults::nexus::da::SAMPLE_SIZE_BASE)
                .expect("default sample_size_base > 0"),
            sample_size_max: NonZeroU16::new(defaults::nexus::da::SAMPLE_SIZE_MAX)
                .expect("default sample_size_max > 0"),
            threshold_base: NonZeroU16::new(defaults::nexus::da::THRESHOLD_BASE)
                .expect("default threshold_base > 0"),
            per_attester_shards: NonZeroU16::new(defaults::nexus::da::PER_ATTESTER_SHARDS)
                .expect("default per_attester_shards > 0"),
            ingest_quota_window_blocks: NonZeroU64::new(
                defaults::nexus::da::INGEST_QUOTA_WINDOW_BLOCKS,
            )
            .expect("default ingest quota window > 0"),
            ingest_quota_max_count_per_account: NonZeroU64::new(
                defaults::nexus::da::INGEST_QUOTA_MAX_COUNT_PER_ACCOUNT,
            )
            .expect("default ingest quota count > 0"),
            ingest_quota_max_bytes_per_account: NonZeroU64::new(
                defaults::nexus::da::INGEST_QUOTA_MAX_BYTES_PER_ACCOUNT,
            )
            .expect("default ingest quota bytes > 0"),
            audit: DaAudit::default(),
            recovery: DaRecovery::default(),
            rotation: DaRotation::default(),
        }
});
/// Rolling audit configuration ensuring long-term DA coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaAudit {
    /// Signatures verified per audit window.
    pub sample_size: NonZeroU16,
    /// Number of audit windows retained before slashing for insufficient coverage.
    pub window_count: NonZeroU16,
    /// Duration of an audit window.
    pub interval: Duration,
}
impl_default!(DaAudit => {
        Self {
            sample_size: NonZeroU16::new(defaults::nexus::da::audit::SAMPLE_SIZE)
                .expect("default audit sample size > 0"),
            window_count: NonZeroU16::new(defaults::nexus::da::audit::WINDOW_COUNT)
                .expect("default audit window count > 0"),
            interval: defaults::nexus::da::audit::INTERVAL,
        }
});
/// Recovery deadline configuration for missing DA proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaRecovery {
    /// Deadline for providing recovery proofs once requested.
    pub request_timeout: Duration,
}
impl_default!(DaRecovery => {
        Self {
            request_timeout: defaults::nexus::da::recovery::REQUEST_TIMEOUT,
        }
});
/// Temporal diversity / attester rotation configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct DaRotation {
    /// Maximum appearances of an attester inside the rolling window.
    pub max_hits_per_window: NonZeroU16,
    /// Rolling window length (slots) for temporal diversity enforcement.
    pub window_slots: NonZeroU16,
    /// Domain-separation tag for deterministic rotation seed derivation.
    pub seed_tag: String,
    /// Latency-bias decay factor applied to attester weights.
    pub latency_decay: f64,
}
impl_default!(DaRotation => {
        Self {
            max_hits_per_window: NonZeroU16::new(
                defaults::nexus::da::rotation::MAX_HITS_PER_WINDOW,
            )
            .expect("default rotation max hits > 0"),
            window_slots: NonZeroU16::new(defaults::nexus::da::rotation::WINDOW_SLOTS)
                .expect("default rotation window slots > 0"),
            seed_tag: defaults::nexus::da::rotation::SEED_TAG.to_string(),
            latency_decay: defaults::nexus::da::rotation::LATENCY_DECAY,
        }
});
impl Fusion {
    /// Determine whether recent TEU demand satisfies the fusion criteria.
    #[must_use]
    pub fn should_fuse(&self, recent_teu: &[u64]) -> bool {
        let window = usize::from(self.observation_slots.get());
        if recent_teu.len() < window {
            return false;
        }
        recent_teu
            .iter()
            .rev()
            .take(window)
            .all(|&teu| teu <= u64::from(self.floor_teu))
    }
    /// Determine whether current TEU demand exceeds the split threshold.
    #[must_use]
    pub fn should_exit(&self, current_teu: u64) -> bool {
        current_teu > u64::from(self.exit_teu)
    }
    /// Maximum fused-window duration in slots before re-evaluating load.
    #[must_use]
    pub fn max_window_slots(&self) -> u16 {
        self.max_window_slots.get()
    }
}
impl Da {
    /// Maximum number of public dataspaces that can be served per slot under baseline sampling.
    #[must_use]
    pub fn max_public_dataspaces_per_slot(&self) -> u32 {
        let per_ds = u32::from(self.q_in_slot_per_ds_min.get()).max(1);
        self.q_in_slot_total.get() / per_ds
    }
}
impl DaRotation {
    /// Check if the observed attester occurrences within a window violate the configured cap.
    #[must_use]
    pub fn violates_temporal_diversity(
        &self,
        occurrences_within_window: u32,
        window_span_slots: u32,
    ) -> bool {
        let cap = u32::from(self.max_hits_per_window.get());
        let window_cap = u32::from(self.window_slots.get());
        occurrences_within_window > cap && window_span_slots >= window_cap
    }
    /// Expose the configured temporal window length (slots).
    #[must_use]
    pub fn window_slots(&self) -> u16 {
        self.window_slots.get()
    }
    /// Expose the configured hit cap within the temporal window.
    #[must_use]
    pub fn max_hits_per_window(&self) -> u16 {
        self.max_hits_per_window.get()
    }
}
/// Pipeline settings controlling execution behavior.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Pipeline {
    /// Enable dynamic prepass for IVM access-set derivation.
    pub dynamic_prepass: bool,
    /// Cache derived access sets for IVM manifests (advisory only).
    pub access_set_cache_enabled: bool,
    /// Enable parallel per-transaction overlay construction.
    pub parallel_overlay: bool,
    /// Number of worker threads for overlay construction (0 = auto).
    pub workers: usize,
    /// Capacity for the stateless validation cache (0 = disabled).
    pub stateless_cache_cap: usize,
    /// Enable parallel application of overlays (per conflict-free layer).
    pub parallel_apply: bool,
    /// Use BinaryHeap-based ready queue in the deterministic scheduler.
    /// Default is per-wave sort; this switch is for benchmarking and development.
    pub ready_queue_heap: bool,
    /// Optional GPU key bucketing (stable radix on (key, tx_idx, rw_flag)) for scheduler prepass.
    /// Deterministic CPU fallback is always available. Off by default.
    pub gpu_key_bucket: bool,
    /// Emit scheduler input/output traces for deterministic tie-break debugging.
    pub debug_trace_scheduler_inputs: bool,
    /// Emit transaction evaluation traces during overlay application (developer diagnostics).
    pub debug_trace_tx_eval: bool,
    /// Per-scheme caps (0 disables) for signature batch verification.
    pub signature_batch_max_ed25519: usize,
    /// Maximum batch size for secp256k1 signatures (0 disables).
    pub signature_batch_max_secp256k1: usize,
    /// Maximum batch size for PQC signatures (0 disables).
    pub signature_batch_max_pqc: usize,
    /// Maximum batch size for BLS signatures (0 disables).
    pub signature_batch_max_bls: usize,
    /// IVM pre-decode cache capacity (decoded streams).
    pub cache_size: usize,
    /// Maximum decoded instructions retained per cached entry (0 = unlimited).
    pub ivm_cache_max_decoded_ops: usize,
    /// Aggregate IVM preparation/runtime allocation retention budget (bytes; 0 disables).
    pub ivm_cache_max_bytes: usize,
    /// Finite active IVM allocation budget, distinct from idle retention (zero denies allocation).
    pub ivm_execution_max_bytes: usize,
    /// Rayon worker cap for prover/trace verification (0 = physical cores).
    pub ivm_prover_threads: usize,
    /// Maximum instructions allowed per overlay (0 = unlimited).
    pub overlay_max_instructions: usize,
    /// Maximum serialized Norito bytes allowed per overlay (0 = unlimited).
    pub overlay_max_bytes: u64,
    /// Execute overlay instructions in chunks of this size (at least 1).
    pub overlay_chunk_instructions: usize,
    /// Gas fees configuration.
    pub gas: Gas,
    /// Mandatory admission-time ceiling for `ProgramMetadata.max_cycles`.
    pub ivm_max_cycles_upper_bound: NonZeroU64,
    /// Maximum decoded Kotodama instructions accepted during admission (0 = unlimited).
    pub ivm_max_decoded_instructions: u64,
    /// Maximum decoded Kotodama byte length accepted during admission (0 = unlimited).
    pub ivm_max_decoded_bytes: u64,
    /// Maximum transactions processed by the quarantine lane per block (0 = disabled).
    pub quarantine_max_txs_per_block: usize,
    /// Per-transaction cycle cap for quarantine lane (0 = unlimited).
    pub quarantine_tx_max_cycles: u64,
    /// Default cursor mode for server-facing query endpoints.
    pub query_default_cursor_mode: QueryCursorMode,
    /// Maximum fetch size for iterable queries executed inside the IVM.
    pub query_max_fetch_size: u64,
    /// Minimum gas units required to use stored cursor mode (0 = disabled).
    pub query_stored_min_gas_units: u64,
    /// AMX per-dataspace execution budget in milliseconds.
    pub amx_per_dataspace_budget_ms: u64,
    /// AMX group execution budget across dataspaces in milliseconds.
    pub amx_group_budget_ms: u64,
    /// Estimated nanoseconds per instruction used for AMX budgeting.
    pub amx_per_instruction_ns: u64,
    /// Estimated nanoseconds per memory access used for AMX budgeting.
    pub amx_per_memory_access_ns: u64,
    /// Estimated nanoseconds per syscall used for AMX budgeting.
    pub amx_per_syscall_ns: u64,
}
impl_default!(Pipeline => {
        Self {
            dynamic_prepass: defaults::pipeline::DYNAMIC_PREPASS,
            access_set_cache_enabled: defaults::pipeline::ACCESS_SET_CACHE_ENABLED,
            parallel_overlay: defaults::pipeline::PARALLEL_OVERLAY,
            workers: defaults::pipeline::WORKERS,
            stateless_cache_cap: defaults::pipeline::STATELESS_CACHE_CAP,
            parallel_apply: defaults::pipeline::PARALLEL_APPLY,
            ready_queue_heap: defaults::pipeline::READY_QUEUE_HEAP,
            gpu_key_bucket: defaults::pipeline::GPU_KEY_BUCKET,
            debug_trace_scheduler_inputs: defaults::pipeline::DEBUG_TRACE_SCHEDULER_INPUTS,
            debug_trace_tx_eval: defaults::pipeline::DEBUG_TRACE_TX_EVAL,
            signature_batch_max_ed25519: defaults::pipeline::SIGNATURE_BATCH_MAX_ED25519,
            signature_batch_max_secp256k1: defaults::pipeline::SIGNATURE_BATCH_MAX_SECP256K1,
            signature_batch_max_pqc: defaults::pipeline::SIGNATURE_BATCH_MAX_PQC,
            signature_batch_max_bls: defaults::pipeline::SIGNATURE_BATCH_MAX_BLS,
            cache_size: defaults::pipeline::CACHE_SIZE,
            ivm_cache_max_decoded_ops: defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
            ivm_cache_max_bytes: defaults::pipeline::IVM_CACHE_MAX_BYTES,
            ivm_execution_max_bytes: defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ivm_prover_threads: defaults::pipeline::IVM_PROVER_THREADS,
            overlay_max_instructions: defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS,
            overlay_max_bytes: defaults::pipeline::OVERLAY_MAX_BYTES,
            overlay_chunk_instructions: defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS,
            gas: Gas {
                tech_account_id: defaults::pipeline::GAS_TECH_ACCOUNT_ID.to_owned(),
                accepted_assets: Vec::new(),
                units_per_gas: Vec::new(),
            },
            ivm_max_cycles_upper_bound: defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND,
            ivm_max_decoded_instructions: defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS,
            ivm_max_decoded_bytes: defaults::pipeline::IVM_MAX_DECODED_BYTES,
            quarantine_max_txs_per_block: defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK,
            quarantine_tx_max_cycles: defaults::pipeline::QUARANTINE_TX_MAX_CYCLES,
            query_default_cursor_mode: QueryCursorMode::Ephemeral,
            query_max_fetch_size: defaults::pipeline::QUERY_MAX_FETCH_SIZE,
            query_stored_min_gas_units: defaults::pipeline::QUERY_STORED_MIN_GAS_UNITS,
            amx_per_dataspace_budget_ms: defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS,
            amx_group_budget_ms: defaults::pipeline::AMX_GROUP_BUDGET_MS,
            amx_per_instruction_ns: defaults::pipeline::AMX_PER_INSTRUCTION_NS,
            amx_per_memory_access_ns: defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS,
            amx_per_syscall_ns: defaults::pipeline::AMX_PER_SYSCALL_NS,
        }
});
/// One retained lane-incarnation lineage binding committed into a Sumeragi height context.
///
/// The complete projection contains every active or retired lane identifier ever
/// observed by the state. Retired entries remain consensus-relevant because a
/// later recreation derives its next incarnation from this retained generation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::parameters::actual::SumeragiLaneLifecycleEntry")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub struct SumeragiLaneLifecycleEntry {
    /// Canonical lane identifier.
    pub lane_id: LaneId,
    /// Monotonic incarnation generation retained for this lane identifier.
    pub generation: u64,
    /// Non-zero commitment for the latest active or retired incarnation.
    pub incarnation: Hash,
    /// Global carrier height that activated this incarnation.
    pub activation_height: u64,
}
/// Build the canonical Sumeragi preimage of the Nexus and AMX inputs that can
/// change proposal assembly or deterministic validation.
///
/// The projection deliberately excludes local storage paths, worker pool
/// sizing, caches, and telemetry. It includes the validated lane geometry,
/// dataspace and routing catalogs, lane election/fee/AXT/DA policy, the five
/// deterministic AMX budgets, and staged active public-lane validator records.
/// It also commits the complete retained lane-incarnation lineage, including
/// retired lane identifiers, generations, commitments, and activation heights,
/// so peers with divergent lifecycle histories cannot enter the same height or
/// later derive the same recreated lane differently. Active validator records
/// and retained lineage entries are sorted canonically before encoding.
///
/// The framing and tag grammar are owned by [`iroha_data_model::nexus::NexusAmxContextWriterV1`]
/// and [`iroha_data_model::nexus::decode_nexus_amx_context_v1`]; a field added here must also
/// be added to that grammar.
#[must_use]
pub fn sumeragi_nexus_amx_context_preimage(
    nexus: &Nexus,
    pipeline: &Pipeline,
    active_validators: &[GenesisActiveNexusLaneRecord],
    retained_lane_lineage: &[SumeragiLaneLifecycleEntry],
) -> Vec<u8> {
    use iroha_data_model::nexus::{NexusAmxContextWriterV1, tag};
    let mut preimage = NexusAmxContextWriterV1::new();
    preimage.field(tag::LANE_COUNT, &nexus.lane_catalog.lane_count().get());
    let (_, consensus_lanes) = nexus.lane_catalog.consensus_projection();
    preimage.field(tag::LANES, &consensus_lanes);
    let mut retained_lane_lineage = retained_lane_lineage.to_vec();
    retained_lane_lineage.sort_unstable_by(|left, right| {
        left.lane_id
            .cmp(&right.lane_id)
            .then_with(|| left.generation.cmp(&right.generation))
            .then_with(|| left.incarnation.cmp(&right.incarnation))
            .then_with(|| left.activation_height.cmp(&right.activation_height))
    });
    preimage.field(
        tag::LANE_LIFECYCLE_COUNT,
        &u64::try_from(retained_lane_lineage.len())
            .expect("retained lane lineage length fits in u64"),
    );
    for entry in retained_lane_lineage {
        preimage.field(tag::LANE_LIFECYCLE_LANE_ID, &entry.lane_id);
        preimage.field(tag::LANE_LIFECYCLE_GENERATION, &entry.generation);
        preimage.field(tag::LANE_LIFECYCLE_INCARNATION, &entry.incarnation);
        preimage.field(
            tag::LANE_LIFECYCLE_ACTIVATION_HEIGHT,
            &entry.activation_height,
        );
    }
    let mut dataspaces = nexus.dataspace_catalog.entries().iter().collect::<Vec<_>>();
    dataspaces.sort_unstable_by_key(|entry| entry.id);
    let dataspace_count = u64::try_from(dataspaces.len()).expect("dataspace count fits in u64");
    preimage.field(tag::DATASPACE_COUNT, &dataspace_count);
    for entry in dataspaces {
        preimage.field(tag::DATASPACE_ID, &entry.id);
        preimage.field(tag::DATASPACE_ALIAS, &entry.alias);
        preimage.field(tag::DATASPACE_FAULT_TOLERANCE, &entry.fault_tolerance);
    }
    preimage.field(
        tag::ROUTING_DEFAULT_LANE,
        &nexus.routing_policy.default_lane,
    );
    preimage.field(
        tag::ROUTING_DEFAULT_DATASPACE,
        &nexus.routing_policy.default_dataspace,
    );
    preimage.field(
        tag::ROUTING_RULE_COUNT,
        &u64::try_from(nexus.routing_policy.rules.len()).expect("routing rule count fits in u64"),
    );
    for rule in &nexus.routing_policy.rules {
        preimage.field(tag::ROUTING_RULE_LANE, &rule.lane);
        preimage.field(tag::ROUTING_RULE_DATASPACE, &rule.dataspace);
        preimage.field(tag::ROUTING_RULE_ACCOUNT, &rule.matcher.account);
        preimage.field(tag::ROUTING_RULE_INSTRUCTION, &rule.matcher.instruction);
    }
    let public_validator_mode = match nexus.staking.public_validator_mode {
        LaneValidatorMode::StakeElected => 0_u8,
        LaneValidatorMode::AdminManaged => 1,
    };
    let restricted_validator_mode = match nexus.staking.restricted_validator_mode {
        LaneValidatorMode::StakeElected => 0_u8,
        LaneValidatorMode::AdminManaged => 1,
    };
    preimage.field(tag::STAKING_PUBLIC_VALIDATOR_MODE, &public_validator_mode);
    preimage.field(
        tag::STAKING_RESTRICTED_VALIDATOR_MODE,
        &restricted_validator_mode,
    );
    preimage.field(
        tag::STAKING_MIN_VALIDATOR_STAKE,
        &nexus.staking.min_validator_stake,
    );
    preimage.field(
        tag::STAKING_MAX_VALIDATORS,
        &nexus.staking.max_validators.get(),
    );
    preimage.field(
        tag::STAKING_MAX_STAKE_SHARES_PER_VALIDATOR,
        &nexus.staking.max_stake_shares_per_validator.get(),
    );
    preimage.field(
        tag::STAKING_MAX_PENDING_UNBONDS_PER_SHARE,
        &nexus.staking.max_pending_unbonds_per_share.get(),
    );
    preimage.field(
        tag::STAKING_UNBONDING_DELAY_NS,
        &nexus.staking.unbonding_delay.as_nanos(),
    );
    preimage.field(tag::STAKING_MAX_SLASH_BPS, &nexus.staking.max_slash_bps);
    preimage.field(tag::STAKING_STAKE_ASSET_ID, &nexus.staking.stake_asset_id);
    preimage.field(
        tag::STAKING_STAKE_ESCROW_ACCOUNT_ID,
        &nexus.staking.stake_escrow_account_id,
    );
    preimage.field(
        tag::STAKING_SLASH_SINK_ACCOUNT_ID,
        &nexus.staking.slash_sink_account_id,
    );
    preimage.field(tag::FEES_ASSET, &nexus.fees.fee_asset_id);
    preimage.field(tag::FEES_SINK, &nexus.fees.fee_sink_account_id);
    preimage.field(tag::FEES_BASE, &nexus.fees.base_fee);
    preimage.field(tag::FEES_PER_BYTE, &nexus.fees.per_byte_fee);
    preimage.field(tag::FEES_PER_INSTRUCTION, &nexus.fees.per_instruction_fee);
    preimage.field(tag::FEES_PER_GAS_UNIT, &nexus.fees.per_gas_unit_fee);
    preimage.field(
        tag::FEES_SPONSOR_VAULT_CUSTODY_ACCOUNT_ID,
        &nexus.fees.sponsor_vault_custody_account_id,
    );
    let settlement_mode = match nexus.fees.settlement_mode {
        NexusFeeSettlementMode::Direct => 0_u8,
        NexusFeeSettlementMode::LaneRelayBurn => 1,
    };
    preimage.field(tag::FEES_SETTLEMENT_MODE, &settlement_mode);
    let successful_claim_fee_exempt_authorities = nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .iter()
        .map(|authority| {
            authority
                .canonical_i105()
                .expect("validated Nexus fee-exempt authority must encode as canonical I105")
        })
        .collect::<Vec<_>>();
    preimage.field(
        tag::FEES_SUCCESSFUL_CLAIM_EXEMPT_AUTHORITIES,
        &successful_claim_fee_exempt_authorities,
    );
    preimage.field(
        tag::DATASPACE_FEE_SPONSOR_PROGRAM_IDS,
        &nexus.dataspace_fee_sponsor_program_ids,
    );
    preimage.field(tag::AXT_SLOT_LENGTH_MS, &nexus.axt.slot_length_ms.get());
    preimage.field(tag::AXT_MAX_CLOCK_SKEW_MS, &nexus.axt.max_clock_skew_ms);
    preimage.field(
        tag::AXT_PROOF_CACHE_TTL_SLOTS,
        &nexus.axt.proof_cache_ttl_slots.get(),
    );
    preimage.field(
        tag::AXT_REPLAY_RETENTION_SLOTS,
        &nexus.axt.replay_retention_slots.get(),
    );
    preimage.field(tag::FUSION_FLOOR_TEU, &nexus.fusion.floor_teu);
    preimage.field(tag::FUSION_EXIT_TEU, &nexus.fusion.exit_teu);
    preimage.field(
        tag::FUSION_OBSERVATION_SLOTS,
        &nexus.fusion.observation_slots.get(),
    );
    preimage.field(
        tag::FUSION_MAX_WINDOW_SLOTS,
        &nexus.fusion.max_window_slots.get(),
    );
    preimage.field(tag::AUTOSCALE_ENABLED, &nexus.autoscale.enabled);
    preimage.field(
        tag::AUTOSCALE_MIN_LANE_ID,
        &nexus.autoscale.min_lane_id.get(),
    );
    preimage.field(
        tag::AUTOSCALE_MAX_LANE_ID_EXCLUSIVE,
        &nexus.autoscale.max_lane_id_exclusive.get(),
    );
    preimage.field(
        tag::AUTOSCALE_TARGET_BLOCK_MS,
        &nexus.autoscale.target_block_ms.get(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_OUT_LATENCY_RATIO_BITS,
        &nexus.autoscale.scale_out_latency_ratio.to_bits(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_IN_LATENCY_RATIO_BITS,
        &nexus.autoscale.scale_in_latency_ratio.to_bits(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_OUT_UTILIZATION_RATIO_BITS,
        &nexus.autoscale.scale_out_utilization_ratio.to_bits(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_IN_UTILIZATION_RATIO_BITS,
        &nexus.autoscale.scale_in_utilization_ratio.to_bits(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_OUT_WINDOW_BLOCKS,
        &nexus.autoscale.scale_out_window_blocks.get(),
    );
    preimage.field(
        tag::AUTOSCALE_SCALE_IN_WINDOW_BLOCKS,
        &nexus.autoscale.scale_in_window_blocks.get(),
    );
    preimage.field(
        tag::AUTOSCALE_COOLDOWN_BLOCKS,
        &nexus.autoscale.cooldown_blocks.get(),
    );
    preimage.field(
        tag::AUTOSCALE_PER_LANE_TARGET_TPS,
        &nexus.autoscale.per_lane_target_tps.get(),
    );
    preimage.field(
        tag::AUTOSCALE_LAST_TRANSITION_HEIGHT,
        &nexus.autoscale.last_transition_height,
    );
    preimage.field(tag::COMMIT_WINDOW_SLOTS, &nexus.commit.window_slots.get());
    let da = &nexus.da;
    preimage.field(tag::DA_Q_IN_SLOT_TOTAL, &da.q_in_slot_total.get());
    preimage.field(tag::DA_Q_IN_SLOT_PER_DS_MIN, &da.q_in_slot_per_ds_min.get());
    preimage.field(tag::DA_SAMPLE_SIZE_BASE, &da.sample_size_base.get());
    preimage.field(tag::DA_SAMPLE_SIZE_MAX, &da.sample_size_max.get());
    preimage.field(tag::DA_THRESHOLD_BASE, &da.threshold_base.get());
    preimage.field(tag::DA_PER_ATTESTER_SHARDS, &da.per_attester_shards.get());
    preimage.field(
        tag::DA_INGEST_QUOTA_WINDOW_BLOCKS,
        &da.ingest_quota_window_blocks.get(),
    );
    preimage.field(
        tag::DA_INGEST_QUOTA_MAX_COUNT_PER_ACCOUNT,
        &da.ingest_quota_max_count_per_account.get(),
    );
    preimage.field(
        tag::DA_INGEST_QUOTA_MAX_BYTES_PER_ACCOUNT,
        &da.ingest_quota_max_bytes_per_account.get(),
    );
    preimage.field(tag::DA_AUDIT_SAMPLE_SIZE, &da.audit.sample_size.get());
    preimage.field(tag::DA_AUDIT_WINDOW_COUNT, &da.audit.window_count.get());
    preimage.field(
        tag::DA_AUDIT_INTERVAL_NS,
        &nexus.da.audit.interval.as_nanos(),
    );
    preimage.field(
        tag::DA_RECOVERY_REQUEST_TIMEOUT_NS,
        &nexus.da.recovery.request_timeout.as_nanos(),
    );
    preimage.field(
        tag::DA_ROTATION_MAX_HITS_PER_WINDOW,
        &nexus.da.rotation.max_hits_per_window.get(),
    );
    preimage.field(
        tag::DA_ROTATION_WINDOW_SLOTS,
        &nexus.da.rotation.window_slots.get(),
    );
    preimage.field(tag::DA_ROTATION_SEED_TAG, &nexus.da.rotation.seed_tag);
    preimage.field(
        tag::DA_ROTATION_LATENCY_DECAY_BITS,
        &nexus.da.rotation.latency_decay.to_bits(),
    );
    preimage.field(
        tag::PIPELINE_AMX_PER_DATASPACE_BUDGET_MS,
        &pipeline.amx_per_dataspace_budget_ms,
    );
    preimage.field(
        tag::PIPELINE_AMX_GROUP_BUDGET_MS,
        &pipeline.amx_group_budget_ms,
    );
    preimage.field(
        tag::PIPELINE_AMX_PER_INSTRUCTION_NS,
        &pipeline.amx_per_instruction_ns,
    );
    preimage.field(
        tag::PIPELINE_AMX_PER_MEMORY_ACCESS_NS,
        &pipeline.amx_per_memory_access_ns,
    );
    preimage.field(
        tag::PIPELINE_AMX_PER_SYSCALL_NS,
        &pipeline.amx_per_syscall_ns,
    );
    let mut active_validators = active_validators.to_vec();
    active_validators.sort_by(|(left, _), (right, _)| left.cmp(right));
    preimage.field(
        tag::STAGED_ACTIVE_PUBLIC_LANE_VALIDATORS,
        &active_validators,
    );
    preimage.finish()
}
/// Compute the canonical Sumeragi commitment to the Nexus and AMX inputs: the hash of
/// [`sumeragi_nexus_amx_context_preimage`].
#[must_use]
pub fn sumeragi_nexus_amx_context_hash(
    nexus: &Nexus,
    pipeline: &Pipeline,
    active_validators: &[GenesisActiveNexusLaneRecord],
    retained_lane_lineage: &[SumeragiLaneLifecycleEntry],
) -> Hash {
    Hash::new(sumeragi_nexus_amx_context_preimage(
        nexus,
        pipeline,
        active_validators,
        retained_lane_lineage,
    ))
}
/// Tiered state backend settings controlling hot/cold storage behaviour.
#[derive(Debug, Clone)]
pub struct TieredState {
    /// Enable tiered snapshots.
    pub enabled: bool,
    /// Maximum number of keys to keep hot (0 = unlimited).
    pub hot_retained_keys: usize,
    /// Hot-tier byte budget using canonical encoded-key bytes plus measured value bytes
    /// (0 = unlimited). Grace or unspillable retention may temporarily exceed this budget.
    pub hot_retained_bytes: Bytes,
    /// Minimum snapshots to retain newly hot entries before demotion (0 = disabled).
    pub hot_retained_grace_snapshots: u64,
    /// Optional on-disk root for cold shards.
    pub cold_store_root: Option<PathBuf>,
    /// Optional on-disk root for DA-backed cold shards.
    pub da_store_root: Option<PathBuf>,
    /// Number of snapshots to retain on disk (0 = keep all).
    pub max_snapshots: usize,
    /// Optional cold-tier byte budget across snapshots (0 = unlimited).
    pub max_cold_bytes: Bytes,
}
/// Economics configuration for oracle slashing and rewards.
#[derive(Debug, Clone)]
pub struct OracleEconomics {
    /// Asset used to pay oracle rewards.
    pub reward_asset: AssetDefinitionId,
    /// Account that funds oracle rewards.
    pub reward_pool: AccountId,
    /// Fixed reward amount for an inlier observation.
    pub reward_amount: Quantity,
    /// Asset debited when applying penalties.
    pub slash_asset: AssetDefinitionId,
    /// Account credited with collected penalties.
    pub slash_receiver: AccountId,
    /// Penalty applied to outlier observations.
    pub slash_outlier_amount: Quantity,
    /// Penalty applied when a provider reports an error.
    pub slash_error_amount: Quantity,
    /// Penalty applied when a provider misses a slot.
    pub slash_no_show_amount: Quantity,
    /// Asset staked as a bond when opening disputes.
    pub dispute_bond_asset: AssetDefinitionId,
    /// Bond amount required to open a dispute.
    pub dispute_bond_amount: Quantity,
    /// Reward paid to successful challengers.
    pub dispute_reward_amount: Quantity,
    /// Penalty charged for frivolous disputes.
    pub frivolous_slash_amount: Quantity,
}
/// Approval thresholds for classed oracle governance stages.
#[derive(Debug, Clone, Copy)]
pub struct OracleChangeThresholds {
    /// Votes required for low-class changes.
    pub low: NonZeroUsize,
    /// Votes required for medium-class changes.
    pub medium: NonZeroUsize,
    /// Votes required for high-class changes.
    pub high: NonZeroUsize,
}
/// Governance configuration for oracle change proposals.
#[derive(Debug, Clone, Copy)]
pub struct OracleGovernance {
    /// SLA for the intake stage (blocks).
    pub intake_sla_blocks: u64,
    /// SLA for the rules committee stage (blocks).
    pub rules_sla_blocks: u64,
    /// SLA for the COP review stage (blocks).
    pub cop_sla_blocks: u64,
    /// SLA for the technical audit stage (blocks).
    pub technical_sla_blocks: u64,
    /// SLA for the policy jury stage (blocks).
    pub policy_jury_sla_blocks: u64,
    /// SLA for the enactment stage (blocks).
    pub enact_sla_blocks: u64,
    /// Intake approvals required.
    pub intake_min_votes: NonZeroUsize,
    /// Rules committee approvals required.
    pub rules_min_votes: NonZeroUsize,
    /// COP approvals keyed by change class.
    pub cop_min_votes: OracleChangeThresholds,
    /// Technical audit approvals required.
    pub technical_min_votes: NonZeroUsize,
    /// Policy jury approvals keyed by change class.
    pub policy_jury_min_votes: OracleChangeThresholds,
}
/// Twitter binding attestation guardrails.
#[derive(Debug, Clone)]
pub struct OracleTwitterBinding {
    /// Feed identifier expected for twitter follow attestations.
    pub feed_id: Name,
    /// Pepper identifier that must match the keyed hash.
    pub pepper_id: String,
    /// Maximum allowed TTL for attestations (milliseconds).
    pub max_ttl_ms: u64,
    /// Minimum allowed TTL for attestations (milliseconds).
    pub min_ttl_ms: u64,
    /// Minimum spacing between updates for the same binding hash (milliseconds).
    pub min_update_spacing_ms: u64,
}
/// Oracle aggregation configuration.
#[derive(Clone)]
pub struct Oracle {
    /// Maximum number of feed events retained per feed (oldest entries are pruned).
    pub history_depth: NonZeroUsize,
    /// Economic settings for oracle slashing/rewards.
    pub economics: OracleEconomics,
    /// Governance settings for oracle change proposals.
    pub governance: OracleGovernance,
    /// Guardrails for twitter follow binding attestations.
    pub twitter_binding: OracleTwitterBinding,
}
impl fmt::Debug for Oracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oracle")
            .field("history_depth", &self.history_depth)
            .field("governance", &self.governance)
            .field("twitter_binding", &self.twitter_binding)
            .finish()
    }
}
/// Compute lane configuration used by the gateway and scheduler.
#[derive(Debug, Clone)]
pub struct Compute {
    /// Whether compute is enabled.
    pub enabled: bool,
    /// Namespaces allowed for compute routes.
    pub namespaces: BTreeSet<Name>,
    /// Default TTL applied to calls (slots).
    pub default_ttl_slots: NonZeroU64,
    /// Maximum TTL accepted for calls (slots).
    pub max_ttl_slots: NonZeroU64,
    /// Maximum request payload size (bytes).
    pub max_request_bytes: Bytes,
    /// Maximum response payload size (bytes).
    pub max_response_bytes: Bytes,
    /// Per-call gas cap.
    pub max_gas_per_call: NonZeroU64,
    /// Resource profiles advertised by the node.
    pub resource_profiles: BTreeMap<Name, ComputeResourceBudget>,
    /// Default resource profile name.
    pub default_resource_profile: Name,
    /// Price families mapping cycles/egress into compute units.
    pub price_families: BTreeMap<Name, ComputePriceWeights>,
    /// Default price family identifier.
    pub default_price_family: Name,
    /// Authentication policy enforced when routes omit an override.
    pub auth_policy: ComputeAuthPolicy,
    /// Sandbox rules applied to compute execution.
    pub sandbox: ComputeSandboxRules,
    /// Economic settings for pricing, sponsorship, and governance bounds.
    pub economics: ComputeEconomics,
    /// Service-level objectives enforced by the gateway/scheduler.
    pub slo: ComputeSlo,
}
/// Content lane configuration.
#[derive(Debug, Clone)]
pub struct Content {
    /// Maximum tarball size accepted for a bundle (bytes).
    pub max_bundle_bytes: u64,
    /// Maximum number of files allowed in an archive.
    pub max_files: u32,
    /// Maximum allowed path length per entry.
    pub max_path_len: u32,
    /// Maximum retention window (blocks) for expiring bundles.
    pub max_retention_blocks: u64,
    /// Chunk size (bytes) used during ingestion.
    pub chunk_size_bytes: u32,
    /// Optional allow-list of accounts permitted to publish bundles.
    pub publish_allow_accounts: Vec<iroha_data_model::account::AccountId>,
    /// Rate/bandwidth limits for the content gateway.
    pub limits: ContentLimits,
    /// Default Cache-Control max-age (seconds) applied to bundles.
    pub default_cache_max_age_secs: u32,
    /// Upper bound for Cache-Control max-age (seconds).
    pub max_cache_max_age_secs: u32,
    /// Whether bundles are immutable by default.
    pub immutable_bundles: bool,
    /// Default read auth mode for bundles that omit an override.
    pub default_auth_mode: ContentAuthMode,
    /// Service-level objectives for the content gateway.
    pub slo: ContentSlo,
    /// Proof-of-work guard configuration for content fetches.
    pub pow: ContentPow,
    /// Default DA stripe layout applied to content bundles.
    pub stripe_layout: DaStripeLayout,
}
/// Content gateway SLO targets and rate limits.
#[derive(Debug, Clone, Copy)]
pub struct ContentSlo {
    /// Target p50 latency (milliseconds) for content responses.
    pub target_p50_latency_ms: NonZeroU32,
    /// Target p99 latency (milliseconds) for content responses.
    pub target_p99_latency_ms: NonZeroU32,
    /// Target availability (basis points) for content responses.
    pub target_availability_bps: NonZeroU32,
}
/// Rate/bandwidth limits for the content gateway.
#[derive(Debug, Clone, Copy)]
pub struct ContentLimits {
    /// Maximum requests per second accepted by the gateway.
    pub max_requests_per_second: NonZeroU32,
    /// Burst allowance for request tokens.
    pub request_burst: NonZeroU32,
    /// Maximum egress bytes per second served by the gateway.
    pub max_egress_bytes_per_second: NonZeroU64,
    /// Burst allowance for egress bytes.
    pub egress_burst_bytes: NonZeroU64,
}
/// Proof-of-work guard configuration for content fetches.
#[derive(Debug, Clone)]
pub struct ContentPow {
    /// Difficulty in leading zero bits (0 disables PoW).
    pub difficulty_bits: u8,
    /// Header name expected to carry PoW tokens.
    pub header_name: String,
}
impl Compute {
    /// Apply a governance price-family update with bounds enforcement.
    pub fn apply_price_update(
        &mut self,
        family: &Name,
        new_weights: ComputePriceWeights,
    ) -> core::result::Result<(), ComputeGovernanceError> {
        self.economics
            .apply_price_update(family, new_weights, &mut self.price_families)
    }
}
/// Compute SLO targets and caps.
#[derive(Debug, Clone, Copy)]
pub struct ComputeSlo {
    /// Maximum in-flight requests per route.
    pub max_inflight_per_route: NonZeroUsize,
    /// Maximum queued requests per route (beyond in-flight).
    pub queue_depth_per_route: NonZeroUsize,
    /// Maximum allowed requests per second (token-bucket).
    pub max_requests_per_second: NonZeroU32,
    /// Target p50 latency budget (milliseconds).
    pub target_p50_latency_ms: NonZeroU64,
    /// Target p95 latency budget (milliseconds).
    pub target_p95_latency_ms: NonZeroU64,
    /// Target p99 latency budget (milliseconds).
    pub target_p99_latency_ms: NonZeroU64,
}
/// Economic settings for compute pricing, sponsorship, and governance bounds.
#[derive(Debug, Clone)]
pub struct ComputeEconomics {
    /// Maximum compute units that may be charged per call.
    pub max_cu_per_call: NonZeroU64,
    /// Maximum amplification ratio (response/ingress) permitted for compute calls.
    pub max_amplification_ratio: NonZeroU32,
    /// Fee split across burn/validators/providers (basis points).
    pub fee_split: ComputeFeeSplit,
    /// Sponsor policy caps for subsidised calls.
    pub sponsor_policy: ComputeSponsorPolicy,
    /// Price delta bounds per risk class.
    pub price_bounds: BTreeMap<ComputePriceRiskClass, ComputePriceDeltaBounds>,
    /// Risk class mapping for price families.
    pub price_risk_classes: BTreeMap<Name, ComputePriceRiskClass>,
    /// Baseline price families used for governance delta calculations.
    pub price_family_baseline: BTreeMap<Name, ComputePriceWeights>,
    /// Multipliers applied for GPU/TEE/best-effort execution classes.
    pub price_amplifiers: ComputePriceAmplifiers,
}
impl ComputeEconomics {
    /// Apply a governance price update after validating bounds.
    pub fn apply_price_update(
        &self,
        family: &Name,
        new_weights: ComputePriceWeights,
        price_families: &mut BTreeMap<Name, ComputePriceWeights>,
    ) -> core::result::Result<(), ComputeGovernanceError> {
        let baseline = self.price_family_baseline.get(family).ok_or_else(|| {
            ComputeGovernanceError::UnknownPriceFamily {
                family: family.clone(),
            }
        })?;
        let risk_class = self.price_risk_classes.get(family).ok_or_else(|| {
            ComputeGovernanceError::MissingRiskClass {
                family: family.clone(),
            }
        })?;
        let bounds = self
            .price_bounds
            .get(risk_class)
            .ok_or_else(|| ComputeGovernanceError::MissingRiskBounds { class: *risk_class })?;
        if baseline.unit_label != new_weights.unit_label {
            return Err(ComputeGovernanceError::UnitLabelChanged {
                family: family.clone(),
                from: baseline.unit_label.clone(),
                to: new_weights.unit_label.clone(),
            });
        }
        let cycles_delta = delta_bps(new_weights.cycles_per_unit, baseline.cycles_per_unit);
        if cycles_delta > bounds.max_cycles_delta_bps.get() {
            return Err(ComputeGovernanceError::CyclesDeltaExceeded {
                family: family.clone(),
                delta_bps: cycles_delta,
                max_bps: bounds.max_cycles_delta_bps.get(),
            });
        }
        let egress_delta = delta_bps(
            new_weights.egress_bytes_per_unit,
            baseline.egress_bytes_per_unit,
        );
        if egress_delta > bounds.max_egress_delta_bps.get() {
            return Err(ComputeGovernanceError::EgressDeltaExceeded {
                family: family.clone(),
                delta_bps: egress_delta,
                max_bps: bounds.max_egress_delta_bps.get(),
            });
        }
        price_families.insert(family.clone(), new_weights);
        Ok(())
    }
    /// Validate that a requested sponsor allocation fits the configured caps.
    pub fn validate_sponsor_allocation(
        &self,
        requested_cu: u64,
    ) -> core::result::Result<(), ComputeGovernanceError> {
        self.validate_sponsor_allocation_with_usage(requested_cu, 0)
    }
    /// Validate sponsor allocation against per-call and daily caps.
    pub fn validate_sponsor_allocation_with_usage(
        &self,
        requested_cu: u64,
        consumed_today: u64,
    ) -> core::result::Result<(), ComputeGovernanceError> {
        let per_call_cap = self.sponsor_policy.max_cu_per_call.get();
        if requested_cu > per_call_cap {
            return Err(ComputeGovernanceError::SponsorCapExceeded {
                requested: requested_cu,
                limit: per_call_cap,
            });
        }
        let running = consumed_today.saturating_add(requested_cu);
        let daily_cap = self.sponsor_policy.max_daily_cu.get();
        if running > daily_cap {
            return Err(ComputeGovernanceError::SponsorCapExceeded {
                requested: running,
                limit: daily_cap,
            });
        }
        Ok(())
    }
}
fn delta_bps(value: NonZeroU64, baseline: NonZeroU64) -> u16 {
    let base = baseline.get() as u128;
    let value = value.get() as u128;
    let diff = if value > base {
        value - base
    } else {
        base - value
    };
    (diff.saturating_mul(10_000) / base) as u16
}
/// Cursor handling mode for server-facing iterable queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryCursorMode {
    /// Return only the first batch; do not store a server-side cursor.
    Ephemeral,
    /// Store a cursor in the LiveQueryStore and allow continuation.
    Stored,
}
/// Gas fees configuration: accepted assets, conversion mapping, and tech account.
#[derive(Debug, Clone)]
pub struct Gas {
    /// System-owned technical account that receives gas fee transfers.
    pub tech_account_id: String,
    /// Allowlist of accepted gas asset IDs.
    pub accepted_assets: Vec<String>,
    /// Deterministic conversion mapping (asset minimal units per one gas unit).
    #[allow(clippy::struct_field_names)]
    pub units_per_gas: Vec<GasRate>,
}
/// Governance-defined liquidity tiers for gas settlement routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GasLiquidity {
    /// Deep pools with negligible slippage.
    Tier1,
    /// Mid-depth pools with moderate slippage.
    #[default]
    Tier2,
    /// Thin pools or credit-constrained venues.
    Tier3,
}
impl FromStr for GasLiquidity {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "tier1" => Ok(Self::Tier1),
            "tier2" => Ok(Self::Tier2),
            "tier3" => Ok(Self::Tier3),
            _ => Err(()),
        }
    }
}
/// Rolling-volatility classification for gas settlement routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GasVolatility {
    /// Normal trading conditions.
    #[default]
    Stable,
    /// Elevated but healthy volatility.
    Elevated,
    /// Dislocated markets requiring maximal margin.
    Dislocated,
}
impl FromStr for GasVolatility {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stable" => Ok(Self::Stable),
            "elevated" => Ok(Self::Elevated),
            "dislocated" => Ok(Self::Dislocated),
            _ => Err(()),
        }
    }
}
/// Deterministic gas conversion entry mapping an accepted asset to units per gas.
#[derive(Debug, Clone)]
pub struct GasRate {
    /// Asset ID string
    pub asset: String,
    /// Minimal units of the asset per one gas unit
    pub units_per_gas: u64,
    /// Time-weighted price of the gas asset denominated in local units per XOR.
    pub twap_local_per_xor: Numeric,
    /// Liquidity profile used to derive haircut tiers for the conversion path.
    pub liquidity: GasLiquidity,
    /// Volatility bucket derived from oracle inputs.
    pub volatility: GasVolatility,
}
/// Block storage (Kura) configuration.
#[derive(Debug, Clone)]
pub struct Kura {
    /// Initialization mode for block storage.
    pub init_mode: InitMode,
    /// Directory path for on-disk storage.
    pub store_dir: WithOrigin<PathBuf>,
    /// Maximum on-disk footprint for Kura (bytes, 0 = unlimited).
    pub max_disk_usage_bytes: Bytes,
    /// Maximum canonical complete native context projection bytes per committed carrier.
    pub native_context_archive_max_bytes: NonZeroUsize,
    /// Number of recent blocks kept in memory.
    pub blocks_in_memory: NonZeroUsize,
    /// Total fixed native history-checkpoint slots; Core admits their checked complete layout.
    pub history_checkpoint_cache_capacity: NonZeroUsize,
    /// Finite requested-allocation limit for State's shared block-hash generations.
    /// Includes unpublished successors and generations retained by readers.
    pub block_hash_history_bytes: Bytes,
    /// Finite requested-allocation limit for State's transaction-membership generations.
    /// Includes unpublished successors and generations retained by readers.
    pub transaction_history_bytes: Bytes,
    /// Finite physical and requested-allocation limits for the retained membership segment.
    pub membership_storage: KuraMembershipStoragePolicy,
    /// Immutable bounded content-addressed FASTPQ artifact storage policy.
    pub fastpq_artifacts: KuraFastpqArtifactPolicy,
    /// Whether to append new blocks as JSONL to `blocks.jsonl` under the active Kura lane.
    pub debug_output_new_blocks: bool,
    /// Fsync policy for block persistence.
    pub fsync_mode: FsyncMode,
    /// Interval used when batching fsync calls.
    pub fsync_interval: Duration,
}
/// Finite limits for one retained membership generation; exhaustion requires real reclamation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KuraMembershipStoragePolicy {
    /// Maximum segment extent, including incomplete or abandoned reservations.
    pub max_bytes: NonZeroU64,
    /// Requested allocation bytes for original segment controls and append workspaces.
    pub memory_bytes: NonZeroUsize,
}
/// Immutable storage limits for opaque FASTPQ artifacts; these limits confer no proof authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KuraFastpqArtifactPolicy {
    /// Maximum complete artifact bytes, including its nominal encoded wrapper.
    pub max_artifact_bytes: NonZeroUsize,
    /// Maximum stable content records; one publication temporary is counted separately.
    pub max_artifacts: NonZeroUsize,
    /// Maximum actual stable plus temporary file bytes retained in the namespace.
    pub max_total_bytes: NonZeroU64,
}
/// Invalid configured FASTPQ storage geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KuraFastpqArtifactPolicyError {
    /// The namespace cannot hold one maximum-size artifact.
    #[error("FASTPQ artifact byte cap exceeds its aggregate storage byte cap")]
    ArtifactExceedsAggregate,
    /// A bounded read cannot represent its one-byte overflow probe.
    #[error("FASTPQ artifact byte cap leaves no representable overflow probe")]
    ArtifactReadOverflow,
    /// The stable count cannot represent the additional publication temporary.
    #[error("FASTPQ stable artifact count leaves no representable temporary slot")]
    TemporaryCountOverflow,
}
impl KuraFastpqArtifactPolicy {
    /// Validate the complete immutable storage policy before opening its namespace.
    ///
    /// # Errors
    /// Rejects a per-artifact cap above the aggregate cap or unrepresentable
    /// bounded-read and stable-plus-temporary geometry.
    pub fn validate(self) -> core::result::Result<(), KuraFastpqArtifactPolicyError> {
        let artifact_bytes = u64::try_from(self.max_artifact_bytes.get())
            .map_err(|_| KuraFastpqArtifactPolicyError::ArtifactReadOverflow)?;
        if artifact_bytes > self.max_total_bytes.get() {
            return Err(KuraFastpqArtifactPolicyError::ArtifactExceedsAggregate);
        }
        if self.max_artifact_bytes.get().checked_add(1).is_none()
            || artifact_bytes.checked_add(1).is_none()
        {
            return Err(KuraFastpqArtifactPolicyError::ArtifactReadOverflow);
        }
        self.max_artifacts
            .get()
            .checked_add(1)
            .ok_or(KuraFastpqArtifactPolicyError::TemporaryCountOverflow)?;
        Ok(())
    }
}
impl_default!(Queue => {
        Self {
            transaction_time_to_live: defaults::queue::TRANSACTION_TIME_TO_LIVE,
            capacity: defaults::queue::CAPACITY,
            capacity_per_user: defaults::queue::CAPACITY_PER_USER,
            max_retained_bytes: defaults::queue::MAX_RETAINED_BYTES,
            expired_cull_interval: defaults::queue::EXPIRED_CULL_INTERVAL,
            expired_cull_batch: defaults::queue::EXPIRED_CULL_BATCH,

        }
});
/// Node role in consensus participation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Full validator: proposes, votes, and finalizes blocks.
    Validator,
    /// Observer/sync-only: does not propose or vote; syncs blocks and serves queries.
    Observer,
}
/// Validator activation policy for a lane.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LaneValidatorMode {
    /// Validators are elected through the staking surface.
    StakeElected,
    /// Validators are administered directly without staking.
    AdminManaged,
}
impl LaneValidatorMode {
    /// Returns the canonical string representation for logs/telemetry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StakeElected => "stake_elected",
            Self::AdminManaged => "admin_managed",
        }
    }
}
/// Consensus key-rotation and algorithm policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumeragiKeys {
    /// Minimum lead time between publishing and activating a consensus key.
    pub activation_lead_blocks: u64,
    /// Dual-key overlap window during rotation.
    pub overlap_grace_blocks: u64,
    /// Grace window after declared consensus-key expiry.
    pub expiry_grace_blocks: u64,
    /// Allowed consensus signing algorithms.
    pub allowed_algorithms: BTreeSet<Algorithm>,
}
impl_default!(SumeragiKeys => {
        Self {
            activation_lead_blocks: defaults::sumeragi::KEY_ACTIVATION_LEAD_BLOCKS,
            overlap_grace_blocks: defaults::sumeragi::KEY_OVERLAP_GRACE_BLOCKS,
            expiry_grace_blocks: defaults::sumeragi::KEY_EXPIRY_GRACE_BLOCKS,
            allowed_algorithms: defaults::sumeragi::key_allowed_algorithms()
                .into_iter()
                .collect(),
        }
});
/// Optional overrides of the Sumeragi core's local parameters (`LocalParams`,
/// `specs/sumeragi.md` §12.4).
///
/// Field names follow `iroha_sumeragi::api::LocalParams`; the node maps them onto
/// `LocalParams::for_committee_size(n)` once the committee size `n` is known, so `None` keeps the
/// §9.3 default for that size. This crate does not depend on the consensus core. The complete
/// set is validated by the core at startup (§9.4); parsing only rejects zero intervals and a
/// zero `sync_batch`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SumeragiLocalOverrides {
    /// Base view timeout `T_base`.
    pub t_base: Option<Duration>,
    /// Timeout cap `T_max`.
    pub t_max: Option<Duration>,
    /// Largest start level.
    pub start_cap: Option<u32>,
    /// Fast commits needed to lower the start level by one.
    pub decay_after: Option<u32>,
    /// State rebroadcast interval while unsettled.
    pub rebroadcast_interval: Option<Duration>,
    /// Status interval while settled.
    pub status_keepalive: Option<Duration>,
    /// Payload build timeout.
    pub build_timeout: Option<Duration>,
    /// Body fetch retry interval.
    pub fetch_retry: Option<Duration>,
    /// Entries per sync request.
    pub sync_batch: Option<u16>,
    /// Sync request retry interval.
    pub sync_retry: Option<Duration>,
    /// Bytes per sync response.
    pub sync_max_bytes: Option<u32>,
    /// Observers kept in the peer table besides the committee.
    pub max_observers: Option<u32>,
}
impl SumeragiLocalOverrides {
    /// Whether no local parameter is overridden.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}
/// Whether `path` equals `base` or lies below it, compared lexically after removing `.`
/// components and resolving `..` against preceding components (no filesystem access, so
/// symbolic links are not followed).
#[must_use]
pub fn path_is_within(path: &std::path::Path, base: &std::path::Path) -> bool {
    fn normalize(path: &std::path::Path) -> PathBuf {
        use std::path::Component;
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => match out.components().next_back() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    // `/..` is `/`.
                    Some(Component::RootDir | Component::Prefix(_)) => {}
                    // A relative path that climbs above its start keeps the `..`.
                    None | Some(Component::ParentDir | Component::CurDir) => out.push(".."),
                },
                other => out.push(other.as_os_str()),
            }
        }
        out
    }
    normalize(path).starts_with(normalize(base))
}
#[cfg(test)]
mod sumeragi_core_config_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn local_overrides_is_empty_only_without_overrides() {
        assert!(SumeragiLocalOverrides::default().is_empty());
        let one = SumeragiLocalOverrides {
            sync_batch: Some(1),
            ..SumeragiLocalOverrides::default()
        };
        assert!(!one.is_empty());
    }

    #[test]
    fn path_is_within_compares_normalized_paths() {
        assert!(path_is_within(
            Path::new("./storage/x"),
            Path::new("storage")
        ));
        assert!(path_is_within(
            Path::new("storage"),
            Path::new("./storage/")
        ));
        assert!(path_is_within(Path::new("a/b/../b/c"), Path::new("a/b")));
        assert!(path_is_within(Path::new("/srv/a"), Path::new("/")));
        assert!(path_is_within(Path::new("/../srv"), Path::new("/srv")));
        assert!(!path_is_within(
            Path::new("storage-sumeragi-records"),
            Path::new("storage")
        ));
        assert!(!path_is_within(Path::new("a/../c"), Path::new("a")));
        assert!(!path_is_within(
            Path::new("../storage/x"),
            Path::new("storage")
        ));
        assert!(path_is_within(Path::new("../../x"), Path::new("..")));
        assert!(!path_is_within(
            Path::new("/srv"),
            Path::new("/srv/records")
        ));
    }

    #[test]
    fn default_record_paths_are_store_siblings() {
        assert_eq!(
            Sumeragi::default_records_dir(Path::new("./storage")),
            Some(PathBuf::from("./storage-sumeragi-records"))
        );
        assert_eq!(
            Sumeragi::default_installation_log(Path::new("/data/peer1")),
            Some(PathBuf::from("/data/peer1-sumeragi-installation.log"))
        );
        assert_eq!(
            Sumeragi::default_records_dir(Path::new("storage/peer0/")),
            Some(PathBuf::from("storage/peer0-sumeragi-records"))
        );
        assert_eq!(Sumeragi::default_records_dir(Path::new("/")), None);
        assert_eq!(Sumeragi::default_installation_log(Path::new("..")), None);
        assert_eq!(
            Sumeragi::store_sibling(Path::new("kura"), ".x"),
            Some(PathBuf::from("kura.x"))
        );
    }

    #[test]
    fn default_sumeragi_places_records_outside_the_default_store() {
        let sumeragi = Sumeragi::default();
        let store = PathBuf::from(defaults::kura::STORE_DIR);
        assert!(!path_is_within(&sumeragi.records_dir, &store));
        assert!(!path_is_within(
            &sumeragi.installation_log,
            &sumeragi.records_dir
        ));
        assert!(sumeragi.local.is_empty());
        assert!(sumeragi.retired_keys.is_empty());
    }
}
/// First-release Sumeragi node configuration.
///
/// Consensus mode, block cadence, DA layout, leader seed, roster, and quorum
/// rules are selected by signed genesis/height context rather than mutable
/// local configuration.
#[derive(Debug, Clone)]
pub struct Sumeragi {
    /// Node-local participation role.
    pub role: NodeRole,
    /// Public deployment binding for the runtime-only global beacon share signer.
    pub global_beacon_partial_signer_provider_handle: Option<String>,
    /// Exact non-zero provider contract revision paired with the beacon signer handle.
    pub global_beacon_partial_signer_provider_revision: Option<u64>,
    /// Exact non-zero public policy commitment paired with the beacon signer binding.
    pub global_beacon_partial_signer_provider_policy_digest: Option<[u8; 32]>,
    /// Consensus key-rotation and algorithm policy.
    pub keys: SumeragiKeys,
    /// Optional overrides of the core's local parameters.
    pub local: SumeragiLocalOverrides,
    /// Resolved directory of the safety records and the record-store id (§7.4); outside the
    /// Kura store directory.
    pub records_dir: PathBuf,
    /// Resolved path of the key installation log (§7.4); outside `records_dir`.
    pub installation_log: PathBuf,
    /// Retired consensus keys: restored like the others, never used to sign (§7.4 Keys).
    pub retired_keys: Vec<PublicKey>,
}
impl_default!(Sumeragi => {
        let store_dir = PathBuf::from(defaults::kura::STORE_DIR);
        Self {
            role: NodeRole::Validator,
            global_beacon_partial_signer_provider_handle: None,
            global_beacon_partial_signer_provider_revision: None,
            global_beacon_partial_signer_provider_policy_digest: None,
            keys: SumeragiKeys::default(),
            local: SumeragiLocalOverrides::default(),
            records_dir: Sumeragi::default_records_dir(&store_dir)
                .expect("the default Kura store directory has a final component"),
            installation_log: Sumeragi::default_installation_log(&store_dir)
                .expect("the default Kura store directory has a final component"),
            retired_keys: Vec::new(),
        }
});
impl Sumeragi {
    /// Default safety-record directory for a Kura store directory: its sibling
    /// `<store dir name>-sumeragi-records`. `None` when `store_dir` has no final component.
    #[must_use]
    pub fn default_records_dir(store_dir: &std::path::Path) -> Option<PathBuf> {
        Self::store_sibling(store_dir, defaults::sumeragi::RECORDS_DIR_SUFFIX)
    }
    /// Default installation-log file for a Kura store directory: its sibling
    /// `<store dir name>-sumeragi-installation.log`. `None` when `store_dir` has no final
    /// component.
    #[must_use]
    pub fn default_installation_log(store_dir: &std::path::Path) -> Option<PathBuf> {
        Self::store_sibling(store_dir, defaults::sumeragi::INSTALLATION_LOG_SUFFIX)
    }
    fn store_sibling(store_dir: &std::path::Path, suffix: &str) -> Option<PathBuf> {
        let name = store_dir.file_name()?;
        let mut sibling = name.to_os_string();
        sibling.push(suffix);
        Some(store_dir.with_file_name(sibling))
    }
}
/// Trusted peers configuration: the local peer and its peers.
#[derive(Debug, Clone)]
pub struct TrustedPeers {
    /// Local peer description.
    pub myself: Peer,
    /// Other trusted peers.
    pub others: UniqueVec<Peer>,
    /// Proof-of-Possession (PoP) for validator BLS keys, keyed by public key.
    /// Only BLS trusted peers with explicit valid entries form the validator
    /// roster. An empty map yields no validators, and entries cannot introduce
    /// peers outside the trusted-peer set.
    pub pops: std::collections::BTreeMap<PublicKey, Vec<u8>>,
}
impl TrustedPeers {
    /// Returns a list of trusted peers which is guaranteed to have at
    /// least one element - the id of the peer itself.
    pub fn into_non_empty_vec(self) -> UniqueVec<PeerId> {
        std::iter::once(self.myself)
            .chain(self.others)
            .map(|peer| peer.id().clone())
            .collect()
    }
    /// Tells whether a trusted peers list has some other peers except for the peer itself
    #[cfg(test)]
    pub fn contains_other_trusted_peers(&self) -> bool {
        !self.others.is_empty()
    }
    /// Return the validator roster size resolved by the bootstrap PoP policy.
    #[must_use]
    pub fn validator_roster_len(&self) -> usize {
        if self.pops.is_empty() {
            self.others.len().saturating_add(1)
        } else {
            self.pops.len()
        }
    }
}
/// Live query store configuration.
#[derive(Debug, Clone, Copy)]
pub struct LiveQueryStore {
    /// Idle time before a live query is evicted.
    pub idle_time: Duration,
    /// Maximum number of live queries.
    pub capacity: NonZeroUsize,
    /// Per-user live query limit.
    pub capacity_per_user: NonZeroUsize,
}
impl_default!(LiveQueryStore => {
        Self {
            idle_time: defaults::torii::QUERY_IDLE_TIME,
            capacity: defaults::torii::QUERY_STORE_CAPACITY,
            capacity_per_user: defaults::torii::QUERY_STORE_CAPACITY_PER_USER,
        }
});
/// Block synchronization parameters.
#[derive(Debug, Clone, Copy)]
pub struct BlockSync {
    /// Block gossip interval.
    pub gossip_period: Duration,
    /// Maximum block gossip interval (idle backoff ceiling).
    pub gossip_max_period: Duration,
    /// Fanout cap for block-sync gossip (peer samples, block sync updates, availability votes, and NEW_VIEW gossip).
    pub gossip_size: NonZeroU32,
}
/// Dataspace-aware transaction gossip targeting policy.
#[derive(Debug, Clone, Copy)]
pub struct DataspaceGossip {
    /// Drop gossip for unknown dataspaces instead of falling back to restricted routing.
    pub drop_unknown_dataspace: bool,
    /// Optional cap on restricted gossip targets (None = all authorized native lane validators).
    pub restricted_target_cap: Option<NonZeroUsize>,
    /// Optional cap on the number of peers targeted for public gossip (None = broadcast).
    pub public_target_cap: Option<NonZeroUsize>,
    /// Interval between reshuffles of public gossip target selection.
    pub public_target_reshuffle: Duration,
    /// Interval between reshuffles of restricted gossip target selection.
    pub restricted_target_reshuffle: Duration,
}
impl_default!(DataspaceGossip => {
        Self {
            drop_unknown_dataspace: defaults::network::TX_GOSSIP_DROP_UNKNOWN_DATASPACE,
            restricted_target_cap: defaults::network::TX_GOSSIP_RESTRICTED_TARGET_CAP,
            public_target_cap: defaults::network::TX_GOSSIP_PUBLIC_TARGET_CAP,
            public_target_reshuffle: defaults::network::TX_GOSSIP_PUBLIC_TARGET_RESHUFFLE,
            restricted_target_reshuffle: defaults::network::TX_GOSSIP_RESTRICTED_TARGET_RESHUFFLE,
        }
});
/// Transaction gossiping parameters.
#[derive(Debug, Clone, Copy)]
pub struct TransactionGossiper {
    /// Transaction gossip interval.
    pub gossip_period: Duration,
    /// Maximum number of transactions sent or accepted per gossip message (canonical ceiling: 512).
    pub gossip_size: NonZeroU32,
    /// Number of gossip periods to wait before re-sending the same transactions.
    pub gossip_resend_ticks: NonZeroU32,
    /// Dataspace-aware targeting options.
    pub dataspace: DataspaceGossip,
}
/// Proof endpoint DoS/backpressure policy.
#[derive(Debug, Clone, Copy)]
pub struct ProofApi {
    /// Rolling-window rate (requests per minute). None disables limiting.
    pub rate_per_minute: Option<NonZeroU32>,
    /// Burst tokens allowed within the window.
    pub burst: Option<NonZeroU32>,
    /// Maximum accepted proof request payload size.
    pub max_body_bytes: Bytes,
    /// Maximum proof-bearing request bodies buffered concurrently before handler admission.
    pub body_max_inflight: NonZeroUsize,
    /// Absolute deadline for reading one admitted proof-bearing request body.
    pub body_read_timeout: Duration,
    /// Egress budget for proof responses (bytes/sec). None disables.
    pub egress_bytes_per_sec: Option<NonZeroU64>,
    /// Burst budget for proof responses (bytes).
    pub egress_burst_bytes: Option<NonZeroU64>,
    /// Maximum page size accepted by proof listings.
    pub max_list_limit: NonZeroU32,
    /// Wall-clock timeout applied to proof list/count handlers.
    pub request_timeout: Duration,
    /// Cache lifetime advertised for proof lookups.
    pub cache_max_age: Duration,
    /// Retry hint surfaced on throttling responses.
    pub retry_after: Duration,
}
#[derive(Clone, Copy)]
struct RedactedSecret(usize);
impl RedactedSecret {
    const fn present(present: bool) -> Self {
        if present { Self(1) } else { Self(0) }
    }

    const fn count(count: usize) -> Self {
        Self(count)
    }
}
impl fmt::Debug for RedactedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[REDACTED; {} configured]", self.0)
    }
}
/// Listener-wide Torii API tokens with debug output that never exposes token text.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ToriiApiTokens(Vec<String>);
impl fmt::Debug for ToriiApiTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[REDACTED; {} Torii API token(s)]", self.0.len())
    }
}
impl core::ops::Deref for ToriiApiTokens {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl AsRef<[String]> for ToriiApiTokens {
    fn as_ref(&self) -> &[String] {
        &self.0
    }
}
impl From<Vec<String>> for ToriiApiTokens {
    fn from(tokens: Vec<String>) -> Self {
        Self(tokens)
    }
}
impl norito::json::JsonDeserialize for ToriiApiTokens {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> core::result::Result<Self, norito::json::Error> {
        <Vec<String> as norito::json::JsonDeserialize>::json_deserialize(parser).map(Self)
    }
}
/// Limits for app-facing list/query endpoints.
#[derive(Debug, Clone, Copy)]
pub struct AppApi {
    /// Default page size applied when clients omit `limit`.
    pub default_list_limit: NonZeroU32,
    /// Maximum page size accepted by app-facing list/query endpoints.
    pub max_list_limit: NonZeroU32,
    /// Maximum fetch size accepted by app-facing iterable queries.
    pub max_fetch_size: NonZeroU32,
    /// Rate-limiter cost per default-sized page, rounding partial pages up.
    pub rate_limit_cost_per_page: NonZeroU32,
    /// Maximum allowed clock skew for signed app requests.
    pub request_signature_max_clock_skew: Duration,
    /// TTL for app-request nonces retained for replay detection. Configuration
    /// parsing requires it to exceed twice the maximum clock skew.
    pub request_signature_nonce_ttl: Duration,
    /// Maximum number of nonce entries held in memory for replay detection.
    pub request_signature_replay_cache_capacity: NonZeroUsize,
}
/// Webhook delivery/backpressure configuration.
#[derive(Debug, Clone, Copy)]
pub struct Webhook {
    /// Maximum pending webhook deliveries persisted on disk.
    pub queue_capacity: NonZeroUsize,
    /// Maximum delivery attempts before a payload is dropped.
    pub max_attempts: NonZeroU32,
    /// Initial backoff delay applied to webhook retries.
    pub backoff_initial: Duration,
    /// Maximum backoff delay applied to webhook retries.
    pub backoff_max: Duration,
    /// HTTP connect timeout for webhook delivery.
    pub connect_timeout: Duration,
    /// HTTP write timeout for webhook delivery.
    pub write_timeout: Duration,
    /// HTTP read timeout for webhook delivery.
    pub read_timeout: Duration,
}
impl_default!(Webhook => {
        Self {
            queue_capacity: NonZeroUsize::new(defaults::torii::WEBHOOK_QUEUE_CAPACITY)
                .expect("default webhook queue capacity non-zero"),
            max_attempts: NonZeroU32::new(defaults::torii::WEBHOOK_MAX_ATTEMPTS)
                .expect("default webhook max attempts non-zero"),
            backoff_initial: Duration::from_millis(defaults::torii::WEBHOOK_BACKOFF_INITIAL_MS),
            backoff_max: Duration::from_millis(defaults::torii::WEBHOOK_BACKOFF_MAX_MS),
            connect_timeout: Duration::from_millis(defaults::torii::WEBHOOK_CONNECT_TIMEOUT_MS),
            write_timeout: Duration::from_millis(defaults::torii::WEBHOOK_WRITE_TIMEOUT_MS),
            read_timeout: Duration::from_millis(defaults::torii::WEBHOOK_READ_TIMEOUT_MS),
        }
});
/// Webhook destination security configuration (SSRF guard rails).
#[derive(Debug, Clone)]
pub struct WebhookSecurity {
    /// Master enable switch for webhook destination guard rails.
    pub enabled: bool,
    /// CIDR allow-list for webhook destinations (empty => only public IPs are allowed).
    pub allow_cidrs: Vec<String>,
}
impl_default!(WebhookSecurity => {
        Self {
            enabled: defaults::torii::webhook_security::ENABLED,
            allow_cidrs: defaults::torii::webhook_security::allow_cidrs(),
        }
});
/// Push notification delivery configuration (FCM/APNS).
#[derive(Clone)]
pub struct Push {
    /// Enable the push bridge (disabled by default).
    pub enabled: bool,
    /// Optional steady-state rate (requests/minute). None disables limiting.
    pub rate_per_minute: Option<NonZeroU32>,
    /// Optional burst tokens for push dispatch.
    pub burst: Option<NonZeroU32>,
    /// HTTP connect timeout used for push delivery.
    pub connect_timeout: Duration,
    /// HTTP request timeout used for push delivery.
    pub request_timeout: Duration,
    /// Maximum topics recorded per registered device.
    pub max_topics_per_device: NonZeroUsize,
    /// Firebase project ID used with FCM HTTP v1.
    pub fcm_project_id: Option<String>,
    /// Path to a Firebase service-account JSON key used to mint FCM OAuth tokens.
    pub fcm_service_account_path: Option<PathBuf>,
    /// APNs environment (`sandbox` or `production`).
    pub apns_environment: String,
    /// APNs topic, usually the app bundle identifier.
    pub apns_topic: Option<String>,
    /// Apple developer team ID for APNs token authentication.
    pub apns_team_id: Option<String>,
    /// APNs key ID for token authentication.
    pub apns_key_id: Option<String>,
    /// Path to the APNs `.p8` private key used for token authentication.
    pub apns_private_key_path: Option<PathBuf>,
    /// Optional APNs endpoint base URL override for tests or private deployments.
    pub apns_endpoint: Option<Url>,
}
impl fmt::Debug for Push {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Push")
            .field("enabled", &self.enabled)
            .field("rate_per_minute", &self.rate_per_minute)
            .field("burst", &self.burst)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_topics_per_device", &self.max_topics_per_device)
            .field("fcm_project_id", &self.fcm_project_id)
            .field(
                "fcm_service_account_path",
                &RedactedSecret::present(self.fcm_service_account_path.is_some()),
            )
            .field("apns_environment", &self.apns_environment)
            .field("apns_topic", &self.apns_topic)
            .field("apns_team_id", &self.apns_team_id)
            .field("apns_key_id", &self.apns_key_id)
            .field(
                "apns_private_key_path",
                &RedactedSecret::present(self.apns_private_key_path.is_some()),
            )
            .field(
                "apns_endpoint",
                &RedactedSecret::present(self.apns_endpoint.is_some()),
            )
            .finish()
    }
}
impl_default!(Push => {
        Self {
            enabled: defaults::torii::PUSH_ENABLED,
            rate_per_minute: defaults::torii::PUSH_RATE_LIMIT_ENABLED
                .then_some(defaults::torii::PUSH_RATE_PER_MINUTE),
            burst: defaults::torii::PUSH_RATE_LIMIT_ENABLED
                .then_some(defaults::torii::PUSH_BURST),
            connect_timeout: Duration::from_millis(defaults::torii::PUSH_CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(defaults::torii::PUSH_REQUEST_TIMEOUT_MS),
            max_topics_per_device: defaults::torii::PUSH_MAX_TOPICS_PER_DEVICE,
            fcm_project_id: None,
            fcm_service_account_path: None,
            apns_environment: defaults::torii::PUSH_APNS_ENVIRONMENT.to_string(),
            apns_topic: None,
            apns_team_id: None,
            apns_key_id: None,
            apns_private_key_path: None,
            apns_endpoint: None,
        }
});
/// Torii API configuration.
#[derive(Clone)]
pub struct Torii {
    /// API listening address.
    pub address: WithOrigin<SocketAddr>,
    /// Maximum request body size.
    pub max_content_len: Bytes,
    /// Base directory for Torii persistence (attachments, webhooks, DA queues).
    pub data_dir: PathBuf,
    /// Optional key pair used to sign transaction submission receipts.
    pub receipt_signer: Option<KeyPair>,
    /// Optional per-authority query rate (tokens/sec). None disables limiting.
    pub query_rate_per_authority_per_sec: Option<NonZeroU32>,
    /// Optional per-authority burst capacity (tokens).
    pub query_burst_per_authority: Option<NonZeroU32>,
    /// Maximum concurrent query executions admitted by Torii.
    pub query_max_inflight: NonZeroUsize,
    /// Maximum concurrent heavy query executions admitted by Torii.
    pub query_heavy_max_inflight: NonZeroUsize,
    /// Bytes split between bounded signed-query ingress and complete fanout working sets.
    /// Four ingress slots each account five live representations; fanout receives
    /// the remainder after fixed metadata and overlapping phase reservations.
    pub query_fanout_max_retained_bytes: Bytes,
    /// Maximum complete working set for one query, independent of aggregate capacity.
    pub query_fanout_max_working_set_bytes: Bytes,
    /// Absolute deadline for one admitted App routed-read body.
    pub app_api_routed_read_body_read_timeout: Duration,
    /// Maximum time a query waits for execution capacity before Torii rejects it.
    pub query_queue_timeout: Duration,
    /// Optional per-authority transaction submission rate (tokens/sec). None disables limiting.
    pub tx_rate_per_authority_per_sec: Option<NonZeroU32>,
    /// Optional per-authority transaction burst capacity (tokens).
    pub tx_burst_per_authority: Option<NonZeroU32>,
    /// Optional per-origin deploy rate (tokens/sec). None disables limiting.
    pub deploy_rate_per_origin_per_sec: Option<NonZeroU32>,
    /// Optional per-origin deploy burst capacity (tokens).
    pub deploy_burst_per_origin: Option<NonZeroU32>,
    /// Optional public Soracloud local-read rate per remote IP (tokens/sec). None disables limiting.
    pub soracloud_public_rate_per_ip_per_sec: Option<NonZeroU32>,
    /// Optional public Soracloud local-read burst capacity per remote IP (tokens).
    pub soracloud_public_burst_per_ip: Option<NonZeroU32>,
    /// Maximum concurrent public Soracloud local-read executions.
    pub soracloud_public_max_inflight: NonZeroUsize,
    /// Maximum hosted Soracloud response body buffered for P2P proxy forwarding.
    pub soracloud_public_max_response_bytes: Bytes,
    /// Optional signed Soracloud mutation rate per account+origin (tokens/sec).
    pub soracloud_mutation_rate_per_account_origin_per_sec: Option<NonZeroU32>,
    /// Optional signed Soracloud mutation burst per account+origin (tokens).
    pub soracloud_mutation_burst_per_account_origin: Option<NonZeroU32>,
    /// Maximum concurrent signed Soracloud mutation executions.
    pub soracloud_mutation_max_inflight: NonZeroUsize,
    /// Maximum signed Soracloud mutation body size before signature verification.
    pub soracloud_mutation_max_body_bytes: Bytes,
    /// Require a valid API token for app-facing endpoints.
    pub require_api_token: bool,
    /// Allowed API tokens (opaque strings). Empty means no tokens defined.
    pub api_tokens: ToriiApiTokens,
    /// Optional fee policy: asset definition id (e.g., `62Fk4FPcMuLvW5QjDGNF2a4jAmjM`).
    pub api_fee_asset_id: Option<String>,
    /// Optional fee policy: fixed amount per request.
    pub api_fee_amount: Option<Quantity>,
    /// Optional fee policy: receiver account id (canonical I105 literal).
    pub api_fee_receiver: Option<String>,
    /// SoraNet privacy ingestion guard rails (auth/rate/namespace).
    pub soranet_privacy_ingest: SoranetPrivacyIngest,
    /// Optional authenticated native Bootle/Lantern blind-issuance service.
    pub privacy_bootle_lantern_issuer: Option<ToriiBootleLanternIssuer>,
    /// CIDRs whose effective transport sources bypass API rate limits only.
    pub api_rate_limit_bypass_cidrs: Vec<String>,
    /// Exact effective transport source hosts trusted for internal API reads and routing.
    pub internal_api_trusted_cidrs: Vec<String>,
    /// Optional Torii base URLs used to fetch peer telemetry metadata.
    pub peer_telemetry_urls: Vec<Url>,
    /// Peer telemetry geo lookup configuration.
    pub peer_geo: ToriiPeerGeo,
    /// Emit filter-match debug traces (developer diagnostics only).
    pub debug_match_filters: bool,
    /// Operator authentication policy for operator-facing endpoints.
    pub operator_auth: ToriiOperatorAuth,
    /// Operator request-signature authentication for operator-facing endpoints.
    pub operator_signatures: ToriiOperatorSignatures,
    /// Maximum concurrent pre-auth connections (global).
    pub preauth_max_connections: Option<NonZeroUsize>,
    /// Maximum concurrent pre-auth connections per IP.
    pub preauth_max_connections_per_ip: Option<NonZeroUsize>,
    /// Pre-auth handshake rate per IP (tokens/sec).
    pub preauth_rate_per_ip_per_sec: Option<NonZeroU32>,
    /// Pre-auth handshake burst per IP (tokens).
    pub preauth_burst_per_ip: Option<NonZeroU32>,
    /// Optional temporary ban duration applied on repeated violations.
    pub preauth_temp_ban: Option<Duration>,
    /// Maximum number of temporary pre-auth bans retained in memory.
    pub preauth_ban_capacity: NonZeroUsize,
    /// Explicit source hosts allowed to bypass pre-auth limits.
    pub preauth_allow_cidrs: Vec<String>,
    /// Optional per-scheme pre-auth concurrency caps.
    pub preauth_scheme_limits: Vec<PreauthSchemeLimit>,
    /// Optional high-load threshold (queued txs) to enable rate limiting.
    /// When `None`, Torii uses an internal default.
    pub api_high_load_tx_threshold: Option<usize>,
    /// Optional queued-transaction threshold above which Torii rejects new stream admissions.
    /// When `None`, Torii uses its internal stream default.
    pub api_high_load_stream_threshold: Option<usize>,
    /// Optional queued-transaction threshold above which Torii rejects new subscription WebSockets.
    /// When `None`, Torii uses the streaming threshold.
    pub api_high_load_subscription_threshold: Option<usize>,
    /// Capacity of the broadcast channel used for events/SSE/webhooks.
    pub events_buffer_capacity: NonZeroUsize,
    /// WebSocket message timeout for Torii event/block streams.
    pub ws_message_timeout: Duration,
    /// Enable app-facing webhook routes and workers.
    pub webhooks_enabled: bool,
    /// Enable app-facing ZK attachment routes and workers.
    pub zk_attachments_enabled: bool,
    /// ZK attachments TTL (seconds) for app-facing attachments store.
    pub attachments_ttl_secs: u64,
    /// ZK attachments maximum allowed size per item (bytes).
    pub attachments_max_bytes: u64,
    /// Maximum number of attachments retained per tenant (0 = unlimited).
    pub attachments_per_tenant_max_count: u64,
    /// Maximum aggregate attachment bytes retained per tenant (0 = unlimited).
    pub attachments_per_tenant_max_bytes: u64,
    /// Maximum number of attachments retained by this node (1..=20,000).
    pub attachments_global_max_count: u64,
    /// Maximum aggregate attachment bytes retained by this node.
    pub attachments_global_max_bytes: u64,
    /// Allowed MIME types for attachment payloads (post-sniff).
    pub attachments_allowed_mime_types: Vec<String>,
    /// Maximum expanded bytes allowed when decompressing attachments.
    pub attachments_max_expanded_bytes: u64,
    /// Maximum nested archive depth allowed when decompressing attachments.
    pub attachments_max_archive_depth: u32,
    /// Execution mode for attachment sanitization.
    pub attachments_sanitizer_mode: AttachmentSanitizerMode,
    /// Attachment sanitization timeout (milliseconds).
    pub attachments_sanitize_timeout_ms: u64,
    /// Enable background ZK prover worker (non-consensus, app-facing only).
    pub zk_prover_enabled: bool,
    /// Scan period for the background prover worker (seconds).
    pub zk_prover_scan_period_secs: u64,
    /// Retention TTL for background ZK prover reports (seconds).
    pub zk_prover_reports_ttl_secs: u64,
    /// Maximum number of background ZK prover reports retained on disk.
    pub zk_prover_reports_max_count: u64,
    /// Maximum aggregate bytes retained by prover reports and summary shards.
    pub zk_prover_reports_max_bytes: u64,
    /// Maximum number of attachments processed concurrently by the prover worker.
    pub zk_prover_max_inflight: usize,
    /// Maximum aggregate attachment bytes processed per scan cycle.
    pub zk_prover_max_scan_bytes: u64,
    /// Maximum wall-clock time (milliseconds) spent in a single scan cycle.
    pub zk_prover_max_scan_millis: u64,
    /// Directory containing verifying key bytes for the background prover.
    pub zk_prover_keys_dir: PathBuf,
    /// Allowlisted backend prefixes for the background prover (empty = allow all).
    pub zk_prover_allowed_backends: Vec<String>,
    /// Allowlisted circuit identifiers for the background prover (empty = allow all).
    pub zk_prover_allowed_circuits: Vec<String>,
    /// Maximum concurrent IVM contract simulation and view workers.
    pub ivm_tooling_max_inflight: usize,
    /// Wall-clock timeout for synchronous IVM simulation and view tooling.
    pub ivm_tooling_timeout_ms: u64,
    /// Iroha Connect configuration.
    pub connect: Connect,
    /// ISO 20022 bridge configuration.
    pub iso_bridge: IsoBridge,
    /// Transaction-ingress compute and HTTP batch limits.
    pub transaction_ingress: TransactionIngress,
    /// Data-availability ingest configuration.
    pub da_ingest: DaIngest,
    /// SoraFS discovery cache configuration.
    pub sorafs_discovery: SorafsDiscovery,
    /// Embedded SoraFS storage configuration.
    pub sorafs_storage: SorafsStorage,
    /// Repair scheduler configuration for SoraFS.
    pub sorafs_repair: SorafsRepair,
    /// GC scheduler configuration for SoraFS.
    pub sorafs_gc: SorafsGc,
    /// Quota configuration for SoraFS control-plane endpoints.
    pub sorafs_quota: SorafsQuota,
    /// Alias cache policy shared across gateways and SDKs.
    pub sorafs_alias_cache: SorafsAliasCachePolicy,
    /// Gateway policy and automation configuration for SoraFS delivery.
    pub sorafs_gateway: SorafsGateway,
    /// Proof-of-Retrievability coordinator configuration.
    pub sorafs_por: SorafsPor,
    /// Appeal-finance settlement submitter configuration.
    pub sorafs_appeal_finance_settlement: SorafsAppealFinanceSettlement,
    /// Transport-specific configuration (Norito-RPC rollout, streaming knobs).
    pub transport: ToriiTransport,
    /// Native MCP endpoint configuration.
    pub mcp: ToriiMcp,
    /// Cross-origin browser access policy.
    pub cors: ToriiCors,
    /// Proof endpoint DoS/backpressure policy.
    pub proof_api: ProofApi,
    /// Optional account-onboarding authority configuration.
    pub account_onboarding: Option<AccountOnboarding>,
    /// Optional app-facing faucet configuration.
    pub faucet: Option<ToriiFaucet>,
    /// Optional RAM-LFE runtime configuration.
    pub ram_lfe: Option<ToriiRamLfe>,
    /// Optional transaction-history visibility/auth configuration.
    pub tx_history: Option<ToriiTxHistory>,
    /// Retail recipient lookup route configuration.
    pub recipient_lookup: ToriiRecipientLookup,
    /// Optional current bank-selected KAGEMUSHA issuer dependencies; absent disables serving.
    pub kagemusha_enrollment: Option<KagemushaEnrollmentIssuer>,
    /// Explicit Torii origins used for public-dataspace routed reads.
    pub public_dataspace_upstreams: Vec<ToriiPublicDataspaceUpstream>,
    /// App-facing query/backpressure limits.
    pub app_api: AppApi,
    /// Webhook delivery/backpressure configuration.
    pub webhook: Webhook,
    /// Webhook destination security configuration (SSRF guard rails).
    pub webhook_security: WebhookSecurity,
    /// Push notification delivery configuration.
    pub push: Push,
}
impl fmt::Debug for Torii {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Torii")
            .field("address", &self.address)
            .field("max_content_len", &self.max_content_len)
            .field("data_dir", &self.data_dir)
            .field(
                "receipt_signer",
                &RedactedSecret::present(self.receipt_signer.is_some()),
            )
            .field("query_max_inflight", &self.query_max_inflight)
            .field("query_heavy_max_inflight", &self.query_heavy_max_inflight)
            .field(
                "query_fanout_max_retained_bytes",
                &self.query_fanout_max_retained_bytes,
            )
            .field(
                "query_fanout_max_working_set_bytes",
                &self.query_fanout_max_working_set_bytes,
            )
            .field("require_api_token", &self.require_api_token)
            .field("api_tokens", &self.api_tokens)
            .field(
                "peer_telemetry_urls",
                &RedactedSecret::count(self.peer_telemetry_urls.len()),
            )
            .field("peer_geo", &self.peer_geo)
            .field("operator_auth", &self.operator_auth)
            .field("operator_signatures", &self.operator_signatures)
            .field("transport", &self.transport)
            .field("mcp", &self.mcp)
            .field("proof_api", &self.proof_api)
            .field(
                "account_onboarding",
                &RedactedSecret::present(self.account_onboarding.is_some()),
            )
            .field("faucet_configured", &self.faucet.is_some())
            .field(
                "ram_lfe_program_count",
                &self
                    .ram_lfe
                    .as_ref()
                    .map_or(0, |config| config.programs.len()),
            )
            .field("tx_history", &self.tx_history)
            .field("recipient_lookup", &self.recipient_lookup)
            .field("kagemusha_enrollment", &self.kagemusha_enrollment)
            .field("da_ingest", &self.da_ingest)
            .field("push", &self.push)
            .finish_non_exhaustive()
    }
}
/// Non-secret production policy for native Bootle/Lantern blind issuance.
///
/// Issuer trapdoors, authentication credentials, and provider implementations
/// are runtime-injected and are deliberately absent from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToriiBootleLanternIssuer {
    /// Durable one-shot authorization store directory.
    pub state_dir: PathBuf,
    /// Exact non-zero bound on concurrent native issuance operations.
    pub max_inflight: NonZeroUsize,
    /// Exact governed issuer identity resolved from committed state.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Exact governed policy identity resolved from committed state.
    pub policy_id: PrivacyPolicyIdV1,
    /// Number of committed blocks for which a fresh authorization is valid.
    pub authorization_lifetime_blocks: u64,
    /// Maximum retained authorization records.
    pub max_records: usize,
    /// Maximum reserved canonical authorization-store bytes.
    pub max_total_bytes: u64,
    /// Terminal records retained after their authoritative horizon.
    pub terminal_retention_blocks: u64,
    /// Deployment-owned provider-registry handle.
    pub runtime_provider_registry_handle: String,
    /// Exact non-zero provider-registry policy revision.
    pub runtime_provider_registry_revision: u64,
    /// Exact non-zero provider-registry public-policy digest.
    pub runtime_provider_registry_policy_digest: [u8; 32],
}
include!("actual/torii_tx_history.rs");
/// Retail recipient lookup route configuration for Torii app API.
#[derive(Debug, Clone)]
pub struct ToriiRecipientLookup {
    /// Governed FX corridor policy used to authorize retail recipient reads.
    pub policy_id: iroha_model_base::name::Name,
    /// Maximum route/lookup requests accepted per signer each minute.
    pub requests_per_minute: u32,
    /// HTTP request timeout applied to upstream bank Core API calls.
    pub request_timeout: Duration,
    /// Configured bank Core API routes keyed by canonical FI id.
    pub routes: Vec<ToriiRecipientLookupRoute>,
}
impl_default!(ToriiRecipientLookup => {
        Self {
            policy_id: defaults::torii::recipient_lookup::POLICY_ID
                .parse()
                .expect("default retail recipient policy id must be valid"),
            requests_per_minute: defaults::torii::recipient_lookup::REQUESTS_PER_MINUTE,
            request_timeout: Duration::from_millis(
                defaults::torii::recipient_lookup::REQUEST_TIMEOUT_MS,
            ),
            routes: Vec::new(),
        }
});
/// Single bank Core API route used by the retail recipient lookup endpoint.
#[derive(Clone)]
pub struct ToriiRecipientLookupRoute {
    /// Canonical FI identifier, for example `hbl.sbp` or `ubl.sbp`.
    pub fi_id: String,
    /// Bank Core API base URL.
    pub base_url: Url,
    /// Service bearer token used only by Torii when calling the bank Core API.
    pub bearer_token: String,
}
/// One explicitly configured public-dataspace Torii upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToriiPublicDataspaceUpstream {
    /// Exact numeric dataspace identity (`0` is the universal dataspace).
    pub dataspace_id: DataSpaceId,
    /// Canonical credential-free Torii base URL.
    pub base_url: Url,
}
impl fmt::Debug for ToriiRecipientLookupRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToriiRecipientLookupRoute")
            .field("fi_id", &self.fi_id)
            .field(
                "base_url",
                &RedactedSecret::present(!self.base_url.as_str().is_empty()),
            )
            .field("bearer_token", &RedactedSecret::present(true))
            .finish()
    }
}
/// Execution mode for attachment sanitization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentSanitizerMode {
    /// Run the sanitizer inside the Torii process.
    InProcess,
    /// Run the sanitizer in a dedicated subprocess.
    Subprocess,
}
impl AttachmentSanitizerMode {
    /// Render a stable label for config and telemetry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Subprocess => "subprocess",
        }
    }
}
/// Operator signature authentication configuration for Torii operator endpoints.
#[derive(Debug, Clone)]
pub struct ToriiOperatorSignatures {
    /// Master enable switch for signature auth on operator endpoints.
    pub enabled: bool,
    /// Allow the node identity key (from `[common]`) to sign operator requests.
    pub allow_node_key: bool,
    /// Absolute deadline for collecting one request body before signature verification.
    pub body_read_timeout: Duration,
    /// Additional allow-listed operator public keys.
    pub allowed_public_keys: Vec<PublicKey>,
    /// Maximum allowed clock skew for signed requests.
    pub max_clock_skew: Duration,
    /// TTL for nonces retained for replay detection. Configuration parsing
    /// requires it to exceed twice the maximum clock skew.
    pub nonce_ttl: Duration,
    /// Maximum number of nonce entries held for replay detection.
    pub replay_cache_capacity: NonZeroUsize,
}
impl_default!(ToriiOperatorSignatures => {
        Self {
            enabled: defaults::torii::operator_signatures::ENABLED,
            allow_node_key: defaults::torii::operator_signatures::ALLOW_NODE_KEY,
            body_read_timeout: defaults::torii::operator_signatures::BODY_READ_TIMEOUT,
            allowed_public_keys: defaults::torii::operator_signatures::allowed_public_keys(),
            max_clock_skew: Duration::from_secs(
                defaults::torii::operator_signatures::MAX_CLOCK_SKEW_SECS,
            ),
            nonce_ttl: Duration::from_secs(defaults::torii::operator_signatures::NONCE_TTL_SECS),
            replay_cache_capacity: NonZeroUsize::new(
                defaults::torii::operator_signatures::REPLAY_CACHE_CAPACITY,
            )
            .expect("default operator signature replay cache capacity must be non-zero"),
        }
});
/// Operator authentication configuration for Torii operator endpoints.
#[derive(Clone)]
pub struct ToriiOperatorAuth {
    /// Master enable switch for operator authentication.
    pub enabled: bool,
    /// Require mTLS at ingress before allowing operator endpoints.
    pub require_mtls: bool,
    /// Explicit trusted proxy hosts allowed to assert forwarded client certificates.
    pub mtls_trusted_proxy_cidrs: Vec<String>,
    /// Operator-token allow-list used only to bootstrap the first credential.
    pub tokens: Vec<String>,
    /// Auth attempt rate (per minute). None disables.
    pub rate_per_minute: Option<NonZeroU32>,
    /// Auth attempt burst tokens. None disables.
    pub burst: Option<NonZeroU32>,
    /// Per-kind capacity for expiry-bound operator-auth state.
    pub ephemeral_state_capacity: NonZeroUsize,
    /// Maximum number of persisted operator WebAuthn credentials.
    pub credential_capacity: NonZeroUsize,
    /// Temporary lockout policy for repeated failures.
    pub lockout: OperatorAuthLockout,
    /// WebAuthn configuration (when enabled).
    pub webauthn: Option<OperatorWebAuthnConfig>,
}
impl fmt::Debug for ToriiOperatorAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToriiOperatorAuth")
            .field("enabled", &self.enabled)
            .field("require_mtls", &self.require_mtls)
            .field("mtls_trusted_proxy_cidrs", &self.mtls_trusted_proxy_cidrs)
            .field("tokens", &RedactedSecret::count(self.tokens.len()))
            .field("rate_per_minute", &self.rate_per_minute)
            .field("burst", &self.burst)
            .field("ephemeral_state_capacity", &self.ephemeral_state_capacity)
            .field("credential_capacity", &self.credential_capacity)
            .field("lockout", &self.lockout)
            .field("webauthn", &self.webauthn)
            .finish()
    }
}
impl_default!(ToriiOperatorAuth => {
        Self {
            enabled: defaults::torii::operator_auth::ENABLED,
            require_mtls: defaults::torii::operator_auth::REQUIRE_MTLS,
            mtls_trusted_proxy_cidrs: defaults::torii::operator_auth::mtls_trusted_proxy_cidrs(),
            tokens: defaults::torii::operator_auth::tokens(),
            rate_per_minute: defaults::torii::operator_auth::RATE_PER_MIN.and_then(NonZeroU32::new),
            burst: defaults::torii::operator_auth::BURST.and_then(NonZeroU32::new),
            ephemeral_state_capacity: NonZeroUsize::new(
                defaults::torii::operator_auth::EPHEMERAL_STATE_CAPACITY,
            )
            .expect("default operator-auth ephemeral state capacity must be non-zero"),
            credential_capacity: NonZeroUsize::new(
                defaults::torii::operator_auth::CREDENTIAL_CAPACITY,
            )
            .expect("default operator-auth credential capacity must be non-zero"),
            lockout: OperatorAuthLockout::default(),
            webauthn: None,
        }
});
/// Lockout policy applied after repeated authentication failures.
#[derive(Debug, Clone, Copy)]
pub struct OperatorAuthLockout {
    /// Failures required to trigger a lockout (None disables lockouts).
    pub failures: Option<NonZeroU32>,
    /// Sliding window used to count failures.
    pub window: Duration,
    /// Lockout duration once triggered.
    pub duration: Duration,
}
impl_default!(OperatorAuthLockout => {
        Self {
            failures: NonZeroU32::new(defaults::torii::operator_auth::LOCKOUT_FAILURES),
            window: Duration::from_secs(defaults::torii::operator_auth::LOCKOUT_WINDOW_SECS),
            duration: Duration::from_secs(defaults::torii::operator_auth::LOCKOUT_DURATION_SECS),
        }
});
/// WebAuthn configuration required for operator auth.
#[derive(Debug, Clone)]
pub struct OperatorWebAuthnConfig {
    /// RP ID used for WebAuthn (domain).
    pub rp_id: String,
    /// RP display name used in WebAuthn options.
    pub rp_name: String,
    /// Allowed WebAuthn origins.
    pub origins: Vec<Url>,
    /// User identifier injected into WebAuthn registration options.
    pub user_id: Vec<u8>,
    /// User name injected into WebAuthn registration options.
    pub user_name: String,
    /// User display name injected into WebAuthn registration options.
    pub user_display_name: String,
    /// Challenge TTL for registration/assertion options.
    pub challenge_ttl: Duration,
    /// Session token TTL after successful assertion.
    pub session_ttl: Duration,
    /// Require user verification during assertions.
    pub require_user_verification: bool,
    /// Allowed WebAuthn algorithms.
    pub allowed_algorithms: Vec<OperatorWebAuthnAlgorithm>,
}
/// Supported WebAuthn algorithms for operator auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorWebAuthnAlgorithm {
    /// COSE alg -7 (ES256 / P-256).
    Es256,
    /// COSE alg -8 (Ed25519).
    Ed25519,
}
impl OperatorWebAuthnAlgorithm {
    /// Return the COSE algorithm identifier.
    #[must_use]
    pub const fn cose_alg(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Ed25519 => -8,
        }
    }
    /// Render a stable label for telemetry and logging.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Ed25519 => "ed25519",
        }
    }
}
/// Peer telemetry geo lookup configuration.
#[derive(Clone)]
pub struct ToriiPeerGeo {
    /// Enable geo lookups for peer telemetry.
    pub enabled: bool,
    /// Optional geo endpoint; required and HTTPS-only when lookups are enabled.
    pub endpoint: Option<Url>,
}
impl fmt::Debug for ToriiPeerGeo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToriiPeerGeo")
            .field("enabled", &self.enabled)
            .field(
                "endpoint",
                &RedactedSecret::present(self.endpoint.is_some()),
            )
            .finish()
    }
}
impl_default!(ToriiPeerGeo => {
        Self {
            enabled: defaults::torii::peer_geo::ENABLED,
            endpoint: defaults::torii::peer_geo::endpoint(),
        }
});
/// Ingress controls for SoraNet privacy telemetry endpoints.
#[derive(Debug, Clone)]
pub struct SoranetPrivacyIngest {
    /// Master enable switch for the `/v1/soranet/privacy/*` endpoints.
    pub enabled: bool,
    /// Requests-per-second budget (None disables limiting).
    pub rate_per_sec: Option<NonZeroU32>,
    /// Burst capacity for the ingest limiter.
    pub burst: Option<NonZeroU32>,
    /// CIDR allow-list for trusted submitters; empty -> deny.
    pub allow_cidrs: Vec<String>,
}
impl_default!(SoranetPrivacyIngest => {
        Self {
            enabled: defaults::torii::soranet_privacy_ingest::ENABLED,
            rate_per_sec: defaults::torii::soranet_privacy_ingest::RATE_PER_SEC
                .and_then(std::num::NonZeroU32::new),
            burst: defaults::torii::soranet_privacy_ingest::BURST
                .and_then(std::num::NonZeroU32::new),
            allow_cidrs: defaults::torii::soranet_privacy_ingest::allow_cidrs(),
        }
});
/// Transport-specific configuration exposed by Torii.
#[derive(Debug, Clone, Default)]
pub struct ToriiTransport {
    /// Explicit trusted proxy hosts whose appended `X-Forwarded-For` chain is
    /// used to derive the canonical remote IP.
    pub trusted_proxy_cidrs: Vec<String>,
    /// HTTP/1 listener, parser, and socket limits.
    pub http: ToriiHttpTransport,
    /// Optional HTTPS listener sharing the HTTP router and connection limits.
    pub https: Option<ToriiHttpsTransport>,
    /// Norito-RPC rollout settings.
    pub norito_rpc: NoritoRpcTransport,
}
include!("actual/torii_http_transport.rs");
include!("actual/torii_https_transport.rs");
include!("actual/torii_mcp_profile.rs");
/// Norito-RPC transport configuration (stage, allowlist, toggles).
#[derive(Clone)]
pub struct NoritoRpcTransport {
    /// Master enable switch for Norito-RPC decoding.
    pub enabled: bool,
    /// Require mTLS at the ingress tier before allowing Norito-RPC (surfaced via `/rpc/capabilities`).
    pub require_mtls: bool,
    /// Explicit trusted proxy hosts allowed to assert forwarded client certificates.
    pub mtls_trusted_proxy_cidrs: Vec<String>,
    /// Explicit list of client tokens permitted during the `canary` stage.
    pub allowed_clients: Vec<String>,
    /// Current rollout stage label.
    pub stage: NoritoRpcStage,
}
impl fmt::Debug for NoritoRpcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoritoRpcTransport")
            .field("enabled", &self.enabled)
            .field("require_mtls", &self.require_mtls)
            .field("mtls_trusted_proxy_cidrs", &self.mtls_trusted_proxy_cidrs)
            .field(
                "allowed_clients",
                &RedactedSecret::count(self.allowed_clients.len()),
            )
            .field("stage", &self.stage)
            .finish()
    }
}
/// Rollout stage for the Norito-RPC transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoritoRpcStage {
    /// Norito-RPC disabled outright.
    Disabled,
    /// Canary stage: restricted to the configured allowlist.
    Canary,
    /// General availability: all authenticated clients may use Norito-RPC (default).
    #[default]
    Ga,
}
impl NoritoRpcStage {
    /// Parse an exact first-release label into a stage variant.
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "disabled" => Some(Self::Disabled),
            "canary" => Some(Self::Canary),
            "ga" => Some(Self::Ga),
            _ => None,
        }
    }
    /// Canonical label representation for serialization.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Canary => "canary",
            Self::Ga => "ga",
        }
    }
}
impl_default!(NoritoRpcTransport => {
        Self {
            enabled: defaults::torii::transport::norito_rpc::ENABLED,
            require_mtls: defaults::torii::transport::norito_rpc::REQUIRE_MTLS,
            mtls_trusted_proxy_cidrs:
                defaults::torii::transport::norito_rpc::mtls_trusted_proxy_cidrs(),
            allowed_clients: defaults::torii::transport::norito_rpc::allowed_clients(),
            stage: NoritoRpcStage::parse(defaults::torii::transport::norito_rpc::STAGE)
                .expect("default Norito-RPC stage label is valid"),
        }
});
impl_default!(ToriiMcp => {
        Self {
            enabled: defaults::torii::mcp::ENABLED,
            max_request_bytes: defaults::torii::mcp::MAX_REQUEST_BYTES,
            max_tools_per_list: defaults::torii::mcp::MAX_TOOLS_PER_LIST,
            max_inflight_dispatches: NonZeroUsize::new(
                defaults::torii::mcp::MAX_INFLIGHT_DISPATCHES,
            )
            .expect("default MCP in-flight dispatch limit is non-zero"),
            profile: ToriiMcpProfile::parse(defaults::torii::mcp::PROFILE)
                .expect("default MCP profile label is valid"),
            expose_operator_routes: defaults::torii::mcp::EXPOSE_OPERATOR_ROUTES,
            allow_tool_prefixes: defaults::torii::mcp::allow_tool_prefixes(),
            deny_tool_prefixes: defaults::torii::mcp::deny_tool_prefixes(),
            rate_per_minute: defaults::torii::mcp::RATE_PER_MINUTE.and_then(NonZeroU32::new),
            burst: defaults::torii::mcp::BURST.and_then(NonZeroU32::new),
        }
});
/// Account-onboarding authority wiring exposed to Torii.
#[derive(Debug, Clone)]
pub struct AccountOnboarding {
    /// Account identifier that signs onboarding transactions.
    pub authority: AccountId,
    /// Runtime-only file from which the onboarding signer was loaded.
    pub private_key_file: PathBuf,
    /// Validated signer corresponding exactly to `authority`.
    pub signer: KeyPair,
    /// API credentials accepted by sponsored onboarding.
    pub credentials: Vec<AccountOnboardingCredential>,
    /// Permission names that onboarding may additionally grant to new accounts.
    pub additional_permissions: Vec<Name>,
    /// Optional exact sponsor program enrolled for each newly onboarded account.
    pub fee_sponsor_program_id: Option<FeeSponsorProgramId>,
    /// Default alias lease term applied during onboarding.
    pub lease_term_years: NonZeroU8,
    /// Optional native deterministic alias auto-renew configuration.
    pub auto_renew: Option<AccountOnboardingAutoRenew>,
}
/// One header-token credential accepted by sponsored onboarding.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountOnboardingCredential {
    /// Stable operator-facing credential identifier.
    pub id: Name,
    /// Exact domain or dataspace to which the credential is confined.
    pub scope: AccountOnboardingCredentialScope,
    /// BLAKE3 digest of the runtime-only token.
    pub token_hash: [u8; 32],
}
impl fmt::Debug for AccountOnboardingCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountOnboardingCredential")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("token_hash", &RedactedSecret::present(true))
            .finish()
    }
}
/// Exact textual scope attached to an onboarding API credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOnboardingCredentialScope {
    /// One fully-qualified domain.
    Domain(DomainId),
    /// One textual dataspace name, resolved against static and live catalogs later.
    Dataspace(Name),
}
/// Native deterministic auto-renew defaults configured for onboarded aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOnboardingAutoRenew {
    /// Lease term requested by each renewal.
    pub term_years: NonZeroU8,
    /// Maximum amount the owner authorizes per renewal.
    pub max_amount: Quantity,
    /// How far before expiry native block processing begins attempting renewal.
    pub renew_before_expiry: Duration,
    /// Deterministic retry delay after an insufficient-funds failure.
    pub retry_backoff: Duration,
    /// Consecutive failure limit before native processing suspends auto-renew.
    pub max_failures: NonZeroU32,
}
/// App-facing faucet configuration exposed to Torii.
#[derive(Debug, Clone)]
pub struct ToriiFaucet {
    /// Account identifier that signs faucet transfers.
    pub authority: AccountId,
    /// Runtime-only file from which the faucet signer was loaded.
    pub private_key_file: PathBuf,
    /// Validated signer corresponding exactly to `authority`.
    pub signer: KeyPair,
    /// Asset definition selector distributed by the faucet.
    ///
    /// This may be either a canonical Base58 asset definition identifier or an
    /// on-chain asset alias that must be resolved against world state.
    pub asset_definition_id: String,
    /// Fixed quantity transferred by each accepted faucet claim.
    pub amount: Quantity,
    /// Non-zero difficulty in leading zero bits for faucet proof-of-work.
    pub pow_difficulty_bits: NonZeroU8,
    /// Scrypt `log2(N)` cost parameter for faucet proof-of-work.
    pub pow_scrypt_log_n: u8,
    /// Scrypt block size parameter for faucet proof-of-work.
    pub pow_scrypt_r: u32,
    /// Scrypt parallelization parameter for faucet proof-of-work.
    pub pow_scrypt_p: u32,
    /// Maximum age of an accepted faucet PoW anchor, measured in committed blocks.
    pub pow_max_anchor_age_blocks: NonZeroU64,
    /// Number of recent committed blocks to scan for prior faucet claims when adapting difficulty.
    pub pow_adaptive_lookback_blocks: u64,
    /// Number of recent faucet claims required to add one extra difficulty bit.
    pub pow_adaptive_claims_per_extra_bit: u64,
    /// Maximum number of adaptive difficulty bits added on top of the base difficulty.
    pub pow_adaptive_max_extra_bits: u8,
    /// Whether finalized global threshold-beacon seeds are mixed into faucet challenges.
    pub pow_beacon_seed_enabled: bool,
}
/// RAM-LFE runtime configuration exposed to Torii.
#[derive(Debug, Clone)]
pub struct ToriiRamLfe {
    /// Program runtimes keyed by on-chain RAM-LFE program id.
    pub programs: Vec<ToriiRamLfeProgram>,
}
/// Per-program secret/signer material for the Torii RAM-LFE runtime.
#[derive(Clone)]
pub struct ToriiRamLfeProgram {
    /// On-chain RAM-LFE program handled by this runtime entry.
    pub program_id: iroha_data_model::ram_lfe::RamLfeProgramId,
    /// Hidden derivation secret committed by the on-chain program policy.
    pub secret: RamLfeSecret,
    /// Hidden BFV RAM-FHE program executed by this runtime entry.
    pub hidden_program: iroha_crypto::HiddenRamFheProgram,
    /// Private key used to sign receipts for this program.
    pub signer_private_key: PrivateKey,
    /// Optional receipt TTL enforced by the runtime.
    pub receipt_ttl: Option<Duration>,
}
impl fmt::Debug for ToriiRamLfeProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToriiRamLfeProgram")
            .field("program_id", &self.program_id)
            .field("secret", &self.secret)
            .field("hidden_program", &"[REDACTED hidden RAM-FHE program]")
            .field("signer_private_key", &"[REDACTED RAM-LFE signer]")
            .field("receipt_ttl", &self.receipt_ttl)
            .finish()
    }
}
/// Per-scheme cap applied by the Torii pre-auth gate.
#[derive(Debug, Clone)]
pub struct PreauthSchemeLimit {
    /// Scheme label (matches `ConnScheme::label()` in Torii).
    pub scheme: String,
    /// Maximum concurrent connections allowed for the scheme.
    pub max_connections: NonZeroUsize,
}
/// Replication policy applied to DA blobs based on their class.
#[derive(Debug, Clone)]
pub struct DaReplicationPolicy {
    default: RetentionPolicy,
    overrides: BTreeMap<BlobClass, RetentionPolicy>,
    taikai_availability: BTreeMap<TaikaiAvailabilityClass, RetentionPolicy>,
}
impl DaReplicationPolicy {
    /// Construct a policy from a default retention profile and class overrides.
    #[must_use]
    pub fn new(
        default: RetentionPolicy,
        overrides: BTreeMap<BlobClass, RetentionPolicy>,
        taikai_availability: BTreeMap<TaikaiAvailabilityClass, RetentionPolicy>,
    ) -> Self {
        Self {
            default,
            overrides,
            taikai_availability,
        }
    }
    fn retention_for_class(&self, class: BlobClass) -> &RetentionPolicy {
        self.overrides.get(&class).unwrap_or(&self.default)
    }
    fn retention_for_taikai(
        &self,
        availability: Option<TaikaiAvailabilityClass>,
    ) -> &RetentionPolicy {
        availability
            .and_then(|class| self.taikai_availability.get(&class))
            .unwrap_or_else(|| self.retention_for_class(BlobClass::TaikaiSegment))
    }
    /// Returns the enforced retention profile for the provided blob class.
    #[must_use]
    pub fn retention_for(
        &self,
        class: BlobClass,
        availability: Option<TaikaiAvailabilityClass>,
    ) -> &RetentionPolicy {
        if class == BlobClass::TaikaiSegment {
            return self.retention_for_taikai(availability);
        }
        self.retention_for_class(class)
    }
    /// Returns the enforced profile and whether the submitted policy mismatched it.
    #[must_use]
    pub fn enforce<'a>(
        &'a self,
        class: BlobClass,
        availability: Option<TaikaiAvailabilityClass>,
        submitted: &RetentionPolicy,
    ) -> (&'a RetentionPolicy, bool) {
        let expected = self.retention_for(class, availability);
        (expected, *submitted != *expected)
    }
}
impl_default!(DaReplicationPolicy => {
        let default = super::defaults::torii::da_replication_default_policy();
        let overrides = super::defaults::torii::da_replication_overrides()
            .into_iter()
            .collect();
        let taikai_availability = super::defaults::torii::taikai_availability_overrides()
            .into_iter()
            .collect();
        Self {
            default,
            overrides,
            taikai_availability,
        }
});
/// Torii transaction-ingress resource corridor.
#[derive(Debug, Clone, Copy)]
pub struct TransactionIngress {
    /// Maximum number of physical decode, verification, and admission jobs.
    pub max_concurrent_compute_jobs: NonZeroUsize,
    /// Maximum number of signed transactions in one HTTP batch.
    pub max_batch_transactions: NonZeroUsize,
    /// Maximum number of verified-source compiler working sets admitted concurrently.
    pub verified_source_max_concurrent_compiles: NonZeroUsize,
    /// Absolute deadline for reading one admitted verified-source request body.
    pub verified_source_body_read_timeout: Duration,
}
impl_default!(TransactionIngress => {
        Self {
            max_concurrent_compute_jobs:
                super::defaults::torii::TRANSACTION_INGRESS_MAX_CONCURRENT_COMPUTE_JOBS,
            max_batch_transactions:
                super::defaults::torii::TRANSACTION_INGRESS_MAX_BATCH_TRANSACTIONS,
            verified_source_max_concurrent_compiles:
                super::defaults::torii::VERIFIED_SOURCE_MAX_CONCURRENT_COMPILES,
            verified_source_body_read_timeout:
                super::defaults::torii::VERIFIED_SOURCE_BODY_READ_TIMEOUT,
        }
});
/// Data-availability ingest configuration.
#[derive(Clone)]
#[allow(clippy::struct_field_names)]
pub struct DaIngest {
    /// Per-`(lane, epoch)` bounds for committed manifests and, independently, in-flight
    /// reservations. At most twice this many fingerprints can be present during active ingests.
    pub replay_cache_capacity: NonZeroUsize,
    /// Maximum number of distinct `(lane, epoch)` windows retained globally.
    pub replay_cache_max_lane_epochs: NonZeroUsize,
    /// TTL applied to replay cache entries.
    pub replay_cache_ttl: Duration,
    /// Maximum sequence lag tolerated before rejecting manifests.
    pub replay_cache_max_sequence_lag: u64,
    /// Directory used to persist replay cursors across restarts.
    pub replay_cache_store_dir: PathBuf,
    /// Directory where canonical DA manifests are queued for SoraFS orchestration.
    pub manifest_store_dir: PathBuf,
    /// Maximum number of concurrent CPU-intensive DA ingest jobs.
    pub max_concurrent_compute_jobs: NonZeroUsize,
    /// Maximum number of DA spool batches queued for async disk persistence.
    pub spool_queue_capacity: NonZeroUsize,
    /// Maximum number of DA spool batches flushed by one worker write pass.
    pub spool_batch_max: NonZeroUsize,
    /// Symmetric key used to encrypt governance-only metadata entries.
    pub governance_metadata_key: Option<[u8; 32]>,
    /// Optional label advertised inside encrypted governance metadata envelopes.
    pub governance_metadata_key_label: Option<String>,
    /// Optional SoraNS anchor delivery configuration for Taikai envelopes.
    pub taikai_anchor: Option<DaTaikaiAnchor>,
    /// Replication policy enforced for each blob class.
    pub replication_policy: DaReplicationPolicy,
    /// Rent policy applied to DA submissions.
    pub rent_policy: DaRentPolicyV1,
    /// Optional telemetry cluster label used for Taikai ingest metrics.
    pub telemetry_cluster_label: Option<String>,
}
impl fmt::Debug for DaIngest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaIngest")
            .field("replay_cache_capacity", &self.replay_cache_capacity)
            .field(
                "replay_cache_max_lane_epochs",
                &self.replay_cache_max_lane_epochs,
            )
            .field("replay_cache_ttl", &self.replay_cache_ttl)
            .field(
                "replay_cache_max_sequence_lag",
                &self.replay_cache_max_sequence_lag,
            )
            .field("replay_cache_store_dir", &self.replay_cache_store_dir)
            .field("manifest_store_dir", &self.manifest_store_dir)
            .field(
                "max_concurrent_compute_jobs",
                &self.max_concurrent_compute_jobs,
            )
            .field("spool_queue_capacity", &self.spool_queue_capacity)
            .field("spool_batch_max", &self.spool_batch_max)
            .field(
                "governance_metadata_key",
                &RedactedSecret::present(self.governance_metadata_key.is_some()),
            )
            .field(
                "governance_metadata_key_label_configured",
                &self.governance_metadata_key_label.is_some(),
            )
            .field("taikai_anchor", &self.taikai_anchor)
            .field("replication_policy", &self.replication_policy)
            .field("rent_policy", &self.rent_policy)
            .field("telemetry_cluster_label", &self.telemetry_cluster_label)
            .finish()
    }
}
/// Configuration describing how Torii should publish Taikai artefacts to SoraNS.
#[derive(Clone)]
pub struct DaTaikaiAnchor {
    /// HTTP(S) endpoint that accepts Taikai envelope uploads.
    pub endpoint: Url,
    /// Optional bearer token supplied to the anchor service.
    pub api_token: Option<String>,
    /// Ed25519 identity required to sign content-bound anchor receipts.
    pub receipt_public_key: PublicKey,
    /// Poll interval between spool scans.
    pub poll_interval: Duration,
    /// Absolute deadline for one upload and signed receipt response.
    pub request_timeout: Duration,
}
impl fmt::Debug for DaTaikaiAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaTaikaiAnchor")
            .field("endpoint", &RedactedSecret::present(true))
            .field(
                "api_token",
                &RedactedSecret::present(self.api_token.is_some()),
            )
            .field("receipt_public_key", &self.receipt_public_key)
            .field("poll_interval", &self.poll_interval)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}
impl_default!(DaIngest => {
        Self {
            replay_cache_capacity: super::defaults::torii::DA_REPLAY_CACHE_CAPACITY,
            replay_cache_max_lane_epochs: super::defaults::torii::DA_REPLAY_CACHE_MAX_LANE_EPOCHS,
            replay_cache_ttl: Duration::from_secs(super::defaults::torii::DA_REPLAY_CACHE_TTL_SECS),
            replay_cache_max_sequence_lag: super::defaults::torii::DA_REPLAY_CACHE_MAX_SEQUENCE_LAG,
            replay_cache_store_dir: super::defaults::torii::da_replay_cache_store_dir(),
            manifest_store_dir: super::defaults::torii::da_manifest_store_dir(),
            max_concurrent_compute_jobs: super::defaults::torii::DA_MAX_CONCURRENT_COMPUTE_JOBS,
            spool_queue_capacity: super::defaults::torii::DA_SPOOL_QUEUE_CAPACITY,
            spool_batch_max: super::defaults::torii::DA_SPOOL_BATCH_MAX,
            governance_metadata_key: defaults::torii::da_governance_metadata_key(),
            governance_metadata_key_label: defaults::torii::da_governance_metadata_key_label(),
            taikai_anchor: None,
            replication_policy: DaReplicationPolicy::default(),
            rent_policy: DaRentPolicyV1::default(),
            telemetry_cluster_label: None,
        }
});
/// Torii-side SoraFS discovery configuration.
#[derive(Debug, Clone)]
pub struct SorafsDiscovery {
    /// Whether the discovery API is active.
    pub discovery_enabled: bool,
    /// Capability names recognised by the cache.
    pub known_capabilities: Vec<String>,
    /// Durable checkpoint containing provider advert replay high-water marks.
    pub replay_checkpoint_path: PathBuf,
    /// Maximum admitted-provider high-water marks accepted in the checkpoint.
    pub replay_checkpoint_max_entries: NonZeroUsize,
    /// Optional admission registry configuration.
    pub admission: Option<SorafsAdmission>,
    /// Optional publish peer discovery hints served to SoraFS deploy clients.
    pub publish: SorafsPublishDiscovery,
}
impl_default!(SorafsDiscovery => {
        Self {
            discovery_enabled: super::defaults::torii::SORAFS_DISCOVERY_ENABLED,
            known_capabilities: super::defaults::torii::sorafs_known_capabilities(),
            replay_checkpoint_path: super::defaults::torii::sorafs_discovery_replay_checkpoint_path(
            ),
            replay_checkpoint_max_entries:
                super::defaults::torii::SORAFS_DISCOVERY_REPLAY_MAX_ENTRIES,
            admission: None,
            publish: SorafsPublishDiscovery::default(),
        }
});
/// Governance admission registry configuration for SoraFS providers.
#[derive(Debug, Clone, Copy)]
pub struct SorafsAdmission;

/// Config-backed SoraFS publish peer hints exposed by Torii.
#[derive(Debug, Clone, Default)]
pub struct SorafsPublishDiscovery {
    /// Public gateway base URL deploy clients should verify after pinning.
    pub gateway_base_url: Option<SorafsPublishBaseUrl>,
    /// Torii URLs deploy clients should pin storage to after registering a paid pin.
    pub pin_torii_urls: Vec<SorafsPublishBaseUrl>,
}
/// Canonical HTTP(S) origin advertised to SoraFS deploy clients.
///
/// The validated representation has no credentials, query, fragment, or non-root path. Its
/// canonical configuration and wire spelling omits the root-path slash.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SorafsPublishBaseUrl(Url);
/// Maximum encoded length of one SoraFS publish origin.
pub const SORAFS_PUBLISH_BASE_URL_MAX_BYTES_V1: usize = 2_048;
/// Maximum number of pin Torii origins exposed by SoraFS publish discovery.
pub const SORAFS_PUBLISH_PIN_TORII_URLS_MAX_V1: usize = 500;
impl SorafsPublishBaseUrl {
    /// Return the canonical origin spelling without a trailing root-path slash.
    pub fn as_str(&self) -> &str {
        let serialized = self.0.as_str();
        serialized.strip_suffix('/').unwrap_or(serialized)
    }

    /// Return the parsed URL.
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}
impl fmt::Debug for SorafsPublishBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SorafsPublishBaseUrl")
            .field(&self.as_str())
            .finish()
    }
}
impl fmt::Display for SorafsPublishBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl FromStr for SorafsPublishBaseUrl {
    type Err = SorafsPublishBaseUrlError;

    fn from_str(raw: &str) -> core::result::Result<Self, Self::Err> {
        if raw.is_empty() {
            return Err(SorafsPublishBaseUrlError::Empty);
        }
        if raw.len() > SORAFS_PUBLISH_BASE_URL_MAX_BYTES_V1 {
            return Err(SorafsPublishBaseUrlError::TooLong);
        }
        if raw.chars().any(char::is_whitespace) || raw.chars().any(char::is_control) {
            return Err(SorafsPublishBaseUrlError::NonCanonical);
        }
        let url = Url::parse(raw).map_err(|_| SorafsPublishBaseUrlError::Invalid)?;
        let host = url.host().ok_or(SorafsPublishBaseUrlError::Invalid)?;
        if url.cannot_be_a_base() {
            return Err(SorafsPublishBaseUrlError::Invalid);
        }
        let literal_loopback = match host {
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
            url::Host::Domain(_) => false,
        };
        if url.scheme() != "https" && !(url.scheme() == "http" && literal_loopback) {
            return Err(SorafsPublishBaseUrlError::InsecureScheme);
        }
        let authority_start = url.scheme().len() + "://".len();
        let authority_end = url.as_str()[authority_start..]
            .find('/')
            .map_or(url.as_str().len(), |offset| authority_start + offset);
        if url.as_str()[authority_start..authority_end].contains('@') {
            return Err(SorafsPublishBaseUrlError::UserInfo);
        }
        if url.query().is_some() {
            return Err(SorafsPublishBaseUrlError::Query);
        }
        if url.fragment().is_some() {
            return Err(SorafsPublishBaseUrlError::Fragment);
        }
        if url.path() != "/" {
            return Err(SorafsPublishBaseUrlError::Path);
        }
        if url.port() == Some(0) {
            return Err(SorafsPublishBaseUrlError::ZeroPort);
        }
        if url.domain().is_some_and(|domain| domain.ends_with('.')) {
            return Err(SorafsPublishBaseUrlError::NonCanonical);
        }
        let canonical = url
            .as_str()
            .strip_suffix('/')
            .ok_or(SorafsPublishBaseUrlError::NonCanonical)?;
        if raw != canonical {
            return Err(SorafsPublishBaseUrlError::NonCanonical);
        }
        Ok(Self(url))
    }
}
/// Reason a configured SoraFS publish origin is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SorafsPublishBaseUrlError {
    /// No URL was supplied.
    #[error("must not be empty")]
    Empty,
    /// The URL exceeds the established Torii URL admission bound.
    #[error("must not exceed 2048 bytes")]
    TooLong,
    /// The value is not an absolute hierarchical URL with a host.
    #[error("must be an absolute HTTP(S) URL with a host")]
    Invalid,
    /// The transport is not HTTPS or literal-loopback HTTP.
    #[error("must use HTTPS; HTTP is allowed only for a literal loopback IP address")]
    InsecureScheme,
    /// User information was embedded in the authority.
    #[error("must not contain user information")]
    UserInfo,
    /// A query component was supplied.
    #[error("must not contain a query")]
    Query,
    /// A fragment component was supplied.
    #[error("must not contain a fragment")]
    Fragment,
    /// The URL contains a non-root path.
    #[error("must be an origin without a path")]
    Path,
    /// Port zero cannot identify a reachable service.
    #[error("must not use port zero")]
    ZeroPort,
    /// The spelling is not the unique canonical representation.
    #[error(
        "must use exact canonical spelling without whitespace, aliases, default ports, or a trailing slash"
    )]
    NonCanonical,
}
/// Native repair worker and durable transaction-forwarder configuration.
#[derive(Debug, Clone)]
pub struct SorafsRepair {
    /// Optional authenticated remote source reader for finalized native repair leases.
    pub source: Option<SorafsRepairSource>,
    /// Enable native repair processing.
    pub enabled: bool,
    /// Lease duration requested by native repair claims (seconds).
    pub claim_ttl_secs: u64,
    /// Renewal lead time for native repair claims (seconds).
    pub heartbeat_interval_secs: u64,
    /// Maximum transaction forwarding attempts before dead-lettering.
    pub max_attempts: u32,
    /// Concurrent native repair executions per node.
    pub worker_concurrency: usize,
}
impl_default!(SorafsRepair => {
        Self {
            source: None,
            enabled: defaults::sorafs::repair::ENABLED,
            claim_ttl_secs: defaults::sorafs::repair::CLAIM_TTL_SECS,
            heartbeat_interval_secs: defaults::sorafs::repair::HEARTBEAT_INTERVAL_SECS,
            max_attempts: defaults::sorafs::repair::MAX_ATTEMPTS,
            worker_concurrency: defaults::sorafs::repair::WORKER_CONCURRENCY,
        }
});
/// Account-authenticated remote repair source configuration.
#[derive(Debug, Clone)]
pub struct SorafsRepairSource {
    /// Provider-id hex to origin allowlist, matched against live signed adverts.
    /// HTTPS is required except for explicitly configured numeric loopback HTTP origins.
    pub origins: std::collections::BTreeMap<String, String>,
    /// Account owning the finalized repair worker lease.
    pub authority: AccountId,
    /// Owner-only runtime software credential; contents never enter configuration or logs.
    pub credential: PathBuf,
    /// Maximum duration of the complete remote repair operation in milliseconds.
    pub timeout_ms: u64,
}
/// GC scheduler configuration.
#[derive(Debug, Clone)]
pub struct SorafsGc {
    /// Enable the GC worker.
    pub enabled: bool,
    /// Optional directory for durable GC state.
    pub state_dir: Option<PathBuf>,
    /// GC cadence (seconds).
    pub interval_secs: u64,
    /// Maximum deletions per GC run.
    pub max_deletions_per_run: u32,
    /// Grace window for retention expiry (seconds).
    pub retention_grace_secs: u64,
}
impl_default!(SorafsGc => {
        Self {
            enabled: defaults::sorafs::gc::ENABLED,
            state_dir: defaults::sorafs::gc::state_dir(),
            interval_secs: defaults::sorafs::gc::INTERVAL_SECS,
            max_deletions_per_run: defaults::sorafs::gc::MAX_DELETIONS_PER_RUN,
            retention_grace_secs: defaults::sorafs::gc::RETENTION_GRACE_SECS,
        }
});
/// Proof-of-Retrievability coordinator configuration.
#[derive(Debug, Clone)]
pub struct SorafsPor {
    /// Enable the verified coordinator runtime.
    pub enabled: bool,
    /// Exact public bindings for the production PoTR signer and finalized-reader boundary.
    pub potr_runtime: Option<SorafsPotrRuntimeBinding>,
    /// Duration of a PoR epoch (seconds).
    pub epoch_interval_secs: u64,
    /// Window granted to providers to submit proofs (seconds).
    pub response_window_secs: u64,
    /// Private filesystem directory for coordinator, drand, and VRF state.
    pub state_dir: PathBuf,
    /// Pinned drand trust and transport configuration.
    pub drand: SorafsPorDrand,
    /// Durable authenticated provider VRF state path.
    pub vrf_state_path: PathBuf,
    /// Deadline from epoch start before missing VRFs enter the forced path.
    pub vrf_submission_deadline_secs: u64,
    /// Maximum durable provider VRF entries.
    pub vrf_max_entries: usize,
    /// Number of epochs retained in provider VRF state.
    pub vrf_retention_epochs: u64,
    /// Maximum accepted clock skew for signed provider VRF submissions.
    pub vrf_max_clock_skew_secs: u64,
    /// Minimum trusted-auditor signature count required on verdicts.
    pub auditor_signature_threshold: NonZeroU16,
}
impl_default!(SorafsPor => {
        Self {
            enabled: super::defaults::sorafs::por::ENABLED,
            potr_runtime: None,
            epoch_interval_secs: super::defaults::sorafs::por::EPOCH_INTERVAL_SECS,
            response_window_secs: super::defaults::sorafs::por::RESPONSE_WINDOW_SECS,
            state_dir: super::defaults::sorafs::por::state_dir(),
            drand: SorafsPorDrand::default(),
            vrf_state_path: super::defaults::sorafs::por::vrf_state_path(),
            vrf_submission_deadline_secs:
                super::defaults::sorafs::por::VRF_SUBMISSION_DEADLINE_SECS,
            vrf_max_entries: super::defaults::sorafs::por::VRF_MAX_ENTRIES,
            vrf_retention_epochs: super::defaults::sorafs::por::VRF_RETENTION_EPOCHS,
            vrf_max_clock_skew_secs: super::defaults::sorafs::por::VRF_MAX_CLOCK_SKEW_SECS,
            auditor_signature_threshold: NonZeroU16::new(
                super::defaults::sorafs::por::AUDITOR_SIGNATURE_THRESHOLD,
            )
            .expect("default PoR auditor signature threshold must be non-zero"),
        }
});
/// Exact non-secret production boundary for PoTR signing and finalized policy reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPotrRuntimeBinding {
    /// Independently administered gateway signer binding.
    pub gateway_signer: SorafsPotrRuntimeSignerBinding,
    /// Independently administered provider signer binding.
    pub provider_signer: SorafsPotrRuntimeSignerBinding,
    /// Exact Ed25519 gateway verification key.
    pub gateway_public_key: [u8; 32],
    /// Stable identity of the admission-reader facade.
    pub reader_id: [u8; 32],
    /// Stable identity of the immutable finalized-state source.
    pub source_id: [u8; 32],
    /// Stable identity of the admission-material resolver.
    pub resolver_id: [u8; 32],
    /// Exact baseline finalized provider-admission policy.
    pub baseline_admission_policy: SorafsPotrAdmissionPolicyBinding,
}
/// Public identity and qualification of one PoTR runtime signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPotrRuntimeSignerBinding {
    /// Stable opaque authenticated external signer handle.
    pub handle: String,
    /// Stable signer administration identity.
    pub signer_id: [u8; 32],
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the signer's public policy.
    pub policy_digest: [u8; 32],
}
/// Exact finalized provider-admission policy pinned at PoTR startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SorafsPotrAdmissionPolicyBinding {
    /// Provider governed by this admission revision.
    pub provider_id: [u8; 32],
    /// Stable identity of the provider-admission policy series.
    pub policy_identity: [u8; 32],
    /// Digest of the exact provider-admission revision.
    pub policy_digest: [u8; 32],
    /// Monotonic revision within the policy series.
    pub policy_sequence: u64,
    /// Finalized block height containing this revision.
    pub finalized_height: u64,
    /// Exact finalized block hash paired with the height.
    pub finalized_block_hash: [u8; 32],
    /// Digest of the exact council-verified admission envelope.
    pub admission_envelope_digest: [u8; 32],
}
/// Pinned drand chain and hardened HTTP client configuration for SoraFS PoR.
#[derive(Debug, Clone)]
pub struct SorafsPorDrand {
    /// Exact supported drand scheme identifier.
    pub scheme: String,
    /// Pinned chain hash.
    pub chain_hash: [u8; 32],
    /// Pinned compressed G2 public key.
    pub public_key: [u8; 96],
    /// Pinned chain genesis timestamp.
    pub genesis_time: u64,
    /// Pinned beacon period in seconds.
    pub period_secs: u64,
    /// Independent HTTPS chain-root endpoints.
    pub endpoints: Vec<String>,
    /// Required endpoint agreement count.
    pub quorum: u16,
    /// Maximum endpoint count accepted from configuration.
    pub max_endpoints: usize,
    /// TCP/TLS connection timeout.
    pub connect_timeout: Duration,
    /// Complete request timeout.
    pub request_timeout: Duration,
    /// Maximum response bytes.
    pub max_body_bytes: usize,
    /// Maximum age of a beacon relative to pinned chain timing.
    pub max_beacon_age_secs: u64,
    /// Maximum tolerated future clock skew.
    pub max_future_skew_secs: u64,
    /// Durable verified high-water path.
    pub state_path: PathBuf,
}
impl_default!(SorafsPorDrand => {
        Self {
            scheme: String::new(),
            chain_hash: [0; 32],
            public_key: [0; 96],
            genesis_time: 0,
            period_secs: 0,
            endpoints: Vec::new(),
            quorum: super::defaults::sorafs::por::DRAND_QUORUM,
            max_endpoints: super::defaults::sorafs::por::DRAND_MAX_ENDPOINTS,
            connect_timeout: Duration::from_millis(
                super::defaults::sorafs::por::DRAND_CONNECT_TIMEOUT_MS,
            ),
            request_timeout: Duration::from_millis(
                super::defaults::sorafs::por::DRAND_REQUEST_TIMEOUT_MS,
            ),
            max_body_bytes: super::defaults::sorafs::por::DRAND_MAX_BODY_BYTES,
            max_beacon_age_secs: super::defaults::sorafs::por::DRAND_MAX_BEACON_AGE_SECS,
            max_future_skew_secs: super::defaults::sorafs::por::DRAND_MAX_FUTURE_SKEW_SECS,
            state_path: super::defaults::sorafs::por::drand_state_path(),
        }
});
/// SoraFS appeal-finance settlement submitter configuration.
#[derive(Debug, Clone)]
pub struct SorafsAppealFinanceSettlement {
    /// Exact governed asset definition accepted by the appeal-finance APIs.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact ledger scale bound to the governed asset definition.
    pub asset_scale: u32,
    /// Governed inline appeal pricing policy.
    pub pricing: SorafsAppealPricingPolicy,
    /// Governed inline appeal settlement policy.
    pub settlement: SorafsAppealSettlementPolicy,
    /// Non-secret bindings for runtime-only external signer providers.
    pub submitter_signers: Vec<SorafsAppealFinanceSignerBinding>,
    /// Independent non-secret binding for the sealed checkpoint provider.
    pub checkpoint_provider: Option<SorafsAppealFinanceCheckpointBinding>,
    /// Interval between worker reconciliation scans for follow-up settlement steps.
    pub worker_scan_interval: Duration,
    /// Maximum signing/submission attempts for one semantic ledger operation.
    pub worker_max_retry_attempts: u32,
    /// Maximum pending semantic operations retained durably.
    pub worker_max_pending: usize,
    /// Maximum finalized idempotency tombstones retained durably.
    pub worker_max_completed: usize,
    /// Maximum terminal dead letters retained durably.
    pub worker_max_dead_letters: usize,
    /// Maximum canonical checkpoint size.
    pub worker_checkpoint_max_bytes: u64,
}
impl_default!(SorafsAppealFinanceSettlement => {
        Self {
            asset_definition_id: defaults::torii::sorafs_appeal_finance::asset_definition_id(),
            asset_scale: defaults::torii::sorafs_appeal_finance::ASSET_SCALE,
            pricing: SorafsAppealPricingPolicy::default(),
            settlement: SorafsAppealSettlementPolicy::default(),
            submitter_signers: Vec::new(),
            checkpoint_provider: None,
            worker_scan_interval: Duration::from_millis(
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_SCAN_INTERVAL_MS,
            ),
            worker_max_retry_attempts:
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_RETRY_ATTEMPTS,
            worker_max_pending:
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_PENDING,
            worker_max_completed:
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_COMPLETED,
            worker_max_dead_letters:
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_DEAD_LETTERS,
            worker_checkpoint_max_bytes:
                defaults::torii::SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES,
        }
});
/// Canonical inline appeal pricing policy carried by the validated config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealPricingPolicy {
    /// Governed policy version.
    pub version: String,
    /// Quote validity window in seconds.
    pub quote_ttl_secs: u64,
    /// Default moderation panel size used by pricing.
    pub default_panel_size: u32,
    /// Urgency multipliers.
    pub urgency_multipliers: SorafsAppealUrgencyMultipliers,
    /// Complete first-release appeal class inventory.
    pub classes: SorafsAppealPricingClasses,
}
impl_default!(SorafsAppealPricingPolicy => {
        Self {
            version: defaults::torii::sorafs_appeal_finance::BASELINE_POLICY_VERSION.to_owned(),
            quote_ttl_secs: defaults::torii::sorafs_appeal_finance::PRICING_QUOTE_TTL_SECS,
            default_panel_size: defaults::torii::sorafs_appeal_finance::DEFAULT_PANEL_SIZE,
            urgency_multipliers: SorafsAppealUrgencyMultipliers::default(),
            classes: SorafsAppealPricingClasses::default(),
        }
});
/// Canonical urgency multipliers for appeal pricing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealUrgencyMultipliers {
    /// Multiplier applied to normal-urgency appeals.
    pub normal: Numeric,
    /// Multiplier applied to high-urgency appeals.
    pub high: Numeric,
}
impl_default!(SorafsAppealUrgencyMultipliers => {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            normal: policy::numeric(policy::PRICING_URGENCY_NORMAL_MULTIPLIER),
            high: policy::numeric(policy::PRICING_URGENCY_HIGH_MULTIPLIER),
        }
});
/// Complete, closed first-release appeal pricing class inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealPricingClasses {
    /// Content moderation appeals.
    pub content: SorafsAppealPricingClassPolicy,
    /// Access-policy appeals.
    pub access: SorafsAppealPricingClassPolicy,
    /// Fraud appeals.
    pub fraud: SorafsAppealPricingClassPolicy,
    /// Other governed appeals.
    pub other: SorafsAppealPricingClassPolicy,
}
impl_default!(SorafsAppealPricingClasses => {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            content: SorafsAppealPricingClassPolicy::baseline(
                policy::PRICING_CONTENT_BASE_RATE_XOR,
                policy::PRICING_CONTENT_BACKLOG_TARGET,
                policy::PRICING_CONTENT_BACKLOG_CAP,
                policy::PRICING_CONTENT_SIZE_DIVISOR_MB,
                policy::PRICING_CONTENT_SIZE_CAP,
                policy::PRICING_CONTENT_MIN_DEPOSIT_XOR,
                policy::PRICING_CONTENT_MAX_DEPOSIT_XOR,
            ),
            access: SorafsAppealPricingClassPolicy::baseline(
                policy::PRICING_ACCESS_BASE_RATE_XOR,
                policy::PRICING_ACCESS_BACKLOG_TARGET,
                policy::PRICING_ACCESS_BACKLOG_CAP,
                policy::PRICING_ACCESS_SIZE_DIVISOR_MB,
                policy::PRICING_ACCESS_SIZE_CAP,
                policy::PRICING_ACCESS_MIN_DEPOSIT_XOR,
                policy::PRICING_ACCESS_MAX_DEPOSIT_XOR,
            ),
            fraud: SorafsAppealPricingClassPolicy::baseline(
                policy::PRICING_FRAUD_BASE_RATE_XOR,
                policy::PRICING_FRAUD_BACKLOG_TARGET,
                policy::PRICING_FRAUD_BACKLOG_CAP,
                policy::PRICING_FRAUD_SIZE_DIVISOR_MB,
                policy::PRICING_FRAUD_SIZE_CAP,
                policy::PRICING_FRAUD_MIN_DEPOSIT_XOR,
                policy::PRICING_FRAUD_MAX_DEPOSIT_XOR,
            ),
            other: SorafsAppealPricingClassPolicy::baseline(
                policy::PRICING_OTHER_BASE_RATE_XOR,
                policy::PRICING_OTHER_BACKLOG_TARGET,
                policy::PRICING_OTHER_BACKLOG_CAP,
                policy::PRICING_OTHER_SIZE_DIVISOR_MB,
                policy::PRICING_OTHER_SIZE_CAP,
                policy::PRICING_OTHER_MIN_DEPOSIT_XOR,
                policy::PRICING_OTHER_MAX_DEPOSIT_XOR,
            ),
        }
});
/// Canonical pricing parameters for one appeal class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealPricingClassPolicy {
    /// Base XOR rate.
    pub base_rate_xor: XorQuantity,
    /// Backlog at which the backlog multiplier reaches one.
    pub backlog_target: u32,
    /// Additional backlog multiplier cap.
    pub backlog_cap: Numeric,
    /// Evidence-size divisor in MiB.
    pub size_divisor_mb: Numeric,
    /// Additional evidence-size multiplier cap.
    pub size_cap: Numeric,
    /// Minimum admitted appeal deposit.
    pub min_deposit_xor: XorQuantity,
    /// Maximum admitted appeal deposit.
    pub max_deposit_xor: XorQuantity,
    /// Governed class-level surge multiplier.
    pub surge_multiplier: Numeric,
}
impl SorafsAppealPricingClassPolicy {
    fn baseline(
        base_rate_xor: &str,
        backlog_target: u32,
        backlog_cap: &str,
        size_divisor_mb: &str,
        size_cap: &str,
        min_deposit_xor: &str,
        max_deposit_xor: &str,
    ) -> Self {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            base_rate_xor: policy::xor_quantity(base_rate_xor),
            backlog_target,
            backlog_cap: policy::numeric(backlog_cap),
            size_divisor_mb: policy::numeric(size_divisor_mb),
            size_cap: policy::numeric(size_cap),
            min_deposit_xor: policy::xor_quantity(min_deposit_xor),
            max_deposit_xor: policy::xor_quantity(max_deposit_xor),
            surge_multiplier: policy::numeric(policy::PRICING_SURGE_MULTIPLIER),
        }
    }
}
/// Canonical inline appeal settlement policy carried by the validated config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealSettlementPolicy {
    /// Governed policy version.
    pub version: String,
    /// Default moderation panel size used by settlement.
    pub default_panel_size: u32,
    /// Juror reward schedule.
    pub panel_rewards: SorafsAppealPanelRewards,
    /// Complete first-release settlement rule inventory.
    pub rules: SorafsAppealSettlementRules,
}
impl_default!(SorafsAppealSettlementPolicy => {
        Self {
            version: defaults::torii::sorafs_appeal_finance::BASELINE_POLICY_VERSION.to_owned(),
            default_panel_size: defaults::torii::sorafs_appeal_finance::DEFAULT_PANEL_SIZE,
            panel_rewards: SorafsAppealPanelRewards::default(),
            rules: SorafsAppealSettlementRules::default(),
        }
});
/// Canonical appeal-panel reward schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealPanelRewards {
    /// XOR stipend paid to each attending juror.
    pub stipend_per_juror_xor: XorQuantity,
    /// XOR bonus pool paid once per case.
    pub case_bonus_xor: XorQuantity,
}
impl_default!(SorafsAppealPanelRewards => {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            stipend_per_juror_xor: policy::xor_quantity(policy::SETTLEMENT_STIPEND_PER_JUROR_XOR),
            case_bonus_xor: policy::xor_quantity(policy::SETTLEMENT_CASE_BONUS_XOR),
        }
});
/// Complete first-release appeal settlement rule inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealSettlementRules {
    /// Rules for terminal moderation decisions.
    pub decisions: SorafsAppealDecisionRules,
    /// Rule applied before panel activation.
    pub withdrawn_before_panel: SorafsAppealSettlementRule,
    /// Rule applied after panel activation.
    pub withdrawn_after_panel: SorafsAppealSettlementRule,
    /// Rule applied to frivolous appeals.
    pub frivolous: SorafsAppealSettlementRule,
    /// Rule applied while an appeal remains escalated.
    pub escalated: SorafsAppealSettlementRule,
}
impl_default!(SorafsAppealSettlementRules => {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            decisions: SorafsAppealDecisionRules::default(),
            withdrawn_before_panel: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_WITHDRAWN_BEFORE_PANEL_REFUND_RATE,
                policy::SETTLEMENT_WITHDRAWN_BEFORE_PANEL_TREASURY_RATE,
            ),
            withdrawn_after_panel: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_WITHDRAWN_AFTER_PANEL_REFUND_RATE,
                policy::SETTLEMENT_WITHDRAWN_AFTER_PANEL_TREASURY_RATE,
            ),
            frivolous: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_FRIVOLOUS_REFUND_RATE,
                policy::SETTLEMENT_FRIVOLOUS_TREASURY_RATE,
            ),
            escalated: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_ESCALATED_REFUND_RATE,
                policy::SETTLEMENT_ESCALATED_TREASURY_RATE,
            ),
        }
});
/// Complete first-release decision settlement rule inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealDecisionRules {
    /// Rule applied when the original decision is upheld.
    pub uphold: SorafsAppealSettlementRule,
    /// Rule applied when the original decision is overturned.
    pub overturn: SorafsAppealSettlementRule,
    /// Rule applied when the original decision is modified.
    pub modify: SorafsAppealSettlementRule,
}
impl_default!(SorafsAppealDecisionRules => {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            uphold: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_UPHOLD_REFUND_RATE,
                policy::SETTLEMENT_UPHOLD_TREASURY_RATE,
            ),
            overturn: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_OVERTURN_REFUND_RATE,
                policy::SETTLEMENT_OVERTURN_TREASURY_RATE,
            ),
            modify: SorafsAppealSettlementRule::baseline(
                policy::SETTLEMENT_MODIFY_REFUND_RATE,
                policy::SETTLEMENT_MODIFY_TREASURY_RATE,
            ),
        }
});
/// Canonical refund/treasury fractions for one appeal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealSettlementRule {
    /// Fraction of the deposit returned to the appellant.
    pub refund_rate: Numeric,
    /// Fraction of the deposit transferred to treasury.
    pub treasury_rate: Numeric,
}
impl SorafsAppealSettlementRule {
    fn baseline(refund_rate: &str, treasury_rate: &str) -> Self {
        use defaults::torii::sorafs_appeal_finance as policy;
        Self {
            refund_rate: policy::numeric(refund_rate),
            treasury_rate: policy::numeric(treasury_rate),
        }
    }
}
/// Public identity of one appeal-finance runtime signer provider.
///
/// The opaque handle is resolved only through [`crate::parameters::actual::Root`]
/// runtime dependencies. No private key or provider credential is accepted by
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealFinanceSignerBinding {
    /// Stable opaque authenticated external signer handle.
    pub handle: String,
    /// Exact transaction authority controlled by this signer.
    pub authority: AccountId,
    /// Exact Ed25519 public key expected from the runtime provider.
    pub public_key: PublicKey,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
    /// First finalized block height at which this binding is active.
    pub valid_from_block_height: u64,
    /// First finalized block height at which this binding is revoked.
    pub revoked_at_block_height: Option<u64>,
}
/// Public identity and policy of the independent sealed checkpoint provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsAppealFinanceCheckpointBinding {
    /// Stable opaque sealed checkpoint provider handle.
    pub handle: String,
    /// Exact Ed25519 checkpoint verification key.
    pub public_key: PublicKey,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Public identity and policy of the runtime moderation quarantine-key provider.
///
/// The opaque handle is resolved only through runtime dependency injection.
/// Credentials, key material, tokens, and vendor diagnostics are never valid
/// configuration inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsModerationQuarantineKeyProviderBinding {
    /// Stable opaque deployment-owned provider handle.
    pub handle: String,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Exact public identity and qualification of one native SoraFS transaction signer.
///
/// A credential path explicitly selects daemon-owned software custody; omission resolves
/// the handle through deployment-owned runtime injection. Secret bytes never enter config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsNativeTransactionSignerBinding {
    /// Owner-only canonical private-key credential; absent selects an external provider.
    pub software_credential: Option<PathBuf>,
    /// Stable opaque production provider handle.
    pub handle: String,
    /// Canonical transaction authority derived from `public_key`.
    pub authority: AccountId,
    /// Exact signature algorithm exposed by the runtime provider.
    pub algorithm: Algorithm,
    /// Exact public key exposed by the runtime provider.
    pub public_key: PublicKey,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Role-separated public bindings for native SoraFS transaction signers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SorafsNativeTransactionSignerBindings {
    /// Proof-outcome transaction signer binding.
    pub proof_outcome: Option<SorafsNativeTransactionSignerBinding>,
    /// Repair transaction signer binding.
    pub repair: Option<SorafsNativeTransactionSignerBinding>,
    /// Reserve/rent transaction signer binding.
    pub reserve: Option<SorafsNativeTransactionSignerBinding>,
    /// Orderbook transaction signer binding.
    pub orderbook: Option<SorafsNativeTransactionSignerBinding>,
}
/// Finite process-shared admission for private signer-journal inventory scans.
#[derive(Debug, Clone, Copy)]
pub struct SorafsSignerJournalInventory {
    /// Concurrent requested resident allocation bytes, including scan and retained paths.
    pub resident_bytes: Bytes,
    /// Concurrent logical directory and metadata probes; not physical disk bytes.
    pub metadata_probes: u64,
    /// Concurrent retained path, scan and receipt file descriptors.
    pub open_handles: u32,
}
impl SorafsSignerJournalInventory {
    /// Minimum requested bytes for bounded native ACL buffers, retained paths and receipt reads.
    pub const MIN_RESIDENT_BYTES: u64 = 2 * 1024 * 1024;
    /// One complete 65,536-record scan, its control entry, overflow guard and 65 pinned ancestors.
    pub const MIN_METADATA_PROBES: u64 = 8 * 65_538 + 92 * 65 + 34;
    /// Sixty-five ancestor handles, one ownership lock, one pinned receipt and four probes.
    pub const MIN_OPEN_HANDLES: u32 = 71;
}
impl Default for SorafsSignerJournalInventory {
    fn default() -> Self {
        Self {
            resident_bytes: defaults::sorafs::storage::SIGNER_JOURNAL_INVENTORY_RESIDENT_BYTES,
            metadata_probes: defaults::sorafs::storage::SIGNER_JOURNAL_INVENTORY_METADATA_PROBES,
            open_handles: defaults::sorafs::storage::SIGNER_JOURNAL_INVENTORY_OPEN_HANDLES,
        }
    }
}
/// Embedded SoraFS storage configuration (Torii-owned).
#[derive(Debug, Clone)]
pub struct SorafsStorage {
    /// Whether the storage worker is enabled.
    pub enabled: bool,
    /// Exact on-chain provider identity projected into this storage worker.
    pub provider_id: Option<ProviderId>,
    /// Root directory for chunk data, manifests, and telemetry artefacts.
    pub data_dir: PathBuf,
    /// Maximum on-disk footprint allocated to stored chunks.
    pub max_capacity_bytes: Bytes,
    /// Maximum number of concurrent fetch streams served.
    pub max_parallel_fetches: usize,
    /// Maximum number of pinned manifests accepted before back-pressure.
    pub max_pins: usize,
    /// One configured inventory resource pool shared by all SoraFS signer purposes.
    pub signer_journal_inventory: SorafsSignerJournalInventory,
    /// Periodic Proof-of-Retrievability sampling cadence (seconds).
    pub por_sample_interval_secs: u64,
    /// Maximum PDP segments that one governed challenge may sample.
    pub pdp_sample_window: u16,
    /// Aggregate in-memory budget for canonical PDP tree indexes.
    pub pdp_tree_memory_limit_bytes: Bytes,
    /// Whether authenticated moderation-screening admission is enabled.
    pub moderation_screening_enabled: bool,
    /// Canonical non-secret moderation authority bundle path.
    pub moderation_screening_authority_bundle_path: Option<PathBuf>,
    /// Reviewed BLAKE3 digest of the exact canonical authority bundle bytes.
    pub moderation_screening_authority_bundle_digest: Option<[u8; 32]>,
    /// Exact public identity and policy of the runtime quarantine-key provider.
    pub moderation_quarantine_key_provider: Option<SorafsModerationQuarantineKeyProviderBinding>,
    /// Governed PoP credential-service policy. Runtime key material is injected
    /// separately and is never represented in configuration.
    pub pop_credentials: Option<SorafsPopCredentialService>,
    /// Finalized-chain moderation orchestration policy. Transaction signing,
    /// finalized reads, and terminal sinks remain runtime-injected.
    pub moderation_orchestrator: Option<SorafsModerationOrchestrator>,
    /// Production case-bound SFM-4b3 evidence-viewer policy. Finalized reads,
    /// WebAuthn, rotating grants, erasure, and receipt signing remain
    /// runtime-injected.
    pub evidence_viewer: Option<SorafsEvidenceViewer>,
    /// Finalized-ledger reputation projection and external publication policy.
    ///
    /// Finalized queries, threshold signing, Governance DAG publication, and
    /// native journal transaction submission remain runtime-injected.
    pub reputation_runtime: Option<SorafsReputationRuntime>,
    /// Restart-safe finalized reserve-event feed into the durable
    /// transparency source index.
    pub reserve_transparency_runtime: Option<SorafsReserveTransparencyRuntime>,
    /// Authenticated immutable archive used to retain compacted finalized PoR
    /// replay records.
    ///
    /// The archive implementation and its Ed25519 signing key remain
    /// deployment-owned runtime dependencies. Configuration contains only the
    /// exact public identity, revision, policy digest, and verification key.
    pub por_replay_archive: Option<SorafsPorReplayArchive>,
    /// Finalized-ledger billing projection, statement delivery, and
    /// hedge-intent generation policy.
    ///
    /// Ledger queries, proof verification, external signing, immutable publication,
    /// acknowledgement authority, and sealed epoch storage remain
    /// runtime-injected.
    pub hedging_billing_runtime: Option<SorafsHedgingBillingRuntime>,
    /// Supervised finalized-ledger provider-ingest policy.
    ///
    /// Authenticated source fetching, completion signing, and sealed monotonic
    /// checkpointing are resolved from runtime-only providers by their
    /// configured public identities.
    pub provider_ingest_runtime: Option<SorafsProviderIngestRuntime>,
    /// Durable admission-bound PDP provider protocol policy.
    pub pdp_provider: SorafsPdpProviderPolicy,
    /// Retention and checkpoint bounds for auxiliary embedded runtime state.
    pub runtime: SorafsRuntimeRetention,
    /// Optional human-friendly alias advertised in telemetry.
    pub alias: Option<String>,
    /// Optional overrides applied when producing provider adverts.
    pub adverts: SorafsAdvertOverrides,
    /// Optional smoothing configuration applied to metering outputs.
    pub metering_smoothing: SorafsMeteringSmoothing,
    /// Stream-token issuance configuration for chunk-range gateways.
    pub stream_tokens: SorafsTokenConfig,
    /// Role-separated public bindings for native transaction signer providers.
    pub native_transaction_signers: SorafsNativeTransactionSignerBindings,
    /// Durable native orderbook transaction worker policy.
    pub orderbook_worker: SorafsOrderbookWorker,
    /// Durable native reserve/rent transaction worker policy.
    pub reserve_worker: SorafsReserveWorker,
    /// Canonical Norito trust-policy file required for reputation snapshot admission.
    pub reputation_trust_policy_path: Option<PathBuf>,
    /// Canonical Norito trust-policy file reused by the committed billing runtime.
    pub hedging_feed_trust_policy_path: Option<PathBuf>,
    /// Local SFM-4c privacy aggregate publication scheduler.
    pub privacy_aggregates: SorafsPrivacyAggregateSchedule,
    /// Local SFM-4b3 evidence-viewer audit-report publication scheduler.
    pub evidence_viewer_audits: SorafsEvidenceViewerAuditSchedule,
    /// Optional filesystem directory used to publish governance artefacts.
    pub governance_dag_dir: Option<PathBuf>,
    /// Optional publisher peer identifier used for signed Governance DAG blocks.
    pub governance_dag_publisher_peer_id: Option<String>,
    /// Opaque authenticated external signer handle for Governance DAG blocks.
    pub governance_dag_signer_handle: Option<String>,
    /// Exact non-zero public-policy revision required from the runtime signer.
    pub governance_dag_signer_revision: Option<u64>,
    /// Exact non-zero public-policy digest required from the runtime signer.
    pub governance_dag_signer_policy_digest: Option<[u8; 32]>,
    /// Canonical lowercase strong Ed25519 public key bound to the runtime signer.
    pub governance_dag_publisher_public_key_hex: Option<String>,
    /// Governance DAG public service and shared sealed producer-state binding.
    pub governance_dag_service: SorafsGovernanceDagService,
}
/// Non-secret qualification and worker policy for finalized PoR replay archival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPorReplayArchive {
    /// Stable deployment-owned runtime-provider handle.
    pub handle: String,
    /// Exact non-zero immutable archive identity.
    pub archive_id: [u8; 32],
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the archive's public policy.
    pub policy_digest: [u8; 32],
    /// Canonical strong Ed25519 key authenticating archive receipts.
    pub signing_public_key: [u8; 32],
    /// Supervised reconciliation and compaction cadence.
    pub poll_interval: Duration,
    /// Maximum records reconciled and compacted in one worker tick.
    pub max_records_per_tick: u32,
    /// Exact maximum signed successor receipts accepted in one lookup proof.
    pub max_successor_receipts: u32,
    /// Exact maximum canonical bytes accepted for one lookup proof.
    pub max_successor_proof_bytes: u64,
}
/// Governance DAG public-service configuration and shared sealed producer state.
#[derive(Debug, Clone)]
pub struct SorafsGovernanceDagService {
    /// Whether filesystem feeds are reconciled to the public endpoint continuously.
    pub enabled: bool,
    /// Optional service state directory; defaults below the governance publisher root.
    pub state_dir: Option<PathBuf>,
    /// IPFS-compatible HTTP API base URL used to add, pin, verify, and retrieve objects.
    pub ipfs_api_url: Option<String>,
    /// Public-head mode (`signed_http` or `ipns`).
    pub head_mode: String,
    /// Signed-head HTTP endpoint providing strong-ETag compare-and-swap.
    pub signed_head_url: Option<String>,
    /// IPNS name resolved by `ipns` mode.
    pub ipns_name: Option<String>,
    /// IPFS keystore alias passed to `name/publish` by `ipns` mode.
    pub ipns_key_name: Option<String>,
    /// Opaque runtime authenticator handle for the IPFS/Kubo API.
    pub ipfs_authenticator_handle: Option<String>,
    /// Exact non-zero IPFS authenticator provider revision.
    pub ipfs_authenticator_revision: Option<u64>,
    /// Exact non-zero digest of the IPFS authenticator public policy.
    pub ipfs_authenticator_policy_digest: Option<[u8; 32]>,
    /// Exact strong Ed25519 key verifying IPFS request-auth envelopes.
    pub ipfs_request_auth_public_key: Option<[u8; 32]>,
    /// Opaque runtime authenticator handle for the signed-head endpoint.
    pub head_authenticator_handle: Option<String>,
    /// Exact non-zero signed-head authenticator provider revision.
    pub head_authenticator_revision: Option<u64>,
    /// Exact non-zero digest of the signed-head authenticator public policy.
    pub head_authenticator_policy_digest: Option<[u8; 32]>,
    /// Exact strong Ed25519 key verifying signed-head request-auth envelopes.
    pub head_request_auth_public_key: Option<[u8; 32]>,
    /// Maximum lifetime accepted for one signed outbound request envelope.
    pub request_auth_max_envelope_lifetime_secs: u64,
    /// Maximum future clock skew accepted for an outbound request envelope.
    pub request_auth_max_future_skew_secs: u64,
    /// Opaque runtime sealed-state store handle shared with the signed local producer.
    pub checkpoint_store_handle: Option<String>,
    /// Exact non-zero sealed-state store provider revision.
    pub checkpoint_store_revision: Option<u64>,
    /// Exact non-zero digest of the sealed-state store public policy.
    pub checkpoint_store_policy_digest: Option<[u8; 32]>,
    /// Canonical lowercase strong Ed25519 public key expected on every block, node, and head.
    pub publisher_public_key_hex: Option<String>,
    /// Filesystem feed reconciliation interval.
    pub poll_interval: Duration,
    /// TCP/TLS connection timeout.
    pub connect_timeout: Duration,
    /// End-to-end HTTP request timeout.
    pub request_timeout: Duration,
    /// DNS resolution timeout before resolved addresses are pinned into the client.
    pub dns_timeout: Duration,
    /// Maximum remote response bytes accepted.
    pub max_response_bytes: Bytes,
    /// Maximum request payload bytes accepted from local feeds.
    pub max_request_bytes: Bytes,
    /// Maximum future clock skew accepted for source blocks and heads.
    pub max_future_skew_secs: u64,
    /// Permit plain HTTP endpoints (intended only for isolated test deployments).
    pub allow_insecure_http: bool,
    /// Permit a loopback, private, or otherwise non-public IPFS API endpoint.
    pub allow_private_ipfs_endpoint: bool,
    /// Permit a loopback, private, or otherwise non-public signed-head endpoint.
    pub allow_private_head_endpoint: bool,
    /// Permit publishing when the configured public head does not yet exist.
    pub allow_head_bootstrap: bool,
    /// Status, metrics, and bounded mirror query listener.
    pub listen_addr: String,
}
/// Dedicated standalone Governance DAG service configuration view.
///
/// Unlike [`Root`], this view never loads consensus identity or node private
/// keys from the source TOML.
#[derive(Debug, Clone)]
pub struct SorafsGovernanceDagServiceView {
    /// Verified filesystem publisher root consumed by the service.
    pub source_dir: Option<PathBuf>,
    /// Publisher peer identifier bound to the signed local producer.
    pub producer_publisher_peer_id: Option<String>,
    /// Opaque authenticated external signer handle bound to the local producer.
    pub producer_signer_handle: Option<String>,
    /// Exact non-zero public-policy revision required from the producer signer.
    pub producer_signer_revision: Option<u64>,
    /// Exact non-zero public-policy digest required from the producer signer.
    pub producer_signer_policy_digest: Option<[u8; 32]>,
    /// Canonical lowercase strong Ed25519 public key bound to the producer signer.
    pub producer_publisher_public_key_hex: Option<String>,
    /// Validated public publisher/mirror settings.
    pub service: SorafsGovernanceDagService,
}
impl SorafsGovernanceDagServiceView {
    /// Read and validate only standalone Governance DAG service fields.
    ///
    /// # Errors
    ///
    /// Returns [`FromTomlSourceError`] when the dedicated view cannot be read
    /// or its conditional service requirements are invalid.
    pub fn from_toml_source(mut src: TomlSource) -> Result<Self, FromTomlSourceError> {
        let root = src.table_mut();
        if root.contains_key("extends") {
            return Err(Report::new(FromTomlSourceError).attach(
                "the standalone Governance DAG service requires a self-contained TOML file; `extends` is not supported",
            ));
        }
        if let Some(storage) = root
            .get("sorafs")
            .and_then(|value| value.as_table())
            .and_then(|sorafs| sorafs.get("storage"))
            .and_then(|value| value.as_table())
        {
            if storage.contains_key("governance_dag_signing_key_path") {
                return Err(Report::new(FromTomlSourceError)
                    .attach("sorafs.storage.governance_dag_signing_key_path is forbidden in V1"));
            }
            for key in storage.keys() {
                if key.starts_with("governance_dag_")
                    && !matches!(
                        key.as_str(),
                        "governance_dag_dir"
                            | "governance_dag_publisher_peer_id"
                            | "governance_dag_signer_handle"
                            | "governance_dag_signer_revision"
                            | "governance_dag_signer_policy_digest_hex"
                            | "governance_dag_publisher_public_key_hex"
                            | "governance_dag_service"
                    )
                {
                    return Err(Report::new(FromTomlSourceError).attach(format!(
                        "sorafs.storage.{key} is not a supported Governance DAG V1 field"
                    )));
                }
            }
            if let Some(service) = storage
                .get("governance_dag_service")
                .and_then(|value| value.as_table())
            {
                for field in [
                    "ipfs_bearer_token_path",
                    "head_bearer_token_path",
                    "checkpoint_key_path",
                ] {
                    if service.contains_key(field) {
                        return Err(Report::new(FromTomlSourceError).attach(format!(
                            "sorafs.storage.governance_dag_service.{field} is forbidden in V1"
                        )));
                    }
                }
            }
        }
        root.retain(|key, _| key == "sorafs");
        if let Some(sorafs) = root
            .get_mut("sorafs")
            .and_then(|value| value.as_table_mut())
        {
            sorafs.retain(|key, _| key == "storage");
            if let Some(storage) = sorafs
                .get_mut("storage")
                .and_then(|value| value.as_table_mut())
            {
                storage.retain(|key, _| {
                    matches!(
                        key,
                        "governance_dag_dir"
                            | "governance_dag_publisher_peer_id"
                            | "governance_dag_signer_handle"
                            | "governance_dag_signer_revision"
                            | "governance_dag_signer_policy_digest_hex"
                            | "governance_dag_publisher_public_key_hex"
                            | "governance_dag_service"
                    )
                });
            }
        }
        ConfigReader::new()
            .without_env()
            .with_toml_source(src)
            .read_and_complete::<user::SorafsGovernanceDagServiceRoot>()
            .change_context(FromTomlSourceError)?
            .parse()
            .change_context(FromTomlSourceError)
    }
}
/// Retention and checkpoint bounds for auxiliary embedded SoraFS runtime state.
#[derive(Debug, Clone, Copy)]
pub struct SorafsRuntimeRetention {
    /// Maximum replay events retained for each local event stream.
    pub event_history_limit: usize,
    /// Maximum entries retained in each auxiliary state index.
    pub state_entry_limit: usize,
    /// Maximum encoded size accepted for one auxiliary runtime checkpoint.
    pub checkpoint_max_bytes: Bytes,
    /// Finalized reconciliation cadence for durable proof-outcome delivery.
    pub proof_outcome_forwarder_interval: Duration,
    /// Submission attempts allowed for one exact proof-outcome transaction.
    pub proof_outcome_max_attempts: u32,
}
/// Durable admission-bound PDP provider protocol policy.
#[derive(Debug, Clone, Copy)]
pub struct SorafsPdpProviderPolicy {
    /// Maximum pending challenges retained by the provider runtime.
    pub max_pending_records: u32,
    /// Maximum compact terminal replay records retained by the provider runtime.
    pub max_terminal_records: u32,
    /// Maximum canonical durable checkpoint size.
    pub checkpoint_max_bytes: Bytes,
    /// Maximum canonical challenge payload size.
    pub challenge_max_bytes: Bytes,
    /// Maximum canonical proof payload size.
    pub proof_max_bytes: Bytes,
    /// Minimum governed challenge response window in seconds.
    pub min_response_window_secs: u64,
    /// Maximum governed challenge response window in seconds.
    pub max_response_window_secs: u64,
    /// Maximum provider timestamp skew ahead of server time in seconds.
    pub max_future_skew_secs: u64,
    /// Minimum age of compact terminal replay records before pruning, in seconds.
    pub terminal_retention_secs: u64,
}
mod sorafs_pop_credentials;
pub use sorafs_pop_credentials::{SorafsPopApprovalSigner, SorafsPopCredentialService};
/// Non-secret production policy for finalized-chain moderation orchestration.
#[derive(Debug, Clone)]
pub struct SorafsModerationOrchestrator {
    /// Private local checkpoint-cache path.
    pub checkpoint_path: PathBuf,
    /// Identity-pinned authoritative sealed checkpoint-store handle.
    pub checkpoint_store_handle: String,
    /// Exact non-zero checkpoint-store adapter and public-policy revision.
    pub checkpoint_store_revision: u64,
    /// Exact checkpoint-store public-policy digest.
    pub checkpoint_store_policy_digest: [u8; 32],
    /// Archive-lifetime-stable Ed25519 trust anchor for sealed checkpoint statements.
    /// Provider-internal rotation must preserve this public identity in V1.
    pub checkpoint_store_attestation_public_key: [u8; 32],
    /// Governance authority used only for deterministic deadline maintenance.
    pub maintenance_authority: AccountId,
    /// Identity-pinned runtime-only moderation transaction signer handle.
    pub transaction_signer_handle: String,
    /// Exact non-zero moderation transaction signer revision.
    pub transaction_signer_revision: u64,
    /// Exact moderation transaction signer public-policy digest.
    pub transaction_signer_policy_digest: [u8; 32],
    /// Identity-pinned strict transaction ingress handle.
    pub strict_ingress_handle: String,
    /// Exact non-zero strict transaction ingress revision.
    pub strict_ingress_revision: u64,
    /// Exact strict transaction ingress public-policy digest.
    pub strict_ingress_policy_digest: [u8; 32],
    /// Identity-pinned settlement handoff handle.
    pub settlement_handoff_handle: String,
    /// Exact non-zero settlement handoff revision.
    pub settlement_handoff_revision: u64,
    /// Exact settlement handoff public-policy digest.
    pub settlement_handoff_policy_digest: [u8; 32],
    /// Identity-pinned publication handoff handle.
    pub publication_handoff_handle: String,
    /// Exact non-zero publication handoff revision.
    pub publication_handoff_revision: u64,
    /// Exact publication handoff public-policy digest.
    pub publication_handoff_policy_digest: [u8; 32],
    /// Identity-pinned durable panel-notification handle.
    pub panel_notification_handle: String,
    /// Exact non-zero panel-notification adapter revision.
    pub panel_notification_revision: u64,
    /// Exact panel-notification adapter public-policy digest.
    pub panel_notification_policy_digest: [u8; 32],
    /// Identity-pinned immutable panel-notification receipt archive handle.
    pub panel_notification_archive_handle: String,
    /// Exact non-zero receipt archive adapter revision.
    pub panel_notification_archive_revision: u64,
    /// Exact receipt archive adapter public-policy digest.
    pub panel_notification_archive_policy_digest: [u8; 32],
    /// Stable non-secret receipt archive namespace identity.
    pub panel_notification_archive_id: [u8; 32],
    /// Bootstrap Ed25519 archive signer anchoring the sealed epoch log.
    pub panel_notification_archive_bootstrap_public_key: [u8; 32],
    /// Exact Ed25519 public key authenticating durable archive readback.
    pub panel_notification_archive_public_key: [u8; 32],
    /// Inclusive final generation authorized for the predecessor archive signer.
    pub panel_notification_archive_predecessor_revocation_generation: Option<u64>,
    /// Prior-signer authorization signature for the current transition.
    pub panel_notification_archive_predecessor_authorization_signature: Option<[u8; 64]>,
    /// New-signer proof-of-possession signature for the current transition.
    pub panel_notification_archive_new_key_possession_signature: Option<[u8; 64]>,
    /// Maximum appeals and activated cases in one complete finalized snapshot.
    pub max_cases: usize,
    /// Maximum finalized typed events retained in one snapshot.
    pub max_events: usize,
    /// Maximum pending native transactions.
    pub max_outbox_entries: usize,
    /// Maximum stable operation identities and terminal dead letters.
    pub max_idempotency_records: usize,
    /// Independent retention ceiling for downstream handoffs and panel notifications.
    pub max_handoffs: usize,
    /// Safe attempts under one unchanged operation identity.
    pub max_submit_attempts: u32,
    /// Maximum canonical checkpoint size.
    pub checkpoint_max_bytes: Bytes,
    /// Maximum canonical panel-notification archive artifact size.
    pub panel_notification_archive_max_bytes: Bytes,
    /// Finalized reconciliation and maintenance cadence.
    pub worker_interval: Duration,
    /// Maximum native maintenance actions emitted in one scan.
    pub maintenance_batch_limit: usize,
}
/// Non-secret production policy for the SFM-4b3 evidence viewer.
#[derive(Debug, Clone)]
pub struct SorafsEvidenceViewer {
    /// Private canonical checkpoint path.
    pub checkpoint_path: PathBuf,
    /// Maximum canonical checkpoint size.
    pub checkpoint_max_bytes: Bytes,
    /// Identity-pinned authoritative checkpoint-store runtime handle.
    pub checkpoint_store_handle: String,
    /// Exact non-zero checkpoint-store adapter and public-policy revision.
    pub checkpoint_store_revision: u64,
    /// Exact checkpoint-store adapter public-policy digest.
    pub checkpoint_store_policy_digest: [u8; 32],
    /// Maximum session lifetime.
    pub session_ttl: Duration,
    /// Rotating grant lifetime.
    pub grant_ttl: Duration,
    /// WebAuthn challenge lifetime.
    pub challenge_ttl: Duration,
    /// Maximum authenticated plaintext range.
    pub max_range_bytes: Bytes,
    /// Maximum retained challenges.
    pub max_challenges: usize,
    /// Maximum retained sessions.
    pub max_sessions: usize,
    /// Maximum retained signed receipts.
    pub max_receipts: usize,
    /// Maximum retained idempotency tombstones.
    pub max_idempotency_records: usize,
    /// Retention interval after the last session expires.
    pub retention_after_expiry: Duration,
    /// WebAuthn relying-party identifier.
    pub webauthn_rp_id: String,
    /// Exact HTTPS origins accepted by WebAuthn.
    pub webauthn_allowed_origins: Vec<String>,
    /// Identity-pinned WebAuthn runtime handle.
    pub webauthn_handle: String,
    /// Exact non-zero WebAuthn adapter and public-policy revision.
    pub webauthn_revision: u64,
    /// Exact WebAuthn adapter public-policy digest.
    pub webauthn_policy_digest: [u8; 32],
    /// Identity-pinned rotating-grant runtime handle.
    pub grant_handle: String,
    /// Exact non-zero rotating-grant adapter and public-policy revision.
    pub grant_revision: u64,
    /// Exact rotating-grant adapter public-policy digest.
    pub grant_policy_digest: [u8; 32],
    /// Identity-pinned irreversible-erasure runtime handle.
    pub erasure_handle: String,
    /// Exact non-zero irreversible-erasure adapter and public-policy revision.
    pub erasure_revision: u64,
    /// Exact irreversible-erasure adapter public-policy digest.
    pub erasure_policy_digest: [u8; 32],
    /// Identity-pinned immutable compaction-archive runtime handle.
    pub compaction_archive_handle: String,
    /// Stable non-secret immutable archive namespace.
    pub compaction_archive_id: [u8; 32],
    /// Exact non-zero compaction-archive adapter and public-policy revision.
    pub compaction_archive_revision: u64,
    /// Exact compaction-archive adapter public-policy digest.
    pub compaction_archive_policy_digest: [u8; 32],
    /// Exact Ed25519 archive receipt-verification key.
    pub compaction_archive_public_key: [u8; 32],
    /// Supervised immutable-archive compaction cadence.
    pub compaction_interval: Duration,
    /// Maximum expired records archived by one supervised tick.
    pub compaction_max_records: u32,
    /// Identity-pinned Ed25519 receipt signer handle.
    pub receipt_signer_handle: String,
    /// Exact non-zero receipt-signer adapter and public-policy revision.
    pub receipt_signer_revision: u64,
    /// Exact receipt-signer adapter public-policy digest.
    pub receipt_signer_policy_digest: [u8; 32],
    /// Exact receipt-verification key.
    pub receipt_signer_public_key: [u8; 32],
    /// Identity-pinned external transparency-publisher runtime handle.
    pub transparency_publisher_handle: String,
    /// Exact non-zero transparency-publisher adapter and public-policy revision.
    pub transparency_publisher_revision: u64,
    /// Exact transparency-publisher adapter public-policy digest.
    pub transparency_publisher_policy_digest: [u8; 32],
    /// Exact Ed25519 transparency-head verification key.
    pub transparency_publisher_public_key: [u8; 32],
}
/// Non-secret production policy for the supervised SoraFS hedging/billing runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsHedgingBillingRuntime {
    /// Private directory containing the canonical projector checkpoint.
    pub state_dir: PathBuf,
    /// Absolute path to the canonical public deterministic service policy.
    pub service_policy_path: PathBuf,
    /// Reviewed digest returned by the canonical service policy.
    pub service_policy_digest: [u8; 32],
    /// Identity-pinned finalized billing query provider handle.
    pub finalized_query_handle: String,
    /// Exact non-zero finalized-query provider revision.
    pub finalized_query_revision: u64,
    /// Exact non-zero digest of the finalized-query provider's public policy.
    pub finalized_query_policy_digest: [u8; 32],
    /// Identity-pinned consensus journal verifier handle.
    pub journal_verifier_handle: String,
    /// Exact non-zero journal-verifier provider revision.
    pub journal_verifier_revision: u64,
    /// Exact non-zero digest of the journal-verifier provider's public policy.
    pub journal_verifier_policy_digest: [u8; 32],
    /// Identity-pinned authenticated external statement signer handle.
    pub statement_signer_handle: String,
    /// Exact non-zero statement-signer provider revision.
    pub statement_signer_revision: u64,
    /// Exact non-zero digest of the statement-signer provider's public policy.
    pub statement_signer_policy_digest: [u8; 32],
    /// Identity-pinned immutable statement publisher handle.
    pub statement_publisher_handle: String,
    /// Exact non-zero statement-publisher provider revision.
    pub statement_publisher_revision: u64,
    /// Exact non-zero digest of the statement-publisher provider's public policy.
    pub statement_publisher_policy_digest: [u8; 32],
    /// Identity-pinned acknowledgement authority handle.
    pub acknowledgement_authority_handle: String,
    /// Exact non-zero acknowledgement-authority provider revision.
    pub acknowledgement_authority_revision: u64,
    /// Exact non-zero digest of the acknowledgement authority's public policy.
    pub acknowledgement_authority_policy_digest: [u8; 32],
    /// Identity-pinned sealed monotonic epoch-witness store handle.
    pub epoch_witness_store_handle: String,
    /// Exact non-zero epoch-witness-store provider revision.
    pub epoch_witness_store_revision: u64,
    /// Exact non-zero digest of the epoch-witness store's public policy.
    pub epoch_witness_store_policy_digest: [u8; 32],
    /// Finalized reconciliation and delivery cadence.
    pub poll_interval: Duration,
    /// Maximum finalized journal pages consumed in one worker tick.
    pub max_pages_per_tick: u32,
    /// Maximum finalized period closes consumed in one worker tick.
    pub max_period_closes_per_tick: u32,
    /// Maximum signer/publication/reconciliation operations in one tick.
    pub max_delivery_operations_per_tick: u32,
    /// Maximum admitted finalized-head lag before readiness fails closed.
    pub max_finalized_lag_blocks: u64,
}
/// Durable completion-outbox policy for supervised SoraFS provider ingest.
#[derive(Debug, Clone, Copy)]
pub struct SorafsProviderIngestOutbox {
    /// Maximum non-terminal ingest jobs. Active work is never pruned.
    pub max_active_entries: usize,
    /// Maximum terminal tombstones retained for replay safety.
    pub max_terminal_entries: usize,
    /// Maximum failures or completion-delivery attempts.
    pub max_attempts: u32,
    /// Maximum canonical checkpoint size.
    pub checkpoint_max_bytes: Bytes,
    /// Deadline for one external sealed-checkpoint operation, in milliseconds.
    pub checkpoint_operation_timeout_ms: u64,
    /// Source-claim lease duration in milliseconds.
    pub source_lease_ttl_ms: u64,
    /// Initial retry delay in milliseconds.
    pub retry_base_delay_ms: u64,
    /// Maximum retry delay in milliseconds.
    pub retry_max_delay_ms: u64,
    /// Maximum finalized-block age of a terminal tombstone.
    pub terminal_retention_blocks: u64,
    /// Maximum canonical size of one signed completion transaction; this must
    /// meet the production floor and leave room for two retained canonical copies.
    pub max_signed_transaction_bytes: Bytes,
    /// Maximum payload-free rows returned by one status page.
    pub max_status_page_size: usize,
}
/// Public qualification binding for one provider-attestation runtime effect.
///
/// The handle is an opaque deployment identity, not an endpoint or credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsProviderAttestationRuntimeBinding {
    /// Stable credential-free production provider handle.
    pub handle: String,
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Bounded activation policy for the Musubi provider-attestation journal.
///
/// The native completion-credential selection binds fixed native clock, approval and inventory
/// owners. Its clock protects process crashes only, not offline restoration. External selected
/// bindings retain independent qualification and cannot substitute for native custody.
/// Services remain disabled unless this complete policy is explicitly selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsProviderAttestationJournal {
    /// Qualified clock: native crash-durable UTC or an independently authenticated external seal.
    pub clock: SorafsProviderAttestationRuntimeBinding,
    /// Qualified approval-only signer, using the dedicated completion identity.
    pub approval_signer: SorafsProviderAttestationRuntimeBinding,
    /// Qualified authenticated coordinator-inventory provider.
    pub inventory: SorafsProviderAttestationRuntimeBinding,
    /// Maximum retained active and terminal entries, independently of the
    /// checkpoint byte cap.
    pub max_entries: usize,
    /// Maximum approval or inventory-handoff attempts per stage.
    pub max_attempts: u32,
    /// Lease duration for approval and inventory-handoff claims.
    pub lease_ttl_ms: u64,
    /// Maximum external approval-signer operation duration.
    pub approval_timeout_ms: u64,
    /// Maximum external coordinator-inventory operation duration.
    pub handoff_timeout_ms: u64,
    /// Delay before retrying a transient stage failure.
    pub retry_delay_ms: u64,
    /// Maximum canonical checkpoint size, independently of the entry cap and
    /// including the minimum reserve for one active intent's worst-case future
    /// attestation state.
    pub checkpoint_max_bytes: usize,
    /// Maximum CAS conflicts retried by one journal operation.
    pub max_cas_retries: u32,
}
/// Public binding for the external finalized-archive retention authority.
#[derive(Debug, Clone)]
pub struct SorafsProviderIngestFinalizedArchiveRetentionAuthority {
    /// Identity-pinned credential-free sealed-CAS provider handle.
    pub handle: String,
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the authority's public policy.
    pub policy_digest: [u8; 32],
}
/// Non-secret bounds for the daemon-owned finalized provider-ingest archive.
#[derive(Debug, Clone)]
pub struct SorafsProviderIngestFinalizedArchive {
    /// Normalized relative namespace resolved below the daemon's Kura root.
    pub relative_root: PathBuf,
    /// Maximum canonical bytes admitted for one immutable anchor record.
    pub max_record_bytes: u64,
    /// Maximum immutable anchor records admitted by one archive namespace.
    pub max_archive_entries: usize,
    /// Maximum aggregate canonical bytes admitted by one archive namespace.
    pub max_total_bytes: u64,
    /// Maximum provider projections admitted at one finalized anchor.
    pub max_providers_per_anchor: usize,
    /// Maximum assigned orders admitted for one provider at one anchor.
    pub max_orders_per_provider: usize,
    /// Maximum aggregate provider/order rows admitted at one finalized anchor.
    pub max_total_orders_per_anchor: usize,
    /// Maximum rows returned by one provider-indexed archive page.
    pub max_page_rows: usize,
    /// Maximum authenticated lag between the Kura and archive tips.
    pub max_kura_tip_lag_blocks: u64,
    /// External authority required before any retention checkpoint is installed.
    pub retention_authority: Option<SorafsProviderIngestFinalizedArchiveRetentionAuthority>,
}
/// Non-secret production policy for supervised SoraFS provider ingest.
///
/// The opaque handles identify qualified providers. An owner-only credential path explicitly
/// selects native software custody; secret bytes and fetched payloads stay outside configuration.
#[derive(Debug, Clone)]
pub struct SorafsProviderIngestRuntime {
    /// Explicit admitted provider id to HTTPS origin mapping for native assignment source reads.
    /// Explicit numeric loopback HTTP origins are allowed for local networks.
    pub native_source_origins: BTreeMap<String, String>,
    /// Owner-only canonical completion credential selecting the built-in software producer.
    /// None selects explicitly injected external provider adapters.
    pub native_completion_credential: Option<PathBuf>,
    /// Identity-pinned authenticated source-fetch provider handle.
    pub authenticated_source_fetch_handle: String,
    /// Exact non-zero authenticated source-pool adapter/public-policy revision.
    pub authenticated_source_fetch_revision: u64,
    /// Exact non-zero digest of the authenticated source-pool public policy.
    pub authenticated_source_fetch_policy_digest: [u8; 32],
    /// Identity-pinned governed completion-signer resolver handle.
    pub completion_signer_resolver_handle: String,
    /// Exact non-zero governed signer-resolver adapter/public-policy revision.
    pub completion_signer_resolver_revision: u64,
    /// Exact non-zero digest of the governed signer-resolver public policy.
    pub completion_signer_resolver_policy_digest: [u8; 32],
    /// Stable authenticated external completion-signer handle.
    pub completion_signer_handle: String,
    /// Exact non-zero completion-signer adapter and public-policy revision.
    pub completion_signer_adapter_revision: u64,
    /// Exact chain-authoritative completion-signer policy identity and digest lineage.
    pub completion_signer_policy: ProviderIngestCompletionSignerPolicyV1,
    /// Exact admitted completion-signature algorithm.
    pub completion_signer_algorithm: Algorithm,
    /// Exact public key controlled by the external completion signer.
    pub completion_signer_public_key: PublicKey,
    /// Identity-pinned sealed monotonic checkpoint-store handle.
    pub checkpoint_store_handle: String,
    /// Exact non-zero checkpoint-store adapter and public-policy revision.
    pub checkpoint_store_revision: u64,
    /// Exact non-zero digest of the checkpoint store's public policy.
    pub checkpoint_store_policy_digest: [u8; 32],
    /// Delay between finalized assignment scans, in milliseconds.
    pub scan_interval_ms: u64,
    /// Maximum finalized assignment rows requested in one page.
    pub max_page_rows: usize,
    /// Maximum finalized pages reconciled in one tick.
    pub max_pages_per_tick: usize,
    /// Maximum source jobs performed in one tick.
    pub max_source_jobs_per_tick: usize,
    /// Maximum governed source providers passed to one authenticated fetch.
    pub max_source_providers: usize,
    /// Timeout for authenticated source fetch, verification, and storage.
    pub source_operation_timeout_ms: u64,
    /// Durable source-lease renewal cadence.
    pub source_lease_renew_interval_ms: u64,
    /// Timeout for completion payload construction and external signing.
    pub signer_timeout_ms: u64,
    /// Timeout for transaction preflight, submission, and observation.
    pub ingress_timeout_ms: u64,
    /// Time-to-live assigned to one completion transaction.
    pub completion_transaction_ttl_ms: u64,
    /// Daemon-owned immutable finalized-assignment archive policy.
    pub finalized_archive: SorafsProviderIngestFinalizedArchive,
    /// Durable payload-free completion-outbox policy.
    pub outbox: SorafsProviderIngestOutbox,
    /// Optional native completed-bundle attestation journal. Activation requires exact
    /// native credential bindings and explicitly initialized retained custody.
    pub provider_attestation_journal: Option<SorafsProviderAttestationJournal>,
}
/// Operational policy for the durable native orderbook transaction worker.
#[derive(Debug, Clone, Copy)]
pub struct SorafsOrderbookWorker {
    /// Whether generation of new supervised orderbook work is enabled.
    ///
    /// Enabling provider storage independently keeps durable drain and
    /// finalized reconciliation active.
    pub enabled: bool,
    /// Finalized-state scan cadence.
    pub scan_interval: Duration,
    /// Maximum fills requested by one native match transaction.
    pub match_batch_limit: u32,
    /// Maximum expiries/closures requested by one native maintenance transaction.
    pub maintenance_batch_limit: u32,
    /// Maximum pending semantic operations retained durably.
    pub max_pending: u32,
    /// Maximum finalized idempotency tombstones retained durably.
    pub max_completed: u32,
    /// Maximum terminal dead letters retained durably.
    pub max_dead_letters: u32,
    /// Maximum signing/submission attempts under one semantic identity.
    pub max_attempts: u32,
    /// Maximum canonical durable checkpoint size.
    pub checkpoint_max_bytes: Bytes,
}
/// Operational policy for the durable native reserve/rent transaction worker.
#[derive(Debug, Clone, Copy)]
pub struct SorafsReserveWorker {
    /// Whether generation of new supervised reserve/rent work is enabled.
    ///
    /// Enabling provider storage independently keeps durable drain and
    /// finalized reconciliation active.
    pub enabled: bool,
    /// Finalized-state scan cadence.
    pub scan_interval: Duration,
    /// Maximum durable operations inspected in one fair scan.
    pub scan_batch_limit: u32,
    /// Maximum pending semantic operations retained durably.
    pub max_pending: u32,
    /// Maximum finalized idempotency tombstones retained durably.
    pub max_completed: u32,
    /// Maximum terminal dead letters retained durably.
    pub max_dead_letters: u32,
    /// Maximum signing/submission attempts under one semantic identity.
    pub max_attempts: u32,
    /// Maximum canonical durable checkpoint size.
    pub checkpoint_max_bytes: Bytes,
}
/// Local SFM-4c privacy aggregate publication scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPrivacyAggregatePopulation {
    /// Stable public population label.
    pub label: String,
    /// Governed selector digest.
    pub digest: [u8; 32],
}
/// One fixed metric coordinate in the governed privacy query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPrivacyAggregateMetric {
    /// Stable metric key.
    pub key: String,
    /// Stable public unit.
    pub unit: String,
}
/// Exact non-secret identity and public policy of one transparency runtime provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsTransparencyRuntimeProviderBinding {
    /// Stable opaque deployment-owned provider handle.
    pub handle: String,
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
/// Local SFM-4c privacy aggregate publication scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPrivacyAggregateSchedule {
    /// Whether config-backed due-cycle publication is enabled.
    pub enabled: bool,
    /// Width of each privacy aggregate cycle, in seconds.
    pub cycle_seconds: u64,
    /// Governed inclusive start of the first releasable cycle.
    pub first_cycle_start_unix: u64,
    /// Delay after a cycle closes before publication, in seconds.
    pub publish_delay_seconds: u64,
    /// Public aggregate identifier prefix.
    pub aggregate_id_prefix: String,
    /// Stable governed query identity, unchanged across policy rotations.
    pub query_id: Option<[u8; 32]>,
    /// Fixed, sorted public population universe.
    pub population_inventory: Vec<SorafsPrivacyAggregatePopulation>,
    /// Fixed, sorted public metric schema.
    pub metric_schema: Vec<SorafsPrivacyAggregateMetric>,
    /// Governed privacy mode.
    pub privacy_mode: String,
    /// Reduced governed epsilon numerator.
    pub epsilon_numerator: u64,
    /// Reduced governed epsilon denominator.
    pub epsilon_denominator: u64,
    /// Maximum contribution from one private subject to one metric.
    pub per_subject_metric_cap: u64,
    /// Minimum distinct-subject count required for publication.
    pub suppression_threshold: u64,
    /// Reviewed governed privacy-policy digest.
    pub policy_digest: Option<[u8; 32]>,
    /// Exact production threshold-PRF provider binding for DP modes.
    pub cycle_prf_provider: Option<SorafsTransparencyRuntimeProviderBinding>,
    /// Exact production finalized release-anchor binding.
    pub release_anchor_provider: Option<SorafsTransparencyRuntimeProviderBinding>,
    /// Exact production external leader-lease binding.
    pub leader_lease_provider: Option<SorafsTransparencyRuntimeProviderBinding>,
    /// Exact production fused privacy Governance publisher binding.
    ///
    /// The stable handle is the provider identity exposed by the V1 runtime
    /// boundary. The runtime provider owns all credentials and private state.
    pub fenced_privacy_publisher: Option<SorafsTransparencyRuntimeProviderBinding>,
    /// Reduced composed-epsilon budget numerator.
    pub composition_budget_epsilon_numerator: u64,
    /// Reduced composed-epsilon budget denominator.
    pub composition_budget_epsilon_denominator: u64,
    /// Maximum publications retained under this composition-budget policy.
    pub composition_budget_max_publications: u64,
}
/// Local SFM-4b3 evidence-viewer audit-report publication scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SorafsEvidenceViewerAuditSchedule {
    /// Whether config-backed due-cycle publication is enabled.
    pub enabled: bool,
    /// Width of each evidence-viewer audit-report cycle, in seconds.
    pub cycle_seconds: u64,
    /// Delay after a cycle closes before publication, in seconds.
    pub publish_delay_seconds: u64,
}
impl_default!(SorafsStorage => {
        Self {
            enabled: defaults::sorafs::storage::ENABLED,
            provider_id: None,
            data_dir: defaults::sorafs::storage::data_dir(),
            max_capacity_bytes: defaults::sorafs::storage::MAX_CAPACITY_BYTES,
            max_parallel_fetches: defaults::sorafs::storage::MAX_PARALLEL_FETCHES,
            max_pins: defaults::sorafs::storage::MAX_PINS,
            signer_journal_inventory: SorafsSignerJournalInventory::default(),
            por_sample_interval_secs: defaults::sorafs::storage::POR_SAMPLE_INTERVAL_SECS,
            pdp_sample_window: defaults::sorafs::storage::PDP_SAMPLE_WINDOW,
            pdp_tree_memory_limit_bytes: defaults::sorafs::storage::PDP_TREE_MEMORY_LIMIT_BYTES,
            moderation_screening_enabled: defaults::sorafs::storage::MODERATION_SCREENING_ENABLED,
            moderation_screening_authority_bundle_path: None,
            moderation_screening_authority_bundle_digest: None,
            moderation_quarantine_key_provider: None,
            pop_credentials: None,
            moderation_orchestrator: None,
            evidence_viewer: None,
            reputation_runtime: None,
            reserve_transparency_runtime: None,
            por_replay_archive: None,
            hedging_billing_runtime: None,
            provider_ingest_runtime: None,
            pdp_provider: SorafsPdpProviderPolicy::default(),
            runtime: SorafsRuntimeRetention::default(),
            alias: defaults::sorafs::storage::alias(),
            adverts: SorafsAdvertOverrides::default(),
            metering_smoothing: SorafsMeteringSmoothing::default(),
            stream_tokens: SorafsTokenConfig::default(),
            native_transaction_signers: SorafsNativeTransactionSignerBindings::default(),
            orderbook_worker: SorafsOrderbookWorker::default(),
            reserve_worker: SorafsReserveWorker::default(),
            reputation_trust_policy_path: None,
            hedging_feed_trust_policy_path: None,
            privacy_aggregates: SorafsPrivacyAggregateSchedule::default(),
            evidence_viewer_audits: SorafsEvidenceViewerAuditSchedule::default(),
            governance_dag_dir: defaults::sorafs::storage::governance_dir(),
            governance_dag_publisher_peer_id:
                defaults::sorafs::storage::governance_publisher_peer_id(),
            governance_dag_signer_handle: None,
            governance_dag_signer_revision: None,
            governance_dag_signer_policy_digest: None,
            governance_dag_publisher_public_key_hex: None,
            governance_dag_service: SorafsGovernanceDagService::default(),
        }
});
impl_default!(SorafsGovernanceDagService => {
        use defaults::sorafs::storage::governance_dag_service as service;
        Self {
            enabled: service::ENABLED,
            state_dir: service::state_dir(),
            ipfs_api_url: None,
            head_mode: service::HEAD_MODE.to_owned(),
            signed_head_url: None,
            ipns_name: None,
            ipns_key_name: None,
            ipfs_authenticator_handle: None,
            ipfs_authenticator_revision: None,
            ipfs_authenticator_policy_digest: None,
            ipfs_request_auth_public_key: None,
            head_authenticator_handle: None,
            head_authenticator_revision: None,
            head_authenticator_policy_digest: None,
            head_request_auth_public_key: None,
            request_auth_max_envelope_lifetime_secs:
                service::REQUEST_AUTH_MAX_ENVELOPE_LIFETIME_SECS,
            request_auth_max_future_skew_secs: service::REQUEST_AUTH_MAX_FUTURE_SKEW_SECS,
            checkpoint_store_handle: None,
            checkpoint_store_revision: None,
            checkpoint_store_policy_digest: None,
            publisher_public_key_hex: None,
            poll_interval: Duration::from_secs(service::POLL_INTERVAL_SECS),
            connect_timeout: Duration::from_millis(service::CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(service::REQUEST_TIMEOUT_MS),
            dns_timeout: Duration::from_millis(service::DNS_TIMEOUT_MS),
            max_response_bytes: service::MAX_RESPONSE_BYTES,
            max_request_bytes: service::MAX_REQUEST_BYTES,
            max_future_skew_secs: service::MAX_FUTURE_SKEW_SECS,
            allow_insecure_http: service::ALLOW_INSECURE_HTTP,
            allow_private_ipfs_endpoint: service::ALLOW_PRIVATE_IPFS_ENDPOINT,
            allow_private_head_endpoint: service::ALLOW_PRIVATE_HEAD_ENDPOINT,
            allow_head_bootstrap: service::ALLOW_HEAD_BOOTSTRAP,
            listen_addr: service::LISTEN_ADDR.to_owned(),
        }
});
impl_default!(SorafsRuntimeRetention => {
        Self {
            event_history_limit: defaults::sorafs::storage::RUNTIME_EVENT_HISTORY_LIMIT,
            state_entry_limit: defaults::sorafs::storage::RUNTIME_STATE_ENTRY_LIMIT,
            checkpoint_max_bytes: defaults::sorafs::storage::RUNTIME_CHECKPOINT_MAX_BYTES,
            proof_outcome_forwarder_interval: Duration::from_millis(
                defaults::sorafs::storage::RUNTIME_PROOF_OUTCOME_FORWARDER_INTERVAL_MS.get(),
            ),
            proof_outcome_max_attempts:
                defaults::sorafs::storage::RUNTIME_PROOF_OUTCOME_MAX_ATTEMPTS.get(),
        }
});
impl_default!(SorafsPdpProviderPolicy => {
        use defaults::sorafs::storage::pdp_provider as pdp;
        Self {
            max_pending_records: pdp::MAX_PENDING_RECORDS,
            max_terminal_records: pdp::MAX_TERMINAL_RECORDS,
            checkpoint_max_bytes: pdp::CHECKPOINT_MAX_BYTES,
            challenge_max_bytes: pdp::CHALLENGE_MAX_BYTES,
            proof_max_bytes: pdp::PROOF_MAX_BYTES,
            min_response_window_secs: pdp::MIN_RESPONSE_WINDOW_SECS,
            max_response_window_secs: pdp::MAX_RESPONSE_WINDOW_SECS,
            max_future_skew_secs: pdp::MAX_FUTURE_SKEW_SECS,
            terminal_retention_secs: pdp::TERMINAL_RETENTION_SECS,
        }
});
impl_default!(SorafsOrderbookWorker => {
        use defaults::sorafs::storage::orderbook_worker as worker;
        Self {
            enabled: worker::ENABLED,
            scan_interval: Duration::from_millis(worker::SCAN_INTERVAL_MS.get()),
            match_batch_limit: worker::MATCH_BATCH_LIMIT.get(),
            maintenance_batch_limit: worker::MAINTENANCE_BATCH_LIMIT.get(),
            max_pending: worker::MAX_PENDING.get(),
            max_completed: worker::MAX_COMPLETED.get(),
            max_dead_letters: worker::MAX_DEAD_LETTERS.get(),
            max_attempts: worker::MAX_ATTEMPTS.get(),
            checkpoint_max_bytes: worker::CHECKPOINT_MAX_BYTES,
        }
});
impl_default!(SorafsReserveWorker => {
        use defaults::sorafs::storage::reserve_worker as worker;
        Self {
            enabled: worker::ENABLED,
            scan_interval: Duration::from_millis(worker::SCAN_INTERVAL_MS.get()),
            scan_batch_limit: worker::SCAN_BATCH_LIMIT.get(),
            max_pending: worker::MAX_PENDING.get(),
            max_completed: worker::MAX_COMPLETED.get(),
            max_dead_letters: worker::MAX_DEAD_LETTERS.get(),
            max_attempts: worker::MAX_ATTEMPTS.get(),
            checkpoint_max_bytes: worker::CHECKPOINT_MAX_BYTES,
        }
});
impl_default!(SorafsPrivacyAggregateSchedule => {
        Self {
            enabled: defaults::sorafs::storage::privacy_aggregates::ENABLED,
            cycle_seconds: defaults::sorafs::storage::privacy_aggregates::CYCLE_SECONDS,
            first_cycle_start_unix:
                defaults::sorafs::storage::privacy_aggregates::FIRST_CYCLE_START_UNIX,
            publish_delay_seconds:
                defaults::sorafs::storage::privacy_aggregates::PUBLISH_DELAY_SECONDS,
            aggregate_id_prefix:
                defaults::sorafs::storage::privacy_aggregates::AGGREGATE_ID_PREFIX.to_string(),
            query_id: None,
            population_inventory: Vec::new(),
            metric_schema: Vec::new(),
            privacy_mode:
                defaults::sorafs::storage::privacy_aggregates::PRIVACY_MODE.to_string(),
            epsilon_numerator:
                defaults::sorafs::storage::privacy_aggregates::EPSILON_NUMERATOR,
            epsilon_denominator:
                defaults::sorafs::storage::privacy_aggregates::EPSILON_DENOMINATOR,
            per_subject_metric_cap:
                defaults::sorafs::storage::privacy_aggregates::PER_SUBJECT_METRIC_CAP,
            suppression_threshold:
                defaults::sorafs::storage::privacy_aggregates::SUPPRESSION_THRESHOLD,
            policy_digest: None,
            cycle_prf_provider: None,
            release_anchor_provider: None,
            leader_lease_provider: None,
            fenced_privacy_publisher: None,
            composition_budget_epsilon_numerator:
                defaults::sorafs::storage::privacy_aggregates::COMPOSITION_BUDGET_EPSILON_NUMERATOR,
            composition_budget_epsilon_denominator:
                defaults::sorafs::storage::privacy_aggregates::COMPOSITION_BUDGET_EPSILON_DENOMINATOR,
            composition_budget_max_publications:
                defaults::sorafs::storage::privacy_aggregates::COMPOSITION_BUDGET_MAX_PUBLICATIONS,
        }
});
impl_default!(SorafsEvidenceViewerAuditSchedule => {
        Self {
            enabled: defaults::sorafs::storage::evidence_viewer_audits::ENABLED,
            cycle_seconds: defaults::sorafs::storage::evidence_viewer_audits::CYCLE_SECONDS,
            publish_delay_seconds:
                defaults::sorafs::storage::evidence_viewer_audits::PUBLISH_DELAY_SECONDS,
        }
});
/// Under-delivery penalty policy enforced for SoraFS providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SorafsPenaltyPolicy {
    /// Minimum utilisation ratio (basis points) required before a strike is counted.
    pub utilisation_floor_bps: u16,
    /// Minimum uptime success rate (basis points) required before a strike is counted.
    pub uptime_floor_bps: u16,
    /// Minimum Proof-of-Retrievability success rate (basis points) required before a strike.
    pub por_success_floor_bps: u16,
    /// Number of consecutive strikes required before applying a penalty.
    pub strike_threshold: u32,
    /// Fraction of bonded collateral removed when a penalty triggers (basis points).
    pub penalty_bond_bps: u16,
    /// Cooldown window count (settlement windows) enforced between penalties.
    pub cooldown_windows: u32,
    /// Maximum PDP failures tolerated within a telemetry window before forcing a strike (0 = none).
    pub max_pdp_failures: u32,
    /// Maximum PoTR SLA breaches tolerated within a telemetry window before forcing a strike (0 = none).
    pub max_potr_breaches: u32,
}
impl SorafsPenaltyPolicy {
    /// Compute the cooldown interval in seconds based on the configured settlement window.
    #[must_use]
    pub fn cooldown_window_secs(&self, settlement_window_secs: u64) -> u64 {
        settlement_window_secs.saturating_mul(u64::from(self.cooldown_windows))
    }
}
impl_default!(SorafsPenaltyPolicy => {
        Self {
            utilisation_floor_bps: defaults::governance::sorafs_penalty::UTILISATION_FLOOR_BPS,
            uptime_floor_bps: defaults::governance::sorafs_penalty::UPTIME_FLOOR_BPS,
            por_success_floor_bps: defaults::governance::sorafs_penalty::POR_SUCCESS_FLOOR_BPS,
            strike_threshold: defaults::governance::sorafs_penalty::STRIKE_THRESHOLD,
            penalty_bond_bps: defaults::governance::sorafs_penalty::PENALTY_BOND_BPS,
            cooldown_windows: defaults::governance::sorafs_penalty::COOLDOWN_WINDOWS,
            max_pdp_failures: defaults::governance::sorafs_penalty::MAX_PDP_FAILURES,
            max_potr_breaches: defaults::governance::sorafs_penalty::MAX_POTR_BREACHES,
        }
});
/// Telemetry authentication and replay policy for SoraFS capacity windows.
#[derive(Debug, Clone)]
pub struct SorafsTelemetryPolicy {
    /// Require telemetry submissions to originate from a configured allow-list.
    pub require_submitter: bool,
    /// Require a replay nonce on each telemetry window.
    /// When disabled, windows without a nonce are accepted but provided nonces are still checked.
    pub require_nonce: bool,
    /// Maximum tolerated gap between consecutive telemetry windows.
    pub max_window_gap: Duration,
    /// Reject zero-capacity telemetry windows.
    pub reject_zero_capacity: bool,
    /// Accounts permitted to submit telemetry when `require_submitter` is true.
    pub submitters: Vec<AccountId>,
    /// Per-provider submitter overrides; when present, this list is enforced instead of the global list.
    pub per_provider_submitters: BTreeMap<ProviderId, Vec<AccountId>>,
}
impl_default!(SorafsTelemetryPolicy => {
        Self {
            require_submitter: defaults::governance::sorafs_telemetry::REQUIRE_SUBMITTER,
            require_nonce: defaults::governance::sorafs_telemetry::REQUIRE_NONCE,
            max_window_gap: Duration::from_secs(
                defaults::governance::sorafs_telemetry::MAX_WINDOW_GAP_SECS,
            ),
            reject_zero_capacity: defaults::governance::sorafs_telemetry::REJECT_ZERO_CAPACITY,
            submitters: defaults::governance::sorafs_telemetry::submitters()
                .iter()
                .map(|id| {
                    AccountId::parse_encoded(id)
                        .expect("default SoraFS telemetry submitter account id")
                })
                .collect(),
            per_provider_submitters: BTreeMap::new(),
        }
});
/// Optional smoothing parameters for metering outputs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SorafsMeteringSmoothing {
    /// Alpha applied to the GiB·hour exponential moving average.
    pub gib_hours_alpha: Option<f64>,
    /// Alpha applied to the PoR-success exponential moving average.
    pub por_success_alpha: Option<f64>,
}
mod stream_token_gateway;
pub use stream_token_gateway::SorafsStreamTokenGatewayNativeConfig;
mod stream_token_signer;
pub use stream_token_signer::{
    SorafsStreamTokenAttesterConfig, SorafsStreamTokenAuthorityConfig,
    SorafsStreamTokenNativeConfig, SorafsStreamTokenObserverConfig, SorafsStreamTokenSignerConfig,
};

/// Stream-token issuance configuration for chunk-range gateways.
#[derive(Debug, Clone)]
pub struct SorafsTokenConfig {
    /// Enable stream-token issuance.
    pub enabled: bool,
    /// Complete signer and independent attester/observer trust, absent when disabled.
    pub signer: Option<SorafsStreamTokenSignerConfig>,
    /// Explicit native gateway transaction custody, required when issuance is enabled.
    pub admission_native: Option<SorafsStreamTokenGatewayNativeConfig>,
    /// Credential-free handle pinned to the native consensus gateway owner.
    pub admission_provider_handle: Option<String>,
    /// Exact non-zero native admission policy revision.
    pub admission_provider_revision: Option<u64>,
    /// Exact non-zero commitment to the governed native admission policy.
    pub admission_provider_policy_digest: Option<[u8; 32]>,
    /// Durable callback row ceiling; also bounds local queued/reserved lease cleanup tickets.
    pub admission_max_pending: u32,
    /// Maximum active token quota windows admitted by native consensus.
    pub admission_max_tracked_tokens: u32,
    /// Maximum ordered callbacks replayed by one reconciliation tick.
    pub admission_reconcile_max_items: u32,
    /// Interval between supervised native callback reconciliation attempts.
    pub admission_reconcile_interval_ms: u64,
    /// Absolute budget shared by admission, callback reconciliation and final Serving proof.
    pub admission_operation_timeout_ms: u64,
    /// Maximum lifetime of one cross-replica concurrency lease.
    pub admission_lease_ttl_ms: u64,
    /// Default TTL applied to tokens (seconds).
    pub default_ttl_secs: u64,
    /// Default concurrent-stream budget encoded per token.
    pub default_max_streams: u16,
    /// Default sustained throughput per token (bytes per second).
    pub default_rate_limit_bytes: u64,
    /// Default refresh budget (requests per minute).
    pub default_requests_per_minute: u32,
}
impl_default!(SorafsTokenConfig => {
        Self {
            enabled: defaults::sorafs::storage::tokens::ENABLED,
            signer: None,
            admission_native: None,
            admission_provider_handle: None,
            admission_provider_revision: None,
            admission_provider_policy_digest: None,
            admission_max_pending: defaults::sorafs::storage::tokens::ADMISSION_MAX_PENDING,
            admission_max_tracked_tokens:
                defaults::sorafs::storage::tokens::ADMISSION_MAX_TRACKED_TOKENS,
            admission_reconcile_max_items:
                defaults::sorafs::storage::tokens::ADMISSION_RECONCILE_MAX_ITEMS,
            admission_reconcile_interval_ms:
                defaults::sorafs::storage::tokens::ADMISSION_RECONCILE_INTERVAL_MS,
            admission_operation_timeout_ms:
                defaults::sorafs::storage::tokens::ADMISSION_OPERATION_TIMEOUT_MS,
            admission_lease_ttl_ms: defaults::sorafs::storage::tokens::ADMISSION_LEASE_TTL_MS,
            default_ttl_secs: defaults::sorafs::storage::tokens::DEFAULT_TTL_SECS,
            default_max_streams: defaults::sorafs::storage::tokens::DEFAULT_MAX_STREAMS,
            default_rate_limit_bytes: defaults::sorafs::storage::tokens::DEFAULT_RATE_LIMIT_BYTES,
            default_requests_per_minute:
                defaults::sorafs::storage::tokens::DEFAULT_REQUESTS_PER_MINUTE,
        }
});
include!("actual_sorafs_gateway.rs");
/// Optional overrides for provider advert telemetry generated by the storage worker.
#[derive(Debug, Clone)]
pub struct SorafsAdvertOverrides {
    /// Optional governance stake pointer advertised alongside the provider ID.
    pub stake_pointer: Option<String>,
    /// Availability tier advertised in QoS hints.
    pub availability: String,
    /// Maximum retrieval latency (milliseconds) advertised in QoS hints.
    pub max_latency_ms: u32,
    /// Rendezvous topics broadcast for discovery.
    pub topics: Vec<String>,
}
impl_default!(SorafsAdvertOverrides => {
        Self {
            stake_pointer: None,
            availability: defaults::sorafs::storage::advert_availability(),
            max_latency_ms: defaults::sorafs::storage::ADVERT_MAX_LATENCY_MS,
            topics: defaults::sorafs::storage::advert_topics(),
        }
});
/// One governed Ed25519 signer authorized to approve SoraFS pin manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsPinApprovalSigner {
    /// Stable payload-free signer identifier.
    pub signer_id: String,
    /// Governed Ed25519 verifying key.
    pub public_key: PublicKey,
    /// First executing block height at which this key may approve manifests.
    pub valid_from_block_height: u64,
    /// First executing block height at which this key is revoked.
    pub revoked_at_block_height: Option<u64>,
}
impl SorafsPinApprovalSigner {
    /// Return whether this signer is authorized at `block_height`.
    #[must_use]
    pub fn is_active_at(&self, block_height: u64) -> bool {
        block_height >= self.valid_from_block_height
            && self
                .revoked_at_block_height
                .is_none_or(|revoked_at| block_height < revoked_at)
    }
}
/// Governance-defined constraints enforced on SoraFS pin policies.
#[derive(Debug, Clone)]
pub struct SorafsPinPolicyConstraints {
    /// Minimum number of replicas required for an approved manifest.
    pub min_replicas_floor: u16,
    /// Optional ceiling on requested replicas.
    pub max_replicas_ceiling: Option<u16>,
    /// Optional maximum retention epoch (inclusive).
    pub max_retention_epoch: Option<u64>,
    /// Allowed storage classes for replicas; `None` permits any class.
    pub allowed_storage_classes: Option<BTreeSet<SorafsStorageClass>>,
    /// Whether manifest validation requires council signatures.
    pub require_council_signatures: bool,
    /// Required number of distinct active trusted approval signatures.
    pub approval_quorum: u16,
    /// Canonically signer-id-ordered trusted Ed25519 approval roster.
    pub approval_signers: Vec<SorafsPinApprovalSigner>,
    /// Maximum number of retained pin-manifest records in consensus state.
    pub max_global_manifests: u64,
    /// Maximum aggregate content bytes represented by live pin manifests.
    pub max_global_bytes: u64,
    /// Maximum number of retained pin-manifest records submitted by one account.
    pub max_manifests_per_authority: u64,
    /// Maximum aggregate content bytes represented by one account's live pins.
    pub max_bytes_per_authority: u64,
    /// Maximum predecessor depth admitted for a manifest lineage.
    pub max_lineage_depth: u32,
    /// Maximum number of retained direct successors admitted for one manifest.
    pub max_successor_fanout: u32,
}
impl_default!(SorafsPinPolicyConstraints => {
        Self {
            min_replicas_floor: super::defaults::governance::sorafs_pin_policy::MIN_REPLICAS_FLOOR,
            max_replicas_ceiling:
                super::defaults::governance::sorafs_pin_policy::MAX_REPLICAS_CEILING,
            max_retention_epoch:
                super::defaults::governance::sorafs_pin_policy::MAX_RETENTION_EPOCH,
            allowed_storage_classes: None,
            require_council_signatures:
                super::defaults::governance::sorafs_pin_policy::REQUIRE_COUNCIL_SIGNATURES,
            approval_quorum: super::defaults::governance::sorafs_pin_policy::APPROVAL_QUORUM,
            approval_signers: Vec::new(),
            max_global_manifests:
                super::defaults::governance::sorafs_pin_policy::MAX_GLOBAL_MANIFESTS,
            max_global_bytes: super::defaults::governance::sorafs_pin_policy::MAX_GLOBAL_BYTES,
            max_manifests_per_authority:
                super::defaults::governance::sorafs_pin_policy::MAX_MANIFESTS_PER_AUTHORITY,
            max_bytes_per_authority:
                super::defaults::governance::sorafs_pin_policy::MAX_BYTES_PER_AUTHORITY,
            max_lineage_depth: super::defaults::governance::sorafs_pin_policy::MAX_LINEAGE_DEPTH,
            max_successor_fanout:
                super::defaults::governance::sorafs_pin_policy::MAX_SUCCESSOR_FANOUT,
        }
});
/// Exact first-release Connect relay strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectRelayStrategy {
    /// Re-broadcast Connect envelopes across the peer network.
    Broadcast,
    /// Keep Connect delivery inside the local Torii process.
    LocalOnly,
}
/// Iroha Connect configuration.
#[derive(Debug, Clone, Copy)]
pub struct Connect {
    /// Enable Iroha Connect WS + P2P relay.
    pub enabled: bool,
    /// Max concurrent WS sessions across roles.
    pub ws_max_sessions: usize,
    /// Max concurrent WS sessions per remote IP (0 disables the per-IP cap).
    pub ws_per_ip_max_sessions: usize,
    /// Per-IP WS handshake rate (requests per minute, 0 disables rate limiting).
    pub ws_rate_per_ip_per_min: u32,
    /// Session inactivity TTL.
    pub session_ttl: Duration,
    /// Maximum WS frame size accepted for Connect frames (bytes).
    pub frame_max_bytes: usize,
    /// Maximum buffered payload per session (bytes) for pending delivery.
    pub session_buffer_max_bytes: usize,
    /// Heartbeat ping interval.
    pub ping_interval: Duration,
    /// Number of consecutive missed pongs tolerated before disconnect.
    pub ping_miss_tolerance: u32,
    /// Minimum heartbeat interval enforced for browser transports.
    pub ping_min_interval: Duration,
    /// Dedupe cache TTL.
    pub dedupe_ttl: Duration,
    /// Dedupe cache capacity (entries).
    pub dedupe_cap: usize,
    /// Enable P2P re-broadcast relay.
    pub relay_enabled: bool,
    /// Exact relay strategy.
    pub relay_strategy: ConnectRelayStrategy,
    /// Hop TTL for Connect relay envelopes (0 disables cross-node rebroadcast).
    pub p2p_ttl_hops: u8,
}
/// ISO 20022 bridge configuration.
#[derive(Debug, Clone)]
pub struct IsoBridge {
    /// Enable ISO 20022 ingestion endpoints.
    pub enabled: bool,
    /// Maximum request body accepted by an ISO 20022 submission endpoint.
    pub max_body_bytes: Bytes,
    /// TTL for deduplication records (seconds).
    pub dedupe_ttl_secs: u64,
    /// Default rail/profile identifier used when requests do not select one.
    pub default_profile: String,
    /// Operator-defined profile overrides or additions.
    pub profiles: Vec<IsoBridgeProfile>,
    /// Directory where ISO bridge message state is persisted.
    /// Payment queue admission is refused when this is absent.
    pub store_dir: Option<PathBuf>,
    /// Age retention window for durable ISO records (seconds); zero disables age pruning.
    pub store_retention_secs: u64,
    /// Maximum durable ISO records to retain (non-zero and bounded by the V1 hard limit).
    pub store_max_records: u64,
    /// Optional external audit export directory for manifest/notary preimages.
    pub audit_export_dir: Option<PathBuf>,
    /// Optional global embedded XML signature policy override.
    pub embedded_signature_policy: Option<String>,
    /// Optional signer configuration when enabled.
    pub signer: Option<IsoBridgeSigner>,
    /// Mutually isolated institutions admitted to the ISO bridge.
    pub participants: Vec<IsoBridgeParticipant>,
    /// Operator request keys that may read every ISO record but may not mutate bridge state.
    pub audit_admin_keys: Vec<PublicKey>,
    /// Mapping of IBANs to on-ledger account identifiers.
    pub account_aliases: Vec<IsoAccountAlias>,
    /// Mapping of currency codes to asset definitions.
    pub currency_assets: Vec<IsoCurrencyAsset>,
    /// Reference-data ingestion and refresh settings.
    pub reference_data: IsoReferenceData,
}
/// One institution admitted to the ISO 20022 bridge.
#[derive(Debug, Clone)]
pub struct IsoBridgeParticipant {
    /// Stable, deployment-unique participant identifier.
    pub id: String,
    /// Operator request-signature keys owned by this participant.
    pub operator_keys: Vec<PublicKey>,
    /// BIC, LEI, or clearing-member identifiers owned by this participant.
    pub financial_identifiers: Vec<String>,
    /// Rail/profile identifiers this participant may use.
    pub allowed_profiles: Vec<String>,
    /// Bridge roles assigned to the participant (`originator` and/or `counterparty`).
    pub roles: Vec<String>,
}
/// Operator-defined ISO bridge rail profile.
#[derive(Debug, Clone)]
pub struct IsoBridgeProfile {
    /// Stable profile identifier.
    pub id: String,
    /// Rail family identifier.
    pub rail: String,
    /// Optional profile-level embedded XML signature policy.
    pub embedded_signature_policy: Option<String>,
    /// SHA-256 pins for accepted XMLDSig signer public-key bytes.
    pub signature_public_key_sha256_pins: Vec<String>,
    /// SHA-256 pins for accepted X.509 trust-anchor certificate DER bytes.
    pub x509_trust_anchor_sha256_pins: Vec<String>,
    /// Certificate-policy OIDs required on accepted X.509 signer certificates.
    pub x509_required_certificate_policy_oids: Vec<String>,
    /// Whether X.509 signer certificates must be covered by a fresh verified CRL.
    pub x509_require_crl_revocation_check: bool,
    /// Base64 DER CRLs accepted as rail-profile revocation material.
    pub x509_crl_der_base64: Vec<String>,
    /// Whether X.509 signer certificates must be covered by a fresh verified OCSP response.
    pub x509_require_ocsp_revocation_check: bool,
    /// Base64 DER OCSP responses accepted as rail-profile revocation material.
    pub x509_ocsp_response_der_base64: Vec<String>,
    /// SHA-256 pins of DER XMLDSig X.509 certificates denied by this profile.
    pub revoked_certificate_sha256: Vec<String>,
    /// Required reference datasets for this profile.
    pub required_reference_datasets: Vec<String>,
    /// Message profile entries owned by this rail profile.
    pub message_profiles: Vec<IsoMessageProfile>,
}
/// Message-specific ISO bridge profile configuration.
#[derive(Debug, Clone)]
pub struct IsoMessageProfile {
    /// Canonical message family such as `pacs.008`.
    pub message_type: String,
    /// Direction identifier (`inbound`, `outbound`, or `follow-up`).
    pub direction: String,
    /// Exact ISO message definition identifiers accepted by this entry.
    pub versions: Vec<String>,
    /// Accepted business service identifiers.
    pub business_services: Vec<String>,
    /// Whether a Business Application Header is required.
    pub require_app_header: bool,
    /// Whether BizSvc must be present.
    pub require_business_service: bool,
    /// Whether UETR must be present.
    pub require_uetr: bool,
    /// Structured address mode identifier.
    pub structured_address_mode: String,
    /// Maximum serialized supplementary-data bytes.
    pub supplementary_data_max_bytes: usize,
    /// Currency minor-unit overrides.
    pub amount_minor_units: Vec<IsoCurrencyMinorUnit>,
}
/// Currency minor-unit override for ISO amount validation.
#[derive(Debug, Clone)]
pub struct IsoCurrencyMinorUnit {
    /// ISO 4217 currency code.
    pub currency: String,
    /// Number of permitted fractional decimal places.
    pub minor_units: u8,
}
/// Signing configuration for ISO bridge transactions.
#[derive(Debug, Clone)]
pub struct IsoBridgeSigner {
    /// Account identifier used as the transaction authority.
    pub account_id: String,
    /// Private key used to sign generated transactions.
    pub private_key: PrivateKey,
}
/// Account alias mapping (IBAN -> AccountId).
#[derive(Debug, Clone)]
pub struct IsoAccountAlias {
    /// External IBAN representation.
    pub iban: String,
    /// Account identifier (canonical I105 literal).
    pub account_id: String,
}
/// Currency to asset definition mapping.
#[derive(Debug, Clone)]
pub struct IsoCurrencyAsset {
    /// ISO 4217 currency code (e.g., `USD`).
    pub currency: String,
    /// Asset definition selector (canonical Base58 or leased alias).
    pub asset_definition: String,
    /// Maximum settlement quantity accepted for one bridge message.
    pub max_amount: Quantity,
}
/// Reference data inputs (ISIN/CUSIP, BIC↔LEI, MIC, securities ledger maps).
#[derive(Debug, Clone)]
pub struct IsoReferenceData {
    /// Refresh cadence for reference snapshot ingestion.
    pub refresh_interval: Duration,
    /// Optional path to an ANNA/CUSIP crosswalk snapshot.
    pub isin_crosswalk_path: Option<PathBuf>,
    /// Optional path to a BIC↔LEI mapping snapshot.
    pub bic_lei_path: Option<PathBuf>,
    /// Optional path to a MIC directory snapshot.
    pub mic_directory_path: Option<PathBuf>,
    /// Optional path to a CSD venue to ledger-domain crosswalk snapshot.
    pub csd_venue_path: Option<PathBuf>,
    /// Optional path to a securities settlement-account crosswalk snapshot.
    pub securities_account_path: Option<PathBuf>,
    /// Optional path to a securities cash-leg crosswalk snapshot.
    pub cash_leg_path: Option<PathBuf>,
    /// Directory where loaded snapshots and provenance metadata should be cached.
    pub cache_dir: Option<PathBuf>,
}
impl_default!(IsoReferenceData => {
        Self {
            refresh_interval: Duration::from_secs(
                super::defaults::torii::ISO_BRIDGE_REFERENCE_REFRESH_SECS,
            ),
            isin_crosswalk_path: None,
            bic_lei_path: None,
            mic_directory_path: None,
            csd_venue_path: None,
            securities_account_path: None,
            cash_leg_path: None,
            cache_dir: None,
        }
});
/// Zero-knowledge proof configuration namespace.
#[derive(Debug, Clone)]
pub struct Zk {
    /// Optional local diagnostic trace checking; never proof authority.
    pub trace: DiagnosticTrace,
    /// Bounds for the diagnostic native polynomial-opening endpoint.
    pub ipa_commitment: IpaCommitment,
    /// Maximum proofs accepted by one host batch-verification syscall.
    pub max_verify_batch: u32,
    /// Native PIPA-R verification policy.
    pub pipa_r: PipaR,
    /// FASTPQ prover settings.
    pub fastpq: Fastpq,
    /// Native STARK/FRI verification settings.
    pub stark: Stark,
    /// SCCP proof-admission and deterministic verifier-work limits.
    pub sccp: Sccp,
    /// Cap on the number of recent ballot ciphertexts kept per election.
    pub ballot_history_cap: usize,
    /// Maximum accepted proof size for stateless pre-verification (bytes).
    pub preverify_max_bytes: usize,
    /// Soft byte-budget for stateless pre-verification (0 = unlimited).
    pub preverify_budget_bytes: u64,
    /// Maximum number of recent proof records to retain per backend (0 = unlimited).
    pub proof_history_cap: usize,
    /// Minimum number of blocks to retain proof records regardless of cap (age-based pruning).
    pub proof_retention_grace_blocks: u64,
    /// Maximum number of proof records pruned per enforcement pass (0 = unlimited).
    pub proof_prune_batch: usize,
    /// Maximum length of a bridge proof range (`end_height - start_height + 1`, 0 = unlimited).
    pub bridge_proof_max_range_len: u64,
    /// Maximum age (in blocks) a bridge proof's end height may trail the current block (0 = unlimited).
    pub bridge_proof_max_past_age_blocks: u64,
    /// Maximum future drift (in blocks) a bridge proof's end height may lead the current block (0 = unlimited).
    pub bridge_proof_max_future_drift_blocks: u64,
    /// Poseidon parameter set identifier to embed into policies (if any).
    pub poseidon_params_id: Option<u32>,
    /// Pedersen parameter set identifier to embed into policies (if any).
    pub pedersen_params_id: Option<u32>,
    /// Governed verifying key for every final Kaigi authorization action.
    pub kaigi_authorization_vk: Option<VerifyingKeyRef>,

    /// Optional verifying key reference used for Kaigi usage commitment proofs.
    pub kaigi_usage_vk: Option<VerifyingKeyRef>,
    /// Maximum proof size accepted from a single confidential operation.
    pub max_proof_size_bytes: u32,
    /// Maximum number of nullifiers a transaction may consume.
    pub max_nullifiers_per_tx: u32,
    /// Maximum number of commitments a transaction may create.
    pub max_commitments_per_tx: u32,
    /// Maximum confidential operations allowed in a block.
    pub max_confidential_ops_per_block: u32,
    /// Verifier timeout for confidential proofs.
    pub verify_timeout: Duration,
    /// Maximum age (in blocks) for anchors referenced by confidential proofs.
    pub max_anchor_age_blocks: u64,
    /// Aggregate proof bytes allowed per block.
    pub max_proof_bytes_block: u64,
    /// Maximum verification calls allowed per transaction.
    pub max_verify_calls_per_tx: u32,
    /// Maximum verification calls allowed per block.
    pub max_verify_calls_per_block: u32,
    /// Maximum public inputs accepted per proof.
    pub max_public_inputs: u32,
    /// Configured reorg depth bound for retaining commitment tree checkpoints.
    pub reorg_depth_bound: u64,
    /// Minimum delay (in blocks) between policy change request and activation.
    pub policy_transition_delay_blocks: u64,
    /// Grace window (in blocks) around policy activation for conversions.
    pub policy_transition_window_blocks: u64,
    /// Maximum confidential-policy transitions that may share one effective height.
    pub policy_transition_max_per_height: NonZeroU32,
    /// Non-zero commitment tree root history length to retain.
    pub tree_roots_history_len: NonZeroUsize,
    /// Interval (in blocks) between frontier checkpoints.
    pub tree_frontier_checkpoint_interval: u64,
    /// Maximum active verifier entries allowed in registry.
    pub registry_max_vk_entries: u32,
    /// Maximum active parameter sets allowed in registry.
    pub registry_max_params_entries: u32,
    /// Maximum number of registry mutations allowed per block.
    pub registry_max_delta_per_block: u32,
    /// Gas schedule applied to confidential verification.
    pub gas: ConfidentialGas,
}
/// SCCP proof-admission and deterministic verifier-work limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sccp {
    /// Maximum closed SCCP proofs in one transaction.
    pub max_proofs_per_transaction: NonZeroU32,
    /// Maximum closed SCCP proofs committed in one block.
    pub max_proofs_per_block: NonZeroU32,
    /// Maximum canonical bytes retained for one closed SCCP proof.
    pub max_proof_bytes_per_proof: NonZeroU64,
    /// Maximum aggregate SCCP proof bytes in one transaction.
    pub max_proof_bytes_per_transaction: NonZeroU64,
    /// Maximum aggregate SCCP proof bytes committed in one block.
    pub max_proof_bytes_per_block: NonZeroU64,
    /// Maximum native-finality continuation headers in one transaction.
    pub max_native_headers_per_transaction: NonZeroU32,
    /// Maximum native-finality continuation headers committed in one block.
    pub max_native_headers_per_block: NonZeroU32,
    /// Maximum Ethereum light-client updates in one transaction.
    pub max_ethereum_light_client_updates_per_transaction: NonZeroU32,
    /// Maximum Ethereum light-client updates committed in one block.
    pub max_ethereum_light_client_updates_per_block: NonZeroU32,
    /// Maximum framed native-finality header bytes in one transaction.
    pub max_native_header_bytes_per_transaction: NonZeroU64,
    /// Maximum framed native-finality header bytes committed in one block.
    pub max_native_header_bytes_per_block: NonZeroU64,
    /// Maximum Ed25519 signature checks in one transaction.
    pub max_ed25519_signature_checks_per_transaction: NonZeroU32,
    /// Maximum Ed25519 signature checks committed in one block.
    pub max_ed25519_signature_checks_per_block: NonZeroU32,
    /// Maximum BSC fast-finality vote attestations (fast-aggregate BLS checks) in one
    /// transaction.
    pub max_bls_vote_attestations_per_transaction: NonZeroU32,
    /// Maximum BSC fast-finality vote attestations (fast-aggregate BLS checks) committed in one
    /// block.
    pub max_bls_vote_attestations_per_block: NonZeroU32,
}
impl_default!(Sccp => {
        Self {
            max_proofs_per_transaction: defaults::zk::sccp::MAX_PROOFS_PER_TRANSACTION,
            max_proofs_per_block: defaults::zk::sccp::MAX_PROOFS_PER_BLOCK,
            max_proof_bytes_per_proof: defaults::zk::sccp::MAX_PROOF_BYTES_PER_PROOF,
            max_proof_bytes_per_transaction: defaults::zk::sccp::MAX_PROOF_BYTES_PER_TRANSACTION,
            max_proof_bytes_per_block: defaults::zk::sccp::MAX_PROOF_BYTES_PER_BLOCK,
            max_native_headers_per_transaction:
                defaults::zk::sccp::MAX_NATIVE_HEADERS_PER_TRANSACTION,
            max_native_headers_per_block: defaults::zk::sccp::MAX_NATIVE_HEADERS_PER_BLOCK,
            max_ethereum_light_client_updates_per_transaction:
                defaults::zk::sccp::MAX_ETHEREUM_LIGHT_CLIENT_UPDATES_PER_TRANSACTION,
            max_ethereum_light_client_updates_per_block:
                defaults::zk::sccp::MAX_ETHEREUM_LIGHT_CLIENT_UPDATES_PER_BLOCK,
            max_native_header_bytes_per_transaction:
                defaults::zk::sccp::MAX_NATIVE_HEADER_BYTES_PER_TRANSACTION,
            max_native_header_bytes_per_block:
                defaults::zk::sccp::MAX_NATIVE_HEADER_BYTES_PER_BLOCK,
            max_ed25519_signature_checks_per_transaction:
                defaults::zk::sccp::MAX_ED25519_SIGNATURE_CHECKS_PER_TRANSACTION,
            max_ed25519_signature_checks_per_block:
                defaults::zk::sccp::MAX_ED25519_SIGNATURE_CHECKS_PER_BLOCK,
            max_bls_vote_attestations_per_transaction:
                defaults::zk::sccp::MAX_BLS_VOTE_ATTESTATIONS_PER_TRANSACTION,
            max_bls_vote_attestations_per_block:
                defaults::zk::sccp::MAX_BLS_VOTE_ATTESTATIONS_PER_BLOCK,
        }
});
/// CABAC runtime mode compiled into the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CabacMode {
    /// CABAC code paths are disabled; only rANS is available.
    #[default]
    Disabled,
    /// CABAC code paths are compiled but negotiated adaptively per manifest.
    Adaptive,
    /// CABAC is forced on regardless of manifest preferences.
    Forced,
}
/// Execution backend for bundled rANS acceleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BundleAcceleration {
    /// Always use the portable scalar implementation.
    #[default]
    None,
    /// Force CPU SIMD paths (AVX2/NEON) when bundled mode is enabled.
    CpuSimd,
    /// Route bundle kernels through the GPU acceleration hooks.
    Gpu,
}
/// Build-time codec toggles used by the runtime.
#[derive(Debug, Clone)]
pub struct StreamingCodec {
    /// CABAC runtime mode (disabled/adaptive/forced).
    pub cabac_mode: CabacMode,
    /// Trellis-enabled block sizes (empty until claim-avoidance ships).
    pub trellis_block_sizes: Vec<u16>,
    /// Path to the deterministic SignedRansTablesV1 artefact.
    pub rans_tables_path: PathBuf,
    /// Entropy mode advertised by manifests/headers.
    pub entropy_mode: EntropyMode,
    /// Bundle width used when `entropy_mode` enables bundled rANS.
    pub bundle_width: u8,
    /// Preferred acceleration backend for bundle execution.
    pub bundle_accel: BundleAcceleration,
}
impl StreamingCodec {
    /// Construct codec toggles from repository defaults.
    #[must_use]
    pub fn from_defaults() -> Self {
        assert!(
            norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
            "Bundled rANS is mandatory; rebuild with ENABLE_RANS_BUNDLES=1"
        );
        Self {
            cabac_mode: CabacMode::Disabled,
            trellis_block_sizes: defaults::streaming::codec::trellis_blocks(),
            rans_tables_path: defaults::streaming::codec::rans_tables_path(),
            entropy_mode: EntropyMode::RansBundled,
            bundle_width: defaults::streaming::codec::bundle_width(),
            bundle_accel: BundleAcceleration::None,
        }
    }
}
impl_default!(StreamingCodec => {
        Self::from_defaults()
});
/// Norito streaming configuration used by the runtime.
#[derive(Debug, Clone)]
pub struct Streaming {
    /// Node-owned key material used for streaming control-plane handshakes.
    pub key_material: StreamingKeyMaterial,
    /// Directory where streaming session snapshots are persisted.
    pub session_store_dir: PathBuf,
    /// Feature bitmask advertised during capability negotiation.
    pub feature_bits: u32,
    /// Audio/video sync enforcement policy.
    pub sync: StreamingSync,
    /// Codec toggles (CABAC gating, trellis scopes, rANS artefact path).
    pub codec: StreamingCodec,
}
/// Runtime representation of the audio/video sync enforcement gate.
#[derive(Debug, Clone, Copy)]
pub struct StreamingSync {
    /// Enable the sync enforcement gate.
    pub enabled: bool,
    /// Observe-only mode logs violations without rejection.
    pub observe_only: bool,
    /// Minimum diagnostic window (milliseconds) required before enforcement.
    pub min_window_ms: u16,
    /// Sustained EWMA drift threshold (milliseconds).
    pub ewma_threshold_ms: u16,
    /// Hard cap for any single frame drift (milliseconds).
    pub hard_cap_ms: u16,
}
impl StreamingSync {
    /// Construct sync enforcement defaults from repository constants.
    #[must_use]
    pub fn from_defaults() -> Self {
        Self {
            enabled: defaults::streaming::sync::ENABLED,
            observe_only: defaults::streaming::sync::OBSERVE_ONLY,
            min_window_ms: defaults::streaming::sync::MIN_WINDOW_MS,
            ewma_threshold_ms: defaults::streaming::sync::EWMA_THRESHOLD_MS,
            hard_cap_ms: defaults::streaming::sync::HARD_CAP_MS,
        }
    }
}
impl_default!(StreamingSync => {
        Self::from_defaults()
});
/// Settlement conversion routing configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct Settlement {
    /// Router configuration for XOR conversion.
    pub router: Router,
}
/// Router configuration controlling shadow-price and buffer guard rails.
#[derive(Debug, Clone, Copy)]
pub struct Router {
    /// TWAP window used during settlement conversion.
    pub twap_window: Duration,
    /// Base epsilon safety margin (basis points).
    pub epsilon_bps: u16,
    /// Buffer alert threshold percentage.
    pub buffer_alert_pct: u8,
    /// Buffer throttle threshold percentage.
    pub buffer_throttle_pct: u8,
    /// Buffer XOR-only threshold percentage.
    pub buffer_xor_only_pct: u8,
    /// Buffer halt threshold percentage.
    pub buffer_halt_pct: u8,
    /// Buffer coverage horizon (hours).
    pub buffer_horizon_hours: u16,
}
impl_default!(Router => {
        Self {
            twap_window: Duration::from_secs(defaults::settlement::router::TWAP_WINDOW_SECS),
            epsilon_bps: defaults::settlement::router::EPSILON_BPS,
            buffer_alert_pct: defaults::settlement::router::ALERT_PCT,
            buffer_throttle_pct: defaults::settlement::router::THROTTLE_PCT,
            buffer_xor_only_pct: defaults::settlement::router::XOR_ONLY_PCT,
            buffer_halt_pct: defaults::settlement::router::HALT_PCT,
            buffer_horizon_hours: defaults::settlement::router::BUFFER_HORIZON_HOURS,
        }
});
/// Native PIPA-R verification policy for the exact compiled circuit registry.
#[derive(Debug, Clone, Copy)]
pub struct PipaR {
    /// Enable native PIPA-R verification in hosts.
    pub enabled: bool,
    /// Maximum canonical outer envelope length in bytes.
    pub max_envelope_bytes: usize,
    /// Maximum canonical proof-payload length in bytes.
    pub max_proof_bytes: usize,
}
impl_default!(PipaR => {
    Self {
        enabled: defaults::zk::pipa_r::ENABLED,
        max_envelope_bytes: defaults::zk::pipa_r::MAX_ENVELOPE_BYTES,
        max_proof_bytes: defaults::zk::pipa_r::MAX_PROOF_BYTES,
    }
});
/// Local diagnostic polynomial-opening bounds; these confer no ledger authority.
#[derive(Debug, Clone, Copy)]
pub struct IpaCommitment {
    /// Maximum domain exponent for diagnostic polynomial openings.
    pub max_k: u32,
    /// Maximum diagnostic transcript-label length in bytes.
    pub max_transcript_label_len: usize,
    /// Maximum encoded diagnostic polynomial-opening envelope size.
    pub max_envelope_bytes: usize,
    /// Require ASCII diagnostic transcript labels.
    pub enforce_transcript_label_ascii: bool,
}
impl_default!(IpaCommitment => { Self {
    max_k: defaults::zk::ipa_commitment::MAX_K,
    max_transcript_label_len: defaults::zk::ipa_commitment::MAX_TRANSCRIPT_LABEL_LEN,
    max_envelope_bytes: defaults::zk::ipa_commitment::MAX_ENVELOPE_BYTES,
    enforce_transcript_label_ascii: defaults::zk::ipa_commitment::ENFORCE_TRANSCRIPT_LABEL_ASCII,
} });
/// Optional local trace-checking policy, independent of monetary proof verification.
#[derive(Debug, Clone, Copy)]
pub struct DiagnosticTrace {
    /// Enable optional local diagnostic trace checking.
    pub enabled: bool,
    /// Maximum diagnostic tasks dispatched in one worker batch.
    pub max_batch: u32,
    /// Diagnostic worker threads (0 selects the bounded automatic count).
    pub worker_threads: usize,
    /// Diagnostic ingress capacity (0 derives a bounded capacity).
    pub queue_cap: usize,
    /// Maximum diagnostic enqueue wait in milliseconds.
    pub enqueue_wait_ms: u64,
    /// Capacity of the important diagnostic-task retry ring.
    pub retry_ring_cap: usize,
    /// Maximum retry rounds for an important diagnostic task.
    pub retry_max_attempts: u32,
    /// Diagnostic retry scheduler interval in milliseconds.
    pub retry_tick_ms: u64,
}
impl_default!(DiagnosticTrace => {
    Self {
        enabled: defaults::zk::trace::ENABLED,
        max_batch: defaults::zk::trace::MAX_BATCH,
        worker_threads: defaults::zk::trace::WORKER_THREADS,
        queue_cap: defaults::zk::trace::QUEUE_CAP,
        enqueue_wait_ms: defaults::zk::trace::ENQUEUE_WAIT_MS,
        retry_ring_cap: defaults::zk::trace::RETRY_RING_CAP,
        retry_max_attempts: defaults::zk::trace::RETRY_MAX_ATTEMPTS,
        retry_tick_ms: defaults::zk::trace::RETRY_TICK_MS,
    }
});
/// Native STARK/FRI verification settings.
#[derive(Debug, Clone, Copy)]
pub struct Stark {
    /// Enable native STARK verification (requires `zk-stark` build feature).
    pub enabled: bool,
    /// Maximum accepted outer STARK OpenVerifyEnvelope length (bytes).
    pub max_envelope_bytes: usize,
    /// Maximum accepted proof payload length (bytes).
    pub max_proof_bytes: usize,
}
impl_default!(Stark => {
        Self {
            enabled: crate::parameters::defaults::zk::stark::ENABLED,
            max_envelope_bytes: crate::parameters::defaults::zk::stark::MAX_ENVELOPE_BYTES,
            max_proof_bytes: crate::parameters::defaults::zk::stark::MAX_PROOF_BYTES,
        }
});
/// Telemetry profiles describing high-level capability bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryProfile {
    /// Telemetry is disabled entirely.
    Disabled,
    /// Enable lightweight operator metrics and status endpoints.
    Operator,
    /// Enable operator metrics plus costly runtime probes and timings.
    Extended,
    /// Enable operator metrics plus developer-only JSON/file outputs.
    Developer,
    /// Enable all telemetry capabilities supported by the build.
    Full,
}
impl TelemetryProfile {
    /// Return whether lightweight metrics instrumentation is enabled.
    #[inline]
    #[must_use]
    pub const fn metrics_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
    /// Return whether costly metric probes and timings are enabled.
    #[inline]
    #[must_use]
    pub const fn expensive_metrics_enabled(self) -> bool {
        matches!(self, Self::Extended | Self::Full)
    }
    /// Return whether developer-only telemetry outputs are enabled.
    #[inline]
    #[must_use]
    pub const fn developer_outputs_enabled(self) -> bool {
        matches!(self, Self::Developer | Self::Full)
    }
}
impl From<user::TelemetryProfile> for TelemetryProfile {
    fn from(profile: user::TelemetryProfile) -> Self {
        match profile {
            user::TelemetryProfile::Disabled => Self::Disabled,
            user::TelemetryProfile::Operator => Self::Operator,
            user::TelemetryProfile::Extended => Self::Extended,
            user::TelemetryProfile::Developer => Self::Developer,
            user::TelemetryProfile::Full => Self::Full,
        }
    }
}
/// Telemetry integrity policy (hash chaining + optional signing key).
#[derive(Clone)]
pub struct TelemetryIntegrity {
    /// Enable hash-chained telemetry exports.
    pub enabled: bool,
    /// Optional directory for integrity state snapshots.
    pub state_dir: Option<PathBuf>,
    /// Optional signing key for keyed hashes.
    pub signing_key: Option<[u8; 32]>,
    /// Optional key identifier for rotation workflows.
    pub signing_key_id: Option<String>,
}
impl core::fmt::Debug for TelemetryIntegrity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TelemetryIntegrity")
            .field("enabled", &self.enabled)
            .field("state_dir_configured", &self.state_dir.is_some())
            .field("signing_key_configured", &self.signing_key.is_some())
            .field("signing_key_id_configured", &self.signing_key_id.is_some())
            .finish()
    }
}
impl_default!(TelemetryIntegrity => {
        Self {
            enabled: defaults::telemetry::integrity::ENABLED,
            state_dir: None,
            signing_key: None,
            signing_key_id: None,
        }
});
/// Complete configuration needed to start regular telemetry.
#[derive(Clone)]
pub struct Telemetry {
    /// Telemetry endpoint URL.
    pub url: Url,
    /// Minimum retry period on failure.
    pub min_retry_period: Duration,
    /// Exponent for exponential backoff upper bound.
    pub max_retry_delay_exponent: u8,
    /// Optional Telegram bot key for alerts.
    pub telegram_bot_key: Option<String>,
    /// Optional Telegram chat ID for alerts.
    pub telegram_chat_id: Option<String>,
    /// Optional minimum level for Telegram alerts (e.g., "WARN", "ERROR").
    pub telegram_min_level: Option<String>,
    /// Optional list of target prefixes to include (e.g., ["p2p", "network"]). If empty or None, include all.
    pub telegram_targets: Option<Vec<String>>,
    /// Optional alerts rate limit (messages per minute).
    pub telegram_rate_per_minute: Option<NonZeroU32>,
    /// Include a metrics snapshot in alerts.
    pub telegram_include_metrics: bool,
    /// Optional allow-list of `msg` kinds to send.
    pub telegram_allow_kinds: Option<Vec<String>>,
    /// Optional deny-list of `msg` kinds to suppress.
    pub telegram_deny_kinds: Option<Vec<String>>,
}
impl core::fmt::Debug for Telemetry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Telemetry")
            .field("url", &"<redacted>")
            .field("min_retry_period", &self.min_retry_period)
            .field("max_retry_delay_exponent", &self.max_retry_delay_exponent)
            .field(
                "telegram_bot_key_configured",
                &self.telegram_bot_key.is_some(),
            )
            .field(
                "telegram_chat_id_configured",
                &self.telegram_chat_id.is_some(),
            )
            .field("telegram_min_level", &self.telegram_min_level)
            .field("telegram_targets", &self.telegram_targets)
            .field("telegram_rate_per_minute", &self.telegram_rate_per_minute)
            .field("telegram_include_metrics", &self.telegram_include_metrics)
            .field("telegram_allow_kinds", &self.telegram_allow_kinds)
            .field("telegram_deny_kinds", &self.telegram_deny_kinds)
            .finish()
    }
}
/// Network Time Service (NTS) configuration.
#[derive(Debug, Clone, Copy)]
pub struct Nts {
    /// Sampling interval for peer time probes.
    pub sample_interval: Duration,
    /// Maximum peers to sample per round.
    pub sample_cap_per_round: usize,
    /// Maximum acceptable round-trip time (milliseconds) for samples.
    pub max_rtt_ms: u64,
    /// Trim percent for median aggregation (0–45 allowed; 10 typical).
    pub trim_percent: u8,
    /// Per-peer ring buffer capacity for samples.
    pub per_peer_buffer: usize,
    /// Enable EMA smoothing of network offset.
    pub smoothing_enabled: bool,
    /// EMA alpha in [0,1]; higher means more responsive.
    pub smoothing_alpha: f64,
    /// Maximum allowed adjustment per minute (ms) when smoothing.
    pub max_adjust_ms_per_min: u64,
    /// Minimum number of peer samples required before NTS is considered healthy.
    pub min_samples: usize,
    /// Maximum absolute offset (ms) allowed before NTS is considered unhealthy (0 disables).
    pub max_offset_ms: u64,
    /// Maximum confidence (MAD) in ms allowed before NTS is considered unhealthy (0 disables).
    pub max_confidence_ms: u64,
    /// Enforcement mode for unhealthy NTS.
    pub enforcement_mode: NtsEnforcementMode,
}
/// Enforcement modes for unhealthy NTS during admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtsEnforcementMode {
    /// Log unhealthy NTS status but accept time-sensitive transactions.
    Warn,
    /// Reject time-sensitive transactions when NTS is unhealthy.
    Reject,
}
impl NtsEnforcementMode {
    /// Canonical config label for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Reject => "reject",
        }
    }
}
#[cfg(test)]
#[path = "actual/npos_timeout_tests.rs"]
mod tests_npos_timeouts;
/// IVM runtime presentation toggles.
#[derive(Debug, Clone, Copy)]
pub struct Ivm {
    /// Banner/presentation toggles surfaced during startup.
    pub banner: Banner,
}
impl Ivm {
    /// Construct an `Ivm` configuration from repository defaults.
    #[must_use]
    pub fn from_defaults() -> Self {
        Self {
            banner: Banner::from_defaults(),
        }
    }
}
impl_default!(Ivm => {
        Self::from_defaults()
});
/// Startup banner settings.
#[derive(Debug, Clone, Copy)]
pub struct Banner {
    /// Whether to print the Norito/IVM startup banner on daemon launch.
    pub show: bool,
    /// Whether to play the retro startup tune when compiled with the `beep` feature.
    pub beep: bool,
}
impl Banner {
    /// Construct banner settings from repository defaults.
    #[must_use]
    pub const fn from_defaults() -> Self {
        Self {
            show: defaults::ivm::banner::show(),
            beep: defaults::ivm::banner::beep(),
        }
    }
}
impl_default!(Banner => {
        Self::from_defaults()
});
/// Norito codec configuration (actual layer).
///
/// Norito serialization layout and adaptive thresholds are canonical for this
/// release. Actual configuration contains only operational controls that are
/// read by the daemon at startup.
#[derive(Debug, Clone, Copy)]
pub struct Norito {
    /// Allow GPU compression offload when compiled and available.
    pub allow_gpu_compression: bool,
    /// Maximum allowed Norito archive length in bytes (0 = unlimited).
    pub max_archive_len: u64,
}
/// Severity bands reported by the fraud-monitoring service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FraudRiskBand {
    /// Lowest severity rating produced by the external assessor.
    Low,
    /// Medium severity rating indicating elevated but tolerable risk.
    Medium,
    /// High severity rating signalling transactions that should be halted.
    High,
    /// Critical severity threshold reserved for outright blocking decisions.
    Critical,
}
impl FraudRiskBand {
    /// Return the canonical lowercase string representation expected by config files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}
impl core::fmt::Display for FraudRiskBand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl core::str::FromStr for FraudRiskBand {
    type Err = ();
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}
impl From<super::user::FraudRiskBand> for FraudRiskBand {
    fn from(value: super::user::FraudRiskBand) -> Self {
        match value {
            super::user::FraudRiskBand::Low => Self::Low,
            super::user::FraudRiskBand::Medium => Self::Medium,
            super::user::FraudRiskBand::High => Self::High,
            super::user::FraudRiskBand::Critical => Self::Critical,
        }
    }
}
/// Registered assessment attester (engine id + public key).
#[derive(Debug, Clone)]
pub struct FraudAttester {
    /// Deterministic identifier of the scoring engine / attester.
    pub engine_id: String,
    /// Public key used to verify assessment signatures.
    pub public_key: PublicKey,
}
impl FraudAttester {
    /// Create a trimmed engine identifier for metrics/logging.
    #[must_use]
    pub fn engine_label(&self) -> &str {
        let trimmed = self.engine_id.trim();
        if trimmed.is_empty() {
            "unknown"
        } else {
            trimmed
        }
    }
}
/// Strongly typed fraud-monitoring configuration used by the host.
#[derive(Debug, Clone)]
pub struct FraudMonitoring {
    /// Master switch controlling whether fraud assessments gate admission.
    pub enabled: bool,
    /// Ordered list of HTTP endpoints queried for fraud assessments.
    pub service_endpoints: Vec<Url>,
    /// Timeout applied to the initial TCP connection attempt.
    pub connect_timeout: Duration,
    /// Timeout applied to the full HTTP request, including body transfer.
    pub request_timeout: Duration,
    /// Grace period after which missing assessments trigger warnings or fallback.
    pub missing_assessment_grace: Duration,
    /// Minimum severity band required for admission; `None` disables gating.
    pub required_minimum_band: Option<FraudRiskBand>,
    /// Registered assessment attesters whose signatures must validate assessments.
    pub attesters: Vec<FraudAttester>,
}
impl FraudMonitoring {
    #[allow(clippy::too_many_arguments)]
    /// Construct a [`FraudMonitoring`] instance from validated user parameters.
    pub fn new(
        enabled: bool,
        service_endpoints: Vec<Url>,
        connect_timeout: Duration,
        request_timeout: Duration,
        missing_assessment_grace_secs: u64,
        required_minimum_band: Option<FraudRiskBand>,
        attesters: Vec<FraudAttester>,
    ) -> Self {
        let mut deduped = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for endpoint in service_endpoints {
            let key = endpoint.as_str().to_owned();
            if seen.insert(key) {
                deduped.push(endpoint);
            }
        }
        let connect_timeout = if connect_timeout.is_zero() {
            defaults::fraud_monitoring::CONNECT_TIMEOUT
        } else {
            connect_timeout
        };
        let request_timeout = if request_timeout.is_zero() {
            defaults::fraud_monitoring::REQUEST_TIMEOUT
        } else {
            request_timeout
        };
        let missing_assessment_grace = Duration::from_secs(missing_assessment_grace_secs);
        let mut attesters: Vec<FraudAttester> = attesters
            .into_iter()
            .filter_map(|mut attester| {
                let trimmed = attester.engine_id.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let mut normalized = trimmed.to_ascii_lowercase();
                if normalized.is_empty() {
                    normalized = trimmed.to_string();
                }
                attester.engine_id = normalized;
                Some(attester)
            })
            .collect();
        attesters.sort_by(|a, b| a.engine_id.cmp(&b.engine_id));
        attesters.dedup_by(|a, b| a.engine_id == b.engine_id);
        Self {
            enabled,
            service_endpoints: deduped,
            connect_timeout,
            request_timeout,
            missing_assessment_grace,
            required_minimum_band,
            attesters,
        }
    }
    /// Return the registered attester for the provided engine identifier.
    #[must_use]
    pub fn attester(&self, engine_id: &str) -> Option<&FraudAttester> {
        let key = engine_id.trim();
        if key.is_empty() {
            return None;
        }
        self.attesters
            .iter()
            .find(|attester| attester.engine_id == key)
    }
}
impl_default!(FraudMonitoring => {
        Self {
            enabled: defaults::fraud_monitoring::ENABLED,
            service_endpoints: Vec::new(),
            connect_timeout: defaults::fraud_monitoring::CONNECT_TIMEOUT,
            request_timeout: defaults::fraud_monitoring::REQUEST_TIMEOUT,
            missing_assessment_grace: Duration::from_secs(
                defaults::fraud_monitoring::MISSING_ASSESSMENT_GRACE_SECS,
            ),
            required_minimum_band: None,
            attesters: Vec::new(),
        }
});
include!("actual/tests.rs");
