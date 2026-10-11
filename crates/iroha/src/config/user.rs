//! User configuration view.
use crate::{
    config::BasicAuth,
    crypto::{KeyPair, PrivateKey, PublicKey},
    data_model::prelude::{AccountId, NetworkId},
};
use error_stack::{Report, ResultExt};
use iroha_config_base::{
    ParameterOrigin, ReadConfig, WithOrigin,
    attach::ConfigValueAndOrigin,
    file_source::{ConfigFileAccess, ConfigFileRequest, ConfigFileSource, read_checked},
    util::{DurationMs, Emitter, EmitterResultExt},
};
use iroha_model_base::chain::ChainId;
use iroha_service_model::soranet::AnonymityPolicy;
use iroha_service_model::soranet::RolloutPhase;
use iroha_torii_shared::network_profile_names;
use sorafs_manifest::alias_cache::AliasCachePolicy;
use std::{fmt, fs::File, io::Read as _, path::PathBuf, time::Duration};
use url::Url;
/// Minimal allowed transaction time-to-live.
const MIN_TRANSACTION_TTL: Duration = Duration::from_secs(1);
const MAX_PUBLIC_IDENTITY_FILE_BYTES: usize = 512;

pub(super) struct NativeConfigFiles;
impl ConfigFileSource for NativeConfigFiles {
    fn read(
        &self,
        path: &std::path::Path,
        request: ConfigFileRequest,
    ) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        if request.access == ConfigFileAccess::Private {
            return iroha_fs::read_private(path, request.maximum);
        }
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "public identity source is not a regular file",
            ));
        }
        let maximum = u64::try_from(request.maximum)
            .ok()
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configuration byte bound overflows",
                )
            })?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(maximum).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// Root of the user-facing configuration loaded from TOML + env.
#[derive(Clone, Debug, ReadConfig)]
pub struct Root {
    /// Unique chain identifier.
    #[config(env = "CHAIN")]
    pub chain: ChainId,
    /// Exact genesis-lineage identity used for signed protocol requests.
    #[config(env = "NETWORK_ID")]
    pub network_id: Option<NetworkId>,
    /// Public file containing exactly one LF-terminated canonical genesis-lineage identity.
    pub network_id_file: Option<WithOrigin<PathBuf>>,
    /// Torii API URL.
    #[config(env = "TORII_URL")]
    pub torii_url: WithOrigin<Url>,
    /// Optional HTTP Basic Auth credentials.
    pub basic_auth: Option<BasicAuth>,
    /// Owner-held Torii listener credential. Kept in private client configuration.
    pub api_token: Option<crate::secrecy::SecretString>,
    /// Timeout for Torii HTTP requests.
    #[config(default = "super::DEFAULT_TORII_REQUEST_TIMEOUT.into()")]
    pub torii_request_timeout_ms: WithOrigin<DurationMs>,
    #[config(nested)]
    /// Account configuration.
    pub account: Account,
    #[config(nested)]
    /// Transaction defaults.
    pub transaction: Transaction,
    #[config(nested)]
    /// SoraFS-specific configuration.
    pub sorafs: Sorafs,
    #[config(nested)]
    /// Optional Musubi production-publication platform bindings.
    pub musubi: Musubi,
}
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
/// Errors found while validating or parsing user configuration.
pub enum ParseError {
    /// Transaction status timeout should be smaller than its time-to-live.
    #[error("Transaction status timeout should be smaller than its time-to-live")]
    TxTimeoutVsTtl,
    /// Transaction time-to-live is below the minimal allowed value.
    #[error("Transaction time-to-live should be at least {MIN_TRANSACTION_TTL:?}")]
    TxTtlTooSmall,
    /// Failed to construct a key pair from provided public and private keys.
    #[error("Failed to construct a key pair from provided public and private keys")]
    KeyPair,
    /// Unsupported URL scheme in `torii_url`.
    #[error("Unsupported URL scheme: `{scheme}`")]
    UnsupportedUrlScheme {
        /// Scheme part of the provided URL.
        scheme: String,
    },
    /// Invalid `SoraFS` anonymity rollout policy label.
    #[error("Invalid `SoraFS` anonymity policy label: `{value}`")]
    InvalidSorafsAnonymityPolicy {
        /// The supplied label.
        value: String,
    },
    /// Invalid rollout phase label (`sorafs.rollout_phase`).
    #[error("Invalid `SoraFS` rollout phase label: `{value}`")]
    InvalidSorafsRolloutPhase {
        /// The supplied label.
        value: String,
    },
    /// Unknown public account network profile.
    #[error("Invalid account network profile: `{profile}`")]
    InvalidAccountProfile {
        /// Supplied profile label.
        profile: String,
    },
    /// Public account network profile and explicit chain discriminant disagree.
    #[error(
        "Account profile `{profile}` expects chain discriminant `{expected}`, but config supplied `{actual}`"
    )]
    AccountProfileDiscriminantMismatch {
        /// Supplied profile label.
        profile: String,
        /// Expected I105 chain discriminant for the profile.
        expected: u16,
        /// Actual explicit I105 chain discriminant.
        actual: u16,
    },
    /// Account config omitted both profile and explicit discriminant.
    #[error("Account config must set `profile` or an explicit `chain_discriminant`")]
    MissingAccountNetworkContext,
    /// Explicit account chain discriminant is zero.
    #[error("Account chain discriminant must be nonzero")]
    ZeroAccountChainDiscriminant,
    /// Exact network identity was absent, ambiguous, or invalid.
    #[error("Invalid exact network identity configuration")]
    InvalidNetworkIdentity,
}
type ReportResult<T, E> = core::result::Result<T, Report<[E]>>;
/// Resolve `account.profile` and `account.chain_discriminant` with the shared
/// [`super::resolve_account_chain_discriminant`] rule, reporting a failure with its origin.
fn resolve_account_network_context(
    profile: Option<&str>,
    explicit: Option<WithOrigin<u16>>,
    emitter: &mut Emitter<ParseError>,
) -> Option<u16> {
    let error = match super::resolve_account_chain_discriminant(
        profile,
        explicit.as_ref().map(|value| *value.value()),
    ) {
        Ok(discriminant) => return Some(discriminant),
        Err(error) => error,
    };
    let hint = match &error {
        super::AccountChainDiscriminantError::Missing => format!(
            "set `account.profile` to a public network ({}) or `account.chain_discriminant` to the I105 chain discriminant of the target network",
            network_profile_names()
        ),
        super::AccountChainDiscriminantError::UnknownProfile { .. } => {
            format!("supported account profiles: {}", network_profile_names())
        }
        super::AccountChainDiscriminantError::ProfileMismatch { profile, .. } => format!(
            "remove `account.chain_discriminant` or select the profile of the target network instead of `{profile}`"
        ),
        super::AccountChainDiscriminantError::Zero => {
            "set `account.chain_discriminant` to the nonzero I105 chain discriminant of the target network".to_owned()
        }
    };
    let mut report = Report::new(ParseError::from(error));
    if let Some(explicit) = explicit {
        report = report.attach(explicit.into_attachment());
    }
    emitter.emit(report.attach(hint));
    None
}
fn resolve_account_private_key(
    inline: Option<WithOrigin<PrivateKey>>,
    file: Option<WithOrigin<PathBuf>>,
    emitter: &mut Emitter<ParseError>,
    files: &dyn ConfigFileSource,
) -> Option<(PrivateKey, ParameterOrigin)> {
    let file = match (inline, file) {
        (Some(_), Some(_)) => {
            emitter.emit(
                Report::new(ParseError::KeyPair).attach(
                    "account.private_key and account.private_key_file are mutually exclusive; configure exactly one private-key source",
                ),
            );
            return None;
        }
        (Some(inline), None) => return Some(inline.into_tuple()),
        (None, Some(file)) => file,
        (None, None) => {
            emitter.emit(
                Report::new(ParseError::KeyPair).attach(
                    "missing account private-key source; configure exactly one of account.private_key or account.private_key_file",
                ),
            );
            return None;
        }
    };
    let path = file.resolve_relative_path();
    let (_, origin) = file.into_tuple();
    if path.as_os_str().is_empty() {
        emitter.emit(Report::new(ParseError::KeyPair).attach("account.private_key_file is empty"));
        return None;
    }
    let private_key = read_checked(
        files,
        &path,
        ConfigFileRequest {
            access: ConfigFileAccess::Private,
            maximum: 4096,
        },
    )
    .map_err(eyre::Report::from)
    .and_then(|bytes| super::private_key_file::parse(&bytes));
    match private_key {
        Ok(private_key) => Some((private_key, origin)),
        Err(error) => {
            emitter.emit(Report::new(ParseError::KeyPair).attach(format!(
                "cannot load account.private_key_file `{}`: {error:#}",
                path.display()
            )));
            None
        }
    }
}
pub(super) fn resolve_network_id_source(
    inline: Option<NetworkId>,
    file: Option<WithOrigin<PathBuf>>,
    emitter: &mut Emitter<ParseError>,
    files: &dyn ConfigFileSource,
) -> Option<NetworkId> {
    let file = match (inline, file) {
        (Some(_), Some(_)) => {
            emitter.emit(Report::new(ParseError::InvalidNetworkIdentity).attach(
                "network_id and network_id_file are mutually exclusive; configure exactly one public identity source",
            ));
            return None;
        }
        (Some(network_id), None) => return Some(network_id),
        (None, Some(file)) => file,
        (None, None) => {
            emitter.emit(Report::new(ParseError::InvalidNetworkIdentity).attach(
                "missing exact network identity; configure exactly one of network_id or network_id_file",
            ));
            return None;
        }
    };
    let path = file.resolve_relative_path();
    if path.as_os_str().is_empty() {
        emitter.emit(
            Report::new(ParseError::InvalidNetworkIdentity).attach("network_id_file is empty"),
        );
        return None;
    }
    let bytes = match read_checked(
        files,
        &path,
        ConfigFileRequest {
            access: ConfigFileAccess::Public,
            maximum: MAX_PUBLIC_IDENTITY_FILE_BYTES,
        },
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            emitter.emit(
                Report::new(ParseError::InvalidNetworkIdentity).attach(format!(
                    "cannot read network_id_file `{}`: {error}",
                    path.display()
                )),
            );
            return None;
        }
    };
    let Ok(encoded) = std::str::from_utf8(&bytes) else {
        emitter.emit(
            Report::new(ParseError::InvalidNetworkIdentity)
                .attach("network_id_file must contain UTF-8"),
        );
        return None;
    };
    let Some(identity_text) = encoded.strip_suffix('\n') else {
        emitter.emit(
            Report::new(ParseError::InvalidNetworkIdentity).attach(format!(
                "network_id_file `{}` must contain exactly one LF-terminated canonical network identity",
                path.display()
            )),
        );
        return None;
    };
    if identity_text.is_empty()
        || identity_text
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        emitter.emit(
            Report::new(ParseError::InvalidNetworkIdentity).attach(format!(
                "network_id_file `{}` must contain exactly one LF-terminated canonical network identity",
                path.display()
            )),
        );
        return None;
    }
    match identity_text.parse::<NetworkId>() {
        Ok(network_id) if encoded == format!("{network_id}\n") => Some(network_id),
        Ok(_) => {
            emitter.emit(
                Report::new(ParseError::InvalidNetworkIdentity).attach(format!(
                    "network_id_file `{}` does not contain the canonical network identity spelling",
                    path.display()
                )),
            );
            None
        }
        Err(err) => {
            emitter.emit(
                Report::new(ParseError::InvalidNetworkIdentity).attach(format!(
                    "network_id_file `{}` does not contain a valid network identity: {err}",
                    path.display()
                )),
            );
            None
        }
    }
}
impl Root {
    /// Validates user configuration for semantic errors and constructs a complete
    /// [`super::Config`].
    ///
    /// # Errors
    /// If a set of validity errors occurs.
    pub fn parse(self) -> ReportResult<super::Config, ParseError> {
        self.parse_with_musubi_sections(&NativeConfigFiles)
            .map(|(configuration, _publication, _fetch)| configuration)
    }
    pub(crate) fn parse_with_musubi_file_source(
        self,
        files: &dyn ConfigFileSource,
    ) -> ReportResult<(super::Config, MusubiPublication), ParseError> {
        self.parse_with_musubi_sections(files)
            .map(|(configuration, publication, _fetch)| (configuration, publication))
    }
    #[allow(clippy::too_many_lines)]
    fn parse_with_musubi_sections(
        self,
        files: &dyn ConfigFileSource,
    ) -> ReportResult<(super::Config, MusubiPublication, MusubiFetch), ParseError> {
        let Self {
            chain: chain_id,
            network_id,
            network_id_file,
            torii_url,
            basic_auth,
            api_token,
            torii_request_timeout_ms,
            account:
                Account {
                    profile,
                    public_key,
                    private_key,
                    private_key_file,
                    chain_discriminant,
                },
            transaction:
                Transaction {
                    time_to_live_ms: tx_ttl,
                    status_timeout_ms: tx_timeout,
                    nonce: tx_add_nonce,
                },
            sorafs,
            musubi:
                Musubi {
                    publication: musubi_publication,
                    fetch: musubi_fetch,
                },
        } = self;
        let mut emitter = Emitter::new();
        let network_id =
            resolve_network_id_source(network_id, network_id_file, &mut emitter, files);
        if tx_ttl.value().get() < MIN_TRANSACTION_TTL {
            emitter.emit(
                Report::new(ParseError::TxTtlTooSmall)
                    .attach(tx_ttl.clone().into_attachment())
                    .attach(format!(
                        "Note: minimal allowed TTL is {MIN_TRANSACTION_TTL:?}"
                    )),
            )
        }
        if tx_timeout.value() > tx_ttl.value() {
            emitter.emit(
                Report::new(ParseError::TxTimeoutVsTtl)
                    .attach(tx_timeout.clone().into_attachment())
                    .attach(tx_ttl.clone().into_attachment())
                    .attach(format!(
                        "Note: transaction status timeout must not exceed TTL (timeout={:?}, ttl={:?})",
                        tx_timeout.value(),
                        tx_ttl.value()
                    )),
            )
        }
        match torii_url.value().scheme() {
            "http" | "https" => {}
            scheme => emitter.emit(
                Report::new(ParseError::UnsupportedUrlScheme {
                    scheme: scheme.to_string(),
                })
                .attach(torii_url.clone().into_attachment())
                .attach("Note: only `http` and `https` protocols are supported"),
            ),
        }
        let torii_api_url = super::normalize_torii_api_url(torii_url.into_value());
        let account_chain_discriminant =
            resolve_account_network_context(profile.as_deref(), chain_discriminant, &mut emitter);
        let (public_key, public_key_origin) = public_key.into_tuple();
        let private_key =
            resolve_account_private_key(private_key, private_key_file, &mut emitter, files);
        let key_pair = private_key.and_then(|(private_key, private_key_origin)| {
            KeyPair::new(public_key.clone(), private_key)
                .attach(ConfigValueAndOrigin::new("[REDACTED]", public_key_origin))
                .attach(ConfigValueAndOrigin::new("[REDACTED]", private_key_origin))
                .change_context(ParseError::KeyPair)
                .ok_or_emit(&mut emitter)
        });
        let account_id = AccountId::of(public_key);
        let Sorafs {
            alias_cache,
            rollout_phase,
            anonymity_policy,
        } = sorafs;
        let alias_policy = alias_cache.into_policy();
        let rollout_phase_value =
            RolloutPhase::parse(rollout_phase.as_str()).unwrap_or_else(|| {
                emitter.emit(
                    Report::new(ParseError::InvalidSorafsRolloutPhase {
                        value: rollout_phase.clone(),
                    })
                    .attach("invalid `sorafs.rollout_phase`; expected exactly canary|ramp|default"),
                );
                RolloutPhase::default()
            });
        let phase_default_policy = match rollout_phase_value {
            RolloutPhase::Canary => AnonymityPolicy::GuardPq,
            RolloutPhase::Ramp => AnonymityPolicy::MajorityPq,
            RolloutPhase::Default => AnonymityPolicy::StrictPq,
        };
        let default_anonymity_policy = anonymity_policy
            .map_or(phase_default_policy, |label| {
                AnonymityPolicy::parse(&label).unwrap_or_else(|| {
                    emitter.emit(
                        Report::new(ParseError::InvalidSorafsAnonymityPolicy {
                            value: label.clone(),
                        })
                        .attach(format!(
                            "invalid `sorafs.anonymity_policy` value `{label}`; expected exactly anon-guard-pq|anon-majority-pq|anon-strict-pq"
                        )),
                    );
                    phase_default_policy
                })
            });
        emitter.into_result()?;
        let network_id =
            network_id.expect("network identity should be valid when emitter succeeds");
        let account_chain_discriminant = account_chain_discriminant
            .expect("account network context should be valid when emitter succeeds");
        Ok((
            super::Config {
                chain: chain_id,
                network_id,
                account: account_id,
                account_chain_discriminant,
                key_pair: key_pair.unwrap(),
                torii_api_url,
                basic_auth,
                api_token,
                torii_request_timeout: torii_request_timeout_ms.into_value().get(),
                transaction_ttl: tx_ttl.into_value().get(),
                transaction_status_timeout: tx_timeout.into_value().get(),
                transaction_add_nonce: tx_add_nonce,
                sorafs_alias_cache: alias_policy,
                sorafs_anonymity_policy: default_anonymity_policy,
                sorafs_rollout_phase: rollout_phase_value,
            },
            musubi_publication,
            musubi_fetch,
        ))
    }
}
/// Account parameters for building the default signer identity.
///
/// The network context is explicit: set `profile` for a public network or
/// `chain_discriminant` for any other network. Omitting both is a parse error.
#[derive(Debug, Clone, ReadConfig)]
pub struct Account {
    /// Public network profile (`taira` or `minamoto`) that determines the I105 chain
    /// discriminant.
    #[config(env = "ACCOUNT_PROFILE")]
    pub profile: Option<String>,
    /// Public key of the account.
    #[config(env = "ACCOUNT_PUBLIC_KEY")]
    pub public_key: WithOrigin<PublicKey>,
    /// Private key of the account.
    #[config(env = "ACCOUNT_PRIVATE_KEY")]
    pub private_key: Option<WithOrigin<PrivateKey>>,
    /// Owner-held file containing the account's canonical private key.
    #[config(env = "ACCOUNT_PRIVATE_KEY_FILE")]
    pub private_key_file: Option<WithOrigin<PathBuf>>,
    /// Explicit I105 chain discriminant used when parsing and rendering account literals.
    ///
    /// Required for networks without a public `profile`; with a profile it must match the
    /// profile's discriminant. It has no default.
    #[config(env = "ACCOUNT_CHAIN_DISCRIMINANT")]
    pub chain_discriminant: Option<WithOrigin<u16>>,
}
/// Transaction defaults used by the client.
#[derive(Debug, Clone, ReadConfig)]
pub struct Transaction {
    /// Transaction time-to-live.
    #[config(default = "super::DEFAULT_TRANSACTION_TIME_TO_LIVE.into()")]
    pub time_to_live_ms: WithOrigin<DurationMs>,
    /// Timeout for waiting on transaction status.
    #[config(default = "super::DEFAULT_TRANSACTION_STATUS_TIMEOUT.into()")]
    pub status_timeout_ms: WithOrigin<DurationMs>,
    /// Whether to add a random nonce to transactions.
    #[config(default = "super::DEFAULT_TRANSACTION_NONCE")]
    pub nonce: bool,
}
/// Musubi-specific platform client configuration.
#[derive(Clone, Debug, Default, ReadConfig)]
pub struct Musubi {
    #[config(nested)]
    /// Optional production-publication service and public request bindings.
    pub publication: MusubiPublication,
    #[config(nested)]
    /// Optional authenticated `SoraFS` archive-fetch bindings.
    pub fetch: MusubiFetch,
}
/// Raw authenticated archive-fetch values admitted from `[musubi.fetch]`.
///
/// These fields have no environment mappings. Operator credentials are named only by
/// platform-owned files and are never embedded in this configuration value.
#[derive(Clone, Default, ReadConfig)]
pub struct MusubiFetch {
    /// Exact genesis-lineage identity used to sign stream-token issuance requests.
    pub network_id: Option<NetworkId>,
    /// Stable, non-secret client label sent to `SoraFS` token issuers.
    pub client_id: Option<String>,
    /// Optional bounded request timeout in milliseconds.
    pub request_timeout_ms: Option<u64>,
    /// Exact provider-specific HTTPS origins and credential-file bindings.
    #[config(default)]
    pub provider_gateways: Vec<MusubiFetchProviderGateway>,
}
impl fmt::Debug for MusubiFetch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiFetch")
            .field("configured", &!self.provider_gateways.is_empty())
            .field("network_id_configured", &self.network_id.is_some())
            .field("provider_gateway_count", &self.provider_gateways.len())
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish_non_exhaustive()
    }
}
/// One trusted provider identity, HTTPS origin, and runtime-only operator key file.
#[derive(Clone, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct MusubiFetchProviderGateway {
    /// Lowercase hexadecimal public `SoraFS` provider identifier.
    pub provider_id: String,
    /// Provider-specific `SoraFS` HTTPS origin.
    pub url: String,
    /// Canonical operator public key authorized by this provider.
    pub operator_public_key: String,
    /// Platform-owned file containing the provider-authorized operator private key.
    pub operator_private_key_file: String,
}
impl fmt::Debug for MusubiFetchProviderGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiFetchProviderGateway")
            .field("provider_id", &self.provider_id)
            .field(
                "operator_public_key_configured",
                &!self.operator_public_key.is_empty(),
            )
            .field(
                "operator_private_key_configured",
                &!self.operator_private_key_file.is_empty(),
            )
            .finish_non_exhaustive()
    }
}
/// Raw production-publication values admitted from `[musubi.publication]`.
///
/// These fields deliberately have no environment mappings. The Musubi runtime performs the
/// security-sensitive semantic validation and keeps service URLs out of diagnostics.
#[derive(Clone, Default, ReadConfig)]
pub struct MusubiPublication {
    /// Private authenticated seed-ingress HTTPS base URL.
    pub seed_ingress_url: Option<String>,
    /// Private permanent-pin and replication-coordinator HTTPS base URL.
    pub storage_coordinator_url: Option<String>,
    /// Public I105 account of the admitted seed-ingress broker.
    pub ingress_broker: Option<String>,
    /// Lowercase hexadecimal public `SoraFS` seed-provider identifier.
    pub seed_provider: Option<String>,
    /// Exact registry admission-policy revision expected by the publication.
    pub expected_policy_revision: Option<u64>,
    /// Optional bounded request timeout in milliseconds.
    pub request_timeout_ms: Option<u64>,
    /// Exact provider-specific readback origins.
    #[config(default)]
    pub provider_gateways: Vec<MusubiPublicationProviderGateway>,
    /// Optional path to a canonical public namespace-delegation proof.
    pub namespace_delegation_file: Option<String>,
}
impl fmt::Debug for MusubiPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiPublication")
            .field("configured", &self.seed_ingress_url.is_some())
            .field("provider_gateway_count", &self.provider_gateways.len())
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field(
                "namespace_delegation_configured",
                &self.namespace_delegation_file.is_some(),
            )
            .finish_non_exhaustive()
    }
}
/// One public provider identity and private provider-specific readback HTTPS base.
#[derive(Clone, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct MusubiPublicationProviderGateway {
    /// Lowercase hexadecimal public `SoraFS` provider identifier.
    pub provider_id: String,
    /// Authenticated private readback HTTPS base URL; providers may share a service.
    pub url: String,
    /// Exact provider management origin for account-signed attestation inventory reads.
    /// HTTPS is required except for an explicitly selected numeric loopback HTTP origin.
    pub attestation_url: String,
}
impl fmt::Debug for MusubiPublicationProviderGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiPublicationProviderGateway")
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}
/// SoraFS-specific configuration.
#[derive(Debug, Clone, ReadConfig)]
pub struct Sorafs {
    #[config(nested)]
    /// Alias cache policy applied to gateway responses.
    pub alias_cache: AliasCache,
    /// Rollout phase label controlling default anonymity policy.
    #[config(default = "RolloutPhase::default().label().to_owned()")]
    pub rollout_phase: String,
    /// Default `SoraNet` anonymity policy stage for gateway fetches.
    pub anonymity_policy: Option<String>,
}
impl Default for Sorafs {
    fn default() -> Self {
        Self {
            alias_cache: AliasCache::default(),
            rollout_phase: RolloutPhase::default().label().to_owned(),
            anonymity_policy: Some(AnonymityPolicy::default().label().to_owned()),
        }
    }
}
/// Alias cache policy knobs surfaced to clients.
#[derive(Debug, Clone, Copy, ReadConfig)]
pub struct AliasCache {
    /// Positive TTL in seconds applied to cached alias proofs.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS")]
    pub positive_ttl: u64,
    /// Refresh window in seconds before the positive TTL elapses.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS")]
    pub refresh_window: u64,
    /// Hard expiry in seconds after which stale proofs are rejected.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS")]
    pub hard_expiry: u64,
    /// Negative cache TTL in seconds for missing aliases.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS")]
    pub negative_ttl: u64,
    /// TTL in seconds for revoked aliases (`410 Gone` responses).
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS")]
    pub revocation_ttl: u64,
    /// Maximum age in seconds tolerated before alias proof bundles must rotate.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS")]
    pub rotation_max_age: u64,
    /// Grace period in seconds applied after an approved successor manifest.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS")]
    pub successor_grace: u64,
    /// Grace period in seconds applied to governance-driven alias rotations.
    #[config(default = "iroha_service_model::sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS")]
    pub governance_grace: u64,
}
impl Default for AliasCache {
    fn default() -> Self {
        Self {
            positive_ttl: iroha_service_model::sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS,
            refresh_window: iroha_service_model::sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS,
            hard_expiry: iroha_service_model::sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS,
            negative_ttl: iroha_service_model::sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS,
            revocation_ttl: iroha_service_model::sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS,
            rotation_max_age: iroha_service_model::sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS,
            successor_grace: iroha_service_model::sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS,
            governance_grace: iroha_service_model::sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS,
        }
    }
}
impl AliasCache {
    /// Convert explicit SDK configuration into the reusable alias cache policy.
    #[must_use]
    pub fn into_policy(self) -> AliasCachePolicy {
        AliasCachePolicy::new(
            Duration::from_secs(self.positive_ttl),
            Duration::from_secs(self.refresh_window),
            Duration::from_secs(self.hard_expiry),
            Duration::from_secs(self.negative_ttl),
            Duration::from_secs(self.revocation_ttl),
            Duration::from_secs(self.rotation_max_age),
            Duration::from_secs(self.successor_grace),
            Duration::from_secs(self.governance_grace),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Algorithm;
    use std::{fs, str::FromStr, time::Duration};
    #[test]
    fn alias_cache_policy_preserves_every_configured_duration() {
        let policy = AliasCache {
            positive_ttl: 1,
            refresh_window: 2,
            hard_expiry: 3,
            negative_ttl: 4,
            revocation_ttl: 5,
            rotation_max_age: 6,
            successor_grace: 7,
            governance_grace: 8,
        }
        .into_policy();
        assert_eq!(
            [
                policy.positive_ttl(),
                policy.refresh_window(),
                policy.hard_expiry(),
                policy.negative_ttl(),
                policy.revocation_ttl(),
                policy.rotation_max_age(),
                policy.successor_grace(),
                policy.governance_grace()
            ],
            [1, 2, 3, 4, 5, 6, 7, 8].map(Duration::from_secs)
        );
    }
    fn root_with_timeouts(ttl: Duration, timeout: Duration) -> Root {
        let key_pair =
            KeyPair::try_from_seed(b"iroha:config:user:tests".to_vec(), Algorithm::Ed25519)
                .expect("derive user-config fixture key");
        Root {
            chain: ChainId::from_str("test-chain").expect("chain id"),
            network_id: Some(NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                crate::data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xA5; iroha_crypto::Hash::LENGTH]),
            ))),
            network_id_file: None,
            torii_url: WithOrigin::inline(
                Url::parse("http://127.0.0.1:8080/torii").expect("valid torii url"),
            ),
            basic_auth: None,
            api_token: None,
            torii_request_timeout_ms: WithOrigin::inline(DurationMs::from(
                crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            )),
            account: Account {
                profile: None,
                public_key: WithOrigin::inline(key_pair.public_key().clone()),
                private_key: Some(WithOrigin::inline(key_pair.private_key().clone())),
                private_key_file: None,
                chain_discriminant: Some(WithOrigin::inline(777)),
            },
            transaction: Transaction {
                time_to_live_ms: WithOrigin::inline(DurationMs::from(ttl)),
                status_timeout_ms: WithOrigin::inline(DurationMs::from(timeout)),
                nonce: false,
            },
            sorafs: Sorafs::default(),
            musubi: Musubi::default(),
        }
    }
    #[test]
    fn root_with_timeouts_uses_checked_fixture_seed_derivation() {
        let root = root_with_timeouts(Duration::from_secs(5), Duration::from_secs(3));
        let expected =
            KeyPair::try_from_seed(b"iroha:config:user:tests".to_vec(), Algorithm::Ed25519)
                .expect("derive expected user-config fixture key");
        assert_eq!(root.account.public_key.value(), expected.public_key());
        assert_eq!(
            root.account
                .private_key
                .as_ref()
                .expect("inline private key")
                .value(),
            expected.private_key()
        );
    }
    #[test]
    fn network_id_file_supplies_the_exact_signing_domain() {
        let expected = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            crate::data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"client file backed network identity"),
        ));
        let identity_file = tempfile::NamedTempFile::new().expect("identity file");
        fs::write(identity_file.path(), format!("{expected}\n")).expect("write identity");
        let mut emitter = Emitter::new();
        let resolved = resolve_network_id_source(
            None,
            Some(WithOrigin::inline(identity_file.path().to_path_buf())),
            &mut emitter,
            &NativeConfigFiles,
        );
        assert_eq!(resolved, Some(expected));
        assert!(emitter.into_result().is_ok());
    }
    #[test]
    fn network_id_file_rejects_noncanonical_record_bytes() {
        let expected = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            crate::data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"client canonical network identity file bytes"),
        ));
        let canonical = expected.to_string();
        for (label, contents) in [
            ("missing final LF", canonical.clone()),
            ("CRLF terminator", format!("{canonical}\r\n")),
            ("leading space", format!(" {canonical}\n")),
            ("trailing space", format!("{canonical} \n")),
            ("extra empty record", format!("{canonical}\n\n")),
            ("multiple records", format!("{canonical}\n{canonical}\n")),
        ] {
            let identity_file = tempfile::NamedTempFile::new().expect("identity file");
            fs::write(identity_file.path(), contents).expect("write malformed identity");
            let mut emitter = Emitter::new();
            assert!(
                resolve_network_id_source(
                    None,
                    Some(WithOrigin::inline(identity_file.path().to_path_buf())),
                    &mut emitter,
                    &NativeConfigFiles,
                )
                .is_none(),
                "{label} must fail closed"
            );
            assert!(emitter.into_result().is_err(), "{label} must emit an error");
        }
    }
    #[test]
    fn network_id_rejects_ambiguous_inline_and_file_sources() {
        let expected = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            crate::data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"ambiguous client network identity"),
        ));
        let identity_file = tempfile::NamedTempFile::new().expect("identity file");
        fs::write(identity_file.path(), format!("{expected}\n")).expect("write identity");
        let mut emitter = Emitter::new();
        assert!(
            resolve_network_id_source(
                Some(expected),
                Some(WithOrigin::inline(identity_file.path().to_path_buf())),
                &mut emitter,
                &NativeConfigFiles,
            )
            .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
    #[test]
    fn parse_accepts_timeout_not_exceeding_ttl() {
        let ttl = Duration::from_secs(5);
        let timeout = Duration::from_secs(3);
        let config = root_with_timeouts(ttl, timeout)
            .parse()
            .expect("configuration should be valid");
        assert_eq!(config.transaction_ttl, ttl);
        assert_eq!(config.transaction_status_timeout, timeout);
    }
    fn parse_errors(root: Root) -> Vec<ParseError> {
        root.parse()
            .expect_err("configuration should be rejected")
            .frames()
            .filter_map(|frame| frame.downcast_ref::<ParseError>())
            .cloned()
            .collect()
    }
    fn with_network_context(profile: Option<&str>, explicit: Option<u16>) -> Root {
        let mut root = root_with_timeouts(Duration::from_secs(5), Duration::from_secs(3));
        root.account.profile = profile.map(str::to_owned);
        root.account.chain_discriminant = explicit.map(WithOrigin::inline);
        root
    }
    #[test]
    fn parse_rejects_missing_account_network_context() {
        for profile in [None, Some(""), Some("  ")] {
            assert_eq!(
                parse_errors(with_network_context(profile, None)),
                [ParseError::MissingAccountNetworkContext],
                "{profile:?} must not select a default network"
            );
        }
    }
    #[test]
    fn parse_preserves_explicit_account_chain_discriminant() {
        let config = with_network_context(None, Some(777))
            .parse()
            .expect("an explicit discriminant is a complete network context");
        assert_eq!(config.account_chain_discriminant, 777);
    }
    #[test]
    fn parse_uses_account_profile_chain_discriminant() {
        for (profile, expected) in [
            (
                iroha_torii_shared::NETWORK_PROFILE_TAIRA,
                iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT,
            ),
            (
                iroha_torii_shared::NETWORK_PROFILE_MINAMOTO,
                iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            ),
            ("Taira", iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT),
        ] {
            let config = with_network_context(Some(profile), None)
                .parse()
                .expect("a public profile is a complete network context");
            assert_eq!(config.account_chain_discriminant, expected, "{profile}");
        }
    }
    #[test]
    fn parse_accepts_matching_account_profile_and_chain_discriminant() {
        let config = with_network_context(
            Some(iroha_torii_shared::NETWORK_PROFILE_TAIRA),
            Some(iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT),
        )
        .parse()
        .expect("a matching explicit discriminant should be accepted");
        assert_eq!(
            config.account_chain_discriminant,
            iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT
        );
    }
    #[test]
    fn parse_rejects_account_profile_discriminant_mismatch() {
        assert_eq!(
            parse_errors(with_network_context(
                Some(iroha_torii_shared::NETWORK_PROFILE_TAIRA),
                Some(753),
            )),
            [ParseError::AccountProfileDiscriminantMismatch {
                profile: iroha_torii_shared::NETWORK_PROFILE_TAIRA.to_owned(),
                expected: iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT,
                actual: 753,
            }]
        );
    }
    #[test]
    fn parse_rejects_unknown_account_profile() {
        for explicit in [None, Some(777)] {
            assert_eq!(
                parse_errors(with_network_context(Some("unknownnet"), explicit)),
                [ParseError::InvalidAccountProfile {
                    profile: "unknownnet".to_owned(),
                }],
                "explicit discriminant {explicit:?}"
            );
        }
    }
    #[test]
    fn parse_rejects_zero_account_chain_discriminant() {
        assert_eq!(
            parse_errors(with_network_context(None, Some(0))),
            [ParseError::ZeroAccountChainDiscriminant]
        );
    }
    #[test]
    fn parse_preserves_torii_request_timeout() {
        let mut root = root_with_timeouts(Duration::from_secs(5), Duration::from_secs(3));
        let timeout = Duration::from_secs(7);
        root.torii_request_timeout_ms = WithOrigin::inline(DurationMs::from(timeout));
        let config = root.parse().expect("configuration should be valid");
        assert_eq!(config.torii_request_timeout, timeout);
    }
    #[test]
    fn parse_rejects_timeout_exceeding_ttl() {
        let err = root_with_timeouts(Duration::from_secs(2), Duration::from_secs(3))
            .parse()
            .expect_err("timeout longer than TTL should be rejected");
        let parse_errors: Vec<_> = err
            .frames()
            .filter_map(|frame| frame.downcast_ref::<ParseError>())
            .collect();
        assert!(
            parse_errors
                .iter()
                .any(|error| matches!(error, ParseError::TxTimeoutVsTtl)),
            "expected `ParseError::TxTimeoutVsTtl`, found {parse_errors:?}"
        );
        assert!(format!("{err:?}").contains("transaction status timeout must not exceed TTL"));
    }
}
