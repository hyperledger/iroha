//! First-release Musubi registry, signing, and production-publication boundary.
//!
//! Public finalized reads load the required exact-network account signer from the selected Iroha
//! `client.toml` and sign every concrete query body/path. Mutations use the same required signing
//! configuration and sign the concrete V1 instruction locally. Publication delegates clean-package
//! validation, authenticated seed ingress, pin/order coordination, and provider readback to an
//! explicit runtime service; the default service fails closed. Archive registration itself is not
//! delegated: the signer prebuilds, fee-quotes, and signs one exact transaction, the publication
//! journal persists it before submission, and recovery pairs that transaction identity with the
//! authoritative archive embedded in a finalized archive-location page before any storage
//! coordination begins. Release claims likewise reconstruct the journaled signature, query
//! authoritative payload-hash status first, and replay the same locally verified Torii bytes only
//! when the engine confirms that the signed location and readback floor is still current. The
//! authorization-inclusive wire digest is a local replay-integrity binding; transaction status does
//! not attest it.
use crate::{
    publication_runtime::read_bounded_platform_config_v1,
    publish::{
        PublicationAdvanceV1, PublicationAmxSubmissionV1, PublicationArchiveAbsenceEvidenceV1,
        PublicationArchiveLocationAdvanceV1, PublicationArchiveLocationIntentV1,
        PublicationArchiveLocationTerminalReasonV1, PublicationArchiveLocationTerminalV1,
        PublicationArchiveRegistrationAdvanceV1, PublicationArchiveRegistrationIntentV1,
        PublicationArchiveRegistrationTerminalV1, PublicationArchiveRegistrationV1,
        PublicationBackend, PublicationBackendError, PublicationBackendFailureClass,
        PublicationCarSource, PublicationEngine, PublicationError, PublicationFinalEvidenceV1,
        PublicationOperationIdV1, PublicationProviderRegistrationCheckpointAdvanceV1,
        PublicationProviderRegistrationCheckpointV1, PublicationReadbackEvidenceV1,
        PublicationRegisteredArchiveV1, PublicationReleaseAbsenceEvidenceV1,
        PublicationReleasePreparationFloorV1, PublicationReleaseSubmissionAdvanceV1,
        PublicationReleaseSubmissionIntentV1, PublicationReleaseSubmissionTerminalV1,
        PublicationReplicationAdvanceV1, PublicationReplicationCheckpointV1, PublicationRequestV1,
        PublicationValidationEvidenceV1, archive_registration_intent_valid_until_ms,
        release_submission_valid_until_ms,
    },
};
use iroha::{
    blocking::{AccountClient, Client},
    client::{Client as AsyncClient, FeeQuoteRequest, musubi::QueryResult},
    config::Config,
};
#[cfg(test)]
use iroha_data_model::isi::musubi::PublishMusubiReleaseV1;
use iroha_data_model::{
    NetworkId,
    account::address::ChainDiscriminantGuard,
    isi::InstructionBox,
    musubi::{
        MUSUBI_MAX_PAGE_SIZE_V1, MUSUBI_MIN_HEALTHY_REPLICAS_V1, MusubiAliasHistoryPageV1,
        MusubiAliasQueryV1, MusubiAliasRecordV1, MusubiArchiveCommitmentV1,
        MusubiArchiveLocationIdV1, MusubiArchiveLocationPageV1, MusubiArchiveLocationQueryV1,
        MusubiArchiveLocationStateV1, MusubiArchiveLocationV1, MusubiArchiveRetentionDispositionV1,
        MusubiArchiveRetentionPageV1, MusubiArchiveRetentionQueryV1, MusubiExactPackageQueryV1,
        MusubiExactReleaseQueryV1, MusubiExactReleaseSnapshotV1, MusubiMaintainerPageV1,
        MusubiNamespaceBindingV1, MusubiOrderedPackagePageV1, MusubiOrderedPrefixQueryV1,
        MusubiOrderedPrefixV1, MusubiPackageIdV1, MusubiPackagePageQueryV1, MusubiPackageRecordV1,
        MusubiPackageSelectorV1, MusubiPageRequestV1, MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationRecordV1, MusubiReleaseIdV1, MusubiResolverIndexPageV1,
        MusubiResolverIndexQueryV1, MusubiSearchPageV1, MusubiSearchQueryV1,
        MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptV1, MusubiVersionPageV1,
    },
    sorafs::capacity::ProviderId,
    transaction::{FeePaymentIntent, SignedTransaction, TransactionPayload},
};
use iroha_model_base::metadata::Metadata;
use iroha_musubi_service::MusubiSeedIngressCarPlanV1;
#[cfg(test)]
use std::fs;
use std::{
    error::Error,
    fmt,
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
mod provider_inventory;
const MAX_PUBLIC_CONFIG_BYTES_USIZE: usize = 1024 * 1024;
const PLATFORM_CONFIG_PROVENANCE_CONTEXT: &str =
    "iroha:musubi:platform-client-config-provenance:v1";
/// Retry classification for a redacted registry failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryFailureClassV1 {
    /// The same bounded request may succeed when retried.
    Retryable,
    /// External state or local configuration must change before retrying.
    Permanent,
    /// The exact requested record does not exist.
    NotFound,
    /// A finalized cursor is stale and must not be silently restarted.
    StaleCursor,
}
/// Authoritative terminal state for one exact signed transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryTerminalTransactionStateV1 {
    /// The transaction was finalized with a rejection.
    Rejected,
    /// The transaction expired without application.
    Expired,
}
/// Payload transaction state recovered from the typed Torii status endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryTransactionStateV1 {
    /// No authoritative or pending record is currently visible.
    Absent,
    /// The transaction is pending or only has a non-authoritative terminal hint.
    Pending,
    /// The payload transaction is durably applied at the reported block height.
    Applied {
        /// Applied block height from authoritative state.
        block_height: u64,
    },
    /// The transaction has an authoritative terminal negative state.
    Terminal {
        /// Terminal kind.
        kind: RegistryTerminalTransactionStateV1,
        /// Finalized rejection height, absent for expiry without block inclusion.
        block_height: Option<u64>,
    },
}
/// Observed result of submitting and status-checking one locally signed mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryMutationSubmissionV1 {
    /// The payload transaction is applied.
    Applied {
        /// Locally derived payload transaction hash.
        transaction_hash: [u8; 32],
        /// Applied block height from authoritative state.
        block_height: u64,
    },
    /// The payload transaction has no authoritative terminal result yet.
    Pending {
        /// Locally derived payload transaction hash.
        transaction_hash: [u8; 32],
    },
    /// The payload transaction reached an authoritative negative terminal state.
    Terminal {
        /// Locally derived payload transaction hash.
        transaction_hash: [u8; 32],
        /// Terminal kind.
        kind: RegistryTerminalTransactionStateV1,
        /// Finalized rejection height, absent for expiry without block inclusion.
        block_height: Option<u64>,
    },
}
/// Stable, secret-redacted registry error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryErrorV1 {
    class: RegistryFailureClassV1,
    code: &'static str,
}
impl RegistryErrorV1 {
    const fn new(class: RegistryFailureClassV1, code: &'static str) -> Self {
        Self { class, code }
    }
    /// Return the retry classification without exposing transport or configuration detail.
    #[must_use]
    pub const fn class(&self) -> RegistryFailureClassV1 {
        self.class
    }
    /// Return the stable public error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
impl fmt::Display for RegistryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}
impl Error for RegistryErrorV1 {}

/// Resolve an explicit native configuration or the public configuration of the default wallet.
///
/// This selection does not load signing material. It is invoked only by consumers that need an
/// authenticated registry context; local graph and offline-cache paths remain independent.
pub(crate) fn selected_client_config_path_v1(
    explicit: Option<&Path>,
) -> Result<PathBuf, RegistryErrorV1> {
    select_client_config_path(explicit, || {
        let root = iroha_wallet::default_wallet_dir().map_err(|_| default_wallet_unavailable())?;
        default_wallet_config_at(&root)
    })
}

fn select_client_config_path(
    explicit: Option<&Path>,
    default: impl FnOnce() -> Result<PathBuf, RegistryErrorV1>,
) -> Result<PathBuf, RegistryErrorV1> {
    let path = match explicit {
        Some(path) => path.to_owned(),
        None => return default(),
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|_| invalid_public_config())
    }
}

fn default_wallet_config_at(root: &Path) -> Result<PathBuf, RegistryErrorV1> {
    // Selecting a missing wallet must not create custody while performing a registry read.
    if !root.is_dir() {
        return Err(default_wallet_unavailable());
    }
    iroha_wallet::WalletStore::open(root, None)
        .and_then(|store| store.config_path("default"))
        .map_err(|_| default_wallet_unavailable())
}

fn default_wallet_unavailable() -> RegistryErrorV1 {
    RegistryErrorV1::new(
        RegistryFailureClassV1::Permanent,
        "MUSUBI_DEFAULT_WALLET_UNAVAILABLE",
    )
}

/// Exact-network authenticated client for the fixed public Musubi V1 finalized-query inventory.
#[derive(Clone)]
pub struct RegistryReadClientV1 {
    client: AsyncClient,
    account: AccountClient,
    timeout: Duration,
    account_chain_discriminant: u16,
}
impl fmt::Debug for RegistryReadClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryReadClientV1")
            .field("authenticated", &true)
            .field("timeout", &self.timeout)
            .field(
                "account_chain_discriminant",
                &self.account_chain_discriminant,
            )
            .finish_non_exhaustive()
    }
}
/// One bounded platform configuration image shared by authenticated consumers in this process.
pub(crate) struct RegistryPublicConfigImageV1 {
    path: PathBuf,
    bytes: Vec<u8>,
}
/// Transient commitment to one exact platform configuration image and its anchored path.
///
/// This value is deliberately crate-private and has no codec implementation. It may bridge two
/// phases of one process, but must never enter a lockfile, publication journal, or diagnostic.
pub(crate) struct PlatformConfigProvenanceV1 {
    path: PathBuf,
    digest: [u8; 32],
}
impl fmt::Debug for PlatformConfigProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformConfigProvenanceV1")
            .field("bound", &true)
            .finish_non_exhaustive()
    }
}
impl PlatformConfigProvenanceV1 {
    /// Return the already-anchored path whose later image must match this commitment.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    /// Return whether `bytes` are exactly the image committed by this provenance value.
    pub(crate) fn matches(&self, bytes: &[u8]) -> bool {
        self.digest == platform_config_provenance_digest(bytes)
    }
}
impl fmt::Debug for RegistryPublicConfigImageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryPublicConfigImageV1")
            .field("byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl Drop for RegistryPublicConfigImageV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}
impl RegistryPublicConfigImageV1 {
    /// Read one anchored, bounded configuration image without constructing a signer or transport.
    pub(crate) fn load(config: Option<&Path>) -> Result<Self, RegistryErrorV1> {
        let path = selected_client_config_path_v1(config)?;
        let bytes = read_bounded_config(&path)?;
        Ok(Self { path, bytes })
    }
    /// Read only the public address profile needed to reproduce compiled package bytes.
    ///
    /// Account keys, endpoints, storage configuration and environment overrides are not inputs
    /// to this projection. Parsing errors remain redacted because the image can contain secrets.
    pub(crate) fn account_chain_discriminant(&self) -> Result<u16, RegistryErrorV1> {
        let source = std::str::from_utf8(&self.bytes).map_err(|_| invalid_public_config())?;
        let table = source
            .parse::<toml::Table>()
            .map_err(|_| invalid_public_config())?;
        let account = table
            .get("account")
            .and_then(toml::Value::as_table)
            .ok_or_else(invalid_public_config)?;
        let profile = account
            .get("profile")
            .map(|value| value.as_str().ok_or_else(invalid_public_config))
            .transpose()?;
        let explicit = account
            .get("chain_discriminant")
            .map(|value| {
                value
                    .as_integer()
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(invalid_public_config)
            })
            .transpose()?;
        iroha::config::resolve_account_chain_discriminant(profile, explicit)
            .map_err(|_| invalid_public_config())
    }
    /// Read the explicit exact deployment identity and public account-address profile.
    ///
    /// Offline registry selection uses this projection of the retained bounded image without
    /// loading a signer, endpoint, or cache. The network identity must use its canonical checked
    /// spelling; it has no default. Parsing failures disclose neither source text nor credentials.
    pub(crate) fn registry_binding(&self) -> Result<(NetworkId, u16), RegistryErrorV1> {
        let source = std::str::from_utf8(&self.bytes).map_err(|_| invalid_public_config())?;
        let table = source
            .parse::<toml::Table>()
            .map_err(|_| invalid_public_config())?;
        let network_id = match (table.get("network_id"), table.get("network_id_file")) {
            (Some(value), None) => value
                .as_str()
                .ok_or_else(invalid_public_config)?
                .parse::<NetworkId>()
                .map_err(|_| invalid_public_config())?,
            (None, Some(value)) => {
                let selected = value
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .ok_or_else(invalid_public_config)?;
                let selected = Path::new(selected);
                let path = if selected.is_absolute() {
                    selected.to_path_buf()
                } else {
                    self.path
                        .parent()
                        .ok_or_else(invalid_public_config)?
                        .join(selected)
                };
                // Match the platform's canonical public identity record: exactly one checked
                // identity followed by LF, with a 512-byte ceiling and no credential parsing.
                let bytes = crate::local_file::read_bounded_single_link_regular_file_v1(&path, 512)
                    .map_err(|_| invalid_public_config())?;
                let record = std::str::from_utf8(&bytes).map_err(|_| invalid_public_config())?;
                let text = record
                    .strip_suffix('\n')
                    .ok_or_else(invalid_public_config)?;
                let network = text
                    .parse::<NetworkId>()
                    .map_err(|_| invalid_public_config())?;
                if record != format!("{network}\n") {
                    return Err(invalid_public_config());
                }
                network
            }
            _ => return Err(invalid_public_config()),
        };
        Ok((network_id, self.account_chain_discriminant()?))
    }
    /// Return the original path used to resolve relative platform-owned files.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    /// Borrow the exact bounded bytes read from the selected configuration descriptor.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Commit this exact image without retaining its possibly secret-bearing bytes.
    pub(crate) fn provenance(&self) -> PlatformConfigProvenanceV1 {
        PlatformConfigProvenanceV1 {
            path: self.path.clone(),
            digest: platform_config_provenance_digest(&self.bytes),
        }
    }
}
fn platform_config_provenance_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PLATFORM_CONFIG_PROVENANCE_CONTEXT);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
impl RegistryReadClientV1 {
    /// Rebuild an authenticated reader from a borrowed exact-network Iroha client.
    ///
    /// The reader owns its validated account runtime and explicit deadline. The source client
    /// remains unchanged and need not outlive the reader.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not credential-free HTTP(S), the account key does not
    /// match the canonical single-signature account, the timeout is outside the one-minute bound,
    /// a legacy witness header is configured, or the chain discriminant is zero.
    pub fn new(
        client: &AsyncClient,
        timeout: Duration,
        account_chain_discriminant: u16,
    ) -> Result<Self, RegistryErrorV1> {
        if !matches!(client.endpoint().scheme(), "http" | "https")
            || !client.endpoint().username().is_empty()
            || client.endpoint().password().is_some()
            || timeout == Duration::ZERO
            || timeout > Duration::from_secs(60)
            || account_chain_discriminant == 0
            || client.account().controller.single_signatory()
                != Some(client.key_pair().public_key())
            || client
                .headers()
                .keys()
                .any(|name| name.eq_ignore_ascii_case("X-Iroha-Witness"))
        {
            return Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID",
            ));
        }
        let mut builder = client.to_builder();
        builder.torii_request_timeout = timeout;
        builder.account_chain_discriminant = account_chain_discriminant;
        let client = builder.build().map_err(|_| invalid_public_config())?;
        let account = client
            .account_client()
            .map_err(|_| invalid_public_config())?;
        let account = AccountClient::from_client(account).map_err(|_| invalid_public_config())?;
        Ok(Self {
            client,
            account,
            timeout,
            account_chain_discriminant,
        })
    }
    #[cfg(test)]
    pub(crate) fn new_for_test(
        torii_url: Url,
        timeout: Duration,
        account_chain_discriminant: u16,
    ) -> Result<Self, RegistryErrorV1> {
        Self::new(
            &Self::test_client_context(torii_url, timeout, account_chain_discriminant)?,
            timeout,
            account_chain_discriminant,
        )
    }
    /// Build a fixture context without creating a temporary blocking runtime.
    #[cfg(test)]
    fn test_client_context(
        torii_url: Url,
        timeout: Duration,
        account_chain_discriminant: u16,
    ) -> Result<AsyncClient, RegistryErrorV1> {
        let torii_url: String = torii_url.into();
        let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|_| invalid_public_config())?;
        let source = format!(
            r#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "{torii_url}"
torii_request_timeout_ms = {timeout_ms}

[account]
chain_discriminant = {account_chain_discriminant}
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
"#,
        );
        let (configuration, _) = Config::load_bytes_with_musubi_publication(
            Path::new("musubi-authenticated-test-client.toml"),
            source.as_bytes(),
        )
        .map_err(|_| invalid_public_config())?;
        AsyncClient::builder(configuration)
            .build()
            .map_err(|_| invalid_public_config())
    }
    /// Load the exact-network account signer from `--config` or the default developer wallet.
    ///
    /// The exact network identity, account, matching private key, Torii URL, timeout, and account
    /// profile are mandatory typed configuration. Default custody is the platform wallet named
    /// `default`; an implicit working-directory client file is never consulted. Command-line
    /// credential values are never accepted.
    ///
    /// # Errors
    ///
    /// Returns `MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID` on non-Unix targets before the selected
    /// absolute path is inspected. On Unix, returns an error when the bounded configuration cannot
    /// be read or its signer, exact network, endpoint, timeout, profile, or discriminant is invalid.
    pub fn load(config: Option<&Path>) -> Result<Self, RegistryErrorV1> {
        Self::load_with_config_image(config).map(|(reader, _image)| reader)
    }
    /// Load the authenticated reader and retain the exact same bounded image for sibling parsers.
    ///
    /// The returned image is transient configuration provenance. Callers must parse any required
    /// secret-free subtrees immediately and must not retain its raw bytes in resolver graphs.
    pub(crate) fn load_with_config_image(
        config: Option<&Path>,
    ) -> Result<(Self, RegistryPublicConfigImageV1), RegistryErrorV1> {
        let image = RegistryPublicConfigImageV1::load(config)?;
        let reader = Self::load_from_config_bytes(image.path(), image.bytes())?;
        Ok((reader, image))
    }
    /// Parse the exact-network signer and endpoint from one already-read `client.toml` image.
    ///
    /// Publication uses this entry point so the signer, private runtime client, and finalized
    /// registry reader all derive from the same bounded file image instead of reopening a path
    /// after authenticated storage coordination has started.
    pub(crate) fn load_from_config_bytes(
        path: &Path,
        bytes: &[u8],
    ) -> Result<Self, RegistryErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLIC_CONFIG_BYTES_USIZE {
            return Err(invalid_public_config());
        }
        let (configuration, _) = Config::load_bytes_with_musubi_publication(path, bytes)
            .map_err(|_| invalid_public_config())?;
        let timeout = configuration.torii_request_timeout;
        let account_chain_discriminant = configuration.account_chain_discriminant;
        Self::new(
            &AsyncClient::builder(configuration)
                .build()
                .map_err(|_| invalid_public_config())?,
            timeout,
            account_chain_discriminant,
        )
    }
    /// Return the configured authenticated endpoint without exposing signer material.
    #[must_use]
    pub fn torii_url(&self) -> &Url {
        self.client.endpoint()
    }
    /// Return the validated I105 account chain discriminant used by the request signer.
    #[must_use]
    pub const fn account_chain_discriminant(&self) -> u16 {
        self.account_chain_discriminant
    }
    /// Return the exact genesis identity used by authenticated registry reads.
    pub(crate) fn network_id(&self) -> NetworkId {
        *self.client.network_id()
    }
    /// Resolve canonical `namespace/package` text to its structural package identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the selector or authoritative prefix page is
    /// invalid, the query fails, or the exact package does not exist.
    pub fn resolve_selector(
        &self,
        selector: &MusubiPackageSelectorV1,
    ) -> Result<MusubiPackageIdV1, RegistryErrorV1> {
        selector.validate().map_err(|_| invalid_response())?;
        let prefix =
            MusubiOrderedPrefixV1::new(&selector.to_string()).map_err(|_| invalid_response())?;
        let page = self.ordered_prefix(&MusubiOrderedPrefixQueryV1 {
            prefix,
            page: first_page(2),
        })?;
        page.items
            .into_iter()
            .find(|entry| &entry.selector == selector)
            .map(|entry| entry.package)
            .ok_or_else(|| {
                RegistryErrorV1::new(RegistryFailureClassV1::NotFound, "MUSUBI_PACKAGE_NOT_FOUND")
            })
    }
    /// Bind a canonical selector through its immutable namespace even before first publication.
    ///
    /// Unlike [`Self::resolve_selector`], this queries the namespace directory prefix and does
    /// not require a package row to exist. This is the package/publication boundary for claiming
    /// a previously absent package under an already-registered namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the selector, namespace binding, or authoritative
    /// prefix page is invalid, or when the registry query fails.
    pub fn bind_selector_namespace(
        &self,
        selector: &MusubiPackageSelectorV1,
    ) -> Result<MusubiPackageIdV1, RegistryErrorV1> {
        selector.validate().map_err(|_| invalid_response())?;
        let prefix = MusubiOrderedPrefixV1::new(&format!("{}/", selector.namespace))
            .map_err(|_| invalid_response())?;
        let page = self.ordered_prefix(&MusubiOrderedPrefixQueryV1 {
            prefix,
            page: first_page(1),
        })?;
        package_id_from_namespace_binding(selector, &page.namespace_binding)
    }
    /// Fetch and validate one exact authoritative package record.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or a returned record is
    /// malformed or does not match the requested package.
    pub fn exact_package(
        &self,
        package: MusubiPackageIdV1,
    ) -> Result<Option<MusubiPackageRecordV1>, RegistryErrorV1> {
        optional_query_result(
            self.account
                .musubi()
                .exact_package(&MusubiExactPackageQueryV1 { package }),
        )
    }
    /// Fetch and validate one paired finalized home/universal release snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or a returned snapshot
    /// is malformed or does not match the requested release.
    pub fn exact_release(
        &self,
        release: MusubiReleaseIdV1,
    ) -> Result<Option<MusubiExactReleaseSnapshotV1>, RegistryErrorV1> {
        optional_query_result(
            self.account
                .musubi()
                .exact_release(&MusubiExactReleaseQueryV1 { release }),
        )
    }
    /// Fetch and validate one immutable finalized provider bundle-attestation audit record.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails, the record is malformed,
    /// its signature is invalid, or its key differs from the requested key.
    pub fn provider_bundle_attestation(
        &self,
        key: MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<MusubiProviderBundleAttestationRecordV1>, RegistryErrorV1> {
        optional_query_result(self.account.musubi().provider_bundle_attestation(&key))
    }
    /// Fetch and validate one finalized resolver-index page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or the page is not
    /// canonical for the supplied request.
    pub fn resolver_index(
        &self,
        request: &MusubiResolverIndexQueryV1,
    ) -> Result<MusubiResolverIndexPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().resolver_index(request))
    }
    /// Fetch and validate one finalized package-version page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or the page is not
    /// canonical for the supplied request.
    pub fn versions(
        &self,
        request: &MusubiPackagePageQueryV1,
    ) -> Result<MusubiVersionPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().versions(request))
    }
    /// Fetch and validate one finalized accepted-member and pending-invitation page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or the maintainer page is
    /// malformed or inconsistent with the supplied request.
    pub fn maintainers(
        &self,
        request: &MusubiPackagePageQueryV1,
    ) -> Result<MusubiMaintainerPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().maintainers(request))
    }
    /// Fetch and validate one finalized archive-location page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or a returned archive or
    /// location record is malformed or belongs to another archive.
    pub fn archive_locations(
        &self,
        request: &MusubiArchiveLocationQueryV1,
    ) -> Result<Option<MusubiArchiveLocationPageV1>, RegistryErrorV1> {
        optional_query_result(self.account.musubi().archive_locations(request))
    }
    /// Fetch and validate exact finalized cache-retention decisions for one bounded batch.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is invalid, the registry query fails,
    /// or the response snapshot or ordered decisions do not match the request.
    pub fn archive_retention(
        &self,
        request: &MusubiArchiveRetentionQueryV1,
    ) -> Result<MusubiArchiveRetentionPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().archive_retention(request))
    }
    /// Fetch and structurally validate one exact permanent alias record.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or a returned alias record
    /// is malformed or does not match the requested alias.
    pub fn alias(
        &self,
        request: &MusubiAliasQueryV1,
    ) -> Result<Option<MusubiAliasRecordV1>, RegistryErrorV1> {
        optional_query_result(self.account.musubi().alias(request))
    }
    /// Fetch and validate one finalized permanent-alias history page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or the page is not
    /// canonical for the supplied alias request.
    pub fn alias_history(
        &self,
        request: &MusubiAliasQueryV1,
    ) -> Result<MusubiAliasHistoryPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().alias_history(request))
    }
    /// Fetch and validate one finalized byte-ordered package-prefix page.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry query fails or the page is not
    /// canonical for the supplied ordered-prefix request.
    pub fn ordered_prefix(
        &self,
        request: &MusubiOrderedPrefixQueryV1,
    ) -> Result<MusubiOrderedPackagePageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().ordered_prefix(request))
    }
    /// Search the rebuildable finalized-event metadata projection by exact normalized terms.
    ///
    /// This discovery API is intentionally separate from [`Self::resolver_index`]; callers
    /// must resolve a selected structural package through the universal sparse index.
    ///
    /// # Errors
    ///
    /// Returns an error when the search request is invalid, the registry query
    /// fails, or the response is not canonical for the request.
    pub fn search(
        &self,
        request: &MusubiSearchQueryV1,
    ) -> Result<MusubiSearchPageV1, RegistryErrorV1> {
        required_query_result(self.account.musubi().search(request))
    }
}
/// Convert a completed typed query result without owning transport or decoding.
fn required_query_result<T>(response: iroha::Result<QueryResult<T>>) -> Result<T, RegistryErrorV1> {
    optional_query_result(response)?.ok_or_else(|| {
        RegistryErrorV1::new(
            RegistryFailureClassV1::NotFound,
            "MUSUBI_REGISTRY_RECORD_NOT_FOUND",
        )
    })
}
/// Preserve finalized absence/stale-cursor semantics and redact SDK errors.
fn optional_query_result<T>(
    response: iroha::Result<QueryResult<T>>,
) -> Result<Option<T>, RegistryErrorV1> {
    match response.map_err(|error| match error {
        iroha::Error::InvalidRequest {
            operation: "musubi.v1.query.archive_retention",
            ..
        } => RegistryErrorV1::new(
            RegistryFailureClassV1::Permanent,
            "MUSUBI_REGISTRY_RETENTION_REQUEST_INVALID",
        ),
        iroha::Error::InvalidRequest {
            operation: "musubi.v1.query.search",
            ..
        } => RegistryErrorV1::new(
            RegistryFailureClassV1::Permanent,
            "MUSUBI_REGISTRY_SEARCH_REQUEST_INVALID",
        ),
        iroha::Error::ResponseBinding { .. } | iroha::Error::InvalidRequest { .. } => {
            invalid_response()
        }
        _ => RegistryErrorV1::new(
            RegistryFailureClassV1::Retryable,
            "MUSUBI_REGISTRY_QUERY_FAILED",
        ),
    })? {
        QueryResult::Found(value) => Ok(Some(value)),
        QueryResult::NotFound => Ok(None),
        QueryResult::StaleCursor => Err(RegistryErrorV1::new(
            RegistryFailureClassV1::StaleCursor,
            "MUSUBI_REGISTRY_STALE_CURSOR",
        )),
    }
}
/// Client that loads a complete signer only at a registry mutation boundary.
#[derive(Clone)]
pub struct RegistrySigningClientV1 {
    client: Client,
    account_chain_discriminant: u16,
}
impl fmt::Debug for RegistrySigningClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        formatter
            .debug_struct("RegistrySigningClientV1")
            .field("authority", self.client.client().account())
            .field(
                "account_chain_discriminant",
                &self.account_chain_discriminant,
            )
            .finish_non_exhaustive()
    }
}
impl RegistrySigningClientV1 {
    /// Return the exact genesis-derived identity from the trusted signing configuration.
    #[must_use]
    pub(crate) fn network_id(&self) -> NetworkId {
        *self.client.client().network_id()
    }
    /// Clone an authenticated registry reader from this exact signing configuration.
    pub(crate) fn authenticated_reader(&self) -> Result<RegistryReadClientV1, RegistryErrorV1> {
        RegistryReadClientV1::new(
            self.client.client(),
            self.client.client().torii_request_timeout(),
            self.account_chain_discriminant,
        )
    }
    /// Load an explicit native configuration or the default developer wallet.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing configuration cannot be loaded or is invalid.
    pub fn load(config: Option<&Path>) -> Result<Self, RegistryErrorV1> {
        let image = RegistryPublicConfigImageV1::load(config)?;
        Self::load_with_publication_config_bytes(image.path(), image.bytes())
            .map(|(signer, _)| signer)
    }
    #[cfg(test)]
    pub(crate) fn load_with_publication_config(
        config: Option<&Path>,
    ) -> Result<(Self, iroha::config::MusubiPublicationConfig), RegistryErrorV1> {
        let image = RegistryPublicConfigImageV1::load(config)?;
        Self::load_with_publication_config_bytes(image.path(), image.bytes())
    }
    pub(crate) fn load_with_publication_config_bytes(
        path: &Path,
        bytes: &[u8],
    ) -> Result<(Self, iroha::config::MusubiPublicationConfig), RegistryErrorV1> {
        let (configuration, publication) = Config::load_bytes_with_musubi_publication(path, bytes)
            .map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Permanent,
                    "MUSUBI_REGISTRY_SIGNING_CONFIG_INVALID",
                )
            })?;
        Ok((Self::from_configuration(configuration)?, publication))
    }
    fn from_configuration(mut configuration: Config) -> Result<Self, RegistryErrorV1> {
        let account_chain_discriminant = configuration.account_chain_discriminant;
        configuration.torii_request_timeout = configuration
            .torii_request_timeout
            .min(Duration::from_secs(60));
        let client = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(account_chain_discriminant);
            Client::new(configuration).map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Permanent,
                    "MUSUBI_REGISTRY_SIGNING_CONFIG_INVALID",
                )
            })?
        };
        Ok(Self {
            client,
            account_chain_discriminant,
        })
    }
    /// Return the configured mutation authority.
    #[must_use]
    pub fn authority(&self) -> &iroha_data_model::account::AccountId {
        self.client.client().account()
    }
    /// Return the validated I105 account chain discriminant used by this signer.
    #[must_use]
    pub const fn account_chain_discriminant(&self) -> u16 {
        self.account_chain_discriminant
    }
    /// Construct the fixed private-publication HTTPS client from this signer.
    ///
    /// Only the chain, account, and key pair are copied. Torii Basic Auth and configured
    /// headers are deliberately excluded from the private publication service boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested timeout or the signer's configured
    /// publication-runtime endpoint cannot form a safe authenticated client.
    pub fn publication_runtime_client(
        &self,
        timeout: Duration,
    ) -> Result<
        iroha_musubi_service::AuthenticatedMusubiPublicationRuntimeClientV1,
        iroha_musubi_service::MusubiPublicationRuntimeTransportErrorV1,
    > {
        iroha_musubi_service::AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
            self.client.client(),
            timeout,
        )
    }
    /// Build the sole generated publication client from original TLS intent and this exact signer.
    /// Torii credentials and extra headers remain excluded by the lower client owner.
    /// # Errors
    /// Refuses changed original network, chain, endpoint, timeout or TLS material.
    pub(crate) fn generated_publication_runtime_client(
        &self,
        selection: iroha_musubi_service::GeneratedLocalPublicationTransportV1,
        timeout: Duration,
    ) -> Result<
        iroha_musubi_service::AuthenticatedMusubiPublicationRuntimeClientV1,
        iroha_musubi_service::MusubiPublicationRuntimeTransportErrorV1,
    > {
        iroha_musubi_service::AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_iroha_client(
            self.client.client(), selection, timeout,
        )
    }
    /// Parse one canonical account argument under the signing client's network profile.
    ///
    /// The scoped override is thread-local and is removed before returning. No key material is
    /// accepted, retained, or exposed by this method.
    ///
    /// # Errors
    ///
    /// Returns an error when `input` is not a canonical encoded account for the
    /// signer's configured chain discriminant.
    pub fn parse_account_id(
        &self,
        input: &str,
    ) -> Result<iroha_data_model::account::AccountId, RegistryErrorV1> {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        iroha_data_model::account::AccountId::parse_encoded(input).map_err(|_| {
            RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_ACCOUNT_ID_INVALID",
            )
        })
    }
    /// Sign, submit, and wait for commitment of one concrete V1 instruction.
    ///
    /// # Errors
    ///
    /// Returns an error when payload construction, fee quotation, signing,
    /// submission, or authoritative status validation fails, or when the
    /// transaction remains pending or reaches a terminal negative state.
    pub fn submit_v1<I>(&self, instruction: I) -> Result<[u8; 32], RegistryErrorV1>
    where
        I: Into<InstructionBox>,
    {
        match self.submit_observed_v1(instruction)? {
            RegistryMutationSubmissionV1::Applied {
                transaction_hash, ..
            } => Ok(transaction_hash),
            RegistryMutationSubmissionV1::Pending { .. } => Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Retryable,
                "MUSUBI_REGISTRY_TRANSACTION_PENDING",
            )),
            RegistryMutationSubmissionV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Expired,
                ..
            } => Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Retryable,
                "MUSUBI_REGISTRY_TRANSACTION_EXPIRED",
            )),
            RegistryMutationSubmissionV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Rejected,
                ..
            } => Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_REGISTRY_TRANSACTION_TERMINAL_FAILURE",
            )),
        }
    }
    pub(crate) fn submit_observed_v1<I>(
        &self,
        instruction: I,
    ) -> Result<RegistryMutationSubmissionV1, RegistryErrorV1>
    where
        I: Into<InstructionBox>,
    {
        let payload = self.prebuild_v1(instruction)?;
        let transaction = self.quote_and_sign_v1(payload)?;
        let transaction_hash = *transaction.hash().as_ref();
        let submission = self.submit_signed_v1(&transaction);
        if let Ok(observed_hash) = submission {
            validate_mutation_submission_hash(transaction_hash, observed_hash)?;
        }
        let state = match self.transaction_application_state_v1(&transaction) {
            Ok(state) => state,
            Err(status_error) => {
                return Err(match submission {
                    Err(submission_error)
                        if status_error.class() != RegistryFailureClassV1::Permanent =>
                    {
                        submission_error
                    }
                    _ => status_error,
                });
            }
        };
        match state {
            RegistryTransactionStateV1::Applied { block_height } => {
                Ok(RegistryMutationSubmissionV1::Applied {
                    transaction_hash,
                    block_height,
                })
            }
            RegistryTransactionStateV1::Pending => {
                Ok(RegistryMutationSubmissionV1::Pending { transaction_hash })
            }
            RegistryTransactionStateV1::Absent => match submission {
                Ok(_) => Ok(RegistryMutationSubmissionV1::Pending { transaction_hash }),
                Err(error) => Err(error),
            },
            RegistryTransactionStateV1::Terminal { kind, block_height } => {
                Ok(RegistryMutationSubmissionV1::Terminal {
                    transaction_hash,
                    kind,
                    block_height,
                })
            }
        }
    }
    /// Prebuild one exact unsigned V1 mutation payload without contacting Torii.
    ///
    /// # Errors
    ///
    /// Returns an error when the instruction cannot be converted into a valid
    /// transaction payload under the signer's configured chain context.
    pub fn prebuild_v1<I>(&self, instruction: I) -> Result<TransactionPayload, RegistryErrorV1>
    where
        I: Into<InstructionBox>,
    {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        let instruction: InstructionBox = instruction.into();
        self.client
            .account_client()
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [instruction],
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Permanent,
                    "MUSUBI_REGISTRY_TRANSACTION_BUILD_FAILED",
                )
            })
    }
    /// Fee-quote and sign the exact prebuilt payload without submitting it.
    ///
    /// # Errors
    ///
    /// Returns an error when fee quotation or local signing of the exact payload fails.
    pub fn quote_and_sign_v1(
        &self,
        mut payload: TransactionPayload,
    ) -> Result<SignedTransaction, RegistryErrorV1> {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        let quote = self
            .client
            .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
            .map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Retryable,
                    "MUSUBI_REGISTRY_TRANSACTION_QUOTE_OR_SIGN_FAILED",
                )
            })?;
        if !payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent)
        {
            return Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_REGISTRY_TRANSACTION_QUOTE_BINDING_FAILED",
            ));
        }
        payload.fee_payment = quote.intent;
        self.client
            .account_client()
            .sign_transaction(payload)
            .map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Permanent,
                    "MUSUBI_REGISTRY_TRANSACTION_QUOTE_OR_SIGN_FAILED",
                )
            })
    }
    /// Submit and wait for the exact already-signed V1 transaction without rebuilding it.
    ///
    /// # Errors
    ///
    /// Returns an error when submission or commitment waiting fails.
    pub fn submit_signed_v1(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<[u8; 32], RegistryErrorV1> {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        let hash = self
            .client
            .submit_transaction_and_wait(transaction)
            .map_err(|_| {
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Retryable,
                    "MUSUBI_REGISTRY_MUTATION_FAILED",
                )
            })?;
        Ok(*hash.as_ref())
    }
    pub(crate) fn transaction_application_state_v1(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<RegistryTransactionStateV1, RegistryErrorV1> {
        let _chain_discriminant = ChainDiscriminantGuard::enter(self.account_chain_discriminant);
        let response = self
            .client
            .client()
            .get_transaction_status_response(transaction.hash())
            .map_err(|error| match error.downcast_ref::<iroha::Error>() {
                Some(iroha::Error::ResponseBinding {
                    operation: "pipeline.transaction_status",
                    field: "hash",
                }) => RegistryErrorV1::new(
                    RegistryFailureClassV1::Permanent,
                    "MUSUBI_REGISTRY_TRANSACTION_STATUS_HASH_MISMATCH",
                ),
                _ => RegistryErrorV1::new(
                    RegistryFailureClassV1::Retryable,
                    "MUSUBI_REGISTRY_TRANSACTION_STATUS_FAILED",
                ),
            })?;
        let Some(response) = response else {
            return Ok(RegistryTransactionStateV1::Absent);
        };
        if response.hash != transaction.hash().to_string() {
            return Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_REGISTRY_TRANSACTION_STATUS_HASH_MISMATCH",
            ));
        }
        match response.status.kind.as_str() {
            "Applied" | "Rejected" | "Expired" if response.resolved_from != "state" => {
                Ok(RegistryTransactionStateV1::Pending)
            }
            "Applied" => response
                .status
                .block_height
                .filter(|height| *height > 0)
                .map(|block_height| RegistryTransactionStateV1::Applied { block_height })
                .ok_or_else(|| {
                    RegistryErrorV1::new(
                        RegistryFailureClassV1::Permanent,
                        "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID",
                    )
                }),
            "Queued" | "Approved" | "Committed" => Ok(RegistryTransactionStateV1::Pending),
            "Rejected" => response
                .status
                .block_height
                .filter(|height| *height > 0)
                .map(|block_height| RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Rejected,
                    block_height: Some(block_height),
                })
                .ok_or_else(|| {
                    RegistryErrorV1::new(
                        RegistryFailureClassV1::Permanent,
                        "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID",
                    )
                }),
            "Expired" => {
                if response.status.block_height == Some(0) {
                    return Err(RegistryErrorV1::new(
                        RegistryFailureClassV1::Permanent,
                        "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID",
                    ));
                }
                Ok(RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Expired,
                    block_height: response.status.block_height,
                })
            }
            _ => Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID",
            )),
        }
    }
}
fn validate_mutation_submission_hash(
    expected_hash: [u8; 32],
    observed_hash: [u8; 32],
) -> Result<(), RegistryErrorV1> {
    if observed_hash != expected_hash {
        return Err(RegistryErrorV1::new(
            RegistryFailureClassV1::Permanent,
            "MUSUBI_REGISTRY_TRANSACTION_HASH_MISMATCH",
        ));
    }
    Ok(())
}
/// Runtime-only production services whose authenticated server contracts are outside Torii reads.
pub trait PublicationRuntimeServicesV1 {
    /// Parse, verify, resolve, and compiler-check the exact clean package CAR.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when the package cannot be read or
    /// does not satisfy the exact validation and compiler-admission contract.
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError>;
    /// Stage bytes through an admitted authenticated seed-ingress broker and return its receipt.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when authenticated staging fails or
    /// the returned receipt cannot be bound to the expected ingress transcript.
    fn stage_authenticated_seed_ingress(
        &mut self,
        operation_id: PublicationOperationIdV1,
        expected: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &MusubiSeedIngressCarPlanV1,
        car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, PublicationBackendError>;
    /// Revalidate or append the durable provider-sidecar anchor before proof submission.
    ///
    /// # Errors
    ///
    /// Implementations return a classified backend error when provider
    /// registration evidence cannot be recovered or advanced safely.
    fn checkpoint_archive_location_provider_registrations(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _registered: &PublicationRegisteredArchiveV1,
        _generation: u8,
        _prior_location_ids: &[MusubiArchiveLocationIdV1],
        _checkpoint: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<PublicationProviderRegistrationCheckpointAdvanceV1, PublicationBackendError> {
        Ok(PublicationProviderRegistrationCheckpointAdvanceV1::Ready)
    }
    /// Coordinate and sign an exact location CAS without submitting it.
    ///
    /// The caller journals the returned transaction before invoking
    /// [`Self::submit_or_recover_archive_location`].
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when an exact location transaction
    /// cannot be coordinated, validated, or signed.
    fn prepare_archive_location_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationIntentV1, PublicationBackendError>;
    /// Submit or recover the exact journaled location transaction and finalized state.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when the journaled transaction cannot
    /// be submitted or reconciled with authoritative finalized state.
    fn submit_or_recover_archive_location(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        intent: &PublicationArchiveLocationIntentV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError>;
    /// Read, parse, and verify the complete archive through one finalized provider.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when provider readback fails or the
    /// returned archive differs from the finalized commitment.
    fn readback_provider(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        location: &MusubiArchiveLocationV1,
        provider: ProviderId,
    ) -> Result<PublicationReadbackEvidenceV1, PublicationBackendError>;
}
/// Fail-closed runtime used until an operator supplies all authenticated production services.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePublicationRuntimeV1;
impl PublicationRuntimeServicesV1 for UnavailablePublicationRuntimeV1 {
    fn validate_clean_package(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError> {
        Err(PublicationBackendError::permanent(
            "PACKAGE_VALIDATOR_NOT_CONFIGURED",
        ))
    }
    fn stage_authenticated_seed_ingress(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _expected: &MusubiSeedIngressReceiptBindingV1,
        _commitment: &MusubiArchiveCommitmentV1,
        _plan: &MusubiSeedIngressCarPlanV1,
        _car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, PublicationBackendError> {
        // This explicit fallback never probes Torii or the implemented private service. A
        // configured production runtime supplies that authenticated service client instead.
        Err(PublicationBackendError::permanent(
            "SEED_INGRESS_SERVICE_NOT_CONFIGURED",
        ))
    }
    fn prepare_archive_location_intent(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _registered: &PublicationRegisteredArchiveV1,
        _generation: u8,
        _prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationIntentV1, PublicationBackendError> {
        Err(PublicationBackendError::permanent(
            "STORAGE_COORDINATOR_NOT_CONFIGURED",
        ))
    }
    fn submit_or_recover_archive_location(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _registered: &PublicationRegisteredArchiveV1,
        _intent: &PublicationArchiveLocationIntentV1,
        _prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError> {
        Err(PublicationBackendError::permanent(
            "STORAGE_COORDINATOR_NOT_CONFIGURED",
        ))
    }
    fn readback_provider(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _registered: &PublicationRegisteredArchiveV1,
        _location: &MusubiArchiveLocationV1,
        _provider: ProviderId,
    ) -> Result<PublicationReadbackEvidenceV1, PublicationBackendError> {
        Err(PublicationBackendError::permanent(
            "PROVIDER_READBACK_NOT_CONFIGURED",
        ))
    }
}
/// Concrete publication backend combining finalized reads, local signing, and runtime services.
#[derive(Debug)]
pub struct RegistryPublicationBackendV1<S> {
    read: RegistryReadClientV1,
    signing: RegistrySigningClientV1,
    services: S,
    operation_id: PublicationOperationIdV1,
    publisher: iroha_data_model::account::AccountId,
}
impl<S> RegistryPublicationBackendV1<S> {
    /// Bind the backend to exactly one public request and operation id.
    ///
    /// # Errors
    ///
    /// Returns an error when the read and signing clients use different chain
    /// profiles or the signing authority differs from the request publisher.
    pub fn new(
        read: RegistryReadClientV1,
        signing: RegistrySigningClientV1,
        services: S,
        request: &PublicationRequestV1,
    ) -> Result<Self, RegistryErrorV1> {
        if read.account_chain_discriminant() != signing.account_chain_discriminant() {
            return Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_PUBLICATION_REGISTRY_PROFILE_MISMATCH",
            ));
        }
        if signing.authority() != &request.publisher {
            return Err(RegistryErrorV1::new(
                RegistryFailureClassV1::Permanent,
                "MUSUBI_PUBLICATION_AUTHORITY_MISMATCH",
            ));
        }
        Ok(Self {
            read,
            signing,
            services,
            operation_id: request.operation_id(),
            publisher: request.publisher.clone(),
        })
    }
    fn check_operation(
        &self,
        operation_id: PublicationOperationIdV1,
    ) -> Result<(), PublicationBackendError> {
        if operation_id == self.operation_id {
            Ok(())
        } else {
            Err(PublicationBackendError::permanent(
                "PUBLICATION_OPERATION_MISMATCH",
            ))
        }
    }
    fn check_request(&self, request: &PublicationRequestV1) -> Result<(), PublicationBackendError> {
        if request.operation_id() == self.operation_id && request.publisher == self.publisher {
            Ok(())
        } else {
            Err(PublicationBackendError::permanent(
                "PUBLICATION_REQUEST_MISMATCH",
            ))
        }
    }
    fn recover_registered_archive(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
        minimum_finalized_height: Option<u64>,
    ) -> Result<Option<PublicationRegisteredArchiveV1>, PublicationBackendError> {
        let query = MusubiArchiveLocationQueryV1 {
            archive_id: request.archive_commitment.archive_id(),
            page: first_page(
                u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1).expect("page maximum fits u32"),
            ),
        };
        let Some(page) = self
            .read
            .archive_locations(&query)
            .map_err(registry_backend_error)?
        else {
            return Ok(None);
        };
        if page.network_id != request.network_id() {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_REGISTRATION_CONFLICT",
            ));
        }
        if minimum_finalized_height.is_some_and(|height| page.snapshot.finalized_height < height) {
            return Ok(None);
        }
        let recovered = PublicationRegisteredArchiveV1 {
            finalized_transaction_hash: intent.transaction_hash,
            network_id: request.network_id,
            snapshot: page.snapshot,
            archive: page.archive,
        };
        recovered
            .validate_for(request, intent)
            .map_err(|_| PublicationBackendError::permanent("ARCHIVE_REGISTRATION_CONFLICT"))?;
        Ok(Some(recovered))
    }
    fn finalized_archive_absence(
        &self,
        request: &PublicationRequestV1,
        minimum_finalized_height: Option<u64>,
    ) -> Result<Option<PublicationArchiveAbsenceEvidenceV1>, PublicationBackendError> {
        let page = self
            .read
            .archive_retention(&MusubiArchiveRetentionQueryV1 {
                archive_ids: vec![request.archive_commitment.archive_id()],
                expected_snapshot: None,
            })
            .map_err(registry_backend_error)?;
        if page.network_id != request.network_id() {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_ABSENCE_NETWORK_CONFLICT",
            ));
        }
        if minimum_finalized_height.is_some_and(|height| page.snapshot.finalized_height < height) {
            return Ok(None);
        }
        let decision = page.items.into_iter().next().ok_or_else(|| {
            PublicationBackendError::permanent("ARCHIVE_ABSENCE_RESPONSE_INVALID")
        })?;
        if decision.disposition != MusubiArchiveRetentionDispositionV1::RetainUnknown {
            return Ok(None);
        }
        Ok(Some(PublicationArchiveAbsenceEvidenceV1 {
            network_id: request.network_id,
            snapshot: page.snapshot,
            finalized_time_ms: page.finalized_time_ms,
            decision,
        }))
    }
    fn finalized_release_absence(
        &self,
        request: &PublicationRequestV1,
        minimum_finalized_height: Option<u64>,
    ) -> Result<Option<PublicationReleaseAbsenceEvidenceV1>, PublicationBackendError> {
        let requirement = format!("={}", request.publication.manifest.release.version)
            .parse::<iroha_data_model::musubi::MusubiVersionReqV1>()
            .map_err(|_| PublicationBackendError::permanent("RELEASE_REQUIREMENT_INVALID"))?;
        let resolver_query = MusubiResolverIndexQueryV1 {
            package: request.publication.manifest.release.package.clone(),
            requirement: Some(requirement),
            page: first_page(1),
        };
        let resolver_page = self
            .read
            .resolver_index(&resolver_query)
            .map_err(registry_backend_error)?;
        if resolver_page.network_id != request.network_id() {
            return Err(PublicationBackendError::permanent(
                "RELEASE_FINALIZED_NETWORK_CONFLICT",
            ));
        }
        if minimum_finalized_height
            .is_some_and(|height| resolver_page.snapshot.finalized_height < height)
        {
            return Ok(None);
        }
        if !resolver_page.items.is_empty() {
            let Some(exact_release) = self
                .read
                .exact_release(request.publication.manifest.release.clone())
                .map_err(registry_backend_error)?
            else {
                return Err(PublicationBackendError::retryable(
                    "RELEASE_FINALIZED_SNAPSHOT_MOVED",
                ));
            };
            validate_finalized_release_snapshot_progress(
                resolver_page.snapshot,
                exact_release.snapshot,
            )?;
            validate_finalized_idempotent_release(request, &exact_release)?;
            // The authoritative status for this exact payload was checked before this lookup.
            // Core accepts a byte-identical same-publisher release replay as an idempotent no-op,
            // so keep the attempt live and let the existing location gate decide whether the
            // journaled bytes may be submitted again. Never synthesize transaction application.
            return Ok(None);
        }
        if resolver_page.next_cursor.is_some() {
            return Err(PublicationBackendError::permanent(
                "RELEASE_ABSENCE_RESPONSE_INVALID",
            ));
        }
        let retention_query = MusubiArchiveRetentionQueryV1 {
            archive_ids: vec![request.archive_commitment.archive_id()],
            expected_snapshot: Some(resolver_page.snapshot),
        };
        let retention_page = match self.read.archive_retention(&retention_query) {
            Ok(page) => page,
            Err(error) if error.class() == RegistryFailureClassV1::StaleCursor => {
                return Err(PublicationBackendError::retryable(
                    "RELEASE_ABSENCE_SNAPSHOT_MOVED",
                ));
            }
            Err(error) => return Err(registry_backend_error(error)),
        };
        let absence = PublicationReleaseAbsenceEvidenceV1 {
            resolver_page,
            retention_query,
            retention_page,
        };
        absence
            .validate_for(request)
            .map_err(|_| PublicationBackendError::permanent("RELEASE_ABSENCE_RESPONSE_INVALID"))?;
        Ok(Some(absence))
    }
    fn terminal_release_state(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
        kind: RegistryTerminalTransactionStateV1,
        block_height: Option<u64>,
    ) -> Result<PublicationReleaseSubmissionAdvanceV1, PublicationBackendError> {
        if block_height == Some(0) {
            return Err(PublicationBackendError::permanent(
                "RELEASE_SUBMISSION_TERMINAL_STATUS_INVALID",
            ));
        }
        let Some(absence) = self.finalized_release_absence(request, block_height)? else {
            return Ok(PublicationReleaseSubmissionAdvanceV1::Pending);
        };
        let terminal = match (kind, block_height) {
            (RegistryTerminalTransactionStateV1::Rejected, Some(block_height)) => {
                PublicationReleaseSubmissionTerminalV1::registry_rejected(
                    intent,
                    block_height,
                    absence,
                )
            }
            (RegistryTerminalTransactionStateV1::Rejected, None) => {
                return Err(PublicationBackendError::permanent(
                    "RELEASE_SUBMISSION_TERMINAL_STATUS_INVALID",
                ));
            }
            (RegistryTerminalTransactionStateV1::Expired, Some(block_height)) => {
                PublicationReleaseSubmissionTerminalV1::registry_expired(
                    intent,
                    block_height,
                    absence,
                )
            }
            (RegistryTerminalTransactionStateV1::Expired, None) => {
                let deadline = release_submission_valid_until_ms(intent).ok_or_else(|| {
                    PublicationBackendError::permanent("RELEASE_SUBMISSION_INTENT_INVALID")
                })?;
                if absence.retention_page.finalized_time_ms <= deadline {
                    return Ok(PublicationReleaseSubmissionAdvanceV1::Pending);
                }
                PublicationReleaseSubmissionTerminalV1::finalized_validity_window_elapsed(
                    intent, absence,
                )
            }
        };
        Ok(PublicationReleaseSubmissionAdvanceV1::Terminal(terminal))
    }
    fn finalized_validity_window_release_state(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
    ) -> Result<Option<PublicationReleaseSubmissionTerminalV1>, PublicationBackendError> {
        let Some(absence) = self.finalized_release_absence(request, None)? else {
            return Ok(None);
        };
        let deadline = release_submission_valid_until_ms(intent).ok_or_else(|| {
            PublicationBackendError::permanent("RELEASE_SUBMISSION_INTENT_INVALID")
        })?;
        if absence.retention_page.finalized_time_ms <= deadline {
            return Ok(None);
        }
        Ok(Some(
            PublicationReleaseSubmissionTerminalV1::finalized_validity_window_elapsed(
                intent, absence,
            ),
        ))
    }
    fn pending_release_state(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
    ) -> Result<PublicationReleaseSubmissionAdvanceV1, PublicationBackendError> {
        self.finalized_validity_window_release_state(request, intent)
            .map(|terminal| {
                terminal.map_or(
                    PublicationReleaseSubmissionAdvanceV1::Pending,
                    PublicationReleaseSubmissionAdvanceV1::Terminal,
                )
            })
    }
    fn terminal_registration_state(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
        kind: RegistryTerminalTransactionStateV1,
        block_height: Option<u64>,
    ) -> Result<PublicationArchiveRegistrationAdvanceV1, PublicationBackendError> {
        if block_height == Some(0) {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_REGISTRATION_TERMINAL_STATUS_INVALID",
            ));
        }
        if let Some(registered) = self.recover_registered_archive(request, intent, block_height)? {
            return Ok(PublicationArchiveRegistrationAdvanceV1::Registered(
                registered,
            ));
        }
        let Some(absence) = self.finalized_archive_absence(request, block_height)? else {
            return Ok(PublicationArchiveRegistrationAdvanceV1::Pending);
        };
        match kind {
            RegistryTerminalTransactionStateV1::Rejected => Err(
                PublicationBackendError::permanent("ARCHIVE_REGISTRATION_TRANSACTION_REJECTED"),
            ),
            RegistryTerminalTransactionStateV1::Expired => {
                Ok(PublicationArchiveRegistrationAdvanceV1::TerminalAbsent(
                    PublicationArchiveRegistrationTerminalV1::registry_expired(
                        intent,
                        block_height,
                        absence,
                    ),
                ))
            }
        }
    }
    fn finalized_validity_window_registration_state(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
    ) -> Result<PublicationArchiveRegistrationAdvanceV1, PublicationBackendError> {
        let Some(absence) = self.finalized_archive_absence(request, None)? else {
            return Ok(PublicationArchiveRegistrationAdvanceV1::Pending);
        };
        terminal_after_finalized_validity_window(request, intent, absence).map(|terminal| {
            terminal.map_or(
                PublicationArchiveRegistrationAdvanceV1::Pending,
                PublicationArchiveRegistrationAdvanceV1::TerminalAbsent,
            )
        })
    }
}
fn validate_finalized_idempotent_release(
    request: &PublicationRequestV1,
    exact_release: &MusubiExactReleaseSnapshotV1,
) -> Result<(), PublicationBackendError> {
    let manifest = &request.publication.manifest;
    let home = &exact_release.home_release;
    let universal = &exact_release.universal_release;
    let exact_query = MusubiExactReleaseQueryV1 {
        release: manifest.release.clone(),
    };
    if exact_release.validate_for(&exact_query).is_err()
        || exact_release.network_id != request.network_id()
        || &home.manifest != manifest
        || home.release_digest != manifest.release_digest()
        || universal.release != manifest.release
        || universal.release_digest != manifest.release_digest()
        || universal.archive_id != manifest.archive_id
        || universal.source_digest != request.archive_commitment.source_tree_digest
        || universal.interface_digest != manifest.interface_digest
        || universal.abi != manifest.abi
        || universal.dependencies != manifest.dependencies
    {
        return Err(PublicationBackendError::permanent(
            "RELEASE_FINALIZED_COMMITMENT_CONFLICT",
        ));
    }
    if home.published_by != request.publisher {
        return Err(PublicationBackendError::permanent(
            "RELEASE_FINALIZED_PUBLISHER_CONFLICT",
        ));
    }
    Ok(())
}
fn validate_finalized_release_snapshot_progress(
    resolver_snapshot: iroha_data_model::musubi::MusubiRegistrySnapshotV1,
    exact_snapshot: iroha_data_model::musubi::MusubiRegistrySnapshotV1,
) -> Result<(), PublicationBackendError> {
    if exact_snapshot.finalized_height == resolver_snapshot.finalized_height
        && exact_snapshot != resolver_snapshot
    {
        return Err(PublicationBackendError::permanent(
            "RELEASE_FINALIZED_SNAPSHOT_CONFLICT",
        ));
    }
    if exact_snapshot.finalized_height < resolver_snapshot.finalized_height
        || exact_snapshot.index_revision < resolver_snapshot.index_revision
    {
        return Err(PublicationBackendError::retryable(
            "RELEASE_FINALIZED_SNAPSHOT_MOVED",
        ));
    }
    Ok(())
}
fn terminal_after_finalized_validity_window(
    request: &PublicationRequestV1,
    intent: &PublicationArchiveRegistrationIntentV1,
    absence: PublicationArchiveAbsenceEvidenceV1,
) -> Result<Option<PublicationArchiveRegistrationTerminalV1>, PublicationBackendError> {
    absence
        .validate_for(request)
        .map_err(|_| PublicationBackendError::permanent("ARCHIVE_ABSENCE_RESPONSE_INVALID"))?;
    let valid_until_ms = archive_registration_intent_valid_until_ms(intent)
        .ok_or_else(|| PublicationBackendError::permanent("ARCHIVE_REGISTRATION_INTENT_INVALID"))?;
    if absence.finalized_time_ms <= valid_until_ms {
        return Ok(None);
    }
    let terminal = PublicationArchiveRegistrationTerminalV1::finalized_validity_window_elapsed(
        intent, absence,
    );
    terminal
        .validate_for(request, intent)
        .map_err(|_| PublicationBackendError::permanent("ARCHIVE_ABSENCE_RESPONSE_INVALID"))?;
    Ok(Some(terminal))
}
fn validate_registration_submission_hash(
    expected: [u8; 32],
    submitted: [u8; 32],
) -> Result<(), PublicationBackendError> {
    if submitted == expected {
        Ok(())
    } else {
        Err(PublicationBackendError::permanent(
            "ARCHIVE_REGISTRATION_TRANSACTION_HASH_MISMATCH",
        ))
    }
}
fn validate_release_submission_hash(
    expected: [u8; 32],
    submitted: [u8; 32],
) -> Result<(), PublicationBackendError> {
    if submitted == expected {
        Ok(())
    } else {
        Err(PublicationBackendError::permanent(
            "RELEASE_SUBMISSION_TRANSACTION_HASH_MISMATCH",
        ))
    }
}
fn submit_release_after_current_location_gate<T>(
    location_matches_signed_floor: bool,
    submit_exact_transaction: impl FnOnce() -> T,
) -> Option<T> {
    location_matches_signed_floor.then(submit_exact_transaction)
}
impl<S: PublicationRuntimeServicesV1> PublicationBackend for RegistryPublicationBackendV1<S> {
    fn current_time_ms(&mut self) -> Result<u64, PublicationBackendError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PublicationBackendError::permanent("SYSTEM_TIME_INVALID"))?;
        u64::try_from(elapsed.as_millis())
            .map_err(|_| PublicationBackendError::permanent("SYSTEM_TIME_INVALID"))
    }
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        self.services
            .validate_clean_package(operation_id, request, car)
    }
    fn stage_authenticated_seed_ingress(
        &mut self,
        operation_id: PublicationOperationIdV1,
        expected: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &MusubiSeedIngressCarPlanV1,
        car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.services.stage_authenticated_seed_ingress(
            operation_id,
            expected,
            commitment,
            plan,
            car,
        )
    }
    fn prepare_archive_registration_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        receipt: &MusubiSeedIngressReceiptV1,
    ) -> Result<PublicationArchiveRegistrationIntentV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        let instruction = request.archive_registration_instruction(receipt);
        let payload = self
            .signing
            .prebuild_v1(instruction)
            .map_err(registry_backend_error)?;
        let signed_transaction = self
            .signing
            .quote_and_sign_v1(payload)
            .map_err(registry_backend_error)?;
        Ok(PublicationArchiveRegistrationIntentV1::new(
            operation_id,
            request,
            receipt.clone(),
            signed_transaction,
        ))
    }
    fn submit_or_recover_archive_registration(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
    ) -> Result<PublicationArchiveRegistrationAdvanceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        intent
            .validate_for(operation_id, request, &intent.staging_receipt)
            .map_err(|_| {
                PublicationBackendError::permanent("ARCHIVE_REGISTRATION_INTENT_INVALID")
            })?;
        let initial_state = self
            .signing
            .transaction_application_state_v1(&intent.signed_transaction)
            .map_err(registry_backend_error)?;
        match initial_state {
            RegistryTransactionStateV1::Applied { block_height } => {
                return Ok(self
                    .recover_registered_archive(request, intent, Some(block_height))?
                    .map_or(
                        PublicationArchiveRegistrationAdvanceV1::Pending,
                        PublicationArchiveRegistrationAdvanceV1::Registered,
                    ));
            }
            RegistryTransactionStateV1::Pending => {
                return self.finalized_validity_window_registration_state(request, intent);
            }
            RegistryTransactionStateV1::Terminal { kind, block_height } => {
                return self.terminal_registration_state(request, intent, kind, block_height);
            }
            RegistryTransactionStateV1::Absent => {}
        }
        if let Some(registered) = self.recover_registered_archive(request, intent, None)? {
            return Ok(PublicationArchiveRegistrationAdvanceV1::Registered(
                registered,
            ));
        }
        if let terminal @ PublicationArchiveRegistrationAdvanceV1::TerminalAbsent(_) =
            self.finalized_validity_window_registration_state(request, intent)?
        {
            return Ok(terminal);
        }
        let submission = self.signing.submit_signed_v1(&intent.signed_transaction);
        if let Ok(transaction_hash) = submission {
            validate_registration_submission_hash(intent.transaction_hash, transaction_hash)?;
        }
        let observed_state = self
            .signing
            .transaction_application_state_v1(&intent.signed_transaction)
            .map_err(registry_backend_error)?;
        match observed_state {
            RegistryTransactionStateV1::Applied { block_height } => Ok(self
                .recover_registered_archive(request, intent, Some(block_height))?
                .map_or(
                    PublicationArchiveRegistrationAdvanceV1::Pending,
                    PublicationArchiveRegistrationAdvanceV1::Registered,
                )),
            RegistryTransactionStateV1::Pending => {
                self.finalized_validity_window_registration_state(request, intent)
            }
            RegistryTransactionStateV1::Terminal { kind, block_height } => {
                self.terminal_registration_state(request, intent, kind, block_height)
            }
            RegistryTransactionStateV1::Absent => {
                if let Some(registered) = self.recover_registered_archive(request, intent, None)? {
                    return Ok(PublicationArchiveRegistrationAdvanceV1::Registered(
                        registered,
                    ));
                }
                if let terminal @ PublicationArchiveRegistrationAdvanceV1::TerminalAbsent(_) =
                    self.finalized_validity_window_registration_state(request, intent)?
                {
                    return Ok(terminal);
                }
                match submission {
                    Ok(_) => Ok(PublicationArchiveRegistrationAdvanceV1::Pending),
                    Err(error) => Err(registry_backend_error(error)),
                }
            }
        }
    }
    fn checkpoint_archive_location_provider_registrations(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
        checkpoint: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<PublicationProviderRegistrationCheckpointAdvanceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        self.services
            .checkpoint_archive_location_provider_registrations(
                operation_id,
                request,
                registered,
                generation,
                prior_location_ids,
                checkpoint,
            )
    }
    fn prepare_archive_location_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationIntentV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        self.services.prepare_archive_location_intent(
            operation_id,
            request,
            registered,
            generation,
            prior_location_ids,
        )
    }
    fn submit_or_recover_archive_location(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        intent: &PublicationArchiveLocationIntentV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        self.services.submit_or_recover_archive_location(
            operation_id,
            request,
            registered,
            intent,
            prior_location_ids,
        )
    }
    fn finalized_replication(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<PublicationReplicationAdvanceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        let query = MusubiArchiveLocationQueryV1 {
            archive_id: request.archive_commitment.archive_id(),
            page: first_page(
                u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1).expect("page maximum fits u32"),
            ),
        };
        let Some(page) = self
            .read
            .archive_locations(&query)
            .map_err(registry_backend_error)?
        else {
            return Ok(PublicationReplicationAdvanceV1::Pending);
        };
        let registered_location = registration.location().map_err(|_| {
            PublicationBackendError::permanent("ARCHIVE_LOCATION_REGISTRATION_INVALID")
        })?;
        let location = page
            .items
            .iter()
            .find(|candidate| candidate.location_id == registration.location_id())
            .cloned();
        page.validate().map_err(|_| {
            PublicationBackendError::permanent("ARCHIVE_LOCATION_FINALIZED_PAGE_INVALID")
        })?;
        let registered_page = &registration.finalized_page;
        if (page.snapshot.finalized_height == registered_page.snapshot.finalized_height
            && page.snapshot != registered_page.snapshot)
            || (page.snapshot == registered_page.snapshot
                && (page.archive != registered_page.archive || page.items != registered_page.items))
            || (page.archive.location_revision == registered_page.archive.location_revision
                && (page.archive != registered_page.archive || page.items != registered_page.items))
        {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_FINALIZED_PAGE_INVALID",
            ));
        }
        if page.snapshot.finalized_height < registration.finalized_page.snapshot.finalized_height
            || page.snapshot.index_revision < registration.finalized_page.snapshot.index_revision
            || page.archive.location_revision
                < registration.finalized_page.archive.location_revision
            || location
                .as_ref()
                .is_some_and(|current| current.revision < registered_location.revision)
        {
            return Ok(PublicationReplicationAdvanceV1::Pending);
        }
        registration
            .validate_polled_page(request, &page)
            .map_err(|_| {
                PublicationBackendError::permanent("ARCHIVE_LOCATION_FINALIZED_PAGE_INVALID")
            })?;
        let registered = registration
            .intent
            .prepared_page
            .archive
            .registration_projection();
        if page.archive.registration_projection() != registered {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT",
            ));
        }
        if let Some(location) = location {
            return if location.state == MusubiArchiveLocationStateV1::Healthy
                && location.providers.len() >= usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1)
            {
                let checkpoint = PublicationReplicationCheckpointV1 {
                    finalized_page: page,
                };
                checkpoint
                    .validate_for(request, registration)
                    .map_err(|_| {
                        PublicationBackendError::permanent(
                            "ARCHIVE_LOCATION_FINALIZED_CHECKPOINT_INVALID",
                        )
                    })?;
                Ok(PublicationReplicationAdvanceV1::Healthy(checkpoint))
            } else {
                Ok(PublicationReplicationAdvanceV1::Pending)
            };
        }
        if page.snapshot.finalized_height <= registration.finalized_page.snapshot.finalized_height
            || page.archive.location_revision
                <= registration.finalized_page.archive.location_revision
        {
            return Ok(PublicationReplicationAdvanceV1::Pending);
        }
        Ok(PublicationReplicationAdvanceV1::Retired(
            PublicationArchiveLocationTerminalV1 {
                transaction_hash: registration.intent.transaction_hash,
                reason: PublicationArchiveLocationTerminalReasonV1::Retired,
                finalized_page: page,
            },
        ))
    }
    fn readback_provider(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        location: &MusubiArchiveLocationV1,
        provider: ProviderId,
    ) -> Result<PublicationReadbackEvidenceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        self.services
            .readback_provider(operation_id, request, registered, location, provider)
    }
    fn prepare_release_submission_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        preparation: &PublicationReleasePreparationFloorV1,
    ) -> Result<PublicationReleaseSubmissionIntentV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        let payload = self
            .signing
            .prebuild_v1(request.publish_instruction())
            .map_err(registry_backend_error)?;
        let signed_transaction = self
            .signing
            .quote_and_sign_v1(payload)
            .map_err(registry_backend_error)?;
        PublicationReleaseSubmissionIntentV1::try_new(
            operation_id,
            request,
            preparation.clone(),
            &signed_transaction,
        )
        .map_err(|_| PublicationBackendError::permanent("RELEASE_SUBMISSION_INTENT_INVALID"))
    }
    fn submit_or_recover_release_submission(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
        allow_absent_submission: bool,
    ) -> Result<PublicationReleaseSubmissionAdvanceV1, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        let signed_transaction = intent
            .reconstruct_signed_transaction(operation_id, request)
            .map_err(|_| PublicationBackendError::permanent("RELEASE_SUBMISSION_INTENT_INVALID"))?;
        let initial_state = self
            .signing
            .transaction_application_state_v1(&signed_transaction)
            .map_err(registry_backend_error)?;
        match initial_state {
            RegistryTransactionStateV1::Applied { block_height } => {
                return Ok(PublicationReleaseSubmissionAdvanceV1::Applied(
                    PublicationAmxSubmissionV1::new(
                        operation_id,
                        &request.publish_instruction(),
                        intent.transaction_hash,
                        block_height,
                    ),
                ));
            }
            RegistryTransactionStateV1::Pending => {
                return self.pending_release_state(request, intent);
            }
            RegistryTransactionStateV1::Terminal { kind, block_height } => {
                return self.terminal_release_state(request, intent, kind, block_height);
            }
            RegistryTransactionStateV1::Absent => {}
        }
        if let Some(terminal) = self.finalized_validity_window_release_state(request, intent)? {
            return Ok(PublicationReleaseSubmissionAdvanceV1::Terminal(terminal));
        }
        let Some(submission) =
            submit_release_after_current_location_gate(allow_absent_submission, || {
                self.signing.submit_signed_v1(&signed_transaction)
            })
        else {
            return Ok(PublicationReleaseSubmissionAdvanceV1::Pending);
        };
        if let Ok(transaction_hash) = submission {
            validate_release_submission_hash(intent.transaction_hash, transaction_hash)?;
        }
        let observed_state = self
            .signing
            .transaction_application_state_v1(&signed_transaction)
            .map_err(registry_backend_error)?;
        match observed_state {
            RegistryTransactionStateV1::Applied { block_height } => Ok(
                PublicationReleaseSubmissionAdvanceV1::Applied(PublicationAmxSubmissionV1::new(
                    operation_id,
                    &request.publish_instruction(),
                    intent.transaction_hash,
                    block_height,
                )),
            ),
            RegistryTransactionStateV1::Pending => self.pending_release_state(request, intent),
            RegistryTransactionStateV1::Terminal { kind, block_height } => {
                self.terminal_release_state(request, intent, kind, block_height)
            }
            RegistryTransactionStateV1::Absent => {
                if let Some(terminal) =
                    self.finalized_validity_window_release_state(request, intent)?
                {
                    return Ok(PublicationReleaseSubmissionAdvanceV1::Terminal(terminal));
                }
                match submission {
                    Ok(_) => Ok(PublicationReleaseSubmissionAdvanceV1::Pending),
                    Err(error) => Err(registry_backend_error(error)),
                }
            }
        }
    }
    fn finalized_release_and_index(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        submission: &PublicationAmxSubmissionV1,
    ) -> Result<Option<PublicationFinalEvidenceV1>, PublicationBackendError> {
        self.check_operation(operation_id)?;
        self.check_request(request)?;
        let release_id = request.publication.manifest.release.clone();
        let Some(exact_release) = self
            .read
            .exact_release(release_id)
            .map_err(registry_backend_error)?
        else {
            return Ok(None);
        };
        if exact_release.network_id != request.network_id() {
            return Err(PublicationBackendError::permanent(
                "RELEASE_FINALIZED_NETWORK_CONFLICT",
            ));
        }
        if exact_release.snapshot.finalized_height < submission.applied_height {
            return Ok(None);
        }
        Ok(Some(PublicationFinalEvidenceV1 {
            network_id: request.network_id,
            snapshot: exact_release.snapshot,
            home_release: exact_release.home_release,
            universal_release: exact_release.universal_release,
        }))
    }
}
/// Bounded polling policy for finalized replication and release verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationPollPolicyV1 {
    /// Total calls, including the initial attempt.
    pub max_attempts: u8,
    /// Delay after the first pending or retryable result.
    pub initial_delay: Duration,
    /// Maximum exponential-backoff delay.
    pub max_delay: Duration,
}
impl Default for PublicationPollPolicyV1 {
    fn default() -> Self {
        Self {
            max_attempts: 12,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(5),
        }
    }
}
impl PublicationPollPolicyV1 {
    /// Validate non-zero bounded attempts and sub-minute delays.
    ///
    /// # Errors
    ///
    /// Returns an error when the attempt count is zero, either delay is zero,
    /// the maximum is shorter than the initial delay, or it exceeds 30 seconds.
    pub fn validate(self) -> Result<(), PublicationError> {
        if self.max_attempts == 0
            || self.initial_delay == Duration::ZERO
            || self.max_delay < self.initial_delay
            || self.max_delay > Duration::from_secs(30)
        {
            return Err(PublicationError::InvalidJournal(
                "publication polling policy is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}
/// Resume with bounded exponential backoff, preserving pending state when the budget expires.
///
/// # Errors
///
/// Returns an error when the polling policy is invalid, publication fails permanently, all attempts
/// end in a retryable backend error, or no observable result is produced.
pub fn resume_with_bounded_polling(
    engine: &PublicationEngine<'_>,
    operation_id: PublicationOperationIdV1,
    source: &dyn PublicationCarSource,
    backend: &mut dyn PublicationBackend,
    policy: PublicationPollPolicyV1,
) -> Result<PublicationAdvanceV1, PublicationError> {
    policy.validate()?;
    let mut delay = policy.initial_delay;
    let mut last_pending = None;
    let mut last_retryable = None;
    for attempt in 0..policy.max_attempts {
        match engine.resume(operation_id, source, backend) {
            Ok(PublicationAdvanceV1::Pending(phase)) => {
                last_pending = Some(PublicationAdvanceV1::Pending(phase));
                last_retryable = None;
            }
            Ok(result) => return Ok(result),
            Err(PublicationError::Backend(error))
                if error.class() == PublicationBackendFailureClass::Retryable =>
            {
                last_pending = None;
                last_retryable = Some(error);
            }
            Err(error) => return Err(error),
        }
        if attempt + 1 < policy.max_attempts {
            thread::sleep(delay);
            delay = delay.saturating_mul(2).min(policy.max_delay);
        }
    }
    last_retryable.map_or_else(
        || {
            last_pending.ok_or_else(|| {
                PublicationError::InvalidJournal(
                    "publication polling completed without an observable result".to_owned(),
                )
            })
        },
        |error| Err(PublicationError::Backend(error)),
    )
}
fn first_page(limit: u32) -> MusubiPageRequestV1 {
    MusubiPageRequestV1 {
        limit,
        cursor: None,
    }
}
fn invalid_response() -> RegistryErrorV1 {
    RegistryErrorV1::new(
        RegistryFailureClassV1::Permanent,
        "MUSUBI_REGISTRY_RESPONSE_INVALID",
    )
}
fn package_id_from_namespace_binding(
    selector: &MusubiPackageSelectorV1,
    binding: &MusubiNamespaceBindingV1,
) -> Result<MusubiPackageIdV1, RegistryErrorV1> {
    selector.validate().map_err(|_| invalid_response())?;
    binding.validate().map_err(|_| invalid_response())?;
    if selector.namespace != binding.namespace {
        return Err(invalid_response());
    }
    let package = MusubiPackageIdV1::new(
        binding.home_dataspace,
        binding.scope.clone(),
        selector.name.clone(),
    );
    package.validate().map_err(|_| invalid_response())?;
    Ok(package)
}
#[cfg(test)]
fn validate_maintainer_page(
    request: &MusubiPackagePageQueryV1,
    page: &MusubiMaintainerPageV1,
) -> Result<(), RegistryErrorV1> {
    page.validate_for(request).map_err(|_| invalid_response())
}
fn invalid_public_config() -> RegistryErrorV1 {
    RegistryErrorV1::new(
        RegistryFailureClassV1::Permanent,
        "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID",
    )
}
fn registry_backend_error(error: RegistryErrorV1) -> PublicationBackendError {
    match error.class() {
        RegistryFailureClassV1::Retryable => PublicationBackendError::retryable(error.code()),
        RegistryFailureClassV1::Permanent
        | RegistryFailureClassV1::NotFound
        | RegistryFailureClassV1::StaleCursor => PublicationBackendError::permanent(error.code()),
    }
}
fn read_bounded_config(path: &Path) -> Result<Vec<u8>, RegistryErrorV1> {
    read_bounded_platform_config_v1(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::NotFound {
            "MUSUBI_REGISTRY_CONFIG_NOT_FOUND"
        } else {
            "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
        };
        RegistryErrorV1::new(RegistryFailureClassV1::Permanent, code)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{
        PublicationReleaseSignedEnvelopeV1, PublicationReleaseSubmissionTerminalReasonV1,
    };
    use iroha::crypto::{Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair, SignatureOf};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        isi::{InstructionBox, musubi::AddMusubiArchiveLocationV1},
        musubi::{
            ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiArchiveAvailabilityV1,
            MusubiArchiveCommitmentV1, MusubiArchiveRecordV1, MusubiArchiveRetentionDecisionV1,
            MusubiArchiveRetentionDispositionV1, MusubiArchiveRetentionPageV1,
            MusubiArchiveRetentionQueryV1, MusubiArtifactGovernanceStateV1, MusubiContentDigestV1,
            MusubiInvitationStateV1, MusubiInviteIdV1, MusubiKotodamaEditionV1,
            MusubiMaintainerDirectoryEntryV1, MusubiMaintainerInvitationV1,
            MusubiNamespaceBindingDigestV1, MusubiNamespaceV1, MusubiPackageMemberV1,
            MusubiPackageRecordV1, MusubiPackageRevisionsV1, MusubiPackageRoleV1,
            MusubiPackageScopeV1, MusubiProviderBundleAttestationSetDigestV1, MusubiPublicationV1,
            MusubiReasonV1, MusubiRegistrySnapshotV1, MusubiReleaseIdV1, MusubiReleaseManifestV1,
            MusubiReleaseMetadataV1, MusubiReleaseRecordV1, MusubiReleaseRevisionsV1,
            MusubiReleaseSelectionStateV1, MusubiReleaseYankV1, MusubiResolutionProofV1,
            MusubiResolverReleaseRowV1, MusubiSearchPageRequestV1,
            MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptPayloadV1,
            MusubiSemanticReleaseDigestV1, MusubiStorageAvailabilityV1, MusubiVerificationLockV1,
            MusubiVersionV1,
        },
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid, ReplicationOrderId,
        },
        transaction::{Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder},
    };
    use iroha_model_base::topology::DataSpaceId;
    use std::{cell::Cell, io::Write as _, net::TcpListener, time::Duration};
    use tempfile::tempdir;
    fn test_network_id(byte: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([byte; Hash::LENGTH]),
        ))
    }

    #[test]
    fn explicit_registry_config_never_consults_default_custody() {
        let temporary = tempdir().unwrap();
        let absolute = temporary.path().join("explicit.toml");
        assert_eq!(
            selected_client_config_path_v1(Some(&absolute)).unwrap(),
            absolute
        );
        let relative = Path::new("explicit-client.toml");
        let selected = select_client_config_path(Some(relative), || {
            panic!("explicit configuration must not inspect default custody")
        })
        .unwrap();
        assert_eq!(selected, std::env::current_dir().unwrap().join(relative));
    }

    #[test]
    fn registry_wallet_selection_reads_only_validated_public_identity() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("wallets");
        let store = iroha_wallet::WalletStore::open(&root, None).unwrap();
        let network = iroha_wallet::WalletNetwork::new(
            test_network_id(0x61),
            "fc56984b-2be7-431d-840e-21514d1883f0".into(),
            "https://taira.sora.org/".parse().unwrap(),
            369,
        )
        .unwrap();
        let info = store.create("default", &network).unwrap();
        fs::remove_file(info.config_path.parent().unwrap().join("private.key")).unwrap();
        let path = select_client_config_path(None, || default_wallet_config_at(&root)).unwrap();
        assert_eq!(path, info.config_path);
        let image = RegistryPublicConfigImageV1::load(Some(&path)).unwrap();
        assert_eq!(image.registry_binding().unwrap(), (network.network_id, 369));
        assert!(RegistrySigningClientV1::load(Some(&path)).is_err());
        let missing = temporary.path().join("absent-custody");
        assert_eq!(
            default_wallet_config_at(&missing).unwrap_err().code(),
            "MUSUBI_DEFAULT_WALLET_UNAVAILABLE"
        );
        assert!(
            !missing.exists(),
            "registry selection must not create custody"
        );
        fs::write(&info.config_path, "substituted-public-context").unwrap();
        assert_eq!(
            default_wallet_config_at(&root).unwrap_err().code(),
            "MUSUBI_DEFAULT_WALLET_UNAVAILABLE"
        );
    }
    /// Bind a simulated reader to a fixture's independently selected exact network.
    fn read_client_on_network(
        url: Url,
        timeout: Duration,
        discriminant: u16,
        network_id: NetworkId,
    ) -> Result<RegistryReadClientV1, RegistryErrorV1> {
        let source = RegistryReadClientV1::test_client_context(url, timeout, discriminant)?;
        let mut builder = source.to_builder();
        builder.network_id = network_id;
        RegistryReadClientV1::new(
            &builder.build().map_err(|_| invalid_public_config())?,
            timeout,
            discriminant,
        )
    }
    fn authenticated_reader_config(url: &str) -> String {
        let signer = KeyPair::try_from_seed(vec![0x59; 32], Algorithm::Ed25519)
            .expect("authenticated reader key");
        format!(
            r#"
chain = "musubi-registry-test"
network_id = "{}"
torii_url = "{url}"
torii_request_timeout_ms = 2000

[account]
profile = "taira"
public_key = "{}"
private_key = "{}"
"#,
            test_network_id(0x15),
            signer.public_key(),
            ExposedPrivateKey(signer.private_key().clone()),
        )
    }
    fn serve_http_once(
        status: &'static str,
        response: Vec<u8>,
    ) -> (Url, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one query connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2_048];
            let (header_end, content_length) = loop {
                let read = stream.read(&mut buffer).expect("read query request");
                assert_ne!(read, 0, "query request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).expect("HTTP headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                break (header_end + 4, content_length);
            };
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).expect("read query body");
                assert_ne!(read, 0, "query request ended before its body");
                request.extend_from_slice(&buffer[..read]);
            }
            let request_body = request[header_end..header_end + content_length].to_vec();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
            request_body
        });
        (
            format!("http://{address}/").parse().expect("loopback URL"),
            server,
        )
    }
    fn serve_json_once(response: Vec<u8>) -> (Url, thread::JoinHandle<Vec<u8>>) {
        serve_http_once("200 OK", response)
    }
    #[derive(Debug)]
    struct HttpRequestCapture {
        path: String,
        body: Vec<u8>,
    }
    fn serve_http_sequence(
        responses: Vec<(&'static str, Vec<u8>)>,
    ) -> (Url, thread::JoinHandle<Vec<HttpRequestCapture>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let server = thread::spawn(move || {
            let mut request_bodies = Vec::with_capacity(responses.len());
            for (status, response) in responses {
                let (mut stream, _) = listener.accept().expect("query connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2_048];
                let (header_end, content_length, path) = loop {
                    let read = stream.read(&mut buffer).expect("read query request");
                    assert_ne!(read, 0, "query request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers =
                        std::str::from_utf8(&request[..header_end]).expect("HTTP headers");
                    let path = headers
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .expect("HTTP request path")
                        .to_owned();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                        .unwrap_or(0);
                    break (header_end + 4, content_length, path);
                };
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut buffer).expect("read query body");
                    assert_ne!(read, 0, "query request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                }
                request_bodies.push(HttpRequestCapture {
                    path,
                    body: request[header_end..header_end + content_length].to_vec(),
                });
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .expect("write response headers");
                stream.write_all(&response).expect("write response body");
            }
            request_bodies
        });
        (
            format!("http://{address}/").parse().expect("loopback URL"),
            server,
        )
    }
    fn retention_page(
        archive_ids: &[ArchiveId],
        snapshot: MusubiRegistrySnapshotV1,
    ) -> MusubiArchiveRetentionPageV1 {
        MusubiArchiveRetentionPageV1 {
            network_id: test_network_id(0x81),
            items: archive_ids
                .iter()
                .map(|archive_id| MusubiArchiveRetentionDecisionV1 {
                    archive_id: *archive_id,
                    disposition: MusubiArchiveRetentionDispositionV1::RetainUnknown,
                    active_releases: 0,
                    yanked_releases: 0,
                    taken_down_releases: 0,
                    storage: None,
                })
                .collect(),
            snapshot,
            finalized_time_ms: 1_700_000_000_000,
        }
    }
    #[test]
    fn archive_retention_client_binds_snapshot_and_exact_item_order() {
        let archive_ids = vec![ArchiveId::new([0x11; 32]), ArchiveId::new([0x22; 32])];
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 7,
            finalized_block_hash: [0x71; 32],
            index_revision: 9,
        };
        let request = MusubiArchiveRetentionQueryV1 {
            archive_ids: archive_ids.clone(),
            expected_snapshot: Some(snapshot),
        };
        let valid = retention_page(&archive_ids, snapshot);
        let (url, server) =
            serve_json_once(norito::json::to_vec(&valid).expect("retention page JSON"));
        let client =
            read_client_on_network(url, Duration::from_secs(2), 753, test_network_id(0x81))
                .expect("authenticated registry client");
        assert_eq!(
            client
                .archive_retention(&request)
                .expect("exact retention response"),
            valid
        );
        server.join().expect("query server");
        let mut stale = retention_page(&archive_ids, snapshot);
        stale.snapshot.finalized_height += 1;
        stale.snapshot.finalized_block_hash = [0x72; 32];
        let (url, server) = serve_json_once(norito::json::to_vec(&stale).expect("stale page JSON"));
        let client =
            read_client_on_network(url, Duration::from_secs(2), 753, test_network_id(0x81))
                .expect("authenticated registry client");
        assert_eq!(
            client
                .archive_retention(&request)
                .expect_err("snapshot mismatch must fail closed")
                .code(),
            "MUSUBI_REGISTRY_RESPONSE_INVALID"
        );
        server.join().expect("query server");
        let mismatched_ids = vec![archive_ids[0], ArchiveId::new([0x33; 32])];
        let mismatched = retention_page(&mismatched_ids, snapshot);
        let (url, server) = serve_json_once(
            norito::json::to_vec(&mismatched).expect("mismatched retention page JSON"),
        );
        let client =
            read_client_on_network(url, Duration::from_secs(2), 753, test_network_id(0x81))
                .expect("authenticated registry client");
        assert_eq!(
            client
                .archive_retention(&request)
                .expect_err("item mismatch must fail closed")
                .code(),
            "MUSUBI_REGISTRY_RESPONSE_INVALID"
        );
        server.join().expect("query server");
        let reversed = retention_page(&[archive_ids[1], archive_ids[0]], snapshot);
        let (url, server) =
            serve_json_once(norito::json::to_vec(&reversed).expect("reversed page JSON"));
        let client =
            read_client_on_network(url, Duration::from_secs(2), 753, test_network_id(0x81))
                .expect("authenticated registry client");
        assert_eq!(
            client
                .archive_retention(&request)
                .expect_err("noncanonical item order must fail closed")
                .code(),
            "MUSUBI_REGISTRY_RESPONSE_INVALID"
        );
        server.join().expect("query server");
    }
    #[test]
    fn archive_retention_rejects_an_invalid_request_before_network_io() {
        let client = RegistryReadClientV1::new_for_test(
            "http://127.0.0.1:9/".parse().expect("loopback URL"),
            Duration::from_secs(1),
            753,
        )
        .expect("authenticated reader");
        let error = client
            .archive_retention(&MusubiArchiveRetentionQueryV1 {
                archive_ids: Vec::new(),
                expected_snapshot: None,
            })
            .expect_err("invalid retention request must fail before transport");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_RETENTION_REQUEST_INVALID");
    }
    #[cfg(unix)]
    #[test]
    fn public_config_image_loads_an_address_profile_without_credentials() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let source = "torii_url = false\n[account]\nprofile = 'taira'\n\
                      public_key = 'not-a-key'\nprivate_key = 'not-a-key'\n";
        fs::write(&path, source).expect("write signer-free configuration");
        let image = RegistryPublicConfigImageV1::load(Some(&path))
            .expect("read bounded image without parsing credentials");
        fs::remove_file(&path).expect("remove original configuration after capturing its image");
        assert_eq!(image.bytes(), source.as_bytes());
        assert_eq!(
            image.account_chain_discriminant().expect("public profile"),
            369
        );
        assert_eq!(
            RegistryReadClientV1::load_from_config_bytes(image.path(), image.bytes())
                .expect_err("authenticated access still requires valid signer configuration")
                .code(),
            "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
        );
    }
    #[cfg(unix)]
    #[test]
    fn public_registry_binding_uses_the_retained_image_without_signer_or_endpoint() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("public.toml");
        let network_id = test_network_id(0x15);
        for profile in ["profile = 'taira'", "chain_discriminant = 369"] {
            let source = format!("network_id = '{network_id}'\n[account]\n{profile}\n");
            fs::write(&path, &source).expect("write public binding");
            let image = RegistryPublicConfigImageV1::load(Some(&path)).expect("bounded image");
            fs::remove_file(&path).expect("remove original configuration");
            let binding = image
                .registry_binding()
                .expect("signer-free registry binding");
            assert_eq!(binding, (network_id, 369));
            assert_eq!(image.bytes(), source.as_bytes());
            assert_eq!(binding.0.to_string(), network_id.to_string());
        }
    }
    #[cfg(unix)]
    #[test]
    fn public_registry_binding_supports_bounded_canonical_relative_identity_files() {
        let temporary = tempdir().expect("public binding directory");
        let path = temporary.path().join("client.toml");
        let identity_path = temporary.path().join("network.id");
        let network = test_network_id(0x28);
        fs::write(
            &path,
            "network_id_file = 'network.id'\n[account]\nprofile = 'taira'\n",
        )
        .expect("public configuration");
        let image = RegistryPublicConfigImageV1::load(Some(&path)).expect("retained configuration");
        fs::write(&identity_path, format!("{network}\n")).expect("canonical identity record");
        assert_eq!(
            image.registry_binding().expect("relative public record"),
            (network, 369)
        );
        for record in [
            network.to_string(),
            format!("{network}\r\n"),
            format!("{network}\n{network}\n"),
            "x".repeat(513),
        ] {
            fs::write(&identity_path, record).expect("invalid identity record");
            assert_eq!(
                image
                    .registry_binding()
                    .expect_err("record rejected")
                    .code(),
                "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
            );
        }
        fs::write(&identity_path, format!("{network}\n")).expect("restore canonical record");
        let link = temporary.path().join("alias.id");
        std::os::unix::fs::symlink(&identity_path, &link).expect("symbolic identity alias");
        fs::write(
            &path,
            "network_id_file = 'alias.id'\n[account]\nprofile = 'taira'\n",
        )
        .expect("linked identity config");
        assert!(
            RegistryPublicConfigImageV1::load(Some(&path))
                .expect("config image")
                .registry_binding()
                .is_err()
        );
        fs::write(&path, format!("network_id = '{network}'\nnetwork_id_file = 'network.id'\n[account]\nprofile = 'taira'\n")).expect("ambiguous identity config");
        assert!(
            RegistryPublicConfigImageV1::load(Some(&path))
                .expect("config image")
                .registry_binding()
                .is_err()
        );
    }
    #[test]
    fn public_registry_binding_rejects_missing_or_invalid_identity_without_disclosure() {
        let network_id = test_network_id(0x15).to_string();
        let invalid_sources = [
            "[account]\nprofile = 'taira'\n".to_owned(),
            "network_id = 369\n[account]\nprofile = 'taira'\n".to_owned(),
            "network_id = 'secret-invalid-network'\n[account]\nprofile = 'taira'\n".to_owned(),
            format!(
                "network_id = '{}'\n[account]\nprofile = 'taira'\n",
                "15".repeat(32)
            ),
            format!(
                "network_id = '{}'\n[account]\nprofile = 'taira'\n",
                test_network_id(0xab).to_string().to_lowercase()
            ),
            format!("network_id = '{network_id}'\n[account]\nprofile = 'secret-invalid-profile'\n"),
            format!(
                "network_id = '{network_id}'\n[account]\nprofile = 'taira'\nchain_discriminant = 753\n"
            ),
            format!("network_id = '{network_id}'\n"),
            "network_id = 'unterminated-secret\n".to_owned(),
        ];
        for source in invalid_sources {
            let image = RegistryPublicConfigImageV1 {
                path: PathBuf::from("must-not-be-opened-secret.toml"),
                bytes: source.as_bytes().to_vec(),
            };
            let error = image
                .registry_binding()
                .expect_err("invalid public binding");
            assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
            assert_eq!(error.code(), "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID");
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("secret"));
                assert!(!rendered.contains(&network_id));
                assert!(!rendered.contains(&source));
            }
        }
        let image = RegistryPublicConfigImageV1 {
            path: PathBuf::from("must-not-be-opened-secret.toml"),
            bytes: vec![0xff],
        };
        assert_eq!(
            image
                .registry_binding()
                .expect_err("UTF-8 is required")
                .code(),
            "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
        );
    }
    #[test]
    fn public_address_projection_enforces_the_canonical_profile_rules() {
        for (source, expected) in [
            ("[account]\n", None),
            ("[account]\nprofile = ''\n", None),
            ("[account]\nprofile = 'taira'\n", Some(369)),
            ("[account]\nprofile = 'minamoto'\n", Some(753)),
            ("[account]\nchain_discriminant = 753\n", Some(753)),
            (
                "[account]\nprofile = 'taira'\nchain_discriminant = 369\n",
                Some(369),
            ),
            (
                "[account]\nprofile = 'taira'\nchain_discriminant = 753\n",
                None,
            ),
            ("[account]\nprofile = 'unknown-profile'\n", None),
            ("[account]\nprofile = 369\n", None),
            ("[account]\nchain_discriminant = '753'\n", None),
            ("[account]\nchain_discriminant = 0\n", None),
            ("[account]\nchain_discriminant = -1\n", None),
            ("[account]\nchain_discriminant = 65536\n", None),
            ("[account]\nchain_discriminant = 753.0\n", None),
            ("account = 'not-a-table'\n", None),
            ("", None),
            ("[account", None),
        ] {
            let image = RegistryPublicConfigImageV1 {
                path: PathBuf::from("must-not-be-opened.toml"),
                bytes: source.as_bytes().to_vec(),
            };
            match (image.account_chain_discriminant(), expected) {
                (Ok(actual), Some(expected)) => assert_eq!(actual, expected, "{source}"),
                (Err(error), None) => {
                    assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
                    assert_eq!(error.code(), "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID");
                }
                (actual, expected) => panic!("unexpected public profile: {actual:?}, {expected:?}"),
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn authenticated_config_image_loads_one_exact_signer_and_redacts_it() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let source = authenticated_reader_config("https://registry.example/iroha/");
        fs::write(&path, &source).expect("write authenticated config fixture");
        let (client, image) = RegistryReadClientV1::load_with_config_image(Some(&path))
            .expect("load signer and exact bounded image");
        assert_eq!(
            client.network_id(),
            image.registry_binding().expect("public identity").0
        );
        assert_eq!(
            client.torii_url().as_str(),
            "https://registry.example/iroha/"
        );
        assert_eq!(client.account_chain_discriminant(), 369);
        let same_bytes = fs::read(&path).expect("read the selected config image");
        assert_eq!(image.path(), path.as_path());
        assert_eq!(image.bytes(), same_bytes.as_slice());
        let provenance = image.provenance();
        assert_eq!(provenance.path(), path.as_path());
        assert!(provenance.matches(&same_bytes));
        let mut changed_bytes = same_bytes.clone();
        changed_bytes.push(b'\n');
        assert!(!provenance.matches(&changed_bytes));
        let image_debug = format!("{image:?}");
        assert!(!image_debug.contains(&source));
        assert!(!image_debug.contains(path.to_string_lossy().as_ref()));
        let client_debug = format!("{client:?}");
        assert!(!client_debug.contains("private_key"));
        assert!(!client_debug.contains("ed0120"));
        let provenance_debug = format!("{provenance:?}");
        assert!(!provenance_debug.contains(&source));
        assert!(!provenance_debug.contains(path.to_string_lossy().as_ref()));
        assert!(
            !provenance_debug
                .contains(&hex::encode(platform_config_provenance_digest(&same_bytes)))
        );
        let from_bytes = RegistryReadClientV1::load_from_config_bytes(&path, &same_bytes)
            .expect("load authenticated context from the already-read image");
        assert_eq!(from_bytes.torii_url(), client.torii_url());
        assert_eq!(
            from_bytes.account_chain_discriminant(),
            client.account_chain_discriminant()
        );
    }
    #[test]
    fn authenticated_config_requires_network_context_without_changing_universal_identity() {
        let path = Path::new("authenticated-reader-network-context-test.toml");
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking refusal observer");
        let url = format!(
            "http://{}/",
            listener.local_addr().expect("loopback address")
        );
        let source = authenticated_reader_config(&url);
        let reader = RegistryReadClientV1::load_from_config_bytes(path, source.as_bytes())
            .expect("explicit account network profile");
        let signer = KeyPair::try_from_seed(vec![0x59; 32], Algorithm::Ed25519)
            .expect("authenticated reader key");
        assert_eq!(
            reader.client.account(),
            &AccountId::new(signer.public_key().clone())
        );
        let explicit = source.replace("profile = \"taira\"", "chain_discriminant = 369");
        assert_ne!(source, explicit);
        let other = RegistryReadClientV1::load_from_config_bytes(path, explicit.as_bytes())
            .expect("equivalent explicit discriminant for the same universal account");
        assert_eq!(reader.client.account(), other.client.account());
        assert_eq!(reader.client.network_id(), other.client.network_id());
        assert_eq!(reader.account_chain_discriminant(), 369);
        assert_eq!(other.account_chain_discriminant(), 369);
        for invalid in [
            source.replace("[account]", "[account]\ndomain = \"packages.universal\""),
            source.replace("profile = \"taira\"\n", ""),
            source.replace("profile = \"taira\"", "profile = \" \""),
            source.replace(
                "torii_request_timeout_ms = 2000",
                "torii_request_timeout_ms = 60001",
            ),
        ] {
            assert_ne!(source, invalid);
            let error = RegistryReadClientV1::load_from_config_bytes(path, invalid.as_bytes())
                .expect_err(
                    "retired account scope, missing network context, or excessive deadline must fail before dispatch",
                );
            assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
            assert_eq!(error.code(), "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID");
        }
        let retry = RegistryReadClientV1::load_from_config_bytes(path, source.as_bytes())
            .expect("the same original bytes remain valid after rejected configurations");
        assert_eq!(retry.client.account(), reader.client.account());
        assert_eq!(retry.client.network_id(), reader.client.network_id());
        assert_eq!(retry.account_chain_discriminant(), 369);
        assert_eq!(
            listener
                .accept()
                .expect_err("configuration validation must not dispatch HTTP")
                .kind(),
            std::io::ErrorKind::WouldBlock,
        );
    }
    #[cfg(unix)]
    #[test]
    fn authenticated_config_rejects_missing_and_foreign_account_keys_before_dispatch() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let valid = authenticated_reader_config("http://127.0.0.1:9/");
        let missing = valid
            .lines()
            .filter(|line| !line.trim_start().starts_with("private_key ="))
            .collect::<Vec<_>>()
            .join("\n");
        let foreign = KeyPair::try_from_seed(vec![0x5A; 32], Algorithm::Ed25519)
            .expect("foreign account key");
        let foreign_private = ExposedPrivateKey(foreign.private_key().clone()).to_string();
        let mismatched = valid
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("private_key =") {
                    format!("private_key = \"{foreign_private}\"")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        for source in [missing, mismatched] {
            fs::write(&path, source).expect("write rejected authenticated config");
            let error = RegistryReadClientV1::load_with_config_image(Some(&path))
                .expect_err("missing or foreign signer must fail before dispatch");
            assert_eq!(error.code(), "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID");
        }
    }
    #[cfg(unix)]
    #[test]
    fn public_config_image_rejects_symbolic_and_hard_links() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        fs::write(
            &path,
            authenticated_reader_config("https://registry.example/iroha/"),
        )
        .expect("write authenticated config fixture");
        let symbolic = temporary.path().join("symbolic.toml");
        symlink(&path, &symbolic).expect("create symbolic link");
        assert_eq!(
            RegistryReadClientV1::load_with_config_image(Some(&symbolic))
                .expect_err("symbolic configuration must fail closed")
                .code(),
            "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
        );
        let hard = temporary.path().join("hard.toml");
        fs::hard_link(&path, &hard).expect("create hard link");
        for linked in [&path, &hard] {
            assert_eq!(
                RegistryReadClientV1::load_with_config_image(Some(linked))
                    .expect_err("multiply linked configuration must fail closed")
                    .code(),
                "MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn public_config_image_anchors_a_relative_selection_once() {
        let current = std::env::current_dir().expect("current directory");
        let temporary =
            tempfile::tempdir_in(&current).expect("workspace-local temporary directory");
        let path = temporary.path().join("client.toml");
        fs::write(
            &path,
            authenticated_reader_config("https://registry.example/iroha/"),
        )
        .expect("write authenticated config fixture");
        let relative = path
            .strip_prefix(&current)
            .expect("temporary path is below current directory");
        let (_, image) = RegistryReadClientV1::load_with_config_image(Some(relative))
            .expect("load relative public configuration");
        assert!(image.path().is_absolute());
        assert_eq!(image.path(), path.as_path());
    }
    #[test]
    fn missing_public_config_never_creates_its_parent() {
        let parent = tempdir().expect("temporary parent");
        let path = parent.path().join("must-remain-absent/client.toml");
        let error = RegistryReadClientV1::load_with_config_image(Some(&path))
            .expect_err("missing public configuration must fail closed");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_CONFIG_NOT_FOUND");
        assert!(!path.parent().expect("requested path has a parent").exists());
    }
    #[test]
    fn search_rejects_an_invalid_request_before_network_io() {
        let client = RegistryReadClientV1::new_for_test(
            "http://127.0.0.1:9/".parse().expect("loopback URL"),
            Duration::from_secs(1),
            753,
        )
        .expect("authenticated reader");
        let error = client
            .search(&MusubiSearchQueryV1 {
                query: String::new(),
                page: MusubiSearchPageRequestV1 {
                    limit: 50,
                    cursor: None,
                },
            })
            .expect_err("invalid search must fail before transport");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_SEARCH_REQUEST_INVALID");
    }
    #[test]
    fn signing_client_parses_account_arguments_under_its_taira_profile() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let signer_keypair = KeyPair::try_from_seed(vec![89; 32], Algorithm::Ed25519)
            .expect("signer fixture key pair");
        let private_key = ExposedPrivateKey(signer_keypair.private_key().clone()).to_string();
        let network_id = test_network_id(0x15);
        fs::write(
            &path,
            format!(
                r#"
                    chain = "musubi-registry-test"
                    network_id = "{network_id}"
                    torii_url = "https://registry.example/iroha/"
                    [account]
                    profile = "taira"
                    public_key = "{}"
                    private_key = "{}"
                "#,
                signer_keypair.public_key(),
                private_key,
            ),
        )
        .expect("write signing config fixture");
        let signing = RegistrySigningClientV1::load(Some(&path)).expect("load Taira signer");
        assert_eq!(signing.account_chain_discriminant(), 369);
        assert!(!format!("{signing:?}").contains(&private_key));
        let expected = account(90);
        let taira_literal = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            expected.canonical_i105().expect("Taira account literal")
        };
        assert_eq!(
            signing
                .parse_account_id(&taira_literal)
                .expect("Taira account argument"),
            expected
        );
        let default_literal = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(753);
            expected.canonical_i105().expect("default-network literal")
        };
        let error = signing
            .parse_account_id(&default_literal)
            .expect_err("another network's account literal must be rejected");
        assert_eq!(error.code(), "MUSUBI_ACCOUNT_ID_INVALID");
    }
    fn signing_client_at(
        url: &Url,
        signer_keypair: &KeyPair,
        network_id: NetworkId,
    ) -> RegistrySigningClientV1 {
        let temporary = tempdir().expect("temporary signing configuration");
        let path = temporary.path().join("client.toml");
        let private_key = ExposedPrivateKey(signer_keypair.private_key().clone()).to_string();
        fs::write(
            &path,
            format!(
                r#"
                    chain = "musubi-registry-test"
                    network_id = "{network_id}"
                    torii_url = "{url}"
                    [account]
                    profile = "taira"
                    public_key = "{}"
                    private_key = "{}"
                "#,
                signer_keypair.public_key(),
                private_key,
            ),
        )
        .expect("write signing client fixture");
        RegistrySigningClientV1::load(Some(&path)).expect("load signing client fixture")
    }
    fn signed_status_probe(signer: &KeyPair) -> SignedTransaction {
        let authority = AccountId::new(signer.public_key().clone());
        let mut builder = TransactionBuilder::new(
            test_network_id(0x15),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(Vec::<InstructionBox>::new());
        builder.set_creation_time(Duration::from_millis(900));
        builder.sign(signer.private_key())
    }
    fn transaction_status_body_for_hash(hash: &str, kind: &str) -> Vec<u8> {
        norito::json::to_vec(&norito::json!({
            "hash": hash,
            "status": { "kind": kind, "block_height": 44 },
            "scope": "global",
            "resolved_from": "state",
        }))
        .expect("transaction status JSON")
    }
    fn transaction_status_body(transaction: &SignedTransaction, kind: &str) -> Vec<u8> {
        transaction_status_body_for_hash(&transaction.hash().to_string(), kind)
    }
    /// Torii's typed HTTP 404 body establishing global status absence for exactly one hash.
    ///
    /// A bare 404, for example from a misrouted proxy, never establishes absence.
    fn transaction_status_absence_body_for_hash(hash: &str) -> Vec<u8> {
        norito::json::to_vec(&norito::json!({
            "code": "pipeline_transaction_status_not_found",
            "message": "Missing status.",
            "details": {
                "pipeline_transaction_status_not_found": {
                    "hash": hash,
                    "scope": "global",
                },
            },
        }))
        .expect("transaction status absence JSON")
    }
    #[test]
    fn signing_client_maps_applied_and_pending_transaction_statuses_over_http() {
        let signer = KeyPair::try_from_seed(vec![92; 32], Algorithm::Ed25519)
            .expect("status signer fixture");
        let transaction = signed_status_probe(&signer);
        for (kind, expected) in [
            (
                "Applied",
                RegistryTransactionStateV1::Applied { block_height: 44 },
            ),
            ("Queued", RegistryTransactionStateV1::Pending),
        ] {
            let (url, server) = serve_json_once(transaction_status_body(&transaction, kind));
            let signing = signing_client_at(&url, &signer, test_network_id(0x15));
            assert_eq!(
                signing
                    .transaction_application_state_v1(&transaction)
                    .expect("typed transaction status"),
                expected
            );
            server.join().expect("status server");
        }
    }
    #[test]
    fn signing_client_maps_rejected_and_absent_transaction_statuses_over_http() {
        let signer = KeyPair::try_from_seed(vec![93; 32], Algorithm::Ed25519)
            .expect("status signer fixture");
        let transaction = signed_status_probe(&signer);
        let (url, server) = serve_json_once(transaction_status_body(&transaction, "Rejected"));
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        let state = signing
            .transaction_application_state_v1(&transaction)
            .expect("state-final rejected transaction");
        assert_eq!(
            state,
            RegistryTransactionStateV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Rejected,
                block_height: Some(44),
            }
        );
        server.join().expect("rejected status server");
        let (url, server) = serve_http_once(
            "404 Not Found",
            transaction_status_absence_body_for_hash(&transaction.hash().to_string()),
        );
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        assert_eq!(
            signing
                .transaction_application_state_v1(&transaction)
                .expect("absent status response"),
            RegistryTransactionStateV1::Absent
        );
        server.join().expect("absent status server");
        let other = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::new(b"other"));
        for body in [
            Vec::new(),
            transaction_status_absence_body_for_hash(&other.to_string()),
        ] {
            let (url, server) = serve_http_once("404 Not Found", body);
            let signing = signing_client_at(&url, &signer, test_network_id(0x15));
            assert_eq!(
                signing
                    .transaction_application_state_v1(&transaction)
                    .expect_err("an unbound 404 never establishes absence"),
                RegistryErrorV1::new(
                    RegistryFailureClassV1::Retryable,
                    "MUSUBI_REGISTRY_TRANSACTION_STATUS_FAILED",
                )
            );
            server.join().expect("unbound absence server");
        }
    }
    #[test]
    fn signing_client_requires_state_finality_and_height_for_terminal_statuses() {
        let signer = KeyPair::try_from_seed(vec![97; 32], Algorithm::Ed25519)
            .expect("status signer fixture");
        let transaction = signed_status_probe(&signer);
        let transaction_hash = transaction.hash().to_string();
        let cached_rejection_hash = transaction_hash.clone();
        let cached_rejection = norito::json::to_vec(&norito::json!({
            "hash": cached_rejection_hash,
            "status": { "kind": "Rejected", "block_height": 44 },
            "scope": "global",
            "resolved_from": "cache",
        }))
        .expect("cached rejection JSON");
        let (url, server) = serve_json_once(cached_rejection);
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        assert_eq!(
            signing
                .transaction_application_state_v1(&transaction)
                .expect("non-authoritative rejection remains pending"),
            RegistryTransactionStateV1::Pending
        );
        server.join().expect("cached rejection server");
        let cached_applied_hash = transaction_hash.clone();
        let cached_applied = norito::json::to_vec(&norito::json!({
            "hash": cached_applied_hash,
            "status": { "kind": "Applied", "block_height": 44 },
            "scope": "global",
            "resolved_from": "cache",
        }))
        .expect("cached Applied JSON");
        let (url, server) = serve_json_once(cached_applied);
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        assert_eq!(
            signing
                .transaction_application_state_v1(&transaction)
                .expect("non-authoritative Applied remains pending"),
            RegistryTransactionStateV1::Pending
        );
        server.join().expect("cached Applied server");
        let heightless_applied_hash = transaction_hash.clone();
        let heightless_applied = norito::json::to_vec(&norito::json!({
            "hash": heightless_applied_hash,
            "status": { "kind": "Applied" },
            "scope": "global",
            "resolved_from": "state",
        }))
        .expect("heightless applied JSON");
        let (url, server) = serve_json_once(heightless_applied);
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        let error = signing
            .transaction_application_state_v1(&transaction)
            .expect_err("applied status without committed height is not finality evidence");
        assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
        assert_eq!(error.code(), "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID");
        server.join().expect("heightless applied server");
        let (url, server) = serve_json_once(transaction_status_body(&transaction, "Expired"));
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        assert_eq!(
            signing
                .transaction_application_state_v1(&transaction)
                .expect("state-final expiry"),
            RegistryTransactionStateV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Expired,
                block_height: Some(44),
            }
        );
        server.join().expect("state-final expiry server");
        let zero_height_expiry = norito::json::to_vec(&norito::json!({
            "hash": transaction_hash,
            "status": { "kind": "Expired", "block_height": 0 },
            "scope": "global",
            "resolved_from": "state",
        }))
        .expect("zero-height expiry JSON");
        let (url, server) = serve_json_once(zero_height_expiry);
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        let error = signing
            .transaction_application_state_v1(&transaction)
            .expect_err("zero is not a valid finalized block height");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_TRANSACTION_STATUS_INVALID");
        server.join().expect("zero-height expiry server");
    }
    #[test]
    fn signing_client_rejects_a_status_response_for_another_transaction() {
        let signer = KeyPair::try_from_seed(vec![96; 32], Algorithm::Ed25519)
            .expect("status signer fixture");
        let transaction = signed_status_probe(&signer);
        let (url, server) = serve_json_once(transaction_status_body_for_hash(
            &"ff".repeat(32),
            "Applied",
        ));
        let signing = signing_client_at(&url, &signer, test_network_id(0x15));
        let error = signing
            .transaction_application_state_v1(&transaction)
            .expect_err("another transaction's applied status must fail closed");
        assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
        assert_eq!(
            error.code(),
            "MUSUBI_REGISTRY_TRANSACTION_STATUS_HASH_MISMATCH"
        );
        server.join().expect("wrong-hash status server");
    }
    #[test]
    fn mutation_submission_hash_must_match_the_locally_signed_transaction() {
        validate_mutation_submission_hash([0x41; 32], [0x41; 32])
            .expect("matching signed transaction hash");
        let error = validate_mutation_submission_hash([0x41; 32], [0x42; 32])
            .expect_err("substituted submission hash");
        assert_eq!(error.class(), RegistryFailureClassV1::Permanent);
        assert_eq!(error.code(), "MUSUBI_REGISTRY_TRANSACTION_HASH_MISMATCH");
    }
    #[test]
    fn public_queries_decode_accounts_with_the_configured_discriminant() {
        let expected = account(91);
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "discriminant-fixture".parse().expect("package name"),
        );
        let request = MusubiPackagePageQueryV1 {
            package: package.clone(),
            page: first_page(10),
        };
        let expected_page = MusubiMaintainerPageV1 {
            query: request.clone(),
            items: vec![MusubiMaintainerDirectoryEntryV1::Accepted(
                MusubiPackageMemberV1 {
                    package,
                    account: expected.clone(),
                    role: MusubiPackageRoleV1::Owner,
                    accepted_at_height: 2,
                    governance_revision: 3,
                },
            )],
            next_cursor: None,
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 5,
                finalized_block_hash: [6; 32],
                index_revision: 7,
            },
        };
        expected_page
            .validate_for(&request)
            .expect("canonical maintainer page");
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&expected_page).expect("maintainer response JSON")
        };
        let (url, server) = serve_json_once(response);
        let client = RegistryReadClientV1::new_for_test(url, Duration::from_secs(2), 369)
            .expect("Taira registry reader");
        // The cloned reader retains its account runtime after the original facade is dropped.
        let retained = client.clone();
        drop(client);
        let actual_page = retained
            .maintainers(&request)
            .expect("configured discriminant applies during response decoding");
        assert_eq!(actual_page, expected_page);
        let [MusubiMaintainerDirectoryEntryV1::Accepted(member)] = actual_page.items.as_slice()
        else {
            panic!("one accepted maintainer must be returned");
        };
        let actual = member.account.clone();
        assert_eq!(actual, expected);
        let body = server.join().expect("query server");
        let sent: MusubiPackagePageQueryV1 =
            norito::json::from_slice(&body).expect("typed query body");
        assert_eq!(sent, request);
    }
    #[test]
    fn reader_rebuild_binds_explicit_timeout_and_discriminant_without_mutating_source() {
        let source = RegistryReadClientV1::new_for_test(
            "http://127.0.0.1:1".parse().expect("test endpoint"),
            Duration::from_secs(2),
            753,
        )
        .expect("source reader");
        let reader = RegistryReadClientV1::new(&source.client, Duration::from_secs(3), 369)
            .expect("reader with explicit network formatting and deadline");
        assert_eq!(reader.client.account_chain_discriminant(), 369);
        assert_eq!(
            reader.client.torii_request_timeout(),
            Duration::from_secs(3)
        );
        assert_eq!(source.client.account_chain_discriminant(), 753);
        assert_eq!(
            source.client.torii_request_timeout(),
            Duration::from_secs(2)
        );
        assert_eq!(reader.client.network_id(), source.client.network_id());
        assert_eq!(reader.client.account(), source.client.account());
        let network_reader = read_client_on_network(
            source.client.endpoint().clone(),
            Duration::from_secs(3),
            369,
            test_network_id(0x81),
        )
        .expect("explicit simulated network");
        assert_eq!(*network_reader.client.network_id(), test_network_id(0x81));
        assert_ne!(
            network_reader.client.network_id(),
            source.client.network_id()
        );
    }
    #[test]
    fn typed_query_result_conversion_preserves_absence_staleness_and_redaction() {
        assert_eq!(
            optional_query_result(Ok(QueryResult::Found(7))),
            Ok(Some(7))
        );
        assert_eq!(required_query_result(Ok(QueryResult::Found(7))), Ok(7));
        assert_eq!(
            optional_query_result::<u8>(Ok(QueryResult::NotFound)),
            Ok(None)
        );
        let absent =
            required_query_result::<u8>(Ok(QueryResult::NotFound)).expect_err("required record");
        assert_eq!(absent.class(), RegistryFailureClassV1::NotFound);
        assert_eq!(absent.code(), "MUSUBI_REGISTRY_RECORD_NOT_FOUND");
        for error in [
            optional_query_result::<u8>(Ok(QueryResult::StaleCursor))
                .expect_err("stale optional record"),
            required_query_result::<u8>(Ok(QueryResult::StaleCursor))
                .expect_err("stale required record"),
        ] {
            assert_eq!(error.class(), RegistryFailureClassV1::StaleCursor);
            assert_eq!(error.code(), "MUSUBI_REGISTRY_STALE_CURSOR");
        }
        let failure = iroha::Error::Decode {
            operation: "musubi.v1.query.maintainers",
            details: "private response detail".to_owned(),
        };
        let error = optional_query_result::<u8>(Err(failure)).expect_err("SDK error is redacted");
        assert_eq!(error.class(), RegistryFailureClassV1::Retryable);
        assert_eq!(error.to_string(), "MUSUBI_REGISTRY_QUERY_FAILED");
    }
    #[test]
    fn typed_validation_errors_preserve_registry_classifications() {
        let invalid = optional_query_result::<u8>(Err(iroha::Error::ResponseBinding {
            operation: "musubi.v1.query.exact_package",
            field: "package",
        }))
        .expect_err("substituted response");
        assert_eq!(invalid, invalid_response());
        for (operation, code) in [
            (
                "musubi.v1.query.archive_retention",
                "MUSUBI_REGISTRY_RETENTION_REQUEST_INVALID",
            ),
            (
                "musubi.v1.query.search",
                "MUSUBI_REGISTRY_SEARCH_REQUEST_INVALID",
            ),
            (
                "musubi.v1.query.provider_bundle_attestation",
                "MUSUBI_REGISTRY_RESPONSE_INVALID",
            ),
        ] {
            let invalid = optional_query_result::<u8>(Err(iroha::Error::InvalidRequest {
                operation,
                details: "private request detail".to_owned(),
            }))
            .expect_err("invalid local query");
            assert_eq!(invalid.class(), RegistryFailureClassV1::Permanent);
            assert_eq!(invalid.code(), code);
        }
    }
    #[test]
    fn namespace_binding_derives_an_absent_package_identity() {
        let selector: MusubiPackageSelectorV1 =
            "dex.universal/new-package".parse().expect("selector");
        let binding = MusubiNamespaceBindingV1 {
            namespace: selector.namespace.clone(),
            home_dataspace: DataSpaceId::new(7),
            scope: MusubiPackageScopeV1::Domain("dex".parse().expect("domain")),
            generation: 4,
        };
        let package = package_id_from_namespace_binding(&selector, &binding)
            .expect("namespace binding is enough before a package row exists");
        assert_eq!(package.home_dataspace, DataSpaceId::new(7));
        assert_eq!(package.scope, binding.scope);
        assert_eq!(package.name, selector.name);
        let other: MusubiPackageSelectorV1 = "other.universal/new-package"
            .parse()
            .expect("other selector");
        let error = package_id_from_namespace_binding(&other, &binding)
            .expect_err("a response for another namespace must be rejected");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_RESPONSE_INVALID");
    }
    #[test]
    fn exact_queries_reject_valid_records_for_another_identity() {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "registry-fixture".parse().expect("package name"),
        );
        let owner = account(40);
        let package_record = MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: MusubiNamespaceV1::new("registry").expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([0x41; 32]),
            owners: vec![owner.clone()],
            member_accounts: vec![owner],
            claimed_at_height: 10,
            revisions: MusubiPackageRevisionsV1 {
                governance: 1,
                metadata: 1,
                archive_locations: 1,
            },
        };
        package_record.validate().expect("valid package record");
        let requested_package = MusubiPackageIdV1::new(
            DataSpaceId::new(8),
            MusubiPackageScopeV1::DataspaceRoot,
            "other".parse().expect("other package name"),
        );
        let package_response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&package_record).expect("package record JSON")
        };
        let (url, server) = serve_json_once(package_response);
        let client = RegistryReadClientV1::new_for_test(url, Duration::from_secs(2), 369)
            .expect("registry reader");
        let error = client
            .exact_package(requested_package.clone())
            .expect_err("an exact package response cannot cross identities");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_RESPONSE_INVALID");
        let request_body = server.join().expect("package query server");
        let query: MusubiExactPackageQueryV1 =
            norito::json::from_slice(&request_body).expect("exact package query JSON");
        assert_eq!(query.package, requested_package);
        let (request, _, _, _) = publication_fixture();
        let published_release = request.publication.manifest.release.clone();
        let release_snapshot = exact_release_snapshot(&request);
        release_snapshot
            .validate_for(&MusubiExactReleaseQueryV1 {
                release: published_release.clone(),
            })
            .expect("valid paired release snapshot");
        let requested_release = MusubiReleaseIdV1::new(
            published_release.package,
            "2.0.0".parse::<MusubiVersionV1>().expect("other version"),
        );
        let release_response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&release_snapshot).expect("release snapshot JSON")
        };
        let (url, server) = serve_json_once(release_response);
        let client = read_client_on_network(url, Duration::from_secs(2), 369, request.network_id())
            .expect("registry reader");
        let error = client
            .exact_release(requested_release.clone())
            .expect_err("an exact release response cannot cross identities");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_RESPONSE_INVALID");
        let request_body = server.join().expect("release query server");
        let query: MusubiExactReleaseQueryV1 =
            norito::json::from_slice(&request_body).expect("exact release query JSON");
        assert_eq!(query.release, requested_release);
    }
    #[test]
    fn maintainer_page_accepts_members_and_pending_invites_for_the_requested_package() {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "demo".parse().expect("package name"),
        );
        let owner = account(41);
        let invited = account(42);
        let mut items = vec![
            MusubiMaintainerDirectoryEntryV1::Accepted(MusubiPackageMemberV1 {
                package: package.clone(),
                account: owner.clone(),
                role: MusubiPackageRoleV1::Owner,
                accepted_at_height: 2,
                governance_revision: 3,
            }),
            MusubiMaintainerDirectoryEntryV1::PendingInvitation(MusubiMaintainerInvitationV1 {
                invite_id: MusubiInviteIdV1::new([4; 32]),
                package: package.clone(),
                invited_by: owner,
                invited_account: invited,
                role: MusubiPackageRoleV1::Owner,
                expected_governance_revision: 3,
                expires_at_height: 20,
                state: MusubiInvitationStateV1::Pending,
            }),
        ];
        items.sort_by_key(MusubiMaintainerDirectoryEntryV1::key);
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 5,
            finalized_block_hash: [6; 32],
            index_revision: 7,
        };
        let request = MusubiPackagePageQueryV1 {
            package: package.clone(),
            page: first_page(10),
        };
        let page = MusubiMaintainerPageV1 {
            query: request.clone(),
            items,
            next_cursor: None,
            snapshot,
        };
        validate_maintainer_page(&request, &page)
            .expect("accepted and pending entries share the requested package");
        let foreign_package = MusubiPackageIdV1::new(
            DataSpaceId::new(8),
            MusubiPackageScopeV1::DataspaceRoot,
            "foreign".parse().expect("foreign package name"),
        );
        let mismatched = MusubiMaintainerPageV1 {
            query: request.clone(),
            items: vec![MusubiMaintainerDirectoryEntryV1::Accepted(
                MusubiPackageMemberV1 {
                    package: foreign_package,
                    account: account(43),
                    role: MusubiPackageRoleV1::Owner,
                    accepted_at_height: 2,
                    governance_revision: 3,
                },
            )],
            next_cursor: None,
            snapshot,
        };
        let error = validate_maintainer_page(&request, &mismatched)
            .expect_err("a package-crossing directory response must be rejected");
        assert_eq!(error.code(), "MUSUBI_REGISTRY_RESPONSE_INVALID");
    }
    #[test]
    fn bind_selector_namespace_uses_a_namespace_prefix_without_requiring_a_row() {
        let selector: MusubiPackageSelectorV1 =
            "dex.universal/new-package".parse().expect("selector");
        let query = MusubiOrderedPrefixQueryV1 {
            prefix: MusubiOrderedPrefixV1::new("dex.universal/").expect("namespace prefix"),
            page: first_page(1),
        };
        let page = MusubiOrderedPackagePageV1 {
            query,
            network_id: test_network_id(1),
            namespace_binding: MusubiNamespaceBindingV1 {
                namespace: selector.namespace.clone(),
                home_dataspace: DataSpaceId::new(7),
                scope: MusubiPackageScopeV1::Domain("dex".parse().expect("domain")),
                generation: 4,
            },
            items: Vec::new(),
            next_cursor: None,
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 2,
                finalized_block_hash: [3; 32],
                index_revision: 5,
            },
        };
        let response = norito::json::to_vec(&page).expect("directory response JSON");
        let (url, server) = serve_json_once(response);
        let client = read_client_on_network(url, Duration::from_secs(2), 753, test_network_id(1))
            .expect("authenticated registry client");
        let package = client
            .bind_selector_namespace(&selector)
            .expect("empty namespace directory still binds a package");
        assert_eq!(package.home_dataspace, DataSpaceId::new(7));
        assert_eq!(package.name, selector.name);
        let request_body = server.join().expect("query server");
        let query: MusubiOrderedPrefixQueryV1 =
            norito::json::from_slice(&request_body).expect("ordered-prefix request JSON");
        assert_eq!(query.prefix.as_str(), "dex.universal/");
        assert_eq!(query.page.limit, 1);
        assert!(query.page.cursor.is_none());
    }
    struct CountingReader<'a> {
        reads: &'a Cell<usize>,
    }
    impl Read for CountingReader<'_> {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            Ok(0)
        }
    }
    #[test]
    fn missing_seed_ingress_fails_before_reading_car() {
        let mut runtime = UnavailablePublicationRuntimeV1;
        let reads = Cell::new(0);
        let mut reader = CountingReader { reads: &reads };
        let operation = "0101010101010101010101010101010101010101010101010101010101010101"
            .parse()
            .expect("operation id");
        let commitment = publication_commitment();
        let plan = MusubiSeedIngressCarPlanV1 {
            version: 0,
            payload_digest: [0; 32],
            content_length: 0,
            chunks: Vec::new(),
            files: Vec::new(),
        };
        // The service does not inspect the binding, commitment, plan, or reader before refusing.
        let error = runtime
            .stage_authenticated_seed_ingress(
                operation,
                &binding(),
                &commitment,
                &plan,
                &mut reader,
            )
            .expect_err("unconfigured ingress must fail closed");
        assert_eq!(error.code(), "SEED_INGRESS_SERVICE_NOT_CONFIGURED");
        assert_eq!(reads.get(), 0);
    }
    fn publication_commitment() -> MusubiArchiveCommitmentV1 {
        MusubiArchiveCommitmentV1 {
            root_cid: ManifestRootCid::from_blake3_digest([0x31; 32]).expect("root CID"),
            chunker: ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".to_owned(),
                name: "sf1".to_owned(),
                semver: "1.0.0".to_owned(),
                multihash_code: 0x1f,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([0x32; 32]),
            por_root: MusubiContentDigestV1::new([0x33; 32]),
            content_length: 1_024,
            car_digest: MusubiContentDigestV1::new([0x34; 32]),
            car_size: 2_048,
            bundle_digest: MusubiContentDigestV1::new([0x35; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x36; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x37; 32]),
            file_count: 2,
            chunk_count: 4,
        }
    }
    fn publication_fixture() -> (
        PublicationRequestV1,
        KeyPair,
        KeyPair,
        PublicationArchiveRegistrationIntentV1,
    ) {
        let commitment = publication_commitment();
        let publisher_key =
            KeyPair::try_from_seed(vec![94; 32], Algorithm::Ed25519).expect("publisher key");
        let broker_key =
            KeyPair::try_from_seed(vec![95; 32], Algorithm::Ed25519).expect("broker key");
        let publisher = AccountId::new(publisher_key.public_key().clone());
        let broker = AccountId::new(broker_key.public_key().clone());
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "registry-fixture".parse().expect("package name"),
        );
        let release = MusubiReleaseIdV1::new(
            package,
            "1.0.0".parse::<MusubiVersionV1>().expect("version"),
        );
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let manifest = MusubiReleaseManifestV1 {
            release,
            edition: MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([0x38; 32]).expect("ABI"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([0x39; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            archive_id: commitment.archive_id(),
            verification_lock_digest: lock.digest(),
        };
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 42,
            finalized_block_hash: [0x3a; 32],
            index_revision: 3,
        };
        let request = PublicationRequestV1 {
            network_id: test_network_id(0x3b),
            publisher: publisher.clone(),
            ingress_broker: broker.clone(),
            seed_provider: ProviderId::new([0x3c; 32]),
            namespace: MusubiNamespaceV1::new("registry").expect("namespace"),
            publication: MusubiPublicationV1 {
                manifest,
                resolution: MusubiResolutionProofV1 { snapshot, lock },
            },
            archive_commitment: commitment,
            namespace_delegation: None,
            expected_policy_revision: 1,
            expected_governance_revision: None,
            nonce: [0x3d; 32],
        };
        request.validate().expect("publication request fixture");
        let payload = MusubiSeedIngressReceiptPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding: MusubiSeedIngressReceiptBindingV1 {
                network_id: request.network_id(),
                publisher,
                ingress_broker: broker,
                seed_provider: request.seed_provider,
                semantic_release_manifest_digest: request.publication.manifest.semantic_digest(),
                archive_id: request.archive_commitment.archive_id(),
                car_body_digest: request.archive_commitment.car_digest,
                car_body_length: request.archive_commitment.car_size,
                nonce: request.nonce,
            },
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
        };
        let receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    payload.signing_hash(),
                )
                .expect("receipt signature"),
            }],
            payload,
        };
        let mut builder = TransactionBuilder::new(
            request.network_id(),
            request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([request.archive_registration_instruction(&receipt)]);
        builder.set_creation_time(Duration::from_millis(receipt.payload.issued_at_ms));
        let transaction = builder.sign(publisher_key.private_key());
        let intent = PublicationArchiveRegistrationIntentV1::new(
            request.operation_id(),
            &request,
            receipt,
            transaction,
        );
        intent
            .validate_for(request.operation_id(), &request, &intent.staging_receipt)
            .expect("registration intent fixture");
        (request, publisher_key, broker_key, intent)
    }
    fn exact_release_snapshot(request: &PublicationRequestV1) -> MusubiExactReleaseSnapshotV1 {
        let manifest = request.publication.manifest.clone();
        let yank = MusubiReleaseYankV1 {
            release: manifest.release.clone(),
            yanked: false,
            reason: MusubiReasonV1::new("initial publication").expect("yank reason"),
            changed_by: request.publisher.clone(),
            changed_at_height: 50,
            revision: 1,
        };
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 60,
            finalized_block_hash: [0x3e; 32],
            index_revision: 4,
        };
        MusubiExactReleaseSnapshotV1 {
            network_id: request.network_id(),
            snapshot,
            home_release: MusubiReleaseRecordV1 {
                release_digest: manifest.release_digest(),
                manifest: manifest.clone(),
                published_by: request.publisher.clone(),
                published_at_height: 50,
                yank: yank.clone(),
                artifact_governance: MusubiArtifactGovernanceStateV1::Available,
                revisions: MusubiReleaseRevisionsV1 {
                    yank: 1,
                    artifact_governance: 1,
                },
            },
            universal_release: MusubiResolverReleaseRowV1 {
                release: manifest.release.clone(),
                release_digest: manifest.release_digest(),
                archive_id: manifest.archive_id,
                source_digest: request.archive_commitment.source_tree_digest,
                interface_digest: manifest.interface_digest,
                abi: manifest.abi,
                dependencies: manifest.dependencies.clone(),
                selection: MusubiReleaseSelectionStateV1 {
                    yank,
                    storage: MusubiArchiveAvailabilityV1 {
                        archive_id: manifest.archive_id,
                        availability: MusubiStorageAvailabilityV1::Selectable,
                        healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                        active_locations: 1,
                        finalized_height: 55,
                        finalized_block_hash: [0x3f; 32],
                        index_revision: 3,
                    },
                    governance: MusubiArtifactGovernanceStateV1::Available,
                },
                index_revision: 4,
            },
        }
    }
    fn archive_page(
        request: &PublicationRequestV1,
        receipt: MusubiSeedIngressReceiptV1,
    ) -> MusubiArchiveLocationPageV1 {
        MusubiArchiveLocationPageV1 {
            network_id: request.network_id(),
            archive: MusubiArchiveRecordV1 {
                archive_id: request.archive_commitment.archive_id(),
                commitment: request.archive_commitment.clone(),
                staging_receipt: receipt,
                registered_by: request.publisher.clone(),
                registered_at_height: 50,
                location_revision: 1,
                location_ids: Vec::new(),
            },
            items: Vec::new(),
            next_cursor: None,
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 60,
                finalized_block_hash: [0x3e; 32],
                index_revision: 4,
            },
        }
    }
    fn release_resolver_page(
        request: &PublicationRequestV1,
        items: Vec<MusubiResolverReleaseRowV1>,
        snapshot: MusubiRegistrySnapshotV1,
    ) -> MusubiResolverIndexPageV1 {
        MusubiResolverIndexPageV1 {
            query: MusubiResolverIndexQueryV1 {
                package: request.publication.manifest.release.package.clone(),
                requirement: Some(
                    format!("={}", request.publication.manifest.release.version)
                        .parse()
                        .expect("exact release requirement"),
                ),
                page: first_page(1),
            },
            network_id: request.network_id(),
            items,
            next_cursor: None,
            snapshot,
        }
    }
    fn release_absence_retention_page(
        request: &PublicationRequestV1,
        snapshot: MusubiRegistrySnapshotV1,
        finalized_time_ms: u64,
    ) -> MusubiArchiveRetentionPageV1 {
        MusubiArchiveRetentionPageV1 {
            network_id: request.network_id(),
            items: vec![MusubiArchiveRetentionDecisionV1 {
                archive_id: request.archive_commitment.archive_id(),
                disposition: MusubiArchiveRetentionDispositionV1::PruneUnreferenced,
                active_releases: 0,
                yanked_releases: 0,
                taken_down_releases: 0,
                storage: Some(MusubiArchiveAvailabilityV1 {
                    archive_id: request.archive_commitment.archive_id(),
                    availability: MusubiStorageAvailabilityV1::Selectable,
                    healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                    active_locations: 1,
                    finalized_height: snapshot.finalized_height - 1,
                    finalized_block_hash: [0x61; 32],
                    index_revision: snapshot.index_revision - 1,
                }),
            }],
            snapshot,
            finalized_time_ms,
        }
    }
    fn release_submission_fixture() -> (
        PublicationRequestV1,
        KeyPair,
        PublicationReleaseSubmissionIntentV1,
    ) {
        let (request, publisher_key, _, archive_intent) = publication_fixture();
        let prepared_page = archive_page(&request, archive_intent.staging_receipt.clone());
        let location_id = MusubiArchiveLocationIdV1::new([0x51; 32]);
        let pin_manifest = ManifestDigest::new([0x52; 32]);
        let replication_order = ReplicationOrderId::new([0x53; 32]);
        let provider_attestation_set_digest =
            MusubiProviderBundleAttestationSetDigestV1::new([0x54; 32]);
        let location_instruction = AddMusubiArchiveLocationV1 {
            archive_id: request.archive_commitment.archive_id(),
            location_id,
            pin_manifest,
            replication_order,
            provider_attestation_set_digest,
            renew_after_epoch: 10,
            expires_at_epoch: 20,
            expected_location_revision: prepared_page.archive.location_revision,
        };
        let mut location_builder = TransactionBuilder::new(
            request.network_id(),
            request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([location_instruction.clone()]);
        location_builder.set_creation_time(Duration::from_millis(1_500));
        let location_transaction = location_builder.sign(publisher_key.private_key());
        let location_intent = PublicationArchiveLocationIntentV1::new(
            request.operation_id(),
            1,
            prepared_page.clone(),
            location_instruction,
            location_transaction,
        );
        let providers = vec![
            ProviderId::new([0x55; 32]),
            ProviderId::new([0x56; 32]),
            ProviderId::new([0x57; 32]),
        ];
        let location = MusubiArchiveLocationV1 {
            location_id,
            archive_id: request.archive_commitment.archive_id(),
            pin_manifest,
            replication_order,
            providers: providers.clone(),
            provider_attestation_set_digest,
            renew_after_epoch: 10,
            expires_at_epoch: 20,
            finalized_height: 61,
            revision: 2,
            state: MusubiArchiveLocationStateV1::Healthy,
        };
        let mut finalized_page = prepared_page;
        finalized_page.archive.location_revision = 2;
        finalized_page.archive.location_ids = vec![location_id];
        finalized_page.items = vec![location];
        finalized_page.snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 61,
            finalized_block_hash: [0x61; 32],
            index_revision: 5,
        };
        let registration = PublicationArchiveRegistrationV1 {
            intent: location_intent,
            applied_height: 61,
            finalized_page: finalized_page.clone(),
        };
        let readbacks = providers
            .into_iter()
            .take(2)
            .map(|provider| PublicationReadbackEvidenceV1 {
                provider,
                location_id,
                replication_order,
                commitment: request.archive_commitment.clone(),
                semantic_release_digest: request.publication.manifest.semantic_digest(),
                verification_lock_digest: request.publication.manifest.verification_lock_digest,
            })
            .collect();
        let preparation = PublicationReleasePreparationFloorV1::try_new(
            1,
            PublicationReplicationCheckpointV1 { finalized_page },
            readbacks,
            &request,
            &registration,
        )
        .expect("valid release preparation fixture");
        let mut release_builder = TransactionBuilder::new(
            request.network_id(),
            request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([request.publish_instruction()]);
        release_builder.set_creation_time(Duration::from_millis(2_000));
        let release_transaction = release_builder.sign(publisher_key.private_key());
        let intent = PublicationReleaseSubmissionIntentV1::try_new(
            request.operation_id(),
            &request,
            preparation,
            &release_transaction,
        )
        .expect("valid release submission fixture");
        (request, publisher_key, intent)
    }
    fn publication_absence(
        request: &PublicationRequestV1,
        finalized_time_ms: u64,
    ) -> PublicationArchiveAbsenceEvidenceV1 {
        PublicationArchiveAbsenceEvidenceV1 {
            network_id: request.network_id,
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 60,
                finalized_block_hash: [0x3e; 32],
                index_revision: 4,
            },
            finalized_time_ms,
            decision: MusubiArchiveRetentionDecisionV1 {
                archive_id: request.archive_commitment.archive_id(),
                disposition: MusubiArchiveRetentionDispositionV1::RetainUnknown,
                active_releases: 0,
                yanked_releases: 0,
                taken_down_releases: 0,
                storage: None,
            },
        }
    }
    #[test]
    fn finalized_idempotent_release_requires_exact_commitments_and_original_publisher() {
        let (request, _, _, _) = publication_fixture();
        let exact = exact_release_snapshot(&request);
        validate_finalized_idempotent_release(&request, &exact)
            .expect("same-publisher exact release is replay-safe");
        let mut another_publisher = exact.clone();
        another_publisher.home_release.published_by = account(99);
        another_publisher
            .validate()
            .expect("publisher variation remains a structurally valid paired snapshot");
        let error = validate_finalized_idempotent_release(&request, &another_publisher)
            .expect_err("another publisher's release cannot authorize replay");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "RELEASE_FINALIZED_PUBLISHER_CONFLICT");
        let mut another_commitment = exact;
        another_commitment.home_release.manifest.interface_digest =
            MusubiContentDigestV1::new([0x91; 32]);
        another_commitment.home_release.release_digest =
            another_commitment.home_release.manifest.release_digest();
        another_commitment.universal_release.interface_digest =
            another_commitment.home_release.manifest.interface_digest;
        another_commitment.universal_release.release_digest =
            another_commitment.home_release.release_digest;
        another_commitment
            .validate()
            .expect("commitment variation remains a structurally valid paired snapshot");
        let error = validate_finalized_idempotent_release(&request, &another_commitment)
            .expect_err("different immutable commitments cannot be replayed");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "RELEASE_FINALIZED_COMMITMENT_CONFLICT");
        let resolver_snapshot = another_commitment.snapshot;
        let mut same_height_fork = resolver_snapshot;
        same_height_fork.finalized_block_hash = [0x92; 32];
        let error =
            validate_finalized_release_snapshot_progress(resolver_snapshot, same_height_fork)
                .expect_err("same-height finalized hash conflict must fail closed");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "RELEASE_FINALIZED_SNAPSHOT_CONFLICT");
    }
    #[test]
    fn absent_exact_transaction_with_matching_release_remains_location_gated() {
        let (request, publisher_key, intent) = release_submission_fixture();
        let exact = exact_release_snapshot(&request);
        let resolver = release_resolver_page(
            &request,
            vec![exact.universal_release.clone()],
            exact.snapshot,
        );
        let (resolver_json, exact_json) = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            (
                norito::json::to_vec(&resolver).expect("resolver page JSON"),
                norito::json::to_vec(&exact).expect("exact release JSON"),
            )
        };
        let (url, server) = serve_http_sequence(vec![
            (
                "404 Not Found",
                transaction_status_absence_body_for_hash(&hex::encode(intent.transaction_hash)),
            ),
            ("200 OK", resolver_json),
            ("200 OK", exact_json),
        ]);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let mut backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        assert!(matches!(
            backend
                .submit_or_recover_release_submission(
                    request.operation_id(),
                    &request,
                    &intent,
                    false,
                )
                .expect("matching finalized release keeps the exact absent attempt live"),
            PublicationReleaseSubmissionAdvanceV1::Pending
        ));
        let requests = server.join().expect("status and release query server");
        assert_eq!(
            requests.len(),
            3,
            "the disabled location gate must not send"
        );
        assert!(
            requests[0]
                .path
                .starts_with("/v1/pipeline/transactions/status"),
            "the exact transaction status must be queried before release reads"
        );
        let resolver_query: MusubiResolverIndexQueryV1 =
            norito::json::from_slice(&requests[1].body).expect("resolver query JSON");
        assert_eq!(resolver_query, resolver.query);
        let exact_query: MusubiExactReleaseQueryV1 =
            norito::json::from_slice(&requests[2].body).expect("exact release query JSON");
        assert_eq!(exact_query.release, request.publication.manifest.release);
        validate_finalized_idempotent_release(&request, &exact)
            .expect("matching finalized release authorizes exact replay");
        let sends = Cell::new(0);
        assert_eq!(
            submit_release_after_current_location_gate(true, || {
                sends.set(sends.get() + 1);
                intent.transaction_hash
            }),
            Some(intent.transaction_hash)
        );
        assert_eq!(sends.get(), 1, "the current location gate permits one send");
        assert_eq!(
            submit_release_after_current_location_gate(false, || {
                sends.set(sends.get() + 1);
                intent.transaction_hash
            }),
            None
        );
        assert_eq!(sends.get(), 1, "a stale location gate suppresses the send");
    }
    #[test]
    fn finalized_release_absence_rejects_a_foreign_network_resolver_page() {
        let (request, publisher_key, _, _) = publication_fixture();
        let mut resolver = release_resolver_page(
            &request,
            Vec::new(),
            MusubiRegistrySnapshotV1 {
                finalized_height: 62,
                finalized_block_hash: [0x62; 32],
                index_revision: 6,
            },
        );
        resolver.network_id = test_network_id(0x91);
        resolver
            .validate()
            .expect("foreign network remains a structurally valid response");
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&resolver).expect("foreign resolver page JSON")
        };
        let (url, server) = serve_json_once(response);
        // A valid reader of the other network must still fail the publication's trusted network binding.
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            test_network_id(0x91),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let error = backend
            .finalized_release_absence(&request, None)
            .expect_err("a foreign resolver page cannot prove release absence");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "RELEASE_FINALIZED_NETWORK_CONFLICT");
        server.join().expect("foreign resolver query server");
    }
    #[test]
    fn finalized_archive_absence_rejects_a_foreign_network_retention_page() {
        let (request, publisher_key, _, _) = publication_fixture();
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 62,
            finalized_block_hash: [0x62; 32],
            index_revision: 6,
        };
        let mut retention = release_absence_retention_page(&request, snapshot, 1_700_000_000_000);
        retention.network_id = test_network_id(0x91);
        retention
            .validate()
            .expect("foreign network remains a structurally valid response");
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&retention).expect("foreign retention page JSON")
        };
        let (url, server) = serve_json_once(response);
        // A valid reader of the other network must still fail the publication's trusted network binding.
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            test_network_id(0x91),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let error = backend
            .finalized_archive_absence(&request, None)
            .expect_err("a foreign retention page cannot prove archive absence");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "ARCHIVE_ABSENCE_NETWORK_CONFLICT");
        server.join().expect("foreign retention query server");
    }
    #[test]
    fn pending_release_becomes_terminal_after_finalized_deadline_and_exact_absence() {
        let (request, publisher_key, intent) = release_submission_fixture();
        let transaction = intent
            .reconstruct_signed_transaction(request.operation_id(), &request)
            .expect("reconstruct exact release transaction");
        let deadline = release_submission_valid_until_ms(&intent).expect("release deadline");
        let snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 62,
            finalized_block_hash: [0x62; 32],
            index_revision: 6,
        };
        let resolver = release_resolver_page(&request, Vec::new(), snapshot);
        let retention = release_absence_retention_page(&request, snapshot, deadline + 1);
        let (resolver_json, retention_json) = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            (
                norito::json::to_vec(&resolver).expect("resolver absence JSON"),
                norito::json::to_vec(&retention).expect("retention absence JSON"),
            )
        };
        let (url, server) = serve_http_sequence(vec![
            ("200 OK", transaction_status_body(&transaction, "Queued")),
            ("200 OK", resolver_json),
            ("200 OK", retention_json),
        ]);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let mut backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let terminal = match backend
            .submit_or_recover_release_submission(request.operation_id(), &request, &intent, true)
            .expect("pending status must still check the finalized deadline")
        {
            PublicationReleaseSubmissionAdvanceV1::Terminal(terminal) => terminal,
            other => panic!("expected finalized deadline terminal state, got {other:?}"),
        };
        assert_eq!(terminal.transaction_hash, intent.transaction_hash);
        assert_eq!(
            terminal.signed_transaction_digest,
            intent.signed_transaction_digest
        );
        match terminal.reason {
            PublicationReleaseSubmissionTerminalReasonV1::FinalizedValidityWindowElapsed {
                absence,
            } => {
                assert_eq!(absence.resolver_page, resolver);
                assert_eq!(absence.retention_page, retention);
            }
            other => panic!("unexpected terminal reason: {other:?}"),
        }
        let requests = server.join().expect("status and absence query server");
        assert_eq!(requests.len(), 3, "pending expiry must not resubmit");
    }
    #[test]
    fn finalized_chain_time_rotates_only_after_deadline_and_exact_absence() {
        let (request, _, _, intent) = publication_fixture();
        let valid_until_ms = archive_registration_intent_valid_until_ms(&intent)
            .expect("registration validity deadline");
        assert!(
            terminal_after_finalized_validity_window(
                &request,
                &intent,
                publication_absence(&request, valid_until_ms),
            )
            .expect("valid nonterminal evidence")
            .is_none()
        );
        let terminal = terminal_after_finalized_validity_window(
            &request,
            &intent,
            publication_absence(&request, valid_until_ms + 1),
        )
        .expect("valid terminal evidence")
        .expect("deadline has elapsed");
        assert_eq!(terminal.transaction_hash, intent.transaction_hash);
        let mut wrong_archive = publication_absence(&request, valid_until_ms + 1);
        wrong_archive.decision.archive_id = ArchiveId::new([0xff; 32]);
        assert_eq!(
            terminal_after_finalized_validity_window(&request, &intent, wrong_archive)
                .expect_err("another archive cannot prove terminal absence")
                .code(),
            "ARCHIVE_ABSENCE_RESPONSE_INVALID"
        );
    }
    #[test]
    fn production_prebuild_and_submission_hash_check_preserve_the_exact_transaction() {
        let (request, publisher_key, _, intent) = publication_fixture();
        let signing = signing_client_at(
            &"http://127.0.0.1:9/".parse().expect("loopback URL"),
            &publisher_key,
            request.network_id(),
        );
        let instruction = request.archive_registration_instruction(&intent.staging_receipt);
        let exact_instruction: InstructionBox = instruction.clone().into();
        let payload = signing
            .prebuild_v1(instruction)
            .expect("offline exact transaction prebuild");
        assert_eq!(payload.network_id().copied(), Some(request.network_id()));
        assert_eq!(payload.authority(), &request.publisher);
        assert!(matches!(
            payload.instructions(),
            Executable::Instructions(instructions)
                if instructions.len() == 1
                    && instructions.iter().next() == Some(&exact_instruction)
        ));
        validate_registration_submission_hash(intent.transaction_hash, intent.transaction_hash)
            .expect("exact returned transaction hash");
        let error = validate_registration_submission_hash(intent.transaction_hash, [0xff; 32])
            .expect_err("substituted transaction hash");
        assert_eq!(
            error.code(),
            "ARCHIVE_REGISTRATION_TRANSACTION_HASH_MISMATCH"
        );
        validate_release_submission_hash(intent.transaction_hash, intent.transaction_hash)
            .expect("exact release submission hash");
        assert_eq!(
            validate_release_submission_hash(intent.transaction_hash, [0xfe; 32])
                .expect_err("substituted release submission hash")
                .code(),
            "RELEASE_SUBMISSION_TRANSACTION_HASH_MISMATCH"
        );
        let read = RegistryReadClientV1::new_for_test(
            "http://127.0.0.1:9/".parse().expect("loopback URL"),
            Duration::from_secs(1),
            753,
        )
        .expect("different-profile reader");
        let error = match RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        ) {
            Ok(_) => panic!("read and signing clients must share one address profile"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "MUSUBI_PUBLICATION_REGISTRY_PROFILE_MISMATCH");
    }
    #[test]
    fn compact_release_reconstruction_matches_the_production_torii_body() {
        let (request, publisher_key, _, _) = publication_fixture();
        let mut builder = TransactionBuilder::new(
            request.network_id(),
            request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([request.publish_instruction()]);
        builder.set_creation_time(Duration::from_millis(2_000));
        let signed = builder.sign(publisher_key.private_key());
        let envelope =
            PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(&request, &signed)
                .expect("compact exact release envelope");
        let reconstructed = envelope
            .reconstruct_signed_transaction(&request)
            .expect("reconstructed exact release transaction");
        let submitted = iroha::client::PreparedTransactionPayload::from_transaction(&signed);
        let replayed = iroha::client::PreparedTransactionPayload::from_transaction(&reconstructed);
        assert_eq!(replayed.hash(), submitted.hash());
        assert_eq!(replayed.as_bytes(), submitted.as_bytes());
    }
    #[test]
    fn final_publication_verification_uses_one_paired_exact_release_query() {
        let (request, publisher_key, _, _) = publication_fixture();
        let exact_release = exact_release_snapshot(&request);
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&exact_release).expect("exact release snapshot JSON")
        };
        let (url, server) = serve_json_once(response);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let mut backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let operation_id = request.operation_id();
        let instruction = PublishMusubiReleaseV1::new(
            request.namespace.clone(),
            request.publication.clone(),
            request.namespace_delegation.clone(),
            request.expected_policy_revision,
            request.expected_governance_revision,
        );
        let submission =
            PublicationAmxSubmissionV1::new(operation_id, &instruction, [0x72; 32], 55);
        let evidence = backend
            .finalized_release_and_index(operation_id, &request, &submission)
            .expect("paired final query succeeds")
            .expect("paired final evidence is visible");
        assert_eq!(evidence.network_id, request.network_id);
        assert_eq!(evidence.snapshot, exact_release.snapshot);
        assert_eq!(evidence.home_release, exact_release.home_release);
        assert_eq!(evidence.universal_release, exact_release.universal_release);
        let request_body = server.join().expect("exact release query server");
        let query: MusubiExactReleaseQueryV1 =
            norito::json::from_slice(&request_body).expect("exact release query JSON");
        assert_eq!(query.release, request.publication.manifest.release);
    }
    #[test]
    fn final_publication_verification_rejects_a_foreign_network_snapshot() {
        let (request, publisher_key, _, _) = publication_fixture();
        let mut exact_release = exact_release_snapshot(&request);
        exact_release.network_id = test_network_id(0x91);
        exact_release
            .validate()
            .expect("foreign network remains a structurally valid response");
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&exact_release).expect("foreign exact release snapshot JSON")
        };
        let (url, server) = serve_json_once(response);
        // A valid reader of the other network must still fail the publication's trusted network binding.
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            test_network_id(0x91),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let mut backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let operation_id = request.operation_id();
        let instruction = PublishMusubiReleaseV1::new(
            request.namespace.clone(),
            request.publication.clone(),
            request.namespace_delegation.clone(),
            request.expected_policy_revision,
            request.expected_governance_revision,
        );
        let submission =
            PublicationAmxSubmissionV1::new(operation_id, &instruction, [0x72; 32], 55);
        let error = backend
            .finalized_release_and_index(operation_id, &request, &submission)
            .expect_err("a foreign network response cannot become final evidence");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        assert_eq!(error.code(), "RELEASE_FINALIZED_NETWORK_CONFLICT");
        server.join().expect("foreign exact release query server");
    }
    #[test]
    fn production_recovery_binds_the_finalized_authoritative_archive_page() {
        let (request, publisher_key, broker_key, intent) = publication_fixture();
        let exact_page = archive_page(&request, intent.staging_receipt.clone());
        let exact_page_json = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&exact_page).expect("archive page JSON")
        };
        let (url, server) = serve_json_once(exact_page_json);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let recovered = backend
            .recover_registered_archive(&request, &intent, None)
            .expect("recover exact archive")
            .expect("authoritative archive exists");
        assert_eq!(
            recovered.finalized_transaction_hash,
            intent.transaction_hash
        );
        assert_eq!(recovered.archive, exact_page.archive);
        let request_body = server.join().expect("archive query server");
        let query: MusubiArchiveLocationQueryV1 =
            norito::json::from_slice(&request_body).expect("archive query JSON");
        assert_eq!(query.archive_id, intent.archive_id);
        let mut replacement_payload = intent.staging_receipt.payload.clone();
        replacement_payload.issued_at_ms = 1_100;
        replacement_payload.expires_at_ms = 2_100;
        let replacement_receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    replacement_payload.signing_hash(),
                )
                .expect("replacement receipt signature"),
            }],
            payload: replacement_payload,
        };
        let conflicting_page = archive_page(&request, replacement_receipt);
        conflicting_page
            .validate()
            .expect("structurally valid conflict");
        let conflicting_page_json = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&conflicting_page).expect("conflicting archive page JSON")
        };
        let (url, server) = serve_json_once(conflicting_page_json);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let error = backend
            .recover_registered_archive(&request, &intent, None)
            .expect_err("different receipt must not recover the authoritative archive");
        assert_eq!(error.code(), "ARCHIVE_REGISTRATION_CONFLICT");
        server.join().expect("conflicting archive query server");
    }
    #[test]
    fn terminal_transaction_status_still_recovers_an_exact_finalized_archive() {
        let (request, publisher_key, _, intent) = publication_fixture();
        let exact_page = archive_page(&request, intent.staging_receipt.clone());
        let response = {
            let _chain_discriminant = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(&exact_page).expect("archive page JSON")
        };
        let (url, server) = serve_json_once(response);
        let read = read_client_on_network(
            url.clone(),
            Duration::from_secs(2),
            369,
            request.network_id(),
        )
        .expect("registry reader");
        let signing = signing_client_at(&url, &publisher_key, request.network_id());
        let backend = RegistryPublicationBackendV1::new(
            read,
            signing,
            UnavailablePublicationRuntimeV1,
            &request,
        )
        .expect("publication backend");
        let outcome = backend
            .terminal_registration_state(
                &request,
                &intent,
                RegistryTerminalTransactionStateV1::Rejected,
                Some(55),
            )
            .expect("exact finalized archive wins over terminal status");
        let PublicationArchiveRegistrationAdvanceV1::Registered(registered) = outcome else {
            panic!("terminal status with an exact archive must recover registration");
        };
        assert_eq!(registered.archive, exact_page.archive);
        assert_eq!(registered.snapshot, exact_page.snapshot);
        server.join().expect("archive query server");
    }
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive fixture key pair");
        AccountId::new(keypair.public_key().clone())
    }
    fn binding() -> MusubiSeedIngressReceiptBindingV1 {
        MusubiSeedIngressReceiptBindingV1 {
            network_id: test_network_id(1),
            publisher: account(2),
            ingress_broker: account(3),
            seed_provider: ProviderId::new([4; 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([5; 32]),
            archive_id: ArchiveId::new([6; 32]),
            car_body_digest: MusubiContentDigestV1::new([7; 32]),
            car_body_length: 8,
            nonce: [9; 32],
        }
    }
    #[test]
    fn polling_policy_rejects_unbounded_delay() {
        let error = PublicationPollPolicyV1 {
            max_attempts: 1,
            initial_delay: Duration::from_secs(31),
            max_delay: Duration::from_secs(31),
        }
        .validate()
        .expect_err("sub-minute bound is mandatory");
        assert!(matches!(error, PublicationError::InvalidJournal(_)));
    }
}
