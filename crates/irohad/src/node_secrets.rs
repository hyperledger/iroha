//! Fixed-name runtime secrets of a `data_dir` node.
//!
//! A node whose configuration sets `data_dir` keeps its secrets in fixed files under
//! `<data_dir>/secrets/` ([`NodeSecretFile`]). Two groups exist:
//! - the key files the configuration names (`validator.key`, `transport.key`, `streaming.key` and
//!   the `authority/*.key` network-authority keys). The configuration parser reads them, so every
//!   one that exists passes [`verify_config_key_custody`] first, whenever the node file is loaded
//!   (including `--check-config` and `--check-storage`);
//! - the runtime-only secrets (`runtime_signer.key`, `beacon.cred`), which
//!   [`NodeSecretsV1`] opens only for a real start, after the complete configuration has passed the
//!   offline checks: `--check-config` and `--check-storage` never open them.
//!
//! Every file is read through [`load_bounded_runtime_credential_v1`]: an absolute path with no
//! untrusted links, foreign ownership or shared write access in its ancestors. Retained native
//! handles admit one single-link regular file, readable only by its current owner, with
//! the exact (or bounded) size of its record. The bytes are zeroized after parsing. The path is
//! walked as written first: a symlinked component is admitted only when the link and its directory
//! are root-owned and not group/world-writable (system links such as macOS `/var`), so a symlinked
//! `data_dir`, `secrets` directory or user-owned ancestor is refused.
//!
//! Each loaded runtime secret is checked against the public binding the configuration carries:
//! - `runtime_signer.key` (required when `soracloud_runtime.submission.signer` is configured, which
//!   `production_mode` requires) must be the Ed25519 key of that binding, whose handle, revision
//!   and policy digest must be the compiled file-backed signer binding
//!   ([`iroha_config::parameters::actual::node_runtime_signer`]);
//! - `authority/onboarding.key` (when onboarding reads it from the fixed path) must be the key of
//!   `torii.account_onboarding.authority`;
//! - `beacon.cred`, when present on a validator, yields the global-beacon partial signer. Its
//!   provider binding (handle, revision, policy digest) is read from the credential header and must
//!   equal the configured `sumeragi.global_beacon_partial_signer_provider_*` binding when one is set.
//!
//! The file-backed Soracloud signer ([`FileRuntimeSignerV1`]) and its key-record parser are shared
//! with the `iroha3d_taira` launcher, which supplies its own compiled policy and
//! inherited-descriptor loader.
//!
//! TODO(P8): `iroha3d_taira` and its inherited-descriptor launcher are deleted at the cutover; until
//! then they never use the fixed files.

use crate::{
    IrohaRuntimeDeps, IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderRegistryErrorV1,
    IrohaRuntimeProviderRegistryV1, IrohaRuntimeProviderSlotV1, RuntimeCredentialErrorV1,
    runtime_credential::load_bounded_runtime_credential_v1,
    runtime_provider_registry::resolve_runtime_deps_from_bindings,
    soracloud_runtime_signer::{
        SoracloudRuntimeMutationSignerV1, SoracloudRuntimeSignerProbeErrorV1,
        SoracloudRuntimeSignerQualificationV1, SoracloudRuntimeSigningErrorV1,
    },
};
use iroha_allocation::AllocationBudget;
use iroha_config::parameters::{
    actual::{
        DataDir, NodeRole, NodeSecretFile, Root as Config, SoracloudRuntimeMutationSignerBinding,
        Sumeragi, node_runtime_signer,
    },
    is_production_runtime_handle,
};
use iroha_core::beacon::{
    GlobalThresholdBeaconPartialSignerV1,
    credential::{
        GlobalBeaconCredentialImportErrorV1, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1,
        decode_global_beacon_partial_signer_credential_v1,
        global_beacon_partial_signer_credential_header_v1,
    },
};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, PrivateKey, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    soracloud::{
        SoracloudRuntimeProvenancePurposeV1, validate_soracloud_runtime_provenance_preimage_v1,
    },
    transaction::{SignedTransaction, TransactionBuilder, TransactionPayload},
};
use std::{
    fmt,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
};
use zeroize::Zeroizing;

/// Upper bound of a private-key file (one private multihash and a newline).
pub const AUTHORITY_KEY_FILE_MAX_BYTES_V1: usize = 64 * 1024;
/// Key files the configuration parser reads from `<data_dir>/secrets/` when the configuration
/// names them; [`verify_config_key_custody`] checks each one that exists.
pub const CONFIG_KEY_FILES_V1: [NodeSecretFile; 5] = [
    NodeSecretFile::Validator,
    NodeSecretFile::Transport,
    NodeSecretFile::Streaming,
    NodeSecretFile::FaucetAuthority,
    NodeSecretFile::OnboardingAuthority,
];

/// Compiled public binding of one file-backed Soracloud runtime signer adapter.
#[derive(Clone, Copy)]
pub(crate) struct RuntimeSignerPolicyV1 {
    /// Handle prefix; the lowercase raw Ed25519 public key follows.
    pub(crate) handle_prefix: &'static str,
    /// Exact adapter and public-policy revision.
    pub(crate) revision: u64,
    /// Digest of the adapter's compiled public policy.
    pub(crate) policy_digest: fn() -> [u8; 32],
}

/// The `data_dir` runtime signer ([`node_runtime_signer`]).
pub(crate) const NODE_RUNTIME_SIGNER_POLICY_V1: RuntimeSignerPolicyV1 = RuntimeSignerPolicyV1 {
    handle_prefix: node_runtime_signer::HANDLE_PREFIX_V1,
    revision: node_runtime_signer::REVISION_V1,
    policy_digest: node_runtime_signer::policy_digest_v1,
};

/// A node secret that cannot be used. Messages name the file and never carry secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeSecretsErrorV1 {
    /// A required fixed secret file does not exist.
    Missing(NodeSecretFile),
    /// A fixed secret file failed its custody checks or could not be read.
    Custody {
        /// Offending file.
        file: NodeSecretFile,
        /// Custody failure.
        error: RuntimeCredentialErrorV1,
    },
    /// A fixed secret file does not hold one canonical record of its kind.
    Malformed(NodeSecretFile),
    /// A loaded secret does not match its public binding in the configuration.
    BindingMismatch {
        /// Offending file.
        file: NodeSecretFile,
        /// Which part of the binding differs.
        detail: &'static str,
    },
    /// The configuration requests something the fixed-file loader does not provide.
    Unsupported(&'static str),
    /// The runtime-provider catalog rejected the resolved secrets.
    Registry(IrohaRuntimeProviderRegistryErrorV1),
}

impl fmt::Display for NodeSecretsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(file) => write!(
                formatter,
                "required node secret `secrets/{}` is missing",
                file.relative_path()
            ),
            Self::Custody { file, error } => write!(
                formatter,
                "node secret `secrets/{}` failed custody checks ({})",
                file.relative_path(),
                match error {
                    RuntimeCredentialErrorV1::InvalidSource =>
                        "it must be one owner-only regular file with a single link, owned by \
                         this user, reached through trusted directories without untrusted links",
                    RuntimeCredentialErrorV1::InvalidLength =>
                        "its size is not the exact record size",
                    RuntimeCredentialErrorV1::Unavailable => "it could not be read",
                }
            ),
            Self::Malformed(file) => write!(
                formatter,
                "node secret `secrets/{}` does not hold one canonical record",
                file.relative_path()
            ),
            Self::BindingMismatch { file, detail } => write!(
                formatter,
                "node secret `secrets/{}` does not match its configured public binding: {detail}",
                file.relative_path()
            ),
            Self::Unsupported(message) => formatter.write_str(message),
            Self::Registry(error) => write!(formatter, "node secrets were not admitted: {error}"),
        }
    }
}

impl std::error::Error for NodeSecretsErrorV1 {}

/// Failure opening node credentials, retaining host-local memory failures separately.
#[derive(Debug)]
pub enum NodeSecretsLoadErrorV1 {
    /// An unavailable, malformed, or substituted secret.
    Secret(NodeSecretsErrorV1),
    /// Admission or construction failed in the original local credential pool.
    BeaconSession(iroha_core::beacon::GlobalThresholdBeaconSessionError),
    /// Exact local decoder failure; the original credential has not been rejected.
    BeaconDecode(norito::core::DecodeAttemptError),
}

impl From<NodeSecretsErrorV1> for NodeSecretsLoadErrorV1 {
    fn from(error: NodeSecretsErrorV1) -> Self {
        Self::Secret(error)
    }
}

impl fmt::Display for NodeSecretsLoadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(error) => error.fmt(formatter),
            Self::BeaconDecode(_) => {
                formatter.write_str("node beacon credential decoder is unavailable")
            }
            Self::BeaconSession(error) => write!(
                formatter,
                "node beacon custody could not be retained: {error}"
            ),
        }
    }
}

impl std::error::Error for NodeSecretsLoadErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Secret(error) => Some(error),
            Self::BeaconSession(error) => Some(error),
            Self::BeaconDecode(error) => Some(error),
        }
    }
}

/// The runtime secrets a `data_dir` node starts with.
pub struct NodeSecretsV1 {
    data_dir: DataDir,
    runtime_signer: Option<Arc<FileRuntimeSignerV1>>,
    beacon: Option<FileBeaconSignerV1>,
}

impl fmt::Debug for NodeSecretsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeSecretsV1")
            .field("data_dir", &self.data_dir.root())
            .field(
                "runtime_signer",
                &self.runtime_signer.as_ref().map(|signer| &signer.handle),
            )
            .field("beacon", &self.beacon.as_ref().map(|beacon| &beacon.handle))
            .finish()
    }
}

impl NodeSecretsV1 {
    /// Open the runtime signer and beacon credential the configuration needs and verify the
    /// onboarding authority key. Returns `None` when the configuration has no `data_dir`.
    ///
    /// # Errors
    ///
    /// [`NodeSecretsLoadErrorV1`] for an invalid secret or a failure to retain its public
    /// transcript in the caller's original pool. All current and pending sessions share it.
    pub fn open(
        config: &Config,
        budget: &AllocationBudget,
    ) -> Result<Option<Self>, NodeSecretsLoadErrorV1> {
        let Some(data_dir) = config.data_dir.clone() else {
            return Ok(None);
        };
        verify_onboarding_authority_key(&data_dir, config)?;
        let runtime_signer = match config.soracloud_runtime.submission.signer.as_ref() {
            Some(binding) => Some(Arc::new(load_runtime_signer(&data_dir, binding)?)),
            None if config.soracloud_runtime.production_mode => {
                return Err(NodeSecretsErrorV1::Unsupported(
                    "soracloud_runtime.production_mode requires soracloud_runtime.submission.signer",
                ).into());
            }
            None => None,
        };
        let network_id = NetworkId::from_genesis_hash(config.genesis.expected_hash);
        let beacon = load_beacon_signer(&data_dir, &network_id, &config.sumeragi, budget)?;
        Ok(Some(Self {
            data_dir,
            runtime_signer,
            beacon,
        }))
    }

    /// Resolve the configured runtime-provider catalog from these secrets and attach the beacon
    /// signer derived from `beacon.cred` when the configuration does not request it.
    ///
    /// # Errors
    ///
    /// [`NodeSecretsErrorV1::Unsupported`] when the catalog requests a provider other than the
    /// Soracloud runtime signer and the global-beacon partial signer, and
    /// [`NodeSecretsErrorV1::Registry`] when the catalog rejects the resolution.
    pub fn resolve_runtime_deps(
        &self,
        config: &Config,
    ) -> Result<IrohaRuntimeDeps, NodeSecretsErrorV1> {
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(config)
            .map_err(NodeSecretsErrorV1::Registry)?;
        // TODO: compose the stock broker for the remaining provider roles once a profile enables
        // one; no compiled profile does today.
        if bindings.iter().any(|binding| {
            !matches!(
                binding.slot(),
                IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner
                    | IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner
            )
        }) {
            return Err(NodeSecretsErrorV1::Unsupported(
                "a data_dir node resolves only the Soracloud runtime signer and the global-beacon \
                 partial signer from secrets/; remove the other runtime-provider bindings",
            ));
        }
        let beacon_requested = bindings
            .iter()
            .any(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner);
        let dependencies = resolve_runtime_deps_from_bindings(&bindings, Some(self))
            .map_err(NodeSecretsErrorV1::Registry)?;
        Ok(match (&self.beacon, beacon_requested) {
            (Some(beacon), false) => {
                dependencies.with_sumeragi_global_beacon_partial_signer(beacon.signer.clone())
            }
            _ => dependencies,
        })
    }

    fn existing_secret(&self, file: NodeSecretFile) -> Result<Option<PathBuf>, NodeSecretsErrorV1> {
        existing_secret_path(&self.data_dir, file)
    }
}

impl IrohaRuntimeProviderRegistryV1 for NodeSecretsV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
        let mut dependencies = IrohaRuntimeDeps::default();
        for binding in bindings.iter() {
            match binding.slot() {
                IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner => {
                    let signer = self
                        .runtime_signer
                        .as_ref()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
                    let exact = binding
                        .soracloud_runtime_signer_binding()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                    if exact.handle() != signer.handle
                        || exact.authority() != &AccountId::new(signer.signer_public_key().clone())
                        || exact.public_key() != signer.signer_public_key()
                        || exact.qualification() != signer.qualification_v1()
                    {
                        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                    }
                    let signer: Arc<dyn SoracloudRuntimeMutationSignerV1> = signer.clone();
                    dependencies = dependencies.with_soracloud_runtime_mutation_signer(signer);
                }
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    let beacon = self
                        .beacon
                        .as_ref()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
                    if binding.handle() != beacon.handle
                        || binding.revision() != Some(beacon.revision)
                        || binding.policy_digest() != Some(beacon.policy_digest)
                    {
                        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                    }
                    dependencies = dependencies
                        .with_sumeragi_global_beacon_partial_signer(beacon.signer.clone());
                }
                _ => return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution),
            }
        }
        Ok(dependencies)
    }
}

/// Admit the fixed secret path through the native retained-handle custody boundary.
/// Missing files remain optional until the caller applies its role-specific requirement.
fn existing_secret_path(
    data_dir: &DataDir,
    file: NodeSecretFile,
) -> Result<Option<PathBuf>, NodeSecretsErrorV1> {
    let path = data_dir.secret(file);
    let refused = |error| NodeSecretsErrorV1::Custody { file, error };
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(refused(RuntimeCredentialErrorV1::InvalidSource));
    }
    match iroha_fs::RetainedFile::open_private(&path) {
        Ok(_) => Ok(Some(path)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(refused(RuntimeCredentialErrorV1::InvalidSource)),
    }
}

/// Check the custody of every [`CONFIG_KEY_FILES_V1`] file that exists under
/// `<data_dir>/secrets/`, before the configuration parser reads the ones the configuration names.
///
/// Each file passes the same checks as the runtime secrets ([`load_bounded_runtime_credential_v1`]
/// with at most [`AUTHORITY_KEY_FILE_MAX_BYTES_V1`] bytes); its bytes are zeroized unread.
///
/// # Errors
///
/// [`NodeSecretsErrorV1::Custody`] naming the first file that fails.
pub fn verify_config_key_custody(data_dir: &DataDir) -> Result<(), NodeSecretsErrorV1> {
    for file in CONFIG_KEY_FILES_V1 {
        if let Some(path) = existing_secret_path(data_dir, file)? {
            drop(load_secret(
                &path,
                file,
                1,
                AUTHORITY_KEY_FILE_MAX_BYTES_V1,
            )?);
        }
    }
    Ok(())
}

fn load_secret(
    path: &Path,
    file: NodeSecretFile,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, NodeSecretsErrorV1> {
    load_bounded_runtime_credential_v1(path, minimum_bytes, maximum_bytes)
        .map_err(|error| NodeSecretsErrorV1::Custody { file, error })
}

/// Parse one canonical Ed25519 private multihash followed by exactly one newline, the record of
/// every file-backed runtime signer. `None` for any other bytes.
pub(crate) fn parse_ed25519_signer_record_v1(bytes: &[u8]) -> Option<KeyPair> {
    let record = bytes.strip_suffix(b"\n")?;
    let literal = std::str::from_utf8(record).ok()?;
    let exposed = literal.parse::<ExposedPrivateKey>().ok()?;
    if exposed.0.algorithm() != Algorithm::Ed25519
        || exposed.try_to_multihash_string().ok()? != literal
    {
        return None;
    }
    KeyPair::from_private_key(exposed.0).ok()
}

/// Load `runtime_signer.key` and require the configured binding to describe exactly this signer.
fn load_runtime_signer(
    data_dir: &DataDir,
    binding: &SoracloudRuntimeMutationSignerBinding,
) -> Result<FileRuntimeSignerV1, NodeSecretsErrorV1> {
    const FILE: NodeSecretFile = NodeSecretFile::RuntimeSigner;
    let path = existing_secret_path(data_dir, FILE)?.ok_or(NodeSecretsErrorV1::Missing(FILE))?;
    let bytes = load_secret(
        &path,
        FILE,
        node_runtime_signer::KEY_FILE_BYTES_V1,
        node_runtime_signer::KEY_FILE_BYTES_V1,
    )?;
    let key_pair =
        parse_ed25519_signer_record_v1(&bytes).ok_or(NodeSecretsErrorV1::Malformed(FILE))?;
    drop(bytes);
    let signer = FileRuntimeSignerV1::new(NODE_RUNTIME_SIGNER_POLICY_V1, key_pair).ok_or(
        NodeSecretsErrorV1::Unsupported(
            "the file-backed Soracloud runtime signer supports Ed25519 keys only",
        ),
    )?;
    verify_runtime_signer_binding(&signer, binding)?;
    Ok(signer)
}

fn verify_runtime_signer_binding(
    signer: &FileRuntimeSignerV1,
    binding: &SoracloudRuntimeMutationSignerBinding,
) -> Result<(), NodeSecretsErrorV1> {
    let mismatch = |detail| NodeSecretsErrorV1::BindingMismatch {
        file: NodeSecretFile::RuntimeSigner,
        detail,
    };
    let public_key = signer.key_pair.public_key();
    if binding.algorithm != Algorithm::Ed25519 {
        return Err(mismatch("the binding algorithm must be ed25519"));
    }
    if &binding.public_key != public_key {
        return Err(mismatch("public_key_hex is not this key"));
    }
    if binding.authority != AccountId::new(public_key.clone()) {
        return Err(mismatch("authority is not the account of this key"));
    }
    if binding.handle != signer.handle {
        return Err(mismatch(
            "handle must be `software://iroha/node-secrets/runtime-signer/<public key hex>`",
        ));
    }
    if binding.revision != node_runtime_signer::REVISION_V1 {
        return Err(mismatch("revision is not the file-backed signer revision"));
    }
    if binding.policy_digest != node_runtime_signer::policy_digest_v1() {
        return Err(mismatch(
            "policy_digest_hex is not the file-backed signer policy digest",
        ));
    }
    Ok(())
}

/// Verify `authority/onboarding.key` when onboarding reads its signer from that fixed path.
///
/// The configuration parser already loaded the signer and matched it to the authority; this adds
/// the custody checks and matches the file's key to the authority once more.
fn verify_onboarding_authority_key(
    data_dir: &DataDir,
    config: &Config,
) -> Result<(), NodeSecretsErrorV1> {
    const FILE: NodeSecretFile = NodeSecretFile::OnboardingAuthority;
    let Some(onboarding) = config.torii.account_onboarding.as_ref() else {
        return Ok(());
    };
    if onboarding.private_key_file != data_dir.secret(FILE) {
        return Ok(());
    }
    let path = existing_secret_path(data_dir, FILE)?.ok_or(NodeSecretsErrorV1::Missing(FILE))?;
    let bytes = load_secret(&path, FILE, 1, AUTHORITY_KEY_FILE_MAX_BYTES_V1)?;
    let public_key = parse_authority_key(&bytes, FILE)?;
    drop(bytes);
    let mismatch = || NodeSecretsErrorV1::BindingMismatch {
        file: FILE,
        detail: "the key is not the signatory of torii.account_onboarding.authority",
    };
    if onboarding.authority.try_signatory() != Some(&public_key)
        || onboarding.signer.public_key() != &public_key
    {
        return Err(mismatch());
    }
    Ok(())
}

/// Parse one private-key multihash, optionally newline-terminated, into its public key.
fn parse_authority_key(
    bytes: &[u8],
    file: NodeSecretFile,
) -> Result<PublicKey, NodeSecretsErrorV1> {
    let malformed = || NodeSecretsErrorV1::Malformed(file);
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    let literal = text.strip_suffix('\n').unwrap_or(text);
    if literal.is_empty() || literal.contains(['\n', '\r']) {
        return Err(malformed());
    }
    let private_key = PrivateKey::from_str(literal).map_err(|_| malformed())?;
    let key_pair = KeyPair::from_private_key(private_key).map_err(|_| malformed())?;
    Ok(key_pair.public_key().clone())
}

/// Global-beacon partial signer loaded from `beacon.cred` with its header-derived binding.
struct FileBeaconSignerV1 {
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
    signer: Arc<dyn GlobalThresholdBeaconPartialSignerV1>,
}

/// Load `beacon.cred` when it exists; the provider binding comes from its header.
fn load_beacon_signer(
    data_dir: &DataDir,
    network_id: &NetworkId,
    sumeragi: &Sumeragi,
    budget: &AllocationBudget,
) -> Result<Option<FileBeaconSignerV1>, NodeSecretsLoadErrorV1> {
    const FILE: NodeSecretFile = NodeSecretFile::BeaconCredential;
    let Some(path) = existing_secret_path(data_dir, FILE)? else {
        return Ok(None);
    };
    if sumeragi.role != NodeRole::Validator {
        return Err(NodeSecretsErrorV1::Unsupported(
            "secrets/beacon.cred is present but sumeragi.role is not `validator`",
        )
        .into());
    }
    let bytes = load_secret(&path, FILE, 1, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1)?;
    let beacon = decode_beacon_credential(&bytes, network_id, sumeragi, budget)?;
    drop(bytes);
    Ok(Some(beacon))
}

fn decode_beacon_credential(
    bytes: &[u8],
    network_id: &NetworkId,
    sumeragi: &Sumeragi,
    budget: &AllocationBudget,
) -> Result<FileBeaconSignerV1, NodeSecretsLoadErrorV1> {
    const FILE: NodeSecretFile = NodeSecretFile::BeaconCredential;
    let mismatch = |detail| NodeSecretsErrorV1::BindingMismatch { file: FILE, detail };
    let header =
        global_beacon_partial_signer_credential_header_v1(bytes).map_err(|error| match error {
            iroha_core::beacon::credential::ConsensusThresholdCredentialDecodeErrorV1::Rejected => {
                NodeSecretsLoadErrorV1::Secret(NodeSecretsErrorV1::Malformed(FILE))
            }
            iroha_core::beacon::credential::ConsensusThresholdCredentialDecodeErrorV1::Resource(
                error,
            ) => NodeSecretsLoadErrorV1::BeaconDecode(error),
        })?;
    if header.network_id != *network_id {
        return Err(mismatch("the credential belongs to another network").into());
    }
    if !is_production_runtime_handle(&header.handle) {
        return Err(mismatch("the credential handle is not a production provider handle").into());
    }
    let configured = (
        sumeragi
            .global_beacon_partial_signer_provider_handle
            .as_deref(),
        sumeragi.global_beacon_partial_signer_provider_revision,
        sumeragi.global_beacon_partial_signer_provider_policy_digest,
    );
    match configured {
        (None, None, None) => {}
        (Some(handle), Some(revision), Some(policy_digest))
            if handle == header.handle
                && revision == header.revision
                && policy_digest == header.policy_digest => {}
        _ => {
            return Err(mismatch(
                "the configured sumeragi.global_beacon_partial_signer_provider_* binding differs \
                 from the credential header",
            )
            .into());
        }
    }
    let custody = decode_global_beacon_partial_signer_credential_v1(
        bytes,
        network_id,
        &header.handle,
        header.revision,
        header.policy_digest,
        budget,
    )
    .map_err(|error| match error {
        GlobalBeaconCredentialImportErrorV1::Credential(_) => {
            NodeSecretsLoadErrorV1::Secret(NodeSecretsErrorV1::Malformed(FILE))
        }
        GlobalBeaconCredentialImportErrorV1::DecodeResource(error) => {
            NodeSecretsLoadErrorV1::BeaconDecode(error)
        }
        GlobalBeaconCredentialImportErrorV1::Session(error) => {
            NodeSecretsLoadErrorV1::BeaconSession(error)
        }
    })?;
    Ok(FileBeaconSignerV1 {
        handle: header.handle,
        revision: header.revision,
        policy_digest: header.policy_digest,
        signer: Arc::new(custody),
    })
}

/// Soracloud runtime mutation and provenance signer backed by one Ed25519 key file.
///
/// The adapter's compiled public binding ([`RuntimeSignerPolicyV1`]) fixes its handle prefix,
/// revision and policy digest: [`NODE_RUNTIME_SIGNER_POLICY_V1`] for `runtime_signer.key`, and the
/// `iroha3d_taira` launcher's own policy for its inherited descriptor.
pub(crate) struct FileRuntimeSignerV1 {
    policy: RuntimeSignerPolicyV1,
    handle: String,
    key_pair: KeyPair,
}

impl FileRuntimeSignerV1 {
    /// Bind `key_pair` to `policy`; `None` for a key that is not Ed25519.
    pub(crate) fn new(policy: RuntimeSignerPolicyV1, key_pair: KeyPair) -> Option<Self> {
        let handle = match key_pair.public_key().try_to_bytes() {
            Ok((Algorithm::Ed25519, payload)) if payload.len() == 32 => {
                format!("{}{}", policy.handle_prefix, hex::encode(payload))
            }
            _ => return None,
        };
        Some(Self {
            policy,
            handle,
            key_pair,
        })
    }

    /// Active, non-test qualification of this adapter's compiled policy.
    pub(crate) fn qualification_v1(&self) -> SoracloudRuntimeSignerQualificationV1 {
        SoracloudRuntimeSignerQualificationV1::new(
            self.policy.revision,
            (self.policy.policy_digest)(),
            true,
            false,
        )
    }

    /// Public key of the loaded signer.
    pub(crate) fn signer_public_key(&self) -> &PublicKey {
        self.key_pair.public_key()
    }
}

impl SoracloudRuntimeMutationSignerV1 for FileRuntimeSignerV1 {
    fn handle(&self) -> &str {
        &self.handle
    }

    fn authority(&self) -> AccountId {
        AccountId::new(self.key_pair.public_key().clone())
    }

    fn public_key(&self) -> Result<PublicKey, SoracloudRuntimeSignerProbeErrorV1> {
        Ok(self.key_pair.public_key().clone())
    }

    fn qualification(
        &self,
    ) -> Result<SoracloudRuntimeSignerQualificationV1, SoracloudRuntimeSignerProbeErrorV1> {
        Ok(self.qualification_v1())
    }

    fn sign_transaction(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoracloudRuntimeSigningErrorV1> {
        if payload.authority() != &self.authority() {
            return Err(SoracloudRuntimeSigningErrorV1::InputAuthorityMismatch);
        }
        TransactionBuilder::from_payload(payload)
            .map_err(|_| SoracloudRuntimeSigningErrorV1::Refused)?
            .try_sign(self.key_pair.private_key())
            .map_err(|_| SoracloudRuntimeSigningErrorV1::Refused)
    }

    fn sign_provenance(
        &self,
        purpose: SoracloudRuntimeProvenancePurposeV1,
        preimage: &[u8],
    ) -> Result<Signature, SoracloudRuntimeSigningErrorV1> {
        validate_soracloud_runtime_provenance_preimage_v1(purpose, preimage)
            .map_err(|_| SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage)?;
        Signature::try_new(self.key_pair.private_key(), preimage)
            .map_err(|_| SoracloudRuntimeSigningErrorV1::Refused)
    }
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
mod native_custody_tests {
    use super::*;
    use iroha_fs::{PrivateDirectory, PublishMode};

    #[test]
    fn fixed_secret_paths_are_admitted_through_native_private_handles() {
        let temporary = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(temporary.path().join("node")).unwrap();
        let secrets = root.create_child("secrets").unwrap();
        let data_dir = DataDir::new(root.path().to_owned());
        let file = NodeSecretFile::Validator;
        assert_eq!(existing_secret_path(&data_dir, file).unwrap(), None);
        secrets
            .write_atomic("validator.key", b"bounded fixture", PublishMode::CreateNew)
            .unwrap();
        assert_eq!(
            existing_secret_path(&data_dir, file).unwrap(),
            Some(data_dir.secret(file))
        );
        std::fs::hard_link(data_dir.secret(file), secrets.path().join("linked.key")).unwrap();
        assert!(existing_secret_path(&data_dir, file).is_err());
    }
}
