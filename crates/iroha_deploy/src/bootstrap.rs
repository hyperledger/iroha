//! Independently signed, bounded native checkpoints for developer-network bootstrap.
//!
//! The installed release selects [`ReleaseTrust`]; an HTTP response never supplies its key.
//! Authentication binds the network, reset generation, endpoints and complete native checkpoint.
//! [`ReleaseCheckpointStore`] retains a monotonic release watermark in owner-private storage.
//! This is bootstrap provenance, not a fresh committee readiness observation: callers still use
//! [`FinalityVerifier::observe`] before admitting operations on the parent network.
//! A running verifier retains its own advancing checkpoint; a release must never replace that
//! checkpoint with an older tip. Changing the installed authority fails closed against retained
//! releases and requires an independently authenticated key-rotation migration.
// TODO(DX5): qualify recurring signed Taira checkpoint publication and the connected dataspace
// provisioning flow using the approved installation profile's independently selected key/floor.

use std::{fs::File, path::Path, sync::Mutex};

use iroha_crypto::{Algorithm, Hash, PrivateKey, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    sumeragi_finality::{MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint},
};
use iroha_fs::{FileIdentity, OwnerDirectory, PrivateDirectory, PublishMode};
use norito::{Decode, Encode};

use crate::verify::finality::FinalityVerifier;

mod runtime;
pub use runtime::ParentFinalityStore;
mod amx_sources;
pub(crate) use amx_sources::{AmxSourceSelection, ParentBootstrapSources};
mod profile;
mod transport;
pub use profile::{
    InstalledNetworkProfile, InstalledNetworkProfiles, MAX_INSTALLED_NETWORK_PROFILES,
    MAX_INSTALLED_PROFILE_BYTES, NETWORK_PROFILES_FILENAME,
};
pub use transport::{CheckpointReadError, CheckpointTransport, MAX_DOWNLOADED_CHECKPOINT_BYTES};
mod provisioning;
pub use provisioning::{ReleaseBuildRegistry, ReleaseFaucet, ReleasePeer};
mod publication;
mod registry;
pub use publication::{
    NetworkPublicationPolicy, PinnedPublicationGenesis, PreparedNetworkPublication,
    prepare_network_publication,
};

const RELEASE_DOMAIN: &[u8] = b"iroha.developer.network-checkpoint.v1\0";
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// Maximum canonical signed bootstrap artifact accepted before any decoding.
pub const MAX_RELEASE_CHECKPOINT_BYTES: usize = MAX_FINALITY_CHECKPOINT_BYTES + 32 * 1024;
/// A release may authorize fresh bootstraps for at most one day.
pub const MAX_RELEASE_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000;

/// Failure to authenticate or durably retain an independently selected release.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// Native private-file custody or publication failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Another live operation holds bootstrap custody; retry within the existing deadline.
    #[error("network bootstrap custody is already in use")]
    Busy,
    /// Bounded input, signature, clock or monotonicity validation failed.
    #[error("network bootstrap: {0}")]
    Invalid(&'static str),
    /// The signed checkpoint failed native consensus verification.
    #[error(transparent)]
    Finality(#[from] crate::verify::finality::FinalityError),
}

type Result<T> = std::result::Result<T, BootstrapError>;

/// Trust distributed with an authenticated installation, never with a queried peer's response.
#[derive(Clone, Debug)]
pub struct ReleaseTrust {
    network_name: String,
    public_key: PublicKey,
    minimum_serial: u64,
}

impl ReleaseTrust {
    /// Select one installed Ed25519 release authority and the installation's rollback floor.
    ///
    /// # Errors
    /// Invalid network label, zero serial floor or a non-Ed25519 authority.
    pub fn new(network_name: String, public_key: PublicKey, minimum_serial: u64) -> Result<Self> {
        validate_network_name(&network_name)?;
        if minimum_serial == 0 || public_key.try_algorithm().ok() != Some(Algorithm::Ed25519) {
            return Err(BootstrapError::Invalid(
                "invalid installed release authority or floor",
            ));
        }
        Ok(Self {
            network_name,
            public_key,
            minimum_serial,
        })
    }
}

/// Signed network identity and retrieval policy; all fields are authenticated together.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::NetworkReleaseV1")]
pub struct NetworkRelease {
    /// Installed human-facing selection, such as `taira`.
    pub network_name: String,
    /// Strictly increasing publication serial across every reset of this network label.
    pub serial: u64,
    /// Monotonic reset generation; a different genesis requires a higher generation.
    pub generation: u64,
    /// Genesis-derived network identity, independent of DNS and peer claims.
    pub network_id: NetworkId,
    /// Consensus chain label authenticated with the selected genesis.
    pub chain_id: String,
    /// Explicit account-address profile authenticated with this network generation.
    pub account_chain_discriminant: u16,
    /// Qualified native World schema for independently verified current-state projections.
    pub native_world_schema: Hash,
    /// Inclusive release validity start in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive release expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Approved HTTPS Torii roots. Credentials, query strings and fragments are prohibited.
    pub torii_roots: Vec<String>,
    /// Exact BLS member-to-approved-root hints; the native verifier still selects the committee.
    pub peers: Vec<ReleasePeer>,
    /// Optional testnet funding and finite automatic spending allowances for a managed wallet.
    pub faucet: Option<ReleaseFaucet>,
    /// Explicit public build registry on this parent network; absence disables remote resolution.
    pub build_registry: Option<ReleaseBuildRegistry>,
    /// Hash of the complete canonical native checkpoint frame.
    pub checkpoint_hash: Hash,
    /// Authenticated checkpoint height, repeated for monotonic release comparison.
    pub checkpoint_height: u64,
    /// Authenticated checkpoint block hash, repeated to reject same-height equivocation.
    pub checkpoint_block_hash: Hash,
}

/// Sole canonical wire artifact, without a response-selected verification key.
#[derive(Debug, Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::SignedNetworkCheckpointV1")]
pub struct SignedNetworkCheckpoint {
    release: NetworkRelease,
    signature: Signature,
    checkpoint: Vec<u8>,
}

impl SignedNetworkCheckpoint {
    /// Sign a release whose metadata exactly describes an internally valid native checkpoint.
    /// The private release key remains a runtime input and is never retained in the artifact.
    ///
    /// # Errors
    /// Invalid metadata, substituted checkpoint, native verification or signing failure.
    pub fn sign(
        release: NetworkRelease,
        checkpoint: &SumeragiFinalityCheckpoint,
        private_key: &PrivateKey,
    ) -> Result<Self> {
        validate_release(&release)?;
        if private_key.algorithm() != Algorithm::Ed25519 {
            return Err(BootstrapError::Invalid(
                "release signing requires the installed Ed25519 authority",
            ));
        }
        let checkpoint = checkpoint
            .encode_canonical()
            .map_err(|_| BootstrapError::Invalid("invalid native checkpoint frame"))?;
        verify_checkpoint(&release, &checkpoint)?;
        let signature = Signature::try_new(private_key, &release_preimage(&release)?)
            .map_err(|_| BootstrapError::Invalid("release signing failed"))?;
        Ok(Self {
            release,
            signature,
            checkpoint,
        })
    }

    /// Encode the single canonical release artifact with a finite byte bound.
    ///
    /// # Errors
    /// Encoding failure or an oversized artifact.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        let bytes = norito::encode_canonical(self)
            .map_err(|_| BootstrapError::Invalid("cannot encode release artifact"))?;
        if bytes.len() > MAX_RELEASE_CHECKPOINT_BYTES {
            return Err(BootstrapError::Invalid(
                "release artifact exceeds byte bound",
            ));
        }
        Ok(bytes)
    }
}

/// Authenticated bootstrap material, exposed only after durable monotonic publication.
pub struct AuthenticatedBootstrap {
    release: NetworkRelease,
    verifier: FinalityVerifier,
    reset: bool,
}

impl AuthenticatedBootstrap {
    /// Independently authenticated identity, endpoints and expiry.
    pub fn release(&self) -> &NetworkRelease {
        &self.release
    }

    /// Whether this accepted artifact advances a previously retained reset generation.
    /// Callers must create a new context rather than relabel existing funds or journals.
    pub const fn is_network_reset(&self) -> bool {
        self.reset
    }

    /// Bind native HTTP observation clients to this release's approved endpoints and network.
    /// Endpoint hints cannot select the authenticated committee: the verifier still chooses each
    /// BLS member and verifies every returned chain. No credentials are copied between clients.
    ///
    /// # Errors
    /// Any client endpoint was not independently authorized by the signed release, or the
    /// transport's network, committee identity, endpoint bounds or deadline are invalid.
    pub fn http_source(
        &self,
        proof_clients: Vec<iroha::client::Client>,
        peer_clients: Vec<(iroha_model_base::peer::PeerId, iroha::client::Client)>,
        deadline: std::time::Instant,
    ) -> std::result::Result<
        crate::verify::http::HttpFinalitySource,
        crate::verify::http::HttpFinalityError,
    > {
        for client in proof_clients
            .iter()
            .chain(peer_clients.iter().map(|(_, client)| client))
        {
            if !self
                .release
                .torii_roots
                .iter()
                .any(|root| root == client.endpoint().as_str())
            {
                return Err(crate::verify::http::HttpFinalityError::Invalid(
                    "endpoint absent from signed release",
                ));
            }
        }
        crate::verify::http::HttpFinalitySource::new(
            self.release.network_id,
            std::num::NonZeroU64::new(self.verifier.checkpoint().height()).ok_or(
                crate::verify::http::HttpFinalityError::Invalid("checkpoint height"),
            )?,
            proof_clients,
            peer_clients,
            deadline,
        )
    }

    /// Consume the bootstrap and continue contiguous native finality verification.
    pub fn into_verifier(self) -> FinalityVerifier {
        self.verifier
    }
}

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::RetainedNetworkReleaseV1")]
struct RetainedRelease {
    artifact: SignedNetworkCheckpoint,
    last_verified_at_ms: u64,
}

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::ReleaseWatermarkV1")]
struct ReleaseWatermark {
    accepted: Option<RetainedRelease>,
}

/// Exclusive private custody of one installed network label's release watermark.
///
/// Keep this directory outside resettable developer generations. This release watermark is
/// separate from the later contiguous finality checkpoint, which its runtime must also retain.
pub struct ReleaseCheckpointStore {
    directory: PrivateDirectory,
    lock: File,
    state: Mutex<ReleaseStoreState>,
}

struct ReleaseStoreState {
    publication_uncertain: bool,
}

impl ReleaseCheckpointStore {
    /// Open or initialize native owner-private custody and acquire its exclusive lock.
    ///
    /// # Errors
    /// Invalid custody, unsafe path, another owner or durability failure.
    pub fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or(BootstrapError::Invalid("release custody path"))?;
        let parent = OwnerDirectory::open_or_create(
            path.parent()
                .ok_or(BootstrapError::Invalid("release custody path"))?,
        )?;
        // The unaccepted watermark is part of the first atomic directory publication. A crash
        // before it cannot leave a visible store that looks like lost accepted custody.
        let initial = norito::encode_canonical(&ReleaseWatermark { accepted: None })
            .map_err(|_| BootstrapError::Invalid("cannot initialize release watermark"))?;
        let _: ReleaseWatermark = decode(&initial, MAX_RELEASE_CHECKPOINT_BYTES)?;
        let directory = match parent
            .publish_private_child(name, &[("release.lock", &[]), ("accepted.nrt", &initial)])
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                PrivateDirectory::open(parent.path().join(name))?
            }
            Err(error) => return Err(error.into()),
        };
        let lock = directory.open_existing_lock("release.lock")?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => BootstrapError::Busy,
            std::fs::TryLockError::Error(error) => BootstrapError::Io(error),
        })?;
        lock.sync_all()?;
        directory.sync()?;
        Ok(Self {
            directory,
            lock,
            state: Mutex::new(ReleaseStoreState {
                publication_uncertain: false,
            }),
        })
    }

    /// Reauthenticate the retained release without network I/O while its signed policy is valid.
    ///
    /// The same independently installed authority, native checkpoint checks and clock watermark
    /// apply. Returns `None` only before first acceptance, after expiry, or when a newer installed
    /// serial floor requires refreshing the release. This never supplies fresh committee
    /// readiness; provider discovery and parent operations still perform their own observation.
    ///
    /// # Errors
    /// Unsafe or uncertain custody, invalid retained authority/checkpoint, or clock rollback.
    pub fn authenticate_retained(
        &self,
        trust: &ReleaseTrust,
        now_ms: u64,
    ) -> Result<Option<AuthenticatedBootstrap>> {
        let bytes = {
            let state = self
                .state
                .lock()
                .map_err(|_| BootstrapError::Invalid("release custody update was interrupted"))?;
            self.check_custody(&state)?;
            let Some(retained) = self.read_watermark()?.accepted else {
                return Ok(None);
            };
            verify_retained_release(trust, &retained, now_ms)?;
            if now_ms >= retained.artifact.release.expires_at_ms
                || retained.artifact.release.serial < trust.minimum_serial
            {
                return Ok(None);
            }
            retained.artifact.encode_canonical()?
        };
        self.authenticate(trust, &bytes, now_ms).map(Some)
    }

    /// Authenticate an untrusted release and checkpoint, then durably publish its watermark.
    /// Repeated exact artifacts are safe; older serials, clock rollback, changed same-generation
    /// genesis, regressed heights and same-height equivocation are rejected before publication.
    ///
    /// # Errors
    /// Bounds, canonical decoding, installed signature/floor, freshness, rollback or native
    /// checkpoint verification fails; failed writes never authorize network operations.
    pub fn authenticate(
        &self,
        trust: &ReleaseTrust,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<AuthenticatedBootstrap> {
        // Serialize in-process callers as well as retaining the native inter-process lock.
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapError::Invalid("release custody update was interrupted"))?;
        self.check_custody(&state)?;
        let artifact: SignedNetworkCheckpoint = decode(bytes, MAX_RELEASE_CHECKPOINT_BYTES)?;
        verify_release_signature(trust, &artifact)?;
        if artifact.release.serial < trust.minimum_serial {
            return Err(BootstrapError::Invalid(
                "release precedes installed rollback floor",
            ));
        }
        if now_ms < artifact.release.issued_at_ms || now_ms >= artifact.release.expires_at_ms {
            return Err(BootstrapError::Invalid("release is not currently valid"));
        }
        let previous = self.read_watermark()?.accepted;
        let mut reset = false;
        if let Some(previous) = previous {
            // Expiry limits fresh bootstrap, not the lifetime of a retained rollback watermark.
            verify_retained_release(trust, &previous, now_ms)?;
            reset = validate_successor(&previous.artifact.release, &artifact.release)?;
        }
        let verifier = verify_checkpoint(&artifact.release, &artifact.checkpoint)?;
        let release = artifact.release.clone();
        let retained = RetainedRelease {
            artifact,
            last_verified_at_ms: now_ms,
        };
        self.publish(&mut state, retained)?;
        Ok(AuthenticatedBootstrap {
            release,
            verifier,
            reset,
        })
    }

    fn check_custody(&self, state: &ReleaseStoreState) -> Result<()> {
        if state.publication_uncertain {
            return Err(BootstrapError::Invalid(
                "release publication uncertain; reopen custody",
            ));
        }
        self.directory.revalidate()?;
        if FileIdentity::of(&self.directory.open_read("release.lock")?)?
            != FileIdentity::of(&self.lock)?
        {
            return Err(BootstrapError::Invalid("release custody lock was replaced"));
        }
        Ok(())
    }

    fn read_watermark(&self) -> Result<ReleaseWatermark> {
        decode(
            &self
                .directory
                .read("accepted.nrt", MAX_RELEASE_CHECKPOINT_BYTES + 1024)?,
            MAX_RELEASE_CHECKPOINT_BYTES + 1024,
        )
    }

    fn publish(&self, state: &mut ReleaseStoreState, retained: RetainedRelease) -> Result<()> {
        self.directory.revalidate()?;
        if FileIdentity::of(&self.directory.open_read("release.lock")?)?
            != FileIdentity::of(&self.lock)?
        {
            return Err(BootstrapError::Invalid("release custody lock was replaced"));
        }
        let encoded = norito::encode_canonical(&ReleaseWatermark {
            accepted: Some(retained),
        })
        .map_err(|_| BootstrapError::Invalid("cannot encode retained release"))?;
        let _: ReleaseWatermark = decode(&encoded, MAX_RELEASE_CHECKPOINT_BYTES + 1024)?;
        if let Err(error) =
            self.directory
                .write_atomic("accepted.nrt", &encoded, PublishMode::Replace)
        {
            state.publication_uncertain = true;
            return Err(error.into());
        }
        Ok(())
    }
}

fn verify_retained_release(
    trust: &ReleaseTrust,
    retained: &RetainedRelease,
    now_ms: u64,
) -> Result<()> {
    verify_release_signature(trust, &retained.artifact)?;
    if retained.last_verified_at_ms < retained.artifact.release.issued_at_ms
        || retained.last_verified_at_ms >= retained.artifact.release.expires_at_ms
        || now_ms < retained.last_verified_at_ms
        || Hash::new(&retained.artifact.checkpoint) != retained.artifact.release.checkpoint_hash
    {
        return Err(BootstrapError::Invalid(
            "local clock or retained observation regressed",
        ));
    }
    Ok(())
}

fn decode<T: norito::codec::Decode + norito::NoritoSchema>(
    bytes: &[u8],
    limit: usize,
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(BootstrapError::Invalid(
            "release material exceeds byte bound",
        ));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| BootstrapError::Invalid("release material is not canonical"))
}

fn validate_network_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 48
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || !name.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(BootstrapError::Invalid("invalid installed network name"));
    }
    Ok(())
}

fn validate_release(release: &NetworkRelease) -> Result<()> {
    validate_network_name(&release.network_name)?;
    if release.serial == 0
        || release.generation == 0
        || release.chain_id.is_empty()
        || release.chain_id.len() > 1024
        || release.checkpoint_height < 2
        || release.checkpoint_height == u64::MAX
        || release.expires_at_ms <= release.issued_at_ms
        || release.expires_at_ms - release.issued_at_ms > MAX_RELEASE_VALIDITY_MS
        || release.torii_roots.is_empty()
        || release.torii_roots.len() > 32
    {
        return Err(BootstrapError::Invalid(
            "invalid bounded network release metadata",
        ));
    }
    let mut roots = std::collections::BTreeSet::new();
    for root in &release.torii_roots {
        if root.len() > 2048 {
            return Err(BootstrapError::Invalid(
                "signed Torii root exceeds byte bound",
            ));
        }
        let url = url::Url::parse(root)
            .map_err(|_| BootstrapError::Invalid("invalid signed Torii root"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with('/')
            || url.as_str() != root
            || !roots.insert(root)
        {
            return Err(BootstrapError::Invalid(
                "signed Torii roots must be unique canonical HTTPS roots",
            ));
        }
    }
    provisioning::validate(release)?;
    Ok(())
}

fn release_preimage(release: &NetworkRelease) -> Result<Vec<u8>> {
    let encoded = norito::encode_canonical(release)
        .map_err(|_| BootstrapError::Invalid("cannot encode release metadata"))?;
    if encoded.len() > MAX_MANIFEST_BYTES {
        return Err(BootstrapError::Invalid(
            "release metadata exceeds byte bound",
        ));
    }
    let mut preimage = Vec::with_capacity(RELEASE_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(RELEASE_DOMAIN);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

fn verify_release_signature(
    trust: &ReleaseTrust,
    artifact: &SignedNetworkCheckpoint,
) -> Result<()> {
    validate_release(&artifact.release)?;
    if artifact.release.network_name != trust.network_name {
        return Err(BootstrapError::Invalid(
            "release differs from installed network",
        ));
    }
    artifact
        .signature
        .verify(&trust.public_key, &release_preimage(&artifact.release)?)
        .map_err(|_| BootstrapError::Invalid("release signature differs from installed authority"))
}

fn verify_checkpoint(release: &NetworkRelease, bytes: &[u8]) -> Result<FinalityVerifier> {
    if bytes.is_empty()
        || bytes.len() > MAX_FINALITY_CHECKPOINT_BYTES
        || Hash::new(bytes) != release.checkpoint_hash
    {
        return Err(BootstrapError::Invalid(
            "checkpoint differs from signed release digest",
        ));
    }
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes)
        .map_err(|_| BootstrapError::Invalid("invalid canonical native checkpoint"))?;
    if checkpoint.height() != release.checkpoint_height
        || Hash::from(checkpoint.block_hash()) != release.checkpoint_block_hash
    {
        return Err(BootstrapError::Invalid(
            "checkpoint differs from signed height or block",
        ));
    }
    if checkpoint.tip().committee.iter().any(|validator| {
        !release
            .peers
            .iter()
            .any(|peer| peer.node_id.public_key() == &validator.public_key)
    }) {
        return Err(BootstrapError::Invalid(
            "signed release omits a checkpoint committee endpoint",
        ));
    }
    let native =
        iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &release.network_id,
            &release.chain_id,
        )
        .map_err(crate::verify::finality::FinalityError::from)?;
    if native.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global {
        return Err(BootstrapError::Invalid(
            "public parent release requires a committed global root",
        ));
    }
    Ok(FinalityVerifier::from_checkpoint(
        checkpoint,
        release.network_id,
        &release.chain_id,
    )?)
}

fn validate_successor(previous: &NetworkRelease, next: &NetworkRelease) -> Result<bool> {
    if next.serial < previous.serial
        || next.generation < previous.generation
        || next.issued_at_ms < previous.issued_at_ms
        || (next.serial == previous.serial && next != previous)
    {
        return Err(BootstrapError::Invalid(
            "release serial, generation or issue time regressed or equivocated",
        ));
    }
    if next.generation == previous.generation {
        if next.network_id != previous.network_id
            || next.chain_id != previous.chain_id
            || next.account_chain_discriminant != previous.account_chain_discriminant
            || next.checkpoint_height < previous.checkpoint_height
            || (next.checkpoint_height == previous.checkpoint_height
                && (next.checkpoint_block_hash != previous.checkpoint_block_hash
                    || next.checkpoint_hash != previous.checkpoint_hash))
        {
            return Err(BootstrapError::Invalid(
                "same-generation ledger identity or checkpoint changed",
            ));
        }
        Ok(false)
    } else if next.network_id == previous.network_id {
        Err(BootstrapError::Invalid(
            "network reset must authenticate a different genesis",
        ))
    } else {
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
