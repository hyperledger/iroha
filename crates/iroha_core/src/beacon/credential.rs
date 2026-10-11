//! Runtime credential codec for global-beacon seat shares.
//!
//! A seat credential carries complete public DKG transcripts plus the
//! zeroizing aggregate scalar triple owned by one signer seat. Its header binds
//! the exact runtime-provider qualification (slot, handle, revision and public
//! inventory digest) and the genesis-derived network identity. The producer
//! ([`encode_global_beacon_partial_signer_credential_v1`]) checks every canonical
//! secret component against its exact validated public transcript and seat through
//! the existing deterministic commitment equation. The runtime importer
//! ([`decode_global_beacon_partial_signer_credential_v1`]) also performs its genuine
//! partial-signing capability self-test. Credential production does not generate
//! an unpersisted randomized proof or encode any proof into the credential wire.
//!
//! The consensus-threshold framing (header, secret scalar triple, public
//! inventory digest and bounded canonical encoding) is shared with the
//! Parliament timed-release credential owned by the node's runtime broker.
//! Neither producer nor importer performs file I/O; credential bytes are handed
//! directly to a supervisor credential facility.

use iroha_allocation::AllocationBudget;
use iroha_data_model::{NetworkId, consensus::GlobalThresholdBeaconKeySessionV1};
use norito::{DecodeLimits, NoritoDeserialize, NoritoSerialize, core::PayloadRef};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    GlobalThresholdBeaconSessionBindingV1, GlobalThresholdBeaconSessionError,
    RuntimeGlobalThresholdBeaconShareCustodyV1, ValidatedGlobalThresholdBeaconSessionV1,
    validate_global_threshold_beacon_session_v1,
};

/// Stable runtime-provider slot wire identifier of the global-beacon partial signer.
pub const GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1: u16 = 59;
/// Sole first-release consensus-threshold credential and inventory version.
pub const CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1: u16 = 1;
/// Maximum canonical byte length of one consensus-threshold credential.
pub const MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of key sessions carried by one consensus-threshold credential.
pub const MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1: usize = 64;
/// Bounded decode limits for one consensus-threshold credential of `len` encoded bytes.
///
/// Sequence length and nesting depth are fixed by the credential layout. Total
/// elements and allocation follow Norito's canonical per-length bounds: a
/// signed all-edge DKG transcript decodes to far more than it encodes (two
/// 31-seat sessions encode to 3.8 MB and allocate 48–64 MiB and 2–4 million
/// elements), so a fixed budget rejects valid large committees, while a
/// per-length budget keeps a small input from reserving a large one.
/// [`decode_consensus_threshold_credential_v1`] rejects credentials above
/// [`MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1`] before decoding.
#[must_use]
pub const fn consensus_threshold_credential_decode_limits_v1(len: usize) -> DecodeLimits {
    let canonical = norito::canonical_decode_limits(len);
    DecodeLimits::new(
        16_384,
        canonical.max_field_bytes(),
        canonical.max_total_elements(),
        canonical.max_total_allocated_bytes(),
        64,
    )
}

/// Decode one canonical consensus-threshold credential frame.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialDecodeErrorV1::Rejected`] for empty,
/// oversized, malformed or intrinsically over-limit frames. A refusal from the
/// original enclosing decode scope or physical allocator retains its exact cause
/// in [`ConsensusThresholdCredentialDecodeErrorV1::Resource`], even after that
/// scope ends. This classification does not fund the raw decoded graph.
pub fn decode_consensus_threshold_credential_v1<T>(
    bytes: &[u8],
) -> Result<T, ConsensusThresholdCredentialDecodeErrorV1>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 {
        return Err(ConsensusThresholdCredentialDecodeErrorV1::Rejected);
    }
    norito::decode_canonical_for_admission(
        bytes,
        consensus_threshold_credential_decode_limits_v1(bytes.len()),
    )
    .map_err(|error| match error.kind() {
        norito::core::DecodeAttemptErrorKind::Invalid => {
            ConsensusThresholdCredentialDecodeErrorV1::Rejected
        }
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
        | norito::core::DecodeAttemptErrorKind::Allocator => {
            if cfg!(all(test, sumeragi_core_mutation = "HC89")) {
                ConsensusThresholdCredentialDecodeErrorV1::Rejected
            } else {
                ConsensusThresholdCredentialDecodeErrorV1::Resource(error)
            }
        }
    })
}

/// One canonical frame decode failure, retaining host-local refusal provenance.
///
/// Display is payload-free; the original non-wire cause is available through
/// [`std::error::Error::source`]. No allocation-pool release token is manufactured.
#[derive(Debug, Error)]
pub enum ConsensusThresholdCredentialDecodeErrorV1 {
    /// The complete frame or its intrinsic codec limits were invalid.
    #[error("consensus threshold-signer credential was rejected")]
    Rejected,
    /// The enclosing decode scope or physical allocator refused this exact attempt.
    #[error("consensus threshold-signer credential decoder is unavailable")]
    Resource(#[source] norito::core::DecodeAttemptError),
}

const CONSENSUS_THRESHOLD_CREDENTIAL_MAGIC_V1: [u8; 8] = *b"IRTHR001";
const CONSENSUS_THRESHOLD_PUBLIC_INVENTORY_DOMAIN_V1: &[u8] =
    b"iroha.runtime-consensus-threshold.public-inventory.v1";

/// Payload-free consensus-threshold credential codec failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConsensusThresholdCredentialErrorV1 {
    /// The qualification, network, session inventory, or share was invalid.
    #[error("consensus threshold-signer credential was rejected")]
    Rejected,
    /// Canonical encoding failed or exceeded its fixed byte ceiling.
    #[error("consensus threshold-signer credential encoding failed")]
    Encoding,
}

/// Import failure preserving the original finite resource refusal separately from bad credentials.
#[derive(Debug, Error)]
pub enum GlobalBeaconCredentialImportErrorV1 {
    /// The canonical credential, qualification, inventory or private share was rejected.
    #[error(transparent)]
    Credential(#[from] ConsensusThresholdCredentialErrorV1),
    /// Original local raw-decoder refusal; no protocol-invalid judgment was made.
    #[error("consensus threshold-signer credential decoder is unavailable")]
    DecodeResource(#[source] norito::core::DecodeAttemptError),
    /// Admission or physical construction of the retained public graph failed locally.
    #[error(transparent)]
    Session(GlobalThresholdBeaconSessionError),
}

impl From<ConsensusThresholdCredentialDecodeErrorV1> for GlobalBeaconCredentialImportErrorV1 {
    fn from(error: ConsensusThresholdCredentialDecodeErrorV1) -> Self {
        match error {
            ConsensusThresholdCredentialDecodeErrorV1::Rejected => {
                Self::Credential(ConsensusThresholdCredentialErrorV1::Rejected)
            }
            ConsensusThresholdCredentialDecodeErrorV1::Resource(error) => {
                Self::DecodeResource(error)
            }
        }
    }
}

impl From<GlobalThresholdBeaconSessionError> for GlobalBeaconCredentialImportErrorV1 {
    fn from(error: GlobalThresholdBeaconSessionError) -> Self {
        match error {
            GlobalThresholdBeaconSessionError::Invalid(_) => {
                Self::Credential(ConsensusThresholdCredentialErrorV1::Rejected)
            }
            local => Self::Session(local),
        }
    }
}

/// Public header framing every consensus-threshold signer credential.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[norito(decode_fields)]
pub struct ConsensusThresholdCredentialHeaderV1 {
    /// Fixed credential magic `IRTHR001`.
    pub magic: [u8; 8],
    /// Credential version; only [`CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1`] is admitted.
    pub version: u16,
    /// Stable runtime-provider slot wire identifier.
    pub slot: u16,
    /// Genesis-derived network identity bound by every carried session.
    pub network_id: NetworkId,
    /// Production runtime-provider handle.
    pub handle: String,
    /// Nonzero public provider-catalog revision.
    pub revision: u64,
    /// Public inventory digest configured as the provider policy digest.
    pub policy_digest: [u8; 32],
}

impl ConsensusThresholdCredentialHeaderV1 {
    /// Build a current-version header for one runtime-provider slot.
    #[must_use]
    pub fn new(
        slot: u16,
        network_id: NetworkId,
        handle: String,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            magic: CONSENSUS_THRESHOLD_CREDENTIAL_MAGIC_V1,
            version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
            slot,
            network_id,
            handle,
            revision,
            policy_digest,
        }
    }

    /// Require this header to name exactly the expected slot, network and qualification.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusThresholdCredentialErrorV1::Rejected`] for a wrong
    /// magic, version, slot, network, handle, revision or policy digest.
    pub fn validate(
        &self,
        slot: u16,
        network_id: &NetworkId,
        handle: &str,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Result<(), ConsensusThresholdCredentialErrorV1> {
        if self.magic != CONSENSUS_THRESHOLD_CREDENTIAL_MAGIC_V1
            || self.version != CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1
            || self.slot != slot
            || self.network_id != *network_id
            || self.handle != handle
            || self.revision != revision
            || self.policy_digest != policy_digest
            || self.revision == 0
            || self.policy_digest == [0; 32]
        {
            return Err(ConsensusThresholdCredentialErrorV1::Rejected);
        }
        Ok(())
    }
}

/// Zeroizing wire owner of one secret `(s, r, u)` scalar triple.
///
/// It has no `Clone` or `Debug` surface and scrubs itself on drop.
#[derive(NoritoSerialize, NoritoDeserialize)]
#[norito(decode_fields)]
pub struct ConsensusThresholdSecretScalarTripleV1 {
    components: [[u8; 32]; 3],
}

impl ConsensusThresholdSecretScalarTripleV1 {
    /// Move a zeroizing triple into its wire owner, scrubbing the source.
    #[must_use]
    pub fn from_zeroizing(mut components: Zeroizing<[[u8; 32]; 3]>) -> Self {
        Self {
            components: std::mem::take(&mut *components),
        }
    }

    /// Move the triple back into a zeroizing owner, scrubbing the wire owner.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<[[u8; 32]; 3]> {
        Zeroizing::new(std::mem::take(&mut self.components))
    }
}

impl Drop for ConsensusThresholdSecretScalarTripleV1 {
    fn drop(&mut self) {
        self.components.zeroize();
    }
}

/// Compute the domain-separated digest of one canonical public inventory.
///
/// V1 computes `SHA-256(domain || u64_be(encoded_len) || canonical_norito(inventory))`.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialErrorV1::Encoding`] for an empty or
/// oversized encoding and [`ConsensusThresholdCredentialErrorV1::Rejected`]
/// for the all-zero digest.
pub fn consensus_threshold_public_inventory_digest_v1<T: NoritoSerialize>(
    inventory: &T,
) -> Result<[u8; 32], ConsensusThresholdCredentialErrorV1> {
    use sha2::Digest as _;
    struct CanonicalDigestWriter {
        digest: sha2::Sha256,
        remaining: usize,
    }
    impl std::io::Write for CanonicalDigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            self.digest.update(bytes);
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let encoded_len = norito::canonical_frame_len(inventory)
        .map_err(|_| ConsensusThresholdCredentialErrorV1::Encoding)?;
    if encoded_len == 0 || encoded_len > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 {
        return Err(ConsensusThresholdCredentialErrorV1::Encoding);
    }
    let mut digest = sha2::Sha256::new();
    digest.update(CONSENSUS_THRESHOLD_PUBLIC_INVENTORY_DOMAIN_V1);
    digest.update(
        u64::try_from(encoded_len)
            .map_err(|_| ConsensusThresholdCredentialErrorV1::Encoding)?
            .to_be_bytes(),
    );
    let mut writer = CanonicalDigestWriter {
        digest,
        remaining: encoded_len,
    };
    norito::core::write_canonical_to_writer(inventory, &mut writer)
        .map_err(|_| ConsensusThresholdCredentialErrorV1::Encoding)?;
    if writer.remaining != 0 {
        return Err(ConsensusThresholdCredentialErrorV1::Encoding);
    }
    let digest: [u8; 32] = writer.digest.finalize().into();
    if digest == [0; 32] {
        return Err(ConsensusThresholdCredentialErrorV1::Rejected);
    }
    Ok(digest)
}

/// Encode one secret credential with the canonical layout and a fixed byte ceiling.
///
/// Ambient Norito layout flags are ignored, so every producer emits the one
/// canonical byte string accepted by the importer.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialErrorV1::Encoding`] when encoding
/// fails, is empty, or exceeds [`MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1`].
pub fn encode_consensus_threshold_secret_credential_v1<T: NoritoSerialize>(
    wire: &T,
) -> Result<Zeroizing<Vec<u8>>, ConsensusThresholdCredentialErrorV1> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let encoded = Zeroizing::new(
        norito::core::to_bytes_bounded(wire, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1)
            .map_err(|_| ConsensusThresholdCredentialErrorV1::Encoding)?,
    );
    if encoded.is_empty() {
        return Err(ConsensusThresholdCredentialErrorV1::Encoding);
    }
    Ok(encoded)
}

/// Require a nonempty session inventory within the fixed credential ceiling.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialErrorV1::Rejected`] for an empty or
/// excessive inventory.
pub fn validate_consensus_threshold_session_count_v1(
    count: usize,
) -> Result<(), ConsensusThresholdCredentialErrorV1> {
    if count == 0 || count > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1 {
        return Err(ConsensusThresholdCredentialErrorV1::Rejected);
    }
    Ok(())
}

/// Validate the public qualification a producer is about to bind into a credential.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialErrorV1::Rejected`] for an all-zero
/// network, a non-production handle, a zero revision, or a zero digest.
pub fn validate_consensus_threshold_provisioning_v1(
    network_id: &NetworkId,
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
) -> Result<(), ConsensusThresholdCredentialErrorV1> {
    if network_id.as_bytes().iter().all(|byte| *byte == 0)
        || iroha_config::parameters::validate_production_runtime_handle(handle).is_err()
        || revision == 0
        || policy_digest == [0; 32]
    {
        return Err(ConsensusThresholdCredentialErrorV1::Rejected);
    }
    Ok(())
}

/// One global-beacon share supplied by an authenticated DKG provisioning path.
///
/// The type has no serialization, cloning, or debug surface. Use
/// [`encode_global_beacon_partial_signer_credential_v1`] to produce the
/// zeroizing bytes handed directly to a supervisor credential facility.
pub struct RuntimeGlobalBeaconShareProvisioningV1 {
    public_session: ValidatedGlobalThresholdBeaconSessionV1,
    signer_index: u16,
    components: ConsensusThresholdSecretScalarTripleV1,
}

/// Borrowed canonical credential source tied to its original public and scalar owners.
///
/// This view neither copies nor transfers secret custody or attests signing capability.
/// The sole credential encoder verifies its exact prepared session pointer, seat,
/// canonical scalar triple and public commitment before writing original output.
#[derive(Clone, Copy)]
pub struct GlobalBeaconCredentialSourceV1<'a> {
    session: &'a ValidatedGlobalThresholdBeaconSessionV1,
    seat: u16,
    components: &'a [[u8; 32]; 3],
}
impl<'a> GlobalBeaconCredentialSourceV1<'a> {
    pub(in crate::beacon) fn new(
        session: &'a ValidatedGlobalThresholdBeaconSessionV1,
        seat: u16,
        components: &'a [[u8; 32]; 3],
    ) -> Self {
        Self {
            session,
            seat,
            components,
        }
    }
    /// Borrow the exact original authenticated public session owner.
    #[must_use]
    pub fn authenticated_session(self) -> &'a ValidatedGlobalThresholdBeaconSessionV1 {
        self.session
    }
    /// Return the one-based seat without exposing private components.
    #[must_use]
    pub const fn signer_index(self) -> u16 {
        self.seat
    }
}

impl RuntimeGlobalBeaconShareProvisioningV1 {
    /// Retain one sealed public transcript and consume its zeroizing aggregate share.
    #[must_use]
    pub fn new(
        public_session: ValidatedGlobalThresholdBeaconSessionV1,
        signer_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Self {
        Self {
            public_session,
            signer_index,
            components: ConsensusThresholdSecretScalarTripleV1::from_zeroizing(components),
        }
    }

    /// Borrow the original scalar and public owners for the single canonical encoder.
    #[must_use]
    pub fn credential_source(&self) -> GlobalBeaconCredentialSourceV1<'_> {
        GlobalBeaconCredentialSourceV1::new(
            &self.public_session,
            self.signer_index,
            &self.components.components,
        )
    }

    /// Complete public DKG transcript this share belongs to, borrowed from its original owner.
    #[must_use]
    pub fn public_session(&self) -> &GlobalThresholdBeaconKeySessionV1 {
        self.public_session.record()
    }

    /// Borrow the authenticated original owner for preparing output before exposing any share.
    pub fn authenticated_session(&self) -> &ValidatedGlobalThresholdBeaconSessionV1 {
        &self.public_session
    }

    /// Whether the retained public transcript belongs to the caller's original pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.public_session.belongs_to(budget)
    }

    /// One-based signer seat of this share.
    #[must_use]
    pub fn signer_index(&self) -> u16 {
        self.signer_index
    }
}

#[derive(NoritoSerialize, NoritoDeserialize)]
struct RuntimeGlobalBeaconShareCredentialWireV1 {
    public_session: GlobalThresholdBeaconKeySessionV1,
    signer_index: u16,
    components: ConsensusThresholdSecretScalarTripleV1,
}

#[derive(NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::beacon::credential::RuntimeGlobalBeaconSignerCredentialWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_signer_credential"
)]
struct RuntimeGlobalBeaconSignerCredentialWireV1 {
    header: ConsensusThresholdCredentialHeaderV1,
    sessions: Vec<RuntimeGlobalBeaconShareCredentialWireV1>,
}

struct CredentialSequence<T>(arrayvec::ArrayVec<T, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1>);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for CredentialSequence<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(writer, self.0.iter())
    }
}

#[derive(NoritoSerialize)]
struct RuntimeGlobalBeaconPublicInventoryEntryWireV1<'a> {
    public_session: PayloadRef<'a, GlobalThresholdBeaconKeySessionV1>,
    signer_index: u16,
}

#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::beacon::credential::RuntimeGlobalBeaconPublicInventoryWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_public_inventory"
)]
struct RuntimeGlobalBeaconPublicInventoryWireV1<'a> {
    version: u16,
    slot: u16,
    network_id: NetworkId,
    sessions: CredentialSequence<RuntimeGlobalBeaconPublicInventoryEntryWireV1<'a>>,
}

fn global_beacon_public_inventory_wire_v1<'a>(
    network_id: NetworkId,
    sessions: impl IntoIterator<Item = (&'a GlobalThresholdBeaconKeySessionV1, u16)>,
) -> Result<RuntimeGlobalBeaconPublicInventoryWireV1<'a>, ConsensusThresholdCredentialErrorV1> {
    let mut entries = arrayvec::ArrayVec::new();
    for (public_session, signer_index) in sessions {
        if public_session.network_id != network_id {
            return Err(ConsensusThresholdCredentialErrorV1::Rejected);
        }
        entries
            .try_push(RuntimeGlobalBeaconPublicInventoryEntryWireV1 {
                public_session: PayloadRef(public_session),
                signer_index,
            })
            .map_err(|_| ConsensusThresholdCredentialErrorV1::Rejected)?;
    }
    validate_consensus_threshold_session_count_v1(entries.len())?;
    entries.sort_unstable_by(|left, right| {
        left.public_session
            .session_id
            .cmp(&right.public_session.session_id)
            .then_with(|| left.signer_index.cmp(&right.signer_index))
    });
    let sessions = CredentialSequence(entries);
    Ok(RuntimeGlobalBeaconPublicInventoryWireV1 {
        version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
        slot: GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1,
        network_id,
        sessions,
    })
}

/// Compute the canonical public global-beacon session-and-seat inventory digest.
///
/// This digest is the exact value configured as the provider policy digest. It
/// commits to the complete public DKG transcript for every provisioned session
/// and to the local signer seat, but never serializes or hashes private share
/// components. V1 computes
/// `SHA-256(domain || u64_be(encoded_len) || canonical_norito(inventory))`,
/// where the inventory contains version 1, the role slot, the exact network,
/// and entries sorted by session identifier then signer index.
///
/// # Errors
///
/// Rejects empty, excessive, or cross-network inventories and encoding failure.
#[expect(
    single_use_lifetimes,
    reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
)]
pub fn global_beacon_partial_signer_inventory_digest_v1<'a>(
    network_id: NetworkId,
    sessions: impl IntoIterator<Item = &'a RuntimeGlobalBeaconShareProvisioningV1>,
) -> Result<[u8; 32], ConsensusThresholdCredentialErrorV1> {
    let inventory = global_beacon_public_inventory_wire_v1(
        network_id,
        sessions
            .into_iter()
            .map(|session| (session.public_session.record(), session.signer_index)),
    )?;
    consensus_threshold_public_inventory_digest_v1(&inventory)
}

/// Compute the same beacon inventory binding from public sessions and seats only.
///
/// # Errors
///
/// Rejects empty, excessive, or cross-network inventories and encoding failure.
pub fn global_beacon_partial_signer_public_inventory_digest_v1(
    network_id: NetworkId,
    sessions: &[(&GlobalThresholdBeaconKeySessionV1, u16)],
) -> Result<[u8; 32], ConsensusThresholdCredentialErrorV1> {
    let inventory = global_beacon_public_inventory_wire_v1(
        network_id,
        sessions
            .iter()
            .map(|(session, signer_index)| (*session, *signer_index)),
    )?;
    consensus_threshold_public_inventory_digest_v1(&inventory)
}

mod prepared_output;
pub use prepared_output::{
    GlobalBeaconCredentialEncodeErrorV1, PreparedGlobalBeaconCredentialV1,
    SecretConsensusThresholdCredentialV1, encode_global_beacon_partial_signer_credential_v1,
};

/// Decode and import one global-beacon seat credential for an exact qualification.
///
/// The header must name the global-beacon slot, `network_id` and the configured
/// `handle`, `revision` and `policy_digest`. The session vector must be
/// strictly sorted, and the recomputed public inventory digest must equal the
/// header digest before any share is imported. Every share is replayed through
/// Core's share-import validation.
///
/// # Errors
///
/// Returns [`ConsensusThresholdCredentialErrorV1::Rejected`] for noncanonical
/// bytes, a substituted header, a reordered or duplicate inventory, a digest
/// mismatch, or a share that does not match its public transcript and seat.
pub fn decode_global_beacon_partial_signer_credential_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
    budget: &AllocationBudget,
) -> Result<RuntimeGlobalThresholdBeaconShareCustodyV1, GlobalBeaconCredentialImportErrorV1> {
    let (custody, shares) = decode_global_beacon_inventory_v1(
        bytes,
        network_id,
        handle,
        revision,
        policy_digest,
        budget,
    )?;
    drop(shares);
    Ok(custody)
}

/// Decode one exactly bound credential and return its sealed, validated shares.
///
/// The complete credential is decoded once. Every public session is admitted
/// from `budget`, and the returned provisioning shares retain that same graph.
/// Extending an inventory reuses these owners through canonical encoding.
///
/// # Errors
/// Returns a rejected credential or the original local session resource failure.
pub fn decode_global_beacon_partial_signer_credential_shares_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
    budget: &AllocationBudget,
) -> Result<Vec<RuntimeGlobalBeaconShareProvisioningV1>, GlobalBeaconCredentialImportErrorV1> {
    let (custody, shares) = decode_global_beacon_inventory_v1(
        bytes,
        network_id,
        handle,
        revision,
        policy_digest,
        budget,
    )?;
    drop(custody);
    Ok(shares)
}

fn decode_global_beacon_inventory_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    handle: &str,
    revision: u64,
    policy_digest: [u8; 32],
    budget: &AllocationBudget,
) -> Result<
    (
        RuntimeGlobalThresholdBeaconShareCustodyV1,
        Vec<RuntimeGlobalBeaconShareProvisioningV1>,
    ),
    GlobalBeaconCredentialImportErrorV1,
> {
    // TODO: replace the raw credential DTO decode and its outer inventory buffers
    // with physical prepaid decoding; the retained session graph is separately
    // admitted from the caller's original pool, never from a per-import pool.
    let wire: RuntimeGlobalBeaconSignerCredentialWireV1 =
        decode_consensus_threshold_credential_v1(bytes)?;
    wire.header.validate(
        GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1,
        network_id,
        handle,
        revision,
        policy_digest,
    )?;
    validate_consensus_threshold_session_count_v1(wire.sessions.len())?;
    if wire.sessions.windows(2).any(|pair| {
        pair[0]
            .public_session
            .session_id
            .cmp(&pair[1].public_session.session_id)
            .then_with(|| pair[0].signer_index.cmp(&pair[1].signer_index))
            .is_ge()
    }) {
        return Err(ConsensusThresholdCredentialErrorV1::Rejected.into());
    }
    let public_inventory = global_beacon_public_inventory_wire_v1(
        *network_id,
        wire.sessions
            .iter()
            .map(|session| (&session.public_session, session.signer_index)),
    )?;
    if consensus_threshold_public_inventory_digest_v1(&public_inventory)?
        != wire.header.policy_digest
    {
        return Err(ConsensusThresholdCredentialErrorV1::Rejected.into());
    }
    drop(public_inventory);
    let custody = RuntimeGlobalThresholdBeaconShareCustodyV1::new();
    let mut shares = Vec::with_capacity(wire.sessions.len());
    for session in wire.sessions {
        let binding = global_beacon_session_binding_v1(&session.public_session);
        let public_session =
            validate_global_threshold_beacon_session_v1(&session.public_session, &binding, budget)?;
        custody
            .import_components(
                public_session.clone(),
                session.signer_index,
                Zeroizing::new(session.components.components),
            )
            .map_err(|_| ConsensusThresholdCredentialErrorV1::Rejected)?;
        shares.push(RuntimeGlobalBeaconShareProvisioningV1 {
            public_session,
            signer_index: session.signer_index,
            components: session.components,
        });
    }
    Ok((custody, shares))
}

/// Read the public header of one canonical global-beacon seat credential.
///
/// The complete credential is decoded canonically, so no header is read from
/// malformed, truncated or trailing bytes. Every carried share is dropped, and
/// scrubbed, before this returns. The header is not checked against any
/// expected qualification: a launcher that derives the provider binding from
/// it must still import the credential through
/// [`decode_global_beacon_partial_signer_credential_v1`] with the header's
/// handle, revision and policy digest and the expected network.
///
/// # Errors
///
/// Returns a completed rejection for malformed or intrinsically over-limit bytes,
/// or the exact local decoder refusal without judging the credential invalid.
pub fn global_beacon_partial_signer_credential_header_v1(
    bytes: &[u8],
) -> Result<ConsensusThresholdCredentialHeaderV1, ConsensusThresholdCredentialDecodeErrorV1> {
    let RuntimeGlobalBeaconSignerCredentialWireV1 { header, sessions } =
        decode_consensus_threshold_credential_v1(bytes)?;
    drop(sessions);
    Ok(header)
}

fn global_beacon_session_binding_v1(
    record: &GlobalThresholdBeaconKeySessionV1,
) -> GlobalThresholdBeaconSessionBindingV1 {
    GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.network_id,
        session_id: record.session_id,
        roster_hash: record.roster_hash,
        transcript_hash: record.transcript_hash,
    }
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;

#[cfg(test)]
mod prepared_scalar_wire_tests {
    use super::*;

    #[test]
    fn scalar_triple_keeps_its_exact_single_positional_field_payload() {
        let wire = ConsensusThresholdSecretScalarTripleV1::from_zeroizing(Zeroizing::new([
            [0x11; 32], [0x22; 32], [0x33; 32],
        ]));
        let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let mut payload = Vec::new();
        norito::core::serialize_to_writer(&wire, &mut payload).unwrap();
        // The one positional field is a nested array, whose three children each
        // contain 32 length-prefixed scalar bytes. Its payload is 3 * (1 + 64)
        // bytes, so the fixed V1 compact field length is [0xc3, 0x01].
        let mut expected = vec![0xc3, 0x01];
        for component in [[0x11; 32], [0x22; 32], [0x33; 32]] {
            expected.push(64);
            for byte in component {
                expected.push(1);
                expected.push(byte);
            }
        }
        assert_eq!(payload, expected);
        // This secret is one positional field of its native credential owner,
        // not a separately schema-framed public value.
        let limits = norito::canonical_decode_limits(payload.len());
        let scratch_bytes = limits.max_total_allocated_bytes();
        let counter_bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
        let pool = AllocationBudget::new(
            scratch_bytes
                .checked_add(counter_bytes)
                .expect("finite scalar fixture grant fits usize"),
        );
        let scratch = pool
            .try_reserve_bytes(scratch_bytes)
            .expect("fund original scalar decoder scratch");
        let context = norito::core::DecodeBudgetContext::try_new_owned(limits, &pool)
            .expect("fund original scalar decoder counter");
        let (decoded, used) = context
            .with(|| {
                norito::core::decode_field_canonical::<ConsensusThresholdSecretScalarTripleV1>(
                    &payload,
                )
            })
            .unwrap();
        assert_eq!(used, payload.len());
        assert_eq!(
            *decoded.into_zeroizing(),
            [[0x11; 32], [0x22; 32], [0x33; 32]]
        );
        assert_eq!(*wire.into_zeroizing(), [[0x11; 32], [0x22; 32], [0x33; 32]]);
        drop(context);
        assert_eq!(pool.reserved_bytes(), scratch_bytes);
        drop(scratch);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn named_private_scalar_storage_is_scrubbed_by_the_original_drop() {
        let mut wire = std::mem::ManuallyDrop::new(
            ConsensusThresholdSecretScalarTripleV1::from_zeroizing(Zeroizing::new([[0x77; 32]; 3])),
        );
        let bytes = std::ptr::addr_of!(wire.components).cast::<u8>();
        // SAFETY: the ManuallyDrop keeps this stack allocation live. Calling
        // the original destructor once neither frees nor moves these inline
        // bytes; inspect only their byte representation, never a dropped T.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut wire);
            assert!(
                std::slice::from_raw_parts(bytes, 96)
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
}
