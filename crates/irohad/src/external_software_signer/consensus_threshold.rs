//! Runtime-credential software custody for consensus threshold-signing broker slots.
//!
//! The standard broker reads two fixed supervisor credential names only when
//! the public catalog requests the corresponding slot. Credential envelopes
//! bind the exact provider qualification and genesis-derived network identity
//! to complete public DKG transcripts plus zeroizing scalar triples. Startup
//! replays Core's cryptographic import checks before exposing either backend.
//! Core owns the global-beacon credential codec and the shared credential
//! framing (`iroha_core::beacon::credential`); this module owns the Parliament
//! timed-release codec, the launchd bundle, and broker backend resolution.
//!
//! This is ordinary process-local software custody. It does not claim
//! proactive refresh, post-quantum security, or tolerance of process-memory
//! compromise. Rotation is a supervisor generation change: publish a bumped
//! public provider-catalog revision with the matching replacement credential
//! inventory, then restart the broker so the old process and shares are gone.
//! Prepared rotation appends the target share while preserving the full incumbent inventory;
//! a restart imports both, and only consensus chooses which session serves a pulse.
//! There is no hot reload, and rolling back both catalog and credential rolls
//! back this operational retirement. Core's committed-state retirement gates
//! remain the authority for deciding when an old share may be removed.

mod parliament_funding;
mod prepared;
pub use parliament_funding::RuntimeParliamentTleCredentialFundingErrorV1;
mod provisioning_command;
pub use prepared::{
    RuntimePreparedGlobalBeaconCredentialV1, prepare_global_beacon_transition_credential_v1,
};
pub(crate) use provisioning_command::dispatch_if_requested as dispatch_beacon_custody_preparation_if_requested;

use crate::runtime_credential::{RuntimeCredentialErrorV1, load_bounded_runtime_credential_v1};
use crate::{
    ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1,
    GlobalBeaconPartialSignerBrokerBackendV1, IrohaRuntimeProviderBindingV1,
    IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderRegistryErrorV1,
    IrohaRuntimeProviderSlotV1, ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    ParliamentTlePartialReleaseSignerBrokerBackendV1, RuntimeProviderBrokerBackendRegistryV1,
    RuntimeProviderBrokerBackendsV1,
};
use iroha_allocation::AllocationBudget;
use iroha_core::beacon::RuntimeGlobalThresholdBeaconShareCustodyV1;
use iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1;
use iroha_core::beacon::credential::CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1;
use iroha_core::beacon::credential::ConsensusThresholdCredentialDecodeErrorV1;
use iroha_core::beacon::credential::ConsensusThresholdCredentialErrorV1;
use iroha_core::beacon::credential::ConsensusThresholdCredentialHeaderV1;
use iroha_core::beacon::credential::ConsensusThresholdSecretScalarTripleV1;
use iroha_core::beacon::credential::GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1;
use iroha_core::beacon::credential::MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1;
use iroha_core::beacon::credential::RuntimeGlobalBeaconShareProvisioningV1;
use iroha_core::beacon::credential::consensus_threshold_public_inventory_digest_v1;
#[cfg(test)]
use iroha_core::beacon::credential::decode_consensus_threshold_credential_v1;
use iroha_core::beacon::credential::decode_global_beacon_partial_signer_credential_shares_v1;
use iroha_core::beacon::credential::decode_global_beacon_partial_signer_credential_v1;
use iroha_core::beacon::credential::encode_consensus_threshold_secret_credential_v1;
use iroha_core::beacon::credential::encode_global_beacon_partial_signer_credential_v1;
use iroha_core::beacon::credential::global_beacon_partial_signer_inventory_digest_v1;
use iroha_core::beacon::credential::validate_consensus_threshold_provisioning_v1;
use iroha_core::beacon::credential::validate_consensus_threshold_session_count_v1;
use iroha_core::beacon::credential::{
    GlobalBeaconCredentialEncodeErrorV1, GlobalBeaconCredentialImportErrorV1,
    PreparedGlobalBeaconCredentialV1, SecretConsensusThresholdCredentialV1,
};
use iroha_core::beacon::{
    GlobalThresholdBeaconPartialSignerV1 as _, GlobalThresholdBeaconSessionError,
};
use iroha_core::tle_release::RuntimeTleReleaseShareCustodyV1;
use iroha_core::tle_release::TlePartialReleaseSignerV1 as _;
use iroha_core::tle_release::TleProjectedPartialReleaseSignerV1 as _;
use iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1;
use iroha_core_timed_ovn::tle::TlePartialReleaseShareV1;
use iroha_core_timed_ovn::tle::ValidatedTleReleaseProjectionV1;
use iroha_data_model::{NetworkId, consensus::GlobalThresholdBeaconPartialSignatureV1};
use norito::{NoritoDeserialize, NoritoSerialize};
use std::{fmt, path::Path, sync::Arc};
use zeroize::{Zeroize as _, Zeroizing};

/// Fixed supervisor credential containing global-beacon software shares.
pub const GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1: &str =
    "iroha-global-beacon-partial-signer-v1.norito";
/// Fixed supervisor credential containing Parliament TLE release shares.
pub const PARLIAMENT_TLE_PARTIAL_RELEASE_SIGNER_CREDENTIAL_NAME_V1: &str =
    "iroha-parliament-tle-partial-release-signer-v1.norito";

// Core's credential codec binds the same stable slot identifier.
const _: () = assert!(
    IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
        == GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1
);

const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1: [u8; 8] = *b"IRTHB001";
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_HEADER_BYTES_V1: usize = 28;
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1: u16 = 1 << 0;
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_PARLIAMENT_TLE_V1: u16 = 1 << 1;
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_KNOWN_FLAGS_V1: u16 =
    CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1
        | CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_PARLIAMENT_TLE_V1;
#[cfg(test)]
const PARLIAMENT_TLE_SIGNER_CREDENTIAL_SCHEMA_NAME_V1: &str =
    "iroha.runtime_provider_broker.v1.consensus_threshold.parliament_tle_signer_credential";
#[cfg(test)]
const PARLIAMENT_TLE_PUBLIC_INVENTORY_SCHEMA_NAME_V1: &str =
    "iroha.runtime_provider_broker.v1.consensus_threshold.parliament_tle_public_inventory";

/// Secret-free runtime threshold-signer credential failure with payload-free display.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeConsensusThresholdSignerCredentialErrorV1 {
    /// The public qualification, network, session inventory, or share was invalid.
    Rejected,
    /// The fixed runtime credential could not be securely opened or read.
    Unavailable,
    /// Canonical credential encoding failed or exceeded its fixed byte ceiling.
    Encoding,
    /// Local original-pool admission failed; the credential has not been judged invalid.
    Session(GlobalThresholdBeaconSessionError),
    /// Exact original raw-decoder refusal, classified before its scopes ended.
    DecodeResource(norito::core::DecodeAttemptError),
    /// Original prepared-output or share-import failure, retaining local source identity.
    Output(GlobalBeaconCredentialEncodeErrorV1),
    /// Exact local refusal constructing the original Parliament decoded graph.
    ParliamentFunding(RuntimeParliamentTleCredentialFundingErrorV1),
}

impl fmt::Display for RuntimeConsensusThresholdSignerCredentialErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "consensus threshold-signer runtime credential was rejected",
            Self::Unavailable => "consensus threshold-signer runtime credential is unavailable",
            Self::Encoding => "consensus threshold-signer runtime credential encoding failed",
            Self::Session(_) => "consensus threshold-signer original session admission failed",
            Self::Output(_) => "consensus threshold-signer prepared output failed",
            Self::ParliamentFunding(_) => "Parliament credential backing is unavailable",
            Self::DecodeResource(_) => {
                "consensus threshold-signer credential decoder is unavailable"
            }
        })
    }
}

impl std::error::Error for RuntimeConsensusThresholdSignerCredentialErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::DecodeResource(error) => Some(error),
            Self::Output(error) => Some(error),
            Self::ParliamentFunding(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GlobalBeaconCredentialEncodeErrorV1>
    for RuntimeConsensusThresholdSignerCredentialErrorV1
{
    fn from(error: GlobalBeaconCredentialEncodeErrorV1) -> Self {
        match error {
            GlobalBeaconCredentialEncodeErrorV1::Credential(error) => error.into(),
            original => Self::Output(original),
        }
    }
}

impl From<GlobalBeaconCredentialImportErrorV1>
    for RuntimeConsensusThresholdSignerCredentialErrorV1
{
    fn from(error: GlobalBeaconCredentialImportErrorV1) -> Self {
        match error {
            GlobalBeaconCredentialImportErrorV1::Credential(error) => error.into(),
            GlobalBeaconCredentialImportErrorV1::DecodeResource(error) => {
                Self::DecodeResource(error)
            }
            GlobalBeaconCredentialImportErrorV1::Session(error) => Self::Session(error),
        }
    }
}

impl From<GlobalThresholdBeaconSessionError> for RuntimeConsensusThresholdSignerCredentialErrorV1 {
    fn from(error: GlobalThresholdBeaconSessionError) -> Self {
        GlobalBeaconCredentialImportErrorV1::from(error).into()
    }
}

impl From<ConsensusThresholdCredentialDecodeErrorV1>
    for RuntimeConsensusThresholdSignerCredentialErrorV1
{
    fn from(error: ConsensusThresholdCredentialDecodeErrorV1) -> Self {
        match error {
            ConsensusThresholdCredentialDecodeErrorV1::Rejected => Self::Rejected,
            ConsensusThresholdCredentialDecodeErrorV1::Resource(error) => {
                Self::DecodeResource(error)
            }
        }
    }
}

impl From<ConsensusThresholdCredentialErrorV1>
    for RuntimeConsensusThresholdSignerCredentialErrorV1
{
    fn from(error: ConsensusThresholdCredentialErrorV1) -> Self {
        match error {
            ConsensusThresholdCredentialErrorV1::Encoding => Self::Encoding,
            _ => Self::Rejected,
        }
    }
}

/// One Parliament TLE share supplied by an authenticated DKG provisioning path.
///
/// The type has no serialization, cloning, or debug surface. Use
/// [`encode_parliament_tle_partial_release_signer_credential_v1`] to produce
/// the zeroizing bytes handed directly to a supervisor credential facility.
pub struct RuntimeParliamentTleShareProvisioningV1 {
    public_session: TleKeySessionPublicStateV1,
    participant_index: u16,
    components: Zeroizing<[[u8; 32]; 3]>,
}

impl RuntimeParliamentTleShareProvisioningV1 {
    /// Consume one public transcript and its zeroizing aggregate share.
    #[must_use]
    pub fn new(
        public_session: TleKeySessionPublicStateV1,
        participant_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Self {
        Self {
            public_session,
            participant_index,
            components,
        }
    }
}

#[derive(NoritoSerialize, NoritoDeserialize)]
#[norito(decode_fields)]
struct RuntimeParliamentTleShareCredentialWireV1 {
    public_session: TleKeySessionPublicStateV1,
    participant_index: u16,
    components: ConsensusThresholdSecretScalarTripleV1,
}

#[derive(NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTleSignerCredentialWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.parliament_tle_signer_credential"
)]
#[norito(decode_fields)]
struct RuntimeParliamentTleSignerCredentialWireV1 {
    header: ConsensusThresholdCredentialHeaderV1,
    sessions: Vec<RuntimeParliamentTleShareCredentialWireV1>,
}

#[derive(NoritoSerialize)]
struct RuntimeParliamentTlePublicInventoryEntryWireV1 {
    public_session: TleKeySessionPublicStateV1,
    participant_index: u16,
}

#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTlePublicInventoryWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.parliament_tle_public_inventory"
)]
struct RuntimeParliamentTlePublicInventoryWireV1 {
    version: u16,
    slot: u16,
    network_id: NetworkId,
    sessions: Vec<RuntimeParliamentTlePublicInventoryEntryWireV1>,
}

#[derive(NoritoSerialize)]
struct ParliamentPublicInventoryEntryViewV1<'a> {
    public_session: norito::core::PayloadRef<'a, TleKeySessionPublicStateV1>,
    participant_index: u16,
}
struct ParliamentPublicInventoryEntriesV1<'a>(&'a [RuntimeParliamentTleShareCredentialWireV1]);
impl norito::core::SerializePayload for ParliamentPublicInventoryEntriesV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<ParliamentPublicInventoryEntryViewV1<'_>, _>(
            writer,
            self.0
                .iter()
                .map(|session| ParliamentPublicInventoryEntryViewV1 {
                    public_session: norito::core::PayloadRef(&session.public_session),
                    participant_index: session.participant_index,
                }),
        )
    }
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTlePublicInventoryWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.parliament_tle_public_inventory"
)]
struct ParliamentPublicInventoryViewV1<'a> {
    version: u16,
    slot: u16,
    network_id: NetworkId,
    sessions: ParliamentPublicInventoryEntriesV1<'a>,
}

fn parliament_tle_public_inventory_wire_v1(
    network_id: NetworkId,
    sessions: impl IntoIterator<Item = (TleKeySessionPublicStateV1, u16)>,
) -> Result<
    RuntimeParliamentTlePublicInventoryWireV1,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    let mut sessions = sessions
        .into_iter()
        .map(|(public_session, participant_index)| {
            if public_session.network_id != *network_id.as_bytes() {
                return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
            }
            Ok(RuntimeParliamentTlePublicInventoryEntryWireV1 {
                public_session,
                participant_index,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_consensus_threshold_session_count_v1(sessions.len())?;
    sessions.sort_by(|left, right| {
        left.public_session
            .key_session_id
            .cmp(&right.public_session.key_session_id)
            .then_with(|| left.participant_index.cmp(&right.participant_index))
    });
    Ok(RuntimeParliamentTlePublicInventoryWireV1 {
        version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
        slot: IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id(),
        network_id,
        sessions,
    })
}

/// Compute the canonical public Parliament-TLE session-and-seat inventory digest.
///
/// This digest is the exact value configured as the provider policy digest. It
/// commits to every complete public TLE transcript and the local participant
/// seat without serializing or hashing private share components. V1 computes
/// `SHA-256(domain || u64_be(encoded_len) || canonical_norito(inventory))`,
/// where the inventory contains version 1, the role slot, the exact network,
/// and entries sorted by key-session identifier then participant index.
///
/// # Errors
///
/// Rejects empty, excessive, or cross-network inventories and encoding failure.
pub fn parliament_tle_partial_release_signer_inventory_digest_v1(
    network_id: NetworkId,
    sessions: &[RuntimeParliamentTleShareProvisioningV1],
) -> Result<[u8; 32], RuntimeConsensusThresholdSignerCredentialErrorV1> {
    let inventory = parliament_tle_public_inventory_wire_v1(
        network_id,
        sessions
            .iter()
            .map(|session| (session.public_session.clone(), session.participant_index)),
    )?;
    consensus_threshold_public_inventory_digest_v1(&inventory).map_err(Into::into)
}

/// Frame the two optional threshold credentials for one launchd stdin handoff.
///
/// The bundle contains only a fixed header and the already canonical secret
/// credential frames. Its allocation is reserved once and zeroized on drop.
/// A deployment-owned administrator writes the returned bytes once to the
/// root-protected launchd FIFO; neither secret bytes nor source paths enter the
/// broker argv, environment, plist, public catalog, or filesystem namespace.
///
/// # Errors
///
/// Rejects empty or oversized credential frames and total-length overflow.
pub fn encode_consensus_threshold_credential_bundle_v1(
    global_beacon: Option<&[u8]>,
    parliament_tle: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeConsensusThresholdSignerCredentialErrorV1> {
    fn credential_len_v1(
        credential: Option<&[u8]>,
    ) -> Result<usize, RuntimeConsensusThresholdSignerCredentialErrorV1> {
        let Some(credential) = credential else {
            return Ok(0);
        };
        if credential.is_empty() || credential.len() > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        Ok(credential.len())
    }

    let global_len = credential_len_v1(global_beacon)?;
    let tle_len = credential_len_v1(parliament_tle)?;
    let encoded_len = CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_HEADER_BYTES_V1
        .checked_add(global_len)
        .and_then(|len| len.checked_add(tle_len))
        .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Encoding)?;
    let mut allocation = Vec::new();
    allocation
        .try_reserve_exact(encoded_len)
        .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Encoding)?;
    let mut encoded = Zeroizing::new(allocation);
    let mut flags = 0_u16;
    if global_beacon.is_some() {
        flags |= CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1;
    }
    if parliament_tle.is_some() {
        flags |= CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_PARLIAMENT_TLE_V1;
    }
    encoded.extend_from_slice(&CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1);
    encoded.extend_from_slice(&CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1.to_be_bytes());
    encoded.extend_from_slice(&flags.to_be_bytes());
    encoded.extend_from_slice(
        &u64::try_from(global_len)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Encoding)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u64::try_from(tle_len)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Encoding)?
            .to_be_bytes(),
    );
    if let Some(credential) = global_beacon {
        encoded.extend_from_slice(credential);
    }
    if let Some(credential) = parliament_tle {
        encoded.extend_from_slice(credential);
    }
    debug_assert_eq!(encoded.len(), encoded_len);
    Ok(encoded)
}

/// Canonically encode a cryptographically validated Parliament TLE share inventory.
///
/// The returned allocation scrubs itself on drop and is intended to be passed
/// directly to the supervisor credential facility. This function performs no
/// file I/O and never writes private material to configuration or ledger state.
///
/// # Errors
///
/// Rejects invalid production qualification, empty or excessive inventories,
/// cross-network transcripts, duplicate sessions, and shares that do not match
/// the complete public DKG transcript and participant seat.
pub fn encode_parliament_tle_partial_release_signer_credential_v1(
    network_id: NetworkId,
    handle: impl Into<String>,
    revision: u64,
    policy_digest: [u8; 32],
    sessions: Vec<RuntimeParliamentTleShareProvisioningV1>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeConsensusThresholdSignerCredentialErrorV1> {
    let handle = handle.into();
    if parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &sessions)?
        != policy_digest
    {
        return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
    }
    validate_consensus_threshold_provisioning_v1(&network_id, &handle, revision, policy_digest)?;
    let header = ConsensusThresholdCredentialHeaderV1::new(
        IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id(),
        network_id,
        handle,
        revision,
        policy_digest,
    );
    let sessions = encode_parliament_tle_sessions_v1(&network_id, sessions)?;
    encode_consensus_threshold_secret_credential_v1(&RuntimeParliamentTleSignerCredentialWireV1 {
        header,
        sessions,
    })
    .map_err(Into::into)
}

fn encode_parliament_tle_sessions_v1(
    network_id: &NetworkId,
    mut sessions: Vec<RuntimeParliamentTleShareProvisioningV1>,
) -> Result<
    Vec<RuntimeParliamentTleShareCredentialWireV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    validate_consensus_threshold_session_count_v1(sessions.len())?;
    sessions.sort_by(|left, right| {
        left.public_session
            .key_session_id
            .cmp(&right.public_session.key_session_id)
            .then_with(|| left.participant_index.cmp(&right.participant_index))
    });
    let validation_custody = RuntimeTleReleaseShareCustodyV1::new();
    let mut encoded = Vec::with_capacity(sessions.len());
    for session in sessions {
        let RuntimeParliamentTleShareProvisioningV1 {
            public_session,
            participant_index,
            components,
        } = session;
        if public_session.network_id != *network_id.as_bytes() {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        validation_custody
            .import_components(
                public_session.clone(),
                participant_index,
                Zeroizing::new(*components),
            )
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?;
        encoded.push(RuntimeParliamentTleShareCredentialWireV1 {
            public_session,
            participant_index,
            components: ConsensusThresholdSecretScalarTripleV1::from_zeroizing(components),
        });
    }
    Ok(encoded)
}

/// Exact two-slot backend registry populated from runtime credentials.
///
/// The registry owns only zeroizing Core custody objects plus stable public
/// qualification. It exposes no share inventory or secret-export operation.
#[derive(Clone, Default)]
pub struct RuntimeConsensusThresholdSignerBackendsV1 {
    global_beacon: Option<Arc<RuntimeGlobalBeaconPartialSignerBackendV1>>,
    parliament_tle: Option<Arc<RuntimeParliamentTlePartialReleaseSignerBackendV1>>,
}

impl RuntimeConsensusThresholdSignerBackendsV1 {
    /// Construct an empty exact registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            global_beacon: None,
            parliament_tle: None,
        }
    }

    /// Consume one exact launchd stdin credential bundle.
    ///
    /// launchd opens a root-protected FIFO before changing to the broker UID.
    /// The independent administrator writes one bundle and closes the writer;
    /// this reader never resolves a secret pathname. Bundle presence must
    /// exactly match the two threshold slots requested by the public catalog.
    ///
    /// # Errors
    ///
    /// Rejects a missing, truncated, trailing, oversized, unknown-version, or
    /// catalog-mismatched bundle and applies the same complete credential and
    /// public-transcript validation as the systemd credential path.
    pub fn load_from_launchd_credential_bundle_v1(
        catalog: &IrohaRuntimeProviderBindingsV1,
        reader: &mut impl std::io::Read,
        budget: &AllocationBudget,
    ) -> Result<Self, RuntimeConsensusThresholdSignerCredentialErrorV1> {
        let mut requested_flags = 0_u16;
        for configured in catalog.iter() {
            let flag = match configured.slot() {
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1
                }
                IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                    CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_PARLIAMENT_TLE_V1
                }
                _ => continue,
            };
            if requested_flags & flag != 0 {
                return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
            }
            requested_flags |= flag;
        }

        let mut header = [0_u8; CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_HEADER_BYTES_V1];
        reader
            .read_exact(&mut header)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
        let version = u16::from_be_bytes([header[8], header[9]]);
        let flags = u16::from_be_bytes([header[10], header[11]]);
        let global_len = usize::try_from(u64::from_be_bytes(
            header[12..20]
                .try_into()
                .expect("fixed credential-bundle global length"),
        ))
        .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?;
        let tle_len = usize::try_from(u64::from_be_bytes(
            header[20..28]
                .try_into()
                .expect("fixed credential-bundle TLE length"),
        ))
        .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?;
        let global_present = flags & CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1 != 0;
        let tle_present = flags & CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_PARLIAMENT_TLE_V1 != 0;
        if header[..8] != CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1
            || version != CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1
            || flags & !CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_KNOWN_FLAGS_V1 != 0
            || flags != requested_flags
            || global_present != (global_len != 0)
            || tle_present != (tle_len != 0)
            || global_len > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1
            || tle_len > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1
        {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        let payload_len = global_len
            .checked_add(tle_len)
            .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?;
        let mut allocation = Vec::new();
        allocation
            .try_reserve_exact(payload_len)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
        allocation.resize(payload_len, 0);
        let mut payload = Zeroizing::new(allocation);
        reader
            .read_exact(&mut payload)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
        let mut trailing = [0_u8; 1];
        let trailing_len = reader
            .read(&mut trailing)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
        trailing.zeroize();
        if trailing_len != 0 {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }

        let (global_credential, tle_credential) = payload.split_at(global_len);
        let mut loaded = Self::new();
        for configured in catalog.iter() {
            match configured.slot() {
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    loaded.global_beacon = Some(decode_global_beacon_credential_v1(
                        global_credential,
                        catalog.network_id(),
                        configured,
                        budget,
                    )?);
                }
                IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                    loaded.parliament_tle = Some(decode_parliament_tle_credential_v1(
                        tle_credential,
                        catalog.network_id(),
                        configured,
                        budget,
                    )?);
                }
                _ => {}
            }
        }
        Ok(loaded)
    }

    /// Load every requested threshold signer from its fixed runtime credential.
    ///
    /// `credential_directory` is normally the supervisor-provided
    /// `CREDENTIALS_DIRECTORY`. It may be absent only when the catalog requests
    /// neither threshold-signing slot. Credential file names are fixed by this
    /// module; no path or secret value is accepted through configuration.
    ///
    /// # Errors
    ///
    /// Rejects a missing or insecure credential, noncanonical encoding,
    /// catalog substitution, invalid public transcript, duplicate session, or
    /// private share that does not match its advertised participant seat.
    pub fn load_from_credential_directory_v1(
        catalog: &IrohaRuntimeProviderBindingsV1,
        credential_directory: Option<&Path>,
        budget: &AllocationBudget,
    ) -> Result<Self, RuntimeConsensusThresholdSignerCredentialErrorV1> {
        let mut loaded = Self::new();
        for configured in catalog.iter() {
            match configured.slot() {
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    if loaded.global_beacon.is_some() {
                        return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
                    }
                    let directory = credential_directory
                        .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
                    let bytes = load_fixed_credential_v1(
                        directory,
                        GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
                    )?;
                    loaded.global_beacon = Some(decode_global_beacon_credential_v1(
                        &bytes,
                        catalog.network_id(),
                        configured,
                        budget,
                    )?);
                }
                IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                    if loaded.parliament_tle.is_some() {
                        return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
                    }
                    let directory = credential_directory
                        .ok_or(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
                    let bytes = load_fixed_credential_v1(
                        directory,
                        PARLIAMENT_TLE_PARTIAL_RELEASE_SIGNER_CREDENTIAL_NAME_V1,
                    )?;
                    loaded.parliament_tle = Some(decode_parliament_tle_credential_v1(
                        &bytes,
                        catalog.network_id(),
                        configured,
                        budget,
                    )?);
                }
                _ => {}
            }
        }
        Ok(loaded)
    }
}

fn load_fixed_credential_v1(
    directory: &Path,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, RuntimeConsensusThresholdSignerCredentialErrorV1> {
    load_bounded_runtime_credential_v1(
        &directory.join(name),
        1,
        MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1,
    )
    .map_err(|error| match error {
        RuntimeCredentialErrorV1::Unavailable => {
            RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable
        }
        RuntimeCredentialErrorV1::InvalidSource | RuntimeCredentialErrorV1::InvalidLength => {
            RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected
        }
    })
}

fn decode_global_beacon_credential_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &AllocationBudget,
) -> Result<
    Arc<RuntimeGlobalBeaconPartialSignerBackendV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    let qualification = configured_qualification_v1(
        configured,
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
    )?;
    let custody = decode_global_beacon_partial_signer_credential_v1(
        bytes,
        network_id,
        configured.handle(),
        qualification.revision,
        qualification.policy_digest,
        budget,
    )?;
    Ok(Arc::new(RuntimeGlobalBeaconPartialSignerBackendV1 {
        handle: configured.handle().to_owned(),
        qualification,
        custody: Arc::new(custody),
    }))
}

/// Decode a global-beacon credential for its exact configured binding and return its shares.
///
/// Core validates the complete credential, including every share against its public transcript
/// and seat, before any share is returned.
fn decode_global_beacon_credential_shares_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &AllocationBudget,
) -> Result<
    Vec<RuntimeGlobalBeaconShareProvisioningV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    let qualification = configured_qualification_v1(
        configured,
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
    )?;
    decode_global_beacon_partial_signer_credential_shares_v1(
        bytes,
        network_id,
        configured.handle(),
        qualification.revision,
        qualification.policy_digest,
        budget,
    )
    .map_err(Into::into)
}

/// Resolve consumed launcher bytes through the complete native credential validator.
pub(crate) fn decode_global_beacon_runtime_signer_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &AllocationBudget,
) -> Result<
    Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    let backend = decode_global_beacon_credential_v1(bytes, network_id, configured, budget)?;
    Ok(backend.custody.clone())
}

fn decode_parliament_tle_credential_v1(
    bytes: &[u8],
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &AllocationBudget,
) -> Result<
    Arc<RuntimeParliamentTlePartialReleaseSignerBackendV1>,
    RuntimeConsensusThresholdSignerCredentialErrorV1,
> {
    let funded = parliament_funding::decode(bytes, budget)?;
    let funded = funded.try_map(|wire| {
        let qualification = validate_credential_header_v1(
            &wire.header,
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
            network_id,
            configured,
        )?;
        validate_consensus_threshold_session_count_v1(wire.sessions.len())?;
        if wire.sessions.windows(2).any(|pair| {
            pair[0]
                .public_session
                .key_session_id
                .cmp(&pair[1].public_session.key_session_id)
                .then_with(|| pair[0].participant_index.cmp(&pair[1].participant_index))
                .is_ge()
        }) {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        let public_inventory = ParliamentPublicInventoryViewV1 {
            version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id(),
            network_id: *network_id,
            sessions: ParliamentPublicInventoryEntriesV1(&wire.sessions),
        };
        if consensus_threshold_public_inventory_digest_v1(&public_inventory)?
            != qualification.policy_digest
        {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        let custody = Arc::new(RuntimeTleReleaseShareCustodyV1::new());
        for session in wire.sessions {
            if session.public_session.network_id != *network_id.as_bytes() {
                return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
            }
            custody
                .import_components(
                    session.public_session,
                    session.participant_index,
                    session.components.into_zeroizing(),
                )
                .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)?;
        }
        Ok(RuntimeParliamentTleDecodedGraphV1 {
            handle: wire.header.handle,
            qualification,
            custody,
        })
    })?;
    // TODO: fund outer std Arc controls, Core BTreeMap nodes and supervisor
    // I/O backing with exact original owners. This ledger covers only the
    // decoded handle/session graph and its actual fixed charge-ledger backing.
    Ok(Arc::new(
        RuntimeParliamentTlePartialReleaseSignerBackendV1 { funded },
    ))
}

fn configured_qualification_v1(
    configured: &IrohaRuntimeProviderBindingV1,
    slot: IrohaRuntimeProviderSlotV1,
) -> Result<ConsensusSignerProviderQualificationV1, RuntimeConsensusThresholdSignerCredentialErrorV1>
{
    match (
        configured.slot() == slot,
        configured.revision(),
        configured.policy_digest(),
    ) {
        (true, Some(revision), Some(policy_digest)) => Ok(
            ConsensusSignerProviderQualificationV1::new(revision, policy_digest, false),
        ),
        _ => Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected),
    }
}

fn validate_credential_header_v1(
    header: &ConsensusThresholdCredentialHeaderV1,
    slot: IrohaRuntimeProviderSlotV1,
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
) -> Result<ConsensusSignerProviderQualificationV1, RuntimeConsensusThresholdSignerCredentialErrorV1>
{
    let qualification = configured_qualification_v1(configured, slot)?;
    header.validate(
        slot.wire_id(),
        network_id,
        configured.handle(),
        qualification.revision,
        qualification.policy_digest,
    )?;
    Ok(qualification)
}

struct RuntimeGlobalBeaconPartialSignerBackendV1 {
    handle: String,
    qualification: ConsensusSignerProviderQualificationV1,
    custody: Arc<RuntimeGlobalThresholdBeaconShareCustodyV1>,
}

impl GlobalBeaconPartialSignerBrokerBackendV1 for RuntimeGlobalBeaconPartialSignerBackendV1 {
    fn handle(&self) -> &str {
        &self.handle
    }

    fn qualification(
        &self,
    ) -> Result<ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1>
    {
        Ok(self.qualification)
    }

    fn attest_partial_signing_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        self.custody
            .attest_partial_signing_capability(session, expected_signer_index)
            .map_err(|error| match error {
                iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::Unavailable => {
                    GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable
                }
                iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::NotOwned
                | iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::InvalidRequest => {
                    GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected
                }
            })
    }

    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<
        GlobalThresholdBeaconPartialSignatureV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        self.custody
            .sign_partial(session, payload)
            .map_err(|_| GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected)
    }
}

struct RuntimeParliamentTleDecodedGraphV1 {
    handle: String,
    qualification: ConsensusSignerProviderQualificationV1,
    custody: Arc<RuntimeTleReleaseShareCustodyV1>,
}

struct RuntimeParliamentTlePartialReleaseSignerBackendV1 {
    funded: parliament_funding::FundedOwner<RuntimeParliamentTleDecodedGraphV1>,
}

impl ParliamentTlePartialReleaseSignerBrokerBackendV1
    for RuntimeParliamentTlePartialReleaseSignerBackendV1
{
    fn handle(&self) -> &str {
        &self.funded.get().handle
    }

    fn qualification(
        &self,
    ) -> Result<
        ConsensusSignerProviderQualificationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    > {
        Ok(self.funded.get().qualification)
    }

    fn attest_partial_release_capability(
        &self,
        session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<
        iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    > {
        self.funded
            .get()
            .custody
            .attest_partial_release_capability(session, expected_participant_index)
            .map_err(|error| match error {
                iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1::Unavailable => {
                    ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Unavailable
                }
                iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1::NotOwned
                | iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1::InvalidRequest => {
                    ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected
                }
            })
    }

    fn sign_projected_partial_release(
        &self,
        projection: &ValidatedTleReleaseProjectionV1,
    ) -> Result<TlePartialReleaseShareV1, ParliamentTlePartialReleaseSignerBrokerBackendErrorV1>
    {
        self.funded
            .get()
            .custody
            .sign_projected_partial_release(projection)
            .map_err(|_| ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected)
    }
}

impl RuntimeProviderBrokerBackendRegistryV1 for RuntimeConsensusThresholdSignerBackendsV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<RuntimeProviderBrokerBackendsV1, IrohaRuntimeProviderRegistryErrorV1> {
        let mut requested_global = false;
        let mut requested_tle = false;
        for configured in bindings.iter() {
            match configured.slot() {
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                    let backend = self
                        .global_beacon
                        .as_deref()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
                    exact_backend_binding_v1(configured, backend.handle(), backend.qualification)?;
                    if requested_global {
                        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                    }
                    requested_global = true;
                }
                IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                    let backend = self
                        .parliament_tle
                        .as_deref()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
                    exact_backend_binding_v1(
                        configured,
                        backend.handle(),
                        backend.funded.get().qualification,
                    )?;
                    if requested_tle {
                        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                    }
                    requested_tle = true;
                }
                _ => return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution),
            }
        }
        if requested_global != self.global_beacon.is_some()
            || requested_tle != self.parliament_tle.is_some()
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders);
        }
        let mut resolved = RuntimeProviderBrokerBackendsV1::new();
        if let Some(backend) = &self.global_beacon {
            resolved = resolved.with_global_beacon_partial_signer(backend.clone());
        }
        if let Some(backend) = &self.parliament_tle {
            resolved = resolved.with_parliament_tle_partial_release_signer(backend.clone());
        }
        Ok(resolved)
    }
}

fn exact_backend_binding_v1(
    configured: &IrohaRuntimeProviderBindingV1,
    handle: &str,
    qualification: ConsensusSignerProviderQualificationV1,
) -> Result<(), IrohaRuntimeProviderRegistryErrorV1> {
    if qualification.test_marked {
        return Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected);
    }
    if configured.handle() != handle
        || configured.revision() != Some(qualification.revision)
        || configured.policy_digest() != Some(qualification.policy_digest)
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
    }
    Ok(())
}

/// Direct credential tests and proof-valid fixtures shared with broker socket tests.
#[cfg(test)]
pub(crate) mod tests {
    fn test_credential_budget() -> AllocationBudget {
        AllocationBudget::new(256 * 1024 * 1024)
    }

    fn parliament_funding_fixture_v1() -> (
        IrohaRuntimeProviderBindingsV1,
        Zeroizing<Vec<u8>>,
        TleFixtureV1,
    ) {
        let network = network_id_v1(0xC1);
        let fixture = tle_fixture_v1(network, 0xC2);
        let provisions = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            Zeroizing::new(*fixture.components),
        )];
        let digest =
            parliament_tle_partial_release_signer_inventory_digest_v1(network, &provisions)
                .expect("exact Parliament funding fixture inventory");
        let catalog = tle_catalog_v1(digest);
        let bytes = encode_parliament_tle_partial_release_signer_credential_v1(
            network, HANDLE, REVISION, digest, provisions,
        )
        .expect("canonical Parliament funding fixture");
        (catalog, bytes, fixture)
    }

    #[test]
    fn parliament_prepaid_fields_preserve_canonical_frame_and_borrowed_inventory() {
        let (catalog, bytes, fixture) = parliament_funding_fixture_v1();
        let pool = test_credential_budget();
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let funded = parliament_funding::decode(&bytes, &pool).unwrap();
        assert!(funded.belongs_to(&pool));
        assert!(!funded.belongs_to(&foreign));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(
            norito::encode_canonical(funded.get()).unwrap(),
            bytes.as_slice()
        );
        assert_eq!(
            funded.get().sessions[0].public_session,
            *fixture.validated.public_state()
        );
        let view = ParliamentPublicInventoryViewV1 {
            version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id(),
            network_id: *catalog.network_id(),
            sessions: ParliamentPublicInventoryEntriesV1(&funded.get().sessions),
        };
        let owning = parliament_tle_public_inventory_wire_v1(
            *catalog.network_id(),
            [(fixture.validated.public_state().clone(), 1)],
        )
        .unwrap();
        assert_eq!(
            norito::encode_canonical(&view).unwrap(),
            norito::encode_canonical(&owning).unwrap()
        );
        assert_eq!(
            consensus_threshold_public_inventory_digest_v1(&view).unwrap(),
            consensus_threshold_public_inventory_digest_v1(&owning).unwrap()
        );
        assert!(pool.reserved_bytes() > 0);
        drop(funded);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn parliament_decoded_graph_stays_charged_through_final_registry_reader() {
        let (catalog, bytes, fixture) = parliament_funding_fixture_v1();
        let pool = test_credential_budget();
        let backend = decode_parliament_tle_credential_v1(
            &bytes,
            catalog.network_id(),
            catalog.iter().next().unwrap(),
            &pool,
        )
        .unwrap();
        assert!(backend.funded.belongs_to(&pool));
        assert_eq!(Arc::strong_count(&backend.funded.get().custody), 1);
        let retained = pool.reserved_bytes();
        assert!(retained > 0);
        let registry = RuntimeConsensusThresholdSignerBackendsV1 {
            global_beacon: None,
            parliament_tle: Some(backend),
        };
        pool.set_limit_bytes(0);
        let another = registry.clone();
        assert_eq!(
            pool.reserved_bytes(),
            retained,
            "cloning charges the same graph once"
        );
        registry
            .parliament_tle
            .as_ref()
            .unwrap()
            .attest_partial_release_capability(&fixture.validated, 1)
            .unwrap();
        let final_reader = another.resolve(&catalog).unwrap();
        drop(registry);
        drop(another);
        assert_eq!(
            pool.reserved_bytes(),
            retained,
            "trait dispatch retains the original owner"
        );
        drop(final_reader);
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "only final reclamation releases graph credit"
        );
    }

    #[test]
    fn parliament_actual_backing_shortage_keeps_original_refusal_and_retries_same_bytes() {
        let (catalog, bytes, _) = parliament_funding_fixture_v1();
        let input_hash = Hash::new(bytes.as_slice());
        let funded_probe = test_credential_budget();
        let probe = parliament_funding::decode(&bytes, &funded_probe).unwrap();
        let peak = funded_probe.peak_reserved_bytes();
        assert!(peak > parliament_funding::preparation_bytes() + HANDLE.len());
        drop(probe);
        assert_eq!(funded_probe.reserved_bytes(), 0);

        let pool = AllocationBudget::new(peak - 1);
        let error = decode_parliament_tle_credential_v1(
            &bytes,
            catalog.network_id(),
            catalog.iter().next().unwrap(),
            &pool,
        )
        .err()
        .expect("one byte below actual admitted peak must refuse");
        let RuntimeConsensusThresholdSignerCredentialErrorV1::ParliamentFunding(
            RuntimeParliamentTleCredentialFundingErrorV1::Storage(
                iroha_allocation::ChargedBufferError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity {
                        reserved_bytes,
                        limit_bytes,
                        ..
                    },
                ),
            ),
        ) = &error
        else {
            panic!("physical funding refusal must remain typed and local");
        };
        assert!(*reserved_bytes > 0);
        assert_eq!(*limit_bytes, peak - 1);
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "failed DTO owners are reclaimed before refund"
        );
        assert!(!error.to_string().contains(HANDLE));
        assert_eq!(Hash::new(bytes.as_slice()), input_hash);
        drop(error);
        pool.set_limit_bytes(peak);
        let retried = decode_parliament_tle_credential_v1(
            &bytes,
            catalog.network_id(),
            catalog.iter().next().unwrap(),
            &pool,
        )
        .unwrap();
        assert!(retried.funded.belongs_to(&pool));
        assert_eq!(Hash::new(bytes.as_slice()), input_hash);
        drop(retried);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn parliament_invalid_private_share_refunds_only_after_decoded_graph_retirement() {
        let (catalog, bytes, _) = parliament_funding_fixture_v1();
        let mut wire: RuntimeParliamentTleSignerCredentialWireV1 =
            decode_consensus_threshold_credential_v1(&bytes).unwrap();
        wire.sessions[0].components =
            ConsensusThresholdSecretScalarTripleV1::from_zeroizing(Zeroizing::new([[0; 32]; 3]));
        let invalid = encode_consensus_threshold_secret_credential_v1(&wire).unwrap();
        let pool = test_credential_budget();
        assert!(matches!(
            decode_parliament_tle_credential_v1(
                &invalid,
                catalog.network_id(),
                catalog.iter().next().unwrap(),
                &pool,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(pool.peak_reserved_bytes() > parliament_funding::preparation_bytes());
    }

    #[test]
    fn parliament_prepaid_import_preserves_existing_committee_profiles_through_maximum() {
        for committee in [
            4,
            7,
            iroha_crypto::threshold_bls::THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
        ] {
            let network = network_id_v1(0xD1);
            let fixture = tle_fixture_with_committee_v1(network, committee as u8 + 0x20, committee);
            let provisions = vec![RuntimeParliamentTleShareProvisioningV1::new(
                fixture.validated.public_state().clone(),
                1,
                fixture.components,
            )];
            let digest =
                parliament_tle_partial_release_signer_inventory_digest_v1(network, &provisions)
                    .unwrap();
            let catalog = tle_catalog_v1(digest);
            let bytes = encode_parliament_tle_partial_release_signer_credential_v1(
                network, HANDLE, REVISION, digest, provisions,
            )
            .unwrap();
            let pool = test_credential_budget();
            let backend = decode_parliament_tle_credential_v1(
                &bytes,
                catalog.network_id(),
                catalog.iter().next().unwrap(),
                &pool,
            )
            .unwrap();
            backend
                .attest_partial_release_capability(&fixture.validated, 1)
                .unwrap();
            assert!(backend.funded.belongs_to(&pool));
            drop(backend);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
    use super::*;
    use crate::external_software_signer::ExternalSoftwareSignerBackendsV1;
    use iroha_config::parameters::actual::Root as Config;
    use iroha_config_base::toml::TomlSource;
    use iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1;
    use iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1;
    use iroha_core::beacon::complete_beacon_dkg_fixture_for_seat_v1;
    use iroha_core::beacon::validate_global_threshold_beacon_session_v1;
    use iroha_core_timed_ovn::evidence::TimedOvnReleaseIdentityPublicV1;
    use iroha_core_timed_ovn::tle::AuthorizedTleReleaseProjectionV1;
    use iroha_core_timed_ovn::tle::TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1;
    use iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1;
    use iroha_crypto::{
        Hash, HashOf,
        threshold_bls::{
            AdaptiveThresholdBlsParameters, DasRenDealerSecret,
            THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1, ThresholdBlsSession, TleReleasePurpose,
        },
        tle::TleReleaseIdentityV1,
    };
    use iroha_data_model::{
        block::BlockHeader,
        consensus::{GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconKeySessionV1},
        governance::types::BallotAttemptId,
    };
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::{
        fs,
        io::{Cursor, Write as _},
        os::unix::fs::{PermissionsExt as _, symlink},
        path::{Path, PathBuf},
    };

    const HANDLE: &str = "software://iroha/consensus-threshold/primary";
    const REVISION: u64 = 7;
    const POLICY_DIGEST: [u8; 32] = [0xA7; 32];
    const BLS12_381_SCALAR_MODULUS_BE_V1: [u8; 32] = [
        0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1, 0xD8,
        0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x01,
    ];

    struct BeaconFixtureV1 {
        record: GlobalThresholdBeaconKeySessionV1,
        validated: ValidatedGlobalThresholdBeaconSessionV1,
        components: Zeroizing<[[u8; 32]; 3]>,
    }

    struct TleFixtureV1 {
        threshold_session: ThresholdBlsSession<TleReleasePurpose>,
        validated: ValidatedTleKeySessionV1,
        components: Zeroizing<[[u8; 32]; 3]>,
    }

    /// Fully resolved beacon signer fixture used by authenticated broker tests.
    pub(crate) struct ConsensusThresholdBeaconBrokerTestFixtureV1 {
        /// Exact runtime-provider catalog bound into the credential.
        pub(crate) catalog: IrohaRuntimeProviderBindingsV1,
        /// Broker backends resolved from the canonical credential.
        pub(crate) backends: RuntimeProviderBrokerBackendsV1,
        /// Independently validated public session used to verify partials.
        pub(crate) session: ValidatedGlobalThresholdBeaconSessionV1,
        /// Synthetic canonical credential retained only for consumed-descriptor tests.
        pub(crate) credential: SecretConsensusThresholdCredentialV1,
    }

    /// Fully resolved TLE signer fixture used by authenticated broker tests.
    pub(crate) struct ConsensusThresholdTleBrokerTestFixtureV1 {
        /// Exact runtime-provider catalog bound into the credential.
        pub(crate) catalog: IrohaRuntimeProviderBindingsV1,
        /// Broker backends resolved from the canonical credential.
        pub(crate) backends: RuntimeProviderBrokerBackendsV1,
        /// Authorized public release projection used by the broker operation.
        pub(crate) projection: AuthorizedTleReleaseProjectionV1,
        /// Independently validated public session used to verify partials.
        pub(crate) session: ValidatedTleKeySessionV1,
        /// Public release identity used to verify partials.
        pub(crate) identity: TleReleaseIdentityV1,
    }

    fn accumulate_canonical_scalar_v1(total: &mut [u8; 32], term: &[u8; 32]) {
        assert!(
            *total < BLS12_381_SCALAR_MODULUS_BE_V1 && *term < BLS12_381_SCALAR_MODULUS_BE_V1,
            "DKG fixture components must be canonical BLS12-381 scalars"
        );
        let mut carry = 0_u16;
        for (total_byte, term_byte) in total.iter_mut().rev().zip(term.iter().rev()) {
            let sum = u16::from(*total_byte) + u16::from(*term_byte) + carry;
            *total_byte = u8::try_from(sum & 0xFF).expect("masked scalar byte fits u8");
            carry = sum >> 8;
        }
        assert_eq!(
            carry, 0,
            "sum of two reduced BLS12-381 scalars fits 256 bits"
        );
        if *total < BLS12_381_SCALAR_MODULUS_BE_V1 {
            return;
        }
        let mut borrow = 0_i16;
        for (total_byte, modulus_byte) in total
            .iter_mut()
            .rev()
            .zip(BLS12_381_SCALAR_MODULUS_BE_V1.iter().rev())
        {
            let difference = i16::from(*total_byte) - i16::from(*modulus_byte) - borrow;
            if difference < 0 {
                *total_byte =
                    u8::try_from(difference + 256).expect("borrow-reduced scalar byte fits u8");
                borrow = 1;
            } else {
                *total_byte = u8::try_from(difference).expect("reduced scalar byte fits u8");
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "reduction subtracts a smaller modulus");
    }

    fn accumulate_component_triple_v1(
        total: &mut Zeroizing<[[u8; 32]; 3]>,
        contribution: &Zeroizing<[[u8; 32]; 3]>,
    ) {
        for (total_component, contribution_component) in total.iter_mut().zip(contribution.iter()) {
            accumulate_canonical_scalar_v1(total_component, contribution_component);
        }
    }

    /// Public session binding of a beacon record; Core's credential codec derives the same one.
    fn beacon_binding_v1(
        record: &GlobalThresholdBeaconKeySessionV1,
    ) -> GlobalThresholdBeaconSessionBindingV1 {
        GlobalThresholdBeaconSessionBindingV1 {
            network_id: record.network_id,
            session_id: record.session_id,
            roster_hash: record.roster_hash,
            transcript_hash: record.transcript_hash,
        }
    }

    fn beacon_fixture_roster_v1(committee_size: u16) -> Vec<iroha_model_base::peer::PeerId> {
        let mut peers = (1..=committee_size)
            .map(|seed| {
                let key = iroha_crypto::KeyPair::try_from_seed(
                    vec![u8::try_from(seed).expect("fixture seat fits u8"); 32],
                    iroha_crypto::Algorithm::BlsNormal,
                )
                .expect("deterministic signed-DKG roster key");
                iroha_model_base::peer::PeerId::new(key.public_key().clone())
            })
            .collect::<Vec<_>>();
        peers.sort();
        peers
    }

    fn beacon_fixture_roster_hash_v1(committee_size: u16) -> [u8; 32] {
        iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&beacon_fixture_roster_v1(
            committee_size,
        ))
    }

    fn beacon_fixture_with_committee_v1(
        network_id: NetworkId,
        session_byte: u8,
        committee_size: u16,
        budget: &AllocationBudget,
    ) -> BeaconFixtureV1 {
        beacon_fixture_with_roster_hash_v1(
            network_id,
            session_byte,
            committee_size,
            beacon_fixture_roster_hash_v1(committee_size),
            &budget,
        )
    }

    fn beacon_fixture_with_roster_hash_v1(
        network_id: NetworkId,
        session_byte: u8,
        committee_size: u16,
        roster_hash: [u8; 32],
        budget: &AllocationBudget,
    ) -> BeaconFixtureV1 {
        beacon_fixture_with_session_v1(
            network_id,
            [session_byte; 32],
            committee_size,
            roster_hash,
            &budget,
        )
    }

    fn beacon_fixture_with_session_v1(
        network_id: NetworkId,
        session_id: [u8; 32],
        committee_size: u16,
        roster_hash: [u8; 32],
        budget: &AllocationBudget,
    ) -> BeaconFixtureV1 {
        beacon_fixture_for_seat_v1(
            network_id,
            session_id,
            committee_size,
            roster_hash,
            1,
            &budget,
        )
    }

    fn beacon_fixture_for_seat_v1(
        network_id: NetworkId,
        session_id: [u8; 32],
        committee_size: u16,
        roster_hash: [u8; 32],
        signer_index: u16,
        budget: &AllocationBudget,
    ) -> BeaconFixtureV1 {
        let (record, components) = complete_beacon_dkg_fixture_for_seat_v1(
            network_id,
            session_id,
            committee_size,
            signer_index,
        );
        assert_eq!(
            record.roster_hash, roster_hash,
            "beacon fixture must use the exact signed BLS roster"
        );
        let binding = beacon_binding_v1(&record);
        let validated = validate_global_threshold_beacon_session_v1(&record, &binding, &budget)
            .expect("revalidate beacon fixture transcript");
        BeaconFixtureV1 {
            record,
            validated,
            components,
        }
    }

    fn beacon_credential_fixture_v1(
        network: NetworkId,
        handle: &str,
        revision: u64,
        digest: [u8; 32],
        shares: Vec<RuntimeGlobalBeaconShareProvisioningV1>,
        budget: &AllocationBudget,
    ) -> Result<SecretConsensusThresholdCredentialV1, ConsensusThresholdCredentialErrorV1> {
        let produce = || -> Result<_, GlobalBeaconCredentialEncodeErrorV1> {
            let mut prepared = PreparedGlobalBeaconCredentialV1::new(
                network,
                handle,
                revision,
                digest,
                shares
                    .iter()
                    .map(|share| (share.authenticated_session(), share.signer_index())),
                budget,
            )?;
            encode_global_beacon_partial_signer_credential_v1(
                &mut prepared,
                shares
                    .iter()
                    .map(RuntimeGlobalBeaconShareProvisioningV1::credential_source),
            )?;
            prepared.into_credential().map_err(|(_, error)| error)
        };
        produce().map_err(|error| match error {
            GlobalBeaconCredentialEncodeErrorV1::Credential(error) => error,
            GlobalBeaconCredentialEncodeErrorV1::Share(
                iroha_core::beacon::GlobalThresholdBeaconError::ThresholdBls(
                    iroha_crypto::threshold_bls::ThresholdBlsError::SecretShareMismatch
                    | iroha_crypto::threshold_bls::ThresholdBlsError::InvalidScalar,
                ),
            ) => ConsensusThresholdCredentialErrorV1::Rejected,
            local => panic!("unexpected credential fixture failure: {local:?}"),
        })
    }

    fn beacon_fixture_v1(
        network_id: NetworkId,
        session_byte: u8,
        budget: &AllocationBudget,
    ) -> BeaconFixtureV1 {
        beacon_fixture_with_committee_v1(network_id, session_byte, 4, &budget)
    }

    fn tle_fixture_with_committee_v1(
        network_id: NetworkId,
        session_byte: u8,
        committee_size: u16,
    ) -> TleFixtureV1 {
        let threshold = committee_size
            .checked_sub(1)
            .map(|fault_numerator| fault_numerator / 3 + 1)
            .expect("TLE fixture committee is nonzero");
        let threshold_session = ThresholdBlsSession::<TleReleasePurpose>::new(
            *network_id.as_bytes(),
            [session_byte; 32],
            [0x41; 32],
            committee_size,
            threshold,
        )
        .expect("construct TLE threshold session");
        let parameters = AdaptiveThresholdBlsParameters::derive(&threshold_session)
            .expect("derive TLE fixture parameters");
        let mut rng = StdRng::from_seed([session_byte.wrapping_add(0x31); 32]);
        let mut dealers = Vec::with_capacity(usize::from(committee_size));
        let mut components = Zeroizing::new([[0_u8; 32]; 3]);
        for dealer_index in 1_u16..=committee_size {
            let (dealer_secret, dealer) =
                DasRenDealerSecret::generate_with_rng(&parameters, dealer_index, &mut rng)
                    .expect("generate TLE fixture dealer");
            let contribution = dealer_secret
                .private_share(&parameters, &dealer, 1)
                .expect("derive authenticated TLE fixture contribution")
                .components_for_authenticated_encryption();
            accumulate_component_triple_v1(&mut components, &contribution);
            dealers.push(dealer);
        }
        let qualified_dealers = (1_u16..=committee_size).collect::<Vec<_>>();
        let validated = ValidatedTleKeySessionV1::from_qualified_dealers(
            threshold_session,
            &dealers,
            &qualified_dealers,
            [0x51; 32],
        )
        .expect("finalize proof-valid TLE fixture");
        TleFixtureV1 {
            threshold_session,
            validated,
            components,
        }
    }

    fn tle_fixture_v1(network_id: NetworkId, session_byte: u8) -> TleFixtureV1 {
        tle_fixture_with_committee_v1(network_id, session_byte, 4)
    }

    fn configured_consensus_catalog_v1(
        slot: IrohaRuntimeProviderSlotV1,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> IrohaRuntimeProviderBindingsV1 {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/kagami/iroha3-dev/peer0.toml");
        let source = fs::read_to_string(path).expect("read checked-in default daemon config");
        let mut table: toml::Table = toml::from_str(&source).expect("parse default daemon config");
        let genesis = table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("default daemon genesis table");
        assert_eq!(
            genesis
                .remove("expected_hash_file")
                .and_then(|value| value.as_str().map(str::to_owned))
                .as_deref(),
            Some("genesis.expected_hash")
        );
        assert!(
            genesis
                .insert(
                    "expected_hash".to_owned(),
                    toml::Value::String(network_id_v1(0xC1).to_string()),
                )
                .is_none()
        );
        let mut config = Config::from_toml_source(TomlSource::inline(table))
            .expect("resolve checked-in default daemon config for threshold catalog test");
        match slot {
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => {
                config.sumeragi.global_beacon_partial_signer_provider_handle =
                    Some(HANDLE.to_owned());
                config
                    .sumeragi
                    .global_beacon_partial_signer_provider_revision = Some(revision);
                config
                    .sumeragi
                    .global_beacon_partial_signer_provider_policy_digest = Some(policy_digest);
            }
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner => {
                config
                    .gov
                    .parliament_tle_partial_release_signer_provider_handle =
                    Some(HANDLE.to_owned());
                config
                    .gov
                    .parliament_tle_partial_release_signer_provider_revision = Some(revision);
                config
                    .gov
                    .parliament_tle_partial_release_signer_provider_policy_digest =
                    Some(policy_digest);
            }
            _ => panic!("unsupported threshold test slot {slot:?}"),
        }
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project threshold signer through production config collector");
        let binding = catalog
            .iter()
            .find(|binding| binding.slot() == slot)
            .expect("configured threshold slot must be projected");
        assert_eq!(binding.handle(), HANDLE);
        assert_eq!(binding.revision(), Some(revision));
        assert_eq!(binding.policy_digest(), Some(policy_digest));
        assert_eq!(catalog.network_id(), &network_id_v1(0xC1));
        catalog
    }

    fn beacon_catalog_with_revision_v1(
        revision: u64,
        policy_digest: [u8; 32],
    ) -> IrohaRuntimeProviderBindingsV1 {
        IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "consensus-threshold-credential-test",
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            HANDLE,
            revision,
            policy_digest,
        )
        .with_network_id_for_test(network_id_v1(0xC1))
    }

    fn beacon_catalog_v1(policy_digest: [u8; 32]) -> IrohaRuntimeProviderBindingsV1 {
        beacon_catalog_with_revision_v1(REVISION, policy_digest)
    }

    fn tle_catalog_with_revision_v1(
        revision: u64,
        policy_digest: [u8; 32],
    ) -> IrohaRuntimeProviderBindingsV1 {
        IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "consensus-threshold-credential-test",
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
            HANDLE,
            revision,
            policy_digest,
        )
        .with_network_id_for_test(network_id_v1(0xC1))
    }

    fn tle_catalog_v1(policy_digest: [u8; 32]) -> IrohaRuntimeProviderBindingsV1 {
        tle_catalog_with_revision_v1(REVISION, policy_digest)
    }

    fn beacon_pulse_aggregator_v1(
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        block_hash_byte: u8,
    ) -> GlobalThresholdBeaconPulseAggregatorV1 {
        let anchor = GlobalThresholdBeaconChainAnchorV1 {
            height: 40,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [block_hash_byte; 32],
            )),
        };
        GlobalThresholdBeaconPulseAggregatorV1::new(
            session.clone(),
            41,
            anchor,
            iroha_core::beacon::pulse_context_fixture_v1(),
        )
        .expect("construct canonical beacon pulse")
    }

    fn consensus_threshold_beacon_broker_test_fixture_for_committee_v1(
        committee_size: u16,
        session_byte: u8,
    ) -> ConsensusThresholdBeaconBrokerTestFixtureV1 {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_with_committee_v1(
            network_id,
            session_byte,
            committee_size,
            &producer_budget,
        );
        let session = fixture.validated.clone();
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive broker-roundtrip beacon inventory digest");
        let catalog = beacon_catalog_v1(policy_digest);
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode broker-roundtrip beacon credential");
        let backend = decode_global_beacon_credential_v1(
            &credential,
            catalog.network_id(),
            catalog.iter().next().expect("one beacon binding"),
            &budget,
        )
        .expect("decode broker-roundtrip beacon credential");
        let registry = RuntimeConsensusThresholdSignerBackendsV1 {
            global_beacon: Some(backend),
            parliament_tle: None,
        };
        let backends = registry
            .resolve(&catalog)
            .expect("resolve broker-roundtrip beacon backend");
        ConsensusThresholdBeaconBrokerTestFixtureV1 {
            catalog,
            backends,
            session,
            credential,
        }
    }

    /// Builds a beacon fixture through canonical provisioning, decode, and resolution.
    pub(crate) fn consensus_threshold_beacon_broker_test_fixture_v1()
    -> ConsensusThresholdBeaconBrokerTestFixtureV1 {
        consensus_threshold_beacon_broker_test_fixture_for_committee_v1(4, 0x79)
    }

    /// Build an exact-roster provider fixture for the separate readiness broker operation.
    pub(crate) fn consensus_threshold_beacon_readiness_broker_test_fixture_v1() -> (
        ConsensusThresholdBeaconBrokerTestFixtureV1,
        iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
        iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
    ) {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        use iroha_data_model::{
            nexus::ValidatorSeatReadinessContextV1,
            sumeragi::epoch::{InstalledBeaconEpochBindingV1, ValidatorGenerationV1},
        };
        let network_id = network_id_v1(0xC1);
        let mut peers = (1..=4_u8)
            .map(|seed| {
                iroha_model_base::peer::PeerId::new(
                    iroha_crypto::KeyPair::try_from_seed(
                        vec![seed; 32],
                        iroha_crypto::Algorithm::BlsNormal,
                    )
                    .unwrap()
                    .public_key()
                    .clone(),
                )
            })
            .collect::<Vec<_>>();
        peers.sort();
        let fixture = beacon_fixture_with_roster_hash_v1(
            network_id,
            0x89,
            4,
            iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&peers),
            &producer_budget,
        );
        let session = fixture.validated.clone();
        let authority = ValidatorGenerationV1 {
            network_id,
            generation: 1,
            validators: peers,
        };
        let context = ValidatorSeatReadinessContextV1 {
            version: 1,
            network_id,
            transition_id: [0xC3; 32],
            target_epoch: 2,
            authority_generation: 1,
            authority_id: authority.generation_id().unwrap(),
            first_height: 201,
            last_height: 300,
            validator_index: 0,
            beacon: InstalledBeaconEpochBindingV1 {
                session_id: session.record().session_id,
                transcript_hash: session.record().transcript_hash,
            },
        };
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning).unwrap();
        let catalog = beacon_catalog_v1(policy);
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy,
            provisioning,
            &producer_budget,
        )
        .unwrap();
        let backend = decode_global_beacon_credential_v1(
            &credential,
            &network_id,
            catalog.iter().next().unwrap(),
            &budget,
        )
        .unwrap();
        let registry = RuntimeConsensusThresholdSignerBackendsV1 {
            global_beacon: Some(backend),
            parliament_tle: None,
        };
        let backends = registry.resolve(&catalog).unwrap();
        (
            ConsensusThresholdBeaconBrokerTestFixtureV1 {
                catalog,
                backends,
                session,
                credential,
            },
            authority,
            context,
        )
    }

    /// Builds a maximum-committee beacon fixture for ordinary-stack broker tests.
    pub(crate) fn consensus_threshold_beacon_broker_max_committee_test_fixture_v1()
    -> ConsensusThresholdBeaconBrokerTestFixtureV1 {
        consensus_threshold_beacon_broker_test_fixture_for_committee_v1(
            THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
            0x7F,
        )
    }

    fn consensus_threshold_tle_broker_test_fixture_for_committee_v1(
        committee_size: u16,
        session_byte: u8,
    ) -> ConsensusThresholdTleBrokerTestFixtureV1 {
        let network_id = network_id_v1(0xC1);
        let fixture = tle_fixture_with_committee_v1(network_id, session_byte, committee_size);
        let (projection, identity) = tle_projection_v1(&fixture);
        let projection = projection.projection().clone();
        let session = fixture.validated.clone();
        let provisioning = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive broker-roundtrip TLE inventory digest");
        let catalog = tle_catalog_v1(policy_digest);
        let credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
        )
        .expect("encode broker-roundtrip TLE credential");
        let backend = decode_parliament_tle_credential_v1(
            &credential,
            catalog.network_id(),
            catalog.iter().next().expect("one TLE binding"),
            &test_credential_budget(),
        )
        .expect("decode broker-roundtrip TLE credential");
        let registry = RuntimeConsensusThresholdSignerBackendsV1 {
            global_beacon: None,
            parliament_tle: Some(backend),
        };
        let backends = registry
            .resolve(&catalog)
            .expect("resolve broker-roundtrip TLE backend");
        ConsensusThresholdTleBrokerTestFixtureV1 {
            catalog,
            backends,
            projection,
            session,
            identity,
        }
    }

    /// Builds a TLE fixture through canonical provisioning, decode, and resolution.
    pub(crate) fn consensus_threshold_tle_broker_test_fixture_v1()
    -> ConsensusThresholdTleBrokerTestFixtureV1 {
        consensus_threshold_tle_broker_test_fixture_for_committee_v1(4, 0x7A)
    }

    /// Builds a maximum-committee TLE fixture for ordinary-stack broker tests.
    pub(crate) fn consensus_threshold_tle_broker_max_committee_test_fixture_v1()
    -> ConsensusThresholdTleBrokerTestFixtureV1 {
        consensus_threshold_tle_broker_test_fixture_for_committee_v1(
            THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
            0x80,
        )
    }

    fn secure_credential_directory_v1() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("create credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("harden credential directory");
        let canonical = fs::canonicalize(directory.path()).expect("canonical credential path");
        (directory, canonical)
    }

    fn write_credential_v1(directory: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = directory.join(name);
        let mut file = fs::File::create(&path).expect("create runtime credential");
        file.write_all(bytes).expect("write runtime credential");
        file.sync_all().expect("sync runtime credential");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set runtime credential mode");
        path
    }

    fn tle_projection_v1(
        fixture: &TleFixtureV1,
    ) -> (ValidatedTleReleaseProjectionV1, TleReleaseIdentityV1) {
        let identity = TleReleaseIdentityV1::new(
            fixture.threshold_session,
            [0x61; 32],
            [0x62; 32],
            [0x63; 32],
            [0x64; 32],
            [0x65; 32],
            100,
            [0x66; 32],
        )
        .expect("construct exact TLE release identity");
        let identity_payload = identity
            .payload_bytes()
            .try_into()
            .expect("fixed-size TLE identity payload");
        let identity_digest = iroha_crypto::sha256(
            identity
                .release_message()
                .expect("frame TLE release identity"),
        );
        let projection = AuthorizedTleReleaseProjectionV1 {
            version: TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1,
            ballot_attempt_id: BallotAttemptId::new([0x63; 32]),
            opening_deadline_height: 110,
            finalized_height: 100,
            key_session: fixture.validated.public_state().clone(),
            public_release_identity: TimedOvnReleaseIdentityPublicV1 {
                tle_key_session_id: fixture.validated.public_state().key_session_id,
                governance_attempt_id: [0x61; 32],
                body_instance_id: [0x62; 32],
                ballot_attempt_id: [0x63; 32],
                survivor_corpus_root: [0x64; 32],
                no_recovery_root: [0x65; 32],
                target_finalized_height: 100,
                parameter_hash: [0x66; 32],
            },
            identity_payload,
            identity_digest,
        }
        .validate()
        .expect("validate TLE broker projection");
        (projection, identity)
    }

    #[test]
    fn global_beacon_credential_loads_resolves_and_signs_verified_partial() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network_id, 0x71, &producer_budget);
        let validated = fixture.validated.clone();
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive beacon inventory digest");
        let catalog = configured_consensus_catalog_v1(
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            REVISION,
            policy_digest,
        );
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode beacon runtime credential");
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&credential), None)
            .expect("frame beacon credential for launchd stdin");
        let bundled =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut Cursor::new(bundle.as_slice()),
                &budget,
            )
            .expect("load beacon credential from launchd bundle");
        bundled
            .resolve(&catalog)
            .expect("resolve launchd-bundled beacon backend");
        let mut wrong_presence = Zeroizing::new(bundle.as_slice().to_vec());
        wrong_presence[10..12].copy_from_slice(&0_u16.to_be_bytes());
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut Cursor::new(wrong_presence.as_slice()),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut Cursor::new(&bundle[..bundle.len() - 1]),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)
        ));
        let (_guard, directory) = secure_credential_directory_v1();
        write_credential_v1(
            &directory,
            GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
            &credential,
            0o600,
        );
        let loaded = RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
            &catalog,
            Some(&directory),
            &budget,
        )
        .expect("load beacon runtime credential");
        loaded
            .resolve(&catalog)
            .expect("resolve exact beacon backend");
        ExternalSoftwareSignerBackendsV1::new()
            .with_base_registry(Arc::new(loaded.clone()))
            .resolve(&catalog)
            .expect("compose threshold backend beneath external signer registry");

        let anchor = GlobalThresholdBeaconChainAnchorV1 {
            height: 40,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x81; 32])),
        };
        let mut verifier = GlobalThresholdBeaconPulseAggregatorV1::new(
            validated.clone(),
            41,
            anchor,
            iroha_core::beacon::pulse_context_fixture_v1(),
        )
        .expect("construct canonical beacon pulse");
        let partial = loaded
            .global_beacon
            .as_deref()
            .expect("loaded beacon backend")
            .sign_partial(&validated, verifier.payload())
            .expect("sign exact beacon pulse");
        assert!(
            verifier
                .accept_partial(partial)
                .expect("independently verify beacon partial")
        );
    }

    #[test]
    fn parliament_tle_credential_loads_resolves_and_signs_verified_partial() {
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = tle_fixture_v1(network_id, 0x72);
        let (projection, identity) = tle_projection_v1(&fixture);
        let validated = fixture.validated.clone();
        let provisioning = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive Parliament TLE inventory digest");
        let catalog = configured_consensus_catalog_v1(
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
            REVISION,
            policy_digest,
        );
        let credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
        )
        .expect("encode Parliament TLE runtime credential");
        let bundle = encode_consensus_threshold_credential_bundle_v1(None, Some(&credential))
            .expect("frame Parliament TLE credential for launchd stdin");
        let bundled =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut Cursor::new(bundle.as_slice()),
                &budget,
            )
            .expect("load Parliament TLE credential from launchd bundle");
        bundled
            .resolve(&catalog)
            .expect("resolve launchd-bundled Parliament TLE backend");
        let (_guard, directory) = secure_credential_directory_v1();
        write_credential_v1(
            &directory,
            PARLIAMENT_TLE_PARTIAL_RELEASE_SIGNER_CREDENTIAL_NAME_V1,
            &credential,
            0o600,
        );
        let loaded = RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
            &catalog,
            Some(&directory),
            &budget,
        )
        .expect("load Parliament TLE runtime credential");
        loaded.resolve(&catalog).expect("resolve exact TLE backend");
        ExternalSoftwareSignerBackendsV1::new()
            .with_base_registry(Arc::new(loaded.clone()))
            .resolve(&catalog)
            .expect("compose TLE backend beneath external signer registry");

        let partial = loaded
            .parliament_tle
            .as_deref()
            .expect("loaded TLE backend")
            .sign_projected_partial_release(&projection)
            .expect("sign exact Parliament TLE projection");
        validated
            .verify_partial_release(&identity, 100, &partial)
            .expect("independently verify Parliament TLE partial");
    }

    include!("consensus_threshold/prepared_tests.rs");

    #[test]
    fn beacon_supervisor_restart_rotation_requires_revision_bump_and_removes_predecessor() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let predecessor = beacon_fixture_v1(network_id, 0x7B, &producer_budget);
        let predecessor_session = predecessor.validated.clone();
        let successor = beacon_fixture_v1(network_id, 0x7C, &producer_budget);
        let successor_session = successor.validated.clone();
        let old_provisioning = vec![
            RuntimeGlobalBeaconShareProvisioningV1::new(
                predecessor.validated.clone(),
                1,
                predecessor.components,
            ),
            RuntimeGlobalBeaconShareProvisioningV1::new(
                successor.validated.clone(),
                1,
                successor.components,
            ),
        ];
        let old_policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &old_provisioning)
                .expect("derive predecessor-plus-successor beacon inventory digest");
        let old_catalog = beacon_catalog_v1(old_policy_digest);
        let old_credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            old_policy_digest,
            old_provisioning,
            &producer_budget,
        )
        .expect("encode predecessor-plus-successor beacon credential");
        let (old_directory_guard, old_directory) = secure_credential_directory_v1();
        write_credential_v1(
            &old_directory,
            GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
            &old_credential,
            0o600,
        );
        let old_backend =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &old_catalog,
                Some(&old_directory),
                &budget,
            )
            .expect("start revision-N beacon backend");
        old_backend
            .resolve(&old_catalog)
            .expect("resolve revision-N beacon backend");
        for (session, marker) in [(&predecessor_session, 0x91), (&successor_session, 0x92)] {
            let mut verifier = beacon_pulse_aggregator_v1(session, marker);
            let partial = old_backend
                .global_beacon
                .as_deref()
                .expect("revision-N beacon backend")
                .sign_partial(session, verifier.payload())
                .expect("revision-N inventory signs both sessions");
            assert!(
                verifier
                    .accept_partial(partial)
                    .expect("verify revision-N beacon partial")
            );
        }

        let replacement_successor = beacon_fixture_v1(network_id, 0x7C, &producer_budget);
        let new_provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            replacement_successor.validated.clone(),
            1,
            replacement_successor.components,
        )];
        let new_policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &new_provisioning)
                .expect("derive successor-only beacon inventory digest");
        let new_catalog = beacon_catalog_with_revision_v1(REVISION + 1, new_policy_digest);
        assert_eq!(old_catalog.network_id(), new_catalog.network_id());
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &new_catalog,
                Some(&old_directory),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        drop(old_backend);
        drop(old_credential);
        drop(old_directory_guard);

        let new_credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION + 1,
            new_policy_digest,
            new_provisioning,
            &producer_budget,
        )
        .expect("encode successor-only beacon credential");
        let (_new_directory_guard, new_directory) = secure_credential_directory_v1();
        write_credential_v1(
            &new_directory,
            GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
            &new_credential,
            0o600,
        );
        let restarted_backend =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &new_catalog,
                Some(&new_directory),
                &budget,
            )
            .expect("restart with revision-N-plus-one beacon backend");
        restarted_backend
            .resolve(&new_catalog)
            .expect("resolve revision-N-plus-one beacon backend");

        let predecessor_pulse = beacon_pulse_aggregator_v1(&predecessor_session, 0x93);
        assert!(
            restarted_backend
                .global_beacon
                .as_deref()
                .expect("restarted beacon backend")
                .sign_partial(&predecessor_session, predecessor_pulse.payload())
                .is_err(),
            "the restarted successor-only inventory must not retain the predecessor"
        );
        let mut successor_pulse = beacon_pulse_aggregator_v1(&successor_session, 0x94);
        let successor_partial = restarted_backend
            .global_beacon
            .as_deref()
            .expect("restarted beacon backend")
            .sign_partial(&successor_session, successor_pulse.payload())
            .expect("restarted backend signs the successor session");
        assert!(
            successor_pulse
                .accept_partial(successor_partial)
                .expect("verify restarted successor beacon partial")
        );
    }

    #[test]
    fn tle_supervisor_restart_rotation_requires_revision_bump_and_removes_predecessor() {
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let predecessor = tle_fixture_v1(network_id, 0x7D);
        let predecessor_session = predecessor.validated.clone();
        let (predecessor_projection, predecessor_identity) = tle_projection_v1(&predecessor);
        let successor = tle_fixture_v1(network_id, 0x7E);
        let successor_session = successor.validated.clone();
        let (successor_projection, successor_identity) = tle_projection_v1(&successor);
        let old_provisioning = vec![
            RuntimeParliamentTleShareProvisioningV1::new(
                predecessor.validated.public_state().clone(),
                1,
                predecessor.components,
            ),
            RuntimeParliamentTleShareProvisioningV1::new(
                successor.validated.public_state().clone(),
                1,
                successor.components,
            ),
        ];
        let old_policy_digest = parliament_tle_partial_release_signer_inventory_digest_v1(
            network_id,
            &old_provisioning,
        )
        .expect("derive predecessor-plus-successor TLE inventory digest");
        let old_catalog = tle_catalog_v1(old_policy_digest);
        let old_credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            old_policy_digest,
            old_provisioning,
        )
        .expect("encode predecessor-plus-successor TLE credential");
        let (old_directory_guard, old_directory) = secure_credential_directory_v1();
        write_credential_v1(
            &old_directory,
            PARLIAMENT_TLE_PARTIAL_RELEASE_SIGNER_CREDENTIAL_NAME_V1,
            &old_credential,
            0o600,
        );
        let old_backend =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &old_catalog,
                Some(&old_directory),
                &budget,
            )
            .expect("start revision-N TLE backend");
        old_backend
            .resolve(&old_catalog)
            .expect("resolve revision-N TLE backend");
        for (session, projection, identity) in [
            (
                &predecessor_session,
                &predecessor_projection,
                &predecessor_identity,
            ),
            (
                &successor_session,
                &successor_projection,
                &successor_identity,
            ),
        ] {
            let partial = old_backend
                .parliament_tle
                .as_deref()
                .expect("revision-N TLE backend")
                .sign_projected_partial_release(projection)
                .expect("revision-N inventory signs both sessions");
            session
                .verify_partial_release(identity, 100, &partial)
                .expect("verify revision-N TLE partial");
        }

        let replacement_successor = tle_fixture_v1(network_id, 0x7E);
        let new_provisioning = vec![RuntimeParliamentTleShareProvisioningV1::new(
            replacement_successor.validated.public_state().clone(),
            1,
            replacement_successor.components,
        )];
        let new_policy_digest = parliament_tle_partial_release_signer_inventory_digest_v1(
            network_id,
            &new_provisioning,
        )
        .expect("derive successor-only TLE inventory digest");
        let new_catalog = tle_catalog_with_revision_v1(REVISION + 1, new_policy_digest);
        assert_eq!(old_catalog.network_id(), new_catalog.network_id());
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &new_catalog,
                Some(&old_directory),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        drop(old_backend);
        drop(old_credential);
        drop(old_directory_guard);

        let new_credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION + 1,
            new_policy_digest,
            new_provisioning,
        )
        .expect("encode successor-only TLE credential");
        let (_new_directory_guard, new_directory) = secure_credential_directory_v1();
        write_credential_v1(
            &new_directory,
            PARLIAMENT_TLE_PARTIAL_RELEASE_SIGNER_CREDENTIAL_NAME_V1,
            &new_credential,
            0o600,
        );
        let restarted_backend =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &new_catalog,
                Some(&new_directory),
                &budget,
            )
            .expect("restart with revision-N-plus-one TLE backend");
        restarted_backend
            .resolve(&new_catalog)
            .expect("resolve revision-N-plus-one TLE backend");

        assert!(
            restarted_backend
                .parliament_tle
                .as_deref()
                .expect("restarted TLE backend")
                .sign_projected_partial_release(&predecessor_projection)
                .is_err(),
            "the restarted successor-only inventory must not retain the predecessor"
        );
        let successor_partial = restarted_backend
            .parliament_tle
            .as_deref()
            .expect("restarted TLE backend")
            .sign_projected_partial_release(&successor_projection)
            .expect("restarted backend signs the successor session");
        successor_session
            .verify_partial_release(&successor_identity, 100, &successor_partial)
            .expect("verify restarted successor TLE partial");
    }

    fn tle_header_v1() -> ConsensusThresholdCredentialHeaderV1 {
        ConsensusThresholdCredentialHeaderV1::new(
            IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id(),
            network_id_v1(0xC1),
            HANDLE.to_owned(),
            REVISION,
            POLICY_DIGEST,
        )
    }

    #[test]
    fn secret_credential_encoding_ignores_ambient_layout_flags() {
        let wire = RuntimeParliamentTleSignerCredentialWireV1 {
            header: tle_header_v1(),
            sessions: Vec::new(),
        };
        let canonical =
            norito::encode_canonical(&wire).expect("encode canonical signer credential fixture");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::core::to_bytes(&wire).expect("encode alternate-layout signer fixture")
        };
        assert_ne!(alternate, canonical, "fixture must exercise layout drift");

        let encoded = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            encode_consensus_threshold_secret_credential_v1(&wire)
                .expect("bounded secret credential encoding must force canonical layout")
        };
        assert_eq!(encoded.as_slice(), canonical.as_slice());
    }

    #[test]
    fn consensus_threshold_frames_separate_credentials_and_public_inventories() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let tle = RuntimeParliamentTleSignerCredentialWireV1 {
            header: tle_header_v1(),
            sessions: Vec::new(),
        };
        let tle_bytes = crate::frame_test_support::assert_current_frame(
            &tle,
            "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTleSignerCredentialWireV1",
            PARLIAMENT_TLE_SIGNER_CREDENTIAL_SCHEMA_NAME_V1,
        );
        // A real Core-encoded beacon credential is a distinct signer credential root.
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network_id, 0x78, &producer_budget);
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive beacon inventory digest");
        let beacon_bytes = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode Core beacon credential");
        assert!(matches!(
            norito::decode_canonical::<RuntimeParliamentTleSignerCredentialWireV1>(&beacon_bytes),
            Err(norito::Error::SchemaMismatch)
        ));
        let beacon_catalog = beacon_catalog_v1(policy_digest);
        assert!(matches!(
            decode_global_beacon_credential_v1(
                &tle_bytes,
                beacon_catalog.network_id(),
                beacon_catalog.iter().next().expect("one beacon binding"),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        let tle_inventory = RuntimeParliamentTlePublicInventoryWireV1 {
            version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
            slot: tle.header.slot,
            network_id,
            sessions: Vec::new(),
        };
        crate::frame_test_support::assert_frame_encoding(
            &tle_inventory,
            "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTlePublicInventoryWireV1",
            PARLIAMENT_TLE_PUBLIC_INVENTORY_SCHEMA_NAME_V1,
        );
        assert_ne!(
            norito::schema::identity::frame_hash::<RuntimeParliamentTlePublicInventoryWireV1>(),
            norito::core::schema_hash_for_name(
                "iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_public_inventory"
            )
        );
        assert_ne!(
            consensus_threshold_public_inventory_digest_v1(&tle_inventory).expect("TLE digest"),
            policy_digest
        );

        // Containers compose the Rust nominal child, not its root projection.
        crate::frame_test_support::assert_nominal_container_frames(
            || RuntimeParliamentTleSignerCredentialWireV1 {
                header: tle_header_v1(),
                sessions: Vec::new(),
            },
            "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTleSignerCredentialWireV1",
            PARLIAMENT_TLE_SIGNER_CREDENTIAL_SCHEMA_NAME_V1,
        );
        crate::frame_test_support::assert_nominal_container_frames(
            || RuntimeParliamentTlePublicInventoryWireV1 {
                version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
                slot: tle.header.slot,
                network_id: network_id_v1(0xC1),
                sessions: Vec::new(),
            },
            "irohad::external_software_signer::consensus_threshold::RuntimeParliamentTlePublicInventoryWireV1",
            PARLIAMENT_TLE_PUBLIC_INVENTORY_SCHEMA_NAME_V1,
        );
    }

    #[test]
    fn consensus_threshold_top_level_schema_hashes_are_golden() {
        fn decoder_frame_hash<T: for<'de> NoritoDeserialize<'de>>() -> [u8; 16] {
            norito::schema::identity::frame_hash::<T>()
        }
        // Core owns and pins the global-beacon credential and inventory frames.
        for (name, expected_hash_hex, actual_hash) in [
            (
                PARLIAMENT_TLE_SIGNER_CREDENTIAL_SCHEMA_NAME_V1,
                "4071e4e5876f8a71466b3e94581b710b",
                norito::schema::identity::frame_hash::<RuntimeParliamentTleSignerCredentialWireV1>(
                ),
            ),
            (
                PARLIAMENT_TLE_PUBLIC_INVENTORY_SCHEMA_NAME_V1,
                "3087d1f9251cf172e937752119357b34",
                norito::schema::identity::frame_hash::<RuntimeParliamentTlePublicInventoryWireV1>(),
            ),
        ] {
            assert_eq!(hex::encode(actual_hash), expected_hash_hex);
            assert_eq!(
                actual_hash,
                norito::core::schema_hash_for_name(name),
                "derived schema hash drifted for {name}"
            );
        }
        assert_eq!(
            decoder_frame_hash::<RuntimeParliamentTleSignerCredentialWireV1>(),
            norito::schema::identity::frame_hash::<RuntimeParliamentTleSignerCredentialWireV1>(),
        );
    }

    #[test]
    fn public_inventory_digests_are_order_stable_and_seat_bound() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let first = beacon_fixture_v1(network_id, 0x81, &producer_budget);
        let second = beacon_fixture_v1(network_id, 0x82, &producer_budget);
        let mut beacon_inventory = vec![
            RuntimeGlobalBeaconShareProvisioningV1::new(
                first.validated.clone(),
                1,
                first.components,
            ),
            RuntimeGlobalBeaconShareProvisioningV1::new(
                second.validated.clone(),
                1,
                second.components,
            ),
        ];
        let beacon_forward =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &beacon_inventory)
                .expect("derive forward beacon inventory digest");
        beacon_inventory.reverse();
        let beacon_reverse =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &beacon_inventory)
                .expect("derive reverse beacon inventory digest");
        assert_eq!(beacon_forward, beacon_reverse);
        let reverse_credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            beacon_reverse,
            beacon_inventory,
            &producer_budget,
        )
        .expect("encode reverse-ordered beacon inventory");
        let first = beacon_fixture_v1(network_id, 0x81, &producer_budget);
        let second = beacon_fixture_v1(network_id, 0x82, &producer_budget);
        let forward_credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            beacon_forward,
            vec![
                RuntimeGlobalBeaconShareProvisioningV1::new(
                    first.validated.clone(),
                    1,
                    first.components,
                ),
                RuntimeGlobalBeaconShareProvisioningV1::new(
                    second.validated.clone(),
                    1,
                    second.components,
                ),
            ],
            &producer_budget,
        )
        .expect("encode forward-ordered beacon inventory");
        assert_eq!(&*forward_credential, &*reverse_credential);
        let beacon_catalog = beacon_catalog_v1(beacon_forward);
        decode_global_beacon_credential_v1(
            &forward_credential,
            beacon_catalog.network_id(),
            beacon_catalog.iter().next().expect("one beacon binding"),
            &budget,
        )
        .expect("decode canonical two-session beacon inventory");

        let seat_fixture = beacon_fixture_v1(network_id, 0x83, &producer_budget);
        let seat_one = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            seat_fixture.validated.clone(),
            1,
            Zeroizing::new(*seat_fixture.components),
        )];
        let seat_two = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            seat_fixture.validated.clone(),
            2,
            seat_fixture.components,
        )];
        assert_ne!(
            global_beacon_partial_signer_inventory_digest_v1(network_id, &seat_one)
                .expect("derive beacon seat-one inventory digest"),
            global_beacon_partial_signer_inventory_digest_v1(network_id, &seat_two)
                .expect("derive beacon seat-two inventory digest")
        );

        let first = tle_fixture_v1(network_id, 0x84);
        let second = tle_fixture_v1(network_id, 0x85);
        let mut tle_inventory = vec![
            RuntimeParliamentTleShareProvisioningV1::new(
                first.validated.public_state().clone(),
                1,
                first.components,
            ),
            RuntimeParliamentTleShareProvisioningV1::new(
                second.validated.public_state().clone(),
                1,
                second.components,
            ),
        ];
        let tle_forward =
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &tle_inventory)
                .expect("derive forward TLE inventory digest");
        tle_inventory.reverse();
        let tle_reverse =
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &tle_inventory)
                .expect("derive reverse TLE inventory digest");
        assert_eq!(tle_forward, tle_reverse);
        let reverse_credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            tle_reverse,
            tle_inventory,
        )
        .expect("encode reverse-ordered TLE inventory");
        let first = tle_fixture_v1(network_id, 0x84);
        let second = tle_fixture_v1(network_id, 0x85);
        let forward_credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            tle_forward,
            vec![
                RuntimeParliamentTleShareProvisioningV1::new(
                    first.validated.public_state().clone(),
                    1,
                    first.components,
                ),
                RuntimeParliamentTleShareProvisioningV1::new(
                    second.validated.public_state().clone(),
                    1,
                    second.components,
                ),
            ],
        )
        .expect("encode forward-ordered TLE inventory");
        assert_eq!(&*forward_credential, &*reverse_credential);
        let tle_catalog = tle_catalog_v1(tle_forward);
        let mut reordered_wire: RuntimeParliamentTleSignerCredentialWireV1 =
            decode_consensus_threshold_credential_v1(&forward_credential)
                .expect("decode canonical TLE credential for order substitution");
        reordered_wire.sessions.reverse();
        let reordered_credential = encode_consensus_threshold_secret_credential_v1(&reordered_wire)
            .expect("encode noncanonical TLE session order");
        assert!(matches!(
            decode_parliament_tle_credential_v1(
                &reordered_credential,
                tle_catalog.network_id(),
                tle_catalog.iter().next().expect("one TLE binding"),
                &test_credential_budget(),
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));

        let seat_fixture = tle_fixture_v1(network_id, 0x86);
        let seat_one = vec![RuntimeParliamentTleShareProvisioningV1::new(
            seat_fixture.validated.public_state().clone(),
            1,
            Zeroizing::new(*seat_fixture.components),
        )];
        let seat_two = vec![RuntimeParliamentTleShareProvisioningV1::new(
            seat_fixture.validated.public_state().clone(),
            2,
            seat_fixture.components,
        )];
        assert_ne!(
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &seat_one)
                .expect("derive TLE seat-one inventory digest"),
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &seat_two)
                .expect("derive TLE seat-two inventory digest")
        );
    }

    #[test]
    fn same_revision_public_inventory_substitution_fails_closed() {
        // Core owns the global-beacon wire; its substitution test lives beside the codec.
        let network_id = network_id_v1(0xC1);
        let expected = tle_fixture_v1(network_id, 0x89);
        let expected_inventory = vec![RuntimeParliamentTleShareProvisioningV1::new(
            expected.validated.public_state().clone(),
            1,
            expected.components,
        )];
        let expected_digest = parliament_tle_partial_release_signer_inventory_digest_v1(
            network_id,
            &expected_inventory,
        )
        .expect("derive expected TLE inventory digest");
        let catalog = tle_catalog_v1(expected_digest);
        drop(expected_inventory);

        let substituted = tle_fixture_v1(network_id, 0x8A);
        let substituted_inventory = vec![RuntimeParliamentTleShareProvisioningV1::new(
            substituted.validated.public_state().clone(),
            1,
            substituted.components,
        )];
        let substituted_digest = parliament_tle_partial_release_signer_inventory_digest_v1(
            network_id,
            &substituted_inventory,
        )
        .expect("derive substituted TLE inventory digest");
        assert_ne!(expected_digest, substituted_digest);
        let credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            substituted_digest,
            substituted_inventory,
        )
        .expect("encode substituted TLE inventory");
        let mut wire: RuntimeParliamentTleSignerCredentialWireV1 =
            decode_consensus_threshold_credential_v1(&credential)
                .expect("decode substituted TLE inventory");
        wire.header.policy_digest = expected_digest;
        let rebound = encode_consensus_threshold_secret_credential_v1(&wire)
            .expect("rebind substituted TLE header to expected policy digest");
        assert!(matches!(
            decode_parliament_tle_credential_v1(
                &rebound,
                catalog.network_id(),
                catalog.iter().next().expect("one TLE binding"),
                &test_credential_budget(),
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
    }

    #[test]
    fn credential_header_substitution_and_noncanonical_bytes_fail_closed() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network_id, 0x73, &producer_budget);
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive substituted-header inventory digest");
        let catalog = beacon_catalog_v1(policy_digest);
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode valid beacon credential");
        decode_global_beacon_credential_v1(
            &credential,
            catalog.network_id(),
            catalog.iter().next().expect("one binding"),
            &budget,
        )
        .expect("exact catalog binding");
        // Every configured qualification field is bound to the Core credential header.
        let foreign_handle = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "consensus-threshold-credential-test",
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
            "software://iroha/consensus-threshold/other",
            REVISION,
            policy_digest,
        )
        .with_network_id_for_test(network_id);
        let tle_slot = tle_catalog_v1(policy_digest);
        for (network, catalog) in [
            (network_id_v1(0x91), beacon_catalog_v1(policy_digest)),
            (network_id, foreign_handle),
            (
                network_id,
                beacon_catalog_with_revision_v1(REVISION + 1, policy_digest),
            ),
            (network_id, beacon_catalog_v1([0xA8; 32])),
            (network_id, tle_slot),
        ] {
            assert!(matches!(
                decode_global_beacon_credential_v1(
                    &credential,
                    &network,
                    catalog.iter().next().expect("one binding"),
                    &budget,
                ),
                Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
            ));
        }
        let mut noncanonical = Zeroizing::new(credential.to_vec());
        noncanonical.push(0);
        assert!(matches!(
            decode_global_beacon_credential_v1(
                &noncanonical,
                catalog.network_id(),
                catalog.iter().next().expect("one binding"),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
    }

    #[test]
    fn tle_credential_header_substitution_fails_closed() {
        // The broker-owned TLE codec validates the same shared Core header.
        let network_id = network_id_v1(0xC1);
        let fixture = tle_fixture_v1(network_id, 0x7F);
        let provisioning = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            parliament_tle_partial_release_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive TLE inventory digest");
        let catalog = tle_catalog_v1(policy_digest);
        let credential = encode_parliament_tle_partial_release_signer_credential_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
        )
        .expect("encode valid TLE credential");
        for substitution in 0..5 {
            let mut wire: RuntimeParliamentTleSignerCredentialWireV1 =
                decode_consensus_threshold_credential_v1(&credential)
                    .expect("decode valid credential for adversarial mutation");
            match substitution {
                0 => wire.header.network_id = network_id_v1(0x91),
                1 => wire.header.handle = "software://iroha/consensus-threshold/other".to_owned(),
                2 => wire.header.revision += 1,
                3 => wire.header.policy_digest = [0xA8; 32],
                4 => {
                    wire.header.slot =
                        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id();
                }
                _ => unreachable!(),
            }
            let substituted = encode_consensus_threshold_secret_credential_v1(&wire)
                .expect("encode structurally canonical substituted credential");
            assert!(matches!(
                decode_parliament_tle_credential_v1(
                    &substituted,
                    catalog.network_id(),
                    catalog.iter().next().expect("one binding"),
                    &test_credential_budget(),
                ),
                Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
            ));
        }
    }

    #[test]
    fn duplicate_empty_and_invalid_session_inventories_fail_closed() {
        let producer_budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        assert!(matches!(
            beacon_credential_fixture_v1(
                network_id,
                HANDLE,
                REVISION,
                POLICY_DIGEST,
                Vec::new(),
                &producer_budget
            ),
            Err(ConsensusThresholdCredentialErrorV1::Rejected)
        ));

        let fixture = beacon_fixture_v1(network_id, 0x74, &producer_budget);
        let duplicate = beacon_fixture_v1(network_id, 0x74, &producer_budget);
        let duplicate_provisioning = vec![
            RuntimeGlobalBeaconShareProvisioningV1::new(
                fixture.validated.clone(),
                1,
                fixture.components,
            ),
            RuntimeGlobalBeaconShareProvisioningV1::new(
                duplicate.validated.clone(),
                1,
                duplicate.components,
            ),
        ];
        let duplicate_policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &duplicate_provisioning)
                .expect("derive duplicate beacon inventory digest");
        assert!(matches!(
            beacon_credential_fixture_v1(
                network_id,
                HANDLE,
                REVISION,
                duplicate_policy_digest,
                duplicate_provisioning,
                &producer_budget
            ),
            Err(ConsensusThresholdCredentialErrorV1::Rejected)
        ));

        let fixture = tle_fixture_v1(network_id, 0x75);
        let invalid_provisioning = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            Zeroizing::new([[0; 32]; 3]),
        )];
        let invalid_policy_digest = parliament_tle_partial_release_signer_inventory_digest_v1(
            network_id,
            &invalid_provisioning,
        )
        .expect("derive invalid-share TLE inventory digest");
        assert!(matches!(
            encode_parliament_tle_partial_release_signer_credential_v1(
                network_id,
                HANDLE,
                REVISION,
                invalid_policy_digest,
                invalid_provisioning,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
    }

    #[test]
    fn missing_insecure_and_symlink_credentials_fail_closed() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network_id, 0x76, &producer_budget);
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive credential-source inventory digest");
        let catalog = beacon_catalog_v1(policy_digest);
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode valid credential");
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &catalog, None, &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)
        ));
        let (_guard, directory) = secure_credential_directory_v1();
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &catalog,
                Some(&directory),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)
        ));

        let path = write_credential_v1(
            &directory,
            GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
            &credential,
            0o644,
        );
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &catalog,
                Some(&directory),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
        fs::remove_file(&path).expect("remove insecure credential");
        let target = write_credential_v1(&directory, "credential-target", &credential, 0o600);
        symlink(&target, &path).expect("substitute credential symlink");
        assert!(matches!(
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &catalog,
                Some(&directory),
                &budget,
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
                | Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)
        ));
    }

    #[test]
    fn qualification_drift_and_test_marking_remain_fail_closed() {
        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
        let network_id = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network_id, 0x77, &producer_budget);
        let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy_digest =
            global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning)
                .expect("derive qualification inventory digest");
        let catalog = beacon_catalog_v1(policy_digest);
        let credential = beacon_credential_fixture_v1(
            network_id,
            HANDLE,
            REVISION,
            policy_digest,
            provisioning,
            &producer_budget,
        )
        .expect("encode valid credential");
        let backend = decode_global_beacon_credential_v1(
            &credential,
            catalog.network_id(),
            catalog.iter().next().expect("one binding"),
            &budget,
        )
        .expect("decode exact credential");
        let mut drifted = RuntimeConsensusThresholdSignerBackendsV1 {
            global_beacon: Some(backend),
            parliament_tle: None,
        };
        Arc::get_mut(
            drifted
                .global_beacon
                .as_mut()
                .expect("unique beacon backend"),
        )
        .expect("backend has one owner")
        .qualification =
            ConsensusSignerProviderQualificationV1::new(REVISION + 1, policy_digest, false);
        assert!(matches!(
            drifted.resolve(&catalog),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        Arc::get_mut(
            drifted
                .global_beacon
                .as_mut()
                .expect("unique beacon backend"),
        )
        .expect("backend has one owner")
        .qualification = ConsensusSignerProviderQualificationV1::new(REVISION, policy_digest, true);
        assert!(matches!(
            drifted.resolve(&catalog),
            Err(IrohaRuntimeProviderRegistryErrorV1::TestProviderRejected)
        ));
    }

    fn network_id_v1(marker: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([marker; 32]),
        ))
    }
    #[test]
    fn global_beacon_runtime_import_preserves_original_pool_and_aggregate_inventory_limit() {
        let producer_budget = test_credential_budget();
        let network = network_id_v1(0xC1);
        let first = beacon_fixture_v1(network, 0xC2, &producer_budget);
        let second = beacon_fixture_v1(network, 0xC3, &producer_budget);
        let inventory = vec![
            RuntimeGlobalBeaconShareProvisioningV1::new(
                first.validated.clone(),
                1,
                Zeroizing::new(*first.components),
            ),
            RuntimeGlobalBeaconShareProvisioningV1::new(
                second.validated.clone(),
                1,
                Zeroizing::new(*second.components),
            ),
        ];
        let policy = global_beacon_partial_signer_inventory_digest_v1(network, &inventory).unwrap();
        let catalog = beacon_catalog_v1(policy);
        let binding = catalog.iter().next().unwrap();
        let bytes = beacon_credential_fixture_v1(
            network,
            HANDLE,
            REVISION,
            policy,
            inventory,
            &producer_budget,
        )
        .unwrap();
        let original_hash = Hash::new(bytes.as_slice());
        let first_bytes = iroha_core::beacon::global_threshold_beacon_session_allocation_bytes_v1(
            &first.record,
            &beacon_binding_v1(&first.record),
        )
        .unwrap();
        let second_bytes = iroha_core::beacon::global_threshold_beacon_session_allocation_bytes_v1(
            &second.record,
            &beacon_binding_v1(&second.record),
        )
        .unwrap();
        let budget = AllocationBudget::new(first_bytes.max(second_bytes));
        let error = decode_global_beacon_runtime_signer_v1(&bytes, &network, binding, &budget)
            .err()
            .expect("one-session credits cannot retain both current and pending sessions");
        let RuntimeConsensusThresholdSignerCredentialErrorV1::Session(
            GlobalThresholdBeaconSessionError::Admission(
                iroha_allocation::AllocationRefusal::Capacity {
                    requested_bytes,
                    reserved_bytes,
                    limit_bytes,
                    ..
                },
            ),
        ) = error
        else {
            panic!(
                "aggregate retained inventory pressure must preserve local capacity classification"
            )
        };
        assert!(
            reserved_bytes > 0,
            "the first original graph remained charged when the second was admitted"
        );
        assert!(requested_bytes <= limit_bytes);
        assert_eq!(limit_bytes, budget.limit_bytes());
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "failed complete import releases earlier entries"
        );
        assert_eq!(Hash::new(bytes.as_slice()), original_hash);
        budget.set_limit_bytes(first_bytes + second_bytes);
        let signer =
            decode_global_beacon_runtime_signer_v1(&bytes, &network, binding, &budget).unwrap();
        signer
            .attest_partial_signing_capability(&first.validated, 1)
            .unwrap();
        signer
            .attest_partial_signing_capability(&second.validated, 1)
            .unwrap();
        let retained = budget.reserved_bytes();
        assert!(retained > 0);
        let last = Arc::clone(&signer);
        drop(signer);
        assert_eq!(budget.reserved_bytes(), retained);
        drop(last);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(Hash::new(bytes.as_slice()), original_hash);
    }

    #[test]
    fn global_beacon_credential_loader_retains_exact_original_refusal() {
        let producer_budget = test_credential_budget();
        let network = network_id_v1(0xC1);
        let fixture = beacon_fixture_v1(network, 0xC4, &producer_budget);
        let inventory = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
            fixture.validated.clone(),
            1,
            fixture.components,
        )];
        let policy = global_beacon_partial_signer_inventory_digest_v1(network, &inventory).unwrap();
        let catalog = beacon_catalog_v1(policy);
        let bytes = beacon_credential_fixture_v1(
            network,
            HANDLE,
            REVISION,
            policy,
            inventory,
            &producer_budget,
        )
        .unwrap();
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&bytes), None).unwrap();
        let budget = test_credential_budget();
        let held = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let error =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut bundle.as_slice(),
                &budget,
            )
            .err()
            .expect("original registry pool is full");
        let RuntimeConsensusThresholdSignerCredentialErrorV1::Session(
            GlobalThresholdBeaconSessionError::Admission(actual),
        ) = error
        else {
            panic!("loader must preserve original admission refusal")
        };
        let iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes, ..
        } = &actual
        else {
            panic!("actual pool is temporarily held")
        };
        assert_eq!(
            actual,
            budget.try_reserve_bytes(*requested_bytes).unwrap_err()
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(held);
        let loaded =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
                &catalog,
                &mut bundle.as_slice(),
                &budget,
            )
            .unwrap();
        assert!(budget.reserved_bytes() > 0);
        loaded
            .global_beacon
            .as_ref()
            .unwrap()
            .attest_partial_signing_capability(&fixture.validated, 1)
            .unwrap();
        drop(loaded);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(matches!(
            decode_global_beacon_runtime_signer_v1(
                &bytes,
                &network_id_v1(0xCE),
                catalog.iter().next().unwrap(),
                &budget
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
    }

    #[test]
    fn global_and_tle_credentials_keep_local_decode_origin_after_scope_and_retry_exact_bytes() {
        let beacon = consensus_threshold_beacon_broker_test_fixture_v1();
        let budget = test_credential_budget();
        let beacon_hash = Hash::new(beacon.credential.as_slice());
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let failed = norito::with_decode_limits_scope(limits, || {
            decode_global_beacon_credential_v1(
                &beacon.credential,
                beacon.catalog.network_id(),
                beacon.catalog.iter().next().unwrap(),
                &budget,
            )
        })
        .err()
        .expect("actual inherited decoder limit");
        assert_eq!(
            failed.to_string(),
            "consensus threshold-signer credential decoder is unavailable"
        );
        assert!(std::error::Error::source(&failed).is_some());
        let RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(error) = failed else {
            panic!("local decoder failure cannot reject a credential");
        };
        assert_eq!(
            error.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(matches!(
            error.into_error(),
            norito::Error::ScopedDecodeResource(_)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        let backend = decode_global_beacon_credential_v1(
            &beacon.credential,
            beacon.catalog.network_id(),
            beacon.catalog.iter().next().unwrap(),
            &budget,
        )
        .unwrap();
        assert_eq!(Hash::new(beacon.credential.as_slice()), beacon_hash);
        drop(backend);
        assert_eq!(budget.reserved_bytes(), 0);

        let network = network_id_v1(0xC1);
        let fixture = tle_fixture_v1(network, 0xD8);
        let provisions = vec![RuntimeParliamentTleShareProvisioningV1::new(
            fixture.validated.public_state().clone(),
            1,
            fixture.components,
        )];
        let digest =
            parliament_tle_partial_release_signer_inventory_digest_v1(network, &provisions)
                .unwrap();
        let catalog = tle_catalog_v1(digest);
        let bytes = encode_parliament_tle_partial_release_signer_credential_v1(
            network, HANDLE, REVISION, digest, provisions,
        )
        .unwrap();
        let original = Hash::new(bytes.as_slice());
        let failed = norito::with_decode_limits_scope(limits, || {
            decode_parliament_tle_credential_v1(
                &bytes,
                &network,
                catalog.iter().next().unwrap(),
                &test_credential_budget(),
            )
        })
        .err()
        .expect("actual inherited TLE decoder limit");
        assert_eq!(
            failed.to_string(),
            "consensus threshold-signer credential decoder is unavailable"
        );
        let RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(error) = failed else {
            panic!("TLE must preserve the same shared decoder failure");
        };
        assert_eq!(
            error.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        let backend = decode_parliament_tle_credential_v1(
            &bytes,
            &network,
            catalog.iter().next().unwrap(),
            &test_credential_budget(),
        )
        .unwrap();
        assert_eq!(Hash::new(bytes.as_slice()), original);
        drop(backend);
        assert!(matches!(
            decode_parliament_tle_credential_v1(
                &[],
                &network,
                catalog.iter().next().unwrap(),
                &test_credential_budget(),
            ),
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected)
        ));
    }
}
