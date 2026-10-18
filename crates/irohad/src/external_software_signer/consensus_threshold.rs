//! Runtime-credential software custody for the consensus threshold-signing broker slot.
//!
//! The standard broker reads the fixed supervisor credential name only when
//! the public catalog requests the global-beacon slot. The credential envelope
//! binds the exact provider qualification and genesis-derived network identity
//! to complete public DKG transcripts plus zeroizing scalar triples. Startup
//! replays Core's cryptographic import checks before exposing the backend.
//! Core owns the global-beacon credential codec and the shared credential
//! framing (`iroha_core::beacon::credential`); this module owns the launchd
//! bundle and broker backend resolution.
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

mod prepared;
mod provisioning_command;
pub use prepared::{
    RuntimePreparedGlobalBeaconCredentialV1, prepare_global_beacon_transition_credential_v1,
};
pub use provisioning_command::dispatch_if_requested as dispatch_beacon_custody_preparation_if_requested;

use crate::runtime_credential::{RuntimeCredentialErrorV1, load_bounded_runtime_credential_v1};
use crate::{
    ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1,
    GlobalBeaconPartialSignerBrokerBackendV1, IrohaRuntimeProviderBindingV1,
    IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderRegistryErrorV1,
    IrohaRuntimeProviderSlotV1, RuntimeProviderBrokerBackendRegistryV1,
    RuntimeProviderBrokerBackendsV1,
};
use iroha_allocation::AllocationBudget;
use iroha_core::beacon::RuntimeGlobalThresholdBeaconShareCustodyV1;
use iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1;
use iroha_core::beacon::credential::CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1;
use iroha_core::beacon::credential::ConsensusThresholdCredentialDecodeErrorV1;
use iroha_core::beacon::credential::ConsensusThresholdCredentialErrorV1;
use iroha_core::beacon::credential::GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1;
use iroha_core::beacon::credential::MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1;
use iroha_core::beacon::credential::RuntimeGlobalBeaconShareProvisioningV1;
use iroha_core::beacon::credential::decode_global_beacon_partial_signer_credential_shares_v1;
use iroha_core::beacon::credential::decode_global_beacon_partial_signer_credential_v1;
use iroha_core::beacon::credential::encode_global_beacon_partial_signer_credential_v1;
use iroha_core::beacon::credential::global_beacon_partial_signer_inventory_digest_v1;
use iroha_core::beacon::credential::{
    GlobalBeaconCredentialEncodeErrorV1, GlobalBeaconCredentialImportErrorV1,
    PreparedGlobalBeaconCredentialV1, SecretConsensusThresholdCredentialV1,
};
use iroha_core::beacon::{
    GlobalThresholdBeaconPartialSignerV1 as _, GlobalThresholdBeaconSessionError,
};
use iroha_data_model::{NetworkId, consensus::GlobalThresholdBeaconPartialSignatureV1};
use std::{fmt, path::Path, sync::Arc};
use zeroize::{Zeroize as _, Zeroizing};

/// Fixed supervisor credential containing global-beacon software shares.
pub const GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1: &str =
    "iroha-global-beacon-partial-signer-v1.norito";

// Core's credential codec binds the same stable slot identifier.
const _: () = assert!(
    IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
        == GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1
);

const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1: [u8; 8] = *b"IRTHB001";
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_HEADER_BYTES_V1: usize = 20;
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1: u16 = 1 << 0;
const CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_KNOWN_FLAGS_V1: u16 =
    CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1;

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
}

impl fmt::Display for RuntimeConsensusThresholdSignerCredentialErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "consensus threshold-signer runtime credential was rejected",
            Self::Unavailable => "consensus threshold-signer runtime credential is unavailable",
            Self::Encoding => "consensus threshold-signer runtime credential encoding failed",
            Self::Session(_) => "consensus threshold-signer original session admission failed",
            Self::Output(_) => "consensus threshold-signer prepared output failed",
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

/// Frame the optional global-beacon threshold credential for one launchd stdin handoff.
///
/// The bundle contains only a fixed header and the already canonical secret
/// credential frame. Its allocation is reserved once and zeroized on drop.
/// A deployment-owned administrator writes the returned bytes once to the
/// root-protected launchd FIFO; neither secret bytes nor source paths enter the
/// broker argv, environment, plist, public catalog, or filesystem namespace.
///
/// # Errors
///
/// Rejects an empty or oversized credential frame and total-length overflow.
pub fn encode_consensus_threshold_credential_bundle_v1(
    global_beacon: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeConsensusThresholdSignerCredentialErrorV1> {
    let global_len = match global_beacon {
        None => 0,
        Some(credential) => {
            if credential.is_empty()
                || credential.len() > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1
            {
                return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
            }
            credential.len()
        }
    };
    let encoded_len = CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_HEADER_BYTES_V1
        .checked_add(global_len)
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
    encoded.extend_from_slice(&CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1);
    encoded.extend_from_slice(&CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1.to_be_bytes());
    encoded.extend_from_slice(&flags.to_be_bytes());
    encoded.extend_from_slice(
        &u64::try_from(global_len)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Encoding)?
            .to_be_bytes(),
    );
    if let Some(credential) = global_beacon {
        encoded.extend_from_slice(credential);
    }
    debug_assert_eq!(encoded.len(), encoded_len);
    Ok(encoded)
}

/// Exact backend registry populated from the runtime credential.
///
/// The registry owns only zeroizing Core custody objects plus stable public
/// qualification. It exposes no share inventory or secret-export operation.
#[derive(Clone, Default)]
pub struct RuntimeConsensusThresholdSignerBackendsV1 {
    global_beacon: Option<Arc<RuntimeGlobalBeaconPartialSignerBackendV1>>,
}

impl RuntimeConsensusThresholdSignerBackendsV1 {
    /// Construct an empty exact registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            global_beacon: None,
        }
    }

    /// Consume one exact launchd stdin credential bundle.
    ///
    /// launchd opens a root-protected FIFO before changing to the broker UID.
    /// The independent administrator writes one bundle and closes the writer;
    /// this reader never resolves a secret pathname. Bundle presence must
    /// exactly match the threshold slot requested by the public catalog.
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
        let global_present = flags & CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_GLOBAL_BEACON_V1 != 0;
        if header[..8] != CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_MAGIC_V1
            || version != CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1
            || flags & !CONSENSUS_THRESHOLD_CREDENTIAL_BUNDLE_KNOWN_FLAGS_V1 != 0
            || flags != requested_flags
            || global_present != (global_len != 0)
            || global_len > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1
        {
            return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected);
        }
        let mut allocation = Vec::new();
        allocation
            .try_reserve_exact(global_len)
            .map_err(|_| RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)?;
        allocation.resize(global_len, 0);
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

        let mut loaded = Self::new();
        for configured in catalog.iter() {
            if configured.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner {
                loaded.global_beacon = Some(decode_global_beacon_credential_v1(
                    &payload,
                    catalog.network_id(),
                    configured,
                    budget,
                )?);
            }
        }
        Ok(loaded)
    }

    /// Load the requested threshold signer from its fixed runtime credential.
    ///
    /// `credential_directory` is normally the supervisor-provided
    /// `CREDENTIALS_DIRECTORY`. It may be absent only when the catalog does not
    /// request the threshold-signing slot. The credential file name is fixed by
    /// this module; no path or secret value is accepted through configuration.
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
            if configured.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner {
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
pub fn decode_global_beacon_runtime_signer_v1(
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

impl RuntimeProviderBrokerBackendRegistryV1 for RuntimeConsensusThresholdSignerBackendsV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<RuntimeProviderBrokerBackendsV1, IrohaRuntimeProviderRegistryErrorV1> {
        let mut requested_global = false;
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
                _ => return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution),
            }
        }
        if requested_global != self.global_beacon.is_some() {
            return Err(IrohaRuntimeProviderRegistryErrorV1::UnexpectedProviders);
        }
        let mut resolved = RuntimeProviderBrokerBackendsV1::new();
        if let Some(backend) = &self.global_beacon {
            resolved = resolved.with_global_beacon_partial_signer(backend.clone());
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
pub mod tests {
    fn test_credential_budget() -> AllocationBudget {
        AllocationBudget::new(256 * 1024 * 1024)
    }

    use super::*;
    use crate::external_software_signer::ExternalSoftwareSignerBackendsV1;
    use iroha_config::parameters::actual::Root as Config;
    use iroha_config_base::toml::TomlSource;
    use iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1;
    use iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1;
    use iroha_core::beacon::complete_beacon_dkg_fixture_for_seat_v1;
    use iroha_core::beacon::validate_global_threshold_beacon_session_v1;
    use iroha_crypto::{Hash, HashOf, threshold_bls::THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1};
    use iroha_data_model::{
        block::BlockHeader,
        consensus::{GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconKeySessionV1},
    };
    use std::{
        fs,
        io::{Cursor, Write as _},
        os::unix::fs::{PermissionsExt as _, symlink},
        path::{Path, PathBuf},
    };

    const HANDLE: &str = "software://iroha/consensus-threshold/primary";
    const REVISION: u64 = 7;
    const POLICY_DIGEST: [u8; 32] = [0xA7; 32];
    struct BeaconFixtureV1 {
        record: GlobalThresholdBeaconKeySessionV1,
        validated: ValidatedGlobalThresholdBeaconSessionV1,
        components: Zeroizing<[[u8; 32]; 3]>,
    }

    /// Fully resolved beacon signer fixture used by authenticated broker tests.
    pub struct ConsensusThresholdBeaconBrokerTestFixtureV1 {
        /// Exact runtime-provider catalog bound into the credential.
        pub(crate) catalog: IrohaRuntimeProviderBindingsV1,
        /// Broker backends resolved from the canonical credential.
        pub(crate) backends: RuntimeProviderBrokerBackendsV1,
        /// Independently validated public session used to verify partials.
        pub(crate) session: ValidatedGlobalThresholdBeaconSessionV1,
        /// Synthetic canonical credential retained only for consumed-descriptor tests.
        pub(crate) credential: SecretConsensusThresholdCredentialV1,
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
            budget,
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
            budget,
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
            budget,
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
        let validated = validate_global_threshold_beacon_session_v1(&record, &binding, budget)
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
        let encoded = produce();
        // Encoding consumes provisioning custody; release the secret scalars before returning.
        drop(shares);
        encoded.map_err(|error| match error {
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
        beacon_fixture_with_committee_v1(network_id, session_byte, 4, budget)
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
    pub fn consensus_threshold_beacon_broker_test_fixture_v1()
    -> ConsensusThresholdBeaconBrokerTestFixtureV1 {
        consensus_threshold_beacon_broker_test_fixture_for_committee_v1(4, 0x79)
    }

    /// Build an exact-roster provider fixture for the separate readiness broker operation.
    pub fn consensus_threshold_beacon_readiness_broker_test_fixture_v1() -> (
        ConsensusThresholdBeaconBrokerTestFixtureV1,
        iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
        iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
    ) {
        use iroha_data_model::{
            nexus::ValidatorSeatReadinessContextV1,
            sumeragi::epoch::{InstalledBeaconEpochBindingV1, ValidatorGenerationV1},
        };

        let producer_budget = test_credential_budget();
        let budget = test_credential_budget();
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
    pub fn consensus_threshold_beacon_broker_max_committee_test_fixture_v1()
    -> ConsensusThresholdBeaconBrokerTestFixtureV1 {
        consensus_threshold_beacon_broker_test_fixture_for_committee_v1(
            THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
            0x7F,
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
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&credential))
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
        let other_slot = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "consensus-threshold-credential-test",
            IrohaRuntimeProviderSlotV1::ReputationThresholdSigner,
            HANDLE,
            REVISION,
            policy_digest,
        )
        .with_network_id_for_test(network_id);
        for (network, catalog) in [
            (network_id_v1(0x91), beacon_catalog_v1(policy_digest)),
            (network_id, foreign_handle),
            (
                network_id,
                beacon_catalog_with_revision_v1(REVISION + 1, policy_digest),
            ),
            (network_id, beacon_catalog_v1([0xA8; 32])),
            (network_id, other_slot),
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
    fn duplicate_and_empty_session_inventories_fail_closed() {
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
            Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected
                | RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable)
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
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&bytes)).unwrap();
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
    fn global_beacon_credential_keeps_local_decode_origin_after_scope_and_retry_exact_bytes() {
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
    }
}
