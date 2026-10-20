//! Explicit candidate testing selected by original signed genesis.
//!
//! This policy selects the actual candidate relation for engineering tests. It grants no
//! qualification, State installation, execution finality, SCCP or enactment authority.
//! Absence from original signed genesis disables candidate testing. A mutable World
//! parameter, caller-authored policy or chain label cannot construct the authenticated
//! selection below.
//!
//! TODO(E2): install this selection immutably through original genesis execution, preserve
//! its source through replay, and consume it only in the complete authenticated ballot
//! State adapter. Keep production certification and enactment separately qualified.

use iroha_crypto::HashOf;
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    AnonymousBallotCodecErrorV1, ProofProfileIdV1,
    framing::{decode_enc_bounded, enc_bounded},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId,
    block::SignedBlock,
    isi::SetParameter,
    parameter::{CustomParameter, CustomParameterId, Parameter},
    sumeragi_finality::{AuthenticatedGenesis, AuthenticatedSignedGenesisV1, GenesisReadError},
    transaction::{Executable, TransactionEntrypoint},
};

/// Why a candidate selection cannot be decoded or authenticated.
///
/// Original JSON decoding/re-encoding errors and binary decoder refusals stay typed:
/// a caller must not turn local allocation or enclosing-budget refusal into a committed
/// invalidity verdict. Binary authoring uses the shared ballot codec's encoding diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum ParliamentCandidateTestingErrorV1 {
    /// Original signed-genesis authentication failed or its JSON resource owner refused.
    #[error(transparent)]
    Genesis(#[from] GenesisReadError),
    /// The custom parameter has another identity.
    #[error("another candidate-testing parameter identity")]
    ParameterIdentity,
    /// The selected policy version is unsupported.
    #[error("candidate-testing policy version {actual} is unsupported")]
    Version {
        /// Supplied version.
        actual: u16,
    },
    /// The descriptor does not select the actual V1 candidate.
    #[error("candidate-testing policy selects an unsupported proof profile")]
    Profile,
    /// A custom parameter exceeds the bounded canonical JSON envelope.
    #[error("candidate-testing JSON has {actual} bytes; at most 256 are permitted")]
    JsonTooLarge {
        /// Supplied JSON bytes.
        actual: usize,
    },
    /// The payload is not the canonical key-ordered JSON of the exact policy.
    #[error("candidate-testing JSON is not canonical")]
    NonCanonicalJson,
    /// JSON decoding failed or its original resource owner refused.
    #[error(transparent)]
    Json(#[from] norito::json::Error),
    /// Encoding failed or its original resource owner refused.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// Bounded canonical binary decoding or encoding failed.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
    /// The original authenticated genesis belongs to another independently selected network.
    #[error("candidate-testing genesis belongs to another network")]
    ForeignNetwork,
    /// Original signed genesis contains more than one candidate-testing instruction.
    #[error("signed genesis repeats its candidate-testing policy")]
    DuplicatePolicy,
    /// The authenticated owner did not retain explicit original instructions.
    #[error("candidate-testing genesis lacks explicit original instructions")]
    NonInstructionGenesis,
}

/// Explicit genesis selection of the real anonymous-ballot candidate for testing.
///
/// This is authoring data, not authority. Only extraction from an independently pinned
/// authenticated original constructs [`AuthenticatedParliamentCandidateTestingV1`].
/// No default selects this policy, and it contains no production activation mode.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::ParliamentCandidateTestingPolicyV1"
)]
pub struct ParliamentCandidateTestingPolicyV1 {
    /// Policy format version, exactly one.
    pub version: u16,
    /// Exact descriptor digest of the supported candidate relation and parameter row.
    pub profile: ProofProfileIdV1,
}

impl ParliamentCandidateTestingPolicyV1 {
    /// An explicit authoring choice; this does not activate any network.
    pub const CANDIDATE_V1: Self = Self {
        version: 1,
        profile: ProofProfileIdV1::V1,
    };

    /// Maximum complete canonical Norito policy frame.
    pub const MAX_WIRE_BYTES: usize = 256;

    /// Maximum canonical JSON in the original custom parameter.
    pub const MAX_JSON_BYTES: usize = 256;

    /// The sole reserved genesis parameter identity.
    #[must_use]
    pub fn parameter_id() -> &'static CustomParameterId {
        static ID: std::sync::OnceLock<CustomParameterId> = std::sync::OnceLock::new();
        ID.get_or_init(|| {
            "parliament_candidate_testing_v1"
                .parse()
                .expect("static candidate-testing parameter identity")
        })
    }

    /// Require the exact supported policy and proof profile.
    ///
    /// # Errors
    /// Returns [`ParliamentCandidateTestingErrorV1::Version`] or
    /// [`ParliamentCandidateTestingErrorV1::Profile`] for another selection.
    pub fn validate(&self) -> Result<(), ParliamentCandidateTestingErrorV1> {
        if self.version != 1 {
            return Err(ParliamentCandidateTestingErrorV1::Version {
                actual: self.version,
            });
        }
        if !self.profile.is_v1() {
            return Err(ParliamentCandidateTestingErrorV1::Profile);
        }
        Ok(())
    }

    /// Encode the validated policy as one bounded canonical header-framed Norito value.
    ///
    /// # Errors
    /// Refuses unsupported selections and canonical encoding failures.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ParliamentCandidateTestingErrorV1> {
        self.validate()?;
        Ok(enc_bounded(
            self,
            "candidate-testing policy",
            Self::MAX_WIRE_BYTES,
        )?)
    }

    /// Decode exactly one bounded canonical Norito policy, with no trailing bytes.
    ///
    /// # Errors
    /// Refuses malformed, noncanonical, oversized or unsupported selections; retains
    /// the original local decoder refusal.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ParliamentCandidateTestingErrorV1> {
        let value: Self =
            decode_enc_bounded(bytes, "candidate-testing policy", Self::MAX_WIRE_BYTES)?;
        value.validate()?;
        Ok(value)
    }

    /// Author the exact bounded canonical JSON custom parameter.
    ///
    /// # Errors
    /// Refuses unsupported selections and original encoding failures.
    pub fn to_custom_parameter(
        &self,
    ) -> Result<CustomParameter, ParliamentCandidateTestingErrorV1> {
        self.validate()?;
        let payload = Json::try_new(*self)?;
        if payload.get().len() > Self::MAX_JSON_BYTES {
            return Err(ParliamentCandidateTestingErrorV1::JsonTooLarge {
                actual: payload.get().len(),
            });
        }
        Ok(CustomParameter::new(Self::parameter_id().clone(), payload))
    }

    /// Read the exact reserved parameter without substituting defaults on failure.
    ///
    /// # Errors
    /// Refuses another identity, oversized, malformed or noncanonical JSON, and an
    /// unsupported version/profile. Original JSON and encoding refusal stay typed.
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Self, ParliamentCandidateTestingErrorV1> {
        if parameter.id() != Self::parameter_id() {
            return Err(ParliamentCandidateTestingErrorV1::ParameterIdentity);
        }
        let payload = parameter.payload();
        if payload.get().len() > Self::MAX_JSON_BYTES {
            return Err(ParliamentCandidateTestingErrorV1::JsonTooLarge {
                actual: payload.get().len(),
            });
        }
        let value: Self = norito::json::from_str(payload.get())?;
        value.validate()?;
        if Json::try_new(value)? != *payload {
            return Err(ParliamentCandidateTestingErrorV1::NonCanonicalJson);
        }
        Ok(value)
    }
}

/// The exact candidate selection authenticated in one original network genesis.
///
/// Private fields and the absence of a decoder or public constructor prevent authoring
/// data or a restored World flag from asserting this fact. This proves only signed
/// selection: it grants no genesis execution, committed State, finality, qualification,
/// SCCP or proposal-enactment authority. Runtime consumers must also enforce their
/// independently selected network and the original direct instruction coordinate.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedParliamentCandidateTestingV1 {
    network: NetworkId,
    policy: ParliamentCandidateTestingPolicyV1,
    entrypoint: HashOf<TransactionEntrypoint>,
    position: (usize, usize),
}

impl AuthenticatedParliamentCandidateTestingV1 {
    /// The exact genesis-derived network authenticated by the original source owner.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network
    }

    /// The validated candidate selected by that original signed instruction.
    #[must_use]
    pub const fn policy(&self) -> &ParliamentCandidateTestingPolicyV1 {
        &self.policy
    }

    /// Canonical entrypoint hash of the original signed genesis input.
    #[must_use]
    pub const fn source_entrypoint_hash(&self) -> HashOf<TransactionEntrypoint> {
        self.entrypoint
    }

    /// Original zero-based Network input and instruction indices in signed genesis.
    #[must_use]
    pub const fn source_position(&self) -> (usize, usize) {
        self.position
    }
}

/// Extract candidate testing from an independently pinned, authenticated original.
///
/// `expected_network` is the consumer's independently selected network; do not derive it
/// from an untrusted candidate. The source's existing authentication covers every
/// original signature, complete input commitments and native genesis authority.
/// Absence returns `None`, disabling testing. Only explicit original instructions are
/// inspected; attached authoring outputs and mutable World values grant no authority.
///
/// The network identity derives from the genesis hash; embedding it in its own signed
/// policy would create a hash self-reference. This exact-source extraction supplies
/// the binding instead.
///
/// # Errors
/// Refuses a foreign network, duplicate policy or any invalid bounded policy payload.
/// It does not consume or erase original decoder refusal causes.
pub fn parliament_candidate_testing_from_genesis_v1(
    genesis: &AuthenticatedSignedGenesisV1,
    expected_network: &NetworkId,
) -> Result<Option<AuthenticatedParliamentCandidateTestingV1>, ParliamentCandidateTestingErrorV1> {
    let network = NetworkId::from_genesis_hash(genesis.block().hash());
    if network != *expected_network || network != genesis.pins().network_id {
        return Err(ParliamentCandidateTestingErrorV1::ForeignNetwork);
    }
    extract_candidate_testing(genesis.block(), network)
}

/// Authenticate one original native genesis and extract its candidate selection.
///
/// The consumer supplies its independently pinned network. The canonical genesis
/// authenticator checks the complete original proposal commitments, signatures and
/// native authority; extraction borrows that same immutable source. No API pairs an
/// already authenticated epoch with a different caller-supplied block.
///
/// This is the native execution counterpart of
/// [`parliament_candidate_testing_from_genesis_v1`]. Neither reader grants execution
/// finality or production qualification.
///
/// # Errors
/// Preserves original genesis authentication/JSON errors and candidate policy errors;
/// rejects another network or any non-external original genesis input.
pub fn authenticate_parliament_candidate_genesis_v1(
    original: &SignedBlock,
    expected_network: &NetworkId,
) -> Result<
    (
        AuthenticatedGenesis,
        Option<AuthenticatedParliamentCandidateTestingV1>,
    ),
    ParliamentCandidateTestingErrorV1,
> {
    let network = NetworkId::from_genesis_hash(original.hash());
    if network != *expected_network {
        return Err(ParliamentCandidateTestingErrorV1::ForeignNetwork);
    }
    let authenticated = crate::sumeragi_finality::authenticated_genesis(original)?;
    if authenticated.network_id() != network {
        return Err(ParliamentCandidateTestingErrorV1::ForeignNetwork);
    }
    let selection = extract_candidate_testing(original, network)?;
    Ok((authenticated, selection))
}

fn extract_candidate_testing(
    original: &SignedBlock,
    network: NetworkId,
) -> Result<Option<AuthenticatedParliamentCandidateTestingV1>, ParliamentCandidateTestingErrorV1> {
    let mut selection = None;
    for (transaction_index, input) in original.network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(transaction) = input else {
            return Err(ParliamentCandidateTestingErrorV1::NonInstructionGenesis);
        };
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(ParliamentCandidateTestingErrorV1::NonInstructionGenesis);
        };
        for (instruction_index, instruction) in instructions.iter().enumerate() {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = set.inner() else {
                continue;
            };
            if custom.id() != ParliamentCandidateTestingPolicyV1::parameter_id() {
                continue;
            }
            let policy = ParliamentCandidateTestingPolicyV1::from_custom_parameter(custom)?;
            if selection.is_some() {
                return Err(ParliamentCandidateTestingErrorV1::DuplicatePolicy);
            }
            selection = Some(AuthenticatedParliamentCandidateTestingV1 {
                network,
                policy,
                entrypoint: transaction.hash_as_entrypoint(),
                position: (transaction_index, instruction_index),
            });
        }
    }
    Ok(selection)
}

#[cfg(test)]
mod tests;
