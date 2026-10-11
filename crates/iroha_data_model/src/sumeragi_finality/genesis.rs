//! Native epoch roots derived from exact authenticated signed genesis.
//!
//! Genesis execution results do not supply signing authority. This reader uses only signed
//! registrations, metadata and `NPoS` parameters; the executed overlay must independently match
//! the same context before its result or retained schedule can be published.

use crate::{
    NetworkId,
    block::{BlockHeader, SignedBlock},
    isi::SetParameter,
    parameter::{
        Parameter,
        system::{ConsensusMode, SumeragiNposParameters},
    },
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationV1, ValidatorEpochContextV1,
    },
    transaction::{Executable, TransactionDomain},
};
use iroha_crypto::{Hash, HashOf, PublicKey};
use iroha_model_base::peer::PeerId;

/// An invalid signed genesis or its original, unfinished JSON decoding attempt.
///
/// This local read error is not a signed rejection and has no wire codec. Callers must
/// classify the original decoder cause before publishing a deterministic verdict.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GenesisReadError {
    /// Signed authority, commitments, metadata, or policy bounds are invalid.
    #[error("{0}")]
    Invalid(String),
    /// The original signed parameter decoder did not complete successfully.
    #[error("signed genesis JSON: {0}")]
    Json(#[from] norito::json::Error),
}

impl From<String> for GenesisReadError {
    fn from(error: String) -> Self {
        Self::Invalid(error)
    }
}
impl From<&str> for GenesisReadError {
    fn from(error: &str) -> Self {
        Self::Invalid(error.into())
    }
}

/// Complete projections of the one authenticated signed-genesis reconstruction.
///
/// This local move-only result has no wire codec and proves no result-only execution finality.
/// Consumers still bind their independently selected network, chain label and original source.
#[derive(Debug)]
pub struct AuthenticatedGenesis {
    /// Complete native epoch reconstructed from the original signed instructions.
    epoch: ValidatorEpochContextV1,
    /// Exact already decoded metadata scalars, also needed by independently pinned owners.
    metadata: crate::parameter::system::ConsensusHandshakeMetadata,
}

impl AuthenticatedGenesis {
    /// Copy the exact metadata produced by this original canonical authentication.
    /// This performs no decoding and grants no execution-result or mutable-state authority.
    #[must_use]
    pub const fn metadata(&self) -> crate::parameter::system::ConsensusHandshakeMetadata {
        self.metadata
    }

    /// Move the exact complete epoch and copied root scope from their sole signed-body producer.
    /// This neither clones their graph nor confers result-only execution or source authority.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ValidatorEpochContextV1,
        crate::block::consensus::SumeragiRootScope,
    ) {
        (self.epoch, self.metadata.sumeragi_context.root_scope)
    }
}

/// Authenticate the genesis body and reconstruct its complete native signing context.
/// The returned epoch and scope are independent of result-only certificate data and mutable World.
/// Its network identity is the signed genesis header hash, not a caller-selected network.
///
/// # Errors
/// Rejects non-genesis input, invalid proposal commitments or original signatures,
/// ambiguous authority or consensus metadata, malformed signed parameters, and an
/// invalid reconstructed epoch or committee.
pub fn authenticated_genesis(
    genesis: &SignedBlock,
) -> Result<AuthenticatedGenesis, GenesisReadError> {
    authenticated_genesis_with_validation(genesis, None)
}

// Source authentication and signed reconstruction always precede pure context reuse.
// Standalone readers retain their original independent validation-only path.
pub(super) fn authenticated_genesis_with_validation(
    genesis: &SignedBlock,
    validation: Option<&super::EpochValidationScope>,
) -> Result<AuthenticatedGenesis, GenesisReadError> {
    authenticate_with_policy(genesis, validation, &mut OrdinaryPolicy(None))
}

// The ordinary and retained owners run exactly the same signature, instruction,
// metadata and complete epoch checks, in the same order.
fn authenticate_with_policy<P: PolicySource>(
    genesis: &SignedBlock,
    validation: Option<&super::EpochValidationScope>,
    policy: &mut P,
) -> Result<AuthenticatedGenesis, P::Error> {
    if !genesis.header().is_genesis() {
        return Err("native epoch root requires height-one signed genesis".into());
    }
    genesis.validate_proposal_commitments()?;
    let first = genesis
        .external_transactions()
        .next()
        .ok_or("signed genesis is empty")?;
    let signer = first
        .authority()
        .try_signatory()
        .ok_or("genesis requires one exact signing authority")?;
    let mut signatures = genesis.signatures();
    let signature = signatures
        .next()
        .ok_or("signed genesis has no block signature")?;
    if signature.index() != 0 || signatures.next().is_some() {
        return Err("genesis must carry exactly its index-zero authority signature".into());
    }
    signature
        .signature()
        .verify_hash(signer, genesis.hash())
        .map_err(|error| error.to_string())?;
    let mut npos_seen = false;
    for (transaction_index, transaction) in genesis.external_transactions().enumerate() {
        if transaction.authority().try_signatory() != Some(signer)
            || transaction.domain() != &TransactionDomain::Genesis
        {
            return Err("genesis transaction changes its signing authority or domain".into());
        }
        transaction
            .verify_signature()
            .map_err(|error| error.to_string())?;
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err("genesis epoch authority requires explicit signed instructions".into());
        };
        for (instruction_index, instruction) in instructions.iter().enumerate() {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = set.inner() else {
                continue;
            };
            if custom.id() != &SumeragiNposParameters::parameter_id() {
                continue;
            }
            policy.read(custom, (transaction_index, instruction_index))?;
            if npos_seen {
                return Err("genesis repeats its signed NPoS parameter authority".into());
            }
            npos_seen = true;
        }
    }
    let metadata = signed_genesis_consensus_metadata(genesis)?;
    if metadata.wire_protocol_version != u32::from(crate::sumeragi::PROTOCOL_VERSION) {
        return Err("genesis metadata does not bind the current native protocol".into());
    }
    let mode = ConsensusMode::from(metadata.mode);
    let network_id = NetworkId::from_genesis_hash(genesis.hash());
    let (last_height, leader_seed) = match mode {
        ConsensusMode::Permissioned => (
            u64::MAX,
            Hash::new_from_chunks(&[
                b"iroha:native-permissioned-leader:v1",
                &[0],
                network_id.as_bytes(),
            ])
            .into(),
        ),
        ConsensusMode::Npos => {
            let parameters = policy
                .parameters()
                .ok_or("NPoS genesis omits its signed epoch length and seed")?;
            crate::nexus::ValidatorElectionPolicyV1::validate_npos_parameters(parameters)?;
            (parameters.epoch_length_blocks.get(), parameters.epoch_seed)
        }
    };
    let committee: Vec<ValidatorCommitteeMemberV1> = super::genesis_registrations(genesis)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(
            |(validator, proof_of_possession)| ValidatorCommitteeMemberV1 {
                validator,
                proof_of_possession,
            },
        )
        .collect();
    // Generation zero is the signed registered roster itself; no separate key template exists.
    let authorization =
        ValidatorEpochAuthorizationV1::genesis_from_committee(network_id, &committee, last_height)
            .map_err(|error| error.to_string())?;
    let epoch = ValidatorEpochContextV1 {
        da_layout: metadata.sumeragi_context.da_layout,
        version: 1,
        network_id,
        mode,
        authorization,
        committee,
        leader_seed,
    };
    match validation {
        Some(validation) => validation.validate_known_or_fresh(&epoch)?,
        None => epoch.validate()?,
    }
    Ok(AuthenticatedGenesis { epoch, metadata })
}

mod original_policy;
pub use original_policy::{OriginalGenesisRead, OriginalGenesisReadError};

trait PolicySource {
    type Error: From<GenesisReadError>
        + From<String>
        + From<&'static str>
        + From<norito::json::Error>;

    fn read(
        &mut self,
        custom: &crate::parameter::CustomParameter,
        coordinate: (usize, usize),
    ) -> Result<(), Self::Error>;

    fn parameters(&self) -> Option<&SumeragiNposParameters>;
}

struct OrdinaryPolicy(Option<SumeragiNposParameters>);
impl PolicySource for OrdinaryPolicy {
    type Error = GenesisReadError;

    fn read(
        &mut self,
        custom: &crate::parameter::CustomParameter,
        _: (usize, usize),
    ) -> Result<(), Self::Error> {
        self.0 = Some(
            SumeragiNposParameters::from_custom_parameter(custom)?
                .ok_or("invalid signed genesis NPoS parameters")?,
        );
        Ok(())
    }

    fn parameters(&self) -> Option<&SumeragiNposParameters> {
        self.0.as_ref()
    }
}

/// Decode and validate the unique consensus metadata in an authenticated signed genesis body.
///
/// # Errors
/// Missing, duplicate, malformed or invalid current consensus metadata.
pub fn signed_genesis_consensus_metadata(
    block: &SignedBlock,
) -> Result<crate::parameter::system::ConsensusHandshakeMetadata, GenesisReadError> {
    use crate::parameter::system::{ConsensusHandshakeMetadata, consensus_metadata};
    let mut metadata = None;
    for transaction in block.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for instruction in instructions {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = set.inner() else {
                continue;
            };
            if custom.id() != &consensus_metadata::handshake_meta_id() {
                continue;
            }
            let decoded =
                norito::json::from_str::<ConsensusHandshakeMetadata>(custom.payload().get())?;
            if metadata.replace(decoded).is_some() {
                return Err(
                    "signed genesis contains more than one consensus metadata instruction".into(),
                );
            }
        }
    }
    let metadata = metadata.ok_or("signed genesis contains no consensus metadata instruction")?;
    metadata
        .validate()
        .map_err(|error| format!("invalid signed genesis consensus metadata: {error}"))?;
    Ok(metadata)
}

/// Upper bound on an independently selected signed genesis original.
pub const MAX_SIGNED_GENESIS_BYTES_V1: usize = 8 * 1024 * 1024;

/// Independently selected pins for one exact signed genesis original.
///
/// Every field must come from an authenticated source other than the genesis bytes (for
/// example a signed release manifest). `roster` is the complete genesis committee in canonical
/// order; its `3f + 1` size is enforced by [`authenticated_genesis`]. Callers may add stricter rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGenesisPinsV1 {
    /// Exact chain label.
    pub chain_id: String,
    /// Genesis-derived network identity.
    pub network_id: NetworkId,
    /// Signed genesis header hash.
    pub genesis_hash: HashOf<BlockHeader>,
    /// SHA-256 of the exact framed signed genesis bytes.
    pub signed_genesis_sha256: [u8; 32],
    /// The genesis signing authority.
    pub genesis_public_key: PublicKey,
    /// The complete ordered genesis validator roster.
    pub roster: Vec<PeerId>,
    /// Signed consensus mode.
    pub mode: ConsensusMode,
}

/// A signed genesis original authenticated against independently selected pins.
///
/// It has no decoder: only [`authenticate_signed_genesis_v1`] constructs it.
#[derive(Clone)]
pub struct AuthenticatedSignedGenesisV1 {
    pins: SignedGenesisPinsV1,
    block: SignedBlock,
    metadata: crate::parameter::system::ConsensusHandshakeMetadata,
    epoch: ValidatorEpochContextV1,
    validators: Vec<super::FinalityValidator>,
}

impl core::fmt::Debug for AuthenticatedSignedGenesisV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedSignedGenesisV1")
            .field("network_id", &self.pins.network_id)
            .field("genesis_hash", &self.pins.genesis_hash)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSignedGenesisV1 {
    /// The pins this original was authenticated against.
    #[must_use]
    pub fn pins(&self) -> &SignedGenesisPinsV1 {
        &self.pins
    }
    /// The exact authenticated signed genesis block.
    #[must_use]
    pub fn block(&self) -> &SignedBlock {
        &self.block
    }
    /// The unique signed consensus metadata.
    #[must_use]
    pub fn metadata(&self) -> &crate::parameter::system::ConsensusHandshakeMetadata {
        &self.metadata
    }
    /// The reconstructed signed genesis epoch.
    #[must_use]
    pub fn epoch(&self) -> &ValidatorEpochContextV1 {
        &self.epoch
    }
    /// The genesis committee as finality validators.
    #[must_use]
    pub fn validators(&self) -> &[super::FinalityValidator] {
        &self.validators
    }
    /// SHA-256 of the exact framed signed genesis bytes.
    #[must_use]
    pub fn signed_genesis_sha256(&self) -> [u8; 32] {
        self.pins.signed_genesis_sha256
    }
}

/// Authenticate one exact framed signed genesis original against independent pins.
///
/// # Errors
/// Invalid pins; bytes that differ from the pinned digest, are not one canonical resultless
/// height-one block, or carry a different hash or network; anything other than the sole
/// index-zero authority signature; non-explicit or foreign-authority transactions; an invalid
/// transaction signature; or a reconstructed epoch whose mode, network or ordered committee
/// differs from the pins. Original allocator/enclosing binary limits and signed JSON
/// refusal causes remain typed in [`super::FinalityReadError`]; they are not invalid pins.
pub fn authenticate_signed_genesis_v1(
    wire: &[u8],
    pins: &SignedGenesisPinsV1,
) -> Result<AuthenticatedSignedGenesisV1, super::FinalityReadError> {
    use crate::transaction::TransactionEntrypoint;
    use iroha_crypto::Algorithm;
    use sha2::{Digest as _, Sha256};
    if wire.is_empty()
        || wire.len() > MAX_SIGNED_GENESIS_BYTES_V1
        || pins.chain_id.is_empty()
        || pins.chain_id.len() > 512
        || pins.chain_id.trim() != pins.chain_id
        || pins.chain_id.as_bytes().contains(&0)
        || pins.signed_genesis_sha256 == [0; 32]
        || pins.roster.is_empty()
        || pins.roster.windows(2).any(|peers| peers[0] >= peers[1])
        || pins
            .roster
            .iter()
            .any(|peer| peer.public_key().try_algorithm() != Ok(Algorithm::BlsNormal))
    {
        return Err(super::malformed("invalid independently selected native genesis pins").into());
    }
    if <[u8; 32]>::from(Sha256::digest(wire)) != pins.signed_genesis_sha256 {
        return Err(
            super::malformed("signed genesis original differs from selected raw hash").into(),
        );
    }
    let block =
        norito::core::with_decode_limits_scope(norito::canonical_decode_limits(wire.len()), || {
            crate::block::decode_framed_signed_block(wire)
        })
        .map_err(|error| {
            #[cfg(all(test, sumeragi_model_mutation = "DM11"))]
            {
                // Deliberately erase only original binary refusal provenance.
                let _ = error;
                return super::FinalityReadError::Invalid(super::malformed(
                    "signed genesis original is not an exact canonical block",
                ));
            }
            #[cfg(not(all(test, sumeragi_model_mutation = "DM11")))]
            match error.kind() {
                norito::core::DecodeAttemptErrorKind::Allocator
                | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
                    super::FinalityReadError::DecodeResource(error)
                }
                norito::core::DecodeAttemptErrorKind::Invalid => super::FinalityReadError::Invalid(
                    super::malformed("signed genesis original is not an exact canonical block"),
                ),
            }
        })?;
    if block
        .encode_wire()
        .map_err(|_| super::malformed("signed genesis cannot encode canonically"))?
        != wire
        || !block.header().is_genesis()
        || !block.is_resultless_proposal()
        || block.hash() != pins.genesis_hash
        || NetworkId::from_genesis_hash(block.hash()) != pins.network_id
    {
        return Err(
            super::malformed("signed genesis differs from selected root or network").into(),
        );
    }
    let mut signatures = block.signatures();
    let signature = signatures
        .next()
        .ok_or_else(|| super::malformed("signed genesis has no authority signature"))?;
    if signature.index() != 0 || signatures.next().is_some() {
        return Err(
            super::malformed("signed genesis requires its sole index-zero signature").into(),
        );
    }
    signature
        .signature()
        .verify_hash(&pins.genesis_public_key, pins.genesis_hash)
        .map_err(|_| {
            super::malformed("signed genesis signature differs from selected authority")
        })?;
    drop(signatures);
    if block.external_entrypoint_count() == 0
        || block
            .network_entrypoints()
            .any(|entry| !matches!(entry, TransactionEntrypoint::External(_)))
    {
        return Err(
            super::malformed("signed genesis requires only explicit signed transactions").into(),
        );
    }
    for transaction in block.external_transactions() {
        if transaction.authority().try_signatory() != Some(&pins.genesis_public_key)
            || transaction.domain() != &TransactionDomain::Genesis
        {
            return Err(super::malformed(
                "genesis transaction differs from selected authority or domain",
            )
            .into());
        }
        transaction
            .verify_signature()
            .map_err(|_| super::malformed("signed genesis transaction signature is invalid"))?;
    }
    // Native epoch validation verifies canonical BLS keys, all proofs of possession,
    // signed current metadata and the complete signed genesis authority generation.
    let AuthenticatedGenesis { epoch, metadata } =
        authenticated_genesis(&block).map_err(|error| match error {
            GenesisReadError::Json(error) => {
                #[cfg(all(test, sumeragi_model_mutation = "DM12"))]
                {
                    // Deliberately erase only the original signed JSON refusal.
                    let _ = error;
                    super::FinalityReadError::Invalid(super::malformed(
                        "signed genesis native epoch is invalid",
                    ))
                }
                #[cfg(not(all(test, sumeragi_model_mutation = "DM12")))]
                super::FinalityReadError::Genesis(GenesisReadError::Json(error))
            }
            GenesisReadError::Invalid(_) => super::FinalityReadError::Invalid(super::malformed(
                "signed genesis native epoch is invalid",
            )),
        })?;
    if (&epoch.mode, &epoch.network_id, epoch.committee.len())
        != (&pins.mode, &pins.network_id, pins.roster.len())
        || !epoch
            .committee
            .iter()
            .zip(&pins.roster)
            .all(|(member, peer)| &member.validator == peer)
    {
        return Err(super::malformed(
            "signed genesis epoch differs from independently selected mode or roster",
        )
        .into());
    }
    let validators: Vec<_> = epoch
        .committee
        .iter()
        .map(|member| super::FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let (crypto, _committee) = super::ProofCrypto::new(&validators)
        .map_err(|_| super::malformed("signed genesis selected native BLS roster is invalid"))?;
    #[cfg(all(test, sumeragi_model_mutation = "DM10"))]
    {
        // Restore only the duplicate canonical authentication formerly performed by
        // constructing and discarding a second verifier over this exact same body.
        let _ = authenticated_genesis(&block)?;
    }
    super::authenticated_genesis_instance(
        &block,
        &pins.chain_id,
        &validators,
        &crypto,
        &epoch,
        metadata.sumeragi_context.root_scope,
    )
    .map_err(|_| super::malformed("signed genesis selected native BLS roster is invalid"))?;
    Ok(AuthenticatedSignedGenesisV1 {
        pins: pins.clone(),
        block,
        metadata,
        epoch,
        validators,
    })
}
