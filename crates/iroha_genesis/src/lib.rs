//! Genesis-related logic and constructs. Contains the [`GenesisBlock`],
//! [`RawGenesisTransaction`] and the [`GenesisBuilder`] structures.
//! Every genesis batch signs expiry height two and its one-based sequence so the
//! genesis parameter snapshot may require either ingress rule from height one.
//! Normalization preserves authored source boundaries and refuses inputs above
//! the fixed FASTPQ bootstrap budget; draft generators partition physical routes explicitly.
#![allow(unexpected_cfgs)]
#![allow(
    clippy::let_and_return,
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::double_must_use,
    clippy::field_reassign_with_default,
    clippy::manual_contains,
    clippy::items_after_statements,
    clippy::clone_on_copy
)]
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;

/// Genesis runs at height one; every signed batch remains admissible when its
/// own parameter snapshot enables height expiry or per-authority sequencing.
fn genesis_transaction_metadata(index: u64) -> Result<Metadata> {
    let mut metadata = Metadata::default();
    metadata.insert(
        "expires_at_height".parse().expect("fixed metadata name"),
        Json::from(2_u64),
    );
    metadata.insert(
        "tx_sequence".parse().expect("fixed metadata name"),
        Json::from(
            index
                .checked_add(1)
                .ok_or_else(|| eyre!("genesis sequence exceeds u64"))?,
        ),
    );
    Ok(metadata)
}
mod bounded_manifest;
#[cfg(test)]
mod ivm_path_codec_tests;
use base64::Engine as _;
pub use bounded_manifest::{
    GENESIS_IVM_BYTECODE_MAX_BYTES_V1, GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1,
    GENESIS_MANIFEST_JSON_MAX_BYTES_V1, GENESIS_MANIFEST_JSON_MAX_DEPTH_V1,
    GENESIS_MANIFEST_JSON_MAX_STRING_BYTES_V1, GENESIS_MANIFEST_JSON_MAX_TOKENS_V1,
    SIGNED_GENESIS_MAX_BYTES_V1, decode_signed_genesis, read_genesis_manifest_bytes,
    read_signed_genesis, read_signed_genesis_bytes, signed_genesis_decode_limits_v1,
    validate_genesis_manifest_json,
};
use core::num::NonZeroU64;
use derive_more::Constructor;
use eyre::{Result, WrapErr, eyre};
use iroha_config::parameters::{
    actual::Crypto as ActualCrypto, defaults::confidential::RULES_VERSION,
    user::SmIntrinsicsPolicyConfig,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PublicKey, bls_normal_pop_verify};
use iroha_data_model::isi::register::RegisterBox;
use iroha_data_model::{
    account::curve::CurveId,
    block::{
        BlockHeader, SignedBlock,
        consensus::{ConsensusGenesisModeParams, ConsensusGenesisParams, NposGenesisParams},
        consensus::{
            MAX_VALIDATORS_PER_HEIGHT, SumeragiGenesisContextParameters, is_valid_committee_size,
        },
    },
    confidential::{
        ConfidentialFeatureDigest, ConfidentialStatus, DEFAULT_GENESIS_CONFIDENTIAL_POLICY_HASH,
    },
    da::commitment::DaProofPolicyBundle,
    isi::{
        InstructionRegistry, Register, SetParameter, register::RegisterPeerWithPop,
        set_instruction_registry, verifying_keys,
    },
    parameter::{
        Parameter,
        custom::CustomParameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            SumeragiNposParameters, SumeragiParameters, confidential_metadata, consensus_metadata,
            crypto_metadata,
        },
    },
    prelude::*,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    transaction::{DEFAULT_TRANSACTION_TIME_TO_LIVE, FeePaymentIntent},
};
use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt::Debug,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const CONSENSUS_PROTOCOL_VERSION: u32 = iroha_data_model::sumeragi::PROTOCOL_VERSION as u32;
#[cfg(test)]
fn checked_genesis_fixture_keypair() -> KeyPair {
    KeyPair::try_random().expect("genesis fixture key generation should succeed")
}
#[cfg(test)]
fn checked_genesis_fixture_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("genesis fixture key generation should succeed")
}
#[cfg(test)]
fn deterministic_test_genesis_topology_entries() -> Vec<GenesisTopologyEntry> {
    let mut topology = (0_u8..4)
        .map(|index| {
            let validator =
                KeyPair::try_from_seed(vec![0x20_u8.wrapping_add(index); 32], Algorithm::BlsNormal)
                    .expect("derive deterministic genesis fixture validator");
            let pop = iroha_crypto::bls_normal_pop_prove(validator.private_key())
                .expect("derive deterministic genesis fixture proof of possession");
            GenesisTopologyEntry::new(
                iroha_model_base::peer::PeerId::new(validator.public_key().clone()),
                pop,
            )
        })
        .collect::<Vec<_>>();
    topology.sort_by(|left, right| left.peer.cmp(&right.peer));
    topology
}
/// Domain of the genesis account, technically required for the pre-genesis state
pub static GENESIS_DOMAIN_ID: LazyLock<DomainId> =
    LazyLock::new(|| DomainId::parse_fully_qualified("genesis.universal").unwrap());
/// Construct an [`InstructionRegistry`] with all built-in Iroha instructions and
/// set it as the global registry.
///
/// The genesis tooling relies on dynamic instruction (de)serialization. Without initializing the
/// registry attempts to decode [`InstructionBox`] values will fail at runtime.
pub fn init_instruction_registry() {
    set_instruction_registry(default_instruction_registry());
}
/// Create an [`InstructionRegistry`] populated with all instructions supported
/// by Iroha out of the box.
pub fn default_instruction_registry() -> InstructionRegistry {
    iroha_data_model::instruction_registry::default()
}
/// Canonically decoded and independently verified signed-genesis bundle.
#[derive(Debug, Clone)]
pub struct ValidatedGenesisBundle {
    block: SignedBlock,
    canonical_wire: Vec<u8>,
    public_key: PublicKey,
    expected_hash: HashOf<BlockHeader>,
    validator_pops: BTreeMap<PublicKey, Vec<u8>>,
    consensus_metadata: ConsensusHandshakeMetadata,
}
impl ValidatedGenesisBundle {
    /// Return the verified signed block.
    #[must_use]
    pub fn block(&self) -> &SignedBlock {
        &self.block
    }
    /// Return the canonical framed Norito bytes for the signed block.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
    /// Return the verifier key bound to the signed block.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Return the exact verified block hash.
    #[must_use]
    pub const fn expected_hash(&self) -> HashOf<BlockHeader> {
        self.expected_hash
    }
    /// Return the validator-key to proof-of-possession roster signed into genesis.
    #[must_use]
    pub fn validator_pops(&self) -> &BTreeMap<PublicKey, Vec<u8>> {
        &self.validator_pops
    }
    /// Return the unique consensus handshake metadata signed into genesis.
    #[must_use]
    pub const fn consensus_metadata(&self) -> &ConsensusHandshakeMetadata {
        &self.consensus_metadata
    }
}
/// Decode and independently validate a complete signed-genesis bundle.
///
/// The validator rejects non-canonical Norito, a mismatched verifier key or
/// exact hash, invalid block or transaction signatures, an invalid validator
/// roster, and any consensus or instruction semantic mismatch with `manifest`.
///
/// # Errors
///
/// Returns a validation report describing the first failed binding.
pub fn validate_prepared_genesis_bundle(
    signed_wire: &[u8],
    manifest: &RawGenesisTransaction,
    public_key: &PublicKey,
    expected_hash: HashOf<BlockHeader>,
) -> Result<ValidatedGenesisBundle> {
    let block = decode_signed_genesis(signed_wire)?;
    // The sole framed decoder already compared the canonical writer against these exact
    // source bytes. The validated bundle owns a source copy, not another encoding.
    // TODO: this source backing needs an explicit retained caller-pool ledger.
    let mut canonical_wire = Vec::new();
    canonical_wire
        .try_reserve_exact(signed_wire.len())
        .wrap_err("retain authenticated signed genesis source")?;
    canonical_wire.extend_from_slice(signed_wire);
    if block.hash() != expected_hash {
        return Err(eyre!(
            "signed genesis body hashes to {}, expected {}",
            block.hash(),
            expected_hash
        ));
    }
    let first = block
        .external_transactions()
        .next()
        .ok_or_else(|| eyre!("signed genesis contains no external transactions"))?;
    let embedded_signer = first
        .authority()
        .try_signatory()
        .ok_or_else(|| eyre!("genesis authority must be one canonical single-key account"))?;
    if embedded_signer != public_key {
        return Err(eyre!(
            "signed genesis signer {embedded_signer} differs from verifier key {public_key}"
        ));
    }
    {
        let mut signatures = block.signatures();
        let signature = signatures
            .next()
            .ok_or_else(|| eyre!("signed genesis has no block signature"))?;
        if signature.index() != 0 || signatures.next().is_some() {
            return Err(eyre!(
                "signed genesis must have exactly one block signature at index 0"
            ));
        }
        signature
            .signature()
            .verify_hash(public_key, block.hash())
            .map_err(|error| eyre!("verify genesis block signature: {error}"))?;
    }
    for transaction in block.external_transactions() {
        transaction
            .verify_signature()
            .map_err(|error| eyre!("verify genesis transaction signature: {error}"))?;
    }
    let validator_pops = signed_genesis_validator_pops(&block)?;
    let consensus_metadata = signed_genesis_consensus_metadata(&block)?;
    validate_signed_manifest_binding(manifest, &block, public_key, &consensus_metadata)?;
    Ok(ValidatedGenesisBundle {
        block,
        canonical_wire,
        public_key: public_key.clone(),
        expected_hash,
        validator_pops,
        consensus_metadata,
    })
}
/// Read and validate the validator keys and BLS proofs of possession in genesis.
///
/// The caller must independently authenticate this exact genesis body and its
/// network identity before trusting the returned roster. This helper validates
/// the peer registrations, unique keys, supported exact `3f + 1` committee size,
/// and every BLS proof of possession; it does not verify block or transaction
/// signatures, the genesis identity, or the remaining instruction semantics.
///
/// # Errors
///
/// Returns an error for duplicate validators, an invalid BLS proof of possession,
/// or a committee outside the supported exact Sumeragi geometry.
pub fn signed_genesis_validator_pops(block: &SignedBlock) -> Result<BTreeMap<PublicKey, Vec<u8>>> {
    let mut validator_pops = BTreeMap::new();
    for transaction in block.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for instruction in instructions {
            let Some(RegisterBox::Peer(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
            else {
                continue;
            };
            let validator_key = register.peer.public_key().clone();
            if validator_pops.contains_key(&validator_key) {
                return Err(eyre!(
                    "signed genesis registers validator {validator_key} more than once"
                ));
            }
            if validator_pops.len() >= MAX_VALIDATORS_PER_HEIGHT {
                return Err(eyre!(
                    "signed genesis validator roster exceeds the supported maximum {MAX_VALIDATORS_PER_HEIGHT}"
                ));
            }
            bls_normal_pop_verify(&validator_key, &register.pop).map_err(|error| {
                eyre!("signed genesis validator {validator_key} has an invalid PoP: {error}")
            })?;
            validator_pops.insert(validator_key, register.pop.clone());
        }
    }
    if !is_valid_committee_size(validator_pops.len()) {
        return Err(eyre!(
            "signed genesis validator roster must be an exact Sumeragi `3f + 1` committee in the supported range 4..={MAX_VALIDATORS_PER_HEIGHT} (saw {})",
            validator_pops.len()
        ));
    }
    Ok(validator_pops)
}
/// Decode and validate the unique consensus metadata signed into a genesis block.
///
/// # Errors
///
/// Returns an error when the block omits the metadata, contains it more than
/// once, cannot decode it canonically, or carries invalid consensus parameters.
pub fn signed_genesis_consensus_metadata(
    block: &SignedBlock,
) -> Result<ConsensusHandshakeMetadata> {
    iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block)
        .map_err(|error| eyre!(error))
}
fn validate_signed_manifest_binding(
    manifest: &RawGenesisTransaction,
    block: &SignedBlock,
    public_key: &PublicKey,
    signed_metadata: &ConsensusHandshakeMetadata,
) -> Result<()> {
    if signed_metadata.mode != manifest.consensus_mode() {
        return Err(eyre!(
            "genesis manifest consensus mode {} differs from signed body mode {}",
            manifest.consensus_mode(),
            signed_metadata.mode
        ));
    }
    if manifest.wire_protocol_version() != signed_metadata.wire_protocol_version {
        return Err(eyre!(
            "genesis manifest wire protocol version {} differs from signed body version {}",
            manifest.wire_protocol_version(),
            signed_metadata.wire_protocol_version
        ));
    }
    if manifest.consensus_fingerprint() != Some(signed_metadata.consensus_fingerprint) {
        return Err(eyre!(
            "genesis manifest consensus fingerprint differs from signed body"
        ));
    }
    if manifest.sumeragi_context_parameters() != signed_metadata.sumeragi_context {
        return Err(eyre!(
            "genesis manifest Sumeragi context differs from signed body"
        ));
    }
    let expected = manifest
        .clone()
        .with_consensus_meta()?
        .parse()
        .wrap_err("expand genesis manifest instructions")?;
    let actual_len = block.external_transactions().len();
    if expected.len() != actual_len {
        return Err(eyre!(
            "signed genesis transaction count differs from genesis manifest"
        ));
    }
    let genesis_account = AccountId::new(public_key.clone());
    let canonical_fee_intent = FeePaymentIntent::authority(Vec::new(), None);
    let mut previous_creation_time: Option<u128> = None;
    for (index, (expected_batch, transaction)) in expected
        .iter()
        .zip(block.external_transactions())
        .enumerate()
    {
        if transaction.domain() != &iroha_data_model::transaction::TransactionDomain::Genesis
            || transaction.authority() != &genesis_account
        {
            return Err(eyre!(
                "signed genesis transaction {index} has the wrong domain or root authority"
            ));
        }
        if transaction.metadata()
            != &genesis_transaction_metadata(
                u64::try_from(index).wrap_err("genesis index exceeds u64")?,
            )?
            || transaction.nonce().is_some()
            || transaction.multisig_signatures().is_some()
            || transaction.attachments().is_some()
            || transaction.fee_payment_intent() != &canonical_fee_intent
            || transaction.time_to_live() != Some(DEFAULT_TRANSACTION_TIME_TO_LIVE)
        {
            return Err(eyre!(
                "signed genesis transaction {index} has non-canonical envelope fields"
            ));
        }
        let creation_time = transaction.creation_time().as_millis();
        if let Some(previous) = previous_creation_time {
            let expected_creation_time = previous.checked_add(1).ok_or_else(|| {
                eyre!(
                    "signed genesis transaction {index} creation time overflows the canonical millisecond sequence"
                )
            })?;
            if creation_time != expected_creation_time {
                return Err(eyre!(
                    "signed genesis transaction {index} creation time is not the next canonical millisecond"
                ));
            }
        }
        previous_creation_time = Some(creation_time);
        let Executable::Instructions(actual_batch) = transaction.instructions() else {
            return Err(eyre!(
                "signed genesis transaction {index} is not an instruction batch"
            ));
        };
        let mut expected_instructions = expected_batch.iter();
        let mut actual_instructions = actual_batch.iter();
        loop {
            match (expected_instructions.next(), actual_instructions.next()) {
                (Some(expected), Some(actual))
                    if Encode::encode(expected) == Encode::encode(actual) => {}
                (None, None) => break,
                _ => {
                    return Err(eyre!(
                        "signed genesis transaction {index} differs from genesis manifest"
                    ));
                }
            }
        }
    }
    let final_transaction_time = previous_creation_time
        .expect("a validated genesis manifest always expands to at least one transaction");
    let expected_block_time = final_transaction_time.checked_add(1).ok_or_else(|| {
        eyre!("signed genesis final transaction time cannot be followed by a canonical block time")
    })?;
    if block.header().creation_time().as_millis() != expected_block_time {
        return Err(eyre!(
            "signed genesis block creation time must be the millisecond after its final transaction"
        ));
    }
    Ok(())
}
/// Genesis block, represented as a thin wrapper around a signed block.
///
/// If an executor upgrade is specified (see [`RawGenesisTransaction::executor`]), the first transaction
/// must contain a single [`Upgrade`] instruction; otherwise it may contain parameters or other instructions.
/// Subsequent transactions can contain parameter settings, instructions, topology change, and IVM triggers.
/// Callers can access the wrapped [`SignedBlock`] via tuple struct syntax (`GenesisBlock.0`).
///
/// Raw manifest builders produce a canonical resultless proposal. A deployment signer such as `kagami genesis sign`
/// must execute it under the selected runtime configuration and publish the resulting result-bearing block.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenesisBlock(pub SignedBlock);
/// Format of `genesis.json` user file that tooling consumes before producing
/// the canonical [`GenesisBlock`].
///
/// It should be signed, converted to a [`GenesisBlock`], and serialized in Norito format before
/// supplying to an Iroha peer. See `kagami genesis sign`. Only the canonical Norito form is
/// supported. The structure mirrors the user-facing manifest consumed by `kagami genesis`.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_genesis::RawGenesisTransaction")]
#[derive(Debug, Clone, JsonSerialize, IntoSchema, Encode, Decode)]
pub struct RawGenesisTransaction {
    /// Unique chain identifier of the blockchain instance.
    chain: ChainId,
    /// Chain discriminant / i105 network prefix used to encode account literals in this manifest.
    chain_discriminant: u16,
    /// Optional path to the IVM executor bytecode file (`.to`). If omitted,
    /// no executor upgrade is included in genesis.
    #[norito(default)]
    executor: Option<IvmPath>,
    /// Path to the directory that contains prebuilt IVM bytecode referenced by
    /// triggers or other components.
    #[norito(default)]
    ivm_dir: IvmPath,
    /// List of raw genesis transactions that set parameters, execute
    /// instructions, update topology, or configure triggers.
    #[norito(default)]
    transactions: Vec<RawGenesisTx>,
    /// Consensus mode selected and signed by genesis. Fresh Sumeragi startup consumes the
    /// corresponding signed handshake metadata and freezes this mode into the height-one context.
    consensus_mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    /// First-release consensus wire protocol version.
    wire_protocol_version: u32,
    /// Optional typed deterministic fingerprint of consensus parameters.
    #[norito(default)]
    consensus_fingerprint: Option<ConsensusFingerprint>,
    /// Genesis-selected Sumeragi context parameters.
    ///
    /// JSON manifests must provide this explicitly. Programmatic builders put their selected
    /// profile here before signing; live nodes never infer it from local configuration.
    sumeragi_context: SumeragiGenesisContextParameters,
    /// Cryptography configuration snapshot advertised alongside the manifest.
    #[norito(default)]
    crypto: ManifestCrypto,
}
/// Cryptography defaults advertised in the genesis manifest.
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, IntoSchema, Encode, Decode, PartialEq, Eq,
)]
pub struct ManifestCrypto {
    /// Whether the OpenSSL-backed SM preview helpers are enabled.
    #[norito(default = "iroha_config::parameters::defaults::crypto::enable_sm_openssl_preview")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            default = "iroha_config::parameters::defaults::crypto::enable_sm_openssl_preview"
        )
    )]
    pub sm_openssl_preview: bool,
    /// SM intrinsic dispatch policy (`auto`, `force-enable`, `force-disable`).
    #[norito(default = "iroha_config::parameters::defaults::crypto::sm_intrinsics_policy")]
    pub sm_intrinsics: String,
    /// Default hash algorithm identifier (e.g., `blake2b-256`, `sm3-256`).
    pub default_hash: String,
    /// Signing algorithms allowed for transaction admission.
    pub allowed_signing: Vec<Algorithm>,
    /// Default distinguishing identifier applied when SM2 signatures omit it.
    pub sm2_distid_default: String,
    /// Curve identifiers (per the registry) allowed for account controllers.
    ///
    /// When omitted, the list is derived from `allowed_signing`.
    #[norito(default)]
    pub allowed_curve_ids: Vec<u8>,
}
impl Default for ManifestCrypto {
    fn default() -> Self {
        use iroha_config::parameters::defaults::crypto as defaults;
        Self {
            sm_openssl_preview: defaults::enable_sm_openssl_preview(),
            sm_intrinsics: defaults::sm_intrinsics_policy(),
            default_hash: defaults::default_hash(),
            allowed_signing: defaults::allowed_signing(),
            sm2_distid_default: defaults::sm2_distid_default(),
            allowed_curve_ids: defaults::allowed_curve_ids(),
        }
    }
}
impl ManifestCrypto {
    /// Validate the manifest crypto configuration is internally consistent.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing algorithms omit `ed25519`, if SM2 support
    /// is requested without enabling the `sm` feature toggles, or if SM2-related
    /// defaults (hash algorithm and distinguishing identifier) are inconsistent.
    pub fn validate(&self) -> eyre::Result<()> {
        if !self
            .allowed_signing
            .iter()
            .any(|algo| matches!(algo, Algorithm::Ed25519))
        {
            return Err(eyre!(
                "`allowed_signing` must include `ed25519` for control-plane operations"
            ));
        }
        let has_sm2 = self
            .allowed_signing
            .iter()
            .any(|algo| algo.as_static_str().eq_ignore_ascii_case("sm2"));
        if has_sm2 && !cfg!(feature = "sm") {
            return Err(eyre!(
                "`allowed_signing` includes `sm2`, but this build lacks SM support"
            ));
        }
        if has_sm2 {
            if !self.default_hash.trim().eq_ignore_ascii_case("sm3-256") {
                return Err(eyre!(
                    "`default_hash` must be `sm3-256` when `allowed_signing` contains `sm2`"
                ));
            }
            if self.sm2_distid_default.trim().is_empty() {
                return Err(eyre!(
                    "`sm2_distid_default` must be non-empty when `allowed_signing` contains `sm2`"
                ));
            }
        } else if self.default_hash.trim().eq_ignore_ascii_case("sm3-256") {
            return Err(eyre!(
                "`default_hash` is `sm3-256`, but `allowed_signing` does not include `sm2`; add `sm2` to enable SM cryptography"
            ));
        }
        if self.sm_openssl_preview && !cfg!(feature = "sm-ffi-openssl") {
            return Err(eyre!(
                "`sm_openssl_preview` requires building with the `sm-ffi-openssl` feature"
            ));
        }
        // Validate SM intrinsic policy string.
        SmIntrinsicsPolicyConfig::from_str(self.sm_intrinsics.as_str())?;
        let allowed_curves = self.resolved_allowed_curve_ids();
        if allowed_curves.is_empty() {
            return Err(eyre!(
                "`allowed_curve_ids` resolved to an empty set; enable at least one curve (ed25519)"
            ));
        }
        for id in &allowed_curves {
            let curve = CurveId::try_from(*id).map_err(|err| {
                eyre!("`allowed_curve_ids` contains unknown identifier {id:#04X}: {err}")
            })?;
            let algo = curve.algorithm();
            if !self.allowed_signing.contains(&algo) {
                return Err(eyre!(
                    "`allowed_curve_ids` includes curve id {id:#04X} ({}) \
                     but `allowed_signing` does not list the matching algorithm",
                    algo.as_static_str()
                ));
            }
        }
        Ok(())
    }
    /// Determine whether SM helper syscalls should be enabled based on the manifest.
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
    fn resolved_allowed_curve_ids(&self) -> Vec<u8> {
        let mut ids = if self.allowed_curve_ids.is_empty() {
            iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
                &self.allowed_signing,
            )
        } else {
            self.allowed_curve_ids.clone()
        };
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}
impl From<ManifestCrypto> for ActualCrypto {
    fn from(value: ManifestCrypto) -> Self {
        let allowed_curve_ids = value.resolved_allowed_curve_ids();
        let ManifestCrypto {
            sm_openssl_preview,
            sm_intrinsics,
            default_hash,
            allowed_signing,
            sm2_distid_default,
            ..
        } = value;
        Self {
            enable_sm_openssl_preview: sm_openssl_preview,
            sm_intrinsics: sm_intrinsics
                .parse::<SmIntrinsicsPolicyConfig>()
                .expect("manifest crypto must be validated before conversion")
                .into(),
            default_hash,
            allowed_signing,
            sm2_distid_default,
            allowed_curve_ids,
        }
    }
}
#[derive(Default)]
struct GenesisVkRegistry {
    entries: BTreeMap<VerifyingKeyId, VerifyingKeyRecord>,
    by_circuit: BTreeMap<(String, u32), VerifyingKeyId>,
}
/// Compute the verifying-key set hash derived from the provided genesis instructions.
///
/// # Errors
///
/// Returns an [`eyre::Report`] if any instruction fails while building the verifying-key registry.
pub fn compute_genesis_vk_set_hash<'a, I>(instructions: I) -> eyre::Result<Option<[u8; 32]>>
where
    I: IntoIterator<Item = &'a InstructionBox>,
{
    GenesisVkRegistry::build(instructions).map(|registry| registry.vk_set_hash())
}
impl GenesisVkRegistry {
    fn build<'a, I>(instructions: I) -> eyre::Result<Self>
    where
        I: IntoIterator<Item = &'a InstructionBox>,
    {
        let mut registry = Self::default();
        for instr in instructions {
            registry.apply_instruction(instr)?;
        }
        Ok(registry)
    }
    fn apply_instruction(&mut self, instr: &InstructionBox) -> eyre::Result<()> {
        if let Some(register) = instr
            .as_any()
            .downcast_ref::<verifying_keys::RegisterVerifyingKey>()
        {
            self.apply_register(register.id(), register.record())?;
        } else if let Some(update) = instr
            .as_any()
            .downcast_ref::<verifying_keys::UpdateVerifyingKey>()
        {
            self.apply_update(update.id(), update.record())?;
        }
        Ok(())
    }
    fn apply_register(
        &mut self,
        id: &VerifyingKeyId,
        record: &VerifyingKeyRecord,
    ) -> eyre::Result<()> {
        if self.entries.contains_key(id) {
            return Err(eyre!(
                "duplicate verifying key `{}` in genesis",
                Self::id_display(id)
            ));
        }
        if record.circuit_id.trim().is_empty() {
            return Err(eyre!(
                "verifying key `{}` missing circuit_id in genesis",
                Self::id_display(id)
            ));
        }
        if record.public_inputs_schema_hash == [0u8; 32] {
            return Err(eyre!(
                "verifying key `{}` missing public_inputs_schema_hash in genesis",
                Self::id_display(id)
            ));
        }
        if record.gas_schedule_id.is_none() {
            return Err(eyre!(
                "verifying key `{}` missing gas_schedule_id in genesis",
                Self::id_display(id)
            ));
        }
        let key = (record.circuit_id.clone(), record.version);
        if let Some(existing) = self.by_circuit.get(&key)
            && existing != id
        {
            return Err(eyre!(
                "circuit `{}` version {} already bound to `{}` in genesis",
                record.circuit_id,
                record.version,
                Self::id_display(existing)
            ));
        }
        self.entries.insert(id.clone(), record.clone());
        self.by_circuit.insert(key, id.clone());
        Ok(())
    }
    fn apply_update(
        &mut self,
        id: &VerifyingKeyId,
        record: &VerifyingKeyRecord,
    ) -> eyre::Result<()> {
        let Some(old) = self.entries.get(id) else {
            return Err(eyre!(
                "verifying key `{}` updated before registration in genesis",
                Self::id_display(id)
            ));
        };
        if record.version <= old.version {
            return Err(eyre!(
                "verifying key `{}` update does not bump version ({} -> {}) in genesis",
                Self::id_display(id),
                old.version,
                record.version
            ));
        }
        if record.circuit_id.trim().is_empty() {
            return Err(eyre!(
                "verifying key `{}` update missing circuit_id in genesis",
                Self::id_display(id)
            ));
        }
        if record.public_inputs_schema_hash == [0u8; 32] {
            return Err(eyre!(
                "verifying key `{}` update missing public_inputs_schema_hash in genesis",
                Self::id_display(id)
            ));
        }
        if record.gas_schedule_id.is_none() {
            return Err(eyre!(
                "verifying key `{}` update missing gas_schedule_id in genesis",
                Self::id_display(id)
            ));
        }
        let old_key = (old.circuit_id.clone(), old.version);
        self.by_circuit.remove(&old_key);
        let new_key = (record.circuit_id.clone(), record.version);
        if let Some(existing) = self.by_circuit.get(&new_key)
            && existing != id
        {
            return Err(eyre!(
                "circuit `{}` version {} already bound to `{}` in genesis update",
                record.circuit_id,
                record.version,
                Self::id_display(existing)
            ));
        }
        self.entries.insert(id.clone(), record.clone());
        self.by_circuit.insert(new_key, id.clone());
        Ok(())
    }
    fn vk_set_hash(&self) -> Option<[u8; 32]> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, rec)| matches!(rec.status, ConfidentialStatus::Active))
            .collect();
        if entries.is_empty() {
            return None;
        }
        entries.sort_by(|(id_a, rec_a), (id_b, rec_b)| {
            rec_a
                .circuit_id
                .cmp(&rec_b.circuit_id)
                .then(rec_a.version.cmp(&rec_b.version))
                .then(id_a.backend.as_str().cmp(id_b.backend.as_str()))
                .then(id_a.name.cmp(&id_b.name))
        });
        let mut buf = Vec::with_capacity(entries.len() * 160);
        for (id, rec) in entries {
            buf.extend_from_slice(id.backend.as_bytes());
            buf.push(0);
            buf.extend_from_slice(id.name.as_bytes());
            buf.push(0);
            buf.extend_from_slice(rec.circuit_id.as_bytes());
            buf.push(0);
            buf.extend_from_slice(&rec.version.to_le_bytes());
            buf.extend_from_slice(&rec.commitment);
            buf.extend_from_slice(&rec.public_inputs_schema_hash);
            if let Some(ref gas) = rec.gas_schedule_id {
                buf.extend_from_slice(gas.as_bytes());
            }
            buf.push(0xFF);
        }
        Some(Hash::new(&buf).into())
    }
    fn id_display(id: &VerifyingKeyId) -> String {
        format!("{}::{}", id.backend.as_str(), id.name)
    }
}
/// Norito-compatible JSON helpers for serializing and deserializing genesis instruction lists.
pub mod genesis_instructions_json;
/// Individual genesis transaction as represented in JSON. A transaction may set parameters, execute
/// instructions, schedule IVM triggers, or set the initial topology.
#[derive(Debug, Clone, JsonDeserialize, IntoSchema, Encode, Decode, Default)]
#[norito(decode_from_slice)]
pub struct RawGenesisTx {
    /// Parameter updates applied at genesis.
    #[norito(skip_serializing_if = "Option::is_none")]
    parameters: Option<Parameters>,
    /// Iroha instructions executed during genesis.
    ///
    /// Genesis JSON stores each instruction as a structured Norito object.
    #[norito(default)]
    #[norito(with = "crate::genesis_instructions_json")]
    instructions: Vec<InstructionBox>,
    /// Triggers whose executable is IVM bytecode, not instructions. Retained as a dedicated
    /// collection until the trigger subsystem unifies instruction-backed and IVM-backed variants.
    #[norito(default)]
    ivm_triggers: Vec<GenesisIvmTrigger>,
    /// Initial topology (list of peers) to bootstrap the network.
    ///
    /// Entries are provided as `{ "peer": <PeerId>, "pop_hex": "<hex>" }` to keep
    /// peers and their PoPs together. `pop_hex` may be omitted while composing
    /// manifests but must be present before signing.
    #[norito(default)]
    topology: Vec<GenesisTopologyEntry>,
}
impl norito::json::JsonSerialize for RawGenesisTx {
    fn json_serialize(&self, out: &mut String) {
        fn write_field<F>(out: &mut String, first: &mut bool, key: &str, write_value: F)
        where
            F: FnOnce(&mut String),
        {
            if *first {
                *first = false;
            } else {
                out.push(',');
            }
            norito::json::write_json_string(key, out);
            out.push(':');
            write_value(out);
        }
        out.push('{');
        let mut first = true;
        // Preserve deterministic ordering (lexicographic by key) to match prior map output.
        write_field(out, &mut first, "instructions", |out| {
            genesis_instructions_json::instructions_to_value(&self.instructions)
                .json_serialize(out);
        });
        write_field(out, &mut first, "ivm_triggers", |out| {
            self.ivm_triggers.json_serialize(out);
        });
        if let Some(parameters) = &self.parameters {
            write_field(out, &mut first, "parameters", |out| {
                parameters.json_serialize(out);
            });
        }
        write_field(out, &mut first, "topology", |out| {
            self.topology.json_serialize(out);
        });
        out.push('}');
    }
}
impl RawGenesisTx {
    /// Instructions carried by this raw genesis transaction.
    #[must_use]
    pub fn instructions(&self) -> &[InstructionBox] {
        &self.instructions
    }
    /// Topology entries carried by this transaction.
    #[must_use]
    pub fn topology(&self) -> &[GenesisTopologyEntry] {
        &self.topology
    }
}
/// Peer PoP entry used to merge PoPs into topology entries.
#[cfg(test)]
#[derive(
    Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize, IntoSchema, Encode, Decode,
)]
pub struct GenesisPeerPop {
    /// Peer public key.
    pub public_key: PublicKey,
    /// Proof-of-possession bytes.
    pub pop: Vec<u8>,
}
/// Peer + proof-of-possession pair in genesis manifest.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, IntoSchema, Encode, Decode)]
pub struct GenesisTopologyEntry {
    /// Peer identifier.
    pub peer: PeerId,
    /// `PoP` hex string (lowercase, without `0x`).
    #[norito(skip_serializing_if = "Option::is_none")]
    pub pop_hex: Option<String>,
}
impl From<PeerId> for GenesisTopologyEntry {
    fn from(peer: PeerId) -> Self {
        Self {
            peer,
            pop_hex: None,
        }
    }
}
impl GenesisTopologyEntry {
    /// Build a topology entry from raw PoP bytes.
    #[must_use]
    pub fn new(peer: PeerId, pop: Vec<u8>) -> Self {
        Self {
            peer,
            pop_hex: Some(hex::encode(pop)),
        }
    }
    /// Decode the PoP hex string into bytes, if present.
    pub fn pop_bytes(&self) -> Result<Option<Vec<u8>>> {
        let Some(pop_hex) = self.pop_hex.as_deref() else {
            return Ok(None);
        };
        let trimmed = pop_hex
            .strip_prefix("0x")
            .or_else(|| pop_hex.strip_prefix("0X"))
            .unwrap_or(pop_hex);
        let bytes = hex::decode(trimmed).map_err(|err| {
            eyre!(
                "invalid `pop_hex` for topology peer {}: {err}",
                self.peer.public_key()
            )
        })?;
        if bytes.is_empty() {
            return Err(eyre!(
                "`pop_hex` for topology peer {} is empty",
                self.peer.public_key()
            ));
        }
        Ok(Some(bytes))
    }
}
impl norito::json::JsonDeserialize for GenesisTopologyEntry {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = norito::json::Value::json_deserialize(parser)?;
        let mut map = match value {
            norito::json::Value::Object(map) => map,
            _ => {
                return Err(norito::json::Error::Message(
                    "topology entries must be objects with `peer` and optional `pop_hex`"
                        .to_string(),
                ));
            }
        };
        let peer_value = map
            .remove("peer")
            .ok_or_else(|| norito::json::Error::missing_field("peer"))?;
        let peer: PeerId = norito::json::value::from_value(peer_value).map_err(|err| {
            norito::json::Error::Message(format!("failed to decode `peer`: {err}"))
        })?;
        let pop_hex = match map.remove("pop_hex") {
            None | Some(norito::json::Value::Null) => None,
            Some(norito::json::Value::String(raw)) => Some(normalize_pop_hex(&raw)?),
            Some(other) => {
                let raw = norito::json::value::from_value::<String>(other).map_err(|err| {
                    norito::json::Error::Message(format!("failed to decode `pop_hex`: {err}"))
                })?;
                Some(normalize_pop_hex(&raw)?)
            }
        };
        if let Some((field, _)) = map.into_iter().next() {
            return Err(norito::json::Error::UnknownField { field });
        }
        Ok(Self { peer, pop_hex })
    }
}
fn normalize_pop_hex(raw: &str) -> Result<String, norito::json::Error> {
    let trimmed = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let bytes = hex::decode(trimmed)
        .map_err(|err| norito::json::Error::Message(format!("invalid `pop_hex`: {err}")))?;
    if bytes.is_empty() {
        return Err(norito::json::Error::Message(
            "`pop_hex` must not be empty".to_string(),
        ));
    }
    Ok(hex::encode(bytes))
}
/// Fully expanded view of a genesis manifest after all automatic injections.
#[derive(Debug, Clone)]
pub struct NormalizedGenesis {
    /// Unique chain identifier.
    pub chain: ChainId,
    /// Chain discriminant / i105 network prefix used to encode account literals in this manifest.
    pub chain_discriminant: u16,
    /// Optional path to the executor bytecode.
    pub executor: Option<IvmPath>,
    /// Directory containing IVM bytecode libraries.
    pub ivm_dir: PathBuf,
    /// Consensus mode advertised in genesis.
    pub consensus_mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    /// First-release consensus protocol version.
    pub wire_protocol_version: u32,
    /// Deterministic fingerprint of consensus parameters.
    pub consensus_fingerprint: ConsensusFingerprint,
    /// Signed Sumeragi height-context transport parameters.
    pub sumeragi_context: SumeragiGenesisContextParameters,
    /// Cryptography snapshot advertised alongside genesis.
    pub crypto: ManifestCrypto,
    /// Final transaction batches that will be signed into the genesis block.
    pub transactions: Vec<Vec<InstructionBox>>,
}
impl NormalizedGenesis {
    /// Render the normalized manifest as a JSON value with structured instructions.
    #[must_use]
    pub fn to_json_value(&self) -> norito::json::Value {
        use norito::json::{Number, Value};
        let mut map = norito::json::Map::new();
        map.insert(
            "chain".to_string(),
            norito::json::value::to_value(&self.chain).expect("serialize chain id"),
        );
        map.insert(
            "chain_discriminant".to_string(),
            norito::json::value::to_value(&self.chain_discriminant)
                .expect("serialize chain_discriminant"),
        );
        if let Some(path) = &self.executor {
            map.insert(
                "executor".to_string(),
                norito::json::Value::String(path.0.display().to_string()),
            );
        } else {
            map.insert("executor".to_string(), Value::Null);
        }
        map.insert(
            "ivm_dir".to_string(),
            norito::json::Value::String(self.ivm_dir.display().to_string()),
        );
        map.insert(
            "consensus_mode".to_string(),
            norito::json::value::to_value(&self.consensus_mode).expect("serialize consensus_mode"),
        );
        map.insert(
            "wire_protocol_version".to_string(),
            norito::json::value::to_value(&self.wire_protocol_version)
                .expect("serialize wire_protocol_version"),
        );
        map.insert(
            "consensus_fingerprint".to_string(),
            norito::json::value::to_value(&self.consensus_fingerprint)
                .expect("serialize consensus fingerprint"),
        );
        map.insert(
            "sumeragi_context".to_string(),
            norito::json::value::to_value(&self.sumeragi_context)
                .expect("serialize Sumeragi context parameters"),
        );
        map.insert(
            "crypto".to_string(),
            norito::json::value::to_value(&self.crypto).expect("serialize crypto"),
        );
        let transactions = self
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, instructions)| {
                let mut tx_map = norito::json::Map::new();
                tx_map.insert("index".to_string(), Value::Number(Number::U64(idx as u64)));
                tx_map.insert(
                    "instructions".to_string(),
                    genesis_instructions_json::instructions_to_value(instructions),
                );
                Value::Object(tx_map)
            })
            .collect();
        map.insert("transactions".to_string(), Value::Array(transactions));
        Value::Object(map)
    }
    /// Render normalized genesis as pretty JSON.
    pub fn to_pretty_json(&self) -> Result<String, norito::json::Error> {
        norito::json::to_json_pretty(&self.to_json_value())
    }
}
/// Path to IVM bytecode file or its directory
#[derive(Debug, Clone, IntoSchema)]
#[schema(transparent = "String")]
pub struct IvmPath(PathBuf);
impl Default for IvmPath {
    fn default() -> Self {
        Self(PathBuf::from("."))
    }
}
impl IvmPath {
    /// Access the underlying path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}
fn parameter_targets_same_slot(lhs: &Parameter, rhs: &Parameter) -> bool {
    use core::mem::discriminant;
    match (lhs, rhs) {
        (Parameter::Sumeragi(a), Parameter::Sumeragi(b)) => discriminant(a) == discriminant(b),
        (Parameter::Block(a), Parameter::Block(b)) => discriminant(a) == discriminant(b),
        (Parameter::Transaction(a), Parameter::Transaction(b)) => {
            discriminant(a) == discriminant(b)
        }
        (Parameter::Executor(a), Parameter::Executor(b)) => discriminant(a) == discriminant(b),
        (Parameter::SmartContract(a), Parameter::SmartContract(b)) => {
            discriminant(a) == discriminant(b)
        }
        (Parameter::Custom(a), Parameter::Custom(b)) => a.id() == b.id(),
        _ => false,
    }
}
fn collect_parameter_instructions(parameters: &Parameters) -> Vec<InstructionBox> {
    let mut generated = Vec::new();
    for parameter in parameters.parameters() {
        // The structured genesis block is authoritative for every policy slot,
        // including admission and execution limits. Its signed instructions
        // must retain the same values rather than reconstructing defaults.
        if generated
            .iter()
            .any(|existing| parameter_targets_same_slot(existing, &parameter))
        {
            continue;
        }
        generated.push(parameter);
    }
    generated
        .into_iter()
        .map(|parameter| InstructionBox::from(SetParameter::new(parameter)))
        .collect()
}
fn is_consensus_handshake_metadata_instruction(instruction: &InstructionBox) -> bool {
    instruction
        .as_any()
        .downcast_ref::<SetParameter>()
        .is_some_and(|set_param| {
            matches!(
                set_param.inner(),
                Parameter::Custom(custom) if custom.id() == &consensus_metadata::handshake_meta_id()
            )
        })
}
fn compute_consensus_parameters_fingerprint(
    params: &iroha_data_model::block::consensus::ConsensusGenesisParams,
) -> Result<[u8; 32]> {
    iroha_data_model::block::consensus::fingerprint::compute(params)
        .map_err(|error| eyre!("invalid signed consensus parameters: {error}"))
}
/// Incomplete genesis source JSON whose consensus fingerprint and NPoS XOR pin are not yet bound.
///
/// Source templates are not [`RawGenesisTransaction`] values and cannot be signed. They must be
/// materialized with the explicit network XOR selection before entering validation or signing.
#[derive(Clone, Debug)]
pub struct GenesisSourceTemplate {
    json_path: PathBuf,
    value: norito::json::Value,
}

impl GenesisSourceTemplate {
    /// Read an explicitly named `.template.json` source under genesis JSON resource bounds.
    ///
    /// # Errors
    ///
    /// Returns an error unless the path names a bounded JSON object which carries no
    /// pre-materialization consensus fingerprint.
    pub fn from_path(json_path: impl AsRef<Path>) -> Result<Self> {
        let json_path = json_path.as_ref();
        let is_template_name = json_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".template.json"));
        if !is_template_name {
            return Err(eyre!(
                "genesis source templates must use the `.template.json` suffix: {}",
                json_path.display()
            ));
        }
        let bytes =
            bounded_manifest::read_genesis_manifest_bytes(json_path).wrap_err_with(|| {
                eyre!(
                    "failed to read bounded genesis source template at {}",
                    json_path.display()
                )
            })?;
        let value: norito::json::Value = norito::json::from_slice(&bytes).map_err(|error| {
            eyre!(
                "failed to decode genesis source template {}: {error}",
                json_path.display()
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            eyre!(
                "genesis source template {} must be a JSON object",
                json_path.display()
            )
        })?;
        if object.get("consensus_fingerprint") != Some(&norito::json::Value::Null) {
            return Err(eyre!(
                "genesis source template {} must set consensus_fingerprint to null until authority materialization",
                json_path.display()
            ));
        }
        Ok(Self {
            json_path: json_path.to_path_buf(),
            value,
        })
    }

    /// Pin the explicit NPoS XOR selection and produce a complete Raw manifest.
    ///
    /// The consensus fingerprint is recomputed after materialization. The signed handshake
    /// authenticates the result, and Core rechecks the genesis roster during startup.
    ///
    /// # Errors
    ///
    /// Returns an error when the explicit NPoS XOR selection is invalid, or the completed JSON
    /// is not a valid [`RawGenesisTransaction`].
    pub fn materialize(
        mut self,
        xor_asset_definition_id: Option<AssetDefinitionId>,
    ) -> Result<RawGenesisTransaction> {
        let is_npos = self
            .value
            .get("consensus_mode")
            .and_then(norito::json::Value::as_str)
            == Some("Npos");
        if is_npos != xor_asset_definition_id.is_some() {
            return Err(eyre!(
                "NPoS source materialization requires an explicit canonical XOR definition; permissioned sources omit it"
            ));
        }
        if let Some(asset) = xor_asset_definition_id {
            let chain = self
                .value
                .get("chain")
                .and_then(norito::json::Value::as_str)
                .unwrap_or_default();
            if chain == "00000000-0000-0000-0000-000000000753"
                && asset.to_string() == "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            {
                return Err(eyre!(
                    "public Nexus requires its operator-provisioned mainnet XOR definition; the Taira testnet definition is forbidden"
                ));
            }
            if chain == "fc56984b-2be7-431d-840e-21514d1883f0"
                && asset.to_string() != "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            {
                return Err(eyre!("public Taira requires its canonical XOR definition"));
            }
            let transactions = self
                .value
                .get_mut("transactions")
                .and_then(norito::json::Value::as_array_mut)
                .ok_or_else(|| eyre!("genesis source has no transaction array"))?;
            let mut pinned = 0;
            for transaction in transactions {
                if let Some(payload) = transaction
                    .get_mut("parameters")
                    .and_then(|value| value.get_mut("custom"))
                    .and_then(|value| value.get_mut("sumeragi_npos_parameters"))
                    .and_then(|value| value.get_mut("payload"))
                    .and_then(norito::json::Value::as_object_mut)
                {
                    payload.insert(
                        "xor_asset_definition_id".to_owned(),
                        norito::json::Value::String(asset.to_string()),
                    );
                    pinned += 1;
                }
            }
            if pinned != 1 {
                return Err(eyre!(
                    "NPoS source must have exactly one authoritative XOR asset pin"
                ));
            }
        }
        let completed = norito::json::to_vec(&self.value)
            .map_err(|error| eyre!("serialize materialized genesis manifest: {error}"))?;
        let manifest = RawGenesisTransaction::from_json_slice_at_path(&completed, &self.json_path)?;
        manifest.validate_mode_specific_consensus_parameters()?;
        manifest.with_consensus_meta()
    }
}

impl RawGenesisTransaction {
    /// Validate consensus-mode parameters.
    ///
    /// # Errors
    ///
    /// Returns an error when NPoS parameters disagree with the consensus mode, or the initial
    /// epoch cannot contain the committed anchor and authenticated beacon pulse required before
    /// its boundary.
    pub fn validate_mode_specific_consensus_parameters(&self) -> Result<()> {
        let parameters = self.effective_parameters()?;
        let scheduled_epoch_length = parameters.sumeragi().epoch_length_blocks;
        let npos_parameter = parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id());
        let npos_parameters = npos_parameter
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()?
            .flatten();
        match (self.consensus_mode, npos_parameters) {
            (SumeragiConsensusMode::Permissioned, Some(_)) => Err(eyre!(
                "permissioned genesis must omit `sumeragi_npos_parameters`"
            )),
            (SumeragiConsensusMode::Permissioned, None) => Ok(()),
            (SumeragiConsensusMode::Npos, None) => Err(eyre!(
                "NPoS genesis requires `sumeragi_npos_parameters`; node-local election defaults are not signed inputs"
            )),
            (SumeragiConsensusMode::Npos, Some(parameters)) => {
                // The pulse at boundary - 1 authenticates a committed anchor at boundary - 2.
                // Height zero is not a block and cannot serve as that anchor.
                if parameters.epoch_length_blocks().get() < 3 {
                    return Err(eyre!(
                        "NPoS genesis requires epoch_length_blocks >= 3 for its committed beacon anchor and pre-boundary pulse"
                    ));
                }
                if parameters.epoch_length_blocks() != scheduled_epoch_length {
                    return Err(eyre!(
                        "NPoS epoch_length_blocks must equal the signed Sumeragi epoch_length_blocks"
                    ));
                }
                Ok(())
            }
        }
    }
    fn validate_structured_parameter_blocks(&self) -> Result<()> {
        let positions = self
            .transactions
            .iter()
            .enumerate()
            .filter_map(|(index, tx)| tx.parameters.as_ref().map(|_| index))
            .collect::<Vec<_>>();
        if positions.len() > 1 {
            return Err(eyre!(
                "genesis manifest contains multiple structured `parameters` blocks at transaction indices {positions:?}; use exactly one authoritative block because `Parameters` is a complete snapshot, not a patch"
            ));
        }
        Ok(())
    }
    fn validate_no_explicit_set_parameter_instructions(&self) -> Result<()> {
        if let Some((tx_index, instr_index)) =
            Self::explicit_set_parameter_position(&self.transactions)
        {
            return Err(eyre!(Self::explicit_set_parameter_message(
                tx_index,
                instr_index
            )));
        }
        Ok(())
    }
    fn explicit_set_parameter_position(transactions: &[RawGenesisTx]) -> Option<(usize, usize)> {
        transactions.iter().enumerate().find_map(|(tx_index, tx)| {
            tx.instructions
                .iter()
                .position(|instruction| {
                    instruction
                        .as_any()
                        .downcast_ref::<SetParameter>()
                        .is_some()
                })
                .map(|instr_index| (tx_index, instr_index))
        })
    }
    fn explicit_set_parameter_message(tx_index: usize, instr_index: usize) -> String {
        format!(
            "genesis transactions must not contain SetParameter instructions (tx {tx_index}, instruction {instr_index}); move parameters into the structured `parameters` block"
        )
    }
    fn expect_object(
        value: norito::json::Value,
        context: &'static str,
    ) -> Result<norito::json::Map, norito::json::Error> {
        match value {
            norito::json::Value::Object(map) => Ok(map),
            _ => Err(norito::json::Error::InvalidField {
                field: context.into(),
                message: String::from("expected object"),
            }),
        }
    }
    fn take_required_field<T>(
        map: &mut norito::json::Map,
        field: &'static str,
    ) -> Result<T, norito::json::Error>
    where
        T: norito::json::JsonDeserialize,
    {
        let value = map
            .remove(field)
            .ok_or_else(|| norito::json::Error::missing_field(field))?;
        Self::decode_value(value, field)
    }
    fn take_optional_field<T>(
        map: &mut norito::json::Map,
        field: &'static str,
    ) -> Result<Option<T>, norito::json::Error>
    where
        T: norito::json::JsonDeserialize,
    {
        match map.remove(field) {
            Some(norito::json::Value::Null) | None => Ok(None),
            Some(value) => Self::decode_value(value, field).map(Some),
        }
    }
    fn decode_value<T>(
        value: norito::json::Value,
        field: &'static str,
    ) -> Result<T, norito::json::Error>
    where
        T: norito::json::JsonDeserialize,
    {
        norito::json::value::from_value(value).map_err(|err| {
            norito::json::Error::Message(format!("failed to decode `{field}`: {err}"))
        })
    }
    fn reject_set_parameter_instructions(
        transactions: &[RawGenesisTx],
    ) -> Result<(), norito::json::Error> {
        if let Some((tx_index, instr_index)) = Self::explicit_set_parameter_position(transactions) {
            return Err(norito::json::Error::Message(
                Self::explicit_set_parameter_message(tx_index, instr_index),
            ));
        }
        Ok(())
    }
    fn from_json_value(value: norito::json::Value) -> Result<Self, norito::json::Error> {
        let mut map = Self::expect_object(value, "RawGenesisTransaction")?;
        let chain = Self::take_required_field::<ChainId>(&mut map, "chain")?;
        let chain_discriminant = Self::take_required_field::<u16>(&mut map, "chain_discriminant")?;
        let executor = Self::take_optional_field::<IvmPath>(&mut map, "executor")?;
        let ivm_dir = map
            .remove("ivm_dir")
            .map(|value| match value {
                norito::json::Value::String(raw) => Ok(IvmPath(PathBuf::from(raw))),
                norito::json::Value::Null => Ok(IvmPath::default()),
                other => Self::decode_value::<IvmPath>(other, "ivm_dir"),
            })
            .transpose()?
            .unwrap_or_else(IvmPath::default);
        let transactions_value = map
            .remove("transactions")
            .unwrap_or_else(|| norito::json::Value::Array(Vec::new()));
        let _chain_discriminant =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
        let transactions =
            Self::decode_value::<Vec<RawGenesisTx>>(transactions_value, "transactions")?;
        Self::reject_set_parameter_instructions(&transactions)?;
        let parameter_blocks = transactions
            .iter()
            .enumerate()
            .filter_map(|(index, tx)| tx.parameters.as_ref().map(|_| index))
            .collect::<Vec<_>>();
        if parameter_blocks.len() > 1 {
            return Err(norito::json::Error::Message(format!(
                "genesis manifest contains multiple structured `parameters` blocks at transaction indices {parameter_blocks:?}; use exactly one authoritative block because `Parameters` is a complete snapshot, not a patch"
            )));
        }
        let consensus_mode = Self::take_required_field::<
            iroha_data_model::parameter::system::SumeragiConsensusMode,
        >(&mut map, "consensus_mode")?;
        let wire_protocol_version =
            Self::take_required_field::<u32>(&mut map, "wire_protocol_version")?;
        let consensus_fingerprint =
            Self::take_optional_field::<ConsensusFingerprint>(&mut map, "consensus_fingerprint")?;
        let sumeragi_context = Self::take_required_field::<SumeragiGenesisContextParameters>(
            &mut map,
            "sumeragi_context",
        )?;
        let crypto = map
            .remove("crypto")
            .map(|value| Self::decode_value::<ManifestCrypto>(value, "crypto"))
            .transpose()?
            .unwrap_or_else(ManifestCrypto::default);
        if let Some((field, _)) = map.into_iter().next() {
            return Err(norito::json::Error::UnknownField { field });
        }
        Ok(Self {
            chain,
            chain_discriminant,
            executor,
            ivm_dir,
            transactions,
            consensus_mode,
            wire_protocol_version,
            consensus_fingerprint,
            sumeragi_context,
            crypto,
        })
    }
    /// Compute the effective parameter set from the authoritative structured parameter snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest contains more than one structured parameter block or any
    /// explicit [`SetParameter`] instruction. Parameters must be supplied only through the
    /// structured `parameters` block.
    pub fn effective_parameters(&self) -> Result<Parameters> {
        self.validate_no_explicit_set_parameter_instructions()?;
        self.validate_structured_parameter_blocks()?;
        Ok(self
            .transactions
            .iter()
            .find_map(|transaction| transaction.parameters.as_ref())
            .cloned()
            .unwrap_or_default())
    }
    /// Populate consensus metadata fields with defaults and a computed consensus fingerprint.
    ///
    /// Existing transactions are preserved. Every parameter read must complete before the
    /// resulting fingerprint can be used by normalization or signing.
    ///
    /// # Errors
    /// Returns the original parameter decoding failure, invalid mode/policy binding, or
    /// fingerprint construction error. Local decoder failures are not missing metadata.
    pub fn with_consensus_meta(mut self) -> Result<Self> {
        use iroha_data_model::parameter::system::{
            BlockParameters, SumeragiConsensusMode, SumeragiParameters,
        };
        let params = self.effective_parameters()?;
        let sumeragi: SumeragiParameters = params.sumeragi().clone();
        let block: BlockParameters = params.block();
        let custom = params.custom();
        let block_cadence_ms = sumeragi.block_cadence_ms();
        let block_max_transactions = block.max_transactions();
        // `effective_parameters()` applies the single structured parameter snapshot.
        let npos_param_id = SumeragiNposParameters::parameter_id();
        let npos_payload = custom
            .get(&npos_param_id)
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()?
            .flatten();
        // Consensus mode is a first-release signed-genesis choice. Runtime
        // mode staging is unrepresentable, and the mere presence of NPoS
        // tuning data must never infer or flip the live protocol mode.
        let mode = self.consensus_mode;
        let mode = match (mode, npos_payload) {
            (SumeragiConsensusMode::Permissioned, None) => ConsensusGenesisModeParams::Permissioned,
            (SumeragiConsensusMode::Permissioned, Some(_)) => {
                return Err(eyre!(
                    "permissioned genesis must omit `sumeragi_npos_parameters`"
                ));
            }
            (SumeragiConsensusMode::Npos, None) => {
                return Err(eyre!("NPoS genesis requires `sumeragi_npos_parameters`"));
            }
            (SumeragiConsensusMode::Npos, Some(npos)) => {
                ConsensusGenesisModeParams::Npos(NposGenesisParams {
                    epoch_length_blocks: npos.epoch_length_blocks(),
                    epoch_seed: npos.epoch_seed(),
                    max_validators: npos.max_validators(),
                    min_self_bond: npos.min_self_bond().clone(),
                    min_nomination_bond: npos.min_nomination_bond().clone(),
                    finality_margin_blocks: npos.finality_margin_blocks(),
                    evidence_horizon_blocks: npos.evidence_horizon_blocks(),
                    activation_lag_blocks: npos.activation_lag_blocks(),
                    slashing_delay_blocks: npos.slashing_delay_blocks(),
                })
            }
        };
        let dm_params = ConsensusGenesisParams {
            block_cadence_ms,
            block_max_transactions,
            mode,
            protocol_version: iroha_config::parameters::defaults::sumeragi::PROTOCOL_VERSION,
            sumeragi_context: self.sumeragi_context.clone(),
        };
        let fp = compute_consensus_parameters_fingerprint(&dm_params)?;
        self.wire_protocol_version = CONSENSUS_PROTOCOL_VERSION;
        self.consensus_fingerprint = Some(ConsensusFingerprint::new(fp));
        Ok(self)
    }
    /// Expand the manifest into a normalized, fully-injected representation.
    ///
    /// The returned structure includes consensus/crypto metadata and the exact
    /// transaction batches that will be signed into the genesis block.
    ///
    /// # Errors
    ///
    /// - if consensus metadata cannot be populated
    /// - if instruction injection fails (e.g., invalid topology PoPs)
    pub fn normalize(self) -> Result<NormalizedGenesis> {
        self.validate_mode_specific_consensus_parameters()?;
        // Always refresh consensus metadata so fingerprints stay aligned with
        // effective parameters after manifest edits.
        let manifest = self.with_consensus_meta()?;
        let consensus_mode = manifest.consensus_mode;
        if manifest.wire_protocol_version != CONSENSUS_PROTOCOL_VERSION {
            return Err(eyre!(
                "unsupported wire_protocol_version after normalization"
            ));
        }
        let consensus_fingerprint = manifest.consensus_fingerprint.clone().ok_or_else(|| {
            eyre!(
                "consensus_fingerprint missing after normalization; call with_consensus_meta first"
            )
        })?;
        let sumeragi_context = manifest.sumeragi_context.clone();
        sumeragi_context
            .validate()
            .map_err(|error| eyre!("invalid signed Sumeragi context parameters: {error}"))?;
        let chain = manifest.chain.clone();
        let chain_discriminant = manifest.chain_discriminant;
        let executor = manifest.executor.clone();
        let ivm_dir = manifest.ivm_dir.as_path().to_path_buf();
        let wire_protocol_version = manifest.wire_protocol_version;
        let crypto = manifest.crypto.clone();
        let transactions = manifest.parse()?;
        Ok(NormalizedGenesis {
            chain,
            chain_discriminant,
            executor,
            ivm_dir,
            consensus_mode,
            wire_protocol_version,
            consensus_fingerprint,
            sumeragi_context,
            crypto,
            transactions,
        })
    }
    /// Chain identifier advertised in the manifest.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain
    }
    /// Chain discriminant / i105 network prefix advertised in the manifest.
    #[must_use]
    pub const fn chain_discriminant(&self) -> u16 {
        self.chain_discriminant
    }
    /// Override the chain discriminant used when rendering this manifest.
    #[must_use]
    pub fn with_chain_discriminant(mut self, chain_discriminant: u16) -> Self {
        self.chain_discriminant = chain_discriminant;
        self
    }
    /// Raw genesis transactions preserved in the manifest.
    #[must_use]
    pub fn transactions(&self) -> &[RawGenesisTx] {
        &self.transactions
    }
    /// Append one instruction-only transaction without rebuilding any original transaction.
    ///
    /// Authored parameters, topology, triggers, policies and transaction boundaries retain
    /// their exact original values and order. This unsigned assembly operation confers no
    /// instruction authority; the original genesis signer and Core staging still admit it.
    ///
    /// # Errors
    /// Refuses `SetParameter`, which must remain in the structured parameter snapshot.
    pub fn append_instruction_transaction(
        mut self,
        instruction: impl Into<InstructionBox>,
    ) -> Result<Self> {
        let instruction = instruction.into();
        if instruction
            .as_any()
            .downcast_ref::<SetParameter>()
            .is_some()
        {
            return Err(eyre!(
                "instruction-only genesis append refuses SetParameter; use the structured parameter snapshot"
            ));
        }
        self.transactions.push(RawGenesisTx {
            instructions: vec![instruction],
            ..RawGenesisTx::default()
        });
        Ok(self)
    }
    /// Validate that the canonical validator topology which will enter genesis is an exact
    /// supported committee. Its ordered BLS roster is validator generation zero.
    ///
    /// # Errors
    ///
    /// Returns an error when the topology is not an exact supported `3f + 1`
    /// committee, repeats a peer, or contains a missing or invalid BLS proof of possession.
    pub fn validate_genesis_topology(&self) -> Result<()> {
        let mut topology = self
            .transactions
            .iter()
            .flat_map(|transaction| transaction.topology.iter())
            .map(|entry| entry.peer.clone())
            .collect::<Vec<_>>();
        if !is_valid_committee_size(topology.len()) {
            return Err(eyre!(
                "genesis signing requires an exact Sumeragi `3f + 1` topology in the supported range 4..={MAX_VALIDATORS_PER_HEIGHT} (saw {})",
                topology.len()
            ));
        }
        topology.sort();
        if topology.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(eyre!(
                "genesis topology repeats a validator identity; provision one canonical entry per validator"
            ));
        }
        for entry in self.transactions.iter().flat_map(|tx| &tx.topology) {
            let validator_key = entry.peer.public_key();
            let pop = entry.pop_bytes()?.ok_or_else(|| {
                eyre!("missing `pop_hex` entry for topology peer {validator_key}")
            })?;
            bls_normal_pop_verify(validator_key, &pop).map_err(|error| {
                eyre!("genesis topology validator {validator_key} has an invalid PoP: {error}")
            })?;
        }
        Ok(())
    }
    /// Replace one instruction-only raw transaction with one or more instruction-only transactions.
    ///
    /// This deliberately refuses to rewrite a transaction that also carries parameters, IVM
    /// triggers, or topology. Callers can therefore perform a narrow transaction-boundary migration
    /// without silently moving any other genesis semantics.
    #[cfg(test)]
    pub fn replace_instruction_only_transaction(
        &mut self,
        index: usize,
        replacement_batches: Vec<Vec<InstructionBox>>,
    ) -> Result<()> {
        if replacement_batches.is_empty() {
            return Err(eyre!(
                "replacement for raw genesis transaction {index} must contain at least one batch"
            ));
        }
        if let Some((batch_index, _)) = replacement_batches
            .iter()
            .enumerate()
            .find(|(_, batch)| batch.is_empty())
        {
            return Err(eyre!(
                "replacement batch {batch_index} for raw genesis transaction {index} must not be empty"
            ));
        }
        if let Some((batch_index, instruction_index)) = replacement_batches
            .iter()
            .enumerate()
            .find_map(|(batch_index, batch)| {
                batch
                    .iter()
                    .position(|instruction| {
                        instruction
                            .as_any()
                            .downcast_ref::<SetParameter>()
                            .is_some()
                    })
                    .map(|instruction_index| (batch_index, instruction_index))
            })
        {
            return Err(eyre!(
                "replacement batch {batch_index}, instruction {instruction_index} contains SetParameter; move parameters into the structured `parameters` block"
            ));
        }
        let original = self.transactions.get(index).ok_or_else(|| {
            eyre!(
                "raw genesis transaction index {index} is out of bounds for {} transactions",
                self.transactions.len()
            )
        })?;
        if original.parameters.is_some()
            || !original.ivm_triggers.is_empty()
            || !original.topology.is_empty()
        {
            return Err(eyre!(
                "raw genesis transaction {index} is not instruction-only; refusing to move parameters, IVM triggers, or topology"
            ));
        }
        let replacements = replacement_batches
            .into_iter()
            .map(|instructions| RawGenesisTx {
                parameters: None,
                instructions,
                ivm_triggers: Vec::new(),
                topology: Vec::new(),
            });
        self.transactions.splice(index..=index, replacements);
        Ok(())
    }
    /// Partition one explicitly selected instruction-only draft batch at authored boundaries.
    ///
    /// Every nonzero length describes one contiguous output batch. Their sum must
    /// equal the original instruction count, so values and order cannot change.
    /// All unselected transactions retain their exact boundaries. Apply this
    /// transformation before preparing or signing a generated manifest.
    ///
    /// # Errors
    ///
    /// Refuses an invalid index, zero or incomplete partitions, structured parameters,
    /// topology, IVM triggers, or noncanonical explicit `SetParameter` instructions.
    pub fn partition_instruction_only_transaction(
        mut self,
        index: usize,
        lengths: &[usize],
    ) -> Result<Self> {
        Self::reject_set_parameter_instructions(&self.transactions)?;
        let transaction = self.transactions.get(index).ok_or_else(|| {
            eyre!(
                "raw genesis transaction index {index} is out of bounds for {} transactions",
                self.transactions.len()
            )
        })?;
        if transaction.parameters.is_some()
            || !transaction.topology.is_empty()
            || !transaction.ivm_triggers.is_empty()
        {
            return Err(eyre!(
                "raw genesis transaction {index} is not instruction-only; refusing to partition parameters, IVM triggers, or topology"
            ));
        }
        let total = lengths
            .iter()
            .try_fold(0_usize, |total, length| total.checked_add(*length));
        if lengths.is_empty()
            || lengths.contains(&0)
            || total != Some(transaction.instructions.len())
        {
            return Err(eyre!(
                "raw genesis transaction {index} partition must preserve its exact {} instructions in nonempty batches",
                transaction.instructions.len()
            ));
        }
        let mut instructions = self.transactions.remove(index).instructions.into_iter();
        let replacements = lengths.iter().map(|length| RawGenesisTx {
            instructions: instructions.by_ref().take(*length).collect(),
            ..RawGenesisTx::default()
        });
        self.transactions.splice(index..index, replacements);
        Ok(self)
    }
    /// Remove topology entries from all transactions.
    #[must_use]
    pub fn clear_topology(mut self) -> Self {
        for tx in &mut self.transactions {
            tx.topology.clear();
        }
        self
    }
    /// Consensus mode advertised in the manifest.
    ///
    #[must_use]
    pub fn consensus_mode(&self) -> iroha_data_model::parameter::system::SumeragiConsensusMode {
        self.consensus_mode
    }
    /// Return a copy of the manifest with `consensus_mode` populated for handshake metadata.
    #[must_use]
    pub fn with_consensus_mode(
        mut self,
        mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    ) -> Self {
        self.consensus_mode = mode;
        self
    }
    /// Optional typed consensus fingerprint advertised in the manifest.
    #[must_use]
    pub const fn consensus_fingerprint(&self) -> Option<ConsensusFingerprint> {
        self.consensus_fingerprint
    }
    /// First-release consensus wire protocol version advertised in the manifest.
    #[must_use]
    pub const fn wire_protocol_version(&self) -> u32 {
        self.wire_protocol_version
    }
    /// Cryptography configuration snapshot advertised in the manifest.
    #[must_use]
    pub fn crypto(&self) -> &ManifestCrypto {
        &self.crypto
    }
}
#[cfg(test)]
#[path = "genesis_manifest_tests.rs"]
mod tests2;
impl RawGenesisTransaction {
    fn resolve_paths_relative_to(mut self, here: &Path) -> Self {
        if let Some(executor) = &mut self.executor {
            executor.resolve(here);
        }
        self.ivm_dir.resolve(here);
        for tx in &mut self.transactions {
            tx.ivm_triggers
                .iter_mut()
                .for_each(|trigger| trigger.action.executable.resolve(&self.ivm_dir.0));
        }
        self
    }

    /// Construct [`RawGenesisTransaction`] from JSON bytes while resolving relative paths as if
    /// the bytes had been read from `json_path`.
    ///
    /// This is the in-memory counterpart of [`Self::from_path`]. Admission tooling which has
    /// already read and hashed a manifest can therefore reproduce the signer's path semantics
    /// without reopening or rewriting the source file.
    ///
    /// # Errors
    ///
    /// - `json_path` has no parent directory
    /// - deserialization failed
    pub fn from_json_slice_at_path(json: &[u8], json_path: impl AsRef<Path>) -> Result<Self> {
        let json_path = json_path.as_ref();
        let here = json_path
            .parent()
            .ok_or_else(|| eyre!("json file should be in some directory"))?;
        let value = Self::from_json_slice(json).map_err(|err| {
            eyre!(
                "failed to deserialize raw genesis transaction for {}: {err}",
                json_path.display()
            )
        })?;
        Ok(value.resolve_paths_relative_to(here))
    }

    /// Iterate over all instructions contained in this manifest.
    #[must_use]
    pub fn instructions(&self) -> impl Iterator<Item = &InstructionBox> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.instructions.iter())
    }
    /// Return the exact Sumeragi context parameters selected by this manifest.
    #[must_use]
    pub fn sumeragi_context_parameters(&self) -> SumeragiGenesisContextParameters {
        self.sumeragi_context.clone()
    }
    /// Replace the Sumeragi context parameters that will be fingerprinted
    /// and signed with this manifest.
    #[must_use]
    pub fn with_sumeragi_context_parameters(
        mut self,
        parameters: SumeragiGenesisContextParameters,
    ) -> Self {
        self.sumeragi_context = parameters;
        self
    }
    /// Construct [`RawGenesisTransaction`] from a json file at `json_path`,
    /// resolving relative paths to `json_path`.
    ///
    /// # Errors
    ///
    /// - file not found
    /// - metadata access to the file failed
    /// - the path is not a stable direct regular file or exceeds the first-release byte limit
    /// - deserialization failed
    pub fn from_path(json_path: impl AsRef<Path>) -> Result<Self> {
        let contents = bounded_manifest::read_genesis_manifest_bytes(json_path.as_ref())
            .wrap_err_with(|| {
                eyre!(
                    "failed to read bounded genesis at {}",
                    json_path.as_ref().display()
                )
            })?;
        Self::from_json_slice_at_path(&contents, json_path)
    }
    /// Revert to builder to add modifications.
    pub fn into_builder(self) -> GenesisBuilder {
        let block_cadence_ms = self
            .transactions
            .iter()
            .find_map(|tx| {
                tx.parameters
                    .as_ref()
                    .map(|parameters| parameters.sumeragi.block_cadence_ms)
            })
            .unwrap_or_else(|| Parameters::default().sumeragi.block_cadence_ms);
        let transactions = self
            .transactions
            .into_iter()
            .map(|tx| GenesisTxBuilder {
                parameters: tx
                    .parameters
                    .map_or(Vec::new(), |p| p.parameters().collect()),
                instructions: tx.instructions,
                ivm_triggers: tx.ivm_triggers,
                topology: tx.topology,
            })
            .collect();
        GenesisBuilder {
            chain: self.chain,
            executor: self.executor,
            ivm_dir: self.ivm_dir.0,
            transactions,
            crypto: self.crypto,
            da_proof_policies: None,
            block_cadence_ms,
            consensus_mode: self.consensus_mode,
            wire_protocol_version: self.wire_protocol_version,
            consensus_fingerprint: self.consensus_fingerprint,
            sumeragi_context: Some(self.sumeragi_context),
        }
    }
    /// Build and sign a resultless genesis proposal.
    ///
    /// # Errors
    ///
    /// Fails if `RawGenesisTransaction::parse` fails or the transaction and
    /// block timestamps cannot be represented in `u64` milliseconds.
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisBlock> {
        self.build_and_sign_with_da_proof_policies(genesis_key_pair, None)
    }
    /// Build and sign a resultless genesis proposal with an explicit confidential policy hash.
    ///
    /// This does not derive the hash from the manifest. Callers that know the
    /// runtime confidential policy must compute it before signing, so the signed genesis
    /// header commits to the same policy that validators will enforce.
    ///
    /// # Errors
    ///
    /// Fails if the system clock is invalid, the genesis topology is not an exact
    /// supported committee, or [`RawGenesisTransaction::parse`] fails.
    pub fn build_and_sign_with_confidential_policy_hash(
        self,
        genesis_key_pair: &KeyPair,
        confidential_policy_hash: Option<[u8; 32]>,
    ) -> Result<GenesisBlock> {
        self.build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            genesis_key_pair,
            None,
            confidential_policy_hash,
        )
    }
    /// Build and sign a resultless genesis proposal, overriding the embedded DA proof policies.
    ///
    /// # Errors
    ///
    /// Fails if `RawGenesisTransaction::parse` fails.
    pub fn build_and_sign_with_da_proof_policies(
        self,
        genesis_key_pair: &KeyPair,
        da_proof_policies: Option<DaProofPolicyBundle>,
    ) -> Result<GenesisBlock> {
        self.build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            genesis_key_pair,
            da_proof_policies,
            None,
        )
    }
    /// Build and sign a resultless genesis proposal, overriding DA proof policies and the confidential policy hash.
    ///
    /// # Errors
    ///
    /// Fails if `RawGenesisTransaction::parse` fails.
    pub fn build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
        self,
        genesis_key_pair: &KeyPair,
        da_proof_policies: Option<DaProofPolicyBundle>,
        confidential_policy_hash: Option<[u8; 32]>,
    ) -> Result<GenesisBlock> {
        let genesis_creation_base_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .wrap_err("system clock is before UNIX_EPOCH")?
            .as_millis()
            .try_into()
            .wrap_err("current UNIX timestamp does not fit into u64 milliseconds")?;
        self.build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            genesis_key_pair,
            da_proof_policies,
            confidential_policy_hash,
            genesis_creation_base_ms,
        )
    }
    /// Build and sign a resultless genesis proposal with explicit DA/confidential policy commitments and a deterministic transaction creation-time base.
    ///
    /// Transaction `i` receives `creation_time_base_ms + i`; the genesis block
    /// timestamp remains one millisecond after the final transaction.
    ///
    /// # Errors
    ///
    /// Fails if the genesis topology is not an exact supported committee,
    /// [`RawGenesisTransaction::parse`] fails, or the transaction and block
    /// timestamps cannot be represented in `u64` milliseconds.
    pub fn build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
        self,
        genesis_key_pair: &KeyPair,
        da_proof_policies: Option<DaProofPolicyBundle>,
        confidential_policy_hash: Option<[u8; 32]>,
        creation_time_base_ms: u64,
    ) -> Result<GenesisBlock> {
        self.validate_genesis_topology()?;
        let genesis_account = AccountId::new(genesis_key_pair.public_key().clone());
        let instruction_batches = self.parse()?;
        let timestamp_span = u64::try_from(instruction_batches.len())
            .wrap_err("genesis transaction count does not fit into u64")?;
        creation_time_base_ms
            .checked_add(timestamp_span)
            .ok_or_else(|| {
                eyre!(
                    "genesis creation-time base {creation_time_base_ms} cannot represent \
                     {} transactions and the block timestamp",
                    instruction_batches.len()
                )
            })?;
        let mut transactions = Vec::new();
        for (tx_index, instructions) in instruction_batches.into_iter().enumerate() {
            #[cfg(debug_assertions)]
            if norito::debug_trace_enabled() {
                let encoded = norito::codec::encode_adaptive(&instructions);
                eprintln!(
                    "GenesisBuilder::build_and_sign: instructions batch len={} encoded_bytes={}",
                    instructions.len(),
                    encoded.len()
                );
            }
            let tx_index =
                u64::try_from(tx_index).expect("genesis transaction count validated above");
            let mut builder = TransactionBuilder::new_genesis(
                genesis_account.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .with_metadata(genesis_transaction_metadata(tx_index)?);
            builder.set_creation_time(Duration::from_millis(
                creation_time_base_ms
                    .checked_add(tx_index)
                    .expect("genesis timestamp span validated above"),
            ));
            let transaction = builder
                .try_sign(genesis_key_pair.private_key())
                .wrap_err_with(|| format!("failed to sign genesis transaction batch {tx_index}"))?;
            transactions.push(transaction);
        }
        let confidential_digest = ConfidentialFeatureDigest::new(
            None,
            None,
            None,
            Some(RULES_VERSION),
            Some(confidential_policy_hash.unwrap_or(DEFAULT_GENESIS_CONFIDENTIAL_POLICY_HASH)),
        );
        let block = SignedBlock::try_genesis_with_da_proof_policies(
            transactions,
            genesis_key_pair.private_key(),
            Some(confidential_digest),
            None,
            da_proof_policies,
        )
        .wrap_err("failed to sign genesis block")?;
        Ok(GenesisBlock(block))
    }
    /// Parse [`RawGenesisTransaction`] to the list of source instructions of the genesis transactions
    ///
    /// # Errors
    ///
    /// Fails if `self.executor` path fails to load [`Executor`].
    #[allow(clippy::too_many_lines)]
    pub fn parse(self) -> Result<Vec<Vec<InstructionBox>>> {
        self.validate_mode_specific_consensus_parameters()?;
        // Always recompute generated fields for the live Sumeragi protocol,
        // so stale or externally injected handshake metadata cannot survive
        // into the signed genesis block.
        let manifest = self.with_consensus_meta()?;
        manifest
            .crypto
            .validate()
            .map_err(|err| eyre!("invalid crypto configuration in genesis manifest: {err}"))?;
        let block_cadence_ms = manifest.effective_parameters()?.sumeragi.block_cadence_ms;
        let RawGenesisTransaction {
            chain: _,
            chain_discriminant: _,
            executor,
            ivm_dir: _,
            mut transactions,
            consensus_mode,
            wire_protocol_version,
            consensus_fingerprint,
            sumeragi_context,
            crypto: _,
        } = manifest;
        for tx in &mut transactions {
            tx.instructions
                .retain(|instruction| !is_consensus_handshake_metadata_instruction(instruction));
            if let Some(parameters) = &mut tx.parameters {
                let filtered_parameters = parameters
                    .parameters()
                    .filter(|parameter| {
                        !matches!(
                            parameter,
                            Parameter::Custom(custom)
                                if custom.id() == &consensus_metadata::handshake_meta_id()
                        )
                    })
                    .collect::<Vec<_>>();
                *parameters = Parameters::from_iter(filtered_parameters);
            }
        }
        let meta_vec = Self::build_consensus_meta_instructions(
            consensus_mode,
            block_cadence_ms,
            wire_protocol_version,
            consensus_fingerprint,
            sumeragi_context,
        )?;
        let mut pending_meta = if meta_vec.is_empty() {
            None
        } else {
            Some(meta_vec)
        };
        let mut instructions_list = Vec::new();
        let mut ivm_bytecode_total = 0_usize;
        if let Some(executor_path) = executor {
            let executor = load_genesis_ivm_bytecode(&executor_path, &mut ivm_bytecode_total)?;
            let upgrade_executor = Upgrade::new(Executor::new(executor)).into();
            instructions_list.push(vec![upgrade_executor]);
        }
        for tx in transactions {
            let mut instructions = Vec::new();
            if let Some(parameters) = tx.parameters {
                let generated = collect_parameter_instructions(&parameters);
                instructions.extend(generated);
            }
            if !tx.instructions.is_empty() {
                instructions.extend(tx.instructions);
            }
            for trigger in tx.ivm_triggers {
                let trigger = trigger.try_into_with_ivm_bytecode_budget(&mut ivm_bytecode_total)?;
                instructions.push(Register::trigger(trigger).into());
            }
            if !tx.topology.is_empty() {
                let mut seen = BTreeSet::new();
                for entry in tx.topology {
                    let pk = entry.peer.public_key().clone();
                    if !seen.insert(pk.clone()) {
                        return Err(eyre!("duplicate `topology` entry for peer {pk}"));
                    }
                    let pop = entry.pop_bytes()?.ok_or_else(|| {
                        eyre!(
                            "missing `pop_hex` entry for topology peer {}",
                            entry.peer.public_key()
                        )
                    })?;
                    let register = RegisterPeerWithPop::new(entry.peer, pop);
                    instructions.push(InstructionBox::from(register));
                }
            }
            if let Some(meta) = pending_meta.take() {
                if instructions.is_empty() {
                    instructions = meta;
                } else {
                    instructions_list.push(instructions);
                    instructions_list.push(meta);
                    continue;
                }
            }
            if !instructions.is_empty() {
                instructions_list.push(instructions);
            }
        }
        if let Some(meta) = pending_meta
            && !meta.is_empty()
        {
            instructions_list.push(meta);
        }
        let generated_tail = instructions_list.len();
        Self::inject_crypto_manifest_param(&mut instructions_list, &manifest.crypto)?;
        let registry = GenesisVkRegistry::build(instructions_list.iter().flatten())?;
        Self::inject_confidential_registry_param(&mut instructions_list, registry.vk_set_hash());
        // These two generated global parameters share one canonical metadata owner.
        // Authored instruction, trigger, and topology batches are never repacked.
        if instructions_list.len() == generated_tail + 2 {
            let confidential = instructions_list
                .pop()
                .expect("generated confidential metadata");
            instructions_list
                .last_mut()
                .expect("generated crypto metadata")
                .extend(confidential);
        }
        validate_genesis_batch_limit(
            &instructions_list,
            usize::try_from(
                iroha_data_model::parameter::FastpqSourcePolicyV1::BOOTSTRAP_NETWORK_INPUTS,
            )
            .expect("the bootstrap input count fits usize"),
        )?;
        Ok(instructions_list)
    }

    fn inject_confidential_registry_param(
        instructions_list: &mut Vec<Vec<InstructionBox>>,
        vk_set_hash: Option<[u8; 32]>,
    ) {
        let already_present = instructions_list.iter().flatten().any(|instr| {
            instr
                .as_any()
                .downcast_ref::<SetParameter>()
                .and_then(|set| {
                    if let Parameter::Custom(custom) = set.inner() {
                        (custom.id() == &confidential_metadata::registry_root_id()).then_some(())
                    } else {
                        None
                    }
                })
                .is_some()
        });
        if already_present {
            return;
        }
        let mut meta_fields = norito::json::Map::new();
        let hash_field = vk_set_hash.map_or(norito::json::Value::Null, |hash| {
            let encoded = format!("0x{}", hex::encode(hash));
            norito::json::Value::String(encoded)
        });
        meta_fields.insert("vk_set_hash".to_string(), hash_field);
        let meta_value = norito::json::Value::Object(meta_fields);
        let param = Parameter::Custom(CustomParameter::new(
            confidential_metadata::registry_root_id(),
            Json::new(meta_value),
        ));
        instructions_list.push(vec![InstructionBox::from(SetParameter::new(param))]);
    }
    fn inject_crypto_manifest_param(
        instructions_list: &mut Vec<Vec<InstructionBox>>,
        crypto: &ManifestCrypto,
    ) -> eyre::Result<()> {
        let meta_id = crypto_metadata::manifest_meta_id();
        let ensure_matches = |existing: &CustomParameter| -> eyre::Result<()> {
            let observed: ManifestCrypto = existing
                .payload()
                .try_into_any()
                .map_err(|err| eyre!("failed to decode crypto manifest payload: {err}"))?;
            if &observed != crypto {
                return Err(eyre!(
                    "crypto manifest payload in genesis differs from advertised `crypto` block"
                ));
            }
            Ok(())
        };
        for existing in instructions_list
            .iter()
            .flatten()
            .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
        {
            if let Parameter::Custom(custom) = existing.inner()
                && custom.id() == &meta_id
            {
                return ensure_matches(custom);
            }
        }
        let mut payload_map = norito::json::Map::new();
        payload_map.insert(
            "sm_openssl_preview".to_string(),
            norito::json::Value::Bool(crypto.sm_openssl_preview),
        );
        payload_map.insert(
            "default_hash".to_string(),
            norito::json::Value::String(crypto.default_hash.clone()),
        );
        payload_map.insert(
            "sm2_distid_default".to_string(),
            norito::json::Value::String(crypto.sm2_distid_default.clone()),
        );
        payload_map.insert(
            "allowed_curve_ids".to_string(),
            norito::json::Value::Array(
                crypto
                    .allowed_curve_ids
                    .iter()
                    .copied()
                    .map(|n| norito::json::Value::Number(u64::from(n).into()))
                    .collect(),
            ),
        );
        payload_map.insert(
            "allowed_signing".to_string(),
            norito::json::Value::Array(
                crypto
                    .allowed_signing
                    .iter()
                    .map(|algo| norito::json::Value::String(algo.as_static_str().to_string()))
                    .collect(),
            ),
        );
        let payload = norito::json::Value::Object(payload_map);
        let param = Parameter::Custom(CustomParameter::new(meta_id, Json::new(payload)));
        instructions_list.push(vec![InstructionBox::from(SetParameter::new(param))]);
        Ok(())
    }
    fn build_consensus_meta_instructions(
        consensus_mode: SumeragiConsensusMode,
        block_cadence_ms: NonZeroU64,
        wire_protocol_version: u32,
        consensus_fingerprint: Option<ConsensusFingerprint>,
        sumeragi_context: SumeragiGenesisContextParameters,
    ) -> Result<Vec<InstructionBox>> {
        let mut instructions = Vec::new();
        let fingerprint = consensus_fingerprint.ok_or_else(|| {
            eyre!(
                "genesis manifest missing `consensus_fingerprint`; call `with_consensus_meta` before signing"
            )
        })?;
        let metadata = ConsensusHandshakeMetadata {
            mode: consensus_mode,
            block_cadence_ms,
            wire_protocol_version,
            consensus_fingerprint: fingerprint,
            sumeragi_context,
        };
        metadata
            .validate()
            .map_err(|error| eyre!("invalid signed consensus handshake metadata: {error}"))?;
        let meta_value = norito::json::value::to_value(&metadata)
            .expect("serialize consensus handshake metadata to JSON");
        let handshake_payload = Json::from_norito_value_ref(&meta_value)
            .expect("handshake metadata JSON must serialize");
        let handshake_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            handshake_payload,
        ));
        instructions.push(InstructionBox::from(SetParameter::new(handshake_param)));
        Ok(instructions)
    }
}
impl norito::json::JsonDeserialize for RawGenesisTransaction {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = norito::json::Value::json_deserialize(parser)?;
        Self::from_json_value(value)
    }
}
/// Builder to build [`RawGenesisTransaction`] and [`GenesisBlock`].
/// No guarantee of validity of the built genesis transactions and block.
#[must_use]
pub struct GenesisBuilder {
    chain: ChainId,
    executor: Option<IvmPath>,
    ivm_dir: PathBuf,
    transactions: Vec<GenesisTxBuilder>,
    crypto: ManifestCrypto,
    da_proof_policies: Option<DaProofPolicyBundle>,
    block_cadence_ms: NonZeroU64,
    consensus_mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    wire_protocol_version: u32,
    consensus_fingerprint: Option<ConsensusFingerprint>,
    sumeragi_context: Option<SumeragiGenesisContextParameters>,
}
/// Domain editing mode of the [`GenesisBuilder`] to register accounts and assets under the domain.
#[must_use]
pub struct GenesisDomainBuilder {
    chain: ChainId,
    executor: Option<IvmPath>,
    ivm_dir: PathBuf,
    transactions: Vec<GenesisTxBuilder>,
    domain_id: DomainId,
    crypto: ManifestCrypto,
    da_proof_policies: Option<DaProofPolicyBundle>,
    block_cadence_ms: NonZeroU64,
    consensus_mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    wire_protocol_version: u32,
    consensus_fingerprint: Option<ConsensusFingerprint>,
    sumeragi_context: Option<SumeragiGenesisContextParameters>,
}
#[derive(Default)]
struct GenesisTxBuilder {
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    ivm_triggers: Vec<GenesisIvmTrigger>,
    topology: Vec<GenesisTopologyEntry>,
}
impl GenesisBuilder {
    /// Construct [`GenesisBuilder`] with an executor upgrade.
    ///
    /// Before building, callers must provide the Sumeragi context through its
    /// dedicated setter.
    pub fn new(chain: ChainId, executor: impl Into<PathBuf>, ivm_dir: impl Into<PathBuf>) -> Self {
        Self {
            chain,
            executor: Some(executor.into().into()),
            ivm_dir: ivm_dir.into(),
            transactions: vec![GenesisTxBuilder::default()],
            crypto: ManifestCrypto::default(),
            da_proof_policies: None,
            block_cadence_ms: SumeragiParameters::default().block_cadence_ms,
            consensus_mode: SumeragiConsensusMode::Permissioned,
            wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
            consensus_fingerprint: None,
            sumeragi_context: None,
        }
    }
    /// Construct [`GenesisBuilder`] without an executor upgrade.
    ///
    /// Before building, callers must provide the Sumeragi context through its
    /// dedicated setter.
    pub fn new_without_executor(chain: ChainId, ivm_dir: impl Into<PathBuf>) -> Self {
        Self {
            chain,
            executor: None,
            ivm_dir: ivm_dir.into(),
            transactions: vec![GenesisTxBuilder::default()],
            crypto: ManifestCrypto::default(),
            da_proof_policies: None,
            block_cadence_ms: SumeragiParameters::default().block_cadence_ms,
            consensus_mode: SumeragiConsensusMode::Permissioned,
            wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
            consensus_fingerprint: None,
            sumeragi_context: None,
        }
    }
    /// Override the cryptography snapshot advertised alongside the manifest.
    pub fn with_crypto(mut self, crypto: ManifestCrypto) -> Self {
        self.crypto = crypto;
        self
    }
    /// Override the DA proof policy bundle embedded into genesis.
    pub fn with_da_proof_policies(mut self, policies: DaProofPolicyBundle) -> Self {
        self.da_proof_policies = Some(policies);
        self
    }
    /// Select the exact Sumeragi context parameters which will be embedded
    /// in and signed by genesis.
    #[must_use]
    pub fn with_sumeragi_context_parameters(
        mut self,
        parameters: SumeragiGenesisContextParameters,
    ) -> Self {
        self.sumeragi_context = Some(parameters);
        self
    }
    /// Select the signed immutable block cadence stored by genesis.
    #[must_use]
    pub fn with_block_cadence_ms(mut self, block_cadence_ms: NonZeroU64) -> Self {
        self.block_cadence_ms = block_cadence_ms;
        self
    }
    fn current_tx_mut(&mut self) -> &mut GenesisTxBuilder {
        self.transactions
            .last_mut()
            .expect("at least one transaction exists")
    }
    /// Entry a domain registration and transition to [`GenesisDomainBuilder`].
    pub fn domain(self, domain_id: DomainId) -> GenesisDomainBuilder {
        self.domain_with_metadata(domain_id, Metadata::default())
    }
    /// Same as [`GenesisBuilder::domain`], but attach a metadata to the domain.
    pub fn domain_with_metadata(
        mut self,
        domain_id: DomainId,
        metadata: Metadata,
    ) -> GenesisDomainBuilder {
        let new_domain = Domain::new(domain_id.clone()).with_metadata(metadata);
        self.current_tx_mut()
            .instructions
            .push(Register::domain(new_domain).into());
        GenesisDomainBuilder {
            chain: self.chain,
            executor: self.executor,
            ivm_dir: self.ivm_dir,
            transactions: self.transactions,
            domain_id,
            crypto: self.crypto,
            da_proof_policies: self.da_proof_policies,
            block_cadence_ms: self.block_cadence_ms,
            consensus_mode: self.consensus_mode,
            wire_protocol_version: self.wire_protocol_version,
            consensus_fingerprint: self.consensus_fingerprint,
            sumeragi_context: self.sumeragi_context,
        }
    }
    /// Append a parameter to the authoritative snapshot in the first transaction.
    ///
    /// [`Parameters`] is a complete snapshot rather than a transaction-local patch, so a
    /// genesis manifest must contain exactly one structured `parameters` block. Calling this
    /// method after [`Self::next_transaction`] still updates that first authoritative snapshot.
    pub fn append_parameter(mut self, parameter: Parameter) -> Self {
        self.transactions
            .first_mut()
            .expect("genesis builder always contains at least one transaction")
            .parameters
            .push(parameter);
        self
    }
    /// Append an instruction to the current transaction.
    ///
    /// Parameters have a dedicated authoritative snapshot and must be added with
    /// [`Self::append_parameter`].
    ///
    /// # Panics
    ///
    /// Panics if `instruction` is [`SetParameter`].
    pub fn append_instruction(mut self, instruction: impl Into<InstructionBox>) -> Self {
        let instruction = instruction.into();
        assert!(
            instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_none(),
            "GenesisBuilder::append_instruction does not accept SetParameter; use GenesisBuilder::append_parameter"
        );
        self.current_tx_mut().instructions.push(instruction);
        self
    }
    /// Overwrite the initial topology of the current transaction.
    pub fn set_topology<T: Into<GenesisTopologyEntry>>(mut self, topology: Vec<T>) -> Self {
        self.current_tx_mut().topology = topology.into_iter().map(Into::into).collect();
        self
    }
    /// Merge PoPs into the topology entries of the current transaction.
    ///
    /// # Panics
    ///
    /// Panics if the input contains duplicate peers or peers not present in the topology.
    #[cfg(test)]
    pub fn set_topology_pop(mut self, topology_pop: Vec<GenesisPeerPop>) -> Self {
        if topology_pop.is_empty() {
            return self;
        }
        let mut pop_map = BTreeMap::new();
        for GenesisPeerPop { public_key, pop } in topology_pop {
            assert!(
                !pop_map.contains_key(&public_key),
                "duplicate topology pop entry for peer {public_key}"
            );
            pop_map.insert(public_key, pop);
        }
        let tx = self.current_tx_mut();
        for entry in &mut tx.topology {
            if let Some(pop) = pop_map.remove(entry.peer.public_key()) {
                entry.pop_hex = Some(hex::encode(pop));
            }
        }
        if let Some(pk) = pop_map.keys().next() {
            panic!("topology pop entry provided for peer {pk} missing from topology");
        }
        self
    }
    /// Start a new empty transaction.
    pub fn next_transaction(mut self) -> Self {
        self.transactions.push(GenesisTxBuilder::default());
        self
    }
    /// Finish building, sign, and produce a resultless [`GenesisBlock`] proposal.
    ///
    /// # Errors
    ///
    /// Fails if internal [`RawGenesisTransaction::build_and_sign`] fails.
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisBlock> {
        let da_proof_policies = self.da_proof_policies.clone();
        self.build_raw()?
            .build_and_sign_with_da_proof_policies(genesis_key_pair, da_proof_policies)
    }
    /// Finish building, sign, and produce a resultless [`GenesisBlock`] proposal with a confidential policy hash.
    ///
    /// # Errors
    ///
    /// Fails if internal [`RawGenesisTransaction::build_and_sign_with_confidential_policy_hash`] fails.
    pub fn build_and_sign_with_confidential_policy_hash(
        self,
        genesis_key_pair: &KeyPair,
        confidential_policy_hash: Option<[u8; 32]>,
    ) -> Result<GenesisBlock> {
        let da_proof_policies = self.da_proof_policies.clone();
        self.build_raw()?
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
                genesis_key_pair,
                da_proof_policies,
                confidential_policy_hash,
            )
    }
    /// Finish building and produce a [`RawGenesisTransaction`].
    ///
    /// # Errors
    ///
    /// Fails unless the signed Sumeragi context parameters have been supplied.
    pub fn build_raw(self) -> Result<RawGenesisTransaction> {
        let mut parameter_snapshot = Parameters::default();
        let mut source_transactions = self.transactions;
        for tx in &mut source_transactions {
            for parameter in std::mem::take(&mut tx.parameters) {
                parameter_snapshot.set_parameter(parameter);
            }
        }
        parameter_snapshot.sumeragi.block_cadence_ms = self.block_cadence_ms;
        let mut transactions: Vec<_> = source_transactions
            .into_iter()
            .map(|tx| RawGenesisTx {
                parameters: None,
                instructions: tx.instructions,
                ivm_triggers: tx.ivm_triggers,
                topology: tx.topology,
            })
            .collect();
        let first = transactions
            .first_mut()
            .expect("genesis builder always contains at least one transaction");
        first.parameters = Some(parameter_snapshot);
        let sumeragi_context = self.sumeragi_context.ok_or_else(|| {
            eyre!("genesis builder requires explicit signed Sumeragi context parameters")
        })?;
        Ok(RawGenesisTransaction {
            chain: self.chain,
            chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
            executor: self.executor,
            ivm_dir: self.ivm_dir.into(),
            transactions,
            consensus_mode: self.consensus_mode,
            wire_protocol_version: self.wire_protocol_version,
            consensus_fingerprint: self.consensus_fingerprint,
            sumeragi_context,
            crypto: self.crypto,
        })
    }
}
impl GenesisDomainBuilder {
    /// Finish this domain and return to genesis block building.
    pub fn finish_domain(self) -> GenesisBuilder {
        GenesisBuilder {
            chain: self.chain,
            executor: self.executor,
            ivm_dir: self.ivm_dir,
            transactions: self.transactions,
            crypto: self.crypto,
            da_proof_policies: self.da_proof_policies,
            block_cadence_ms: self.block_cadence_ms,
            consensus_mode: self.consensus_mode,
            wire_protocol_version: self.wire_protocol_version,
            consensus_fingerprint: self.consensus_fingerprint,
            sumeragi_context: self.sumeragi_context,
        }
    }
    /// Add an account to this domain.
    pub fn account(self, signatory: PublicKey) -> Self {
        self.account_with_metadata(signatory, Metadata::default())
    }
    /// Add an account (having provided `metadata`) to this domain.
    pub fn account_with_metadata(mut self, signatory: PublicKey, metadata: Metadata) -> Self {
        let account_id = AccountId::new(signatory);
        let register = Register::account(Account::new(account_id.clone()).with_metadata(metadata));
        self.current_tx_mut().instructions.push(register.into());
        self
    }
    /// Add [`AssetDefinition`] to this domain.
    pub fn asset(mut self, asset_name: Name, asset_spec: NumericSpec) -> Self {
        let asset_display_name = asset_name.to_string();
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(self.domain_id.clone(), asset_name);
        let asset_definition = AssetDefinition::new(
            asset_definition_id,
            asset_display_name,
            asset_spec,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        );
        self.current_tx_mut()
            .instructions
            .push(Register::asset_definition(asset_definition).into());
        self
    }
    fn current_tx_mut(&mut self) -> &mut GenesisTxBuilder {
        self.transactions
            .last_mut()
            .expect("at least one transaction exists")
    }
}
// Manifest paths are String payload fields. Containing records own their frames;
// Norito's blanket bare Encode/Decode implementations require only payload codecs.
impl norito::core::SerializePayload for IvmPath {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let s = self.0.to_str().expect("path contains not valid UTF-8");
        norito::core::SerializePayload::serialize(&s, writer)
    }
}
impl<'a> norito::core::DeserializePayload<'a> for IvmPath {
    fn deserialize(archived: &'a norito::core::Archived<IvmPath>) -> Self {
        let s: String = norito::core::DeserializePayload::deserialize(archived.cast());
        IvmPath(PathBuf::from(s))
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<IvmPath>,
    ) -> Result<Self, norito::core::Error> {
        let s = <String as norito::core::DeserializePayload>::try_deserialize(archived.cast())?;
        Ok(IvmPath(PathBuf::from(s)))
    }
}
impl From<PathBuf> for IvmPath {
    fn from(value: PathBuf) -> Self {
        Self(value)
    }
}
impl TryFrom<IvmPath> for IvmBytecode {
    type Error = eyre::Report;
    fn try_from(value: IvmPath) -> Result<Self, Self::Error> {
        let mut total = 0;
        load_genesis_ivm_bytecode(&value, &mut total)
    }
}
fn checked_genesis_ivm_bytecode_total(current: usize, next: usize) -> Result<usize> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| eyre!("aggregate genesis IVM bytecode size overflow"))?;
    if total > GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1 {
        return Err(eyre!(
            "aggregate genesis IVM bytecode exceeds the {}-byte first-release limit",
            GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1
        ));
    }
    Ok(total)
}
fn load_genesis_ivm_bytecode(value: &IvmPath, total: &mut usize) -> Result<IvmBytecode> {
    let remaining = GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1
        .checked_sub(*total)
        .ok_or_else(|| {
            eyre!(
                "aggregate genesis IVM bytecode exceeds the {}-byte first-release limit",
                GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1
            )
        })?;
    let blob = bounded_manifest::read_genesis_ivm_bytecode(&value.0, remaining)
        .wrap_err_with(|| eyre!("failed to read bytecode from {}", value.0.display()))?;
    *total = checked_genesis_ivm_bytecode_total(*total, blob.len())?;
    Ok(IvmBytecode::from_compiled(blob))
}
impl IvmPath {
    /// Resolve `self` to `here/self`, assuming `self` is an unresolved relative path to `here`. In
    /// case `self` is absolute, it replaces `here` i.e. this method mutates nothing.
    fn resolve(&mut self, here: impl AsRef<Path>) {
        self.0 = here.as_ref().join(&self.0)
    }
}
impl norito::json::FastJsonWrite for IvmPath {
    fn write_json(&self, out: &mut String) {
        let value = self.0.to_str().expect("path contains not valid UTF-8");
        norito::json::JsonSerialize::json_serialize(value, out);
    }
}
impl norito::json::JsonDeserialize for IvmPath {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let raw = parser.parse_string()?;
        Ok(Self(PathBuf::from(raw)))
    }
}
/// Human-readable alternative to [`Trigger`] whose action executes IVM
/// bytecode instead of a native instruction sequence.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize, IntoSchema, Encode, Decode, Constructor)]
#[norito(decode_from_slice)]
pub struct GenesisIvmTrigger {
    /// Unique trigger identifier.
    id: TriggerId,
    /// Action describing executable, repeats, authority and filter.
    action: GenesisIvmAction,
}
/// Human-readable alternative to [`Action`] which contains IVM bytecode as the executable payload.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize, IntoSchema, Encode, Decode)]
#[norito(decode_from_slice)]
pub struct GenesisIvmAction {
    /// Path to the compiled IVM bytecode (`.to`) file.
    executable: IvmPath,
    /// Trigger repetition policy.
    repeats: Repeats,
    /// Account authorized to trigger execution.
    authority: AccountId,
    /// Event filter selecting which events cause the trigger to fire.
    filter: EventFilterBox,
}
impl GenesisIvmAction {
    /// Construct [`GenesisIvmAction`]
    pub fn new(
        executable: impl Into<PathBuf>,
        repeats: impl Into<Repeats>,
        authority: AccountId,
        filter: impl Into<EventFilterBox>,
    ) -> Self {
        Self {
            executable: executable.into().into(),
            repeats: repeats.into(),
            authority,
            filter: filter.into(),
        }
    }
    fn try_into_with_ivm_bytecode_budget(self, total: &mut usize) -> Result<Action> {
        Action::new(
            load_genesis_ivm_bytecode(&self.executable, total)?,
            self.repeats,
            self.authority,
            self.filter,
        )
        .map_err(Into::into)
    }
}
impl GenesisIvmTrigger {
    fn try_into_with_ivm_bytecode_budget(self, total: &mut usize) -> Result<Trigger> {
        Ok(Trigger::new(
            self.id,
            self.action.try_into_with_ivm_bytecode_budget(total)?,
        ))
    }
}
impl TryFrom<GenesisIvmTrigger> for Trigger {
    type Error = eyre::Report;
    fn try_from(value: GenesisIvmTrigger) -> Result<Self, Self::Error> {
        let mut total = 0;
        value.try_into_with_ivm_bytecode_budget(&mut total)
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for IvmPath {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (path, used) = <String as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((Self(PathBuf::from(path)), used))
    }
}
impl TryFrom<GenesisIvmAction> for Action {
    type Error = eyre::Report;
    fn try_from(value: GenesisIvmAction) -> Result<Self, Self::Error> {
        let mut total = 0;
        value.try_into_with_ivm_bytecode_budget(&mut total)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn instruction_transaction_append_preserves_every_original_manifest_field() -> Result<()> {
        init_instruction_registry();
        let mut original = GenesisBuilder::new_without_executor(
            ChainId::from("instruction-append"),
            PathBuf::from("."),
        )
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .build_raw()?;
        original = original.with_chain_discriminant(1337);
        let before = norito::json::to_value(&original)?;
        let appended = original.append_instruction_transaction(Log::new(
            iroha_data_model::level::Level::INFO,
            "explicit appended transaction".into(),
        ))?;
        let mut after = norito::json::to_value(&appended)?;
        let transactions = after
            .as_object_mut()
            .unwrap()
            .get_mut("transactions")
            .unwrap();
        let transactions = transactions.as_array_mut().unwrap();
        let new = transactions.pop().unwrap();
        assert_eq!(
            transactions.len(),
            before
                .get("transactions")
                .unwrap()
                .as_array()
                .unwrap()
                .len()
        );
        assert_eq!(after, before, "only the appended transaction may differ");
        assert!(new.get("parameters").is_none());
        assert_eq!(new.get("topology").unwrap().as_array().unwrap().len(), 0);
        assert_eq!(
            new.get("ivm_triggers").unwrap().as_array().unwrap().len(),
            0
        );
        assert_eq!(
            new.get("instructions").unwrap().as_array().unwrap().len(),
            1
        );
        assert_eq!(appended.chain_discriminant(), 1337);
        Ok(())
    }

    #[test]
    fn instruction_transaction_append_refuses_parameter_layout_migration() -> Result<()> {
        let original = GenesisBuilder::new_without_executor(
            ChainId::from("instruction-append"),
            PathBuf::from("."),
        )
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .build_raw()?;
        let error = original
            .append_instruction_transaction(SetParameter::new(Parameter::Block(
                iroha_data_model::parameter::BlockParameter::MaxTransactions(
                    core::num::NonZeroU64::new(99).unwrap(),
                ),
            )))
            .unwrap_err();
        assert!(error.to_string().contains("structured parameter snapshot"));
        Ok(())
    }

    use super::*;
    use eyre::Result;
    use iroha_data_model::{
        block::SignedBlock,
        isi::SetParameter,
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, confidential_metadata, consensus_metadata},
        },
        transaction::Executable,
    };
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_KEYPAIR, BOB_KEYPAIR};
    use iroha_version::codec::EncodeVersioned;
    use tempfile::TempDir;

    impl GenesisBuilder {
        fn build_raw_for_test(self) -> RawGenesisTransaction {
            self.with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
                .build_raw()
                .expect("complete deterministic test genesis builder")
        }
    }
    fn with_test_signing_topology(mut manifest: RawGenesisTransaction) -> RawGenesisTransaction {
        manifest
            .transactions
            .first_mut()
            .expect("test genesis manifest has one transaction")
            .topology = deterministic_test_genesis_topology_entries();
        manifest
    }

    fn configured_execution_policy_for_test() -> Parameters {
        use std::num::{NonZeroU16, NonZeroU64};
        let mut parameters = Parameters::default();
        parameters.transaction.max_signatures = NonZeroU64::new(3).unwrap();
        parameters.transaction.max_instructions = NonZeroU64::new(5).unwrap();
        parameters.transaction.ivm_bytecode_size = NonZeroU64::new(65_536).unwrap();
        parameters.transaction.max_tx_bytes = NonZeroU64::new(524_288).unwrap();
        parameters.transaction.max_decompressed_bytes = NonZeroU64::new(1_048_576).unwrap();
        parameters.transaction.max_metadata_depth = NonZeroU16::new(3).unwrap();
        parameters.transaction.max_time_to_live_ms = NonZeroU64::new(1_000).unwrap();
        parameters.transaction.require_height_ttl = true;
        parameters.transaction.require_sequence = true;
        parameters.executor.fuel = NonZeroU64::new(1_000).unwrap();
        parameters.executor.memory = NonZeroU64::new(2_097_152).unwrap();
        parameters.executor.execution_depth = 4;
        parameters.executor.max_output_items = NonZeroU64::new(2).unwrap();
        parameters.executor.max_output_bytes = NonZeroU64::new(16_384).unwrap();
        parameters.smart_contract.fuel = NonZeroU64::new(2_000).unwrap();
        parameters.smart_contract.memory = NonZeroU64::new(4_194_304).unwrap();
        parameters.smart_contract.execution_depth = 3;
        parameters.smart_contract.max_output_items = NonZeroU64::new(4).unwrap();
        parameters.smart_contract.max_output_bytes = NonZeroU64::new(32_768).unwrap();
        parameters
    }

    #[test]
    fn complete_parameter_instructions_retain_every_admission_and_execution_slot() {
        let expected = configured_execution_policy_for_test();
        let original_slots = expected.parameters().collect::<Vec<_>>();
        let instructions = collect_parameter_instructions(&expected);
        let actual_slots = instructions
            .iter()
            .map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetParameter>()
                    .expect("every policy slot is its typed SetParameter")
                    .inner()
                    .clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_slots, original_slots);
        for (index, slot) in actual_slots.iter().enumerate() {
            assert!(
                actual_slots[..index]
                    .iter()
                    .all(|previous| !parameter_targets_same_slot(previous, slot)),
                "every authoritative slot is emitted exactly once"
            );
        }
        assert_eq!(Parameters::from_iter(actual_slots), expected);
    }

    #[test]
    fn signed_genesis_retains_complete_configured_execution_policy() -> Result<()> {
        init_instruction_registry();
        let expected = configured_execution_policy_for_test();
        let manifest = with_test_signing_topology(
            expected
                .parameters()
                .fold(
                    GenesisBuilder::new_without_executor(
                        ChainId::from("genesis-complete-execution-policy"),
                        ".",
                    ),
                    GenesisBuilder::append_parameter,
                )
                .build_raw_for_test(),
        )
        .with_consensus_meta()?;
        assert_eq!(manifest.effective_parameters()?, expected);
        let key = KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519);
        let block = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &key, None, None, 1_000,
            )?
            .0;
        let signed_slots = block
            .external_transactions()
            .flat_map(|transaction| match transaction.instructions() {
                Executable::Instructions(instructions) => instructions.iter(),
                _ => panic!("genesis policy must use its signed instruction batches"),
            })
            .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
            .map(|instruction| instruction.inner().clone())
            .collect::<Vec<_>>();
        for original in expected.parameters() {
            assert_eq!(
                signed_slots
                    .iter()
                    .filter(|slot| **slot == original)
                    .count(),
                1,
                "the signed body must retain the exact authoritative parameter {original:?}"
            );
        }
        validate_prepared_genesis_bundle(
            &block.encode_wire()?,
            &manifest,
            key.public_key(),
            block.hash(),
        )?;
        Ok(())
    }

    #[test]
    fn signed_genesis_batches_have_canonical_expiry_and_increasing_sequences() -> Result<()> {
        init_instruction_registry();
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let manifest = with_test_signing_topology(
            GenesisBuilder::new_without_executor(ChainId::from("genesis-ingress-policy"), ".")
                .append_parameter(Parameter::Transaction(
                    iroha_data_model::parameter::system::TransactionParameter::RequireHeightTtl(
                        true,
                    ),
                ))
                .append_parameter(Parameter::Transaction(
                    iroha_data_model::parameter::system::TransactionParameter::RequireSequence(
                        true,
                    ),
                ))
                .build_raw_for_test(),
        )
        .with_consensus_meta()?;
        let effective = manifest.effective_parameters()?;
        assert!(effective.transaction.require_height_ttl);
        assert!(effective.transaction.require_sequence);
        let block = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &key, None, None, 1_000,
            )?
            .0;
        assert!(block.external_transactions().len() > 1);
        for (index, transaction) in block.external_transactions().enumerate() {
            assert_eq!(transaction.expires_at_height()?, Some(2));
            assert_eq!(transaction.tx_sequence()?, Some(index as u64 + 1));
            assert_eq!(transaction.metadata().iter().len(), 2);
        }
        validate_prepared_genesis_bundle(
            &block.encode_wire()?,
            &manifest,
            key.public_key(),
            block.hash(),
        )?;
        assert!(genesis_transaction_metadata(u64::MAX).is_err());
        Ok(())
    }

    fn load_genesis_source_template_for_test(relative_path: &str) -> Result<RawGenesisTransaction> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
        GenesisSourceTemplate::from_path(path)?.materialize(Some(
            SumeragiNposParameters::default().xor_asset_definition_id,
        ))
    }

    #[test]
    fn source_template_materialization_requires_explicit_xor_selection() -> Result<()> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/genesis.template.json");
        let unbound = RawGenesisTransaction::from_path(&path)?;
        assert_eq!(unbound.consensus_fingerprint(), None);
        assert!(
            unbound
                .validate_mode_specific_consensus_parameters()
                .is_err()
        );
        let template = GenesisSourceTemplate::from_path(&path)?;
        let is_npos = template
            .value
            .get("consensus_mode")
            .and_then(norito::json::Value::as_str)
            == Some("Npos");
        let wrong = if is_npos {
            None
        } else {
            Some(SumeragiNposParameters::default().xor_asset_definition_id)
        };
        assert!(template.clone().materialize(wrong).is_err());
        let selected = is_npos.then(|| SumeragiNposParameters::default().xor_asset_definition_id);
        let materialized = template.materialize(selected)?;
        assert!(materialized.consensus_fingerprint().is_some());
        Ok(())
    }

    #[test]
    fn direct_signing_rejects_a_non_committee_topology() {
        let genesis_key_pair = checked_genesis_fixture_keypair();
        let mut topology = deterministic_test_genesis_topology_entries();
        topology.pop();
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("invalid-genesis-topology"),
            PathBuf::from("."),
        )
        .set_topology(topology)
        .build_raw_for_test();
        let error = manifest
            .build_and_sign(&genesis_key_pair)
            .expect_err("genesis signing rejects a non-3f+1 topology");
        assert!(
            error
                .to_string()
                .contains("exact Sumeragi `3f + 1` topology")
        );
    }

    #[test]
    fn direct_signing_validates_each_topology_proof_of_possession() {
        let topology = deterministic_test_genesis_topology_entries();
        let make_manifest = |topology| {
            GenesisBuilder::new_without_executor(
                ChainId::from("genesis-topology-pop-verification"),
                PathBuf::from("."),
            )
            .set_topology(topology)
            .build_raw_for_test()
        };
        let valid = make_manifest(topology.clone());
        valid
            .validate_genesis_topology()
            .expect("valid BLS proofs bind every unique validator");
        valid
            .build_and_sign(&checked_genesis_fixture_keypair())
            .expect("a valid committee remains signable");

        for (label, pop_hex, expected_error) in [
            ("missing", None, "missing `pop_hex`"),
            ("empty", Some(String::new()), "is empty"),
            ("malformed", Some("not-hex".to_owned()), "invalid `pop_hex`"),
            ("wrong length", Some("00".to_owned()), "invalid PoP"),
            (
                "another validator's proof",
                topology[1].pop_hex.clone(),
                "invalid PoP",
            ),
            (
                "corrupted proof",
                Some({
                    let mut pop = topology[0].pop_bytes().unwrap().unwrap();
                    pop[0] ^= 1;
                    hex::encode(pop)
                }),
                "invalid PoP",
            ),
        ] {
            let mut invalid_topology = topology.clone();
            invalid_topology[0].pop_hex = pop_hex;
            let invalid = make_manifest(invalid_topology);
            let validation_error = invalid.validate_genesis_topology().expect_err(label);
            assert!(
                validation_error.to_string().contains(expected_error),
                "{label}: {validation_error}"
            );
            let signing_error = invalid
                .build_and_sign(&checked_genesis_fixture_keypair())
                .expect_err(label);
            assert!(
                signing_error.to_string().contains(expected_error),
                "{label}: {signing_error}"
            );
        }
    }

    #[test]
    fn genesis_epoch_reserves_a_committed_beacon_anchor_and_pulse() {
        for epoch_length in [1, 2, 3] {
            let mut parameters = SumeragiNposParameters::default();
            parameters.epoch_length_blocks = NonZeroU64::new(epoch_length).unwrap();
            parameters.evidence_horizon_blocks = epoch_length;
            parameters.slashing_delay_blocks = epoch_length;
            let manifest = GenesisBuilder::new_without_executor(
                ChainId::from("genesis-beacon-window"),
                PathBuf::from("."),
            )
            .append_parameter(Parameter::Custom(parameters.into_custom_parameter()))
            .append_parameter(Parameter::Sumeragi(
                iroha_data_model::parameter::system::SumeragiParameter::EpochLengthBlocks(
                    NonZeroU64::new(epoch_length).unwrap(),
                ),
            ))
            .set_topology(deterministic_test_genesis_topology_entries())
            .build_raw_for_test()
            .with_consensus_mode(SumeragiConsensusMode::Npos);
            if epoch_length < 3 {
                let error = manifest
                    .build_and_sign(&checked_genesis_fixture_keypair())
                    .expect_err("initial epoch cannot authenticate a height-zero beacon anchor");
                assert!(error.to_string().contains("epoch_length_blocks >= 3"));
            } else {
                manifest
                    .validate_mode_specific_consensus_parameters()
                    .expect("three heights admit the protocol anchor and pulse shape");
            }
        }
    }

    #[test]
    fn genesis_rejects_contradictory_signed_epoch_lengths() {
        let manifest = GenesisBuilder::new_without_executor(
            ChainId::from("contradictory-beacon-epoch"),
            PathBuf::from("."),
        )
        .append_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .append_parameter(Parameter::Sumeragi(
            iroha_data_model::parameter::system::SumeragiParameter::EpochLengthBlocks(
                NonZeroU64::new(11).unwrap(),
            ),
        ))
        .set_topology(deterministic_test_genesis_topology_entries())
        .build_raw_for_test()
        .with_consensus_mode(SumeragiConsensusMode::Npos);
        assert!(
            manifest
                .build_and_sign(&checked_genesis_fixture_keypair())
                .expect_err("conflicting signed scheduling authority must never sign")
                .to_string()
                .contains("must equal the signed Sumeragi epoch_length_blocks")
        );
    }

    #[test]
    fn aggregate_genesis_ivm_bytecode_budget_accepts_exact_limit() {
        assert_eq!(
            checked_genesis_ivm_bytecode_total(GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1 - 1, 1)
                .expect("exact aggregate bytecode limit must be accepted"),
            GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1
        );
        assert!(
            checked_genesis_ivm_bytecode_total(GENESIS_IVM_BYTECODE_MAX_TOTAL_BYTES_V1, 1).is_err()
        );
    }
    fn test_builder() -> (TempDir, GenesisBuilder) {
        let tmp_dir = TempDir::new().unwrap();
        let dummy_bytecode = IvmBytecode::from_compiled(vec![1, 2, 3]);
        let executor_path = tmp_dir.path().join("executor.to");
        std::fs::write(&executor_path, dummy_bytecode).unwrap();
        let chain = ChainId::from("00000000-0000-0000-0000-000000000000");
        let ivm_dir = tmp_dir.path().join("ivm/");
        let builder = GenesisBuilder::new(chain, executor_path, ivm_dir)
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended());
        (tmp_dir, builder)
    }
    #[test]
    fn parse_without_optional_fields() -> Result<()> {
        let tmp_dir = TempDir::new().unwrap();
        let dummy_bytecode = IvmBytecode::from_compiled(vec![1, 2, 3]);
        let executor_path = tmp_dir.path().join("executor.to");
        std::fs::write(&executor_path, dummy_bytecode).unwrap();
        let sumeragi_context =
            norito::json::to_json(&SumeragiGenesisContextParameters::recommended())?;
        let genesis = format!(
            r#"{{"chain":"00000000-0000-0000-0000-000000000000","chain_discriminant":{},"executor":"{}","consensus_mode":"Permissioned","wire_protocol_version":{},"sumeragi_context":{},"transactions":[{{}}]}}"#,
            iroha_data_model::account::address::chain_discriminant(),
            executor_path.file_name().unwrap().to_str().unwrap(),
            iroha_data_model::sumeragi::PROTOCOL_VERSION,
            sumeragi_context,
        );
        let genesis_path = tmp_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis).unwrap();
        let kp = checked_genesis_fixture_keypair();
        let from_path = RawGenesisTransaction::from_path(&genesis_path)?;
        let bytes = std::fs::read(&genesis_path)?;
        let from_hashed_bytes =
            RawGenesisTransaction::from_json_slice_at_path(&bytes, &genesis_path)?;
        assert_eq!(
            norito::json::to_vec(&from_path)?,
            norito::json::to_vec(&from_hashed_bytes)?,
            "in-memory admission must reproduce the signer's exact path semantics"
        );
        with_test_signing_topology(from_path).build_and_sign(&kp)?;
        Ok(())
    }
    #[test]
    fn parse_genesis_accepts_structured_accounts_without_selector_bootstrap() -> Result<()> {
        init_instruction_registry();
        let (tmp_dir, builder) = test_builder();
        let (public_key, _) = checked_genesis_fixture_keypair().into_parts();
        let domain_name: Name = "wonderland".parse()?;
        let account_id = AccountId::new(public_key.clone());
        let domain_id = DomainId::try_new(&domain_name, "universal")?;
        let genesis = builder
            .domain(domain_id)
            .account(public_key)
            .finish_domain()
            .build_raw_for_test()
            .with_consensus_mode(SumeragiConsensusMode::Permissioned);
        let json = norito::json::to_json_pretty(&genesis)?;
        assert!(
            json.contains(&account_id.to_string()),
            "expected i105 account id in genesis JSON"
        );
        let genesis_path = tmp_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, json)?;
        RawGenesisTransaction::from_path(&genesis_path)?;
        Ok(())
    }
    #[test]
    fn parse_genesis_rejects_raw_public_key_account_literals() -> Result<()> {
        init_instruction_registry();
        let public_key_literal = ALICE_KEYPAIR.public_key().to_string();
        let sumeragi_context =
            norito::json::to_json(&SumeragiGenesisContextParameters::recommended())?;
        let genesis = format!(
            r#"{{
                "chain":"00000000-0000-0000-0000-000000000000",
                "chain_discriminant":{},
                "executor":null,
                "ivm_dir":".",
                "consensus_mode":"Permissioned",
                "sumeragi_context":{},
                "transactions":[{{
                    "instructions":[{{"Register":{{"Account":{{"id":"{public_key_literal}","metadata":{{}},"label":null,"uaid":null}}}}}}]
                }}]
            }}"#,
            iroha_data_model::account::address::chain_discriminant(),
            sumeragi_context,
        );
        let error = norito::json::from_str::<RawGenesisTransaction>(&genesis)
            .expect_err("raw public-key account literals are not part of first-release genesis");
        assert!(error.to_string().contains("invalid register account"));
        Ok(())
    }
    #[test]
    fn build_and_sign_refreshes_stale_consensus_fingerprint() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("iroha:test:refresh-consensus-fp");
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        let expected = manifest
            .clone()
            .with_consensus_meta()?
            .consensus_fingerprint
            .clone()
            .expect("expected consensus fingerprint");
        manifest.consensus_fingerprint = Some(ConsensusFingerprint::new([0xDE; 32]));
        let genesis = with_test_signing_topology(manifest)
            .build_and_sign(&checked_genesis_fixture_keypair())?;
        let mut found = None;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(batch) = tx.instructions() {
                for instr in batch {
                    if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                        && let Parameter::Custom(custom) = set_param.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                    {
                        let payload: norito::json::Value = custom
                            .payload()
                            .try_into_any_norito()
                            .expect("decode handshake metadata payload");
                        if let Some(norito::json::Value::String(fp)) =
                            payload.get("consensus_fingerprint")
                        {
                            found = Some(fp.clone());
                            break;
                        }
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        let got = found.expect("consensus_handshake_meta not found");
        assert_eq!(got, expected.to_string());
        Ok(())
    }
    #[test]
    fn raw_genesis_tx_parameters_json_serializes() {
        let tx = RawGenesisTx {
            parameters: Some(Parameters::default()),
            ..RawGenesisTx::default()
        };
        let json = norito::json::to_json(&tx).expect("serialize raw genesis tx");
        let value = norito::json::parse_value(&json).expect("parse raw genesis tx json");
        let obj = value
            .as_object()
            .expect("raw genesis tx must serialize to an object");
        assert!(
            obj.get("parameters").is_some(),
            "parameters must be present when provided"
        );
    }
    #[test]
    fn default_genesis_omits_set_parameter_instructions() -> Result<()> {
        init_instruction_registry();
        let genesis =
            load_genesis_source_template_for_test("../../defaults/genesis.template.json")?;
        assert!(!genesis.transactions.is_empty());
        assert!(
            genesis
                .transactions
                .iter()
                .any(|tx| tx.parameters.is_some()),
            "default genesis should seed parameters in the structured block"
        );
        assert!(
            genesis
                .transactions
                .iter()
                .flat_map(|tx| &tx.instructions)
                .all(|instr| instr.as_any().downcast_ref::<SetParameter>().is_none()),
            "manifest instructions must not include SetParameter"
        );
        Ok(())
    }
    #[test]
    fn shipped_genesis_assets_have_non_blank_human_names() -> Result<()> {
        use iroha_data_model::asset::definition::validate_asset_name;
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifests = [
            repo_root.join("defaults/genesis.template.json"),
            repo_root.join("defaults/nexus/genesis.template.json"),
            repo_root.join("defaults/kagami/iroha3-dev/genesis.template.json"),
            repo_root.join("defaults/kagami/iroha3-nexus/genesis.template.json"),
            repo_root.join("configs/soranexus/nexus/genesis.template.json"),
            repo_root.join("configs/soranexus/taira/genesis.template.json"),
        ];
        for manifest_path in manifests {
            let raw = std::fs::read_to_string(&manifest_path)?;
            let value = norito::json::parse_value(&raw)?;
            let transactions = value
                .get("transactions")
                .and_then(norito::json::Value::as_array)
                .ok_or_else(|| eyre!("{} missing transactions array", manifest_path.display()))?;
            for instruction in transactions
                .iter()
                .filter_map(|tx| tx.get("instructions"))
                .filter_map(norito::json::Value::as_array)
                .flatten()
            {
                let Some(asset_definition) = instruction
                    .get("Register")
                    .and_then(|register| register.get("AssetDefinition"))
                else {
                    continue;
                };
                let name = asset_definition
                    .get("name")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or_default();
                let id = asset_definition
                    .get("id")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or("<missing-id>");
                validate_asset_name(name).map_err(|err| {
                    eyre!(
                        "{} contains invalid asset definition `{}`: {}",
                        manifest_path.display(),
                        id,
                        err
                    )
                })?;
            }
        }
        Ok(())
    }
    #[test]
    fn shipped_public_genesis_manifests_do_not_fake_public_xor() -> Result<()> {
        use std::collections::BTreeSet;
        const PUBLIC_TAIRA_XOR_ID: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
        const PUBLIC_XOR_ALIAS: &str = "xor#universal";
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifests = [
            (
                repo_root.join("configs/soranexus/taira/genesis.template.json"),
                true,
            ),
            (
                repo_root.join("defaults/nexus/genesis.template.json"),
                false,
            ),
            (
                repo_root.join("configs/soranexus/nexus/genesis.template.json"),
                false,
            ),
        ];
        for (manifest_path, requires_taira_xor_id) in manifests {
            let raw = std::fs::read_to_string(&manifest_path)?;
            let value = norito::json::parse_value(&raw)?;
            let transactions = value
                .get("transactions")
                .and_then(norito::json::Value::as_array)
                .ok_or_else(|| eyre!("{} missing transactions array", manifest_path.display()))?;
            let mut registered_asset_ids = BTreeSet::new();
            let mut public_xor_binding = None;
            for instruction in transactions
                .iter()
                .filter_map(|tx| tx.get("instructions"))
                .filter_map(norito::json::Value::as_array)
                .flatten()
            {
                if let Some(id) = instruction
                    .get("Register")
                    .and_then(|register| register.get("AssetDefinition"))
                    .and_then(|asset| asset.get("id"))
                    .and_then(norito::json::Value::as_str)
                {
                    if id.starts_with("xor#") {
                        return Err(eyre!(
                            "{} registers alias-shaped public XOR asset definition id `{id}`; register a canonical Base58 id and bind `{PUBLIC_XOR_ALIAS}` instead",
                            manifest_path.display()
                        ));
                    }
                    registered_asset_ids.insert(id.to_owned());
                }
                let Some(binding) = instruction.get("SetAssetDefinitionAlias") else {
                    continue;
                };
                if binding.get("alias").and_then(norito::json::Value::as_str)
                    == Some(PUBLIC_XOR_ALIAS)
                {
                    let target = binding
                        .get("asset_definition_id")
                        .and_then(norito::json::Value::as_str)
                        .ok_or_else(|| {
                            eyre!(
                                "{} binds `{PUBLIC_XOR_ALIAS}` without asset_definition_id",
                                manifest_path.display()
                            )
                        })?;
                    public_xor_binding = Some(target.to_owned());
                }
            }
            if let Some(target) = public_xor_binding {
                if target.starts_with("xor#") {
                    return Err(eyre!(
                        "{} binds `{PUBLIC_XOR_ALIAS}` to alias-shaped asset definition id `{target}`",
                        manifest_path.display()
                    ));
                }
                if !registered_asset_ids.contains(&target) {
                    return Err(eyre!(
                        "{} binds `{PUBLIC_XOR_ALIAS}` to `{target}` without registering that canonical asset",
                        manifest_path.display()
                    ));
                }
                if requires_taira_xor_id && target != PUBLIC_TAIRA_XOR_ID {
                    return Err(eyre!(
                        "{} must bind `{PUBLIC_XOR_ALIAS}` to live Taira XOR `{PUBLIC_TAIRA_XOR_ID}`, found `{target}`",
                        manifest_path.display()
                    ));
                }
            } else if requires_taira_xor_id {
                return Err(eyre!(
                    "{} must bind `{PUBLIC_XOR_ALIAS}` to live Taira XOR `{PUBLIC_TAIRA_XOR_ID}`",
                    manifest_path.display()
                ));
            }
        }
        Ok(())
    }
    #[test]
    fn soranexus_taira_genesis_binds_sorafs_appeal_xor_at_scale_nine() -> Result<()> {
        const SORA_XOR_ID: &str = "61CtjvNd9T3THAR65GsMVHr82Bjc";
        const SORA_XOR_ALIAS: &str = "xor#sora.universal";
        const SORA_XOR_SCALE: u64 = 9;
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest_path = repo_root.join("configs/soranexus/taira/genesis.template.json");
        let raw = std::fs::read_to_string(&manifest_path)?;
        let value = norito::json::parse_value(&raw)?;
        let transactions = value
            .get("transactions")
            .and_then(norito::json::Value::as_array)
            .ok_or_else(|| eyre!("{} missing transactions array", manifest_path.display()))?;
        let mut sora_xor_registered = false;
        let mut sora_xor_scale = None;
        let mut sora_xor_binding = None;
        for instruction in transactions
            .iter()
            .filter_map(|tx| tx.get("instructions"))
            .filter_map(norito::json::Value::as_array)
            .flatten()
        {
            if let Some(asset_definition) = instruction
                .get("Register")
                .and_then(|register| register.get("AssetDefinition"))
                && asset_definition
                    .get("id")
                    .and_then(norito::json::Value::as_str)
                    == Some(SORA_XOR_ID)
            {
                if sora_xor_registered {
                    return Err(eyre!(
                        "{} registers governed Sora XOR `{SORA_XOR_ID}` more than once",
                        manifest_path.display()
                    ));
                }
                sora_xor_registered = true;
                sora_xor_scale = asset_definition
                    .get("spec")
                    .and_then(|spec| spec.get("scale"))
                    .and_then(norito::json::Value::as_u64);
            }
            let Some(binding) = instruction.get("SetAssetDefinitionAlias") else {
                continue;
            };
            if binding.get("alias").and_then(norito::json::Value::as_str) != Some(SORA_XOR_ALIAS) {
                continue;
            }
            if sora_xor_binding.is_some() {
                return Err(eyre!(
                    "{} binds governed Sora XOR alias `{SORA_XOR_ALIAS}` more than once",
                    manifest_path.display()
                ));
            }
            sora_xor_binding = binding
                .get("asset_definition_id")
                .and_then(norito::json::Value::as_str);
        }
        assert_eq!(
            sora_xor_binding,
            Some(SORA_XOR_ID),
            "{} must bind governed appeal asset `{SORA_XOR_ALIAS}` to `{SORA_XOR_ID}`",
            manifest_path.display()
        );
        assert_eq!(
            sora_xor_scale,
            Some(SORA_XOR_SCALE),
            "{} must register governed appeal asset `{SORA_XOR_ID}` at fixed scale {SORA_XOR_SCALE}; reseed pre-release state instead of mutating a live chain",
            manifest_path.display()
        );
        Ok(())
    }
    #[test]
    fn shipped_genesis_manifests_advertise_current_npos_crypto_caps() -> Result<()> {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifests = [
            repo_root.join("defaults/genesis.template.json"),
            repo_root.join("defaults/nexus/genesis.template.json"),
            repo_root.join("defaults/kagami/iroha3-dev/genesis.template.json"),
            repo_root.join("defaults/kagami/iroha3-nexus/genesis.template.json"),
            repo_root.join("configs/soranexus/nexus/genesis.template.json"),
            repo_root.join("configs/soranexus/taira/genesis.template.json"),
        ];
        let bls_curve = iroha_data_model::account::curve::CurveId::try_from_algorithm(
            iroha_crypto::Algorithm::BlsNormal,
        )
        .expect("bls curve id");
        for manifest_path in manifests {
            let raw = std::fs::read_to_string(&manifest_path)?;
            let value = norito::json::parse_value(&raw)?;
            let wire_protocol_version = value
                .get("wire_protocol_version")
                .and_then(norito::json::Value::as_u64)
                .ok_or_else(|| {
                    eyre!("{} missing wire_protocol_version", manifest_path.display())
                })?;
            assert_eq!(
                wire_protocol_version,
                u64::from(CONSENSUS_PROTOCOL_VERSION),
                "{} must advertise the current consensus wire protocol",
                manifest_path.display()
            );
            let crypto = value
                .get("crypto")
                .ok_or_else(|| eyre!("{} missing crypto section", manifest_path.display()))?;
            let allowed_signing = crypto
                .get("allowed_signing")
                .and_then(norito::json::Value::as_array)
                .ok_or_else(|| {
                    eyre!("{} missing crypto.allowed_signing", manifest_path.display())
                })?;
            assert!(
                allowed_signing
                    .iter()
                    .filter_map(norito::json::Value::as_str)
                    .any(|algo| algo.eq_ignore_ascii_case("bls_normal")),
                "{} must advertise bls_normal for NPoS bootstrap",
                manifest_path.display()
            );
            let allowed_curve_ids = crypto
                .get("allowed_curve_ids")
                .and_then(norito::json::Value::as_array)
                .ok_or_else(|| {
                    eyre!(
                        "{} missing crypto.allowed_curve_ids",
                        manifest_path.display()
                    )
                })?;
            assert!(
                allowed_curve_ids.iter().any(|value| {
                    value
                        .as_u64()
                        .is_some_and(|curve| curve == u64::from(bls_curve.as_u8()))
                }),
                "{} must advertise the BLS curve id for NPoS bootstrap",
                manifest_path.display()
            );
        }
        Ok(())
    }
    #[test]
    fn set_topology_pop_merges_entries() {
        let bls = checked_genesis_fixture_keypair_with_algorithm(Algorithm::BlsNormal);
        let pop =
            iroha_crypto::bls_normal_pop_prove(bls.private_key()).expect("BLS PoP generation");
        let peer = PeerId::new(bls.public_key().clone());
        let manifest =
            GenesisBuilder::new_without_executor(ChainId::from("test-topology-pop"), ".")
                .set_topology(vec![peer.clone()])
                .set_topology_pop(vec![GenesisPeerPop {
                    public_key: peer.public_key().clone(),
                    pop: pop.clone(),
                }])
                .build_raw_for_test();
        let tx = &manifest.transactions()[0];
        assert_eq!(tx.topology().len(), 1);
        assert_eq!(tx.topology()[0].peer, peer);
        let expected = hex::encode(pop);
        assert_eq!(tx.topology()[0].pop_hex.as_deref(), Some(expected.as_str()));
    }
    #[test]
    fn parse_injects_register_peer_with_pop() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-chain");
        let (peer_pk, _) = checked_genesis_fixture_keypair().into_parts();
        let peer_id = PeerId::from(peer_pk.clone());
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .set_topology(vec![GenesisTopologyEntry::new(
                peer_id.clone(),
                vec![1, 2, 3, 4],
            )])
            .build_raw_for_test()
            .with_consensus_meta()?;
        let batches = manifest.parse()?;
        let registers: Vec<_> = batches
            .into_iter()
            .flatten()
            .filter_map(|instr| {
                instr
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Peer(inner) => Some(inner.clone()),
                        _ => None,
                    })
            })
            .collect();
        assert_eq!(registers.len(), 1);
        assert_eq!(registers[0].peer, peer_id);
        assert_eq!(registers[0].pop, vec![1, 2, 3, 4]);
        Ok(())
    }
    #[test]
    fn parse_errors_when_pop_missing() {
        init_instruction_registry();
        let chain = ChainId::from("test-pop-missing");
        let (peer_pk, _) = checked_genesis_fixture_keypair().into_parts();
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .set_topology(vec![GenesisTopologyEntry::from(PeerId::from(peer_pk))])
            .build_raw_for_test()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let err = manifest.parse().expect_err("missing pop must error");
        assert!(
            err.to_string()
                .contains("missing `pop_hex` entry for topology peer"),
            "{err}"
        );
    }
    #[test]
    fn parse_injects_consensus_handshake_metadata() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta");
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        let batches = manifest.parse()?;
        let mut found = false;
        for instr in batches.into_iter().flatten() {
            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set_param.inner()
                && custom.id() == &consensus_metadata::handshake_meta_id()
            {
                found = true;
                break;
            }
        }
        assert!(found, "consensus handshake metadata parameter not found");
        Ok(())
    }
    #[test]
    fn parse_rejects_stale_consensus_handshake_metadata_instruction() {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta-replace");
        let stale_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::from_norito_value_ref(&norito::json::Value::Object({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "mode".to_string(),
                    norito::json::Value::String("Permissioned".to_string()),
                );
                payload.insert(
                    "wire_protocol_version".to_string(),
                    norito::json::to_value(&1u32).expect("serialize protocol version"),
                );
                payload.insert(
                    "consensus_fingerprint".to_string(),
                    norito::json::Value::String("0x0000bad".to_string()),
                );
                payload
            }))
            .expect("construct stale handshake payload"),
        ));
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        manifest
            .transactions
            .first_mut()
            .expect("missing manifest transaction")
            .instructions
            .push(InstructionBox::from(SetParameter::new(stale_param)));
        let error = manifest
            .parse()
            .expect_err("explicit handshake SetParameter must be rejected");
        assert!(
            error
                .to_string()
                .contains("SetParameter instructions (tx 0, instruction 0)"),
            "unexpected error: {error:?}"
        );
    }
    #[test]
    fn parse_replaces_stale_consensus_handshake_metadata_in_parameters() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta-replace-params");
        let expected_fingerprint = GenesisBuilder::new_without_executor(chain.clone(), ".")
            .build_raw_for_test()
            .with_consensus_meta()?
            .consensus_fingerprint
            .expect("consensus fingerprint expected")
            .to_string();
        let stale_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::from_norito_value_ref(&norito::json::Value::Object({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "mode".to_string(),
                    norito::json::Value::String("Permissioned".to_string()),
                );
                payload.insert(
                    "wire_protocol_version".to_string(),
                    norito::json::to_value(&1u32).expect("serialize protocol version"),
                );
                payload.insert(
                    "consensus_fingerprint".to_string(),
                    norito::json::Value::String("0x0000bad".to_string()),
                );
                payload
            }))
            .expect("construct stale handshake payload"),
        ));
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        let mut parameters = Parameters::default();
        parameters.set_parameter(stale_param);
        manifest
            .transactions
            .first_mut()
            .expect("missing manifest transaction")
            .parameters = Some(parameters);
        let mut found = Vec::new();
        for instr in manifest.parse()?.into_iter().flatten() {
            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set_param.inner()
                && custom.id() == &consensus_metadata::handshake_meta_id()
                && let Ok(payload) = custom
                    .payload()
                    .try_into_any_norito::<norito::json::Value>()
            {
                if let Some(fingerprint) =
                    payload
                        .get("consensus_fingerprint")
                        .and_then(|value: &norito::json::Value| {
                            value.as_str().map(std::string::ToString::to_string)
                        })
                {
                    found.push(fingerprint);
                }
            }
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], expected_fingerprint);
        Ok(())
    }
    #[test]
    fn parse_rejects_explicit_consensus_handshake_metadata() {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta-preserve-valid");
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        manifest.consensus_mode = SumeragiConsensusMode::Permissioned;
        manifest.wire_protocol_version = 7;
        let expected_fingerprint = manifest
            .clone()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters")
            .consensus_fingerprint
            .expect("consensus fingerprint expected")
            .to_string();
        let explicit_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::from_norito_value_ref(&norito::json::Value::Object({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "mode".to_string(),
                    norito::json::Value::String("Permissioned".to_string()),
                );
                payload.insert(
                    "wire_protocol_version".to_string(),
                    norito::json::to_value(&7u32).expect("serialize protocol version"),
                );
                payload.insert(
                    "consensus_fingerprint".to_string(),
                    norito::json::Value::String(expected_fingerprint.clone()),
                );
                payload
            }))
            .expect("construct handshake payload"),
        ));
        manifest
            .transactions
            .first_mut()
            .expect("missing manifest transaction")
            .instructions
            .push(InstructionBox::from(SetParameter::new(explicit_param)));
        let error = manifest
            .parse()
            .expect_err("explicit handshake SetParameter must be rejected");
        assert!(
            error
                .to_string()
                .contains("SetParameter instructions (tx 0, instruction 0)"),
            "unexpected error: {error:?}"
        );
    }
    #[test]
    fn parse_rejects_external_consensus_handshake_metadata_instruction() {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta-preserve-external-fingerprint");
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let external_fingerprint =
            "0x1111111111111111111111111111111111111111111111111111111111111111";
        let explicit_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::from_norito_value_ref(&norito::json::Value::Object({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "mode".to_string(),
                    norito::json::Value::String("Npos".to_string()),
                );
                payload.insert(
                    "wire_protocol_version".to_string(),
                    norito::json::to_value(&1u32).expect("serialize protocol version"),
                );
                payload.insert(
                    "consensus_fingerprint".to_string(),
                    norito::json::Value::String(external_fingerprint.to_string()),
                );
                payload
            }))
            .expect("construct handshake payload"),
        ));
        manifest
            .transactions
            .first_mut()
            .expect("missing manifest transaction")
            .instructions
            .push(InstructionBox::from(SetParameter::new(explicit_param)));
        let error = manifest
            .parse()
            .expect_err("external handshake SetParameter must be rejected");
        assert!(
            error
                .to_string()
                .contains("SetParameter instructions (tx 0, instruction 0)"),
            "unexpected error: {error:?}"
        );
    }
    #[test]
    fn parse_recomputes_structured_consensus_handshake_metadata() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-consensus-meta-preserve-valid-params");
        let mut manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        manifest.consensus_mode = SumeragiConsensusMode::Permissioned;
        manifest.wire_protocol_version = 7;
        let expected_fingerprint = manifest
            .clone()
            .with_consensus_meta()?
            .consensus_fingerprint
            .expect("consensus fingerprint expected")
            .to_string();
        let explicit_param = Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            Json::from_norito_value_ref(&norito::json::Value::Object({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "mode".to_string(),
                    norito::json::Value::String("Permissioned".to_string()),
                );
                payload.insert(
                    "wire_protocol_version".to_string(),
                    norito::json::to_value(&7u32).expect("serialize protocol version"),
                );
                payload.insert(
                    "consensus_fingerprint".to_string(),
                    norito::json::Value::String(expected_fingerprint.clone()),
                );
                payload
            }))
            .expect("construct handshake payload"),
        ));
        let mut parameters = Parameters::default();
        parameters.set_parameter(explicit_param);
        manifest
            .transactions
            .first_mut()
            .expect("missing manifest transaction")
            .parameters = Some(parameters);
        let mut found = Vec::new();
        for instr in manifest.parse()?.into_iter().flatten() {
            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set_param.inner()
                && custom.id() == &consensus_metadata::handshake_meta_id()
                && let Ok(payload) = custom
                    .payload()
                    .try_into_any_norito::<norito::json::Value>()
            {
                found.push(payload);
            }
        }
        assert_eq!(found.len(), 1);
        let payload = found.remove(0);
        assert_eq!(
            payload.get("mode").and_then(norito::json::Value::as_str),
            Some("Permissioned")
        );
        assert_eq!(
            payload
                .get("wire_protocol_version")
                .and_then(norito::json::Value::as_u64),
            Some(u64::from(CONSENSUS_PROTOCOL_VERSION))
        );
        assert_eq!(
            payload
                .get("consensus_fingerprint")
                .and_then(norito::json::Value::as_str),
            Some(expected_fingerprint.as_str())
        );
        Ok(())
    }
    #[test]
    fn parse_injects_confidential_registry_root() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-confidential-meta");
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        let batches = manifest.parse()?;
        let mut found = false;
        for instr in batches.into_iter().flatten() {
            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set_param.inner()
                && custom.id() == &confidential_metadata::registry_root_id()
            {
                let value: norito::json::Value = custom
                    .payload()
                    .try_into_any_norito()
                    .expect("decode confidential registry payload");
                let vk_field = value.get("vk_set_hash");
                assert!(
                    matches!(vk_field, Some(norito::json::Value::Null)),
                    "expected null vk_set_hash for empty registry, got {vk_field:?}"
                );
                found = true;
                break;
            }
        }
        assert!(found, "confidential registry root parameter not found");
        Ok(())
    }
    #[test]
    fn parse_injects_crypto_manifest_metadata() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-crypto-meta");
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .build_raw_for_test()
            .with_consensus_meta()?;
        let expected_crypto = manifest.crypto().clone();
        let batches = manifest.parse()?;
        let mut found = None;
        for instr in batches.into_iter().flatten() {
            if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set_param.inner()
                && custom.id() == &crypto_metadata::manifest_meta_id()
            {
                let value: ManifestCrypto = custom
                    .payload()
                    .try_into_any()
                    .expect("decode manifest crypto payload");
                found = Some(value);
                break;
            }
        }
        let found = found.expect("crypto manifest metadata parameter not found");
        assert_eq!(found, expected_crypto);
        Ok(())
    }
    #[test]
    fn parse_rejects_mismatched_crypto_manifest_metadata() {
        init_instruction_registry();
        let chain = ChainId::from("test-crypto-meta-mismatch");
        let mut wrong_crypto = ManifestCrypto::default();
        wrong_crypto.default_hash = "blake2b-512".to_owned();
        let payload =
            norito::json::value::to_value(&wrong_crypto).expect("serialize mismatched crypto");
        let manual_param = Parameter::Custom(CustomParameter::new(
            crypto_metadata::manifest_meta_id(),
            Json::new(payload),
        ));
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .append_parameter(manual_param)
            .build_raw_for_test()
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let err = manifest
            .parse()
            .expect_err("mismatched crypto metadata should be rejected");
        assert!(
            err.to_string()
                .contains("crypto manifest payload in genesis differs"),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    fn parse_respects_manual_confidential_registry_root() -> Result<()> {
        init_instruction_registry();
        let chain = ChainId::from("test-confidential-manual");
        let manual = Parameter::Custom(CustomParameter::new(
            confidential_metadata::registry_root_id(),
            Json::new({
                let mut payload = norito::json::Map::new();
                payload.insert(
                    "vk_set_hash".to_string(),
                    norito::json::Value::String(
                        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                );
                norito::json::Value::Object(payload)
            }),
        ));
        let manifest = GenesisBuilder::new_without_executor(chain, ".")
            .append_parameter(manual)
            .build_raw_for_test()
            .with_consensus_meta()?;
        let batches = manifest.parse()?;
        let count = batches
            .into_iter()
            .flatten()
            .filter(|instr| {
                instr
                    .as_any()
                    .downcast_ref::<SetParameter>()
                    .is_some_and(|set_param| {
                        matches!(
                            set_param.inner(),
                            Parameter::Custom(custom)
                                if custom.id() == &confidential_metadata::registry_root_id()
                        )
                    })
            })
            .count();
        assert_eq!(count, 1, "expected exactly one registry root parameter");
        Ok(())
    }
    #[test]
    fn load_new_genesis_block() -> Result<()> {
        let genesis_key_pair = checked_genesis_fixture_keypair();
        let (alice_public_key, _) = checked_genesis_fixture_keypair().into_parts();
        let (_tmp_dir, builder) = test_builder();
        let _genesis_block = builder
            .domain(DomainId::try_new("wonderland", "universal")?)
            .account(alice_public_key)
            .finish_domain()
            .set_topology(deterministic_test_genesis_topology_entries())
            .build_and_sign(&genesis_key_pair)?;
        Ok(())
    }
    #[test]
    fn signed_block_versioned_roundtrip() -> Result<()> {
        init_instruction_registry();
        let genesis_key_pair = checked_genesis_fixture_keypair();
        let (tmp_dir, builder) = test_builder();
        let _ = tmp_dir;
        let block = builder
            .set_topology(deterministic_test_genesis_topology_entries())
            .build_and_sign(&genesis_key_pair)?;
        let wire = block
            .0
            .canonical_wire()
            .map_err(|error| eyre!("encode canonical genesis wire: {error}"))?;
        assert_eq!(wire.payload(), &block.0.encode_versioned()[1..]);
        let decoded = iroha_data_model::block::decode_framed_signed_block(wire.as_framed())
            .map_err(|error| eyre!("decode canonical genesis wire: {error}"))?;
        assert_eq!(
            decoded.external_transactions().count(),
            block.0.external_transactions().count()
        );
        Ok(())
    }
    include!("genesis_block_builder_example_tests.rs");
    include!("genesis_tail_tests.rs");
}

/// Bound the exact authored genesis inputs without changing source boundaries.
fn validate_genesis_batch_limit(batches: &[Vec<InstructionBox>], limit: usize) -> Result<()> {
    if batches.len() > limit {
        return Err(eyre!(
            "genesis has {} network inputs, exceeding the FASTPQ bootstrap limit {limit}; author compatible draft batches explicitly before signing",
            batches.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod genesis_batch_limit_tests {
    use iroha_data_model::{
        Level,
        isi::{InstructionBox, Log},
        prelude::{Executor, Upgrade},
        transaction::IvmBytecode,
    };

    use super::validate_genesis_batch_limit;

    fn log(message: &str) -> InstructionBox {
        Log::new(Level::INFO, message.to_owned()).into()
    }

    fn messages(batches: &[Vec<InstructionBox>]) -> Vec<Vec<String>> {
        batches
            .iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|instruction| format!("{instruction:?}"))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn refuses_overbudget_inputs_without_changing_authored_order() {
        let batches: Vec<Vec<InstructionBox>> =
            (0..15).map(|i| vec![log(&i.to_string())]).collect();
        let flat = messages(&batches).concat();
        assert!(
            validate_genesis_batch_limit(&batches, 11)
                .unwrap_err()
                .to_string()
                .contains("15 network inputs")
        );
        assert_eq!(
            messages(&batches).concat(),
            flat,
            "original order is retained"
        );
    }

    #[test]
    fn keeps_a_leading_executor_upgrade_alone() {
        let mut batches = vec![vec![InstructionBox::from(Upgrade::new(Executor::new(
            IvmBytecode::from_compiled(vec![1, 2, 3]),
        )))]];
        batches.extend((0..5).map(|i| vec![log(&i.to_string())]));
        let original = messages(&batches);
        assert!(validate_genesis_batch_limit(&batches, 2).is_err());
        assert_eq!(messages(&batches), original);
        assert_eq!(batches[0].len(), 1, "the executor upgrade stays alone");
        assert!(batches[1..].iter().all(|batch| batch.len() == 1));
    }

    #[test]
    fn leaves_small_genesis_unchanged() {
        let batches: Vec<Vec<InstructionBox>> = (0..3).map(|i| vec![log(&i.to_string())]).collect();
        let before = messages(&batches);
        validate_genesis_batch_limit(&batches, 11).unwrap();
        assert_eq!(messages(&batches), before);
    }
}
