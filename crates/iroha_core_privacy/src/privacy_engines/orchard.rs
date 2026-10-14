//! First-release Orchard V3 action-bundle prover and verifier.
//!
//! The integration deliberately exposes no caller-selected Orchard protocol or circuit version.
//! Every bundle is reconstructed as `orchard_v3`, every proof is verified with the `PostNu6_3` key,
//! and the historical insecure and compatibility circuits are therefore unrepresentable. Production
//! proving is a two-phase protocol: prepare fixes randomized actions and the Halo2 proof, then a
//! consuming authorization step signs those exact bytes together with the complete native consensus
//! binding.
use super::prover_randomness::{HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInOut as _, KeyInit as _},
};
use incrementalmerkletree::{Position, frontier::Frontier};
use iroha_data_model::privacy::{PrivacyConsensusLimitsV1, PrivacyNativeConsensusBindingV1};
use nonempty::NonEmpty;
use orchard::{
    Action, Address, Anchor, Bundle, Proof,
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::{Authorization, Authorized, BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey},
    note::{
        ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext,
    },
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::MerkleHashOrchard,
    value::{NoteValue, ValueCommitment},
};
pub use orchard::{
    keys::{Scope, SpendingKey},
    note::Note,
    tree::MerklePath,
};
use rand::TryRngCore as _;
use rand_core_06::{CryptoRng as CryptoRng06, RngCore as RngCore06};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Maximum Orchard actions admitted by the first-release Taira profile.
pub const ORCHARD_MAX_ACTIONS_V1: usize = 2;
/// Exact pinned upstream Orchard crate version.
pub const ORCHARD_UPSTREAM_CRATE_VERSION_V1: &str = "0.15.4";
/// Exact pinned upstream source revision.
pub const ORCHARD_UPSTREAM_REVISION_V1: &str = "9d07047d32c4787e1b7964b4cf4fa0286c93824c";
/// SHA-256 of the pinned upstream Post-NU6.3 circuit description.
pub const ORCHARD_POST_NU6_3_CIRCUIT_DESCRIPTION_SHA256_V1: &str =
    "8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90";
/// Magic and version for the sole first-release Orchard authorization wire.
pub const ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1: [u8; 4] = *b"ORC1";
/// Exact retained rand-core 0.6 bridge used by the Orchard producer.
pub(crate) const ORCHARD_PROVER_RANDOMNESS_POLICY_V1: &[u8] = b"bridge=chacha20poly1305-aead:source-key=entropy[0..32]:source-nonce=entropy[32..44]:source-plaintext=entropy[44..64]+IROHA-ORC-V1:seed-aad=iroha.privacy.orchard-v3.prover-rng.seed-bridge.v1:retained-key=ciphertext32:nonce-prefix=tag[0..4]:stream-aad=iroha.privacy.orchard-v3.prover-rng.stream-block.v1:stream-nonce=prefix4+u64be-counter:stream-plaintext=stream-aad+zeros-to64:counter-start=0:counter-u64max-exclusive:consumed-bytes-zeroized:state-zeroized+poisoned-on-error-unwind-drop:single-state-no-replay:v1";
/// Complete native-engine profile descriptor.
pub(crate) const ORCHARD_COMPILED_PROFILE_DESCRIPTOR_V1: &[u8] = b"version=1|protocol=orchard-v3|pool=orchard|circuit=PostNu6_3|upstream=orchard-0.15.4@9d07047d32c4787e1b7964b4cf4fa0286c93824c|circuit_description_sha256=8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90|critical_deps=halo2-proofs-0.3.4:halo2-gadgets-0.5.0:incrementalmerkletree-0.8.2:pasta-curves-0.5.2:reddsa-0.5.2|producer=native-builder:two-phase-prepare-then-consuming-authorize:nonempty-spend-or-wallet-change:PostNu6_3:self-verified|prover_rng=shared-rand0.9-TryCryptoRng-fixed64-health-policy-v1+orchard-retained-bridge-policy-v1|flags=spends-enabled:outputs-enabled:cross-address-disabled|actions=1..2|halo2_proof_bytes=2720+2272*actions|authorization_wire=ORC1:u8-action-count:halo2-proof:ordered-64-byte-spend-signatures:64-byte-binding-signature|sighash=sha256-framed-native-consensus-binding-digest-and-public-bundle-v1|legacy=unrepresentable";
const SIGHASH_DOMAIN_V1: &[u8] = b"iroha.privacy.orchard-v3.bundle-sighash.v1";
const PROVER_RNG_SEED_DOMAIN_V1: &[u8] = b"iroha.privacy.orchard-v3.prover-rng.seed-bridge.v1";
const PROVER_RNG_STREAM_DOMAIN_V1: &[u8] = b"iroha.privacy.orchard-v3.prover-rng.stream-block.v1";
const PROVER_RNG_SEED_FRAME_V1: [u8; 12] = *b"IROHA-ORC-V1";
const ORCHARD_AUTHORIZATION_HEADER_BYTES_V1: usize = ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1.len() + 1;
const ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1: usize = 64;
/// Exact note-commitment membership depth of the first-release Orchard pool.
pub const ORCHARD_TREE_DEPTH_V1: u8 = 32;
const ORCHARD_PROVER_ENTROPY_BYTES_V1: usize = 64;
const ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1: usize = 64;
const _: () = assert!(PROVER_RNG_STREAM_DOMAIN_V1.len() <= ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1);
/// Exact public data for one Orchard V3 action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardActionPublicV1 {
    /// Canonical Pallas-base nullifier encoding.
    pub nullifier: [u8; 32],
    /// Canonical non-identity randomized RedPallas verification key.
    pub randomized_key: [u8; 32],
    /// Canonical extracted note commitment.
    pub note_commitment: [u8; 32],
    /// Canonical non-identity ephemeral Pallas public key.
    pub ephemeral_key: [u8; 32],
    /// Exact Orchard encrypted-note ciphertext.
    pub encrypted_note: [u8; 580],
    /// Exact Orchard outgoing ciphertext.
    pub outgoing_ciphertext: [u8; 80],
    /// Canonical Pallas value commitment.
    pub value_commitment: [u8; 32],
}
/// Exact public data for one first-release Orchard V3 bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardBundlePublicV1 {
    /// Complete mandatory Iroha consensus binding signed by every action.
    pub consensus_binding: PrivacyNativeConsensusBindingV1,
    /// Canonical Orchard note-commitment-tree anchor.
    pub anchor: [u8; 32],
    /// Signed public Orchard value balance.
    pub value_balance: i64,
    /// Non-empty ordered Orchard actions.
    pub actions: Vec<OrchardActionPublicV1>,
}
/// One wallet-owned note and authentication path consumed by the native prover.
///
/// The spending key is intentionally omitted from `Debug`; callers transfer ownership into the
/// prover so the integration does not retain an additional long-lived copy.
pub struct OrchardSpendProverInputV1 {
    spending_key: SpendingKey,
    note: Note,
    merkle_path: MerklePath,
}
impl core::fmt::Debug for OrchardSpendProverInputV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OrchardSpendProverInputV1")
            .field("spending_key", &"<redacted>")
            .field("note", &"<redacted>")
            .field("merkle_path_position", &self.merkle_path.position())
            .finish()
    }
}
impl OrchardSpendProverInputV1 {
    /// Construct one native spend from an Orchard key, note, and depth-32 path.
    #[must_use]
    pub fn new(spending_key: SpendingKey, note: Note, merkle_path: MerklePath) -> Self {
        Self {
            spending_key,
            note,
            merkle_path,
        }
    }
    /// Parse one exact wallet note opening and its complete depth-32 path.
    ///
    /// The derived note commitment must reach `expected_anchor`. This keeps raw upstream Orchard
    /// component parsing inside native Rust and makes a partial path, malformed field element,
    /// wrong key/address, or stale anchor unrepresentable as a prepared prover input.
    pub fn from_wallet_parts_v1(
        spending_key: [u8; 32],
        recipient: [u8; 43],
        value: u64,
        rho: [u8; 32],
        random_seed: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; ORCHARD_TREE_DEPTH_V1 as usize],
        expected_anchor: [u8; 32],
    ) -> Result<Self, OrchardSpendInputErrorV1> {
        let spending_key = Option::<SpendingKey>::from(SpendingKey::from_bytes(spending_key))
            .ok_or(OrchardSpendInputErrorV1::SpendingKey)?;
        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient))
            .ok_or(OrchardSpendInputErrorV1::Recipient)?;
        if FullViewingKey::from(&spending_key)
            .scope_for_address(&recipient)
            .is_none()
        {
            return Err(OrchardSpendInputErrorV1::RecipientOwnership);
        }
        let rho =
            Option::<Rho>::from(Rho::from_bytes(&rho)).ok_or(OrchardSpendInputErrorV1::Rho)?;
        let random_seed = Option::<RandomSeed>::from(RandomSeed::from_bytes(random_seed, &rho))
            .ok_or(OrchardSpendInputErrorV1::RandomSeed)?;
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            random_seed,
            NoteVersion::V2,
        ))
        .ok_or(OrchardSpendInputErrorV1::Note)?;
        let path = authentication_path
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
                    .ok_or(OrchardSpendInputErrorV1::AuthenticationPath { index })
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| OrchardSpendInputErrorV1::AuthenticationPathLength)?;
        let merkle_path = MerklePath::from_parts(leaf_position, path);
        let anchor = merkle_path
            .root(ExtractedNoteCommitment::from(note.commitment()))
            .to_bytes();
        if anchor != expected_anchor {
            return Err(OrchardSpendInputErrorV1::AnchorMismatch);
        }
        Ok(Self::new(spending_key, note, merkle_path))
    }
}
/// Failure parsing one native Orchard wallet spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrchardSpendInputErrorV1 {
    /// The ZIP-32 Orchard spending key is not canonical.
    #[error("Orchard spending key is invalid")]
    SpendingKey,
    /// The raw Orchard recipient address is not canonical.
    #[error("Orchard recipient address is invalid")]
    Recipient,
    /// The note recipient is not controlled by the supplied spending key.
    #[error("Orchard recipient is not controlled by the spending key")]
    RecipientOwnership,
    /// The note rho field is not canonical.
    #[error("Orchard note rho is invalid")]
    Rho,
    /// The note random seed is not canonical for its rho.
    #[error("Orchard note random seed is invalid")]
    RandomSeed,
    /// The supplied note components do not construct a valid V2 note.
    #[error("Orchard note opening is invalid")]
    Note,
    /// One path sibling is not a canonical Orchard field element.
    #[error("Orchard authentication path element {index} is invalid")]
    AuthenticationPath {
        /// Zero-based path level.
        index: usize,
    },
    /// The authentication path does not have the exact depth-32 shape.
    #[error("Orchard authentication path must contain exactly 32 elements")]
    AuthenticationPathLength,
    /// The note and path do not authenticate to the requested retained anchor.
    #[error("Orchard authentication path does not reach the retained anchor")]
    AnchorMismatch,
}
/// One wallet-controlled change output consumed by the native prover.
///
/// Post-NU6.3 Orchard disables cross-address transfers, so retained shielded
/// value is represented only as wallet-owned change. Withdrawn value is exposed
/// through the bundle's signed public value balance.
pub struct OrchardChangeProverInputV1 {
    spending_key: SpendingKey,
    scope: Scope,
    diversifier_index: u32,
    value: u64,
    memo: [u8; 512],
}
impl core::fmt::Debug for OrchardChangeProverInputV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OrchardChangeProverInputV1")
            .field("spending_key", &"<redacted>")
            .field("scope", &self.scope)
            .field("diversifier_index", &self.diversifier_index)
            .field("value", &self.value)
            .field("memo", &"<redacted>")
            .finish()
    }
}
impl OrchardChangeProverInputV1 {
    /// Construct wallet-controlled change at one ZIP-32 diversifier index.
    #[must_use]
    pub fn new(
        spending_key: SpendingKey,
        scope: Scope,
        diversifier_index: u32,
        value: u64,
        memo: [u8; 512],
    ) -> Self {
        Self {
            spending_key,
            scope,
            diversifier_index,
            value,
            memo,
        }
    }
    /// Parse one exact wallet-controlled change opening.
    ///
    /// `internal_scope` selects the sole two ZIP-32 scopes without exposing
    /// upstream Orchard key types across wallet-worker boundaries.
    pub fn from_wallet_parts_v1(
        spending_key: [u8; 32],
        internal_scope: bool,
        diversifier_index: u32,
        value: u64,
        memo: [u8; 512],
    ) -> Result<Self, OrchardChangeInputErrorV1> {
        let spending_key = Option::<SpendingKey>::from(SpendingKey::from_bytes(spending_key))
            .ok_or(OrchardChangeInputErrorV1::SpendingKey)?;
        let scope = if internal_scope {
            Scope::Internal
        } else {
            Scope::External
        };
        Ok(Self::new(
            spending_key,
            scope,
            diversifier_index,
            value,
            memo,
        ))
    }
}
/// Failure parsing one native Orchard wallet change output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrchardChangeInputErrorV1 {
    /// The ZIP-32 Orchard spending key is not canonical.
    #[error("Orchard change spending key is invalid")]
    SpendingKey,
}
/// Complete public statement and canonical ORC1 authorization emitted by the prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardProvedBundleV1 {
    /// Proof-independent public bundle reconstructed by validators.
    pub public: OrchardBundlePublicV1,
    /// Exact Halo2 proof and ordered RedPallas signatures in the ORC1 wire.
    pub authorization: Vec<u8>,
}
/// Proof-independent public Orchard actions emitted by the prepare phase.
///
/// A caller uses this exact draft to construct the canonical Iroha statement and transaction
/// intent. It deliberately contains no consensus binding: authorization can only happen later by
/// consuming [`OrchardPreparedBundleV1`] with the finalized binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardBundleDraftV1 {
    /// Canonical Orchard note-commitment-tree anchor.
    pub anchor: [u8; 32],
    /// Signed public Orchard value balance.
    pub value_balance: i64,
    /// Non-empty ordered randomized Orchard actions.
    pub actions: Vec<OrchardActionPublicV1>,
}
/// Secret-bearing Orchard state between proof creation and authorization.
///
/// This type intentionally implements neither `Clone` nor serialization. Its
/// consuming authorization API prevents signing the same randomized actions
/// under two transaction intents and retains the already-advanced prover RNG,
/// so authorization never rebuilds a bundle or replays caller entropy.
pub struct OrchardPreparedBundleV1 {
    proven: Bundle<InProgress<Proof, Unauthorized>, i64>,
    signing_keys: Vec<SpendAuthorizingKey>,
    upstream_rng: OrchardUpstreamRngV1,
    draft: OrchardBundleDraftV1,
}
impl core::fmt::Debug for OrchardPreparedBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OrchardPreparedBundleV1")
            .field("proven", &"<proof-bearing private state>")
            .field("signing_keys", &"<redacted>")
            .field("upstream_rng", &"<redacted>")
            .field("draft", &self.draft)
            .finish()
    }
}
impl OrchardPreparedBundleV1 {
    /// Borrow the exact randomized public actions that must enter the statement.
    #[must_use]
    pub const fn public_draft(&self) -> &OrchardBundleDraftV1 {
        &self.draft
    }
}
/// Canonical compact representation of one Orchard note-commitment frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct OrchardFrontierPartsV1 {
    /// Number of leaves already appended.
    pub tree_size: u64,
    /// Most recently appended leaf, absent only for the empty tree.
    pub leaf: Option<[u8; 32]>,
    /// Past subtree roots needed to continue appending.
    pub ommers: Vec<[u8; 32]>,
    /// Root derived from the complete compact frontier.
    pub root: [u8; 32],
}
/// Failure returned by the native first-release Orchard verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrchardNativeErrorV1 {
    /// The complete mandatory consensus binding was malformed.
    #[error("Orchard native consensus binding is invalid")]
    ConsensusBinding,
    /// Canonical encoding of the validated consensus binding failed.
    #[error("Orchard native consensus binding could not be canonically encoded")]
    ConsensusBindingEncoding,
    /// The action count was outside the compiled non-empty bound.
    #[error("Orchard action count {actual} is outside 1..={max}")]
    ActionCount {
        /// Supplied count.
        actual: usize,
        /// Compiled maximum.
        max: usize,
    },
    /// The proof did not have the unique canonical size for its action count.
    #[error("Orchard proof length {actual} does not equal canonical length {expected}")]
    ProofLength {
        /// Supplied proof length.
        actual: usize,
        /// Exact required proof length.
        expected: usize,
    },
    /// The proof payload does not use the sole first-release wire version.
    #[error("Orchard authorization wire magic/version is not ORC1")]
    AuthorizationWireMagic,
    /// The proof payload action count differs from the public statement.
    #[error(
        "Orchard authorization wire action count {encoded} differs from statement count {expected}"
    )]
    AuthorizationActionCount {
        /// Count encoded in the authorization wire.
        encoded: usize,
        /// Exact public statement count.
        expected: usize,
    },
    /// The anchor was not a canonical Pallas-base encoding.
    #[error("Orchard anchor is not canonical")]
    AnchorEncoding,
    /// An action nullifier was not canonical.
    #[error("Orchard action {index} nullifier is not canonical")]
    NullifierEncoding {
        /// Ordered action index.
        index: usize,
    },
    /// An action randomized verification key was not canonical.
    #[error("Orchard action {index} randomized key is not canonical")]
    RandomizedKeyEncoding {
        /// Ordered action index.
        index: usize,
    },
    /// An action extracted note commitment was not canonical.
    #[error("Orchard action {index} note commitment is not canonical")]
    NoteCommitmentEncoding {
        /// Ordered action index.
        index: usize,
    },
    /// An action value commitment was not canonical.
    #[error("Orchard action {index} value commitment is not canonical")]
    ValueCommitmentEncoding {
        /// Ordered action index.
        index: usize,
    },
    /// An action contained an identity randomized key or invalid ephemeral key.
    #[error("Orchard action {index} violates canonical action construction")]
    ActionEncoding {
        /// Ordered action index.
        index: usize,
    },
    /// The fixed V3 bundle could not be reconstructed.
    #[error("Orchard V3 bundle construction rejected canonical public data")]
    BundleEncoding,
    /// A RedPallas spend-authorization signature failed.
    #[error("Orchard action {index} spend-authorization signature is invalid")]
    SpendAuthorizationSignature {
        /// Ordered action index.
        index: usize,
    },
    /// The RedPallas binding signature failed.
    #[error("Orchard binding signature is invalid")]
    BindingSignature,
    /// The Post-NU6.3 Halo2 proof failed.
    #[error("Orchard Post-NU6.3 Halo2 action proof is invalid")]
    Halo2Proof,
}
/// Failure returned by the sole first-release native Orchard producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrchardProverErrorV1 {
    /// The complete mandatory consensus binding was malformed.
    #[error("Orchard native consensus binding is invalid")]
    ConsensusBinding,
    /// Canonical encoding of the validated consensus binding failed.
    #[error("Orchard native consensus binding could not be canonically encoded")]
    ConsensusBindingEncoding,
    /// The requested anchor was not a canonical Pallas-base encoding.
    #[error("Orchard prover anchor is not canonical")]
    AnchorEncoding,
    /// No real spend or wallet-controlled change was requested.
    #[error("Orchard prover request must contain at least one spend or change output")]
    EmptyOperation,
    /// The requested action count cannot fit the closed first-release profile.
    #[error("Orchard prover action count {actual} is outside 1..={max}")]
    ActionCount {
        /// Number of real actions requested before padding.
        actual: usize,
        /// Compiled first-release maximum.
        max: usize,
    },
    /// The requested padding floor cannot fit the closed first-release profile.
    #[error("Orchard prover minimum action count {actual} is outside 1..={max}")]
    MinimumActionCount {
        /// Caller-supplied padding floor.
        actual: u8,
        /// Compiled first-release maximum.
        max: usize,
    },
    /// A spend was not owned by its key or did not authenticate to the anchor.
    #[error("Orchard spend {index} is inconsistent with its key, note, path, or anchor")]
    SpendInput {
        /// Ordered spend-input index.
        index: usize,
    },
    /// A wallet-controlled change output was inconsistent with its key or profile.
    #[error("Orchard change output {index} is inconsistent with its key or profile")]
    ChangeInput {
        /// Ordered change-output index.
        index: usize,
    },
    /// Operating-system or injected entropy was unavailable.
    #[error("Orchard prover randomness is unavailable")]
    RandomnessUnavailable,
    /// Entropy repeated a prohibited constant-half or short-period pattern.
    #[error("Orchard prover randomness failed its health checks")]
    RandomnessHealth,
    /// The upstream fixed-profile builder rejected the bounded request.
    #[error("Orchard fixed-profile bundle construction failed")]
    BundleConstruction,
    /// The pinned Post-NU6.3 Halo2 prover failed.
    #[error("Orchard Post-NU6.3 Halo2 proof construction failed")]
    Halo2Proof,
    /// One or more real or fabricated spends could not be authorized.
    #[error("Orchard RedPallas authorization failed")]
    Authorization,
    /// The producer emitted an unexpected action count or wire length.
    #[error("Orchard producer violated its closed-profile output shape")]
    OutputShape,
    /// The independently reconstructed production verifier rejected the result.
    #[error("Orchard producer self-check failed")]
    SelfCheck,
}
/// Failure while restoring or advancing the authoritative Orchard frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum OrchardFrontierErrorV1 {
    /// Empty and non-empty shape fields disagree.
    #[error("Orchard frontier tree size, leaf, and ommers have an inconsistent empty shape")]
    EmptyShape,
    /// The persisted leaf is not a canonical Pallas-base encoding.
    #[error("Orchard frontier leaf is not canonical")]
    LeafEncoding,
    /// One persisted ommer is not a canonical Pallas-base encoding.
    #[error("Orchard frontier ommer {index} is not canonical")]
    OmmerEncoding {
        /// Zero-based ommer index.
        index: usize,
    },
    /// The compact parts do not describe a valid depth-32 frontier.
    #[error("Orchard compact frontier parts are inconsistent or exceed depth 32")]
    FrontierShape,
    /// The reconstructed root differs from persisted authoritative state.
    #[error("Orchard reconstructed frontier root differs from persisted root")]
    RootMismatch,
    /// An output note commitment is not a canonical Orchard leaf.
    #[error("Orchard output action {index} note commitment is not canonical")]
    NoteCommitmentEncoding {
        /// Zero-based output action index.
        index: usize,
    },
    /// Appending another action would exceed the depth-32 tree capacity.
    #[error("Orchard note-commitment tree is full")]
    TreeFull,
}
struct ParsedOrchardAuthorizationV1<'a> {
    halo2_proof: &'a [u8],
    spend_authorization_signatures: Vec<[u8; ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1]>,
    binding_signature: [u8; ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1],
}
fn decode_merkle_hash(
    bytes: &[u8; 32],
    error: OrchardFrontierErrorV1,
) -> Result<MerkleHashOrchard, OrchardFrontierErrorV1> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes)).ok_or(error)
}
fn restore_orchard_frontier_v1(
    tree_size: u64,
    leaf: Option<[u8; 32]>,
    ommers: &[[u8; 32]],
) -> Result<Frontier<MerkleHashOrchard, ORCHARD_TREE_DEPTH_V1>, OrchardFrontierErrorV1> {
    if tree_size == 0 {
        if leaf.is_some() || !ommers.is_empty() {
            return Err(OrchardFrontierErrorV1::EmptyShape);
        }
        return Ok(Frontier::empty());
    }
    let leaf = leaf.ok_or(OrchardFrontierErrorV1::EmptyShape)?;
    let leaf = decode_merkle_hash(&leaf, OrchardFrontierErrorV1::LeafEncoding)?;
    let ommers = ommers
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            decode_merkle_hash(bytes, OrchardFrontierErrorV1::OmmerEncoding { index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Frontier::from_parts(Position::from(tree_size - 1), leaf, ommers)
        .map_err(|_| OrchardFrontierErrorV1::FrontierShape)
}
fn orchard_frontier_parts_v1(
    frontier: Frontier<MerkleHashOrchard, ORCHARD_TREE_DEPTH_V1>,
) -> OrchardFrontierPartsV1 {
    let root = frontier.root().to_bytes();
    let tree_size = frontier.tree_size();
    let (leaf, ommers) = frontier.take().map_or((None, Vec::new()), |frontier| {
        let (_, leaf, ommers) = frontier.into_parts();
        (
            Some(leaf.to_bytes()),
            ommers.into_iter().map(|ommer| ommer.to_bytes()).collect(),
        )
    });
    OrchardFrontierPartsV1 {
        tree_size,
        leaf,
        ommers,
        root,
    }
}
/// Return the unique pinned Orchard V3 empty-tree root.
#[must_use]
#[doc(hidden)]
pub fn orchard_empty_root_v1() -> [u8; 32] {
    Frontier::<MerkleHashOrchard, ORCHARD_TREE_DEPTH_V1>::empty()
        .root()
        .to_bytes()
}
/// Return whether bytes are one canonical Orchard nullifier encoding.
#[must_use]
pub(crate) fn is_canonical_orchard_nullifier_v1(bytes: &[u8; 32]) -> bool {
    bool::from(Nullifier::from_bytes(bytes).is_some())
}
/// Reconstruct and validate one persisted compact Orchard frontier.
///
/// # Errors
///
/// Rejects inconsistent empty/non-empty shape, non-canonical field values,
/// impossible ommer structure or depth, and a root mismatch.
pub(crate) fn validate_orchard_frontier_v1(
    tree_size: u64,
    leaf: Option<[u8; 32]>,
    ommers: &[[u8; 32]],
    expected_root: [u8; 32],
) -> Result<(), OrchardFrontierErrorV1> {
    let frontier = restore_orchard_frontier_v1(tree_size, leaf, ommers)?;
    if frontier.root().to_bytes() != expected_root {
        return Err(OrchardFrontierErrorV1::RootMismatch);
    }
    Ok(())
}
/// Append ordered output commitments and return the complete successor parts.
///
/// # Errors
///
/// Rejects malformed persisted state, non-canonical commitments, or a full depth-32 tree.
pub(crate) fn append_orchard_commitments_v1(
    tree_size: u64,
    leaf: Option<[u8; 32]>,
    ommers: &[[u8; 32]],
    expected_root: [u8; 32],
    output_commitments: &[[u8; 32]],
) -> Result<OrchardFrontierPartsV1, OrchardFrontierErrorV1> {
    let mut frontier = restore_orchard_frontier_v1(tree_size, leaf, ommers)?;
    if frontier.root().to_bytes() != expected_root {
        return Err(OrchardFrontierErrorV1::RootMismatch);
    }
    for (index, commitment) in output_commitments.iter().enumerate() {
        let commitment = Option::<ExtractedNoteCommitment>::from(
            ExtractedNoteCommitment::from_bytes(commitment),
        )
        .ok_or(OrchardFrontierErrorV1::NoteCommitmentEncoding { index })?;
        if !frontier.append(MerkleHashOrchard::from_cmx(&commitment)) {
            return Err(OrchardFrontierErrorV1::TreeFull);
        }
    }
    Ok(orchard_frontier_parts_v1(frontier))
}
/// Return the unique first-release authorization-wire size for `action_count`.
#[must_use]
pub fn orchard_authorization_wire_size_v1(action_count: usize) -> Option<usize> {
    let halo2_proof = Proof::expected_proof_size(action_count);
    ORCHARD_AUTHORIZATION_HEADER_BYTES_V1
        .checked_add(halo2_proof)?
        .checked_add(action_count.checked_mul(ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1)?)?
        .checked_add(ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1)
}
fn decode_authorization_wire_v1(
    proof_bytes: &[u8],
    action_count: usize,
) -> Result<ParsedOrchardAuthorizationV1<'_>, OrchardNativeErrorV1> {
    let expected = orchard_authorization_wire_size_v1(action_count).ok_or(
        OrchardNativeErrorV1::ProofLength {
            actual: proof_bytes.len(),
            expected: usize::MAX,
        },
    )?;
    if proof_bytes.len() != expected {
        return Err(OrchardNativeErrorV1::ProofLength {
            actual: proof_bytes.len(),
            expected,
        });
    }
    if proof_bytes[..ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1.len()]
        != ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1
    {
        return Err(OrchardNativeErrorV1::AuthorizationWireMagic);
    }
    let encoded_action_count = usize::from(proof_bytes[ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1.len()]);
    if encoded_action_count != action_count {
        return Err(OrchardNativeErrorV1::AuthorizationActionCount {
            encoded: encoded_action_count,
            expected: action_count,
        });
    }
    let halo2_len = Proof::expected_proof_size(action_count);
    let halo2_start = ORCHARD_AUTHORIZATION_HEADER_BYTES_V1;
    let halo2_end = halo2_start + halo2_len;
    let mut cursor = halo2_end;
    let mut spend_authorization_signatures = Vec::with_capacity(action_count);
    for _ in 0..action_count {
        let end = cursor + ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1;
        let mut signature = [0; ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1];
        signature.copy_from_slice(&proof_bytes[cursor..end]);
        spend_authorization_signatures.push(signature);
        cursor = end;
    }
    let mut binding_signature = [0; ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1];
    binding_signature.copy_from_slice(&proof_bytes[cursor..]);
    Ok(ParsedOrchardAuthorizationV1 {
        halo2_proof: &proof_bytes[halo2_start..halo2_end],
        spend_authorization_signatures,
        binding_signature,
    })
}
fn append_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(
        u64::try_from(field.len())
            .expect("compiled Orchard field length fits u64")
            .to_be_bytes(),
    );
    hasher.update(field);
}
/// Derive the sole message signed by every action and the bundle binding key.
///
/// The canonical native consensus-binding digest binds the chain, genesis,
/// action position, transaction intent, and exact activated verifier profile.
/// The remaining framing independently binds every Orchard public action byte
/// and its order, including ciphertexts that are not Halo2 public inputs.
///
/// # Errors
///
/// Rejects a malformed binding or a failure to produce its canonical Norito digest.
pub fn derive_orchard_bundle_sighash_v1(
    bundle: &OrchardBundlePublicV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
) -> Result<[u8; 32], OrchardNativeErrorV1> {
    bundle
        .consensus_binding
        .validate(consensus_limits)
        .map_err(|_| OrchardNativeErrorV1::ConsensusBinding)?;
    let binding_digest = bundle
        .consensus_binding
        .digest()
        .map_err(|_| OrchardNativeErrorV1::ConsensusBindingEncoding)?;
    let mut hasher = Sha256::new();
    append_field(&mut hasher, SIGHASH_DOMAIN_V1);
    append_field(&mut hasher, binding_digest.as_bytes());
    append_field(&mut hasher, &bundle.anchor);
    append_field(&mut hasher, &bundle.value_balance.to_be_bytes());
    append_field(
        &mut hasher,
        &u64::try_from(bundle.actions.len())
            .expect("bounded Orchard action count fits u64")
            .to_be_bytes(),
    );
    for action in &bundle.actions {
        append_field(&mut hasher, &action.nullifier);
        append_field(&mut hasher, &action.randomized_key);
        append_field(&mut hasher, &action.note_commitment);
        append_field(&mut hasher, &action.ephemeral_key);
        append_field(&mut hasher, &action.encrypted_note);
        append_field(&mut hasher, &action.outgoing_ciphertext);
        append_field(&mut hasher, &action.value_commitment);
    }
    Ok(hasher.finalize().into())
}
fn orchard_v3_verifying_key() -> &'static VerifyingKey {
    static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
}
fn orchard_v3_proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}
/// Zeroizing deterministic bridge into the pinned rand-core 0.6 Orchard API.
///
/// The caller's complete health-checked 64-byte block is compressed into the
/// key without a plain stack seed. The retained key, nonce prefix, and unread
/// stream bytes are all zeroized when the consuming prepared bundle exits.
struct OrchardUpstreamRngV1 {
    key: Zeroizing<[u8; 32]>,
    nonce_prefix: Zeroizing<[u8; 4]>,
    reservoir: Zeroizing<[u8; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1]>,
    cursor: usize,
    next_block: u64,
    poisoned: bool,
}
/// Arms zeroization before a retained RNG state transition can unwind.
struct OrchardRngTransitionGuardV1<'a> {
    rng: &'a mut OrchardUpstreamRngV1,
    armed: bool,
}
impl<'a> OrchardRngTransitionGuardV1<'a> {
    fn new(rng: &'a mut OrchardUpstreamRngV1) -> Self {
        Self { rng, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for OrchardRngTransitionGuardV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.rng.poison_v1();
        }
    }
}
impl OrchardUpstreamRngV1 {
    fn from_entropy_v1(
        entropy: &[u8; ORCHARD_PROVER_ENTROPY_BYTES_V1],
    ) -> Result<Self, OrchardProverErrorV1> {
        let source_cipher = ChaCha20Poly1305::new_from_slice(&entropy[..32])
            .map_err(|_| OrchardProverErrorV1::RandomnessHealth)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        key[..20].copy_from_slice(&entropy[44..]);
        key[20..].copy_from_slice(&PROVER_RNG_SEED_FRAME_V1);
        let source_nonce = <&Nonce>::try_from(&entropy[32..44])
            .map_err(|_| OrchardProverErrorV1::RandomnessHealth)?;
        let mut tag = source_cipher
            .encrypt_inout_detached(
                source_nonce,
                PROVER_RNG_SEED_DOMAIN_V1,
                (&mut key[..]).into(),
            )
            .map_err(|_| OrchardProverErrorV1::RandomnessHealth)?;
        let mut nonce_prefix = Zeroizing::new([0_u8; 4]);
        nonce_prefix.copy_from_slice(&tag[..4]);
        tag.as_mut_slice().zeroize();
        Ok(Self {
            key,
            nonce_prefix,
            reservoir: Zeroizing::new([0_u8; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1]),
            cursor: ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1,
            next_block: 0,
            poisoned: false,
        })
    }
    fn poison_v1(&mut self) {
        self.key.zeroize();
        self.nonce_prefix.zeroize();
        self.reservoir.zeroize();
        self.cursor = ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1;
        self.next_block.zeroize();
        self.poisoned = true;
    }
    fn try_refill_v1(&mut self) -> Result<(), rand_core_06::Error> {
        if self.poisoned {
            return Err(orchard_upstream_rng_error_v1());
        }
        let mut transition = OrchardRngTransitionGuardV1::new(self);
        transition.rng.reservoir.zeroize();
        transition.rng.reservoir[..PROVER_RNG_STREAM_DOMAIN_V1.len()]
            .copy_from_slice(PROVER_RNG_STREAM_DOMAIN_V1);
        transition.rng.cursor = ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1;
        transition.rng.poisoned = true;
        let Some(next_block) = transition.rng.next_block.checked_add(1) else {
            return Err(orchard_upstream_rng_error_v1());
        };
        let mut nonce = Zeroizing::new([0_u8; 12]);
        nonce[..4].copy_from_slice(transition.rng.nonce_prefix.as_slice());
        nonce[4..].copy_from_slice(&transition.rng.next_block.to_be_bytes());
        transition.rng.next_block = next_block;
        let cipher = match ChaCha20Poly1305::new_from_slice(transition.rng.key.as_slice()) {
            Ok(cipher) => cipher,
            Err(_) => return Err(orchard_upstream_rng_error_v1()),
        };
        let stream_nonce = match <&Nonce>::try_from(nonce.as_slice()) {
            Ok(nonce) => nonce,
            Err(_) => return Err(orchard_upstream_rng_error_v1()),
        };
        let mut tag = match cipher.encrypt_inout_detached(
            stream_nonce,
            PROVER_RNG_STREAM_DOMAIN_V1,
            (&mut transition.rng.reservoir[..]).into(),
        ) {
            Ok(tag) => tag,
            Err(_) => return Err(orchard_upstream_rng_error_v1()),
        };
        tag.as_mut_slice().zeroize();
        transition.rng.cursor = 0;
        transition.rng.poisoned = false;
        transition.disarm();
        Ok(())
    }
    fn try_fill_canonical_v1(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        if self.poisoned {
            self.poison_v1();
            destination.zeroize();
            return Err(orchard_upstream_rng_error_v1());
        }
        let mut offset = 0;
        while offset < destination.len() {
            if self.cursor == ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1 {
                if let Err(error) = self.try_refill_v1() {
                    destination.zeroize();
                    return Err(error);
                }
            }
            let copied =
                (ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1 - self.cursor).min(destination.len() - offset);
            let end = self.cursor + copied;
            destination[offset..offset + copied].copy_from_slice(&self.reservoir[self.cursor..end]);
            self.reservoir[self.cursor..end].zeroize();
            self.cursor = end;
            offset += copied;
        }
        Ok(())
    }
}
impl Drop for OrchardUpstreamRngV1 {
    fn drop(&mut self) {
        self.poison_v1();
    }
}
impl RngCore06 for OrchardUpstreamRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.try_fill_canonical_v1(destination)
            .expect("zeroizing Orchard RNG bridge exhausted its fixed counter");
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.try_fill_canonical_v1(destination)
    }
}
impl CryptoRng06 for OrchardUpstreamRngV1 {}
fn orchard_upstream_rng_error_v1() -> rand_core_06::Error {
    rand_core_06::Error::new(OrchardProverErrorV1::RandomnessUnavailable)
}
fn map_orchard_randomness_error_v1(
    error: TryCryptoProverRandomnessErrorV1,
) -> OrchardProverErrorV1 {
    match error {
        TryCryptoProverRandomnessErrorV1::Unavailable => {
            OrchardProverErrorV1::RandomnessUnavailable
        }
        TryCryptoProverRandomnessErrorV1::Unhealthy => OrchardProverErrorV1::RandomnessHealth,
    }
}
fn seeded_upstream_rng_v1<R: rand::TryCryptoRng + ?Sized>(
    randomness: &mut R,
) -> Result<OrchardUpstreamRngV1, OrchardProverErrorV1> {
    let mut checked =
        HealthCheckedTryCryptoRngV1::new(randomness).map_err(map_orchard_randomness_error_v1)?;
    let mut entropy = Zeroizing::new([0_u8; ORCHARD_PROVER_ENTROPY_BYTES_V1]);
    checked
        .try_fill_bytes(entropy.as_mut())
        .map_err(map_orchard_randomness_error_v1)?;
    OrchardUpstreamRngV1::from_entropy_v1(&entropy)
}
fn public_draft_from_bundle_v1<T: Authorization>(bundle: &Bundle<T, i64>) -> OrchardBundleDraftV1 {
    let actions = bundle
        .actions()
        .iter()
        .map(|action| OrchardActionPublicV1 {
            nullifier: action.nullifier().to_bytes(),
            randomized_key: <[u8; 32]>::from(action.rk()),
            note_commitment: action.cmx().to_bytes(),
            ephemeral_key: action.encrypted_note().epk_bytes,
            encrypted_note: action.encrypted_note().enc_ciphertext,
            outgoing_ciphertext: action.encrypted_note().out_ciphertext,
            value_commitment: action.cv_net().to_bytes(),
        })
        .collect();
    OrchardBundleDraftV1 {
        anchor: bundle.anchor().to_bytes(),
        value_balance: *bundle.value_balance(),
        actions,
    }
}
fn encode_authorized_bundle_v1(
    bundle: &Bundle<Authorized, i64>,
    consensus_binding: PrivacyNativeConsensusBindingV1,
) -> Result<OrchardProvedBundleV1, OrchardProverErrorV1> {
    let draft = public_draft_from_bundle_v1(bundle);
    let public = OrchardBundlePublicV1 {
        consensus_binding,
        anchor: draft.anchor,
        value_balance: draft.value_balance,
        actions: draft.actions,
    };
    let expected = orchard_authorization_wire_size_v1(public.actions.len())
        .ok_or(OrchardProverErrorV1::OutputShape)?;
    let mut authorization = Vec::with_capacity(expected);
    authorization.extend_from_slice(&ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1);
    authorization
        .push(u8::try_from(public.actions.len()).map_err(|_| OrchardProverErrorV1::OutputShape)?);
    authorization.extend_from_slice(bundle.authorization().proof().as_ref());
    for action in bundle.actions().iter() {
        authorization.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }
    authorization.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));
    if authorization.len() != expected {
        return Err(OrchardProverErrorV1::OutputShape);
    }
    Ok(OrchardProvedBundleV1 {
        public,
        authorization,
    })
}
fn parse_action(
    index: usize,
    action: &OrchardActionPublicV1,
    spend_authorization_signature: [u8; ORCHARD_REDPALLAS_SIGNATURE_BYTES_V1],
) -> Result<Action<redpallas::Signature<SpendAuth>>, OrchardNativeErrorV1> {
    let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&action.nullifier))
        .ok_or(OrchardNativeErrorV1::NullifierEncoding { index })?;
    let randomized_key = redpallas::VerificationKey::<SpendAuth>::try_from(action.randomized_key)
        .map_err(|_| OrchardNativeErrorV1::RandomizedKeyEncoding { index })?;
    let note_commitment = Option::<ExtractedNoteCommitment>::from(
        ExtractedNoteCommitment::from_bytes(&action.note_commitment),
    )
    .ok_or(OrchardNativeErrorV1::NoteCommitmentEncoding { index })?;
    let value_commitment =
        Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&action.value_commitment))
            .ok_or(OrchardNativeErrorV1::ValueCommitmentEncoding { index })?;
    Action::from_parts(
        nullifier,
        randomized_key,
        note_commitment,
        TransmittedNoteCiphertext {
            epk_bytes: action.ephemeral_key,
            enc_ciphertext: action.encrypted_note,
            out_ciphertext: action.outgoing_ciphertext,
        },
        value_commitment,
        redpallas::Signature::<SpendAuth>::from(spend_authorization_signature),
    )
    .map_err(|_| OrchardNativeErrorV1::ActionEncoding { index })
}
/// Prepare one Post-NU6.3 Orchard bundle with injected fallible entropy.
///
/// `minimum_action_count` is the privacy-padding floor and must be one or two. Every real spend and
/// every wallet-controlled change consumes one action because the pinned V3 profile disables
/// cross-address transfers. Randomized public actions and the Halo2 proof are finalized here,
/// before a transaction intent exists. Callers must construct that intent from
/// [`OrchardPreparedBundleV1::public_draft`] and then consume the prepared state with
/// [`authorize_orchard_bundle_v1`].
///
/// # Errors
///
/// Rejects malformed anchors, empty or oversized requests, inconsistent
/// key/note/path tuples, invalid change ownership, entropy failure or obvious
/// repeated entropy, value-balance overflow, or proof construction failure.
pub fn prepare_orchard_bundle_v1_with_rng<R: rand::TryCryptoRng + ?Sized>(
    anchor: [u8; 32],
    spends: Vec<OrchardSpendProverInputV1>,
    changes: Vec<OrchardChangeProverInputV1>,
    minimum_action_count: u8,
    randomness: &mut R,
) -> Result<OrchardPreparedBundleV1, OrchardProverErrorV1> {
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(anchor))
        .ok_or(OrchardProverErrorV1::AnchorEncoding)?;
    let requested_actions =
        spends
            .len()
            .checked_add(changes.len())
            .ok_or(OrchardProverErrorV1::ActionCount {
                actual: usize::MAX,
                max: ORCHARD_MAX_ACTIONS_V1,
            })?;
    if requested_actions == 0 {
        return Err(OrchardProverErrorV1::EmptyOperation);
    }
    if requested_actions > ORCHARD_MAX_ACTIONS_V1 {
        return Err(OrchardProverErrorV1::ActionCount {
            actual: requested_actions,
            max: ORCHARD_MAX_ACTIONS_V1,
        });
    }
    if minimum_action_count == 0 || usize::from(minimum_action_count) > ORCHARD_MAX_ACTIONS_V1 {
        return Err(OrchardProverErrorV1::MinimumActionCount {
            actual: minimum_action_count,
            max: ORCHARD_MAX_ACTIONS_V1,
        });
    }
    let expected_actions = requested_actions.max(usize::from(minimum_action_count));
    let version = BundleVersion::orchard_v3();
    let mut builder = Builder::new(
        BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: Some(minimum_action_count),
        },
        version,
        Flags::CROSS_ADDRESS_DISABLED,
        anchor,
    )
    .map_err(|_| OrchardProverErrorV1::BundleConstruction)?;
    let mut signing_keys = Vec::with_capacity(requested_actions);
    for (
        index,
        OrchardSpendProverInputV1 {
            spending_key,
            note,
            merkle_path,
        },
    ) in spends.into_iter().enumerate()
    {
        let viewing_key = FullViewingKey::from(&spending_key);
        let signing_key = SpendAuthorizingKey::from(&spending_key);
        builder
            .add_spend(viewing_key, note, merkle_path)
            .map_err(|_| OrchardProverErrorV1::SpendInput { index })?;
        signing_keys.push(signing_key);
    }
    for (
        index,
        OrchardChangeProverInputV1 {
            spending_key,
            scope,
            diversifier_index,
            value,
            memo,
        },
    ) in changes.into_iter().enumerate()
    {
        let viewing_key = FullViewingKey::from(&spending_key);
        let recipient = viewing_key.address_at(diversifier_index, scope);
        let outgoing_viewing_key = viewing_key.to_ovk(scope);
        let signing_key = SpendAuthorizingKey::from(&spending_key);
        builder
            .add_change_output(
                viewing_key,
                Some(outgoing_viewing_key),
                recipient,
                NoteValue::from_raw(value),
                memo,
            )
            .map_err(|_| OrchardProverErrorV1::ChangeInput { index })?;
        signing_keys.push(signing_key);
    }
    // The pinned upstream Orchard crate consumes the rand-core 0.6 traits and
    // exposes infallible `fill_bytes` internally. Seed one in-memory CSPRNG only
    // after all deterministic input checks, so operating-system entropy failure
    // remains a typed error and cannot become a panic halfway through proving.
    let mut upstream_rng = seeded_upstream_rng_v1(randomness)?;
    let (unsigned, _) = builder
        .build::<i64>(&mut upstream_rng)
        .map_err(|_| OrchardProverErrorV1::BundleConstruction)?
        .ok_or(OrchardProverErrorV1::BundleConstruction)?;
    if unsigned.actions().len() != expected_actions
        || unsigned.actions().len() > ORCHARD_MAX_ACTIONS_V1
    {
        return Err(OrchardProverErrorV1::OutputShape);
    }
    let proven = unsigned
        .create_proof(orchard_v3_proving_key(), &mut upstream_rng)
        .map_err(|_| OrchardProverErrorV1::Halo2Proof)?;
    let draft = public_draft_from_bundle_v1(&proven);
    Ok(OrchardPreparedBundleV1 {
        proven,
        signing_keys,
        upstream_rng,
        draft,
    })
}
/// Prepare one Post-NU6.3 Orchard bundle using operating-system entropy.
///
/// # Errors
///
/// Returns the same closed set of typed failures as [`prepare_orchard_bundle_v1_with_rng`].
pub fn prepare_orchard_bundle_v1(
    anchor: [u8; 32],
    spends: Vec<OrchardSpendProverInputV1>,
    changes: Vec<OrchardChangeProverInputV1>,
    minimum_action_count: u8,
) -> Result<OrchardPreparedBundleV1, OrchardProverErrorV1> {
    prepare_orchard_bundle_v1_with_rng(
        anchor,
        spends,
        changes,
        minimum_action_count,
        &mut rand::rngs::OsRng,
    )
}
/// Consume a prepared bundle and authorize its exact randomized public actions.
///
/// The prepared proof, signing keys, and already-advanced in-memory prover RNG
/// are moved into this call. There is no API that can clone or replay them.
///
/// ```compile_fail
/// use iroha_core_privacy::privacy_engines::orchard::{
///     OrchardPreparedBundleV1, authorize_orchard_bundle_v1,
/// };
/// use iroha_data_model::privacy::{
///     PrivacyConsensusLimitsV1, PrivacyNativeConsensusBindingV1,
/// };
///
/// fn double_authorize(
///     prepared: OrchardPreparedBundleV1,
///     binding: PrivacyNativeConsensusBindingV1,
///     limits: &PrivacyConsensusLimitsV1,
/// ) {
///     authorize_orchard_bundle_v1(prepared, binding.clone(), limits).unwrap();
///     authorize_orchard_bundle_v1(prepared, binding, limits).unwrap();
/// }
/// ```
///
/// # Errors
///
/// Rejects a malformed mandatory consensus binding, canonical binding-digest failure,
/// signing/encoding failure, or any result rejected by the independent production verifier.
pub fn authorize_orchard_bundle_v1(
    prepared: OrchardPreparedBundleV1,
    consensus_binding: PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
) -> Result<OrchardProvedBundleV1, OrchardProverErrorV1> {
    consensus_binding
        .validate(consensus_limits)
        .map_err(|_| OrchardProverErrorV1::ConsensusBinding)?;
    let public = OrchardBundlePublicV1 {
        consensus_binding: consensus_binding.clone(),
        anchor: prepared.draft.anchor,
        value_balance: prepared.draft.value_balance,
        actions: prepared.draft.actions.clone(),
    };
    let sighash =
        derive_orchard_bundle_sighash_v1(&public, consensus_limits).map_err(
            |error| match error {
                OrchardNativeErrorV1::ConsensusBinding => OrchardProverErrorV1::ConsensusBinding,
                OrchardNativeErrorV1::ConsensusBindingEncoding => {
                    OrchardProverErrorV1::ConsensusBindingEncoding
                }
                _ => OrchardProverErrorV1::OutputShape,
            },
        )?;
    let mut upstream_rng = prepared.upstream_rng;
    let authorized = prepared
        .proven
        .apply_signatures(&mut upstream_rng, sighash, &prepared.signing_keys)
        .map_err(|_| OrchardProverErrorV1::Authorization)?;
    let proved = encode_authorized_bundle_v1(&authorized, consensus_binding)?;
    if proved.public != public {
        return Err(OrchardProverErrorV1::OutputShape);
    }
    verify_orchard_bundle_v1(&proved.public, &proved.authorization, consensus_limits)
        .map_err(|_| OrchardProverErrorV1::SelfCheck)?;
    Ok(proved)
}
/// Verify one complete first-release Orchard V3 bundle.
///
/// # Errors
///
/// Returns a typed failure for malformed encodings, count/size violations,
/// invalid RedPallas signatures, or an invalid Post-NU6.3 Halo2 proof.
pub fn verify_orchard_bundle_v1(
    public: &OrchardBundlePublicV1,
    proof_bytes: &[u8],
    consensus_limits: &PrivacyConsensusLimitsV1,
) -> Result<(), OrchardNativeErrorV1> {
    public
        .consensus_binding
        .validate(consensus_limits)
        .map_err(|_| OrchardNativeErrorV1::ConsensusBinding)?;
    if public.actions.is_empty() || public.actions.len() > ORCHARD_MAX_ACTIONS_V1 {
        return Err(OrchardNativeErrorV1::ActionCount {
            actual: public.actions.len(),
            max: ORCHARD_MAX_ACTIONS_V1,
        });
    }
    let authorization = decode_authorization_wire_v1(proof_bytes, public.actions.len())?;
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(public.anchor))
        .ok_or(OrchardNativeErrorV1::AnchorEncoding)?;
    let actions = public
        .actions
        .iter()
        .zip(authorization.spend_authorization_signatures)
        .enumerate()
        .map(|(index, (action, signature))| parse_action(index, action, signature))
        .collect::<Result<Vec<_>, _>>()?;
    let actions = NonEmpty::from_vec(actions).ok_or(OrchardNativeErrorV1::ActionCount {
        actual: 0,
        max: ORCHARD_MAX_ACTIONS_V1,
    })?;
    let authorization = Authorized::from_parts(
        Proof::new(authorization.halo2_proof.to_vec()),
        redpallas::Signature::<Binding>::from(authorization.binding_signature),
    );
    let bundle = Bundle::try_from_parts(
        actions,
        Flags::CROSS_ADDRESS_DISABLED,
        public.value_balance,
        anchor,
        authorization,
        BundleVersion::orchard_v3(),
    )
    .map_err(|_| OrchardNativeErrorV1::BundleEncoding)?;
    let sighash = derive_orchard_bundle_sighash_v1(public, consensus_limits)?;
    for (index, action) in bundle.actions().iter().enumerate() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .map_err(|_| OrchardNativeErrorV1::SpendAuthorizationSignature { index })?;
    }
    bundle
        .binding_validating_key()
        .verify(&sighash, bundle.authorization().binding_signature())
        .map_err(|_| OrchardNativeErrorV1::BindingSignature)?;
    bundle
        .verify_proof(orchard_v3_verifying_key())
        .map_err(|_| OrchardNativeErrorV1::Halo2Proof)
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        NetworkId,
        block::BlockHeader,
        privacy::{
            PrivacyEngineManifestDigestV1, PrivacyNativeConsensusBindingValidationErrorV1,
            PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyStatementContextV1,
            PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1,
            PrivacyVerifierDigestV1,
        },
    };
    use orchard::{
        Anchor,
        builder::{Builder, BundleType},
        bundle::BundleVersion,
    };
    use rand_08::{SeedableRng as _, rngs::StdRng};
    use std::sync::OnceLock;
    fn consensus_limits() -> PrivacyConsensusLimitsV1 {
        PrivacyConsensusLimitsV1::taira_default()
    }
    fn consensus_binding(seed: u8) -> PrivacyNativeConsensusBindingV1 {
        let genesis_hash = Hash::prehashed([seed.wrapping_add(6); 32]);
        let context = PrivacyStatementContextV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(genesis_hash),
            ),
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([seed; 32]),
            parameter_id: PrivacyParameterIdV1::new([seed.wrapping_add(1); 32]),
            parameter_digest: PrivacyParameterDigestV1::new([seed.wrapping_add(2); 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([seed.wrapping_add(3); 32]),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(
                [seed.wrapping_add(4); 32],
            ),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new([seed.wrapping_add(5); 32]),
        };
        PrivacyNativeConsensusBindingV1::new(&context, genesis_hash.into(), &consensus_limits())
            .expect("canonical Orchard test binding")
    }
    #[test]
    fn consensus_fixture_binds_the_canonical_genesis_bytes() {
        let limits = consensus_limits();
        for seed in [0x44_u8, 0x55, 0x66, 0x6A, 0x72, 0x73, 0xFA] {
            let binding = consensus_binding(seed);
            let mut expected = [seed.wrapping_add(6); 32];
            expected[31] |= 1;
            assert_eq!(binding.genesis_hash, expected);
            assert_eq!(binding.network_id.as_bytes(), &expected);
            assert_eq!(binding.validate(&limits), Ok(()));
            if seed.wrapping_add(6) & 1 == 0 {
                let mut unmarked = binding;
                unmarked.genesis_hash[31] &= !1;
                let expected_error = if unmarked.genesis_hash == [0; 32] {
                    PrivacyNativeConsensusBindingValidationErrorV1::ZeroGenesisHash
                } else {
                    PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch
                };
                assert_eq!(unmarked.validate(&limits), Err(expected_error));
            }
        }
    }
    pub(crate) fn build_fixture(
        action_count: u8,
        rng_seed: [u8; 32],
        consensus_binding: PrivacyNativeConsensusBindingV1,
    ) -> (OrchardBundlePublicV1, Vec<u8>) {
        let version = BundleVersion::orchard_v3();
        let mut rng = StdRng::from_seed(rng_seed);
        let builder = Builder::new(
            BundleType::Transactional {
                bundle_required: true,
                pad_to_minimum: Some(action_count),
            },
            version,
            version.default_flags(),
            Anchor::empty_tree(),
        )
        .expect("pinned Orchard V3 builder");
        let unsigned = builder
            .build::<i64>(&mut rng)
            .expect("build dummy action")
            .expect("bundle required")
            .0;
        let proven = unsigned
            .create_proof(orchard_v3_proving_key(), &mut rng)
            .expect("create Post-NU6.3 proof");
        // Sign the exact Iroha framing rather than an unbound caller
        // message. Signatures are applied after deriving it from the
        // proof-independent public action bytes.
        let draft = public_draft_from_bundle_v1(&proven);
        let raw = OrchardBundlePublicV1 {
            consensus_binding: consensus_binding.clone(),
            anchor: draft.anchor,
            value_balance: draft.value_balance,
            actions: draft.actions,
        };
        let sighash = derive_orchard_bundle_sighash_v1(&raw, &consensus_limits())
            .expect("derive canonical Orchard signature hash");
        let authorized = proven
            .apply_signatures(&mut rng, sighash, &[])
            .expect("apply canonical Orchard signatures");
        let proved = encode_authorized_bundle_v1(&authorized, consensus_binding)
            .expect("encode canonical Orchard authorization");
        (proved.public, proved.authorization)
    }
    pub(crate) fn fixture() -> &'static (OrchardBundlePublicV1, Vec<u8>) {
        static FIXTURE: OnceLock<(OrchardBundlePublicV1, Vec<u8>)> = OnceLock::new();
        FIXTURE.get_or_init(|| build_fixture(1, [0xA7; 32], consensus_binding(0x44)))
    }
    fn two_action_fixture() -> &'static (OrchardBundlePublicV1, Vec<u8>) {
        static FIXTURE: OnceLock<(OrchardBundlePublicV1, Vec<u8>)> = OnceLock::new();
        FIXTURE.get_or_init(|| build_fixture(2, [0xB8; 32], consensus_binding(0x55)))
    }
    fn alternate_one_action_fixture() -> &'static (OrchardBundlePublicV1, Vec<u8>) {
        static FIXTURE: OnceLock<(OrchardBundlePublicV1, Vec<u8>)> = OnceLock::new();
        FIXTURE.get_or_init(|| build_fixture(1, [0xC9; 32], consensus_binding(0x66)))
    }
    #[derive(Clone, Copy)]
    enum ProverEntropyModeV1 {
        Healthy,
        Constant,
        ConstantLeftHalf,
        ConstantRightHalf,
        Period(usize),
        Fail,
    }
    #[derive(Debug)]
    struct ProverEntropyErrorV1;
    impl core::fmt::Display for ProverEntropyErrorV1 {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected Orchard prover entropy failure")
        }
    }
    struct ProverEntropyRngV1(ProverEntropyModeV1);
    impl rand::TryRngCore for ProverEntropyRngV1 {
        type Error = ProverEntropyErrorV1;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0_u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0_u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            match self.0 {
                ProverEntropyModeV1::Healthy => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(73).wrapping_add(19);
                    }
                    Ok(())
                }
                ProverEntropyModeV1::Constant => {
                    destination.fill(0xA5);
                    Ok(())
                }
                ProverEntropyModeV1::ConstantLeftHalf => {
                    let half = destination.len() / 2;
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = if index < half {
                            0xA5
                        } else {
                            (index as u8).wrapping_mul(73).wrapping_add(19)
                        };
                    }
                    Ok(())
                }
                ProverEntropyModeV1::ConstantRightHalf => {
                    let half = destination.len() / 2;
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = if index < half {
                            (index as u8).wrapping_mul(73).wrapping_add(19)
                        } else {
                            0x5A
                        };
                    }
                    Ok(())
                }
                ProverEntropyModeV1::Period(period) => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = ((index % period) as u8).wrapping_mul(29).wrapping_add(7);
                    }
                    Ok(())
                }
                ProverEntropyModeV1::Fail => {
                    let partial = destination.len() / 2;
                    destination
                        .iter_mut()
                        .take(partial)
                        .enumerate()
                        .for_each(|(index, byte)| *byte = index as u8);
                    Err(ProverEntropyErrorV1)
                }
            }
        }
    }
    impl rand::TryCryptoRng for ProverEntropyRngV1 {}
    struct RecordingEntropyRngV1 {
        cursor: usize,
        requests: Vec<usize>,
    }
    impl RecordingEntropyRngV1 {
        fn new() -> Self {
            Self {
                cursor: 0,
                requests: Vec::new(),
            }
        }
    }
    impl rand::TryRngCore for RecordingEntropyRngV1 {
        type Error = ProverEntropyErrorV1;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0_u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0_u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.requests.push(destination.len());
            for byte in destination {
                *byte = (self.cursor as u8).wrapping_mul(73).wrapping_add(19);
                self.cursor += 1;
            }
            Ok(())
        }
    }
    impl rand::TryCryptoRng for RecordingEntropyRngV1 {}
    struct PanicEntropyRngV1 {
        requests: usize,
    }
    impl rand::TryRngCore for PanicEntropyRngV1 {
        type Error = ProverEntropyErrorV1;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("deterministically invalid input reached entropy")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("deterministically invalid input reached entropy")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.requests += 1;
            let partial = destination.len() / 2;
            for (index, byte) in destination.iter_mut().take(partial).enumerate() {
                *byte = index as u8;
            }
            panic!("deterministically invalid input reached entropy")
        }
    }
    impl rand::TryCryptoRng for PanicEntropyRngV1 {}
    fn spending_key(seed: u8) -> SpendingKey {
        (1_u8..=u8::MAX)
            .find_map(|counter| {
                let mut bytes = [seed; 32];
                bytes[0] = counter;
                bytes[15] = counter.rotate_left(3);
                bytes[31] = seed ^ counter.rotate_right(1);
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .expect("at least one deterministic Orchard spending key")
    }
    struct WalletSpendPartsV1 {
        spending_key: [u8; 32],
        recipient: [u8; 43],
        value: u64,
        rho: [u8; 32],
        random_seed: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; ORCHARD_TREE_DEPTH_V1 as usize],
        anchor: [u8; 32],
    }
    fn wallet_spend_parts(spending_key_seed: u8, recipient_key_seed: u8) -> WalletSpendPartsV1 {
        let sender_spending_key = spending_key(spending_key_seed);
        let recipient_key = spending_key(recipient_key_seed);
        let recipient = FullViewingKey::from(&recipient_key).address_at(17_u32, Scope::External);
        let recipient_bytes = recipient.to_raw_address_bytes();
        let rho_bytes = [3; 32];
        let rho =
            Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).expect("small canonical Orchard rho");
        let random_seed_bytes = [4; 32];
        let random_seed =
            Option::<RandomSeed>::from(RandomSeed::from_bytes(random_seed_bytes, &rho))
                .expect("deterministic valid Orchard random seed");
        let value = 23;
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            random_seed,
            NoteVersion::V2,
        ))
        .expect("canonical Orchard wallet note");
        let authentication_path = [[0; 32]; ORCHARD_TREE_DEPTH_V1 as usize];
        let merkle_path = MerklePath::from_parts(
            9,
            authentication_path.map(|bytes| {
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
                    .expect("zero is a canonical Orchard path element")
            }),
        );
        let anchor = merkle_path
            .root(ExtractedNoteCommitment::from(note.commitment()))
            .to_bytes();
        WalletSpendPartsV1 {
            spending_key: *sender_spending_key.to_bytes(),
            recipient: recipient_bytes,
            value,
            rho: rho_bytes,
            random_seed: random_seed_bytes,
            leaf_position: 9,
            authentication_path,
            anchor,
        }
    }
    fn change_input(seed: u8, value: u64) -> OrchardChangeProverInputV1 {
        OrchardChangeProverInputV1::new(
            spending_key(seed),
            Scope::External,
            u32::from(seed),
            value,
            [seed; 512],
        )
    }
    #[test]
    fn wallet_spend_constructor_binds_key_note_path_and_retained_anchor() {
        let valid = wallet_spend_parts(0x31, 0x31);
        OrchardSpendProverInputV1::from_wallet_parts_v1(
            valid.spending_key,
            valid.recipient,
            valid.value,
            valid.rho,
            valid.random_seed,
            valid.leaf_position,
            valid.authentication_path,
            valid.anchor,
        )
        .expect("complete wallet spend opens the retained anchor");
        let wrong_owner = wallet_spend_parts(0x31, 0x32);
        assert_eq!(
            OrchardSpendProverInputV1::from_wallet_parts_v1(
                wrong_owner.spending_key,
                wrong_owner.recipient,
                wrong_owner.value,
                wrong_owner.rho,
                wrong_owner.random_seed,
                wrong_owner.leaf_position,
                wrong_owner.authentication_path,
                wrong_owner.anchor,
            )
            .expect_err("a foreign recipient must fail before proving"),
            OrchardSpendInputErrorV1::RecipientOwnership
        );
        let stale = wallet_spend_parts(0x33, 0x33);
        let mut stale_anchor = stale.anchor;
        stale_anchor[0] ^= 1;
        assert_eq!(
            OrchardSpendProverInputV1::from_wallet_parts_v1(
                stale.spending_key,
                stale.recipient,
                stale.value,
                stale.rho,
                stale.random_seed,
                stale.leaf_position,
                stale.authentication_path,
                stale_anchor,
            )
            .expect_err("a stale retained anchor must fail"),
            OrchardSpendInputErrorV1::AnchorMismatch
        );
        let malformed_path = wallet_spend_parts(0x34, 0x34);
        let mut authentication_path = malformed_path.authentication_path;
        authentication_path[7] = [u8::MAX; 32];
        assert_eq!(
            OrchardSpendProverInputV1::from_wallet_parts_v1(
                malformed_path.spending_key,
                malformed_path.recipient,
                malformed_path.value,
                malformed_path.rho,
                malformed_path.random_seed,
                malformed_path.leaf_position,
                authentication_path,
                malformed_path.anchor,
            )
            .expect_err("a noncanonical path element must fail"),
            OrchardSpendInputErrorV1::AuthenticationPath { index: 7 }
        );
        let malformed_recipient = wallet_spend_parts(0x35, 0x35);
        assert_eq!(
            OrchardSpendProverInputV1::from_wallet_parts_v1(
                malformed_recipient.spending_key,
                [u8::MAX; 43],
                malformed_recipient.value,
                malformed_recipient.rho,
                malformed_recipient.random_seed,
                malformed_recipient.leaf_position,
                malformed_recipient.authentication_path,
                malformed_recipient.anchor,
            )
            .expect_err("a noncanonical recipient must fail"),
            OrchardSpendInputErrorV1::Recipient
        );
        let malformed_rho = wallet_spend_parts(0x36, 0x36);
        assert_eq!(
            OrchardSpendProverInputV1::from_wallet_parts_v1(
                malformed_rho.spending_key,
                malformed_rho.recipient,
                malformed_rho.value,
                [u8::MAX; 32],
                malformed_rho.random_seed,
                malformed_rho.leaf_position,
                malformed_rho.authentication_path,
                malformed_rho.anchor,
            )
            .expect_err("a noncanonical rho must fail"),
            OrchardSpendInputErrorV1::Rho
        );
    }
    fn production_prover_fixture() -> &'static OrchardProvedBundleV1 {
        static FIXTURE: OnceLock<OrchardProvedBundleV1> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let prepared = prepare_orchard_bundle_v1_with_rng(
                orchard_empty_root_v1(),
                Vec::new(),
                vec![change_input(0x31, 17)],
                ORCHARD_MAX_ACTIONS_V1 as u8,
                &mut ProverEntropyRngV1(ProverEntropyModeV1::Healthy),
            )
            .expect("prepare production Orchard proof");
            authorize_orchard_bundle_v1(prepared, consensus_binding(0x6A), &consensus_limits())
                .expect("authorize production Orchard proof")
        })
    }
    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
    fn public_bytes_for_kat(public: &OrchardBundlePublicV1) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            public
                .consensus_binding
                .digest()
                .expect("canonical binding digest")
                .as_bytes(),
        );
        bytes.extend_from_slice(&public.anchor);
        bytes.extend_from_slice(&public.value_balance.to_be_bytes());
        bytes.push(u8::try_from(public.actions.len()).expect("bounded action count"));
        for action in &public.actions {
            bytes.extend_from_slice(&action.nullifier);
            bytes.extend_from_slice(&action.randomized_key);
            bytes.extend_from_slice(&action.note_commitment);
            bytes.extend_from_slice(&action.ephemeral_key);
            bytes.extend_from_slice(&action.encrypted_note);
            bytes.extend_from_slice(&action.outgoing_ciphertext);
            bytes.extend_from_slice(&action.value_commitment);
        }
        bytes
    }
    #[test]
    fn deterministic_public_and_authorization_known_answers_are_stable() {
        let (public, authorization) = fixture();
        // Pin the genesis-derived NetworkId and identical canonical genesis bytes.
        assert_eq!(
            (
                hex::encode(
                    derive_orchard_bundle_sighash_v1(public, &consensus_limits())
                        .expect("canonical Orchard signature hash"),
                ),
                sha256_hex(&public_bytes_for_kat(public)),
                sha256_hex(authorization),
            ),
            (
                "6e6c49cd734cb573fb7a506816dc8ca09febd4b219279b9e68d68ef11320543e".to_owned(),
                "9707670460bcc99e65052e24b5919c8edcdd2822ba360b1eda20430095cd320b".to_owned(),
                "96091d8cc928d74fd94778b6a293d3b58b7961f40e99dbb1d0d061c1b1738fca".to_owned(),
            )
        );
    }
    #[test]
    fn production_prover_builds_change_signs_encodes_and_self_verifies() {
        let proved = production_prover_fixture();
        assert_eq!(proved.public.actions.len(), ORCHARD_MAX_ACTIONS_V1);
        assert_eq!(proved.public.value_balance, -17);
        assert_eq!(
            proved.authorization.len(),
            orchard_authorization_wire_size_v1(ORCHARD_MAX_ACTIONS_V1)
                .expect("maximum-action wire")
        );
        verify_orchard_bundle_v1(&proved.public, &proved.authorization, &consensus_limits())
            .expect("production output independently verifies");
        let mut changed_public = proved.public.clone();
        changed_public.actions[0].encrypted_note[317] ^= 0x80;
        assert!(
            verify_orchard_bundle_v1(&changed_public, &proved.authorization, &consensus_limits())
                .is_err()
        );
        let mut changed_authorization = proved.authorization.clone();
        let middle = changed_authorization.len() / 2;
        changed_authorization[middle] ^= 1;
        assert!(
            verify_orchard_bundle_v1(&proved.public, &changed_authorization, &consensus_limits())
                .is_err()
        );
    }
    #[test]
    fn prepare_finalizes_exact_actions_before_consuming_authorization() {
        let mut entropy = RecordingEntropyRngV1::new();
        let prepared = prepare_orchard_bundle_v1_with_rng(
            orchard_empty_root_v1(),
            Vec::new(),
            vec![change_input(0x37, 23)],
            1,
            &mut entropy,
        )
        .expect("prepare randomized Orchard actions and proof");
        assert_eq!(entropy.requests, [ORCHARD_PROVER_ENTROPY_BYTES_V1]);
        let draft = prepared.public_draft().clone();
        assert_eq!(draft.actions.len(), 1);
        assert_eq!(draft.value_balance, -23);
        let binding = consensus_binding(0x72);
        let proved = authorize_orchard_bundle_v1(prepared, binding.clone(), &consensus_limits())
            .expect("consume prepared state and authorize exact actions");
        assert_eq!(
            entropy.requests,
            [ORCHARD_PROVER_ENTROPY_BYTES_V1],
            "authorization must continue the retained zeroizing bridge without re-entering caller entropy"
        );
        assert_eq!(proved.public.consensus_binding, binding);
        assert_eq!(proved.public.anchor, draft.anchor);
        assert_eq!(proved.public.value_balance, draft.value_balance);
        assert_eq!(proved.public.actions, draft.actions);
        verify_orchard_bundle_v1(&proved.public, &proved.authorization, &consensus_limits())
            .expect("authorized exact draft verifies");
    }
    #[test]
    fn authorize_consumes_and_rejects_a_malformed_mandatory_binding() {
        let prepared = prepare_orchard_bundle_v1_with_rng(
            orchard_empty_root_v1(),
            Vec::new(),
            vec![change_input(0x38, 29)],
            1,
            &mut ProverEntropyRngV1(ProverEntropyModeV1::Healthy),
        )
        .expect("prepare randomized Orchard actions and proof");
        let mut invalid_binding = consensus_binding(0x73);
        invalid_binding.genesis_hash = [0; 32];
        assert_eq!(
            authorize_orchard_bundle_v1(prepared, invalid_binding, &consensus_limits())
                .expect_err("zero genesis must fail before authorization"),
            OrchardProverErrorV1::ConsensusBinding
        );
    }
    #[test]
    fn production_prover_rejects_invalid_shape_before_requesting_entropy() {
        let anchor = orchard_empty_root_v1();
        let mut panic_rng = PanicEntropyRngV1 { requests: 0 };
        assert_eq!(
            prepare_orchard_bundle_v1_with_rng(
                [u8::MAX; 32],
                Vec::new(),
                vec![change_input(1, 1)],
                1,
                &mut panic_rng,
            )
            .expect_err("non-canonical anchor"),
            OrchardProverErrorV1::AnchorEncoding
        );
        assert_eq!(
            prepare_orchard_bundle_v1_with_rng(anchor, Vec::new(), Vec::new(), 1, &mut panic_rng,)
                .expect_err("empty operation"),
            OrchardProverErrorV1::EmptyOperation
        );
        assert_eq!(
            prepare_orchard_bundle_v1_with_rng(
                anchor,
                Vec::new(),
                vec![change_input(1, 1), change_input(2, 2), change_input(3, 3),],
                1,
                &mut panic_rng,
            )
            .expect_err("three requested actions"),
            OrchardProverErrorV1::ActionCount {
                actual: 3,
                max: ORCHARD_MAX_ACTIONS_V1,
            }
        );
        for minimum in [0, 3, u8::MAX] {
            assert_eq!(
                prepare_orchard_bundle_v1_with_rng(
                    anchor,
                    Vec::new(),
                    vec![change_input(1, 1)],
                    minimum,
                    &mut panic_rng,
                )
                .expect_err("invalid padding floor"),
                OrchardProverErrorV1::MinimumActionCount {
                    actual: minimum,
                    max: ORCHARD_MAX_ACTIONS_V1,
                }
            );
        }
        assert_eq!(panic_rng.requests, 0);
    }
    #[test]
    fn production_prover_randomness_failures_are_typed_and_fail_closed() {
        let anchor = orchard_empty_root_v1();
        for (mode, expected) in [
            (
                ProverEntropyModeV1::Fail,
                OrchardProverErrorV1::RandomnessUnavailable,
            ),
            (
                ProverEntropyModeV1::Constant,
                OrchardProverErrorV1::RandomnessHealth,
            ),
            (
                ProverEntropyModeV1::ConstantLeftHalf,
                OrchardProverErrorV1::RandomnessHealth,
            ),
            (
                ProverEntropyModeV1::ConstantRightHalf,
                OrchardProverErrorV1::RandomnessHealth,
            ),
        ] {
            let error = prepare_orchard_bundle_v1_with_rng(
                anchor,
                Vec::new(),
                vec![change_input(0x41, 9)],
                1,
                &mut ProverEntropyRngV1(mode),
            )
            .expect_err("unhealthy entropy must not produce an artifact");
            assert_eq!(error, expected);
        }
        for period in [1, 2, 4, 8, 16, 32] {
            assert_eq!(
                prepare_orchard_bundle_v1_with_rng(
                    anchor,
                    Vec::new(),
                    vec![change_input(0x42, 11)],
                    1,
                    &mut ProverEntropyRngV1(ProverEntropyModeV1::Period(period)),
                )
                .expect_err("short-period entropy must not produce an artifact"),
                OrchardProverErrorV1::RandomnessHealth,
                "period-{period} entropy was not rejected"
            );
        }
    }
    #[test]
    fn caller_entropy_unwind_does_not_construct_reusable_prepared_state() {
        let mut entropy = PanicEntropyRngV1 { requests: 0 };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prepare_orchard_bundle_v1_with_rng(
                    orchard_empty_root_v1(),
                    Vec::new(),
                    vec![change_input(0x43, 13)],
                    1,
                    &mut entropy,
                )
                .ok();
            }))
            .is_err()
        );
        assert_eq!(entropy.requests, 1);
    }
    #[test]
    fn upstream_bridge_is_partition_invariant_and_fail_closed_after_zeroization() {
        let mut first_source = RecordingEntropyRngV1::new();
        let mut second_source = RecordingEntropyRngV1::new();
        let mut first = seeded_upstream_rng_v1(&mut first_source).expect("healthy source");
        let mut second = seeded_upstream_rng_v1(&mut second_source).expect("healthy source");
        assert_eq!(first_source.requests, [ORCHARD_PROVER_ENTROPY_BYTES_V1]);
        assert_eq!(second_source.requests, [ORCHARD_PROVER_ENTROPY_BYTES_V1]);
        let mut expected = [0_u8; 257];
        first.fill_bytes(&mut expected);
        let mut actual = [0_u8; 257];
        second.fill_bytes(&mut actual[..13]);
        second.fill_bytes(&mut actual[13..191]);
        second.fill_bytes(&mut actual[191..]);
        assert_eq!(actual, expected);
        second.poison_v1();
        assert_eq!(*second.key, [0; 32]);
        assert_eq!(*second.nonce_prefix, [0; 4]);
        assert_eq!(*second.reservoir, [0; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1]);
        let mut destination = [0xA5; 32];
        assert!(second.try_fill_bytes(&mut destination).is_err());
        assert_eq!(destination, [0; 32]);
        let mut unwind_source = RecordingEntropyRngV1::new();
        let mut unwinding = seeded_upstream_rng_v1(&mut unwind_source).expect("healthy source");
        let mut first_byte = [0_u8; 1];
        unwinding.fill_bytes(&mut first_byte);
        assert_ne!(*unwinding.key, [0; 32]);
        assert!(unwinding.reservoir.iter().any(|byte| *byte != 0));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _transition = OrchardRngTransitionGuardV1::new(&mut unwinding);
                panic!("injected retained Orchard RNG transition unwind");
            }))
            .is_err()
        );
        assert_eq!(*unwinding.key, [0; 32]);
        assert_eq!(*unwinding.nonce_prefix, [0; 4]);
        assert_eq!(
            *unwinding.reservoir,
            [0; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1]
        );
        assert!(unwinding.poisoned);
        let mut exhausted_source = RecordingEntropyRngV1::new();
        let mut exhausted = seeded_upstream_rng_v1(&mut exhausted_source).expect("healthy source");
        let mut consumed_prefix = [0_u8; 60];
        exhausted.fill_bytes(&mut consumed_prefix);
        exhausted.next_block = u64::MAX;
        let mut destination = [0x5A; 32];
        assert!(exhausted.try_fill_bytes(&mut destination).is_err());
        assert_eq!(destination, [0; 32]);
        assert_eq!(*exhausted.key, [0; 32]);
        assert_eq!(*exhausted.nonce_prefix, [0; 4]);
        assert_eq!(
            *exhausted.reservoir,
            [0; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1]
        );
        assert!(exhausted.poisoned);
    }
    #[test]
    fn upstream_bridge_output_is_bound_to_every_entropy_byte() {
        let entropy = core::array::from_fn(|index| (index as u8).wrapping_mul(73).wrapping_add(19));
        let mut baseline_rng =
            OrchardUpstreamRngV1::from_entropy_v1(&entropy).expect("fixed entropy shape");
        let mut baseline = [0_u8; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1];
        baseline_rng.fill_bytes(&mut baseline);
        assert_eq!(
            hex::encode(baseline_rng.key.as_slice()),
            "71135673e9a5c7256fd5cb3f820064174c51b0d5deff28ac83b2395443c4e026"
        );
        assert_eq!(
            hex::encode(baseline_rng.nonce_prefix.as_slice()),
            "6ec07117"
        );
        assert_eq!(
            hex::encode(baseline),
            "778557505775363d40ce9d55c5069d7a3093d1a9495cd20164f11dacab35c8b262e90352c284785392655f4af503c6f0c9ef37f5c35b09ec1f76da923e97ec1f"
        );
        for index in 0..ORCHARD_PROVER_ENTROPY_BYTES_V1 {
            let mut mutated_entropy = entropy;
            mutated_entropy[index] ^= 1;
            let mut mutated_rng = OrchardUpstreamRngV1::from_entropy_v1(&mutated_entropy)
                .expect("fixed entropy shape");
            let mut mutated = [0_u8; ORCHARD_UPSTREAM_RNG_BLOCK_BYTES_V1];
            mutated_rng.fill_bytes(&mut mutated);
            assert_ne!(mutated, baseline, "entropy byte {index} was not bound");
        }
    }
    #[test]
    fn maximum_two_action_bundle_round_trips_and_order_is_bound() {
        let (public, proof) = two_action_fixture();
        assert_eq!(public.actions.len(), ORCHARD_MAX_ACTIONS_V1);
        assert_eq!(
            proof.len(),
            orchard_authorization_wire_size_v1(ORCHARD_MAX_ACTIONS_V1)
                .expect("canonical maximum-action wire")
        );
        verify_orchard_bundle_v1(public, proof, &consensus_limits())
            .expect("maximum-action Orchard V3 bundle verifies");
        let mut reordered = public.clone();
        reordered.actions.swap(0, 1);
        assert!(
            verify_orchard_bundle_v1(&reordered, proof, &consensus_limits()).is_err(),
            "action order must be bound by proof and signatures"
        );
    }
    #[test]
    fn only_post_nu6_3_profile_is_constructed() {
        assert_eq!(
            orchard_v3_verifying_key().circuit_version(),
            OrchardCircuitVersion::PostNu6_3
        );
        assert!(orchard_v3_verifying_key().supports_cross_address_restriction());
        assert!(
            ORCHARD_COMPILED_PROFILE_DESCRIPTOR_V1
                .windows(b"legacy=unrepresentable".len())
                .any(|window| window == b"legacy=unrepresentable")
        );
        for exact_bridge_field in [
            PROVER_RNG_SEED_DOMAIN_V1,
            PROVER_RNG_STREAM_DOMAIN_V1,
            PROVER_RNG_SEED_FRAME_V1.as_slice(),
        ] {
            assert!(
                ORCHARD_PROVER_RANDOMNESS_POLICY_V1
                    .windows(exact_bridge_field.len())
                    .any(|window| window == exact_bridge_field),
                "retained RNG policy omitted an exact bridge field"
            );
        }
        assert!(
            ORCHARD_COMPILED_PROFILE_DESCRIPTOR_V1
                .windows(b"orchard-retained-bridge-policy-v1".len())
                .any(|window| window == b"orchard-retained-bridge-policy-v1")
        );
    }
    #[test]
    fn empty_frontier_root_matches_upstream_vector_and_shape_is_fail_closed() {
        assert_eq!(
            orchard_empty_root_v1(),
            [
                0xae, 0x29, 0x35, 0xf1, 0xdf, 0xd8, 0xa2, 0x4a, 0xed, 0x7c, 0x70, 0xdf, 0x7d, 0xe3,
                0xa6, 0x68, 0xeb, 0x7a, 0x49, 0xb1, 0x31, 0x98, 0x80, 0xdd, 0xe2, 0xbb, 0xd9, 0x03,
                0x1a, 0xe5, 0xd8, 0x2f,
            ],
            "the node-derived origin must match the pinned upstream depth-32 vector"
        );
        validate_orchard_frontier_v1(0, None, &[], orchard_empty_root_v1())
            .expect("canonical empty frontier");
        assert_eq!(
            validate_orchard_frontier_v1(0, Some([0; 32]), &[], orchard_empty_root_v1()),
            Err(OrchardFrontierErrorV1::EmptyShape)
        );
        assert_eq!(
            validate_orchard_frontier_v1(0, None, &[[0; 32]], orchard_empty_root_v1()),
            Err(OrchardFrontierErrorV1::EmptyShape)
        );
        let mut wrong_root = orchard_empty_root_v1();
        wrong_root[0] ^= 1;
        assert_eq!(
            validate_orchard_frontier_v1(0, None, &[], wrong_root),
            Err(OrchardFrontierErrorV1::RootMismatch)
        );
    }
    #[test]
    fn compact_frontier_round_trips_appends_and_rejects_adversarial_parts() {
        let successor = append_orchard_commitments_v1(
            0,
            None,
            &[],
            orchard_empty_root_v1(),
            &[[0; 32], [1; 32]],
        )
        .expect("append two canonical commitments");
        assert_eq!(successor.tree_size, 2);
        assert!(successor.leaf.is_some());
        assert_eq!(successor.ommers.len(), 1);
        validate_orchard_frontier_v1(
            successor.tree_size,
            successor.leaf,
            &successor.ommers,
            successor.root,
        )
        .expect("persisted compact successor reconstructs exactly");
        assert_eq!(
            append_orchard_commitments_v1(0, None, &[], orchard_empty_root_v1(), &[[u8::MAX; 32]],),
            Err(OrchardFrontierErrorV1::NoteCommitmentEncoding { index: 0 })
        );
        assert_eq!(
            validate_orchard_frontier_v1(1, Some([u8::MAX; 32]), &[], successor.root),
            Err(OrchardFrontierErrorV1::LeafEncoding)
        );
        assert_eq!(
            validate_orchard_frontier_v1(2, Some([0; 32]), &[[u8::MAX; 32]], successor.root,),
            Err(OrchardFrontierErrorV1::OmmerEncoding { index: 0 })
        );
        assert_eq!(
            validate_orchard_frontier_v1(2, Some([0; 32]), &[], successor.root),
            Err(OrchardFrontierErrorV1::FrontierShape)
        );
        let full_ommers = vec![[0; 32]; usize::from(ORCHARD_TREE_DEPTH_V1)];
        let full = restore_orchard_frontier_v1(
            1_u64 << ORCHARD_TREE_DEPTH_V1,
            Some([0; 32]),
            &full_ommers,
        )
        .expect("synthetic full-depth canonical frontier");
        let full_root = full.root().to_bytes();
        assert_eq!(
            append_orchard_commitments_v1(
                1_u64 << ORCHARD_TREE_DEPTH_V1,
                Some([0; 32]),
                &full_ommers,
                full_root,
                &[[1; 32]],
            ),
            Err(OrchardFrontierErrorV1::TreeFull)
        );
    }
    #[test]
    fn complete_orchard_v3_bundle_round_trips() {
        let (public, proof) = fixture();
        assert_eq!(
            proof.len(),
            orchard_authorization_wire_size_v1(1).expect("canonical one-action wire")
        );
        verify_orchard_bundle_v1(public, proof, &consensus_limits())
            .expect("complete Orchard V3 bundle verifies");
    }
    #[test]
    fn strict_counts_proof_size_and_canonical_encodings_fail_closed() {
        let (public, proof) = fixture();
        let mut changed = public.clone();
        changed.consensus_binding.genesis_hash = [0; 32];
        assert_eq!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::ConsensusBinding)
        );
        changed = public.clone();
        changed.actions.clear();
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::ActionCount { actual: 0, .. })
        ));
        changed = public.clone();
        changed.actions = vec![changed.actions[0].clone(); ORCHARD_MAX_ACTIONS_V1 + 1];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::ActionCount { .. })
        ));
        let malformed = [
            proof[..proof.len() - 1].to_vec(),
            [proof.as_slice(), &[0]].concat(),
            Vec::new(),
        ];
        for malformed in malformed {
            assert!(matches!(
                verify_orchard_bundle_v1(public, &malformed, &consensus_limits()),
                Err(OrchardNativeErrorV1::ProofLength { .. })
            ));
        }
        let mut changed_proof = proof.clone();
        changed_proof[0] ^= 1;
        assert_eq!(
            verify_orchard_bundle_v1(public, &changed_proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::AuthorizationWireMagic)
        );
        changed_proof = proof.clone();
        changed_proof[ORCHARD_AUTHORIZATION_WIRE_MAGIC_V1.len()] = 2;
        assert_eq!(
            verify_orchard_bundle_v1(public, &changed_proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::AuthorizationActionCount {
                encoded: 2,
                expected: 1
            })
        );
        changed = public.clone();
        changed.anchor = [0xFF; 32];
        assert_eq!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::AnchorEncoding)
        );
        changed = public.clone();
        changed.actions[0].nullifier = [0xFF; 32];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::NullifierEncoding { index: 0 })
        ));
        changed = public.clone();
        changed.actions[0].randomized_key = [0; 32];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::RandomizedKeyEncoding { index: 0 }
                | OrchardNativeErrorV1::ActionEncoding { index: 0 })
        ));
        changed = public.clone();
        changed.actions[0].note_commitment = [0xFF; 32];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::NoteCommitmentEncoding { index: 0 })
        ));
        changed = public.clone();
        changed.actions[0].ephemeral_key = [0; 32];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::ActionEncoding { index: 0 })
        ));
        changed = public.clone();
        changed.actions[0].value_commitment = [0xFF; 32];
        assert!(matches!(
            verify_orchard_bundle_v1(&changed, proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::ValueCommitmentEncoding { index: 0 })
        ));
    }
    #[test]
    fn every_signed_public_component_and_authorization_rejects_mutation() {
        let (public, proof) = fixture();
        let mutations: [fn(&mut OrchardBundlePublicV1); 18] = [
            |value| {
                value.consensus_binding.network_id = NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x90; 32])),
                )
            },
            |value| value.consensus_binding.genesis_hash[0] ^= 1,
            |value| value.consensus_binding.action_index ^= 1,
            |value| {
                value.consensus_binding.transaction_intent_digest =
                    PrivacyTransactionIntentDigestV1::new([0x91; 32]);
            },
            |value| {
                value.consensus_binding.parameter_id = PrivacyParameterIdV1::new([0x92; 32]);
            },
            |value| {
                value.consensus_binding.parameter_digest =
                    PrivacyParameterDigestV1::new([0x93; 32]);
            },
            |value| {
                value.consensus_binding.verifier_digest = PrivacyVerifierDigestV1::new([0x94; 32]);
            },
            |value| {
                value.consensus_binding.statement_schema_digest =
                    PrivacyStatementSchemaDigestV1::new([0x95; 32]);
            },
            |value| {
                value.consensus_binding.engine_manifest_digest =
                    PrivacyEngineManifestDigestV1::new([0x96; 32]);
            },
            |value| value.anchor[0] ^= 1,
            |value| value.value_balance ^= 1,
            |value| value.actions[0].nullifier[0] ^= 1,
            |value| value.actions[0].randomized_key[0] ^= 1,
            |value| value.actions[0].note_commitment[0] ^= 1,
            |value| value.actions[0].ephemeral_key[0] ^= 1,
            |value| value.actions[0].encrypted_note[0] ^= 1,
            |value| value.actions[0].outgoing_ciphertext[0] ^= 1,
            |value| value.actions[0].value_commitment[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = public.clone();
            mutate(&mut changed);
            assert!(verify_orchard_bundle_v1(&changed, proof, &consensus_limits()).is_err());
        }
        let (other_public, other_proof) = alternate_one_action_fixture();
        let mut substituted_action = public.clone();
        substituted_action.actions[0] = other_public.actions[0].clone();
        assert!(
            verify_orchard_bundle_v1(&substituted_action, proof, &consensus_limits()).is_err(),
            "a valid action from another prepared bundle must not substitute"
        );
        assert_eq!(other_proof.len(), proof.len());
        assert!(
            verify_orchard_bundle_v1(public, other_proof, &consensus_limits()).is_err(),
            "a same-shape authorization from another prepared bundle must not substitute"
        );
        let halo2_len = Proof::expected_proof_size(public.actions.len());
        let spend_signature_offset = ORCHARD_AUTHORIZATION_HEADER_BYTES_V1 + halo2_len;
        let mut changed_proof = proof.clone();
        changed_proof[spend_signature_offset] ^= 1;
        assert_eq!(
            verify_orchard_bundle_v1(public, &changed_proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::SpendAuthorizationSignature { index: 0 })
        );
        changed_proof = proof.clone();
        let last = changed_proof.len() - 1;
        changed_proof[last] ^= 1;
        assert_eq!(
            verify_orchard_bundle_v1(public, &changed_proof, &consensus_limits()),
            Err(OrchardNativeErrorV1::BindingSignature)
        );
        let samples = 32usize.min(halo2_len);
        for sample in 0..samples {
            let offset = ORCHARD_AUTHORIZATION_HEADER_BYTES_V1 + sample * halo2_len / samples;
            let mut corrupted = proof.clone();
            corrupted[offset] ^= 1 << (sample % 8);
            assert_eq!(
                verify_orchard_bundle_v1(public, &corrupted, &consensus_limits()),
                Err(OrchardNativeErrorV1::Halo2Proof)
            );
        }
    }
}
