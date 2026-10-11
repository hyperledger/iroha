//! Data structures supporting Kaigi instructions.
/// Canonical identity inputs recomputed by Kaigi authorization verifiers.
pub mod authorization;
pub mod participation;
/// Exact canonical Pasta field encodings used by Kaigi authorization.
pub mod scalar;
use crate::account::AccountId;
use derive_more::Display;
use getset::Getters;
use iroha_crypto::{Hash, HashOf, MerkleTree};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};
use participation::KaigiPrivateParticipationLedgerV1;
use scalar::KaigiAuthorizationScalarV1;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
/// Domain separation tag for Kaigi roster commitment leaves.
const KAIGI_ROSTER_LEAF_TAG: &[u8] = b"iroha:kaigi:roster:leaf:v1\x00";
/// Seed used for the deterministic empty Kaigi roster root.
const KAIGI_ROSTER_EMPTY_SEED: &[u8] = b"iroha:kaigi:roster:empty:v1\x00";
/// Minimum relay hops required by the first-release Kaigi onion route.
pub const KAIGI_RELAY_MANIFEST_MIN_HOPS_V1: usize = 3;
/// Maximum relay hops accepted by the first-release Kaigi onion route.
pub const KAIGI_RELAY_MANIFEST_MAX_HOPS_V1: usize = 8;
/// Maximum opaque HPKE public-key descriptor size accepted by Kaigi V1.
///
/// This accommodates every ML-KEM public key currently supported by the
/// workspace, plus headroom for hybrid-suite framing, while bounding ledger
/// and operator-snapshot work before Kaigi gains an explicit suite tag.
pub const KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1: usize = 4 * 1024;
/// Maximum number of live relay descriptors in the first-release Kaigi registry.
///
/// The bound is shared by native admission and operator-facing snapshots so a
/// descriptor accepted on-chain can always be inspected through bounded APIs.
pub const KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1: usize = 500;
/// Hard JSON-size ceiling for native Kaigi metadata values in V1.
///
/// This protocol bound is independent of the configurable metadata limit so
/// nodes never decode an arbitrarily large retained Kaigi value.
pub const KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1: usize = 1024 * 1024;
/// Maximum encoded JSON size of one retained Kaigi call record in V1.
pub const KAIGI_RECORD_MAX_JSON_BYTES_V1: usize = KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1;
/// Maximum transparent participants or private roster commitments in V1.
pub const KAIGI_MAX_PARTICIPANTS_V1: usize = 4_096;
/// Maximum retained private nullifiers in V1.
///
/// One join and leave per maximum live roster plus mandatory host-create and
/// host-end actions. Admission reserves every live leave and the host end;
/// subsequent rejoins may consume only unreserved history capacity.
pub const KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1: usize = 2 * KAIGI_MAX_PARTICIPANTS_V1 + 2;
/// Maximum retained private usage commitments in V1.
pub const KAIGI_MAX_USAGE_COMMITMENTS_V1: usize = 4_096;
/// Maximum governance-allowlisted relay identities in V1.
///
/// This matches the live relay-registry bound while still allowing a retired
/// predecessor identity to authorize its registered successor.
pub const KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1: usize = KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1;
fn empty_roster_root() -> Hash {
    Hash::new(KAIGI_ROSTER_EMPTY_SEED)
}
fn roster_leaf_hash(commitment: &KaigiAuthorizationScalarV1) -> HashOf<[u8; 32]> {
    let mut buf = [0u8; KAIGI_ROSTER_LEAF_TAG.len() + Hash::LENGTH];
    buf[..KAIGI_ROSTER_LEAF_TAG.len()].copy_from_slice(KAIGI_ROSTER_LEAF_TAG);
    buf[KAIGI_ROSTER_LEAF_TAG.len()..].copy_from_slice(commitment.as_ref());
    HashOf::from_untyped_unchecked(Hash::new(buf))
}
fn compute_roster_root_from(commitments: &[KaigiParticipantCommitment]) -> Hash {
    if commitments.is_empty() {
        return empty_roster_root();
    }
    let mut tree = MerkleTree::<[u8; 32]>::default();
    for entry in commitments {
        tree.add(roster_leaf_hash(&entry.commitment));
    }
    tree.root().map_or_else(empty_roster_root, Hash::from)
}
/// Identifier for a Kaigi session scoped to a domain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Display,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
#[display("{domain_id}:{call_name}")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kaigi::KaigiId")]
pub struct KaigiId {
    /// Domain that owns the call.
    pub domain_id: DomainId,
    /// Name of the call within the domain namespace.
    pub call_name: Name,
}
impl KaigiId {
    /// Construct a new call identifier.
    #[must_use]
    pub fn new(domain_id: DomainId, call_name: Name) -> Self {
        Self {
            domain_id,
            call_name,
        }
    }
}
/// Privacy configuration for Kaigi sessions.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(tag = "mode", content = "state")]
#[norito(reuse_archived)]
pub enum KaigiPrivacyMode {
    /// Participants are stored explicitly.
    Transparent,
    /// Participants use commitments/nullifiers for roster privacy.
    ZkRosterV1,
}
/// Room access policy that determines viewer authentication requirements.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    Default,
)]
#[norito(tag = "policy", content = "state")]
#[norito(reuse_archived)]
pub enum KaigiRoomPolicy {
    /// Viewers may join without presenting authentication tokens.
    Public,
    /// Viewers must authenticate before the relay forwards traffic.
    #[default]
    Authenticated,
}
/// Canonical private opening commitment for an authenticated participant.
///
/// Transaction signers and retained participation owners remain ledger-visible.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct KaigiParticipantCommitment {
    /// Exact Pasta Fp commitment to the participant's private opening.
    pub commitment: KaigiAuthorizationScalarV1,
}
/// Nullifier entry ensuring joins/leaves occur only once.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
#[norito(deny_unknown_fields)]
pub struct KaigiParticipantNullifier {
    /// Exact Pasta Fp nullifier binding the action and participation sequence.
    pub digest: KaigiAuthorizationScalarV1,
}
/// Relay hop metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct KaigiRelayHop {
    /// Account offering relay services.
    pub relay_id: AccountId,
    /// HPKE public key bytes advertised by the relay.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub hpke_public_key: Vec<u8>,
    /// Relative weight for load-balancing decisions.
    pub weight: u8,
}
/// Relay manifest enumerating hops for onion routing.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct KaigiRelayManifest {
    /// Relay hops to traverse for control/data packets.
    pub hops: Vec<KaigiRelayHop>,
    /// Timestamp after which the manifest must be refreshed.
    ///
    /// Admission requires this value to be strictly after the current block time.
    pub expiry_ms: u64,
}
/// Relay registration descriptor persisted in domain metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct KaigiRelayRegistration {
    /// Registered account advertising relay capabilities.
    ///
    /// Native execution requires its live domain-qualified primary alias to
    /// select the relay governance domain.
    pub relay_id: AccountId,
    /// HPKE public key bytes advertised by the relay.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub hpke_public_key: Vec<u8>,
    /// Bandwidth class signalled by the relay (larger value == higher capacity).
    pub bandwidth_class: u8,
}
/// Health indicator reported for a Kaigi relay.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(tag = "status", content = "state")]
#[norito(reuse_archived)]
pub enum KaigiRelayHealthStatus {
    /// Relay is operating as expected.
    Healthy,
    /// Relay is experiencing partial degradation but may still forward traffic.
    Degraded,
    /// Relay is unavailable and should be treated as failed.
    Unavailable,
}
impl KaigiRelayHealthStatus {
    /// Map the status to a deterministic metric value for gauges.
    #[must_use]
    pub const fn metric_value(self) -> i64 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Unavailable => 2,
        }
    }
    /// Human-readable label used for telemetry metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}
/// Signed health feedback persisted in domain metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct KaigiRelayFeedback {
    /// Relay being reported on.
    pub relay_id: AccountId,
    /// Kaigi session where the relay observation occurred.
    pub call: KaigiId,
    /// Account submitting the feedback (typically the host).
    pub reported_by: AccountId,
    /// Reported relay status.
    pub status: KaigiRelayHealthStatus,
    /// Timestamp (milliseconds since epoch) when the feedback was recorded.
    pub reported_at_ms: u64,
    /// Optional human-readable notes or reason for the update.
    pub notes: Option<String>,
}
/// Governance-managed allowlist restricting which relays may operate in a domain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    Default,
)]
#[norito(reuse_archived)]
pub struct KaigiRelayAllowlist {
    /// Set of relay accounts authorised by governance.
    pub allowed_relays: BTreeSet<AccountId>,
}
impl KaigiRelayAllowlist {
    /// Check whether the exact canonical relay id is included in the allowlist.
    ///
    /// Stateful account-ID rekey lineage handling belongs at the Core admission
    /// boundary and is deliberately not inferred by this pure data-model helper.
    #[must_use]
    pub fn contains(&self, relay_id: &AccountId) -> bool {
        self.allowed_relays.contains(relay_id)
    }
}
/// Configuration submitted by the host when creating a call.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct NewKaigi {
    /// Identifier of the call.
    #[getset(get = "pub")]
    pub id: KaigiId,
    /// Account hosting the call.
    #[getset(get = "pub")]
    pub host: AccountId,
    /// Optional human readable title.
    #[getset(get = "pub")]
    pub title: Option<String>,
    /// Optional description of the session.
    #[getset(get = "pub")]
    pub description: Option<String>,
    /// Maximum number of concurrent participants (excluding the host).
    ///
    /// When present, native admission requires this value to be between one and
    /// [`KAIGI_MAX_PARTICIPANTS_V1`] inclusive. `None` uses that protocol maximum.
    #[getset(get = "pub")]
    pub max_participants: Option<u32>,
    /// Gas rate charged per minute of call time (host provided).
    #[getset(get = "pub")]
    pub gas_rate_per_minute: u64,
    /// Optional per-call metadata for additional signalling.
    #[getset(get = "pub")]
    pub metadata: Metadata,
    /// Optional scheduled start timestamp (milliseconds since epoch).
    #[getset(get = "pub")]
    pub scheduled_start_ms: Option<u64>,
    /// Optional billing account used to settle call costs.
    ///
    /// First-release native admission requires this to identify the signed host;
    /// delegated third-party billing is not yet supported.
    #[getset(get = "pub")]
    pub billing_account: Option<AccountId>,
    /// Privacy configuration requested by the host.
    #[getset(get = "pub")]
    pub privacy_mode: KaigiPrivacyMode,
    /// Viewer authentication policy enforced by the relays.
    #[getset(get = "pub")]
    pub room_policy: KaigiRoomPolicy,
    /// Optional relay manifest snapshot carrying structured relay metadata.
    #[getset(get = "pub")]
    pub relay_manifest: Option<KaigiRelayManifest>,
}
impl NewKaigi {
    /// Create a call builder with default metadata.
    #[must_use]
    pub fn with_defaults(id: KaigiId, host: AccountId) -> Self {
        Self {
            id,
            host,
            title: None,
            description: None,
            max_participants: None,
            gas_rate_per_minute: 0,
            metadata: Metadata::default(),
            scheduled_start_ms: None,
            billing_account: None,
            privacy_mode: KaigiPrivacyMode::Transparent,
            room_policy: KaigiRoomPolicy::default(),
            relay_manifest: None,
        }
    }
}
/// Lifecycle state of a call.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(tag = "status", content = "state")]
#[norito(reuse_archived)]
pub enum KaigiStatus {
    /// Call has been created but not yet ended.
    Active,
    /// Call has concluded.
    Ended,
}
/// Stored call record tracked inside domain metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(reuse_archived)]
pub struct KaigiRecord {
    /// Identifier of the call.
    pub id: KaigiId,
    /// Host account that created the call.
    pub host: AccountId,
    /// Optional billing account, which must equal the host in V1.
    pub billing_account: Option<AccountId>,
    /// Optional human readable title.
    pub title: Option<String>,
    /// Optional description provided by the host.
    pub description: Option<String>,
    /// Maximum non-zero number of participants allowed (excluding host).
    pub max_participants: Option<u32>,
    /// Gas rate charged per minute of call time.
    pub gas_rate_per_minute: u64,
    /// Call metadata supplied by the host.
    pub metadata: Metadata,
    /// Optional scheduled start timestamp announced by the host.
    pub scheduled_start_ms: Option<u64>,
    /// Privacy configuration applied to the session.
    pub privacy_mode: KaigiPrivacyMode,
    /// Viewer authentication policy enforced by the relays.
    pub room_policy: KaigiRoomPolicy,
    /// Relay manifest snapshot carrying structured relay metadata.
    pub relay_manifest: Option<KaigiRelayManifest>,
    /// Host commitment used to authorize privacy-mode host actions.
    pub host_commitment: Option<KaigiParticipantCommitment>,
    /// Deterministic Merkle root of the roster commitment tree.
    pub roster_root: Hash,
    /// Participant roster commitments used in privacy mode.
    pub roster_commitments: Vec<KaigiParticipantCommitment>,
    /// Original account ownership and consumed participation sequences.
    pub private_participation: KaigiPrivateParticipationLedgerV1,
    /// Nullifier log preventing duplicate actions in privacy mode.
    pub nullifier_log: Vec<KaigiParticipantNullifier>,
    /// Historical usage commitments recorded for privacy billing.
    pub usage_commitments: Vec<KaigiAuthorizationScalarV1>,
    /// Current status of the call.
    pub status: KaigiStatus,
    /// Milliseconds since epoch when the record was created.
    pub created_at_ms: u64,
    /// Milliseconds since epoch when the call was ended (if applicable).
    pub ended_at_ms: Option<u64>,
    /// Milliseconds of call time recorded so far.
    pub total_duration_ms: u64,
    /// Total gas billed for this session across all usage records.
    pub total_billed_gas: u64,
    /// Number of usage segments recorded.
    pub segments_recorded: u32,
    /// Participants currently associated with the call; the host is always implicit and absent.
    pub participants: Vec<AccountId>,
    /// Additional participant metadata (keyed by participant id) for future expansion.
    #[norito(json = "crate::json_helpers::account_metadata_map")]
    pub participant_metadata: BTreeMap<AccountId, Metadata>,
}
impl KaigiRecord {
    /// Construct a call record from a [`NewKaigi`] template.
    #[must_use]
    pub fn from_new(template: &NewKaigi, created_at_ms: u64) -> Self {
        Self {
            id: template.id.clone(),
            host: template.host.clone(),
            billing_account: template.billing_account.clone(),
            title: template.title.clone(),
            description: template.description.clone(),
            max_participants: template.max_participants,
            gas_rate_per_minute: template.gas_rate_per_minute,
            metadata: template.metadata.clone(),
            scheduled_start_ms: template.scheduled_start_ms,
            privacy_mode: template.privacy_mode,
            room_policy: template.room_policy,
            relay_manifest: template.relay_manifest.clone(),
            host_commitment: None,
            roster_root: empty_roster_root(),
            roster_commitments: Vec::new(),
            private_participation: KaigiPrivateParticipationLedgerV1::default(),
            nullifier_log: Vec::new(),
            usage_commitments: Vec::new(),
            status: KaigiStatus::Active,
            created_at_ms,
            ended_at_ms: None,
            total_duration_ms: 0,
            total_billed_gas: 0,
            segments_recorded: 0,
            participants: Vec::new(),
            participant_metadata: BTreeMap::new(),
        }
    }
    /// Determine if the participant list contains the exact canonical `account` id.
    #[must_use]
    pub fn has_participant(&self, account: &AccountId) -> bool {
        self.participants
            .iter()
            .any(|participant| participant == account)
    }
    /// Determine if the roster already contains `commitment`.
    #[must_use]
    pub fn has_commitment(&self, commitment: &KaigiParticipantCommitment) -> bool {
        self.roster_commitments
            .iter()
            .any(|existing| existing.commitment == commitment.commitment)
    }
    /// Current Merkle root of the roster commitment tree.
    #[must_use]
    pub fn roster_root(&self) -> Hash {
        self.roster_root
    }
    /// Compute the roster root for an arbitrary commitment slice.
    #[must_use]
    pub fn compute_roster_root(commitments: &[KaigiParticipantCommitment]) -> Hash {
        compute_roster_root_from(commitments)
    }
    fn refresh_roster_root(&mut self) {
        self.roster_root = Self::compute_roster_root(&self.roster_commitments);
    }
    /// Append a roster commitment without additional deduplication.
    pub fn push_commitment(&mut self, commitment: KaigiParticipantCommitment) {
        self.roster_commitments.push(commitment);
        self.refresh_roster_root();
    }
    /// Remove a commitment if present.
    pub fn remove_commitment(&mut self, commitment: &KaigiParticipantCommitment) -> bool {
        let len_before = self.roster_commitments.len();
        self.roster_commitments
            .retain(|existing| existing.commitment != commitment.commitment);
        let removed = len_before != self.roster_commitments.len();
        if removed {
            self.refresh_roster_root();
        }
        removed
    }
    /// Check if a nullifier digest has already been recorded.
    #[must_use]
    pub fn has_nullifier(&self, nullifier: &KaigiParticipantNullifier) -> bool {
        self.nullifier_log
            .iter()
            .any(|existing| existing.digest == nullifier.digest)
    }
    /// Append a nullifier to the audit log.
    pub fn push_nullifier(&mut self, nullifier: KaigiParticipantNullifier) {
        self.nullifier_log.push(nullifier);
    }
    /// Append a usage commitment to the privacy usage log.
    pub fn push_usage_commitment(&mut self, commitment: KaigiAuthorizationScalarV1) {
        self.usage_commitments.push(commitment);
    }
    /// Append a participant, preserving uniqueness.
    pub fn push_participant(&mut self, account: AccountId) {
        if !self.has_participant(&account) {
            self.participants.push(account);
            self.participants.sort_unstable();
            self.participants.dedup();
        }
    }
    /// Remove an exact participant and its associated metadata if present.
    pub fn remove_participant(&mut self, account: &AccountId) -> bool {
        let len_before = self.participants.len();
        self.participants
            .retain(|participant| participant != account);
        let removed = len_before != self.participants.len();
        if removed {
            self.participant_metadata.remove(account);
        }
        removed
    }
    /// Replace the relay manifest snapshot associated with the call.
    pub fn set_relay_manifest(&mut self, manifest: Option<KaigiRelayManifest>) {
        self.relay_manifest = manifest;
    }
}
/// Helper used for rendering deterministic metadata keys in domain storage.
///
/// # Errors
///
/// Returns [`ParseError`](crate::error::ParseError) if the composed key violates
/// the [`Name`] invariants enforced by the parser.
pub fn kaigi_metadata_key(call_name: &Name) -> Result<Name, iroha_model_base::error::ParseError> {
    let composite = format!("kaigi__{}", call_name.as_ref());
    Name::from_str(&composite)
}
fn relay_account_key_fragment(relay_id: &AccountId) -> String {
    let digest = HashOf::new(relay_id);
    hex::encode(digest.as_ref())
}
/// Helper used for storing Kaigi relay registrations inside domain metadata.
///
/// The suffix is a digest of the complete canonical account identity, so both
/// single-key and multisignature relay accounts have bounded, collision-resistant keys.
///
/// # Errors
///
/// Returns [`ParseError`](crate::error::ParseError) if the composed key violates [`Name`] rules.
pub fn kaigi_relay_metadata_key(
    relay_id: &AccountId,
) -> Result<Name, iroha_model_base::error::ParseError> {
    let key = format!("kaigi_relay__{}", relay_account_key_fragment(relay_id));
    Name::from_str(&key)
}
/// Helper used for storing Kaigi relay health feedback in domain metadata.
///
/// The suffix is a digest of the complete canonical account identity, so both
/// single-key and multisignature relay accounts have bounded, collision-resistant keys.
///
/// # Errors
///
/// Returns [`ParseError`](crate::error::ParseError) if the composed key violates [`Name`] rules.
pub fn kaigi_relay_feedback_key(
    relay_id: &AccountId,
) -> Result<Name, iroha_model_base::error::ParseError> {
    let key = format!(
        "kaigi_relay_feedback__{}",
        relay_account_key_fragment(relay_id)
    );
    Name::from_str(&key)
}
/// Metadata key storing the governance-managed relay allowlist.
///
/// # Errors
///
/// Returns [`ParseError`](crate::error::ParseError) if the key violates [`Name`] rules.
pub fn kaigi_relay_allowlist_key() -> Result<Name, iroha_model_base::error::ParseError> {
    Name::from_str("kaigi_relay_allowlist")
}
/// Prelude re-export for Kaigi data structures.
pub mod prelude {
    pub use super::{
        KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1, KAIGI_MAX_PARTICIPANTS_V1,
        KAIGI_MAX_USAGE_COMMITMENTS_V1, KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1,
        KAIGI_RECORD_MAX_JSON_BYTES_V1, KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1,
        KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1, KAIGI_RELAY_MANIFEST_MAX_HOPS_V1,
        KAIGI_RELAY_MANIFEST_MIN_HOPS_V1, KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1, KaigiId,
        KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiPrivacyMode, KaigiRecord,
        KaigiRelayAllowlist, KaigiRelayFeedback, KaigiRelayHealthStatus, KaigiRelayHop,
        KaigiRelayManifest, KaigiRelayRegistration, KaigiRoomPolicy, KaigiStatus, NewKaigi,
        kaigi_metadata_key, kaigi_relay_allowlist_key, kaigi_relay_feedback_key,
        kaigi_relay_metadata_key,
    };
    pub use super::{
        participation::KaigiPrivateParticipationLedgerV1, scalar::KaigiAuthorizationScalarV1,
    };
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use norito::codec::{decode_adaptive, encode_adaptive};
    use std::str::FromStr;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked Kaigi fixture keypair")
    }
    fn checked_account_id() -> AccountId {
        AccountId::new(checked_random_keypair().public_key().clone())
    }
    #[test]
    fn metadata_key_prefixes_call_name() {
        let call_name = Name::from_str("demo").expect("valid name");
        let key = kaigi_metadata_key(&call_name).expect("metadata key");
        assert_eq!(key.as_ref(), "kaigi__demo");
    }
    #[test]
    fn call_record_participant_management_is_deterministic() {
        let domain_id = DomainId::try_new("nexus", "universal").expect("domain id");
        let host = checked_account_id();
        let call_id = KaigiId::new(domain_id.clone(), Name::from_str("daily").unwrap());
        let template = NewKaigi::with_defaults(call_id, host);
        let mut record = KaigiRecord::from_new(&template, 1234);
        assert_eq!(record.status, KaigiStatus::Active);
        assert!(record.participants.is_empty());
        let bob = checked_account_id();
        record.push_participant(bob.clone());
        record.push_participant(bob.clone());
        assert_eq!(record.participants.len(), 1);
        assert!(record.has_participant(&bob));
        record
            .participant_metadata
            .insert(bob.clone(), Metadata::default());
        record
            .participant_metadata
            .insert(record.host.clone(), Metadata::default());

        {
            let ordinary = norito::json::to_json(&record).expect("serialize call record JSON");
            assert_eq!(
                norito::json::to_json_bounded(&record, ordinary.len())
                    .expect("serialize call record at exact JSON limit"),
                ordinary
            );
            assert_eq!(
                norito::json::to_json_bounded(&record, ordinary.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
        }
        assert!(record.remove_participant(&bob));
        assert!(!record.has_participant(&bob));
        assert!(!record.participant_metadata.contains_key(&bob));
        assert!(record.participant_metadata.contains_key(&record.host));
        assert!(!record.remove_participant(&bob));
        assert!(record.participants.is_empty());
    }
    #[test]
    fn kaigi_participant_metadata_preserves_original_account_refusal_and_canonical_map() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        let host = AccountId::new(
            KeyPair::from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let participant = AccountId::new(
            KeyPair::from_seed(vec![43; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let id = KaigiId::new(
            DomainId::try_new("nexus", "universal").unwrap(),
            "account_metadata_refusal".parse().unwrap(),
        );
        let mut expected = KaigiRecord::from_new(&NewKaigi::with_defaults(id, host), 1234);
        expected.push_participant(participant.clone());
        expected
            .participant_metadata
            .insert(participant.clone(), Metadata::default());
        let wire = norito::json::to_json(&expected).unwrap();
        let map_wire = norito::json::to_json(&expected.participant_metadata).unwrap();
        let source_pointer = wire.as_ptr();
        let decode = |mode| -> Result<(), norito::json::Error> {
            if mode == 0 {
                let mut parser = norito::json::Parser::new(&map_wire);
                let decoded = crate::json_helpers::account_metadata_map::deserialize(&mut parser)?;
                assert_eq!(decoded, expected.participant_metadata);
            } else {
                let decoded: KaigiRecord = norito::json::from_json(&wire)?;
                assert_eq!(decoded, expected);
            }
            Ok(())
        };
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let demands = [0, 1].map(|mode| {
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(mode));
            decoded.expect("actual reader accepts the original canonical input");
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            demand
        });
        let context_limit = demands
            .iter()
            .try_fold(0_usize, |sum, demand| {
                demand
                    .checked_mul(*demand)?
                    .checked_mul(2)?
                    .checked_add(sum)
            })
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // The original pool owns decoder counters, not the ordinary DTO graph.
        // Exercise every real quota cut: the retired reader performed another
        // Metadata decode after its account parse, so a final-charge-only cut
        // would not establish propagation at the actual account-key boundary.
        for (mode, demand) in demands.into_iter().enumerate() {
            for limit in 0..demand {
                let before = original.consumed_allocated_bytes();
                let mut observed = None;
                let refusal = original.with(|| norito::with_decode_limits_scope(
                    limits(limit), || classify_decode_attempt(|| {
                        let error = decode(mode).expect_err("actual below-demand reader must refuse");
                        let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                            panic!("Kaigi participant metadata must retain its original account scoped refusal at mode {mode}, quota {limit}: {error:?}");
                        };
                        observed = Some(origin.clone());
                        Err::<(), _>(error.into_core_error())
                    }))).unwrap_err();
                assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                let refusal = refusal.into_error();
                let Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted,
                    limit: reported_limit,
                }) = refusal.decode_resource_error()
                else {
                    panic!("actual quota refusal must retain its original resource fields");
                };
                assert_eq!(reported_limit, u64::try_from(limit).unwrap());
                assert!(attempted > reported_limit);
                assert!(attempted <= u64::try_from(demand).unwrap());
                let norito::Error::ScopedDecodeResource(returned) = refusal else {
                    panic!("reader must return its exact original observer");
                };
                assert_eq!(returned, observed.unwrap());
                drop(returned);
                assert_eq!(pool.reserved_bytes(), baseline);
                let after_refusal = original.consumed_allocated_bytes();
                // The outer owner is debited before the inner quota refuses.
                assert_eq!(after_refusal - before, attempted);
                original
                    .with(|| decode(mode))
                    .expect("same input and original context retry");
                assert_eq!(
                    original.consumed_allocated_bytes() - after_refusal,
                    u64::try_from(demand).unwrap()
                );
                assert_eq!(pool.reserved_bytes(), baseline);
                let (refusal, usage) =
                    norito::core::with_decode_limits_measured(limits(limit), || decode(mode));
                let error = refusal
                    .expect_err("same input unscoped refusal")
                    .into_core_error();
                assert_eq!(
                    error.decode_resource_error(),
                    Some(DecodeResourceError::TotalAllocationExceeded {
                        attempted,
                        limit: reported_limit,
                    })
                );
                assert!(!matches!(error, norito::Error::ScopedDecodeResource(_)));
                assert!(u64::try_from(usage.total_allocated_bytes()).unwrap() < attempted);
            }
        }
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(
            norito::json::to_json_bounded(&expected, wire.len()).unwrap(),
            wire
        );
        assert_eq!(
            norito::json::to_json_bounded(&expected, wire.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
        let binary = encode_adaptive(&expected);
        assert_eq!(decode_adaptive::<KaigiRecord>(&binary).unwrap(), expected);
        let key = participant.canonical_i105().unwrap();
        let key_json = norito::json::to_json(&key).unwrap();
        let duplicate_map = format!("{{{key_json}:{{}},{key_json}:{{}}}}");
        let duplicate_wire = wire.replace(
            &format!("\"participant_metadata\":{map_wire}"),
            &format!("\"participant_metadata\":{duplicate_map}"),
        );
        assert_ne!(duplicate_wire, wire);
        let error = norito::json::from_json::<KaigiRecord>(&duplicate_wire).unwrap_err();
        assert!(matches!(error, norito::json::Error::DuplicateField { .. }));
        let malformed_wire = wire.replace(
            &format!("\"participant_metadata\":{map_wire}"),
            "\"participant_metadata\":{\"alice@banka.dataspace\":{}}",
        );
        assert_ne!(malformed_wire, wire);
        let error = norito::json::from_json::<KaigiRecord>(&malformed_wire).unwrap_err();
        assert!(error.into_core_error().decode_resource_error().is_none());
        assert_eq!(wire.as_ptr(), source_pointer);
        assert_eq!(expected.participant_metadata.len(), 1);
    }

    #[test]
    fn call_record_preserves_creation_timestamp_and_schedule() {
        let domain_id = DomainId::try_new("nexus", "universal").expect("domain id");
        let host = checked_account_id();
        let call_id = KaigiId::new(domain_id.clone(), Name::from_str("standup").unwrap());
        let mut template = NewKaigi::with_defaults(call_id, host);
        template.scheduled_start_ms = Some(7_777);
        template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
        template.relay_manifest = Some(KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: checked_account_id(),
                hpke_public_key: vec![0, 1, 2],
                weight: 1,
            }],
            expiry_ms: 9_999,
        });
        let record = KaigiRecord::from_new(&template, 1_234);
        assert_eq!(record.created_at_ms, 1_234);
        assert_eq!(record.scheduled_start_ms, Some(7_777));
        assert_eq!(record.privacy_mode, KaigiPrivacyMode::ZkRosterV1);
        assert!(record.roster_commitments.is_empty());
        assert!(record.nullifier_log.is_empty());
        assert_eq!(
            record.relay_manifest.as_ref(),
            template.relay_manifest.as_ref()
        );
    }
    #[test]
    fn relay_hop_canonical_roundtrip() {
        let _domain = DomainId::try_new("relay-domain", "universal").expect("domain");
        let relay = checked_account_id();
        let hop = KaigiRelayHop {
            relay_id: relay.clone(),
            hpke_public_key: vec![0xAA, 0xBB, 0xCC],
            weight: 3,
        };
        let bytes = encode_adaptive(&hop);
        let decoded: KaigiRelayHop = decode_adaptive(&bytes).expect("decode relay hop");
        assert_eq!(decoded, hop);
    }
    #[test]
    fn new_kaigi_canonical_roundtrip() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        let host_keypair = checked_random_keypair();
        let host = AccountId::new(host_keypair.public_key().clone());
        let id = KaigiId::new(
            domain.clone(),
            Name::from_str("weekly-sync").expect("call name"),
        );
        let relay = checked_account_id();
        let manifest = KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: relay,
                hpke_public_key: vec![0x01; 32],
                weight: 5,
            }],
            expiry_ms: 1_700_111_000_000,
        };
        let mut metadata = Metadata::default();
        metadata.insert(Name::from_str("topic").expect("metadata key"), "status");
        let call = NewKaigi {
            id,
            host: host.clone(),
            title: Some("Weekly Sync".to_owned()),
            description: Some("Roadmap alignment".to_owned()),
            max_participants: Some(16),
            gas_rate_per_minute: 120,
            metadata,
            scheduled_start_ms: Some(1_700_000_000_000),
            billing_account: Some(host),
            privacy_mode: KaigiPrivacyMode::ZkRosterV1,
            room_policy: KaigiRoomPolicy::Authenticated,
            relay_manifest: Some(manifest),
        };
        let hop_bytes =
            encode_adaptive(&call.relay_manifest.as_ref().expect("manifest present").hops[0]);
        let _ = <AccountId as norito::core::DecodeFromSlice>::decode_from_slice(&hop_bytes);
        let manifest_bytes =
            encode_adaptive(call.relay_manifest.as_ref().expect("manifest present"));
        let _manifest_decoded: KaigiRelayManifest =
            decode_adaptive(&manifest_bytes).expect("decode manifest");
        let bytes = encode_adaptive(&call);
        let decoded: NewKaigi = decode_adaptive(&bytes).expect("decode create kaigi payload");
        assert_eq!(decoded, call);
    }

    #[test]
    fn kaigi_json_requires_explicit_room_policy() {
        let domain = DomainId::try_new("kaigi", "universal").expect("domain");
        let host = checked_account_id();
        let id = KaigiId::new(domain, Name::from_str("strict-room").expect("call name"));
        let call = NewKaigi::with_defaults(id, host);
        let record = KaigiRecord::from_new(&call, 1);

        for (label, mut value) in [
            (
                "NewKaigi",
                norito::json::to_value(&call).expect("serialize NewKaigi"),
            ),
            (
                "KaigiRecord",
                norito::json::to_value(&record).expect("serialize KaigiRecord"),
            ),
        ] {
            assert!(
                value
                    .as_object_mut()
                    .expect("Kaigi JSON object")
                    .remove("room_policy")
                    .is_some(),
                "{label} fixture must contain room_policy"
            );
            assert!(
                match label {
                    "NewKaigi" => norito::json::from_value::<NewKaigi>(value).is_err(),
                    "KaigiRecord" => norito::json::from_value::<KaigiRecord>(value).is_err(),
                    _ => unreachable!("fixed Kaigi type inventory"),
                },
                "{label} must reject a missing room_policy"
            );
        }
    }
    #[test]
    fn participant_commitment_norito_roundtrip() {
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap(),
        };
        let bytes = encode_adaptive(&commitment);
        let decoded: KaigiParticipantCommitment =
            decode_adaptive(&bytes).expect("decode commitment");
        assert_eq!(decoded, commitment);
    }
    #[test]
    fn roster_root_updates_with_commitment_changes() {
        let empty_root = KaigiRecord::compute_roster_root(&[]);
        assert_eq!(empty_root, empty_roster_root());
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x2A; 32]).unwrap(),
        };
        let populated_root = KaigiRecord::compute_roster_root(std::slice::from_ref(&commitment));
        assert_ne!(populated_root, empty_root);
        let domain = DomainId::try_new("kaigi", "universal").expect("domain");
        let host_key = checked_random_keypair();
        let host = AccountId::new(host_key.public_key().clone());
        let call_id = KaigiId::new(domain.clone(), Name::from_str("privacy").expect("call"));
        let template = NewKaigi::with_defaults(call_id, host.clone());
        let mut record = KaigiRecord::from_new(&template, 0);
        assert_eq!(record.roster_root(), empty_roster_root());
        record.push_commitment(commitment);
        assert_eq!(record.roster_root(), populated_root);
        assert!(record.has_commitment(&commitment));
        let removed = record.remove_commitment(&commitment);
        assert!(removed);
        assert!(record.roster_commitments.is_empty());
        assert_eq!(record.roster_root(), empty_roster_root());
    }
    #[test]
    fn relay_manifest_can_be_replaced_or_cleared() {
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain");
        let host_key = checked_random_keypair();
        let host = AccountId::new(host_key.public_key().clone());
        let call_id = KaigiId::new(domain_id.clone(), Name::from_str("route").expect("call"));
        let mut template = NewKaigi::with_defaults(call_id, host.clone());
        let initial_manifest = KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: checked_account_id(),
                hpke_public_key: vec![1, 2, 3],
                weight: 5,
            }],
            expiry_ms: 123,
        };
        template.relay_manifest = Some(initial_manifest.clone());
        let mut record = KaigiRecord::from_new(&template, 0);
        assert_eq!(record.relay_manifest.as_ref(), Some(&initial_manifest));
        let updated_manifest = KaigiRelayManifest {
            hops: vec![
                KaigiRelayHop {
                    relay_id: checked_account_id(),
                    hpke_public_key: vec![4, 5, 6],
                    weight: 7,
                },
                KaigiRelayHop {
                    relay_id: checked_account_id(),
                    hpke_public_key: vec![7, 8, 9],
                    weight: 3,
                },
            ],
            expiry_ms: 456,
        };
        record.set_relay_manifest(Some(updated_manifest.clone()));
        assert_eq!(record.relay_manifest.as_ref(), Some(&updated_manifest));
        record.set_relay_manifest(None);
        assert!(record.relay_manifest.is_none());
    }
    #[test]
    fn relay_registration_norito_roundtrip() {
        let _domain_id = DomainId::try_new("kaigi", "universal").expect("domain");
        let relay_id = checked_account_id();
        let registration = KaigiRelayRegistration {
            relay_id: relay_id.clone(),
            hpke_public_key: vec![0xAA, 0xBB, 0xCC],
            bandwidth_class: 7,
        };
        let bytes = encode_adaptive(&registration);
        let decoded: KaigiRelayRegistration =
            decode_adaptive(&bytes).expect("decode relay registration");
        assert_eq!(decoded, registration);
        let key = kaigi_relay_metadata_key(&relay_id).expect("metadata key");
        assert!(key.as_ref().starts_with("kaigi_relay__"));
    }
    #[test]
    fn relay_feedback_key_uses_canonical_account_digest() {
        let relay = checked_account_id();
        let key = kaigi_relay_feedback_key(&relay).expect("feedback key");
        let digest = relay_account_key_fragment(&relay);
        assert_eq!(key.as_ref(), format!("kaigi_relay_feedback__{digest}"));
    }
    #[test]
    fn relay_keys_support_multisig_account_identity() {
        let member = crate::account::MultisigMember::new(
            checked_account_id().expect_single_signatory().clone(),
            1,
        )
        .expect("valid multisig member");
        let policy =
            crate::account::MultisigPolicy::new(1, vec![member]).expect("valid multisig policy");
        let relay = AccountId::new_multisig(policy);
        let registration = kaigi_relay_metadata_key(&relay).expect("multisig registration key");
        let feedback = kaigi_relay_feedback_key(&relay).expect("multisig feedback key");
        assert!(registration.as_ref().starts_with("kaigi_relay__"));
        assert!(feedback.as_ref().starts_with("kaigi_relay_feedback__"));
    }
    #[test]
    fn allowlist_membership_checks_handle_present_and_missing_relays() {
        let relay = checked_account_id();
        let mut allowlist = KaigiRelayAllowlist::default();
        allowlist.allowed_relays.insert(relay.clone());
        assert!(allowlist.contains(&relay));
        let other = checked_account_id();
        assert!(!allowlist.contains(&other));
    }
    #[test]
    fn participant_nullifier_norito_roundtrip() {
        let nullifier = KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes([0x26; 32]).unwrap(),
        };
        let bytes = encode_adaptive(&nullifier);
        let decoded: KaigiParticipantNullifier = decode_adaptive(&bytes).expect("decode nullifier");
        assert_eq!(decoded, nullifier);
    }
}

#[cfg(test)]
mod final_wire_tests;

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<super::KaigiId>(
            "iroha_data_model::kaigi::KaigiId",
        );
    }
}
