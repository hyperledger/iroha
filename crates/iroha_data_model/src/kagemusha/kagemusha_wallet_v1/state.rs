//! Private wallet state, transition statements, step and lineage proofs, commit receipts and
//! packages (§§3, 3.1, 3.2, 4.1; design §§3–5).
//!
//! The private state is split into a *core*, which holds every field a step proof σ reads,
//! changes or carries, and a *rest*, which only the lineage relation Λ opens. The state
//! commitment is one canonical σ-field value, `P(kgwcore1, core elements || P(kgwrest1, rest
//! elements))` (§3): this module fixes the fields, their σ-field element order, the map leaves,
//! keys and chain entries, the public transition statement, the step proof σ, the lineage proof
//! Ω with its public outputs, the operation-dependent `proof_digest` (§4.1) and the provider
//! receipt τ that certifies one committed transition. A package `(statement, σ, τ)` — plus
//! Ω(pred) for Send, Unload and Retiring — is consumed only after its receipt verifies natively
//! (§3.1); a proof alone is never a transferable credit.
//!
//! The data model computes every Poseidon value natively with `iroha_pasta` ([`super::poseidon`]):
//! the commitment and rest digest, the chain appends, the map leaves and roots, the σ statement
//! digest, the packed-byte `proof_digest` and the lineage digest.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_VERSION_V1, WalletResult, WalletVersionsV1,
    digest::{
        KagemushaWalletObjectDigestDomainV1 as ObjectDomain, KagemushaWalletSignerOutputV1,
        KagemushaWalletSigningDomainV1 as Domain, WalletFieldItemsV1, WalletTranscriptV1,
        kagemusha_wallet_field_from_u128_v1, kagemusha_wallet_freeze_signature_v1,
        kagemusha_wallet_signed_object_digest_v1, kagemusha_wallet_signing_message_v1,
        kagemusha_wallet_verify_signature_v1,
    },
    identity::{
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1, KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        KagemushaWalletCredentialV1, KagemushaWalletRegulatoryPolicyV1, KagemushaWalletSchemeV1,
        kagemusha_wallet_provider_contract_v1,
    },
    invalid_v1, is_zero_v1,
    keys::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    messages::KagemushaWalletRequestBodyV1,
    overflow_v1,
    policy::{
        KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1, KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1,
        KagemushaWalletQuotaWindowKindV1, KagemushaWalletQuotaWindowV1,
    },
    poseidon::{
        KAGEMUSHA_WALLET_BLACKLIST_HISTORY_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_CORE_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_NULLIFIER_DOMAIN_V1, KAGEMUSHA_WALLET_OPERATION_ID_DOMAIN_V1,
        KAGEMUSHA_WALLET_PACKAGE_DOMAIN_V1, KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1,
        KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1, KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1,
        KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_REST_DOMAIN_V1,
        KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1, KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
        KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1, KagemushaWalletIndexedInsertV1,
        KagemushaWalletIndexedLeafV1, KagemushaWalletIndexedOpeningV1,
        KagemushaWalletIndexedTreeV1, kagemusha_wallet_empty_map_root_v1,
        kagemusha_wallet_indexed_verify_membership_v1, kagemusha_wallet_pair_key_v1,
        kagemusha_wallet_poseidon_bytes_v1, kagemusha_wallet_poseidon_v1, poseidon_items_v1,
    },
    require_canonical_field_v1, require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1,
    require_version_v1,
};

#[cfg(test)]
#[path = "state_tests.rs"]
pub(super) mod state_tests;

const DIGEST_BYTES: usize = 32;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

/// Exact inline transcript bytes of one state commitment: its canonical 32-byte encoding.
pub const KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1: usize = DIGEST_BYTES;

/// σ-field element counts of every effect variant, in tag order: `credit_id`, the receipt digest,
/// Request, Credited, nullifier, charge-quote and update digests are one element each (`P`
/// values, owner answer B1); the Bootstrap enrollment id and marker digest are two limbs each.
const EFFECT_FIELD_ITEMS: [usize; 8] = [4, 4, 9, 4, 2, 5, 3, 0];

const fn max_width_v1(widths: &[usize]) -> usize {
    let mut max = 0;
    let mut index = 0;
    while index < widths.len() {
        if widths[index] > max {
            max = widths[index];
        }
        index += 1;
    }
    max
}

/// Exact `receipt-body` transcript bytes.
pub const KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1: usize = 2
    + 3 * DIGEST_BYTES
    + U128_BYTES
    + DIGEST_BYTES
    + 2 * KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1
    + 4 * DIGEST_BYTES;
/// Exact transcript bytes of the public outputs of one lineage proof Ω (§3.2).
pub const KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1: usize = 2
    + 2 * DIGEST_BYTES
    + KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1
    + 2 * DIGEST_BYTES
    + super::keys::KAGEMUSHA_DEVICE_PUBLIC_KEY_SEC1_BYTES_V1
    + 1
    + U64_BYTES
    + U32_BYTES
    + U128_BYTES
    + 2 * DIGEST_BYTES;

/// σ-field elements of the state core (§3), before the appended rest digest.
pub const KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1: usize = 33;
/// σ-field elements of the state rest (§3).
pub const KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1: usize = 8;
/// σ-field elements of the zero-filled effect union of the statement encoding.
pub const KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1: usize = max_width_v1(&EFFECT_FIELD_ITEMS);
/// σ-field elements of the statement encoding: 17 header elements and the effect union.
pub const KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1: usize =
    17 + KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1;
/// Slots of the quota-usage array, aligned one to one with the quota-window slots (§3.3, owner
/// answer B5).
pub const KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1: usize = KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1;

// ---------------------------------------------------------------------------------------
// Lifecycle, commitment and private state (§§3, 3.2)
// ---------------------------------------------------------------------------------------

/// Lifecycle of one wallet incarnation; it never reverts from `Retiring` (§6.3).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLifecycleV1"
)]
pub enum KagemushaWalletLifecycleV1 {
    /// Normal operation.
    #[codec(index = 1)]
    Active,
    /// New receiving quotes and funding closed; remaining value and existing claims persist.
    #[codec(index = 2)]
    Retiring,
}

impl KagemushaWalletLifecycleV1 {
    /// Every lifecycle, in tag order.
    pub const ALL: [Self; 2] = [Self::Active, Self::Retiring];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Retiring => 2,
        }
    }
}

/// State commitment (the head commitment): one canonical value of the σ field, Pasta `Fp`
/// (the Vesta scalar field of the single-parity σ), with two levels (§3, owner answer Q10).
///
/// The value is `P(kgwcore1, core elements || P(kgwrest1, rest elements))`
/// ([`KagemushaWalletStateV1::commitment`]) in its canonical 32-byte little-endian encoding.
/// The all-zero value is used only as the Bootstrap predecessor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateCommitmentV1"
)]
pub struct KagemushaWalletStateCommitmentV1 {
    /// Canonical little-endian σ-field encoding.
    pub value: [u8; 32],
}

impl KagemushaWalletStateCommitmentV1 {
    /// The all-zero commitment, used only as the Bootstrap predecessor.
    pub const ZERO: Self = Self { value: [0; 32] };

    /// Whether the commitment is the all-zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        is_zero_v1(&self.value)
    }

    /// Whether the commitment is a canonical σ-field encoding.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        super::digest::kagemusha_wallet_is_canonical_field_v1(&self.value)
    }

    /// Whether the commitment is a nonzero canonical σ-field encoding.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.is_zero() && self.is_canonical()
    }

    /// Append the inline transcript.
    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        transcript.digest(&self.value)
    }

    /// Exact inline transcript bytes: the canonical encoding.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        self.write(WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1,
        ))
        .finish()
    }
}

/// State core: every field a step proof σ reads, changes or carries (§3).
///
/// The field order is the σ-field element order of the commitment
/// ([`KagemushaWalletStateV1::core_field_items`]). The scheme and asset (owner answer Q4), the
/// blacklist issue time and the regulatory policy's maximum blacklist age (owner answer Q5)
/// are core fields, so `σ_send` enforces the maximum list age; the quota share expiry (owner
/// answer B7) and the policy's maximum anchor response time (owner answer B8) are core fields,
/// so `σ_send` enforces the share expiry and the Send time span. Load and redeem recovery share
/// one map and root keyed by `(kind, ordinal)` (owner answer Q3). The credential digest, map
/// roots, the quota-usage array root, chains, the blacklist and quota-windows roots and the
/// state nonce are canonical σ-field values; an all-zero digest or root means "none held" where
/// noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateCoreV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletStateCoreV1 {
    /// Lifecycle.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Enrolled asset scope digest.
    pub asset_digest: [u8; 32],
    /// Wallet incarnation identity.
    pub wallet_id: [u8; 32],
    /// Object digest `P(kgwocrd1, ·)` of the current credential, a canonical σ-field value.
    pub credential_digest: [u8; 32],
    /// Balance in integer asset units; the spendable value is `balance − burned_total` with
    /// Ω(pred)'s lineage-adjusted `burned_total` (§3.2).
    pub balance: u128,
    /// Burned credits as last resynchronized from a consumed Ω(pred) (§3.2).
    pub burned_total: u128,
    /// Transition sequence; zero at Bootstrap.
    pub sequence: u128,
    /// Next payer send ordinal.
    pub next_send: u128,
    /// Next ordinary Load ordinal.
    pub next_load: u128,
    /// Next unload redemption ordinal.
    pub next_redeem: u128,
    /// Running hash chain over sent-credit descriptors; zero when empty.
    pub send_chain: [u8; 32],
    /// Running hash chain over received-credit descriptors; zero when empty.
    pub recv_chain: [u8; 32],
    /// Permanent consumed-credit map root.
    pub consumed_credit_root: [u8; 32],
    /// Pending-outgoing map root.
    pub pending_outgoing_root: [u8; 32],
    /// Load/redeem recovery map root, keyed by `(kind, ordinal)`.
    pub load_redeem_recovery_root: [u8; 32],
    /// Fee-claim recovery map root.
    pub fee_claim_root: [u8; 32],
    /// Root of the depth-6 quota-usage array aligned with the held share's window slots (owner
    /// answer B5); the all-padding root when no share is held. A Send charges its touched
    /// windows in place; only a quota-share refresh rebuilds it.
    pub quota_usage_root: [u8; 32],
    /// Active controls: scheme policy enabled and credential permitted.
    pub enabled_controls: u32,
    /// Windows root of the held quota share; zero when none is held.
    pub quota_windows_root: [u8; 32],
    /// Expiry of the held quota share in Unix milliseconds (owner answer B7); zero when none is
    /// held.
    pub quota_share_expires_at_ms: u64,
    /// Version of the held blacklist; zero when none is held.
    pub blacklist_version: u64,
    /// Gap-tree root of the held blacklist; zero when none is held.
    pub blacklist_root: [u8; 32],
    /// Issuance time of the held blacklist in Unix milliseconds; zero when none is held.
    pub blacklist_issued_at_ms: u64,
    /// Maximum blacklist age of the credential's regulatory policy; zero for no age rule.
    pub blacklist_max_age_ms: u64,
    /// Response-age bound of a time anchor of the credential's regulatory policy; with the quota
    /// control it also bounds the Send time span `U − L` (owner answer B8).
    pub time_anchor_max_response_ms: u64,
    /// Attestation lease expiry of the current credential; zero when not permitted.
    pub lease_expires_at_ms: u64,
    /// Epoch of the held scheme policy; zero when none is held.
    pub policy_epoch: u64,
    /// Accepted time floor in Unix milliseconds; it never decreases.
    pub accepted_time_floor_ms: u64,
    /// Fresh state nonce hiding the commitment.
    pub state_nonce: [u8; 32],
}

/// State rest: the remaining fields, committed by the rest digest and opened only by Λ (§3).
///
/// It holds the rest of the credential's regulatory policy body (the maximum blacklist age and
/// the maximum anchor response time are core fields), the held policy objects by object digest
/// (`P` values, one element each), the committed time anchor and the blacklist-history root
/// (owner answer B6). An all-zero digest means "none held".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateRestV1"
)]
pub struct KagemushaWalletStateRestV1 {
    /// Controls the credential's regulatory policy permits.
    pub permitted_controls: u32,
    /// Digest of the held scheme policy; zero when none is held.
    pub scheme_policy: [u8; 32],
    /// Fee schedule named by the held scheme policy; zero for no fee.
    pub fee_schedule: [u8; 32],
    /// Digest of the held blacklist; zero when none is held.
    pub blacklist: [u8; 32],
    /// Digest of the held quota share; zero when none is held.
    pub quota_share: [u8; 32],
    /// Identity of the held quota share; zero when none is held.
    pub quota_share_id: u64,
    /// Digest of the committed time anchor; zero when none is committed.
    pub time_anchor: [u8; 32],
    /// Root of the depth-32 indexed blacklist-history map `list_version → (list_version,
    /// entries_root)` (owner answer B6): every `RefreshPolicy(Blacklist)` inserts the new list,
    /// and no other transition changes it.
    pub blacklist_history_root: [u8; 32],
}

/// Private state of one wallet incarnation (§3): core and rest.
///
/// Map roots authenticate local maps whose openings and retained objects live beside the
/// state; a root is not a backup of its map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateV1")]
pub struct KagemushaWalletStateV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Core: opened by every step proof.
    pub core: KagemushaWalletStateCoreV1,
    /// Rest: opened only by the lineage relation.
    pub rest: KagemushaWalletStateRestV1,
}

impl KagemushaWalletStateV1 {
    /// Bootstrap state of a newly enrolled incarnation (§3.2): zero balance, `burned_total`,
    /// ordinals and sequence, the empty root of every indexed map, the blacklist history
    /// included ([`kagemusha_wallet_empty_map_root_v1`]), the all-padding quota-usage array root
    /// ([`kagemusha_wallet_quota_usage_empty_root_v1`]), empty chains (the field zero), no held
    /// policy object, and the credential's regulatory policy and lease.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential and a zero or noncanonical state nonce.
    pub fn bootstrap(
        credential: &KagemushaWalletCredentialV1,
        state_nonce: [u8; 32],
    ) -> WalletResult<Self> {
        credential.validate()?;
        let body = &credential.body;
        let empty = kagemusha_wallet_empty_map_root_v1();
        let state = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            core: KagemushaWalletStateCoreV1 {
                lifecycle: KagemushaWalletLifecycleV1::Active,
                scheme_id: body.scheme_id,
                asset_digest: body.asset_digest,
                wallet_id: body.wallet_id,
                credential_digest: credential.credential_digest(),
                balance: 0,
                burned_total: 0,
                sequence: 0,
                next_send: 0,
                next_load: 0,
                next_redeem: 0,
                send_chain: [0; 32],
                recv_chain: [0; 32],
                consumed_credit_root: empty,
                pending_outgoing_root: empty,
                load_redeem_recovery_root: empty,
                fee_claim_root: empty,
                quota_usage_root: kagemusha_wallet_quota_usage_empty_root_v1(),
                enabled_controls: 0,
                quota_windows_root: [0; 32],
                quota_share_expires_at_ms: 0,
                blacklist_version: 0,
                blacklist_root: [0; 32],
                blacklist_issued_at_ms: 0,
                blacklist_max_age_ms: body.regulatory_policy.blacklist_max_age_ms,
                time_anchor_max_response_ms: body.regulatory_policy.time_anchor_max_response_ms,
                lease_expires_at_ms: body.lease_expires_at_ms,
                policy_epoch: 0,
                accepted_time_floor_ms: 0,
                state_nonce,
            },
            rest: KagemushaWalletStateRestV1 {
                permitted_controls: body.regulatory_policy.permitted_controls,
                scheme_policy: [0; 32],
                fee_schedule: [0; 32],
                blacklist: [0; 32],
                quota_share: [0; 32],
                quota_share_id: 0,
                time_anchor: [0; 32],
                blacklist_history_root: empty,
            },
        };
        state.validate()?;
        Ok(state)
    }

    /// The credential's regulatory policy as the state holds it: the permitted controls from
    /// the rest, the maximum blacklist age and maximum anchor response time from the core.
    #[must_use]
    pub const fn regulatory_policy(&self) -> KagemushaWalletRegulatoryPolicyV1 {
        KagemushaWalletRegulatoryPolicyV1 {
            permitted_controls: self.rest.permitted_controls,
            blacklist_max_age_ms: self.core.blacklist_max_age_ms,
            time_anchor_max_response_ms: self.core.time_anchor_max_response_ms,
        }
    }

    /// Validate the state's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, a zero or noncanonical credential digest, map
    /// root, quota-usage root, blacklist-history root or nonce, noncanonical chains, policy roots
    /// or held object digests, and inconsistent control fields ([`Self::validate_controls`]).
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("state.version", self.version)?;
        let core = &self.core;
        let rest = &self.rest;
        for (field, digest) in [
            ("state.core.scheme_id", &core.scheme_id),
            ("state.core.asset_digest", &core.asset_digest),
            ("state.core.wallet_id", &core.wallet_id),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        require_nonzero_field_v1("state.core.credential_digest", &core.credential_digest)?;
        require_nonzero_field_v1(
            "state.rest.blacklist_history_root",
            &rest.blacklist_history_root,
        )?;
        for (field, value) in [
            ("state.rest.scheme_policy", &rest.scheme_policy),
            ("state.rest.fee_schedule", &rest.fee_schedule),
            ("state.rest.blacklist", &rest.blacklist),
            ("state.rest.quota_share", &rest.quota_share),
            ("state.rest.time_anchor", &rest.time_anchor),
        ] {
            require_canonical_field_v1(field, value)?;
        }
        for (field, value) in [
            (
                "state.core.consumed_credit_root",
                &core.consumed_credit_root,
            ),
            (
                "state.core.pending_outgoing_root",
                &core.pending_outgoing_root,
            ),
            (
                "state.core.load_redeem_recovery_root",
                &core.load_redeem_recovery_root,
            ),
            ("state.core.fee_claim_root", &core.fee_claim_root),
            ("state.core.quota_usage_root", &core.quota_usage_root),
            ("state.core.state_nonce", &core.state_nonce),
        ] {
            require_nonzero_field_v1(field, value)?;
        }
        for (field, value) in [
            ("state.core.send_chain", &core.send_chain),
            ("state.core.recv_chain", &core.recv_chain),
            ("state.core.quota_windows_root", &core.quota_windows_root),
            ("state.core.blacklist_root", &core.blacklist_root),
        ] {
            require_canonical_field_v1(field, value)?;
        }
        self.validate_controls()
    }

    /// Validate the control fields (§7, design C6).
    ///
    /// # Errors
    ///
    /// Rejects an invalid regulatory policy, active controls the credential does not permit,
    /// held-object fields that disagree about whether the object is held, and a lease that
    /// disagrees with the regulatory policy.
    pub fn validate_controls(&self) -> WalletResult<()> {
        let core = &self.core;
        let rest = &self.rest;
        let policy = self.regulatory_policy();
        policy.validate()?;
        if core.enabled_controls & !policy.permitted_controls != 0 {
            return Err(invalid_v1("state.core.enabled_controls"));
        }
        let scheme_policy_held = core.policy_epoch != 0;
        if scheme_policy_held == is_zero_v1(&rest.scheme_policy)
            || (!scheme_policy_held
                && (core.enabled_controls != 0 || !is_zero_v1(&rest.fee_schedule)))
        {
            return Err(invalid_v1("state.scheme_policy"));
        }
        let blacklist_held = core.blacklist_version != 0;
        if blacklist_held == is_zero_v1(&rest.blacklist)
            || blacklist_held == is_zero_v1(&core.blacklist_root)
            || (!blacklist_held && core.blacklist_issued_at_ms != 0)
        {
            return Err(invalid_v1("state.blacklist"));
        }
        let share_held = rest.quota_share_id != 0;
        if share_held == is_zero_v1(&rest.quota_share)
            || share_held == is_zero_v1(&core.quota_windows_root)
            || share_held == (core.quota_share_expires_at_ms == 0)
        {
            return Err(invalid_v1("state.quota_share"));
        }
        let lease_permitted = policy.permits(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1);
        if (core.lease_expires_at_ms != 0) != lease_permitted {
            return Err(invalid_v1("state.core.lease_expires_at_ms"));
        }
        Ok(())
    }

    /// Validate that the state belongs to `credential`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid state or credential, another scheme, asset, wallet or credential,
    /// or a regulatory policy or lease that differs from the credential's.
    pub fn validate_for_credential(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> WalletResult<()> {
        self.validate()?;
        credential.validate()?;
        let body = &credential.body;
        require_scheme_v1(
            "state.core.scheme_id",
            &self.core.scheme_id,
            &body.scheme_id,
        )?;
        if self.core.asset_digest != body.asset_digest {
            return Err(invalid_v1("state.core.asset_digest"));
        }
        if self.core.wallet_id != body.wallet_id {
            return Err(invalid_v1("state.core.wallet_id"));
        }
        if self.core.credential_digest != credential.credential_digest() {
            return Err(invalid_v1("state.core.credential_digest"));
        }
        if self.regulatory_policy() != body.regulatory_policy {
            return Err(invalid_v1("state.regulatory_policy"));
        }
        if self.core.lease_expires_at_ms != body.lease_expires_at_ms {
            return Err(invalid_v1("state.core.lease_expires_at_ms"));
        }
        Ok(())
    }

    /// Whether every bit of `control` is active.
    #[must_use]
    pub const fn is_active(&self, control: u32) -> bool {
        control != 0 && self.core.enabled_controls & control == control
    }

    /// Whether Send needs a same-boot anchored interval: an active quota or lease control, or
    /// an enforced blacklist with a list-age rule (design C6).
    #[must_use]
    pub const fn send_requires_time_anchor(&self) -> bool {
        self.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1)
            || self.is_active(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1)
            || (self.is_active(KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1)
                && self.core.blacklist_version > 0
                && self.core.blacklist_max_age_ms > 0)
    }

    /// σ-field elements of the core, in commitment order (§3, element rule of
    /// [`super::poseidon`]).
    ///
    /// Order (33 elements): lifecycle; scheme id (2); asset digest (2); wallet id (2);
    /// credential digest (1); balance, `burned_total`, sequence, `next_send`, `next_load`,
    /// `next_redeem`; `send_chain`, `recv_chain`; the consumed-credit, pending-outgoing,
    /// load/redeem-recovery and fee-claim roots and the quota-usage array root; enabled controls;
    /// quota-windows root; quota share expiry; blacklist version, root, issue time and maximum
    /// age; maximum anchor response time; lease expiry; policy epoch; accepted-time floor; state
    /// nonce.
    ///
    /// # Errors
    ///
    /// Rejects an invalid state.
    pub fn core_field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        self.validate()?;
        let core = &self.core;
        let items = WalletFieldItemsV1::with_capacity(KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1)
            .integer(u128::from(core.lifecycle.tag()))
            .digest(&core.scheme_id)
            .digest(&core.asset_digest)
            .digest(&core.wallet_id)
            .field(&core.credential_digest)
            .integer(core.balance)
            .integer(core.burned_total)
            .integer(core.sequence)
            .integer(core.next_send)
            .integer(core.next_load)
            .integer(core.next_redeem)
            .field(&core.send_chain)
            .field(&core.recv_chain)
            .field(&core.consumed_credit_root)
            .field(&core.pending_outgoing_root)
            .field(&core.load_redeem_recovery_root)
            .field(&core.fee_claim_root)
            .field(&core.quota_usage_root)
            .integer(u128::from(core.enabled_controls))
            .field(&core.quota_windows_root)
            .integer(u128::from(core.quota_share_expires_at_ms))
            .integer(u128::from(core.blacklist_version))
            .field(&core.blacklist_root)
            .integer(u128::from(core.blacklist_issued_at_ms))
            .integer(u128::from(core.blacklist_max_age_ms))
            .integer(u128::from(core.time_anchor_max_response_ms))
            .integer(u128::from(core.lease_expires_at_ms))
            .integer(u128::from(core.policy_epoch))
            .integer(u128::from(core.accepted_time_floor_ms))
            .field(&core.state_nonce);
        debug_assert_eq!(items.len(), KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1);
        Ok(items.finish())
    }

    /// σ-field elements of the rest, in rest-digest order (§3).
    ///
    /// Order (8 elements): permitted controls; scheme policy; fee schedule; blacklist; quota
    /// share; quota share id; time anchor; blacklist-history root.
    ///
    /// # Errors
    ///
    /// Rejects an invalid state.
    pub fn rest_field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        self.validate()?;
        let rest = &self.rest;
        let items = WalletFieldItemsV1::with_capacity(KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1)
            .integer(u128::from(rest.permitted_controls))
            .field(&rest.scheme_policy)
            .field(&rest.fee_schedule)
            .field(&rest.blacklist)
            .field(&rest.quota_share)
            .integer(u128::from(rest.quota_share_id))
            .field(&rest.time_anchor)
            .field(&rest.blacklist_history_root);
        debug_assert_eq!(items.len(), KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1);
        Ok(items.finish())
    }

    /// Rest digest `P(kgwrest1, rest elements)` (§3).
    ///
    /// # Errors
    ///
    /// Rejects an invalid state.
    pub fn rest_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(
            KAGEMUSHA_WALLET_REST_DOMAIN_V1,
            &self.rest_field_items()?,
        ))
    }

    /// State commitment `P(kgwcore1, core elements || rest digest)` (§3, owner answer Q10).
    ///
    /// # Errors
    ///
    /// Rejects an invalid state.
    pub fn commitment(&self) -> WalletResult<KagemushaWalletStateCommitmentV1> {
        let mut items = self.core_field_items()?;
        items.push(self.rest_digest()?);
        Ok(KagemushaWalletStateCommitmentV1 {
            value: poseidon_items_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &items),
        })
    }

    /// Spendable value `balance − burned_total` with the lineage-adjusted `burned_total` of
    /// `omega`, the Ω recorded for this state's head at fold time (§§3.2, 6.1).
    ///
    /// # Errors
    ///
    /// Rejects an invalid state or Ω, an Ω of another head, wallet or credential, and a
    /// `burned_total` above the balance.
    pub fn spendable_with(&self, omega: &KagemushaWalletLineagePublicV1) -> WalletResult<u128> {
        omega.validate()?;
        if omega.head != self.commitment()? {
            return Err(invalid_v1("lineage.head"));
        }
        if omega.wallet_id != self.core.wallet_id {
            return Err(invalid_v1("lineage.wallet_id"));
        }
        if omega.credential_digest != self.core.credential_digest {
            return Err(invalid_v1("lineage.credential_digest"));
        }
        self.core
            .balance
            .checked_sub(omega.burned_total)
            .ok_or_else(|| overflow_v1("state.spendable"))
    }

    /// Native Unload pre-check: a positive `amount` at most `balance − burned_total` with
    /// Ω(pred)'s `burned_total` (§6.1).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::spendable_with`] rejects, a zero amount, and an amount above the
    /// spendable value.
    pub fn check_unload(
        &self,
        amount: u128,
        omega: &KagemushaWalletLineagePublicV1,
    ) -> WalletResult<()> {
        let spendable = self.spendable_with(omega)?;
        if amount == 0 || amount > spendable {
            return Err(invalid_v1("state.unload_amount"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Map leaves, keys, chain entries and the credit-digest leaf (§3)
// ---------------------------------------------------------------------------------------

/// Kind of a leaf of the shared load/redeem recovery map; the high part of its key (owner
/// answer Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KagemushaWalletRecoveryKindV1 {
    /// A load leaf.
    Load,
    /// A redeem leaf.
    Redeem,
}

impl KagemushaWalletRecoveryKindV1 {
    /// Key tag: Load 1, Redeem 2.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Load => 1,
            Self::Redeem => 2,
        }
    }
}

/// Permanent consumed-credit leaf: `credit_id → (amount, receive sequence)` (§3).
///
/// No state commitment contains a Payment digest: this leaf is computable from the Request
/// and the predecessor head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletConsumedCreditLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletConsumedCreditLeafV1 {
    /// Received credit identity (the map key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Amount credited.
    pub amount: u128,
    /// Sequence of the Receive transition that consumed the credit.
    pub receive_sequence: u128,
}

impl KagemushaWalletConsumedCreditLeafV1 {
    /// Poseidon domain of this map's values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1;

    /// Map key: `credit_id`.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.credit_id
    }

    /// Leaf elements: `credit_id`, amount, receive sequence (3).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id`.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("consumed_credit.credit_id", &self.credit_id)?;
        Ok(WalletFieldItemsV1::with_capacity(3)
            .field(&self.credit_id)
            .integer(self.amount)
            .integer(self.receive_sequence)
            .finish())
    }

    /// Map value `P(kgwccrd1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }
}

/// Pending-outgoing leaf of one committed Send awaiting `ArchiveSent` (§3): the send
/// descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPendingOutgoingLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletPendingOutgoingLeafV1 {
    /// Credit identity (the map key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Bound receiver wallet.
    pub receiver_wallet_id: [u8; 32],
    /// Payer send ordinal consumed by the Send.
    pub send_ordinal: u128,
    /// Amount credited to the receiver.
    pub amount: u128,
    /// Fee earned at the Send commit.
    pub fee: u128,
    /// Object digest `P(kgworeq1, ·)` of the signed Request, a canonical σ-field value.
    pub request_digest: [u8; 32],
}

impl KagemushaWalletPendingOutgoingLeafV1 {
    /// Poseidon domain of this map's values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1;

    /// Map key: `credit_id`.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.credit_id
    }

    /// Leaf elements, the send descriptor: `credit_id`, receiver wallet (2), send ordinal,
    /// amount, fee, Request digest (7).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id` or Request digest.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        send_descriptor_items_v1(
            &self.credit_id,
            &self.receiver_wallet_id,
            self.send_ordinal,
            self.amount,
            self.fee,
            &self.request_digest,
        )
    }

    /// Map value `P(kgwpout1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }
}

/// Elements of one send descriptor: the pending-outgoing leaf and the `send_chain` entry.
fn send_descriptor_items_v1(
    credit_id: &[u8; 32],
    receiver_wallet_id: &[u8; 32],
    send_ordinal: u128,
    amount: u128,
    fee: u128,
    request_digest: &[u8; 32],
) -> WalletResult<Vec<[u8; 32]>> {
    require_nonzero_field_v1("send_descriptor.credit_id", credit_id)?;
    require_nonzero_field_v1("send_descriptor.request_digest", request_digest)?;
    Ok(WalletFieldItemsV1::with_capacity(7)
        .field(credit_id)
        .digest(receiver_wallet_id)
        .integer(send_ordinal)
        .integer(amount)
        .integer(fee)
        .field(request_digest)
        .finish())
}

/// Load leaf of one absorbed ordinary Load receipt in the shared load/redeem recovery map (§3, owner answer
/// Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLoadLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletLoadLeafV1 {
    /// Load ordinal (the low part of the map key).
    pub ordinal: u128,
    /// Ordinary receipt digest `P_bytes(kgwolod1, transcript)`, a canonical σ-field value.
    pub receipt_digest: [u8; 32],
    /// Net offline amount added.
    pub amount: u128,
}

impl KagemushaWalletLoadLeafV1 {
    /// Poseidon domain of load values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1;

    /// Map key `(Load, ordinal)`: `1 · 2^128 + ordinal`.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        kagemusha_wallet_pair_key_v1(KagemushaWalletRecoveryKindV1::Load.tag(), self.ordinal)
    }

    /// Leaf elements: ordinal, receipt digest, amount (3).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical receipt digest.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("load.receipt_digest", &self.receipt_digest)?;
        Ok(WalletFieldItemsV1::with_capacity(3)
            .integer(self.ordinal)
            .field(&self.receipt_digest)
            .integer(self.amount)
            .finish())
    }

    /// Map value `P(kgwload1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }
}

/// Redeem leaf of one unload claim in the shared load/redeem recovery map (§3, owner answer
/// Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRedeemLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletRedeemLeafV1 {
    /// Redemption ordinal (the low part of the map key).
    pub ordinal: u128,
    /// Unload nullifier `P(kgwnull1, ·)`, a canonical σ-field value.
    pub nullifier: [u8; 32],
    /// Net offline amount subtracted.
    pub amount: u128,
    /// Online charge withheld from the payout.
    pub online_charge: u128,
}

impl KagemushaWalletRedeemLeafV1 {
    /// Poseidon domain of redeem values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1;

    /// Map key `(Redeem, ordinal)`: `2 · 2^128 + ordinal`.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        kagemusha_wallet_pair_key_v1(KagemushaWalletRecoveryKindV1::Redeem.tag(), self.ordinal)
    }

    /// Leaf elements: ordinal, nullifier, amount, online charge (4).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical nullifier.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("redeem.nullifier", &self.nullifier)?;
        Ok(WalletFieldItemsV1::with_capacity(4)
            .integer(self.ordinal)
            .field(&self.nullifier)
            .integer(self.amount)
            .integer(self.online_charge)
            .finish())
    }

    /// Map value `P(kgwrdm_1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }
}

/// Fee-claim leaf of one nonzero Send fee awaiting payout (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeClaimLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletFeeClaimLeafV1 {
    /// Credit identity (the map key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Fee earned at the Send commit.
    pub fee: u128,
    /// Object digest `P(kgwofee1, ·)` of the historical fee schedule, a canonical σ-field value.
    pub fee_schedule_digest: [u8; 32],
}

impl KagemushaWalletFeeClaimLeafV1 {
    /// Poseidon domain of this map's values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1;

    /// Map key: `credit_id`.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.credit_id
    }

    /// Leaf elements: `credit_id`, fee, fee schedule digest (3).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id` or fee schedule digest.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("fee_claim.credit_id", &self.credit_id)?;
        require_nonzero_field_v1("fee_claim.fee_schedule_digest", &self.fee_schedule_digest)?;
        Ok(WalletFieldItemsV1::with_capacity(3)
            .field(&self.credit_id)
            .integer(self.fee)
            .field(&self.fee_schedule_digest)
            .finish())
    }

    /// Map value `P(kgwfee_1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }
}

/// One leaf of the quota-usage array (§3.3, owner answer B5): the kind, start and end of the
/// window in its slot and the gross amount consumed in that window.
///
/// The array has 64 slots aligned one to one with the held share's window slots; an empty
/// window slot (every slot without a share) holds the padding leaf
/// ([`kagemusha_wallet_quota_usage_padding_leaf_v1`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaUsageLeafV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletQuotaUsageLeafV1 {
    /// Window kind.
    pub window_kind: KagemushaWalletQuotaWindowKindV1,
    /// Window start in Unix milliseconds.
    pub window_start_ms: u64,
    /// Window end in Unix milliseconds; a refresh keeps it for this `(kind, start)` key.
    pub window_end_ms: u64,
    /// Gross amount consumed in this window; never replenished. A refreshed window may carry
    /// `used` above a lowered limit, which only refuses further charges.
    pub used: u128,
}

impl KagemushaWalletQuotaUsageLeafV1 {
    /// Poseidon domain of this leaf.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1;

    /// Usage leaf of `window` with `used`.
    #[must_use]
    pub const fn for_window(window: &KagemushaWalletQuotaWindowV1, used: u128) -> Self {
        Self {
            window_kind: window.kind,
            window_start_ms: window.start_ms,
            window_end_ms: window.end_ms,
            used,
        }
    }

    /// Whether this leaf belongs to `window`: same kind, start and end.
    #[must_use]
    pub fn matches_window(&self, window: &KagemushaWalletQuotaWindowV1) -> bool {
        self.window_kind == window.kind
            && self.window_start_ms == window.start_ms
            && self.window_end_ms == window.end_ms
    }

    /// Leaf elements: window kind tag, start, end, used (4).
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        quota_usage_items_v1(
            self.window_kind.tag(),
            self.window_start_ms,
            self.window_end_ms,
            self.used,
        )
    }

    /// Leaf `P(kgwquse1, elements)`.
    #[must_use]
    pub fn leaf_value(&self) -> [u8; 32] {
        poseidon_items_v1(Self::DOMAIN, &self.field_items())
    }
}

fn quota_usage_items_v1(kind: u8, start_ms: u64, end_ms: u64, used: u128) -> Vec<[u8; 32]> {
    WalletFieldItemsV1::with_capacity(4)
        .integer(u128::from(kind))
        .integer(u128::from(start_ms))
        .integer(u128::from(end_ms))
        .integer(used)
        .finish()
}

/// Padding leaf of an empty quota-usage slot: `P(kgwquse1, [0, 0, 0, 0])`.
#[must_use]
pub fn kagemusha_wallet_quota_usage_padding_leaf_v1() -> [u8; 32] {
    poseidon_items_v1(
        KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1,
        &quota_usage_items_v1(0, 0, 0, 0),
    )
}

/// Quota-usage array node `P(kgwqusn1, [left, right])` over canonical children.
///
/// # Errors
///
/// Rejects a noncanonical child.
pub fn kagemusha_wallet_quota_usage_node_v1(
    left: &[u8; 32],
    right: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1,
        &[*left, *right],
    )
}

/// Root of the all-padding quota-usage array: the Bootstrap `quota_usage_root` and the root of
/// every state that holds no quota share.
#[must_use]
pub fn kagemusha_wallet_quota_usage_empty_root_v1() -> [u8; 32] {
    static ROOT: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| KagemushaWalletQuotaUsageArrayV1::empty().root())
}

/// Levels of one depth-6 Poseidon tree over 64 leaves with node domain `node_domain`: level 0
/// holds the leaves and level 6 the root.
pub(super) fn quota_tree_levels_v1(leaves: Vec<[u8; 32]>, node_domain: u64) -> Vec<Vec<[u8; 32]>> {
    debug_assert_eq!(leaves.len(), KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1);
    let mut levels = Vec::with_capacity(KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1 + 1);
    let mut level = leaves;
    while level.len() > 1 {
        let next = level
            .chunks_exact(2)
            .map(|pair| poseidon_items_v1(node_domain, &[pair[0], pair[1]]))
            .collect();
        levels.push(level);
        level = next;
    }
    levels.push(level);
    levels
}

/// Opening of `slot` in tree `levels` built by [`quota_tree_levels_v1`].
pub(super) fn quota_tree_opening_v1(
    levels: &[Vec<[u8; 32]>],
    slot: u8,
) -> WalletResult<KagemushaWalletQuotaOpeningV1> {
    let mut position = usize::from(slot);
    if position >= KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 {
        return Err(invalid_v1("quota_opening.slot"));
    }
    let mut siblings = [[0_u8; 32]; KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1];
    for (sibling, level) in siblings.iter_mut().zip(levels) {
        *sibling = level
            .get(position ^ 1)
            .copied()
            .ok_or_else(|| invalid_v1("quota_opening.slot"))?;
        position >>= 1;
    }
    Ok(KagemushaWalletQuotaOpeningV1 { slot, siblings })
}

/// Opening of one slot of the depth-6 quota-window tree or quota-usage array: its slot and
/// exactly 6 siblings, height 0 first (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletQuotaOpeningV1 {
    /// Opened slot, below 64.
    pub slot: u8,
    /// Sibling σ-field values, height 0 first.
    pub siblings: [[u8; 32]; KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1],
}

impl KagemushaWalletQuotaOpeningV1 {
    fn root_over(&self, leaf: &[u8; 32], node_domain: u64) -> WalletResult<[u8; 32]> {
        if usize::from(self.slot) >= KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 {
            return Err(invalid_v1("quota_opening.slot"));
        }
        let mut node = *leaf;
        for (height, sibling) in self.siblings.iter().enumerate() {
            let pair = if (self.slot >> height) & 1 == 1 {
                [*sibling, node]
            } else {
                [node, *sibling]
            };
            node = kagemusha_wallet_poseidon_v1(node_domain, &pair)
                .map_err(|_| invalid_v1("quota_opening.sibling"))?;
        }
        Ok(node)
    }

    /// Quota-usage array root recomputed from `leaf` (a usage leaf or the padding leaf) at the
    /// opened slot, with `P(kgwqusn1, ·)` nodes.
    ///
    /// # Errors
    ///
    /// Rejects a slot outside the array and a noncanonical leaf or sibling.
    pub fn usage_root(&self, leaf: &[u8; 32]) -> WalletResult<[u8; 32]> {
        self.root_over(leaf, KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1)
    }

    /// Quota-window tree root recomputed from the window leaf `leaf` at the opened slot, with
    /// `P(kgwqwnd1, ·)` nodes.
    ///
    /// # Errors
    ///
    /// Rejects a slot outside the tree and a noncanonical leaf or sibling.
    pub fn window_root(&self, leaf: &[u8; 32]) -> WalletResult<[u8; 32]> {
        self.root_over(leaf, super::poseidon::KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1)
    }
}

/// The quota-usage array of one wallet (§3.3, owner answer B5): the one exception to the
/// depth-32 indexed maps, a depth-6 Poseidon tree over 64 slots aligned one to one with the held
/// share's window slots, windows first and padding after. Its root is the core's
/// `quota_usage_root`. A Send charges its touched windows in place; a quota-share refresh
/// rebuilds it ([`Self::rebuild_for_share`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletQuotaUsageArrayV1 {
    slots: [Option<KagemushaWalletQuotaUsageLeafV1>; KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1],
}

impl Default for KagemushaWalletQuotaUsageArrayV1 {
    fn default() -> Self {
        Self::empty()
    }
}

impl KagemushaWalletQuotaUsageArrayV1 {
    /// The all-padding array of a wallet that holds no quota share.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            slots: [None; KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1],
        }
    }

    /// Array from explicit slots: occupied slots first, padding after.
    ///
    /// # Errors
    ///
    /// Rejects an occupied slot after a padding slot.
    pub fn from_slots(
        slots: [Option<KagemushaWalletQuotaUsageLeafV1>; KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1],
    ) -> WalletResult<Self> {
        let occupied = slots.iter().take_while(|slot| slot.is_some()).count();
        if slots[occupied..].iter().any(Option::is_some) {
            return Err(invalid_v1("quota_usage.slots"));
        }
        Ok(Self { slots })
    }

    /// Array aligned with `windows` with nothing consumed.
    ///
    /// # Errors
    ///
    /// Rejects more than 64 windows.
    pub fn zero_for(windows: &[KagemushaWalletQuotaWindowV1]) -> WalletResult<Self> {
        if windows.len() > KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 {
            return Err(invalid_v1("quota_usage.slots"));
        }
        let mut array = Self::empty();
        for (slot, window) in array.slots.iter_mut().zip(windows) {
            *slot = Some(KagemushaWalletQuotaUsageLeafV1::for_window(window, 0));
        }
        Ok(array)
    }

    /// The 64 slots, padding as `None`.
    #[must_use]
    pub const fn slots(
        &self,
    ) -> &[Option<KagemushaWalletQuotaUsageLeafV1>; KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1] {
        &self.slots
    }

    /// Leaf of `slot`, or `None` for padding or a slot outside the array.
    #[must_use]
    pub fn leaf(&self, slot: u8) -> Option<KagemushaWalletQuotaUsageLeafV1> {
        self.slots.get(usize::from(slot)).copied().flatten()
    }

    fn leaf_hashes(&self) -> Vec<[u8; 32]> {
        let padding = kagemusha_wallet_quota_usage_padding_leaf_v1();
        self.slots
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map_or(padding, KagemushaWalletQuotaUsageLeafV1::leaf_value)
            })
            .collect()
    }

    fn levels(&self) -> Vec<Vec<[u8; 32]>> {
        quota_tree_levels_v1(
            self.leaf_hashes(),
            KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1,
        )
    }

    /// Array root, one canonical σ-field value.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels()
            .last()
            .and_then(|root| root.first())
            .copied()
            .unwrap_or([0; 32])
    }

    /// Opening of `slot` against [`Self::root`].
    ///
    /// # Errors
    ///
    /// Rejects a slot outside the array.
    pub fn opening(&self, slot: u8) -> WalletResult<KagemushaWalletQuotaOpeningV1> {
        quota_tree_opening_v1(&self.levels(), slot)
    }

    /// Require slot `i` to hold the kind, start and end of `windows[i]` for every window, and
    /// padding after the last window.
    ///
    /// # Errors
    ///
    /// Rejects more than 64 windows, a missing or mismatched leaf, and an occupied slot after
    /// the windows.
    pub fn validate_aligned(&self, windows: &[KagemushaWalletQuotaWindowV1]) -> WalletResult<()> {
        if windows.len() > KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 {
            return Err(invalid_v1("quota_usage.slots"));
        }
        for (slot, window) in self.slots.iter().zip(windows) {
            if !slot.is_some_and(|leaf| leaf.matches_window(window)) {
                return Err(invalid_v1("quota_usage.alignment"));
            }
        }
        if self.slots[windows.len()..].iter().any(Option::is_some) {
            return Err(invalid_v1("quota_usage.alignment"));
        }
        Ok(())
    }

    /// Charge `gross` in place at `slot` against `limit` and return the new `used`.
    pub(super) fn charge(&mut self, slot: u8, gross: u128, limit: u128) -> WalletResult<u128> {
        let leaf = self
            .slots
            .get_mut(usize::from(slot))
            .and_then(Option::as_mut)
            .ok_or_else(|| invalid_v1("quota_usage.slot"))?;
        let used = leaf
            .used
            .checked_add(gross)
            .ok_or_else(|| overflow_v1("quota_usage.used"))?;
        if used > limit {
            return Err(invalid_v1("quota_window.limit"));
        }
        leaf.used = used;
        Ok(used)
    }

    /// Rebuild the array for a newly installed quota share (§3.3 `RefreshPolicy`; owner answers
    /// B4, B5 and B8), checking only the 64 slots of this (the predecessor's) array and the
    /// windows of the new share:
    ///
    /// - every new window is longer than `max_response_ms` (`end − start > max_response_ms`);
    /// - a new window whose key `(kind, start)` this array holds keeps that key's `end` and
    ///   carries its `used`;
    /// - a new window whose key is absent starts at `used = 0` and is admitted only if
    ///   `start ≥ floor_ms`, unless the predecessor never held a share (`first_allocation`);
    /// - an old key that the new share omits may be dropped only if its `used = 0` or its
    ///   `end ≤ floor_ms`.
    ///
    /// `floor_ms` is the successor accepted-time floor `F`. Consumed quota is never reset: a
    /// charged key that may be dropped has ended by `F`, floors never decrease, so it can never
    /// be re-added at zero, and a live charged key cannot be dropped.
    ///
    /// # Errors
    ///
    /// Rejects more than 64 windows, a window not longer than `max_response_ms`, a key whose
    /// end changes, an absent key starting before `floor_ms` (except at the first allocation),
    /// and a dropped charged key that has not ended by `floor_ms`.
    pub fn rebuild_for_share(
        &self,
        first_allocation: bool,
        windows: &[KagemushaWalletQuotaWindowV1],
        floor_ms: u64,
        max_response_ms: u64,
    ) -> WalletResult<Self> {
        if windows.len() > KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 {
            return Err(invalid_v1("quota_usage.slots"));
        }
        let held = |kind: KagemushaWalletQuotaWindowKindV1, start: u64| {
            self.slots
                .iter()
                .flatten()
                .find(|leaf| leaf.window_kind == kind && leaf.window_start_ms == start)
        };
        let mut rebuilt = Self::empty();
        for (slot, window) in rebuilt.slots.iter_mut().zip(windows) {
            let length = window
                .end_ms
                .checked_sub(window.start_ms)
                .ok_or_else(|| invalid_v1("quota_window.end_ms"))?;
            if length <= max_response_ms {
                return Err(invalid_v1("quota_share.window_length"));
            }
            let used = match held(window.kind, window.start_ms) {
                Some(leaf) if leaf.window_end_ms == window.end_ms => leaf.used,
                Some(_) => return Err(invalid_v1("quota_usage.window_end_ms")),
                None if first_allocation || window.start_ms >= floor_ms => 0,
                None => return Err(invalid_v1("quota_share.window_start_ms")),
            };
            *slot = Some(KagemushaWalletQuotaUsageLeafV1::for_window(window, used));
        }
        for leaf in self.slots.iter().flatten() {
            let kept = windows.iter().any(|window| {
                window.kind == leaf.window_kind && window.start_ms == leaf.window_start_ms
            });
            if !kept && leaf.used != 0 && leaf.window_end_ms > floor_ms {
                return Err(invalid_v1("quota_usage.dropped"));
            }
        }
        Ok(rebuilt)
    }
}

/// Blacklist-history entry `list_version → (list_version, entries_root)` of the rest's
/// depth-32 indexed blacklist-history map (§3.3, owner answer B6).
///
/// Every `RefreshPolicy(Blacklist)` inserts the new list's pair. A Receive under a Request that
/// recorded a nonzero `(receiver_blacklist_version, receiver_blacklist_root)` finds that pair in
/// the history of the head it receives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletBlacklistHistoryLeafV1 {
    /// List version (the map key); at least 1.
    pub list_version: u64,
    /// Gap-tree root of that list version, a nonzero canonical σ-field value.
    pub entries_root: [u8; 32],
}

impl KagemushaWalletBlacklistHistoryLeafV1 {
    /// Poseidon domain of this map's values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_BLACKLIST_HISTORY_VALUE_DOMAIN_V1;

    /// Map key: the list version as one element.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        kagemusha_wallet_field_from_u128_v1(u128::from(self.list_version))
    }

    /// Leaf elements: list version, entries root (2).
    ///
    /// # Errors
    ///
    /// Rejects version zero and a zero or noncanonical root.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        if self.list_version == 0 {
            return Err(invalid_v1("blacklist_history.list_version"));
        }
        require_nonzero_field_v1("blacklist_history.entries_root", &self.entries_root)?;
        Ok(WalletFieldItemsV1::with_capacity(2)
            .integer(u128::from(self.list_version))
            .field(&self.entries_root)
            .finish())
    }

    /// Map value `P(kgwbhst1, elements)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }

    /// Verify that `leaf` at `opening` proves this pair present under `history_root`: the
    /// version's leaf with exactly this entries root.
    ///
    /// # Errors
    ///
    /// Rejects an invalid pair, a leaf of another key or value (another root recorded for the
    /// version), and an opening that does not reach `history_root`.
    pub fn verify_membership(
        &self,
        history_root: &[u8; 32],
        leaf: &KagemushaWalletIndexedLeafV1,
        opening: &KagemushaWalletIndexedOpeningV1,
    ) -> WalletResult<()> {
        if leaf.key != self.key() || leaf.value != self.leaf_value()? {
            return Err(invalid_v1("blacklist_history.leaf"));
        }
        kagemusha_wallet_indexed_verify_membership_v1(history_root, leaf, opening)
            .map_err(|_| invalid_v1("blacklist_history.opening"))
    }

    /// Insert this pair into the native history store `history` and return the witness.
    ///
    /// # Errors
    ///
    /// Rejects an invalid pair and a version the history already holds.
    pub fn insert_into(
        &self,
        history: &mut KagemushaWalletIndexedTreeV1,
    ) -> WalletResult<KagemushaWalletIndexedInsertV1> {
        history.insert(self.key(), self.leaf_value()?)
    }
}

/// Exact σ-field preimage of one chain append: `[chain] || entry elements` (§3).
fn chain_append_preimage_v1(chain: &[u8; 32], entry: Vec<[u8; 32]>) -> WalletResult<Vec<[u8; 32]>> {
    require_canonical_field_v1("chain", chain)?;
    let mut items = Vec::with_capacity(entry.len().saturating_add(1));
    items.push(*chain);
    items.extend(entry);
    Ok(items)
}

/// Descriptor appended to `send_chain` by one Send (§3): `credit_id`, counterparty wallet and
/// amount, and for a send also its ordinal, fee and Request digest. It contains no Payment
/// digest.
///
/// `send_chain' = P(kgwschn1, [send_chain] || descriptor elements)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(16))]
pub struct KagemushaWalletSendChainEntryV1 {
    /// Credit identity, a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Receiving wallet.
    pub receiver_wallet_id: [u8; 32],
    /// Consumed payer send ordinal.
    pub send_ordinal: u128,
    /// Amount credited to the receiver.
    pub amount: u128,
    /// Fee earned at the Send commit.
    pub fee: u128,
    /// Request digest.
    pub request_digest: [u8; 32],
}

impl KagemushaWalletSendChainEntryV1 {
    /// Poseidon domain of the append.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1;

    /// Entry elements: the pending-outgoing descriptor order (8).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id`.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        send_descriptor_items_v1(
            &self.credit_id,
            &self.receiver_wallet_id,
            self.send_ordinal,
            self.amount,
            self.fee,
            &self.request_digest,
        )
    }

    /// σ-field preimage `[send_chain] || elements` of appending this entry to `send_chain`.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical chain value and what [`Self::field_items`] rejects.
    pub fn append_preimage(&self, send_chain: &[u8; 32]) -> WalletResult<Vec<[u8; 32]>> {
        chain_append_preimage_v1(send_chain, self.field_items()?)
    }

    /// Successor chain `P(kgwschn1, [send_chain] || elements)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::append_preimage`] rejects.
    pub fn append(&self, send_chain: &[u8; 32]) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(
            Self::DOMAIN,
            &self.append_preimage(send_chain)?,
        ))
    }
}

/// Descriptor appended to `recv_chain` by one Receive (§3): `credit_id`, counterparty wallet
/// and amount. It contains no Payment digest.
///
/// `recv_chain' = P(kgwrchn1, [recv_chain] || descriptor elements)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(16))]
pub struct KagemushaWalletRecvChainEntryV1 {
    /// Credit identity, a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Paying wallet.
    pub payer_wallet_id: [u8; 32],
    /// Amount credited.
    pub amount: u128,
}

impl KagemushaWalletRecvChainEntryV1 {
    /// Poseidon domain of the append.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1;

    /// Entry elements: `credit_id`, payer wallet (2), amount (4).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id`.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("recv_chain.credit_id", &self.credit_id)?;
        Ok(WalletFieldItemsV1::with_capacity(4)
            .field(&self.credit_id)
            .digest(&self.payer_wallet_id)
            .integer(self.amount)
            .finish())
    }

    /// σ-field preimage `[recv_chain] || elements` of appending this entry to `recv_chain`.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical chain value and what [`Self::field_items`] rejects.
    pub fn append_preimage(&self, recv_chain: &[u8; 32]) -> WalletResult<Vec<[u8; 32]>> {
        chain_append_preimage_v1(recv_chain, self.field_items()?)
    }

    /// Successor chain `P(kgwrchn1, [recv_chain] || elements)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::append_preimage`] rejects.
    pub fn append(&self, recv_chain: &[u8; 32]) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(
            Self::DOMAIN,
            &self.append_preimage(recv_chain)?,
        ))
    }
}

/// Lineage-level credit-digest entry `credit_id → (Payment digest, burned flag)` (§3).
///
/// `Λ_recv` inserts it into the credit-digest root that Ω exposes and `CreditStatus` opens; it
/// is not part of the state commitment. The tree is the depth-32 indexed tree of
/// [`super::poseidon`] keyed by `credit_id` (owner answer A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletCreditDigestLeafV1 {
    /// Credit identity (the tree key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Digest of the full canonical Payment that credited it, a canonical σ-field value.
    pub payment_digest: [u8; 32],
    /// Whether `Λ_recv` took the burn branch for this credit (§3.2).
    pub burned: bool,
}

impl KagemushaWalletCreditDigestLeafV1 {
    /// Poseidon domain of this value.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1;

    /// Tree key: `credit_id`.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.credit_id
    }

    /// Leaf elements: `credit_id`, Payment digest, burned flag `0` or `1` (3).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id` or Payment digest.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("credit_digest.credit_id", &self.credit_id)?;
        require_nonzero_field_v1("credit_digest.payment_digest", &self.payment_digest)?;
        Ok(WalletFieldItemsV1::with_capacity(3)
            .field(&self.credit_id)
            .field(&self.payment_digest)
            .integer(u128::from(self.burned))
            .finish())
    }

    /// Map value `P(kgwcdig1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects.
    pub fn leaf_value(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(Self::DOMAIN, &self.field_items()?))
    }

    /// Indexed-tree leaf `(credit_id, value, next_key)` of this entry.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::field_items`] rejects and a `next_key` that is noncanonical or
    /// nonzero and not above `credit_id`.
    pub fn indexed_leaf(&self, next_key: [u8; 32]) -> WalletResult<KagemushaWalletIndexedLeafV1> {
        let leaf = KagemushaWalletIndexedLeafV1 {
            key: self.credit_id,
            value: self.leaf_value()?,
            next_key,
        };
        leaf.validate()?;
        Ok(leaf)
    }
}

impl KagemushaWalletCreditDigestLeafV1 {
    /// Record this entry in the native credit-digest tree `tree` (§3.2, owner-approved decision
    /// Q3): membership or insert. An absent `credit_id` is inserted with this entry; a present
    /// one keeps its recorded leaf, so its Payment digest and `burned` flag stay as they were at
    /// the first insertion even when they differ from this entry, and the root is unchanged.
    ///
    /// # Errors
    ///
    /// Rejects an invalid entry and a full tree.
    pub fn record(
        &self,
        tree: &mut KagemushaWalletIndexedTreeV1,
    ) -> WalletResult<KagemushaWalletCreditDigestRecordV1> {
        let value = self.leaf_value()?;
        if tree.get(&self.credit_id).is_some() {
            let (leaf, opening) = tree.membership(&self.credit_id)?;
            Ok(KagemushaWalletCreditDigestRecordV1::Present { leaf, opening })
        } else {
            Ok(KagemushaWalletCreditDigestRecordV1::Inserted {
                witness: tree.insert(self.credit_id, value)?,
            })
        }
    }
}

/// One `Λ_recv` credit-digest update (§3.2, owner-approved decision Q3): the single opening of
/// the membership-or-insert gadget, either the key's own leaf (present, root unchanged) or its
/// low leaf (absent, insert). The credit-digest tree stays insert-only and `burned` is fixed at
/// the first insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Both variants retain fixed inline Copy proof witnesses; boxing would introduce heap custody and change the record API"
)]
pub enum KagemushaWalletCreditDigestRecordV1 {
    /// `credit_id` is already recorded: its existing leaf and opening.
    Present {
        /// Recorded leaf of `credit_id`, with its first Payment digest and burned flag.
        leaf: KagemushaWalletIndexedLeafV1,
        /// Opening of the recorded leaf against the old root.
        opening: KagemushaWalletIndexedOpeningV1,
    },
    /// `credit_id` is absent: the insertion of the proposed entry.
    Inserted {
        /// Insertion witness against the old root.
        witness: KagemushaWalletIndexedInsertV1,
    },
}

impl KagemushaWalletCreditDigestRecordV1 {
    /// Verify the update of `old_root` for the `proposed` entry and return the successor root:
    /// `old_root` for a present key, whatever Payment digest and burned flag it records, or the
    /// root after inserting `proposed`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid proposed entry, a present leaf of another key or an opening that does
    /// not reach `old_root`, and what [`KagemushaWalletIndexedInsertV1::verify`] rejects (an
    /// insertion of a present key included).
    pub fn verify(
        &self,
        old_root: &[u8; 32],
        proposed: &KagemushaWalletCreditDigestLeafV1,
    ) -> WalletResult<[u8; 32]> {
        let value = proposed.leaf_value()?;
        match self {
            Self::Present { leaf, opening } => {
                if leaf.key != proposed.credit_id {
                    return Err(invalid_v1("credit_digest.record"));
                }
                kagemusha_wallet_indexed_verify_membership_v1(old_root, leaf, opening)?;
                Ok(*old_root)
            }
            Self::Inserted { witness } => witness.verify(old_root, &proposed.credit_id, &value),
        }
    }
}

/// The consumed-credit transition `Λ_recv` checks from the predecessor core to the committed
/// successor core (§3.2; owner answer B3 of the third set).
///
/// On accept the credit is inserted. On the burn branch the credit stays consumed, and with a
/// duplicate `credit_id` (already in the predecessor's root) the committed consumed-credit root
/// equals the predecessor's root or is a structurally valid indexed-tree insert of a fresh key,
/// one proved absent from the predecessor's root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaWalletConsumedCreditTransitionV1 {
    /// Accept: the insertion of the Receive's consumed-credit entry.
    Accept {
        /// Insertion witness of `credit_id` against the predecessor root.
        witness: KagemushaWalletIndexedInsertV1,
    },
    /// Burn with the committed root equal to the predecessor's root.
    BurnUnchanged,
    /// Burn with the committed root a structurally valid insert of a fresh key.
    BurnInserted {
        /// Inserted key, absent from the predecessor root.
        key: [u8; 32],
        /// Inserted nonzero canonical value.
        value: [u8; 32],
        /// Insertion witness against the predecessor root.
        witness: KagemushaWalletIndexedInsertV1,
    },
}

impl KagemushaWalletConsumedCreditTransitionV1 {
    /// Verify that `committed_root` follows `predecessor_root` under this branch for the
    /// Receive's consumed-credit `entry`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid entry, an accept witness that does not insert `entry`, a burn insert
    /// of a key present in the predecessor root or with an invalid witness, and a committed root
    /// other than the one the branch yields.
    pub fn verify(
        &self,
        predecessor_root: &[u8; 32],
        committed_root: &[u8; 32],
        entry: &KagemushaWalletConsumedCreditLeafV1,
    ) -> WalletResult<()> {
        let value = entry.leaf_value()?;
        let expected = match self {
            Self::Accept { witness } => {
                witness.verify(predecessor_root, &entry.credit_id, &value)?
            }
            Self::BurnUnchanged => *predecessor_root,
            Self::BurnInserted {
                key,
                value,
                witness,
            } => witness.verify(predecessor_root, key, value)?,
        };
        if expected == *committed_root {
            Ok(())
        } else {
            Err(invalid_v1("consumed_credit.root"))
        }
    }
}

// ---------------------------------------------------------------------------------------
// Operations, effects and statements (§§3.1, 3.2, 4.1)
// ---------------------------------------------------------------------------------------

/// Kind of one proven state transition; each tag has its own step relation (§3.2).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletOperationKindV1"
)]
pub enum KagemushaWalletOperationKindV1 {
    /// Install the zero state of a newly enrolled incarnation.
    #[codec(index = 1)]
    Bootstrap,
    /// Absorb the next finalized ordinary Load receipt.
    #[codec(index = 2)]
    Load,
    /// Irreversibly debit a payment to a bound receiver.
    #[codec(index = 3)]
    Send,
    /// Credit a received Payment once.
    #[codec(index = 4)]
    Receive,
    /// Remove a delivered pending-outgoing descriptor.
    #[codec(index = 5)]
    ArchiveSent,
    /// Create a ledger-directed redemption claim.
    #[codec(index = 6)]
    Unload,
    /// Apply one authenticated policy update.
    #[codec(index = 7)]
    RefreshPolicy,
    /// Close new receiving quotes and funding, preserving Send of remaining value.
    #[codec(index = 8)]
    Retiring,
}

impl KagemushaWalletOperationKindV1 {
    /// Every operation kind, in tag order.
    pub const ALL: [Self; 8] = [
        Self::Bootstrap,
        Self::Load,
        Self::Send,
        Self::Receive,
        Self::ArchiveSent,
        Self::Unload,
        Self::RefreshPolicy,
        Self::Retiring,
    ];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Load => 2,
            Self::Send => 3,
            Self::Receive => 4,
            Self::ArchiveSent => 5,
            Self::Unload => 6,
            Self::RefreshPolicy => 7,
            Self::Retiring => 8,
        }
    }

    /// Whether the operation commits only from a folded head and its σ consumes Ω(pred):
    /// Send, Unload and Retiring (§3.1). Its package carries Ω(pred) and its receipt uses the
    /// Ω‖σ `proof_digest` domain; every other operation uses the σ-only domain.
    #[must_use]
    pub const fn consumes_lineage(self) -> bool {
        matches!(self, Self::Send | Self::Unload | Self::Retiring)
    }
}

/// Kind of the signed object applied by one `RefreshPolicy` transition (design C1).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPolicyUpdateKindV1"
)]
pub enum KagemushaWalletPolicyUpdateKindV1 {
    /// Replacement credential (lease renewal).
    #[codec(index = 1)]
    Credential,
    /// Scheme policy.
    #[codec(index = 2)]
    SchemePolicy,
    /// Blacklist.
    #[codec(index = 3)]
    Blacklist,
    /// Quota share.
    #[codec(index = 4)]
    QuotaShare,
    /// Time anchor.
    #[codec(index = 5)]
    TimeAnchor,
}

impl KagemushaWalletPolicyUpdateKindV1 {
    /// Every update kind, in tag order.
    pub const ALL: [Self; 5] = [
        Self::Credential,
        Self::SchemePolicy,
        Self::Blacklist,
        Self::QuotaShare,
        Self::TimeAnchor,
    ];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Credential => 1,
            Self::SchemePolicy => 2,
            Self::Blacklist => 3,
            Self::QuotaShare => 4,
            Self::TimeAnchor => 5,
        }
    }
}

/// Public effect of one transition; its tag equals the operation kind (design C1).
///
/// The effect enters the statement digest as its σ-field element list
/// ([`KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1`] elements after zero fill); there is no effect byte
/// transcript. The Send effect binds the exact signed Request by its object digest, which binds
/// the verification dependencies by digest (§8); the Receive effect contains no Payment digest
/// (§§3, 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEffectV1")]
#[repr(align(16))]
pub enum KagemushaWalletEffectV1 {
    /// Install the zero state from the generation-0 enrollment marker.
    #[codec(index = 1)]
    Bootstrap {
        /// Enrollment identity of the credential.
        enrollment_id: [u8; 32],
        /// `marker_digest` of the generation-0 Enrollment marker (design C3).
        enrollment_marker: [u8; 32],
    },
    /// Absorb the ordinary Load receipt at the predecessor's `next_load`.
    #[codec(index = 2)]
    Load {
        /// Ordinary finalized Load receipt digest.
        receipt_digest: [u8; 32],
        /// Consumed load ordinal.
        load_ordinal: u128,
        /// Net offline value added to the balance.
        amount: u128,
        /// Online charge paid on the ledger; zero without a charge quote.
        online_charge: u128,
    },
    /// Irreversibly debit `amount + fee` to the bound receiver.
    #[codec(index = 3)]
    Send {
        /// Credit identity of the Request.
        credit_id: [u8; 32],
        /// Bound receiver wallet.
        receiver_wallet_id: [u8; 32],
        /// Consumed payer send ordinal.
        send_ordinal: u128,
        /// Amount credited to the receiver; positive.
        amount: u128,
        /// Fee earned at this commit.
        fee: u128,
        /// Object digest `P(kgworeq1, ·)` of the signed Request.
        request: [u8; 32],
        /// Effective accepted time lower bound `L`.
        accepted_lower_ms: u64,
        /// Effective accepted time upper bound `U`.
        accepted_upper_ms: u64,
    },
    /// Credit a received Payment once.
    #[codec(index = 4)]
    Receive {
        /// Credit identity.
        credit_id: [u8; 32],
        /// Paying wallet.
        payer_wallet_id: [u8; 32],
        /// Amount added to the balance; positive.
        amount: u128,
    },
    /// Remove the pending-outgoing descriptor of a delivered or burned credit.
    #[codec(index = 5)]
    ArchiveSent {
        /// Credit identity.
        credit_id: [u8; 32],
        /// Credited digest `P_bytes(kgwcrdd1, ·)` of the verified evidence, a canonical
        /// σ-field value.
        credited: [u8; 32],
    },
    /// Create a ledger-directed redemption claim.
    #[codec(index = 6)]
    Unload {
        /// Unload nullifier ([`kagemusha_wallet_unload_nullifier_v1`]).
        nullifier: [u8; 32],
        /// Consumed redemption ordinal.
        redeem_ordinal: u128,
        /// Net offline value subtracted from the balance; positive.
        amount: u128,
        /// Online charge withheld from the payout; at most `amount`.
        online_charge: u128,
        /// Charge quote object digest `P(kgwochg1, ·)`; zero exactly when `online_charge` is
        /// zero.
        charge_quote: [u8; 32],
    },
    /// Apply exactly one signed policy update.
    #[codec(index = 7)]
    RefreshPolicy {
        /// Kind of the applied update object.
        update_kind: KagemushaWalletPolicyUpdateKindV1,
        /// Object digest of the applied update.
        update: [u8; 32],
        /// Successor accepted time floor.
        accepted_time_floor_ms: u64,
    },
    /// Close new receiving quotes and funding; `next_load` is in the statement.
    #[codec(index = 8)]
    Retiring,
}

impl KagemushaWalletEffectV1 {
    /// Operation kind of this effect.
    #[must_use]
    pub const fn kind(&self) -> KagemushaWalletOperationKindV1 {
        match self {
            Self::Bootstrap { .. } => KagemushaWalletOperationKindV1::Bootstrap,
            Self::Load { .. } => KagemushaWalletOperationKindV1::Load,
            Self::Send { .. } => KagemushaWalletOperationKindV1::Send,
            Self::Receive { .. } => KagemushaWalletOperationKindV1::Receive,
            Self::ArchiveSent { .. } => KagemushaWalletOperationKindV1::ArchiveSent,
            Self::Unload { .. } => KagemushaWalletOperationKindV1::Unload,
            Self::RefreshPolicy { .. } => KagemushaWalletOperationKindV1::RefreshPolicy,
            Self::Retiring => KagemushaWalletOperationKindV1::Retiring,
        }
    }

    /// Transcript tag; equal to the Norito wire tag and the operation kind tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        self.kind().tag()
    }

    /// Operation-id input of this effect (§4.1): Bootstrap enrollment id, Load receipt digest,
    /// Send and Receive credit id, `ArchiveSent` Credited digest, Unload nullifier,
    /// `RefreshPolicy` update digest, and the zero element for Retiring. Every input other than
    /// the Bootstrap enrollment id (two limbs) is one `P` element
    /// ([`kagemusha_wallet_operation_id_v1`]).
    ///
    /// `ArchiveSent` uses the Credited digest, which binds the credit id, because a no-op
    /// archive branch lets the wallet archive the same descriptor again with new evidence
    /// (§3.2); reusing an operation id with changed inputs fails (§4.1).
    #[must_use]
    pub const fn operation_input(&self) -> [u8; 32] {
        match self {
            Self::Bootstrap { enrollment_id, .. } => *enrollment_id,
            Self::Load { receipt_digest, .. } => *receipt_digest,
            Self::Send { credit_id, .. } | Self::Receive { credit_id, .. } => *credit_id,
            Self::ArchiveSent { credited, .. } => *credited,
            Self::Unload { nullifier, .. } => *nullifier,
            Self::RefreshPolicy { update, .. } => *update,
            Self::Retiring => [0; 32],
        }
    }

    /// Position of this variant in the tag-ordered width tables.
    const fn index(&self) -> usize {
        match self {
            Self::Bootstrap { .. } => 0,
            Self::Load { .. } => 1,
            Self::Send { .. } => 2,
            Self::Receive { .. } => 3,
            Self::ArchiveSent { .. } => 4,
            Self::Unload { .. } => 5,
            Self::RefreshPolicy { .. } => 6,
            Self::Retiring => 7,
        }
    }

    /// σ-field element count of this variant before zero fill.
    const fn field_items_len(&self) -> usize {
        EFFECT_FIELD_ITEMS[self.index()]
    }

    /// Append this variant's σ-field elements: every `P` value (`credit_id` and the receipt digest,
    /// Request, Credited, nullifier, charge-quote and update digests) is one element; the
    /// Bootstrap enrollment id and marker digest are two limbs each.
    fn write_field_items(&self, items: WalletFieldItemsV1) -> WalletFieldItemsV1 {
        match self {
            Self::Bootstrap {
                enrollment_id,
                enrollment_marker,
            } => items.digest(enrollment_id).digest(enrollment_marker),
            Self::Load {
                receipt_digest,
                load_ordinal,
                amount,
                online_charge,
            } => items
                .field(receipt_digest)
                .integer(*load_ordinal)
                .integer(*amount)
                .integer(*online_charge),
            Self::Send {
                credit_id,
                receiver_wallet_id,
                send_ordinal,
                amount,
                fee,
                request,
                accepted_lower_ms,
                accepted_upper_ms,
            } => items
                .field(credit_id)
                .digest(receiver_wallet_id)
                .integer(*send_ordinal)
                .integer(*amount)
                .integer(*fee)
                .field(request)
                .integer(u128::from(*accepted_lower_ms))
                .integer(u128::from(*accepted_upper_ms)),
            Self::Receive {
                credit_id,
                payer_wallet_id,
                amount,
            } => items
                .field(credit_id)
                .digest(payer_wallet_id)
                .integer(*amount),
            Self::ArchiveSent {
                credit_id,
                credited,
            } => items.field(credit_id).field(credited),
            Self::Unload {
                nullifier,
                redeem_ordinal,
                amount,
                online_charge,
                charge_quote,
            } => items
                .field(nullifier)
                .integer(*redeem_ordinal)
                .integer(*amount)
                .integer(*online_charge)
                .field(charge_quote),
            Self::RefreshPolicy {
                update_kind,
                update,
                accepted_time_floor_ms,
            } => items
                .integer(u128::from(update_kind.tag()))
                .field(update)
                .integer(u128::from(*accepted_time_floor_ms)),
            Self::Retiring => items,
        }
    }

    /// Validate the effect's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, a zero or noncanonical `P` value (`credit_id`, receipt digest, Request,
    /// Credited, nullifier and update digests; a noncanonical charge-quote digest), a zero Send,
    /// Receive or Unload amount, a Send whose gross debit overflows or whose accepted interval
    /// is inverted, and an Unload whose online charge exceeds its amount or disagrees with its
    /// charge quote.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Bootstrap {
                enrollment_id,
                enrollment_marker,
            } => {
                require_nonzero_v1("effect.enrollment_id", enrollment_id)?;
                require_nonzero_v1("effect.enrollment_marker", enrollment_marker)
            }
            Self::Load { receipt_digest, .. } => {
                require_nonzero_field_v1("effect.receipt_digest", receipt_digest)
            }
            Self::Send {
                credit_id,
                receiver_wallet_id,
                amount,
                fee,
                request,
                accepted_lower_ms,
                accepted_upper_ms,
                ..
            } => {
                require_nonzero_field_v1("effect.credit_id", credit_id)?;
                require_nonzero_v1("effect.receiver_wallet_id", receiver_wallet_id)?;
                require_nonzero_field_v1("effect.request", request)?;
                if *amount == 0 {
                    return Err(invalid_v1("effect.amount"));
                }
                amount
                    .checked_add(*fee)
                    .ok_or_else(|| overflow_v1("effect.gross"))?;
                if accepted_lower_ms > accepted_upper_ms {
                    return Err(invalid_v1("effect.accepted_time"));
                }
                Ok(())
            }
            Self::Receive {
                credit_id,
                payer_wallet_id,
                amount,
            } => {
                require_nonzero_field_v1("effect.credit_id", credit_id)?;
                require_nonzero_v1("effect.payer_wallet_id", payer_wallet_id)?;
                if *amount == 0 {
                    return Err(invalid_v1("effect.amount"));
                }
                Ok(())
            }
            Self::ArchiveSent {
                credit_id,
                credited,
            } => {
                require_nonzero_field_v1("effect.credit_id", credit_id)?;
                require_nonzero_field_v1("effect.credited", credited)
            }
            Self::Unload {
                nullifier,
                amount,
                online_charge,
                charge_quote,
                ..
            } => {
                require_nonzero_field_v1("effect.nullifier", nullifier)?;
                require_canonical_field_v1("effect.charge_quote", charge_quote)?;
                if *amount == 0 {
                    return Err(invalid_v1("effect.amount"));
                }
                if online_charge > amount {
                    return Err(invalid_v1("effect.online_charge"));
                }
                if (*online_charge > 0) == is_zero_v1(charge_quote) {
                    return Err(invalid_v1("effect.charge_quote"));
                }
                Ok(())
            }
            Self::RefreshPolicy { update, .. } => require_nonzero_field_v1("effect.update", update),
            Self::Retiring => Ok(()),
        }
    }
}

/// σ-field elements of one operation identity (§4.1): `wallet_id` (2 limbs), the kind tag, then
/// the input, which is the Bootstrap enrollment id as two limbs, the zero element for Retiring
/// and one `P` element otherwise (4 elements, 5 for Bootstrap; kind and arity make the encoding
/// injective).
///
/// # Errors
///
/// Rejects a Retiring input other than zero and a noncanonical `P` input.
pub fn kagemusha_wallet_operation_id_items_v1(
    wallet_id: &[u8; 32],
    kind: KagemushaWalletOperationKindV1,
    input: &[u8; 32],
) -> WalletResult<Vec<[u8; 32]>> {
    let items = WalletFieldItemsV1::with_capacity(5)
        .digest(wallet_id)
        .integer(u128::from(kind.tag()));
    let items = match kind {
        KagemushaWalletOperationKindV1::Bootstrap => items.digest(input),
        KagemushaWalletOperationKindV1::Retiring => {
            if !is_zero_v1(input) {
                return Err(invalid_v1("operation_id.input"));
            }
            items.field(input)
        }
        _ => {
            require_canonical_field_v1("operation_id.input", input)?;
            items.field(input)
        }
    };
    Ok(items.finish())
}

/// Provider operation identity `P(kgwopid1, [wallet_id (2), kind] || input)` (§4.1, owner
/// answer B1), one canonical σ-field value.
///
/// # Errors
///
/// Rejects what [`kagemusha_wallet_operation_id_items_v1`] rejects.
pub fn kagemusha_wallet_operation_id_v1(
    wallet_id: &[u8; 32],
    kind: KagemushaWalletOperationKindV1,
    input: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    Ok(poseidon_items_v1(
        KAGEMUSHA_WALLET_OPERATION_ID_DOMAIN_V1,
        &kagemusha_wallet_operation_id_items_v1(wallet_id, kind, input)?,
    ))
}

/// σ-field elements of one unload nullifier: `scheme_id` (2), `wallet_id` (2),
/// `redeem_ordinal` (5).
#[must_use]
pub fn kagemusha_wallet_unload_nullifier_items_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    redeem_ordinal: u128,
) -> Vec<[u8; 32]> {
    WalletFieldItemsV1::with_capacity(5)
        .digest(scheme_id)
        .digest(wallet_id)
        .integer(redeem_ordinal)
        .finish()
}

/// Unload nullifier `P(kgwnull1, [scheme_id (2), wallet_id (2), redeem_ordinal])` (§6.1, owner
/// answer B1), one canonical σ-field value.
#[must_use]
pub fn kagemusha_wallet_unload_nullifier_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    redeem_ordinal: u128,
) -> [u8; 32] {
    poseidon_items_v1(
        KAGEMUSHA_WALLET_NULLIFIER_DOMAIN_V1,
        &kagemusha_wallet_unload_nullifier_items_v1(scheme_id, wallet_id, redeem_ordinal),
    )
}

/// Public statement of one transition (§§3.1, 3.2).
///
/// `lifecycle`, `sequence` and `next_load` are the successor state's values. Bootstrap has
/// sequence zero and an all-zero predecessor; every later sequence is its predecessor's plus
/// one. `enabled_controls` is the predecessor core's mask that σ enforced (`σ_send`'s statement
/// binds it, §3.2). For Send, Unload and Retiring the lineage fields are Ω(pred)'s
/// `burned_total` and pending-outgoing root, which σ takes as public inputs; every other
/// operation carries the core values forward and its lineage fields are zero (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStatementV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletStatementV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Frozen relation identity of the scheme.
    pub relation_id: [u8; 32],
    /// Digest of the credential this transition runs under.
    pub credential_digest: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Successor lifecycle.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Successor sequence.
    pub sequence: u128,
    /// Successor `next_load`.
    pub next_load: u128,
    /// Predecessor core's enabled-controls mask enforced by σ.
    pub enabled_controls: u32,
    /// Ω(pred)'s lineage-adjusted `burned_total`; zero unless the operation consumes Ω(pred).
    pub lineage_burned_total: u128,
    /// Ω(pred)'s pending-outgoing root; zero unless the operation consumes Ω(pred).
    pub lineage_pending_outgoing_root: [u8; 32],
    /// Predecessor state commitment.
    pub predecessor: KagemushaWalletStateCommitmentV1,
    /// Successor state commitment.
    pub successor: KagemushaWalletStateCommitmentV1,
    /// Public effect.
    pub effect: KagemushaWalletEffectV1,
}

impl KagemushaWalletStatementV1 {
    /// σ public-input encoding of the statement (§3.2): the
    /// [`KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1`] σ-field elements hashed as
    /// `P(kgwstmt1, items)` ([`Self::statement_digest`]). There is no statement byte
    /// transcript.
    ///
    /// Order: version; relation id (2); scheme id (2); asset digest (2); credential digest;
    /// successor lifecycle, sequence and `next_load`; enabled controls; lineage `burned_total`;
    /// lineage pending-outgoing root; predecessor; successor; effect tag; the effect's elements
    /// zero-filled to [`KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1`] (26 elements).
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        self.validate()?;
        let items = WalletFieldItemsV1::with_capacity(KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1)
            .integer(u128::from(self.version))
            .digest(&self.relation_id)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .field(&self.credential_digest)
            .integer(u128::from(self.lifecycle.tag()))
            .integer(self.sequence)
            .integer(self.next_load)
            .integer(u128::from(self.enabled_controls))
            .integer(self.lineage_burned_total)
            .field(&self.lineage_pending_outgoing_root)
            .field(&self.predecessor.value)
            .field(&self.successor.value)
            .integer(u128::from(self.effect.tag()));
        let items = self.effect.write_field_items(items).zeros(
            KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1.saturating_sub(self.effect.field_items_len()),
        );
        debug_assert_eq!(items.len(), KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1);
        Ok(items.finish())
    }

    /// Statement digest `P(kgwstmt1, field items)` (§3.2, owner answer B1): the σ statement
    /// digest, which the receipt, the package, the output descriptor and `CreditStatus` bind.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement.
    pub fn statement_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(
            KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
            &self.field_items()?,
        ))
    }

    /// Operation identity of this transition for `wallet_id` (§4.1).
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_operation_id_v1`] rejects.
    pub fn operation_id(&self, wallet_id: &[u8; 32]) -> WalletResult<[u8; 32]> {
        kagemusha_wallet_operation_id_v1(
            wallet_id,
            self.effect.kind(),
            &self.effect.operation_input(),
        )
    }

    /// Validate the statement's self-contained rules (§§3.1, 3.2, design §4.2).
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a noncanonical credential digest, undefined
    /// control bits, a noncanonical predecessor or lineage root, an incomplete successor, an
    /// invalid effect, lineage fields
    /// present for an operation that does not consume Ω(pred) or a missing lineage root for
    /// one that does, a Bootstrap that is not the unique zero-state base case, a later
    /// transition without a predecessor, a Retiring effect whose successor is not Retiring, a
    /// Load whose `next_load` is not its ordinal plus one, and a replacement-credential refresh
    /// whose update is not the statement's credential.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("statement.version", self.version)?;
        for (field, digest) in [
            ("statement.scheme_id", &self.scheme_id),
            ("statement.relation_id", &self.relation_id),
            ("statement.asset_digest", &self.asset_digest),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        require_nonzero_field_v1("statement.credential_digest", &self.credential_digest)?;
        if self.enabled_controls & !KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 != 0 {
            return Err(invalid_v1("statement.enabled_controls"));
        }
        require_canonical_field_v1("statement.predecessor", &self.predecessor.value)?;
        require_nonzero_field_v1("statement.successor", &self.successor.value)?;
        require_canonical_field_v1(
            "statement.lineage_pending_outgoing_root",
            &self.lineage_pending_outgoing_root,
        )?;
        self.effect.validate()?;
        if self.effect.kind().consumes_lineage() {
            require_nonzero_v1(
                "statement.lineage_pending_outgoing_root",
                &self.lineage_pending_outgoing_root,
            )?;
        } else if self.lineage_burned_total != 0 || !is_zero_v1(&self.lineage_pending_outgoing_root)
        {
            return Err(invalid_v1("statement.lineage"));
        }
        if let KagemushaWalletEffectV1::Bootstrap { .. } = &self.effect {
            if self.sequence != 0
                || !self.predecessor.is_zero()
                || self.lifecycle != KagemushaWalletLifecycleV1::Active
                || self.next_load != 0
                || self.enabled_controls != 0
            {
                return Err(invalid_v1("statement.bootstrap"));
            }
        } else {
            if self.sequence == 0 {
                return Err(invalid_v1("statement.sequence"));
            }
            if self.predecessor.is_zero() {
                return Err(invalid_v1("statement.predecessor"));
            }
        }
        match &self.effect {
            KagemushaWalletEffectV1::Retiring
                if self.lifecycle != KagemushaWalletLifecycleV1::Retiring =>
            {
                Err(invalid_v1("statement.lifecycle"))
            }
            KagemushaWalletEffectV1::Load { load_ordinal, .. } => {
                let next = load_ordinal
                    .checked_add(1)
                    .ok_or_else(|| overflow_v1("statement.next_load"))?;
                if self.next_load == next {
                    Ok(())
                } else {
                    Err(invalid_v1("statement.next_load"))
                }
            }
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                update,
                ..
            } if *update != self.credential_digest => Err(invalid_v1("effect.update")),
            _ => Ok(()),
        }
    }

    /// Validate the statement against the scheme it claims.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement, another scheme, or another relation.
    pub fn validate_for_scheme(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        require_scheme_v1("statement.scheme_id", &self.scheme_id, &scheme.scheme_id())?;
        require_scheme_v1(
            "statement.relation_id",
            &self.relation_id,
            &scheme.relation_id,
        )
    }

    /// Validate the statement against the credential it runs under.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement, another scheme, credential or asset, a Bootstrap for
    /// another enrollment, a Send to or Receive from the wallet itself, and an Unload whose
    /// nullifier does not recompute.
    pub fn validate_for_credential(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> WalletResult<()> {
        self.validate()?;
        credential.validate()?;
        let body = &credential.body;
        require_scheme_v1("statement.scheme_id", &self.scheme_id, &body.scheme_id)?;
        if self.credential_digest != credential.credential_digest() {
            return Err(invalid_v1("statement.credential_digest"));
        }
        if self.asset_digest != body.asset_digest {
            return Err(invalid_v1("statement.asset_digest"));
        }
        self.validate_effect_for_wallet(&body.scheme_id, &body.wallet_id)?;
        match &self.effect {
            KagemushaWalletEffectV1::Bootstrap { enrollment_id, .. }
                if *enrollment_id != body.enrollment_id =>
            {
                Err(invalid_v1("effect.enrollment_id"))
            }
            _ => Ok(()),
        }
    }

    /// Wallet-bound effect rules: no Send to or Receive from the wallet itself, and an Unload
    /// nullifier that recomputes for `wallet_id`.
    fn validate_effect_for_wallet(
        &self,
        scheme_id: &[u8; 32],
        wallet_id: &[u8; 32],
    ) -> WalletResult<()> {
        match &self.effect {
            KagemushaWalletEffectV1::Send {
                receiver_wallet_id, ..
            } if receiver_wallet_id == wallet_id => Err(invalid_v1("effect.receiver_wallet_id")),
            KagemushaWalletEffectV1::Receive {
                payer_wallet_id, ..
            } if payer_wallet_id == wallet_id => Err(invalid_v1("effect.payer_wallet_id")),
            KagemushaWalletEffectV1::Unload {
                nullifier,
                redeem_ordinal,
                ..
            } if *nullifier
                != kagemusha_wallet_unload_nullifier_v1(scheme_id, wallet_id, *redeem_ordinal) =>
            {
                Err(invalid_v1("effect.nullifier"))
            }
            _ => Ok(()),
        }
    }

    /// The §3.2 consumer checks of a statement that consumes `omega` = Ω(pred), run before
    /// mutation: the operation consumes Ω(pred); scheme and relation identity; `σ.predecessor
    /// = Ω.head`; `statement.credential_digest = Ω.credential`; σ's `burned_total` and
    /// pending-outgoing inputs equal Ω's; the enabled-controls mask equals Ω's (which selects
    /// `σ_send`'s verifying key); the predecessor lifecycle is Ω's; and the wallet-bound effect
    /// rules for `Ω.wallet_id`. The receipt check under `Ω.payment_key` is the package's.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement or Ω and every mismatch above.
    pub fn validate_against_lineage(
        &self,
        omega: &KagemushaWalletLineagePublicV1,
    ) -> WalletResult<()> {
        self.validate()?;
        omega.validate()?;
        if !self.effect.kind().consumes_lineage() {
            return Err(invalid_v1("statement.lineage"));
        }
        require_scheme_v1("lineage.scheme_id", &omega.scheme_id, &self.scheme_id)?;
        require_scheme_v1("lineage.relation_id", &omega.relation_id, &self.relation_id)?;
        let predecessor_lifecycle = match self.effect {
            KagemushaWalletEffectV1::Retiring => KagemushaWalletLifecycleV1::Active,
            _ => self.lifecycle,
        };
        for (field, matches) in [
            ("lineage.head", omega.head == self.predecessor),
            (
                "lineage.credential_digest",
                omega.credential_digest == self.credential_digest,
            ),
            (
                "lineage.burned_total",
                omega.burned_total == self.lineage_burned_total,
            ),
            (
                "lineage.pending_outgoing_root",
                omega.pending_outgoing_root == self.lineage_pending_outgoing_root,
            ),
            (
                "lineage.enabled_controls",
                omega.enabled_controls == self.enabled_controls,
            ),
            (
                "lineage.lifecycle",
                omega.lifecycle == predecessor_lifecycle,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        self.validate_effect_for_wallet(&self.scheme_id, &omega.wallet_id)
    }

    /// Validate `self` as the direct successor of `predecessor` (§§3.1, 6.3, design §4.2).
    ///
    /// Every operation other than Retiring keeps the lifecycle, so a Retiring wallet keeps
    /// receiving, loading finalized ordinary receipts, sending and unloading (§6.3).
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement, another scheme, relation or asset, a predecessor
    /// commitment or sequence that does not chain, a lifecycle that reverts or retires twice,
    /// a `next_load` that does not follow its effect, and a credential change outside a
    /// replacement-credential refresh.
    pub fn validate_successor_of(&self, predecessor: &Self) -> WalletResult<()> {
        self.validate()?;
        predecessor.validate()?;
        require_scheme_v1(
            "statement.scheme_id",
            &self.scheme_id,
            &predecessor.scheme_id,
        )?;
        require_scheme_v1(
            "statement.relation_id",
            &self.relation_id,
            &predecessor.relation_id,
        )?;
        if self.asset_digest != predecessor.asset_digest {
            return Err(invalid_v1("statement.asset_digest"));
        }
        if self.predecessor != predecessor.successor {
            return Err(invalid_v1("statement.predecessor"));
        }
        let sequence = predecessor
            .sequence
            .checked_add(1)
            .ok_or_else(|| overflow_v1("statement.sequence"))?;
        if self.sequence != sequence {
            return Err(invalid_v1("statement.sequence"));
        }
        let lifecycle_ok = match self.effect {
            KagemushaWalletEffectV1::Retiring => {
                predecessor.lifecycle == KagemushaWalletLifecycleV1::Active
            }
            _ => self.lifecycle == predecessor.lifecycle,
        };
        if !lifecycle_ok {
            return Err(invalid_v1("statement.lifecycle"));
        }
        let next_load_ok = match self.effect {
            KagemushaWalletEffectV1::Load { load_ordinal, .. } => {
                load_ordinal == predecessor.next_load
            }
            _ => self.next_load == predecessor.next_load,
        };
        if !next_load_ok {
            return Err(invalid_v1("statement.next_load"));
        }
        let replaces_credential = matches!(
            self.effect,
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                ..
            }
        );
        if !replaces_credential && self.credential_digest != predecessor.credential_digest {
            return Err(invalid_v1("statement.credential_digest"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Step proof σ, lineage proof Ω and `proof_digest` (§§3.1, 3.2, 4.1)
// ---------------------------------------------------------------------------------------

/// Step proof σ: the single-parity Vesta proof of one transition's step relation (§3.2).
///
/// Its exact length is the one the verifying-key allowlist records for its selector
/// ([`super::KagemushaWalletVerifyingKeyAllowlistV1::check_step_proof`], owner answers Q6 and
/// Q11); until the artifacts freeze, G1 bounds σ only through the frame that carries it.
// TODO(G3): the concrete PIPA-v1 proof layout and the frozen allowlist lengths come from the
// artifact set.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStepProofV1"
)]
pub struct KagemushaWalletStepProofV1 {
    /// Opaque proof bytes.
    pub bytes: Vec<u8>,
}

impl KagemushaWalletStepProofV1 {
    /// Validate the proof bytes.
    ///
    /// # Errors
    ///
    /// Rejects an empty proof.
    pub fn validate(&self) -> WalletResult<()> {
        if self.bytes.is_empty() {
            return Err(invalid_v1("step_proof.bytes"));
        }
        Ok(())
    }
}

/// Public outputs of one lineage proof Ω (§3.2).
///
/// Ω publicly exposes the head commitment; `wallet_id`, credential digest and `payment_key`;
/// scheme and relation identity; the policy facts (lifecycle, policy epoch and
/// enabled-controls mask); and the lineage-adjusted `burned_total`, pending-outgoing root and
/// credit-digest root. Its fixed transcript prefixes the Ω bytes, so every exposed value is
/// bound by `proof_digest` and the Payment digest (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLineagePublicV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletLineagePublicV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Frozen relation identity of the scheme.
    pub relation_id: [u8; 32],
    /// Folded head commitment.
    pub head: KagemushaWalletStateCommitmentV1,
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Credential object digest `P(kgwocrd1, ·)` of the head.
    pub credential_digest: [u8; 32],
    /// Payment key that signs the wallet's receipts.
    pub payment_key: KagemushaDevicePublicKeyV1,
    /// Lifecycle of the head.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Policy epoch of the head.
    pub policy_epoch: u64,
    /// Enabled-controls mask of the head; selects `σ_send`'s verifying key (§3.2).
    pub enabled_controls: u32,
    /// Lineage-adjusted `burned_total`.
    pub burned_total: u128,
    /// Lineage-adjusted pending-outgoing root.
    pub pending_outgoing_root: [u8; 32],
    /// Lineage-level credit-digest root.
    pub credit_digest_root: [u8; 32],
}

impl KagemushaWalletLineagePublicV1 {
    /// Exact public-output transcript
    /// ([`KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1`] bytes).
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let transcript =
            WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .digest(&self.scheme_id)
                .digest(&self.relation_id);
        self.head
            .write(transcript)
            .digest(&self.wallet_id)
            .digest(&self.credential_digest)
            .key(&self.payment_key)
            .u8(self.lifecycle.tag())
            .u64(self.policy_epoch)
            .u32(self.enabled_controls)
            .u128(self.burned_total)
            .digest(&self.pending_outgoing_root)
            .digest(&self.credit_digest_root)
            .finish()
    }

    /// Validate the public outputs.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, a zero or noncanonical credential digest, an
    /// invalid payment key, an incomplete head, zero or noncanonical roots, and undefined control
    /// bits.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("lineage.version", self.version)?;
        for (field, digest) in [
            ("lineage.scheme_id", &self.scheme_id),
            ("lineage.relation_id", &self.relation_id),
            ("lineage.wallet_id", &self.wallet_id),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        require_nonzero_field_v1("lineage.credential_digest", &self.credential_digest)?;
        self.payment_key.validate()?;
        require_nonzero_field_v1("lineage.head", &self.head.value)?;
        require_nonzero_field_v1("lineage.pending_outgoing_root", &self.pending_outgoing_root)?;
        require_nonzero_field_v1("lineage.credit_digest_root", &self.credit_digest_root)?;
        if self.enabled_controls & !KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 != 0 {
            return Err(invalid_v1("lineage.enabled_controls"));
        }
        Ok(())
    }
}

/// One lineage proof Ω in single-parity transport form: its public outputs and the PIPA-v1
/// transport proof on Pallas with its accumulator and deferred values (§3.2).
///
/// The Ω bytes are `public transcript || proof`: the proof bytes alone do not contain their
/// instances, and §8 requires that no unauthenticated extension change the canonical Payment
/// digest while preserving its authorization. A head has at most one recorded Ω, and every
/// Lineage message, Payment and ledger package from that head carries those exact bytes
/// (§3.1 step 5).
// TODO(G3): the transport proof layout and the native decide belong to the artifact set; its
// exact length is the allowlist's transport length (owner answers Q6 and Q11), and until the
// artifacts freeze G1 bounds Ω only through the frame that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLineageV1"
)]
pub struct KagemushaWalletLineageV1 {
    /// Public outputs.
    pub public: KagemushaWalletLineagePublicV1,
    /// Opaque transport proof bytes.
    pub proof: Vec<u8>,
}

impl KagemushaWalletLineageV1 {
    /// Validate the public outputs and the proof bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid public outputs and an empty proof.
    pub fn validate(&self) -> WalletResult<()> {
        self.public.validate()?;
        if self.proof.is_empty() {
            return Err(invalid_v1("lineage.proof"));
        }
        Ok(())
    }

    /// Exact Ω bytes: the public transcript followed by the transport proof.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = self.public.transcript();
        bytes.extend_from_slice(&self.proof);
        bytes
    }

    /// Lineage digest `P_bytes(kgwlin_1, Ω bytes)`, one canonical σ-field value; byte-identity
    /// reuse compares it (§5.1, owner answer A3).
    #[must_use]
    pub fn lineage_digest(&self) -> [u8; 32] {
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, &self.bytes())
    }
}

/// Ω(pred) slot of a package or capsule: present exactly for Send, Unload and Retiring
/// (§3.1).
// The lineage is a bounded value carried inline; boxing would only add an allocation while the
// wire shape stays the same.
#[allow(
    clippy::large_enum_variant,
    reason = "the bounded lineage stays inline in the canonical wire value"
)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLineageSlotV1"
)]
pub enum KagemushaWalletLineageSlotV1 {
    /// No Ω: Bootstrap, Load, Receive, `ArchiveSent` and `RefreshPolicy`.
    #[codec(index = 0)]
    None,
    /// Ω(pred) of a Send, Unload or Retiring.
    #[codec(index = 1)]
    Present {
        /// Lineage proof of the predecessor head.
        lineage: KagemushaWalletLineageV1,
    },
}

impl KagemushaWalletLineageSlotV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Present { .. } => 1,
        }
    }

    /// The carried lineage, if any.
    #[must_use]
    pub const fn lineage(&self) -> Option<&KagemushaWalletLineageV1> {
        match self {
            Self::None => None,
            Self::Present { lineage } => Some(lineage),
        }
    }

    /// Validate the slot against `kind`: present exactly when `kind` consumes Ω(pred), and
    /// a present lineage valid.
    ///
    /// # Errors
    ///
    /// Rejects a slot present or absent against the kind and an invalid lineage.
    pub fn validate_for(&self, kind: KagemushaWalletOperationKindV1) -> WalletResult<()> {
        match (kind.consumes_lineage(), self) {
            (true, Self::Present { lineage }) => lineage.validate(),
            (false, Self::None) => Ok(()),
            _ => Err(invalid_v1("lineage.slot")),
        }
    }
}

/// `proof_digest` bound by the receipt of a `kind` transition (§4.1, owner answer Q9): one
/// canonical σ-field value.
///
/// Send, Unload and Retiring: `P_bytes(kgwprf_1, LE32 len(Ω) || Ω || LE32 len(σ) || σ)` over
/// the Ω(pred) bytes and σ. Every other operation: the distinct σ-only domain
/// `P_bytes(kgwstep1, LE32 len(σ) || σ)`.
///
/// # Errors
///
/// Rejects an empty σ, an invalid Ω, an Ω present or absent against `kind`, and a length above
/// `u32`.
pub fn kagemusha_wallet_proof_digest_v1(
    kind: KagemushaWalletOperationKindV1,
    lineage: Option<&KagemushaWalletLineageV1>,
    step_proof: &KagemushaWalletStepProofV1,
) -> WalletResult<[u8; 32]> {
    step_proof.validate()?;
    let step_len = u32::try_from(step_proof.bytes.len())
        .map_err(|_| overflow_v1("proof_digest.step_proof"))?;
    match (kind.consumes_lineage(), lineage) {
        (true, Some(lineage)) => {
            lineage.validate()?;
            let omega = lineage.bytes();
            let omega_len =
                u32::try_from(omega.len()).map_err(|_| overflow_v1("proof_digest.lineage"))?;
            let capacity = omega
                .len()
                .saturating_add(step_proof.bytes.len())
                .saturating_add(2 * U32_BYTES);
            let body = WalletTranscriptV1::with_capacity(capacity)
                .u32(omega_len)
                .bytes(&omega)
                .u32(step_len)
                .bytes(&step_proof.bytes)
                .finish();
            Ok(kagemusha_wallet_poseidon_bytes_v1(
                KAGEMUSHA_WALLET_PROOF_DOMAIN_V1,
                &body,
            ))
        }
        (false, None) => {
            let body =
                WalletTranscriptV1::with_capacity(step_proof.bytes.len().saturating_add(U32_BYTES))
                    .u32(step_len)
                    .bytes(&step_proof.bytes)
                    .finish();
            Ok(kagemusha_wallet_poseidon_bytes_v1(
                KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
                &body,
            ))
        }
        _ => Err(invalid_v1("proof_digest.lineage")),
    }
}

// ---------------------------------------------------------------------------------------
// Receipt and package (§§3.1, 4.1)
// ---------------------------------------------------------------------------------------

/// Identity under which a receipt is signed and verified: scheme, wallet, provider contract
/// and payment key.
///
/// The signing wallet takes it from its credential. A consumer of a package carrying Ω(pred)
/// takes it from Ω, because τ verifies under `Ω.payment_key` (§3.2) and a Payment carries no
/// payer credential (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletReceiptSignerV1 {
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Provider contract identity.
    pub provider_contract: [u8; 32],
    /// Payment key that signs receipts.
    pub payment_key: KagemushaDevicePublicKeyV1,
}

impl KagemushaWalletReceiptSignerV1 {
    /// Signer identity of `credential`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential.
    pub fn from_credential(credential: &KagemushaWalletCredentialV1) -> WalletResult<Self> {
        credential.validate()?;
        let body = &credential.body;
        Ok(Self {
            scheme_id: body.scheme_id,
            wallet_id: body.wallet_id,
            provider_contract: body.provider_contract,
            payment_key: body.payment_key,
        })
    }

    /// Signer identity exposed by an Ω, under the single V1 provider contract.
    ///
    /// # Errors
    ///
    /// Rejects invalid public outputs.
    pub fn from_lineage(public: &KagemushaWalletLineagePublicV1) -> WalletResult<Self> {
        public.validate()?;
        Ok(Self {
            scheme_id: public.scheme_id,
            wallet_id: public.wallet_id,
            provider_contract: kagemusha_wallet_provider_contract_v1(),
            payment_key: public.payment_key,
        })
    }
}

/// Derived `receipt-body` fields of one commit receipt (§4.1).
///
/// Scheme, wallet and provider contract come from the signer; sequence and commitments from
/// the statement. This value is never transmitted; it is recomputed by every verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(16))]
pub struct KagemushaWalletReceiptBodyV1 {
    /// Receipt version.
    pub version: u16,
    /// Signer scheme.
    pub scheme_id: [u8; 32],
    /// Signer wallet.
    pub wallet_id: [u8; 32],
    /// Signer provider contract.
    pub provider_contract: [u8; 32],
    /// Statement successor sequence.
    pub sequence: u128,
    /// Operation identity `P(kgwopid1, ·)` derived from the statement.
    pub operation_id: [u8; 32],
    /// Statement predecessor commitment.
    pub predecessor: KagemushaWalletStateCommitmentV1,
    /// Statement successor commitment.
    pub successor: KagemushaWalletStateCommitmentV1,
    /// Statement digest `P(kgwstmt1, ·)`.
    pub statement_digest: [u8; 32],
    /// Operation-dependent proof digest ([`kagemusha_wallet_proof_digest_v1`]), a σ-field
    /// value.
    pub proof_digest: [u8; 32],
    /// Recovery capsule digest.
    pub capsule_digest: [u8; 32],
    /// Full canonical Payment digest of a Receive, a σ-field value; zero for every other
    /// operation.
    pub payment_digest: [u8; 32],
}

impl KagemushaWalletReceiptBodyV1 {
    /// Derive the receipt body of `statement` and `proof_digest` under `signer`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement, a statement for another scheme, a zero or noncanonical
    /// proof digest, a zero capsule digest, a noncanonical Payment digest, and a Payment digest
    /// present or absent against the operation (present exactly for Receive).
    pub fn derive(
        signer: &KagemushaWalletReceiptSignerV1,
        statement: &KagemushaWalletStatementV1,
        proof_digest: &[u8; 32],
        capsule_digest: [u8; 32],
        payment_digest: [u8; 32],
    ) -> WalletResult<Self> {
        statement.validate()?;
        require_scheme_v1("receipt.scheme_id", &statement.scheme_id, &signer.scheme_id)?;
        require_nonzero_field_v1("receipt.proof_digest", proof_digest)?;
        require_nonzero_v1("receipt.capsule_digest", &capsule_digest)?;
        require_canonical_field_v1("receipt.payment_digest", &payment_digest)?;
        let receive = statement.effect.kind() == KagemushaWalletOperationKindV1::Receive;
        if receive == is_zero_v1(&payment_digest) {
            return Err(invalid_v1("receipt.payment_digest"));
        }
        Ok(Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: signer.scheme_id,
            wallet_id: signer.wallet_id,
            provider_contract: signer.provider_contract,
            sequence: statement.sequence,
            operation_id: statement.operation_id(&signer.wallet_id)?,
            predecessor: statement.predecessor,
            successor: statement.successor,
            statement_digest: statement.statement_digest()?,
            proof_digest: *proof_digest,
            capsule_digest,
            payment_digest,
        })
    }

    /// Exact `receipt-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let transcript =
            WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .digest(&self.scheme_id)
                .digest(&self.wallet_id)
                .digest(&self.provider_contract)
                .u128(self.sequence)
                .digest(&self.operation_id);
        self.successor
            .write(self.predecessor.write(transcript))
            .digest(&self.statement_digest)
            .digest(&self.proof_digest)
            .digest(&self.capsule_digest)
            .digest(&self.payment_digest)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwrcpt1, transcript)`: the 32 bytes the payment key signs
    /// with ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Receipt, &self.transcript())
    }
}

/// Durable provider commit receipt τ signed by the wallet's payment key (§§4.1, 4.2).
///
/// `payment_digest` is the full canonical Payment digest a Receive receipt binds (§4.1) and
/// zero otherwise; it is carried so a verifier can rebuild τ's body without the Payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletReceiptV1"
)]
pub struct KagemushaWalletReceiptV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Operation identity; recomputed from the statement by every verifier.
    pub operation_id: [u8; 32],
    /// Digest of the frozen recovery capsule body.
    pub capsule_digest: [u8; 32],
    /// Full canonical Payment digest of a Receive; zero otherwise.
    pub payment_digest: [u8; 32],
    /// Payment-key signature over the receipt signing message (`kgwrcpt1`).
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletReceiptV1 {
    /// Freeze a payment-key signature over the derived receipt body of the signing wallet.
    ///
    /// # Errors
    ///
    /// Rejects a statement that does not run under `credential`, what
    /// [`KagemushaWalletReceiptBodyV1::derive`] rejects, and a signature that does not verify
    /// under the credential's payment key.
    pub fn sign(
        credential: &KagemushaWalletCredentialV1,
        statement: &KagemushaWalletStatementV1,
        proof_digest: &[u8; 32],
        capsule_digest: [u8; 32],
        payment_digest: [u8; 32],
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        statement.validate_for_credential(credential)?;
        let signer = KagemushaWalletReceiptSignerV1::from_credential(credential)?;
        let body = KagemushaWalletReceiptBodyV1::derive(
            &signer,
            statement,
            proof_digest,
            capsule_digest,
            payment_digest,
        )?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &signer.payment_key,
            Domain::Receipt,
            &body.signing_message(),
            signer_output,
        )?;
        let receipt = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            operation_id: body.operation_id,
            capsule_digest,
            payment_digest,
            signature,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validate the receipt's self-contained fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero digests, a noncanonical operation identity or Payment
    /// digest, or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("receipt.version", self.version)?;
        require_nonzero_field_v1("receipt.operation_id", &self.operation_id)?;
        require_nonzero_v1("receipt.capsule_digest", &self.capsule_digest)?;
        require_canonical_field_v1("receipt.payment_digest", &self.payment_digest)?;
        self.signature.validate()?;
        Ok(())
    }

    /// Derive this receipt's body for `statement` and `proof_digest` under `signer`.
    ///
    /// # Errors
    ///
    /// Rejects what [`KagemushaWalletReceiptBodyV1::derive`] rejects and an operation
    /// identity that differs from the one derived from the statement.
    pub fn body(
        &self,
        signer: &KagemushaWalletReceiptSignerV1,
        statement: &KagemushaWalletStatementV1,
        proof_digest: &[u8; 32],
    ) -> WalletResult<KagemushaWalletReceiptBodyV1> {
        self.validate()?;
        let body = KagemushaWalletReceiptBodyV1::derive(
            signer,
            statement,
            proof_digest,
            self.capsule_digest,
            self.payment_digest,
        )?;
        if body.operation_id != self.operation_id {
            return Err(invalid_v1("receipt.operation_id"));
        }
        Ok(body)
    }

    /// Verify the receipt and return its object digest `P(kgworcp1, [m, r_lo, r_hi, s_lo,
    /// s_hi])` (owner answer B1).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::body`] rejects and a signature that does not verify under the
    /// signer's payment key.
    pub fn verify(
        &self,
        signer: &KagemushaWalletReceiptSignerV1,
        statement: &KagemushaWalletStatementV1,
        proof_digest: &[u8; 32],
    ) -> WalletResult<[u8; 32]> {
        let body = self.body(signer, statement, proof_digest)?;
        let message = body.signing_message();
        kagemusha_wallet_verify_signature_v1(
            &signer.payment_key,
            Domain::Receipt,
            &message,
            &self.signature,
        )?;
        Ok(kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::Receipt,
            &message,
            &self.signature,
        ))
    }
}

/// Package digest `P(kgwpkg_1, [statement_digest, proof_digest, receipt_digest])` (owner answer
/// B1), one canonical σ-field value.
///
/// # Errors
///
/// Rejects a noncanonical input.
pub fn kagemusha_wallet_package_digest_v1(
    statement_digest: &[u8; 32],
    proof_digest: &[u8; 32],
    receipt_digest: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_PACKAGE_DOMAIN_V1,
        &[*statement_digest, *proof_digest, *receipt_digest],
    )
}

/// Digests of one verified package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletPackageDigestsV1 {
    /// Statement digest.
    pub statement: [u8; 32],
    /// Operation-dependent proof digest.
    pub proof: [u8; 32],
    /// Receipt digest.
    pub receipt: [u8; 32],
    /// Package digest.
    pub package: [u8; 32],
}

/// Complete public state package `(statement, σ, τ)`, plus Ω(pred) when the operation consumes
/// it (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPackageV1"
)]
pub struct KagemushaWalletPackageV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Transition statement.
    pub statement: KagemushaWalletStatementV1,
    /// Ω(pred): present exactly for Send, Unload and Retiring.
    pub lineage: KagemushaWalletLineageSlotV1,
    /// Step proof σ.
    pub step_proof: KagemushaWalletStepProofV1,
    /// Provider commit receipt τ.
    pub receipt: KagemushaWalletReceiptV1,
}

impl KagemushaWalletPackageV1 {
    /// Assemble a package from its parts.
    #[must_use]
    pub fn new(
        statement: KagemushaWalletStatementV1,
        lineage: KagemushaWalletLineageSlotV1,
        step_proof: KagemushaWalletStepProofV1,
        receipt: KagemushaWalletReceiptV1,
    ) -> Self {
        Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            statement,
            lineage,
            step_proof,
            receipt,
        }
    }

    /// Validate the package's self-contained structure, including the §3.2 consumer
    /// equalities between the statement and a carried Ω(pred).
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid statement, σ or receipt, an Ω(pred) present or
    /// absent against the operation or failing
    /// [`KagemushaWalletStatementV1::validate_against_lineage`], and a receipt Payment digest
    /// present or absent against the operation.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("package.version", self.version)?;
        self.statement.validate()?;
        self.step_proof.validate()?;
        self.receipt.validate()?;
        let kind = self.statement.effect.kind();
        self.lineage.validate_for(kind)?;
        if let Some(lineage) = self.lineage.lineage() {
            self.statement.validate_against_lineage(&lineage.public)?;
        }
        if (kind == KagemushaWalletOperationKindV1::Receive)
            == is_zero_v1(&self.receipt.payment_digest)
        {
            return Err(invalid_v1("package.receipt.payment_digest"));
        }
        Ok(())
    }

    /// Operation-dependent `proof_digest` of this package (§4.1).
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_proof_digest_v1`] rejects.
    pub fn proof_digest(&self) -> WalletResult<[u8; 32]> {
        kagemusha_wallet_proof_digest_v1(
            self.statement.effect.kind(),
            self.lineage.lineage(),
            &self.step_proof,
        )
    }

    /// Validate the package, verify its receipt under `signer` and return its digests.
    ///
    /// σ and Ω are verified by the proof owner.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, a receipt whose operation identity does not
    /// recompute, and a receipt signature that does not verify.
    pub fn verify_with(
        &self,
        signer: &KagemushaWalletReceiptSignerV1,
    ) -> WalletResult<KagemushaWalletPackageDigestsV1> {
        self.validate()?;
        let proof = self.proof_digest()?;
        let receipt = self.receipt.verify(signer, &self.statement, &proof)?;
        let statement = self.statement.statement_digest()?;
        Ok(KagemushaWalletPackageDigestsV1 {
            statement,
            proof,
            receipt,
            package: kagemusha_wallet_package_digest_v1(&statement, &proof, &receipt)?,
        })
    }

    /// Verify the package against the credential it runs under and return its digests.
    ///
    /// The credential's own issuer signature is verified separately by its consumer; σ and Ω
    /// are verified by the proof owner.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify_with`] rejects, a statement for another credential, scheme,
    /// asset or enrollment, and an Ω(pred) of another wallet or payment key.
    pub fn verify(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> WalletResult<KagemushaWalletPackageDigestsV1> {
        self.statement.validate_for_credential(credential)?;
        if let Some(lineage) = self.lineage.lineage() {
            if lineage.public.wallet_id != credential.body.wallet_id {
                return Err(invalid_v1("lineage.wallet_id"));
            }
            if lineage.public.payment_key != credential.body.payment_key {
                return Err(invalid_v1("lineage.payment_key"));
            }
        }
        self.verify_with(&KagemushaWalletReceiptSignerV1::from_credential(
            credential,
        )?)
    }

    /// The §3.2 consumer checks of a package carrying Ω(pred), run before mutation by a
    /// receiver, the ledger or a fee-claim verifier that holds no payer credential: the
    /// statement equalities of [`Self::validate`] and τ verified under `Ω.payment_key` and
    /// `Ω.wallet_id`. Returns the receipt signer taken from Ω and the package digests.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify_with`] rejects and a package without Ω(pred).
    pub fn check_lineage_consumer(
        &self,
    ) -> WalletResult<(
        KagemushaWalletReceiptSignerV1,
        KagemushaWalletPackageDigestsV1,
    )> {
        self.validate()?;
        let lineage = self
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?;
        let signer = KagemushaWalletReceiptSignerV1::from_lineage(&lineage.public)?;
        let digests = self.verify_with(&signer)?;
        Ok((signer, digests))
    }

    /// Verifying-key selector of σ (§3.2; owner answers Q11, A5 and B6, technical decision Q5):
    /// the operation tag and, for Send, the enabled-controls mask (equal to
    /// `Ω.enabled_controls` by the consumer checks); for Receive, the blacklist bit exactly when
    /// the package's Request recorded a nonzero receiver blacklist decision
    /// (`receiver_blacklist_version ≠ 0`), whatever the receiver's current enabled controls, so
    /// selecting a Receive key takes the Request; zero for every other operation. Statements and
    /// Ω carry one scheme-level `relation_id`; the selector picks σ's entry of the verifying-key
    /// allowlist ([`super::KagemushaWalletVerifyingKeyAllowlistV1`]) whose digest the relation
    /// binds. `request` is required for Receive and ignored otherwise.
    ///
    /// # Errors
    ///
    /// Rejects a Receive package without a Request, a Request whose `credit_id` is not the
    /// effect's, and an invalid Request body.
    pub fn verifying_key_selector(
        &self,
        request: Option<&KagemushaWalletRequestBodyV1>,
    ) -> WalletResult<(KagemushaWalletOperationKindV1, u32)> {
        let kind = self.statement.effect.kind();
        Ok(match (&self.statement.effect, request) {
            (KagemushaWalletEffectV1::Send { .. }, _) => (kind, self.statement.enabled_controls),
            (KagemushaWalletEffectV1::Receive { credit_id, .. }, Some(request)) => {
                request.validate()?;
                if request.credit_id() != *credit_id {
                    return Err(invalid_v1("package.request"));
                }
                let mask = if request.receiver_blacklist_version == 0 {
                    0
                } else {
                    KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1
                };
                (kind, mask)
            }
            (KagemushaWalletEffectV1::Receive { .. }, None) => {
                return Err(invalid_v1("package.request"));
            }
            _ => (kind, 0),
        })
    }

    /// Package digest after [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify`] rejects.
    pub fn package_digest(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> WalletResult<[u8; 32]> {
        Ok(self.verify(credential)?.package)
    }
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletStateV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("state.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletStatementV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("statement.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletReceiptV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("receipt.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletLineageV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("lineage.version", self.public.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletLineageSlotV1 {
    fn require_versions(&self) -> WalletResult<()> {
        self.lineage()
            .map_or(Ok(()), WalletVersionsV1::require_versions)
    }
}

impl WalletVersionsV1 for KagemushaWalletPackageV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("package.version", self.version)?;
        self.statement.require_versions()?;
        self.lineage.require_versions()?;
        self.receipt.require_versions()
    }
}
