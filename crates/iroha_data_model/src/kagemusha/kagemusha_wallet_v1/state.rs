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
        KagemushaWalletDigestRoleV1 as Role, KagemushaWalletSignerOutputV1,
        KagemushaWalletSigningDomainV1 as Domain, WalletFieldItemsV1, WalletTranscriptV1,
        kagemusha_wallet_digest_v1, kagemusha_wallet_freeze_signature_v1,
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
    overflow_v1,
    policy::KagemushaWalletQuotaWindowKindV1,
    poseidon::{
        KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_CORE_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_PROOF_DOMAIN_V1,
        KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1,
        KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_REST_DOMAIN_V1,
        KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1, KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
        KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1, KagemushaWalletIndexedLeafV1,
        kagemusha_wallet_empty_map_root_v1, kagemusha_wallet_pair_key_v1,
        kagemusha_wallet_poseidon_bytes_v1, poseidon_items_v1,
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

const BOOTSTRAP_EFFECT_FIELDS_BYTES: usize = 2 * DIGEST_BYTES;
const LOAD_EFFECT_FIELDS_BYTES: usize = DIGEST_BYTES + 3 * U128_BYTES;
const SEND_EFFECT_FIELDS_BYTES: usize = 3 * DIGEST_BYTES + 3 * U128_BYTES + 2 * U64_BYTES;
const RECEIVE_EFFECT_FIELDS_BYTES: usize = 2 * DIGEST_BYTES + U128_BYTES;
const ARCHIVE_SENT_EFFECT_FIELDS_BYTES: usize = 2 * DIGEST_BYTES;
const UNLOAD_EFFECT_FIELDS_BYTES: usize = 2 * DIGEST_BYTES + 3 * U128_BYTES;
const REFRESH_POLICY_EFFECT_FIELDS_BYTES: usize = 1 + DIGEST_BYTES + U64_BYTES;
const RETIRING_EFFECT_FIELDS_BYTES: usize = 0;

/// Fixed field widths of every effect variant, in tag order.
const EFFECT_FIELDS_BYTES: [usize; 8] = [
    BOOTSTRAP_EFFECT_FIELDS_BYTES,
    LOAD_EFFECT_FIELDS_BYTES,
    SEND_EFFECT_FIELDS_BYTES,
    RECEIVE_EFFECT_FIELDS_BYTES,
    ARCHIVE_SENT_EFFECT_FIELDS_BYTES,
    UNLOAD_EFFECT_FIELDS_BYTES,
    REFRESH_POLICY_EFFECT_FIELDS_BYTES,
    RETIRING_EFFECT_FIELDS_BYTES,
];

/// σ-field element counts of every effect variant, in tag order: `credit_id` and the Credited
/// digest are one element each (§3, owner answer A3), every other digest two limbs.
const EFFECT_FIELD_ITEMS: [usize; 8] = [4, 5, 10, 4, 2, 7, 4, 0];

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

/// Zero-filled union width of every effect transcript: the largest variant (Send).
pub const KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1: usize = max_width_v1(&EFFECT_FIELDS_BYTES);
/// Exact effect transcript bytes: one tag byte followed by the zero-filled union.
pub const KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1: usize =
    1 + KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1;
/// Exact `statement` transcript bytes.
pub const KAGEMUSHA_WALLET_STATEMENT_TRANSCRIPT_BYTES_V1: usize = 2
    + 4 * DIGEST_BYTES
    + 1
    + 2 * U128_BYTES
    + U32_BYTES
    + U128_BYTES
    + DIGEST_BYTES
    + 2 * KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1
    + KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1;
/// Exact `receipt-body` transcript bytes.
pub const KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1: usize = 2
    + 3 * DIGEST_BYTES
    + U128_BYTES
    + DIGEST_BYTES
    + 2 * KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1
    + 4 * DIGEST_BYTES;
/// Exact `operation-id` transcript bytes: `wallet_id || u8 kind || input`.
pub const KAGEMUSHA_WALLET_OPERATION_ID_TRANSCRIPT_BYTES_V1: usize =
    DIGEST_BYTES + 1 + DIGEST_BYTES;
/// Exact `package` transcript bytes: `statement_digest || proof_digest || receipt_digest`.
pub const KAGEMUSHA_WALLET_PACKAGE_TRANSCRIPT_BYTES_V1: usize = 3 * DIGEST_BYTES;
/// Exact `unload-nullifier` transcript bytes: `scheme_id || wallet_id || LE128 ordinal`.
pub const KAGEMUSHA_WALLET_UNLOAD_NULLIFIER_TRANSCRIPT_BYTES_V1: usize =
    2 * DIGEST_BYTES + U128_BYTES;
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
pub const KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1: usize = 32;
/// σ-field elements of the state rest (§3).
pub const KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1: usize = 13;
/// σ-field elements of the zero-filled effect union of the statement encoding.
pub const KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1: usize = max_width_v1(&EFFECT_FIELD_ITEMS);
/// σ-field elements of the statement encoding: 18 header elements and the effect union.
pub const KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1: usize =
    18 + KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1;

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
    /// New setup and funding closed; existing claims are preserved.
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
/// are core fields, so `σ_send` enforces the maximum list age. Load and redeem recovery share
/// one map and root keyed by `(kind, ordinal)` (owner answer Q3). Map roots, chains, the
/// blacklist and quota-windows roots and the state nonce are canonical σ-field values; an
/// all-zero digest or root means "none held" where noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateCoreV1"
)]
pub struct KagemushaWalletStateCoreV1 {
    /// Lifecycle.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Enrolled asset scope digest.
    pub asset_digest: [u8; 32],
    /// Wallet incarnation identity.
    pub wallet_id: [u8; 32],
    /// Digest of the current credential.
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
    /// Next load voucher ordinal.
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
    /// Persistent quota-usage map root; `RefreshPolicy` never changes it.
    pub quota_usage_root: [u8; 32],
    /// Active controls: scheme policy enabled and credential permitted.
    pub enabled_controls: u32,
    /// Windows root of the held quota share; zero when none is held.
    pub quota_windows_root: [u8; 32],
    /// Version of the held blacklist; zero when none is held.
    pub blacklist_version: u64,
    /// Gap-tree root of the held blacklist; zero when none is held.
    pub blacklist_root: [u8; 32],
    /// Issuance time of the held blacklist in Unix milliseconds; zero when none is held.
    pub blacklist_issued_at_ms: u64,
    /// Maximum blacklist age of the credential's regulatory policy; zero for no age rule.
    pub blacklist_max_age_ms: u64,
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
/// It holds the rest of the credential's regulatory policy body (the maximum blacklist age is a
/// core field), the held policy objects by digest and the committed time anchor. An all-zero
/// digest means "none held".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateRestV1"
)]
pub struct KagemushaWalletStateRestV1 {
    /// Controls the credential's regulatory policy permits.
    pub permitted_controls: u32,
    /// Response-age bound of a time anchor of the credential's regulatory policy.
    pub time_anchor_max_response_ms: u64,
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
    /// ordinals and sequence, the empty root of every map
    /// ([`kagemusha_wallet_empty_map_root_v1`]), empty chains (the field zero), no held policy
    /// object, and the credential's regulatory policy and lease.
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
                quota_usage_root: empty,
                enabled_controls: 0,
                quota_windows_root: [0; 32],
                blacklist_version: 0,
                blacklist_root: [0; 32],
                blacklist_issued_at_ms: 0,
                blacklist_max_age_ms: body.regulatory_policy.blacklist_max_age_ms,
                lease_expires_at_ms: body.lease_expires_at_ms,
                policy_epoch: 0,
                accepted_time_floor_ms: 0,
                state_nonce,
            },
            rest: KagemushaWalletStateRestV1 {
                permitted_controls: body.regulatory_policy.permitted_controls,
                time_anchor_max_response_ms: body.regulatory_policy.time_anchor_max_response_ms,
                scheme_policy: [0; 32],
                fee_schedule: [0; 32],
                blacklist: [0; 32],
                quota_share: [0; 32],
                quota_share_id: 0,
                time_anchor: [0; 32],
            },
        };
        state.validate()?;
        Ok(state)
    }

    /// The credential's regulatory policy as the state holds it: the permitted controls and
    /// time-anchor bound from the rest, the maximum blacklist age from the core.
    #[must_use]
    pub const fn regulatory_policy(&self) -> KagemushaWalletRegulatoryPolicyV1 {
        KagemushaWalletRegulatoryPolicyV1 {
            permitted_controls: self.rest.permitted_controls,
            blacklist_max_age_ms: self.core.blacklist_max_age_ms,
            time_anchor_max_response_ms: self.rest.time_anchor_max_response_ms,
        }
    }

    /// Validate the state's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, zero or noncanonical map roots or nonce,
    /// noncanonical chains or policy roots, and inconsistent control fields
    /// ([`Self::validate_controls`]).
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("state.version", self.version)?;
        let core = &self.core;
        for (field, digest) in [
            ("state.core.scheme_id", &core.scheme_id),
            ("state.core.asset_digest", &core.asset_digest),
            ("state.core.wallet_id", &core.wallet_id),
            ("state.core.credential_digest", &core.credential_digest),
        ] {
            require_nonzero_v1(field, digest)?;
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
    /// Order: lifecycle; scheme id (2); asset digest (2); wallet id (2); credential digest (2);
    /// balance, `burned_total`, sequence, `next_send`, `next_load`, `next_redeem`; `send_chain`,
    /// `recv_chain`; the consumed-credit, pending-outgoing, load/redeem-recovery, fee-claim and
    /// quota-usage roots; enabled controls; quota-windows root; blacklist version, root, issue
    /// time and maximum age; lease expiry; policy epoch; accepted-time floor; state nonce.
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
            .digest(&core.credential_digest)
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
            .integer(u128::from(core.blacklist_version))
            .field(&core.blacklist_root)
            .integer(u128::from(core.blacklist_issued_at_ms))
            .integer(u128::from(core.blacklist_max_age_ms))
            .integer(u128::from(core.lease_expires_at_ms))
            .integer(u128::from(core.policy_epoch))
            .integer(u128::from(core.accepted_time_floor_ms))
            .field(&core.state_nonce);
        debug_assert_eq!(items.len(), KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1);
        Ok(items.finish())
    }

    /// σ-field elements of the rest, in rest-digest order (§3).
    ///
    /// Order: permitted controls; time-anchor response bound; scheme policy (2); fee schedule
    /// (2); blacklist (2); quota share (2); quota share id; time anchor (2).
    ///
    /// # Errors
    ///
    /// Rejects an invalid state.
    pub fn rest_field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        self.validate()?;
        let rest = &self.rest;
        let items = WalletFieldItemsV1::with_capacity(KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1)
            .integer(u128::from(rest.permitted_controls))
            .integer(u128::from(rest.time_anchor_max_response_ms))
            .digest(&rest.scheme_policy)
            .digest(&rest.fee_schedule)
            .digest(&rest.blacklist)
            .digest(&rest.quota_share)
            .integer(u128::from(rest.quota_share_id))
            .digest(&rest.time_anchor);
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
    /// Digest of the signed Request.
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
    /// amount, fee, Request digest (2) (8).
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
    Ok(WalletFieldItemsV1::with_capacity(8)
        .field(credit_id)
        .digest(receiver_wallet_id)
        .integer(send_ordinal)
        .integer(amount)
        .integer(fee)
        .digest(request_digest)
        .finish())
}

/// Load leaf of one absorbed voucher in the shared load/redeem recovery map (§3, owner answer
/// Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLoadLeafV1"
)]
pub struct KagemushaWalletLoadLeafV1 {
    /// Load ordinal (the low part of the map key).
    pub ordinal: u128,
    /// Digest of the absorbed voucher.
    pub voucher_digest: [u8; 32],
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

    /// Leaf elements: ordinal, voucher digest (2), amount (4).
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        WalletFieldItemsV1::with_capacity(4)
            .integer(self.ordinal)
            .digest(&self.voucher_digest)
            .integer(self.amount)
            .finish()
    }

    /// Map value `P(kgwload1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    #[must_use]
    pub fn leaf_value(&self) -> [u8; 32] {
        poseidon_items_v1(Self::DOMAIN, &self.field_items())
    }
}

/// Redeem leaf of one unload claim in the shared load/redeem recovery map (§3, owner answer
/// Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRedeemLeafV1"
)]
pub struct KagemushaWalletRedeemLeafV1 {
    /// Redemption ordinal (the low part of the map key).
    pub ordinal: u128,
    /// Unload nullifier.
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

    /// Leaf elements: ordinal, nullifier (2), amount, online charge (5).
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        WalletFieldItemsV1::with_capacity(5)
            .integer(self.ordinal)
            .digest(&self.nullifier)
            .integer(self.amount)
            .integer(self.online_charge)
            .finish()
    }

    /// Map value `P(kgwrdm_1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    #[must_use]
    pub fn leaf_value(&self) -> [u8; 32] {
        poseidon_items_v1(Self::DOMAIN, &self.field_items())
    }
}

/// Fee-claim leaf of one nonzero Send fee awaiting payout (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeClaimLeafV1"
)]
pub struct KagemushaWalletFeeClaimLeafV1 {
    /// Credit identity (the map key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Fee earned at the Send commit.
    pub fee: u128,
    /// Digest of the historical fee schedule.
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

    /// Leaf elements: `credit_id`, fee, fee schedule digest (2) (4).
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical `credit_id`.
    pub fn field_items(&self) -> WalletResult<Vec<[u8; 32]>> {
        require_nonzero_field_v1("fee_claim.credit_id", &self.credit_id)?;
        Ok(WalletFieldItemsV1::with_capacity(4)
            .field(&self.credit_id)
            .integer(self.fee)
            .digest(&self.fee_schedule_digest)
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

/// Persistent quota-usage leaf keyed by `(window_kind, window_start_ms)` (§7, design C6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaUsageLeafV1"
)]
pub struct KagemushaWalletQuotaUsageLeafV1 {
    /// Window kind (key part).
    pub window_kind: KagemushaWalletQuotaWindowKindV1,
    /// Window start in Unix milliseconds (key part).
    pub window_start_ms: u64,
    /// Window end in Unix milliseconds; later shares keep it for this key.
    pub window_end_ms: u64,
    /// Gross amount consumed in this window; never replenished.
    pub used: u128,
}

impl KagemushaWalletQuotaUsageLeafV1 {
    /// Poseidon domain of this map's values.
    pub const DOMAIN: u64 = KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1;

    /// Map key `(window kind tag, window start)`: `tag · 2^128 + window_start_ms`.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        kagemusha_wallet_pair_key_v1(self.window_kind.tag(), u128::from(self.window_start_ms))
    }

    /// Leaf elements: window kind tag, start, end, used (4).
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        WalletFieldItemsV1::with_capacity(4)
            .integer(u128::from(self.window_kind.tag()))
            .integer(u128::from(self.window_start_ms))
            .integer(u128::from(self.window_end_ms))
            .integer(self.used)
            .finish()
    }

    /// Map value `P(kgwquse1, elements)`, the `value` of this entry's indexed-tree leaf
    /// (§3.2).
    #[must_use]
    pub fn leaf_value(&self) -> [u8; 32] {
        poseidon_items_v1(Self::DOMAIN, &self.field_items())
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
    /// Absorb the next finalized load voucher.
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
    /// Close new setup and funding.
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
/// The transcript is the tag followed by the variant's fixed fields and zero fill to
/// [`KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1`]. The Send effect binds the exact signed Request
/// by its digest, which binds the verification dependencies by digest (§8); the Receive effect
/// contains no Payment digest (§§3, 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEffectV1")]
pub enum KagemushaWalletEffectV1 {
    /// Install the zero state from the generation-0 enrollment marker.
    #[codec(index = 1)]
    Bootstrap {
        /// Enrollment identity of the credential.
        enrollment_id: [u8; 32],
        /// `marker_digest` of the generation-0 Enrollment marker (design C3).
        enrollment_marker: [u8; 32],
    },
    /// Absorb the voucher at the predecessor's `next_load`.
    #[codec(index = 2)]
    Load {
        /// Voucher digest.
        voucher: [u8; 32],
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
        /// Digest of the signed Request.
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
        /// Charge quote digest; zero exactly when `online_charge` is zero.
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
    /// Close new setup and funding; `next_load` is in the statement.
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

    /// Operation-id input of this effect (§4.1): Bootstrap enrollment id, Load voucher,
    /// Send and Receive credit id, `ArchiveSent` Credited digest, Unload nullifier,
    /// `RefreshPolicy` update digest, and 32 zero bytes for Retiring.
    ///
    /// `ArchiveSent` uses the Credited digest, which binds the credit id, because a no-op
    /// archive branch lets the wallet archive the same descriptor again with new evidence
    /// (§3.2); reusing an operation id with changed inputs fails (§4.1).
    #[must_use]
    pub const fn operation_input(&self) -> [u8; 32] {
        match self {
            Self::Bootstrap { enrollment_id, .. } => *enrollment_id,
            Self::Load { voucher, .. } => *voucher,
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

    /// Fixed field width of this variant before zero fill.
    const fn fields_bytes(&self) -> usize {
        EFFECT_FIELDS_BYTES[self.index()]
    }

    /// σ-field element count of this variant before zero fill.
    const fn field_items_len(&self) -> usize {
        EFFECT_FIELD_ITEMS[self.index()]
    }

    /// Append this variant's fixed fields.
    fn write_fields(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        match self {
            Self::Bootstrap {
                enrollment_id,
                enrollment_marker,
            } => transcript.digest(enrollment_id).digest(enrollment_marker),
            Self::Load {
                voucher,
                load_ordinal,
                amount,
                online_charge,
            } => transcript
                .digest(voucher)
                .u128(*load_ordinal)
                .u128(*amount)
                .u128(*online_charge),
            Self::Send {
                credit_id,
                receiver_wallet_id,
                send_ordinal,
                amount,
                fee,
                request,
                accepted_lower_ms,
                accepted_upper_ms,
            } => transcript
                .digest(credit_id)
                .digest(receiver_wallet_id)
                .u128(*send_ordinal)
                .u128(*amount)
                .u128(*fee)
                .digest(request)
                .u64(*accepted_lower_ms)
                .u64(*accepted_upper_ms),
            Self::Receive {
                credit_id,
                payer_wallet_id,
                amount,
            } => transcript
                .digest(credit_id)
                .digest(payer_wallet_id)
                .u128(*amount),
            Self::ArchiveSent {
                credit_id,
                credited,
            } => transcript.digest(credit_id).digest(credited),
            Self::Unload {
                nullifier,
                redeem_ordinal,
                amount,
                online_charge,
                charge_quote,
            } => transcript
                .digest(nullifier)
                .u128(*redeem_ordinal)
                .u128(*amount)
                .u128(*online_charge)
                .digest(charge_quote),
            Self::RefreshPolicy {
                update_kind,
                update,
                accepted_time_floor_ms,
            } => transcript
                .u8(update_kind.tag())
                .digest(update)
                .u64(*accepted_time_floor_ms),
            Self::Retiring => transcript,
        }
    }

    /// Append the tag, the fixed fields and the zero fill of the union.
    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        self.write_fields(transcript.u8(self.tag()))
            .zeros(KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1.saturating_sub(self.fields_bytes()))
    }

    /// Exact effect transcript: tag, fields, zero fill to the union width.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        self.write(WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1,
        ))
        .finish()
    }

    /// Append this variant's σ-field elements: `credit_id` is one element (§3), every other
    /// digest two limbs.
    fn write_field_items(&self, items: WalletFieldItemsV1) -> WalletFieldItemsV1 {
        match self {
            Self::Bootstrap {
                enrollment_id,
                enrollment_marker,
            } => items.digest(enrollment_id).digest(enrollment_marker),
            Self::Load {
                voucher,
                load_ordinal,
                amount,
                online_charge,
            } => items
                .digest(voucher)
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
                .digest(request)
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
                .digest(nullifier)
                .integer(*redeem_ordinal)
                .integer(*amount)
                .integer(*online_charge)
                .digest(charge_quote),
            Self::RefreshPolicy {
                update_kind,
                update,
                accepted_time_floor_ms,
            } => items
                .integer(u128::from(update_kind.tag()))
                .digest(update)
                .integer(u128::from(*accepted_time_floor_ms)),
            Self::Retiring => items,
        }
    }

    /// Validate the effect's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, a noncanonical `credit_id` or Credited digest, a zero Send,
    /// Receive or Unload
    /// amount, a Send whose gross debit overflows or whose accepted interval is inverted, and
    /// an Unload whose online charge exceeds its amount or disagrees with its charge quote.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Bootstrap {
                enrollment_id,
                enrollment_marker,
            } => {
                require_nonzero_v1("effect.enrollment_id", enrollment_id)?;
                require_nonzero_v1("effect.enrollment_marker", enrollment_marker)
            }
            Self::Load { voucher, .. } => require_nonzero_v1("effect.voucher", voucher),
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
                require_nonzero_v1("effect.request", request)?;
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
                require_nonzero_v1("effect.nullifier", nullifier)?;
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
            Self::RefreshPolicy { update, .. } => require_nonzero_v1("effect.update", update),
            Self::Retiring => Ok(()),
        }
    }
}

/// Exact `operation-id` transcript: `wallet_id || u8 kind || input`.
#[must_use]
pub fn kagemusha_wallet_operation_id_transcript_v1(
    wallet_id: &[u8; 32],
    kind: KagemushaWalletOperationKindV1,
    input: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_OPERATION_ID_TRANSCRIPT_BYTES_V1)
        .digest(wallet_id)
        .u8(kind.tag())
        .digest(input)
        .finish()
}

/// Provider operation identity `H("operation-id", wallet_id || u8 kind || input)` (§4.1).
#[must_use]
pub fn kagemusha_wallet_operation_id_v1(
    wallet_id: &[u8; 32],
    kind: KagemushaWalletOperationKindV1,
    input: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::OperationId,
        &kagemusha_wallet_operation_id_transcript_v1(wallet_id, kind, input),
    )
}

/// Exact `unload-nullifier` transcript: `scheme_id || wallet_id || LE128 redeem_ordinal`.
#[must_use]
pub fn kagemusha_wallet_unload_nullifier_transcript_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    redeem_ordinal: u128,
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_UNLOAD_NULLIFIER_TRANSCRIPT_BYTES_V1)
        .digest(scheme_id)
        .digest(wallet_id)
        .u128(redeem_ordinal)
        .finish()
}

/// Unload nullifier `H("unload-nullifier", scheme_id || wallet_id || LE128 ordinal)` (§6.1).
#[must_use]
pub fn kagemusha_wallet_unload_nullifier_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    redeem_ordinal: u128,
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::UnloadNullifier,
        &kagemusha_wallet_unload_nullifier_transcript_v1(scheme_id, wallet_id, redeem_ordinal),
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
    /// Exact `statement` transcript (constant length).
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let transcript =
            WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_STATEMENT_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .digest(&self.scheme_id)
                .digest(&self.relation_id)
                .digest(&self.credential_digest)
                .digest(&self.asset_digest)
                .u8(self.lifecycle.tag())
                .u128(self.sequence)
                .u128(self.next_load)
                .u32(self.enabled_controls)
                .u128(self.lineage_burned_total)
                .digest(&self.lineage_pending_outgoing_root);
        let transcript = self.successor.write(self.predecessor.write(transcript));
        self.effect.write(transcript).finish()
    }

    /// Statement digest `H("statement", transcript)`, bound by the receipt and package.
    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        kagemusha_wallet_digest_v1(Role::Statement, &self.transcript())
    }

    /// σ public-input encoding of the statement (§3.2): the
    /// [`KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1`] σ-field elements hashed as
    /// `P(kgwstmt1, items)` ([`Self::field_digest`]).
    ///
    /// Order: version; relation id (2); scheme id (2); asset digest (2); credential digest
    /// (2); successor lifecycle, sequence and `next_load`; enabled controls; lineage
    /// `burned_total`; lineage pending-outgoing root (1); predecessor (1); successor (1);
    /// effect tag; the effect's elements zero-filled to
    /// [`KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1`].
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
            .digest(&self.credential_digest)
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

    /// σ public-input digest `P(kgwstmt1, field items)` (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement.
    pub fn field_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(poseidon_items_v1(
            KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
            &self.field_items()?,
        ))
    }

    /// Operation identity of this transition for `wallet_id` (§4.1).
    #[must_use]
    pub fn operation_id(&self, wallet_id: &[u8; 32]) -> [u8; 32] {
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
    /// Rejects another version, zero bindings, undefined control bits, a noncanonical
    /// predecessor or lineage root, an incomplete successor, an invalid effect, lineage fields
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
            ("statement.credential_digest", &self.credential_digest),
            ("statement.asset_digest", &self.asset_digest),
        ] {
            require_nonzero_v1(field, digest)?;
        }
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
    /// receiving, loading issued vouchers, sending and unloading (§6.3).
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
    /// Credential digest of the head.
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
    /// Rejects another version, zero identities, an invalid payment key, an incomplete head,
    /// zero or noncanonical roots, and undefined control bits.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("lineage.version", self.version)?;
        for (field, digest) in [
            ("lineage.scheme_id", &self.scheme_id),
            ("lineage.relation_id", &self.relation_id),
            ("lineage.wallet_id", &self.wallet_id),
            ("lineage.credential_digest", &self.credential_digest),
        ] {
            require_nonzero_v1(field, digest)?;
        }
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
    /// Operation identity derived from the statement.
    pub operation_id: [u8; 32],
    /// Statement predecessor commitment.
    pub predecessor: KagemushaWalletStateCommitmentV1,
    /// Statement successor commitment.
    pub successor: KagemushaWalletStateCommitmentV1,
    /// Statement digest.
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
            operation_id: statement.operation_id(&signer.wallet_id),
            predecessor: statement.predecessor,
            successor: statement.successor,
            statement_digest: statement.statement_digest(),
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
    /// Rejects another version, zero digests, a noncanonical Payment digest, or a
    /// non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("receipt.version", self.version)?;
        require_nonzero_v1("receipt.operation_id", &self.operation_id)?;
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

    /// Verify the receipt and return its digest `H("receipt", m || signature)`.
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
            Role::Receipt,
            &message,
            &self.signature,
        ))
    }
}

/// Package digest `H("package", statement_digest || proof_digest || receipt_digest)`.
#[must_use]
pub fn kagemusha_wallet_package_digest_v1(
    statement_digest: &[u8; 32],
    proof_digest: &[u8; 32],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::Package,
        &WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_PACKAGE_TRANSCRIPT_BYTES_V1)
            .digest(statement_digest)
            .digest(proof_digest)
            .digest(receipt_digest)
            .finish(),
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
        let statement = self.statement.statement_digest();
        Ok(KagemushaWalletPackageDigestsV1 {
            statement,
            proof,
            receipt,
            package: kagemusha_wallet_package_digest_v1(&statement, &proof, &receipt),
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

    /// Verifying-key selector of σ (§3.2, owner answers Q11 and A5): the operation tag and,
    /// for Send, the enabled-controls mask (equal to `Ω.enabled_controls` by the consumer
    /// checks); for Receive, the blacklist bit of the statement's mask, which selects the
    /// `σ_recv` that proves the payer's non-membership in the receiver's committed list; zero for
    /// every other operation. Statements and Ω carry one scheme-level `relation_id`; the
    /// selector picks σ's entry of the verifying-key allowlist
    /// ([`super::KagemushaWalletVerifyingKeyAllowlistV1`]) whose digest the relation binds.
    #[must_use]
    pub fn verifying_key_selector(&self) -> (KagemushaWalletOperationKindV1, u32) {
        let kind = self.statement.effect.kind();
        match kind {
            KagemushaWalletOperationKindV1::Send => (kind, self.statement.enabled_controls),
            KagemushaWalletOperationKindV1::Receive => (
                kind,
                self.statement.enabled_controls & KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
            ),
            _ => (kind, 0),
        }
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
