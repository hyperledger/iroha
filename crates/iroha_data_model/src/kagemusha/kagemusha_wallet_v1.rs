//! KAGEMUSHA wallet protocol V1: canonical objects of the single offline wallet protocol.
//!
//! There is exactly one KAGEMUSHA protocol, specified by
//! `specs/kagemusha_single_design_proposal.md` (cited as §n): a proof-carrying offline
//! wallet whose hardware-backed P-256 payment key signs the commit receipts of a durable
//! software state provider running in the released app on a stock, uncompromised phone.
//! There is no per-payment issuer call, no Reserve/Commit approval and no signature-only
//! alternative. This module owns the G1 canonical objects of that protocol (§10): Norito
//! layouts, fixed-layout transcripts, domain-separated digests, the P-256 device key and
//! signature values, signer roles, enrollment identities, the issuer-signed credential,
//! renewal requests, the artifact manifest, the private state and its packages, signed policy
//! objects, peer messages and their envelope, local custody objects of the state provider,
//! and ledger boundary objects.
//!
//! # Digests and signatures (§8)
//!
//! Two hash families apply (§3). Every value a step relation computes or opens is a Poseidon
//! value `P` of the σ field, computed natively with `iroha_pasta`: `credit_id`, the state
//! commitment, chains, the depth-32 indexed map trees, the blacklist, quota-window and
//! credit-digest trees, the σ statement digest, and (packed-byte `P_bytes`) `proof_digest`, the
//! Payment digest, the lineage, credit-opening, credit-status and credited digests and every
//! signing message. The remaining digests are
//!
//! ```text
//! H(role, body) = SHA-256("iroha:kagemusha:wallet:v1:" || role || 0x00 || LE64(len(body)) || body)
//! ```
//!
//! over a fixed-layout transcript: little-endian fixed-width integers, raw 32-byte digests,
//! 65-byte uncompressed SEC1 keys, 64-byte `r || s` signatures, and enums as one tag byte
//! followed by a zero-filled union. A reference to a signer certificate is its 32-byte
//! certificate digest. Every P-256 signature signs the 32-byte signing message
//! `m = P_bytes(d, transcript)` of its body's signing domain `d` with ECDSA-P256-SHA256 (owner
//! answer A1); the signer output is normalized to low S and verified before it is frozen into an
//! object. Verifiers recompute `m`, reject high-S signatures and never rewrite received bytes.
//! The digest of a signed object is `H(role, m || signature)`.
//!
//! # Canonical frames
//!
//! Canonical bytes are complete `norito::encode_canonical` frames: the 40-byte header, the
//! zero padding required by the type's archived alignment (8 bytes for types whose own fields
//! or nested structs hold a `u128`, including the envelope, and 0 bytes when a `u128` occurs
//! only inside a sequence, on the admitted `aarch64` and `x86_64` native targets), then the
//! payload. Every byte bound
//! counts the complete frame and is checked before decoding. `armv7` is not an admitted native
//! target: its `u128` alignment would change that padding. Decoding follows one order: byte
//! cap, canonical decode under payload-derived resource limits, version fields, expected
//! scheme, then structural validation.
//!
//! Decoding or validating a value never grants monetary authority by itself. A signature
//! confers only the authority of its named role (§2.3); monetary admission also requires the
//! recursive proofs, provider receipts and ledger state owned by the components in §9.

use crate::nexus::AxtAssetIncarnationValidationError;

mod custody;
mod digest;
mod identity;
mod keys;
mod ledger;
mod messages;
mod policy;
mod poseidon;
mod state;
mod verifying_keys;
// `vectors_tests` writes and compares `fixtures/kagemusha/wallet_v1_vectors.json`; the Kotlin
// `core-jvm` (`KagemushaWalletWireV1`) and Swift (`KagemushaWalletWireV1`) consumers recompute
// it (design §8, C11).
// TODO(G4/G6): add the JS, Python and C# consumers when their wire copies migrate.

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod size_tests;
#[cfg(test)]
mod vectors_tests;

pub use self::{
    custody::{
        KAGEMUSHA_WALLET_OUTPUT_TRANSCRIPT_BYTES_V1, KagemushaWalletCompletionRecordV1,
        KagemushaWalletFoldRecordV1, KagemushaWalletMarkerStateV1, KagemushaWalletMarkerV1,
        KagemushaWalletOutputDescriptorV1, KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletRetainedInputRoleV1, KagemushaWalletRetainedInputV1,
        KagemushaWalletTerminalReasonV1, kagemusha_wallet_output_digest_v1,
        kagemusha_wallet_output_transcript_v1,
    },
    digest::{
        KAGEMUSHA_WALLET_DIGEST_PREFIX_V1, KAGEMUSHA_WALLET_FIELD_MODULUS_V1,
        KAGEMUSHA_WALLET_SIGNED_OBJECT_TRANSCRIPT_BYTES_V1, KagemushaWalletDigestRoleV1,
        KagemushaWalletSignerOutputV1, KagemushaWalletSigningDomainV1, kagemusha_wallet_digest_v1,
        kagemusha_wallet_field_from_u128_v1, kagemusha_wallet_freeze_signature_v1,
        kagemusha_wallet_is_canonical_field_v1, kagemusha_wallet_signed_object_digest_v1,
        kagemusha_wallet_signing_message_v1, kagemusha_wallet_verify_signature_v1,
    },
    identity::{
        KAGEMUSHA_WALLET_ANDROID_FORBIDDEN_FACTS_V1, KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1,
        KAGEMUSHA_WALLET_APPLE_FORBIDDEN_FACTS_V1, KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1,
        KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1, KAGEMUSHA_WALLET_ASSET_SCOPE_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_CERTIFICATE_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1, KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        KAGEMUSHA_WALLET_CREDENTIAL_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1,
        KAGEMUSHA_WALLET_ENROLLMENT_CHALLENGE_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_ENROLLMENT_KEY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_FACT_APP_ATTEST_GENUINE_DEVICE_V1,
        KAGEMUSHA_WALLET_FACT_APP_ATTEST_KEY_BINDING_V1,
        KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1,
        KAGEMUSHA_WALLET_FACT_APP_SIGNING_IDENTITY_V1, KAGEMUSHA_WALLET_FACT_BOOTLOADER_LOCKED_V1,
        KAGEMUSHA_WALLET_FACT_HARDWARE_BACKED_KEY_V1,
        KAGEMUSHA_WALLET_FACT_LOCAL_COMPROMISE_CHECKS_CLEAR_V1,
        KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1, KAGEMUSHA_WALLET_FACT_PLAY_INTEGRITY_SIGNAL_V1,
        KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1, KAGEMUSHA_WALLET_FACT_STRONGBOX_V1,
        KAGEMUSHA_WALLET_FACT_VERIFIED_BOOT_V1, KAGEMUSHA_WALLET_FACTS_DEFINED_MASK_V1,
        KAGEMUSHA_WALLET_ID_TRANSCRIPT_BYTES_V1, KAGEMUSHA_WALLET_PROVIDER_CONTRACT_NAME_V1,
        KAGEMUSHA_WALLET_PROVIDER_CONTRACT_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_RELATION_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1,
        KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1,
        KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MIN_V1,
        KAGEMUSHA_WALLET_RENEWAL_APPLE_ASSERTION_MAX_BYTES_V1,
        KAGEMUSHA_WALLET_RENEWAL_CHALLENGE_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_RENEWAL_KEY_BINDING_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_SCHEME_TRANSCRIPT_BYTES_V1, KagemushaWalletArtifactManifestBodyV1,
        KagemushaWalletArtifactManifestV1, KagemushaWalletAssetScopeV1,
        KagemushaWalletCertificateSetV1, KagemushaWalletCredentialBodyV1,
        KagemushaWalletCredentialV1, KagemushaWalletDerCertificateV1,
        KagemushaWalletEnrollmentChallengeV1, KagemushaWalletEvidenceKindV1,
        KagemushaWalletEvidenceV1, KagemushaWalletRegulatoryPolicyV1,
        KagemushaWalletRenewalEvidenceV1, KagemushaWalletRenewalRequestV1, KagemushaWalletSchemeV1,
        KagemushaWalletSignerCertificateBodyV1, KagemushaWalletSignerCertificateV1,
        KagemushaWalletSignerRoleV1, kagemusha_wallet_account_digest_v1,
        kagemusha_wallet_enrollment_id_v1, kagemusha_wallet_enrollment_key_binding_v1,
        kagemusha_wallet_enrollment_key_transcript_v1, kagemusha_wallet_evidence_digest_v1,
        kagemusha_wallet_evidence_transcript_v1, kagemusha_wallet_id_transcript_v1,
        kagemusha_wallet_id_v1, kagemusha_wallet_provider_contract_transcript_v1,
        kagemusha_wallet_provider_contract_v1, kagemusha_wallet_relation_id_v1,
        kagemusha_wallet_relation_transcript_v1,
        kagemusha_wallet_renewal_assertion_client_data_hash_v1,
        kagemusha_wallet_renewal_challenge_transcript_v1,
        kagemusha_wallet_renewal_key_binding_transcript_v1,
    },
    keys::{
        KAGEMUSHA_DEVICE_PUBLIC_KEY_SEC1_BYTES_V1, KAGEMUSHA_DEVICE_SIGNATURE_BYTES_V1,
        KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1,
    },
    ledger::{
        KAGEMUSHA_WALLET_LEDGER_CONTROL_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_LEDGER_CONTROL_UNION_BYTES_V1,
        KAGEMUSHA_WALLET_LOAD_VOUCHER_BODY_TRANSCRIPT_BYTES_V1, KagemushaWalletAbandonmentV1,
        KagemushaWalletActivationV1, KagemushaWalletCloseLoadsV1, KagemushaWalletFeeClaimV1,
        KagemushaWalletFeePayoutV1, KagemushaWalletLedgerControlActionV1,
        KagemushaWalletLedgerControlBodyV1, KagemushaWalletLedgerControlV1,
        KagemushaWalletLoadVoucherBodyV1, KagemushaWalletLoadVoucherV1,
        KagemushaWalletUnloadChargeV1, KagemushaWalletUnloadClaimV1, KagemushaWalletUnloadPayoutV1,
    },
    messages::{
        KAGEMUSHA_WALLET_CREDIT_OPENING_DEPTH_V1,
        KAGEMUSHA_WALLET_CREDIT_STATUS_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_CREDITED_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_OFFER_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1, KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1,
        KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_SESSION_CONTROL_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1, KagemushaWalletCreditOpeningV1,
        KagemushaWalletCreditStatusV1, KagemushaWalletCreditedEvidenceV1,
        KagemushaWalletCreditedV1, KagemushaWalletDeliveryStatusV1, KagemushaWalletEnvelopeV1,
        KagemushaWalletFeeScheduleSlotV1, KagemushaWalletLineageMessageV1,
        KagemushaWalletMessageV1, KagemushaWalletOfferBodyV1, KagemushaWalletOfferV1,
        KagemushaWalletPaymentDigestsV1, KagemushaWalletPaymentV1, KagemushaWalletPolicyDataItemV1,
        KagemushaWalletPolicyDataV1, KagemushaWalletRequestBodyV1, KagemushaWalletRequestV1,
        KagemushaWalletSessionAuthV1, KagemushaWalletSessionControlKindV1,
        KagemushaWalletSessionControlV1, KagemushaWalletSignedRequestV1,
        kagemusha_wallet_payment_transcript_v1, kagemusha_wallet_text_decode_v1,
        kagemusha_wallet_text_encode_v1,
    },
    policy::{
        KAGEMUSHA_WALLET_BLACKLIST_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1, KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1,
        KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1, KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1,
        KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1,
        KAGEMUSHA_WALLET_CHARGE_QUOTE_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1,
        KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_QUOTA_SHARE_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1, KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1,
        KAGEMUSHA_WALLET_SCHEME_POLICY_BODY_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_TIME_ANCHOR_BODY_TRANSCRIPT_BYTES_V1, KagemushaWalletAnchoredTimeV1,
        KagemushaWalletBlacklistBodyV1, KagemushaWalletBlacklistEntryV1,
        KagemushaWalletBlacklistGapOpeningV1, KagemushaWalletBlacklistV1,
        KagemushaWalletChargeKindV1, KagemushaWalletChargeQuoteBodyV1,
        KagemushaWalletChargeQuoteV1, KagemushaWalletFeeRoundingV1,
        KagemushaWalletFeeScheduleBodyV1, KagemushaWalletFeeScheduleV1,
        KagemushaWalletMonotonicReadingV1, KagemushaWalletPolicyRefreshV1,
        KagemushaWalletPolicyUpdateV1, KagemushaWalletQuotaShareBodyV1,
        KagemushaWalletQuotaShareV1, KagemushaWalletQuotaWindowKindV1,
        KagemushaWalletQuotaWindowV1, KagemushaWalletSchemePolicyBodyV1,
        KagemushaWalletSchemePolicyV1, KagemushaWalletTimeAnchorBodyV1,
        KagemushaWalletTimeAnchorV1, KagemushaWalletTimeIntervalV1,
        kagemusha_wallet_blacklist_leaf_v1, kagemusha_wallet_blacklist_node_v1,
        kagemusha_wallet_blacklist_root_v1, kagemusha_wallet_load_ledger_debit_v1,
        kagemusha_wallet_quota_empty_window_leaf_v1, kagemusha_wallet_quota_node_v1,
        kagemusha_wallet_quota_windows_root_v1, kagemusha_wallet_unload_account_payout_v1,
    },
    poseidon::{
        KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1, KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1,
        KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_CORE_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1, KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1, KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_INDEXED_EMPTY_OPENING_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1,
        KAGEMUSHA_WALLET_INDEXED_LEAF_OPENING_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1, KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1,
        KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1, KAGEMUSHA_WALLET_INDEXED_TREE_SLOTS_V1,
        KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_PACKED_CHUNK_BYTES_V1, KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
        KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1,
        KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1,
        KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1, KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1,
        KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1, KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1,
        KAGEMUSHA_WALLET_REST_DOMAIN_V1, KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1,
        KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1, KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
        KagemushaWalletIndexedInsertV1, KagemushaWalletIndexedLeafV1,
        KagemushaWalletIndexedOpeningV1, KagemushaWalletIndexedRemoveV1,
        KagemushaWalletIndexedTreeV1, KagemushaWalletIndexedUpdateV1,
        kagemusha_wallet_empty_map_root_v1, kagemusha_wallet_indexed_empty_subtree_v1,
        kagemusha_wallet_indexed_node_v1, kagemusha_wallet_indexed_verify_membership_v1,
        kagemusha_wallet_indexed_verify_non_membership_v1, kagemusha_wallet_integer_cmp_v1,
        kagemusha_wallet_packed_bytes_v1, kagemusha_wallet_pair_key_v1,
        kagemusha_wallet_poseidon_bytes_v1, kagemusha_wallet_poseidon_v1,
    },
    state::{
        KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1, KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1,
        KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1, KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1,
        KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_OPERATION_ID_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_PACKAGE_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1, KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1,
        KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1, KAGEMUSHA_WALLET_STATEMENT_TRANSCRIPT_BYTES_V1,
        KAGEMUSHA_WALLET_UNLOAD_NULLIFIER_TRANSCRIPT_BYTES_V1, KagemushaWalletConsumedCreditLeafV1,
        KagemushaWalletCreditDigestLeafV1, KagemushaWalletEffectV1, KagemushaWalletFeeClaimLeafV1,
        KagemushaWalletLifecycleV1, KagemushaWalletLineagePublicV1, KagemushaWalletLineageSlotV1,
        KagemushaWalletLineageV1, KagemushaWalletLoadLeafV1, KagemushaWalletOperationKindV1,
        KagemushaWalletPackageDigestsV1, KagemushaWalletPackageV1,
        KagemushaWalletPendingOutgoingLeafV1, KagemushaWalletPolicyUpdateKindV1,
        KagemushaWalletQuotaUsageLeafV1, KagemushaWalletReceiptBodyV1,
        KagemushaWalletReceiptSignerV1, KagemushaWalletReceiptV1, KagemushaWalletRecoveryKindV1,
        KagemushaWalletRecvChainEntryV1, KagemushaWalletRedeemLeafV1,
        KagemushaWalletSendChainEntryV1, KagemushaWalletStateCommitmentV1,
        KagemushaWalletStateCoreV1, KagemushaWalletStateRestV1, KagemushaWalletStateV1,
        KagemushaWalletStatementV1, KagemushaWalletStepProofV1,
        kagemusha_wallet_operation_id_transcript_v1, kagemusha_wallet_operation_id_v1,
        kagemusha_wallet_package_digest_v1, kagemusha_wallet_proof_digest_v1,
        kagemusha_wallet_unload_nullifier_transcript_v1, kagemusha_wallet_unload_nullifier_v1,
    },
    verifying_keys::{
        KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
        KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1,
        KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES_V1,
        KagemushaWalletVerifyingKeyAllowlistV1, KagemushaWalletVerifyingKeyEntryV1,
    },
};

/// Version carried by every KAGEMUSHA wallet V1 object and transcript.
pub const KAGEMUSHA_WALLET_VERSION_V1: u16 = 1;

/// Text transport discriminator: `kgm1:` followed by unpadded base64url of one canonical
/// envelope frame (§8).
pub const KAGEMUSHA_WALLET_TEXT_PREFIX_V1: &str = "kgm1:";
/// Maximum complete canonical envelope frame for Offer and `SessionControl` (§8).
pub const KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1: usize = 2_048;
/// Maximum complete canonical envelope frame for Request, Payment, Credited, `PolicyData` and
/// Lineage (§8, R9).
pub const KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1: usize = 10_000;
/// Maximum complete `kgm1:` text for a session-bounded envelope.
pub const KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1: usize =
    text_max_bytes_v1(KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1);
/// Maximum complete `kgm1:` text for a message-bounded envelope.
pub const KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1: usize =
    text_max_bytes_v1(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);

/// `F_payment`: every byte of the largest valid Payment envelope other than the Ω
/// transport-proof bytes and the `σ_send` bytes (§8), for proof lengths of 128 to 9,999 bytes
/// each (pinned by `size_tests`).
pub const KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1: usize = 1_681;
/// Joint R9 budget of the Ω transport proof and the largest `σ_send`:
/// `10,000 − F_payment` (§8, owner answer Q6). The σ and Ω byte caps are the exact lengths of
/// the frozen verifying-key allowlist, which must satisfy this budget; until the artifacts
/// freeze, G1 bounds σ and Ω only through the frames that carry them.
pub const KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1: usize =
    KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 - KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1;
/// Maximum signer certificates in one certificate set: payer issuer, receiver issuer and
/// fee-schedule signer (design C2).
pub const KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1: usize = 3;

/// Maximum standalone canonical frame of one signer certificate.
pub const KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1: usize = 512;
/// Maximum standalone canonical frame of one scheme identity.
pub const KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1: usize = 512;
/// Maximum standalone canonical frame of one wallet credential.
pub const KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one signed scheme policy.
pub const KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one signed fee schedule.
pub const KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one signed time anchor.
pub const KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1: usize = 512;
/// Maximum standalone canonical frame of one load voucher.
pub const KAGEMUSHA_WALLET_LOAD_VOUCHER_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one signed artifact manifest.
pub const KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one wallet-key ledger control.
pub const KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one unused-enrollment abandonment.
pub const KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one local provider marker.
pub const KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one signed quota share.
pub const KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1: usize = 8_192;
/// Maximum standalone canonical frame of one unload claim.
pub const KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1: usize = 16_384;
/// Maximum standalone canonical frame of one fee claim.
pub const KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1: usize = 16_384;
/// Maximum standalone canonical frame of one Bootstrap activation.
pub const KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1: usize = 16_384;
/// Maximum standalone canonical frame of one load closure.
pub const KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1: usize = 16_384;
/// Maximum standalone canonical frame of one signed load/unload charge quote.
pub const KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1: usize = 1_024;
/// Maximum standalone canonical frame of one attestation-lease renewal request.
pub const KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1: usize = 73_728;
/// Maximum standalone canonical frame of one local completion record.
pub const KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1: usize = 65_536;
/// Maximum standalone canonical frame of one local recovery capsule.
pub const KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1: usize = 262_144;
/// Maximum standalone canonical frame of one local fold record.
///
/// The record carries one Ω, which must fit the 10,000-byte Payment that carries it (§8), so
/// the record shares the message bound.
pub const KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1: usize = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
/// Maximum standalone canonical frame of one complete signed blacklist: 2,228,736 bytes.
///
/// The blacklist is not a peer message and has no envelope: a wallet downloads this frame only
/// while online, from the issuer or ledger, and peers never relay it, so its size does not
/// bear on the per-kind envelope bounds. Every canonical entry takes 34 bytes (an element length, a field length and the 32-byte
/// digest); the cap allows one entry per gap leaf plus 512 bytes for the header, body and
/// signature. The measured maximum list (65,535 entries) is 2,228,433 bytes, so the design
/// C1 figure of 2,228,224 bytes, which would reject a maximum list, is superseded by this
/// formula; SDKs take the cap from the vectors file.
pub const KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1: usize = 65_536 * 34 + 512;

/// Error returned when a KAGEMUSHA wallet V1 value fails canonical decoding or validation.
#[derive(Debug)]
pub enum KagemushaWalletValidationErrorV1 {
    /// Canonical Norito encoding or decoding failed.
    Codec(norito::Error),
    /// A complete canonical frame exceeded its protocol bound.
    EncodedSizeExceeded {
        /// Complete frame length in bytes.
        actual: usize,
        /// Maximum accepted frame length in bytes.
        max: usize,
    },
    /// A version field differs from [`KAGEMUSHA_WALLET_VERSION_V1`].
    UnsupportedVersion {
        /// Stable field label.
        field: &'static str,
        /// Decoded version value.
        version: u16,
    },
    /// A value names a scheme, network or relation other than the expected one.
    SchemeMismatch {
        /// Stable field label.
        field: &'static str,
    },
    /// A field or binding is malformed or inconsistent.
    InvalidField {
        /// Stable field label.
        field: &'static str,
    },
    /// A signature is malformed, high-S, or does not verify under the required key over the
    /// signing message of its domain.
    InvalidSignature {
        /// Signing domain of the signed body.
        domain: KagemushaWalletSigningDomainV1,
    },
    /// Checked integer arithmetic or a length conversion overflowed.
    ArithmeticOverflow {
        /// Stable field label.
        field: &'static str,
    },
}

impl core::fmt::Display for KagemushaWalletValidationErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "canonical KAGEMUSHA wallet V1 codec failed: {error}"),
            Self::EncodedSizeExceeded { actual, max } => {
                write!(
                    f,
                    "KAGEMUSHA wallet V1 frame size {actual} exceeds limit {max}"
                )
            }
            Self::UnsupportedVersion { field, version } => {
                write!(
                    f,
                    "unsupported KAGEMUSHA wallet V1 `{field}` version {version}"
                )
            }
            Self::SchemeMismatch { field } => {
                write!(f, "KAGEMUSHA wallet V1 `{field}` names another scheme")
            }
            Self::InvalidField { field } => {
                write!(f, "invalid KAGEMUSHA wallet V1 field `{field}`")
            }
            Self::InvalidSignature { domain } => write!(
                f,
                "invalid KAGEMUSHA wallet V1 signature in signing domain `{}`",
                domain.as_str()
            ),
            Self::ArithmeticOverflow { field } => {
                write!(f, "KAGEMUSHA wallet V1 arithmetic overflow in `{field}`")
            }
        }
    }
}

impl std::error::Error for KagemushaWalletValidationErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<norito::Error> for KagemushaWalletValidationErrorV1 {
    fn from(error: norito::Error) -> Self {
        Self::Codec(error)
    }
}

impl From<AxtAssetIncarnationValidationError> for KagemushaWalletValidationErrorV1 {
    fn from(_: AxtAssetIncarnationValidationError) -> Self {
        Self::InvalidField {
            field: "asset_incarnation",
        }
    }
}

/// Result type shared by the wallet object owners.
type WalletResult<T> = Result<T, KagemushaWalletValidationErrorV1>;

const fn text_max_bytes_v1(frame_max_bytes: usize) -> usize {
    match KAGEMUSHA_WALLET_TEXT_PREFIX_V1
        .len()
        .checked_add(unpadded_base64url_len_v1(frame_max_bytes))
    {
        Some(total) => total,
        None => panic!("KAGEMUSHA wallet V1 text bound overflow"),
    }
}

/// Exact unpadded base64url length of `len` raw bytes.
const fn unpadded_base64url_len_v1(len: usize) -> usize {
    let full_groups = match (len / 3).checked_mul(4) {
        Some(value) => value,
        None => panic!("KAGEMUSHA wallet V1 base64url length overflow"),
    };
    let tail = match len % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    match full_groups.checked_add(tail) {
        Some(value) => value,
        None => panic!("KAGEMUSHA wallet V1 base64url length overflow"),
    }
}

fn invalid_v1(field: &'static str) -> KagemushaWalletValidationErrorV1 {
    KagemushaWalletValidationErrorV1::InvalidField { field }
}

fn overflow_v1(field: &'static str) -> KagemushaWalletValidationErrorV1 {
    KagemushaWalletValidationErrorV1::ArithmeticOverflow { field }
}

fn require_version_v1(field: &'static str, version: u16) -> WalletResult<()> {
    if version == KAGEMUSHA_WALLET_VERSION_V1 {
        Ok(())
    } else {
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { field, version })
    }
}

/// Version fields of one wire value and of every wire value nested in it.
///
/// Every framed decode checks all of them after canonical decoding and before the per-kind
/// bound and the expected scheme (design §0), so a nested body that also names another scheme
/// is reported as an unsupported version, never as a scheme mismatch. Fields are checked in
/// declaration order, outer value first.
trait WalletVersionsV1 {
    /// Require every version field to equal [`KAGEMUSHA_WALLET_VERSION_V1`].
    fn require_versions(&self) -> WalletResult<()>;
}

/// Whether a digest is the all-zero value, which encodes "none".
fn is_zero_v1(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

/// Reject the all-zero value, which encodes "none" for a digest.
fn require_nonzero_v1(field: &'static str, digest: &[u8; 32]) -> WalletResult<()> {
    if is_zero_v1(digest) {
        Err(invalid_v1(field))
    } else {
        Ok(())
    }
}

/// Reject a noncanonical σ-field encoding (`>= p`, design §1.2).
fn require_canonical_field_v1(field: &'static str, value: &[u8; 32]) -> WalletResult<()> {
    if digest::kagemusha_wallet_is_canonical_field_v1(value) {
        Ok(())
    } else {
        Err(invalid_v1(field))
    }
}

/// Reject a noncanonical or zero σ-field encoding.
fn require_nonzero_field_v1(field: &'static str, value: &[u8; 32]) -> WalletResult<()> {
    require_nonzero_v1(field, value)?;
    require_canonical_field_v1(field, value)
}

fn require_scheme_v1(
    field: &'static str,
    actual: &[u8; 32],
    expected: &[u8; 32],
) -> WalletResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { field })
    }
}

/// Encode one canonical frame and enforce its complete-frame bound.
fn encode_frame_v1<T: norito::NoritoSerialize>(value: &T, max: usize) -> WalletResult<Vec<u8>> {
    let bytes = norito::encode_canonical(value)?;
    if bytes.len() > max {
        return Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: bytes.len(),
            max,
        });
    }
    Ok(bytes)
}

/// Decode one exact canonical frame after its byte cap, under payload-derived limits that
/// are installed before any derived sequence decoder can reserve memory.
fn decode_frame_v1<T>(bytes: &[u8], max: usize) -> WalletResult<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.len() > max {
        return Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: bytes.len(),
            max,
        });
    }
    let limits = norito::canonical_decode_limits(bytes.len());
    Ok(norito::decode_canonical_with_limits(bytes, limits)?)
}
