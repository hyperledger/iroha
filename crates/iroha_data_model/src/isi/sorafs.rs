use super::*;
use crate::musubi::ArchiveId;
use crate::sorafs::{
    capacity::{
        CapacityDisputeId, CapacityDisputeOutcome, CapacityDisputeRecord, CapacityTelemetryRecord,
        ProviderId,
    },
    moderation_ledger::{
        ModerationAppealIntakeV1, ModerationChallengeDecisionV1, ModerationChallengeKindV1,
        ModerationLedgerPolicyV1,
    },
    orderbook::OrderbookAdmissionPolicyV1,
    pin_registry::{
        ManifestAliasBinding, ManifestDigest, ProviderIngestCompletionAuthorityV1,
        ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
    },
    pop_registry::PopIssuerPolicyV1,
    pricing::{PricingScheduleRecord, ProviderCreditRecord},
    proof_ledger::ProofOutcomeSignerPolicyV1,
    reputation::{ReputationJournalAuthorityPolicyV1, ReputationJournalEntryV1},
    reserve::{
        ReserveAuthorityPolicyV1, ReserveLifecycleStage, ReserveMovementKindV1,
        ReserveProviderTermsV1,
    },
};
use iroha_crypto::HashOf;

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use sorafs_manifest::{capacity::ReplicationAssignmentV1, deal::XorQuantity};
isi! {
    /// Initialize the sole provider admission authority from signed genesis.
    /// All later admission changes require an exact enacted Parliament certificate.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1")]
    pub struct InitializeSorafsProviderAdmissionV1 {
        /// Network-independent council template authenticated by signed genesis.
        pub council: crate::sorafs::provider_admission::governance::InitialProviderAdmissionCouncilV1,
        /// At most 64 initial providers, strictly ordered by the enclosed provider id.
        pub providers: Vec<crate::sorafs::provider_admission::governance::InitialProviderAdmissionV1>,
    }
}
impl crate::seal::Instruction for InitializeSorafsProviderAdmissionV1 {}
isi! {
    /// Register a canonical `SoraFS` manifest with the paid pin registry.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterPinManifest")]
    pub struct RegisterPinManifest {
        /// Canonical Norito-encoded `sorafs_manifest::ManifestV1` payload.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub manifest_payload: Vec<u8>,
        /// Optional alias binding approved with the manifest.
        pub alias: Option<ManifestAliasBinding>,
        /// Optional predecessor manifest digest forming a succession chain.
        pub successor_of: Option<ManifestDigest>,
    }
}
impl crate::seal::Instruction for RegisterPinManifest {}
isi! {
    /// Assert the publisher's exact active paid pin and replication assignment at execution.
    /// A successful signed execution requires native block finality and execution proof verification.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::AssertSorafsPublicationV1")]
    pub struct AssertSorafsPublicationV1 {
        /// Exact manifest registered by the transaction authority.
        pub manifest_digest: ManifestDigest,
        /// Exact automatic replication order derived from the manifest digest.
        pub order_id: ReplicationOrderId,
        /// Current assignment revision expected by the publisher.
        pub assignment_revision: u64,
        /// BLAKE3 of the complete canonical replication order bytes.
        pub canonical_order_digest: [u8; 32],
        /// Require every assigned provider completion, instead of a live assigned order.
        pub require_complete: bool,
        /// Fresh non-zero challenge retained independently by the publisher.
        pub challenge: [u8; 32],
        /// Independently trusted finalized floor preceding this assertion.
        pub minimum_height: u64,
        /// Exact block hash at that floor.
        pub minimum_block_hash: [u8; 32],
    }
}
impl crate::seal::Instruction for AssertSorafsPublicationV1 {}
isi! {
    /// Approve a previously registered manifest digest.
#[norito_schema(name = "iroha_data_model::isi::sorafs::ApprovePinManifest")]
pub struct ApprovePinManifest {
    /// Manifest digest previously registered with the pin registry.
    pub digest: ManifestDigest,
        /// Optional governance envelope (`manifest_signatures.json`) attached to the approval.
        #[norito (json = "crate::json_helpers::base64_vec::option")]
        pub council_envelope: Option<Vec<u8>>,
        /// Optional digest of the council envelope (`manifest_signatures.json`).
        #[norito (json = "crate::json_helpers::fixed_bytes::option")]
        pub council_envelope_digest: Option<[u8; 32]>,
    }
}
impl crate::seal::Instruction for ApprovePinManifest {}
isi! {
    /// Retire a manifest digest from the pin registry.
#[norito_schema(name = "iroha_data_model::isi::sorafs::RetirePinManifest")]
pub struct RetirePinManifest {
    /// Manifest digest to retire.
    pub digest: ManifestDigest,
        /// Optional human-readable reason recorded alongside the retirement.
        pub reason: Option<String>,
    }
}
impl crate::seal::Instruction for RetirePinManifest {}
isi! {
    /// Bind an approved alias to a manifest digest.
#[norito_schema(name = "iroha_data_model::isi::sorafs::BindManifestAlias")]
pub struct BindManifestAlias {
    /// Manifest digest that will be associated with the alias.
    pub digest: ManifestDigest,
        /// Alias binding payload approved by governance.
        pub binding: ManifestAliasBinding,
        /// Epoch (inclusive) when the alias becomes active.
        pub bound_epoch: u64,
        /// Epoch (inclusive) when the alias expires unless renewed.
        pub expiry_epoch: u64,
    }
}
impl crate::seal::Instruction for BindManifestAlias {}
isi! {
    /// Register or update capacity for an already governed, bonded provider.
    ///
    /// Execution requires the transaction authority to be the exact registered provider owner and
    /// the declaration's stake to be covered by the owner-funded native reserve ledger. This
    /// instruction never creates or changes a provider-owner binding.
#[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterCapacityDeclaration")]
pub struct RegisterCapacityDeclaration {
    /// Canonical Norito `CapacityDeclarationV1`; registration time and registry summaries are derived by consensus.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub declaration: Vec<u8>,
    }
}
impl crate::seal::Instruction for RegisterCapacityDeclaration {}
isi! {
    /// Record a capacity telemetry snapshot for a provider.
#[norito_schema(name = "iroha_data_model::isi::sorafs::RecordCapacityTelemetry")]
pub struct RecordCapacityTelemetry {
    /// Telemetry record used to update the fee ledger.
    pub record: CapacityTelemetryRecord,
    }
}
impl crate::seal::Instruction for RecordCapacityTelemetry {}
isi! {
    /// Register a governance-authored dispute targeting a storage provider.
#[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterCapacityDispute")]
pub struct RegisterCapacityDispute {
    /// Canonical dispute record that will be persisted in the registry.
    pub record: CapacityDisputeRecord,
    }
}
impl crate::seal::Instruction for RegisterCapacityDispute {}
isi! {
    /// Issue a replication order covering one or more storage providers.
#[norito_schema(name = "iroha_data_model::isi::sorafs::IssueReplicationOrder")]
pub struct IssueReplicationOrder {
    /// Deterministic identifier assigned to the replication order.
    pub order_id: ReplicationOrderId,
        /// Canonical Norito-encoded replication order payload.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub order_payload: Vec<u8>,
        /// Unix second (inclusive) when the order is issued.
        pub issued_epoch: u64,
        /// Unix second (inclusive) when the order expires.
        pub deadline_epoch: u64,
        /// Optional immutable Musubi archive purpose installed atomically with this order.
        pub musubi_archive: Option<ArchiveId>,
    }
}
impl crate::seal::Instruction for IssueReplicationOrder {}
isi! {
    /// Mark a replication order as completed.
#[norito_schema(name = "iroha_data_model::isi::sorafs::CompleteReplicationOrder")]
pub struct CompleteReplicationOrder {
    /// Identifier of the replication order.
    pub order_id: ReplicationOrderId,
        /// Provider assignment whose ingestion is complete.
        pub provider_id: ProviderId,
        /// Unix second (inclusive) when replication completed.
        pub completion_epoch: u64,
        /// Exact chain-authoritative provider owner and signer policy expected at commit.
        pub expected_authority: ProviderIngestCompletionAuthorityV1,
        /// Exact order-scoped assignment revision expected at commit.
        pub expected_assignment_revision: u64,
        /// Finalized committed-chain prefix on which preparation was based.
        pub finalized_anchor: ProviderIngestFinalizedAnchorV1,
    }
}
impl crate::seal::Instruction for CompleteReplicationOrder {}
isi! {
    /// Replace the provider assignment set of a pending replication order.
#[norito_schema(name = "iroha_data_model::isi::sorafs::ReviseReplicationOrderAssignments")]
pub struct ReviseReplicationOrderAssignments {
    /// Identifier of the pending replication order.
    pub order_id: ReplicationOrderId,
        /// Current assignment revision required for compare-and-set.
        pub expected_assignment_revision: u64,
        /// Strict monotonic successor revision.
        pub next_assignment_revision: u64,
        /// Complete canonical replacement assignment set.
        pub assignments: Vec<ReplicationAssignmentV1>,
    }
}
impl crate::seal::Instruction for ReviseReplicationOrderAssignments {}
isi! {
    /// Mark a pending replication order as expired after its deadline.
#[norito_schema(name = "iroha_data_model::isi::sorafs::ExpireReplicationOrder")]
pub struct ExpireReplicationOrder {
    /// Identifier of the replication order.
    pub order_id: ReplicationOrderId,
        /// Unix second at which the order is expired; must be later than its deadline and no later than consensus time.
        pub expiration_epoch: u64,
    }
}
impl crate::seal::Instruction for ExpireReplicationOrder {}
isi! {
    /// Retired direct provider-owner registration surface.
    ///
    /// Core rejects this instruction unconditionally. Provider ownership is
    /// established only by enacting a [`SorafsProviderGovernanceActionV1`].
#[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterProviderOwner")]
pub struct RegisterProviderOwner {
    /// Provider identifier that will be bound.
    pub provider_id: ProviderId,
        /// Account identifier that owns the provider.
        pub owner: AccountId,
    }
}
impl crate::seal::Instruction for RegisterProviderOwner {}
isi! {
    /// Retired direct provider-owner removal surface.
    ///
    /// Core rejects this instruction unconditionally. Provider ownership is
    /// removed only by enacting a [`SorafsProviderGovernanceActionV1`].
#[norito_schema(name = "iroha_data_model::isi::sorafs::UnregisterProviderOwner")]
pub struct UnregisterProviderOwner {
    /// Provider identifier whose binding will be removed.
    pub provider_id: ProviderId,
    }
}
impl crate::seal::Instruction for UnregisterProviderOwner {}
/// Establish one previously unknown `SoraFS` provider-owner binding.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct EstablishSorafsProviderOwnerV1 {
    /// Provider identifier that must not already have an owner.
    pub provider_id: ProviderId,
    /// Existing account that will own the provider.
    pub owner: AccountId,
}
/// Compare-and-set replacement of one `SoraFS` provider owner.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct RebindSorafsProviderOwnerV1 {
    /// Provider identifier whose owner will be replaced.
    pub provider_id: ProviderId,
    /// Exact current owner required for compare-and-set.
    pub expected_owner: AccountId,
    /// Existing account that becomes the next owner.
    pub next_owner: AccountId,
}
/// Compare-and-remove one `SoraFS` provider-owner binding.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct RemoveSorafsProviderOwnerV1 {
    /// Provider identifier whose owner will be removed.
    pub provider_id: ProviderId,
    /// Exact current owner required for compare-and-remove.
    pub expected_owner: AccountId,
}
/// Closed provider-owner transition admitted only through native governance.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "action",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SorafsProviderGovernanceActionV1 {
    /// Establish a provider that has no owner binding.
    #[codec(index = 0)]
    Establish(EstablishSorafsProviderOwnerV1),
    /// Replace the exact current owner.
    #[codec(index = 1)]
    Rebind(RebindSorafsProviderOwnerV1),
    /// Remove the exact current owner.
    #[codec(index = 2)]
    Remove(RemoveSorafsProviderOwnerV1),
    /// Enact an exact council-policy or provider-admission transition.
    #[codec(index = 3)]
    Admission(crate::sorafs::provider_admission::governance::ProviderAdmissionGovernanceActionV1),
}
impl SorafsProviderGovernanceActionV1 {
    /// Validate the closed action before proposal admission or enactment.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero provider identifier or a no-op rebind.
    pub fn validate(&self) -> Result<(), iroha_model_base::error::ParseError> {
        if let Self::Admission(action) = self {
            return action.provider_id().map(|_| ()).map_err(|_| {
                iroha_model_base::error::ParseError::new(
                    "invalid canonical provider admission effect",
                )
            });
        }
        let provider_id = match self {
            Self::Establish(action) => action.provider_id,
            Self::Rebind(action) => {
                if action.expected_owner == action.next_owner {
                    return Err(iroha_model_base::error::ParseError::new(
                        "SoraFS provider-owner rebind must change the owner",
                    ));
                }
                action.provider_id
            }
            Self::Remove(action) => action.provider_id,
            Self::Admission(_) => unreachable!("admission validated above"),
        };
        if provider_id == ProviderId::default() {
            return Err(iroha_model_base::error::ParseError::new(
                "SoraFS provider governance action requires a non-zero provider id",
            ));
        }
        Ok(())
    }
    /// Provider identifier affected by this transition.
    #[must_use]
    pub fn provider_id(&self) -> Option<ProviderId> {
        match self {
            Self::Establish(action) => Some(action.provider_id),
            Self::Rebind(action) => Some(action.provider_id),
            Self::Remove(action) => Some(action.provider_id),
            Self::Admission(action) => action.provider_id().ok().flatten(),
        }
    }
}
isi! {
    /// Compare-and-set the completion authority for a `SoraFS` provider.
#[norito_schema(name = "iroha_data_model::isi::sorafs::SetProviderIngestCompletionAuthority")]
pub struct SetProviderIngestCompletionAuthority {
    /// Provider whose completion authority is updated.
    pub provider_id: ProviderId,
        /// Exact current authority, or `None` for first registration.
        pub expected_current: Option<ProviderIngestCompletionAuthorityV1>,
        /// Exact successor owner and governed signer policy.
        pub next: ProviderIngestCompletionAuthorityV1,
    }
}
impl crate::seal::Instruction for SetProviderIngestCompletionAuthority {}
isi! {
    /// Revoke the exact current completion authority for a `SoraFS` provider.
#[norito_schema(name = "iroha_data_model::isi::sorafs::RevokeProviderIngestCompletionAuthority")]
pub struct RevokeProviderIngestCompletionAuthority {
    /// Provider whose completion authority is revoked.
    pub provider_id: ProviderId,
        /// Exact current authority required for compare-and-remove.
        pub expected_current: ProviderIngestCompletionAuthorityV1,
    }
}
impl crate::seal::Instruction for RevokeProviderIngestCompletionAuthority {}
isi! {
    /// Update the governance-controlled pricing schedule for `SoraFS`.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetPricingSchedule")]
    pub struct SetPricingSchedule {
        /// Pricing schedule record that replaces the previous schedule.
        pub schedule: PricingScheduleRecord,
    }
}
impl crate::seal::Instruction for SetPricingSchedule {}
isi! {
    /// Upsert the governed credit projection for a storage provider.
    ///
    /// The provider-owner binding and owner-funded native reserve account must
    /// already exist. Submitted `bonded + slashed` must exactly equal the
    /// locked reserve balance net of treasury-funded principal, and an upsert
    /// cannot reset slash history or create bonded collateral.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::sorafs::UpsertProviderCredit")]
    pub struct UpsertProviderCredit {
        /// Exact current native record hash, or explicit absence for initial creation.
        /// This field is required in JSON; omission never authorizes an unguarded upsert.
        #[norito(required)]
        pub expected_current: Option<HashOf<ProviderCreditRecord>>,
        /// Credit record snapshot used to seed or update governance accounting.
        pub record: ProviderCreditRecord,
    }
}
impl crate::seal::Instruction for UpsertProviderCredit {}
isi! {
    /// Activate the next governance-controlled `PoP` issuer policy revision.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsPopIssuerPolicy")]
    pub struct SetSorafsPopIssuerPolicy {
        /// Policy revision to validate and activate.
        pub policy: PopIssuerPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsPopIssuerPolicy {}
isi! {
    /// Commit a bounded batch of private `PoP` credentials and public roots atomically.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::CommitSorafsPopCredentialBatch")]
    pub struct CommitSorafsPopCredentialBatch {
        /// Exact canonical Norito `PopCredentialCommitmentBatchV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub batch_payload: Vec<u8>,
    }
}
impl crate::seal::Instruction for CommitSorafsPopCredentialBatch {}
isi! {
    /// Publish a strict signed extension of the active `PoP` revocation list.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::PublishSorafsPopRevocationList")]
    pub struct PublishSorafsPopRevocationList {
        /// Exact canonical Norito `sorafs_manifest::PopRevocationListV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub revocation_list_payload: Vec<u8>,
        /// Exact active issuer-policy digest expected by the publisher.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub issuer_policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for PublishSorafsPopRevocationList {}
isi! {
    /// Activate the next governance-controlled `SoraFS` orderbook policy revision.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsOrderbookPolicy")]
    pub struct SetSorafsOrderbookPolicy {
        /// Policy revision to validate and activate.
        pub policy: OrderbookAdmissionPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsOrderbookPolicy {}
isi! {
    /// Submit a signed canonical order to the authoritative `SoraFS` orderbook ledger.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsOrderbookOrder")]
    pub struct SubmitSorafsOrderbookOrder {
        /// Exact canonical Norito `sorafs_manifest::orderbook::OrderRequestV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub order_payload: Vec<u8>,
        /// Active governance policy digest expected by the submitter.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for SubmitSorafsOrderbookOrder {}
isi! {
    /// Commit a signed owner cancellation to the authoritative `SoraFS` orderbook ledger.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::CancelSorafsOrderbookOrder")]
    pub struct CancelSorafsOrderbookOrder {
        /// Exact canonical Norito `sorafs_manifest::orderbook::OrderCancelV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub cancel_payload: Vec<u8>,
        /// Active governance policy digest expected by the submitter.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for CancelSorafsOrderbookOrder {}
isi! {
    /// Execute one bounded deterministic price-time matching transition.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MatchSorafsOrderbook")]
    pub struct MatchSorafsOrderbook {
        /// Exact active governance policy digest expected by the matcher.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
        /// Exact authoritative book revision on which the match was computed.
        pub expected_book_revision: u64,
        /// Maximum fills to commit in this transition.
        pub max_fills: u32,
    }
}
impl crate::seal::Instruction for MatchSorafsOrderbook {}
isi! {
    /// Retire expired orders and channels in one bounded authoritative transition.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::MaintainSorafsOrderbook")]
    pub struct MaintainSorafsOrderbook {
        /// Exact active governance policy digest expected by the caller.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
        /// Exact authoritative book revision expected by the caller.
        pub expected_book_revision: u64,
        /// Maximum order/channel records to retire.
        pub max_items: u32,
    }
}
impl crate::seal::Instruction for MaintainSorafsOrderbook {}
isi! {
    /// Settle a funded channel lock and record its signed receipt in the authoritative ledger.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RecordSorafsOrderbookSettlementReceipt")]
    pub struct RecordSorafsOrderbookSettlementReceipt {
        /// Exact canonical Norito `sorafs_manifest::orderbook::SettlementReceiptV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub receipt_payload: Vec<u8>,
        /// Active governance policy digest expected by the recorder.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for RecordSorafsOrderbookSettlementReceipt {}
isi! {
    /// Activate the next chain-authoritative reserve/rent policy revision.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsReservePolicy")]
    pub struct SetSorafsReservePolicy {
        /// Governance policy to validate and activate.
        pub policy: ReserveAuthorityPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsReservePolicy {}
isi! {
    /// Register one provider reserve partition and immutable underwriting terms.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterSorafsReserveAccount")]
    pub struct RegisterSorafsReserveAccount {
        /// Provider underwriting terms.
        pub terms: ReserveProviderTermsV1,
        /// Exact active reserve policy digest expected by governance.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for RegisterSorafsReserveAccount {}
isi! {
    /// Submit a provider-authenticated reserve top-up or withdrawal request.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RequestSorafsReserveMovement")]
    pub struct RequestSorafsReserveMovement {
        /// Globally unique request identifier.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub movement_id: [u8; 32],
        /// Provider reserve partition.
        pub provider_id: ProviderId,
        /// Top-up or withdrawal direction.
        pub kind: ReserveMovementKindV1,
        /// Exact non-zero movement amount.
        pub amount: XorQuantity,
        /// Provider account revision expected by the request.
        pub expected_provider_revision: u64,
        /// Exact active reserve policy digest expected by the request.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for RequestSorafsReserveMovement {}
isi! {
    /// Decide and atomically apply or reject a pending reserve movement.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::DecideSorafsReserveMovement")]
    pub struct DecideSorafsReserveMovement {
        /// Pending movement identifier.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub movement_id: [u8; 32],
        /// Provider account revision expected by the decision.
        pub expected_provider_revision: u64,
        /// Exact active reserve policy digest expected by the decision service.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
        /// Whether governance approves the movement.
        pub approve: bool,
        /// Bounded governance rationale.
        pub rationale: String,
    }
}
impl crate::seal::Instruction for DecideSorafsReserveMovement {}
isi! {
    /// Charge one or more deterministic rent periods to a provider.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::ChargeSorafsReserveRent")]
    pub struct ChargeSorafsReserveRent {
        /// Provider reserve partition.
        pub provider_id: ProviderId,
        /// Provider account revision expected by the charge.
        pub expected_provider_revision: u64,
        /// Number of billing periods, bounded by native execution.
        pub billing_periods: u16,
        /// Exact active reserve policy digest expected by governance.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for ChargeSorafsReserveRent {}
isi! {
    /// Advance a provider's deterministic reserve lifecycle projection.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::AdvanceSorafsReserveLifecycle")]
    pub struct AdvanceSorafsReserveLifecycle {
        /// Provider reserve partition.
        pub provider_id: ProviderId,
        /// Provider account revision expected by the transition.
        pub expected_provider_revision: u64,
        /// Deterministic days past due.
        pub days_past_due: u16,
        /// Exact active reserve policy digest expected by governance.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for AdvanceSorafsReserveLifecycle {}
isi! {
    /// Draw reserve credit under the provider's tier and global debt caps.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::DrawSorafsReserveCredit")]
    pub struct DrawSorafsReserveCredit {
        /// Provider reserve partition.
        pub provider_id: ProviderId,
        /// Provider account revision expected by the draw.
        pub expected_provider_revision: u64,
        /// Exact non-zero draw amount.
        pub amount: XorQuantity,
        /// Exact active reserve policy digest expected by governance.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for DrawSorafsReserveCredit {}
isi! {
    /// Repay accrued reserve interest and then credit principal.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RepaySorafsReserveCredit")]
    pub struct RepaySorafsReserveCredit {
        /// Provider reserve partition.
        pub provider_id: ProviderId,
        /// Provider account revision expected by the repayment.
        pub expected_provider_revision: u64,
        /// Exact non-zero repayment amount.
        pub amount: XorQuantity,
        /// Exact active reserve policy digest expected by the provider.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for RepaySorafsReserveCredit {}
isi! {
    /// Submit a bounded provider-authenticated reserve lifecycle appeal.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsReserveAppeal")]
    pub struct SubmitSorafsReserveAppeal {
        /// Globally unique appeal identifier.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub appeal_id: [u8; 32],
        /// Appealing provider.
        pub provider_id: ProviderId,
        /// Provider revision expected by the appeal.
        pub expected_provider_revision: u64,
        /// Requested lifecycle stage.
        pub requested_stage: ReserveLifecycleStage,
        /// Bounded provider reason.
        pub reason: String,
        /// Optional external evidence digest.
        #[norito (json = "crate::json_helpers::fixed_bytes::option")]
        pub evidence_digest: Option<[u8; 32]>,
        /// Exact active reserve policy digest expected by the provider.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for SubmitSorafsReserveAppeal {}
isi! {
    /// Attach a terminal governance decision to a pending reserve appeal.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::DecideSorafsReserveAppeal")]
    pub struct DecideSorafsReserveAppeal {
        /// Pending appeal identifier.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub appeal_id: [u8; 32],
        /// Provider account revision expected by the decision.
        pub expected_provider_revision: u64,
        /// Exact active reserve policy digest expected by the decision service.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub policy_digest: [u8; 32],
        /// Whether governance accepts and applies the requested stage.
        pub accept: bool,
        /// Bounded governance rationale.
        pub rationale: String,
    }
}
impl crate::seal::Instruction for DecideSorafsReserveAppeal {}
/// Repair lease-claim action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct SorafsRepairClaimV1 {
    /// Requested lease duration measured from the committing block time.
    pub lease_duration_ms: u64,
    /// Bounded caller key used for exact replay handling.
    pub idempotency_key: String,
}
/// Repair lease-renewal action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct SorafsRepairRenewV1 {
    /// Exact current lease generation.
    pub lease_generation: u64,
    /// Requested lease duration measured from the committing block time.
    pub lease_duration_ms: u64,
    /// Bounded caller key used for exact replay handling.
    pub idempotency_key: String,
}
/// Successful repair terminal action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct SorafsRepairCompleteV1 {
    /// Exact current lease generation.
    pub lease_generation: u64,
    /// Digest of external completion verification evidence.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub evidence_digest: [u8; 32],
    /// Bounded caller key used for exact replay handling.
    pub idempotency_key: String,
}
/// Failed repair terminal action without slashing.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct SorafsRepairFailV1 {
    /// Exact current lease generation.
    pub lease_generation: u64,
    /// Digest of the failure reason or external evidence.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub failure_digest: [u8; 32],
    /// Bounded caller key used for exact replay handling.
    pub idempotency_key: String,
}
/// Escalated repair terminal action with an atomic slash proposal.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
pub struct SorafsRepairEscalateV1 {
    /// Exact current lease generation.
    pub lease_generation: u64,
    /// Exact canonical `sorafs_manifest::repair::RepairSlashProposalV1` bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub slash_proposal_payload: Vec<u8>,
    /// Bounded caller key used for exact replay handling.
    pub idempotency_key: String,
}
/// Chain-authoritative mutation of one `SoraFS` repair task.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "action", content = "value", rename_all = "snake_case")]
pub enum SorafsRepairTaskActionV1 {
    /// Acquire an absent or expired exclusive worker lease.
    Claim(SorafsRepairClaimV1),
    /// Extend the caller's unexpired lease.
    Renew(SorafsRepairRenewV1),
    /// Commit the task's single successful terminal outcome.
    Complete(SorafsRepairCompleteV1),
    /// Commit the task's single unsuccessful terminal outcome without slashing.
    Fail(SorafsRepairFailV1),
    /// Commit an escalated terminal outcome and slash proposal atomically.
    Escalate(SorafsRepairEscalateV1),
}
impl SorafsRepairTaskActionV1 {
    /// Return the caller-supplied idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        match self {
            Self::Claim(action) => &action.idempotency_key,
            Self::Renew(action) => &action.idempotency_key,
            Self::Complete(action) => &action.idempotency_key,
            Self::Fail(action) => &action.idempotency_key,
            Self::Escalate(action) => &action.idempotency_key,
        }
    }
}
isi! {
    /// Admit one exact canonical repair report under a subsystem exactly-once identity.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsRepairTask")]
    pub struct SubmitSorafsRepairTask {
        /// Non-zero source identity. `PoTR` uses the signed receipt digest.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub source_identity: [u8; 32],
        /// Exact canonical `sorafs_manifest::repair::RepairReportV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub report_payload: Vec<u8>,
    }
}
impl crate::seal::Instruction for SubmitSorafsRepairTask {}
isi! {
    /// Apply one compare-and-set repair lease or terminal transition.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::ApplySorafsRepairTaskAction")]
    pub struct ApplySorafsRepairTaskAction {
        /// Canonical repair ticket identifier.
        pub ticket_id: String,
        /// Exact task revision observed by the submitter.
        pub expected_revision: u64,
        /// Typed mutation to commit.
        pub action: SorafsRepairTaskActionV1,
    }
}
impl crate::seal::Instruction for ApplySorafsRepairTaskAction {}
isi! {
    /// Commit the provider owner's single appeal against an escalated repair slash.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsRepairAppeal")]
    pub struct SubmitSorafsRepairAppeal {
        /// Canonical repair ticket identifier.
        pub ticket_id: String,
        /// Exact task revision observed by the submitter.
        pub expected_revision: u64,
        /// Digest of external appeal evidence.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub evidence_digest: [u8; 32],
        /// Bounded payload-free appeal reason.
        pub reason: String,
        /// Bounded caller key used for exact replay handling.
        pub idempotency_key: String,
    }
}
impl crate::seal::Instruction for SubmitSorafsRepairAppeal {}
/// Canonical PDP proof material accepted by the chain-authoritative outcome journal.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct SorafsPdpProofOutcomeSubmissionV1 {
    /// Exact canonical `sorafs_manifest::PdpGovernanceArchiveV1` bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub archive_payload: Vec<u8>,
}
/// Canonical `PoTR` proof material accepted by the chain-authoritative outcome journal.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct SorafsPotrProofOutcomeSubmissionV1 {
    /// Exact canonical dual-signed `sorafs_manifest::PotrReceiptV1` bytes.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub receipt_payload: Vec<u8>,
    /// Council-verified admission envelope captured during receipt validation.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub admission_envelope_digest: [u8; 32],
}
/// Existing canonical proof material accepted by the chain-authoritative outcome journal.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::sorafs::SorafsProofOutcomeSubmissionV1")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "proof_kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SorafsProofOutcomeSubmissionV1 {
    /// Exact canonical PDP terminal archive and authentication material.
    #[codec(index = 0)]
    Pdp(SorafsPdpProofOutcomeSubmissionV1),
    /// Exact canonical dual-signed `PoTR` receipt and admission binding.
    #[codec(index = 1)]
    Potr(SorafsPotrProofOutcomeSubmissionV1),
}
isi! {
    /// Activate or rotate provider-scoped governed keys for `PDP` and `PoTR` outcome validation.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsProofOutcomeSignerPolicy")]
    pub struct SetSorafsProofOutcomeSignerPolicy {
        /// Monotonic provider-scoped signer policy.
        pub policy: ProofOutcomeSignerPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsProofOutcomeSignerPolicy {}
isi! {
    /// Commit one validated `PDP` or `PoTR` terminal outcome.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsProofOutcome")]
    pub struct SubmitSorafsProofOutcome {
        /// Existing canonical proof/archive material; no competing receipt schema is accepted.
        pub submission: SorafsProofOutcomeSubmissionV1,
    }
}
impl crate::seal::Instruction for SubmitSorafsProofOutcome {}
isi! {
    /// Activate the next governed recorder-policy revision for the reputation journal.
    ///
    /// Native execution requires original signed genesis custody or one sole direct ordinary
    /// instruction. The permanent record retains that exact successful activation source.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsReputationJournalAuthorityPolicy")]
    pub struct SetSorafsReputationJournalAuthorityPolicy {
        /// Strict predecessor-linked recorder policy.
        pub policy: ReputationJournalAuthorityPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsReputationJournalAuthorityPolicy {}
isi! {
    /// Commit one terminal native `PoR` projection to the global reputation journal.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::AppendSorafsPorReputationJournalEntry")]
    pub struct AppendSorafsPorReputationJournalEntry {
        /// Canonical policy-bound, content-addressed `PoR` entry carrying authenticated source time.
        ///
        /// Consensus stamps the authoritative recorded time during execution.
        pub entry: ReputationJournalEntryV1,
    }
}
impl crate::seal::Instruction for AppendSorafsPorReputationJournalEntry {}
isi! {
    /// Deliver the exact immutable append intent created by a committed native gateway source.
    ///
    /// This must be the sole direct instruction in its original source-pinned signed envelope.
    /// The native owner assigns the global journal index at execution; callers never reserve one.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::AppendSorafsStreamTokenReputationJournalEntry")]
    pub struct AppendSorafsStreamTokenReputationJournalEntry {
        /// Canonical policy-bound, content-addressed token entry carrying authenticated source time.
        ///
        /// Consensus stamps the authoritative recorded time during execution.
        pub entry: ReputationJournalEntryV1,
    }
}
impl crate::seal::Instruction for AppendSorafsStreamTokenReputationJournalEntry {}
isi! {
    /// Resolve one pending authoritative capacity dispute and append its terminal journal revision.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::ResolveSorafsCapacityDispute")]
    pub struct ResolveSorafsCapacityDispute {
        /// Existing authoritative capacity-dispute identity.
        pub dispute_id: CapacityDisputeId,
        /// Exact active reputation recorder-policy digest expected by the decision.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub expected_authority_policy_digest: [u8; 32],
        /// Governance outcome applied exactly once.
        pub outcome: CapacityDisputeOutcome,
        /// Digest of the canonical decision evidence or signed envelope.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub decision_digest: [u8; 32],
        /// Optional bounded canonical governance rationale.
        pub rationale: Option<String>,
    }
}
impl crate::seal::Instruction for ResolveSorafsCapacityDispute {}
isi! {
    /// Activate the next authoritative `SoraFS` moderation-ledger policy revision.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SetSorafsModerationPolicy")]
    pub struct SetSorafsModerationPolicy {
        /// Policy revision to validate and activate.
        pub policy: ModerationLedgerPolicyV1,
    }
}
impl crate::seal::Instruction for SetSorafsModerationPolicy {}
isi! {
    /// Admit one appellant-authenticated moderation appeal and pin frozen citizen-bond anchors.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsModerationAppeal")]
    pub struct SubmitSorafsModerationAppeal {
        /// Immutable bounded appeal intake.
        pub intake: ModerationAppealIntakeV1,
    }
}
impl crate::seal::Instruction for SubmitSorafsModerationAppeal {}
isi! {
    /// Register one authority-bound private `PoP` membership proof for panel eligibility.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RegisterSorafsModerationJurorEligibility")]
    pub struct RegisterSorafsModerationJurorEligibility {
        /// Appeal case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Exact canonical Norito `PopMembershipProofV1` bytes; never persisted.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub membership_proof_payload: Vec<u8>,
    }
}
impl crate::seal::Instruction for RegisterSorafsModerationJurorEligibility {}
isi! {
    /// Close eligibility registration and persist the uniquely deterministic panel draw.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::FinalizeSorafsModerationSortition")]
    pub struct FinalizeSorafsModerationSortition {
        /// Appeal case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Exact pinned citizen-bond snapshot digest expected by the operator.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub citizen_snapshot_digest: [u8; 32],
        /// Exact consensus-pinned first post-registration block hash expected to seed the draw.
        ///
        /// Native start-of-block maintenance fixes this anchor after registration closes.
        /// Execution remains stable across later `QueuePlan` carriers and rejects caller-selected
        /// or same-anchor-block proposals.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub randomness_anchor: [u8; 32],
        /// Proposed primary roster; execution recomputes and rejects biased input.
        pub proposed_jurors: Vec<AccountId>,
        /// Proposed failover order; execution recomputes and rejects biased input.
        pub proposed_waitlist: Vec<AccountId>,
    }
}
impl crate::seal::Instruction for FinalizeSorafsModerationSortition {}
isi! {
    /// Accept one authority-bound primary moderation-juror assignment.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::AcceptSorafsModerationJurorAssignment")]
    pub struct AcceptSorafsModerationJurorAssignment {
        /// Appeal case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Exact sortition digest expected by the juror.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub sortition_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for AcceptSorafsModerationJurorAssignment {}
isi! {
    /// Apply deterministic no-show replacements and activate commit/reveal atomically.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::ActivateSorafsModerationCase")]
    pub struct ActivateSorafsModerationCase {
        /// Appeal case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Exact sortition digest expected by the operator.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub sortition_digest: [u8; 32],
    }
}
impl crate::seal::Instruction for ActivateSorafsModerationCase {}
isi! {
    /// Submit one canonical juror commitment to an authoritative moderation case.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsModerationCommit")]
    pub struct SubmitSorafsModerationCommit {
        /// Exact canonical Norito `SoraFsModerationBallotCommitV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub commit_payload: Vec<u8>,
    }
}
impl crate::seal::Instruction for SubmitSorafsModerationCommit {}
isi! {
    /// Raise one bounded, bonded, payload-free public moderation challenge.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::RaiseSorafsModerationChallenge")]
    pub struct RaiseSorafsModerationChallenge {
        /// Moderation case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Challenge id unique within the case and round.
        pub challenge_id: String,
        /// Fixed challenge category.
        pub kind: ModerationChallengeKindV1,
        /// Optional canonical juror target.
        pub target_juror: Option<AccountId>,
        /// Digest of external evidence; raw evidence is not placed on-chain.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub evidence_digest: [u8; 32],
        /// Bounded payload-free reason label.
        pub reason: String,
    }
}
impl crate::seal::Instruction for RaiseSorafsModerationChallenge {}
isi! {
    /// Resolve one pending authoritative moderation challenge.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::ResolveSorafsModerationChallenge")]
    pub struct ResolveSorafsModerationChallenge {
        /// Moderation case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
        /// Existing challenge identifier.
        pub challenge_id: String,
        /// Governance decision.
        pub decision: ModerationChallengeDecisionV1,
    }
}
impl crate::seal::Instruction for ResolveSorafsModerationChallenge {}
/// Permissionlessly expire one unresolved moderation challenge after its resolution grace.
/// Construct with named case, round, and challenge identifiers.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[getset(get = "pub")]
#[norito_schema(name = "iroha_data_model::isi::sorafs::ExpireSorafsModerationChallenge")]
pub struct ExpireSorafsModerationChallenge {
    /// Moderation case identifier.
    pub case_id: String,
    /// Ballot round identifier.
    pub round_id: String,
    /// Existing challenge identifier.
    pub challenge_id: String,
}
impl crate::seal::Instruction for ExpireSorafsModerationChallenge {}
isi! {
    /// Submit one canonical juror reveal to an authoritative moderation case.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::SubmitSorafsModerationReveal")]
    pub struct SubmitSorafsModerationReveal {
        /// Exact canonical Norito `SoraFsModerationBallotRevealV1` bytes.
        #[norito (json = "crate::json_helpers::base64_vec")]
        pub reveal_payload: Vec<u8>,
    }
}
impl crate::seal::Instruction for SubmitSorafsModerationReveal {}
isi! {
    /// Finalize a closed moderation case and atomically record outcome and no-shows.
    #[norito_schema(name = "iroha_data_model::isi::sorafs::FinalizeSorafsModerationCase")]
    pub struct FinalizeSorafsModerationCase {
        /// Moderation case identifier.
        pub case_id: String,
        /// Ballot round identifier.
        pub round_id: String,
    }
}
impl crate::seal::Instruction for FinalizeSorafsModerationCase {}
impl RegisterPinManifest {
    /// Create a new `RegisterPinManifest` instruction.
    #[must_use]
    pub fn new(
        manifest_payload: Vec<u8>,
        alias: Option<ManifestAliasBinding>,
        successor_of: Option<ManifestDigest>,
    ) -> Self {
        Self {
            manifest_payload,
            alias,
            successor_of,
        }
    }
}
impl ApprovePinManifest {
    /// Create a new `ApprovePinManifest` instruction.
    #[must_use]
    pub fn new(
        digest: ManifestDigest,
        council_envelope: Option<Vec<u8>>,
        council_envelope_digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            digest,
            council_envelope,
            council_envelope_digest,
        }
    }
}
impl RetirePinManifest {
    /// Create a new `RetirePinManifest` instruction.
    #[must_use]
    pub fn new(digest: ManifestDigest, reason: Option<String>) -> Self {
        Self { digest, reason }
    }
}
impl BindManifestAlias {
    /// Create a new `BindManifestAlias` instruction.
    #[must_use]
    pub fn new(
        digest: ManifestDigest,
        binding: ManifestAliasBinding,
        bound_epoch: u64,
        expiry_epoch: u64,
    ) -> Self {
        Self {
            digest,
            binding,
            bound_epoch,
            expiry_epoch,
        }
    }
}
impl RegisterCapacityDeclaration {
    /// Create a new `RegisterCapacityDeclaration` instruction.
    #[must_use]
    pub fn new(declaration: Vec<u8>) -> Self {
        Self { declaration }
    }
}
impl RecordCapacityTelemetry {
    /// Create a new `RecordCapacityTelemetry` instruction.
    #[must_use]
    pub fn new(record: CapacityTelemetryRecord) -> Self {
        Self { record }
    }
}
impl RegisterCapacityDispute {
    /// Create a new `RegisterCapacityDispute` instruction.
    #[must_use]
    pub fn new(record: CapacityDisputeRecord) -> Self {
        Self { record }
    }
}
impl IssueReplicationOrder {
    /// Create a new `IssueReplicationOrder` instruction.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        order_id: ReplicationOrderId,
        order_payload: Vec<u8>,
        issued_epoch: u64,
        deadline_epoch: u64,
    ) -> Self {
        Self {
            order_id,
            order_payload,
            issued_epoch,
            deadline_epoch,
            musubi_archive: None,
        }
    }
    /// Bind this order to one already-registered immutable Musubi archive.
    #[must_use]
    pub const fn for_musubi_archive(mut self, archive_id: ArchiveId) -> Self {
        self.musubi_archive = Some(archive_id);
        self
    }
}
impl CompleteReplicationOrder {
    /// Create a new `CompleteReplicationOrder` instruction.
    #[must_use]
    pub fn new(
        order_id: ReplicationOrderId,
        provider_id: ProviderId,
        completion_epoch: u64,
        expected_authority: ProviderIngestCompletionAuthorityV1,
        expected_assignment_revision: u64,
        finalized_anchor: ProviderIngestFinalizedAnchorV1,
    ) -> Self {
        Self {
            order_id,
            provider_id,
            completion_epoch,
            expected_authority,
            expected_assignment_revision,
            finalized_anchor,
        }
    }
}
impl ReviseReplicationOrderAssignments {
    /// Create an exact compare-and-set assignment revision.
    #[must_use]
    pub fn new(
        order_id: ReplicationOrderId,
        expected_assignment_revision: u64,
        next_assignment_revision: u64,
        assignments: Vec<ReplicationAssignmentV1>,
    ) -> Self {
        Self {
            order_id,
            expected_assignment_revision,
            next_assignment_revision,
            assignments,
        }
    }
}
impl ExpireReplicationOrder {
    /// Create a new `ExpireReplicationOrder` instruction.
    #[must_use]
    pub fn new(order_id: ReplicationOrderId, expiration_epoch: u64) -> Self {
        Self {
            order_id,
            expiration_epoch,
        }
    }
}
impl SetPricingSchedule {
    /// Create a new `SetPricingSchedule` instruction.
    #[must_use]
    pub fn new(schedule: PricingScheduleRecord) -> Self {
        Self { schedule }
    }
}
impl UpsertProviderCredit {
    /// Create a new `UpsertProviderCredit` instruction.
    #[must_use]
    pub fn new(
        expected_current: Option<HashOf<ProviderCreditRecord>>,
        record: ProviderCreditRecord,
    ) -> Self {
        Self {
            expected_current,
            record,
        }
    }
}
impl SetSorafsPopIssuerPolicy {
    /// Construct an issuer-policy activation instruction.
    #[must_use]
    pub fn new(policy: PopIssuerPolicyV1) -> Self {
        Self { policy }
    }
}
impl CommitSorafsPopCredentialBatch {
    /// Construct an atomic credential commitment batch instruction.
    #[must_use]
    pub fn new(batch_payload: Vec<u8>) -> Self {
        Self { batch_payload }
    }
}
impl PublishSorafsPopRevocationList {
    /// Construct a signed revocation publication instruction.
    #[must_use]
    pub fn new(revocation_list_payload: Vec<u8>, issuer_policy_digest: [u8; 32]) -> Self {
        Self {
            revocation_list_payload,
            issuer_policy_digest,
        }
    }
}
impl SetSorafsOrderbookPolicy {
    /// Construct a policy-activation instruction.
    #[must_use]
    pub fn new(policy: OrderbookAdmissionPolicyV1) -> Self {
        Self { policy }
    }
}
impl SubmitSorafsOrderbookOrder {
    /// Construct a signed order-submission instruction.
    #[must_use]
    pub fn new(order_payload: Vec<u8>, policy_digest: [u8; 32]) -> Self {
        Self {
            order_payload,
            policy_digest,
        }
    }
}
impl CancelSorafsOrderbookOrder {
    /// Construct a signed owner-cancellation instruction.
    #[must_use]
    pub fn new(cancel_payload: Vec<u8>, policy_digest: [u8; 32]) -> Self {
        Self {
            cancel_payload,
            policy_digest,
        }
    }
}
impl MatchSorafsOrderbook {
    /// Construct a bounded deterministic matching instruction.
    #[must_use]
    pub const fn new(policy_digest: [u8; 32], expected_book_revision: u64, max_fills: u32) -> Self {
        Self {
            policy_digest,
            expected_book_revision,
            max_fills,
        }
    }
}
impl MaintainSorafsOrderbook {
    /// Construct a bounded order/channel expiry instruction.
    #[must_use]
    pub const fn new(policy_digest: [u8; 32], expected_book_revision: u64, max_items: u32) -> Self {
        Self {
            policy_digest,
            expected_book_revision,
            max_items,
        }
    }
}
impl RecordSorafsOrderbookSettlementReceipt {
    /// Construct a signed funded-lock settlement and receipt instruction.
    #[must_use]
    pub fn new(receipt_payload: Vec<u8>, policy_digest: [u8; 32]) -> Self {
        Self {
            receipt_payload,
            policy_digest,
        }
    }
}
impl SetSorafsReservePolicy {
    /// Construct an authoritative reserve policy activation.
    #[must_use]
    pub fn new(policy: ReserveAuthorityPolicyV1) -> Self {
        Self { policy }
    }
}
impl RegisterSorafsReserveAccount {
    /// Construct a provider reserve-account registration.
    #[must_use]
    pub fn new(terms: ReserveProviderTermsV1, policy_digest: [u8; 32]) -> Self {
        Self {
            terms,
            policy_digest,
        }
    }
}
impl RequestSorafsReserveMovement {
    /// Construct a provider reserve movement request.
    #[must_use]
    pub fn new(
        movement_id: [u8; 32],
        provider_id: ProviderId,
        kind: ReserveMovementKindV1,
        amount: XorQuantity,
        expected_provider_revision: u64,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            movement_id,
            provider_id,
            kind,
            amount,
            expected_provider_revision,
            policy_digest,
        }
    }
}
impl DecideSorafsReserveMovement {
    /// Construct a terminal reserve movement decision.
    #[must_use]
    pub fn new(
        movement_id: [u8; 32],
        expected_provider_revision: u64,
        policy_digest: [u8; 32],
        approve: bool,
        rationale: String,
    ) -> Self {
        Self {
            movement_id,
            expected_provider_revision,
            policy_digest,
            approve,
            rationale,
        }
    }
}
impl ChargeSorafsReserveRent {
    /// Construct a deterministic reserve rent charge.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_provider_revision: u64,
        billing_periods: u16,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            provider_id,
            expected_provider_revision,
            billing_periods,
            policy_digest,
        }
    }
}
impl AdvanceSorafsReserveLifecycle {
    /// Construct a reserve lifecycle transition.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_provider_revision: u64,
        days_past_due: u16,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            provider_id,
            expected_provider_revision,
            days_past_due,
            policy_digest,
        }
    }
}
impl DrawSorafsReserveCredit {
    /// Construct a capped reserve-credit draw.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_provider_revision: u64,
        amount: XorQuantity,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            provider_id,
            expected_provider_revision,
            amount,
            policy_digest,
        }
    }
}
impl RepaySorafsReserveCredit {
    /// Construct a reserve-credit repayment.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_provider_revision: u64,
        amount: XorQuantity,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            provider_id,
            expected_provider_revision,
            amount,
            policy_digest,
        }
    }
}
impl SubmitSorafsReserveAppeal {
    /// Construct a provider reserve lifecycle appeal.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        appeal_id: [u8; 32],
        provider_id: ProviderId,
        expected_provider_revision: u64,
        requested_stage: ReserveLifecycleStage,
        reason: String,
        evidence_digest: Option<[u8; 32]>,
        policy_digest: [u8; 32],
    ) -> Self {
        Self {
            appeal_id,
            provider_id,
            expected_provider_revision,
            requested_stage,
            reason,
            evidence_digest,
            policy_digest,
        }
    }
}
impl DecideSorafsReserveAppeal {
    /// Construct a terminal reserve appeal decision.
    #[must_use]
    pub fn new(
        appeal_id: [u8; 32],
        expected_provider_revision: u64,
        policy_digest: [u8; 32],
        accept: bool,
        rationale: String,
    ) -> Self {
        Self {
            appeal_id,
            expected_provider_revision,
            policy_digest,
            accept,
            rationale,
        }
    }
}
impl SubmitSorafsRepairTask {
    /// Construct an exactly-once repair-task admission instruction.
    #[must_use]
    pub fn new(source_identity: [u8; 32], report_payload: Vec<u8>) -> Self {
        Self {
            source_identity,
            report_payload,
        }
    }
}
impl ApplySorafsRepairTaskAction {
    /// Construct a compare-and-set repair-task mutation.
    #[must_use]
    pub fn new(
        ticket_id: String,
        expected_revision: u64,
        action: SorafsRepairTaskActionV1,
    ) -> Self {
        Self {
            ticket_id,
            expected_revision,
            action,
        }
    }
}
impl SubmitSorafsRepairAppeal {
    /// Construct a provider-owner repair slash appeal.
    #[must_use]
    pub fn new(
        ticket_id: String,
        expected_revision: u64,
        evidence_digest: [u8; 32],
        reason: String,
        idempotency_key: String,
    ) -> Self {
        Self {
            ticket_id,
            expected_revision,
            evidence_digest,
            reason,
            idempotency_key,
        }
    }
}
impl SetSorafsProofOutcomeSignerPolicy {
    /// Construct a governed proof-signer policy activation.
    #[must_use]
    pub fn new(policy: ProofOutcomeSignerPolicyV1) -> Self {
        Self { policy }
    }
}
impl SubmitSorafsProofOutcome {
    /// Construct a canonical proof-outcome submission.
    #[must_use]
    pub fn new(submission: SorafsProofOutcomeSubmissionV1) -> Self {
        Self { submission }
    }
}
impl SetSorafsReputationJournalAuthorityPolicy {
    /// Construct a governed reputation recorder-policy activation.
    #[must_use]
    pub fn new(policy: ReputationJournalAuthorityPolicyV1) -> Self {
        Self { policy }
    }
}
impl AppendSorafsPorReputationJournalEntry {
    /// Construct a canonical `PoR` reputation-journal append.
    #[must_use]
    pub fn new(entry: ReputationJournalEntryV1) -> Self {
        Self { entry }
    }
}
impl AppendSorafsStreamTokenReputationJournalEntry {
    /// Construct a canonical stream-token reputation-journal append.
    #[must_use]
    pub fn new(entry: ReputationJournalEntryV1) -> Self {
        Self { entry }
    }
}
impl ResolveSorafsCapacityDispute {
    /// Construct a governed, predecessor-bound capacity-dispute resolution.
    #[must_use]
    pub fn new(
        dispute_id: CapacityDisputeId,
        expected_authority_policy_digest: [u8; 32],
        outcome: CapacityDisputeOutcome,
        decision_digest: [u8; 32],
        rationale: Option<String>,
    ) -> Self {
        Self {
            dispute_id,
            expected_authority_policy_digest,
            outcome,
            decision_digest,
            rationale,
        }
    }
}
impl SetSorafsModerationPolicy {
    /// Construct a moderation policy activation instruction.
    #[must_use]
    pub fn new(policy: ModerationLedgerPolicyV1) -> Self {
        Self { policy }
    }
}
impl SubmitSorafsModerationAppeal {
    /// Construct an appellant-authenticated appeal-intake instruction.
    #[must_use]
    pub fn new(intake: ModerationAppealIntakeV1) -> Self {
        Self { intake }
    }
}
impl RegisterSorafsModerationJurorEligibility {
    /// Construct a private `PoP` eligibility-proof submission.
    #[must_use]
    pub fn new(case_id: String, round_id: String, membership_proof_payload: Vec<u8>) -> Self {
        Self {
            case_id,
            round_id,
            membership_proof_payload,
        }
    }
}
impl FinalizeSorafsModerationSortition {
    /// Construct a deterministic sortition-finalization instruction.
    #[must_use]
    pub fn new(
        case_id: String,
        round_id: String,
        citizen_snapshot_digest: [u8; 32],
        randomness_anchor: [u8; 32],
        proposed_jurors: Vec<AccountId>,
        proposed_waitlist: Vec<AccountId>,
    ) -> Self {
        Self {
            case_id,
            round_id,
            citizen_snapshot_digest,
            randomness_anchor,
            proposed_jurors,
            proposed_waitlist,
        }
    }
}
impl AcceptSorafsModerationJurorAssignment {
    /// Construct an authority-bound assignment acceptance.
    #[must_use]
    pub fn new(case_id: String, round_id: String, sortition_digest: [u8; 32]) -> Self {
        Self {
            case_id,
            round_id,
            sortition_digest,
        }
    }
}
impl ActivateSorafsModerationCase {
    /// Construct a deterministic failover and ballot-activation instruction.
    #[must_use]
    pub fn new(case_id: String, round_id: String, sortition_digest: [u8; 32]) -> Self {
        Self {
            case_id,
            round_id,
            sortition_digest,
        }
    }
}
impl SubmitSorafsModerationCommit {
    /// Construct a canonical commitment submission.
    #[must_use]
    pub fn new(commit_payload: Vec<u8>) -> Self {
        Self { commit_payload }
    }
}
impl RaiseSorafsModerationChallenge {
    /// Construct a payload-free challenge submission.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        case_id: String,
        round_id: String,
        challenge_id: String,
        kind: ModerationChallengeKindV1,
        target_juror: Option<AccountId>,
        evidence_digest: [u8; 32],
        reason: String,
    ) -> Self {
        Self {
            case_id,
            round_id,
            challenge_id,
            kind,
            target_juror,
            evidence_digest,
            reason,
        }
    }
}
impl ResolveSorafsModerationChallenge {
    /// Construct a challenge-resolution instruction.
    #[must_use]
    pub fn new(
        case_id: String,
        round_id: String,
        challenge_id: String,
        decision: ModerationChallengeDecisionV1,
    ) -> Self {
        Self {
            case_id,
            round_id,
            challenge_id,
            decision,
        }
    }
}
impl SubmitSorafsModerationReveal {
    /// Construct a canonical reveal submission.
    #[must_use]
    pub fn new(reveal_payload: Vec<u8>) -> Self {
        Self { reveal_payload }
    }
}
impl FinalizeSorafsModerationCase {
    /// Construct a terminal case-finalization instruction.
    #[must_use]
    pub fn new(case_id: String, round_id: String) -> Self {
        Self { case_id, round_id }
    }
}
impl RegisterProviderOwner {
    /// Create a new `RegisterProviderOwner` instruction.
    #[must_use]
    pub fn new(provider_id: ProviderId, owner: AccountId) -> Self {
        Self { provider_id, owner }
    }
}
impl UnregisterProviderOwner {
    /// Create a new `UnregisterProviderOwner` instruction.
    #[must_use]
    pub fn new(provider_id: ProviderId) -> Self {
        Self { provider_id }
    }
}
impl SetProviderIngestCompletionAuthority {
    /// Create an exact compare-and-set provider completion authority update.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_current: Option<ProviderIngestCompletionAuthorityV1>,
        next: ProviderIngestCompletionAuthorityV1,
    ) -> Self {
        Self {
            provider_id,
            expected_current,
            next,
        }
    }
}
impl RevokeProviderIngestCompletionAuthority {
    /// Create an exact compare-and-remove provider completion authority revocation.
    #[must_use]
    pub fn new(
        provider_id: ProviderId,
        expected_current: ProviderIngestCompletionAuthorityV1,
    ) -> Self {
        Self {
            provider_id,
            expected_current,
        }
    }
}

impl_aos_decode_from_slice!(RegisterPinManifest {
    manifest_payload: Vec<u8>,
    alias: Option<ManifestAliasBinding>,
    successor_of: Option<ManifestDigest>,
});
impl_aos_decode_from_slice!(InitializeSorafsProviderAdmissionV1 {
    council: crate::sorafs::provider_admission::governance::InitialProviderAdmissionCouncilV1,
    providers: Vec<crate::sorafs::provider_admission::governance::InitialProviderAdmissionV1>,
});
impl_aos_decode_from_slice!(AssertSorafsPublicationV1 {
    manifest_digest: ManifestDigest,
    order_id: ReplicationOrderId,
    assignment_revision: u64,
    canonical_order_digest: [u8; 32],
    require_complete: bool,
    challenge: [u8; 32],
    minimum_height: u64,
    minimum_block_hash: [u8; 32],
});
impl_aos_decode_from_slice!(ApprovePinManifest {
    digest: ManifestDigest,
    council_envelope: Option<Vec<u8>>,
    council_envelope_digest: Option<[u8; 32]>,
});
impl_aos_decode_from_slice!(RetirePinManifest {
    digest: ManifestDigest,
    reason: Option<String>,
});
impl_aos_decode_from_slice!(BindManifestAlias {
    digest: ManifestDigest,
    binding: ManifestAliasBinding,
    bound_epoch: u64,
    expiry_epoch: u64,
});
impl_aos_decode_from_slice!(RegisterCapacityDeclaration {
    declaration: Vec<u8>,
});
impl_aos_decode_from_slice!(RecordCapacityTelemetry {
    record: CapacityTelemetryRecord,
});
impl_aos_decode_from_slice!(RegisterCapacityDispute {
    record: CapacityDisputeRecord,
});
impl_aos_decode_from_slice!(IssueReplicationOrder {
    order_id: ReplicationOrderId,
    order_payload: Vec<u8>,
    issued_epoch: u64,
    deadline_epoch: u64,
    musubi_archive: Option<ArchiveId>,
});
impl_aos_decode_from_slice!(CompleteReplicationOrder {
    order_id: ReplicationOrderId,
    provider_id: ProviderId,
    completion_epoch: u64,
    expected_authority: ProviderIngestCompletionAuthorityV1,
    expected_assignment_revision: u64,
    finalized_anchor: ProviderIngestFinalizedAnchorV1,
});
impl_aos_decode_from_slice!(ReviseReplicationOrderAssignments {
    order_id: ReplicationOrderId,
    expected_assignment_revision: u64,
    next_assignment_revision: u64,
    assignments: Vec<ReplicationAssignmentV1>,
});
impl_aos_decode_from_slice!(ExpireReplicationOrder {
    order_id: ReplicationOrderId,
    expiration_epoch: u64,
});
impl_aos_decode_from_slice!(RegisterProviderOwner {
    provider_id: ProviderId,
    owner: AccountId,
});
impl_aos_decode_from_slice!(UnregisterProviderOwner {
    provider_id: ProviderId,
});
impl_aos_decode_from_slice!(SetProviderIngestCompletionAuthority {
    provider_id: ProviderId,
    expected_current: Option<ProviderIngestCompletionAuthorityV1>,
    next: ProviderIngestCompletionAuthorityV1,
});
impl_aos_decode_from_slice!(RevokeProviderIngestCompletionAuthority {
    provider_id: ProviderId,
    expected_current: ProviderIngestCompletionAuthorityV1,
});
impl_aos_decode_from_slice!(SetPricingSchedule {
    schedule: PricingScheduleRecord,
});
impl_aos_decode_from_slice!(UpsertProviderCredit {
    expected_current: Option<HashOf<ProviderCreditRecord>>,
    record: ProviderCreditRecord,
});
impl_aos_decode_from_slice!(SetSorafsPopIssuerPolicy {
    policy: PopIssuerPolicyV1,
});
impl_aos_decode_from_slice!(CommitSorafsPopCredentialBatch {
    batch_payload: Vec<u8>,
});
impl_aos_decode_from_slice!(PublishSorafsPopRevocationList {
    revocation_list_payload: Vec<u8>,
    issuer_policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(SetSorafsOrderbookPolicy {
    policy: OrderbookAdmissionPolicyV1,
});
impl_aos_decode_from_slice!(SubmitSorafsOrderbookOrder {
    order_payload: Vec<u8>,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(CancelSorafsOrderbookOrder {
    cancel_payload: Vec<u8>,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(MatchSorafsOrderbook {
    policy_digest: [u8; 32],
    expected_book_revision: u64,
    max_fills: u32,
});
impl_aos_decode_from_slice!(MaintainSorafsOrderbook {
    policy_digest: [u8; 32],
    expected_book_revision: u64,
    max_items: u32,
});
impl_aos_decode_from_slice!(RecordSorafsOrderbookSettlementReceipt {
    receipt_payload: Vec<u8>,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(SetSorafsReservePolicy {
    policy: ReserveAuthorityPolicyV1,
});
impl_aos_decode_from_slice!(RegisterSorafsReserveAccount {
    terms: ReserveProviderTermsV1,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(RequestSorafsReserveMovement {
    movement_id: [u8; 32],
    provider_id: ProviderId,
    kind: ReserveMovementKindV1,
    amount: XorQuantity,
    expected_provider_revision: u64,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(DecideSorafsReserveMovement {
    movement_id: [u8; 32],
    expected_provider_revision: u64,
    policy_digest: [u8; 32],
    approve: bool,
    rationale: String,
});
impl_aos_decode_from_slice!(ChargeSorafsReserveRent {
    provider_id: ProviderId,
    expected_provider_revision: u64,
    billing_periods: u16,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(AdvanceSorafsReserveLifecycle {
    provider_id: ProviderId,
    expected_provider_revision: u64,
    days_past_due: u16,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(DrawSorafsReserveCredit {
    provider_id: ProviderId,
    expected_provider_revision: u64,
    amount: XorQuantity,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(RepaySorafsReserveCredit {
    provider_id: ProviderId,
    expected_provider_revision: u64,
    amount: XorQuantity,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(SubmitSorafsReserveAppeal {
    appeal_id: [u8; 32],
    provider_id: ProviderId,
    expected_provider_revision: u64,
    requested_stage: ReserveLifecycleStage,
    reason: String,
    evidence_digest: Option<[u8; 32]>,
    policy_digest: [u8; 32],
});
impl_aos_decode_from_slice!(DecideSorafsReserveAppeal {
    appeal_id: [u8; 32],
    expected_provider_revision: u64,
    policy_digest: [u8; 32],
    accept: bool,
    rationale: String,
});
impl_aos_decode_from_slice!(SubmitSorafsRepairTask {
    source_identity: [u8; 32],
    report_payload: Vec<u8>,
});
impl_aos_decode_from_slice!(ApplySorafsRepairTaskAction {
    ticket_id: String,
    expected_revision: u64,
    action: SorafsRepairTaskActionV1,
});
impl_aos_decode_from_slice!(SubmitSorafsRepairAppeal {
    ticket_id: String,
    expected_revision: u64,
    evidence_digest: [u8; 32],
    reason: String,
    idempotency_key: String,
});
impl_aos_decode_from_slice!(SetSorafsProofOutcomeSignerPolicy {
    policy: ProofOutcomeSignerPolicyV1,
});
impl_aos_decode_from_slice!(SubmitSorafsProofOutcome {
    submission: SorafsProofOutcomeSubmissionV1,
});
impl_aos_decode_from_slice!(SetSorafsReputationJournalAuthorityPolicy {
    policy: ReputationJournalAuthorityPolicyV1,
});
impl_aos_decode_from_slice!(AppendSorafsPorReputationJournalEntry {
    entry: ReputationJournalEntryV1,
});
impl_aos_decode_from_slice!(AppendSorafsStreamTokenReputationJournalEntry {
    entry: ReputationJournalEntryV1,
});
impl_aos_decode_from_slice!(ResolveSorafsCapacityDispute {
    dispute_id: CapacityDisputeId,
    expected_authority_policy_digest: [u8; 32],
    outcome: CapacityDisputeOutcome,
    decision_digest: [u8; 32],
    rationale: Option<String>,
});
impl_aos_decode_from_slice!(SetSorafsModerationPolicy {
    policy: ModerationLedgerPolicyV1,
});
impl_aos_decode_from_slice!(SubmitSorafsModerationAppeal {
    intake: ModerationAppealIntakeV1,
});
impl_aos_decode_from_slice!(RegisterSorafsModerationJurorEligibility {
    case_id: String,
    round_id: String,
    membership_proof_payload: Vec<u8>,
});
impl_aos_decode_from_slice!(FinalizeSorafsModerationSortition {
    case_id: String,
    round_id: String,
    citizen_snapshot_digest: [u8; 32],
    randomness_anchor: [u8; 32],
    proposed_jurors: Vec<AccountId>,
    proposed_waitlist: Vec<AccountId>,
});
impl_aos_decode_from_slice!(AcceptSorafsModerationJurorAssignment {
    case_id: String,
    round_id: String,
    sortition_digest: [u8; 32],
});
impl_aos_decode_from_slice!(ActivateSorafsModerationCase {
    case_id: String,
    round_id: String,
    sortition_digest: [u8; 32],
});
impl_aos_decode_from_slice!(SubmitSorafsModerationCommit {
    commit_payload: Vec<u8>,
});
impl_aos_decode_from_slice!(RaiseSorafsModerationChallenge {
    case_id: String,
    round_id: String,
    challenge_id: String,
    kind: ModerationChallengeKindV1,
    target_juror: Option<AccountId>,
    evidence_digest: [u8; 32],
    reason: String,
});
impl_aos_decode_from_slice!(ResolveSorafsModerationChallenge {
    case_id: String,
    round_id: String,
    challenge_id: String,
    decision: ModerationChallengeDecisionV1,
});
impl_aos_decode_from_slice!(ExpireSorafsModerationChallenge {
    case_id: String,
    round_id: String,
    challenge_id: String,
});
impl_aos_decode_from_slice!(SubmitSorafsModerationReveal {
    reveal_payload: Vec<u8>,
});
impl_aos_decode_from_slice!(FinalizeSorafsModerationCase {
    case_id: String,
    round_id: String,
});
#[cfg(test)]
mod tests {
    include!("sorafs/provider_credit_cas_tests.rs");
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use crate::sorafs::{
        capacity::{CapacityDisputeEvidence, CapacityDisputeId},
        reputation::{
            PorTerminalOutcomeV1, PorTerminalStatusV1, ReputationJournalPayloadV1,
            StreamTokenValidationBindingV1, StreamTokenValidationOutcomeV1,
            StreamTokenValidationStatusV1,
        },
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use norito::core::DecodeFromSlice;
    fn owner() -> AccountId {
        AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        )
    }
    fn digest(byte: u8) -> ManifestDigest {
        ManifestDigest::new([byte; 32])
    }
    fn provider(byte: u8) -> ProviderId {
        ProviderId::new([byte; 32])
    }
    #[test]
    fn provider_governance_actions_are_closed_canonical_and_compare_and_set() {
        let current = owner();
        let next = AccountId::new(
            "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
                .parse()
                .expect("replacement public key"),
        );
        let actions = [
            SorafsProviderGovernanceActionV1::Establish(EstablishSorafsProviderOwnerV1 {
                provider_id: provider(0x31),
                owner: current.clone(),
            }),
            SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                provider_id: provider(0x32),
                expected_owner: current.clone(),
                next_owner: next,
            }),
            SorafsProviderGovernanceActionV1::Remove(RemoveSorafsProviderOwnerV1 {
                provider_id: provider(0x33),
                expected_owner: current.clone(),
            }),
        ];
        for action in actions {
            action.validate().expect("valid governance action");
            let encoded = norito::codec::Encode::encode(&action);
            let decoded =
                <SorafsProviderGovernanceActionV1 as norito::codec::DecodeAll>::decode_all(
                    &mut encoded.as_slice(),
                )
                .expect("canonical action roundtrip");
            assert_eq!(decoded, action);
        }
        assert!(
            SorafsProviderGovernanceActionV1::Establish(EstablishSorafsProviderOwnerV1 {
                provider_id: ProviderId::default(),
                owner: current.clone(),
            })
            .validate()
            .is_err()
        );
        assert!(
            SorafsProviderGovernanceActionV1::Rebind(RebindSorafsProviderOwnerV1 {
                provider_id: provider(0x34),
                expected_owner: current.clone(),
                next_owner: current,
            })
            .validate()
            .is_err()
        );
    }
    fn xor_quantity_nanos(value: u128) -> Quantity {
        Quantity::from_canonical_numeric(Numeric::new(
            value,
            crate::sorafs::pricing::XOR_QUANTITY_SCALE,
        ))
        .expect("u128 nano-XOR SoraFS fixture fits Quantity")
    }
    fn order_id() -> ReplicationOrderId {
        ReplicationOrderId::new([0x44; 32])
    }
    fn alias() -> ManifestAliasBinding {
        ManifestAliasBinding {
            namespace: "sora".to_owned(),
            name: "docs".to_owned(),
            proof: vec![0xAA, 0xBB],
        }
    }
    fn capacity_declaration() -> crate::sorafs::capacity::CapacityDeclarationRecord {
        use crate::sorafs::capacity::CapacityDeclarationRecord;
        CapacityDeclarationRecord::new(
            provider(0x31),
            vec![0x01, 0x02, 0x03],
            512,
            10,
            12,
            120,
            Metadata::default(),
        )
    }
    fn capacity_telemetry() -> CapacityTelemetryRecord {
        CapacityTelemetryRecord::new(
            provider(0x32),
            20,
            21,
            512,
            500,
            480,
            4,
            3,
            9_999,
            9_998,
            1_024,
            5,
            1,
            2,
            0,
        )
        .with_nonce(7)
    }
    fn capacity_dispute() -> CapacityDisputeRecord {
        CapacityDisputeRecord::new_pending(
            CapacityDisputeId::new([0xD1; 32]),
            provider(0x33),
            [0xC1; 32],
            Some([0x44; 32]),
            1,
            30,
            "provider missed replication target".to_owned(),
            Some("replicate to replacement provider".to_owned()),
            CapacityDisputeEvidence {
                digest: [0xE1; 32],
                media_type: Some("application/norito".to_owned()),
                uri: Some("sorafs://evidence".to_owned()),
                size_bytes: Some(4096),
            },
            vec![0x99, 0x88],
        )
    }
    fn provider_credit() -> ProviderCreditRecord {
        ProviderCreditRecord::new(
            provider(0x34),
            xor_quantity_nanos(10_000),
            xor_quantity_nanos(20_000),
            xor_quantity_nanos(15_000),
            xor_quantity_nanos(1_000),
            100,
            200,
            Metadata::default(),
        )
    }
    fn provider_ingest_completion_authority() -> ProviderIngestCompletionAuthorityV1 {
        ProviderIngestCompletionAuthorityV1::new(
            owner().clone(),
            owner(),
            crate::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0x91; 32],
                revision: 1,
                predecessor_digest: None,
                policy_digest: [0x92; 32],
            },
        )
    }
    fn provider_ingest_finalized_anchor() -> ProviderIngestFinalizedAnchorV1 {
        ProviderIngestFinalizedAnchorV1 {
            height: 87,
            block_hash: [0x93; 32],
        }
    }
    fn replacement_assignments() -> Vec<ReplicationAssignmentV1> {
        vec![ReplicationAssignmentV1 {
            provider_id: [0x94; 32],
            slice_gib: 1,
            lane: None,
        }]
    }
    fn reputation_policy() -> ReputationJournalAuthorityPolicyV1 {
        ReputationJournalAuthorityPolicyV1 {
            version: crate::sorafs::reputation::REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: owner(),
            dispute_recorder_authority: owner(),
            token_recorder_authority: owner(),
            stream_token_delivery:
                crate::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 24 * 60 * 60 * 1_000,
        }
    }
    #[test]
    #[ignore = "explicit maintenance command prints the current reputation policy instruction frames"]
    fn print_reputation_policy_record_fixture_row() {
        // This is the current structural codec fixture, not a governed policy publication.
        let policy = reputation_policy();
        policy
            .validate()
            .expect("current reputation policy fixture");
        let row = crate::isi::generated_record_identity_tests::capture(
            SetSorafsReputationJournalAuthorityPolicy::new(policy),
        );
        println!(
            "REPUTATION_POLICY_FIXTURE_ROW={}",
            norito::json::to_json(&row).expect("current reputation policy instruction capture")
        );
    }

    fn por_reputation_entry() -> ReputationJournalEntryV1 {
        let policy = reputation_policy();
        ReputationJournalEntryV1::try_new(
            provider(0x39),
            policy.canonical_digest().expect("reputation policy digest"),
            owner(),
            1_700_000_001_700,
            None,
            ReputationJournalPayloadV1::PorTerminal(PorTerminalOutcomeV1 {
                challenge_id: [0x81; 32],
                manifest_digest: [0x82; 32],
                epoch_id: 9,
                drand_round: 11,
                forced: false,
                sample_count: 8,
                failed_samples: 0,
                issued_at_unix_ms: 1_700_000_000_000,
                deadline_at_unix_ms: 1_700_000_001_500,
                responded_at_unix_ms: Some(1_700_000_001_400),
                decided_at_unix_ms: 1_700_000_001_700,
                proof_digest: Some([0x83; 32]),
                repair_task_id: None,
                verifier_latency_ms: Some(7),
                status: PorTerminalStatusV1::Verified,
            }),
        )
        .expect("canonical PoR reputation entry")
    }
    fn token_reputation_entry() -> ReputationJournalEntryV1 {
        let policy = reputation_policy();
        ReputationJournalEntryV1::try_new(
            provider(0x3A),
            policy.canonical_digest().expect("reputation policy digest"),
            owner(),
            1_700_000_002_000,
            None,
            ReputationJournalPayloadV1::StreamTokenValidation(StreamTokenValidationOutcomeV1 {
                binding: StreamTokenValidationBindingV1 {
                    gateway_id: [0x84; 32],
                    gateway_sequence: 1,
                    request_context_digest: [0x85; 32],
                },
                token_body_digest: Some([0x86; 32]),
                token_key_version: Some(1),
                validated_at_unix_ms: 1_700_000_002_000,
                status: StreamTokenValidationStatusV1::Accepted,
            }),
        )
        .expect("canonical stream-token reputation entry")
    }
    fn orderbook_policy() -> OrderbookAdmissionPolicyV1 {
        OrderbookAdmissionPolicyV1 {
            version: crate::sorafs::orderbook::ORDERBOOK_ADMISSION_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            market_id: [0xA5; 32],
            matcher_authority: owner(),
            settlement_authority: owner(),
            paused: false,
            min_order_gib: 1,
            max_order_gib: 1_024,
            price_tick_micro_xor: 10,
            max_maker_fee_bps: 100,
            max_taker_fee_bps: 200,
            max_order_lifetime_secs: 86_400,
            max_receipt_age_secs: 3_600,
            max_clock_skew_secs: 30,
            max_receipt_bytes: 1 << 30,
            max_receipts_per_channel: 1_024,
        }
    }
    fn reserve_policy() -> ReserveAuthorityPolicyV1 {
        let domain = iroha_model_base::domain::DomainId::try_new("sora", "universal")
            .expect("reserve domain");
        ReserveAuthorityPolicyV1 {
            version: crate::sorafs::reserve::RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: crate::sorafs::reserve::ReservePolicyV1::default(),
            asset_definition: crate::asset::AssetDefinitionId::derive_from_components(
                domain,
                "xor".parse().expect("reserve asset name"),
            ),
            custody_account: owner(),
            treasury_account: AccountId::new(
                "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                    .parse()
                    .expect("treasury public key"),
            ),
            operations_authority: owner(),
            decision_authority: owner(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000)
                .expect("reserve debt cap"),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        }
    }
    #[test]
    fn reserve_policy_digest_commits_service_authorities() {
        let policy = reserve_policy();
        let baseline = policy.digest().expect("baseline reserve policy digest");
        let mut operations_rotated = policy.clone();
        operations_rotated.operations_authority = policy.treasury_account.clone();
        assert_ne!(
            operations_rotated
                .digest()
                .expect("operations-authority digest"),
            baseline
        );
        let mut decision_rotated = policy;
        decision_rotated.decision_authority = decision_rotated.treasury_account.clone();
        assert_ne!(
            decision_rotated
                .digest()
                .expect("decision-authority digest"),
            baseline
        );
    }
    fn reserve_terms() -> ReserveProviderTermsV1 {
        ReserveProviderTermsV1 {
            provider_id: provider(0x36),
            provider_account: owner(),
            tier: crate::sorafs::reserve::ReserveTier::TierA,
            storage_class: crate::sorafs::pin_registry::StorageClass::Hot,
            duration: crate::sorafs::reserve::ReserveDuration::Monthly,
            capacity_gib: 16,
        }
    }
    fn moderation_policy() -> ModerationLedgerPolicyV1 {
        ModerationLedgerPolicyV1 {
            version: crate::sorafs::moderation_ledger::MODERATION_LEDGER_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            challenge_voting_asset_id: crate::asset::AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("sora", "universal")
                    .expect("governance domain"),
                "xor".parse().expect("governance asset name"),
            ),
            challenge_bond_amount: Quantity::from(
                crate::sorafs::moderation_ledger::MODERATION_CHALLENGE_BOND_AMOUNT_V1,
            ),
            challenge_escrow_account: owner(),
            challenge_slash_receiver_account: owner(),
            challenge_rejected_slash_bps:
                crate::sorafs::moderation_ledger::MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
            challenge_resolution_grace_ms:
                crate::sorafs::moderation_ledger::MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
            max_panel_size: 5,
            max_candidate_pool_size: 32,
            max_waitlist_size: 5,
            max_exclusions_per_case: 16,
            max_total_window_ms: 90_000_000,
            max_challenges_per_case: 4,
            missing_commit_penalty_points: 10,
            unrevealed_commit_penalty_points: 20,
        }
    }
    fn proof_outcome_signer_policy() -> ProofOutcomeSignerPolicyV1 {
        ProofOutcomeSignerPolicyV1 {
            version: crate::sorafs::proof_ledger::PROOF_OUTCOME_SIGNER_POLICY_VERSION_V1,
            provider_id: provider(0x74),
            revision: 1,
            predecessor_digest: None,
            admission_envelope_digest: [0x75; 32],
            pdp_public_key: [0x76; 32],
            potr_mldsa_public_key: vec![0x77, 0x78],
            gateway_public_key: [0x79; 32],
            valid_from_unix: 1_000,
            valid_until_unix: 2_000,
        }
    }
    fn moderation_appeal_intake() -> ModerationAppealIntakeV1 {
        let appellant = owner();
        ModerationAppealIntakeV1 {
            version: crate::sorafs::moderation_ledger::MODERATION_APPEAL_INTAKE_VERSION_V1,
            case_id: "appeal-1".to_owned(),
            round_id: "round-1".to_owned(),
            appellant: appellant.clone(),
            appealed_decision_digest: [0x61; 32],
            proof_token_digest: [0x62; 32],
            evidence_bundle_digest: [0x63; 32],
            appeal_deposit_lock_digest: [0x64; 32],
            appeal_finance_config_version: "finance-v1".to_owned(),
            policy_reference: "policy-v1".to_owned(),
            evidence_uri: None,
            panel_size: 1,
            waitlist_size: 1,
            quorum: 1,
            exclusions: vec![appellant],
            registration_deadline_unix_ms: 1_000,
            acceptance_deadline_unix_ms: 2_000,
            commit_deadline_unix_ms: 3_000,
            challenge_submission_deadline_unix_ms: 4_000,
            challenge_resolution_deadline_unix_ms: 4_000
                + crate::sorafs::moderation_ledger::MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
            reveal_deadline_unix_ms: 4_001
                + crate::sorafs::moderation_ledger::MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
            policy_digest: moderation_policy().digest().expect("policy digest"),
        }
    }
    #[test]
    fn issue_replication_order_rejects_the_pre_binding_wire_layout() {
        #[derive(Encode)]
        struct PreBindingIssueReplicationOrder {
            order_id: ReplicationOrderId,
            order_payload: Vec<u8>,
            issued_epoch: u64,
            deadline_epoch: u64,
        }
        let retired = PreBindingIssueReplicationOrder {
            order_id: order_id(),
            order_payload: vec![0x01, 0x02, 0x03],
            issued_epoch: 70,
            deadline_epoch: 90,
        }
        .encode();
        assert!(
            IssueReplicationOrder::decode_from_slice(&retired).is_err(),
            "the four-field pre-binding wire must be regenerated, not defaulted"
        );
    }

    #[test]
    fn register_pin_manifest_json_roundtrip() {
        let manifest = RegisterPinManifest::new(vec![1, 2, 3], None, None);
        let value = norito::json::to_value(&manifest).expect("register pin manifest json");
        let decoded: RegisterPinManifest =
            norito::json::from_value(value).expect("register pin manifest decode");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn proof_outcome_submission_json_is_tagged_exact_and_fail_closed() {
        let pdp = SorafsProofOutcomeSubmissionV1::Pdp(SorafsPdpProofOutcomeSubmissionV1 {
            archive_payload: vec![0, 1, 2],
        });
        let expected_pdp: norito::json::Value =
            norito::json::from_str(r#"{"proof_kind":"pdp","value":{"archive_payload":"AAEC"}}"#)
                .expect("valid expected PDP JSON");
        assert_eq!(
            norito::json::to_value(&pdp).expect("encode PDP submission"),
            expected_pdp
        );
        assert_eq!(
            norito::json::from_value::<SorafsProofOutcomeSubmissionV1>(expected_pdp)
                .expect("decode PDP submission"),
            pdp
        );
        let potr = SorafsProofOutcomeSubmissionV1::Potr(SorafsPotrProofOutcomeSubmissionV1 {
            receipt_payload: vec![4, 5],
            admission_envelope_digest: [7; 32],
        });
        let expected_potr: norito::json::Value = norito::json::from_str(&format!(
            r#"{{"proof_kind":"potr","value":{{"receipt_payload":"BAU=","admission_envelope_digest":[{}]}}}}"#,
            std::iter::repeat_n("7", 32).collect::<Vec<_>>().join(",")
        ))
        .expect("valid expected PoTR JSON");
        assert_eq!(
            norito::json::to_value(&potr).expect("encode PoTR submission"),
            expected_potr
        );
        assert_eq!(
            norito::json::from_value::<SorafsProofOutcomeSubmissionV1>(expected_potr)
                .expect("decode PoTR submission"),
            potr
        );
        assert_eq!(
            <SorafsProofOutcomeSubmissionV1 as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::isi::sorafs::SorafsProofOutcomeSubmissionV1"
        );
        for value in [&pdp, &potr] {
            let bytes = norito::encode_canonical(value).expect("shared submission owner");
            assert_eq!(
                bytes[6..22],
                norito::schema::identity::frame_hash::<SorafsProofOutcomeSubmissionV1>()
            );
            let restored: SorafsProofOutcomeSubmissionV1 =
                norito::decode_canonical(&bytes).expect("submission roundtrip");
            assert_eq!(&restored, value);
            let mut wrong_owner = bytes.clone();
            wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<
                SubmitSorafsProofOutcome,
            >());
            assert!(matches!(
                norito::decode_canonical::<SorafsProofOutcomeSubmissionV1>(&wrong_owner),
                Err(norito::Error::SchemaMismatch)
            ));
            assert!(
                norito::decode_canonical::<SorafsProofOutcomeSubmissionV1>(
                    &bytes[..bytes.len() - 1]
                )
                .is_err()
            );
        }
        for malformed in [
            r#"{"proof_kind":"unknown","value":{"archive_payload":"AAEC"}}"#,
            r#"{"proof_kind":"pdp","value":{"archive_payload":"***"}}"#,
            r#"{"proof_kind":"potr","value":{"receipt_payload":"BAU="}}"#,
            r#"{"proof_kind":"potr","value":{"receipt_payload":"BAU=","admission_envelope_digest":[7]}}"#,
            r#"{"proof_kind":"pdp","value":{"archive_payload":"AAEC","receipt_payload":"BAU="}}"#,
            r#"{"proof_kind":"pdp","proof_kind":"potr","value":{"archive_payload":"AAEC"}}"#,
            r#"{"proof_kind":"pdp","value":{"archive_payload":"AAEC","archive_payload":"AAEC"}}"#,
        ] {
            assert!(
                norito::json::from_str::<SorafsProofOutcomeSubmissionV1>(malformed).is_err(),
                "malformed proof-outcome JSON must fail closed: {malformed}"
            );
        }
    }
    #[test]
    fn proof_outcome_submission_schema_references_explicit_payloads() {
        use core::any::TypeId;
        use iroha_schema::{IntoSchema as _, Metadata};
        let schema = SorafsProofOutcomeSubmissionV1::schema();
        let Metadata::Enum(metadata) = schema
            .get::<SorafsProofOutcomeSubmissionV1>()
            .expect("proof-outcome enum schema")
        else {
            panic!("proof-outcome schema must be an enum");
        };
        assert_eq!(metadata.variants.len(), 2);
        assert_eq!(metadata.variants[0].tag, "pdp");
        assert_eq!(metadata.variants[0].discriminant, 0);
        assert_eq!(
            metadata.variants[0].ty,
            Some(TypeId::of::<SorafsPdpProofOutcomeSubmissionV1>())
        );
        assert_eq!(metadata.variants[1].tag, "potr");
        assert_eq!(metadata.variants[1].discriminant, 1);
        assert_eq!(
            metadata.variants[1].ty,
            Some(TypeId::of::<SorafsPotrProofOutcomeSubmissionV1>())
        );
        assert!(schema.contains_key::<SorafsPdpProofOutcomeSubmissionV1>());
        assert!(schema.contains_key::<SorafsPotrProofOutcomeSubmissionV1>());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn sorafs_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterPinManifest::new(
            vec![0x01, 0x02, 0x03],
            Some(alias()),
            Some(digest(0x10)),
        ));
        assert_slice_roundtrip(ApprovePinManifest::new(
            digest(0x11),
            Some(vec![0xCA, 0xFE]),
            Some([0x23; 32]),
        ));
        assert_slice_roundtrip(RetirePinManifest::new(
            digest(0x11),
            Some("superseded".to_owned()),
        ));
        assert_slice_roundtrip(BindManifestAlias::new(digest(0x11), alias(), 65, 365));
        assert_slice_roundtrip(RegisterCapacityDeclaration::new(
            capacity_declaration().declaration,
        ));
        assert_slice_roundtrip(RecordCapacityTelemetry::new(capacity_telemetry()));
        assert_slice_roundtrip(RegisterCapacityDispute::new(capacity_dispute()));
        assert_slice_roundtrip(IssueReplicationOrder::new(
            order_id(),
            vec![0x01, 0x02, 0x03],
            70,
            90,
        ));
        assert_slice_roundtrip(
            IssueReplicationOrder::new(order_id(), vec![0x04, 0x05], 70, 90)
                .for_musubi_archive(ArchiveId::new([0xA5; 32])),
        );
        assert_slice_roundtrip(CompleteReplicationOrder::new(
            order_id(),
            provider(0x35),
            88,
            provider_ingest_completion_authority(),
            1,
            provider_ingest_finalized_anchor(),
        ));
        assert_slice_roundtrip(ReviseReplicationOrderAssignments::new(
            order_id(),
            1,
            2,
            replacement_assignments(),
        ));
        assert_slice_roundtrip(ExpireReplicationOrder::new(order_id(), 91));
        assert_slice_roundtrip(RegisterProviderOwner::new(provider(0x35), owner()));
        assert_slice_roundtrip(UnregisterProviderOwner::new(provider(0x35)));
        assert_slice_roundtrip(SetProviderIngestCompletionAuthority::new(
            provider(0x35),
            None,
            provider_ingest_completion_authority(),
        ));
        assert_slice_roundtrip(RevokeProviderIngestCompletionAuthority::new(
            provider(0x35),
            provider_ingest_completion_authority(),
        ));
        assert_slice_roundtrip(SetPricingSchedule::new(
            PricingScheduleRecord::launch_default(),
        ));
        assert_slice_roundtrip(UpsertProviderCredit::new(None, provider_credit()));
        assert_slice_roundtrip(UpsertProviderCredit::new(
            Some(HashOf::new(&provider_credit())),
            provider_credit(),
        ));
        assert_slice_roundtrip(SetSorafsOrderbookPolicy::new(orderbook_policy()));
        assert_slice_roundtrip(SubmitSorafsOrderbookOrder::new(
            vec![0x01, 0x02],
            [0x51; 32],
        ));
        assert_slice_roundtrip(CancelSorafsOrderbookOrder::new(
            vec![0x03, 0x04],
            [0x52; 32],
        ));
        assert_slice_roundtrip(MatchSorafsOrderbook::new([0x53; 32], 7, 16));
        assert_slice_roundtrip(MaintainSorafsOrderbook::new([0x54; 32], 8, 32));
        assert_slice_roundtrip(RecordSorafsOrderbookSettlementReceipt::new(
            vec![0x05, 0x06],
            [0x55; 32],
        ));
        assert_slice_roundtrip(SetSorafsReservePolicy::new(reserve_policy()));
        assert_slice_roundtrip(RegisterSorafsReserveAccount::new(
            reserve_terms(),
            [0x56; 32],
        ));
        assert_slice_roundtrip(RequestSorafsReserveMovement::new(
            [0x57; 32],
            provider(0x36),
            ReserveMovementKindV1::TopUp,
            XorQuantity::try_from_micro(10_000_000).expect("movement amount"),
            1,
            [0x56; 32],
        ));
        assert_slice_roundtrip(DecideSorafsReserveMovement::new(
            [0x57; 32],
            2,
            [0x56; 32],
            true,
            "approved".to_owned(),
        ));
        assert_slice_roundtrip(ChargeSorafsReserveRent::new(
            provider(0x36),
            2,
            1,
            [0x56; 32],
        ));
        assert_slice_roundtrip(AdvanceSorafsReserveLifecycle::new(
            provider(0x36),
            3,
            8,
            [0x56; 32],
        ));
        assert_slice_roundtrip(DrawSorafsReserveCredit::new(
            provider(0x36),
            4,
            XorQuantity::try_from_micro(5_000_000).expect("credit amount"),
            [0x56; 32],
        ));
        assert_slice_roundtrip(RepaySorafsReserveCredit::new(
            provider(0x36),
            5,
            XorQuantity::try_from_micro(1_000_000).expect("repayment amount"),
            [0x56; 32],
        ));
        assert_slice_roundtrip(SubmitSorafsReserveAppeal::new(
            [0x58; 32],
            provider(0x36),
            6,
            ReserveLifecycleStage::Warning,
            "review delinquency evidence".to_owned(),
            Some([0x59; 32]),
            [0x56; 32],
        ));
        assert_slice_roundtrip(DecideSorafsReserveAppeal::new(
            [0x58; 32],
            7,
            [0x56; 32],
            false,
            "evidence insufficient".to_owned(),
        ));
        assert_slice_roundtrip(SubmitSorafsRepairTask::new([0x70; 32], vec![0x01, 0x02]));
        for action in [
            SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                lease_duration_ms: 1_000,
                idempotency_key: "claim-1".to_owned(),
            }),
            SorafsRepairTaskActionV1::Renew(SorafsRepairRenewV1 {
                lease_generation: 1,
                lease_duration_ms: 2_000,
                idempotency_key: "renew-1".to_owned(),
            }),
            SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                lease_generation: 1,
                evidence_digest: [0x71; 32],
                idempotency_key: "complete-1".to_owned(),
            }),
            SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                lease_generation: 1,
                failure_digest: [0x72; 32],
                idempotency_key: "fail-1".to_owned(),
            }),
            SorafsRepairTaskActionV1::Escalate(SorafsRepairEscalateV1 {
                lease_generation: 1,
                slash_proposal_payload: vec![0x03, 0x04],
                idempotency_key: "escalate-1".to_owned(),
            }),
        ] {
            assert_slice_roundtrip(ApplySorafsRepairTaskAction::new(
                "REP-1".to_owned(),
                1,
                action,
            ));
        }
        assert_slice_roundtrip(SubmitSorafsRepairAppeal::new(
            "REP-1".to_owned(),
            3,
            [0x73; 32],
            "provider evidence".to_owned(),
            "appeal-1".to_owned(),
        ));
        assert_slice_roundtrip(SetSorafsProofOutcomeSignerPolicy::new(
            proof_outcome_signer_policy(),
        ));
        assert_slice_roundtrip(SubmitSorafsProofOutcome::new(
            SorafsProofOutcomeSubmissionV1::Pdp(SorafsPdpProofOutcomeSubmissionV1 {
                archive_payload: vec![0x74, 0x75],
            }),
        ));
        assert_slice_roundtrip(SubmitSorafsProofOutcome::new(
            SorafsProofOutcomeSubmissionV1::Potr(SorafsPotrProofOutcomeSubmissionV1 {
                receipt_payload: vec![0x76, 0x77],
                admission_envelope_digest: [0x78; 32],
            }),
        ));
        assert_slice_roundtrip(SetSorafsReputationJournalAuthorityPolicy::new(
            reputation_policy(),
        ));
        assert_slice_roundtrip(AppendSorafsPorReputationJournalEntry::new(
            por_reputation_entry(),
        ));
        assert_slice_roundtrip(AppendSorafsStreamTokenReputationJournalEntry::new(
            token_reputation_entry(),
        ));
        assert_slice_roundtrip(ResolveSorafsCapacityDispute::new(
            CapacityDisputeId::new([0xD1; 32]),
            reputation_policy()
                .canonical_digest()
                .expect("reputation policy digest"),
            CapacityDisputeOutcome::Upheld,
            [0x87; 32],
            Some("governance decision".to_owned()),
        ));
        assert_slice_roundtrip(SetSorafsModerationPolicy::new(moderation_policy()));
        assert_slice_roundtrip(SubmitSorafsModerationAppeal::new(moderation_appeal_intake()));
        let finalize_sortition = FinalizeSorafsModerationSortition::new(
            "appeal-1".to_owned(),
            "round-1".to_owned(),
            [0x65; 32],
            [0x64; 32],
            vec![owner()],
            Vec::new(),
        );
        assert_eq!(finalize_sortition.citizen_snapshot_digest, [0x65; 32]);
        assert_eq!(finalize_sortition.randomness_anchor, [0x64; 32]);
        assert_slice_roundtrip(finalize_sortition);
        assert_slice_roundtrip(AcceptSorafsModerationJurorAssignment::new(
            "appeal-1".to_owned(),
            "round-1".to_owned(),
            [0x66; 32],
        ));
        assert_slice_roundtrip(ActivateSorafsModerationCase::new(
            "appeal-1".to_owned(),
            "round-1".to_owned(),
            [0x66; 32],
        ));
        assert_slice_roundtrip(SubmitSorafsModerationCommit::new(vec![0x07, 0x08]));
        assert_slice_roundtrip(RaiseSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-1".to_owned(),
            ModerationChallengeKindV1::EvidenceMismatch,
            None,
            [0x61; 32],
            "evidence mismatch".to_owned(),
        ));
        assert_slice_roundtrip(ResolveSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-1".to_owned(),
            ModerationChallengeDecisionV1::Rejected,
        ));
        assert_slice_roundtrip(ExpireSorafsModerationChallenge {
            case_id: "case-1".to_owned(),
            round_id: "round-1".to_owned(),
            challenge_id: "challenge-1".to_owned(),
        });
        assert_slice_roundtrip(SubmitSorafsModerationReveal::new(vec![0x09, 0x0A]));
        assert_slice_roundtrip(FinalizeSorafsModerationCase::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
        ));
    }
    #[test]
    fn sorafs_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::registry::default();
        assert_registry_decodes(
            &registry,
            RegisterPinManifest::new(vec![0x01, 0x02, 0x03], Some(alias()), Some(digest(0x10))),
        );
        assert_registry_decodes(
            &registry,
            ApprovePinManifest::new(digest(0x11), Some(vec![0xCA, 0xFE]), Some([0x23; 32])),
        );
        assert_registry_decodes(
            &registry,
            RetirePinManifest::new(digest(0x11), Some("superseded".to_owned())),
        );
        assert_registry_decodes(
            &registry,
            BindManifestAlias::new(digest(0x11), alias(), 65, 365),
        );
        assert_registry_decodes(
            &registry,
            RegisterCapacityDeclaration::new(capacity_declaration().declaration),
        );
        assert_registry_decodes(
            &registry,
            RecordCapacityTelemetry::new(capacity_telemetry()),
        );
        assert_registry_decodes(&registry, RegisterCapacityDispute::new(capacity_dispute()));
        assert_registry_decodes(
            &registry,
            IssueReplicationOrder::new(order_id(), vec![0x01, 0x02, 0x03], 70, 90),
        );
        assert_registry_decodes(
            &registry,
            CompleteReplicationOrder::new(
                order_id(),
                provider(0x35),
                88,
                provider_ingest_completion_authority(),
                1,
                provider_ingest_finalized_anchor(),
            ),
        );
        assert_registry_decodes(
            &registry,
            ReviseReplicationOrderAssignments::new(order_id(), 1, 2, replacement_assignments()),
        );
        assert_registry_decodes(&registry, ExpireReplicationOrder::new(order_id(), 91));
        assert_registry_decodes(
            &registry,
            RegisterProviderOwner::new(provider(0x35), owner()),
        );
        assert_registry_decodes(&registry, UnregisterProviderOwner::new(provider(0x35)));
        assert_registry_decodes(
            &registry,
            SetProviderIngestCompletionAuthority::new(
                provider(0x35),
                None,
                provider_ingest_completion_authority(),
            ),
        );
        assert_registry_decodes(
            &registry,
            RevokeProviderIngestCompletionAuthority::new(
                provider(0x35),
                provider_ingest_completion_authority(),
            ),
        );
        assert_registry_decodes(&registry, SetSorafsOrderbookPolicy::new(orderbook_policy()));
        assert_registry_decodes(
            &registry,
            SubmitSorafsOrderbookOrder::new(vec![0x01, 0x02], [0x51; 32]),
        );
        assert_registry_decodes(
            &registry,
            CancelSorafsOrderbookOrder::new(vec![0x03, 0x04], [0x52; 32]),
        );
        assert_registry_decodes(&registry, MatchSorafsOrderbook::new([0x53; 32], 7, 16));
        assert_registry_decodes(&registry, MaintainSorafsOrderbook::new([0x54; 32], 8, 32));
        assert_registry_decodes(
            &registry,
            RecordSorafsOrderbookSettlementReceipt::new(vec![0x05, 0x06], [0x55; 32]),
        );
        assert_registry_decodes(&registry, SetSorafsReservePolicy::new(reserve_policy()));
        assert_registry_decodes(
            &registry,
            RegisterSorafsReserveAccount::new(reserve_terms(), [0x56; 32]),
        );
        assert_registry_decodes(
            &registry,
            RequestSorafsReserveMovement::new(
                [0x57; 32],
                provider(0x36),
                ReserveMovementKindV1::TopUp,
                XorQuantity::try_from_micro(10_000_000).expect("movement amount"),
                1,
                [0x56; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            DecideSorafsReserveMovement::new(
                [0x57; 32],
                2,
                [0x56; 32],
                true,
                "approved".to_owned(),
            ),
        );
        assert_registry_decodes(
            &registry,
            ChargeSorafsReserveRent::new(provider(0x36), 2, 1, [0x56; 32]),
        );
        assert_registry_decodes(
            &registry,
            AdvanceSorafsReserveLifecycle::new(provider(0x36), 3, 8, [0x56; 32]),
        );
        assert_registry_decodes(
            &registry,
            DrawSorafsReserveCredit::new(
                provider(0x36),
                4,
                XorQuantity::try_from_micro(5_000_000).expect("credit amount"),
                [0x56; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            RepaySorafsReserveCredit::new(
                provider(0x36),
                5,
                XorQuantity::try_from_micro(1_000_000).expect("repayment amount"),
                [0x56; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsReserveAppeal::new(
                [0x58; 32],
                provider(0x36),
                6,
                ReserveLifecycleStage::Warning,
                "review delinquency evidence".to_owned(),
                Some([0x59; 32]),
                [0x56; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            DecideSorafsReserveAppeal::new(
                [0x58; 32],
                7,
                [0x56; 32],
                false,
                "evidence insufficient".to_owned(),
            ),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsRepairTask::new([0x70; 32], vec![0x01, 0x02]),
        );
        assert_registry_decodes(
            &registry,
            ApplySorafsRepairTaskAction::new(
                "REP-1".to_owned(),
                1,
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: 1_000,
                    idempotency_key: "claim-1".to_owned(),
                }),
            ),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsRepairAppeal::new(
                "REP-1".to_owned(),
                3,
                [0x73; 32],
                "provider evidence".to_owned(),
                "appeal-1".to_owned(),
            ),
        );
        assert_registry_decodes(
            &registry,
            SetSorafsProofOutcomeSignerPolicy::new(proof_outcome_signer_policy()),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Pdp(
                SorafsPdpProofOutcomeSubmissionV1 {
                    archive_payload: vec![0x74, 0x75],
                },
            )),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Potr(
                SorafsPotrProofOutcomeSubmissionV1 {
                    receipt_payload: vec![0x76, 0x77],
                    admission_envelope_digest: [0x78; 32],
                },
            )),
        );
        assert_registry_decodes(
            &registry,
            SetSorafsReputationJournalAuthorityPolicy::new(reputation_policy()),
        );
        assert_registry_decodes(
            &registry,
            AppendSorafsPorReputationJournalEntry::new(por_reputation_entry()),
        );
        assert_registry_decodes(
            &registry,
            AppendSorafsStreamTokenReputationJournalEntry::new(token_reputation_entry()),
        );
        assert_registry_decodes(
            &registry,
            ResolveSorafsCapacityDispute::new(
                CapacityDisputeId::new([0xD1; 32]),
                reputation_policy()
                    .canonical_digest()
                    .expect("reputation policy digest"),
                CapacityDisputeOutcome::Upheld,
                [0x87; 32],
                Some("governance decision".to_owned()),
            ),
        );
        assert_registry_decodes(
            &registry,
            SetSorafsModerationPolicy::new(moderation_policy()),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsModerationAppeal::new(moderation_appeal_intake()),
        );
        assert_registry_decodes(
            &registry,
            FinalizeSorafsModerationSortition::new(
                "appeal-1".to_owned(),
                "round-1".to_owned(),
                [0x65; 32],
                [0x64; 32],
                vec![owner()],
                Vec::new(),
            ),
        );
        assert_registry_decodes(
            &registry,
            AcceptSorafsModerationJurorAssignment::new(
                "appeal-1".to_owned(),
                "round-1".to_owned(),
                [0x66; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            ActivateSorafsModerationCase::new(
                "appeal-1".to_owned(),
                "round-1".to_owned(),
                [0x66; 32],
            ),
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsModerationCommit::new(vec![0x07, 0x08]),
        );
        assert_registry_decodes(
            &registry,
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x61; 32],
                "evidence mismatch".to_owned(),
            ),
        );
        assert_registry_decodes(
            &registry,
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            ),
        );
        assert_registry_decodes(
            &registry,
            ExpireSorafsModerationChallenge {
                case_id: "case-1".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-1".to_owned(),
            },
        );
        assert_registry_decodes(
            &registry,
            SubmitSorafsModerationReveal::new(vec![0x09, 0x0A]),
        );
        assert_registry_decodes(
            &registry,
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned()),
        );
    }
    #[test]
    fn proof_outcome_submission_frame_roundtrips_both_variants_and_rejects_instruction_root() {
        for submission in [
            SorafsProofOutcomeSubmissionV1::Pdp(SorafsPdpProofOutcomeSubmissionV1 {
                archive_payload: vec![0, 1, 2],
            }),
            SorafsProofOutcomeSubmissionV1::Potr(SorafsPotrProofOutcomeSubmissionV1 {
                receipt_payload: vec![4, 5],
                admission_envelope_digest: [7; 32],
            }),
        ] {
            let bytes = norito::encode_canonical(&submission).unwrap();
            let header = norito::core::Header::read(bytes.as_slice()).unwrap();
            assert_eq!(
                header.schema,
                norito::core::schema_hash_for_name(
                    "iroha_data_model::isi::sorafs::SorafsProofOutcomeSubmissionV1"
                )
            );
            let decoded: SorafsProofOutcomeSubmissionV1 = norito::decode_canonical(&bytes).unwrap();
            assert_eq!(decoded, submission);
            assert_eq!(norito::encode_canonical(&decoded).unwrap(), bytes);
            let instruction = SubmitSorafsProofOutcome::new(submission);
            let foreign = norito::encode_canonical(&instruction).unwrap();
            assert_eq!(
                norito::decode_canonical::<SubmitSorafsProofOutcome>(&foreign).unwrap(),
                instruction
            );
            assert!(matches!(
                norito::decode_canonical::<SorafsProofOutcomeSubmissionV1>(&foreign),
                Err(norito::Error::SchemaMismatch)
            ));
        }
    }
}

include!("sorafs/stream_token_custody.rs");
include!("sorafs/stream_token_authority.rs");
include!("sorafs/stream_token_gateway.rs");
include!("sorafs/final_promotion_authority.rs");
include!("sorafs/final_promotion_account_custody.rs");
include!("sorafs/release_manifest_authority.rs");
include!("sorafs/topology_authority.rs");
