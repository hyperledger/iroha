//! Finalized native fee receipts, custody snapshots, allocations and claims.
mod statement;
/// Fixed ordinary-write key for the complete per-block fee evidence root.
pub use crate::execution_witness::FEE_EVIDENCE_WITNESS_KEY_V1;
use crate::{
    validation_fee::{RetailFeeReceiptV1, ValidationFeeTreasuryPayoutBindingV1},
    validation_fee_rewards::{
        ValidationFeeConversionAttempt, ValidationFeeExposurePage, ValidationFeeRewardAllocation,
        ValidationFeeRewardBeneficiaryAlias, ValidationFeeRewardBeneficiaryRevision,
        ValidationFeeRewardClaim, ValidationFeeRewardEntitlement, ValidationFeeRewardsState,
        ValidationFeeServiceSnapshot,
    },
};
use iroha_crypto::{Hash, HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment};
use iroha_model_base::state_path::StatePath;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
pub use statement::{
    MAX_RETAIL_FEE_RECEIPT_PAGE_BYTES_V1, MAX_RETAIL_FEE_RECEIPT_PAGE_COUNT_V1,
    RetailFeeCurrentHeadProofV1, RetailFeeReceiptCursorV1, RetailFeeReceiptPageV1,
    retail_fee_head_leaf_hash_v1, retail_fee_head_node_hash_v1, retail_fee_head_path_v1,
};
use std::num::NonZeroU64;
/// Maximum bounded records retained in one native fee sidecar.
pub const MAX_FEE_EVIDENCE_RECORDS_V1: u32 = 4_096;
/// Maximum canonical framed bytes in one complete native fee proof.
pub const MAX_FEE_EVIDENCE_BLOCK_BYTES_V1: usize = 8 * 1024 * 1024;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeRewardCustodySnapshotV1")]
/// Exact post-block custody state and its independently governed binding.
pub struct FeeRewardCustodySnapshotV1 {
    /// Calendar-effective Parliament binding.
    pub binding: ValidationFeeTreasuryPayoutBindingV1,
    /// Protected native balances, claims, and historical service counters.
    pub state: ValidationFeeRewardsState,
    /// Actual protected SBD treasury balance in cents, including unrelated deposits.
    pub treasury_sbd_minor: u128,
    /// Actual XOR reward custody balance in native minor units.
    pub reward_pool_xor_minor: u128,
    /// Fixed XOR definition scale authenticated in the native custody snapshot.
    pub xor_scale: u32,
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidencePayloadV1")]
#[norito(tag = "kind", content = "value")]
/// Native-only accounting record committed to block finality.
pub enum FeeEvidencePayloadV1 {
    /// Customer maintenance or positive/included payment receipt.
    RetailReceipt(RetailFeeReceiptV1),
    /// Native changed wallet cursor, including enrollment and recovery.
    RetailReceiptHead(crate::validation_fee::RetailFeeReceiptHeadV1),
    /// End-of-block native reward accounting state.
    RewardCustody(FeeRewardCustodySnapshotV1),
    /// Historical source service-key snapshot read independently of its allocation.
    RewardService(ValidationFeeServiceSnapshot),
    /// Immutable conversion allocation, including original oracle evidence.
    RewardAllocation(ValidationFeeRewardAllocation),
    /// Original funded allocation reattached as a source without new funding.
    RewardAllocationSource(ValidationFeeRewardAllocation),
    /// Historical eligible-stake page independently authenticating a distribution.
    RewardExposure(ValidationFeeExposurePage),
    /// Automatic claimable entitlement from one funded validator exposure page.
    RewardEntitlement(ValidationFeeRewardEntitlement),
    /// Immutable funded staking reward claim.
    RewardClaim(ValidationFeeRewardClaim),
    /// Immutable historical account to original beneficiary mapping.
    RewardBeneficiaryAlias(ValidationFeeRewardBeneficiaryAlias),
    /// Exact native authorized owner revision used by a claim or recovery.
    RewardBeneficiaryRevision(ValidationFeeRewardBeneficiaryRevision),
    /// Scheduled native conversion, including failed pool execution.
    RewardAttempt(ValidationFeeConversionAttempt),
    /// Complete protected Parliament registry preimage for this block.
    PolicyRegistry(crate::validation_fee::ValidationFeePolicyRegistryV1),
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceRecordV1")]
/// Canonically ordered leaf from one completed block.
pub struct FeeEvidenceRecordV1 {
    /// Protected native state key; identifies exactly one record.
    pub key: StatePath,
    /// Block that finalized this record or custody snapshot.
    pub recorded_at_height: u64,
    /// Exact native typed payload.
    pub payload: FeeEvidencePayloadV1,
}
impl FeeEvidenceRecordV1 {
    /// Check height and conservation invariants before proof construction.
    pub fn is_valid(&self) -> bool {
        if self.recorded_at_height == 0 {
            return false;
        }
        match &self.payload {
            FeeEvidencePayloadV1::PolicyRegistry(registry) => {
                self.key.as_ref() == "native_fee_registry_v1" && registry.validate().is_ok()
            }
            FeeEvidencePayloadV1::RetailReceipt(r) => {
                r.recorded_at_height == self.recorded_at_height
                    && r.collected_minor.checked_add(r.waived_minor) == Some(r.scheduled_minor)
                    && crate::validation_fee::retail_fee_receipt_state_key_v1(r)
                        .is_ok_and(|key| key == self.key)
            }
            FeeEvidencePayloadV1::RetailReceiptHead(head) => {
                head.updated_at_height == self.recorded_at_height
                    && (head.sequence == 0) == head.last_receipt_hash.is_none()
                    && crate::validation_fee::retail_fee_receipt_head_state_key_v1(&head.wallet_id)
                        .is_ok_and(|key| key == self.key)
            }
            FeeEvidencePayloadV1::RewardCustody(r) => {
                r.binding.invariant_error().is_none()
                    && r.xor_scale <= 18
                    && r.state.pending_sbd_total <= r.treasury_sbd_minor
                    && r.state.reserved_xor <= r.reward_pool_xor_minor
                    && crate::validation_fee_rewards::validation_fee_reward_state_key(
                        &r.binding, "State",
                    )
                    .is_ok_and(|key| key == self.key)
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().ends_with("/State")
            }
            FeeEvidencePayloadV1::RewardService(r) => {
                crate::validation_fee::honiara_month_bounds(r.earning_period_start_ms)
                    .is_ok_and(|(start, _)| start == r.earning_period_start_ms)
                    && !r.service_blocks.is_empty()
                    && r.service_blocks.len() <= MAX_FEE_EVIDENCE_RECORDS_V1 as usize
                    && r.service_blocks.values().all(|weight| *weight > 0)
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self
                        .key
                        .as_ref()
                        .ends_with(&format!("/Service/{:020}", r.earning_period_start_ms))
            }
            FeeEvidencePayloadV1::RewardAllocation(r)
            | FeeEvidencePayloadV1::RewardAllocationSource(r) => {
                let source = matches!(
                    self.payload,
                    FeeEvidencePayloadV1::RewardAllocationSource(_)
                );
                (if source {
                    r.converted_at_height <= self.recorded_at_height
                } else {
                    r.converted_at_height == self.recorded_at_height
                }) && r.converted_at_height > 0
                    && r.sbd_minor > 0
                    && r.min_xor_minor > 0
                    && !r.service_blocks.is_empty()
                    && r.service_blocks.len() <= MAX_FEE_EVIDENCE_RECORDS_V1 as usize
                    && r.service_blocks.values().all(|weight| *weight > 0)
                    && r.gross_shares.keys().eq(r.service_blocks.keys())
                    && r.reference_observations.len() <= 5
                    && crate::validation_fee_rewards::validate_allocation_bytes(r).is_ok()
                    && r.gross_shares
                        .values()
                        .try_fold(0u128, |a, b| a.checked_add(*b))
                        == Some(r.xor_minor)
                    && r.xor_minor >= r.min_xor_minor
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self
                        .key
                        .as_ref()
                        .ends_with(&format!("/Allocation/{}", r.sequence))
            }
            FeeEvidencePayloadV1::RewardExposure(page) => {
                crate::validation_fee::honiara_month_bounds(page.earning_period_start_ms)
                    .is_ok_and(|(start, _)| start == page.earning_period_start_ms)
                    && crate::validation_fee_rewards::validate_exposure_page(page).is_ok()
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().ends_with(&format!(
                        "/Exposure/{:020}/{}/{:020}",
                        page.earning_period_start_ms,
                        hex::encode(Hash::new(page.validator.to_string().as_bytes()).as_ref()),
                        page.page_index,
                    ))
            }
            FeeEvidencePayloadV1::RewardEntitlement(entitlement) => {
                entitlement.recorded_at_height == self.recorded_at_height
                    && entitlement.service_end > entitlement.service_start
                    && !entitlement.shares.is_empty()
                    && entitlement.shares.len()
                        <= crate::validation_fee_rewards::MAX_REWARD_RECIPIENTS
                    && entitlement
                        .beneficiaries
                        .keys()
                        .eq(entitlement.shares.keys())
                    && entitlement
                        .shares
                        .values()
                        .try_fold(0u128, |a, b| a.checked_add(*b))
                        .is_some()
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().ends_with(&format!(
                        "/Entitlement/{:020}/{}/{:020}",
                        entitlement.allocation_sequence,
                        hex::encode(
                            Hash::new(entitlement.validator.to_string().as_bytes()).as_ref()
                        ),
                        entitlement.page_index,
                    ))
            }
            FeeEvidencePayloadV1::RewardAttempt(r) => {
                r.attempted_at_height == self.recorded_at_height
                    && r.reference_observations.len() <= 5
                    && r.reference_observations.iter().all(|reference| {
                        crate::validation_fee_rewards::validate_reference_observation_bytes(
                            reference,
                        )
                        .is_ok()
                    })
                    && r.sbd_minor > 0
                    && r.min_xor_minor > 0
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().contains("/Attempt/")
            }
            FeeEvidencePayloadV1::RewardBeneficiaryAlias(r) => {
                self.key.as_ref().contains("/ValidationFeeRewards/")
                    && [&r.account_id, &r.beneficiary_id]
                        .into_iter()
                        .all(|account| {
                            crate::validation_fee_rewards::validate_reward_identity(account).is_ok()
                        })
                    && self.key.as_ref().ends_with(&format!(
                        "/BeneficiaryAlias/{}",
                        hex::encode(Hash::new(r.account_id.to_string().as_bytes()).as_ref())
                    ))
            }
            FeeEvidencePayloadV1::RewardBeneficiaryRevision(r) => {
                r.authorized_at_height > 0
                    && [&r.account_id, &r.beneficiary_id]
                        .into_iter()
                        .chain(r.previous_account_id.iter())
                        .all(|account| {
                            crate::validation_fee_rewards::validate_reward_identity(account).is_ok()
                        })
                    && r.authorized_at_height <= self.recorded_at_height
                    && ((r.revision == 0
                        && r.account_id == r.beneficiary_id
                        && r.previous_account_id.is_none())
                        || (r.revision > 0
                            && r.previous_account_id
                                .as_ref()
                                .is_some_and(|old| old != &r.account_id)))
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().ends_with(&format!(
                        "/BeneficiaryHistory/{}/{:020}",
                        hex::encode(Hash::new(r.beneficiary_id.to_string().as_bytes()).as_ref()),
                        r.revision
                    ))
            }
            FeeEvidencePayloadV1::RewardClaim(r) => {
                r.claimed_at_height == self.recorded_at_height
                    && r.xor_minor > 0
                    && self.key.as_ref().contains("/ValidationFeeRewards/")
                    && self.key.as_ref().contains("/Claim/")
            }
        }
    }
}
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceSnapshotV1")]
/// Complete typed evidence root/count, committed at every block height.
pub struct FeeEvidenceSnapshotV1 {
    /// First-release schema version.
    pub version: u16,
    /// Exact completed block height.
    pub evaluated_height: u64,
    /// Domain-separated empty root or native typed Merkle root.
    pub root: Hash,
    /// Cumulative sparse root of all current wallet heads at this checkpoint.
    pub account_heads_root: Hash,
    /// Exact leaf count; binds proof completeness.
    pub count: u32,
}
impl FeeEvidenceSnapshotV1 {
    /// Derive a complete canonical commitment, rejecting omitted-order duplicates.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero height, excessive count, invalid records, or
    /// records not uniquely ordered at that height.
    pub fn from_records(height: u64, records: &[FeeEvidenceRecordV1]) -> Result<Self, String> {
        let count = u32::try_from(records.len()).map_err(|_| "fee record count overflow")?;
        if height == 0
            || count > MAX_FEE_EVIDENCE_RECORDS_V1
            || records
                .iter()
                .any(|r| r.recorded_at_height != height || !r.is_valid())
            || records.windows(2).any(|w| w[0].key >= w[1].key)
        {
            return Err("invalid or unordered native fee records".into());
        }
        let root = MerkleTree::<FeeEvidenceRecordV1>::root_from_typed_leaves(
            records.iter().map(HashOf::new),
        )
        .map_or_else(|| Hash::new(b"iroha.fee_evidence.empty.v1"), Hash::from);
        Ok(Self {
            version: 1,
            evaluated_height: height,
            root,
            account_heads_root: Hash::new([]),
            count,
        })
    }
    /// Validate fixed version, count and empty-root identity.
    pub fn is_valid(&self) -> bool {
        self.version == 1
            && self.evaluated_height > 0
            && self.count <= MAX_FEE_EVIDENCE_RECORDS_V1
            && (self.count != 0 || self.root == Hash::new(b"iroha.fee_evidence.empty.v1"))
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceWitnessProofV1")]
/// Ordinary SMT inclusion of the fixed root/count snapshot.
pub struct FeeEvidenceWitnessProofV1 {
    /// Fixed native fee evidence key.
    pub key: Vec<u8>,
    /// Canonical Norito snapshot bytes.
    pub value: Vec<u8>,
    /// Exact 256-level leaf-to-root ordinary SMT proof.
    pub siblings: Vec<Hash>,
}
impl FeeEvidenceWitnessProofV1 {
    /// Verify the fixed synthetic write against an ordinary-write SMT root.
    #[must_use]
    pub fn verify(&self, expected_ordinary_writes_root: Hash) -> bool {
        self.verified_commitment(expected_ordinary_writes_root)
            .is_ok_and(|commitment| commitment.is_some())
    }

    fn verified_commitment(
        &self,
        expected_ordinary_writes_root: Hash,
    ) -> Result<Option<FeeEvidenceSnapshotV1>, norito::Error> {
        if self.key != FEE_EVIDENCE_WITNESS_KEY_V1 || self.siblings.len() != 256 {
            return Ok(None);
        }
        let commitment = norito::decode_canonical::<FeeEvidenceSnapshotV1>(&self.value)?;
        if !commitment.is_valid() {
            return Ok(None);
        }
        let path = Hash::new(&self.key);
        let value_hash = Hash::new(&self.value);
        let mut leaf_preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
        leaf_preimage.push(0);
        leaf_preimage.extend_from_slice(path.as_ref());
        leaf_preimage.extend_from_slice(value_hash.as_ref());
        let mut current = Hash::new(leaf_preimage);
        for (level, sibling) in self.siblings.iter().copied().enumerate() {
            let path_bit = 255_usize.saturating_sub(level);
            let byte = path.as_ref()[path_bit / 8];
            let right = byte & (1_u8 << (path_bit % 8)) != 0;
            current = if right {
                fee_ordinary_smt_node_hash(sibling, current)
            } else {
                fee_ordinary_smt_node_hash(current, sibling)
            };
        }
        Ok((current == expected_ordinary_writes_root).then_some(commitment))
    }

    /// Decode and return the exact canonical snapshot commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be canonically decoded or its
    /// fields are incoherent.
    pub fn commitment(&self) -> Result<FeeEvidenceSnapshotV1, String> {
        let commitment: FeeEvidenceSnapshotV1 =
            norito::decode_canonical(&self.value).map_err(|error| {
                if matches!(&error, norito::Error::NonCanonicalEncoding) {
                    "native fee evidence snapshot commitment is non-canonical".to_owned()
                } else {
                    format!("native fee evidence snapshot commitment is invalid: {error}")
                }
            })?;
        if !commitment.is_valid() {
            return Err("native fee evidence snapshot commitment is incoherent".to_owned());
        }
        Ok(commitment)
    }
}

fn fee_ordinary_smt_node_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = vec![1];
    bytes.extend_from_slice(left.as_ref());
    bytes.extend_from_slice(right.as_ref());
    Hash::new(bytes)
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceBlockProofV1")]
/// Complete immutable block accounting corpus, not a selective live projection.
pub struct FeeEvidenceBlockProofV1 {
    /// Finality-authenticated root/count proof.
    pub snapshot_witness: FeeEvidenceWitnessProofV1,
    /// Every fee record in canonical order; the snapshot count prevents omissions.
    pub records: Vec<FeeEvidenceRecordV1>,
}
impl FeeEvidenceBlockProofV1 {
    /// Check complete corpus equality against an authenticated ordinary-write root.
    pub fn verify(&self, root: Hash) -> bool {
        self.verify_checked(root)
            .is_ok_and(|snapshot| snapshot.is_some())
    }

    /// Verify the complete proof and return its authenticated snapshot without
    /// erasing canonical decoder resource refusals.
    ///
    /// `Ok(None)` means a completed structural, membership or corpus mismatch.
    /// Consensus execution must use this method rather than the boolean
    /// reporting predicate so local resource exhaustion remains retryable.
    ///
    /// # Errors
    /// Returns the original canonical snapshot decode error, including an active
    /// decode-budget refusal. A successful snapshot is decoded exactly once.
    pub fn verify_checked(
        &self,
        root: Hash,
    ) -> Result<Option<FeeEvidenceSnapshotV1>, norito::Error> {
        let Some(snapshot) = self.snapshot_witness.verified_commitment(root)? else {
            return Ok(None);
        };
        Ok(
            FeeEvidenceSnapshotV1::from_records(snapshot.evaluated_height, &self.records)
                .is_ok_and(|mut observed| {
                    observed.account_heads_root = snapshot.account_heads_root;
                    observed == snapshot
                })
                .then_some(snapshot),
        )
    }
    /// Retrieve the exact retained registry preimage from the complete native corpus.
    pub fn registry(&self) -> Option<&crate::validation_fee::ValidationFeePolicyRegistryV1> {
        self.records.iter().find_map(|r| match &r.payload {
            FeeEvidencePayloadV1::PolicyRegistry(registry) => Some(registry),
            _ => None,
        })
    }
    /// Produce a compact requested-record proof from the complete verified corpus.
    pub fn record_proof(&self, key: &StatePath) -> Option<FeeEvidenceRecordProofV1> {
        let index = self.records.binary_search_by(|r| r.key.cmp(key)).ok()?;
        let tree: MerkleTree<FeeEvidenceRecordV1> = self.records.iter().map(HashOf::new).collect();
        Some(FeeEvidenceRecordProofV1 {
            snapshot_witness: self.snapshot_witness.clone(),
            record: self.records[index].clone(),
            membership: tree.get_proof(u32::try_from(index).ok()?)?,
        })
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceRecordProofV1")]
/// Compact proof for one authenticated retail receipt or reward record.
pub struct FeeEvidenceRecordProofV1 {
    /// Inclusion of the root/count snapshot in finality.
    pub snapshot_witness: FeeEvidenceWitnessProofV1,
    /// Exact native record.
    pub record: FeeEvidenceRecordV1,
    /// Canonical typed Merkle membership including leaf index.
    pub membership: MerkleProof<FeeEvidenceRecordV1>,
}
impl FeeEvidenceRecordProofV1 {
    /// Verify the complete two-level proof against finality's ordinary-write root.
    pub fn verify(&self, root: Hash) -> bool {
        let Ok(snapshot) = self.snapshot_witness.commitment() else {
            return false;
        };
        let Some(count) = NonZeroU64::new(u64::from(snapshot.count)) else {
            return false;
        };
        self.record.is_valid()
            && self.record.recorded_at_height == snapshot.evaluated_height
            && self.snapshot_witness.verify(root)
            && self.membership.verify(
                &HashOf::new(&self.record),
                &MerkleTreeCommitment::new(HashOf::from_untyped_unchecked(snapshot.root), count),
            )
    }
}

/// Exact complete native evidence for one finality-authenticated block.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceFinalizedBlockV1")]
pub struct FeeEvidenceFinalizedBlockV1 {
    /// Native certified block frame and candidate committee; the window verifier
    /// authenticates it from the independently trusted opening checkpoint.
    pub finality: crate::sumeragi_finality::SumeragiFinalityProof,
    /// Complete root/count and accounting corpus.
    pub evidence: FeeEvidenceBlockProofV1,
    /// Finalized protected registry snapshot inclusion.
    pub policy_witness: crate::validation_fee::ValidationFeePolicyWitnessProofV1,
    /// Exact registry preimage, or absence before the first enactment.
    pub registry: Option<crate::validation_fee::ValidationFeePolicyRegistryV1>,
}
impl FeeEvidenceFinalizedBlockV1 {
    /// Header supplying the block's time, height and parent identity.
    ///
    /// It is authenticated only after [`FeeEvidenceWindowProofV1::verify`] succeeds.
    #[must_use]
    pub fn header(&self) -> &crate::block::BlockHeader {
        &self.finality.block_header
    }
}
/// Independently authenticated window bounds; never derive this from the proof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceTrustAnchorV1")]
pub struct FeeEvidenceTrustAnchorV1 {
    /// Exact genesis-derived network identity.
    pub network_id: crate::NetworkId,
    /// Independently authenticated native checkpoint whose tip is the opening block.
    pub opening_checkpoint: crate::sumeragi_finality::SumeragiFinalityCheckpoint,
    /// Independently pinned closing height; prevents a shorter selective window.
    pub closing_height: u64,
    /// Exact finalized closing block identity.
    pub closing_block_hash: HashOf<crate::block::BlockHeader>,
}
impl FeeEvidenceTrustAnchorV1 {
    /// Opening balance checkpoint height.
    #[must_use]
    pub fn opening_height(&self) -> u64 {
        self.opening_checkpoint.height()
    }
    /// Exact finalized opening block identity.
    #[must_use]
    pub fn opening_block_hash(&self) -> HashOf<crate::block::BlockHeader> {
        self.opening_checkpoint.block_hash()
    }
}
/// Complete contiguous accounting window, including both opening and closing snapshots.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::FeeEvidenceWindowProofV1")]
pub struct FeeEvidenceWindowProofV1 {
    /// First-release schema version.
    pub version: u16,
    /// Every block in ascending order, including the opening balance checkpoint.
    pub blocks: Vec<FeeEvidenceFinalizedBlockV1>,
}
impl FeeEvidenceWindowProofV1 {
    /// Authenticate a complete window against an independently supplied checkpoint.
    /// Trust propagates forward from the pinned opening checkpoint through each
    /// contiguous native certificate; the closing block must match its independent pin.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, incomplete or invalid finality,
    /// mismatched roots or policy provenance, altered immutable records, invalid
    /// reward evidence, or accounting that does not conserve funds.
    pub fn verify(&self, anchor: &FeeEvidenceTrustAnchorV1) -> Result<(), String> {
        use crate::validation_fee::ValidationFeePolicySnapshotCommitmentV1;
        if self.version != 1 {
            return Err("unsupported native fee accounting window version".into());
        }
        let roots = statement::verify_finality_window(&self.blocks, anchor)?;
        let mut immutable_payloads = std::collections::BTreeMap::new();
        for (index, block) in self.blocks.iter().enumerate().rev() {
            for record in &block.evidence.records {
                retain_immutable_payload(record, &mut immutable_payloads)?;
            }

            let height = anchor
                .opening_height()
                .checked_add(index as u64)
                .ok_or("window height overflow")?;
            if block.finality.height() != height {
                return Err("native fee finality height mismatch".into());
            }
            let root = roots[index];
            if !block.evidence.verify(root)
                || block
                    .evidence
                    .snapshot_witness
                    .commitment()?
                    .evaluated_height
                    != height
                || !block.policy_witness.verify(root)
                || block.policy_witness.commitment()?
                    != ValidationFeePolicySnapshotCommitmentV1::from_registry(
                        height,
                        u64::try_from(block.header().creation_time().as_millis())
                            .map_err(|_| "block time overflow")?,
                        block.registry.as_ref(),
                    )
            {
                return Err("native fee receipt or Parliament registry proof mismatch".into());
            }
            if block.registry.as_ref() != block.evidence.registry() {
                return Err("native fee registry preimage differs from retained corpus".into());
            }
            if let Some(registry) = &block.registry {
                registry.validate().map_err(|e| e.to_string())?;
            }
            let at_ms = u64::try_from(block.header().creation_time().as_millis())
                .map_err(|_| "block time overflow")?;
            let effective = block
                .registry
                .as_ref()
                .and_then(|registry| registry.payout_policies.effective_entry_at_height(height));
            let retained = effective.or_else(|| {
                block
                    .registry
                    .as_ref()
                    .and_then(|registry| registry.payout_policies.head())
            });
            let custody = block
                .evidence
                .records
                .iter()
                .filter_map(|r| match &r.payload {
                    FeeEvidencePayloadV1::RewardCustody(c) => Some(c),
                    _ => None,
                })
                .collect::<Vec<_>>();
            match retained {
                None if !custody.is_empty() => {
                    return Err("unconfigured fees have reward custody".into());
                }
                Some(entry) if custody.len() != 1 || entry.payout_binding != custody[0].binding => {
                    return Err(
                        "reward custody binding differs from the independently finalized Parliament conversion policy".into(),
                    );
                }
                _ => (),
            }
            if let Some(c) = custody.first() {
                if effective.is_none()
                    && block.evidence.records.iter().any(|record| {
                        matches!(
                            record.payload,
                            FeeEvidencePayloadV1::RewardAttempt(_)
                                | FeeEvidencePayloadV1::RewardAllocation(_)
                                | FeeEvidencePayloadV1::RewardEntitlement(_)
                                | FeeEvidencePayloadV1::RewardClaim(_)
                        )
                    })
                {
                    return Err(
                        "inactive payout lifecycle contains a monetary reward effect".into(),
                    );
                }
                verify_beneficiary_sources(&block.evidence.records, &c.binding)?;
                verify_entitlement_sources(&block.evidence.records, &c.binding)?;
                let attempts = block
                    .evidence
                    .records
                    .iter()
                    .filter_map(|r| match &r.payload {
                        FeeEvidencePayloadV1::RewardAttempt(a) => Some(a),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if attempts.len() > 1 {
                    return Err("multiple native conversion attempts in one block".into());
                }
                for attempt in &attempts {
                    if attempt.lifecycle_seal
                        != c.binding.lifecycle_seal().map_err(|e| e.to_string())?
                        || attempt.attempted_at_ms != at_ms
                        || attempt.sbd_minor > c.binding.max_sbd_per_attempt_minor
                    {
                        return Err("native conversion attempt differs from governed limits".into());
                    }
                    for observation in &attempt.reference_observations {
                        let key = observation
                            .observation
                            .body
                            .provider_id
                            .try_signatory()
                            .ok_or("reference provider has no single signing controller")?;
                        observation
                            .observation
                            .signature
                            .verify(key, &observation.observation.body)
                            .map_err(|e| format!("original reference report signature: {e}"))?;
                    }
                    if crate::validation_fee_rewards::reference_minimum(
                        &c.binding,
                        &attempt.reference_observations,
                        at_ms,
                        height,
                        attempt.sbd_minor,
                        c.xor_scale,
                    )? != Some(attempt.min_xor_minor)
                    {
                        return Err(
                            "native reference quorum, freshness or exact minimum differs".into(),
                        );
                    }
                }
                for allocation in block
                    .evidence
                    .records
                    .iter()
                    .filter_map(|r| match &r.payload {
                        FeeEvidencePayloadV1::RewardAllocation(a) => Some(a),
                        _ => None,
                    })
                {
                    if attempts.len() != 1 {
                        return Err("allocation has no unique native conversion attempt".into());
                    }
                    let attempt = attempts[0];
                    if allocation.lifecycle_seal != attempt.lifecycle_seal
                        || allocation.sbd_minor != attempt.sbd_minor
                        || allocation.min_xor_minor != attempt.min_xor_minor
                        || allocation.earning_period_start_ms != attempt.earning_period_start_ms
                        || allocation.converted_at_ms != at_ms
                        || allocation.reference_observations != attempt.reference_observations
                        || crate::validation_fee_rewards::allocate(
                            allocation.xor_minor,
                            &allocation.service_blocks,
                        )? != allocation.gross_shares
                        || !block.evidence.records.iter().any(|source| {
                            let FeeEvidencePayloadV1::RewardService(service) = &source.payload
                            else {
                                return false;
                            };
                            service.earning_period_start_ms == allocation.earning_period_start_ms
                                && service.service_blocks == allocation.service_blocks
                                && crate::validation_fee_rewards::validation_fee_reward_state_key(
                                    &c.binding,
                                    &format!("Service/{:020}", service.earning_period_start_ms),
                                )
                                .is_ok_and(|key| key == source.key)
                        })
                    {
                        return Err("allocation differs from funded conversion or authenticated historical service".into());
                    }
                }
            }
            for record in &block.evidence.records {
                if let FeeEvidencePayloadV1::RetailReceipt(receipt) = &record.payload
                    && !block.registry.as_ref().is_some_and(|registry| {
                        registry.registered_policies.iter().any(|entry| {
                            entry.policy_hash == receipt.policy_hash
                                && entry.policy.policy_version == receipt.policy_revision
                        })
                    })
                {
                    return Err("native fee receipt policy provenance is absent".into());
                }
            }
        }
        verify_conservation_records(
            self.blocks
                .iter()
                .map(|block| block.evidence.records.as_slice()),
        )
    }
}
fn retain_immutable_payload(
    record: &FeeEvidenceRecordV1,
    retained: &mut std::collections::BTreeMap<StatePath, (Hash, bool)>,
) -> Result<(), String> {
    if matches!(
        record.payload,
        FeeEvidencePayloadV1::RewardCustody(_)
            | FeeEvidencePayloadV1::PolicyRegistry(_)
            | FeeEvidencePayloadV1::RewardService(_)
            | FeeEvidencePayloadV1::RetailReceiptHead(_)
    ) {
        return Ok(());
    }
    // Original allocation and source copies commit the same underlying receipt.
    let payload_bytes = match &record.payload {
        FeeEvidencePayloadV1::RewardAllocation(allocation)
        | FeeEvidencePayloadV1::RewardAllocationSource(allocation) => norito::to_bytes(allocation),
        _ => norito::to_bytes(&record.payload),
    }
    .map_err(|error| error.to_string())?;
    let payload_hash = Hash::new(payload_bytes);
    let monetary = matches!(record.payload, FeeEvidencePayloadV1::RewardAllocation(_));
    if let Some((previous, seen_monetary)) = retained.get_mut(&record.key) {
        let repeatable = matches!(
            record.payload,
            FeeEvidencePayloadV1::RewardBeneficiaryAlias(_)
                | FeeEvidencePayloadV1::RewardBeneficiaryRevision(_)
                | FeeEvidencePayloadV1::RewardExposure(_)
                | FeeEvidencePayloadV1::RewardAllocationSource(_)
        ) || (monetary && !*seen_monetary);
        if *previous != payload_hash || !repeatable {
            return Err("native immutable fee record is replayed or changed across blocks".into());
        }
        *seen_monetary |= monetary;
    } else {
        retained.insert(record.key.clone(), (payload_hash, monetary));
    }
    Ok(())
}

fn verify_entitlement_sources(
    records: &[FeeEvidenceRecordV1],
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<(), String> {
    use crate::validation_fee_rewards::{
        allocate, allocate_page, validation_fee_entitlement_key, validation_fee_exposure_page_key,
        validation_fee_reward_state_key,
    };
    use std::collections::BTreeMap;
    let mut allocations = BTreeMap::new();
    let mut pages = BTreeMap::new();
    for record in records {
        match &record.payload {
            FeeEvidencePayloadV1::RewardAllocation(allocation)
            | FeeEvidencePayloadV1::RewardAllocationSource(allocation) => {
                if validation_fee_reward_state_key(
                    binding,
                    &format!("Allocation/{}", allocation.sequence),
                )? != record.key
                    || allocate(allocation.xor_minor, &allocation.service_blocks)?
                        != allocation.gross_shares
                    || allocations
                        .insert(allocation.sequence, allocation)
                        .is_some()
                {
                    return Err("invalid or duplicate funded allocation source".into());
                }
            }
            FeeEvidencePayloadV1::RewardExposure(page) => {
                if validation_fee_exposure_page_key(
                    binding,
                    page.earning_period_start_ms,
                    &page.validator,
                    page.page_index,
                )? != record.key
                    || pages
                        .insert(
                            (
                                page.earning_period_start_ms,
                                page.validator.clone(),
                                page.page_index,
                            ),
                            page,
                        )
                        .is_some()
                {
                    return Err("invalid or duplicate historical exposure source".into());
                }
            }
            _ => (),
        }
    }
    for record in records {
        let FeeEvidencePayloadV1::RewardEntitlement(entitlement) = &record.payload else {
            continue;
        };
        if validation_fee_entitlement_key(
            binding,
            entitlement.allocation_sequence,
            &entitlement.validator,
            entitlement.page_index,
        )? != record.key
        {
            return Err("automatic reward entitlement key differs from its identity".into());
        }
        let allocation = allocations
            .get(&entitlement.allocation_sequence)
            .ok_or("automatic reward entitlement has no funded allocation source")?;
        let page = pages
            .get(&(
                allocation.earning_period_start_ms,
                entitlement.validator.clone(),
                entitlement.page_index,
            ))
            .ok_or("automatic reward entitlement has no historical exposure source")?;
        let gross = allocation
            .gross_shares
            .get(&entitlement.validator)
            .ok_or("automatic reward entitlement names an unfunded validator")?;
        let total_service = allocation
            .service_blocks
            .get(&entitlement.validator)
            .ok_or("automatic reward entitlement names a validator without service")?;
        let count = page
            .exposure
            .iter()
            .try_fold(0u64, |sum, cohort| sum.checked_add(cohort.service_blocks))
            .ok_or("historical exposure service overflow")?;
        if allocation.converted_at_height > entitlement.recorded_at_height
            || entitlement.service_start.checked_add(count) != Some(entitlement.service_end)
            || allocate_page(*gross, *total_service, entitlement.service_start, page)?
                != entitlement.shares
        {
            return Err(
                "automatic reward entitlement differs from funded historical exposure".into(),
            );
        }
    }
    Ok(())
}
fn verify_beneficiary_sources(
    records: &[FeeEvidenceRecordV1],
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<(), String> {
    use crate::validation_fee_rewards::{
        validation_fee_beneficiary_alias_key as alias_key,
        validation_fee_beneficiary_revision_key as revision_key,
    };
    use std::collections::BTreeMap;
    let mut aliases = BTreeMap::new();
    let mut revisions = BTreeMap::new();
    for record in records {
        match &record.payload {
            FeeEvidencePayloadV1::RewardBeneficiaryAlias(alias) => {
                if alias_key(binding, &alias.account_id)? != record.key
                    || aliases
                        .insert(alias.account_id.clone(), alias.beneficiary_id.clone())
                        .is_some()
                {
                    return Err("invalid or duplicated immutable beneficiary alias source".into());
                }
            }
            FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision) => {
                if revision_key(binding, &revision.beneficiary_id, revision.revision)? != record.key
                    || revisions
                        .insert(
                            (revision.beneficiary_id.clone(), revision.revision),
                            revision,
                        )
                        .is_some()
                {
                    return Err("invalid or duplicated immutable beneficiary owner revision".into());
                }
            }
            _ => (),
        }
    }
    for record in records {
        match &record.payload {
            FeeEvidencePayloadV1::RewardEntitlement(entitlement) => {
                if !entitlement
                    .beneficiaries
                    .keys()
                    .eq(entitlement.shares.keys())
                    || entitlement
                        .beneficiaries
                        .iter()
                        .any(|(historical, original)| aliases.get(historical) != Some(original))
                {
                    return Err(
                        "historical entitlement beneficiary differs from authenticated alias source"
                            .into(),
                    );
                }
            }
            FeeEvidencePayloadV1::RewardClaim(claim) => {
                let owner = revisions
                    .get(&(claim.beneficiary_id.clone(), claim.beneficiary_revision))
                    .ok_or("funded claim lacks its authenticated owner revision")?;
                if aliases.get(&claim.account_id) != Some(&claim.beneficiary_id)
                    || owner.account_id != claim.account_id
                    || owner.authorized_at_height > claim.claimed_at_height
                {
                    return Err(
                        "funded claim differs from its authenticated beneficiary owner".into(),
                    );
                }
            }
            FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision)
                if revision.authorized_at_height == record.recorded_at_height =>
            {
                if aliases.get(&revision.account_id) != Some(&revision.beneficiary_id) {
                    return Err("new beneficiary owner lacks its immutable identity alias".into());
                }
                if revision.revision > 0 {
                    let previous = revisions
                        .get(&(revision.beneficiary_id.clone(), revision.revision - 1))
                        .ok_or("beneficiary recovery lacks its previous authorized owner")?;
                    if revision.previous_account_id.as_ref() != Some(&previous.account_id)
                        || previous.authorized_at_height > revision.authorized_at_height
                    {
                        return Err(
                            "beneficiary recovery changes the original owner lineage".into()
                        );
                    }
                }
            }
            _ => (),
        }
    }
    Ok(())
}
fn verify_conservation_records<'records, Records>(blocks: Records) -> Result<(), String>
where
    Records: IntoIterator<Item = &'records [FeeEvidenceRecordV1]>,
{
    use std::collections::BTreeMap;
    let state_of = |records: &[FeeEvidenceRecordV1]| {
        records
            .iter()
            .find_map(|r| match &r.payload {
                FeeEvidencePayloadV1::RewardCustody(c) => Some(c.state),
                _ => None,
            })
            .unwrap_or_default()
    };
    let mut blocks = blocks.into_iter();
    let mut expected = state_of(blocks.next().ok_or("missing opening custody")?);
    let opening_allocation_sequence = expected.next_allocation;
    // An arbitrary trusted opening checkpoint authenticates aggregate prior
    // claims and unfinished allocation work. Newly created entitlements below
    // have exact beneficiaries; only the opening amount can remain unattributed.
    let mut opening_unattributed = expected.reserved_xor;
    let mut claimable = BTreeMap::<crate::account::AccountId, u128>::new();
    let mut exposure_cursors = BTreeMap::<(u64, crate::account::AccountId), (u64, u64)>::new();
    for records in blocks {
        // Records are grouped by type below, while native claims precede the
        // scheduled conversion. A valid claim-and-refill block can therefore
        // have a temporary audit sum above u128 even though every live reserve
        // remains within u128. Narrow only the final conserved block balance.
        let mut reserved_xor = iroha_primitives::bigint::BigInt::from(expected.reserved_xor);
        let custody = records.iter().find_map(|r| match &r.payload {
            FeeEvidencePayloadV1::RewardCustody(c) => Some(c),
            _ => None,
        });
        let mut allocations = BTreeMap::new();
        let mut entitlements = BTreeMap::new();
        let mut claims = BTreeMap::new();
        if let Some(custody) = custody {
            verify_entitlement_sources(records, &custody.binding)?;
        }
        for record in records {
            match &record.payload {
                FeeEvidencePayloadV1::RetailReceipt(r) => {
                    if r.collected_minor > 0 {
                        expected.pending_sbd_total = expected
                            .pending_sbd_total
                            .checked_add(u128::from(r.collected_minor))
                            .ok_or("SBD receipt credit overflow")?;
                    }
                }
                FeeEvidencePayloadV1::RewardAttempt(a) => {
                    let binding = &custody
                        .ok_or("conversion attempt has no native custody")?
                        .binding;
                    if expected.last_attempt_ms.is_some_and(|last| {
                        a.attempted_at_ms
                            .checked_sub(last)
                            .is_none_or(|delta| delta < binding.min_interval_ms)
                    }) || expected.last_attempt_height >= a.attempted_at_height
                        || a.earning_period_start_ms
                            >= crate::validation_fee::honiara_month_bounds(a.attempted_at_ms)?.0
                    {
                        return Err(
                            "conversion attempt replays a rate window or immature earning period"
                                .into(),
                        );
                    }
                    expected.last_attempt_ms = Some(a.attempted_at_ms);
                    expected.last_attempt_height = a.attempted_at_height;
                }
                FeeEvidencePayloadV1::RewardAllocation(a) => {
                    if allocations.insert(a.sequence, a).is_some() {
                        return Err("duplicate allocation sequence".into());
                    }
                }
                FeeEvidencePayloadV1::RewardEntitlement(entitlement) => {
                    let key = (
                        entitlement.allocation_sequence,
                        entitlement.validator.clone(),
                        entitlement.page_index,
                    );
                    if entitlements.insert(key, entitlement).is_some() {
                        return Err("duplicate automatic reward entitlement".into());
                    }
                }
                FeeEvidencePayloadV1::RewardClaim(c) => {
                    if claims.insert(c.sequence, c).is_some() {
                        return Err("duplicate claim sequence".into());
                    }
                }
                _ => (),
            }
        }
        for (sequence, a) in allocations {
            if sequence != expected.next_allocation {
                return Err("allocation sequence has a gap or replay".into());
            }
            expected.next_allocation = sequence
                .checked_add(1)
                .ok_or("allocation sequence overflow")?;
            let binding = &custody.ok_or("allocation has no native custody")?.binding;
            let day = a
                .converted_at_ms
                .checked_add(39_600_000)
                .ok_or("Honiara conversion day overflow")?
                / 86_400_000;
            if expected.conversion_day != day {
                expected.conversion_day = day;
                expected.converted_today_sbd = 0;
            }
            expected.converted_today_sbd = expected
                .converted_today_sbd
                .checked_add(a.sbd_minor)
                .ok_or("daily conversion sum overflow")?;
            if expected.converted_today_sbd > binding.max_sbd_per_day_minor {
                return Err("conversion exceeds governed daily cap".into());
            }
            expected.last_conversion_ms = Some(a.converted_at_ms);

            expected.pending_sbd_total = expected
                .pending_sbd_total
                .checked_sub(u128::from(a.sbd_minor))
                .ok_or("conversion exceeds authenticated SBD credits")?;
            reserved_xor = reserved_xor
                .checked_add(&iroha_primitives::bigint::BigInt::from(a.xor_minor))
                .map_err(|error| format!("XOR allocation audit overflow: {error}"))?;
            for validator in a.service_blocks.keys() {
                exposure_cursors.insert((sequence, validator.clone()), (0, 0));
            }
        }
        for ((sequence, validator, page_index), entitlement) in entitlements {
            if sequence >= expected.next_allocation {
                return Err("automatic entitlement precedes funded allocation".into());
            }
            let cursor = exposure_cursors
                .entry((sequence, validator))
                .or_insert_with(|| {
                    // The trusted checkpoint may lie halfway through an older
                    // allocation. Preserve its first observed native continuation.
                    (page_index, entitlement.service_start)
                });
            if *cursor != (page_index, entitlement.service_start)
                || (page_index == 0 && entitlement.service_start != 0)
            {
                return Err(
                    "automatic reward entitlement has a replay or exposure page gap".into(),
                );
            }
            *cursor = (
                page_index
                    .checked_add(1)
                    .ok_or("exposure page index overflow")?,
                entitlement.service_end,
            );
            for (historical, amount) in &entitlement.shares {
                let beneficiary = entitlement
                    .beneficiaries
                    .get(historical)
                    .ok_or("automatic reward entitlement lacks a beneficiary")?;
                if sequence < opening_allocation_sequence {
                    opening_unattributed = opening_unattributed
                        .checked_sub(*amount)
                        .ok_or("old entitlement exceeds trusted opening reward reserve")?;
                }
                let credit = claimable.entry(beneficiary.clone()).or_default();
                *credit = credit
                    .checked_add(*amount)
                    .ok_or("automatic entitlement balance overflow")?;
            }
        }
        for (sequence, c) in claims {
            if sequence != expected.next_claim {
                return Err("claim sequence has a gap or replay".into());
            }
            expected.next_claim = sequence.checked_add(1).ok_or("claim sequence overflow")?;
            let binding = &custody.ok_or("claim has no native custody")?.binding;
            if c.lifecycle_seal != binding.lifecycle_seal().map_err(|e| e.to_string())?
                || c.xor_minor < u128::from(binding.min_reward_claim_xor_minor)
            {
                return Err("claim violates governed lifecycle or retained-dust threshold".into());
            }
            let credit = claimable.entry(c.beneficiary_id.clone()).or_default();
            let from_known = (*credit).min(c.xor_minor);
            *credit = credit
                .checked_sub(from_known)
                .ok_or("claim balance underflow")?;
            let from_opening = c
                .xor_minor
                .checked_sub(from_known)
                .ok_or("claim amount underflow")?;
            opening_unattributed = opening_unattributed
                .checked_sub(from_opening)
                .ok_or("claim exceeds automatic entitlement and trusted opening reward balance")?;
            reserved_xor = reserved_xor
                .checked_sub(&iroha_primitives::bigint::BigInt::from(c.xor_minor))
                .map_err(|error| format!("XOR claim audit overflow: {error}"))?;
            if reserved_xor.is_negative() {
                return Err("claim exceeds reserved XOR".into());
            }
        }
        expected.reserved_xor = reserved_xor
            .try_to_u128()
            .ok_or("closing XOR reserve exceeds its balance bound")?;
        let actual = state_of(records);
        if expected.pending_sbd_total != actual.pending_sbd_total
            || expected.reserved_xor != actual.reserved_xor
            || expected.next_allocation != actual.next_allocation
            || expected.next_claim != actual.next_claim
            || expected.last_attempt_ms != actual.last_attempt_ms
            || expected.last_attempt_height != actual.last_attempt_height
            || expected.last_conversion_ms != actual.last_conversion_ms
            || expected.conversion_day != actual.conversion_day
            || expected.converted_today_sbd != actual.converted_today_sbd
        {
            return Err(
                "native fee complete-window conservation differs from closing custody".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{asset::AssetDefinitionId, block::BlockHeader, smart_contract::ContractAddress};
    use iroha_model_base::{
        domain::DomainId,
        name::Name,
        topology::{DataSpaceId, LaneId},
    };
    use std::collections::BTreeMap;
    pub(super) fn receipt(height: u64, suffix: &str) -> FeeEvidenceRecordV1 {
        let keypair =
            iroha_crypto::KeyPair::from_seed(vec![17; 32], iroha_crypto::Algorithm::Ed25519);
        let account_id = crate::account::AccountId::new(keypair.public_key().clone());
        let mut record = FeeEvidenceRecordV1 {
            key: format!("retail_fee_receipts_v1/{suffix}").parse().unwrap(),
            recorded_at_height: height,
            payload: FeeEvidencePayloadV1::RetailReceipt(RetailFeeReceiptV1 {
                wallet_id: account_id.clone(),
                sequence: 1,
                previous_receipt_hash: None,
                receipt_id: [suffix.as_bytes()[0]; 32],
                account_id,
                kind: crate::validation_fee::RetailFeeReceiptKindV1::Maintenance,
                billing_month_start_ms: 1_793_430_000_000,
                policy_revision: 1,
                policy_hash: [23; 32],
                scheduled_minor: 100,
                collected_minor: 30,
                waived_minor: 70,
                payment_count: 0,
                source_transaction_hash: None,
                effective_at_ms: Some(1_796_022_000_000),
                recorded_at_height: height,
                assessment: None,
            }),
        };
        if let FeeEvidencePayloadV1::RetailReceipt(r) = &record.payload {
            record.key = crate::validation_fee::retail_fee_receipt_state_key_v1(r).unwrap();
        }
        record
    }
    #[test]
    fn native_fee_record_and_snapshot_roundtrip_and_conservation() {
        let record = receipt(19, "a");
        assert!(record.is_valid());
        let bytes = norito::to_bytes(&record).unwrap();
        assert_eq!(
            norito::decode_canonical::<FeeEvidenceRecordV1>(&bytes).unwrap(),
            record
        );
        let json = norito::json::to_json(&record).unwrap();
        assert_eq!(
            norito::json::from_str::<FeeEvidenceRecordV1>(&json).unwrap(),
            record
        );
        let snapshot =
            FeeEvidenceSnapshotV1::from_records(19, std::slice::from_ref(&record)).unwrap();
        assert_eq!(
            norito::decode_canonical::<FeeEvidenceSnapshotV1>(
                &norito::to_bytes(&snapshot).unwrap()
            )
            .unwrap(),
            snapshot
        );
        let mut corrupt = record;
        let FeeEvidencePayloadV1::RetailReceipt(r) = &mut corrupt.payload else {
            unreachable!()
        };
        r.waived_minor = 71;
        assert!(FeeEvidenceSnapshotV1::from_records(19, &[corrupt]).is_err());
    }
    #[test]
    fn native_fee_snapshot_rejects_duplicate_order_and_height_and_binds_empty() {
        let a = receipt(19, "a");
        let b = receipt(19, "b");
        assert!(FeeEvidenceSnapshotV1::from_records(19, &[a.clone(), b.clone()]).is_ok());
        assert!(FeeEvidenceSnapshotV1::from_records(19, &[b, a.clone()]).is_err());
        assert!(FeeEvidenceSnapshotV1::from_records(19, &[a.clone(), a.clone()]).is_err());
        assert!(FeeEvidenceSnapshotV1::from_records(20, &[a]).is_err());
        let mut empty = FeeEvidenceSnapshotV1::from_records(19, &[]).unwrap();
        assert!(empty.is_valid());
        empty.root = Hash::new(b"not-empty");
        assert!(!empty.is_valid());
    }
    fn account(seed: u8) -> crate::account::AccountId {
        crate::account::AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    fn binding() -> ValidationFeeTreasuryPayoutBindingV1 {
        let network = crate::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([7; 32])),
        );
        let address = |nonce| {
            ContractAddress::derive(&network, &account(1), nonce, DataSpaceId::UNIVERSAL)
                .expect("address")
        };
        let asset = |name: &str| {
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("fees", "paynet").expect("domain"),
                name.parse::<Name>().expect("name"),
            )
        };
        ValidationFeeTreasuryPayoutBindingV1 {
            contract_address: address(1),
            code_hash: [1; 32],
            entrypoint: "autonomous_validation_fee_tick"
                .parse()
                .expect("entrypoint"),
            treasury_account_id: address(1).subject_id(),
            ds_asset_id: asset("sbd"),
            xor_asset_id: asset("xor"),
            pool_contract_address: address(2),
            pool_code_hash: [2; 32],
            pool_vault_account_id: address(2).subject_id(),
            reward_pool_account_id: address(3).subject_id(),
            reference_feed_id: "xor_per_sbd".parse().expect("feed"),
            reference_feed_config_version: 1,
            reference_provider_accounts: (10..15).map(account).collect(),
            max_sbd_per_attempt_minor: 1000,
            max_sbd_per_day_minor: 100_000,
            min_interval_ms: 60000,
            max_source_age_ms: 300_000,
            max_slippage_bps: 100,
            validator_lane_id: LaneId::new(0),
            min_reward_claim_xor_minor: 1,
        }
    }

    fn custody_record(height: u64, state: ValidationFeeRewardsState) -> FeeEvidenceRecordV1 {
        let binding = binding();
        FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_reward_state_key(&binding, "State")
                .unwrap(),
            recorded_at_height: height,
            payload: FeeEvidencePayloadV1::RewardCustody(FeeRewardCustodySnapshotV1 {
                treasury_sbd_minor: state.pending_sbd_total + 1000,
                reward_pool_xor_minor: state.reserved_xor + 1000,
                binding,
                state,
                xor_scale: 2,
            }),
        }
    }
    fn conservation_vectors() -> Vec<Vec<FeeEvidenceRecordV1>> {
        let mut opening = ValidationFeeRewardsState {
            pending_sbd_total: 20,
            reserved_xor: 1,
            ..Default::default()
        };
        let opening_records = vec![receipt(1, "a"), custody_record(1, opening)];
        let period = 1_790_773_200_000;
        let now = crate::validation_fee::honiara_month_bounds(period)
            .unwrap()
            .1;
        let seal = binding().lifecycle_seal().unwrap();
        opening.pending_sbd_total += 30;
        opening.last_attempt_height = 2;
        opening.last_attempt_ms = Some(now);
        let attempt = |height, at| FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_reward_state_key(
                &binding(),
                &format!("Attempt/{height}"),
            )
            .unwrap(),
            recorded_at_height: height,
            payload: FeeEvidencePayloadV1::RewardAttempt(ValidationFeeConversionAttempt {
                attempted_at_height: height,
                attempted_at_ms: at,
                earning_period_start_ms: period,
                sbd_minor: 50,
                min_xor_minor: 99,
                lifecycle_seal: seal,
                reference_observations: vec![],
            }),
        };
        // An unsuccessful attempt changes only its rate clock. The waived 70 cents
        // and the opening checkpoint's receipt never become new reward credit.
        let failed = vec![receipt(2, "b"), attempt(2, now), custody_record(2, opening)];
        let at = now + 60_000;
        let allocation = FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_reward_state_key(
                &binding(),
                "Allocation/0",
            )
            .unwrap(),
            recorded_at_height: 3,
            payload: FeeEvidencePayloadV1::RewardAllocation(ValidationFeeRewardAllocation {
                sequence: 0,
                lifecycle_seal: seal,
                earning_period_start_ms: period,
                sbd_minor: 50,
                xor_minor: 100,
                converted_at_height: 3,
                converted_at_ms: at,
                min_xor_minor: 99,
                reference_observations: vec![],
                service_blocks: BTreeMap::from([(account(1), 1)]),
                gross_shares: BTreeMap::from([(account(1), 100)]),
            }),
        };
        assert!(allocation.is_valid());
        opening.pending_sbd_total = 0;
        opening.reserved_xor = 101;
        opening.next_allocation = 1;
        opening.last_attempt_height = 3;
        opening.last_attempt_ms = Some(at);
        opening.last_conversion_ms = Some(at);
        opening.conversion_day = (at + 39_600_000) / 86_400_000;
        opening.converted_today_sbd = 50;
        let exposure = FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_exposure_page_key(
                &binding(),
                period,
                &account(1),
                0,
            )
            .unwrap(),
            recorded_at_height: 3,
            payload: FeeEvidencePayloadV1::RewardExposure(ValidationFeeExposurePage {
                earning_period_start_ms: period,
                validator: account(1),
                page_index: 0,
                exposure: vec![crate::validation_fee_rewards::ValidationFeeRewardExposure {
                    service_blocks: 1,
                    stakes: BTreeMap::from([(
                        account(1),
                        iroha_primitives::numeric::Quantity::one(),
                    )]),
                }],
            }),
        };
        let entitlement = FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_entitlement_key(
                &binding(),
                0,
                &account(1),
                0,
            )
            .unwrap(),
            recorded_at_height: 3,
            payload: FeeEvidencePayloadV1::RewardEntitlement(ValidationFeeRewardEntitlement {
                allocation_sequence: 0,
                validator: account(1),
                page_index: 0,
                service_start: 0,
                service_end: 1,
                recorded_at_height: 3,
                shares: BTreeMap::from([(account(1), 100)]),
                beneficiaries: BTreeMap::from([(account(1), account(1))]),
            }),
        };
        let converted = vec![
            attempt(3, at),
            allocation,
            custody_record(3, opening),
            exposure,
            entitlement,
        ];
        opening.reserved_xor = 1;
        opening.next_claim = 1;
        let claim = FeeEvidenceRecordV1 {
            key: crate::validation_fee_rewards::validation_fee_reward_state_key(
                &binding(),
                "Claim/0",
            )
            .unwrap(),
            recorded_at_height: 4,
            payload: FeeEvidencePayloadV1::RewardClaim(ValidationFeeRewardClaim {
                beneficiary_id: account(1),
                beneficiary_revision: 0,
                sequence: 0,
                account_id: account(1),
                xor_minor: 100,
                claimed_at_height: 4,
                claimed_at_ms: at + 1000,
                lifecycle_seal: seal,
            }),
        };
        vec![
            opening_records,
            failed,
            converted,
            vec![claim, custody_record(4, opening)],
        ]
    }
    #[test]
    fn native_fee_complete_window_accounts_only_collected_funds_failed_attempts_and_retained_dust()
    {
        let vectors = conservation_vectors();
        verify_conservation_records(vectors.iter().map(Vec::as_slice)).unwrap();
        for block in &vectors {
            assert!(block.iter().all(FeeEvidenceRecordV1::is_valid));
        }
        let mut waived_as_credit = vectors.clone();
        let FeeEvidencePayloadV1::RewardCustody(c) = &mut waived_as_credit[1][2].payload else {
            unreachable!()
        };
        c.state.pending_sbd_total += 70;
        assert!(verify_conservation_records(waived_as_credit.iter().map(Vec::as_slice)).is_err());
        let mut omitted_conversion = vectors.clone();
        omitted_conversion[2].remove(1);
        assert!(verify_conservation_records(omitted_conversion.iter().map(Vec::as_slice)).is_err());
        let mut replay = vectors.clone();
        let FeeEvidencePayloadV1::RewardClaim(c) = &mut replay[3][0].payload else {
            unreachable!()
        };
        c.sequence = 1;
        assert!(verify_conservation_records(replay.iter().map(Vec::as_slice)).is_err());
        let mut lost_dust = vectors.clone();
        let FeeEvidencePayloadV1::RewardCustody(c) = &mut lost_dust[3][1].payload else {
            unreachable!()
        };
        c.state.reserved_xor = 0;
        assert!(verify_conservation_records(lost_dust.iter().map(Vec::as_slice)).is_err());
        let mut fast_retry = vectors;
        let FeeEvidencePayloadV1::RewardAttempt(a) = &mut fast_retry[2][0].payload else {
            unreachable!()
        };
        a.attempted_at_ms -= 1;
        assert!(verify_conservation_records(fast_retry.iter().map(Vec::as_slice)).is_err());
    }

    #[test]
    fn automatic_entitlement_requires_funded_allocation_and_exact_exposure_sources() {
        let records = conservation_vectors().remove(2);
        verify_entitlement_sources(&records, &binding()).unwrap();
        for missing in [1, 3] {
            let mut invalid = records.clone();
            invalid.remove(missing);
            assert!(verify_entitlement_sources(&invalid, &binding()).is_err());
        }
        let mut invalid = records.clone();
        let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut invalid[4].payload else {
            unreachable!()
        };
        value.shares.insert(account(1), 99);
        assert!(verify_entitlement_sources(&invalid, &binding()).is_err());
        let mut invalid = records.clone();
        let FeeEvidencePayloadV1::RewardExposure(value) = &mut invalid[3].payload else {
            unreachable!()
        };
        value.exposure[0].stakes =
            BTreeMap::from([(account(2), iroha_primitives::numeric::Quantity::one())]);
        assert!(verify_entitlement_sources(&invalid, &binding()).is_err());
        let mut vectors = conservation_vectors();
        vectors[2].remove(4);
        assert!(
            verify_conservation_records(vectors.iter().map(Vec::as_slice)).is_err(),
            "gross funding alone must not authorize a beneficiary claim"
        );
    }

    #[test]
    fn delayed_allocation_sources_do_not_reserve_twice_or_replay_conversion() {
        let mut vectors = conservation_vectors();
        let mut entitlement = vectors[2].remove(4);
        let mut exposure = vectors[2].remove(3);
        let mut source = vectors[2][1].clone();
        let FeeEvidencePayloadV1::RewardAllocation(value) = source.payload else {
            unreachable!()
        };
        source.payload = FeeEvidencePayloadV1::RewardAllocationSource(value);
        source.recorded_at_height = 4;
        exposure.recorded_at_height = 4;
        entitlement.recorded_at_height = 4;
        let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut entitlement.payload else {
            unreachable!()
        };
        value.recorded_at_height = 4;
        vectors[3].extend([source.clone(), exposure, entitlement]);
        verify_conservation_records(vectors.iter().map(Vec::as_slice)).unwrap();
        let mut retained = BTreeMap::new();
        retain_immutable_payload(&source, &mut retained).unwrap();
        retain_immutable_payload(&vectors[2][1], &mut retained).unwrap();
        retain_immutable_payload(&source, &mut retained).unwrap();
        assert!(retain_immutable_payload(&vectors[2][1], &mut retained).is_err());
        let FeeEvidencePayloadV1::RewardAllocationSource(value) = &mut source.payload else {
            unreachable!()
        };
        value.sbd_minor += 1;
        assert!(retain_immutable_payload(&source, &mut retained).is_err());
    }

    #[test]
    fn entitlement_pages_are_contiguous_and_trusted_windows_can_open_mid_allocation() {
        let mut vectors = conservation_vectors();
        let FeeEvidencePayloadV1::RewardAllocation(value) = &mut vectors[2][1].payload else {
            unreachable!()
        };
        value.service_blocks.insert(account(1), 2);
        let mut source = vectors[2][1].clone();
        let FeeEvidencePayloadV1::RewardAllocation(value) = source.payload else {
            unreachable!()
        };
        source.payload = FeeEvidencePayloadV1::RewardAllocationSource(value);
        source.recorded_at_height = 4;
        let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut vectors[2][4].payload else {
            unreachable!()
        };
        value.shares.insert(account(1), 50);
        let mut exposure = vectors[2][3].clone();
        let FeeEvidencePayloadV1::RewardExposure(value) = &mut exposure.payload else {
            unreachable!()
        };
        value.page_index = 1;
        exposure.key = crate::validation_fee_rewards::validation_fee_exposure_page_key(
            &binding(),
            value.earning_period_start_ms,
            &value.validator,
            1,
        )
        .unwrap();
        exposure.recorded_at_height = 4;
        let mut entitlement = vectors[2][4].clone();
        let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut entitlement.payload else {
            unreachable!()
        };
        value.page_index = 1;
        value.service_start = 1;
        value.service_end = 2;
        value.recorded_at_height = 4;
        entitlement.key = crate::validation_fee_rewards::validation_fee_entitlement_key(
            &binding(),
            0,
            &account(1),
            1,
        )
        .unwrap();
        entitlement.recorded_at_height = 4;
        vectors[3].extend([source, exposure, entitlement]);
        verify_conservation_records(vectors.iter().map(Vec::as_slice)).unwrap();
        verify_conservation_records(vectors[2..].iter().map(Vec::as_slice)).unwrap();
        let mut duplicate = vectors.clone();
        duplicate[3].push(vectors[3][4].clone());
        assert!(verify_conservation_records(duplicate.iter().map(Vec::as_slice)).is_err());
        let FeeEvidencePayloadV1::RewardExposure(value) = &mut vectors[3][3].payload else {
            unreachable!()
        };
        value.page_index = 2;
        vectors[3][3].key = crate::validation_fee_rewards::validation_fee_exposure_page_key(
            &binding(),
            value.earning_period_start_ms,
            &value.validator,
            2,
        )
        .unwrap();
        let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut vectors[3][4].payload else {
            unreachable!()
        };
        value.page_index = 2;
        vectors[3][4].key = crate::validation_fee_rewards::validation_fee_entitlement_key(
            &binding(),
            0,
            &account(1),
            2,
        )
        .unwrap();
        assert!(verify_conservation_records(vectors.iter().map(Vec::as_slice)).is_err());
    }

    #[test]
    fn native_fee_beneficiary_sources_bind_historical_allocations_and_exact_claim_revision() {
        use crate::validation_fee_rewards::{
            validation_fee_beneficiary_alias_key as alias_key,
            validation_fee_beneficiary_revision_key as revision_key,
        };
        let binding = binding();
        let original = account(1);
        let middle = account(2);
        let latest = account(3);
        let alias = |account_id: crate::account::AccountId| FeeEvidenceRecordV1 {
            key: alias_key(&binding, &account_id).unwrap(),
            recorded_at_height: 4,
            payload: FeeEvidencePayloadV1::RewardBeneficiaryAlias(
                ValidationFeeRewardBeneficiaryAlias {
                    account_id,
                    beneficiary_id: original.clone(),
                },
            ),
        };
        let revision =
            |revision, account_id, previous_account_id, authorized_at_height| FeeEvidenceRecordV1 {
                key: revision_key(&binding, &original, revision).unwrap(),
                recorded_at_height: 4,
                payload: FeeEvidencePayloadV1::RewardBeneficiaryRevision(
                    ValidationFeeRewardBeneficiaryRevision {
                        beneficiary_id: original.clone(),
                        revision,
                        account_id,
                        previous_account_id,
                        authorized_at_height,
                    },
                ),
            };
        let mut claim = conservation_vectors()[3][0].clone();
        let FeeEvidencePayloadV1::RewardClaim(value) = &mut claim.payload else {
            unreachable!()
        };
        value.account_id = middle.clone();
        value.beneficiary_revision = 1;
        // A claim under revision 1 remains valid when another recovery occurs later
        // in the same block. The original service identity is never rewritten.
        let records = vec![
            alias(original.clone()),
            alias(middle.clone()),
            alias(latest.clone()),
            revision(0, original.clone(), None, 1),
            revision(1, middle.clone(), Some(original.clone()), 3),
            revision(2, latest, Some(middle.clone()), 4),
            claim,
            conservation_vectors()[2][4].clone(),
        ];
        assert!(records.iter().all(FeeEvidenceRecordV1::is_valid));
        verify_beneficiary_sources(&records, &binding).unwrap();
        for index in [1, 4] {
            let mut missing = records.clone();
            missing.remove(index);
            assert!(verify_beneficiary_sources(&missing, &binding).is_err());
        }
        let mut wrong_owner = records.clone();
        let FeeEvidencePayloadV1::RewardClaim(value) = &mut wrong_owner[6].payload else {
            unreachable!()
        };
        value.beneficiary_revision = 2;
        assert!(verify_beneficiary_sources(&wrong_owner, &binding).is_err());
        let mut redirect = records.clone();
        let FeeEvidencePayloadV1::RewardBeneficiaryAlias(value) = &mut redirect[0].payload else {
            unreachable!()
        };
        value.beneficiary_id = middle.clone();
        assert!(verify_beneficiary_sources(&redirect, &binding).is_err());
        let mut broken_lineage = records.clone();
        let FeeEvidencePayloadV1::RewardBeneficiaryRevision(value) = &mut broken_lineage[5].payload
        else {
            unreachable!()
        };
        value.previous_account_id = Some(original);
        assert!(verify_beneficiary_sources(&broken_lineage, &binding).is_err());
        let mut wrong_key = records.clone();
        wrong_key[1].key = alias_key(&binding, &account(9)).unwrap();
        assert!(verify_beneficiary_sources(&wrong_key, &binding).is_err());

        let mut retained = BTreeMap::new();
        retain_immutable_payload(&records[1], &mut retained).unwrap();
        let mut later_source = records[1].clone();
        later_source.recorded_at_height = 5;
        retain_immutable_payload(&later_source, &mut retained).unwrap();
        let FeeEvidencePayloadV1::RewardBeneficiaryAlias(value) = &mut later_source.payload else {
            unreachable!()
        };
        value.beneficiary_id = middle;
        assert!(retain_immutable_payload(&later_source, &mut retained).is_err());
        let mut money = BTreeMap::new();
        retain_immutable_payload(&records[6], &mut money).unwrap();
        assert!(retain_immutable_payload(&records[6], &mut money).is_err());
    }
}
