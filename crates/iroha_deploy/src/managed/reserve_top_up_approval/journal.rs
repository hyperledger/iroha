//! Bounded immutable approval intent; decoded historical fields remain claims requiring a capability.

use super::*;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId, account::AccountId, block::BlockHeader, sorafs::capacity::ProviderId,
};
use iroha_fs::PublishMode;
use iroha_wallet::operations::ReserveMovementDecisionRequest;

pub(super) const MAX_POLICY_BYTES: usize = 32 * 1024;
pub(super) const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_PARTITION_BYTES: usize = 32 * 1024;
pub(super) const MAX_AMOUNT_BYTES: usize = 1024;
const MAX_HISTORY_BYTES: usize = 8 * 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 128 * 1024;

/// Retained comparison data, never a decoder or constructor for authenticated request evidence.
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::reserve_top_up_approval::HistoryClaim")]
pub(super) struct HistoryClaim {
    transaction_hash: HashOf<SignedTransaction>,
    height: u64,
    block_hash: HashOf<BlockHeader>,
    block_time_ms: u64,
    network_id: NetworkId,
    provider_id: ProviderId,
    provider_account: AccountId,
    movement_id: [u8; 32],
    amount: XorQuantity,
    requested_provider_revision: u64,
    policy_digest: [u8; 32],
}
impl HistoryClaim {
    pub(super) fn from_history(history: &ManagedHistoricalReserveTopUp) -> Result<Self> {
        encode(history.amount(), MAX_AMOUNT_BYTES)?;
        let original = history.original();
        let claim = Self {
            transaction_hash: original.transaction_hash,
            height: original.height,
            block_hash: original.block_hash,
            block_time_ms: original.block_time_ms,
            network_id: history.network_id(),
            provider_id: history.provider_id(),
            provider_account: history.provider_account().clone(),
            movement_id: history.movement_id(),
            amount: history.amount().clone(),
            requested_provider_revision: history.requested_provider_revision(),
            policy_digest: history.policy_digest(),
        };
        claim.validate()?;
        Ok(claim)
    }
    fn validate(&self) -> Result<()> {
        encode(self, MAX_HISTORY_BYTES)?;
        encode(&self.amount, MAX_AMOUNT_BYTES)?;
        if self.height < 2
            || self.block_time_ms == 0
            || self.provider_id == ProviderId::default()
            || self.movement_id == [0; 32]
            || self.amount.is_zero()
            || self.requested_provider_revision == u64::MAX
        {
            return Err(invalid("invalid retained historical request claims"));
        }
        Ok(())
    }
    pub(super) fn matches(&self, history: &ManagedHistoricalReserveTopUp) -> Result<()> {
        self.validate()?;
        if self != &Self::from_history(history)? {
            return Err(invalid(
                "approval historical request differs from original capability",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_intent(intent: &ManagedReserveTopUpApprovalIntent) -> Result<()> {
    encode(&intent.policy, MAX_POLICY_BYTES)?;
    encode(&intent.partition, MAX_PARTITION_BYTES)?;
    if intent.rationale.is_empty() || intent.rationale.len() > RESERVE_MAX_REASON_BYTES_V1 {
        return Err(invalid(
            "approval rationale is empty or exceeds native byte bound",
        ));
    }
    intent
        .policy
        .validate()
        .map_err(|_| invalid("invalid selected reserve policy"))?;
    validate_provider_record(&intent.partition, intent.partition.terms.provider_id)
        .map_err(|_| invalid("invalid selected reserve partition"))?;
    if intent.partition.terms.provider_id == ProviderId::default()
        || intent.expected_provider_revision != intent.partition.revision
        || intent.expected_provider_revision == u64::MAX
        || intent.partition.pending_movements == 0
    {
        return Err(invalid(
            "approval requires its selected current provider CAS and pending counter",
        ));
    }
    // A counter is only structural preflight; it does not establish this movement's Pending status.
    let terms = &intent.partition.terms;
    intent
        .policy
        .economics
        .quote(
            terms.storage_class,
            terms.capacity_gib,
            terms.duration,
            terms.tier,
            XorQuantity::zero(),
        )
        .map_err(|_| invalid("invalid selected reserve underwriting"))?;
    Ok(())
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::reserve_top_up_approval::Original")]
pub(super) struct Original {
    pub history: HistoryClaim,
    pub selection: ReserveMovementDecisionSelection,
    pub policy: ReserveAuthorityPolicyV1,
    pub partition: ReserveProviderAccountV1,
    pub rationale: String,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub fn validate(&self) -> Result<()> {
        self.history.validate()?;
        encode(&self.selection, MAX_SELECTION_BYTES)?;
        encode(&self.policy, MAX_POLICY_BYTES)?;
        encode(&self.partition, MAX_PARTITION_BYTES)?;
        if self.rationale.is_empty()
            || self.rationale.len() > RESERVE_MAX_REASON_BYTES_V1
            || self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(invalid(
                "original approval rationale or checkpoint exceeds its bound",
            ));
        }
        // Tighter component admissions precede restored intent clones.
        validate_intent(&self.intent())?;
        let selected = &self.selection;
        if selected.network_id != self.history.network_id
            || selected.provider_id != self.history.provider_id
            || selected.provider_account != self.history.provider_account
            || selected.provider_id != self.partition.terms.provider_id
            || selected.provider_account != self.partition.terms.provider_account
            || selected.expected_provider_revision <= self.history.requested_provider_revision
            || selected.partition_policy_digest != self.partition.policy_digest
            || selected.policy_digest
                != self
                    .policy
                    .digest()
                    .map_err(|_| invalid("invalid original policy digest"))?
            || selected.asset_definition != self.policy.asset_definition
            || selected.custody_account != self.policy.custody_account
            || selected.treasury_account != self.policy.treasury_account
            || selected.operations_authority != self.policy.operations_authority
            || selected.decision_authority != self.policy.decision_authority
        {
            return Err(invalid(
                "original approval differs from its immutable selected claims",
            ));
        }
        Ok(())
    }
    pub fn intent(&self) -> ManagedReserveTopUpApprovalIntent {
        ManagedReserveTopUpApprovalIntent {
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            expected_provider_revision: self.selection.expected_provider_revision,
            rationale: self.rationale.clone(),
        }
    }
    pub fn matches_intent(&self, intent: &ManagedReserveTopUpApprovalIntent) -> Result<()> {
        self.validate()?;
        validate_intent(intent)?;
        if self.policy != intent.policy
            || self.partition != intent.partition
            || self.selection.expected_provider_revision != intent.expected_provider_revision
            || self.rationale != intent.rationale
        {
            return Err(invalid(
                "original approval policy, partition, revision or rationale cannot be replaced",
            ));
        }
        Ok(())
    }
    pub fn matches_current(&self, current: &VerifiedReserveAccountStateV1) -> bool {
        current.height() >= self.history.height
            && current.network_id() == self.selection.network_id
            && current.provider_id() == self.selection.provider_id
            && current.owner() == &self.selection.provider_account
            && current.operator() == &self.selection.operations_authority
            && current.policy().policy == self.policy
            && current.current() == Some(&self.partition)
    }
    pub fn request(&self, terms: &Terms, deadline: Instant) -> ReserveMovementDecisionRequest {
        ReserveMovementDecisionRequest {
            selection: self.selection.clone(),
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            movement_id: self.history.movement_id,
            approve: true,
            rationale: self.rationale.clone(),
            deadline_unix_ms: terms.signing_deadline_unix_ms,
            options: terms.options(deadline),
        }
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_ORIGINAL_BYTES)
    }
}

impl Selected<Original> {
    pub fn matches(
        &self,
        intent: &ManagedReserveTopUpApprovalIntent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(intent)?;
        self.terms.matches(utc, options)
    }
    pub fn request(&self, deadline: Instant) -> ReserveMovementDecisionRequest {
        Original::request(self, &self.terms, deadline)
    }
}

pub(super) fn read_intent(directory: &PrivateDirectory) -> Result<Option<Original>> {
    let names = directory.entries(3)?;
    if names.iter().any(|name| {
        !["original.nrt", "dispatch.nrt", "attempts"]
            .iter()
            .any(|allowed| name == *allowed)
    }) {
        return Err(invalid("funding semantic intent contains unknown material"));
    }
    let Some(bytes) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? else {
        require_empty(directory)?;
        return Ok(None);
    };
    let original: Original = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original approval intent"))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        Purpose::FundingApproval(intent.selection.provider_id),
        intent.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    Selected::from_history(intent, history).map(Some)
}
pub(super) fn required_original(directory: &PrivateDirectory) -> Result<Selected<Original>> {
    read_original(directory)?.ok_or_else(|| invalid("original funding intent is absent"))
}
pub(super) fn publish_intent(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    original.validate()?;
    let bytes = encode(original, MAX_ORIGINAL_BYTES)?;
    if let Some(retained) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? {
        if retained != bytes {
            return Err(invalid("original funding semantic selection changed"));
        }
        return Ok(());
    }
    directory.write_atomic("original.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(())
}
pub(super) fn explicit(
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
    account: &AccountService,
) -> Result<()> {
    let purpose = Purpose::FundingApproval(original.selection.provider_id);
    let history = History::read(
        directory,
        purpose,
        original.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    let terms = match history.retained_terms() {
        Some(terms) => {
            terms.matches(utc, options)?;
            terms.clone()
        }
        None => Terms::new(utc, options)?,
    };
    attempts::initial(
        history,
        terms,
        Observation::ordinary(),
        options.deadline,
        |attempt| {
            account
                .inspect_reserve_movement_decision_preparation(
                    &attempt.wallet_path(),
                    &original.request(attempt.terms(), options.deadline),
                )
                .map_err(|_| invalid("funding attempt differs from original wallet request"))
        },
        |attempt, _, deadline| {
            account
                .retain_reserve_movement_decision_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("cannot retain original unsigned funding request"))
        },
    )
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;

/// Exercise retained comparison claims without manufacturing a historical capability.
#[cfg(test)]
pub(super) fn assert_history_claim_mutations_refuse(
    history: &ManagedHistoricalReserveTopUp,
    mut check: impl FnMut(HistoryClaim),
) {
    let claim = HistoryClaim::from_history(history).unwrap();
    claim.matches(history).unwrap();
    for field in 0..12 {
        let mut changed = claim.clone();
        match field {
            0 => {
                changed.transaction_hash = HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"different original transaction",
                ))
            }
            1 => changed.height += 1,
            2 => {
                changed.block_hash = HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"different original carrier",
                ))
            }
            3 => changed.block_time_ms += 1,
            4 => {
                changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    iroha_crypto::Hash::new(b"different original network"),
                ))
            }
            5 => changed.provider_id = ProviderId::new([0x92; 32]),
            6 => {
                changed.provider_account = AccountId::new(
                    iroha_crypto::KeyPair::try_from_seed(
                        vec![0x93; 32],
                        iroha_crypto::Algorithm::Ed25519,
                    )
                    .unwrap()
                    .public_key()
                    .clone(),
                )
            }
            7 => changed.movement_id[0] ^= 1,
            8 => {
                changed.amount = history
                    .amount()
                    .checked_add(&XorQuantity::try_from_micro(1).unwrap())
                    .unwrap()
            }
            9 => changed.requested_provider_revision += 1,
            10 => changed.policy_digest[0] ^= 1,
            _ => {
                changed.height -= 1;
                changed.block_time_ms -= 1;
            }
        }
        assert!(
            changed.matches(history).is_err(),
            "changed history claim field {field}"
        );
        check(changed);
    }
}
