//! Immutable bounded original top-up intent; the wallet alone owns its signed envelope.

use super::*;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use iroha_fs::PublishMode;
use iroha_wallet::operations::ReserveTopUpRequest;

pub(super) const MAX_POLICY_BYTES: usize = 32 * 1024;
pub(super) const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_PARTITION_BYTES: usize = 32 * 1024;
pub(super) const MAX_AMOUNT_BYTES: usize = 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 96 * 1024;

pub(super) fn validate_intent(intent: &ManagedReserveTopUpIntent) -> Result<()> {
    encode(&intent.policy, MAX_POLICY_BYTES)?;
    encode(&intent.partition, MAX_PARTITION_BYTES)?;
    encode(&intent.amount, MAX_AMOUNT_BYTES)?;
    intent
        .policy
        .validate()
        .map_err(|_| invalid("invalid selected reserve policy"))?;
    validate_provider_record(&intent.partition, intent.partition.terms.provider_id)
        .map_err(|_| invalid("invalid selected reserve partition"))?;
    if intent.partition.terms.provider_id == ProviderId::default()
        || intent.expected_provider_revision != intent.partition.revision
        || intent.expected_provider_revision == u64::MAX
        || intent.movement_id == [0; 32]
        || intent.amount.is_zero()
        || intent.partition.pending_movements >= intent.policy.max_pending_movements_per_provider
    {
        return Err(invalid(
            "invalid selected top-up id, amount, provider revision or pending ceiling",
        ));
    }
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
#[norito_schema(name = "iroha_deploy::managed::reserve_top_up::Original")]
pub(super) struct Original {
    pub selection: ReserveTopUpSelection,
    pub policy: ReserveAuthorityPolicyV1,
    pub partition: ReserveProviderAccountV1,
    pub movement_id: [u8; 32],
    pub amount: XorQuantity,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub fn validate(&self) -> Result<()> {
        encode(&self.selection, MAX_SELECTION_BYTES)?;
        // Admission precedes intent()'s clones, including restored originals.
        encode(&self.policy, MAX_POLICY_BYTES)?;
        encode(&self.partition, MAX_PARTITION_BYTES)?;
        encode(&self.amount, MAX_AMOUNT_BYTES)?;
        if self.checkpoint.is_empty() || self.checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid("original top-up checkpoint exceeds its bound"));
        }
        validate_intent(&self.intent())?;
        let selected = &self.selection;
        if selected.provider_id != self.partition.terms.provider_id
            || selected.provider_account != self.partition.terms.provider_account
            || selected.partition_policy_digest != self.partition.policy_digest
            || selected.policy_digest
                != self
                    .policy
                    .digest()
                    .map_err(|_| invalid("invalid original reserve digest"))?
            || selected.asset_definition != self.policy.asset_definition
            || selected.custody_account != self.policy.custody_account
            || selected.treasury_account != self.policy.treasury_account
            || selected.operations_authority != self.policy.operations_authority
            || selected.decision_authority != self.policy.decision_authority
        {
            return Err(invalid(
                "original top-up differs from its immutable selection",
            ));
        }
        Ok(())
    }
    pub fn intent(&self) -> ManagedReserveTopUpIntent {
        ManagedReserveTopUpIntent {
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            expected_provider_revision: self.selection.expected_provider_revision,
            movement_id: self.movement_id,
            amount: self.amount.clone(),
        }
    }
    pub fn matches_intent(&self, intent: &ManagedReserveTopUpIntent) -> Result<()> {
        self.validate()?;
        validate_intent(intent)?;
        if self.policy != intent.policy
            || self.partition != intent.partition
            || self.selection.expected_provider_revision != intent.expected_provider_revision
            || self.movement_id != intent.movement_id
            || self.amount != intent.amount
        {
            return Err(invalid(
                "original top-up policy, partition or movement cannot be replaced",
            ));
        }
        Ok(())
    }
    pub fn matches_current(&self, current: &VerifiedReserveAccountStateV1) -> bool {
        current.network_id() == self.selection.network_id
            && current.provider_id() == self.selection.provider_id
            && current.owner() == &self.selection.provider_account
            && current.operator() == &self.selection.operations_authority
            && current.policy().policy == self.policy
            && current.current() == Some(&self.partition)
    }
    pub fn request(&self, terms: &Terms, deadline: Instant) -> ReserveTopUpRequest {
        ReserveTopUpRequest {
            selection: self.selection.clone(),
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            movement_id: self.movement_id,
            amount: self.amount.clone(),
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
        intent: &ManagedReserveTopUpIntent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(intent)?;
        self.terms.matches(utc, options)
    }
    pub fn request(&self, deadline: Instant) -> ReserveTopUpRequest {
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
        // Checkpoint Vec<u8> consumes byte sequence elements; do not truncate its 32 MiB cap to 4096.
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original top-up intent"))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        Purpose::FundingRequest(intent.selection.provider_id),
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
    let purpose = Purpose::FundingRequest(original.selection.provider_id);
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
                .inspect_reserve_top_up_preparation_in_parent(
                    attempt.directory(),
                    std::ffi::OsStr::new("transaction"),
                    &original.request(attempt.terms(), options.deadline),
                )
                .map_err(|_| invalid("funding attempt differs from original wallet request"))
        },
        |attempt, _, deadline| {
            account
                .retain_reserve_top_up_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("cannot retain original unsigned funding request"))
        },
    )
}
