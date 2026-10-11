//! Bounded immutable generated declaration intent; the wallet owns the sole signed journal.

use super::*;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use iroha_crypto::HashOf;
use iroha_data_model::sorafs::{
    capacity::CapacityDeclarationRecord, pricing::PricingScheduleRecord,
    reserve::history::validate_provider_record,
};
use iroha_fs::PublishMode;
use iroha_wallet::operations::ProviderCapacityDeclarationRequest;
use provider_economics::{
    EconomicAmounts, MAX_CREDIT_BYTES, MAX_PARTITION_BYTES, MAX_POLICY_BYTES, MAX_PRICING_BYTES,
};

pub(super) const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_DECLARATION_BYTES: usize = 256 * 1024;
pub(super) const MAX_CAPACITY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024;

pub(super) fn admit_selection_inputs(
    partition: &ReserveProviderAccountV1,
    credit: &ProviderCreditRecord,
    declaration: &CapacityDeclarationV1,
) -> Result<()> {
    encode(partition, MAX_PARTITION_BYTES)?;
    encode(credit, MAX_CREDIT_BYTES)?;
    encode(declaration, MAX_DECLARATION_BYTES)?;
    Ok(())
}
pub(super) fn admit(
    policy: &ReserveAuthorityPolicyV1,
    partition: &ReserveProviderAccountV1,
    credit: &ProviderCreditRecord,
    declaration: &CapacityDeclarationV1,
    pricing: &PricingScheduleRecord,
    previous_capacity: Option<&CapacityDeclarationRecord>,
) -> Result<()> {
    encode(policy, MAX_POLICY_BYTES)?;
    admit_selection_inputs(partition, credit, declaration)?;
    encode(pricing, MAX_PRICING_BYTES)?;
    if let Some(previous) = previous_capacity {
        encode(previous, MAX_CAPACITY_BYTES)?;
    }
    Ok(())
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::provider_capacity::Original")]
pub(super) struct Original {
    pub selection: ProviderCapacityDeclarationSelection,
    pub policy: ReserveAuthorityPolicyV1,
    pub partition: ReserveProviderAccountV1,
    pub credit: ProviderCreditRecord,
    pub declaration: CapacityDeclarationV1,
    pub pricing: PricingScheduleRecord,
    pub previous_capacity: Option<CapacityDeclarationRecord>,
    pub observed_block_time_ms: u64,
    pub economics: EconomicAmounts,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub fn validate(&self) -> Result<()> {
        encode(&self.selection, MAX_SELECTION_BYTES)?;
        admit(
            &self.policy,
            &self.partition,
            &self.credit,
            &self.declaration,
            &self.pricing,
            self.previous_capacity.as_ref(),
        )?;
        encode(&self.economics, 16 * 1024)?;
        self.policy
            .validate()
            .map_err(|_| invalid("invalid original capacity reserve policy"))?;
        self.pricing
            .validate()
            .map_err(|_| invalid("invalid original capacity pricing"))?;
        self.declaration
            .validate()
            .map_err(|_| invalid("invalid original capacity declaration"))?;
        validate_provider_record(&self.partition, self.selection.provider_id)
            .map_err(|_| invalid("invalid original capacity partition"))?;
        let selected = &self.selection;
        let bond = self
            .partition
            .reserve_balance
            .checked_sub(&self.partition.debt_principal)
            .map_err(std::io::Error::other)?;
        let locked = self
            .credit
            .bonded
            .checked_add(&self.credit.slashed)
            .map_err(std::io::Error::other)?;
        if self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
            || self.observed_block_time_ms < 1000
            || self.economics.observed_epoch != self.observed_block_time_ms / 1000
            || !self.economics.top_up.is_zero()
            || selected.provider_id != self.partition.terms.provider_id
            || selected.provider_account != self.partition.terms.provider_account
            || self.declaration.provider_id != *selected.provider_id.as_bytes()
            || self.credit.provider_id != selected.provider_id
            || self.partition.terms.capacity_gib < self.declaration.committed_capacity_gib
            || self.credit.bonded.is_zero()
            || &locked != bond.as_quantity()
            || &self.credit.bonded < self.declaration.stake.stake_amount.as_quantity()
            || self.credit.bonded < self.credit.required_bond
            || self
                .previous_capacity
                .as_ref()
                .is_some_and(|row| row.provider_id != selected.provider_id)
            || selected.partition_revision != self.partition.revision
            || selected.partition_policy_digest != self.partition.policy_digest
            || selected.declaration_hash
                != HashOf::try_new(&self.declaration).map_err(std::io::Error::other)?
            || selected.credit_hash
                != HashOf::try_new(&self.credit).map_err(std::io::Error::other)?
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
                "original capacity differs from its immutable selection or backing claims",
            ));
        }
        Ok(())
    }
    pub fn matches_intent(&self, policy: &ReserveAuthorityPolicyV1) -> Result<()> {
        self.validate()?;
        encode(policy, MAX_POLICY_BYTES)?;
        if &self.policy != policy {
            return Err(invalid("original capacity policy cannot be replaced"));
        }
        Ok(())
    }
    pub fn request(&self, terms: &Terms, deadline: Instant) -> ProviderCapacityDeclarationRequest {
        ProviderCapacityDeclarationRequest {
            selection: self.selection.clone(),
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            credit: self.credit.clone(),
            declaration: self.declaration.clone(),
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
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(policy)?;
        self.terms.matches(utc, options)
    }
    pub fn request(&self, deadline: Instant) -> ProviderCapacityDeclarationRequest {
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
        // Checkpoint and prior declaration byte sequences retain their documented caps; the
        // total allocation, total element count, frame and nesting limits remain finite.
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            112 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original capacity declaration intent"))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        Purpose::FundingCapacity(intent.selection.provider_id),
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
    let purpose = Purpose::FundingCapacity(original.selection.provider_id);
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
                .inspect_provider_capacity_declaration_preparation_in_parent(
                    attempt.directory(),
                    std::ffi::OsStr::new("transaction"),
                    &original.request(attempt.terms(), options.deadline),
                )
                .map_err(|_| invalid("funding attempt differs from original wallet request"))
        },
        |attempt, _, deadline| {
            account
                .retain_provider_capacity_declaration_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("cannot retain original unsigned funding request"))
        },
    )
}
