//! Bounded immutable initial credit intent; the wallet remains the sole signed journal owner.

use super::*;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use iroha_crypto::HashOf;
use iroha_data_model::sorafs::{capacity::ProviderId, reserve::history::validate_provider_record};
use iroha_fs::PublishMode;
use iroha_wallet::operations::ProviderCreditUpsertRequest;

pub(super) const MAX_POLICY_BYTES: usize = 32 * 1024;
pub(super) const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_PARTITION_BYTES: usize = 32 * 1024;
pub(super) const MAX_CREDIT_BYTES: usize = 64 * 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 176 * 1024;

pub(super) fn validate_intent(
    policy: &ReserveAuthorityPolicyV1,
    partition: &ReserveProviderAccountV1,
    record: &ProviderCreditRecord,
) -> Result<()> {
    // Admit each original graph before any clone/hash or derived wallet request.
    encode(policy, MAX_POLICY_BYTES)?;
    encode(partition, MAX_PARTITION_BYTES)?;
    encode(record, MAX_CREDIT_BYTES)?;
    policy
        .validate()
        .map_err(|_| invalid("invalid selected reserve policy"))?;
    validate_provider_record(partition, partition.terms.provider_id)
        .map_err(|_| invalid("invalid selected reserve partition"))?;
    if record.provider_id == ProviderId::default()
        || record.provider_id != partition.terms.provider_id
        || partition.terms.provider_account == policy.custody_account
        || !record.slashed.is_zero()
        || record.last_penalty_epoch.is_some()
    {
        return Err(invalid(
            "initial credit has invalid provider or authored slash history",
        ));
    }
    // Equality is checked against selected claims only. Native Upsert independently
    // authenticates actual current aggregate backing and owner-funded reserve.
    let claimed_bond = partition
        .reserve_balance
        .checked_sub(&partition.debt_principal)
        .map_err(|_| invalid("selected reserve has invalid owner-funded balance"))?;
    let locked = record
        .bonded
        .checked_add(&record.slashed)
        .map_err(|_| invalid("selected credit quantities cannot be added"))?;
    if &locked != claimed_bond.as_quantity() {
        return Err(invalid(
            "initial credit differs from selected owner-funded reserve",
        ));
    }
    Ok(())
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::provider_credit::Original")]
pub(super) struct Original {
    pub selection: ProviderCreditUpsertSelection,
    pub policy: ReserveAuthorityPolicyV1,
    pub partition: ReserveProviderAccountV1,
    pub record: ProviderCreditRecord,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub fn validate(&self) -> Result<()> {
        encode(&self.selection, MAX_SELECTION_BYTES)?;
        validate_intent(&self.policy, &self.partition, &self.record)?;
        let selected = &self.selection;
        if self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
            || selected.expected_current.is_some()
            || selected.credit_authority != self.policy.decision_authority
            || selected.provider_id != self.partition.terms.provider_id
            || selected.provider_account != self.partition.terms.provider_account
            || selected.partition_revision != self.partition.revision
            || selected.partition_policy_digest != self.partition.policy_digest
            || selected.desired_record_hash
                != HashOf::try_new(&self.record).map_err(std::io::Error::other)?
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
                "original initial credit differs from its immutable selection",
            ));
        }
        Ok(())
    }
    pub fn intent(&self) -> ManagedInitialProviderCreditIntent {
        ManagedInitialProviderCreditIntent {
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            record: self.record.clone(),
        }
    }
    pub fn matches_intent(&self, intent: &ManagedInitialProviderCreditIntent) -> Result<()> {
        self.validate()?;
        validate_intent(&intent.policy, &intent.partition, &intent.record)?;
        if self.policy != intent.policy
            || self.partition != intent.partition
            || self.record != intent.record
        {
            return Err(invalid(
                "original initial credit policy, partition or record cannot be replaced",
            ));
        }
        Ok(())
    }
    pub fn request(&self, terms: &Terms, deadline: Instant) -> ProviderCreditUpsertRequest {
        ProviderCreditUpsertRequest {
            selection: self.selection.clone(),
            policy: self.policy.clone(),
            partition: self.partition.clone(),
            current_credit: None,
            record: self.record.clone(),
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
        intent: &ManagedInitialProviderCreditIntent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(intent)?;
        self.terms.matches(utc, options)
    }
    pub fn request(&self, deadline: Instant) -> ProviderCreditUpsertRequest {
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
            // Checkpoint Vec<u8> consumes byte sequence elements; retain the full documented cap.
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original initial credit intent"))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        Purpose::FundingCredit(intent.selection.provider_id),
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
    let purpose = Purpose::FundingCredit(original.selection.provider_id);
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
                .inspect_provider_credit_upsert_preparation_in_parent(
                    attempt.directory(),
                    std::ffi::OsStr::new("transaction"),
                    &original.request(attempt.terms(), options.deadline),
                )
                .map_err(|_| invalid("funding attempt differs from original wallet request"))
        },
        |attempt, _, deadline| {
            account
                .retain_provider_credit_upsert_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("cannot retain original unsigned funding request"))
        },
    )
}
