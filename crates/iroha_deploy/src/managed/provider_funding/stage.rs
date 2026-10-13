//! Create-only child selections bound to the original automatic economics.
//! These rows remain retained intent; each child independently verifies current native state.

use super::*;
use iroha_crypto::HashOf;
use iroha_data_model::sorafs::{pricing::ProviderCreditRecord, reserve::ReserveProviderAccountV1};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_model_base::metadata::Metadata;

const MAX_STAGE_BYTES: usize = MAX_CHECKPOINT_BYTES + 96 * 1024;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_deploy::managed::provider_funding::Stage")]
pub(super) enum Stage {
    Approval,
    Credit,
}
impl Stage {
    fn filename(self) -> &'static str {
        match self {
            Self::Approval => "approval-selection.nrt",
            Self::Credit => "credit-selection.nrt",
        }
    }
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::provider_funding::SelectedStage")]
pub(super) struct SelectedStage {
    pub stage: Stage,
    pub original: HashOf<original::Original>,
    pub partition: ReserveProviderAccountV1,
    pub checkpoint: Vec<u8>,
    #[norito(required)]
    pub credit: Option<ProviderCreditRecord>,
}
impl SelectedStage {
    pub(super) fn select(
        stage: Stage,
        original: &original::Original,
        account_state: &VerifiedReserveAccountStateV1,
        verifier: &FinalityVerifier,
        minimum_height: u64,
    ) -> Result<Self> {
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("funding child requires selected certified state"))?;
        let partition = account_state
            .current()
            .ok_or_else(|| invalid("funding child requires its native reserve partition"))?;
        encode(partition, provider_economics::MAX_PARTITION_BYTES)?;
        if account_state.height() < minimum_height
            || account_state.network_id() != original.network_id
            || verifier.checkpoint().network_id() != original.network_id
            || account_state.height() != tip.height()
            || account_state.context_id() != tip.context_id()
            || account_state.block_time_ms() != tip.header().creation_time_ms
            || account_state.policy().policy != original.policy
            || account_state.pricing() != &original.pricing
            || account_state.credit().is_some()
            || account_state.capacity().is_some()
        {
            return Err(invalid(
                "funding child native predecessor changed or predates its carrier",
            ));
        }
        let mut selected = Self {
            stage,
            original: original.digest()?,
            partition: partition.clone(),
            checkpoint: checkpoint_bytes(verifier)?,
            credit: None,
        };
        if stage == Stage::Credit {
            selected.credit = Some(selected.expected_credit(original)?);
        }
        selected.validate(stage, original)?;
        Ok(selected)
    }

    pub(super) fn validate(&self, stage: Stage, original: &original::Original) -> Result<()> {
        encode(&self.partition, provider_economics::MAX_PARTITION_BYTES)?;
        iroha_data_model::sorafs::reserve::history::validate_provider_record(
            &self.partition,
            original.partition.terms.provider_id,
        )
        .map_err(|_| invalid("invalid original funding child partition"))?;
        if let Some(credit) = &self.credit {
            encode(credit, provider_economics::MAX_CREDIT_BYTES)?;
        }
        let needs_top_up = !original.economics.top_up.is_zero();
        let funded_balance = original
            .partition
            .reserve_balance
            .checked_add(&original.economics.top_up)
            .map_err(std::io::Error::other)?;
        let (increments, pending, balance) = match stage {
            Stage::Approval if needs_top_up => (1, 1, &original.partition.reserve_balance),
            Stage::Approval => return Err(invalid("zero top-up cannot select an approval")),
            Stage::Credit => (if needs_top_up { 2 } else { 0 }, 0, &funded_balance),
        };
        let revision = original
            .partition
            .revision
            .checked_add(increments)
            .ok_or_else(|| invalid("funding child revision overflow"))?;
        if self.stage != stage
            || self.original != original.digest()?
            || self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
            || self.partition.terms != original.partition.terms
            || self.partition.revision != revision
            || self.partition.pending_movements != pending
            || &self.partition.reserve_balance != balance
            || self.partition.debt_principal != original.partition.debt_principal
            || self.partition.accrued_interest != original.partition.accrued_interest
            || self.partition.open_appeals != 0
            || match stage {
                Stage::Approval => self.credit.is_some(),
                Stage::Credit => self.credit.as_ref() != Some(&self.expected_credit(original)?),
            }
        {
            return Err(invalid(
                "original automatic funding child selection changed",
            ));
        }
        Ok(())
    }

    pub(super) fn approval(
        &self,
        original: &original::Original,
    ) -> Result<ManagedReserveTopUpApprovalIntent> {
        self.validate(Stage::Approval, original)?;
        Ok(ManagedReserveTopUpApprovalIntent {
            policy: original.policy.clone(),
            partition: self.partition.clone(),
            expected_provider_revision: self.partition.revision,
            rationale: "managed localnet provider reserve bootstrap".into(),
        })
    }

    pub(super) fn credit(
        &self,
        original: &original::Original,
    ) -> Result<ManagedInitialProviderCreditIntent> {
        self.validate(Stage::Credit, original)?;
        Ok(ManagedInitialProviderCreditIntent {
            policy: original.policy.clone(),
            partition: self.partition.clone(),
            record: self
                .credit
                .clone()
                .ok_or_else(|| invalid("funding credit selection is absent"))?,
        })
    }
    fn expected_credit(&self, original: &original::Original) -> Result<ProviderCreditRecord> {
        let bonded = self
            .partition
            .reserve_balance
            .checked_sub(&self.partition.debt_principal)
            .map_err(std::io::Error::other)?;
        Ok(ProviderCreditRecord::new(
            self.partition.terms.provider_id,
            original.economics.available_credit.clone(),
            bonded.as_quantity().clone(),
            original.economics.price_bond.clone(),
            original.economics.expected_settlement.clone(),
            original.economics.onboarding_epoch,
            original.economics.observed_epoch,
            Metadata::default(),
        ))
    }
}

pub(super) fn read(
    directory: &PrivateDirectory,
    stage: Stage,
    original: &original::Original,
) -> Result<Option<SelectedStage>> {
    let Some(bytes) = read_optional(directory, stage.filename(), MAX_STAGE_BYTES)? else {
        return Ok(None);
    };
    let selected: SelectedStage = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_STAGE_BYTES,
            MAX_STAGE_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(std::io::Error::other)?;
    selected.validate(stage, original)?;
    Ok(Some(selected))
}

pub(super) fn publish(
    directory: &PrivateDirectory,
    stage: Stage,
    original: &original::Original,
    selected: &SelectedStage,
) -> Result<()> {
    selected.validate(stage, original)?;
    directory.write_atomic(
        stage.filename(),
        &encode(selected, MAX_STAGE_BYTES)?,
        PublishMode::CreateNew,
    )?;
    Ok(())
}
