//! Current owner-consented FI settlement of an exact retained controlled lock.

use super::*;
use crate::{
    executor::ContractRuntimeExecutionContext,
    state::{asset_fi, asset_uid},
};
use iroha_data_model::escrow::control::AssetLockWaterfallSettlementV1;
use iroha_data_model::isi::error::MathError;

/// Every field is derived from current native state under the exclusive transaction.
/// The money kernel consumes this value once; a contract cannot construct one.
pub(in crate::smartcontracts::isi) struct VerifiedControlledWaterfallBatch {
    record: AssetEscrowRecord,
    authority: AccountId,
    beneficiary: AccountId,
    fi: AccountId,
    draw: Quantity,
    sweep: Quantity,
    custody_to_fi: Quantity,
    custody_to_beneficiary: Quantity,
    binding: Vec<u8>,
}

impl VerifiedControlledWaterfallBatch {
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        AssetEscrowRecord,
        AccountId,
        AccountId,
        AccountId,
        Quantity,
        Quantity,
        Quantity,
        Quantity,
        Vec<u8>,
    ) {
        (
            self.record,
            self.authority,
            self.beneficiary,
            self.fi,
            self.draw,
            self.sweep,
            self.custody_to_fi,
            self.custody_to_beneficiary,
            self.binding,
        )
    }
}

/// Transfer one already validated draw/refund without changing the retained lock.
/// The existing lock mutation remains the sole owner of remaining/CAS/status.
pub(super) fn transfer(
    tx: &mut StateTransaction<'_, '_>,
    record: &AssetEscrowRecord,
    beneficiary: &AccountId,
    amount: &Quantity,
    terms: &AssetLockWaterfallSettlementV1,
    context: &ContractRuntimeExecutionContext,
) -> Result<(), Error> {
    ensure_positive(amount)?;
    if amount > &record.remaining_amount || record.status != AssetEscrowStatus::Locked {
        return Err(validation_err(
            "controlled waterfall exceeds its current locked reserve",
        ));
    }
    let authority = &context.contract_subject;
    let control = controlled::existing_control(tx.world(), &record.id)?;
    controlled::authenticate(tx.world(), authority, Some(context), &control)?;
    let policy = asset_uid::member_policy(tx.world(), &record.asset_definition, beneficiary)?
        .ok_or_else(|| validation_err("controlled waterfall beneficiary has no UID policy"))?;
    if policy.revision != terms.expected_policy_revision {
        return Err(validation_err(
            "controlled waterfall UID policy revision changed",
        ));
    }
    let link = asset_fi::active_link(
        tx.world(),
        &record.asset_definition,
        beneficiary,
        terms.expected_link_revision,
    )?;
    if !link.waterfall || link.controller.as_ref() != Some(&context.contract_address) {
        return Err(validation_err(
            "controlled waterfall requires the beneficiary's exact current owner consent",
        ));
    }
    if beneficiary != &record.seller && record.buyer.as_ref() != Some(beneficiary) {
        return Err(validation_err(
            "controlled waterfall destination is not a retained lock party",
        ));
    }
    let original_owner =
        asset_uid::member_policy(tx.world(), &record.asset_definition, &record.seller)?;
    let holdings = asset_uid::holdings(tx.world(), &policy, &BTreeMap::new())?;
    // A refund, or a release between wallets of the same UID, already belongs to
    // this policy. Adding the incoming amount again would confiscate excess funds.
    let total = if original_owner
        .as_ref()
        .is_some_and(|original| original.uid == policy.uid)
    {
        holdings
    } else {
        holdings
            .checked_add(amount)
            .map_err(|_| MathError::Overflow)?
    };
    let overflow = match &policy.holding_limit {
        Some(cap) if total > *cap => total.checked_sub(cap).map_err(|_| MathError::Overflow)?,
        _ => Quantity::zero(),
    };
    let custody_to_fi = overflow.clone().min(amount.clone());
    let sweep = overflow
        .checked_sub(&custody_to_fi)
        .map_err(|_| MathError::Overflow)?;
    let custody_to_beneficiary = amount
        .checked_sub(&custody_to_fi)
        .map_err(|_| MathError::Overflow)?;
    let binding = asset_uid::encode(&(
        "controlled-lock-owner-waterfall-v1",
        record,
        beneficiary,
        amount,
        &policy,
        &link,
        &control,
        &sweep,
        &custody_to_fi,
        &custody_to_beneficiary,
    ))?;
    let verified = VerifiedControlledWaterfallBatch {
        record: record.clone(),
        authority: authority.clone(),
        beneficiary: beneficiary.clone(),
        fi: link.fi_account_id,
        draw: amount.clone(),
        sweep,
        custody_to_fi,
        custody_to_beneficiary,
        binding,
    };
    super::super::asset::isi::execute_verified_controlled_waterfall_batch(tx, verified)
}
