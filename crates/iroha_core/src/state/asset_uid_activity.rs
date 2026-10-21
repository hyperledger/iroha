//! Purpose-aware native UID calendar accounting.

use super::*;

/// Internal source provenance selected by the sealed numeric movement kernel.
/// This is never an instruction argument or a contract-selectable exemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MovementActivity {
    /// Owner payment or first funding of a native reserve: consume both ceilings.
    Payment,
    /// Exact FI-attested and owner-approved off-ramp: consume gross outgoing only.
    LinkedFi,
    /// Existing payer reserve already charged at funding: consume neither again.
    RetainedCustody,
}

/// Accumulate each source debit once in a complete native movement occurrence.
pub(super) fn charge_activity(
    world: &impl WorldReadOnly,
    movement: &Movement<'_>,
    now_ms: u64,
    activities: &mut BTreeMap<StatePath, AssetUidUsageV1>,
) -> Result<(), Error> {
    if movement.activity == MovementActivity::RetainedCustody {
        return Ok(());
    }
    // A retained custody account has beneficial ownership, but no wallet
    // membership. Only exact wallet sources can create new UID usage here.
    let Some(policy) = member_policy(
        world,
        movement.source.definition(),
        movement.source.account(),
    )?
    else {
        return Ok(());
    };
    let day = policy.daily_window.day_start_ms(now_ms).map_err(reject)?;
    let key = usage_key(&policy.asset_definition_id, &policy.uid, day);
    if !activities.contains_key(&key) {
        activities.insert(key.clone(), usage(world, &policy, day)?);
    }
    let current = activities.get_mut(&key).expect("usage inserted above");
    current.outgoing_amount = current
        .outgoing_amount
        .checked_add(movement.amount)
        .map_err(|_| MathError::Overflow)?;
    if policy
        .daily_outgoing_limit
        .as_ref()
        .is_some_and(|limit| current.outgoing_amount > *limit)
    {
        return Err(Error::AssetTransferAdmission(
            AssetTransferAdmissionError::PolicyRejected(
                "identity-wide asset calendar daily outgoing limit exceeded".into(),
            ),
        ));
    }
    if movement.activity == MovementActivity::Payment {
        current.spend_amount = current
            .spend_amount
            .checked_add(movement.amount)
            .map_err(|_| MathError::Overflow)?;
        if policy
            .daily_spend_limit
            .as_ref()
            .is_some_and(|limit| current.spend_amount > *limit)
        {
            return Err(Error::AssetTransferAdmission(
                AssetTransferAdmissionError::PolicyRejected(
                    "identity-wide asset calendar daily spending limit exceeded".into(),
                ),
            ));
        }
    }
    Ok(())
}
