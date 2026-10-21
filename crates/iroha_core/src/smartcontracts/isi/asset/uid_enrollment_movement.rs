// Enrollment is checked at preparation and again at exact prepared consumption.
fn ensure_uid_enrollment_movement(
    world: &impl WorldReadOnly,
    source: &AssetId,
    destination: &AssetId,
    purpose: NumericAssetTransferSourcePolicy,
) -> Result<(), Error> {
    use crate::state::asset_uid_enrollment as enrollment;
    if enrollment::enrollment(world, source.definition())?.is_none()
        && enrollment::enrollment(world, destination.definition())?.is_none()
    {
        return Ok(());
    }
    let reject = |message: &'static str| {
        InstructionExecutionError::InvariantViolation(message.into())
    };
    if source.definition() != destination.definition()
        || source.scope() != &iroha_data_model::asset::AssetBalanceScope::Global
        || destination.scope() != &iroha_data_model::asset::AssetBalanceScope::Global
    {
        return Err(reject("enrolled movement requires one exact Global asset"));
    }
    let native_source = || {
        let mut records = world.asset_escrows().iter().filter(|(_, record)| {
            record.asset_definition == *source.definition()
                && record.custody == *source.account()
                && !record.remaining_amount.is_zero()
        });
        let record = records.next().map(|(_, record)| record).ok_or_else(|| {
            reject("enrolled native custody requires its exact unresolved record")
        })?;
        if records.next().is_some()
            || enrollment::beneficial(world, source.definition(), source.account())?.is_some()
            || enrollment::beneficial(world, source.definition(), &record.seller)?.is_none()
        {
            return Err(reject("enrolled native custody has ambiguous beneficial ownership"));
        }
        Ok::<_, Error>(record)
    };
    let new_custody = || {
        // Only sealed native capabilities select Funding/Partition after checking
        // the derived destination. A caller-supplied address never selects them.
        if enrollment::beneficial(world, destination.definition(), destination.account())?.is_some()
            || world.asset_escrows().iter().any(|(_, record)| record.custody == *destination.account())
            || world.assets().get(destination).is_some_and(|value| !value.as_ref().is_zero())
        {
            return Err(reject("new native custody must be unclassified and unfunded"));
        }
        Ok(())
    };
    match purpose {
        NumericAssetTransferSourcePolicy::NativeEscrowFunding => {
            enrollment::require_active_beneficial(world, source)?;
            new_custody()
        }
        NumericAssetTransferSourcePolicy::NativeEscrowPartition => {
            native_source()?;
            new_custody()
        }
        NumericAssetTransferSourcePolicy::NativeEscrowReturn => {
            let record = native_source()?;
            if destination.account() != &record.seller {
                return Err(reject("retained return must name the exact original payer"));
            }
            // Returning existing ownership remains possible after institutional
            // revocation or an ordinary incoming freeze. No new credit is granted.
            Ok(())
        }
        NumericAssetTransferSourcePolicy::NativeEscrowCustody => {
            native_source()?;
            enrollment::require_active_beneficial(world, destination)
        }
        _ => {
            enrollment::require_active_beneficial(world, source)?;
            enrollment::require_active_beneficial(world, destination)
        }
    }
}
