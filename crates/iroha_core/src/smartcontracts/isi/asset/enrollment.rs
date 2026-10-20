// Enrollment purposes come only from native preparation, never from signed flags.

fn ensure_native_enrollment_movement(
    world: &impl WorldReadOnly,
    source: &AssetId,
    destination: &AssetId,
    amount: &Quantity,
    purpose: NumericAssetTransferSourcePolicy,
) -> Result<(), Error> {
    use crate::state::asset_uid_enrollment::{beneficial, enrollment, require_active_beneficial};
    if enrollment(world, source.definition())?.is_none() {
        return Ok(());
    }
    let reject = |message: &str| InstructionExecutionError::InvariantViolation(message.into());
    if source.definition() != destination.definition()
        || source.scope() != &AssetBalanceScope::Global
        || destination.scope() != &AssetBalanceScope::Global
    {
        return Err(reject(
            "enrolled asset movement requires one exact Global definition",
        ));
    }
    match purpose {
        NumericAssetTransferSourcePolicy::NativeEscrowFunding => {
            require_active_beneficial(world, source)?;
            // The consumed escrow/atomic-opening capability has already bound
            // this exact fresh deterministic custody to its original source.
            if beneficial(world, destination.definition(), destination.account())?.is_some()
                || world
                    .asset_escrows()
                    .iter()
                    .any(|(_, record)| record.custody == *destination.account())
            {
                return Err(reject("native funding requires fresh unclassified custody"));
            }
        }
        NumericAssetTransferSourcePolicy::NativeEscrowCustody
        | NumericAssetTransferSourcePolicy::NativeEscrowPartition
        | NumericAssetTransferSourcePolicy::NativeEscrowReturn => {
            let mut matches = world.asset_escrows().iter().filter(|(_, record)| {
                record.asset_definition == *source.definition()
                    && record.custody == *source.account()
            });
            let (_, record) = matches
                .next()
                .ok_or_else(|| reject("enrolled custody has no retained native record"))?;
            if matches.next().is_some()
                || amount > &record.remaining_amount
                || record.remaining_amount.is_zero()
                || beneficial(world, source.definition(), &record.seller)?.is_none()
            {
                return Err(reject(
                    "enrolled native custody differs from its retained owner or reserve",
                ));
            }
            match purpose {
                NumericAssetTransferSourcePolicy::NativeEscrowReturn => {
                    if destination.account() != &record.seller {
                        return Err(reject(
                            "native ownership return must pay the exact retained original payer",
                        ));
                    }
                    // The existing payer owns this reserve already. Eligibility
                    // revocation/closed receive cannot create new ownership here;
                    // the narrow return control policy keeps ordinary use frozen.
                }
                NumericAssetTransferSourcePolicy::NativeEscrowPartition => {
                    if beneficial(world, destination.definition(), destination.account())?.is_some()
                        || world
                            .asset_escrows()
                            .iter()
                            .any(|(_, record)| record.custody == *destination.account())
                    {
                        return Err(reject(
                            "native partition requires fresh unclassified child custody",
                        ));
                    }
                }
                _ => require_active_beneficial(world, destination)?,
            }
        }
        _ => {
            require_active_beneficial(world, source)?;
            require_active_beneficial(world, destination)?;
        }
    }
    Ok(())
}
