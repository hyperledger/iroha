// The sealed controller/owner-link capability supplies each leg's exact purpose.

pub(in crate::smartcontracts::isi) fn execute_verified_controlled_waterfall_batch(
    state_transaction: &mut StateTransaction<'_, '_>,
    verified: crate::smartcontracts::isi::escrow::controlled_waterfall::VerifiedControlledWaterfallBatch,
) -> Result<(), Error> {
    let (
        record,
        authority,
        beneficiary,
        fi,
        draw,
        sweep,
        custody_to_fi,
        custody_to_beneficiary,
        binding,
    ) = verified.into_parts();
    if state_transaction.world.asset_escrows.get(&record.id) != Some(&record)
        || record.release_authority.as_ref() != Some(&authority)
        || draw > record.remaining_amount
        || draw.is_zero()
        || custody_to_fi
            .checked_add(&custody_to_beneficiary)
            .map_err(|_| MathError::Overflow)?
            != draw
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "controlled waterfall differs from its exact retained lock".into(),
        ));
    }
    let is_retained_return = beneficiary == record.seller;
    let custody = AssetId::new(record.asset_definition.clone(), record.custody.clone());
    let beneficiary = AssetId::new(record.asset_definition.clone(), beneficiary);
    let fi = AssetId::new(record.asset_definition, fi);
    let entries = [
        (
            &beneficiary,
            &fi,
            sweep,
            NumericAssetTransferSourcePolicy::LinkedFi,
        ),
        (
            &custody,
            &fi,
            custody_to_fi,
            NumericAssetTransferSourcePolicy::NativeEscrowCustody,
        ),
        (
            &custody,
            &beneficiary,
            custody_to_beneficiary,
            if is_retained_return { NumericAssetTransferSourcePolicy::NativeEscrowReturn } else { NumericAssetTransferSourcePolicy::NativeEscrowCustody },
        ),
    ];
    // Both sources must cover their entire debit before any incoming credit.
    // Sibling wallets and locked holdings never confer permission over their keys.
    for (source, amount) in [(&beneficiary, &entries[0].2), (&custody, &draw)] {
        if amount.is_zero() {
            continue;
        }
        let balance = state_transaction
            .world
            .assets
            .get(source)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero);
        balance
            .checked_sub(amount)
            .map_err(|_| MathError::NotEnoughQuantity)?;
    }
    let mut plans = Vec::with_capacity(3);
    for (source, destination, amount, source_policy) in entries {
        if amount.is_zero() {
            continue;
        }
        // Exact splitting never over-credits the beneficiary, so ordinary strict
        // UID holding checks remain enabled even for this composite operation.
        plans.push(PreparedNumericTransferPlan::prepare(
            state_transaction,
            &authority,
            source.clone(),
            destination.clone(),
            amount,
            NumericAssetTransferScopePolicy::Ambient,
            NumericAssetTransferAuthorityPolicy::ProtocolAuthorized,
            source_policy,
            if source_policy == NumericAssetTransferSourcePolicy::NativeEscrowReturn { NumericAssetTransferControlPolicy::RetainedPayerReturn } else { NumericAssetTransferControlPolicy::Enforce },
            NumericAssetDestinationAdmissionPolicy::ExistingAccount,
        )?);
    }
    let authorization = NumericAssetMovementAuthorization {
        debit: NumericMovementDebitAuthorization::Protocol,
        transcript_authority: authority,
        transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
            tag: "controlled-lock-owner-waterfall-v1",
            binding,
        },
        // The exact binding retains both immutable lock and current owner link;
        // individual plans independently retain LinkedFi/NativeEscrow provenance.
        source_policy: NumericAssetTransferSourcePolicy::NativeEscrowCustody,
        control_policy: NumericAssetTransferControlPolicy::Enforce,
        destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
    };
    let batch =
        PreparedNumericAssetMovementBatch::aggregate(state_transaction, plans, authorization)?;
    let applied = batch.apply(state_transaction)?;
    for movement in applied {
        #[allow(clippy::float_arithmetic)]
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .observe_tx_amount(movement.amount.as_numeric().clone().to_f64_lossy());
        emit_numeric_asset_transfer_events(
            state_transaction,
            movement.source_id,
            movement.destination_id,
            movement.amount,
        );
    }
    Ok(())
}
