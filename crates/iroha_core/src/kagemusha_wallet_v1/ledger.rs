//! Verified operations and atomic ledger batches.
use super::*;

/// Verify Bootstrap and permanently record activation before permitting any load.
///
/// # Errors
/// Rejects invalid signatures/proofs, unregistered bindings, abandonment, or another Bootstrap.
pub fn activate(
    tx: &mut impl Transaction,
    verifier: &impl NativePackageVerifier,
    activation: &KagemushaWalletActivationV1,
) -> Result<()> {
    let c = &activation.credential.body;
    let registration = tx.registration(&c.scheme_id, &c.asset_digest)?;
    registration.require(&c.scheme_id, &c.asset_digest)?;
    if registration.asset != activation.asset {
        return Err(Error::Binding);
    }
    activation.verify(&registration.scheme)?;
    verifier.verify(
        &registration.scheme,
        &activation.credential,
        &activation.bootstrap,
    )?;
    let digest = activation.bootstrap.verify(&activation.credential)?.package;
    if let Some(record) = tx.wallet(&c.scheme_id, &c.wallet_id)? {
        if record.asset != c.asset_digest || record.activation != digest {
            return Err(Error::Conflict);
        }
        if record.phase == Phase::Abandoned {
            return Err(Error::Lifecycle);
        }
        // An exact activation retry must not reopen a closed wallet.
        return Ok(());
    }
    let mut batch = Batch::new(c.scheme_id, c.asset_digest);
    batch.wallet = Some((
        c.wallet_id,
        WalletRecord {
            asset: c.asset_digest,
            phase: Phase::Active,
            activation: digest,
            next_load: 0,
        },
    ));
    tx.apply(batch)
}

/// Permanently disable an unused enrollment. Activated incarnations cannot be abandoned.
///
/// # Errors
/// Rejects invalid signed controls, unregistered bindings, or prior activation/load issuance.
pub fn abandon(
    tx: &mut impl Transaction,
    abandonment: &KagemushaWalletAbandonmentV1,
) -> Result<()> {
    abandonment.validate()?;
    let c = &abandonment.control.body;
    tx.registration(&c.scheme_id, &c.asset_digest)?
        .require(&c.scheme_id, &c.asset_digest)?;
    if let Some(record) = tx.wallet(&c.scheme_id, &c.wallet_id)? {
        return if record.phase == Phase::Abandoned && record.asset == c.asset_digest {
            Ok(())
        } else {
            Err(Error::Lifecycle)
        };
    }
    let mut batch = Batch::new(c.scheme_id, c.asset_digest);
    batch.wallet = Some((
        c.wallet_id,
        WalletRecord {
            asset: c.asset_digest,
            phase: Phase::Abandoned,
            activation: [0; 32],
            next_load: 0,
        },
    ));
    tx.apply(batch)
}

/// Close issuance atomically after proving all previously issued loads were absorbed.
///
/// # Errors
/// Rejects invalid proofs, unactivated/abandoned wallets, or an unabsorbed issued load.
pub fn close_loads(
    tx: &mut impl Transaction,
    verifier: &impl NativePackageVerifier,
    close: &KagemushaWalletCloseLoadsV1,
) -> Result<()> {
    let c = &close.credential.body;
    let registration = tx.registration(&c.scheme_id, &c.asset_digest)?;
    registration.require(&c.scheme_id, &c.asset_digest)?;
    close.verify(&registration.scheme)?;
    verifier.verify(&registration.scheme, &close.credential, &close.package)?;
    let mut record = tx
        .wallet(&c.scheme_id, &c.wallet_id)?
        .ok_or(Error::Lifecycle)?;
    if record.asset != c.asset_digest {
        return Err(Error::Binding);
    }
    if record.phase == Phase::Abandoned {
        return Err(Error::Lifecycle);
    }
    // Issuance is successive from zero, so equality proves no load >= next_load exists.
    if record.next_load != close.package.statement.next_load {
        return Err(Error::OutstandingLoad);
    }
    if record.phase == Phase::Closed {
        return Ok(());
    }
    record.phase = Phase::Closed;
    let mut batch = Batch::new(c.scheme_id, c.asset_digest);
    batch.wallet = Some((c.wallet_id, record));
    tx.apply(batch)
}

/// Debit the authenticated payer, reserve the exact offline value and assign the next ordinal.
/// The returned receipt is authenticated only after its ordinary transaction finalizes.
///
/// # Errors
/// Rejects inactive wallets, changed retry inputs, invalid quotes, overflow or unfunded debits.
pub fn issue_load(tx: &mut impl Transaction, command: &LoadCommand) -> Result<Issuance> {
    if command.request_id == [0; 32] || command.amount == 0 || tx.block_height() < 2 {
        return Err(Error::Binding);
    }
    let mut record = tx
        .wallet(&command.scheme, &command.wallet)?
        .ok_or(Error::Lifecycle)?;
    if record.asset != command.asset {
        return Err(Error::Binding);
    }
    let registration = tx.registration(&command.scheme, &record.asset)?;
    registration.require(&command.scheme, &record.asset)?;
    if let Some(prior) = tx.issuance(&command.scheme, &command.wallet, &command.request_id)? {
        if prior.command != *command
            || prior.payer != *tx.authority()
            || prior.body.transaction_hash != tx.transaction_hash()
            || prior.body.block_height != tx.block_height()
        {
            return Err(Error::Conflict);
        }
        // Only deterministic retry of the original execution can reuse its receipt.
        // A later transaction must fail so successful input identifies the original issuance.
        return Ok(prior);
    }
    if record.phase != Phase::Active {
        return Err(Error::Lifecycle);
    }
    if record.next_load != command.ordinal {
        return Err(Error::Conflict);
    }
    if *tx.authority() == registration.reserve {
        return Err(Error::Binding);
    }
    let ordinal = record.next_load;
    record.next_load = ordinal.checked_add(1).ok_or(Error::Overflow)?;
    let mut batch = Batch::new(command.scheme, record.asset);
    batch.transfers.push(Transfer {
        from: tx.authority().clone(),
        to: registration.reserve,
        amount: command.amount,
    });
    let (online_charge, charge_quote) = if let Some(charge) = &command.charge {
        let quote = &charge.quote;
        let certificate = tx.certificate(&command.scheme, &quote.body.signer_certificate)?;
        quote.verify(&registration.scheme, &certificate)?;
        quote.require_terms(
            KagemushaWalletChargeKindV1::Load,
            &command.wallet,
            ordinal,
            command.amount,
            quote.body.online_charge,
        )?;
        if quote.body.asset_digest != record.asset
            || kagemusha_wallet_account_digest_v1(&charge.beneficiary)?
                != quote.body.beneficiary_account_digest
        {
            return Err(Error::Binding);
        }
        command
            .amount
            .checked_add(quote.body.online_charge)
            .ok_or(Error::Overflow)?;
        batch.transfers.push(Transfer {
            from: tx.authority().clone(),
            to: charge.beneficiary.clone(),
            amount: quote.body.online_charge,
        });
        (quote.body.online_charge, quote.charge_quote_digest())
    } else {
        (0, [0; 32])
    };
    let body = KagemushaWalletLoadReceiptV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: command.scheme,
        asset_digest: record.asset,
        wallet_id: command.wallet,
        ordinal,
        amount: command.amount,
        online_charge,
        charge_quote,
        transaction_hash: tx.transaction_hash(),
        block_height: tx.block_height(),
        request_id: command.request_id,
        payer_account_digest: kagemusha_wallet_account_digest_v1(tx.authority())?,
    };
    body.validate()?;
    let issuance = Issuance {
        command: command.clone(),
        payer: tx.authority().clone(),
        body,
    };
    batch.wallet = Some((command.wallet, record));
    batch.issuance = Some(issuance.clone());
    tx.apply(batch)?;
    Ok(issuance)
}

fn prior_payout(
    tx: &impl Transaction,
    scheme: &Digest,
    key: KagemushaWalletPayoutKeyV1,
    source: Digest,
    amount: u128,
) -> Result<Option<KagemushaWalletPayoutRecordV1>> {
    let prior = tx.payout(scheme, key)?;
    if prior
        .as_ref()
        .is_some_and(|p| p.key != key || p.source != source || p.amount != amount)
    {
        return Err(Error::Conflict);
    }
    Ok(prior)
}

/// Pay a verified Unload once at face value, split only by its signed online charge.
///
/// # Errors
/// Rejects invalid proofs, conflicting nullifiers, wrong bindings or an unfunded reserve.
pub fn pay_unload(
    tx: &mut impl Transaction,
    verifier: &impl NativePackageVerifier,
    claim: &KagemushaWalletUnloadClaimV1,
) -> Result<KagemushaWalletPayoutRecordV1> {
    let c = &claim.credential.body;
    let registration = tx.registration(&c.scheme_id, &c.asset_digest)?;
    registration.require(&c.scheme_id, &c.asset_digest)?;
    let paid = claim.verify(&registration.scheme)?;
    verifier.verify(&registration.scheme, &claim.credential, &claim.package)?;
    let key = KagemushaWalletPayoutKeyV1::Unload(paid.nullifier);
    if let Some(prior) = prior_payout(tx, &c.scheme_id, key, paid.package, paid.amount)? {
        return Ok(prior);
    }
    let payout = KagemushaWalletPayoutRecordV1 {
        key,
        source: paid.package,
        amount: paid.amount,
        transaction: tx.transaction_hash(),
    };
    let mut batch = Batch::new(c.scheme_id, c.asset_digest);
    if paid.account_payout != 0 {
        batch.transfers.push(Transfer {
            from: registration.reserve.clone(),
            to: claim.account.clone(),
            amount: paid.account_payout,
        });
    }
    if let KagemushaWalletUnloadChargeV1::Quoted { beneficiary, .. } = &claim.charge {
        batch.transfers.push(Transfer {
            from: registration.reserve,
            to: beneficiary.clone(),
            amount: paid.online_charge,
        });
    }
    batch.payout = Some(payout);
    tx.apply(batch)?;
    Ok(payout)
}

/// Pay the historical fixed-beneficiary fee once per committed Send credit identity.
/// Delivery and the current fee schedule do not affect an already earned fee.
///
/// # Errors
/// Rejects missing historical records, invalid signatures/proofs, replay conflicts or insolvency.
pub fn pay_fee(
    tx: &mut impl Transaction,
    verifier: &impl NativePackageVerifier,
    claim: &KagemushaWalletFeeClaimV1,
) -> Result<KagemushaWalletPayoutRecordV1> {
    let c = &claim.payment.request.body;
    let registration = tx.registration(&c.scheme_id, &c.asset_digest)?;
    registration.require(&c.scheme_id, &c.asset_digest)?;
    let inputs = tx.fee_inputs(claim)?;
    let paid = claim.verify(
        &registration.scheme,
        &inputs.request,
        &inputs.payer,
        &inputs.certificates,
    )?;
    verifier.verify(&registration.scheme, &inputs.payer, &claim.payment.send)?;
    let key = KagemushaWalletPayoutKeyV1::Fee(paid.credit_id);
    if let Some(prior) = prior_payout(tx, &c.scheme_id, key, paid.payment, paid.fee)? {
        return Ok(prior);
    }
    let payout = KagemushaWalletPayoutRecordV1 {
        key,
        source: paid.payment,
        amount: paid.fee,
        transaction: tx.transaction_hash(),
    };
    let mut batch = Batch::new(c.scheme_id, c.asset_digest);
    batch.transfers.push(Transfer {
        from: registration.reserve,
        to: claim.beneficiary.clone(),
        amount: paid.fee,
    });
    batch.payout = Some(payout);
    tx.apply(batch)?;
    Ok(payout)
}
