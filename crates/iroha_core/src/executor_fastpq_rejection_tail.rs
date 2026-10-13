//! Bound the complete post-rejection source tail before signed body work starts.
//!
//! At most one retained ballot slash and one PipelineGas transfer share the same
//! E owner. Nexus burn/receipt settlement contributes no transfer. These public
//! shape exemplars neither replace the live ledger nor describe an executable
//! witness; every original quantity uses the widest legal positive encoding.

use super::*;
use crate::fastpq::{
    FastpqSourceStatementBuildLimits,
    source_prefix_lengths::{
        PrefixLengthError,
        entry::{EntryFrameLengthError, measure_fastpq_source_entry_frame_usage},
    },
    source_reservation::admission::SOURCE_INTRINSIC_REJECTION,
};
use iroha_data_model::{
    fastpq::{TransferDeltaTranscript, TransferSmtWitness, TransferTranscript},
    isi::governance::{CastPlainBallot, CastZkBallot},
    parameter::FastpqSourceLimitsV1,
};
use iroha_primitives::{
    bigint::BigInt,
    numeric::{MAX_DECIMAL_SCALE, MAX_MANTISSA_BYTES},
};

#[derive(std::fmt::Debug)]
enum TailError {
    Intrinsic,
    ReceiverDeferred(crate::execution_attempt::ExecutionDeferred),
    Fault(String),
}

struct TransferIdentities<'a> {
    from: &'a AccountId,
    to: &'a AccountId,
    asset: &'a AssetDefinitionId,
}

fn construction(
    value: FastpqSourceLimitsV1,
) -> Result<FastpqSourceStatementBuildLimits, TailError> {
    let length = |value: u64| {
        usize::try_from(value)
            .map_err(|_| TailError::Fault("FASTPQ intrinsic exceeds host length width".into()))
    };
    Ok(FastpqSourceStatementBuildLimits {
        max_executed_entries: value.max_executed_entries,
        max_transcripts: length(u64::from(value.max_transcripts))?,
        max_deltas: length(u64::from(value.max_deltas))?,
        max_input_transcript_bytes: length(value.max_input_transcript_bytes)?,
        max_statement_bytes: length(value.max_statement_bytes)?,
        max_total_statement_bytes: length(value.max_total_statement_bytes)?,
    })
}

fn widest_quantity() -> Result<Quantity, TailError> {
    let mut bytes = [0xff; MAX_MANTISSA_BYTES];
    *bytes.last_mut().expect("quantity mantissa is nonempty") = 0x7f;
    let integer =
        BigInt::from_twos_bytes(&bytes).map_err(|error| TailError::Fault(error.to_string()))?;
    let numeric = Numeric::try_new(integer, MAX_DECIMAL_SCALE)
        .map_err(|error| TailError::Fault(error.to_string()))?;
    Quantity::try_from_numeric(numeric).map_err(|error| TailError::Fault(error.to_string()))
}

fn classify(error: EntryFrameLengthError) -> TailError {
    match error {
        EntryFrameLengthError::Bound(_)
        | EntryFrameLengthError::Prefix(
            PrefixLengthError::Deltas { .. }
            | PrefixLengthError::Input { .. }
            | PrefixLengthError::Public { .. },
        ) => TailError::Intrinsic,
        other => TailError::Fault(other.to_string()),
    }
}

fn measure_tail(
    hash: iroha_crypto::Hash,
    tails: &[TransferIdentities<'_>],
    ceiling: FastpqSourceLimitsV1,
) -> Result<crate::fastpq::FastpqSourceTranscriptUsage, TailError> {
    if tails.len() > 2 {
        return Err(TailError::Fault(
            "rejection tail has more than two movements".into(),
        ));
    }
    let limits = construction(ceiling)?;
    if ceiling.max_executed_entries == 0
        || tails.len() > limits.max_transcripts
        || tails.len() > limits.max_deltas
    {
        return Err(TailError::Intrinsic);
    }
    // Count actual variable identities before cloning any into source exemplars.
    let mut identity_bytes = 0_u64;
    for tail in tails {
        for length in [
            norito::canonical_frame_len(tail.from),
            norito::canonical_frame_len(tail.to),
            norito::canonical_frame_len(tail.asset),
        ] {
            let length =
                u64::try_from(length.map_err(|error| TailError::Fault(error.to_string()))?)
                    .map_err(|_| {
                        TailError::Fault("rejection identity length exceeds u64".into())
                    })?;
            identity_bytes = identity_bytes
                .checked_add(length)
                .ok_or_else(|| TailError::Fault("rejection identity lengths overflow".into()))?;
            if identity_bytes > ceiling.max_input_transcript_bytes {
                return Err(TailError::Intrinsic);
            }
        }
    }
    let quantity = widest_quantity()?;
    let mut transcripts = Vec::with_capacity(tails.len());
    for tail in tails {
        transcripts.push(TransferTranscript {
            batch_hash: hash,
            authority_digest: hash,
            poseidon_preimage_digest: Some(hash),
            deltas: vec![TransferDeltaTranscript {
                from_account: tail.from.clone(),
                to_account: tail.to.clone(),
                asset_definition: tail.asset.clone(),
                amount: quantity.clone(),
                from_balance_before: quantity.clone(),
                from_balance_after: quantity.clone(),
                to_balance_before: quantity.clone(),
                to_balance_after: quantity.clone(),
                from_smt_witness: TransferSmtWitness::default(),
                to_smt_witness: TransferSmtWitness::default(),
            }],
        });
    }
    measure_fastpq_source_entry_frame_usage(hash, &transcripts, limits).map_err(classify)
}

fn check(
    state: &StateTransaction<'_, '_>,
    authority: &AccountId,
    transaction: &SignedTransaction,
    fee_quote: Option<&FeeAdmissionQuote>,
    ballot: Option<&InstructionBox>,
) -> Result<(), TailError> {
    let hash = iroha_crypto::Hash::from(transaction.hash_as_entrypoint());
    let ceiling = state
        .fastpq_rejection_tail_context(hash)
        .map_err(TailError::Fault)?;
    let mut tails = Vec::with_capacity(2);
    // Penalties settle first. The owner is always the authenticated authority,
    // never a caller-controlled plain owner or a ZK public-input hint.
    if let Some(ballot) = ballot {
        let referendum = if let Some(plain) = ballot.as_any().downcast_ref::<CastPlainBallot>() {
            &plain.referendum_id
        } else if let Some(zk) = ballot.as_any().downcast_ref::<CastZkBallot>() {
            &zk.election_id
        } else {
            return Err(TailError::Fault(
                "signed ballot binding has a non-ballot instruction".into(),
            ));
        };
        if let Some(record) = state
            .world
            .governance_locks
            .get(referendum)
            .and_then(|group| group.locks.get(authority))
        {
            if &record.owner != authority {
                return Err(TailError::Fault(
                    "retained governance owner differs from its key".into(),
                ));
            }
            if record.custody.escrowed && !record.amount.is_zero() {
                tails.push(TransferIdentities {
                    from: &record.custody.bond_escrow_account,
                    to: &record.custody.slash_receiver_account,
                    asset: &record.custody.asset_definition_id,
                });
            }
        }
    }
    let gas = fee_quote.and_then(|quote| {
        quote
            .charges
            .iter()
            .find(|charge| charge.kind == FeeChargeKind::PipelineGas && !charge.max_bound.is_zero())
            .map(|charge| (quote, charge))
    });
    let receiver = if gas.is_some() {
        Some(
            crate::pipeline_gas_policy::receiver_id(&state.pipeline.gas.tech_account_id).map_err(
                |error| match crate::execution_attempt::norito_decode_attempt_error(
                    error,
                    |error| format!("invalid committed pipeline gas receiver: {error}"),
                ) {
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        TailError::ReceiverDeferred(reason)
                    }
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                        TailError::Fault(error)
                    }
                },
            )?,
        )
    } else {
        None
    };
    if let Some((quote, charge)) = gas {
        let payer = match &quote.debit_source {
            FeeDebitSource::Account(account) if account == authority => account,
            FeeDebitSource::SponsorProgram(program)
                if transaction
                    .fee_payment_intent()
                    .sponsor_program()
                    .is_some_and(|(selected, _)| selected == program) =>
            {
                &state.nexus.fees.sponsor_vault_custody_account_id
            }
            _ => {
                return Err(TailError::Fault(
                    "fee quote payer differs from signed source".into(),
                ));
            }
        };
        tails.push(TransferIdentities {
            from: payer,
            to: receiver
                .as_ref()
                .ok_or_else(|| TailError::Fault("gas receiver is absent".into()))?,
            asset: &charge.asset_definition_id,
        });
    }
    measure_tail(hash, &tails, ceiling)?;
    Ok(())
}

/// Admit the read-only complete rejection shape before fee/effect work begins.
/// Capacity is a canonical rejection; ownership/codec faults abort the carrier.
pub(super) fn preflight(
    state: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    transaction: &SignedTransaction,
    fee_quote: Option<&FeeAdmissionQuote>,
    ballot: Option<&InstructionBox>,
) -> Result<(), ValidationFail> {
    match check(state, authority, transaction, fee_quote, ballot) {
        Ok(()) => Ok(()),
        Err(TailError::Intrinsic) => Err(ValidationFail::NotPermitted(
            SOURCE_INTRINSIC_REJECTION.into(),
        )),
        Err(TailError::ReceiverDeferred(reason)) => Err(state.defer_execution(reason)),
        Err(TailError::Fault(error)) => {
            state.fail_fastpq_rejection_tail(error.clone());
            Err(ValidationFail::InternalError(error))
        }
    }
}

#[cfg(test)]
#[path = "executor_fastpq_rejection_tail/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "executor_fastpq_rejection_tail/sponsored_alias_tests.rs"]
mod sponsored_alias_tests;
