//! Exact full-domain ordinary-source statements and private touched-tree paths.

use iroha_allocation::{AllocationBudget, AllocationReservation};

#[cfg(test)]
use fastpq_prover::gadgets::public_transfer_statement::{
    prepare_quantity_public_transfers, quantity_rows_for_public_preparation,
};
use fastpq_prover::{
    ProofSemantics,
    gadgets::public_transfer_statement::{
        DerivedTransferSmtWitnesses, PublicTransferLimits, TransferSmtBuildLimits,
        materialize_quantity_public_transfers, public_claims_from_transcripts,
    },
};
use iroha_data_model::fastpq::{
    FastpqPublicInputs, FastpqPublicTransferStatementV1, TransferTranscript,
};

use super::{public_inputs_from_dto, public_inputs_to_dto, state_transition_to_dto};

/// Locally constructed exact public statement and its corresponding private paths.
/// This result does not authenticate source finality or qualify a proof profile.
#[derive(Debug)]
pub struct FastpqQuantityStatement {
    statement: FastpqPublicTransferStatementV1,
    witnesses: DerivedTransferSmtWitnesses,
}

impl FastpqQuantityStatement {
    /// Original public transcript facts with canonical full-domain rows and derived roots.
    #[must_use]
    pub const fn statement(&self) -> &FastpqPublicTransferStatementV1 {
        &self.statement
    }

    /// Private paths preserving the statement's original chronological occurrences.
    #[must_use]
    pub const fn witnesses(&self) -> &DerivedTransferSmtWitnesses {
        &self.witnesses
    }

    /// Consume the construction without copying the public statement or private paths.
    #[must_use]
    pub fn into_parts(self) -> (FastpqPublicTransferStatementV1, DerivedTransferSmtWitnesses) {
        (self.statement, self.witnesses)
    }
}

/// Construct an exact ordinary-source statement over the complete ledger quantity domain.
///
/// Public limits apply before transcript projection. Original identities, quantities,
/// digest policy, occurrence order and repeated-key balances must all be consistent;
/// no public value is repaired. Supplied private paths are not used or copied. Derived
/// old/new roots describe the touched-balance tree; other caller inputs are retained.
/// Empty input preserves unchanged caller roots under ordinary-transfer semantics.
/// The original pool/reservation fund private SMT backing and its retained paths.
/// Public projections and canonical statement backing remain separate obligations;
/// this function never creates a replacement allocation pool.
///
/// The ordinary prover lane binds this exact full-domain statement to its canonical
/// compact artifact. Source authentication and finality remain the caller's responsibility.
///
/// # Errors
/// Rejects public/private construction bounds, malformed digests, invalid quantities,
/// arithmetic/chronology failures and inconsistent original public facts.
pub fn quantity_statement_from_finalized_transcripts(
    public_inputs: FastpqPublicInputs,
    transcripts: &[TransferTranscript],
    public_limits: PublicTransferLimits,
    tree_limits: TransferSmtBuildLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> fastpq_prover::Result<FastpqQuantityStatement> {
    if !reservation.belongs_to(budget) {
        return Err(fastpq_prover::Error::AllocationForeignPool);
    }
    let claims = public_claims_from_transcripts(transcripts, public_limits)?;
    #[cfg(test)]
    MATERIALIZER_INVOCATIONS.with(|count| count.set(count.get() + 1));
    let materialized = materialize_quantity_public_transfers(
        &claims,
        public_inputs_from_dto(&public_inputs),
        ProofSemantics::StateTransition,
        public_limits,
        tree_limits,
        budget,
        reservation,
    )?;
    let (transitions, inputs, ordering_hash, witnesses) = materialized.into_parts();
    let statement = FastpqPublicTransferStatementV1 {
        public_inputs: public_inputs_to_dto(&inputs),
        ordering_hash: ordering_hash.into(),
        transitions: transitions.iter().map(state_transition_to_dto).collect(),
        transcripts: claims,
    };
    Ok(FastpqQuantityStatement {
        statement,
        witnesses,
    })
}

/// Fixture-only funding for existing semantic controls; production passes its original pool.
#[cfg(test)]
pub(crate) fn quantity_statement_from_finalized_transcripts_for_testing(
    public_inputs: FastpqPublicInputs,
    transcripts: &[TransferTranscript],
    public_limits: PublicTransferLimits,
    tree_limits: TransferSmtBuildLimits,
) -> fastpq_prover::Result<FastpqQuantityStatement> {
    let updates = transcripts
        .iter()
        .try_fold(0_usize, |count, transcript| {
            count.checked_add(transcript.deltas.len().checked_mul(2)?)
        })
        .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)?;
    // Fund from actual fixture counts, independently of deliberately deficient
    // policy limits under test. Production still enforces the supplied policy.
    let funding = TransferSmtBuildLimits::for_update_limit(updates)
        .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)?;
    let bytes = funding.allocation_bytes(updates, updates)?;
    let budget = AllocationBudget::new(bytes);
    let mut reservation = budget.try_reserve_bytes(bytes)?;
    quantity_statement_from_finalized_transcripts(
        public_inputs,
        transcripts,
        public_limits,
        tree_limits,
        &budget,
        &mut reservation,
    )
}

#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static MATERIALIZER_INVOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Read this test thread's strict full materializer invocation count.
#[cfg(test)]
pub(crate) fn quantity_materializer_invocations_for_testing() -> usize {
    MATERIALIZER_INVOCATIONS.with(std::cell::Cell::get)
}

/// Count a strict finalized statement's exact canonical frame before private SMT work.
///
/// Roots, dataspace, slot, permission and transaction-set inputs are fixed-width model
/// fields, as is the ordering digest. Marked scratch roots satisfy public preparation;
/// their values affect bytes but cannot affect this canonical frame length. Original
/// public facts, every occurrence, exact full keys and quantity frames remain real.
/// Supplied private paths are neither read nor cloned here. Missing single-delta digests
/// are rejected by public preparation; this helper never predicts or repairs finalization.
///
/// This is size measurement, not a statement, proof, root or source authority.
///
/// # Errors
/// Rejects the same public preparation failures as the strict full-domain producer,
/// including invalid digest policy, arithmetic, chronology and explicit public bounds.
#[cfg(test)]
pub(crate) fn quantity_statement_frame_len_from_finalized_transcripts(
    transcripts: &[TransferTranscript],
    public_limits: PublicTransferLimits,
) -> fastpq_prover::Result<usize> {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let marked = iroha_crypto::Hash::prehashed([1; 32]).into();
    let inputs = fastpq_prover::PublicInputs {
        dsid: [0; 16],
        slot: 0,
        old_root: marked,
        new_root: marked,
        perm_root: [0; 32],
        tx_set_hash: [0; 32],
    };
    let claims = public_claims_from_transcripts(transcripts, public_limits)?;
    let transitions = quantity_rows_for_public_preparation(
        &claims,
        inputs,
        public_limits,
        public_limits.max_rows,
    )?;
    let prepared = prepare_quantity_public_transfers(
        &transitions,
        &claims,
        inputs,
        ProofSemantics::StateTransition,
        public_limits,
    )?;
    let ordering_hash = prepared.ordering_hash().into();
    let statement = FastpqPublicTransferStatementV1 {
        public_inputs: public_inputs_to_dto(&inputs),
        ordering_hash,
        transitions: transitions.iter().map(state_transition_to_dto).collect(),
        transcripts: claims,
    };
    norito::core::encoded_frame_len(&statement).map_err(|error| {
        fastpq_prover::Error::TransferInvariant {
            details: format!("canonical quantity statement measurement failed: {error}"),
        }
    })
}

#[cfg(test)]
mod tests;
