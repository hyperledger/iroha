//! Exact signed-transaction context used while replaying committed blocks.

use iroha_crypto::Hash;
use iroha_data_model::transaction::TransactionEntrypoint;

use super::StateTransaction;
use crate::tx::AcceptedTransaction;

/// Bind immutable replay identities without upgrading a sealed reveal to `External` provenance.
pub(crate) fn seed_committed_transaction_context(
    state_transaction: &mut StateTransaction<'_, '_>,
    entrypoint: &TransactionEntrypoint,
    entrypoint_index: usize,
) {
    state_transaction.bind_kagemusha_load_entrypoint_v1(None);
    state_transaction.current_network_entrypoint_hash = Some(entrypoint.hash());
    let transaction = match entrypoint {
        TransactionEntrypoint::External(transaction) => transaction,
        TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
        TransactionEntrypoint::SealedCommitment(_) => return,
    };
    state_transaction.tx_call_hash = Some(Hash::from(entrypoint.execution_call_hash()));
    state_transaction.current_tx_hash =
        Some(AcceptedTransaction::prepare_signed_metadata(transaction).signed_hash);
    let governance_ballot_binding =
        crate::state::standalone_governance_ballot_instruction_v1(transaction.instructions())
            .expect("committed governance ballot carrier must be exact");
    state_transaction.bind_governance_ballot_entrypoint_v1(governance_ballot_binding);
    state_transaction.current_entrypoint_index =
        Some(u64::try_from(entrypoint_index).unwrap_or(u64::MAX));
    if let TransactionEntrypoint::External(signed) = entrypoint {
        state_transaction.bind_kagemusha_load_entrypoint_v1(Some(signed));
    }
}
