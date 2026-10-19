//! Bounded finalized-carrier reads and explicit Network output projections.

use std::num::NonZeroUsize;

use iroha_core::{execution_attempt::ExecutionAttemptError, smartcontracts::isi::tx, state::State};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    query::error::QueryExecutionFail,
    transaction::{SignedTransaction, TransactionEntrypoint, TransactionResult},
};

fn invalid(message: impl std::fmt::Display) -> QueryExecutionFail {
    QueryExecutionFail::Conversion(message.to_string())
}

/// Project a local read refusal only at the HTTP boundary, without inventing missing history.
pub fn query_attempt_error(error: ExecutionAttemptError<QueryExecutionFail>) -> crate::Error {
    let query_error = match error {
        ExecutionAttemptError::Deferred(_) => QueryExecutionFail::CapacityLimit,
        ExecutionAttemptError::Rejected(error) => error,
    };
    crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(query_error))
}

/// Preserve canonical body failures and allocation refusal until the HTTP boundary.
pub fn canonical_attempt_error(
    error: ExecutionAttemptError<iroha_data_model::query::error::CanonicalHistoryError>,
) -> crate::Error {
    query_attempt_error(error.map_rejection(QueryExecutionFail::CanonicalHistory))
}

/// Surface DA hydration pressure as a retryable HTTP refusal, never an empty index.
pub fn da_hydration_error(error: iroha_core::state::DaIndexHydrationError) -> crate::Error {
    match error {
        iroha_core::state::DaIndexHydrationError::Deferred(original) => {
            query_attempt_error(ExecutionAttemptError::Deferred(original))
        }
        error => crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
            error.to_string(),
        )),
    }
}

/// Authenticate and bound the whole carrier before projecting any output.
#[cfg(test)]
fn read_carrier(
    state: &State,
    height: NonZeroUsize,
    hash: HashOf<BlockHeader>,
    max_work: u64,
    max_bytes: u64,
) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<QueryExecutionFail>> {
    let carrier = state.read_finalized_execution_carrier(height, max_work, max_bytes)?;
    if carrier.block().hash() != hash {
        return Err(ExecutionAttemptError::Rejected(invalid(
            "native execution differs from its independently selected hash",
        )));
    }
    Ok(carrier.into_block())
}

/// Borrow signed calls after validating the complete output join; never zip trees.
pub fn signed_calls(
    block: &SignedBlock,
) -> Result<
    impl Iterator<
        Item = (
            HashOf<TransactionEntrypoint>,
            &SignedTransaction,
            &TransactionResult,
        ),
    >,
    QueryExecutionFail,
> {
    block.validate_output_merkle_cache().map_err(invalid)?;
    Ok(block.execution_outputs().iter().filter_map(|output| {
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) = output
        else {
            return None;
        };
        let source = block.network_entrypoint_at(output.input_index as usize)?;
        let signed = match source {
            TransactionEntrypoint::External(signed) => signed,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_) | TransactionEntrypoint::AnonymousBallot(_) => return None,
        };
        Some((source.hash(), signed, &output.result))
    }))
}

/// Resolve a unique ordinary signed submission from exact authenticated history.
/// Reveals and internal invocations cannot impersonate an external submission.
pub fn exact_external_outcome(
    state: &State,
    height: NonZeroUsize,
    hash: HashOf<BlockHeader>,
    target: &HashOf<SignedTransaction>,
) -> Result<(BlockHeader, Option<bool>), ExecutionAttemptError<QueryExecutionFail>> {
    let work = crate::routing::app_query_limits().max_fetch_size;
    let mut outcome = None;
    let mut duplicate = false;
    let header = tx::visit_finalized_network_transactions(
        state,
        height,
        hash,
        work,
        tx::transaction_history_byte_limit(work),
        |source, result| {
            if let TransactionEntrypoint::External(signed) = source
                && signed.hash() == *target
            {
                duplicate |= outcome.replace(result.is_ok()).is_some();
            }
        },
    )?;
    if duplicate {
        return Err(ExecutionAttemptError::Rejected(invalid(
            "signed submission has multiple finalized Network sources",
        )));
    }
    Ok((header, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        block::{builder::BlockBuilder, execution_output::*},
        events::{
            time::{TimeEvent, TimeInterval},
            trigger_completed::TriggerCompletedOutcome,
        },
        transaction::{FeePaymentIntent, TransactionBuilder, signed::ExecutionStep},
        trigger::DataTriggerStep,
    };

    #[test]
    fn original_block_proof_refusal_remains_retryable_instead_of_missing_or_corrupt() {
        use axum::{http::StatusCode, response::IntoResponse as _};
        use iroha_core::state::{AllocationBudget, BlockProofError};

        let pool = AllocationBudget::new(8);
        let held = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let deferred = BlockProofError::Deferred(original.into());
        assert_eq!(
            crate::map_block_proof_error(deferred)
                .into_response()
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
        );
        assert_eq!(pool.reserved_bytes(), 8);
        drop(held);
        let retry = pool.try_reserve_bytes(1).unwrap();
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);

        let height = std::num::NonZeroU64::new(1).unwrap();
        assert!(matches!(
            crate::map_block_proof_error(BlockProofError::BlockNotFound(height)),
            crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                QueryExecutionFail::NotFound
            ))
        ));
        assert!(matches!(
            crate::map_block_proof_error(BlockProofError::Storage {
                block_height: height,
                reason: "authenticated source is corrupt".into(),
            }),
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
    }

    #[test]
    fn original_da_hydration_refusal_remains_retryable_instead_of_an_empty_index() {
        use axum::response::IntoResponse as _;
        let pool = iroha_core::state::AllocationBudget::new(8);
        let _held = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let deferred = iroha_core::state::DaIndexHydrationError::Deferred(original.into());
        assert_eq!(
            da_hydration_error(deferred).into_response().status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
        let missing = iroha_core::state::DaIndexHydrationError::Completed(
            iroha_core::state::DaIndexHydrationFailure::MissingBlock {
                height: std::num::NonZeroU64::new(1).unwrap(),
            },
        );
        assert!(matches!(
            da_hydration_error(missing),
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
    }

    fn proposal() -> SignedBlock {
        let key = KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Ed25519).unwrap();
        let header = BlockHeader::new(
            std::num::NonZeroU64::new(2).unwrap(),
            Some(HashOf::from_untyped_unchecked(Hash::new(
                b"history fixture parent",
            ))),
            None,
            1_000,
            0,
        );
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"history fixture genesis")),
        );
        let mut transaction = TransactionBuilder::new(
            network,
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(std::time::Duration::from_millis(900));
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(transaction.sign(key.private_key()));
        builder.build_with_signature(0, key.private_key())
    }

    fn with_outputs() -> SignedBlock {
        let mut block = proposal();
        let trigger_id: iroha_data_model::trigger::TriggerId = "clock".parse().unwrap();
        let outputs = vec![
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result: TransactionResult::new(Ok(vec![])),
                completions: vec![],
            }),
            ExecutionOutputV1::Time(TimeExecutionOutputV1 {
                invocation: TimeInvocationV1 {
                    schedule_index: 0,
                    event: TimeEvent {
                        interval: TimeInterval {
                            since_ms: 999,
                            length_ms: 1,
                        },
                    },
                    trigger: TriggerUseV1 {
                        trigger_id: trigger_id.clone(),
                        registered_at_height: 1,
                        action_hash: Hash::new(b"clock action"),
                    },
                },
                result: TransactionResult::new(Ok(vec![DataTriggerStep {
                    id: trigger_id.clone(),
                    instructions: ExecutionStep(iroha_primitives::const_vec::ConstVec::new_empty()),
                }])),
                failure_root: None,
                completions: vec![InvocationCompletionV1 {
                    callback_index: 0,
                    trigger_id,
                    outcome: TriggerCompletedOutcome::Success,
                }],
            }),
        ];
        // This fixture also runs without app_api and its application test utilities.
        // Both successful rows declare one structural fragment; no State execution
        // or finality is inferred from attaching this collection.
        block
            .set_execution_outputs(
                outputs,
                2,
                Default::default(),
                vec![],
                Default::default(),
                Default::default(),
                &iroha_data_model::block::output_budget::ExecutionOutputLimits {
                    max_outputs: 16,
                    max_output_bytes: 1024 * 1024,
                    max_total_output_bytes: 2 * 1024 * 1024,
                    max_executed_wire_bytes: 4 * 1024 * 1024,
                },
            )
            .expect("complete structural history outputs");
        block
    }

    #[test]
    fn signed_calls_require_a_complete_output_collection() {
        assert!(signed_calls(&proposal()).is_err());
    }

    #[test]
    fn signed_calls_do_not_project_time_outputs_as_transactions() {
        let block = with_outputs();
        let calls = signed_calls(&block).unwrap().collect::<Vec<_>>();
        assert_eq!(block.execution_outputs().len(), 2);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, block.network_entrypoint_at(0).unwrap().hash());
        assert!(calls[0].2.is_ok());
    }

    #[test]
    fn completion_records_keep_internal_call_identity_without_network_index() {
        let block = with_outputs();
        let mut rows = vec![];
        assert!(
            crate::visit_trigger_completion_records_for_block(&block, 2, |row| {
                rows.push(row);
                true
            })
            .unwrap()
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entrypoint_index, None);
        assert_eq!(rows[0].completion.step_index, 0);
        assert_eq!(
            rows[0].completion.trigger_execution_hash,
            block.execution_outputs()[1]
                .execution_call_hash(block.hash(), &block)
                .unwrap()
                .to_string()
        );
        assert_ne!(
            rows[0].completion.trigger_execution_hash,
            block.network_entrypoint_at(0).unwrap().hash().to_string()
        );
        assert_eq!(rows[0].source, "execution_output");
        let mut visits = 0;
        assert!(
            !crate::visit_trigger_completion_records_for_block(&block, 2, |_| {
                visits += 1;
                false
            })
            .unwrap()
        );
        assert_eq!(visits, 1);
    }

    #[test]
    fn completion_queries_reject_the_removed_reconstruction_option() {
        assert!(
            norito::json::from_str::<crate::TriggerCompletionQuery>(
                r#"{"include_reconstructed":true}"#,
            )
            .is_err()
        );
        assert!(norito::json::from_str::<crate::TriggerCompletionQuery>("{}").is_ok());
    }

    #[test]
    fn read_carrier_rejects_zero_budget_and_missing_finality() {
        let state = State::new_for_testing(
            iroha_core::state::World::new(),
            iroha_core::kura::Kura::blank_kura_for_testing(),
            iroha_core::query::store::LiveQueryStore::start_test(),
        );
        let block = with_outputs();
        let height = NonZeroUsize::new(2).unwrap();
        assert!(matches!(
            read_carrier(&state, height, block.hash(), 0, 1),
            Err(ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
        assert!(read_carrier(&state, height, block.hash(), 16, 1024 * 1024).is_err());
    }
}
