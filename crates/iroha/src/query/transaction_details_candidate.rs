//! Convert a canonical details response to a selective-query candidate, never to trusted evidence.
use super::{QueryError, validate_transaction_details_bindings};
use eyre::eyre;
use iroha_crypto::HashOf;
use iroha_data_model::{
    query::{QueryOutput, QueryOutputBatchBox, QueryResponse},
    transaction::TransactionEntrypoint,
};
use iroha_torii_shared::PipelineTransactionDetailsResponse;

/// Rewrap one exact canonical transaction-details row as a bounded query candidate.
///
/// The original details bytes remain the caller's responsibility to retain. This
/// function only checks canonical encoding and local source/output self-bindings.
/// It preserves the full committed row, including successful or rejected results,
/// unchanged. The output is **untrusted**: authenticate it against the retained
/// signed original and a consecutive finality chain from an independently admitted
/// checkpoint before relying on the transaction or its effects.
///
/// `max_response_bytes` bounds both the original details frame and the emitted
/// query frame. The encoded output size is measured before allocating that frame.
/// No network call, signing, timestamp promotion, or proof construction occurs.
///
/// # Errors
/// Refuses an empty, oversized, malformed or noncanonical original, invalid size
/// bounds, a different entrypoint, inconsistent source/output bindings, or a
/// converted frame exceeding the selected bound.
pub fn transaction_details_candidate_response_v1(
    details_original: &[u8],
    expected_entrypoint: HashOf<TransactionEntrypoint>,
    max_response_bytes: usize,
) -> Result<Vec<u8>, QueryError> {
    if max_response_bytes == 0
        || max_response_bytes > super::TRANSACTION_DETAILS_RESPONSE_MAX_BYTES
        || details_original.is_empty()
        || details_original.len() > max_response_bytes
    {
        return Err(eyre!("transaction-details candidate violates its response byte bound").into());
    }
    let details: PipelineTransactionDetailsResponse = norito::decode_canonical_with_limits(
        details_original,
        norito::canonical_decode_limits(details_original.len()),
    )
    .map_err(|error| QueryError::Other(eyre!("invalid canonical transaction details: {error}")))?;
    validate_transaction_details_bindings(&details, expected_entrypoint)
        .map_err(QueryError::from)?;
    let response = QueryResponse::Iterable(QueryOutput::new_bounded(
        QueryOutputBatchBox::CommittedTransaction(vec![details.transaction]).into(),
        false,
        None,
    ));
    let encoded_len = norito::canonical_frame_len(&response).map_err(|error| {
        QueryError::Other(eyre!("cannot measure transaction candidate: {error}"))
    })?;
    if encoded_len > max_response_bytes {
        return Err(eyre!("transaction query candidate exceeds its response byte bound").into());
    }
    let encoded = norito::encode_canonical(&response).map_err(|error| {
        QueryError::Other(eyre!("cannot encode transaction candidate: {error}"))
    })?;
    if encoded.len() != encoded_len {
        return Err(eyre!("transaction query candidate differs from its measured size").into());
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, MerkleProof};
    use iroha_data_model::{
        block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        executor::ValidationFail,
        isi::error::{InstructionExecutionError, InvalidParameterError},
        query::CommittedTransaction,
        transaction::{
            DataTriggerSequence, FeePaymentIntent, TransactionBuilder, TransactionResult,
            error::TransactionRejectionReason,
        },
    };

    fn fixture(rejected: bool) -> PipelineTransactionDetailsResponse {
        let (authority, key_pair) = iroha_test_samples::gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            crate::client::test_network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .try_sign(key_pair.private_key())
        .unwrap();
        let entrypoint = TransactionEntrypoint::External(signed);
        let entrypoint_hash = entrypoint.hash();
        let result = if rejected {
            Err(TransactionRejectionReason::Validation(
                ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract("candidate rejection retained".to_owned()),
                )),
            ))
        } else {
            Ok(DataTriggerSequence::default())
        };
        let output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: TransactionResult::new(result),
            completions: Vec::new(),
        });
        PipelineTransactionDetailsResponse {
            hash: entrypoint_hash.to_string(),
            transaction: CommittedTransaction {
                block_hash: HashOf::from_untyped_unchecked(Hash::prehashed([0x77; Hash::LENGTH])),
                entrypoint_hash,
                entrypoint_proof: MerkleProof::from_audit_path(0, Vec::new()),
                entrypoint,
                output_hash: HashOf::new(&output),
                output_proof: MerkleProof::from_audit_path(0, Vec::new()),
                output,
            },
        }
    }

    fn convert(details: &PipelineTransactionDetailsResponse) -> Result<Vec<u8>, QueryError> {
        transaction_details_candidate_response_v1(
            &norito::encode_canonical(details).unwrap(),
            details.transaction.entrypoint_hash,
            512 * 1024,
        )
    }

    #[test]
    fn details_candidate_preserves_exact_success_and_rejection_without_proving_them() {
        for rejected in [false, true] {
            let details = fixture(rejected);
            let source = norito::encode_canonical(&details.transaction).unwrap();
            let encoded = convert(&details).unwrap();
            let response: QueryResponse = norito::decode_canonical(&encoded).unwrap();
            let QueryResponse::Iterable(output) = response else {
                panic!("iterable required")
            };
            let (batch, remaining, has_more, cursor) = output.into_parts_with_count_mode();
            assert_eq!(remaining, None);
            assert!(!has_more);
            assert!(cursor.is_none());
            assert_eq!(batch.column_count(), 1);
            assert_eq!(batch.len(), 1);
            let QueryOutputBatchBox::CommittedTransaction(rows) = batch.into_columns().remove(0)
            else {
                panic!("exact transaction column required")
            };
            assert_eq!(norito::encode_canonical(&rows[0]).unwrap(), source);
            assert_eq!(rows[0].result().is_err(), rejected);
        }
    }

    #[test]
    fn details_candidate_refuses_wrong_entrypoint_or_inconsistent_hashes() {
        let details = fixture(false);
        let wire = norito::encode_canonical(&details).unwrap();
        let wrong = HashOf::from_untyped_unchecked(Hash::prehashed([0x31; Hash::LENGTH]));
        assert!(transaction_details_candidate_response_v1(&wire, wrong, 512 * 1024).is_err());
        let mut changed = details.clone();
        changed.hash = wrong.to_string();
        assert!(convert(&changed).is_err());
        let mut changed = details.clone();
        changed.transaction.entrypoint_hash = wrong;
        changed.hash = wrong.to_string();
        assert!(convert(&changed).is_err());
        let mut changed = details.clone();
        changed.transaction.output_hash =
            HashOf::from_untyped_unchecked(Hash::prehashed([0x42; Hash::LENGTH]));
        assert!(convert(&changed).is_err());
    }

    #[test]
    fn details_candidate_refuses_mismatched_input_index_even_with_rehashed_output() {
        let mut details = fixture(false);
        let ExecutionOutputV1::Network(output) = &mut details.transaction.output else {
            panic!("network output required")
        };
        output.input_index = 1;
        details.transaction.output_hash = HashOf::new(&details.transaction.output);
        assert!(convert(&details).is_err());
    }

    #[test]
    fn details_candidate_retains_untrusted_proof_bytes_without_authenticating_them() {
        let mut details = fixture(false);
        details.transaction.block_hash =
            HashOf::from_untyped_unchecked(Hash::prehashed([0xab; Hash::LENGTH]));
        details.transaction.entrypoint_proof = MerkleProof::from_audit_path(
            0,
            vec![Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                [0xcd; Hash::LENGTH],
            )))],
        );
        let original = norito::encode_canonical(&details.transaction).unwrap();
        let encoded = convert(&details).unwrap();
        let QueryResponse::Iterable(output) = norito::decode_canonical(&encoded).unwrap() else {
            panic!("iterable required")
        };
        let QueryOutputBatchBox::CommittedTransaction(rows) = output.batch.into_columns().remove(0)
        else {
            panic!("transaction column required")
        };
        assert_eq!(norito::encode_canonical(&rows[0]).unwrap(), original);
        // Acceptance here means candidate conversion only; the modified carrier
        // and Merkle path still require independent finality verification.
    }

    #[test]
    fn details_candidate_refuses_noncanonical_empty_foreign_and_oversized_frames() {
        let details = fixture(false);
        let hash = details.transaction.entrypoint_hash;
        let wire = norito::encode_canonical(&details).unwrap();
        for bound in [
            0,
            wire.len() - 1,
            super::super::TRANSACTION_DETAILS_RESPONSE_MAX_BYTES + 1,
        ] {
            assert!(transaction_details_candidate_response_v1(&wire, hash, bound).is_err());
        }
        for bad in [Vec::new(), vec![0xff, 0x01], convert(&details).unwrap()] {
            assert!(transaction_details_candidate_response_v1(&bad, hash, 512 * 1024).is_err());
        }
        let mut trailing = wire;
        trailing.push(0);
        assert!(transaction_details_candidate_response_v1(&trailing, hash, 512 * 1024).is_err());
    }

    #[test]
    fn details_candidate_exact_input_and_output_bound_is_accepted() {
        let details = fixture(false);
        let wire = norito::encode_canonical(&details).unwrap();
        let output = convert(&details).unwrap();
        let bound = wire.len().max(output.len());
        assert_eq!(
            transaction_details_candidate_response_v1(
                &wire,
                details.transaction.entrypoint_hash,
                bound,
            )
            .unwrap(),
            output
        );
        assert!(
            transaction_details_candidate_response_v1(
                &wire,
                details.transaction.entrypoint_hash,
                bound - 1,
            )
            .is_err()
        );
    }
}
