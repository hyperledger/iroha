#[cfg(test)]
mod tests_queue_metadata {
    use super::*;
    #[test]
    fn queue_errors_map_to_reason_codes() {
        let cases = [
            (
                queue::Error::Full,
                "PRTRY:QUEUE_FULL",
                "transaction queue is at capacity",
            ),
            (
                queue::Error::MaximumTransactionsPerUser,
                "PRTRY:QUEUE_RATE",
                "authority reached per-user queue capacity",
            ),
            (
                queue::Error::Expired,
                "ED07",
                "transaction expired before admission",
            ),
            (
                queue::Error::UnresolvedRoute {
                    reason: "lane 9 is unknown".to_owned(),
                },
                "PRTRY:ROUTE_UNRESOLVED",
                "transaction route could not be resolved: lane 9 is unknown",
            ),
            (
                queue::Error::InBlockchain,
                "PRTRY:ALREADY_COMMITTED",
                "transaction already committed to the blockchain",
            ),
            (
                queue::Error::IsInQueue,
                "PRTRY:ALREADY_ENQUEUED",
                "transaction already present in the queue",
            ),
        ];
        for (error, expected_code, expected_detail) in cases {
            // array copy, pattern moves
            let (code, detail) = queue_rejection_metadata(&error);
            assert_eq!(code, expected_code);
            assert_eq!(detail, expected_detail);
        }
    }
    #[test]
    fn local_fee_admission_refusal_reports_capacity_without_a_rejection_code() {
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let error = queue::Error::Deferred(original.clone().into());
        assert_eq!(Error::status_code_for_queue_error(&error), StatusCode::TOO_MANY_REQUESTS);
        let envelope = Error::queue_error_envelope(&error, None);
        assert_eq!(envelope.code, "admission_deferred");
        let details = envelope.details.unwrap();
        assert_eq!(details.retry_after_seconds, Some(1));
        assert!(details.reject_code.is_none());
        assert!(details.fee.is_none());
        let queue::Error::Deferred(owner) = error else { unreachable!() };
        assert_eq!(owner.allocation_refusal(), Some(&original));
        drop(occupied);
    }
    #[test]
    fn unsupported_current_queue_admission_has_permanent_canonical_error() {
        let error = queue::Error::UnsupportedTransactionAdmission {
            reason: "current consensus does not support multi-route transaction admission"
                .to_owned(),
        };
        assert_eq!(
            Error::status_code_for_queue_error(&error),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            Error::queue_error_summary(&error).0,
            "unsupported_transaction_admission"
        );
        assert_eq!(
            queue_rejection_metadata(&error).0,
            "PRTRY:UNSUPPORTED_TRANSACTION_ADMISSION"
        );
        let envelope = Error::queue_error_envelope(&error, None);
        assert_eq!(envelope.code, "unsupported_transaction_admission");
        assert!(envelope.details.unwrap().retry_after_seconds.is_none());
    }
    /// Torii stage of the resource contract (`specs/zk_resource_contract.json`): a transaction
    /// no block can carry is a permanent refusal, not backpressure, and its detail carries the
    /// actual and the permitted bytes.
    #[test]
    fn never_includable_transaction_refusal_is_permanent_and_reports_both_byte_counts() {
        let never = iroha_data_model::parameter::system::TransactionNeverIncludable {
            encoded_bytes: 4_128_769,
            max_bytes: 4_128_768,
        };
        let error = queue::Error::UnsupportedTransactionAdmission {
            reason: never.to_string(),
        };
        assert_eq!(
            Error::status_code_for_queue_error(&error),
            StatusCode::BAD_REQUEST
        );
        let (reject_code, detail) = queue_rejection_metadata(&error);
        assert_eq!(reject_code, "PRTRY:UNSUPPORTED_TRANSACTION_ADMISSION");
        assert!(
            detail.contains("4128769") && detail.contains("4128768"),
            "{detail}"
        );
        let envelope = Error::queue_error_envelope(&error, None);
        assert_eq!(envelope.code, "unsupported_transaction_admission");
        assert!(envelope.message.contains("a transaction a block can carry"));
        let details = envelope.details.unwrap();
        assert!(details.retry_after_seconds.is_none());
        assert_eq!(
            details.reject_code.as_deref(),
            Some("PRTRY:UNSUPPORTED_TRANSACTION_ADMISSION")
        );
    }
    #[test]
    fn queue_domain_mismatch_is_permanent_and_matches_stateless_rejection_category() {
        use iroha_data_model::{isi::error::Mismatch, transaction::TransactionDomain};
        let expected = TransactionDomain::Network(iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"queue expected network")),
        ));
        for actual in [
            TransactionDomain::Genesis,
            TransactionDomain::Network(iroha_data_model::NetworkId::from_genesis_hash(
                HashOf::from_untyped_unchecked(Hash::new(b"queue foreign network")),
            )),
        ] {
            let mismatch = Mismatch { expected, actual };
            let stateless =
                iroha_core::tx::AcceptTransactionFail::TransactionDomainMismatch(mismatch.clone());
            let error = queue::Error::TransactionDomainMismatch(mismatch);
            assert_eq!(
                Error::status_code_for_queue_error(&error),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                queue_rejection_metadata(&error).0,
                accept_transaction_metadata(&stateless).0
            );
            let envelope = Error::queue_error_envelope(&error, None);
            assert_eq!(envelope.code, "transaction_rejected");
            assert!(envelope.details.unwrap().retry_after_seconds.is_none());
            let response = Error::PushIntoQueue {
                source: Box::new(error),
                backpressure: queue::BackpressureState::default(),
            }
            .into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(!response.headers().contains_key("retry-after"));
        }
    }
}
