//! Genuine available payload provenance distinguishes intrinsic bounds from local retry ownership.

use super::*;
use iroha_sumeragi::preimage::payload_hash;

#[test]
fn original_available_payload_global_archive_cap_is_invalid_inside_wider_scope() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let original = publication_tests::proposal(chain, worker);
        let mut malformed = original.payload().as_slice().to_vec();
        assert_eq!(&malformed[1..5], &norito::core::MAGIC);
        let limit = norito::core::max_archive_len();
        let length_offset = 1 + 4 + 1 + 1 + 16 + 1;
        malformed[length_offset..length_offset + 8].copy_from_slice(&(limit + 1).to_le_bytes());
        let mut header = original.header().clone();
        header.payload_hash = payload_hash(&**worker.context.crypto.as_ref().unwrap(), &malformed);
        header.payload_len = u32::try_from(malformed.len()).unwrap();
        // Actual four-validator custody authenticates these bytes; nested framing still decides validity.
        let block = chain.author_payload(header, malformed);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let source = std::ptr::from_ref(block.source());
        let bytes = block.payload().as_slice().as_ptr();
        let height = worker.state.view().height();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64),
            || {
                let original_error =
                    norito::core::from_bytes_view(&block.payload().as_slice()[1..])
                        .err()
                        .unwrap();
                assert!(
                    matches!(original_error, norito::Error::ArchiveLengthExceeded {
                    length, limit: actual_limit
                } if length == limit + 1 && actual_limit == limit)
                );
                assert!(
                    matches!(
                        payload::decode(block.payload().as_slice()),
                        Err(payload::PayloadError::NotCanonical(_))
                    ),
                    "a globally impossible declared archive must never borrow an unrelated outer budget"
                );
                assert!(matches!(
                    worker.execute(&block, hash, false),
                    Some(ExecOutcome::Invalid)
                ));
            },
        );
        let (cached_source, verdict) = worker
            .results
            .get(&hash)
            .expect("completed negative result");
        assert_eq!(cached_source, block.source());
        assert!(matches!(verdict, ExecOutcome::Invalid));
        assert!(worker.routing_refusal.is_none());
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.recovery.is_none());
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), height);
        assert_eq!(std::ptr::from_ref(block.source()), source);
        assert_eq!(block.payload().as_slice().as_ptr(), bytes);
        assert!(matches!(
            worker.execute(&block, hash, false),
            Some(ExecOutcome::Invalid)
        ));
        assert_eq!(worker.results.len(), 1);
    });
}

fn assert_original_local_refusal<const N: usize>(ceilings: [norito::DecodeLimits; N]) {
    publication_tests::with_worker(move |chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let source = std::ptr::from_ref(block.source());
        let bytes = block.payload().as_slice().as_ptr();
        let height = worker.state.view().height();
        for limits in ceilings {
            let error = norito::with_decode_limits_scope(limits, || {
                iroha_data_model::block::decode_framed_signed_block(block.payload().as_slice())
            })
            .unwrap_err();
            assert!(
                error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit,
                "genuine original decoder refusal: {error:?}"
            );
            assert!(matches!(
                norito::with_decode_limits_scope(limits, || worker.execute(&block, hash, false)),
                Some(ExecOutcome::Failed(_))
            ));
            let owner = worker
                .routing_refusal
                .as_ref()
                .expect("worker retains original typed decoder reason");
            assert_eq!(
                owner.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            assert!(
                owner.allocation_refusal().is_none(),
                "a scoped counter cannot invent a pool release owner"
            );
            assert!(!worker.results.contains_key(&hash));
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.recovery.is_none());
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), height);
            assert_eq!(std::ptr::from_ref(block.source()), source);
            assert_eq!(block.payload().as_slice().as_ptr(), bytes);
        }
        assert!(matches!(
            worker.execute(&block, hash, false),
            Some(ExecOutcome::Valid { .. })
        ));
        assert!(worker.routing_refusal.is_none());
        assert_eq!(
            worker.state.view().height(),
            height,
            "execution does not publish"
        );
        assert_eq!(std::ptr::from_ref(block.source()), source);
        assert_eq!(block.payload().as_slice().as_ptr(), bytes);
    });
}

#[test]
fn original_available_payload_local_decode_refusal_keeps_typed_worker_reason_and_retry() {
    assert_original_local_refusal([
        norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 64),
    ]);
}

#[test]
fn original_available_payload_narrow_depth_refusal_keeps_typed_worker_reason_and_retry() {
    assert_original_local_refusal([norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
    )]);
}
