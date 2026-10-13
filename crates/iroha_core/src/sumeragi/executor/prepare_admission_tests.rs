//! Actual funded Begin execution, first-Prepare admission and provisional rollback.

use super::*;
use iroha_data_model::asset::{AssetBalanceScope, AssetId};
use iroha_primitives::time::{MockTimeHandle, TimeSource};
use iroha_sumeragi::crypto::SigningError;
use mv::storage::StorageReadOnly;

fn with_paid_begin(
    test: impl FnOnce(&mut Worker<'_>, AvailableBody, Hash32, AssetId, MockTimeHandle, u64)
    + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("ct5-paid-original")
        .spawn(move || {
            crate::sumeragi::amx::with_paid_global_begin_fixture(|chain, signed| {
                let fee_asset = AssetId::with_scope(
                    signed.fee_payment_intent().charge_limits()[0]
                        .asset_definition_id
                        .clone(),
                    signed.authority().clone(),
                    AssetBalanceScope::Global,
                );
                let block_time_ms = chain.committed(chain.height()).block_time_ms()
                    + chain
                        .state()
                        .view()
                        .world()
                        .parameters()
                        .sumeragi()
                        .block_cadence_ms()
                        .get();
                let (clock, source) = TimeSource::new_mock(Duration::from_millis(block_time_ms));
                publication_tests::with_worker_chain_and_clock(
                    chain,
                    ConsensusMode::Permissioned,
                    Arc::new(lanes::merge::NoLanes),
                    source,
                    |chain, worker, _, _| {
                        let block =
                            publication_tests::proposal_with_transaction(chain, worker, |_, _| {
                                signed
                            });
                        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
                        test(worker, block, hash, fee_asset, clock, block_time_ms);
                    },
                );
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn ct5_post_encoding_clock_advance_rolls_back_actual_begin_and_fees_with_original_decode() {
    with_paid_begin(|worker, block, hash, fee_asset, clock, block_time_ms| {
        let view = worker.state.view();
        let height = view.height();
        let before_fee = view
            .world()
            .assets()
            .get(&fee_asset)
            .unwrap()
            .as_ref()
            .clone();
        let before_amx = view.world().sumeragi_amx().clone();
        let lag = view.world().parameters().sumeragi().due_work_max_lag_ms();
        drop(view);
        let mut original_inputs = None;
        let result = worker.run_execution_with_finisher(&block, hash, false, |worker| {
            let original = worker.finishing.as_ref().unwrap();
            assert!(
                original
                    .overlay
                    .world()
                    .assets()
                    .get(&fee_asset)
                    .unwrap()
                    .as_ref()
                    < &before_fee,
                "the real provisional carrier has charged its actual fee"
            );
            assert!(
                original.overlay.world().sumeragi_amx().transactions.len()
                    > before_amx.transactions.len(),
                "the actual Begin writes the provisional AMX state"
            );
            original_inputs = Some(
                original
                    .valid
                    .as_ref()
                    .external_entrypoints_slice()
                    .as_ptr(),
            );
            let block_time = original.valid.as_ref().header().creation_time();
            worker.finish_execution_with_encoder(false, |original, budget| {
                let bytes = encode_result_preimage(original, budget)?;
                clock.set(block_time + Duration::from_millis(lag + 1));
                Ok(bytes)
            })
        });
        assert!(
            matches!(
                result,
                Err(PublicationError::Deferred(
                    PublicationDeferral::StaleDueWork { .. }
                ))
            ),
            "time-sensitive effects must be locally deferred after the last encoding wait"
        );
        assert!(worker.finishing.is_none() && worker.live.is_none());
        assert!(!worker.results.contains_key(&hash));
        let retained = worker
            .signature_decode
            .as_ref()
            .unwrap()
            .decoded
            .as_ref()
            .unwrap();
        assert_eq!(
            Some(retained.external_entrypoints_slice().as_ptr()),
            original_inputs,
            "stale rollback retains the same original signed-input graph"
        );
        let view = worker.state.view();
        assert_eq!(view.height(), height);
        assert_eq!(
            view.world().assets().get(&fee_asset).unwrap().as_ref(),
            &before_fee
        );
        assert_eq!(view.world().sumeragi_amx(), &before_amx);
        drop(view);
        clock.set(Duration::from_millis(block_time_ms + lag));
        assert!(
            matches!(
                worker.execute(&block, hash, false),
                Some(ExecOutcome::Valid { .. })
            ),
            "inclusive freshness boundary retries the unchanged original without negative caching"
        );
    });
}

#[test]
fn ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source() {
    with_paid_begin(|worker, block, hash, _fee_asset, clock, block_time_ms| {
        let lag = worker
            .state
            .view()
            .world()
            .parameters()
            .sumeragi()
            .due_work_max_lag_ms();
        let Some(ExecOutcome::Valid { result, admission }) = worker.execute(&block, hash, false)
        else {
            panic!("actual original Begin must execute at the fresh boundary")
        };
        let source = iroha_sumeragi::testing::prepare_signing_request(
            block.header().instance,
            block.header().epoch,
            block.header().height,
            0,
            hash,
            result,
            false,
        );
        assert_eq!(admission.check(&source), Ok(()));
        let wrong = iroha_sumeragi::testing::prepare_signing_request(
            block.header().instance,
            block.header().epoch,
            block.header().height,
            0,
            hash,
            Hash32::ZERO,
            true,
        );
        assert_eq!(
            admission.check(&wrong),
            Err(SigningError::InvalidInput),
            "a certificate flag cannot substitute another result"
        );
        clock.set(Duration::from_millis(block_time_ms + lag + 1));
        assert!(
            matches!(
                admission.check(&source),
                Err(SigningError::StaleExecution { .. })
            ),
            "native first signing must recheck the actual wall clock after execution"
        );
        assert!(
            matches!(
                worker.execute(&block, hash, false),
                Some(ExecOutcome::Failed(_))
            ),
            "cached native Valid cannot bypass a fresh local clock check"
        );
        assert!(worker.live.is_none() && worker.signature_decode.is_some());
        assert!(!worker.results.contains_key(&hash));
        assert!(
            matches!(worker.execute(&block, hash, true), Some(ExecOutcome::Valid { result: same, .. }) if same == result),
            "certified re-execution preserves the identical ledger-time verdict"
        );
    });
}

#[test]
fn ct5_admission_capacity_wait_keeps_encoded_original_then_rechecks_freshness() {
    with_paid_begin(|worker, block, hash, _fee_asset, clock, block_time_ms| {
        let lag = worker
            .state
            .view()
            .world()
            .parameters()
            .sumeragi()
            .due_work_max_lag_ms();
        let budget = worker.state.ivm_execution_budget();
        let mut blocker = None;
        let mut pointer = None;
        let result = worker.run_execution_with_encoder(&block, hash, false, |original, budget| {
            let bytes = encode_result_preimage(original, budget)?;
            pointer = Some(bytes.as_slice().as_ptr());
            blocker = Some(
                budget
                    .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                    .unwrap(),
            );
            Ok(bytes)
        });
        assert!(
            matches!(result, Err(PublicationError::Deferred(ref failure)) if failure.allocation_refusal().is_some())
        );
        assert_eq!(
            Some(
                worker
                    .finishing
                    .as_ref()
                    .unwrap()
                    .encoded_preimage
                    .as_ref()
                    .unwrap()
                    .as_slice()
                    .as_ptr()
            ),
            pointer,
            "admission refusal keeps the exact already encoded result allocation"
        );
        drop(blocker);
        clock.set(Duration::from_millis(block_time_ms + lag + 1));
        let result = worker.run_execution_with_encoder(&block, hash, false, |_, _| {
            panic!("retained result must not be re-encoded")
        });
        assert!(matches!(
            result,
            Err(PublicationError::Deferred(
                PublicationDeferral::StaleDueWork { .. }
            ))
        ));
        assert!(
            worker.finishing.is_none()
                && worker.live.is_none()
                && worker.signature_decode.is_some()
        );
        assert!(budget.reserved_bytes() < budget.limit_bytes());
    });
}
