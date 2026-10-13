//! Local clock deferral over genuine State execution, independent roots and certified replay.

use super::*;
use crate::sumeragi::{
    driver::traits::BlockStore as _,
    test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_primitives::time::TimeSource;

/// Exercise the same original State guard for a caller's genuinely signed root.
pub(crate) fn assert_clock_ahead_defers_original(
    make_chain: impl FnOnce() -> CertifiedTestChain + Send + 'static,
) {
    let (clock, source) = TimeSource::new_mock(Duration::ZERO);
    publication_tests::with_worker_from_clock(
        make_chain,
        ConsensusMode::Permissioned,
        source,
        move |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let proposal = payload::decode(block.payload().as_slice()).unwrap();
            let time = proposal.header().creation_time();
            let drift = worker
                .state
                .view()
                .world()
                .parameters()
                .sumeragi()
                .max_clock_drift();
            let boundary = time
                .checked_sub(drift)
                .expect("fixture exceeds the drift allowance");
            clock.set(boundary - Duration::from_millis(1));
            let height = worker.state.view().height();
            for _ in 0..2 {
                assert!(
                    matches!(
                        worker.execute(&block, hash, false),
                        Some(ExecOutcome::Failed(reason)) if reason.contains("ClockAhead")
                    ),
                    "uncertified future block must defer before execution"
                );
                assert!(worker.live.is_none());
                assert!(worker.finishing.is_none());
                assert!(!worker.results.contains_key(&hash));
                assert!(
                    worker.signature_decode.is_some(),
                    "retain the original decoded source"
                );
                assert_eq!(worker.state.view().height(), height);
                assert!(events.try_recv().is_err());
            }
            clock.set(boundary);
            let Some(ExecOutcome::Valid { result, admission }) =
                worker.execute(&block, hash, false)
            else {
                panic!("exact clock boundary must permit genuine execution of the same source")
            };
            // A valid original was already guarded; later clock regression does not erase it.
            clock.set(Duration::ZERO);
            assert_eq!(
                worker.execute(&block, hash, false),
                Some(ExecOutcome::Valid { result, admission })
            );
        },
    );
}

#[test]
fn prepare_withheld_while_block_time_ahead() {
    assert_clock_ahead_defers_original(|| {
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap()
    });
}

#[test]
fn authenticated_proposer_time_above_floor_executes_and_replays_without_restamping() {
    let chosen = Duration::from_millis(20_000);
    let (clock, source) = TimeSource::new_mock(chosen);
    publication_tests::with_worker_clock(source, move |chain, worker, blocks, _events| {
        let original = publication_tests::proposal(chain, worker);
        let proposal = payload::decode(original.payload().as_slice()).unwrap();
        assert!(proposal.header().creation_time() < chosen);
        let mut header = proposal.header();
        header.creation_time_ms = u64::try_from(chosen.as_millis()).unwrap();
        let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
        for transaction in proposal.external_transactions() {
            builder.push_transaction(transaction.clone());
        }
        builder.set_da_commitments(proposal.da_commitments().cloned());
        builder.set_da_proof_policies(proposal.da_proof_policies().cloned());
        builder.set_da_pin_intents(proposal.da_pin_intents().cloned());
        builder.set_npos_consensus_effects(proposal.npos_consensus_effects().cloned());
        builder.set_global_beacon_pulse(proposal.global_beacon_pulse().cloned());
        builder.set_execution_context(proposal.execution_context().cloned());
        let fresh = builder.build(Default::default());
        assert_eq!(
            fresh.external_entrypoints_slice(),
            proposal.external_entrypoints_slice()
        );
        let bytes = payload::encode(&fresh).unwrap();
        let mut native_header = original.header().clone();
        native_header.payload_hash = iroha_sumeragi::preimage::payload_hash(
            &**worker.context.crypto.as_ref().unwrap(),
            &bytes,
        );
        native_header.payload_len = u32::try_from(bytes.len()).unwrap();
        let body = chain.author_payload(native_header, bytes);
        let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
        let outcome = worker.execute(&body, hash, false);
        assert!(
            matches!(outcome, Some(ExecOutcome::Valid { .. })),
            "authenticated proposer time above the input floor must execute: {outcome:?}"
        );
        let Some(ExecOutcome::Valid { result, .. }) = outcome else {
            unreachable!()
        };
        let qc = chain.commit_qc(
            2,
            hash,
            result,
            crate::sumeragi::test_chain::Signers::Quorum,
        );
        worker.discard(2, &[]);
        clock.set(Duration::ZERO);
        let context = worker.context.clone();
        let mut executor = StateExecutor::spawn(context.clone()).unwrap();
        assert!(matches!(executor.execute(&body, &hash, false),
            Some(ExecOutcome::Failed(reason)) if reason.contains("ClockAhead")));
        assert_eq!(executor.prepare(&body, &qc).unwrap(), Some(result));
        blocks.append(&body, &qc).unwrap();
        // A restart releases the original prepared owner before cold replay can acquire it.
        drop(executor);
        let mut restored = StateExecutor::spawn(context).unwrap();
        restored.replay(&body, &qc).unwrap();
        assert_eq!(
            worker.state.view().native_execution_tip().unwrap().result(),
            result
        );
        assert_eq!(
            payload::decode(body.payload().as_slice())
                .unwrap()
                .header()
                .creation_time(),
            chosen
        );
    });
}

#[test]
fn certified_execution_skips_clock_guards() {
    publication_tests::with_worker(|chain, worker, blocks, _events| {
        let (block, qc) = publication_tests::executed(chain, worker);
        worker.discard(block.header().height, &[]);
        assert!(worker.live.is_none());
        let (_, source) = TimeSource::new_mock(Duration::ZERO);
        let mut context = worker.context.clone();
        context.time_source = source;
        let mut executor = StateExecutor::spawn(context.clone()).unwrap();
        assert!(matches!(
            executor.execute(&block, &qc.block_hash, false),
            Some(ExecOutcome::Failed(reason)) if reason.contains("ClockAhead")
        ));
        assert!(
            matches!(executor.execute(&block, &qc.block_hash, true),
            Some(ExecOutcome::Valid { result, .. }) if result == qc.result),
            "the genuine certified re-proposal executes the exact same deterministic result"
        );
        executor.discard(block.header().height, &[]);
        let mut forged = qc.clone();
        forged.agg_sig.0[0] ^= 1;
        assert!(executor.prepare(&block, &forged).is_err());
        assert_eq!(executor.prepare(&block, &qc).unwrap(), Some(qc.result));
        blocks.append(&block, &qc).unwrap();
        // Reopen a cold executor while the local clock still predates the original block.
        drop(executor);
        let mut restored = StateExecutor::spawn(context).unwrap();
        restored.replay(&block, &qc).unwrap();
        assert_eq!(worker.state.view().height() as u64, block.header().height);
        assert_eq!(
            worker.state.view().native_execution_tip().unwrap().result(),
            qc.result
        );
    });
}
