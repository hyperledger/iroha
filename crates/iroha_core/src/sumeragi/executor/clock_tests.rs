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
            let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash, false) else {
                panic!("exact clock boundary must permit genuine execution of the same source")
            };
            // A valid original was already guarded; later clock regression does not erase it.
            clock.set(Duration::ZERO);
            assert_eq!(
                worker.execute(&block, hash, false),
                Some(ExecOutcome::Valid(result))
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
        assert_eq!(
            executor.execute(&block, &qc.block_hash, true),
            Some(ExecOutcome::Valid(qc.result)),
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

fn sccp_clock_chain() -> CertifiedTestChain {
    use crate::smartcontracts::isi::sccp::test_support;
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    let mut config = TestChainConfig::new(crate::state::World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.genesis_block_cadence_ms = std::num::NonZeroU64::new(1_000).unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_millis(test_support::SCCP_UNBONDING_DELAY_MS);
    nexus.staking.max_slash_bps = 10_000;
    config.nexus = Some(nexus);
    config
        .genesis_instructions
        .push(test_support::SampleInstructions::initialize().into());
    CertifiedTestChain::start(config).expect("actual SCCP Global NPoS genesis")
}

#[test]
fn sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry() {
    use crate::smartcontracts::isi::sccp::keepalive;
    let (clock, source) = TimeSource::new_mock(Duration::ZERO);
    publication_tests::with_worker_from_clock(
        sccp_clock_chain,
        ConsensusMode::Npos,
        source,
        move |chain, worker, _blocks, events| {
            let view = chain.state().view();
            let due = keepalive::next_heartbeat_at_ms(view.world()).unwrap();
            let lag = keepalive::clock_parameters(view.world())
                .unwrap()
                .due_work_max_lag_ms;
            drop(view);
            let proposal = chain.proposal(Some(due), Vec::new());
            let bytes = payload::encode(&proposal).unwrap();
            let mut header = publication_tests::proposal(chain, worker).header().clone();
            header.payload_hash = iroha_sumeragi::preimage::payload_hash(
                &**worker.context.crypto.as_ref().unwrap(),
                &bytes,
            );
            header.payload_len = bytes.len().try_into().unwrap();
            header.availability_digest = Hash32::ZERO;
            let block = chain.author_payload(header, bytes);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            clock.set(Duration::from_millis(due + lag));
            let mut encoded_result = None;
            let initial =
                worker.run_execution_with_encoder(&block, hash, false, |result, budget| {
                    let preimage = encode_result_preimage(result, budget)?;
                    encoded_result = result_of_preimage(preimage.as_slice());
                    clock.advance(Duration::from_millis(1));
                    Ok(preimage)
                });
            assert!(
                matches!(initial, Err(PublicationError::Retryable(ref reason)) if reason == "StaleDueWork"),
                "CT5 must resample after completing the original execution before returning Valid"
            );
            let original = worker
                .finishing
                .as_ref()
                .expect("retain exact completed execution");
            let overlay = std::ptr::from_ref(original.overlay.as_ref());
            let result = std::ptr::from_ref(original.phase.ready().unwrap().get());
            assert!(worker.live.is_none());
            for _ in 0..2 {
                assert!(
                    matches!(worker.execute(&block, hash, false), Some(ExecOutcome::Failed(reason)) if reason.contains("StaleDueWork"))
                );
                let retained = worker.finishing.as_ref().unwrap();
                assert_eq!(std::ptr::from_ref(retained.overlay.as_ref()), overlay);
                assert_eq!(
                    std::ptr::from_ref(retained.phase.ready().unwrap().get()),
                    result
                );
                assert!(!worker.results.contains_key(&hash));
            }
            assert!(events.try_recv().is_err());
            let Some(ExecOutcome::Valid(certified_result)) = worker.execute(&block, hash, true)
            else {
                panic!("a certified retry must finish the same original execution")
            };
            assert_eq!(
                std::ptr::from_ref(worker.live.as_ref().unwrap().overlay.as_deref().unwrap()),
                overlay
            );
            // Finishing moves the inline result owner into Live. Its address may change;
            // the original encoded result and retained overlay must remain identical.
            assert_eq!(Some(certified_result), encoded_result);
            // The completed result is not a permanent exemption for later uncertified requests.
            assert!(
                matches!(worker.execute(&block, hash, false), Some(ExecOutcome::Failed(reason)) if reason.contains("StaleDueWork"))
            );
            assert_eq!(
                worker.execute(&block, hash, true),
                Some(ExecOutcome::Valid(certified_result))
            );
        },
    );
}

#[test]
fn sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate() {
    use crate::smartcontracts::isi::sccp::keepalive;
    use iroha_sumeragi::crypto::SigningError;
    let (clock, source) = TimeSource::new_mock(Duration::ZERO);
    publication_tests::with_worker_from_clock(
        sccp_clock_chain,
        ConsensusMode::Npos,
        source,
        move |chain, worker, _blocks, _events| {
            let view = chain.state().view();
            let due = keepalive::next_heartbeat_at_ms(view.world()).unwrap();
            let lag = keepalive::clock_parameters(view.world())
                .unwrap()
                .due_work_max_lag_ms;
            drop(view);
            let proposal = chain.proposal(Some(due), Vec::new());
            let bytes = payload::encode(&proposal).unwrap();
            let mut header = publication_tests::proposal(chain, worker).header().clone();
            header.payload_hash = iroha_sumeragi::preimage::payload_hash(
                &**worker.context.crypto.as_ref().unwrap(),
                &bytes,
            );
            header.payload_len = bytes.len().try_into().unwrap();
            header.availability_digest = Hash32::ZERO;
            let block = chain.author_payload(header, bytes);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            clock.set(Duration::from_millis(due + lag));
            let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash, false) else {
                panic!("genuine due candidate is valid at the exact CT5 boundary");
            };
            let guard = &worker.prepare_clock;
            let header = block.header();
            assert_eq!(
                guard.authorize_uncertified_for_test(header, hash, result),
                Ok(())
            );
            let mut foreign = header.clone();
            foreign.instance.0[0] ^= 1;
            assert_eq!(
                guard.authorize_uncertified_for_test(&foreign, hash, result),
                Err(SigningError::Refused)
            );
            foreign = header.clone();
            foreign.epoch.epoch += 1;
            assert_eq!(
                guard.authorize_uncertified_for_test(&foreign, hash, result),
                Err(SigningError::Refused)
            );
            foreign = header.clone();
            foreign.epoch.context.0[0] ^= 1;
            assert_eq!(
                guard.authorize_uncertified_for_test(&foreign, hash, result),
                Err(SigningError::Refused)
            );
            foreign = header.clone();
            foreign.height += 1;
            assert_eq!(
                guard.authorize_uncertified_for_test(&foreign, hash, result),
                Err(SigningError::Refused)
            );
            assert_eq!(
                guard.authorize_uncertified_for_test(header, Hash32::ZERO, result),
                Err(SigningError::Refused)
            );
            assert_eq!(
                guard.authorize_uncertified_for_test(header, hash, Hash32::ZERO),
                Err(SigningError::Refused)
            );
            clock.advance(Duration::from_millis(1));
            assert_eq!(
                guard.authorize_uncertified_for_test(header, hash, result),
                Err(SigningError::Refused),
                "CT5 must resample the original clock at Prepare signing after Valid was delivered"
            );
            assert_eq!(
                worker.execute(&block, hash, true),
                Some(ExecOutcome::Valid(result))
            );
            assert_eq!(
                worker
                    .prepare_clock
                    .authorize_uncertified_for_test(header, hash, result),
                Err(SigningError::Refused),
                "an earlier certified execution cannot exempt a later uncertified signature"
            );
        },
    );
}
