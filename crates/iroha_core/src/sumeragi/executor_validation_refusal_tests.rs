//! Original validation decoder refusal retains typed worker ownership before local diagnostics.

use super::*;

/// Observe only the actual payload and merge prefix; no production admission is added.
fn original_validation_prefix(worker: &Worker<'_>, block: &AvailableBody) -> usize {
    const CEILING: usize = 1 << 28;
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, 64),
        || {
            let proposal = payload::decode(block.payload().as_slice()).unwrap();
            let schedule = worker.scheduled(block.header().height).unwrap();
            let expansion = lanes::merge::expand(
                worker.state,
                &proposal,
                &*worker.context.lane_blocks,
                Duration::from_millis(schedule.params.exec_budget_ms),
            )
            .unwrap();
            drop(expansion);
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
            else {
                panic!("original validation prefix allocation observation changed");
            };
            assert_eq!(limit, CEILING as u64);
            let prefix = usize::try_from(attempted).unwrap() - CEILING - 1;
            assert!(prefix > 0);
            prefix
        },
    )
}

#[test]
fn original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
            panic!("the actual available body must execute before certification refusal");
        };
        let qc = chain.commit_qc(
            block.header().height,
            hash,
            result,
            crate::sumeragi::test_chain::Signers::Quorum,
        );
        let original_source = std::ptr::from_ref(block.source());
        let original_bytes = block.payload().as_slice().as_ptr();
        let original = worker.live.as_ref().unwrap();
        let original_commitment = std::ptr::from_ref(original.commitment().get());
        let original_overlay = std::ptr::from_ref(original.overlay.as_ref().unwrap());
        let original_witness = iroha_crypto::HashOf::new(original.witness.as_ref().unwrap().wire());
        let PublicationPhase::Executed { preimage, .. } = &original.phase else {
            panic!("the same original execution must await publication");
        };
        let original_preimage = preimage.as_slice().as_ptr();
        let budget = worker.state.ivm_execution_budget();
        let epoch = crossbeam_epoch::pin();
        let occupied_bytes = budget.reserved_bytes();
        let height = worker.state.view().height();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let error = norito::with_decode_limits_scope(limits, || {
            crate::sumeragi::certified_chain::CertifiedChain::new(&worker.state.view())
                .map(|reader| reader.instance())
        })
        .unwrap_err();
        let crate::execution_attempt::ExecutionAttemptError::Deferred(original_refusal) = error
        else {
            panic!("original certificate authority read must retain its typed refusal: {error:?}");
        };
        assert!(original_refusal.allocation_refusal().is_none());
        assert!(matches!(
            norito::with_decode_limits_scope(limits, || worker.prepare(&block, &qc)),
            Err(PublicationError::Deferred(ref source)) if source.execution() == Some(&original_refusal)
        ));
        assert_eq!(
            worker.routing_refusal.as_ref(),
            Some(&original_refusal),
            "the prepared-certificate diagnostic retains the original typed reader owner"
        );
        let retained = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(retained.commitment().get()),
            original_commitment
        );
        assert_eq!(
            std::ptr::from_ref(retained.overlay.as_ref().unwrap()),
            original_overlay
        );
        assert_eq!(
            iroha_crypto::HashOf::new(retained.witness.as_ref().unwrap().wire()),
            original_witness
        );
        let PublicationPhase::Executed { preimage, .. } = &retained.phase else {
            panic!("an unfinished authority read cannot stage the original publication");
        };
        assert_eq!(preimage.as_slice().as_ptr(), original_preimage);
        assert_eq!(budget.reserved_bytes(), occupied_bytes);
        assert_eq!(worker.state.view().height(), height);
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(worker.pending_commit.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.quarantine_context.is_none());
        assert!(worker.recovery.is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(std::ptr::from_ref(block.source()), original_source);
        assert_eq!(block.payload().as_slice().as_ptr(), original_bytes);
        drop(epoch);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
        assert!(worker.routing_refusal.is_none());
        let retained = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(retained.commitment().get()),
            original_commitment
        );
        assert_eq!(
            std::ptr::from_ref(retained.overlay.as_ref().unwrap()),
            original_overlay
        );
        assert_eq!(
            iroha_crypto::HashOf::new(retained.witness.as_ref().unwrap().wire()),
            original_witness
        );
        assert!(matches!(retained.phase, PublicationPhase::Prepared { .. }));
        assert_eq!(worker.state.view().height(), height);
    });
}

#[test]
fn original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let original_source = std::ptr::from_ref(block.source());
        let original_bytes = block.payload().as_slice().as_ptr();
        let height = worker.state.view().height();
        let prefix = original_validation_prefix(worker, &block);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, prefix, 64);
        let error = norito::with_decode_limits_scope(limits, || {
            let proposal = payload::decode(block.payload().as_slice())
                .expect("original payload prefix completes");
            let schedule = worker.scheduled(block.header().height).unwrap();
            let committee = schedule
                .epoch
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect::<Vec<_>>();
            let topology = Topology::new(committee);
            let expansion = lanes::merge::expand(
                worker.state,
                &proposal,
                &*worker.context.lane_blocks,
                Duration::from_millis(schedule.params.exec_budget_ms),
            )
            .expect("original merge prefix completes before validation refusal");
            ValidBlock::validate_sumeragi_block(
                proposal,
                &topology,
                &worker.context.genesis_account,
                Duration::from_millis(schedule.params.block_time_ms),
                worker.context.consensus_mode,
                expansion,
                block.header(),
                block.payload().as_slice(),
                worker.state,
            )
            .unpack(|_| {})
            .map(|_| ())
            .unwrap_err()
            .1
        });
        let BlockValidationError::ExecutionDeferred(original) = *error else {
            panic!("actual post-merge validator must preserve its local reason: {error:?}");
        };
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(matches!(
            norito::with_decode_limits_scope(limits, || worker.execute(&block, hash)),
            Some(ExecOutcome::Failed(_))
        ));
        assert_eq!(
            worker.routing_refusal.as_ref(),
            Some(&original),
            "local diagnostic must retain the actual validation owner"
        );
        assert!(!worker.results.contains_key(&hash));
        assert!(worker.quarantine_context.is_none());
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.recovery.is_none());
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), height);
        assert_eq!(std::ptr::from_ref(block.source()), original_source);
        assert_eq!(block.payload().as_slice().as_ptr(), original_bytes);
        let returned = worker
            .signature_decode
            .as_ref()
            .and_then(|attempt| attempt.decoded.as_ref())
            .expect("actual local validation returns the original decoded graph");
        let original_entries = returned.external_entrypoints_slice().as_ptr();
        assert!(returned.signatures_admitted_to(&worker.state.ivm_execution_budget()));
        assert!(
            returned
                .matches_resultless_proposal_wire(block.payload().as_slice())
                .unwrap()
        );
        assert!(matches!(
            worker.execute(&block, hash),
            Some(ExecOutcome::Valid(_))
        ));
        let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase else {
            panic!("same original decoded graph completes production validation");
        };
        assert_eq!(
            valid.as_ref().external_entrypoints_slice().as_ptr(),
            original_entries
        );
        assert!(worker.signature_decode.is_none());
        assert!(worker.routing_refusal.is_none());
        assert_eq!(
            worker.state.view().height(),
            height,
            "retry executes without publishing"
        );
        assert_eq!(std::ptr::from_ref(block.source()), original_source);
        assert_eq!(block.payload().as_slice().as_ptr(), original_bytes);
    });
}

#[test]
fn prepared_certificate_busy_retries_same_execution_after_original_reader_release() {
    use std::{
        sync::mpsc,
        task::{Context, Poll, Waker},
    };
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
            panic!("the actual signed body must execute before reader contention");
        };
        let qc = chain.commit_qc(
            block.header().height,
            hash,
            result,
            crate::sumeragi::test_chain::Signers::Quorum,
        );
        let state = worker.state;
        let original_source = std::ptr::from_ref(block.source());
        let original_bytes = block.payload().as_slice().as_ptr();
        let original = worker.live.as_ref().unwrap();
        let original_commitment = std::ptr::from_ref(original.commitment().get());
        let original_overlay = std::ptr::from_ref(original.overlay.as_ref().unwrap());
        let original_witness = iroha_crypto::HashOf::new(original.witness.as_ref().unwrap().wire());
        let PublicationPhase::Executed { preimage, .. } = &original.phase else {
            panic!("the original execution must await publication");
        };
        let original_preimage = preimage.as_slice().as_ptr();
        let budget = state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let epoch = crossbeam_epoch::pin();
        let occupied = budget.reserved_bytes();
        let height = state.view().height();
        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let holder = scope.spawn(move || {
                state.with_held_header_for_reader_test(|wait| {
                    ready_tx.send(wait).unwrap();
                    // A blocking regression releases the real guard on a finite deadline.
                    release_rx.recv_timeout(Duration::from_secs(20)).is_ok()
                })
            });
            let original_wait = ready_rx.recv_timeout(Duration::from_secs(20)).unwrap();
            let outcome = worker.prepare(&block, &qc);
            // Release before any assertion can unwind and strand the foreign holder.
            release_tx.send(()).ok();
            assert!(
                holder.join().unwrap(),
                "reader probe blocked on the actual writer"
            );
            let Err(PublicationError::Deferred(reason)) = outcome else {
                panic!("original reader Busy must remain typed: {outcome:?}");
            };
            assert!(
                matches!(&reason, crate::sumeragi::driver::traits::PublicationDeferral::StateViewBusy(wait) if wait == &original_wait)
            );
            let wait = original_wait;
            assert_eq!(
                registration.poll_wait(&wait, &mut Context::from_waker(Waker::noop())),
                Poll::Ready(()),
                "release before first poll must not be lost"
            );
        });
        let retained = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(retained.commitment().get()),
            original_commitment
        );
        assert_eq!(
            std::ptr::from_ref(retained.overlay.as_ref().unwrap()),
            original_overlay
        );
        assert_eq!(
            iroha_crypto::HashOf::new(retained.witness.as_ref().unwrap().wire()),
            original_witness
        );
        let PublicationPhase::Executed { preimage, .. } = &retained.phase else {
            panic!("unfinished reader cannot stage the original publication");
        };
        assert_eq!(preimage.as_slice().as_ptr(), original_preimage);
        assert_eq!(budget.reserved_bytes(), occupied);
        assert_eq!(state.view().height(), height);
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(worker.pending_commit.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.recovery.is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(std::ptr::from_ref(block.source()), original_source);
        assert_eq!(block.payload().as_slice().as_ptr(), original_bytes);
        drop(epoch);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
        let retained = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(retained.commitment().get()),
            original_commitment
        );
        assert_eq!(
            std::ptr::from_ref(retained.overlay.as_ref().unwrap()),
            original_overlay
        );
        assert_eq!(
            iroha_crypto::HashOf::new(retained.witness.as_ref().unwrap().wire()),
            original_witness
        );
        assert!(matches!(retained.phase, PublicationPhase::Prepared { .. }));
        assert_eq!(state.view().height(), height);
    });
}

/// Reach the native finalizer with an authenticated retained sample history and exact
/// original-pool capacity refusals. Probes change only the local allocation ceiling;
/// signed history, protocol behavior, source contents and allocator behavior stay intact.
#[test]
fn original_lane_finalizer_refusal_returns_same_graph_before_seal_and_publishes_after_retry() {
    use crate::sumeragi::driver::traits::BlockStore as _;
    use iroha_allocation::AllocationRefusal;
    use iroha_data_model::{
        parameter::{Parameter, system::SumeragiParameters},
        sumeragi_lanes::{
            SumeragiLaneAutoscale, SumeragiLanePolicy, SumeragiLaneSample, SumeragiLaneSamples,
        },
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    const RETAINED_HISTORY_BLOCKS: usize = 1_024;
    publication_tests::with_worker_from(
        || {
            let mut config = crate::sumeragi::test_chain::TestChainConfig::new(
                crate::state::World::new(),
                1_000,
            );
            let mut policy = SumeragiLanePolicy::for_chain(
                SumeragiParameters::default(),
                iroha_sumeragi::availability::recommended_data_availability_layout(),
            );
            policy.autoscale = Some(SumeragiLaneAutoscale {
                min_lane: LaneId::new(16),
                max_lane_exclusive: LaneId::new(20),
                dataspace: DataSpaceId::UNIVERSAL,
                committee_size: 4,
                per_lane_target_tps: 10,
                window: 2_048,
                scale_out_permille: 800,
                scale_in_permille: 200,
                cooldown: 3,
            });
            config
                .genesis_parameters
                .push(Parameter::Custom(policy.into_custom_parameter()));
            let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
                .expect("actual signed autoscale genesis");
            let genesis_height = chain.height();
            assert_eq!(genesis_height, 1);
            assert_eq!(chain.validators().len(), 4);
            let initial_samples = chain.state().view().world().sumeragi_lanes().samples.len();
            assert!(
                initial_samples <= 1,
                "only actual genesis may precede the history"
            );
            for _ in 0..RETAINED_HISTORY_BLOCKS {
                // The canonical fixture inserts one signed clock-work transaction;
                // its ordinary execution, exact quorum and publication remain mandatory.
                assert!(chain.commit(Vec::new()).is_empty());
            }
            assert_eq!(
                chain.height(),
                genesis_height + u64::try_from(RETAINED_HISTORY_BLOCKS).unwrap()
            );
            let first_epoch = chain
                .committed(genesis_height + 1)
                .header()
                .expect("actual certified non-genesis history")
                .epoch;
            assert_eq!(first_epoch.epoch, 0, "retained history is genuinely in E0");
            // Clone the existing charged owner, then release the State view before
            // authenticating each committed block; no sample graph is reconstructed.
            let samples = chain
                .state()
                .view()
                .world()
                .sumeragi_lanes()
                .samples
                .clone();
            assert_eq!(samples.len(), initial_samples + RETAINED_HISTORY_BLOCKS);
            assert!(samples.admitted_to(&chain.state().ivm_execution_budget()));
            {
                let view = chain.state().view();
                let history = view.canonical_history();
                let tip = view
                    .native_execution_tip()
                    .expect("the original publication carries its authenticated native tip");
                assert_eq!(tip.height(), chain.height());
                let first =
                    std::num::NonZeroUsize::new(usize::try_from(genesis_height).unwrap()).unwrap();
                let last =
                    std::num::NonZeroUsize::new(usize::try_from(tip.height()).unwrap()).unwrap();
                assert_eq!(history.height(), last.get());
                let mut remaining_samples = samples.len();
                let mut successor: Option<crate::sumeragi::certified_chain::CommittedBlock> = None;
                history
                    .visit_executed_backwards(
                        first,
                        last,
                        |_, _| Ok(()),
                        |stored| {
                            // One original-tip walk authenticates every source. Keep
                            // only the immediate successor, including the first real
                            // non-genesis block's exact extension of signed genesis.
                            if let Some(next) = successor.as_ref() {
                                assert!(next.extends(&stored));
                            }
                            if let Some(index) = remaining_samples.checked_sub(1) {
                                let sample = &samples[index];
                                assert_eq!(
                                    sample.height,
                                    genesis_height - u64::try_from(initial_samples).unwrap()
                                        + u64::try_from(index).unwrap()
                                        + 1,
                                    "no retained authenticated height is skipped or synthesized"
                                );
                                assert_eq!(stored.height(), sample.height);
                                assert_eq!(stored.block_time_ms(), sample.time_ms);
                                assert_eq!(sample.lanes, 1);
                                if sample.height > genesis_height {
                                    assert_eq!(stored.header().unwrap().epoch, first_epoch);
                                    assert_eq!(
                                        stored.block().external_entrypoints_slice().len(),
                                        1
                                    );
                                    assert!(
                                        stored
                                            .block()
                                            .network_output_at(0)
                                            .unwrap()
                                            .1
                                            .result
                                            .is_ok()
                                    );
                                    assert_eq!(sample.transactions, 1);
                                }
                                remaining_samples = index;
                            } else {
                                // If genesis produced no sample, its receipt is still
                                // required to authenticate the oldest sample's parent.
                                assert_eq!(stored.height(), genesis_height);
                            }
                            successor = Some(stored);
                            Ok(())
                        },
                    )
                    .expect("every original sample has one authenticated canonical receipt");
                assert_eq!(remaining_samples, 0);
                assert_eq!(successor.as_ref().unwrap().height(), genesis_height);
                drop(successor);
            }
            assert!(
                samples
                    .windows(2)
                    .all(|pair| pair[0].time_ms < pair[1].time_ms)
            );
            assert!(
                chain
                    .state()
                    .view()
                    .world()
                    .sumeragi_lanes()
                    .lanes
                    .is_empty()
            );
            drop(samples);
            chain
        },
        ConsensusMode::Permissioned,
        |chain, worker, blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let original_limit = budget.limit_bytes();
            let height = worker.state.view().height();
            let sample_ptr = worker
                .state
                .view()
                .world()
                .sumeragi_lanes()
                .samples
                .as_ptr();
            let next_sample_bytes = {
                let view = worker.state.view();
                let samples = &view.world().sumeragi_lanes().samples;
                assert!(samples.admitted_to(&budget));
                assert!(samples.len() >= RETAINED_HISTORY_BLOCKS);
                assert!(
                    samples.len() < 2_049,
                    "actual signed window retains this entire suffix"
                );
                assert_eq!(
                    samples.last().unwrap().height,
                    u64::try_from(height).unwrap()
                );
                let next_count = samples.len().checked_add(1).unwrap();
                std::alloc::Layout::array::<SumeragiLaneSample>(next_count)
                    .unwrap()
                    .size()
                    .checked_add(SumeragiLaneSamples::control_layout().size())
                    .unwrap()
            };
            let mut earlier_execution_request = 0;
            let mut attempt = SignatureDecodeAttempt {
                block_hash: hash,
                source: block.clone(),
                decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget)
                    .expect("same State-pool decoder"),
                decoded: None,
                returned_refusal: None,
                amx_legs: None,
            };
            let entries = attempt
                .original_decoded(&budget)
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr();
            worker.signature_decode = Some(attempt);
            // Keep MV reclamation out of this operation's exact capacity observations.
            let epoch = crossbeam_epoch::pin();
            let mut ceiling = budget.reserved_bytes();
            let mut reached_lane_finalizer = false;
            for probe in 0..128 {
                budget.set_limit_bytes(ceiling);
                let outcome = worker.run_execution(&block, hash);
                eprintln!(
                    "native finalizer capacity probe {probe}: ceiling={ceiling}, reserved={}, decoded={}, finishing={}, live={}, outcome={outcome:?}",
                    budget.reserved_bytes(),
                    worker
                        .signature_decode
                        .as_ref()
                        .is_some_and(|slot| slot.decoded.is_some()),
                    worker.finishing.is_some(),
                    worker.live.is_some(),
                );
                let (next_ceiling, at_lane_finalizer) = match &outcome {
                    Err(PublicationError::Deferred(source)) => {
                        let at_lane_finalizer = source.execution().is_some_and(|original| {
                            original.phase()
                                == Some(
                                    crate::execution_attempt::ExecutionPhase::NativeLaneFinalizer,
                                )
                        });
                        if at_lane_finalizer {
                            assert_eq!(
                                worker.routing_refusal.as_ref(),
                                source.execution(),
                                "the actual finalizer retains its exact refusal through both worker owners"
                            );
                        }
                        if let Some(original) = source.execution() {
                            let requested = match original.allocation_refusal() {
                                Some(AllocationRefusal::Capacity {
                                    requested_bytes, ..
                                })
                                | Some(AllocationRefusal::ExceedsLimit {
                                    requested_bytes, ..
                                }) => *requested_bytes,
                                other => panic!(
                                    "actual execution capacity refused without demand: {other:?}"
                                ),
                            };
                            if at_lane_finalizer {
                                assert_eq!(
                                    requested, next_sample_bytes,
                                    "the real finalizer prepays exactly the authenticated suffix plus control"
                                );
                                assert!(earlier_execution_request > 0);
                                assert!(
                                    requested > earlier_execution_request,
                                    "the authenticated suffix exceeds earlier observed transient execution requests"
                                );
                            } else {
                                earlier_execution_request =
                                    earlier_execution_request.max(requested);
                            }
                        }
                        let next = match source.allocation_refusal() {
                            Some(AllocationRefusal::Capacity {
                                requested_bytes,
                                reserved_bytes,
                                ..
                            }) => reserved_bytes.checked_add(*requested_bytes).unwrap(),
                            Some(AllocationRefusal::ExceedsLimit {
                                requested_bytes, ..
                            }) => budget
                                .reserved_bytes()
                                .checked_add(*requested_bytes)
                                .unwrap(),
                            Some(AllocationRefusal::DemandOverflow) => {
                                panic!("actual native demand overflowed")
                            }
                            None => {
                                panic!("capacity probe encountered another local owner: {source:?}")
                            }
                        };
                        (next, at_lane_finalizer)
                    }
                    other => panic!("capacity probe did not reach a retained refusal: {other:?}"),
                };
                // Ignoring the original HC133 finalizer outcome reaches the late take.
                // Its typed refusal must fail the same original graph assertion below.
                let returned = worker
                    .signature_decode
                    .as_ref()
                    .and_then(|original| original.decoded.as_ref())
                    .unwrap_or_else(|| {
                        panic!(
                            "late lane refusal must return the sole original graph before sealing: probe={probe}, ceiling={ceiling}, reserved={}, finishing={}, live={}, outcome={outcome:?}",
                            budget.reserved_bytes(),
                            worker.finishing.is_some(),
                            worker.live.is_some(),
                        )
                    });
                assert_eq!(returned.external_entrypoints_slice().as_ptr(), entries);
                assert!(returned.signatures_admitted_to(&budget));
                assert!(
                    returned
                        .matches_resultless_proposal_wire(block.payload().as_slice())
                        .unwrap()
                );
                assert_eq!(worker.state.view().height(), height);
                assert_eq!(
                    worker
                        .state
                        .view()
                        .world()
                        .sumeragi_lanes()
                        .samples
                        .as_ptr(),
                    sample_ptr
                );
                assert!(worker.live.is_none());
                assert!(worker.finishing.is_none());
                assert!(worker.results.is_empty());
                assert!(worker.pending_commit.is_none());
                assert!(worker.quarantine_context.is_none());
                assert!(worker.recovery.is_none());
                assert!(worker.context.staging.get(&hash).is_none());
                assert!(events.try_recv().is_err());
                if at_lane_finalizer {
                    reached_lane_finalizer = true;
                    break;
                }
                assert!(
                    next_ceiling > ceiling,
                    "one original capacity admission makes strict progress"
                );
                assert!(
                    next_ceiling <= original_limit,
                    "source still fits its unchanged full pool"
                );
                ceiling = next_ceiling;
            }
            budget.set_limit_bytes(original_limit);
            drop(epoch);
            assert!(
                reached_lane_finalizer,
                "native capacity probes reached the real late lane step"
            );
            let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
                panic!("the same original proposal retries after local capacity is restored");
            };
            let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase
            else {
                panic!("same original graph finishes execution");
            };
            assert_eq!(
                valid.as_ref().external_entrypoints_slice().as_ptr(),
                entries
            );
            assert!(worker.signature_decode.is_none());
            let qc = chain.commit_qc(
                block.header().height,
                hash,
                result,
                crate::sumeragi::test_chain::Signers::Quorum,
            );
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
            let original = worker.context.staging.get(&hash).unwrap();
            assert_eq!(
                original.executed.external_entrypoints_slice().as_ptr(),
                entries
            );
            blocks.append(&block, &qc).unwrap();
            worker.commit(&block, &qc).unwrap();
            let published = worker.state.view().latest_block().unwrap().unwrap();
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                &published,
                &original.executed
            ));
            assert_eq!(worker.state.view().height(), height + 1);
        },
    );
}

/// Exercise the actual validator-to-Worker handoff, including the source guard's refusal.
/// Faults use the existing one-shot accessor and transaction application API; they do not
/// mutate the funded witness, fabricate a source or add a production injection hook.
#[test]
fn validated_witness_guard_failure_requires_recovery_without_reexecuting_original_source() {
    use crate::sumeragi::driver::traits::BlockStore as _;

    // Zero is the ordinary publication control. One is prior one-shot extraction;
    // two is a genuine empty application after the original output seal completed.
    for fault in 0..3 {
        publication_tests::with_worker(move |chain, worker, blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let height = worker.state.view().height();
            let original_available = block.payload().as_slice().as_ptr();
            let original_source = std::ptr::from_ref(block.source());
            let mut attempt = SignatureDecodeAttempt {
                block_hash: hash,
                source: block.clone(),
                decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget)
                    .expect("actual original-pool signature decoder"),
                decoded: None,
                returned_refusal: None,
                amx_legs: None,
            };
            let entries = attempt
                .original_decoded(&budget)
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr();
            let proposal = attempt.decoded.take().unwrap();
            worker.signature_decode = Some(attempt);
            let scheduled = worker.scheduled(block.header().height).unwrap();
            let committee = scheduled
                .epoch
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect::<Vec<_>>();
            let topology = Topology::new(committee.clone());
            let expansion = lanes::merge::expand(
                worker.state,
                &proposal,
                &*worker.context.lane_blocks,
                Duration::from_millis(scheduled.params.exec_budget_ms),
            )
            .unwrap();
            let mut recorded_events = Vec::new();
            let (valid, mut overlay) = ValidBlock::validate_sumeragi_block(
                proposal,
                &topology,
                &worker.context.genesis_account,
                Duration::from_millis(scheduled.params.block_time_ms),
                worker.context.consensus_mode,
                expansion,
                block.header(),
                block.payload().as_slice(),
                worker.state,
            )
            .unpack(|event| recorded_events.push(event.into()))
            .expect("actual available proposal seals its real execution and witness");
            assert_eq!(
                valid.as_ref().external_entrypoints_slice().as_ptr(),
                entries
            );
            assert!(valid.as_ref().signatures_admitted_to(&budget));
            let original_fragments = overlay.committed_fragment_count();
            let detached = if fault == 1 {
                let witness = overlay
                    .take_exec_witness()
                    .expect("first actual witness owner");
                witness.verify_source_binding().unwrap();
                Some(witness)
            } else {
                None
            };
            if fault == 2 {
                // This normal State API rejects any application after the output seal.
                // An empty transaction cannot change the original transaction or wire graph.
                overlay.transaction().apply();
                assert_eq!(overlay.committed_fragment_count(), original_fragments);
                assert!(
                    overlay
                        .verify_execution_output_seal(valid.as_ref())
                        .is_err()
                );
            }
            let outcome = worker.retain_validated_execution(
                &block,
                hash,
                valid,
                overlay,
                committee,
                recorded_events,
            );
            if fault == 0 {
                assert!(outcome.unwrap().is_some());
                let original = worker.finishing.as_ref().unwrap();
                assert_eq!(
                    original
                        .valid
                        .as_ref()
                        .external_entrypoints_slice()
                        .as_ptr(),
                    entries
                );
                original.witness.verify_source_binding().unwrap();
                assert!(worker.recovery.is_none());
                assert!(worker.signature_decode.is_none());
                let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
                    panic!("ordinary witness handoff completes the same actual execution");
                };
                let qc = chain.commit_qc(
                    block.header().height,
                    hash,
                    result,
                    crate::sumeragi::test_chain::Signers::Quorum,
                );
                assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
                let staged = worker.context.staging.get(&hash).unwrap();
                assert_eq!(
                    staged.executed.external_entrypoints_slice().as_ptr(),
                    entries
                );
                blocks.append(&block, &qc).unwrap();
                worker.commit(&block, &qc).unwrap();
                let published = worker.state.view().latest_block().unwrap().unwrap();
                assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                    &published,
                    &staged.executed
                ));
                assert_eq!(worker.state.view().height(), height + 1);
                return;
            }
            let Err(PublicationError::RecoveryRequired(reason)) = outcome else {
                panic!(
                    "an absent or source-invalid original witness cannot promise retry: {outcome:?}"
                );
            };
            assert_eq!(worker.recovery.as_deref(), Some(reason.as_str()));
            assert_eq!(
                reason,
                "the original execution witness is absent or no longer source-valid"
            );
            assert!(worker.finishing.is_none());
            assert!(worker.live.is_none());
            assert!(worker.pending_commit.is_none());
            assert!(worker.results.is_empty());
            assert!(worker.quarantine_context.is_none());
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), height);
            let original_decode = worker.signature_decode.as_ref().unwrap();
            assert!(original_decode.decoded.is_none());
            let decoder = std::ptr::from_ref(&original_decode.decoder);
            let expected = PublicationError::RecoveryRequired(reason.clone()).to_string();
            assert!(matches!(
                worker.execute(&block, hash),
                Some(ExecOutcome::Failed(report)) if report == expected
            ));
            assert_eq!(worker.recovery.as_deref(), Some(reason.as_str()));
            assert_eq!(
                std::ptr::from_ref(&worker.signature_decode.as_ref().unwrap().decoder),
                decoder,
                "execute observes latched recovery before another decode or State execution"
            );
            assert!(worker.signature_decode.as_ref().unwrap().decoded.is_none());
            assert!(worker.results.is_empty());
            assert!(worker.finishing.is_none());
            assert!(worker.live.is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), height);
            assert_eq!(block.payload().as_slice().as_ptr(), original_available);
            assert_eq!(std::ptr::from_ref(block.source()), original_source);
            if let Some(original_witness) = detached {
                // The actual first extracted owner remains separate and immutable;
                // recovery never reimports it or fabricates a replacement witness.
                original_witness.verify_source_binding().unwrap();
            }
        });
    }
}

/// Observe cumulative allocation of an actual completed original reader. The explicit
/// failed reservation is diagnostic only and grants no source or successful allocation.
fn original_reader_decode_allocation(read: impl FnOnce()) -> usize {
    const CEILING: usize = 1 << 28;
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, 64),
        || {
            read();
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
            else {
                panic!("the original cumulative reader observation changed");
            };
            assert_eq!(limit, u64::try_from(CEILING).unwrap());
            let allocation = usize::try_from(attempted).unwrap() - CEILING - 1;
            assert!(allocation > 0);
            allocation
        },
    )
}

#[test]
fn prepared_certificate_uses_bounded_signed_root_without_rewalking_execution_history() {
    use crate::sumeragi::driver::traits::BlockStore as _;
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
    publication_tests::with_worker_from(
        || {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                    .unwrap();
            for _ in 0..8 {
                assert!(chain.commit(Vec::new()).is_empty());
            }
            assert_eq!(chain.height(), 9);
            chain
        },
        ConsensusMode::Permissioned,
        |chain, worker, blocks, events| {
            assert_eq!(chain.validators().len(), 4);
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
                panic!("the genuine successor executes under its original native parent");
            };
            let qc = chain.commit_qc(block.header().height, hash, result, Signers::Quorum);
            let budget = worker.state.ivm_execution_budget();
            let epoch = crossbeam_epoch::pin();
            let reserved = budget.reserved_bytes();
            let height = worker.state.view().height();
            let original_source = std::ptr::from_ref(block.source());
            let original_payload = block.payload().as_slice().as_ptr();
            let live = worker.live.as_ref().unwrap();
            let original_overlay = std::ptr::from_ref(live.overlay.as_ref().unwrap());
            let original_commitment = std::ptr::from_ref(live.commitment().get());
            let original_witness = iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire());
            let root_allocation = original_reader_decode_allocation(|| {
                let view = worker.state.view();
                let reader = crate::sumeragi::certified_chain::CertifiedChain::new(&view).unwrap();
                assert_eq!(reader.instance(), chain.instance());
                assert_eq!(reader.genesis().hash(), chain.genesis().hash());
            });
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, root_allocation, 64);
            assert!(
                matches!(
                    norito::with_decode_limits_scope(limits, || {
                        crate::sumeragi::certified_chain::committed_block(&worker.state.view(), 1)
                    }),
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ),
                "the real execution-ancestry read cannot fit the single signed-root decode"
            );
            assert!(
                norito::with_decode_limits_scope(limits, || {
                    worker.verify_prepared_certificate(&block, &qc)
                })
                .is_ok(),
                "root selection must not consume unrelated historical result preimages"
            );
            // Genuine signed invalid certificates remain refused under this same bounded reader.
            for signers in [Signers::BelowQuorum, Signers::All] {
                let invalid = chain.commit_qc(block.header().height, hash, result, signers);
                assert!(matches!(
                    norito::with_decode_limits_scope(limits, || {
                        worker.verify_prepared_certificate(&block, &invalid)
                    }),
                    Err(PublicationError::Retryable(_))
                ));
            }
            assert_eq!(budget.reserved_bytes(), reserved);
            assert_eq!(worker.state.view().height(), height);
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            let retained = worker.live.as_ref().unwrap();
            assert_eq!(
                std::ptr::from_ref(retained.overlay.as_ref().unwrap()),
                original_overlay
            );
            assert_eq!(
                std::ptr::from_ref(retained.commitment().get()),
                original_commitment
            );
            assert_eq!(
                iroha_crypto::HashOf::new(retained.witness.as_ref().unwrap().wire()),
                original_witness
            );
            assert!(matches!(retained.phase, PublicationPhase::Executed { .. }));
            assert_eq!(std::ptr::from_ref(block.source()), original_source);
            assert_eq!(block.payload().as_slice().as_ptr(), original_payload);
            assert!(block.admitted_to(&budget));
            drop(epoch);
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
            blocks.append(&block, &qc).unwrap();
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.applied, (block.header().height, hash));
            assert_eq!(worker.state.view().height(), height + 1);
            assert_eq!(std::ptr::from_ref(block.source()), original_source);
            assert_eq!(block.payload().as_slice().as_ptr(), original_payload);
        },
    );
}

#[test]
fn successor_context_uses_original_parent_and_bounded_signed_root_without_history_rewalk() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    publication_tests::with_worker_from(
        || {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                    .unwrap();
            for _ in 0..8 {
                assert!(chain.commit(Vec::new()).is_empty());
            }
            assert_eq!(chain.height(), 9);
            chain
        },
        ConsensusMode::Permissioned,
        |chain, _worker, _blocks, _events| {
            assert_eq!(chain.validators().len(), 4);
            let proposal = chain.proposal(None, Vec::new());
            let view = chain.state().view();
            let parent =
                crate::sumeragi::certified_chain::committed_block(&view, chain.height()).unwrap();
            let current = &view
                .world()
                .consensus_schedule()
                .ready(proposal.header().height().get())
                .unwrap()
                .epoch;
            let expected = iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
                instance: chain.instance().0,
                epoch: current.authorization.epoch,
                epoch_context_id: current.context_id().unwrap(),
                parent_consensus_hash: parent.core_hash().0,
                parent_result: parent.result().0,
            };
            expected.validate().unwrap();
            assert_eq!(parent.height(), chain.height());
            assert_eq!(
                parent.block_hash(),
                proposal.header().prev_block_hash().unwrap()
            );
            let budget = chain.state().ivm_execution_budget();
            let reserved = budget.reserved_bytes();
            let inputs_allocation = original_reader_decode_allocation(|| {
                let original_parent =
                    crate::sumeragi::certified_chain::committed_block(&view, chain.height())
                        .unwrap();
                let reader = crate::sumeragi::certified_chain::CertifiedChain::new(&view).unwrap();
                assert_eq!(reader.instance(), chain.instance());
                assert_eq!(original_parent.core_hash(), parent.core_hash());
                assert_eq!(original_parent.result(), parent.result());
            });
            let limits = norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                inputs_allocation,
                64,
            );
            assert!(
                matches!(
                    norito::with_decode_limits_scope(limits, || {
                        let _original_parent = crate::sumeragi::certified_chain::committed_block(
                            &view,
                            chain.height(),
                        )?;
                        crate::sumeragi::certified_chain::committed_block(&view, 1)
                    }),
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ),
                "the genuine full ancestry cannot fit the exact current-parent plus signed-root cut"
            );
            assert!(
                norito::with_decode_limits_scope(limits, || {
                    crate::sumeragi::schedule::authenticate_successor_context(
                        &view,
                        &proposal.header(),
                        &expected,
                    )
                })
                .is_ok()
            );
            // Every independently authenticated authority and parent field still binds exactly.
            for field in 0..5 {
                let mut foreign = expected;
                match field {
                    0 => foreign.instance[0] ^= 1,
                    1 => foreign.epoch += 1,
                    2 => foreign.epoch_context_id[0] ^= 1,
                    3 => foreign.parent_consensus_hash[0] ^= 1,
                    _ => foreign.parent_result[0] ^= 1,
                }
                assert!(matches!(
                    norito::with_decode_limits_scope(limits, || {
                        crate::sumeragi::schedule::authenticate_successor_context(
                            &view,
                            &proposal.header(),
                            &foreign,
                        )
                    }),
                    Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                        crate::sumeragi::schedule::ScheduleError::Epoch(_)
                    ))
                ));
            }
            let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
            assert!(matches!(
                norito::with_decode_limits_scope(zero, || {
                    crate::sumeragi::schedule::authenticate_successor_context(
                        &view,
                        &proposal.header(),
                        &expected,
                    )
                }),
                Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
            ));
            assert_eq!(budget.reserved_bytes(), reserved);
            assert_eq!(view.height(), usize::try_from(chain.height()).unwrap());
            assert_eq!(
                view.native_execution_tip().unwrap().height(),
                chain.height()
            );
        },
    );
}
