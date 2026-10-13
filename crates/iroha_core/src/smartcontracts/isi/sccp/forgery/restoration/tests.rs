//! Genuine recorded histories and adversarial restored claims; DATA mutation grants no authority.
use super::*;
use crate::{
    query::store::LiveQueryStore,
    smartcontracts::isi::sccp::forgery::tests::{active_member_chain_with_penalty_delay, future},
    sumeragi::{
        evidence::{record::parse_record, validate_persisted_records},
        test_chain::CertifiedTestChain,
    },
};
use iroha_data_model::{block::consensus::EvidenceRecord, isi::InstructionBox};
use norito::codec::Encode as _;
use std::sync::Arc;

fn recorded() -> (CertifiedTestChain, Hash) {
    let (mut chain, committee, ordinary) = active_member_chain_with_penalty_delay(2);
    let evidence = future(&chain, &committee);
    let tip = chain.state().view().native_execution_tip().unwrap();
    let signed = chain.sign(
        &ordinary,
        [InstructionBox::from(evidence)],
        tip.creation_time_ms() + 1,
    );
    assert_eq!(
        chain.commit(vec![signed]),
        [true],
        "actual signed Network execution and finality"
    );
    let view = chain.state().view();
    assert_eq!(view.height(), 3);
    assert_eq!(view.world().consensus_evidence().len(), 1);
    assert_eq!(view.world().sccp_forgery_offences().len(), 3);
    let id = *view.world().consensus_evidence().iter().next().unwrap().0;
    assert_eq!(
        view.world()
            .consensus_evidence()
            .get(&id)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    drop(view);
    (chain, id)
}
fn claim(state: &State, id: Hash) -> EvidenceRecord {
    state
        .world
        .consensus_evidence
        .view()
        .get(&id)
        .unwrap()
        .canonical_projection()
}
fn funded(state: &State, claim: &EvidenceRecord) -> RetainedEvidenceRecord {
    let text = norito::json::to_json(claim).unwrap();
    parse_record(
        &mut norito::json::Parser::new(&text),
        state.evidence_preparation_budget(),
    )
    .unwrap()
}
fn replace(state: &State, id: Hash, claim: &EvidenceRecord) {
    let owner = funded(state, claim);
    let mut block = state.world.consensus_evidence.block();
    block.insert(id, owner);
    block.commit();
}
fn replay_restore(
    chain: &CertifiedTestChain,
    mut replay: CertifiedTestChain,
) -> CertifiedTestChain {
    let state = chain.state();
    let decoded = crate::state::deserialize::KuraSeed {
        execution_budget: AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        kura: Arc::clone(chain.kura()),
        lane_manifests: state.lane_manifests.read().clone(),
        query_handle: LiveQueryStore::start_test(),
        #[cfg(feature = "telemetry")]
        telemetry: crate::telemetry::StateTelemetry::default(),
    }
    .into_state_from_json(norito::json::to_value(state.as_ref()).unwrap());
    assert!(matches!(
        decoded,
        Err(crate::state::deserialize::StateRestoreError::NativeExecutionReplayRequired)
    ));
    // A decoded World is not an executed State. Use the maintained startup replay path:
    // the fixture independently executes the same signed genesis, then verifies and
    // executes every original certified suffix carrier without replacement certificates.
    replay.replay_from(chain).unwrap();
    validate_persisted_records(replay.state()).unwrap();
    assert_eq!(
        replay.state().view().native_execution_tip(),
        state.view().native_execution_tip()
    );
    replay
}

fn restore_recorded(chain: &CertifiedTestChain) -> CertifiedTestChain {
    replay_restore(chain, active_member_chain_with_penalty_delay(2).0)
}

#[test]
fn signed_submit_pending_and_applied_roundtrip_through_actual_state_restore() {
    let (mut chain, id) = recorded();
    validate_persisted_records(chain.state()).unwrap();
    let restored_chain = restore_recorded(&chain);
    let restored = restored_chain.state();
    assert_eq!(claim(restored, id), claim(chain.state(), id));
    assert_eq!(
        restored.view().native_execution_tip(),
        chain.state().view().native_execution_tip()
    );
    drop(restored_chain);
    chain.commit(Vec::new());
    validate_persisted_records(chain.state()).unwrap();
    chain.commit(Vec::new());
    assert_eq!(
        claim(chain.state(), id).penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    validate_persisted_records(chain.state()).unwrap();
    let restored_chain = restore_recorded(&chain);
    let restored = restored_chain.state();
    assert_eq!(claim(restored, id), claim(chain.state(), id));
    let undo = restored.world.consensus_evidence.snapshot();
    assert_eq!(
        undo.revert_map()
            .get(&id)
            .unwrap()
            .as_ref()
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert_eq!(restored.world.sccp_forgery_offences.view().len(), 3);
}

#[test]
fn original_carrier_time_rule_g6_and_peer_substitutions_are_not_snapshot_authority() {
    let (chain, id) = recorded();
    let original = claim(chain.state(), id);
    let tip = chain.state().view().native_execution_tip();
    for mutation in 0..8 {
        let restored_chain = restore_recorded(&chain);
        let state = restored_chain.state();
        let mut changed = original.clone();
        let RecordedEvidenceV1::SccpForgery(material) = &mut changed.evidence else {
            panic!("SCCP record")
        };
        match mutation {
            0 => changed.recorded_at_ms += 1,
            1 => changed.recorded_at_view += 1,
            2 => changed.recorded_at_height += 1,
            3 => material.rule = iroha_data_model::sccp::native::SccpForgeryRuleV1::E4,
            4 => material.offenders[0].activation_height += 1,
            5 => material.offenders[0].validator = material.offenders[1].validator.clone(),
            6 => {
                changed.attribution.offenders[0].peer_id =
                    changed.attribution.offenders[1].peer_id.clone()
            }
            _ => changed.attribution.instance[0] ^= 1,
        }
        let text = norito::json::to_json(&changed).unwrap();
        match parse_record(
            &mut norito::json::Parser::new(&text),
            state.evidence_preparation_budget(),
        ) {
            Ok(owner) => {
                let mut block = state.world.consensus_evidence.block();
                block.insert(id, owner);
                block.commit();
                assert!(
                    validate_persisted_records(state).is_err(),
                    "history mutation {mutation}"
                );
            }
            // Activation beyond generation start and duplicate account tuples may fail the
            // earlier closed codec. That is a rejection, not a forged owner bypass for tests.
            Err(error) => assert!(
                matches!(mutation, 4 | 5),
                "unexpected codec refusal {mutation}: {error}"
            ),
        }
        assert_eq!(state.view().native_execution_tip(), tip);
    }
    validate_persisted_records(chain.state()).unwrap();
}

#[test]
fn complete_original_offence_set_detects_total_record_omission_extra_id_and_wrong_max() {
    let (chain, id) = recorded();
    for mutation in 0..8 {
        let restored_chain = restore_recorded(&chain);
        let state = restored_chain.state();
        match mutation {
            0 => {
                let mut block = state.world.consensus_evidence.block();
                assert!(block.remove(id).is_some());
                block.commit();
            }
            1 | 2 => {
                let key = state
                    .world
                    .sccp_forgery_offences
                    .view()
                    .iter()
                    .next()
                    .unwrap()
                    .0
                    .clone();
                state
                    .world
                    .sccp_forgery_offences
                    .try_with_admitted_block(|block| {
                        if mutation == 1 {
                            block.try_remove_admitted(key).map_err(|(_, error)| error)?;
                        } else {
                            block
                                .try_insert_admitted(key, [0x77; 32])
                                .map_err(|(_, error)| error)?;
                        }
                        Ok::<_, mv::storage::AdmittedStorageError>(())
                    })
                    .unwrap();
            }
            3..=5 => {
                let maximum = match mutation {
                    3 => None,
                    4 => Some(0),
                    _ => Some(2),
                };
                let mut world = state.world.block();
                *world.sccp_forgery_max_generation.get_mut() = maximum;
                world.commit();
                assert_eq!(
                    *state.world.sccp_forgery_max_generation.view().get(),
                    maximum
                );
            }
            6 => {
                let owner = funded(state, &claim(state, id));
                let mut block = state.world.consensus_evidence.block();
                block.insert(Hash::new(b"foreign restored record key"), owner);
                block.commit();
            }
            _ => {
                let keys: Vec<_> = state
                    .world
                    .sccp_forgery_offences
                    .view()
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect();
                state
                    .world
                    .sccp_forgery_offences
                    .try_with_admitted_block(|block| {
                        for key in keys {
                            block.try_remove_admitted(key).map_err(|(_, error)| error)?;
                        }
                        Ok::<_, mv::storage::AdmittedStorageError>(())
                    })
                    .unwrap();
            }
        }
        assert!(
            validate_persisted_records(state).is_err(),
            "complete-set mutation {mutation}"
        );
    }
    validate_persisted_records(chain.state()).unwrap();
}

#[test]
fn good_current_record_cannot_hide_a_changed_predecessor_claim() {
    let (mut chain, id) = recorded();
    chain.commit(Vec::new()); // Both H4 and H3 must contain the same pending record.
    let state = chain.state();
    let original = claim(state, id);
    let tip = state.view().native_execution_tip();
    let mut changed = original.clone();
    changed.recorded_at_ms += 1;
    replace(state, id, &changed);
    replace(state, id, &original); // Exact good current owner, deliberately bad undo owner.
    assert_eq!(claim(state, id), original);
    assert!(validate_persisted_records(state).is_err());
    assert_eq!(state.view().native_execution_tip(), tip);
}

#[test]
fn pending_cannot_replace_actual_applied_mark_or_claim_early_application() {
    let (mut chain, id) = recorded();
    let restored_chain = restore_recorded(&chain);
    let state = restored_chain.state();
    let mut early = claim(state, id);
    early.penalty_status = EvidencePenaltyStatus::Applied { height: 3 };
    replace(state, id, &early);
    assert!(validate_persisted_records(state).is_err());
    drop(restored_chain);
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let state = chain.state();
    let mut overdue = claim(state, id);
    assert_eq!(
        overdue.penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    overdue.penalty_status = EvidencePenaltyStatus::Pending;
    replace(state, id, &overdue);
    let error = validate_persisted_records(state).unwrap_err();
    assert!(error.to_string().contains("penalty lifecycle"), "{error}");
}

#[test]
fn authority_cells_and_generation_cuts_cannot_be_replaced_by_decoded_claims() {
    let (chain, _) = recorded();
    let state = chain.state();
    validate_persisted_records(state).unwrap();
    let mut world = state.world.block();
    *world.sccp_liability_clock.get_mut() += 1;
    world.commit();
    assert!(validate_persisted_records(state).is_err());
}

#[test]
fn raw_generation_decoder_and_anchor_decoder_keep_original_pool_and_exact_bytes() {
    let (chain, _) = recorded();
    // This is a codec/pool control over bytes from an actual executed fixture. It does
    // not treat serialization of a decoded claim as historical authority.
    let raw = chain
        .state()
        .world
        .sccp_committee_generations
        .view()
        .get(&1)
        .unwrap()
        .encode();
    let budget = AllocationBudget::new(1 << 20);
    let generation = RetainedSccpGeneration::decode_canonical(&raw, &budget).unwrap();
    assert_eq!(generation.encode(), raw);
    assert!(generation.belongs_to(&budget));
    drop(generation);
    assert_eq!(budget.reserved_bytes(), 0);
    let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    assert!(RetainedSccpGeneration::decode_canonical(&raw, &budget).is_err());
    drop(occupied);
    let generation = RetainedSccpGeneration::decode_canonical(&raw, &budget).unwrap();
    drop(generation);
    let mut changed = raw.clone();
    changed.push(0);
    assert!(RetainedSccpGeneration::decode_canonical(&changed, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    let values = vec![SccpAnchorV1 {
        core_hash: [1; 32],
        result: [2; 32],
    }];
    let bytes = values.encode();
    assert_eq!(
        anchors(&bytes, &budget).unwrap().as_slice(),
        values.as_slice()
    );
    let mut changed = bytes;
    changed.push(0);
    assert!(anchors(&changed, &budget).is_err());
    assert!(
        anchors(
            &vec![
                SccpAnchorV1 {
                    core_hash: [1; 32],
                    result: [2; 32],
                };
                4096
            ]
            .encode(),
            &budget,
        )
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn startup_adapter_preserves_original_refusal_and_deterministic_invalidity() {
    use crate::{
        execution_attempt::ExecutionAttemptError as Attempt, state::MergeLedgerCommitError,
        sumeragi::evidence::restoration_failure,
    };
    let budget = AllocationBudget::new(1);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let converted = restoration_failure(Error::Source(Attempt::Deferred(original.clone().into())));
    let MergeLedgerCommitError::ExecutionDeferred(kept) = converted else {
        panic!("original deferred owner")
    };
    assert_eq!(kept.allocation_refusal(), Some(&original));
    assert!(matches!(
        restoration_failure(invalid("forged source")),
        MergeLedgerCommitError::ExecutionStatePublication(_)
    ));
    assert!(matches!(
        restoration_failure(Preparation::OriginalHistoryPending.into()),
        MergeLedgerCommitError::ExecutionObservationChanged
    ));
    let retained = restoration_failure(Preparation::Admission(original.clone()).into());
    let MergeLedgerCommitError::StateStorageAdmission(
        crate::state::StateStorageAdmissionError::SccpEvidence(Preparation::Admission(kept)),
    ) = retained
    else {
        panic!("original preparation owner")
    };
    assert_eq!(kept, original);
    let storage = crate::state::sccp_forgery_custody::ForgeryStorageError::Storage(
        mv::storage::AdmittedStorageError::Allocation(original.clone()),
    );
    let converted = restoration_failure(Error::Storage(storage.clone()));
    let MergeLedgerCommitError::StateStorageAdmission(
        crate::state::StateStorageAdmissionError::SccpForgery(kept),
    ) = converted
    else {
        panic!("original SCCP storage owner")
    };
    assert_eq!(kept, storage);
    drop(occupied);

    // Capture an actual original writer conflict, rather than manufacturing a release token.
    let budget = AllocationBudget::new(1 << 20);
    let store =
        crate::state::sccp_forgery_custody::OffenceStorage::try_new_admitted(budget).unwrap();
    let busy = store
        .try_with_admitted_block(|_| {
            let failure = store
                .try_with_admitted_block(|_| Ok::<_, mv::storage::AdmittedStorageError>(()))
                .unwrap_err();
            match failure {
                mv::storage::AdmittedBlockError::Admission(original) => {
                    Ok::<_, mv::storage::AdmittedStorageError>(original)
                }
                mv::storage::AdmittedBlockError::Callback(_) => {
                    panic!("writer conflict precedes callback")
                }
            }
        })
        .unwrap();
    assert!(matches!(
        busy,
        mv::storage::AdmittedStorageError::Busy { .. }
    ));
    let storage = crate::state::sccp_forgery_custody::ForgeryStorageError::Storage(busy);
    let converted = restoration_failure(Error::Storage(storage.clone()));
    let MergeLedgerCommitError::StateStorageAdmission(
        crate::state::StateStorageAdmissionError::SccpForgery(kept),
    ) = converted
    else {
        panic!("original busy/release owner")
    };
    assert_eq!(kept, storage);
}

#[test]
fn authenticated_pending_carrier_retries_original_pool_without_double_consumption() {
    use crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead;
    let (chain, _) = recorded();
    let state = chain.state();
    let mut read = SccpHistoryRead::from_original_state_for_test(state);
    let budget = read.budget().clone();
    let network = read.network();
    let mut reducer = SccpRestore::new(state, 3, &budget).unwrap();
    let mut occupied = None;
    let mut calls = [0usize; 3];
    let mut pending_identity = None;
    let result = read.poll_for_test::<Error>(|source, instance| {
        let h = source.block().header().height().get();
        calls[usize::try_from(h - 1).unwrap()] += 1;
        if h == 3 {
            pending_identity = Some((
                source.block().hash(),
                source.core(),
                source.result(),
                source.delta().as_ptr(),
            ));
            occupied = Some(
                budget
                    .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                    .unwrap(),
            );
        }
        reducer.consume(source, instance, network, &budget, state)
    });
    let error = result.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Preparation(Preparation::Admission(_)) | Error::Storage(_)
        ),
        "{error}"
    );
    assert_eq!(calls, [1, 1, 1]);
    assert_eq!(read.consumed_for_test(), 2);
    assert!(!read.sealed_for_test());
    assert!(reducer.records.as_slice().is_empty());
    assert!(reducer.facts.offences.view().is_empty());
    drop(occupied.take());
    read.poll_for_test::<Error>(|source, instance| {
        let h = source.block().header().height().get();
        assert_eq!(h, 3, "authenticated predecessors are not consumed again");
        assert_eq!(
            Some((
                source.block().hash(),
                source.core(),
                source.result(),
                source.delta().as_ptr()
            )),
            pending_identity
        );
        calls[2] += 1;
        reducer.consume(source, instance, network, &budget, state)
    })
    .unwrap();
    assert_eq!(calls, [1, 1, 2]);
    assert_eq!(read.consumed_for_test(), 3);
    assert!(read.sealed_for_test() && reducer.is_complete());
    assert_eq!(reducer.records.as_slice().len(), 1);
    assert_eq!(reducer.facts.offences.view().len(), 3);
}

#[test]
fn ordinary_history_is_streamed_without_height_sized_carrier_residency() {
    use crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead;
    let (mut chain, _) = recorded();
    // Every fixture call executes genuine nonempty ordinary work. No forged receipt,
    // production empty block, or enlarged source/pool limit is used by this control.
    for _ in 0..96 {
        chain.commit(Vec::new());
    }
    let state = chain.state();
    let tip = u64::try_from(state.view().height()).unwrap();
    // Measure original authenticated source lengths with a separate streaming pass.
    // Only scalar counters survive this pass; the restore below authenticates its own sources.
    let mut measure = SccpHistoryRead::from_original_state_for_test(state);
    let mut archive_volume = 0usize;
    let mut block_volume = 0u64;
    measure
        .poll_for_test::<Error>(|source, _| {
            archive_volume = archive_volume
                .checked_add(source.archive_source_bytes_for_test())
                .unwrap();
            block_volume = block_volume
                .checked_add(source.block().canonical_wire_identity().unwrap().0)
                .unwrap();
            Ok(())
        })
        .unwrap();
    assert!(measure.sealed_for_test());
    drop(measure);
    let mut read = SccpHistoryRead::from_original_state_for_test(state);
    let budget = read.budget().clone();
    let network = read.network();
    let mut reducer = SccpRestore::new(state, tip, &budget).unwrap();
    let limit = budget.limit_bytes();
    let source_state_and_reducer = budget.reserved_bytes();
    let headroom = archive_volume / 2;
    assert!(headroom > 0 && headroom < limit - source_state_and_reducer);
    // A real competing owner occupies this SAME configured pool. This is not a replacement
    // budget or a fabricated quota error; existing State and later prefix owners remain charged.
    let competing = budget
        .try_reserve_bytes(limit - source_state_and_reducer - headroom)
        .unwrap();
    let baseline = budget.reserved_bytes();
    assert_eq!(limit - baseline, headroom);
    assert!(
        archive_volume > headroom,
        "old cumulative archive residency cannot fit"
    );
    assert!(block_volume > 0);
    let mut consumed = 0u64;
    let mut actual_archive_volume = 0usize;
    let mut observed_extra = 0usize;
    read.poll_for_test::<Error>(|source, instance| {
        assert_eq!(source.block().header().height().get(), consumed + 1);
        actual_archive_volume = actual_archive_volume
            .checked_add(source.archive_source_bytes_for_test())
            .unwrap();
        reducer.consume(source, instance, network, &budget, state)?;
        consumed += 1;
        observed_extra = observed_extra.max(budget.reserved_bytes().saturating_sub(baseline));
        assert!(reducer.records.as_slice().len() <= 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(actual_archive_volume, archive_volume);
    assert_eq!(consumed, tip);
    assert!(read.sealed_for_test() && reducer.is_complete());
    assert_eq!(read.retained_carriers_for_test(), 0);
    assert!(read.peak_retained_carriers_for_test() <= 2);
    assert!(read.peak_retained_carriers_for_test() > 0);
    assert_eq!(reducer.records.as_slice().len(), 1);
    assert_eq!(reducer.facts.offences.view().len(), 3);
    assert!(observed_extra > 0 && observed_extra <= headroom);
    assert_eq!(budget.limit_bytes(), limit);
    // This boundary observation is not a claim to measure every transient allocator peak;
    // successful execution under the unchanged finite pool enforces every charged peak.
    drop(competing);
}

#[test]
fn nonglobal_current_empty_cannot_hide_a_predecessor_sccp_record() {
    let (chain, id) = recorded();
    let original = claim(chain.state(), id);
    crate::state::native_capture_fixture::with_native_capture_dataspace_source(
        |state, block, guard, _source, _hash| {
            // Use the genuine independently signed Dataspace parent. Dropping its unrelated
            // pending transfer does not forge a Global tip or a successful forgery history.
            drop(guard);
            drop(block);
            let tip = state.view().native_execution_tip().unwrap();
            assert!(matches!(
                tip.root_scope(),
                iroha_data_model::block::consensus::SumeragiRootScope::Dataspace { .. }
            ));
            assert!(state.world.consensus_evidence.view().is_empty());
            validate_persisted_records(state).unwrap();
            let owner = funded(state, &original);
            let mut insert = state.world.consensus_evidence.block();
            insert.insert(id, owner);
            insert.commit();
            let mut remove = state.world.consensus_evidence.block();
            assert!(remove.remove(id).is_some());
            remove.commit();
            assert!(state.world.consensus_evidence.view().is_empty());
            assert!(
                state
                    .world
                    .consensus_evidence
                    .snapshot()
                    .revert_map()
                    .get(&id)
                    .unwrap()
                    .is_some()
            );
            let error = validate_persisted_records(state).unwrap_err();
            assert!(
                error.to_string().contains("no original Global history"),
                "{error}"
            );
            assert_eq!(state.view().native_execution_tip(), Some(tip));
        },
    );
}

#[test]
fn absent_original_tip_refuses_undo_only_offences_and_maximum() {
    use crate::smartcontracts::isi::sccp::test_support::blank_state;
    let (chain, id) = recorded();
    let original_key = chain
        .state()
        .world
        .sccp_forgery_offences
        .view()
        .iter()
        .next()
        .unwrap()
        .0
        .clone();
    for maximum_only in [false, true] {
        let mut state = blank_state();
        let budget = state
            .world
            .sccp_forgery_offences
            .allocation_budget()
            .clone();
        assert!(state.view().native_execution_tip().is_none());
        if maximum_only {
            state.world.sccp_forgery_max_generation =
                crate::state::sccp_forgery_custody::initialize_max(None, Some(Some(1)), &budget)
                    .unwrap();
        } else {
            // Copy the exact key through the destination's original owner, then create a
            // current-empty/predecessor-present claim. The decoded claim is not authority.
            let key =
                OffenceKey::try_copy(original_key.0, original_key.1, &original_key.2, &budget)
                    .unwrap();
            state
                .world
                .sccp_forgery_offences
                .try_with_admitted_block(|block| {
                    block
                        .try_insert_admitted(key.clone(), *id.as_ref())
                        .map_err(|(_, error)| error)
                })
                .unwrap();
            state
                .world
                .sccp_forgery_offences
                .try_with_admitted_block(|block| {
                    block.try_remove_admitted(key).map_err(|(_, error)| error)
                })
                .unwrap();
            assert!(state.world.sccp_forgery_offences.view().is_empty());
        }
        assert!(state.world.consensus_evidence.view().is_empty());
        let error = validate_persisted_records(&state).unwrap_err();
        assert!(
            error.to_string().contains("no original Global history"),
            "{error}"
        );
    }
}

thread_local! {
    // Test-only contention owns a real reservation from the exact source pool. It never
    // supplies a synthetic refusal and cannot change production authority or return values.
    static OCCUPY_AFTER_SUBMITS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OCCUPIED_AFTER_SUBMITS: std::cell::RefCell<Option<iroha_allocation::AllocationReservation>> = const { std::cell::RefCell::new(None) };
}
struct AfterSubmitsContention;
impl Drop for AfterSubmitsContention {
    fn drop(&mut self) {
        OCCUPY_AFTER_SUBMITS.with(|flag| flag.set(false));
        OCCUPIED_AFTER_SUBMITS.with(|owner| owner.borrow_mut().take());
    }
}
pub(super) fn after_submits_checkpoint(height: u64, budget: &AllocationBudget) {
    if height == 3 && OCCUPY_AFTER_SUBMITS.with(|flag| flag.replace(false)) {
        let charge = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        OCCUPIED_AFTER_SUBMITS.with(|owner| assert!(owner.borrow_mut().replace(charge).is_none()));
    }
}

#[test]
fn installed_record_and_partial_delta_retry_without_readmitting_the_submit() {
    use crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead;
    let (chain, _) = recorded();
    let state = chain.state();
    let mut read = SccpHistoryRead::from_original_state_for_test(state);
    let budget = read.budget().clone();
    let network = read.network();
    let mut reducer = SccpRestore::new(state, 3, &budget).unwrap();
    let guard = AfterSubmitsContention;
    OCCUPY_AFTER_SUBMITS.with(|flag| flag.set(true));
    let mut identity = None;
    let refused = read
        .poll_for_test::<Error>(|source, instance| {
            if source.block().header().height().get() == 3 {
                identity = Some((
                    source.block().hash(),
                    source.core(),
                    source.result(),
                    source.delta().as_ptr(),
                ));
            }
            reducer.consume(source, instance, network, &budget, state)
        })
        .unwrap_err();
    assert!(
        matches!(
            refused,
            Error::Preparation(Preparation::Admission(_)) | Error::Storage(_)
        ),
        "{refused}"
    );
    assert_eq!(read.consumed_for_test(), 2);
    assert!(!read.sealed_for_test());
    assert!(reducer.progress.submits_done);
    assert!(
        reducer.progress.delta_index > 0,
        "actual preceding delta cells installed before refusal"
    );
    assert!(!reducer.progress.delta_done);
    assert_eq!(reducer.records.as_slice().len(), 1);
    assert_eq!(reducer.facts.offences.view().len(), 3);
    assert_eq!(reducer.progress.expected_offences, 3);
    assert_eq!(reducer.facts.derived_maximum, Some(1));
    let network_index = reducer.progress.network_index;
    let delta_index = reducer.progress.delta_index;
    drop(guard);
    let mut retries = 0;
    read.poll_for_test::<Error>(|source, instance| {
        retries += 1;
        assert_eq!(source.block().header().height().get(), 3);
        assert_eq!(
            identity,
            Some((
                source.block().hash(),
                source.core(),
                source.result(),
                source.delta().as_ptr()
            ))
        );
        assert_eq!(reducer.progress.network_index, network_index);
        assert_eq!(reducer.progress.delta_index, delta_index);
        reducer.consume(source, instance, network, &budget, state)
    })
    .unwrap();
    assert_eq!(retries, 1);
    assert!(read.sealed_for_test() && reducer.is_complete());
    assert_eq!(read.consumed_for_test(), 3);
    assert_eq!(reducer.records.as_slice().len(), 1);
    assert_eq!(reducer.facts.offences.view().len(), 3);
    assert_eq!(reducer.facts.maximum, Some(1));
}

#[test]
fn enclosing_decode_refusals_keep_original_origin_after_helper_scopes_retire() {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    use ivm::error::ExecutionDeferral;
    use norito::core::DecodeBudgetContext;
    let (chain, _) = recorded();
    let raw = chain
        .state()
        .world
        .sccp_committee_generations
        .view()
        .get(&1)
        .unwrap()
        .encode();
    let pool = AllocationBudget::new(1 << 20);
    let limits = |allocated| {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocated, usize::MAX)
    };
    let context = DecodeBudgetContext::try_new_owned(limits(1 << 20), &pool).unwrap();
    let baseline = pool.reserved_bytes();
    // This error is produced by the real nested record decoder under an actual enclosing
    // caller ceiling. Consume it only after its inner context and narrow scope have retired.
    let original = context.with(|| {
        norito::with_decode_limits_scope(limits(0), || {
            RetainedSccpGeneration::decode_canonical(&raw, &pool).unwrap_err()
        })
    });
    let error = generation_error(original);
    assert!(
        matches!(error, Error::Source(Attempt::Deferred(ref original))
        if original.reason() == ExecutionDeferral::ActiveMemoryCapacity),
        "{error}"
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    let generation = context
        .with(|| RetainedSccpGeneration::decode_canonical(&raw, &pool))
        .unwrap();
    assert_eq!(generation.encode(), raw);
    assert!(generation.belongs_to(&pool));
    drop(generation);
    assert_eq!(pool.reserved_bytes(), baseline);

    let custom = SumeragiNposParameters::default().into_custom_parameter();
    let refused = context
        .with(|| norito::with_decode_limits_scope(limits(0), || policy_delay(&custom, &pool)))
        .unwrap_err();
    assert!(
        matches!(refused, Error::Source(Attempt::Deferred(ref original))
        if original.reason() == ExecutionDeferral::ActiveMemoryCapacity),
        "{refused}"
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(
        context
            .with(|| policy_delay(&custom, &pool))
            .unwrap()
            .unwrap()
            > 0
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    let mut malformed = raw.clone();
    malformed.push(0);
    let malformed = context
        .with(|| RetainedSccpGeneration::decode_canonical(&malformed, &pool))
        .unwrap_err();
    assert!(!matches!(
        generation_error(malformed),
        Error::Source(Attempt::Deferred(_))
    ));
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn permissioned_history_without_npos_policy_restores_but_present_invalid_policy_refuses() {
    use crate::{state::World, sumeragi::test_chain::TestChainConfig};
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    assert_eq!(chain.state().view().height(), 2);
    assert!(
        chain
            .state()
            .world_view()
            .sumeragi_npos_parameters()
            .unwrap()
            .is_none()
    );
    validate_persisted_records(chain.state()).unwrap();
    let restored_chain = replay_restore(
        &chain,
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap(),
    );
    let restored = restored_chain.state();
    assert_eq!(
        restored.view().native_execution_tip(),
        chain.state().view().native_execution_tip()
    );
    assert!(restored.world.consensus_evidence.view().is_empty());
    assert!(restored.world.sccp_forgery_offences.view().is_empty());
    assert!(
        restored
            .world
            .sccp_forgery_max_generation
            .view()
            .get()
            .is_none()
    );
    let pool = AllocationBudget::new(1 << 20);
    let malformed = iroha_data_model::parameter::CustomParameter::new(
        SumeragiNposParameters::parameter_id(),
        iroha_primitives::json::Json::new(false),
    );
    assert!(policy_delay(&malformed, &pool).is_err());
    let invalid = SumeragiNposParameters {
        slashing_delay_blocks: 0,
        ..SumeragiNposParameters::default()
    }
    .into_custom_parameter();
    assert!(policy_delay(&invalid, &pool).is_err());
}

#[test]
fn successful_submit_cannot_restore_without_its_original_penalty_policy() {
    use crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead;
    let (chain, _) = recorded();
    let state = chain.state();
    let mut read = SccpHistoryRead::from_original_state_for_test(state);
    let budget = read.budget().clone();
    let network = read.network();
    let mut reducer = SccpRestore::new(state, 3, &budget).unwrap();
    let refused = read
        .poll_for_test::<Error>(|source, instance| {
            if source.block().header().height().get() == 3 {
                // Negative internal-fact mutation only: the source remains genuinely signed.
                // No snapshot policy or protocol default may replace this missing original fact.
                assert_eq!(reducer.delay, Some(2));
                reducer.delay = None;
            }
            reducer.consume(source, instance, network, &budget, state)
        })
        .unwrap_err();
    assert!(matches!(refused, Error::Invalid(ref message) if message == "original delay missing"));
    assert_eq!(read.consumed_for_test(), 2);
    assert!(reducer.records.as_slice().is_empty());
    assert!(reducer.facts.offences.view().is_empty());
}
