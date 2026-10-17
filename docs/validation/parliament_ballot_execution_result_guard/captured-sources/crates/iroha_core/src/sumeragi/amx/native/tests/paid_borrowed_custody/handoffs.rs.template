//! Final-boundary discovery, original proof custody and exact certified restart.

use super::*;
use crate::query::native_receipts::{NativeAmxRelaySourceV1, amx_relays};
use iroha_data_model::isi::sumeragi_amx::RelayGlobalAmxHandoffV1;

#[inline(never)]
fn boundary_roots() -> (CertifiedTestChain, CertifiedTestChain) {
    // The existing fixture authenticates a real NPoS boundary. Its DKG ceremony is
    // explicitly seeded component prestate at H8, not a claimed network ceremony.
    let mut global = CertifiedTestChain::npos_amx_boundary_fixture();
    let participant = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    let registration = RegisterAmxDataspaceV1 {
        dataspace: FIRST,
        instance: participant.instance().0,
        anchor: norito::encode_canonical(
            &authenticated_genesis(participant.genesis())
                .unwrap()
                .into_parts()
                .0,
        )
        .unwrap(),
    };
    let signed = global.sign(&global_config().genesis_key, [registration.into()], 1_999);
    let outcome = global.commit(vec![signed]);
    assert_eq!(
        outcome,
        vec![true],
        "registered AMX fixture must have its actual genesis capability: {:?}",
        global
            .committed(10)
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result,
    );
    assert_eq!(global.height(), 10);
    (global, participant)
}

#[test]
fn native_amx_handoff_registration_without_explicit_genesis_grant_refuses() {
    let mut global = CertifiedTestChain::npos_boundary_fixture();
    let participant = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    let registration = RegisterAmxDataspaceV1 {
        dataspace: FIRST,
        instance: participant.instance().0,
        anchor: norito::encode_canonical(
            &authenticated_genesis(participant.genesis())
                .unwrap()
                .into_parts()
                .0,
        )
        .unwrap(),
    };
    let signed = global.sign(&global_config().genesis_key, [registration.into()], 1_999);
    assert_eq!(global.commit(vec![signed]), vec![false]);
    let original = global.committed(10);
    let error = original
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .as_ref()
        .unwrap_err();
    assert!(
        format!("{error:?}")
            .contains("registering an AMX dataspace needs genesis or CanSetParameters"),
        "missing original registration grant must preserve its actual native refusal: {error:?}",
    );
    assert!(
        global
            .state()
            .view()
            .world()
            .sumeragi_amx()
            .dataspace(FIRST)
            .is_none()
    );
}

#[test]
fn native_amx_handoff_discovery_delivers_final_boundary_without_record_and_replays_both_roots() {
    let (global, mut participant) = boundary_roots();
    assert!(
        !prepared_intent_path(&global).exists(),
        "an epoch-boundary schedule is not an AMX record coordinates frame"
    );
    let budget = global.state().ivm_execution_budget();
    let (descriptor, instruction) = budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = global.state().view();
        assert!(amx_relays(&view, 9).unwrap().complete_next().unwrap().is_none());
        let mut discovery = amx_relays(&view, 10).unwrap();
        let intent = discovery.complete_next().unwrap().expect(
            "authenticated final epoch boundary must deliver its handoff without an AMX row or successor",
        );
        assert!(discovery.complete_next().unwrap().is_none());
        let (descriptor, instruction) = intent.into_parts();
        assert_eq!(descriptor.source(), NativeAmxRelaySourceV1::EpochBoundary {
            epoch: 0,
            next_epoch: 1,
        });
        assert_eq!(descriptor.source_height(), 10);
        assert_eq!(descriptor.source_carrier(), global.committed(10).block().hash());
        assert_eq!(descriptor.source_network(), global.network_id());
        assert_eq!(descriptor.source_scope(), SumeragiRootScope::Global);
        assert_eq!(descriptor.target_network(), participant.network_id());
        assert_eq!(descriptor.target_instance(), participant.instance().0);
        assert_eq!(descriptor.target_scope(), participant.root_scope());
        let relay = instruction.as_any().downcast_ref::<RelayGlobalAmxHandoffV1>().unwrap();
        assert_eq!(relay.dataspace, FIRST);
        assert_eq!(relay.proof.block.consensus_header,
            global.committed(10).block().commit_certificate().unwrap().consensus_header());
        assert!(instruction.amx_proof_admitted_to(&budget));
        let bytes = instruction.amx_proof_allocation_bytes().unwrap();
        drop(discovery);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline + bytes);
        (descriptor, instruction)
    });
    let expected = norito::encode_canonical(&instruction).unwrap();
    let signed = participant.sign(&payer(), [instruction], 2_999);
    assert_eq!(participant.commit_at(3_000, vec![signed]), vec![true]);
    assert_eq!(native(&participant).participant.global.epoch(), 1);
    assert_eq!(
        global.height(),
        10,
        "no successor or unrelated payment unlocks delivery"
    );

    // Reverify the original explicit H8 DKG prestate in a new pool, then replay H9/H10. This verifies restart custody without claiming a transaction-driven DKG.
    let restored_global = CertifiedTestChain::restore_npos_amx_boundary_fixture(&global).unwrap();
    assert_eq!(restored_global.height(), 10);
    assert!(!prepared_intent_path(&restored_global).exists());
    {
        let view = restored_global.state().view();
        let mut restarted = amx_relays(&view, 10).unwrap();
        let repeated = restarted.complete_next().unwrap().unwrap();
        assert_eq!(*repeated.descriptor(), descriptor);
        assert_eq!(
            norito::encode_canonical(repeated.instruction()).unwrap(),
            expected
        );
        assert!(restarted.complete_next().unwrap().is_none());
    }
    let mut restored_participant =
        CertifiedTestChain::start(private_config(&restored_global, FIRST)).unwrap();
    restored_participant.replay_from(&participant).unwrap();
    assert_eq!(native(&restored_participant), native(&participant));
    assert_eq!(native(&restored_participant).participant.global.epoch(), 1);
}

fn handoff_pointers(proof: &iroha_data_model::sumeragi_amx::AmxHandoffProofV1) -> [usize; 3] {
    [
        proof.block.consensus_header.as_ptr() as usize,
        proof.block.commit_qc.as_ptr() as usize,
        proof.block.result_preimage.as_ptr() as usize,
    ]
}

#[test]
fn native_amx_handoff_refusal_keeps_original_pool_graph_and_final_namespace_until_retry() {
    use crate::query::native_receipts::{
        NativeAmxHandoffRelayErrorV1, NativeAmxRelayDiscoveryErrorV1, NativeAmxRelayDiscoveryPollV1,
    };
    let retirement_pin = crossbeam_epoch::pin();
    let (global, _) = boundary_roots();
    let budget = global.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = global.state().view();
        let mut read = amx_relays(&view, 10).unwrap();
        while read.retained_handoff_proof().is_none() {
            assert!(matches!(
                read.poll().unwrap(),
                NativeAmxRelayDiscoveryPollV1::Pending
            ));
        }
        let proof = read.retained_handoff_proof().unwrap();
        assert!(proof.belongs_to(&budget));
        let pointers = handoff_pointers(proof.canonical());
        let original_bytes = norito::encode_canonical(proof.canonical()).unwrap();
        let reserved = budget.reserved_bytes();
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - reserved)
            .unwrap();
        let refused = read.poll();
        assert!(
            matches!(
                refused,
                Err(NativeAmxRelayDiscoveryErrorV1::Handoff(
                    NativeAmxHandoffRelayErrorV1::Instruction(
                        iroha_data_model::isi::AmxInstructionAdmissionErrorV1::Admission(
                            iroha_allocation::AllocationRefusal::Capacity { .. }
                        )
                    )
                ))
            ),
            "handoff action must retain original-pool refusal before its graph moves"
        );
        assert_eq!(
            handoff_pointers(read.retained_handoff_proof().unwrap().canonical()),
            pointers
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), reserved);
        while read.retained_handoff_instruction().is_none() {
            assert!(matches!(
                read.poll().unwrap(),
                NativeAmxRelayDiscoveryPollV1::Pending
            ));
        }
        let retained = read.retained_handoff_instruction().unwrap();
        assert!(retained.amx_proof_admitted_to(&budget));
        let proof = &retained
            .as_any()
            .downcast_ref::<RelayGlobalAmxHandoffV1>()
            .unwrap()
            .proof;
        assert_eq!(handoff_pointers(proof), pointers);
        assert_eq!(norito::encode_canonical(proof).unwrap(), original_bytes);
        let mut namespace = IntentNamespaceReplacement::new(&global);
        namespace.replace();
        let refused = read.complete_next();
        namespace.restore();
        assert!(
            refused.is_err(),
            "handoff must recheck its original namespace after action admission"
        );
        let retained = read.retained_handoff_instruction().unwrap();
        assert_eq!(
            handoff_pointers(
                &retained
                    .as_any()
                    .downcast_ref::<RelayGlobalAmxHandoffV1>()
                    .unwrap()
                    .proof
            ),
            pointers
        );
        let delivered = read.complete_next().unwrap().unwrap();
        assert_eq!(
            handoff_pointers(
                &delivered
                    .instruction()
                    .as_any()
                    .downcast_ref::<RelayGlobalAmxHandoffV1>()
                    .unwrap()
                    .proof
            ),
            pointers
        );
        assert!(read.complete_next().unwrap().is_none());
        let bytes = delivered
            .instruction()
            .amx_proof_allocation_bytes()
            .unwrap();
        drop(read);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline + bytes);
        drop(delivered);
        assert_eq!(budget.reserved_bytes(), baseline);
    });
    drop(retirement_pin);
}

#[test]
fn native_amx_handoff_discovery_rejects_substituted_original_witness_and_retries_same_height() {
    let (global, _) = boundary_roots();
    let path = prepared_intent_path(&global).with_extension("nrt");
    let prior = global
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            9,
            hex::encode(global.committed(9).block().hash().as_ref()),
        ));
    let original = std::fs::read(&path).unwrap();
    let earlier = std::fs::read(&prior).unwrap();
    let view = global.state().view();
    std::fs::write(&path, &earlier).unwrap();
    let refused = amx_relays(&view, 10).unwrap().complete_next();
    std::fs::write(&path, &original).unwrap();
    assert!(
        refused.is_err(),
        "a different original witness cannot authorize an epoch-boundary handoff"
    );
    let mut recovered = amx_relays(&view, 10).unwrap();
    let intent = recovered.complete_next().unwrap().unwrap();
    assert_eq!(intent.descriptor().source_height(), 10);
    assert_eq!(
        intent.descriptor().source_carrier(),
        global.committed(10).block().hash()
    );
    assert!(recovered.complete_next().unwrap().is_none());
}
