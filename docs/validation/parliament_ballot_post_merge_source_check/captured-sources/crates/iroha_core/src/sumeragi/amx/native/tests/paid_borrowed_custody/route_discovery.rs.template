//! Route-local discovery retains original authority while independent targets progress.

use super::*;
use crate::query::native_receipts::{
    NativeAmxHandoffRelayErrorV1, NativeAmxRelayDiscoveryErrorV1, NativeAmxRelayDiscoveryPollV1,
    amx_relays_to,
};
use iroha_data_model::isi::sumeragi_amx::{
    ExpireAmxV1, PrepareAmxV1, RelayAmxPreparedV1, RelayGlobalAmxHandoffV1, SettleAmxV1,
};

#[test]
fn native_amx_route_discovery_selects_prepare_expiry_and_final_decision_before_target_acquisition()
{
    let (roots, restored, tx, begin_height) = restarted_paid_decision();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = restored.state().view();
        for (index, participant) in roots.participants.iter().enumerate() {
            let mut begin = amx_relays_to(&view, begin_height, participant.network_id()).unwrap();
            let intent = begin.complete_next().unwrap().unwrap();
            assert_eq!(
                intent.descriptor().target_network(),
                participant.network_id()
            );
            let prepare = intent
                .instruction()
                .as_any()
                .downcast_ref::<PrepareAmxV1>()
                .unwrap();
            assert_eq!(prepare.dataspace, [FIRST, SECOND][index]);
            assert_eq!(prepare.transaction.id().unwrap(), tx);
            assert!(intent.instruction().amx_proof_admitted_to(&budget));
            assert!(
                begin.complete_next().unwrap().is_none(),
                "one route never constructs the other participant or Global expiry carrier"
            );
            drop(intent);
            drop(begin);
            let mut decision =
                amx_relays_to(&view, restored.height(), participant.network_id()).unwrap();
            let intent = decision.complete_next().unwrap().unwrap();
            let settle = intent
                .instruction()
                .as_any()
                .downcast_ref::<SettleAmxV1>()
                .unwrap();
            assert_eq!(settle.dataspace, [FIRST, SECOND][index]);
            assert_eq!(settle.decision.record.tx(), tx);
            assert_eq!(intent.descriptor().source_height(), restored.height());
            assert_eq!(
                intent.descriptor().target_network(),
                participant.network_id()
            );
            assert!(decision.complete_next().unwrap().is_none());
        }
        let mut expiry = amx_relays_to(&view, begin_height, restored.network_id()).unwrap();
        let intent = expiry.complete_next().unwrap().unwrap();
        let instruction = intent
            .instruction()
            .as_any()
            .downcast_ref::<ExpireAmxV1>()
            .unwrap();
        assert_eq!(instruction.tx, tx);
        assert_eq!(intent.descriptor().source_height(), begin_height);
        assert_eq!(intent.descriptor().target_network(), restored.network_id());
        assert!(intent.descriptor().ready_at_ms().is_some());
        assert!(intent.instruction().amx_proof_admitted_to(&budget));
        assert!(expiry.complete_next().unwrap().is_none());
        drop(intent);
        drop(expiry);
        let mut no_local_settle =
            amx_relays_to(&view, restored.height(), restored.network_id()).unwrap();
        assert!(no_local_settle.complete_next().unwrap().is_none());
        drop(no_local_settle);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline);
    });
    for participant in &roots.participants {
        let view = participant.state().view();
        let mut parent =
            amx_relays_to(&view, participant.height(), roots.global.network_id()).unwrap();
        let intent = parent.complete_next().unwrap().unwrap();
        assert_eq!(
            intent.descriptor().target_network(),
            roots.global.network_id()
        );
        let prepared = intent
            .instruction()
            .as_any()
            .downcast_ref::<RelayAmxPreparedV1>()
            .unwrap();
        assert_eq!(prepared.proof.record.tx(), tx);
        assert!(parent.complete_next().unwrap().is_none());
        let mut foreign =
            amx_relays_to(&view, participant.height(), participant.network_id()).unwrap();
        assert!(
            foreign.complete_next().unwrap().is_none(),
            "an authenticated private record emits only parent-directed work"
        );
    }
}

#[test]
fn native_amx_route_discovery_retains_refused_handoff_while_another_destination_advances() {
    let retirement_pin = crossbeam_epoch::pin();
    // This is a genuine certified boundary with explicit component DKG prestate.
    // Two immutable registrations produce independently routed funded instructions.
    let mut global = CertifiedTestChain::npos_amx_boundary_fixture();
    let participants =
        [FIRST, SECOND].map(|id| CertifiedTestChain::start(private_config(&global, id)).unwrap());
    let registrations = [FIRST, SECOND]
        .into_iter()
        .zip(&participants)
        .map(|(id, chain)| {
            RegisterAmxDataspaceV1 {
                dataspace: id,
                instance: chain.instance().0,
                anchor: norito::encode_canonical(
                    &authenticated_genesis(chain.genesis())
                        .unwrap()
                        .into_parts()
                        .0,
                )
                .unwrap(),
            }
            .into()
        })
        .collect::<Vec<InstructionBox>>();
    let signed = global.sign(&global_config().genesis_key, registrations, 1_999);
    assert_eq!(global.commit(vec![signed]), vec![true]);
    assert_eq!(global.height(), 10);
    let budget = global.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = global.state().view();
        let mut first = amx_relays_to(&view, 10, participants[0].network_id()).unwrap();
        while first.retained_handoff_proof().is_none() {
            assert!(matches!(first.poll().unwrap(), NativeAmxRelayDiscoveryPollV1::Pending));
        }
        let pointers = {
            let proof = first.retained_handoff_proof().unwrap();
            assert!(proof.belongs_to(&budget));
            handoff_pointers(proof.canonical())
        };
        let occupied = budget.try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes()).unwrap();
        assert!(matches!(first.poll(), Err(NativeAmxRelayDiscoveryErrorV1::Handoff(
            NativeAmxHandoffRelayErrorV1::Instruction(
                iroha_data_model::isi::AmxInstructionAdmissionErrorV1::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                )
            )
        ))));
        drop(occupied);
        let first_reserved = budget.reserved_bytes();
        let mut second = amx_relays_to(&view, 10, participants[1].network_id()).unwrap();
        let delivered = second.complete_next().unwrap().unwrap();
        assert_eq!(delivered.descriptor().target_network(), participants[1].network_id(),
            "requested route must be selected before unrelated target graph acquisition");
        assert_eq!(delivered.instruction().as_any().downcast_ref::<RelayGlobalAmxHandoffV1>().unwrap().dataspace, SECOND);
        assert!(delivered.instruction().amx_proof_admitted_to(&budget));
        assert!(second.complete_next().unwrap().is_none());
        assert_eq!(handoff_pointers(first.retained_handoff_proof().unwrap().canonical()), pointers,
            "independent destination progress never replaces the refused route's original proof graph");
        drop(delivered);
        drop(second);
        assert_eq!(budget.reserved_bytes(), first_reserved);
        let resumed = first.complete_next().unwrap().unwrap();
        let original = resumed.instruction().as_any().downcast_ref::<RelayGlobalAmxHandoffV1>().unwrap();
        assert_eq!(original.dataspace, FIRST);
        assert_eq!(handoff_pointers(&original.proof), pointers);
        assert!(first.complete_next().unwrap().is_none());
        drop(resumed);
        drop(first);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline);
    });
    drop(retirement_pin);
}

fn handoff_pointers(proof: &iroha_data_model::sumeragi_amx::AmxHandoffProofV1) -> [usize; 3] {
    [
        proof.block.consensus_header.as_ptr() as usize,
        proof.block.commit_qc.as_ptr() as usize,
        proof.block.result_preimage.as_ptr() as usize,
    ]
}
