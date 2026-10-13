//! Fixed-size source/frame controls; these fixtures authenticate no native forgery.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
use crate::state::State;
use iroha_data_model::{
    isi::Log,
    transaction::{FeePaymentIntent, TransactionBuilder, signed::SealedTransactionReveal},
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

fn evidence() -> SubmitSccpForgeryEvidenceV1 {
    SubmitSccpForgeryEvidenceV1 {
        qc: [1; 116],
        header: [2; 221],
        aggregate_signature: [3; 96],
        anchor: None,
    }
}

#[test]
fn keepalive_exact_direct_source_is_consumed_once_and_nested_calls_fail() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let instruction = InstructionBox::from(iroha_data_model::isi::chain::Keepalive {});
    let signed = signed(&state, vec![instruction.clone()]);
    let input = TransactionEntrypoint::External(signed.clone());
    for direct in [false, true] {
        source(&mut tx, &input);
        tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &instruction, 0, direct);
        assert_eq!(tx.consume_direct_keepalive().is_ok(), direct);
        assert!(tx.consume_direct_keepalive().is_err());
    }
    source(&mut tx, &input);
    tx.arm_direct_sccp_forgery(&signed, &BOB_ID, &instruction, 0, true);
    assert!(tx.consume_direct_keepalive().is_err());
}
fn signed(state: &State, instructions: Vec<InstructionBox>) -> SignedTransaction {
    TransactionBuilder::new(
        *state.network_id_ref(),
        ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(ALICE_KEYPAIR.private_key())
}
fn source(tx: &mut StateTransaction<'_, '_>, input: &TransactionEntrypoint) {
    let signed = match input {
        TransactionEntrypoint::External(signed) => signed,
        TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
        _ => unreachable!(),
    };
    tx.current_tx_hash = Some(signed.hash());
    tx.current_network_entrypoint_hash = Some(input.hash());
    tx.current_entrypoint_index = Some(4);
    tx.tx_call_hash = Some(Hash::from(input.execution_call_hash()));
    tx.bind_sccp_forgery_source(input, 4);
}

#[test]
fn captured_original_needs_the_exact_direct_frame_and_is_consumed_once() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let data = evidence();
    let signed = signed(&state, vec![data.clone().into()]);
    for reveal in [false, true] {
        let input = if reveal {
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                Hash::new(b"commitment"),
                signed.clone(),
                [7; 32],
            ))
        } else {
            TransactionEntrypoint::External(signed.clone())
        };
        source(&mut tx, &input);
        assert!(
            tx.consume_direct_sccp_forgery(&data).is_err(),
            "capture alone grants no instruction authority"
        );
        source(&mut tx, &input);
        tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &data.clone().into(), 0, true);
        assert!(tx.consume_direct_sccp_forgery(&data).is_ok());
        tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &data.clone().into(), 0, true);
        assert!(
            tx.consume_direct_sccp_forgery(&data).is_err(),
            "a consumed source cannot be rearmed"
        );
    }
}

#[test]
fn altered_payload_source_authority_index_or_nested_frame_has_no_ticket() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let data = evidence();
    let signed = signed(&state, vec![data.clone().into()]);
    let input = TransactionEntrypoint::External(signed.clone());
    for case in 0..9 {
        source(&mut tx, &input);
        let mut changed = data.clone();
        match case {
            0 => changed.qc[0] ^= 1,
            1 => changed.header[0] ^= 1,
            2 => changed.aggregate_signature[0] ^= 1,
            3 => tx.current_tx_hash = None,
            4 => tx.current_network_entrypoint_hash = None,
            5 => tx.current_entrypoint_index = Some(5),
            6 => tx.tx_call_hash = None,
            _ => {}
        }
        tx.arm_direct_sccp_forgery(
            &signed,
            if case == 7 { &BOB_ID } else { &ALICE_ID },
            &changed.clone().into(),
            0,
            case != 8,
        );
        assert!(
            tx.consume_direct_sccp_forgery(&changed).is_err(),
            "case {case}"
        );
    }
    source(&mut tx, &input);
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &data.clone().into(), 1, true);
    assert!(tx.consume_direct_sccp_forgery(&data).is_err());
}

#[test]
fn source_change_after_arming_and_mixed_signed_body_refuse() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let data = evidence();
    let sole = signed(&state, vec![data.clone().into()]);
    source(&mut tx, &TransactionEntrypoint::External(sole.clone()));
    tx.arm_direct_sccp_forgery(&sole, &ALICE_ID, &data.clone().into(), 0, true);
    let mut different = data.clone();
    different.header[0] ^= 1;
    assert!(tx.consume_direct_sccp_forgery(&different).is_err());
    assert!(
        tx.consume_direct_sccp_forgery(&data).is_err(),
        "even a rejected consumption destroys the ticket"
    );
    let mixed = signed(
        &state,
        vec![
            data.clone().into(),
            Log::new(iroha_logger::Level::INFO, "other".into()).into(),
        ],
    );
    source(&mut tx, &TransactionEntrypoint::External(mixed.clone()));
    tx.arm_direct_sccp_forgery(&mixed, &ALICE_ID, &data.clone().into(), 0, true);
    assert!(tx.consume_direct_sccp_forgery(&data).is_err());
}

#[test]
fn signed_body_completion_clears_any_remaining_ticket() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let data = evidence();
    let signed = signed(&state, vec![data.clone().into()]);
    source(&mut tx, &TransactionEntrypoint::External(signed.clone()));
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &data.clone().into(), 0, true);
    tx.clear_sccp_forgery_source();
    assert!(tx.consume_direct_sccp_forgery(&data).is_err());
}

#[test]
fn pause_direct_source_binds_each_signed_slot_and_cannot_be_rearmed_or_substituted() {
    use crate::state::sccp_pause_entrypoint::PauseOperation;
    use iroha_data_model::isi::sccp::AcceptSccpPausePanelSeatV1;
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let first = AcceptSccpPausePanelSeatV1 { panel_seq: 1 };
    let second = AcceptSccpPausePanelSeatV1 { panel_seq: 2 };
    let signed = signed(&state, vec![first.into(), second.into()]);
    let input = TransactionEntrypoint::External(signed.clone());
    for direct in [false, true] {
        source(&mut tx, &input);
        tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &first.into(), 0, direct);
        assert_eq!(
            tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
                .is_ok(),
            direct
        );
        assert!(
            tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
                .is_err()
        );
    }
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &first.into(), 0, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
            .is_err(),
        "a consumed signed panel instruction cannot be rearmed"
    );
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &first.into(), 1, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
            .is_err()
    );
    tx.arm_direct_sccp_forgery(&signed, &BOB_ID, &second.into(), 1, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(second))
            .is_err()
    );
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &second.into(), 1, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
            .is_err()
    );
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &second.into(), 1, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(second))
            .is_err(),
        "failed substitution consumes original slot"
    );
    source(&mut tx, &input);
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &second.into(), 1, true);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(second))
            .is_ok()
    );
    source(&mut tx, &input);
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &first.into(), 0, true);
    tx.current_entrypoint_index = Some(5);
    assert!(
        tx.consume_direct_sccp_pause(PauseOperation::Accept(first))
            .is_err()
    );
}

#[test]
fn sccp_pause_acceptance_executes_only_from_the_actual_signed_frame_and_rolls_back() {
    use crate::smartcontracts::{
        Execute as _,
        isi::sccp::{
            fast_pause,
            pause_record::RetainedSccpPausePanel,
            store,
            test_support::{sample_pause_panel, sample_route},
        },
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        isi::sccp::{AcceptSccpPausePanelSeatV1, EndorseSccpFastPauseV1},
        sccp::params::SccpParametersV1,
    };
    let state = blank_state();
    let mut block = state.block(header(2));
    let acceptance = AcceptSccpPausePanelSeatV1 { panel_seq: 1 };
    let signed = signed(&state, vec![acceptance.into()]);
    let input = TransactionEntrypoint::External(signed.clone());
    let mut panel = sample_pause_panel(1);
    panel.drawn[0] = ALICE_ID.clone();
    panel.accepted.clear();
    let mut tx = block.transaction();
    store::parameters::set(&mut tx, Some(SccpParametersV1::taira_default()));
    let retained =
        RetainedSccpPausePanel::admit(&panel, tx.sccp_evidence_preparation_budget()).unwrap();
    store::pause_panel::set(&mut tx, Some(retained));
    store::routes::insert(
        &mut tx,
        SccpNetworkV1::EthereumMainnet,
        sample_route(SccpNetworkV1::EthereumMainnet),
    )
    .unwrap();
    tx.apply();
    {
        let mut tx = block.transaction();
        assert!(
            fast_pause::admit(&*tx.world, *state.network_id_ref(), signed.payload(), None).is_ok()
        );
        assert!(acceptance.execute(&ALICE_ID, &mut tx).is_err());
        source(&mut tx, &input);
        tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &acceptance.into(), 0, true);
        acceptance.execute(&ALICE_ID, &mut tx).unwrap();
        assert!(
            store::pause_panel::get(&*tx.world)
                .as_ref()
                .unwrap()
                .accepted
                .binary_search(&ALICE_ID)
                .is_ok()
        );
        assert!(
            fast_pause::admit(&*tx.world, *state.network_id_ref(), signed.payload(), None).is_err()
        );
        assert!(acceptance.execute(&ALICE_ID, &mut tx).is_err());
        // Dropping the actual transaction discards both the account graph and its event.
    }
    assert!(
        store::pause_panel::get(&block.world)
            .as_ref()
            .unwrap()
            .accepted
            .is_empty()
    );
    let instruction = EndorseSccpFastPauseV1 {
        network_id: *state.network_id_ref(),
        network: SccpNetworkV1::EthereumMainnet,
        panel_id: panel.primary_id,
        head: 0,
        incident_digest: [7; 32],
    };
    let signed = self::signed(&state, vec![instruction.into()]);
    let mut tx = block.transaction();
    source(&mut tx, &TransactionEntrypoint::External(signed.clone()));
    tx.arm_direct_sccp_forgery(&signed, &ALICE_ID, &instruction.into(), 0, true);
    assert!(
        instruction.execute(&ALICE_ID, &mut tx).is_err(),
        "a genuine signature does not supply missing Parliament eligibility"
    );
    assert!(store::fast_pause_rounds::iter(&*tx.world).next().is_none());
    assert!(
        store::pause_panel::get(&*tx.world)
            .as_ref()
            .unwrap()
            .accepted
            .is_empty()
    );
}
