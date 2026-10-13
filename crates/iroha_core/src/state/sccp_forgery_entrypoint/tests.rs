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
