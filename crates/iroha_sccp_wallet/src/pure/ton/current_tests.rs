//! Current TON certificate/proof cell shapes and operation source selection.

use super::*;
use crate::pure::{
    bundle::{CertificateUseV1, DestinationContextV1, certificate_wire, verify_message_bundle},
    control::{DestinationControlStateV1, verify_control_bundle},
    rotation::verify_rotation_steps,
    test_support::{Fixture, INSTANCE, NETWORK, NOW},
};
use iroha_sccp::v1::{
    destination::DestinationFlavor, finality::checkpoint_id, ton_cell::parse_snake_bytes,
};

fn context(f: &Fixture) -> DestinationContextV1<'_> {
    DestinationContextV1 {
        taira_network_id: NETWORK,
        consensus_instance: INSTANCE,
        destination: f.destination,
        flavor: DestinationFlavor::Ton,
        committee_state: f.state,
        ton_keys: Some(&f.keys),
        checkpoints: &f.checkpoints,
        now_ms: NOW,
    }
}

fn child(cell: &Cell, index: usize) -> &Cell {
    cell.refs()[index].cell().unwrap()
}

#[test]
fn current_certificate_cells_preserve_all_fixed_original_bytes() {
    let fixture = Fixture::new();
    let original = fixture.message().certificate;
    let wire = certificate_wire(&original).unwrap();
    let certificate = certificate_cell(&wire).unwrap();
    assert_eq!(certificate.bit_len(), 800);
    assert_eq!(certificate.refs().len(), 2);
    assert_eq!(&certificate.data()[..96], &original.aggregate_signature);
    assert_eq!(&certificate.data()[96..], &original.qc[112..]);
    let qc = child(&certificate, 0);
    assert_eq!(qc.bit_len(), 896);
    assert!(qc.refs().is_empty());
    assert_eq!(qc.data(), &original.qc[..112]);
    let head = child(&certificate, 1);
    assert_eq!(head.bit_len(), 872);
    assert_eq!(head.refs().len(), 1);
    assert_eq!(head.data(), &original.header[..109]);
    let tail = child(head, 0);
    assert_eq!(tail.bit_len(), 896);
    assert!(tail.refs().is_empty());
    assert_eq!(tail.data(), &original.header[109..]);
    assert_eq!(
        cell_from_boc(&certificate.to_boc().unwrap()).unwrap(),
        certificate
    );
    let reference = checkpoint_ref_cell(&CheckpointRefV1 {
        header: original.header.to_vec(),
    })
    .unwrap();
    assert_eq!(reference.bit_len(), 0);
    assert_eq!(reference.refs().len(), 1);
    assert_eq!(child(&reference, 0), head);
    let mut malformed = wire.clone();
    malformed.qc.pop();
    assert_eq!(certificate_cell(&malformed), Err(TonError::BadCertificate));
    malformed = wire.clone();
    malformed.header.push(0);
    assert_eq!(certificate_cell(&malformed), Err(TonError::BadCertificate));
    malformed = wire;
    malformed.ton_signature.pop();
    assert_eq!(certificate_cell(&malformed), Err(TonError::FieldTooLarge));
    assert_eq!(
        checkpoint_ref_cell(&CheckpointRefV1 { header: vec![] }),
        Err(TonError::BadCertificate)
    );
}

#[test]
fn block_message_and_control_cells_use_current_shapes_and_exact_paths() {
    let fixture = Fixture::new();
    for bundle in [fixture.message(), fixture.historical_message()] {
        let proof = bundle.message_proof();
        let block = block_ref_cell(&proof.block).unwrap();
        assert_eq!(block.bit_len(), 425);
        assert_eq!(
            block.refs().len(),
            usize::from(!proof.block.history_path.is_empty())
        );
        assert_eq!(&block.data()[..8], &proof.block.height.to_be_bytes());
        assert_eq!(&block.data()[8..40], &proof.block.sccp_root);
        assert_eq!(
            &block.data()[40..44],
            &proof.block.message_count.to_be_bytes()
        );
        assert_eq!(
            &block.data()[44..52],
            &proof.block.history_index.to_be_bytes()
        );
        assert_eq!(
            usize::from(block.data()[52]),
            proof.block.history_path.len()
        );
        let message = message_proof_cell(&proof).unwrap();
        assert_eq!(message.bit_len(), 41);
        assert_eq!(message.refs().len(), 3);
        assert_eq!(
            parse_snake_bytes(child(&message, 0), MAX_PAYLOAD_BYTES).unwrap(),
            proof.payload
        );
        assert_eq!(
            child(&message, 1),
            &hash_chunks(&proof.path).unwrap().unwrap()
        );
        assert_eq!(child(&message, 2), &block);
        assert_eq!(cell_from_boc(&message.to_boc().unwrap()).unwrap(), message);
    }
    let proof = fixture.control().control_proof();
    let cell = control_proof_cell(&proof).unwrap();
    assert_eq!(cell.bit_len(), 690);
    assert_eq!(cell.refs().len(), 2);
    let mut reader = Bits {
        cell: &cell,
        offset: 0,
    };
    assert_eq!(reader.read(64).unwrap(), u128::from(proof.control_nonce));
    assert_eq!(reader.read(8).unwrap(), u128::from(proof.track));
    assert_eq!(reader.read(1).unwrap(), u128::from(proof.parliament_paused));
    assert_eq!(
        reader.read(64).unwrap(),
        u128::from(proof.fast_pause_until_ms)
    );
    for byte in proof.certificate_id.iter().chain(&proof.effect_hash) {
        assert_eq!(reader.read(8).unwrap(), u128::from(*byte));
    }
    assert_eq!(reader.read(32).unwrap(), u128::from(proof.leaf_index));
    assert_eq!(reader.read(8).unwrap(), proof.path.len() as u128);
    assert_eq!(reader.read(1).unwrap(), 1);
    assert_eq!(child(&cell, 1), &block_ref_cell(&proof.block).unwrap());
    let mut bad = proof.clone();
    bad.parliament_paused = 2;
    assert_eq!(control_proof_cell(&bad), Err(TonError::FieldTooLarge));
    bad = proof;
    bad.path = vec![[1; 32]; MAX_BLOCK_PATH + 1];
    assert_eq!(control_proof_cell(&bad), Err(TonError::FieldTooLarge));
    let mut bad = fixture.message().message_proof();
    bad.payload = vec![1; MAX_PAYLOAD_BYTES + 1];
    assert_eq!(message_proof_cell(&bad), Err(TonError::FieldTooLarge));
    let mut bad = fixture.message().message_proof();
    bad.path = vec![[1; 32]; MAX_BLOCK_PATH + 1];
    assert_eq!(message_proof_cell(&bad), Err(TonError::FieldTooLarge));
    let mut bad = fixture.message().message_proof().block;
    bad.history_path = vec![[1; 32]; MAX_HISTORY_PATH + 1];
    assert_eq!(block_ref_cell(&bad), Err(TonError::FieldTooLarge));
}

#[test]
fn message_ops_select_checkpoint_source_independently_of_history() {
    let mut fixture = Fixture::new();
    for bundle in [fixture.message(), fixture.historical_message()] {
        fixture.checkpoints.insert(
            bundle.certificate.height,
            checkpoint_id(&bundle.certificate.header),
        );
        for usage in [CertificateUseV1::Inline, CertificateUseV1::Checkpoint] {
            let selected = context(&fixture);
            let verified =
                verify_message_bundle(&bundle, &selected, BundlePurposeV1::Finalize, usage)
                    .unwrap();
            let body = finalize_body(&verified, 7, &[3; 32]).unwrap();
            let op = if usage == CertificateUseV1::Inline {
                OP_SCCP_FINALIZE
            } else {
                OP_SCCP_FINALIZE_CHECKPOINT
            };
            assert_eq!(&body.data()[..4], &op.to_be_bytes());
            assert_eq!(body.bit_len(), 363);
            assert_eq!(body.refs().len(), 2);
            assert_eq!(
                child(&body, 1),
                &message_proof_cell(&bundle.message_proof()).unwrap()
            );
            assert_eq!(
                void_expired_body(&verified, 7, &[3; 32]),
                Err(TonError::WrongPurpose)
            );
            let mut later = selected;
            later.now_ms = bundle.deadline_ms + 1;
            let voided =
                verify_message_bundle(&bundle, &later, BundlePurposeV1::VoidExpired, usage)
                    .unwrap();
            let body = void_expired_body(&voided, 7, &[3; 32]).unwrap();
            let op = if usage == CertificateUseV1::Inline {
                OP_SCCP_VOID_EXPIRED
            } else {
                OP_SCCP_VOID_EXPIRED_CHECKPOINT
            };
            assert_eq!(&body.data()[..4], &op.to_be_bytes());
            assert_eq!(body.bit_len(), 427);
            assert_eq!(body.refs().len(), 2);
            assert_eq!(
                finalize_body(&voided, 7, &[3; 32]),
                Err(TonError::WrongPurpose)
            );
        }
    }
}

#[test]
fn checkpoint_messages_send_successor_keys_only_for_key_changes() {
    let fixture = Fixture::new();
    let next = Fixture::with_tag(1);
    for target in [&fixture, &next] {
        let plan =
            verify_rotation_steps(&[fixture.rotation(1, 101, target)], &context(&fixture), 2)
                .unwrap();
        let checkpoint = &plan.steps()[0];
        let body = checkpoint_body(checkpoint, 9, &[3; 32]).unwrap();
        assert_eq!(&body.data()[..4], &OP_SCCP_CHECKPOINT.to_be_bytes());
        assert_eq!(body.bit_len(), 364);
        let changed = target.state.root != fixture.state.root;
        assert_eq!(body.refs().len(), 1 + usize::from(changed));
        assert_eq!(
            child(&body, 0),
            &certificate_cell(checkpoint.certificate()).unwrap()
        );
        if changed {
            assert_eq!(child(&body, 1), &key_chunks(&next.keys).unwrap());
        }
    }
}

#[test]
fn control_ops_preserve_complete_cause_and_checkpoint_source() {
    let mut fixture = Fixture::new();
    let bundle = fixture.control();
    fixture.checkpoints.insert(
        bundle.certificate.height,
        checkpoint_id(&bundle.certificate.header),
    );
    for usage in [CertificateUseV1::Inline, CertificateUseV1::Checkpoint] {
        let verified = verify_control_bundle(
            &bundle,
            &context(&fixture),
            &DestinationControlStateV1::default(),
            usage,
        )
        .unwrap();
        let body = apply_control_body(&verified, 1, &[3; 32]).unwrap();
        let op = if usage == CertificateUseV1::Inline {
            OP_SCCP_APPLY_CONTROL
        } else {
            OP_SCCP_APPLY_CONTROL_CHECKPOINT
        };
        assert_eq!(&body.data()[..4], &op.to_be_bytes());
        assert_eq!(body.bit_len(), 363);
        assert_eq!(body.refs().len(), 2);
        assert_eq!(
            child(&body, 1),
            &control_proof_cell(&bundle.control_proof()).unwrap()
        );
    }
}

#[test]
fn typed_stack_preserves_cell_and_integer_order_and_rejects_noncanonical_nodes() {
    let keys = key_chunks(&Fixture::new().keys).unwrap();
    let empty = CellBuilder::new().build();
    let mut bottom = CellBuilder::new();
    bottom
        .store_ref(empty.clone())
        .unwrap()
        .store_uint(1, 8)
        .unwrap()
        .store_uint(7, 64)
        .unwrap();
    let bottom = bottom.build();
    let mut root = CellBuilder::new();
    root.store_uint(2, 24)
        .unwrap()
        .store_uint(3, 8)
        .unwrap()
        .store_ref(bottom.clone())
        .unwrap()
        .store_ref(keys.clone())
        .unwrap();
    let boc = root.build().to_boc().unwrap();
    let values = parse_stack(&boc).unwrap();
    assert_eq!(values.len(), 2);
    assert!(matches!(values[0], TvmStackValueV1::Integer(value) if value.to_u64() == Some(7)));
    assert_eq!(values[1], TvmStackValueV1::Cell(keys));
    assert_eq!(parse_int_stack(&boc), Err(TonError::BadStack));
    for (depth, extra_bit, extra_ref, missing_cell) in [
        (0, false, true, false),
        (1, true, false, false),
        (1, false, true, false),
        (1, false, false, true),
        (2, false, false, false),
        (0xff_ffff, false, false, false),
    ] {
        let mut hostile = CellBuilder::new();
        hostile.store_uint(depth, 24).unwrap();
        if depth != 0 {
            hostile
                .store_uint(3, 8)
                .unwrap()
                .store_ref(empty.clone())
                .unwrap();
            if !missing_cell {
                hostile.store_ref(bottom.clone()).unwrap();
            }
        }
        if extra_bit {
            hostile.store_bit(false).unwrap();
        }
        if extra_ref {
            hostile.store_ref(empty.clone()).unwrap();
        }
        assert_eq!(
            parse_stack(&hostile.build().to_boc().unwrap()),
            Err(TonError::BadStack)
        );
    }
    let mut trailing = CellBuilder::new();
    trailing
        .store_uint(0, 24)
        .unwrap()
        .store_bit(false)
        .unwrap();
    assert_eq!(
        parse_stack(&trailing.build().to_boc().unwrap()),
        Err(TonError::BadStack)
    );
    for values in [vec![], vec![0], vec![-1, 0, 7, i64::MAX]] {
        let decoded = parse_int_stack(&stack_of_ints(&values).unwrap()).unwrap();
        assert_eq!(decoded.len(), values.len());
        for (value, decoded) in values.iter().zip(decoded) {
            let mut expected = [if *value < 0 { 0xff } else { 0 }; 33];
            expected[25..].copy_from_slice(&value.to_be_bytes());
            assert_eq!(decoded, Some(TvmIntV1(expected)));
        }
    }
}
