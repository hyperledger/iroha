//! Current block-reference and control-cause proof controls.

use super::*;
use crate::v1::{
    destination::BlockRefV1,
    finality::{FLAG_ACTIVE, SccpFinalityHeaderFieldsV1},
    hashes::word_address,
    history::HistoryAccumulatorV1,
    merkle::PromoteOddTree,
};

const TAIRA: [u8; 32] = [0x11; 32];

fn destination() -> DestinationV1 {
    DestinationV1 {
        network: SccpNetworkV1::EthereumMainnet,
        route_revision: 1,
        destination_word: word_address(&[0x22; 20]),
    }
}

fn payload(nonce: u64, recipient: [u8; 20]) -> Vec<u8> {
    SccpTransferPayloadV1::outbound(
        SccpNetworkV1::EthereumMainnet,
        nonce,
        1,
        1_800_000_000_000,
        1_000,
        vec![1, 2, 3],
        recipient.to_vec(),
    )
    .unwrap()
    .encode()
    .unwrap()
}

struct Block {
    leaves: Vec<[u8; 32]>,
    tree: PromoteOddTree,
    payloads: Vec<Vec<u8>>,
}

fn block() -> Block {
    let dest = destination();
    let payloads: Vec<Vec<u8>> = (0..3).map(|nonce| payload(nonce, [0x33; 20])).collect();
    let mut leaves: Vec<[u8; 32]> = payloads
        .iter()
        .map(|bytes| {
            MessageProofV1 {
                payload: bytes.clone(),
                ..MessageProofV1::default()
            }
            .transfer(&TAIRA, &dest)
            .unwrap()
            .leaf
        })
        .collect();
    let control = ControlProofV1 {
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
        ..ControlProofV1::default()
    };
    leaves.push(control.leaf(&TAIRA, &dest).unwrap());
    let tree = PromoteOddTree::block(&leaves).unwrap();
    Block {
        leaves,
        tree,
        payloads,
    }
}

fn header(
    height: u64,
    root: [u8; 32],
    count: u32,
    history: &HistoryAccumulatorV1,
) -> SccpFinalityHeaderV1 {
    SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: TAIRA,
        height,
        timestamp_ms: 1_800_000_000_000,
        flags: FLAG_ACTIVE,
        message_count: count,
        sccp_root: root,
        history_root: history.root(),
        history_size: history.size(),
        generation: 1,
        committee_root: [9; 32],
        validity_ms: 0,
        next_committee_root: [0; 32],
    })
    .unwrap()
}
fn block_ref(height: u64, root: [u8; 32], count: u32) -> BlockRefV1 {
    BlockRefV1 {
        height,
        sccp_root: root,
        message_count: count,
        history_index: 0,
        history_path: vec![],
    }
}
fn control() -> ControlProofV1 {
    ControlProofV1 {
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
        ..ControlProofV1::default()
    }
}

#[test]
fn direct_transfer_and_control() {
    let block = block();
    let mut history = HistoryAccumulatorV1::new();
    history
        .append(&hashes::history_leaf(50, &block.tree.root(), 4))
        .unwrap();
    let attestation = header(50, block.tree.root(), 4, &history);
    let dest = destination();
    let proof = MessageProofV1 {
        payload: block.payloads[1].clone(),
        leaf_index: 1,
        path: block.tree.path(1).unwrap(),
        block: block_ref(50, block.tree.root(), 4),
    };
    let verified = verify_transfer(&attestation, &proof, &TAIRA, &dest).unwrap();
    assert_eq!(verified.payload.nonce, 1);
    assert_eq!(verified.leaf, block.leaves[1]);
    let wrong_index = MessageProofV1 {
        leaf_index: 2,
        ..proof.clone()
    };
    assert_eq!(
        verify_transfer(&attestation, &wrong_index, &TAIRA, &dest),
        Err(ProofError::BadBlockPath)
    );
    let control = ControlProofV1 {
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
        leaf_index: 3,
        path: block.tree.path(3).unwrap(),
        block: block_ref(50, block.tree.root(), 4),
        ..ControlProofV1::default()
    };
    assert_eq!(
        verify_control(&attestation, &control, &TAIRA, &dest),
        Ok(block.leaves[3])
    );
    // The same fields with the other pause value, or another revision, do not verify.
    let resumed = ControlProofV1 {
        parliament_paused: 0,
        ..control.clone()
    };
    assert_eq!(
        verify_control(&attestation, &resumed, &TAIRA, &dest),
        Err(ProofError::BadBlockPath)
    );
    let other_revision = DestinationV1 {
        route_revision: 2,
        ..dest
    };
    assert_eq!(
        verify_control(&attestation, &control, &TAIRA, &other_revision),
        Err(ProofError::BadBlockPath)
    );
    // A transfer proof offered at the control leaf position fails.
    let at_control = MessageProofV1 {
        payload: block.payloads[0].clone(),
        leaf_index: 3,
        path: block.tree.path(3).unwrap(),
        block: block_ref(50, block.tree.root(), 4),
    };
    assert_eq!(
        verify_transfer(&attestation, &at_control, &TAIRA, &dest),
        Err(ProofError::BadBlockPath)
    );
    let empty = header(50, [0; 32], 0, &history);
    assert_eq!(
        verify_transfer(&empty, &proof, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut extra = proof.clone();
    extra.block.history_path.push([1; 32]);
    assert_eq!(
        verify_transfer(&attestation, &extra, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut extra = proof.clone();
    extra.block.history_index = 1;
    assert_eq!(
        verify_transfer(&attestation, &extra, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut altered = proof.clone();
    altered.block.sccp_root = [1; 32];
    assert_eq!(
        verify_transfer(&attestation, &altered, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    for change in 0..5 {
        let mut altered = control.clone();
        match change {
            0 => altered.track = 2,
            1 => altered.fast_pause_until_ms = 10,
            2 => altered.certificate_id = [0; 32],
            3 => altered.effect_hash = [1; 32],
            _ => altered.control_nonce += 1,
        }
        assert_eq!(
            verify_control(&attestation, &altered, &TAIRA, &dest),
            Err(ProofError::BadBlockPath)
        );
    }
}

#[test]
fn historical_mode() {
    let block = block();
    let mut history = HistoryAccumulatorV1::new();
    history
        .append(&hashes::history_leaf(7, &[1; 32], 1))
        .unwrap();
    let old_leaf = hashes::history_leaf(50, &block.tree.root(), 4);
    history.append(&old_leaf).unwrap();
    history
        .append(&hashes::history_leaf(80, &[2; 32], 2))
        .unwrap();
    let history_leaves = [
        hashes::history_leaf(7, &[1; 32], 1),
        old_leaf,
        hashes::history_leaf(80, &[2; 32], 2),
    ];
    let latest = header(80, [2; 32], 2, &history);
    let history_ref = BlockRefV1 {
        height: 50,
        sccp_root: block.tree.root(),
        message_count: 4,
        history_index: 1,
        history_path: crate::v1::history::history_path(&history_leaves, 1).unwrap(),
    };
    let proof = MessageProofV1 {
        payload: block.payloads[2].clone(),
        leaf_index: 2,
        path: block.tree.path(2).unwrap(),
        block: history_ref.clone(),
    };
    let dest = destination();
    let verified = verify_transfer(&latest, &proof, &TAIRA, &dest).unwrap();
    assert_eq!(verified.payload.nonce, 2);
    let control = ControlProofV1 {
        leaf_index: 3,
        path: block.tree.path(3).unwrap(),
        block: history_ref,
        ..control()
    };
    assert!(verify_control(&latest, &control, &TAIRA, &dest).is_ok());
    let mut bad_height = proof.clone();
    bad_height.block.height = 51;
    assert_eq!(
        verify_transfer(&latest, &bad_height, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut zero_count = control.clone();
    zero_count.block.message_count = 0;
    assert_eq!(
        verify_control(&latest, &zero_count, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut future = proof.clone();
    future.block.height = 81;
    assert_eq!(
        verify_transfer(&latest, &future, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut bad_index = proof.clone();
    bad_index.block.history_index = 0;
    assert_eq!(
        verify_transfer(&latest, &bad_index, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    let mut extra = proof.clone();
    extra.block.history_path.push([0; 32]);
    assert_eq!(
        verify_transfer(&latest, &extra, &TAIRA, &dest),
        Err(ProofError::BadBlockReference)
    );
    assert_eq!(
        verify_transfer(&latest, &proof, &[8; 32], &dest),
        Err(ProofError::BadBlockReference)
    );
}

#[test]
fn payload_binding() {
    let dest = destination();
    let self_recipient = MessageProofV1 {
        payload: payload(0, [0x22; 20]),
        ..MessageProofV1::default()
    };
    assert_eq!(
        self_recipient.transfer(&TAIRA, &dest),
        Err(ProofError::RecipientIsDestination)
    );
    let other_revision = DestinationV1 {
        route_revision: 9,
        ..dest
    };
    let proof = MessageProofV1 {
        payload: payload(0, [0x33; 20]),
        ..MessageProofV1::default()
    };
    assert_eq!(
        proof.transfer(&TAIRA, &other_revision),
        Err(ProofError::WrongDestination)
    );
    let bsc = DestinationV1 {
        network: SccpNetworkV1::BscMainnet,
        ..dest
    };
    assert_eq!(
        proof.transfer(&TAIRA, &bsc),
        Err(ProofError::WrongDestination)
    );
    let garbage = MessageProofV1 {
        payload: vec![1, 2, 3],
        ..MessageProofV1::default()
    };
    assert_eq!(garbage.transfer(&TAIRA, &dest), Err(ProofError::BadPayload));
    let zero_nonce = ControlProofV1::default();
    assert_eq!(zero_nonce.leaf(&TAIRA, &dest), Err(ProofError::BadControl));
}

#[test]
fn is_self_per_codec() {
    let word = word_address(&[0x22; 20]);
    let dest = DestinationV1 {
        network: SccpNetworkV1::BscMainnet,
        route_revision: 1,
        destination_word: word,
    };
    assert!(dest.is_self(2, &[0x22; 20]));
    assert!(!dest.is_self(2, &[0x23; 20]));
    // The retired 21-byte TRON form (`0x41` then the address) names no deployment.
    let mut retired = vec![0x41];
    retired.extend_from_slice(&[0x22; 20]);
    assert!(!dest.is_self(5, &retired));
    let ton_dest = DestinationV1 {
        network: SccpNetworkV1::TonMainnet,
        route_revision: 1,
        destination_word: [0x44; 32],
    };
    let mut ton_account = vec![0; 4];
    ton_account.extend_from_slice(&[0x44; 32]);
    assert!(ton_dest.is_self(CODEC_TON_ACCOUNT36, &ton_account));
    ton_account[35] = 0;
    assert!(!ton_dest.is_self(CODEC_TON_ACCOUNT36, &ton_account));
}
