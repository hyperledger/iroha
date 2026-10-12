//! Current certificate ABI layouts and rejection controls; source burn/log controls are retained.
use super::*;
use crate::v1::{
    destination_abi::{SELECTORS, TOPIC_CONTROL_APPLIED},
    hashes::keccak256,
};
const TAIRA: [u8; 32] = [0x11; 32];
fn word_hex(data: &[u8], index: usize) -> String {
    crate::v1::hashes::to_hex(&data[index * WORD..(index + 1) * WORD])
}

// Raw bytes intentionally exercise ABI shape, not cryptographic certificate acceptance.
fn certificate() -> TairaCertificateV1 {
    TairaCertificateV1 {
        qc: vec![0x11; 116],
        header: vec![0x22; 221],
        signature: vec![0x33; 192],
        committee: vec![0x44; 192],
        signer_ys: vec![0x55; 144],
        ton_signature: vec![0x66; 96],
    }
}
fn proof() -> MessageProofV1 {
    MessageProofV1 {
        payload: vec![0x02; 133],
        leaf_index: 1,
        path: vec![[0x77; 32], [0x88; 32]],
        block: BlockRefV1 {
            height: 3,
            sccp_root: [1; 32],
            message_count: 2,
            history_index: 5,
            history_path: vec![[2; 32], [3; 32], [4; 32]],
        },
    }
}
fn checkpoint() -> CheckpointRefV1 {
    CheckpointRefV1 {
        header: certificate().header,
    }
}
#[test]
fn token_shapes() {
    assert!(!AbiToken::Word([0; 32]).is_dynamic());
    assert!(AbiToken::Bytes(vec![]).is_dynamic());
    assert!(AbiToken::Array(vec![]).is_dynamic());
    let certificate = certificate_token(&certificate());
    assert!(certificate.is_dynamic());
    assert_eq!(certificate.head_len(), WORD);
    assert_eq!(
        certificate.encode().len(),
        5 * WORD + (WORD + 128) + (WORD + 224) + (WORD + 192) + (WORD + 192) + (WORD + 160)
    );
    let checkpoint = checkpoint_token(&checkpoint());
    assert!(checkpoint.is_dynamic());
    assert_eq!(checkpoint.head_len(), WORD);
    assert_eq!(checkpoint.encode().len(), 2 * WORD + 224);
    let block = block_ref_token(&proof().block);
    assert!(block.is_dynamic());
    assert_eq!(block.head_len(), WORD);
    assert_eq!(block.encode().len(), 9 * WORD);
    assert_eq!(padding(0), 0);
    assert_eq!(padding(1), 31);
    assert_eq!(padding(32), 0);
    assert_eq!(padding(80), 16);
}
#[test]
fn bytes_and_array_encoding() {
    let encoded = encode_tokens(&[AbiToken::Bytes(vec![0xab; 33])]);
    assert_eq!(encoded.len(), 4 * WORD);
    assert_eq!(word_hex(&encoded, 0), format!("{:064x}", 0x20));
    assert_eq!(word_hex(&encoded, 1), format!("{:064x}", 33));
    assert_eq!(encoded[2 * WORD..2 * WORD + 33], [0xab; 33]);
    assert!(encoded[2 * WORD + 33..].iter().all(|byte| *byte == 0));
    let array = encode_tokens(&[AbiToken::Array(vec![
        AbiToken::Word([1; 32]),
        AbiToken::Word([2; 32]),
    ])]);
    assert_eq!(word_hex(&array, 0), format!("{:064x}", 0x20));
    assert_eq!(word_hex(&array, 1), format!("{:064x}", 2));
    assert_eq!(array[2 * WORD..3 * WORD], [1; 32]);
    // Array of dynamic tuples: offsets relative to the first element head.
    let nested = encode_tokens(&[AbiToken::Array(vec![
        AbiToken::Tuple(vec![AbiToken::Bytes(vec![1])]),
        AbiToken::Tuple(vec![AbiToken::Bytes(vec![2, 3])]),
    ])]);
    assert_eq!(word_hex(&nested, 1), format!("{:064x}", 2));
    assert_eq!(word_hex(&nested, 2), format!("{:064x}", 0x40));
    // First tuple: offset word + length word + one padded data word.
    assert_eq!(word_hex(&nested, 3), format!("{:064x}", 0x40 + 3 * WORD));
    assert_eq!(nested.len(), 4 * WORD + 2 * 3 * WORD);
}

#[test]
fn finalize_calldata_layout() {
    let certificate = certificate();
    let proof = proof();
    let data = finalize_from_taira_calldata(&certificate, &proof);
    assert_eq!(data[..4], SELECTOR_FINALIZE_FROM_TAIRA);
    let args = &data[4..];
    let certificate_len = certificate_token(&certificate).encode().len();
    assert_eq!(word_hex(args, 0), format!("{:064x}", 2 * WORD));
    assert_eq!(
        word_hex(args, 1),
        format!("{:064x}", 2 * WORD + certificate_len)
    );
    let cert = &args[2 * WORD..];
    assert_eq!(word_hex(cert, 0), format!("{:064x}", 5 * WORD));
    assert_eq!(word_hex(cert, 1), format!("{:064x}", 6 * WORD + 128));
    assert_eq!(word_hex(cert, 5), format!("{:064x}", 116));
    let msg = &args[2 * WORD + certificate_len..];
    assert_eq!(word_hex(msg, 0), format!("{:064x}", 4 * WORD));
    assert_eq!(word_hex(msg, 1), format!("{:064x}", 1));
    assert_eq!(word_hex(msg, 2), format!("{:064x}", 5 * WORD + 160));
    assert_eq!(word_hex(msg, 3), format!("{:064x}", 8 * WORD + 160));
    assert_eq!(msg.len(), 17 * WORD + 160);
}
#[test]
fn every_state_changing_call_uses_its_selector() {
    let cert = certificate();
    let checkpoint = checkpoint();
    let proof = proof();
    let control = ControlProofV1 {
        control_nonce: 1,
        track: 2,
        parliament_paused: 1,
        fast_pause_until_ms: 99,
        certificate_id: [6; 32],
        effect_hash: [7; 32],
        leaf_index: 0,
        path: vec![],
        block: proof.block.clone(),
    };
    let calls = [
        finalize_from_taira_calldata(&cert, &proof),
        finalize_from_checkpoint_calldata(&checkpoint, &proof),
        submit_checkpoints_calldata(std::slice::from_ref(&cert)),
        apply_control_calldata(&cert, &control),
        apply_control_from_checkpoint_calldata(&checkpoint, &control),
        void_expired_calldata(9, &cert, &proof),
        void_expired_from_checkpoint_calldata(9, &checkpoint, &proof),
        void_frozen_calldata(4, 2),
        TransferToTairaCallV1 {
            taira_recipient: vec![1],
            token_amount: 5,
            expected_nonce: 0,
        }
        .calldata(),
    ];
    let expected = [
        SELECTOR_FINALIZE_FROM_TAIRA,
        SELECTOR_FINALIZE_FROM_CHECKPOINT,
        SELECTOR_SUBMIT_CHECKPOINTS,
        SELECTOR_APPLY_CONTROL,
        SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT,
        SELECTOR_VOID_EXPIRED,
        SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
        SELECTOR_VOID_FROZEN,
        SELECTOR_TRANSFER_TO_TAIRA,
    ];
    for (calldata, selector) in calls.iter().zip(expected) {
        assert_eq!(selector_of(calldata), Ok(selector));
        assert_eq!((calldata.len() - 4) % WORD, 0);
        assert!(SELECTORS.iter().any(|(_, _, known)| *known == selector));
    }
    for (i, from_checkpoint) in [(5, false), (6, true)] {
        assert_eq!(
            VoidCallV1::decode(&calls[i]),
            Ok(VoidCallV1::Expired {
                nonce: 9,
                from_checkpoint
            })
        );
        assert_eq!(VoidCallV1::decode(&calls[i]).unwrap().range(), (9, 1));
    }
    assert_eq!(
        VoidCallV1::decode(&calls[7]),
        Ok(VoidCallV1::Frozen {
            first_nonce: 4,
            count: 2
        })
    );
    assert_eq!(VoidCallV1::decode(&calls[7]).unwrap().range(), (4, 2));
    assert_eq!(VoidCallV1::decode(&calls[0]), Err(AbiError::WrongSelector));
    assert_eq!(VoidCallV1::decode(&[0x5b]), Err(AbiError::BadLength));
    let mut long = calls[7].clone();
    long.push(0);
    assert_eq!(VoidCallV1::decode(&long), Err(AbiError::BadLength));
    let mut dirty = calls[5].clone();
    dirty[4] = 1;
    assert_eq!(VoidCallV1::decode(&dirty), Err(AbiError::DirtyWord));
    let mut invalid = control;
    invalid.parliament_paused = 2;
    let control = control_proof_token(&invalid).encode();
    assert_eq!(
        read_u64(&control, 2 * WORD),
        Ok(2),
        "do not normalize invalid raw bool to true"
    );
}
fn with_gap(calldata: &[u8], at: usize) -> Vec<u8> {
    let mut out = calldata[..4 + at].to_vec();
    out.extend_from_slice(&[0; WORD]);
    out.extend_from_slice(&calldata[4 + at..]);
    out
}

fn bump(calldata: &mut [u8], at: usize, delta: u64) {
    let low = 4 + at + 24..4 + at + WORD;
    let value = u64::from_be_bytes(calldata[low.clone()].try_into().expect("8 bytes")) + delta;
    calldata[low].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn abi_shapes_measure_the_canonical_encoding() {
    assert!(SHAPE_CERTIFICATE.is_dynamic());
    assert_eq!(SHAPE_CERTIFICATE.head_len(), WORD);
    assert!(SHAPE_CHECKPOINT.is_dynamic());
    assert!(SHAPE_BLOCK_REF.is_dynamic());
    assert!(AbiShape::Bytes.is_dynamic() && AbiShape::Words.is_dynamic());
    assert!(!SHAPE_U64.is_dynamic());
    let direct = finalize_from_taira_calldata(&certificate(), &proof());
    let direct_args = [SHAPE_CERTIFICATE, SHAPE_MESSAGE_PROOF];
    assert_eq!(check_canonical_args(&direct[4..], &direct_args), Ok(()));
    assert_eq!(
        canonical_sequence_size(&direct_args, &direct[4..], 0),
        Ok(direct.len() - 4)
    );
    let stored = finalize_from_checkpoint_calldata(&checkpoint(), &proof());
    let stored_args = [SHAPE_CHECKPOINT, SHAPE_MESSAGE_PROOF];
    assert_eq!(check_canonical_args(&stored[4..], &stored_args), Ok(()));
    assert_eq!(
        check_canonical_args(&stored[4..], &direct_args),
        Err(AbiError::BadOffset)
    );
    let bytes = encode_tokens(&[AbiToken::Bytes(vec![9; 33])]);
    assert_eq!(AbiShape::Bytes.canonical_size(&bytes, WORD), Ok(3 * WORD));
    assert_eq!(
        AbiShape::Bytes.canonical_size(&bytes[..3 * WORD - 1], WORD),
        Err(AbiError::BadLength)
    );
    let words = encode_tokens(&[path_token(&[[5; 32]; 3])]);
    assert_eq!(AbiShape::Words.canonical_size(&words, WORD), Ok(4 * WORD));
    assert_eq!(
        AbiShape::Words.canonical_size(&words[..4 * WORD - 1], WORD),
        Err(AbiError::BadLength)
    );
    assert_eq!(
        SHAPE_U32.canonical_size(&word_u64(1 << 32), 0),
        Err(AbiError::DirtyWord)
    );
    assert_eq!(SHAPE_B32.canonical_size(&[0xff; 32], 0), Ok(WORD));
}
fn rejects_malformed_void(canonical: &[u8]) {
    let args = &canonical[4..];
    let source_at = read_usize(args, WORD).unwrap();
    let proof_at = read_usize(args, 2 * WORD).unwrap();
    let path_at = proof_at + read_usize(args, proof_at + 2 * WORD).unwrap();
    let block_at = proof_at + read_usize(args, proof_at + 3 * WORD).unwrap();
    let history_at = block_at + read_usize(args, block_at + 4 * WORD).unwrap();
    let edit = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut data = canonical.to_vec();
        change(&mut data);
        VoidCallV1::decode(&data)
    };
    for extra in [1, WORD] {
        assert_eq!(
            edit(&|d| d.resize(d.len() + extra, 0)),
            Err(AbiError::BadLength)
        );
    }
    assert_eq!(
        edit(&|d| {
            d.pop();
        }),
        Err(AbiError::BadLength)
    );
    for offset in [
        23,
        proof_at + WORD + 27,
        block_at + 23,
        block_at + 2 * WORD + 27,
        block_at + 3 * WORD + 23,
    ] {
        assert_eq!(
            edit(&|d| d[4 + offset] = 1),
            Err(AbiError::DirtyWord),
            "{offset}"
        );
    }
    assert_eq!(edit(&|d| d[4 + WORD] = 1), Err(AbiError::BadOffset));
    assert_eq!(
        edit(&|d| {
            *d = with_gap(d, source_at);
            bump(d, WORD, 32);
            bump(d, 2 * WORD, 32);
        }),
        Err(AbiError::BadOffset)
    );
    // A gap inside the source tuple with the enclosing proof offset repaired remains noncanonical.
    let source_bytes_at = source_at + read_usize(args, source_at).unwrap();
    assert_eq!(
        edit(&|d| {
            *d = with_gap(d, source_bytes_at);
            bump(d, source_at, 32);
            bump(d, 2 * WORD, 32);
        }),
        Err(AbiError::BadOffset)
    );
    assert_eq!(
        edit(&|d| {
            *d = with_gap(d, path_at);
            bump(d, proof_at + 2 * WORD, 32);
            bump(d, proof_at + 3 * WORD, 32);
        }),
        Err(AbiError::BadOffset)
    );
    assert_eq!(
        edit(&|d| {
            *d = with_gap(d, history_at);
            bump(d, block_at + 4 * WORD, 32);
        }),
        Err(AbiError::BadOffset)
    );
    let payload_at = proof_at + read_usize(args, proof_at).unwrap();
    assert_eq!(
        edit(&|d| d[4 + payload_at + WORD + 159] = 1),
        Err(AbiError::DirtyPadding)
    );
    assert_eq!(edit(&|d| bump(d, path_at, 1)), Err(AbiError::BadOffset));
    assert_eq!(edit(&|d| bump(d, history_at, 1)), Err(AbiError::BadLength));
}
#[test]
fn void_expired_decodes_only_the_canonical_encoding() {
    let data = void_expired_calldata(9, &certificate(), &proof());
    assert_eq!(
        VoidCallV1::decode(&data),
        Ok(VoidCallV1::Expired {
            nonce: 9,
            from_checkpoint: false
        })
    );
    rejects_malformed_void(&data);
}
#[test]
fn void_expired_from_checkpoint_decodes_only_the_canonical_encoding() {
    let data = void_expired_from_checkpoint_calldata(u64::MAX, &checkpoint(), &proof());
    assert_eq!(
        VoidCallV1::decode(&data),
        Ok(VoidCallV1::Expired {
            nonce: u64::MAX,
            from_checkpoint: true
        })
    );
    rejects_malformed_void(&data);
    for (mut swapped, selector) in [
        (
            void_expired_calldata(1, &certificate(), &proof()),
            SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
        ),
        (
            void_expired_from_checkpoint_calldata(1, &checkpoint(), &proof()),
            SELECTOR_VOID_EXPIRED,
        ),
    ] {
        swapped[..4].copy_from_slice(&selector);
        assert_eq!(VoidCallV1::decode(&swapped), Err(AbiError::BadOffset));
    }
}
#[test]
fn void_expired_accepts_every_integer_at_its_full_width() {
    let mut proof = proof();
    proof.leaf_index = u32::MAX;
    proof.block.height = u64::MAX;
    proof.block.message_count = u32::MAX;
    proof.block.history_index = u64::MAX;
    for (data, from_checkpoint) in [
        (
            void_expired_calldata(u64::MAX, &certificate(), &proof),
            false,
        ),
        (
            void_expired_from_checkpoint_calldata(u64::MAX, &checkpoint(), &proof),
            true,
        ),
    ] {
        assert_eq!(
            VoidCallV1::decode(&data),
            Ok(VoidCallV1::Expired {
                nonce: u64::MAX,
                from_checkpoint
            })
        );
    }
}
#[test]
fn submit_checkpoints_layout() {
    let cert = certificate();
    let len = certificate_token(&cert).encode().len();
    let data = submit_checkpoints_calldata(&[cert.clone(), cert]);
    let args = &data[4..];
    assert_eq!(word_hex(args, 0), format!("{WORD:064x}"));
    assert_eq!(word_hex(args, 1), format!("{:064x}", 2));
    assert_eq!(word_hex(args, 2), format!("{:064x}", 2 * WORD));
    assert_eq!(word_hex(args, 3), format!("{:064x}", 2 * WORD + len));
    assert_eq!(args.len(), 4 * WORD + 2 * len);
}
#[test]
fn void_frozen_decodes_only_admitted_ranges() {
    for (first_nonce, count) in [(0, 1), (0, 256), (u64::MAX, 1), (u64::MAX - 255, 256)] {
        assert_eq!(
            VoidCallV1::decode(&void_frozen_calldata(first_nonce, count)),
            Ok(VoidCallV1::Frozen { first_nonce, count })
        );
    }
    for (first_nonce, count) in [(0, 0), (0, 257), (u64::MAX, 2), (u64::MAX - 254, 256)] {
        assert_eq!(
            VoidCallV1::decode(&void_frozen_calldata(first_nonce, count)),
            Err(AbiError::BadVoidRange),
            "{first_nonce} + {count}"
        );
    }
    let canonical = void_frozen_calldata(4, 3);
    let mut dirty_count = canonical.clone();
    dirty_count[4 + WORD + 23] = 1;
    assert_eq!(VoidCallV1::decode(&dirty_count), Err(AbiError::DirtyWord));
    assert_eq!(
        VoidCallV1::decode(&canonical[..canonical.len() - 1]),
        Err(AbiError::BadLength)
    );
    let mut trailing_word = canonical;
    trailing_word.extend_from_slice(&[0; WORD]);
    assert_eq!(VoidCallV1::decode(&trailing_word), Err(AbiError::BadLength));
}

#[test]
fn transfer_to_taira_canonical_roundtrip_and_negatives() {
    let call = TransferToTairaCallV1 {
        taira_recipient: vec![0xaa; 35],
        token_amount: 1_000_000_000,
        expected_nonce: 7,
    };
    let data = call.calldata();
    assert_eq!(data.len(), TRANSFER_TO_TAIRA_HEAD_BYTES + 64);
    assert_eq!(word_hex(&data[4..], 0), format!("{:064x}", 0x60));
    assert_eq!(TransferToTairaCallV1::decode(&data), Ok(call.clone()));
    let max = TransferToTairaCallV1 {
        taira_recipient: vec![1; 1024],
        token_amount: u128::MAX,
        expected_nonce: u64::MAX,
    };
    assert_eq!(TransferToTairaCallV1::decode(&max.calldata()), Ok(max));

    let mut wrong_selector = data.clone();
    wrong_selector[0] ^= 1;
    assert_eq!(
        TransferToTairaCallV1::decode(&wrong_selector),
        Err(AbiError::WrongSelector)
    );
    let mut bad_offset = data.clone();
    bad_offset[4 + 31] = 0x80;
    assert_eq!(
        TransferToTairaCallV1::decode(&bad_offset),
        Err(AbiError::BadOffset)
    );
    let mut dirty_padding = data.clone();
    let last = dirty_padding.len() - 1;
    dirty_padding[last] = 1;
    assert_eq!(
        TransferToTairaCallV1::decode(&dirty_padding),
        Err(AbiError::DirtyPadding)
    );
    let mut trailing = data.clone();
    trailing.extend_from_slice(&[0; 32]);
    assert_eq!(
        TransferToTairaCallV1::decode(&trailing),
        Err(AbiError::BadLength)
    );
    assert_eq!(
        TransferToTairaCallV1::decode(&data[..data.len() - 1]),
        Err(AbiError::BadLength)
    );
    let empty = TransferToTairaCallV1 {
        taira_recipient: vec![],
        ..call.clone()
    };
    assert_eq!(
        TransferToTairaCallV1::decode(&empty.calldata()),
        Err(AbiError::BadRecipientLength)
    );
    let long = TransferToTairaCallV1 {
        taira_recipient: vec![1; 1025],
        ..call.clone()
    };
    assert_eq!(
        TransferToTairaCallV1::decode(&long.calldata()),
        Err(AbiError::BadRecipientLength)
    );
    let zero = TransferToTairaCallV1 {
        token_amount: 0,
        ..call.clone()
    };
    assert_eq!(
        TransferToTairaCallV1::decode(&zero.calldata()),
        Err(AbiError::BadAmount)
    );
    let mut huge = data.clone();
    huge[4 + WORD + 15] = 1;
    assert_eq!(
        TransferToTairaCallV1::decode(&huge),
        Err(AbiError::DirtyWord)
    );
    let mut dirty_nonce = data;
    dirty_nonce[4 + 2 * WORD + 23] = 1;
    assert_eq!(
        TransferToTairaCallV1::decode(&dirty_nonce),
        Err(AbiError::DirtyWord)
    );
}

#[test]
fn transfer_to_taira_rebuilds_the_inbound_payload() {
    let call = TransferToTairaCallV1 {
        taira_recipient: vec![0xaa; 35],
        token_amount: 1_000_000_000,
        expected_nonce: 7,
    };
    let caller = [0x33; 20];
    let bsc = call
        .inbound_payload(SccpNetworkV1::BscMainnet, 2, &caller)
        .unwrap();
    assert_eq!(bsc.sender.bytes, caller);
    assert_eq!(bsc.nonce, 7);
    assert_eq!(bsc.route_revision, 2);
    assert_eq!(bsc.amount, 1_000_000_000);
    assert_eq!(bsc.route_id, "taira_bsc_xor");
    let eth = call
        .inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &caller)
        .unwrap();
    assert_eq!(eth.sender.bytes, caller);
    assert_eq!(
        call.inbound_payload(SccpNetworkV1::TonMainnet, 1, &caller),
        Err(AbiError::PayloadMismatch)
    );
    assert_eq!(
        call.inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &[0; 20]),
        Err(AbiError::PayloadMismatch)
    );
}

#[test]
fn view_calls_and_returns() {
    assert_eq!(ViewCallV1::ControlNonce.calldata(), SELECTOR_CONTROL_NONCE);
    let consumed = ViewCallV1::IsConsumed(300).calldata();
    assert_eq!(consumed.len(), 36);
    assert_eq!(consumed[..4], SELECTOR_IS_CONSUMED);
    assert_eq!(word_hex(&consumed[4..], 0), format!("{:064x}", 300));
    let nonces = ViewCallV1::TransferNonces([0x44; 20]).calldata();
    assert_eq!(nonces[4..16], [0; 12]);
    assert_eq!(nonces[16..], [0x44; 20]);

    let state = CommitteeViewV1 {
        root: [1; 32],
        until_ms: 99,
        start: 7,
        high: 10,
        generation: 8,
    };
    let encoded = encode_committee_state_return(&state);
    assert_eq!(
        ViewCallV1::CommitteeState.decode_return(&encoded),
        Ok(ViewReturnV1::CommitteeState(state))
    );
    let mut dirty = encoded.clone();
    dirty[WORD] = 1;
    assert_eq!(
        decode_committee_state_return(&dirty),
        Err(AbiError::DirtyWord)
    );
    assert_eq!(
        decode_committee_state_return(&encoded[..4 * WORD]),
        Err(AbiError::BadLength)
    );
    for latch in [false, true] {
        let joined = state.with_equivocated(latch);
        assert_eq!(joined.equivocated, latch);
        assert_eq!(joined.root, state.root);
        assert_eq!(joined.until_ms, state.until_ms);
        assert_eq!(joined.start, state.start);
        assert_eq!(joined.high, state.high);
        assert_eq!(joined.generation, state.generation);
    }
    let pause = PauseViewV1 {
        parliament_paused: false,
        fast_pause_until_ms: 90,
        control_nonce: 2,
        effective: true,
    };
    let encoded = encode_pause_state_return(&pause);
    assert_eq!(
        ViewCallV1::PauseState.decode_return(&encoded),
        Ok(ViewReturnV1::PauseState(pause))
    );
    for offset in [0, 3 * WORD] {
        let mut dirty = encoded.clone();
        dirty[offset + 31] = 2;
        assert_eq!(decode_pause_state_return(&dirty), Err(AbiError::BadBool));
    }
    for offset in [WORD, 2 * WORD] {
        let mut dirty = encoded.clone();
        dirty[offset] = 1;
        assert_eq!(decode_pause_state_return(&dirty), Err(AbiError::DirtyWord));
    }
    assert_eq!(
        decode_pause_state_return(&encoded[..3 * WORD]),
        Err(AbiError::BadLength)
    );
    let pin = SccpCommitteePinV1 {
        generation: 8,
        committee_root: [1; 32],
        start_height: 7,
        until_ms: 99,
    };
    let encoded = encode_initial_committee_return(&pin);
    assert_eq!(
        ViewCallV1::InitialCommittee.decode_return(&encoded),
        Ok(ViewReturnV1::InitialCommittee(pin))
    );
    for offset in [0, 2 * WORD, 3 * WORD] {
        let mut dirty = encoded.clone();
        dirty[offset] = 1;
        assert_eq!(
            decode_initial_committee_return(&dirty),
            Err(AbiError::DirtyWord)
        );
    }
    assert_eq!(
        decode_initial_committee_return(&encoded[..3 * WORD]),
        Err(AbiError::BadLength)
    );
    let checkpoint = ViewCallV1::CheckpointHeader(9).calldata();
    assert_eq!(&checkpoint[4..], word_u64(9));
    assert_eq!(
        ViewCallV1::CheckpointHeader(9).decode_return(&TAIRA),
        Ok(ViewReturnV1::Bytes32(TAIRA))
    );
    assert_eq!(
        ViewCallV1::Equivocated.decode_return(&word_u64(1)),
        Ok(ViewReturnV1::Bool(true))
    );
    assert_eq!(
        ViewCallV1::Equivocated.decode_return(&word_u64(2)),
        Err(AbiError::BadBool)
    );
    let one = word_u64(1);
    assert_eq!(
        ViewCallV1::MintingPaused.decode_return(&one),
        Ok(ViewReturnV1::Bool(true))
    );
    assert_eq!(
        ViewCallV1::IsConsumed(0).decode_return(&[0; 32]),
        Ok(ViewReturnV1::Bool(false))
    );
    assert_eq!(decode_bool_return(&word_u64(2)), Err(AbiError::BadBool));
    assert_eq!(
        ViewCallV1::RouteRevision.decode_return(&one),
        Ok(ViewReturnV1::U32(1))
    );
    assert_eq!(
        decode_u32_return(&word_u64(1 << 32)),
        Err(AbiError::DirtyWord)
    );
    for call in [
        ViewCallV1::MaxValidityMs,
        ViewCallV1::TransferNonces([0x44; 20]),
        ViewCallV1::ControlNonce,
        ViewCallV1::OpCount,
    ] {
        assert_eq!(call.decode_return(&one), Ok(ViewReturnV1::U64(1)));
        assert_eq!(
            call.decode_return(&word_u64(u64::MAX)),
            Ok(ViewReturnV1::U64(u64::MAX))
        );
        assert_eq!(call.decode_return(&[0; 33]), Err(AbiError::BadLength));
        let mut overflow = word_u64(u64::MAX);
        overflow[23] = 1;
        assert_eq!(call.decode_return(&overflow), Err(AbiError::DirtyWord));
    }
    assert_eq!(
        ViewCallV1::MaxWrappedSupply.decode_return(&word_u128(u128::MAX)),
        Ok(ViewReturnV1::U128(u128::MAX))
    );
    let mut wide = [0_u8; 32];
    wide[15] = 1;
    assert_eq!(decode_u128_return(&wide), Err(AbiError::DirtyWord));
    for call in [ViewCallV1::TairaNetworkId, ViewCallV1::ConsensusInstance] {
        assert_eq!(call.decode_return(&TAIRA), Ok(ViewReturnV1::Bytes32(TAIRA)));
        assert_eq!(call.decode_return(&TAIRA[..31]), Err(AbiError::BadLength));
    }
    assert_eq!(
        decode_bytes32_return(&TAIRA[..31]),
        Err(AbiError::BadLength)
    );
    assert_eq!(decode_u64_return(&[0; 33]), Err(AbiError::BadLength));
    for call in [
        ViewCallV1::CommitteeState,
        ViewCallV1::TairaNetworkId,
        ViewCallV1::RouteRevision,
        ViewCallV1::MaxWrappedSupply,
        ViewCallV1::MintingPaused,
        ViewCallV1::ControlNonce,
        ViewCallV1::ConsensusInstance,
        ViewCallV1::InitialCommittee,
        ViewCallV1::PauseState,
        ViewCallV1::OpCount,
        ViewCallV1::MaxValidityMs,
    ] {
        assert_eq!(call.calldata(), call.selector());
    }
}

fn inbound_log() -> (TransferToTairaLogV1, SccpTransferPayloadV1) {
    let sender = [0x33; 20];
    let payload = SccpTransferPayloadV1::inbound(
        SccpNetworkV1::BscMainnet,
        4,
        1,
        77,
        sender.to_vec(),
        vec![9; 40],
    )
    .unwrap();
    let log = TransferToTairaLogV1 {
        message_id: payload.message_id(&TAIRA).unwrap(),
        sender,
        nonce: 4,
        payload: payload.encode().unwrap(),
    };
    (log, payload)
}

#[test]
fn transfer_to_taira_log_roundtrip_and_binding() {
    let (log, payload) = inbound_log();
    let (topics, data) = log.encode();
    assert_eq!(
        topics[0],
        keccak256(&[b"SccpTransferToTaira(bytes32,address,uint64,bytes)"])
    );
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &data),
        Ok(log.clone())
    );
    assert_eq!(
        log.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 1),
        Ok(payload)
    );
    assert_eq!(
        log.verified_payload(&TAIRA, SccpNetworkV1::EthereumMainnet, 1),
        Err(AbiError::PayloadMismatch)
    );
    assert_eq!(
        log.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 2),
        Err(AbiError::PayloadMismatch)
    );
    assert_eq!(
        log.verified_payload(&[0x12; 32], SccpNetworkV1::BscMainnet, 1),
        Err(AbiError::PayloadMismatch)
    );
    let wrong_nonce = TransferToTairaLogV1 {
        nonce: 5,
        ..log.clone()
    };
    assert_eq!(
        wrong_nonce.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 1),
        Err(AbiError::PayloadMismatch)
    );

    assert_eq!(
        TransferToTairaLogV1::decode(&topics[..2], &data),
        Err(AbiError::WrongTopicCount)
    );
    let mut wrong_topic = topics.clone();
    wrong_topic[0] = TOPIC_CONTROL_APPLIED;
    assert_eq!(
        TransferToTairaLogV1::decode(&wrong_topic, &data),
        Err(AbiError::WrongTopic)
    );
    let mut dirty_sender = topics.clone();
    dirty_sender[2][0] = 0x41;
    assert_eq!(
        TransferToTairaLogV1::decode(&dirty_sender, &data),
        Err(AbiError::DirtyWord)
    );
    let mut bad_offset = data.clone();
    bad_offset[2 * WORD - 1] = 0x60;
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &bad_offset),
        Err(AbiError::BadOffset)
    );
    let mut trailing = data.clone();
    trailing.extend_from_slice(&[0; 32]);
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &trailing),
        Err(AbiError::BadLength)
    );
    let mut padded = data.clone();
    let last = padded.len() - 1;
    padded[last] = 1;
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &padded),
        Err(AbiError::DirtyPadding)
    );
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &data[..64]),
        Err(AbiError::BadLength)
    );
    let mut huge_length = data.clone();
    huge_length[2 * WORD..3 * WORD].copy_from_slice(&word_u64(u64::MAX));
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &huge_length),
        Err(AbiError::BadLength)
    );
}

#[test]
fn voided_log_roundtrip() {
    let log = VoidedLogV1 {
        message_id: [7; 32],
        nonce: 12,
    };
    let (topics, data) = log.encode();
    assert_eq!(topics[0], keccak256(&[b"SccpVoided(bytes32,uint64)"]));
    assert!(data.is_empty());
    assert_eq!(VoidedLogV1::decode(&topics, &data), Ok(log));
    assert!(!log.is_frozen());
    let frozen = VoidedLogV1 {
        message_id: [0; 32],
        nonce: 3,
    };
    assert!(frozen.is_frozen());
    assert_eq!(VoidedLogV1::decode(&topics, &[0]), Err(AbiError::BadLength));
    assert_eq!(
        VoidedLogV1::decode(&topics[..1], &data),
        Err(AbiError::WrongTopicCount)
    );
    let mut wrong = topics.clone();
    wrong[0] = TOPIC_TRANSFER_TO_TAIRA;
    assert_eq!(
        VoidedLogV1::decode(&wrong, &data),
        Err(AbiError::WrongTopic)
    );
    let mut dirty = topics;
    dirty[2][0] = 1;
    assert_eq!(VoidedLogV1::decode(&dirty, &data), Err(AbiError::DirtyWord));
}

#[test]
fn evm_helpers() {
    for network in [SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet] {
        assert_eq!(evm_account(network, &[1; 20]), Ok(vec![1; 20]));
    }
    for network in [SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet] {
        assert_eq!(
            evm_account(network, &[1; 20]),
            Err(AbiError::PayloadMismatch)
        );
    }
    assert_eq!(selector_of(&[1, 2, 3]), Err(AbiError::BadLength));
    assert_eq!(read_bool(&word_u64(1), 0), Ok(true));
    assert_eq!(read_address(&word_address(&[5; 20]), 0), Ok([5; 20]));
    assert_eq!(checked_word(&[0; 31], 0), Err(AbiError::BadLength));
}
