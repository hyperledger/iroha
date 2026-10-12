//! Current native-certificate EVM fixture; unchanged burn/frozen conformance stays in the parent.

use super::*;
use iroha_crypto::{
    Algorithm, KeyPair, PrivateKey,
    bls::consensus::{aggregate, sign_preimage},
};
use iroha_data_model::sccp::deployment::SccpCommitteePinV1;
use iroha_sccp::v1::{
    committee::{CommitteeStateV1, committee_root},
    control::{ControlLeafV1, control_leaf},
    destination::{
        BlockRefV1, CertificateAuthorityV1, CheckpointRefV1, ControlProofV1, DestinationFlavor,
        MessageProofV1, TairaCertificateV1,
    },
    destination_abi::{EVENT_TOPICS, SELECTORS, TOPIC_CERTIFICATE},
    evm_abi::{
        self, AbiToken, CommitteeViewV1, PauseViewV1, TransferToTairaLogV1, ViewCallV1,
        ViewReturnV1, VoidedLogV1, encode_tokens,
    },
    finality::{
        FLAG_ACTIVE, FLAG_ROTATION, QcFixedV1, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
        commit_preimage, outer_result,
    },
    hashes::word_u64,
    proof::{verify_control, verify_transfer},
};

const INSTANCE: [u8; 32] = [0x77; 32];

struct Committee {
    keys: Vec<[u8; 48]>,
    secrets: Vec<PrivateKey>,
}
impl Committee {
    fn new(generation: u8) -> Self {
        let mut pairs: Vec<_> = (0..4)
            .map(|seat| {
                let key = KeyPair::from_seed(
                    vec![b'S', b'C', b'C', b'P', generation, seat],
                    Algorithm::BlsNormal,
                );
                let bytes: [u8; 48] = key.public_key().to_bytes().1.try_into().unwrap();
                (bytes, key.private_key().clone())
            })
            .collect();
        pairs.sort_by_key(|(key, _)| *key);
        let (keys, secrets) = pairs.into_iter().unzip();
        Self { keys, secrets }
    }
    fn root(&self) -> [u8; 32] {
        committee_root(&self.keys).unwrap()
    }
    fn certificate(&self, header: &SccpFinalityHeaderV1) -> (TairaCertificateV1, [u8; 96]) {
        let qc = QcFixedV1 {
            epoch: if header.height() < 200 { 1 } else { 2 },
            epoch_context: [0x88; 32],
            view: 0,
            block_hash: keccak256(&[b"SCCP/FIXTURE/BLOCK/V1", &header.height().to_be_bytes()]),
            result_body: [0x66; 32],
            signers: 7,
        };
        let preimage = commit_preimage(
            &INSTANCE,
            &qc,
            header.height(),
            &outer_result(header, &qc.result_body).0,
        );
        let signature = aggregate(
            self.secrets[..3]
                .iter()
                .map(|key| sign_preimage(key, &preimage).unwrap()),
        )
        .unwrap();
        (
            TairaCertificateV1::new(&qc, header, &signature, &self.keys).unwrap(),
            signature,
        )
    }
}

fn certificate_json(
    header: &SccpFinalityHeaderV1,
    wire: &TairaCertificateV1,
    signature: &[u8; 96],
    keys: &[[u8; 48]],
) -> Value {
    obj([
        ("height", num(header.height())),
        ("qc", hex(&wire.qc)),
        ("aggregate_signature", hex(signature)),
        ("header", hex(header.as_bytes())),
        ("committee", hexes(keys)),
        ("signature_evm", hex(&wire.signature)),
        ("signer_ys", hex(&wire.signer_ys)),
    ])
}

fn call_json(label: &str, function: &str, calldata: &[u8]) -> Value {
    obj([
        ("label", text(label)),
        ("function", text(function)),
        ("calldata", hex(calldata)),
    ])
}

#[allow(
    clippy::too_many_lines,
    reason = "one coherent signed scenario pins every current entry point and view"
)]
pub(super) fn fixture() -> Value {
    let g7 = Committee::new(7);
    let g8 = Committee::new(8);
    let destination = eth_destination();
    let control_fields = ControlLeafV1 {
        route_revision: 1,
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        fast_pause_until_ms: 0,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
    };
    let control_hash = control_leaf(
        &TAIRA,
        destination.network,
        &destination.destination_word,
        &control_fields,
    )
    .unwrap();
    let payloads: Vec<_> = (0..4).map(eth_outbound).collect();
    let block50 = PromoteOddTree::block(&[eth_transfer_leaf(0)]).unwrap();
    let block100 =
        PromoteOddTree::block(&[eth_transfer_leaf(1), eth_transfer_leaf(2), control_hash]).unwrap();
    let block200 = PromoteOddTree::block(&[eth_transfer_leaf(3)]).unwrap();
    let history = [
        history_leaf(50, &block50.root(), 1),
        history_leaf(100, &block100.root(), 3),
        history_leaf(200, &block200.root(), 1),
    ];
    let fields = |height, generation, root| SccpFinalityHeaderFieldsV1 {
        network_id: TAIRA,
        height,
        timestamp_ms: T0 + height * 1_000,
        flags: FLAG_ACTIVE,
        generation,
        committee_root: root,
        ..Default::default()
    };
    let x100 = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        message_count: 3,
        sccp_root: block100.root(),
        history_size: 2,
        history_root: history_root(&history[..2]).unwrap(),
        ..fields(100, 7, g7.root())
    })
    .unwrap();
    let x150 = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        history_size: 2,
        history_root: history_root(&history[..2]).unwrap(),
        validity_ms: 14 * DAY,
        next_committee_root: g8.root(),
        ..fields(150, 7, g7.root())
    })
    .unwrap();
    let x200 = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        message_count: 1,
        sccp_root: block200.root(),
        history_size: 3,
        history_root: history_root(&history).unwrap(),
        ..fields(200, 8, g8.root())
    })
    .unwrap();
    let (c100, sigma100) = g7.certificate(&x100);
    let (c150, sigma150) = g7.certificate(&x150);
    let (c200, sigma200) = g8.certificate(&x200);
    let pin = SccpCommitteePinV1 {
        generation: 7,
        committee_root: g7.root(),
        start_height: 1,
        until_ms: T0 + 14 * DAY,
    };
    let initial = CommitteeStateV1::from_pin(
        pin.generation,
        pin.committee_root,
        pin.start_height,
        pin.until_ms,
    )
    .unwrap();
    let authority =
        CertificateAuthorityV1::new(DestinationFlavor::Evm, &TAIRA, &INSTANCE, &initial, None)
            .unwrap();
    assert_eq!(authority.verify(&c100, |_| None).unwrap().header, x100);
    assert_eq!(authority.verify(&c150, |_| None).unwrap().header, x150);
    let mut rotated = initial;
    rotated.apply_checkpoint(&x150, None, T0 + 200_000).unwrap();
    assert_eq!(rotated.generation, 8);
    assert_eq!(rotated.root, g8.root());
    assert!(!rotated.is_current(&x100));
    assert!(rotated.accepts_checkpoint(&x150));
    assert!(!rotated.accepts_checkpoint(&x100));
    let authority =
        CertificateAuthorityV1::new(DestinationFlavor::Evm, &TAIRA, &INSTANCE, &rotated, None)
            .unwrap();
    assert_eq!(authority.verify(&c200, |_| None).unwrap().header, x200);
    let direct = BlockRefV1 {
        height: 100,
        sccp_root: block100.root(),
        message_count: 3,
        history_index: 0,
        history_path: vec![],
    };
    let historical = BlockRefV1 {
        history_index: 1,
        history_path: history_path(&history, 1).unwrap(),
        ..direct.clone()
    };
    let proof1 = MessageProofV1 {
        payload: payloads[1].encode().unwrap(),
        leaf_index: 0,
        path: block100.path(0).unwrap(),
        block: direct.clone(),
    };
    let proof2 = MessageProofV1 {
        payload: payloads[2].encode().unwrap(),
        leaf_index: 1,
        path: block100.path(1).unwrap(),
        block: historical.clone(),
    };
    let control = ControlProofV1 {
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        fast_pause_until_ms: 0,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
        leaf_index: 2,
        path: block100.path(2).unwrap(),
        block: direct,
    };
    let historical_control = ControlProofV1 {
        block: historical,
        ..control.clone()
    };
    verify_transfer(&x100, &proof1, &TAIRA, &destination).unwrap();
    verify_transfer(&x200, &proof2, &TAIRA, &destination).unwrap();
    verify_control(&x100, &control, &TAIRA, &destination).unwrap();
    verify_control(&x200, &historical_control, &TAIRA, &destination).unwrap();
    let ref100 = CheckpointRefV1 {
        header: x100.as_bytes().to_vec(),
    };
    let ref200 = CheckpointRefV1 {
        header: x200.as_bytes().to_vec(),
    };
    let transfer_call = TransferToTairaCallV1 {
        taira_recipient: taira_account(9),
        token_amount: 1_500_000_000,
        expected_nonce: 0,
    };
    assert_eq!(
        TransferToTairaCallV1::decode(&transfer_call.calldata()),
        Ok(transfer_call.clone())
    );
    let void_inline = evm_abi::void_expired_calldata(1, &c100, &proof1);
    let void_checkpoint = evm_abi::void_expired_from_checkpoint_calldata(2, &ref200, &proof2);
    assert_eq!(
        VoidCallV1::decode(&void_inline),
        Ok(VoidCallV1::Expired {
            nonce: 1,
            from_checkpoint: false
        })
    );
    assert_eq!(
        VoidCallV1::decode(&void_checkpoint),
        Ok(VoidCallV1::Expired {
            nonce: 2,
            from_checkpoint: true
        })
    );
    let calls = vec![
        call_json(
            "finalize_direct",
            "finalizeFromTaira",
            &evm_abi::finalize_from_taira_calldata(&c100, &proof1),
        ),
        call_json(
            "finalize_historical",
            "finalizeFromTaira",
            &evm_abi::finalize_from_taira_calldata(&c200, &proof2),
        ),
        call_json(
            "finalize_checkpoint_direct",
            "finalizeFromCheckpoint",
            &evm_abi::finalize_from_checkpoint_calldata(&ref100, &proof1),
        ),
        call_json(
            "finalize_checkpoint_historical",
            "finalizeFromCheckpoint",
            &evm_abi::finalize_from_checkpoint_calldata(&ref200, &proof2),
        ),
        call_json(
            "checkpoint_rotation",
            "submitCheckpoints",
            &evm_abi::submit_checkpoints_calldata(std::slice::from_ref(&c150)),
        ),
        call_json(
            "checkpoint_rotation_and_latest",
            "submitCheckpoints",
            &evm_abi::submit_checkpoints_calldata(&[c150.clone(), c200.clone()]),
        ),
        call_json(
            "apply_control_direct",
            "applyControl",
            &evm_abi::apply_control_calldata(&c100, &control),
        ),
        call_json(
            "apply_control_historical",
            "applyControl",
            &evm_abi::apply_control_calldata(&c200, &historical_control),
        ),
        call_json(
            "apply_control_checkpoint",
            "applyControlFromCheckpoint",
            &evm_abi::apply_control_from_checkpoint_calldata(&ref200, &historical_control),
        ),
        call_json("void_expired", "voidExpired", &void_inline),
        call_json(
            "void_expired_checkpoint",
            "voidExpiredFromCheckpoint",
            &void_checkpoint,
        ),
        call_json("void_frozen", "voidFrozen", &void_frozen_calldata(4, 3)),
        call_json(
            "transfer_to_taira",
            "transferToTaira",
            &transfer_call.calldata(),
        ),
    ];
    let views: Vec<_> = [
        ("committeeState", ViewCallV1::CommitteeState),
        ("checkpointHeader", ViewCallV1::CheckpointHeader(150)),
        ("pauseState", ViewCallV1::PauseState),
        ("consensusInstance", ViewCallV1::ConsensusInstance),
        ("initialCommittee", ViewCallV1::InitialCommittee),
        ("equivocated", ViewCallV1::Equivocated),
        ("maxValidityMs", ViewCallV1::MaxValidityMs),
        ("isConsumed", ViewCallV1::IsConsumed(300)),
        ("transferNonces", ViewCallV1::TransferNonces([0x55; 20])),
        ("tairaNetworkId", ViewCallV1::TairaNetworkId),
        ("routeRevision", ViewCallV1::RouteRevision),
        ("maxWrappedSupply", ViewCallV1::MaxWrappedSupply),
        ("mintingPaused", ViewCallV1::MintingPaused),
        ("controlNonce", ViewCallV1::ControlNonce),
        ("opCount", ViewCallV1::OpCount),
    ]
    .into_iter()
    .map(|(name, call)| call_json(name, name, &call.calldata()))
    .collect();
    let committee_view = CommitteeViewV1 {
        root: rotated.root,
        generation: rotated.generation,
        start: rotated.start,
        high: rotated.high,
        until_ms: rotated.until_ms,
    };
    let committee_return = evm_abi::encode_committee_state_return(&committee_view);
    assert_eq!(
        ViewCallV1::CommitteeState.decode_return(&committee_return),
        Ok(ViewReturnV1::CommitteeState(committee_view))
    );
    let pause = PauseViewV1 {
        parliament_paused: true,
        fast_pause_until_ms: 0,
        control_nonce: 1,
        effective: true,
    };
    let pause_return = evm_abi::encode_pause_state_return(&pause);
    assert_eq!(
        ViewCallV1::PauseState.decode_return(&pause_return),
        Ok(ViewReturnV1::PauseState(pause))
    );
    let pin_return = evm_abi::encode_initial_committee_return(&pin);
    assert_eq!(
        ViewCallV1::InitialCommittee.decode_return(&pin_return),
        Ok(ViewReturnV1::InitialCommittee(pin))
    );
    let log_json = |label: &str, topics: Vec<[u8; 32]>, data: Vec<u8>| {
        obj([
            ("label", text(label)),
            ("topics", hexes(&topics)),
            ("data", hex(&data)),
        ])
    };
    let caller = [0x55; 20];
    let inbound = transfer_call
        .inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &caller)
        .unwrap();
    let transfer_log = TransferToTairaLogV1 {
        message_id: inbound.message_id(&TAIRA).unwrap(),
        sender: caller,
        nonce: 0,
        payload: inbound.encode().unwrap(),
    };
    assert_eq!(
        transfer_log.verified_payload(&TAIRA, SccpNetworkV1::EthereumMainnet, 1),
        Ok(inbound)
    );
    let (topics, data) = transfer_log.encode();
    let mut logs = vec![log_json("transfer_to_taira", topics, data)];
    for (label, id, nonce) in [
        ("voided_expired", payloads[1].message_id(&TAIRA).unwrap(), 1),
        ("voided_frozen", [0; 32], 4),
    ] {
        let (topics, data) = VoidedLogV1 {
            message_id: id,
            nonce,
        }
        .encode();
        logs.push(log_json(label, topics, data));
    }
    logs.push(log_json(
        "certificate_100",
        vec![TOPIC_CERTIFICATE, word_u64(100), word_u64(7)],
        encode_tokens(&[
            AbiToken::Bytes(c100.qc.clone()),
            AbiToken::Bytes(c100.header.clone()),
            AbiToken::Bytes(c100.signature.clone()),
        ]),
    ));
    let payload_json: Vec<_> = payloads
        .iter()
        .map(|payload| {
            obj([
                ("nonce", num(payload.nonce)),
                ("payload", hex(&payload.encode().unwrap())),
                ("message_id", hex(&payload.message_id(&TAIRA).unwrap())),
            ])
        })
        .collect();
    let scenario = obj([
        ("taira_network_id", hex(&TAIRA)),
        ("consensus_instance", hex(&INSTANCE)),
        (
            "destination",
            obj([
                ("target", profile(destination.network)),
                ("route_revision", num(1)),
                ("destination_word", hex(&destination.destination_word)),
            ]),
        ),
        ("deadline_ms", num(DEADLINE)),
        ("payloads", Value::Array(payload_json)),
        ("committee_g7", hexes(&g7.keys)),
        ("committee_g8", hexes(&g8.keys)),
        (
            "pin",
            obj([
                ("generation", num(pin.generation)),
                ("committee_root", hex(&pin.committee_root)),
                ("start_height", num(pin.start_height)),
                ("until_ms", num(pin.until_ms)),
            ]),
        ),
        (
            "certificate_100",
            certificate_json(&x100, &c100, &sigma100, &g7.keys),
        ),
        (
            "certificate_150_rotation",
            certificate_json(&x150, &c150, &sigma150, &g7.keys),
        ),
        (
            "certificate_200",
            certificate_json(&x200, &c200, &sigma200, &g8.keys),
        ),
        ("block_100_root", hex(&block100.root())),
        ("history_leaves", hexes(&history)),
        (
            "control",
            obj([
                ("control_nonce", num(1)),
                ("track", num(1)),
                ("parliament_paused", Value::Bool(true)),
                ("fast_pause_until_ms", num(0)),
                ("certificate_id", hex(&control_fields.certificate_id)),
                ("effect_hash", hex(&control_fields.effect_hash)),
            ]),
        ),
        ("committee_state_after_rotation", hex(&committee_return)),
        ("pause_state_return", hex(&pause_return)),
        ("initial_committee_return", hex(&pin_return)),
    ]);
    with(
        header(
            "iroha.sccp.evm-calldata.v1",
            "specs/sccp.md §3.7, §5.1–§5.2.2 (revision 5)",
        ),
        vec![
            ("scenario", scenario),
            (
                "selectors",
                Value::Array(
                    SELECTORS
                        .iter()
                        .map(|(name, signature, selector)| {
                            obj([
                                ("function", text(name)),
                                ("signature", text(signature)),
                                ("selector", hex(selector)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "events",
                Value::Array(
                    EVENT_TOPICS
                        .iter()
                        .map(|(_, signature, topic)| {
                            obj([("signature", text(signature)), ("topic0", hex(topic))])
                        })
                        .collect(),
                ),
            ),
            ("calls", Value::Array(calls)),
            ("views", Value::Array(views)),
            ("logs", Value::Array(logs)),
            (
                "calldata_conformance",
                Value::Array(calldata_conformance(&transfer_call)),
            ),
        ],
    )
}
