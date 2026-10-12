//! Current native-certificate wallet calls against the canonical EVM calldata fixture.
//! Original burn/log semantics and independently generated EIP-1559 signing vectors are retained.
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::{
    api::{
        ApiShapeError, SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1,
        SccpMessageProofBundleV1, SccpRotationV1,
    },
    v1::{
        committee::{CommitteeStateV1, committee_root},
        control::{ControlLeafV1, control_leaf},
        destination::DestinationFlavor,
        destination_abi::DestinationError,
        evm_abi::TransferToTairaCallV1,
        finality::{QcFixedV1, SccpFinalityHeaderV1, checkpoint_id},
        hashes::{keccak256, transfer_leaf},
        history::history_path,
        merkle::PromoteOddTree,
        payload::SccpTransferPayloadV1,
        proof::{DestinationV1, ProofError},
    },
};
use iroha_sccp_wallet::pure::{
    bundle::{
        BundleError, BundlePurposeV1, CertificateUseV1, DestinationContextV1, verify_message_bundle,
    },
    control::{
        ControlBundleError, DestinationControlStateV1, PreFinalizeActionV1, TairaControlV1,
        plan_before_finalize, verify_control_bundle,
    },
    evm::{
        Eip1559TransactionV1, EvmError, EvmSigningKey, SignedEip1559V1, apply_control_calldata,
        finalize_calldata, submit_checkpoints_calldata, transfer_to_taira_calldata,
        void_expired_calldata, void_frozen_calldata,
    },
    rotation::{RotationChainError, verify_rotation_steps},
};
use norito::json::Value;
use std::{collections::BTreeMap, path::PathBuf};
#[path = "support/current.rs"]
pub mod support;
const T0: u64 = 1_800_000_000_000;
fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp")
        .join(name);
    norito::json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing fixture field {key}"))
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn fixed<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}
fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}
fn certificate(value: &Value) -> SccpCertificateV1 {
    SccpCertificateV1 {
        height: number(field(value, "height")),
        qc: fixed(field(value, "qc")),
        aggregate_signature: fixed(field(value, "aggregate_signature")),
        header: fixed(field(value, "header")),
        committee: field(value, "committee")
            .as_array()
            .unwrap()
            .iter()
            .map(fixed::<48>)
            .collect(),
    }
}
struct Scenario {
    taira: [u8; 32],
    instance: [u8; 32],
    destination: DestinationV1,
    deadline_ms: u64,
    initial: CommitteeStateV1,
    rotated: CommitteeStateV1,
    c100: SccpCertificateV1,
    c150: SccpCertificateV1,
    c200: SccpCertificateV1,
    next_keys: Vec<[u8; 48]>,
    payloads: Vec<Vec<u8>>,
    message_ids: Vec<[u8; 32]>,
    block100: PromoteOddTree,
    history: Vec<[u8; 32]>,
    control: ControlLeafV1,
    checkpoints: BTreeMap<u64, [u8; 32]>,
    empty_checkpoints: BTreeMap<u64, [u8; 32]>,
    calls: Value,
    secrets: Vec<[u8; 32]>,
}
fn scenario() -> Scenario {
    let calldata = fixture("evm_calldata_v1.json");
    let value = field(&calldata, "scenario");
    let taira = fixed(field(value, "taira_network_id"));
    let instance = fixed(field(value, "consensus_instance"));
    let dest = field(value, "destination");
    assert_eq!(field(dest, "target").as_str(), Some("ethereum-mainnet"));
    let destination = DestinationV1 {
        network: SccpNetworkV1::EthereumMainnet,
        route_revision: u32::try_from(number(field(dest, "route_revision"))).unwrap(),
        destination_word: fixed(field(dest, "destination_word")),
    };
    let payloads: Vec<_> = field(value, "payloads")
        .as_array()
        .unwrap()
        .iter()
        .map(|p| bytes(field(p, "payload")))
        .collect();
    let message_ids: Vec<_> = field(value, "payloads")
        .as_array()
        .unwrap()
        .iter()
        .map(|p| fixed(field(p, "message_id")))
        .collect();
    for (payload, id) in payloads.iter().zip(&message_ids) {
        assert_eq!(
            &SccpTransferPayloadV1::decode(payload)
                .unwrap()
                .message_id(&taira)
                .unwrap(),
            id
        );
    }
    let leaf = field(value, "control");
    let control = ControlLeafV1 {
        route_revision: destination.route_revision,
        control_nonce: number(field(leaf, "control_nonce")),
        track: u8::try_from(number(field(leaf, "track"))).unwrap(),
        parliament_paused: u8::from(field(leaf, "parliament_paused").as_bool().unwrap()),
        fast_pause_until_ms: number(field(leaf, "fast_pause_until_ms")),
        certificate_id: fixed(field(leaf, "certificate_id")),
        effect_hash: fixed(field(leaf, "effect_hash")),
    };
    let block100 = PromoteOddTree::block(&[
        transfer_leaf(&message_ids[1], &destination.destination_word),
        transfer_leaf(&message_ids[2], &destination.destination_word),
        control_leaf(
            &taira,
            destination.network,
            &destination.destination_word,
            &control,
        )
        .unwrap(),
    ])
    .unwrap();
    assert_eq!(block100.root(), fixed::<32>(field(value, "block_100_root")));
    let c100 = certificate(field(value, "certificate_100"));
    let c150 = certificate(field(value, "certificate_150_rotation"));
    let c200 = certificate(field(value, "certificate_200"));
    let pin = field(value, "pin");
    let initial = CommitteeStateV1::from_pin(
        number(field(pin, "generation")),
        fixed(field(pin, "committee_root")),
        number(field(pin, "start_height")),
        number(field(pin, "until_ms")),
    )
    .unwrap();
    let mut rotated = initial;
    rotated
        .apply_checkpoint(
            &SccpFinalityHeaderV1::parse(&c150.header).unwrap(),
            None,
            T0 + 200_000,
        )
        .unwrap();
    assert_eq!(rotated.root, committee_root(&c200.committee).unwrap());
    let checkpoints = [&c100, &c150, &c200]
        .into_iter()
        .map(|c| (c.height, checkpoint_id(&c.header)))
        .collect();
    Scenario {
        taira,
        instance,
        destination,
        deadline_ms: number(field(value, "deadline_ms")),
        initial,
        rotated,
        c100,
        c150,
        c200,
        next_keys: field(value, "committee_g8")
            .as_array()
            .unwrap()
            .iter()
            .map(fixed::<48>)
            .collect(),
        payloads,
        message_ids,
        block100,
        history: field(value, "history_leaves")
            .as_array()
            .unwrap()
            .iter()
            .map(fixed::<32>)
            .collect(),
        control,
        checkpoints,
        empty_checkpoints: BTreeMap::new(),
        calls: field(&calldata, "calls").clone(),
        secrets: (0..4_u8)
            .map(|index| keccak256(&[b"SCCP/FIXTURE/KEY/V1", &[index]]))
            .collect(),
    }
}
impl Scenario {
    fn call(&self, label: &str) -> Vec<u8> {
        bytes(field(
            self.calls
                .as_array()
                .unwrap()
                .iter()
                .find(|c| field(c, "label").as_str() == Some(label))
                .unwrap(),
            "calldata",
        ))
    }
    fn g7_context(&self, now_ms: u64) -> DestinationContextV1<'_> {
        DestinationContextV1 {
            taira_network_id: self.taira,
            consensus_instance: self.instance,
            destination: self.destination,
            flavor: DestinationFlavor::Evm,
            committee_state: self.initial,
            ton_keys: None,
            checkpoints: &self.empty_checkpoints,
            now_ms,
        }
    }
    fn rotated_context(&self, now_ms: u64) -> DestinationContextV1<'_> {
        DestinationContextV1 {
            committee_state: self.rotated,
            ..self.g7_context(now_ms)
        }
    }
    fn block(&self, historical: bool) -> SccpBlockRefV1 {
        SccpBlockRefV1 {
            height: 100,
            sccp_root: self.block100.root(),
            message_count: 3,
            history_index: u64::from(historical),
            history_path: if historical {
                history_path(&self.history, 1).unwrap()
            } else {
                vec![]
            },
        }
    }
    fn direct_bundle(&self) -> SccpMessageProofBundleV1 {
        SccpMessageProofBundleV1 {
            message_id: self.message_ids[1],
            payload: self.payloads[1].clone(),
            deadline_ms: self.deadline_ms,
            leaf_index: 0,
            path: self.block100.path(0).unwrap(),
            block: self.block(false),
            certificate: self.c100.clone(),
        }
    }
    fn historical_bundle(&self) -> SccpMessageProofBundleV1 {
        SccpMessageProofBundleV1 {
            message_id: self.message_ids[2],
            payload: self.payloads[2].clone(),
            deadline_ms: self.deadline_ms,
            leaf_index: 1,
            path: self.block100.path(1).unwrap(),
            block: self.block(true),
            certificate: self.c200.clone(),
        }
    }
    fn control_bundle(&self, historical: bool) -> SccpControlProofBundleV1 {
        SccpControlProofBundleV1 {
            network: self.destination.network,
            revision: self.destination.route_revision,
            control_nonce: self.control.control_nonce,
            track: self.control.track,
            parliament_paused: self.control.parliament_paused != 0,
            fast_pause_until_ms: self.control.fast_pause_until_ms,
            certificate_id: self.control.certificate_id,
            effect_hash: self.control.effect_hash,
            leaf_index: 2,
            path: self.block100.path(2).unwrap(),
            block: self.block(historical),
            certificate: if historical {
                self.c200.clone()
            } else {
                self.c100.clone()
            },
        }
    }
    fn rotation(&self) -> SccpRotationV1 {
        SccpRotationV1 {
            certificate: self.c150.clone(),
            next_committee: self.next_keys.clone(),
        }
    }
}
#[test]
fn direct_finalize_bundle_verifies_and_matches_the_golden_calldata() {
    let s = scenario();
    let verified = verify_message_bundle(
        &s.direct_bundle(),
        &s.g7_context(T0 + 200_000),
        BundlePurposeV1::Finalize,
        CertificateUseV1::Inline,
    )
    .unwrap();
    assert_eq!(verified.nonce(), 1);
    assert_eq!(verified.transfer().message_id, s.message_ids[1]);
    assert_eq!(
        QcFixedV1::parse(&s.c100.qc).unwrap().signers.count_ones(),
        3
    );
    assert_eq!(
        finalize_calldata(&verified).unwrap(),
        s.call("finalize_direct")
    );
    assert_eq!(
        void_expired_calldata(&verified),
        Err(EvmError::WrongPurpose)
    );
    let checkpoint = verify_message_bundle(
        &s.direct_bundle(),
        &DestinationContextV1 {
            checkpoints: &s.checkpoints,
            ..s.g7_context(T0 + 200_000)
        },
        BundlePurposeV1::Finalize,
        CertificateUseV1::Checkpoint,
    )
    .unwrap();
    assert_eq!(
        finalize_calldata(&checkpoint).unwrap(),
        s.call("finalize_checkpoint_direct")
    );
}
#[test]
fn historical_finalize_bundle_verifies_and_matches_the_golden_calldata() {
    let s = scenario();
    for (usage, label) in [
        (CertificateUseV1::Inline, "finalize_historical"),
        (
            CertificateUseV1::Checkpoint,
            "finalize_checkpoint_historical",
        ),
    ] {
        let verified = verify_message_bundle(
            &s.historical_bundle(),
            &DestinationContextV1 {
                checkpoints: if usage == CertificateUseV1::Checkpoint {
                    &s.checkpoints
                } else {
                    &s.empty_checkpoints
                },
                ..s.rotated_context(T0 + 300_000)
            },
            BundlePurposeV1::Finalize,
            usage,
        )
        .unwrap();
        assert!(verified.is_historical());
        assert_eq!(verified.nonce(), 2);
        assert_eq!(finalize_calldata(&verified).unwrap(), s.call(label));
    }
}
#[test]
fn void_bundles_match_the_golden_calldata_after_the_deadline() {
    let s = scenario();
    let after = s.deadline_ms + 1;
    let direct = verify_message_bundle(
        &s.direct_bundle(),
        &s.g7_context(after),
        BundlePurposeV1::VoidExpired,
        CertificateUseV1::Inline,
    )
    .unwrap();
    assert_eq!(
        void_expired_calldata(&direct).unwrap(),
        s.call("void_expired")
    );
    assert_eq!(finalize_calldata(&direct), Err(EvmError::WrongPurpose));
    let historical = verify_message_bundle(
        &s.historical_bundle(),
        &DestinationContextV1 {
            checkpoints: &s.checkpoints,
            ..s.rotated_context(after)
        },
        BundlePurposeV1::VoidExpired,
        CertificateUseV1::Checkpoint,
    )
    .unwrap();
    assert_eq!(
        void_expired_calldata(&historical).unwrap(),
        s.call("void_expired_checkpoint")
    );
    assert_eq!(
        verify_message_bundle(
            &s.direct_bundle(),
            &s.g7_context(s.deadline_ms),
            BundlePurposeV1::VoidExpired,
            CertificateUseV1::Inline
        ),
        Err(BundleError::DeadlineNotReached)
    );
    assert_eq!(void_frozen_calldata(4, 3).unwrap(), s.call("void_frozen"));
}
#[test]
fn transfer_to_taira_calldata_matches_the_golden_calldata() {
    let s = scenario();
    let golden = s.call("transfer_to_taira");
    let call = TransferToTairaCallV1::decode(&golden).unwrap();
    assert_eq!(
        transfer_to_taira_calldata(
            &call.taira_recipient,
            call.token_amount,
            call.expected_nonce
        )
        .unwrap(),
        golden
    );
}
#[test]
fn rotation_chain_verifies_and_matches_the_golden_calldata() {
    let s = scenario();
    let plan = verify_rotation_steps(&[s.rotation()], &s.g7_context(T0 + 200_000), 8).unwrap();
    assert_eq!(*plan.final_state(), s.rotated);
    assert_eq!(
        submit_checkpoints_calldata(&plan),
        vec![s.call("checkpoint_rotation")]
    );
    assert!(
        verify_message_bundle(
            &s.direct_bundle(),
            &s.rotated_context(T0 + 300_000),
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        )
        .is_err()
    );
    assert!(
        verify_message_bundle(
            &s.direct_bundle(),
            &s.rotated_context(T0 + 300_000),
            BundlePurposeV1::Finalize,
            CertificateUseV1::Checkpoint
        )
        .is_err()
    );
}
#[test]
fn control_bundles_verify_and_match_the_golden_calldata() {
    let s = scenario();
    let applied = DestinationControlStateV1::default();
    for (historical, usage, label) in [
        (false, CertificateUseV1::Inline, "apply_control_direct"),
        (true, CertificateUseV1::Inline, "apply_control_historical"),
        (
            true,
            CertificateUseV1::Checkpoint,
            "apply_control_checkpoint",
        ),
    ] {
        let mut context = if historical {
            s.rotated_context(T0 + 300_000)
        } else {
            s.g7_context(T0 + 200_000)
        };
        if usage == CertificateUseV1::Checkpoint {
            context.checkpoints = &s.checkpoints;
        }
        let verified =
            verify_control_bundle(&s.control_bundle(historical), &context, &applied, usage)
                .unwrap();
        assert_eq!(apply_control_calldata(&verified), s.call(label));
        assert!(!verified.finalize_allowed_after_apply(context.now_ms));
    }
    assert_eq!(
        plan_before_finalize(
            &applied,
            Some(&TairaControlV1 {
                control_nonce: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0
            }),
            T0
        ),
        PreFinalizeActionV1::ApplyControl {
            control_nonce: 1,
            paused: true
        }
    );
}
fn finalize(
    bundle: &SccpMessageProofBundleV1,
    context: &DestinationContextV1<'_>,
) -> Result<(), BundleError> {
    verify_message_bundle(
        bundle,
        context,
        BundlePurposeV1::Finalize,
        CertificateUseV1::Inline,
    )
    .map(|_| ())
}
#[test]
fn tampered_committees_fail() {
    let s = scenario();
    let selected = s.g7_context(T0 + 200_000);
    let good = s.direct_bundle();
    let mut swapped = good.clone();
    swapped.certificate.committee = s.next_keys.clone();
    assert_eq!(
        finalize(&swapped, &selected),
        Err(BundleError::Shape(ApiShapeError::CommitteeRootMismatch))
    );
    let mut forged = swapped.clone();
    let mut fields = SccpFinalityHeaderV1::parse(&forged.certificate.header)
        .unwrap()
        .fields();
    fields.committee_root = committee_root(&s.next_keys).unwrap();
    forged.certificate.header = fields.to_bytes();
    assert!(finalize(&forged, &selected).is_err());
    let mut unordered = good.clone();
    unordered.certificate.committee.swap(1, 2);
    assert_eq!(
        finalize(&unordered, &selected),
        Err(BundleError::Shape(ApiShapeError::BadCommittee))
    );
    let mut duplicate = good.clone();
    duplicate.certificate.committee[1] = duplicate.certificate.committee[0];
    assert_eq!(
        finalize(&duplicate, &selected),
        Err(BundleError::Shape(ApiShapeError::BadCommittee))
    );
    let mut shrunk = good;
    shrunk.certificate.committee.pop();
    assert_eq!(
        finalize(&shrunk, &selected),
        Err(BundleError::Shape(ApiShapeError::BadCommittee))
    );
}
#[test]
fn tampered_bitmaps_and_signatures_fail() {
    let s = scenario();
    let selected = s.g7_context(T0 + 200_000);
    let good = s.direct_bundle();
    assert_eq!(QcFixedV1::parse(&good.certificate.qc).unwrap().signers, 7);
    for bitmap in [0_u32, 3, 15, 7 | (1 << 4)] {
        let mut bad = good.clone();
        bad.certificate.qc[112..].copy_from_slice(&bitmap.to_be_bytes());
        assert_eq!(
            finalize(&bad, &selected),
            Err(BundleError::Shape(ApiShapeError::BadSignerSet))
        );
    }
    let no_checkpoints = BTreeMap::new();
    let selected = DestinationContextV1 {
        checkpoints: &no_checkpoints,
        ..selected
    };
    let mut shifted = good.clone();
    shifted.certificate.qc[112..].copy_from_slice(&14_u32.to_be_bytes());
    assert_eq!(
        finalize(&shifted, &selected),
        Err(BundleError::Certificate(DestinationError::BadSignature))
    );
    let mut substituted = good.clone();
    substituted.certificate.aggregate_signature = s.c150.aggregate_signature;
    assert_eq!(
        finalize(&substituted, &selected),
        Err(BundleError::Certificate(DestinationError::BadSignature))
    );
    for signature in [[0; 96], iroha_sccp::v1::committee::IDENTITY_SIGNATURE] {
        let mut malformed = good.clone();
        malformed.certificate.aggregate_signature = signature;
        assert!(finalize(&malformed, &selected).is_err());
    }
    let mut flipped = good;
    flipped.certificate.aggregate_signature[5] ^= 0x40;
    assert!(finalize(&flipped, &selected).is_err());
}
#[test]
fn tampered_paths_payloads_and_deadlines_fail() {
    let s = scenario();
    let selected = s.g7_context(T0 + 200_000);
    let good = s.direct_bundle();
    for mutate in [
        |b: &mut SccpMessageProofBundleV1| b.path[0][31] ^= 1,
        |b: &mut SccpMessageProofBundleV1| b.path.push([0; 32]),
        |b: &mut SccpMessageProofBundleV1| b.leaf_index = 1,
    ] {
        let mut bad = good.clone();
        mutate(&mut bad);
        assert_eq!(
            finalize(&bad, &selected),
            Err(BundleError::Proof(ProofError::BadBlockPath))
        );
    }
    let mut count = good.clone();
    count.block.message_count += 1;
    assert_eq!(
        finalize(&count, &selected),
        Err(BundleError::Proof(ProofError::BadBlockReference))
    );
    let mut trailing = good.clone();
    trailing.payload.push(0);
    assert_eq!(
        finalize(&trailing, &selected),
        Err(BundleError::Proof(ProofError::BadPayload))
    );
    let mut bsc = good.clone();
    bsc.payload[9] = 2;
    assert_eq!(
        finalize(&bsc, &selected),
        Err(BundleError::Proof(ProofError::BadPayload))
    );
    let mut id = good.clone();
    id.message_id = s.message_ids[2];
    assert_eq!(
        finalize(&id, &selected),
        Err(BundleError::MessageIdMismatch)
    );
    let mut deadline = good.clone();
    deadline.deadline_ms += 1;
    assert_eq!(
        finalize(&deadline, &selected),
        Err(BundleError::DeadlineMismatch)
    );
    let mut amount = good.clone();
    let mut payload = SccpTransferPayloadV1::decode(&amount.payload).unwrap();
    payload.amount += 1;
    amount.payload = payload.encode().unwrap();
    assert_eq!(
        finalize(&amount, &selected),
        Err(BundleError::Proof(ProofError::BadBlockPath))
    );
    assert_eq!(
        finalize(&good, &s.g7_context(s.deadline_ms + 1)),
        Err(BundleError::DeadlinePassed)
    );
    assert_eq!(finalize(&good, &s.g7_context(s.deadline_ms)), Ok(()));
}
#[test]
fn wrong_network_destination_and_expired_committees_fail() {
    let s = scenario();
    let good = s.direct_bundle();
    let selected = s.g7_context(T0 + 200_000);
    let mut wrong = selected;
    wrong.taira_network_id[0] ^= 1;
    assert_eq!(finalize(&good, &wrong), Err(BundleError::HeaderMismatch));
    let mut candidate = good.clone();
    candidate.certificate.height += 1;
    assert_eq!(
        finalize(&candidate, &selected),
        Err(BundleError::Shape(ApiShapeError::CertificateHeightMismatch))
    );
    wrong = selected;
    wrong.destination.destination_word[31] ^= 1;
    assert_eq!(
        finalize(&good, &wrong),
        Err(BundleError::Proof(ProofError::BadBlockPath))
    );
    wrong = selected;
    wrong.destination.route_revision += 1;
    assert_eq!(
        finalize(&good, &wrong),
        Err(BundleError::Proof(ProofError::WrongDestination))
    );
    wrong = selected;
    wrong.destination.network = SccpNetworkV1::BscMainnet;
    assert_eq!(
        finalize(&good, &wrong),
        Err(BundleError::Proof(ProofError::WrongDestination))
    );
    assert_eq!(
        verify_message_bundle(
            &good,
            &s.g7_context(s.initial.until_ms + 1),
            BundlePurposeV1::VoidExpired,
            CertificateUseV1::Inline
        )
        .map(|_| ()),
        Err(BundleError::Certificate(
            DestinationError::CommitteeNotAccepted
        ))
    );
    assert!(finalize(&good, &s.rotated_context(T0 + 200_000)).is_err());
}
#[test]
fn control_bundles_of_another_revision_or_network_fail() {
    let s = scenario();
    let context = s.g7_context(T0 + 200_000);
    let applied = DestinationControlStateV1::default();
    let mut revision = s.control_bundle(false);
    revision.revision = 2;
    assert_eq!(
        verify_control_bundle(&revision, &context, &applied, CertificateUseV1::Inline),
        Err(ControlBundleError::WrongDeployment)
    );
    let mut other = context;
    other.destination.route_revision = 2;
    assert_eq!(
        verify_control_bundle(&revision, &other, &applied, CertificateUseV1::Inline),
        Err(ControlBundleError::Bundle(BundleError::Proof(
            ProofError::BadBlockPath
        )))
    );
    let mut network = s.control_bundle(false);
    network.network = SccpNetworkV1::BscMainnet;
    assert_eq!(
        verify_control_bundle(&network, &context, &applied, CertificateUseV1::Inline),
        Err(ControlBundleError::WrongDeployment)
    );
    for mutate in [
        |b: &mut SccpControlProofBundleV1| b.parliament_paused = false,
        |b: &mut SccpControlProofBundleV1| b.certificate_id[0] ^= 1,
        |b: &mut SccpControlProofBundleV1| b.effect_hash[0] ^= 1,
        |b: &mut SccpControlProofBundleV1| b.fast_pause_until_ms = 1,
    ] {
        let mut bad = s.control_bundle(false);
        mutate(&mut bad);
        assert_eq!(
            verify_control_bundle(&bad, &context, &applied, CertificateUseV1::Inline),
            Err(ControlBundleError::Bundle(BundleError::Proof(
                ProofError::BadBlockPath
            )))
        );
    }
    let mut transfer = s.control_bundle(false);
    transfer.leaf_index = 0;
    transfer.path = s.block100.path(0).unwrap();
    assert_eq!(
        verify_control_bundle(&transfer, &context, &applied, CertificateUseV1::Inline),
        Err(ControlBundleError::Bundle(BundleError::Proof(
            ProofError::BadBlockPath
        )))
    );
    assert_eq!(
        verify_control_bundle(
            &s.control_bundle(false),
            &context,
            &DestinationControlStateV1 {
                control_nonce: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0
            },
            CertificateUseV1::Inline
        ),
        Err(ControlBundleError::Stale)
    );
}
#[test]
fn a_lagging_destination_replays_seventeen_generations_in_two_calls() {
    let f = support::Fixture::new();
    let context = DestinationContextV1 {
        taira_network_id: support::NETWORK,
        consensus_instance: support::INSTANCE,
        destination: f.destination,
        flavor: DestinationFlavor::Evm,
        committee_state: f.state,
        ton_keys: None,
        checkpoints: &f.checkpoints,
        now_ms: support::NOW,
    };
    let steps: Vec<_> = (1..=17)
        .map(|generation| f.rotation(generation, 100 + generation, &f))
        .collect();
    let plan = verify_rotation_steps(&steps, &context, 18).unwrap();
    assert_eq!(
        plan.batches().map(<[_]>::len).collect::<Vec<_>>(),
        vec![16, 1]
    );
    assert_eq!(submit_checkpoints_calldata(&plan).len(), 2);
    assert_eq!(plan.final_state().generation, 18);
    assert_eq!(
        verify_rotation_steps(&steps[..16], &context, 18),
        Err(RotationChainError::ChainTooShort {
            reached: 17,
            target: 18
        })
    );
}

/// Vectors produced by `ethers` 6 (`Wallet.signTransaction`) with fixture key 0.
struct EthersVector {
    chain_id: u64,
    nonce: u64,
    priority: u128,
    max_fee: u128,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    unsigned: &'static str,
    signing_hash: &'static str,
    signed: &'static str,
    hash: &'static str,
}

fn ethers_vectors() -> Vec<EthersVector> {
    vec![
        EthersVector {
            chain_id: 1,
            nonce: 7,
            priority: 2_000_000_000,
            max_fee: 30_000_000_000,
            gas_limit: 300_000,
            to: Some([0x22; 20]),
            value: 0,
            data: hex::decode(
                "5b094c0000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003",
            )
            .expect("hex"),
            unsigned: "02f86e010784773594008506fc23ac00830493e094222222222222222222222222222222222222222280b8445b094c0000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003c0",
            signing_hash: "7ac8e9a661b4af960911fa48c1a4d3d8a662f9b70d692046a4f6e9a19c9615e4",
            signed: "02f8b1010784773594008506fc23ac00830493e094222222222222222222222222222222222222222280b8445b094c0000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003c080a0de11561abac7d15eecc33c8fd926227a66b7b38abe552e40d1347c60a40b0687a058c004a5e32d982425206ead057b34749a313d024e179e79dafd8997a3199724",
            hash: "0c5c47605cae9f496dbd72a4d00d3f50a8b948474ff484137b6d7ace795b5186",
        },
        EthersVector {
            chain_id: 56,
            nonce: 0,
            priority: 0,
            max_fee: 1_000_000_000,
            gas_limit: 21_000,
            to: Some(
                hex::decode("7e90b4f929bcfd28c8dec8831d30dacb139d7184")
                    .expect("hex")
                    .try_into()
                    .expect("20 bytes"),
            ),
            value: 1_000_000_000_000_000_000,
            data: Vec::new(),
            unsigned: "02eb388080843b9aca00825208947e90b4f929bcfd28c8dec8831d30dacb139d7184880de0b6b3a764000080c0",
            signing_hash: "8685178feadcd84692a5bf8fa5e5d34ad849ebe68029be6ce936fea6fdf6566a",
            signed: "02f86e388080843b9aca00825208947e90b4f929bcfd28c8dec8831d30dacb139d7184880de0b6b3a764000080c080a094999ef2cd185e46d8260e04ba7cecc813a8f231ed30cd0124f47b404a55a394a0312984475358507fde823756782855080bf59efc5d5c3b19db814d347d7bfa85",
            hash: "3f65e77155c73d0030f6d91bcd2e77a7d54ec52c049b4d470b420c735498c2b8",
        },
        EthersVector {
            chain_id: 1,
            nonce: 1,
            priority: 1,
            max_fee: 1,
            gas_limit: 3_000_000,
            to: None,
            value: 0,
            data: vec![0x60; 60],
            unsigned: "02f84901010101832dc6c08080b83c606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060c0",
            signing_hash: "066d6fc4aa9239811db3aa65e3cc06fe01b772a48b9d63fdadc6661e7141a43b",
            signed: "02f88c01010101832dc6c08080b83c606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060c001a0ecd42ee94bae8709e11bb11217b1f92f24f325c77ec0857c1d6bfea797d6dc6ea02e86336ecdd9c790eeb0f56e4ceb010c7fb580b1214c28591dc62fd5e2cc1df4",
            hash: "3e3b452deef43cc376f632641db36013aeab8fab4707bf3020ad4cdcd7b485f0",
        },
    ]
}

#[test]
fn eip1559_transactions_match_ethers_and_recover_the_signer() {
    let s = scenario();
    let key = EvmSigningKey::from_secret(s.secrets[0]).expect("fixture key 0");
    assert_eq!(
        hex::encode(key.address()),
        "7e90b4f929bcfd28c8dec8831d30dacb139d7184"
    );
    for vector in ethers_vectors() {
        let transaction = Eip1559TransactionV1 {
            chain_id: vector.chain_id,
            nonce: vector.nonce,
            max_priority_fee_per_gas: vector.priority,
            max_fee_per_gas: vector.max_fee,
            gas_limit: vector.gas_limit,
            to: vector.to,
            value: vector.value,
            data: vector.data,
        };
        assert_eq!(hex::encode(transaction.unsigned_bytes()), vector.unsigned);
        assert_eq!(hex::encode(transaction.signing_hash()), vector.signing_hash);
        let export = transaction.export_unsigned();
        assert_eq!(export.hex(), format!("0x{}", vector.unsigned));
        assert_eq!(
            Eip1559TransactionV1::decode_unsigned(&export.unsigned).expect("decodes"),
            transaction
        );
        let signed = transaction.sign(&key).expect("signs");
        assert_eq!(signed.sender().expect("sender"), key.address());
        // RFC 6979 with low-S is deterministic, so the signature equals ethers' byte for byte.
        assert_eq!(hex::encode(signed.raw()), vector.signed);
        assert_eq!(hex::encode(signed.hash()), vector.hash);
        let decoded =
            SignedEip1559V1::decode(&hex::decode(vector.signed).expect("hex")).expect("decodes");
        assert_eq!(decoded, signed);
        assert_eq!(decoded.sender().expect("sender"), key.address());
    }
}

#[test]
fn finalize_calldata_ships_in_a_signed_transaction_from_a_key_file() {
    let s = scenario();
    let verified = verify_message_bundle(
        &s.direct_bundle(),
        &s.g7_context(T0 + 200_000),
        BundlePurposeV1::Finalize,
        CertificateUseV1::Inline,
    )
    .expect("verifies");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("relayer.key");
    std::fs::write(&path, format!("0x{}\n", hex::encode(s.secrets[3]))).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    let key = EvmSigningKey::load(&path).expect("owner-only key file");
    let transaction = Eip1559TransactionV1::contract_call(
        s.destination.network,
        s.destination.destination_word[12..]
            .try_into()
            .expect("20 bytes"),
        finalize_calldata(&verified).expect("calldata"),
        0,
        1_000_000_000,
        40_000_000_000,
        250_000,
    )
    .expect("transaction");
    let signed = transaction.sign(&key).expect("signed");
    let decoded = SignedEip1559V1::decode(&signed.raw()).expect("decodes");
    assert_eq!(decoded.transaction.data, s.call("finalize_direct"));
    assert_eq!(decoded.sender().expect("sender"), key.address());
    // The --emit path: an external signer returns a signature over the exported hash.
    let export = transaction.export_unsigned();
    let external = key
        .sign_digest(&export.signing_hash)
        .expect("external signature");
    assert_eq!(
        transaction
            .with_signature_from(&external, &key.address())
            .expect("attached"),
        signed
    );
    let parts = export.qr_payloads(1_000).expect("qr parts");
    assert!(parts.len() > 1);
    assert!(parts.iter().all(|part| part.len() <= 1_000));
}
