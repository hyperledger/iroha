//! Pure wallet native certificate, checkpoint, mutation and transaction-signing controls.
//! Native calldata is checked against the canonical shared encoder and strict void decoder;
//! independent contract-produced native calldata goldens remain a separate qualification gate.
//! The unchanged ethers EIP-1559 vectors below retain their independent byte assertions.

#[path = "../src/pure/test_support.rs"]
mod support;
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::{
    api::{SccpMessageProofBundleV1, SccpRotationV1},
    v1::{
        destination::{
            CertificateSourceV1, DestinationError, DestinationFlavor, DestinationObservationV1,
            MessagePurposeV1, PreflightError, StopReasonV1,
        },
        evm_abi::{self, VoidCallV1},
        finality::{FLAG_ROTATION, SccpFinalityHeaderV1},
        payload::SccpTransferPayloadV1,
    },
};
use iroha_sccp_wallet::pure::{
    bundle::{BundleError, BundleSourceV1, VerifiedMessageBundleV1, verify_message_bundle},
    control::verify_control_bundle,
    evm::{
        Eip1559TransactionV1, EvmError, EvmSigningKey, SignedEip1559V1, apply_control_calldata,
        finalize_calldata, submit_checkpoints_calldata, transfer_to_taira_calldata,
        void_expired_calldata, void_frozen_calldata,
    },
    rotation::{RotationChainError, verify_rotation_steps},
};
use std::collections::BTreeMap;
use support::{DAY, Fixture, NOW, T0, reads};
fn verify(
    bundle: &SccpMessageProofBundleV1,
    view: &DestinationObservationV1,
    purpose: MessagePurposeV1,
) -> Result<VerifiedMessageBundleV1, BundleError> {
    verify_message_bundle(
        bundle,
        &bundle.message_id,
        view,
        BundleSourceV1::Inline,
        purpose,
    )
}
// Public synthetic inputs formerly stored beside the retired attestation vectors.
// Preserve their exact key/address identities for the independent ethers transaction assertions.
fn fixture_secret(index: usize) -> [u8; 32] {
    let (secret, public, address) = match index {
        0 => (
            "998dba6f0ff534544e377f85847d49e338287a687a30139a1e4900525c48f197",
            "03ffc6231fa71edc1715d243ae48240e0358bc2b2a74c2143cc309337b5cf59853",
            "7e90b4f929bcfd28c8dec8831d30dacb139d7184",
        ),
        3 => (
            "95adaf16cd7a4d9a6ce6f60ee687fcc878156de1df211cac87ccab6f8c28b3bf",
            "0301ba61fcd41f51cdab41c59f35e716e6cebd0cab91644211d22fdaf8dd77185c",
            "6f21936622742a72e51cf9595c32d4c1db0e7ea5",
        ),
        _ => panic!("unsupported synthetic transaction key"),
    };
    let key: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
    assert_eq!(
        hex::encode(iroha_sccp::ethereum_signing::public_key_of(&key).unwrap()),
        public
    );
    assert_eq!(
        hex::encode(iroha_sccp::ethereum_signing::address_of_secret(&key).unwrap()),
        address
    );
    key
}

#[test]
fn direct_finalize_bundle_verifies_and_preserves_native_calldata() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(false);
    let view = f.observation(NOW, reads(&b.certificate, false));
    let verified = verify(&b, &view, MessagePurposeV1::Finalize).unwrap();
    assert!(!verified.is_historical());
    assert_eq!(verified.message_id(), b.message_id);
    assert_eq!(verified.nonce(), 5);
    assert_eq!(verified.amount(), 1_000_000_000);
    assert_eq!(verified.deadline_ms(), T0 + DAY);
    let native = b.certificate.to_destination_certificate().unwrap();
    let proof = b.message_proof(&support::NETWORK, &b.message_id).unwrap();
    let data = finalize_calldata(&verified).unwrap();
    assert_eq!(data, evm_abi::finalize_from_taira_calldata(&native, &proof));
    assert_eq!(&data[..4], &[0x10, 0xef, 0xea, 0x88]);
    assert_eq!(
        void_expired_calldata(&verified),
        Err(EvmError::WrongPurpose)
    );
}
#[test]
fn historical_finalize_preserves_history_inside_native_block_reference() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(true);
    let view = f.observation(NOW, reads(&b.certificate, false));
    let verified = verify(&b, &view, MessagePurposeV1::Finalize).unwrap();
    assert!(verified.is_historical());
    assert_eq!(verified.proof().block.history_path, b.block.history_path);
    let native = b.certificate.to_destination_certificate().unwrap();
    assert_eq!(
        finalize_calldata(&verified).unwrap(),
        evm_abi::finalize_from_taira_calldata(&native, verified.proof())
    );
    let stored = f.observation(NOW, reads(&b.certificate, true));
    let checkpoint = verify_message_bundle(
        &b,
        &b.message_id,
        &stored,
        BundleSourceV1::Checkpoint,
        MessagePurposeV1::Finalize,
    )
    .unwrap();
    let CertificateSourceV1::Checkpoint(reference) = checkpoint.source() else {
        panic!("explicit checkpoint")
    };
    assert_eq!(
        finalize_calldata(&checkpoint).unwrap(),
        evm_abi::finalize_from_checkpoint_calldata(reference, checkpoint.proof())
    );
}
#[test]
fn void_bundles_preserve_native_calldata_and_deadline_boundary() {
    let f = Fixture::new(DestinationFlavor::Evm);
    for historical in [false, true] {
        let b = f.message(historical);
        let exact = f.observation(b.deadline_ms, reads(&b.certificate, false));
        assert!(verify(&b, &exact, MessagePurposeV1::VoidExpired).is_err());
        let late = f.observation(b.deadline_ms + 1, reads(&b.certificate, false));
        let verified = verify(&b, &late, MessagePurposeV1::VoidExpired).unwrap();
        let data = void_expired_calldata(&verified).unwrap();
        assert_eq!(
            VoidCallV1::decode(&data).unwrap(),
            VoidCallV1::Expired {
                nonce: 5,
                from_checkpoint: false
            }
        );
        assert_eq!(finalize_calldata(&verified), Err(EvmError::WrongPurpose));
        let mut tail = data.clone();
        tail.push(0);
        assert!(VoidCallV1::decode(&tail).is_err());
        let stored = f.observation(b.deadline_ms + 1, reads(&b.certificate, true));
        let verified = verify_message_bundle(
            &b,
            &b.message_id,
            &stored,
            BundleSourceV1::Checkpoint,
            MessagePurposeV1::VoidExpired,
        )
        .unwrap();
        assert_eq!(
            VoidCallV1::decode(&void_expired_calldata(&verified).unwrap()).unwrap(),
            VoidCallV1::Expired {
                nonce: 5,
                from_checkpoint: true
            }
        );
    }
    assert_eq!(
        VoidCallV1::decode(&void_frozen_calldata(4, 3).unwrap()).unwrap(),
        VoidCallV1::Frozen {
            first_nonce: 4,
            count: 3
        }
    );
    assert!(void_frozen_calldata(0, 0).is_err());
    assert!(void_frozen_calldata(u64::MAX, 2).is_err());
}
#[test]
fn transfer_to_taira_retains_canonical_calldata_and_amount_checks() {
    let recipient = vec![1, 2, 3];
    let bytes = transfer_to_taira_calldata(&recipient, 1000, 5).unwrap();
    assert_eq!(
        bytes,
        evm_abi::TransferToTairaCallV1 {
            taira_recipient: recipient,
            token_amount: 1000,
            expected_nonce: 5
        }
        .calldata()
    );
    assert_eq!(
        transfer_to_taira_calldata(&[], 1000, 5),
        Err(EvmError::BadRecipient)
    );
    assert_eq!(
        transfer_to_taira_calldata(&vec![1; 1025], 1000, 5),
        Err(EvmError::BadRecipient)
    );
    assert_eq!(
        transfer_to_taira_calldata(&[1], 0, 5),
        Err(EvmError::BadAmount)
    );
}
#[test]
fn checkpoint_chain_verifies_and_preserves_native_calldata() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let steps = f.rotations(2);
    let view = f.observation(
        NOW,
        steps.iter().map(|s| (s.certificate.height, None)).collect(),
    );
    let plan = verify_rotation_steps(&steps, None, &view, 9).unwrap();
    assert_eq!(plan.final_observation().committee().generation, 9);
    assert_eq!(plan.stopped(), None);
    let expected = steps
        .iter()
        .map(|s| s.certificate.to_destination_certificate().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        submit_checkpoints_calldata(&plan).unwrap(),
        vec![evm_abi::submit_checkpoints_calldata(&expected)]
    );
}
#[test]
fn control_bundles_preserve_complete_native_calldata_and_pause_semantics() {
    let f = Fixture::new(DestinationFlavor::Evm);
    for historical in [false, true] {
        for paused in [false, true] {
            let b = f.control(historical, paused, 0);
            let view = f.observation(NOW, reads(&b.certificate, false));
            let verified = verify_control_bundle(&b, &view, BundleSourceV1::Inline).unwrap();
            assert_eq!(verified.is_historical(), historical);
            assert_eq!(verified.finalize_allowed_after_apply(), !paused);
            let cert = b.certificate.to_destination_certificate().unwrap();
            assert_eq!(
                apply_control_calldata(&verified).unwrap(),
                evm_abi::apply_control_calldata(&cert, verified.proof())
            );
        }
    }
    let b = f.control(false, false, NOW + 1000);
    let view = f.observation(NOW, reads(&b.certificate, false));
    assert!(
        !verify_control_bundle(&b, &view, BundleSourceV1::Inline)
            .unwrap()
            .finalize_allowed_after_apply()
    );
}
#[test]
fn tampered_native_committees_fail_without_offered_root_trust() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(false);
    let view = f.observation(NOW, reads(&b.certificate, false));
    let mut bad = b.clone();
    bad.certificate.committee[0][3] ^= 1;
    assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    let mut bad = b.clone();
    bad.certificate.committee.swap(0, 1);
    assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    let mut bad = b.clone();
    bad.certificate.committee[1] = bad.certificate.committee[0];
    assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    let mut bad = b.clone();
    bad.certificate.committee.pop();
    assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    let mut state = *view.committee();
    state.root = [0x99; 32];
    let other = f.observation_with(NOW, state, reads(&b.certificate, false), view.pause());
    assert!(verify(&b, &other, MessagePurposeV1::Finalize).is_err());
}
#[test]
fn tampered_exact_bitmaps_and_bls_encodings_fail() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(false);
    let view = f.observation(NOW, reads(&b.certificate, false));
    assert_eq!(&b.certificate.qc[112..], &7_u32.to_be_bytes());
    for bitmap in [0_u32, 3, 15, 23] {
        let mut bad = b.clone();
        bad.certificate.qc[112..].copy_from_slice(&bitmap.to_be_bytes());
        assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    }
    let mut shifted = b.clone();
    shifted.certificate.qc[112..].copy_from_slice(&14_u32.to_be_bytes());
    assert!(verify(&shifted, &view, MessagePurposeV1::Finalize).is_err());
    let mut bad = b.clone();
    bad.certificate.aggregate_signature[5] ^= 0x40;
    assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    for signature in [
        [0; 96],
        iroha_sccp::v1::committee::IDENTITY_SIGNATURE,
        [0xff; 96],
    ] {
        let mut bad = b.clone();
        bad.certificate.aggregate_signature = signature;
        assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    }
}
#[test]
fn tampered_paths_payloads_and_deadlines_fail() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(false);
    let view = f.observation(NOW, reads(&b.certificate, false));
    let mut mutants = Vec::new();
    let mut bad = b.clone();
    bad.path[0][31] ^= 1;
    mutants.push(bad);
    let mut bad = b.clone();
    bad.path.push([0; 32]);
    mutants.push(bad);
    let mut bad = b.clone();
    bad.leaf_index = 0;
    mutants.push(bad);
    let mut bad = b.clone();
    bad.block.message_count = 4;
    mutants.push(bad);
    let mut bad = b.clone();
    let mut payload = SccpTransferPayloadV1::decode(&bad.payload).unwrap();
    payload.amount += 1;
    bad.payload = payload.encode().unwrap();
    bad.message_id = payload.message_id(&support::NETWORK).unwrap();
    mutants.push(bad);
    let mut bad = b.clone();
    bad.payload.push(0);
    mutants.push(bad);
    let mut bad = b.clone();
    bad.payload[9] ^= 1;
    mutants.push(bad);
    let mut bad = b.clone();
    bad.message_id[0] ^= 1;
    mutants.push(bad);
    let mut bad = b.clone();
    bad.deadline_ms += 1;
    mutants.push(bad);
    for bad in mutants {
        assert!(verify(&bad, &view, MessagePurposeV1::Finalize).is_err());
    }
    assert!(
        verify(
            &b,
            &f.observation(b.deadline_ms, reads(&b.certificate, false)),
            MessagePurposeV1::Finalize
        )
        .is_ok()
    );
    assert!(
        verify(
            &b,
            &f.observation(b.deadline_ms + 1, reads(&b.certificate, false)),
            MessagePurposeV1::Finalize
        )
        .is_err()
    );
}
#[test]
fn foreign_identity_destination_expiry_and_retired_checkpoint_fail() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.message(false);
    for field in 0..5 {
        let mut other = Fixture::new(DestinationFlavor::Evm);
        match field {
            0 => other.deployment.taira_network_id[0] ^= 1,
            1 => other.deployment.consensus_instance[0] ^= 1,
            2 => other.deployment.destination_word[31] ^= 1,
            3 => other.deployment.route_revision += 1,
            _ => other.deployment.network = SccpNetworkV1::BscMainnet,
        };
        assert!(
            verify(
                &b,
                &other.observation(NOW, reads(&b.certificate, false)),
                MessagePurposeV1::Finalize
            )
            .is_err()
        );
    }
    let mut bad = b.clone();
    bad.certificate.height += 1;
    assert!(
        verify(
            &bad,
            &f.observation(NOW, reads(&b.certificate, false)),
            MessagePurposeV1::Finalize
        )
        .is_err()
    );
    assert!(
        verify(
            &b,
            &f.observation(T0 + 14 * DAY + 1, reads(&b.certificate, false)),
            MessagePurposeV1::VoidExpired
        )
        .is_err()
    );
    let view = f.observation(NOW, reads(&b.certificate, true));
    let mut state = *view.committee();
    state.generation += 1;
    state.start = 151;
    state.high = 150;
    let retired = f.observation_with(NOW, state, reads(&b.certificate, true), view.pause());
    assert!(
        verify_message_bundle(
            &b,
            &b.message_id,
            &retired,
            BundleSourceV1::Checkpoint,
            MessagePurposeV1::Finalize
        )
        .is_err()
    );
    let mut historical = f.message(true);
    let view = f.observation(NOW, reads(&historical.certificate, false));
    historical.block.history_path[0][0] ^= 1;
    assert!(verify(&historical, &view, MessagePurposeV1::Finalize).is_err());
}
#[test]
fn rotation_successor_bounds_and_authenticated_generation_are_enforced() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let steps = f.rotations(2);
    let view = f.observation(
        NOW,
        steps.iter().map(|s| (s.certificate.height, None)).collect(),
    );
    let mut bad = steps.clone();
    bad[0].next_committee.pop();
    assert!(verify_rotation_steps(&bad, None, &view, 9).is_err());
    let mut bad = steps.clone();
    bad[0].next_committee[0][3] ^= 1;
    assert!(verify_rotation_steps(&bad, None, &view, 9).is_err());
    let fields = f.fields(150, 7);
    let plain = SccpRotationV1 {
        certificate: f.certificate(&fields, 7),
        next_committee: steps[0].next_committee.clone(),
    };
    assert!(verify_rotation_steps(&[plain], None, &view, 8).is_err());
    let mut gap = f.fields(150, 9);
    gap.flags |= FLAG_ROTATION;
    gap.validity_ms = DAY;
    gap.next_committee_root = f.deployment.pin_root;
    let skip = SccpRotationV1 {
        certificate: f.certificate(&gap, 7),
        next_committee: steps[0].next_committee.clone(),
    };
    assert!(verify_rotation_steps(&[skip], None, &view, 10).is_err());
    let mut invalid = gap;
    invalid.validity_ms = 0;
    assert!(SccpFinalityHeaderV1::from_fields(&invalid).is_err());
    invalid.validity_ms = 31 * DAY;
    assert!(SccpFinalityHeaderV1::from_fields(&invalid).is_err());
    invalid.validity_ms = DAY;
    invalid.generation = u64::MAX;
    assert!(SccpFinalityHeaderV1::from_fields(&invalid).is_err());
}
#[test]
fn rotation_bad_signers_breaks_and_latch_are_explicit() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let steps = f.rotations(2);
    let view = f.observation(
        NOW,
        steps.iter().map(|s| (s.certificate.height, None)).collect(),
    );
    let mut bad = steps.clone();
    bad[0].certificate.qc[112..].copy_from_slice(&3_u32.to_be_bytes());
    assert!(verify_rotation_steps(&bad, None, &view, 9).is_err());
    let mut bad = steps.clone();
    bad[0].certificate.aggregate_signature[5] ^= 1;
    assert!(verify_rotation_steps(&bad, None, &view, 9).is_err());
    assert!(verify_rotation_steps(&steps[1..], None, &view, 9).is_err());
    assert_eq!(
        verify_rotation_steps(&steps[..1], Some(151), &view, 9),
        Err(RotationChainError::ChainTooShort {
            reached: 8,
            target: 9,
            first_uncertified_handoff: Some(151)
        })
    );
    let conflict = f.observation(NOW, BTreeMap::from([(150, Some([0x99; 32]))]));
    let stopped = verify_rotation_steps(&steps, None, &conflict, 9).unwrap();
    assert_eq!(stopped.stopped(), Some(StopReasonV1::Latch));
    assert_eq!(stopped.checkpoints().len(), 1);
    assert!(stopped.final_observation().committee().equivocated);
    assert_eq!(stopped.final_observation().committee().generation, 7);
}
#[test]
fn a_lagging_destination_replays_seventeen_generations_in_two_native_calls() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let steps = f.rotations(17);
    let view = f.observation(
        NOW,
        steps.iter().map(|s| (s.certificate.height, None)).collect(),
    );
    let plan = verify_rotation_steps(&steps, None, &view, 24).unwrap();
    assert_eq!(
        plan.batches().map(<[_]>::len).collect::<Vec<_>>(),
        vec![16, 1]
    );
    assert_eq!(submit_checkpoints_calldata(&plan).unwrap().len(), 2);
    assert_eq!(plan.final_observation().committee().generation, 24);
    assert_eq!(plan.final_observation().committee().start, 167);
    assert_eq!(plan.stopped(), None);
}
#[test]
fn control_bundles_reject_foreign_route_path_effect_and_stale_nonce() {
    let f = Fixture::new(DestinationFlavor::Evm);
    let b = f.control(false, true, 0);
    let view = f.observation(NOW, reads(&b.certificate, false));
    for which in 0..7 {
        let mut bad = b.clone();
        match which {
            0 => bad.network = SccpNetworkV1::BscMainnet,
            1 => bad.revision += 1,
            2 => bad.path[0][0] ^= 1,
            3 => bad.certificate_id[0] ^= 1,
            4 => bad.effect_hash[0] ^= 1,
            5 => bad.fast_pause_until_ms = NOW + 1,
            _ => bad.track = 2,
        };
        assert!(verify_control_bundle(&bad, &view, BundleSourceV1::Inline).is_err());
    }
    let verified = verify_control_bundle(&b, &view, BundleSourceV1::Inline).unwrap();
    let stale = f.observation_with(
        NOW,
        *view.committee(),
        reads(&b.certificate, false),
        verified.after(),
    );
    assert_eq!(
        verify_control_bundle(&b, &stale, BundleSourceV1::Inline),
        Err(BundleError::Preflight(PreflightError::Destination(
            DestinationError::StaleControl
        )))
    );
}

// ---------------------------------------------------------------------------------------------
// EIP-1559
// ---------------------------------------------------------------------------------------------

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
    let key = EvmSigningKey::from_secret(fixture_secret(0)).expect("fixture key 0");
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
    let f = Fixture::new(DestinationFlavor::Evm);
    let bundle = f.message(false);
    let observation = f.observation(NOW, reads(&bundle.certificate, false));
    let verified = verify(&bundle, &observation, MessagePurposeV1::Finalize).expect("verifies");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("relayer.key");
    std::fs::write(&path, format!("0x{}\n", hex::encode(fixture_secret(3)))).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    let key = EvmSigningKey::load(&path).expect("owner-only key file");
    let transaction = Eip1559TransactionV1::contract_call(
        f.deployment.network,
        f.deployment.destination_word[12..]
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
    assert_eq!(
        decoded.transaction.data,
        finalize_calldata(&verified).expect("exact verified calldata")
    );
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

#[test]
fn native_rust_fixture_calls_keep_all_exact_calldata_assertions() {
    use iroha_sccp::{
        api::{SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1},
        v1::{
            destination::{CheckpointObservationsV1, DeploymentV1, Destination},
            finality::checkpoint_id,
        },
    };
    use norito::json::Value;
    fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
        v.get(key).unwrap_or_else(|| panic!("field {key}"))
    }
    fn word(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    }
    fn fixed<const N: usize>(v: &Value) -> [u8; N] {
        word(v).try_into().unwrap()
    }
    fn num(v: &Value, key: &str) -> u64 {
        field(v, key).as_u64().unwrap()
    }
    fn boolean(v: &Value, key: &str) -> bool {
        field(v, key).as_bool().unwrap()
    }
    fn array(v: &Value, key: &str) -> Vec<[u8; 32]> {
        field(v, key)
            .as_array()
            .unwrap()
            .iter()
            .map(fixed)
            .collect()
    }
    fn certificate(row: &Value) -> SccpCertificateV1 {
        let evm = field(row, "evm");
        let header = fixed(field(evm, "header"));
        SccpCertificateV1 {
            height: SccpFinalityHeaderV1::parse(&header).unwrap().height(),
            qc: fixed(field(evm, "qc")),
            aggregate_signature: fixed(field(field(row, "ton"), "signature")),
            header,
            committee: word(field(evm, "committee"))
                .chunks_exact(48)
                .map(|key| key.try_into().unwrap())
                .collect(),
        }
    }
    fn block(v: &Value) -> SccpBlockRefV1 {
        SccpBlockRefV1 {
            height: num(v, "height"),
            sccp_root: fixed(field(v, "sccpRoot")),
            message_count: u32::try_from(num(v, "messageCount")).unwrap(),
            history_index: num(v, "historyIndex"),
            history_path: array(v, "historyPath"),
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp/evm_calldata_v1.json");
    let fixture: Value = norito::json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let pool = field(&fixture, "certificates").as_object().unwrap();
    let certificates: BTreeMap<_, _> = pool
        .iter()
        .map(|(id, row)| (id.as_str(), certificate(row)))
        .collect();
    let mut count = 0;
    for call in field(&fixture, "calls").as_array().unwrap() {
        let function = field(call, "function").as_str().unwrap();
        let expected = word(field(call, "calldata"));
        if function == "transferToTaira" {
            let decoded = evm_abi::TransferToTairaCallV1::decode(&expected).unwrap();
            assert_eq!(
                transfer_to_taira_calldata(
                    &decoded.taira_recipient,
                    decoded.token_amount,
                    decoded.expected_nonce
                )
                .unwrap(),
                expected
            );
            count += 1;
            continue;
        }
        let scenario = field(call, "scenario");
        let dep = field(scenario, "deployment");
        let pin = field(dep, "pin");
        assert_eq!(field(dep, "network").as_str(), Some("ethereum-mainnet"));
        let deployment = DeploymentV1 {
            flavor: DestinationFlavor::Evm,
            taira_network_id: fixed(field(dep, "taira_network_id")),
            consensus_instance: fixed(field(dep, "consensus_instance")),
            network: SccpNetworkV1::EthereumMainnet,
            destination_word: fixed(field(dep, "destination_word")),
            route_revision: u32::try_from(num(dep, "route_revision")).unwrap(),
            max_wrapped_supply: field(dep, "max_wrapped_supply")
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            pin_generation: num(pin, "generation"),
            pin_root: fixed(field(pin, "committee_root")),
            pin_start_height: num(pin, "start_height"),
            pin_until_ms: num(pin, "until_ms"),
            pin_keys: None,
        };
        let mut destination = Destination::new(deployment).unwrap();
        let steps = field(scenario, "steps").as_array().unwrap();
        // Establish every checkpoint/generation by actual native verification from the fixture's
        // independent deployment pin. Never import offered state_after or an offered root as pin.
        for prefix in &steps[..steps.len() - 1] {
            assert_eq!(field(prefix, "call").as_str(), Some("submitCheckpoints"));
            let certs: Vec<_> = field(prefix, "certificates")
                .as_array()
                .unwrap()
                .iter()
                .map(|id| {
                    certificates[id.as_str().unwrap()]
                        .to_destination_certificate()
                        .unwrap()
                })
                .collect();
            destination
                .submit_checkpoints(&certs, &[], num(prefix, "now_ms"))
                .unwrap();
        }
        let step = steps.last().unwrap();
        let now = num(step, "now_ms");
        let reads = certificates
            .values()
            .map(|cert| {
                (
                    cert.height,
                    destination.state().checkpoints.get(&cert.height).copied(),
                )
            })
            .collect();
        let observation = DestinationObservationV1::new(
            destination.deployment().clone(),
            destination.state().committee,
            None,
            CheckpointObservationsV1::Evm(reads),
            destination.pause_state(now),
            now,
        )
        .unwrap();
        let actual = match function {
            "submitCheckpoints" => {
                let ids = field(step, "certificates").as_array().unwrap();
                let mut rotations = Vec::new();
                for id in ids {
                    let cert = certificates[id.as_str().unwrap()].clone();
                    let header = SccpFinalityHeaderV1::parse(&cert.header).unwrap();
                    let next = field(&fixture, "committees")
                        .as_object()
                        .unwrap()
                        .values()
                        .find(|committee| {
                            fixed::<32>(field(committee, "root")) == header.next_committee_root()
                        })
                        .expect("successor committed root");
                    rotations.push(SccpRotationV1 {
                        certificate: cert,
                        next_committee: field(next, "keys")
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(fixed)
                            .collect(),
                    });
                }
                let target =
                    observation.committee().generation + u64::try_from(rotations.len()).unwrap();
                let plan = verify_rotation_steps(&rotations, None, &observation, target).unwrap();
                assert_eq!(plan.stopped(), None);
                let calls = submit_checkpoints_calldata(&plan).unwrap();
                assert_eq!(calls.len(), 1);
                calls[0].clone()
            }
            "voidFrozen" => void_frozen_calldata(
                field(step, "firstNonce").as_str().unwrap().parse().unwrap(),
                num(step, "count"),
            )
            .unwrap(),
            _ => {
                let (cert, source) = if let Some(id) = step.get("certificate") {
                    (
                        certificates[id.as_str().unwrap()].clone(),
                        BundleSourceV1::Inline,
                    )
                } else {
                    let raw = word(field(field(step, "checkpoint"), "header"));
                    let cert = certificates
                        .values()
                        .find(|cert| cert.header.as_slice() == raw)
                        .unwrap()
                        .clone();
                    assert_eq!(
                        observation.checkpoint(cert.height).unwrap(),
                        Some(checkpoint_id(&cert.header))
                    );
                    (cert, BundleSourceV1::Checkpoint)
                };
                let proof = field(step, "proof");
                if function.starts_with("applyControl") {
                    let b = SccpControlProofBundleV1 {
                        network: observation.deployment().network,
                        revision: observation.deployment().route_revision,
                        control_nonce: num(proof, "controlNonce"),
                        track: u8::try_from(num(proof, "track")).unwrap(),
                        parliament_paused: boolean(proof, "parliamentPaused"),
                        fast_pause_until_ms: num(proof, "fastPauseUntilMs"),
                        certificate_id: fixed(field(proof, "certificateId")),
                        effect_hash: fixed(field(proof, "effectHash")),
                        leaf_index: u32::try_from(num(proof, "leafIndex")).unwrap(),
                        path: array(proof, "path"),
                        block: block(field(proof, "block")),
                        certificate: cert,
                    };
                    let verified = verify_control_bundle(&b, &observation, source).unwrap();
                    assert_eq!(
                        verified.finalize_allowed_after_apply(),
                        !verified.after().effective
                    );
                    apply_control_calldata(&verified).unwrap()
                } else {
                    let payload = word(field(proof, "payload"));
                    let decoded = SccpTransferPayloadV1::decode(&payload).unwrap();
                    let b = SccpMessageProofBundleV1 {
                        message_id: decoded
                            .message_id(&observation.deployment().taira_network_id)
                            .unwrap(),
                        payload,
                        deadline_ms: decoded.deadline_ms,
                        leaf_index: u32::try_from(num(proof, "leafIndex")).unwrap(),
                        path: array(proof, "path"),
                        block: block(field(proof, "block")),
                        certificate: cert,
                    };
                    let purpose = if function.starts_with("void") {
                        MessagePurposeV1::VoidExpired
                    } else {
                        MessagePurposeV1::Finalize
                    };
                    let verified =
                        verify_message_bundle(&b, &b.message_id, &observation, source, purpose)
                            .unwrap();
                    assert_eq!(verified.nonce(), decoded.nonce);
                    assert_eq!(verified.deadline_ms(), decoded.deadline_ms);
                    if purpose == MessagePurposeV1::Finalize {
                        assert_eq!(
                            verified.message_id(),
                            fixed(field(field(step, "expected"), "return"))
                        );
                        finalize_calldata(&verified).unwrap()
                    } else {
                        assert_eq!(verified.nonce(), num(step, "nonce"));
                        void_expired_calldata(&verified).unwrap()
                    }
                }
            }
        };
        assert_eq!(
            actual,
            expected,
            "native golden {}",
            field(call, "label").as_str().unwrap()
        );
        count += 1;
    }
    assert_eq!(count, 9, "all native golden calls remain covered");
}
