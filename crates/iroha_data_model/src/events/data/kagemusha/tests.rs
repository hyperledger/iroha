//! Canonical Load events and independently signed native finality captures.

use super::*;
use crate::{
    account::AccountId,
    events::{
        EventBox,
        data::{DataEvent, DataEventFilter},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

fn payer() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn receipt() -> KagemushaWalletLoadReceiptV1 {
    KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [3; 32],
        request_id: [4; 32],
        ordinal: 7,
        amount: 123,
        online_charge: 0,
        charge_quote: [0; 32],
        transaction_hash: [5; 32],
        block_height: 2,
        payer_account_digest: crate::kagemusha::kagemusha_wallet_account_digest_v1(&payer())
            .unwrap(),
    }
}

#[test]
fn event_binds_complete_validated_receipt_and_exact_filter() {
    let receipt = receipt();
    let event = KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap();
    assert_eq!(event.receipt_digest, receipt.receipt_digest().unwrap());
    let data = DataEvent::from(event);
    assert!(data.domain().is_none());
    #[cfg(feature = "transparent_api")]
    {
        use crate::events::EventFilter;

        assert!(DataEventFilter::Any.matches(&data));
        assert!(DataEventFilter::KagemushaLoadCommitted(None).matches(&data));
        assert!(DataEventFilter::KagemushaLoadCommitted(Some(event.receipt_digest)).matches(&data));
        assert!(!DataEventFilter::KagemushaLoadCommitted(Some([0; 32])).matches(&data));
    }
    let mut changed = receipt;
    changed.amount += 1;
    assert_ne!(
        KagemushaLoadCommittedV1::from_receipt(&changed).unwrap(),
        event
    );
    changed = receipt;
    changed.ordinal = u128::MAX;
    assert!(KagemushaLoadCommittedV1::from_receipt(&changed).is_err());
}

#[test]
fn event_and_envelopes_have_strict_canonical_binary_and_json_roundtrips() {
    let event = KagemushaLoadCommittedV1::from_receipt(&receipt()).unwrap();
    let bytes = norito::encode_canonical(&event).unwrap();
    assert_eq!(
        norito::decode_canonical::<KagemushaLoadCommittedV1>(&bytes).unwrap(),
        event
    );
    let json = norito::json::to_json(&event).unwrap();
    assert_eq!(
        norito::json::from_json::<KagemushaLoadCommittedV1>(&json).unwrap(),
        event
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(norito::decode_canonical::<KagemushaLoadCommittedV1>(&trailing).is_err());
    assert!(
        norito::decode_canonical::<KagemushaLoadCommittedV1>(&bytes[..bytes.len() - 1]).is_err()
    );
    assert!(
        norito::json::from_json::<KagemushaLoadCommittedV1>("{\"receipt_digest\":[]}").is_err()
    );
    let data = DataEvent::from(event);
    assert_eq!(
        norito::decode_canonical::<DataEvent>(&norito::encode_canonical(&data).unwrap()).unwrap(),
        data
    );
    let boxed = EventBox::Data(data.into());
    let boxed_bytes = norito::encode_canonical(&boxed).unwrap();
    let mut hash_preimage = Vec::new();
    norito::codec::encode_adaptive_into(&boxed, &mut hash_preimage).unwrap();
    assert_eq!(Hash::from(HashOf::new(&boxed)), Hash::new(&hash_preimage));
    assert_eq!(
        norito::decode_canonical::<EventBox>(&boxed_bytes).unwrap(),
        boxed
    );
    assert_eq!(
        norito::json::from_json::<EventBox>(&norito::json::to_json(&boxed).unwrap()).unwrap(),
        boxed
    );
    for filter in [
        DataEventFilter::KagemushaLoadCommitted(None),
        DataEventFilter::KagemushaLoadCommitted(Some(event.receipt_digest)),
    ] {
        assert_eq!(
            norito::decode_canonical::<DataEventFilter>(
                &norito::encode_canonical(&filter).unwrap()
            )
            .unwrap(),
            filter
        );
        assert_eq!(
            norito::json::from_json::<DataEventFilter>(&norito::json::to_json(&filter).unwrap())
                .unwrap(),
            filter
        );
    }
}

#[test]
#[ignore = "native capture for the independently pinned ordinary Load event fixture"]
fn print_canonical_load_event_capture() {
    println!(
        "LOAD_EVENT_CAPTURE {}",
        norito::json::to_json(&native_capture()).unwrap()
    );
    println!(
        "NPOS_SCHEDULE_CAPTURE {}",
        norito::json::to_json(&npos_schedule_capture()).unwrap()
    );
}

fn native_capture() -> norito::json::Value {
    native_capture_for("ordinary-load-receipt-v1", receipt())
}

/// Signed component fixture matching the recursive Bootstrap/first-Load tests.
/// The Result is synthetic; the genesis, transaction and four-validator QC are
/// actually signed and checked by the ordinary native finality verifier.
fn first_load_capture() -> norito::json::Value {
    let limbs = |low: u128, high: u128| {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&low.to_le_bytes());
        bytes[16..].copy_from_slice(&high.to_le_bytes());
        bytes
    };
    let mut first = receipt();
    first.scheme_id = limbs(1, 2);
    first.asset_digest = limbs(3, 4);
    first.wallet_id = limbs(5, 6);
    first.ordinal = 0;
    first.amount = 100;
    let mut capture = native_capture_for("ordinary-first-load-receipt-v1", first);
    capture.as_object_mut().unwrap().insert(
        "scope".to_owned(),
        "Genuine native genesis, transaction and four-validator CommitQC verification; synthetic execution Result, not funded World execution or finalized producer-catalog SchemeID evidence.".into(),
    );
    capture
}

#[test]
#[ignore = "native capture for the independently pinned first-Load event fixture"]
fn print_canonical_first_load_event_capture() {
    println!(
        "FIRST_LOAD_EVENT_CAPTURE {}",
        norito::json::to_json(&first_load_capture()).unwrap()
    );
}

fn native_capture_for(
    chain_label: &str,
    mut receipt: KagemushaWalletLoadReceiptV1,
) -> norito::json::Value {
    use crate::{
        block::{BlockSignatures, builder::BlockBuilder},
        isi::kagemusha_wallet::load_finality::verify_finalized_kagemusha_wallet_load_v1,
        isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
        kagemusha::KagemushaWalletLoadFinalityV1,
        sumeragi_finality::{
            ExecutionCommitment, ExecutionResultCommitment, SumeragiCommitCertificateV1,
            test_fixtures::NativeFinalityFixture,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let mut fixture = NativeFinalityFixture::start_with_explicit_parameters(chain_label);
    let header = fixture.next_header();
    let instruction = KagemushaWalletLedgerV1::new(
        receipt.scheme_id,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: receipt.wallet_id,
            asset: receipt.asset_digest,
            ordinal: receipt.ordinal,
            request_id: receipt.request_id,
            amount: receipt.amount,
            charge: None,
        },
    );
    let mut tx = TransactionBuilder::new(
        fixture.network_id(),
        payer(),
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(std::time::Duration::from_millis(
        header.creation_time_ms - 1,
    ));
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let transaction = tx
        .with_instructions([instruction.clone()])
        .sign(signer.private_key());
    receipt.transaction_hash = *transaction.hash().as_ref();
    receipt.block_height = header.height().get();
    let event = KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap();
    let data = DataEvent::from(event);
    let boxed = EventBox::Data(data.clone().into());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![])]);
    let proof = fixture.certify_with_events(block, std::slice::from_ref(&boxed));
    let decision = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let committed = crate::block::output_test_support::committed(decision.block(), 0);
    let exact = verify_finalized_kagemusha_wallet_load_v1(
        &decision,
        &committed,
        fixture.network_id(),
        fixture.chain_id(),
        0,
        &instruction,
        &payer(),
    )
    .unwrap();
    assert_eq!(exact.receipt(), &receipt);
    let tree: iroha_crypto::MerkleTree<EventBox> = [HashOf::new(&boxed)].into_iter().collect();
    let native_finality = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1::from_verified(&decision).unwrap(),
        event_proof: tree.get_proof(0).unwrap(),
    };
    native_finality
        .verify(&fixture.verifier(), &receipt)
        .unwrap();
    let native_finality_frame = native_finality.to_canonical_bytes().unwrap();
    let event_commitment = decision.execution().event_commitment.unwrap();
    let certificate = decision.block().commit_certificate().unwrap();
    let core_header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(certificate.consensus_header()).unwrap();
    let qc: iroha_sumeragi::message::Qc =
        norito::decode_canonical(certificate.commit_qc()).unwrap();
    let committee_public_keys_hex: Vec<String> = decision
        .commitment()
        .schedule
        .current
        .committee
        .iter()
        .map(|member| {
            let (algorithm, payload) = member.validator.public_key().try_to_bytes().unwrap();
            assert_eq!(algorithm, Algorithm::BlsNormal);
            assert_eq!(payload.len(), 48);
            hex::encode(payload)
        })
        .collect();
    let committee_proofs_of_possession_hex: Vec<String> = decision
        .commitment()
        .schedule
        .current
        .committee
        .iter()
        .map(|member| hex::encode(&member.proof_of_possession))
        .collect();
    let mut hash_preimage = Vec::new();
    norito::codec::encode_adaptive_into(&boxed, &mut hash_preimage).unwrap();
    norito::json!({
        "version": 1,
        "chain_id": (fixture.chain_id()),
        "signed_genesis_wire_hex": (hex::encode(fixture.genesis().encode_wire().unwrap())),
        "native_finality_frame_hex": (hex::encode(&native_finality_frame)),
        "native_finality_frame_bytes": (native_finality_frame.len()),
        "receipt_frame_hex": (hex::encode(norito::encode_canonical(&receipt).unwrap())),
        "receipt_transcript_hex": (hex::encode(receipt.transcript().unwrap())),
        "receipt_digest_hex": (hex::encode(event.receipt_digest)),
        "payer_account_digest_hex": (hex::encode(receipt.payer_account_digest)),
        "event_frame_hex": (hex::encode(norito::encode_canonical(&event).unwrap())),
        "data_event_frame_hex": (hex::encode(norito::encode_canonical(&data).unwrap())),
        "event_box_frame_hex": (hex::encode(norito::encode_canonical(&boxed).unwrap())),
        "event_box_hash_preimage_hex": (hex::encode(&hash_preimage)),
        "event_box_hash_hex": (HashOf::new(&boxed).to_string()),
        "event_codec_identity_hex": (hex::encode(norito::schema::identity::frame_hash::<KagemushaLoadCommittedV1>())),
        "result_preimage_hex": (hex::encode(decision.commitment().preimage().unwrap())),
        "result_hash_hex": (hex::encode(decision.result().0)),
        "result_height": (decision.height()),
        "result_alignment": (core::mem::align_of::<ExecutionResultCommitment>()),
        "result_codec_identity_hex": (hex::encode(norito::schema::identity::frame_hash::<ExecutionResultCommitment>())),
        "execution_commitment_frame_hex": (hex::encode(norito::encode_canonical(decision.execution()).unwrap())),
        "execution_commitment_alignment": (core::mem::align_of::<ExecutionCommitment>()),
        "event_commitment_root_hex": (hex::encode(event_commitment.root().as_ref())),
        "event_commitment_count": (event_commitment.leaf_count().get()),
        "commit_vote_preimage_hex": (hex::encode(qc.preimage())),
        "block_hash_preimage_hex": (hex::encode(iroha_sumeragi::preimage::block_hash_preimage(&core_header))),
        "consensus_block_hash_hex": (hex::encode(decision.core_hash().0)),
        "consensus_header_frame_hex": (hex::encode(certificate.consensus_header())),
        "commit_qc_frame_hex": (hex::encode(certificate.commit_qc())),
        "qc_bitmap_hex": (hex::encode(qc.signers.as_bytes())),
        "qc_aggregate_signature_hex": (hex::encode(qc.agg_sig.0)),
        "committee_public_keys_hex": (committee_public_keys_hex),
        "committee_proofs_of_possession_hex": (committee_proofs_of_possession_hex),
        "authenticated_schedule": (schedule_capture(&decision.commitment().schedule)),
    })
}

fn codec_capture<T: norito::NoritoSerialize + norito::NoritoSchema>(
    value: &T,
) -> norito::json::Value {
    let mut payload = Vec::new();
    norito::codec::encode_adaptive_into(value, &mut payload).unwrap();
    norito::json!({
        "frame_hex": (hex::encode(norito::encode_canonical(value).unwrap())),
        "payload_hex": (hex::encode(payload)),
        "codec_identity_hex": (hex::encode(norito::schema::identity::frame_hash::<T>())),
        "alignment": (core::mem::align_of::<T>()),
    })
}

fn context_capture(
    context: &crate::sumeragi::epoch::ValidatorEpochContextV1,
) -> norito::json::Value {
    let members: Vec<_> = context
        .committee
        .iter()
        .map(|member| {
            norito::json!({
                "member": (codec_capture(member)),
                "peer_id": (codec_capture(&member.validator)),
                "public_key": (codec_capture(member.validator.public_key())),
                "public_key_compressed_hex": (hex::encode(member.validator.public_key().try_to_bytes().unwrap().1)),
                "proof_of_possession_hex": (hex::encode(&member.proof_of_possession)),
            })
        })
        .collect();
    norito::json!({
        "context": (codec_capture(context)),
        "context_id_hex": (hex::encode(context.context_id().unwrap())),
        "authorization": (codec_capture(&context.authorization)),
        "authorization_id_hex": (hex::encode(context.authorization.authorization_id().unwrap())),
        "generation": (codec_capture(&context.generation())),
        "generation_id_hex": (hex::encode(context.generation().generation_id().unwrap())),
        "committee": (codec_capture(&context.committee)),
        "members": (members),
        "network_hex": (hex::encode(context.network_id.as_bytes())),
        "epoch": (context.authorization.epoch),
        "first_height": (context.authorization.first_height),
        "last_height": (context.authorization.last_height),
        "leader_seed_hex": (hex::encode(context.leader_seed)),
    })
}

fn schedule_capture(schedule: &crate::sumeragi_finality::ScheduleOutcome) -> norito::json::Value {
    use crate::sumeragi_finality::ScheduledSlot;
    let slots: Vec<_> = [&schedule.next, &schedule.after_next]
        .into_iter()
        .map(|slot| {
            let (kind, height, context_id) = match slot {
                ScheduledSlot::Ready(config) => {
                    ("ready", config.height, config.epoch.context_id().unwrap())
                }
                ScheduledSlot::PendingBoundary {
                    height,
                    predecessor_context_id,
                    ..
                } => ("pending_boundary", *height, *predecessor_context_id),
            };
            norito::json!({
                "kind": (kind),
                "height": (height),
                "context_id_hex": (hex::encode(context_id)),
                "params": (codec_capture(slot.params())),
            })
        })
        .collect();
    norito::json!({
        "height": (schedule.height),
        "current": (context_capture(&schedule.current)),
        "successor_slots": (slots),
        "boundary": (schedule.boundary.as_ref().map(|boundary| norito::json!({
            "body": (codec_capture(boundary)),
            "successor": (context_capture(&boundary.next)),
            "selection_anchor_hex": (hex::encode(boundary.selection_anchor.as_ref())),
            "predecessor_context_id_hex": (hex::encode(boundary.predecessor_context_id)),
        }))),
        // This complete-graph frame is deliberately named: R uses the compact
        // ResultWire projection, whose exact bytes are captured separately.
        "standalone_complete_graph": (codec_capture(schedule)),
    })
}

fn npos_schedule_capture() -> norito::json::Value {
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let cases: Vec<_> = [4, 31]
        .into_iter()
        .map(|seats| {
            let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(seats);
            let verifier = fixture.verifier();
            let blocks: Vec<_> = chain
                .iter()
                .map(|proof| {
                    let decision = verifier.verify_retained_decision(proof).unwrap();
                    let certificate = decision.block().commit_certificate().unwrap();
                    norito::json!({
                        "height": (decision.height()),
                        "proof_frame_hex": (hex::encode(norito::encode_canonical(proof).unwrap())),
                        "result_preimage_hex": (hex::encode(decision.commitment().preimage().unwrap())),
                        "result_hash_hex": (hex::encode(decision.result().0)),
                        "block_hash_hex": (hex::encode(decision.block().hash().as_ref())),
                        "consensus_block_hash_hex": (hex::encode(decision.core_hash().0)),
                        "consensus_header_frame_hex": (hex::encode(certificate.consensus_header())),
                        "commit_qc_frame_hex": (hex::encode(certificate.commit_qc())),
                        "schedule": (schedule_capture(&decision.commitment().schedule)),
                    })
                })
                .collect();
            norito::json!({
                "seats": (seats),
                "chain_id": (fixture.chain_id()),
                "signed_genesis_wire_hex": (hex::encode(fixture.genesis().encode_wire().unwrap())),
                "network_hex": (hex::encode(fixture.network_id().as_bytes())),
                "blocks": (blocks),
            })
        })
        .collect();
    norito::json!({
        "version": 1,
        "scope": "Genuine native QC and genesis/schedule verification; synthetic execution roots and beacon output, not World execution or threshold-beacon ceremony evidence.",
        "cases": (cases),
    })
}

fn saved_capture(name: &str, expected: &norito::json::Value) -> norito::json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha")
        .join(name);
    if std::env::var_os("IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS").is_some_and(|value| value == "1") {
        let mut json = norito::json::to_string_pretty(expected).unwrap();
        json.push('\n');
        std::fs::write(&path, json).expect("update native capture");
    }
    norito::json::from_slice(&std::fs::read(path).expect("native capture")).unwrap()
}

#[test]
fn npos_schedule_proof_bytes_match_independent_native_capture() {
    let expected = npos_schedule_capture();
    assert_eq!(
        saved_capture("ordinary_load_npos_schedule_v1.json", &expected),
        expected
    );
}

#[test]
fn canonical_receipt_and_event_proof_bytes_match_independent_native_capture() {
    let expected = native_capture();
    let saved = saved_capture("ordinary_load_receipt_v1.json", &expected);
    assert_eq!(
        saved, expected,
        "receipt/event frame, transcript, codec identity and exact typed-hash preimage must all match the pinned native capture"
    );
    let preimage = hex::decode(saved["event_box_hash_preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        Hash::new(&preimage).to_string(),
        saved["event_box_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::decode(saved["receipt_transcript_hex"].as_str().unwrap())
            .unwrap()
            .len(),
        282
    );
}

#[test]
fn first_load_receipt_and_event_match_independent_native_capture() {
    let expected = first_load_capture();
    let saved = saved_capture("ordinary_first_load_receipt_v1.json", &expected);
    assert_eq!(saved, expected);
    let bytes = hex::decode(saved["receipt_frame_hex"].as_str().unwrap()).unwrap();
    let receipt: KagemushaWalletLoadReceiptV1 = norito::decode_canonical(&bytes).unwrap();
    let limbs = |bytes: [u8; 32]| {
        [
            u128::from_le_bytes(bytes[..16].try_into().unwrap()),
            u128::from_le_bytes(bytes[16..].try_into().unwrap()),
        ]
    };
    assert_eq!(limbs(receipt.scheme_id), [1, 2]);
    assert_eq!(limbs(receipt.asset_digest), [3, 4]);
    assert_eq!(limbs(receipt.wallet_id), [5, 6]);
    assert_eq!(receipt.ordinal, 0);
    assert_eq!(receipt.amount, 100);
    assert_eq!(receipt.online_charge, 0);
    assert_eq!(receipt.block_height, 2);
    assert_eq!(
        saved["committee_public_keys_hex"].as_array().unwrap().len(),
        4
    );
    assert_eq!(
        saved["receipt_transcript_hex"].as_str().unwrap(),
        hex::encode(receipt.transcript().unwrap())
    );
    assert_eq!(
        saved["receipt_digest_hex"].as_str().unwrap(),
        hex::encode(receipt.receipt_digest().unwrap())
    );
}
