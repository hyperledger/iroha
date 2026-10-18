//! Genuine alternate-quorum certificates over explicitly synthetic Load event results.
//! This tests finality admission, not World execution or monetary qualification.

use super::*;

#[test]
fn live_load_finality_accepts_alternate_quorum_only_for_the_same_authenticated_decision() {
    use iroha_crypto::{MerkleProof, MerkleTree, bls::consensus};
    use iroha_data_model::{
        events::{
            EventBox,
            data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
        },
        sumeragi_finality::SumeragiCommitCertificateV1,
        testing::native_finality::NativeFinalityFixture,
    };
    use iroha_sumeragi::{
        message::Qc,
        types::{AggregateSignature, Bitmap},
    };

    let parent = NativeFinalityFixture::start("kagemusha-funding-witness-agreement");
    let work = parent.block_with_submitted_work(parent.next_header());
    let transaction = work.external_transactions().next().unwrap();
    // The fixture signs supplied event results; no ledger Load is executed here.
    let receipt = KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [3; 32],
        request_id: [4; 32],
        ordinal: 0,
        amount: 100,
        online_charge: 0,
        charge_quote: [0; 32],
        transaction_hash: *transaction.hash().as_ref(),
        block_height: work.header().height().get(),
        payer_account_digest: kagemusha_wallet_account_digest_v1(transaction.authority()).unwrap(),
    };
    let event = EventBox::Data(
        DataEvent::from(KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap()).into(),
    );
    let events = [event.clone()];
    let tree: MerkleTree<EventBox> = events.iter().map(HashOf::new).collect();
    let mut selected = parent.clone();
    let proof = selected.certify_with_events(work.clone(), &events);
    let verifier = selected.verifier();
    let block = verifier.verify_retained_decision(&proof).unwrap();
    let anchor = parent.verifier();
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1::from_verified(&block).unwrap(),
        event_proof: tree.get_proof(0).unwrap(),
    };
    verify_captured_load_finality(&anchor, &block, &receipt, &evidence).unwrap();

    // Use only NativeFinalityFixture's public fixed keys in its exact committee order.
    let mut keys = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    assert_eq!(proof.committee.len(), 4);
    for (key, validator) in keys.iter().zip(&proof.committee) {
        assert_eq!(key.public_key(), &validator.public_key);
    }
    let witness = |chosen: &[u32]| {
        let mut candidate = evidence.clone();
        let mut qc: Qc = canonical(&candidate.certificate.commit_qc).unwrap();
        qc.view += 1;
        qc.signers = Bitmap::from_indices(keys.len(), chosen.iter().copied()).unwrap();
        let shares = chosen
            .iter()
            .map(|index| {
                consensus::sign_preimage(keys[*index as usize].private_key(), &qc.preimage())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        qc.agg_sig = AggregateSignature(consensus::aggregate(&shares).unwrap());
        candidate.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
        candidate
    };
    let alternate = witness(&[1, 2, 3]);
    assert_ne!(
        evidence.certificate.commit_qc,
        alternate.certificate.commit_qc
    );
    assert_eq!(
        evidence.certificate.consensus_header,
        alternate.certificate.consensus_header
    );
    assert_eq!(
        evidence.certificate.result_preimage,
        alternate.certificate.result_preimage
    );
    alternate.verify(&anchor, &receipt).unwrap();
    verify_captured_load_finality(&anchor, &block, &receipt, &alternate).unwrap();

    for invalid in [witness(&[1, 2]), witness(&[0, 1, 2, 3])] {
        assert!(invalid.verify(&anchor, &receipt).is_err());
        assert!(verify_captured_load_finality(&anchor, &block, &receipt, &invalid).is_err());
    }
    let mut unsigned = alternate.clone();
    let mut qc: Qc = canonical(&unsigned.certificate.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    unsigned.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(verify_captured_load_finality(&anchor, &block, &receipt, &unsigned).is_err());

    // A different, independently valid header with the same receipt event is still
    // another decision. Compact verification succeeds, selected-block agreement fails.
    let mut header_branch = parent.clone();
    let mut header = parent.next_header();
    header.creation_time_ms += 1;
    let changed =
        header_branch.certify_with_events(parent.block_with_submitted_work(header), &events);
    let changed = header_branch
        .verifier()
        .verify_retained_decision(&changed)
        .unwrap();
    let mut changed_header = evidence.clone();
    changed_header.certificate = SumeragiCommitCertificateV1::from_verified(&changed).unwrap();
    changed_header.verify(&anchor, &receipt).unwrap();
    assert!(verify_captured_load_finality(&anchor, &block, &receipt, &changed_header).is_err());

    // A different authenticated event result can still contain the same receipt.
    // Its valid counted event proof must not substitute for the selected result.
    let mut extra_receipt = receipt;
    extra_receipt.amount += 1;
    let extra = EventBox::Data(
        DataEvent::from(KagemushaLoadCommittedV1::from_receipt(&extra_receipt).unwrap()).into(),
    );
    let changed_events = [event, extra];
    let changed_tree: MerkleTree<EventBox> = changed_events.iter().map(HashOf::new).collect();
    let mut result_branch = parent;
    let changed = result_branch.certify_with_events(work, &changed_events);
    let changed = result_branch
        .verifier()
        .verify_retained_decision(&changed)
        .unwrap();
    let mut changed_result = evidence.clone();
    changed_result.certificate = SumeragiCommitCertificateV1::from_verified(&changed).unwrap();
    changed_result.event_proof = changed_tree.get_proof(0).unwrap();
    changed_result.verify(&anchor, &receipt).unwrap();
    assert_eq!(
        evidence.certificate.consensus_header,
        changed_result.certificate.consensus_header
    );
    assert_ne!(
        evidence.certificate.result_preimage,
        changed_result.certificate.result_preimage
    );
    assert!(verify_captured_load_finality(&anchor, &block, &receipt, &changed_result).is_err());

    let mut wrong_receipt = receipt;
    wrong_receipt.amount += 1;
    assert!(verify_captured_load_finality(&anchor, &block, &wrong_receipt, &evidence).is_err());
    let mut wrong_path = evidence;
    wrong_path.event_proof = MerkleProof::from_audit_path(1, vec![]);
    assert!(verify_captured_load_finality(&anchor, &block, &receipt, &wrong_path).is_err());
}
