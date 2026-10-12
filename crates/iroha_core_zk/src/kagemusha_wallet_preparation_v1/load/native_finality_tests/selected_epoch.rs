//! Selected-epoch Load gate checks with actual native BLS and synthetic event execution.

use super::*;
use iroha_data_model::sumeragi_finality::{
    CertifiedResultScope, CertifiedResultV1, SumeragiCommitCheckpointV1, result_of_preimage,
};

fn successor_epoch_source() -> (NativeLoad, SumeragiCommitCheckpointV1) {
    let (fixture, chain) =
        NativeFinalityFixture::short_npos_boundary_chain_with_explicit_parameters(4);
    let native = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    let certified = fixture.verifier();
    let boundary = SumeragiCommitCertificateV1::from_verified(
        &certified.verify_retained_decision(&chain[2]).unwrap(),
    )
    .unwrap();
    let mut reader = SumeragiCommitVerifierV1::new(&native).unwrap();
    let checkpoint = reader.verify_epoch_boundary(&boundary).unwrap();
    assert_eq!(checkpoint.selected_epoch().authorization.epoch, 1);

    let receipt = KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [3; 32],
        request_id: [4; 32],
        ordinal: 0,
        amount: 101,
        online_charge: 7,
        charge_quote: [5; 32],
        transaction_hash: [6; 32],
        block_height: 4,
        payer_account_digest: [7; 32],
    };
    let unrelated = KagemushaWalletLoadReceiptV1 {
        request_id: [8; 32],
        ..receipt
    };
    let events = [unrelated, receipt].map(|value| {
        EventBox::Data(
            DataEvent::KagemushaLoadCommitted(
                KagemushaLoadCommittedV1::from_receipt(&value).unwrap(),
            )
            .into(),
        )
    });
    let events: MerkleTree<EventBox> = events.iter().map(HashOf::new).collect();
    let mut certificate = SumeragiCommitCertificateV1::from_verified(
        &certified.verify_retained_decision(&chain[3]).unwrap(),
    )
    .unwrap();
    // Retain the genuine H4 header/epoch/schedule and sign a synthetic event result with
    // the actual fixture quorum. This is native BLS gate evidence, not World execution.
    let (finality_header, mut result) = CertifiedResultV1::decode(
        &certificate.result_preimage,
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap()
    .into_parts();
    result.execution.event_commitment = events.commitment();
    result.validate().unwrap();
    certificate.result_preimage =
        CertifiedResultV1::from_parts_unvalidated(finality_header, result)
            .preimage()
            .unwrap();
    let mut qc: Qc = norito::decode_canonical(&certificate.commit_qc).unwrap();
    qc.result = result_of_preimage(&certificate.result_preimage).unwrap();
    resign_fixture_quorum(&mut qc);
    certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate,
        event_proof: events.get_proof(1).unwrap(),
    };
    (
        NativeLoad {
            native,
            receipt,
            evidence,
            events,
        },
        checkpoint,
    )
}

fn resign_fixture_quorum(qc: &mut Qc) {
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| {
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal)
        })
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1, 2]).unwrap();
    let shares: Vec<_> = keys[..3]
        .iter()
        .map(|key| {
            iroha_crypto::bls::consensus::sign_preimage(key.private_key(), &qc.preimage()).unwrap()
        })
        .collect();
    qc.agg_sig = iroha_sumeragi::types::AggregateSignature(
        iroha_crypto::bls::consensus::aggregate(&shares).unwrap(),
    );
}

#[test]
fn requires_selected_epoch_and_preserves_authenticated_state_on_failure() {
    let (source, checkpoint) = successor_epoch_source();
    assert_eq!(source.evidence.certificate.height().unwrap(), 4);
    assert_eq!(source.evidence.certificate.epoch_id().unwrap(), 1);
    assert!(matches!(
        source.check(&source.receipt, &source.evidence),
        Err(state::Error::Proof(_))
    ));

    // Select only the exact checkpoint just exported by the authenticated H3 boundary.
    // This tests the gate's selected input, not wallet archive/manifest persistence.
    let selected_bytes = checkpoint.encode_canonical().unwrap();
    let selected = SumeragiCommitCheckpointV1::decode_canonical(&selected_bytes).unwrap();
    let mut reader =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&selected, &source.native).unwrap();
    let receipt = source.receipt.to_canonical_bytes().unwrap();
    let evidence = source.evidence.to_canonical_bytes().unwrap();
    let mut wrong_event = source.evidence.clone();
    wrong_event.event_proof = source.events.get_proof(0).unwrap();
    assert!(matches!(
        super::super::authenticate_originals(
            &mut reader,
            &receipt,
            &wrong_event.to_canonical_bytes().unwrap()
        ),
        Err(state::Error::Proof(_))
    ));
    assert_eq!(reader.export_epoch_checkpoint(1).unwrap(), selected);
    let authenticated =
        super::super::authenticate_originals(&mut reader, &receipt, &evidence).unwrap();
    assert_eq!(authenticated.0, source.receipt);
    assert_eq!(
        authenticated.1,
        [
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadReceipt,
                bytes: receipt.clone(),
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadFinality,
                bytes: evidence.clone(),
            },
        ]
    );
    assert_eq!(
        super::super::authenticate_originals(&mut reader, &receipt, &evidence).unwrap(),
        authenticated
    );
    assert_eq!(reader.export_epoch_checkpoint(1).unwrap(), selected);
}

#[test]
fn load_resource_refusal_keeps_selected_epoch_and_retries_after_scope_retirement() {
    let (source, selected) = successor_epoch_source();
    let mut reader =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&selected, &source.native).unwrap();
    let receipt = source.receipt.to_canonical_bytes().unwrap();
    let evidence = source.evidence.to_canonical_bytes().unwrap();
    for allocation in [0, 64] {
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
        let error = norito::with_decode_limits_scope(limits, || {
            super::super::authenticate_originals(&mut reader, &receipt, &evidence)
        })
        .unwrap_err();
        assert!(matches!(error, state::Error::DecodeResource(ref cause)
            if cause.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit));
        assert_eq!(reader.export_epoch_checkpoint(1).unwrap(), selected);
    }
    let authenticated =
        super::super::authenticate_originals(&mut reader, &receipt, &evidence).unwrap();
    assert_eq!(authenticated.0, source.receipt);
    assert_eq!(reader.export_epoch_checkpoint(1).unwrap(), selected);
}

#[test]
fn rejects_an_appended_certificate_as_a_framing_violation() {
    let source = NativeLoad::new("wallet-load-gate-appended-certificate");
    source.check(&source.receipt, &source.evidence).unwrap();
    let receipt = source.receipt.to_canonical_bytes().unwrap();
    let mut appended = source.evidence.to_canonical_bytes().unwrap();
    appended.extend_from_slice(&source.evidence.certificate.to_canonical_bytes().unwrap());
    // A second frame cannot be interpreted as a list entry in the singular envelope.
    // This is canonical framing refusal, not a duplicate-certificate semantic rule.
    assert!(matches!(
        authenticate_originals(&source.native, &receipt, &appended),
        Err(state::Error::Invalid("Load original binding"))
    ));
}
