//! Shared first-Load receipt capture and independent native BLS/event admission.
//! The captured execution identities are synthetic component inputs; its native
//! certificate and receipt are checked without relabeling their bytes.

use iroha_data_model::sumeragi_finality::{
    FinalityValidator, SumeragiCommitCertificateV1, SumeragiCommitVerifierV1,
    SumeragiFinalityVerifier, authenticated_genesis,
};
use std::fs;

const CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/kagemusha/ordinary_first_load_receipt_v1.json"
);
/// Read the exact separately generated first-Load capture with a finite extent.
pub(crate) fn first_capture() -> String {
    let metadata =
        fs::symlink_metadata(CAPTURE).expect("exact separately generated first-Load capture");
    assert!(metadata.file_type().is_file() && metadata.len() <= 1 << 20);
    fs::read_to_string(CAPTURE).unwrap()
}

/// Authenticate the original certificate and exact receipt event from signed genesis.
/// This supplies fixture DATA after native BLS admission, never a catalog grant.
pub(crate) fn verified_receipt(capture: &str) -> [u8; 282] {
    let json: norito::json::Value = norito::json::from_str(capture).unwrap();
    let raw = |name: &str| {
        let text = json[name].as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let genesis =
        iroha_data_model::block::decode_framed_signed_block(&raw("signed_genesis_wire_hex"))
            .unwrap();
    let epoch = authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let roster = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let native =
        SumeragiFinalityVerifier::new(&genesis, json["chain_id"].as_str().unwrap(), roster)
            .unwrap();
    let certificate = SumeragiCommitCertificateV1 {
        consensus_header: raw("consensus_header_frame_hex"),
        commit_qc: raw("commit_qc_frame_hex"),
        result_preimage: raw("result_preimage_hex"),
    };
    let mut verifier = SumeragiCommitVerifierV1::new(&native).unwrap();
    let verified = verifier.verify(&certificate).unwrap();
    assert_eq!(verified.height(), 2);
    let receipt =
        iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1::decode_canonical(
            &raw("receipt_frame_hex"),
        )
        .unwrap();
    let event =
        iroha_data_model::events::data::kagemusha::KagemushaLoadCommittedV1::from_receipt(&receipt)
            .unwrap();
    let boxed = iroha_data_model::events::EventBox::Data(
        iroha_data_model::events::data::DataEvent::KagemushaLoadCommitted(event).into(),
    );
    let path = iroha_crypto::MerkleProof::from_audit_path(0, vec![]);
    assert!(path.verify(
        &iroha_crypto::HashOf::new(&boxed),
        verified.execution().event_commitment.as_ref().unwrap()
    ));
    let transcript = receipt.transcript().unwrap();
    assert_eq!(transcript.as_slice(), raw("receipt_transcript_hex"));
    assert_eq!(receipt.block_height, verified.height());
    transcript
}
