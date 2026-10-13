//! Genuine native quorum and exact input/output membership controls; outputs are synthetic.

use super::*;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    ValidationFail,
    block::{SignedBlock, execution_output::ExecutionOutputV1},
    query::CommittedTransaction,
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
        world_state_value_hash_v1,
    },
    testing::native_finality::NativeFinalityFixture,
    transaction::error::TransactionRejectionReason,
};
use iroha_torii_shared::PipelineTransactionStatus;

fn snapshot() -> WorldStateSnapshotV1 {
    WorldStateSnapshotV1 {
        schema_hash: Hash::new(b"original receipt schema"),
        entries: vec![WorldStateSnapshotEntryV1 {
            field_id: "world.sccp_parameters".into(),
            kind: WorldStateElementKindV1::Cell,
            key_hash: None,
            value_hash: world_state_value_hash_v1(
                &None::<iroha_data_model::sccp::params::SccpParametersV1>,
            )
            .unwrap(),
        }],
    }
}

fn details(block: &SignedBlock) -> PipelineTransactionDetailsResponse {
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[index as usize].clone();
    PipelineTransactionDetailsResponse {
        hash: entrypoint.hash().to_string(),
        transaction: CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: entrypoint.hash(),
            entrypoint_proof: block.network_input_proof(0).unwrap(),
            entrypoint,
            output_hash: HashOf::new(&output),
            output_proof: block.output_proof(index).unwrap(),
            output,
        },
    }
}

fn status(
    transaction: &SignedTransaction,
    height: u64,
    kind: &str,
) -> PipelineTransactionStatusResponse {
    PipelineTransactionStatusResponse::new(
        transaction.hash().to_string(),
        PipelineTransactionStatus {
            kind: kind.into(),
            block_height: Some(height),
        },
        "global".into(),
        "state".into(),
    )
}

fn certified(
    rejected: bool,
) -> (
    NativeFinalityFixture,
    AuthenticatedOrigin,
    SignedTransaction,
    SumeragiFinalityProof,
    PipelineTransactionDetailsResponse,
) {
    let mut native = NativeFinalityFixture::start("sccp-receipt-fixture");
    let mut block = native.block_with_submitted_work(native.next_header());
    if rejected {
        NativeFinalityFixture::install_network_results(
            &mut block,
            vec![Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("fixture rejection".into()),
            ))],
        );
    }
    let snapshot = snapshot();
    let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
    let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
    let details = details(&block);
    let TransactionEntrypoint::External(transaction) = details.transaction.entrypoint() else {
        panic!("external fixture")
    };
    let transaction = transaction.clone();
    let original = super::super::origin::test_cut(&native, &snapshot, &proof);
    (native, original, transaction, proof, details)
}

#[test]
fn native_receipt_derives_success_and_rejection_from_exact_certified_execution() {
    for rejected in [false, true] {
        let (_, original, tx, proof, details) = certified(rejected);
        // Even an endpoint's opposite status label cannot substitute the certified output.
        let candidate = status(
            &tx,
            proof.height(),
            if rejected { "Applied" } else { "Rejected" },
        );
        let outcome = verify_receipt(&original, &tx, &candidate, &proof, &details).unwrap();
        assert_eq!(
            outcome.outcome,
            if rejected {
                SccpStepOutcomeKindV1::Failed
            } else {
                SccpStepOutcomeKindV1::Confirmed
            }
        );
        assert_eq!(outcome.transaction, tx.hash().as_ref());
        assert_eq!(outcome.evidence.len(), 4);
        let retained: SumeragiFinalityProof =
            norito::json::from_slice(&outcome.evidence[2].bytes).unwrap();
        assert_eq!(retained, proof);
        let cut: norito::json::Value =
            norito::json::from_slice(&outcome.evidence[0].bytes).unwrap();
        assert_eq!(cut, original.receipt_cut());
    }
}

#[test]
fn native_receipt_rejects_substituted_envelope_output_proof_and_unretained_height() {
    let (mut native, original, tx, proof, original_details) = certified(false);
    let candidate = status(&tx, proof.height(), "Applied");
    let later = native.block_with_submitted_work(native.next_header());
    let later_proof = native.certify_with_world_root(later, snapshot().root().unwrap());
    let later_block =
        iroha_data_model::block::decode_framed_signed_block(&later_proof.block_wire).unwrap();
    let mut substituted = details(&later_block);
    substituted.hash = original_details.hash.clone();
    assert!(
        verify_receipt(&original, &tx, &candidate, &proof, &substituted).is_err(),
        "a genuine alternate signed transaction cannot retire the retained envelope"
    );
    let mut forged = original_details.clone();
    let ExecutionOutputV1::Network(output) = &mut forged.transaction.output else {
        panic!("network output")
    };
    output.result = Err(TransactionRejectionReason::Validation(
        ValidationFail::NotPermitted("forged rejection".into()),
    ))
    .into();
    assert!(
        verify_receipt(&original, &tx, &candidate, &proof, &forged).is_err(),
        "a forged failure cannot authorize retry"
    );
    let mut bad_proof = proof.clone();
    *bad_proof.block_wire.last_mut().unwrap() ^= 1;
    assert!(verify_receipt(&original, &tx, &candidate, &bad_proof, &original_details).is_err());
    assert!(
        original.verify_retained_block(&later_proof).is_err(),
        "endpoint tip cannot extend the selected original prefix"
    );
    assert!(
        candidate_height(
            original.height(),
            &tx,
            &status(&tx, later_proof.height(), "Applied")
        )
        .unwrap()
        .is_none()
    );
    let newer = super::super::origin::test_cut(&native, &snapshot(), &later_proof);
    assert!(
        verify_receipt(&newer, &tx, &candidate, &proof, &original_details).is_ok(),
        "a later independently selected cut retains the original receipt"
    );
}

#[test]
fn raw_expiry_missing_height_and_foreign_status_never_retire_work() {
    let (_, original, tx, proof, _) = certified(false);
    for kind in ["Expired", "Queued", "Approved", "Committed"] {
        assert!(
            candidate_height(original.height(), &tx, &status(&tx, proof.height(), kind))
                .unwrap()
                .is_none()
        );
    }
    for height in [None, Some(0), Some(1), Some(original.height() + 1)] {
        let mut candidate = status(&tx, proof.height(), "Applied");
        candidate.status.block_height = height;
        assert!(
            candidate_height(original.height(), &tx, &candidate)
                .unwrap()
                .is_none()
        );
    }
    let mut candidate = status(&tx, proof.height(), "Applied");
    candidate.scope = "local".into();
    assert!(candidate_height(original.height(), &tx, &candidate).is_err());
    candidate.scope = "global".into();
    candidate.hash = Hash::new(b"another original transaction").to_string();
    assert!(candidate_height(original.height(), &tx, &candidate).is_err());
}

#[test]
fn observe_leaves_a_transport_reported_expiry_pending() {
    use std::io::{Read as _, Write as _};
    let (_, original, tx, proof, _) = certified(false);
    let response = norito::json::to_vec(&status(&tx, proof.height(), "Expired")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = crate::fallback_config();
    config.torii_api_url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    config.network_id = *tx.network_id().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0 && request.len() + read <= 16 * 1024);
            request.extend_from_slice(&chunk[..read]);
        }
        let request = std::str::from_utf8(&request).unwrap();
        assert!(request.starts_with("GET /v1/pipeline/transactions/status?"));
        assert!(request.contains("scope=global"));
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
        stream.write_all(&response).unwrap();
    });
    let client = Client::builder(config).build().unwrap();
    let outcome = observe(&client, &original, &tx);
    server.join().unwrap();
    assert!(
        outcome.unwrap().is_none(),
        "an HTTP expiry response is not native execution authority"
    );
}
