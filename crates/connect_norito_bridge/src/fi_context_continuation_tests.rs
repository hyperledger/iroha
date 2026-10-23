//! Real certified continuation cases; candidate admission alone proves no execution.
use super::*;
use crate::fi_context_verification::tests::{Fixture, ffi_fixture};
use iroha_data_model::sumeragi_finality::{
    SumeragiFinalityCheckpoint, SumeragiFinalityVerifier, verify_checkpoint_page,
};

fn selection(
    f: &Fixture,
    checkpoint: &SumeragiFinalityCheckpoint,
) -> (Vec<u8>, FiContinuationCursor) {
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        checkpoint,
        &f.request.network_id,
        &f.request.chain_id,
    )
    .unwrap();
    let wire = checkpoint.encode_canonical().unwrap();
    let cursor = FiContinuationCursor {
        sha256: sha256(&wire),
        height: tip.height(),
        context_id: *tip.context_id().as_ref(),
        block_hash: *tip.header().hash().as_ref(),
    };
    (wire, cursor)
}
fn at_carrier(f: &Fixture) -> (Vec<u8>, FiContinuationCursor, Vec<u8>) {
    let page = verify_checkpoint_page(
        f.request.network_id,
        &f.checkpoint,
        &f.capsule.finality_proof_chain,
        4096,
        16 * 1024 * 1024,
    )
    .unwrap();
    let (wire, cursor) = selection(f, page.checkpoint());
    let mut capsule = f.capsule.clone();
    capsule.finality_proof_chain = vec![capsule.finality_proof_chain.last().unwrap().clone()];
    (wire, cursor, capsule.encode_canonical().unwrap())
}
fn verify(
    f: &Fixture,
    capsule: &[u8],
    wire: &[u8],
    cursor_wire: &[u8],
    cursor: &FiContinuationCursor,
) -> Result<VerifiedFiContextAssertionV1, String> {
    verify_fi_context_continuation(
        capsule,
        &f.original_request,
        wire,
        &f.checkpoint_bytes,
        cursor_wire,
        &f.expected(),
        cursor,
    )
}

#[test]
fn candidate_admission_accepts_signed_failed_observation_but_confers_no_execution() {
    for failed in [false, true] {
        let f = Fixture::new(failed, false);
        let (admitted, _, _) = admit_original(
            &f.capsule.assertion_signed_transaction,
            &f.original_request,
            &f.checkpoint_bytes,
            &f.expected(),
        )
        .unwrap();
        assert_eq!(admitted.request_sha256, f.request.original_sha256);
        assert_eq!(
            admitted.assertion_wire_sha256,
            sha256(&f.capsule.assertion_signed_transaction)
        );
        let object = json::from_slice_value(&admitted.to_json().unwrap()).unwrap();
        assert_eq!(object.as_object().unwrap().len(), 6);
        assert_eq!(
            object["schema"].as_str(),
            Some("iroha.fi-assertion-original.admitted.v1")
        );
        assert!(object.as_object().unwrap().values().all(Value::is_string));
        let (cp, cursor, capsule) = at_carrier(&f);
        assert_eq!(
            verify(
                &f,
                &capsule,
                &f.capsule.assertion_signed_transaction,
                &cp,
                &cursor
            )
            .is_ok(),
            !failed
        );
    }
    let extra = Fixture::new(false, true);
    assert!(
        admit_original(
            &extra.capsule.assertion_signed_transaction,
            &extra.original_request,
            &extra.checkpoint_bytes,
            &extra.expected()
        )
        .is_err()
    );
    let original = Fixture::new(false, false);
    let mut foreign = original.expected();
    foreign.runtime_manifest_sha256 = [0x19; 32];
    assert!(
        admit_original(
            &original.capsule.assertion_signed_transaction,
            &original.original_request,
            &original.checkpoint_bytes,
            &foreign
        )
        .is_err()
    );
    let mut foreign = original.expected();
    foreign.uid = [0x19; 32];
    assert!(
        admit_original(
            &original.capsule.assertion_signed_transaction,
            &original.original_request,
            &original.checkpoint_bytes,
            &foreign
        )
        .is_err()
    );
}

#[test]
fn exact_success_at_cursor_anchor_preserves_original_floor_and_v1_behavior() {
    let f = Fixture::new(false, false);
    let original = f.original_request.clone();
    let retained = f.capsule.assertion_signed_transaction.clone();
    let (cp, cursor, capsule) = at_carrier(&f);
    assert_eq!(cursor.height, 3);
    let verified = verify(&f, &capsule, &retained, &cp, &cursor).unwrap();
    assert_eq!(verified.block_height, 3);
    assert_eq!(verified.request_sha256, f.request.original_sha256);
    assert_eq!(f.original_request, original);
    assert_eq!(f.capsule.assertion_signed_transaction, retained);
    assert!(
        crate::fi_context_verification::verify_fi_context_assertion_v1(
            &capsule,
            &original,
            &f.checkpoint_bytes,
            &f.expected()
        )
        .is_err(),
        "V1 still needs its original anchor"
    );
    assert!(
        crate::fi_context_verification::verify_fi_context_assertion_v1(
            &capsule,
            &original,
            &cp,
            &f.expected()
        )
        .is_err(),
        "New cursor cannot replace V1 original floor"
    );
}

#[test]
fn continuation_refuses_wrong_original_floor_signed_wire_snapshot_and_overshooting_cursor() {
    let f = Fixture::new(false, false);
    let (cp, cursor, capsule) = at_carrier(&f);
    assert!(
        verify_fi_context_continuation(
            &capsule,
            &f.original_request,
            &f.capsule.assertion_signed_transaction,
            &cp,
            &cp,
            &f.expected(),
            &cursor
        )
        .is_err()
    );
    let different = Fixture::new(true, false);
    assert!(
        verify(
            &f,
            &capsule,
            &different.capsule.assertion_signed_transaction,
            &cp,
            &cursor
        )
        .is_err()
    );
    let mut substituted = AssetFiContextAssertionCapsuleV1::decode_canonical(&capsule).unwrap();
    substituted.snapshot = different.capsule.snapshot.clone();
    assert!(
        verify(
            &f,
            &substituted.encode_canonical().unwrap(),
            &f.capsule.assertion_signed_transaction,
            &cp,
            &cursor
        )
        .is_err()
    );
    let (later, late) = selection(&f, &f.later_checkpoint);
    assert!(late.height > cursor.height);
    assert!(
        verify(
            &f,
            &capsule,
            &f.capsule.assertion_signed_transaction,
            &later,
            &late
        )
        .is_err()
    );
    let bad = FiContinuationCursor {
        sha256: cursor.sha256,
        height: cursor.height,
        context_id: cursor.context_id,
        block_hash: [0x77; 32],
    };
    assert!(
        verify(
            &f,
            &capsule,
            &f.capsule.assertion_signed_transaction,
            &cp,
            &bad
        )
        .is_err()
    );
    let mut tampered = f.capsule.assertion_signed_transaction.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        admit_original(
            &tampered,
            &f.original_request,
            &f.checkpoint_bytes,
            &f.expected()
        )
        .is_err()
    );
}

#[test]
fn successive_pages_recover_original_without_changing_request_floor_or_signed_wire() {
    let f = Fixture::with_delay(false, false, 5);
    let proofs = &f.capsule.finality_proof_chain;
    let first = verify_checkpoint_page(
        f.request.network_id,
        &f.checkpoint,
        &proofs[..3],
        4096,
        16 * 1024 * 1024,
    )
    .unwrap();
    let second = verify_checkpoint_page(
        f.request.network_id,
        first.checkpoint(),
        &proofs[2..5],
        4096,
        16 * 1024 * 1024,
    )
    .unwrap();
    let (cp, cursor) = selection(&f, second.checkpoint());
    let mut capsule = f.capsule.clone();
    capsule.finality_proof_chain = proofs[4..].to_vec();
    assert_eq!(cursor.height, 6);
    assert_eq!(f.request.minimum_height, 2);
    assert_eq!(
        verify(
            &f,
            &capsule.encode_canonical().unwrap(),
            &f.capsule.assertion_signed_transaction,
            &cp,
            &cursor
        )
        .unwrap()
        .block_height,
        8
    );
}

#[test]
fn c_abi_admission_and_continuation_return_distinct_results_and_clear_failures() {
    let (capsule, request, floor, trust) = ffi_fixture(false, false);
    let parsed = AssetFiContextAssertionCapsuleV1::decode_canonical(&capsule).unwrap();
    let wire = &parsed.assertion_signed_transaction;
    let mut output = std::ptr::null_mut();
    let mut length = 0;
    let code = unsafe {
        connect_norito_admit_fi_assertion_original_v1(
            wire.as_ptr(),
            wire.len() as c_ulong,
            request.as_ptr(),
            request.len() as c_ulong,
            floor.as_ptr(),
            floor.len() as c_ulong,
            trust.as_ptr(),
            trust.len() as c_ulong,
            &mut output,
            &mut length,
        )
    };
    assert_eq!(code, 0);
    let bytes = unsafe { slice::from_raw_parts(output, length as usize) };
    assert_eq!(
        json::from_slice_value(bytes).unwrap()["schema"].as_str(),
        Some("iroha.fi-assertion-original.admitted.v1")
    );
    let candidate_result = bytes.to_vec();
    crate::connect_norito_free(output);
    let normalized = normalize_asset_fi_context_request_v1(&request).unwrap();
    let root = SumeragiFinalityCheckpoint::decode_canonical(&floor).unwrap();
    let page = verify_checkpoint_page(
        normalized.network_id,
        &root,
        &parsed.finality_proof_chain,
        4096,
        16 * 1024 * 1024,
    )
    .unwrap();
    let cp = page.checkpoint().encode_canonical().unwrap();
    let cursor=json::to_value(&norito::json!({"checkpointSha256":(hex::encode(sha256(&cp))),
        "checkpointHeight":(page.tip().height().to_string()),"checkpointContextId":(hex::encode(page.tip().context_id().as_ref())),
        "checkpointBlockHash":(hex::encode(page.tip().header().hash().as_ref()))})).unwrap();
    let original = json::from_slice_value(&trust).unwrap();
    let envelope=json::to_vec(&norito::json!({"schema":"iroha.fi-context-continuation-trust.v1","original":original,"cursor":cursor})).unwrap();
    let mut suffix = parsed.clone();
    suffix.finality_proof_chain = vec![parsed.finality_proof_chain.last().unwrap().clone()];
    let bytes = suffix.encode_canonical().unwrap();
    for candidate in [bytes.as_slice(), &[0_u8][..]] {
        let code = unsafe {
            connect_norito_verify_fi_context_continuation_v1(
                candidate.as_ptr(),
                candidate.len() as c_ulong,
                request.as_ptr(),
                request.len() as c_ulong,
                wire.as_ptr(),
                wire.len() as c_ulong,
                floor.as_ptr(),
                floor.len() as c_ulong,
                cp.as_ptr(),
                cp.len() as c_ulong,
                envelope.as_ptr(),
                envelope.len() as c_ulong,
                &mut output,
                &mut length,
            )
        };
        if candidate.len() > 1 {
            assert_eq!(code, 0);
            let result = unsafe { slice::from_raw_parts(output, length as usize) };
            assert_eq!(
                json::from_slice_value(result).unwrap()["blockHeight"].as_str(),
                Some("3")
            );
            // Opt-in producer export: only exact bytes from an already successful native test.
            // Refuse existing destinations; no fixture or assertion is skipped when unset.
            if let Some(destination) = std::env::var_os("IROHA_FI_CONTINUATION_FIXTURE_OUTPUT_DIR")
            {
                let directory = std::path::PathBuf::from(destination);
                assert!(directory.is_absolute());
                std::fs::create_dir(&directory).expect("fixture output must be a new directory");
                let mut inventory = Vec::new();
                for (name, original) in [
                    ("candidate-wire.norito", wire.as_slice()),
                    ("request.json", request.as_slice()),
                    ("original-checkpoint.norito", floor.as_slice()),
                    ("original-trust.json", trust.as_slice()),
                    ("cursor-checkpoint.norito", cp.as_slice()),
                    ("continuation-trust.json", envelope.as_slice()),
                    ("capsule.norito", candidate),
                    ("candidate-result.json", candidate_result.as_slice()),
                    ("continuation-result.json", result),
                ] {
                    std::fs::write(directory.join(name), original).unwrap();
                    inventory.push(format!("{}  {}\n", hex::encode(sha256(original)), name));
                }
                std::fs::write(directory.join("SHA256SUMS"), inventory.concat()).unwrap();
            }
            crate::connect_norito_free(output);
        } else {
            assert_eq!(code, ERR_FI_CONTEXT_CONTINUATION);
            assert!(output.is_null());
            assert_eq!(length, 0);
        }
    }
}
