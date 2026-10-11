//! Canonical local wallet proving; the Core owner selects and verifies the circuit.

use super::*;
use iroha_core_zk::confidential::{ConfidentialProof, ConfidentialProver, ConfidentialTree};
use napi::bindgen_prelude::AsyncTask;
use zeroize::{Zeroize, Zeroizing};

fn prover(network: &[u8], asset: &str, spend_key: &[u8]) -> napi::Result<ConfidentialProver> {
    let network = parse_transaction_network_id_bytes(network)?;
    let asset: AssetDefinitionId = asset.parse().map_err(norito_to_napi)?;
    if spend_key.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential spend key must be 32 bytes",
        ));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(spend_key);
    ConfidentialProver::new(network, &asset, key).map_err(norito_to_napi)
}

// N-API owns these temporary strings; parsing guards erase them on success,
// rejection and unwind. JavaScript's original immutable strings remain caller-owned.
impl Zeroize for JsConfidentialTransferInputV2 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho_hex.zeroize();
        self.diversifier_hex.zeroize();
        self.leaf_index.zeroize();
    }
}
impl Zeroize for JsConfidentialTransferOutputV2 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho_hex.zeroize();
        self.owner_tag_hex.zeroize();
    }
}
impl Zeroize for JsConfidentialUnshieldOutputV3 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho_hex.zeroize();
    }
}

fn validate_shape(leaves: usize, inputs: usize, outputs: usize) -> napi::Result<()> {
    if leaves > (1 << confidential_v2::CONFIDENTIAL_TREE_DEPTH_V2) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential tree exceeds its capacity",
        ));
    }
    if !(1..=2).contains(&inputs) || !(1..=2).contains(&outputs) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential proving requires one or two input notes and valid output counts",
        ));
    }
    Ok(())
}

fn envelope(result: ConfidentialProof) -> JsConfidentialTransferProofEnvelopeV2 {
    JsConfidentialTransferProofEnvelopeV2 {
        nullifiers: result
            .nullifiers
            .into_iter()
            .map(|v| Buffer::from(v.to_vec()))
            .collect(),
        output_commitments: result
            .output_commitments
            .into_iter()
            .map(|v| Buffer::from(v.to_vec()))
            .collect(),
        root: Buffer::from(result.root.to_vec()),
        proof: Buffer::from(result.proof.bytes),
    }
}

enum ConfidentialOperation {
    Transfer {
        inputs: Vec<ConfidentialTransferInputV2>,
        outputs: Vec<ConfidentialTransferOutputV2>,
    },
    Redemption {
        inputs: Vec<ConfidentialUnshieldInputV2>,
        amount: u128,
        change: Option<ConfidentialUnshieldOutputV3>,
    },
}

struct ConfidentialJob {
    prover: ConfidentialProver,
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    operation: ConfidentialOperation,
}

/// Owned local proving job; all private inputs clear when consumed or abandoned.
pub struct ConfidentialProvingTask {
    job: Option<ConfidentialJob>,
}

impl napi::Task for ConfidentialProvingTask {
    type Output = ConfidentialProof;
    type JsValue = JsConfidentialTransferProofEnvelopeV2;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let job = self.job.take().ok_or_else(|| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "confidential proving job was consumed",
            )
        })?;
        let tree = ConfidentialTree::Commitments {
            root: job.root,
            leaves: &job.leaves,
        };
        match job.operation {
            ConfidentialOperation::Transfer { inputs, outputs } => {
                job.prover.prove_transfer(tree, inputs, outputs)
            }
            ConfidentialOperation::Redemption {
                inputs,
                amount,
                change,
            } => job.prover.prove_unshield(tree, inputs, amount, change),
        }
        .map_err(norito_to_napi)
    }

    fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(envelope(output))
    }
}

/// Prove off the JavaScript thread using the canonical circuit and selected key.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn prove_confidential_transfer(
    network_id: Uint8Array,
    asset_definition_id: String,
    spend_key: Uint8Array,
    tree_commitments_hex: Vec<String>,
    inputs: Vec<JsConfidentialTransferInputV2>,
    outputs: Vec<JsConfidentialTransferOutputV2>,
    root_hex: String,
) -> napi::Result<AsyncTask<ConfidentialProvingTask>> {
    let mut inputs = Zeroizing::new(inputs);
    let mut outputs = Zeroizing::new(outputs);
    let prover = prover(
        network_id.as_ref(),
        &asset_definition_id,
        spend_key.as_ref(),
    )?;
    validate_shape(tree_commitments_hex.len(), inputs.len(), outputs.len())?;
    let leaves = parse_confidential_tree_commitments(tree_commitments_hex)?;
    let inputs = parse_confidential_transfer_inputs_v2(core::mem::take(&mut *inputs))?;
    let outputs = parse_confidential_transfer_outputs_v2(core::mem::take(&mut *outputs))?;
    let root = parse_fixed_32_hex("root", &root_hex)?;
    Ok(AsyncTask::new(ConfidentialProvingTask {
        job: Some(ConfidentialJob {
            prover,
            leaves,
            root,
            operation: ConfidentialOperation::Transfer { inputs, outputs },
        }),
    }))
}

/// Prove redemption off the JavaScript thread, selecting full or change internally.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn prove_confidential_redemption(
    network_id: Uint8Array,
    asset_definition_id: String,
    spend_key: Uint8Array,
    tree_commitments_hex: Vec<String>,
    inputs: Vec<JsConfidentialTransferInputV2>,
    public_amount: String,
    root_hex: String,
    change: Option<JsConfidentialUnshieldOutputV3>,
) -> napi::Result<AsyncTask<ConfidentialProvingTask>> {
    let mut inputs = Zeroizing::new(inputs);
    let mut change = Zeroizing::new(change);
    let prover = prover(
        network_id.as_ref(),
        &asset_definition_id,
        spend_key.as_ref(),
    )?;
    validate_shape(tree_commitments_hex.len(), inputs.len(), 1)?;
    let leaves = parse_confidential_tree_commitments(tree_commitments_hex)?;
    let inputs = parse_confidential_unshield_inputs_v2(core::mem::take(&mut *inputs))?;
    let amount = parse_confidential_amount_u128("publicAmount", &public_amount)?;
    let mut outputs = parse_confidential_unshield_outputs_v3(
        core::mem::take(&mut *change).into_iter().collect(),
    )?;
    let root = parse_fixed_32_hex("root", &root_hex)?;
    Ok(AsyncTask::new(ConfidentialProvingTask {
        job: Some(ConfidentialJob {
            prover,
            leaves,
            root,
            operation: ConfidentialOperation::Redemption {
                inputs,
                amount,
                change: outputs.pop(),
            },
        }),
    }))
}

/// Return the canonical default owner diversifier used by private redemption change.
#[napi]
pub fn default_confidential_diversifier() -> Buffer {
    Buffer::from(confidential_v2::default_confidential_diversifier_v2().to_vec())
}

/// Owned public commitment history computed off the JavaScript thread.
pub struct ConfidentialRootTask {
    commitments: Vec<[u8; 32]>,
}

impl napi::Task for ConfidentialRootTask {
    type Output = [u8; 32];
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        confidential_v2::compute_confidential_root_v3(&self.commitments).map_err(norito_to_napi)
    }

    fn resolve(&mut self, _env: napi::Env, root: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(Buffer::from(root.to_vec()))
    }
}

/// Compute the fixed-depth local history root without authenticating ledger state.
#[napi]
pub fn compute_confidential_root(
    commitments: Vec<String>,
) -> napi::Result<AsyncTask<ConfidentialRootTask>> {
    if commitments.len() > (1 << confidential_v2::CONFIDENTIAL_TREE_DEPTH_V2) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential tree exceeds its capacity",
        ));
    }
    Ok(AsyncTask::new(ConfidentialRootTask {
        commitments: parse_confidential_tree_commitments(commitments)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use napi::Task;

    #[test]
    fn default_diversifier_matches_core_and_change_owner_derivation() {
        let value = default_confidential_diversifier();
        let expected = confidential_v2::default_confidential_diversifier_v2();
        assert_eq!(value.as_ref(), expected.as_slice());
        let explicit = confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(
            &[91; 32],
            value.as_ref().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            explicit,
            confidential_v2::derive_confidential_owner_tag_v2(&[91; 32]).unwrap()
        );
    }

    #[test]
    fn local_root_matches_core_paths_and_rejects_capacity_before_parsing() {
        let error = compute_confidential_root(vec![String::new(); 65_537])
            .err()
            .unwrap();
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert_eq!(error.reason, "confidential tree exceeds its capacity");
        assert!(compute_confidential_root(vec!["FF".repeat(32)]).is_err());
        for commitments in [vec![], vec![[1; 32]], vec![[1; 32], [2; 32], [3; 32]]] {
            let mut task = ConfidentialRootTask {
                commitments: commitments.clone(),
            };
            let root = task.compute().unwrap();
            assert_eq!(
                root,
                confidential_v2::compute_confidential_root_v3(&commitments).unwrap()
            );
            for index in 0..commitments.len() {
                assert_eq!(
                    root,
                    confidential_v2::compute_confidential_merkle_path_v2(&commitments, index)
                        .unwrap()
                        .root
                );
            }
        }
    }

    #[test]
    fn owned_worker_produces_a_self_verified_full_redemption() {
        let asset = AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .unwrap()
        .to_string();
        let input = ConfidentialUnshieldInputV2 {
            amount: 7,
            rho: [92; 32],
            diversifier: confidential_v2::default_confidential_diversifier_v2(),
            leaf_index: 0,
        };
        let owner = confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(
            &[91; 32],
            input.diversifier,
        )
        .unwrap();
        let leaf =
            confidential_v2::derive_confidential_note_v2(&asset, 7, input.rho, owner).unwrap();
        let root = confidential_v2::compute_confidential_merkle_path_v2(&[leaf], 0)
            .unwrap()
            .root;
        let mut task = ConfidentialProvingTask {
            job: Some(ConfidentialJob {
                prover: prover(&[1; 32], &asset, &[91; 32]).unwrap(),
                leaves: vec![leaf],
                root,
                operation: ConfidentialOperation::Redemption {
                    inputs: vec![input],
                    amount: 7,
                    change: None,
                },
            }),
        };
        let result = std::thread::spawn(move || {
            let proof = task.compute().unwrap();
            assert!(task.job.is_none());
            assert!(task.compute().is_err());
            proof
        })
        .join()
        .unwrap();
        assert_eq!(
            result.relation,
            iroha_core_zk::ProofRelation::ConfidentialFullUnshield
        );
        assert_eq!(result.root, root);
        assert_eq!(result.nullifiers.len(), 1);
        assert!(result.output_commitments.is_empty());
        assert!(!result.proof.bytes.is_empty());
    }

    #[test]
    fn owned_worker_jobs_cross_threads_and_are_consumed_on_preflight_failure() {
        let asset = AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .unwrap()
        .to_string();
        for operation in [
            ConfidentialOperation::Transfer {
                inputs: vec![],
                outputs: vec![],
            },
            ConfidentialOperation::Redemption {
                inputs: vec![],
                amount: 7,
                change: None,
            },
        ] {
            let mut task = ConfidentialProvingTask {
                job: Some(ConfidentialJob {
                    prover: prover(&[1; 32], &asset, &[7; 32]).unwrap(),
                    leaves: vec![],
                    root: [0; 32],
                    operation,
                }),
            };
            std::thread::spawn(move || {
                assert!(task.compute().is_err());
                assert!(
                    task.job.is_none(),
                    "failed computation must release its input owner"
                );
                let retry = task.compute().unwrap_err();
                assert_eq!(retry.reason, "confidential proving job was consumed");
            })
            .join()
            .unwrap();
        }
    }

    #[test]
    fn wallet_rejects_network_key_and_empty_spend_before_proof_work() {
        assert!(prover(&[0; 31], "", &[1; 32]).is_err());
        let asset = AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .unwrap()
        .to_string();
        assert!(prover(&[1; 32], &asset, &[0; 32]).is_err());
        assert!(prover(&[1; 32], &asset, &[1; 31]).is_err());
        let transfer = prove_confidential_transfer(
            Uint8Array::from(vec![1; 32]),
            asset.clone(),
            Uint8Array::from(vec![1; 32]),
            vec![],
            vec![],
            vec![],
            "00".repeat(32),
        );
        assert!(
            transfer
                .err()
                .unwrap()
                .reason
                .contains("one or two input notes")
        );
        let redemption = prove_confidential_redemption(
            Uint8Array::from(vec![1; 32]),
            asset,
            Uint8Array::from(vec![1; 32]),
            vec![],
            vec![],
            "1".into(),
            "00".repeat(32),
            None,
        );
        assert!(
            redemption
                .err()
                .unwrap()
                .reason
                .contains("one or two input notes")
        );
    }

    #[test]
    fn ffi_private_strings_and_shape_controls_clear_all_owned_fields() {
        let mut input = JsConfidentialTransferInputV2 {
            amount: "7".into(),
            rho_hex: "11".repeat(32),
            diversifier_hex: Some("22".repeat(32)),
            leaf_index: 17,
        };
        input.zeroize();
        assert!(input.amount.is_empty() && input.rho_hex.is_empty());
        assert!(input.diversifier_hex.as_ref().is_none_or(String::is_empty));
        assert_eq!(input.leaf_index, 0);
        let mut output = JsConfidentialTransferOutputV2 {
            amount: "7".into(),
            rho_hex: "11".repeat(32),
            owner_tag_hex: "33".repeat(32),
        };
        output.zeroize();
        assert!(
            output.amount.is_empty()
                && output.rho_hex.is_empty()
                && output.owner_tag_hex.is_empty()
        );
        let mut change = JsConfidentialUnshieldOutputV3 {
            amount: "2".into(),
            rho_hex: "44".repeat(32),
        };
        change.zeroize();
        assert!(change.amount.is_empty() && change.rho_hex.is_empty());
        assert!(validate_shape(65536, 1, 1).is_ok());
        for counts in [(65537, 1, 1), (1, 0, 1), (1, 3, 1), (1, 1, 0), (1, 1, 3)] {
            assert!(validate_shape(counts.0, counts.1, counts.2).is_err());
        }
    }

    #[test]
    fn native_note_hex_and_amounts_reject_aliases_before_decoding() {
        assert_eq!(
            parse_fixed_32_hex("rho", &"ab".repeat(32)).unwrap(),
            [0xab; 32]
        );
        for invalid in [
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(32)),
            format!(" {}", "ab".repeat(32)),
            "a".repeat(63),
            "x".repeat(64),
            "a".repeat(65),
        ] {
            assert!(parse_fixed_32_hex("rho", &invalid).is_err());
        }
        assert_eq!(parse_confidential_amount_u128("amount", "7").unwrap(), 7);
        for invalid in ["", " 7", "7 ", "+7", "-7", "7.0"] {
            assert!(parse_confidential_amount_u128("amount", invalid).is_err());
        }
    }

    #[test]
    fn note_parsers_preserve_fields_and_reject_late_private_field_errors() {
        let input = || JsConfidentialTransferInputV2 {
            amount: "17".into(),
            rho_hex: "11".repeat(32),
            diversifier_hex: Some("22".repeat(32)),
            leaf_index: 31,
        };
        let transfer = parse_confidential_transfer_inputs_v2(vec![input()]).unwrap();
        let redemption = parse_confidential_unshield_inputs_v2(vec![input()]).unwrap();
        assert_eq!(transfer[0].amount, 17);
        assert_eq!(transfer[0].rho, [0x11; 32]);
        assert_eq!(transfer[0].diversifier, [0x22; 32]);
        assert_eq!(transfer[0].leaf_index, 31);
        assert_eq!(redemption[0].amount, transfer[0].amount);
        assert_eq!(redemption[0].rho, transfer[0].rho);
        assert_eq!(redemption[0].diversifier, transfer[0].diversifier);
        assert_eq!(redemption[0].leaf_index, transfer[0].leaf_index);
        let invalid_input = || {
            let mut note = input();
            note.diversifier_hex = None;
            note
        };
        for error in [
            parse_confidential_transfer_inputs_v2(vec![input(), invalid_input()]).unwrap_err(),
            parse_confidential_unshield_inputs_v2(vec![input(), invalid_input()]).unwrap_err(),
        ] {
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert_eq!(error.reason, "inputs[1].diversifier_hex is required");
        }
        let output = || JsConfidentialTransferOutputV2 {
            amount: "17".into(),
            rho_hex: "33".repeat(32),
            owner_tag_hex: "44".repeat(32),
        };
        let parsed = parse_confidential_transfer_outputs_v2(vec![output()]).unwrap();
        assert_eq!(parsed[0].amount, 17);
        assert_eq!(parsed[0].rho, [0x33; 32]);
        assert_eq!(parsed[0].owner_tag, [0x44; 32]);
        let mut invalid_output = output();
        invalid_output.owner_tag_hex = "private-invalid-tag".into();
        let error =
            parse_confidential_transfer_outputs_v2(vec![output(), invalid_output]).unwrap_err();
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("outputs[1].owner_tag_hex"));
        assert!(!error.reason.contains("private-invalid-tag"));

        let change = || JsConfidentialUnshieldOutputV3 {
            amount: "3".into(),
            rho_hex: "55".repeat(32),
        };
        let parsed = parse_confidential_unshield_outputs_v3(vec![change()]).unwrap();
        assert_eq!(parsed[0].amount, 3);
        assert_eq!(parsed[0].rho, [0x55; 32]);
        let mut invalid_change = change();
        invalid_change.rho_hex = "private-invalid-rho".into();
        let error =
            parse_confidential_unshield_outputs_v3(vec![change(), invalid_change]).unwrap_err();
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("outputs[1].rho_hex"));
        assert!(!error.reason.contains("private-invalid-rho"));
    }

    #[test]
    fn public_envelope_preserves_native_proof_and_output_order() {
        use iroha_core_zk::ProofRelation;
        let actual = envelope(ConfidentialProof {
            relation: ProofRelation::ConfidentialTransfer,
            proof: iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), vec![7, 8]),
            root: [3; 32],
            nullifiers: vec![[4; 32], [5; 32]],
            output_commitments: vec![[6; 32]],
        });
        assert_eq!(actual.proof.as_ref(), &[7, 8]);
        assert_eq!(actual.root.as_ref(), &[3; 32]);
        assert_eq!(actual.nullifiers[1].as_ref(), &[5; 32]);
        assert_eq!(actual.output_commitments[0].as_ref(), &[6; 32]);
    }

    #[test]
    fn native_note_derivation_matches_core_and_redacts_late_decode_failures() {
        let asset = AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .unwrap()
        .to_string();
        let key = [7; 32];
        let rho = [0x11; 32];
        let diversifier = [0x22; 32];
        let owner =
            confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(&key, diversifier)
                .unwrap();
        let derived_owner = derive_confidential_owner_tag_v2(
            Uint8Array::from(key.to_vec()),
            Some(hex::encode(diversifier)),
        )
        .unwrap();
        assert_eq!(derived_owner.as_ref(), &owner);
        let note = derive_confidential_note_v2(
            asset.clone(),
            "17".into(),
            hex::encode(rho),
            hex::encode(owner),
        )
        .unwrap();
        assert_eq!(
            note.as_ref(),
            &confidential_v2::derive_confidential_note_v2(&asset, 17, rho, owner).unwrap()
        );
        let network = parse_transaction_network_id_bytes(&[1; 32]).unwrap();
        let nullifier = derive_confidential_nullifier_v2(
            Uint8Array::from(vec![1; 32]),
            asset.clone(),
            Uint8Array::from(key.to_vec()),
            hex::encode(rho),
        )
        .unwrap();
        assert_eq!(
            nullifier.as_ref(),
            &confidential_v2::derive_confidential_nullifier_v3(
                &key,
                rho,
                confidential_v2::derive_confidential_asset_tag_v3(&asset).unwrap(),
                confidential_v2::derive_confidential_network_tag_v3(&network).unwrap(),
            )
            .unwrap()
        );
        // `Buffer` has no `Debug`, so the rejections are taken with `err()`.
        for error in [
            derive_confidential_owner_tag_v2(Uint8Array::from(key.to_vec()), None)
                .err()
                .expect("an owner tag without a diversifier is rejected"),
            derive_confidential_note_v2(
                asset.clone(),
                "17".into(),
                hex::encode(rho),
                "private-invalid-owner".into(),
            )
            .err()
            .expect("an invalid owner is rejected"),
            derive_confidential_nullifier_v2(
                Uint8Array::from(vec![1; 32]),
                asset,
                Uint8Array::from(key.to_vec()),
                "private-invalid-rho".into(),
            )
            .err()
            .expect("an invalid rho is rejected"),
        ] {
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(!error.reason.contains("private-invalid"));
        }
    }
}
