//! Four-validator generic verification of a one-note, full-capacity wallet proof.
//!
//! The local tree is a synthetic proof statement, not a ledger-authorized asset
//! root. Only `VerifyProof` records are submitted; this does not move value or
//! revive retired confidential-transfer instructions.
use super::{fetch_proof_snapshot, proof_fixtures::corrupt_native_proof};
use eyre::{Report, Result, ensure};
use integration_tests::sandbox;
use iroha_core_zk::{
    self as zk, ProofRelation,
    confidential::{ConfidentialProof, ConfidentialProver, ConfidentialTree},
    confidential_v2::{
        CONFIDENTIAL_TREE_CAPACITY_V2, ConfidentialUnshieldInputV2,
        compute_confidential_merkle_path_v2, confidential_unshield_v2_vk_record,
        default_confidential_diversifier_v2, derive_confidential_note_v2,
        derive_confidential_owner_tag_v2_with_diversifier, poseidon_empty_root_v2,
    },
};
use iroha_data_model::{
    NetworkId,
    asset::AssetDefinitionId,
    isi::{verifying_keys, zk::VerifyProof},
    permission::Permission,
    prelude::{Grant, Json},
    proof::{ProofAttachment, ProofBox, ProofId, ProofStatus, VerifyingKeyId},
    transaction::FeePaymentIntent,
    zk::OpenVerifyEnvelope,
};
use iroha_test_network::{Network, NetworkBuilder, read_on_dedicated_thread};
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
use std::time::Duration;
use zeroize::Zeroizing;

fn full_tree_wallet_proof(network_id: NetworkId) -> Result<ConfidentialProof> {
    // Deterministic disposable test openings; production proof randomness is
    // supplied by the public prover's operating-system entropy source.
    let spend_key = Zeroizing::new([0x31; 32]);
    let asset = AssetDefinitionId::from_uuid_bytes([
        1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
    ])?;
    let input = ConfidentialUnshieldInputV2 {
        amount: 9,
        rho: [0x23; 32],
        diversifier: default_confidential_diversifier_v2(),
        leaf_index: 0,
    };
    let owner =
        derive_confidential_owner_tag_v2_with_diversifier(spend_key.as_ref(), input.diversifier)
            .map_err(Report::msg)?;
    let commitment =
        derive_confidential_note_v2(&asset.to_string(), input.amount, input.rho, owner)
            .map_err(Report::msg)?;
    let mut filler = [0; 32];
    filler[0] = 7;
    let mut commitments = vec![filler; CONFIDENTIAL_TREE_CAPACITY_V2];
    commitments[0] = commitment;
    assert_eq!(commitments.len(), 65_536);
    assert!(commitments.iter().all(|leaf| *leaf != [0; 32]));
    let path =
        compute_confidential_merkle_path_v2(&commitments, input.leaf_index).map_err(Report::msg)?;
    let root = path.root;
    assert_ne!(root, poseidon_empty_root_v2());
    let paths = [path];
    let prover = ConfidentialProver::new(network_id, &asset, spend_key)?;
    let result = prover.prove_unshield(
        ConfidentialTree::Paths {
            root,
            paths: &paths,
        },
        vec![input],
        9,
        None,
    )?;
    assert_eq!(result.relation, ProofRelation::ConfidentialFullUnshield);
    assert_eq!(result.root, root);
    assert_eq!(result.nullifiers.len(), 1);
    assert!(result.output_commitments.is_empty());
    Ok(result)
}

async fn record_on_every_validator(
    network: &Network,
    attachment: ProofAttachment,
    expected: ProofStatus,
) -> Result<()> {
    let id = ProofId {
        backend: attachment.proof.backend.clone(),
        proof_hash: zk::hash_proof(&attachment.proof),
    };
    let client = integration_tests::sync::rebind_blocking_client(&network.client(), |client| {
        client.transaction_status_timeout = Duration::from_secs(600);
        client.transaction_ttl = Some(Duration::from_secs(660));
    });
    read_on_dedicated_thread(move || {
        client.submit(
            VerifyProof::new(attachment),
            FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await?;
    let id_text = id.to_string();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    for (index, peer) in network.peers().iter().enumerate() {
        let mut url = peer.client().client().endpoint().clone();
        url.path_segments_mut()
            .expect("Torii base URL")
            .clear()
            .extend(["v1", "proofs", id_text.as_str()]);
        loop {
            match tokio::time::timeout_at(deadline, fetch_proof_snapshot(url.clone()))
                .await
                .map_err(|_| eyre::eyre!("validator {index} proof query exceeded its deadline"))?
            {
                Ok((backend, hash, status)) => {
                    ensure!(
                        backend == id.backend && hash == id.proof_hash,
                        "wrong proof identity"
                    );
                    if status == expected {
                        break;
                    }
                    ensure!(
                        status == ProofStatus::Submitted,
                        "validator {index} stored unexpected terminal proof status {status:?}"
                    );
                }
                Err(error) if super::is_retryable_snapshot_error(&error) => {}
                Err(error) => return Err(error),
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "validator {index} did not store {expected:?} for the exact proof"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires same-candidate daemon and real four-validator full-capacity native proof verification"]
async fn four_validator_full_tree_wallet_proof_records_reject_corruption_and_relabelling()
-> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_REQUIRE_NETWORK").as_deref() == Ok("1"),
        "this qualification requires IROHA_TEST_REQUIRE_NETWORK=1"
    );
    let full_record = confidential_unshield_v2_vk_record("integration", 1).map_err(Report::msg)?;
    let full_key = full_record
        .key
        .clone()
        .expect("canonical inline full-unshield key");
    let full_id = VerifyingKeyId::new(&full_key.backend, "full_tree_unshield_vk");
    let transfer_record = zk::confidential_v2::confidential_transfer_v2_vk_record("integration", 1)
        .map_err(Report::msg)?;
    let transfer_key = transfer_record
        .key
        .clone()
        .expect("canonical inline confidential-transfer key");
    let transfer_id = VerifyingKeyId::new(&transfer_key.backend, "full_tree_wrong_role_vk");
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_genesis_instruction(Grant::account_permission(
            Permission::new("CanManageVerifyingKeys".into(), Json::new(())),
            SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        ))
        .with_genesis_instruction(verifying_keys::RegisterVerifyingKey {
            id: full_id.clone(),
            record: full_record,
        })
        .with_genesis_instruction(verifying_keys::RegisterVerifyingKey {
            id: transfer_id.clone(),
            record: transfer_record.clone(),
        });
    let network = sandbox::start_network_async_or_skip(builder, "full_tree_wallet_proof_records")
        .await?
        .ok_or_else(|| eyre::eyre!("mandatory four-validator qualification was skipped"))?;
    ensure!(
        network.peers().len() == 4,
        "expected exactly four validators"
    );
    let network_id = *network.client().client().network_id();
    for peer in network.peers() {
        ensure!(
            *peer.client().client().network_id() == network_id,
            "network identity mismatch"
        );
    }
    let result = tokio::task::spawn_blocking(move || full_tree_wallet_proof(network_id)).await??;
    ensure!(
        zk::verify_backend(&full_key.backend, &result.proof, Some(&full_key))
            .expect("full proof verification must be admitted"),
        "full proof must verify locally"
    );
    let corrupt = corrupt_native_proof(&result.proof);
    ensure!(
        !zk::verify_backend(&full_key.backend, &corrupt, Some(&full_key))
            .expect("corrupted proof verification must be admitted"),
        "corrupted native proof must fail"
    );
    let mut wrong_role: OpenVerifyEnvelope = norito::decode_canonical(&result.proof.bytes)?;
    wrong_role.circuit_id = transfer_record.circuit_id;
    wrong_role.vk_hash = transfer_record.commitment;
    wrong_role.public_inputs =
        zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec();
    let wrong_role = ProofBox::new(
        transfer_key.backend.clone(),
        norito::encode_canonical(&wrong_role)?,
    );
    ensure!(
        !zk::verify_backend(&transfer_key.backend, &wrong_role, Some(&transfer_key))
            .expect("wrong-role proof verification must be admitted"),
        "full-unshield proof cannot attest a confidential transfer"
    );
    for (proof, key, status) in [
        (result.proof, full_id.clone(), ProofStatus::Verified),
        (corrupt, full_id, ProofStatus::Rejected),
        (wrong_role, transfer_id, ProofStatus::Rejected),
    ] {
        record_on_every_validator(
            &network,
            ProofAttachment::new_ref(proof.backend.clone(), proof, key),
            status,
        )
        .await?;
    }
    Ok(())
}
