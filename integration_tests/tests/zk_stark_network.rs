//! Multi-peer STARK integration coverage for governance voting.
#![cfg(feature = "zk-stark")]
use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::sandbox;
use iroha::blocking::Client;
use iroha_crypto::blake2::{Blake2b512, Digest as _};
use iroha_data_model::{
    isi::{Grant, InstructionBox},
    permission::Permission,
    proof::{ProofAttachment, VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_executor_data_model::permission::governance::{
    CanEnactGovernance, CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::json::Json;
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::ALICE_ID;
fn has_test_network_feature(feature: &str) -> bool {
    std::env::var("TEST_NETWORK_IROHAD_FEATURES")
        .ok()
        .map(|value| {
            value
                .split([',', ' ', '\t', '\n'])
                .any(|item| item.trim() == feature)
        })
        .unwrap_or(false)
}
fn require_test_network_feature(feature: &str, test_name: &str) -> Result<()> {
    ensure!(
        has_test_network_feature(feature),
        "{test_name}: TEST_NETWORK_IROHAD_FEATURES must include `{feature}` to execute the runtime path"
    );
    Ok(())
}
fn sample_stark_vk_box(backend: &str, circuit_id: &str) -> VerifyingKeyBox {
    let vk_payload = iroha_core_zk::stark::StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.to_owned(),
        n_log2: iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let bytes = norito::to_bytes(&vk_payload).expect("encode stark vk payload");
    VerifyingKeyBox::new(backend.to_owned(), bytes)
}
fn limb_as_instance_bytes(limb: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&limb.to_le_bytes());
    out
}
fn derive_ballot_nullifier(
    domain_tag: &str,
    chain_id: &iroha_model_base::chain::ChainId,
    election_id: &str,
    commit: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        domain_tag.len() + chain_id.as_str().len() + election_id.len() + commit.len() + 24,
    );
    let push_len = |buf: &mut Vec<u8>, len: usize| {
        let len_u64 = len as u64;
        buf.extend_from_slice(&len_u64.to_le_bytes());
    };
    push_len(&mut input, domain_tag.len());
    input.extend_from_slice(domain_tag.as_bytes());
    push_len(&mut input, chain_id.as_str().len());
    input.extend_from_slice(chain_id.as_str().as_bytes());
    push_len(&mut input, election_id.len());
    input.extend_from_slice(election_id.as_bytes());
    input.extend_from_slice(commit);
    let digest = Blake2b512::digest(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
async fn submit_and_wait_next_block<I>(
    client: &Client,
    network: &sandbox::SerializedNetwork,
    instruction: I,
    expected_height: &mut u64,
    context: &str,
) -> Result<()>
where
    I: Into<InstructionBox>,
{
    client
        .submit_with_metadata(
            instruction,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        )
        .wrap_err_with(|| format!("submit {context}"))?;
    *expected_height = expected_height.saturating_add(1);
    network
        .ensure_blocks(*expected_height)
        .await
        .wrap_err_with(|| format!("wait for commit after {context}"))?;
    Ok(())
}
#[tokio::test]
#[ignore = "no audited semantic governance STARK AIR is registered; generic Binding role labels fail closed"]
async fn stark_governance_paths() -> Result<()> {
    require_test_network_feature("zk-stark", stringify!(stark_governance_paths))?;
    let backend = "stark/fri";
    let ballot_circuit_id = "vote-ballot";
    let tally_circuit_id = "vote-tally";
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers();
    let Some(network) =
        sandbox::start_network_async_or_skip(builder, stringify!(stark_governance_paths)).await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let mut expected_height = 1_u64;
    let client = network.client();
    let election_id = "stark-vote-network-e2e".to_owned();
    submit_and_wait_next_block(
        &client,
        &network,
        Grant::account_permission(
            Permission::new("CanManageVerifyingKeys".to_string(), Json::new(())),
            ALICE_ID.clone(),
        ),
        &mut expected_height,
        "grant CanManageVerifyingKeys",
    )
    .await?;
    submit_and_wait_next_block(
        &client,
        &network,
        Grant::account_permission(Permission::from(CanManageParliament), ALICE_ID.clone()),
        &mut expected_height,
        "grant CanManageParliament",
    )
    .await?;
    submit_and_wait_next_block(
        &client,
        &network,
        Grant::account_permission(
            Permission::from(CanSubmitGovernanceBallot {
                referendum_id: election_id.clone(),
            }),
            ALICE_ID.clone(),
        ),
        &mut expected_height,
        "grant CanSubmitGovernanceBallot",
    )
    .await?;
    submit_and_wait_next_block(
        &client,
        &network,
        Grant::account_permission(Permission::from(CanEnactGovernance), ALICE_ID.clone()),
        &mut expected_height,
        "grant CanEnactGovernance",
    )
    .await?;
    let ballot_vk_id = VerifyingKeyId::new(backend, "vote_ballot");
    let ballot_vk_box = sample_stark_vk_box(backend, ballot_circuit_id);
    let ballot_schema = b"gov:vote:ballot:schema:v1".to_vec();
    let mut ballot_vk_record = VerifyingKeyRecord::new(
        1,
        ballot_circuit_id,
        BackendTag::Stark,
        "goldilocks",
        iroha_crypto::Hash::new(&ballot_schema).into(),
        iroha_core_zk::hash_vk(&ballot_vk_box),
    );
    ballot_vk_record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
    ballot_vk_record.gas_schedule_id = Some("sched_ballot".to_owned());
    ballot_vk_record.vk_len = ballot_vk_box.bytes.len() as u32;
    ballot_vk_record.max_proof_bytes = 8 * 1024 * 1024;
    ballot_vk_record.key = Some(ballot_vk_box.clone());
    submit_and_wait_next_block(
        &client,
        &network,
        iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: ballot_vk_id.clone(),
            record: ballot_vk_record,
        },
        &mut expected_height,
        "register ballot verifying key",
    )
    .await?;
    let tally_vk_id = VerifyingKeyId::new(backend, "vote_tally");
    let tally_vk_box = sample_stark_vk_box(backend, tally_circuit_id);
    let tally_schema = b"gov:vote:tally:schema:v1".to_vec();
    let mut tally_vk_record = VerifyingKeyRecord::new(
        1,
        tally_circuit_id,
        BackendTag::Stark,
        "goldilocks",
        iroha_crypto::Hash::new(&tally_schema).into(),
        iroha_core_zk::hash_vk(&tally_vk_box),
    );
    tally_vk_record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
    tally_vk_record.gas_schedule_id = Some("sched_tally".to_owned());
    tally_vk_record.vk_len = tally_vk_box.bytes.len() as u32;
    tally_vk_record.max_proof_bytes = 8 * 1024 * 1024;
    tally_vk_record.key = Some(tally_vk_box.clone());
    submit_and_wait_next_block(
        &client,
        &network,
        iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: tally_vk_id.clone(),
            record: tally_vk_record,
        },
        &mut expected_height,
        "register tally verifying key",
    )
    .await?;
    let nullifier_domain = "gov:ballot:v1".to_owned();
    let eligible_root = [0x22; 32];
    submit_and_wait_next_block(
        &client,
        &network,
        iroha_data_model::isi::zk::CreateElection {
            election_id: election_id.clone(),
            options: 2,
            eligible_root,
            start_ts: 0,
            end_ts: 0,
            vk_ballot: ballot_vk_id.clone(),
            vk_tally: tally_vk_id.clone(),
            domain_tag: nullifier_domain.clone(),
        },
        &mut expected_height,
        "create election",
    )
    .await?;
    let bad_commit = [0x33; 32];
    let mismatched_ballot_proof = iroha_core_zk::prove_stark_fri_open_verify_envelope(
        backend,
        tally_circuit_id,
        &tally_vk_box,
        &tally_schema,
        vec![vec![bad_commit], vec![eligible_root]],
    )
    .map_err(|err| eyre!(err))?;
    let mismatched_ballot_attachment = ProofAttachment::new_ref(
        backend.to_owned(),
        mismatched_ballot_proof,
        ballot_vk_id.clone(),
    );
    let mismatched_nullifier = derive_ballot_nullifier(
        &nullifier_domain,
        client.client().chain(),
        &election_id,
        &bad_commit,
    );
    let bad_ballot = client.submit(
        iroha_data_model::isi::zk::SubmitBallot {
            election_id: election_id.clone(),
            ciphertext: bad_commit.to_vec(),
            ballot_proof: mismatched_ballot_attachment,
            nullifier: mismatched_nullifier,
        },
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    assert!(
        bad_ballot.is_err(),
        "mismatched ballot circuit/backend binding should be rejected"
    );
    let commit = [0x11; 32];
    let ballot_proof = iroha_core_zk::prove_stark_fri_open_verify_envelope(
        backend,
        ballot_circuit_id,
        &ballot_vk_box,
        &ballot_schema,
        vec![vec![commit], vec![eligible_root]],
    )
    .map_err(|err| eyre!(err))?;
    let ballot_attachment =
        ProofAttachment::new_ref(backend.to_owned(), ballot_proof, ballot_vk_id.clone());
    let nullifier = derive_ballot_nullifier(
        &nullifier_domain,
        client.client().chain(),
        &election_id,
        &commit,
    );
    submit_and_wait_next_block(
        &client,
        &network,
        iroha_data_model::isi::zk::SubmitBallot {
            election_id: election_id.clone(),
            ciphertext: commit.to_vec(),
            ballot_proof: ballot_attachment,
            nullifier,
        },
        &mut expected_height,
        "submit valid ballot",
    )
    .await?;
    let tally = vec![7_u64, 2_u64];
    let tally_columns = tally
        .iter()
        .map(|&value| vec![limb_as_instance_bytes(value)])
        .collect::<Vec<_>>();
    let tally_proof = iroha_core_zk::prove_stark_fri_open_verify_envelope(
        backend,
        tally_circuit_id,
        &tally_vk_box,
        &tally_schema,
        tally_columns,
    )
    .map_err(|err| eyre!(err))?;
    let tally_attachment = ProofAttachment::new_ref(backend.to_owned(), tally_proof, tally_vk_id);
    submit_and_wait_next_block(
        &client,
        &network,
        iroha_data_model::isi::zk::FinalizeElection {
            election_id,
            tally,
            tally_proof: tally_attachment,
        },
        &mut expected_height,
        "finalize election",
    )
    .await?;
    Ok(())
}
