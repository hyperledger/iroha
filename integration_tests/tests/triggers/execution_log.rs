#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Trigger execution log coverage.
#![cfg(feature = "fault_injection")]
use eyre::{Ok, Result, eyre};
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::{
    crypto::{MerkleProof, MerkleTreeCommitment},
    data_model::{
        block::execution_output::ExecutionOutputV1,
        events::pipeline::BlockEventFilter,
        prelude::*,
        sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier},
    },
};
use iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger;
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use nonzero_ext::nonzero;
use std::{num::NonZeroU64, time::Instant};
use tokio::{task::spawn_blocking, time::timeout};
/// # Scenario
///
/// 1. Client fetches the exact transaction carrier and authenticates its contiguous finality
///    from the locally provisioned signed genesis.
/// 2. Client selects the transaction by entrypoint hash and obtains its input/output proofs.
/// 3a. If proofs are valid, the client accepts the data.
/// 3b. If proofs are invalid or tampered with, the client rejects the data.
#[tokio::test]
async fn client_verifies_transaction_entrypoint_and_output_proofs() -> Result<()> {
    let rose_def: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("asset definition"),
        "rose".parse().expect("asset definition"),
    );
    let alice_rose = AssetId::new(rose_def.clone(), ALICE_ID.clone());
    let bob_rose = AssetId::new(rose_def, BOB_ID.clone());
    let user_instruction = Transfer::asset_quantity(alice_rose.clone(), 5u32, BOB_ID.clone());
    let data_trigger_instruction =
        Transfer::asset_quantity(bob_rose.clone(), 3u32, ALICE_ID.clone());
    let genesis_key_pair = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
    let genesis_authority = AccountId::new(genesis_key_pair.public_key().clone());
    // Initialize a network with a registered data-trigger at genesis.
    let builder = NetworkBuilder::new()
        .with_genesis_keypair(genesis_key_pair)
        // The genesis submitter explicitly authorizes Alice's trigger to observe Bob's asset.
        .with_genesis_instruction(Grant::account_permission(
            CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            },
            genesis_authority,
        ))
        .with_genesis_instruction(SetParameter::new(Parameter::SmartContract(
            iroha_data_model::parameter::SmartContractParameter::ExecutionDepth(1),
        )))
        .with_genesis_instruction(Register::trigger(Trigger::new(
            "data-bob-alice-0".parse().unwrap(),
            Action::new(
                [data_trigger_instruction],
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                DataEventFilter::Asset(
                    AssetEventFilter::new()
                        .for_asset(bob_rose)
                        .for_events(AssetEventSet::Added),
                ),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        )));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(client_verifies_transaction_entrypoint_and_output_proofs),
    )
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    // Subscribe to committed block headers.
    let mut events = timeout(
        network.sync_timeout(),
        test_client.account_client().events().subscribe([BlockEventFilter::new()
            .for_height(nonzero!(2u64))
            .for_status(BlockStatus::Committed)]),
    )
    .await
    .map_err(|_| {
        eyre::eyre!(
            "client_verifies_transaction_entrypoint_and_output_proofs: timed out opening block event stream"
        )
    })??;
    // Submit the user transaction and derive its entrypoint hash.
    let tx_hash: HashOf<SignedTransaction> = spawn_blocking(move || {
        test_client.submit(
            user_instruction,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await
    .unwrap()?;
    let entrypoint_hash: HashOf<TransactionEntrypoint> =
        HashOf::from_untyped_unchecked(tx_hash.into());
    // Wait for the observed carrier header, then independently authenticate its execution below.
    let event_timeout = network.sync_timeout();
    let header = timeout(event_timeout, async {
        let EventBox::Pipeline(PipelineEventBox::Block(event)) =
            events.next().await.unwrap().unwrap()
        else {
            panic!("expected block event");
        };
        *event.header()
    })
    .await?;
    events.close().await?;
    let block_hash = header.hash();
    // The original provisioning bundle is the trust anchor; no HTTP response chooses genesis.
    let provisioned = network.native_genesis_provisioning_bundle()?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_slice(&provisioned.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &provisioned.signed_wire,
        &manifest,
        &provisioned.public_key,
        provisioned.block_hash,
    )?;
    assert_eq!(
        iroha_data_model::NetworkId::from_genesis_hash(genesis.expected_hash()),
        network.network_id(),
    );
    let validators = genesis
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect();
    let mut verifier =
        SumeragiFinalityVerifier::new(genesis.block(), network.chain_id().as_ref(), validators)?;
    let client = network
        .client()
        .client()
        .clone()
        .with_request_deadline(Instant::now() + network.sync_timeout());
    let authenticated = spawn_blocking(move || -> Result<_> {
        let mut tip = None;
        for height in 1..=header.height().get() {
            let proof = client.get_sumeragi_finality_proof(
                NonZeroU64::new(height).expect("finality prefix starts at one"),
                verifier.root_scope(),
            )?;
            tip = Some(verifier.verify(&proof)?);
        }
        tip.ok_or_else(|| eyre!("observed carrier must have a nonempty finality prefix"))
    })
    .await??;
    let carrier_block = authenticated.block();
    assert_eq!(carrier_block.hash(), block_hash);
    let (input_index, entrypoint) = carrier_block
        .network_entrypoints()
        .enumerate()
        .find(|(_, entrypoint)| entrypoint.hash() == entrypoint_hash)
        .expect("authenticated carrier contains the submitted transaction");
    let input_index = u32::try_from(input_index)?;
    let (output_index, _) = carrier_block
        .network_output_at(input_index)
        .expect("submitted transaction has one full typed network output");
    let output = carrier_block.execution_outputs()[usize::try_from(output_index)?].clone();
    let committed_tx = CommittedTransaction {
        block_hash,
        entrypoint_hash,
        entrypoint_proof: carrier_block
            .network_input_proof(input_index)
            .expect("selected network input has an inclusion proof"),
        entrypoint: entrypoint.clone(),
        output_hash: HashOf::new(&output),
        output_proof: carrier_block
            .output_proof(output_index)
            .expect("selected typed output has an inclusion proof"),
        output,
    };
    assert_eq!(*committed_tx.block_hash(), block_hash);
    assert!(
        committed_tx
            .verify_inclusion_in_authenticated_execution(carrier_block, authenticated.execution(),)
    );
    const TEST_MAX_MERKLE_LEAF_COUNT: u64 = 1_u64 << 9;
    // Verify inclusion proof for the transaction entrypoint.
    let leaf = committed_tx.entrypoint().hash();
    let proof: MerkleProof<TransactionEntrypoint> = committed_tx.entrypoint_proof().clone();
    let entrypoint_commitment = carrier_block
        .network_input_merkle_commitment()
        .expect("non-empty block should have an entrypoint commitment");
    assert!(
        entrypoint_commitment.leaf_count().get() <= TEST_MAX_MERKLE_LEAF_COUNT,
        "test carrier must remain within the explicit 512-entrypoint bound"
    );
    assert!(proof.verify(&leaf, &entrypoint_commitment));
    let wrong_entrypoint_count = NonZeroU64::new(
        entrypoint_commitment
            .leaf_count()
            .get()
            .checked_mul(2)
            .expect("test leaf count can be doubled"),
    )
    .expect("doubled leaf count remains non-zero");
    let wrong_entrypoint_commitment =
        MerkleTreeCommitment::new(*entrypoint_commitment.root(), wrong_entrypoint_count);
    assert!(
        !proof.verify(&leaf, &wrong_entrypoint_commitment),
        "the proof must reject a mismatched authenticated entrypoint count"
    );
    // Fault injection: proof should now fail for a tampered entrypoint.
    let mut tampered_tx = committed_tx.clone();
    let self_transfer = Transfer::asset_quantity(alice_rose, 100u32, ALICE_ID.clone());
    // Inject a zero-net-effect, self-neutralizing instruction.
    tampered_tx.inject_instructions([self_transfer]);
    let leaf = tampered_tx.entrypoint().hash();
    let bad_proof = tampered_tx.entrypoint_proof().clone();
    assert!(!bad_proof.verify(&leaf, &entrypoint_commitment));
    // Verify inclusion proof for the full typed transaction output.
    let leaf = HashOf::new(committed_tx.output());
    let proof: MerkleProof<ExecutionOutputV1> = committed_tx.output_proof().clone();
    let output_commitment = carrier_block
        .output_merkle_commitment()
        .expect("non-empty block should have an output commitment");
    assert!(
        output_commitment.leaf_count().get() <= TEST_MAX_MERKLE_LEAF_COUNT,
        "test carrier must remain within the explicit 512-output bound"
    );
    assert!(proof.verify(&leaf, &output_commitment));
    let wrong_output_count = NonZeroU64::new(
        output_commitment
            .leaf_count()
            .get()
            .checked_mul(2)
            .expect("test leaf count can be doubled"),
    )
    .expect("doubled leaf count remains non-zero");
    let wrong_output_commitment =
        MerkleTreeCommitment::new(*output_commitment.root(), wrong_output_count);
    assert!(
        !proof.verify(&leaf, &wrong_output_commitment),
        "the proof must reject a mismatched authenticated output count"
    );
    // Fault injection: altering the result changes the full typed output commitment.
    let mut tampered_tx = committed_tx.clone();
    tampered_tx.swap_result();
    let leaf = HashOf::new(tampered_tx.output());
    let bad_proof = tampered_tx.output_proof().clone();
    assert!(!bad_proof.verify(&leaf, &output_commitment));
    Ok(())
}
