//! Four-validator custody of real transfer transcripts under native execution finality.
//!
//! This proves neither the q77 relation nor D7 source-manifest/spend admission.
//! TODO: join the complete production D7 owner and proof-bound source policy once
//! those paths exist; do not promote this transcript prerequisite into that gate.
use std::{
    collections::BTreeSet,
    num::NonZeroU64,
    time::{Duration, Instant},
};

use eyre::{Result, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest},
    query::QueryError,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId, ValidationFail,
    asset::AssetBalancePolicy,
    block::{
        SignedBlock,
        proofs::{BlockProofs, TrustedBlockProofAnchor},
    },
    prelude::*,
    query::error::QueryExecutionFail,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_model_base::{domain::DomainId, metadata::Metadata, peer::PeerId};
use iroha_test_network::{Network, NetworkBuilder, init_instruction_registry};
use iroha_test_samples::{ALICE_ID, gen_account_in};

const MAX_HEIGHT: u64 = 64;
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(180);

fn transfer(
    client: &Client,
    asset: AssetId,
    destination: AccountId,
    amount: u32,
) -> Result<SignedTransaction> {
    let account = client.account_client();
    let instructions: Vec<InstructionBox> =
        vec![Transfer::asset_quantity(asset, amount, destination).into()];
    let mut payload = account.prepare_transaction(
        AccountTransactionDraft::new(
            instructions,
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        )
        .with_time_to_live(Duration::from_secs(660)),
    )?;
    let quote = client.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed selected payer or gas limit"
    );
    payload.fee_payment = quote.intent;
    let signed = account.sign_transaction(payload)?;
    client.submit_transaction_and_wait(&signed)?;
    Ok(signed)
}

fn applied_transfer_height(
    status: &iroha_torii_shared::PipelineTransactionStatusResponse,
) -> Result<Option<u64>> {
    ensure!(
        status.scope == "local",
        "status escaped the selected validator"
    );
    match status.status.kind.as_str() {
        "Queued" | "Approved" | "Committed" => Ok(None),
        "Applied" => {
            ensure!(
                status.resolved_from == "state",
                "Applied status is not state-resolved"
            );
            let height = status
                .status
                .block_height
                .ok_or_else(|| eyre!("Applied transfer has no carrier height"))?;
            ensure!(
                (2..=MAX_HEIGHT).contains(&height),
                "transfer carrier height is out of bounds"
            );
            Ok(Some(height))
        }
        _ => Err(eyre!(
            "exact transfer has unexpected status {}",
            status.status.kind
        )),
    }
}

fn committed_transfer(
    network: &Network,
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<(CommittedTransaction, VerifiedSumeragiBlock)> {
    let expected = TransactionEntrypoint::External(transaction.clone());
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let reader = client.client().clone().with_request_deadline(deadline);
    loop {
        ensure!(
            Instant::now() < deadline,
            "exact transfer did not become visible on this validator"
        );
        if let Some(status) = reader.get_transaction_status_response_local(transaction.hash())? {
            if let Some(height) = applied_transfer_height(&status)? {
                // The signed exact-details route checks the input/output identity. Only
                // canonical absence is retried; malformed, unauthorized and other errors fail.
                let details = match reader.get_transaction_details(expected.hash()) {
                    Ok(details) => Some(details),
                    Err(QueryError::Validation(ValidationFail::QueryFailed(
                        QueryExecutionFail::NotFound,
                    ))) => None,
                    Err(error) => return Err(error.into()),
                };
                if let Some(details) = details {
                    let entry = details.transaction;
                    ensure!(
                        entry.entrypoint_hash() == &expected.hash()
                            && entry.entrypoint() == &expected
                            && entry.result().is_ok(),
                        "exact signed transfer did not apply"
                    );
                    // Status supplies only an untrusted bounded locator. Authenticate the
                    // whole prefix against provisioned genesis before using its carrier.
                    let verified = certified_tip(network, client, height)?;
                    ensure!(
                        entry.block_hash() == &verified.block().hash()
                            && entry.verify_inclusion_in_block(verified.block()),
                        "invalid exact transfer carrier"
                    );
                    verified.verify_committed_transaction(&network.network_id(), &entry)?;
                    return Ok((entry, verified));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn transfer_height_requires_local_applied_state_and_bounded_carrier() {
    use iroha_torii_shared::{PipelineTransactionStatus, PipelineTransactionStatusResponse};
    let original = PipelineTransactionStatusResponse::new(
        Hash::new(b"locator test").to_string(),
        PipelineTransactionStatus {
            kind: "Applied".into(),
            block_height: Some(2),
        },
        "local".into(),
        "state".into(),
    );
    assert_eq!(applied_transfer_height(&original).unwrap(), Some(2));
    let mut maximum = original.clone();
    maximum.status.block_height = Some(MAX_HEIGHT);
    assert_eq!(applied_transfer_height(&maximum).unwrap(), Some(MAX_HEIGHT));
    for kind in ["Queued", "Approved", "Committed"] {
        let mut pending = original.clone();
        pending.status.kind = kind.into();
        assert_eq!(applied_transfer_height(&pending).unwrap(), None);
    }
    for mutation in 0..9 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.scope = "global".into(),
            1 => changed.resolved_from = "cache".into(),
            2 => changed.status.block_height = None,
            3 => changed.status.block_height = Some(0),
            4 => changed.status.block_height = Some(1),
            5 => changed.status.block_height = Some(MAX_HEIGHT + 1),
            6 => changed.status.kind = "Rejected".into(),
            7 => changed.status.kind = "Expired".into(),
            8 => changed.status.kind = "Unknown".into(),
            _ => unreachable!(),
        }
        assert!(
            applied_transfer_height(&changed).is_err(),
            "mutation {mutation}"
        );
    }
}

fn selected_genesis(network: &Network) -> Result<SumeragiFinalityVerifier> {
    // This bundle comes from test provisioning, not from the peer being verified.
    let provisioned = network.native_genesis_provisioning_bundle()?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_slice(&provisioned.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &provisioned.signed_wire,
        &manifest,
        &provisioned.public_key,
        provisioned.block_hash,
    )?;
    ensure!(
        NetworkId::from_genesis_hash(genesis.expected_hash()) == network.network_id(),
        "provisioned genesis network differs"
    );
    ensure!(
        genesis.consensus_metadata().sumeragi_context.da_layout
            == iroha_sumeragi::availability::recommended_data_availability_layout(),
        "mandatory RS16 layout differs"
    );
    let validators: Vec<_> = genesis
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect();
    ensure!(
        validators.len() == 4,
        "expected exactly four genesis validators"
    );
    Ok(SumeragiFinalityVerifier::new(
        genesis.block(),
        &network.chain_id().to_string(),
        validators,
    )?)
}

fn certified_tip(network: &Network, client: &Client, height: u64) -> Result<VerifiedSumeragiBlock> {
    ensure!(
        (2..=MAX_HEIGHT).contains(&height),
        "transfer height outside bounded successor corridor"
    );
    let mut verifier = selected_genesis(network)?;
    let expected_members: BTreeSet<_> = network
        .peers()
        .iter()
        .map(|peer| peer.id().clone())
        .collect();
    ensure!(
        expected_members.len() == 4,
        "duplicate network validator identity"
    );
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let reader = client.client().clone().with_request_deadline(deadline);
    let mut tip = None;
    for next in 1..=height {
        let proof = reader.get_sumeragi_finality_proof(
            NonZeroU64::new(next).expect("positive bounded height"),
            iroha_data_model::sumeragi_finality::CertifiedResultScope::from_root_scope(
                verifier.root_scope(),
            ),
        )?;
        let verified = verifier.verify(&proof)?;
        let members: BTreeSet<_> = proof
            .committee
            .iter()
            .map(|validator| PeerId::new(validator.public_key.clone()))
            .collect();
        ensure!(
            proof.committee.len() == 4 && members == expected_members,
            "finality committee differs from provisioned validators"
        );
        if next > 1 {
            let certificate = verified
                .block()
                .commit_certificate()
                .ok_or_else(|| eyre!("certified successor lacks embedded certificate"))?;
            let qc: iroha_sumeragi::message::Qc =
                norito::decode_canonical(certificate.commit_qc())?;
            ensure!(
                qc.signers.count_ones() == 3,
                "successor must carry exact n-f quorum"
            );
            let mut corrupted = proof.clone();
            corrupted.block_wire.pop();
            ensure!(
                verifier.verify_retained_decision(&corrupted).is_err(),
                "truncated executed wire retained finality authority"
            );
            let mut missing_vote = proof.clone();
            missing_vote.committee.pop();
            ensure!(
                verifier.verify_retained_decision(&missing_vote).is_err(),
                "incomplete committee retained finality authority"
            );
        }
        ensure!(
            Instant::now() < deadline,
            "contiguous native finality exceeded deadline"
        );
        tip = Some(verified);
    }
    tip.ok_or_else(|| eyre!("empty verified prefix"))
}

fn check_transcript(
    network: &Network,
    verified: &VerifiedSumeragiBlock,
    committed: &CommittedTransaction,
    block: &SignedBlock,
    transaction: &SignedTransaction,
    asset: &AssetDefinitionId,
    destination: &AccountId,
    before: (u32, u32),
    amount: u32,
) -> Result<BlockProofs> {
    verified.verify_committed_transaction(&network.network_id(), committed)?;
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign FASTPQ transcript network",
    )));
    ensure!(
        verified
            .verify_committed_transaction(&foreign, committed)
            .is_err(),
        "foreign network admitted signed source"
    );
    let entry_hash = transaction.hash_as_entrypoint();
    let anchor = TrustedBlockProofAnchor::from_verified_finality(block, verified, &entry_hash)?;
    let proof = block
        .network_execution_proof(&entry_hash)
        .ok_or_else(|| eyre!("missing exact network execution proof"))?;
    ensure!(
        proof.verify(&anchor),
        "actual queried source proof does not match certified execution"
    );
    let call_hash = Hash::from(entry_hash);
    let bundle = proof
        .fastpq_transcripts
        .get(&call_hash)
        .ok_or_else(|| eyre!("actual transfer lacks retained FASTPQ transcript"))?;
    ensure!(
        bundle.len() == 1 && bundle[0].batch_hash == call_hash && bundle[0].deltas.len() == 1,
        "transfer transcript occurrence or call identity differs"
    );
    ensure!(
        bundle[0].poseidon_preimage_digest.is_some(),
        "transfer digest was not finalized before publication"
    );
    let delta = &bundle[0].deltas[0];
    ensure!(
        delta.from_account == *ALICE_ID
            && delta.to_account == *destination
            && delta.asset_definition == *asset,
        "transfer principal or asset differs"
    );
    ensure!(
        delta.amount == Quantity::from(amount)
            && delta.from_balance_before == Quantity::from(before.0)
            && delta.from_balance_after == Quantity::from(before.0 - amount)
            && delta.to_balance_before == Quantity::from(before.1)
            && delta.to_balance_after == Quantity::from(before.1 + amount),
        "finalized transfer quantities differ from actual funded execution"
    );
    // Each mutation keeps the native authenticated anchor untouched.
    for mutation in 0..11 {
        let mut changed = proof.clone();
        match mutation {
            0 => {
                changed.fastpq_transcripts.remove(&call_hash);
            }
            1 => changed
                .fastpq_transcripts
                .get_mut(&call_hash)
                .unwrap()
                .push(bundle[0].clone()),
            2 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0].batch_hash =
                    Hash::new(b"another execution call")
            }
            3 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0].authority_digest =
                    Hash::new(b"another authority")
            }
            4 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0].deltas[0].amount =
                    Quantity::from(amount + 1)
            }
            5 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0].deltas[0]
                    .from_balance_after = Quantity::from(before.0)
            }
            6 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0].deltas[0].to_account =
                    ALICE_ID.clone()
            }
            7 => {
                changed.fastpq_transcripts.get_mut(&call_hash).unwrap()[0]
                    .poseidon_preimage_digest = None
            }
            8 => changed.executed_block_wire_hash = Hash::new(b"another certified execution"),
            9 => changed.block_height = NonZeroU64::new(verified.height() + 1).unwrap(),
            10 => {
                changed.entry_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"another signed entry"))
            }
            _ => unreachable!(),
        }
        ensure!(
            !changed.verify(&anchor),
            "source substitution {mutation} verified"
        );
    }
    Ok(proof)
}

fn observe(
    network: &Network,
    transaction: &SignedTransaction,
    asset: &AssetDefinitionId,
    destination: &AccountId,
    before: (u32, u32),
    amount: u32,
) -> Result<(Hash, Vec<u8>)> {
    let mut expected = None;
    for peer in network.peers() {
        let client = peer.client();
        let (committed, verified) = committed_transfer(network, &client, transaction)?;
        let block = verified.block();
        let proof = check_transcript(
            network,
            &verified,
            &committed,
            block,
            transaction,
            asset,
            destination,
            before,
            amount,
        )?;
        let current = (
            verified.context_id(),
            norito::encode_canonical(&proof.fastpq_transcripts)?,
        );
        eprintln!(
            "finalized_fastpq_source peer={} height={} context={} entry={} transcript_bytes={} transcript_hash={}",
            peer.id(),
            verified.height(),
            current.0,
            transaction.hash_as_entrypoint(),
            current.1.len(),
            Hash::new(&current.1)
        );
        if let Some(original) = &expected {
            ensure!(
                *original == current,
                "validators disagree on certified execution or transcript bytes"
            );
        }
        expected = Some(current);
    }
    expected.ok_or_else(|| eyre!("no validators observed"))
}

#[test]
#[ignore = "requires same-candidate daemon and mandatory four-validator native finalized transcript custody"]
fn four_validator_fastpq_transcripts_bind_finality_and_survive_restart() -> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_REQUIRE_NETWORK").as_deref() == Ok("1"),
        "mandatory network qualification cannot skip"
    );
    init_instruction_registry();
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_config_layer(|layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1024_i64 * 1024 * 1024,
                )
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0");
        });
    let (network, rt) =
        sandbox::start_network_blocking_or_skip(builder, "fastpq_finalized_transcript_custody")?
            .ok_or_else(|| eyre!("mandatory four-validator network was skipped"))?;
    let result = (|| -> Result<()> {
        ensure!(
            network.peers().len() == 4,
            "expected exactly four validators"
        );
        rt.block_on(network.ensure_blocks(1))?;
        let client = network.client();
        let (destination, _) = gen_account_in("wonderland");
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "finalized_transcript".parse()?,
        );
        let definition = AssetDefinition::numeric(
            asset.clone(),
            "finalized transcript custody",
            AssetBalancePolicy::Global,
            Some(DomainId::try_new("wonderland", "universal")?),
        );
        let source_asset = AssetId::new(asset.clone(), ALICE_ID.clone());
        let setup: Vec<InstructionBox> = vec![
            Register::account(Account::new(destination.clone())).into(),
            Register::asset_definition(definition).into(),
            Mint::asset_quantity(200_u32, source_asset.clone()).into(),
        ];
        client.submit_all(setup, FeePaymentIntent::authority(Vec::new(), None))?;
        let first = transfer(&client, source_asset.clone(), destination.clone(), 20)?;
        let first_observation = observe(&network, &first, &asset, &destination, (200, 0), 20)?;
        let second = transfer(&client, source_asset, destination.clone(), 7)?;
        let second_observation = observe(&network, &second, &asset, &destination, (180, 20), 7)?;
        ensure!(
            first_observation.0 != second_observation.0
                && first_observation.1 != second_observation.1,
            "distinct applied transfers collapsed into one source context"
        );
        for peer in network.peers() {
            let reader = peer.client();
            let (_, first_finality) = committed_transfer(&network, &reader, &first)?;
            let (_, second_finality) = committed_transfer(&network, &reader, &second)?;
            ensure!(
                TrustedBlockProofAnchor::from_verified_finality(
                    first_finality.block(),
                    &second_finality,
                    &first.hash_as_entrypoint()
                )
                .is_err(),
                "a later valid certificate authenticated an earlier source"
            );
        }
        for peer in network.peers() {
            rt.block_on(peer.shutdown());
        }
        for peer in network.peers() {
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            rt.block_on(peer.start_checked(layers.iter(), None))?;
        }
        ensure!(
            observe(&network, &first, &asset, &destination, (200, 0), 20)? == first_observation,
            "restart changed first certified source"
        );
        ensure!(
            observe(&network, &second, &asset, &destination, (180, 20), 7)? == second_observation,
            "restart changed second certified source"
        );
        for peer in network.peers() {
            let client = peer.client();
            for (account, quantity) in [(&*ALICE_ID, 173_u32), (&destination, 27_u32)] {
                let id = AssetId::new(asset.clone(), account.clone());
                let actual = client
                    .client()
                    .query_single(FindAssetById::new(id.clone()))?;
                ensure!(
                    actual.id() == &id && actual.value() == &Quantity::from(quantity),
                    "restart duplicated or lost a financial effect"
                );
            }
        }
        Ok(())
    })();
    rt.block_on(network.shutdown());
    result
}
