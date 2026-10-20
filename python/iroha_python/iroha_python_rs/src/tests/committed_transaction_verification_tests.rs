//! Actual native execution and independently selected checkpoint tests for selective inclusion.
use super::*;
use crate::{PyNetworkId, verify_committed_transaction_inclusion_py};
use iroha_core::{
    state::{StorageReadOnly, World},
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::Hash;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    block::{SharedSignedBlock, execution_output::ExecutionOutputV1},
    isi::{InstructionBox, Log, Unregister},
    query::{QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryResponse},
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use pyo3::types::PyBytesMethods;
use std::time::Duration;

struct Fixture {
    chain: CertifiedTestChain,
    block: SharedSignedBlock,
    selected: CommittedTransaction,
    checkpoint: SumeragiFinalityCheckpoint,
    proofs: Vec<SumeragiFinalityProof>,
}
impl Fixture {
    fn new(rejected: bool) -> Self {
        let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).unwrap();
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit(Vec::new());
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let mut transaction = TransactionBuilder::new(
            chain.network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        );
        transaction.set_creation_time(Duration::from_millis(1_002));
        let instruction: InstructionBox = if rejected {
            Unregister::domain(
                iroha_model_base::domain::DomainId::try_new("absent_inclusion", "universal")
                    .unwrap(),
            )
            .into()
        } else {
            Log::new(
                iroha_data_model::Level::INFO,
                "actual selective inclusion".into(),
            )
            .into()
        };
        let transaction = transaction
            .with_instructions([instruction])
            .sign(key.private_key());
        let mut first = TransactionBuilder::new(
            chain.network_id(),
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        first.set_creation_time(Duration::from_millis(1_002));
        let first = first
            .with_instructions([Log::new(
                iroha_data_model::Level::INFO,
                "independent first output".into(),
            )])
            .sign(key.private_key());
        assert_eq!(
            chain.commit(vec![first, transaction]),
            vec![true, !rejected]
        );
        let block = chain.committed(3).block().clone();
        let output = block.network_output_at(1).unwrap().1.clone();
        let output = ExecutionOutputV1::Network(output);
        let selected = CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: block.network_entrypoint_at(1).unwrap().hash(),
            entrypoint_proof: block.network_input_proof(1).unwrap(),
            entrypoint: block.network_entrypoint_at(1).unwrap().clone(),
            output_hash: HashOf::new(&output),
            output_proof: block.output_proof(1).unwrap(),
            output,
        };
        assert!(selected.verify_inclusion_in_block(&block));
        let view = chain.state().view();
        let proofs = vec![
            build_proof(&view, 2).unwrap(),
            build_proof(&view, 3).unwrap(),
        ];
        drop(view);
        Self {
            chain,
            block,
            selected,
            checkpoint,
            proofs,
        }
    }
    fn network(&self) -> NetworkId {
        self.chain.network_id()
    }
    fn chain_json(&self) -> String {
        json::to_json(&self.proofs).unwrap()
    }
    fn checkpoint_bytes(&self) -> Vec<u8> {
        self.checkpoint.encode_canonical().unwrap()
    }
    fn verify(
        &self,
        row: &CommittedTransaction,
        proofs: &[SumeragiFinalityProof],
        checkpoint: &[u8],
    ) -> PyResult<(String, Vec<u8>)> {
        self.verify_response(
            &response(vec![row.clone()]),
            row.entrypoint_hash,
            proofs,
            self.network(),
            self.checkpoint.chain_id(),
            checkpoint,
        )
    }
    fn verify_response(
        &self,
        response: &[u8],
        expected: HashOf<TransactionEntrypoint>,
        proofs: &[SumeragiFinalityProof],
        network: NetworkId,
        label: &str,
        checkpoint: &[u8],
    ) -> PyResult<(String, Vec<u8>)> {
        pyo3::Python::attach(|py| {
            let (projection, promoted) = verify_committed_transaction_inclusion_py(
                py,
                &hex::encode(expected.as_ref()),
                response,
                &json::to_json(&proofs.to_vec()).unwrap(),
                &PyNetworkId { inner: network },
                label,
                checkpoint,
                753,
            )?;
            Ok((projection, promoted.bind(py).as_bytes().to_vec()))
        })
    }
}
fn response(rows: Vec<CommittedTransaction>) -> Vec<u8> {
    norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
        batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::CommittedTransaction(
            rows,
        )),
        remaining_items: Some(0),
        has_more: false,
        continue_cursor: None,
    }))
    .unwrap()
}

#[test]
fn native_selected_output_authenticates_real_bls_chain_and_exact_projection() {
    pyo3::Python::initialize();
    let f = Fixture::new(false);
    let checkpoint = f.checkpoint_bytes();
    let (projection, promoted) = f.verify(&f.selected, &f.proofs, &checkpoint).unwrap();
    let result: json::Value = json::from_json(&projection).unwrap();
    let (_, page) = authenticate_committed_transaction(
        f.selected.entrypoint_hash,
        &response(vec![f.selected.clone()]),
        &f.chain_json(),
        f.network(),
        f.checkpoint.chain_id(),
        &checkpoint,
    )
    .unwrap();
    let tip = page.tip();
    let wire = tip.canonical_executed_wire().unwrap();
    assert_eq!(
        result["output_hash"].as_str(),
        Some(hex::encode(f.selected.output_hash.as_ref()).as_str())
    );
    assert_eq!(
        result["block_hash"].as_str(),
        Some(hex::encode(f.block.hash().as_ref()).as_str())
    );
    assert_eq!(result["block_height"].as_u64(), Some(3));
    assert_eq!(
        result["executed_block_wire_len"].as_u64(),
        Some(wire.len() as u64)
    );
    assert_eq!(
        result["executed_block_wire_hash"].as_str(),
        Some(hex::encode(Hash::new(&wire).as_ref()).as_str())
    );
    assert_eq!(result["network_id"], json::to_value(&f.network()).unwrap());
    assert_eq!(
        result["context_id"],
        json::to_value(&tip.context_id()).unwrap()
    );
    let execution = tip.execution();
    let execution_json = &result["execution_commitment"];
    assert_eq!(execution_json.as_object().unwrap().len(), 7);
    for (field, expected) in [
        (
            "parent_state_root",
            json::to_value(&execution.parent_state_root).unwrap(),
        ),
        (
            "post_state_root",
            json::to_value(&execution.post_state_root).unwrap(),
        ),
        (
            "ordinary_writes_root",
            json::to_value(&execution.ordinary_writes_root).unwrap(),
        ),
        (
            "executed_block_wire_len",
            json::to_value(&execution.executed_block_wire_len).unwrap(),
        ),
        (
            "executed_block_wire_hash",
            json::to_value(&execution.executed_block_wire_hash).unwrap(),
        ),
    ] {
        assert_eq!(execution_json[field], expected, "{field}");
    }
    let inputs = execution.transaction_input_commitment.as_ref().unwrap();
    let outputs = execution.transaction_output_commitment.as_ref().unwrap();
    for (field, root, count) in [
        (
            "transaction_input_commitment",
            json::to_value(&inputs.root()).unwrap(),
            inputs.leaf_count().get(),
        ),
        (
            "transaction_output_commitment",
            json::to_value(&outputs.root()).unwrap(),
            outputs.leaf_count().get(),
        ),
    ] {
        let tree = &execution_json[field];
        assert_eq!(tree.as_object().unwrap().len(), 2, "{field}");
        assert_eq!(tree["root"], root, "{field}");
        assert_eq!(
            tree["leaf_count"],
            json::to_value(&count).unwrap(),
            "{field}"
        );
    }
    assert_eq!(result["result_ok"].as_bool(), Some(true));
    assert_eq!(result["proof_kind"].as_str(), Some("selective-v1"));
    assert_eq!(
        SumeragiFinalityCheckpoint::decode_canonical(&promoted)
            .unwrap()
            .height(),
        3
    );
    // An independently retained promoted checkpoint can reauthenticate its exact tip.
    assert!(f.verify(&f.selected, &f.proofs[1..], &promoted).is_ok());
    for bad in [
        f.proofs[1..].to_vec(),
        vec![f.proofs[1].clone(), f.proofs[0].clone()],
        vec![f.proofs[0].clone(), f.proofs[0].clone()],
    ] {
        assert!(f.verify(&f.selected, &bad, &checkpoint).is_err());
    }
    let mut bad = f.proofs.clone();
    let last = bad[1].block_wire.len() - 1;
    bad[1].block_wire[last] ^= 1;
    assert!(f.verify(&f.selected, &bad, &checkpoint).is_err());
    bad = f.proofs.clone();
    bad[1].block_header = f.proofs[0].block_header;
    assert!(f.verify(&f.selected, &bad, &checkpoint).is_err());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign network",
    )));
    let row = response(vec![f.selected.clone()]);
    assert!(
        f.verify_response(
            &row,
            f.selected.entrypoint_hash,
            &f.proofs,
            foreign,
            f.checkpoint.chain_id(),
            &checkpoint
        )
        .is_err()
    );
    assert!(
        f.verify_response(
            &row,
            f.selected.entrypoint_hash,
            &f.proofs,
            f.network(),
            "foreign chain",
            &checkpoint
        )
        .is_err()
    );
    assert!(
        f.verify_response(
            &row,
            HashOf::from_untyped_unchecked(Hash::new(b"other transaction")),
            &f.proofs,
            f.network(),
            f.checkpoint.chain_id(),
            &checkpoint
        )
        .is_err()
    );
    assert!(f.verify(&f.selected, &f.proofs, &[3; 32]).is_err());
    let mut trailing = checkpoint.clone();
    trailing.push(0);
    assert!(f.verify(&f.selected, &f.proofs, &trailing).is_err());
    // Export only the original executed/certified inputs and the native verifier's
    // own result. This lets an installed wheel exercise its actual PyO3 dispatch
    // against the same proof without a second handwritten fixture authority.
    if std::env::var("IROHA_PRINT_PYTHON_NATIVE_FINALITY_FIXTURE").as_deref() == Ok("1") {
        let capture = json::Value::Object(
            [
                (
                    "transaction_hash",
                    hex::encode(f.selected.entrypoint_hash.as_ref()),
                ),
                (
                    "transaction_response_hex",
                    hex::encode(response(vec![f.selected.clone()])),
                ),
                ("proof_chain_json", f.chain_json()),
                ("network_id", f.network().to_string()),
                ("chain_id", f.checkpoint.chain_id().to_owned()),
                ("trusted_checkpoint_hex", hex::encode(&checkpoint)),
                ("expected_projection_json", projection),
                ("promoted_checkpoint_hex", hex::encode(&promoted)),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), json::Value::from(value)))
            .collect(),
        );
        println!(
            "PYTHON_NATIVE_FINALITY_FIXTURE={}",
            json::to_json(&capture).unwrap()
        );
    }
}

#[test]
fn native_selected_output_rejects_rehashed_outputs_and_swapped_rows() {
    pyo3::Python::initialize();
    let f = Fixture::new(false);
    let checkpoint = f.checkpoint_bytes();
    let mut changed = f.selected.clone();
    let ExecutionOutputV1::Network(output) = &mut changed.output else {
        panic!("native network output")
    };
    output.result = Err(
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted("substituted result".into()),
        ),
    )
    .into();
    changed.output_hash = HashOf::new(&changed.output);
    assert!(f.verify(&changed, &f.proofs, &checkpoint).is_err());
    let mut swapped = f.selected.clone();
    swapped.output = f.block.execution_outputs()[0].clone();
    swapped.output_hash = HashOf::new(&swapped.output);
    swapped.output_proof = f.block.output_proof(0).unwrap();
    assert!(f.verify(&swapped, &f.proofs, &checkpoint).is_err());
    // This forged internal output is only hostile query input, never executed or certified.
    let mut internal = f.selected.clone();
    internal.output = ExecutionOutputV1::time_output_limit_rejection(
        iroha_data_model::block::execution_output::TimeInvocationV1 {
            schedule_index: 0,
            event: iroha_data_model::events::time::TimeEvent {
                interval: iroha_data_model::events::time::TimeInterval {
                    since_ms: 1_001,
                    length_ms: 1,
                },
            },
            trigger: iroha_data_model::block::execution_output::TriggerUseV1 {
                trigger_id: "forged-internal-output".parse().unwrap(),
                registered_at_height: 0,
                action_hash: Hash::new(b"untrusted trigger claim"),
            },
        },
    );
    internal.output_hash = HashOf::new(&internal.output);
    assert!(f.verify(&internal, &f.proofs, &checkpoint).is_err());
    let mut wrong_input = f.selected.clone();
    wrong_input.entrypoint = f.block.network_entrypoint_at(0).unwrap().clone();
    wrong_input.entrypoint_hash = wrong_input.entrypoint.hash();
    wrong_input.entrypoint_proof = f.block.network_input_proof(0).unwrap();
    assert!(f.verify(&wrong_input, &f.proofs, &checkpoint).is_err());
    let mut query = response(vec![f.selected.clone()]);
    query.push(0);
    assert!(
        f.verify_response(
            &query,
            f.selected.entrypoint_hash,
            &f.proofs,
            f.network(),
            f.checkpoint.chain_id(),
            &checkpoint
        )
        .is_err()
    );
    assert!(
        f.verify_response(
            &response(vec![f.selected.clone(), f.selected.clone()]),
            f.selected.entrypoint_hash,
            &f.proofs,
            f.network(),
            f.checkpoint.chain_id(),
            &checkpoint
        )
        .is_err()
    );
    assert!(f.verify(&f.selected, &[], &checkpoint).is_err());
}

#[test]
fn native_selected_output_authenticates_actual_rejected_execution() {
    pyo3::Python::initialize();
    let f = Fixture::new(true);
    let (projection, promoted) = f
        .verify(&f.selected, &f.proofs, &f.checkpoint_bytes())
        .unwrap();
    let result: json::Value = json::from_json(&projection).unwrap();
    assert_eq!(result["result_ok"].as_bool(), Some(false));
    assert!(result["rejection_code"].as_str().is_some());
    assert_eq!(
        SumeragiFinalityCheckpoint::decode_canonical(&promoted)
            .unwrap()
            .height(),
        3
    );
}

#[test]
fn native_selected_output_rejects_chain_resource_overflow_before_authentication() {
    pyo3::Python::initialize();
    let f = Fixture::new(false);
    let error = authenticate_committed_transaction(
        f.selected.entrypoint_hash,
        &response(vec![f.selected.clone()]),
        &" ".repeat(MAX_FINALITY_CHAIN_JSON_BYTES + 1),
        f.network(),
        f.checkpoint.chain_id(),
        &f.checkpoint_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("16 MiB"));
    // Small structurally decodable candidates exercise count refusal before crypto.
    let mut candidate = f.proofs[0].clone();
    candidate.block_wire.clear();
    candidate.committee.clear();
    let proofs = vec![candidate; MAX_FINALITY_CHAIN_PROOFS + 1];
    let error = f
        .verify(&f.selected, &proofs, &f.checkpoint_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("1..4096"));
}

#[test]
fn native_selected_output_account_context_matrix_uses_real_authenticated_wire() {
    pyo3::Python::initialize();
    let fixture = Fixture::new(false);
    let row = response(vec![fixture.selected.clone()]);
    let checkpoint = fixture.checkpoint_bytes();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    let mut prior_promoted = None;
    pyo3::Python::attach(|py| {
        for prefix in [117, 369, 753, 117] {
            let (projection, promoted) = verify_committed_transaction_inclusion_py(
                py,
                &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                &row,
                &fixture.chain_json(),
                &PyNetworkId {
                    inner: fixture.network(),
                },
                fixture.checkpoint.chain_id(),
                &checkpoint,
                prefix,
            )
            .unwrap();
            let decoded: json::Value = json::from_json(&projection).unwrap();
            let authority = fixture
                .selected
                .entrypoint
                .authority_opt()
                .unwrap()
                .to_i105_for_discriminant(prefix)
                .unwrap();
            assert_eq!(
                decoded.get("authority").and_then(json::Value::as_str),
                Some(authority.as_str())
            );
            let promoted = promoted.bind(py).as_bytes().to_vec();
            if let Some(prior) = &prior_promoted {
                assert_eq!(&promoted, prior);
            } else {
                prior_promoted = Some(promoted);
            }
            let mut malformed = row.clone();
            malformed.push(0);
            assert!(
                verify_committed_transaction_inclusion_py(
                    py,
                    &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                    &malformed,
                    &fixture.chain_json(),
                    &PyNetworkId {
                        inner: fixture.network()
                    },
                    fixture.checkpoint.chain_id(),
                    &checkpoint,
                    prefix
                )
                .is_err()
            );
            assert_eq!(
                iroha_data_model::account::address::chain_discriminant(),
                ambient
            );
        }
    });
}

struct CertifiedBatchContextFixture {
    inclusion: Fixture,
    sender: AccountId,
    recipient: AccountId,
    definition: iroha_data_model::asset::AssetDefinitionId,
}

impl CertifiedBatchContextFixture {
    fn new() -> Self {
        use iroha_core::state::WorldReadOnly as _;
        use iroha_data_model::{
            asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
            domain::Domain,
            events::data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferRejectionCode},
            isi::{TransferAssetBatch, TransferAssetBatchEntry},
        };
        use iroha_primitives::numeric::Quantity;

        let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).unwrap();
        let recipient_key = KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).unwrap();
        let sender = AccountId::new(key.public_key().clone());
        let recipient = AccountId::new(recipient_key.public_key().clone());
        let domain =
            iroha_model_base::domain::DomainId::try_new("prefix-receipts", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
        let source_asset = AssetId::new(definition.clone(), sender.clone());
        let destination_asset = AssetId::new(definition.clone(), recipient.clone());
        let world = World::with_assets(
            [Domain::new(domain).build(&sender)],
            [
                Account::new(sender.clone()).build(&sender),
                Account::new(recipient.clone()).build(&sender),
            ],
            [AssetDefinition::numeric(
                definition.clone(),
                "prefix receipt coin",
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender)],
            [Asset::new(source_asset.clone(), 10_u32)],
            [],
        );
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit(Vec::new());
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let batch = TransferAssetBatch::independent(vec![
            TransferAssetBatchEntry::with_leg_id(
                "paid",
                sender.clone(),
                recipient.clone(),
                definition.clone(),
                3_u32,
            ),
            TransferAssetBatchEntry::with_leg_id(
                "insufficient",
                sender.clone(),
                recipient.clone(),
                definition.clone(),
                1_000_u32,
            ),
        ]);
        let mut builder = TransactionBuilder::new(
            chain.network_id(),
            sender.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1_002));
        let transaction = builder.with_instructions([batch]).sign(key.private_key());
        // Real ordinary admission/execution and actual BLS Commit QCs. No result,
        // output leaf, proof, or balance is manufactured by the fixture.
        assert_eq!(chain.commit(vec![transaction]), vec![true]);
        let block = chain.committed(3).block().clone();
        let output = ExecutionOutputV1::Network(block.network_output_at(0).unwrap().1.clone());
        let selected = CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: block.network_entrypoint_at(0).unwrap().hash(),
            entrypoint_proof: block.network_input_proof(0).unwrap(),
            entrypoint: block.network_entrypoint_at(0).unwrap().clone(),
            output_hash: HashOf::new(&output),
            output_proof: block.output_proof(0).unwrap(),
            output,
        };
        assert!(selected.verify_inclusion_in_block(&block));
        let outcomes = selected.result().batch_transfer_outcomes();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].asset, source_asset);
        assert_eq!(outcomes[0].destination, recipient);
        assert_eq!(outcomes[0].amount, Quantity::from(3_u32));
        assert!(matches!(
            &outcomes[0].status,
            AssetBatchTransferLegStatus::Applied
        ));
        assert_eq!(outcomes[1].asset, source_asset);
        assert_eq!(outcomes[1].destination, recipient);
        assert!(
            matches!(&outcomes[1].status, AssetBatchTransferLegStatus::Rejected(rejection)
            if rejection.code == AssetBatchTransferRejectionCode::InsufficientFunds)
        );
        let view = chain.state().view();
        assert_eq!(
            view.world().assets().get(&source_asset).unwrap().as_ref(),
            &Quantity::from(7_u32)
        );
        assert_eq!(
            view.world()
                .assets()
                .get(&destination_asset)
                .unwrap()
                .as_ref(),
            &Quantity::from(3_u32)
        );
        let proofs = vec![
            build_proof(&view, 2).unwrap(),
            build_proof(&view, 3).unwrap(),
        ];
        drop(view);
        Self {
            inclusion: Fixture {
                chain,
                block,
                selected,
                checkpoint,
                proofs,
            },
            sender,
            recipient,
            definition,
        }
    }
}

#[test]
fn native_selected_batch_output_context_matrix_preserves_real_crypto_and_nested_accounts() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    pyo3::Python::initialize();
    let batch = CertifiedBatchContextFixture::new();
    let fixture = &batch.inclusion;
    let row = response(vec![fixture.selected.clone()]);
    let row_hash = Hash::new(&row);
    let checkpoint = fixture.checkpoint_bytes();
    let checkpoint_hash = Hash::new(&checkpoint);
    let proofs_json = fixture.chain_json();
    let (authenticated, page) = authenticate_committed_transaction(
        fixture.selected.entrypoint_hash,
        &row,
        &proofs_json,
        fixture.network(),
        fixture.checkpoint.chain_id(),
        &checkpoint,
    )
    .unwrap();
    assert_eq!(authenticated, fixture.selected);
    let promoted_reference = page.checkpoint().encode_canonical().unwrap();
    let executed_wire = page.tip().canonical_executed_wire().unwrap();
    let executed_wire_hash = hex::encode(Hash::new(&executed_wire).as_ref());
    let output_wire = norito::to_bytes(&fixture.selected.output).unwrap();
    let entrypoint_wire = fixture.selected.entrypoint.encode_wire_v1().unwrap();
    let TransactionEntrypoint::External(signed) = &fixture.selected.entrypoint else {
        panic!("fixture is one real native external transfer batch");
    };
    let signed_wire = signed.encode_wire_v1().unwrap();
    let signature = signed.signature().clone();
    let ambient = chain_discriminant();
    let mut stable_projection = None;
    pyo3::Python::attach(|py| {
        for prefix in [117, 369, 753, 369, 117, 753] {
            let (projection, promoted) = verify_committed_transaction_inclusion_py(
                py,
                &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                &row,
                &proofs_json,
                &PyNetworkId {
                    inner: fixture.network(),
                },
                fixture.checkpoint.chain_id(),
                &checkpoint,
                prefix,
            )
            .unwrap();
            let projected: json::Value = json::from_json(&projection).unwrap();
            let sender = batch.sender.to_i105_for_discriminant(prefix).unwrap();
            let recipient = batch.recipient.to_i105_for_discriminant(prefix).unwrap();
            let asset = format!("{}#{sender}", batch.definition);
            assert_eq!(projected["authority"].as_str(), Some(sender.as_str()));
            assert_eq!(projected["result_ok"].as_bool(), Some(true));
            let outcomes = projected["batch_outcomes"].as_array().unwrap();
            let nested = projected["committed_transaction"]["output"]["detail"]["result"]["batch_transfer_outcomes"].as_array().unwrap();
            assert_eq!(outcomes.len(), 2);
            assert_eq!(nested.len(), 2);
            for (index, (leg, amount, status)) in [
                ("paid", "3", "Applied"),
                ("insufficient", "1000", "Rejected"),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(outcomes[index]["leg_index"].as_u64(), Some(index as u64));
                assert_eq!(outcomes[index]["leg_id"].as_str(), Some(leg));
                assert_eq!(outcomes[index]["amount"].as_str(), Some(amount));
                assert_eq!(outcomes[index]["status"].as_str(), Some(status));
                assert_eq!(outcomes[index]["asset"].as_str(), Some(asset.as_str()));
                assert_eq!(
                    outcomes[index]["destination"].as_str(),
                    Some(recipient.as_str())
                );
                assert_eq!(nested[index]["asset"].as_str(), Some(asset.as_str()));
                assert_eq!(
                    nested[index]["destination"].as_str(),
                    Some(recipient.as_str())
                );
            }
            assert_eq!(outcomes[0]["rejection_code"], json::Value::Null);
            assert_eq!(
                outcomes[1]["rejection_code"].as_str(),
                Some("InsufficientFunds")
            );
            let iroha_data_model::events::data::prelude::AssetBatchTransferLegStatus::Rejected(
                rejection,
            ) = &fixture.selected.result().batch_transfer_outcomes()[1].status
            else {
                unreachable!()
            };
            assert_eq!(
                outcomes[1]["rejection_message"].as_str(),
                Some(rejection.message.as_str())
            );
            assert_eq!(
                projected["output_hash"].as_str(),
                Some(hex::encode(fixture.selected.output_hash.as_ref()).as_str())
            );
            assert_eq!(
                projected["executed_block_wire_hash"].as_str(),
                Some(executed_wire_hash.as_str())
            );
            assert_eq!(
                projected["executed_block_wire_len"].as_u64(),
                Some(executed_wire.len() as u64)
            );
            assert_eq!(promoted.bind(py).as_bytes(), promoted_reference.as_slice());
            {
                let _guard = ChainDiscriminantGuard::enter(prefix);
                assert_eq!(
                    projected["committed_transaction"],
                    json::to_value(&fixture.selected).unwrap()
                );
                let decoded: CommittedTransaction =
                    json::from_value(projected["committed_transaction"].clone()).unwrap();
                assert_eq!(decoded, fixture.selected);
                assert_eq!(norito::to_bytes(&decoded.output).unwrap(), output_wire);
                assert_eq!(
                    decoded.entrypoint.encode_wire_v1().unwrap(),
                    entrypoint_wire
                );
            }
            // Only presentation-bearing fields vary. All other public fields,
            // including roots, hashes, proofs' context and wire length, remain exact.
            let mut stable = projected.clone();
            for field in ["authority", "batch_outcomes", "committed_transaction"] {
                stable.as_object_mut().unwrap().remove(field);
            }
            if let Some(reference) = &stable_projection {
                assert_eq!(&stable, reference);
            } else {
                stable_projection = Some(stable);
            }

            let envelope = crate::signed_transaction_envelope_from_versioned_v1_py(
                &signed_wire,
                &PyNetworkId {
                    inner: fixture.network(),
                },
                prefix,
            )
            .unwrap();
            assert_eq!(envelope.authority, sender);
            let envelope_json = envelope.to_json().unwrap();
            let envelope_type = py.get_type::<crate::SignedTransactionEnvelope>();
            assert_eq!(
                crate::SignedTransactionEnvelope::from_json(&envelope_type, &envelope_json, prefix)
                    .unwrap()
                    .signed_transaction_versioned,
                signed_wire
            );
            for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                // Selection is independent of NetworkId; the projection itself
                // may be rendered under any explicit u16. Exact-account imports
                // must nevertheless reject a different selected presentation.
                assert!(
                    crate::parse_selected_account_id(&sender, "projected authority", foreign)
                        .is_err()
                );
                assert!(
                    crate::parse_selected_account_id(&recipient, "projected destination", foreign)
                        .is_err()
                );
                assert!(
                    crate::SignedTransactionEnvelope::from_json(
                        &envelope_type,
                        &envelope_json,
                        foreign
                    )
                    .is_err()
                );
            }

            let mut forged = fixture.selected.clone();
            let ExecutionOutputV1::Network(output) = &mut forged.output else {
                unreachable!()
            };
            output.result.1[0].destination = batch.sender.clone();
            assert_ne!(HashOf::new(&forged.output), fixture.selected.output_hash);
            // Both an old hash and a recomputed substituted hash fail actual
            // inclusion authentication; prefix rendering cannot legitimize either.
            for recompute in [false, true] {
                if recompute {
                    forged.output_hash = HashOf::new(&forged.output);
                }
                assert!(
                    verify_committed_transaction_inclusion_py(
                        py,
                        &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                        &response(vec![forged.clone()]),
                        &proofs_json,
                        &PyNetworkId {
                            inner: fixture.network()
                        },
                        fixture.checkpoint.chain_id(),
                        &checkpoint,
                        prefix
                    )
                    .is_err()
                );
                assert_eq!(chain_discriminant(), ambient);
            }
            let mut malformed = row.clone();
            malformed.push(0);
            assert!(
                verify_committed_transaction_inclusion_py(
                    py,
                    &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                    &malformed,
                    &proofs_json,
                    &PyNetworkId {
                        inner: fixture.network()
                    },
                    fixture.checkpoint.chain_id(),
                    &checkpoint,
                    prefix
                )
                .is_err()
            );
            let (again, promoted_again) = verify_committed_transaction_inclusion_py(
                py,
                &hex::encode(fixture.selected.entrypoint_hash.as_ref()),
                &row,
                &proofs_json,
                &PyNetworkId {
                    inner: fixture.network(),
                },
                fixture.checkpoint.chain_id(),
                &checkpoint,
                prefix,
            )
            .unwrap();
            assert_eq!(again, projection);
            assert_eq!(
                promoted_again.bind(py).as_bytes(),
                promoted_reference.as_slice()
            );
            assert_eq!(Hash::new(&row), row_hash);
            assert_eq!(Hash::new(&checkpoint), checkpoint_hash);
            assert_eq!(
                norito::to_bytes(&fixture.selected.output).unwrap(),
                output_wire
            );
            assert_eq!(
                fixture.selected.entrypoint.encode_wire_v1().unwrap(),
                entrypoint_wire
            );
            assert_eq!(signed.signature(), &signature);
            signed.verify_signature().unwrap();
            assert_eq!(chain_discriminant(), ambient);
        }
    });
}

fn details_wire(row: &CommittedTransaction) -> Vec<u8> {
    norito::to_bytes(&iroha_torii_shared::PipelineTransactionDetailsResponse {
        hash: row.entrypoint_hash.to_string(),
        transaction: row.clone(),
    })
    .unwrap()
}

fn verify_details_fixture(f: &Fixture, wire: &[u8], prefix: u16) -> PyResult<(String, Vec<u8>)> {
    pyo3::Python::attach(|py| {
        let (projection, promoted) =
            crate::transaction_details::verify_transaction_details_inclusion(
                py,
                &hex::encode(f.selected.entrypoint_hash.as_ref()),
                &pyo3::types::PyBytes::new(py, wire),
                &f.chain_json(),
                &PyNetworkId { inner: f.network() },
                f.checkpoint.chain_id(),
                &pyo3::types::PyBytes::new(py, &f.checkpoint_bytes()),
                prefix,
            )?;
        Ok((projection, promoted.bind(py).as_bytes().to_vec()))
    })
}

#[test]
fn native_details_receipts_share_real_accepted_rejected_and_mixed_batch_producer() {
    pyo3::Python::initialize();
    let batch = CertifiedBatchContextFixture::new();
    for f in [&Fixture::new(false), &Fixture::new(true), &batch.inclusion] {
        let wire = details_wire(&f.selected);
        for prefix in [117, 369, 753] {
            let (details, promoted) = verify_details_fixture(f, &wire, prefix).unwrap();
            let (query, query_promoted) = pyo3::Python::attach(|py| {
                let (projection, promoted) = verify_committed_transaction_inclusion_py(
                    py,
                    &hex::encode(f.selected.entrypoint_hash.as_ref()),
                    &response(vec![f.selected.clone()]),
                    &f.chain_json(),
                    &PyNetworkId { inner: f.network() },
                    f.checkpoint.chain_id(),
                    &f.checkpoint_bytes(),
                    prefix,
                )
                .unwrap();
                (projection, promoted.bind(py).as_bytes().to_vec())
            });
            assert_eq!(details, query);
            assert_eq!(promoted, query_promoted);
            assert_eq!(wire, details_wire(&f.selected));
            let projected: json::Value = json::from_json(&details).unwrap();
            assert_eq!(
                projected["result_ok"].as_bool(),
                Some(f.selected.result().is_ok())
            );
            assert_eq!(
                projected["batch_outcomes"].as_array().unwrap().len(),
                f.selected.result().batch_transfer_outcomes().len()
            );
        }
    }
}

#[test]
fn native_details_refuse_wrong_original_frame_hash_row_output_and_root() {
    pyo3::Python::initialize();
    let f = Fixture::new(false);
    let expected = f.selected.entrypoint_hash;
    let wire = details_wire(&f.selected);
    let mut altered = wire.clone();
    altered.push(0);
    assert!(verify_details_fixture(&f, &altered, 369).is_err());
    assert!(verify_details_fixture(&f, &response(vec![f.selected.clone()]), 369).is_err());
    assert!(verify_details_fixture(&f, &[], 369).is_err());
    let other = HashOf::from_untyped_unchecked(Hash::new(b"unrelated details row"));
    let wrong_hash = iroha_torii_shared::PipelineTransactionDetailsResponse {
        hash: other.to_string(),
        transaction: f.selected.clone(),
    };
    assert!(verify_details_fixture(&f, &norito::to_bytes(&wrong_hash).unwrap(), 369).is_err());
    let mut wrong_row = wrong_hash.clone();
    wrong_row.hash = expected.to_string();
    wrong_row.transaction.entrypoint_hash = other;
    assert!(verify_details_fixture(&f, &norito::to_bytes(&wrong_row).unwrap(), 369).is_err());
    let mut wrong_output = f.selected.clone();
    wrong_output.output = f.block.execution_outputs()[0].clone();
    wrong_output.output_hash = HashOf::new(&wrong_output.output);
    wrong_output.output_proof = f.block.output_proof(0).unwrap();
    assert!(verify_details_fixture(&f, &details_wire(&wrong_output), 369).is_err());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign details network",
    )));
    for (network, chain, checkpoint) in [
        (foreign, f.checkpoint.chain_id(), f.checkpoint_bytes()),
        (f.network(), "wrong-chain", f.checkpoint_bytes()),
        (f.network(), f.checkpoint.chain_id(), vec![3; 32]),
    ] {
        assert!(
            authenticate_selected_response(
                expected,
                &wire,
                &f.chain_json(),
                network,
                chain,
                &checkpoint,
                |bytes| crate::transaction_details::decode_bound_details(expected, bytes)
            )
            .is_err()
        );
    }
    pyo3::Python::attach(|py| {
        let hash = crate::transaction_details::transaction_details_carrier_block_hash(
            &hex::encode(expected.as_ref()),
            &pyo3::types::PyBytes::new(py, &wire),
        )
        .unwrap();
        assert_eq!(hash, hex::encode(f.block.hash().as_ref()));
        assert!(
            crate::transaction_details::transaction_details_carrier_block_hash(
                &hex::encode(other.as_ref()),
                &pyo3::types::PyBytes::new(py, &wire)
            )
            .is_err()
        );
    });
}

#[test]
fn native_details_builder_selects_only_exact_hash_and_preserves_reader_context() {
    use iroha_data_model::query::dsl::{CompoundPredicate, SelectorTuple};
    use iroha_data_model::query::parameters::QueryParams;
    use iroha_data_model::query::{CommittedTxFilters, QueryItemKind, QueryRequest, SignedQuery};
    use iroha_version::codec::DecodeVersioned as _;
    use norito::codec::Encode as _;
    pyo3::Python::initialize();
    let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let (_, private) = key.private_key().to_bytes();
    let expected = HashOf::from_untyped_unchecked(Hash::new(b"details-builder"));
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"details-query-network",
    )));
    pyo3::Python::attach(|py| {
        for prefix in [117, 369, 753] {
            let selected = authority.to_i105_for_discriminant(prefix).unwrap();
            let build = || {
                crate::transaction_details::build_find_transaction_details_query(
                    py,
                    &selected,
                    &pyo3::types::PyBytes::new(py, &private),
                    &PyNetworkId { inner: network },
                    &hex::encode(expected.as_ref()),
                    prefix,
                )
                .unwrap()
            };
            let first = build();
            let second = build();
            // Bound the actual signed details fixture for the planned transport request cap.
            assert!(!first.bind(py).as_bytes().is_empty());
            assert!(first.bind(py).as_bytes().len() <= 64 * 1024);
            assert!(second.bind(py).as_bytes().len() <= 64 * 1024);
            let signed = SignedQuery::decode_all_versioned(first.bind(py).as_bytes()).unwrap();
            let again = SignedQuery::decode_all_versioned(second.bind(py).as_bytes()).unwrap();
            signed.verify_signature().unwrap();
            assert_eq!(signed.authority(), &authority);
            assert_eq!(signed.payload.network_id(), network);
            assert_ne!(signed.payload.nonce(), again.payload.nonce());
            assert_eq!(signed.payload.time_to_live_ms().get(), 100_000);
            let QueryRequest::Start(query) = signed.request() else {
                panic!("start query")
            };
            let (kind, predicate, selector, payload) = query.parts();
            assert_eq!(kind, QueryItemKind::CommittedTransaction);
            assert_eq!(query.params(), &QueryParams::default());
            assert_eq!(
                payload,
                iroha_data_model::query::transaction::FindTransactions.encode()
            );
            assert_eq!(
                selector,
                SelectorTuple::<CommittedTransaction>::default().encode()
            );
            assert_eq!(
                predicate,
                CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
                    entry_eq: Some(expected),
                    ..CommittedTxFilters::default()
                })
                .encode()
            );
            let wrong = if prefix == 369 { 753 } else { 369 };
            assert!(
                crate::transaction_details::build_find_transaction_details_query(
                    py,
                    &selected,
                    &pyo3::types::PyBytes::new(py, &private),
                    &PyNetworkId { inner: network },
                    &hex::encode(expected.as_ref()),
                    wrong
                )
                .is_err()
            );
        }
    });
}
