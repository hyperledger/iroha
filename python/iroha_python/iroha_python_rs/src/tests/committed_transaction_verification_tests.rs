//! Actual native execution and independently selected checkpoint tests for selective inclusion.
use super::*;
use crate::{PyNetworkId, verify_committed_transaction_inclusion_py};
use iroha_core::{
    state::World,
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
