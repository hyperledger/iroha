//! Actual native execution and independently selected checkpoint tests for selective inclusion.
use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    block::{
        BlockHeader, SharedSignedBlock,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    },
    isi::{InstructionBox, Log, Unregister},
    query::{QueryOutput, QueryOutputBatchBoxTuple},
    transaction::{FeePaymentIntent, TransactionBuilder},
};
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
        assert_eq!(chain.commit(vec![transaction]), vec![!rejected]);
        let block = chain.committed(3).block().clone();
        let output = block.network_output_at(0).unwrap().1.clone();
        let output = ExecutionOutputV1::Network(output);
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
    fn chain_json(&self) -> Vec<u8> {
        json::to_vec(&self.proofs).unwrap()
    }
    fn checkpoint_bytes(&self) -> Vec<u8> {
        self.checkpoint.encode_canonical().unwrap()
    }
    fn verify(&self, response_bytes: &[u8]) -> Result<VerifiedCommittedTransaction, String> {
        verify_committed_transaction_inclusion(
            response_bytes,
            &self.chain_json(),
            self.network(),
            self.checkpoint.chain_id(),
            &self.checkpoint_bytes(),
            self.selected.entrypoint_hash,
        )
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
fn checkpoint_page_requires_signed_consecutive_chain_from_independent_context() {
    let fixture = Fixture::new(false);
    let page = verify_checkpoint_page(
        fixture.network(),
        &fixture.checkpoint,
        &fixture.proofs,
        MAX_CHAIN_PROOFS,
        MAX_CHAIN_JSON_BYTES,
    )
    .unwrap();
    assert_eq!(page.checkpoint().network_id(), fixture.network());
    assert_eq!(page.checkpoint().height(), 3);
    assert_eq!(page.checkpoint().block_hash(), fixture.block.hash());

    let wrong_checkpoint = build_checkpoint(&fixture.chain.state().view(), 1).unwrap();
    assert!(
        verify_checkpoint_page(
            fixture.network(),
            &wrong_checkpoint,
            &fixture.proofs,
            MAX_CHAIN_PROOFS,
            MAX_CHAIN_JSON_BYTES,
        )
        .is_err()
    );
    let wrong_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign inclusion network",
    )));
    assert!(
        verify_checkpoint_page(
            wrong_network,
            &fixture.checkpoint,
            &fixture.proofs,
            MAX_CHAIN_PROOFS,
            MAX_CHAIN_JSON_BYTES,
        )
        .is_err()
    );
    let repeated = [fixture.proofs[0].clone(), fixture.proofs[0].clone()];
    assert!(
        verify_checkpoint_page(
            fixture.network(),
            &fixture.checkpoint,
            &repeated,
            MAX_CHAIN_PROOFS,
            MAX_CHAIN_JSON_BYTES,
        )
        .is_err()
    );
}

#[test]
fn authentic_current_row_and_four_negative_evidence_cases() {
    let fixture = Fixture::new(false);
    let selected = &fixture.selected;
    let selected_response = response(vec![selected.clone()]);
    let verified = fixture.verify(&selected_response).unwrap();
    assert_eq!(verified.row, norito::to_bytes(selected).unwrap());
    assert_eq!(verified.output_hash, *selected.output_hash.as_ref());
    assert_eq!(verified.block_hash, *fixture.block.hash().as_ref());
    assert_eq!(verified.block_height, 3);
    assert!(verified.result_ok);
    assert_eq!(
        candidate_block_hash(&selected_response, selected.entrypoint_hash).unwrap(),
        Some(verified.block_hash)
    );
    let promoted = SumeragiFinalityCheckpoint::decode_canonical(&verified.checkpoint).unwrap();
    assert_eq!(promoted.height(), 3);
    assert_eq!(promoted.block_hash(), fixture.block.hash());
    let wrong_network = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"foreign network")),
    );
    assert!(
        verify_committed_transaction_inclusion(
            &selected_response,
            &fixture.chain_json(),
            wrong_network,
            fixture.checkpoint.chain_id(),
            &fixture.checkpoint_bytes(),
            selected.entrypoint_hash
        )
        .is_err()
    );
    assert!(
        verify_committed_transaction_inclusion(
            &selected_response,
            &fixture.chain_json(),
            fixture.network(),
            "foreign-chain",
            &fixture.checkpoint_bytes(),
            selected.entrypoint_hash
        )
        .is_err()
    );
    let mut altered_proofs = fixture.proofs.clone();
    let last_byte = altered_proofs[1].block_wire.last_mut().unwrap();
    *last_byte ^= 1;
    assert!(
        verify_committed_transaction_inclusion(
            &selected_response,
            &json::to_vec(&altered_proofs).unwrap(),
            fixture.network(),
            fixture.checkpoint.chain_id(),
            &fixture.checkpoint_bytes(),
            selected.entrypoint_hash
        )
        .is_err()
    );
    let wrong_transaction = HashOf::from_untyped_unchecked(Hash::new(b"wrong transaction"));
    assert!(
        verify_committed_transaction_inclusion(
            &selected_response,
            &fixture.chain_json(),
            fixture.network(),
            fixture.checkpoint.chain_id(),
            &fixture.checkpoint_bytes(),
            wrong_transaction
        )
        .is_err()
    );
    assert!(candidate_block_hash(&selected_response, wrong_transaction).is_err());
    let mut altered_output = selected.clone();
    altered_output.output_hash = HashOf::from_untyped_unchecked(Hash::new(b"mismatched output"));
    assert!(fixture.verify(&response(vec![altered_output])).is_err());
    let mut rehashed_output = selected.clone();
    rehashed_output.output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: Err(
            iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted("replacement result".into()),
            ),
        )
        .into(),
        completions: Vec::new(),
    });
    rehashed_output.output_hash = HashOf::new(&rehashed_output.output);
    assert!(fixture.verify(&response(vec![rehashed_output])).is_err());
    for checkpoint in [vec![], vec![0x71; 32], {
        let mut bytes = fixture.checkpoint_bytes();
        bytes.push(0);
        bytes
    }] {
        assert!(
            verify_committed_transaction_inclusion(
                &selected_response,
                &fixture.chain_json(),
                fixture.network(),
                fixture.checkpoint.chain_id(),
                &checkpoint,
                selected.entrypoint_hash
            )
            .is_err()
        );
    }
}

#[test]
fn actual_rejected_execution_remains_authenticated_and_promotes_its_checkpoint() {
    let fixture = Fixture::new(true);
    let verified = fixture
        .verify(&response(vec![fixture.selected.clone()]))
        .unwrap();
    assert!(!verified.result_ok);
    assert_eq!(verified.row, norito::to_bytes(&fixture.selected).unwrap());
    assert_eq!(
        SumeragiFinalityCheckpoint::decode_canonical(&verified.checkpoint)
            .unwrap()
            .block_hash(),
        fixture.block.hash()
    );
}

#[test]
fn candidate_distinguishes_exact_empty_page_from_invalid_evidence() {
    let fixture = Fixture::new(false);
    let selected = fixture.selected.clone();
    let empty = response(Vec::new());
    assert_eq!(
        candidate_block_hash(&empty, selected.entrypoint_hash).unwrap(),
        None,
    );
    assert!(decode_single_response(&empty).is_err());

    let mut output = [0xff; 32];
    let status = unsafe {
        connect_norito_committed_transaction_candidate_block_hash_v1(
            empty.as_ptr(),
            empty.len() as c_ulong,
            selected.entrypoint_hash.as_ref().as_ptr(),
            32,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, 1);
    assert_eq!(output, [0; 32]);

    let multirow = response(vec![selected.clone(), selected.clone()]);
    assert!(candidate_block_hash(&multirow, selected.entrypoint_hash).is_err());
    let mut output = [0xff; 32];
    let status = unsafe {
        connect_norito_committed_transaction_candidate_block_hash_v1(
            multirow.as_ptr(),
            multirow.len() as c_ulong,
            selected.entrypoint_hash.as_ref().as_ptr(),
            32,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, ERR_COMMITTED_INCLUSION);
    assert_eq!(output, [0; 32]);
    let foreign = norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
        batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Numeric(vec![])),
        remaining_items: Some(0),
        has_more: false,
        continue_cursor: None,
    }))
    .unwrap();
    assert!(candidate_block_hash(&foreign, selected.entrypoint_hash).is_err());
    let inconsistent_page = norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
        batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::CommittedTransaction(
            Vec::new(),
        )),
        remaining_items: Some(1),
        has_more: false,
        continue_cursor: None,
    }))
    .unwrap();
    assert!(candidate_block_hash(&inconsistent_page, selected.entrypoint_hash).is_err());
    assert!(candidate_block_hash(&[0x7f], selected.entrypoint_hash).is_err());
}

#[test]
fn ffi_failure_clears_every_output_before_rejection() {
    let mut row_pointer = ptr::dangling_mut::<u8>();
    let mut row_len: c_ulong = 12;
    let mut output_hash = [0xff; 32];
    let mut block_hash = [0xff; 32];
    let mut height = 42_u64;
    let mut result_ok = 1_u8;
    let mut checkpoint_pointer = ptr::dangling_mut::<u8>();
    let mut checkpoint_len: c_ulong = 12;
    let status = unsafe {
        connect_norito_verify_committed_transaction_inclusion_v1(
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            &mut row_pointer,
            &mut row_len,
            output_hash.as_mut_ptr(),
            block_hash.as_mut_ptr(),
            &mut height,
            &mut result_ok,
            &mut checkpoint_pointer,
            &mut checkpoint_len,
        )
    };
    assert_eq!(status, ERR_COMMITTED_INCLUSION);
    assert!(row_pointer.is_null());
    assert_eq!(row_len, 0);
    assert_eq!(output_hash, [0; 32]);
    assert_eq!(block_hash, [0; 32]);
    assert_eq!(height, 0);
    assert_eq!(result_ok, 0);
    assert!(checkpoint_pointer.is_null());
    assert_eq!(checkpoint_len, 0);
}

#[test]
fn ffi_returns_row_and_same_verified_checkpoint_as_two_owned_buffers() {
    let fixture = Fixture::new(false);
    let response_bytes = response(vec![fixture.selected.clone()]);
    let chain = fixture.chain_json();
    let checkpoint = fixture.checkpoint_bytes();
    let network = fixture.network();
    let label = fixture.checkpoint.chain_id();
    let mut row_ptr = ptr::null_mut();
    let mut row_len = 0;
    let mut checkpoint_ptr = ptr::null_mut();
    let mut checkpoint_len = 0;
    let mut output = [0; 32];
    let mut block = [0; 32];
    let mut height = 0;
    let mut result_ok = 0;
    let status = unsafe {
        connect_norito_verify_committed_transaction_inclusion_v1(
            response_bytes.as_ptr(),
            response_bytes.len() as c_ulong,
            chain.as_ptr(),
            chain.len() as c_ulong,
            network.as_bytes().as_ptr(),
            32,
            label.as_ptr(),
            label.len() as c_ulong,
            checkpoint.as_ptr(),
            checkpoint.len() as c_ulong,
            fixture.selected.entrypoint_hash.as_ref().as_ptr(),
            32,
            &mut row_ptr,
            &mut row_len,
            output.as_mut_ptr(),
            block.as_mut_ptr(),
            &mut height,
            &mut result_ok,
            &mut checkpoint_ptr,
            &mut checkpoint_len,
        )
    };
    assert_eq!(status, 0);
    assert!(!row_ptr.is_null());
    assert!(!checkpoint_ptr.is_null());
    let row = unsafe { slice::from_raw_parts(row_ptr, row_len as usize) }.to_vec();
    let checkpoint =
        unsafe { slice::from_raw_parts(checkpoint_ptr, checkpoint_len as usize) }.to_vec();
    crate::connect_norito_free(row_ptr);
    crate::connect_norito_free(checkpoint_ptr);
    assert_eq!(row, norito::to_bytes(&fixture.selected).unwrap());
    assert_eq!(output, *fixture.selected.output_hash.as_ref());
    assert_eq!(block, *fixture.block.hash().as_ref());
    assert_eq!(height, 3);
    assert_eq!(result_ok, 1);
    let promoted = SumeragiFinalityCheckpoint::decode_canonical(&checkpoint).unwrap();
    assert_eq!(promoted.block_hash(), fixture.block.hash());
    iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier::from_trusted_checkpoint(
        &promoted, &network, label,
    )
    .unwrap();
}
