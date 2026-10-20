//! Real Core/QC prefix tests for the public checkpoint boundary, never deployment qualification.
use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::build_proof,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    block::execution_output::ExecutionOutputV1,
    isi::{InstructionBox, Log, Unregister},
    nexus::DataSpaceId,
    query::{
        CommittedTransaction, QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple,
        QueryResponse,
    },
    sumeragi_finality::{SumeragiFinalityCheckpoint, verify_checkpoint_page},
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use std::time::Duration;
const CHAIN: &str = "sumeragi-certified-test-chain";
fn fixture(offset: u64) -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    for height in 2..=4 {
        chain.commit_at(height * 1000 + offset, Vec::new());
    }
    chain
}
fn wires(chain: &CertifiedTestChain) -> Vec<Vec<u8>> {
    let view = chain.state().view();
    (1..=4)
        .map(|height| norito::to_bytes(&build_proof(&view, height).unwrap()).unwrap())
        .collect()
}
fn call(
    genesis: &[u8],
    frames: &[Vec<u8>],
    network: NetworkId,
    chain: &str,
) -> Result<Output, Failure> {
    authenticate(
        genesis,
        &frames.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        network,
        chain,
        &Sha256::digest(genesis),
    )
}
#[test]
fn public_checkpoint_real_core_prefix_exports_replayable_tip() {
    let chain = fixture(0);
    let frames = wires(&chain);
    // Exercise unchanged certified executed genesis, matching the public retained input kind.
    let first = build_proof(&chain.state().view(), 1).unwrap();
    let genesis = first.block_wire;
    assert!(
        decode_framed_signed_block(&genesis)
            .unwrap()
            .commit_certificate()
            .is_some()
    );
    let output = call(&genesis, &frames, chain.network_id(), CHAIN).unwrap();
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&output.checkpoint).unwrap();
    assert_eq!(checkpoint.height(), 4);
    let proofs: Vec<SumeragiFinalityProof> = json::from_json(&output.tip_proof_chain_json).unwrap();
    assert_eq!(proofs.len(), 1);
    let page = verify_checkpoint_page(
        chain.network_id(),
        &checkpoint,
        &proofs,
        MAX_PROOFS,
        MAX_PROOF_BYTES,
    )
    .unwrap();
    assert_eq!(page.tip().height(), 4);
    assert_eq!(
        page.checkpoint().encode_canonical().unwrap(),
        output.checkpoint
    );
    let metadata: json::Value = json::from_json(&output.metadata_json).unwrap();
    assert_eq!(metadata["proof_count"].as_u64(), Some(4));
    assert_eq!(metadata["root_scope"].as_str(), Some("Global"));
}
#[test]
fn public_checkpoint_rejects_wrong_pins_and_genesis_without_successor() {
    let chain = fixture(0);
    let frames = wires(&chain);
    let genesis = chain.genesis().encode_wire().unwrap();
    assert!(call(&genesis, &frames[..1], chain.network_id(), CHAIN).is_err());
    assert!(call(&genesis, &frames, chain.network_id(), "foreign-chain").is_err());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign public root",
    )));
    assert!(call(&genesis, &frames, foreign, CHAIN).is_err());
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    assert!(authenticate(&genesis, &refs, chain.network_id(), CHAIN, &[1; 32]).is_err());
    let mut altered = genesis.clone();
    altered.push(0);
    assert!(call(&altered, &frames, chain.network_id(), CHAIN).is_err());
}
#[test]
fn public_checkpoint_rejects_gaps_reordering_tampering_and_forks() {
    let chain = fixture(0);
    let frames = wires(&chain);
    let genesis = chain.genesis().encode_wire().unwrap();
    let mut gap = frames.clone();
    gap.remove(1);
    assert!(call(&genesis, &gap, chain.network_id(), CHAIN).is_err());
    let mut reorder = frames.clone();
    reorder.swap(1, 2);
    assert!(call(&genesis, &reorder, chain.network_id(), CHAIN).is_err());
    let mut duplicate = frames.clone();
    duplicate[2] = duplicate[1].clone();
    assert!(call(&genesis, &duplicate, chain.network_id(), CHAIN).is_err());
    let mut changed = frames.clone();
    changed[2].push(0);
    assert!(call(&genesis, &changed, chain.network_id(), CHAIN).is_err());
    let mut proof: SumeragiFinalityProof = norito::decode_canonical(&frames[2]).unwrap();
    proof.committee[0].proof_of_possession[0] ^= 1;
    changed[2] = norito::to_bytes(&proof).unwrap();
    assert!(call(&genesis, &changed, chain.network_id(), CHAIN).is_err());
    let fork = fixture(1);
    assert_eq!(fork.network_id(), chain.network_id());
    changed = frames.clone();
    changed[2] = wires(&fork)[2].clone();
    assert!(call(&genesis, &changed, chain.network_id(), CHAIN).is_err());
}
#[test]
fn public_checkpoint_rejects_authenticated_private_root_before_proofs() {
    use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let parent = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"selected public parent",
    )));
    let private = NativeFinalityFixture::start_with_scope(
        "private-refusal",
        SumeragiRootScope::Dataspace {
            parent_network_id: parent,
            dataspace_id: DataSpaceId::new(7),
        },
    );
    let genesis = private.genesis().encode_wire().unwrap();
    let proof = norito::to_bytes(private.genesis_proof()).unwrap();
    // These are genuine signed native fixture carriers, used only for root refusal.
    // Private scope is refused before this intentionally repeated prefix is decoded.
    let error = call(
        &genesis,
        &[proof.clone(), proof],
        private.network_id(),
        "private-refusal",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Failure::Input("public finality requires the selected Global genesis")
    ));
}
#[test]
fn public_checkpoint_closed_bounds_refuse_before_native_parsing() {
    let proof = b"bounded non-proof".as_slice();
    assert!(validate_bounds(&[], &[proof, proof], CHAIN, &[1; 32]).is_err());
    assert!(validate_bounds(&vec![0; MAX_GENESIS + 1], &[proof, proof], CHAIN, &[1; 32]).is_err());
    assert!(validate_bounds(b"x", &[proof, proof], &"x".repeat(MAX_CHAIN + 1), &[1; 32]).is_err());
    assert!(validate_bounds(b"x", &[proof, proof], " chain", &[1; 32]).is_err());
    for control in [
        "chain\nlabel",
        "chain\tlabel",
        "chain\u{7f}label",
        "chain\u{85}label",
    ] {
        assert!(validate_bounds(b"x", &[proof, proof], control, &[1; 32]).is_err());
    }
    assert!(validate_bounds(b"x", &[proof, proof], CHAIN, &[0; 32]).is_err());
    assert!(validate_bounds(b"x", &vec![proof; MAX_PROOFS + 1], CHAIN, &[1; 32]).is_err());
    let large = vec![0; MAX_PROOF_BYTES];
    assert!(validate_bounds(b"x", &[&large, proof], CHAIN, &[1; 32]).is_err());
}
#[test]
fn public_checkpoint_python_error_retains_native_category() {
    Python::initialize();
    Python::attach(|py| {
        let error = Failure::Native(
            "proof_verification",
            iroha_data_model::sumeragi_finality::FinalityError(
                "invalid original certificate".into(),
            )
            .into(),
        )
        .into_py(py);
        assert!(error.is_instance_of::<PublicFinalityReadError>(py));
        assert_eq!(
            error
                .value(py)
                .getattr("kind")
                .unwrap()
                .extract::<String>()
                .unwrap(),
            "invalid"
        );
        assert_eq!(
            error
                .value(py)
                .getattr("phase")
                .unwrap()
                .extract::<String>()
                .unwrap(),
            "proof_verification"
        );
    });
}

#[test]
fn public_checkpoint_original_resource_refusal_survives_scope_and_python_projection() {
    let chain = fixture(0);
    let frames = wires(&chain);
    let genesis = chain.genesis().encode_wire().unwrap();
    let limit = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    // Real canonical frame decoding, not a fabricated ResourceDecodeError.
    let genesis_error = norito::with_decode_limits_scope(limit, || {
        call(&genesis, &frames, chain.network_id(), CHAIN)
    })
    .unwrap_err();
    let proof_error =
        norito::with_decode_limits_scope(limit, || decode_proof(&frames[0])).unwrap_err();
    Python::initialize();
    for (error, expected_phase) in [
        (genesis_error, "genesis_decode"),
        (proof_error, "proof_decode"),
    ] {
        let Failure::Native(phase, FinalityReadError::DecodeResource(original)) = &error else {
            panic!("expected original enclosing decoder refusal, got {error:?}");
        };
        assert_eq!(*phase, expected_phase);
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(matches!(
            original.error().decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }) if attempted > 0
        ));
        Python::attach(|py| {
            let error = error.into_py(py);
            assert!(error.is_instance_of::<PublicFinalityReadError>(py));
            assert_eq!(
                error
                    .value(py)
                    .getattr("kind")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "decode_resource"
            );
            assert_eq!(
                error
                    .value(py)
                    .getattr("phase")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                expected_phase
            );
        });
    }
    // A failed local budget does not poison the same immutable input on retry.
    assert!(call(&genesis, &frames, chain.network_id(), CHAIN).is_ok());
}

#[test]
fn public_checkpoint_tip_composes_with_real_committed_success_and_rejection() {
    use crate::committed_transaction_verification::authenticate_committed_transaction;
    Python::initialize();
    for rejected in [false, true] {
        let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).unwrap();
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1000)).unwrap();
        chain.commit(Vec::new());
        let mut tx = TransactionBuilder::new(
            chain.network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        );
        tx.set_creation_time(Duration::from_millis(1002));
        let instruction: InstructionBox = if rejected {
            Unregister::domain(
                iroha_model_base::domain::DomainId::try_new("absent_inclusion", "universal")
                    .unwrap(),
            )
            .into()
        } else {
            Log::new(
                iroha_data_model::Level::INFO,
                "public checkpoint inclusion".into(),
            )
            .into()
        };
        let tx = tx.with_instructions([instruction]).sign(key.private_key());
        assert_eq!(chain.commit(vec![tx]), vec![!rejected]);
        let block = chain.committed(3).block().clone();
        let selected_output =
            ExecutionOutputV1::Network(block.network_output_at(0).unwrap().1.clone());
        let selected = CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: block.network_entrypoint_at(0).unwrap().hash(),
            entrypoint_proof: block.network_input_proof(0).unwrap(),
            entrypoint: block.network_entrypoint_at(0).unwrap().clone(),
            output_hash: HashOf::new(&selected_output),
            output_proof: block.output_proof(0).unwrap(),
            output: selected_output,
        };
        assert!(selected.verify_inclusion_in_block(&block));
        let response = |row: CommittedTransaction| {
            norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
                batch: QueryOutputBatchBoxTuple::from_batch(
                    QueryOutputBatchBox::CommittedTransaction(vec![row]),
                ),
                remaining_items: Some(0),
                has_more: false,
                continue_cursor: None,
            }))
            .unwrap()
        };
        let view = chain.state().view();
        let frames: Vec<_> = (1..=3)
            .map(|height| norito::to_bytes(&build_proof(&view, height).unwrap()).unwrap())
            .collect();
        let genesis = build_proof(&view, 1).unwrap().block_wire;
        drop(view);
        let exported = call(&genesis, &frames, chain.network_id(), CHAIN).unwrap();
        let (verified, page) = authenticate_committed_transaction(
            selected.entrypoint_hash,
            &response(selected.clone()),
            &exported.tip_proof_chain_json,
            chain.network_id(),
            CHAIN,
            &exported.checkpoint,
        )
        .unwrap();
        assert_eq!(verified, selected);
        assert_eq!(page.tip().height(), 3);
        assert_eq!(
            page.checkpoint().encode_canonical().unwrap(),
            exported.checkpoint
        );
        // An authentic finality tip must not accept a substituted committed output.
        let mut altered = selected.clone();
        altered.output_hash = HashOf::from_untyped_unchecked(Hash::new(b"substituted output"));
        assert!(
            authenticate_committed_transaction(
                selected.entrypoint_hash,
                &response(altered),
                &exported.tip_proof_chain_json,
                chain.network_id(),
                CHAIN,
                &exported.checkpoint,
            )
            .is_err()
        );
    }
}

#[test]
fn public_checkpoint_genesis_reader_diagnostics_keep_original_source_category() {
    // Diagnostic projection only; neither failure is a proof acceptance fixture.
    let json_error = json::from_json::<json::Value>("{").unwrap_err();
    let cases = [
        (
            GenesisReadError::Invalid("wrong signed genesis".into()),
            "invalid",
        ),
        (GenesisReadError::Json(json_error), "json"),
    ];
    Python::initialize();
    Python::attach(|py| {
        for (original, source_kind) in cases {
            let error = Failure::Native("genesis_authentication", original.into()).into_py(py);
            assert_eq!(
                error
                    .value(py)
                    .getattr("kind")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "genesis_read"
            );
            assert_eq!(
                error
                    .value(py)
                    .getattr("source_kind")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                source_kind
            );
        }
    });
}
