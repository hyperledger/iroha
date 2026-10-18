//! Admission-time deterministic batching tests for signature schemes.

#![allow(clippy::cast_possible_truncation)]
//! Exercise the production stateless transaction-admission boundary directly.
//! Consensus authentication and execution have separate block-level coverage; these
//! fixtures use ordinary post-genesis transactions so every signature path runs.
use core::time::Duration;
use iroha_core::{
    block::{BlockValidationError, ValidBlock},
    governance::manifest::LaneManifestRegistry,
    prelude::*,
    state::State,
    tx::{AcceptTransactionFail, SignatureRejectionCode},
};
#[cfg(feature = "bls")]
use iroha_crypto::Signature;
use iroha_crypto::{Algorithm, HashOf, KeyPair, PrivateKey, SignatureOf};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
#[cfg(all(feature = "bls", feature = "telemetry"))]
use iroha_model_base::topology::LaneId;
use iroha_primitives::time::TimeSource;
use nonzero_ext::nonzero;
use std::sync::Arc;
fn setup_world_with_account(algo: Algorithm) -> (State, AccountId, NetworkId, KeyPair) {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_random_keypair_with_algorithm(algo);
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state =
        State::new_with_chain_for_testing(world, kura, query_handle, ChainId::from("chain"));
    let network_id = *state.network_id_ref();
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    if !crypto_cfg.allowed_signing.contains(&algo) {
        crypto_cfg.allowed_signing.push(algo);
        crypto_cfg.allowed_signing.sort();
        crypto_cfg.allowed_signing.dedup();
    }
    crypto_cfg.allowed_curve_ids =
        iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
            &crypto_cfg.allowed_signing,
        );
    state.set_crypto(crypto_cfg);
    (state, account_id, network_id, kp)
}
fn checked_random_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked admission batching keypair")
}
fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("generate checked admission batching keypair for requested algorithm")
}
#[test]
fn admission_batching_fixture_key_generation_preserves_algorithm() {
    for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::MlDsa] {
        let key_pair = checked_random_keypair_with_algorithm(algorithm);
        assert_eq!(key_pair.public_key().algorithm(), algorithm);
    }
    let default_key_pair = checked_random_keypair();
    assert_eq!(
        default_key_pair.public_key().algorithm(),
        Algorithm::Ed25519
    );
    #[cfg(feature = "bls")]
    {
        let key_pair = checked_random_keypair_with_algorithm(Algorithm::BlsNormal);
        assert_eq!(key_pair.public_key().algorithm(), Algorithm::BlsNormal);
    }
    #[cfg(feature = "sm")]
    {
        let key_pair = checked_random_keypair_with_algorithm(Algorithm::Sm2);
        assert_eq!(key_pair.public_key().algorithm(), Algorithm::Sm2);
    }
}
fn checked_signature_of<T: norito::codec::Encode>(
    private_key: &PrivateKey,
    payload: &T,
) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn checked_signature_from_hash<T>(private_key: &PrivateKey, hash: HashOf<T>) -> SignatureOf<T> {
    SignatureOf::try_from_hash(private_key, hash).expect("test fixture hash signing should succeed")
}
fn validate_admission(
    block: &SignedBlock,
    state: &State,
    authority: &AccountId,
) -> Result<(), BlockValidationError> {
    assert!(
        !block.header().is_genesis(),
        "batching requires ordinary transactions"
    );
    let view = state.view();
    let prepared = ValidBlock::prepare_external_transactions(block);
    let parameters = view.world().parameters();
    let pipeline = view.pipeline().clone();
    let snapshot = super::StaticValidationData {
        expected_block_height: block.header().height().get().try_into().unwrap(),
        max_clock_drift: parameters.sumeragi().max_clock_drift(),
        tx_params: parameters.transaction(),
        crypto_cfg: view.crypto(),
        pipeline_parallelism: state.pipeline_parallelism().clone(),
        pipeline_cfg: pipeline,
        aggregate_lane: view.nexus().routing_policy.default_lane,
    };
    #[cfg(feature = "telemetry")]
    let metrics = Some(view.metrics());
    #[cfg(not(feature = "telemetry"))]
    let metrics = ();
    ValidBlock::validate_static_with_snapshot(
        block,
        view.network_id(),
        authority,
        &snapshot,
        &vec![None; prepared.len()],
        &vec![None; block.external_entrypoint_count()],
        &prepared,
        metrics,
    )
}
fn assert_invalid_signature(result: Result<(), BlockValidationError>) {
    assert!(
        matches!(result, Err(BlockValidationError::TransactionAccept(
            AcceptTransactionFail::SignatureVerification(ref fail)
        )) if fail.code() == SignatureRejectionCode::InvalidSignature),
        "admission must reject the invalid transaction signature, got {result:?}"
    );
}
fn build_block_with_txs(
    good_kp: &KeyPair,
    bad_kp: &KeyPair,
    leader_kp: &KeyPair,
    authority: &AccountId,
    network_id: &NetworkId,
) -> SignedBlock {
    // Build a few transactions where exactly one is signed by a wrong key
    let mk = |msg: &str, kp: &KeyPair| {
        let mut tx = TransactionBuilder::new(
            *network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(good_kp.private_key());
        tx.set_signature(TransactionSignature(checked_signature_of(
            kp.private_key(),
            tx.payload(),
        )));
        tx
    };
    let txs = vec![
        mk("ok-1", good_kp),
        mk("ok-2", good_kp),
        mk("bad", bad_kp), // wrong key for same authority
        mk("ok-3", good_kp),
    ];
    presigned_block_with_creation_after_txs(leader_kp, txs)
}
#[cfg(feature = "bls")]
fn bls_pop_metadata(kp: &KeyPair) -> iroha_model_base::metadata::Metadata {
    let pop = iroha_crypto::bls_normal_pop_prove(kp.private_key()).expect("BLS PoP");
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        "bls_pop".parse().expect("valid BLS PoP metadata key"),
        iroha_primitives::json::Json::new(hex::encode_upper(pop)),
    );
    metadata
}
#[cfg(feature = "bls")]
fn mk_tx_with_creation_time(
    network_id: &NetworkId,
    authority: &AccountId,
    msg: &str,
    ct_ms: u64,
    signer: &KeyPair,
    pop_authority: &KeyPair,
) -> SignedTransaction {
    use core::time::Duration;
    let mut b = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    b.set_creation_time(Duration::from_millis(ct_ms));
    let mut tx = b
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .with_metadata(bls_pop_metadata(pop_authority))
        .sign(pop_authority.private_key());
    tx.set_signature(TransactionSignature(checked_signature_of(
        signer.private_key(),
        tx.payload(),
    )));
    tx
}
fn presigned_block_with_creation_after_txs(
    leader: &KeyPair,
    txs: Vec<SignedTransaction>,
) -> SignedBlock {
    fn creation_ms(tx: &SignedTransaction) -> u64 {
        let raw = tx.creation_time().as_millis();
        if raw > u128::from(u64::MAX) {
            u64::MAX
        } else {
            raw as u64
        }
    }
    let block_ct = txs
        .iter()
        .map(creation_ms)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let merkle_root = {
        let hashes = txs.iter().map(SignedTransaction::hash_as_entrypoint);
        let tree: iroha_crypto::MerkleTree<TransactionEntrypoint> = hashes.collect();
        tree.root()
    };
    let mut header = BlockHeader::new(nonzero!(2_u64), None, None, block_ct, 0);
    header.merkle_root = merkle_root;
    let sig = BlockSignature::new(
        0,
        checked_signature_from_hash(leader.private_key(), header.hash()),
    );
    SignedBlock::presigned(sig, header, txs)
}
#[cfg(feature = "bls")]
fn enable_bls_batching(state: &mut iroha_core::state::State) {
    let mut cfg = state.view().pipeline().clone();
    cfg.signature_batch_max_bls = 16;
    state.set_pipeline(cfg);
}
/// BLS same-message group duplicate payloads: constructing two identical transactions
/// is rejected by admission (duplicate payload). This still exercises same-message
/// grouping path in signature preverification before the duplicate check.
#[cfg(feature = "bls")]
#[test]
fn bls_same_message_group_duplicate_rejected() {
    // World and keys
    let (mut state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let leader = good.clone();
    // Two transactions with identical payloads (same creation_time and instructions), both signed correctly
    let ct = 1_651_234_567u64;
    let tx1 = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &good, &good);
    let tx2 = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &good, &good);
    let block = presigned_block_with_creation_after_txs(&leader, vec![tx1, tx2]);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        matches!(result, Err(BlockValidationError::DuplicateTransactions)),
        "duplicate identical BLS transactions should be rejected"
    );
    #[cfg(feature = "telemetry")]
    {
        let (same, multi, det) = state.view().metrics().pipeline_sig_bls_counts();
        assert!(same >= 1, "expected same-message aggregate to be used");
        assert_eq!(multi, 0, "unexpected multi-message aggregate count");
        assert_eq!(det, 0, "unexpected deterministic count");
    }
}
/// BLS mixed micro-batch: includes a same-message group (two identical valid txs)
/// and two distinct singletons. Signature preverification should run the fast-aggregate
/// for the group and exact multi-message verification for the singletons. The overall
/// block is rejected due to duplicate payloads.
#[cfg(feature = "bls")]
#[test]
fn bls_mixed_group_and_singletons_duplicate_rejected() {
    // World and keys
    let (mut state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let leader = good.clone();
    // Two identical valid transactions (same payload) form the same-message group
    let ct = 1_651_234_567u64;
    let tx_same1 = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &good, &good);
    let tx_same2 = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &good, &good);
    // Two distinct valid transactions (different payloads) serve as singletons
    let tx_s1 = mk_tx_with_creation_time(&network_id, &authority, "s1", ct + 1, &good, &good);
    let tx_s2 = mk_tx_with_creation_time(&network_id, &authority, "s2", ct + 2, &good, &good);
    let block =
        presigned_block_with_creation_after_txs(&leader, vec![tx_same1, tx_same2, tx_s1, tx_s2]);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        matches!(result, Err(BlockValidationError::DuplicateTransactions)),
        "block with duplicate BLS txs should be rejected, got {result:?}"
    );
    #[cfg(feature = "telemetry")]
    {
        let (same, multi, det) = state.view().metrics().pipeline_sig_bls_counts();
        assert!(same >= 1, "expected same-message aggregate to be used");
        assert!(multi >= 1, "expected multi-message verification to be used");
        assert_eq!(det, 0, "unexpected deterministic count");
    }
}
/// BLS same-message group bisection: one of two identical payloads is signed by a wrong key.
#[cfg(feature = "bls")]
#[test]
fn bls_same_message_group_bisect_bad() {
    let (mut state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let bad = checked_random_keypair_with_algorithm(Algorithm::BlsNormal);
    let leader = good.clone();
    let ct = 1_651_234_567u64;
    let tx_good = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &good, &good);
    // Same payload but signed with a key that does not match the authority
    let tx_bad = mk_tx_with_creation_time(&network_id, &authority, "same", ct, &bad, &good);
    let block = presigned_block_with_creation_after_txs(&leader, vec![tx_good, tx_bad]);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        matches!(result, Err(BlockValidationError::DuplicateTransactions)),
        "duplicate same-message payloads must be rejected, got {result:?}"
    );
    #[cfg(feature = "telemetry")]
    {
        let (same, multi, det) = state.view().metrics().pipeline_sig_bls_counts();
        assert!(
            same >= 1,
            "expected same-message aggregate attempt to be recorded"
        );
        assert_eq!(multi, 0, "unexpected multi-message aggregate count");
        assert_eq!(det, 0, "unexpected deterministic count");
        let ((same_success, same_failure), _) = state
            .view()
            .metrics()
            .pipeline_sig_bls_result_totals(LaneId::SINGLE);
        assert_eq!(
            same_success, 0,
            "invalid same-message group must not verify"
        );
        assert!(
            same_failure >= 1,
            "invalid same-message group must be counted"
        );
    }
}
/// BLS multi-message verification across distinct messages: two valid BLS txs with
/// different payloads should be accepted when batching is enabled.
#[cfg(feature = "bls")]
#[test]
fn bls_multi_message_verification_ok() {
    let (mut state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let leader = good.clone();
    // Two distinct messages with current creation time (avoid TTL rejection)
    let tx1 = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "m1".to_string())])
    .with_metadata(bls_pop_metadata(&good))
    .sign(good.private_key());
    let tx2 = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "m2".to_string())])
    .with_metadata(bls_pop_metadata(&good))
    .sign(good.private_key());
    let block = presigned_block_with_creation_after_txs(&leader, vec![tx1, tx2]);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        result.is_ok(),
        "block with distinct valid BLS txs must be accepted, got {result:?}"
    );
    #[cfg(feature = "telemetry")]
    {
        let (same, multi, det) = state.view().metrics().pipeline_sig_bls_counts();
        assert_eq!(same, 0, "unexpected same-message aggregate count");
        assert!(multi >= 1, "expected multi-message verification to be used");
        assert_eq!(det, 0, "unexpected deterministic count");
    }
}
#[cfg(feature = "sm")]
#[test]
fn sm2_transactions_rejected_when_sm_disabled() {
    let (state, authority, network_id, signer) = setup_world_with_account(Algorithm::Sm2);
    let mut crypto_cfg = (*state.crypto()).clone();
    crypto_cfg
        .allowed_signing
        .retain(|algorithm| *algorithm != Algorithm::Sm2);
    crypto_cfg.allowed_curve_ids =
        iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
            &crypto_cfg.allowed_signing,
        );
    state.set_crypto(crypto_cfg);
    let leader = checked_random_keypair();
    let block = build_block_with_txs(&signer, &signer, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        matches!(result, Err(BlockValidationError::TransactionAccept(
            AcceptTransactionFail::SignatureVerification(ref fail)
        )) if fail.code() == SignatureRejectionCode::AlgorithmNotPermitted),
        "SM2 block should be rejected when SM is disabled, got {result:?}"
    );
}
#[cfg(feature = "sm")]
#[test]
fn sm2_transactions_accepted() {
    let (state, authority, network_id, signer) = setup_world_with_account(Algorithm::Sm2);
    let leader = checked_random_keypair();
    let block = build_block_with_txs(&signer, &signer, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert!(
        result.is_ok(),
        "SM2 block should be accepted when SM is enabled, got {result:?}"
    );
}
/// Distinct-message admission must preserve the validity of each transaction
/// signature, rather than relying on a verdict over their combined point.
#[cfg(feature = "bls")]
#[test]
fn bls_multi_message_rejects_balancing_altered_transaction_signatures() {
    let (mut state, authority, network_id, signer) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let leader = signer.clone();
    let mut tx1 = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "independent admission signature one".to_string(),
    )])
    .with_metadata(bls_pop_metadata(&signer))
    .sign(signer.private_key());
    let mut tx2 = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "independent admission signature two".to_string(),
    )])
    .with_metadata(bls_pop_metadata(&signer))
    .sign(signer.private_key());
    let sig1 = tx1.signature().0.payload().to_vec();
    let sig2 = tx2.signature().0.payload().to_vec();
    let delta = Signature::try_new(signer.private_key(), b"admission balancing point")
        .expect("produce canonical BLS point")
        .payload()
        .to_vec();
    assert_eq!(delta.len(), 96, "BLS-normal signatures use compressed G2");
    let mut negative_delta = delta.clone();
    // In the canonical compressed BLS12-381 encoding, negation flips the
    // lexicographic-sort flag while retaining the same x-coordinate.
    negative_delta[0] ^= 0x20;
    let altered_sig1 =
        iroha_crypto::bls_normal_aggregate_signatures(&[sig1.as_slice(), delta.as_slice()])
            .expect("first altered signature remains canonical");
    let altered_sig2 = iroha_crypto::bls_normal_aggregate_signatures(&[
        sig2.as_slice(),
        negative_delta.as_slice(),
    ])
    .expect("second altered signature remains canonical");
    tx1.set_signature(TransactionSignature(SignatureOf::from_signature(
        Signature::from_bytes(&altered_sig1),
    )));
    tx2.set_signature(TransactionSignature(SignatureOf::from_signature(
        Signature::from_bytes(&altered_sig2),
    )));
    tx1.verify_signature()
        .expect_err("first altered transaction signature must fail independently");
    tx2.verify_signature()
        .expect_err("second altered transaction signature must fail independently");
    let block = presigned_block_with_creation_after_txs(&leader, vec![tx1, tx2]);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
}
/// BLS multi-message verification: one of two distinct payloads is signed by a wrong key
/// and should trigger an exact-verification failure plus telemetry bookkeeping.
#[cfg(feature = "bls")]
#[test]
fn bls_multi_message_verification_fails_and_counts() {
    let (mut state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_bls_batching(&mut state);
    let bad = checked_random_keypair_with_algorithm(Algorithm::BlsNormal);
    let leader = good.clone();
    let ct = 1_751_234_567u64;
    let tx_valid = mk_tx_with_creation_time(&network_id, &authority, "m1", ct, &good, &good);
    let tx_bad = mk_tx_with_creation_time(&network_id, &authority, "m2", ct + 1, &bad, &good);
    let block = presigned_block_with_creation_after_txs(&leader, vec![tx_valid, tx_bad]);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
    #[cfg(feature = "telemetry")]
    {
        let ((same_success, same_failure), (multi_success, multi_failure)) = state
            .view()
            .metrics()
            .pipeline_sig_bls_result_totals(LaneId::SINGLE);
        assert_eq!(
            same_success + same_failure,
            0,
            "same-message aggregates should not be exercised in this scenario"
        );
        assert_eq!(
            multi_success, 0,
            "no multi-message verification should succeed"
        );
        assert!(
            multi_failure >= 1,
            "multi-message verification failures should be counted"
        );
    }
}
#[cfg(feature = "bls")]
#[test]
fn bls_batch_bisection_finds_bad_sig() {
    // Normal BLS variant
    let (state, authority, network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    let bad = checked_random_keypair_with_algorithm(Algorithm::BlsNormal);
    let leader = good.clone();
    let block = build_block_with_txs(&good, &bad, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
}
#[test]
fn mldsa_batch_bisection_finds_bad_sig() {
    // ML‑DSA (Dilithium3)
    let (state, authority, network_id, good) = setup_world_with_account(Algorithm::MlDsa);
    let bad = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    let leader = checked_random_keypair();
    let block = build_block_with_txs(&good, &bad, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
}
#[test]
fn ed25519_batch_bisection_finds_bad_sig() {
    let (state, authority, network_id, good) = setup_world_with_account(Algorithm::Ed25519);
    let bad = checked_random_keypair_with_algorithm(Algorithm::Ed25519);
    let leader = checked_random_keypair();
    let block = build_block_with_txs(&good, &bad, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
}
#[test]
fn secp256k1_batch_bisection_finds_bad_sig() {
    let (state, authority, network_id, good) = setup_world_with_account(Algorithm::Secp256k1);
    let bad = checked_random_keypair_with_algorithm(Algorithm::Secp256k1);
    let leader = checked_random_keypair();
    let block = build_block_with_txs(&good, &bad, &leader, &authority, &network_id);
    let result = validate_admission(&block, &state, &authority);
    assert_invalid_signature(result);
}
#[test]
fn rejects_transaction_signed_with_disallowed_algorithm() {
    let (state, authority, network_id, secp) = setup_world_with_account(Algorithm::Secp256k1);
    let max_clock_drift = core::time::Duration::from_secs(0);
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(1_u64),
        nonzero!(16_u64),
        nonzero!(2048_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let tx = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "secp attempt".to_owned())])
    .sign(secp.private_key());
    let mut crypto_cfg = (*state.crypto()).clone();
    crypto_cfg
        .allowed_signing
        .retain(|algo| *algo == Algorithm::Ed25519);
    crypto_cfg.allowed_curve_ids =
        iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
            &crypto_cfg.allowed_signing,
        );
    state.set_crypto(crypto_cfg.clone());
    let (_clock, time_source) = TimeSource::new_mock(tx.creation_time());
    match AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        max_clock_drift,
        tx_limits,
        &crypto_cfg,
        &time_source,
    ) {
        Err(AcceptTransactionFail::SignatureVerification(fail)) => {
            assert_eq!(fail.code(), SignatureRejectionCode::AlgorithmNotPermitted);
            assert!(
                fail.detail.contains("not permitted"),
                "expected rejection due to disallowed algorithm, got {:?}",
                fail.detail
            );
        }
        other => panic!("expected SignatureVerification failure, got {other:?}"),
    }
}
#[test]
fn accepts_transaction_once_algorithm_whitelisted() {
    let (state, authority, network_id, secp) = setup_world_with_account(Algorithm::Secp256k1);
    let max_clock_drift = Duration::from_secs(0);
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(1_u64),
        nonzero!(16_u64),
        nonzero!(2048_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let tx = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "secp allowed".to_owned())])
    .sign(secp.private_key());
    let mut crypto_cfg = (*state.crypto()).clone();
    if !crypto_cfg.allowed_signing.contains(&Algorithm::Secp256k1) {
        crypto_cfg.allowed_signing.push(Algorithm::Secp256k1);
        crypto_cfg.allowed_signing.sort();
        crypto_cfg.allowed_signing.dedup();
    }
    state.set_crypto(crypto_cfg.clone());
    let (_clock, time_source) = TimeSource::new_mock(tx.creation_time());
    AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        max_clock_drift,
        tx_limits,
        &crypto_cfg,
        &time_source,
    )
    .expect("transaction should be accepted after whitelisting");
}
#[test]
fn rejects_transaction_when_ttl_expired() {
    let (state, authority, network_id, kp) = setup_world_with_account(Algorithm::Ed25519);
    let max_clock_drift = Duration::from_secs(0);
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(1_u64),
        nonzero!(16_u64),
        nonzero!(2048_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let mut builder = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder = builder.with_instructions([Log::new(Level::INFO, "expired ttl".to_owned())]);
    builder.set_creation_time(Duration::from_secs(0));
    builder.set_ttl(Duration::from_secs(1));
    let tx = builder.sign(kp.private_key());
    let crypto_cfg = (*state.crypto()).clone();
    let (_clock, time_source) = TimeSource::new_mock(Duration::from_secs(2));
    match AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        max_clock_drift,
        tx_limits,
        &crypto_cfg,
        &time_source,
    ) {
        Err(AcceptTransactionFail::TransactionExpired { .. }) => {}
        other => panic!("expected TransactionExpired failure, got {other:?}"),
    }
}
#[test]
fn accepts_transaction_with_valid_ttl() {
    let (state, authority, network_id, kp) = setup_world_with_account(Algorithm::Ed25519);
    let max_clock_drift = Duration::from_secs(5);
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(1_u64),
        nonzero!(16_u64),
        nonzero!(2048_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let now = Duration::from_secs(10);
    let creation_time = now.saturating_sub(Duration::from_secs(1));
    let mut builder = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder = builder.with_instructions([Log::new(Level::INFO, "valid ttl".to_owned())]);
    builder.set_creation_time(creation_time);
    builder.set_ttl(Duration::from_secs(10));
    let tx = builder.sign(kp.private_key());
    let crypto_cfg = (*state.crypto()).clone();
    let (_clock, time_source) = TimeSource::new_mock(now);
    AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        max_clock_drift,
        tx_limits,
        &crypto_cfg,
        &time_source,
    )
    .expect("transaction with unexpired TTL should be accepted");
}
