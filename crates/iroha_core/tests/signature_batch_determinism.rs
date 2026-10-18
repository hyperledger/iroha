//! Determinism tests for signature preverification batching under input permutations.

#![allow(clippy::items_after_statements)]
//! Ensures that, for a block containing one bad signature among valid ones, the offending
//! transaction identified by batch verification is stable across different input orders.
use crate::native_validation;
use iroha_core::{
    block::BlockValidationError as BErr,
    prelude::*,
    state::{State, StateReadOnly},
    tx::AcceptTransactionFail as AF,
};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, SignatureOf};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
fn setup_world_with_account(algo: Algorithm) -> (State, AccountId, NetworkId, KeyPair) {
    use iroha_core::{kura::Kura, query::store::LiveQueryStore};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let kp = checked_keypair_with_algorithm(algo);
    let (pubkey, _) = kp.clone().into_parts();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(pubkey);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let state =
        State::new_with_chain_for_testing(world, kura, query_handle, ChainId::from("chain"));
    let network_id = *state.network_id_ref();
    let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    if !crypto_cfg.allowed_signing.contains(&algo) {
        crypto_cfg.allowed_signing.push(algo);
        crypto_cfg.allowed_signing.sort();
        crypto_cfg.allowed_signing.dedup();
    }
    state.set_crypto(crypto_cfg);
    (state, account_id, network_id, kp)
}
fn checked_signature_of<T: norito::codec::Encode>(
    private_key: &PrivateKey,
    payload: &T,
) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("signature batch fixture key generation should succeed")
}
fn checked_bls_keypair() -> KeyPair {
    checked_keypair_with_algorithm(Algorithm::BlsNormal)
}
#[test]
fn checked_keypair_with_algorithm_preserves_signature_algorithm() {
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::Ed25519).algorithm(),
        Algorithm::Ed25519
    );
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::Secp256k1).algorithm(),
        Algorithm::Secp256k1
    );
    assert_eq!(checked_bls_keypair().algorithm(), Algorithm::BlsNormal);
}
fn enable_batch_caps(state: &mut iroha_core::state::State) {
    let mut cfg = state.view().pipeline().clone();
    // Enable modest caps for all schemes (harmless for unused ones)
    cfg.signature_batch_max_ed25519 = 8;
    cfg.signature_batch_max_secp256k1 = 8;
    #[cfg(feature = "bls")]
    {
        cfg.signature_batch_max_bls = 16;
    }
    state.set_pipeline(cfg);
}
#[derive(Clone)]
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        // Numerical Recipes LCG constants
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0
    }
}
fn shuffle<T: Clone>(rng: &mut Lcg, v: &[T]) -> Vec<T> {
    let mut out = v.to_vec();
    let n = out.len();
    for i in (1..n).rev() {
        let j = usize::try_from(rng.next()).unwrap_or(0) % (i + 1);
        out.swap(i, j);
    }
    out
}
#[test]
fn ed25519_batch_permutation_finds_same_bad_sig() {
    let (mut state, authority, _network_id, good) = setup_world_with_account(Algorithm::Ed25519);
    enable_batch_caps(&mut state);
    let bad = checked_keypair_with_algorithm(Algorithm::Ed25519);
    let chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    // Build a few transactions where exactly one is signed by a wrong key
    let mk = |msg: &str, mismatched_sig: bool| {
        let mut tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(good.private_key());
        if mismatched_sig {
            let sig = TransactionSignature(checked_signature_of(bad.private_key(), tx.payload()));
            tx.set_signature(sig);
        }
        tx
    };
    let tx_ok1 = mk("ok-1", false);
    let tx_ok2 = mk("ok-2", false);
    let tx_bad = mk("bad", true);
    let tx_ok3 = mk("ok-3", false);
    let tx_ok4 = mk("ok-4", false);
    let baseline = vec![tx_ok1, tx_ok2, tx_bad.clone(), tx_ok3, tx_ok4];
    let bad_sig = tx_bad.signature().clone();
    // Deterministic permutations
    let mut rng = Lcg::new(0xED_25_51_9D);
    for _ in 0..32 {
        let perm = shuffle(&mut rng, &baseline);
        let block = native_validation::proposal(&chain, perm);
        let err = native_validation::validate(&chain, block)
            .expect_err("block must be rejected due to bad signature");
        match *err {
            BErr::TransactionAccept(AF::SignatureVerification(fail)) => {
                assert_eq!(
                    fail.signature, bad_sig,
                    "offending signature must match the known bad tx signature"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
#[test]
fn secp256k1_batch_permutation_finds_same_bad_sig() {
    let (mut state, authority, _network_id, good) = setup_world_with_account(Algorithm::Secp256k1);
    enable_batch_caps(&mut state);
    let bad = checked_keypair_with_algorithm(Algorithm::Secp256k1);
    let chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    let mk = |msg: &str, mismatched_sig: bool| {
        let mut tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(good.private_key());
        if mismatched_sig {
            let sig = TransactionSignature(checked_signature_of(bad.private_key(), tx.payload()));
            tx.set_signature(sig);
        }
        tx
    };
    let tx_ok1 = mk("ok-1", false);
    let tx_ok2 = mk("ok-2", false);
    let tx_bad = mk("bad", true);
    let tx_ok3 = mk("ok-3", false);
    let tx_ok4 = mk("ok-4", false);
    let baseline = vec![tx_ok1, tx_ok2, tx_bad.clone(), tx_ok3, tx_ok4];
    let bad_sig = tx_bad.signature().clone();
    let mut rng = Lcg::new(0x53_45_43_50);
    for _ in 0..32 {
        let perm = shuffle(&mut rng, &baseline);
        let block = native_validation::proposal(&chain, perm);
        let err = native_validation::validate(&chain, block)
            .expect_err("block must be rejected due to bad signature");
        use iroha_core::{block::BlockValidationError as BErr, tx::AcceptTransactionFail as AF};
        match *err {
            BErr::TransactionAccept(AF::SignatureVerification(fail)) => {
                assert_eq!(
                    fail.signature, bad_sig,
                    "offending signature must match the known bad tx signature"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
#[test]
#[cfg(feature = "bls")]
fn bls_multimessage_batch_passes() {
    let (mut state, authority, _network_id, signer) =
        setup_world_with_account(Algorithm::BlsNormal);
    enable_batch_caps(&mut state);
    let chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    let mk = |msg: &str| {
        TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(signer.private_key())
    };
    let txs = vec![mk("m1"), mk("m2"), mk("m3"), mk("m4"), mk("m5")];
    let block = native_validation::proposal(&chain, txs);
    native_validation::validate(&chain, block).expect("valid BLS multi-message batch must pass");
}
#[test]
#[cfg(feature = "bls")]
fn bls_multimessage_batch_finds_same_bad_sig() {
    let (mut state, authority, _network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_batch_caps(&mut state);
    let bad = checked_bls_keypair();
    let chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    let mk = |msg: &str, mismatched_sig: bool| {
        let mut tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(good.private_key());
        if mismatched_sig {
            let sig = TransactionSignature(checked_signature_of(bad.private_key(), tx.payload()));
            tx.set_signature(sig);
        }
        tx
    };
    let tx_ok1 = mk("ok-1", false);
    let tx_ok2 = mk("ok-2", false);
    let tx_bad = mk("bad", true);
    let tx_ok3 = mk("ok-3", false);
    let tx_ok4 = mk("ok-4", false);
    let baseline = vec![tx_ok1, tx_ok2, tx_bad.clone(), tx_ok3, tx_ok4];
    let bad_sig = tx_bad.signature().clone();
    let mut rng = Lcg::new(0xB150_0BAD);
    for _ in 0..32 {
        let perm = shuffle(&mut rng, &baseline);
        let block = native_validation::proposal(&chain, perm);
        let err = native_validation::validate(&chain, block)
            .expect_err("block must be rejected due to bad BLS signature");
        match *err {
            BErr::TransactionAccept(AF::SignatureVerification(fail)) => {
                assert_eq!(
                    fail.signature, bad_sig,
                    "offending signature must match the known bad tx signature"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
#[cfg(feature = "bls")]
#[test]
fn bls_batch_permutation_finds_same_bad_sig() {
    let (mut state, authority, _network_id, good) = setup_world_with_account(Algorithm::BlsNormal);
    enable_batch_caps(&mut state);
    let bad = checked_bls_keypair();
    let chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    // Use distinct messages to exercise multi-message aggregation path
    let mk = |msg: &str, mismatched_sig: bool| {
        let mut tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, msg.to_string())])
        .sign(good.private_key());
        if mismatched_sig {
            let sig = TransactionSignature(checked_signature_of(bad.private_key(), tx.payload()));
            tx.set_signature(sig);
        }
        tx
    };
    let tx_ok1 = mk("m1", false);
    let tx_ok2 = mk("m2", false);
    let tx_bad = mk("m3-bad", true);
    let tx_ok3 = mk("m4", false);
    let tx_ok4 = mk("m5", false);
    let baseline = vec![tx_ok1, tx_ok2, tx_bad.clone(), tx_ok3, tx_ok4];
    let bad_sig = tx_bad.signature().clone();
    let mut rng = Lcg::new(0xB1_5B_4D);
    for _ in 0..16 {
        let perm = shuffle(&mut rng, &baseline);
        let block = native_validation::proposal(&chain, perm);
        let err = native_validation::validate(&chain, block)
            .expect_err("block must be rejected due to bad signature");
        use iroha_core::{block::BlockValidationError as BErr, tx::AcceptTransactionFail as AF};
        match *err {
            BErr::TransactionAccept(AF::SignatureVerification(fail)) => {
                assert_eq!(
                    fail.signature, bad_sig,
                    "offending signature must match the known bad tx signature"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
