//! Benchmarks for transaction signing, acceptance, validation, and block signing.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
use criterion::{BatchSize, Criterion};
use iroha_core::{
    block::*,
    governance::manifest::LaneManifestRegistry,
    prelude::*,
    query::store::LiveQueryStore,
    smartcontracts::{Execute, isi::Registrable as _, ivm::cache::IvmCache},
    state::{State, World},
};
use iroha_data_model::{
    account::AccountId,
    isi::{InstructionBox, Log},
    prelude::*,
    transaction::{IvmBytecode, TransactionBuilder},
};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::gen_account_in;
use std::sync::{Arc, LazyLock};
static STARTER_DOMAIN: LazyLock<DomainId> =
    LazyLock::new(|| DomainId::try_new("start", "universal").unwrap());
static STARTER_KEYPAIR: LazyLock<KeyPair> = LazyLock::new(KeyPair::random);
static STARTER_ID: LazyLock<AccountId> =
    LazyLock::new(|| AccountId::new(STARTER_KEYPAIR.public_key().clone()));
// Shared Tokio runtime for benches that need background tasks (e.g., LiveQueryStore)
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
});
fn benchmark_network_id(label: &[u8]) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::new(label),
        ),
    )
}
fn build_test_transaction(network_id: NetworkId) -> TransactionBuilder {
    TransactionBuilder::new(
        network_id,
        STARTER_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions::<InstructionBox>([
        Log::new(Level::INFO, "validation benchmark one".to_owned()).into(),
        Log::new(Level::INFO, "validation benchmark two".to_owned()).into(),
        Log::new(Level::INFO, "validation benchmark three".to_owned()).into(),
    ])
}
fn build_test_and_transient_state() -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    // Ensure Tokio reactor is available for LiveQueryStore background task
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let (account_id, key_pair) = gen_account_in(&*STARTER_DOMAIN);
    let state = State::try_new(
        iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        {
            let domain = Domain::new(STARTER_DOMAIN.clone()).build(&account_id);
            let account = Account::new(account_id.clone()).build(&account_id);
            World::with([domain], [account], [])
        },
        Arc::clone(&kura),
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
    .expect("benchmark State startup must validate");
    let nexus = state.nexus_snapshot();
    state
        .install_materialized_lane_manifests_for_catalog(
            &Arc::new(LaneManifestRegistry::from_config(
                &nexus.lane_catalog,
                &nexus.governance,
                &nexus.registry,
            )),
            &nexus.lane_catalog,
            &nexus.governance,
        )
        .expect("benchmark lane manifest source must be materialized");
    {
        let network_id = *state.network_id_ref();
        let transaction = TransactionBuilder::new(
            network_id,
            account_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "init".to_string())])
        .sign(key_pair.private_key());
        let (max_clock_drift, tx_limits) = {
            let state_view = state.view();
            let params = state_view.world.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let crypto_cfg = state.crypto();
        let unverified_block = BlockBuilder::new(vec![
            AcceptedTransaction::accept(
                transaction,
                &network_id,
                max_clock_drift,
                tx_limits,
                crypto_cfg.as_ref(),
            )
            .unwrap(),
        ])
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("benchmark canonical block read")
                .as_deref(),
        )
        .sign(key_pair.private_key())
        .unpack(|_| {});
        let signed_block = iroha_data_model::block::SharedSignedBlock::try_new(
            SignedBlock::from(unverified_block.clone()),
            &state.ivm_execution_budget(),
        )
        .expect("benchmark shared block control");
        let mut state_block = state
            .try_block(unverified_block.header())
            .expect("benchmark persisted runtime ABI must validate");
        let mut state_transaction = state_block.transaction();
        let path_to_executor =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../defaults/executor.to");
        let bytecode = std::fs::read(&path_to_executor)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_executor.display()));
        let executor = Executor::new(IvmBytecode::from_compiled(bytecode));
        let (authority, _authority_keypair) = gen_account_in("genesis");
        // Ignore upgrade failure and keep the default executor when bytecode is invalid
        let _ = Upgrade::new(executor).execute(&authority, &mut state_transaction);
        state_transaction.apply();
        // Mark the transaction as recorded in this block before commit
        {
            use std::collections::BTreeSet;
            let hash = unverified_block
                .transactions()
                .first()
                .expect("Block must contain transaction")
                .as_ref()
                .hash_as_entrypoint();
            let height = std::num::NonZeroUsize::new(
                unverified_block
                    .header()
                    .height()
                    .get()
                    .try_into()
                    .expect("Block height fits into usize"),
            )
            .expect("Block height is non-zero");
            state_block
                .transactions
                .insert_block(BTreeSet::from([hash]), height);
        }
        state_block.block_hashes.push_for_tests(signed_block.hash());
        state_block.commit().unwrap();
        kura.store_block(signed_block)
            .expect("store block in bench setup");
    }
    state
}
fn accept_transaction(criterion: &mut Criterion) {
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let state = build_test_and_transient_state();
    let network_id = *state.network_id_ref();
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let transaction = build_test_transaction(network_id).sign(STARTER_KEYPAIR.private_key());
    let crypto_cfg = state.crypto();
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(|| {
            match AcceptedTransaction::accept(
                transaction.clone(),
                &network_id,
                max_clock_drift,
                tx_limits,
                crypto_cfg.as_ref(),
            ) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
}
fn sign_transaction(criterion: &mut Criterion) {
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let network_id = benchmark_network_id(b"validation-sign-transaction");
    let transaction = build_test_transaction(network_id);
    let (_, private_key) = KeyPair::random().into_parts();
    let mut count = 0;
    let _ = criterion.bench_function("sign", |b| {
        b.iter_batched(
            || transaction.clone(),
            |transaction| {
                let _: SignedTransaction = transaction.sign(&private_key);
                count += 1;
            },
            BatchSize::SmallInput,
        );
    });
    println!("Count: {count}");
}
fn validate_transaction(criterion: &mut Criterion) {
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let state = build_test_and_transient_state();
    let network_id = *state.network_id_ref();
    let (account_id, key_pair) = gen_account_in(&*STARTER_DOMAIN);
    let transaction = TransactionBuilder::new(
        network_id,
        account_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "init".to_string())])
    .sign(key_pair.private_key());
    let (max_clock_drift, tx_limits) = {
        let state_view = state.view();
        let params = state_view.world.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let crypto_cfg = state.crypto();
    let unverified_block = BlockBuilder::new(vec![
        AcceptedTransaction::accept(
            transaction,
            &network_id,
            max_clock_drift,
            tx_limits,
            crypto_cfg.as_ref(),
        )
        .unwrap(),
    ])
    .chain(
        0,
        state
            .view()
            .latest_block()
            .expect("benchmark canonical block read")
            .as_deref(),
    )
    .sign(key_pair.private_key())
    .unpack(|_| {});
    let signed_block = iroha_data_model::block::SharedSignedBlock::try_new(
        SignedBlock::from(unverified_block.clone()),
        &state.ivm_execution_budget(),
    )
    .expect("benchmark shared block control");
    let transaction = AcceptedTransaction::accept(
        build_test_transaction(network_id).sign(STARTER_KEYPAIR.private_key()),
        &network_id,
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
    )
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let mut ivm_cache = IvmCache::new();
    let mut state_block = state
        .try_block(unverified_block.header())
        .expect("benchmark persisted runtime ABI must validate");
    let _ = criterion.bench_function("validate", |b| {
        b.iter(|| {
            match iroha_core::tx::execute_component_transaction_for_testing(
                &mut state_block,
                transaction.clone(),
                &mut ivm_cache,
                None,
            ) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        });
    });
    {
        use std::collections::BTreeSet;
        let hash = unverified_block
            .transactions()
            .first()
            .expect("Block must contain transaction")
            .as_ref()
            .hash_as_entrypoint();
        let height = std::num::NonZeroUsize::new(
            unverified_block
                .header()
                .height()
                .get()
                .try_into()
                .expect("Block height fits into usize"),
        )
        .expect("Block height is non-zero");
        state_block
            .transactions
            .insert_block(BTreeSet::from([hash]), height);
    }
    state_block.block_hashes.push_for_tests(signed_block.hash());
    state_block.commit().unwrap();
    {
        let view = state.view();
        view.kura()
            .store_block(signed_block)
            .expect("store block in bench setup");
    }
    println!("Success count: {success_count}, Failure count: {failure_count}");
}
fn sign_blocks(criterion: &mut Criterion) {
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    // Ensure Tokio reactor is available for LiveQueryStore background task
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let state = State::try_new(
        iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        World::new(),
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
    .expect("benchmark State startup must validate");
    let network_id = *state.network_id_ref();
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let crypto_cfg = state.crypto();
    let transaction = AcceptedTransaction::accept(
        build_test_transaction(network_id).sign(STARTER_KEYPAIR.private_key()),
        &network_id,
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
    )
    .expect("Failed to accept transaction.");
    let (_, peer_private_key) = KeyPair::random().into_parts();
    let mut count = 0;
    let block = BlockBuilder::new(vec![transaction]).chain(
        0,
        state
            .view()
            .latest_block()
            .expect("benchmark canonical block read")
            .as_deref(),
    );
    let _ = criterion.bench_function("sign_block", |b| {
        b.iter_batched(
            || block.clone(),
            |block| {
                let _: NewBlock = block.sign(&peer_private_key).unpack(|_| {});
                count += 1;
            },
            BatchSize::SmallInput,
        );
    });
    println!("Count: {count}");
}
/// Entry point for the benchmark binary.
fn main() {
    // Silence IVM banner if executor/VM paths initialize it.
    #[allow(unused_imports)]
    {
        use ivm::set_banner_enabled;
        set_banner_enabled(false);
    }
    let mut c = Criterion::default().configure_from_args();
    accept_transaction(&mut c);
    sign_transaction(&mut c);
    validate_transaction(&mut c);
    sign_blocks(&mut c);
    c.final_summary();
}
