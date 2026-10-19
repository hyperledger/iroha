//! Collection worker and metadata filtering costs over identical account scans.

use std::{hint::black_box, sync::Arc, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::json::Json;
use iroha_torii::{MaybeTelemetry, collection_query_for_bench};

fn account_state(count: usize) -> Arc<State> {
    let mut metadata = Metadata::default();
    metadata.insert("tier".parse().expect("metadata key"), Json::new("gold"));
    metadata.insert(
        "payload".parse().expect("metadata key"),
        Json::new("x".repeat(4096)),
    );
    let accounts = (0..count).map(|index| {
        let mut seed = vec![0xC7; 32];
        seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let key = KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("benchmark key");
        let id = AccountId::new(key.public_key().clone());
        Account::new(id.clone())
            .with_metadata(metadata.clone())
            .build(&id)
    });
    Arc::new(State::new_for_testing(
        World::with([], accounts, []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ))
}

fn bench_collection_metadata(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("torii_collection_metadata");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_secs(2));
    for count in [128, 1024] {
        let state = account_state(count);
        group.throughput(Throughput::Elements(count as u64));
        // Both predicates reject every account and return the same empty exact
        // page. Only the metadata predicate needs the full row JSON graph.
        for (name, filter) in [
            ("scalar_rejection", "label = \"unmatched\""),
            ("metadata_rejection", "metadata.tier = \"silver\""),
        ] {
            let query = norito::json!({
                "filter": filter, "include_total": true, "limit": 10, "select": ["id"]
            });
            group.bench_with_input(BenchmarkId::new(name, count), &query, |b, query| {
                b.iter(|| {
                    runtime.block_on(async {
                        let response = collection_query_for_bench(
                            Arc::clone(&state),
                            "accounts",
                            None,
                            query.clone(),
                            MaybeTelemetry::disabled(),
                        )
                        .await
                        .expect("collection query");
                        assert_eq!(response.status(), axum::http::StatusCode::OK);
                        let body = axum::body::to_bytes(response.into_body(), 1024)
                            .await
                            .expect("bounded empty page");
                        let page: norito::json::Value =
                            norito::json::from_slice(&body).expect("page JSON");
                        assert_eq!(page["total"].as_u64(), Some(0));
                        assert!(page["items"].as_array().expect("items").is_empty());
                        black_box(body);
                    })
                });
            });
        }
    }
    group.finish();
}

/// Run the collection metadata benchmarks.
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_collection_metadata(&mut criterion);
    criterion.final_summary();
}
