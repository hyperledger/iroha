//! Benchmarks for core query execution (e.g., FindAccounts) over varying state sizes.

#![allow(
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::field_reassign_with_default,
    clippy::items_after_statements
)]
use criterion::{BatchSize, BenchmarkId, Criterion};
use iroha_core::{
    prelude::*,
    query::snapshot::{CursorMode as LaneCursorMode, run_on_snapshot, run_on_snapshot_with_mode},
    query::store::LiveQueryStore,
    smartcontracts::{
        Execute, ValidQuery,
        isi::query::{QueryCountMode, QueryLimits},
        ivm::host::CoreHostImpl,
    },
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    prelude::*,
    query::{
        ErasedIterQuery, QueryBox, QueryRequest, QueryResponse, QueryWithParams,
        account::prelude::{FindAccounts, FindAccountsWithAsset},
        asset::prelude::{FindAssetDefinitions, FindAssets},
        domain::prelude::FindDomains,
        dsl::CompoundPredicate,
        nft::prelude::FindNfts,
        parameters::{FetchSize, Pagination, QueryParams, Sorting},
        trigger::prelude::{FindActiveTriggerIds, FindTriggers},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;
use ivm::{
    IVM,
    core_query::{CoreQueryEntityTagV1, QUERY_PAGE_CAPACITY_V1},
    host::IVMHost,
};
use std::{num::NonZeroU64, sync::LazyLock};
// Shared Tokio runtime for benches that need background tasks (e.g., LiveQueryStore)
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
});
fn fixture_account_in_domain(label: &str, _domain_id: &DomainId) -> AccountId {
    let seed: Vec<u8> = label.as_bytes().iter().copied().cycle().take(32).collect();
    let (public_key, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("derive query benchmark account key")
        .into_parts();
    AccountId::new(public_key)
}
fn bench_domain_id() -> DomainId {
    DomainId::try_new("bench", "universal").expect("bench domain id")
}
fn bench_account(label: &str) -> AccountId {
    fixture_account_in_domain(label, &bench_domain_id())
}
fn bench_asset_def_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("bench", "universal").expect("bench domain"),
        "coin".parse().expect("bench asset definition name"),
    )
}
fn build_state_with_accounts(n: usize) -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    // Ensure Tokio reactor is available for LiveQueryStore background task
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let domain_id = bench_domain_id();
    let authority_id = bench_account("authority");
    let domain = Domain::new(domain_id.clone()).build(&authority_id);
    let mut accounts = Vec::with_capacity(n);
    for i in 0..n {
        let acc_id = bench_account(&format!("user{i}"));
        // Use the account itself as the authority for building
        let account = Account::new(acc_id.clone()).build(&acc_id);
        accounts.push(account);
    }
    State::new(
        World::with([domain], accounts, []),
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
}
fn bench_find_accounts_small(c: &mut Criterion) {
    let state = build_state_with_accounts(1_000);
    c.bench_function("find_accounts_iter_1k", |b| {
        b.iter(|| {
            let state_view = state.view();
            let iter = ValidQuery::execute(FindAccounts, CompoundPredicate::PASS, &state_view)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_accounts_large(c: &mut Criterion) {
    let state = build_state_with_accounts(10_000);
    c.bench_function("find_accounts_iter_10k", |b| {
        b.iter(|| {
            let state_view = state.view();
            let iter = ValidQuery::execute(FindAccounts, CompoundPredicate::PASS, &state_view)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_accounts_filter_id_literal(c: &mut Criterion) {
    let state = build_state_with_accounts(10_000);
    let needle = bench_account("user4242");
    let filter = CompoundPredicate::<Account>::build(|p| p.equals("id", needle.to_string()));
    c.bench_function("find_accounts_filter_id_literal_10k", |b| {
        b.iter(|| {
            let view = state.view();
            let iter =
                ValidQuery::execute(FindAccounts, filter.clone(), &view).expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_accounts_sort_id(c: &mut Criterion) {
    let state = build_state_with_accounts(10_000);
    c.bench_function("find_accounts_sort_by_id_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAccounts, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let mut vec: Vec<_> = iter.collect();
            vec.sort_by(|a, b| a.id().cmp(b.id()));
            std::hint::black_box(vec.len());
        })
    });
}
fn bench_find_accounts_paginate(c: &mut Criterion) {
    let state = build_state_with_accounts(10_000);
    let page = 100usize;
    c.bench_function("find_accounts_paginate_10k_page_100", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAccounts, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let items: Vec<_> = iter.collect();
            let mut pages = 0usize;
            let mut idx = 0usize;
            while idx < items.len() {
                let end = (idx + page).min(items.len());
                let _page_slice = &items[idx..end];
                pages += 1;
                idx = end;
            }
            std::hint::black_box(pages);
        })
    });
}
#[derive(Clone, Copy)]
struct TypedCoreQueryFamily {
    benchmark_name: &'static str,
    tag: CoreQueryEntityTagV1,
    words_per_item: u64,
}
const TYPED_CORE_QUERY_FAMILIES: [TypedCoreQueryFamily; 5] = [
    TypedCoreQueryFamily {
        benchmark_name: "typed_core_query_accounts_page_64",
        tag: CoreQueryEntityTagV1::Account,
        words_per_item: 2,
    },
    TypedCoreQueryFamily {
        benchmark_name: "typed_core_query_assets_page_64",
        tag: CoreQueryEntityTagV1::Asset,
        words_per_item: 2,
    },
    TypedCoreQueryFamily {
        benchmark_name: "typed_core_query_asset_definitions_page_64",
        tag: CoreQueryEntityTagV1::AssetDefinition,
        words_per_item: 6,
    },
    TypedCoreQueryFamily {
        benchmark_name: "typed_core_query_domains_page_64",
        tag: CoreQueryEntityTagV1::Domain,
        words_per_item: 3,
    },
    TypedCoreQueryFamily {
        benchmark_name: "typed_core_query_nfts_page_64",
        tag: CoreQueryEntityTagV1::Nft,
        words_per_item: 3,
    },
];
fn raw_core_query_response(
    state: &State,
    query_handle: &iroha_core::query::store::LiveQueryStoreHandle,
    authority: &AccountId,
    tag: CoreQueryEntityTagV1,
) -> QueryResponse {
    let page_size = NonZeroU64::new(QUERY_PAGE_CAPACITY_V1 as u64)
        .expect("typed query page capacity is non-zero");
    let params = QueryParams::new(
        Pagination::new(Some(page_size), 0),
        Sorting::default(),
        FetchSize::new(Some(page_size)),
    );
    macro_rules! request_for {
        ($item:ty, $query:expr) => {{
            let query = $query;
            let erased = ErasedIterQuery::<$item>::new(
                CompoundPredicate::PASS,
                iroha_data_model::query::dsl::SelectorTuple::default(),
                norito::codec::Encode::encode(&query),
            );
            let boxed: QueryBox<_> = Box::new(erased);
            QueryRequest::Start(
                QueryWithParams::new(&boxed, params.clone())
                    .expect("benchmark query type has a canonical mapping"),
            )
        }};
    }
    let request = match tag {
        CoreQueryEntityTagV1::Account => request_for!(Account, FindAccounts),
        CoreQueryEntityTagV1::Asset => request_for!(Asset, FindAssets),
        CoreQueryEntityTagV1::AssetDefinition => {
            request_for!(AssetDefinition, FindAssetDefinitions)
        }
        CoreQueryEntityTagV1::Domain => request_for!(Domain, FindDomains),
        CoreQueryEntityTagV1::Nft => request_for!(Nft, FindNfts),
    };
    let response = run_on_snapshot(
        state,
        query_handle,
        authority,
        request,
        QueryLimits::default(),
    )
    .unwrap_or_else(|error| panic!("execute raw {tag:?} QueryResponse baseline: {error:?}"));
    let QueryResponse::Iterable(output) = &response else {
        panic!("raw {tag:?} baseline must return an iterable QueryResponse")
    };
    assert_eq!(
        output.batch.len(),
        QUERY_PAGE_CAPACITY_V1,
        "raw {tag:?} baseline must contain one full page"
    );
    assert!(
        !output.has_more && output.continue_cursor.is_none(),
        "exactly one raw {tag:?} page must exhaust the fixture"
    );
    response
}
fn build_state_for_typed_core_query_pages() -> (State, AccountId, [u64; 5]) {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let authority = bench_account("typed-query-authority");
    let mut domains = Vec::with_capacity(QUERY_PAGE_CAPACITY_V1);
    let mut accounts = Vec::with_capacity(QUERY_PAGE_CAPACITY_V1);
    let mut asset_definitions = Vec::with_capacity(QUERY_PAGE_CAPACITY_V1);
    let mut assets = Vec::with_capacity(QUERY_PAGE_CAPACITY_V1);
    let mut nfts = Vec::with_capacity(QUERY_PAGE_CAPACITY_V1);
    accounts.push(Account::new(authority.clone()).build(&authority));
    for i in 0..QUERY_PAGE_CAPACITY_V1 {
        let domain_id = DomainId::try_new(format!("typed{i}"), "universal")
            .expect("typed query benchmark domain id");
        domains.push(Domain::new(domain_id.clone()).build(&authority));
        let account_id = bench_account(&format!("typed-query-user{i}"));
        if i + 1 < QUERY_PAGE_CAPACITY_V1 {
            accounts.push(Account::new(account_id.clone()).build(&authority));
        }
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "coin".parse().expect("asset name"),
        );
        asset_definitions.push(
            AssetDefinition::numeric(
                asset_definition_id.clone(),
                "coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority),
        );
        assets.push(Asset::new(
            AssetId::of(asset_definition_id, authority.clone()),
            Quantity::from(u64::try_from(i).expect("fixture index fits u64") + 1),
        ));
        let nft_id: NftId = format!("ticket{i}$typed{i}.universal")
            .parse()
            .expect("typed query benchmark NFT id");
        nfts.push(Nft::new(nft_id, Metadata::default()).build(&authority));
    }
    let state = State::new(
        World::with_assets(domains, accounts, asset_definitions, assets, nfts),
        kura,
        query_handle.clone(),
        #[cfg(feature = "telemetry")]
        <_>::default(),
    );
    let raw_query_response_bytes = TYPED_CORE_QUERY_FAMILIES.map(|family| {
        u64::try_from(
            norito::to_bytes(&raw_core_query_response(
                &state,
                &query_handle,
                &authority,
                family.tag,
            ))
            .unwrap_or_else(|error| {
                panic!(
                    "encode raw {:?} QueryResponse baseline: {error}",
                    family.tag
                )
            })
            .len(),
        )
        .expect("raw QueryResponse length fits u64")
    });
    (state, authority, raw_query_response_bytes)
}
fn bench_typed_core_query_pages(c: &mut Criterion) {
    let (state, authority, raw_query_response_bytes) = build_state_for_typed_core_query_pages();
    let view = state.view();
    let mut host = CoreHostImpl::new(authority);
    host.set_query_state(&view);
    host.enable_core_query_page_metrics();
    for (family, raw_query_response_bytes) in TYPED_CORE_QUERY_FAMILIES
        .into_iter()
        .zip(raw_query_response_bytes)
    {
        let page_layout =
            ivm::list::ListLayoutV1::try_new(QUERY_PAGE_CAPACITY_V1 as u64, family.words_per_item)
                .expect("typed query-page List layout");
        // Prove the performance contract on the exact production path before
        // Criterion samples it. Keeping these assertions outside the timed
        // loop prevents validation overhead from contaminating the result.
        host.reset_core_query_page_metrics();
        let mut preflight_vm = IVM::new(u64::MAX);
        preflight_vm.set_register(10, family.tag.as_u64());
        preflight_vm.set_register(11, 0);
        preflight_vm.set_register(12, QUERY_PAGE_CAPACITY_V1 as u64);
        host.syscall(ivm::syscalls::SYSCALL_CORE_QUERY_PAGE, &mut preflight_vm)
            .unwrap_or_else(|error| {
                panic!(
                    "preflight typed {:?} production page query: {error:?}",
                    family.tag
                )
            });
        let preflight_items =
            ivm::list::read_words(&preflight_vm, preflight_vm.register(10), page_layout)
                .unwrap_or_else(|error| {
                    panic!(
                        "preflight materialize typed {:?} production page: {error:?}",
                        family.tag
                    )
                });
        assert_eq!(
            preflight_items.len(),
            QUERY_PAGE_CAPACITY_V1,
            "one full typed {:?} production page",
            family.tag
        );
        let preflight_metrics = host
            .core_query_page_metrics()
            .expect("typed page-query counters enabled");
        assert_eq!(
            preflight_metrics.host_queries, 1,
            "one host query per typed {:?} production page",
            family.tag
        );
        assert_eq!(
            preflight_metrics.projection_decodes, 1,
            "one projection decode per typed {:?} production page",
            family.tag
        );
        assert!(
            preflight_metrics.leaf_tlv_bytes > 0,
            "typed {:?} leaves must be encoded exactly once before materialization",
            family.tag
        );
        assert!(
            preflight_metrics.projection_payload_bytes < raw_query_response_bytes,
            "typed {:?} projection payload ({} bytes) must be smaller than the raw QueryResponse envelope ({} bytes)",
            family.tag,
            preflight_metrics.projection_payload_bytes,
            raw_query_response_bytes,
        );
        c.bench_function(family.benchmark_name, |b| {
            b.iter_batched(
                || {
                    let mut vm = IVM::new(u64::MAX);
                    vm.set_register(10, family.tag.as_u64());
                    vm.set_register(11, 0);
                    vm.set_register(12, QUERY_PAGE_CAPACITY_V1 as u64);
                    vm
                },
                |mut vm| {
                    host.reset_core_query_page_metrics();
                    let gas = host
                        .syscall(ivm::syscalls::SYSCALL_CORE_QUERY_PAGE, &mut vm)
                        .unwrap_or_else(|error| {
                            panic!("execute typed {:?} page query: {error:?}", family.tag)
                        });
                    let items = ivm::list::read_words(&vm, vm.register(10), page_layout)
                        .unwrap_or_else(|error| {
                            panic!("materialize typed {:?} page: {error:?}", family.tag)
                        });
                    assert_eq!(
                        items.len(),
                        QUERY_PAGE_CAPACITY_V1,
                        "one full typed {:?} page",
                        family.tag
                    );
                    let metrics = host
                        .core_query_page_metrics()
                        .expect("typed page-query counters enabled");
                    assert_eq!(
                        metrics.host_queries, 1,
                        "one host query per typed {:?} page",
                        family.tag
                    );
                    assert_eq!(
                        metrics.projection_decodes, 1,
                        "one projection decode per typed {:?} page",
                        family.tag
                    );
                    assert!(
                        metrics.leaf_tlv_bytes > 0,
                        "typed {:?} leaves must be encoded exactly once before materialization",
                        family.tag
                    );
                    assert!(
                        metrics.projection_payload_bytes < raw_query_response_bytes,
                        "typed {:?} projection payload ({} bytes) must be smaller than the raw QueryResponse envelope ({} bytes)",
                        family.tag,
                        metrics.projection_payload_bytes,
                        raw_query_response_bytes,
                    );
                    std::hint::black_box((gas, items, vm.register(11), metrics));
                },
                BatchSize::SmallInput,
            )
        });
    }
}
fn bench_snapshot_vs_live_find_domains_first_batch(c: &mut Criterion) {
    // Build world with 10k domains
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let authority_id = bench_account("authority");
    let mut domains = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let id = DomainId::try_new(format!("d{}", i), "universal").unwrap();
        domains.push(Domain::new(id).build(&authority_id));
    }
    let state = State::new_for_testing(
        World::with(
            domains,
            [Account::new(authority_id.clone()).build(&authority_id)],
            [],
        ),
        kura,
        query_handle.clone(),
    );
    // Build erased iterable FindDomains with small fetch_size
    let params = iroha_data_model::query::parameters::QueryParams::default();
    let payload =
        norito::codec::Encode::encode(&iroha_data_model::query::domain::prelude::FindDomains);
    let erased = iroha_data_model::query::ErasedIterQuery::<Domain>::new(
        iroha_data_model::query::dsl::CompoundPredicate::PASS,
        iroha_data_model::query::dsl::SelectorTuple::default(),
        payload,
    );
    let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
    // Live (baseline): just execute ValidQuery and take first batch materialization cost
    c.bench_function("live_find_domains_first_batch", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(
                iroha_data_model::query::domain::prelude::FindDomains,
                iroha_data_model::query::dsl::CompoundPredicate::PASS,
                &v,
            )
            .expect("query execute");
            // Materialize first 100
            let count = iter.take(100).count();
            std::hint::black_box(count);
        })
    });
    // Snapshot ephemeral
    c.bench_function("snapshot_ephemeral_find_domains_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("domain query type has a canonical mapping"),
            );
            let resp = run_on_snapshot(
                &state,
                &query_handle,
                &authority_id,
                request,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
    // Snapshot stored (same first-batch measurement)
    c.bench_function("snapshot_stored_find_domains_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("domain query type has a canonical mapping"),
            );
            let resp = run_on_snapshot_with_mode(
                &state,
                &query_handle,
                &authority_id,
                request,
                LaneCursorMode::Stored,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
    let mut count_group = c.benchmark_group("snapshot_find_domains_count_mode_first_batch");
    for count_mode in [QueryCountMode::Exact, QueryCountMode::Bounded] {
        let label = match count_mode {
            QueryCountMode::Exact => "exact",
            QueryCountMode::Bounded => "bounded",
        };
        let limits = QueryLimits::default().with_count_mode(count_mode);
        count_group.bench_with_input(
            BenchmarkId::new("ephemeral", label),
            &limits,
            |b, limits| {
                b.iter(|| {
                    let request = iroha_data_model::query::QueryRequest::Start(
                        iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                            .expect("domain query type has a canonical mapping"),
                    );
                    let resp =
                        run_on_snapshot(&state, &query_handle, &authority_id, request, *limits)
                            .expect("lane ok");
                    let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                        panic!("expected iterable")
                    };
                    let (batch, _rem, cur) = first.into_parts();
                    if let Some(cur) = cur {
                        query_handle.drop_query(&cur.query);
                    }
                    let v = match batch.into_iter().next().expect("slice") {
                        iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
                        _ => unreachable!(),
                    };
                    std::hint::black_box(v.len());
                })
            },
        );
        count_group.bench_with_input(BenchmarkId::new("stored", label), &limits, |b, limits| {
            b.iter(|| {
                let request = iroha_data_model::query::QueryRequest::Start(
                    iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                        .expect("domain query type has a canonical mapping"),
                );
                let resp = run_on_snapshot_with_mode(
                    &state,
                    &query_handle,
                    &authority_id,
                    request,
                    LaneCursorMode::Stored,
                    *limits,
                )
                .expect("lane ok");
                let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                    panic!("expected iterable")
                };
                let (batch, _rem, cur) = first.into_parts();
                if let Some(cur) = cur {
                    query_handle.drop_query(&cur.query);
                }
                let v = match batch.into_iter().next().expect("slice") {
                    iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
                    _ => unreachable!(),
                };
                std::hint::black_box(v.len());
            })
        });
    }
    count_group.finish();
}
fn bench_snapshot_vs_live_find_assets_first_batch(c: &mut Criterion) {
    use iroha_data_model::query::asset::prelude::FindAssets;
    // Build world: 1k accounts, each with one asset
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("bench", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("bench", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let mut accounts = Vec::with_capacity(1_000);
    let mut assets: Vec<iroha_data_model::asset::Asset> = Vec::with_capacity(1_000);
    for i in 0..1_000 {
        let acc_id = bench_account(&format!("user{i}"));
        let acc = Account::new(acc_id.clone()).build(&acc_id);
        accounts.push(acc);
        let asset_id = AssetId::new(asset_def_id.clone(), acc_id.clone());
        assets.push(iroha_data_model::asset::Asset::new(
            asset_id,
            Quantity::from(1_u32),
        ));
    }
    let domain = Domain::new(domain_id).build(&accounts[0].id().clone());
    let world = World::with_assets(
        [domain],
        accounts.clone(),
        [AssetDefinition::numeric(
            asset_def_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&accounts[0].id().clone())],
        assets,
        [],
    );
    let state = State::new_for_testing(world, kura, query_handle.clone());
    // Build erased iterable FindAssets
    let params = iroha_data_model::query::parameters::QueryParams::default();
    let payload = norito::codec::Encode::encode(&FindAssets);
    let erased = iroha_data_model::query::ErasedIterQuery::<Asset>::new(
        iroha_data_model::query::dsl::CompoundPredicate::PASS,
        iroha_data_model::query::dsl::SelectorTuple::default(),
        payload,
    );
    let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
    // Live baseline
    c.bench_function("live_find_assets_first_batch", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(
                FindAssets,
                iroha_data_model::query::dsl::CompoundPredicate::PASS,
                &v,
            )
            .expect("query execute");
            std::hint::black_box(iter.take(100).count());
        })
    });
    // Snapshot ephemeral vs stored
    let authority = bench_account("authority");
    c.bench_function("snapshot_ephemeral_find_assets_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("asset query type has a canonical mapping"),
            );
            let resp = run_on_snapshot(
                &state,
                &query_handle,
                &authority,
                request,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::Asset(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
    c.bench_function("snapshot_stored_find_assets_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("asset query type has a canonical mapping"),
            );
            let resp = run_on_snapshot_with_mode(
                &state,
                &query_handle,
                &authority,
                request,
                LaneCursorMode::Stored,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::Asset(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
}
fn bench_snapshot_sorted_asset_defs_first_batch(c: &mut Criterion) {
    use iroha_data_model::query::asset::prelude::FindAssetDefinitions;
    // Build world with 10k asset defs and rank metadata
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let auth = bench_account("authority");
    let domain = Domain::new(DomainId::try_new("bench", "universal").unwrap()).build(&auth);
    let mut defs = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bench", "universal").unwrap(),
            format!("ad{i}").parse().unwrap(),
        );
        let mut ad = AssetDefinition::numeric(
            id,
            format!("ad{i}"),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&auth);
        let _ = ad.metadata_mut().insert(
            "rank".parse().unwrap(),
            iroha_primitives::json::Json::from(norito::json!(i % 100)),
        );
        defs.push(ad);
    }
    let world = World::with([domain], [Account::new(auth.clone()).build(&auth)], defs);
    let state = State::new(
        world,
        kura,
        query_handle.clone(),
        #[cfg(feature = "telemetry")]
        <_>::default(),
    );
    // Params with sorting by metadata key rank
    let mut params = iroha_data_model::query::parameters::QueryParams::default();
    params.sorting =
        iroha_data_model::query::parameters::Sorting::by_metadata_key("rank".parse().unwrap());
    let payload = norito::codec::Encode::encode(&FindAssetDefinitions);
    let erased = iroha_data_model::query::ErasedIterQuery::<AssetDefinition>::new(
        iroha_data_model::query::dsl::CompoundPredicate::PASS,
        iroha_data_model::query::dsl::SelectorTuple::default(),
        payload,
    );
    let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
    c.bench_function("snapshot_ephemeral_sorted_asset_defs_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("asset-definition query type has a canonical mapping"),
            );
            let resp = run_on_snapshot(
                &state,
                &query_handle,
                &auth,
                request,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
    c.bench_function("snapshot_stored_sorted_asset_defs_first_batch", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("asset-definition query type has a canonical mapping"),
            );
            let resp = run_on_snapshot_with_mode(
                &state,
                &query_handle,
                &auth,
                request,
                LaneCursorMode::Stored,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = resp else {
                panic!("expected iterable")
            };
            let (batch, _rem, cur) = first.into_parts();
            if let Some(cur) = cur {
                query_handle.drop_query(&cur.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
    c.bench_function("snapshot_stored_sorted_asset_defs_first_continue", |b| {
        b.iter(|| {
            let request = iroha_data_model::query::QueryRequest::Start(
                iroha_data_model::query::QueryWithParams::new(&qbox, params.clone())
                    .expect("asset-definition query type has a canonical mapping"),
            );
            let first = run_on_snapshot_with_mode(
                &state,
                &query_handle,
                &auth,
                request,
                LaneCursorMode::Stored,
                QueryLimits::default(),
            )
            .expect("lane ok");
            let iroha_data_model::query::QueryResponse::Iterable(first) = first else {
                panic!("expected iterable")
            };
            let (_first_batch, _first_remaining, cursor) = first.into_parts();
            let cursor = cursor.expect("stored continuation");
            let continued = run_on_snapshot_with_mode(
                &state,
                &query_handle,
                &auth,
                iroha_data_model::query::QueryRequest::Continue(cursor),
                LaneCursorMode::Stored,
                QueryLimits::default(),
            )
            .expect("continue ok");
            let iroha_data_model::query::QueryResponse::Iterable(continued) = continued else {
                panic!("expected iterable")
            };
            let (batch, _remaining, next_cursor) = continued.into_parts();
            if let Some(next_cursor) = next_cursor {
                query_handle.drop_query(&next_cursor.query);
            }
            let v = match batch.into_iter().next().expect("slice") {
                iroha_data_model::query::QueryOutputBatchBox::AssetDefinition(v) => v,
                _ => unreachable!(),
            };
            std::hint::black_box(v.len());
        })
    });
}
fn build_state_with_assets(n_accounts: usize, assets_per_account: usize) -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let domain_id = bench_domain_id();
    let authority_id = bench_account("authority");
    let domain = Domain::new(domain_id.clone()).build(&authority_id);
    let base_def_id = bench_asset_def_id();
    let mut definition_ids = Vec::with_capacity(assets_per_account.max(1));
    definition_ids.push(base_def_id.clone());
    for j in 1..assets_per_account {
        definition_ids.push(AssetDefinitionId::derive_from_components(
            DomainId::try_new("bench", "universal").unwrap(),
            format!("coin{j}").parse().unwrap(),
        ));
    }
    let definitions: Vec<_> = definition_ids
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, id)| {
            let name = if index == 0 {
                "coin".to_owned()
            } else {
                format!("coin{index}")
            };
            AssetDefinition::numeric(
                id,
                name,
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority_id)
        })
        .collect();
    let mut accounts = Vec::with_capacity(n_accounts);
    let mut assets = Vec::with_capacity(n_accounts * definition_ids.len());
    for i in 0..n_accounts {
        let acc_id = bench_account(&format!("user{i}"));
        let account = Account::new(acc_id.clone()).build(&acc_id);
        for (j, definition_id) in definition_ids.iter().enumerate() {
            let asset_id = AssetId::new(definition_id.clone(), acc_id.clone());
            let value = Quantity::from(u128::from(j as u64 + 1));
            assets.push(Asset::new(asset_id, value));
        }
        accounts.push(account);
    }
    State::new(
        World::with_assets([domain], accounts, definitions, assets, []),
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
}
fn bench_find_assets_iter(c: &mut Criterion) {
    let state = build_state_with_assets(5_000, 2);
    c.bench_function("find_assets_iter_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAssets, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_assets_filter_account(c: &mut Criterion) {
    let state = build_state_with_assets(10_000, 1);
    let target = bench_account("user9999");
    let filter = CompoundPredicate::<Asset>::build(|p| p.equals("account", target.to_string()));
    c.bench_function("find_assets_filter_account_literal", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAssets, filter.clone(), &v).expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_assets_filter_quantity(c: &mut Criterion) {
    let state = build_state_with_assets(5_000, 2);
    let threshold = Quantity::from(2_u32);
    c.bench_function("find_assets_filter_quantity_ge_2", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAssets, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let count = iter.filter(|a| a.value() >= &threshold).count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_assets_filter_definition_literal(c: &mut Criterion) {
    let state = build_state_with_assets(10_000, 2);
    let definition = bench_asset_def_id();
    let filter =
        CompoundPredicate::<Asset>::build(|p| p.equals("definition", definition.to_string()));
    c.bench_function("find_assets_filter_definition_literal", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAssets, filter.clone(), &v).expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_assets_filter_domain_literal(c: &mut Criterion) {
    let state = build_state_with_assets(10_000, 2);
    let filter = CompoundPredicate::<Asset>::build(|p| p.equals("domain", "bench"));
    c.bench_function("find_assets_filter_domain_literal", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindAssets, filter.clone(), &v).expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_accounts_with_asset_literal(c: &mut Criterion) {
    let state = build_state_with_assets(10_000, 1);
    let definition = bench_asset_def_id();
    let target = bench_account("user4242");
    let filter = CompoundPredicate::<Account>::build(|p| p.equals("id", target.to_string()));
    c.bench_function("find_accounts_with_asset_id_literal_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(
                FindAccountsWithAsset::new(definition.clone()),
                filter.clone(),
                &v,
            )
            .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn build_state_with_domains(n: usize) -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let authority_id = bench_account("authority");
    let mut domains = Vec::with_capacity(n);
    for i in 0..n {
        let id = DomainId::try_new(format!("d{}", i), "universal").expect("domain id");
        domains.push(Domain::new(id).build(&authority_id));
    }
    State::new(
        World::with(domains, [], []),
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
}
fn bench_find_domains_iter(c: &mut Criterion) {
    let state = build_state_with_domains(5_000);
    c.bench_function("find_domains_iter_5k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindDomains, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_domains_sort(c: &mut Criterion) {
    let state = build_state_with_domains(10_000);
    c.bench_function("find_domains_sort_by_id_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindDomains, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let mut vec: Vec<_> = iter.collect();
            vec.sort_by(|a, b| a.id().cmp(b.id()));
            std::hint::black_box(vec.len());
        })
    });
}
fn build_state_with_asset_definitions(n: usize) -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    let domain_id = bench_domain_id();
    let authority_id = bench_account("authority");
    let domain = Domain::new(domain_id.clone()).build(&authority_id);
    let owner = Account::new(authority_id.clone()).build(&authority_id);
    let mut defs = Vec::with_capacity(n);
    for i in 0..n {
        let def_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bench", "universal").expect("domain"),
            format!("coin{i}").parse().expect("ad id"),
        );
        defs.push(
            AssetDefinition::numeric(
                def_id,
                format!("coin{i}"),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority_id),
        );
    }
    State::new(
        World::with_assets([domain], [owner], defs, [], []),
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
}
fn bench_find_asset_defs_iter(c: &mut Criterion) {
    let state = build_state_with_asset_definitions(10_000);
    c.bench_function("find_asset_defs_iter_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter =
                ValidQuery::execute(FindAssetDefinitions::new(), CompoundPredicate::PASS, &v)
                    .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn build_state_with_triggers(n_time: usize, n_by_call: usize) -> State {
    use iroha_core::block::BlockBuilder;
    use iroha_data_model::{
        events::time::{ExecutionTime, TimeEventFilter},
        trigger::prelude::*,
    };
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _guard = RUNTIME.enter();
    let query_handle = LiveQueryStore::start_test();
    // Start with an empty world and then register domain/account to act as authority
    // Use `new_for_testing` to provide a telemetry instance when required
    let state = State::new_for_testing(World::default(), kura, query_handle);
    fn dummy_accepted_transaction(network_id: NetworkId) -> AcceptedTransaction<'static> {
        use std::{borrow::Cow, time::Duration};
        let keypair = KeyPair::random();
        let authority = AccountId::new(keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(0));
        let tx = builder
            .with_instructions([Log::new(Level::INFO, "dummy".to_owned())])
            .sign(keypair.private_key());
        AcceptedTransaction::new_unchecked(Cow::Owned(tx))
    }
    // Create a header for a block to stage registrations
    let latest = state
        .view()
        .latest_block()
        .expect("benchmark canonical block read");
    let priv_key = iroha_crypto::KeyPair::random().private_key().clone();
    let header = BlockBuilder::new(vec![dummy_accepted_transaction(*state.network_id_ref())])
        .chain(0, latest.as_deref())
        .sign(&priv_key)
        .unpack(|_| {})
        .header();
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    // Authority
    let domain_id = bench_domain_id();
    let authority_id = bench_account("authority");
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&authority_id, &mut stx)
        .expect("register domain");
    Register::account(Account::new(authority_id.clone()))
        .execute(&authority_id, &mut stx)
        .expect("register account");
    // Time triggers (PreCommit), minimal action body
    for i in 0..n_time {
        let trig_id: TriggerId = format!("time_{}", i).parse().unwrap();
        let t = Trigger::new(
            trig_id,
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                authority_id.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(t)
            .execute(&authority_id, &mut stx)
            .expect("register time trigger");
    }
    // By-call triggers (no-op)
    use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
    for i in 0..n_by_call {
        let trig_id: TriggerId = format!("call_{}", i).parse().unwrap();
        let t = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                authority_id.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(t)
            .execute(&authority_id, &mut stx)
            .expect("register by-call trigger");
    }
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    state
}
fn bench_find_triggers_iter(c: &mut Criterion) {
    let state = build_state_with_triggers(5_000, 5_000);
    c.bench_function("find_triggers_iter_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindTriggers, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
fn bench_find_active_trigger_ids_iter(c: &mut Criterion) {
    let state = build_state_with_triggers(10_000, 0);
    c.bench_function("find_active_trigger_ids_iter_10k", |b| {
        b.iter(|| {
            let v = state.view();
            let iter = ValidQuery::execute(FindActiveTriggerIds, CompoundPredicate::PASS, &v)
                .expect("query execute");
            let count = iter.count();
            std::hint::black_box(count);
        })
    });
}
/// Entry point for the benchmark binary.
fn main() {
    // Silence IVM banner for benches that may trigger VM init in inner paths.
    #[allow(unused_imports)]
    {
        use ivm::set_banner_enabled;
        set_banner_enabled(false);
    }
    let mut c = Criterion::default().configure_from_args();
    bench_find_accounts_small(&mut c);
    bench_find_accounts_large(&mut c);
    bench_find_accounts_filter_id_literal(&mut c);
    bench_find_assets_iter(&mut c);
    bench_find_assets_filter_account(&mut c);
    bench_find_assets_filter_quantity(&mut c);
    bench_find_assets_filter_definition_literal(&mut c);
    bench_find_assets_filter_domain_literal(&mut c);
    bench_find_accounts_with_asset_literal(&mut c);
    bench_find_domains_iter(&mut c);
    bench_find_domains_sort(&mut c);
    bench_find_asset_defs_iter(&mut c);
    bench_find_triggers_iter(&mut c);
    bench_find_active_trigger_ids_iter(&mut c);
    bench_find_accounts_sort_id(&mut c);
    bench_find_accounts_paginate(&mut c);
    bench_typed_core_query_pages(&mut c);
    bench_snapshot_vs_live_find_domains_first_batch(&mut c);
    bench_snapshot_vs_live_find_assets_first_batch(&mut c);
    bench_snapshot_sorted_asset_defs_first_batch(&mut c);
    c.final_summary();
}
