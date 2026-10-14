//! Grouped Torii core route integration tests.

#[path = "../account_query_subrouter_smoke.rs"]
mod account_query_subrouter_smoke;
#[path = "../accounts_endpoints.rs"]
mod accounts_endpoints;
#[path = "../accounts_portfolio.rs"]
mod accounts_portfolio;
#[path = "../address_parsing.rs"]
mod address_parsing;
#[path = "../app_api_router_smoke.rs"]
mod app_api_router_smoke;
#[path = "../asset_definitions_endpoints.rs"]
mod asset_definitions_endpoints;
#[path = "../configuration_endpoint.rs"]
mod configuration_endpoint;
#[path = "../domains_endpoints.rs"]
mod domains_endpoints;
#[path = "../first_release_api.rs"]
mod first_release_api;
#[path = "../nfts_endpoints.rs"]
mod nfts_endpoints;
#[path = "../operator_core_pipeline_reads.rs"]
mod operator_core_pipeline_reads;
#[path = "../router_feature_matrix.rs"]
mod router_feature_matrix;
#[path = "../runtime_endpoints.rs"]
mod runtime_endpoints;
#[path = "../rwas_endpoints.rs"]
mod rwas_endpoints;
#[path = "../transactions_query_operator_auth.rs"]
mod transactions_query_operator_auth;
#[path = "../webhooks_subrouter_smoke.rs"]
mod webhooks_subrouter_smoke;
