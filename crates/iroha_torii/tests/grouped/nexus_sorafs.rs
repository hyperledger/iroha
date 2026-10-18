//! Grouped Torii Nexus, SoraFS, contract, and app surface integration tests.

#[path = "../contracts_call_integration.rs"]
mod contracts_call_integration;
#[path = "../kaigi_endpoints.rs"]
mod kaigi_endpoints;
#[path = "../kaigi_operator_reads.rs"]
mod kaigi_operator_reads;
#[path = "../nexus_dataspaces_summary.rs"]
mod nexus_dataspaces_summary;
#[path = "../nexus_public_lanes.rs"]
mod nexus_public_lanes;
#[path = "../push_bridge.rs"]
mod push_bridge;
#[path = "../sns_registrar.rs"]
mod sns_registrar;
#[path = "../sorafs_discovery.rs"]
mod sorafs_discovery;
#[path = "../sorafs_repair_endpoints.rs"]
mod sorafs_repair_endpoints;
#[path = "../soranet_privacy_endpoints.rs"]
mod soranet_privacy_endpoints;
#[path = "../space_directory_manifests.rs"]
mod space_directory_manifests;
#[path = "../subscriptions_endpoints.rs"]
mod subscriptions_endpoints;

#[path = "../nexus_lifecycle_endpoint.rs"]
mod nexus_lifecycle_endpoint;
