//! Grouped Iroha Core integration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "../fx_routing_review.rs"]
mod fx_routing_review;
#[path = "../../src/manifest_signing_test_support.rs"]
mod manifest_signing_test_support;
#[path = "../pin_registry.rs"]
mod pin_registry;
#[path = "../quarantine_lane.rs"]
mod quarantine_lane;
#[path = "../query_active_abi.rs"]
mod query_active_abi;
#[path = "../queue_regressions.rs"]
mod queue_regressions;
#[path = "../queue_stress.rs"]
mod queue_stress;
#[path = "../runtime_upgrade_admission.rs"]
mod runtime_upgrade_admission;
#[path = "../settlement_overlay.rs"]
mod settlement_overlay;
#[path = "../social_viral_incentives.rs"]
mod social_viral_incentives;
#[path = "../sparse_block_bytes.rs"]
mod sparse_block_bytes;
#[path = "../sumeragi_doc_sync.rs"]
mod sumeragi_doc_sync;
#[path = "../validation_fee_admission.rs"]
mod validation_fee_admission;
#[path = "../validation_fee_plain_ballot_gates.rs"]
mod validation_fee_plain_ballot_gates;
#[path = "../zk_backend_tags.rs"]
mod zk_backend_tags;
#[path = "../zk_dedup.rs"]
mod zk_dedup;
#[path = "../zk_lane_warning.rs"]
mod zk_lane_warning;
#[path = "../zk_ledger_scaffold.rs"]
mod zk_ledger_scaffold;
#[path = "../zk_proof_event_callhash.rs"]
mod zk_proof_event_callhash;
#[path = "../zk_proof_retention.rs"]
mod zk_proof_retention;
