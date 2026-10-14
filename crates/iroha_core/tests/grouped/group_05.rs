//! Grouped Iroha Core integration tests.

#[path = "../../src/manifest_signing_test_support.rs"]
mod manifest_signing_test_support;
#[path = "../private_settlement_responder_attestation.rs"]
mod private_settlement_responder_attestation;
#[path = "../zk_roots_get_cap.rs"]
mod zk_roots_get_cap;
#[path = "../zk_stark.rs"]
mod zk_stark;
#[path = "../zk_testkit.rs"]
mod zk_testkit;
#[path = "../zk_verify.rs"]
mod zk_verify;
#[path = "../zk_verify_vendor_e2e.rs"]
mod zk_verify_vendor_e2e;
#[path = "../zk_vk_circuit_index.rs"]
mod zk_vk_circuit_index;
#[path = "../zk_vk_events.rs"]
mod zk_vk_events;
#[path = "../zk_vote_get_tally.rs"]
mod zk_vote_get_tally;
#[path = "../zk_vote_tally_audit.rs"]
mod zk_vote_tally_audit;
