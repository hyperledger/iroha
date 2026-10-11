//! Grouped Iroha data model integration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "../account_address_vectors.rs"]
mod account_address_vectors;
#[path = "../account_id_roundtrip.rs"]
mod account_id_roundtrip;
#[path = "../address_curve_registry.rs"]
mod address_curve_registry;
#[path = "../api_exports.rs"]
mod api_exports;
#[path = "../axt_descriptor_fixture.rs"]
mod axt_descriptor_fixture;
#[path = "../axt_envelope_fixture.rs"]
mod axt_envelope_fixture;
#[path = "../axt_proof_envelope.rs"]
mod axt_proof_envelope;
#[path = "../ballot_proof_json.rs"]
mod ballot_proof_json;
#[path = "../ballot_proof_roundtrip.rs"]
mod ballot_proof_roundtrip;
#[path = "../blockheader_roundtrip.rs"]
mod blockheader_roundtrip;
#[path = "../confidential_memo_envelope_v1.rs"]
mod confidential_memo_envelope_v1;
#[path = "../consensus_roundtrip.rs"]
mod consensus_roundtrip;
#[path = "../da_ingest_roundtrip.rs"]
mod da_ingest_roundtrip;
#[path = "../data_model.rs"]
mod data_model;
#[path = "../find_roles_by_account_id.rs"]
mod find_roles_by_account_id;
#[path = "../id_json.rs"]
mod id_json;
#[path = "../id_of_constructors.rs"]
mod id_of_constructors;
#[path = "../instruction_box_clone.rs"]
mod instruction_box_clone;
#[path = "../instruction_impls.rs"]
mod instruction_impls;
#[path = "../instruction_registry_checksum.rs"]
mod instruction_registry_checksum;
#[path = "../instruction_registry_lazy_init.rs"]
mod instruction_registry_lazy_init;
#[path = "../instruction_registry_reset.rs"]
mod instruction_registry_reset;
#[path = "../join_kaigi_commitment_roundtrip.rs"]
mod join_kaigi_commitment_roundtrip;
#[path = "../join_kaigi_decode.rs"]
mod join_kaigi_decode;
#[path = "../kaigi_events_roundtrip.rs"]
mod kaigi_events_roundtrip;
#[path = "../mintable_json.rs"]
mod mintable_json;
#[path = "../model_derive_repro.rs"]
mod model_derive_repro;
#[path = "../native_evidence_codec.rs"]
mod native_evidence_codec;
