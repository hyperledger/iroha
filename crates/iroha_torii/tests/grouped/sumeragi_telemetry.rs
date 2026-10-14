//! Grouped Torii Sumeragi and telemetry integration tests.

#[path = "../metrics_registry.rs"]
mod metrics_registry;
#[path = "../metrics_registry_reset.rs"]
mod metrics_registry_reset;
#[path = "../pipeline_recovery_endpoint.rs"]
mod pipeline_recovery_endpoint;
#[path = "../sse_proof_callhash.rs"]
mod sse_proof_callhash;
#[path = "../sse_proof_envelope_hash.rs"]
mod sse_proof_envelope_hash;
#[path = "../sse_proof_rejected_fields.rs"]
mod sse_proof_rejected_fields;
#[path = "../sse_proof_verified_fields.rs"]
mod sse_proof_verified_fields;
#[path = "../sumeragi_params_endpoint.rs"]
mod sumeragi_params_endpoint;
#[path = "../sumeragi_status_sse.rs"]
mod sumeragi_status_sse;
#[path = "../sumeragi_status_sse_profile_gate.rs"]
mod sumeragi_status_sse_profile_gate;
#[path = "../sumeragi_tel_subrouter_smoke.rs"]
mod sumeragi_tel_subrouter_smoke;
#[path = "../telemetry_gating.rs"]
mod telemetry_gating;
#[path = "../torii_start.rs"]
mod torii_start;

#[cfg(feature = "telemetry")]
#[path = "../common/sumeragi_evidence.rs"]
mod sumeragi_evidence;
#[path = "../sumeragi_evidence_count_endpoint.rs"]
mod sumeragi_evidence_count_endpoint;
#[path = "../sumeragi_evidence_list_endpoint.rs"]
mod sumeragi_evidence_list_endpoint;
