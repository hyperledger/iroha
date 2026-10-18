//! Grouped integration harness for Nexus, streaming, and Sora/SoraFS flows.
#[path = "kotodama_examples.rs"]
mod kotodama_examples;
#[path = "nexus/mod.rs"]
mod nexus;
#[path = "norito_burn_fixture.rs"]
mod norito_burn_fixture;
#[cfg(feature = "quic")]
#[path = "norito_streaming_end_to_end.rs"]
mod norito_streaming_end_to_end;
#[path = "norito_streaming_fec.rs"]
mod norito_streaming_fec;
#[cfg(feature = "quic")]
#[path = "norito_streaming_feedback.rs"]
mod norito_streaming_feedback;
#[path = "norito_streaming_negative.rs"]
mod norito_streaming_negative;
#[path = "norito_streaming_roundtrip.rs"]
mod norito_streaming_roundtrip;
#[path = "sorafs_gateway_capability_refusal.rs"]
mod sorafs_gateway_capability_refusal;
#[path = "sorafs_gateway_conformance.rs"]
mod sorafs_gateway_conformance;
#[path = "sorafs_orchestrator_parity.rs"]
mod sorafs_orchestrator_parity;
#[path = "soranet_web_deploy.rs"]
mod soranet_web_deploy;
#[path = "streaming/mod.rs"]
mod streaming;
