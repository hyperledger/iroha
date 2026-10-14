//! Grouped IVM integration tests.

#[path = "../common.rs"]
mod common;
#[path = "../poseidon_bridge.rs"]
mod poseidon_bridge;
#[path = "../poseidon_cuda_parity.rs"]
mod poseidon_cuda_parity;
#[path = "../poseidon_simd.rs"]
mod poseidon_simd;
#[path = "../predecode_artifact_keying.rs"]
mod predecode_artifact_keying;
#[path = "../predecode_bounds.rs"]
mod predecode_bounds;
#[path = "../predecode_cache.rs"]
mod predecode_cache;
#[path = "../predecode_cache_capacity.rs"]
mod predecode_cache_capacity;
#[path = "../predecode_max_ops.rs"]
mod predecode_max_ops;
#[path = "../predecode_memory_cap.rs"]
mod predecode_memory_cap;
#[path = "../predecode_stats.rs"]
mod predecode_stats;
#[path = "../predecode_test_support.rs"]
mod predecode_test_support;
#[path = "../predecode_vm_path.rs"]
mod predecode_vm_path;
#[path = "../predecoder_fixture_verify.rs"]
mod predecoder_fixture_verify;
#[path = "../predecoder_golden_vectors.rs"]
mod predecoder_golden_vectors;
#[path = "../privacy_enforcement.rs"]
mod privacy_enforcement;
#[path = "../private_input.rs"]
mod private_input;
#[path = "../prop_skeleton.rs"]
mod prop_skeleton;
#[path = "../register_log.rs"]
mod register_log;
#[path = "../register_merkle.rs"]
mod register_merkle;
#[path = "../register_trace.rs"]
mod register_trace;
#[path = "../registers_compact_helper.rs"]
mod registers_compact_helper;
#[path = "../registers_merkle.rs"]
mod registers_merkle;
#[path = "../schema_registry_roundtrip.rs"]
mod schema_registry_roundtrip;
#[path = "../sha256_parity.rs"]
mod sha256_parity;
#[path = "../shift_ops_regression.rs"]
mod shift_ops_regression;
#[path = "../shifts_edge.rs"]
mod shifts_edge;
