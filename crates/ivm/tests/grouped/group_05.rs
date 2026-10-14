//! Grouped IVM integration tests.

#[path = "../common.rs"]
mod common;
#[path = "../kotodama_amounts.rs"]
mod kotodama_amounts;
#[path = "../kotodama_argument_record.rs"]
mod kotodama_argument_record;
#[path = "../kotodama_checked_arithmetic.rs"]
mod kotodama_checked_arithmetic;
#[path = "../kotodama_dead_operands.rs"]
mod kotodama_dead_operands;
#[path = "../kotodama_lists.rs"]
mod kotodama_lists;
#[path = "../kotodama_simple_contracts.rs"]
mod kotodama_simple_contracts;
#[path = "../kotodama_state_aggregate_literal_runtime.rs"]
mod kotodama_state_aggregate_literal_runtime;
#[path = "../kotodama_state_borrowed_operands.rs"]
mod kotodama_state_borrowed_operands;
#[path = "../kotodama_state_map_lowering.rs"]
mod kotodama_state_map_lowering;
#[path = "../kotodama_state_map_pointer.rs"]
mod kotodama_state_map_pointer;
#[path = "../kotodama_state_name_map_runtime.rs"]
mod kotodama_state_name_map_runtime;
#[path = "../kotodama_state_scalar.rs"]
mod kotodama_state_scalar;
#[path = "../kotodama_state_struct_pointer.rs"]
mod kotodama_state_struct_pointer;
#[path = "../kotodama_struct_fields.rs"]
mod kotodama_struct_fields;
#[path = "../kotodama_struct_fields_corehost.rs"]
mod kotodama_struct_fields_corehost;
#[path = "../kotodama_structural_equality.rs"]
mod kotodama_structural_equality;
#[path = "../kotodama_ternary_lowering.rs"]
mod kotodama_ternary_lowering;
#[path = "../kotodama_tuple_codegen_neg.rs"]
mod kotodama_tuple_codegen_neg;
#[path = "../kotodama_tuple_lowering.rs"]
mod kotodama_tuple_lowering;
#[path = "../kotodama_v1_runtime_acceptance.rs"]
mod kotodama_v1_runtime_acceptance;
#[path = "../kotodama_vrf_transport_runtime.rs"]
mod kotodama_vrf_transport_runtime;
#[path = "../kotodama_zk_syscalls.rs"]
mod kotodama_zk_syscalls;
#[path = "../load_code.rs"]
mod load_code;
#[path = "../manifest_roundtrip.rs"]
mod manifest_roundtrip;
#[path = "../memory.rs"]
mod memory;
#[path = "../memory_commit.rs"]
mod memory_commit;
#[path = "../memory_compact_helper.rs"]
mod memory_compact_helper;
#[path = "../memory_log.rs"]
mod memory_log;
#[path = "../memory_merkle.rs"]
mod memory_merkle;
#[path = "../memory_merkle_combined.rs"]
mod memory_merkle_combined;
#[path = "../memory_request_semantics.rs"]
mod memory_request_semantics;
#[path = "../merkle_cross.rs"]
mod merkle_cross;
#[path = "../merkle_crosscrate.rs"]
mod merkle_crosscrate;
#[path = "../merkle_dirs_crosscheck.rs"]
mod merkle_dirs_crosscheck;
#[path = "../merkle_unification.rs"]
mod merkle_unification;
#[path = "../metadata.rs"]
mod metadata;
#[path = "../metadata_parse.rs"]
mod metadata_parse;
#[path = "../metadata_roundtrip.rs"]
mod metadata_roundtrip;
#[path = "../metal_disable_on_mismatch.rs"]
mod metal_disable_on_mismatch;

#[path = "../kotodama_call_tables.rs"]
mod kotodama_call_tables;
#[path = "../tiny_workload_dispatch.rs"]
mod tiny_workload_dispatch;

#[path = "../kotodama_compact_call_schema.rs"]
mod kotodama_compact_call_schema;
