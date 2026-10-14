//! Grouped IVM integration tests.

#[path = "../common.rs"]
mod common;
#[path = "../dynamic_memory.rs"]
mod dynamic_memory;
#[path = "../ed25519_batch.rs"]
mod ed25519_batch;
#[path = "../encoding.rs"]
mod encoding;
#[path = "../expanded_instruction.rs"]
mod expanded_instruction;
#[path = "../field_dispatch.rs"]
mod field_dispatch;
#[path = "../field_ops.rs"]
mod field_ops;
#[path = "../gas.rs"]
mod gas;
#[path = "../gas_conformance.rs"]
mod gas_conformance;
#[path = "../gas_golden.rs"]
mod gas_golden;
#[path = "../gas_property.rs"]
mod gas_property;
#[path = "../gas_replay.rs"]
mod gas_replay;
#[path = "../gas_schedule.rs"]
mod gas_schedule;
#[path = "../gas_schedule_hash.rs"]
mod gas_schedule_hash;
#[path = "../gpu_determinism.rs"]
mod gpu_determinism;
#[path = "../hardware_determinism.rs"]
mod hardware_determinism;
#[path = "../host_roundtrip.rs"]
mod host_roundtrip;
#[path = "../host_syscall_coverage.rs"]
mod host_syscall_coverage;
#[path = "../host_unknown_syscall.rs"]
mod host_unknown_syscall;
#[path = "../i18n.rs"]
mod i18n;
#[path = "../input_tlv_alloc.rs"]
mod input_tlv_alloc;
#[path = "../ivm_abi_doc_sync.rs"]
mod ivm_abi_doc_sync;
