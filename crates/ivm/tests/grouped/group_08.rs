//! Grouped IVM integration tests.

#[path = "../common.rs"]
mod common;
#[path = "../shifts_prop.rs"]
mod shifts_prop;
#[path = "../simd_tail_misalignment.rs"]
mod simd_tail_misalignment;
#[path = "../sm_syscalls.rs"]
mod sm_syscalls;
#[path = "../stack_policy_v1.rs"]
mod stack_policy_v1;
#[path = "../syscall_names_complete.rs"]
mod syscall_names_complete;
#[path = "../syscall_unknown.rs"]
mod syscall_unknown;
#[path = "../syscalls.rs"]
mod syscalls;
#[path = "../syscalls_compact_end2end.rs"]
mod syscalls_compact_end2end;
#[path = "../syscalls_doc_generated.rs"]
mod syscalls_doc_generated;
#[path = "../syscalls_doc_sync.rs"]
mod syscalls_doc_sync;
#[path = "../syscalls_gas_names.rs"]
mod syscalls_gas_names;
#[path = "../syscalls_markdown_gas.rs"]
mod syscalls_markdown_gas;
#[path = "../syscalls_markdown_smoke.rs"]
mod syscalls_markdown_smoke;
#[path = "../syscalls_policy.rs"]
mod syscalls_policy;
#[path = "../syscalls_policy_versions.rs"]
mod syscalls_policy_versions;
#[path = "../syscalls_register_compact.rs"]
mod syscalls_register_compact;
#[path = "../tlv_examples.rs"]
mod tlv_examples;
#[path = "../trace_mode.rs"]
mod trace_mode;
#[path = "../vadd.rs"]
mod vadd;
#[path = "../vector_detect.rs"]
mod vector_detect;
#[path = "../vector_execution_regression.rs"]
mod vector_execution_regression;
#[path = "../vector_gating.rs"]
mod vector_gating;
#[path = "../vector_ops.rs"]
mod vector_ops;
#[path = "../vector_setvl_par.rs"]
mod vector_setvl_par;
#[path = "../verifier.rs"]
mod verifier;
#[path = "../verify_signature_tlv.rs"]
mod verify_signature_tlv;
