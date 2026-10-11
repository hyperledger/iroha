//! Grouped IVM integration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "../zk_mode.rs"]
mod zk_mode;
#[path = "../zk_open_batch_smoke.rs"]
mod zk_open_batch_smoke;
#[path = "../zk_open_envelope_determinism.rs"]
mod zk_open_envelope_determinism;
#[path = "../zk_open_envelope_roundtrip.rs"]
mod zk_open_envelope_roundtrip;
#[path = "../zk_roots_and_vote_syscalls.rs"]
mod zk_roots_and_vote_syscalls;
#[path = "../zk_syscall_policy.rs"]
mod zk_syscall_policy;
#[path = "../zk_trace.rs"]
mod zk_trace;
#[path = "../zk_verify_batch_gating.rs"]
mod zk_verify_batch_gating;
#[path = "../zk_verify_batch_syscall.rs"]
mod zk_verify_batch_syscall;
#[path = "../zk_verify_gating.rs"]
mod zk_verify_gating;
#[path = "../zk_verify_goldilocks.rs"]
mod zk_verify_goldilocks;
#[path = "../zk_verify_pointer_type.rs"]
mod zk_verify_pointer_type;
#[path = "../zk_verify_positive_matrix.rs"]
mod zk_verify_positive_matrix;
#[path = "../zk_verify_syscall.rs"]
mod zk_verify_syscall;
