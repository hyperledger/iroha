//! Parts of one `IVM::run` that lie outside the per-opcode dispatch arms.
//!
//! An invocation can end before its first step, between steps or after its
//! last one. Each record restates the fault surface the interpreter source
//! shows for one such part; tests re-derive every column from
//! `crates/ivm/src/ivm.rs` and `crates/ivm/src/call_runtime.rs`, so a new
//! initialization or terminal error cannot appear without an inventory
//! review.

use super::Obligation;

/// One part of an invocation's run outside the per-opcode dispatch arms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunPhase {
    /// Stable machine-readable identifier.
    pub id: &'static str,
    /// Repository-relative source file holding the phase.
    pub path: &'static str,
    /// Function holding the phase.
    pub function: &'static str,
    /// What the phase does and how a failure in it ends the invocation.
    pub summary: &'static str,
    /// Relation obligation classes the phase engages.
    pub obligations: &'static [Obligation],
    /// `VMError` variants named directly in the phase.
    pub direct_traps: &'static [&'static str],
    /// Fallible helpers whose error the phase propagates with `?`.
    pub fallible_helpers: &'static [&'static str],
    /// Sources of a result the phase returns without `?`: a stored error or a
    /// fallible call in tail position.
    pub result_sources: &'static [&'static str],
}

const INTERPRETER: &str = "crates/ivm/src/ivm.rs";
const RUN: &str = "run_with_host_ref";

/// Every part of `IVM::run` outside the dispatch arms, in execution order.
pub const RUN_PHASES: &[RunPhase] = &[
    RunPhase {
        id: "invocation_entry",
        path: INTERPRETER,
        function: RUN,
        summary: "from function entry to the loop: checks the shared cycle allowance, admits the register logger and trace storage, refuses a non-ZK run that still holds private state, clears the previous invocation's protected call state and enters root-call initialization. A refused shared allowance is an initialization trap; a closed allowance, stale logger custody, stale private state and refused logger or trace storage produce local deferrals, never deterministic contract faults",
        obligations: &[
            Obligation::Initialization,
            Obligation::PrivateMasking,
            Obligation::StatementBinding,
        ],
        direct_traps: &["ExecutionDeferred"],
        fallible_helpers: &[
            "begin_root_call",
            "begin_trace_invocation",
            "budget.ensure_healthy",
            "prepare_invocation_register_log",
        ],
        result_sources: &[],
    },
    RunPhase {
        id: "root_call_initialization",
        path: "crates/ivm/src/call_runtime.rs",
        function: "begin_root_call",
        summary: "inside the run, before the first fetch: resolves the root callable and its authorized entrypoint, consumes the prepaid argument-decode gas or dispatches the default-host public-input syscall, debits result-table and call-table gas, preflights and allocates heap, prepares the root frame and validates the call tables; a failure is an initialization trap with zero completed steps and no runtime padding",
        obligations: &[
            Obligation::Initialization,
            Obligation::Pointers,
            Obligation::Calls,
            Obligation::Faults,
            Obligation::Gas,
            Obligation::Padding,
            Obligation::StatementBinding,
        ],
        direct_traps: &["DecodeError", "PermissionDenied"],
        fallible_helpers: &[
            "callable",
            "callable_index",
            "crate::argument_record::install_empty_call_arguments",
            "crate::argument_record::prepare_default_call_arguments",
            "memory.call_frames.prepare_root",
            "prepare_root_register_events",
            "prepared.install_call_arguments",
            "prepared.is_bound_to",
            "validate_call_tables",
        ],
        result_sources: &[],
    },
    RunPhase {
        id: "step_preamble",
        path: INTERPRETER,
        function: RUN,
        summary: "between loop entry and dispatch, before every step: completes the previous step's shared cycle reservation, publishes trace cycles, stops on halt, traps at end of code without a terminator and at the cycle limit, fetches the instruction, rejects an unadmitted opcode, prices the step, traps on an unaffordable debit, reserves shared cycles and debits base gas",
        obligations: &[
            Obligation::Fetch,
            Obligation::Faults,
            Obligation::Gas,
            Obligation::MemoryOrdering,
        ],
        direct_traps: &[
            "ExceededMaxCycles",
            "InvalidOpcode",
            "MissingHalt",
            "OutOfGas",
        ],
        fallible_helpers: &[
            "budget.reserve",
            "fetch_instruction",
            "finish_step",
            "prepare_trace_instruction",
            "publish_trace_cycles",
            "record_trace_prefetch",
            "recorder.begin_step",
            "reservation.complete",
            "vm.native_preflight_step",
            "vm.prepare_instruction_register_events",
        ],
        result_sources: &[],
    },
    RunPhase {
        id: "terminal",
        path: INTERPRETER,
        function: RUN,
        summary: "after the loop: completes the last shared cycle reservation, pads a ZK run to the cycle horizon with one gas unit per padded cycle and traps when padding gas or shared cycles run out, then returns the recorded contract abort, a failed assertion, an incomplete root result table under protected return integrity, or a refused shared cycle allowance",
        obligations: &[
            Obligation::Copyback,
            Obligation::Faults,
            Obligation::Gas,
            Obligation::Padding,
            Obligation::StatementBinding,
        ],
        direct_traps: &["AssertionFailed", "OutOfGas"],
        fallible_helpers: &[
            "budget.reserve",
            "call_result_word_count",
            "complete",
            "finish_step",
            "prepare_trace_padding",
            "publish_trace_cycles",
            "recorder.finish_step",
            "reservation.complete",
        ],
        result_sources: &["contract_abort_error", "ensure_healthy"],
    },
];

/// Return the phase with the given identifier.
#[must_use]
pub fn run_phase(id: &str) -> Option<&'static RunPhase> {
    RUN_PHASES.iter().find(|phase| phase.id == id)
}
