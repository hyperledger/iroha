//! Terminal and faulting outcomes mapped to their origin and proof obligations.
//!
//! Every [`VMError`] variant is classified by the trap kind `classify_trap`
//! assigns and by where it is produced: prepare-time rejection, root-call
//! initialization trap, interpreter trap, syscall trap, host invariant,
//! node-local deferral or a construction outside any invocation. The
//! exhaustive matches below make a new variant a compile error until it is
//! named; tests compare the tables with the enum sources, `classify_trap` and
//! the stable fault-tag decoders in both directions.
//!
//! [`VM_ERROR_PRODUCERS`] lists every non-test source file below
//! [`VM_ERROR_PRODUCER_SCOPE`] that constructs a variant. The
//! `(variant, file)` pairs are source-checked in both directions; the origin
//! assigned to each pair is a reviewed union over the call paths that reach
//! the file's construction sites.

use super::Obligation;
use crate::{
    VMError, VmTrapKind,
    numeric::{NumericFaultV1, PointerAbiFaultV1},
};

/// Where a failure originates relative to the proved invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrapOrigin {
    /// Raised before `run` while decoding, admitting or preparing an artifact,
    /// its entrypoint, its host or its argument record. No trace exists and no
    /// statement may be produced.
    PrepareRejection,
    /// Raised inside `run` before the first instruction is fetched, by the
    /// entry check of the shared cycle allowance or by root-call
    /// initialization: the prepaid argument-decode gas is consumed, result-
    /// and call-table gas is debited, the heap is preflighted and the call
    /// tables are validated. The invocation ends with zero completed steps,
    /// and the relation must prove the exact error and gas.
    InitializationTrap,
    /// Raised by the fetch-decode-execute loop, its memory, register,
    /// privacy-tag and call-frame helpers, or the terminal block after it.
    InterpreterTrap,
    /// Raised by syscall dispatch, metering or a host handler.
    SyscallTrap,
    /// A violated contract between the VM and its host that an honest host
    /// never produces; the relation must make it unreachable.
    HostInvariant,
    /// A node-local refusal that is never a consensus outcome and must never
    /// be provable as one.
    LocalDeferral,
    /// Constructed outside any VM run by code that reuses the error type: the
    /// result of an enclosing Core instruction, a codec helper Core calls
    /// directly, or a local diagnostic check or accessor. It is never the
    /// outcome of an invocation.
    OutsideInvocation,
}

impl TrapOrigin {
    /// Number of origin classes.
    pub const COUNT: usize = 7;

    /// Every origin class in stable order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::PrepareRejection,
        Self::InitializationTrap,
        Self::InterpreterTrap,
        Self::SyscallTrap,
        Self::HostInvariant,
        Self::LocalDeferral,
        Self::OutsideInvocation,
    ];

    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::PrepareRejection => "prepare_rejection",
            Self::InitializationTrap => "initialization_trap",
            Self::InterpreterTrap => "interpreter_trap",
            Self::SyscallTrap => "syscall_trap",
            Self::HostInvariant => "host_invariant",
            Self::LocalDeferral => "local_deferral",
            Self::OutsideInvocation => "outside_invocation",
        }
    }

    /// Whether a failure of this origin is a terminal outcome of a started
    /// invocation that the complete relation must prove.
    #[must_use]
    pub const fn in_invocation(self) -> bool {
        matches!(
            self,
            Self::InitializationTrap | Self::InterpreterTrap | Self::SyscallTrap
        )
    }

    /// Relation obligation classes a failure of this origin engages.
    ///
    /// A prepare rejection is bound only through the statement: the proved
    /// code, manifest and header are the admitted ones, so a rejected artifact
    /// has no proof. An initialization trap skips runtime padding, so the
    /// padding obligation constrains its executed padding cycles to zero. A
    /// node-local deferral and a construction outside any invocation engage
    /// none because neither may be provable.
    #[must_use]
    pub const fn obligations(self) -> &'static [Obligation] {
        match self {
            Self::PrepareRejection => &[Obligation::StatementBinding],
            Self::InitializationTrap => &[
                Obligation::Initialization,
                Obligation::Faults,
                Obligation::Gas,
                Obligation::Padding,
                Obligation::StatementBinding,
            ],
            Self::InterpreterTrap => &[
                Obligation::Faults,
                Obligation::Gas,
                Obligation::Padding,
                Obligation::StatementBinding,
            ],
            Self::SyscallTrap => &[
                Obligation::Faults,
                Obligation::Gas,
                Obligation::HostResult,
                Obligation::Padding,
                Obligation::StatementBinding,
            ],
            Self::HostInvariant => &[Obligation::Gas, Obligation::HostResult],
            Self::LocalDeferral | Self::OutsideInvocation => &[],
        }
    }
}

/// One reviewed producer of a failure: an origin and a source file whose
/// non-test code constructs the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrapEvidence {
    /// Origin class of the producer.
    pub origin: TrapOrigin,
    /// Repository-relative source file constructing the variant.
    pub path: &'static str,
}

/// `VMError` variants one source file constructs under one origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginGroup {
    /// Origin class shared by the listed variants.
    pub origin: TrapOrigin,
    /// Variant identifiers in `ivm_abi::error::VMError`.
    pub variants: &'static [&'static str],
}

/// One non-test source file that constructs [`VMError`] values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerFile {
    /// Repository-relative source file.
    pub path: &'static str,
    /// Every variant the file constructs, grouped by reviewed origin. A
    /// variant reachable through several call paths appears in each group.
    pub groups: &'static [OriginGroup],
}

impl ProducerFile {
    /// Distinct variants the file constructs, sorted.
    #[must_use]
    pub fn variants(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self
            .groups
            .iter()
            .flat_map(|group| group.variants.iter().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

macro_rules! producer {
    ($path:literal, $($origin:ident: [$($variant:ident),+ $(,)?]),+ $(,)?) => {
        ProducerFile {
            path: $path,
            groups: &[$(OriginGroup {
                origin: TrapOrigin::$origin,
                variants: &[$(stringify!($variant)),+],
            }),+],
        }
    };
}

/// Directories and files whose non-test sources are checked for [`VMError`]
/// constructions: the VM, its ABI, artifact admission, Core and the SoraCloud
/// host. Developer tooling (the Kotodama test driver, the CLI and Torii
/// routing) is outside the consensus invocation path. A new production
/// invocation owner outside these roots must be added here.
pub const VM_ERROR_PRODUCER_SCOPE: &[&str] = &[
    "crates/iroha_core/src",
    "crates/irohad/src/soracloud_runtime.rs",
    "crates/ivm/src",
    "crates/ivm_abi/src",
    "crates/ivm_artifact_admission/src",
];

/// Files below [`VM_ERROR_PRODUCER_SCOPE`] that only describe the variants and
/// are not producers: this inventory names every variant in tables and
/// citations.
pub const VM_ERROR_PRODUCER_EXCLUSIONS: &[&str] = &["crates/ivm/src/proof_coverage"];

/// Every non-test source file in [`VM_ERROR_PRODUCER_SCOPE`] that constructs a
/// [`VMError`] variant, sorted by path.
///
/// The exact `(variant, file)` set is checked against the sources in both
/// directions. Origins are reviewed, not derived: a shared helper lists every
/// origin through which its construction sites are reachable, never fewer.
pub const VM_ERROR_PRODUCERS: &[ProducerFile] = &[
    producer!(
        "crates/iroha_core/src/execution_attempt.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    // The Upgrade-executor instruction: the authority check precedes the migration run,
    // and its failed outcome is relabelled for the instruction. Neither is the terminal
    // trap of a run.
    producer!(
        "crates/iroha_core/src/executor.rs",
        PrepareRejection: [PermissionDenied],
        OutsideInvocation: [DecodeError, ExceededMaxCycles, PermissionDenied],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/cache.rs",
        PrepareRejection: [GenericSyscallNotAllowed, InvalidMetadata],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/cache/runtime_slot.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    // The ledger host. Verifying keys and public-input records are rehydrated from State
    // before the run; `begin_tx` refuses an open nested-call journal, which an honest
    // executor never leaves.
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host.rs",
        PrepareRejection: [NoritoInvalid],
        SyscallTrap: [
            AbiTypeNotAllowed, AmxBudgetExceeded, DecodeError, GenericSyscallNotAllowed,
            HostOutputBudgetExceeded, InvalidMetadata, Metered, NoritoInvalid, NotImplemented,
            OutOfGas, PermissionDenied, UnknownSyscall,
        ],
        HostInvariant: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host/contract_calls.rs",
        SyscallTrap: [CallDepthExceeded, DecodeError, InvalidMetadata, Metered, OutOfGas, PermissionDenied, ReentrantCall],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host/contract_event.rs",
        SyscallTrap: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host/contract_state_namespace.rs",
        SyscallTrap: [PermissionDenied],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host/native_events.rs",
        SyscallTrap: [DecodeError, InvalidMetadata, Metered, PermissionDenied],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/iroha_core/src/smartcontracts/ivm/host/tlv_transport.rs",
        SyscallTrap: [NoritoInvalid],
    ),
    // Core encodes a fee-conversion state value with the VM codec outside any run.
    producer!(
        "crates/iroha_core/src/validation_fee.rs",
        OutsideInvocation: [NoritoInvalid],
    ),
    // The SoraCloud host. Its public inputs are built before the run.
    producer!(
        "crates/irohad/src/soracloud_runtime.rs",
        PrepareRejection: [DecodeError, NoritoInvalid, PermissionDenied],
        SyscallTrap: [
            AbiTypeNotAllowed, DecodeError, Metered, NoritoInvalid, NotImplemented, OutOfGas,
            PermissionDenied, UnknownSyscall,
        ],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/analysis/static_state_keys.rs",
        PrepareRejection: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/analysis/static_state_literals/text_index.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/analysis/static_state_workspace.rs",
        PrepareRejection: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/analysis/syscall_usage.rs",
        PrepareRejection: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    // Argument records are prepared by Core before the run, installed by root-call
    // initialization, validated at protected calls and decoded by a syscall.
    producer!(
        "crates/ivm/src/argument_record.rs",
        PrepareRejection: [DecodeError, OutOfGas],
        InitializationTrap: [DecodeError, NoritoInvalid, OutOfGas],
        InterpreterTrap: [DecodeError],
        SyscallTrap: [DecodeError, NoritoInvalid],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/byte_merkle_tree.rs",
        PrepareRejection: [MemoryOutOfBounds],
        InterpreterTrap: [MemoryOutOfBounds],
        SyscallTrap: [MemoryOutOfBounds],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/byte_merkle_tree/canonical_nodes.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/cache_memory.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/cache_memory/reg_log_owner.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/cache_memory/shared_allocation.rs",
        PrepareRejection: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    // Frame preparation serves the root call and every protected child call; the access
    // check guards guest and host memory transfers.
    producer!(
        "crates/ivm/src/call_frame.rs",
        InitializationTrap: [AssertionFailed, MemoryOutOfBounds, MisalignedAccess],
        InterpreterTrap: [
            AssertionFailed, MemoryAccessViolation, MemoryOutOfBounds, MisalignedAccess,
        ],
        SyscallTrap: [MemoryAccessViolation],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/call_gas.rs",
        InitializationTrap: [GasCostOverflow],
        InterpreterTrap: [GasCostOverflow],
    ),
    // `select_entrypoint` runs before the run; `begin_root_call` and call-table validation
    // run inside it.
    producer!(
        "crates/ivm/src/call_runtime.rs",
        PrepareRejection: [DecodeError, PermissionDenied],
        InitializationTrap: [
            AssertionFailed, DecodeError, NoritoInvalid, PermissionDenied, PrivacyViolation,
        ],
        InterpreterTrap: [AssertionFailed, DecodeError, NoritoInvalid, PrivacyViolation],
    ),
    producer!(
        "crates/ivm/src/call_runtime/layouts.rs",
        PrepareRejection: [InvalidMetadata],
        InitializationTrap: [DecodeError],
        InterpreterTrap: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/call_runtime/values.rs",
        InitializationTrap: [AssertionFailed, DecodeError, PrivacyViolation],
        InterpreterTrap: [AssertionFailed, DecodeError, PrivacyViolation],
    ),
    producer!(
        "crates/ivm/src/contract_return_stack.rs",
        InterpreterTrap: [AssertionFailed],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/core_host.rs",
        PrepareRejection: [NoritoInvalid],
        SyscallTrap: [
            AbiTypeNotAllowed, DecodeError, Metered, NoritoInvalid, NotImplemented,
            PermissionDenied, UnknownSyscall,
        ],
        HostInvariant: [HostUnavailable],
    ),
    producer!(
        "crates/ivm/src/decoder.rs",
        PrepareRejection: [MemoryAccessViolation],
        InterpreterTrap: [MemoryAccessViolation],
    ),
    producer!(
        "crates/ivm/src/execution_diagnostics.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/execution_memory_recorder.rs",
        HostInvariant: [HostUnavailable],
        LocalDeferral: [ExecutionDeferred],
        OutsideInvocation: [MemoryOutOfBounds],
    ),
    producer!(
        "crates/ivm/src/execution_memory_recorder/private_scrub.rs",
        HostInvariant: [HostUnavailable],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/execution_packets/runtime.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/execution_step_recorder.rs",
        HostInvariant: [HostUnavailable],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/host.rs",
        PrepareRejection: [NoritoInvalid],
        SyscallTrap: [
            AbiTypeNotAllowed, DecodeError, MemoryOutOfBounds, Metered, NoritoInvalid,
            NotImplemented, OutOfGas, PermissionDenied, RegisterOutOfBounds, UnknownSyscall,
        ],
        HostInvariant: [HostUnavailable],
    ),
    producer!(
        "crates/ivm/src/host/state_map_key.rs",
        SyscallTrap: [NoritoInvalid],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    // The interpreter, program loading, syscall dispatch and the gas, heap and TLV helpers
    // they share. `debit_gas` and the heap preflight serve argument prepayment before the
    // run, root-call initialization and the opcodes or syscalls that call them. A shared
    // cycle allowance that an earlier run of the same signed source exhausted is refused
    // at entry, before the first fetch. A non-ZK run entered with private state is a
    // violated host lifecycle contract.
    producer!(
        "crates/ivm/src/ivm.rs",
        PrepareRejection: [
            DecodeError, GenericSyscallNotAllowed, InvalidMetadata, InvalidOpcode,
            MemoryOutOfBounds, OutOfGas, OutOfMemory, UnknownSyscall,
        ],
        InitializationTrap: [
            AbiTypeNotAllowed, DecodeError, ExceededMaxCycles, NoritoInvalid, OutOfGas, OutOfMemory,
        ],
        InterpreterTrap: [
            AbiTypeNotAllowed, AssertionFailed, DecodeError, ExceededMaxCycles, GasCostOverflow,
            InvalidMetadata, InvalidOpcode, InvalidVectorLength, MemoryAccessViolation,
            MisalignedAccess, MissingHalt, NoritoInvalid, OutOfGas, PrivacyViolation,
            RegisterOutOfBounds, VectorExtensionDisabled, ZkExtensionDisabled,
        ],
        SyscallTrap: [
            AbiTypeNotAllowed, ContractAbort, DecodeError, GenericSyscallNotAllowed,
            MemoryOutOfBounds, NoritoInvalid, OutOfMemory, PrivacyViolation, SyscallOutOfGas,
            UnknownSyscall,
        ],
        HostInvariant: [
            HostUnavailable, SyscallGasQuoteExceeded,
            SyscallMeteringModeMismatch,
        ],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/program_load.rs",
        PrepareRejection: [InvalidMetadata],
    ),
    // Stale or detached register-logger custody is a violated host lifecycle contract.
    producer!(
        "crates/ivm/src/ivm/register_logging.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/register_logging/event_counts.rs",
        InterpreterTrap: [InvalidOpcode],
        LocalDeferral: [AllocationDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/runtime_template.rs",
        LocalDeferral: [AllocationDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/snapshot.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/trace_logging.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/ivm/trace_logging/change_counts.rs",
        InterpreterTrap: [InvalidOpcode],
    ),
    producer!(
        "crates/ivm/src/ivm_cache.rs",
        PrepareRejection: [MemoryOutOfBounds],
    ),
    producer!(
        "crates/ivm/src/ivm_cache/instruction_stream.rs",
        PrepareRejection: [MemoryOutOfBounds],
    ),
    producer!(
        "crates/ivm/src/json.rs",
        SyscallTrap: [DecodeError, NoritoInvalid, UnknownSyscall],
    ),
    producer!(
        "crates/ivm/src/list.rs",
        SyscallTrap: [DecodeError],
    ),
    // Loads and stores serve opcodes and host handlers; code and input preloading and the
    // heap limits are set before the run; allocation serves root-call initialization and
    // the allocation syscalls.
    producer!(
        "crates/ivm/src/memory.rs",
        PrepareRejection: [MemoryOutOfBounds, OutOfMemory],
        InitializationTrap: [OutOfMemory],
        InterpreterTrap: [DecodeError, MemoryAccessViolation, MemoryOutOfBounds, MisalignedAccess],
        SyscallTrap: [MemoryAccessViolation, MemoryOutOfBounds, MisalignedAccess, OutOfMemory],
        HostInvariant: [HostUnavailable],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/memory/dirty_chunks.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/memory/private_scrub.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/memory/read_log.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/memory/write_log.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/memory/write_log/storage.rs",
        LocalDeferral: [AllocationDeferred],
    ),
    producer!(
        "crates/ivm/src/mock_wsv.rs",
        SyscallTrap: [
            AbiTypeNotAllowed, DecodeError, InvalidMetadata, Metered, NoritoInvalid, NotImplemented,
            PermissionDenied, UnknownSyscall,
        ],
        HostInvariant: [HostUnavailable],
    ),
    // Diagnostic fixture admission/replacement and typed calls share this module.
    // Fixture controls run outside execution; admitted nested calls and emission
    // capture run inside the syscall, with allocator refusal remaining local.
    producer!(
        "crates/ivm/src/mock_wsv/contract_calls.rs",
        PrepareRejection: [InvalidMetadata, PermissionDenied],
        SyscallTrap: [CallDepthExceeded, DecodeError, InvalidMetadata, Metered, NoritoInvalid, OutOfGas, PermissionDenied, ReentrantCall],
        LocalDeferral: [ExecutionDeferred],
        OutsideInvocation: [InvalidMetadata, NoritoInvalid, PermissionDenied],
    ),
    producer!(
        "crates/ivm/src/numeric_gas.rs",
        SyscallTrap: [GasCostOverflow],
    ),
    producer!(
        "crates/ivm/src/numeric_tlv.rs",
        SyscallTrap: [GasCostOverflow, PointerAbiFault],
    ),
    producer!(
        "crates/ivm/src/numeric_v1.rs",
        SyscallTrap: [GasCostOverflow, NumericFault, PointerAbiFault, UnknownSyscall],
    ),
    producer!(
        "crates/ivm/src/pointer_abi.rs",
        SyscallTrap: [AbiTypeNotAllowed, NoritoInvalid],
    ),
    producer!(
        "crates/ivm/src/prepared.rs",
        PrepareRejection: [DecodeError],
    ),
    producer!(
        "crates/ivm/src/prepared/control_flow.rs",
        PrepareRejection: [DecodeError],
    ),
    producer!(
        "crates/ivm/src/prepared/entrypoints.rs",
        PrepareRejection: [DecodeError],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/prepared/owner.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/private_input.rs",
        PrepareRejection: [NoritoInvalid],
        SyscallTrap: [NoritoInvalid],
    ),
    producer!(
        "crates/ivm/src/private_memory_ranges.rs",
        LocalDeferral: [AllocationDeferred],
    ),
    producer!(
        "crates/ivm/src/private_memory_ranges/storage.rs",
        LocalDeferral: [ExecutionDeferred],
    ),
    // The compact register proof is an accessor used outside the run.
    producer!(
        "crates/ivm/src/registers.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
        OutsideInvocation: [RegisterOutOfBounds],
    ),
    producer!(
        "crates/ivm/src/runtime.rs",
        SyscallTrap: [UnknownSyscall],
    ),
    producer!(
        "crates/ivm/src/state_overlay.rs",
        PrepareRejection: [NoritoInvalid],
        SyscallTrap: [NoritoInvalid],
    ),
    producer!(
        "crates/ivm/src/state_scan.rs",
        SyscallTrap: [InvalidMetadata, NoritoInvalid],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/state_value.rs",
        SyscallTrap: [DecodeError, NoritoInvalid, OutOfMemory],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/sum.rs",
        SyscallTrap: [DecodeError],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/syscall_metering.rs",
        SyscallTrap: [GasCostOverflow],
        HostInvariant: [SyscallMeteringModeMismatch],
    ),
    // Canonical capture and funded materialization serve production nested calls,
    // native event emission, and the local test host with identical schema rules.
    producer!(
        "crates/ivm/src/value_record.rs",
        SyscallTrap: [DecodeError, OutOfGas],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/value_record/capture.rs",
        SyscallTrap: [DecodeError, Metered, OutOfGas],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/value_record/materialize.rs",
        SyscallTrap: [DecodeError, OutOfGas],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/value_utilities.rs",
        SyscallTrap: [DecodeError, Metered, NoritoInvalid, OutOfGas, UnknownSyscall],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/vrf.rs",
        SyscallTrap: [OutOfGas],
    ),
    // Local diagnostic trace checks run outside the invocation.
    producer!(
        "crates/ivm/src/zk.rs",
        LocalDeferral: [ExecutionDeferred],
        OutsideInvocation: [AssertionFailed],
    ),
    producer!(
        "crates/ivm/src/zk/cycle_roots.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/zk/delta_rows.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/zk/diagnostic_snapshot.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
        OutsideInvocation: [DecodeError],
    ),
    producer!(
        "crates/ivm/src/zk/register_authentication.rs",
        OutsideInvocation: [AssertionFailed],
    ),
    producer!(
        "crates/ivm/src/zk/register_batches.rs",
        HostInvariant: [HostUnavailable],
    ),
    producer!(
        "crates/ivm/src/zk/register_events.rs",
        HostInvariant: [HostUnavailable],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/zk/runtime_trace.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm/src/zk/trace_storage.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_abi/src/arguments.rs",
        PrepareRejection: [DecodeError, NoritoInvalid],
    ),
    producer!(
        "crates/ivm_abi/src/axt.rs",
        SyscallTrap: [NoritoInvalid, PermissionDenied],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_abi/src/codec.rs",
        PrepareRejection: [NoritoInvalid],
        InitializationTrap: [NoritoInvalid],
        SyscallTrap: [NoritoInvalid],
    ),
    producer!(
        "crates/ivm_abi/src/entrypoint.rs",
        PrepareRejection: [DecodeError],
        InitializationTrap: [DecodeError],
        SyscallTrap: [DecodeError],
    ),
    // Helper constructors used by syscall dispatch and hosts, and the numeric-ABI fault
    // conversion.
    producer!(
        "crates/ivm_abi/src/error.rs",
        SyscallTrap: [Metered, NotImplemented, PointerAbiFault],
    ),
    producer!(
        "crates/ivm_abi/src/metadata.rs",
        PrepareRejection: [InvalidMetadata],
    ),
    producer!(
        "crates/ivm_abi/src/metadata/literal_table.rs",
        PrepareRejection: [AbiTypeNotAllowed, InvalidMetadata],
    ),
    producer!(
        "crates/ivm_abi/src/metadata/program_header.rs",
        PrepareRejection: [
            ArtifactAbiHashMismatch, InvalidMetadata, ProgramVectorLengthTooLarge,
            UnsupportedProgramAbiVersion, UnsupportedProgramFeatureBits,
            UnsupportedProgramVersion,
        ],
    ),
    producer!(
        "crates/ivm_abi/src/metadata/section_decode.rs",
        PrepareRejection: [InvalidMetadata],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_abi/src/numeric_tlv.rs",
        SyscallTrap: [GasCostOverflow],
    ),
    // Envelope validation serves literal-table admission, argument installation,
    // protected-call tables, the signature opcodes and host handlers.
    producer!(
        "crates/ivm_abi/src/pointer_abi.rs",
        PrepareRejection: [NoritoInvalid],
        InitializationTrap: [NoritoInvalid],
        InterpreterTrap: [NoritoInvalid],
        SyscallTrap: [NoritoInvalid],
        LocalDeferral: [ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_abi/src/state_cursor.rs",
        PrepareRejection: [NoritoInvalid],
        InitializationTrap: [NoritoInvalid],
        SyscallTrap: [NoritoInvalid],
    ),
    producer!(
        "crates/ivm_artifact_admission/src/admitted_program.rs",
        PrepareRejection: [InvalidMetadata],
    ),
    producer!(
        "crates/ivm_artifact_admission/src/decoded.rs",
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_artifact_admission/src/error.rs",
        PrepareRejection: [ArtifactAbiHashMismatch, InvalidMetadata],
        LocalDeferral: [AllocationDeferred, ExecutionDeferred],
    ),
    producer!(
        "crates/ivm_artifact_admission/src/literal.rs",
        PrepareRejection: [InvalidMetadata],
        LocalDeferral: [ExecutionDeferred],
    ),
];

/// One [`VMError`] variant with its trap kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmErrorEntry {
    /// Variant identifier in `ivm_abi::error::VMError`.
    pub variant: &'static str,
    /// Trap kind `classify_trap` assigns; `None` for the `Metered` wrapper,
    /// which is classified by the error it carries.
    pub trap_kind: Option<VmTrapKind>,
}

impl VmErrorEntry {
    /// Reviewed producers of the variant in [`VM_ERROR_PRODUCERS`] order. An
    /// empty list means no file in the producer scope constructs it.
    #[must_use]
    pub fn producers(&self) -> Vec<TrapEvidence> {
        VM_ERROR_PRODUCERS
            .iter()
            .flat_map(|file| {
                file.groups
                    .iter()
                    .filter(|group| group.variants.contains(&self.variant))
                    .map(|group| TrapEvidence {
                        origin: group.origin,
                        path: file.path,
                    })
            })
            .collect()
    }

    /// Distinct origin classes of the reviewed producers, in stable order.
    #[must_use]
    pub fn origins(&self) -> Vec<TrapOrigin> {
        let producers = self.producers();
        TrapOrigin::ALL
            .into_iter()
            .filter(|origin| producers.iter().any(|entry| entry.origin == *origin))
            .collect()
    }
}

const fn error(variant: &'static str, trap_kind: Option<VmTrapKind>) -> VmErrorEntry {
    VmErrorEntry { variant, trap_kind }
}

/// Number of [`VMError`] variants.
pub const VM_ERROR_COUNT: usize = 43;

/// Every [`VMError`] variant in declaration order.
pub const VM_ERRORS: &[VmErrorEntry; VM_ERROR_COUNT] = &[
    error("ExecutionDeferred", Some(VmTrapKind::Other)),
    error("AllocationDeferred", Some(VmTrapKind::Other)),
    // The wrapper is classified by the error it carries.
    error("Metered", None),
    error("OutOfGas", Some(VmTrapKind::OutOfGas)),
    error("OutOfMemory", Some(VmTrapKind::OutOfMemory)),
    error("MemoryAccessViolation", Some(VmTrapKind::MemoryFault)),
    error("MisalignedAccess", Some(VmTrapKind::MemoryFault)),
    error("MemoryOutOfBounds", Some(VmTrapKind::MemoryFault)),
    error("DecodeError", Some(VmTrapKind::DecodeError)),
    error("InvalidOpcode", Some(VmTrapKind::InvalidOpcode)),
    error("UnknownSyscall", Some(VmTrapKind::UnknownSyscall)),
    error("HostUnavailable", Some(VmTrapKind::NotImplemented)),
    error("NotImplemented", Some(VmTrapKind::NotImplemented)),
    error(
        "SyscallGasQuoteExceeded",
        Some(VmTrapKind::SyscallGasQuoteExceeded),
    ),
    error(
        "SyscallMeteringModeMismatch",
        Some(VmTrapKind::SyscallMeteringModeMismatch),
    ),
    error("GasCostOverflow", Some(VmTrapKind::GasCostOverflow)),
    error("SyscallOutOfGas", Some(VmTrapKind::OutOfGas)),
    error("NumericFault", Some(VmTrapKind::NumericFault)),
    error("PointerAbiFault", Some(VmTrapKind::PointerAbiFault)),
    error("AssertionFailed", Some(VmTrapKind::AssertionFailed)),
    error("ContractAbort", Some(VmTrapKind::ContractAbort)),
    error("ExceededMaxCycles", Some(VmTrapKind::ExceededMaxCycles)),
    error("InvalidMetadata", Some(VmTrapKind::InvalidMetadata)),
    error(
        "UnsupportedProgramVersion",
        Some(VmTrapKind::UnsupportedProgramVersion),
    ),
    error(
        "UnsupportedProgramFeatureBits",
        Some(VmTrapKind::UnsupportedProgramFeatureBits),
    ),
    error(
        "UnsupportedProgramAbiVersion",
        Some(VmTrapKind::UnsupportedProgramAbiVersion),
    ),
    error(
        "ProgramVectorLengthTooLarge",
        Some(VmTrapKind::ProgramVectorLengthTooLarge),
    ),
    error(
        "ArtifactAbiHashMismatch",
        Some(VmTrapKind::ArtifactAbiHashMismatch),
    ),
    error(
        "GenericSyscallNotAllowed",
        Some(VmTrapKind::GenericSyscallNotAllowed),
    ),
    error("InvalidVectorLength", Some(VmTrapKind::InvalidVectorLength)),
    error("MissingHalt", Some(VmTrapKind::MissingHalt)),
    error(
        "VectorExtensionDisabled",
        Some(VmTrapKind::PermissionDenied),
    ),
    error("ZkExtensionDisabled", Some(VmTrapKind::PermissionDenied)),
    // No file in the producer scope constructs this variant; the
    // `vm_error_without_producer` open semantic tracks it.
    error("NullifierAlreadyUsed", Some(VmTrapKind::PermissionDenied)),
    error("PermissionDenied", Some(VmTrapKind::PermissionDenied)),
    error("ReentrantCall", Some(VmTrapKind::PermissionDenied)),
    error("CallDepthExceeded", Some(VmTrapKind::PermissionDenied)),
    error("PrivacyViolation", Some(VmTrapKind::PrivacyViolation)),
    error("RegisterOutOfBounds", Some(VmTrapKind::RegisterOutOfBounds)),
    error("NoritoInvalid", Some(VmTrapKind::NoritoInvalid)),
    error("AbiTypeNotAllowed", Some(VmTrapKind::AbiTypeNotAllowed)),
    error(
        "HostOutputBudgetExceeded",
        Some(VmTrapKind::HostOutputBudgetExceeded),
    ),
    error("AmxBudgetExceeded", Some(VmTrapKind::AmxBudgetExceeded)),
];

/// Return the declaration identifier of a [`VMError`] variant.
///
/// The match is exhaustive on purpose: a new variant does not compile until it
/// is named here, and tests then require its [`VM_ERRORS`] entry.
#[must_use]
pub const fn vm_error_variant_name(error: &VMError) -> &'static str {
    match error {
        VMError::ExecutionDeferred(_) => "ExecutionDeferred",
        VMError::AllocationDeferred(_) => "AllocationDeferred",
        VMError::Metered { .. } => "Metered",
        VMError::OutOfGas => "OutOfGas",
        VMError::OutOfMemory => "OutOfMemory",
        VMError::MemoryAccessViolation { .. } => "MemoryAccessViolation",
        VMError::MisalignedAccess { .. } => "MisalignedAccess",
        VMError::MemoryOutOfBounds => "MemoryOutOfBounds",
        VMError::DecodeError => "DecodeError",
        VMError::InvalidOpcode(_) => "InvalidOpcode",
        VMError::UnknownSyscall(_) => "UnknownSyscall",
        VMError::HostUnavailable => "HostUnavailable",
        VMError::NotImplemented { .. } => "NotImplemented",
        VMError::SyscallGasQuoteExceeded { .. } => "SyscallGasQuoteExceeded",
        VMError::SyscallMeteringModeMismatch { .. } => "SyscallMeteringModeMismatch",
        VMError::GasCostOverflow => "GasCostOverflow",
        VMError::SyscallOutOfGas { .. } => "SyscallOutOfGas",
        VMError::NumericFault(_) => "NumericFault",
        VMError::PointerAbiFault(_) => "PointerAbiFault",
        VMError::AssertionFailed => "AssertionFailed",
        VMError::ContractAbort { .. } => "ContractAbort",
        VMError::ExceededMaxCycles => "ExceededMaxCycles",
        VMError::InvalidMetadata => "InvalidMetadata",
        VMError::UnsupportedProgramVersion { .. } => "UnsupportedProgramVersion",
        VMError::UnsupportedProgramFeatureBits { .. } => "UnsupportedProgramFeatureBits",
        VMError::UnsupportedProgramAbiVersion { .. } => "UnsupportedProgramAbiVersion",
        VMError::ProgramVectorLengthTooLarge { .. } => "ProgramVectorLengthTooLarge",
        VMError::ArtifactAbiHashMismatch { .. } => "ArtifactAbiHashMismatch",
        VMError::GenericSyscallNotAllowed { .. } => "GenericSyscallNotAllowed",
        VMError::InvalidVectorLength { .. } => "InvalidVectorLength",
        VMError::MissingHalt => "MissingHalt",
        VMError::VectorExtensionDisabled => "VectorExtensionDisabled",
        VMError::ZkExtensionDisabled => "ZkExtensionDisabled",
        VMError::NullifierAlreadyUsed => "NullifierAlreadyUsed",
        VMError::PermissionDenied => "PermissionDenied",
        VMError::ReentrantCall => "ReentrantCall",
        VMError::CallDepthExceeded => "CallDepthExceeded",
        VMError::PrivacyViolation => "PrivacyViolation",
        VMError::RegisterOutOfBounds => "RegisterOutOfBounds",
        VMError::NoritoInvalid => "NoritoInvalid",
        VMError::AbiTypeNotAllowed { .. } => "AbiTypeNotAllowed",
        VMError::HostOutputBudgetExceeded { .. } => "HostOutputBudgetExceeded",
        VMError::AmxBudgetExceeded { .. } => "AmxBudgetExceeded",
    }
}

/// Return the declaration identifier of a [`VmTrapKind`] variant.
///
/// The match is exhaustive on purpose: a new kind does not compile until it is
/// named here, and tests then require its [`TRAP_KINDS`] entry.
#[must_use]
pub const fn trap_kind_name(kind: VmTrapKind) -> &'static str {
    match kind {
        VmTrapKind::OutOfGas => "OutOfGas",
        VmTrapKind::OutOfMemory => "OutOfMemory",
        VmTrapKind::MemoryFault => "MemoryFault",
        VmTrapKind::DecodeError => "DecodeError",
        VmTrapKind::InvalidOpcode => "InvalidOpcode",
        VmTrapKind::UnknownSyscall => "UnknownSyscall",
        VmTrapKind::NotImplemented => "NotImplemented",
        VmTrapKind::SyscallGasQuoteExceeded => "SyscallGasQuoteExceeded",
        VmTrapKind::SyscallMeteringModeMismatch => "SyscallMeteringModeMismatch",
        VmTrapKind::GasCostOverflow => "GasCostOverflow",
        VmTrapKind::NumericFault => "NumericFault",
        VmTrapKind::PointerAbiFault => "PointerAbiFault",
        VmTrapKind::AssertionFailed => "AssertionFailed",
        VmTrapKind::ContractAbort => "ContractAbort",
        VmTrapKind::ExceededMaxCycles => "ExceededMaxCycles",
        VmTrapKind::InvalidMetadata => "InvalidMetadata",
        VmTrapKind::UnsupportedProgramVersion => "UnsupportedProgramVersion",
        VmTrapKind::UnsupportedProgramFeatureBits => "UnsupportedProgramFeatureBits",
        VmTrapKind::UnsupportedProgramAbiVersion => "UnsupportedProgramAbiVersion",
        VmTrapKind::ProgramVectorLengthTooLarge => "ProgramVectorLengthTooLarge",
        VmTrapKind::ArtifactAbiHashMismatch => "ArtifactAbiHashMismatch",
        VmTrapKind::GenericSyscallNotAllowed => "GenericSyscallNotAllowed",
        VmTrapKind::InvalidVectorLength => "InvalidVectorLength",
        VmTrapKind::MissingHalt => "MissingHalt",
        VmTrapKind::PermissionDenied => "PermissionDenied",
        VmTrapKind::PrivacyViolation => "PrivacyViolation",
        VmTrapKind::RegisterOutOfBounds => "RegisterOutOfBounds",
        VmTrapKind::NoritoInvalid => "NoritoInvalid",
        VmTrapKind::AbiTypeNotAllowed => "AbiTypeNotAllowed",
        VmTrapKind::HostOutputBudgetExceeded => "HostOutputBudgetExceeded",
        VmTrapKind::AmxBudgetExceeded => "AmxBudgetExceeded",
        VmTrapKind::Other => "Other",
    }
}

/// One [`VmTrapKind`] with the outcome classes derived from [`VM_ERRORS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrapKindEntry {
    /// Trap kind captured alongside the raw error.
    pub kind: VmTrapKind,
}

impl TrapKindEntry {
    /// Declaration identifier of the kind.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        trap_kind_name(self.kind)
    }

    /// [`VMError`] variants `classify_trap` maps to this kind.
    pub fn vm_errors(&self) -> impl Iterator<Item = &'static VmErrorEntry> + '_ {
        VM_ERRORS
            .iter()
            .filter(|entry| entry.trap_kind == Some(self.kind))
    }

    /// Distinct origin classes of every variant of this kind, in stable order.
    #[must_use]
    pub fn origins(&self) -> Vec<TrapOrigin> {
        let origins: Vec<TrapOrigin> = self.vm_errors().flat_map(VmErrorEntry::origins).collect();
        TrapOrigin::ALL
            .into_iter()
            .filter(|origin| origins.contains(origin))
            .collect()
    }

    /// Relation obligation classes of every origin of this kind, deduplicated
    /// in [`Obligation::ALL`] order.
    #[must_use]
    pub fn obligations(&self) -> Vec<Obligation> {
        let origins = self.origins();
        Obligation::ALL
            .into_iter()
            .filter(|obligation| {
                origins
                    .iter()
                    .any(|origin| origin.obligations().contains(obligation))
            })
            .collect()
    }
}

const fn kind(kind: VmTrapKind) -> TrapKindEntry {
    TrapKindEntry { kind }
}

/// Number of [`VmTrapKind`] variants.
pub const TRAP_KIND_COUNT: usize = 32;

/// Every [`VmTrapKind`] in declaration order.
pub const TRAP_KINDS: &[TrapKindEntry; TRAP_KIND_COUNT] = &[
    kind(VmTrapKind::OutOfGas),
    kind(VmTrapKind::OutOfMemory),
    kind(VmTrapKind::MemoryFault),
    kind(VmTrapKind::DecodeError),
    kind(VmTrapKind::InvalidOpcode),
    kind(VmTrapKind::UnknownSyscall),
    kind(VmTrapKind::NotImplemented),
    kind(VmTrapKind::SyscallGasQuoteExceeded),
    kind(VmTrapKind::SyscallMeteringModeMismatch),
    kind(VmTrapKind::GasCostOverflow),
    kind(VmTrapKind::NumericFault),
    kind(VmTrapKind::PointerAbiFault),
    kind(VmTrapKind::AssertionFailed),
    kind(VmTrapKind::ContractAbort),
    kind(VmTrapKind::ExceededMaxCycles),
    kind(VmTrapKind::InvalidMetadata),
    kind(VmTrapKind::UnsupportedProgramVersion),
    kind(VmTrapKind::UnsupportedProgramFeatureBits),
    kind(VmTrapKind::UnsupportedProgramAbiVersion),
    kind(VmTrapKind::ProgramVectorLengthTooLarge),
    kind(VmTrapKind::ArtifactAbiHashMismatch),
    kind(VmTrapKind::GenericSyscallNotAllowed),
    kind(VmTrapKind::InvalidVectorLength),
    kind(VmTrapKind::MissingHalt),
    kind(VmTrapKind::PermissionDenied),
    kind(VmTrapKind::PrivacyViolation),
    kind(VmTrapKind::RegisterOutOfBounds),
    kind(VmTrapKind::NoritoInvalid),
    kind(VmTrapKind::AbiTypeNotAllowed),
    kind(VmTrapKind::HostOutputBudgetExceeded),
    kind(VmTrapKind::AmxBudgetExceeded),
    kind(VmTrapKind::Other),
];

/// One stable numeric fault code of the Kotodama V1 numeric syscalls.
///
/// In status mode the tag is returned in `r11` and execution continues; in
/// trap mode the syscall raises `VMError::NumericFault`. The relation must
/// bind the selected mode, the exact tag and the gas of every completed stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumericFaultEntry {
    /// Stable ABI fault.
    pub fault: NumericFaultV1,
    /// Declaration identifier in `ivm_abi::numeric::NumericFaultV1`.
    pub name: &'static str,
}

impl NumericFaultEntry {
    /// Relation obligation classes every numeric fault engages.
    pub const OBLIGATIONS: &'static [Obligation] = &[
        Obligation::TypedValues,
        Obligation::Faults,
        Obligation::Gas,
        Obligation::HostResult,
    ];
}

macro_rules! numeric_fault {
    ($name:ident) => {
        NumericFaultEntry {
            fault: NumericFaultV1::$name,
            name: stringify!($name),
        }
    };
}

/// Number of [`NumericFaultV1`] variants.
pub const NUMERIC_FAULT_COUNT: usize = 13;

/// Every [`NumericFaultV1`] in ascending tag order.
pub const NUMERIC_FAULTS: &[NumericFaultEntry; NUMERIC_FAULT_COUNT] = &[
    numeric_fault!(MantissaOverflow),
    numeric_fault!(ScaleOverflow),
    numeric_fault!(DivisionByZero),
    numeric_fault!(RepeatingDecimal),
    numeric_fault!(ExactDivisionScaleOverflow),
    numeric_fault!(InvalidScale),
    numeric_fault!(InexactConversion),
    numeric_fault!(NegativeQuantity),
    numeric_fault!(QuantityUnderflow),
    numeric_fault!(InvalidRoundingMode),
    numeric_fault!(InvalidFailureMode),
    numeric_fault!(ReservedRegisterNonZero),
    numeric_fault!(NegativeSquareRoot),
];

/// One stable pointer or envelope validation fault code.
///
/// Numeric pointer validation raises `VMError::PointerAbiFault` with the tag;
/// the relation must bind the exact tag and the gas of every completed stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerAbiFaultEntry {
    /// Stable ABI fault.
    pub fault: PointerAbiFaultV1,
    /// Declaration identifier in `ivm_abi::numeric::PointerAbiFaultV1`.
    pub name: &'static str,
}

impl PointerAbiFaultEntry {
    /// Relation obligation classes every pointer-ABI fault engages.
    pub const OBLIGATIONS: &'static [Obligation] = &[
        Obligation::Pointers,
        Obligation::Faults,
        Obligation::Gas,
        Obligation::HostResult,
    ];
}

macro_rules! pointer_fault {
    ($name:ident) => {
        PointerAbiFaultEntry {
            fault: PointerAbiFaultV1::$name,
            name: stringify!($name),
        }
    };
}

/// Number of [`PointerAbiFaultV1`] variants.
pub const POINTER_ABI_FAULT_COUNT: usize = 11;

/// Every [`PointerAbiFaultV1`] in ascending tag order.
pub const POINTER_ABI_FAULTS: &[PointerAbiFaultEntry; POINTER_ABI_FAULT_COUNT] = &[
    pointer_fault!(InvalidAddress),
    pointer_fault!(UnknownType),
    pointer_fault!(TypeNotAllowed),
    pointer_fault!(WrongType),
    pointer_fault!(InvalidEnvelopeVersion),
    pointer_fault!(OversizedLength),
    pointer_fault!(TruncatedEnvelope),
    pointer_fault!(PayloadHashMismatch),
    pointer_fault!(MalformedFrame),
    pointer_fault!(SchemaMismatch),
    pointer_fault!(NonCanonical),
];
