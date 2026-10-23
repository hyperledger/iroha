//! ABI V1 whole-invocation semantic and proof-coverage inventory.
//!
//! This module is a coverage guard, not a proof system. It lists every admitted
//! opcode, every `abi_syscall_list()` entry, every [`VmTrapKind`](crate::VmTrapKind),
//! every [`VMError`](crate::VMError) variant and every numeric/pointer ABI fault,
//! maps each to the relation obligations a complete native invocation proof
//! must discharge, and records which unregistered proof components currently
//! hold equations for it. Nothing here constrains a witness, authorizes
//! `IvmProved` admission or substitutes for the relation.
//!
//! Completion stays open while [`COMPLETE_RELATION`] is `None`, while any entry
//! is not [`CoverageStatus::Complete`], or while [`OPEN_SEMANTICS`] is nonempty;
//! [`completion_blockers`] names each reason separately. There is no default
//! syscall exclusion list: [`DEFAULT_SYSCALL_EXCLUSIONS`] is empty and an
//! unmapped syscall, opcode or fault fails the source-checked tests in this
//! module.
//!
//! The typed tables are the source of truth. The tracked machine-readable
//! artifact at [`INVENTORY_ARTIFACT_PATH`] is rendered from them by
//! [`render_inventory_json`] and must be regenerated with
//! `cargo run --locked -p ivm --features dev-tools --bin gen_proof_coverage_inventory -- --write`.

mod components;
mod invocation;
mod opcodes;
mod phases;
mod render;
mod syscalls;
mod traps;

#[cfg(test)]
mod source_scan;
#[cfg(test)]
mod tests;

pub use components::{
    COMPONENTS, ComponentGeometry, ComponentOpcode, ProofComponent, component,
    components_for_opcode, components_for_trap,
};
pub use invocation::{
    Citation, INVOCATION_OBLIGATIONS, InvocationObligation, PRODUCTION_ADMISSION,
};
pub use opcodes::{
    OPCODE_COUNT, OPCODES, OpcodeEntry, OpcodeFamily, PRIVACY_HELPERS, PcTransition,
    RESERVED_OPCODES, ReservedOpcode, SYSCALL_PRIVACY_FUNCTIONS, StepEffect, TAG_ACCESSORS,
    opcode_entry,
};
pub use phases::{RUN_PHASES, RunPhase, run_phase};
pub use render::render_inventory_json;
pub use syscalls::{
    HOST_PRIVATE_SYSCALLS, HostPrivateSyscall, SYSCALL_COUNT, SYSCALLS, SyscallEntry,
    SyscallRelation, syscall_entry,
};
pub use traps::{
    NUMERIC_FAULTS, NumericFaultEntry, OriginGroup, POINTER_ABI_FAULTS, PointerAbiFaultEntry,
    ProducerFile, TRAP_KINDS, TrapEvidence, TrapKindEntry, TrapOrigin,
    VM_ERROR_PRODUCER_EXCLUSIONS, VM_ERROR_PRODUCER_SCOPE, VM_ERROR_PRODUCERS, VM_ERRORS,
    VmErrorEntry, trap_kind_name, vm_error_variant_name,
};

/// Schema identifier written into the rendered inventory artifact.
pub const INVENTORY_SCHEMA: &str = "iroha.ivm.proof_coverage_inventory.v1";

/// Repository-relative path of the tracked machine-readable inventory.
pub const INVENTORY_ARTIFACT_PATH: &str = "crates/ivm/docs/proof_coverage_inventory.json";

/// Identifier of the single registered whole-invocation relation, once it exists.
///
/// `None` means no entry may be reported as [`CoverageStatus::Complete`]: the
/// components in [`COMPONENTS`] are unregistered substrates, not an invocation
/// proof.
// TODO: Set this to the canonical native proved-invocation relation when the
// complete IVM AIR, statement binding and verifier registration land (task M.2).
pub const COMPLETE_RELATION: Option<&str> = None;

/// Syscalls excluded from complete proof coverage by default.
///
/// This list is intentionally empty and must stay empty: every ABI syscall is
/// in scope, and an unfinished syscall relation keeps completion open instead
/// of being excluded.
pub const DEFAULT_SYSCALL_EXCLUSIONS: &[u32] = &[];

/// Current proof coverage of every stable numeric and pointer-ABI fault code.
///
/// No proof code holds a relation for a numeric syscall, so no fault code is
/// bound in status mode or in trap mode.
// TODO: Derive this per fault code from the numeric syscall relation once it
// exists (task M.2).
pub const FAULT_CODE_COVERAGE: CoverageStatus = CoverageStatus::Uncovered;

/// Whole-invocation relation obligation class.
///
/// Each inventoried opcode, syscall and fault names the classes its semantics
/// engage. Invocation-wide classes are additionally listed once in
/// [`INVOCATION_OBLIGATIONS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Obligation {
    /// Authenticated instruction fetch and decode from the admitted artifact.
    Fetch,
    /// Exact typed values: full register words, privacy tags and typed tables.
    TypedValues,
    /// Initialized inputs: root registers, argument tables, literal tables,
    /// frame generations and initialized-byte bitmaps.
    Initialization,
    /// One address/time-ordered memory, register and owner history.
    MemoryOrdering,
    /// Pointer validity and provenance, region permissions and pointer-ABI
    /// TLV envelopes.
    Pointers,
    /// Protected call entry, frame publication and return continuation.
    Calls,
    /// Result-table initialization scans and immediate-parent copyback.
    Copyback,
    /// Exact terminal and faulting outcomes with native trap priority.
    Faults,
    /// Exact static, dynamic and staged gas debits and cycle accounting.
    Gas,
    /// Terminal state and ZK cycle padding.
    Padding,
    /// Vector registers and logical vector length.
    Vector,
    /// Parallel-section marker semantics.
    Parallel,
    /// Cryptographic precompile relation.
    Precompile,
    /// Proof continuation: segment boundaries bound to one invocation.
    Continuation,
    /// Recursive or aggregate composition of segment and nested proofs.
    ProofComposition,
    /// VM-level recursion: protected callable depth and nested contract calls.
    VmRecursion,
    /// Proof verification performed by the guest through a syscall.
    GuestProofVerification,
    /// Private-trace masking and privacy-tag information flow.
    PrivateMasking,
    /// Exact syscall result registers, status words and output TLVs.
    HostResult,
    /// Authenticated State reads: inclusion, absence and complete ranges.
    StateRead,
    /// Ordered State effects, queued instructions and events.
    StateEffect,
    /// Binding to the public statement derived from signed intent, active
    /// code and manifest, entrypoint, arguments and finalized context.
    StatementBinding,
}

impl Obligation {
    /// Number of obligation classes.
    pub const COUNT: usize = 22;

    /// Every obligation class in stable order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Fetch,
        Self::TypedValues,
        Self::Initialization,
        Self::MemoryOrdering,
        Self::Pointers,
        Self::Calls,
        Self::Copyback,
        Self::Faults,
        Self::Gas,
        Self::Padding,
        Self::Vector,
        Self::Parallel,
        Self::Precompile,
        Self::Continuation,
        Self::ProofComposition,
        Self::VmRecursion,
        Self::GuestProofVerification,
        Self::PrivateMasking,
        Self::HostResult,
        Self::StateRead,
        Self::StateEffect,
        Self::StatementBinding,
    ];

    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::TypedValues => "typed_values",
            Self::Initialization => "initialization",
            Self::MemoryOrdering => "memory_ordering",
            Self::Pointers => "pointers",
            Self::Calls => "calls",
            Self::Copyback => "copyback",
            Self::Faults => "faults",
            Self::Gas => "gas",
            Self::Padding => "padding",
            Self::Vector => "vector",
            Self::Parallel => "parallel",
            Self::Precompile => "precompile",
            Self::Continuation => "continuation",
            Self::ProofComposition => "proof_composition",
            Self::VmRecursion => "vm_recursion",
            Self::GuestProofVerification => "guest_proof_verification",
            Self::PrivateMasking => "private_masking",
            Self::HostResult => "host_result",
            Self::StateRead => "state_read",
            Self::StateEffect => "state_effect",
            Self::StatementBinding => "statement_binding",
        }
    }

    /// One-line requirement the complete relation must satisfy for this class.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::Fetch => {
                "every executed word is the admitted artifact word at the constrained PC"
            }
            Self::TypedValues => {
                "full 64-bit register words, privacy tags and typed table words are constrained, never reduced modulo the proof field"
            }
            Self::Initialization => {
                "initial registers, argument and literal tables, frame generations and initialized bytes derive from the statement and artifact"
            }
            Self::MemoryOrdering => {
                "one address/time-sorted history gives every read the value of the latest write"
            }
            Self::Pointers => {
                "effective addresses, region permissions, pointer provenance and pointer-ABI envelopes are constrained"
            }
            Self::Calls => {
                "call entry publishes the callee frame and protected continuation exactly once"
            }
            Self::Copyback => {
                "return scans every result cell and copies initialized bytes to the immediate parent"
            }
            Self::Faults => {
                "each reachable trap is the unique terminal outcome with native priority"
            }
            Self::Gas => "every debit and completed cycle equals the canonical schedule",
            Self::Padding => {
                "the terminal state and each padded cycle are constrained up to the cycle horizon"
            }
            Self::Vector => {
                "vector register lanes and logical vector length follow the scalar reference"
            }
            Self::Parallel => "parallel markers change no architectural state",
            Self::Precompile => "the primitive's exact output is constrained inside the relation",
            Self::Continuation => {
                "segment boundaries bind the same invocation, complete machine state, gas, reads and effects"
            }
            Self::ProofComposition => {
                "recursive or aggregate composition preserves every segment and nested statement"
            }
            Self::VmRecursion => {
                "callable depth and nested contract depth limits and their failure propagation are constrained"
            }
            Self::GuestProofVerification => {
                "the guest-visible verification result equals the verifier's decision on the bound statement"
            }
            Self::PrivateMasking => {
                "secret-tagged values and private trace columns stay masked and never become public inputs"
            }
            Self::HostResult => {
                "result registers, status words and output envelopes equal the canonical handler output"
            }
            Self::StateRead => {
                "each read is authenticated against the finalized anchor and rechecked against current State"
            }
            Self::StateEffect => {
                "writes, queued instructions and events are bound in order into the statement"
            }
            Self::StatementBinding => {
                "the value is bound to the public statement derived from signed intent and finalized context"
            }
        }
    }
}

/// Current proof coverage of one inventoried entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoverageStatus {
    /// No proof code holds a relation for the entry.
    Uncovered,
    /// At least one unregistered component holds equations for the entry; the
    /// whole-invocation obligations remain open.
    ComponentOnly,
    /// The registered whole-invocation relation discharges every obligation.
    Complete,
}

impl CoverageStatus {
    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Uncovered => "uncovered",
            Self::ComponentOnly => "component_only",
            Self::Complete => "complete",
        }
    }
}

/// A known semantic the inventory cannot yet map to a closed relation obligation.
///
/// Each record keeps completion open until the named owner resolves it and
/// deletes the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenSemantic {
    /// Stable identifier.
    pub id: &'static str,
    /// Inventoried subject the record concerns.
    pub subject: &'static str,
    /// Why the semantic is unmapped or unresolved today.
    pub reason: &'static str,
    /// Source text proving each part of the open condition. Every citation
    /// must still be present in its file's non-test source: when one
    /// disappears the record is corrected, and it is deleted only once none
    /// remains.
    pub evidence: &'static [Citation],
}

const fn evidence(path: &'static str, symbol: &'static str) -> Citation {
    Citation { path, symbol }
}

const CORE_HOST: &str = "crates/iroha_core/src/smartcontracts/ivm/host.rs";
const ROOT_EFFECTS: &str = "crates/iroha_core/src/executor_execution_effects.rs";
const INTERPRETER: &str = "crates/ivm/src/ivm.rs";

/// Unmapped or unresolved semantics that keep completion open.
// TODO: Resolve and delete each record with the complete relation (task M.2);
// never delete a record merely to close the inventory.
pub const OPEN_SEMANTICS: &[OpenSemantic] = &[
    OpenSemantic {
        id: "no_registered_invocation_relation",
        subject: "invocation",
        reason: "IvmProved verification rejects unconditionally; no native execution relation, statement binding or verifier is registered",
        evidence: &[evidence(
            "crates/iroha_core/src/pipeline/overlay.rs",
            "IvmProved requires the complete native STARK execution relation",
        )],
    },
    OpenSemantic {
        id: "soracloud_host_split",
        subject: "syscalls:SORACLOUD_*",
        reason: "SoraCloud syscalls return a metered NotImplemented trap under the ledger host and a response under the SoraCloud host; the proved semantic per invocation kind is unselected",
        evidence: &[
            evidence(CORE_HOST, "fn reject_soracloud_syscall("),
            evidence(
                "crates/irohad/src/soracloud_runtime.rs",
                "impl IVMHost for SoracloudIvmHost",
            ),
        ],
    },
    OpenSemantic {
        id: "vrf_epoch_seed_authenticated_reads",
        subject: "syscalls:VRF_EPOCH_SEED",
        reason: "the host projects epoch seeds from a State pulse scan with conflict removal and latest-epoch fallback; the relation needs authenticated point, range and absence reads for that projection and no read transcript exists (a header field is insufficient)",
        evidence: &[evidence(
            CORE_HOST,
            "pub fn set_vrf_epoch_seeds_from_state(",
        )],
    },
    OpenSemantic {
        id: "per_syscall_trap_matrix",
        subject: "syscalls",
        reason: "reachable trap sets are inventoried per VMError variant, source file and origin, not yet per syscall number; every syscall's trap binding therefore stays uncovered",
        evidence: &[evidence(
            "crates/ivm/src/proof_coverage/syscalls.rs",
            "trap: CoverageStatus::Uncovered",
        )],
    },
    OpenSemantic {
        id: "vm_error_without_producer",
        subject: "vm_errors:NullifierAlreadyUsed",
        reason: "the variant is classified by the trap table but no file in the producer scope constructs it; it must be proven unreachable or removed",
        evidence: &[evidence(
            "crates/ivm_abi/src/error.rs",
            "NullifierAlreadyUsed,",
        )],
    },
    OpenSemantic {
        id: "host_cycle_limit_override",
        subject: "invocation",
        reason: "hosts can override the artifact cycle limit; the override is not yet explicit statement context",
        evidence: &[evidence(INTERPRETER, "pub fn set_max_cycles(")],
    },
    OpenSemantic {
        id: "shared_cycle_allowance_node_local",
        subject: "invocation",
        reason: "a quarantine-lane signed source runs under one shared cycle allowance across its batch segments, nested contract runs and ZK padding; a refused reservation ends a run with ExceededMaxCycles and rejects a parent even after a successful run. The limit is node-local `pipeline.quarantine_tx_max_cycles`, so the outcome is not yet a function of committed State and the statement",
        evidence: &[
            evidence(INTERPRETER, "pub fn run_with_host_and_cycle_budget("),
            evidence(INTERPRETER, "pub fn run_with_host_and_parent_cycle_budget("),
            evidence(ROOT_EFFECTS, "self.pipeline.quarantine_tx_max_cycles"),
        ],
    },
    OpenSemantic {
        id: "host_output_limits_node_local",
        subject: "vm_errors:HostOutputBudgetExceeded",
        reason: "the ledger host refuses queued instructions and output bytes beyond the root-effect limits and raises HostOutputBudgetExceeded; the limits are node-local `pipeline.overlay_max_instructions` and `pipeline.overlay_max_bytes`, so the trap is not yet a function of committed State and the statement",
        evidence: &[
            evidence(
                ROOT_EFFECTS,
                "max_instructions: self.pipeline.overlay_max_instructions",
            ),
            evidence(ROOT_EFFECTS, "max_bytes: self.pipeline.overlay_max_bytes"),
            evidence(CORE_HOST, "ivm::VMError::HostOutputBudgetExceeded"),
        ],
    },
];

/// Aggregate counts of the inventory, used by tests and the rendered artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventorySummary {
    /// Admitted opcodes.
    pub opcodes: usize,
    /// Admitted opcodes without any component relation.
    pub opcodes_uncovered: usize,
    /// Admitted opcodes with component-only relations.
    pub opcodes_component_only: usize,
    /// Admitted opcodes covered by the complete relation.
    pub opcodes_complete: usize,
    /// ABI V1 syscalls.
    pub syscalls: usize,
    /// ABI V1 syscalls whose result, trap and statement bindings are complete.
    pub syscalls_complete: usize,
    /// Trap kinds.
    pub trap_kinds: usize,
    /// Trap kinds covered by the complete relation.
    pub trap_kinds_complete: usize,
    /// `VMError` variants.
    pub vm_errors: usize,
    /// Numeric faults.
    pub numeric_faults: usize,
    /// Numeric faults covered by the complete relation.
    pub numeric_faults_complete: usize,
    /// Pointer-ABI faults.
    pub pointer_abi_faults: usize,
    /// Pointer-ABI faults covered by the complete relation.
    pub pointer_abi_faults_complete: usize,
    /// Unregistered proof components.
    pub components: usize,
    /// Open semantic records.
    pub open_semantics: usize,
}

/// Current coverage status of one admitted opcode, derived from [`COMPONENTS`].
#[must_use]
pub fn opcode_coverage(opcode: u8) -> CoverageStatus {
    if opcode_entry(opcode).is_none() {
        return CoverageStatus::Uncovered;
    }
    component_status(components_for_opcode(opcode).next().is_some())
}

/// Current coverage status of one trap kind, derived from [`COMPONENTS`].
#[must_use]
pub fn trap_coverage(kind: crate::VmTrapKind) -> CoverageStatus {
    component_status(components_for_trap(kind).next().is_some())
}

/// A component relation never yields [`CoverageStatus::Complete`]: only the
/// registered whole-invocation relation can, and none exists while
/// [`COMPLETE_RELATION`] is `None`.
// TODO: Derive `Complete` from the registered relation's own coverage table
// when it lands (task M.2); a component substrate must never upgrade an entry.
const fn component_status(has_component: bool) -> CoverageStatus {
    if has_component {
        CoverageStatus::ComponentOnly
    } else {
        CoverageStatus::Uncovered
    }
}

/// Count every inventoried entry by its current coverage status.
#[must_use]
pub fn summary() -> InventorySummary {
    let count = |status: CoverageStatus| {
        OPCODES
            .iter()
            .filter(|entry| opcode_coverage(entry.opcode) == status)
            .count()
    };
    let fault_codes_complete = |codes: usize| {
        if matches!(FAULT_CODE_COVERAGE, CoverageStatus::Complete) {
            codes
        } else {
            0
        }
    };
    InventorySummary {
        opcodes: OPCODES.len(),
        opcodes_uncovered: count(CoverageStatus::Uncovered),
        opcodes_component_only: count(CoverageStatus::ComponentOnly),
        opcodes_complete: count(CoverageStatus::Complete),
        syscalls: SYSCALLS.len(),
        syscalls_complete: SYSCALLS
            .iter()
            .filter(|entry| entry.status() == CoverageStatus::Complete)
            .count(),
        trap_kinds: TRAP_KINDS.len(),
        trap_kinds_complete: TRAP_KINDS
            .iter()
            .filter(|entry| trap_coverage(entry.kind) == CoverageStatus::Complete)
            .count(),
        vm_errors: VM_ERRORS.len(),
        numeric_faults: NUMERIC_FAULTS.len(),
        numeric_faults_complete: fault_codes_complete(NUMERIC_FAULTS.len()),
        pointer_abi_faults: POINTER_ABI_FAULTS.len(),
        pointer_abi_faults_complete: fault_codes_complete(POINTER_ABI_FAULTS.len()),
        components: COMPONENTS.len(),
        open_semantics: OPEN_SEMANTICS.len(),
    }
}

/// One independent reason complete IVM proof coverage is still open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompletionBlocker {
    /// No whole-invocation relation is registered.
    NoRegisteredRelation,
    /// The default syscall exclusion list is not empty.
    SyscallExclusions,
    /// At least one unmapped or unresolved semantic is recorded.
    OpenSemantics,
    /// At least one admitted opcode is not covered by the complete relation.
    OpcodesIncomplete,
    /// At least one ABI syscall lacks a complete result, trap or statement
    /// binding.
    SyscallsIncomplete,
    /// At least one trap kind is not covered by the complete relation.
    TrapKindsIncomplete,
    /// At least one numeric or pointer-ABI fault code is not covered.
    FaultCodesIncomplete,
    /// At least one invocation-wide obligation is not complete.
    InvocationObligationsIncomplete,
}

impl CompletionBlocker {
    /// Number of blocker kinds.
    pub const COUNT: usize = 8;

    /// Every blocker kind in the order [`completion_blockers`] reports them.
    pub const ALL: [Self; Self::COUNT] = [
        Self::NoRegisteredRelation,
        Self::SyscallExclusions,
        Self::OpenSemantics,
        Self::OpcodesIncomplete,
        Self::SyscallsIncomplete,
        Self::TrapKindsIncomplete,
        Self::FaultCodesIncomplete,
        Self::InvocationObligationsIncomplete,
    ];

    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::NoRegisteredRelation => "no_registered_relation",
            Self::SyscallExclusions => "syscall_exclusions",
            Self::OpenSemantics => "open_semantics",
            Self::OpcodesIncomplete => "opcodes_incomplete",
            Self::SyscallsIncomplete => "syscalls_incomplete",
            Self::TrapKindsIncomplete => "trap_kinds_incomplete",
            Self::FaultCodesIncomplete => "fault_codes_incomplete",
            Self::InvocationObligationsIncomplete => "invocation_obligations_incomplete",
        }
    }
}

/// Everything the completion decision reads.
///
/// [`CompletionInputs::current`] takes the values from the inventory tables;
/// tests build other values to exercise each condition on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionInputs<'a> {
    /// Registered whole-invocation relation, if any.
    pub relation: Option<&'a str>,
    /// Syscalls excluded from complete coverage.
    pub syscall_exclusions: &'a [u32],
    /// Unmapped or unresolved semantics.
    pub open_semantics: &'a [OpenSemantic],
    /// Per-status counts of the inventoried entries.
    pub summary: InventorySummary,
    /// Invocation-wide obligations and their coverage.
    pub invocation_obligations: &'a [InvocationObligation],
}

impl CompletionInputs<'static> {
    /// The inputs the inventory tables hold today.
    #[must_use]
    pub fn current() -> Self {
        Self {
            relation: COMPLETE_RELATION,
            syscall_exclusions: DEFAULT_SYSCALL_EXCLUSIONS,
            open_semantics: OPEN_SEMANTICS,
            summary: summary(),
            invocation_obligations: INVOCATION_OBLIGATIONS,
        }
    }
}

/// Every reason `inputs` leaves complete IVM proof coverage open, in
/// [`CompletionBlocker::ALL`] order.
///
/// Each condition is evaluated on its own: a registered relation does not
/// close coverage while a syscall is excluded, a semantic is open or any
/// opcode, syscall, trap kind, fault code or invocation obligation is not
/// complete.
#[must_use]
pub fn completion_blockers(inputs: &CompletionInputs<'_>) -> Vec<CompletionBlocker> {
    let counts = &inputs.summary;
    let conditions = [
        (
            CompletionBlocker::NoRegisteredRelation,
            inputs.relation.is_none(),
        ),
        (
            CompletionBlocker::SyscallExclusions,
            !inputs.syscall_exclusions.is_empty(),
        ),
        (
            CompletionBlocker::OpenSemantics,
            !inputs.open_semantics.is_empty(),
        ),
        (
            CompletionBlocker::OpcodesIncomplete,
            counts.opcodes_complete != counts.opcodes,
        ),
        (
            CompletionBlocker::SyscallsIncomplete,
            counts.syscalls_complete != counts.syscalls,
        ),
        (
            CompletionBlocker::TrapKindsIncomplete,
            counts.trap_kinds_complete != counts.trap_kinds,
        ),
        (
            CompletionBlocker::FaultCodesIncomplete,
            counts.numeric_faults_complete != counts.numeric_faults
                || counts.pointer_abi_faults_complete != counts.pointer_abi_faults,
        ),
        (
            CompletionBlocker::InvocationObligationsIncomplete,
            inputs
                .invocation_obligations
                .iter()
                .any(|entry| entry.status != CoverageStatus::Complete),
        ),
    ];
    conditions
        .into_iter()
        .filter(|(_, open)| *open)
        .map(|(blocker, _)| blocker)
        .collect()
}

/// Whether complete IVM proof coverage is still open.
///
/// Completion requires a registered whole-invocation relation, every opcode,
/// syscall, trap kind, fault code and invocation obligation complete, no open
/// semantic and an empty default exclusion list.
#[must_use]
pub fn completion_open() -> bool {
    !completion_blockers(&CompletionInputs::current()).is_empty()
}
