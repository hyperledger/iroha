//! Static analysis helpers for compiled IVM programs.
//!
//! This module exposes lightweight inspection utilities that decode `.to` artifacts, walk the
//! canonical instruction stream, and derive register, memory, and syscall usage summaries. The
//! output feeds the AMX/Nexus pipelines (see roadmap item NX-17) by providing a deterministic
//! read/write fingerprint that can be compared against the declared UAID manifests.
//!
//! Typical usage:
//! ```no_run
//! # use ivm::analysis;
//! # fn inspect(bytes: &[u8]) {
//! let report = analysis::analyze_program(bytes).expect("valid program");
//! println!("{} instructions", report.instruction_count);
//! println!("load64 count {}", report.memory.load64);
//! for syscall in &report.syscalls {
//!     println!(
//!         "syscall 0x{:02x} used {} times",
//!         syscall.number, syscall.count
//!     );
//! }
//! # }
//! ```
use crate::{
    VMError, encoding, instruction::wide, ivm_cache::DecodedOp, metadata::ProgramMetadata,
    prepared::PreparedContract,
};
mod aggregate;
mod verified_artifact;
pub use verified_artifact::analyze_verified_artifact_with_memory_budget;
mod static_state;
mod static_state_keys;
mod static_state_literals;
mod static_state_workspace;
mod syscall_scan;
mod syscall_usage;
use static_state_keys::Descriptor as StaticKeyDescriptor;
pub use static_state_keys::StaticStateKeys;
use static_state_literals::LiteralSource;
use std::{error::Error, fmt, num::NonZeroUsize};
pub use syscall_scan::{prepared_syscall_numbers, program_syscall_numbers};
pub use syscall_usage::SyscallUsages;
/// Bytecode-proven durable-state accesses for one deployable contract scope.
///
/// `complete` is true only when every reachable durable-state syscall receives one canonical,
/// authenticated `StatePath` payload on every control-flow path. A caller must retain its
/// conservative state wildcard when this flag is false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticStateAccessAnalysis {
    /// Canonical scheduler keys read by the selected entrypoint scope.
    pub read_keys: StaticStateKeys,
    /// Canonical scheduler keys written by the selected entrypoint scope.
    pub write_keys: StaticStateKeys,
    /// Whether the selected bytecode scope reaches a state-read syscall.
    pub has_state_reads: bool,
    /// Whether the selected bytecode scope reaches a state-write syscall.
    pub has_state_writes: bool,
    /// Whether every reachable state target was proven exact and direct.
    pub complete: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StaticStatePath {
    Literal(u16),
    FromName(u16),
    MapChild { base: u16, key: StaticNoritoKey },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StaticNoritoKey {
    PointerEnvelope(u16),
    LiteralPayload(u16),
}
#[derive(Clone, PartialEq, Eq)]
struct StaticStateFacts {
    names: [Option<u16>; 256],
    paths: [Option<StaticStatePath>; 256],
    pointer_literals: [Option<u16>; 256],
    norito_keys: [Option<StaticNoritoKey>; 256],
    content_may_be_mutable: [bool; 256],
    stack_offsets: [Option<i64>; 256],
    direct: bool,
}
impl StaticStateFacts {
    fn entrypoint() -> Self {
        Self {
            names: [None; 256],
            paths: [None; 256],
            pointer_literals: [None; 256],
            norito_keys: [None; 256],
            content_may_be_mutable: [false; 256],
            stack_offsets: std::array::from_fn(|register| (register == 31).then_some(0)),
            direct: true,
        }
    }
    fn clear(&mut self) {
        self.names = [None; 256];
        self.paths = [None; 256];
        self.pointer_literals = [None; 256];
        self.norito_keys = [None; 256];
        self.content_may_be_mutable = [false; 256];
        self.stack_offsets = [None; 256];
    }
    fn clear_content(&mut self, register: usize) {
        self.names[register] = None;
        self.paths[register] = None;
        self.pointer_literals[register] = None;
        self.norito_keys[register] = None;
        self.content_may_be_mutable[register] = false;
    }
    fn clear_register(&mut self, register: usize) {
        self.clear_content(register);
        self.stack_offsets[register] = None;
    }
    fn copy_register(&mut self, destination: usize, source: usize) {
        self.names[destination] = self.names[source];
        self.paths[destination] = self.paths[source];
        self.pointer_literals[destination] = self.pointer_literals[source];
        self.norito_keys[destination] = self.norito_keys[source];
        self.content_may_be_mutable[destination] = self.content_may_be_mutable[source];
        self.stack_offsets[destination] = self.stack_offsets[source];
    }
    fn mark_content_mutable(&mut self, register: usize) {
        if self.names[register].is_some()
            || self.paths[register].is_some()
            || self.pointer_literals[register].is_some()
            || self.norito_keys[register].is_some()
        {
            self.content_may_be_mutable[register] = true;
        }
    }
    fn invalidate_mutable_content(&mut self) {
        for register in 0..self.content_may_be_mutable.len() {
            if self.content_may_be_mutable[register] {
                self.clear_content(register);
            }
        }
    }
    fn store_is_within_minimum_stack(
        &self,
        base_register: usize,
        immediate: i64,
        byte_len: i64,
    ) -> bool {
        let Some(start) =
            self.stack_offsets[base_register].and_then(|offset| offset.checked_add(immediate))
        else {
            return false;
        };
        let Some(end) = start.checked_add(byte_len) else {
            return false;
        };
        start >= -(crate::memory::Memory::STACK_ALIGNMENT as i64) && end <= 0
    }
    fn merge_from(&mut self, incoming: &Self) -> bool {
        fn retain_common<T: Eq>(
            current_facts: &mut [Option<T>],
            incoming_facts: &[Option<T>],
        ) -> bool {
            let mut changed = false;
            for (current, next) in current_facts.iter_mut().zip(incoming_facts) {
                if current.as_ref() != next.as_ref() && current.take().is_some() {
                    changed = true;
                }
            }
            changed
        }
        let mut changed = retain_common(&mut self.names, &incoming.names);
        changed |= retain_common(&mut self.paths, &incoming.paths);
        changed |= retain_common(&mut self.pointer_literals, &incoming.pointer_literals);
        changed |= retain_common(&mut self.norito_keys, &incoming.norito_keys);
        changed |= retain_common(&mut self.stack_offsets, &incoming.stack_offsets);
        for register in 0..self.content_may_be_mutable.len() {
            let has_content = self.names[register].is_some()
                || self.paths[register].is_some()
                || self.pointer_literals[register].is_some()
                || self.norito_keys[register].is_some();
            let may_be_mutable = has_content
                && (self.content_may_be_mutable[register]
                    || incoming.content_may_be_mutable[register]);
            changed |= self.content_may_be_mutable[register] != may_be_mutable;
            self.content_may_be_mutable[register] = may_be_mutable;
        }
        let direct = self.direct && incoming.direct;
        changed |= self.direct != direct;
        self.direct = direct;
        changed
    }
}
/// Aggregate register usage counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUsage {
    /// Number of times each register was read.
    pub reads: [u64; 256],
    /// Number of times each register was written.
    pub writes: [u64; 256],
}
impl Default for RegisterUsage {
    fn default() -> Self {
        Self {
            reads: [0; 256],
            writes: [0; 256],
        }
    }
}
/// Memory instruction statistics captured during analysis.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryAccesses {
    pub load64: u64,
    pub store64: u64,
    pub load128: u64,
    pub store128: u64,
}
/// Syscall usage summary sorted by syscall number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallUsage {
    pub number: u32,
    pub count: u64,
}
/// Result of analysing a compiled program.
#[derive(Debug, Clone)]
pub struct ProgramAnalysis {
    pub metadata: ProgramMetadata,
    pub instruction_count: usize,
    pub registers: RegisterUsage,
    pub memory: MemoryAccesses,
    pub syscalls: SyscallUsages,
}
/// Errors emitted by [`analyze_program`].
#[derive(Debug)]
pub enum ProgramAnalysisError {
    Metadata(VMError),
    Decode(VMError),
}
impl ProgramAnalysisError {
    /// Recover the original VM error, including a local allocation retry owner.
    ///
    /// Callers must classify local resource refusals before formatting an analysis
    /// diagnostic or turning it into a deterministic program rejection.
    #[must_use]
    pub fn into_vm_error(self) -> VMError {
        match self {
            Self::Metadata(error) | Self::Decode(error) => error,
        }
    }
}
impl fmt::Display for ProgramAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramAnalysisError::Metadata(err) => {
                write!(f, "failed to parse program metadata: {err}")
            }
            ProgramAnalysisError::Decode(err) => {
                write!(f, "failed to decode instruction stream: {err}")
            }
        }
    }
}
impl Error for ProgramAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProgramAnalysisError::Metadata(err) | ProgramAnalysisError::Decode(err) => Some(err),
        }
    }
}
/// Inspect a local diagnostic program and return aggregate usage information.
/// State execution uses [`analyze_program_with_memory_budget`] for allocation custody.
///
/// # Errors
/// Returns canonical decode errors or local allocation refusal.
pub fn analyze_program(bytes: &[u8]) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    analyze_program_in(bytes, None)
}
/// Analyze a program with exact syscall scratch and output allocations funded by its owner.
/// The original pool remains attached to the shared result through every borrower.
///
/// # Errors
/// Preserves canonical metadata/instruction errors and original local allocation refusals.
pub fn analyze_program_with_memory_budget(
    bytes: &[u8],
    budget: &iroha_allocation::AllocationBudget,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    analyze_program_in(bytes, Some(budget))
}
fn analyze_program_in(
    bytes: &[u8],
    budget: Option<&iroha_allocation::AllocationBudget>,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    let (metadata, decoded) = syscall_scan::parsed_stream(bytes)?;
    aggregate::analyze(metadata, || decoded.iter(), budget).map_err(ProgramAnalysisError::Decode)
}
/// Inspect a prepared contract for local diagnostics using its validated instructions.
/// State execution uses [`analyze_prepared_with_memory_budget`] for allocation custody.
///
/// # Errors
/// Returns a local refusal if exact analysis scratch or output cannot be allocated.
pub fn analyze_prepared(
    contract: &PreparedContract,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    analyze_prepared_in(contract, None)
}
/// Analyze prepared instructions using the executing State's original allocation pool.
///
/// # Errors
/// Returns the original local allocation refusal; no guest gas or validity changes.
pub fn analyze_prepared_with_memory_budget(
    contract: &PreparedContract,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    analyze_prepared_in(contract, Some(budget))
}
fn analyze_prepared_in(
    contract: &PreparedContract,
    budget: Option<&iroha_allocation::AllocationBudget>,
) -> Result<ProgramAnalysis, ProgramAnalysisError> {
    aggregate::analyze(
        contract.metadata().clone(),
        || contract.decoded().iter().copied(),
        budget,
    )
    .map_err(ProgramAnalysisError::Decode)
}
/// Prove exact durable-state targets from a prepared contract's authenticated
/// literal table and reachable bytecode.
///
/// Passing an entrypoint restricts the proof to that public selector. Passing `None` analyzes the
/// union of every embedded entrypoint. The proof is deliberately narrow: state targets hidden
/// behind a call, computed at runtime, or merged from ambiguous paths make the result incomplete.
/// This lets scheduler metadata improve precision without becoming a security authority.
/// Instruction facts, the bounded work queue, symbolic key scratch and immutable result keys
/// use the caller's original allocation pool. Result clones retain one original shared owner.
/// Missing selectors or an unprovable control-flow shape return `Ok(None)`.
///
/// # Errors
/// Returns original local allocation refusal before constructing traversal or result backing.
/// Scheduler callers must decline exact hints on refusal and retain conservative fences.
#[must_use]
pub fn analyze_prepared_static_state_accesses(
    contract: &PreparedContract,
    entrypoint: Option<&str>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Option<StaticStateAccessAnalysis>, VMError> {
    static_state::analyze(contract, entrypoint, budget)
}

fn direct_call_edges(op: &DecodedOp) -> Option<(u64, u64)> {
    let offset_words = match wide::opcode(op.inst) {
        wide::control::JAL if wide::rd(op.inst) != 0 => i64::from(wide::imm16(op.inst)),
        wide::control::JALS => i64::from(wide::imm24(op.inst)),
        _ => return None,
    };
    let byte_offset = offset_words.checked_mul(4)?;
    let call_target = i128::from(op.pc)
        .checked_add(i128::from(byte_offset))
        .and_then(|target| u64::try_from(target).ok())?;
    let return_pc = op.pc.checked_add(4)?;
    Some((call_target, return_pc))
}
fn is_protected_contract_return(op: &DecodedOp) -> bool {
    wide::opcode(op.inst) == wide::control::JALR
        && wide::rd(op.inst) == 0
        && wide::rs1(op.inst) == 1
        && wide::imm8(op.inst) == 0
}
fn authenticated_literal_tlv_bytes(contract: &PreparedContract, pointer: u64) -> Option<&[u8]> {
    let start = contract
        .header_len()
        .checked_add(usize::try_from(pointer).ok()?)?;
    let artifact = contract.artifact();
    let fixed_end = start.checked_add(7)?;
    let fixed = artifact.get(start..fixed_end)?;
    let payload_len =
        usize::try_from(u32::from_be_bytes(fixed.get(3..7)?.try_into().ok()?)).ok()?;
    let end = fixed_end
        .checked_add(payload_len)?
        .checked_add(iroha_crypto::Hash::LENGTH)?;
    let bytes = artifact.get(start..end)?;
    crate::pointer_abi::validate_tlv_bytes(bytes).ok()?;
    Some(bytes)
}
fn transfer_static_state_facts(
    op: &DecodedOp,
    literals: &impl LiteralSource,
    facts: &mut StaticStateFacts,
    result: &mut StaticStateAccessAnalysis,
) -> Option<StaticKeyDescriptor> {
    let opcode = wide::opcode(op.inst);
    match opcode {
        wide::memory::LDLIT => {
            let destination = wide::rd(op.inst);
            let index = wide::literal_index(op.inst);
            facts.clear_register(destination);
            facts.names[destination] = literals.name(index).and_then(|_| u16::try_from(index).ok());
            facts.paths[destination] = literals
                .path(index)
                .and_then(|_| u16::try_from(index).ok())
                .map(StaticStatePath::Literal);
            facts.pointer_literals[destination] = literals
                .envelope(index)
                .and_then(|_| u16::try_from(index).ok());
            facts.norito_keys[destination] = literals
                .payload(index)
                .and_then(|_| u16::try_from(index).ok())
                .map(StaticNoritoKey::LiteralPayload);
        }
        wide::memory::LDI64 => {
            facts.clear_register(wide::rd(op.inst));
        }
        wide::memory::LOAD64 => {
            let (_, destination, _, _) = encoding::wide::decode_mem(op.inst);
            facts.clear_register(usize::from(destination));
        }
        wide::memory::STORE64 => {
            let (_, base, _, immediate) = encoding::wide::decode_mem(op.inst);
            if !facts.store_is_within_minimum_stack(usize::from(base), i64::from(immediate), 8) {
                facts.invalidate_mutable_content();
            }
        }
        wide::memory::STORE128 => {
            let (_, base, _, _) = encoding::wide::decode_store128(op.inst);
            if !facts.store_is_within_minimum_stack(usize::from(base), 0, 16) {
                facts.invalidate_mutable_content();
            }
        }
        wide::memory::LOAD128 => {
            let (_, destination_low, _, destination_high) = encoding::wide::decode_load128(op.inst);
            facts.clear_register(usize::from(destination_low));
            facts.clear_register(usize::from(destination_high));
        }
        wide::arithmetic::ADDI => {
            let (_, destination, source, immediate) = encoding::wide::decode_ri(op.inst);
            let stack_offset = facts.stack_offsets[usize::from(source)]
                .and_then(|offset| offset.checked_add(i64::from(immediate)));
            if immediate == 0 {
                facts.copy_register(usize::from(destination), usize::from(source));
            } else {
                facts.clear_register(usize::from(destination));
            }
            facts.stack_offsets[usize::from(destination)] = stack_offset;
        }
        wide::control::BEQ
        | wide::control::BNE
        | wide::control::BLT
        | wide::control::BGE
        | wide::control::BLTU
        | wide::control::BGEU
        | wide::control::JMP
        | wide::control::JR
        | wide::control::HALT => {}
        wide::control::JAL => {
            facts.clear_register(wide::rd(op.inst));
        }
        wide::control::JALS => {
            facts.clear_register(1);
        }
        wide::control::JALR => {
            facts.clear_register(wide::rd(op.inst));
        }
        wide::system::SCALL => {
            let number = u32::from(wide::imm8(op.inst) as u8);
            return transfer_static_state_syscall(number, literals, facts, result);
        }
        wide::system::SYSTEM => {
            let number = encoding::wide::decode_syscallx(op.inst);
            return transfer_static_state_syscall(number, literals, facts, result);
        }
        _ => {
            // A narrow whitelist is intentional. Any unmodelled register or
            // memory transformation invalidates literal provenance.
            facts.clear();
        }
    }
    None
}
fn transfer_static_state_syscall(
    number: u32,
    literals: &impl LiteralSource,
    facts: &mut StaticStateFacts,
    result: &mut StaticStateAccessAnalysis,
) -> Option<StaticKeyDescriptor> {
    if number == crate::syscalls::SYSCALL_INPUT_PUBLISH_TLV {
        facts.mark_content_mutable(10);
        return None;
    }
    if number == crate::syscalls::SYSCALL_POINTER_TO_NORITO {
        let pointer_literal = facts.pointer_literals[10];
        facts.clear_register(10);
        facts.norito_keys[10] = pointer_literal.map(StaticNoritoKey::PointerEnvelope);
        facts.mark_content_mutable(10);
        return None;
    }
    if number == crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO {
        let path = match (facts.names[10], facts.norito_keys[11]) {
            (Some(base), Some(key)) => Some(StaticStatePath::MapChild { base, key }),
            _ => None,
        };
        facts.clear_register(10);
        facts.paths[10] = path;
        facts.mark_content_mutable(10);
        return None;
    }
    if number == crate::syscalls::SYSCALL_STATE_PATH_FROM_NAME {
        let path = facts.names[10].map(StaticStatePath::FromName);
        facts.clear_register(10);
        facts.paths[10] = path;
        facts.mark_content_mutable(10);
        return None;
    }
    if matches!(
        number,
        crate::syscalls::SYSCALL_VALUE_ENCODE
            | crate::syscalls::SYSCALL_BLOB_CONCAT
            | crate::syscalls::SYSCALL_UTF8_VALIDATE
            | crate::syscalls::SYSCALL_VALUE_TO_STRING
            | crate::syscalls::SYSCALL_STATE_VALUE_ENCODE
            | crate::syscalls::SYSCALL_STATE_VALUE_DECODE
            | crate::syscalls::SYSCALL_STATE_MAP_KEY_AT
    ) {
        facts.clear_register(10);
        return None;
    }
    let access = crate::syscalls::syscall_access(number);
    if matches!(
        access,
        crate::syscalls::SyscallAccess::StateRead | crate::syscalls::SyscallAccess::StateWrite
    ) {
        match access {
            crate::syscalls::SyscallAccess::StateRead => result.has_state_reads = true,
            crate::syscalls::SyscallAccess::StateWrite => result.has_state_writes = true,
            _ => unreachable!("state access was matched above"),
        }
        let key = facts.paths[10].and_then(|path| StaticKeyDescriptor::new(path, number, literals));
        let exact = if facts.direct {
            if key.is_none() {
                result.complete = false;
            }
            key
        } else {
            result.complete = false;
            None
        };
        facts.clear();
        return exact;
    }
    // Host calls may publish output pointers or otherwise change the calling
    // convention. A later exact target must establish fresh literal evidence.
    facts.clear();
    None
}
/// Default execution budgets for atomic multi-dataspace execution (NX-17).
#[derive(Debug, Clone)]
pub struct AmxLimits {
    /// Per-dataspace budget in milliseconds (defaults to 30 ms).
    pub per_dataspace_budget_ms: u64,
    /// Group budget across all dataspaces in milliseconds (defaults to 140 ms).
    pub group_budget_ms: u64,
    /// Per-instruction cost in nanoseconds used for coarse estimation.
    pub per_instruction_ns: u64,
    /// Cost in nanoseconds for each memory access.
    pub per_memory_access_ns: u64,
    /// Cost in nanoseconds per syscall invocation.
    pub per_syscall_ns: u64,
}
impl Default for AmxLimits {
    fn default() -> Self {
        Self {
            per_dataspace_budget_ms: 30,
            group_budget_ms: 140,
            per_instruction_ns: 50,
            per_memory_access_ns: 80,
            per_syscall_ns: 120,
        }
    }
}
/// Estimated cost summary for AMX budgeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmxCost {
    /// Estimated per-dataspace execution time (nanoseconds).
    pub estimated_ns_per_dataspace: u64,
    /// Estimated group execution time across all dataspaces (nanoseconds).
    pub estimated_group_ns: u64,
}
/// Budget violation raised when AMX estimates exceed configured limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmxBudgetError {
    /// The per-dataspace budget was exceeded.
    PerDataspaceBudgetExceeded {
        /// Estimated cost in nanoseconds.
        estimated_ns: u64,
        /// Allowed budget in nanoseconds.
        limit_ns: u64,
    },
    /// The group budget across dataspaces was exceeded.
    GroupBudgetExceeded {
        /// Estimated group cost in nanoseconds.
        estimated_ns: u64,
        /// Allowed group budget in nanoseconds.
        limit_ns: u64,
    },
}
/// Estimate the AMX execution cost and enforce per-dataspace/group budgets.
pub fn enforce_amx_budget(
    analysis: &ProgramAnalysis,
    dataspace_count: NonZeroUsize,
    limits: &AmxLimits,
) -> Result<AmxCost, AmxBudgetError> {
    let per_ds_limit = limits.per_dataspace_budget_ms.saturating_mul(1_000_000);
    let group_limit = limits.group_budget_ms.saturating_mul(1_000_000);
    let instruction_count = u64::try_from(analysis.instruction_count).unwrap_or(u64::MAX);
    let memory_accesses = analysis
        .memory
        .load64
        .saturating_add(analysis.memory.store64)
        .saturating_add(analysis.memory.load128)
        .saturating_add(analysis.memory.store128);
    let syscall_calls = analysis
        .syscalls
        .iter()
        .fold(0_u64, |total, entry| total.saturating_add(entry.count));
    let estimated_ns = instruction_count
        .saturating_mul(limits.per_instruction_ns)
        .saturating_add(memory_accesses.saturating_mul(limits.per_memory_access_ns))
        .saturating_add(syscall_calls.saturating_mul(limits.per_syscall_ns));
    if estimated_ns > per_ds_limit {
        return Err(AmxBudgetError::PerDataspaceBudgetExceeded {
            estimated_ns,
            limit_ns: per_ds_limit,
        });
    }
    let dataspace_count = u64::try_from(dataspace_count.get()).unwrap_or(u64::MAX);
    let group_estimated_ns = estimated_ns.saturating_mul(dataspace_count);
    if group_estimated_ns > group_limit {
        return Err(AmxBudgetError::GroupBudgetExceeded {
            estimated_ns: group_estimated_ns,
            limit_ns: group_limit,
        });
    }
    Ok(AmxCost {
        estimated_ns_per_dataspace: estimated_ns,
        estimated_group_ns: group_estimated_ns,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encoding::wide as wide_enc, instruction::wide};

    #[test]
    fn analysis_error_keeps_the_original_allocation_owner_and_vm_failure() {
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        for original in [
            VMError::AllocationDeferred(refusal),
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable),
            VMError::InvalidMetadata,
            VMError::DecodeError,
        ] {
            for metadata in [false, true] {
                let error = if metadata {
                    ProgramAnalysisError::Metadata(original.clone())
                } else {
                    ProgramAnalysisError::Decode(original.clone())
                };
                assert_eq!(error.into_vm_error(), original);
            }
        }
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn analysis_borrowed_scan_matches_owned_instruction_analysis() {
        let bytes = build_program(&[wide_enc::encode_halt()]);
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let decoded =
            crate::ivm_cache::IvmCache::decode_stream(&bytes[parsed.code_offset..]).unwrap();
        let analysis = analyze_program(&bytes).unwrap();
        let owned = aggregate::analyze(parsed.metadata, || decoded.iter().copied(), None).unwrap();
        assert_eq!(analysis.metadata.encode(), owned.metadata.encode());
        assert_eq!(analysis.instruction_count, owned.instruction_count);
        assert_eq!(analysis.registers, owned.registers);
        assert_eq!(analysis.memory, owned.memory);
        assert_eq!(analysis.syscalls, owned.syscalls);
        assert_eq!(analysis.instruction_count, 1);
    }

    #[test]
    fn analysis_canonical_metadata_refusal_is_local_and_retryable() {
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku Analysis { view fn main() authorize(anyone) -> bool { true } }",
            )
            .unwrap();
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || analyze_program(&bytes),
        )
        .unwrap_err();
        assert!(matches!(error, ProgramAnalysisError::Metadata(_)));
        assert_eq!(
            error.into_vm_error(),
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::ActiveMemoryCapacity,)
        );
        assert!(analyze_program(&bytes).unwrap().instruction_count > 0);
    }

    fn base_analysis(instruction_count: usize) -> ProgramAnalysis {
        ProgramAnalysis {
            metadata: ProgramMetadata::default(),
            instruction_count,
            registers: RegisterUsage::default(),
            memory: MemoryAccesses::default(),
            syscalls: SyscallUsages::default(),
        }
    }
    fn build_program(words: &[u32]) -> Vec<u8> {
        let mut bytes = ProgramMetadata::default_for(1, 1, 1).encode();
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn static_state_analysis_proves_compiler_literal_map_child() {
        let source = r#"
seiyaku StaticMapAnalysis { permission CanWrite;
  state StateMap<int, int> Counters;
  kotoage fn write_one() authorize(CanWrite) { Counters[1] = 10; }
}
"#;
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile literal StateMap access");
        let prepared = crate::prepare_contract(std::sync::Arc::<[u8]>::from(program))
            .expect("prepare literal StateMap access");
        let analysis = analyze_prepared_static_state_accesses(
            &prepared,
            Some("write_one"),
            &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("fund static-state workspace")
        .expect("analyze literal StateMap access");
        let descriptor = manifest
            .entrypoints
            .as_deref()
            .and_then(|entrypoints| {
                entrypoints
                    .iter()
                    .find(|entrypoint| entrypoint.name == "write_one")
            })
            .expect("compiled entrypoint descriptor");
        assert!(analysis.complete);
        assert!(analysis.has_state_writes);
        assert_eq!(
            analysis.write_keys.iter().collect::<Vec<_>>(),
            descriptor
                .write_keys
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn static_state_analysis_keeps_user_helper_access_incomplete() {
        // Kotodama moves a private helper with one call site into its caller,
        // which would leave a direct, provable write. Two call sites keep
        // `hidden_write` behind an ordinary protected call.
        let source = r#"
seiyaku HelperMapAnalysis { permission CanWrite;
  state StateMap<int, int> Counters;
  fn hidden_write() { Counters[1] = 10; }
  kotoage fn helper_write() authorize(CanWrite) { hidden_write(); }
  // Two live call sites retain the helper edge under single-use inlining.
  kotoage fn second_helper_write() authorize(CanWrite) { hidden_write(); }
}
"#;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("compile helper-hidden StateMap access");
        let prepared = crate::prepare_contract(std::sync::Arc::<[u8]>::from(program))
            .expect("prepare helper-hidden StateMap access");
        let entry_pc = prepared
            .entrypoint_descriptor("helper_write")
            .expect("helper_write entrypoint")
            .entry_pc;
        let helper_calls = prepared
            .decoded()
            .iter()
            .filter_map(direct_call_edges)
            .map(|(call_target, _)| call_target)
            .collect::<Vec<_>>();
        assert_eq!(helper_calls.len(), 2, "both helper call sites are retained");
        assert!(
            helper_calls
                .iter()
                .all(|target| *target == helper_calls[0] && *target != entry_pc),
            "the state write stays in one separately compiled helper"
        );
        let analysis = analyze_prepared_static_state_accesses(
            &prepared,
            Some("helper_write"),
            &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("fund static-state workspace")
        .expect("analyze helper-hidden StateMap access");
        assert!(analysis.has_state_writes);
        assert!(!analysis.complete);
        assert!(analysis.write_keys.is_empty());
    }
    #[test]
    fn static_state_analysis_marks_reachable_indirect_edge_incomplete() {
        let source = r#"
seiyaku IndirectStateAnalysis { permission CanRun;
  kotoage fn run() authorize(CanRun) {}
}
"#;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("compile direct control-flow fixture");
        let prepared = crate::prepare_contract(std::sync::Arc::<[u8]>::from(program))
            .expect("prepare direct control-flow fixture");
        let entry_pc = prepared
            .entrypoint_descriptor("run")
            .expect("run entrypoint")
            .entry_pc;
        let mut decoded = prepared.decoded().as_ref().to_vec();
        let entry = decoded
            .iter_mut()
            .find(|op| op.pc == entry_pc)
            .expect("entrypoint instruction");
        entry.inst = wide_enc::encode_rr(wide::control::JALR, 0, 2, 0);
        let control_flow = crate::prepared::PreparedControlFlow::from_decoded(&decoded, None)
            .expect("build adversarial indirect control flow");
        let adversarial = crate::prepared::PreparedContract::from_parts(
            crate::prepared::PreparedContractParts {
                artifact: prepared.shared_artifact(),
                metadata: prepared.metadata().clone(),
                manifest: prepared.manifest().clone(),
                header_len: prepared.header_len(),
                code_offset: prepared.code_offset(),
                code_hash: prepared.code_hash(),
                contract_interface: prepared.shared_contract_interface(),
                literal_table: prepared.literal_table().clone(),
                decoded: crate::cache_memory::SharedAllocation::from_boxed(
                    decoded.into_boxed_slice(),
                ),
                prepared_program: prepared.prepared_program().clone(),
                control_flow,
            },
            None,
        )
        .expect("construct analyzer-only adversarial contract");
        let analysis = analyze_prepared_static_state_accesses(
            &adversarial,
            Some("run"),
            &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("fund static-state workspace")
        .expect("analyze indirect control flow");
        assert!(!analysis.complete);
        assert!(!analysis.has_state_reads);
        assert!(!analysis.has_state_writes);
    }
    #[test]
    fn protected_contract_return_requires_exact_jalr_encoding() {
        let op = |inst| DecodedOp { pc: 0, inst };
        assert!(is_protected_contract_return(&op(wide_enc::encode_rr(
            wide::control::JALR,
            0,
            1,
            0,
        ))));
        for inst in [
            wide_enc::encode_rr(wide::control::JR, 1, 0, 0),
            wide_enc::encode_rr(wide::control::JALR, 1, 1, 0),
            wide_enc::encode_rr(wide::control::JALR, 0, 2, 0),
            wide_enc::encode_ri(wide::control::JALR, 0, 1, 1),
        ] {
            assert!(!is_protected_contract_return(&op(inst)));
        }
    }
    #[test]
    fn static_state_analysis_invalidates_host_paths_across_unbounded_stores() {
        let literals = static_state_literals::TestLiterals {
            names: &[Some("Counters")],
            paths: &[],
            envelopes: &[],
            payloads: &[Some(&[0])],
        };
        let stores = [
            wide_enc::encode_store(wide::memory::STORE64, 2, 3, 0),
            wide_enc::encode_store128(wide::memory::STORE128, 2, 3, 4),
        ];
        for store in stores {
            let mut facts = StaticStateFacts::entrypoint();
            facts.names[10] = Some(0);
            facts.norito_keys[11] = Some(StaticNoritoKey::LiteralPayload(0));
            let mut analysis = StaticStateAccessAnalysis {
                complete: true,
                ..StaticStateAccessAnalysis::default()
            };
            let _ = transfer_static_state_syscall(
                crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO,
                &literals,
                &mut facts,
                &mut analysis,
            );
            assert!(facts.content_may_be_mutable[10]);
            let _ = transfer_static_state_facts(
                &DecodedOp { pc: 0, inst: store },
                &literals,
                &mut facts,
                &mut analysis,
            );
            let _ = transfer_static_state_syscall(
                crate::syscalls::SYSCALL_STATE_SET,
                &literals,
                &mut facts,
                &mut analysis,
            );
            assert!(analysis.has_state_writes);
            assert!(!analysis.complete);
            assert!(analysis.write_keys.is_empty());
        }
    }
    #[test]
    fn static_state_analysis_rejects_legacy_name_carrier() {
        let literals = static_state_literals::TestLiterals {
            names: &[Some("legacy")],
            paths: &[],
            envelopes: &[],
            payloads: &[],
        };
        let mut facts = StaticStateFacts::entrypoint();
        facts.names[10] = Some(0);
        let mut analysis = StaticStateAccessAnalysis {
            complete: true,
            ..StaticStateAccessAnalysis::default()
        };
        let _ = transfer_static_state_syscall(
            crate::syscalls::SYSCALL_STATE_SET,
            &literals,
            &mut facts,
            &mut analysis,
        );
        assert!(analysis.has_state_writes);
        assert!(!analysis.complete);
        assert!(analysis.write_keys.is_empty());
    }
    #[test]
    fn static_state_analysis_rejects_nested_scan_wildcard_claim() {
        let literals = static_state_literals::TestLiterals {
            names: &[],
            paths: &[Some("Counters/00")],
            envelopes: &[],
            payloads: &[],
        };
        for syscall in [
            crate::syscalls::SYSCALL_STATE_COUNT,
            crate::syscalls::SYSCALL_STATE_SCAN,
        ] {
            let mut facts = StaticStateFacts::entrypoint();
            facts.paths[10] = Some(StaticStatePath::Literal(0));
            let mut analysis = StaticStateAccessAnalysis {
                complete: true,
                ..StaticStateAccessAnalysis::default()
            };
            let _ = transfer_static_state_syscall(syscall, &literals, &mut facts, &mut analysis);
            assert!(analysis.has_state_reads);
            assert!(!analysis.complete);
            assert!(analysis.read_keys.is_empty());
        }
    }
    #[test]
    fn analysis_reports_registers_memory_and_syscalls() {
        let words = [
            wide_enc::encode_ri(wide::arithmetic::ADDI, 1, 0, 5),
            wide_enc::encode_load(wide::memory::LOAD64, 2, 1, 0),
            wide_enc::encode_store(wide::memory::STORE64, 3, 2, 8),
            wide_enc::encode_branch(wide::control::BEQ, 2, 1, 1),
            wide_enc::encode_sys(wide::system::SCALL, 0x22),
            wide_enc::encode_halt(),
        ];
        let program = build_program(&words);
        let report = analyze_program(&program).expect("analysis succeeds");
        assert_eq!(report.instruction_count, words.len());
        assert_eq!(report.memory.load64, 1);
        assert_eq!(report.memory.store64, 1);
        assert_eq!(report.syscalls.len(), 1);
        assert_eq!(
            report.syscalls[0],
            SyscallUsage {
                number: 0x22,
                count: 1
            }
        );
        assert_eq!(report.registers.reads[0], 1);
        assert!(report.registers.writes[1] >= 1);
        assert!(report.registers.reads[1] >= 2);
        assert!(report.registers.reads[2] >= 1);
    }
    #[test]
    fn analysis_reports_extended_syscall_numbers() {
        let syscall = crate::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
        let words = [wide_enc::encode_syscallx(syscall), wide_enc::encode_halt()];
        let program = build_program(&words);
        let report = analyze_program(&program).expect("analysis succeeds");
        assert_eq!(
            &*report.syscalls,
            &[SyscallUsage {
                number: syscall,
                count: 1
            }]
        );
    }
    #[test]
    fn analysis_rejects_truncated_program() {
        let bytes = vec![0u8; 4];
        let err = analyze_program(&bytes).expect_err("metadata parse should fail");
        assert!(matches!(err, ProgramAnalysisError::Metadata(_)));
    }
    #[test]
    fn analysis_treats_setvl_operand_as_immediate() {
        let words = [
            wide_enc::encode_rr(wide::crypto::SETVL, 0, 0, 8),
            wide_enc::encode_halt(),
        ];
        let program = build_program(&words);
        let report = analyze_program(&program).expect("analysis succeeds");
        assert_eq!(report.instruction_count, words.len());
        assert_eq!(
            report.registers.reads[8], 0,
            "SETVL immediate must not be reported as a register read"
        );
    }
    #[test]
    fn analysis_tracks_poseidon_register_inputs() {
        let words = [
            wide_enc::encode_poseidon2(9, 10, 11),
            wide_enc::encode_poseidon6(8, 20),
            wide_enc::encode_halt(),
        ];
        let report = analyze_program(&build_program(&words)).expect("analysis succeeds");
        assert_eq!(report.registers.writes[9], 1);
        assert_eq!(report.registers.writes[8], 1);
        assert_eq!(report.registers.reads[10], 1);
        assert_eq!(report.registers.reads[11], 1);
        for register in 20..26 {
            assert_eq!(report.registers.reads[register], 1);
        }
        assert_eq!(report.memory, MemoryAccesses::default());
    }
    #[test]
    fn analysis_tracks_indexed_literal_and_implicit_far_link() {
        let words = [
            wide_enc::encode_literal(wide::memory::LDLIT, 42, 0x1234),
            wide_enc::encode_literal(wide::memory::LDI64, 43, 0x5678),
            wide_enc::encode_offset24(wide::control::JALS, 1),
            wide_enc::encode_halt(),
        ];
        let program = build_program(&words);
        let report = analyze_program(&program).expect("analysis succeeds");
        assert_eq!(report.registers.writes[42], 1);
        assert_eq!(report.registers.writes[43], 1);
        assert_eq!(report.registers.writes[1], 1);
        assert_eq!(report.registers.reads.iter().sum::<u64>(), 0);
    }
    #[test]
    fn amx_budget_accepts_small_program() {
        let analysis = base_analysis(10_000);
        let limits = AmxLimits::default();
        let result = enforce_amx_budget(&analysis, NonZeroUsize::new(1).unwrap(), &limits).unwrap();
        assert!(result.estimated_ns_per_dataspace < limits.per_dataspace_budget_ms * 1_000_000);
    }
    #[test]
    fn amx_budget_rejects_large_program() {
        // 700k instructions * 50 ns = 35 ms > 30 ms per-dataspace budget.
        let analysis = base_analysis(700_000);
        let limits = AmxLimits::default();
        let err =
            enforce_amx_budget(&analysis, NonZeroUsize::new(1).unwrap(), &limits).unwrap_err();
        assert!(matches!(
            err,
            AmxBudgetError::PerDataspaceBudgetExceeded { .. }
        ));
    }
    #[test]
    fn amx_budget_rejects_group_overflow() {
        // Fits per-dataspace budget (~27.5 ms) but violates group budget when scaled to 6 lanes.
        let analysis = base_analysis(550_000);
        let limits = AmxLimits::default();
        let err =
            enforce_amx_budget(&analysis, NonZeroUsize::new(6).unwrap(), &limits).unwrap_err();
        assert!(matches!(err, AmxBudgetError::GroupBudgetExceeded { .. }));
    }
    #[test]
    fn amx_budget_cost_overflow_fails_closed() {
        let mut analysis = base_analysis(1);
        analysis.memory.load64 = 1;
        let limits = AmxLimits {
            per_dataspace_budget_ms: 1,
            group_budget_ms: 1,
            per_instruction_ns: u64::MAX,
            per_memory_access_ns: 1,
            per_syscall_ns: 0,
        };

        let err = enforce_amx_budget(&analysis, NonZeroUsize::new(1).unwrap(), &limits)
            .expect_err("overflowing aggregate work must exceed the budget");
        assert_eq!(
            err,
            AmxBudgetError::PerDataspaceBudgetExceeded {
                estimated_ns: u64::MAX,
                limit_ns: 1_000_000,
            }
        );
    }
}
