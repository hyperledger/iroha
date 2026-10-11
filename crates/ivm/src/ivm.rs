//! Core IVM struct implementing the complete Iroha VM v1.1 specification.
//!
//! The VM handles instruction decoding, gas accounting, memory safety and
//! optional zero-knowledge padding exactly as defined by the spec. All opcodes,
//! including field arithmetic, vector operations and advanced control flow are
//! supported and `MAXCYCLES` is enforced when a cycle limit is set.
//!
//! This implementation incorporates the updated architecture with 256 tagged
//! registers and basic hardware feature detection. Vector operations use a
//! deterministic logical lane count capped by the ABI, with hardware helpers
//! kept behind byte-identical fallbacks.
use crate::{
    SyscallPolicy,
    contract_return_stack::ContractReturnStack,
    decoder,
    error::{Perm, VMError, VmTrapKind},
    execution_memory_recorder::{DiagnosticMemoryAccessKind, DiagnosticMemoryAccessRecorder},
    execution_step_recorder::{
        DiagnosticRunEnd, DiagnosticStepOutcome, DiagnosticStepRecorder, DiagnosticStepState,
        PendingDiagnosticStep,
    },
    execution_summary::{EXECUTION_SUMMARY_VERSION_V1, ExecutionSummary},
    gas,
    host::{DefaultHost, IVMHost, host_syscall_metering_spec},
    instruction,
    limits::MAX_CONTRACT_CALL_DEPTH,
    memory::{Memory, MemoryTemplateMismatch},
    metadata::{EmbeddedContractDebugInfoV1, ProgramMetadata},
    pointer_abi::PointerPolicyGuard,
    prepared::PreparedContract,
    private_memory_ranges::PrivateMemoryRanges,
    registers::Registers,
    stack_policy::IvmStackPolicy,
    syscall_metering::{
        STAGED_SYSCALL_ENTRY_GAS, StagedSyscallContext, SyscallCompletion, SyscallMetering,
        SyscallMeteringPhase,
    },
    vector,
    vector::SimdChoice,
    zk::{self, Constraint, DeltaTraceLog, MemEvent, MemLog},
};
#[path = "call_runtime.rs"]
mod call_runtime;
#[cfg(test)]
mod funded_instruction_tests;
#[cfg(test)]
#[path = "ivm/tests/hardware_discovery.rs"]
mod hardware_discovery_tests;
mod input_cursor;
mod literal_table;
#[path = "execution_packets/runtime.rs"]
mod native_packets;
pub(crate) mod register_logging;
mod trace_logging;
pub(crate) use literal_table::{DecodedLiteral, DecodedLiteralTable, decode_literal_table};
mod diagnostic;
#[cfg(test)]
mod snapshot;
use diagnostic::TrapSnapshot;
use iroha_allocation::AllocationBudget;
use likely_stable::unlikely;
#[cfg(feature = "beep")]
use rodio::{
    OutputStream, OutputStreamBuilder, Sink, Source, StreamError, mixer::Mixer, source::SineWave,
};
use sha2::{Digest, Sha256};
#[cfg(feature = "beep")]
use std::time::Duration;
use std::{
    collections::{HashMap, VecDeque},
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
static SUPPRESS_BANNER: AtomicBool = AtomicBool::new(false);
static HARDWARE_CAPABILITIES: OnceLock<HardwareCapabilities> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static HARDWARE_CAPABILITY_LOOKUPS_FOR_TEST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static REFUSE_WORKER_SNAPSHOT_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REFUSE_TRACE_SNAPSHOT_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REFUSE_CALL_RETURN_RESERVATION_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Upper bound on logical vector length supported by the VM.
const LOGICAL_VECTOR_MAX: usize = crate::metadata::VECTOR_LENGTH_MAX as usize;
/// Default logical vector length when not specified by metadata.
const DEFAULT_VECTOR_LENGTH: usize = 4;
/// Canonical instruction width for first-release IVM bytecode.
const WIDE_INSTRUCTION_LEN: u64 = 4;
/// Number of prepared instruction streams retained outside the decode cache.
const PREPARED_PROGRAM_CACHE_CAPACITY: usize = 128;
#[cfg(feature = "beep")]
fn with_audio_mixer(
    open_stream: impl FnOnce() -> Result<OutputStream, StreamError>,
    play: impl FnOnce(&Mixer),
) {
    if let Ok(stream) = open_stream() {
        play(stream.mixer());
    }
}
fn require_registered_syscall_metering(
    number: u32,
    metering: Option<SyscallMetering>,
) -> Result<SyscallMetering, VMError> {
    metering.ok_or(VMError::UnknownSyscall(number))
}
fn host_allows_syscall_masked(host: &dyn IVMHost, policy: SyscallPolicy, number: u32) -> bool {
    let _host_logger_mask = zk::RegLoggerGuard::mask();
    host.allows_syscall(policy, number)
}
fn resolve_syscall_metering(
    host: &dyn IVMHost,
    policy: SyscallPolicy,
    number: u32,
) -> Result<SyscallMetering, VMError> {
    let registered = host_syscall_metering_spec(policy, number).map(|spec| spec.metering);
    if registered.is_some() || crate::syscalls::is_syscall_allowed(policy, number) {
        return require_registered_syscall_metering(number, registered);
    }
    // Tooling hosts may explicitly opt in to host-private syscalls without
    // publishing them in the consensus ABI registry. Keep those calls on the
    // reserved path so the host must provide a deterministic quote before it
    // can perform work. Public ABI calls still fail closed above when their
    // mandatory registry entry is missing.
    host_allows_syscall_masked(host, policy, number)
        .then_some(SyscallMetering::Reserved)
        .ok_or(VMError::UnknownSyscall(number))
}
const SYSCALL_ARGS_0: &[usize] = &[];
const SYSCALL_ARGS_1: &[usize] = &[10];
const SYSCALL_ARGS_2: &[usize] = &[10, 11];
const SYSCALL_ARGS_3: &[usize] = &[10, 11, 12];
const SYSCALL_ARGS_4: &[usize] = &[10, 11, 12, 13];
const SYSCALL_ARGS_5: &[usize] = &[10, 11, 12, 13, 14];
const SYSCALL_ARGS_6: &[usize] = &[10, 11, 12, 13, 14, 15];
#[derive(Clone, Copy, Debug, Default)]
struct SavedSyscallOutputRegisters {
    registers: [usize; 6],
    values: [u64; 6],
    private: [bool; 6],
    len: usize,
}
struct HostRegisterLogIsolation {
    invocation_log: zk::SharedRegLog,
    detached_log: zk::SharedRegLog,
    proof_state_epoch: u64,
    code_hash: [u8; 32],
    zk_mode: bool,
}
include!(concat!(env!("OUT_DIR"), "/syscall_signatures.rs"));
fn default_vector_length() -> usize {
    DEFAULT_VECTOR_LENGTH.clamp(1, LOGICAL_VECTOR_MAX)
}
fn setvl_length(raw: usize) -> Result<usize, VMError> {
    let vl = if raw == 0 { 1 } else { raw };
    if vl > LOGICAL_VECTOR_MAX {
        return Err(VMError::InvalidVectorLength { vector_length: vl });
    }
    Ok(vl)
}
fn validate_vadd64_length(vl: usize) -> Result<(), VMError> {
    if vl == 0 || !vl.is_multiple_of(2) {
        return Err(VMError::InvalidVectorLength { vector_length: vl });
    }
    Ok(())
}
fn isqrt_u64(mut n: u64) -> u64 {
    // Shift to the highest power-of-four <= n.
    let mut bit = 1u64 << 62;
    while bit > n {
        bit >>= 2;
    }
    let mut res = 0u64;
    while bit != 0 {
        if n >= res + bit {
            n -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    res
}
fn checked_div_i64(num: i64, denom: i64) -> Result<i64, VMError> {
    num.checked_div(denom).ok_or(VMError::AssertionFailed)
}
fn checked_rem_i64(num: i64, denom: i64) -> Result<i64, VMError> {
    num.checked_rem(denom).ok_or(VMError::AssertionFailed)
}
fn checked_abs_i64(value: i64) -> Result<i64, VMError> {
    value.checked_abs().ok_or(VMError::AssertionFailed)
}
fn div_ceil_i64(num: i64, denom: i64) -> Result<i64, VMError> {
    let q = checked_div_i64(num, denom)?;
    let r = checked_rem_i64(num, denom)?;
    if r == 0 {
        Ok(q)
    } else if (r > 0 && denom > 0) || (r < 0 && denom < 0) {
        q.checked_add(1).ok_or(VMError::AssertionFailed)
    } else {
        Ok(q)
    }
}
fn abs_i64_to_u64(value: i64) -> u64 {
    value.unsigned_abs()
}
fn gcd_i64(a: i64, b: i64) -> u64 {
    let mut a = abs_i64_to_u64(a);
    let mut b = abs_i64_to_u64(b);
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}
/// Snapshot of hardware accelerators detected on the current host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareCapabilities {
    cuda_available: bool,
    metal_available: bool,
}
impl HardwareCapabilities {
    /// Construct a capability snapshot with explicit CUDA/Metal availability.
    pub const fn new(cuda_available: bool, metal_available: bool) -> Self {
        Self {
            cuda_available,
            metal_available,
        }
    }
    /// Capability snapshot representing no optional accelerators.
    pub const fn none() -> Self {
        Self::new(false, false)
    }
    /// Indicates whether CUDA devices are available.
    pub const fn cuda_available(self) -> bool {
        self.cuda_available
    }
    /// Indicates whether Metal is available (macOS/iOS GPU backend).
    pub const fn metal_available(self) -> bool {
        self.metal_available
    }
}
/// Control whether the VM prints the ASCII banner and hardware feature summary
/// at construction time. Benches can call this to disable noisy output.
pub fn set_banner_enabled(enabled: bool) {
    SUPPRESS_BANNER.store(!enabled, Ordering::Relaxed);
}
fn hardware_capabilities_snapshot() -> &'static HardwareCapabilities {
    #[cfg(test)]
    HARDWARE_CAPABILITY_LOOKUPS_FOR_TEST.with(|count| count.set(count.get() + 1));
    HARDWARE_CAPABILITIES.get_or_init(|| {
        HardwareCapabilities::new(crate::cuda::cuda_available(), vector::metal_available())
    })
}
// Integration with the parallel execution module providing a persistent
// scheduler and deterministic commit of transaction results.
/// Hardware-acceleration policy applied when constructing an [`IVM`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccelerationPolicy {
    allow_cuda: bool,
    allow_metal: bool,
    forced_simd: Option<SimdChoice>,
}
impl AccelerationPolicy {
    /// Construct a policy with explicit toggles.
    pub const fn new(allow_cuda: bool, allow_metal: bool) -> Self {
        Self {
            allow_cuda,
            allow_metal,
            forced_simd: None,
        }
    }
    /// Deterministic policy that disables all optional accelerators.
    pub const fn deterministic() -> Self {
        Self::new(false, false)
    }
    fn env_disables(name: &str) -> bool {
        crate::dev_env::dev_env_flag(name)
    }
    /// Default local policy honoring developer-only `IVM_DISABLE_*` shims.
    ///
    /// Release builds ignore these shims; production nodes apply their parsed
    /// acceleration configuration explicitly.
    pub fn adaptive() -> Self {
        let allow_cuda = !Self::env_disables("IVM_DISABLE_CUDA");
        let allow_metal = !Self::env_disables("IVM_DISABLE_METAL");
        Self::new(allow_cuda, allow_metal)
    }
    /// Enable or disable CUDA.
    pub const fn with_cuda(mut self, allow: bool) -> Self {
        self.allow_cuda = allow;
        self
    }
    /// Enable or disable Metal.
    pub const fn with_metal(mut self, allow: bool) -> Self {
        self.allow_metal = allow;
        self
    }
    /// Override SIMD backend selection. Unsupported choices fall back to scalar.
    pub const fn with_forced_simd(mut self, choice: Option<SimdChoice>) -> Self {
        self.forced_simd = choice;
        self
    }
    pub(crate) const fn allow_cuda(&self) -> bool {
        self.allow_cuda
    }
    pub(crate) const fn allow_metal(&self) -> bool {
        self.allow_metal
    }
    pub(crate) const fn forced_simd(&self) -> Option<SimdChoice> {
        self.forced_simd
    }
}
impl Default for AccelerationPolicy {
    fn default() -> Self {
        Self::adaptive()
    }
}
/// Configuration describing how a new [`IVM`] should be initialised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IvmConfig {
    gas_limit: u64,
    acceleration: AccelerationPolicy,
    capabilities: Option<HardwareCapabilities>,
    stack_policy: IvmStackPolicy,
}
impl IvmConfig {
    /// Create an adaptive configuration without discovering optional accelerators.
    #[must_use]
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            acceleration: AccelerationPolicy::default(),
            capabilities: None,
            stack_policy: IvmStackPolicy::V1,
        }
    }
    /// Deterministic configuration disabling accelerator usage.
    #[must_use]
    pub fn deterministic(gas_limit: u64) -> Self {
        Self::new(gas_limit).with_acceleration(AccelerationPolicy::deterministic())
    }
    /// Adaptive configuration honouring environment toggles for accelerators.
    #[must_use]
    pub fn adaptive(gas_limit: u64) -> Self {
        Self::new(gas_limit)
    }
    /// Override the acceleration policy.
    #[must_use]
    pub fn with_acceleration(mut self, policy: AccelerationPolicy) -> Self {
        self.acceleration = policy;
        self
    }
    /// Override the SIMD backend used by this configuration.
    #[must_use]
    pub fn with_forced_simd(self, choice: Option<SimdChoice>) -> Self {
        self.with_acceleration(self.acceleration().with_forced_simd(choice))
    }
    /// Override the diagnostic capability snapshot without discovering accelerators.
    /// Actual dispatch still requires the backend's own qualification and custody checks.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: HardwareCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }
    /// Gas limit to enforce for the VM.
    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    /// Acceleration policy to apply after construction.
    #[must_use]
    pub const fn acceleration(&self) -> AccelerationPolicy {
        self.acceleration
    }
    /// Query the diagnostic capability snapshot, discovering and qualifying hardware on the
    /// first automatic query. Explicit overrides are returned without discovery.
    #[must_use]
    pub fn capabilities(&self) -> HardwareCapabilities {
        self.capabilities
            .unwrap_or_else(|| *hardware_capabilities_snapshot())
    }
    /// Immutable ABI policy used to derive the VM's guest stack.
    #[must_use]
    pub const fn stack_policy(&self) -> IvmStackPolicy {
        self.stack_policy
    }
    /// Derive the ABI-defined stack limit for this configuration's gas limit.
    #[must_use]
    pub const fn stack_limit_for_gas(&self) -> u64 {
        self.stack_policy.stack_limit_for_gas(self.gas_limit)
    }
    /// Create a builder seeded with this configuration's values.
    #[must_use]
    pub fn builder(self) -> IvmConfigBuilder {
        IvmConfigBuilder::from_config(self)
    }
    /// Produce a modified copy of this configuration.
    #[must_use]
    pub fn map<F>(self, mut f: F) -> Self
    where
        F: FnMut(IvmConfigBuilder) -> IvmConfigBuilder,
    {
        f(self.builder()).build()
    }
    /// Convert this configuration into an [`IvmConfigBuilder`] for further tweaks.
    #[must_use]
    pub fn to_builder(self) -> IvmConfigBuilder {
        self.builder()
    }
    /// Resolve the capability snapshot and retain the explicit result of `f`.
    #[must_use]
    pub fn map_capabilities<F>(self, f: F) -> Self
    where
        F: FnOnce(HardwareCapabilities) -> HardwareCapabilities,
    {
        Self {
            capabilities: Some(f(self.capabilities())),
            ..self
        }
    }
}
/// Builder for `IvmConfig` allowing ergonomic incremental construction.
#[derive(Debug)]
pub struct IvmConfigBuilder {
    gas_limit: u64,
    acceleration: AccelerationPolicy,
    capabilities: Option<HardwareCapabilities>,
    stack_policy: IvmStackPolicy,
}
impl IvmConfigBuilder {
    /// Begin building a configuration without discovering optional accelerators.
    #[must_use]
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            acceleration: AccelerationPolicy::default(),
            capabilities: None,
            stack_policy: IvmStackPolicy::V1,
        }
    }
    /// Create a builder initialised from an existing configuration.
    #[must_use]
    pub fn from_config(config: IvmConfig) -> Self {
        Self {
            gas_limit: config.gas_limit(),
            acceleration: config.acceleration(),
            capabilities: config.capabilities,
            stack_policy: config.stack_policy(),
        }
    }
    /// Configuration enabling deterministic execution (no accelerators).
    #[must_use]
    pub fn deterministic(gas_limit: u64) -> Self {
        Self::new(gas_limit).with_acceleration(AccelerationPolicy::deterministic())
    }
    /// Configuration using the adaptive acceleration policy.
    #[must_use]
    pub fn adaptive(gas_limit: u64) -> Self {
        Self::new(gas_limit)
    }
    /// Override the gas limit.
    #[must_use]
    pub fn with_gas_limit(mut self, gas: u64) -> Self {
        self.gas_limit = gas;
        self
    }
    /// Override the acceleration policy.
    #[must_use]
    pub fn with_acceleration(mut self, policy: AccelerationPolicy) -> Self {
        self.acceleration = policy;
        self
    }
    /// Override SIMD backend selection for this configuration.
    #[must_use]
    pub fn with_forced_simd(mut self, choice: Option<SimdChoice>) -> Self {
        self.acceleration = self.acceleration.with_forced_simd(choice);
        self
    }
    /// Override the diagnostic capability snapshot without discovering accelerators.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: HardwareCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }
    /// Finalise the builder and produce a configuration.
    #[must_use]
    pub fn build(self) -> IvmConfig {
        IvmConfig {
            gas_limit: self.gas_limit,
            acceleration: self.acceleration,
            capabilities: self.capabilities,
            stack_policy: self.stack_policy,
        }
    }
}
/// Builder for configuring [`IVM`] construction.
pub struct IvmBuilder {
    config: IvmConfig,
    suppress_banner: bool,
    host_config: Option<Box<dyn FnOnce(&mut IVM)>>,
}
impl IvmBuilder {
    /// Start building an [`IVM`] with the provided gas limit.
    pub fn new(gas_limit: u64) -> Self {
        Self::from_config(IvmConfig::adaptive(gas_limit))
    }
    /// Builder preset disabling accelerators.
    pub fn deterministic(gas_limit: u64) -> Self {
        Self::from_config(IvmConfig::deterministic(gas_limit))
    }
    /// Builder preset returning both configuration and builder for deterministic runs.
    /// The returned builder does not suppress the startup banner; callers who
    /// want a quiet VM should call [`suppress_startup_banner`](IvmBuilder::suppress_startup_banner).
    pub fn deterministic_config(gas_limit: u64) -> (IvmConfig, IvmBuilder) {
        let config = IvmConfig::deterministic(gas_limit);
        let builder = IvmBuilder::with_config(config);
        (builder.config(), builder)
    }
    /// Builder preset returning both configuration and builder for deterministic runs with banner suppressed.
    #[must_use]
    pub fn deterministic_config_suppressed(gas_limit: u64) -> (IvmConfig, IvmBuilder) {
        let (cfg, builder) = Self::deterministic_config(gas_limit);
        (cfg, builder.suppress_startup_banner())
    }
    /// Builder preset returning both configuration and builder for adaptive runs.
    /// The builder leaves the startup banner enabled by default.
    pub fn adaptive_config(gas_limit: u64) -> (IvmConfig, IvmBuilder) {
        let config = IvmConfig::adaptive(gas_limit);
        let builder = IvmBuilder::with_config(config);
        (builder.config(), builder)
    }
    /// Builder preset returning both configuration and banner-suppressed builder for adaptive runs.
    #[must_use]
    pub fn adaptive_config_suppressed(gas_limit: u64) -> (IvmConfig, IvmBuilder) {
        let (cfg, builder) = Self::adaptive_config(gas_limit);
        (cfg, builder.suppress_startup_banner())
    }
    /// Construct a builder from an existing configuration.
    pub fn from_config(config: IvmConfig) -> Self {
        Self {
            config,
            suppress_banner: false,
            host_config: None,
        }
    }
    /// Construct a builder from an `IvmConfigBuilder`.
    pub fn from_config_builder(builder: IvmConfigBuilder) -> Self {
        Self::from_config(builder.build())
    }
    /// Create a new builder with the provided configuration, leaving the original untouched.
    #[must_use]
    pub fn with_config(config: IvmConfig) -> Self {
        Self::from_config(config)
    }
    /// Override the acceleration policy applied after construction.
    pub fn with_acceleration(mut self, policy: AccelerationPolicy) -> Self {
        self.config.acceleration = policy;
        self
    }
    /// Override SIMD backend selection for subsequent builds.
    pub fn with_forced_simd(mut self, choice: Option<SimdChoice>) -> Self {
        self.config.acceleration = self.config.acceleration.with_forced_simd(choice);
        self
    }
    /// Return a new builder with an updated gas limit.
    #[must_use]
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.config.gas_limit = gas_limit;
        self
    }
    /// Update the acceleration policy without consuming the builder.
    pub fn set_acceleration(&mut self, policy: AccelerationPolicy) -> &mut Self {
        self.config.acceleration = policy;
        self
    }
    /// Update SIMD backend selection without consuming the builder.
    pub fn set_forced_simd(&mut self, choice: Option<SimdChoice>) -> &mut Self {
        let policy = self.config.acceleration.with_forced_simd(choice);
        self.config.acceleration = policy;
        self
    }
    /// Override the gas limit for subsequent builds.
    pub fn set_gas_limit(&mut self, gas_limit: u64) -> &mut Self {
        self.config.gas_limit = gas_limit;
        self
    }
    /// Provide a custom host implementation.
    pub fn with_host<H: IVMHost + Send + Sync + 'static>(mut self, host: H) -> Self {
        self.host_config = Some(Box::new(move |vm| vm.set_host(host)));
        self
    }
    /// Override the constructed VM's diagnostic capability snapshot without discovery.
    /// This does not bypass backend qualification or alter dispatch ownership.
    pub fn with_capabilities(mut self, capabilities: HardwareCapabilities) -> Self {
        self.config.capabilities = Some(capabilities);
        self
    }
    /// Resolve the capability snapshot and retain the explicit result of `f` in this builder.
    #[must_use]
    pub fn map_capabilities_builder<F>(mut self, f: F) -> Self
    where
        F: FnOnce(HardwareCapabilities) -> HardwareCapabilities,
    {
        self.config = self.config.map_capabilities(f);
        self
    }
    /// Skip the startup banner regardless of global flags.
    pub fn suppress_startup_banner(mut self) -> Self {
        self.suppress_banner = true;
        self
    }
    /// Access the current configuration snapshot.
    #[must_use]
    pub fn config(&self) -> IvmConfig {
        self.config
    }
    /// Retrieve the current configuration without consuming the builder.
    #[must_use]
    pub fn build_config(&self) -> IvmConfig {
        self.config
    }
    /// Apply a transformation to the underlying configuration.
    pub fn map_config<F>(&mut self, mut f: F) -> &mut Self
    where
        F: FnMut(IvmConfig) -> IvmConfig,
    {
        self.config = f(self.config);
        self
    }
    /// Current gas limit that will be applied when building.
    #[must_use]
    pub fn gas_limit(&self) -> u64 {
        self.config.gas_limit()
    }
    /// Consume the builder and create an [`IVM`].
    ///
    /// This respects the banner suppression flag and leaves the configuration
    /// unreturned; prefer [`build_with_config`](Self::build_with_config) when the
    /// caller needs to reuse the configuration later. A visible banner queries accelerator
    /// availability; a suppressed banner does not discover hardware.
    pub fn build(self) -> IVM {
        let mut vm = IVM::new_from_config(self.config);
        if let Some(config) = self.host_config {
            config(&mut vm);
        }
        // Check before evaluating arguments: even a suppressed banner must not trigger
        // device discovery, qualification or calibration through its capability query.
        if !self.suppress_banner && !SUPPRESS_BANNER.load(Ordering::Relaxed) {
            let capabilities = vm.hardware_capabilities();
            IVM::startup_banner(
                vm.scheduler_limits.0,
                vm.max_vector_lanes,
                capabilities,
                vm.acceleration_policy.allow_metal() && capabilities.metal_available(),
                vm.acceleration_policy.allow_cuda() && capabilities.cuda_available(),
                self.suppress_banner,
            );
        }
        vm
    }
    /// Consume the builder and return both the final configuration and VM.
    ///
    /// The returned configuration preserves automatic discovery or the explicit capability
    /// override and can construct additional VMs with identical settings.
    pub fn build_with_config(self) -> (IvmConfig, IVM) {
        let cfg = self.config;
        let vm = self.build();
        (cfg, vm)
    }
}
impl From<IvmConfig> for IvmBuilder {
    fn from(config: IvmConfig) -> Self {
        IvmBuilder::from_config(config)
    }
}
impl From<IvmConfigBuilder> for IvmBuilder {
    fn from(builder: IvmConfigBuilder) -> Self {
        IvmBuilder::from_config_builder(builder)
    }
}
#[derive(Clone, Copy)]
struct PreparedOp {
    inst: u32,
    wide_op: u8,
    base_gas: Option<u64>,
}
impl PreparedOp {
    fn from_decoded(op: &crate::ivm_cache::DecodedOp) -> Result<Self, VMError> {
        if !op.pc.is_multiple_of(WIDE_INSTRUCTION_LEN) {
            return Err(VMError::DecodeError);
        }
        let wide_op = instruction::wide::opcode(op.inst);
        if !instruction::wide::is_valid_opcode(wide_op) {
            return Err(VMError::InvalidOpcode((op.inst & 0xFFFF) as u16));
        }
        Ok(Self {
            inst: op.inst,
            wide_op,
            base_gas: gas::cost_of(op.inst),
        })
    }
    fn fetched(&self) -> FetchedOp {
        FetchedOp {
            inst: self.inst,
            wide_op: self.wide_op,
            base_gas: self.base_gas,
        }
    }
}
#[derive(Clone)]
pub(crate) struct PreparedProgram {
    first_pc: u64,
    end_pc: u64,
    ops: crate::cache_memory::SharedAllocation<PreparedOp>,
}
impl PreparedProgram {
    fn prepare_ops(
        decoded: &[crate::ivm_cache::DecodedOp],
        instruction_len: usize,
        budget: Option<&AllocationBudget>,
    ) -> Result<crate::cache_memory::SharedAllocation<PreparedOp>, VMError> {
        let expected_len = decoded.len().saturating_mul(WIDE_INSTRUCTION_LEN as usize);
        if instruction_len != expected_len {
            return Err(VMError::DecodeError);
        }
        let values = decoded.iter().enumerate().map(|(idx, op)| {
            if op.pc != (idx as u64).saturating_mul(WIDE_INSTRUCTION_LEN) {
                return Err(VMError::DecodeError);
            }
            PreparedOp::from_decoded(op)
        });
        match budget {
            Some(budget) => {
                crate::cache_memory::SharedAllocation::try_from_iter_with_memory_budget(
                    values, budget,
                )
            }
            None => crate::cache_memory::SharedAllocation::try_from_iter(values),
        }
    }

    fn from_prepared_ops(
        ops: crate::cache_memory::SharedAllocation<PreparedOp>,
        first_pc: u64,
        instruction_len: usize,
    ) -> Result<Self, VMError> {
        let expected_len = ops.len().saturating_mul(WIDE_INSTRUCTION_LEN as usize);
        if instruction_len != expected_len {
            return Err(VMError::DecodeError);
        }
        let end_pc = first_pc
            .checked_add(instruction_len as u64)
            .ok_or(VMError::DecodeError)?;
        Ok(Self {
            first_pc,
            end_pc,
            ops,
        })
    }
    fn op_at(&self, pc: u64) -> Option<&PreparedOp> {
        if pc < self.first_pc || pc >= self.end_pc {
            return None;
        }
        let offset = pc - self.first_pc;
        if !offset.is_multiple_of(WIDE_INSTRUCTION_LEN) {
            return None;
        }
        let idx = (offset / WIDE_INSTRUCTION_LEN) as usize;
        self.ops.get(idx)
    }
    fn contains_pc(&self, pc: u64) -> bool {
        self.op_at(pc).is_some()
    }
    pub(crate) fn try_retain(&self) -> bool {
        self.ops.try_retain()
    }
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.ops.belongs_to(budget)
    }
}
type PreparedProgramCacheKey = [u8; 32];
struct PreparedProgramCache {
    map: HashMap<PreparedProgramCacheKey, crate::cache_memory::SharedAllocation<PreparedOp>>,
    order: VecDeque<PreparedProgramCacheKey>,
    bytes: usize,
    index_memory: crate::cache_memory::MemoryReservation,
}
impl PreparedProgramCache {
    fn new() -> Self {
        Self {
            index_memory: crate::cache_memory::MemoryReservation::active(0),
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        }
    }
    fn key_for(code: &[u8]) -> PreparedProgramCacheKey {
        let mut hasher = Sha256::new();
        hasher.update(code);
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }
    fn get_or_prepare(
        &mut self,
        code: &[u8],
        decoded: &[crate::ivm_cache::DecodedOp],
    ) -> Result<crate::cache_memory::SharedAllocation<PreparedOp>, VMError> {
        if crate::ivm_cache::cache_limits().capacity == 0
            || crate::cache_memory::memory_stats().limit_bytes == 0
        {
            self.clear_storage();
            return PreparedProgram::prepare_ops(decoded, code.len(), None);
        }
        let key = Self::key_for(code);
        if let Some(hit) = self.map.get(&key).cloned() {
            self.touch(key);
            return Ok(hit);
        }
        let prepared = PreparedProgram::prepare_ops(decoded, code.len(), None)?;
        // Both instruction caches share one allocation-owned byte budget.
        // Evicted borrowers can keep it full; never wait for their execution.
        while !prepared.try_retain() {
            let Some(old) = self.order.pop_front() else {
                self.clear_storage();
                return Ok(prepared);
            };
            self.remove_entry(old);
        }
        let size = Self::entry_size(&prepared);
        self.bytes = self.bytes.saturating_add(size);
        self.map.insert(key, prepared.cache_clone());
        self.touch(key);
        self.enforce_capacity();
        Ok(prepared)
    }
    fn clear_storage(&mut self) {
        self.map = HashMap::new();
        self.order = VecDeque::new();
        self.bytes = 0;
        self.index_memory.set_known_bytes(0);
    }
    fn retain_index_or_clear(&mut self) {
        if self.map.is_empty() {
            self.clear_storage();
            return;
        }
        let bytes = norito::core::owned_hash_table_allocation_bytes::<(
            PreparedProgramCacheKey,
            crate::cache_memory::SharedAllocation<PreparedOp>,
        )>(self.map.capacity())
        .ok()
        .and_then(|bytes| {
            bytes
                .checked_add(self.order.capacity() * std::mem::size_of::<PreparedProgramCacheKey>())
        });
        let Some(bytes) = bytes else {
            self.clear_storage();
            return;
        };
        self.index_memory
            .set_known_bytes(bytes.max(self.index_memory.bytes()));
        if !self.index_memory.try_retain() {
            self.clear_storage();
        }
    }
    fn entry_size(prepared: &crate::cache_memory::SharedAllocation<PreparedOp>) -> usize {
        prepared.allocation_bytes()
    }
    fn touch(&mut self, key: PreparedProgramCacheKey) {
        if let Some(pos) = self.order.iter().position(|candidate| *candidate == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        self.retain_index_or_clear();
    }
    fn enforce_capacity(&mut self) {
        while self.order.len() > PREPARED_PROGRAM_CACHE_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.remove_entry(old);
            } else {
                break;
            }
        }
    }
    fn remove_entry(&mut self, key: PreparedProgramCacheKey) {
        if let Some(prepared) = self.map.remove(&key) {
            self.bytes = self.bytes.saturating_sub(Self::entry_size(&prepared));
        }
    }
}
pub(crate) fn clear_prepared_program_cache() {
    let mut cache = prepared_program_cache()
        .lock()
        .expect("prepared cache lock");
    *cache = PreparedProgramCache::new();
}
fn prepared_program_cache() -> &'static Mutex<PreparedProgramCache> {
    static CACHE: OnceLock<Mutex<PreparedProgramCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(PreparedProgramCache::new()))
}
/// Validate that indexed literal instructions reference an entry of the exact required kind.
pub(crate) fn validate_indexed_literal_instructions(
    decoded: &[crate::ivm_cache::DecodedOp],
    literals: &[DecodedLiteral],
) -> Result<(), VMError> {
    for op in decoded {
        let expected = match instruction::wide::opcode(op.inst) {
            instruction::wide::memory::LDLIT => Some(false),
            instruction::wide::memory::LDI64 => Some(true),
            _ => None,
        };
        if let Some(expects_i64) = expected {
            let literal = literals
                .get(instruction::wide::literal_index(op.inst))
                .ok_or(VMError::InvalidMetadata)?;
            if matches!(literal, DecodedLiteral::I64(_)) != expects_i64 {
                return Err(VMError::InvalidMetadata);
            }
        }
    }
    Ok(())
}
fn validate_generic_program_syscalls(
    decoded: &[crate::ivm_cache::DecodedOp],
) -> Result<(), VMError> {
    for op in decoded {
        let number = match instruction::wide::opcode(op.inst) {
            instruction::wide::system::SCALL => u32::from(instruction::wide::imm8(op.inst) as u8),
            instruction::wide::system::SYSTEM => crate::encoding::wide::decode_syscallx(op.inst),
            _ => continue,
        };
        if !crate::syscalls::is_syscall_allowed(SyscallPolicy::AbiV1, number) {
            return Err(VMError::UnknownSyscall(number));
        }
        if !crate::syscalls::is_generic_program_syscall_allowed(SyscallPolicy::AbiV1, number) {
            return Err(VMError::GenericSyscallNotAllowed { syscall: number });
        }
    }
    Ok(())
}
fn validate_prepared_instruction_bytes(
    code: &[u8],
    decoded: &[crate::ivm_cache::DecodedOp],
) -> Result<(), VMError> {
    let words = code.chunks_exact(WIDE_INSTRUCTION_LEN as usize);
    if !words.remainder().is_empty() || words.len() != decoded.len() {
        return Err(VMError::DecodeError);
    }
    for (index, (bytes, op)) in words.zip(decoded).enumerate() {
        let expected_pc = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(WIDE_INSTRUCTION_LEN))
            .ok_or(VMError::DecodeError)?;
        let expected_word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if op.pc != expected_pc || op.inst != expected_word {
            return Err(VMError::DecodeError);
        }
    }
    Ok(())
}

pub(crate) fn prepare_instruction_stream(
    code: &[u8],
    decoded: &[crate::ivm_cache::DecodedOp],
    first_pc: u64,
    literals: &[DecodedLiteral],
    budget: Option<&AllocationBudget>,
) -> Result<PreparedProgram, VMError> {
    // A prepared-cache hit is keyed by code bytes, so validate the caller's
    // decoded stream against those bytes before looking up or sharing any ops.
    validate_prepared_instruction_bytes(code, decoded)?;
    validate_indexed_literal_instructions(decoded, literals)?;
    let prepared_ops = if let Some(budget) = budget {
        // Original State custody never enters the code-only global cache.
        PreparedProgram::prepare_ops(decoded, code.len(), Some(budget))?
    } else {
        let mut guard = prepared_program_cache()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        guard.get_or_prepare(code, decoded)?
    };
    PreparedProgram::from_prepared_ops(prepared_ops, first_pc, code.len())
}
struct ProgramLoadImage<'a> {
    code_region: &'a [u8],
    metadata: ProgramMetadata,
    contract_interface:
        Option<crate::cache_memory::SharedValue<crate::metadata::EmbeddedContractInterfaceV1>>,
    contract_debug: Option<EmbeddedContractDebugInfoV1>,
    literal_table: DecodedLiteralTable,
    predecoded: Option<crate::ivm_cache::DecodedStream>,
    prepared: Option<PreparedProgram>,
    code_hash: [u8; 32],
    entry_pc: u64,
    strict_return_integrity: bool,
    allow_koto_test_syscalls: bool,
}
#[derive(Clone, Copy)]
struct FetchedOp {
    inst: u32,
    wide_op: u8,
    base_gas: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceMode {
    Off,
    PcOnly,
    DeltaRegisters,
}
mod private_cleanup;
#[cfg(test)]
mod private_disposal_tests;
mod program_load;
mod runtime_template;
pub use runtime_template::RuntimeTemplate;
use runtime_template::{RuntimeTemplateBacking, RuntimeTemplateData};
/// A warmed VM cannot be reset from a different program or memory baseline.
///
/// Runtime pools must discard the mismatched VM instead of replacing its full
/// memory image. A subsequent checkout can construct a correctly sized VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeTemplateResetError {
    kind: RuntimeTemplateResetErrorKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeTemplateResetErrorKind {
    AllocationUnavailable,
    TraceOwnerUnavailable,
    ProgramIdentity {
        current: [u8; 32],
        template: [u8; 32],
    },
    MemoryLifecycle {
        current_generation: u64,
        template_generation: u64,
    },
    MemoryBaselineIdentity,
    MemoryGeometry {
        current_memory_bytes: usize,
        template_memory_bytes: usize,
        current_stack_limit: u64,
        template_stack_limit: u64,
        current_heap_max_limit: u64,
        template_heap_max_limit: u64,
        current_merkle_chunk_bytes: usize,
        template_merkle_chunk_bytes: usize,
        current_merkle_leaves: usize,
        template_merkle_leaves: usize,
    },
}
impl RuntimeTemplateResetError {
    fn from_trace_owner() -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::TraceOwnerUnavailable,
        }
    }
    fn from_allocation_unavailable(_: VMError) -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::AllocationUnavailable,
        }
    }
    fn from_program_identity(current: [u8; 32], template: [u8; 32]) -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::ProgramIdentity { current, template },
        }
    }
    fn from_memory_lifecycle(current_generation: u64, template_generation: u64) -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::MemoryLifecycle {
                current_generation,
                template_generation,
            },
        }
    }
    fn from_memory_baseline_identity() -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::MemoryBaselineIdentity,
        }
    }
    fn from_memory(error: MemoryTemplateMismatch) -> Self {
        Self {
            kind: RuntimeTemplateResetErrorKind::MemoryGeometry {
                current_memory_bytes: error.current.bytes,
                template_memory_bytes: error.template.bytes,
                current_stack_limit: error.current.stack_limit,
                template_stack_limit: error.template.stack_limit,
                current_heap_max_limit: error.current.heap_max_limit,
                template_heap_max_limit: error.template.heap_max_limit,
                current_merkle_chunk_bytes: error.current.merkle_chunk_bytes,
                template_merkle_chunk_bytes: error.template.merkle_chunk_bytes,
                current_merkle_leaves: error.current.merkle_leaves,
                template_merkle_leaves: error.template.merkle_leaves,
            },
        }
    }
}
impl std::fmt::Display for RuntimeTemplateResetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            RuntimeTemplateResetErrorKind::TraceOwnerUnavailable => formatter.write_str(
                "runtime-template trace storage does not retain this VM's original allocation owner",
            ),
            RuntimeTemplateResetErrorKind::AllocationUnavailable => formatter.write_str(
                "runtime-template copy could not reserve memory before resetting the VM",
            ),
            RuntimeTemplateResetErrorKind::ProgramIdentity { current, template } => write!(
                formatter,
                "runtime-template program mismatch: VM has code hash {}, template has code hash {}",
                hex::encode(current),
                hex::encode(template)
            ),
            RuntimeTemplateResetErrorKind::MemoryLifecycle {
                current_generation,
                template_generation,
            } => write!(
                formatter,
                "runtime-template lifecycle mismatch: VM memory generation is {current_generation}, template generation is {template_generation}"
            ),
            RuntimeTemplateResetErrorKind::MemoryBaselineIdentity => formatter.write_str(
                "runtime-template baseline identity mismatch: VM memory was independently replaced",
            ),
            RuntimeTemplateResetErrorKind::MemoryGeometry {
                current_memory_bytes,
                template_memory_bytes,
                current_stack_limit,
                template_stack_limit,
                current_heap_max_limit,
                template_heap_max_limit,
                current_merkle_chunk_bytes,
                template_merkle_chunk_bytes,
                current_merkle_leaves,
                template_merkle_leaves,
            } => write!(
                formatter,
                "runtime-template memory geometry mismatch: VM has {current_memory_bytes} bytes, {current_stack_limit} stack bytes, {current_heap_max_limit} heap-ceiling bytes, {current_merkle_chunk_bytes}-byte Merkle chunks, and {current_merkle_leaves} Merkle leaves; template has {template_memory_bytes} bytes, {template_stack_limit} stack bytes, {template_heap_max_limit} heap-ceiling bytes, {template_merkle_chunk_bytes}-byte Merkle chunks, and {template_merkle_leaves} Merkle leaves"
            ),
        }
    }
}
impl std::error::Error for RuntimeTemplateResetError {}
/// One finite allowance of completed architectural VM cycles shared by a source's runs.
///
/// This is a non-cloneable owner, not source authentication or a host-work budget.
/// Each scoped run consumes the same allowance, including nested VMs and ZK padding.
/// Failed instructions release their pending reservation; previously completed cycles
/// remain consumed. Dropping this owner closes every retained runtime reference.
#[derive(Debug)]
pub struct VmCycleBudget {
    shared: Arc<SharedVmCycleBudget>,
}
#[derive(Debug)]
struct SharedVmCycleBudget {
    limit: u64,
    state: parking_lot::Mutex<VmCycleBudgetState>,
}
#[derive(Debug, Default)]
struct VmCycleBudgetState {
    consumed: u64,
    reserved: u64,
    refused: bool,
    closed: bool,
}
impl VmCycleBudget {
    /// Create an explicit finite allowance. The caller owns source/policy authentication.
    pub fn new(limit: std::num::NonZeroU64) -> Self {
        Self {
            shared: Arc::new(SharedVmCycleBudget {
                limit: limit.get(),
                state: parking_lot::Mutex::new(VmCycleBudgetState::default()),
            }),
        }
    }
    /// The immutable finite allowance established by the owner.
    pub fn limit(&self) -> u64 {
        self.shared.limit
    }
    /// Completed architectural cycles, including completed nested execution and ZK padding.
    pub fn consumed(&self) -> u64 {
        self.shared.state.lock().consumed
    }
    /// Cycles available for another dispatch, excluding active parent reservations.
    pub fn remaining(&self) -> u64 {
        let state = self.shared.state.lock();
        self.shared.limit - state.consumed - state.reserved
    }
    /// Whether the owner is open and has no local runtime-ownership fault.
    ///
    /// This is independent of deterministic cycle exhaustion.
    pub fn is_open(&self) -> bool {
        !self.shared.state.lock().closed
    }
    /// Whether any dispatch or padding reservation was refused for lack of cycles.
    ///
    /// Exact-fit successful execution has zero remaining cycles without exhaustion.
    pub fn exhausted(&self) -> bool {
        self.shared.state.lock().refused
    }
}
impl Drop for VmCycleBudget {
    fn drop(&mut self) {
        self.shared.state.lock().closed = true;
    }
}
impl SharedVmCycleBudget {
    fn ensure_healthy(&self) -> Result<(), VMError> {
        let state = self.state.lock();
        if state.closed {
            Err(VMError::HostUnavailable)
        } else if state.refused {
            Err(VMError::ExceededMaxCycles)
        } else {
            Ok(())
        }
    }
    fn reserve(&self, cycles: u64) -> Result<VmCycleReservation<'_>, VMError> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(VMError::HostUnavailable);
        }
        if state.refused || cycles > self.limit - state.consumed - state.reserved {
            state.refused = true;
            return Err(VMError::ExceededMaxCycles);
        }
        state.reserved += cycles;
        Ok(VmCycleReservation {
            shared: self,
            cycles,
            pending: true,
        })
    }
}
struct VmCycleReservation<'a> {
    shared: &'a SharedVmCycleBudget,
    cycles: u64,
    pending: bool,
}
impl VmCycleReservation<'_> {
    fn complete(mut self, actual: Option<u64>) -> Result<(), VMError> {
        let mut state = self.shared.state.lock();
        state.reserved -= self.cycles;
        self.pending = false;
        if actual != Some(self.cycles) {
            // A lifecycle mutation or a new opcode with an unreviewed cycle cost
            // cannot turn an inaccurate reservation into accepted execution.
            state.closed = true;
            return Err(VMError::HostUnavailable);
        }
        state.consumed += self.cycles;
        Ok(())
    }
}
impl Drop for VmCycleReservation<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.shared.state.lock().reserved -= self.cycles;
        }
    }
}
/// Reservation cost matching the completed-cycle increments in the dispatch table.
fn completed_instruction_cycles(opcode: u8) -> u64 {
    match opcode {
        instruction::wide::arithmetic::ISQRT => 6,
        instruction::wide::arithmetic::DIV_CEIL | instruction::wide::arithmetic::GCD => 12,
        instruction::wide::arithmetic::MEAN => 3,
        _ => 1,
    }
}
pub struct IVM {
    pub registers: Registers,
    // The vector register file has been folded into `registers`. Vector
    // operations access groups of general registers rather than a separate
    // structure.
    pub memory: Memory,
    /// Canonical byte ranges that currently contain private data.
    ///
    /// ZK register tags must survive compiler-generated spills without allowing bytecode to launder
    /// a secret through an untagged load. Guest private stores remain stack-only; the host may
    /// additionally publish opaque typed private-input envelopes in owned HEAP memory.
    private_memory_bytes: PrivateMemoryRanges,
    pub pc: u64,
    host: Option<Box<dyn IVMHost + Send + Sync>>,
    gas_limit: u64,
    pub gas_remaining: u64,
    /// Gas pre-debited for the syscall currently executing.
    ///
    /// This reserve is visible through [`Self::remaining_gas`] so hosts retain
    /// their existing gas-budget view, but it is not available to nested VM
    /// execution until the syscall reports its actual cost.
    syscall_gas_reserve: u64,
    /// Active per-phase accounting for a staged syscall.
    staged_syscall: Option<StagedSyscallContext>,
    /// Most recently completed staged syscall, retained for diagnostics and
    /// deterministic metering assertions.
    last_staged_syscall: Option<StagedSyscallContext>,
    /// Exact canonical entrypoint-argument gas escrowed before guest execution.
    argument_decode_prepaid_gas: Option<u64>,
    pub(crate) captured_root_tables: Option<call_runtime::CapturedRootTables>,
    cycles: u64,
    /// Scoped shared cycle allowance; runtime resets cannot replenish it.
    active_cycle_budget: Option<Arc<SharedVmCycleBudget>>,
    halted: bool,
    constraint_failed: bool,
    contract_abort_error: Option<VMError>,
    constraints: zk::ConstraintLog,
    mem_log: MemLog,
    reg_log: Option<zk::SharedRegLog>,
    /// Whether a host callback currently owns `&mut IVM` with a detached
    /// register log.
    host_trace_log_detached: bool,
    /// Invocation log retained while [`Self::reg_log`] is detached for a host
    /// callback. This also gives trace-policy setters an exact TLS identity to
    /// match instead of trusting a sticky boolean after unwinding.
    host_trace_invocation_log: Option<zk::SharedRegLog>,
    /// Changes whenever proof-facing state is discarded or replaced.
    ///
    /// Host callbacks may invoke public VM lifecycle methods. Capturing this
    /// epoch while the register logger is detached prevents a callback from
    /// resetting and then reconstructing the same apparent program identity
    /// before the logger is reattached.
    proof_state_epoch: u64,
    trace_log: DeltaTraceLog,
    step_log: zk::StepLog,
    trace_mode: TraceMode,
    pc_trace: zk::PcTraceLog,
    delta_trace: zk::DeltaTraceLog,
    vector_enabled: bool,
    /// Maximum number of 64-bit lanes supported natively by the host CPU.
    max_vector_lanes: usize,
    /// Current logical vector length for vector operations.
    vector_length: usize,
    max_cycles: u64,
    metadata: ProgramMetadata,
    code_hash: [u8; 32],
    contract_interface:
        Option<crate::cache_memory::SharedValue<crate::metadata::EmbeddedContractInterfaceV1>>,
    call_layouts: Option<call_runtime::CallLayouts>,
    contract_debug: Option<EmbeddedContractDebugInfoV1>,
    literal_table: DecodedLiteralTable,
    predecoded: Option<crate::ivm_cache::DecodedStream>,
    prepared: Option<PreparedProgram>,
    prepared_required: bool,
    /// Unforgeable local capability installed only by the crate-private Kotodama test-suite loader.
    allow_koto_test_syscalls: bool,
    /// Whether the loaded image is a deployable contract with protected calls.
    strict_return_integrity: bool,
    /// Host-protected return PCs for direct contract calls.
    contract_return_stack: ContractReturnStack,
    /// Aligned outer-return sentinel captured from r1 at invocation start.
    contract_outer_return_pc: Option<u64>,
    /// Bounded optional native producer; only a fresh sealed component run installs it.
    native_packets: Option<native_packets::Recorder>,
    #[cfg(test)]
    predecoded_misses: u64,
    #[cfg(test)]
    program_parse_attempts: u64,
    #[cfg(test)]
    prepared_loads: u64,
    /// Operator-configured scheduler thread limits reported in the startup banner.
    scheduler_limits: (usize, usize),
    /// Flag indicating if zero-knowledge mode is active.
    zk_mode: bool,
    /// Collect formal proof traces while preserving ZK-mode execution semantics.
    zk_trace_enabled: bool,
    entrypoint_pc: Option<u64>,
    program_prefix_len: u64,
    last_diagnostic: Option<TrapSnapshot>,
    /// Low-bit alignment shared by all valid instruction PCs in the loaded program.
    pc_alignment: u64,
    /// Next free offset (relative to `Memory::INPUT_START`) used by the
    /// simple INPUT TLV bump allocator for host-returned pointers.
    input_bump_next: u64,
    acceleration_policy: AccelerationPolicy,
    hardware_capabilities: Option<HardwareCapabilities>,
    // Release aggregate charges after every owned allocation above is destroyed.
    cache_reservation: crate::cache_memory::MemoryReservation,
}
impl IVM {
    /// Construct a builder for configuring VM creation.
    #[must_use]
    pub fn builder(gas_limit: u64) -> IvmBuilder {
        IvmBuilder::new(gas_limit)
    }
    /// Construct a builder preset that disables accelerator usage.
    #[must_use]
    pub fn deterministic_builder(gas_limit: u64) -> IvmBuilder {
        IvmBuilder::deterministic(gas_limit)
    }
    /// Construct a new VM directly from a configuration.
    pub fn with_config(config: IvmConfig) -> IvmBuilder {
        IvmBuilder::from_config(config)
    }
    /// Create a new VM using the default adaptive acceleration policy.
    pub fn new(gas_limit: u64) -> Self {
        IvmBuilder::new(gas_limit).suppress_startup_banner().build()
    }
    /// Create a VM with the default adaptive policy, deferring on local allocation refusal.
    ///
    /// # Errors
    /// Returns a local execution deferral if the VM memory image or Merkle backing
    /// cannot be reserved and allocated. This error does not change transaction validity.
    pub fn try_new(gas_limit: u64) -> Result<Self, VMError> {
        Self::try_new_from_config(IvmConfig::adaptive(gas_limit))
    }

    /// Construct a VM with its fixed guest memory image prepaid by a local pool.
    ///
    /// This funds the fixed image backing, memory and register Merkle nodes.
    /// Root and nested frame initialization bitmaps are admitted before call
    /// entry. Runtime templates, frame-vector growth, and host scratch still
    /// require separate admission.
    /// Capacity refusal is an operational deferral and never consumes guest gas.
    /// TODO: Extend one parent plan across those remaining allocation owners.
    pub fn try_new_with_memory_budget(
        gas_limit: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, VMError> {
        Self::try_new_from_config_with_memory_budget(IvmConfig::adaptive(gas_limit), Some(budget))
    }
    /// Borrow the original allocation pool for host scratch associated with this VM.
    ///
    /// Hosts must retain each admitted scratch reservation until its owned graph is
    /// destroyed. A standalone VM returns `None`; hosts must not substitute another pool.
    pub fn allocation_budget(&self) -> Option<&AllocationBudget> {
        self.memory.allocation_budget()
    }
    /// Construct an independent default VM funded by this VM's original pool.
    ///
    /// Guest memory, registers, call state and tracing policy are freshly
    /// initialized. A standalone VM produces another standalone VM; a funded
    /// VM never substitutes a different pool or falls back to standalone storage.
    ///
    /// # Errors
    /// Returns the original local allocation refusal before publishing the new VM.
    pub fn try_new_in_same_memory_pool(&self, gas_limit: u64) -> Result<Self, VMError> {
        Self::try_new_from_config_with_memory_budget(
            IvmConfig::adaptive(gas_limit),
            self.memory.allocation_budget(),
        )
    }

    /// Create a new VM using the provided configuration.
    pub fn new_with_config(config: IvmConfig) -> Self {
        IVM::new_from_config(config)
    }
    /// First general register index used to hold vector register data.
    const VECTOR_BASE: usize = 32;
    /// Play a short tune on the default audio device.
    ///
    /// This function is only available when built with the `beep` feature.
    #[cfg(feature = "beep")]
    pub fn beep_music() {
        const BPM: u64 = 120;
        const BEAT_MS: u64 = 60_000 / BPM;
        #[derive(Clone, Copy)]
        enum Note {
            A4,
            B4,
            G4,
            E4,
            Rest,
        }
        impl Note {
            fn freq(self) -> Option<u32> {
                match self {
                    Note::A4 => Some(440),
                    Note::B4 => Some(494),
                    Note::G4 => Some(392),
                    Note::E4 => Some(330),
                    Note::Rest => None,
                }
            }
        }
        fn play_element(mixer: &Mixer, note: Note, beats: f32) {
            let dur_ms = (BEAT_MS as f32 * beats) as u64;
            if let Some(f) = note.freq() {
                let sink = Sink::connect_new(mixer);
                let src = SineWave::new(f as f32)
                    .take_duration(Duration::from_millis(dur_ms))
                    .amplify(0.20);
                sink.append(src);
                sink.sleep_until_end();
            } else {
                std::thread::sleep(Duration::from_millis(dur_ms));
            }
        }
        // Japanese song, Kagome-Kagome
        fn play_kagome(mixer: &Mixer) {
            let score = vec![
                (Note::A4, 2.0),
                (Note::A4, 1.0),
                (Note::B4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::Rest, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 0.5),
                (Note::A4, 0.5),
                (Note::A4, 1.0),
                (Note::G4, 0.5),
                (Note::G4, 0.5),
                (Note::A4, 1.0),
                (Note::A4, 0.5),
                (Note::G4, 0.5),
                (Note::E4, 1.0),
                (Note::Rest, 1.0),
                (Note::A4, 1.0),
                (Note::G4, 1.0),
                (Note::A4, 1.0),
                (Note::G4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 0.5),
                (Note::G4, 0.5),
                (Note::E4, 1.0),
                (Note::Rest, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::B4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::Rest, 1.0),
                (Note::A4, 1.0),
                (Note::G4, 0.5),
                (Note::G4, 0.5),
                (Note::A4, 1.0),
                (Note::G4, 0.5),
                (Note::G4, 0.5),
                (Note::A4, 1.0),
                (Note::A4, 1.0),
                (Note::E4, 1.0),
                (Note::Rest, 1.0),
                (Note::A4, 0.5),
                (Note::A4, 0.5),
                (Note::A4, 0.5),
                (Note::A4, 0.5),
                (Note::A4, 1.0),
                (Note::B4, 1.0),
                (Note::A4, 1.5),
                (Note::G4, 0.5),
                (Note::A4, 1.0),
                (Note::Rest, 1.0),
            ];
            for (n, b) in score {
                play_element(mixer, n, b);
            }
        }
        with_audio_mixer(OutputStreamBuilder::open_default_stream, play_kagome);
    }
    fn startup_banner(
        core_count: usize,
        max_vector: usize,
        capabilities: HardwareCapabilities,
        metal: bool,
        cuda: bool,
        suppress: bool,
    ) {
        // Builder-local suppression must not mutate process-global state: VM
        // construction can happen concurrently in tooling and test workers.
        if suppress || SUPPRESS_BANNER.load(Ordering::Relaxed) {
            return;
        }
        const ART: &str = r#" 
 ██╗██████╗  ██████╗ ██╗ ██╗  █████╗ 
 ██║██╔══██╗██╔═══██╗██║ ██║ ██╔══██╗
 ██║██████╔╝██║   ██║███████████████║
 ██║██╔═██║ ██║   ██║██╔═██╔═██╔══██║
 ██║██║ ║██╗╚██████╔╝██║ ██║ ██║  ██║
 ╚═╝╚═╝ ╚══╝ ╚═════╝ ╚═╝ ╚═╝ ╚═╝  ╚═╝

  ╔════════╗ ╔════════╗ ╔════════╗
  ║   イ   ║ ║   ロ   ║ ║   ハ   ║
  ╚════════╝ ╚════════╝ ╚════════╝
  
 ＜ バ　ー　チ　ャ　ル　・　マ　シ　ン ＞

"#;
        println!("{ART}");
        println!(
            "Platform: {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let accel = if max_vector > 1 || metal || cuda {
            "yes"
        } else {
            "no"
        };
        println!("Hardware acceleration detected: {accel}");
        if capabilities.metal_available() {
            let status = if metal {
                "enabled"
            } else {
                "disabled by policy"
            };
            println!("Metal GPU available ({status})");
        }
        if capabilities.cuda_available() {
            let status = if cuda {
                "enabled"
            } else {
                "disabled by policy"
            };
            println!("CUDA GPU available ({status})");
        }
        let core_label = if core_count == 1 { "core" } else { "cores" };
        println!("Using {core_count} {core_label}");
    }
    /// Create a new IVM instance with default host and no program loaded.
    fn new_from_config(config: IvmConfig) -> Self {
        Self::try_new_from_config(config).expect("VM construction requires local memory")
    }
    /// Construct a VM with fallible, allocation-charged memory and Merkle leaves.
    fn try_new_from_config(config: IvmConfig) -> Result<Self, VMError> {
        Self::try_new_from_config_with_memory_budget(config, None)
    }

    fn try_new_from_config_with_memory_budget(
        config: IvmConfig,
        memory_budget: Option<&AllocationBudget>,
    ) -> Result<Self, VMError> {
        // Initially allocate memory for a reasonable code size (can be adjusted upon loading).
        let gas_limit = config.gas_limit();
        let mem = match memory_budget {
            Some(budget) => {
                Memory::new_with_stack_limit_funded(config.stack_limit_for_gas(), budget)?
            }
            None => Memory::new_with_stack_limit(config.stack_limit_for_gas())?,
        };
        let registers = match memory_budget {
            Some(budget) => Registers::try_new_with_memory_budget(budget)?,
            None => Registers::try_new()?,
        };
        vector::set_thread_forced_simd(config.acceleration().forced_simd());
        let max_vector_lanes = {
            #[cfg(target_arch = "x86_64")]
            {
                if std::is_x86_feature_detected!("avx512f") {
                    8
                } else if std::is_x86_feature_detected!("avx2") {
                    4
                } else if std::is_x86_feature_detected!("sse2") {
                    2
                } else {
                    1
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                2
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                1
            }
        };
        // Global Rayon pool initialization is handled by the host (e.g., irohad)
        // based on configuration. Avoid initializing a large global pool here to
        // reduce oversubscription when multiple thread pools coexist.
        let scheduler_limits = crate::parallel::default_scheduler_limits();
        let mut vm = IVM {
            cache_reservation: crate::cache_memory::MemoryReservation::active_unmeasured(0),
            registers,
            memory: mem,
            private_memory_bytes: memory_budget.map_or_else(
                PrivateMemoryRanges::default,
                PrivateMemoryRanges::with_memory_budget,
            ),
            pc: 0,
            host: Some(Box::new(crate::runtime::SyscallDispatcher::new(
                DefaultHost::new(),
            ))),
            gas_limit,
            gas_remaining: gas_limit,
            syscall_gas_reserve: 0,
            staged_syscall: None,
            last_staged_syscall: None,
            argument_decode_prepaid_gas: None,
            captured_root_tables: None,
            cycles: 0,
            active_cycle_budget: None,
            halted: false,
            constraint_failed: false,
            contract_abort_error: None,
            constraints: zk::ConstraintLog::default(),
            mem_log: MemLog::default(),
            reg_log: Some(zk::SharedRegLog::try_new(memory_budget)?),
            host_trace_log_detached: false,
            host_trace_invocation_log: None,
            proof_state_epoch: 0,
            trace_log: DeltaTraceLog::new(memory_budget),
            step_log: zk::StepLog::new(memory_budget),
            trace_mode: TraceMode::Off,
            pc_trace: zk::PcTraceLog::new(memory_budget),
            delta_trace: zk::DeltaTraceLog::new(memory_budget),
            vector_enabled: false,
            max_vector_lanes,
            vector_length: default_vector_length(),
            max_cycles: 0,
            metadata: ProgramMetadata::default(),
            code_hash: [0u8; 32],
            contract_interface: None,
            call_layouts: None,
            contract_debug: None,
            literal_table: DecodedLiteralTable::empty(),
            predecoded: None,
            prepared: None,
            prepared_required: false,
            allow_koto_test_syscalls: false,
            strict_return_integrity: false,
            contract_return_stack: memory_budget.map_or_else(
                ContractReturnStack::default,
                ContractReturnStack::with_memory_budget,
            ),
            contract_outer_return_pc: None,
            native_packets: None,
            #[cfg(test)]
            predecoded_misses: 0,
            #[cfg(test)]
            program_parse_attempts: 0,
            #[cfg(test)]
            prepared_loads: 0,
            scheduler_limits,
            zk_mode: false,
            zk_trace_enabled: false,
            entrypoint_pc: None,
            program_prefix_len: 0,
            last_diagnostic: None,
            pc_alignment: 0,
            input_bump_next: 0,
            acceleration_policy: AccelerationPolicy::deterministic(),
            hardware_capabilities: config.capabilities,
        };
        vm.set_acceleration_policy(config.acceleration());
        Ok(vm)
    }
    fn apply_acceleration_policy(&mut self, policy: AccelerationPolicy) {
        self.acceleration_policy = policy;
        vector::set_thread_forced_simd(policy.forced_simd());
    }
    /// Enable or disable zero-knowledge features.
    ///
    /// When enabled and no explicit cycle limit has been set, the default
    /// [`zk::MAX_CYCLES`] value is used. Disabling ZK clears the cycle limit.
    ///
    /// # Errors
    /// Private-range corruption or exhausted local diagnostic capacity leaves the
    /// mode, private bytes, tags and execution state unchanged.
    pub fn set_zk_mode(&mut self, enabled: bool) -> Result<(), VMError> {
        if !enabled {
            self.scrub_private_state()?;
        }
        self.proof_state_epoch = self.proof_state_epoch.wrapping_add(1);
        self.zk_mode = enabled;
        if enabled {
            if self.max_cycles == 0 {
                self.max_cycles = zk::MAX_CYCLES;
            }
        } else {
            self.max_cycles = 0;
        }
        Ok(())
    }
    /// Enable or disable formal ZK trace collection.
    ///
    /// This does not change ZK-mode execution semantics: ZK opcodes, privacy
    /// tags, assertion handling, max-cycle padding, and gas accounting remain
    /// active. Disabling this only suppresses proof/telemetry artifacts. A
    /// change made by a host during execution applies to the next invocation;
    /// the current invocation keeps the trace policy selected at its start.
    pub fn set_zk_trace_enabled(&mut self, enabled: bool) {
        self.zk_trace_enabled = enabled;
        let scoped_invocation_log = zk::scoped_reg_logger();
        let invocation_owns_this_log = scoped_invocation_log.as_ref().is_some_and(|active| {
            self.reg_log
                .as_ref()
                .is_some_and(|log| zk::SharedRegLog::ptr_eq(active, log))
        });
        let active_callback_owns_this_log = self.host_trace_log_detached
            && scoped_invocation_log.as_ref().is_some_and(|active| {
                self.host_trace_invocation_log
                    .as_ref()
                    .is_some_and(|invocation| zk::SharedRegLog::ptr_eq(active, invocation))
            });
        if !enabled && !invocation_owns_this_log && !active_callback_owns_this_log {
            self.clear_zk_trace_logs();
        }
    }
    /// Returns `true` when formal ZK trace collection is enabled.
    #[inline]
    pub fn zk_trace_enabled(&self) -> bool {
        self.zk_trace_enabled
    }
    /// Set the maximum cycle count used for zero-knowledge padding and enforcement.
    pub fn set_max_cycles(&mut self, max: u64) {
        // The active trace shape is fixed at invocation start. A host callback
        // may configure a later invocation, but it must not silently truncate
        // or backfill the proof that is currently being collected.
        self.proof_state_epoch = self.proof_state_epoch.wrapping_add(1);
        self.max_cycles = max;
    }
    /// Load raw code bytes under the default non-ZK, non-vector execution profile.
    ///
    /// Any profile and per-program execution state from a previously loaded artifact is discarded.
    /// Guest registers and the INPUT/STACK memory regions remain available to preload arguments.
    pub fn load_code(&mut self, code: &[u8]) -> Result<(), VMError> {
        self.last_diagnostic = None;
        self.check_trace_storage_owner()?;
        if code.len() > Memory::HEAP_START as usize {
            return Err(VMError::MemoryOutOfBounds);
        }
        self.scrub_private_state()?;
        self.metadata = ProgramMetadata::default();
        self.vector_enabled = false;
        self.vector_length = default_vector_length();
        self.max_cycles = 0;
        self.zk_mode = false;
        // Preserve INPUT/STACK contents but reset HEAP/OUTPUT for a clean run.
        self.memory.preflight_diagnostic_program_load(code.len())?;
        self.memory.clear_program_heap()?;
        self.memory.load_code(code)?;
        self.memory.clear_output()?;
        self.pc = 0;
        self.entrypoint_pc = Some(0);
        self.program_prefix_len = 0;
        self.contract_debug = None;
        self.contract_interface = None;
        self.call_layouts = None;
        self.literal_table = DecodedLiteralTable::empty();
        self.last_diagnostic = None;
        self.predecoded = None;
        self.prepared = None;
        self.prepared_required = false;
        self.allow_koto_test_syscalls = false;
        self.strict_return_integrity = false;
        self.contract_return_stack.clear();
        self.contract_outer_return_pc = None;
        self.code_hash = iroha_crypto::Hash::new(code).into();
        self.pc_alignment = 0;
        self.halted = false;
        self.constraint_failed = false;
        self.contract_abort_error = None;
        self.clear_zk_trace_logs();
        self.reset_trace_storage()?;
        self.cycles = 0;
        self.memory.commit();
        self.memory.mark_template_clean();
        Ok(())
    }
    /// Validate the canonical program and its complete static execution policy.
    ///
    /// Uses exactly the same preparation as [`Self::load_program`] without allocating
    /// mutable VM storage, callable layouts, or a runtime template. Immutable decoder
    /// and preparation allocations retain their existing independent ownership.
    ///
    /// # Errors
    /// Returns the loader's exact metadata, artifact, instruction, syscall, or local
    /// preparation error. Allocation refusal is never converted into invalid bytecode.
    pub fn validate_program(program: &[u8]) -> Result<(), VMError> {
        program_load::prepare(program, None).map(drop)
    }

    /// Load a program (bytecode) into the VM's code memory.
    pub fn load_program(&mut self, program: &[u8]) -> Result<(), VMError> {
        self.last_diagnostic = None;
        #[cfg(test)]
        {
            self.program_parse_attempts = self.program_parse_attempts.saturating_add(1);
        }
        match program_load::prepare(program, self.memory.allocation_budget())? {
            program_load::PreparedLoadImage::Contract(contract) => self.load_prepared(&contract),
            program_load::PreparedLoadImage::Generic(image) => self.install_program(image),
        }
    }
    /// Load an already validated and prepared contract without reparsing it.
    ///
    /// The immutable artifact, metadata, literal index, decoded stream, and
    /// prepared operations share their original owner when it is this VM's pool.
    /// A funded VM copies diagnostic or foreign-pool instruction and literal indexes
    /// into its own admitted storage before installation. Code bytes are installed into
    /// this VM's memory image.
    pub fn load_prepared(&mut self, contract: &PreparedContract) -> Result<(), VMError> {
        self.load_prepared_with_koto_test_capability(contract, false)
    }
    /// Load a fully validated local Kotodama test-suite artifact.
    ///
    /// Only a [`crate::KotoTestHarnessContract`] (from
    /// [`crate::prepare_koto_test_contract`]) enables the host-private Kotodama
    /// test-syscall range; the raw/program/prepared loaders never do, and
    /// production hosts still reject those syscalls.
    ///
    /// # Errors
    ///
    /// Returns [`VMError`] when the prepared image cannot be installed.
    pub fn load_koto_test_harness(
        &mut self,
        contract: &crate::KotoTestHarnessContract,
    ) -> Result<(), VMError> {
        self.load_prepared_with_koto_test_capability(contract.prepared(), true)
    }
    fn load_prepared_with_koto_test_capability(
        &mut self,
        contract: &PreparedContract,
        allow_koto_test_syscalls: bool,
    ) -> Result<(), VMError> {
        self.last_diagnostic = None;
        #[cfg(test)]
        {
            self.prepared_loads = self.prepared_loads.saturating_add(1);
        }
        let literal_table = match self.memory.allocation_budget() {
            Some(budget) => contract.literal_table().for_budget(budget)?,
            None => contract.literal_table().clone(),
        };
        let (decoded, prepared) = if let Some(budget) = self.memory.allocation_budget()
            && (!contract.decoded().belongs_to(budget)
                || !contract.prepared_program().belongs_to(budget))
        {
            // A code-only cache or another State cannot lend this VM execution
            // credit. Rebuild only instruction arrays from the admitted image.
            let code = &contract.artifact()[contract.code_offset()..];
            let decoded =
                crate::ivm_cache::IvmCache::decode_stream_with_memory_budget(code, budget)?;
            let prepared = prepare_instruction_stream(
                code,
                decoded.as_ref(),
                contract.instruction_entry_pc(),
                literal_table.entries(),
                Some(budget),
            )?;
            (decoded, prepared)
        } else {
            (
                contract.decoded().clone(),
                contract.prepared_program().clone(),
            )
        };
        self.install_program(ProgramLoadImage {
            code_region: contract.code_region(),
            metadata: contract.metadata().clone(),
            contract_interface: Some(contract.shared_contract_interface()),
            contract_debug: None,
            literal_table,
            predecoded: Some(decoded),
            prepared: Some(prepared),
            code_hash: contract.code_hash().into(),
            entry_pc: contract.instruction_entry_pc(),
            strict_return_integrity: true,
            allow_koto_test_syscalls,
        })
    }
    fn install_program(&mut self, image: ProgramLoadImage<'_>) -> Result<(), VMError> {
        self.last_diagnostic = None;
        self.check_trace_storage_owner()?;
        let code_len =
            u64::try_from(image.code_region.len()).map_err(|_| VMError::InvalidMetadata)?;
        if code_len > Memory::HEAP_START || image.entry_pc > code_len {
            return Err(VMError::InvalidMetadata);
        }
        // Prepare complete type traversal indexes before changing the loaded image.
        // Warm invocations retain these original-pool allocations without reanalysis.
        let call_layouts = image
            .contract_interface
            .as_ref()
            .map(|interface| {
                call_runtime::CallLayouts::prepare(interface, self.memory.allocation_budget())
            })
            .transpose()?;
        self.scrub_private_state()?;
        self.memory.call_frames.clear();
        self.captured_root_tables = None;
        self.call_layouts = call_layouts;
        self.metadata = image.metadata.clone();
        self.contract_interface = image.contract_interface;
        self.contract_debug = image.contract_debug;
        self.literal_table = image.literal_table;
        self.vector_enabled = image.metadata.mode & crate::metadata::mode::VECTOR != 0;
        self.max_cycles = image.metadata.max_cycles;
        self.zk_mode = image.metadata.mode & crate::metadata::mode::ZK != 0;
        if self.zk_mode && self.max_cycles == 0 {
            self.max_cycles = zk::MAX_CYCLES;
        }
        self.vector_length = if image.metadata.vector_length == 0 {
            default_vector_length()
        } else {
            usize::from(image.metadata.vector_length)
        };
        // Overlay code while preserving INPUT/STACK contents that may have
        // been preloaded by the host/tests. HEAP/OUTPUT are cleared per load.
        self.predecoded = image.predecoded;
        self.prepared = image.prepared;
        self.prepared_required = true;
        self.allow_koto_test_syscalls = image.allow_koto_test_syscalls;
        self.strict_return_integrity = image.strict_return_integrity;
        self.contract_return_stack.clear();
        self.contract_outer_return_pc = None;
        self.memory
            .preflight_diagnostic_program_load(image.code_region.len())?;
        self.memory.clear_program_heap()?;
        self.memory.load_code(image.code_region)?;
        self.memory.clear_output()?;
        self.registers.set(31, self.memory.stack_top());
        self.code_hash = image.code_hash;
        self.pc = image.entry_pc;
        self.entrypoint_pc = Some(self.pc);
        self.program_prefix_len = image.entry_pc;
        self.last_diagnostic = None;
        self.pc_alignment = self.pc & 0b11;
        self.halted = false;
        self.constraint_failed = false;
        self.contract_abort_error = None;
        self.constraints = zk::ConstraintLog::default();
        self.mem_log = MemLog::default();
        if let Some(log) = &self.reg_log {
            log.lock().scrub();
        }
        self.host_trace_log_detached = false;
        self.host_trace_invocation_log = None;
        self.reset_trace_storage()?;
        self.step_log.reset();
        self.cycles = 0;
        // Recompute the INPUT bump allocator based on any preloaded TLVs so that
        // host allocations append instead of overwriting existing entries.
        self.recompute_input_bump_from_memory()?;
        if crate::dev_env::decode_trace_enabled() {
            eprintln!(
                "[IVM] input_bump_next set to 0x{off:x}",
                off = self.input_bump_next
            );
        }
        self.memory.commit();
        self.memory.mark_template_clean();
        Ok(())
    }
    /// Set the gas limit for execution.
    pub fn set_gas_limit(&mut self, limit: u64) {
        self.gas_limit = limit;
        self.gas_remaining = limit;
        self.syscall_gas_reserve = 0;
        self.staged_syscall = None;
        self.last_staged_syscall = None;
        self.argument_decode_prepaid_gas = None;
        self.captured_root_tables = None;
    }
    pub(crate) fn prepay_argument_decode(&mut self, gas: u64) -> Result<(), VMError> {
        if self.argument_decode_prepaid_gas.is_some() || self.captured_root_tables.is_some() {
            return Err(VMError::DecodeError);
        }
        self.debit_gas(gas)?;
        self.argument_decode_prepaid_gas = Some(gas);
        Ok(())
    }
    pub(crate) fn has_prepaid_argument_decode(&self) -> bool {
        self.argument_decode_prepaid_gas.is_some()
    }
    pub(crate) fn argument_decode_is_prepaid(&self, gas: u64) -> bool {
        self.argument_decode_prepaid_gas == Some(gas)
    }
    pub(crate) fn consume_prepaid_argument_decode(&mut self, gas: u64) -> Result<(), VMError> {
        if !self.argument_decode_is_prepaid(gas) {
            return Err(VMError::DecodeError);
        }
        self.argument_decode_prepaid_gas = None;
        Ok(())
    }
    fn prepared_contains_pc(&self, pc: u64) -> bool {
        self.prepared
            .as_ref()
            .is_some_and(|prepared| prepared.contains_pc(pc))
    }
    fn preflight_contract_return(&mut self) -> Result<(), VMError> {
        if !self.strict_return_integrity {
            return Ok(());
        }
        if self.contract_return_stack.len() >= MAX_CONTRACT_CALL_DEPTH {
            return Err(VMError::AssertionFailed);
        }
        #[cfg(test)]
        if REFUSE_CALL_RETURN_RESERVATION_FOR_TEST.with(|refuse| refuse.replace(false)) {
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable,
            ));
        }
        self.contract_return_stack.preflight_one()
    }
    fn push_contract_return(&mut self, return_pc: u64) {
        if self.strict_return_integrity {
            self.contract_return_stack.push_reserved(return_pc);
        }
    }
    fn fetch_instruction(&mut self) -> Result<FetchedOp, VMError> {
        if let Some(op) = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.op_at(self.pc))
        {
            let fetched = op.fetched();
            self.memory
                .diagnostic_record_prepared_fetch(self.pc, fetched.inst)?;
            return Ok(fetched);
        }
        #[cfg(test)]
        {
            self.predecoded_misses += 1;
        }
        #[cfg(any(test, debug_assertions))]
        eprintln!(
            "[ivm] predecoded miss: has_predecoded={} contains_pc={} pc=0x{pc:x}",
            self.prepared.is_some(),
            self.prepared_contains_pc(self.pc),
            pc = self.pc
        );
        if self.prepared_required {
            return Err(VMError::MemoryAccessViolation {
                addr: self.pc as u32,
                perm: Perm::EXECUTE,
            });
        }
        let inst = decoder::decode(&self.memory, self.pc)?;
        let wide_op = instruction::wide::opcode(inst);
        Ok(FetchedOp {
            inst,
            wide_op,
            base_gas: gas::cost_of(inst),
        })
    }
    /// Access the parsed program metadata for the currently loaded program.
    pub fn metadata(&self) -> &ProgramMetadata {
        &self.metadata
    }
    /// Return the self-describing contract interface retained for the loaded image.
    ///
    /// Compiler-internal host helpers use the declared durable-state schema to
    /// validate typed state paths. Generic programs have no interface and
    /// therefore cannot use schema-bound helpers such as `StateMap` key codecs.
    #[must_use]
    pub fn contract_interface(&self) -> Option<&crate::metadata::EmbeddedContractInterfaceV1> {
        self.contract_interface.as_deref()
    }
    /// Returns `true` when the VM is executing in zero-knowledge mode.
    #[inline]
    pub fn zk_mode_enabled(&self) -> bool {
        self.zk_mode
    }
    #[inline]
    fn zk_trace_collection_enabled(&self) -> bool {
        zk::scoped_reg_logger_enabled().unwrap_or(self.zk_mode && self.zk_trace_enabled)
    }
    #[inline]
    fn zk_match_tags(&self, rs1: usize, rs2: usize) -> Result<Option<bool>, VMError> {
        if self.zk_mode {
            let tag_a = self.registers.tag(rs1);
            let tag_b = self.registers.tag(rs2);
            if tag_a != tag_b {
                return Err(VMError::PrivacyViolation);
            }
            Ok(Some(tag_a))
        } else {
            Ok(None)
        }
    }
    /// Reject private operands before an operation whose trap behavior depends on their values. A
    /// private divide-by-zero, failed assertion, or inverse failure would otherwise reveal a
    /// witness predicate through the public execution result.
    #[inline]
    fn zk_require_public_trap_operands(&self, registers: &[usize]) -> Result<(), VMError> {
        if self.zk_mode
            && registers
                .iter()
                .any(|&register| self.registers.tag(register))
        {
            return Err(VMError::PrivacyViolation);
        }
        Ok(())
    }
    #[inline]
    fn zk_unary_tag(&self, rs: usize) -> Option<bool> {
        if self.zk_mode {
            Some(self.registers.tag(rs))
        } else {
            None
        }
    }
    #[inline]
    fn zk_apply_tag(&mut self, rd: usize, tag: Option<bool>) {
        if let Some(tag) = tag {
            self.registers.set_tag(rd, tag);
        }
    }
    fn memory_privacy_range(addr: u64, len: u64) -> Result<std::ops::Range<u64>, VMError> {
        let end = addr.checked_add(len).ok_or(VMError::PrivacyViolation)?;
        Ok(addr..end)
    }
    /// Return the privacy tag for a scalar memory load.
    ///
    /// A partially overwritten private word is rejected rather than silently
    /// downgrading it to public data or exposing a fragment of the secret.
    fn memory_load_privacy_tag(&self, addr: u64, len: u64) -> Result<bool, VMError> {
        if !self.zk_mode {
            return Ok(false);
        }
        let range = Self::memory_privacy_range(addr, len)?;
        let private_count = self.private_memory_bytes.intersection_len(range);
        match private_count {
            0 => Ok(false),
            count if count == len => {
                let end = addr.checked_add(len).ok_or(VMError::PrivacyViolation)?;
                if addr < Memory::STACK_START || end > self.memory.stack_top() {
                    // Host-issued private HEAP envelopes are opaque handles.
                    // Guest loads cannot reinterpret their canonical bytes and
                    // bypass the typed commitment boundary.
                    return Err(VMError::PrivacyViolation);
                }
                Ok(true)
            }
            _ => Err(VMError::PrivacyViolation),
        }
    }
    /// Reject any non-tag-propagating operation that reads private stack data.
    pub(crate) fn ensure_public_memory(&self, addr: u64, len: u64) -> Result<(), VMError> {
        if !self.zk_mode || self.private_memory_bytes.is_empty() {
            return Ok(());
        }
        if self
            .private_memory_bytes
            .intersects(Self::memory_privacy_range(addr, len)?)
        {
            return Err(VMError::PrivacyViolation);
        }
        Ok(())
    }
    /// Validate that a private value can be spilled without crossing a public
    /// host boundary. Compiler-generated private spills are stack-only.
    fn validate_memory_store_privacy(
        &self,
        addr: u64,
        len: u64,
        private: bool,
    ) -> Result<(), VMError> {
        if !self.zk_mode || !private {
            return Ok(());
        }
        let range = Self::memory_privacy_range(addr, len)?;
        if range.start < Memory::STACK_START || range.end > self.memory.stack_top() {
            return Err(VMError::PrivacyViolation);
        }
        Ok(())
    }
    fn record_memory_store_privacy(&mut self, addr: u64, len: u64, private: bool) {
        self.memory.diagnostic_classify_last_access(
            addr,
            len,
            DiagnosticMemoryAccessKind::Write,
            private,
        );
        let Ok(range) = Self::memory_privacy_range(addr, len) else {
            return;
        };
        self.private_memory_bytes
            .apply_prepared_update(range, self.zk_mode && private);
    }
    fn preflight_memory_store_privacy(
        &mut self,
        addr: u64,
        len: u64,
        private: bool,
    ) -> Result<(), VMError> {
        let range = Self::memory_privacy_range(addr, len)?;
        self.private_memory_bytes
            .try_prepare_update(&range, self.zk_mode && private)
    }
    /// Detect a direct value or complete owned TLV that overlaps private bytes.
    ///
    /// Register tags catch scalar arguments. This additional check prevents a
    /// raw program from passing a public pointer to a private stack spill.
    fn syscall_argument_references_private_memory(&self, value: u64) -> bool {
        if self.private_memory_bytes.is_empty() {
            return false;
        }
        let direct_len = 8;
        if self.memory.inspect_region(value, direct_len).is_ok()
            && self.ensure_public_memory(value, direct_len).is_err()
        {
            return true;
        }
        let Ok(header) = self.memory.inspect_region(value, 7) else {
            return false;
        };
        let payload_len = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as u64;
        let Some(total) = 7u64
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(iroha_crypto::Hash::LENGTH as u64))
        else {
            return false;
        };
        self.memory.inspect_region(value, total).is_ok()
            && self.ensure_public_memory(value, total).is_err()
    }
    #[cfg(test)]
    pub(crate) fn reset_predecode_misses(&mut self) {
        self.predecoded_misses = 0;
    }
    #[cfg(test)]
    pub(crate) fn predecode_misses(&self) -> u64 {
        self.predecoded_misses
    }
    #[cfg(test)]
    pub(crate) fn program_parse_attempts(&self) -> u64 {
        self.program_parse_attempts
    }
    #[cfg(test)]
    pub(crate) fn prepared_loads(&self) -> u64 {
        self.prepared_loads
    }
    /// Query whether policy enables CUDA in the diagnostic capability snapshot.
    /// A disabled policy returns immediately; actual dispatch independently qualifies hardware.
    pub fn uses_cuda(&self) -> bool {
        self.acceleration_policy.allow_cuda() && self.hardware_capabilities().cuda_available()
    }
    /// Returns the acceleration policy currently applied to this VM.
    pub fn acceleration_policy(&self) -> AccelerationPolicy {
        self.acceleration_policy
    }
    /// Query the diagnostic capability snapshot, discovering and qualifying hardware on the
    /// first automatic query. Explicit overrides are returned without discovery.
    pub fn hardware_capabilities(&self) -> HardwareCapabilities {
        self.hardware_capabilities
            .unwrap_or_else(|| *hardware_capabilities_snapshot())
    }
    /// Override this VM's diagnostic capability snapshot without discovering accelerators.
    /// This does not bypass backend qualification or alter dispatch ownership.
    pub fn set_hardware_capabilities(&mut self, capabilities: HardwareCapabilities) {
        self.hardware_capabilities = Some(capabilities);
    }
    /// Update the acceleration policy without discovering optional accelerators.
    pub fn set_acceleration_policy(&mut self, policy: AccelerationPolicy) {
        self.apply_acceleration_policy(policy);
    }
    /// Query whether policy enables Metal in the diagnostic capability snapshot.
    /// A disabled policy returns immediately; actual dispatch independently qualifies hardware.
    pub fn uses_metal(&self) -> bool {
        self.acceleration_policy.allow_metal() && self.hardware_capabilities().metal_available()
    }
    /// Current program counter (byte offset into code region).
    pub fn pc(&self) -> u64 {
        self.pc
    }
    /// Set the current program counter to a decoded instruction boundary.
    ///
    /// # Errors
    /// Returns [`VMError::DecodeError`] when `pc` does not refer to a decoded
    /// instruction in the currently loaded program.
    pub fn set_program_counter(&mut self, pc: u64) -> Result<(), VMError> {
        if self.prepared_contains_pc(pc) {
            self.pc = pc;
            self.entrypoint_pc = Some(pc);
            self.contract_return_stack.clear();
            self.contract_outer_return_pc = None;
            self.memory.call_frames.clear();
            self.captured_root_tables = None;
            Ok(())
        } else {
            Err(VMError::DecodeError)
        }
    }
    /// Allocate space in the INPUT region and write the provided TLV bytes.
    /// Returns the absolute pointer to the start of the TLV.
    pub fn alloc_input_tlv(&mut self, tlv: &[u8]) -> Result<u64, VMError> {
        // 8-byte alignment between entries to preserve natural alignment of common payloads.
        const ALIGN: u64 = 8;
        let mut off = self.input_bump_next;
        let rem = off % ALIGN;
        if rem != 0 {
            off += ALIGN - rem;
        }
        let end = off
            .checked_add(tlv.len() as u64)
            .ok_or(VMError::MemoryOutOfBounds)?;
        if end > Memory::INPUT_SIZE {
            return Err(VMError::MemoryOutOfBounds);
        }
        self.memory.preload_input(off, tlv)?;
        self.input_bump_next = end;
        Ok(Memory::INPUT_START + off)
    }
    /// Allocate a host-produced TLV, preferring INPUT and spilling to HEAP when the
    /// INPUT bump allocator is exhausted.
    ///
    /// This keeps small host returns in the traditional read-only INPUT region while
    /// allowing large streamed reads, such as staged durable-state chunks, to continue
    /// without exhausting the fixed INPUT window.
    pub fn alloc_host_tlv(&mut self, tlv: &[u8]) -> Result<u64, VMError> {
        match self.alloc_input_tlv(tlv) {
            Ok(ptr) => Ok(ptr),
            Err(VMError::MemoryOutOfBounds) => {
                let addr = self.alloc_heap(tlv.len() as u64)?;
                self.store_bytes(addr, tlv)?;
                Ok(addr)
            }
            Err(err) => Err(err),
        }
    }
    /// Allocate an opaque host-produced private TLV in owned HEAP memory.
    ///
    /// INPUT is intentionally not used: private ranges must be writable so the
    /// VM can scrub them before reset, program replacement, or leaving ZK mode.
    pub(crate) fn alloc_host_private_tlv(&mut self, tlv: &[u8]) -> Result<u64, VMError> {
        if !self.zk_mode {
            return Err(VMError::PrivacyViolation);
        }
        let len = u64::try_from(tlv.len()).map_err(|_| VMError::OutOfMemory)?;
        let address = Memory::HEAP_START
            .checked_add(self.memory.heap_allocated_len())
            .ok_or(VMError::OutOfMemory)?;
        self.preflight_memory_store_privacy(address, len, true)?;
        let address = self.alloc_heap(len)?;
        self.memory.store_bytes(address, tlv)?;
        self.record_memory_store_privacy(address, len, true);
        Ok(address)
    }
    fn preflight_host_tlv_allocations_from(
        mut input_cursor: u64,
        mut heap_allocated: u64,
        heap_limit: u64,
        tlv_lengths: &[usize],
    ) -> Result<(), VMError> {
        const ALIGN: u64 = 8;
        for &length in tlv_lengths {
            let length = u64::try_from(length).map_err(|_| VMError::OutOfMemory)?;
            let input_start = input_cursor
                .checked_add(ALIGN - 1)
                .map(|value| value & !(ALIGN - 1))
                .ok_or(VMError::OutOfMemory)?;
            let input_end = input_start
                .checked_add(length)
                .ok_or(VMError::OutOfMemory)?;
            if input_end <= Memory::INPUT_SIZE {
                input_cursor = input_end;
                continue;
            }
            let heap_length = length
                .checked_add(ALIGN - 1)
                .map(|value| value & !(ALIGN - 1))
                .ok_or(VMError::OutOfMemory)?;
            heap_allocated = heap_allocated
                .checked_add(heap_length)
                .ok_or(VMError::OutOfMemory)?;
            if heap_allocated > heap_limit {
                return Err(VMError::OutOfMemory);
            }
        }
        Ok(())
    }
    /// Prove that a sequence of host TLV allocations can complete atomically
    /// with the VM's current INPUT cursor and HEAP ownership.
    ///
    /// Callers use this before the first allocation so a bounded operation can
    /// never publish a partial pointer table and then fail for lack of memory.
    pub(crate) fn preflight_host_tlv_allocations(
        &self,
        tlv_lengths: &[usize],
    ) -> Result<(), VMError> {
        self.preflight_host_tlv_allocations_with_reserved_heap(tlv_lengths, 0)
    }
    /// Prove that host TLVs and a separate compiler-owned HEAP reservation fit
    /// together before either allocation class mutates the VM.
    ///
    /// # Errors
    ///
    /// Returns [`VMError`] when the TLVs and the HEAP reservation cannot all be
    /// allocated from the current INPUT and HEAP capacity.
    pub fn preflight_host_tlv_allocations_with_reserved_heap(
        &self,
        tlv_lengths: &[usize],
        reserved_heap_bytes: u64,
    ) -> Result<(), VMError> {
        let available_heap_limit = self
            .memory
            .heap_limit()
            .checked_sub(reserved_heap_bytes)
            .ok_or(VMError::OutOfMemory)?;
        if self.memory.heap_allocated_len() > available_heap_limit {
            return Err(VMError::OutOfMemory);
        }
        Self::preflight_host_tlv_allocations_from(
            self.input_bump_next,
            self.memory.heap_allocated_len(),
            available_heap_limit,
            tlv_lengths,
        )
    }
    /// Prove that host TLVs and compiler-owned HEAP allocations fit a clean V1
    /// VM before admitting an invocation.
    pub(crate) fn preflight_fresh_host_tlv_allocations_with_reserved_heap(
        tlv_lengths: &[usize],
        reserved_heap_bytes: u64,
    ) -> Result<(), VMError> {
        let available_heap_limit = Memory::HEAP_SIZE
            .checked_sub(reserved_heap_bytes)
            .ok_or(VMError::OutOfMemory)?;
        Self::preflight_host_tlv_allocations_from(0, 0, available_heap_limit, tlv_lengths)
    }
    /// Require a prospective pointer-ABI envelope range to have public, VM-owned provenance.
    ///
    /// Pointer envelopes may reside in immutable program data, INPUT, or the allocated portion of
    /// HEAP. Guest stack/output bytes and unallocated heap capacity are not pointer-ABI object
    /// stores, even when their bytes happen to form a valid envelope.
    pub(crate) fn ensure_owned_public_tlv_range(
        &self,
        address: u64,
        len: u64,
    ) -> Result<(), VMError> {
        self.ensure_public_memory(address, len)?;
        self.ensure_owned_tlv_range(address, len)
    }
    /// Require a prospective pointer-ABI envelope range to have VM-owned
    /// provenance without scanning its complete payload.
    ///
    /// Pointer decoders use this after reading a bounded public header and
    /// before copying the complete declared range. Private guest stores are
    /// stack-only, while owned pointer-ABI regions exclude the stack, so the
    /// complete privacy check can occur after the corresponding staged debit.
    pub(crate) fn ensure_owned_tlv_range(&self, address: u64, len: u64) -> Result<(), VMError> {
        let end = address.checked_add(len).ok_or(VMError::NoritoInvalid)?;
        let in_code = end <= self.memory.code_len() && self.is_validated_literal_pointer(address);
        let in_heap = address >= Memory::HEAP_START
            && end
                <= Memory::HEAP_START
                    .checked_add(self.memory.heap_allocated_len())
                    .ok_or(VMError::NoritoInvalid)?;
        let in_input = address >= Memory::INPUT_START
            && end
                <= Memory::INPUT_START
                    .checked_add(Memory::INPUT_SIZE)
                    .ok_or(VMError::NoritoInvalid)?;
        if in_code || in_heap || in_input {
            Ok(())
        } else {
            Err(VMError::NoritoInvalid)
        }
    }
    /// Snapshot one complete opaque private TLV after reserved syscall gas was debited.
    pub(crate) fn snapshot_private_tlv(
        &self,
        address: u64,
        maximum_envelope: usize,
    ) -> Result<Vec<u8>, VMError> {
        if !self.zk_mode {
            return Err(VMError::PrivacyViolation);
        }
        const HEADER_BYTES: u64 = 7;
        self.ensure_owned_tlv_range(address, HEADER_BYTES)?;
        let header = self
            .memory
            .load_region(address, HEADER_BYTES)
            .map_err(|error| {
                crate::error::preserve_execution_deferral(error, VMError::NoritoInvalid)
            })?;
        let payload_len = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
        let total = 7usize
            .checked_add(payload_len)
            .and_then(|bytes| bytes.checked_add(iroha_crypto::Hash::LENGTH))
            .ok_or(VMError::NoritoInvalid)?;
        if total > maximum_envelope {
            return Err(VMError::NoritoInvalid);
        }
        let total_u64 = u64::try_from(total).map_err(|_| VMError::NoritoInvalid)?;
        self.ensure_owned_tlv_range(address, total_u64)?;
        let range = Self::memory_privacy_range(address, total_u64)?;
        if self.private_memory_bytes.intersection_len(range) != total_u64 {
            return Err(VMError::PrivacyViolation);
        }
        self.memory
            .load_region(address, total_u64)
            .map(<[u8]>::to_vec)
            .map_err(|error| {
                crate::error::preserve_execution_deferral(error, VMError::NoritoInvalid)
            })
    }
    /// Require a raw compiler-owned object to fit wholly within allocated HEAP.
    ///
    /// Unlike pointer-ABI envelopes, compiler-owned Lists may never alias code
    /// literals or INPUT. Their schema is supplied out of band and their
    /// provenance is the successful guest/host heap allocation itself.
    pub(crate) fn ensure_owned_heap_range(&self, address: u64, len: u64) -> Result<(), VMError> {
        self.ensure_public_memory(address, len)?;
        let end = address.checked_add(len).ok_or(VMError::DecodeError)?;
        let heap_end = Memory::HEAP_START
            .checked_add(self.memory.heap_allocated_len())
            .ok_or(VMError::DecodeError)?;
        if address >= Memory::HEAP_START && end <= heap_end {
            Ok(())
        } else {
            Err(VMError::DecodeError)
        }
    }
    /// Return whether `address` is an exact loader-validated literal envelope start.
    pub(crate) fn is_validated_literal_pointer(&self, address: u64) -> bool {
        self.literal_table
            .pointer_starts()
            .binary_search(&address)
            .is_ok()
    }
    fn inspect_owned_public_tlv_header(&self, ptr: u64) -> Result<(u64, u8), VMError> {
        ptr.checked_add(7).ok_or(VMError::NoritoInvalid)?;
        self.ensure_public_memory(ptr, 7)?;
        let hdr = self.memory.load_region(ptr, 7).map_err(|error| {
            crate::error::preserve_execution_deferral(error, VMError::NoritoInvalid)
        })?;
        let len = u64::from(u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]));
        let total = 7_u64
            .checked_add(len)
            .and_then(|size| {
                size.checked_add(
                    u64::try_from(iroha_crypto::Hash::LENGTH)
                        .expect("digest length always fits u64"),
                )
            })
            .ok_or(VMError::NoritoInvalid)?;
        ptr.checked_add(total).ok_or(VMError::NoritoInvalid)?;
        // Privacy is a public-boundary invariant, not an owned-region
        // side-effect. Check the complete self-described range before
        // rejecting invalid provenance so stack-shaped envelopes cannot
        // declassify a private payload through a boolean decoder result.
        self.ensure_public_memory(ptr, total)?;
        self.ensure_owned_tlv_range(ptr, total)?;
        Ok((len, hdr[2]))
    }
    /// Charge the byte-linear portion of a direct signature opcode before
    /// checksum hashing or cryptographic verification.
    ///
    /// All operands are inspected even after a malformed public pointer so a
    /// later private operand still fails with `PrivacyViolation`. Aliased
    /// operands are charged independently because validation scans each role.
    fn preflight_signature_opcode_payloads(&mut self, pointers: [u64; 3]) -> Result<bool, VMError> {
        let mut payload_lengths = [0_u64; 3];
        let mut malformed = false;
        for (index, pointer) in pointers.into_iter().enumerate() {
            match self.inspect_owned_public_tlv_header(pointer) {
                Ok((length, version)) => {
                    if version == 1 {
                        payload_lengths[index] = length;
                    } else {
                        // Version rejection is fixed-header work. It precedes
                        // checksum hashing, so it must not receive the
                        // byte-linear surcharge.
                        malformed = true;
                    }
                }
                Err(VMError::PrivacyViolation) => return Err(VMError::PrivacyViolation),
                Err(error) if error.execution_deferral().is_some() => return Err(error),
                Err(_) => malformed = true,
            }
        }
        if malformed {
            return Ok(false);
        }
        let extra_gas = crate::gas::signature_opcode_extra_gas(
            payload_lengths[0],
            payload_lengths[1],
            payload_lengths[2],
        )
        .ok_or(VMError::GasCostOverflow)?;
        self.debit_gas(extra_gas)?;
        Ok(true)
    }
    /// Validate a pointer-ABI TLV in any owned public region and return its decoded view.
    pub fn validate_tlv(&self, ptr: u64) -> Result<crate::pointer_abi::Tlv<'_>, VMError> {
        let (len, _) = self.inspect_owned_public_tlv_header(ptr)?;
        let total = 7_u64
            .checked_add(len)
            .and_then(|size| {
                size.checked_add(
                    u64::try_from(iroha_crypto::Hash::LENGTH)
                        .expect("digest length always fits u64"),
                )
            })
            .ok_or(VMError::NoritoInvalid)?;
        let envelope = self.memory.load_region(ptr, total).map_err(|error| {
            crate::error::preserve_execution_deferral(error, VMError::NoritoInvalid)
        })?;
        match crate::pointer_abi::validate_tlv_bytes(envelope) {
            Ok(tlv) => {
                let (policy, abi_version) = crate::pointer_abi::current_policy()
                    .unwrap_or_else(|| (self.syscall_policy(), self.abi_version()));
                let unsupported_abi = abi_version != 1;
                let disallowed_type =
                    !crate::pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id);
                if unsupported_abi || disallowed_type {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: abi_version,
                        type_id: tlv.type_id as u16,
                    });
                }
                Ok(tlv)
            }
            Err(err) => Err(err),
        }
    }
    /// Validate a public cryptographic operand with a boolean result for malformed TLVs.
    /// Privacy violations and operational refusals never become verification failures.
    fn validate_public_crypto_tlv(
        &self,
        ptr: u64,
    ) -> Result<Option<crate::pointer_abi::Tlv<'_>>, VMError> {
        match self.validate_tlv(ptr) {
            Ok(tlv) => Ok(Some(tlv)),
            Err(VMError::PrivacyViolation) => Err(VMError::PrivacyViolation),
            Err(error) if error.execution_deferral().is_some() => Err(error),
            Err(_) => Ok(None),
        }
    }
    /// Validate a pointer-ABI TLV in the INPUT region and return its decoded view.
    pub fn validate_input_tlv(&self, ptr: u64) -> Result<crate::pointer_abi::Tlv<'_>, VMError> {
        let input_end = Memory::INPUT_START
            .checked_add(Memory::INPUT_SIZE)
            .ok_or(VMError::NoritoInvalid)?;
        if !(Memory::INPUT_START..input_end).contains(&ptr) {
            return Err(VMError::NoritoInvalid);
        }
        self.validate_tlv(ptr)
    }
    /// Clone a validated TLV from any readable region into an owned buffer.
    pub fn clone_tlv(&self, ptr: u64) -> Result<Vec<u8>, VMError> {
        let tlv = self.validate_tlv(ptr)?;
        let mut out = Vec::with_capacity(7 + tlv.payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(tlv.type_id as u16).to_be_bytes());
        out.push(tlv.version);
        out.extend_from_slice(&(tlv.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(tlv.payload);
        let hash: [u8; 32] = iroha_crypto::Hash::new(tlv.payload).into();
        out.extend_from_slice(&hash);
        Ok(out)
    }
    /// ABI version extracted from the program header.
    pub fn abi_version(&self) -> u8 {
        self.metadata.abi_version
    }
    /// Effective syscall policy for the currently loaded program.
    ///
    /// The first release only accepts ABI v1 programs, so loaded programs
    /// always use the canonical v1 syscall surface.
    pub fn syscall_policy(&self) -> SyscallPolicy {
        debug_assert_eq!(self.metadata.abi_version, 1);
        SyscallPolicy::AbiV1
    }
    /// Reset registers, PC and cycles while preserving loaded program and host.
    ///
    /// # Errors
    /// Private-range corruption or exhausted local diagnostic capacity leaves
    /// guest execution state unchanged. The preceding diagnostic is cleared
    /// when reset is attempted. The caller may retry with a coherent owner.
    pub fn reset(&mut self) -> Result<(), VMError> {
        self.last_diagnostic = None;
        self.check_trace_storage_owner()?;
        self.scrub_private_state()?;
        self.reset_execution_state()?;
        Ok(())
    }
    /// Reset transient state after the memory owner has completed its cleanup.
    fn reset_execution_state(&mut self) -> Result<(), VMError> {
        self.last_diagnostic = None;
        self.check_trace_storage_owner()?;
        let resume_pc = self
            .entrypoint_pc
            .or_else(|| self.prepared.as_ref().map(|prepared| prepared.first_pc))
            .unwrap_or(0);
        let _logger_mask = zk::RegLoggerGuard::mask();
        self.clear_zk_trace_logs();
        self.registers.reset_to_zero();
        self.registers.set(31, self.memory.stack_top());
        self.pc = resume_pc;
        self.cycles = 0;
        self.halted = false;
        self.constraint_failed = false;
        self.contract_abort_error = None;
        self.constraints = zk::ConstraintLog::default();
        self.mem_log = MemLog::default();
        if let Some(log) = &self.reg_log {
            log.lock().scrub();
        }
        self.host_trace_log_detached = false;
        if let Some(invocation_log) = self.host_trace_invocation_log.take() {
            invocation_log.lock().scrub();
        }
        self.reset_trace_storage()?;
        self.step_log.reset();
        self.contract_return_stack.clear();
        self.contract_outer_return_pc = None;
        self.memory.call_frames.clear();
        // Gas remaining is not reset here; set_gas_limit should be called if needed.
        self.gas_remaining = self.remaining_gas();
        self.syscall_gas_reserve = 0;
        self.staged_syscall = None;
        self.last_staged_syscall = None;
        self.argument_decode_prepaid_gas = None;
        self.captured_root_tables = None;
        self.vector_length = if self.metadata.vector_length == 0 {
            default_vector_length()
        } else {
            usize::from(self.metadata.vector_length)
        };
        Ok(())
    }
    /// Capture the current post-load state as a reusable execution baseline.
    ///
    /// Hosts should call this after loading and configuring an immutable
    /// program, before attaching an invocation-specific host or arguments.
    /// Exclusive access keeps allocation geometry fixed during funded capture.
    /// State-owned VMs prepay the complete private snapshot through their
    /// original allocation pool before constructing any cloned payload.
    ///
    /// # Errors
    /// Defers locally if the baseline owns live call frames or any owned
    /// memory/register snapshot cannot be reserved.
    pub fn try_runtime_template(&mut self) -> Result<RuntimeTemplate, VMError> {
        // Exclusive access prevents interior read-log or Merkle-cache growth
        // between the allocation plan and the copy. No caller-supplied pool can
        // substitute equal-looking limits for the original State pool.
        let owner_bytes = RuntimeTemplate::owner_allocation_bytes()?;
        let mut allocation_lease = self
            .memory
            .allocation_budget()
            .map(|budget| {
                let mut plan =
                    crate::execution_memory::ExecutionMemoryPlan::array::<u8>(owner_bytes)
                        .map_err(VMError::AllocationDeferred)?;
                plan.include_child(self.memory.runtime_template_memory_plan()?)
                    .map_err(VMError::AllocationDeferred)?;
                plan.include_child(self.registers.runtime_template_memory_plan()?)
                    .map_err(VMError::AllocationDeferred)?;
                plan.include_child(self.private_memory_bytes.runtime_template_memory_plan()?)
                    .map_err(VMError::AllocationDeferred)?;
                crate::execution_memory::ExecutionMemoryLease::reserve(budget, plan)
                    .map_err(VMError::AllocationDeferred)
            })
            .transpose()?;
        let cache_reservation = crate::cache_memory::MemoryReservation::active(owner_bytes);
        let memory = self
            .memory
            .try_clone_for_runtime_template(allocation_lease.as_mut())?;
        let registers = self.registers.try_clone_for_runtime_template()?;
        let private_memory_bytes = self
            .private_memory_bytes
            .try_clone_for_runtime_template(allocation_lease.as_mut())?;
        Ok(RuntimeTemplate::new(
            RuntimeTemplateData {
                memory,
                registers,
                private_memory_bytes,
                code_hash: self.code_hash,
                pc: self.pc,
                gas_limit: self.gas_limit,
                max_cycles: self.max_cycles,
                trace_mode: self.trace_mode,
                zk_mode: self.zk_mode,
                zk_trace_enabled: self.zk_trace_enabled,
                entrypoint_pc: self.entrypoint_pc,
                input_bump_next: self.input_bump_next,
            },
            RuntimeTemplateBacking {
                cache_reservation,
                _allocation_lease: allocation_lease,
            },
        ))
    }
    /// Restore a warmed VM to a previously captured post-load baseline.
    ///
    /// Program metadata and predecoded code are immutable and remain in place. Invocation-specific
    /// hosts, registers, traces, gas, entrypoints, input, heap, and output are reset. Memory
    /// restoration is proportional to the number of chunks modified by the invocation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeTemplateResetError`] when the VM and template refer to
    /// different programs or memory baselines, their memory geometries differ,
    /// or missing private-range capacity cannot be reserved.
    /// The guest state is left unchanged so a runtime pool can discard it without
    /// a full reload. Attempting reset clears the preceding trap diagnostic.
    pub fn reset_from_runtime_template(
        &mut self,
        template: &RuntimeTemplate,
    ) -> Result<(), RuntimeTemplateResetError> {
        self.last_diagnostic = None;
        let template = template.data();
        if self.code_hash != template.code_hash {
            return Err(RuntimeTemplateResetError::from_program_identity(
                self.code_hash,
                template.code_hash,
            ));
        }
        self.memory
            .ensure_template_geometry(&template.memory)
            .map_err(RuntimeTemplateResetError::from_memory)?;
        let current_generation = self.memory.template_generation();
        let template_generation = template.memory.template_generation();
        if current_generation != template_generation {
            return Err(RuntimeTemplateResetError::from_memory_lifecycle(
                current_generation,
                template_generation,
            ));
        }
        if !self.memory.shares_baseline_lineage(&template.memory) {
            return Err(RuntimeTemplateResetError::from_memory_baseline_identity());
        }
        self.check_trace_storage_owner()
            .map_err(|_| RuntimeTemplateResetError::from_trace_owner())?;
        self.private_memory_bytes
            .try_prepare_restore(&template.private_memory_bytes)
            .map_err(RuntimeTemplateResetError::from_allocation_unavailable)?;
        // The template restores dirty memory chunks, so stale tags must not
        // cause reset() to scrub bytes restored from that baseline.
        self.memory
            .reset_from_template(&template.memory)
            .map_err(RuntimeTemplateResetError::from_memory)?;
        self.private_memory_bytes.clear();
        // A pooled runtime must begin each invocation with the complete gas
        // budget. `reset()` deliberately preserves the current remaining gas,
        // so replenish it before resetting transient execution state.
        self.set_gas_limit(template.gas_limit);
        self.max_cycles = template.max_cycles;
        self.trace_mode = template.trace_mode;
        self.zk_trace_enabled = template.zk_trace_enabled;
        self.entrypoint_pc = template.entrypoint_pc;
        self.input_bump_next = template.input_bump_next;
        self.set_host(DefaultHost::default());
        self.reset_execution_state()
            .map_err(|_| RuntimeTemplateResetError::from_trace_owner())?;
        self.zk_mode = template.zk_mode;
        self.registers.restore_from_template(&template.registers);
        self.private_memory_bytes
            .restore_prepared(&template.private_memory_bytes);
        self.pc = template.pc;
        self.last_diagnostic = None;
        Ok(())
    }
    /// Prepare a reset runtime for nonblocking retention by a runtime pool.
    ///
    /// Call after `reset_from_runtime_template`. Active invocation owners are
    /// removed before measuring idle storage. Failure means the caller must
    /// discard this runtime; it never changes a completed execution's outcome.
    pub fn try_retain_cache_allocations(&mut self) -> bool {
        if self.contract_debug.is_some()
            || self.last_diagnostic.is_some()
            || !matches!(self.constraints.allocated_bytes(), Ok(0))
            || !matches!(self.mem_log.allocated_bytes(), Ok(0))
            || !matches!(self.trace_log.allocated_bytes(), Ok(0))
            || !matches!(self.step_log.allocated_bytes(), Ok(0))
            || !matches!(self.delta_trace.allocated_bytes(), Ok(0))
            || !matches!(self.pc_trace.allocated_bytes(), Ok(0))
        {
            return false;
        }
        self.host = None;
        self.active_cycle_budget = None;
        self.contract_return_stack.compact_for_cache();
        let Some(log) = self.reg_log.as_ref() else {
            return false;
        };
        if self
            .memory
            .allocation_budget()
            .is_some_and(|budget| !log.belongs_to(budget))
        {
            return false;
        }
        if log.lock().capacity() != 0 {
            let Ok(replacement) = zk::SharedRegLog::try_new(self.memory.allocation_budget()) else {
                return false;
            };
            self.reg_log = Some(replacement);
        }
        if !self.memory.prepare_for_cache() {
            return false;
        }
        self.cache_reservation.set_known_bytes(0);
        self.cache_reservation.try_retain()
            && self
                .reg_log
                .as_mut()
                .is_some_and(zk::SharedRegLog::try_retain)
            && self.memory.try_retain()
            && self.registers.try_retain()
            && self.private_memory_bytes.try_retain()
            && self.contract_return_stack.try_retain()
            && self
                .call_layouts
                .as_ref()
                .is_none_or(call_runtime::CallLayouts::try_retain)
            && self
                .contract_interface
                .as_ref()
                .is_none_or(|value| value.try_retain())
            && self.literal_table.try_retain()
            && self
                .predecoded
                .as_ref()
                .is_none_or(|value| value.try_retain())
            && self
                .prepared
                .as_ref()
                .is_none_or(|value| value.try_retain())
    }

    /// Transfer a uniquely owned pooled runtime back into active execution.
    ///
    /// Shared immutable program allocations remain charged to retention while
    /// borrowed. Invocation scratch storage is reported as unmeasured active
    /// ownership until reset, so it cannot be mistaken for a complete heap cap.
    pub fn activate_cached_runtime(&mut self) {
        self.cache_reservation.mark_unmeasured();
        if let Some(log) = &mut self.reg_log {
            log.activate();
        }
        self.memory.activate_cache_accounting();
        self.registers.make_active();
        self.private_memory_bytes.make_active();
        self.contract_return_stack.make_active();
        self.set_host(DefaultHost::default());
    }
    /// Get the value of a general-purpose register.
    pub fn register(&self, idx: usize) -> u64 {
        self.registers.get(idx)
    }
    /// Reject a private-tagged register before its value crosses a public host boundary.
    ///
    /// Hosts must call this for syscall registers and other register values they expose outside the
    /// VM. Contract results use [`Self::public_call_result_word`]. Non-ZK programs have no private register tags and therefore always pass this check.
    ///
    /// # Errors
    /// Returns [`VMError::PrivacyViolation`] when `idx` contains a private value in ZK mode.
    pub fn ensure_public_register(&self, idx: usize) -> Result<(), VMError> {
        if self.zk_mode && self.registers.tag(idx) {
            return Err(VMError::PrivacyViolation);
        }
        Ok(())
    }
    /// Reject a private-tagged pointer or a TLV envelope overlapping private
    /// guest memory before the envelope crosses a public host boundary.
    ///
    /// This validates the complete pointer-ABI envelope as well as the
    /// register tag. It is intended for pointer-valued syscall arguments; a
    /// scalar syscall argument should use [`Self::ensure_public_register`].
    ///
    /// # Errors
    /// Returns a structured VM error when the register is private, the TLV is
    /// invalid, or any byte in the envelope remains private.
    pub fn ensure_public_tlv_register(&self, idx: usize) -> Result<(), VMError> {
        self.ensure_public_register(idx)?;
        self.validate_tlv(self.registers.get(idx)).map(|_| ())
    }
    /// Set the value of a general-purpose register.
    pub fn set_register(&mut self, idx: usize, value: u64) {
        self.registers.set(idx, value);
    }
    /// Request a graceful halt after the current instruction.
    pub fn request_exit(&mut self) {
        self.halted = true;
    }
    /// Request an abort and mark the run as failed.
    pub fn request_abort(&mut self) {
        self.halted = true;
        self.constraint_failed = true;
        self.contract_abort_error = None;
    }
    /// Request an application-level abort with a declared contract error code.
    pub fn request_contract_abort(
        &mut self,
        contract: String,
        name: String,
        error_type: String,
        schema_hash: [u8; 32],
        code: u32,
        message: Option<String>,
    ) {
        self.halted = true;
        self.constraint_failed = true;
        self.contract_abort_error = Some(VMError::ContractAbort {
            contract: contract.into_boxed_str(),
            name,
            error_type,
            schema_hash,
            code,
            message: message.map(String::into_boxed_str),
        });
    }
    /// Get a copy of a vector register (128-bit value as four 32-bit lanes).
    pub fn vector_register(&self, idx: usize) -> [u32; 4] {
        let stride = self.vector_length.max(1);
        let start = Self::VECTOR_BASE + idx * stride;
        let mut out = [0u32; 4];
        if start >= 256 {
            return out;
        }
        let lanes = stride.min(4).min(256 - start);
        for (lane, slot) in out.iter_mut().enumerate().take(lanes) {
            *slot = self.registers.get(start + lane) as u32;
        }
        out
    }
    /// Set the contents of a vector register.
    pub fn set_vector_register(&mut self, idx: usize, values: [u32; 4]) {
        let stride = self.vector_length.max(1);
        let start = Self::VECTOR_BASE + idx * stride;
        if start >= 256 {
            return;
        }
        let lanes = stride.min(4).min(256 - start);
        for (lane, value) in values.iter().enumerate().take(lanes) {
            self.registers.set(start + lane, u64::from(*value));
        }
    }
    /// Maximum vector lanes supported by hardware.
    pub fn max_vector_lanes(&self) -> usize {
        self.max_vector_lanes
    }
    /// Current logical vector length.
    pub fn vector_length(&self) -> usize {
        self.vector_length
    }
    /// Replace the host environment used for syscalls.
    pub fn set_host<H: IVMHost + Send + Sync + 'static>(&mut self, host: H) {
        self.host = Some(Box::new(crate::runtime::SyscallDispatcher::new(host)));
    }
    /// Get the remaining gas after execution.
    pub fn remaining_gas(&self) -> u64 {
        self.gas_remaining
            .saturating_add(self.syscall_gas_reserve)
            .min(self.gas_limit)
    }
    /// Gas currently reserved for a prepared syscall, or zero for direct host calls.
    #[must_use]
    pub fn syscall_reserved_gas(&self) -> u64 {
        self.syscall_gas_reserve
    }
    /// Return the active staged-syscall accounting context, if any.
    #[must_use]
    pub const fn staged_syscall_context(&self) -> Option<&StagedSyscallContext> {
        self.staged_syscall.as_ref()
    }
    /// Return the most recently completed staged-syscall accounting context.
    #[must_use]
    pub const fn last_staged_syscall_context(&self) -> Option<&StagedSyscallContext> {
        self.last_staged_syscall.as_ref()
    }
    /// Debit one staged syscall phase immediately before the corresponding work begins.
    ///
    /// If the phase is unaffordable, no gas is deducted for it and the method returns
    /// [`VMError::SyscallOutOfGas`]. Gas charged by earlier completed phases remains consumed.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::SyscallMeteringModeMismatch`] outside an active
    /// staged syscall, [`VMError::GasCostOverflow`] on accounting overflow, or
    /// [`VMError::SyscallOutOfGas`] when the next phase cannot be afforded.
    pub fn charge_syscall_stage(
        &mut self,
        phase: SyscallMeteringPhase,
        gas: u64,
    ) -> Result<(), VMError> {
        let syscall = self
            .staged_syscall
            .as_ref()
            .map(StagedSyscallContext::syscall)
            .ok_or(VMError::SyscallMeteringModeMismatch { syscall: 0 })?;
        if self.gas_remaining < gas {
            return Err(VMError::SyscallOutOfGas {
                syscall,
                phase: phase.tag(),
            });
        }
        self.staged_syscall
            .as_mut()
            .expect("staged syscall presence checked above")
            .record_charge(phase, gas)?;
        self.gas_remaining -= gas;
        Ok(())
    }
    /// Mark the active staged call as a recoverable failure.
    ///
    /// Handlers call this before returning `Ok(0)` with a stable failure code in
    /// `r11`. The executor otherwise records successful completion.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::SyscallMeteringModeMismatch`] outside an active staged syscall.
    pub fn mark_staged_syscall_recoverable_failure(&mut self) -> Result<(), VMError> {
        let context = self
            .staged_syscall
            .as_mut()
            .ok_or(VMError::SyscallMeteringModeMismatch { syscall: 0 })?;
        if context.completion().is_some() {
            return Err(VMError::SyscallMeteringModeMismatch {
                syscall: context.syscall(),
            });
        }
        context.finish(SyscallCompletion::RecoverableFailure);
        Ok(())
    }
    /// Replace the gas available to nested execution without releasing the
    /// current syscall's pre-debited reserve.
    pub fn set_syscall_spendable_gas(&mut self, remaining: u64) {
        let spendable_cap = self.gas_limit.saturating_sub(self.syscall_gas_reserve);
        self.gas_remaining = remaining.min(spendable_cap);
    }
    /// Access the underlying host as a type-erased value to support downcasting.
    pub fn host_mut_any(&mut self) -> Option<&mut dyn std::any::Any> {
        self.host.as_deref_mut().map(|h| h.as_any())
    }
    /// Get the canonical hash of the loaded program image.
    ///
    /// Self-describing contract programs use the domain-separated full-artifact hash, while raw
    /// code loaded through [`Self::load_code`] hashes that raw instruction image.
    pub fn code_hash(&self) -> [u8; 32] {
        self.code_hash
    }
    /// Access the log of memory events collected during the last run.
    pub fn memory_log(&self) -> &[MemEvent] {
        &self.mem_log.events
    }
    /// Capture detached diagnostics through the original State/cache allocation pool.
    ///
    /// The register logger stays locked during complete demand calculation and
    /// copying. Its source remains unchanged; all refund callbacks run after the
    /// guard leaves. This is optional local diagnostic data, never proof admission.
    ///
    /// # Errors
    /// Refuses foreign parent custody, unavailable original credit, malformed
    /// internal trace geometry or physical allocation before publishing a copy.
    pub fn try_diagnostic_snapshot(
        &self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<zk::DiagnosticTraceSnapshot, VMError> {
        if self
            .memory
            .allocation_budget()
            .is_some_and(|original| !original.same_pool(budget))
        {
            return Err(VMError::HostUnavailable);
        }
        budget.with_deferred_refund_notifications(|_| {
            let empty = zk::RegLog::new(self.memory.allocation_budget());
            let register_log = self.reg_log.as_ref().map(zk::SharedRegLog::lock);
            let register_log = register_log.as_deref().unwrap_or(&empty);
            let source = zk::DiagnosticTraceSource {
                registers: zk::DiagnosticRegisterSource::Deltas(&self.trace_log),
                constraints: &self.constraints.list,
                memory_events: &self.mem_log.events,
                register_events: register_log.as_slice(),
                steps: self.step_log.as_slice(),
            };
            let plan = source.allocation_plan()?;
            let mut parent = crate::execution_memory::ExecutionMemoryLease::reserve(budget, plan)
                .map_err(VMError::AllocationDeferred)?;
            source.try_snapshot_from_parent(&mut parent)
        })
    }
    fn finish_digest(hasher: Sha256) -> [u8; 32] {
        hasher.finalize().into()
    }
    fn hash_pc_trace(entries: &[u64]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:pc-trace:v1");
        hasher.update((entries.len() as u64).to_le_bytes());
        for pc in entries {
            hasher.update(pc.to_le_bytes());
        }
        Self::finish_digest(hasher)
    }
    fn hash_delta_trace(entries: &zk::DeltaTraceLog) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:delta-trace:v1");
        hasher.update((entries.len() as u64).to_le_bytes());
        for entry in entries.entries() {
            hasher.update(entry.pc.to_le_bytes());
            hasher.update((entry.changes.len() as u64).to_le_bytes());
            for (index, value, tag) in entry.changes {
                hasher.update((*index as u64).to_le_bytes());
                hasher.update(value.to_le_bytes());
                hasher.update([u8::from(*tag)]);
            }
        }
        Self::finish_digest(hasher)
    }
    fn hash_constraints(constraints: &[Constraint]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:constraints:v1");
        hasher.update((constraints.len() as u64).to_le_bytes());
        for constraint in constraints {
            match *constraint {
                Constraint::Zero { reg, cycle } => {
                    hasher.update([0]);
                    hasher.update((reg as u64).to_le_bytes());
                    hasher.update(cycle.to_le_bytes());
                }
                Constraint::Eq { reg1, reg2, cycle } => {
                    hasher.update([1]);
                    hasher.update((reg1 as u64).to_le_bytes());
                    hasher.update((reg2 as u64).to_le_bytes());
                    hasher.update(cycle.to_le_bytes());
                }
                Constraint::Range { reg, bits, cycle } => {
                    hasher.update([2]);
                    hasher.update((reg as u64).to_le_bytes());
                    hasher.update([bits]);
                    hasher.update(cycle.to_le_bytes());
                }
            }
        }
        Self::finish_digest(hasher)
    }
    fn update_path_digest(hasher: &mut Sha256, path: &[[u8; 32]]) {
        hasher.update((path.len() as u64).to_le_bytes());
        for sibling in path {
            hasher.update(sibling);
        }
    }
    fn hash_memory_log(events: &[MemEvent]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:memory-log:v1");
        hasher.update((events.len() as u64).to_le_bytes());
        for event in events {
            match event {
                MemEvent::Load {
                    addr,
                    value,
                    size,
                    path,
                    root,
                } => {
                    hasher.update([0]);
                    hasher.update(addr.to_le_bytes());
                    hasher.update(value.to_le_bytes());
                    hasher.update([*size]);
                    Self::update_path_digest(&mut hasher, path);
                    hasher.update(root.as_ref());
                }
                MemEvent::Store {
                    addr,
                    value,
                    size,
                    path,
                    root,
                } => {
                    hasher.update([1]);
                    hasher.update(addr.to_le_bytes());
                    hasher.update(value.to_le_bytes());
                    hasher.update([*size]);
                    Self::update_path_digest(&mut hasher, path);
                    hasher.update(root.as_ref());
                }
            }
        }
        Self::finish_digest(hasher)
    }
    fn hash_register_log(events: &[zk::RegEvent]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:register-log:v1");
        hasher.update((events.len() as u64).to_le_bytes());
        for event in events {
            match event {
                zk::RegEvent::Read {
                    index,
                    value,
                    tag,
                    path,
                    root,
                } => {
                    hasher.update([0]);
                    hasher.update((*index as u64).to_le_bytes());
                    hasher.update(value.to_le_bytes());
                    hasher.update([u8::from(*tag)]);
                    Self::update_path_digest(&mut hasher, path);
                    hasher.update(root.as_ref());
                }
                zk::RegEvent::Write {
                    index,
                    value,
                    tag,
                    path,
                    root,
                } => {
                    hasher.update([1]);
                    hasher.update((*index as u64).to_le_bytes());
                    hasher.update(value.to_le_bytes());
                    hasher.update([u8::from(*tag)]);
                    Self::update_path_digest(&mut hasher, path);
                    hasher.update(root.as_ref());
                }
            }
        }
        Self::finish_digest(hasher)
    }
    fn hash_step_log(steps: &[zk::StepEntry]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ivm-summary:step-log:v1");
        hasher.update((steps.len() as u64).to_le_bytes());
        for step in steps {
            hasher.update(step.pc.to_le_bytes());
            hasher.update(step.reg_root.as_ref());
            hasher.update(step.mem_root.as_ref());
        }
        Self::finish_digest(hasher)
    }
    /// Count trace/log events priced by the execution-summary syscall without
    /// materializing or hashing the summary.
    pub(crate) fn execution_summary_event_count(&self) -> u64 {
        let register_log = self.proof_register_log_handle();
        u64::try_from(self.pc_trace.as_slice().len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(self.delta_trace.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(self.trace_log.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(self.constraints.list.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(self.mem_log.events.len()).unwrap_or(u64::MAX))
            .saturating_add(
                u64::try_from(
                    register_log
                        .as_ref()
                        .map_or(0, |log| log.lock().as_slice().len()),
                )
                .unwrap_or(u64::MAX),
            )
            .saturating_add(u64::try_from(self.step_log.as_slice().len()).unwrap_or(u64::MAX))
    }
    /// Build a deterministic, self-reported summary of the current execution state.
    ///
    /// The returned hashes are not an independently verifiable proof or an
    /// authenticated attestation of execution.
    pub fn execution_summary(&mut self) -> ExecutionSummary {
        let register_log = self.proof_register_log_handle();
        let empty = zk::RegLog::new(self.memory.allocation_budget());
        let register_log = register_log.as_ref().map(zk::SharedRegLog::lock);
        let register_log = register_log.as_deref().unwrap_or(&empty);
        let output = self.memory.read_output();
        let mut output_hasher = Sha256::new();
        output_hasher.update(b"ivm-summary:output:v1");
        output_hasher.update((output.len() as u64).to_le_bytes());
        output_hasher.update(output);
        let gas_remaining = self.remaining_gas();
        ExecutionSummary {
            version: EXECUTION_SUMMARY_VERSION_V1,
            code_hash: self.code_hash,
            final_register_root: self.register_root(),
            final_memory_root: *self.memory.current_root().as_ref(),
            output_hash: Self::finish_digest(output_hasher),
            pc_trace_hash: Self::hash_pc_trace(self.pc_trace.as_slice()),
            delta_trace_hash: Self::hash_delta_trace(&self.delta_trace),
            register_trace_hash: Self::hash_delta_trace(&self.trace_log),
            constraint_hash: Self::hash_constraints(&self.constraints.list),
            memory_log_hash: Self::hash_memory_log(&self.mem_log.events),
            register_log_hash: Self::hash_register_log(register_log.as_slice()),
            step_log_hash: Self::hash_step_log(self.step_log.as_slice()),
            cycles: self.cycles,
            max_cycles: self.max_cycles,
            gas_used: self.gas_limit.saturating_sub(gas_remaining),
            gas_remaining,
            pc_trace_len: self.pc_trace.as_slice().len() as u64,
            delta_trace_len: self.delta_trace.len() as u64,
            register_trace_len: self.trace_log.len() as u64,
            constraint_len: self.constraints.list.len() as u64,
            memory_log_len: self.mem_log.events.len() as u64,
            register_log_len: register_log.as_slice().len() as u64,
            step_log_len: self.step_log.as_slice().len() as u64,
            zk_mode: self.zk_mode,
            halted: self.halted,
            constraint_failed: self.constraint_failed,
        }
    }
    /// Get the Merkle root of the register file.
    pub fn register_root(&self) -> [u8; 32] {
        *self.registers.merkle_root().as_ref()
    }
    pub fn trace_mode(&self) -> TraceMode {
        self.trace_mode
    }
    pub fn set_trace_mode(&mut self, mode: TraceMode) {
        self.proof_state_epoch = self.proof_state_epoch.wrapping_add(1);
        self.trace_mode = mode;
        self.pc_trace.clear();
        self.delta_trace.scrub();
    }
    pub fn trace_pcs(&self) -> &[u64] {
        self.pc_trace.as_slice()
    }
    pub fn delta_register_trace(&self) -> &zk::DeltaTraceLog {
        &self.delta_trace
    }
    /// Independently capture immutable runtime observations under this VM's original pool.
    ///
    /// Checkpoint clones retain the same charged backing. Admission or allocator
    /// refusal leaves the VM and any existing capture unchanged.
    pub fn try_runtime_trace_capture(&self) -> Result<zk::RuntimeTraceCapture, VMError> {
        self.check_trace_storage_owner()?;
        zk::RuntimeTraceCapture::try_capture(&self.pc_trace, &self.delta_trace)
    }
    /// Access per-cycle Merkle roots collected during the last run.
    pub fn step_log(&self) -> &[zk::StepEntry] {
        self.step_log.as_slice()
    }
    /// Access constraints logged during execution.
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints.list
    }
    #[inline]
    pub(crate) fn debit_gas(&mut self, gas: u64) -> Result<(), VMError> {
        if unlikely(self.gas_remaining < gas) {
            return Err(VMError::OutOfGas);
        }
        if let Some(recorder) = &mut self.native_packets {
            recorder.gas_debit(self.gas_remaining, gas)?;
        }
        self.gas_remaining -= gas;
        Ok(())
    }
    #[inline]
    fn validate_syscall_privacy(&self, number: u32) -> Result<(), VMError> {
        if matches!(
            number,
            crate::syscalls::SYSCALL_GET_PRIVATE_INPUT
                | crate::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM
        ) && !self.zk_mode
        {
            return Err(VMError::PrivacyViolation);
        }
        if number == crate::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM {
            // This is the sole host boundary allowed to consume opaque typed
            // private numeric pointers. Exact pointer and canonical payload
            // validation happens after the reserved quote is debited.
            if !self.registers.tag(10) || !self.registers.tag(11) {
                return Err(VMError::PrivacyViolation);
            }
            return Ok(());
        }
        if self.zk_mode {
            for &register in syscall_public_input_registers(number) {
                if self.registers.tag(register)
                    || self.syscall_argument_references_private_memory(self.registers.get(register))
                {
                    return Err(VMError::PrivacyViolation);
                }
            }
        }
        Ok(())
    }
    /// Snapshot and clear output-only registers before entering the host. Registers that overlap
    /// the declared input window are already proven public by `validate_syscall_privacy` and must
    /// remain intact for the host call. This prevents a successful no-write or partial-write host
    /// from declassifying stale private register contents.
    #[inline]
    fn sanitize_syscall_output_privacy(&mut self, number: u32) -> SavedSyscallOutputRegisters {
        let mut saved = SavedSyscallOutputRegisters::default();
        if !self.zk_mode {
            return saved;
        }
        let inputs = syscall_public_input_registers(number);
        for &register in syscall_public_output_registers(number) {
            if !inputs.contains(&register) {
                debug_assert!(saved.len < saved.registers.len());
                saved.registers[saved.len] = register;
                saved.values[saved.len] = self.registers.get(register);
                saved.private[saved.len] = self.registers.tag(register);
                saved.len += 1;
                self.registers.set(register, 0);
                self.registers.set_tag(register, false);
            }
        }
        saved
    }
    #[inline]
    fn restore_syscall_output_privacy(&mut self, saved: SavedSyscallOutputRegisters) {
        for index in 0..saved.len {
            let register = saved.registers[index];
            self.registers.set(register, saved.values[index]);
            self.registers.set_tag(register, saved.private[index]);
        }
    }
    #[inline]
    fn finalize_syscall_output_privacy(&mut self, number: u32) -> Result<(), VMError> {
        if !self.zk_mode {
            return Ok(());
        }
        if number == crate::syscalls::SYSCALL_GET_PRIVATE_INPUT {
            self.registers.set_tag(10, true);
            return Ok(());
        }
        if number == crate::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM {
            // A successful full-width Pedersen commitment is the explicit
            // declassification boundary. No intermediate projection is
            // written to registers or guest-visible memory.
            self.registers.set_tag(10, false);
            return Ok(());
        }
        for &register in syscall_public_output_registers(number) {
            if self.registers.tag(register) {
                return Err(VMError::PrivacyViolation);
            }
        }
        Ok(())
    }
    #[inline]
    pub(crate) fn execute_syscall(
        &mut self,
        host: &mut dyn IVMHost,
        number: u32,
    ) -> Result<(), VMError> {
        self.execute_syscall_with_register_log(host, number, None)
    }

    pub(crate) fn execute_syscall_with_register_log(
        &mut self,
        host: &mut dyn IVMHost,
        number: u32,
        prepared_log: Option<&register_logging::PreparedHostRegisterLog>,
    ) -> Result<(), VMError> {
        if crate::syscalls::is_koto_test_syscall(number) && !self.allow_koto_test_syscalls {
            return Err(VMError::UnknownSyscall(number));
        }
        if self.contract_interface.is_none() {
            let policy = self.syscall_policy();
            if crate::syscalls::is_syscall_allowed(policy, number)
                && !crate::syscalls::is_generic_program_syscall_allowed(policy, number)
            {
                return Err(VMError::GenericSyscallNotAllowed { syscall: number });
            }
        }
        let metering = resolve_syscall_metering(host, self.syscall_policy(), number)?;
        let _register_batch = self.prepare_syscall_register_events(number)?;
        let admitted_log;
        let prepared_log = match prepared_log {
            Some(prepared) => prepared,
            None => {
                admitted_log = self.prepare_host_register_log()?;
                &admitted_log
            }
        };
        match metering {
            SyscallMetering::Reserved => self.execute_reserved_syscall(host, number, prepared_log),
            SyscallMetering::Staged => self.execute_staged_syscall(host, number, prepared_log),
        }
    }
    #[inline]
    fn execute_reserved_syscall(
        &mut self,
        host: &mut dyn IVMHost,
        number: u32,
        prepared_log: &register_logging::PreparedHostRegisterLog,
    ) -> Result<(), VMError> {
        debug_assert_eq!(self.syscall_gas_reserve, 0);
        debug_assert!(self.staged_syscall.is_none());
        self.validate_syscall_privacy(number)?;
        let saved_outputs = self.sanitize_syscall_output_privacy(number);
        let prepare_isolation = self.isolate_host_register_log(prepared_log)?;
        let prepared = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Host code may create or inspect unrelated VMs on this thread.
            // Mask the invocation logger so those accesses cannot contaminate
            // or disclose values through this VM's proof log.
            let _host_logger_mask = zk::RegLoggerGuard::mask();
            host.prepare_syscall(number, self)
        })) {
            Ok(prepared) => prepared,
            Err(payload) => {
                {
                    let _host_logger_mask = zk::RegLoggerGuard::mask();
                    self.restore_syscall_output_privacy(saved_outputs);
                }
                self.abort_host_register_log_isolation(prepare_isolation);
                std::panic::resume_unwind(payload);
            }
        };
        self.restore_host_register_log(prepare_isolation)?;
        let quoted = match prepared {
            Ok(quoted) => quoted,
            Err(error) => {
                self.restore_syscall_output_privacy(saved_outputs);
                let (metered_gas, source) = error.split_metered();
                if let Some(gas) = metered_gas {
                    self.debit_gas(gas)?;
                }
                return Err(source);
            }
        };
        if let Err(error) = self.debit_gas(quoted) {
            self.restore_syscall_output_privacy(saved_outputs);
            return Err(error);
        }
        self.syscall_gas_reserve = quoted;
        let register_values_before = self.registers.snapshot();
        let register_tags_before = self.registers.snapshot_tags();
        let syscall_isolation = match self.isolate_host_register_log(prepared_log) {
            Ok(isolation) => isolation,
            Err(error) => {
                self.syscall_gas_reserve = 0;
                return Err(error);
            }
        };
        let host_result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _host_logger_mask = zk::RegLoggerGuard::mask();
            host.syscall(number, self)
        })) {
            Ok(host_result) => host_result,
            Err(payload) => {
                {
                    let _host_logger_mask = zk::RegLoggerGuard::mask();
                    self.restore_syscall_output_privacy(saved_outputs);
                }
                self.syscall_gas_reserve = 0;
                self.abort_host_register_log_isolation(syscall_isolation);
                std::panic::resume_unwind(payload);
            }
        };
        match self.restore_host_register_log(syscall_isolation) {
            Ok(true) => {
                self.record_host_register_changes(&register_values_before, &register_tags_before);
            }
            Ok(false) => {}
            Err(error) => {
                self.syscall_gas_reserve = 0;
                return Err(error);
            }
        }
        let (actual, outcome) = match host_result {
            Ok(actual) => (actual, Ok(())),
            Err(error) => {
                let (metered_gas, source) = error.split_metered();
                // A host that cannot provide a tighter error cost must not
                // receive a refund for work it may already have performed.
                // Consuming the pre-debited quote is the deterministic,
                // fail-closed fallback; explicitly metered errors still refund
                // any unused part of the quote.
                (metered_gas.unwrap_or(quoted), Err(source))
            }
        };
        self.syscall_gas_reserve = 0;
        if actual > quoted {
            self.gas_remaining = 0;
            return Err(VMError::SyscallGasQuoteExceeded { quoted, actual });
        }
        self.gas_remaining = self
            .gas_remaining
            .saturating_add(quoted - actual)
            .min(self.gas_limit);
        if outcome.is_ok() {
            self.finalize_syscall_output_privacy(number)?;
        }
        outcome
    }
    #[inline]
    fn execute_staged_syscall(
        &mut self,
        host: &mut dyn IVMHost,
        number: u32,
        prepared_log: &register_logging::PreparedHostRegisterLog,
    ) -> Result<(), VMError> {
        debug_assert_eq!(self.syscall_gas_reserve, 0);
        if self.staged_syscall.is_some() {
            return Err(VMError::SyscallMeteringModeMismatch { syscall: number });
        }
        self.staged_syscall = Some(StagedSyscallContext::new(number));
        if let Err(error) =
            self.charge_syscall_stage(SyscallMeteringPhase::Entry, STAGED_SYSCALL_ENTRY_GAS)
        {
            self.finish_staged_syscall(SyscallCompletion::Trap);
            return Err(error);
        }
        // Privacy validation is bounded syscall-entry work. Debit the entry
        // phase first so a private or stack-backed pointer cannot trigger even
        // that validation for free or take precedence over entry-phase OOG.
        if let Err(error) = self.validate_syscall_privacy(number) {
            self.finish_staged_syscall(SyscallCompletion::Trap);
            return Err(error);
        }
        self.sanitize_syscall_output_privacy(number);
        let register_values_before = self.registers.snapshot();
        let register_tags_before = self.registers.snapshot_tags();
        let syscall_isolation = match self.isolate_host_register_log(prepared_log) {
            Ok(isolation) => isolation,
            Err(error) => {
                self.finish_staged_syscall(SyscallCompletion::Trap);
                return Err(error);
            }
        };
        let host_result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _host_logger_mask = zk::RegLoggerGuard::mask();
            host.syscall(number, self)
        })) {
            Ok(host_result) => host_result,
            Err(payload) => {
                self.finish_staged_syscall(SyscallCompletion::Trap);
                self.abort_host_register_log_isolation(syscall_isolation);
                std::panic::resume_unwind(payload);
            }
        };
        match self.restore_host_register_log(syscall_isolation) {
            Ok(true) => {
                self.record_host_register_changes(&register_values_before, &register_tags_before);
            }
            Ok(false) => {}
            Err(error) => {
                self.finish_staged_syscall(SyscallCompletion::Trap);
                return Err(error);
            }
        }
        match host_result {
            Ok(0) => {
                let completion = self
                    .staged_syscall
                    .as_ref()
                    .and_then(StagedSyscallContext::completion)
                    .unwrap_or(SyscallCompletion::Success);
                if completion == SyscallCompletion::Trap {
                    self.finish_staged_syscall(SyscallCompletion::Trap);
                    return Err(VMError::SyscallMeteringModeMismatch { syscall: number });
                }
                self.finish_staged_syscall(completion);
                self.finalize_syscall_output_privacy(number)?;
                Ok(())
            }
            Ok(_actual) => {
                self.finish_staged_syscall(SyscallCompletion::Trap);
                Err(VMError::SyscallMeteringModeMismatch { syscall: number })
            }
            Err(error) => {
                let (metered_gas, source) = error.split_metered();
                self.finish_staged_syscall(SyscallCompletion::Trap);
                if metered_gas.is_some() {
                    Err(VMError::SyscallMeteringModeMismatch { syscall: number })
                } else {
                    Err(source)
                }
            }
        }
    }
    fn finish_staged_syscall(&mut self, completion: SyscallCompletion) {
        if let Some(mut context) = self.staged_syscall.take() {
            if context.completion().is_none() || completion == SyscallCompletion::Trap {
                context.finish(completion);
            }
            self.last_staged_syscall = Some(context);
        }
    }
    fn record_host_register_changes(&self, values_before: &[u64; 256], tags_before: &[bool; 256]) {
        let values_after = self.registers.snapshot();
        let tags_after = self.registers.snapshot_tags();
        for index in 1..values_after.len() {
            if values_before[index] != values_after[index]
                || tags_before[index] != tags_after[index]
            {
                self.registers.record_write_proof(index);
            }
        }
    }
    /// Execute the loaded program starting at the current `pc`.
    ///
    /// This is the heart of the VM: a classic fetch‑decode‑execute loop. For each instruction we
    /// deduct gas, perform the operation and then advance the program counter by one 32-bit word.
    /// When zero-knowledge trace collection is active the
    /// register state is logged on every cycle so that a prover can later reconstruct a trace. The
    /// loop terminates on `HALT` or when an error is encountered.
    pub fn run(&mut self) -> Result<(), VMError> {
        self.last_diagnostic = None;
        let Some(mut host) = self.host.take() else {
            return Err(VMError::HostUnavailable);
        };
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.run_with_host_ref(host.as_mut(), None)
        }));
        self.host = Some(host);
        match outcome {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    /// Execute the loaded program using a borrowed host without storing it in the VM.
    pub fn run_with_host(&mut self, host: &mut dyn IVMHost) -> Result<(), VMError> {
        self.run_with_host_ref(host, None)
    }
    /// Run with a prepaid, local-only diagnostic step recorder.
    ///
    /// Captured register snapshots can contain private values. The recorder
    /// does not witness all memory or host accesses and cannot authorize an
    /// execution proof or a consensus transaction.
    pub fn run_with_host_diagnostic_steps(
        &mut self,
        host: &mut dyn IVMHost,
        recorder: &mut DiagnosticStepRecorder,
    ) -> Result<(), VMError> {
        self.last_diagnostic = None;
        recorder.begin_run()?;
        let result = self.run_with_host_ref(host, Some(recorder));
        if recorder.end().is_none() {
            recorder.finish_run(DiagnosticRunEnd {
                state: self.diagnostic_step_state(),
                padding_cycles: 0,
                outcome: result.as_ref().map(|_| ()).map_err(Self::classify_trap),
            });
        }
        result
    }
    /// Run with separate prepaid local step and ordered memory-byte diagnostics.
    ///
    /// This deliberately incomplete diagnostic pair cannot authorize a proof
    /// or a transaction. The memory recorder is detached even if a host panics.
    pub fn run_with_host_diagnostic_steps_and_memory(
        &mut self,
        host: &mut dyn IVMHost,
        steps: &mut DiagnosticStepRecorder,
        memory_accesses: &DiagnosticMemoryAccessRecorder,
    ) -> Result<(), VMError> {
        self.last_diagnostic = None;
        steps.begin_run()?;
        memory_accesses.begin_run(self.zk_mode)?;
        self.memory
            .capture_diagnostic_initial_image(memory_accesses)?;
        self.memory
            .install_diagnostic_access_recorder(memory_accesses.shared())?;
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.run_with_host_diagnostic_steps(host, steps)
        }));
        self.memory.clear_diagnostic_access_recorder();
        match outcome {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    /// Run with the caller's single finite allowance for completed architectural cycles.
    ///
    /// Reusing a VM or running another Batch segment does not replenish `budget`.
    /// Core owns the signed-source binding and must use ordinary `run_with_host`
    /// for separately executed trigger callbacks. Gas and per-program cycle checks
    /// remain independent. A refused shared reservation returns `ExceededMaxCycles`.
    pub fn run_with_host_and_cycle_budget(
        &mut self,
        host: &mut dyn IVMHost,
        budget: &VmCycleBudget,
    ) -> Result<(), VMError> {
        self.run_with_host_and_shared_cycles(host, Arc::clone(&budget.shared))
    }
    /// Run a nested VM with the active parent's exact cycle allowance, if present.
    ///
    /// Hosts must use this for nested contract dispatch rather than creating a new
    /// allowance or deriving one from a remaining-cycle scalar.
    pub fn run_with_host_and_parent_cycle_budget(
        &mut self,
        host: &mut dyn IVMHost,
        parent: &IVM,
    ) -> Result<(), VMError> {
        match &parent.active_cycle_budget {
            Some(shared) => self.run_with_host_and_shared_cycles(host, Arc::clone(shared)),
            None => self.run_with_host(host),
        }
    }
    fn run_with_host_and_shared_cycles(
        &mut self,
        host: &mut dyn IVMHost,
        shared: Arc<SharedVmCycleBudget>,
    ) -> Result<(), VMError> {
        self.last_diagnostic = None;
        if self
            .active_cycle_budget
            .as_ref()
            .is_some_and(|active| !Arc::ptr_eq(active, &shared))
        {
            // Rebinding a runtime retained by another active source is a local
            // host ownership error, not deterministic capacity exhaustion.
            shared.state.lock().closed = true;
            if let Some(active) = &self.active_cycle_budget {
                active.state.lock().closed = true;
            }
            return Err(VMError::HostUnavailable);
        }
        shared.ensure_healthy()?;
        let previous = self.active_cycle_budget.replace(shared);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| self.run_with_host(host)));
        self.active_cycle_budget = previous;
        match result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    #[inline]
    fn commit_memory_after_run_if_needed(&mut self) {
        if self.zk_trace_collection_enabled() {
            self.memory.commit();
        }
    }
    fn diagnostic_step_state(&self) -> DiagnosticStepState {
        DiagnosticStepState {
            pc: self.pc,
            gas_remaining: self.gas_remaining,
            cycles: self.cycles,
            vector_length: self.vector_length,
            halted: self.halted,
            constraint_failed: self.constraint_failed,
            registers: self.registers.snapshot(),
            tags: self.registers.snapshot_tags(),
        }
    }
    fn run_with_host_ref(
        &mut self,
        host: &mut dyn IVMHost,
        mut recorder: Option<&mut DiagnosticStepRecorder>,
    ) -> Result<(), VMError> {
        self.last_diagnostic = None;
        // Keep a local reference through host callbacks/lifecycle changes. This
        // owner never comes from program bytes or a warmed runtime template.
        let cycle_budget = self.active_cycle_budget.clone();
        if let Some(budget) = &cycle_budget {
            budget.ensure_healthy()?;
        }
        // Admit the next logger before changing guest state or clearing the
        // preceding invocation. Invalid detached custody is severed without allocation.
        self.prepare_invocation_register_log()?;
        // Select this invocation's policy from its configuration, never from
        // an outer VM's thread-local scope.
        let invocation_log = if self.zk_mode && self.zk_trace_enabled {
            self.reg_log.clone()
        } else {
            None
        };
        let _reg_logger_guard = zk::RegLoggerGuard::install(invocation_log);
        // Proof-facing accessors describe the most recent invocation. Clear
        // prior artifacts even when this run has tracing disabled.
        self.clear_zk_trace_logs();
        if !self.zk_mode && (self.registers.has_private() || !self.private_memory_bytes.is_empty())
        {
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation,
            ));
        }
        let invocation_trace = self.begin_trace_invocation()?;
        self.last_diagnostic = None;
        self.halted = false;
        self.constraint_failed = false;
        self.contract_abort_error = None;
        self.cycles = 0;
        // A run is one invocation. Never retain protected return state after a
        // prior trap or across a pooled-runtime reuse boundary.
        self.contract_return_stack.clear();
        self.contract_outer_return_pc = None;
        self.memory.call_frames.clear();
        let mut pending_step: Option<PendingDiagnosticStep> = None;
        let mut fault_position =
            iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization;
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pointer_policy_guard =
                PointerPolicyGuard::install(self.syscall_policy(), self.abi_version());
            self.begin_root_call(host)?;
            let mut last_logged_cycle = 0;
            let mut pending_cycles: Option<(u64, VmCycleReservation<'_>)> = None;
            let mut pending_register_batch = None;
            // Fetch-Decode-Execute loop
            loop {
                fault_position = iroha_data_model::executor::fault::IvmFaultPositionV1::Execute {
                    pc_offset: self.pc.saturating_sub(self.program_prefix_len),
                };
                if let Some((before, reservation)) = pending_cycles.take() {
                    reservation.complete(self.cycles.checked_sub(before))?;
                }
                if let Some(step) = pending_step.take() {
                    recorder
                        .as_deref_mut()
                        .expect("diagnostic step has recorder")
                        .finish_step(
                            step,
                            self.diagnostic_step_state(),
                            DiagnosticStepOutcome::Completed,
                        )?;
                }
                self.native_finish_step();
                drop(pending_register_batch.take());
                self.publish_trace_cycles(&invocation_trace, &mut last_logged_cycle)?;
                // Stop the loop if HALT was executed. When a cycle limit is set we
                // continue executing even after a failed assertion so the trace
                // length is independent of witness values.
                if unlikely(self.halted || (!self.zk_mode && self.constraint_failed)) {
                    break;
                }
                if unlikely(self.pc == self.memory.code_len()) {
                    return Err(VMError::MissingHalt);
                }
                if unlikely(self.max_cycles != 0 && self.cycles >= self.max_cycles) {
                    return Err(VMError::ExceededMaxCycles);
                }
                self.record_trace_prefetch(&invocation_trace)?;
                if let Some(recorder) = recorder.as_deref_mut() {
                    pending_step = Some(recorder.begin_step(self.diagnostic_step_state())?);
                    self.memory
                        .diagnostic_step_ordinal(recorder.records().len() as u64);
                }
                let fetched = self.fetch_instruction()?;
                let instr = fetched.inst;
                if let Some(step) = pending_step.as_mut() {
                    step.fetched(instr);
                }
                let length = WIDE_INSTRUCTION_LEN;
                let wide_op = fetched.wide_op;
                if crate::dev_env::decode_trace_enabled() {
                    eprintln!(
                        "pc=0x{pc:08x} instr=0x{w:08x} len={len}",
                        pc = self.pc,
                        w = instr,
                        len = WIDE_INSTRUCTION_LEN
                    );
                }
                let opcode_hi = (instr >> 24) as u8;
                if !instruction::wide::is_valid_opcode(wide_op) {
                    return Err(VMError::InvalidOpcode((instr & 0xFFFF) as u16));
                }
                // Determine the gas cost for this operation and deduct it.
                // Scale vector op costs by the current logical vector length.
                let cost = gas::cost_from_parts(fetched.base_gas, wide_op, self.vector_length)
                    .ok_or(VMError::InvalidOpcode((instr & 0xFFFF) as u16))?;
                if let Some(step) = pending_step.as_mut() {
                    step.priced(cost);
                }
                if unlikely(self.gas_remaining < cost) {
                    return Err(VMError::OutOfGas);
                }
                let prepared_host_log =
                    self.prepare_trace_instruction(&invocation_trace, instr, |vm| {
                        pending_register_batch =
                            Some(vm.prepare_instruction_register_events(instr)?);
                        // Shell, shared-cycle and native capture demand all precede
                        // base gas and execute under the same observation quota.
                        let prepared_host_log = matches!(
                            wide_op,
                            instruction::wide::system::SCALL | instruction::wide::system::SYSTEM
                        )
                        .then(|| vm.prepare_host_register_log())
                        .transpose()?;
                        if let Some(budget) = &cycle_budget {
                            let reservation =
                                budget.reserve(completed_instruction_cycles(wide_op))?;
                            pending_cycles = Some((vm.cycles, reservation));
                        }
                        vm.native_preflight_step(instr, cost)?;
                        Ok(prepared_host_log)
                    })?;
                self.gas_remaining -= cost;
                // Execute the instruction
                let opcode = instr & 0x7F;
                if crate::dev_env::decode_trace_enabled() {
                    eprintln!("[IVM] opcode_lo=0x{opcode:02x} opcode_hi=0x{opcode_hi:02x}");
                }
                // Dispatch via the canonical wide (8-bit opcode) instruction table. Classic
                // encodings are no longer executable; unknown opcodes trap with `InvalidOpcode`.
                match wide_op {
                    instruction::wide::system::GETGAS => {
                        let rd = instruction::wide::rd(instr);
                        self.registers.set(rd, self.gas_remaining);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::system::SCALL => {
                        let imm8 = instruction::wide::imm8(instr) as u8 as u32;
                        if !host_allows_syscall_masked(host, self.syscall_policy(), imm8) {
                            return Err(VMError::UnknownSyscall(imm8));
                        }
                        self.execute_syscall_with_register_log(
                            host,
                            imm8,
                            prepared_host_log.as_ref(),
                        )?;
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::system::SYSTEM => {
                        let number = crate::encoding::wide::decode_syscallx(instr);
                        if !host_allows_syscall_masked(host, self.syscall_policy(), number) {
                            return Err(VMError::UnknownSyscall(number));
                        }
                        self.execute_syscall_with_register_log(
                            host,
                            number,
                            prepared_host_log.as_ref(),
                        )?;
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ADD => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self
                            .registers
                            .get(rs1)
                            .wrapping_add(self.registers.get(rs2));
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SUB => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self
                            .registers
                            .get(rs1)
                            .wrapping_sub(self.registers.get(rs2));
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::AND => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self.registers.get(rs1) & self.registers.get(rs2);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::OR => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self.registers.get(rs1) | self.registers.get(rs2);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::XOR => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self.registers.get(rs1) ^ self.registers.get(rs2);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SLL => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self.registers.get(rs1) << (self.registers.get(rs2) & 0x3f);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SRL => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self.registers.get(rs1) >> (self.registers.get(rs2) & 0x3f);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SRA => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = ((self.registers.get(rs1) as i64)
                            >> (self.registers.get(rs2) & 0x3f))
                            as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::MUL => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let val = self
                            .registers
                            .get(rs1)
                            .wrapping_mul(self.registers.get(rs2));
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::MULH => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64 as i128;
                        let b = self.registers.get(rs2) as i64 as i128;
                        let val = ((a * b) >> 64) as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::MULHU => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let prod = (self.registers.get(rs1) as u128)
                            .wrapping_mul(self.registers.get(rs2) as u128);
                        let val = (prod >> 64) as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::MULHSU => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64 as i128;
                        let b = self.registers.get(rs2) as u64 as i128;
                        let val = ((a * b) >> 64) as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::DIV => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let num = self.registers.get(rs1) as i64;
                        let denom = self.registers.get(rs2) as i64;
                        let val = checked_div_i64(num, denom)?;
                        self.registers.set(rd, val as u64);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::DIVU => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let denom = self.registers.get(rs2);
                        if denom == 0 {
                            return Err(VMError::AssertionFailed);
                        }
                        let val = self.registers.get(rs1) / denom;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::REM => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let num = self.registers.get(rs1) as i64;
                        let denom = self.registers.get(rs2) as i64;
                        let val = checked_rem_i64(num, denom)?;
                        self.registers.set(rd, val as u64);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::REMU => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let denom = self.registers.get(rs2);
                        if denom == 0 {
                            return Err(VMError::AssertionFailed);
                        }
                        let val = self.registers.get(rs1) % denom;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SLT => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let lhs = self.registers.get(rs1) as i64;
                        let rhs = self.registers.get(rs2) as i64;
                        self.registers.set(rd, u64::from(lhs < rhs));
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SLTU => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let lhs = self.registers.get(rs1);
                        let rhs = self.registers.get(rs2);
                        self.registers.set(rd, u64::from(lhs < rhs));
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SEQ => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let lhs = self.registers.get(rs1);
                        let rhs = self.registers.get(rs2);
                        self.registers.set(rd, u64::from(lhs == rhs));
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::SNE => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let lhs = self.registers.get(rs1);
                        let rhs = self.registers.get(rs2);
                        self.registers.set(rd, u64::from(lhs != rhs));
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::CMOV => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let cond = instruction::wide::rs2(instr);
                        if self.zk_mode && self.registers.tag(cond) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if self.registers.get(cond) != 0 {
                            let val = self.registers.get(src);
                            self.registers.set(rd, val);
                            let tag = self.zk_unary_tag(src);
                            self.zk_apply_tag(rd, tag);
                        }
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::NEG => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = self.registers.get(src).wrapping_neg();
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::NOT => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = !self.registers.get(src);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ROTL => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let amt = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(src, amt)?;
                        let sh = (self.registers.get(amt) & 0x3f) as u32;
                        let val = self.registers.get(src).rotate_left(sh);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ROTR => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let amt = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(src, amt)?;
                        let sh = (self.registers.get(amt) & 0x3f) as u32;
                        let val = self.registers.get(src).rotate_right(sh);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ROTL_IMM => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let sh = (instruction::wide::imm8(instr) as u8 as u32) & 0x3f;
                        let val = self.registers.get(src).rotate_left(sh);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(WIDE_INSTRUCTION_LEN);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ROTR_IMM => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let sh = (instruction::wide::imm8(instr) as u8 as u32) & 0x3f;
                        let val = self.registers.get(src).rotate_right(sh);
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::POPCNT => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = self.registers.get(src).count_ones() as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::CLZ => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = self.registers.get(src).leading_zeros() as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::CTZ => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = self.registers.get(src).trailing_zeros() as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ISQRT => {
                        let rd = instruction::wide::rd(instr);
                        let src = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(src);
                        let val = self.registers.get(src);
                        let root = isqrt_u64(val);
                        self.registers.set(rd, root);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 6;
                        continue;
                    }
                    instruction::wide::arithmetic::MIN => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64;
                        let b = self.registers.get(rs2) as i64;
                        self.registers
                            .set(rd, if a < b { a as u64 } else { b as u64 });
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::MAX => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64;
                        let b = self.registers.get(rs2) as i64;
                        self.registers
                            .set(rd, if a > b { a as u64 } else { b as u64 });
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ABS => {
                        let rd = instruction::wide::rd(instr);
                        let rs = instruction::wide::rs1(instr);
                        self.zk_require_public_trap_operands(&[rs])?;
                        let tag = self.zk_unary_tag(rs);
                        let v = self.registers.get(rs) as i64;
                        let abs = checked_abs_i64(v)?;
                        self.registers.set(rd, abs as u64);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::DIV_CEIL => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let num = self.registers.get(rs1) as i64;
                        let denom = self.registers.get(rs2) as i64;
                        let val = div_ceil_i64(num, denom)?;
                        self.registers.set(rd, val as u64);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 12;
                        continue;
                    }
                    instruction::wide::arithmetic::GCD => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64;
                        let b = self.registers.get(rs2) as i64;
                        let g = gcd_i64(a, b);
                        self.registers.set(rd, g);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 12;
                        continue;
                    }
                    instruction::wide::arithmetic::MEAN => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let a = self.registers.get(rs1) as i64;
                        let b = self.registers.get(rs2) as i64;
                        let sum = (a as i128) + (b as i128);
                        let avg = (sum / 2) as i64;
                        self.registers.set(rd, avg as u64);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 3;
                        continue;
                    }
                    instruction::wide::arithmetic::ADDI => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(rs1);
                        let imm = i64::from(i16::from(instruction::wide::imm8(instr)));
                        let val = (self.registers.get(rs1) as i64).wrapping_add(imm) as u64;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ANDI => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(rs1);
                        let imm = instruction::wide::imm8(instr) as i64 as u64;
                        let val = self.registers.get(rs1) & imm;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::ORI => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(rs1);
                        let imm = instruction::wide::imm8(instr) as i64 as u64;
                        let val = self.registers.get(rs1) | imm;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::XORI => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let tag = self.zk_unary_tag(rs1);
                        let imm = instruction::wide::imm8(instr) as i64 as u64;
                        let val = self.registers.get(rs1) ^ imm;
                        self.registers.set(rd, val);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::arithmetic::CMOVI => {
                        let rd = instruction::wide::rd(instr);
                        let cond = instruction::wide::rs1(instr);
                        let imm = i64::from(instruction::wide::imm8(instr)) as u64;
                        if self.zk_mode && self.registers.tag(cond) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if self.registers.get(cond) != 0 {
                            self.registers.set(rd, imm);
                            if self.zk_mode {
                                self.registers.set_tag(rd, false);
                            }
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::LDLIT => {
                        let rd = instruction::wide::rd(instr);
                        let index = instruction::wide::literal_index(instr);
                        let DecodedLiteral::Pointer(pointer) = self
                            .literal_table
                            .entries()
                            .get(index)
                            .copied()
                            .ok_or(VMError::InvalidMetadata)?
                        else {
                            return Err(VMError::InvalidMetadata);
                        };
                        self.registers.set(rd, pointer);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::LDI64 => {
                        let rd = instruction::wide::rd(instr);
                        let index = instruction::wide::literal_index(instr);
                        let DecodedLiteral::I64(value) = self
                            .literal_table
                            .entries()
                            .get(index)
                            .copied()
                            .ok_or(VMError::InvalidMetadata)?
                        else {
                            return Err(VMError::InvalidMetadata);
                        };
                        self.registers.set(rd, value);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::LOAD64 => {
                        let rd = instruction::wide::rd(instr);
                        let base = instruction::wide::rs1(instr);
                        let imm = i64::from(i16::from(instruction::wide::imm8(instr)));
                        if self.zk_mode && self.registers.tag(base) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let addr = (self.registers.get(base) as i64).wrapping_add(imm) as u64;
                        let value = self.memory.load_u64(addr)?;
                        let tag = self.memory_load_privacy_tag(addr, 8)?;
                        self.memory.diagnostic_classify_last_access(
                            addr,
                            8,
                            DiagnosticMemoryAccessKind::Read,
                            tag,
                        );
                        self.registers.set(rd, value);
                        if self.zk_mode {
                            self.registers.set_tag(rd, tag);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::LOAD128 => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let rd_lo = instruction::wide::rd(instr);
                        let base = instruction::wide::rs1(instr);
                        let rd_hi = instruction::wide::rs2(instr);
                        if self.zk_mode && self.registers.tag(base) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if rd_lo >= 256 || rd_hi >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let addr = self.registers.get(base);
                        if !addr.is_multiple_of(16) {
                            return Err(VMError::MisalignedAccess { addr: addr as u32 });
                        }
                        let value = self.memory.load_u128(addr)?;
                        let tag = self.memory_load_privacy_tag(addr, 16)?;
                        self.memory.diagnostic_classify_last_access(
                            addr,
                            16,
                            DiagnosticMemoryAccessKind::Read,
                            tag,
                        );
                        self.registers.set(rd_lo, value as u64);
                        self.registers.set(rd_hi, (value >> 64) as u64);
                        if self.zk_mode {
                            self.registers.set_tag(rd_lo, tag);
                            self.registers.set_tag(rd_hi, tag);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::STORE64 => {
                        let base = instruction::wide::rd(instr);
                        let rs = instruction::wide::rs1(instr);
                        let imm = i64::from(i16::from(instruction::wide::imm8(instr)));
                        if self.zk_mode && self.registers.tag(base) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let addr = (self.registers.get(base) as i64).wrapping_add(imm) as u64;
                        let value = self.registers.get(rs);
                        let tag = self.zk_mode && self.registers.tag(rs);
                        self.validate_memory_store_privacy(addr, 8, tag)?;
                        self.preflight_memory_store_privacy(addr, 8, tag)?;
                        self.memory.store_u64(addr, value)?;
                        self.record_memory_store_privacy(addr, 8, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::memory::STORE128 => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let base = instruction::wide::rd(instr);
                        let rs_lo = instruction::wide::rs1(instr);
                        let rs_hi = instruction::wide::rs2(instr);
                        if self.zk_mode && self.registers.tag(base) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if rs_lo >= 256 || rs_hi >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let addr = self.registers.get(base);
                        if !addr.is_multiple_of(16) {
                            return Err(VMError::MisalignedAccess { addr: addr as u32 });
                        }
                        let lo = self.registers.get(rs_lo);
                        let hi = self.registers.get(rs_hi);
                        let tag = self.zk_match_tags(rs_lo, rs_hi)?.unwrap_or(false);
                        self.validate_memory_store_privacy(addr, 16, tag)?;
                        self.preflight_memory_store_privacy(addr, 16, tag)?;
                        let value = ((hi as u128) << 64) | lo as u128;
                        self.memory.store_u128(addr, value)?;
                        self.record_memory_store_privacy(addr, 16, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::HALT => {
                        if self.strict_return_integrity {
                            return Err(VMError::AssertionFailed);
                        }
                        self.halted = true;
                        self.cycles += 1;
                        self.pc = self.pc.wrapping_add(length);
                        // Commit completed HALT work at the loop boundary before
                        // trace flushing, which may unwind while allocating.
                        continue;
                    }
                    instruction::wide::crypto::SETVL => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        self.vector_length = setvl_length(instruction::wide::rs2(instr))?;
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::VADD32 | instruction::wide::crypto::VADD64 => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = Self::VECTOR_BASE + instruction::wide::rd(instr) * stride;
                        let rs = Self::VECTOR_BASE + instruction::wide::rs1(instr) * stride;
                        let rt = Self::VECTOR_BASE + instruction::wide::rs2(instr) * stride;
                        if rd + vl > 256 || rs + vl > 256 || rt + vl > 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        if wide_op == instruction::wide::crypto::VADD64 {
                            validate_vadd64_length(vl)?;
                            // Process full 128-bit chunks through the vector helpers when possible.
                            let mut lane = 0usize;
                            while lane + 4 <= vl {
                                let mut a = [0u32; 4];
                                let mut b = [0u32; 4];
                                for offset in 0..4 {
                                    let idx = lane + offset;
                                    if self.zk_mode {
                                        let a_tag = self.registers.tag(rs + idx);
                                        let b_tag = self.registers.tag(rt + idx);
                                        if a_tag != b_tag {
                                            return Err(VMError::PrivacyViolation);
                                        }
                                        self.registers.set_tag(rd + idx, a_tag);
                                    }
                                    a[offset] = self.registers.get(rs + idx) as u32;
                                    b[offset] = self.registers.get(rt + idx) as u32;
                                }
                                // Enforce pair tag alignment for zk mode (lo/hi halves must share a tag).
                                if self.zk_mode {
                                    for pair in 0..2 {
                                        let lo = lane + pair * 2;
                                        let hi = lo + 1;
                                        let tag_lo = self.registers.tag(rd + lo);
                                        let tag_hi = self.registers.tag(rd + hi);
                                        if tag_lo != tag_hi {
                                            return Err(VMError::PrivacyViolation);
                                        }
                                    }
                                }
                                let sum = vector::vadd64(a, b);
                                for (offset, value) in sum.iter().enumerate() {
                                    let idx = lane + offset;
                                    self.registers.set(rd + idx, u64::from(*value));
                                }
                                lane += 4;
                            }
                            // Handle any remaining pairs with the scalar fallback.
                            let pairs = (vl - lane) / 2;
                            for pair in 0..pairs {
                                let lo_idx = lane + pair * 2;
                                let hi_idx = lo_idx + 1;
                                let a_lo = self.registers.get(rs + lo_idx) & 0xffff_ffff;
                                let a_hi = self.registers.get(rs + hi_idx) & 0xffff_ffff;
                                let b_lo = self.registers.get(rt + lo_idx) & 0xffff_ffff;
                                let b_hi = self.registers.get(rt + hi_idx) & 0xffff_ffff;
                                if self.zk_mode {
                                    let a_lo_tag = self.registers.tag(rs + lo_idx);
                                    let a_hi_tag = self.registers.tag(rs + hi_idx);
                                    let b_lo_tag = self.registers.tag(rt + lo_idx);
                                    let b_hi_tag = self.registers.tag(rt + hi_idx);
                                    if a_lo_tag != a_hi_tag
                                        || b_lo_tag != b_hi_tag
                                        || a_lo_tag != b_lo_tag
                                    {
                                        return Err(VMError::PrivacyViolation);
                                    }
                                    self.registers.set_tag(rd + lo_idx, a_lo_tag);
                                    self.registers.set_tag(rd + hi_idx, a_lo_tag);
                                }
                                let a = (a_hi << 32) | a_lo;
                                let b = (b_hi << 32) | b_lo;
                                let sum = a.wrapping_add(b);
                                self.registers.set(rd + lo_idx, sum & 0xffff_ffff);
                                self.registers.set(rd + hi_idx, sum >> 32);
                            }
                        } else {
                            let mut lane = 0usize;
                            while lane + 4 <= vl {
                                let mut a = [0u32; 4];
                                let mut b = [0u32; 4];
                                for offset in 0..4 {
                                    let idx = lane + offset;
                                    if self.zk_mode {
                                        let taga = self.registers.tag(rs + idx);
                                        let tagb = self.registers.tag(rt + idx);
                                        if taga != tagb {
                                            return Err(VMError::PrivacyViolation);
                                        }
                                        self.registers.set_tag(rd + idx, taga);
                                    }
                                    a[offset] = self.registers.get(rs + idx) as u32;
                                    b[offset] = self.registers.get(rt + idx) as u32;
                                }
                                let sum = vector::vadd32(a, b);
                                for (offset, value) in sum.iter().enumerate() {
                                    let idx = lane + offset;
                                    self.registers.set(rd + idx, u64::from(*value));
                                }
                                lane += 4;
                            }
                            for idx in lane..vl {
                                let a = self.registers.get(rs + idx) as u32;
                                let b = self.registers.get(rt + idx) as u32;
                                if self.zk_mode {
                                    let taga = self.registers.tag(rs + idx);
                                    let tagb = self.registers.tag(rt + idx);
                                    if taga != tagb {
                                        return Err(VMError::PrivacyViolation);
                                    }
                                    self.registers.set_tag(rd + idx, taga);
                                }
                                self.registers.set(rd + idx, u64::from(a.wrapping_add(b)));
                            }
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BEQ => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs);
                        let b = self.registers.get(rt);
                        let taken = a == b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BNE => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs);
                        let b = self.registers.get(rt);
                        let taken = a != b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BLT => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs) as i64;
                        let b = self.registers.get(rt) as i64;
                        let taken = a < b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BGE => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs) as i64;
                        let b = self.registers.get(rt) as i64;
                        let taken = a >= b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BLTU => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs);
                        let b = self.registers.get(rt);
                        let taken = a < b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::BGEU => {
                        let rs = instruction::wide::rd(instr);
                        let rt = instruction::wide::rs1(instr);
                        let offset = i64::from(instruction::wide::imm8(instr));
                        if self.zk_mode && (self.registers.tag(rs) || self.registers.tag(rt)) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs);
                        let b = self.registers.get(rt);
                        let taken = a >= b;
                        if taken {
                            let byte_off = offset as i64 * 4;
                            self.pc = ((self.pc as i64) + byte_off) as u64;
                        } else {
                            self.pc = self.pc.wrapping_add(length);
                        }
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::JR => {
                        let rs = instruction::wide::rd(instr);
                        if self.zk_mode && self.registers.tag(rs) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if self.strict_return_integrity {
                            return Err(VMError::AssertionFailed);
                        }
                        self.pc = self.registers.get(rs);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::JALR => {
                        let rd = instruction::wide::rd(instr);
                        let rs = instruction::wide::rs1(instr);
                        if self.zk_mode && self.registers.tag(rs) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let imm = i64::from(instruction::wide::imm8(instr));
                        if self.strict_return_integrity && !(rd == 0 && rs == 1 && imm == 0) {
                            return Err(VMError::AssertionFailed);
                        }
                        let raw_target = self.registers.get(rs).wrapping_add_signed(imm);
                        let target =
                            ((raw_target.wrapping_sub(self.pc_alignment)) & !3) | self.pc_alignment;
                        if self.strict_return_integrity {
                            if let Some(expected) = self.contract_return_stack.last().copied() {
                                if target != expected {
                                    return Err(VMError::AssertionFailed);
                                }
                            } else {
                                if self.contract_outer_return_pc != Some(target) {
                                    return Err(VMError::AssertionFailed);
                                }
                                if target != self.memory.code_len() {
                                    return Err(VMError::AssertionFailed);
                                }
                            }
                            self.finish_call()?;
                            self.contract_return_stack.pop();
                            if target == self.memory.code_len() {
                                // Contract hosts use end-of-code as the trusted
                                // outer-invocation return sentinel.
                                self.halted = true;
                            }
                        }
                        let return_pc = self.pc.wrapping_add(length);
                        self.registers.set(rd, return_pc);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = target;
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::JAL => {
                        let rd = instruction::wide::rd(instr);
                        let imm = instruction::wide::imm16(instr) as i64;
                        let return_pc = self.pc.wrapping_add(length);
                        if self.strict_return_integrity {
                            if rd != 0 && rd != 1 {
                                return Err(VMError::AssertionFailed);
                            }
                            if rd == 1 {
                                self.begin_child_call(((self.pc as i64) + (imm * 4)) as u64)?;
                                self.push_contract_return(return_pc);
                            }
                        }
                        self.registers.set(rd, return_pc);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = ((self.pc as i64) + (imm * 4)) as u64;
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::JMP => {
                        let imm = i64::from(instruction::wide::imm24(instr));
                        self.pc = ((self.pc as i64) + (imm * 4)) as u64;
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::control::JALS => {
                        let imm = i64::from(instruction::wide::imm24(instr));
                        let return_pc = self.pc.wrapping_add(length);
                        self.begin_child_call(((self.pc as i64) + (imm * 4)) as u64)?;
                        self.push_contract_return(return_pc);
                        self.registers.set(1, return_pc);
                        if self.zk_mode {
                            self.registers.set_tag(1, false);
                        }
                        self.pc = ((self.pc as i64) + (imm * 4)) as u64;
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::VAND => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = Self::VECTOR_BASE + instruction::wide::rd(instr) * stride;
                        let rs = Self::VECTOR_BASE + instruction::wide::rs1(instr) * stride;
                        let rt = Self::VECTOR_BASE + instruction::wide::rs2(instr) * stride;
                        if rd + vl > 256 || rs + vl > 256 || rt + vl > 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let mut lane = 0usize;
                        while lane + 4 <= vl {
                            let mut a = [0u32; 4];
                            let mut b = [0u32; 4];
                            for offset in 0..4 {
                                let idx = lane + offset;
                                if self.zk_mode {
                                    let taga = self.registers.tag(rs + idx);
                                    let tagb = self.registers.tag(rt + idx);
                                    if taga != tagb {
                                        return Err(VMError::PrivacyViolation);
                                    }
                                    self.registers.set_tag(rd + idx, taga);
                                }
                                a[offset] = self.registers.get(rs + idx) as u32;
                                b[offset] = self.registers.get(rt + idx) as u32;
                            }
                            let out = vector::vand(a, b);
                            for (offset, value) in out.iter().enumerate() {
                                let idx = lane + offset;
                                self.registers.set(rd + idx, u64::from(*value));
                            }
                            lane += 4;
                        }
                        for idx in lane..vl {
                            if self.zk_mode {
                                let taga = self.registers.tag(rs + idx);
                                let tagb = self.registers.tag(rt + idx);
                                if taga != tagb {
                                    return Err(VMError::PrivacyViolation);
                                }
                                self.registers.set_tag(rd + idx, taga);
                            }
                            let a = self.registers.get(rs + idx) as u32;
                            let b = self.registers.get(rt + idx) as u32;
                            self.registers.set(rd + idx, u64::from(a & b));
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::VXOR => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = Self::VECTOR_BASE + instruction::wide::rd(instr) * stride;
                        let rs = Self::VECTOR_BASE + instruction::wide::rs1(instr) * stride;
                        let rt = Self::VECTOR_BASE + instruction::wide::rs2(instr) * stride;
                        if rd + vl > 256 || rs + vl > 256 || rt + vl > 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let mut lane = 0usize;
                        while lane + 4 <= vl {
                            let mut a = [0u32; 4];
                            let mut b = [0u32; 4];
                            for offset in 0..4 {
                                let idx = lane + offset;
                                if self.zk_mode {
                                    let taga = self.registers.tag(rs + idx);
                                    let tagb = self.registers.tag(rt + idx);
                                    if taga != tagb {
                                        return Err(VMError::PrivacyViolation);
                                    }
                                    self.registers.set_tag(rd + idx, taga);
                                }
                                a[offset] = self.registers.get(rs + idx) as u32;
                                b[offset] = self.registers.get(rt + idx) as u32;
                            }
                            let out = vector::vxor(a, b);
                            for (offset, value) in out.iter().enumerate() {
                                let idx = lane + offset;
                                self.registers.set(rd + idx, u64::from(*value));
                            }
                            lane += 4;
                        }
                        for idx in lane..vl {
                            if self.zk_mode {
                                let taga = self.registers.tag(rs + idx);
                                let tagb = self.registers.tag(rt + idx);
                                if taga != tagb {
                                    return Err(VMError::PrivacyViolation);
                                }
                                self.registers.set_tag(rd + idx, taga);
                            }
                            let a = self.registers.get(rs + idx) as u32;
                            let b = self.registers.get(rt + idx) as u32;
                            self.registers.set(rd + idx, u64::from(a ^ b));
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::VOR => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = Self::VECTOR_BASE + instruction::wide::rd(instr) * stride;
                        let rs = Self::VECTOR_BASE + instruction::wide::rs1(instr) * stride;
                        let rt = Self::VECTOR_BASE + instruction::wide::rs2(instr) * stride;
                        if rd + vl > 256 || rs + vl > 256 || rt + vl > 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let mut lane = 0usize;
                        while lane + 4 <= vl {
                            let mut a = [0u32; 4];
                            let mut b = [0u32; 4];
                            for offset in 0..4 {
                                let idx = lane + offset;
                                if self.zk_mode {
                                    let taga = self.registers.tag(rs + idx);
                                    let tagb = self.registers.tag(rt + idx);
                                    if taga != tagb {
                                        return Err(VMError::PrivacyViolation);
                                    }
                                    self.registers.set_tag(rd + idx, taga);
                                }
                                a[offset] = self.registers.get(rs + idx) as u32;
                                b[offset] = self.registers.get(rt + idx) as u32;
                            }
                            let out = vector::vor(a, b);
                            for (offset, value) in out.iter().enumerate() {
                                let idx = lane + offset;
                                self.registers.set(rd + idx, u64::from(*value));
                            }
                            lane += 4;
                        }
                        for idx in lane..vl {
                            if self.zk_mode {
                                let taga = self.registers.tag(rs + idx);
                                let tagb = self.registers.tag(rt + idx);
                                if taga != tagb {
                                    return Err(VMError::PrivacyViolation);
                                }
                                self.registers.set_tag(rd + idx, taga);
                            }
                            let a = self.registers.get(rs + idx) as u32;
                            let b = self.registers.get(rt + idx) as u32;
                            self.registers.set(rd + idx, u64::from(a | b));
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::VROT32 => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = Self::VECTOR_BASE + instruction::wide::rd(instr) * stride;
                        let rs = Self::VECTOR_BASE + instruction::wide::rs1(instr) * stride;
                        if rd + vl > 256 || rs + vl > 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let shift = (instruction::wide::imm8(instr) as u8 & 0x1F) as u32;
                        let mut lane = 0usize;
                        while lane + 4 <= vl {
                            let mut a = [0u32; 4];
                            for (offset, value) in a.iter_mut().enumerate() {
                                let idx = lane + offset;
                                if self.zk_mode {
                                    let src_tag = self.registers.tag(rs + idx);
                                    self.registers.set_tag(rd + idx, src_tag);
                                }
                                *value = self.registers.get(rs + idx) as u32;
                            }
                            let rotated = vector::vrot32(a, shift);
                            for (offset, value) in rotated.iter().enumerate() {
                                let idx = lane + offset;
                                self.registers.set(rd + idx, u64::from(*value));
                            }
                            lane += 4;
                        }
                        for idx in lane..vl {
                            if self.zk_mode {
                                let src_tag = self.registers.tag(rs + idx);
                                self.registers.set_tag(rd + idx, src_tag);
                            }
                            let value = self.registers.get(rs + idx) as u32;
                            let rotated = value.rotate_left(shift) as u64;
                            self.registers.set(rd + idx, rotated);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::SHA256BLOCK => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let vl = self.vector_length.max(1);
                        let stride = vl;
                        let rd = instruction::wide::rd(instr);
                        let ptr_reg = instruction::wide::rs1(instr);
                        if self.zk_mode && self.registers.tag(ptr_reg) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let base = Self::VECTOR_BASE + rd * stride;
                        let second = base + stride;
                        if second + stride > 256 || ptr_reg >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let state_lanes = stride.min(4);
                        if self.zk_mode
                            && (0..state_lanes).any(|lane| {
                                self.registers.tag(base + lane) || self.registers.tag(second + lane)
                            })
                        {
                            return Err(VMError::PrivacyViolation);
                        }
                        let addr = self.registers.get(ptr_reg);
                        self.ensure_public_memory(addr, 64)?;
                        let mut block = [0u8; 64];
                        self.memory.load_bytes(addr, &mut block)?;
                        if self.zk_trace_collection_enabled() {
                            for (i, b) in block.iter().enumerate() {
                                let (root, path) =
                                    self.memory.merkle_root_and_path(addr + i as u64)?;
                                self.mem_log.record(MemEvent::Load {
                                    addr: addr + i as u64,
                                    value: *b as u128,
                                    size: 1,
                                    path,
                                    root,
                                });
                            }
                        }
                        let mut state = [0u32; 8];
                        let first_lanes = state_lanes;
                        for (lane, slot) in state.iter_mut().take(first_lanes).enumerate() {
                            *slot = self.registers.get(base + lane) as u32;
                        }
                        let second_lanes = state_lanes;
                        for (lane, slot) in state.iter_mut().skip(4).take(second_lanes).enumerate()
                        {
                            *slot = self.registers.get(second + lane) as u32;
                        }
                        vector::sha256_compress(&mut state, &block);
                        for (lane, value) in state.iter().take(first_lanes).enumerate() {
                            self.registers.set(base + lane, u64::from(*value));
                        }
                        for (lane, value) in state.iter().skip(4).take(second_lanes).enumerate() {
                            self.registers.set(second + lane, u64::from(*value));
                        }
                        if self.zk_mode {
                            for lane in 0..state_lanes {
                                self.registers.set_tag(base + lane, false);
                                self.registers.set_tag(second + lane, false);
                            }
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::SHA3BLOCK => {
                        let rd = instruction::wide::rd(instr);
                        let rs_state = instruction::wide::rs1(instr);
                        let rs_block = instruction::wide::rs2(instr);
                        if self.zk_mode
                            && (self.registers.tag(rd)
                                || self.registers.tag(rs_state)
                                || self.registers.tag(rs_block))
                        {
                            return Err(VMError::PrivacyViolation);
                        }
                        if rd >= 256 || rs_state >= 256 || rs_block >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let state_ptr = self.registers.get(rs_state);
                        let block_ptr = self.registers.get(rs_block);
                        let out_ptr = self.registers.get(rd);
                        self.ensure_public_memory(state_ptr, (25 * 8) as u64)?;
                        self.ensure_public_memory(block_ptr, 136)?;
                        let mut state = [0u64; 25];
                        let mut state_bytes = [0u8; 25 * 8];
                        self.memory.load_bytes(state_ptr, &mut state_bytes)?;
                        for i in 0..25 {
                            let mut lane = [0u8; 8];
                            lane.copy_from_slice(&state_bytes[i * 8..(i + 1) * 8]);
                            state[i] = u64::from_le_bytes(lane);
                        }
                        let mut block = [0u8; 136];
                        self.memory.load_bytes(block_ptr, &mut block)?;
                        crate::sha3::sha3_absorb_block(&mut state, &block);
                        let mut out_bytes = [0u8; 25 * 8];
                        for i in 0..25 {
                            out_bytes[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
                        }
                        self.preflight_memory_store_privacy(
                            out_ptr,
                            out_bytes.len() as u64,
                            false,
                        )?;
                        self.memory.store_bytes(out_ptr, &out_bytes)?;
                        self.record_memory_store_privacy(out_ptr, out_bytes.len() as u64, false);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::AESENC => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs_state = instruction::wide::rs1(instr);
                        let rs_key = instruction::wide::rs2(instr);
                        if rd + 1 >= 256 || rs_state + 1 >= 256 || rs_key + 1 >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        if self.zk_mode {
                            let state_tag_lo = self.registers.tag(rs_state);
                            let state_tag_hi = self.registers.tag(rs_state + 1);
                            let key_tag_lo = self.registers.tag(rs_key);
                            let key_tag_hi = self.registers.tag(rs_key + 1);
                            if state_tag_lo != state_tag_hi
                                || key_tag_lo != key_tag_hi
                                || state_tag_lo != key_tag_lo
                            {
                                return Err(VMError::PrivacyViolation);
                            }
                            self.registers.set_tag(rd, state_tag_lo);
                            self.registers.set_tag(rd + 1, state_tag_lo);
                        }
                        let mut state = [0u8; 16];
                        let s_lo = self.registers.get(rs_state).to_le_bytes();
                        let s_hi = self.registers.get(rs_state + 1).to_le_bytes();
                        state[..8].copy_from_slice(&s_lo);
                        state[8..].copy_from_slice(&s_hi);
                        let mut rk = [0u8; 16];
                        let k_lo = self.registers.get(rs_key).to_le_bytes();
                        let k_hi = self.registers.get(rs_key + 1).to_le_bytes();
                        rk[..8].copy_from_slice(&k_lo);
                        rk[8..].copy_from_slice(&k_hi);
                        let out = crate::aes::aesenc(state, rk);
                        let lo = u64::from_le_bytes(out[..8].try_into().unwrap());
                        let hi = u64::from_le_bytes(out[8..].try_into().unwrap());
                        self.registers.set(rd, lo);
                        self.registers.set(rd + 1, hi);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::AESDEC => {
                        if unlikely(!self.vector_enabled) {
                            return Err(VMError::VectorExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs_state = instruction::wide::rs1(instr);
                        let rs_key = instruction::wide::rs2(instr);
                        if rd + 1 >= 256 || rs_state + 1 >= 256 || rs_key + 1 >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        if self.zk_mode {
                            let state_tag_lo = self.registers.tag(rs_state);
                            let state_tag_hi = self.registers.tag(rs_state + 1);
                            let key_tag_lo = self.registers.tag(rs_key);
                            let key_tag_hi = self.registers.tag(rs_key + 1);
                            if state_tag_lo != state_tag_hi
                                || key_tag_lo != key_tag_hi
                                || state_tag_lo != key_tag_lo
                            {
                                return Err(VMError::PrivacyViolation);
                            }
                            self.registers.set_tag(rd, state_tag_lo);
                            self.registers.set_tag(rd + 1, state_tag_lo);
                        }
                        let mut state = [0u8; 16];
                        let s_lo = self.registers.get(rs_state).to_le_bytes();
                        let s_hi = self.registers.get(rs_state + 1).to_le_bytes();
                        state[..8].copy_from_slice(&s_lo);
                        state[8..].copy_from_slice(&s_hi);
                        let mut rk = [0u8; 16];
                        let k_lo = self.registers.get(rs_key).to_le_bytes();
                        let k_hi = self.registers.get(rs_key + 1).to_le_bytes();
                        rk[..8].copy_from_slice(&k_lo);
                        rk[8..].copy_from_slice(&k_hi);
                        let out = crate::aes::aesdec(state, rk);
                        let lo = u64::from_le_bytes(out[..8].try_into().unwrap());
                        let hi = u64::from_le_bytes(out[8..].try_into().unwrap());
                        self.registers.set(rd, lo);
                        self.registers.set(rd + 1, hi);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::BLAKE2S => {
                        use iroha_crypto::blake2::{Blake2s256, Digest as _};
                        let rd = instruction::wide::rd(instr);
                        let rs = instruction::wide::rs1(instr);
                        if self.zk_mode && self.registers.tag(rs) {
                            return Err(VMError::PrivacyViolation);
                        }
                        if rd + 1 >= 256 || rs >= 256 {
                            return Err(VMError::RegisterOutOfBounds);
                        }
                        let ptr = self.registers.get(rs);
                        self.ensure_public_memory(ptr, 64)?;
                        let mut input = [0u8; 64];
                        self.memory.load_bytes(ptr, &mut input)?;
                        let mut hasher = Blake2s256::new();
                        hasher.update(input);
                        let digest = hasher.finalize();
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&digest);
                        let lo = u64::from_le_bytes(out[..8].try_into().unwrap());
                        let hi = u64::from_le_bytes(out[8..16].try_into().unwrap());
                        self.registers.set(rd, lo);
                        self.registers.set(rd + 1, hi);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                            self.registers.set_tag(rd + 1, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::POSEIDON2 => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        if self.zk_mode && (self.registers.tag(rs1) || self.registers.tag(rs2)) {
                            // This legacy scalar gadget returns only 64 bits
                            // and is never a Secret<T> declassification path.
                            return Err(VMError::PrivacyViolation);
                        }
                        let a = self.registers.get(rs1);
                        let b = self.registers.get(rs2);
                        let res = crate::poseidon::poseidon2(a, b);
                        self.registers.set(rd, res);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::POSEIDON6 => {
                        let Some((rd, rs_base)) = crate::encoding::wide::decode_poseidon6(instr)
                        else {
                            return Err(VMError::DecodeError);
                        };
                        let rd = usize::from(rd);
                        let rs_base = usize::from(rs_base);
                        if self.zk_mode {
                            for index in 0..instruction::wide::crypto::POSEIDON6_INPUTS {
                                if self.registers.tag(rs_base + index) {
                                    // This legacy scalar gadget returns only
                                    // 64 bits and cannot consume Secret<T>.
                                    return Err(VMError::PrivacyViolation);
                                }
                            }
                        }
                        let vals = std::array::from_fn(|index| {
                            debug_assert!(index < instruction::wide::crypto::POSEIDON6_INPUTS);
                            self.registers.get(rs_base + index)
                        });
                        let res = crate::poseidon::poseidon6(vals);
                        self.registers.set(rd, res);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::ED25519BATCHVERIFY => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        if self.zk_mode && self.registers.tag(rs1) {
                            return Err(VMError::PrivacyViolation);
                        }
                        let mut fail_index = 0u64;
                        let request_ptr = self.registers.get(rs1);
                        let payload_len = match self.inspect_owned_public_tlv_header(request_ptr) {
                            Ok((payload_len, _)) => Some(payload_len),
                            Err(VMError::PrivacyViolation) => {
                                return Err(VMError::PrivacyViolation);
                            }
                            Err(error) if error.execution_deferral().is_some() => {
                                return Err(error);
                            }
                            Err(_) => None,
                        };
                        let ok = if let Some(payload_len) = payload_len {
                            if payload_len
                                > u64::try_from(crate::gas::ED25519_BATCH_MAX_PAYLOAD_BYTES)
                                    .expect("batch payload limit always fits u64")
                            {
                                false
                            } else {
                                self.debit_gas(crate::gas::ed25519_batch_extra_gas(
                                    payload_len,
                                    0,
                                ))?;
                                let request = self
                                    .validate_public_crypto_tlv(request_ptr)?
                                    .and_then(|tlv_req| {
                                        (tlv_req.type_id_raw()
                                            == crate::pointer_abi::PointerType::NoritoBytes as u16)
                                            .then(|| {
                                                norito::decode_from_bytes_with_limits::<
                                                    crate::signature::Ed25519BatchRequest,
                                                >(
                                                    tlv_req.payload,
                                                    crate::gas::ED25519_BATCH_DECODE_LIMITS,
                                                )
                                                .ok()
                                            })
                                            .flatten()
                                    });
                                if let Some(request) = request {
                                    if request.entries.is_empty() {
                                        false
                                    } else if request.entries.len()
                                        > crate::gas::ED25519_BATCH_MAX_ENTRIES
                                    {
                                        fail_index = u64::try_from(request.entries.len())
                                            .map_err(|_| VMError::GasCostOverflow)?;
                                        false
                                    } else {
                                        let entry_count = u64::try_from(request.entries.len())
                                            .map_err(|_| VMError::GasCostOverflow)?;
                                        self.debit_gas(crate::gas::ed25519_batch_extra_gas(
                                            0,
                                            entry_count,
                                        ))?;
                                        match crate::signature::verify_ed25519_batch(
                                            &request,
                                            crate::gas::ED25519_BATCH_MAX_ENTRIES,
                                        ) {
                                            Ok(()) => true,
                                            Err(err) => {
                                                fail_index = match err {
                                                    crate::signature::Ed25519BatchError::Empty => 0,
                                                    crate::signature::Ed25519BatchError::TooMany {
                                                        actual,
                                                        ..
                                                    } => u64::try_from(actual)
                                                        .map_err(|_| VMError::GasCostOverflow)?,
                                                    crate::signature::Ed25519BatchError::InvalidEntry {
                                                        index,
                                                    }
                                                    | crate::signature::Ed25519BatchError::SignatureFailed {
                                                        index,
                                                    } => u64::try_from(index)
                                                        .map_err(|_| VMError::GasCostOverflow)?,
                                                };
                                                false
                                            }
                                        }
                                    }
                                } else {
                                    false
                                }
                            }
                        } else {
                            false
                        };
                        self.registers.set(rd, if ok { 1 } else { 0 });
                        self.registers.set(rs2, fail_index);
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                            self.registers.set_tag(rs2, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::ED25519VERIFY => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        if self.zk_mode
                            && (self.registers.tag(rd)
                                || self.registers.tag(rs1)
                                || self.registers.tag(rs2))
                        {
                            return Err(VMError::PrivacyViolation);
                        }
                        let msg_ptr = self.registers.get(rs1);
                        let sig_ptr = self.registers.get(rs2);
                        let pk_ptr = self.registers.get(rd);
                        let operands_ready =
                            self.preflight_signature_opcode_payloads([msg_ptr, sig_ptr, pk_ptr])?;
                        let ok = if operands_ready
                            && let (Some(tlv_msg), Some(tlv_sig), Some(tlv_pk)) = (
                                self.validate_public_crypto_tlv(msg_ptr)?,
                                self.validate_public_crypto_tlv(sig_ptr)?,
                                self.validate_public_crypto_tlv(pk_ptr)?,
                            ) {
                            let types_ok = tlv_msg.type_id_raw()
                                == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_sig.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_pk.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16;
                            types_ok
                                && crate::signature::verify_signature(
                                    crate::signature::SignatureScheme::Ed25519,
                                    tlv_msg.payload,
                                    tlv_sig.payload,
                                    tlv_pk.payload,
                                )
                        } else {
                            false
                        };
                        self.registers.set(rd, if ok { 1 } else { 0 });
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::ECDSAVERIFY => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        if self.zk_mode
                            && (self.registers.tag(rd)
                                || self.registers.tag(rs1)
                                || self.registers.tag(rs2))
                        {
                            return Err(VMError::PrivacyViolation);
                        }
                        let msg_ptr = self.registers.get(rs1);
                        let sig_ptr = self.registers.get(rs2);
                        let pk_ptr = self.registers.get(rd);
                        let operands_ready =
                            self.preflight_signature_opcode_payloads([msg_ptr, sig_ptr, pk_ptr])?;
                        let ok = if operands_ready
                            && let (Some(tlv_msg), Some(tlv_sig), Some(tlv_pk)) = (
                                self.validate_public_crypto_tlv(msg_ptr)?,
                                self.validate_public_crypto_tlv(sig_ptr)?,
                                self.validate_public_crypto_tlv(pk_ptr)?,
                            ) {
                            let types_ok = tlv_msg.type_id_raw()
                                == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_sig.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_pk.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16;
                            types_ok
                                && crate::signature::verify_signature(
                                    crate::signature::SignatureScheme::Secp256k1,
                                    tlv_msg.payload,
                                    tlv_sig.payload,
                                    tlv_pk.payload,
                                )
                        } else {
                            false
                        };
                        self.registers.set(rd, if ok { 1 } else { 0 });
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::DILITHIUMVERIFY => {
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        if self.zk_mode
                            && (self.registers.tag(rd)
                                || self.registers.tag(rs1)
                                || self.registers.tag(rs2))
                        {
                            return Err(VMError::PrivacyViolation);
                        }
                        let msg_ptr = self.registers.get(rs1);
                        let sig_ptr = self.registers.get(rs2);
                        let pk_ptr = self.registers.get(rd);
                        let operands_ready =
                            self.preflight_signature_opcode_payloads([msg_ptr, sig_ptr, pk_ptr])?;
                        let ok = if operands_ready
                            && let (Some(tlv_msg), Some(tlv_sig), Some(tlv_pk)) = (
                                self.validate_public_crypto_tlv(msg_ptr)?,
                                self.validate_public_crypto_tlv(sig_ptr)?,
                                self.validate_public_crypto_tlv(pk_ptr)?,
                            ) {
                            let types_ok = tlv_msg.type_id_raw()
                                == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_sig.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16
                                && tlv_pk.type_id_raw()
                                    == crate::pointer_abi::PointerType::Blob as u16;
                            types_ok
                                && crate::signature::verify_signature(
                                    crate::signature::SignatureScheme::MlDsa,
                                    tlv_msg.payload,
                                    tlv_sig.payload,
                                    tlv_pk.payload,
                                )
                        } else {
                            false
                        };
                        self.registers.set(rd, if ok { 1 } else { 0 });
                        if self.zk_mode {
                            self.registers.set_tag(rd, false);
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::ASSERT => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rs = instruction::wide::rs1(instr);
                        self.zk_require_public_trap_operands(&[rs])?;
                        if self.zk_trace_collection_enabled() {
                            self.constraints.record(Constraint::Zero {
                                reg: rs,
                                cycle: self.cycles,
                            });
                        }
                        let value = self.registers.get(rs);
                        if value != 0 {
                            self.constraint_failed = true;
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::ASSERT_EQ => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        self.zk_require_public_trap_operands(&[rs1, rs2])?;
                        if self.zk_trace_collection_enabled() {
                            self.constraints.record(Constraint::Eq {
                                reg1: rs1,
                                reg2: rs2,
                                cycle: self.cycles,
                            });
                        }
                        let v1 = self.registers.get(rs1);
                        let v2 = self.registers.get(rs2);
                        if v1 != v2 {
                            self.constraint_failed = true;
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::FADD => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let v1 = self.registers.get(rs1);
                        let v2 = self.registers.get(rs2);
                        let res = crate::field::add(v1, v2);
                        self.registers.set(rd, res);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::FSUB => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let v1 = self.registers.get(rs1);
                        let v2 = self.registers.get(rs2);
                        let res = crate::field::sub(v1, v2);
                        self.registers.set(rd, res);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::FMUL => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs1 = instruction::wide::rs1(instr);
                        let rs2 = instruction::wide::rs2(instr);
                        let tag = self.zk_match_tags(rs1, rs2)?;
                        let v1 = self.registers.get(rs1);
                        let v2 = self.registers.get(rs2);
                        let res = crate::field::mul(v1, v2);
                        self.registers.set(rd, res);
                        self.zk_apply_tag(rd, tag);
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::FINV => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rd = instruction::wide::rd(instr);
                        let rs = instruction::wide::rs1(instr);
                        self.zk_require_public_trap_operands(&[rs])?;
                        let tag = self.registers.tag(rs);
                        let value = self.registers.get(rs);
                        match crate::field::inv(value) {
                            Some(inv) => {
                                self.registers.set(rd, inv);
                                self.zk_apply_tag(rd, Some(tag));
                            }
                            None => {
                                self.constraint_failed = true;
                            }
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::zk::ASSERT_RANGE => {
                        if unlikely(!self.zk_mode) {
                            return Err(VMError::ZkExtensionDisabled);
                        }
                        let rs = instruction::wide::rs1(instr);
                        let imm = instruction::wide::imm8(instr) as u8;
                        self.zk_require_public_trap_operands(&[rs])?;
                        if self.zk_trace_collection_enabled() {
                            self.constraints.record(Constraint::Range {
                                reg: rs,
                                bits: imm,
                                cycle: self.cycles,
                            });
                        }
                        if imm <= 64 {
                            let mask = if imm == 64 {
                                u64::MAX
                            } else {
                                (1u64 << imm) - 1
                            };
                            let value = self.registers.get(rs);
                            if value & !mask != 0 {
                                self.constraint_failed = true;
                            }
                        } else {
                            self.constraint_failed = true;
                        }
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    instruction::wide::crypto::PARBEGIN | instruction::wide::crypto::PAREND => {
                        // Parallel sections are markers; no state change required.
                        self.pc = self.pc.wrapping_add(length);
                        self.cycles += 1;
                        continue;
                    }
                    _ => {
                        if crate::dev_env::debug_invalid_enabled() {
                            eprintln!(
                                "[invalid wide opcode] pc=0x{pc:08x} instr=0x{ins:08x} op_lo=0x{op_lo:02x} op_hi=0x{op_hi:02x}",
                                pc = self.pc,
                                ins = instr,
                                op_lo = opcode,
                                op_hi = wide_op,
                            );
                        }
                        return Err(VMError::InvalidOpcode((instr & 0xFFFF) as u16));
                    }
                }
            }
            if let Some((before, reservation)) = pending_cycles.take() {
                reservation.complete(self.cycles.checked_sub(before))?;
            }
            if let Some(step) = pending_step.take() {
                recorder
                    .as_deref_mut()
                    .expect("diagnostic step has recorder")
                    .finish_step(
                        step,
                        self.diagnostic_step_state(),
                        DiagnosticStepOutcome::Completed,
                    )?;
            }
            // If we exit the loop early, pad the trace so that prover and verifier
            // observe exactly `max_cycles` steps when zero‑knowledge mode is enabled.
            if self.zk_mode && self.max_cycles != 0 && self.cycles < self.max_cycles {
                // Append dummy cycles (treated as NOPs) until the target length is
                // reached. Each padded cycle still costs one unit of gas.
                let remaining = self.max_cycles - self.cycles;
                // Preserve the existing OOG outcome when padding cannot be paid.
                // Otherwise admit its complete root backing before any padding
                // cycles, shared allowance or gas are consumed.
                if self.gas_remaining >= remaining {
                    self.prepare_trace_padding(&invocation_trace, remaining)?;
                }
                let native_before_padding = (self.gas_remaining, self.cycles);
                if let Some(budget) = &cycle_budget {
                    // Padding contributes to architectural cycles even when the
                    // existing following gas check rejects the padded execution.
                    budget.reserve(remaining)?.complete(Some(remaining))?;
                }
                self.cycles = self.max_cycles;
                // Padding instructions still consume gas like NOPs (cost 1 each)
                if self.gas_remaining < remaining {
                    return Err(VMError::OutOfGas);
                } else {
                    self.gas_remaining -= remaining;
                }
                self.native_padding_completed(native_before_padding.0, native_before_padding.1);
                self.publish_trace_cycles(&invocation_trace, &mut last_logged_cycle)?;
            }
            self.commit_memory_after_run_if_needed();
            if let Some(error) = self.contract_abort_error.clone() {
                Err(error)
            } else if self.constraint_failed {
                Err(VMError::AssertionFailed)
            } else {
                if self.strict_return_integrity {
                    self.call_result_word_count()?;
                }
                Ok(())
            }
        })) {
            Ok(result) => result,
            Err(payload) => {
                self.finish_trace_invocation(invocation_trace);
                // Policy probes such as `allows_syscall` run before syscall
                // callback isolation. If any host hook panics, discard the
                // partial invocation proof before preserving the original
                // unwind behavior for the caller.
                self.abort_host_register_log_isolation(None);
                self.memory.call_frames.clear();
                self.captured_root_tables = None;
                std::panic::resume_unwind(payload);
            }
        };
        self.finish_trace_invocation(invocation_trace);
        let result = result.and_then(|()| {
            // A host may swallow a nested error and return from its last syscall.
            // Never accept such a parent after a shared reservation was refused.
            cycle_budget
                .as_ref()
                .map_or(Ok(()), |budget| budget.ensure_healthy())
        });
        if let Some(recorder) = recorder {
            if let Some(step) = pending_step.take() {
                let trap = result
                    .as_ref()
                    .err()
                    .map(Self::classify_trap)
                    .unwrap_or(VmTrapKind::Other);
                recorder.finish_step(
                    step,
                    self.diagnostic_step_state(),
                    DiagnosticStepOutcome::Trapped(trap),
                )?;
            }
            let state = self.diagnostic_step_state();
            let last_instruction_cycles = recorder
                .records()
                .last()
                .map_or(0, |step| step.after.cycles);
            recorder.finish_run(DiagnosticRunEnd {
                state,
                padding_cycles: if result.is_ok() {
                    state.cycles.saturating_sub(last_instruction_cycles)
                } else {
                    0
                },
                outcome: result.as_ref().map(|_| ()).map_err(Self::classify_trap),
            });
        }
        if let Err(err) = &result {
            self.memory.call_frames.clear();
            self.captured_root_tables = None;
            // Inline semantic context masks its register read; local refusals
            // retain only the returned error and never publish a diagnostic.
            self.capture_trap_at(err, fault_position);
        }
        result
    }
    /// Get the number of cycles executed in the last `run()`.
    #[inline]
    pub fn get_cycle_count(&self) -> u64 {
        self.cycles
    }
    /// Convenience wrapper that forwards to the memory subsystem.
    #[inline]
    pub fn store_u8(&mut self, addr: u64, byte: u8) -> Result<(), VMError> {
        self.preflight_memory_store_privacy(addr, 1, false)?;
        self.memory.store_u8(addr, byte)?;
        self.record_memory_store_privacy(addr, 1, false);
        Ok(())
    }
    #[inline]
    pub fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), VMError> {
        self.preflight_memory_store_privacy(addr, 4, false)?;
        self.memory.store_u32(addr, value)?;
        self.record_memory_store_privacy(addr, 4, false);
        Ok(())
    }
    #[inline]
    pub fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), VMError> {
        self.preflight_memory_store_privacy(addr, 8, false)?;
        self.memory.store_u64(addr, value)?;
        self.record_memory_store_privacy(addr, 8, false);
        Ok(())
    }
    #[inline]
    pub fn store_u128(&mut self, addr: u64, value: u128) -> Result<(), VMError> {
        self.preflight_memory_store_privacy(addr, 16, false)?;
        self.memory.store_u128(addr, value)?;
        self.record_memory_store_privacy(addr, 16, false);
        Ok(())
    }
    #[inline]
    pub fn store_bytes(&mut self, addr: u64, bytes: &[u8]) -> Result<(), VMError> {
        self.preflight_memory_store_privacy(addr, bytes.len() as u64, false)?;
        self.memory.store_bytes(addr, bytes)?;
        self.record_memory_store_privacy(addr, bytes.len() as u64, false);
        Ok(())
    }
    #[inline]
    pub fn load_u32(&self, addr: u64) -> Result<u32, VMError> {
        self.ensure_public_memory(addr, 4)?;
        let value = self.memory.load_u32(addr)?;
        self.memory.diagnostic_classify_last_access(
            addr,
            4,
            DiagnosticMemoryAccessKind::Read,
            false,
        );
        Ok(value)
    }
    #[inline]
    /// Load a 64-bit value from memory.
    ///
    /// This is a thin wrapper around the underlying memory subsystem, exposed
    /// on `IVM` for convenience by external users (e.g., executor host code)
    /// that interact with VM memory via the VM handle.
    pub fn load_u64(&self, addr: u64) -> Result<u64, VMError> {
        self.ensure_public_memory(addr, 8)?;
        let value = self.memory.load_u64(addr)?;
        self.memory.diagnostic_classify_last_access(
            addr,
            8,
            DiagnosticMemoryAccessKind::Read,
            false,
        );
        Ok(value)
    }
    #[inline]
    pub fn load_u128(&self, addr: u64) -> Result<u128, VMError> {
        self.ensure_public_memory(addr, 16)?;
        let value = self.memory.load_u128(addr)?;
        self.memory.diagnostic_classify_last_access(
            addr,
            16,
            DiagnosticMemoryAccessKind::Read,
            false,
        );
        Ok(value)
    }
    #[inline]
    pub fn load_bytes(&self, addr: u64, out: &mut [u8]) -> Result<(), VMError> {
        self.ensure_public_memory(addr, out.len() as u64)?;
        self.memory.load_bytes(addr, out)?;
        self.memory.diagnostic_classify_last_access(
            addr,
            out.len() as u64,
            DiagnosticMemoryAccessKind::HostRead,
            false,
        );
        Ok(())
    }
    #[inline]
    pub fn preload_input(&mut self, offset: u64, data: &[u8]) -> Result<(), VMError> {
        self.memory.preload_input(offset, data)
    }
    #[inline]
    pub fn alloc_heap(&mut self, size: u64) -> Result<u64, VMError> {
        self.memory.alloc(size)
    }
    #[inline]
    pub fn grow_heap(&mut self, additional: u64) -> Result<u64, VMError> {
        self.memory.grow_heap(additional)
    }
    /// Retrieve a copy of the output region. Intended for use by hosts after
    /// `SYSCALL_COMMIT_OUTPUT`.
    #[inline]
    pub fn read_output(&self) -> &[u8] {
        self.memory.read_output()
    }
    /// Return the length of the append-only output prefix written by the guest.
    #[inline]
    pub fn output_used_len(&self) -> u64 {
        self.memory.output_used_len()
    }
    /// Borrow only the append-only output prefix written by the guest.
    #[inline]
    pub fn read_output_used(&self) -> &[u8] {
        self.memory.read_output_used()
    }
    /// Produce a CompactProofBundle for the memory chunk containing `addr` by invoking the metered
    /// GET_MERKLE_COMPACT host path. This helper writes temporary data into the OUTPUT region.
    pub fn get_memory_compact_bundle(
        &mut self,
        addr: u64,
        depth_cap: Option<usize>,
    ) -> Result<crate::merkle_utils::CompactProofBundle, VMError> {
        let out_ptr = Memory::OUTPUT_START;
        let root_out = out_ptr + 8192;
        // Set syscall arguments in registers
        self.set_register(10, addr);
        self.set_register(11, out_ptr);
        self.set_register(12, depth_cap.unwrap_or(0) as u64);
        self.set_register(13, root_out);
        // Gate by policy and invoke host handler directly
        let num = crate::syscalls::SYSCALL_GET_MERKLE_COMPACT;
        if !crate::syscalls::is_syscall_allowed(self.syscall_policy(), num) {
            return Err(VMError::UnknownSyscall(num));
        }
        let mut host = self.host.take().ok_or(VMError::HostUnavailable)?;
        let syscall_result = self.execute_syscall(host.as_mut(), num);
        self.host = Some(host);
        syscall_result?;
        // Parse header and decode typed compact proof
        let mut hdr = [0u8; 1 + 4 + 4];
        self.memory.load_bytes(out_ptr, &mut hdr)?;
        let depth = hdr[0] as usize;
        let total = 1 + 4 + 4 + depth * 32;
        let mut buf = vec![0u8; total];
        self.memory.load_bytes(out_ptr, &mut buf)?;
        let (cp, _) = crate::merkle_utils::decode_compact_proof_bytes(&buf)
            .map_err(|_| VMError::DecodeError)?;
        // Read root
        let mut root = [0u8; 32];
        self.memory.load_bytes(root_out, &mut root)?;
        // Build bundle
        let siblings: Vec<[u8; 32]> = cp
            .siblings()
            .iter()
            .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
            .collect();
        Ok(crate::merkle_utils::CompactProofBundle {
            depth: cp.depth(),
            dirs: cp.dirs(),
            siblings,
            root,
        })
    }
    /// Produce a CompactProofBundle for the register leaf at `idx` by invoking
    /// the metered GET_REGISTER_MERKLE_COMPACT host path. This helper writes
    /// temporary data into the OUTPUT region.
    pub fn get_registers_compact_bundle(
        &mut self,
        idx: usize,
        depth_cap: Option<usize>,
    ) -> Result<crate::merkle_utils::CompactProofBundle, VMError> {
        if idx >= crate::parallel::REGISTER_COUNT {
            return Err(VMError::RegisterOutOfBounds);
        }
        let idx = u64::try_from(idx).map_err(|_| VMError::RegisterOutOfBounds)?;
        let out_ptr = Memory::OUTPUT_START;
        let root_out = out_ptr + 12288;
        // Set syscall arguments in registers
        self.set_register(10, idx);
        self.set_register(11, out_ptr);
        self.set_register(12, depth_cap.unwrap_or(0) as u64);
        self.set_register(13, root_out);
        // Gate by policy and invoke host handler directly
        let num = crate::syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT;
        if !crate::syscalls::is_syscall_allowed(self.syscall_policy(), num) {
            return Err(VMError::UnknownSyscall(num));
        }
        let mut host = self.host.take().ok_or(VMError::HostUnavailable)?;
        let syscall_result = self.execute_syscall(host.as_mut(), num);
        self.host = Some(host);
        syscall_result?;
        // Parse header and decode typed compact proof
        let mut hdr = [0u8; 1 + 4 + 4];
        self.memory.load_bytes(out_ptr, &mut hdr)?;
        let depth = hdr[0] as usize;
        let total = 1 + 4 + 4 + depth * 32;
        let mut buf = vec![0u8; total];
        self.memory.load_bytes(out_ptr, &mut buf)?;
        let (cp, _) = crate::merkle_utils::decode_compact_proof_bytes(&buf)
            .map_err(|_| VMError::DecodeError)?;
        // Read root
        let mut root = [0u8; 32];
        self.memory.load_bytes(root_out, &mut root)?;
        // Build bundle
        let siblings: Vec<[u8; 32]> = cp
            .siblings()
            .iter()
            .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
            .collect();
        Ok(crate::merkle_utils::CompactProofBundle {
            depth: cp.depth(),
            dirs: cp.dirs(),
            siblings,
            root,
        })
    }
}
#[cfg(test)]
mod ivm_sched_tests {
    use super::*;
    #[test]
    fn vm_reports_global_scheduler_limits() {
        crate::parallel::set_default_scheduler_limits(Some(2), Some(2));
        let vm = IVM::new(0);
        assert_eq!(vm.scheduler_limits, (2, 2));
        // Reset to auto for other tests
        crate::parallel::set_default_scheduler_limits(None, None);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{instruction, ivm_cache, metadata::LITERAL_SECTION_MAGIC};
    use std::{
        any::Any,
        cell::Cell,
        collections::BTreeMap,
        sync::atomic::{AtomicU32, Ordering as AtomicOrdering},
    };
    #[cfg(feature = "beep")]
    #[test]
    fn unavailable_audio_output_is_safe() {
        let played = Cell::new(false);
        with_audio_mixer(
            || Err(StreamError::NoDevice),
            |_| {
                played.set(true);
            },
        );
        assert!(!played.get());
    }
    #[test]
    fn private_memory_ranges_merge_split_and_respect_half_open_boundaries() {
        let mut ranges = PrivateMemoryRanges::default();
        ranges.try_insert(10..20).unwrap();
        ranges.try_insert(20..24).unwrap();
        ranges.try_insert(4..10).unwrap();
        assert_eq!(ranges.pairs_for_testing(), &[(4, 24)]);
        assert!(!ranges.intersects(0..4));
        assert!(!ranges.intersects(24..40));
        assert!(!ranges.intersects(12..12));
        assert!(ranges.intersects(3..5));
        assert!(ranges.intersects(23..24));
        assert_eq!(ranges.intersection_len(0..40), 20);
        ranges.try_remove(8..20).unwrap();
        assert_eq!(ranges.pairs_for_testing(), &[(4, 8), (20, 24)]);
        assert_eq!(ranges.intersection_len(4..24), 8);
        assert!(!ranges.intersects(8..20));
    }
    #[test]
    fn private_memory_ranges_remove_mixed_overlaps_and_adjacent_boundaries() {
        let mut ranges = PrivateMemoryRanges::default();
        for range in [1..3, 5..7, 9..11, 13..15] {
            ranges.try_insert(range).unwrap();
        }
        ranges.try_remove(2..14).unwrap();
        assert_eq!(ranges.pairs_for_testing(), &[(1, 2), (14, 15)]);
        ranges.try_remove(2..14).unwrap();
        assert_eq!(ranges.pairs_for_testing(), &[(1, 2), (14, 15)]);
        ranges.try_remove(3..13).unwrap();
        assert_eq!(ranges.pairs_for_testing(), &[(1, 2), (14, 15)]);
        ranges.try_remove(1..2).unwrap();
        ranges.try_remove(14..15).unwrap();
        assert!(ranges.is_empty());
    }
    #[test]
    fn private_memory_range_lookup_ignores_large_unrelated_public_span() {
        let mut ranges = PrivateMemoryRanges::default();
        ranges.try_insert(2_000_000..2_000_001).unwrap();
        assert!(!ranges.intersects(0..1_048_576));
        assert_eq!(ranges.intersection_len(0..1_048_576), 0);
        assert!(ranges.intersects(1_999_999..2_000_001));
    }
    #[test]
    fn private_memory_ranges_match_byte_reference_across_overwrites() {
        let operations = [
            (true, 10..20),
            (true, 30..40),
            (true, 18..32),
            (false, 12..14),
            (false, 19..35),
            (true, 0..64),
            (false, 1..63),
            (false, 0..64),
        ];
        let mut ranges = PrivateMemoryRanges::default();
        let mut bytes = [false; 64];
        for (private, range) in operations {
            if private {
                ranges.try_insert(range.clone()).unwrap();
            } else {
                ranges.try_remove(range.clone()).unwrap();
            }
            for byte in range {
                bytes[usize::try_from(byte).expect("test byte fits usize")] = private;
            }
            for start in 0..=64_usize {
                for end in start..=64_usize {
                    let expected =
                        u64::try_from(bytes[start..end].iter().filter(|private| **private).count())
                            .expect("64-byte reference count fits u64");
                    let start = u64::try_from(start).expect("test start fits u64");
                    let end = u64::try_from(end).expect("test end fits u64");
                    assert_eq!(ranges.intersection_len(start..end), expected);
                    assert_eq!(ranges.intersects(start..end), expected != 0);
                }
            }
        }
    }
    #[test]
    fn private_range_growth_refusal_precedes_guest_store() {
        let mut vm = quiet_vm(1_000);
        vm.zk_mode = true;
        let start = Memory::STACK_START;
        vm.memory.store_u32(start + 4, 0xAABB_CCDD).unwrap();
        for range in [
            start..start + 16,
            start + 32..start + 40,
            start + 48..start + 56,
            start + 64..start + 72,
        ] {
            vm.private_memory_bytes.try_insert(range).unwrap();
        }
        let before = vm.private_memory_bytes.try_clone().unwrap();
        let gas = vm.remaining_gas();
        PrivateMemoryRanges::refuse_next_growth_for_testing();
        assert!(matches!(
            vm.store_u32(start + 4, 7),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(vm.memory.load_u32(start + 4).unwrap(), 0xAABB_CCDD);
        assert_eq!(vm.private_memory_bytes, before);
        assert_eq!(vm.remaining_gas(), gas);
        vm.store_u32(start + 4, 7).unwrap();
        assert_eq!(
            vm.private_memory_bytes.pairs_for_testing()[0],
            (start, start + 4)
        );
        assert_eq!(vm.memory.load_u32(start + 4).unwrap(), 7);
    }
    #[test]
    fn private_tlv_growth_refusal_preserves_heap_cursor() {
        let mut vm = quiet_vm(1_000);
        vm.zk_mode = true;
        let heap = vm.memory.heap_allocated_len();
        PrivateMemoryRanges::refuse_next_growth_for_testing();
        assert!(matches!(
            vm.alloc_host_private_tlv(&[1, 2, 3]),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(vm.memory.heap_allocated_len(), heap);
        assert!(vm.private_memory_bytes.is_empty());
        let address = vm.alloc_host_private_tlv(&[1, 2, 3]).unwrap();
        assert_eq!(address, Memory::HEAP_START + heap);
        assert_eq!(
            vm.private_memory_bytes.pairs_for_testing(),
            &[(address, address + 3)]
        );
    }
    #[test]
    fn failed_private_scrub_retains_all_range_tags() {
        let mut vm = quiet_vm(1_000);
        let start = Memory::STACK_START;
        vm.memory.store_u8(start, 0xA5).unwrap();
        vm.private_memory_bytes
            .try_insert(start..start + 1)
            .unwrap();
        let invalid = vm.memory.stack_top();
        vm.private_memory_bytes
            .try_insert(invalid..invalid + 1)
            .unwrap();
        let before = vm.private_memory_bytes.try_clone().unwrap();
        assert_eq!(
            vm.scrub_private_memory(),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation
            ))
        );
        assert_eq!(vm.private_memory_bytes, before);
        assert_eq!(vm.memory.load_u8(start).unwrap(), 0xA5);
    }
    #[test]
    fn missing_allowed_syscall_metering_entry_fails_closed() {
        let number = crate::syscalls::SYSCALL_EXIT;
        assert!(crate::syscalls::is_syscall_allowed(
            SyscallPolicy::AbiV1,
            number
        ));
        assert_eq!(
            require_registered_syscall_metering(number, None),
            Err(VMError::UnknownSyscall(number))
        );
    }
    #[test]
    fn explicitly_allowed_generic_host_private_syscall_uses_reserved_metering() {
        struct ToolingHost {
            prepared: Cell<bool>,
            dispatched: bool,
        }
        impl IVMHost for ToolingHost {
            fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
                assert_eq!(number, 0x00FD_0001);
                self.prepared.set(true);
                Ok(0)
            }
            fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
                assert_eq!(number, 0x00FD_0001);
                self.dispatched = true;
                Ok(0)
            }
            fn allows_syscall(&self, policy: SyscallPolicy, number: u32) -> bool {
                number == 0x00FD_0001 || crate::syscalls::is_syscall_allowed(policy, number)
            }
            fn as_any(&mut self) -> &mut dyn Any
            where
                Self: 'static,
            {
                self
            }
        }
        let number = 0x00FD_0001;
        assert!(!crate::syscalls::is_syscall_allowed(
            SyscallPolicy::AbiV1,
            number
        ));
        assert!(!crate::syscalls::is_koto_test_syscall(number));
        assert!(host_syscall_metering_spec(SyscallPolicy::AbiV1, number).is_none());
        let mut code = Vec::new();
        code.extend_from_slice(&crate::encoding::wide::encode_syscallx(number).to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&code)
            .expect("load host-private syscall program");
        let mut host = ToolingHost {
            prepared: Cell::new(false),
            dispatched: false,
        };
        vm.run_with_host(&mut host)
            .expect("explicitly allowed host-private syscall must run");
        assert!(host.prepared.get());
        assert!(host.dispatched);
    }
    #[test]
    fn generic_program_admission_rejects_every_durable_state_syscall() {
        for syscall in [
            crate::syscalls::SYSCALL_STATE_GET,
            crate::syscalls::SYSCALL_STATE_SET,
            crate::syscalls::SYSCALL_STATE_DEL,
            crate::syscalls::SYSCALL_STATE_HAS,
            crate::syscalls::SYSCALL_STATE_LEN,
            crate::syscalls::SYSCALL_STATE_COUNT,
        ] {
            let mut program = ProgramMetadata::default().encode();
            program
                .extend_from_slice(&crate::encoding::wide::encode_syscallx(syscall).to_le_bytes());
            program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
            let mut vm = IVM::new(u64::MAX);
            assert_eq!(
                vm.load_program(&program),
                Err(VMError::GenericSyscallNotAllowed { syscall }),
                "generic admission accepted durable-state syscall {syscall:#08x}"
            );
        }
    }
    #[test]
    fn generic_program_unknown_syscalls_keep_the_unknown_syscall_error() {
        let syscall = 0x00FC_FFFF;
        assert!(!crate::syscalls::is_syscall_allowed(
            SyscallPolicy::AbiV1,
            syscall
        ));
        assert!(!crate::syscalls::is_koto_test_syscall(syscall));
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(&crate::encoding::wide::encode_syscallx(syscall).to_le_bytes());
        program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut admitted = IVM::new(u64::MAX);
        assert_eq!(
            admitted.load_program(&program),
            Err(VMError::UnknownSyscall(syscall))
        );
        let mut code = Vec::new();
        code.extend_from_slice(&crate::encoding::wide::encode_syscallx(syscall).to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut raw = IVM::new(u64::MAX);
        raw.load_code(&code).expect("load raw generic program");
        assert_eq!(raw.run(), Err(VMError::UnknownSyscall(syscall)));
    }
    #[test]
    fn raw_generic_execution_rejects_durable_state_before_host_dispatch() {
        struct DispatchSpy {
            prepared: Cell<bool>,
            dispatched: bool,
        }
        impl IVMHost for DispatchSpy {
            fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
                self.prepared.set(true);
                Ok(0)
            }
            fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
                self.dispatched = true;
                Ok(0)
            }
            fn as_any(&mut self) -> &mut dyn Any
            where
                Self: 'static,
            {
                self
            }
        }
        for syscall in [
            crate::syscalls::SYSCALL_STATE_GET,
            crate::syscalls::SYSCALL_STATE_SET,
            crate::syscalls::SYSCALL_STATE_DEL,
            crate::syscalls::SYSCALL_STATE_HAS,
            crate::syscalls::SYSCALL_STATE_LEN,
            crate::syscalls::SYSCALL_STATE_COUNT,
        ] {
            let mut code = Vec::new();
            code.extend_from_slice(&crate::encoding::wide::encode_syscallx(syscall).to_le_bytes());
            code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
            let mut vm = IVM::new(u64::MAX);
            vm.load_code(&code).expect("load raw generic program");
            let sentinel = 0xfeed_face_cafe_beef;
            vm.set_register(10, sentinel);
            let mut host = DispatchSpy {
                prepared: Cell::new(false),
                dispatched: false,
            };
            assert_eq!(
                vm.run_with_host(&mut host),
                Err(VMError::GenericSyscallNotAllowed { syscall })
            );
            assert!(
                !host.prepared.get(),
                "generic rejection must precede quoting"
            );
            assert!(!host.dispatched, "generic rejection must precede dispatch");
            assert_eq!(vm.register(10), sentinel, "failure published a result");
        }
    }
    #[test]
    fn permissive_host_cannot_enable_kotodama_test_syscalls_for_raw_code() {
        struct ToolingHost {
            prepared: Cell<bool>,
            dispatched: bool,
        }
        impl IVMHost for ToolingHost {
            fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
                self.prepared.set(true);
                Ok(0)
            }
            fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
                self.dispatched = true;
                Ok(0)
            }
            fn allows_syscall(&self, policy: SyscallPolicy, number: u32) -> bool {
                crate::syscalls::is_koto_test_syscall(number)
                    || crate::syscalls::is_syscall_allowed(policy, number)
            }
            fn as_any(&mut self) -> &mut dyn Any
            where
                Self: 'static,
            {
                self
            }
        }
        let number = crate::syscalls::SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS;
        let mut code = Vec::new();
        code.extend_from_slice(&crate::encoding::wide::encode_syscallx(number).to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&code)
            .expect("load raw Kotodama test-syscall program");
        let mut host = ToolingHost {
            prepared: Cell::new(false),
            dispatched: false,
        };
        assert_eq!(
            vm.run_with_host(&mut host),
            Err(VMError::UnknownSyscall(number))
        );
        assert!(!host.prepared.get());
        assert!(!host.dispatched);
    }
    #[test]
    fn public_syscall_privacy_boundaries_match_the_normative_abi_signatures() {
        fn count(declaration: &str, implicit_r10: bool) -> usize {
            let explicit = (10usize..=15)
                .rev()
                .find(|register| declaration.contains(&format!("r{register}")))
                .map_or(0, |register| register - 9);
            let declaration = declaration.strip_suffix('"').unwrap_or(declaration);
            if explicit == 0 && implicit_r10 && declaration != "-" {
                1
            } else {
                explicit
            }
        }
        assert_eq!(count("r10=value, r14=reserved", false), 5);
        assert_eq!(count("r10=value, r15=reserved", false), 6);
        let mut documented_inputs = BTreeMap::new();
        let mut documented_outputs = BTreeMap::new();
        let mut current_number = None;
        for line in include_str!("../spec/syscalls.toml").lines() {
            if let Some(raw) = line
                .strip_prefix("number = \"")
                .and_then(|raw| raw.strip_suffix('"'))
            {
                current_number = u32::from_str_radix(
                    raw.strip_prefix("0x")
                        .expect("syscall number is hexadecimal"),
                    16,
                )
                .ok();
                continue;
            }
            let Some(number) = current_number else {
                continue;
            };
            if let Some(arguments) = line.strip_prefix("args = \"") {
                assert!(
                    documented_inputs
                        .insert(number, count(arguments, false))
                        .is_none(),
                    "duplicate syscall input signature for {number:#x}"
                );
            } else if let Some(returns) = line.strip_prefix("ret = \"") {
                assert!(
                    documented_outputs
                        .insert(number, count(returns, true))
                        .is_none(),
                    "duplicate syscall output signature for {number:#x}"
                );
            }
        }
        for &number in crate::syscalls::abi_syscall_list() {
            let documented_input = *documented_inputs
                .get(&number)
                .unwrap_or_else(|| panic!("missing ABI input signature for syscall {number:#x}"));
            let documented_output = *documented_outputs
                .get(&number)
                .unwrap_or_else(|| panic!("missing ABI output signature for syscall {number:#x}"));
            let registers = |documented| match documented {
                0 => SYSCALL_ARGS_0,
                1 => SYSCALL_ARGS_1,
                2 => SYSCALL_ARGS_2,
                3 => SYSCALL_ARGS_3,
                4 => SYSCALL_ARGS_4,
                5 => SYSCALL_ARGS_5,
                6 => SYSCALL_ARGS_6,
                _ => panic!("unsupported ABI argument count {documented}"),
            };
            assert_eq!(
                syscall_public_input_registers(number),
                registers(documented_input),
                "privacy input boundary disagrees with the ABI signature for syscall {number:#x}"
            );
            assert_eq!(
                syscall_public_output_registers(number),
                registers(documented_output),
                "privacy output boundary disagrees with the ABI signature for syscall {number:#x}"
            );
        }
    }
    #[test]
    fn transfer_availability_syscall_stays_inside_the_abi_v1_public_window() {
        let inputs = syscall_public_input_registers(
            crate::syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
        );
        assert_eq!(inputs, &[10, 11, 12, 13, 14]);
        assert!(
            inputs.iter().all(|register| (10..=14).contains(register)),
            "availability syscall must never consume private or reserved r15"
        );
    }
    #[test]
    fn syscall_output_privacy_finalization_uses_only_normative_signatures() {
        let mut vm = IVM::new(u64::MAX);
        vm.set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        for register in 10..=12 {
            vm.registers.set_tag(register, true);
        }
        assert_eq!(
            vm.finalize_syscall_output_privacy(crate::syscalls::SYSCALL_STATE_SCAN),
            Err(VMError::PrivacyViolation)
        );
        for register in 10..=12 {
            assert!(
                vm.registers.tag(register),
                "privacy finalization laundered a secret host output in r{register}"
            );
        }
        for register in 10..=14 {
            vm.registers.set_tag(register, true);
        }
        vm.finalize_syscall_output_privacy(0x00ff_fffe)
            .expect("unknown syscall has no declared public outputs");
        for register in 10..=14 {
            assert!(
                vm.registers.tag(register),
                "unknown syscall declassified undocumented r{register}"
            );
        }
        vm.registers.set_tag(10, false);
        vm.finalize_syscall_output_privacy(crate::syscalls::SYSCALL_GET_PRIVATE_INPUT)
            .expect("private-input syscall explicitly classifies its result");
        assert!(vm.registers.tag(10));
    }
    #[test]
    fn ivm_is_send_sync_for_state_sharing() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<IVM>();
        assert_sync::<IVM>();
    }
    #[test]
    fn run_with_host_accepts_non_sync_host() {
        struct NonSyncHost(Cell<u64>);
        impl IVMHost for NonSyncHost {
            fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
                Ok(0)
            }
            fn syscall(&mut self, _number: u32, vm: &mut IVM) -> Result<u64, VMError> {
                let next = self.0.get().saturating_add(1);
                self.0.set(next);
                vm.set_register(10, next);
                Ok(0)
            }
            fn as_any(&mut self) -> &mut dyn Any
            where
                Self: 'static,
            {
                self
            }
        }
        let mut vm = IVM::new(u64::MAX);
        let mut host = NonSyncHost(Cell::new(0));
        let code = crate::encoding::wide::encode_halt().to_le_bytes();
        vm.load_code(&code).expect("load halt");
        vm.run_with_host(&mut host).expect("borrowed host runs");
    }
    #[test]
    fn builder_respects_deterministic_policy() {
        set_banner_enabled(false);
        let vm = IVM::deterministic_builder(u64::MAX)
            .suppress_startup_banner()
            .build();
        assert!(!vm.uses_cuda());
        assert!(!vm.uses_metal());
        assert_eq!(
            vm.acceleration_policy(),
            AccelerationPolicy::deterministic()
        );
    }
    #[test]
    fn deterministic_policy_disables_acceleration() {
        let policy = AccelerationPolicy::deterministic();
        assert!(!policy.allow_cuda());
        assert!(!policy.allow_metal());
    }
    fn program_with_imm(imm: i16) -> Vec<u8> {
        let mut bytes = ProgramMetadata::default().encode();
        let imm8 = imm.clamp(-128, 127) as i8;
        let add = crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 0, imm8);
        bytes.extend_from_slice(&add.to_le_bytes());
        bytes.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        bytes
    }
    fn unique_program() -> Vec<u8> {
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        let next = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        let imm = ((next % 2047) + 1) as i16;
        program_with_imm(imm)
    }
    #[test]
    fn execution_summary_is_stable_for_same_program() {
        set_banner_enabled(false);
        let program = program_with_imm(7);
        let config = IvmConfig::deterministic(u64::MAX);
        let mut first = IVM::new_with_config(config);
        first.load_program(&program).expect("first program loads");
        let mut second = first.try_clone_snapshot().expect("fund VM snapshot");
        second.host = Some(Box::new(crate::runtime::SyscallDispatcher::new(
            DefaultHost::new(),
        )));
        first.run().expect("first program runs");
        let first_summary = first.execution_summary();
        second.run().expect("second program runs");
        let second_summary = second.execution_summary();
        assert_eq!(first_summary, second_summary);
        assert_eq!(first_summary.version, EXECUTION_SUMMARY_VERSION_V1);
        assert_eq!(first_summary.code_hash, first.code_hash());
    }
    fn store_program_with_mode(mode: u8, max_cycles: u64) -> Vec<u8> {
        let metadata = ProgramMetadata {
            mode,
            max_cycles,
            abi_version: 1,
            ..ProgramMetadata::default()
        };
        let mut program = metadata.encode();
        let store =
            crate::encoding::wide::encode_store(instruction::wide::memory::STORE64, 1, 2, 0);
        program.extend_from_slice(&store.to_le_bytes());
        program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    #[test]
    fn non_zk_run_defers_memory_merkle_commit_until_root_is_requested() {
        let mut vm = quiet_vm(u64::MAX);
        vm.load_program(&store_program_with_mode(0, 0))
            .expect("program loads");
        let before = vm.memory.current_root();
        assert!(!vm.memory.dirty_for_testing());
        vm.set_register(1, Memory::HEAP_START);
        vm.set_register(2, 0xCAFE_BABE_DEAD_BEEFu64);
        vm.run().expect("program runs");
        assert!(
            vm.memory.dirty_for_testing(),
            "non-ZK execution should not rebuild the full memory Merkle tree eagerly"
        );
        let summary = vm.execution_summary();
        assert!(!vm.memory.dirty_for_testing());
        assert_ne!(summary.final_memory_root, *before.as_ref());
    }
    #[test]
    fn zk_run_with_trace_collection_disabled_defers_memory_merkle_commit() {
        let mut vm = quiet_vm(u64::MAX);
        vm.load_program(&store_program_with_mode(crate::ivm_mode::ZK, 4))
            .expect("program loads");
        vm.set_zk_trace_enabled(false);
        let before = vm.memory.current_root();
        assert!(!vm.memory.dirty_for_testing());
        vm.set_register(1, Memory::HEAP_START);
        vm.set_register(2, 0xABCD_EF01_2345_6789u64);
        vm.run().expect("program runs");
        assert!(
            vm.memory.dirty_for_testing(),
            "ZK semantic execution without trace collection should not rebuild the full memory Merkle tree eagerly"
        );
        let summary = vm.execution_summary();
        assert!(!vm.memory.dirty_for_testing());
        assert_ne!(summary.final_memory_root, *before.as_ref());
    }
    #[test]
    fn zk_trace_collection_is_disabled_by_default() {
        let vm = quiet_vm(u64::MAX);
        assert!(!vm.zk_trace_enabled());
    }
    #[test]
    fn explicitly_enabled_zk_trace_collection_commits_memory_merkle_root_before_returning() {
        let mut vm = quiet_vm(u64::MAX);
        vm.load_program(&store_program_with_mode(crate::ivm_mode::ZK, 4))
            .expect("program loads");
        vm.set_zk_trace_enabled(true);
        let before = vm.memory.current_root();
        assert!(!vm.memory.dirty_for_testing());
        vm.set_register(1, Memory::HEAP_START);
        vm.set_register(2, 0xABCD_EF01_2345_6789u64);
        vm.run().expect("program runs");
        assert!(
            !vm.memory.dirty_for_testing(),
            "ZK trace collection must keep the final memory root committed"
        );
        assert_ne!(*vm.memory.current_root().as_ref(), *before.as_ref());
    }
    fn empty_blob_tlv() -> Vec<u8> {
        use crate::pointer_abi::PointerType;
        let mut tlv = Vec::with_capacity(7 + iroha_crypto::Hash::LENGTH);
        tlv.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
        tlv.push(1);
        tlv.extend_from_slice(&0u32.to_be_bytes());
        let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new([]).into();
        tlv.extend_from_slice(&hash);
        tlv
    }
    fn quiet_vm(gas_limit: u64) -> IVM {
        set_banner_enabled(false);
        IVM::new(gas_limit)
    }
    fn program_with_literal_prefix() -> (Vec<u8>, usize) {
        let mut bytes = ProgramMetadata::default().encode();
        let header_len = bytes.len();
        let literal = empty_blob_tlv();
        bytes.extend_from_slice(&LITERAL_SECTION_MAGIC);
        bytes.extend_from_slice(&(1u32).to_le_bytes()); // one literal entry
        bytes.extend_from_slice(&1u32.to_le_bytes()); // align the executable code
        bytes.extend_from_slice(&(literal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&24u64.to_le_bytes()); // LTLB-relative TLV pointer
        bytes.extend_from_slice(&literal);
        bytes.push(0);
        let literal_prefix = bytes.len() - header_len;
        let addi = kotodama_lang::compiler::encode_addi(1, 1, 0).expect("encode addi");
        bytes.extend_from_slice(&addi.to_le_bytes());
        bytes.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        (bytes, literal_prefix)
    }
    fn program_with_indexed_literal(index: u16) -> (Vec<u8>, u64) {
        let mut bytes = ProgramMetadata::default().encode();
        let literal = empty_blob_tlv();
        bytes.extend_from_slice(&LITERAL_SECTION_MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(literal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&24u64.to_le_bytes());
        bytes.extend_from_slice(&literal);
        bytes.push(0);
        let load =
            crate::encoding::wide::encode_literal(instruction::wide::memory::LDLIT, 5, index);
        bytes.extend_from_slice(&load.to_le_bytes());
        bytes.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        (bytes, 24)
    }
    fn program_with_indexed_i64(value: i64, index: u16) -> Vec<u8> {
        let mut bytes = ProgramMetadata::default().encode();
        bytes.extend_from_slice(&LITERAL_SECTION_MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        let descriptor =
            crate::metadata::encode_literal_descriptor(crate::metadata::LiteralKindV1::I64, 24)
                .expect("small i64 literal offset");
        bytes.extend_from_slice(&descriptor.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        let load =
            crate::encoding::wide::encode_literal(instruction::wide::memory::LDI64, 5, index);
        bytes.extend_from_slice(&load.to_le_bytes());
        bytes.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        bytes
    }
    fn program_with_two_indexed_literals() -> (Vec<u8>, usize, [u64; 2]) {
        let mut bytes = ProgramMetadata::default().encode();
        let metadata_len = bytes.len();
        let first = empty_blob_tlv();
        let second = empty_blob_tlv();
        let offsets_len = 2 * 8;
        let data_len = first.len() + second.len();
        let post_pad = (4 - ((16 + offsets_len + data_len) % 4)) % 4;
        let offsets = [
            (16 + offsets_len) as u64,
            (16 + offsets_len + first.len()) as u64,
        ];
        bytes.extend_from_slice(&LITERAL_SECTION_MAGIC);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&(post_pad as u32).to_le_bytes());
        bytes.extend_from_slice(&(data_len as u32).to_le_bytes());
        let entries_start = metadata_len + 16;
        for offset in offsets {
            bytes.extend_from_slice(&offset.to_le_bytes());
        }
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);
        bytes.extend(std::iter::repeat_n(0, post_pad));
        bytes.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        (bytes, entries_start, offsets)
    }
    fn program_with_unaligned_contract_prefix() -> (Vec<u8>, usize) {
        let interface = crate::metadata::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![ivm_abi::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm_abi::call::CallSchemaV1::empty(),
                results: ivm_abi::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "ivm-runtime-tests".to_owned(),
            abi_hash: crate::syscalls::compute_abi_hash(crate::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![crate::metadata::EmbeddedEntrypointDescriptor {
                name: "inspect".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization:
                    iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let prefix = (1..=32)
            .map(|len| crate::metadata::EmbeddedContractInterfaceV1 {
                seiyaku_name: "TestContract".to_owned(),
                compiler_fingerprint: "x".repeat(len),
                ..interface.clone()
            })
            .map(|interface| interface.encode_section())
            .find(|section| !section.len().is_multiple_of(WIDE_INSTRUCTION_LEN as usize))
            .expect("CNTR section can produce an unaligned code prefix");
        let mut bytes = ProgramMetadata::default().encode();
        let prefix_len = prefix.len();
        bytes.extend_from_slice(&prefix);
        for word in [
            crate::encoding::wide::encode_store(instruction::wide::memory::STORE64, 12, 0, 0),
            crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 12, 0),
            crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 11, 0, 1),
            crate::encoding::wide::encode_ri(instruction::wide::control::JALR, 0, 1, 0),
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        (bytes, prefix_len)
    }
    #[test]
    fn prepared_instruction_stream_requires_exact_code_words_and_offsets() {
        let halt = crate::encoding::wide::encode_halt();
        let code = halt.to_le_bytes();
        let valid = [crate::ivm_cache::DecodedOp { pc: 0, inst: halt }];
        let wrong_word = [crate::ivm_cache::DecodedOp {
            pc: 0,
            inst: crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 0, 7),
        }];
        let wrong_pc = [crate::ivm_cache::DecodedOp { pc: 4, inst: halt }];

        // Reject inconsistency both before preparation and after a valid call
        // may have warmed the code-keyed prepared cache.
        assert!(matches!(
            prepare_instruction_stream(&code, &wrong_word, 0, &[], None),
            Err(VMError::DecodeError)
        ));
        assert!(prepare_instruction_stream(&code, &valid, 0, &[], None).is_ok());
        for decoded in [&wrong_word[..], &wrong_pc[..], &[][..]] {
            assert!(matches!(
                prepare_instruction_stream(&code, decoded, 0, &[], None),
                Err(VMError::DecodeError)
            ));
        }
        assert!(matches!(
            prepare_instruction_stream(&code[..3], &[], 0, &[], None),
            Err(VMError::DecodeError)
        ));
    }

    #[test]
    fn load_program_predecodes_instructions() {
        set_banner_enabled(false);
        ivm_cache::init_global_with_capacity(64);
        let program = unique_program();
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("program loads");
        assert!(vm.predecoded.is_some());
        assert!(vm.prepared_contains_pc(vm.pc));
        let decoded_len = vm
            .predecoded
            .as_ref()
            .map(|ops| ops.len())
            .unwrap_or_default();
        let prepared_len = vm
            .prepared
            .as_ref()
            .map(|prepared| prepared.ops.len())
            .unwrap_or_default();
        assert_eq!(prepared_len, decoded_len);
    }
    #[test]
    fn indexed_literal_load_returns_prevalidated_tlv_pointer() {
        set_banner_enabled(false);
        let (program, expected_pointer) = program_with_indexed_literal(0);
        let mut vm = IVM::new(1);
        vm.load_program(&program)
            .expect("indexed literal program loads");
        vm.run().expect("indexed literal program runs");
        assert_eq!(vm.register(5), expected_pointer);
        let literal = vm
            .memory
            .load_region(expected_pointer, empty_blob_tlv().len() as u64)
            .expect("literal pointer resolves inside code memory");
        let tlv = crate::pointer_abi::validate_tlv_bytes(literal)
            .expect("loader-validated pointer remains a valid TLV");
        assert_eq!(tlv.type_id, crate::pointer_abi::PointerType::Blob);
        assert_eq!(vm.remaining_gas(), 0, "LDLIT has a one-gas base cost");
    }
    #[test]
    fn indexed_i64_load_executes_signed_boundaries() {
        set_banner_enabled(false);
        for value in [i64::MIN, -1, 0, 1, i64::MAX] {
            let program = program_with_indexed_i64(value, 0);
            let mut vm = IVM::new(1);
            vm.load_program(&program)
                .expect("indexed i64 program loads");
            vm.run().expect("indexed i64 program runs");
            assert_eq!(vm.register(5) as i64, value);
            assert_eq!(vm.remaining_gas(), 0, "LDI64 has one-gas base cost");
        }
    }
    #[test]
    fn indexed_i64_never_grants_pointer_provenance() {
        set_banner_enabled(false);
        let program = program_with_indexed_i64(24, 0);
        let mut vm = IVM::new(1);
        vm.load_program(&program)
            .expect("indexed i64 program loads");
        assert!(!vm.is_validated_literal_pointer(24));
        assert!(matches!(vm.validate_tlv(24), Err(VMError::NoritoInvalid)));
        vm.run().expect("indexed i64 program runs");
        assert_eq!(vm.register(5), 24);
    }
    #[test]
    fn code_hash_binds_indexed_i64_kind_and_payload() {
        let original = program_with_indexed_i64(7, 0);
        let metadata_len = ProgramMetadata::default().encode().len();
        let mut kind_mutation = original.clone();
        kind_mutation[metadata_len + 16 + 7] = 0;
        let mut payload_mutation = original.clone();
        payload_mutation[metadata_len + 16 + 8] ^= 1;
        let original_hash = crate::metadata::contract_code_hash(&original);
        for mutation in [&kind_mutation, &payload_mutation] {
            assert_ne!(crate::metadata::contract_code_hash(mutation), original_hash);
        }
    }
    #[test]
    fn indexed_program_metadata_rejections_are_fail_closed() {
        let mut case_groups = vec![(
            "indexed_i64_out_of_range_is_rejected_at_load",
            vec![program_with_indexed_i64(7, 1)],
        )];
        let (mut pointer_program, _) = program_with_indexed_literal(0);
        let pointer_code = pointer_program.len() - 8;
        let ldi64 = crate::encoding::wide::encode_literal(instruction::wide::memory::LDI64, 5, 0);
        pointer_program[pointer_code..pointer_code + 4].copy_from_slice(&ldi64.to_le_bytes());
        let mut scalar_program = program_with_indexed_i64(7, 0);
        let scalar_code = scalar_program.len() - 8;
        let ldlit = crate::encoding::wide::encode_literal(instruction::wide::memory::LDLIT, 5, 0);
        scalar_program[scalar_code..scalar_code + 4].copy_from_slice(&ldlit.to_le_bytes());
        case_groups.push((
            "indexed_literal_opcode_kind_mismatch_is_rejected_at_load",
            vec![pointer_program, scalar_program],
        ));
        let metadata_len = ProgramMetadata::default().encode().len();
        let mut unknown_kind = program_with_indexed_i64(7, 0);
        let descriptor = metadata_len + 16;
        unknown_kind[descriptor + 7] = 0xff;
        let canonical = program_with_indexed_i64(7, 0);
        let mut short = canonical.clone();
        short[metadata_len + 8..metadata_len + 12].copy_from_slice(&1u32.to_le_bytes());
        short[metadata_len + 12..metadata_len + 16].copy_from_slice(&7u32.to_le_bytes());
        let mut long = canonical;
        long[metadata_len + 12..metadata_len + 16].copy_from_slice(&9u32.to_le_bytes());
        long[metadata_len + 8..metadata_len + 12].copy_from_slice(&3u32.to_le_bytes());
        let data_end = metadata_len + 16 + 8 + 8;
        long.splice(data_end..data_end, [0; 4]);
        case_groups.push((
            "indexed_i64_rejects_unknown_kind_and_wrong_length",
            vec![unknown_kind, short, long],
        ));
        case_groups.push((
            "indexed_literal_out_of_range_is_rejected_at_load",
            vec![program_with_indexed_literal(1).0],
        ));
        let (mut program, _) = program_with_indexed_literal(0);
        let entry_start = ProgramMetadata::default().encode().len() + 16;
        program[entry_start..entry_start + 8].copy_from_slice(&0u64.to_le_bytes());
        case_groups.push((
            "indexed_literal_table_target_must_point_into_typed_data",
            vec![program],
        ));
        let (canonical, entries_start, offsets) = program_with_two_indexed_literals();
        let mut duplicate_and_reordered = Vec::new();
        for entries in [[offsets[0], offsets[0]], [offsets[1], offsets[0]]] {
            let mut program = canonical.clone();
            program[entries_start..entries_start + 8].copy_from_slice(&entries[0].to_le_bytes());
            program[entries_start + 8..entries_start + 16]
                .copy_from_slice(&entries[1].to_le_bytes());
            duplicate_and_reordered.push(program);
        }
        case_groups.push((
            "indexed_literal_table_rejects_duplicate_and_reordered_targets",
            duplicate_and_reordered,
        ));
        let (canonical, entries_start, offsets) = program_with_two_indexed_literals();
        let mut leading_gap = canonical.clone();
        leading_gap[entries_start..entries_start + 8]
            .copy_from_slice(&(offsets[0] + 1).to_le_bytes());
        let mut interior_target = canonical.clone();
        interior_target[entries_start + 8..entries_start + 16]
            .copy_from_slice(&(offsets[0] + 1).to_le_bytes());
        let (mut bad_hash, _) = program_with_indexed_literal(0);
        let hash_byte = ProgramMetadata::default().encode().len() + 16 + 8 + 7;
        bad_hash[hash_byte] ^= 1;
        case_groups.push((
            "indexed_literal_table_rejects_gaps_interior_targets_and_bad_pointer_hashes",
            vec![leading_gap, interior_target, bad_hash],
        ));
        assert_eq!(case_groups.len(), 7, "indexed admission case inventory");
        set_banner_enabled(false);
        for (case_id, programs) in case_groups {
            for program in programs {
                let mut vm = IVM::new(u64::MAX);
                assert!(
                    matches!(vm.load_program(&program), Err(VMError::InvalidMetadata)),
                    "indexed admission case {case_id} did not fail closed"
                );
            }
        }
    }
    #[test]
    fn pointer_validation_rejects_nonliteral_code_addresses() {
        set_banner_enabled(false);
        let (program, literal_pointer) = program_with_indexed_literal(0);
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("literal program loads");
        vm.validate_tlv(literal_pointer)
            .expect("indexed literal start is owned program data");
        assert!(matches!(
            vm.validate_tlv(literal_pointer + 1),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            vm.validate_tlv(vm.pc()),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn signed24_call_transfer_uses_implicit_link_register() {
        set_banner_enabled(false);
        let call = crate::encoding::wide::encode_offset24(instruction::wide::control::JALS, 2);
        let halt = crate::encoding::encode_halt();
        let body = crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 7, 0, 9);
        let ret = crate::encoding::wide::encode_rr(instruction::wide::control::JALR, 0, 1, 0);
        let code = [call, halt, body, ret]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&code).expect("compact call code loads");
        vm.run().expect("compact call returns to halt");
        assert_eq!(vm.register(1), 4);
        assert_eq!(vm.register(7), 9);
    }
    #[test]
    fn signed24_jump_sign_extends_negative_offset() {
        set_banner_enabled(false);
        let enter = crate::encoding::wide::encode_jump(instruction::wide::control::JAL, 0, 2);
        let halt = crate::encoding::encode_halt();
        let body = crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 7, 0, 9);
        let jump_back = crate::encoding::wide::encode_offset24(instruction::wide::control::JMP, -2);
        let code = [enter, halt, body, jump_back]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&code).expect("compact jump code loads");
        vm.run().expect("negative compact jump reaches halt");
        assert_eq!(vm.register(7), 9);
    }
    mod read_deferrals;
    mod runtime_memory;

    #[test]
    fn raw_code_resets_the_prior_program_execution_profile() {
        set_banner_enabled(false);
        let metadata = ProgramMetadata {
            mode: crate::metadata::mode::VECTOR | crate::metadata::mode::ZK,
            vector_length: 8,
            max_cycles: 7,
            ..ProgramMetadata::default()
        };
        let mut profiled_program = metadata.encode();
        profiled_program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut reused = IVM::new(u64::MAX);
        reused
            .load_program(&profiled_program)
            .expect("profiled program loads");
        assert!(reused.vector_enabled);
        assert!(reused.zk_mode_enabled());
        reused.pc_alignment = 3;
        reused.cycles = 9;
        reused.request_contract_abort(
            "Test".to_owned(),
            "Rejected".to_owned(),
            "test::Error".to_owned(),
            [0; 32],
            17,
            None,
        );
        let mut raw = Vec::new();
        raw.extend_from_slice(
            &crate::encoding::wide::encode_rr(instruction::wide::crypto::SETVL, 0, 0, 8)
                .to_le_bytes(),
        );
        raw.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        reused.load_code(&raw).expect("raw code loads");
        assert_eq!(reused.metadata.mode, 0);
        assert!(!reused.vector_enabled);
        assert!(!reused.zk_mode_enabled());
        assert_eq!(reused.max_cycles, 0);
        assert_eq!(reused.vector_length(), default_vector_length());
        assert_eq!(reused.pc_alignment, 0);
        assert_eq!(reused.cycles, 0);
        assert!(!reused.halted);
        assert!(!reused.constraint_failed);
        assert_eq!(reused.contract_abort_error, None);
        let reused_result = reused.run();
        let mut fresh = IVM::new(u64::MAX);
        fresh.load_code(&raw).expect("raw code loads in fresh VM");
        let fresh_result = fresh.run();
        assert_eq!(reused_result, fresh_result);
        assert_eq!(fresh_result, Err(VMError::VectorExtensionDisabled));
    }
    #[test]
    fn deployable_contract_rejects_noncanonical_indirect_control_flow_at_admission() {
        set_banner_enabled(false);
        let (mut program, _) = program_with_unaligned_contract_prefix();
        let indirect = crate::encoding::wide::encode_rr(instruction::wide::control::JALR, 0, 2, 0);
        let instruction_start = program.len() - WIDE_INSTRUCTION_LEN as usize;
        program[instruction_start..].copy_from_slice(&indirect.to_le_bytes());
        let mut vm = IVM::new(u64::MAX);
        assert_eq!(
            vm.load_program(&program),
            Err(VMError::InvalidMetadata),
            "unverifiable indirect control flow must fail before execution"
        );
    }
    #[test]
    fn loaded_program_prefix_is_not_executable() {
        set_banner_enabled(false);
        let (program, literal_prefix) = program_with_literal_prefix();
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program)
            .expect("program with literals loads");
        assert!(literal_prefix > 0);
        vm.pc = 0;
        let err = vm.run().expect_err("literal prefix must not execute");
        assert!(matches!(
            err,
            VMError::MemoryAccessViolation {
                perm: Perm::EXECUTE,
                ..
            }
        ));
    }
    #[test]
    fn fallthrough_without_explicit_termination_is_error() {
        set_banner_enabled(false);
        let addi = crate::encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 1, 0, 7);
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&addi.to_le_bytes()).expect("load raw code");
        let err = vm.run().expect_err("fallthrough must trap");
        assert!(matches!(err, VMError::MissingHalt));
    }
    #[test]
    fn scallx_dispatches_extended_syscall_id() {
        struct RecordingHost {
            seen: Option<u32>,
        }
        impl IVMHost for RecordingHost {
            fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
                Ok(0)
            }
            fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
                self.seen = Some(number);
                vm.set_register(10, u64::from(number));
                Ok(0)
            }
            fn as_any(&mut self) -> &mut dyn std::any::Any
            where
                Self: 'static,
            {
                self
            }
        }
        set_banner_enabled(false);
        let syscall = crate::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS;
        let mut code = Vec::new();
        code.extend_from_slice(&crate::encoding::wide::encode_syscallx(syscall).to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        let mut vm = IVM::new(u64::MAX);
        vm.load_code(&code).expect("load raw code");
        let mut host = RecordingHost { seen: None };
        vm.run_with_host(&mut host).expect("SCALLX program runs");
        assert_eq!(host.seen, Some(syscall));
        assert_eq!(vm.register(10), u64::from(syscall));
    }
    #[test]
    fn load_program_rejects_non_v1_abi_version() {
        let mut vm = quiet_vm(u64::MAX);
        let mut program = ProgramMetadata::default_for(1, 1, 1).encode();
        assert_eq!(program.len(), crate::HEADER_SIZE);
        program[16] = 2;
        program.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        assert_eq!(
            vm.load_program(&program),
            Err(VMError::UnsupportedProgramAbiVersion { version: 2 })
        );
    }
    #[test]
    fn recompute_input_bump_handles_empty_tlv() {
        let mut vm = quiet_vm(u64::MAX);
        let tlv = empty_blob_tlv();
        vm.memory.preload_input(0, &tlv).expect("preload empty TLV");
        let mut program = ProgramMetadata::default().encode();
        program.extend_from_slice(&crate::encoding::encode_halt().to_le_bytes());
        vm.load_program(&program)
            .expect("load program with TLV scan");
        let new_tlv = empty_blob_tlv();
        let ptr = vm.alloc_input_tlv(&new_tlv).expect("allocate second TLV");
        assert!(ptr > Memory::INPUT_START);
        let mut buf = vec![0u8; tlv.len()];
        vm.memory
            .load_bytes(Memory::INPUT_START, &mut buf)
            .expect("read first TLV");
        assert_eq!(buf, tlv);
    }
    #[test]
    fn alloc_host_tlv_prefers_input_when_space_is_available() {
        let mut vm = quiet_vm(u64::MAX);
        let tlv = empty_blob_tlv();
        let ptr = vm.alloc_host_tlv(&tlv).expect("allocate host TLV");
        assert!(
            (Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&ptr),
            "host TLV should stay in input while space remains"
        );
        assert_eq!(ptr, Memory::INPUT_START);
        let loaded = vm
            .memory
            .load_region(ptr, tlv.len() as u64)
            .expect("read input TLV");
        assert_eq!(loaded, tlv);
    }
    #[test]
    fn alloc_host_tlv_spills_to_heap_after_input_fills() {
        let mut vm = quiet_vm(u64::MAX);
        let filler = vec![0u8; Memory::INPUT_SIZE as usize];
        vm.alloc_input_tlv(&filler)
            .expect("fill the input allocator exactly");
        let tlv = empty_blob_tlv();
        let ptr = vm.alloc_host_tlv(&tlv).expect("spill host TLV to heap");
        assert!(
            (Memory::HEAP_START..Memory::INPUT_START).contains(&ptr),
            "host spill pointer should land in heap"
        );
        let spilled = vm.validate_tlv(ptr).expect("validate owned heap TLV");
        assert_eq!(spilled.type_id, crate::pointer_abi::PointerType::Blob);
        assert!(spilled.payload.is_empty());
    }
    #[test]
    fn alloc_host_tlv_spills_when_input_tail_cannot_fit_next_tlv() {
        let mut vm = quiet_vm(u64::MAX);
        let tlv = empty_blob_tlv();
        let filler = vec![0u8; Memory::INPUT_SIZE as usize - (tlv.len() - 1)];
        vm.alloc_input_tlv(&filler)
            .expect("leave a too-small tail in the input allocator");
        let ptr = vm
            .alloc_host_tlv(&tlv)
            .expect("spill host TLV when the remaining input tail is too small");
        assert!(
            (Memory::HEAP_START..Memory::INPUT_START).contains(&ptr),
            "host spill pointer should land in heap when only an undersized input tail remains"
        );
        let spilled = vm.validate_tlv(ptr).expect("validate owned heap TLV");
        assert_eq!(spilled.type_id, crate::pointer_abi::PointerType::Blob);
        assert!(spilled.payload.is_empty());
    }
    #[test]
    fn alloc_host_tlv_propagates_out_of_memory_when_heap_spill_cannot_fit() {
        let mut vm = quiet_vm(u64::MAX);
        let filler = vec![0u8; Memory::INPUT_SIZE as usize];
        vm.alloc_input_tlv(&filler)
            .expect("fill the input allocator exactly");
        vm.memory
            .set_heap_limit(0)
            .expect("shrink heap limit to zero");
        let err = vm
            .alloc_host_tlv(&empty_blob_tlv())
            .expect_err("host TLV spill should fail without heap space");
        assert!(matches!(err, VMError::OutOfMemory));
    }
    #[test]
    fn host_tlv_preflight_honors_exact_heap_reservation_without_partial_state() {
        set_banner_enabled(false);
        let small_tlv_len = empty_blob_tlv().len();
        IVM::preflight_fresh_host_tlv_allocations_with_reserved_heap(
            &[small_tlv_len],
            Memory::HEAP_SIZE,
        )
        .expect("an INPUT-only TLV must coexist with an exact full-HEAP reservation");
        assert!(matches!(
            IVM::preflight_fresh_host_tlv_allocations_with_reserved_heap(
                &[small_tlv_len],
                Memory::HEAP_SIZE + 1,
            ),
            Err(VMError::OutOfMemory)
        ));
        let vm = IVM::new(u64::MAX);
        let input_before = vm.input_bump_next;
        let heap_before = vm.memory.heap_allocated_len();
        assert!(matches!(
            vm.preflight_host_tlv_allocations_with_reserved_heap(
                &[Memory::INPUT_SIZE as usize, small_tlv_len],
                Memory::HEAP_SIZE,
            ),
            Err(VMError::OutOfMemory)
        ));
        assert_eq!(vm.input_bump_next, input_before);
        assert_eq!(vm.memory.heap_allocated_len(), heap_before);
    }
    #[test]
    fn owned_tlv_validation_rejects_unallocated_heap_bytes() {
        let mut vm = quiet_vm(u64::MAX);
        let tlv = empty_blob_tlv();
        vm.store_bytes(Memory::HEAP_START, &tlv)
            .expect("write well-formed bytes into unallocated heap capacity");
        assert!(matches!(
            vm.validate_tlv(Memory::HEAP_START),
            Err(VMError::NoritoInvalid)
        ));
        let ptr = vm
            .alloc_heap(u64::try_from(tlv.len()).expect("TLV length fits u64"))
            .expect("claim the heap prefix containing the envelope");
        assert_eq!(ptr, Memory::HEAP_START);
        vm.validate_tlv(ptr)
            .expect("the same envelope is valid after its heap range is owned");
    }
    #[test]
    fn input_tlv_validation_is_provenance_strict_and_region_specific() {
        set_banner_enabled(false);
        let tlv = empty_blob_tlv();
        let mut vm = IVM::new(u64::MAX);
        let input = vm.alloc_input_tlv(&tlv).expect("allocate INPUT envelope");
        vm.validate_input_tlv(input)
            .expect("accept an owned INPUT envelope");
        let heap = vm
            .alloc_heap(u64::try_from(tlv.len()).expect("TLV length fits u64"))
            .expect("allocate HEAP envelope");
        vm.store_bytes(heap, &tlv).expect("store HEAP envelope");
        vm.validate_tlv(heap)
            .expect("the central decoder accepts allocated HEAP");
        assert!(matches!(
            vm.validate_input_tlv(heap),
            Err(VMError::NoritoInvalid)
        ));
        vm.store_bytes(Memory::OUTPUT_START, &tlv)
            .expect("store adversarial OUTPUT envelope");
        assert!(matches!(
            vm.validate_input_tlv(Memory::OUTPUT_START),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn argument_decode_escrow_requires_the_exact_prepaid_cost() {
        let mut vm = quiet_vm(100);
        vm.prepay_argument_decode(40)
            .expect("escrow argument decode gas");
        assert_eq!(vm.remaining_gas(), 60);
        assert!(vm.argument_decode_is_prepaid(40));
        assert!(!vm.argument_decode_is_prepaid(41));
        assert_eq!(
            vm.consume_prepaid_argument_decode(41),
            Err(VMError::DecodeError)
        );
        assert!(
            vm.argument_decode_is_prepaid(40),
            "a mismatched consumer must not discard the valid escrow"
        );
        vm.consume_prepaid_argument_decode(40)
            .expect("consume matching argument decode escrow");
        assert!(!vm.argument_decode_is_prepaid(40));
    }
    #[test]
    fn run_prefers_predecoded_instructions() {
        set_banner_enabled(false);
        ivm_cache::init_global_with_capacity(64);
        let program = program_with_imm(1);
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program).expect("program loads");
        vm.reset_predecode_misses();
        vm.run().expect("run succeeds");
        assert_eq!(vm.predecode_misses(), 0);
        vm.load_program(&program).expect("reload succeeds");
        vm.reset_predecode_misses();
        vm.run().expect("second run succeeds");
        assert_eq!(vm.predecode_misses(), 0);
    }
    #[test]
    fn runtime_trap_populates_last_diagnostic() {
        set_banner_enabled(false);
        // A durable write survives optimization and guarantees that execution
        // reaches a metered instruction; an otherwise empty contract is HALT-only.
        let source = r#"
seiyaku Demo {
  state int value;

  hajimari() {
    value = 1;
  }
}
"#;
        let output = kotodama_lang::session::CompilerSession::default()
            .build(kotodama_lang::session::CompileRequest {
                source,
                source_name: Some("contracts/runtime_trap.ko"),
            })
            .expect("compile kotodama source");
        assert!(!output.report.source_map.is_empty());
        assert!(output.report.source_map.iter().all(|entry| {
            entry.source.source_path.as_deref() == Some("contracts/runtime_trap.ko")
        }));
        let metadata = ProgramMetadata::parse(&output.artifact).expect("parse compiled metadata");
        let lifecycle = metadata
            .contract_interface
            .as_ref()
            .and_then(|interface| {
                interface
                    .entrypoints
                    .iter()
                    .find(|entrypoint| entrypoint.name == "hajimari")
            })
            .expect("compiled hajimari entrypoint");
        let entrypoint_pc = u64::try_from(metadata.prefix_len())
            .expect("metadata prefix fits u64")
            .checked_add(lifecycle.entry_pc)
            .expect("entrypoint PC fits u64");
        let mut vm = IVM::new(0);
        vm.load_program(&output.artifact)
            .expect("load compiled program");
        vm.set_program_counter(entrypoint_pc)
            .expect("select hajimari entrypoint");
        let err = vm.run().expect_err("zero gas should trap");
        assert_eq!(err, VMError::OutOfGas);
        let diag = vm.last_diagnostic().expect("diagnostic should be captured");
        assert_eq!(diag.trap_kind, VmTrapKind::OutOfGas);
        assert_eq!(diag.budget.gas_limit, 0);
        assert_eq!(diag.context.entrypoint_pc, Some(entrypoint_pc));
        assert!(
            diag.source.is_none(),
            "deployable artifacts exclude source maps; tooling resolves the hash-keyed sidecar"
        );
    }
    #[test]
    fn missing_halt_classifies_as_missing_halt_trap() {
        assert_eq!(
            IVM::classify_trap(&VMError::MissingHalt),
            VmTrapKind::MissingHalt
        );
    }
    #[test]
    fn host_output_budget_error_has_a_distinct_trap_kind() {
        let error = VMError::HostOutputBudgetExceeded {
            resource: crate::HostOutputResource::Bytes,
            attempted: 9,
            limit: 8,
        };
        assert_eq!(
            IVM::classify_trap(&error),
            VmTrapKind::HostOutputBudgetExceeded
        );
    }
    #[test]
    fn unsupported_program_metadata_errors_preserve_exact_trap_kind() {
        let cases = [
            (
                VMError::UnsupportedProgramVersion { major: 2, minor: 0 },
                VmTrapKind::UnsupportedProgramVersion,
            ),
            (
                VMError::UnsupportedProgramFeatureBits { bits: 0x80 },
                VmTrapKind::UnsupportedProgramFeatureBits,
            ),
            (
                VMError::UnsupportedProgramAbiVersion { version: 2 },
                VmTrapKind::UnsupportedProgramAbiVersion,
            ),
            (
                VMError::ProgramVectorLengthTooLarge {
                    vector_length: u8::MAX,
                    max_allowed: 64,
                },
                VmTrapKind::ProgramVectorLengthTooLarge,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(IVM::classify_trap(&error), expected);
        }
    }
    #[test]
    fn metered_trap_classifies_as_source_error() {
        let err = VMError::metered(17, VMError::PermissionDenied);
        assert_eq!(IVM::classify_trap(&err), VmTrapKind::PermissionDenied);
    }
    #[test]
    fn hardware_capabilities_consistent_with_usage() {
        set_banner_enabled(false);
        let vm = IVM::builder(u64::MAX).suppress_startup_banner().build();
        let caps = vm.hardware_capabilities();
        if vm.uses_cuda() {
            assert!(caps.cuda_available());
        }
        if vm.uses_metal() {
            assert!(caps.metal_available());
        }
    }
    #[test]
    fn builder_can_override_capabilities() {
        set_banner_enabled(false);
        let disabled_caps = HardwareCapabilities::none();
        let vm = IVM::builder(u64::MAX)
            .with_capabilities(disabled_caps)
            .with_acceleration(AccelerationPolicy::new(true, true))
            .suppress_startup_banner()
            .build();
        assert_eq!(vm.hardware_capabilities(), disabled_caps);
        assert!(!vm.uses_cuda());
        assert!(!vm.uses_metal());
        let enabled_cuda = HardwareCapabilities::new(true, false);
        let vm = IVM::builder(u64::MAX)
            .with_capabilities(enabled_cuda)
            .with_acceleration(AccelerationPolicy::new(true, false))
            .suppress_startup_banner()
            .build();
        assert_eq!(vm.hardware_capabilities(), enabled_cuda);
        assert!(vm.uses_cuda());
        assert!(!vm.uses_metal());
    }
    #[test]
    fn builder_config_roundtrip() {
        set_banner_enabled(false);
        let (cfg, builder) = IvmBuilder::deterministic_config_suppressed(2048);
        let builder = builder.map_capabilities_builder(|_| HardwareCapabilities::new(true, false));
        let snapshot = builder.config();
        let expected_cfg = cfg.map_capabilities(|_| HardwareCapabilities::new(true, false));
        assert_eq!(snapshot.gas_limit(), 2048);
        assert_eq!(snapshot.acceleration(), AccelerationPolicy::deterministic());
        assert_eq!(
            snapshot.capabilities(),
            HardwareCapabilities::new(true, false)
        );
        assert_eq!(expected_cfg, snapshot);
        let vm = IVM::new_with_config(snapshot);
        assert_eq!(vm.remaining_gas(), 2048);
        assert_eq!(
            vm.acceleration_policy(),
            AccelerationPolicy::deterministic()
        );
    }
    #[test]
    fn builder_gas_limit_getter_tracks_updates() {
        set_banner_enabled(false);
        let mut builder = IVM::with_config(IvmConfig::adaptive(100)).suppress_startup_banner();
        builder
            .set_acceleration(AccelerationPolicy::adaptive())
            .map_config(|cfg| cfg.with_acceleration(AccelerationPolicy::adaptive()));
        assert_eq!(builder.gas_limit(), 100);
        builder.set_gas_limit(500).map_config(|cfg| {
            IvmConfigBuilder::from_config(cfg)
                .with_gas_limit(500)
                .build()
        });
        assert_eq!(builder.gas_limit(), 500);
        let vm = builder.build();
        assert_eq!(vm.remaining_gas(), 500);
    }
    #[test]
    fn config_builder_conversion_allows_roundtrip_editing() {
        set_banner_enabled(false);
        let builder = IVM::builder(256)
            .with_gas_limit(300)
            .suppress_startup_banner();
        assert_eq!(builder.config().gas_limit(), 300);
        let final_cfg = builder.build_config().builder().with_gas_limit(350).build();
        let (cfg, vm) = IVM::with_config(final_cfg)
            .suppress_startup_banner()
            .build_with_config();
        assert_eq!(vm.remaining_gas(), 350);
        let vm2 = IVM::with_config(cfg).suppress_startup_banner().build();
        assert_eq!(vm2.remaining_gas(), 350);
    }
    #[test]
    fn new_with_config_respects_settings() {
        set_banner_enabled(false);
        let config = IvmConfig::new(256)
            .with_acceleration(AccelerationPolicy::deterministic())
            .with_capabilities(HardwareCapabilities::none());
        let vm = IVM::new_with_config(config);
        assert_eq!(vm.remaining_gas(), 256);
        assert_eq!(
            vm.acceleration_policy(),
            AccelerationPolicy::deterministic()
        );
        assert_eq!(vm.hardware_capabilities(), HardwareCapabilities::none());
        assert!(!vm.uses_cuda());
        assert!(!vm.uses_metal());
    }
    #[test]
    fn config_builder_presets() {
        set_banner_enabled(false);
        let deterministic = IvmConfigBuilder::deterministic(300).build();
        assert_eq!(deterministic.gas_limit(), 300);
        assert_eq!(
            deterministic.acceleration(),
            AccelerationPolicy::deterministic()
        );
        let adaptive = IvmConfigBuilder::adaptive(400)
            .with_capabilities(HardwareCapabilities::none())
            .build();
        assert_eq!(adaptive.gas_limit(), 400);
        assert_eq!(adaptive.acceleration(), AccelerationPolicy::adaptive());
        assert_eq!(adaptive.capabilities(), HardwareCapabilities::none());
    }
    #[test]
    fn stack_limit_for_gas_uses_immutable_v1_policy() {
        set_banner_enabled(false);
        let cfg = IvmConfig::adaptive(100_000);
        assert_eq!(cfg.stack_policy(), IvmStackPolicy::V1);
        assert_eq!(cfg.stack_limit_for_gas(), 400_000);
        assert_eq!(
            IvmConfig::adaptive(0).stack_limit_for_gas(),
            IvmStackPolicy::V1.minimum_stack_bytes()
        );
        assert_eq!(
            IvmConfig::adaptive(u64::MAX).stack_limit_for_gas(),
            IvmStackPolicy::V1.maximum_stack_bytes()
        );
    }
    #[test]
    fn config_capability_mapping_helper() {
        set_banner_enabled(false);
        let cfg = IvmConfig::adaptive(100).map_capabilities(|caps| caps);
        let builder = IVM::builder(100)
            .map_capabilities_builder(|caps| caps)
            .suppress_startup_banner();
        assert_eq!(cfg.capabilities(), builder.config().capabilities());
    }
    #[test]
    fn config_forced_simd_overrides_detection() {
        set_banner_enabled(false);
        let _simd_guard = vector::forced_simd_test_lock();
        let prev = vector::set_thread_forced_simd(None);
        let cfg = IvmConfig::adaptive(128).with_forced_simd(Some(SimdChoice::Scalar));
        let vm = IVM::with_config(cfg).suppress_startup_banner().build();
        assert_eq!(
            vm.acceleration_policy().forced_simd(),
            Some(SimdChoice::Scalar)
        );
        assert_eq!(vector::simd_choice(), SimdChoice::Scalar);
        match prev {
            Some(choice) => {
                vector::set_thread_forced_simd(Some(choice));
            }
            None => vector::clear_thread_forced_simd(),
        }
    }
    #[test]
    fn adaptive_config_suppressed_helpers() {
        set_banner_enabled(false);
        let (cfg, builder) = IvmBuilder::adaptive_config_suppressed(700);
        assert_eq!(cfg.gas_limit(), 700);
        let (returned_cfg, vm) = builder.build_with_config();
        assert_eq!(returned_cfg.gas_limit(), 700);
        assert_eq!(vm.remaining_gas(), 700);
        let vm2 = IVM::with_config(returned_cfg)
            .suppress_startup_banner()
            .build();
        assert_eq!(vm2.remaining_gas(), 700);
    }
    #[test]
    fn config_into_builder_conversions() {
        set_banner_enabled(false);
        let cfg = IvmConfig::deterministic(123);
        let builder_from_config = IvmBuilder::from(cfg);
        assert_eq!(builder_from_config.config(), cfg);
        let cfg_builder = cfg.builder().with_gas_limit(456);
        let builder_from_builder = IvmBuilder::from(cfg_builder);
        assert_eq!(builder_from_builder.config().gas_limit(), 456);
    }
    #[test]
    fn set_acceleration_policy_updates_policy_snapshot() {
        set_banner_enabled(false);
        let mut vm = IVM::builder(u64::MAX)
            .suppress_startup_banner()
            .with_acceleration(AccelerationPolicy::deterministic())
            .build();
        assert_eq!(
            vm.acceleration_policy(),
            AccelerationPolicy::deterministic()
        );
        let policy = AccelerationPolicy::new(true, true);
        vm.set_acceleration_policy(policy);
        assert_eq!(vm.acceleration_policy(), policy);
    }
    #[test]
    fn second_load_hits_global_cache() {
        set_banner_enabled(false);
        ivm_cache::init_global_with_capacity(64);
        let program = unique_program();
        let before = ivm_cache::global_counters();
        let mut first = IVM::new(u64::MAX);
        first
            .load_program(&program)
            .expect("first load populates cache");
        let after_first = ivm_cache::global_counters();
        // Other tests may update the shared cache concurrently, so ensure we registered at least one miss.
        assert!(after_first.1 - before.1 >= 1);
        let mut second = IVM::new(u64::MAX);
        second
            .load_program(&program)
            .expect("second load retrieves cache");
        let after_second = ivm_cache::global_counters();
        assert!(after_second.0 - after_first.0 >= 1);
    }
    #[test]
    fn reset_preserves_entry_pc_with_literal_prefix() {
        set_banner_enabled(false);
        ivm_cache::init_global_with_capacity(64);
        let (program, literal_prefix) = program_with_literal_prefix();
        let literal_pc = literal_prefix as u64;
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&program)
            .expect("program with literals loads");
        assert_eq!(vm.pc(), literal_pc);
        assert!(vm.predecoded.is_some());
        assert!(vm.prepared_contains_pc(literal_pc));
        vm.set_register(31, 0);
        vm.reset().expect("private lifecycle cleanup succeeds");
        assert_eq!(vm.pc(), literal_pc);
        assert_eq!(vm.register(31), vm.memory.stack_top());
        assert!(vm.prepared_contains_pc(literal_pc));
    }
    #[test]
    fn generic_abort_cannot_inherit_a_contract_error_code() {
        let mut vm = quiet_vm(u64::MAX);
        vm.set_register(10, 18);
        vm.request_abort();
        assert_eq!(vm.contract_abort_error, None);
        vm.request_contract_abort(
            "Test".to_owned(),
            "Rejected".to_owned(),
            "test::Error".to_owned(),
            [0; 32],
            18,
            None,
        );
        assert_eq!(
            vm.contract_abort_error,
            Some(VMError::ContractAbort {
                contract: "Test".into(),
                name: "Rejected".to_owned(),
                error_type: "test::Error".to_owned(),
                schema_hash: [0; 32],
                code: 18,
                message: None,
            })
        );
    }
}

#[cfg(test)]
#[path = "vm_cycle_budget_tests.rs"]
mod vm_cycle_budget_tests;
