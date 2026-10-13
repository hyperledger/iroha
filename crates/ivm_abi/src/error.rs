//! Error types and permission flags for the VM.
//!
//! Error variants cover common failure modes including privacy tag violations.
use crate::numeric::{NumericFaultV1, PointerAbiFaultV1};
/// Original local allocation refusal carried by [`VMError::AllocationDeferred`].
/// This is the allocation owner's type; re-exporting it does not copy its custody.
pub use iroha_allocation::{AllocationRefusal, AllocatorRefusal};
use iroha_data_model::executor::fault::{IvmFaultKindV1, IvmFaultV1};
/// Original move-only native verification refusal owned by the shared proof layer.
pub use iroha_plonk::verification_attempt::VerificationRefusal;
use std::{error::Error as StdError, fmt};
/// Memory region permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perm(u8);
impl Perm {
    pub const NONE: Perm = Perm(0);
    pub const READ: Perm = Perm(1);
    pub const WRITE: Perm = Perm(2);
    pub const EXECUTE: Perm = Perm(4);
    pub fn contains(self, other: Perm) -> bool {
        (self.0 & other.0) == other.0
    }
}
// Enable bitwise OR for Perm flags
use std::ops::BitOr;
impl BitOr for Perm {
    type Output = Perm;
    fn bitor(self, rhs: Perm) -> Perm {
        Perm(self.0 | rhs.0)
    }
}
/// High-level trap category captured alongside the raw [`VMError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmTrapKind {
    OutOfGas,
    OutOfMemory,
    MemoryFault,
    DecodeError,
    InvalidOpcode,
    UnknownSyscall,
    NotImplemented,
    SyscallGasQuoteExceeded,
    SyscallMeteringModeMismatch,
    GasCostOverflow,
    NumericFault,
    PointerAbiFault,
    AssertionFailed,
    ContractAbort,
    ExceededMaxCycles,
    InvalidMetadata,
    UnsupportedProgramVersion,
    UnsupportedProgramFeatureBits,
    UnsupportedProgramAbiVersion,
    ProgramVectorLengthTooLarge,
    ArtifactAbiHashMismatch,
    GenericSyscallNotAllowed,
    InvalidVectorLength,
    MissingHalt,
    PermissionDenied,
    PrivacyViolation,
    RegisterOutOfBounds,
    NoritoInvalid,
    AbiTypeNotAllowed,
    HostOutputBudgetExceeded,
    AmxBudgetExceeded,
    Other,
}
/// Consensus-retained host resource whose execution budget was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOutputResource {
    /// Number of retained effect artifacts.
    Items,
    /// Aggregate encoded size of retained effect artifacts.
    Bytes,
}
/// Source location mapped from compiler-emitted debug metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmSourceLocation<'a> {
    pub function: Option<&'a str>,
    pub path: Option<&'a str>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}
/// Budget-related execution snapshot captured at trap time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmBudgetSnapshot {
    pub gas_limit: u64,
    pub gas_remaining: u64,
    pub gas_used: u64,
    pub cycles: u64,
    pub max_cycles: u64,
    pub stack_limit_bytes: u64,
    pub stack_bytes_used: u64,
}
/// Additional execution context captured at trap time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmExecutionContext<'a> {
    pub entrypoint_pc: Option<u64>,
    pub current_function: Option<&'a str>,
    pub opcode: Option<u16>,
    pub syscall: Option<u32>,
    pub predecoded_loaded: bool,
    pub predecoded_hit: Option<bool>,
}
/// Borrowed semantic-trap context; rendering also requires the original returned [`VMError`].
///
/// Text borrows the VM's retained source metadata. This view owns no error or allocation
/// and cannot outlive or permit replacement of that metadata. Local refusals have no view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmExecutionDiagnostic<'a> {
    /// Canonical bounded execution fault, absent for application rejections.
    pub fault: Option<IvmFaultV1>,
    pub trap_kind: VmTrapKind,
    pub pc: u64,
    pub source: Option<VmSourceLocation<'a>>,
    pub budget: VmBudgetSnapshot,
    pub context: VmExecutionContext<'a>,
}
/// Local inability to complete an execution attempt. This is never a protocol
/// rejection or a deterministic VM fault and deliberately has no wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionDeferral {
    /// Original host custody or an immutable construction plan was inconsistent.
    /// Execution rolls back without fees or rejection; the native owner must halt
    /// for recovery rather than retry, quarantine or certify this local result.
    LocalInvariantViolation,
    /// The host allocator could not supply the requested physical storage.
    AllocationUnavailable,
    /// The local active execution memory admission owner has no capacity.
    ActiveMemoryCapacity,
    /// Governed verifier artifacts are not loaded or require an authenticated reload.
    /// This local availability condition cannot become a transaction rejection.
    VerifierArtifactsUnavailable,
    /// Native verification was cooperatively cancelled before a verdict.
    VerificationCancelled,
    /// Native verification exceeded its own scratch budget; no allocation-pool wait is implied.
    NativeVerificationMemoryUnavailable,
    /// Trusted verifier initialization failed before an incoming-proof verdict was available.
    VerifierInitializationUnavailable,
    /// Original local committed execution history is missing, corrupt, or not readable.
    /// This is never evidence that the signed transaction was rejected.
    CanonicalHistoryUnavailable,
    /// A bounded native ancestry read exhausted its local source-work or byte allowance.
    /// No allocator wake source is implied by this independent read limit.
    CanonicalHistoryCapacity,
    /// The local trace owner no longer matches its admitted invocation or storage scope.
    /// Retry with a coherent owner; this does not establish a guest or protocol fault.
    TraceOwnerUnavailable,
}
impl fmt::Display for ExecutionDeferral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LocalInvariantViolation => "local original execution custody invariant violated",
            Self::AllocationUnavailable => "local allocation unavailable",
            Self::ActiveMemoryCapacity => "local active execution memory capacity unavailable",
            Self::VerifierArtifactsUnavailable => "local governed verifier artifacts unavailable",
            Self::VerificationCancelled => "native verification cancelled before completion",
            Self::NativeVerificationMemoryUnavailable => {
                "native verification scratch budget unavailable"
            }
            Self::VerifierInitializationUnavailable => {
                "trusted verifier initialization unavailable"
            }
            Self::CanonicalHistoryUnavailable => "local canonical execution history unavailable",
            Self::CanonicalHistoryCapacity => {
                "local canonical execution history read capacity unavailable"
            }
            Self::TraceOwnerUnavailable => "local execution trace owner unavailable",
        })
    }
}
impl StdError for ExecutionDeferral {}
/// VM errors.
#[derive(Debug)]
pub enum VMError {
    /// Abandon this local attempt without retaining a transaction result; the
    /// native host distinguishes retryable local pressure from recovery-only custody failure.
    ExecutionDeferred(ExecutionDeferral),
    /// Original active allocation refusal, including its exact pool's release observation.
    /// This local owner is never a metered guest fault or a wire rejection.
    AllocationDeferred(AllocationRefusal),
    /// Original canonical decoder refusal captured before its admission scope retired.
    /// This opaque non-wire owner grants no allocation-pool wakeup or guest fault.
    DecodeDeferred(norito::core::DecodeLocalRefusal),
    /// Original physical allocator refusal; grants no finite-pool release observation.
    AllocatorDeferred(AllocatorRefusal),
    /// Original native verification failure, moved without allocating or producing a verdict.
    VerificationDeferred(VerificationRefusal),
    /// Host work failed after consuming a deterministic amount of syscall gas.
    ///
    /// The VM executor debits `gas` and then returns `source` so trap
    /// classification and diagnostics preserve the original failure kind.
    Metered {
        gas: u64,
        source: Box<VMError>,
    },
    OutOfGas,
    OutOfMemory,
    MemoryAccessViolation {
        addr: u32,
        perm: Perm,
    },
    MisalignedAccess {
        addr: u32,
    },
    /// Access outside the configured VM memory bounds.
    MemoryOutOfBounds,
    /// Instruction decoding failed due to invalid data or out-of-bounds fetch.
    DecodeError,
    InvalidOpcode(u16),
    UnknownSyscall(u32),
    /// VM was asked to run or execute a host-dependent operation without a host attached.
    HostUnavailable,
    /// Syscall number is reserved/known but not implemented by the current host build.
    NotImplemented {
        syscall: u32,
    },
    /// A host returned an actual gas cost above its side-effect-free preparation quote.
    SyscallGasQuoteExceeded {
        /// Upper bound supplied before the VM entered the host.
        quoted: u64,
        /// Cost reported after the host returned.
        actual: u64,
    },
    /// A syscall used reserve/refund reporting while registered for staged
    /// metering, or attempted a staged charge without an active staged call.
    SyscallMeteringModeMismatch {
        /// Syscall whose registered metering mode was violated.
        syscall: u32,
    },
    /// A deterministic gas formula exceeded the `u64` gas domain.
    GasCostOverflow,
    /// The next staged syscall phase could not be afforded.
    ///
    /// No gas is debited for the named phase; gas charged by earlier phases is retained.
    SyscallOutOfGas {
        /// Syscall executing the staged phase.
        syscall: u32,
        /// Stable staged-metering phase tag.
        phase: u8,
    },
    /// A checked numeric operation failed in trap mode.
    NumericFault(NumericFaultV1),
    /// A numeric pointer envelope failed stable ABI validation.
    PointerAbiFault(PointerAbiFaultV1),
    AssertionFailed,
    /// Contract requested an application-level abort with a stable numeric code.
    ContractAbort {
        /// Authenticated seiyaku name where the rejection originated.
        contract: Box<str>,
        /// Authenticated symbolic variant name within the declared error type.
        name: String,
        /// Stable nominal error type identity.
        error_type: String,
        /// Hash of the exact signed variant schema.
        schema_hash: [u8; 32],
        /// Validated nonzero enum-local variant code.
        code: u32,
        /// Static presentation text authenticated by the originating contract interface.
        /// Its immutable storage keeps this rare diagnostic from inflating every VM result.
        message: Option<Box<str>>,
    },
    ExceededMaxCycles,
    InvalidMetadata,
    /// The fixed header declares a version outside the sole first-release 1.1 surface.
    UnsupportedProgramVersion {
        /// Declared major version.
        major: u8,
        /// Declared minor version.
        minor: u8,
    },
    /// The fixed header contains mode bits unknown to ABI V1.
    UnsupportedProgramFeatureBits {
        /// Unknown feature bits only, excluding recognized bits.
        bits: u8,
    },
    /// The fixed header selects an ABI version unavailable in this release.
    UnsupportedProgramAbiVersion {
        /// Declared ABI version.
        version: u8,
    },
    /// The fixed header requests more logical vector lanes than ABI V1 permits.
    ProgramVectorLengthTooLarge {
        /// Declared vector length.
        vector_length: u8,
        /// Maximum accepted vector length.
        max_allowed: u8,
    },
    /// A self-describing artifact targets a different canonical ABI descriptor.
    ArtifactAbiHashMismatch {
        /// ABI descriptor hash required by the runtime.
        expected: [u8; 32],
        /// Authenticated ABI descriptor hash carried by the artifact.
        actual: [u8; 32],
    },
    /// A contract-bound syscall appeared in an ABI-authenticated generic program.
    GenericSyscallNotAllowed {
        /// Rejected syscall number.
        syscall: u32,
    },
    InvalidVectorLength {
        vector_length: usize,
    },
    /// Program reached the end of the executable region without an explicit terminating syscall or HALT.
    MissingHalt,
    VectorExtensionDisabled,
    ZkExtensionDisabled,
    NullifierAlreadyUsed,
    PermissionDenied,
    /// A nested invocation targeted an address already active in its ancestry.
    ReentrantCall,
    /// A nested invocation exceeded the canonical call-depth bound.
    CallDepthExceeded,
    PrivacyViolation,
    RegisterOutOfBounds,
    /// Malformed Norito TLV envelope or checksum mismatch.
    NoritoInvalid,
    /// Pointer‑ABI type not allowed under the current ABI policy.
    AbiTypeNotAllowed {
        abi: u8,
        type_id: u16,
    },
    /// An execution attempted to retain more effect output than consensus permits.
    HostOutputBudgetExceeded {
        /// Resource whose limit was exceeded.
        resource: HostOutputResource,
        /// Amount the host attempted to retain.
        attempted: u64,
        /// Consensus maximum for the resource.
        limit: u64,
    },
    /// AMX static analysis budget exceeded for the current dataspace.
    AmxBudgetExceeded {
        /// Dataspace whose slice exceeded the configured budget.
        dataspace: iroha_model_base::topology::DataSpaceId,
        /// Stage that exceeded the budget (e.g., commit).
        stage: iroha_data_model::errors::AmxStage,
        /// Estimated elapsed milliseconds for the stage.
        elapsed_ms: u64,
        /// Configured budget in milliseconds.
        budget_ms: u64,
    },
}
impl VMError {
    /// Wrap an error with deterministic gas charged before surfacing it.
    #[must_use]
    pub fn metered(gas: u64, source: VMError) -> Self {
        if source.execution_deferral().is_some() {
            return source.into_unmetered();
        }
        match source {
            VMError::Metered {
                gas: existing,
                source,
            } => VMError::Metered {
                gas: gas.saturating_add(existing),
                source,
            },
            source => VMError::Metered {
                gas,
                source: Box::new(source),
            },
        }
    }
    /// Return a local retry reason, including inside manually constructed wrappers.
    #[must_use]
    pub fn execution_deferral(&self) -> Option<ExecutionDeferral> {
        match self.as_unmetered() {
            Self::ExecutionDeferred(reason) => Some(*reason),
            Self::AllocationDeferred(_) => Some(ExecutionDeferral::ActiveMemoryCapacity),
            Self::AllocatorDeferred(_) => Some(ExecutionDeferral::AllocationUnavailable),
            Self::DecodeDeferred(original) => Some(match original.kind() {
                norito::core::DecodeLocalRefusalKind::Allocator => {
                    ExecutionDeferral::AllocationUnavailable
                }
                norito::core::DecodeLocalRefusalKind::EnclosingLimit => {
                    ExecutionDeferral::ActiveMemoryCapacity
                }
            }),
            Self::VerificationDeferred(original) => {
                use iroha_plonk::verification_attempt::VerificationRefusalKind as Kind;
                Some(match original.kind() {
                    Kind::Decode(norito::core::DecodeLocalRefusalKind::Allocator) => {
                        ExecutionDeferral::AllocationUnavailable
                    }
                    Kind::Decode(norito::core::DecodeLocalRefusalKind::EnclosingLimit) => {
                        ExecutionDeferral::ActiveMemoryCapacity
                    }
                    Kind::NativeCancelled => ExecutionDeferral::VerificationCancelled,
                    Kind::NativeMemoryBudget => {
                        ExecutionDeferral::NativeVerificationMemoryUnavailable
                    }
                    Kind::InitializationUnavailable => {
                        ExecutionDeferral::VerifierInitializationUnavailable
                    }
                    Kind::LocalInvariantViolation => ExecutionDeferral::LocalInvariantViolation,
                })
            }
            Self::HostUnavailable
            | Self::SyscallGasQuoteExceeded { .. }
            | Self::SyscallMeteringModeMismatch { .. } => {
                Some(ExecutionDeferral::LocalInvariantViolation)
            }
            _ => None,
        }
    }
    /// Project only deterministic failures of a started invocation.
    ///
    /// Admission errors, application rejections and local host/resource failures
    /// deliberately have no runtime fault value. This exhaustive projection does
    /// not use presentation strings or the coarser diagnostic trap categories.
    #[must_use]
    pub fn fault_kind(&self) -> Option<IvmFaultKindV1> {
        use IvmFaultKindV1 as F;
        Some(match self.as_unmetered() {
            Self::OutOfGas | Self::SyscallOutOfGas { .. } => F::OutOfGas,
            Self::OutOfMemory => F::MemoryLimitExceeded,
            Self::MemoryAccessViolation { .. } => F::MemoryAccessViolation,
            Self::MisalignedAccess { .. } => F::MisalignedAccess,
            Self::MemoryOutOfBounds => F::MemoryOutOfBounds,
            Self::DecodeError => F::DecodeError,
            Self::InvalidOpcode(_) => F::InvalidOpcode,
            Self::UnknownSyscall(_) => F::UnknownSyscall,
            Self::NotImplemented { .. } => F::UnsupportedSyscall,
            Self::GasCostOverflow => F::GasCostOverflow,
            Self::NumericFault(code) => F::Numeric(*code),
            Self::PointerAbiFault(code) => F::PointerAbi(*code),
            Self::AssertionFailed => F::AssertionFailed,
            Self::ExceededMaxCycles => F::ExceededMaxCycles,
            Self::InvalidMetadata => F::InvalidMetadata,
            Self::InvalidVectorLength { .. } => F::InvalidVectorLength,
            Self::MissingHalt => F::MissingHalt,
            Self::VectorExtensionDisabled => F::VectorExtensionDisabled,
            Self::ZkExtensionDisabled => F::ZkExtensionDisabled,
            Self::NullifierAlreadyUsed => F::NullifierAlreadyUsed,
            Self::PermissionDenied => F::PermissionDenied,
            Self::ReentrantCall => F::ReentrantCall,
            Self::CallDepthExceeded => F::CallDepthExceeded,
            Self::PrivacyViolation => F::PrivacyViolation,
            Self::RegisterOutOfBounds => F::RegisterOutOfBounds,
            Self::NoritoInvalid => F::NoritoInvalid,
            Self::AbiTypeNotAllowed { .. } => F::AbiTypeNotAllowed,
            Self::HostOutputBudgetExceeded {
                resource: HostOutputResource::Items,
                ..
            } => F::HostOutputItemsExceeded,
            Self::HostOutputBudgetExceeded {
                resource: HostOutputResource::Bytes,
                ..
            } => F::HostOutputBytesExceeded,
            Self::AmxBudgetExceeded { .. } => F::AmxBudgetExceeded,
            Self::ExecutionDeferred(_)
            | Self::AllocationDeferred(_)
            | Self::AllocatorDeferred(_)
            | Self::DecodeDeferred(_)
            | Self::VerificationDeferred(_)
            | Self::HostUnavailable
            | Self::SyscallGasQuoteExceeded { .. }
            | Self::SyscallMeteringModeMismatch { .. }
            | Self::ContractAbort { .. }
            | Self::UnsupportedProgramVersion { .. }
            | Self::UnsupportedProgramFeatureBits { .. }
            | Self::UnsupportedProgramAbiVersion { .. }
            | Self::ProgramVectorLengthTooLarge { .. }
            | Self::ArtifactAbiHashMismatch { .. }
            | Self::GenericSyscallNotAllowed { .. } => return None,
            Self::Metered { .. } => unreachable!("as_unmetered removes metering wrappers"),
        })
    }
    /// Construct a metered `NotImplemented` error for a known syscall.
    #[must_use]
    pub fn metered_not_implemented(gas: u64, syscall: u32) -> Self {
        Self::metered(gas, VMError::NotImplemented { syscall })
    }
    /// Return the original error kind, peeling metered wrappers.
    #[must_use]
    pub fn as_unmetered(&self) -> &VMError {
        match self {
            VMError::Metered { source, .. } => source.as_unmetered(),
            error => error,
        }
    }
    /// Return the gas attached to this error, if it is metered.
    #[must_use]
    pub fn metered_gas(&self) -> Option<u64> {
        if self.execution_deferral().is_some() {
            return None;
        }
        match self {
            VMError::Metered { gas, .. } => Some(*gas),
            _ => None,
        }
    }
    /// Consume this error and return the original unmetered error kind.
    #[must_use]
    pub fn into_unmetered(self) -> VMError {
        match self {
            VMError::Metered { source, .. } => source.into_unmetered(),
            error => error,
        }
    }
    /// Consume this error and split any attached gas from the original error.
    #[must_use]
    pub fn split_metered(self) -> (Option<u64>, VMError) {
        if self.execution_deferral().is_some() {
            return (None, self.into_unmetered());
        }
        match self {
            VMError::Metered { gas, source } => (Some(gas), source.into_unmetered()),
            error => (None, error),
        }
    }
}
impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMError::Metered { gas, source } => {
                write!(f, "metered syscall error after {gas} gas: {source}")
            }
            VMError::ExecutionDeferred(reason) => write!(f, "execution deferred: {reason}"),
            VMError::AllocationDeferred(refusal) => {
                write!(f, "execution allocation deferred: {refusal}")
            }
            VMError::AllocatorDeferred(original) => {
                write!(f, "physical allocation deferred: {original}")
            }
            VMError::DecodeDeferred(original) => {
                write!(f, "execution decode deferred: {original}")
            }
            VMError::VerificationDeferred(original) => {
                write!(f, "native verification deferred: {original}")
            }
            VMError::OutOfGas => write!(f, "out of gas"),
            VMError::OutOfMemory => write!(f, "out of memory"),
            VMError::MemoryAccessViolation { addr, perm } => {
                write!(
                    f,
                    "memory access violation at 0x{addr:08x} (needed permission: {perm:?})"
                )
            }
            VMError::MisalignedAccess { addr } => {
                write!(f, "misaligned memory access at 0x{addr:08x}")
            }
            VMError::MemoryOutOfBounds => write!(f, "memory access out of bounds"),
            VMError::DecodeError => write!(f, "instruction decode error"),
            VMError::InvalidOpcode(op) => write!(f, "invalid or unknown opcode 0x{op:02x}"),
            VMError::UnknownSyscall(num) => write!(f, "unknown syscall number {num}"),
            VMError::HostUnavailable => write!(f, "host unavailable"),
            VMError::NotImplemented { syscall } => {
                write!(f, "syscall 0x{syscall:02x} not implemented by host")
            }
            VMError::SyscallGasQuoteExceeded { quoted, actual } => write!(
                f,
                "syscall gas quote exceeded (quoted={quoted}, actual={actual})"
            ),
            VMError::SyscallMeteringModeMismatch { syscall } => write!(
                f,
                "syscall 0x{syscall:02x} violated its registered metering mode"
            ),
            VMError::GasCostOverflow => write!(f, "gas cost exceeded the canonical u64 domain"),
            VMError::SyscallOutOfGas { syscall, phase } => write!(
                f,
                "syscall 0x{syscall:02x} ran out of gas before metering phase {phase}"
            ),
            VMError::NumericFault(fault) => {
                write!(f, "numeric operation failed with ABI fault {}", fault.tag())
            }
            VMError::PointerAbiFault(fault) => {
                write!(
                    f,
                    "numeric pointer validation failed with ABI fault {}",
                    fault.tag()
                )
            }
            VMError::AssertionFailed => write!(f, "assertion failed (constraint violation)"),
            VMError::ContractAbort {
                error_type,
                code,
                message,
                ..
            } => {
                write!(f, "seiyaku aborted with {error_type} code {code}")?;
                if let Some(message) = message {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            VMError::ExceededMaxCycles => write!(f, "execution exceeded max cycles"),
            VMError::InvalidMetadata => write!(f, "invalid program metadata"),
            VMError::UnsupportedProgramVersion { major, minor } => {
                write!(f, "unsupported IVM program version {major}.{minor}")
            }
            VMError::UnsupportedProgramFeatureBits { bits } => {
                write!(f, "unsupported IVM program feature bits 0x{bits:02x}")
            }
            VMError::UnsupportedProgramAbiVersion { version } => {
                write!(f, "unsupported IVM program ABI version {version}")
            }
            VMError::ProgramVectorLengthTooLarge {
                vector_length,
                max_allowed,
            } => write!(
                f,
                "IVM program vector length {vector_length} exceeds maximum {max_allowed}"
            ),
            VMError::ArtifactAbiHashMismatch { expected, actual } => write!(
                f,
                "contract artifact ABI hash mismatch (expected={}, actual={})",
                HexBytes(expected),
                HexBytes(actual)
            ),
            VMError::GenericSyscallNotAllowed { syscall } => write!(
                f,
                "syscall 0x{syscall:02x} is not allowed in a generic IVM program"
            ),
            VMError::InvalidVectorLength { vector_length } => {
                write!(f, "invalid vector length {vector_length}")
            }
            VMError::MissingHalt => write!(f, "program terminated without HALT, EXIT, or ABORT"),
            VMError::VectorExtensionDisabled => write!(f, "vector extension not enabled"),
            VMError::ZkExtensionDisabled => write!(f, "zk extension not enabled"),
            VMError::NullifierAlreadyUsed => write!(f, "nullifier already used"),
            VMError::PermissionDenied => write!(f, "permission denied"),
            VMError::ReentrantCall => write!(f, "contract address is already active"),
            VMError::CallDepthExceeded => write!(f, "contract call depth exceeded"),
            VMError::PrivacyViolation => write!(f, "privacy tag violation"),
            VMError::RegisterOutOfBounds => write!(f, "register index out of bounds"),
            VMError::NoritoInvalid => write!(f, "invalid Norito TLV envelope"),
            VMError::AbiTypeNotAllowed { abi, type_id } => write!(
                f,
                "pointer-ABI type 0x{type_id:04x} not allowed for abi_version={abi}"
            ),
            VMError::HostOutputBudgetExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                f,
                "host output budget exceeded (resource={resource:?}, attempted={attempted}, limit={limit})"
            ),
            VMError::AmxBudgetExceeded {
                dataspace,
                stage,
                elapsed_ms,
                budget_ms,
            } => write!(
                f,
                "amx budget exceeded (dataspace={}, stage={stage:?}, elapsed_ms={}, budget_ms={})",
                dataspace.as_u64(),
                elapsed_ms,
                budget_ms
            ),
        }
    }
}
struct HexBytes<'a>(&'a [u8]);
impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl StdError for VMError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            VMError::Metered { source, .. } => Some(source.as_ref()),
            VMError::DecodeDeferred(original) => Some(original),
            VMError::AllocatorDeferred(original) => Some(original),
            VMError::VerificationDeferred(original) => Some(original),
            _ => None,
        }
    }
}

/// Preserve a local operational refusal when mapping a deterministic decode fault.
///
/// The complete original error retains its cause and any existing pool/release
/// observation; a decoder scope never invents an allocation-pool wakeup.
/// Converting it to malformed input would make transaction validity depend on
/// local resource pressure. Semantic failures retain the caller's existing map.
pub fn preserve_execution_deferral(error: VMError, malformed: VMError) -> VMError {
    if error.execution_deferral().is_some() {
        error
    } else {
        malformed
    }
}

// Numeric pointer faults have one canonical conversion for all ABI producers and runtime consumers.
impl From<iroha_primitives::numeric_abi::NumericAbiError> for VMError {
    fn from(error: iroha_primitives::numeric_abi::NumericAbiError) -> Self {
        use iroha_primitives::numeric_abi::NumericAbiError;
        let fault = match error {
            NumericAbiError::SchemaMismatch => PointerAbiFaultV1::SchemaMismatch,
            NumericAbiError::NonCanonicalMantissa
            | NumericAbiError::NonCanonicalDecimal
            | NumericAbiError::MantissaOverflow
            | NumericAbiError::InvalidScale
            | NumericAbiError::NegativeQuantity => PointerAbiFaultV1::NonCanonical,
            NumericAbiError::FrameTooLarge => PointerAbiFaultV1::OversizedLength,
            NumericAbiError::FrameTooShort
            | NumericAbiError::InvalidHeader
            | NumericAbiError::CompressionNotAllowed
            | NumericAbiError::LayoutFlagsNotAllowed
            | NumericAbiError::LengthMismatch
            | NumericAbiError::Norito(_) => PointerAbiFaultV1::MalformedFrame,
        };
        VMError::PointerAbiFault(fault)
    }
}

#[cfg(test)]
mod numeric_abi_error_tests {
    use super::{PointerAbiFaultV1, VMError};
    use iroha_primitives::numeric_abi::NumericAbiError;

    #[test]
    fn every_numeric_frame_error_maps_to_its_stable_pointer_fault() {
        use NumericAbiError::*;
        use PointerAbiFaultV1::{MalformedFrame, NonCanonical, OversizedLength};

        let cases = [
            (FrameTooShort, MalformedFrame),
            (FrameTooLarge, OversizedLength),
            (InvalidHeader, MalformedFrame),
            (SchemaMismatch, PointerAbiFaultV1::SchemaMismatch),
            (CompressionNotAllowed, MalformedFrame),
            (LayoutFlagsNotAllowed, MalformedFrame),
            (LengthMismatch, MalformedFrame),
            (MantissaOverflow, NonCanonical),
            (NonCanonicalMantissa, NonCanonical),
            (InvalidScale, NonCanonical),
            (NonCanonicalDecimal, NonCanonical),
            (NegativeQuantity, NonCanonical),
            (Norito("invalid checksum".into()), MalformedFrame),
        ];
        for (error, expected) in cases {
            let actual = VMError::from(error.clone());
            assert!(
                matches!(actual, VMError::PointerAbiFault(found) if found == expected),
                "numeric frame error {error:?} changed its pointer fault"
            );
        }
    }
}

#[cfg(test)]
mod execution_deferral_tests {
    #[test]
    fn physical_allocator_transport_is_unmetered_and_not_a_fault() {
        use iroha_allocation::{AllocatorRefusal, ChargedBufferError};
        use std::error::Error;
        // Transport-only control. Core tests obtain this variant from a real null allocation.
        let original = AllocatorRefusal::try_from(ChargedBufferError::Allocator {
            requested_bytes: 97,
        })
        .unwrap();
        let error = VMError::AllocatorDeferred(original);
        assert_eq!(
            error.execution_deferral(),
            Some(ExecutionDeferral::AllocationUnavailable)
        );
        assert!(error.fault_kind().is_none());
        assert!(error.source().unwrap().is::<AllocatorRefusal>());
        let error =
            preserve_execution_deferral(VMError::metered(99, error), VMError::NoritoInvalid);
        assert!(error.metered_gas().is_none());
        let VMError::AllocatorDeferred(original) = error.into_unmetered() else {
            panic!("retain exact physical owner")
        };
        assert!(matches!(
            original.into_buffer_error().unwrap(),
            ChargedBufferError::Allocator {
                requested_bytes: 97
            }
        ));
        assert!(
            core::mem::size_of::<VMError>() < 128,
            "the error remains inline"
        );
    }

    use super::{ExecutionDeferral, VMError, preserve_execution_deferral};

    fn assert_reason(error: &VMError, reason: ExecutionDeferral) {
        assert!(
            matches!(error.as_unmetered(), VMError::ExecutionDeferred(found) if *found == reason)
        );
        assert_eq!(error.execution_deferral(), Some(reason));
    }

    #[test]
    fn decode_mapping_keeps_complete_operational_errors_and_existing_semantic_faults() {
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let error = preserve_execution_deferral(
            VMError::AllocationDeferred(refusal.clone()),
            VMError::NoritoInvalid,
        );
        assert!(matches!(error, VMError::AllocationDeferred(ref found) if *found == refusal));
        for reason in [
            ExecutionDeferral::LocalInvariantViolation,
            ExecutionDeferral::AllocationUnavailable,
            ExecutionDeferral::ActiveMemoryCapacity,
            ExecutionDeferral::VerifierArtifactsUnavailable,
            ExecutionDeferral::VerificationCancelled,
            ExecutionDeferral::NativeVerificationMemoryUnavailable,
            ExecutionDeferral::VerifierInitializationUnavailable,
            ExecutionDeferral::TraceOwnerUnavailable,
        ] {
            assert_reason(
                &preserve_execution_deferral(
                    VMError::ExecutionDeferred(reason),
                    VMError::DecodeError,
                ),
                reason,
            );
        }
        let wrapped = VMError::Metered {
            gas: 17,
            source: Box::new(error),
        };
        let mapped = preserve_execution_deferral(wrapped, VMError::DecodeError);
        let VMError::Metered { gas, source } = mapped else {
            panic!("mapping changed original wrapper");
        };
        assert_eq!(gas, 17);
        assert!(matches!(*source, VMError::AllocationDeferred(found) if found == refusal));
        assert!(matches!(
            preserve_execution_deferral(VMError::MemoryOutOfBounds, VMError::NoritoInvalid),
            VMError::NoritoInvalid
        ));
        drop(occupied);
    }

    #[test]
    fn contract_abort_preserves_authenticated_text_and_identity_through_metering() {
        // Retain the existing size guard pending measured review of the new inline owner.
        assert!(core::mem::size_of::<VMError>() < 128);
        let rejection = VMError::ContractAbort {
            contract: "Treasury".into(),
            name: "InsufficientFunds".into(),
            error_type: "treasury::Error".into(),
            schema_hash: [7; 32],
            code: 18,
            message: Some("残高が不足しています".into()),
        };
        assert_eq!(
            rejection.to_string(),
            "seiyaku aborted with treasury::Error code 18: 残高が不足しています"
        );
        fn assert_abort(error: &VMError) {
            let VMError::ContractAbort {
                contract,
                name,
                error_type,
                schema_hash,
                code,
                message,
            } = error
            else {
                panic!("lost completed abort");
            };
            assert_eq!(&**contract, "Treasury");
            assert_eq!(&**name, "InsufficientFunds");
            assert_eq!(&**error_type, "treasury::Error");
            assert_eq!(*schema_hash, [7; 32]);
            assert_eq!(*code, 18);
            assert_eq!(message.as_deref(), Some("残高が不足しています"));
        }
        let metered = VMError::metered(123, rejection);
        assert_abort(metered.as_unmetered());
        let (gas, moved) = metered.split_metered();
        assert_eq!(gas, Some(123));
        assert_abort(&moved);
    }

    #[test]
    fn local_refusal_never_acquires_a_deterministic_gas_charge() {
        let reason = ExecutionDeferral::AllocationUnavailable;
        let deferred = VMError::metered(123, VMError::ExecutionDeferred(reason));
        assert_reason(&deferred, reason);
        let wrapped = VMError::Metered {
            gas: 456,
            source: Box::new(deferred),
        };
        assert_eq!(wrapped.execution_deferral(), Some(reason));
        assert_eq!(wrapped.metered_gas(), None);
        let (gas, moved) = wrapped.split_metered();
        assert_eq!(gas, None);
        assert_reason(&moved, reason);
    }

    #[test]
    fn deterministic_guest_memory_fault_preserves_metering() {
        let fault = VMError::metered(123, VMError::OutOfMemory);
        assert_eq!(fault.execution_deferral(), None);
        let (gas, moved) = fault.split_metered();
        assert_eq!(gas, Some(123));
        assert!(matches!(moved, VMError::OutOfMemory));
    }

    #[test]
    fn original_capacity_release_survives_every_metered_boundary() {
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let error = VMError::AllocationDeferred(refusal.clone());
        assert_eq!(
            error.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity)
        );
        let error = VMError::metered(123, error);
        assert!(matches!(&error, VMError::AllocationDeferred(found) if *found == refusal));
        let wrapped = VMError::Metered {
            gas: 456,
            source: Box::new(error),
        };
        assert_eq!(wrapped.metered_gas(), None);
        let error = VMError::metered(789, wrapped);
        assert!(matches!(&error, VMError::AllocationDeferred(found) if *found == refusal));
        let (gas, moved) = error.split_metered();
        assert_eq!(gas, None);
        assert!(matches!(moved, VMError::AllocationDeferred(found) if found == refusal));
        drop(occupied);
    }

    #[test]
    fn unavailable_governed_verifier_is_local_and_cannot_be_metered() {
        let reason = ExecutionDeferral::VerifierArtifactsUnavailable;
        assert_eq!(
            reason.to_string(),
            "local governed verifier artifacts unavailable"
        );
        let original = VMError::metered(777, VMError::ExecutionDeferred(reason));
        assert_reason(&original, reason);
        let (gas, moved) = original.split_metered();
        assert_eq!(gas, None);
        assert_reason(&moved, reason);
    }

    #[test]
    fn canonical_history_deferrals_cannot_be_metered_as_vm_faults() {
        for reason in [
            ExecutionDeferral::CanonicalHistoryUnavailable,
            ExecutionDeferral::CanonicalHistoryCapacity,
        ] {
            let original = VMError::metered(777, VMError::ExecutionDeferred(reason));
            assert_reason(&original, reason);
            let (gas, moved) = original.split_metered();
            assert_eq!(gas, None);
            assert_reason(&moved, reason);
        }
    }

    #[test]
    fn trace_owner_mismatch_remains_local_through_nested_metering() {
        let reason = ExecutionDeferral::TraceOwnerUnavailable;
        assert_eq!(
            reason.to_string(),
            "local execution trace owner unavailable"
        );
        let nested = VMError::Metered {
            gas: 17,
            source: Box::new(VMError::Metered {
                gas: 91,
                source: Box::new(VMError::ExecutionDeferred(reason)),
            }),
        };
        assert_eq!(nested.execution_deferral(), Some(reason));
        assert_eq!(nested.metered_gas(), None);
        let nested = preserve_execution_deferral(nested, VMError::DecodeError);
        let VMError::Metered { gas: 17, source } = &nested else {
            panic!("outer diagnostic wrapper changed");
        };
        assert!(matches!(&**source, VMError::Metered { gas: 91, .. }));
        let original = VMError::metered(123, nested);
        assert_reason(&original, reason);
        let (gas, moved) = original.split_metered();
        assert_eq!(gas, None);
        assert_reason(&moved, reason);
    }
}

#[cfg(test)]
mod canonical_decode_deferral_tests {
    use super::*;

    #[test]
    fn retained_codec_refusal_has_no_metered_gas_or_deterministic_fault() {
        let bytes = norito::encode_canonical(&vec![31_u8; 8]).unwrap();
        let cause = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                norito::decode_canonical_for_admission::<Vec<u8>>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            },
        )
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let error = VMError::DecodeDeferred(cause.clone());
        assert_eq!(
            error.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(error.fault_kind(), None);
        let error = VMError::metered(91, error);
        assert!(matches!(&error, VMError::DecodeDeferred(found) if *found == cause));
        let nested = VMError::Metered {
            gas: 27,
            source: Box::new(error),
        };
        assert_eq!(
            nested.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(nested.fault_kind(), None);
        let (gas, error) = nested.split_metered();
        assert_eq!(gas, None);
        assert!(matches!(&error, VMError::DecodeDeferred(found) if *found == cause));
        let error = preserve_execution_deferral(error, VMError::NoritoInvalid);
        assert!(matches!(&error, VMError::DecodeDeferred(found) if *found == cause));
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<norito::core::DecodeLocalRefusal>(),
            Some(&cause)
        );
        assert!(error.to_string().starts_with("execution decode deferred: "));
    }

    #[test]
    fn captured_allocator_refusal_retains_bytes_without_a_pool_wakeup() {
        // This synthetic decoder result exercises the established classifier trust
        // boundary; it is not evidence of an actual physical allocation failure.
        let cause = norito::core::classify_decode_attempt(|| {
            Err::<(), _>(norito::Error::AllocationFailed { bytes: 127 })
        })
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let error = VMError::DecodeDeferred(cause.clone());
        assert_eq!(
            error.execution_deferral(),
            Some(ExecutionDeferral::AllocationUnavailable)
        );
        assert_eq!(error.fault_kind(), None);
        let (gas, returned) = VMError::metered(13, error).split_metered();
        assert_eq!(gas, None);
        let VMError::DecodeDeferred(original) = returned else {
            panic!("lost decoder owner")
        };
        assert_eq!(original, cause);
        assert_eq!(original.allocation_bytes(), Some(127));
    }
}

#[cfg(test)]
mod native_verification_deferral_tests {
    use super::*;
    use iroha_plonk::{
        pcs::ipa::IpaError,
        verification_attempt::{VerificationAttemptError, native_verification_error},
        verifier::VerifyError,
    };

    #[test]
    fn exact_native_budget_and_cancellation_move_through_nested_metering_without_faults() {
        // This is a genuine native budget check, not a claim that physical allocation failed.
        let budget = iroha_plonk::keys::KeygenConfigV2::pipa_r(Vec::new()).msm_budget;
        let refusal = budget.check(usize::MAX).unwrap_err();
        let cancellation = iroha_pasta::CancellationToken::new();
        assert!(iroha_pasta::CancellationToken::checkpoint(Some(&cancellation)).is_ok());
        cancellation.cancel();
        let cancelled =
            iroha_pasta::CancellationToken::checkpoint(Some(&cancellation)).unwrap_err();
        for (original, reason) in [
            (
                VerifyError::Ipa(IpaError::Msm(refusal.into())),
                ExecutionDeferral::NativeVerificationMemoryUnavailable,
            ),
            (
                VerifyError::from(cancelled),
                ExecutionDeferral::VerificationCancelled,
            ),
        ] {
            let original = Box::new(original);
            let expected_address: *const VerifyError = &*original;
            let attempt = native_verification_error(
                VerifyError::BatchItem {
                    index: 2,
                    error: original,
                },
                |_| -> () {
                    panic!("unfinished native work cannot reject a proof");
                },
            );
            let VerificationAttemptError::Deferred(owner) = attempt else {
                panic!("lost native owner");
            };
            let error = VMError::VerificationDeferred(owner);
            assert_eq!(error.execution_deferral(), Some(reason));
            assert_eq!(error.fault_kind(), None);
            assert!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<VerificationRefusal>()
                    .is_some()
            );
            let nested = VMError::Metered {
                gas: 19,
                source: Box::new(VMError::Metered {
                    gas: 41,
                    source: Box::new(error),
                }),
            };
            assert_eq!(nested.execution_deferral(), Some(reason));
            assert_eq!(nested.fault_kind(), None);
            assert_eq!(nested.metered_gas(), None);
            let mapped = preserve_execution_deferral(nested, VMError::NoritoInvalid);
            let (gas, moved) = VMError::metered(71, mapped).split_metered();
            assert_eq!(gas, None);
            let VMError::VerificationDeferred(owner) = moved else {
                panic!("lost original after consuming split");
            };
            assert!(owner.decode_refusal().is_none());
            let Some(VerifyError::BatchItem { index, error }) = owner.native_verification_error()
            else {
                panic!("lost original typed outer failure");
            };
            assert_eq!(*index, 2);
            let retained_address: *const VerifyError = &**error;
            assert_eq!(retained_address, expected_address);
            match reason {
                ExecutionDeferral::NativeVerificationMemoryUnavailable => assert!(
                    matches!(&**error, VerifyError::Ipa(IpaError::Msm(actual)) if *actual == refusal.into())
                ),
                ExecutionDeferral::VerificationCancelled => {
                    assert!(matches!(&**error, VerifyError::Cancelled))
                }
                _ => unreachable!(),
            }
        }
    }
}
