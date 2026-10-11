//! Vector and cryptographic helper functions used by the VM.
//!
//! This module implements the primitives required by the specification,
//! including lane-wise arithmetic, bitwise operations and the SHA‑256
//! compression round used by the `SHA256BLOCK` instruction.
//!
//! The updated spec defines a **scalable vector extension** which adapts to the
//! host CPU's SIMD width.  These helpers now detect the available SIMD features
//! (SSE, AVX2, AVX‑512 or NEON) at runtime and operate on a lane count derived
//! from that width.  When no SIMD support is available, a 32-bit scalar fallback
//! is used.  Additional cryptographic primitives such as AESENC or BLAKE2s
//! should also be implemented here with optional hardware acceleration.
#[cfg(any(test, all(target_os = "macos", feature = "metal")))]
use crate::sha256_ref::sha256_compress_scalar_ref;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_buffers;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_cost;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_ed25519_cost;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_merkle_cost_rehash;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_merkle_cost_root;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_merkle_cost_tree;
mod sha256_cpu;
#[cfg(all(target_os = "macos", feature = "metal"))]
use metal_buffers::MetalBuffer;
#[cfg(test)]
pub(crate) use sha256_cpu::context::Sha256Backend;
pub(crate) use sha256_cpu::context::{Sha256Context, Sha256Observed};
#[cfg(any(test, all(target_os = "macos", feature = "metal")))]
mod metal_owner;
#[cfg(all(target_os = "macos", feature = "metal"))]
mod metal_runtime;
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) use metal_runtime::MetalSelection;
mod metal_receipts;
pub use metal_receipts::{MetalKernel, metal_completed_dispatches};
#[cfg(all(test, feature = "metal-hardware-tests"))]
mod metal_qualification;
#[cfg(test)]
mod metal_qualification_wait;

#[cfg(all(target_os = "macos", feature = "metal"))]
use objc2_foundation::NSUInteger;
#[cfg(all(target_os = "macos", feature = "metal"))]
use objc2_metal::*;
#[cfg(all(target_os = "macos", feature = "metal"))]
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGMainDisplayID() -> u32;
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn warm_up_core_graphics_display() {
    unsafe {
        let _ = CGMainDisplayID();
    }
}
use std::sync::{Mutex, MutexGuard};
#[cfg(all(target_os = "macos", feature = "metal"))]
use std::time::{Duration, Instant};
/// Return true if the host CPU supports SIMD operations that the vector extension can leverage.
/// This is a lightweight stand‑in for more elaborate feature detection used by a production
/// implementation. Determine if SIMD vector operations are available on the current
/// architecture.  This helper is intentionally small and only checks for a
/// minimal baseline feature on supported platforms.  Additional runtime feature
/// detection can be added as the implementation grows.
use std::{
    cell::Cell,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
/// The SIMD backend selected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdChoice {
    /// AVX-512 back-end (requires AVX2 for the current 256-bit implementations).
    Avx512,
    Avx2,
    Sse2,
    Neon,
    Scalar,
}
static SIMD_CHOICE: OnceLock<SimdChoice> = OnceLock::new();
static SIMD_POLICY_ENABLED: AtomicBool = AtomicBool::new(true);
static SIMD_OVERRIDE: AtomicU8 = AtomicU8::new(0);
thread_local! {
    static TLS_SIMD_OVERRIDE: Cell<u8> = const { Cell::new(0) };
}
fn forced_simd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
pub fn forced_simd_test_lock() -> MutexGuard<'static, ()> {
    forced_simd_lock()
        .lock()
        .expect("forced_simd lock poisoned")
}
fn encode_override(choice: Option<SimdChoice>) -> u8 {
    match choice {
        None => 0,
        Some(SimdChoice::Scalar) => 1,
        Some(SimdChoice::Sse2) => 2,
        Some(SimdChoice::Avx2) => 3,
        Some(SimdChoice::Avx512) => 4,
        Some(SimdChoice::Neon) => 5,
    }
}
fn decode_override(val: u8) -> Option<SimdChoice> {
    match val {
        1 => Some(SimdChoice::Scalar),
        2 => Some(SimdChoice::Sse2),
        3 => Some(SimdChoice::Avx2),
        4 => Some(SimdChoice::Avx512),
        5 => Some(SimdChoice::Neon),
        _ => None,
    }
}
fn clamp_to_supported(choice: SimdChoice) -> SimdChoice {
    match choice {
        SimdChoice::Scalar => SimdChoice::Scalar,
        #[cfg(target_arch = "x86_64")]
        SimdChoice::Avx512 => {
            if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx2") {
                SimdChoice::Avx512
            } else {
                SimdChoice::Scalar
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        SimdChoice::Avx512 => SimdChoice::Scalar,
        #[cfg(target_arch = "x86_64")]
        SimdChoice::Avx2 => {
            if std::is_x86_feature_detected!("avx2") {
                SimdChoice::Avx2
            } else {
                SimdChoice::Scalar
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        SimdChoice::Avx2 => SimdChoice::Scalar,
        #[cfg(target_arch = "x86_64")]
        SimdChoice::Sse2 => {
            if std::is_x86_feature_detected!("sse2") {
                SimdChoice::Sse2
            } else {
                SimdChoice::Scalar
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        SimdChoice::Sse2 => SimdChoice::Scalar,
        #[cfg(target_arch = "aarch64")]
        SimdChoice::Neon => {
            if std::arch::is_aarch64_feature_detected!("neon") {
                SimdChoice::Neon
            } else {
                SimdChoice::Scalar
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        SimdChoice::Neon => SimdChoice::Scalar,
    }
}
/// Return any configured process-wide SIMD override, clamped to supported backends.
pub(crate) fn forced_simd_choice() -> Option<SimdChoice> {
    if let Some(choice) = TLS_SIMD_OVERRIDE.with(|c| decode_override(c.get())) {
        return Some(clamp_to_supported(choice));
    }
    decode_override(SIMD_OVERRIDE.load(Ordering::Relaxed)).map(clamp_to_supported)
}
/// Override runtime SIMD detection for this process.
///
/// This is intended for configuration- or test-driven overrides rather than
/// production feature gating; unsupported overrides fall back to `Scalar`.
/// Returns the previously configured override, if any.
pub fn set_forced_simd(choice: Option<SimdChoice>) -> Option<SimdChoice> {
    decode_override(SIMD_OVERRIDE.swap(encode_override(choice), Ordering::Relaxed))
}
/// Clear any configured SIMD override and resume hardware detection.
pub fn clear_forced_simd() {
    set_forced_simd(None);
}
fn detect_simd_choice() -> SimdChoice {
    *SIMD_CHOICE.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx2") {
                return SimdChoice::Avx512;
            }
            if std::is_x86_feature_detected!("avx2") {
                return SimdChoice::Avx2;
            }
            if std::is_x86_feature_detected!("sse2") {
                return SimdChoice::Sse2;
            }
            SimdChoice::Scalar
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return SimdChoice::Neon;
            }
            SimdChoice::Scalar
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            SimdChoice::Scalar
        }
    })
}
/// Return the hardware-detected SIMD choice without policy/override influence.
pub(crate) fn detected_simd_choice() -> SimdChoice {
    detect_simd_choice()
}
/// Whether SIMD is allowed by the current acceleration policy.
pub(crate) fn simd_policy_enabled() -> bool {
    SIMD_POLICY_ENABLED.load(Ordering::Relaxed)
}
/// Apply a process-wide SIMD policy. When disabled, SIMD detection/overrides are
/// ignored and scalar execution is forced.
pub(crate) fn set_simd_policy_enabled(enabled: bool) {
    SIMD_POLICY_ENABLED.store(enabled, Ordering::SeqCst);
    if enabled {
        clear_forced_simd();
    } else {
        set_forced_simd(Some(SimdChoice::Scalar));
    }
}
/// Override runtime SIMD detection for the current thread only.
/// Returns the previous thread-local override (if any).
pub fn set_thread_forced_simd(choice: Option<SimdChoice>) -> Option<SimdChoice> {
    TLS_SIMD_OVERRIDE.with(|cell| {
        let prev = cell.replace(encode_override(choice));
        decode_override(prev)
    })
}
/// Clear the thread-local override.
pub fn clear_thread_forced_simd() {
    set_thread_forced_simd(None);
}
#[cfg(all(target_os = "macos", feature = "metal"))]
static METAL_ARTIFACT_INVALID: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_os = "macos", feature = "metal"))]
static METAL_FORCED_DISABLED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_os = "macos", feature = "metal"))]
static METAL_CONFIG_ENABLED: AtomicBool = AtomicBool::new(true);
#[cfg(all(target_os = "macos", feature = "metal"))]
static METAL_LAST_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_error_slot() -> &'static Mutex<Option<String>> {
    METAL_LAST_ERROR.get_or_init(|| Mutex::new(None))
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn set_metal_status_message(message: Option<String>) {
    if let Ok(mut guard) = metal_error_slot().lock() {
        *guard = message;
    }
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn record_metal_disable(reason: impl Into<String>) {
    let message = reason.into();
    if let Some(health) = metal_runtime::current_health() {
        health.quarantine(false);
    }
    if let Ok(mut guard) = metal_error_slot().lock() {
        *guard = Some(message.clone());
    }
    eprintln!("ivm: selected Metal device quarantined: {message}");
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_last_error_message() -> Option<String> {
    metal_error_slot()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
pub(crate) fn metal_last_error_message() -> Option<String> {
    None
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_env_disabled() -> bool {
    if !crate::dev_env::dev_env_flag("IVM_DISABLE_METAL") {
        return false;
    }
    let disabled = std::env::var("IVM_DISABLE_METAL")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    if disabled {
        set_metal_status_message(Some(
            "disabled by IVM_DISABLE_METAL environment override".to_owned(),
        ));
    }
    disabled
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_policy_enabled() -> bool {
    if crate::acceleration_config().max_gpus == Some(0)
        || crate::acceleration_config().resource_limits.devices == 0
        || metal_env_disabled()
    {
        return false;
    }
    if !METAL_CONFIG_ENABLED.load(Ordering::SeqCst) {
        return false;
    }
    if METAL_FORCED_DISABLED.load(Ordering::SeqCst) {
        return false;
    }
    true
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_runtime_allowed() -> bool {
    metal_policy_enabled()
        && !METAL_ARTIFACT_INVALID.load(Ordering::SeqCst)
        && metal_runtime::current_allowed()
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub fn metal_disabled() -> bool {
    !metal_policy_enabled()
        || METAL_ARTIFACT_INVALID.load(Ordering::SeqCst)
        || !metal_runtime::current_allowed()
        || metal_runtime::all_quarantined()
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
pub fn metal_disabled() -> bool {
    false
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_parity_ok() -> bool {
    !METAL_ARTIFACT_INVALID.load(Ordering::SeqCst)
        && metal_runtime::current_allowed()
        && !metal_runtime::all_quarantined()
}
/// Detect the best available SIMD option for the current platform.
pub fn simd_choice() -> SimdChoice {
    if !simd_policy_enabled() {
        return SimdChoice::Scalar;
    }
    if let Some(choice) = forced_simd_choice() {
        return choice;
    }
    detect_simd_choice()
}
/// Return true if the host CPU supports SIMD operations that the vector extension can leverage.
pub fn vector_supported() -> bool {
    simd_choice() != SimdChoice::Scalar
}
/// Return the detected SIMD vector width in bits. Platforms without SIMD
/// support fall back to 32-bit scalar operations.
pub fn simd_bits() -> usize {
    match simd_choice() {
        SimdChoice::Avx512 => 512,
        SimdChoice::Avx2 => 256,
        SimdChoice::Sse2 | SimdChoice::Neon => 128,
        SimdChoice::Scalar => 32,
    }
}
/// Number of 32-bit lanes available for vector operations.
pub fn simd_lanes() -> usize {
    simd_bits() / 32
}
/// Return a short string describing the SIMD backend selected at runtime.
pub fn simd_backend() -> &'static str {
    match simd_choice() {
        SimdChoice::Avx512 => "avx512",
        SimdChoice::Avx2 => "avx2",
        SimdChoice::Sse2 => "sse2",
        SimdChoice::Neon => "neon",
        SimdChoice::Scalar => "scalar",
    }
}
/// Return true when the process-owned Metal backend passed startup qualification.
pub fn metal_available() -> bool {
    #[cfg(all(target_os = "macos", feature = "metal"))]
    {
        with_metal_state(|_| ()).is_some()
    }
    #[cfg(not(all(target_os = "macos", feature = "metal")))]
    {
        false
    }
}
#[cfg(all(target_os = "macos", feature = "metal"))]
use objc2::rc::Retained;
#[cfg(all(target_os = "macos", feature = "metal"))]
use objc2::runtime::ProtocolObject;
#[cfg(all(target_os = "macos", feature = "metal"))]
const METAL_KERNELS: &[u8] = include_bytes!("../metal/v1/ivm_kernels.metallib");
#[cfg(all(target_os = "macos", feature = "metal"))]
const METAL_KERNELS_SHA256: [u8; 32] = [
    0xfe, 0x62, 0xa0, 0x35, 0xab, 0x74, 0x81, 0x64, 0x6e, 0x64, 0xc2, 0xf2, 0x72, 0xf3, 0x86, 0x69,
    0xc3, 0x53, 0xb9, 0x5f, 0x5a, 0xb7, 0x9e, 0xc5, 0x87, 0x6d, 0x41, 0x2f, 0x88, 0x23, 0x71, 0x70,
];

#[cfg(all(target_os = "macos", feature = "metal"))]
fn bundled_metal_library(
    device: &ProtocolObject<dyn MTLDevice>,
) -> Option<Retained<ProtocolObject<dyn MTLLibrary>>> {
    use sha2::Digest as _;

    if sha2::Sha256::digest(METAL_KERNELS).as_slice() != METAL_KERNELS_SHA256 {
        METAL_ARTIFACT_INVALID.store(true, Ordering::Release);
        set_metal_status_message(Some("embedded Metal library digest mismatch".to_owned()));
        return None;
    }
    let data = dispatch2::DispatchData::from_static_bytes(METAL_KERNELS);
    device.newLibraryWithData_error(&data).ok()
}
#[cfg(all(target_os = "macos", feature = "metal"))]
struct MetalState {
    device: Retained<ProtocolObject<dyn objc2_metal::MTLDevice>>,
    queue: Retained<ProtocolObject<dyn objc2_metal::MTLCommandQueue>>,
    vadd64: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    vadd32: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    vand: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    vxor: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    vor: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    sha256: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    sha256_leaves: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    sha256_pairs: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    // Ordinary single-round and permutation work stays on the CPU; the startup
    // self-test and required hardware qualification execute these kernels.
    #[cfg(all(test, feature = "metal-hardware-tests"))]
    keccak: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    #[cfg(all(test, feature = "metal-hardware-tests"))]
    aesenc: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    #[cfg(all(test, feature = "metal-hardware-tests"))]
    aesdec: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    aesenc_batch: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    aesdec_batch: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    aesenc_rounds: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    aesdec_rounds: Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>,
    ed25519_signature: Option<Retained<ProtocolObject<dyn objc2_metal::MTLComputePipelineState>>>,
    merkle_rehash_cost: Mutex<metal_merkle_cost_rehash::CostCache>,
    merkle_tree_cost: Mutex<metal_merkle_cost_tree::CostCache>,
    merkle_root_cost: Mutex<metal_merkle_cost_root::CostCache>,
    ed25519_cost: Mutex<metal_ed25519_cost::CostCache>,
    batch_cost: [Mutex<metal_cost::exact::CostCache>; metal_cost::BATCH_FAMILIES],
}
#[cfg(all(target_os = "macos", feature = "metal"))]
trait MetalBufferElement: Copy {}
#[cfg(all(target_os = "macos", feature = "metal"))]
impl MetalBufferElement for u8 {}
#[cfg(all(target_os = "macos", feature = "metal"))]
impl MetalBufferElement for u32 {}
#[cfg(all(target_os = "macos", feature = "metal"))]
impl MetalBufferElement for u64 {}

#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_input_buffer<T: MetalBufferElement>(
    device: &ProtocolObject<dyn MTLDevice>,
    values: &[T],
    byte_len: usize,
) -> Option<MetalBuffer> {
    if byte_len > core::mem::size_of_val(values) {
        return None;
    }
    let mut buffer = MetalBuffer::allocate(device, byte_len)?;
    buffer.copy_input(values, byte_len)?;
    Some(buffer)
}

#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_output_buffer(
    device: &ProtocolObject<dyn MTLDevice>,
    byte_len: usize,
) -> Option<MetalBuffer> {
    MetalBuffer::allocate(device, byte_len)
}

#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_dispatch(
    queue: &ProtocolObject<dyn MTLCommandQueue>,
    pipeline: &ProtocolObject<dyn MTLComputePipelineState>,
    buffers: &[&MetalBuffer],
    grid_width: NSUInteger,
    threadgroup_width: NSUInteger,
    context: &str,
    receipt: Option<MetalKernel>,
) -> Option<()> {
    // Another command may have quarantined this same physical device.
    // No new work from this owner may begin after that failure.
    if !metal_runtime_allowed() {
        return None;
    }
    let mut command = metal_buffers::Command::prepare(queue, buffers)?;
    if !command.encode(pipeline, grid_width, threadgroup_width) {
        command.quarantine();
        set_metal_status_message(Some(format!(
            "{context} could not encode qualified command"
        )));
        return None;
    }
    if !command.commit() {
        return None;
    }
    let outcome = finalize_command_buffer(&mut command, context);
    let completed = matches!(outcome, MetalCommandOutcome::Complete);
    // A command can finish while another thread quarantines the process-owned
    // device. Discard that result and let the caller recompute from its original
    // input on CPU. Only accepted completions earn production receipts.
    let accepted =
        metal_dispatch_result_allowed(completed, command.usable() && metal_runtime_allowed());
    metal_receipts::record_completion(receipt, accepted);
    accepted.then_some(())
}

#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_dispatch_result_allowed(completed: bool, backend_allowed: bool) -> bool {
    completed && backend_allowed
}

#[cfg(all(target_os = "macos", feature = "metal"))]
impl MetalState {
    fn new(device: Retained<ProtocolObject<dyn MTLDevice>>) -> Option<Self> {
        use objc2_foundation::ns_string;
        let queue = device.newCommandQueue()?;
        let lib = bundled_metal_library(&device)?;
        let func = lib.newFunctionWithName(ns_string!("vadd64"))?;
        let vadd64 = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("vadd32"))?;
        let vadd32 = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("vand"))?;
        let vand = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("vxor"))?;
        let vxor = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("vor"))?;
        let vor = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("sha256_compress"))?;
        let sha256 = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        // Batch SHA-256 leaves kernel: one 64-byte block per thread
        let func = lib.newFunctionWithName(ns_string!("sha256_leaves"))?;
        let sha256_leaves = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("sha256_pairs_reduce"))?;
        let sha256_pairs = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        let func = lib.newFunctionWithName(ns_string!("keccak_f1600"))?;
        let keccak = device
            .newComputePipelineStateWithFunction_error(&func)
            .ok()?;
        // AES round kernels (enc/dec)
        let func_e = lib.newFunctionWithName(ns_string!("aesenc_round"))?;
        let aesenc = device
            .newComputePipelineStateWithFunction_error(&func_e)
            .ok()?;
        let func_d = lib.newFunctionWithName(ns_string!("aesdec_round"))?;
        let aesdec = device
            .newComputePipelineStateWithFunction_error(&func_d)
            .ok()?;
        let func_eb = lib.newFunctionWithName(ns_string!("aesenc_round_batch"))?;
        let aesenc_batch = device
            .newComputePipelineStateWithFunction_error(&func_eb)
            .ok()?;
        let func_db = lib.newFunctionWithName(ns_string!("aesdec_round_batch"))?;
        let aesdec_batch = device
            .newComputePipelineStateWithFunction_error(&func_db)
            .ok()?;
        let func_ebr = lib.newFunctionWithName(ns_string!("aesenc_rounds_batch"))?;
        let aesenc_rounds = device
            .newComputePipelineStateWithFunction_error(&func_ebr)
            .ok()?;
        let func_dbr = lib.newFunctionWithName(ns_string!("aesdec_rounds_batch"))?;
        let aesdec_rounds = device
            .newComputePipelineStateWithFunction_error(&func_dbr)
            .ok()?;
        let mut ed25519_signature = lib
            .newFunctionWithName(ns_string!("signature_kernel"))
            .and_then(|func| device.newComputePipelineStateWithFunction_error(&func).ok());
        // Startup self-tests prove parity for required Metal pipelines. Optional
        // pipelines, such as Ed25519 batch verification, can fail closed
        // individually while the rest of the backend remains available.
        let force_fail = if crate::dev_env::dev_env_flag("IVM_FORCE_METAL_SELFTEST_FAIL") {
            std::env::var("IVM_FORCE_METAL_SELFTEST_FAIL")
                .map(|v| v == "1")
                .unwrap_or(false)
        } else {
            false
        };
        if force_fail {
            record_metal_disable("self-test failure forced via IVM_FORCE_METAL_SELFTEST_FAIL");
            return None;
        }
        let debug_selftest = if crate::dev_env::dev_env_flag("IVM_DEBUG_METAL_SELFTEST") {
            std::env::var("IVM_DEBUG_METAL_SELFTEST")
                .map(|v| matches!(v.trim(), "1" | "true" | "TRUE"))
                .unwrap_or(false)
        } else {
            false
        };
        let self_test_ok = {
            // vadd32 quick check
            let a = [1u32, 2, 3, 4];
            let b = [4u32, 3, 2, 1];
            let expect = [5u32, 5, 5, 5];
            let add_ok = {
                let buf_a =
                    metal_input_buffer(&device, &a[..], a.len() * core::mem::size_of::<u32>())?;
                let buf_b =
                    metal_input_buffer(&device, &b[..], b.len() * core::mem::size_of::<u32>())?;
                let buf_out = metal_output_buffer(&device, a.len() * core::mem::size_of::<u32>())?;
                metal_dispatch(
                    &queue,
                    &vadd32,
                    &[&buf_a, &buf_b, &buf_out],
                    1,
                    1,
                    "metal self-test vadd32",
                    None,
                )?;
                let ptr = buf_out.contents().as_ptr() as *const u32;
                let out_slice = unsafe { std::slice::from_raw_parts(ptr, 4) };
                out_slice == expect
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test vadd32 {}",
                    if add_ok { "ok" } else { "FAIL" }
                );
            }
            let add64_ok = {
                let a = [0x0000_0000_ffff_ffff, (0x8000_0000u64 << 32) | 0x0000_0001];
                let b = [
                    (0x0000_0001u64 << 32) | 0x0000_0001,
                    (0x7fff_ffffu64 << 32) | 0xffff_ffff,
                ];
                let expect = [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])];
                let buf_a =
                    metal_input_buffer(&device, &a[..], a.len() * core::mem::size_of::<u64>())?;
                let buf_b =
                    metal_input_buffer(&device, &b[..], b.len() * core::mem::size_of::<u64>())?;
                let buf_out = metal_output_buffer(&device, a.len() * core::mem::size_of::<u64>())?;
                metal_dispatch(
                    &queue,
                    &vadd64,
                    &[&buf_a, &buf_b, &buf_out],
                    1,
                    1,
                    "metal self-test vadd64",
                    None,
                )?;
                let ptr = buf_out.contents().as_ptr() as *const u64;
                let out_slice = unsafe { std::slice::from_raw_parts(ptr, 2) };
                out_slice == expect
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test vadd64 {}",
                    if add64_ok { "ok" } else { "FAIL" }
                );
            }
            let bit_ops_ok = {
                let lhs = [0xffff_0000u32, 0x1234_5678, 0x0f0f_0f0f, 0xaaaa_5555];
                let rhs = [0x00ff_ff00u32, 0xf0f0_f0f0, 0x3333_cccc, 0x5555_aaaa];
                let run_bit = |pipeline, expect: [u32; 4], label: &str| -> Option<bool> {
                    let buf_lhs = metal_input_buffer(
                        &device,
                        &lhs[..],
                        lhs.len() * core::mem::size_of::<u32>(),
                    )?;
                    let buf_rhs = metal_input_buffer(
                        &device,
                        &rhs[..],
                        rhs.len() * core::mem::size_of::<u32>(),
                    )?;
                    let buf_out =
                        metal_output_buffer(&device, lhs.len() * core::mem::size_of::<u32>())?;
                    metal_dispatch(
                        &queue,
                        pipeline,
                        &[&buf_lhs, &buf_rhs, &buf_out],
                        1,
                        1,
                        label,
                        None,
                    )?;
                    let ptr = buf_out.contents().as_ptr() as *const u32;
                    let out_slice = unsafe { std::slice::from_raw_parts(ptr, 4) };
                    Some(out_slice == expect)
                };
                let and_ok = run_bit(
                    &vand,
                    [
                        lhs[0] & rhs[0],
                        lhs[1] & rhs[1],
                        lhs[2] & rhs[2],
                        lhs[3] & rhs[3],
                    ],
                    "metal self-test vand",
                )
                .unwrap_or(false);
                let xor_ok = run_bit(
                    &vxor,
                    [
                        lhs[0] ^ rhs[0],
                        lhs[1] ^ rhs[1],
                        lhs[2] ^ rhs[2],
                        lhs[3] ^ rhs[3],
                    ],
                    "metal self-test vxor",
                )
                .unwrap_or(false);
                let or_ok = run_bit(
                    &vor,
                    [
                        lhs[0] | rhs[0],
                        lhs[1] | rhs[1],
                        lhs[2] | rhs[2],
                        lhs[3] | rhs[3],
                    ],
                    "metal self-test vor",
                )
                .unwrap_or(false);
                and_ok && xor_ok && or_ok
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test vector-bit {}",
                    if bit_ops_ok { "ok" } else { "FAIL" }
                );
            }
            // sha256 compress quick check against local scalar
            let sha_ok = {
                let mut st_scalar = [
                    0x6a09e667u32,
                    0xbb67ae85,
                    0x3c6ef372,
                    0xa54ff53a,
                    0x510e527f,
                    0x9b05688c,
                    0x1f83d9ab,
                    0x5be0cd19,
                ];
                let mut st_metal = st_scalar;
                let mut block = [0u8; 64];
                // "abc" padded
                block[0] = b'a';
                block[1] = b'b';
                block[2] = b'c';
                block[3] = 0x80;
                block[63] = 24;
                sha256_compress_scalar_ref(&mut st_scalar, &block);
                // Run through Metal pipeline
                let buf_state = metal_input_buffer(
                    &device,
                    &st_metal[..],
                    st_metal.len() * core::mem::size_of::<u32>(),
                )?;
                let buf_block = metal_input_buffer(&device, &block[..], block.len())?;
                metal_dispatch(
                    &queue,
                    &sha256,
                    &[&buf_state, &buf_block],
                    1,
                    1,
                    "metal self-test sha256",
                    None,
                )?;
                let ptr = buf_state.contents().as_ptr() as *const u32;
                let out_slice = unsafe { std::slice::from_raw_parts(ptr, 8) };
                st_metal.copy_from_slice(out_slice);
                st_metal == st_scalar
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test sha256 {}",
                    if sha_ok { "ok" } else { "FAIL" }
                );
            }
            let sha_leaves_ok = {
                let mut block_a = [0u8; 64];
                block_a[0] = b'a';
                block_a[1] = b'b';
                block_a[2] = b'c';
                block_a[3] = 0x80;
                block_a[63] = 24;
                let mut block_b = [0u8; 64];
                block_b[0] = b'n';
                block_b[1] = b'o';
                block_b[2] = b'r';
                block_b[3] = b'i';
                block_b[4] = b't';
                block_b[5] = b'o';
                block_b[6] = 0x80;
                block_b[63] = 48;
                let blocks = [block_a, block_b];
                let expected: Vec<[u8; 32]> = blocks
                    .iter()
                    .map(|block| {
                        let mut state = [
                            0x6a09e667u32,
                            0xbb67ae85,
                            0x3c6ef372,
                            0xa54ff53a,
                            0x510e527f,
                            0x9b05688c,
                            0x1f83d9ab,
                            0x5be0cd19,
                        ];
                        sha256_compress_scalar_ref(&mut state, block);
                        let mut digest = [0u8; 32];
                        for (index, word) in state.iter().enumerate() {
                            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                        }
                        digest
                    })
                    .collect();
                let flat: Vec<u8> = blocks
                    .iter()
                    .flat_map(|block| block.iter())
                    .copied()
                    .collect();
                let buf_blocks = metal_input_buffer(&device, &flat[..], flat.len())?;
                let buf_out =
                    metal_output_buffer(&device, blocks.len() * 8 * core::mem::size_of::<u32>())?;
                metal_dispatch(
                    &queue,
                    &sha256_leaves,
                    &[&buf_blocks, &buf_out],
                    blocks.len() as NSUInteger,
                    1,
                    "metal self-test sha256 leaves",
                    None,
                )?;
                let words = unsafe {
                    std::slice::from_raw_parts(
                        buf_out.contents().as_ptr() as *const u32,
                        blocks.len() * 8,
                    )
                };
                let actual: Vec<[u8; 32]> = words
                    .chunks_exact(8)
                    .map(|chunk| {
                        let mut digest = [0u8; 32];
                        for (index, word) in chunk.iter().enumerate() {
                            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                        }
                        digest
                    })
                    .collect();
                actual == expected
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test sha256-leaves {}",
                    if sha_leaves_ok { "ok" } else { "FAIL" }
                );
            }
            // AES round quick check against CPU reference
            let aes_ok = {
                let state = [
                    0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ];
                let rk = [
                    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf,
                    0x7f, 0x67, 0x98,
                ];
                let cpu_enc = crate::aes::aesenc_impl(state, rk);
                let cpu_dec = crate::aes::aesdec_impl(cpu_enc, rk);
                // Run AESENC
                let buf_s = metal_input_buffer(&device, &state[..], 16)?;
                let buf_k = metal_input_buffer(&device, &rk[..], 16)?;
                let buf_out = metal_output_buffer(&device, 16)?;
                metal_dispatch(
                    &queue,
                    &aesenc,
                    &[&buf_s, &buf_k, &buf_out],
                    1,
                    1,
                    "metal self-test aesenc",
                    None,
                )?;
                let mut enc_out = [0u8; 16];
                unsafe {
                    let ptr = buf_out.contents().as_ptr() as *const u8;
                    core::ptr::copy_nonoverlapping(ptr, enc_out.as_mut_ptr(), 16);
                }
                if enc_out != cpu_enc {
                    false
                } else {
                    // Run AESDEC on enc_out
                    let buf_s2 = metal_input_buffer(&device, &enc_out[..], 16)?;
                    let buf_out2 = metal_output_buffer(&device, 16)?;
                    metal_dispatch(
                        &queue,
                        &aesdec,
                        &[&buf_s2, &buf_k, &buf_out2],
                        1,
                        1,
                        "metal self-test aesdec",
                        None,
                    )?;
                    let mut dec_out = [0u8; 16];
                    unsafe {
                        let ptr2 = buf_out2.contents().as_ptr() as *const u8;
                        core::ptr::copy_nonoverlapping(ptr2, dec_out.as_mut_ptr(), 16);
                    }
                    dec_out == cpu_dec
                }
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test aes-round {}",
                    if aes_ok { "ok" } else { "FAIL" }
                );
            }
            let aes_batch_ok = {
                let states = [
                    [
                        0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                        0xcc, 0xdd, 0xee, 0xff,
                    ],
                    [
                        0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                        0x33, 0x22, 0x11, 0x00,
                    ],
                ];
                let rk = [
                    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf,
                    0x7f, 0x67, 0x98,
                ];
                let flat_states: Vec<u8> = states
                    .iter()
                    .flat_map(|state| state.iter())
                    .copied()
                    .collect();
                let run_batch = |pipeline, expected: [[u8; 16]; 2], label: &str| -> Option<bool> {
                    let buf_states =
                        metal_input_buffer(&device, &flat_states[..], flat_states.len())?;
                    let buf_rk = metal_input_buffer(&device, &rk[..], 16)?;
                    let buf_out = metal_output_buffer(&device, flat_states.len())?;
                    metal_dispatch(
                        &queue,
                        pipeline,
                        &[&buf_states, &buf_rk, &buf_out],
                        states.len() as NSUInteger,
                        1,
                        label,
                        None,
                    )?;
                    let ptr = buf_out.contents().as_ptr() as *const u8;
                    let out_slice = unsafe { std::slice::from_raw_parts(ptr, flat_states.len()) };
                    let actual: Vec<[u8; 16]> = out_slice
                        .chunks_exact(16)
                        .map(|chunk| {
                            let mut block = [0u8; 16];
                            block.copy_from_slice(chunk);
                            block
                        })
                        .collect();
                    Some(actual == expected)
                };
                let enc_expected = [
                    crate::aes::aesenc_impl(states[0], rk),
                    crate::aes::aesenc_impl(states[1], rk),
                ];
                let dec_expected = [
                    crate::aes::aesdec_impl(states[0], rk),
                    crate::aes::aesdec_impl(states[1], rk),
                ];
                run_batch(&aesenc_batch, enc_expected, "metal self-test aesenc batch")
                    .unwrap_or(false)
                    && run_batch(&aesdec_batch, dec_expected, "metal self-test aesdec batch")
                        .unwrap_or(false)
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test aes-batch {}",
                    if aes_batch_ok { "ok" } else { "FAIL" }
                );
            }
            // AES fused two-round quick check against CPU streaming
            let aes_fused_ok = {
                let state = [
                    0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ];
                let rk1 = [
                    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf,
                    0x7f, 0x67, 0x98,
                ];
                let mut rk2 = rk1;
                rk2[0] ^= 0xAA;
                rk2[1] ^= 0x55;
                let cpu_enc2 = {
                    let r1 = crate::aes::aesenc_impl(state, rk1);
                    crate::aes::aesenc_impl(r1, rk2)
                };
                let cpu_dec2 = {
                    let r1 = crate::aes::aesdec_impl(cpu_enc2, rk1);
                    crate::aes::aesdec_impl(r1, rk2)
                };
                let flat_states: [u8; 16] = state;
                let rks: [u8; 32] = {
                    let mut buf = [0u8; 32];
                    buf[..16].copy_from_slice(&rk1);
                    buf[16..].copy_from_slice(&rk2);
                    buf
                };
                let buf_states = metal_input_buffer(&device, &flat_states[..], 16)?;
                let buf_rks = metal_input_buffer(&device, &rks[..], 32)?;
                let n_buf = [2u32; 1];
                let buf_n = metal_input_buffer(&device, &n_buf[..], core::mem::size_of::<u32>())?;
                let buf_out = metal_output_buffer(&device, 16)?;
                // ENC 2 rounds
                metal_dispatch(
                    &queue,
                    &aesenc_rounds,
                    &[&buf_states, &buf_rks, &buf_out, &buf_n],
                    1,
                    1,
                    "metal self-test aesenc rounds",
                    None,
                )?;
                let mut enc2 = [0u8; 16];
                unsafe {
                    let ptr = buf_out.contents().as_ptr() as *const u8;
                    core::ptr::copy_nonoverlapping(ptr, enc2.as_mut_ptr(), 16);
                }
                if enc2 != cpu_enc2 {
                    false
                } else {
                    // DEC 2 rounds
                    let buf_states2 = metal_input_buffer(&device, &enc2[..], 16)?;
                    let buf_out2 = metal_output_buffer(&device, 16)?;
                    metal_dispatch(
                        &queue,
                        &aesdec_rounds,
                        &[&buf_states2, &buf_rks, &buf_out2, &buf_n],
                        1,
                        1,
                        "metal self-test aesdec rounds",
                        None,
                    )?;
                    let mut dec2 = [0u8; 16];
                    unsafe {
                        let ptr2 = buf_out2.contents().as_ptr() as *const u8;
                        core::ptr::copy_nonoverlapping(ptr2, dec2.as_mut_ptr(), 16);
                    }
                    dec2 == cpu_dec2
                }
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test aes-fused {}",
                    if aes_fused_ok { "ok" } else { "FAIL" }
                );
            }
            let keccak_ok = {
                let mut init = [0u64; 25];
                for (i, value) in init.iter_mut().enumerate() {
                    *value = (i as u64) * 0x0101_0101_0101_0101u64;
                }
                let mut cpu_state = init;
                crate::sha3::keccak_f1600_impl(&mut cpu_state);
                let mut gpu_state = init;
                let buf_state = metal_input_buffer(
                    &device,
                    &gpu_state[..],
                    gpu_state.len() * core::mem::size_of::<u64>(),
                )?;
                metal_dispatch(
                    &queue,
                    &keccak,
                    &[&buf_state],
                    1,
                    1,
                    "metal self-test keccak",
                    None,
                )?;
                let ptr = buf_state.contents().as_ptr() as *const u64;
                let out = unsafe { std::slice::from_raw_parts(ptr, 25) };
                gpu_state.copy_from_slice(out);
                let ok = gpu_state == cpu_state;
                if debug_selftest && !ok {
                    eprintln!("ivm: metal self-test keccak mismatch:");
                    for i in 0..25 {
                        eprintln!(
                            "  lane {i:02}: cpu=0x{cpu:016x} metal=0x{gpu:016x}",
                            cpu = cpu_state[i],
                            gpu = gpu_state[i]
                        );
                    }
                }
                ok
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test keccak {}",
                    if keccak_ok { "ok" } else { "FAIL" }
                );
            }
            let sha_pairs_ok = {
                fn cpu_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
                    let mut state = [
                        0x6a09e667u32,
                        0xbb67ae85,
                        0x3c6ef372,
                        0xa54ff53a,
                        0x510e527f,
                        0x9b05688c,
                        0x1f83d9ab,
                        0x5be0cd19,
                    ];
                    let mut block = [0u8; 64];
                    block[..32].copy_from_slice(left);
                    block[32..].copy_from_slice(right);
                    sha256_compress_scalar_ref(&mut state, &block);
                    let mut pad = [0u8; 64];
                    pad[0] = 0x80;
                    pad[62] = 0x02;
                    pad[63] = 0x00;
                    sha256_compress_scalar_ref(&mut state, &pad);
                    let mut out = [0u8; 32];
                    for (i, word) in state.iter().enumerate() {
                        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                    }
                    out
                }
                let mut d0 = [0u8; 32];
                let mut d1 = [0u8; 32];
                let mut d2 = [0u8; 32];
                for i in 0..32 {
                    d0[i] = i as u8;
                    d1[i] = 0x40 + i as u8;
                    d2[i] = 0x80 + i as u8;
                }
                let digests = [d0, d1, d2];
                let first = cpu_pair(&digests[0], &digests[1]);
                let expected = cpu_pair(&first, &digests[2]);
                let mut cur = digests
                    .iter()
                    .flat_map(|d| d.iter())
                    .copied()
                    .collect::<Vec<u8>>();
                let mut count = digests.len();
                while count > 1 {
                    let pairs = count / 2;
                    let has_leftover = (count & 1) != 0;
                    let mut next = vec![0u8; (pairs + if has_leftover { 1 } else { 0 }) * 32];
                    if pairs > 0 {
                        let in_buf = metal_input_buffer(&device, &cur[..], cur.len())?;
                        let out_buf =
                            metal_output_buffer(&device, pairs * 8 * core::mem::size_of::<u32>())?;
                        metal_dispatch(
                            &queue,
                            &sha256_pairs,
                            &[&in_buf, &out_buf],
                            pairs as NSUInteger,
                            1,
                            "metal self-test sha256 pairs",
                            None,
                        )?;
                        let words = unsafe {
                            std::slice::from_raw_parts(
                                out_buf.contents().as_ptr() as *const u32,
                                pairs * 8,
                            )
                        };
                        for pair in 0..pairs {
                            for j in 0..8 {
                                let word = words[pair * 8 + j];
                                next[pair * 32 + j * 4..pair * 32 + j * 4 + 4]
                                    .copy_from_slice(&word.to_be_bytes());
                            }
                        }
                    }
                    if has_leftover {
                        let src_idx = (count - 1) * 32;
                        let dst_idx = pairs * 32;
                        next[dst_idx..dst_idx + 32].copy_from_slice(&cur[src_idx..src_idx + 32]);
                    }
                    cur = next;
                    count = cur.len() / 32;
                }
                cur[..32] == expected
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test sha256-pairs {}",
                    if sha_pairs_ok { "ok" } else { "FAIL" }
                );
            }
            let ed25519_ok = {
                use ed25519_dalek::{Signer, SigningKey};
                let key = SigningKey::from_bytes(&[7u8; 32]);
                let pk = key.verifying_key();
                let msg = b"ivm-metal-ed25519";
                let sig = key.sign(msg).to_bytes();
                let hram =
                    crate::signature::ed25519_challenge_scalar_bytes(&sig, pk.as_bytes(), msg);
                let mut sig_bad = sig;
                sig_bad[0] ^= 0x80;
                let sigs = [sig, sig_bad];
                let pks = [pk.to_bytes(), pk.to_bytes()];
                let hrams = [hram, hram];
                let flat_sigs: Vec<u8> = sigs.iter().flat_map(|s| s.iter()).copied().collect();
                let flat_pks: Vec<u8> = pks.iter().flat_map(|p| p.iter()).copied().collect();
                let flat_hrams: Vec<u8> = hrams.iter().flat_map(|h| h.iter()).copied().collect();
                let count_buf = [sigs.len() as u32];
                let buf_sigs = metal_input_buffer(&device, &flat_sigs[..], flat_sigs.len())?;
                let buf_pks = metal_input_buffer(&device, &flat_pks[..], flat_pks.len())?;
                let buf_hrams = metal_input_buffer(&device, &flat_hrams[..], flat_hrams.len())?;
                let buf_count =
                    metal_input_buffer(&device, &count_buf[..], core::mem::size_of::<u32>())?;
                let buf_out = metal_output_buffer(&device, sigs.len())?;
                if let Some(ref pipeline) = ed25519_signature {
                    metal_dispatch(
                        &queue,
                        pipeline,
                        &[&buf_sigs, &buf_pks, &buf_hrams, &buf_count, &buf_out],
                        sigs.len() as NSUInteger,
                        pipeline.threadExecutionWidth(),
                        "metal self-test ed25519 batch",
                        None,
                    )?;
                    let out = unsafe {
                        std::slice::from_raw_parts(
                            buf_out.contents().as_ptr() as *const u8,
                            sigs.len(),
                        )
                    };
                    out == [1u8, 0u8]
                } else {
                    true
                }
            };
            if debug_selftest {
                eprintln!(
                    "ivm: metal self-test ed25519 {}",
                    if ed25519_ok { "ok" } else { "FAIL" }
                );
            }
            if !ed25519_ok {
                eprintln!(
                    "ivm: metal signature kernel self-test failed; disabling only the ed25519 Metal pipeline"
                );
                ed25519_signature = None;
                set_metal_status_message(Some(
                    "metal ed25519 signature kernel self-test mismatch; CPU fallback remains active"
                        .to_owned(),
                ));
            }
            add_ok
                && add64_ok
                && bit_ops_ok
                && sha_ok
                && sha_leaves_ok
                && aes_ok
                && aes_batch_ok
                && aes_fused_ok
                && keccak_ok
                && sha_pairs_ok
        };
        if !self_test_ok {
            if debug_selftest {
                eprintln!("ivm: metal self-test overall result = FAIL");
            }
            #[cfg(target_os = "macos")]
            {
                record_metal_disable("golden-vector self-test mismatch");
            }
            return None;
        } else if debug_selftest {
            eprintln!("ivm: metal self-test overall result = ok");
        }
        Some(Self {
            device,
            queue,
            vadd64,
            vadd32,
            vand,
            vxor,
            vor,
            sha256,
            sha256_leaves,
            sha256_pairs,
            #[cfg(all(test, feature = "metal-hardware-tests"))]
            aesenc,
            #[cfg(all(test, feature = "metal-hardware-tests"))]
            aesdec,
            aesenc_batch,
            aesdec_batch,
            aesenc_rounds,
            aesdec_rounds,
            #[cfg(all(test, feature = "metal-hardware-tests"))]
            keccak,
            ed25519_signature,
            merkle_rehash_cost: Mutex::new(metal_merkle_cost_rehash::CostCache::default()),
            merkle_tree_cost: Mutex::new(metal_merkle_cost_tree::CostCache::default()),
            merkle_root_cost: Mutex::new(metal_merkle_cost_root::CostCache::default()),
            ed25519_cost: Mutex::new(metal_ed25519_cost::CostCache::default()),
            batch_cost: std::array::from_fn(
                |_| Mutex::new(metal_cost::exact::CostCache::default()),
            ),
        })
    }
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn with_metal_state<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&MetalState) -> R,
{
    metal_runtime::with_state(f)
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn with_metal_state_try<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&MetalState) -> Option<R>,
{
    with_metal_state(f).flatten()
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_rehash_tree_auto(tree: &crate::ByteMerkleTree, data: &[u8]) -> bool {
    metal_runtime::metal_rehash_tree_auto(tree, data)
}
#[cfg(all(target_os = "macos", not(feature = "metal")))]
pub(crate) fn metal_rehash_tree_auto(_tree: &crate::ByteMerkleTree, _data: &[u8]) -> bool {
    false
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_root_from_bytes_auto(data: &[u8], chunk: usize) -> Option<[u8; 32]> {
    metal_runtime::metal_root_from_bytes_auto(data, chunk)
}
#[cfg(all(target_os = "macos", not(feature = "metal")))]
pub(crate) fn metal_root_from_bytes_auto(_data: &[u8], _chunk: usize) -> Option<[u8; 32]> {
    None
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn metal_tree_from_bytes_auto(
    data: &[u8],
    chunk: usize,
) -> Option<crate::ByteMerkleTree> {
    metal_runtime::metal_tree_from_bytes_auto(data, chunk)
}
#[cfg(all(target_os = "macos", not(feature = "metal")))]
pub(crate) fn metal_tree_from_bytes_auto(
    _data: &[u8],
    _chunk: usize,
) -> Option<crate::ByteMerkleTree> {
    None
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) fn select_metal_batch(
    work: metal_cost::MetalBatchWork,
    items: usize,
) -> Option<metal_aes::MetalAesSelection> {
    metal_runtime::select_batch(work, items)
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) use metal_cost::MetalBatchWork;
#[cfg(all(target_os = "macos", feature = "metal"))]
enum MetalCommandOutcome {
    Complete,
    Failed,
    Uncertain,
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn finalize_command_buffer(
    command: &mut metal_buffers::Command<'_, '_>,
    context: &str,
) -> MetalCommandOutcome {
    const METAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
    let started = Instant::now();
    loop {
        if let Some(success) = command.observe_completion() {
            if success {
                return MetalCommandOutcome::Complete;
            }
            command.quarantine();
            set_metal_status_message(Some(format!("{context} command buffer failed")));
            return MetalCommandOutcome::Failed;
        }
        if started.elapsed() >= METAL_COMMAND_TIMEOUT {
            command.mark_uncertain();
            set_metal_status_message(Some(format!(
                "{context} command buffer timed out after {METAL_COMMAND_TIMEOUT:?}"
            )));
            return MetalCommandOutcome::Uncertain;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[cfg(all(target_os = "macos", feature = "metal"))]
pub fn release_metal_state() {
    metal_runtime::release();
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
pub fn release_metal_state() {}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vadd64(a: [u32; 4], b: [u32; 4]) -> Option<[u32; 4]> {
    if !metal_runtime_allowed() {
        return None;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state(|ctx| {
            let mut in_a = [0u64; 2];
            let mut in_b = [0u64; 2];
            in_a[0] = (a[0] as u64) | ((a[1] as u64) << 32);
            in_a[1] = (a[2] as u64) | ((a[3] as u64) << 32);
            in_b[0] = (b[0] as u64) | ((b[1] as u64) << 32);
            in_b[1] = (b[2] as u64) | ((b[3] as u64) << 32);
            let buf_a = metal_input_buffer(
                &ctx.device,
                &in_a[..],
                in_a.len() * core::mem::size_of::<u64>(),
            )?;
            let buf_b = metal_input_buffer(
                &ctx.device,
                &in_b[..],
                in_b.len() * core::mem::size_of::<u64>(),
            )?;
            let buf_out =
                metal_output_buffer(&ctx.device, in_a.len() * core::mem::size_of::<u64>())?;
            metal_dispatch(
                &ctx.queue,
                &ctx.vadd64,
                &[&buf_a, &buf_b, &buf_out],
                1,
                1,
                "metal vadd64",
                Some(MetalKernel::Add64),
            )?;
            let ptr = buf_out.contents().as_ptr() as *const u64;
            let out_slice = unsafe { std::slice::from_raw_parts(ptr, 2) };
            let r0 = out_slice[0];
            let r1 = out_slice[1];
            Some([
                (r0 & 0xffff_ffff) as u32,
                (r0 >> 32) as u32,
                (r1 & 0xffff_ffff) as u32,
                (r1 >> 32) as u32,
            ])
        })?
    })
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
fn metal_vadd64(_a: [u32; 4], _b: [u32; 4]) -> Option<[u32; 4]> {
    None
}
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vadd32(a: [u32; 4], b: [u32; 4]) -> Option<[u32; 4]> {
    if !metal_runtime_allowed() {
        return None;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state(|ctx| {
            let buf_a =
                metal_input_buffer(&ctx.device, &a[..], a.len() * core::mem::size_of::<u32>())?;
            let buf_b =
                metal_input_buffer(&ctx.device, &b[..], b.len() * core::mem::size_of::<u32>())?;
            let buf_out = metal_output_buffer(&ctx.device, a.len() * core::mem::size_of::<u32>())?;
            metal_dispatch(
                &ctx.queue,
                &ctx.vadd32,
                &[&buf_a, &buf_b, &buf_out],
                1,
                1,
                "metal vadd32",
                Some(MetalKernel::Add32),
            )?;
            let ptr = buf_out.contents().as_ptr() as *const u32;
            let out_slice = unsafe { std::slice::from_raw_parts(ptr, 4) };
            Some([out_slice[0], out_slice[1], out_slice[2], out_slice[3]])
        })?
    })
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
fn metal_vadd32(_a: [u32; 4], _b: [u32; 4]) -> Option<[u32; 4]> {
    None
}
#[cfg(target_os = "macos")]
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vbit_cached(
    a: [u32; 4],
    b: [u32; 4],
    kernel: MetalKernel,
    select: fn(&MetalState) -> &ProtocolObject<dyn objc2_metal::MTLComputePipelineState>,
) -> Option<[u32; 4]> {
    if !metal_runtime_allowed() {
        return None;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state(|ctx| {
            let pipeline = select(ctx);
            let buf_a =
                metal_input_buffer(&ctx.device, &a[..], a.len() * core::mem::size_of::<u32>())?;
            let buf_b =
                metal_input_buffer(&ctx.device, &b[..], b.len() * core::mem::size_of::<u32>())?;
            let buf_out = metal_output_buffer(&ctx.device, a.len() * core::mem::size_of::<u32>())?;
            metal_dispatch(
                &ctx.queue,
                pipeline,
                &[&buf_a, &buf_b, &buf_out],
                1,
                1,
                "metal vector bit pipeline",
                Some(kernel),
            )?;
            let ptr = buf_out.contents().as_ptr() as *const u32;
            let out_slice = unsafe { std::slice::from_raw_parts(ptr, 4) };
            Some([out_slice[0], out_slice[1], out_slice[2], out_slice[3]])
        })?
    })
}
#[cfg(target_os = "macos")]
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vand(a: [u32; 4], b: [u32; 4]) -> Option<[u32; 4]> {
    metal_vbit_cached(a, b, MetalKernel::And, |ctx| &ctx.vand)
}
#[cfg(target_os = "macos")]
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vxor(a: [u32; 4], b: [u32; 4]) -> Option<[u32; 4]> {
    metal_vbit_cached(a, b, MetalKernel::Xor, |ctx| &ctx.vxor)
}
#[cfg(target_os = "macos")]
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_vor(a: [u32; 4], b: [u32; 4]) -> Option<[u32; 4]> {
    metal_vbit_cached(a, b, MetalKernel::Or, |ctx| &ctx.vor)
}
#[cfg(target_os = "macos")]
#[cfg(all(target_os = "macos", feature = "metal"))]
fn metal_sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) -> bool {
    if !metal_runtime_allowed() {
        return false;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state(|ctx| {
            let Some(buf_state) = metal_input_buffer(
                &ctx.device,
                &state[..],
                state.len() * core::mem::size_of::<u32>(),
            ) else {
                return false;
            };
            let Some(buf_block) = metal_input_buffer(&ctx.device, &block[..], block.len()) else {
                return false;
            };
            if metal_dispatch(
                &ctx.queue,
                &ctx.sha256,
                &[&buf_state, &buf_block],
                1,
                1,
                "metal sha256 compress",
                Some(MetalKernel::Sha256),
            )
            .is_none()
            {
                return false;
            }
            let ptr = buf_state.contents().as_ptr() as *const u32;
            let out_slice = unsafe { std::slice::from_raw_parts(ptr, 8) };
            if !buf_state.usable() {
                return false;
            }
            state.copy_from_slice(out_slice);
            true
        })
        .unwrap_or(false)
    })
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
fn metal_sha256_compress(_state: &mut [u32; 8], _block: &[u8; 64]) -> bool {
    false
}
#[cfg(all(target_os = "macos", feature = "metal"))]
#[path = "vector/metal_merkle.rs"]
mod metal_merkle;
#[cfg(all(test, target_os = "macos", feature = "metal"))]
pub(crate) use metal_merkle::{metal_merkle_root, metal_sha256_leaves, metal_sha256_pairs_reduce};
#[cfg(all(
    test,
    not(all(target_os = "macos", feature = "metal")),
    any(target_os = "macos", test)
))]
pub(crate) fn metal_sha256_leaves(
    _blocks: &[[u8; 64]],
) -> Option<iroha_accel::HostOutput<[u8; 32]>> {
    None
}
#[cfg(all(
    test,
    not(all(target_os = "macos", feature = "metal")),
    any(target_os = "macos", test)
))]
pub(crate) fn metal_sha256_pairs_reduce(_digests: &[[u8; 32]]) -> Option<[u8; 32]> {
    None
}
#[cfg(all(test, not(all(target_os = "macos", feature = "metal"))))]
pub(crate) fn metal_merkle_root(_digests: &[[u8; 32]]) -> Option<[u8; 32]> {
    None
}
#[cfg(all(target_os = "macos", feature = "metal"))]
#[path = "vector/metal_signature.rs"]
mod metal_signature;
#[cfg(all(target_os = "macos", feature = "metal"))]
pub(crate) use metal_runtime::metal_ed25519_auto_into;
#[cfg(all(target_os = "macos", feature = "metal", test))]
pub(crate) use metal_signature::metal_ed25519_verify_batch_into;
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_run_kernel_for_tests(
    function_name: &str,
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
) -> Option<Vec<u8>> {
    if signatures.len() != public_keys.len() || signatures.len() != hrams.len() {
        return None;
    }
    if signatures.is_empty() {
        return Some(Vec::new());
    }
    use objc2::rc::autoreleasepool;
    use objc2_foundation::NSString;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let device = &ctx.device;
            let queue = &ctx.queue;
            let lib = bundled_metal_library(device)?;
            let function_name = NSString::from_str(function_name);
            let func = lib.newFunctionWithName(&function_name)?;
            let pipeline = device
                .newComputePipelineStateWithFunction_error(&func)
                .ok()?;
            let n = signatures.len();
            let flat_sigs: Vec<u8> = signatures.iter().flat_map(|s| s.iter()).copied().collect();
            let flat_pks: Vec<u8> = public_keys.iter().flat_map(|p| p.iter()).copied().collect();
            let flat_hrams: Vec<u8> = hrams.iter().flat_map(|h| h.iter()).copied().collect();
            let count_buf = [n as u32];
            let buf_sigs = metal_input_buffer(device, &flat_sigs[..], flat_sigs.len())?;
            let buf_pks = metal_input_buffer(device, &flat_pks[..], flat_pks.len())?;
            let buf_hrams = metal_input_buffer(device, &flat_hrams[..], flat_hrams.len())?;
            let buf_count =
                metal_input_buffer(device, &count_buf[..], core::mem::size_of::<u32>())?;
            let buf_out = metal_output_buffer(device, n)?;
            metal_dispatch(
                queue,
                &pipeline,
                &[&buf_sigs, &buf_pks, &buf_hrams, &buf_count, &buf_out],
                n as NSUInteger,
                pipeline.threadExecutionWidth().max(1),
                "metal ed25519 batch verify direct",
                None,
            )?;
            let out =
                unsafe { std::slice::from_raw_parts(buf_out.contents().as_ptr() as *const u8, n) };
            Some(out.to_vec())
        })
    })
}
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_verify_batch_direct_for_tests(
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
) -> Option<Vec<bool>> {
    let out =
        metal_ed25519_run_kernel_for_tests("signature_kernel", signatures, public_keys, hrams)?;
    Some(out.into_iter().map(|byte| byte != 0).collect())
}
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_status_batch_direct_for_tests(
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
) -> Option<Vec<u8>> {
    metal_ed25519_run_kernel_for_tests("signature_status_kernel", signatures, public_keys, hrams)
}
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_check_bytes_for_tests(
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
) -> Option<Vec<[u8; 32]>> {
    if signatures.is_empty() {
        return Some(Vec::new());
    }
    use objc2::rc::autoreleasepool;
    use objc2_foundation::NSString;
    if signatures.len() != public_keys.len() || signatures.len() != hrams.len() {
        return None;
    }
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let device = &ctx.device;
            let queue = &ctx.queue;
            let lib = bundled_metal_library(device)?;
            let function_name = NSString::from_str("signature_check_bytes_kernel");
            let func = lib.newFunctionWithName(&function_name)?;
            let pipeline = device
                .newComputePipelineStateWithFunction_error(&func)
                .ok()?;
            let n = signatures.len();
            let flat_sigs: Vec<u8> = signatures
                .iter()
                .flat_map(|sig| sig.iter())
                .copied()
                .collect();
            let flat_pks: Vec<u8> = public_keys
                .iter()
                .flat_map(|pk| pk.iter())
                .copied()
                .collect();
            let flat_hrams: Vec<u8> = hrams
                .iter()
                .flat_map(|scalar| scalar.iter())
                .copied()
                .collect();
            let count_buf = [n as u32];
            let buf_sigs = metal_input_buffer(device, &flat_sigs[..], flat_sigs.len())?;
            let buf_pks = metal_input_buffer(device, &flat_pks[..], flat_pks.len())?;
            let buf_hrams = metal_input_buffer(device, &flat_hrams[..], flat_hrams.len())?;
            let buf_count =
                metal_input_buffer(device, &count_buf[..], core::mem::size_of::<u32>())?;
            let buf_out = metal_output_buffer(device, n * 32)?;
            metal_dispatch(
                queue,
                &pipeline,
                &[&buf_sigs, &buf_pks, &buf_hrams, &buf_count, &buf_out],
                n as NSUInteger,
                pipeline.threadExecutionWidth().max(1),
                "metal ed25519 check bytes direct",
                None,
            )?;
            let out = unsafe {
                std::slice::from_raw_parts(buf_out.contents().as_ptr() as *const u8, n * 32)
            };
            Some(
                out.chunks_exact(32)
                    .map(|chunk| {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(chunk);
                        bytes
                    })
                    .collect(),
            )
        })
    })
}
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_field_roundtrip_for_tests(inputs: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    if inputs.is_empty() {
        return Some(Vec::new());
    }
    use objc2::rc::autoreleasepool;
    use objc2_foundation::NSString;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let device = &ctx.device;
            let queue = &ctx.queue;
            let lib = bundled_metal_library(device)?;
            let function_name = NSString::from_str("field_roundtrip_kernel");
            let func = lib.newFunctionWithName(&function_name)?;
            let pipeline = device
                .newComputePipelineStateWithFunction_error(&func)
                .ok()?;
            let n = inputs.len();
            let flat_inputs: Vec<u8> = inputs
                .iter()
                .flat_map(|point| point.iter())
                .copied()
                .collect();
            let count_buf = [n as u32];
            let buf_inputs = metal_input_buffer(device, &flat_inputs[..], flat_inputs.len())?;
            let buf_count =
                metal_input_buffer(device, &count_buf[..], core::mem::size_of::<u32>())?;
            let buf_out = metal_output_buffer(device, n * 32)?;
            metal_dispatch(
                queue,
                &pipeline,
                &[&buf_inputs, &buf_count, &buf_out],
                n as NSUInteger,
                pipeline.threadExecutionWidth().max(1),
                "metal ed25519 field roundtrip direct",
                None,
            )?;
            let out = unsafe {
                std::slice::from_raw_parts(buf_out.contents().as_ptr() as *const u8, n * 32)
            };
            Some(
                out.chunks_exact(32)
                    .map(|chunk| {
                        let mut value = [0u8; 32];
                        value.copy_from_slice(chunk);
                        value
                    })
                    .collect(),
            )
        })
    })
}
#[cfg(all(target_os = "macos", feature = "metal", test))]
fn metal_ed25519_point_decompress_for_tests(
    inputs: &[[u8; 32]],
) -> Option<(Vec<u8>, Vec<[u8; 32]>)> {
    if inputs.is_empty() {
        return Some((Vec::new(), Vec::new()));
    }
    use objc2::rc::autoreleasepool;
    use objc2_foundation::NSString;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let device = &ctx.device;
            let queue = &ctx.queue;
            let lib = bundled_metal_library(device)?;
            let function_name = NSString::from_str("point_decompress_status_kernel");
            let func = lib.newFunctionWithName(&function_name)?;
            let pipeline = device
                .newComputePipelineStateWithFunction_error(&func)
                .ok()?;
            let n = inputs.len();
            let flat_inputs: Vec<u8> = inputs
                .iter()
                .flat_map(|point| point.iter())
                .copied()
                .collect();
            let count_buf = [n as u32];
            let buf_inputs = metal_input_buffer(device, &flat_inputs[..], flat_inputs.len())?;
            let buf_count =
                metal_input_buffer(device, &count_buf[..], core::mem::size_of::<u32>())?;
            let buf_status = metal_output_buffer(device, n)?;
            let buf_out = metal_output_buffer(device, n * 32)?;
            metal_dispatch(
                queue,
                &pipeline,
                &[&buf_inputs, &buf_count, &buf_status, &buf_out],
                n as NSUInteger,
                pipeline.threadExecutionWidth().max(1),
                "metal ed25519 point decompress direct",
                None,
            )?;
            let statuses = unsafe {
                std::slice::from_raw_parts(buf_status.contents().as_ptr() as *const u8, n)
            };
            let out = unsafe {
                std::slice::from_raw_parts(buf_out.contents().as_ptr() as *const u8, n * 32)
            };
            Some((
                statuses.to_vec(),
                out.chunks_exact(32)
                    .map(|chunk| {
                        let mut value = [0u8; 32];
                        value.copy_from_slice(chunk);
                        value
                    })
                    .collect(),
            ))
        })
    })
}
// Ordinary single-round work uses CPU AES; this entrypoint executes the
// embedded kernel during required hardware qualification.
#[cfg(all(
    target_os = "macos",
    feature = "metal",
    test,
    feature = "metal-hardware-tests"
))]
pub fn metal_aesenc_round(state: [u8; 16], rk: [u8; 16]) -> Option<[u8; 16]> {
    if !metal_runtime_allowed() {
        return None;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let buf_s = metal_input_buffer(&ctx.device, &state[..], 16)?;
            let buf_k = metal_input_buffer(&ctx.device, &rk[..], 16)?;
            let buf_out = metal_output_buffer(&ctx.device, 16)?;
            metal_dispatch(
                &ctx.queue,
                &ctx.aesenc,
                &[&buf_s, &buf_k, &buf_out],
                1,
                1,
                "metal aesenc round",
                Some(MetalKernel::AesEnc),
            )?;
            let mut out = [0u8; 16];
            unsafe {
                let ptr = buf_out.contents().as_ptr() as *const u8;
                core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), 16);
            }
            Some(out)
        })
    })
}
#[cfg(all(
    target_os = "macos",
    feature = "metal",
    test,
    feature = "metal-hardware-tests"
))]
pub fn metal_aesdec_round(state: [u8; 16], rk: [u8; 16]) -> Option<[u8; 16]> {
    if !metal_runtime_allowed() {
        return None;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let buf_s = metal_input_buffer(&ctx.device, &state[..], 16)?;
            let buf_k = metal_input_buffer(&ctx.device, &rk[..], 16)?;
            let buf_out = metal_output_buffer(&ctx.device, 16)?;
            metal_dispatch(
                &ctx.queue,
                &ctx.aesdec,
                &[&buf_s, &buf_k, &buf_out],
                1,
                1,
                "metal aesdec round",
                Some(MetalKernel::AesDec),
            )?;
            let mut out = [0u8; 16];
            unsafe {
                let ptr = buf_out.contents().as_ptr() as *const u8;
                core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), 16);
            }
            Some(out)
        })
    })
}
#[cfg(all(
    target_os = "macos",
    feature = "metal",
    test,
    feature = "metal-hardware-tests"
))]
pub fn metal_keccak_f1600(state: &mut [u64; 25]) -> bool {
    if !metal_runtime_allowed() {
        return false;
    }
    use objc2::rc::autoreleasepool;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            let buf =
                metal_input_buffer(&ctx.device, &state[..], 25 * core::mem::size_of::<u64>())?;
            metal_dispatch(
                &ctx.queue,
                &ctx.keccak,
                &[&buf],
                1,
                1,
                "metal keccak_f1600",
                Some(MetalKernel::Keccak),
            )?;
            let ptr = buf.contents().as_ptr() as *const u64;
            let out = unsafe { std::slice::from_raw_parts(ptr, 25) };
            if !buf.usable() {
                return None;
            }
            state.copy_from_slice(out);
            Some(())
        })
    })
    .is_some()
}
#[cfg(all(target_os = "macos", feature = "metal"))]
#[path = "vector/metal_aes.rs"]
mod metal_aes;
#[cfg(all(target_os = "macos", feature = "metal-hardware-tests", test))]
pub(crate) use metal_aes::metal_aes_batch_in_place;
#[cfg(all(target_os = "macos", feature = "metal", test))]
pub use metal_aes::{
    metal_aesdec_batch_into, metal_aesdec_rounds_batch_into, metal_aesenc_batch_into,
    metal_aesenc_rounds_batch_into,
};
// A fixed IVM vector instruction or one SHA-256 block cannot amortize even a
// single GPU transfer and launch. The M1 Ultra local comparison measured
// 100,000 four-lane additions at 930.5 us on CPU and 177.67 s via Metal.
// Metal Merkle, AES batches and Ed25519 batches use separate qualified cost
// profiles. This floor remains for fixed-size operations and provisional CUDA
// batch selection until CUDA has independently qualified public cost profiles.
const MIN_GPU_TRANSFER_BYTES: usize = 4 * 1024;
#[cfg(any(test, target_os = "macos", feature = "cuda"))]
const FIXED_VECTOR_TRANSFER_BYTES: usize = 3 * std::mem::size_of::<[u32; 4]>();
const SHA256_BLOCK_TRANSFER_BYTES: usize =
    2 * std::mem::size_of::<[u32; 8]>() + std::mem::size_of::<[u8; 64]>();

pub(crate) fn gpu_launch_eligible(transfer_bytes: usize) -> bool {
    transfer_bytes >= MIN_GPU_TRANSFER_BYTES
}

/// Perform one SHA-256 compression round on a 64 byte block.
pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    if gpu_launch_eligible(SHA256_BLOCK_TRANSFER_BYTES) && metal_sha256_compress(state, block) {
        return;
    }
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(SHA256_BLOCK_TRANSFER_BYTES)
        && crate::cuda::sha256_compress_cuda(state, block)
    {
        return;
    }
    Sha256Context::production().compress(state, block);
}
/// Lane-wise addition of two 32-bit vectors. The length of `a` and `b` must
/// match and determines the number of lanes processed.
pub fn vadd32_slice(a: &[u32], b: &[u32], out: &mut [u32]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
                    let vr = _mm256_add_epi32(va, vb);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_add_epi32(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i].wrapping_add(b[i]);
                    i += 1;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_add_epi32(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i].wrapping_add(b[i]);
                    i += 1;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            while i + 4 <= len {
                let va = vld1q_u32(a.as_ptr().add(i));
                let vb = vld1q_u32(b.as_ptr().add(i));
                let vr = vaddq_u32(va, vb);
                vst1q_u32(out.as_mut_ptr().add(i), vr);
                i += 4;
            }
            while i < len {
                out[i] = a[i].wrapping_add(b[i]);
                i += 1;
            }
            return;
        }
    }
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        *o = x.wrapping_add(y);
    }
}
/// Lane-wise bitwise AND of two vectors.
pub fn vand_slice(a: &[u32], b: &[u32], out: &mut [u32]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
                    let vr = _mm256_and_si256(va, vb);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_and_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] & b[i];
                    i += 1;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_and_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] & b[i];
                    i += 1;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            while i + 4 <= len {
                let va = vld1q_u32(a.as_ptr().add(i));
                let vb = vld1q_u32(b.as_ptr().add(i));
                let vr = vandq_u32(va, vb);
                vst1q_u32(out.as_mut_ptr().add(i), vr);
                i += 4;
            }
            while i < len {
                out[i] = a[i] & b[i];
                i += 1;
            }
            return;
        }
    }
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        *o = x & y;
    }
}
/// Lane-wise bitwise XOR of two vectors.
pub fn vxor_slice(a: &[u32], b: &[u32], out: &mut [u32]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
                    let vr = _mm256_xor_si256(va, vb);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_xor_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] ^ b[i];
                    i += 1;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_xor_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] ^ b[i];
                    i += 1;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            while i + 4 <= len {
                let va = vld1q_u32(a.as_ptr().add(i));
                let vb = vld1q_u32(b.as_ptr().add(i));
                let vr = veorq_u32(va, vb);
                vst1q_u32(out.as_mut_ptr().add(i), vr);
                i += 4;
            }
            while i < len {
                out[i] = a[i] ^ b[i];
                i += 1;
            }
            return;
        }
    }
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
}
/// Lane-wise bitwise OR of two vectors.
pub fn vor_slice(a: &[u32], b: &[u32], out: &mut [u32]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
                    let vr = _mm256_or_si256(va, vb);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_or_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] | b[i];
                    i += 1;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_or_si128(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i] | b[i];
                    i += 1;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            while i + 4 <= len {
                let va = vld1q_u32(a.as_ptr().add(i));
                let vb = vld1q_u32(b.as_ptr().add(i));
                let vr = vorrq_u32(va, vb);
                vst1q_u32(out.as_mut_ptr().add(i), vr);
                i += 4;
            }
            while i < len {
                out[i] = a[i] | b[i];
                i += 1;
            }
            return;
        }
    }
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        *o = x | y;
    }
}
/// Rotate each 32-bit lane left by `k` bits.
pub fn vrot32_slice(a: &[u32], k: u32, out: &mut [u32]) {
    debug_assert_eq!(a.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                let k = (k & 31) as i32;
                let shl = _mm_cvtsi32_si128(k);
                let shr = _mm_cvtsi32_si128(32 - k);
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let left = _mm256_sll_epi32(va, shl);
                    let right = _mm256_srl_epi32(va, shr);
                    let vr = _mm256_or_si256(left, right);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let left = _mm_sll_epi32(va, shl);
                    let right = _mm_srl_epi32(va, shr);
                    let vr = _mm_or_si128(left, right);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i].rotate_left(k as u32);
                    i += 1;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                let k = (k & 31) as i32;
                let shl = _mm_cvtsi32_si128(k);
                let shr = _mm_cvtsi32_si128(32 - k);
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let left = _mm_sll_epi32(va, shl);
                    let right = _mm_srl_epi32(va, shr);
                    let vr = _mm_or_si128(left, right);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    out[i] = a[i].rotate_left(k as u32);
                    i += 1;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            let k = (k & 31) as i32;
            let sh_left = vdupq_n_s32(k);
            let sh_right = vdupq_n_s32(-(32 - k));
            while i + 4 <= len {
                let va = vld1q_u32(a.as_ptr().add(i));
                let left = vshlq_u32(va, sh_left);
                let right = vshlq_u32(va, sh_right);
                let vr = vorrq_u32(left, right);
                vst1q_u32(out.as_mut_ptr().add(i), vr);
                i += 4;
            }
            while i < len {
                out[i] = a[i].rotate_left(k as u32);
                i += 1;
            }
            return;
        }
    }
    for (o, &x) in out.iter_mut().zip(a) {
        *o = x.rotate_left(k);
    }
}
/// Lane-wise 64-bit addition. The vector must have an even number of lanes.
pub fn vadd64_slice(a: &[u32], b: &[u32], out: &mut [u32]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    debug_assert!(a.len().is_multiple_of(2));
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match simd_choice() {
            SimdChoice::Avx512 | SimdChoice::Avx2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 8 <= len {
                    let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
                    let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
                    let vr = _mm256_add_epi64(va, vb);
                    _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr);
                    i += 8;
                }
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_add_epi64(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    let a0 = (a[i] as u64) | ((a[i + 1] as u64) << 32);
                    let b0 = (b[i] as u64) | ((b[i + 1] as u64) << 32);
                    let r = a0.wrapping_add(b0);
                    out[i] = (r & 0xffff_ffff) as u32;
                    out[i + 1] = (r >> 32) as u32;
                    i += 2;
                }
                return;
            }
            SimdChoice::Sse2 => {
                use core::arch::x86_64::*;
                let mut i = 0usize;
                let len = a.len();
                while i + 4 <= len {
                    let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
                    let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
                    let vr = _mm_add_epi64(va, vb);
                    _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, vr);
                    i += 4;
                }
                while i < len {
                    let a0 = (a[i] as u64) | ((a[i + 1] as u64) << 32);
                    let b0 = (b[i] as u64) | ((b[i + 1] as u64) << 32);
                    let r = a0.wrapping_add(b0);
                    out[i] = (r & 0xffff_ffff) as u32;
                    out[i + 1] = (r >> 32) as u32;
                    i += 2;
                }
                return;
            }
            _ => {}
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if matches!(simd_choice(), SimdChoice::Neon) {
            use core::arch::aarch64::*;
            let mut i = 0usize;
            let len = a.len();
            while i + 4 <= len {
                // Load as u32x4, reinterpret to u64x2, add, reinterpret back to u32x4.
                let va32 = vld1q_u32(a.as_ptr().add(i));
                let vb32 = vld1q_u32(b.as_ptr().add(i));
                let va64 = vreinterpretq_u64_u32(va32);
                let vb64 = vreinterpretq_u64_u32(vb32);
                let vr64 = vaddq_u64(va64, vb64);
                let vr32 = vreinterpretq_u32_u64(vr64);
                vst1q_u32(out.as_mut_ptr().add(i), vr32);
                i += 4;
            }
            while i < len {
                let a0 = (a[i] as u64) | ((a[i + 1] as u64) << 32);
                let b0 = (b[i] as u64) | ((b[i + 1] as u64) << 32);
                let r = a0.wrapping_add(b0);
                out[i] = (r & 0xffff_ffff) as u32;
                out[i + 1] = (r >> 32) as u32;
                i += 2;
            }
            return;
        }
    }
    for i in (0..a.len()).step_by(2) {
        let a0 = (a[i] as u64) | ((a[i + 1] as u64) << 32);
        let b0 = (b[i] as u64) | ((b[i + 1] as u64) << 32);
        let r = a0.wrapping_add(b0);
        out[i] = (r & 0xffff_ffff) as u32;
        out[i + 1] = (r >> 32) as u32;
    }
}
/// Construct requested logical lanes from the caller's original execution lease.
/// Include `ExecutionMemoryPlan::array::<u32>(lanes)` in the complete
/// parent plan before calling. The allocation keeps its charge until final drop.
pub fn zero_vector(
    lanes: usize,
    lease: &mut crate::execution_memory::ExecutionMemoryLease,
) -> Result<crate::execution_memory::ExecutionBuffer<u32>, iroha_allocation::PrepaidBufferError> {
    let mut output = crate::execution_memory::ExecutionBuffer::new(lanes, lease)?;
    for _ in 0..lanes {
        output.push_reserved(0);
    }
    Ok(output)
}
/// Apply `vadd32` using the available SIMD path into initialized caller-owned storage.
/// Dynamic callers may borrow their prepaid ExecutionBuffer's initialized slice.
pub fn vadd32_auto_into(a: &[u32], b: &[u32], output: &mut [u32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(output.len(), a.len());

    vadd32_slice(a, b, output);
}
/// Apply `vadd64` using the available SIMD path into initialized caller-owned storage.
/// Dynamic callers may borrow their prepaid ExecutionBuffer's initialized slice.
pub fn vadd64_auto_into(a: &[u32], b: &[u32], output: &mut [u32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(output.len(), a.len());
    assert!(a.len().is_multiple_of(2));
    vadd64_slice(a, b, output);
}
/// Apply `vand` using the available SIMD path into initialized caller-owned storage.
/// Dynamic callers may borrow their prepaid ExecutionBuffer's initialized slice.
pub fn vand_auto_into(a: &[u32], b: &[u32], output: &mut [u32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(output.len(), a.len());

    vand_slice(a, b, output);
}
/// Apply `vxor` using the available SIMD path into initialized caller-owned storage.
/// Dynamic callers may borrow their prepaid ExecutionBuffer's initialized slice.
pub fn vxor_auto_into(a: &[u32], b: &[u32], output: &mut [u32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(output.len(), a.len());

    vxor_slice(a, b, output);
}
/// Apply `vor` using the available SIMD path into initialized caller-owned storage.
/// Dynamic callers may borrow their prepaid ExecutionBuffer's initialized slice.
pub fn vor_auto_into(a: &[u32], b: &[u32], output: &mut [u32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(output.len(), a.len());

    vor_slice(a, b, output);
}
/// Rotate logical lanes using the available SIMD path into caller-owned storage.
pub fn vrot32_auto_into(a: &[u32], k: u32, output: &mut [u32]) {
    assert_eq!(output.len(), a.len());
    vrot32_slice(a, k, output);
}
/// Lane-wise 32-bit addition of two vectors.
pub fn vadd32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    #[cfg(target_os = "macos")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && let Some(res) = metal_vadd32(a, b)
    {
        return res;
    }
    let mut out = [0; 4];
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && crate::cuda::vadd32_cuda_into(&a, &b, &mut out)
    {
        return out;
    }
    vadd32_slice(&a, &b, &mut out);
    out
}
/// Lane-wise 64-bit addition (two lanes).
pub fn vadd64(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    #[cfg(target_os = "macos")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && let Some(res) = metal_vadd64(a, b)
    {
        return res;
    }
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES) {
        let a64 = [
            (a[0] as u64) | ((a[1] as u64) << 32),
            (a[2] as u64) | ((a[3] as u64) << 32),
        ];
        let b64 = [
            (b[0] as u64) | ((b[1] as u64) << 32),
            (b[2] as u64) | ((b[3] as u64) << 32),
        ];
        let mut res = [0; 2];
        if crate::cuda::vadd64_cuda_into(&a64, &b64, &mut res) {
            let r0 = res[0];
            let r1 = res[1];
            return [
                (r0 & 0xffff_ffff) as u32,
                (r0 >> 32) as u32,
                (r1 & 0xffff_ffff) as u32,
                (r1 >> 32) as u32,
            ];
        }
    }
    let mut out = [0; 4];
    vadd64_slice(&a, &b, &mut out);
    out
}
/// Bitwise AND of two vectors.
pub fn vand(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && let Some(res) = metal_vand(a, b)
    {
        return res;
    }
    let mut out = [0; 4];
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && crate::cuda::vand_cuda_into(&a, &b, &mut out)
    {
        return out;
    }
    vand_slice(&a, &b, &mut out);
    out
}
/// Bitwise XOR of two vectors.
pub fn vxor(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && let Some(res) = metal_vxor(a, b)
    {
        return res;
    }
    let mut out = [0; 4];
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && crate::cuda::vxor_cuda_into(&a, &b, &mut out)
    {
        return out;
    }
    vxor_slice(&a, &b, &mut out);
    out
}
/// Bitwise OR of two vectors.
pub fn vor(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && let Some(res) = metal_vor(a, b)
    {
        return res;
    }
    let mut out = [0; 4];
    #[cfg(feature = "cuda")]
    if gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES)
        && crate::cuda::vor_cuda_into(&a, &b, &mut out)
    {
        return out;
    }
    vor_slice(&a, &b, &mut out);
    out
}
/// Rotate each 32-bit lane left by `k` bits.
pub fn vrot32(a: [u32; 4], k: u32) -> [u32; 4] {
    let mut out = [0; 4];
    vrot32_slice(&a, k, &mut out);
    out
}
// Expose a small toggle to force-enable/disable Metal in tests and tooling.
#[cfg(all(target_os = "macos", feature = "metal"))]
pub fn set_metal_enabled(enabled: bool) {
    METAL_CONFIG_ENABLED.store(enabled, Ordering::SeqCst);
    METAL_FORCED_DISABLED.store(!enabled, Ordering::SeqCst);
    if !enabled {
        set_metal_status_message(Some("disabled by configuration".to_owned()));
        release_metal_state();
    } else {
        set_metal_status_message(None);
    }
}
#[cfg(all(target_os = "macos", feature = "metal"))]
#[doc(hidden)]
pub fn reset_metal_backend_for_tests() {
    METAL_ARTIFACT_INVALID.store(false, Ordering::SeqCst);
    METAL_FORCED_DISABLED.store(false, Ordering::SeqCst);
    METAL_CONFIG_ENABLED.store(true, Ordering::SeqCst);
    release_metal_state();
    set_metal_status_message(None);
}
#[cfg(not(all(target_os = "macos", feature = "metal")))]
#[doc(hidden)]
pub fn reset_metal_backend_for_tests() {}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn completed_metal_work_is_rejected_after_owner_quarantine() {
        assert!(metal_dispatch_result_allowed(true, true));
        assert!(!metal_dispatch_result_allowed(false, true));
        assert!(!metal_dispatch_result_allowed(true, false));
        assert!(!metal_dispatch_result_allowed(false, false));
    }

    #[test]
    fn fixed_width_operations_skip_gpu_launch() {
        assert_eq!(FIXED_VECTOR_TRANSFER_BYTES, 48);
        assert_eq!(SHA256_BLOCK_TRANSFER_BYTES, 128);
        assert!(!gpu_launch_eligible(FIXED_VECTOR_TRANSFER_BYTES));
        assert!(!gpu_launch_eligible(SHA256_BLOCK_TRANSFER_BYTES));
        assert!(!gpu_launch_eligible(MIN_GPU_TRANSFER_BYTES - 1));
        assert!(gpu_launch_eligible(MIN_GPU_TRANSFER_BYTES));

        let a = [u32::MAX, 2, 3, 4];
        let b = [1, 3, 5, 7];
        assert_eq!(vadd32(a, b), [0, 5, 8, 11]);
        assert_eq!(vand(a, b), [1, 2, 1, 4]);
        assert_eq!(vxor(a, b), [u32::MAX - 1, 1, 6, 3]);
        assert_eq!(vor(a, b), [u32::MAX, 3, 7, 7]);
    }
    #[cfg(not(all(target_os = "macos", feature = "metal")))]
    #[test]
    fn metal_sha256_merkle_helpers_return_none_without_metal_feature() {
        let block = [0u8; 64];
        let digest = [0u8; 32];
        assert!(metal_sha256_leaves(&[block]).is_none());
        assert_eq!(metal_sha256_pairs_reduce(&[digest]), None);
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_sha256_leaves_matches_cpu() {
        if !metal_available() {
            eprintln!("Metal unavailable; skipping sha256 leaves parity test");
            return;
        }
        reset_metal_backend_for_tests();
        let mut block_a = [0u8; 64];
        block_a[0] = b'a';
        block_a[1] = b'b';
        block_a[2] = b'c';
        block_a[3] = 0x80;
        block_a[63] = 24;
        let mut block_b = [0u8; 64];
        block_b[0] = b'n';
        block_b[1] = b'o';
        block_b[2] = b'r';
        block_b[3] = b'i';
        block_b[4] = b't';
        block_b[5] = b'o';
        block_b[6] = 0x80;
        block_b[63] = 48;
        let blocks = [block_a, block_b];
        let expected: Vec<[u8; 32]> = blocks
            .iter()
            .map(|block| {
                let mut state = [
                    0x6a09e667u32,
                    0xbb67ae85,
                    0x3c6ef372,
                    0xa54ff53a,
                    0x510e527f,
                    0x9b05688c,
                    0x1f83d9ab,
                    0x5be0cd19,
                ];
                sha256_compress_scalar_ref(&mut state, block);
                let mut digest = [0u8; 32];
                for (index, word) in state.iter().enumerate() {
                    digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                digest
            })
            .collect();
        let Some(actual) = metal_sha256_leaves(&blocks) else {
            eprintln!(
                "Metal backend unavailable after startup self-tests; skipping sha256 leaves parity test",
            );
            return;
        };
        assert_eq!(actual.as_slice(), expected.as_slice());
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_sha256_pairs_reduce_matches_cpu() {
        fn cpu_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let mut state = [
                0x6a09e667u32,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut block = [0u8; 64];
            block[..32].copy_from_slice(left);
            block[32..].copy_from_slice(right);
            sha256_compress_scalar_ref(&mut state, &block);
            let mut pad = [0u8; 64];
            pad[0] = 0x80;
            pad[62] = 0x02;
            pad[63] = 0x00;
            sha256_compress_scalar_ref(&mut state, &pad);
            let mut out = [0u8; 32];
            for (index, word) in state.iter().enumerate() {
                out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }
        if !metal_available() {
            eprintln!("Metal unavailable; skipping sha256 pair-reduce parity test");
            return;
        }
        reset_metal_backend_for_tests();
        let mut d0 = [0u8; 32];
        let mut d1 = [0u8; 32];
        let mut d2 = [0u8; 32];
        for (index, byte) in d0.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in d1.iter_mut().enumerate() {
            *byte = 0x40 + index as u8;
        }
        for (index, byte) in d2.iter_mut().enumerate() {
            *byte = 0x80 + index as u8;
        }
        let digests = [d0, d1, d2];
        let first = cpu_pair(&digests[0], &digests[1]);
        let expected = cpu_pair(&first, &digests[2]);
        assert_eq!(metal_sha256_pairs_reduce(&digests), Some(expected));
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_merkle_root_matches_canonical_hash_markers() {
        use sha2::Digest as _;

        if !metal_available() {
            return;
        }
        let leaves: Vec<[u8; 32]> = (0..5u8)
            .map(|value| sha2::Sha256::digest([value; 32]).into())
            .collect();
        for count in [1usize, 3, 4, 5] {
            let expected = iroha_crypto::MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(
                leaves[..count].iter().copied(),
            );
            assert_eq!(
                metal_merkle_root(&leaves[..count]),
                expected.root().map(|root| *root.as_ref()),
            );
        }
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_ed25519_batch_matches_cpu() {
        use curve25519_dalek::{
            constants::{ED25519_BASEPOINT_COMPRESSED, ED25519_BASEPOINT_POINT},
            edwards::{CompressedEdwardsY, EdwardsPoint},
            scalar::Scalar,
        };
        use ed25519_dalek::{Signer, SigningKey};
        if !metal_available() {
            eprintln!("Metal unavailable; skipping ed25519 batch parity test");
            return;
        }
        reset_metal_backend_for_tests();
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let pk = key.verifying_key();
        let msg = b"metal batch test";
        let sig = key.sign(msg).to_bytes();
        let hram = crate::signature::ed25519_challenge_scalar_bytes(&sig, pk.as_bytes(), msg);
        let mut bad_sig = sig;
        bad_sig[0] ^= 0x40;
        let sigs = [sig, bad_sig];
        let pks = [pk.to_bytes(), pk.to_bytes()];
        let hrams = [hram, hram];
        let points = [pk.to_bytes(), *ED25519_BASEPOINT_COMPRESSED.as_bytes()];
        let good_r: [u8; 32] = sig[..32]
            .try_into()
            .expect("signature R slice has 32 bytes");
        let good_s: [u8; 32] = sig[32..]
            .try_into()
            .expect("signature S slice has 32 bytes");
        let a_point = CompressedEdwardsY(pk.to_bytes())
            .decompress()
            .expect("public key should decompress on CPU");
        let s_scalar =
            Scalar::from_canonical_bytes(good_s).expect("signature scalar should be canonical");
        let h_scalar =
            Scalar::from_canonical_bytes(hram).expect("challenge scalar should be canonical");
        let cpu_s_only = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &Scalar::ZERO,
            &(-a_point),
            &s_scalar,
        )
        .compress()
        .to_bytes();
        let cpu_h_only = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &h_scalar,
            &(-a_point),
            &Scalar::ZERO,
        )
        .compress()
        .to_bytes();
        let mut s_only_sig = [0u8; 64];
        s_only_sig[32..].copy_from_slice(&good_s);
        let h_only_sig = [0u8; 64];
        let mut unit_sig = [0u8; 64];
        unit_sig[32] = 1;
        let mut double_sig = [0u8; 64];
        double_sig[32] = 2;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let metal_s_only =
            metal_ed25519_check_bytes_for_tests(&[s_only_sig], &[identity], &[[0u8; 32]]);
        let metal_h_only =
            metal_ed25519_check_bytes_for_tests(&[h_only_sig], &[pk.to_bytes()], &[hram]);
        let metal_b1 = metal_ed25519_check_bytes_for_tests(&[unit_sig], &[identity], &[[0u8; 32]]);
        let metal_b2 =
            metal_ed25519_check_bytes_for_tests(&[double_sig], &[identity], &[[0u8; 32]]);
        let cpu_b1 = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let cpu_b2 = (Scalar::from(2u64) * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pow2_sigs: Vec<[u8; 64]> = (0..64)
            .map(|bit| {
                let mut sig_bytes = [0u8; 64];
                sig_bytes[32 + bit / 8] = 1u8 << (bit % 8);
                sig_bytes
            })
            .collect();
        let pow2_pks = vec![identity; 64];
        let pow2_hrams = vec![[0u8; 32]; 64];
        let metal_pow2 = metal_ed25519_check_bytes_for_tests(&pow2_sigs, &pow2_pks, &pow2_hrams);
        let pow2_first_mismatch = metal_pow2.as_ref().and_then(|metal_points| {
            metal_points.iter().enumerate().find_map(|(bit, actual)| {
                let mut scalar_bytes = [0u8; 32];
                scalar_bytes[bit / 8] = 1u8 << (bit % 8);
                let scalar = Scalar::from_canonical_bytes(scalar_bytes)
                    .expect("power-of-two scalar should be canonical");
                let expected = (scalar * ED25519_BASEPOINT_POINT).compress().to_bytes();
                (expected != *actual).then_some((bit, expected, *actual))
            })
        });
        let direct = metal_ed25519_verify_batch_direct_for_tests(&sigs, &pks, &hrams);
        let status = metal_ed25519_status_batch_direct_for_tests(&sigs, &pks, &hrams);
        let check_bytes = metal_ed25519_check_bytes_for_tests(&sigs, &pks, &hrams);
        let field_roundtrip = metal_ed25519_field_roundtrip_for_tests(&points);
        let point_decompress = metal_ed25519_point_decompress_for_tests(&points);
        let Some(field_roundtrip) = field_roundtrip else {
            panic!("Metal field roundtrip diagnostic kernel should return results");
        };
        for (expected, actual) in points.iter().zip(field_roundtrip.iter()) {
            let mut expected_y = *expected;
            expected_y[31] &= 0x7f;
            assert_eq!(
                *actual, expected_y,
                "Metal fe_frombytes/fe_tobytes should preserve the encoded y-coordinate",
            );
        }
        let Some((point_statuses, point_outputs)) = point_decompress else {
            panic!("Metal point decompress diagnostic kernel should return results");
        };
        let expected_neg_points: Vec<[u8; 32]> = points
            .iter()
            .map(|point| {
                let mut negated = *point;
                negated[31] ^= 0x80;
                negated
            })
            .collect();
        assert_eq!(
            point_statuses,
            vec![5, 5],
            "Metal point decompress should accept the public key and basepoint",
        );
        assert_eq!(
            point_outputs, expected_neg_points,
            "Metal ge_frombytes_negate_vartime should negate the encoded point sign",
        );
        assert_eq!(
            direct,
            Some(vec![true, false]),
            "Metal signature kernel should match the CPU on good and bad signatures",
        );
        assert_eq!(
            status,
            Some(vec![5, 4]),
            "Metal signature status kernel should accept the good signature and reject the tampered one",
        );
        assert_eq!(
            check_bytes,
            Some(vec![good_r, good_r]),
            "Metal signature check-bytes kernel should reconstruct the canonical R value",
        );
        assert_eq!(
            metal_s_only,
            Some(vec![cpu_s_only]),
            "Metal [s]B multiplication should match the CPU",
        );
        assert_eq!(
            metal_h_only,
            Some(vec![cpu_h_only]),
            "Metal [h](-A) multiplication should match the CPU",
        );
        assert_eq!(
            metal_b1,
            Some(vec![cpu_b1]),
            "Metal scalar-1 basepoint multiplication should produce the canonical basepoint",
        );
        assert_eq!(
            metal_b2,
            Some(vec![cpu_b2]),
            "Metal scalar-2 basepoint multiplication should match the CPU",
        );
        assert_eq!(
            pow2_first_mismatch, None,
            "Metal power-of-two basepoint multiplications should match the CPU across the scalar bit range",
        );
        reset_metal_backend_for_tests();
        assert!(
            metal_available(),
            "Metal backend should initialize on Metal-capable hosts",
        );
        assert!(
            with_metal_state_try(|ctx| Some(ctx.ed25519_signature.is_some())).unwrap_or(false),
            "Metal startup self-test should keep the ed25519 signature pipeline enabled",
        );
        let mut output = [false; 2];
        let before = metal_completed_dispatches(MetalKernel::Ed25519);
        assert!(metal_ed25519_verify_batch_into(
            &sigs,
            &pks,
            &hrams,
            &mut output
        ));
        assert_eq!(output, [true, false]);
        assert!(
            metal_completed_dispatches(MetalKernel::Ed25519) > before,
            "qualified Metal verification must execute its signature kernel"
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_sha256_compress_returns_true() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        let mut state = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];
        let block = [0u8; 64];
        assert!(metal_sha256_compress(&mut state, &block));
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_vadd32_single_vector_matches_scalar() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        reset_metal_backend_for_tests();
        let a = [0xFFFF_FFFFu32, 0x0000_0001, 0x1234_5678, 0x9ABC_DEF0];
        let b = [0x0000_0001u32, 0x0000_0001, 0x8765_4321, 0x1111_1111];
        let expected = [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ];
        assert_eq!(metal_vadd32(a, b), Some(expected));
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_vadd64_single_vector_matches_scalar() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        reset_metal_backend_for_tests();
        let a = [0xFFFF_FFFFu32, 0x0000_0000, 0x0000_0001, 0x8000_0000];
        let b = [0x0000_0001u32, 0x0000_0001, 0xFFFF_FFFF, 0x7FFF_FFFF];
        let lane0 =
            ((a[1] as u64) << 32 | a[0] as u64).wrapping_add(((b[1] as u64) << 32) | b[0] as u64);
        let lane1 =
            ((a[3] as u64) << 32 | a[2] as u64).wrapping_add(((b[3] as u64) << 32) | b[2] as u64);
        let expected = [
            (lane0 & 0xFFFF_FFFF) as u32,
            (lane0 >> 32) as u32,
            (lane1 & 0xFFFF_FFFF) as u32,
            (lane1 >> 32) as u32,
        ];
        assert_eq!(metal_vadd64(a, b), Some(expected));
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_bitwise_single_vector_matches_scalar() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        reset_metal_backend_for_tests();
        let lhs = [0xffff_0000u32, 0x1234_5678, 0x0f0f_0f0f, 0xaaaa_5555];
        let rhs = [0x00ff_ff00u32, 0xf0f0_f0f0, 0x3333_cccc, 0x5555_aaaa];
        assert_eq!(
            metal_vand(lhs, rhs),
            Some([
                lhs[0] & rhs[0],
                lhs[1] & rhs[1],
                lhs[2] & rhs[2],
                lhs[3] & rhs[3],
            ]),
        );
        assert_eq!(
            metal_vxor(lhs, rhs),
            Some([
                lhs[0] ^ rhs[0],
                lhs[1] ^ rhs[1],
                lhs[2] ^ rhs[2],
                lhs[3] ^ rhs[3],
            ]),
        );
        assert_eq!(
            metal_vor(lhs, rhs),
            Some([
                lhs[0] | rhs[0],
                lhs[1] | rhs[1],
                lhs[2] | rhs[2],
                lhs[3] | rhs[3],
            ]),
        );
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_aes_batch_matches_scalar() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        reset_metal_backend_for_tests();
        let states = [
            [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ],
            [
                0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                0x22, 0x11, 0x00,
            ],
        ];
        let rk = [
            0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
            0x67, 0x98,
        ];
        let expected_enc: Vec<[u8; 16]> = states
            .iter()
            .map(|&state| crate::aes::aesenc_impl(state, rk))
            .collect();
        let expected_dec: Vec<[u8; 16]> = states
            .iter()
            .map(|&state| crate::aes::aesdec_impl(state, rk))
            .collect();
        let mut output = vec![[0; 16]; states.len()];
        assert!(metal_aesenc_batch_into(&states, rk, &mut output));
        assert_eq!(output, expected_enc);
        assert!(metal_aesdec_batch_into(&states, rk, &mut output));
        assert_eq!(output, expected_dec);
    }
    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn metal_aes_rounds_batch_matches_scalar() {
        if !metal_available() {
            eprintln!("No Metal GPU available; skipping test");
            return;
        }
        reset_metal_backend_for_tests();
        let states = [
            [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ],
            [
                0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                0x22, 0x11, 0x00,
            ],
        ];
        let round_keys = [
            [
                0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
                0x67, 0x98,
            ],
            [
                0xa5, 0x40, 0x76, 0x28, 0x10, 0x4f, 0xdc, 0xe6, 0x43, 0xdd, 0x27, 0x0f, 0x6c, 0xa7,
                0x63, 0x6f,
            ],
            [
                0x2c, 0x5e, 0x2f, 0x88, 0x6a, 0x84, 0xd2, 0x57, 0x8b, 0x3f, 0x8c, 0x9c, 0x4f, 0x11,
                0x64, 0x15,
            ],
        ];
        let expected_enc: Vec<[u8; 16]> = states
            .iter()
            .copied()
            .map(|state| {
                round_keys
                    .iter()
                    .copied()
                    .fold(state, crate::aes::aesenc_impl)
            })
            .collect();
        let expected_dec: Vec<[u8; 16]> = states
            .iter()
            .copied()
            .map(|state| {
                round_keys
                    .iter()
                    .copied()
                    .fold(state, crate::aes::aesdec_impl)
            })
            .collect();
        let mut output = vec![[0; 16]; states.len()];
        assert!(metal_aesenc_rounds_batch_into(
            &states,
            &round_keys,
            &mut output
        ));
        assert_eq!(output, expected_enc);
        assert!(metal_aesdec_rounds_batch_into(
            &states,
            &round_keys,
            &mut output
        ));
        assert_eq!(output, expected_dec);
    }

    #[cfg(all(target_os = "macos", feature = "metal"))]
    #[test]
    fn with_metal_state_reuses_cached_state() {
        if !metal_runtime_allowed() {
            eprintln!("Metal runtime disabled; skipping reuse assertion");
            return;
        }
        reset_metal_backend_for_tests();
        let first = with_metal_state(|state| objc2::rc::Retained::as_ptr(&state.queue) as usize);
        let second = with_metal_state(|state| objc2::rc::Retained::as_ptr(&state.queue) as usize);
        match (first, second) {
            (Some(a), Some(b)) => assert_eq!(a, b, "reuse the same qualified Metal state"),
            _ => eprintln!("Metal state unavailable; skipping reuse assertion"),
        }
    }
}
