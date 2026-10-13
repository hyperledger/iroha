//! IVM-only task and artifact admission over the shared physical process owner.
//!
//! This module creates no context, stream, module, device buffer or native cache.
//! Opt-out and selection caps affect only IVM; they neither disable FASTPQ nor
//! replace physical health. Every variable policy allocation is prepaid by the
//! same process metadata budget and remains charged through its final borrower.

use crate::cuda::policy::{Kernel, select_admitted_device};
use iroha_accel::{
    DeviceIdentity, PtxArtifact,
    cuda::{CudaDevice, CudaFailure, CudaProcess},
};
use iroha_allocation::{ChargedBuffer, ChargedShared};
use parking_lot::Mutex;
use std::{
    alloc::Layout,
    cell::{Cell, RefCell},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

mod admission;
pub(crate) mod measured;
use admission::KernelAdmission;

struct DevicePolicy {
    slot: usize,
    identity: DeviceIdentity,
    kernels: [KernelAdmission; Kernel::ALL.len()],
    measured_costs: [crate::cuda_cost::ProfileCell; crate::cuda_cost::FAMILY_COUNT],
}
struct Policies {
    records: Mutex<ChargedBuffer<ChargedShared<DevicePolicy>>>,
}
static POLICIES: OnceLock<Policies> = OnceLock::new();
static POLICY_INSTALL: Mutex<()> = Mutex::new(());
static ENABLED: AtomicBool = AtomicBool::new(true);
static DEVICE_CAP: Mutex<Option<usize>> = Mutex::new(None);

#[derive(Clone)]
struct ActiveDevice {
    device: CudaDevice<'static>,
    policy: ChargedShared<DevicePolicy>,
    index: usize,
    kernel: Kernel,
    artifact: PtxArtifact,
    qualifying: bool,
}
thread_local! {
    static TASK: Cell<Option<u64>> = const { Cell::new(None) };
    static ACTIVE: RefCell<Option<ActiveDevice>> = const { RefCell::new(None) };
}
#[cfg(feature = "cuda-hardware-tests")]
thread_local! { static QUALIFICATION: Cell<Option<usize>> = const { Cell::new(None) }; }

fn physical_process() -> Option<&'static CudaProcess> {
    if !crate::cuda_artifact::eligible() {
        return None;
    }
    CudaProcess::get().or_else(|| {
        let config = crate::acceleration_config();
        CudaProcess::install(config.resource_limits).ok()
    })
}

/// Allocate only IVM policy backing after the single physical owner is installed.
pub(crate) fn initialize_policy() -> Result<(), CudaFailure> {
    if POLICIES.get().is_some() {
        return Ok(());
    }
    let _install = POLICY_INSTALL.try_lock().ok_or(CudaFailure::Busy)?;
    if POLICIES.get().is_some() {
        return Ok(());
    }
    let process = physical_process().ok_or(CudaFailure::Unavailable)?;
    let capacity = process.record_capacity();
    let layout = Layout::array::<ChargedShared<DevicePolicy>>(capacity)
        .map_err(|_| CudaFailure::InvalidRequest)?;
    let mut reservation = process.reserve_consumer_metadata(layout)?;
    let records = ChargedBuffer::from_reservation(capacity, &mut reservation)
        .map_err(|_| CudaFailure::Capacity)?;
    POLICIES
        .set(Policies {
            records: Mutex::new(records),
        })
        .map_err(|_| CudaFailure::InvalidRequest)
}

/// Apply IVM selection policy without changing any physical owner's identity.
pub(crate) fn configure(enabled: bool, cap: Option<usize>) {
    *DEVICE_CAP.lock() = cap;
    ENABLED.store(enabled, Ordering::Release);
}

fn policy_for(device: &CudaDevice<'static>, slot: usize) -> Option<ChargedShared<DevicePolicy>> {
    initialize_policy().ok()?;
    let mut policies = POLICIES.get()?.records.try_lock()?;
    if let Some(policy) = policies
        .as_slice()
        .iter()
        .find(|entry| entry.identity == device.identity())
    {
        return Some(policy.clone());
    }
    if policies.as_slice().len() == policies.capacity() {
        return None;
    }
    let process = physical_process()?;
    let mut reservation = process
        .reserve_consumer_metadata(ChargedShared::<DevicePolicy>::allocation_layout())
        .ok()?;
    let policy = ChargedShared::from_reservation(
        DevicePolicy {
            slot,
            identity: device.identity(),
            kernels: std::array::from_fn(|_| KernelAdmission::default()),
            measured_costs: std::array::from_fn(|_| crate::cuda_cost::ProfileCell::default()),
        },
        &mut reservation,
    )
    .ok()?;
    policies.push_reserved(policy.clone());
    Some(policy)
}

fn selection_count(process: &CudaProcess) -> Option<usize> {
    let cap = DEVICE_CAP.try_lock()?;
    let count = process.try_record_count().ok()?;
    Some(cap.map_or(count, |limit| limit.min(count)))
}

/// Observed stable slots under the configured selection cap; no new native owner.
pub(crate) fn device_slots() -> usize {
    if !ENABLED.load(Ordering::Acquire) {
        return 0;
    }
    let Some(process) = physical_process() else {
        return 0;
    };
    if matches!(process.discover(), Err(CudaFailure::Busy)) {
        return 0;
    }
    selection_count(process).unwrap_or(0)
}

/// Number of current usable IVM devices, with no independent native initialization.
pub(crate) fn usable_device_count() -> usize {
    if !ENABLED.load(Ordering::Acquire) {
        return 0;
    }
    let Some(process) = physical_process() else {
        return 0;
    };
    if matches!(process.discover(), Err(CudaFailure::Busy)) {
        return 0;
    }
    let Some(count) = selection_count(process) else {
        return 0;
    };
    (0..count)
        .filter(|&index| process.device(index).is_some())
        .count()
}

/// Bind self-test admission to the original device and exact artifact bytes.
pub(crate) fn admit_kernel(
    kernel: Kernel,
    artifact: PtxArtifact,
    validate: impl Fn() -> Result<bool, CudaFailure>,
) -> bool {
    if !ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let Some(process) = physical_process() else {
        return false;
    };
    if matches!(process.discover(), Err(CudaFailure::Busy)) {
        return false;
    }
    let previous = ACTIVE.with(|slot| slot.borrow().clone());
    let Some(count) = selection_count(process) else {
        return false;
    };
    let pinned = previous
        .as_ref()
        .map(|active| active.index)
        .or_else(qualification_device);
    let task = TASK.with(|task| task.get().unwrap_or(0));
    let preferred = if count == 0 {
        0
    } else {
        (task % count as u64) as usize
    };
    select_admitted_device(count, preferred, pinned, |index| {
        let Some(device) = process.device(index) else {
            return false;
        };
        let Some(policy) = policy_for(&device, index) else {
            return false;
        };
        ACTIVE.with(|slot| {
            *slot.borrow_mut() = Some(ActiveDevice {
                device: device.clone(),
                policy: policy.clone(),
                index,
                kernel,
                artifact,
                qualifying: true,
            })
        });
        let admitted = device.usable()
            && policy.kernels[kernel as usize].admit(artifact, &validate)
            && device.usable();
        if admitted {
            ACTIVE.with(|slot| {
                if let Some(active) = slot.borrow_mut().as_mut() {
                    active.qualifying = false;
                }
            });
        } else {
            ACTIVE.with(|slot| *slot.borrow_mut() = previous.clone());
        }
        admitted
    })
    .is_some()
}

/// Read retained policy owners, including quarantined devices, without discovery.
pub(crate) fn completion_snapshot(
    slot: usize,
) -> Result<Option<crate::cuda::CudaCompletionSnapshot>, crate::cuda::CudaCompletionError> {
    let Some(policies) = POLICIES.get() else {
        return Ok(None);
    };
    let records = policies
        .records
        .try_lock()
        .ok_or(crate::cuda::CudaCompletionError::Busy)?;
    Ok(records
        .as_slice()
        .iter()
        .find(|policy| policy.slot == slot)
        .map(|policy| {
            crate::cuda::CudaCompletionSnapshot::new(
                policy.identity,
                std::array::from_fn(|index| policy.kernels[index].completed()),
            )
        }))
}

/// Credit only the exact healthy owner selected for this admitted production batch.
pub(crate) fn record_completed(kernel: Kernel, artifact: PtxArtifact) {
    ACTIVE.with(|slot| {
        let active = slot.borrow();
        let Some(active) = active.as_ref() else {
            return;
        };
        if active.kernel == kernel && active.artifact == artifact && active.device.usable() {
            active.policy.kernels[kernel as usize].record_completed(artifact, !active.qualifying);
        }
    });
}

/// Attribute a validated compound batch to both exact kernels on the pinned owner.
pub(crate) fn record_completed_compound(
    kernel: Kernel,
    artifact: PtxArtifact,
    other: Kernel,
    other_artifact: PtxArtifact,
) {
    ACTIVE.with(|slot| {
        let active = slot.borrow();
        let Some(active) = active.as_ref() else {
            return;
        };
        if active.kernel == kernel && active.artifact == artifact && active.device.usable() {
            active.policy.kernels[kernel as usize].record_completed_with(
                artifact,
                &active.policy.kernels[other as usize],
                other_artifact,
                !active.qualifying,
            );
        }
    });
}

/// Borrow the already selected physical device and matching immutable artifact.
pub(crate) fn with_selected<T>(
    kernel: Kernel,
    artifact: PtxArtifact,
    call: impl FnOnce(&CudaDevice<'static>) -> Result<T, CudaFailure>,
) -> Result<T, CudaFailure> {
    if !ENABLED.load(Ordering::Acquire) {
        return Err(CudaFailure::Unavailable);
    }
    ACTIVE.with(|slot| {
        let active = slot.borrow().clone().ok_or(CudaFailure::Unavailable)?;
        let cap = DEVICE_CAP.try_lock().ok_or(CudaFailure::Busy)?;
        if cap.is_some_and(|limit| active.index >= limit) {
            return Err(CudaFailure::Unavailable);
        }
        drop(cap);
        if active.kernel != kernel || active.artifact != artifact {
            return Err(CudaFailure::InvalidRequest);
        }
        if !active.device.usable() || !active.policy.kernels[kernel as usize].can_attempt(artifact)
        {
            return Err(CudaFailure::Quarantined);
        }
        if !(active.policy.kernels[kernel as usize].admitted(artifact) || active.qualifying) {
            return Err(CudaFailure::Unavailable);
        }
        let result = call(&active.device);
        // Native children are reclaimed inside the operation closure. A checked
        // free/destroy error can quarantine after download produced host staging;
        // that staging must be discarded before reaching a caller destination.
        if !active.device.usable() || !active.policy.kernels[kernel as usize].can_attempt(artifact)
        {
            return Err(CudaFailure::Quarantined);
        }
        result
    })
}

/// Check a second admitted kernel in a compound operation on the pinned owner.
pub(crate) fn current_is_admitted(kernel: Kernel, artifact: PtxArtifact) -> bool {
    ACTIVE.with(|slot| {
        slot.borrow().as_ref().is_some_and(|active| {
            active.device.usable() && active.policy.kernels[kernel as usize].admitted(artifact)
        })
    })
}

pub(crate) fn current_kernel() -> Option<Kernel> {
    ACTIVE.with(|slot| slot.borrow().as_ref().map(|active| active.kernel))
}

pub(crate) fn quarantine_current_kernel() -> bool {
    ACTIVE.with(|slot| {
        let Some(active) = slot.borrow().clone() else {
            return false;
        };
        active.policy.kernels[active.kernel as usize].quarantine();
        true
    })
}

pub(crate) fn with_task_scope<T>(task: u64, call: impl FnOnce() -> T) -> T {
    struct Restore(Option<u64>, Option<ActiveDevice>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TASK.with(|slot| slot.set(self.0));
            ACTIVE.with(|slot| *slot.borrow_mut() = self.1.take());
        }
    }
    let old_task = TASK.with(|slot| slot.replace(Some(task)));
    let _restore = Restore(old_task, ACTIVE.with(|slot| slot.borrow().clone()));
    call()
}

pub(crate) fn qualification_device() -> Option<usize> {
    #[cfg(feature = "cuda-hardware-tests")]
    {
        QUALIFICATION.with(Cell::get)
    }
    #[cfg(not(feature = "cuda-hardware-tests"))]
    {
        None
    }
}

/// Pin a hardware qualification workload to one existing physical owner.
#[cfg(feature = "cuda-hardware-tests")]
pub(crate) fn with_device_for_qualification<T>(
    index: usize,
    call: impl FnOnce() -> T,
) -> Option<T> {
    physical_process()?.device(index)?;
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            QUALIFICATION.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(QUALIFICATION.with(|slot| slot.replace(Some(index))));
    Some(call())
}
