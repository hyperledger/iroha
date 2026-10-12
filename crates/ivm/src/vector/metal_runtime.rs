//! One exact physical lease for discovery, calibration, execution and acceptance.

use super::*;
use metal_owner::{DeviceLease, DeviceRegistry, DiscoveryGate, FairProgress, HealthLease};
use std::{alloc::Layout, cell::RefCell};

static DEVICES: DeviceRegistry<MetalState> = DeviceRegistry::new();
static DISCOVERY: DiscoveryGate = DiscoveryGate::new();
static DISCOVERY_PROGRESS: FairProgress = FairProgress::new();
static ED25519_PROGRESS: FairProgress = FairProgress::new();
static MERKLE_REHASH_PROGRESS: FairProgress = FairProgress::new();
static MERKLE_TREE_PROGRESS: FairProgress = FairProgress::new();
static MERKLE_ROOT_PROGRESS: FairProgress = FairProgress::new();
static BATCH_PROGRESS: [FairProgress; metal_cost::BATCH_FAMILIES] =
    [const { FairProgress::new() }; metal_cost::BATCH_FAMILIES];
const CALIBRATION_BUDGET: Duration = Duration::from_secs(8);
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);
const DISCOVERY_BUDGET: Duration = Duration::from_secs(1);

#[cfg(test)]
mod configuration_tests {
    use super::*;

    #[test]
    fn applying_acceleration_policy_does_not_discover_metal() {
        const CHILD: &str = "IVM_METAL_LAZY_CONFIG_TEST";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let path = module_path!().split_once("::").expect("crate module").1;
            let test = format!("{path}::applying_acceleration_policy_does_not_discover_metal");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture"])
                .env(CHILD, "1")
                .env_remove("IVM_DISABLE_METAL")
                .output()
                .expect("isolated acceleration configuration test");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{stdout}\n{stderr}");
            assert!(stdout.contains("1 passed; 0 failed; 0 ignored"), "{stdout}");
            return;
        }

        crate::set_acceleration_config(crate::AccelerationConfig {
            enable_metal: true,
            enable_cuda: false,
            max_gpus: None,
            resource_limits: iroha_accel::RegistryLimits::STANDARD,
            ..Default::default()
        });
        assert!(metal_policy_enabled());
        assert_eq!(DEVICES.len(), 0);
        // Unmeasured geometry must also decline before discovery or calibration.
        for leaves in [0, 8_191, 229_377, usize::MAX] {
            assert!(metal_merkle_cost_rehash::Geometry::new(0, 32, leaves).is_none());
        }
        let retained = crate::ByteMerkleTree::new(1, 32).unwrap();
        assert!(!metal_rehash_tree_auto(&retained, &[1]));
        for (bytes, chunk) in [
            (0, 32),
            (8_191 * 32, 32),
            (65_536 * 32 + 1, 32),
            (1, 0),
            (1, 33),
        ] {
            // Test the real root entrypoint with unsupported borrowed geometry.
            // The fixed tiny slice controls invalid chunk cases; count bounds
            // are also checked directly without manufacturing huge input data.
            assert!(metal_merkle_cost_root::Geometry::new(bytes, chunk).is_none());
            assert!(metal_merkle_cost_tree::Geometry::new(bytes, chunk).is_none());
        }
        assert!(metal_root_from_bytes_auto(&[1], 0).is_none());
        assert!(metal_root_from_bytes_auto(&[1], 33).is_none());
        assert!(metal_root_from_bytes_auto(&[1], 32).is_none());
        assert!(metal_tree_from_bytes_auto(&[1], 0).is_none());
        assert!(metal_tree_from_bytes_auto(&[1], 33).is_none());
        assert!(metal_tree_from_bytes_auto(&[1], 32).is_none());
        for (work, items) in [
            (metal_cost::MetalBatchWork::Encrypt, 2_049),
            (metal_cost::MetalBatchWork::DecryptRounds(65), 128),
        ] {
            assert!(select_batch(work, items).is_none());
        }
        let unsupported = [crate::signature::Ed25519BatchItem::default(); 513];
        let mut output = [true; 513];
        assert!(!metal_ed25519_auto_into(&unsupported, &mut output));
        assert!(output.into_iter().all(|value| value));
        assert!(!metal_ed25519_auto_into(&unsupported[..16], &mut []));
        let long = [0u8; 65_537];
        let unsupported = [crate::signature::Ed25519BatchItem {
            message: &long,
            ..Default::default()
        }; 16];
        let mut output = [true; 16];
        assert!(!metal_ed25519_auto_into(&unsupported, &mut output));
        assert!(output.into_iter().all(|value| value));
        assert_eq!(DEVICES.len(), 0);
        // Check after policy application: entering this gate beforehand would suppress the
        // very discovery this test must catch. The gate records attempts even without a GPU.
        let discovery = DISCOVERY
            .try_enter(Instant::now(), Duration::MAX)
            .expect("applying policy must leave discovery untouched");
        // Hold ordinary discovery admission to model pending qualification. Even on a GPU
        // host, enabled policy must not be reported as availability or successful parity.
        let pending = crate::acceleration_runtime_status().metal;
        assert!(pending.configured);
        assert!(!pending.available);
        assert!(!pending.parity_ok);
        drop(discovery);
        crate::set_acceleration_config(crate::AccelerationConfig {
            enable_metal: false,
            enable_cuda: false,
            ..Default::default()
        });
        let disabled = crate::acceleration_runtime_status().metal;
        assert!(!disabled.configured);
        assert!(!disabled.available);
        assert!(!disabled.parity_ok);
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<DeviceLease<MetalState>>> = const { RefCell::new(None) };
    static HEALTH: RefCell<Option<HealthLease>> = const { RefCell::new(None) };
}

fn limit() -> usize {
    let config = crate::acceleration_config();
    config
        .max_gpus
        .unwrap_or(config.resource_limits.devices)
        .min(config.resource_limits.devices)
}

pub(super) fn current_health() -> Option<HealthLease> {
    HEALTH.with(|slot| slot.borrow().clone())
}

fn physical_limit() -> usize {
    crate::acceleration_config().resource_limits.devices
}
fn record_allowed(lease: &DeviceLease<MetalState>) -> bool {
    DEVICES.eligible(lease, physical_limit(), limit())
}
pub(super) fn current_allowed() -> bool {
    ACTIVE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_none_or(|lease| record_allowed(lease) && lease.health().usable())
    })
}

fn bind<R>(lease: &DeviceLease<MetalState>, call: impl FnOnce() -> R) -> R {
    ACTIVE.with(|state| {
        HEALTH.with(|health| metal_owner::with_device_binding(state, health, lease, call))
    })
}

fn discover() {
    if !metal_policy_enabled() || limit() == 0 || METAL_ARTIFACT_INVALID.load(Ordering::Acquire) {
        return;
    }
    let now = Instant::now();
    let Some(_pass) = DISCOVERY.try_enter(now, DISCOVERY_RETRY) else {
        return;
    };
    let config = crate::acceleration_config();
    let resources = iroha_accel::ProcessResources::get_or_initialize(config.resource_limits);
    if !DEVICES.prepare(config.resource_limits.devices, |layout| {
        resources.try_consumer_metadata(layout)
    }) {
        return;
    }
    warm_up_core_graphics_display();
    // Register the complete bounded inventory before spending time qualifying.
    // A slow first device must not conceal later devices from required evidence.
    let devices = objc2_metal::MTLCopyAllDevices();
    let fallback = devices
        .iter()
        .next()
        .is_none()
        .then(|| objc2_metal::MTLCreateSystemDefaultDevice())
        .flatten();
    let complete = devices.len() <= config.resource_limits.discovery_ordinals as usize;
    DEVICES.reconcile_presence(physical_limit(), complete, |identity| {
        devices.iter().any(|device| device.registryID() == identity)
            || fallback
                .as_ref()
                .is_some_and(|device| device.registryID() == identity)
    });
    let observed = || {
        devices
            .iter()
            .chain(fallback.iter().cloned())
            .take(config.resource_limits.discovery_ordinals as usize)
    };
    for device in observed() {
        if !metal_policy_enabled() || limit() == 0 {
            return;
        }
        let _ = DEVICES.observe(device.registryID(), physical_limit(), |bytes| {
            resources.try_consumer_metadata(Layout::array::<u8>(bytes).ok()?)
        });
    }
    let count = DEVICES.len().min(physical_limit());
    let Some(mut progress) = DISCOVERY_PROGRESS.try_pass(count, now, DISCOVERY_BUDGET) else {
        return;
    };
    DEVICES.qualify_fair(
        &mut progress,
        physical_limit(),
        limit(),
        Instant::now,
        |record| {
            if !metal_policy_enabled() || !record_allowed(record) {
                return None;
            }
            let device =
                observed().find(|device| device.registryID() == record.health().identity())?;
            bind(record, || MetalState::new(device))
        },
    );
}

#[cfg(all(test, feature = "metal-hardware-tests"))]
fn qualify(record: &DeviceLease<MetalState>, device: &ProtocolObject<dyn MTLDevice>) {
    use objc2::Message;

    if record.value().is_some() || !record.health().usable() || !record_allowed(record) {
        return;
    }
    // Golden-vector native calls carry physical health before MetalState exists.
    bind(record, || {
        record.initialize(|| MetalState::new(device.retain()));
    });
}

pub(super) fn all_quarantined() -> bool {
    DEVICES.all_quarantined(physical_limit())
}

pub(super) fn with_state<R>(call: impl FnOnce(&MetalState) -> R) -> Option<R> {
    if !metal_runtime_allowed() {
        return None;
    }
    if let Some(lease) = ACTIVE.with(|slot| slot.borrow().clone()) {
        let state = lease.value()?;
        // The operation checks its exact command owner before publishing bytes.
        // Never turn a completed caller copy into a refusal afterwards.
        return Some(call(state));
    }
    discover();
    for index in 0..DEVICES.len().min(physical_limit()) {
        let Some(lease) = DEVICES.record(index, physical_limit()) else {
            continue;
        };
        if !record_allowed(&lease) {
            continue;
        }
        let Some(state) = lease.value() else {
            continue;
        };
        return bind(&lease, || Some(call(state)));
    }
    None
}

/// The private token keeps measured geometry and physical execution inseparable.
pub(crate) struct MetalSelection {
    lease: DeviceLease<MetalState>,
}
impl MetalSelection {
    pub(crate) fn run<R>(self, call: impl FnOnce() -> R) -> Option<R> {
        if !metal_runtime_allowed() || !record_allowed(&self.lease) || self.lease.value().is_none()
        {
            return None;
        }
        bind(&self.lease, || Some(call()))
    }
}

fn select(
    progress: &FairProgress,
    cost: impl Fn(&MetalState, &mut dyn FnMut() -> Option<Instant>) -> Option<u64>,
) -> Option<MetalSelection> {
    if !metal_runtime_allowed() {
        return None;
    }
    let active = ACTIVE.with(|slot| slot.borrow().clone());
    if active.is_none() {
        discover();
    }
    let count = DEVICES.len().min(physical_limit());
    let mut pass = progress.try_pass(count, Instant::now(), CALIBRATION_BUDGET);
    let start = pass.as_ref().map_or(0, metal_owner::FairPass::start);
    if let Some(lease) = active {
        let state = lease.value()?;
        let index = (0..count).find(|&index| {
            DEVICES
                .record(index, physical_limit())
                .is_some_and(|other| iroha_allocation::ChargedShared::ptr_eq(&lease, &other))
        })?;
        cost(state, &mut || {
            pass.as_mut()?.begin_attempt(index, Instant::now())
        })?;
        return record_allowed(&lease).then_some(MetalSelection { lease });
    }
    let lease =
        DEVICES.select_costed(physical_limit(), limit(), start, |index, lease, state| {
            bind(lease, || {
                cost(state, &mut || {
                    pass.as_mut()?.begin_attempt(index, Instant::now())
                })
            })
        })?;
    Some(MetalSelection { lease })
}

/// Retain the current exact qualified owner through delayed output acceptance.
pub(super) fn current_selection() -> Option<MetalSelection> {
    let lease = ACTIVE.with(|slot| slot.borrow().clone())?;
    if !record_allowed(&lease) || lease.value().is_none() {
        return None;
    }
    Some(MetalSelection { lease })
}

/// Rehash a fixed retained tree, including complete canonical-node refresh.
/// Selection reads only public geometry and the actual qualified CPU baseline.
pub(super) fn metal_rehash_tree_auto(tree: &crate::ByteMerkleTree, data: &[u8]) -> bool {
    let Some(geometry) =
        metal_merkle_cost_rehash::Geometry::new(data.len(), tree.chunk_size(), tree.leaf_count())
    else {
        return false;
    };
    let context = Sha256Context::production();
    let Some(baseline) = sha256_cpu::context::Sha256Baseline::capture(context) else {
        return false;
    };
    select(&MERKLE_REHASH_PROGRESS, |state, begin| {
        state.merkle_rehash_cost.try_lock().ok()?.qualified_cost(
            Instant::now(),
            geometry,
            baseline,
            context,
            begin,
            |started| metal_merkle_cost_rehash::calibrate(geometry, baseline, context, started),
        )
    })
    .and_then(|selection| {
        selection.run(|| metal_merkle::rehash_tree(tree, data, baseline, context))
    })
    .unwrap_or(false)
}

/// Byte-root selection reads only exact public geometry. The selected original
/// physical owner remains bound through the complete operation and final readback.
pub(super) fn metal_root_from_bytes_auto(data: &[u8], chunk: usize) -> Option<[u8; 32]> {
    let geometry = metal_merkle_cost_root::Geometry::new(data.len(), chunk)?;
    select(&MERKLE_ROOT_PROGRESS, |state, begin| {
        state.merkle_root_cost.try_lock().ok()?.qualified_cost(
            Instant::now(),
            geometry,
            begin,
            |started| metal_merkle_cost_root::calibrate(geometry, started),
        )
    })?
    .run(|| metal_merkle::root_from_bytes(data, chunk))
    .flatten()
}

/// Complete retained-tree construction, bound to exact public geometry and
/// the actual original CPU baseline. No caller bytes enter calibration.
pub(super) fn metal_tree_from_bytes_auto(
    data: &[u8],
    chunk: usize,
) -> Option<crate::ByteMerkleTree> {
    let geometry = metal_merkle_cost_tree::Geometry::new(data.len(), chunk)?;
    let context = Sha256Context::production();
    let baseline = sha256_cpu::context::Sha256Baseline::capture(context)?;
    let selection = select(&MERKLE_TREE_PROGRESS, |state, begin| {
        state.merkle_tree_cost.try_lock().ok()?.qualified_cost(
            Instant::now(),
            geometry,
            baseline,
            context,
            begin,
            |started| metal_merkle_cost_tree::calibrate(geometry, baseline, context, started),
        )
    })?;
    if !baseline.is_current(context) {
        return None;
    }
    selection
        .run(|| {
            let original = current_selection()?;
            let tree = metal_merkle::tree_from_bytes(data, chunk)?;
            if !baseline.is_current(context) {
                return None;
            }
            // Re-enter this same physical owner after complete destination construction.
            original.run(|| tree)
        })
        .flatten()
}

pub(super) fn select_batch(
    work: metal_cost::MetalBatchWork,
    items: usize,
) -> Option<metal_aes::MetalAesSelection> {
    let geometry = metal_cost::exact::Geometry::new(work, items)?;
    let baseline = metal_cost::AesCpuBaseline::capture(work);
    let selection = select(&BATCH_PROGRESS[work.family_index()], |state, begin| {
        state.batch_cost[work.family_index()]
            .try_lock()
            .ok()?
            .qualified_cost(Instant::now(), geometry, baseline, begin, |started| {
                metal_cost::exact::calibrate(geometry, baseline, started)
            })
    })?;
    metal_aes::MetalAesSelection::new(selection, baseline, items)
}

/// Selection and execution borrow the same immutable public geometry and keep
/// the original physical owner through result acceptance.
pub(crate) fn metal_ed25519_auto_into(
    items: &[crate::signature::Ed25519BatchItem<'_>],
    destination: &mut [bool],
) -> bool {
    if items.len() != destination.len() || !metal_policy_enabled() {
        return false;
    }
    let Some(geometry) = crate::signature::ed25519_geometry::MessageGeometry::new(items) else {
        return false;
    };
    select(&ED25519_PROGRESS, |state, begin| {
        state.ed25519_signature.as_ref()?;
        state.ed25519_cost.try_lock().ok()?.qualified_cost(
            Instant::now(),
            geometry,
            begin,
            |started| metal_ed25519_cost::calibrate(geometry, started),
        )
    })
    .and_then(|selected| {
        selected.run(|| super::metal_signature::metal_ed25519_items_into(items, destination))
    })
    .unwrap_or(false)
}

pub(super) fn restart_discovery() {
    DISCOVERY.restart();
}

/// Physical identity, qualification and custody are retained on operator opt-out.
pub(super) fn release() {
    restart_discovery();
}

#[cfg(all(test, feature = "metal-hardware-tests"))]
pub(super) fn device_slots() -> Option<usize> {
    if !metal_policy_enabled() || limit() == 0 {
        return None;
    }
    discover();
    let devices = objc2_metal::MTLCopyAllDevices();
    let fallback = devices
        .iter()
        .next()
        .is_none()
        .then(|| objc2_metal::MTLCreateSystemDefaultDevice())
        .flatten();
    let count = DEVICES.len().min(physical_limit());
    let mut expected = 0usize;
    // Qualification starts in an isolated process: every allowed physical
    // identity must have a charged record, even if its initialization is pending.
    // Budget pressure therefore refuses evidence rather than shrinking its census.
    for device in devices.iter().chain(fallback.iter().cloned()).take(
        physical_limit().min(
            crate::acceleration_config()
                .resource_limits
                .discovery_ordinals as usize,
        ),
    ) {
        if !(0..count).any(|index| {
            DEVICES
                .record(index, physical_limit())
                .is_some_and(|record| record.health().identity() == device.registryID())
        }) {
            return None;
        }
        expected += 1;
    }
    (count == expected).then_some(count)
}
#[cfg(all(test, feature = "metal-hardware-tests"))]
pub(super) fn with_device_for_qualification<R>(
    index: usize,
    call: impl FnOnce() -> R,
) -> Option<R> {
    if !metal_policy_enabled() {
        return None;
    }
    discover();
    let lease = DEVICES.record(index, physical_limit())?;
    if lease.value().is_none() {
        // Required qualification explicitly visits every recorded physical device;
        // ordinary discovery's bounded warm-up cannot turn missing work into a pass.
        let devices = objc2_metal::MTLCopyAllDevices();
        let fallback = devices
            .iter()
            .next()
            .is_none()
            .then(|| objc2_metal::MTLCreateSystemDefaultDevice())
            .flatten();
        for device in devices.iter().chain(fallback.iter().cloned()) {
            if device.registryID() == lease.health().identity() {
                qualify(&lease, &device);
                break;
            }
        }
    }
    lease.value()?;
    Some(bind(&lease, call))
}
