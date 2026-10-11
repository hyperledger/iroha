//! Genuine catalog revisions and directly owned children exercise the callback-free round.
//! Sleeping children are ownership fixtures, never daemon or service-readiness evidence.

use super::*;
use crate::managed::runtime::progress::{Cause, Failure, Phase, Progress};
use iroha_fs::{PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;
use std::cell::RefCell;

#[derive(Default, Debug)]
struct Trace {
    revisions: usize,
    running: Vec<ProviderId>,
    providers: Vec<usize>,
    exit_material: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum At {
    Entry,
    Provider(usize),
    Binding(usize),
}

type Hook = (At, Box<dyn FnOnce()>);
thread_local! {
    static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        TRACE.with(|value| {
            let _ = value.borrow_mut().take();
        });
        HOOK.with(|value| {
            let _ = value.borrow_mut().take();
        });
    }
}

fn trace<T>(action: impl FnOnce() -> T) -> (T, Trace) {
    TRACE.with(|value| assert!(value.borrow_mut().replace(Trace::default()).is_none()));
    let _restore = Restore;
    let result = action();
    (
        result,
        TRACE.with(|value| value.borrow_mut().take().unwrap()),
    )
}

fn on(at: At, action: impl FnOnce() + 'static) {
    HOOK.with(|value| assert!(value.borrow_mut().replace((at, Box::new(action))).is_none()));
}

fn after(at: At) {
    let action = HOOK.with(|value| {
        let mut value = value.borrow_mut();
        if value.as_ref().is_some_and(|(selected, _)| *selected == at) {
            value.take().map(|(_, action)| action)
        } else {
            None
        }
    });
    if let Some(action) = action {
        action();
    }
}

pub(in crate::managed::runtime::owned) fn revision() {
    TRACE.with(|value| {
        if let Some(value) = value.borrow_mut().as_mut() {
            value.revisions += 1;
        }
    });
}

pub(in crate::managed::runtime::owned) fn running(provider: ProviderId) {
    TRACE.with(|value| {
        if let Some(value) = value.borrow_mut().as_mut() {
            value.running.push(provider);
        }
    });
}

pub(in crate::managed::runtime::owned) fn after_entry() {
    after(At::Entry);
}

pub(in crate::managed::runtime::owned) fn before_binding(index: usize) {
    after(At::Binding(index));
}

pub(in crate::managed::runtime::owned) fn after_provider(index: usize) {
    TRACE.with(|value| {
        if let Some(value) = value.borrow_mut().as_mut() {
            value.providers.push(index);
        }
    });
    after(At::Provider(index));
}

pub(in crate::managed::runtime::owned) fn exit_material(result: &Result<()>) {
    TRACE.with(|value| {
        if let Some(value) = value.borrow_mut().as_mut() {
            value.exit_material = Some(result.is_ok());
        }
    });
}

struct Fixture {
    processes: PeerProcesses,
    gateways: [OwnedGateway; 3],
    prepared: PreparedLocalnet,
    _temporary: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let (temporary, prepared, launch) = super::launch();
    let mut processes = PeerProcesses {
        children: Vec::new(),
        launch: Some(launch),
        background: None,
    };
    for _ in 0..4 {
        processes.children.push(Arc::new(Mutex::new(
            Command::new("/bin/sleep").arg("120").spawn().unwrap(),
        )));
    }
    let gateways = processes.gateways().unwrap();
    Fixture {
        processes,
        gateways,
        prepared,
        _temporary: temporary,
    }
}

fn budget() -> activation::Budget {
    activation::Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(120),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    }
}

// Literal pre-grouping recipe, including each independent Budget::call and final check.
fn original(
    fixture: &mut Fixture,
    budget: &activation::Budget,
) -> std::result::Result<(), Failure> {
    let plans = budget.call(|_| {
        fixture.gateways[0]
            .original_provider_plans(&fixture.prepared)?
            .ok_or_else(|| invalid("original provider plans absent"))
    })?;
    for (plan, gateway) in plans.iter().zip(&mut fixture.gateways) {
        if plan.provider_id() != gateway.provider() {
            return Err(budget.progress.unconfirmed());
        }
        activation::validate_live(&fixture.prepared, gateway, budget)?;
    }
    budget.check()?;
    Ok(())
}

fn grouped(fixture: &mut Fixture, budget: &activation::Budget) -> std::result::Result<(), Failure> {
    activation::validate_gateways(&fixture.prepared, &mut fixture.gateways, budget)
}

#[test]
fn gateway_round_validates_one_exact_launch_with_all_original_provider_checks() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let providers = fixture.gateways.each_ref().map(|gateway| gateway.provider);
    let (old, old_trace) = trace(|| original(&mut fixture, &budget()));
    old.unwrap();
    assert_eq!(old_trace.revisions, 3);
    assert_eq!(old_trace.running.len(), 6);
    let (result, observed) = trace(|| grouped(&mut fixture, &budget()));
    result.unwrap();
    assert_eq!(
        observed.revisions, 2,
        "full aggregate entry and full aggregate exit"
    );
    assert_eq!(observed.providers, [0, 1, 2]);
    assert_eq!(observed.exit_material, Some(true));
    assert_eq!(
        observed.running,
        [
            providers[0],
            providers[0],
            providers[1],
            providers[1],
            providers[2],
            providers[2],
            providers[0],
            providers[1],
            providers[2]
        ]
    );
    fixture.processes.stop().unwrap();
}

#[test]
fn gateway_round_refuses_mixed_launch_order_foreign_generation_and_stopped_children() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let original_launch = Arc::clone(&fixture.gateways[1].launch);
    fixture.gateways[1].launch = Arc::new(GeneratedLaunch {
        owner: Arc::clone(&original_launch.owner),
        revision: Arc::clone(&original_launch.revision),
        original: original_launch.original.clone(),
        active: AtomicBool::new(true),
    });
    let (result, observed) = trace(|| grouped(&mut fixture, &budget()));
    assert!(
        result.is_err(),
        "equal material cannot substitute another launch owner"
    );
    assert_eq!(observed.revisions, 0);
    fixture.gateways[1].launch = original_launch;
    fixture.gateways.swap(0, 1);
    let (result, observed) = trace(|| grouped(&mut fixture, &budget()));
    assert!(result.is_err());
    assert_eq!(observed.revisions, 2);
    assert_eq!(
        observed.running.len(),
        3,
        "ordinary order error still closes every child"
    );
    fixture.gateways.swap(0, 1);
    let mut foreign = fixture.prepared.clone();
    foreign.context.name.push_str("-foreign");
    assert!(activation::validate_gateways(&foreign, &mut fixture.gateways, &budget()).is_err());
    grouped(&mut fixture, &budget()).unwrap();
    let original_child = Arc::clone(&fixture.gateways[1].child);
    let mut exited = Command::new("/usr/bin/true").spawn().unwrap();
    exited.wait().unwrap();
    fixture.gateways[1].child = Arc::new(Mutex::new(exited));
    let (result, observed) = trace(|| grouped(&mut fixture, &budget()));
    assert!(
        result.is_err(),
        "an exited original handle cannot pass a shared launch check"
    );
    assert_eq!(observed.revisions, 2);
    assert_eq!(
        observed.running.len(),
        6,
        "two first-provider checks, refused second child, then all exit children"
    );
    fixture.gateways[1].child = original_child;
    fixture.processes.stop().unwrap();
    assert!(fixture.processes.children.is_empty());
    assert!(grouped(&mut fixture, &budget()).is_err());
    assert!(!fixture.gateways[0].launch.active.load(Ordering::Acquire));
}

#[test]
fn gateway_round_closes_profile_and_children_after_ordinary_error_or_cancellation() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let generation =
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let path = generation.path().to_path_buf();
    let selected = fixture.gateways[1].provider;
    fixture.gateways[1].provider = ProviderId::new([0xAC; 32]);
    on(At::Provider(0), move || {
        let root = PrivateDirectory::open_exact(path).unwrap();
        let mut bytes = root.read("peer3.toml", 1024 * 1024).unwrap().to_vec();
        bytes.extend_from_slice(b"\n# changed original gateway round profile\n");
        root.write_atomic("peer3.toml", &bytes, PublishMode::Replace)
            .unwrap();
    });
    let (result, observed) = trace(|| grouped(&mut fixture, &budget()));
    assert!(result.is_err());
    assert_eq!(observed.providers, [0]);
    assert_eq!(observed.revisions, 2);
    assert_eq!(
        observed.exit_material,
        Some(false),
        "full exit sees persistent mutation despite earlier provider-order error"
    );
    assert_eq!(
        observed.running.len(),
        5,
        "two first-provider checks plus all three exit observations"
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    fixture.gateways[1].provider = selected;
    grouped(&mut fixture, &budget()).unwrap();

    let cancelled_budget = budget();
    let cancelled = Arc::clone(&cancelled_budget.cancelled);
    on(At::Entry, move || cancelled.store(true, Ordering::Release));
    let (result, observed) = trace(|| grouped(&mut fixture, &cancelled_budget));
    assert!(matches!(
        result,
        Err(Failure::Activation {
            cause: Cause::Cancelled,
            ..
        })
    ));
    assert_eq!(
        observed.revisions, 2,
        "cancellation cannot skip the full admitted source exit"
    );
    assert_eq!(observed.exit_material, Some(true));
    assert_eq!(observed.running.len(), 3);
    fixture.processes.stop().unwrap();
}

#[test]
fn gateway_round_keeps_original_active_decode_admission_and_error_recipe() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let limits = |allocated| {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    };
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    baseline.with(|| original(&mut fixture, &budget())).unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for allocated in [1, charge - 1, charge] {
        let old = DecodeBudgetContext::new(limits(allocated));
        let (expected, expected_trace) = trace(|| old.with(|| original(&mut fixture, &budget())));
        let current = DecodeBudgetContext::new(limits(allocated));
        let (actual, actual_trace) = trace(|| current.with(|| grouped(&mut fixture, &budget())));
        assert_eq!(actual, expected);
        assert_eq!(actual_trace.revisions, expected_trace.revisions);
        assert_eq!(actual_trace.running, expected_trace.running);
        assert_eq!(
            actual_trace.exit_material, None,
            "active path never enters grouped admission"
        );
        assert_eq!(
            current.consumed_allocated_bytes(),
            old.consumed_allocated_bytes()
        );
        if allocated == 1 {
            assert!(actual.is_err());
        }
        if allocated == charge {
            assert_eq!(actual, Ok(()));
            assert_eq!(actual_trace.revisions, 3);
        }
    }
    let expired = activation::Budget {
        timeout: Duration::ZERO,
        ..budget()
    };
    let expected = original(&mut fixture, &expired);
    let active = DecodeBudgetContext::new(limits(1));
    assert_eq!(active.with(|| grouped(&mut fixture, &expired)), expected);
    assert!(matches!(
        expected,
        Err(Failure::Activation {
            phase: Phase::Selection,
            cause: Cause::Deadline
        })
    ));
    fixture.processes.stop().unwrap();
}

#[test]
fn gateway_compliance_pair_reduces_images_with_identical_native_and_child_observations() {
    use crate::localnet::service_authorities::count_profile_images;
    use crate::managed::service_authority::profile_validation_test_support::operation_paths;
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let (((expected, old_trace), old_images), old_locks) = operation_paths(|| {
        count_profile_images(|| {
            GeneratedServiceRuntime::test_full_gateway_pair(|| {
                trace(|| grouped(&mut fixture, &budget()))
            })
        })
    });
    expected.unwrap();
    let (((actual, current), images), locks) =
        operation_paths(|| count_profile_images(|| trace(|| grouped(&mut fixture, &budget()))));
    actual.unwrap();
    assert_eq!((old_images, images), (20, 14));
    assert_eq!(
        locks, old_locks,
        "every original native lock observation remains"
    );
    assert_eq!(current.revisions, old_trace.revisions);
    assert_eq!(current.providers, old_trace.providers);
    assert_eq!(current.running, old_trace.running);
    assert_eq!(current.exit_material, old_trace.exit_material);
    assert_eq!(current.revisions, 2);
    assert_eq!(current.running.len(), 9);
    fixture.processes.stop().unwrap();
}

#[test]
fn gateway_compliance_pair_closes_persistent_change_and_ordinary_error_at_full_exit() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture();
    let generation =
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = original.to_vec();
    changed.extend_from_slice(b"\n# changed between the two compliance projections\n");
    let selected = fixture.gateways[1].provider;
    // The first provider's second image sample used to fail before this ordinary order error.
    // The full aggregate source exit must still take precedence when detection moves later.
    fixture.gateways[1].provider = ProviderId::new([0xAC; 32]);
    for full in [true, false] {
        let path = generation.path().to_path_buf();
        let changed = changed.clone();
        on(At::Binding(0), move || {
            PrivateDirectory::open_exact(path)
                .unwrap()
                .write_atomic("peer3.toml", &changed, PublishMode::Replace)
                .unwrap();
        });
        let (result, observed) = trace(|| {
            if full {
                GeneratedServiceRuntime::test_full_gateway_pair(|| grouped(&mut fixture, &budget()))
            } else {
                grouped(&mut fixture, &budget())
            }
        });
        assert!(result.is_err());
        assert_eq!(observed.revisions, 2);
        assert_eq!(observed.exit_material, Some(false));
        assert_eq!(observed.providers, if full { vec![] } else { vec![0] });
        assert_eq!(observed.running.len(), if full { 4 } else { 5 });
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
    }
    fixture.gateways[1].provider = selected;
    grouped(&mut fixture, &budget()).unwrap();
    fixture.processes.stop().unwrap();
}
