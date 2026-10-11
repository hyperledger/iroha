//! Genuine renderer/child ownership exercises the startup tail's exact original plan reads.
//! These sleeping child handles supply no daemon, readiness, enrollment or discovery evidence.

use super::*;
use crate::localnet::service_authorities::count_profile_validations;
use crate::managed::service_authority::profile_validation_test_support;
use iroha_fs::{PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;

struct Fixture {
    // Stop and join every owned child before retained launch handles and temporary files drop.
    processes: PeerProcesses,
    gateways: [OwnedGateway; 3],
    prepared: PreparedLocalnet,
    _temporary: tempfile::TempDir,
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

fn fixture(owned: bool) -> Fixture {
    let (temporary, prepared, launch) = super::launch();
    let launch = if owned {
        let GeneratedLaunch {
            owner, revision, ..
        } = Arc::try_unwrap(launch)
            .ok()
            .expect("one actual launch owner");
        drop(owner);
        let revision = Arc::try_unwrap(revision)
            .ok()
            .expect("one actual catalog revision");
        let construction = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
        let owner = construction
            .with(|| GeneratedServiceRuntime::open(&prepared))
            .unwrap();
        GeneratedLaunch::new(Arc::new(owner), revision, &prepared).unwrap()
    } else {
        launch
    };
    let mut processes = PeerProcesses {
        children: Vec::new(),
        launch: Some(launch),
        background: None,
    };
    for _ in 0..4 {
        let child = Command::new("/bin/sleep").arg("120").spawn().unwrap();
        processes.children.push(Arc::new(Mutex::new(child)));
    }
    let gateways = processes.gateways().unwrap();
    Fixture {
        processes,
        gateways,
        prepared,
        _temporary: temporary,
    }
}

type Selections = (
    Vec<RetainedProviderServicePlan>,
    [RetainedProviderServicePlan; 3],
);

// The original three continuation selections followed by the aggregate selection.
fn standalone(fixture: &Fixture) -> Result<Selections> {
    let individual = fixture
        .gateways
        .iter()
        .map(|gateway| {
            fixture
                .prepared
                .provider_service_plan(gateway.provider())?
                .ok_or_else(|| invalid("renewal requires original provider plan"))
        })
        .collect::<Result<Vec<_>>>()?;
    let plans = fixture
        .prepared
        .provider_service_plans()?
        .ok_or_else(|| invalid("original provider plans absent"))?;
    Ok((individual, plans))
}

// Invoke the same gateway methods used at those four exact production selection sites.
fn retained(fixture: &Fixture) -> Result<Selections> {
    let individual = fixture
        .gateways
        .iter()
        .map(|gateway| {
            gateway
                .original_provider_plan(&fixture.prepared)?
                .ok_or_else(|| invalid("renewal requires original provider plan"))
        })
        .collect::<Result<Vec<_>>>()?;
    let plans = fixture.gateways[0]
        .original_provider_plans(&fixture.prepared)?
        .ok_or_else(|| invalid("original provider plans absent"))?;
    Ok((individual, plans))
}

fn same(actual: &Selections, expected: &Selections) {
    assert_eq!(actual.0.len(), 3);
    assert_eq!(expected.0.len(), 3);
    for (actual, expected) in actual
        .0
        .iter()
        .chain(actual.1.iter())
        .zip(expected.0.iter().chain(expected.1.iter()))
    {
        assert_eq!(actual.network_id(), expected.network_id());
        assert_eq!(actual.provider_id(), expected.provider_id());
        assert_eq!(actual.slot(), expected.slot());
        assert_eq!(actual.peer_index(), expected.peer_index());
        assert_eq!(
            actual.original_profile_commitment(),
            expected.original_profile_commitment()
        );
        assert_eq!(actual.reserve_terms(), expected.reserve_terms());
        assert_eq!(actual.pricing(), expected.pricing());
        assert_eq!(actual.declaration(), expected.declaration());
        assert_eq!(actual.admission_material(), expected.admission_material());
        assert_eq!(actual.https_origin(), expected.https_origin());
    }
}

#[test]
fn discovery_tail_retains_four_exact_original_selections_without_recapture() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture(false);
    let (expected, original_captures) = count_profile_validations(|| standalone(&fixture));
    let expected = expected.unwrap();
    assert_eq!(original_captures, 4);
    let ((actual, checks), captures) =
        count_profile_validations(|| profile_validation_test_support::count(|| retained(&fixture)));
    same(&actual.unwrap(), &expected);
    assert_eq!(captures, 0);
    assert_eq!(
        checks, 8,
        "fresh whole-profile entry and exit for every selection"
    );
    fixture.processes.stop().unwrap();
    assert!(fixture.processes.children.is_empty());
    // Original intent survives child shutdown, but cannot assert a running process or revision.
    same(&retained(&fixture).unwrap(), &expected);
    for gateway in &fixture.gateways {
        assert!(gateway.require_running().is_err());
    }
}

#[test]
fn discovery_tail_original_selection_closes_errors_and_refuses_source_or_owner_changes() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture(false);
    let expected = retained(&fixture).unwrap();
    let mut foreign = fixture.prepared.clone();
    foreign.context.name.push_str("-other");
    let (_, captures) = count_profile_validations(|| {
        assert!(
            fixture.gateways[0]
                .original_provider_plan(&foreign)
                .is_err()
        );
        assert!(
            fixture.gateways[0]
                .original_provider_plans(&foreign)
                .is_err()
        );
    });
    assert_eq!(
        captures, 0,
        "foreign generation is refused before fallback or projection"
    );
    let selected = fixture.gateways[0].provider;
    fixture.gateways[0].provider = ProviderId::new([0xAC; 32]);
    let (refused, checks) = profile_validation_test_support::count(|| {
        fixture.gateways[0].original_provider_plan(&fixture.prepared)
    });
    let unknown_error = refused.unwrap_err().to_string();
    assert_eq!(
        checks, 2,
        "ordinary projection refusal must close the native source"
    );
    assert_eq!(
        unknown_error,
        fixture
            .prepared
            .provider_service_plan(fixture.gateways[0].provider)
            .unwrap_err()
            .to_string()
    );
    let generation =
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.extend_from_slice(b"\n# changed original discovery-tail source\n");
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    let changed_error = fixture.gateways[0]
        .original_provider_plan(&fixture.prepared)
        .unwrap_err()
        .to_string();
    assert_ne!(
        changed_error, unknown_error,
        "source refusal precedes invalid provider projection"
    );
    assert!(
        fixture.gateways[0]
            .original_provider_plans(&fixture.prepared)
            .is_err()
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    fixture.gateways[0].provider = selected;
    same(&retained(&fixture).unwrap(), &expected);
    let runtime = generation.open_child("runtime").unwrap();
    let operations = runtime.open_child("service-operations").unwrap();
    let network = operations.open_child("network").unwrap();
    let owner = network.open_child("generated-service-runtime").unwrap();
    let lock = owner.path().join("operation.lock");
    let displaced = owner.path().join("displaced.lock");
    std::fs::rename(&lock, &displaced).unwrap();
    let replacement = owner.open_lock("operation.lock").unwrap();
    assert!(retained(&fixture).is_err());
    drop(replacement);
    std::fs::remove_file(&lock).unwrap();
    std::fs::rename(&displaced, &lock).unwrap();
    same(&retained(&fixture).unwrap(), &expected);
    fixture.processes.stop().unwrap();
}

#[test]
fn discovery_tail_original_selection_preserves_active_and_owned_admission() {
    let _resources = crate::managed::native_test_guard();
    let mut fixture = fixture(false);
    let warm = retained(&fixture).unwrap();
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, captures) = count_profile_validations(|| baseline.with(|| standalone(&fixture)));
    let expected = expected.unwrap();
    assert_eq!(captures, 4);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for allocated in [1, charge - 1, charge] {
        let old = DecodeBudgetContext::new(limits(allocated));
        let (expected, old_captures) =
            count_profile_validations(|| old.with(|| standalone(&fixture)));
        let new = DecodeBudgetContext::new(limits(allocated));
        let (actual, captures) = count_profile_validations(|| new.with(|| retained(&fixture)));
        if allocated == 1 {
            assert!(
                actual.is_err() && expected.is_err(),
                "a positive tiny budget must refuse full capture"
            );
        }
        if allocated == charge {
            assert!(
                actual.is_ok() && expected.is_ok(),
                "the exact original charge must suffice"
            );
        }
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => same(&actual, &expected),
            (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
            _ => panic!("actual and original physical admission outcomes differ"),
        }
        assert_eq!(captures, old_captures);
        assert_eq!(
            new.consumed_allocated_bytes(),
            old.consumed_allocated_bytes()
        );
    }
    same(&expected, &warm);
    fixture.processes.stop().unwrap();
    drop(fixture);
    let mut fixture = self::fixture(true);
    let (expected, old_captures) = count_profile_validations(|| standalone(&fixture));
    let (actual, captures) = count_profile_validations(|| retained(&fixture));
    same(&actual.unwrap(), &expected.unwrap());
    assert_eq!(old_captures, 4);
    assert_eq!(
        captures, 4,
        "Owned renderer retains each original full capture outside its former scope"
    );
    fixture.processes.stop().unwrap();
}
