//! Actual three-provider imports keep their original source, output and admission recipe.

use super::*;
use crate::managed::service_authority::profile_validation_test_support;
use iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1;
use norito::core::DecodeBudgetContext;
use std::cell::RefCell;

#[derive(Default)]
struct Observation {
    disabled: bool,
    context: Option<ValidatorEpochContextV1>,
    children: Vec<usize>,
    epoch_charges: Vec<u64>,
    alive: Option<Box<dyn Fn() -> bool>>,
}
thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}
struct Observer;
impl Observer {
    fn begin(disabled: bool, context: Option<ValidatorEpochContextV1>) -> Self {
        OBSERVATION.with(|value| {
            assert!(
                value
                    .borrow_mut()
                    .replace(Observation {
                        disabled,
                        context,
                        ..Observation::default()
                    })
                    .is_none()
            );
        });
        Self
    }
    fn finish(self) -> Observation {
        OBSERVATION.with(|value| value.borrow_mut().take().unwrap())
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        OBSERVATION.with(|value| {
            value.borrow_mut().take();
        });
    }
}

pub(in crate::managed::generated_service_runtime) fn select_scope(
    scope: Option<CheckpointImportScope>,
) -> Option<CheckpointImportScope> {
    let disabled = OBSERVATION.with(|value| {
        let mut value = value.borrow_mut();
        let Some(observation) = value.as_mut() else {
            return false;
        };
        if !observation.disabled {
            observation.alive = scope
                .as_ref()
                .map(|scope| -> Box<dyn Fn() -> bool> { Box::new(scope.test_alive()) });
        }
        observation.disabled
    });
    if disabled { None } else { scope }
}

pub(in crate::managed::generated_service_runtime) fn after_child(
    index: usize,
    scope: Option<&CheckpointImportScope>,
) {
    OBSERVATION.with(|value| {
        let mut value = value.borrow_mut();
        let Some(observation) = value.as_mut() else {
            return;
        };
        observation.children.push(index);
        if let (Some(scope), Some(context)) = (scope, &observation.context) {
            // Observe only after the real producer. A zero result cannot populate a previously
            // absent context: its admitted native roundtrip has a separately proven positive cost.
            observation
                .epoch_charges
                .push(scope.test_epoch_charge(context));
        }
    });
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 512 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

fn read(
    authority: &ServiceAuthority,
    disabled: bool,
    context: Option<ValidatorEpochContextV1>,
) -> (Result<RuntimeSelection>, usize, usize, Observation) {
    let observer = Observer::begin(disabled, context);
    let _count = ServiceAuthority::test_begin_graph_import_counts();
    let (result, profiles) =
        profile_validation_test_support::count(|| RuntimeSelection::read(authority));
    let imports = ServiceAuthority::test_graph_import_snapshot().unwrap();
    let observation = observer.finish();
    if let Some(alive) = &observation.alive {
        assert!(
            !alive(),
            "no immutable import owner may escape the selection read"
        );
    }
    (result, imports, profiles, observation)
}

#[test]
fn genuine_selection_scope_shares_only_epoch_work_then_drops_and_keeps_active_recipe() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-selection-imports", false, false);
    let peers = fixture.peers();
    assert_eq!(fixture.carriers.len(), 6);
    let context =
        iroha_data_model::sumeragi_finality::authenticated_genesis(fixture.native.chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
    let cold = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let mut validation = iroha_data_model::sumeragi_finality::EpochValidationScope::new();
    cold.with(|| validation.core_epoch(&context)).unwrap();
    assert!(cold.consumed_allocated_bytes() > 0);
    drop(validation);

    // This control selects None at the sole changed argument. It executes the identical
    // canonical RuntimeSelection parser, physical children and return/exit path.
    let (ordinary, imports, profiles, callbacks) = read(&fixture.owner.authority, true, None);
    let ordinary = ordinary.unwrap();
    assert_eq!(
        imports, 3,
        "three real initial bodies select distinct certified frames"
    );
    assert_eq!(callbacks.children, [0, 1, 2]);
    assert!(callbacks.alive.is_none());
    for _ in 0..2 {
        let (actual, actual_imports, actual_profiles, observed) =
            read(&fixture.owner.authority, false, Some(context.clone()));
        assert_same_runtime_selection(&fixture.owner.authority, &actual.unwrap(), &ordinary);
        assert_eq!(
            actual_imports, imports,
            "distinct frames still run the full canonical importer"
        );
        assert_eq!(
            actual_profiles, profiles,
            "every original physical profile fence remains"
        );
        assert_eq!(observed.children, callbacks.children);
        assert_eq!(
            observed.epoch_charges,
            [0, 0, 0],
            "all three actual imports share the one authenticated genesis epoch"
        );
        assert!(observed.alive.is_some());
    }

    // Warming a prior read cannot enter a later caller's active admission. Compare the same
    // canonical recipe under wide, zero, one, exact-minus-one and exact cumulative owners.
    let wide = DecodeBudgetContext::new(limits(512 * 1024 * 1024));
    let (expected, _, _, _) = wide.with(|| read(&fixture.owner.authority, true, None));
    assert_same_runtime_selection(&fixture.owner.authority, &expected.unwrap(), &ordinary);
    let charge = usize::try_from(wide.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for cap in [0, 1, charge - 1, charge] {
        let expected_budget = DecodeBudgetContext::new(limits(cap));
        let (expected, expected_imports, expected_profiles, expected_calls) =
            expected_budget.with(|| read(&fixture.owner.authority, true, None));
        let actual_budget = DecodeBudgetContext::new(limits(cap));
        let (actual, actual_imports, actual_profiles, actual_calls) =
            actual_budget.with(|| read(&fixture.owner.authority, false, None));
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        assert_eq!(actual_imports, expected_imports);
        assert_eq!(actual_profiles, expected_profiles);
        assert_eq!(actual_calls.children, expected_calls.children);
        assert!(
            actual_calls.alive.is_none(),
            "active entry never creates a reuse owner"
        );
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => {
                assert_same_runtime_selection(&fixture.owner.authority, &actual, &expected)
            }
            (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
            _ => panic!("active canonical admission changed"),
        }
    }
    no_http(&peers);

    // An actual Owned original constructed under caller admission keeps its original
    // independent children even when this read itself occurs outside the old admission.
    let Genuine {
        owner,
        prepared,
        _temporary,
        native,
        selection,
        components,
        carriers,
        options,
        catalog,
    } = fixture;
    drop((
        owner, native, selection, components, carriers, options, catalog,
    ));
    let admission = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owned = admission
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    let (expected, expected_imports, expected_profiles, expected_calls) =
        read(&owned.authority, true, None);
    let (actual, actual_imports, actual_profiles, actual_calls) =
        read(&owned.authority, false, None);
    assert_same_runtime_selection(&owned.authority, &actual.unwrap(), &expected.unwrap());
    assert_eq!(actual_imports, expected_imports);
    assert_eq!(actual_profiles, expected_profiles);
    assert_eq!(actual_calls.children, expected_calls.children);
    assert!(actual_calls.alive.is_none());
    no_http(&peers);
    drop(owned);
    drop(_temporary);
}

#[test]
fn genuine_selection_scope_keeps_changed_sources_and_ordinary_error_exit_precedence() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-selection-import-custody", false, false);
    let peers = fixture.peers();
    let (expected, _, _, _) = read(&fixture.owner.authority, false, None);
    let expected = expected.unwrap();
    let generation =
        PrivateDirectory::open_exact(generation_path(&fixture.prepared).unwrap()).unwrap();
    let profile = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = profile.to_vec();
    changed.extend_from_slice(b"\n# same parsed profile with changed original custody\n");
    let provider = fixture.selection.plans[1].provider_id();
    let custody = ServiceAuthority::open_provider_existing(
        &fixture.prepared,
        provider,
        crate::managed::service_authority::ProviderPurpose::Custody,
    )
    .unwrap()
    .unwrap();
    let initial = custody.directory.open_child("enroll").unwrap();
    let body = initial
        .open_child("bodies")
        .unwrap()
        .open_child("0001")
        .unwrap();
    let record = body
        .read(
            "reserved.nrt",
            crate::managed::native_operation::MAX_CHECKPOINT_BYTES * 2,
        )
        .unwrap();
    drop(custody);

    for disabled in [true, false] {
        body.write_atomic(
            "reserved.nrt",
            b"invalid canonical reservation",
            PublishMode::Replace,
        )
        .unwrap();
        let (ordinary, _, _, calls) = read(&fixture.owner.authority, disabled, None);
        assert_eq!(
            calls.children,
            [0],
            "the next provider and its callbacks remain unread after refusal"
        );
        let ordinary = ordinary.err().unwrap();
        assert!(matches!(
            ordinary,
            crate::managed::Error::Bootstrap(
                crate::managed::ManagedBootstrapFailure::RetainedMaterial
            )
        ));
        let source = generation.retain().unwrap();
        let modified = changed.clone();
        let hook = SelectionFinishHook::install(move || {
            source
                .write_atomic("peer3.toml", &modified, PublishMode::Replace)
                .unwrap();
        });
        let (error, _, _, calls) = read(&fixture.owner.authority, disabled, None);
        drop(hook);
        assert_eq!(calls.children, [0]);
        assert!(
            matches!(error, Err(crate::managed::Error::Invalid(message)) if message == "retained service profile input custody differs")
        );
        let (entry_error, _, _, entry_calls) = read(&fixture.owner.authority, disabled, None);
        assert!(entry_error.is_err());
        assert!(entry_calls.children.is_empty());
        assert!(
            entry_calls.alive.is_none(),
            "changed original entry admits no scope"
        );
        generation
            .write_atomic("peer3.toml", &profile, PublishMode::Replace)
            .unwrap();
        body.write_atomic("reserved.nrt", &record, PublishMode::Replace)
            .unwrap();
        let (restored, _, _, _) = read(&fixture.owner.authority, disabled, None);
        assert_same_runtime_selection(&fixture.owner.authority, &restored.unwrap(), &expected);

        let source = generation.retain().unwrap();
        let modified = changed.clone();
        let hook = SelectionFinishHook::install(move || {
            source
                .write_atomic("peer3.toml", &modified, PublishMode::Replace)
                .unwrap();
        });
        let (error, _, _, calls) = read(&fixture.owner.authority, disabled, None);
        drop(hook);
        assert_eq!(calls.children, [0, 1, 2]);
        assert!(
            matches!(error, Err(crate::managed::Error::Invalid(message)) if message == "retained service profile input custody differs")
        );
        generation
            .write_atomic("peer3.toml", &profile, PublishMode::Replace)
            .unwrap();
    }
    no_http(&peers);
    drop((body, initial, generation));
    let Genuine {
        _temporary,
        prepared,
        owner,
        native,
        selection,
        components,
        carriers,
        options,
        catalog,
    } = fixture;
    drop((
        prepared, owner, native, selection, components, carriers, options, catalog,
    ));
    drop(_temporary);
}
