//! Runs every shared scenario fixture against the engine and checks the tracked state machine.
//!
//! The fixtures under `fixtures/zk/workflow_v1/` are the contract the other SDK
//! families run unchanged. This runner interprets them with the deterministic
//! fake world: no network, no wall clock. `README.md` in that directory defines
//! the fixture format this file implements.

use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use norito::json::{Map, Value};

use super::{
    contract::{
        MAX_WORKFLOW_TRANSACTION_BYTES_V1, RoundStateV1, StepKindV1, TransactionStateV1,
        WORKFLOW_RULES_V1, WorkflowErrorCode, WorkflowKindV1, WorkflowStatusV1, state_machine_json,
    },
    engine::{
        BuiltStepPayload, CommittedOutcome, DispatchOutcome, RoundContext, RoundRecovery,
        RoundReport, RoundStatusReport, StepContext, StepFailure, WorkflowAccount, WorkflowClock,
        WorkflowDriver, WorkflowEngine, WorkflowFuture, WorkflowHandle, WorkflowLedger,
        WorkflowObserver, WorkflowRunOptions,
    },
    error::WorkflowError,
    journal::{
        CustodyHandleV1, Digest32, DriverIdentityV1, StepDescriptorV1, WorkflowBindingV1,
        WorkflowId, WorkflowJournalV1, WorkflowPlanV1, WorkflowProgressV1,
    },
    journal_tests::{encode_unchecked, fixture_path, pretty},
    storage::{
        MemoryWorkflowStorage, WorkflowRunnerLease, WorkflowStorage, WorkflowStorageDurability,
        WorkflowStorageError, WorkflowStorageErrorKind,
    },
    testing::{
        FakeDispatch, FakeSign, FakeStatus, FakeWorkflowWorld, fixture_digest,
        run_until_interrupted,
    },
};

/// Scenario categories the contract requires at least one fixture for.
const REQUIRED_CATEGORIES: &[&str] = &[
    "happy_path",
    "interruption_before_submission",
    "interruption_after_ambiguous_submission",
    "interruption_after_irreversible_progress",
    "dispatch_classification",
    "reconciliation",
    "retransmission",
    "replacement_identity",
    "cancellation",
    "duplicate_resume",
    "storage_corruption",
    "uncertain_write",
    "offchain_round",
    "bounds_and_bindings",
];

fn text<'a>(map: &'a Map, key: &str) -> &'a str {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("`{key}` must be a string"))
}

fn optional_text<'a>(map: &'a Map, key: &str) -> Option<&'a str> {
    map.get(key).map(|value| {
        value
            .as_str()
            .unwrap_or_else(|| panic!("`{key}` must be a string"))
    })
}

fn number(map: &Map, key: &str, default: u64) -> u64 {
    map.get(key).map_or(default, |value| {
        value
            .as_u64()
            .unwrap_or_else(|| panic!("`{key}` must be an unsigned integer"))
    })
}

fn flag(map: &Map, key: &str) -> bool {
    map.get(key).is_some_and(|value| {
        value
            .as_bool()
            .unwrap_or_else(|| panic!("`{key}` must be a boolean"))
    })
}

fn strings(map: &Map, key: &str) -> Vec<String> {
    map.get(key).map_or_else(Vec::new, |value| {
        value
            .as_array()
            .unwrap_or_else(|| panic!("`{key}` must be an array"))
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("`{key}` entries must be strings"))
                    .to_owned()
            })
            .collect()
    })
}

fn object<'a>(map: &'a Map, key: &str) -> Option<&'a Map> {
    map.get(key).map(|value| {
        value
            .as_object()
            .unwrap_or_else(|| panic!("`{key}` must be an object"))
    })
}

fn code(id: &str) -> WorkflowErrorCode {
    WorkflowErrorCode::from_id(id).unwrap_or_else(|| panic!("unknown error code `{id}`"))
}

fn split(token: &str) -> (&str, &str) {
    token.split_once(':').unwrap_or((token, ""))
}

fn participants(list: &str) -> Vec<Digest32> {
    list.split(',')
        .filter(|name| !name.is_empty())
        .map(|name| fixture_digest(&format!("participant:{name}")))
        .collect()
}

fn sorted(mut values: Vec<Digest32>) -> Vec<Digest32> {
    values.sort_unstable();
    values
}

fn parse_plan(plan: &Map) -> WorkflowPlanV1 {
    let driver = object(plan, "driver").expect("plan.driver");
    let instance = text(plan, "instance");
    let steps = plan
        .get("steps")
        .and_then(Value::as_array)
        .expect("plan.steps")
        .iter()
        .map(|step| {
            let step = step.as_object().expect("step");
            let label = text(step, "label");
            let intent = fixture_digest(&format!("intent:{label}"));
            match StepKindV1::from_id(text(step, "kind")).expect("step kind") {
                StepKindV1::Transaction => StepDescriptorV1::transaction(label, intent)
                    .with_max_transaction_identities(
                        u8::try_from(number(step, "max_transaction_identities", 1))
                            .expect("identity bound"),
                    ),
                StepKindV1::OffchainRound => StepDescriptorV1::offchain_round(
                    label,
                    intent,
                    flag(step, "irreversible"),
                    u32::try_from(number(step, "participants_required", 0)).expect("participants"),
                    u32::try_from(number(step, "custody_handles_required", 0)).expect("custody"),
                ),
            }
        })
        .collect();
    WorkflowPlanV1 {
        kind: WorkflowKindV1::from_id(text(plan, "kind")).expect("workflow kind"),
        instance: instance.to_owned(),
        driver: DriverIdentityV1 {
            id: text(driver, "id").to_owned(),
            schema_version: u32::try_from(number(driver, "schema_version", 1)).expect("schema"),
        },
        request_context_digest: fixture_digest(&format!("context:{instance}")),
        steps,
    }
}

/// Capability driver scripted by the fixture.
struct FixtureDriver {
    world: Arc<FakeWorkflowWorld>,
    identity: DriverIdentityV1,
    builds: Mutex<VecDeque<String>>,
    round_starts: Mutex<VecDeque<String>>,
    round_recoveries: Mutex<VecDeque<String>>,
}

impl FixtureDriver {
    fn script(&self, script: Option<&Map>) {
        let list = |key: &str| -> VecDeque<String> {
            script.map_or_else(VecDeque::new, |script| strings(script, key).into())
        };
        *self.builds.lock().expect("builds") = list("builds");
        *self.round_starts.lock().expect("round starts") = list("round_starts");
        *self.round_recoveries.lock().expect("round recoveries") = list("round_recoveries");
    }

    fn unconsumed(&self) -> usize {
        self.builds.lock().expect("builds").len()
            + self.round_starts.lock().expect("round starts").len()
            + self
                .round_recoveries
                .lock()
                .expect("round recoveries")
                .len()
    }

    async fn report(
        &self,
        token: String,
        context: RoundContext<'_>,
    ) -> Result<RoundReport, StepFailure> {
        let (kind, argument) = split(&token);
        let status = |participants: Vec<Digest32>| RoundStatusReport {
            round_id: context.round_id,
            context_digest: context.descriptor.intent_digest,
            participants,
        };
        let custody = |count: u32| {
            (0..count)
                .map(|index| CustodyHandleV1 {
                    label: format!("share-{index}"),
                    reference: format!("custody-ref:{}:{index}", context.descriptor.label)
                        .into_bytes(),
                })
                .collect::<Vec<_>>()
        };
        let completed = |status: RoundStatusReport, custody_handles: Vec<CustodyHandleV1>| {
            RoundReport::Completed {
                status,
                transcript: format!("transcript:{}", context.descriptor.label).into_bytes(),
                custody_handles,
            }
        };
        let required = context.descriptor.custody_handles_required;
        Ok(match kind {
            "completed" => completed(status(sorted(participants(argument))), custody(required)),
            "completed_reordered" => {
                let mut reordered = sorted(participants(argument));
                reordered.reverse();
                completed(status(reordered), custody(required))
            }
            "completed_duplicate" => {
                let one = participants(argument);
                completed(status(vec![one[0], one[0]]), custody(required))
            }
            "completed_missing_custody" => {
                completed(status(sorted(participants(argument))), Vec::new())
            }
            "completed_wrong_round" => {
                let mut wrong = status(sorted(participants(argument)));
                wrong.round_id = fixture_digest("round:other");
                completed(wrong, custody(required))
            }
            "completed_context_changed" => {
                let mut changed = status(sorted(participants(argument)));
                changed.context_digest = fixture_digest("intent:changed");
                completed(changed, custody(required))
            }
            "waiting" => RoundReport::Waiting(status(sorted(participants(argument)))),
            "failed" => RoundReport::Failed {
                code: code(argument),
                detail: "scripted round failure".to_owned(),
            },
            "error" => return Err(StepFailure::new(code(argument), "scripted round error")),
            "interrupt" => return self.world.interrupt().await,
            other => panic!("unknown round token `{other}`"),
        })
    }
}

impl WorkflowDriver for FixtureDriver {
    fn identity(&self) -> DriverIdentityV1 {
        self.identity.clone()
    }

    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            let label = format!("{}#{}", context.step_index, context.identity_ordinal);
            self.world.push_effect(format!("build:{label}"));
            let token = self
                .builds
                .lock()
                .expect("builds")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted build of {label}"));
            let (kind, argument) = split(&token);
            let built = |payload: Vec<u8>| BuiltStepPayload {
                intent_digest: context.descriptor.intent_digest,
                unsigned_payload: payload,
            };
            match kind {
                "ok" => Ok(built(FakeWorkflowWorld::payload(&label))),
                // A replacement that rebuilds the bytes of the first identity.
                "repeat_payload" => Ok(built(FakeWorkflowWorld::payload(&format!(
                    "{}#1",
                    context.step_index
                )))),
                "wrong_intent" => Ok(BuiltStepPayload {
                    intent_digest: fixture_digest("intent:other"),
                    unsigned_payload: FakeWorkflowWorld::payload(&label),
                }),
                "oversized" => Ok(built(vec![b'p'; MAX_WORKFLOW_TRANSACTION_BYTES_V1 + 1])),
                "empty" => Ok(built(Vec::new())),
                "fail" => Err(StepFailure::new(code(argument), "scripted build failure")),
                "interrupt" => self.world.interrupt().await,
                other => panic!("unknown build token `{other}`"),
            }
        })
    }

    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            self.world
                .push_effect(format!("round_start:{}", context.step_index));
            let token = self
                .round_starts
                .lock()
                .expect("round starts")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted round start"));
            self.report(token, context).await
        })
    }

    fn recover_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundRecovery, StepFailure>> {
        Box::pin(async move {
            self.world
                .push_effect(format!("round_recover:{}", context.step_index));
            let token = self
                .round_recoveries
                .lock()
                .expect("round recoveries")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted round recovery"));
            if token == "not_started" {
                return Ok(RoundRecovery::NotStarted);
            }
            self.report(token, context).await.map(RoundRecovery::Found)
        })
    }
}

/// Memory storage that can make one store of a call fail.
#[derive(Default)]
struct FaultStorage {
    inner: MemoryWorkflowStorage,
    /// Remaining stores before the fault, and its mode.
    fault: Mutex<Option<(u64, String)>>,
}

impl WorkflowStorage for FaultStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        self.inner.durability()
    }

    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        self.inner.load(id)
    }

    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        let mode = {
            let mut fault = self.fault.lock().expect("fault");
            match fault.as_mut() {
                Some((remaining, _)) if *remaining > 1 => {
                    *remaining -= 1;
                    None
                }
                Some(_) => fault.take().map(|(_, mode)| mode),
                None => None,
            }
        };
        match mode.as_deref() {
            None => self.inner.compare_and_store(id, expected, record),
            // The write never happened.
            Some("unavailable") => Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Unavailable,
                "scripted storage outage",
            )),
            // The write failed and its effect is unknown to the caller; here it was lost.
            Some("lost") => Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "scripted uncertain write (lost)",
            )),
            // The write failed after it was published.
            Some("published") => {
                self.inner.compare_and_store(id, expected, record)?;
                Err(WorkflowStorageError::new(
                    WorkflowStorageErrorKind::WriteUncertain,
                    "scripted uncertain write (published)",
                ))
            }
            Some(other) => panic!("unknown storage fault `{other}`"),
        }
    }

    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        self.inner.acquire_runner(id)
    }
}

/// Another actor triggered by a stored state or from inside an external call.
struct ConcurrentActor {
    world: Arc<FakeWorkflowWorld>,
    engine: WorkflowEngine,
    handle: Mutex<Option<WorkflowHandle>>,
    driver: Mutex<Option<Arc<FixtureDriver>>>,
    trigger: Mutex<Option<(String, String)>>,
}

impl ConcurrentActor {
    fn act_when(&self, current: Option<&str>) {
        let action = {
            let mut trigger = self.trigger.lock().expect("trigger");
            match trigger.as_ref() {
                Some((when, _)) if Some(when.as_str()) == current => {
                    trigger.take().map(|(_, action)| action)
                }
                _ => None,
            }
        };
        let Some(action) = action else {
            return;
        };
        match action.as_str() {
            "cancel" => {
                let cancelled = self
                    .engine
                    .cancel_by_id(
                        self.handle
                            .lock()
                            .expect("handle")
                            .as_ref()
                            .expect("handle")
                            .id(),
                    )
                    .expect("concurrent cancellation");
                self.world
                    .push_effect(format!("concurrent:cancel:{}", cancelled.status));
            }
            "run" => {
                let handle = self.handle.lock().expect("handle").clone().expect("handle");
                let driver = self.driver.lock().expect("driver").clone().expect("driver");
                let result = run_until_interrupted(
                    &self.world,
                    handle.run(driver.as_ref(), &WorkflowRunOptions::default()),
                )
                .expect("a second runner returns at once");
                let outcome = match result {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => error.code.to_string(),
                };
                self.world.push_effect(format!("concurrent:run:{outcome}"));
            }
            other => panic!("unknown concurrent action `{other}`"),
        }
    }
}

impl WorkflowObserver for ConcurrentActor {
    fn on_progress(&self, progress: &WorkflowProgressV1) {
        self.act_when(
            progress
                .current_step
                .and_then(|index| progress.steps.get(index as usize))
                .map(|step| step.state),
        );
    }
}

struct Fixture {
    world: Arc<FakeWorkflowWorld>,
    storage: Arc<FaultStorage>,
    driver: Arc<FixtureDriver>,
    actor: Arc<ConcurrentActor>,
    reader: WorkflowEngine,
    handle: WorkflowHandle,
    plan: WorkflowPlanV1,
    binding: WorkflowBindingV1,
}

impl Fixture {
    fn new(scenario: &Map) -> Self {
        let binding = WorkflowBindingV1 {
            network: "fixture-network".to_owned(),
            authority: "fixture-authority".to_owned(),
        };
        let plan = parse_plan(object(scenario, "plan").expect("plan"));
        let world = Arc::new(FakeWorkflowWorld::new(binding.clone()));
        let storage = Arc::new(FaultStorage::default());
        let driver = Arc::new(FixtureDriver {
            world: Arc::clone(&world),
            identity: plan.driver.clone(),
            builds: Mutex::default(),
            round_starts: Mutex::default(),
            round_recoveries: Mutex::default(),
        });
        let journal_storage: Arc<dyn WorkflowStorage> = storage.clone();
        let account: Arc<dyn WorkflowAccount> = world.clone();
        let ledger: Arc<dyn WorkflowLedger> = world.clone();
        let clock: Arc<dyn WorkflowClock> = world.clone();
        let reader = WorkflowEngine::new(journal_storage, account, ledger, clock);
        let actor = Arc::new(ConcurrentActor {
            world: Arc::clone(&world),
            engine: reader.clone(),
            handle: Mutex::new(None),
            driver: Mutex::new(None),
            trigger: Mutex::new(None),
        });
        let observer: Arc<dyn WorkflowObserver> = actor.clone();
        let handle = reader
            .clone()
            .with_observer(observer)
            .workflow(plan.clone())
            .expect("fixture plan is valid");
        *actor.handle.lock().expect("handle") =
            Some(reader.workflow(plan.clone()).expect("handle"));
        *actor.driver.lock().expect("driver") = Some(Arc::clone(&driver));
        // Avoid a cycle: the actor owns the world, whose hook must not own the actor.
        let weak_actor = Arc::downgrade(&actor);
        world.set_effect_hook(Some(Arc::new(move |effect| {
            if let Some(actor) = weak_actor.upgrade() {
                actor.act_when(Some(&format!("effect:{effect}")));
            }
        })));
        Self {
            world,
            storage,
            driver,
            actor,
            reader,
            handle,
            plan,
            binding,
        }
    }

    fn corrupt(&self, mode: &str) {
        let id = self.handle.id();
        let record = self
            .storage
            .inner
            .load(&id)
            .expect("load")
            .expect("a record to corrupt");
        let damaged = match mode {
            "flip_bit" => {
                let mut damaged = record;
                let middle = damaged.len() / 2;
                damaged[middle] ^= 0x01;
                damaged
            }
            "truncate" => record[..record.len() - 9].to_vec(),
            "append_byte" => {
                let mut damaged = record;
                damaged.push(0);
                damaged
            }
            // A valid journal of another workflow stored under this identifier.
            "foreign_journal" => {
                let mut other = self.plan.clone();
                other.instance.push_str("-other");
                let mut journal =
                    WorkflowJournalV1::new(&other, &self.binding, 1).expect("foreign journal");
                journal.sequence = 1;
                journal.encode_record().expect("record")
            }
            // A canonical record with a correct digest whose status contradicts its steps.
            "status_completed" => {
                let mut journal = WorkflowJournalV1::decode_record(&record).expect("journal");
                journal.status = WorkflowStatusV1::Completed;
                journal.sequence += 1;
                encode_unchecked(&journal)
            }
            other => panic!("unknown corruption `{other}`"),
        };
        self.storage.inner.overwrite_unchecked(&id, damaged);
    }
}

enum CallResult {
    Completed,
    Ok,
    Absent,
    Interrupted,
    Error(Box<WorkflowError>),
}

fn parse_dispatch(token: &str) -> FakeDispatch {
    let (kind, argument) = split(token);
    FakeDispatch::Outcome(match kind {
        "accepted" => DispatchOutcome::Accepted,
        "already_known" => DispatchOutcome::AlreadyKnown,
        "refused" => DispatchOutcome::Refused {
            detail: "scripted refusal".to_owned(),
        },
        "not_admitted" => DispatchOutcome::NotAdmitted {
            code: code(argument),
            detail: "scripted non-admission".to_owned(),
        },
        "ambiguous" => DispatchOutcome::Ambiguous {
            detail: "scripted timeout".to_owned(),
        },
        "interrupt" => return FakeDispatch::Interrupt,
        other => panic!("unknown dispatch token `{other}`"),
    })
}

fn parse_status(token: &str) -> FakeStatus {
    FakeStatus::Outcome(match token {
        "applied" => CommittedOutcome::Applied {
            block_height: Some(7),
        },
        "rejected" => CommittedOutcome::Rejected {
            detail: "scripted rejection".to_owned(),
        },
        "expired" => CommittedOutcome::Expired,
        // Queued, approved, committed, or a terminal kind not resolved from state.
        "observed" | "hint_applied" | "hint_rejected" => CommittedOutcome::ObservedNotFinal,
        "absent" => CommittedOutcome::ExactAbsence,
        // A failed read, or a response not bound to the requested identity and scope.
        "read_failed" | "unbound_response" => CommittedOutcome::ReadFailed {
            detail: "scripted read failure".to_owned(),
        },
        "interrupt" => return FakeStatus::Interrupt,
        other => panic!("unknown status token `{other}`"),
    })
}

fn parse_sign(token: &str) -> FakeSign {
    let (kind, argument) = split(token);
    match kind {
        "ok" => FakeSign::Ok,
        "fail" => FakeSign::Fail(code(argument)),
        "wrong_identity" => FakeSign::WrongIdentity,
        "interrupt" => FakeSign::Interrupt,
        other => panic!("unknown sign token `{other}`"),
    }
}

fn run_call(fixture: &Fixture, call: &Map) -> CallResult {
    let script = object(call, "script");
    let list = |key: &str| script.map_or_else(Vec::new, |script| strings(script, key));
    fixture.world.script(
        list("signs")
            .iter()
            .map(|token| parse_sign(token))
            .collect(),
        list("dispatches")
            .iter()
            .map(|token| parse_dispatch(token))
            .collect(),
        list("statuses")
            .iter()
            .map(|token| parse_status(token))
            .collect(),
    );
    fixture.driver.script(script);
    *fixture.actor.trigger.lock().expect("trigger") =
        object(call, "concurrent").map(|concurrent| {
            (
                text(concurrent, "when").to_owned(),
                text(concurrent, "action").to_owned(),
            )
        });
    *fixture.storage.fault.lock().expect("fault") = object(call, "storage_fault")
        .map(|fault| (number(fault, "store", 1), text(fault, "mode").to_owned()));

    let options = object(call, "options");
    let defaults = WorkflowRunOptions::default();
    let options = WorkflowRunOptions {
        observation_timeout: Duration::from_millis(
            options.map_or(0, |options| number(options, "observation_timeout_ms", 0)),
        ),
        poll_interval: Duration::from_millis(
            options.map_or(1_000, |options| number(options, "poll_interval_ms", 1_000)),
        ),
        retransmit_identical_bytes: options
            .is_some_and(|options| flag(options, "retransmit_identical_bytes")),
        retry_rejected_step: options.is_some_and(|options| flag(options, "retry_rejected_step")),
    };
    assert!(!defaults.retransmit_identical_bytes && !defaults.retry_rejected_step);

    let wrong_driver = FixtureDriver {
        world: Arc::clone(&fixture.world),
        identity: DriverIdentityV1 {
            id: "another-driver".to_owned(),
            schema_version: 1,
        },
        builds: Mutex::default(),
        round_starts: Mutex::default(),
        round_recoveries: Mutex::default(),
    };
    let driver: Option<&dyn WorkflowDriver> = match optional_text(call, "driver") {
        None | Some("present") => Some(fixture.driver.as_ref()),
        Some("absent") => None,
        Some("wrong_identity") => Some(&wrong_driver),
        Some(other) => panic!("unknown driver mode `{other}`"),
    };
    let result = match text(call, "op") {
        "run" => match run_until_interrupted(
            &fixture.world,
            fixture
                .handle
                .run(driver.expect("a run needs a driver"), &options),
        ) {
            None => CallResult::Interrupted,
            Some(Ok(progress)) => {
                assert_eq!(progress.status, WorkflowStatusV1::Completed);
                CallResult::Completed
            }
            Some(Err(error)) => CallResult::Error(Box::new(error)),
        },
        "recover" => {
            match run_until_interrupted(&fixture.world, fixture.handle.recover(driver, &options)) {
                None => CallResult::Interrupted,
                Some(Ok(_)) => CallResult::Ok,
                Some(Err(error)) => CallResult::Error(Box::new(error)),
            }
        }
        "cancel" => match fixture.handle.cancel() {
            Ok(_) => CallResult::Ok,
            Err(error) => CallResult::Error(Box::new(error)),
        },
        "progress" => match fixture.handle.progress() {
            Ok(Some(_)) => CallResult::Ok,
            Ok(None) => CallResult::Absent,
            Err(error) => CallResult::Error(Box::new(error)),
        },
        "corrupt" => {
            fixture.corrupt(text(call, "mode"));
            CallResult::Ok
        }
        other => panic!("unknown op `{other}`"),
    };
    // A fault that was armed must have fired, and every scripted entry must be consumed.
    assert!(
        fixture
            .storage
            .fault
            .lock()
            .expect("fault")
            .take()
            .is_none(),
        "the scripted storage fault never fired"
    );
    assert!(
        fixture
            .actor
            .trigger
            .lock()
            .expect("trigger")
            .take()
            .is_none(),
        "the scripted concurrent actor never acted"
    );
    assert_eq!(fixture.world.unconsumed(), 0, "unconsumed ledger script");
    assert_eq!(fixture.driver.unconsumed(), 0, "unconsumed driver script");
    result
}

fn check_call(fixture: &Fixture, call: &Map, result: &CallResult, context: &str) {
    let expect = object(call, "expect").unwrap_or_else(|| panic!("{context}: expect"));
    let trace = fixture.world.take_trace();
    assert_eq!(trace, strings(expect, "effects"), "{context}: effects");

    let stored = fixture.reader.progress_by_id(fixture.handle.id());
    let expected_result = expect.get("result").expect("expect.result");
    match (result, expected_result) {
        (CallResult::Completed, Value::String(name)) => assert_eq!(name, "completed", "{context}"),
        (CallResult::Ok, Value::String(name)) => assert_eq!(name, "ok", "{context}"),
        (CallResult::Absent, Value::String(name)) => assert_eq!(name, "absent", "{context}"),
        (CallResult::Interrupted, Value::String(name)) => {
            assert_eq!(name, "interrupted", "{context}");
        }
        (CallResult::Error(error), Value::Object(expected)) => {
            assert_eq!(
                error.code.id(),
                text(expected, "error"),
                "{context}: {error}"
            );
            if let Some(stage) = optional_text(expected, "stage") {
                assert_eq!(error.stage.id(), stage, "{context}: stage");
            }
            if let Some(step) = expected.get("step") {
                assert_eq!(
                    error.step_index.map(u64::from),
                    step.as_u64(),
                    "{context}: step"
                );
            }
            if let Some(bounds) = object(expected, "bounds") {
                let actual = error.bounds.expect("bounds");
                assert_eq!(actual.actual, number(bounds, "actual", 0), "{context}");
                assert_eq!(actual.maximum, number(bounds, "maximum", 0), "{context}");
            }
            if let Some(resumable) = expected.get("resumable") {
                assert_eq!(Some(error.is_resumable()), resumable.as_bool(), "{context}");
            }
            if flag(expected, "has_transaction_identity") {
                assert!(error.transaction.is_some(), "{context}: identity");
            }
            match optional_text(expected, "progress") {
                Some("unavailable") => {
                    assert!(
                        error.progress.is_none(),
                        "{context}: no manufactured snapshot"
                    );
                }
                // An uncertain write was published: the error carries the last record this
                // call validated, which is older than the stored one.
                Some("last_validated") => {
                    let carried = error.progress.as_ref().expect("error progress");
                    let stored = stored.as_ref().expect("stored").as_ref().expect("journal");
                    assert!(carried.sequence < stored.sequence, "{context}");
                    assert_eq!(error.last_validated_sequence, Some(carried.sequence));
                }
                // The error states the progress of the journal it left behind.
                None => {
                    let carried = error.progress.as_ref().expect("error progress");
                    let stored = stored.as_ref().expect("stored").as_ref().expect("journal");
                    assert_eq!(
                        carried.to_json(),
                        stored.to_json(),
                        "{context}: error progress"
                    );
                    assert_eq!(error.last_validated_sequence, Some(stored.sequence));
                }
                Some(other) => panic!("{context}: unknown progress expectation `{other}`"),
            }
        }
        (actual, expected) => panic!(
            "{context}: result mismatch, expected {expected:?}, got {}",
            match actual {
                CallResult::Completed => "completed".to_owned(),
                CallResult::Ok => "ok".to_owned(),
                CallResult::Absent => "absent".to_owned(),
                CallResult::Interrupted => "interrupted".to_owned(),
                CallResult::Error(error) => format!("error {error}"),
            }
        ),
    }

    if optional_text(expect, "journal") == Some("unreadable") {
        let error = stored.expect_err("the stored journal must not verify");
        assert_eq!(error.code.id(), text(expect, "journal_error"), "{context}");
        assert!(
            error.progress.is_none(),
            "{context}: no manufactured snapshot"
        );
        return;
    }
    if optional_text(expect, "journal") == Some("absent") {
        assert!(stored.expect("progress").is_none(), "{context}: no journal");
        return;
    }
    let progress = stored
        .unwrap_or_else(|error| panic!("{context}: stored journal: {error}"))
        .unwrap_or_else(|| panic!("{context}: no stored journal"));
    assert_eq!(
        progress.status.id(),
        text(expect, "status"),
        "{context}: status"
    );
    assert_eq!(progress.atomicity, "per_transaction_only");
    let states = progress
        .steps
        .iter()
        .map(|step| step.state.to_owned())
        .collect::<Vec<_>>();
    assert_eq!(states, strings(expect, "steps"), "{context}: step states");

    let partial = object(expect, "partial_completion")
        .unwrap_or_else(|| panic!("{context}: partial_completion is mandatory"));
    let indexes = |key: &str| -> Vec<u32> {
        partial
            .get(key)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{context}: partial_completion.{key}"))
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("index")).expect("index"))
            .collect()
    };
    let actual = &progress.partial_completion;
    assert_eq!(
        actual.confirmed_steps,
        indexes("confirmed_steps"),
        "{context}"
    );
    assert_eq!(
        actual.irreversible_steps,
        indexes("irreversible_steps"),
        "{context}"
    );
    assert_eq!(
        actual.unresolved_steps,
        indexes("unresolved_steps"),
        "{context}"
    );
    assert_eq!(actual.failed_steps, indexes("failed_steps"), "{context}");
    assert_eq!(
        actual.not_started_steps,
        indexes("not_started_steps"),
        "{context}"
    );
    assert_eq!(
        actual.rolled_back_steps,
        indexes("rolled_back_steps"),
        "{context}: nothing is ever rolled back"
    );
    assert!(actual.rolled_back_steps.is_empty());

    if let Some(identities) = object(expect, "identities") {
        for (step, expected) in identities {
            let step: usize = step.parse().expect("step index");
            let expected = expected.as_array().expect("identity list");
            let actual = &progress.steps[step].identities;
            assert_eq!(
                actual.len(),
                expected.len(),
                "{context}: identities of step {step}"
            );
            for (actual, expected) in actual.iter().zip(expected) {
                let expected = expected.as_object().expect("identity");
                assert_eq!(
                    u64::from(actual.dispatch_ordinal),
                    number(expected, "dispatches", 0),
                    "{context}: dispatches"
                );
                assert_eq!(
                    u64::from(actual.possible_admissions),
                    number(expected, "possible_admissions", 0),
                    "{context}: possible admissions"
                );
                assert_eq!(
                    actual.evidence.as_ref().map(|evidence| evidence.kind.id()),
                    optional_text(expected, "evidence"),
                    "{context}: evidence"
                );
            }
        }
    }
    if let Some(received) = object(expect, "participants_received") {
        for (step, expected) in received {
            let step: usize = step.parse().expect("step index");
            assert_eq!(
                Some(u64::from(progress.steps[step].participants_received)),
                expected.as_u64(),
                "{context}: participants of step {step}"
            );
        }
    }
    if let Some(sequence) = expect.get("sequence") {
        assert_eq!(
            Some(progress.sequence),
            sequence.as_u64(),
            "{context}: sequence"
        );
    }
    if let Some(cancel_requested) = expect.get("cancel_requested") {
        assert_eq!(
            Some(progress.cancel_requested),
            cancel_requested.as_bool(),
            "{context}"
        );
    }
}

fn load(path: &std::path::Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    norito::json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn scenario_files() -> Vec<String> {
    let manifest = load(&fixture_path("manifest.json"));
    let manifest = manifest.as_object().expect("manifest");
    assert_eq!(
        text(manifest, "schema"),
        "iroha.durable_workflow.fixtures.v1"
    );
    let listed = strings(manifest, "scenarios");
    // The manifest lists exactly the scenario files in the directory, in order.
    let mut present = std::fs::read_dir(fixture_path("scenarios"))
        .expect("scenarios directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("file name")
        })
        .collect::<Vec<_>>();
    present.sort();
    assert_eq!(
        listed, present,
        "manifest.json must list every scenario file"
    );
    listed
}

#[test]
fn tracked_state_machine_equals_the_tables_the_engine_executes() {
    let tracked = std::fs::read_to_string(fixture_path("state_machine.json")).expect("tracked");
    assert_eq!(
        tracked,
        pretty(&state_machine_json()),
        "fixtures/zk/workflow_v1/state_machine.json differs from workflow/contract.rs; \
         regenerate with `cargo test -p iroha --lib workflow:: -- --ignored`"
    );
}

#[test]
#[ignore = "writes fixtures/zk/workflow_v1/state_machine.json"]
fn regenerate_state_machine() {
    std::fs::write(
        fixture_path("state_machine.json"),
        pretty(&state_machine_json()),
    )
    .expect("write");
}

#[test]
fn every_shared_scenario_passes_against_the_fake_world() {
    let mut categories = Vec::new();
    let mut rules = Vec::new();
    let mut cancelled_in = BTreeSet::new();
    let files = scenario_files();
    for file in &files {
        let scenario = load(&fixture_path("scenarios").join(file));
        let scenario = scenario.as_object().expect("scenario");
        assert_eq!(
            text(scenario, "schema"),
            "iroha.durable_workflow.scenario.v1"
        );
        let id = text(scenario, "id");
        assert_eq!(
            format!("{id}.json"),
            *file,
            "a scenario file is named by its id"
        );
        assert!(!text(scenario, "description").is_empty());
        categories.push(text(scenario, "category").to_owned());
        for rule in strings(scenario, "rules") {
            assert!(
                WORKFLOW_RULES_V1.iter().any(|(known, _)| *known == rule),
                "{id}: unknown rule `{rule}`"
            );
            rules.push(rule);
        }
        let fixture = Fixture::new(scenario);
        let calls = scenario
            .get("calls")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{id}: calls"));
        assert!(!calls.is_empty(), "{id}: at least one call");
        for (index, call) in calls.iter().enumerate() {
            let call = call.as_object().expect("call");
            let context = format!("{id} call {index} ({})", text(call, "op"));
            // The state cancellation finds: the current step, or the last one when all are done.
            if text(call, "op") == "cancel"
                && let Ok(Some(progress)) = fixture.reader.progress_by_id(fixture.handle.id())
            {
                let found = progress
                    .current_step
                    .map_or(progress.steps.len() - 1, |index| index as usize);
                cancelled_in.insert(progress.steps[found].state.to_owned());
            }
            if let Some(concurrent) = object(call, "concurrent")
                && text(concurrent, "action") == "cancel"
            {
                cancelled_in.insert(text(concurrent, "when").to_owned());
            }
            let result = run_call(&fixture, call);
            check_call(&fixture, call, &result, &context);
        }
    }
    for category in REQUIRED_CATEGORIES {
        assert!(
            categories.iter().any(|present| present == category),
            "no scenario of category `{category}`"
        );
    }
    for category in &categories {
        assert!(
            REQUIRED_CATEGORIES.contains(&category.as_str()),
            "unknown category `{category}`"
        );
    }
    // Every rule of the contract is exercised by at least one scenario.
    for (rule, _) in WORKFLOW_RULES_V1 {
        assert!(
            rules.iter().any(|exercised| exercised == rule),
            "no scenario exercises rule `{rule}`"
        );
    }
    // Cancellation is requested in every transaction state and every round state.
    for state in TransactionStateV1::ALL
        .iter()
        .map(|state| state.id())
        .chain(RoundStateV1::ALL.iter().map(|state| state.id()))
    {
        assert!(
            cancelled_in.contains(state),
            "no scenario cancels a workflow whose current step is `{state}`"
        );
    }
    assert!(files.len() >= 60, "the shared scenario set shrank");
}
