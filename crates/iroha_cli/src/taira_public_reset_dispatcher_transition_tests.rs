//! Transaction regressions use real files and interrupted native publication boundaries.
use super::*;
use std::cell::Cell;

#[path = "taira_public_reset_dispatcher_transition_copy_tests.rs"]
mod copy;

struct Fixture {
    _temp: tempfile::TempDir,
    plan: Plan,
    bytes: Vec<u8>,
    root: PathBuf,
    guards: Vec<Vec<u8>>,
    proof: PathBuf,
}
fn file(path: &Path, bytes: &[u8], mode: u32) -> Pin {
    let mut missing = Vec::new();
    let mut parent = path.parent().unwrap();
    while !parent.exists() {
        missing.push(parent.to_path_buf());
        parent = parent.parent().unwrap();
    }
    for directory in missing.into_iter().rev() {
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    Pin {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256_hex(bytes),
        size: bytes.len() as u64,
        mode,
    }
}
fn fixture() -> Fixture {
    let temp = super::super::super::private_custody_test_dir("taira-dispatcher-transition-");
    let dir = temp.path().canonicalize().unwrap();
    fs::create_dir(dir.join("proc")).unwrap();
    fs::set_permissions(dir.join("proc"), fs::Permissions::from_mode(0o700)).unwrap();
    storage::test_process_root(dir.join("proc"));
    let old = file(
        &dir.join("fixed/dispatcher"),
        b"old native dispatcher",
        0o755,
    );
    let candidate = file(
        &dir.join("import/iroha"),
        b"qualified native candidate",
        0o755,
    );
    let evidence = file(
        &dir.join("evidence.json"),
        b"sealed predecessor remains unchanged",
        0o400,
    );
    let pins = (0..SLUGS.len())
        .map(|i| {
            file(
                &dir.join(format!("guards/{i}/guard.json")),
                format!("old guard {i}").as_bytes(),
                0o600,
            )
        })
        .collect();
    let hosts = super::super::super::host_pair::fixture_pair();
    let revision = super::super::super::sample_inventory_fixture().revision;
    let native_edge_candidate = super::super::super::host_pair::fixture_native_edge_candidate(
        &hosts,
        &revision,
        dir.join("native/iroha").to_string_lossy().into_owned(),
    );
    let native_edge_capture = super::super::super::host_pair::fixture_native_edge_capture(
        &hosts,
        super::super::super::EdgeAdmittedReleaseV1 {
            commit: "4".repeat(40),
            release_root: format!(
                "{}/.local/share/iroha/taira/edge/releases/{}",
                hosts.native_edge.owner_home,
                "4".repeat(40)
            ),
            cli_sha256: "a".repeat(64),
            config_sha256: "b".repeat(64),
        },
        &"f".repeat(64),
        &"1".repeat(64),
        &"2".repeat(32),
        &super::super::super::sample_inventory_fixture().next_genesis_hash,
    );
    let plan = Plan {
        schema: SCHEMA.into(),
        operation_id: "a".repeat(32),
        host_identity_sha256: "b".repeat(64),
        hosts,
        trusted_public_key: evidence.clone(),
        candidate: Candidate {
            commit: "c".repeat(40),
            tree: "d".repeat(40),
            signer_fingerprint: "E".repeat(40),
            revision,
            executable: candidate,
            native_edge_candidate,
            preparation: evidence.clone(),
            request: evidence.clone(),
            checks: evidence.clone(),
            capture: evidence.clone(),
            transfer_request: evidence.clone(),
            transfer_completed: evidence.clone(),
            binary_transfer: evidence.clone(),
            source_transfer: evidence.clone(),
        },
        predecessor: Predecessor {
            inventory_sha256: "f".repeat(64),
            authorization_sha256: "1".repeat(64),
            authorization_nonce: "2".repeat(32),
            native_edge_capture,
            rolled_back: false,
            unresolved_journal: None,
            completed_next_step: 15,
            sealed_forward_ordinal: 62,
            completed: evidence.clone(),
            lease: evidence.clone(),
            progress: evidence.clone(),
            dispatcher: old,
            guards: pins,
            occupied: Vec::new(),
        },
    };
    let bytes = json::to_vec(&plan).unwrap();
    let root = dir.join("operations/one");
    let guards = (0..SLUGS.len())
        .map(|i| format!("candidate guard {i}").into_bytes())
        .collect();
    Fixture {
        _temp: temp,
        plan,
        bytes,
        root,
        guards,
        proof: PathBuf::from(evidence.path),
    }
}
fn run(f: &Fixture, action: Action) -> Result<()> {
    storage::transition(&f.plan, &f.bytes, &f.root, &f.guards, action, || Ok(()))
}
fn assert_live(f: &Fixture, new: bool) {
    assert_eq!(
        fs::read(&f.plan.predecessor.dispatcher.path).unwrap(),
        if new {
            b"qualified native candidate".as_slice()
        } else {
            b"old native dispatcher".as_slice()
        }
    );
    for i in 0..SLUGS.len() {
        assert_eq!(
            fs::read(&f.plan.predecessor.guards[i].path).unwrap(),
            if new {
                f.guards[i].clone()
            } else {
                format!("old guard {i}").into_bytes()
            }
        );
    }
    assert_eq!(
        fs::read(&f.proof).unwrap(),
        b"sealed predecessor remains unchanged"
    );
}

fn checked_transition_boundaries(action: Action) -> usize {
    let f = fixture();
    if matches!(action, Action::Rollback) {
        run(&f, Action::Apply).unwrap();
    }
    let calls = Cell::new(0);
    storage::transition(&f.plan, &f.bytes, &f.root, &f.guards, action, || {
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_live(&f, matches!(action, Action::Apply));
    assert!(
        calls.get() > 0,
        "completed transition must expose checked mutation boundaries"
    );
    calls.get()
}
#[test]
fn dispatcher_transition_apply_and_rollback_preserve_exact_original_bytes() {
    let f = fixture();
    storage::check(&f.plan, &f.bytes, &f.root, &f.guards).unwrap();
    assert!(!f.root.exists());
    run(&f, Action::Apply).unwrap();
    assert_live(&f, true);
    run(&f, Action::Rollback).unwrap();
    assert_live(&f, false);
    assert_eq!(
        fs::read(f.root.join("old-dispatcher")).unwrap(),
        b"old native dispatcher"
    );
}
#[test]
fn topology_producer_requires_durable_applied_transition_and_exact_live_guards() {
    let f = fixture();
    assert!(storage::check(&f.plan, &f.bytes, &f.root, &f.guards).is_ok());
    assert!(storage::check_applied(&f.plan, &f.bytes, &f.root, &f.guards).is_err());
    run(&f, Action::Apply).unwrap();
    storage::check_applied(&f.plan, &f.bytes, &f.root, &f.guards).unwrap();
    fs::write(&f.plan.predecessor.guards[0].path, b"foreign guard").unwrap();
    assert!(storage::check_applied(&f.plan, &f.bytes, &f.root, &f.guards).is_err());
}

#[test]
fn topology_producer_rejects_rolled_back_transition() {
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    run(&f, Action::Rollback).unwrap();
    assert!(storage::check_applied(&f.plan, &f.bytes, &f.root, &f.guards).is_err());
}
#[test]
fn dispatcher_transition_completed_replays_do_not_republish() {
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    let inode = fs::metadata(&f.plan.predecessor.dispatcher.path)
        .unwrap()
        .ino();
    run(&f, Action::Apply).unwrap();
    assert_eq!(
        fs::metadata(&f.plan.predecessor.dispatcher.path)
            .unwrap()
            .ino(),
        inode
    );
    run(&f, Action::Rollback).unwrap();
    let inode = fs::metadata(&f.plan.predecessor.dispatcher.path)
        .unwrap()
        .ino();
    run(&f, Action::Rollback).unwrap();
    assert_eq!(
        fs::metadata(&f.plan.predecessor.dispatcher.path)
            .unwrap()
            .ino(),
        inode
    );
    assert!(run(&f, Action::Apply).is_err());
}
#[test]
fn dispatcher_transition_interrupted_publication_resumes_every_checked_boundary() {
    // Census the complete native transition, then inject every observed boundary;
    // the independently captured Mac guard is not a fifth guest publication.
    for cut in 1..=checked_transition_boundaries(Action::Apply) {
        let f = fixture();
        let calls = Cell::new(0);
        let result =
            storage::transition(&f.plan, &f.bytes, &f.root, &f.guards, Action::Apply, || {
                let n = calls.get() + 1;
                calls.set(n);
                need(n != cut, "injected crash")
            });
        assert!(
            result.is_err(),
            "cut {cut} did not interrupt, calls {}",
            calls.get()
        );
        assert_eq!(calls.get(), cut);
        run(&f, Action::Apply).unwrap_or_else(|e| panic!("cut {cut}: {e:#}"));
        assert_live(&f, true);
    }
}
#[test]
fn dispatcher_transition_rollback_from_every_partial_guard_publication() {
    for cut in 1..=checked_transition_boundaries(Action::Apply) {
        let f = fixture();
        let calls = Cell::new(0);
        let interrupted =
            storage::transition(&f.plan, &f.bytes, &f.root, &f.guards, Action::Apply, || {
                let n = calls.get() + 1;
                calls.set(n);
                need(n != cut, "injected crash")
            });
        assert!(interrupted.is_err(), "cut {cut} did not interrupt");
        assert_eq!(calls.get(), cut);
        run(&f, Action::Rollback).unwrap_or_else(|e| panic!("cut {cut}: {e:#}"));
        assert_live(&f, false);
    }
}
#[test]
fn dispatcher_transition_interrupted_rollback_resumes() {
    for cut in 1..=checked_transition_boundaries(Action::Rollback) {
        let f = fixture();
        run(&f, Action::Apply).unwrap();
        let calls = Cell::new(0);
        let result = storage::transition(
            &f.plan,
            &f.bytes,
            &f.root,
            &f.guards,
            Action::Rollback,
            || {
                let n = calls.get() + 1;
                calls.set(n);
                need(n != cut, "injected crash")
            },
        );
        assert!(
            result.is_err(),
            "cut {cut} did not interrupt, calls {}",
            calls.get()
        );
        assert_eq!(calls.get(), cut);
        run(&f, Action::Rollback).unwrap_or_else(|e| panic!("cut {cut}: {e:#}"));
        assert_live(&f, false);
    }
}
#[test]
fn dispatcher_transition_changed_predecessor_refuses_rollback_before_barrier() {
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    let result = storage::transition(
        &f.plan,
        &f.bytes,
        &f.root,
        &f.guards,
        Action::Rollback,
        || Err(eyre!("lease or current runtime changed")),
    );
    assert!(result.is_err());
    assert_live(&f, true);
    assert!(!f.root.join("rollback-requested.json").exists());
}
#[test]
fn dispatcher_transition_rejects_foreign_guard_and_backup() {
    for backup in [false, true] {
        let f = fixture();
        run(&f, Action::Apply).unwrap();
        let path = if backup {
            f.root.join("old-guard-2")
        } else {
            PathBuf::from(&f.plan.predecessor.guards[2].path)
        };
        fs::write(&path, b"foreign payload").unwrap();
        assert!(run(&f, Action::Rollback).is_err());
        assert_eq!(
            fs::read(&f.plan.predecessor.dispatcher.path).unwrap(),
            b"qualified native candidate"
        );
    }
}
#[test]
fn dispatcher_transition_rejects_same_bytes_replaced_inode() {
    for target in ["guard", "backup", "dispatcher"] {
        let f = fixture();
        run(&f, Action::Apply).unwrap();
        let path = match target {
            "guard" => PathBuf::from(&f.plan.predecessor.guards[1].path),
            "backup" => f.root.join("old-dispatcher"),
            _ => PathBuf::from(&f.plan.predecessor.dispatcher.path),
        };
        let bytes = fs::read(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().mode() & 0o7777;
        let replacement = path.with_extension("replacement");
        file(&replacement, &bytes, mode);
        fs::rename(replacement, path).unwrap();
        assert!(
            run(&f, Action::Rollback).is_err(),
            "accepted replaced {target}"
        );
    }
}
#[test]
fn dispatcher_transition_rejects_foreign_namespace_and_plan() {
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    fs::write(f.root.join("foreign"), b"x").unwrap();
    assert!(run(&f, Action::Apply).is_err());
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    assert!(
        storage::transition(
            &f.plan,
            b"different plan",
            &f.root,
            &f.guards,
            Action::Rollback,
            || Ok(())
        )
        .is_err()
    );
}
#[test]
fn dispatcher_transition_rejects_dangling_symlink_as_absence() {
    let f = fixture();
    run(&f, Action::Apply).unwrap();
    fs::remove_file(f.root.join("old-guard-1")).unwrap();
    symlink("/definitely/absent", f.root.join("old-guard-1")).unwrap();
    assert!(run(&f, Action::Rollback).is_err());
}
#[test]
fn dispatcher_transition_refuses_unowned_missing_guard() {
    let f = fixture();
    let calls = Cell::new(0);
    let _ = storage::transition(&f.plan, &f.bytes, &f.root, &f.guards, Action::Apply, || {
        let n = calls.get() + 1;
        calls.set(n);
        need(n != 3, "crash behind barrier")
    });
    fs::remove_file(&f.plan.predecessor.guards[3].path).unwrap();
    assert!(run(&f, Action::Apply).is_err());
    assert!(!Path::new(&f.plan.predecessor.dispatcher.path).exists());
}
#[test]
fn dispatcher_transition_cli_requires_exact_plan_pin_and_action() {
    use clap::Parser as _;
    for extra in [
        vec![],
        vec!["--action", "apply"],
        vec!["--expected-plan-sha256", "a"],
    ] {
        let mut args = vec![
            "iroha",
            "taira",
            "public-reset",
            "dispatcher-transition",
            "--plan",
            "/runtime/plan.json",
        ];
        args.extend(extra);
        assert!(crate::Args::try_parse_from(args).is_err());
    }
}

fn sealed_records(plan: &Plan) -> (HostLeaseV1, HostProgressV1, Value) {
    let p = &plan.predecessor;
    let lease = HostLeaseV1 {
        schema: LEASE_SCHEMA_V1.into(),
        inventory_sha256: p.inventory_sha256.clone(),
        authorization_semantic_sha256: p.authorization_sha256.clone(),
        authorization_nonce: p.authorization_nonce.clone(),
        execution_expires_at_unix_ms: 1,
    };
    let progress = HostProgressV1 {
        schema: HOST_PROGRESS_SCHEMA_V1.into(),
        inventory_sha256: p.inventory_sha256.clone(),
        authorization_sha256: p.authorization_sha256.clone(),
        authorization_nonce: p.authorization_nonce.clone(),
        next_forward_ordinal: p.sealed_forward_ordinal,
        prepared_action: None,
        touched_hosts: SLUGS.iter().map(|s| (*s).into()).collect(),
        sealed: true,
        rolling_back: false,
        last_rollback_rank: 0,
        rolled_back_hosts: Vec::new(),
    };
    let terminal = norito::json!({
        "schema": (super::super::super::JOURNAL_SCHEMA_V1),
        "qualification_scope": "core_testnet",
        "deployment_id": "retained-predecessor",
        "inventory_sha256": (p.inventory_sha256),
        "authorization_sha256": (p.authorization_sha256),
        "authorization_nonce": (p.authorization_nonce),
        "status": "completed",
        "phase": "completed",
        "next_step": (p.completed_next_step),
        "recovery_intent": (Value::Null),
        "touched_validators": (SLUGS[..4].to_vec()),
        "edge_touched": true,
        "edge_rollback_complete": false,
        "rollback_next_validator": 0,
        "failure_summary": "",
        "rollback_failures": (Vec::<String>::new()),
    });
    (lease, progress, terminal)
}
#[test]
fn dispatcher_transition_accepts_exact_sealed_completed_predecessor() {
    let f = fixture();
    let (l, p, t) = sealed_records(&f.plan);
    admission::validate_sealed_records(&f.plan, &l, &p, &t).unwrap();
}
#[test]
fn dispatcher_transition_accepts_explicit_deployment_proven_takeover_without_completion() {
    let mut f = fixture();
    f.plan.predecessor.unresolved_journal = Some(f.plan.predecessor.completed.clone());
    f.plan.predecessor.completed_next_step = 11;
    let (lease, progress, mut proof) = sealed_records(&f.plan);
    proof
        .as_object_mut()
        .unwrap()
        .insert("status".into(), Value::String("sealing".into()));
    proof
        .as_object_mut()
        .unwrap()
        .insert("phase".into(), Value::String("seal".into()));
    let mut operational = proof.clone();
    operational.as_object_mut().unwrap().insert(
        "failure_summary".into(),
        Value::String("native edge seal bookkeeping failed".into()),
    );
    let original = operational.clone();
    admission::validate_deployment_proven_records(&f.plan, &lease, &progress, &proof, &operational)
        .unwrap();
    assert_eq!(operational, original);
    assert_eq!(proof.get("status").and_then(Value::as_str), Some("sealing"));
    assert!(admission::validate_sealed_records(&f.plan, &lease, &progress, &proof).is_err());
    for case in 0..12 {
        let mut plan = f.plan.clone();
        let mut lease = lease.clone();
        let mut progress = progress.clone();
        let mut proof = proof.clone();
        let mut operational = operational.clone();
        match case {
            0 => plan.predecessor.unresolved_journal = None,
            1 => plan.predecessor.rolled_back = true,
            2 => progress.sealed = false,
            3 => progress.rolling_back = true,
            4 => lease.execution_expires_at_unix_ms = u64::MAX,
            5 => {
                proof
                    .as_object_mut()
                    .unwrap()
                    .insert("status".into(), Value::String("completed".into()));
            }
            6 => {
                operational
                    .as_object_mut()
                    .unwrap()
                    .insert("authorization_nonce".into(), Value::String("f".repeat(32)));
            }
            7 => {
                operational
                    .as_object_mut()
                    .unwrap()
                    .insert("status".into(), Value::String("rolling_back".into()));
            }
            8 => {
                operational
                    .as_object_mut()
                    .unwrap()
                    .insert("next_step".into(), Value::from(12_u64));
            }
            9 => {
                operational
                    .as_object_mut()
                    .unwrap()
                    .insert("failure_summary".into(), Value::String("x".repeat(513)));
            }
            10 => {
                proof.as_object_mut().unwrap().insert(
                    "failure_summary".into(),
                    Value::String("unproven failure".into()),
                );
            }
            _ => {
                plan.predecessor.completed_next_step = 10;
                proof
                    .as_object_mut()
                    .unwrap()
                    .insert("next_step".into(), Value::from(10_u64));
                operational
                    .as_object_mut()
                    .unwrap()
                    .insert("next_step".into(), Value::from(10_u64));
            }
        }
        assert!(
            admission::validate_deployment_proven_records(
                &plan,
                &lease,
                &progress,
                &proof,
                &operational,
            )
            .is_err(),
            "case {case}"
        );
    }
}
#[test]
fn dispatcher_transition_accepts_only_complete_occupied_rollback() {
    let mut f = fixture();
    f.plan.predecessor.rolled_back = true;
    f.plan.predecessor.completed_next_step = 5;
    f.plan.predecessor.sealed_forward_ordinal = 49;
    let (lease, mut progress, mut terminal) = sealed_records(&f.plan);
    progress.sealed = false;
    progress.rolling_back = true;
    progress.last_rollback_rank = 1;
    progress.rolled_back_hosts = SLUGS[..4]
        .iter()
        .rev()
        .map(|slug| (*slug).to_owned())
        .collect();
    let record = terminal.as_object_mut().unwrap();
    record.insert("status".into(), Value::String("rolled_back".into()));
    record.insert("phase".into(), Value::String("rolled_back".into()));
    record.insert("edge_touched".into(), Value::Bool(false));
    record.insert("rollback_next_validator".into(), Value::from(4_u64));
    record.insert(
        "failure_summary".into(),
        Value::String("apply failed".into()),
    );
    admission::validate_rolled_back_records(&f.plan, &lease, &progress, &terminal).unwrap();

    for case in 0..10 {
        let (mut lease, mut progress, mut terminal) =
            (lease.clone(), progress.clone(), terminal.clone());
        match case {
            0 => progress.rolled_back_hosts.pop().map(|_| ()).unwrap(),
            1 => progress.touched_hosts.pop().map(|_| ()).unwrap(),
            2 => progress.sealed = true,
            3 => progress.last_rollback_rank = 2,
            4 => lease.inventory_sha256 = "0".repeat(64),
            5 => {
                terminal
                    .as_object_mut()
                    .unwrap()
                    .insert("rollback_next_validator".into(), Value::from(3_u64));
            }
            6 => {
                terminal
                    .as_object_mut()
                    .unwrap()
                    .insert("edge_rollback_complete".into(), Value::Bool(true));
            }
            7 => {
                terminal.as_object_mut().unwrap().insert(
                    "rollback_failures".into(),
                    norito::json!(["validator1 rollback failed"]),
                );
            }
            8 => {
                terminal
                    .as_object_mut()
                    .unwrap()
                    .insert("failure_summary".into(), Value::String(String::new()));
            }
            _ => {
                terminal
                    .as_object_mut()
                    .unwrap()
                    .insert("status".into(), Value::String("rolling_back".into()));
            }
        };
        assert!(
            admission::validate_rolled_back_records(&f.plan, &lease, &progress, &terminal).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn dispatcher_transition_rejects_unsealed_rollback_and_foreign_lease() {
    let f = fixture();
    for case in 0..8 {
        let (mut l, mut p, mut t) = sealed_records(&f.plan);
        match case {
            0 => p.sealed = false,
            1 => p.rolling_back = true,
            2 => p.authorization_nonce = "other".into(),
            3 => l.authorization_semantic_sha256 = "0".repeat(64),
            4 => p.touched_hosts.pop().map(|_| ()).unwrap(),
            5 => p.next_forward_ordinal += 1,
            6 => {
                t.as_object_mut()
                    .unwrap()
                    .insert("status".into(), Value::String("rolled_back".into()));
            }
            _ => {
                t.as_object_mut()
                    .unwrap()
                    .insert("extra".into(), Value::Bool(true));
            }
        }
        assert!(
            admission::validate_sealed_records(&f.plan, &l, &p, &t).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn dispatcher_transition_derives_guards_without_changing_existing_trust_or_roles() {
    let mut f = fixture();
    for (i, slug) in SLUGS.iter().enumerate() {
        let directory = if *slug == "taira-edge" { "edge" } else { *slug };
        let old = HostGuardV1 {
            schema: HOST_GUARD_SCHEMA_V1.into(),
            host_slug: (*slug).into(),
            service_root: format!("/srv/taira/{directory}"),
            state_root: format!("/var/lib/taira/{directory}"),
            trusted_key_sha256: f.plan.trusted_public_key.sha256.clone(),
            dispatcher_path: FIXED_DISPATCHER.into(),
            dispatcher_sha256: f.plan.predecessor.dispatcher.sha256.clone(),
            upload_parent: format!("/srv/taira/{directory}/.public-reset-upload-v1"),
        };
        let raw = json::to_vec(&old).unwrap();
        f.plan.predecessor.guards[i].sha256 = sha256_hex(&raw);
        let new: HostGuardV1 =
            json::from_slice(&admission::derive_guard(&f.plan, i, &raw).unwrap()).unwrap();
        assert_eq!(new.trusted_key_sha256, old.trusted_key_sha256);
        assert_eq!(new.service_root, old.service_root);
        assert_eq!(new.dispatcher_sha256, f.plan.candidate.executable.sha256);
        let mut wrong = f.plan.clone();
        wrong.trusted_public_key.sha256 = "0".repeat(64);
        assert!(admission::derive_guard(&wrong, i, &raw).is_err());
    }
}

#[test]
fn dispatcher_transition_staging_publication_crashes_resume_only_owned_prefixes() {
    for point in ["ownership", "stage-created", "partial-plan", "plan-written"] {
        let f = fixture();
        let parent = f.root.parent().unwrap();
        fs::create_dir(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let stop = if point == "partial-plan" {
            "stage-created"
        } else {
            point
        };
        assert!(
            storage::initialize_operation(&f.root, &f.bytes, |step| {
                need(step != stop, "injected staging interruption")
            })
            .is_err()
        );
        if point == "partial-plan" {
            file(
                &parent.join(".one.staging/.plan.json.partial"),
                &f.bytes[..17],
                0o600,
            );
        }
        run(&f, Action::Apply).unwrap();
        assert_live(&f, true);
    }
    let f = fixture();
    file(
        &f.root.parent().unwrap().join(".one.staging/foreign"),
        b"foreign",
        0o600,
    );
    assert!(run(&f, Action::Apply).is_err());
    assert_live(&f, false);
}

#[cfg(target_os = "linux")]
#[test]
fn dispatcher_transition_inode_scan_rejects_alias_executable_own_fd_and_maps() {
    let f = fixture();
    let proc = f._temp.path().join("process-fixture");
    let process = proc.join(std::process::id().to_string());
    file(&process.join("maps"), b"", 0o600);
    fs::create_dir(process.join("fd")).unwrap();
    let source = Path::new(&f.plan.predecessor.dispatcher.path);
    let meta = fs::metadata(source).unwrap();
    let check = || storage::no_references_at(&proc, meta.dev(), meta.ino());
    check().unwrap();
    // Hard-link pathnames and this process's own FD must still identify the old inode.
    let alias = f._temp.path().join("alias");
    fs::hard_link(source, &alias).unwrap();
    symlink(&alias, process.join("exe")).unwrap();
    assert!(check().is_err());
    fs::remove_file(process.join("exe")).unwrap();
    symlink(&alias, process.join("fd/9")).unwrap();
    assert!(check().is_err());
    fs::remove_file(process.join("fd/9")).unwrap();
    let maps = format!(
        "1000-2000 r-xp 00000000 {:x}:{:x} {} /deleted/alias (deleted)\n",
        rustix::fs::major(meta.dev()),
        rustix::fs::minor(meta.dev()),
        meta.ino()
    );
    fs::write(process.join("maps"), maps).unwrap();
    assert!(check().is_err());
    fs::write(process.join("maps"), "malformed\n").unwrap();
    assert!(check().is_err());
    fs::write(process.join("maps"), "1000-2000 rw-p 00000000 00:00 0\n").unwrap();
    check().unwrap();
}

fn set(v: &mut Value, key: &str, value: Value) {
    v.as_object_mut().unwrap().insert(key.into(), value);
}
fn qualification_records() -> (Candidate, Vec<Value>) {
    let mut c = fixture().plan.candidate;
    c.preparation.sha256 = "a".repeat(64);
    c.executable.sha256 = "b".repeat(64);
    c.executable.size = 20;
    let import = format!(
        "{RUNTIME}/release-import-{}-{}",
        c.commit, c.preparation.sha256
    );
    c.executable.path = format!("{import}/artifacts/bin/iroha");
    c.transfer_request.path = format!("{import}/request.json");
    c.transfer_completed.path = format!("{import}/completed.json");
    c.binary_transfer.path = format!("{import}/artifacts/verified-manifest.json");
    c.source_transfer.path = format!("{import}/source/verified-manifest.json");
    for (pin, name) in [
        (&mut c.preparation, "result.json"),
        (&mut c.request, "request.json"),
        (&mut c.checks, "checks.json"),
        (&mut c.capture, "capture.json"),
    ] {
        pin.path = format!("{import}/preparation/{name}");
        pin.size = 10;
        pin.mode = 0o400;
    }
    c.capture.sha256 = c.preparation.sha256.clone();
    let base = norito::json!({
        "commit": (c.commit),
        "tree": (c.tree),
        "signer_fingerprint": (c.signer_fingerprint),
        "native_check_scope": "basic",
        "native_incremental": false,
        "native_linker": "default",
        "environment_sha256": ("0".repeat(64)),
        "native_environment_sha256": ("1".repeat(64)),
        "target": "aarch64-unknown-linux-gnu",
        "profile": "release",
        "jobs": 6,
        "source_unchanged": true,
        "toolchain_unchanged": true,
        "source_snapshot_sha256": ("2".repeat(64)),
        "source_root": "/producer/source",
        "source_output_target": "/producer/target",
        "compiler_tools": {},
        "tools": {},
        "command": [],
        "release_qualified": false,
        "deployed": false,
    });
    let mut result = base.clone();
    let mut request = base;
    for (key, value) in [
        ("schema", "taira.local-preparation.v1"),
        ("repo_root", "/producer/repo"),
        ("target_dir", "/producer/target"),
    ] {
        set(&mut request, key, Value::String(value.into()));
    }
    let mut produced = Vec::new();
    let mut copied = Vec::new();
    for (name, package) in [
        ("iroha3d_taira", "irohad"),
        ("iroha", "iroha_cli"),
        ("sorafs-node", "sorafs_node"),
        ("kagami", "iroha_kagami"),
    ] {
        produced.push(norito::json!({
            "name": name,
            "package": package,
            "path": (format!("/producer/output/attempts/000001/bin/{name}")),
            "sha256": ("b".repeat(64)),
            "size": 20,
        }));
        copied.push(norito::json!({
            "name": name,
            "sha256": ("b".repeat(64)),
            "size": 20,
        }));
    }
    set(&mut result, "artifacts", Value::Array(produced));
    set(
        &mut result,
        "attempt",
        Value::String("attempts/000001".into()),
    );
    set(&mut result, "timings_seconds", norito::json!({}));
    let checks = norito::json!({
        "request": request,
        "passed": true,
    });
    let binary = norito::json!({
        "commit": (c.commit),
        "destination": (format!("{import}/artifacts/bin")),
        "artifacts": copied,
        "all_hashes_verified": true,
        "activated": false,
    });
    let source = norito::json!({
        "commit": (c.commit),
        "tree": (c.tree),
        "signer_fingerprint": (c.signer_fingerprint),
        "source_root": (format!("{import}/source/source")),
        "clean": true,
        "signature_verified": true,
        "object_inventory_verified": true,
        "history_included": false,
        "runtime_files_transferred": false,
        "runtime_files_included": false,
        "activated": false,
        "sha256": ("c".repeat(64)),
        "size": 10,
        "source_bytes": 10,
        "file_count": 1,
        "result_sha256": (c.preparation.sha256),
    });
    copied.extend([
        norito::json!({
            "name": "source.pack",
            "sha256": ("c".repeat(64)),
            "size": 10,
        }),
        norito::json!({
            "name": "source-capture.json",
            "sha256": ("d".repeat(64)),
            "size": 10,
        }),
    ]);
    for (name, pin) in [
        ("result.json", &c.preparation),
        ("request.json", &c.request),
        ("checks.json", &c.checks),
        ("capture.json", &c.capture),
    ] {
        copied.push(norito::json!({
            "name": (format!("preparation/{name}")),
            "sha256": (pin.sha256),
            "size": (pin.size),
        }));
    }
    let transfer = norito::json!({
        "schema": "taira.release-transfer.v1",
        "commit": (c.commit),
        "tree": (c.tree),
        "signer_fingerprint": (c.signer_fingerprint),
        "result_sha256": (c.preparation.sha256),
        "runtime_root": RUNTIME,
        "rows": copied,
        "allocation": {
            "bytes": 140,
            "files": 10,
            "directories": 6,
        },
    });
    let completed = norito::json!({
        "schema": "taira.release-transfer.completed.v1",
        "request_sha256": (c.transfer_request.sha256),
        "binary_transfer": {
            "path": (c.binary_transfer.path),
            "sha256": (c.binary_transfer.sha256),
        },
        "source_transfer": {
            "path": (c.source_transfer.path),
            "sha256": (c.source_transfer.sha256),
        },
        "activated": false,
    });
    (
        c,
        vec![result, request, checks, binary, source, transfer, completed],
    )
}
#[test]
fn dispatcher_transition_requires_complete_qualified_transfer_producer_join() {
    let (c, records) = qualification_records();
    admission::qualification::validate_records(&c, &records).unwrap();
    for scope in ["full", "build-only"] {
        let mut r = records.clone();
        for row in &mut r[..2] {
            set(row, "native_check_scope", Value::String(scope.into()));
        }
        let request = r[1].clone();
        set(&mut r[2], "request", request);
        let passed = scope != "build-only";
        set(&mut r[2], "passed", Value::Bool(passed));
        admission::qualification::validate_records(&c, &r).unwrap();
        set(&mut r[2], "passed", Value::Bool(!passed));
        admission::qualification::validate_records(&c, &r).unwrap();
        for invalid in [norito::json!((0)), norito::json!((1))] {
            set(&mut r[2], "passed", invalid);
            assert!(admission::qualification::validate_records(&c, &r).is_err());
        }
        set(&mut r[2], "passed", Value::Bool(passed));
        set(
            &mut r[1],
            "native_check_scope",
            Value::String("basic".into()),
        );
        assert!(admission::qualification::validate_records(&c, &r).is_err());
    }
    for case in 0..12 {
        let mut r = records.clone();
        match case {
            0 => set(&mut r[2], "passed", norito::json!((0))),
            1 => set(&mut r[6], "request_sha256", Value::String("0".repeat(64))),
            2 => set(&mut r[4], "result_sha256", Value::String("0".repeat(64))),
            3 => set(&mut r[4], "signature_verified", Value::Bool(false)),
            4 => set(&mut r[0], "commit", Value::String("0".repeat(40))),
            5 => set(&mut r[0], "attempt", Value::String("attempts/1".into())),
            6 => set(&mut r[6], "extra", Value::Bool(true)),
            7 => set(
                &mut r[5]
                    .as_object_mut()
                    .unwrap()
                    .get_mut("rows")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()[5],
                "size",
                norito::json!((64 * 1024 * 1024 + 1)),
            ),
            8 => set(
                r[5].as_object_mut().unwrap().get_mut("allocation").unwrap(),
                "bytes",
                norito::json!((99)),
            ),
            9 => set(
                r[5].as_object_mut().unwrap().get_mut("allocation").unwrap(),
                "files",
                norito::json!((1u64 << 50)),
            ),
            10 => {
                r[5].as_object_mut()
                    .unwrap()
                    .get_mut("rows")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .truncate(6);
            }
            _ => set(
                &mut r[5]
                    .as_object_mut()
                    .unwrap()
                    .get_mut("rows")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()[9],
                "sha256",
                Value::String("0".repeat(64)),
            ),
        }
        assert!(
            admission::qualification::validate_records(&c, &r).is_err(),
            "case {case}"
        );
    }
    let mut wrong = c.clone();
    wrong.executable.sha256 = "0".repeat(64);
    assert!(admission::qualification::validate_records(&wrong, &records).is_err());
}
#[test]
fn dispatcher_transition_requires_native_aarch64_elf_header() {
    let mut header = [0u8; 20];
    header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    header[16] = 2;
    header[18] = 183;
    assert!(admission::qualification::valid_elf(&header));
    header[16] = 3;
    assert!(admission::qualification::valid_elf(&header));
    for (index, value) in [(4, 1), (5, 2), (6, 0), (16, 1), (18, 62)] {
        let mut wrong = header;
        wrong[index] = value;
        assert!(!admission::qualification::valid_elf(&wrong));
    }
    assert!(!admission::qualification::valid_elf(&header[..19]));
}

#[test]
fn dispatcher_transition_prepare_reuses_current_typed_split_source_bindings() {
    let config_commit = "a".repeat(40);
    let daemon_commit = "b".repeat(40);
    let hosts = crate::taira_public_reset::host_pair::fixture_pair();
    let native_edge = crate::taira_public_reset::host_pair::fixture_native_edge_capture(
        &hosts,
        crate::taira_public_reset::EdgeAdmittedReleaseV1 {
            commit: config_commit.clone(),
            release_root: format!(
                "{}/.local/share/iroha/taira/edge/releases/{config_commit}",
                hosts.native_edge.owner_home
            ),
            cli_sha256: "e".repeat(64),
            config_sha256: "f".repeat(64),
        },
        &"1".repeat(64),
        &"2".repeat(64),
        &"3".repeat(32),
        &crate::taira_public_reset::sample_inventory_fixture().next_genesis_hash,
    );
    let mut validators = Vec::new();
    for slug in &SLUGS[..4] {
        let service = format!("/srv/taira/{slug}");
        let release = format!("{service}/releases/{config_commit}");
        let daemon = format!("{RUNTIME}/release-{daemon_commit}-update-one/bin/iroha3d_taira");
        let mut artifacts = Vec::new();
        for (role, path, mode, commit) in [
            ("iroha3d", daemon.clone(), 0o755, daemon_commit.clone()),
            (
                "config",
                format!("{release}/config/config.toml"),
                0o600,
                config_commit.clone(),
            ),
            (
                "genesis",
                format!("{release}/genesis/genesis.json"),
                0o644,
                config_commit.clone(),
            ),
            (
                "genesis_hash",
                format!("{release}/genesis/genesis.sha256"),
                0o644,
                config_commit.clone(),
            ),
            (
                "validator_unit",
                format!("/etc/systemd/system/iroha3d-{slug}.service"),
                0o644,
                daemon_commit.clone(),
            ),
        ] {
            artifacts.push(norito::json!({
                "role": role,
                "path": path,
                "sha256": ("c".repeat(64)),
                "size": 20,
                "mode": mode,
                "source_commit": commit,
            }));
        }
        validators.push(norito::json!({
            "commit": config_commit,
            "release_root": release,
            "argv": [
                daemon,
                "--config",
                (format!("{service}/current/config/config.toml")),
                "--sora",
            ],
            "artifacts": artifacts,
            "service_state": {
                "state": "stopped",
                "value": {
                    "device": 10,
                    "inode": 20,
                },
            },
        }));
    }
    let value = norito::json!({
        "schema": "iroha.taira.dispatcher-current-runtime.v1",
        "host_identity_sha256": (hosts.validator_guest.endpoint.host_identity_sha256.clone()),
        "hosts": (json::to_value(&hosts).unwrap()),
        "validators": validators,
        "native_edge": (json::to_value(&native_edge).unwrap()),
    });
    let typed: prepare::CurrentRuntime = json::from_value(value.clone()).unwrap();
    prepare::validate_runtime(&typed).unwrap();
    let mut wrong = value.clone();
    set(
        &mut wrong,
        "schema",
        Value::String("old.runtime.schema".into()),
    );
    assert!(prepare::validate_runtime(&json::from_value(wrong).unwrap()).is_err());
    let mut wrong = value;
    let daemon = &mut wrong
        .as_object_mut()
        .unwrap()
        .get_mut("validators")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_object_mut()
        .unwrap()
        .get_mut("artifacts")
        .unwrap()
        .as_array_mut()
        .unwrap()[0];
    set(daemon, "source_commit", Value::String(config_commit));
    assert!(prepare::validate_runtime(&json::from_value(wrong).unwrap()).is_err());
}
#[test]
fn dispatcher_transition_prepare_cli_requires_pinned_native_inputs() {
    use clap::Parser as _;
    let args = vec![
        "iroha",
        "taira",
        "public-reset",
        "prepare-dispatcher-transition",
        "--import-root",
        "/import",
        "--expected-result-sha256",
        "a",
        "--native-edge-candidate",
        "/native-candidate.json",
        "--expected-native-edge-candidate-sha256",
        "e",
        "--native-edge-cli",
        "/native/iroha",
        "--source-manifest",
        "/source-manifest.json",
        "--retained-inventory",
        "/inventory.json",
        "--expected-retained-inventory-sha256",
        "b",
        "--current-runtime",
        "/runtime.json",
        "--expected-current-runtime-sha256",
        "c",
        "--trusted-public-key",
        "/trust.json",
        "--operation-id",
        "d",
        "--output",
        "/plan.json",
    ];
    assert!(crate::Args::try_parse_from(args.clone()).is_ok());
    assert!(crate::Args::try_parse_from(&args[..args.len() - 2]).is_err());
    assert!(
        crate::Args::try_parse_from([
            "iroha",
            "taira",
            "public-reset",
            "dispatcher-transition",
            "--plan",
            "/plan.json",
            "--expected-plan-sha256",
            "a",
            "--action",
            "check"
        ])
        .is_ok()
    );
}
