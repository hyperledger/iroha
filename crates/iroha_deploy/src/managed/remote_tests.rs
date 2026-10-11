//! Offline attachment identity, custody and preflight regressions.

use super::*;
use crate::bootstrap::InstalledNetworkProfiles;
use iroha_crypto::{Algorithm, KeyPair};

#[test]
fn attachment_deadline_optional_record_preserves_parent_errors_and_original_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("attachment")).unwrap();
    attachment_turn_deadline(&directory).unwrap();
    let original = encode(&Activation { deadline_ms: 0 }).unwrap();
    directory
        .write_atomic(ACTIVATION, &original, PublishMode::CreateNew)
        .unwrap();
    attachment_turn_deadline(&directory).unwrap();
    #[cfg(unix)]
    {
        let displaced = temporary.path().join("original-attachment");
        std::fs::rename(directory.path(), &displaced).unwrap();
        let result = attachment_turn_deadline(&directory);
        std::fs::rename(displaced, directory.path()).unwrap();
        assert!(
            matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
    attachment_turn_deadline(&directory).unwrap();
    assert_eq!(
        directory.read(ACTIVATION, MAX_METADATA).unwrap().as_slice(),
        original
    );
    directory
        .write_atomic(ACTIVATION, b"invalid activation", PublishMode::Replace)
        .unwrap();
    assert!(attachment_turn_deadline(&directory).is_err());
    directory
        .write_atomic(ACTIVATION, &original, PublishMode::Replace)
        .unwrap();
    attachment_turn_deadline(&directory).unwrap();
}

fn profile(seed: u8, floor: u64, url: &str) -> InstalledNetworkProfile {
    InstalledNetworkProfile::new(
        "fixture".into(),
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
        floor,
        url.into(),
    )
    .unwrap()
}

fn runtime(root: &Path, profiles: InstalledNetworkProfiles) -> InstalledRuntime {
    let directory = PrivateDirectory::open_or_create(root).unwrap();
    for binary in ["kagami", "iroha3d"] {
        std::fs::copy(
            std::env::current_exe().unwrap(),
            directory
                .path()
                .join(format!("{binary}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    directory
        .write_atomic(
            crate::bootstrap::NETWORK_PROFILES_FILENAME,
            &profiles.encode_installation().unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    InstalledRuntime::from_directory(directory.path()).unwrap()
}

#[test]
fn profile_binding_rejects_key_endpoint_or_floor_regression() {
    let selected = profile(81, 4, "https://fixture.example/checkpoint");
    let binding = ProfileBinding::from_profile(&selected);
    binding.verify(&selected).unwrap();
    for changed in [
        profile(82, 4, "https://fixture.example/checkpoint"),
        profile(81, 3, "https://fixture.example/checkpoint"),
        profile(81, 4, "https://other.example/checkpoint"),
    ] {
        assert!(binding.verify(&changed).is_err());
    }
    let bytes = encode(&binding).unwrap();
    let restored: ProfileBinding = decode(&bytes).unwrap();
    restored.verify(&selected).unwrap();
    restored
        .verify(&profile(81, 5, "https://fixture.example/checkpoint"))
        .unwrap();
}

#[test]
fn installed_floor_increase_is_durable_and_concurrent_owner_cannot_regress_it() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open_or_create(temporary.path().join("bindings")).unwrap();
    let original = profile(86, 4, "https://fixture.example/checkpoint");
    let newer = profile(86, 6, "https://fixture.example/checkpoint");
    let binding = Binding {
        profile: ProfileBinding::from_profile(&original),
        spec: super::super::tests::private_spec(),
        account_alias: "admin".into(),
        context: None,
    };
    let directory = parent
        .publish_private_child(
            "private",
            &[("request.lock", b""), (BINDING, &encode(&binding).unwrap())],
        )
        .unwrap();
    let gate = directory.open_existing_lock("request.lock").unwrap();
    gate.try_lock().unwrap();
    assert!(matches!(
        bind_installed_profile(
            &directory,
            &newer,
            Instant::now() + Duration::from_millis(20)
        ),
        Err(Error::ParentDeadline)
    ));
    assert_eq!(read_binding(&directory).unwrap().profile.minimum_serial, 4);
    drop(gate);
    let upgraded = bind_installed_profile(&directory, &newer, Instant::now() + MAX_ATTACH).unwrap();
    assert_eq!(upgraded.profile.minimum_serial, 6);
    assert_eq!(read_binding(&directory).unwrap().profile.minimum_serial, 6);
    assert!(bind_installed_profile(&directory, &original, Instant::now() + MAX_ATTACH).is_err());
    assert!(
        bind_installed_profile(
            &directory,
            &profile(87, 7, "https://fixture.example/checkpoint"),
            Instant::now() + MAX_ATTACH
        )
        .is_err()
    );
    assert_eq!(read_binding(&directory).unwrap().profile.minimum_serial, 6);
    let restored = PrivateDirectory::open(directory.path()).unwrap();
    assert!(read_binding(&restored).unwrap().context.is_none());
    assert_eq!(read_binding(&restored).unwrap().spec, binding.spec);
}

#[test]
fn retained_attachment_requires_an_explicit_canonical_owner_alias() {
    let binding = Binding {
        profile: ProfileBinding::from_profile(&profile(
            87,
            1,
            "https://fixture.example/checkpoint",
        )),
        spec: super::super::tests::private_spec(),
        account_alias: "admin".into(),
        context: None,
    };
    let bytes = encode(&binding).unwrap();
    let restored: Binding = decode(&bytes).unwrap();
    assert_eq!(restored.account_alias, "admin");
    let mut old: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    old.as_object_mut().unwrap().remove("account_alias");
    assert!(decode::<Binding>(&norito::json::to_vec(&old).unwrap()).is_err());
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("binding")).unwrap();
    let mut invalid = binding;
    invalid.account_alias = "admin@other".into();
    directory
        .write_atomic(BINDING, &encode(&invalid).unwrap(), PublishMode::CreateNew)
        .unwrap();
    assert!(read_binding(&directory).is_err());
}

#[test]
fn invalid_or_uninstalled_attachment_requests_have_no_network_generation_side_effects() {
    let _guard = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("managed");
    let store = ManagedStore::open(&root).unwrap();
    let runtime = runtime(
        &temporary.path().join("bundle"),
        InstalledNetworkProfiles::new(Vec::new()).unwrap(),
    );
    let mut request = DataspaceRequest {
        name: "private".into(),
        network: "taira".into(),
        alias: "privateapp".into(),
        account_alias: "admin".into(),
        timeout: MAX_ATTACH,
    };
    assert!(store.up_dataspace(&runtime, &request).is_err());
    request.timeout = Duration::ZERO;
    assert!(store.up_dataspace(&runtime, &request).is_err());
    request.timeout = MAX_ATTACH + Duration::from_secs(1);
    assert!(store.up_dataspace(&runtime, &request).is_err());
    request.name = "../escape".into();
    assert!(store.up_dataspace(&runtime, &request).is_err());
    assert!(store.contexts().unwrap().is_empty());
    assert!(!root.join("attachments").exists());
    assert!(!root.join("releases").exists());
    assert!(store.dataspace_status("unknown").is_err());
}

#[test]
fn ordinary_context_has_no_remote_status_but_incomplete_binding_is_an_error() {
    let _guard = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, _, prepared) =
        super::super::tests::fixture(&temporary.path().join("managed"), "local");
    assert!(store.dataspace_status("local").unwrap().is_none());
    let cancellation = Arc::new(AtomicBool::new(true));
    assert!(
        AttachmentWorker::start(&store, "local", &prepared, cancellation)
            .unwrap()
            .is_none()
    );
    assert!(
        inactive_status(&store, "local", &prepared)
            .unwrap()
            .is_none()
    );
    let runtime = runtime(
        &temporary.path().join("bundle"),
        InstalledNetworkProfiles::new(Vec::new()).unwrap(),
    );
    assert!(
        store
            .build_registry(&runtime, "local", Instant::now() + MAX_ATTACH)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .build_registry(&runtime, "missing", Instant::now() + MAX_ATTACH)
            .is_err()
    );
    let directory = PrivateDirectory::open_or_create(outer_path(&store, "local")).unwrap();
    assert!(read_binding(&directory).is_err());
    assert!(store.dataspace_status("local").is_err());
    assert!(
        store
            .build_registry(&runtime, "local", Instant::now() + MAX_ATTACH)
            .is_err()
    );
    assert!(existing_outer(&store, "../other").is_err());
}

#[test]
fn completed_binding_detects_changed_child_and_preserves_private_reset_evidence() {
    let _guard = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, _, mut prepared) =
        super::super::tests::fixture(&temporary.path().join("managed"), "private");
    let spec = super::super::tests::private_spec();
    prepared.context.dataspace_alias = spec.dataspace_alias.clone();
    prepared.context.dataspace_id = spec.dataspace_id.as_u64();
    let binding = Binding {
        profile: ProfileBinding::from_profile(&profile(
            83,
            1,
            "https://fixture.example/checkpoint",
        )),
        spec,
        account_alias: "admin".into(),
        context: Some(prepared.context.clone()),
    };
    verify_context(&binding, &prepared).unwrap();
    // Context metadata cannot convert a retained Global genesis into a private one.
    assert!(verify_generation_binding(&store, "private", &binding, &prepared).is_err());
    let parent = OwnerDirectory::open_or_create(store.root().join("attachments")).unwrap();
    let directory = parent
        .publish_private_child(
            "private",
            &[("request.lock", b""), (BINDING, &encode(&binding).unwrap())],
        )
        .unwrap();
    let retained = read_binding(&directory).unwrap();
    verify_context(&retained, &prepared).unwrap();
    for field in ["network", "owner", "endpoint", "dataspace"] {
        let mut changed = prepared.clone();
        match field {
            "network" => changed.context.network_id.push('x'),
            "owner" => changed.context.account_id.push('x'),
            "endpoint" => changed.context.torii_url.push('x'),
            _ => changed.context.dataspace_id ^= 1,
        }
        assert!(verify_context(&retained, &changed).is_err());
    }
    store.reset("private").unwrap();
    assert!(read_binding(&directory).unwrap().context.is_some());
    assert!(store.dataspace_status("private").is_err());
}

#[test]
fn failed_first_private_start_retains_exact_context_and_diagnostics_before_attachment() {
    let _guard = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("managed")).unwrap();
    let store = ManagedStore::open(root.path()).unwrap();
    let binary = std::env::current_exe().unwrap();
    let mut request = LocalnetRequest::private_root(binary.clone(), binary);
    request.name = "private".into();
    request.startup_timeout = Duration::from_secs(120);
    let mut binding = Binding {
        profile: ProfileBinding::from_profile(&profile(
            83,
            1,
            "https://fixture.example/checkpoint",
        )),
        spec: super::super::tests::private_spec(),
        account_alias: "admin".into(),
        context: None,
    };
    let parent = OwnerDirectory::open_or_create(store.root().join("attachments")).unwrap();
    let directory = parent
        .publish_private_child(
            "private",
            &[("request.lock", b""), (BINDING, &encode(&binding).unwrap())],
        )
        .unwrap();
    let spec = binding.spec.clone();
    let refused_directory = parent.create_private_child("refused").unwrap();
    let _blocked_record = refused_directory.create_child(BINDING).unwrap();
    let refused = store.up_private_root_bound(&request, &spec, |prepared| {
        retain_prepared_context(
            &store,
            "private",
            &refused_directory,
            &mut binding,
            prepared,
        )
    });
    assert!(
        refused.is_err(),
        "binding publication must fail before native spawn"
    );
    assert!(
        binding.context.is_none(),
        "failed publication must not advance memory"
    );
    let network = store.directory("private").unwrap();
    assert!(
        !network.path().join(STATUS).exists(),
        "spawn status follows successful binding"
    );
    assert!(!network.path().join(WORKER).exists());
    let original = store.prepared("private").unwrap();
    let refused_activation = parent.create_private_child("activation-refused").unwrap();
    refused_activation
        .write_atomic(BINDING, &encode(&binding).unwrap(), PublishMode::CreateNew)
        .unwrap();
    let _blocked_activation = refused_activation.create_child(ACTIVATION).unwrap();
    let mut refused_binding = binding.clone();
    let refused = store.up_private_root_bound(&request, &spec, |prepared| {
        retain_prepared_activation(
            &store,
            "private",
            &refused_activation,
            &mut refused_binding,
            prepared,
            Instant::now() + MAX_ATTACH,
        )
    });
    assert!(
        refused.is_err(),
        "activation publication must precede native spawn"
    );
    assert_eq!(refused_binding.context.as_ref(), Some(&original.context));
    assert!(!network.path().join(STATUS).exists());
    assert!(!network.path().join(WORKER).exists());
    let request_gate = directory.open_existing_lock("request.lock").unwrap();
    request_gate.try_lock().unwrap();
    let original_deadline = Instant::now() + MAX_ATTACH;
    let mut captured = None;
    let result = store.up_private_root_bound(&request, &spec, |prepared| {
        // This must fail while binding is captured. A post-return callback would allow reset
        // to replace the generation between local startup and parent identity publication.
        assert!(matches!(store.reset("private"), Err(Error::Busy(_))));
        let mut foreign = binding.clone();
        foreign.spec.parent_network_id = prepared.context.network_id.parse().unwrap();
        assert!(
            retain_prepared_context(&store, "private", &directory, &mut foreign, prepared).is_err()
        );
        assert!(read_binding(&directory).unwrap().context.is_none());
        let mut substituted = binding.clone();
        let mut other_context = prepared.context.clone();
        other_context.account_id.push('x');
        substituted.context = Some(other_context);
        assert!(
            retain_prepared_context(&store, "private", &directory, &mut substituted, prepared)
                .is_err()
        );
        assert!(read_binding(&directory).unwrap().context.is_none());
        retain_prepared_activation(
            &store,
            "private",
            &directory,
            &mut binding,
            prepared,
            original_deadline,
        )?;
        assert!(
            directory
                .open_existing_lock("request.lock")?
                .try_lock()
                .is_err(),
            "activation publication must not release request serialization",
        );
        assert!(!network.path().join(STATUS).exists());
        assert!(!network.path().join(WORKER).exists());
        // A Ready-triggered worker reads this same function before its request-lock
        // acquisition. It must already have the foreground budget, not RELAY_TURN.
        let worker_deadline = attachment_turn_deadline(&directory).unwrap();
        assert!(worker_deadline > Instant::now() + RELAY_TURN);
        assert!(worker_deadline <= original_deadline + Duration::from_millis(2));
        captured = Some(prepared.clone());
        Ok(())
    });
    assert!(matches!(result, Err(Error::Timeout(timeout)) if timeout == request.startup_timeout));
    let prepared = captured.expect("binding must precede the original-budget worker-start failure");
    drop(request_gate);
    assert_eq!(
        prepared, original,
        "retry must retain the published generation"
    );
    assert_eq!(store.prepared("private").unwrap(), prepared);
    let failure = "startup readiness deadline expired while submitting and confirming the single readiness transaction";
    store
        .directory("private")
        .unwrap()
        .write_atomic(
            STATUS,
            &encode(&ManagedStatus {
                context: prepared.context.clone(),
                phase: ManagedPhase::Failed,
                running_peers: 0,
                failure: Some(failure.into()),
            })
            .unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    retain_prepared_context(&store, "private", &directory, &mut binding, &prepared).unwrap();
    let status = store.dataspace_status("private").unwrap().unwrap();
    assert_eq!(status.local.phase, ManagedPhase::Failed);
    assert_eq!(status.local.running_peers, 0);
    assert_eq!(status.local.failure.as_deref(), Some(failure));
    assert!(status.attachment.parent_confirmed.is_none());
    assert!(status.attachment.local_successor.is_none());
    assert!(directory.path().join(ACTIVATION).exists());
    store.reset("private").unwrap();
    assert!(
        retain_prepared_context(&store, "private", &directory, &mut binding, &prepared).is_err()
    );
    assert_eq!(
        read_binding(&directory).unwrap().context,
        Some(prepared.context)
    );
}

#[test]
fn deadlines_and_unobserved_status_do_not_claim_parent_finality() {
    assert!(remaining(Instant::now()).is_err());
    assert!(remaining(Instant::now() + Duration::from_secs(1)).unwrap() <= Duration::from_secs(1));
    assert!(now_ms().unwrap() > 0);
    let initial = connecting("fixture".into());
    assert_eq!(initial.stage, ManagedAttachmentPhase::Connecting);
    assert!(initial.local_successor.is_none());
    assert!(initial.parent_confirmed.is_none());
    let temporary = tempfile::tempdir().unwrap();
    let release = temporary.path().join("release");
    assert!(
        authenticate_parent(
            &release,
            &profile(84, 1, "https://fixture.example/checkpoint"),
            Instant::now(),
            false,
        )
        .is_err()
    );
    assert!(!release.exists());
}

#[test]
fn attachment_turn_budget_uses_activation_and_bounds_background_retries() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("attachment")).unwrap();
    for activation in [None, Some(0)] {
        if let Some(deadline_ms) = activation {
            directory
                .write_atomic(
                    ACTIVATION,
                    &encode(&Activation { deadline_ms }).unwrap(),
                    PublishMode::Replace,
                )
                .unwrap();
        }
        let before = Instant::now();
        let deadline = attachment_turn_deadline(&directory).unwrap();
        assert!(deadline >= before + RELAY_TURN);
        assert!(deadline <= Instant::now() + RELAY_TURN);
    }
    directory
        .write_atomic(
            ACTIVATION,
            &encode(&Activation {
                deadline_ms: now_ms().unwrap() + 10 * MAX_ATTACH.as_millis() as u64,
            })
            .unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    let before = Instant::now();
    let bounded = attachment_turn_deadline(&directory).unwrap();
    assert!(bounded >= before + MAX_ATTACH);
    assert!(bounded <= Instant::now() + MAX_ATTACH);
    directory
        .write_atomic(ACTIVATION, b"invalid activation", PublishMode::Replace)
        .unwrap();
    assert!(attachment_turn_deadline(&directory).is_err());
}

#[test]
fn terminated_attachment_owner_cannot_keep_advertising_attached() {
    let status = Arc::new(Mutex::new(connecting("fixture".into())));
    status.lock().unwrap().stage = ManagedAttachmentPhase::Attached;
    let thread = thread::spawn(|| {});
    while !thread.is_finished() {
        thread::yield_now();
    }
    let worker = AttachmentWorker { status, thread };
    assert!(worker.is_finished());
    assert_eq!(worker.status().stage, ManagedAttachmentPhase::Unavailable);
    assert!(worker.status().failure.is_some());
}

#[test]
fn release_lock_contention_exhausts_the_original_deadline_without_http() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("release");
    let owner = ReleaseCheckpointStore::open(&path).unwrap();
    let deadline = Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        authenticate_parent(
            &path,
            &profile(85, 1, "https://fixture.example/checkpoint"),
            deadline,
            false,
        ),
        Err(Error::ParentDeadline)
    ));
    assert!(Instant::now() >= deadline);
    drop(owner);
    ReleaseCheckpointStore::open(&path).unwrap();
}

#[test]
fn failure_keeps_retained_operation_stage_and_foreground_deadline_diagnostic() {
    let mut public = connecting("fixture".into());
    record_provisioning_progress(
        &mut public,
        ProvisioningProgress {
            stage: ProvisioningStage::Funding,
            wallet_status: None,
            confirmed: None,
        },
        false,
    );
    public.failure = Some(ManagedAttachmentFailure::PreparationFailed);
    let error = attachment_deadline(&public);
    assert!(matches!(
        error,
        Error::ParentProgressDeadline {
            stage: ManagedAttachmentPhase::Funding,
            failure: ManagedAttachmentFailure::PreparationFailed,
        }
    ));
    assert!(
        error
            .to_string()
            .contains("during funding: operation preparation failed")
    );
    // One turn can finish funding before failing to prepare the namespace. The owner's next
    // retained stage wins; neither failure advances local readiness or creates a receipt.
    record_provisioning_progress(
        &mut public,
        ProvisioningProgress {
            stage: ProvisioningStage::Namespace,
            wallet_status: None,
            confirmed: None,
        },
        false,
    );
    assert!(matches!(
        attachment_deadline(&public),
        Error::ParentProgressDeadline {
            stage: ManagedAttachmentPhase::Namespace,
            failure: ManagedAttachmentFailure::PreparationFailed,
        }
    ));
    assert!(public.parent_confirmed.is_none());
    assert!(public.local_successor.is_none());
    let encoded = encode(&public).unwrap();
    assert_eq!(decode::<ManagedAttachmentStatus>(&encoded).unwrap(), public);
}

#[test]
fn successful_pending_turn_clears_failure_without_fabricating_parent_completion() {
    let mut public = connecting("fixture".into());
    public.failure = Some(ManagedAttachmentFailure::RecoveryFailed);
    let historical = ManagedConfirmedAnchor {
        parent_height: 13,
        child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
            height: 2,
            consensus_hash: [1; 32],
            result: [2; 32],
        },
    };
    public.parent_confirmed = Some(historical);
    record_provisioning_progress(
        &mut public,
        ProvisioningProgress {
            stage: ProvisioningStage::Registering,
            wallet_status: Some(iroha_wallet::operations::OperationStatus::Pending),
            confirmed: None,
        },
        true,
    );
    assert_eq!(public.stage, ManagedAttachmentPhase::Registering);
    assert_eq!(public.wallet_status.as_deref(), Some("Pending"));
    assert_eq!(public.parent_confirmed, Some(historical));
    assert!(public.failure.is_none());
    assert!(matches!(
        attachment_deadline(&public),
        Error::ParentProgressDeadline {
            stage: ManagedAttachmentPhase::Registering,
            failure: ManagedAttachmentFailure::AwaitingCompletion,
        }
    ));
}

#[test]
fn relay_wallet_status_reports_terminal_operations_without_retry_or_false_completion() {
    for (wallet_status, failure) in [
        (
            OperationStatus::Expired,
            Some(ManagedAttachmentFailure::OperationExpired),
        ),
        (
            OperationStatus::Rejected,
            Some(ManagedAttachmentFailure::OperationRejected),
        ),
        (OperationStatus::Pending, None),
        (OperationStatus::Applied, None),
    ] {
        let mut public = connecting("fixture".into());
        public.stage = ManagedAttachmentPhase::Registering;
        public.failure = Some(ManagedAttachmentFailure::RecoveryFailed);
        record_relay_progress(
            &mut public,
            RelayProgress {
                local_successor: None,
                parent: crate::attachment::AttachmentProgress {
                    transaction_status: Some(wallet_status),
                    confirmed: None,
                    pending: true,
                },
            },
        );
        assert_eq!(public.stage, ManagedAttachmentPhase::Registering);
        assert_eq!(
            public.wallet_status.as_deref(),
            Some(wallet_status.as_str())
        );
        assert_eq!(public.failure, failure);
        assert!(public.parent_confirmed.is_none());
        let error = terminal_operation_error(&public);
        assert_eq!(error.is_some(), failure.is_some());
        if let Some(error) = error {
            assert!(matches!(error, Error::Invalid(_)));
            assert!(
                error
                    .to_string()
                    .contains("parent attachment cannot complete")
            );
            assert!(!error.to_string().contains("retry"));
            record_provisioning_progress(
                &mut public,
                ProvisioningProgress {
                    stage: ProvisioningStage::Registering,
                    wallet_status: None,
                    confirmed: None,
                },
                true,
            );
            assert_eq!(
                public.wallet_status.as_deref(),
                Some(wallet_status.as_str())
            );
            assert_eq!(public.failure, failure);
        }
        assert_eq!(
            decode::<ManagedAttachmentStatus>(&encode(&public).unwrap()).unwrap(),
            public,
        );
    }
}

#[test]
fn terminal_provisioning_observations_keep_the_exact_funding_or_namespace_stage() {
    for stage in [ProvisioningStage::Funding, ProvisioningStage::Namespace] {
        for (wallet_status, failure) in [
            (
                OperationStatus::Expired,
                ManagedAttachmentFailure::OperationExpired,
            ),
            (
                OperationStatus::Rejected,
                ManagedAttachmentFailure::OperationRejected,
            ),
        ] {
            let mut public = connecting("fixture".into());
            record_provisioning_progress(
                &mut public,
                ProvisioningProgress {
                    stage,
                    wallet_status: Some(wallet_status),
                    confirmed: None,
                },
                true,
            );
            assert_eq!(public.stage.as_str(), stage.as_str());
            assert_eq!(public.failure, Some(failure));
            assert_eq!(
                public.wallet_status.as_deref(),
                Some(wallet_status.as_str())
            );
            assert!(terminal_operation_error(&public).is_some());
            assert!(public.parent_confirmed.is_none());
        }
    }
}

#[test]
fn terminal_anchor_keeps_historical_receipt_without_advertising_attached() {
    let confirmed = crate::attachment::ConfirmedAnchor {
        parent_height: 13,
        child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
            height: 2,
            consensus_hash: [1; 32],
            result: [2; 32],
        },
    };
    let mut public = connecting("fixture".into());
    public.stage = ManagedAttachmentPhase::Anchoring;
    record_relay_progress(
        &mut public,
        RelayProgress {
            local_successor: None,
            parent: crate::attachment::AttachmentProgress {
                transaction_status: Some(OperationStatus::Expired),
                confirmed: Some(confirmed),
                pending: true,
            },
        },
    );
    assert_eq!(public.stage, ManagedAttachmentPhase::Anchoring);
    assert_eq!(public.parent_confirmed.unwrap().parent_height, 13);
    assert_eq!(
        public.failure,
        Some(ManagedAttachmentFailure::OperationExpired)
    );
    record_provisioning_progress(
        &mut public,
        ProvisioningProgress {
            stage: ProvisioningStage::Attached,
            wallet_status: None,
            confirmed: Some(confirmed),
        },
        true,
    );
    assert_eq!(public.stage, ManagedAttachmentPhase::Anchoring);
    assert_eq!(public.wallet_status.as_deref(), Some("Expired"));
    assert_eq!(public.parent_confirmed.unwrap().child, confirmed.child);
    assert_eq!(
        public.failure,
        Some(ManagedAttachmentFailure::OperationExpired)
    );
    assert!(terminal_operation_error(&public).is_some());
}

#[test]
fn failed_later_relay_reports_anchoring_and_keeps_original_registration_receipt() {
    let mut public = connecting("fixture".into());
    let confirmed = crate::attachment::ConfirmedAnchor {
        parent_height: 13,
        child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
            height: 2,
            consensus_hash: [1; 32],
            result: [2; 32],
        },
    };
    record_provisioning_progress(
        &mut public,
        ProvisioningProgress {
            stage: ProvisioningStage::Attached,
            wallet_status: None,
            confirmed: Some(confirmed),
        },
        true,
    );
    // Initial registration already exists, but neither a historical receipt nor entering a
    // new turn establishes fresh parent readiness or confirms a newer child certificate.
    assert_eq!(public.stage, ManagedAttachmentPhase::Anchoring);
    assert!(public.failure.is_none());
    let original = public.parent_confirmed;
    assert_eq!(original.unwrap().parent_height, 13);
    public.failure = Some(ManagedAttachmentFailure::ParentUnavailable);
    assert_eq!(public.stage.as_str(), "anchoring");
    assert_eq!(public.parent_confirmed, original);
    assert!(public.local_successor.is_none());
    let error = attachment_deadline(&public);
    assert!(matches!(
        error,
        Error::ParentProgressDeadline {
            stage: ManagedAttachmentPhase::Anchoring,
            failure: ManagedAttachmentFailure::ParentUnavailable,
        }
    ));
    assert!(
        error
            .to_string()
            .contains("during anchoring: fresh parent observation is unavailable")
    );
    assert_eq!(
        decode::<ManagedAttachmentStatus>(&encode(&public).unwrap()).unwrap(),
        public
    );
}

#[test]
fn attachment_outer_optional_keeps_initial_absence_named_identity_and_invalid_names() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    assert!(existing_outer(&store, "local").unwrap().is_none());
    assert!(!store.root().join("attachments").exists());
    assert!(matches!(
        existing_outer(&store, "../escape"),
        Err(Error::Invalid(_))
    ));
    assert!(!store.root().join("attachments").exists());

    let root = PrivateDirectory::open(store.root()).unwrap();
    let attachments = root.create_child("attachments").unwrap();
    assert!(store.attachments_directory().unwrap().is_some());
    assert!(existing_outer(&store, "local").unwrap().is_none());
    assert!(attachments.entries(1).unwrap().is_empty());
    let original = attachments.create_child("local").unwrap();
    original
        .write_atomic("evidence", b"original attachment", PublishMode::CreateNew)
        .unwrap();
    let found = existing_outer(&store, "local").unwrap().unwrap();
    assert_eq!(found.identity().unwrap(), original.identity().unwrap());
    assert_eq!(
        found.read("evidence", 19).unwrap().as_slice(),
        b"original attachment"
    );
    assert!(existing_outer(&store, "missing").unwrap().is_none());
    assert_eq!(
        attachments.entries(1).unwrap(),
        [std::ffi::OsString::from("local")]
    );
}

#[cfg(unix)]
#[test]
fn attachment_outer_optional_refuses_lost_replaced_store_root_and_restores_original() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let root = store.root().to_path_buf();
    let attachments = PrivateDirectory::open(&root)
        .unwrap()
        .create_child("attachments")
        .unwrap();
    let original = attachments.create_child("local").unwrap();
    original
        .write_atomic("evidence", b"original attachment", PublishMode::CreateNew)
        .unwrap();
    let identity = original.identity().unwrap();
    let displaced = temporary.path().join("original-root");

    std::fs::rename(&root, &displaced).unwrap();
    let lost = existing_outer(&store, "missing");
    let invalid = existing_outer(&store, "../escape");
    std::fs::rename(&displaced, &root).unwrap();
    assert!(matches!(lost, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound));
    assert!(matches!(invalid, Err(Error::Invalid(_))));
    assert!(existing_outer(&store, "missing").unwrap().is_none());
    assert_eq!(
        existing_outer(&store, "local")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap(),
        identity
    );

    std::fs::rename(&root, &displaced).unwrap();
    let replacement = PrivateDirectory::open_or_create(&root).unwrap();
    let changed = existing_outer(&store, "missing");
    assert!(replacement.entries(0).unwrap().is_empty());
    drop(replacement);
    std::fs::remove_dir(&root).unwrap();
    std::fs::rename(&displaced, &root).unwrap();
    assert!(matches!(changed, Err(Error::Io(_))));
    let restored = existing_outer(&store, "local").unwrap().unwrap();
    assert_eq!(restored.identity().unwrap(), identity);
    assert_eq!(
        restored.read("evidence", 19).unwrap().as_slice(),
        b"original attachment"
    );
    assert!(existing_outer(&store, "missing").unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn attachment_outer_optional_refuses_lost_replaced_admitted_parent_and_restores_original() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let root = PrivateDirectory::open(store.root()).unwrap();
    let attachments = root.create_child("attachments").unwrap();
    let original = attachments.create_child("local").unwrap();
    original
        .write_atomic("evidence", b"original attachment", PublishMode::CreateNew)
        .unwrap();
    let identity = original.identity().unwrap();
    let admitted = store.attachments_directory().unwrap().unwrap();
    let displaced = temporary.path().join("original-attachments");

    std::fs::rename(attachments.path(), &displaced).unwrap();
    let lost = admitted.open_child_optional("missing");
    // A fresh first-open absence is still optional; an already admitted parent is not absent.
    assert!(existing_outer(&store, "missing").unwrap().is_none());
    std::fs::rename(&displaced, attachments.path()).unwrap();
    assert!(matches!(lost, Err(error) if error.kind() == std::io::ErrorKind::NotFound));
    assert!(admitted.open_child_optional("missing").unwrap().is_none());

    std::fs::rename(attachments.path(), &displaced).unwrap();
    let replacement = root.create_child("attachments").unwrap();
    let changed = admitted.open_child_optional("missing");
    assert!(replacement.entries(0).unwrap().is_empty());
    drop(replacement);
    std::fs::remove_dir(attachments.path()).unwrap();
    std::fs::rename(&displaced, attachments.path()).unwrap();
    assert!(
        changed.is_err(),
        "replaced admitted attachments must remain an error"
    );
    let restored = existing_outer(&store, "local").unwrap().unwrap();
    assert_eq!(restored.identity().unwrap(), identity);
    assert_eq!(
        restored.read("evidence", 19).unwrap().as_slice(),
        b"original attachment"
    );
    assert!(admitted.open_child_optional("missing").unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn attachment_outer_optional_refuses_public_container_permissions_without_repair() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let attachments = PrivateDirectory::open(store.root())
        .unwrap()
        .create_child("attachments")
        .unwrap();
    let original = std::fs::metadata(attachments.path()).unwrap().permissions();
    std::fs::set_permissions(attachments.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = existing_outer(&store, "missing");
    let unchanged = std::fs::metadata(attachments.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    std::fs::set_permissions(attachments.path(), original).unwrap();
    assert!(
        matches!(refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(unchanged, 0o755);
    assert!(existing_outer(&store, "missing").unwrap().is_none());
    assert!(attachments.entries(0).unwrap().is_empty());
}

#[cfg(windows)]
#[test]
fn attachment_outer_optional_keeps_native_rename_refusal_and_original_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let root = PrivateDirectory::open(store.root()).unwrap();
    let attachments = root.create_child("attachments").unwrap();
    let original = attachments.create_child("local").unwrap();
    original
        .write_atomic("evidence", b"original attachment", PublishMode::CreateNew)
        .unwrap();
    let identity = original.identity().unwrap();
    let admitted = store.attachments_directory().unwrap().unwrap();
    assert!(std::fs::rename(store.root(), temporary.path().join("moved-root")).is_err());
    assert!(
        std::fs::rename(
            attachments.path(),
            temporary.path().join("moved-attachments")
        )
        .is_err()
    );
    assert!(existing_outer(&store, "missing").unwrap().is_none());
    assert!(admitted.open_child_optional("missing").unwrap().is_none());
    let found = existing_outer(&store, "local").unwrap().unwrap();
    assert_eq!(found.identity().unwrap(), identity);
    assert_eq!(
        found.read("evidence", 19).unwrap().as_slice(),
        b"original attachment"
    );
    assert_eq!(
        attachments.entries(1).unwrap(),
        [std::ffi::OsString::from("local")]
    );
}

#[test]
fn attachment_publication_validates_name_before_creation_and_keeps_exact_files() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    assert!(existing_outer(&store, "private").unwrap().is_none());
    for name in ["../escape", "", "invalid name"] {
        let refused = store.publish_attachment(name, &[("request.lock", b"")]);
        assert!(matches!(refused, Err(Error::Invalid(_))));
    }
    assert!(!store.root().join("attachments").exists());
    let binding = Binding {
        profile: ProfileBinding::from_profile(&profile(
            91,
            1,
            "https://fixture.example/checkpoint",
        )),
        spec: super::super::tests::private_spec(),
        account_alias: "admin".into(),
        context: None,
    };
    let bytes = encode(&binding).unwrap();
    let original = store
        .publish_attachment("private", &[("request.lock", b""), (BINDING, &bytes)])
        .unwrap();
    let directory_identity = original.identity().unwrap();
    let binding_identity =
        iroha_fs::FileIdentity::of(&original.open_read(BINDING).unwrap()).unwrap();
    let lock_identity =
        iroha_fs::FileIdentity::of(&original.open_read("request.lock").unwrap()).unwrap();
    let found = existing_outer(&store, "private").unwrap().unwrap();
    assert_eq!(found.identity().unwrap(), directory_identity);
    assert_eq!(found.read(BINDING, MAX_METADATA).unwrap().as_slice(), bytes);
    assert_eq!(read_binding(&found).unwrap().spec, binding.spec);
    let refused = store.publish_attachment("private", &[(BINDING, b"replacement")]);
    assert!(
        matches!(refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(original.identity().unwrap(), directory_identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&found.open_read(BINDING).unwrap()).unwrap(),
        binding_identity
    );
    assert_eq!(
        iroha_fs::FileIdentity::of(&found.open_read("request.lock").unwrap()).unwrap(),
        lock_identity
    );
    assert_eq!(found.read(BINDING, MAX_METADATA).unwrap().as_slice(), bytes);
    assert!(found.read("request.lock", 0).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn attachment_publication_refuses_root_replacement_after_absence_and_restores_original() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let retained_root = PrivateDirectory::open(store.root()).unwrap();
    let root_identity = retained_root.identity().unwrap();
    assert!(existing_outer(&store, "private").unwrap().is_none());
    let displaced = temporary.path().join("original-root");
    std::fs::rename(store.root(), &displaced).unwrap();
    let missing = store.publish_attachment("private", &[("request.lock", b"")]);
    assert!(
        matches!(missing, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    let replacement = PrivateDirectory::open_or_create(store.root()).unwrap();
    let invalid = store.publish_attachment("../escape", &[("request.lock", b"")]);
    assert!(matches!(invalid, Err(Error::Invalid(_))));
    let refused = store.publish_attachment(
        "private",
        &[("request.lock", b""), (BINDING, b"original binding")],
    );
    assert!(matches!(refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::Other));
    assert!(replacement.entries(0).unwrap().is_empty());
    drop(replacement);
    std::fs::remove_dir(store.root()).unwrap();
    std::fs::rename(displaced, store.root()).unwrap();
    assert_eq!(retained_root.identity().unwrap(), root_identity);
    assert!(existing_outer(&store, "private").unwrap().is_none());
    let original = store
        .publish_attachment(
            "private",
            &[("request.lock", b""), (BINDING, b"original binding")],
        )
        .unwrap();
    let identity = original.identity().unwrap();
    let binding_identity =
        iroha_fs::FileIdentity::of(&original.open_read(BINDING).unwrap()).unwrap();
    let found = existing_outer(&store, "private").unwrap().unwrap();
    assert_eq!(found.identity().unwrap(), identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&found.open_read(BINDING).unwrap()).unwrap(),
        binding_identity
    );
    assert_eq!(
        found.read(BINDING, MAX_METADATA).unwrap().as_slice(),
        b"original binding"
    );
    assert!(found.read("request.lock", 0).unwrap().is_empty());
    assert!(
        matches!(store.publish_attachment("private", &[(BINDING, b"replacement")]), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(found.identity().unwrap(), identity);
    assert_eq!(
        found.read(BINDING, MAX_METADATA).unwrap().as_slice(),
        b"original binding"
    );
}

#[cfg(unix)]
#[test]
fn attachment_publication_refuses_public_container_without_repair_and_retries_original() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let attachments = PrivateDirectory::open(store.root())
        .unwrap()
        .create_child("attachments")
        .unwrap();
    let identity = attachments.identity().unwrap();
    let original_permissions = std::fs::metadata(attachments.path()).unwrap().permissions();
    std::fs::set_permissions(attachments.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = store.publish_attachment(
        "private",
        &[("request.lock", b""), (BINDING, b"original binding")],
    );
    assert!(
        matches!(refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        std::fs::metadata(attachments.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(std::fs::read_dir(attachments.path()).unwrap().count(), 0);
    std::fs::set_permissions(attachments.path(), original_permissions).unwrap();
    assert_eq!(attachments.identity().unwrap(), identity);
    let original = store
        .publish_attachment(
            "private",
            &[("request.lock", b""), (BINDING, b"original binding")],
        )
        .unwrap();
    assert_eq!(
        existing_outer(&store, "private")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap(),
        original.identity().unwrap()
    );
    assert_eq!(
        original.read(BINDING, MAX_METADATA).unwrap().as_slice(),
        b"original binding"
    );
    assert!(original.read("request.lock", 0).unwrap().is_empty());
}

#[test]
fn attached_reply_after_foreground_deadline_refuses_without_changing_receipt() {
    let mut status = connecting("fixture".into());
    status.stage = ManagedAttachmentPhase::Attached;
    status.wallet_status = Some(OperationStatus::Applied.as_str().into());
    status.parent_confirmed = Some(ManagedConfirmedAnchor {
        parent_height: 13,
        child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
            height: 2,
            consensus_hash: [1; 32],
            result: [2; 32],
        },
    });
    let original = status.clone();
    // This is the production decision after blocking IPC: even exact Attached evidence
    // cannot turn a reply after the caller's original cutoff into foreground success.
    let elapsed = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        attachment_complete(&status, elapsed),
        Err(Error::ParentProgressDeadline {
            stage: ManagedAttachmentPhase::Attached,
            failure: ManagedAttachmentFailure::AwaitingCompletion,
        })
    ));
    assert_eq!(status, original);
    assert!(attachment_complete(&status, Instant::now() + MAX_ATTACH).unwrap());
    assert_eq!(status, original);
}

#[test]
fn attached_reply_preserves_terminal_failure_priority_and_exact_completion_gate() {
    let mut status = connecting("fixture".into());
    status.stage = ManagedAttachmentPhase::Attached;
    status.parent_confirmed = Some(ManagedConfirmedAnchor {
        parent_height: 13,
        child: iroha_data_model::private_dataspace::PrivateDataspaceCursor {
            height: 2,
            consensus_hash: [1; 32],
            result: [2; 32],
        },
    });
    let elapsed = Instant::now() - Duration::from_secs(1);
    for failure in [
        ManagedAttachmentFailure::OperationExpired,
        ManagedAttachmentFailure::OperationRejected,
    ] {
        status.failure = Some(failure);
        let expected = terminal_operation_error(&status).unwrap().to_string();
        let original = status.clone();
        let error = attachment_complete(&status, elapsed).unwrap_err();
        assert!(matches!(&error, Error::Invalid(_)));
        assert_eq!(error.to_string(), expected);
        assert_eq!(status, original);
    }
    status.failure = Some(ManagedAttachmentFailure::ParentUnavailable);
    assert!(!attachment_complete(&status, elapsed).unwrap());
    status.failure = None;
    let confirmed = status.parent_confirmed.take();
    assert!(!attachment_complete(&status, elapsed).unwrap());
    status.parent_confirmed = confirmed;
    status.stage = ManagedAttachmentPhase::Anchoring;
    assert!(!attachment_complete(&status, elapsed).unwrap());
    status.stage = ManagedAttachmentPhase::Attached;
    assert!(attachment_complete(&status, Instant::now() + MAX_ATTACH).unwrap());
}

#[test]
fn attachment_join_waits_for_the_original_relay_thread_and_returns_its_panic() {
    for panic in [false, true] {
        let (release, held) = std::sync::mpsc::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = Arc::clone(&completed);
        let task = AttachmentWorker {
            status: Arc::new(Mutex::new(connecting("test-parent".into()))),
            thread: thread::spawn(move || {
                held.recv_timeout(Duration::from_secs(10)).unwrap();
                task_completed.store(true, Ordering::Release);
                assert!(!panic, "controlled relay panic");
            }),
        };
        assert!(!task.is_finished());
        let joiner = thread::spawn(move || task.join());
        assert!(!joiner.is_finished());
        assert!(!completed.load(Ordering::Acquire));
        release.send(()).unwrap();
        let result = joiner.join().unwrap();
        assert!(completed.load(Ordering::Acquire));
        if panic {
            assert!(
                matches!(result, Err(Error::Invalid(message)) if message == "owned parent attachment task panicked")
            );
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn cancelled_relay_turn_refuses_before_runtime_discovery_or_new_custody() {
    let _guard = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, prepared) =
        super::super::tests::fixture(&temporary.path().join("managed"), "local");
    let binding = Binding {
        profile: ProfileBinding::from_profile(&profile(
            87,
            1,
            "https://fixture.example/checkpoint",
        )),
        spec: super::super::tests::private_spec(),
        account_alias: "admin".into(),
        context: None,
    };
    let cancelled = Arc::new(AtomicBool::new(true));
    let status = Mutex::new(connecting("fixture".into()));
    let mut service = None;
    assert!(matches!(
        relay_turn(
            &directory,
            &temporary.path().join("missing-release"),
            &binding,
            &prepared,
            &mut service,
            &status,
            RelayControl {
                refresh: false,
                cancelled: &cancelled
            }
        ),
        Err(ManagedAttachmentFailure::SupervisorStopped)
    ));
    assert!(service.is_none());
    assert!(!directory.path().join("provisioning").exists());
    assert!(!temporary.path().join("missing-release").exists());
    assert_eq!(
        status.lock().unwrap().stage,
        ManagedAttachmentPhase::Connecting
    );
}

#[test]
fn administrative_amx_managed_busy_is_before_origin_signing_and_source_repair() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let selected = profile(81, 4, "https://fixture.example/checkpoint");
    let runtime = runtime(
        &temporary.path().join("installed"),
        InstalledNetworkProfiles::new(vec![selected.clone()]).unwrap(),
    );
    let directory = store
        .publish_attachment(
            "private",
            &[("request.lock", b""), ("unchanged", b"original source")],
        )
        .unwrap();
    let network = PrivateDirectory::open(store.root())
        .unwrap()
        .open_child("networks")
        .unwrap()
        .create_child("private")
        .unwrap();
    let key = KeyPair::from_seed(vec![155; 32], Algorithm::Ed25519);
    let configuration = iroha::config::Config::load_table(
        "admin-fixture.toml",
        toml::toml! {
            chain = "fixture"
            network_id = (super::super::tests::private_spec().parent_network_id.to_string())
            torii_url = "https://fixture.example/"
            [account]
            chain_discriminant = 753
            public_key = (key.public_key().to_string())
            private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
        },
    )
    .unwrap();
    let options = ManagedAmxRegistrationOptions {
        fee_asset: iroha_wallet::operations::XOR_ASSET_DEFINITION
            .parse()
            .unwrap(),
        max_fee: iroha_primitives::numeric::Quantity::from(1_u32),
        deadline_unix_ms: now_ms().unwrap() + 60_000,
        timeout: Duration::from_secs(1),
    };
    // The runtime lease is the existing inactive-generation boundary; it is never bypassed.
    let lease = store::acquire(&network, "runtime.lock", "private").unwrap();
    assert!(
        matches!(store.register_amx_dataspace(&runtime, "private", &configuration, &options), Err(Error::Busy(name)) if name == "private")
    );
    assert_eq!(
        directory
            .read("unchanged", MAX_METADATA)
            .unwrap()
            .as_slice(),
        b"original source"
    );
    assert!(!directory.path().join("provisioning").exists());
    assert!(!directory.path().join("amx-registration").exists());
    assert!(!release_path(&store, "private").exists());
    drop(lease);
    // Releasing the real runtime lease does not manufacture a missing original binding.
    assert!(
        store
            .register_amx_dataspace(&runtime, "private", &configuration, &options)
            .is_err()
    );
    assert_eq!(
        directory
            .read("unchanged", MAX_METADATA)
            .unwrap()
            .as_slice(),
        b"original source"
    );
    assert!(!directory.path().join("amx-registration").exists());
}
