#[test]
fn moderation_delivery_bindings_backends_and_startup_identity_are_exact() {
    use test_moderation::ModerationTerminalHandoffKindV1 as Kind;
    for slot in [
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotification,
    ] {
        let catalog = delivery_catalog(slot);
        let binding = catalog
            .iter()
            .next()
            .map(ProviderBindingWireV1::try_from_binding)
            .transpose()
            .expect("project moderation delivery binding")
            .expect("moderation delivery binding");
        validate_wire_binding(&binding).expect("accept exact plain moderation delivery binding");
        assert!(
            binding.native_signer_binding.is_none(),
            "moderation delivery boundaries reject native signer aliases"
        );
        assert!(matches!(
            prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
            Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
        ));
        match slot {
            IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff => {
                prepare_test_server_state(
                    &catalog,
                    RuntimeProviderBrokerBackendsV1::new().with_moderation_settlement_handoff(
                        Arc::new(ServerTestModerationHandoffBoundary::exact(Kind::Settlement)),
                    ),
                )
                .expect("accept exact settlement handoff boundary");
            }
            IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff => {
                prepare_test_server_state(
                    &catalog,
                    RuntimeProviderBrokerBackendsV1::new().with_moderation_publication_handoff(
                        Arc::new(ServerTestModerationHandoffBoundary::exact(
                            Kind::Publication,
                        )),
                    ),
                )
                .expect("accept exact publication handoff boundary");
            }
            IrohaRuntimeProviderSlotV1::ModerationPanelNotification => {
                prepare_test_server_state(
                    &catalog,
                    RuntimeProviderBrokerBackendsV1::new().with_moderation_panel_notification(
                        Arc::new(ServerTestModerationPanelBoundary::exact()),
                    ),
                )
                .expect("accept exact panel-notification boundary");
            }
            _ => unreachable!(),
        }
    }
    let settlement_catalog =
        delivery_catalog(IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff);
    assert!(matches!(
        prepare_test_server_state(
            &settlement_catalog,
            RuntimeProviderBrokerBackendsV1::new().with_moderation_publication_handoff(Arc::new(
                ServerTestModerationHandoffBoundary::exact(Kind::Publication),
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    for boundary in [
        ServerTestModerationHandoffBoundary::exact(Kind::Settlement)
            .with_handle("queue://moderation/settlement-handoff-substituted"),
        ServerTestModerationHandoffBoundary::exact(Kind::Settlement)
            .with_mode(ServerTestModerationDeliveryMode::DriftOnSecondQualification),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &settlement_catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_moderation_settlement_handoff(Arc::new(boundary)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    let panel_catalog = delivery_catalog(IrohaRuntimeProviderSlotV1::ModerationPanelNotification);
    for boundary in [
        ServerTestModerationPanelBoundary::exact()
            .with_handle("queue://moderation/panel-notification-substituted"),
        ServerTestModerationPanelBoundary::exact()
            .with_mode(ServerTestModerationDeliveryMode::DriftOnSecondQualification),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &panel_catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_moderation_panel_notification(Arc::new(boundary)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    let mut role_confused = settlement_catalog
        .iter()
        .next()
        .map(ProviderBindingWireV1::try_from_binding)
        .transpose()
        .expect("project settlement binding")
        .expect("settlement binding");
    role_confused.native_signer_binding = signer_catalog()
        .iter()
        .next()
        .and_then(IrohaRuntimeProviderBindingV1::native_signer_binding)
        .map(NativeTransactionSignerBindingWireV1::from_binding);
    assert_eq!(
        validate_wire_binding(&role_confused),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn moderation_delivery_hard_cut_rejects_kind_canonical_and_bounds_before_provider() {
    use test_moderation::ModerationTerminalHandoffKindV1 as Kind;
    let handoff_boundary = Arc::new(ServerTestModerationHandoffBoundary::exact(Kind::Settlement));
    let handoff_state = moderation_handoff_state(
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
        handoff_boundary.clone(),
    );
    let handoff_request = moderation_handoff_request(Kind::Settlement);
    let handoff_wire = moderation_handoff_request_to_wire(
        &handoff_request,
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id(),
    )
    .expect("project exact settlement handoff");
    let exact_handoff = moderation_delivery_request(
        &handoff_state,
        1,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
        encode_canonical(&handoff_wire, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)
            .expect("encode exact settlement handoff"),
    );
    validate_operation_request(&exact_handoff).expect("accept exact canonical settlement handoff");
    let publication_state = moderation_handoff_state(
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        Arc::new(ServerTestModerationHandoffBoundary::exact(
            Kind::Publication,
        )),
    );
    let wrong_kind = moderation_delivery_request(
        &publication_state,
        2,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
        encode_canonical(&handoff_wire, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)
            .expect("encode kind-confused handoff"),
    );
    assert_eq!(
        validate_operation_request(&wrong_kind),
        Err(BrokerError::Rejected)
    );
    let mut invalid_handoffs = Vec::new();
    let mut trailing_canonical = handoff_wire.clone();
    trailing_canonical.canonical_handoff.push(0);
    invalid_handoffs.push(trailing_canonical);
    let mut zero_identity = handoff_wire.clone();
    zero_identity.handoff.handoff_id = [0; 32];
    zero_identity.canonical_handoff =
        norito::to_bytes(&zero_identity.handoff).expect("encode zero-id handoff");
    invalid_handoffs.push(zero_identity);
    let mut oversized = handoff_wire.clone();
    oversized.canonical_handoff = vec![0xAA; MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1 + 1];
    invalid_handoffs.push(oversized);
    for (index, invalid) in invalid_handoffs.iter().enumerate() {
        let request = moderation_delivery_request(
            &handoff_state,
            10 + index as u64,
            OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
            encode_canonical(invalid, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)
                .expect("encode invalid handoff frame"),
        );
        assert!(
            validate_operation_request(&request).is_err(),
            "invalid handoff {index} must fail before provider use"
        );
    }
    let mut outer_trailing_payload = exact_handoff.payload.clone();
    outer_trailing_payload.push(0);
    let outer_trailing = moderation_delivery_request(
        &handoff_state,
        19,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
        outer_trailing_payload,
    );
    assert_eq!(
        validate_operation_request(&outer_trailing),
        Err(BrokerError::Protocol)
    );
    assert_eq!(handoff_boundary.delivery_calls.load(Ordering::Relaxed), 0);
    let panel_boundary = Arc::new(ServerTestModerationPanelBoundary::exact());
    let panel_state = moderation_panel_state(panel_boundary.clone());
    let panel_request = moderation_panel_request();
    let panel_wire = moderation_panel_notification_request_to_wire(&panel_request)
        .expect("project exact panel notification");
    let exact_panel = moderation_delivery_request(
        &panel_state,
        20,
        OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
        encode_canonical(
            &panel_wire,
            MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
        )
        .expect("encode exact panel notification"),
    );
    validate_operation_request(&exact_panel).expect("accept exact canonical panel notification");
    let mut invalid_panels = Vec::new();
    let mut trailing_canonical = panel_wire.clone();
    trailing_canonical.canonical_notification.push(0);
    invalid_panels.push(trailing_canonical);
    let mut zero_attempt = panel_wire.clone();
    zero_attempt.attempt = 0;
    invalid_panels.push(zero_attempt);
    let mut exhausted_attempt = panel_wire.clone();
    exhausted_attempt.attempt = exhausted_attempt.attempt_limit + 1;
    invalid_panels.push(exhausted_attempt);
    let mut stale_lease = panel_wire.clone();
    stale_lease.lease_expires_at_unix_ms = stale_lease.notification.source_occurred_at_unix_ms;
    invalid_panels.push(stale_lease);
    let mut oversized = panel_wire;
    oversized.canonical_notification =
        vec![0xBB; MAX_MODERATION_PANEL_NOTIFICATION_CANONICAL_BYTES_V1 + 1];
    invalid_panels.push(oversized);
    for (index, invalid) in invalid_panels.iter().enumerate() {
        let request = moderation_delivery_request(
            &panel_state,
            30 + index as u64,
            OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
            encode_canonical(invalid, MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1)
                .expect("encode invalid panel-notification frame"),
        );
        assert!(
            validate_operation_request(&request).is_err(),
            "invalid panel request {index} must fail before provider use"
        );
    }
    assert_eq!(panel_boundary.delivery_calls.load(Ordering::Relaxed), 0);
}
#[test]
fn moderation_delivery_server_enforces_replay_failures_receipts_and_post_drift() {
    use test_moderation::ModerationTerminalHandoffKindV1 as Kind;
    use test_moderation_runtime::ModerationDurableHandoffRequestV1;
    let handoff_boundary = Arc::new(ServerTestModerationHandoffBoundary::exact(Kind::Settlement));
    let handoff_state = moderation_handoff_state(
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
        handoff_boundary.clone(),
    );
    let handoff_request = moderation_handoff_request(Kind::Settlement);
    let handoff_payload = encode_canonical(
        &moderation_handoff_request_to_wire(
            &handoff_request,
            IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id(),
        )
        .expect("project exact replayable handoff"),
        MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
    )
    .expect("encode exact replayable handoff");
    let first = dispatch_moderation_delivery(
        &handoff_state,
        1,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
        handoff_payload.clone(),
    )
    .expect("deliver settlement handoff");
    let second = dispatch_moderation_delivery(
        &handoff_state,
        2,
        OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
        handoff_payload,
    )
    .expect("replay settlement handoff");
    assert_eq!(
        decode_canonical::<ModerationDurableHandoffOutcomeWireV1>(
            &first,
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("decode delivered outcome")
        .outcome,
        1
    );
    assert_eq!(
        decode_canonical::<ModerationDurableHandoffOutcomeWireV1>(
            &second,
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("decode replay outcome")
        .outcome,
        2
    );
    let mut conflicting_handoff = handoff_request.handoff.clone();
    // Preserve the canonical identity while changing the retained payload so the
    // conflict reaches the durable boundary's exact-byte replay check.
    conflicting_handoff.finalized_cursor.event_index += 1;
    conflicting_handoff.source_event_witness.event_index =
        conflicting_handoff.finalized_cursor.event_index;
    assert_eq!(
        conflicting_handoff.finalized_cursor,
        conflicting_handoff.source_event_witness.cursor()
    );
    assert_eq!(
        conflicting_handoff.handoff_id,
        conflicting_handoff.canonical_id()
    );
    let conflicting_request = ModerationDurableHandoffRequestV1 {
        canonical_handoff: norito::to_bytes(&conflicting_handoff)
            .expect("encode conflicting handoff"),
        handoff: conflicting_handoff,
    };
    assert_ne!(
        conflicting_request.canonical_handoff,
        handoff_request.canonical_handoff
    );
    assert_eq!(
        dispatch_moderation_delivery(
            &handoff_state,
            3,
            OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
            encode_canonical(
                &moderation_handoff_request_to_wire(
                    &conflicting_request,
                    IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id(),
                )
                .expect("project conflicting handoff"),
                MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
            )
            .expect("encode conflicting handoff frame"),
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(handoff_boundary.delivery_calls.load(Ordering::Relaxed), 3);
    for (mode, expected) in [
        (
            ServerTestModerationDeliveryMode::NotDelivered,
            BrokerError::Unavailable,
        ),
        (
            ServerTestModerationDeliveryMode::Ambiguous,
            BrokerError::Ambiguous,
        ),
        (
            ServerTestModerationDeliveryMode::Permanent,
            BrokerError::Rejected,
        ),
        (
            ServerTestModerationDeliveryMode::DriftAfterDelivery,
            BrokerError::Ambiguous,
        ),
    ] {
        let state = moderation_handoff_state(
            IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
            Arc::new(ServerTestModerationHandoffBoundary::exact(Kind::Settlement).with_mode(mode)),
        );
        let payload = encode_canonical(
            &moderation_handoff_request_to_wire(
                &moderation_handoff_request(Kind::Settlement),
                IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id(),
            )
            .expect("project failure-mode handoff"),
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("encode failure-mode handoff");
        assert_eq!(
            dispatch_moderation_delivery(
                &state,
                1,
                OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1,
                payload,
            ),
            Err(expected)
        );
    }
    let panel_boundary = Arc::new(ServerTestModerationPanelBoundary::exact());
    let panel_state = moderation_panel_state(panel_boundary.clone());
    let panel_request = moderation_panel_request();
    let panel_payload = encode_canonical(
        &moderation_panel_notification_request_to_wire(&panel_request)
            .expect("project replayable panel notification"),
        MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
    )
    .expect("encode replayable panel notification");
    let first = dispatch_moderation_delivery(
        &panel_state,
        10,
        OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
        panel_payload.clone(),
    )
    .expect("deliver panel notification");
    let second = dispatch_moderation_delivery(
        &panel_state,
        11,
        OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
        panel_payload,
    )
    .expect("replay panel notification");
    let first = decode_canonical::<ModerationPanelNotificationReceiptWireV1>(
        &first,
        MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
    )
    .expect("decode panel receipt");
    let second = decode_canonical::<ModerationPanelNotificationReceiptWireV1>(
        &second,
        MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
    )
    .expect("decode replayed panel receipt");
    assert_eq!(first, second);
    assert_eq!(
        first.notification_id,
        panel_request.notification.notification_id
    );
    let mut conflicting_panel = moderation_panel_request();
    conflicting_panel.notification.source_operation_id = [0xA1; 32];
    conflicting_panel.canonical_notification = norito::to_bytes(&conflicting_panel.notification)
        .expect("encode conflicting panel notification");
    assert_eq!(
        dispatch_moderation_delivery(
            &panel_state,
            12,
            OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
            encode_canonical(
                // Inject the conflicting canonical frame directly: the public
                // projector already rejects its inconsistent notification ID.
                &ModerationDurablePanelNotificationRequestWireV1 {
                    notification: conflicting_panel.notification.clone(),
                    canonical_notification: conflicting_panel.canonical_notification.clone(),
                    lease_expires_at_unix_ms: conflicting_panel.lease_expires_at_unix_ms,
                    attempt: conflicting_panel.attempt,
                    attempt_limit: conflicting_panel.attempt_limit,
                },
                MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
            )
            .expect("encode conflicting panel notification frame"),
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        panel_boundary.delivery_calls.load(Ordering::Relaxed),
        2,
        "a conflicting notification identity is rejected before provider use"
    );
    // The durable boundary independently enforces exact-byte replay even for
    // a caller that has not passed through the broker's identity validation.
    assert_eq!(
        test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1::deliver_once(
            panel_boundary.as_ref(),
            &conflicting_panel,
        ),
        Err(test_moderation::ModerationPanelNotificationFailureV1::Permanent)
    );
    assert_eq!(panel_boundary.delivery_calls.load(Ordering::Relaxed), 3);
    for (mode, expected) in [
        (
            ServerTestModerationDeliveryMode::NotDelivered,
            BrokerError::Unavailable,
        ),
        (
            ServerTestModerationDeliveryMode::Ambiguous,
            BrokerError::Ambiguous,
        ),
        (
            ServerTestModerationDeliveryMode::Permanent,
            BrokerError::Rejected,
        ),
        (
            ServerTestModerationDeliveryMode::DriftAfterDelivery,
            BrokerError::Ambiguous,
        ),
        (
            ServerTestModerationDeliveryMode::InvalidReceipt,
            BrokerError::Ambiguous,
        ),
    ] {
        let state = moderation_panel_state(Arc::new(
            ServerTestModerationPanelBoundary::exact().with_mode(mode),
        ));
        let payload = encode_canonical(
            &moderation_panel_notification_request_to_wire(&moderation_panel_request())
                .expect("project panel failure mode"),
            MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1,
        )
        .expect("encode panel failure mode");
        assert_eq!(
            dispatch_moderation_delivery(
                &state,
                1,
                OPERATION_MODERATION_PANEL_NOTIFICATION_DELIVER_ONCE_V1,
                payload,
            ),
            Err(expected)
        );
    }
}
#[test]
fn moderation_delivery_round_trips_and_poisons_after_ambiguous_results() {
    use test_moderation::{
        ModerationPanelNotificationFailureV1 as PanelFailure,
        ModerationRuntimeProviderReadinessErrorV1 as ReadinessError,
        ModerationTerminalHandoffKindV1 as Kind,
    };
    use test_moderation_runtime::{
        ModerationDurableHandoffFailureV1 as HandoffFailure,
        ModerationDurableHandoffOutcomeV1 as HandoffOutcome,
    };
    for (slot, kind) in [
        (
            IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff,
            Kind::Settlement,
        ),
        (
            IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
            Kind::Publication,
        ),
    ] {
        let catalog = delivery_catalog(slot);
        let backends = match slot {
            IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff => {
                RuntimeProviderBrokerBackendsV1::new().with_moderation_settlement_handoff(Arc::new(
                    ServerTestModerationHandoffBoundary::exact(kind),
                ))
            }
            IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff => {
                RuntimeProviderBrokerBackendsV1::new().with_moderation_publication_handoff(
                    Arc::new(ServerTestModerationHandoffBoundary::exact(kind)),
                )
            }
            _ => unreachable!(),
        };
        let (_directory, policy, shutdown, server) = start_signer(catalog.clone(), backends);
        let dependencies =
            resolve_test_process(&catalog, &policy).expect("resolve moderation handoff proxy");
        {
            let boundary = match slot {
                IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff => dependencies
                    .sorafs_moderation_settlement_handoff
                    .as_ref()
                    .expect("resolved settlement handoff"),
                IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff => dependencies
                    .sorafs_moderation_publication_handoff
                    .as_ref()
                    .expect("resolved publication handoff"),
                _ => unreachable!(),
            };
            let qualification =
                test_moderation::ModerationRuntimeProviderV1::qualification(boundary.as_ref())
                    .expect("qualify moderation handoff proxy");
            assert_eq!(qualification.revision(), 7);
            assert_eq!(qualification.policy_digest(), TEST_POLICY_DIGEST);
            let request = moderation_handoff_request(kind);
            assert_eq!(
                test_moderation_runtime::ModerationDurableHandoffBoundaryV1::deliver_once(
                    boundary.as_ref(),
                    &request,
                ),
                Ok(HandoffOutcome::Delivered)
            );
            assert_eq!(
                test_moderation_runtime::ModerationDurableHandoffBoundaryV1::deliver_once(
                    boundary.as_ref(),
                    &request,
                ),
                Ok(HandoffOutcome::AlreadyDelivered)
            );
        }
        drop(dependencies);
        shutdown.request_shutdown();
        server
            .join()
            .expect("join moderation handoff broker")
            .expect("moderation handoff broker exits cleanly");
    }
    let panel_catalog = delivery_catalog(IrohaRuntimeProviderSlotV1::ModerationPanelNotification);
    let (_directory, policy, shutdown, server) = start_signer(
        panel_catalog.clone(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_panel_notification(Arc::new(
            ServerTestModerationPanelBoundary::exact(),
        )),
    );
    let dependencies =
        resolve_test_process(&panel_catalog, &policy).expect("resolve panel-notification proxy");
    {
        let boundary = dependencies
            .sorafs_moderation_panel_notification
            .as_ref()
            .expect("resolved panel-notification boundary");
        let request = moderation_panel_request();
        let first =
            test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1::deliver_once(
                boundary.as_ref(),
                &request,
            )
            .expect("deliver brokered panel notification");
        let second =
            test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1::deliver_once(
                boundary.as_ref(),
                &request,
            )
            .expect("replay brokered panel notification");
        assert_eq!(first, second);
        assert_eq!(first.notification_id, request.notification.notification_id);
    }
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join panel-notification broker")
        .expect("panel-notification broker exits cleanly");
    let handoff_catalog = delivery_catalog(IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff);
    let (_directory, policy, shutdown, server) = start_signer(
        handoff_catalog.clone(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_settlement_handoff(Arc::new(
            ServerTestModerationHandoffBoundary::exact(Kind::Settlement)
                .with_mode(ServerTestModerationDeliveryMode::DriftAfterDelivery),
        )),
    );
    let dependencies = resolve_test_process(&handoff_catalog, &policy)
        .expect("resolve drifting moderation handoff proxy");
    {
        let boundary = dependencies
            .sorafs_moderation_settlement_handoff
            .as_ref()
            .expect("resolved drifting settlement handoff");
        assert_eq!(
            test_moderation_runtime::ModerationDurableHandoffBoundaryV1::deliver_once(
                boundary.as_ref(),
                &moderation_handoff_request(Kind::Settlement),
            ),
            Err(HandoffFailure::Ambiguous)
        );
        assert_eq!(
            test_moderation::ModerationRuntimeProviderV1::qualification(boundary.as_ref()),
            Err(ReadinessError::Unavailable),
            "post-delivery qualification drift poisons the session"
        );
    }
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join drifting handoff broker")
        .expect("drifting handoff broker exits cleanly");
    let (_directory, policy, shutdown, server) = start_signer(
        panel_catalog.clone(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_panel_notification(Arc::new(
            ServerTestModerationPanelBoundary::exact()
                .with_mode(ServerTestModerationDeliveryMode::InvalidReceipt),
        )),
    );
    let dependencies =
        resolve_test_process(&panel_catalog, &policy).expect("resolve invalid-receipt panel proxy");
    {
        let boundary = dependencies
            .sorafs_moderation_panel_notification
            .as_ref()
            .expect("resolved invalid-receipt panel boundary");
        assert_eq!(
            test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1::deliver_once(
                boundary.as_ref(),
                &moderation_panel_request(),
            ),
            Err(PanelFailure::Ambiguous)
        );
        assert_eq!(
            test_moderation::ModerationRuntimeProviderV1::qualification(boundary.as_ref()),
            Err(ReadinessError::Unavailable),
            "a substituted panel receipt poisons the session"
        );
    }
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join invalid-receipt panel broker")
        .expect("invalid-receipt panel broker exits cleanly");
}
#[test]
fn catalog_slot_ids_are_bounded_by_configured_multiplicities() {
    let mut maximum = Vec::with_capacity(MAX_CATALOG_ENTRIES_V1);
    for slot in IrohaRuntimeProviderSlotV1::ALL {
        maximum.extend(std::iter::repeat_n(
            slot.wire_id(),
            slot.max_configured_multiplicity(),
        ));
    }
    assert_eq!(maximum.len(), MAX_CATALOG_ENTRIES_V1);
    assert_eq!(
        MAX_CATALOG_ENTRIES_V1,
        IrohaRuntimeProviderSlotV1::ALL.len() - 1
            + iroha_config::parameters::SORAFS_APPEAL_FINANCE_MAX_SUBMITTER_SIGNERS_V1
    );
    assert_eq!(validate_catalog_slot_ids(maximum.iter().copied()), Ok(()));
    let mut oversized = maximum;
    oversized.push(IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id());
    assert_eq!(
        validate_catalog_slot_ids(oversized.iter().copied()),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        validate_catalog_slot_ids([
            IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id(),
            IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id(),
        ]),
        Err(BrokerError::BindingMismatch),
        "a singular role must reject duplicate wire IDs"
    );
    let first_unknown_slot = IrohaRuntimeProviderSlotV1::ALL
        .last()
        .expect("catalog has at least one slot")
        .wire_id()
        .checked_add(1)
        .expect("catalog wire ID increments");
    assert_eq!(
        validate_catalog_slot_ids([first_unknown_slot]),
        Err(BrokerError::BindingMismatch),
        "an unknown role must fail closed"
    );
    assert_eq!(
        validate_catalog_slot_ids([]),
        Err(BrokerError::BindingMismatch),
        "a catalog missing every role is not a handshake catalog"
    );
}
#[test]
fn catalog_slot_ids_enforce_every_sparse_slot_multiplicity_and_reject_unknowns() {
    for slot in IrohaRuntimeProviderSlotV1::ALL {
        let maximum = slot.max_configured_multiplicity();
        assert_eq!(
            validate_catalog_slot_ids(std::iter::repeat_n(slot.wire_id(), maximum)),
            Ok(()),
            "valid multiplicity for wire ID {}",
            slot.wire_id(),
        );
        assert_eq!(
            validate_catalog_slot_ids(std::iter::repeat_n(slot.wire_id(), maximum + 1)),
            Err(BrokerError::BindingMismatch),
            "excess multiplicity for wire ID {}",
            slot.wire_id(),
        );
    }
    for unknown in [0, 53, 61, u16::MAX] {
        assert_eq!(
            validate_catalog_slot_ids([unknown]),
            Err(BrokerError::BindingMismatch),
            "unregistered wire ID {unknown} must fail closed",
        );
    }
}
#[test]
fn signing_payload_bound_matches_canonical_governance_ceiling() {
    assert_eq!(
        MAX_SIGNING_PAYLOAD_BYTES_V1,
        sorafs_manifest::GOVERNANCE_DAG_SIGNING_PAYLOAD_MAX_BYTES_V1
    );
    assert!(
        std::hint::black_box(MAX_SIGNING_PAYLOAD_BYTES_V1)
            > test_reputation_signed::MAX_SIGNED_REPUTATION_SNAPSHOT_ENCODED_BYTES,
        "the signer must admit the largest bounded embedded envelope plus its Governance wrapper"
    );
    assert_eq!(validate_signing_payload_len(0), Err(BrokerError::Rejected));
    assert_eq!(
        validate_signing_payload_len(
            sorafs_manifest::SORAFS_GOVERNANCE_EXTERNAL_PAYLOAD_MAX_BYTES_V1
        ),
        Ok(())
    );
    assert_eq!(
        validate_signing_payload_len(MAX_SIGNING_PAYLOAD_BYTES_V1),
        Ok(())
    );
    assert_eq!(
        validate_signing_payload_len(MAX_SIGNING_PAYLOAD_BYTES_V1 + 1),
        Err(BrokerError::Rejected)
    );
}
#[test]
fn stream_token_and_potr_signers_reject_noncanonical_or_unbound_payloads() {
    let binding = token_signer_binding();
    let validate_token_payload =
        |payload: &[u8]| prepare_stream_token_broker_request(&binding, payload).map(|_| ());

    let token_body = sorafs_manifest::StreamTokenBodyV1 {
        token_id: "0123456789abcdef0123456789abcdef".to_owned(),
        manifest_cid: vec![0x21; 32],
        provider_id: [0x22; 32],
        profile_handle: "sorafs.sf1@1.0.0".to_owned(),
        max_streams: 4,
        ttl_epoch: 1_700_000_600,
        rate_limit_bytes: 8 * 1024 * 1024,
        issued_at: 1_700_000_000,
        requests_per_minute: 120,
        token_pk_version: 7,
    };
    let token_payload = token_body
        .signing_payload_bytes()
        .expect("encode canonical stream-token signing payload");
    assert_eq!(validate_token_payload(&token_payload), Ok(()));
    assert_eq!(
        validate_token_payload(b"arbitrary signing oracle input"),
        Err(BrokerError::Rejected)
    );
    let mut trailing_token = token_payload.clone();
    trailing_token.push(0);
    assert!(validate_token_payload(&trailing_token).is_err());
    let mut invalid_token = token_body;
    invalid_token.max_streams = 0;
    assert_eq!(
        validate_token_payload(
            &invalid_token
                .signing_payload_bytes()
                .expect("encode structurally invalid stream-token body")
        ),
        Err(BrokerError::Rejected)
    );
    let mut receipt = sorafs_manifest::PotrReceiptV1 {
        version: sorafs_manifest::POTR_RECEIPT_VERSION_V1,
        manifest_digest: [0x31; 32],
        provider_id: [0x32; 32],
        tier: sorafs_manifest::ProofStreamTier::Hot,
        deadline_ms: 90_000,
        latency_ms: 42_000,
        status: sorafs_manifest::PotrStatus::Success,
        requested_at_ms: 1_700_000_000_000,
        responded_at_ms: 1_700_000_042_000,
        recorded_at_ms: 1_700_000_042_100,
        range_start: 0,
        range_end: 1_048_575,
        request_id: Some([0x33; 16]),
        trace_id: Some([0x34; 16]),
        note: Some("ok".to_owned()),
        gateway_signature: None,
        provider_signature: None,
    };
    let potr_payload = receipt
        .signing_payload_bytes()
        .expect("encode canonical unsigned PoTR receipt");
    assert_eq!(
        validate_potr_signing_payload(&potr_payload, receipt.provider_id),
        Ok(())
    );
    assert_eq!(
        validate_potr_signing_payload(&potr_payload, [0xFF; 32]),
        Err(BrokerError::BindingMismatch),
        "the PoTR preimage remains pinned to the configured provider policy"
    );
    assert_eq!(
        validate_potr_signing_payload(b"arbitrary signing oracle input", [0x32; 32]),
        Err(BrokerError::Rejected)
    );
    let mut trailing_potr = potr_payload;
    trailing_potr.push(0);
    assert!(validate_potr_signing_payload(&trailing_potr, [0x32; 32]).is_err());
    receipt.gateway_signature = Some(sorafs_manifest::PotrSignatureV1 {
        algorithm: sorafs_manifest::PotrSignatureAlgorithm::Ed25519,
        public_key: vec![0x41; 32],
        signature: vec![0x42; 64],
    });
    let mut signed_field_payload = sorafs_manifest::POTR_RECEIPT_SIGNATURE_DOMAIN_V1.to_vec();
    signed_field_payload.extend_from_slice(
        &norito::to_bytes(&receipt).expect("encode receipt with a populated signature"),
    );
    assert_eq!(
        validate_potr_signing_payload(&signed_field_payload, [0x32; 32]),
        Err(BrokerError::Rejected),
        "the external signer accepts only the canonical unsigned receipt"
    );
}
#[test]
fn stream_token_signer_binding_and_qualification_frames_are_exact() {
    let binding = token_signer_binding();
    assert_eq!(validate_wire_binding(&binding), Ok(()));
    for mutate in [
        |binding: &mut ProviderBindingWireV1| binding.revision = None,
        |binding: &mut ProviderBindingWireV1| binding.revision = Some(0),
        |binding: &mut ProviderBindingWireV1| binding.policy_digest = None,
        |binding: &mut ProviderBindingWireV1| binding.policy_digest = Some([0; 32]),
    ] {
        let mut invalid = binding.clone();
        mutate(&mut invalid);
        assert_eq!(
            validate_wire_binding(&invalid),
            Err(BrokerError::BindingMismatch)
        );
    }
    let request = validated_operation(
        binding,
        OPERATION_QUALIFY_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode qualification request"),
    );
    let signer_backend = stream_token_signer_test_support::signer_binding();
    let exact = encode_canonical(&signer_backend, MAX_STREAM_TOKEN_METADATA_BYTES_V1)
        .expect("encode exact metadata claim");
    assert_eq!(
        validate_operation_result(&request, STATUS_OK_V1, &exact, &network_id()),
        Ok(())
    );
    let mut custody = signer_backend.custody().clone();
    custody.key_revision = 8;
    let changed = StreamTokenSignerRuntimeBindingV1::new(
        custody,
        signer_backend.observer_handle().to_owned(),
        signer_backend.trust_pins_digest(),
    )
    .unwrap();
    let substituted = encode_canonical(&changed, MAX_STREAM_TOKEN_METADATA_BYTES_V1)
        .expect("encode substituted metadata claim");
    assert_eq!(
        validate_operation_result(&request, STATUS_OK_V1, &substituted, &network_id()),
        Err(BrokerError::Protocol)
    );
}
#[test]
fn stream_token_server_observation_rejects_drift_and_test_markers() {
    struct SignerProbe {
        handle: &'static str,
        drift: bool,
        calls: AtomicU64,
    }
    impl iroha_torii::sorafs::StreamTokenSignerClientV1 for SignerProbe {
        fn handle(&self) -> &str {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.drift && call != 0 {
                "hsm://sorafs/stream-token/substitute"
            } else {
                self.handle
            }
        }
        fn sign(
            &self,
            _: &SignerStreamTokenExpectedV1,
            _: &sorafs_manifest::StreamTokenBodyV1,
        ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
            Err(StreamTokenSignerCallErrorV1::Refused)
        }
        fn recover(
            &self,
            _: &SignerStreamTokenExpectedV1,
            _: &sorafs_manifest::StreamTokenBodyV1,
        ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
            Err(StreamTokenSignerCallErrorV1::Refused)
        }
    }
    struct ObserverProbe {
        calls: AtomicU64,
    }
    impl iroha_torii::sorafs::StreamTokenStateObserverClientV1 for ObserverProbe {
        fn finalize_check(
            &self,
            _: &iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
        ) -> Result<iroha_data_model::transaction::SignedTransaction, StreamTokenSignerCallErrorV1>
        {
            panic!("metadata must not submit a native custody check")
        }
        fn handle(&self) -> &'static str {
            self.calls.fetch_add(1, Ordering::SeqCst);
            "state://sorafs/stream-token/observer-primary"
        }
        fn observe(
            &self,
            _: &SignerStreamTokenObservationRequestV1,
        ) -> Result<StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1> {
            panic!("metadata must not fabricate or request custody qualification")
        }
    }
    let observer = Arc::new(ObserverProbe {
        calls: AtomicU64::new(0),
    });
    let binding = token_signer_binding();
    let exact = Arc::new(SignerProbe {
        handle: "hsm://sorafs/stream-token/primary-a",
        drift: false,
        calls: AtomicU64::new(0),
    });
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_stream_token_signer_client(exact.clone())
        .with_stream_token_state_observer(observer.clone());
    make_server_observation(network_id(), &binding, &backends)
        .expect("observe exact non-authorizing routing metadata twice");
    assert_eq!(exact.calls.load(Ordering::SeqCst), 2);
    assert_eq!(observer.calls.load(Ordering::SeqCst), 2);
    for provider in [
        SignerProbe {
            handle: "hsm://sorafs/stream-token/primary-a",
            drift: true,
            calls: AtomicU64::new(0),
        },
        SignerProbe {
            handle: "hsm://sorafs/stream-token/test",
            drift: false,
            calls: AtomicU64::new(0),
        },
    ] {
        let backends = RuntimeProviderBrokerBackendsV1::new()
            .with_stream_token_signer_client(Arc::new(provider))
            .with_stream_token_state_observer(observer.clone());
        assert!(matches!(
            make_server_observation(network_id(), &binding, &backends),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
}
#[test]
fn moderation_quarantine_server_binds_key_identity_and_revalidates_operations() {
    let catalog = moderation_catalog();
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    for backend in [
        ServerTestModerationKeyWrapper::exact()
            .with_handle("software://sorafs/moderation/quarantine-wrapper-substitute"),
        ServerTestModerationKeyWrapper::exact().with_revision(8),
        ServerTestModerationKeyWrapper::exact()
            .with_active_key_id("software://sorafs/moderation/test/quarantine-key"),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_moderation_quarantine_key_wrapper(Arc::new(backend)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    let state = moderation_state(Arc::new(ServerTestModerationKeyWrapper::exact()));
    assert_eq!(
        state.observations[0]
            .moderation_quarantine_active_key_id
            .as_deref(),
        Some(SERVER_TEST_MODERATION_KEY_ID)
    );
    let qualification = dispatch_moderation(
        &state,
        1,
        OPERATION_QUALIFY_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode moderation qualification request"),
    )
    .expect("qualify moderation wrapper");
    assert_eq!(
        decode_canonical::<QualificationResultWireV1>(
            &qualification,
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("decode moderation qualification"),
        QualificationResultWireV1 {
            revision: 7,
            policy_digest: TEST_POLICY_DIGEST,
        }
    );
    let context_digest = [0x31; 32];
    let dek = [0x52; 32];
    let wrapped = dispatch_moderation(
        &state,
        2,
        OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineWrapDekRequestWireV1 {
                context_digest,
                dek,
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode moderation wrap request"),
    )
    .expect("wrap moderation DEK");
    let mut wrapped = decode_canonical::<ModerationQuarantineWrapDekResultWireV1>(
        &wrapped,
        MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
    )
    .expect("decode moderation wrapped DEK");
    let wrapped = std::mem::take(&mut wrapped.wrapped_dek);
    assert_eq!(wrapped.len(), 64);
    let unwrapped = dispatch_moderation(
        &state,
        3,
        OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek: wrapped,
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode moderation unwrap request"),
    )
    .expect("unwrap moderation DEK");
    assert_eq!(
        decode_canonical::<ModerationQuarantineUnwrapDekResultWireV1>(
            &unwrapped,
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("decode moderation unwrapped DEK")
        .dek,
        dek
    );
    let zero_context = make_operation_request(
        TEST_SESSION_ID,
        4,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineWrapDekRequestWireV1 {
                context_digest: [0; 32],
                dek,
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode zero-context moderation wrap"),
    )
    .expect("build zero-context moderation wrap");
    assert_eq!(
        validate_operation_request(&zero_context),
        Err(BrokerError::Rejected)
    );
    let oversized_wrapped = make_operation_request(
        TEST_SESSION_ID,
        5,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek: vec![0xAA; MAX_MODERATION_QUARANTINE_WRAPPED_DEK_BYTES_V1 + 1],
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode oversized moderation wrapped DEK"),
    )
    .expect("build oversized moderation unwrap");
    assert_eq!(
        validate_operation_request(&oversized_wrapped),
        Err(BrokerError::Rejected)
    );
    let drifting = moderation_state(Arc::new(
        ServerTestModerationKeyWrapper::exact().with_post_wrap_drift(),
    ));
    assert_eq!(
        dispatch_moderation(
            &drifting,
            6,
            OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
            encode_canonical(
                &ModerationQuarantineWrapDekRequestWireV1 {
                    context_digest,
                    dek,
                },
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )
            .expect("encode drifting moderation wrap"),
        ),
        Err(BrokerError::Ambiguous)
    );
}
#[test]
fn moderation_quarantine_server_rejects_malformed_inputs_and_unwrap_drift() {
    let state = moderation_state(Arc::new(ServerTestModerationKeyWrapper::exact()));
    let context_digest = [0x31; 32];
    let dek = [0x52; 32];
    let zero_dek = make_operation_request(
        TEST_SESSION_ID,
        1,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineWrapDekRequestWireV1 {
                context_digest,
                dek: [0; 32],
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode zero DEK"),
    )
    .expect("build zero-DEK wrap");
    assert_eq!(
        validate_operation_request(&zero_dek),
        Err(BrokerError::Rejected)
    );
    for key_id in [
        String::new(),
        " software://sorafs/moderation/quarantine-key".to_owned(),
        "software://sorafs/moderation/quarantine?token".to_owned(),
        "software://sorafs/moderation/test/quarantine-key".to_owned(),
        "software://sorafs/moderation/dummy/quarantine-key".to_owned(),
        "software://sorafs/moderation/quarantine-key\n".to_owned(),
        format!(
            "software:{}",
            "x".repeat(MAX_MODERATION_QUARANTINE_KEY_ID_BYTES_V1)
        ),
    ] {
        let invalid_key = make_operation_request(
            TEST_SESSION_ID,
            2,
            state.catalog[0].clone(),
            state.observations[0].metadata_digest,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
            encode_canonical(
                &ModerationQuarantineUnwrapDekRequestWireV1 {
                    key_id,
                    context_digest,
                    wrapped_dek: vec![1],
                },
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )
            .expect("encode invalid key id"),
        )
        .expect("build invalid-key unwrap");
        assert_eq!(
            validate_operation_request(&invalid_key),
            Err(BrokerError::Rejected)
        );
    }
    let empty_wrapped = make_operation_request(
        TEST_SESSION_ID,
        3,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek: Vec::new(),
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode empty wrapped DEK"),
    )
    .expect("build empty-wrapped unwrap");
    assert_eq!(
        validate_operation_request(&empty_wrapped),
        Err(BrokerError::Rejected)
    );
    let maximum_wrapped = make_operation_request(
        TEST_SESSION_ID,
        4,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
        encode_canonical(
            &ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek: vec![0xAA; MAX_MODERATION_QUARANTINE_WRAPPED_DEK_BYTES_V1],
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode maximum wrapped DEK"),
    )
    .expect("build maximum-wrapped unwrap");
    validate_operation_request(&maximum_wrapped)
        .expect("maximum canonical wrapped DEK remains valid");
    let frame = encode_frame(
        FRAME_KIND_OPERATION_REQUEST_V1,
        &maximum_wrapped,
        MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1,
    )
    .expect("maximum moderation request fits its frame ceiling");
    assert!(frame.len() <= MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1);
    assert_eq!(
        decode_operation_frame::<OperationRequestV1>(
            &frame,
            FRAME_KIND_OPERATION_REQUEST_V1,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
        )
        .expect("decode maximum moderation request frame"),
        maximum_wrapped
    );
    assert_eq!(
        dispatch_moderation(
            &state,
            4,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
            maximum_wrapped.payload.clone(),
        ),
        Err(BrokerError::Rejected),
        "the maximum payload reaches the backend before semantic rejection"
    );
    let mut wrapped = context_digest.to_vec();
    wrapped.extend(
        dek.iter()
            .zip(context_digest)
            .map(|(plain, context)| plain ^ context),
    );
    let unwrap_payload = || {
        encode_canonical(
            &ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek: wrapped.clone(),
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode valid unwrap")
    };
    let zero_output = moderation_state(Arc::new(
        ServerTestModerationKeyWrapper::exact().with_zero_unwrap_output(),
    ));
    assert_eq!(
        dispatch_moderation(
            &zero_output,
            5,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
            unwrap_payload(),
        ),
        Err(BrokerError::Rejected)
    );
    let drifting = moderation_state(Arc::new(
        ServerTestModerationKeyWrapper::exact().with_post_unwrap_drift(),
    ));
    assert_eq!(
        dispatch_moderation(
            &drifting,
            6,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
            unwrap_payload(),
        ),
        Err(BrokerError::StaleOrRevoked)
    );
    for (failure, expected) in [
        (
            node::ModerationQuarantineKeyOperationErrorV1::Unavailable,
            BrokerError::Unavailable,
        ),
        (
            node::ModerationQuarantineKeyOperationErrorV1::Rejected,
            BrokerError::Rejected,
        ),
        (
            node::ModerationQuarantineKeyOperationErrorV1::StaleOrRevoked,
            BrokerError::StaleOrRevoked,
        ),
        (
            node::ModerationQuarantineKeyOperationErrorV1::Ambiguous,
            BrokerError::Ambiguous,
        ),
    ] {
        let failing = moderation_state(Arc::new(
            ServerTestModerationKeyWrapper::exact().with_wrap_failure(failure),
        ));
        assert_eq!(
            dispatch_moderation(
                &failing,
                7,
                OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
                encode_canonical(
                    &ModerationQuarantineWrapDekRequestWireV1 {
                        context_digest,
                        dek,
                    },
                    MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
                )
                .expect("encode failing wrap"),
            ),
            Err(expected)
        );
    }
    let invalid_ambiguous_unwrap = moderation_state(Arc::new(
        ServerTestModerationKeyWrapper::exact()
            .with_unwrap_failure(node::ModerationQuarantineKeyOperationErrorV1::Ambiguous),
    ));
    assert_eq!(
        dispatch_moderation(
            &invalid_ambiguous_unwrap,
            8,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1,
            unwrap_payload(),
        ),
        Err(BrokerError::Unavailable),
        "read-only unwrap uncertainty is never represented as ambiguous"
    );
}
#[test]
fn moderation_quarantine_broker_debug_output_redacts_key_material() {
    assert_eq!(
        operation_frame_limit(OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1),
        MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1,
    );
    assert_eq!(
        operation_frame_limit(OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1),
        MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1,
    );
    assert_eq!(
        operation_frame_limit(OPERATION_QUALIFY_V1),
        MAX_QUALIFICATION_FRAME_BYTES_V1,
    );
    let wire = ModerationQuarantineWrapDekRequestWireV1 {
        context_digest: [0x31; 32],
        dek: [222; 32],
    };
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        moderation_binding(),
        [0xA7; 32],
        OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1,
        encode_canonical(&wire, MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1)
            .expect("encode redaction test request"),
    )
    .expect("build redaction test request");
    let result = ModerationQuarantineUnwrapDekResultWireV1 { dek: [222; 32] };
    for rendered in [
        format!("{wire:?}"),
        format!("{request:?}"),
        format!("{result:?}"),
    ] {
        assert!(
            !rendered.contains("222"),
            "debug output must not expose raw DEK bytes: {rendered}",
        );
    }
}
#[test]
fn sensitive_broker_payload_is_scrubbed_before_request_ownership_on_early_errors() {
    let binding = token_signer_binding();
    let (stream, peer) = UnixStream::pair().expect("create isolated broker stream pair");
    let session = Arc::new(BrokerSession {
        decode_pool: new_test_process_pool(),
        connection: Mutex::new(BrokerConnection {
            stream,
            session_id: TEST_SESSION_ID,
            next_request_id: 1,
            poison_reason: None,
        }),
        chain_id: "sensitive-payload-test-chain".to_owned(),
        network_id: network_id(),
        endpoint: EndpointPolicy::for_test(std::path::PathBuf::from("unused-broker.sock")),
        requested_catalog: vec![binding.clone()],
    });

    let oversized_len = MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1 + 1;
    let admission_audit = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    let admission_error = session.call_sensitive(
        &binding,
        [0xA7; 32],
        OPERATION_STREAM_TOKEN_SIGN_V1,
        ScrubbedBytes::with_drop_audit(vec![0xD1; oversized_len], Arc::clone(&admission_audit)),
        false,
    );
    assert!(matches!(
        admission_error,
        Err(BrokerError::Rejected | BrokerError::Unavailable)
    ));
    assert_eq!(
        admission_audit.load(std::sync::atomic::Ordering::SeqCst),
        oversized_len,
        "admission failure must drop the original, fully scrubbed owner",
    );

    let request_audit = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    assert_eq!(
        make_operation_request_with_scrubbed_payload(
            [0; 32],
            1,
            binding.clone(),
            [0xA7; 32],
            OPERATION_STREAM_TOKEN_SIGN_V1,
            ScrubbedBytes::with_drop_audit(vec![0xD2; 37], Arc::clone(&request_audit)),
        ),
        Err(BrokerError::Protocol),
    );
    assert_eq!(
        request_audit.load(std::sync::atomic::Ordering::SeqCst),
        37,
        "request validation failure must retain and scrub the sensitive owner",
    );

    let poisoning_session = Arc::clone(&session);
    assert!(
        thread::spawn(move || {
            let _connection = poisoning_session
                .connection
                .lock()
                .expect("lock broker connection before poisoning");
            panic!("poison broker connection for custody regression");
        })
        .join()
        .is_err()
    );
    let lock_audit = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    assert_eq!(
        session.call_sensitive(
            &binding,
            [0xA7; 32],
            OPERATION_STREAM_TOKEN_SIGN_V1,
            ScrubbedBytes::with_drop_audit(vec![0xD3; 41], Arc::clone(&lock_audit)),
            false,
        ),
        Err(BrokerError::Unavailable),
    );
    assert_eq!(
        lock_audit.load(std::sync::atomic::Ordering::SeqCst),
        41,
        "connection-lock failure must drop the original, fully scrubbed owner",
    );
    drop(peer);
}
#[test]
fn reputation_retention_slot_is_exact_bounded_and_backend_symmetric() {
    let catalog = reputation_retention_server_test_catalog();
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &IrohaRuntimeProviderBindingsV1::empty_for_test("server-test-chain"),
            RuntimeProviderBrokerBackendsV1::new()
                .with_reputation_finalized_archive_retention_authority(Arc::new(
                    ServerTestReputationRetentionAuthority::exact(),
                )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    for backend in [
        ServerTestReputationRetentionAuthority {
            handle: "sealed://sorafs/reputation/retention-substitute".to_owned(),
            ..ServerTestReputationRetentionAuthority::exact()
        },
        ServerTestReputationRetentionAuthority {
            revision: 8,
            ..ServerTestReputationRetentionAuthority::exact()
        },
        ServerTestReputationRetentionAuthority {
            policy_digest: [0x72; 32],
            ..ServerTestReputationRetentionAuthority::exact()
        },
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_reputation_finalized_archive_retention_authority(Arc::new(backend,)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    let state = prepare_test_server_state(
        &catalog,
        RuntimeProviderBrokerBackendsV1::new()
            .with_reputation_finalized_archive_retention_authority(Arc::new(
                ServerTestReputationRetentionAuthority::exact(),
            )),
    )
    .expect("exact reputation retention authority must qualify");
    let binding = state.catalog[0].clone();
    validate_wire_binding(&binding).expect("canonical reputation retention binding");
    let encoded = encode_canonical(&binding, MAX_HANDSHAKE_FRAME_BYTES_V1)
        .expect("encode reputation retention binding");
    assert_eq!(
        decode_canonical::<ProviderBindingWireV1>(&encoded, MAX_HANDSHAKE_FRAME_BYTES_V1)
            .expect("decode reputation retention binding"),
        binding
    );
    assert_eq!(
        operation_frame_limit(OPERATION_REPUTATION_RETENTION_LOAD_V1),
        MAX_REPUTATION_RETENTION_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1),
        MAX_REPUTATION_RETENTION_FRAME_BYTES_V1
    );
    let observation = state.observations[0].clone();
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        observation.metadata_digest,
        OPERATION_REPUTATION_RETENTION_LOAD_V1,
        encode_canonical(
            &ReputationRetentionLoadRequestWireV1 {
                network_id: network_id_from(0x17),
            },
            MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
        )
        .expect("encode wrong-chain retention load"),
    )
    .expect("build wrong-chain retention request");
    assert_eq!(
        dispatch_server_operation(&state, &request),
        Err(BrokerError::BindingMismatch)
    );
    for next_record in [
        Vec::new(),
        vec![0xA5; MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1 + 1],
        vec![1, 2, 3, 0],
    ] {
        let request = make_operation_request(
            TEST_SESSION_ID,
            2,
            binding.clone(),
            observation.metadata_digest,
            OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1,
            encode_canonical(
                &ReputationRetentionCompareAndSwapRequestWireV1 {
                    network_id: network_id(),
                    expected_revision: None,
                    next_record,
                },
                MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
            )
            .expect("encode invalid retention CAS"),
        )
        .expect("build invalid retention CAS");
        assert_eq!(
            validate_operation_request_for_session(&request, "server-test-chain", &network_id(),),
            Err(BrokerError::Rejected)
        );
    }
    let mut oversized_prelude = Vec::new();
    oversized_prelude.extend_from_slice(&binding.slot.to_be_bytes());
    oversized_prelude
        .extend_from_slice(&OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1.to_be_bytes());
    oversized_prelude.extend_from_slice(
        &u32::try_from(MAX_REPUTATION_RETENTION_FRAME_BYTES_V1 + 1)
            .expect("reputation retention frame ceiling fits u32")
            .to_be_bytes(),
    );
    assert_eq!(
        read_operation_request_frame(&mut Cursor::new(oversized_prelude)),
        Err(BrokerError::Protocol),
        "the 64 KiB record envelope is bounded before frame allocation"
    );
}
#[test]
fn governance_checkpoint_server_requires_exact_backend_identity_and_policy() {
    let catalog = checkpoint_catalog();
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    for backend in [
        LaxGovernanceCheckpointStore::new(
            "sealed://governance/runtime-broker-checkpoint-substitute",
            7,
        ),
        LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 8),
        LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 7)
            .with_policy_digest([0x72; 32]),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_governance_dag_checkpoint_store(Arc::new(backend)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    prepare_test_server_state(
        &catalog,
        RuntimeProviderBrokerBackendsV1::new().with_governance_dag_checkpoint_store(Arc::new(
            LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 7),
        )),
    )
    .expect("exact checkpoint backend must qualify");
}
#[test]
fn governance_checkpoint_slot_wire_mapping_roundtrips_replay_state() {
    use node::GovernanceDagSealedStateSlot as Slot;
    for (slot, wire) in [
        (Slot::Checkpoint, 1),
        (Slot::PublishIntent, 2),
        (Slot::ProducerCheckpoint, 3),
        (Slot::ProducerPublishIntent, 4),
        (Slot::IpfsRequestReplay, 5),
        (Slot::SignedHeadRequestReplay, 6),
    ] {
        assert_eq!(sealed_slot_to_wire(slot), wire);
        assert_eq!(sealed_slot_from_wire(wire), Ok(slot));
    }
    assert_eq!(sealed_slot_from_wire(0), Err(BrokerError::Protocol));
    assert_eq!(sealed_slot_from_wire(7), Err(BrokerError::Protocol));
    assert!(!sealed_slot_is_transient(Slot::IpfsRequestReplay));
    assert!(!sealed_slot_is_transient(Slot::SignedHeadRequestReplay));
}
#[test]
fn governance_checkpoint_broker_enforces_monotonic_cas_and_transient_delete() {
    use node::{
        GovernanceDagSealedCheckpointStore as _, GovernanceDagSealedStateRecord,
        GovernanceDagSealedStateSlot as Slot,
    };
    let durable = GovernanceDagSealedStateRecord::new(Slot::Checkpoint, 3, vec![0x31]);
    let intent = GovernanceDagSealedStateRecord::new(Slot::PublishIntent, 5, vec![0x51]);
    let store = Arc::new(
        LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 7)
            .with_record(Slot::Checkpoint, durable.clone())
            .with_record(Slot::PublishIntent, intent.clone()),
    );
    let state = checkpoint_state(store.clone());
    let mut request_id = 1_u64;
    for next in [
        GovernanceDagSealedStateRecord::new(Slot::Checkpoint, 2, vec![0x22]),
        GovernanceDagSealedStateRecord::new(Slot::Checkpoint, 3, vec![0x33]),
    ] {
        assert_eq!(
            dispatch_checkpoint(
                &state,
                request_id,
                OPERATION_SEALED_COMPARE_AND_SWAP_V1,
                compare_payload(Slot::Checkpoint, Some(durable.revision), &next,),
            ),
            Err(BrokerError::Rejected)
        );
        request_id += 1;
    }
    assert_eq!(
        store.compare_and_swap_calls.load(Ordering::Acquire),
        0,
        "a permissive backend must never see durable generation rollback"
    );
    let successor = GovernanceDagSealedStateRecord::new(Slot::Checkpoint, 4, vec![0x44]);
    assert_eq!(
        dispatch_checkpoint(
            &state,
            request_id,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            compare_payload(Slot::Checkpoint, Some([0x99; 32]), &successor,),
        ),
        Err(BrokerError::Conflict)
    );
    request_id += 1;
    assert_eq!(
        store.compare_and_swap_calls.load(Ordering::Acquire),
        0,
        "an exact-CAS mismatch must be rejected before the backend mutation"
    );
    dispatch_checkpoint(
        &state,
        request_id,
        OPERATION_SEALED_COMPARE_AND_SWAP_V1,
        compare_payload(Slot::Checkpoint, Some(durable.revision), &successor),
    )
    .expect("strict durable successor must commit");
    request_id += 1;
    assert_eq!(
        store
            .load(Slot::Checkpoint)
            .expect("load durable checkpoint"),
        Some(successor)
    );
    assert_eq!(
        dispatch_checkpoint(
            &state,
            request_id,
            OPERATION_SEALED_DELETE_V1,
            delete_payload(Slot::Checkpoint, durable.revision),
        ),
        Err(BrokerError::Rejected)
    );
    request_id += 1;
    assert_eq!(
        store.delete_calls.load(Ordering::Acquire),
        0,
        "durable checkpoint slots are not deletable"
    );
    let intent_rollback = GovernanceDagSealedStateRecord::new(Slot::PublishIntent, 4, vec![0x42]);
    assert_eq!(
        dispatch_checkpoint(
            &state,
            request_id,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            compare_payload(Slot::PublishIntent, Some(intent.revision), &intent_rollback,),
        ),
        Err(BrokerError::Rejected)
    );
    request_id += 1;
    let intent_successor = GovernanceDagSealedStateRecord::new(Slot::PublishIntent, 5, vec![0x52]);
    dispatch_checkpoint(
        &state,
        request_id,
        OPERATION_SEALED_COMPARE_AND_SWAP_V1,
        compare_payload(
            Slot::PublishIntent,
            Some(intent.revision),
            &intent_successor,
        ),
    )
    .expect("an active intent may advance at the same generation");
    request_id += 1;
    assert_eq!(
        dispatch_checkpoint(
            &state,
            request_id,
            OPERATION_SEALED_DELETE_V1,
            delete_payload(Slot::PublishIntent, intent.revision),
        ),
        Err(BrokerError::Conflict)
    );
    request_id += 1;
    assert_eq!(
        store.delete_calls.load(Ordering::Acquire),
        0,
        "a stale transient revision must not reach a permissive backend"
    );
    dispatch_checkpoint(
        &state,
        request_id,
        OPERATION_SEALED_DELETE_V1,
        delete_payload(Slot::PublishIntent, intent_successor.revision),
    )
    .expect("delete exact active intent");
    assert_eq!(
        store
            .load(Slot::PublishIntent)
            .expect("load deleted intent"),
        None
    );
}
#[test]
fn governance_checkpoint_broker_rejects_empty_state_and_post_mutation_drift() {
    use node::{GovernanceDagSealedStateRecord, GovernanceDagSealedStateSlot as Slot};
    let write_store = Arc::new(LaxGovernanceCheckpointStore::new(
        SERVER_TEST_CHECKPOINT_HANDLE,
        7,
    ));
    let write_state = checkpoint_state(write_store.clone());
    let empty = GovernanceDagSealedStateRecord::new(Slot::ProducerPublishIntent, 1, Vec::new());
    assert_eq!(
        dispatch_checkpoint(
            &write_state,
            1,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            compare_payload(Slot::ProducerPublishIntent, None, &empty),
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        write_store.compare_and_swap_calls.load(Ordering::Acquire),
        0,
        "empty sealed records must be rejected before the backend"
    );
    let producer_intent_limit =
        node::governance_dag_sealed_state_payload_max_bytes_v1(Slot::ProducerPublishIntent);
    let exact_payload = vec![0xA5; producer_intent_limit];
    let exact = GovernanceDagSealedStateRecord::new(Slot::ProducerPublishIntent, 1, exact_payload);
    validate_sealed_record_fields(
        Slot::ProducerPublishIntent,
        exact.generation,
        exact.revision,
        &exact.payload,
    )
    .expect("the exact producer-intent ceiling is canonical");
    let oversized = GovernanceDagSealedStateRecord::new(
        Slot::ProducerPublishIntent,
        1,
        vec![0xA5; producer_intent_limit + 1],
    );
    assert_eq!(
        validate_sealed_record_fields(
            Slot::ProducerPublishIntent,
            oversized.generation,
            oversized.revision,
            &oversized.payload,
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        dispatch_checkpoint(
            &write_state,
            2,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            compare_payload(Slot::ProducerPublishIntent, None, &oversized),
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        write_store.compare_and_swap_calls.load(Ordering::Acquire),
        0,
        "producer intent limit + 1 must fail before backend allocation or mutation"
    );
    let empty_store = Arc::new(
        LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 7)
            .with_record(Slot::ProducerPublishIntent, empty),
    );
    let empty_state = checkpoint_state(empty_store);
    assert_eq!(
        dispatch_checkpoint(
            &empty_state,
            1,
            OPERATION_SEALED_LOAD_V1,
            encode_canonical(
                &SealedLoadRequestWireV1 {
                    slot: sealed_slot_to_wire(Slot::ProducerPublishIntent),
                },
                MAX_OPERATION_FRAME_BYTES_V1,
            )
            .expect("encode sealed load"),
        ),
        Err(BrokerError::Protocol)
    );
    let store = Arc::new(
        LaxGovernanceCheckpointStore::new(SERVER_TEST_CHECKPOINT_HANDLE, 7)
            .with_post_compare_and_swap_drift(),
    );
    let state = checkpoint_state(store.clone());
    let next = GovernanceDagSealedStateRecord::new(Slot::ProducerCheckpoint, 1, vec![0xA1]);
    assert_eq!(
        dispatch_checkpoint(
            &state,
            1,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            compare_payload(Slot::ProducerCheckpoint, None, &next),
        ),
        Err(BrokerError::Ambiguous),
        "qualification drift after a mutation can never be reported as success"
    );
    assert_eq!(
        store.compare_and_swap_calls.load(Ordering::Acquire),
        1,
        "an ambiguous mutation is not replayed"
    );
    assert_eq!(
        dispatch_checkpoint(
            &state,
            2,
            OPERATION_SEALED_LOAD_V1,
            encode_canonical(
                &SealedLoadRequestWireV1 {
                    slot: sealed_slot_to_wire(Slot::ProducerCheckpoint),
                },
                MAX_OPERATION_FRAME_BYTES_V1,
            )
            .expect("encode sealed load"),
        ),
        Err(BrokerError::StaleOrRevoked)
    );
}
#[test]
fn pop_acme_and_compliance_bindings_are_exact_and_drift_checked() {
    let pop = pop_runtime_binding();
    let acme = runtime_binding(
        IrohaRuntimeProviderSlotV1::GatewayAcmeClient,
        SERVER_TEST_ACME_HANDLE,
    );
    let compliance = runtime_binding(
        IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport,
        SERVER_TEST_COMPLIANCE_HANDLE,
    );
    for binding in [&pop, &acme, &compliance] {
        assert_eq!(validate_wire_binding(binding), Ok(()));
        assert_eq!(validate_observation(binding, &observation(binding)), Ok(()));
    }
    pop_runtime_bindings_from_wire(&pop).expect("reconstruct exact public PoP binding");
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_pop_credential_provider_registry(Arc::new(ServerTestPopRegistry {
            revision: AtomicU64::new(7),
            drift_on_probe: false,
        }))
        .with_gateway_acme_client(Arc::new(ServerTestAcmeClient {
            revision: AtomicU64::new(7),
            drift_on_probe: false,
        }))
        .with_gateway_compliance_feed_transport(Arc::new(ServerTestComplianceTransport {
            revision: AtomicU64::new(7),
            drift_on_probe: false,
        }));
    assert_eq!(
        validate_exact_backend_set(&[pop.clone(), acme.clone(), compliance.clone()], &backends,),
        Ok(())
    );
    for binding in [&pop, &acme, &compliance] {
        make_server_observation(network_id(), binding, &backends)
            .expect("stable exact backend qualifies twice");
    }
    let mut substituted_pop = pop.clone();
    substituted_pop
        .pop_credential_runtime_binding
        .as_mut()
        .expect("PoP exact metadata")
        .issuer_id
        .push('\n');
    assert_eq!(
        validate_wire_binding(&substituted_pop),
        Err(BrokerError::BindingMismatch)
    );
    let mut missing_enrollment_key_digest = pop.clone();
    missing_enrollment_key_digest
        .pop_credential_runtime_binding
        .as_mut()
        .expect("PoP exact metadata")
        .enrollment_recipient_public_key_digest = [0; 32];
    assert_eq!(
        validate_wire_binding(&missing_enrollment_key_digest),
        Err(BrokerError::BindingMismatch)
    );
    let mut missing_wallet_key_digest = pop.clone();
    missing_wallet_key_digest
        .pop_credential_runtime_binding
        .as_mut()
        .expect("PoP exact metadata")
        .wallet_recipient_public_key_digest = [0; 32];
    assert_eq!(
        validate_wire_binding(&missing_wallet_key_digest),
        Err(BrokerError::BindingMismatch)
    );
    let mut confused_acme = acme.clone();
    confused_acme.pop_credential_runtime_binding = pop.pop_credential_runtime_binding.clone();
    assert_eq!(
        validate_wire_binding(&confused_acme),
        Err(BrokerError::BindingMismatch)
    );
    for (binding, backends) in [
        (
            pop.clone(),
            RuntimeProviderBrokerBackendsV1::new().with_pop_credential_provider_registry(Arc::new(
                ServerTestPopRegistry {
                    revision: AtomicU64::new(7),
                    drift_on_probe: true,
                },
            )),
        ),
        (
            acme.clone(),
            RuntimeProviderBrokerBackendsV1::new().with_gateway_acme_client(Arc::new(
                ServerTestAcmeClient {
                    revision: AtomicU64::new(7),
                    drift_on_probe: true,
                },
            )),
        ),
        (
            compliance.clone(),
            RuntimeProviderBrokerBackendsV1::new().with_gateway_compliance_feed_transport(
                Arc::new(ServerTestComplianceTransport {
                    revision: AtomicU64::new(7),
                    drift_on_probe: true,
                }),
            ),
        ),
    ] {
        assert_eq!(
            make_server_observation(network_id(), &binding, &backends),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        );
    }
}
#[test]
fn privacy_cycle_prf_binding_is_exact_and_drift_checked() {
    let binding = privacy_prf_binding();
    assert_eq!(validate_wire_binding(&binding), Ok(()));
    assert_eq!(
        validate_observation(&binding, &observation(&binding)),
        Ok(())
    );
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_privacy_cycle_prf_provider(Arc::new(ServerTestPrivacyCyclePrfProvider::exact()));
    assert_backend_fixture(
        &binding,
        &backends,
        "stable exact threshold-PRF provider qualifies twice",
    );
    let drifted = RuntimeProviderBrokerBackendsV1::new()
        .with_privacy_cycle_prf_provider(Arc::new(ServerTestPrivacyCyclePrfProvider::drifting()));
    assert_eq!(
        make_server_observation(network_id(), &binding, &drifted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
}
#[test]
fn privacy_cycle_prf_operation_is_canonical_bounded_and_read_only() {
    assert!(operation_is_known(OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1));
    assert_eq!(
        operation_frame_limit(OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1),
        MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1
    );
    let binding = privacy_prf_binding();
    let provider = Arc::new(ServerTestPrivacyCyclePrfProvider::exact());
    let backends =
        RuntimeProviderBrokerBackendsV1::new().with_privacy_cycle_prf_provider(provider.clone());
    let observed = make_server_observation(network_id(), &binding, &backends)
        .expect("qualify stable threshold-PRF provider");
    let state = singleton_state(
        "privacy-cycle-prf-test-chain",
        binding.clone(),
        observed.clone(),
        backends,
    );
    let request_value = node::PrivacyCyclePrfRequestV1::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        node::PrivacyAggregateCycleWindow {
            cycle_start_unix: 1_000,
            cycle_end_unix: 2_000,
            due_at_unix: 2_000,
        },
    )
    .expect("canonical threshold-PRF request");
    let wire = PrivacyCyclePrfRequestWireV1::from_request(&request_value);
    wire.to_request()
        .expect("wire reconstructs the exact canonical request");
    let request = make_operation_request(
        [0xA7; 32],
        1,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1,
        encode_canonical(&wire, MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1)
            .expect("encode threshold-PRF request"),
    )
    .expect("construct threshold-PRF operation");
    validate_operation_request(&request).expect("validate canonical threshold-PRF operation");
    let result =
        dispatch_server_operation(&state, &request).expect("dispatch threshold-PRF operation");
    let output = decode_canonical::<PrivacyCyclePrfOutputWireV1>(
        &result,
        MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1,
    )
    .expect("decode scrubbed threshold-PRF output");
    assert_eq!(output.output, [0xD5; 32]);
    assert_eq!(provider.derive_calls.load(Ordering::SeqCst), 1);
    let mut noncanonical = wire;
    noncanonical.cycle_id[0] ^= 1;
    let invalid = make_operation_request(
        [0xA8; 32],
        2,
        binding,
        observed.metadata_digest,
        OPERATION_PRIVACY_CYCLE_PRF_DERIVE_V1,
        encode_canonical(&noncanonical, MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1)
            .expect("encode noncanonical threshold-PRF request"),
    )
    .expect("construct noncanonical threshold-PRF operation");
    assert_eq!(
        validate_operation_request(&invalid),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        provider.derive_calls.load(Ordering::SeqCst),
        1,
        "noncanonical requests fail before provider evaluation"
    );
    let zero_output = encode_canonical(
        &PrivacyCyclePrfOutputWireV1 { output: [0; 32] },
        MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1,
    )
    .expect("encode forbidden zero output");
    assert_eq!(
        make_operation_response(&request, STATUS_OK_V1, zero_output, &state.network_id,),
        Err(BrokerError::Protocol)
    );
    let unit = encode_canonical(&(), MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1)
        .expect("encode payload-free error");
    assert_eq!(
        make_operation_response(&request, STATUS_AMBIGUOUS_V1, unit, &state.network_id,),
        Err(BrokerError::Protocol),
        "read-only PRF derivation can never report an ambiguous mutation"
    );
}
include!("runtime_network_binding_tests.rs");
#[test]
fn transparency_leader_lease_operations_are_canonical_fenced_and_bounded() {
    for operation in [
        OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1,
        OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1,
        OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1,
    ] {
        assert!(operation_is_known(operation));
        assert_eq!(
            operation_frame_limit(operation),
            MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1
        );
    }
    let binding = transparency_leader_lease_runtime_binding();
    let configured =
        transparency_runtime_binding_from_wire(&binding).expect("exact leader-lease binding");
    let provider = Arc::new(ServerTestTransparencyLeaderLeaseProvider::exact());
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_transparency_leader_lease_provider(provider.clone());
    let observed = make_server_observation(network_id(), &binding, &backends)
        .expect("qualify stable leader-lease provider");
    let state = singleton_state(
        "transparency-leader-lease-test-chain",
        binding.clone(),
        observed.clone(),
        backends,
    );
    let scope = node::TransparencyLeaderLeaseScopeV1::try_new(
        [0x1A; 32],
        node::PrivacyAggregateCycleWindow {
            cycle_start_unix: 1_000,
            cycle_end_unix: 2_000,
            due_at_unix: 2_000,
        },
        [0x2A; 32],
    )
    .expect("canonical leader-lease scope");
    let acquire = node::TransparencyLeaderLeaseAcquireRequestV1::try_new(
        scope,
        2_000,
        3_000,
        0,
        configured.clone(),
    )
    .expect("canonical acquisition request");
    let acquire_wire = TransparencyLeaderLeaseAcquireRequestWireV1::from_request(&acquire);
    assert_eq!(
        acquire_wire
            .to_request()
            .expect("reconstruct canonical acquisition request"),
        acquire
    );
    let acquire_request = make_operation_request(
        [0xC1; 32],
        1,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1,
        encode_canonical(&acquire_wire, MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1)
            .expect("encode acquisition request"),
    )
    .expect("construct acquisition operation");
    validate_operation_request(&acquire_request).expect("validate acquisition operation");
    let acquired_result = dispatch_server_operation(&state, &acquire_request)
        .expect("dispatch acquisition operation");
    let acquired = decode_canonical::<TransparencyLeaderLeaseGrantWireV1>(
        &acquired_result,
        MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_grant())
    .expect("decode acquired grant");
    assert_eq!(acquired.fencing_token(), 1);
    assert_eq!(provider.acquire_calls.load(Ordering::SeqCst), 1);
    let renew = node::TransparencyLeaderLeaseRenewRequestV1::try_new(
        acquired.clone(),
        2_500,
        4_000,
        acquired.fencing_token(),
    )
    .expect("canonical renewal request");
    let renew_wire = TransparencyLeaderLeaseRenewRequestWireV1::from_request(&renew);
    assert_eq!(
        renew_wire
            .to_request()
            .expect("reconstruct canonical renewal request"),
        renew
    );
    let renew_request = make_operation_request(
        [0xC2; 32],
        2,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_TRANSPARENCY_LEADER_LEASE_RENEW_V1,
        encode_canonical(&renew_wire, MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1)
            .expect("encode renewal request"),
    )
    .expect("construct renewal operation");
    validate_operation_request(&renew_request).expect("validate renewal operation");
    let renewed_result =
        dispatch_server_operation(&state, &renew_request).expect("dispatch renewal operation");
    let renewed = decode_canonical::<TransparencyLeaderLeaseGrantWireV1>(
        &renewed_result,
        MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_grant())
    .expect("decode renewed grant");
    assert_eq!(renewed.fencing_token(), 2);
    assert_eq!(provider.renew_calls.load(Ordering::SeqCst), 1);
    let release = node::TransparencyLeaderLeaseReleaseRequestV1::try_new(renewed.clone(), 3_000)
        .expect("canonical release request");
    let release_wire = TransparencyLeaderLeaseReleaseRequestWireV1::from_request(&release);
    assert_eq!(
        release_wire
            .to_request()
            .expect("reconstruct canonical release request"),
        release
    );
    let release_request = make_operation_request(
        [0xC3; 32],
        3,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_TRANSPARENCY_LEADER_LEASE_RELEASE_V1,
        encode_canonical(&release_wire, MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1)
            .expect("encode release request"),
    )
    .expect("construct release operation");
    validate_operation_request(&release_request).expect("validate release operation");
    let released_result =
        dispatch_server_operation(&state, &release_request).expect("dispatch release operation");
    let receipt = decode_canonical::<TransparencyLeaderLeaseReleaseReceiptWireV1>(
        &released_result,
        MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_receipt())
    .expect("decode release receipt");
    assert_eq!(receipt.lease_id(), renewed.lease_id());
    assert_eq!(receipt.fencing_token(), renewed.fencing_token());
    assert_eq!(provider.release_calls.load(Ordering::SeqCst), 1);
    let mut substituted_request = acquire_wire;
    substituted_request.provider_binding.revision += 1;
    let invalid_request = make_operation_request(
        [0xC4; 32],
        4,
        binding,
        observed.metadata_digest,
        OPERATION_TRANSPARENCY_LEADER_LEASE_ACQUIRE_V1,
        encode_canonical(
            &substituted_request,
            MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1,
        )
        .expect("encode substituted acquisition request"),
    )
    .expect("construct substituted acquisition operation");
    assert_eq!(
        validate_operation_request(&invalid_request),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        provider.acquire_calls.load(Ordering::SeqCst),
        1,
        "substituted binding fails before provider evaluation"
    );
    let unit = encode_canonical(&(), MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1)
        .expect("encode payload-free transition failure");
    for request in [&acquire_request, &renew_request, &release_request] {
        assert!(
            make_operation_response(request, STATUS_CONFLICT_V1, unit.clone(), &state.network_id,)
                .is_ok()
        );
        assert!(
            make_operation_response(
                request,
                STATUS_AMBIGUOUS_V1,
                unit.clone(),
                &state.network_id,
            )
            .is_ok()
        );
    }
}
#[test]
fn fenced_privacy_publisher_binding_is_exact_and_drift_checked() {
    let binding = privacy_publisher_binding();
    assert_eq!(validate_wire_binding(&binding), Ok(()));
    assert_eq!(
        validate_observation(&binding, &observation(&binding)),
        Ok(())
    );
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_publisher(Arc::new(ServerTestFencedPrivacyPublisher::exact()));
    assert_backend_fixture(
        &binding,
        &backends,
        "stable exact fenced privacy publisher qualifies twice",
    );
    let substituted = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_publisher(Arc::new(ServerTestFencedPrivacyPublisher::substituted()));
    assert_eq!(
        make_server_observation(network_id(), &binding, &substituted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
    let drifted = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_publisher(Arc::new(ServerTestFencedPrivacyPublisher::drifting()));
    assert_eq!(
        make_server_observation(network_id(), &binding, &drifted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
}
#[test]
fn fenced_privacy_nested_payload_rejects_compressed_noncanonical_and_allocation_bombs() {
    assert_eq!(
        validate_fenced_privacy_publication_payload_len(
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        ),
        Ok(())
    );
    assert_eq!(
        validate_fenced_privacy_publication_payload_len(
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1 + 1,
        ),
        Err(BrokerError::Rejected),
        "cap + 1 is rejected without allocating the claimed payload"
    );
    let request = fenced_request();
    let wire = FencedPrivacyPublicationRequestWireV1::from_request(&request);
    let canonical = request.canonical_payload().to_vec();
    let publication =
        norito::decode_canonical::<sorafs_manifest::ModerationLedgerCyclePublicationV1>(&canonical)
            .expect("decode trusted canonical fenced-publication fixture");
    let compressed =
        norito::to_compressed_bytes(&publication, Some(norito::CompressionConfig::default()))
            .expect("encode compressed fenced-publication negative");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let noncanonical = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::core::to_bytes(&publication)
            .expect("encode alternate-layout fenced-publication negative")
    };
    assert_ne!(noncanonical, canonical);
    let mut trailing = canonical.clone();
    trailing.push(0);
    for invalid in [
        compressed.as_slice(),
        noncanonical.as_slice(),
        trailing.as_slice(),
    ] {
        let mut invalid_wire = wire.clone();
        invalid_wire.canonical_payload = invalid.to_vec();
        let policy = operation_decode_policy(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1);
        let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
        let admission = DecodeResourceAdmissionV1::acquire_from(
            pool,
            Some(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1),
            policy,
        )
        .expect("acquire fenced-publication negative admission");
        let _scope = admission.enter();
        assert_eq!(
            invalid_wire.to_request(),
            Err(BrokerError::Rejected),
            "the wire entrypoint rejects the nested representation before reconstruction"
        );
    }
    // A valid payload under a one-byte decoded-allocation ceiling
    // models an attacker-controlled sequence allocation bomb while
    // retaining the exact production schema and outer framing.
    let bomb_policy = DecodeResourcePolicyV1::new(
        (
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        ),
        (MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1, 1),
        (0, 0),
        64,
        (
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
            2 * MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        ),
    );
    let bomb_pool = Arc::new(DecodeResourcePoolV1::new(bomb_policy.max_composed_bytes));
    let bomb_admission = DecodeResourceAdmissionV1::acquire_from(
        bomb_pool,
        Some(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1),
        bomb_policy,
    )
    .expect("acquire allocation-bomb admission");
    let _bomb_scope = bomb_admission.enter();
    assert_eq!(
        decode_fenced_privacy_publication_with_admission(&canonical, &bomb_admission),
        Err(BrokerError::Rejected),
        "nested decoded allocations obey the active broker admission"
    );
}
#[test]
fn fenced_privacy_nested_payload_charges_full_broker_admission() {
    let request = fenced_request();
    let wire = FencedPrivacyPublicationRequestWireV1::from_request(&request);
    let policy = operation_decode_policy(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1);
    let expected_decode = decode_resource_budget(
        wire.canonical_payload.len(),
        MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        policy,
    )
    .expect("derive fenced-publication nested decode budget");
    let expected_charge = expected_decode
        .composed_charge_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(wire.canonical_payload.len()))
        .expect("fenced-publication accounting charge fits usize");
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let admission = DecodeResourceAdmissionV1::acquire_from(
        pool,
        Some(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1),
        policy,
    )
    .expect("acquire fenced-publication accounting admission");
    let scope = admission.enter();
    assert_eq!(
        wire.to_request()
            .expect("reconstruct bounded fenced publication"),
        request
    );
    drop(scope);
    assert_eq!(
        admission
            .usage
            .lock()
            .expect("fenced-publication usage lock")
            .consumed_bytes,
        expected_charge,
        "one retained clone and both decode-plus-canonical-encode phases are charged"
    );
    assert!(
        std::hint::black_box(OPERATION_CUMULATIVE_PHASES_V1.retained_values)
            >= FENCED_PRIVACY_SERVER_PHASES_V1.retained_values
            && OPERATION_CUMULATIVE_PHASES_V1.decoded_values
                >= FENCED_PRIVACY_SERVER_PHASES_V1.decoded_values,
        "the full server validation/dispatch/response path remains within inventory"
    );
}
#[test]
fn fenced_privacy_preflight_uses_selected_process_and_preserves_active_operation() {
    let request = fenced_request();
    let wire = FencedPrivacyPublicationRequestWireV1::from_request(&request);
    let pool = new_test_process_pool();
    assert_eq!(
        wire.to_request_from_pool(Arc::clone(&pool))
            .expect("selected-process preflight"),
        request
    );
    assert_eq!(pool.allocation.reserved_bytes(), 0);
    let full = pool
        .try_acquire(pool.max_bytes)
        .expect("fill selected process cap");
    assert_eq!(
        wire.to_request_from_pool(Arc::clone(&pool)),
        Err(BrokerError::Unavailable),
        "selected-process exhaustion cannot fall back to a different pool"
    );
    let outer_pool = new_test_process_pool();
    let outer = DecodeResourceAdmissionV1::acquire_operation_from(
        Arc::clone(&outer_pool),
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1,
    )
    .expect("reserve existing publication operation");
    {
        let _scope = outer.enter();
        assert_eq!(wire.to_request_from_pool(Arc::clone(&pool)), Ok(request));
        assert!(Arc::ptr_eq(
            &current_decode_resource_admission().expect("active operation remains installed"),
            &outer,
        ));
    }
    drop(outer);
    assert_eq!(outer_pool.allocation.reserved_bytes(), 0);
    let unrelated = DecodeResourceAdmissionV1::acquire_operation_from(
        Arc::clone(&outer_pool),
        OPERATION_QUALIFY_V1,
    )
    .expect("reserve unrelated operation");
    {
        let _scope = unrelated.enter();
        assert_eq!(
            wire.to_request_from_pool(Arc::clone(&pool)),
            Err(BrokerError::Protocol),
            "a different active operation cannot replace its identity with a fresh reservation"
        );
    }
    drop(unrelated);
    drop(full);
    let mut malformed = wire;
    malformed.version = malformed.version.wrapping_add(1);
    assert_eq!(
        malformed.to_request_from_pool(Arc::clone(&pool)),
        Err(BrokerError::Rejected)
    );
    assert_eq!(pool.allocation.reserved_bytes(), 0);
    assert_eq!(outer_pool.allocation.reserved_bytes(), 0);
}

#[test]
fn fenced_privacy_publisher_operation_is_canonical_bounded_and_read_back() {
    assert!(operation_is_known(
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1
    ));
    assert_eq!(
        operation_frame_limit(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1),
        MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1
    );
    let binding = privacy_publisher_binding();
    let qualification =
        qualification_from_binding(&binding).expect("exact publisher qualification");
    let provider = Arc::new(ServerTestFencedPrivacyPublisher::exact());
    let backends =
        RuntimeProviderBrokerBackendsV1::new().with_fenced_privacy_publisher(provider.clone());
    let observed = make_server_observation(network_id(), &binding, &backends)
        .expect("qualify stable fenced privacy publisher");
    let state = singleton_state(
        "fenced-privacy-publisher-test-chain",
        binding.clone(),
        observed.clone(),
        backends,
    );
    let publish = fenced_request();
    let wire = FencedPrivacyPublicationRequestWireV1::from_request(&publish);
    let decode_policy = operation_decode_policy(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1);
    let decode_pool = Arc::new(DecodeResourcePoolV1::new(decode_policy.max_composed_bytes));
    let decode_admission = DecodeResourceAdmissionV1::acquire_from(
        decode_pool,
        Some(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1),
        decode_policy,
    )
    .expect("acquire fenced-publication operation admission");
    let _decode_scope = decode_admission.enter();
    assert_eq!(
        wire.to_request()
            .expect("reconstruct canonical fenced publication"),
        publish
    );
    let wire_debug = format!("{wire:?}");
    assert!(wire_debug.contains("canonical_payload_len"));
    assert!(!wire_debug.contains("canonical_payload:"));
    assert!(!wire_debug.contains(&format!("{:?}", wire.canonical_payload)));
    let request = make_operation_request(
        [0xD1; 32],
        1,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1,
        encode_canonical(&wire, MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1)
            .expect("encode fenced publication"),
    )
    .expect("construct fenced publication operation");
    validate_operation_request(&request).expect("validate fenced publication");
    let result = dispatch_server_operation(&state, &request).expect("dispatch fenced publication");
    let receipt = decode_canonical::<FencedPrivacyPublicationReceiptWireV1>(
        &result,
        MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_receipt(&publish, &binding.handle, qualification))
    .expect("decode verified fenced publication receipt");
    assert!(matches!(
        receipt.disposition(),
        node::FencedPrivacyPublicationDispositionV1::Appended
    ));
    assert_eq!(receipt.included_head(), receipt.readback_head());
    assert_eq!(provider.compare_and_append_calls.load(Ordering::SeqCst), 1);
    let mut tampered = wire.clone();
    tampered.payload_digest[0] ^= 1;
    let invalid_request = make_operation_request(
        [0xD2; 32],
        2,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1,
        encode_canonical(&tampered, MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1)
            .expect("encode tampered fenced publication"),
    )
    .expect("construct tampered fenced publication operation");
    assert_eq!(
        validate_operation_request(&invalid_request),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        provider.compare_and_append_calls.load(Ordering::SeqCst),
        1,
        "noncanonical request fails before provider evaluation"
    );
    let substituted_provider = Arc::new(ServerTestFencedPrivacyPublisher::substituted_receipt());
    let substituted_backends = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_publisher(substituted_provider.clone());
    let substituted_observed =
        make_server_observation(network_id(), &binding, &substituted_backends)
            .expect("qualify publisher whose receipt is substituted");
    let substituted_state = singleton_state(
        "fenced-privacy-substituted-receipt-test-chain",
        binding,
        substituted_observed,
        substituted_backends,
    );
    assert_eq!(
        dispatch_server_operation(&substituted_state, &request),
        Err(BrokerError::Ambiguous)
    );
    assert_eq!(
        substituted_provider
            .compare_and_append_calls
            .load(Ordering::SeqCst),
        1
    );
    let unit = encode_canonical(&(), MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1)
        .expect("encode payload-free publication failure");
    assert!(
        make_operation_response(
            &request,
            STATUS_CONFLICT_V1,
            unit.clone(),
            &state.network_id,
        )
        .is_ok()
    );
    assert!(
        make_operation_response(&request, STATUS_AMBIGUOUS_V1, unit, &state.network_id,).is_ok()
    );
}

include!("stream_token_mutation_tests.rs");
