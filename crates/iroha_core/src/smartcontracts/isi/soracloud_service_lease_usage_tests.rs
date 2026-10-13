//! Hosted-service lease lifecycle regression with one block overlay per phase.
//!
//! Keep committed phases in separate calls so default-stack tests do not retain
//! every `StateBlock` and `StateTransaction` temporary in one large frame.

use super::*;

/// Committed ledger and exact identities shared across separately scoped lease phases.
pub(super) struct ServiceLeaseUsageFixture {
    state: State,
    bundle: SoraDeploymentBundleV1,
    lease_started_height: u64,
    reporting_epoch: u64,
    alice_placement_incarnation: Hash,
    bob_placement_incarnation: Hash,
}

/// Deploy two reporters and commit their initial zero checkpoints.
pub(super) fn prepare_service_lease_usage() -> Result<ServiceLeaseUsageFixture, eyre::Report> {
    permissioned_soracloud_state!(kura, state);
    let mut bundle = sample_bundle("reporter_usage", "1.0.0", 0);
    bundle.container.runtime = SoraContainerRuntimeV1::Inrou;
    bundle.container.entrypoint = "/app/bin/service".to_owned();
    bundle.container.inrou = Some(sample_inrou_manifest());
    bundle.container.capabilities.network = SoraNetworkPolicyV1::Isolated;
    bundle.service.execution_plane = SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.replicas = NonZeroU16::new(2).expect("nonzero");
    bundle.service.placement_targets = sample_inrou_placement_targets();
    bundle.service.economics.prepaid_runtime_balance =
        "1000000000".parse().expect("large prepaid balance");
    bundle.service.lease_volumes = sample_inrou_lease_volumes();
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    bundle.service.artifacts[0].handler_name = None;
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    soracloud_transaction!(state, block_header, state_block, stx);
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut stx)?;
    insert_active_public_lane_validator(&mut stx, BOB_ID.clone(), 500);
    isi::DeploySoracloudService {
        bundle: bundle.clone(),
        initial_service_configs: BTreeMap::new(),
        initial_service_secrets: BTreeMap::new(),
        precondition: SoraServiceMutationPreconditionV1::ServiceAbsent,
        provenance: bundle_provenance(&bundle),
    }
    .execute(&ALICE_ID, &mut stx)?;
    let lease_started_height = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .expect("hosted service lease")
        .lease_started_height;
    let alice_runtime = sample_inrou_replica_runtime_state_for(
        bundle.service.service_name.clone(),
        &bundle.service.service_version,
        1,
        ALICE_ID.clone(),
    );
    let mut placement = sample_inrou_service_placement_record_for(
        bundle.service.service_name.clone(),
        &bundle.service.service_version,
        &alice_runtime,
    );
    placement.placements[0].lease_started_height = lease_started_height;
    let alice_placement_incarnation = placement.placements[0].placement_incarnation;
    let mut bob_assignment = placement.placements[0].clone();
    bob_assignment.replica_slot = 2;
    bob_assignment.placement_incarnation = Hash::new(b"placement-2");
    let bob_placement_incarnation = bob_assignment.placement_incarnation;
    bob_assignment.validator_account_id = BOB_ID.clone();
    bob_assignment.peer_id = PeerId::from(BOB_ID.expect_single_signatory().clone()).to_string();
    placement.desired_replica_count = 2;
    placement.eligible_validator_count = 2;
    placement.placements.push(bob_assignment);
    stx.world.soracloud_inrou_service_placements.insert(
        (
            placement.service_name.as_ref().to_owned(),
            placement.service_version.clone(),
        ),
        placement,
    );
    let now_ms = stx.block_unix_timestamp_ms().max(1);
    for validator in [&*ALICE_ID, &*BOB_ID] {
        let mut capability =
            sample_inrou_host_capability(validator.clone(), now_ms, now_ms.saturating_add(10_000));
        capability.supported_guest_isas = BTreeSet::from([SoraInrouGuestIsaV1::Aarch64]);
        stx.world
            .soracloud_inrou_host_capabilities
            .insert(validator.clone(), capability);
    }
    let reporting_epoch = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .expect("hosted service lease")
        .reporting_epoch;
    let lease_started_height = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .expect("hosted service lease")
        .lease_started_height;
    for (authority, replica_slot) in [(&*ALICE_ID, 1_u16), (&*BOB_ID, 2_u16)] {
        let placement_incarnation = if replica_slot == 1 {
            alice_placement_incarnation
        } else {
            bob_placement_incarnation
        };
        isi::ReportSoracloudServiceLeaseUsage {
            service_name: bundle.service.service_name.clone(),
            lease_started_height,
            reporting_epoch,
            active_service_version: bundle.service.service_version.clone(),
            replica_slot,
            placement_incarnation,
            replica_accounted_egress_bytes: 0,
            finalize_reporter: false,
        }
        .execute(authority, &mut stx)?;
    }
    stx.apply();
    state_block.commit_world_overlay_for_testing()?;
    Ok(ServiceLeaseUsageFixture {
        state,
        bundle,
        lease_started_height,
        reporting_epoch,
        alice_placement_incarnation,
        bob_placement_incarnation,
    })
}

/// Verify exact accounting, economic lease binding, and idempotent checkpoint delivery.
pub(super) fn verify_reporter_usage_and_replays(
    fixture: &ServiceLeaseUsageFixture,
) -> Result<(SoraServiceDeploymentStateV1, SoraServiceLeaseStateV1), eyre::Report> {
    let state = &fixture.state;
    let bundle = &fixture.bundle;
    let lease_started_height = fixture.lease_started_height;
    let reporting_epoch = fixture.reporting_epoch;
    let alice_placement_incarnation = fixture.alice_placement_incarnation;
    let bob_placement_incarnation = fixture.bob_placement_incarnation;
    let successor_height = lease_started_height
        .checked_add(1)
        .expect("the test lease height has a successor");
    soracloud_transaction_at_height!(state, block_header, state_block, stx, successor_height);

    let baseline = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .cloned()
        .expect("deployment baseline");
    let mut mismatched_volume_clock = baseline.clone();
    mismatched_volume_clock.lease_volume_states[0].lease_expires_height += 1;
    mismatched_volume_clock
        .validate()
        .expect_err("leased-volume economics must match the containing service lease");
    let zero_incarnation_error = isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height: 0,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a zero lease incarnation must fail closed");
    assert_invalid_parameter_contains(
        zero_incarnation_error,
        "lease_started_height must be greater than zero",
    );

    let next_lease_started_height = lease_started_height
        .checked_add(1)
        .expect("fixture lease incarnation has a successor");
    let mut next_incarnation = baseline.clone();
    let next_incarnation_lease = next_incarnation
        .service_lease
        .as_mut()
        .expect("hosted service lease");
    assert!(next_lease_started_height < next_incarnation_lease.lease_expires_height);
    next_incarnation_lease.lease_started_height = next_lease_started_height;
    next_incarnation_lease.egress_reporter_checkpoints.clear();
    for volume in &mut next_incarnation.lease_volume_states {
        volume.lease_started_height = next_lease_started_height;
    }
    next_incarnation
        .validate()
        .expect("successor lease incarnation fixture must remain valid");
    stx.world.soracloud_service_deployments.insert(
        bundle.service.service_name.clone(),
        next_incarnation.clone(),
    );
    let stale_incarnation_error = isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err(
        "a report for an old lease must be rejected even when epoch, revision, and slot match",
    );
    assert_invalid_parameter_contains(stale_incarnation_error, "lease-incarnation CAS expected");
    assert_eq!(
        stx.world
            .soracloud_service_deployments
            .get(&bundle.service.service_name),
        Some(&next_incarnation),
        "a stale lease report must not mutate the current incarnation",
    );
    stx.world
        .soracloud_service_deployments
        .insert(bundle.service.service_name.clone(), baseline.clone());

    let alice_bytes = 1024 * 1024;
    let bob_bytes = 10;

    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)?;
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: bob_bytes,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)?;
    let first_lease = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.clone())
        .expect("first ordered lease");
    let first_accounted_bytes = u128::from(alice_bytes) + u128::from(bob_bytes);
    assert_eq!(first_lease.accounted_egress_bytes, first_accounted_bytes);
    assert_eq!(first_lease.egress_reporter_checkpoints.len(), 2);
    assert!(
        first_lease
            .egress_reporter_checkpoints
            .iter()
            .all(|checkpoint| { checkpoint.reporting_epoch == reporting_epoch })
    );
    first_lease.validate()?;
    let mut invalid_aggregate = first_lease.clone();
    invalid_aggregate.accounted_egress_bytes = 0;
    invalid_aggregate
        .validate()
        .expect_err("the cached aggregate must match reporter checkpoints");
    let mut noncanonical = first_lease.clone();
    noncanonical.egress_reporter_checkpoints.reverse();
    noncanonical
        .validate()
        .expect_err("reporter checkpoints must stay in canonical key order");
    let mut wrong_epoch = first_lease.clone();
    wrong_epoch.egress_reporter_checkpoints[0].reporting_epoch = reporting_epoch.saturating_add(1);
    wrong_epoch
        .validate()
        .expect_err("every checkpoint must belong to its containing reporting epoch");
    let mut oversized = first_lease.clone();
    oversized.egress_reporter_checkpoints.resize(
        SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1 + 1,
        first_lease.egress_reporter_checkpoints[0].clone(),
    );
    oversized
        .validate()
        .expect_err("reporter checkpoint state growth must be protocol bounded");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch.saturating_add(2),
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a report outside the current or exact successor epoch must be rejected");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch.saturating_add(2),
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes,
        finalize_reporter: true,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a delayed terminal report must not finalize another reporting epoch");
    let checkpointed_deployment = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .cloned()
        .expect("checkpointed deployment");
    let mut next_bundle = bundle.clone();
    next_bundle.service.service_version = "2.0.0".to_owned();
    let renewed_lease =
        build_http_service_lease_state(&next_bundle, Some(&checkpointed_deployment), 2, true)?
            .expect("renewed lease");
    assert_eq!(
        renewed_lease.egress_reporter_checkpoints,
        first_lease.egress_reporter_checkpoints
    );
    assert_eq!(renewed_lease.lease_started_height, lease_started_height);
    assert_eq!(renewed_lease.accounted_egress_bytes, first_accounted_bytes);
    let retained_lease =
        build_http_service_lease_state(&next_bundle, Some(&checkpointed_deployment), 2, false)?
            .expect("retained lease");
    assert_eq!(
        retained_lease.egress_reporter_checkpoints,
        first_lease.egress_reporter_checkpoints
    );
    let mut repriced_bundle = next_bundle.clone();
    repriced_bundle.service.economics.egress_price_per_mib =
        "0.000006".parse().expect("changed egress price");
    build_http_service_lease_state(&repriced_bundle, Some(&checkpointed_deployment), 2, true)
        .expect_err("one economic lease must reject retroactive unit-price drift");

    let replay_audit = latest_service_audit_event(&stx, &bundle.service.service_name);
    let replay_sequence = crate::soracloud_runtime::latest_soracloud_sequence(&stx.world);
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)?;
    assert_eq!(
        latest_service_audit_event(&stx, &bundle.service.service_name),
        replay_audit
    );
    assert_eq!(
        crate::soracloud_runtime::latest_soracloud_sequence(&stx.world),
        replay_sequence
    );
    let replayed_lease = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.clone())
        .expect("replayed lease");
    assert_eq!(
        replayed_lease.egress_reporter_checkpoints,
        first_lease.egress_reporter_checkpoints
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes,
        finalize_reporter: true,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("an active assignment must not seal its reporter checkpoint");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes - 1,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a reporter checkpoint must not decrease");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: u64::MAX,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("a validator must not spoof another replica slot");

    stx.apply();
    state_block.commit_world_overlay_for_testing()?;
    Ok((baseline, first_lease))
}

/// Commit terminal delivery and exact-counter reopening for a retired reporter.
pub(super) fn verify_reporter_finalization_and_reopening(
    fixture: &ServiceLeaseUsageFixture,
) -> Result<(), eyre::Report> {
    let state = &fixture.state;
    let bundle = &fixture.bundle;
    let lease_started_height = fixture.lease_started_height;
    let reporting_epoch = fixture.reporting_epoch;
    let alice_placement_incarnation = fixture.alice_placement_incarnation;
    let alice_bytes = 1024 * 1024;
    soracloud_transaction_at_height!(state, block_header, state_block, stx, 4);

    let placement_key = (
        bundle.service.service_name.as_ref().to_owned(),
        bundle.service.service_version.clone(),
    );
    let mut retired_alice_placement = stx
        .world
        .soracloud_inrou_service_placements
        .get(&placement_key)
        .cloned()
        .expect("two-reporter placement");
    let alice_assignment_index = retired_alice_placement
        .placements
        .iter()
        .position(|assignment| {
            assignment.replica_slot == 1 && assignment.validator_account_id == *ALICE_ID
        })
        .expect("Alice placement");
    let alice_assignment = retired_alice_placement.placements[alice_assignment_index].clone();
    let successor_assignment = &mut retired_alice_placement.placements[alice_assignment_index];
    successor_assignment.validator_account_id = CARPENTER_ID.clone();
    successor_assignment.peer_id =
        PeerId::from(CARPENTER_ID.expect_single_signatory().clone()).to_string();
    stx.world
        .soracloud_inrou_service_placements
        .insert(placement_key.clone(), retired_alice_placement.clone());
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: alice_bytes + 1,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a former reporter may only submit a terminal checkpoint");
    let terminal_alice_bytes = alice_bytes + 1;
    let terminal = isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: terminal_alice_bytes,
        finalize_reporter: true,
    };
    terminal.clone().execute(&ALICE_ID, &mut stx)?;
    let terminal_deployment = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .cloned()
        .expect("terminal deployment");
    let terminal_audit = latest_service_audit_event(&stx, &bundle.service.service_name);
    let terminal_sequence = crate::soracloud_runtime::latest_soracloud_sequence(&stx.world);
    terminal.execute(&ALICE_ID, &mut stx)?;
    assert_eq!(
        stx.world
            .soracloud_service_deployments
            .get(&bundle.service.service_name),
        Some(&terminal_deployment)
    );
    assert_eq!(
        latest_service_audit_event(&stx, &bundle.service.service_name),
        terminal_audit
    );
    assert_eq!(
        crate::soracloud_runtime::latest_soracloud_sequence(&stx.world),
        terminal_sequence
    );
    let finalized_checkpoint = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .and_then(|lease| {
            lease.egress_reporter_checkpoints.iter().find(|checkpoint| {
                checkpoint.assignment.placement.replica_slot == 1
                    && checkpoint.assignment.placement.validator_account_id == *ALICE_ID
            })
        })
        .expect("finalized Alice checkpoint");
    assert!(finalized_checkpoint.finalize_reporter);
    assert_eq!(
        finalized_checkpoint.accounted_egress_bytes, terminal_alice_bytes,
        "a former reporter's one terminal update must retain final in-flight usage"
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: terminal_alice_bytes + 1,
        finalize_reporter: true,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a sealed former reporter must not advance again");
    retired_alice_placement.placements[alice_assignment_index] = alice_assignment;
    stx.world
        .soracloud_inrou_service_placements
        .insert(placement_key, retired_alice_placement);
    let reopen_with_increase_error = isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: terminal_alice_bytes + 1,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a finalized checkpoint must reopen at its exact terminal byte value");
    assert_invalid_parameter_contains(reopen_with_increase_error, "exact terminal byte value");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: terminal_alice_bytes,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)?;
    let reopened_checkpoint = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .and_then(|lease| {
            lease.egress_reporter_checkpoints.iter().find(|checkpoint| {
                checkpoint.assignment.placement.replica_slot == 1
                    && checkpoint.assignment.placement.validator_account_id == *ALICE_ID
            })
        })
        .expect("reopened Alice checkpoint");
    assert!(!reopened_checkpoint.finalize_reporter);
    assert_eq!(
        reopened_checkpoint.accounted_egress_bytes, terminal_alice_bytes,
        "reopening must preserve the finalized checkpoint's terminal counter"
    );

    stx.apply();
    state_block.commit_world_overlay_for_testing()?;
    Ok(())
}

/// Verify bounded epoch settlement and reject delayed writes to replacement placements.
pub(super) fn verify_reporter_rollover_and_placement_incarnation(
    fixture: &ServiceLeaseUsageFixture,
    baseline: &SoraServiceDeploymentStateV1,
    first_lease: &SoraServiceLeaseStateV1,
) -> Result<(), eyre::Report> {
    let state = &fixture.state;
    let bundle = &fixture.bundle;
    let lease_started_height = fixture.lease_started_height;
    let reporting_epoch = fixture.reporting_epoch;
    let alice_placement_incarnation = fixture.alice_placement_incarnation;
    let bob_placement_incarnation = fixture.bob_placement_incarnation;
    let terminal_alice_bytes = 1024 * 1024 + 1;
    soracloud_transaction_at_height!(state, block_header, state_block, stx, 5);
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: terminal_alice_bytes + 1,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)?;
    let increased_checkpoint = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .and_then(|lease| {
            lease.egress_reporter_checkpoints.iter().find(|checkpoint| {
                checkpoint.assignment.placement.replica_slot == 1
                    && checkpoint.assignment.placement.validator_account_id == *ALICE_ID
            })
        })
        .expect("increased Alice checkpoint");
    assert_eq!(
        increased_checkpoint.accounted_egress_bytes,
        terminal_alice_bytes + 1,
        "a reopened checkpoint may resume monotonic reporting in a later block"
    );

    let mut capped_deployment = baseline.clone();
    let capped_lease = capped_deployment.service_lease.as_mut().expect("lease");
    let capped_checkpoint = first_lease.egress_reporter_checkpoints[0].clone();
    capped_lease.settled_egress_bytes = 7;
    capped_lease.egress_reporter_checkpoints = (0
        ..SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1)
        .map(|index| SoraServiceLeaseEgressCheckpointV1 {
            assignment: SoraServiceLeaseReporterAssignmentV1 {
                service_version: format!("retired-{index:04}"),
                ..capped_checkpoint.assignment.clone()
            },
            accounted_egress_bytes: 1,
            finalize_reporter: true,
            ..capped_checkpoint.clone()
        })
        .collect();
    capped_lease
        .refresh_accounted_egress_bytes()
        .expect("bounded capped reporter aggregate");
    let capped_volumes = capped_deployment.lease_volume_states.clone();
    let capped_lease_started_height = capped_lease.lease_started_height;
    let capped_lease_expires_height = capped_lease.lease_expires_height;
    stx.world.soracloud_service_deployments.insert(
        bundle.service.service_name.clone(),
        capped_deployment.clone(),
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("a full current-epoch table must reject a new identity without rollover");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 2,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must reject a skipped reporting epoch");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 1,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must reject a nonzero successor counter");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: true,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must reject a finalized successor counter");

    let mut manager_unassigned_placement = stx
        .world
        .soracloud_inrou_service_placements
        .get(&(
            bundle.service.service_name.as_ref().to_owned(),
            bundle.service.service_version.clone(),
        ))
        .cloned()
        .expect("reporter placement");
    let manager_assignment = manager_unassigned_placement
        .placements
        .iter_mut()
        .find(|assignment| assignment.validator_account_id == *ALICE_ID)
        .expect("Alice placement");
    manager_assignment.validator_account_id = CARPENTER_ID.clone();
    manager_assignment.peer_id =
        PeerId::from(CARPENTER_ID.expect_single_signatory().clone()).to_string();
    stx.world.soracloud_inrou_service_placements.insert(
        (
            bundle.service.service_name.as_ref().to_owned(),
            bundle.service.service_version.clone(),
        ),
        manager_unassigned_placement,
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        placement_incarnation: alice_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("Soracloud manager authority must not substitute for an exact reporter assignment");

    let mut nonterminal_deployment = capped_deployment.clone();
    nonterminal_deployment
        .service_lease
        .as_mut()
        .expect("lease")
        .egress_reporter_checkpoints[0]
        .finalize_reporter = false;
    stx.world.soracloud_service_deployments.insert(
        bundle.service.service_name.clone(),
        nonterminal_deployment.clone(),
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must preserve unknown usage until every terminal report arrives");
    assert_eq!(
        stx.world
            .soracloud_service_deployments
            .get(&bundle.service.service_name),
        Some(&nonterminal_deployment)
    );

    let mut actively_placed_deployment = capped_deployment.clone();
    let actively_placed_checkpoint = &mut actively_placed_deployment
        .service_lease
        .as_mut()
        .expect("lease")
        .egress_reporter_checkpoints[0];
    let active_bob_assignment = stx
        .world
        .soracloud_inrou_service_placements
        .get(&(
            bundle.service.service_name.as_ref().to_owned(),
            bundle.service.service_version.clone(),
        ))
        .and_then(|record| {
            record
                .placements
                .iter()
                .find(|placement| placement.replica_slot == 2)
                .map(|placement| (placement.clone(), record.reconciled_at_ms))
        })
        .expect("active Bob assignment");
    actively_placed_checkpoint.assignment.service_version = bundle.service.service_version.clone();
    actively_placed_checkpoint.assignment.placement = active_bob_assignment.0;
    actively_placed_checkpoint
        .assignment
        .placement_reconciled_at_ms = active_bob_assignment.1;
    actively_placed_deployment
        .service_lease
        .as_mut()
        .expect("lease")
        .egress_reporter_checkpoints
        .sort_by(|left, right| {
            (
                left.reporting_epoch,
                left.assignment.service_version.as_str(),
                left.assignment.placement.replica_slot,
                left.assignment.placement.placement_incarnation,
                &left.assignment.placement.validator_account_id,
            )
                .cmp(&(
                    right.reporting_epoch,
                    right.assignment.service_version.as_str(),
                    right.assignment.placement.replica_slot,
                    right.assignment.placement.placement_incarnation,
                    &right.assignment.placement.validator_account_id,
                ))
        });
    stx.world.soracloud_service_deployments.insert(
        bundle.service.service_name.clone(),
        actively_placed_deployment,
    );
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must reject any prior checkpoint key that remains actively placed");

    let mut overflowing_deployment = capped_deployment.clone();
    overflowing_deployment
        .service_lease
        .as_mut()
        .expect("lease")
        .settled_egress_bytes = u128::MAX;
    stx.world
        .soracloud_service_deployments
        .insert(bundle.service.service_name.clone(), overflowing_deployment);
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must reject cumulative settled-byte overflow");

    let mut exhausted_sequence_event =
        latest_service_audit_event(&stx, &bundle.service.service_name)
            .expect("existing service audit event");
    exhausted_sequence_event.sequence = u64::MAX;
    let sequence_before_exhaustion =
        crate::soracloud_runtime::latest_soracloud_sequence(&stx.world);
    *stx.world.soracloud_sequence_watermark.get_mut() = u64::MAX;
    stx.world
        .soracloud_service_audit_events
        .insert(u64::MAX, exhausted_sequence_event);
    let audit_exhausted_deployment = capped_deployment.clone();
    stx.world.soracloud_service_deployments.insert(
        bundle.service.service_name.clone(),
        audit_exhausted_deployment.clone(),
    );
    let audit_exhaustion_error = isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height: capped_lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("rollover must fail atomically when no unique audit sequence remains");
    assert_invariant_contains(audit_exhaustion_error, "audit sequence is exhausted");
    assert_eq!(
        stx.world
            .soracloud_service_deployments
            .get(&bundle.service.service_name),
        Some(&audit_exhausted_deployment),
        "audit failure must not persist the prepared epoch settlement"
    );
    stx.world.soracloud_service_audit_events.remove(u64::MAX);
    *stx.world.soracloud_sequence_watermark.get_mut() = sequence_before_exhaustion;

    stx.world
        .soracloud_service_deployments
        .insert(bundle.service.service_name.clone(), capped_deployment);
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)?;
    let rolled_deployment = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .expect("rolled deployment");
    let rolled_lease = rolled_deployment
        .service_lease
        .as_ref()
        .expect("rolled lease");
    assert_eq!(rolled_lease.reporting_epoch, reporting_epoch + 1);
    assert_eq!(rolled_lease.settled_egress_bytes, 7 + 4_096);
    assert_eq!(rolled_lease.accounted_egress_bytes, 7 + 4_096);
    assert_eq!(
        rolled_lease.lease_started_height,
        capped_lease_started_height
    );
    assert_eq!(
        rolled_lease.lease_expires_height,
        capped_lease_expires_height
    );
    assert_eq!(rolled_deployment.lease_volume_states, capped_volumes);
    assert_eq!(rolled_lease.egress_reporter_checkpoints.len(), 1);
    let successor_checkpoint = &rolled_lease.egress_reporter_checkpoints[0];
    assert_eq!(successor_checkpoint.reporting_epoch, reporting_epoch + 1);
    assert_eq!(
        successor_checkpoint
            .assignment
            .placement
            .validator_account_id,
        *BOB_ID
    );
    assert_eq!(successor_checkpoint.accounted_egress_bytes, 0);
    assert!(!successor_checkpoint.finalize_reporter);
    let rollover_event = latest_service_audit_event(&stx, &bundle.service.service_name)
        .expect("reporting epoch rollover audit event");
    assert_eq!(
        rollover_event.action,
        SoraServiceLifecycleActionV1::LeaseReportingEpochRollover
    );
    let mut invalid_rollover_event = rollover_event.clone();
    invalid_rollover_event
        .lease_reporting_epoch_rollover
        .as_mut()
        .expect("typed rollover payload")
        .new_reporting_epoch += 1;
    invalid_rollover_event
        .validate()
        .expect_err("rollover audit payload must bind the exact successor epoch");
    let rollover = rollover_event
        .lease_reporting_epoch_rollover
        .expect("typed rollover payload");
    assert_eq!(rollover.lease_started_height, capped_lease_started_height);
    assert_eq!(rollover.previous_reporting_epoch, reporting_epoch);
    assert_eq!(rollover.new_reporting_epoch, reporting_epoch + 1);
    assert_eq!(rollover.reporter_account_id, *BOB_ID);
    assert_eq!(rollover.placement_incarnation, bob_placement_incarnation);
    assert_eq!(rollover.settled_egress_bytes_delta, 4_096);
    assert_eq!(rollover.settled_egress_bytes, 7 + 4_096);
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height,
        reporting_epoch,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("a stale pre-rollover report must fail closed");

    let returned_placement_key = (
        bundle.service.service_name.as_ref().to_owned(),
        bundle.service.service_version.clone(),
    );
    let mut transit_placement = stx
        .world
        .soracloud_inrou_service_placements
        .get(&returned_placement_key)
        .cloned()
        .expect("active placement after rollover");
    let transit_incarnation = Hash::new(b"bob-placement-transit");
    transit_placement
        .placements
        .iter_mut()
        .find(|assignment| assignment.replica_slot == 2)
        .expect("Bob assignment")
        .placement_incarnation = transit_incarnation;
    stx.world
        .soracloud_inrou_service_placements
        .insert(returned_placement_key.clone(), transit_placement.clone());
    let returned_incarnation = Hash::new(b"bob-placement-returned");
    transit_placement
        .placements
        .iter_mut()
        .find(|assignment| assignment.replica_slot == 2)
        .expect("Bob returned assignment")
        .placement_incarnation = returned_incarnation;
    stx.world
        .soracloud_inrou_service_placements
        .insert(returned_placement_key, transit_placement);

    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height: capped_lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("an A-to-B-to-A delayed report must not target the returned placement");
    let mut returned_runtime = sample_inrou_replica_runtime_state_for(
        bundle.service.service_name.clone(),
        &bundle.service.service_version,
        2,
        BOB_ID.clone(),
    );
    returned_runtime.placement_incarnation = returned_incarnation;
    returned_runtime.reporting_epoch = reporting_epoch + 1;
    returned_runtime.materialized_bundle_hash = bundle.container.bundle_hash;
    let missing_checkpoint = isi::SetSoracloudInrouReplicaRuntimeState {
        state: returned_runtime.clone(),
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("a returned placement must not serve using its predecessor's checkpoint");
    assert_invariant_contains(missing_checkpoint, "must open its zero usage checkpoint");
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height: capped_lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: returned_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: false,
    }
    .execute(&BOB_ID, &mut stx)?;

    let returned_runtime_key = inrou_replica_runtime_key(
        &returned_runtime.service_name,
        &returned_runtime.service_version,
        returned_runtime.replica_slot,
    );
    let returned_lease = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .expect("returned placement lease");
    assert_eq!(returned_lease.egress_reporter_checkpoints.len(), 2);
    returned_lease.validate()?;
    isi::SetSoracloudInrouReplicaRuntimeState {
        state: returned_runtime.clone(),
    }
    .execute(&BOB_ID, &mut stx)?;
    isi::ReportSoracloudServiceLeaseUsage {
        service_name: bundle.service.service_name.clone(),
        lease_started_height: capped_lease_started_height,
        reporting_epoch: reporting_epoch + 1,
        active_service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        placement_incarnation: bob_placement_incarnation,
        replica_accounted_egress_bytes: 0,
        finalize_reporter: true,
    }
    .execute(&BOB_ID, &mut stx)?;
    let returned_lease = stx
        .world
        .soracloud_service_deployments
        .get(&bundle.service.service_name)
        .and_then(|deployment| deployment.service_lease.as_ref())
        .expect("returned placement lease after predecessor finalization");
    for checkpoint in &returned_lease.egress_reporter_checkpoints {
        assert_eq!(
            checkpoint.finalize_reporter,
            checkpoint.assignment.placement.placement_incarnation == bob_placement_incarnation,
            "only the retired placement's exact checkpoint may be finalized"
        );
    }
    isi::ClearSoracloudInrouReplicaRuntimeState {
        service_name: bundle.service.service_name.clone(),
        service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        expected_placement_incarnation: bob_placement_incarnation,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("an A-to-B-to-A delayed clear must not erase the returned placement state");
    assert_eq!(
        stx.world
            .soracloud_inrou_replica_runtime
            .get(&returned_runtime_key),
        Some(&returned_runtime)
    );
    isi::ClearSoracloudInrouReplicaRuntimeState {
        service_name: bundle.service.service_name.clone(),
        service_version: bundle.service.service_version.clone(),
        replica_slot: 2,
        expected_placement_incarnation: returned_incarnation,
    }
    .execute(&BOB_ID, &mut stx)?;
    assert!(
        stx.world
            .soracloud_inrou_replica_runtime
            .get(&returned_runtime_key)
            .is_none()
    );

    let fresh_lease = build_http_service_lease_state(
        bundle,
        None,
        lease_started_height.saturating_add(100),
        false,
    )?
    .expect("fresh hosted-service lease");
    assert!(fresh_lease.egress_reporter_checkpoints.is_empty());
    assert_eq!(fresh_lease.accounted_egress_bytes, 0);
    assert_eq!(fresh_lease.reporting_epoch, 1);
    assert_eq!(fresh_lease.settled_egress_bytes, 0);
    assert_ne!(fresh_lease.lease_started_height, lease_started_height);

    Ok(())
}
