// Exact current/pending custody persistence through the native credential corridor.

#[test]
fn prepared_beacon_credential_append_retains_incumbent_and_pending_across_restart() {
    let budget = test_credential_budget();
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1;
    use iroha_data_model::{
        nexus::{
            ValidatorCommitteeCredentialsV1, ValidatorCommitteePreparationV1,
            ValidatorCommitteeTransitionV1,
        },
    };
    use iroha_model_base::peer::PeerId;
    let network_id = network_id_v1(0xC1);
    let mut keys = (1..=7_u8)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let peers = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let local_peer = beacon_fixture_roster_v1(4)[0].clone();
    let pending_seat = u16::try_from(
        peers
            .iter()
            .position(|peer| peer == &local_peer)
            .expect("incumbent must be in the target committee")
            + 1,
    )
    .unwrap();
    let incumbent = beacon_fixture_v1(network_id, 0x81, &budget);
    let preparation = ValidatorCommitteePreparationV1 {
        version: 1,
        network_id,
        selection_epoch: 0,
        selection_height: 100,
        selection_anchor: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"frozen selection parent",
        )),
        target_epoch: 2,
        first_height: 201,
        last_height: 300,
        authority_generation: 1,
        preparing_authorization_id: [0x91; 32],
        election_seed: [0x92; 32],
        eligibility: iroha_data_model::nexus::ValidatorElectionPolicyV1 {
            epoch_length_blocks: 100,
            ..iroha_data_model::nexus::ValidatorElectionPolicyV1::from_npos_parameters(
                &iroha_data_model::parameter::system::SumeragiNposParameters::default(),
            )
            .unwrap()
        },
        committee: keys
            .iter()
            .map(
                |key| iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1 {
                    validator: PeerId::new(key.public_key().clone()),
                    proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .unwrap(),
                },
            )
            .collect(),
    };
    let (pending_record, pending_components) =
        iroha_core::beacon::complete_beacon_dkg_fixture_for_exact_session_v1(
            iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1 {
                version: iroha_data_model::consensus::GLOBAL_THRESHOLD_BEACON_VERSION_V1,
                network_id,
                session_id: preparation.beacon_session_id().unwrap(),
                attempt_id: preparation.transition_id().unwrap(),
                authority_generation: preparation.authority_generation,
                roster_hash: iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&peers),
                committee_size: 7,
                threshold: 3,
                start_height: preparation.selection_height + 1,
                commitments_end_height: preparation.selection_height + 2,
                deliveries_end_height: preparation.selection_height + 3,
                acceptances_end_height: preparation.selection_height + 4,
            },
            pending_seat,
        );
    let pending = BeaconFixtureV1 {
        validated: validate_global_threshold_beacon_session_v1(
            &pending_record,
            &beacon_binding_v1(&pending_record),
            &budget,
        )
        .unwrap(),
        record: pending_record,
        components: pending_components,
    };
    let transition = ValidatorCommitteeTransitionV1 {
        preparation,
        credentials: Some(ValidatorCommitteeCredentialsV1 {
            beacon: InstalledBeaconEpochBindingV1 {
                session_id: pending.record.session_id,
                transcript_hash: pending.record.transcript_hash,
            },
        }),
        readiness: vec![],
        outcome: None,
    };
    transition.validate().unwrap();
    let provisioning = vec![RuntimeGlobalBeaconShareProvisioningV1::new(
        incumbent.validated.clone(),
        1,
        incumbent.components,
    )];
    let old_policy =
        global_beacon_partial_signer_inventory_digest_v1(network_id, &provisioning).unwrap();
    let old_catalog = beacon_catalog_v1(old_policy);
    let binding = old_catalog.iter().next().unwrap();
    let old = beacon_credential_fixture_v1(
        network_id,
        HANDLE,
        REVISION,
        old_policy,
        provisioning,
        &budget,
    )
    .unwrap();
    let old_digest = Hash::new(old.as_slice());
    let pending_share = || {
        RuntimeGlobalBeaconShareProvisioningV1::new(
            pending.validated.clone(),
            pending_seat,
            Zeroizing::new(*pending.components),
        )
    };
    for invalid in 0..4 {
        let mut changed = transition.clone();
        let revision = if invalid == 0 { REVISION } else { REVISION + 1 };
        let share = match invalid {
            0 => pending_share(),
            1 => {
                changed.credentials.as_mut().unwrap().beacon.transcript_hash[0] ^= 1;
                pending_share()
            }
            2 => RuntimeGlobalBeaconShareProvisioningV1::new(
                pending.validated.clone(),
                if pending_seat == 1 { 2 } else { 1 },
                Zeroizing::new(*pending.components),
            ),
            _ => {
                let mut components = Zeroizing::new(*pending.components);
                components[0] = [0; 32];
                RuntimeGlobalBeaconShareProvisioningV1::new(
                    pending.validated.clone(),
                    pending_seat,
                    components,
                )
            }
        };
        assert!(
            prepare_global_beacon_transition_credential_v1(
                Some((&old, binding)),
                HANDLE,
                revision,
                &changed,
                &local_peer,
                &share,
                &budget
            )
            .is_err(),
            "invalid append {invalid}"
        );
        assert_eq!(Hash::new(old.as_slice()), old_digest);
        let original =
            decode_global_beacon_runtime_signer_v1(&old, &network_id, binding, &budget).unwrap();
        original
            .attest_partial_signing_capability(&incumbent.validated, 1)
            .unwrap();
        assert!(
            original
                .attest_partial_signing_capability(&pending.validated, pending_seat)
                .is_err()
        );
    }
    for mismatch in ["attempt", "generation", "preparation-window", "cutoff"] {
        let mut wrong_session = pending.record.adaptive_dkg.session;
        match mismatch {
            "attempt" => wrong_session.attempt_id[0] ^= 1,
            "generation" => wrong_session.authority_generation += 1,
            "preparation-window" => {
                wrong_session.start_height -= 1;
                wrong_session.commitments_end_height -= 1;
                wrong_session.deliveries_end_height -= 1;
                wrong_session.acceptances_end_height -= 1;
            }
            "cutoff" => {
                wrong_session.start_height = 197;
                wrong_session.commitments_end_height = 198;
                wrong_session.deliveries_end_height = 199;
                wrong_session.acceptances_end_height = 200;
            }
            _ => unreachable!("fixed mismatch cases"),
        }
        let (wrong_record, wrong_components) =
            iroha_core::beacon::complete_beacon_dkg_fixture_for_exact_session_v1(
                wrong_session,
                pending_seat,
            );
        let wrong_session = validate_global_threshold_beacon_session_v1(
            &wrong_record,
            &beacon_binding_v1(&wrong_record),
            &budget,
        )
        .expect("the wrong-binding DKG is independently valid");
        let mut changed = transition.clone();
        changed.credentials.as_mut().unwrap().beacon.transcript_hash = wrong_record.transcript_hash;
        assert!(
            prepare_global_beacon_transition_credential_v1(
                Some((&old, binding)),
                HANDLE,
                REVISION + 1,
                &changed,
                &local_peer,
                &RuntimeGlobalBeaconShareProvisioningV1::new(
                    wrong_session,
                    pending_seat,
                    wrong_components,
                ),
                &budget
            )
            .is_err(),
            "valid DKG with wrong {mismatch} must not provision the frozen transition"
        );
    }
    let retained_once =
        decode_global_beacon_credential_shares_v1(&old, &network_id, binding, &budget).unwrap();
    assert!(retained_once.iter().all(|entry| entry.belongs_to(&budget)));
    let pending_original = pending_share();
    let retained_owner = retained_once[0].authenticated_session().clone();
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let error = super::prepared::prepare_global_beacon_transition_from_retained_v1(
        Some((retained_once.as_slice(), binding)),
        HANDLE,
        REVISION + 1,
        &transition,
        &local_peer,
        &pending_original,
        &budget,
    )
    .err()
    .expect("actual output backing must be admitted too");
    let RuntimeConsensusThresholdSignerCredentialErrorV1::Output(
        GlobalBeaconCredentialEncodeErrorV1::Admission(ref original),
    ) = error
    else {
        panic!("preserve actual output admission cause")
    };
    let iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes, ..
    } = original
    else {
        panic!("original occupied pool")
    };
    assert_eq!(
        *original,
        budget.try_reserve_bytes(*requested_bytes).unwrap_err()
    );
    assert!(
        retained_once[0]
            .authenticated_session()
            .ptr_eq(&retained_owner)
    );
    assert_eq!(Hash::new(old.as_slice()), old_digest);
    drop(held);
    let from_originals = super::prepared::prepare_global_beacon_transition_from_retained_v1(
        Some((retained_once.as_slice(), binding)),
        HANDLE,
        REVISION + 1,
        &transition,
        &local_peer,
        &pending_original,
        &budget,
    )
    .expect(
        "same retained graphs and pending secret retry unchanged after output capacity returns",
    );
    let prepared = prepare_global_beacon_transition_credential_v1(
        Some((&old, binding)),
        HANDLE,
        REVISION + 1,
        &transition,
        &local_peer,
        &pending_share(),
        &budget,
    )
    .unwrap();
    assert_eq!(Hash::new(old.as_slice()), old_digest);
    assert_eq!(
        from_originals.credential.as_slice(),
        prepared.credential.as_slice()
    );
    let foreign = test_credential_budget();
    assert!(matches!(
        super::prepared::prepare_global_beacon_transition_from_retained_v1(
            None,
            HANDLE,
            REVISION + 1,
            &transition,
            &local_peer,
            &pending_share(),
            &foreign
        ),
        Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Session(
            GlobalThresholdBeaconSessionError::ForeignReservation
        ))
    ));
    let catalog = beacon_catalog_with_revision_v1(prepared.revision, prepared.policy_digest);
    let (_guard, directory) = secure_credential_directory_v1();
    write_credential_v1(
        &directory,
        GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
        &prepared.credential,
        0o600,
    );
    // Restart both before and after external certified activation uses the identical inventory.
    // The provider has no activation pointer; callers still supply the authenticated session.
    for _restart in 0..2 {
        let restarted =
            RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                &catalog,
                Some(&directory),
                &budget,
            )
            .unwrap();
        let backend = restarted.global_beacon.as_ref().unwrap();
        for (session, seat) in [
            (&incumbent.validated, 1),
            (&pending.validated, pending_seat),
        ] {
            backend
                .attest_partial_signing_capability(session, seat)
                .unwrap();
            let mut verifier = beacon_pulse_aggregator_v1(session, 0xA2);
            let partial = backend.sign_partial(session, verifier.payload()).unwrap();
            verifier.accept_partial(partial).unwrap();
        }
    }
    assert!(
        prepare_global_beacon_transition_credential_v1(
            Some((&prepared.credential, catalog.iter().next().unwrap())),
            HANDLE,
            REVISION + 2,
            &transition,
            &local_peer,
            &pending_share(),
            &budget
        )
        .is_err()
    );
    assert!(
        decode_global_beacon_runtime_signer_v1(&prepared.credential, &network_id, binding, &budget,).is_err()
    );
    let joining = prepare_global_beacon_transition_credential_v1(
        None,
        HANDLE,
        1,
        &transition,
        &local_peer,
        &pending_share(),
        &budget,
    )
    .unwrap();
    let joining_catalog = beacon_catalog_with_revision_v1(1, joining.policy_digest);
    let joining_provider = decode_global_beacon_runtime_signer_v1(
        &joining.credential,
        &network_id,
        joining_catalog.iter().next().unwrap(),
        &budget,
    )
    .unwrap();
    joining_provider
        .attest_partial_signing_capability(&pending.validated, pending_seat)
        .unwrap();
    assert!(
        joining_provider
            .attest_partial_signing_capability(&incumbent.validated, 1)
            .is_err()
    );
}

#[test]
fn prepared_beacon_restart_preserves_exact_session_inventory_for_every_four_and_seven_seat() {
    let budget = test_credential_budget();
    use iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1;
    let network = network_id_v1(0xC1);
    for (current_size, pending_size) in [(4, 7), (7, 4)] {
        let current_roster = beacon_fixture_roster_v1(current_size);
        let pending_roster = beacon_fixture_roster_v1(pending_size);
        for pending_seat in 1..=pending_size {
            let peer = &pending_roster[usize::from(pending_seat - 1)];
            let current_seat = current_roster
                .iter()
                .position(|current| current == peer)
                .map(|offset| u16::try_from(offset + 1).unwrap());
            let current = current_seat.map(|seat| {
                beacon_fixture_for_seat_v1(
                    network,
                    [0x61; 32],
                    current_size,
                    beacon_fixture_roster_hash_v1(current_size),
                    seat,
                    &budget,
                )
            });
            let pending = beacon_fixture_for_seat_v1(
                network,
                [0x62; 32],
                pending_size,
                beacon_fixture_roster_hash_v1(pending_size),
                pending_seat,
                &budget,
            );
            let mut shares = Vec::new();
            if let Some(current) = &current {
                shares.push(RuntimeGlobalBeaconShareProvisioningV1::new(
                    current.validated.clone(),
                    current_seat.unwrap(),
                    Zeroizing::new(*current.components),
                ));
            }
            shares.push(RuntimeGlobalBeaconShareProvisioningV1::new(
                pending.validated.clone(),
                pending_seat,
                Zeroizing::new(*pending.components),
            ));
            let policy =
                global_beacon_partial_signer_inventory_digest_v1(network, &shares).unwrap();
            let catalog = IrohaRuntimeProviderBindingsV1::with_prepared_beacon_inventory_v1(
                None,
                "beacon-restart-test",
                network,
                HANDLE,
                REVISION,
                policy,
                budget.limit_bytes(),
            )
            .unwrap();
            let credential =
                beacon_credential_fixture_v1(network, HANDLE, REVISION, policy, shares, &budget)
                    .unwrap();
            let retained_shares = decode_global_beacon_credential_shares_v1(
                &credential,
                &network,
                catalog.iter().next().unwrap(),
                &budget,
            )
            .unwrap();
            if let Some(current) = &current {
                let active = InstalledBeaconEpochBindingV1 {
                    session_id: current.record.session_id,
                    transcript_hash: current.record.transcript_hash,
                };
                super::provisioning_command::validate_retained_incumbent(
                    &retained_shares,
                    current_seat,
                    active,
                )
                .unwrap();
                assert!(
                    super::provisioning_command::validate_retained_incumbent(
                        &retained_shares,
                        current_seat,
                        InstalledBeaconEpochBindingV1 {
                            session_id: [0xEF; 32],
                            ..active
                        },
                    )
                    .is_err()
                );
            }
            let (_guard, directory) = secure_credential_directory_v1();
            write_credential_v1(
                &directory,
                GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
                &credential,
                0o600,
            );
            for _restart in 0..2 {
                let catalog = IrohaRuntimeProviderBindingsV1::load_canonical_v1(
                    &catalog.export_canonical_v1().unwrap(),
                )
                .unwrap();
                let restarted =
                    RuntimeConsensusThresholdSignerBackendsV1::load_from_credential_directory_v1(
                        &catalog,
                        Some(&directory),
                        &budget,
                    )
                    .unwrap();
                let provider = restarted.global_beacon.unwrap();
                for (session, seat) in current
                    .iter()
                    .zip(current_seat)
                    .map(|(value, seat)| (&value.validated, seat))
                    .chain(std::iter::once((&pending.validated, pending_seat)))
                {
                    provider
                        .attest_partial_signing_capability(session, seat)
                        .unwrap();
                    let mut aggregator = beacon_pulse_aggregator_v1(session, 0xA5);
                    aggregator
                        .accept_partial(
                            provider
                                .sign_partial(session, aggregator.payload())
                                .unwrap(),
                        )
                        .unwrap();
                    let other_seat = if seat == 1 { 2 } else { 1 };
                    assert!(
                        provider
                            .attest_partial_signing_capability(session, other_seat)
                            .is_err()
                    );
                }
            }
        }
    }
}
