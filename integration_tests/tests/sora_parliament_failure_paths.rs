//! Four-validator failure-path coverage for SORA Parliament attempt custody.

use super::*;
use iroha::data_model::{
    asset::{AssetBalancePolicy, AssetDefinition},
    domain::Domain,
    governance::types::{
        BodyElectionAttemptStatusV1, GovernanceCertificateV1, GovernanceExpectedHeadPresentV1,
        GovernanceExpectedHeadV1, MAX_PARLIAMENT_SORTITION_RETRIES_V1,
        MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1, ParliamentBallotFailureKindV1,
        RuntimeUpgradeProposal, parliament_execution_failure_root_v1,
    },
    isi::governance::{ProposeRuntimeUpgradeProposal, UnregisterCitizen},
    prelude::{AssetDefinitionId, AssetId, FindAssetById, Mint, Quantity},
    runtime::RuntimeUpgradeManifest,
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias,
};
use iroha_executor_data_model::permission::governance::CanProposeRuntimeUpgrade;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::BOB_ID;

const CAPACITY_BOND_AMOUNT: u64 = 37;
const CAPACITY_PUBLIC_SEATS: u32 = 1;
const CAPACITY_HIDDEN_SEATS: u32 = MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1;
const CAPACITY_SORTITION_DELAY_BLOCKS: u64 = 4;
const CONFIRMATION_CITIZENS: usize = 22;
const CONFIRMATION_POLICY_SEATS: u32 = 21;
const CONFIRMATION_INVITATION_BLOCKS: u64 = 68;
const CONFIRMATION_REGISTRATION_BLOCKS: u64 = 66;
const CONFIRMATION_SURVIVOR_FREEZE_PHASE_BLOCKS: u64 = 32;
const TERMINAL_SURVIVOR_FREEZE_PHASE_BLOCKS: u64 = 8;
const BALLOT_COMMITMENT_PHASE_BLOCKS: u64 = 4;
const CONFIRMATION_RELEASE_DELAY_BLOCKS: u64 = 4;
const CONFIRMATION_OPENING_BLOCKS: u64 = 8;
const TERMINAL_POLICY_SEATS: u32 = 3;
const TERMINAL_REGISTRATION_BLOCKS: u64 = 12;
const TERMINAL_ENACTMENT_DELAY: u64 = 4;

pub(super) struct ThresholdSessionsV1 {
    pub(super) logical_beacon: BeaconSessionId,
    pub(super) tle_public_state: TleKeySessionPublicStateV1,
}

async fn assert_runtime_upgrade_registry_empty(client: &Client) -> Result<()> {
    let norito::json::Value::Object(response) = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_runtime_upgrades_json()
    })
    .await?
    else {
        return Err(eyre!("runtime-upgrade list response is not an object"));
    };
    let Some(norito::json::Value::Array(items)) = response.get("items") else {
        return Err(eyre!("runtime-upgrade list response has no items array"));
    };
    assert!(
        items.is_empty(),
        "fail-fast execution fixture requires the runtime-upgrade registry to remain empty",
    );
    Ok(())
}

pub(super) async fn install_threshold_sessions(
    network: &sandbox::SerializedNetwork,
    client: &Client,
) -> Result<ThresholdSessionsV1> {
    let ordered_roster = ordered_validator_roster(network, client).await?;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let beacon_record = deterministic_parliament_beacon_key_record_v1(
        network.network_id(),
        &ordered_roster,
        &beacon_budget,
    )
    .wrap_err("derive failure-corridor beacon fixture")?;
    let tle_public_state =
        deterministic_parliament_tle_key_public_state_v1(network.network_id(), &ordered_roster)
            .wrap_err("derive failure-corridor TLE fixture")?;
    let install_height = next_execution_height(
        client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "failure-corridor threshold-key installation",
    )
    .await?;
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(lifecycle_certificate(
                network,
                &ordered_roster,
                ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
                beacon_record.session.session_id,
                beacon_record.session.transcript_hash,
                norito::encode_canonical(&beacon_record)?,
                install_height,
            )?),
            InstructionBox::from(lifecycle_certificate(
                network,
                &ordered_roster,
                ThresholdKeyLifecycleActionV1::InstallParliamentTleKey,
                *tle_public_state.key_session_id.as_bytes(),
                tle_public_state.transcript_hash,
                norito::encode_canonical(&tle_public_state)?,
                install_height,
            )?),
        ],
    )
    .await?;
    assert_eq!(current_height(client).await?, install_height);
    let activation_height = install_height
        .checked_add(1)
        .ok_or_else(|| eyre!("failure-corridor key activation height overflow"))?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry Parliament failure-corridor threshold-key activation".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(activation_height).await?;
    assert_eq!(current_height(client).await?, activation_height);
    Ok(ThresholdSessionsV1 {
        logical_beacon: BeaconSessionId::for_network_v1(&network.network_id()),
        tle_public_state,
    })
}

fn capacity_failure_builder(
    citizen: &AccountId,
    citizenship_domain: &DomainId,
    citizenship_asset_definition: &AssetDefinitionId,
    contract_address: &ContractAddress,
) -> NetworkBuilder {
    let citizenship_asset_literal = citizenship_asset_definition.to_string();
    let citizenship_escrow_literal = BOB_ID.to_string();
    let builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(POSITIVE_BEACON_SIGNER_MODES)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(move |layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(["nexus", "lane_count"], 1_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["gov", "citizenship_asset_id"], citizenship_asset_literal)
                .write(
                    ["gov", "citizenship_bond_amount"],
                    CAPACITY_BOND_AMOUNT.to_string(),
                )
                .write(
                    ["gov", "citizenship_escrow_account"],
                    citizenship_escrow_literal,
                )
                .write(["gov", "parliament_alternate_size"], 0_i64)
                .write(
                    ["gov", "rules_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "agenda_council_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "interest_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "review_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "oversight_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "policy_jury_size"],
                    i64::from(CAPACITY_HIDDEN_SEATS),
                )
                .write(
                    ["gov", "confirmation_jury_size"],
                    i64::from(CAPACITY_HIDDEN_SEATS),
                );
        })
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanManageSmartContractCode),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanProposeContractDeployment {
                contract_address: contract_address.clone(),
            }),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Register::domain(Domain::new(citizenship_domain.clone())))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            citizenship_asset_definition.clone(),
            "Citizenship Bond".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Register::account(Account::new(citizen.clone())))
        .with_genesis_instruction(Mint::asset_quantity(
            CAPACITY_BOND_AMOUNT,
            AssetId::new(citizenship_asset_definition.clone(), citizen.clone()),
        ))
        .with_genesis_instruction(RegisterCitizen {
            owner: citizen.clone(),
            amount: CAPACITY_BOND_AMOUNT.into(),
        });
    with_signed_npos_epoch(builder, CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS)
}

fn confirmation_capacity_builder(
    citizens: &[AccountId],
    contract_address: &ContractAddress,
) -> NetworkBuilder {
    let mut builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(POSITIVE_BEACON_SIGNER_MODES)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(|layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(["nexus", "lane_count"], 1_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["gov", "citizenship_bond_amount"], "0")
                .write(["gov", "parliament_alternate_size"], 0_i64)
                .write(
                    ["gov", "parliament_invitation_phase_blocks"],
                    CONFIRMATION_INVITATION_BLOCKS as i64,
                )
                .write(["gov", "parliament_public_finding_phase_blocks"], 8_i64)
                .write(
                    ["gov", "rules_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "agenda_council_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "interest_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "review_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "oversight_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "policy_jury_size"],
                    i64::from(CONFIRMATION_POLICY_SEATS),
                )
                .write(["gov", "confirmation_jury_size"], 3_i64)
                .write(
                    ["gov", "parliament_timed_ovn", "registration_phase_blocks"],
                    CONFIRMATION_REGISTRATION_BLOCKS as i64,
                )
                .write(
                    [
                        "gov",
                        "parliament_timed_ovn",
                        "survivor_freeze_phase_blocks",
                    ],
                    CONFIRMATION_SURVIVOR_FREEZE_PHASE_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "commitment_phase_blocks"],
                    BALLOT_COMMITMENT_PHASE_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "release_delay_blocks"],
                    CONFIRMATION_RELEASE_DELAY_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "opening_phase_blocks"],
                    CONFIRMATION_OPENING_BLOCKS as i64,
                )
                .write(["gov", "parliament_timed_ovn", "max_ballot_retries"], 0_i64)
                .write(
                    ["gov", "parliament_timed_ovn", "max_corpus_entries"],
                    32_i64,
                );
        })
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanManageSmartContractCode),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanProposeContractDeployment {
                contract_address: contract_address.clone(),
            }),
            ALICE_ID.clone(),
        ));
    for citizen in citizens {
        builder = builder
            .with_genesis_instruction(Register::account(Account::new(citizen.clone())))
            .with_genesis_instruction(RegisterCitizen {
                owner: citizen.clone(),
                amount: 0_u64.into(),
            });
    }
    with_signed_npos_epoch(builder, CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS)
}

fn certified_terminal_builder(
    citizens: &[AccountId],
    contract_address: &ContractAddress,
    runtime_abi_hash: [u8; 32],
) -> NetworkBuilder {
    let mut builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(POSITIVE_BEACON_SIGNER_MODES)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(|layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(["nexus", "lane_count"], 1_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["gov", "citizenship_bond_amount"], "0")
                .write(
                    ["gov", "min_enactment_delay"],
                    TERMINAL_ENACTMENT_DELAY as i64,
                )
                .write(["gov", "parliament_alternate_size"], 0_i64)
                .write(["gov", "parliament_invitation_phase_blocks"], 40_i64)
                .write(["gov", "parliament_public_finding_phase_blocks"], 8_i64)
                .write(
                    ["gov", "rules_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "agenda_council_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "interest_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "review_panel_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "coordination_council_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "mpc_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "fma_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "oversight_committee_size"],
                    i64::from(CAPACITY_PUBLIC_SEATS),
                )
                .write(
                    ["gov", "policy_jury_size"],
                    i64::from(TERMINAL_POLICY_SEATS),
                )
                .write(["gov", "confirmation_jury_size"], 3_i64)
                .write(
                    ["gov", "parliament_timed_ovn", "registration_phase_blocks"],
                    TERMINAL_REGISTRATION_BLOCKS as i64,
                )
                .write(
                    [
                        "gov",
                        "parliament_timed_ovn",
                        "survivor_freeze_phase_blocks",
                    ],
                    TERMINAL_SURVIVOR_FREEZE_PHASE_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "commitment_phase_blocks"],
                    BALLOT_COMMITMENT_PHASE_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "release_delay_blocks"],
                    CONFIRMATION_RELEASE_DELAY_BLOCKS as i64,
                )
                .write(
                    ["gov", "parliament_timed_ovn", "opening_phase_blocks"],
                    CONFIRMATION_OPENING_BLOCKS as i64,
                )
                .write(["gov", "parliament_timed_ovn", "max_ballot_retries"], 0_i64)
                .write(["gov", "parliament_timed_ovn", "max_corpus_entries"], 8_i64);
        })
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanManageSmartContractCode),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanProposeContractDeployment {
                contract_address: contract_address.clone(),
            }),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                ),
            }),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanProposeRuntimeUpgrade {
                abi_version: 1,
                abi_hash: runtime_abi_hash,
            }),
            ALICE_ID.clone(),
        ));
    for citizen in citizens {
        builder = builder
            .with_genesis_instruction(Register::account(Account::new(citizen.clone())))
            .with_genesis_instruction(RegisterCitizen {
                owner: citizen.clone(),
                amount: 0_u64.into(),
            });
    }
    with_signed_npos_epoch(builder, CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS)
}

async fn draw_and_seal_failure_path_bodies(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    attempt_id: GovernanceAttemptId,
    citizens: &[AccountId],
    citizen_keys: &[KeyPair],
    logical_beacon: BeaconSessionId,
    policy_seats: u32,
) -> Result<BTreeMap<ParliamentBody, BodyInstanceId>> {
    let required_bodies = read_attempt(client, attempt_id)
        .await?
        .required_bodies()
        .iter()
        .map(|required| required.body)
        .collect::<Vec<_>>();
    let request_height =
        next_execution_height(client, 0, "confirmation-capacity initial sortition").await?;
    let pulse_height =
        expected_sortition_slot(network, client, attempt_id, request_height, None).await?;
    assert!(
        pulse_height >= request_height + CAPACITY_SORTITION_DELAY_BLOCKS
            && (pulse_height + 1) % CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS == 0,
        "the initial sortition slot must be the first native pulse height at or after the frozen delay",
    );
    let mut election_ids = BTreeMap::new();
    let mut request_ids = Vec::new();
    let mut registrations = Vec::new();
    for body in &required_bodies {
        let election_id = BodyElectionAttemptId::derive_v1(attempt_id, *body, 0);
        let target_seats = if *body == ParliamentBody::PolicyJury {
            policy_seats
        } else {
            CAPACITY_PUBLIC_SEATS
        };
        let request = SortitionRequestV1::try_new_canonical(
            attempt_id,
            election_id,
            *body,
            parliament_candidate_root_v1(attempt_id, *body, citizens),
            u32::try_from(citizens.len())?,
            target_seats,
            request_height,
            pulse_height,
            logical_beacon,
            None,
        )
        .map_err(|error| eyre!("construct confirmation-capacity sortition request: {error}"))?;
        election_ids.insert(*body, election_id);
        request_ids.push(request.id);
        registrations.push(ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request,
        });
    }
    request_ids.sort_unstable();
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
            ParliamentRegisterSortitionRequestV1 {
                requests: registrations,
            },
        ),
    )
    .await?;
    assert_eq!(current_height(client).await?, request_height);
    let awaiting = read_attempt(client, attempt_id).await?;
    for election_id in election_ids.values() {
        let election = awaiting
            .election(election_id)
            .expect("registered election awaits its native slot");
        assert_eq!(election.attempt().request.pulse_height, pulse_height);
        assert_eq!(
            election.attempt().status,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        );
    }
    // Governance-local wait: only the consensus-native pre-boundary pulse can end it, and
    // consumption happens after the epoch boundary that the same pulse scheduled.
    let pulse = await_native_sortition_pulse(
        network,
        client,
        pulse_height,
        "confirmation-capacity initial sortition pulse",
    )
    .await?;
    cross_native_boundary_after_pulse(
        network,
        client,
        &pulse,
        "confirmation-capacity initial sortition pulse",
    )
    .await?;
    let sortition_governance_seed =
        global_threshold_beacon_governance_seed_v1(&pulse, pulse_height);
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
            ParliamentConsumeSortitionPulseBatchV1 {
                request_ids,
                beacon_session_id: logical_beacon,
                pulse_height,
                pulse_id: BeaconPulseId::new(pulse.pulse_id),
            },
        ),
    )
    .await?;
    let drawn = read_attempt(client, attempt_id).await?;
    for election_id in election_ids.values() {
        let election = drawn
            .election(election_id)
            .expect("drawn election consumed its native slot");
        assert_eq!(
            election.pulse_id(),
            Some(BeaconPulseId::new(pulse.pulse_id))
        );
        assert_eq!(election.pulse_output(), Some(sortition_governance_seed));
    }
    submit_transitions(
        client,
        attempt_id,
        required_bodies.iter().map(|body| {
            ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id: election_ids[body],
                },
            )
        }),
    )
    .await?;

    let invitations = read_attempt(client, attempt_id).await?;
    let invitation_close_height = required_bodies
        .iter()
        .map(|body| {
            invitations
                .election(&election_ids[body])
                .and_then(|election| election.invitation_close_height())
                .expect("confirmation-capacity invitation deadline is frozen")
        })
        .reduce(|left, right| {
            assert_eq!(left, right);
            left
        })
        .expect("governance attempt requires at least one Parliament body");
    let mut invitations_by_member =
        BTreeMap::<AccountId, Vec<(ParliamentBody, BodyElectionAttemptId)>>::new();
    for body in &required_bodies {
        let election = invitations
            .election(&election_ids[body])
            .expect("confirmation-capacity election exists");
        for assignment in election.primary_assignments() {
            invitations_by_member
                .entry(assignment.member.clone())
                .or_default()
                .push((*body, election_ids[body]));
        }
    }
    for (member, member_invitations) in invitations_by_member {
        submit_transitions(
            &client_for(client, &member, citizen_keys),
            attempt_id,
            member_invitations
                .into_iter()
                .map(|(body, election_attempt_id)| {
                    ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                        ParliamentRecordInvitationResponseV1 {
                            election_attempt_id,
                            body,
                            decision: ParliamentInvitationDecisionV1::Accept,
                        },
                    )
                }),
        )
        .await?;
    }
    assert!(current_height(client).await? <= invitation_close_height);
    let roster_seal_height = invitation_close_height
        .checked_add(1)
        .ok_or_else(|| eyre!("confirmation-capacity roster seal height overflow"))?;
    advance_to_execution_predecessor(
        network,
        client,
        roster_seal_height,
        "confirmation-capacity roster sealing",
    )
    .await?;
    submit_transitions(
        client,
        attempt_id,
        required_bodies.iter().map(|body| {
            ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                election_attempt_id: election_ids[body],
            })
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, roster_seal_height);

    let sealed = read_attempt(client, attempt_id).await?;
    let mut body_ids = BTreeMap::new();
    for body in required_bodies {
        let body_state = sealed
            .sealed_body_for_role(body)
            .expect("confirmation-capacity body roster is sealed");
        let expected_seats = if body == ParliamentBody::PolicyJury {
            policy_seats
        } else {
            CAPACITY_PUBLIC_SEATS
        };
        assert_eq!(body_state.instance().original_seats, expected_seats);
        assert_eq!(body_state.assignments().len(), expected_seats as usize);
        body_ids.insert(body, body_state.instance().id);
    }
    Ok(body_ids)
}

async fn complete_failure_path_public_findings(
    client: &Client,
    citizen_keys: &[KeyPair],
    attempt_id: GovernanceAttemptId,
    body_ids: &BTreeMap<ParliamentBody, BodyInstanceId>,
) -> Result<()> {
    let phases = [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
    ];
    for (body, body_id) in body_ids {
        if *body == ParliamentBody::PolicyJury {
            continue;
        }
        submit_transitions(
            client,
            attempt_id,
            phases.into_iter().map(|target| {
                ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                    body_instance_id: *body_id,
                    target,
                })
            }),
        )
        .await?;
        let reflecting = read_attempt(client, attempt_id).await?;
        let member = reflecting
            .body(body_id)
            .and_then(|state| state.assignments().first())
            .map(|assignment| assignment.member.clone())
            .ok_or_else(|| eyre!("one-seat public body has no assignment"))?;
        submit_transition(
            &client_for(client, &member, citizen_keys),
            attempt_id,
            ParliamentLifecycleTransitionV1::EndorsePublicFinding(
                ParliamentEndorsePublicFindingV1 {
                    body_instance_id: *body_id,
                    result_root: public_finding_root(attempt_id, *body),
                },
            ),
        )
        .await?;
        assert_eq!(
            read_attempt(client, attempt_id)
                .await?
                .body(body_id)
                .expect("completed public body")
                .instance()
                .status,
            BodyInstanceStatusV1::Approved,
        );
    }
    Ok(())
}

async fn finalize_failure_path_policy_ballot(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    citizen_keys: &[KeyPair],
    attempt_id: GovernanceAttemptId,
    body_ids: &BTreeMap<ParliamentBody, BodyInstanceId>,
    sessions: &ThresholdSessionsV1,
    policy_seats: u32,
    registration_phase_blocks: u64,
    survivor_freeze_phase_blocks: u64,
    commitment_phase_blocks: u64,
    aye_ballots: usize,
) -> Result<BallotAttemptId> {
    let policy_body_id = body_ids[&ParliamentBody::PolicyJury];
    submit_transitions(
        client,
        attempt_id,
        [
            DeliberationPhaseV1::Orientation,
            DeliberationPhaseV1::Evidence,
            DeliberationPhaseV1::Questions,
            DeliberationPhaseV1::Responses,
            DeliberationPhaseV1::Deliberation,
            DeliberationPhaseV1::Reflection,
            DeliberationPhaseV1::Vote,
        ]
        .into_iter()
        .map(|target| {
            ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                body_instance_id: policy_body_id,
                target,
            })
        }),
    )
    .await?;

    let ballot_attempt_id = BallotAttemptId::derive_v1(policy_body_id, 0);
    let registered_at_height =
        next_execution_height(client, 0, "confirmation-capacity ballot registration").await?;
    let registration_close_height = registered_at_height
        .checked_add(registration_phase_blocks)
        .ok_or_else(|| eyre!("confirmation-capacity registration height overflow"))?;
    let survivor_freeze_height = registration_close_height
        .checked_add(survivor_freeze_phase_blocks)
        .ok_or_else(|| eyre!("confirmation-capacity survivor height overflow"))?;
    let commitment_close_height = survivor_freeze_height
        .checked_add(commitment_phase_blocks)
        .ok_or_else(|| eyre!("confirmation-capacity commitment height overflow"))?;
    let release_height = commitment_close_height
        .checked_add(CONFIRMATION_RELEASE_DELAY_BLOCKS)
        .ok_or_else(|| eyre!("confirmation-capacity release height overflow"))?;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        sessions.tle_public_state.key_session_id,
        sessions.logical_beacon,
        release_height,
    );
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::RegisterBallotAttempt(ParliamentRegisterBallotAttemptV1 {
            body_instance_id: policy_body_id,
            ballot_attempt_id,
            sequence: 0,
            tle_session_id,
            tle_key_session_id: sessions.tle_public_state.key_session_id,
            release_beacon_session_id: sessions.logical_beacon,
            release_height,
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, registered_at_height);

    let casting_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let ballot_attempt_id = (ballot_attempt_id).clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await?;
    let casting = casting_archive(&casting_response, ballot_attempt_id)?;
    let validated_casting = casting
        .validate_v1()
        .wrap_err("validate confirmation-capacity casting context")?;
    let policy_members = read_attempt(client, attempt_id)
        .await?
        .body(&policy_body_id)
        .expect("Policy Jury body exists")
        .assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    assert_eq!(policy_members.len(), policy_seats as usize);
    assert!(aye_ballots <= policy_members.len());

    let mut registration_secrets = BTreeMap::new();
    for (index, member) in policy_members.iter().enumerate() {
        let participant_hash = parliament_ballot_participant_hash_v1(ballot_attempt_id, member);
        let mut rng = StdRng::from_seed(
            Hash::new_from_chunks(&[
                b"iroha.integration.parliament.confirmation-capacity-registration.v1\0",
                attempt_id.as_bytes(),
                &[u8::try_from(index)?],
            ])
            .into(),
        );
        let (secret, registration) = TimedOvnRegistrationSecretV1::generate_with_rng(
            validated_casting.timed_ovn_session(),
            participant_hash,
            &mut rng,
        )
        .wrap_err("generate confirmation-capacity timed-OVN registration")?;
        submit_transition(
            &client_for(client, member, citizen_keys),
            attempt_id,
            ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                ParliamentRegisterBallotParticipantV1 {
                    ballot_attempt_id,
                    registration_record: registration.to_bytes(),
                },
            ),
        )
        .await?;
        assert!(
            registration_secrets
                .insert(participant_hash, secret)
                .is_none()
        );
    }
    assert!(current_height(client).await? < registration_close_height);
    advance_to_execution_predecessor(
        network,
        client,
        registration_close_height,
        "confirmation-capacity registration close",
    )
    .await?;
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CloseBallotRegistration(
            ParliamentCloseBallotRegistrationV1 { ballot_attempt_id },
        ),
    )
    .await?;
    assert_eq!(current_height(client).await?, registration_close_height);

    advance_to_execution_predecessor(
        network,
        client,
        survivor_freeze_height,
        "confirmation-capacity survivor freeze",
    )
    .await?;
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(ParliamentFreezeBallotSurvivorsV1 {
            ballot_attempt_id,
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, survivor_freeze_height);

    let survivors_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let ballot_attempt_id = (ballot_attempt_id).clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await?;
    let survivors_archive = casting_archive(&survivors_response, ballot_attempt_id)?;
    let survivor_ids = survivors_archive
        .survivor_participant_hashes()
        .expect("survivor freeze exposes exact participant hashes");
    assert_eq!(survivor_ids.len(), policy_seats as usize);
    let validated_survivors = survivors_archive
        .validate_v1()
        .wrap_err("validate confirmation-capacity survivor context")?;
    let prepared = validated_survivors
        .prepared_attempt()
        .expect("survivor-frozen context prepares the ballot roster");
    let mut ballot_records = Vec::with_capacity(survivor_ids.len());
    for (index, participant_hash) in survivor_ids.iter().enumerate() {
        let choice = if index < aye_ballots {
            TimedOvnChoiceV1::Aye
        } else {
            TimedOvnChoiceV1::Nay
        };
        let mut rng = StdRng::from_seed(
            Hash::new_from_chunks(&[
                b"iroha.integration.parliament.confirmation-capacity-ballot.v1\0",
                attempt_id.as_bytes(),
                &[u8::try_from(index)?],
            ])
            .into(),
        );
        let record = registration_secrets
            .get(participant_hash)
            .ok_or_else(|| eyre!("survivor has no retained registration secret"))?
            .cast_ballot_with_rng(prepared.survivor_roster(), choice, &mut rng)
            .wrap_err("generate confirmation-capacity timed-OVN ballot")?
            .to_bytes();
        assert_eq!(record.len(), TIMED_OVN_BALLOT_RECORD_BYTES_V1);
        ballot_records.push(record);
    }
    advance_to_execution_predecessor(
        network,
        client,
        commitment_close_height,
        "confirmation-capacity commitment close",
    )
    .await?;
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(ParliamentFreezeTimedOvnCorpusV1 {
            ballot_attempt_id,
            ballot_records,
        }),
    )
    .await?;
    assert_eq!(current_height(client).await?, commitment_close_height);

    advance_to_autonomous_predecessor(
        network,
        client,
        release_height,
        "confirmation-capacity release pulse",
    )
    .await?;
    network.ensure_blocks(release_height).await?;
    let mut pulses = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        pulses.push(pulse_at(&peer.client(), release_height, &network).await?);
    }
    assert!(pulses.windows(2).all(|pair| pair[0] == pair[1]));
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
            ParliamentBeginBallotOpeningBatchV1 {
                ballot_attempt_ids: vec![ballot_attempt_id],
                release_beacon_session_id: sessions.logical_beacon,
                release_height,
                pulse_id: BeaconPulseId::new(pulses[0].pulse_id),
            },
        ),
    )
    .await?;

    let release_context = read_on_dedicated_thread({
        let client = client.client().clone();
        let ballot_attempt_id = (ballot_attempt_id).clone();
        move || client.get_parliament_tle_release_context(ballot_attempt_id)
    })
    .await?;
    let validated_release = release_projection(&release_context)?
        .validate()
        .wrap_err("validate confirmation-capacity release context")?;
    let mut partials = BTreeMap::new();
    for peer in network.peers() {
        let peer_client = peer.client();
        let peer_context = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let ballot_attempt_id = (ballot_attempt_id).clone();
            move || client.get_parliament_tle_release_context(ballot_attempt_id)
        })
        .await?;
        assert_eq!(peer_context, release_context);
        let partial = release_partial(
            read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let release_context = (peer_context).clone();
                move || client.post_parliament_tle_partial_release(&release_context)
            })
            .await?,
        );
        validated_release
            .session()
            .verify_partial_release(
                validated_release.identity(),
                validated_release.finalized_height(),
                &partial,
            )
            .wrap_err("verify confirmation-capacity partial release")?;
        partials.insert(partial.participant_index, partial);
    }
    assert_eq!(partials.len(), VALIDATOR_COUNT);
    let threshold_partials = partials
        .into_values()
        .take(usize::from(release_context.tle_key_session.threshold))
        .collect::<Vec<_>>();
    let final_release = validated_release
        .session()
        .combine_partial_releases(
            validated_release.identity(),
            validated_release.finalized_height(),
            &threshold_partials,
        )
        .wrap_err("combine confirmation-capacity final release")?;
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(ParliamentFinalizeOpenedBallotV1 {
            ballot_attempt_id,
            final_release: ParliamentTleFinalReleaseSignatureV1 {
                key_session_id: final_release.key_session_id,
                identity_digest: final_release.identity_digest,
                signature: final_release.signature,
            },
        }),
    )
    .await?;
    Ok(ballot_attempt_id)
}

async fn certify_failure_path_attempt(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    citizens: &[AccountId],
    citizen_keys: &[KeyPair],
    attempt_id: GovernanceAttemptId,
    sessions: &ThresholdSessionsV1,
) -> Result<GovernanceCertificateV1> {
    submit_transition(
        client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;
    let body_ids = draw_and_seal_failure_path_bodies(
        network,
        client,
        attempt_id,
        citizens,
        citizen_keys,
        sessions.logical_beacon,
        TERMINAL_POLICY_SEATS,
    )
    .await?;
    complete_failure_path_public_findings(client, citizen_keys, attempt_id, &body_ids).await?;
    finalize_failure_path_policy_ballot(
        network,
        client,
        citizen_keys,
        attempt_id,
        &body_ids,
        sessions,
        TERMINAL_POLICY_SEATS,
        TERMINAL_REGISTRATION_BLOCKS,
        TERMINAL_SURVIVOR_FREEZE_PHASE_BLOCKS,
        BALLOT_COMMITMENT_PHASE_BLOCKS,
        2,
    )
    .await?;
    let certified = read_attempt(client, attempt_id).await?;
    assert_eq!(
        certified.attempt().status,
        GovernanceAttemptStatusV1::Certified,
    );
    assert_eq!(certified.attempt().stage, GovernanceStageV1::Enactment);
    let certificate = certified
        .certificate()
        .cloned()
        .expect("ordinary 2-1 Policy approval constructs a certificate");
    certificate
        .validate()
        .wrap_err("validate failure-path certificate")?;
    assert_eq!(
        certificate.enact_at_height,
        certificate.certified_at_height + TERMINAL_ENACTMENT_DELAY,
    );
    Ok(certificate)
}

#[test]
// TODO: this corridor needs a hidden ballot to open, and the timed-OVN release slot is no
// longer consensus demand, so the ballot ends `ReleasePulseUnavailable` unless its frozen
// release height coincides with a native pre-boundary pulse. Re-enable it on the anonymous
// ballot (specs/parliament_private_ballot_design.md 12.2 step 4), which must replace
// `finalize_failure_path_policy_ballot`; the sortition half already uses the native slot.
#[ignore = "timed-OVN release slot is no longer consensus demand; the hidden ballot is replaced by the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4)"]
fn four_validator_certified_effects_record_supersession_and_execution_failure() -> Result<()> {
    let name =
        stringify!(four_validator_certified_effects_record_supersession_and_execution_failure);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator certified-terminal runtime")
                .block_on(
                    four_validator_certified_effects_record_supersession_and_execution_failure_impl(
                    ),
                )
        })
        .expect("spawn four-validator certified-terminal thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_certified_effects_record_supersession_and_execution_failure_impl()
-> Result<()> {
    let citizen_keys = citizen_keys();
    let citizens = citizen_accounts(&citizen_keys);
    let contract_address = ContractAddress::from_str(CONTRACT_ADDRESS)?;
    let runtime_abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let builder = certified_terminal_builder(&citizens, &contract_address, runtime_abi_hash);
    let context =
        stringify!(four_validator_certified_effects_record_supersession_and_execution_failure);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;
    let client = network.client();
    let sessions = install_threshold_sessions(&network, &client).await?;

    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let (competing_contract_code_hash, competing_abi_hash) = stage_contract_artifact(
        &client,
        &minimal_contract_artifact_with_identity(
            "ParliamentSupersessionCompetitor",
            "integration-tests-supersession-competitor",
        ),
    )
    .await?;
    assert_ne!(
        competing_contract_code_hash, code_hash,
        "the supersession fixture must install a genuinely distinct artifact head",
    );
    assert_eq!(
        competing_abi_hash, abi_hash,
        "the competing artifact must preserve the proposal's exact ABI surface",
    );
    let competing_deploy_proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash: competing_contract_code_hash,
        abi_hash: competing_abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let competing_deploy_create = CreateParliamentGovernanceAttemptV1 {
        proposal: competing_deploy_proposal,
        attempt_sequence: 0,
    };
    let competing_deploy_attempt_id = competing_deploy_create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash: competing_contract_code_hash,
                abi_hash: competing_abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(competing_deploy_create),
        ],
    )
    .await?;
    let competing_deploy_certificate = certify_failure_path_attempt(
        &network,
        &client,
        &citizens,
        &citizen_keys,
        competing_deploy_attempt_id,
        &sessions,
    )
    .await?;

    // Register the proposal under test while the competing certificate is
    // certified but not yet due. Its immutable expected head is therefore the
    // same absent head; ordinary block progression enacts the competitor before
    // this attempt finishes certification.
    let deploy_proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let deploy_subject_id = deploy_proposal.governed_subject_id_v1()?;
    let deploy_create = CreateParliamentGovernanceAttemptV1 {
        proposal: deploy_proposal,
        attempt_sequence: 0,
    };
    let deploy_attempt_id = deploy_create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(deploy_create),
        ],
    )
    .await?;
    assert!(current_height(&client).await? < competing_deploy_certificate.enact_at_height);
    let deploy_certificate = certify_failure_path_attempt(
        &network,
        &client,
        &citizens,
        &citizen_keys,
        deploy_attempt_id,
        &sessions,
    )
    .await?;
    assert_eq!(
        deploy_certificate.expected_head, competing_deploy_certificate.expected_head,
        "both certified deployments must compare against the same pre-enactment head",
    );
    assert!(current_height(&client).await? >= competing_deploy_certificate.enact_at_height);
    let competing_enacted = read_attempt(&client, competing_deploy_attempt_id).await?;
    assert_eq!(
        competing_enacted.attempt().status,
        GovernanceAttemptStatusV1::Enacted,
    );
    assert_eq!(
        competing_enacted.certificate(),
        Some(&competing_deploy_certificate),
    );
    assert!(current_height(&client).await? < deploy_certificate.enact_at_height);
    assert_governed_contract_binding(
        &client,
        &contract_address,
        competing_contract_code_hash,
        competing_abi_hash,
        "the certified competing binding must be authoritative before enactment",
    )
    .await?;
    advance_to_autonomous_predecessor(
        &network,
        &client,
        deploy_certificate.enact_at_height,
        "certified deploy supersession",
    )
    .await?;
    network
        .ensure_blocks(deploy_certificate.enact_at_height)
        .await?;
    let superseded = read_attempt(&client, deploy_attempt_id).await?;
    assert_eq!(
        superseded.attempt().status,
        GovernanceAttemptStatusV1::Superseded,
    );
    assert_eq!(
        superseded.terminal_height(),
        Some(deploy_certificate.enact_at_height),
    );
    assert_eq!(
        superseded.superseding_head(),
        Some(GovernanceExpectedHeadV1::Present(
            GovernanceExpectedHeadPresentV1 {
                subject_id: deploy_subject_id,
                version: 1,
                head_root: competing_contract_code_hash.into(),
            },
        )),
        "supersession must bind the exact authoritative contract head",
    );
    assert!(superseded.execution_failure_root().is_none());
    assert_eq!(superseded.certificate(), Some(&deploy_certificate));
    let superseded_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (deploy_attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    for peer in network.peers() {
        let peer_client = peer.client();
        assert_eq!(
            read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let attempt_id = (deploy_attempt_id).clone();
                move || client.get_parliament_attempt(attempt_id)
            })
            .await?
            .state_payload_hex,
            superseded_response.state_payload_hex,
        );
        assert_governed_contract_binding(
            &peer_client,
            &contract_address,
            competing_contract_code_hash,
            competing_abi_hash,
            "all validators must retain the competing contract binding",
        )
        .await?;
    }

    assert_runtime_upgrade_registry_empty(&client).await?;
    let manifest_start_height = current_height(&client)
        .await?
        .checked_add(10)
        .ok_or_else(|| eyre!("runtime-upgrade start height overflow"))?;
    let runtime_manifest = RuntimeUpgradeManifest {
        name: "parliament-execution-failure".to_owned(),
        description: "window expires before certified enactment".to_owned(),
        abi_version: 1,
        abi_hash: runtime_abi_hash,
        added_syscalls: Vec::new(),
        added_pointer_types: Vec::new(),
        start_height: manifest_start_height,
        end_height: manifest_start_height
            .checked_add(10_000)
            .ok_or_else(|| eyre!("runtime-upgrade end height overflow"))?,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let runtime_proposal = ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
        proposal_operator: client.client().account().clone(),
        manifest: runtime_manifest.clone(),
    });
    let runtime_create = CreateParliamentGovernanceAttemptV1 {
        proposal: runtime_proposal,
        attempt_sequence: 0,
    };
    let runtime_attempt_id = runtime_create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeRuntimeUpgradeProposal {
                manifest: runtime_manifest,
            }),
            InstructionBox::from(runtime_create),
        ],
    )
    .await?;
    let runtime_certificate = certify_failure_path_attempt(
        &network,
        &client,
        &citizens,
        &citizen_keys,
        runtime_attempt_id,
        &sessions,
    )
    .await?;
    // Runtime-upgrade enactment performs every fallible validation before its registry insert;
    // after that insert it only emits infallible events and telemetry. This stale `start_height`
    // therefore proves typed deterministic execution-failure classification and unchanged-state
    // isolation, not partial-write rollback. The latter needs another governed effect with a
    // deliberately fallible post-write operation.
    assert!(
        runtime_certificate.certified_at_height > manifest_start_height,
        "the fixture must certify only after the runtime start window has expired",
    );
    advance_to_autonomous_predecessor(
        &network,
        &client,
        runtime_certificate.enact_at_height,
        "certified runtime execution failure",
    )
    .await?;
    network
        .ensure_blocks(runtime_certificate.enact_at_height)
        .await?;
    let execution_failed = read_attempt(&client, runtime_attempt_id).await?;
    let expected_failure_root = parliament_execution_failure_root_v1(
        &runtime_certificate,
        runtime_certificate.enact_at_height,
    );
    assert_eq!(
        execution_failed.attempt().status,
        GovernanceAttemptStatusV1::ExecutionFailed,
    );
    assert_eq!(
        execution_failed.terminal_height(),
        Some(runtime_certificate.enact_at_height),
    );
    assert_eq!(
        execution_failed.execution_failure_root(),
        Some(expected_failure_root),
    );
    assert!(execution_failed.superseding_head().is_none());
    assert_eq!(execution_failed.certificate(), Some(&runtime_certificate));
    assert_runtime_upgrade_registry_empty(&client).await?;

    let execution_failed_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (runtime_attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    for peer in network.peers() {
        let peer_client = peer.client();
        assert_eq!(
            read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let attempt_id = (runtime_attempt_id).clone();
                move || client.get_parliament_attempt(attempt_id)
            })
            .await?
            .state_payload_hex,
            execution_failed_response.state_payload_hex,
            "all validators must commit the same deterministic failure root",
        );
        assert_eq!(
            read_on_dedicated_thread({
                let client = peer_client.client().clone();
                let attempt_id = (deploy_attempt_id).clone();
                move || client.get_parliament_attempt(attempt_id)
            })
            .await?
            .state_payload_hex,
            superseded_response.state_payload_hex,
            "later attempts must not mutate the prior supersession transcript",
        );
        assert_runtime_upgrade_registry_empty(&peer_client).await?;
    }

    let restore_height = current_height(&client).await?;
    let restart_peer = network
        .peers()
        .last()
        .expect("four-validator network has a restore peer")
        .clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(restart_peer.shutdown_if_started().await);
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("certified-terminal restore exceeded {OPERATION_TIMEOUT:?}"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(restore_height),
    )
    .await
    .map_err(|_| eyre!("certified-terminal restore did not recover finalized state"))?;
    let restored_client = restart_peer.client();
    assert_eq!(
        read_on_dedicated_thread({
            let client = restored_client.client().clone();
            let attempt_id = (deploy_attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?
        .state_payload_hex,
        superseded_response.state_payload_hex,
    );
    assert_eq!(
        read_on_dedicated_thread({
            let client = restored_client.client().clone();
            let attempt_id = (runtime_attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?
        .state_payload_hex,
        execution_failed_response.state_payload_hex,
    );
    assert_governed_contract_binding(
        &restored_client,
        &contract_address,
        competing_contract_code_hash,
        competing_abi_hash,
        "restart must retain the competing contract binding",
    )
    .await?;
    assert_runtime_upgrade_registry_empty(&restored_client).await?;
    Ok(())
}

#[test]
// TODO: this corridor needs a hidden ballot to open, and the timed-OVN release slot is no
// longer consensus demand, so the ballot ends `ReleasePulseUnavailable` unless its frozen
// release height coincides with a native pre-boundary pulse. Re-enable it on the anonymous
// ballot (specs/parliament_private_ballot_design.md 12.2 step 4), which must replace
// `finalize_failure_path_policy_ballot`; the sortition half already uses the native slot.
#[ignore = "timed-OVN release slot is no longer consensus demand; the hidden ballot is replaced by the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4)"]
fn four_validator_narrow_policy_aborts_when_confirmation_capacity_is_one() -> Result<()> {
    let name = stringify!(four_validator_narrow_policy_aborts_when_confirmation_capacity_is_one);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator Confirmation-capacity runtime")
                .block_on(
                    four_validator_narrow_policy_aborts_when_confirmation_capacity_is_one_impl(),
                )
        })
        .expect("spawn four-validator Confirmation-capacity thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_narrow_policy_aborts_when_confirmation_capacity_is_one_impl() -> Result<()>
{
    let citizen_keys = citizen_keys()
        .into_iter()
        .take(CONFIRMATION_CITIZENS)
        .collect::<Vec<_>>();
    let citizens = citizen_accounts(&citizen_keys);
    assert_eq!(citizens.len(), CONFIRMATION_CITIZENS);
    let contract_address = ContractAddress::from_str(NO_RESULT_RETRY_CONTRACT_ADDRESS)?;
    let builder = confirmation_capacity_builder(&citizens, &contract_address);
    let context = stringify!(four_validator_narrow_policy_aborts_when_confirmation_capacity_is_one);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;
    let client = network.client();
    let sessions = install_threshold_sessions(&network, &client).await?;

    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(create),
        ],
    )
    .await?;
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;

    let body_ids = draw_and_seal_failure_path_bodies(
        &network,
        &client,
        attempt_id,
        &citizens,
        &citizen_keys,
        sessions.logical_beacon,
        CONFIRMATION_POLICY_SEATS,
    )
    .await?;
    complete_failure_path_public_findings(&client, &citizen_keys, attempt_id, &body_ids).await?;
    let policy_members = read_attempt(&client, attempt_id)
        .await?
        .body(&body_ids[&ParliamentBody::PolicyJury])
        .expect("Policy Jury body exists")
        .assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        citizens
            .iter()
            .filter(|candidate| !policy_members.contains(candidate))
            .count(),
        1,
        "the fixture must leave exactly one disjoint Confirmation candidate",
    );
    let ballot_attempt_id = finalize_failure_path_policy_ballot(
        &network,
        &client,
        &citizen_keys,
        attempt_id,
        &body_ids,
        &sessions,
        CONFIRMATION_POLICY_SEATS,
        CONFIRMATION_REGISTRATION_BLOCKS,
        CONFIRMATION_SURVIVOR_FREEZE_PHASE_BLOCKS,
        BALLOT_COMMITMENT_PHASE_BLOCKS,
        11,
    )
    .await?;

    let rejected = read_attempt(&client, attempt_id).await?;
    assert_eq!(
        rejected.attempt().status,
        GovernanceAttemptStatusV1::Rejected,
    );
    assert_eq!(rejected.attempt().stage, GovernanceStageV1::PolicyJury);
    assert_eq!(
        rejected
            .required_bodies()
            .last()
            .map(|required| required.body),
        Some(ParliamentBody::PolicyJury),
        "an unfillable Confirmation requirement must never be committed",
    );
    assert!(
        rejected
            .required_bodies()
            .iter()
            .all(|required| required.body != ParliamentBody::ConfirmationJury),
    );
    assert!(rejected.certificate().is_none());
    let policy_body = rejected
        .body(&body_ids[&ParliamentBody::PolicyJury])
        .expect("failed Policy Jury remains auditable");
    assert_eq!(
        policy_body.instance().status,
        BodyInstanceStatusV1::NoResult,
    );
    assert!(policy_body.result_root().is_none());
    let ballot = rejected
        .ballot(&ballot_attempt_id)
        .expect("failed narrow ballot remains auditable");
    assert_eq!(ballot.attempt().status, BallotAttemptStatusV1::NoResult);
    assert_eq!(ballot.accepted_ballots(), Some(CONFIRMATION_POLICY_SEATS));
    assert_eq!(ballot.eligible_confirmation_candidates(), Some(1));
    assert_eq!(
        ballot.failure_kind(),
        Some(ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable),
    );
    assert!(ballot.failure_height().is_some());
    assert_governed_contract_absent(
        &client,
        &contract_address,
        "Confirmation-capacity rejection effect isolation",
    )
    .await?;

    let rejected_height = current_height(&client).await?;
    network.ensure_blocks(rejected_height).await?;
    let rejected_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    for peer in network.peers() {
        let peer_client = peer.client();
        let peer_response = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(peer_response.current_height, rejected_height);
        assert_eq!(
            peer_response.state_payload_hex, rejected_response.state_payload_hex,
            "all validators must commit the same Confirmation-capacity abort",
        );
        assert_governed_contract_absent(
            &peer_client,
            &contract_address,
            "Confirmation-capacity peer effect isolation",
        )
        .await?;
    }

    let restart_peer = network
        .peers()
        .last()
        .expect("four-validator network has a restore peer")
        .clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(restart_peer.shutdown_if_started().await);
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("Confirmation-capacity restore exceeded {OPERATION_TIMEOUT:?}"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(rejected_height),
    )
    .await
    .map_err(|_| eyre!("Confirmation-capacity restore did not recover finalized state"))?;
    let restored = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_eq!(
        restored.state_payload_hex, rejected_response.state_payload_hex,
        "restart must retain the complete Confirmation-capacity transcript",
    );
    assert_governed_contract_absent(
        &restart_peer.client(),
        &contract_address,
        "Confirmation-capacity restart effect isolation",
    )
    .await?;
    Ok(())
}

#[test]
fn four_validator_hidden_capacity_retains_then_releases_citizenship_bond() -> Result<()> {
    let name = stringify!(four_validator_hidden_capacity_retains_then_releases_citizenship_bond);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator Parliament failure-path runtime")
                .block_on(
                    four_validator_hidden_capacity_retains_then_releases_citizenship_bond_impl(),
                )
        })
        .expect("spawn four-validator Parliament failure-path thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_hidden_capacity_retains_then_releases_citizenship_bond_impl() -> Result<()>
{
    let all_keys = citizen_keys();
    let citizen_key = all_keys
        .first()
        .cloned()
        .ok_or_else(|| eyre!("deterministic citizen fixture is empty"))?;
    let citizen = AccountId::new(citizen_key.public_key().clone());
    let citizens = vec![citizen.clone()];
    let citizenship_domain = DomainId::try_new("parliament-bond", "universal")?;
    let citizenship_asset_definition =
        AssetDefinitionId::derive_from_components(citizenship_domain.clone(), "xor".parse()?);
    let citizen_asset_id = AssetId::new(citizenship_asset_definition.clone(), citizen.clone());
    let contract_address = ContractAddress::from_str(CONTRACT_ADDRESS)?;
    let builder = capacity_failure_builder(
        &citizen,
        &citizenship_domain,
        &citizenship_asset_definition,
        &contract_address,
    );

    let context = stringify!(four_validator_hidden_capacity_retains_then_releases_citizenship_bond);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;
    let client = network.client();
    let citizen_client = client_for(&client, &citizen, std::slice::from_ref(&citizen_key));
    // Fee admission quotes the citizen's own signed operations before execution, so the
    // retained-bond rejection below is reachable only for a fee-funded citizen.
    enactment::fund_citizen_fees(&network, &client, &citizens).await?;

    assert_asset_not_found(
        &client,
        &citizen_asset_id,
        "genesis citizenship escrow custody",
    )
    .await?;

    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(create),
        ],
    )
    .await?;
    submit_transition(
        &client,
        attempt_id,
        ParliamentLifecycleTransitionV1::CompleteQualification,
    )
    .await?;

    let initial = read_attempt(&client, attempt_id).await?;
    let required_bodies = initial
        .required_bodies()
        .iter()
        .map(|required| required.body)
        .collect::<Vec<_>>();
    assert!(required_bodies.contains(&ParliamentBody::PolicyJury));
    let logical_beacon = BeaconSessionId::for_network_v1(&network.network_id());
    let mut first_failed_pulse_height = None;
    let mut first_request_height = None;
    let mut previous_generation_slot = None;
    let mut final_failure_ids = BTreeMap::new();

    for sequence in 0..=MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        let request_height =
            next_execution_height(&client, 0, "hidden-capacity sortition intent").await?;
        // Every capacity record holds one generation slot. A retry inside the epoch window
        // of the previous record takes the next native pre-boundary height, never the same.
        let pulse_height = expected_sortition_slot(
            &network,
            &client,
            attempt_id,
            request_height,
            previous_generation_slot,
        )
        .await?;
        assert!(pulse_height >= request_height + CAPACITY_SORTITION_DELAY_BLOCKS);
        if let Some(previous) = previous_generation_slot {
            assert_eq!(
                pulse_height,
                previous + CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS,
                "a capacity retry must take the next native boundary slot",
            );
        }
        previous_generation_slot = Some(pulse_height);
        first_failed_pulse_height.get_or_insert(pulse_height);
        first_request_height.get_or_insert(request_height);
        let mut registrations = Vec::with_capacity(required_bodies.len());
        for body in &required_bodies {
            let election_attempt_id = BodyElectionAttemptId::derive_v1(attempt_id, *body, sequence);
            let target_seats = if *body == ParliamentBody::PolicyJury {
                CAPACITY_HIDDEN_SEATS
            } else {
                CAPACITY_PUBLIC_SEATS
            };
            let request = SortitionRequestV1::try_new_canonical(
                attempt_id,
                election_attempt_id,
                *body,
                parliament_candidate_root_v1(attempt_id, *body, &citizens),
                1,
                target_seats,
                request_height,
                pulse_height,
                logical_beacon,
                None,
            )
            .map_err(|error| eyre!("construct hidden-capacity request: {error}"))?;
            final_failure_ids.insert(*body, election_attempt_id);
            registrations.push(ParliamentSortitionRequestRegistrationV1 { sequence, request });
        }
        submit_transition(
            &client,
            attempt_id,
            ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                ParliamentRegisterSortitionRequestV1 {
                    requests: registrations,
                },
            ),
        )
        .await?;
        assert_eq!(current_height(&client).await?, request_height);

        let observed = read_attempt(&client, attempt_id).await?;
        for failure_id in final_failure_ids.values() {
            let failure = observed
                .sortition_capacity_failure(failure_id)
                .expect("Core retains typed hidden-capacity evidence");
            assert_eq!(failure.sequence(), sequence);
            assert_eq!(failure.candidate_count(), 1);
            assert_eq!(failure.failure_height(), request_height);
            assert_eq!(failure.status(), BodyElectionAttemptStatusV1::NoRoster);
            assert!(observed.election(failure_id).is_none());
        }

        if sequence < MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            assert_eq!(observed.attempt().status, GovernanceAttemptStatusV1::Active,);
            if sequence == 0 || sequence + 1 == MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                // An unrelated transaction from the same citizen applies first: the account
                // passes admission and pays its fee, so the refusal that follows is neither a
                // fee nor an admission rejection.
                submit_parliament_instructions(
                    &citizen_client,
                    [Log::new(
                        Level::INFO,
                        "prove the bonded citizen passes admission and fees".to_owned(),
                    )],
                )
                .await?;
                let control_height = request_height
                    .checked_add(1)
                    .ok_or_else(|| eyre!("hidden-capacity control height overflow"))?;
                observe_exact_height(
                    &client,
                    control_height,
                    "hidden-capacity citizen admission control",
                )
                .await?;
                let error = submit_parliament_instructions(
                    &citizen_client,
                    [UnregisterCitizen {
                        owner: citizen.clone(),
                    }],
                )
                .await
                .expect_err("retryable hidden-capacity evidence must retain the bond");
                // The executor refuses to release a bond held by an active attempt. The
                // Applied wait reports that refusal as the typed, state-resolved terminal
                // `Rejected` status of the next block; the status carries no reason text, so
                // the cause is bounded by the applied control above, by the escrow check
                // below and by the release that succeeds once the attempt is terminal.
                let failure = error
                    .chain()
                    .find_map(|cause| {
                        cause.downcast_ref::<iroha::client::TransactionFinalityFailure>()
                    })
                    .ok_or_else(|| {
                        eyre!("retained-bond refusal must be a typed finality failure: {error:?}")
                    })?;
                assert_eq!(
                    failure.response().status.kind,
                    "Rejected",
                    "unexpected retained-bond rejection: {error:?}",
                );
                assert_eq!(
                    failure.response().status.block_height,
                    Some(control_height + 1),
                    "the retained-bond refusal must be committed in the block after the control",
                );
                assert_asset_not_found(
                    &client,
                    &citizen_asset_id,
                    "retryable hidden-capacity evidence keeps the citizenship bond escrowed",
                )
                .await?;
            }
        } else {
            assert_eq!(
                observed.attempt().status,
                GovernanceAttemptStatusV1::Rejected,
            );
            assert_eq!(
                observed.terminal_height(),
                None,
                "terminal_height is reserved for certified-effect execution outcomes",
            );
        }
    }

    // Capacity evidence is recorded without a draw: no generation slot was reached, and no
    // height committed since the first request carries a global beacon pulse.
    let capacity_tip = current_height(&client).await?;
    assert!(
        capacity_tip < first_failed_pulse_height.expect("at least one capacity failure"),
        "the capacity corridor must end before its first native slot",
    );
    for height in first_request_height.expect("at least one capacity request")..=capacity_tip {
        assert_no_global_beacon_pulse_at(
            &client,
            height,
            "pre-request capacity evidence must not consume or demand a beacon pulse",
            &network,
        )
        .await?;
    }
    let rejected_response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    for peer in network.peers() {
        let peer_response = read_on_dedicated_thread({
            let client = peer.client().client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(
            peer_response.state_payload_hex, rejected_response.state_payload_hex,
            "all validators must agree on terminal capacity evidence",
        );
    }

    submit_parliament_instructions(
        &citizen_client,
        [UnregisterCitizen {
            owner: citizen.clone(),
        }],
    )
    .await?;
    let returned_bond = read_on_dedicated_thread({
        let client = client.client().clone();
        move || Ok(client.query_single(FindAssetById::new(citizen_asset_id))?)
    })
    .await?;
    assert_eq!(
        returned_bond.value(),
        &Quantity::from(CAPACITY_BOND_AMOUNT),
        "terminal rejection must release the exact citizenship collateral",
    );

    let restored_height = current_height(&client).await?;
    network.ensure_blocks(restored_height).await?;
    let restart_peer = network
        .peers()
        .last()
        .expect("four-validator network has a restore peer")
        .clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(restart_peer.shutdown_if_started().await);
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("capacity failure restore exceeded {OPERATION_TIMEOUT:?}"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(restored_height),
    )
    .await
    .map_err(|_| eyre!("capacity failure restore did not recover finalized state"))?;
    let restored_response = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_eq!(
        restored_response.state_payload_hex, rejected_response.state_payload_hex,
        "restart must retain the complete typed capacity transcript",
    );
    let restored_bond = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        move || {
            Ok(client.query_single(FindAssetById::new(AssetId::new(
                citizenship_asset_definition,
                citizen,
            )))?)
        }
    })
    .await?;
    assert_eq!(
        restored_bond.value(),
        &Quantity::from(CAPACITY_BOND_AMOUNT),
        "restart must retain the released owner balance",
    );
    Ok(())
}

#[path = "sora_parliament_private_ballot_retry.rs"]
mod private_ballot_retry;
