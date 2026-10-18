//! Four-validator failure-path coverage for SORA Parliament attempt custody.

use super::*;
use iroha::data_model::{
    asset::{AssetBalancePolicy, AssetDefinition},
    domain::Domain,
    governance::types::{
        BodyElectionAttemptStatusV1, MAX_PARLIAMENT_SORTITION_RETRIES_V1,
        MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
    },
    isi::governance::UnregisterCitizen,
    prelude::{AssetDefinitionId, AssetId, FindAssetById, Mint, Quantity},
};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::BOB_ID;

const CAPACITY_BOND_AMOUNT: u64 = 37;
const CAPACITY_PUBLIC_SEATS: u32 = 1;
const CAPACITY_HIDDEN_SEATS: u32 = MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1;
const CAPACITY_SORTITION_DELAY_BLOCKS: u64 = 4;

pub(super) struct ThresholdSessionsV1 {
    pub(super) logical_beacon: BeaconSessionId,
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
    let install_height = next_execution_height(
        client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "failure-corridor threshold-key installation",
    )
    .await?;
    submit_parliament_instructions(
        &client,
        [InstructionBox::from(lifecycle_certificate(
            network,
            &ordered_roster,
            ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            beacon_record.session.session_id,
            beacon_record.session.transcript_hash,
            norito::encode_canonical(&beacon_record)?,
            install_height,
        )?)],
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
