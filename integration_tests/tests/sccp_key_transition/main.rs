//! Actual SCCP key-change certificates from native four-to-seven committee activation.
//!
//! The parent supplies the unchanged public DKG, signer custody, readiness and finality
//! helpers. This child supplies only SCCP genesis and observations; no Parliament route
//! authority, alternate key lifecycle, synthetic block or clock is introduced.

use super::*;
use iroha::data_model::{
    isi::sccp::InitializeSccpV1,
    parameter::{CustomParameter, governance_clock::GovernanceClockParametersV1},
    sccp::{
        generation::SccpGenerationCauseV1,
        params::{SCCP_MIN_EPOCH_MS_V1, SccpParametersV1},
    },
};
use iroha::{client::sccp::SccpFinalityAt, crypto::Algorithm};
use iroha_sccp::{
    api::{SccpCertificateV1, SccpGenerationV1},
    v1::{
        committee::committee_root,
        finality::{SccpFinalityHeaderV1, verify_certificate},
    },
};

const SCENARIO: &str = "sccp_native_four_to_seven_key_change";
const CADENCE_MS: u64 = SCCP_MIN_EPOCH_MS_V1 / EPOCH;
const DRIFT_MS: u64 = 1_000;
const DUE_WORK_LAG_MS: u64 = 2 * DRIFT_MS + 4 * CADENCE_MS;

fn write_json(name: &str, value: &norito::json::Value) -> Result<()> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("target/sccp-continuation");
    fs::create_dir_all(&directory)?;
    let temporary = directory.join(format!("{name}.tmp"));
    fs::write(&temporary, norito::json::to_vec(value)?)?;
    fs::rename(temporary, directory.join(name))?;
    Ok(())
}

fn progress(stage: &str, height: u64) -> Result<()> {
    let value = norito::json!({
        "stage": stage, "height": height,
        "wall_ms": (u64::try_from(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?.as_millis())?),
    });
    write_json("live-fourpeer-sccp-key-change-progress.json", &value)?;
    eprintln!("SCCP_KEY_CHANGE {}", norito::json::to_json(&value)?);
    Ok(())
}

async fn advance_in_bounded_chunks(
    network: &sandbox::SerializedNetwork,
    voters: &[PeerId],
    target: u64,
) -> Result<()> {
    loop {
        let current =
            committee_status::height_until(network.client().client(), Instant::now() + WAIT)
                .await?;
        if current >= target {
            return Ok(());
        }
        // Eight genuine 56.25-second blocks fit the unchanged 600-second progress
        // deadline. Each paid transaction still waits for the exact preceding cut.
        let next = current.saturating_add(8).min(target);
        advance_to_height(network, voters, next).await?;
        progress("ordinary_progress", next)?;
    }
}

fn ordered_keys(block: &CertifiedBlock) -> Result<Vec<[u8; 48]>> {
    block
        .commitment()
        .schedule
        .current
        .committee
        .iter()
        .map(|seat| {
            let (algorithm, bytes) = seat.validator.public_key().try_to_bytes()?;
            ensure!(algorithm == Algorithm::BlsNormal);
            bytes
                .try_into()
                .map_err(|_| eyre!("native committee key width"))
        })
        .collect()
}

type NativeCut = (u64, [u8; 221], [u8; 32], [u8; 32]);

struct SccpObservations {
    certificates: Vec<SccpCertificateV1>,
    generations: Vec<SccpGenerationV1>,
}

fn original_sccp_observations(
    clients: &[Client],
    instance: &[u8; 32],
    old_keys: &[[u8; 48]],
    new_keys: &[[u8; 48]],
    native_cuts: &[NativeCut],
) -> Result<SccpObservations> {
    ensure!(clients.len() == 7);
    let old_root = committee_root(old_keys).ok_or_else(|| eyre!("old committee root"))?;
    let new_root = committee_root(new_keys).ok_or_else(|| eyre!("new committee root"))?;
    ensure!(old_root != new_root);
    let mut certificates = Vec::new();
    for (height, generation, keys, rotation) in [
        (CUTOFF - 1, 1, old_keys, false),
        (CUTOFF, 1, old_keys, true),
        (TARGET_FIRST, 2, new_keys, false),
    ] {
        let mut first = None;
        let mut certified = None;
        for client in clients {
            let capabilities = client.sccp().capabilities()?;
            ensure!(!capabilities.parliament_binding_ballot_available);
            ensure!(!client.sccp().fast_pause()?.eligibility_available);
            let certificate = client
                .sccp()
                .finality(SccpFinalityAt::Height(NonZeroU64::new(height).unwrap()))?;
            ensure!(certificate.height == height && certificate.committee == keys);
            let checked = verify_certificate(
                instance,
                &certificate.qc,
                &certificate.header,
                &certificate.aggregate_signature,
                keys,
            )?;
            ensure!(checked.header.is_active() && checked.header.is_rotation() == rotation);
            ensure!(checked.header.generation() == generation);
            ensure!(checked.qc.signers.count_ones() == exact_quorum(keys.len())?);
            if rotation {
                ensure!(checked.header.next_committee_root() == new_root);
            }
            let cut = (certificate.header, checked.qc.block_hash, checked.result);
            let expected = native_cuts
                .iter()
                .find(|cut| cut.0 == height)
                .ok_or_else(|| eyre!("missing independent native certificate cut"))?;
            ensure!(
                cut == (expected.1, expected.2, expected.3),
                "SCCP API differs from the independently genesis-anchored native journal"
            );
            if let Some(expected) = certified {
                ensure!(cut == expected);
            } else {
                certified = Some(cut);
                first = Some(certificate);
            }
        }
        certificates.push(first.ok_or_else(|| eyre!("missing original peer certificate"))?);
    }
    let original = clients[0].sccp().committee(1)?;
    let next = clients[0].sccp().committee(2)?;
    ensure!(original.keys == old_keys && original.liable);
    ensure!(original.members.len() == 4 && original.members.iter().all(Option::is_some));
    ensure!(
        original
            .end
            .as_ref()
            .is_some_and(|end| end.end_height == CUTOFF)
    );
    ensure!(next.keys == new_keys && next.committee_root == new_root);
    ensure!(next.members.len() == 7 && next.members.iter().all(Option::is_some));
    ensure!(next.cause == SccpGenerationCauseV1::KeyChange && next.start_height == TARGET_FIRST);
    ensure!(
        next.start_timestamp_ms
            == SccpFinalityHeaderV1::parse(&certificates[1].header)?.timestamp_ms()
    );
    for client in &clients[1..] {
        ensure!(client.sccp().committee(1)? == original && client.sccp().committee(2)? == next);
    }
    Ok(SccpObservations {
        certificates,
        generations: vec![original, next],
    })
}

async fn run_key_change() -> Result<()> {
    init_instruction_registry();
    let pool_size = 7;
    let seats = 7;
    let supplementary = pool_size - 4;
    let registry_capacity = i64::try_from(pool_size.max(7))?;
    let xor: AssetDefinitionId = defaults::nexus::staking::stake_asset_id().parse()?;
    ensure!(
        xor.to_string() == TAIRA_XOR,
        "staking must use real genesis-pinned XOR"
    );
    let npos = SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(EPOCH).expect("nonzero epoch"),
        max_validators: 7,
        min_self_bond: 1_000_u64.into(),
        evidence_horizon_blocks: EPOCH * 2,
        slashing_delay_blocks: 1,
        ..SumeragiNposParameters::default()
    };
    npos.validate().map_err(|error| eyre!(error))?;
    let clock = GovernanceClockParametersV1 {
        due_work_max_lag_ms: DUE_WORK_LAG_MS,
        ..GovernanceClockParametersV1::default()
    };
    clock
        .validate(DRIFT_MS, CADENCE_MS)
        .map_err(|error| eyre!(error))?;
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_max_validator_capacity(7)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_npos_genesis_bootstrap(1_000_u64.into())
        .with_block_cadence(Duration::from_millis(CADENCE_MS))
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::MaxClockDriftMs(DRIFT_MS),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::PayloadRetryIntervalMs(NonZeroU64::new(CADENCE_MS).unwrap()),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::DueWorkMaxLagMs(NonZeroU64::new(DUE_WORK_LAG_MS).unwrap()),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(CustomParameter::new(
            GovernanceClockParametersV1::parameter_id().clone(),
            norito::json::to_json(&clock)?.parse::<iroha_primitives::json::Json>()?,
        ))))
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(NonZeroU64::new(EPOCH).expect("nonzero epoch")),
        )))
        .with_committee_validator_p2p_bootstrap(CommitteeValidatorP2pBootstrap::new(
            supplementary,
        )?)?
        .with_config_layer(|layer| {
            // Admission may retain a larger candidate pool than the seven-seat
            // consensus ceiling; the authenticated election selects exactly 3f+1.
            layer
                .write(["nexus", "staking", "max_validators"], registry_capacity)
                .write(
                    ["nexus", "staking", "unbonding_delay_ms"],
                    1_814_400_000_i64,
                )
                .write(["nexus", "staking", "max_slash_bps"], 1_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                );
            // Retain durable vote and driver evidence across each paid rotation
            // and all-seat restart so a stalled readiness submission is diagnosable.
            layer.write(["logger", "filter"], "info,iroha_core::sumeragi=debug");
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )));
    let builder = builder.with_genesis_post_bootstrap_isi(vec![
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x6b; 32],
        }
        .into(),
    ]);
    let network = sandbox::build_network_or_skip(builder, SCENARIO).ok_or_else(|| {
        eyre!("SCCP key-change qualification requires seven actual validator processes")
    })?;
    let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
        .sumeragi_context
        .root_scope;
    let result = Box::pin(async {
        let genesis_bundle = network.native_genesis_provisioning_bundle()?;
        ensure!(
            genesis_bundle.block_hash == network.genesis().0.hash(),
            "genesis provisioners must consume the retained signed manifest and block"
        );
        network.start_all().await?;
        network.ensure_blocks(1).await?;
        progress("genesis_started", 1)?;
        let admin = rebind_blocking_client(&network.client(), |builder| {
            builder.transaction_status_timeout = WAIT;
        });
        let network_id = network.network_id();
        let block_hash = genesis_bundle.block_hash;
        let network_ref = &network;
        let genesis_dkg = Box::pin(run_disposable_genesis_dkg(
            &network,
            finality_limits(),
            5,
            |height, _public_snapshot, deadline| {
                let admin = admin.clone();
                async move {
                    advance_exact_genesis_phase(network_ref, height, deadline).await?;
                    let observed = read_on_dedicated_thread({
                        let admin = admin.clone();
                        move || -> Result<u64> {
                            committee_status::height_until_blocking(&admin, deadline)
                        }
                    })
                    .await
                    .wrap_err("genesis phase status worker failed")?;
                    ensure!(
                        observed == height,
                        "genesis DKG public phase missed exact h{height} observation"
                    );
                    read_on_dedicated_thread(move || {
                        read_genesis_dkg_finality_chain(
                            &admin, network_id, block_hash, height, deadline, root_scope,
                        )
                    })
                    .await
                    .wrap_err("genesis phase finality worker failed")
                }
            },
        ))
        .await?;
        let install: Vec<InstructionBox> =
            norito::json::from_slice(&fs::read(&genesis_dkg.install_instruction_path)?)?;
        ensure!(
            install.len() == 1,
            "native genesis install must emit one instruction"
        );
        let next_height = read_on_dedicated_thread({
            let admin = admin.clone();
            move || -> Result<u64> {
                Ok(committee_status::height_until_blocking(&admin, Instant::now() + WAIT)? + 1)
            }
        })
        .await
        .wrap_err("genesis install height worker failed")?;
        ensure!(
            next_height == 5,
            "genesis installation must execute immediately after the exact h4 DKG cutoff"
        );
        read_on_dedicated_thread({
            let admin = admin.clone();
            move || admin.submit_all(install, FeePaymentIntent::authority(Vec::new(), None))
        })
        .await
        .wrap_err("genesis beacon install worker failed")?;
        network.shutdown().await;
        let genesis_catalogs = stage_genesis_brokers(&network, &genesis_dkg).await?;
        network.start_all().await?;
        network.ensure_blocks(5).await?;
        ensure!(
            network.validators().len() == 4
                && network.committee_validators().len() == supplementary,
            "fixture must start four genesis voters and the exact separate candidate pool"
        );
        let network_id = network.network_id();
        let genesis_voters = network
            .validators()
            .iter()
            .map(iroha_test_network::NetworkPeer::id)
            .collect::<BTreeSet<_>>();
        let pool = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .map(iroha_test_network::NetworkPeer::id)
            .collect::<BTreeSet<_>>();
        ensure!(
            pool.len() == pool_size,
            "all candidate BLS keys must be distinct"
        );
        let escrow = validator_xor_escrow(&network.genesis(), &xor)?;
        ensure!(
            escrow.definition == xor,
            "genesis escrow must hold actual XOR"
        );
        let operators = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .map(|peer| {
                let account = peer.account_id();
                let client = rebind_blocking_client(
                    &network.validators()[0]
                        .client_for(&account, peer.streaming_key_pair().private_key().clone()),
                    |builder| builder.transaction_status_timeout = WAIT,
                );
                Ok((
                    peer.id(),
                    Operator {
                        account,
                        peer: peer.id(),
                        consensus_key: peer
                            .bls_key_pair()
                            .ok_or_else(|| eyre!("missing real BLS candidate key"))?
                            .clone(),
                        pop: peer
                            .bls_pop()
                            .ok_or_else(|| eyre!("missing real BLS possession proof"))?
                            .to_vec(),
                        client,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let fresh_peers = network
            .committee_validators()
            .iter()
            .map(iroha_test_network::NetworkPeer::id)
            .collect::<Vec<_>>();
        let candidates = fresh_peers
            .iter()
            .map(|peer| {
                operators
                    .get(peer)
                    .ok_or_else(|| eyre!("missing candidate operator"))
            })
            .collect::<Result<Vec<_>>>()?;
        let initial_height = read_on_dedicated_thread({
            let admin = admin.clone();
            let xor = xor.clone();
            let escrow = escrow.clone();
            let candidates = candidates.into_iter().cloned().collect::<Vec<_>>();
            move || -> Result<u64> {
                admit_candidates(&admin, &candidates, network_id, &xor, &escrow)?;
                committee_status::height_until_blocking(&admin, Instant::now() + WAIT)
            }
        })
        .await
        .wrap_err("candidate admission worker failed")?;
        ensure!(
            initial_height < SELECTION,
            "candidate pool did not enter the selecting prestate"
        );
        progress("candidate_admission_complete", initial_height)?;
        let initial_generation = read_on_dedicated_thread({
            let admin = admin.clone();
            move || -> Result<_> { Ok(admin.sccp().committee(1)?) }
        })
        .await?;
        ensure!(initial_generation.end.is_none() && initial_generation.keys.len() == 4);
        let initial_roster = network
            .validators()
            .iter()
            .map(iroha_test_network::NetworkPeer::id)
            .collect::<Vec<_>>();
        // Selection is certified at the final height of E. Preparation evidence
        // must also certify an E+1 block under the preparing authorization. The
        // progress helper stops exactly at its target, so pay for that successor
        // explicitly instead of relying on an accidental boundary overshoot.
        advance_in_bounded_chunks(&network, &initial_roster, SELECTION + 1).await?;
        let before = read_validator_committee(&admin, 2).await?;
        let selected = before
            .selected
            .as_ref()
            .ok_or_else(|| eyre!("boundary did not freeze E+2"))?;
        let preparation = selected.transition.preparation.clone();
        preparation.validate().map_err(|error| eyre!(error))?;
        let target = preparation
            .committee
            .iter()
            .map(|seat| seat.validator.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            preparation.network_id == network_id
                && preparation.selection_epoch == 0
                && preparation.selection_height == SELECTION
                && preparation.target_epoch == 2
                && preparation.first_height == TARGET_FIRST
                && preparation.last_height == TARGET_LAST
                && preparation.authority_generation == 1
                && target.len() == seats
                && target == ranked_target(&preparation, &pool, seats)
                && target.is_subset(&pool),
            "selection must freeze the exact public rank and 3f+1 size for the full candidate pool"
        );
        ensure!(
            target.intersection(&genesis_voters).count() >= seats.saturating_sub(supplementary),
            "selected incumbent overlap must satisfy the actual candidate pool geometry"
        );
        for seat in &preparation.committee {
            ensure!(
                operators
                    .get(&seat.validator)
                    .is_some_and(|operator| operator.pop == seat.proof_of_possession),
                "frozen seat must carry its real BLS possession proof"
            );
        }
        progress("selection_verified", SELECTION + 1)?;
        let current_custody = genesis_current_custody(&genesis_dkg, &genesis_catalogs)?;
        let prepared = execute_rotation_preparation(
            &network,
            &admin,
            &operators,
            &preparation,
            &RotationSignerCustody {
                current_custody: &current_custody,
                provider_revision: 2,
                missing_custody: None,
            },
            genesis_bundle.block_hash,
        )
        .await?;
        ensure!(prepared.target.len() == 7 && prepared.prepared.len() == 7);
        progress("all_seven_target_custodians_ready", SELECTION + 1)?;
        advance_in_bounded_chunks(&network, &initial_roster, CUTOFF).await?;
        advance_to_height(&network, &prepared.target, TARGET_FIRST).await?;
        let (_, chain) = read_on_dedicated_thread({
            let admin = admin.clone();
            move || {
                read_contiguous_finality_chain(
                    &admin,
                    network_id,
                    genesis_bundle.block_hash,
                    TARGET_FIRST,
                    root_scope,
                )
            }
        })
        .await?;
        let boundary = chain
            .iter()
            .find(|block| block.height() == CUTOFF)
            .ok_or_else(|| eyre!("missing original key-change boundary"))?;
        let successor = chain
            .last()
            .ok_or_else(|| eyre!("missing new-committee successor"))?;
        verify_equal_vote_context(boundary, &genesis_voters)?;
        let next_voters = prepared.target.iter().cloned().collect::<BTreeSet<_>>();
        verify_equal_vote_context(successor, &next_voters)?;
        let next = &boundary
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .ok_or_else(|| eyre!("key-change boundary lacks native epoch effect"))?
            .next;
        ensure!(next.authorization.decision == ValidatorEpochDecisionV1::Activate);
        ensure!(next.authorization.epoch == 2 && next.authorization.authority_generation == 1);
        ensure!(
            next.authorization.transition_id
                == preparation.transition_id().map_err(|e| eyre!(e))?
        );
        ensure!(
            next.committee
                .iter()
                .map(|seat| &seat.validator)
                .eq(prepared.target.iter())
        );
        ensure!(successor.commitment().schedule.current == *next);
        let old_keys = ordered_keys(boundary)?;
        let new_keys = ordered_keys(successor)?;
        ensure!(old_keys.len() == 4 && new_keys.len() == 7 && old_keys != new_keys);
        ensure!(initial_generation.keys == old_keys);
        let instance = iroha_sumeragi::preimage::instance_id(
            &iroha_core::sumeragi::crypto::BlsCrypto::new(),
            &iroha_sumeragi::types::Hash32(*network_id.as_bytes()),
            network.chain_id().as_str().as_bytes(),
            iroha_sumeragi::preimage::InstanceKind::Global,
            0,
        )
        .0;
        let clients = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .map(NetworkPeer::client)
            .collect::<Vec<_>>();
        let native_cuts = chain
            .iter()
            .filter(|block| (CUTOFF - 1..=TARGET_FIRST).contains(&block.height()))
            .map(|block| {
                (
                    block.height(),
                    *block.certified_result().header().as_bytes(),
                    block.core_hash().0,
                    block.result().0,
                )
            })
            .collect::<Vec<_>>();
        let observations = read_on_dedicated_thread({
            let old_keys = old_keys.clone();
            let new_keys = new_keys.clone();
            move || {
                original_sccp_observations(&clients, &instance, &old_keys, &new_keys, &native_cuts)
            }
        })
        .await?;
        let export = norito::json!({
            "version": 1,
            "chain_id": (network.chain_id().as_str()),
            "network_id": (network_id.as_bytes()),
            "consensus_instance": instance,
            "signed_genesis_wire": (network.genesis().0.encode_wire()?),
            "initial_generation": initial_generation,
            "certificates": (observations.certificates),
            "certificate_roles": ["normal", "key_change", "successor"],
            "generations": (observations.generations),
            "transition": {
                "selection_height": SELECTION,
                "target_epoch": 2,
                "boundary_height": CUTOFF,
                "successor_height": TARGET_FIRST,
                "preparation": preparation,
                "ordered_old_committee": old_keys,
                "ordered_new_committee": new_keys,
                "original_boundary_wire": (boundary.block().encode_wire()?),
                "original_successor_wire": (successor.block().encode_wire()?),
            },
        });
        write_json("live-fourpeer-sccp-key-change.json", &export)?;
        progress("completed", TARGET_FIRST)?;
        Ok(())
    })
    .await;
    network.shutdown_and_release().await;
    result
}

#[test]
fn actual_native_key_change_rotates_sccp_four_to_seven() -> Result<()> {
    const STACK: usize = 32 * 1024 * 1024;
    let worker = std::thread::Builder::new()
        .name(SCENARIO.to_owned())
        .stack_size(STACK)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(STACK)
                .enable_all()
                .build()?
                .block_on(run_key_change())
        })?;
    match worker.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn native_key_change_geometry_preserves_real_one_hour_epochs() {
    assert_eq!(EPOCH * CADENCE_MS, SCCP_MIN_EPOCH_MS_V1);
    assert!(Duration::from_millis(8 * CADENCE_MS) < WAIT);
    assert_eq!((SELECTION, CUTOFF, TARGET_FIRST), (64, 128, 129));
    assert_eq!(DUE_WORK_LAG_MS, 227_000);
    assert!(
        GovernanceClockParametersV1 {
            due_work_max_lag_ms: DUE_WORK_LAG_MS,
            ..GovernanceClockParametersV1::default()
        }
        .validate(DRIFT_MS, CADENCE_MS)
        .is_ok()
    );
    assert!(SccpParametersV1::taira_default().committee_heartbeat_ms > 3 * SCCP_MIN_EPOCH_MS_V1);
}
