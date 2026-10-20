//! Real 4→7→4 committee custody with one original fee-blocked AMX decision.
//!
//! This separate workload test intentionally performs real customer payments and
//! committee ceremonies. The two no-successor tests own idle-finality acceptance.

use super::*;
use crate::amx_harness as amx;
use evidence::PendingKind;
use iroha_config::base::toml::WriteExt as _;
use iroha_data_model::{
    asset::AssetBalanceScope,
    parameter::{CustomParameter, system::ConsensusMode},
    sumeragi_amx::AmxOutcomeV1,
    sumeragi_finality::VerifiedSumeragiBlock,
};
use iroha_model_base::domain::DomainId;

#[path = "retained_boundary.rs"]
mod boundary;
#[path = "rotation_evidence.rs"]
mod evidence;
#[path = "rotation_fees.rs"]
mod fee_audit;

// Exactly three epoch handoffs plus the first real customer payment under the
// third successor authority. The scenario submits no later Global work.
const ROTATION_HISTORY_BOUND: u64 = 3 * EPOCH + 1;

// Customer payments use the Global root's existing universal data space.
fn customer_asset() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("rotation", "universal").unwrap(),
        "credit".parse().unwrap(),
    )
}
fn customer() -> AccountId {
    amx::account(&amx::key(0xAB))
}

fn global_root() -> Result<amx::Root> {
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_length_blocks = NonZeroU64::new(EPOCH).unwrap();
    npos.max_validators = 7;
    npos.min_self_bond = 1_000_u64.into();
    npos.evidence_horizon_blocks = EPOCH * 2;
    npos.slashing_delay_blocks = 1;
    npos.validate().map_err(|error| eyre!(error))?;
    let api_token = amx::listener_credential()?;
    let mut builder = NetworkBuilder::new()
        .with_api_token(api_token.clone())
        .with_peers(4)
        .with_max_validator_capacity(7)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_base_seed("native-amx-real-four-seven-four")
        .with_genesis_keypair(amx::genesis_key(0))
        .with_block_cadence(Duration::from_millis(amx::CADENCE_MS))
        .with_peer_startup_timeout(Duration::from_secs(20 * 60))
        .with_npos_genesis_bootstrap(1_000_u64.into())
        .with_committee_validator_p2p_bootstrap(CommitteeValidatorP2pBootstrap::new(4)?)?
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(NonZeroU64::new(EPOCH).unwrap()),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
        .with_genesis_instruction(Register::account(Account::new(amx::account(&amx::relay(
            0,
        )))))
        .with_genesis_instruction(Register::account(Account::new(customer())))
        .with_genesis_instruction(Register::domain(Domain::new(DomainId::try_new(
            "rotation",
            "universal",
        )?)))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            customer_asset(),
            "Rotation customer credit",
            AssetBalancePolicy::Global,
            Some(DomainId::try_new("rotation", "universal")?),
        )))
        .with_genesis_instruction(Mint::asset_quantity(
            10_000_u32,
            AssetId::of(customer_asset(), ALICE_ID.clone()),
        ))
        .with_genesis_instruction(Grant::account_permission(
            iroha_executor_data_model::permission::query::CanReadAllLedgerData,
            amx::account(&amx::genesis_key(0)),
        ))
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom({
                let mut fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
                fees.fee_sink_account_id = iroha_test_samples::ALICE_ID.clone();
                fees.base_fee = ("1").parse().expect("explicit fixture fee quantity");
                fees.per_byte_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_instruction_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_gas_unit_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.into_custom_parameter()
                    .expect("explicit signed fixture fee policy")
            }),
        ))
        .with_config_layer(|layer| {
            layer
                .write(["nexus", "staking", "max_validators"], 8_i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1024_i64 * 1024 * 1024,
                )
                .write(["logger", "filter"], "info,iroha_core::sumeragi=debug");
        });
    for name in ["ivm_gas_accepted_assets", "ivm_gas_units_per_gas"] {
        builder = builder.with_genesis_instruction(SetParameter::new(Parameter::Custom(
            CustomParameter::new(
                name.parse()?,
                iroha_primitives::json::Json::new(norito::json::Value::Array(vec![])),
            ),
        )));
    }
    amx::Root::from_network(0, builder.build(), ConsensusMode::Npos, api_token)
}

fn operators(network: &Network) -> Result<BTreeMap<PeerId, Operator>> {
    network
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
                        .ok_or_else(|| eyre!("real BLS candidate key absent"))?
                        .clone(),
                    pop: peer
                        .bls_pop()
                        .ok_or_else(|| eyre!("real BLS possession proof absent"))?
                        .to_vec(),
                    client,
                },
            ))
        })
        .collect()
}

fn install_genesis_custody(
    global: &amx::Root,
    runtime: &tokio::runtime::Runtime,
    workload: &rotation_payments::CustomerWorkload,
) -> Result<(DisposableGenesisDkgOutput, BTreeMap<PeerId, Vec<u8>>)> {
    let admin = global.network.client();
    let network = &global.network;
    let hash = global.pins.genesis_hash;
    let network_id = network.network_id();
    let scope = global.scope;
    // Keep the ceremony future out of Runtime::block_on's generic stack frame.
    // Each owned customer payment is supervised on a default Tokio worker.
    runtime.block_on(Box::pin(async {
        network.start_all().await?;
        let bundle = network.native_genesis_provisioning_bundle()?;
        ensure!(bundle.block_hash == hash);
        let dkg =
            run_disposable_genesis_dkg(network, finality_limits(), 5, |height, _, deadline| {
                let admin = admin.clone();
                async move {
                    advance_exact_genesis_phase_with_workload(
                        network,
                        height,
                        deadline,
                        Some(workload),
                    )
                    .await?;
                    read_on_dedicated_thread(move || {
                        read_genesis_dkg_finality_chain(
                            &admin, network_id, hash, height, deadline, scope,
                        )
                    })
                    .await
                }
            })
            .await?;
        let install: Vec<InstructionBox> =
            norito::json::from_slice(&fs::read(&dkg.install_instruction_path)?)?;
        ensure!(install.len() == 1);
        read_on_dedicated_thread({
            let admin = admin.clone();
            move || {
                committee_status::submit_and_observe_until(
                    &admin,
                    &admin,
                    Instant::now() + WAIT,
                    |bounded| {
                        bounded.submit_all(install, FeePaymentIntent::authority(vec![], None))
                    },
                )
            }
        })
        .await?;
        network.shutdown().await;
        let catalogs = stage_genesis_brokers(network, &dkg).await?;
        network.start_all().await?;
        network.ensure_blocks(5).await?;
        Ok((dkg, catalogs))
    }))
}

fn deliver_boundary(
    exchange: &amx::Exchange,
    height: u64,
    epoch: u64,
    current: usize,
    next: usize,
    generation: u64,
) -> Result<VerifiedSumeragiBlock> {
    let global = &exchange.roots[0];
    let original = exchange
        .runtime
        .block_on(evidence::global_at(global, height))?;
    evidence::assert_boundary(&original, epoch, current, next, generation)?;
    let budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
    let action = boundary::boundary_delivery(
        &original,
        global.network.network_id(),
        amx::DATASPACES[1],
        epoch,
        &budget,
    )?;
    amx::submit(
        &exchange.roots[2],
        &amx::genesis_key(2),
        vec![action],
        &exchange.runtime,
    )?;
    Ok(original)
}

// Release the historical finality verifier and result before nested child pre-execution.
fn parent_registration_sources(
    global: &amx::Root,
    runtime: &tokio::runtime::Runtime,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let successor = runtime.block_on(evidence::global_at(global, 2))?;
    amx::authenticated_parent_sources(global, runtime, &successor)
}

#[test]
#[ignore = "16 actual processes, real all-seat DKG and paid 4→7→4 workload; needs three isolated network permits"]
fn original_epoch_zero_commit_releases_paid_escrow_after_real_four_seven_four_rotation_and_restart()
-> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_NETWORK_PARALLELISM")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1)
            >= 3
            && std::env::var_os("IROHA_TEST_SERIALIZE_NETWORKS").is_none(),
        "requires three network permits and --test-threads=1"
    );
    init_instruction_registry();
    let mut setup = prepare_rotation_exchange()?;
    recover_original_decision_after_rotation(&mut setup)
}

// Retain only the durable owners between phases. The original test held its
// later proof and rotation frames while native genesis was still executing.
struct RotationSetup {
    exchange: amx::Exchange,
    dkg: DisposableGenesisDkgOutput,
    catalogs: BTreeMap<PeerId, Vec<u8>>,
    admin: iroha::blocking::Client,
    operators: BTreeMap<PeerId, Operator>,
    workload: rotation_payments::CustomerWorkload,
}

// Keep durable setup owners behind one box in the test wrapper. Preparation
// returns before recovery acquires its proof temporaries; the recovery phase
// borrows this same setup without moving the large Exchange through the wrapper.
// TODO: Qualify this phase boundary with the complete default-stack network test.
#[inline(never)]
fn prepare_rotation_exchange() -> Result<Box<RotationSetup>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let global = global_root()?;
    let customer_journal = global.network.env_dir().join("rotation-customer-workflows");
    let workload = rotation_payments::CustomerWorkload::new(
        global.pins.clone(),
        global.genesis_wire.clone(),
        customer_asset(),
        customer(),
        amx::fee_intent(),
        customer_journal,
        NonZeroU64::new(ROTATION_HISTORY_BOUND).unwrap(),
    )?;
    let (dkg, catalogs) = install_genesis_custody(&global, &runtime, &workload)?;
    let admin = global.network.client();
    let operators = operators(&global.network)?;
    // Legitimate bootstrap funding follows the actual genesis custody installation.
    // It is not height padding and never bypasses the committed fee policy.
    let funding = [amx::genesis_key(0), amx::relay(0)]
        .into_iter()
        .map(|key| {
            Transfer::asset_quantity(
                AssetId::of(amx::fee_asset(), ALICE_ID.clone()),
                100_000_u32,
                amx::account(&key),
            )
            .into()
        })
        .collect::<Vec<InstructionBox>>();
    admin.submit_all(funding, amx::fee_intent())?;
    let candidates = global
        .network
        .committee_validators()
        .iter()
        .map(|peer| operators[&peer.id()].clone())
        .collect::<Vec<_>>();
    let escrow = validator_xor_escrow(&global.network.genesis(), &amx::fee_asset())?;
    admit_candidates(
        &admin,
        &candidates,
        global.network.network_id(),
        &amx::fee_asset(),
        &escrow,
    )?;
    let (genesis, successor) = parent_registration_sources(&global, &runtime)?;
    let exchange = amx::Exchange::attach(
        global,
        runtime,
        genesis,
        successor,
        [
            amx::BankFeeProfile::Metered,
            amx::BankFeeProfile::UnfundedRelay,
        ],
        43_200_000,
    )?;
    Ok(Box::new(RotationSetup {
        exchange,
        dkg,
        catalogs,
        admin,
        operators,
        workload,
    }))
}

// Only the original obligation owners cross phases. The old certified decision is
// moved out of its first verified receipt, never reconstructed from later State.
struct FrozenRotationPayment {
    transaction: iroha_data_model::sumeragi_amx::AmxTransactionV1,
    approvals: [iroha_data_model::sumeragi_amx::AmxDebitApprovalV1; 2],
    original_prepare: evidence::PendingCarrier,
    prepare_fee: Quantity,
    original_pending: evidence::PendingCarrier,
    old_decision: iroha_data_model::sumeragi_amx::AmxCertifiedBlockV1,
}

struct FirstRotationHandoff {
    first: PreparedRotation,
    survivors: BTreeSet<PeerId>,
}

// Prepared custody retains owner-private credential directories. Keep both exact
// ceremony owners alive through bank restart, fee audit and the final idle check.
struct RetainedRotationCustody {
    _second: PreparedRotation,
    _first: PreparedRotation,
}

// Keep only durable owners on this orchestration frame. Each completed ceremony
// and proof acquisition frame returns before the next phase is entered.
#[inline(never)]
fn recover_original_decision_after_rotation(setup: &mut RotationSetup) -> Result<()> {
    let pending = freeze_original_rotation_payment(&mut setup.exchange)?;
    let first = perform_first_rotation_handoff(setup, &pending)?;
    let _custody = perform_second_rotation_handoff(setup, &pending, first)?;
    let final_heights = release_original_rotation_payment(&mut setup.exchange, &pending)?;
    verify_final_rotation_effects(&setup.exchange, &setup.workload, final_heights)
}

#[inline(never)]
fn freeze_original_rotation_payment(
    exchange: &mut amx::Exchange,
) -> Result<Box<FrozenRotationPayment>> {
    // The P0 test deliberately pauses this real service between signing and
    // delivery. Give its ordinary bounded retry owner enough scheduling room to
    // capture the original identity; do not change its eight-dispatch contract.
    exchange.roots[0].relay_layer = std::mem::take(&mut exchange.roots[0].relay_layer)
        .write(["amx_relay", "poll_interval_ms"], 5_000_i64);
    exchange
        .runtime
        .block_on(exchange.roots[0].restart_service())?;
    let (transaction, approvals) = exchange.begin(300, 0xA3, false)?;
    let original_prepare =
        evidence::pause_with_pending(exchange, transaction.id()?, PendingKind::Prepare)?;
    let prepare_fee = evidence::native_carrier_fee(&exchange.roots[2], &original_prepare)?;
    amx::submit(
        &exchange.roots[2],
        &amx::genesis_key(2),
        vec![
            Transfer::asset_quantity(
                AssetId::with_scope(
                    amx::fee_asset(),
                    amx::account(&amx::genesis_key(2)),
                    AssetBalanceScope::Dataspace(amx::DATASPACES[1]),
                ),
                prepare_fee.clone(),
                amx::account(&amx::relay(2)),
            )
            .into(),
        ],
        &exchange.runtime,
    )?;
    evidence::assert_preserved(
        exchange,
        transaction.id()?,
        PendingKind::Prepare,
        &original_prepare,
    )?;
    exchange
        .runtime
        .block_on(exchange.roots[0].restart_service())?;
    let mut original = exchange.observe(
        &transaction,
        &approvals,
        AmxOutcomeV1::Commit,
        [true, false],
    )?;
    let old_decision = original.decisions[0]
        .take()
        .ok_or_else(|| eyre!("actual epoch-zero decision proof absent"))?;
    let global_client = exchange.roots[0].client(&amx::relay(0));
    let global_tip = exchange
        .runtime
        .block_on(amx::status_poll::read_once(
            global_client.client().torii_request_timeout(),
            || async {
                global_client
                    .client()
                    .status()
                    .get()
                    .await
                    .map_err(Into::into)
            },
        ))?
        .blocks;
    ensure!(
        global_tip < EPOCH,
        "initial payment must be decided in epoch zero"
    );
    let certified = exchange
        .runtime
        .block_on(evidence::global_at(&exchange.roots[0], global_tip))?;
    ensure!(certified.commitment().schedule.current.authorization.epoch == 0);
    // The funding was consumed only by Prepare; Settle is durably signed but
    // cannot debit principal or fees until explicitly replenished after rotation.
    let original_pending =
        evidence::pause_with_pending(exchange, transaction.id()?, PendingKind::Settle)?;
    evidence::wait_frozen_obligation(
        exchange,
        &transaction,
        &approvals[1],
        &original_prepare,
        &prepare_fee,
    )?;
    Ok(Box::new(FrozenRotationPayment {
        transaction,
        approvals,
        original_prepare,
        prepare_fee,
        original_pending,
        old_decision,
    }))
}

#[inline(never)]
fn perform_first_rotation_handoff(
    setup: &RotationSetup,
    pending: &FrozenRotationPayment,
) -> Result<FirstRotationHandoff> {
    let RotationSetup {
        exchange,
        dkg,
        catalogs,
        admin,
        operators,
        workload,
    } = setup;
    let FrozenRotationPayment {
        transaction,
        original_pending,
        ..
    } = pending;
    let initial = exchange.roots[0]
        .network
        .validators()
        .iter()
        .map(NetworkPeer::id)
        .collect::<Vec<_>>();
    exchange.runtime.block_on(advance_to_height_with_workload(
        &exchange.roots[0].network,
        &initial,
        SELECTION + 1,
        Some(workload),
    ))?;
    deliver_boundary(exchange, SELECTION, 0, 4, 4, 0)?;
    let preparation = exchange
        .runtime
        .block_on(read_validator_committee(admin, 2))?
        .selected
        .ok_or_else(|| eyre!("real seven-seat preparation absent"))?
        .transition
        .preparation;
    ensure!(preparation.committee.len() == 7 && preparation.selection_height == SELECTION);
    let current = genesis_current_custody(dkg, catalogs)?;
    let first = exchange
        .runtime
        .block_on(execute_rotation_preparation_with_workload(
            &exchange.roots[0].network,
            admin,
            operators,
            &preparation,
            &RotationSignerCustody {
                current_custody: &current,
                provider_revision: 2,
                missing_custody: None,
            },
            exchange.roots[0].pins.genesis_hash,
            Some(workload),
        ))?;
    // The real DKG owner restarts peers with ordinary config; the intentionally
    // paused AMX service stays absent while its exact journal remains on disk.
    evidence::assert_preserved(
        exchange,
        transaction.id()?,
        PendingKind::Settle,
        original_pending,
    )?;
    let survivors = first
        .target
        .iter()
        .take(4)
        .cloned()
        .collect::<BTreeSet<_>>();
    for (peer, owner) in operators {
        if survivors.contains(peer) {
            continue;
        }
        committee_status::submit_and_observe_until(
            &owner.client,
            admin,
            Instant::now() + WAIT,
            |bounded| {
                bounded.submit(
                    ExitPublicLaneValidator {
                        lane_id: LaneId::SINGLE,
                        validator: owner.account.clone(),
                        release_at_ms: committee_staking::finite_release_deadline()?,
                    },
                    FeePaymentIntent::authority(vec![], None),
                )
            },
        )?;
    }
    exchange.runtime.block_on(advance_to_height_with_workload(
        &exchange.roots[0].network,
        &initial,
        CUTOFF,
        Some(workload),
    ))?;
    deliver_boundary(exchange, CUTOFF, 1, 4, 7, 1)?;
    exchange.runtime.block_on(advance_to_height_with_workload(
        &exchange.roots[0].network,
        &first.target,
        TARGET_FIRST,
        Some(workload),
    ))?;
    Ok(FirstRotationHandoff { first, survivors })
}

#[inline(never)]
fn perform_second_rotation_handoff(
    setup: &RotationSetup,
    pending: &FrozenRotationPayment,
    handoff: FirstRotationHandoff,
) -> Result<Box<RetainedRotationCustody>> {
    let RotationSetup {
        exchange,
        admin,
        operators,
        workload,
        ..
    } = setup;
    let FrozenRotationPayment {
        transaction,
        original_pending,
        ..
    } = pending;
    let FirstRotationHandoff { first, survivors } = handoff;
    let return_preparation = exchange
        .runtime
        .block_on(read_validator_committee(admin, 3))?
        .selected
        .ok_or_else(|| eyre!("real four-seat return preparation absent"))?
        .transition
        .preparation;
    ensure!(
        return_preparation
            .committee
            .iter()
            .map(|seat| seat.validator.clone())
            .collect::<BTreeSet<_>>()
            == survivors
    );
    let current = prepared_current_custody(&first.prepared)?;
    let second = exchange
        .runtime
        .block_on(execute_rotation_preparation_with_workload(
            &exchange.roots[0].network,
            admin,
            operators,
            &return_preparation,
            &RotationSignerCustody {
                current_custody: &current,
                provider_revision: 3,
                missing_custody: None,
            },
            exchange.roots[0].pins.genesis_hash,
            Some(workload),
        ))?;
    // The real DKG owner restarts peers with ordinary config; the intentionally
    // paused AMX service stays absent while its exact journal remains on disk.
    evidence::assert_preserved(
        exchange,
        transaction.id()?,
        PendingKind::Settle,
        original_pending,
    )?;
    exchange.runtime.block_on(advance_to_height_with_workload(
        &exchange.roots[0].network,
        &first.target,
        TARGET_LAST,
        Some(workload),
    ))?;
    deliver_boundary(exchange, TARGET_LAST, 2, 7, 4, 2)?;
    exchange.runtime.block_on(advance_to_height_with_workload(
        &exchange.roots[0].network,
        &second.target,
        TARGET_LAST + 1,
        Some(workload),
    ))?;
    Ok(Box::new(RetainedRotationCustody {
        _second: second,
        _first: first,
    }))
}

#[inline(never)]
fn release_original_rotation_payment(
    exchange: &mut amx::Exchange,
    pending: &FrozenRotationPayment,
) -> Result<[u64; 3]> {
    let FrozenRotationPayment {
        transaction,
        approvals,
        original_prepare,
        prepare_fee,
        original_pending,
        old_decision,
    } = pending;
    exchange.runtime.block_on(exchange.roots[2].restart_all())?;
    evidence::wait_frozen_obligation(
        exchange,
        transaction,
        &approvals[1],
        original_prepare,
        prepare_fee,
    )?;
    evidence::assert_preserved(
        exchange,
        transaction.id()?,
        PendingKind::Settle,
        original_pending,
    )?;
    let settle_fee = evidence::native_carrier_fee(&exchange.roots[2], original_pending)?;
    amx::submit(
        &exchange.roots[2],
        &amx::genesis_key(2),
        vec![
            Transfer::asset_quantity(
                AssetId::with_scope(
                    amx::fee_asset(),
                    amx::account(&amx::genesis_key(2)),
                    AssetBalanceScope::Dataspace(amx::DATASPACES[1]),
                ),
                // Fund the original delivery and one separately authorized replay
                // control; both pay the same positive immutable schedule.
                settle_fee.checked_add(&settle_fee)?,
                amx::account(&amx::relay(2)),
            )
            .into(),
        ],
        &exchange.runtime,
    )?;
    evidence::assert_preserved(
        exchange,
        transaction.id()?,
        PendingKind::Settle,
        original_pending,
    )?;
    exchange
        .runtime
        .block_on(exchange.roots[0].restart_service())?;
    let recovered = exchange.observe(transaction, approvals, AmxOutcomeV1::Commit, [true; 2])?;
    ensure!(
        recovered.deliveries[1].is_some_and(|(_, hash)| hash == original_pending.hash()),
        "funding must recover the exact original signed Settle rather than manufacture a new carrier"
    );
    ensure!(
        recovered.decisions[1].as_ref() == Some(old_decision),
        "delayed settlement must retain the exact old certified decision"
    );
    evidence::rejected_replay(exchange, original_pending)?;
    let replayed = exchange.observe(transaction, approvals, AmxOutcomeV1::Commit, [true; 2])?;
    assert_same_original_receipts(&recovered, &replayed)?;
    exchange.runtime.block_on(exchange.roots[2].restart_all())?;
    let restarted = exchange.observe(transaction, approvals, AmxOutcomeV1::Commit, [true; 2])?;
    assert_same_original_receipts(&recovered, &restarted)?;
    let final_heights = exchange.quiescent_heights()?;
    ensure!(
        final_heights[0] == ROTATION_HISTORY_BOUND,
        "the three-handoff workload must end at its exact first successor, without later Global traffic"
    );
    Ok(final_heights)
}

#[inline(never)]
fn verify_final_rotation_effects(
    exchange: &amx::Exchange,
    workload: &rotation_payments::CustomerWorkload,
    final_heights: [u64; 3],
) -> Result<()> {
    for (root, height) in exchange.roots.iter().zip(final_heights) {
        fee_audit::audit(root, height, &exchange.runtime)?;
    }
    assert_final_customer_effects(exchange, workload)?;
    exchange.assert_no_background_blocks(final_heights)
}

// The final complete-World proof is acquired only after the rotation and fee
// checks finish; it need not enlarge either root construction or ceremony frames.
#[inline(never)]
fn assert_final_customer_effects(
    exchange: &amx::Exchange,
    workload: &rotation_payments::CustomerWorkload,
) -> Result<()> {
    // Authenticate aggregate customer effects against the final complete World;
    // a query response or height locator alone cannot establish monetary credit.
    exchange.runtime.block_on(async {
        let cut = amx::fees::world_cut(&exchange.roots[0]).await?;
        let height = cut
            .attestation
            .body
            .finality_proof
            .block_header
            .height()
            .get();
        let final_block = evidence::global_at(&exchange.roots[0], height).await?;
        let world = cut.world_snapshot.authenticate(&final_block)?;
        ensure!(
            world.schema_hash()
                == iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?
        );
        world.verify_table_value(
            "world.assets",
            &AssetId::of(customer_asset(), customer()),
            &iroha_data_model::asset::AssetValue::new(workload.credited_units()?),
        )?;
        Ok::<_, eyre::Report>(())
    })?;
    Ok(())
}

fn assert_same_original_receipts(
    expected: &amx::ExchangeReceipt,
    actual: &amx::ExchangeReceipt,
) -> Result<()> {
    ensure!(
        actual.deliveries == expected.deliveries
            && actual.decisions == expected.decisions
            && actual.results == expected.results
            && actual.fees == expected.fees,
        "replay and cold bank restart must retain the exact original successful carrier, execution output, fee receipt and certified Decision"
    );
    Ok(())
}
