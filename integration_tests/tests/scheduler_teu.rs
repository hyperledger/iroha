//! Native pending-owner TEU accounting through certified execution.
//!
//! Configured legacy lane-router selection and guard-drop cleanup are retired.
//! Actual policy admission/routing is covered in Core's
//! `sumeragi::lanes::routing` tests; this test observes the real queue lifecycle.
#![cfg(feature = "telemetry")]
use eyre::Result;
use iroha_config::parameters::actual::{Nexus, Queue as QueueConfig};
use iroha_core::{
    gas,
    queue::{ConfigLaneRouter, LaneRouter, Queue, QueueLimits},
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    telemetry::StateTelemetry,
    tx::AcceptedTransaction,
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    isi::{
        InstructionBox,
        prelude::{Mint, SetKeyValue, Transfer},
    },
    prelude::*,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{json::Json, time::TimeSource};
use iroha_telemetry::metrics::Metrics;
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::broadcast;
fn build_world(authority: &AccountId, domain_id: &DomainId) -> World {
    let domain = Domain::new(domain_id.clone()).build(authority);
    let account = Account::new(authority.clone()).build(authority);
    let asset_definition_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "xor".parse().unwrap());
    let asset_definition = {
        let __asset_definition_id = asset_definition_id;
        AssetDefinition::new(
            __asset_definition_id.clone(),
            "xor".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(authority);
    World::with([domain], [account], [asset_definition])
}
fn build_transaction(
    network_id: NetworkId,
    authority: &AccountId,
    keypair: &KeyPair,
    time_source: &TimeSource,
    instructions: Vec<InstructionBox>,
) -> AcceptedTransaction<'static> {
    let tx = TransactionBuilder::new_with_time_source(
        network_id,
        authority.clone(),
        time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .with_metadata(Metadata::default())
    .sign(keypair.private_key());
    let default_limits = TransactionParameters::default();
    let params = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(4096_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    AcceptedTransaction::accept(
        tx,
        &network_id,
        Duration::from_secs(30),
        params,
        &crypto_cfg,
    )
    .expect("transaction should be accepted")
}
#[test]
fn queue_teu_backlog_matches_metering() -> Result<()> {
    let (account_id, keypair) = gen_account_in("wonderland");
    let wonderland_domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let world = build_world(&account_id, &wonderland_domain);
    let metrics = Arc::new(Metrics::default());
    let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
    let mut nexus = Nexus::default();
    nexus.fusion.exit_teu = 12_345;
    nexus.fees.base_fee = 0_u32.into();
    nexus.fees.per_byte_fee = 0_u32.into();
    nexus.fees.per_instruction_fee = 0_u32.into();
    nexus.fees.per_gas_unit_fee = 0_u32.into();
    let queue_limits = QueueLimits::from_nexus(&nexus);
    let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
        nexus.routing_policy.clone(),
        nexus.dataspace_catalog.clone(),
        nexus.lane_catalog.clone(),
    ));
    let now_ms = u64::try_from(TimeSource::new_system().get_unix_time().as_millis())?;
    let mut config = TestChainConfig::new(world, now_ms);
    config.nexus = Some(nexus);
    let mut prepared = CertifiedTestChain::prepare(config).expect("original signed genesis");
    Arc::get_mut(&mut prepared.state)
        .expect("unshared original state")
        .telemetry = telemetry;
    let mut chain = CertifiedTestChain::from_prepared(prepared).expect("native genesis execution");
    let state = Arc::clone(chain.state());
    let network_id = chain.network_id();
    let (events_sender, _) = broadcast::channel(16);
    let queue_cfg = QueueConfig::default();
    let queue = Arc::new(Queue::from_config_with_router_and_limits(
        queue_cfg,
        events_sender,
        router,
        queue_limits.clone(),
        None,
    ));
    let time_source = TimeSource::new_system();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        wonderland_domain.clone(),
        "xor".parse().unwrap(),
    );
    let asset_id = AssetId::of(asset_definition_id, account_id.clone());
    let mint = Mint::asset_quantity(10_u32, asset_id.clone());
    let transfer = Transfer::asset_quantity(asset_id.clone(), 5_u32, account_id.clone());
    let metadata_instruction = SetKeyValue::account(
        account_id.clone(),
        "teu_key".parse().unwrap(),
        Json::new("value"),
    );
    let txs = vec![
        build_transaction(
            network_id,
            &account_id,
            &keypair,
            &time_source,
            vec![InstructionBox::from(mint.clone())],
        ),
        build_transaction(
            network_id,
            &account_id,
            &keypair,
            &time_source,
            vec![InstructionBox::from(transfer.clone())],
        ),
        build_transaction(
            network_id,
            &account_id,
            &keypair,
            &time_source,
            vec![InstructionBox::from(metadata_instruction.clone())],
        ),
    ];
    let expected_teu: u64 = [
        gas::meter_instructions(
            &[InstructionBox::from(mint.clone())],
            &iroha_core::gas::DEFAULT_ZK_GAS,
        ),
        gas::meter_instructions(
            &[InstructionBox::from(transfer.clone())],
            &iroha_core::gas::DEFAULT_ZK_GAS,
        ),
        gas::meter_instructions(
            &[InstructionBox::from(metadata_instruction.clone())],
            &iroha_core::gas::DEFAULT_ZK_GAS,
        ),
    ]
    .into_iter()
    .sum::<Result<_, _>>()
    .expect("scheduler fixture instructions must admit gas metering");
    for tx in txs.clone() {
        if let Err(failure) = queue.push(tx, state.view()) {
            return Err(eyre::eyre!(failure.err.to_string()));
        }
    }
    let lane_label = LaneId::SINGLE.as_u32().to_string();
    let dataspace_label = DataSpaceId::UNIVERSAL.as_u64().to_string();
    let backlog = metrics
        .nexus_scheduler_dataspace_teu_backlog
        .with_label_values(&[lane_label.as_str(), dataspace_label.as_str()])
        .get();
    assert_eq!(backlog, expected_teu);
    let capacity = metrics
        .nexus_scheduler_lane_teu_capacity
        .with_label_values(&[lane_label.as_str()])
        .get();
    assert_eq!(capacity, queue_limits.for_lane(LaneId::SINGLE).teu_capacity);
    // Reading and dropping native candidates must preserve input ownership and TEU.
    let max = NonZeroUsize::new(txs.len()).expect("non-zero");
    let pending = queue
        .bounded_pending_snapshot_for_testing(&state.view(), max)
        .expect("pending snapshot");
    assert_eq!(pending.len(), txs.len());
    drop(pending);
    assert_eq!(queue.active_len(), txs.len());
    assert_eq!(
        metrics
            .nexus_scheduler_dataspace_teu_backlog
            .with_label_values(&[lane_label.as_str(), dataspace_label.as_str()])
            .get(),
        expected_teu
    );
    let signed = txs
        .iter()
        .map(|accepted| match accepted.entrypoint() {
            iroha_data_model::transaction::TransactionEntrypoint::External(tx) => tx.clone(),
            _ => unreachable!("this fixture only submits original signed inputs"),
        })
        .collect();
    assert_eq!(chain.commit(signed), vec![true; txs.len()]);
    // The production gossip owner recognizes those exact certified identities,
    // retires them, and publishes the same telemetry used by the node driver.
    assert!(
        queue
            .gossip_batch_with_state(u32::try_from(txs.len())?, &state)
            .is_empty()
    );
    assert!(queue.active_len() == 0);
    let backlog_after = metrics
        .nexus_scheduler_dataspace_teu_backlog
        .with_label_values(&[lane_label.as_str(), dataspace_label.as_str()])
        .get();
    assert_eq!(backlog_after, 0);
    Ok(())
}
