//! Four real validators deliver and recover a paid native receipt at the final block.

use std::{num::NonZeroU64, sync::Arc, time::Duration};

use eyre::{Result, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    client::{NativePaymentRequest, NativePaymentRunOptions, PaymentCreditStatus, PaymentInbox},
    collections::{Collection, ListQuery},
    workflow::{FileWorkflowStorage, WorkflowRunOptions},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    block::consensus::NexusFeeSettlementV1,
    domain::Domain,
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements, Mint,
        Register, SettleAtomic, SettlementId,
    },
    nexus::FeeDebitSource,
    parameter::system::ConsensusMode,
    query::asset::{FindAssetById, FindAssetDefinitionById},
    sumeragi_finality::{
        SignedGenesisPinsV1, SumeragiFinalityVerifier, authenticate_signed_genesis_v1,
    },
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
};
use iroha_model_base::{domain::DomainId, metadata::Metadata, name::Name};
use iroha_primitives::numeric::Quantity;
use iroha_test_network::{Network, NetworkBuilder};
use iroha_test_samples::ALICE_ID;
use sha2::{Digest as _, Sha256};

#[path = "native_payment_network/concurrent_gateways.rs"]
mod concurrent_gateways;
#[path = "native_payment_network/full_return.rs"]
mod full_return;
#[path = "native_payment_network/rejected_payment.rs"]
mod rejected_payment;
#[cfg(unix)]
#[path = "native_payment_network/resource_bound.rs"]
mod resource_bound;

/// Successfully consume every collection page before treating an absent balance as zero.
fn account_snapshot(
    client: &iroha::blocking::Client,
    owner: &AccountId,
) -> Result<std::collections::BTreeMap<AssetId, Quantity>> {
    // A one-row page exercises cursor traversal for every funded payer in these tests.
    let mut rows = client.list(
        Collection::AccountAssets(owner.clone()),
        ListQuery::new().limit(1).include_total(),
    );
    let mut balances = std::collections::BTreeMap::new();
    for row in rows.by_ref() {
        let row = row?;
        ensure!(
            row.get("account_id").and_then(norito::json::Value::as_str)
                == Some(owner.to_string().as_str())
        );
        ensure!(row.get("scope").and_then(norito::json::Value::as_str) == Some("global"));
        let definition = row
            .get("asset")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("account asset row has no canonical asset definition"))?
            .parse::<AssetDefinitionId>()?;
        let quantity = row
            .get("quantity")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("account asset row has no quantity"))?
            .parse::<Quantity>()?;
        ensure!(
            balances
                .insert(AssetId::of(definition, owner.clone()), quantity)
                .is_none(),
            "duplicate asset in complete account snapshot"
        );
    }
    ensure!(
        rows.total() == Some(u64::try_from(balances.len())?),
        "account asset pages did not cover the reported total"
    );
    Ok(balances)
}

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn principal() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("nativepayment", "universal").unwrap(),
        "principal".parse().unwrap(),
    )
}

fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}

fn builder(payer: &AccountId, recipient: &AccountId) -> NetworkBuilder {
    let mut fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    fees.fee_asset_id = fee_asset();
    fees.fee_sink_account_id = ALICE_ID.clone();
    fees.base_fee = 1_u32.into();
    fees.per_byte_fee = 0_u32.into();
    fees.per_instruction_fee = 0_u32.into();
    fees.per_gas_unit_fee = 0_u32.into();
    NetworkBuilder::new()
        .with_peers(4)
        .with_permissioned_consensus()
        .with_auto_populated_trusted_peers()
        .with_base_seed("native-payment-final-tip-v1")
        .with_genesis_keypair(key(0x75))
        .with_config_layer(|layer| {
            layer.write(
                ["nexus", "storage", "local_budget_bytes"],
                1024_i64 * 1024 * 1024,
            );
        })
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom(fees.into_custom_parameter().unwrap()),
        ))
        // The payer has its own account read authority, with no ledger-wide read grant.
        .with_genesis_instruction(Register::account(Account::new(payer.clone())))
        .with_genesis_instruction(Register::account(Account::new(recipient.clone())))
        .with_genesis_instruction(Register::domain(Domain::new(
            DomainId::try_new("nativepayment", "universal").unwrap(),
        )))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            principal(),
            "Payment principal",
            AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Mint::asset_quantity(
            1_000_000_u32,
            AssetId::of(principal(), payer.clone()),
        ))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "Canonical payment fee asset",
            AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Mint::asset_quantity(
            100_u32,
            AssetId::of(fee_asset(), payer.clone()),
        ))
        .with_genesis_instruction(Mint::asset_quantity(
            100_u32,
            AssetId::of(fee_asset(), ALICE_ID.clone()),
        ))
}

fn pins(network: &Network) -> Result<(Vec<u8>, SignedGenesisPinsV1)> {
    let genesis = network.genesis().0;
    let wire = genesis.encode_wire()?;
    let mut roster: Vec<_> = network
        .topology_entries()
        .iter()
        .map(|entry| entry.peer.clone())
        .collect();
    roster.sort();
    let pins = SignedGenesisPinsV1 {
        chain_id: network.chain_id().to_string(),
        network_id: network.network_id(),
        genesis_hash: genesis.hash(),
        signed_genesis_sha256: Sha256::digest(&wire).into(),
        genesis_public_key: key(0x75).public_key().clone(),
        roster,
        mode: ConsensusMode::Permissioned,
    };
    Ok((wire, pins))
}

async fn wait_for_applied_height(network: &Network, height: u64) -> Result<()> {
    // Kura can already contain this height while startup replay has not published State.
    // The live status owner reports its classified committed State height. Readiness here
    // never submits a transaction or needs a successor to the original payment.
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let mut ready = true;
            for peer in network.validators() {
                let client = peer.client();
                match client.client().status().get().await {
                    Ok(status) if status.blocks >= height => {}
                    _ => ready = false,
                }
            }
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| eyre!("all four validators must publish applied State at height {height}"))
}

fn verifier(wire: &[u8], pins: &SignedGenesisPinsV1) -> Result<SumeragiFinalityVerifier> {
    let authenticated = authenticate_signed_genesis_v1(wire, pins)?;
    Ok(SumeragiFinalityVerifier::new(
        authenticated.block(),
        &pins.chain_id,
        authenticated.validators().to_vec(),
    )?)
}

#[test]
fn native_payment_genesis_authenticates_exact_preexecuted_signed_root() -> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let network = builder(&payer, &recipient).build();
    let genesis = network.genesis().0;
    ensure!(genesis.has_results());
    ensure!(genesis.commit_certificate().is_none());
    let (wire, selected) = pins(&network)?;
    ensure!(selected.genesis_hash == genesis.hash());
    ensure!(selected.network_id == iroha_data_model::NetworkId::from_genesis_hash(genesis.hash()));
    let authenticated = authenticate_signed_genesis_v1(&wire, &selected)?;
    ensure!(authenticated.block().encode_wire()? == wire);
    ensure!(authenticated.block().hash() == selected.genesis_hash);
    ensure!(authenticated.epoch().network_id == selected.network_id);
    verifier(&wire, &selected)?;
    Ok(())
}

#[test]
fn paid_payment_and_bank_credit_resume_after_all_validators_restart_at_final_tip() -> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        builder(&payer, &recipient),
        stringify!(paid_payment_and_bank_credit_resume_after_all_validators_restart_at_final_tip),
    )?
    .ok_or_else(|| eyre!("required four-process native payment acceptance cannot skip startup"))?;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4 && network.topology_entries().len() == 4);
        let original_pids = rt.block_on(async {
            let mut pids = Vec::new();
            for peer in network.validators() {
                pids.push(
                    peer.process_id()
                        .await
                        .ok_or_else(|| eyre!("validator is not a live process"))?,
                );
            }
            Ok::<_, eyre::Report>(pids)
        })?;
        let (genesis_wire, selected_pins) = pins(&network)?;
        let gateway = network.validators()[0].client_for(&payer, key(0x76).private_key().clone());
        let initial_height = rt.block_on(gateway.client().status().get())?.blocks;
        let request = NativePaymentRequest::new(
            SettleAtomic::new(
                network.network_id(),
                SettlementId::new(payer.clone(), "invoice-250000".parse()?),
                AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                    source: AssetId::of(principal(), payer.clone()),
                    recipient: recipient.clone(),
                    quantity: 250_000_u32.into(),
                }])
                .map_err(|error| eyre!(error))?,
                AtomicSettlementEscrows::empty(),
                NonZeroU64::new(initial_height + 100).unwrap(),
                Metadata::default(),
            ),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    fee_asset(),
                    Quantity::one(),
                )],
                None,
            ),
        )?;
        // Keep application custody with peer stores when KEEP_DIRS preserves this network.
        let root = tempfile::tempdir_in(network.env_dir())?.keep();
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: Duration::from_secs(120),
                poll_interval: Duration::from_millis(200),
                ..WorkflowRunOptions::default()
            },
            ..NativePaymentRunOptions::default()
        };
        let operation = gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(root.join("payer"))?),
            verifier(&genesis_wire, &selected_pins)?,
        )?;
        let settled = rt.block_on(operation.submit(&options))?;
        let final_height = settled.receipt.settlement().block_height;
        ensure!(
            final_height == initial_height + 1,
            "only the payment may advance the chain"
        );
        let fee = settled
            .receipt
            .nexus_fee_receipt()
            .ok_or_else(|| eyre!("missing authenticated fee"))?;
        ensure!(fee.fee_amount == Quantity::one());
        ensure!(fee.settlement == NexusFeeSettlementV1::Burn);
        ensure!(fee.debit_source == FeeDebitSource::Account(payer.clone()));
        ensure!(fee.fee_asset_id == fee_asset());
        rt.block_on(network.ensure_blocks(final_height))?;
        rt.block_on(wait_for_applied_height(&network, final_height))?;
        let original_hash = settled.receipt.transaction_hash();
        let original_settlement = settled.receipt.settlement().clone();
        let destination = AssetId::of(principal(), recipient.clone());
        let customer: Name = "customer-one".parse()?;
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            root.join("bank"),
        )?))?;
        ensure!(
            inbox.credit(&settled.receipt, &customer, &destination)?
                == PaymentCreditStatus::Recorded
        );
        ensure!(
            inbox
                .pending_notification(&settled.receipt, &customer, &destination)?
                .is_some()
        );
        drop(inbox);
        drop(settled);
        drop(operation);
        drop(gateway);

        // Persisted completion and inbox bytes grant no verification status. Stop every node,
        // replay the same stores, and refetch the original proof through a different gateway.
        rt.block_on(network.shutdown());
        rt.block_on(network.start_all())?;
        rt.block_on(network.ensure_blocks(final_height))?;
        rt.block_on(wait_for_applied_height(&network, final_height))?;
        rt.block_on(async {
            for (peer, original_pid) in network.validators().iter().zip(&original_pids) {
                ensure!(
                    peer.process_id()
                        .await
                        .is_some_and(|pid| pid != *original_pid)
                );
            }
            Ok::<_, eyre::Report>(())
        })?;
        let resumed_gateway =
            network.validators()[1].client_for(&payer, key(0x76).private_key().clone());
        let resumed = resumed_gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(root.join("payer"))?),
            verifier(&genesis_wire, &selected_pins)?,
        )?;
        let recovered = rt
            .block_on(resumed.recover(&options))?
            .receipt
            .ok_or_else(|| eyre!("final-tip payment was not recovered"))?;
        ensure!(
            recovered.transaction_hash() == original_hash
                && recovered.settlement() == &original_settlement
        );
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            root.join("bank"),
        )?))?;
        ensure!(
            inbox.credit(&recovered, &customer, &destination)?
                == PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true
                }
        );
        inbox.acknowledge_notification(&recovered, &customer, &destination)?;
        inbox.acknowledge_notification(&recovered, &customer, &destination)?;
        ensure!(
            inbox
                .pending_notification(&recovered, &customer, &destination)?
                .is_none()
        );

        // A second gateway has no local payment journal. Consensus identity locates the
        // original successful carrier before it can sign or charge another transaction.
        let second_gateway = resumed_gateway.account_client().native_payment(
            request,
            Arc::new(FileWorkflowStorage::open_or_create(
                root.join("second-gateway"),
            )?),
            verifier(&genesis_wire, &selected_pins)?,
        )?;
        let repeated = rt.block_on(second_gateway.resume(&options))?;
        ensure!(repeated.receipt.transaction_hash() == original_hash);
        ensure!(
            inbox.credit(&repeated.receipt, &customer, &destination)?
                == PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: false
                }
        );
        for peer in network.validators() {
            let client = peer.client();
            ensure!(
                rt.block_on(client.client().status().get())?.blocks == final_height,
                "receipt delivery or recovery produced unrelated traffic"
            );
            let payer_asset = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(principal(), payer.clone())))?;
            let recipient_asset = client
                .client()
                .query_single(FindAssetById::new(destination.clone()))?;
            let payer_fees = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(fee_asset(), payer.clone())))?;
            let sink_fees = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(
                    fee_asset(),
                    ALICE_ID.clone(),
                )))?;
            ensure!(payer_asset.value() == &Quantity::from(750_000_u32));
            ensure!(recipient_asset.value() == &Quantity::from(250_000_u32));
            ensure!(payer_fees.value() == &Quantity::from(99_u32));
            ensure!(
                sink_fees.value() == &Quantity::from(100_u32),
                "Nexus burns its one paid fee; the configured sink must retain its genesis 100, got {}",
                sink_fees.value()
            );
            let fee_definition = client
                .client()
                .query_single(FindAssetDefinitionById::new(fee_asset()))?;
            ensure!(
                fee_definition.total_quantity() == &Quantity::from(199_u32),
                "exactly one Nexus fee must burn supply from genesis 200, got {}",
                fee_definition.total_quantity()
            );
        }
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
