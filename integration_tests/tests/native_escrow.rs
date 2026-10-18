//! Native asset escrow integration scenarios.
use eyre::{Result, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{
        isi::escrow::{
            AcceptAssetEscrow, CancelAssetLock, DrawdownAssetLock, ExpireAssetLock,
            MarkEscrowPaymentSent, OpenAssetEscrow, OpenAssetLock, ReleaseAssetEscrow,
        },
        prelude::*,
    },
};
use iroha_crypto::Hash;
use iroha_executor_data_model::permission::asset::CanTransferAsset;
use iroha_model_base::domain::DomainId;
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::time::{Duration, Instant};
fn wait_for_escrow_status(
    client: &Client,
    escrow_id: EscrowId,
    expected: AssetEscrowStatus,
    context: &str,
) -> Result<AssetEscrowRecord> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "escrow was not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query_single(FindAssetEscrowById::new(escrow_id))
        {
            Ok(record) => {
                last_observed = format!("{:?}", record.status);
                if record.status == expected {
                    return Ok(record);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for escrow {escrow_id:?} to become {expected:?} after {context}; last_observed={last_observed}"
    ))
}
fn wait_for_asset_value(
    client: &Client,
    asset_id: &AssetId,
    expected: &Quantity,
    context: &str,
) -> Result<Asset> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "asset was not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query_single(FindAssetById::new(asset_id.clone()))
        {
            Ok(asset) => {
                last_observed = format!("{}", asset.value());
                if asset.value() == expected {
                    return Ok(asset);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for asset {asset_id} to equal {expected} after {context}; last_observed={last_observed}"
    ))
}
fn wait_for_buyer_escrow(
    client: &Client,
    buyer: &AccountId,
    escrow_id: EscrowId,
    context: &str,
) -> Result<Vec<AssetEscrowRecord>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "buyer escrow index was not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query(FindAssetEscrowsByBuyer::new(buyer.clone()))
            .execute_all()
        {
            Ok(records) => {
                last_observed = format!(
                    "{:?}",
                    records.iter().map(|record| record.id).collect::<Vec<_>>()
                );
                if records.iter().any(|record| record.id == escrow_id) {
                    return Ok(records);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for buyer escrow index to include {escrow_id:?} after {context}; last_observed={last_observed}"
    ))
}
#[test]
fn native_asset_escrow_aitai_flow_on_multi_peer_network() -> Result<()> {
    let context = stringify!(native_asset_escrow_aitai_flow_on_multi_peer_network);
    let Some((network, _rt)) =
        sandbox::start_network_blocking_or_skip(NetworkBuilder::new().with_min_peers(4), context)
            .unwrap()
    else {
        return Ok(());
    };
    let client = network.client();
    let result: Result<()> = (|| {
        let seller = ALICE_ID.clone();
        let (buyer, buyer_keypair) = gen_account_in("wonderland");
        let buyer_client = network
            .peer()
            .client_for(&buyer, buyer_keypair.private_key().clone());
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "aitai_xor_native".parse()?,
        );
        let seller_asset_id = AssetId::of(asset_definition_id.clone(), seller.clone());
        client.submit_all(
            [
                InstructionBox::from(Register::account(Account::new(buyer.clone()))),
                Register::asset_definition(AssetDefinition::numeric(
                    asset_definition_id.clone(),
                    "aitai_xor_native".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
                Mint::asset_quantity(100_u64, seller_asset_id.clone()).into(),
            ],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let escrow_id = EscrowId::new(Hash::new("native-aitai-flow"));
        client.submit(
            OpenAssetEscrow::with_evidence_hashes(
                escrow_id,
                asset_definition_id.clone(),
                Quantity::from(40_u64),
                vec![Hash::new("fiat-invoice")],
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let opened =
            wait_for_escrow_status(&client, escrow_id, AssetEscrowStatus::Open, "open escrow")?;
        let custody_asset_id = AssetId::of(asset_definition_id.clone(), opened.custody.clone());
        client.submit(
            Grant::account_permission(
                Permission::from(CanTransferAsset {
                    asset: custody_asset_id.clone(),
                }),
                seller.clone(),
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        assert!(
            client
                .submit(
                    Transfer::asset_quantity(custody_asset_id, 1_u64, seller.clone(),),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err(),
            "active native escrow custody must not be drainable through generic transfer"
        );
        buyer_client.submit(
            AcceptAssetEscrow::new(escrow_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        buyer_client.submit(
            MarkEscrowPaymentSent::new(escrow_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        client.submit(
            ReleaseAssetEscrow::new(escrow_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let released = wait_for_escrow_status(
            &client,
            escrow_id,
            AssetEscrowStatus::Released,
            "release escrow",
        )?;
        assert_eq!(released.buyer, Some(buyer.clone()));
        let buyer_asset_id = AssetId::of(asset_definition_id.clone(), buyer.clone());
        let buyer_asset = wait_for_asset_value(
            &client,
            &buyer_asset_id,
            &Quantity::from(40_u64),
            "release escrow buyer balance",
        )?;
        let seller_asset = wait_for_asset_value(
            &client,
            &seller_asset_id,
            &Quantity::from(60_u64),
            "release escrow seller balance",
        )?;
        assert_eq!(*buyer_asset.value(), Quantity::from(40_u64));
        assert_eq!(*seller_asset.value(), Quantity::from(60_u64));
        let buyer_escrows = wait_for_buyer_escrow(
            &client,
            released.buyer.as_ref().expect("buyer recorded"),
            escrow_id,
            "release escrow buyer index",
        )?;
        assert!(buyer_escrows.iter().any(|record| record.id == escrow_id));
        Ok(())
    })();
    if sandbox::handle_result(result, context)?.is_none() {
        return Ok(());
    }
    Ok(())
}
#[test]
fn native_asset_lock_flow_on_multi_peer_network() -> Result<()> {
    let context = stringify!(native_asset_lock_flow_on_multi_peer_network);
    let Some((network, _rt)) =
        sandbox::start_network_blocking_or_skip(NetworkBuilder::new().with_min_peers(4), context)
            .unwrap()
    else {
        return Ok(());
    };
    let client = network.client();
    let result: Result<()> = (|| {
        let source = ALICE_ID.clone();
        let (destination, destination_keypair) = gen_account_in("wonderland");
        let (release_authority, release_authority_keypair) = gen_account_in("wonderland");
        let destination_client = network
            .peer()
            .client_for(&destination, destination_keypair.private_key().clone());
        let release_authority_client = network.peer().client_for(
            &release_authority,
            release_authority_keypair.private_key().clone(),
        );
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "aitai_xor_lock_native".parse()?,
        );
        let source_asset_id = AssetId::of(asset_definition_id.clone(), source.clone());
        client.submit_all(
            [
                InstructionBox::from(Register::account(Account::new(destination.clone()))),
                InstructionBox::from(Register::account(Account::new(release_authority.clone()))),
                Register::asset_definition(AssetDefinition::numeric(
                    asset_definition_id.clone(),
                    "aitai_xor_lock_native".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
                Mint::asset_quantity(100_u64, source_asset_id.clone()).into(),
            ],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let trusted_lock_id = EscrowId::new(Hash::new("native-asset-lock-trusted"));
        client.submit(
            OpenAssetLock::with_options(
                trusted_lock_id,
                asset_definition_id.clone(),
                destination.clone(),
                Quantity::from(40_u64),
                Some(release_authority.clone()),
                None,
                vec![Hash::new("native-lock-open-evidence")],
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let locked = wait_for_escrow_status(
            &client,
            trusted_lock_id,
            AssetEscrowStatus::Locked,
            "open trusted lock",
        )?;
        assert_eq!(locked.buyer, Some(destination.clone()));
        assert_eq!(locked.release_authority, Some(release_authority.clone()));
        assert_eq!(locked.remaining_amount, Quantity::from(40_u64));
        let custody_asset_id = AssetId::of(asset_definition_id.clone(), locked.custody.clone());
        wait_for_asset_value(
            &client,
            &source_asset_id,
            &Quantity::from(60_u64),
            "trusted lock source debit",
        )?;
        wait_for_asset_value(
            &client,
            &custody_asset_id,
            &Quantity::from(40_u64),
            "trusted lock custody credit",
        )?;
        client.submit(
            Grant::account_permission(
                Permission::from(CanTransferAsset {
                    asset: custody_asset_id.clone(),
                }),
                source.clone(),
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        assert!(
            client
                .submit(
                    Transfer::asset_quantity(custody_asset_id.clone(), 1_u64, source.clone(),),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err(),
            "active native lock custody must not be drainable through generic transfer"
        );
        assert!(
            destination_client
                .submit(
                    DrawdownAssetLock::new(
                        trusted_lock_id,
                        Quantity::from(1_u64),
                        Quantity::from(40_u64),
                    ),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err(),
            "destination cannot draw down when a release authority is set"
        );
        release_authority_client.submit(
            DrawdownAssetLock::new(
                trusted_lock_id,
                Quantity::from(15_u64),
                Quantity::from(40_u64),
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let destination_asset_id = AssetId::of(asset_definition_id.clone(), destination.clone());
        wait_for_asset_value(
            &client,
            &destination_asset_id,
            &Quantity::from(15_u64),
            "trusted lock destination partial credit",
        )?;
        let partially_drawn = wait_for_escrow_status(
            &client,
            trusted_lock_id,
            AssetEscrowStatus::Locked,
            "release-authority partial drawdown",
        )?;
        assert_eq!(partially_drawn.remaining_amount, Quantity::from(25_u64));
        assert!(
            release_authority_client
                .submit(
                    DrawdownAssetLock::new(
                        trusted_lock_id,
                        Quantity::from(1_u64),
                        Quantity::from(40_u64),
                    ),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .is_err(),
            "a stale independently submitted drawdown must not debit custody twice"
        );
        client.submit(
            CancelAssetLock::new(trusted_lock_id, partially_drawn.remaining_amount.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let cancelled = wait_for_escrow_status(
            &client,
            trusted_lock_id,
            AssetEscrowStatus::Cancelled,
            "cancel trusted lock",
        )?;
        assert_eq!(cancelled.remaining_amount, Quantity::zero());
        wait_for_asset_value(
            &client,
            &source_asset_id,
            &Quantity::from(85_u64),
            "trusted lock cancellation refund",
        )?;
        let expiring_lock_id = EscrowId::new(Hash::new("native-asset-lock-expiring"));
        client.submit(
            OpenAssetLock::with_options(
                expiring_lock_id,
                asset_definition_id.clone(),
                destination.clone(),
                Quantity::from(10_u64),
                None,
                Some(0),
                Vec::new(),
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        wait_for_escrow_status(
            &client,
            expiring_lock_id,
            AssetEscrowStatus::Locked,
            "open expiring lock",
        )?;
        destination_client.submit(
            ExpireAssetLock::new(expiring_lock_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let expired = wait_for_escrow_status(
            &client,
            expiring_lock_id,
            AssetEscrowStatus::Expired,
            "expire lock",
        )?;
        assert_eq!(expired.remaining_amount, Quantity::zero());
        wait_for_asset_value(
            &client,
            &source_asset_id,
            &Quantity::from(85_u64),
            "expiring lock refund",
        )?;
        wait_for_asset_value(
            &client,
            &destination_asset_id,
            &Quantity::from(15_u64),
            "destination balance after expiry refund",
        )?;
        Ok(())
    })();
    if sandbox::handle_result(result, context)?.is_none() {
        return Ok(());
    }
    Ok(())
}
