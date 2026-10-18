//! Ensures that minting an asset on one peer propagates to other peers with the correct quantity.
use eyre::{Result, eyre};
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha::query::QueryError;
use iroha_data_model::{
    ValidationFail,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use std::time::Duration;
#[test]
#[allow(clippy::too_many_lines)]
// This test is also covered at the UI level in the iroha_cli tests
// in test_mint_asset.py
fn client_mint_asset_should_increase_amount_on_another_peer() -> Result<()> {
    // Force Norito to use fixed-length sequences in genesis to avoid relying on packed
    // offsets, which are currently unstable in debug builds.
    init_instruction_registry();
    let domain_id: DomainId = DomainId::try_new("domain", "universal")?;
    let create_domain = Register::domain(Domain::new(domain_id.clone()));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("domain", "universal")?,
        "xor".parse()?,
    );
    let create_asset = Register::asset_definition({
        let __asset_definition_id = asset_definition_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    });
    let quantity = Quantity::from(200_u32);
    let mint_asset = Mint::asset_quantity(
        quantity.clone(),
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    // Given
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_ivm_fuel(IvmFuelConfig::Unset)
        .with_genesis_instruction(create_domain)
        .with_genesis_instruction(create_account)
        .with_genesis_instruction(create_asset)
        .with_genesis_instruction(mint_asset);
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(client_mint_asset_should_increase_amount_on_another_peer),
    )?
    else {
        return Ok(());
    };
    let mut peers = network.peers().iter();
    let peer_a = peers.next().unwrap();
    let peer_b = peers.next().unwrap();
    // Wait until the genesis block is committed everywhere.
    rt.block_on(async { network.ensure_blocks_with(|x| x.total >= 1).await })?;
    // Then
    for (idx, peer) in [peer_a, peer_b].into_iter().enumerate() {
        assert_asset_amount(peer, &account_id, &asset_definition_id, &quantity)
            .map_err(|err| eyre::eyre!("failed on peer #{idx} ({}): {err}", peer.torii_url()))?;
    }
    Ok(())
}
fn find_asset(
    peer: &NetworkPeer,
    account_id: &AccountId,
    asset_definition_id: &AssetDefinitionId,
) -> Result<Option<Asset>> {
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    match peer
        .client()
        .client()
        .query_single(FindAssetById::new(asset_id.clone()))
    {
        Ok(asset) if asset.id() == &asset_id => Ok(Some(asset)),
        Ok(_) => Err(eyre!("exact asset query returned a different asset")),
        Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            FindError::Asset(missing),
        )))) if missing.as_ref() == &asset_id => Ok(None),
        Err(error) => Err(eyre!(error)),
    }
}
fn assert_asset_amount(
    peer: &NetworkPeer,
    account_id: &AccountId,
    asset_definition_id: &AssetDefinitionId,
    expected: &Quantity,
) -> Result<()> {
    // Increase retry limit significantly for CI environments.
    // 240 attempts * 250ms = 60 seconds total wait time.
    const MAX_ATTEMPTS: usize = 240;
    const RETRY_DELAY: Duration = Duration::from_millis(250);
    for attempt in 0..=MAX_ATTEMPTS {
        match find_asset(peer, account_id, asset_definition_id) {
            Ok(Some(asset)) => {
                if asset.value() == expected {
                    return Ok(());
                }
            }
            Ok(None) => {
                // Asset not found yet, retry
            }
            Err(e) => {
                // Query failed (e.g. connection refused), retry
                if attempt % 10 == 0 {
                    eprintln!("FindAsset query failed (attempt {attempt}): {e:?}");
                }
            }
        }
        if attempt == MAX_ATTEMPTS {
            break;
        }
        std::thread::sleep(RETRY_DELAY);
    }
    // One final check to produce a good error message
    match find_asset(peer, account_id, asset_definition_id) {
        Ok(Some(asset)) => {
            if asset.value() == expected {
                Ok(())
            } else {
                Err(eyre!(
                    "asset amount mismatch on {}: expected {}, got {}",
                    peer.torii_url(),
                    expected,
                    asset.value()
                ))
            }
        }
        Ok(None) => Err(eyre!(
            "asset {} for account {} not found on {}",
            asset_definition_id,
            account_id,
            peer.torii_url()
        )),
        Err(e) => Err(eyre!(
            "failed to query asset on {}: {:?}",
            peer.torii_url(),
            e
        )),
    }
}
