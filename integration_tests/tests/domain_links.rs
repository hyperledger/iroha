//! Integration tests for receive-path implicit account creation and domain SNS helpers.
use eyre::Result;
use integration_tests::sandbox;
use iroha::{blocking::Client, data_model::prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use tokio::runtime::Runtime;
fn start_network(context: &'static str) -> Option<(sandbox::SerializedNetwork, Runtime)> {
    sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new().with_block_cadence(std::time::Duration::from_secs(2)),
        context,
    )
    .unwrap()
}
fn ensure_registered_domain(client: &Client, domain: &DomainId) -> Result<()> {
    ensure_domain_setup(client, domain)
}
#[test]
fn domain_setup_instruction_pins_domain_dataspace_and_owner() -> Result<()> {
    let domain: DomainId = DomainId::try_new("helperdomain", "universal")?;
    let (owner, _) = gen_account_in("helper_owner");
    let instruction = domain_setup_instruction(&domain, &owner)?;
    let ensure = instruction
        .as_any()
        .downcast_ref::<iroha::data_model::isi::alias_setup::EnsureAlias>()
        .expect("domain setup helper must emit EnsureAlias");
    let AliasIntentV1::Domain(intent) = &ensure.intent else {
        panic!("domain setup helper must emit a domain intent");
    };
    assert_eq!(intent.domain.canonical_name, domain);
    assert_eq!(intent.domain.dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(intent.owner, owner);
    assert_eq!(ensure.acquisition, AliasLeaseAcquisitionV1::new(1, None));
    Ok(())
}
#[test]
fn receive_paths_materialize_unregistered_accounts_for_assets_and_nfts() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(
        receive_paths_materialize_unregistered_accounts_for_assets_and_nfts
    )) else {
        return Ok(());
    };
    let client = network.client();
    let domain: DomainId = DomainId::try_new("receive-without-preregister", "universal")?;
    ensure_registered_domain(&client, &domain)?;
    let source_account = client.client().account().clone();
    let destination_asset = gen_account_in(&domain).0;
    let destination_nft = gen_account_in(&domain).0;
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain.clone(),
        "coin".parse()?,
    );
    client.submit(
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let source_asset_id = AssetId::new(asset_definition_id.clone(), source_account.clone());
    client.submit(
        Mint::asset_quantity(10u32, source_asset_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    client.submit(
        Transfer::asset_quantity(source_asset_id, 4u32, destination_asset.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let destination_asset_id = AssetId::new(asset_definition_id, destination_asset.clone());
    let destination_asset_state = client
        .client()
        .query_single(FindAssetById::new(destination_asset_id))?;
    assert_eq!(*destination_asset_state.value(), Quantity::from(4_u32));
    let nft_id: NftId = format!("nft_receive${domain}").parse()?;
    client.submit(
        Register::nft(Nft::new(nft_id.clone(), Metadata::default())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    client.submit(
        Transfer::nft(source_account, nft_id.clone(), destination_nft.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let nft = client
        .client()
        .query(FindNfts::new())
        .execute_all()?
        .into_iter()
        .find(|nft| nft.id() == &nft_id)
        .expect("nft should exist after transfer");
    assert_eq!(nft.owned_by(), &destination_nft);
    let accounts = client.client().query(FindAccounts::new()).execute_all()?;
    assert!(
        accounts
            .iter()
            .any(|account| account.id() == &destination_asset)
    );
    Ok(())
}
