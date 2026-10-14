//! Baseline throughput and block production under normal conditions.
use eyre::{Result, WrapErr};
use integration_tests::sandbox;
use iroha::data_model::{asset::AssetDefinitionId, parameter::BlockParameter, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use nonzero_ext::nonzero;
#[test]
#[allow(clippy::too_many_lines)]
fn transactions_should_be_applied() -> Result<()> {
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new().with_peers(4),
        stringify!(transactions_should_be_applied),
    )?
    else {
        return Ok(());
    };
    let env_dir = network.env_dir().to_path_buf();
    let result = || -> Result<()> {
        let iroha = network.client();
        let torii = iroha.client().endpoint().clone();
        // Make sure the network is responsive before issuing transactions.
        rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 1).await })
            .wrap_err_with(|| {
                format!(
                    "ensure_blocks_with initial height; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        let mut target_height = iroha
            .status()
            .get()
            .wrap_err_with(|| {
                format!(
                    "initial status read; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?
            .blocks;
        let wait_for_height = |height: u64, label: &str| -> Result<()> {
            rt.block_on(async { network.ensure_blocks_with(|h| h.total >= height).await })
                .wrap_err_with(|| {
                    format!(
                        "ensure_blocks_with {label} failed (torii={torii}, env_dir={})",
                        env_dir.display()
                    )
                })?;
            Ok(())
        };
        iroha
            .submit(
                SetParameter::new(Parameter::Block(BlockParameter::MaxTransactions(nonzero!(
                    1_u64
                )))),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit set_parameter; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after set_parameter")?;
        let domain_id = DomainId::try_new("and", "universal")?;
        let account_pk: PublicKey =
            "ed01201F803CB23B1AAFB958368DF2F67CB78A2D1DFB47FFFC3133718F165F54DFF677".parse()?;
        let account_id = AccountId::new(account_pk);
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("and", "universal")?,
            "MAY".parse()?,
        );
        let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
        let create_domain = domain_setup_instruction(&domain_id, iroha.client().account())?;
        iroha
            .submit(
                create_domain,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit create_domain; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after create_domain")?;
        let create_asset = Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "MAY".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        });
        iroha
            .submit(
                create_asset,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit create_asset; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after create_asset")?;
        let create_account = Register::account(Account::new(account_id.clone()));
        iroha
            .submit(
                create_account,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit create_account; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after create_account")?;
        let mint_asset = Mint::asset_quantity(
            57_787_013_353_273_097_936_105_299_296_u128,
            AssetId::new(asset_definition_id.clone(), account_id.clone()),
        );
        iroha
            .submit(
                mint_asset,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit first mint; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after first mint")?;
        let mint_asset = Mint::asset_quantity(1_u32, AssetId::new(asset_definition_id, account_id));
        iroha
            .submit(
                mint_asset,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| {
                format!(
                    "submit second mint; torii={torii}, env_dir={}",
                    env_dir.display()
                )
            })?;
        target_height += 1;
        wait_for_height(target_height, "after second mint")?;
        iroha
            .client()
            .query(FindAssets::new())
            .execute_all()?
            .into_iter()
            .find(|asset| asset.id() == &asset_id)
            .expect("asset not found");
        Ok(())
    };
    if sandbox::handle_result(result(), stringify!(transactions_should_be_applied))?.is_none() {
        return Ok(());
    }
    Ok(())
}
