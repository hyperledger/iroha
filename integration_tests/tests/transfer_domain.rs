//! Integration tests for domain permissions and transfers.
use eyre::{Result, eyre};
use integration_tests::sandbox;
use iroha::{blocking::Client, crypto::KeyPair, data_model::prelude::*};
use iroha_data_model::alias_setup::{AccountAliasRoleV1, AccountProvisionV1};
use iroha_executor_data_model::permission::{
    account::{AccountAliasPermissionScope, CanManageAccountAlias, CanUnregisterAccount},
    asset::{CanTransferAsset, CanTransferAssetWithDefinition},
    asset_definition::CanUnregisterAssetDefinition,
    domain::CanUnregisterDomain,
    nft::{CanRegisterNft, CanUnregisterNft},
    trigger::{CanExecuteTrigger, CanUnregisterTrigger},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID, SAMPLE_GENESIS_ACCOUNT_ID, gen_account_in};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
const DOMAIN_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
const DOMAIN_VISIBILITY_POLL: Duration = Duration::from_millis(100);
fn start_network(
    builder: NetworkBuilder,
    context: &'static str,
) -> Result<Option<(sandbox::SerializedNetwork, Runtime)>> {
    sandbox::start_network_blocking_or_skip(builder, context)
}
fn checked_random_account_id() -> AccountId {
    AccountId::new(
        KeyPair::try_random()
            .expect("generate checked transfer-domain account keypair")
            .into_parts()
            .0,
    )
}
#[test]
fn transfer_domain_account_fixture_uses_checked_randomness() {
    let _account_id = checked_random_account_id();
}
fn wait_for_domain_owner(
    client: &Client,
    domain_id: &DomainId,
    expected_owner: &AccountId,
    context: &str,
) -> Result<Domain> {
    let deadline = Instant::now() + DOMAIN_VISIBILITY_TIMEOUT;
    let mut last_owner = None;
    loop {
        let domain = client
            .client()
            .query(FindDomains::new())
            .execute_all()?
            .into_iter()
            .find(|domain| domain.id() == domain_id);
        if let Some(domain) = domain {
            if domain.owned_by() == expected_owner {
                return Ok(domain);
            }
            last_owner = Some(domain.owned_by().clone());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "timed out waiting for domain owner after {context}: expected {expected_owner}, last observed {last_owner:?}"
            ));
        }
        std::thread::sleep(DOMAIN_VISIBILITY_POLL);
    }
}
#[test]
fn domain_owner_domain_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(domain_owner_domain_permissions))?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, _bob_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("kingdom", "universal")?,
        "coin".parse()?,
    );
    let coin = AssetDefinition::numeric(
        coin_id.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    );
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Asset-definition registration is issuer-owned in first-release semantics.
    test_client.submit(
        Register::asset_definition(coin.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        Unregister::asset_definition(coin_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can edit metadata in her domain
    let key: Name = "key".parse()?;
    let value = Json::new("value");
    test_client.submit(
        SetKeyValue::domain(kingdom_id.clone(), key.clone(), value),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RemoveKeyValue::domain(kingdom_id.clone(), key),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can grant and revoke domain related permissions
    let permission = CanUnregisterDomain {
        domain: kingdom_id.clone(),
    };
    test_client.submit(
        Grant::account_permission(permission.clone(), bob_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RevokeBox::from(Revoke::account_permission(permission, bob_id)),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can unregister her domain
    test_client.submit(
        Unregister::domain(kingdom_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn domain_owner_account_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) =
        start_network(builder, stringify!(domain_owner_account_permissions))?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (mad_hatter_id, _mad_hatter_keypair) = gen_account_in("kingdom");
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id);
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let mad_hatter = Account::new(mad_hatter_id.clone());
    test_client.submit(
        Register::account(mad_hatter),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Domain ownership no longer grants direct account metadata mutation rights.
    let key: Name = "key".parse()?;
    let value = Json::new("value");
    let err = test_client
        .submit(
            SetKeyValue::account(mad_hatter_id.clone(), key.clone(), value),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("domain owner must not edit another account metadata");
    assert!(err.chain().any(|cause| {
        cause
            .to_string()
            .contains("Can't set value to the metadata of another account")
    }));
    let err = test_client
        .submit(
            RemoveKeyValue::account(mad_hatter_id.clone(), key),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("domain owner must not remove another account metadata");
    assert!(
        err.chain()
            .any(|cause| cause.to_string().contains("metadata of another account"))
    );
    // check that the canonical ALICE account as owner of domain can grant and revoke account related permissions in her domain
    let bob_id = BOB_ID.clone();
    let permission = CanUnregisterAccount {
        account: mad_hatter_id.clone(),
    };
    test_client.submit(
        Grant::account_permission(permission.clone(), bob_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RevokeBox::from(Revoke::account_permission(permission, bob_id)),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can unregister accounts in her domain
    test_client.submit(
        Unregister::account(mad_hatter_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn domain_owner_asset_definition_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(
        builder,
        stringify!(domain_owner_asset_definition_permissions),
    )?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let (rabbit_id, _rabbit_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("kingdom", "universal")?,
        "coin".parse()?,
    );
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let rabbit = Account::new(rabbit_id.clone());
    test_client.submit(
        Register::account(rabbit),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Register asset definition by "bob@kingdom" so he is owner of it.
    let coin = AssetDefinition::numeric(
        coin_id.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    );
    let transaction = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Register::asset_definition(coin)])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&transaction)?;
    // Asset definitions are issuer-owned in first-release semantics.
    let err = test_client
        .submit(
            Transfer::asset_definition(bob_id.clone(), coin_id.clone(), rabbit_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("domain owner must not transfer another account's asset definition");
    assert!(err.chain().any(|cause| {
        cause
            .to_string()
            .contains("Can't transfer asset definition of another account")
    }));
    let key: Name = "key".parse()?;
    let value = Json::new("value");
    test_client.submit(
        SetKeyValue::asset_definition(coin_id.clone(), key.clone(), value),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RemoveKeyValue::asset_definition(coin_id.clone(), key),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let permission = CanUnregisterAssetDefinition {
        asset_definition: coin_id.clone(),
    };
    test_client.submit(
        Grant::account_permission(permission.clone(), bob_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RevokeBox::from(Revoke::account_permission(permission, bob_id)),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        Unregister::asset_definition(coin_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn domain_owner_asset_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(domain_owner_asset_permissions))?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("kingdom", "universal")?,
        "coin".parse()?,
    );
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Register asset definition by "bob@kingdom" so he is owner of it.
    let coin = AssetDefinition::numeric(
        coin_id.clone(),
        "coin".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    );
    let transaction = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Register::asset_definition(coin)])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&transaction)?;
    // Domain ownership still covers mint/burn, but asset transfers require the source owner or an explicit grant.
    let bob_coin_id = AssetId::new(coin_id, bob_id.clone());
    test_client.submit(
        Mint::asset_quantity(20u32, bob_coin_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        Burn::asset_quantity(5u32, bob_coin_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let err = test_client
        .submit(
            Transfer::asset_quantity(bob_coin_id.clone(), 5u32, alice_id),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("domain owner must not transfer another account asset without explicit grant");
    assert!(err.chain().any(|cause| {
        cause
            .to_string()
            .contains("source asset owner must sign the transaction")
    }));
    let alice_id = ALICE_ID.clone();
    let exact_permission = CanTransferAsset {
        asset: bob_coin_id.clone(),
    };
    let grant_exact = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Grant::account_permission(
        exact_permission.clone(),
        alice_id.clone(),
    )])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_exact)?;
    test_client.submit(
        Transfer::asset_quantity(bob_coin_id.clone(), 5u32, alice_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let revoke_exact = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Revoke::account_permission(
        exact_permission,
        alice_id.clone(),
    )])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&revoke_exact)?;
    let _ = test_client
        .submit(
            Transfer::asset_quantity(bob_coin_id.clone(), 1u32, alice_id.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("revoking the asset-specific permission must immediately close access");
    let definition_permission = CanTransferAssetWithDefinition {
        asset_definition: bob_coin_id.definition().clone(),
    };
    let grant_definition = TransactionBuilder::new(
        network.network_id(),
        bob_id,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Grant::account_permission(
        definition_permission,
        alice_id.clone(),
    )])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_definition)?;
    test_client.submit(
        Transfer::asset_quantity(bob_coin_id, 5u32, alice_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn active_alias_domain_owner_cannot_transfer_the_aliased_accounts_assets() -> Result<()> {
    let manage_aliases: Permission = CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        ),
    }
    .into();
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(Grant::account_permission(manage_aliases, ALICE_ID.clone()));
    let Some((network, _rt)) = start_network(
        builder,
        stringify!(active_alias_domain_owner_cannot_transfer_the_aliased_accounts_assets),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    let alias_owner = ALICE_ID.clone();
    let (definition_owner, definition_owner_keypair) = gen_account_in("assets");
    let (source, _source_keypair) = gen_account_in("fi");
    let destination = checked_random_account_id();
    let alias_domain = DomainId::try_new("fi", "universal")?;
    let asset_domain = DomainId::try_new("assets", "universal")?;
    let asset_definition =
        AssetDefinitionId::derive_from_components(asset_domain.clone(), "alias_safe_coin".parse()?);
    let source_asset = AssetId::new(asset_definition.clone(), source.clone());
    client.submit_all::<InstructionBox>(
        [
            domain_setup_instruction(&alias_domain, &alias_owner)?,
            domain_setup_instruction(&asset_domain, &alias_owner)?,
            Register::account(Account::new(definition_owner.clone())).into(),
            Register::account(Account::new(source.clone())).into(),
            Register::account(Account::new(destination.clone())).into(),
        ],
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    client.submit(
        Transfer::domain(alias_owner.clone(), asset_domain, definition_owner.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    client.submit(
        account_alias_setup_instruction(
            "customer@fi.universal",
            &source,
            AccountProvisionV1::Existing,
            AccountAliasRoleV1::Primary,
        )?,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let issue = TransactionBuilder::new(
        network.network_id(),
        definition_owner.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
            asset_definition,
            "alias-safe coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))),
        InstructionBox::from(Mint::asset_quantity(10_u32, source_asset.clone())),
    ])
    .sign(definition_owner_keypair.private_key());
    client.submit_transaction_and_wait(&issue)?;
    let error = client
        .submit(
            Transfer::asset_quantity(source_asset, 1_u32, destination),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err(
            "owning an active alias domain must not authorize transfers from the aliased account",
        );
    assert!(
        error.chain().any(|cause| {
            cause
                .to_string()
                .contains("source asset owner must sign the transaction")
        }),
        "unexpected alias-domain transfer rejection: {error:?}"
    );
    Ok(())
}
#[test]
fn domain_owner_nft_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(domain_owner_nft_permissions))?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let nft_id = NftId::new(DomainId::try_new("kingdom", "universal")?, "nft".parse()?);
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Grant permission to register NFT to "bob@kingdom"
    let permission = CanRegisterNft { domain: kingdom_id };
    test_client.submit(
        Grant::account_permission(permission, bob_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // register NFT by "bob@kingdom" so he is owner of it
    let nft = Nft::new(nft_id.clone(), Metadata::default());
    let transaction = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Register::nft(nft.clone())])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&transaction)?;
    // check that the canonical ALICE account as owner of domain can edit metadata of NFT in her domain
    let key: Name = "key".parse()?;
    let value = Json::new("value");
    test_client.submit(
        SetKeyValue::nft(nft_id.clone(), key.clone(), value),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RemoveKeyValue::nft(nft_id.clone(), key),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can grant and revoke NFT related permissions in her domain
    let permission = CanUnregisterNft {
        nft: nft_id.clone(),
    };
    test_client.submit(
        Grant::account_permission(permission.clone(), bob_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        RevokeBox::from(Revoke::account_permission(permission, bob_id)),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // check that the canonical ALICE account as owner of domain can unregister NFT in her domain
    test_client.submit(
        Unregister::nft(nft_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn domain_owner_trigger_permissions() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) =
        start_network(builder, stringify!(domain_owner_trigger_permissions))?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id);
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "rose".parse()?,
    );
    let asset_id = AssetId::new(asset_definition_id, alice_id.clone());
    let trigger_id: TriggerId = "my_trigger".parse()?;
    let trigger_instructions = vec![Mint::asset_quantity(1u32, asset_id)];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(2_u32),
            bob_id.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let err = test_client
        .submit(
            register_trigger.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("domain owner must not register a trigger owned by another account");
    assert!(
        err.chain()
            .any(|cause| cause.to_string().contains("Missing CanRegisterTrigger"))
    );
    let grant_register_permission = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Grant::account_permission(
        iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
            authority: bob_id.clone(),
        },
        bob_id.clone(),
    )])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_register_permission)?;
    let transaction = TransactionBuilder::new(
        network.network_id(),
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([register_trigger])
    .sign(bob_keypair.private_key());
    test_client.submit_transaction_and_wait(&transaction)?;
    test_client.submit(
        Mint::trigger_repetitions(1_u32, trigger_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        Burn::trigger_repetitions(1_u32, trigger_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let execute_permission = CanExecuteTrigger {
        trigger: trigger_id.clone(),
    };
    let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
    let err = test_client
        .submit(
            Instruction::into_instruction_box(Box::new(execute_trigger)),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("manual execute should still be rejected for this trigger shape");
    assert!(err.chain().any(|cause| {
        cause
            .to_string()
            .contains("Trigger can't be executed manually: filter mismatch")
    }));
    test_client.submit(
        Grant::account_permission(execute_permission, alice_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let permission = CanUnregisterTrigger {
        trigger: trigger_id.clone(),
    };
    test_client.submit(
        Grant::account_permission(permission, bob_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    test_client.submit(
        Unregister::trigger(trigger_id),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
#[test]
fn domain_owner_transfer() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(domain_owner_transfer))? else {
        return Ok(());
    };
    let test_client = network.client();
    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = DomainId::try_new("kingdom", "universal")?;
    let (bob_id, _bob_keypair) = gen_account_in("kingdom");
    // the canonical ALICE account is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    submit_ensure_domain_for_network(&network, &test_client, kingdom)?;
    let bob = Account::new(bob_id.clone());
    test_client.submit(
        Register::account(bob),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let domain =
        wait_for_domain_owner(&test_client, &kingdom_id, &alice_id, "domain registration")?;
    assert_eq!(domain.owned_by(), &alice_id);
    test_client
        .submit(
            Transfer::domain(alice_id, kingdom_id.clone(), bob_id.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("Failed to submit transaction");
    let domain = wait_for_domain_owner(&test_client, &kingdom_id, &bob_id, "domain transfer")?;
    assert_eq!(domain.owned_by(), &bob_id);
    Ok(())
}
#[test]
fn not_allowed_to_transfer_other_user_domain() -> Result<()> {
    let users_domain: DomainId = DomainId::try_new("users", "universal")?;
    let foo_domain: DomainId = DomainId::try_new("foo", "universal")?;
    let user1 = checked_random_account_id();
    let user2 = checked_random_account_id();
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let builder = NetworkBuilder::new()
        .with_genesis_instruction(Register::domain(Domain::new(users_domain.clone())))
        .with_genesis_instruction(Register::account(Account::new(user1.clone())))
        .with_genesis_instruction(Register::account(Account::new(user2.clone())))
        .with_genesis_instruction(Register::domain(Domain::new(foo_domain.clone())))
        .next_genesis_transaction()
        .with_genesis_instruction(Transfer::domain(
            genesis_account.clone(),
            foo_domain.clone(),
            user1.clone(),
        ))
        .with_genesis_instruction(Transfer::domain(
            genesis_account.clone(),
            users_domain.clone(),
            user1.clone(),
        ));
    let Some((network, _rt)) = start_network(
        builder,
        stringify!(not_allowed_to_transfer_other_user_domain),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    let domain = client
        .client()
        .query(FindDomains::new())
        .execute_all()?
        .into_iter()
        .find(|domain| domain.id() == &foo_domain)
        .expect("Failed to execute Iroha Query");
    assert_eq!(domain.owned_by(), &user1);
    let users = client
        .client()
        .query(FindDomains::new())
        .execute_all()?
        .into_iter()
        .find(|domain| domain.id() == &users_domain)
        .expect("Failed to execute Iroha Query");
    assert_eq!(users.owned_by(), &user1);
    // Client authority is "alice@wonderlang".
    // `foo_domain` is owned by `user1@users`.
    // Alice has no rights to `user1` or `foo_domain`.
    // Therefore transaction should be rejected.
    let transfer_domain = Transfer::domain(user1, foo_domain, user2);
    let result = client.submit(
        transfer_domain,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    assert!(result.is_err());
    Ok(())
}
