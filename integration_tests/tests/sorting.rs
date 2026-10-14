//! Tests for sorting and pagination queries
use eyre::{Result, WrapErr as _};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    crypto::{KeyPair, PublicKey},
    data_model::{account::Account, prelude::*, query::parameters::SortOrder},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;
fn start_network(
    builder: NetworkBuilder,
    context: &'static str,
) -> Option<(sandbox::SerializedNetwork, Runtime)> {
    sandbox::start_network_blocking_or_skip(builder, context).unwrap()
}
fn checked_random_public_key() -> PublicKey {
    KeyPair::try_random()
        .expect("generate checked sorting account keypair")
        .into_parts()
        .0
}
#[test]
fn sorting_account_public_key_fixture_uses_checked_randomness() {
    let _public_key = checked_random_public_key();
}
#[test]
#[allow(clippy::cast_possible_truncation)]
fn correct_pagination_assets_after_creating_new_one() {
    const N_ASSETS: usize = 12;
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping: pagination test gated by issue #4786. Set IROHA_RUN_IGNORED=1 to run."
        );
        return;
    }
    // 0 < pagination.start < missing_idx < pagination.end < N_ASSETS
    let missing_indices = vec![N_ASSETS / 2];
    let pagination = Pagination::new(Some(nonzero!(N_ASSETS as u64 / 3)), N_ASSETS as u64 / 3);
    let xor_filter = CompoundPredicate::<Asset>::PASS; // lightweight DSL stub
    let sort_by_metadata_key = "sort".parse::<Name>().expect("Valid");
    let sorting = Sorting::by_metadata_key(sort_by_metadata_key.clone());
    let account_id = ALICE_ID.clone();
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(
        builder,
        stringify!(correct_pagination_assets_after_creating_new_one),
    ) else {
        return;
    };
    let test_client = network.client();
    let mut tester_assets = vec![];
    let mut register_asset_definitions = vec![];
    let mut register_assets = vec![];
    let mut missing_tester_assets = vec![];
    let mut missing_register_asset_definitions = vec![];
    let mut missing_register_assets = vec![];
    for i in 0..N_ASSETS {
        let asset_name = format!("xor{i}");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            asset_name.parse().expect("Valid"),
        );
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            asset_name,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        );
        let asset = Asset::new(AssetId::new(asset_definition_id, account_id.clone()), 1u32);
        if missing_indices.contains(&i) {
            missing_tester_assets.push(asset.clone());
            missing_register_asset_definitions.push(Register::asset_definition(asset_definition));
            missing_register_assets.push(Mint::asset_quantity(1u32, asset.id().clone()));
        } else {
            tester_assets.push(asset.clone());
            register_asset_definitions.push(Register::asset_definition(asset_definition));
            register_assets.push(Mint::asset_quantity(1u32, asset.id().clone()));
        }
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x534f_5254);
    register_asset_definitions.shuffle(&mut rng);
    register_assets.shuffle(&mut rng);
    submit_chunked(&test_client, &register_asset_definitions).expect("Valid");
    submit_chunked(&test_client, &register_assets).expect("Valid");
    let queried_assets = test_client
        .client()
        .query(FindAssets::new())
        .filter(xor_filter.clone())
        .with_pagination(pagination)
        .with_sorting(sorting.clone())
        .execute_all()
        .expect("Valid");
    tester_assets
        .iter()
        .skip(N_ASSETS / 3)
        .take(N_ASSETS / 3)
        .zip(queried_assets)
        .for_each(|(tester, queried)| assert_eq!(*tester, queried));
    for (i, missing_idx) in missing_indices.into_iter().enumerate() {
        tester_assets.insert(missing_idx, missing_tester_assets[i].clone());
    }
    submit_chunked(&test_client, &missing_register_asset_definitions).expect("Valid");
    submit_chunked(&test_client, &missing_register_assets).expect("Valid");
    let queried_assets = test_client
        .client()
        .query(FindAssets::new())
        .filter(xor_filter)
        .with_pagination(pagination)
        .with_sorting(sorting)
        .execute_all()
        .expect("Valid");
    tester_assets
        .iter()
        .skip(N_ASSETS / 3)
        .take(N_ASSETS / 3)
        .zip(queried_assets)
        .for_each(|(tester, queried)| assert_eq!(*tester, queried));
}
const MAX_INSTRUCTIONS_PER_TX: usize = 5;
fn submit_chunked<I>(client: &Client, instructions: &[I]) -> Result<()>
where
    I: Clone + Into<InstructionBox>,
{
    for chunk in instructions.chunks(MAX_INSTRUCTIONS_PER_TX) {
        client
            .submit_all(
                chunk.iter().cloned(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err("Failed to submit instruction batch")?;
    }
    Ok(())
}
fn wait_for_sorted_asset_definitions(
    client: &Client,
    sorting: Sorting,
    included_asset_definitions: &HashSet<AssetDefinitionId>,
    expected_asset_definitions: &[AssetDefinitionId],
) -> Result<Vec<AssetDefinition>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "asset definitions were not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query(FindAssetDefinitions::new())
            .with_sorting(sorting.clone())
            .execute_all()
        {
            Ok(asset_definitions) => {
                let observed = asset_definitions
                    .into_iter()
                    .filter(|asset_definition| {
                        included_asset_definitions.contains(asset_definition.id())
                    })
                    .collect::<Vec<_>>();
                let observed_ids = observed
                    .iter()
                    .map(|asset_definition| asset_definition.id().clone())
                    .collect::<Vec<_>>();
                last_observed = observed_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                if observed_ids == expected_asset_definitions {
                    return Ok(observed);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre::eyre!(
        "timed out waiting for sorted asset definitions; last_observed={last_observed}"
    ))
}
fn wait_for_sorted_accounts(
    client: &Client,
    sorting: Sorting,
    included_accounts: &HashSet<AccountId>,
    expected_accounts: &[AccountId],
) -> Result<Vec<Account>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "accounts were not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query(FindAccounts::new())
            .with_sorting(sorting.clone())
            .execute_all()
        {
            Ok(accounts) => {
                let observed = accounts
                    .into_iter()
                    .filter(|account| included_accounts.contains(account.id()))
                    .collect::<Vec<_>>();
                let observed_ids = observed
                    .iter()
                    .map(|account| account.id().clone())
                    .collect::<Vec<_>>();
                last_observed = observed
                    .iter()
                    .map(Identifiable::id)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                if observed_ids == expected_accounts {
                    return Ok(observed);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre::eyre!(
        "timed out waiting for sorted account ids; last_observed={last_observed}"
    ))
}
fn wait_for_sorted_domains(
    client: &Client,
    sorting: Sorting,
    included_domains: &HashSet<DomainId>,
    expected_domains: &[DomainId],
) -> Result<Vec<Domain>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "domains were not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query(FindDomains::new())
            .with_sorting(sorting.clone())
            .execute_all()
        {
            Ok(domains) => {
                let observed = domains
                    .into_iter()
                    .filter(|domain| included_domains.contains(domain.id()))
                    .collect::<Vec<_>>();
                let observed_ids = observed
                    .iter()
                    .map(|domain| domain.id().clone())
                    .collect::<Vec<_>>();
                last_observed = observed_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                if observed_ids == expected_domains {
                    return Ok(observed);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre::eyre!(
        "timed out waiting for sorted domains; last_observed={last_observed}"
    ))
}
#[test]
#[allow(clippy::too_many_lines)]
fn correct_sorting_of_entities() -> Result<()> {
    let auxiliary_domain_id = DomainId::try_new("_neverland", "universal").expect("Valid");
    let builder = NetworkBuilder::new()
        .with_genesis_instruction(Register::domain(Domain::new(auxiliary_domain_id.clone())));
    let Some((network, _rt)) = start_network(builder, stringify!(correct_sorting_of_entities))
    else {
        return Ok(());
    };
    let test_client = network.client();
    let sort_by_metadata_key = "test_sort".parse::<Name>().expect("Valid");
    // Test sorting asset definitions
    let mut asset_definitions = vec![];
    let mut metadata_of_assets = vec![];
    let mut instructions = vec![];
    let n = 10_u32;
    for i in 0..n {
        let asset_name = format!("xor_{i}");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            asset_name.parse().expect("Valid"),
        );
        let mut asset_metadata = Metadata::default();
        asset_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            asset_name,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(asset_metadata.clone());
        metadata_of_assets.push(asset_metadata);
        asset_definitions.push(asset_definition_id);
        let create_asset_definition = Register::asset_definition(asset_definition);
        instructions.push(create_asset_definition);
    }
    submit_chunked(&test_client, &instructions).expect("Valid");
    let included_asset_definitions = asset_definitions.iter().cloned().collect::<HashSet<_>>();
    let expected_asset_definitions = asset_definitions.iter().rev().cloned().collect::<Vec<_>>();
    let res = wait_for_sorted_asset_definitions(
        &test_client,
        Sorting::by_metadata_key(sort_by_metadata_key.clone()),
        &included_asset_definitions,
        &expected_asset_definitions,
    )?;
    assert!(
        res.iter()
            .map(Identifiable::id)
            .eq(asset_definitions.iter().rev())
    );
    assert!(
        res.iter()
            .map(AssetDefinition::metadata)
            .eq(metadata_of_assets.iter().rev())
    );
    // Test sorting accounts
    let mut accounts = vec![];
    let mut metadata_of_accounts = vec![];
    let mut instructions = vec![];
    let n = 10u32;
    let mut public_keys = (0..n)
        .map(|_| checked_random_public_key())
        .collect::<Vec<_>>();
    public_keys.sort_unstable();
    for i in 0..n {
        let account_id = AccountId::new(public_keys[i as usize].clone());
        let mut account_metadata = Metadata::default();
        account_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let account = Account::new(account_id.clone()).with_metadata(account_metadata.clone());
        accounts.push(account_id);
        metadata_of_accounts.push(account_metadata);
        let create_account = Register::account(account);
        instructions.push(create_account);
    }
    submit_chunked(&test_client, &instructions).expect("Valid");
    let included_accounts = accounts.iter().cloned().collect::<HashSet<_>>();
    let expected_accounts = accounts.iter().rev().cloned().collect::<Vec<_>>();
    let res = wait_for_sorted_accounts(
        &test_client,
        Sorting::by_metadata_key(sort_by_metadata_key.clone()),
        &included_accounts,
        &expected_accounts,
    )?;
    assert!(res.iter().map(Identifiable::id).eq(accounts.iter().rev()));
    assert!(
        res.iter()
            .map(Account::metadata)
            .eq(metadata_of_accounts.iter().rev())
    );
    // Test sorting domains
    let mut domains = vec![];
    let mut metadata_of_domains = vec![];
    let mut instructions = vec![];
    let n = 10u32;
    for i in 0..n {
        let domain_id = DomainId::try_new(format!("neverland{i}"), "universal").expect("Valid");
        let mut domain_metadata = Metadata::default();
        domain_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        domains.push(domain_id.clone());
        metadata_of_domains.push(domain_metadata);
        instructions.push(SetKeyValue::domain(
            domain_id,
            sort_by_metadata_key.clone(),
            n - i - 1,
        ));
    }
    for domain_id in &domains {
        ensure_domain_setup_for_network(&network, domain_id)
            .expect("should ensure sortable domains");
    }
    submit_chunked(&test_client, &instructions).expect("Valid");
    let included_domains = domains.iter().cloned().collect::<HashSet<_>>();
    let expected_domains = domains.iter().rev().cloned().collect::<Vec<_>>();
    let res = wait_for_sorted_domains(
        &test_client,
        Sorting::by_metadata_key(sort_by_metadata_key.clone()),
        &included_domains,
        &expected_domains,
    )?;
    assert!(res.iter().map(Identifiable::id).eq(domains.iter().rev()));
    assert!(
        res.iter()
            .map(Domain::metadata)
            .eq(metadata_of_domains.iter().rev())
    );
    // Naive test sorting of domains
    let input = [(0_i32, 1_u32), (2, 0), (1, 2)];
    let mut domains = vec![];
    let mut metadata_of_domains = vec![];
    let mut instructions = vec![];
    for (idx, val) in input {
        let domain_id = DomainId::try_new(format!("sortland{idx}"), "universal").expect("Valid");
        let mut domain_metadata = Metadata::default();
        domain_metadata.insert(sort_by_metadata_key.clone(), val);
        domains.push(domain_id.clone());
        metadata_of_domains.push(domain_metadata);
        instructions.push(SetKeyValue::domain(
            domain_id,
            sort_by_metadata_key.clone(),
            val,
        ));
    }
    for domain_id in &domains {
        ensure_domain_setup_for_network(&network, domain_id)
            .expect("should ensure underscore sortable domains");
    }
    submit_chunked(&test_client, &instructions).expect("Valid");
    let included_domains = domains.iter().cloned().collect::<HashSet<_>>();
    let expected_domains = vec![domains[1].clone(), domains[0].clone(), domains[2].clone()];
    let res = wait_for_sorted_domains(
        &test_client,
        Sorting::by_metadata_key(sort_by_metadata_key),
        &included_domains,
        &expected_domains,
    )?;
    assert_eq!(res[0].id(), &domains[1]);
    assert_eq!(res[1].id(), &domains[0]);
    assert_eq!(res[2].id(), &domains[2]);
    assert_eq!(res[0].metadata(), &metadata_of_domains[1]);
    assert_eq!(res[1].metadata(), &metadata_of_domains[0]);
    assert_eq!(res[2].metadata(), &metadata_of_domains[2]);
    Ok(())
}
#[test]
fn metadata_sorting_descending() {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(metadata_sorting_descending))
    else {
        return;
    };
    let test_client = network.client();
    let sort_by_metadata_key = "test_sort".parse::<Name>().expect("Valid");
    let mut asset_definitions = vec![];
    let mut metadata_of_assets = vec![];
    let mut instructions = vec![];
    let n = 10_u32;
    for i in 0..n {
        let asset_name = format!("xor_{i}");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            asset_name.parse().expect("Valid"),
        );
        let mut asset_metadata = Metadata::default();
        asset_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            asset_name,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(asset_metadata.clone());
        metadata_of_assets.push(asset_metadata);
        asset_definitions.push(asset_definition_id);
        let create_asset_definition = Register::asset_definition(asset_definition);
        instructions.push(create_asset_definition);
    }
    submit_chunked(&test_client, &instructions).expect("Valid");
    let res = test_client
        .client()
        .query(FindAssetDefinitions::new())
        .with_sorting(Sorting::new(
            Some(sort_by_metadata_key),
            Some(SortOrder::Desc),
        ))
        .execute_all()
        .expect("Valid")
        .into_iter()
        .filter(|asset_definition| asset_definitions.contains(asset_definition.id()))
        .collect::<Vec<_>>();
    assert!(
        res.iter()
            .map(Identifiable::id)
            .eq(asset_definitions.iter())
    );
    assert!(
        res.iter()
            .map(AssetDefinition::metadata)
            .eq(metadata_of_assets.iter())
    );
}
#[test]
fn sort_only_elements_which_have_sorting_key() -> Result<()> {
    const TEST_DOMAIN: &str = "neverland.universal";
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(
        builder,
        stringify!(sort_only_elements_which_have_sorting_key),
    ) else {
        return Ok(());
    };
    let test_client = network.client();
    let domain_id = DomainId::parse_fully_qualified(TEST_DOMAIN).unwrap();
    ensure_domain_setup_for_network(&network, &domain_id)
        .expect("should ensure sorting test domain");
    let sort_by_metadata_key = "test_sort".parse::<Name>().expect("Valid");
    let mut accounts_a = vec![];
    let mut accounts_b = vec![];
    let mut instructions = vec![];
    let mut skip_set = HashSet::new();
    skip_set.insert(4);
    skip_set.insert(7);
    let n = 10u32;
    let mut public_keys = (0..n)
        .map(|_| checked_random_public_key())
        .collect::<Vec<_>>();
    public_keys.sort_unstable();
    for i in 0..n {
        let account_id = AccountId::new(public_keys[i as usize].clone());
        let account = if skip_set.contains(&i) {
            let account = Account::new(account_id.clone());
            accounts_b.push(account_id);
            account
        } else {
            let mut account_metadata = Metadata::default();
            account_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
            let account = Account::new(account_id.clone()).with_metadata(account_metadata);
            accounts_a.push(account_id);
            account
        };
        let create_account = Register::account(account);
        instructions.push(create_account);
    }
    submit_chunked(&test_client, &instructions).wrap_err("Failed to register accounts")?;
    let included_accounts = accounts_a
        .iter()
        .chain(accounts_b.iter())
        .cloned()
        .collect::<HashSet<_>>();
    let accounts = accounts_a
        .iter()
        .rev()
        .chain(accounts_b.iter())
        .cloned()
        .collect::<Vec<_>>();
    let _ = wait_for_sorted_accounts(
        &test_client,
        Sorting::by_metadata_key(sort_by_metadata_key),
        &included_accounts,
        &accounts,
    )
    .wrap_err("Failed to observe sorted accounts")?;
    Ok(())
}
