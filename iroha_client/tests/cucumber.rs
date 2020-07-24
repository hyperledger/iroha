use async_std::task::{self, JoinHandle};
use async_trait::async_trait;
use cucumber::{Cucumber, World};
use futures::executor;
use iroha::{config::Configuration, isi, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use std::{thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/single_config.json";

pub struct IrohaWorld {
    client: Client,
    peer_id: PeerId,
    block_build_time: u64,
    iroha_port: u16,
    result: Option<QueryResult>,
    join_handle: Option<JoinHandle<()>>,
}

#[async_trait(?Send)]
impl World for IrohaWorld {
    async fn new() -> Self {
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let free_port = port_check::free_local_port().expect("Failed to allocate a free port.");
        println!("Free port: {}", free_port);
        configuration.torii_configuration.torii_url = format!("127.0.0.1:{}", free_port);
        let client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        IrohaWorld {
            client,
            peer_id: PeerId::new(
                &configuration.torii_configuration.torii_url,
                &configuration.public_key,
            ),
            block_build_time: 300,
            iroha_port: free_port,
            result: Option::None,
            join_handle: Option::None,
        }
    }
}

mod iroha_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps
            .given_sync("Iroha Peer is up", |mut world, _step| {
                let iroha_port = world.iroha_port;
                world.join_handle = Some(task::spawn(async move {
                    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                    let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                        .expect("Failed to load configuration.");
                    configuration
                        .kura_configuration
                        .kura_block_store_path(temp_dir.path());
                    configuration.torii_configuration.torii_url =
                        format!("127.0.0.1:{}", iroha_port);
                    let iroha = Iroha::new(configuration.clone());
                    iroha.start().await.expect("Failed to start Iroha.");
                    loop {}
                }));
                thread::sleep(Duration::from_millis(world.block_build_time));
                world
            })
            .then_sync("Iroha Peer is down", |mut world, _step| {
                if let Some(join_handle) = world.join_handle {
                    executor::block_on(async {
                        join_handle.cancel().await;
                    });
                    world.join_handle = None;
                    thread::sleep(Duration::from_millis(world.block_build_time));
                }
                world
            });
        steps
    }
}

mod asset_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps.given_regex_sync(
            r"^Peer has Asset Definition with name (.+) and domain (.+)$",
            | mut world,
            matches,
            _step | {
                let asset_definition_name = matches[1].trim();
                let asset_definition_domain = matches[2].trim();
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            isi::Register::<Domain, AssetDefinition> {
                                object: AssetDefinition::new(AssetDefinitionId::new(
                                                &asset_definition_name,
                                                &asset_definition_domain,
                                                )),
                                                destination_id: asset_definition_domain.to_string(),
                            }
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            }
        ).given_regex_sync(
            r"^(.+) Account in domain (.+) has (\d+) amount of Asset with definition (.+) in domain (.+)$",
            | mut world,
            matches,
            _step | {
                let account_name = matches[1].trim();
                let account_domain = matches[2].trim();
                let asset_quantity: u32 = matches[3].trim().parse().expect("Failed to parse Assets Quantity.");
                let asset_definition_name = matches[4].trim();
                let asset_definition_domain = matches[5].trim();
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            isi::Mint {
                                object: asset_quantity,
                                destination_id: AssetId::new(AssetDefinitionId::new(
                                                &asset_definition_name,
                                                &asset_definition_domain,
                                                ), AccountId::new(account_name, account_domain)),
                            }
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            }
        ).then_regex_sync(
            r"^Peer has Asset with definition (.+) in domain (.+) and under account (.+) in domain (.+)$",
            | mut world,
            matches,
            _step | {
                let asset_definition_name = matches[1].trim();
                let asset_definition_domain = matches[2].trim();
                let account_name = matches[3].trim();
                let account_domain = matches[4].trim();
                let request = client::asset::by_account_id_and_definition_id(
                    AccountId::new(&account_name, &account_domain),
                    AssetDefinitionId::new(&asset_definition_name, &asset_definition_domain),
                    );
                let query_result =
                    executor::block_on(async { world.client.request(&request).await })
                    .expect("Failed to execute request.");
                if let QueryResult::GetAccountAssetsWithDefinition(result) = query_result {
                    assert!(!result.assets.is_empty());
                } else {
                    panic!("Wrong Query Result Type.");
                }
                world
            }
        ).then_regex_sync(
            r"^(.+) Account in domain (.+) has (\d+) amount of Asset with definition (.+) in domain (.+)$",
            | mut world,
            matches,
            _step | {
                let account_name = matches[1].trim();
                let account_domain = matches[2].trim();
                let asset_quantity: u32 = matches[3].trim().parse().expect("Failed to parse Assets Quantity.");
                let asset_definition_name = matches[4].trim();
                let asset_definition_domain = matches[5].trim();
                let request = client::asset::by_account_id_and_definition_id(
                    AccountId::new(&account_name, &account_domain),
                    AssetDefinitionId::new(&asset_definition_name, &asset_definition_domain),
                    );
                let query_result =
                    executor::block_on(async { world.client.request(&request).await })
                    .expect("Failed to execute request.");
                if let QueryResult::GetAccountAssetsWithDefinition(result) = query_result {
                    assert!(!result.assets.is_empty());
                    let mut total_quantity = 0;
                    result.assets.iter().for_each(|asset| {
                        total_quantity += asset.quantity;
                    });
                    assert_eq!(asset_quantity, total_quantity);
                } else {
                    panic!("Wrong Query Result Type.");
                }
                world
            }
        );
        steps
    }
}

mod account_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps
            .given_regex_sync(
                r"^Peer has Account with name (.+) and domain (.+)$",
                | mut world,
                matches,
                _step | {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to register an account with id: {}@{}",
                        &account_name, &domain_name
                        );
                    let register_account = isi::Register::<Domain, Account> {
                        object: Account::new(&account_name, &domain_name),
                        destination_id: domain_name.to_string(),
                    };
                    executor::block_on(async {
                        world.client.submit(register_account.into()).await
                    })
                    .expect("Failed to register an account.");
                    thread::sleep(Duration::from_millis(world.block_build_time * 2));
                    world
                }
        )
            .given_regex_sync(
                r"^(.+) Account in domain (.+) has (\d) quantity of Asset with definition (.+) in domain (.+)$",
                |
                mut world,
                matches,
                _step | {
                    let account_name = matches[1].trim();
                    let account_domain_name = matches[2].trim();
                    let quantity: u32 = matches[3].trim().parse().expect("Failed to parse quantity.");
                    let asset_definition_name = matches[4].trim();
                    let asset_definition_domain  = matches[5].trim();
                    println!(
                        "Going to mint an {} of an asset with definition: {}#{} to an account: {}@{}",
                        quantity, asset_definition_name, asset_definition_domain,
                        account_name, account_domain_name);
                    executor::block_on(
                        world.client.submit(
                            isi::Mint {
                                object: quantity,
                                destination_id: AssetId {
                                    definition_id: AssetDefinitionId::new(
                                                       &asset_definition_name,
                                                       &asset_definition_domain
                                                       ),
                                                       account_id: AccountId::new(
                                                           &account_name,
                                                           &account_domain_name
                                                           )
                                }
                            }.into()
                            )
                        ).expect("Failed to submit Mint instruction.");
                    thread::sleep(Duration::from_millis(world.block_build_time));
                    world
                }
        )
            .then_regex_sync(
                r"^Peer has Account with name (.+) and domain (.+)$",
                | mut world,
                matches,
                _step | {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!("Checking account with id: {}@{}", account_name, domain_name);
                    let request =
                        client::account::by_id(AccountId::new(&account_name, &domain_name));
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                        .expect("Failed to execute request.");
                    if let QueryResult::GetAccount(_) = query_result {
                        println!("Account found.");
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                }
                );
        steps
    }
}

mod domain_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps
            .given_regex_sync(
                r"^Peer has Domain with name (.+)$",
                |mut world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Going to add domain with name: {}", domain_name);
                    let add_domain = isi::Add::<Peer, Domain> {
                        object: Domain::new(domain_name.to_string()),
                        destination_id: world.peer_id.clone(),
                    };
                    executor::block_on(async { world.client.submit(add_domain.into()).await })
                        .expect("Failed to add the domain.");
                    thread::sleep(Duration::from_millis(world.block_build_time * 2));
                    world
                },
            )
            .then_regex_sync(
                r"^Peer has Domain with name (.+)$",
                |mut world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Check domain: {}", domain_name);
                    let request = client::domain::by_name(domain_name.to_string());
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                            .expect("Failed to execute request.");
                    if let QueryResult::GetDomain(_) = query_result {
                        println!("Domain found.");
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                },
            );
        steps
    }
}

mod query_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps
            .when_regex_sync(
                r"^(.+) Account from (.+) domain requests all domains$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all domains on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::domain::all();
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                            .expect("Failed to execute request.");
                    if let QueryResult::GetAllDomains(_) = query_result {
                        world.result = Some(query_result);
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                },
            )
            .when_regex_sync(
                r"^(.+) Account from (.+) domain requests all assets$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all assets on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::asset::all();
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                            .expect("Failed to execute request.");
                    if let QueryResult::GetAllAssets(_) = query_result {
                        world.result = Some(query_result);
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                },
            )
            .when_regex_sync(
                r"^(.+) Account from (.+) domain requests all accounts$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all accounts on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::account::all();
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                            .expect("Failed to execute request.");
                    if let QueryResult::GetAllAccounts(_) = query_result {
                        world.result = Some(query_result);
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                },
            )
            .when_regex_sync(
                r"^(.+) Account from (.+) domain requests all asset definitions$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all asset definitions on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::asset::all_definitions();
                    let query_result =
                        executor::block_on(async { world.client.request(&request).await })
                            .expect("Failed to execute request.");
                    if let QueryResult::GetAllAssetsDefinitions(_) = query_result {
                        world.result = Some(query_result);
                    } else {
                        panic!("Wrong Query Result Type.");
                    }
                    world
                },
            )
            .then_regex_sync(
                r"^QueryResult has Domain with name (.+)$",
                |world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Check that result has {} domain in it.", domain_name);
                    if let Some(query_result) = &world.result {
                        if let QueryResult::GetAllDomains(result) = query_result {
                            assert!(result
                                .domains
                                .contains(&Domain::new(domain_name.to_string())));
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex_sync(
                r"^QueryResult has Account with name (.+)$",
                |world, matches, _step| {
                    let account_name = matches[1].trim();
                    println!("Check that result has {} account in it.", account_name);
                    if let Some(query_result) = &world.result {
                        if let QueryResult::GetAllAccounts(result) = query_result {
                            assert!(!result
                                .accounts
                                .iter()
                                .filter(|account| { account.id.name == account_name })
                                .collect::<Vec<&Account>>()
                                .is_empty());
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex_sync(
                r"^QueryResult has Asset Definition with name (.+) and domain (.+)$",
                |world, matches, _step| {
                    let asset_definition_name = matches[1].trim();
                    let asset_definition_domain = matches[2].trim();
                    println!(
                        "Check that result has asset definition {}#{}.",
                        asset_definition_name, asset_definition_domain
                    );
                    if let Some(query_result) = &world.result {
                        println!("{:?}", query_result);
                        if let QueryResult::GetAllAssetsDefinitions(result) = query_result {
                            assert!(!result
                                .assets_definitions
                                .iter()
                                .filter(|asset_definition| {
                                    asset_definition.id
                                        == AssetDefinitionId::new(
                                            &asset_definition_name,
                                            &asset_definition_domain,
                                        )
                                })
                                .collect::<Vec<&AssetDefinition>>()
                                .is_empty());
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex_sync(
                r"^QueryResult has Asset with definition (.+) in domain (.+)$",
                |world, matches, _step| {
                    let asset_definition_name = matches[1].trim();
                    let asset_definition_domain = matches[2].trim();
                    println!(
                        "Check that result has asset {}#{}.",
                        asset_definition_name, asset_definition_domain
                    );
                    if let Some(query_result) = &world.result {
                        println!("{:?}", query_result);
                        if let QueryResult::GetAllAssets(result) = query_result {
                            assert!(!result
                                .assets
                                .iter()
                                .filter(|asset| {
                                    asset.id.definition_id
                                        == AssetDefinitionId::new(
                                            &asset_definition_name,
                                            &asset_definition_domain,
                                        )
                                })
                                .collect::<Vec<&Asset>>()
                                .is_empty());
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            );
        steps
    }
}

mod bridge_steps {
    use super::*;
    use cucumber::Steps;
    use iroha::bridge;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps
            .given_sync("Iroha Bridge module enabled", |mut world, _step| {
                let instructions = vec![
                    isi::Add::<Peer, Domain> {
                        object: Domain::new("bridge".to_string()),
                        destination_id: world.peer_id.clone(),
                    }
                    .into(),
                    isi::Register::<Domain, AssetDefinition> {
                        object: AssetDefinition::new(AssetDefinitionId::new(
                            "bridges_asset",
                            "bridge",
                        )),
                        destination_id: "bridge".to_string(),
                    }
                    .into(),
                    isi::Register::<Domain, AssetDefinition> {
                        object: AssetDefinition::new(AssetDefinitionId::new(
                            "bridge_external_assets_asset",
                            "bridge",
                        )),
                        destination_id: "bridge".to_string(),
                    }
                    .into(),
                    isi::Register::<Domain, AssetDefinition> {
                        object: AssetDefinition::new(AssetDefinitionId::new(
                            "bridge_incoming_external_transactions_asset",
                            "bridge",
                        )),
                        destination_id: "bridge".to_string(),
                    }
                    .into(),
                    isi::Register::<Domain, AssetDefinition> {
                        object: AssetDefinition::new(AssetDefinitionId::new(
                            "bridge_outgoing_external_transactions_asset",
                            "bridge",
                        )),
                        destination_id: "bridge".to_string(),
                    }
                    .into(),
                ];
                executor::block_on(async { world.client.submit_all(instructions).await })
                    .expect("Failed to add the domain.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
            .when_regex_sync(
                r"^(.+) Account from (.+) domain registers Bridge with name (.+)$",
                |mut world, matches, _step| {
                    let bridge_owner_account_name = matches[1].trim();
                    let bridge_owner_domain = matches[2].trim();
                    let bridge_name = matches[3].trim();
                    println!(
                        "Register bridge {} on behalf of account {}@{}",
                        bridge_name, bridge_owner_account_name, bridge_owner_domain
                    );
                    let bridge_owner_public_key = KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key;
                    let bridge_owner_account =
                        Account::with_signatory("bridge_owner", "company", bridge_owner_public_key);
                    let bridge_definition = BridgeDefinition {
                        id: BridgeDefinitionId::new(&bridge_name),
                        kind: BridgeKind::IClaim,
                        owner_account_id: bridge_owner_account.id.clone(),
                    };
                    let register_bridge =
                        bridge::isi::register_bridge(world.peer_id.clone(), &bridge_definition);
                    executor::block_on(async { world.client.submit(register_bridge.into()).await })
                        .expect("Failed to register bridge.");
                    thread::sleep(Duration::from_millis(world.block_build_time * 2));
                    world
                },
            )
            .then_regex_sync(
                r"^Peer has Bridge Definition with name (.+) and kind iclaim and owner (.+)$",
                |world, matches, _step| {
                    let bridge_definition_name = matches[1].trim();
                    let bridge_owner = matches[2].trim();
                    println!(
                        "Check bridge definition with name {} and owner {}",
                        bridge_definition_name, bridge_owner
                    );
                    world
                },
            );
        steps
    }
}

mod dex_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps.given_sync("Iroha DEX module enabled", |world, _step| {
            println!("DEX module enabled.");
            world
        });
        steps
    }
}

#[async_std::main]
async fn main() {
    let runner = Cucumber::<IrohaWorld>::new()
        .features(&["../docs/source/features"])
        .steps(iroha_steps::steps())
        .steps(asset_steps::steps())
        .steps(account_steps::steps())
        .steps(domain_steps::steps())
        .steps(query_steps::steps())
        .steps(bridge_steps::steps())
        .steps(dex_steps::steps());
    runner.run().await;
}
