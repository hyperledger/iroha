use async_std::task::{self, JoinHandle};
use async_trait::async_trait;
use cucumber::{Cucumber, World};
use futures::executor;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
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
        let mut configuration = ClientConfiguration::from_path(CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        let free_port = port_check::free_local_port().expect("Failed to allocate a free port.");
        println!("Free port: {}", free_port);
        configuration.torii_url = format!("127.0.0.1:{}", free_port);
        let iroha_client = Client::new(&configuration);
        IrohaWorld {
            client: iroha_client,
            peer_id: PeerId::new(&configuration.torii_url, &configuration.public_key),
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
                            Register::<Domain, AssetDefinition>::new (
                                AssetDefinition::new(AssetDefinitionId::new(
                                        &asset_definition_name,
                                        &asset_definition_domain,
                                        )),
                                        asset_definition_domain.to_string(),
                                        )
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
                            Mint::<Asset, u32>::new(
                                asset_quantity,
                                AssetId::new(AssetDefinitionId::new(
                                        &asset_definition_name,
                                        &asset_definition_domain,
                                        ), AccountId::new(account_name, account_domain)),
                                        )
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
                if let QueryResult::FindAssetsByAccountIdAndAssetDefinitionId(result) = query_result {
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
                if let QueryResult::FindAssetsByAccountIdAndAssetDefinitionId(result) = query_result {
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
                    let register_account = Register::<Domain, Account>::new(
                        Account::new(AccountId::new(&account_name, &domain_name)),
                        domain_name.to_string(),
                        );
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
                            Mint::<Asset, u32>::new(
                                quantity,
                                AssetId::new(
                                    AssetDefinitionId::new(
                                        &asset_definition_name,
                                        &asset_definition_domain
                                        ),
                                        AccountId::new(
                                            &account_name,
                                            &account_domain_name
                                            )
                                        )
                                ).into()
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
                    if let QueryResult::FindAccountById(_) = query_result {
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
                    let add_domain = Register::<Peer, Domain>::new(
                        Domain::new(domain_name),
                        world.peer_id.clone(),
                    );
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
                    if let QueryResult::FindDomainByName(_) = query_result {
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
                    if let QueryResult::FindAllDomains(_) = query_result {
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
                    if let QueryResult::FindAllAssets(_) = query_result {
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
                    if let QueryResult::FindAllAccounts(_) = query_result {
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
                    if let QueryResult::FindAllAssetsDefinitions(_) = query_result {
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
                        if let QueryResult::FindAllDomains(result) = query_result {
                            assert!(result.domains.contains(&Domain::new(domain_name)));
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
                        if let QueryResult::FindAllAccounts(result) = query_result {
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
                        if let QueryResult::FindAllAssetsDefinitions(result) = query_result {
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
                        if let QueryResult::FindAllAssets(result) = query_result {
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

mod peer_steps {
    use super::*;
    use cucumber::Steps;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        steps.when_regex_sync(
            r"(.+) Account from (.+) domain registers new Trusted Peer with URL (.+) and Public Key (.+)$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let trusted_peer_url = matches[3].trim();
                let trusted_peer_public_key = matches[4].trim();
                let public_key: PublicKey = serde_json::from_value(serde_json::json!(trusted_peer_public_key)).expect("Failed to parse Public Key.");
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            Register::<Peer, Peer>::new (
                                Peer::new(
                                    PeerId::new(
                                        trusted_peer_url,
                                        &public_key)),
                                        world.peer_id.clone()
                                        )
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain sets Maximum Faulty Peers Amount to (\d+)$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let maximum_faulty_peers_amount = matches[3].parse().expect("Failed to parse MaximumFaultyPeersAmount.");
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            Mint::<Peer, Parameter>::new (
                                Parameter::MaximumFaultyPeersAmount(maximum_faulty_peers_amount),
                                world.peer_id.clone()
                                )
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain sets Commit Time to (\d+) milliseconds$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let commit_time_milliseconds = matches[3].parse().expect("Failed to parse CommitTime.");
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            Mint::<Peer, Parameter>::new (
                                Parameter::CommitTime(commit_time_milliseconds),
                                world.peer_id.clone()
                                )
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain sets Transaction Receipt Time to (\d+) milliseconds$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let transaction_receipt_time_milliseconds = matches[3].parse().expect("Failed to parse TransactionReceiptTime.");
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            Mint::<Peer, Parameter>::new (
                                Parameter::TransactionReceiptTime(transaction_receipt_time_milliseconds),
                                world.peer_id.clone()
                                )
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain sets Block Time to (\d+) milliseconds$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let block_time_milliseconds = matches[3].parse().expect("Failed to parse BlockTime.");
                executor::block_on(async {
                    world
                        .client
                        .submit(
                            Mint::<Peer, Parameter>::new (
                                Parameter::BlockTime(block_time_milliseconds),
                                world.peer_id.clone()
                                )
                            .into(),
                            )
                        .await
                })
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain requests List of Trusted Peers$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result = executor::block_on(async {
                    world
                        .client
                        .request(
                            &QueryRequest::new(FindAllPeers::new().into())
                            )
                        .await
                })
                .expect("Failed to execute request.");
                if let QueryResult::FindAllPeers(_) = query_result {
                    world.result = Some(query_result);
                }
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain requests Maximum Faulty Peers Amount$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result = executor::block_on(async {
                    world
                        .client
                        .request(
                            &QueryRequest::new(FindAllParameters::new().into())
                            )
                        .await
                })
                .expect("Failed to execute request.");
                if let QueryResult::FindAllParameters(_) = query_result {
                    world.result = Some(query_result);
                }
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain requests Commit Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result = executor::block_on(async {
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )
                        .await
                })
                .expect("Failed to execute request.");
                if let QueryResult::FindAllParameters(_) = query_result {
                    world.result = Some(query_result);
                }
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain requests Transaction Receipt Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result = executor::block_on(async {
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )
                        .await
                })
                .expect("Failed to execute request.");
                if let QueryResult::FindAllParameters(_) = query_result {
                    world.result = Some(query_result);
                }
                world
            })
        .when_regex_sync(
            r"(.+) Account from (.+) domain requests Block Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result = executor::block_on(async {
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )
                        .await
                })
                .expect("Failed to execute request.");
                if let QueryResult::FindAllParameters(_) = query_result {
                    world.result = Some(query_result);
                }
                world
            })
        .then_regex_sync(
            r"QueryResult contains Trusted Peer with URL (.+) and Public Key (.+)$",
            | world,
            matches,
            _step | {
                let trusted_peer_url = matches[1].trim();
                let trusted_peer_public_key = matches[2].trim();
                let public_key: PublicKey = serde_json::from_value(serde_json::json!(trusted_peer_public_key)).expect("Failed to parse Public Key.");
                if let QueryResult::FindAllPeers(result) = world.result.clone().expect("Result is missing.") {
                    assert!(result.peers.iter().find(|peer_id|  peer_id.address == trusted_peer_url && peer_id.public_key == public_key ).is_some());
                }
                world
            })
        .then_regex_sync(
            r"QueryResult contains Parameter Maximum Faulty Peers Amount with value (\d+)$",
            | world,
            matches,
            _step | {
                let maximum_faulty_peers_amount = matches[1].parse().expect("Failed to parse MaximumFaultyPeersAmount.");
                if let QueryResult::FindAllParameters(result) = world.result.clone().expect("Result is missing.") {
                    assert!(result.parameters.iter().find(|parameter| *parameter == &Parameter::MaximumFaultyPeersAmount(maximum_faulty_peers_amount)).is_some());
                }
                world
            })
        .then_regex_sync(
            r"QueryResult contains Parameter Commit Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let commit_time_milliseconds = matches[1].parse().expect("Failed to parse CommitTime.");
                if let QueryResult::FindAllParameters(result) = world.result.clone().expect("Result is missing.") {
                    assert!(result.parameters.iter().find(|parameter| *parameter == &Parameter::CommitTime(commit_time_milliseconds)).is_some());
                }
                world
            })
        .then_regex_sync(
            r"QueryResult contains Parameter Transaction Receipt Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let transaction_receipt_time_milliseconds = matches[1].parse().expect("Failed to parse TransactionReceiptTime.");
                if let QueryResult::FindAllParameters(result) = world.result.clone().expect("Result is missing.") {
                    assert!(result.parameters.iter().find(|parameter| *parameter == &Parameter::TransactionReceiptTime(transaction_receipt_time_milliseconds)).is_some());
                }
                world
            })
        .then_regex_sync(
            r"QueryResult contains Parameter Block Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let block_time_milliseconds = matches[1].parse().expect("Failed to parse BlockTime.");
                if let QueryResult::FindAllParameters(result) = world.result.clone().expect("Result is missing.") {
                    assert!(result.parameters.iter().find(|parameter| *parameter == &Parameter::BlockTime(block_time_milliseconds)).is_some());
                }
                world
            })
        ;
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
        .steps(peer_steps::steps());
    runner.run().await;
}
