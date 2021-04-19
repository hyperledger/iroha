#![allow(missing_docs, clippy::restriction, clippy::too_many_lines)]

use std::{convert::Infallible, panic::UnwindSafe, thread, time::Duration};

use async_std::task::{self, JoinHandle};
use async_trait::async_trait;
use cucumber_rust::{Cucumber, World as CucumberWorld};
use futures::executor;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/single_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

#[derive(Debug)]
pub struct IrohaWorld {
    client: Client,
    _peer_id: PeerId,
    block_build_time: u64,
    iroha_port: u16,
    result: Option<QueryResult>,
    join_handle: Option<JoinHandle<()>>,
}

impl UnwindSafe for IrohaWorld {}

#[async_trait(?Send)]
impl CucumberWorld for IrohaWorld {
    type Error = Infallible;
    async fn new() -> Result<Self, Infallible> {
        let mut configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        let free_port =
            unique_port::get_unique_free_port().expect("Failed to allocate a free port.");
        println!("Free port: {}", free_port);
        configuration.torii_api_url = format!("127.0.0.1:{}", free_port);
        let iroha_client = Client::new(&configuration);
        Ok(IrohaWorld {
            client: iroha_client,
            _peer_id: PeerId::new(&configuration.torii_api_url, &configuration.public_key),
            block_build_time: 300,
            iroha_port: free_port,
            result: Option::None,
            join_handle: Option::None,
        })
    }
}

mod iroha_steps {
    use cucumber_rust::Steps;

    use super::*;

    const IROHA_WORLD_SLEEP_TIME: Duration = Duration::from_millis(10);

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps
            .given("Iroha Peer is up", |mut world, _step| {
                let iroha_port = world.iroha_port;
                world.join_handle = Some(task::spawn(async move {
                    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                    let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                        .expect("Failed to load configuration.");
                    configuration
                        .kura_configuration
                        .kura_block_store_path(temp_dir.path())
                        .unwrap();
                    configuration.torii_configuration.torii_p2p_url =
                        format!("127.0.0.1:{}", iroha_port);
                    let iroha = Iroha::new(&configuration, AllowAll.into()).unwrap();
                    iroha.start().await.expect("Failed to start Iroha.");
                    loop {
                        thread::sleep(IROHA_WORLD_SLEEP_TIME);
                    }
                }));
                thread::sleep(Duration::from_millis(world.block_build_time));
                world
            })
            .then("Iroha Peer is down", |mut world, _step| {
                if let Some(join_handle) = world.join_handle {
                    executor::block_on(async {
                        let _ = join_handle.cancel().await;
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
    use cucumber_rust::Steps;

    use super::*;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps.given_regex(
            r"^Peer has Asset Definition with name (.+) and domain (.+)$",
            | mut world,
            matches,
            _step | {
                let asset_definition_name = matches[1].trim();
                let asset_definition_domain = matches[2].trim();
                    let _ = world
                        .client
                        .submit(
                            RegisterBox::new (
                                IdentifiableBox::AssetDefinition(
                                    AssetDefinition::new_quantity(
                                        AssetDefinitionId::new(
                                            asset_definition_name,
                                            asset_definition_domain,
                                        )
                                    )
                                    .into()
                                ),
                            )
                        )
                    .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            }
        ).given_regex(
            r"^(.+) Account in domain (.+) has (\d+) amount of Asset with definition (.+) in domain (.+)$",
            | mut world,
            matches,
            _step | {
                let account_name = matches[1].trim();
                let account_domain = matches[2].trim();
                let asset_quantity: u32 = matches[3].trim().parse().expect("Failed to parse Assets Quantity.");
                let asset_definition_name = matches[4].trim();
                let asset_definition_domain = matches[5].trim();
                let _ = world
                    .client
                    .submit(
                        MintBox::new(
                            Value::U32(asset_quantity),
                            IdBox::AssetId(AssetId::new(
                                AssetDefinitionId::new(
                                    asset_definition_name,
                                    asset_definition_domain,
                                ),
                                AccountId::new(account_name, account_domain)),
                            )
                        )
                    )
                    .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            }
        ).then_regex(
            r"^Peer has Asset with definition (.+) in domain (.+) and under account (.+) in domain (.+)$",
            | mut world,
            matches,
            _step | {
                let asset_definition_name = matches[1].trim();
                let asset_definition_domain = matches[2].trim();
                let account_name = matches[3].trim();
                let account_domain = matches[4].trim();
                let request = client::asset::by_account_id_and_definition_id(
                    AccountId::new(account_name, account_domain),
                    AssetDefinitionId::new(asset_definition_name, asset_definition_domain),
                );
                let query_result =
                    world.client.request(&request)
                    .expect("Failed to execute request.");
                if let QueryResult(Value::Vec(assets)) = query_result {
                    assert!(!assets.is_empty());
                } else {
                    panic!("Wrong Query Result Type.");
                }
                world
            }
        ).then_regex(
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
                    AccountId::new(account_name, account_domain),
                    AssetDefinitionId::new(asset_definition_name, asset_definition_domain),
                );
                let query_result =
                    world.client.request(&request)
                    .expect("Failed to execute request.");
                if let QueryResult(Value::Vec(assets)) = query_result {
                    assert!(!assets.is_empty());
                    let mut total_quantity = 0;
                    assets.iter().for_each(|asset| {
                        if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                            asset
                        {
                            if let AssetValue::Quantity(quantity) = *asset.value.read() {
                                total_quantity += quantity;
                            }
                        }
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
    use cucumber_rust::Steps;

    use super::*;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps
            .given_regex(
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
                    let register_account = RegisterBox::new(
                         IdentifiableBox::Account(Account::new(AccountId::new(account_name, domain_name)).into()),
                    );
                    let _ = world.client.submit(register_account)
                        .expect("Failed to register an account.");
                    thread::sleep(Duration::from_millis(world.block_build_time * 2));
                    world
                }
        )
            .given_regex(
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
                        let _ = world.client.submit(
                            MintBox::new(
                                Value::U32(quantity),
                                IdBox::AssetId(AssetId::new(
                                    AssetDefinitionId::new(
                                        asset_definition_name,
                                        asset_definition_domain
                                    ),
                                    AccountId::new(
                                        account_name,
                                        account_domain_name
                                    ))
                                )
                            )
                        ).expect("Failed to submit Mint instruction.");
                    thread::sleep(Duration::from_millis(world.block_build_time));
                    world
                }
            )
            .then_regex(
                r"^Peer has Account with name (.+) and domain (.+)$",
                | mut world,
                matches,
                _step | {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!("Checking account with id: {}@{}", account_name, domain_name);
                    let request =
                        client::account::by_id(AccountId::new(account_name, domain_name));
                    let query_result =
                        world.client.request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                }
            );
        steps
    }
}

mod domain_steps {
    use cucumber_rust::Steps;

    use super::*;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps
            .given_regex(
                r"^Peer has Domain with name (.+)$",
                |mut world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Going to add domain with name: {}", domain_name);
                    let add_domain =
                        RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
                    let _ = world
                        .client
                        .submit(add_domain)
                        .expect("Failed to add the domain.");
                    thread::sleep(Duration::from_millis(world.block_build_time * 2));
                    world
                },
            )
            .then_regex(
                r"^Peer has Domain with name (.+)$",
                |mut world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Check domain: {}", domain_name);
                    let request = client::domain::by_name(domain_name.to_string());
                    let query_result = world
                        .client
                        .request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                },
            );
        steps
    }
}

mod query_steps {
    use cucumber_rust::Steps;

    use super::*;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps
            .when_regex(
                r"^(.+) Account from (.+) domain requests all domains$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all domains on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::domain::all();
                    let query_result = world
                        .client
                        .request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                },
            )
            .when_regex(
                r"^(.+) Account from (.+) domain requests all assets$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all assets on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::asset::all();
                    let query_result = world
                        .client
                        .request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                },
            )
            .when_regex(
                r"^(.+) Account from (.+) domain requests all accounts$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all accounts on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::account::all();
                    let query_result = world
                        .client
                        .request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                },
            )
            .when_regex(
                r"^(.+) Account from (.+) domain requests all asset definitions$",
                |mut world, matches, _step| {
                    let account_name = matches[1].trim();
                    let domain_name = matches[2].trim();
                    println!(
                        "Going to request all asset definitions on behalf of: {}@{}",
                        account_name, domain_name
                    );
                    let request = client::asset::all_definitions();
                    let query_result = world
                        .client
                        .request(&request)
                        .expect("Failed to execute request.");
                    world.result = Some(query_result);
                    world
                },
            )
            .then_regex(
                r"^QueryResult has Domain with name (.+)$",
                |world, matches, _step| {
                    let domain_name = matches[1].trim();
                    println!("Check that result has {} domain in it.", domain_name);
                    if let Some(query_result) = &world.result {
                        if let QueryResult(Value::Vec(domains)) = query_result {
                            assert!(domains.contains(&Domain::new(domain_name).into()));
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex(
                r"^QueryResult has Account with name (.+)$",
                |world, matches, _step| {
                    let account_name = matches[1].trim();
                    println!("Check that result has {} account in it.", account_name);
                    if let Some(query_result) = &world.result {
                        if let QueryResult(Value::Vec(accounts)) = query_result {
                            assert_ne!(
                                accounts
                                    .iter()
                                    .filter(|account| {
                                        if let Value::Identifiable(IdentifiableBox::Account(
                                            account,
                                        )) = account
                                        {
                                            account.id.name == account_name
                                        } else {
                                            false
                                        }
                                    })
                                    .count(),
                                0
                            );
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex(
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
                        if let QueryResult(Value::Vec(assets_definitions)) = query_result {
                            assert_ne!(
                                assets_definitions
                                    .iter()
                                    .filter(|asset_definition| {
                                        if let Value::Identifiable(
                                            IdentifiableBox::AssetDefinition(asset_definition),
                                        ) = asset_definition
                                        {
                                            asset_definition.id
                                                == AssetDefinitionId::new(
                                                    asset_definition_name,
                                                    asset_definition_domain,
                                                )
                                        } else {
                                            false
                                        }
                                    })
                                    .count(),
                                0
                            );
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    } else {
                        panic!("Empty Query Result.");
                    }
                    world
                },
            )
            .then_regex(
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
                        if let QueryResult(Value::Vec(assets)) = query_result {
                            assert_ne!(
                                assets
                                    .iter()
                                    .filter(|asset| {
                                        if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                                            asset
                                        {
                                            asset.id.definition_id
                                                == AssetDefinitionId::new(
                                                    asset_definition_name,
                                                    asset_definition_domain,
                                                )
                                        } else {
                                            false
                                        }
                                    })
                                    .count(),
                                0
                            );
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
    use cucumber_rust::Steps;

    use super::*;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut steps = Steps::<IrohaWorld>::new();
        let _ = steps.when_regex(
            r"(.+) Account from (.+) domain registers new Trusted Peer with URL (.+) and Public Key (.+)$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let trusted_peer_url = matches[3].trim();
                let trusted_peer_public_key = matches[4].trim();
                let public_key: PublicKey = serde_json::from_value(serde_json::json!(trusted_peer_public_key)).expect("Failed to parse Public Key.");
                    let _ = world
                        .client
                        .submit(
                            RegisterBox::new (
                                IdentifiableBox::Peer(Peer::new(
                                    PeerId::new(
                                        trusted_peer_url,
                                        &public_key)).into()),
                                        )
                            )
                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain sets Maximum Faulty Peers Amount to (\d+)$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let maximum_faulty_peers_amount = matches[3].parse().expect("Failed to parse MaximumFaultyPeersAmount.");
                let _ = world
                    .client
                    .submit(
                        MintBox::new (
                            Value::Parameter(Parameter::MaximumFaultyPeersAmount(maximum_faulty_peers_amount)),
                            IdBox::WorldId
                        )
                    )
                    .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
            .when_regex(
                r"(.+) Account from (.+) domain sets Commit Time to (\d+) milliseconds$",
                | mut world,
                matches,
                _step | {
                    let _account_name = matches[1].trim();
                    let _account_domain_name = matches[2].trim();
                    let commit_time_milliseconds = matches[3].parse().expect("Failed to parse CommitTime.");

                    let _ = world
                        .client
                        .submit(
                            MintBox::new (
                                Value::Parameter(Parameter::CommitTime(commit_time_milliseconds)),
                                IdBox::WorldId
                                )
                            )

                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain sets Transaction Receipt Time to (\d+) milliseconds$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let transaction_receipt_time_milliseconds = matches[3].parse().expect("Failed to parse TransactionReceiptTime.");

                    let _ = world
                        .client
                        .submit(
                            MintBox::new (
                                Value::Parameter(Parameter::TransactionReceiptTime(transaction_receipt_time_milliseconds)),
                                IdBox::WorldId
                                )
                            )

                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain sets Block Time to (\d+) milliseconds$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let block_time_milliseconds = matches[3].parse().expect("Failed to parse BlockTime.");

                    let _ = world
                        .client
                        .submit(
                            MintBox::new (
                                Value::Parameter(Parameter::BlockTime(block_time_milliseconds)),
                                IdBox::WorldId
                                )
                            )

                .expect("Failed to execute request.");
                thread::sleep(Duration::from_millis(world.block_build_time * 2));
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain requests List of Trusted Peers$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result =
                    world
                        .client
                        .request(
                            &QueryRequest::new(FindAllPeers::new().into())
                            )

                .expect("Failed to execute request.");
                world.result = Some(query_result);
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain requests Maximum Faulty Peers Amount$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result =
                    world
                        .client
                        .request(
                            &QueryRequest::new(FindAllParameters::new().into())
                            )

                .expect("Failed to execute request.");
                world.result = Some(query_result);
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain requests Commit Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result =
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )

                .expect("Failed to execute request.");
                world.result = Some(query_result);
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain requests Transaction Receipt Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result =
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )

                .expect("Failed to execute request.");
                world.result = Some(query_result);
                world
            })
        .when_regex(
            r"(.+) Account from (.+) domain requests Block Time$",
            | mut world,
            matches,
            _step | {
                let _account_name = matches[1].trim();
                let _account_domain_name = matches[2].trim();
                let query_result =
                    world
                        .client
                        .request(
                            //TODO: replace with FindParameterById or something like that.
                            &QueryRequest::new(FindAllParameters::new().into())
                            )

                .expect("Failed to execute request.");
                world.result = Some(query_result);
                world
            })
        .then_regex(
            r"QueryResult contains Trusted Peer with URL (.+) and Public Key (.+)$",
            | world,
            matches,
            _step | {
                let trusted_peer_url = matches[1].trim();
                let trusted_peer_public_key = matches[2].trim();
                let public_key: PublicKey = serde_json::from_value(serde_json::json!(trusted_peer_public_key)).expect("Failed to parse Public Key.");
                if let QueryResult(Value::Vec(peers)) = world.result.clone().expect("Result is missing.") {
                    assert!(peers.iter().any(
                        |peer_id| if let Value::Id(IdBox::PeerId(peer_id)) = peer_id {
                            peer_id.address == trusted_peer_url && peer_id.public_key == public_key
                        } else {
                            false
                        }
                    ));
                }
                world
            })
        .then_regex(
            r"QueryResult contains Parameter Maximum Faulty Peers Amount with value (\d+)$",
            | world,
            matches,
            _step | {
                let maximum_faulty_peers_amount = matches[1].parse().expect("Failed to parse MaximumFaultyPeersAmount.");
                if let QueryResult(Value::Vec(parameters)) = world.result.clone().expect("Result is missing.") {
                    assert!(parameters.iter().any(
                        |parameter| if let Value::Parameter(parameter) = parameter {
                            *parameter == Parameter::MaximumFaultyPeersAmount(maximum_faulty_peers_amount)
                        } else {
                            false
                        }
                    ));
                }
                world
            })
        .then_regex(
            r"QueryResult contains Parameter Commit Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let commit_time_milliseconds = matches[1].parse().expect("Failed to parse CommitTime.");
                if let QueryResult(Value::Vec(parameters)) = world.result.clone().expect("Result is missing.") {
                    assert!(parameters.iter().any(
                        |parameter| if let Value::Parameter(parameter) = parameter {
                            *parameter == Parameter::CommitTime(commit_time_milliseconds)
                        } else {
                            false
                        }
                    ));
                }
                world
            })
        .then_regex(
            r"QueryResult contains Parameter Transaction Receipt Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let transaction_receipt_time_milliseconds = matches[1].parse().expect("Failed to parse TransactionReceiptTime.");
                if let QueryResult(Value::Vec(parameters)) = world.result.clone().expect("Result is missing.") {
                    assert!(parameters.iter().any(
                        |parameter| if let Value::Parameter(parameter) = parameter {
                            *parameter == Parameter::TransactionReceiptTime(transaction_receipt_time_milliseconds)
                        } else {
                            false
                        }
                    ));
                }
                world
            })
        .then_regex(
            r"QueryResult contains Parameter Block Time with value (\d+)$",
            | world,
            matches,
            _step | {
                let block_time_milliseconds = matches[1].parse().expect("Failed to parse BlockTime.");
                if let QueryResult(Value::Vec(parameters)) = world.result.clone().expect("Result is missing.") {
                    assert!(parameters.iter().any(
                        |parameter| if let Value::Parameter(parameter) = parameter {
                            *parameter == Parameter::BlockTime(block_time_milliseconds)
                        } else {
                            false
                        }
                    ));
                }
                world
            });
        steps
    }
}

#[allow(clippy::future_not_send)]
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
