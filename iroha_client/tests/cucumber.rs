use cucumber::{cucumber, World};
use futures::executor;
use iroha::{config::Configuration, isi, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use std::{default::Default, thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/single_config.json";

pub struct IrohaWorld {
    client: Client,
    peer_id: PeerId,
    block_build_time: u64,
}

impl World for IrohaWorld {}

impl Default for IrohaWorld {
    fn default() -> Self {
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
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
        }
    }
}

mod iroha_steps {
    use super::*;
    use cucumber::{Steps, StepsBuilder};

    pub fn steps() -> Steps<IrohaWorld> {
        let mut builder = StepsBuilder::<IrohaWorld>::new();
        builder.given("Iroha Peer is up", |world, _step| {
            thread::spawn(|| {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
                configuration
                    .kura_configuration
                    .kura_block_store_path(temp_dir.path());
                let iroha = Iroha::new(configuration.clone());
                executor::block_on(async { iroha.start().await }).expect("Failed to start Iroha.");
            });
            thread::sleep(Duration::from_millis(world.block_build_time));
        });
        builder.build()
    }
}

mod asset_steps {
    use super::*;
    use cucumber::{typed_regex, Steps, StepsBuilder};

    pub fn steps() -> Steps<IrohaWorld> {
        let mut builder = StepsBuilder::<IrohaWorld>::new();
        builder.then_regex(
            r"^Iroha has Asset with definition (.+) in domain (.+) and under account (.+) in domain (.+)$",
            typed_regex!(
                IrohaWorld,
                (String, String, String, String) | world,
                asset_definition_name,
                asset_definition_domain,
                account_name,
                account_domain,
                _step | {
                    let request = client::assets::by_account_id_and_definition_id(
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
                }
            ),
        );
        builder.build()
    }
}

mod account_steps {
    use super::*;
    use cucumber::{typed_regex, Steps, StepsBuilder};

    pub fn steps() -> Steps<IrohaWorld> {
        let mut builder = StepsBuilder::<IrohaWorld>::new();
        builder
            .given_regex(
                r"^Iroha has Account with name (.+) and domain (.+)$",
                typed_regex!(
                    IrohaWorld,
                    (String, String) | world,
                    account_name,
                    domain_name,
                    _step | {
                        println!(
                            "Going to register an account with id: {}@{}",
                            account_name, domain_name
                        );
                        let register_account = isi::Register::<Domain, Account> {
                            object: Account::new(&account_name, &domain_name),
                            destination_id: domain_name,
                        };
                        executor::block_on(async {
                            world.client.submit(register_account.into()).await
                        })
                        .expect("Failed to register an account.");
                        thread::sleep(Duration::from_millis(world.block_build_time));
                    }
                ),
            )
            .then_regex(
                r"^Iroha has Account with name (.+) and domain (.+)$",
                typed_regex!(
                    super::IrohaWorld,
                    (String, String) | world,
                    account_name,
                    domain_name,
                    _step | {
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
                    }
                ),
            );
        builder.build()
    }
}

mod domain_steps {
    use super::*;
    use cucumber::{typed_regex, Steps, StepsBuilder};

    pub fn steps() -> Steps<IrohaWorld> {
        let mut builder = StepsBuilder::<IrohaWorld>::new();
        builder
            .given_regex(
                r"^Iroha has Domain with name (.+)$",
                typed_regex!(
                    IrohaWorld,
                    (String) | world,
                    domain_name,
                    _step | {
                        println!("Going to add domain with name: {}", domain_name);
                        let add_domain = isi::Add::<Peer, Domain> {
                            object: Domain::new(domain_name),
                            destination_id: world.peer_id.clone(),
                        };
                        executor::block_on(async { world.client.submit(add_domain.into()).await })
                            .expect("Failed to add the domain.");
                        thread::sleep(Duration::from_millis(world.block_build_time));
                    }
                ),
            )
            .then_regex(
                r"^Iroha has Domain with name (.+)$",
                typed_regex!(
                    IrohaWorld,
                    (String) | world,
                    domain_name,
                    _step | {
                        println!("Check domain: {}", domain_name);
                        let request = client::domain::by_name(domain_name);
                        let query_result =
                            executor::block_on(async { world.client.request(&request).await })
                                .expect("Failed to execute request.");
                        if let QueryResult::GetDomain(_) = query_result {
                            println!("Domain found.");
                        } else {
                            panic!("Wrong Query Result Type.");
                        }
                    }
                ),
            );
        builder.build()
    }
}

mod bridge_steps {
    use super::*;
    use cucumber::{typed_regex, Steps, StepsBuilder};
    use iroha::bridge;

    pub fn steps() -> Steps<IrohaWorld> {
        let mut builder = StepsBuilder::<IrohaWorld>::new();
        builder.given("Iroha Bridge module enabled", |world, _step| {
            let instructions = vec![
                isi::Add::<Peer, Domain> {
                    object: Domain::new("bridge".to_string()),
                    destination_id: world.peer_id.clone(),
                }
                .into(),
                isi::Register::<Domain, AssetDefinition> {
                    object: AssetDefinition::new(AssetDefinitionId::new("bridges_asset", "bridge")),
                    destination_id: "bridge".to_string(),
                }
                .into(),
                isi::Register::<Domain, AssetDefinition> {
                    object: AssetDefinition::new(AssetDefinitionId::new("bridge_asset", "bridge")),
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
            thread::sleep(Duration::from_millis(world.block_build_time));
        });
        builder.when_regex(
            r"^(.+) Account from (.+) domain registers Bridge with name (.+)$",
            typed_regex!(
                IrohaWorld,
                (String, String, String) | world,
                bridge_owner_account_name,
                bridge_owner_domain,
                bridge_name,
                _step | {
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
                    thread::sleep(Duration::from_millis(world.block_build_time));
                }
            ),
        );
        builder.then_regex(
            r"^Iroha has Bridge Definition with name (.+) and kind iclaim and owner (.+)$",
            typed_regex!(
                IrohaWorld,
                (String, String) | _world,
                bridge_definition_name,
                bridge_owner,
                _step | {
                    println!(
                        "Check bridge definition with name {} and owner {}",
                        bridge_definition_name, bridge_owner
                    );
                }
            ),
        );
        builder.build()
    }
}

cucumber! {
    features: "../docs/source/features",
    world: ::IrohaWorld,
    steps: &[
        iroha_steps::steps,
        asset_steps::steps,
        account_steps::steps,
        domain_steps::steps,
        bridge_steps::steps,
    ]
}
