use clap::{App, Arg};
use iroha::{config::Configuration, permissions::AllowAll, Iroha};
use std::{thread, time::Duration};

const CONFIGURATION_PATH: &str = "config.json";
const TRUSTED_PEERS_PATH: &str = "trusted_peers.json";
const GENESIS: &str = "genesis";

#[async_std::main]
async fn main() -> Result<(), String> {
    println!("Hyperledgerいろは2にようこそ！");
    // TODO Add more information about iroha2
    let matches = App::new("Hyperledger/iroha 2")
        .version("0.1.0")
        .arg(
            Arg::with_name(GENESIS)
                .short("g")
                .long(GENESIS)
                .help("Sets a genesis block file path.")
                .takes_value(true)
                .required(false),
        )
        .get_matches();

    let mut configuration = Configuration::from_path(CONFIGURATION_PATH)?;
    configuration.load_trusted_peers_from_path(TRUSTED_PEERS_PATH)?;

    configuration.load_environment()?;

    let genesis_path_option = matches.value_of(GENESIS);
    if let Some(genesis_path) = genesis_path_option {
        println!("Loading genesis block from the path: {}", genesis_path);
        configuration.add_genesis_block_path(genesis_path);
    }

    Iroha::new(configuration, AllowAll.into()).start().await?;
    loop {
        thread::sleep(Duration::from_secs(10));
    }
}
