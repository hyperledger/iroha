use iroha::{config::Configuration, Iroha};
use std::{thread, time::Duration};

const CONFIGURATION_PATH: &str = "config.json";

#[async_std::main]
async fn main() -> Result<(), String> {
    println!("Hyperledgerいろは2にようこそ！");
    let configuration = Configuration::from_path(CONFIGURATION_PATH)?;
    println!("Configuration: {}", configuration);
    Iroha::new(configuration).start()?;
    loop {
        thread::sleep(Duration::from_secs(10));
    }
}
