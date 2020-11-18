use iroha::{config::Configuration, permissions::AllowAll, Iroha};
use std::{thread, time::Duration};

const CONFIGURATION_PATH: &str = "config.json";

#[async_std::main]
async fn main() -> Result<(), String> {
    println!("Hyperledgerいろは2にようこそ！");
    let mut configuration = Configuration::from_path(CONFIGURATION_PATH)?;
    configuration.load_environment()?;
    Iroha::new(configuration, AllowAll.into()).start().await?;
    loop {
        thread::sleep(Duration::from_secs(10));
    }
}
