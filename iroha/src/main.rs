use iroha::{config::Configuration, Iroha};

const CONFIGURATION_PATH: &str = "config.json";

#[async_std::main]
async fn main() -> Result<(), String> {
    println!("Hyperledgerいろは2にようこそ！");
    Iroha::new(Configuration::from_path(CONFIGURATION_PATH)?).start()?;
    Ok(())
}
