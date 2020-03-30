use iroha::{config::Configuration, Iroha};

#[async_std::main]
async fn main() -> Result<(), String> {
    println!("Hyperledgerいろは2にようこそ！");
    Iroha::new(Configuration::from_path("config.json")?)
        .start()
        .await?;
    Ok(())
}
