use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_dsl::prelude::*;
use std::{thread, time::Duration};
use tempfile::TempDir;
const CONFIGURATION_PATH: &str = "tests/test_config.json";

#[test]
fn find_rate_and_make_exchange_isi_should_be_valid() {
    let _ = Pair::new(
        Transfer::<Asset, _, Asset>::new(
            AssetId::from_names("btc", "crypto", "seller", "company"),
            FindAssetQuantityById::new(AssetId::from_names(
                "btc2eth_rate",
                "exchange",
                "dex",
                "exchange",
            )),
            AssetId::from_names("btc", "crypto", "buyer", "company"),
        ),
        Transfer::<Asset, _, Asset>::new(
            AssetId::from_names("eth", "crypto", "buyer", "company"),
            FindAssetQuantityById::new(AssetId::from_names(
                "btc2eth_rate",
                "exchange",
                "dex",
                "exchange",
            )),
            AssetId::from_names("eth", "crypto", "seller", "company"),
        ),
    );
}

#[test]
fn find_rate_and_check_it_greater_than_value_isi_should_be_valid() {
    let _ = If::new(
        Not::new(Greater::new(
            FindAssetQuantityById::new(AssetId::from_names(
                "btc2eth_rate",
                "exchange",
                "dex",
                "exchange",
            )),
            10,
        )),
        Fail::new("rate is less or equal to value"),
    );
}

struct FindRateAndCheckItGreaterThanValue {
    from_currency: String,
    to_currency: String,
    value: u32,
}

impl FindRateAndCheckItGreaterThanValue {
    pub fn new(from_currency: &str, to_currency: &str, value: u32) -> Self {
        FindRateAndCheckItGreaterThanValue {
            from_currency: from_currency.to_string(),
            to_currency: to_currency.to_string(),
            value,
        }
    }

    pub fn into_isi(self) -> If {
        If::new(
            Not::new(Greater::new(
                FindAssetQuantityById::new(AssetId::from_names(
                    &format!("{}2{}_rate", self.from_currency, self.to_currency),
                    "exchange",
                    "dex",
                    "exchange",
                )),
                self.value,
            )),
            Fail::new("rate is less or equal to value"),
        )
    }
}

#[test]
fn find_rate_and_check_it_greater_than_value_predefined_isi_should_be_valid() {
    let _ = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
}

#[async_std::test]
async fn find_rate_and_make_exchange_isi_should_succeed() {
    let free_port = port_check::free_local_port().expect("Failed to allocate a free port.");
    println!("Free port: {}", free_port);
    thread::spawn(move || create_and_start_iroha(free_port));
    task::sleep(Duration::from_millis(300)).await;
    let mut configuration =
        ClientConfiguration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.torii_url = format!("127.0.0.1:{}", free_port);
    let mut iroha_client = Client::new(&configuration);
    iroha_client
        .submit_all(vec![
            Register::<Peer, Domain>::new(
                Domain::new("exchange"),
                PeerId::new(&configuration.torii_url, &configuration.public_key),
            )
            .into(),
            Register::<Peer, Domain>::new(
                Domain::new("company"),
                PeerId::new(&configuration.torii_url, &configuration.public_key),
            )
            .into(),
            Register::<Peer, Domain>::new(
                Domain::new("crypto"),
                PeerId::new(&configuration.torii_url, &configuration.public_key),
            )
            .into(),
            Register::<Domain, Account>::new(
                Account::new(AccountId::new("seller", "company")),
                Name::from("company"),
            )
            .into(),
            Register::<Domain, Account>::new(
                Account::new(AccountId::new("buyer", "company")),
                Name::from("company"),
            )
            .into(),
            Register::<Domain, Account>::new(
                Account::new(AccountId::new("dex", "exchange")),
                Name::from("exchange"),
            )
            .into(),
            Register::<Domain, AssetDefinition>::new(
                AssetDefinition::new(AssetDefinitionId::new("btc", "crypto")),
                Name::from("crypto"),
            )
            .into(),
            Register::<Domain, AssetDefinition>::new(
                AssetDefinition::new(AssetDefinitionId::new("eth", "crypto")),
                Name::from("crypto"),
            )
            .into(),
            Register::<Domain, AssetDefinition>::new(
                AssetDefinition::new(AssetDefinitionId::new("btc2eth_rate", "exchange")),
                Name::from("exchange"),
            )
            .into(),
            Mint::<Asset, u32>::new(
                200,
                AssetId::new(
                    AssetDefinitionId::new("eth", "crypto"),
                    AccountId::new("buyer", "company"),
                ),
            )
            .into(),
            Mint::<Asset, u32>::new(
                20,
                AssetId::new(
                    AssetDefinitionId::new("btc", "crypto"),
                    AccountId::new("seller", "company"),
                ),
            )
            .into(),
            Mint::<Asset, u32>::new(
                20,
                AssetId::new(
                    AssetDefinitionId::new("btc2eth_rate", "exchange"),
                    AccountId::new("dex", "exchange"),
                ),
            )
            .into(),
            Pair::new(
                Transfer::<Asset, _, Asset>::new(
                    AssetId::from_names("btc", "crypto", "seller", "company"),
                    FindAssetQuantityById::new(AssetId::from_names(
                        "btc2eth_rate",
                        "exchange",
                        "dex",
                        "exchange",
                    )),
                    AssetId::from_names("btc", "crypto", "buyer", "company"),
                ),
                Transfer::<Asset, _, Asset>::new(
                    AssetId::from_names("eth", "crypto", "buyer", "company"),
                    FindAssetQuantityById::new(AssetId::from_names(
                        "btc2eth_rate",
                        "exchange",
                        "dex",
                        "exchange",
                    )),
                    AssetId::from_names("eth", "crypto", "seller", "company"),
                ),
            )
            .into(),
        ])
        .await
        .expect("Failed to execute Iroha Special Instruction.");
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    task::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ))
    .await;
    let expected_seller_eth = 20;
    let expected_seller_btc = 0;
    let expected_buyer_eth = 180;
    let expected_buyer_btc = 20;
    if let QueryResult::FindAssetQuantityById(result) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("eth", "crypto", "seller", "company"))
                .into(),
        ))
        .await
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_seller_eth, result.quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult::FindAssetQuantityById(result) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("btc", "crypto", "seller", "company"))
                .into(),
        ))
        .await
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_seller_btc, result.quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult::FindAssetQuantityById(result) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("eth", "crypto", "buyer", "company"))
                .into(),
        ))
        .await
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_buyer_eth, result.quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult::FindAssetQuantityById(result) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("btc", "crypto", "buyer", "company"))
                .into(),
        ))
        .await
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_buyer_btc, result.quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
}

fn create_and_start_iroha(free_port: u16) {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.torii_configuration.torii_url = format!("127.0.0.1:{}", free_port);
    configuration
        .kura_configuration
        .kura_block_store_path(temp_dir.path());
    let iroha = Iroha::new(configuration);
    task::block_on(iroha.start()).expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    #[allow(clippy::empty_loop)]
    loop {}
}
