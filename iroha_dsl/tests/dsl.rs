use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_dsl::prelude::*;
use std::{thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

#[test]
fn find_rate_and_make_exchange_isi_should_be_valid() {
    let _ = Pair::new(
        TransferBox::new(
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company")),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ))
                .into(),
            ),
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company")),
        ),
        TransferBox::new(
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company")),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ))
                .into(),
            ),
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company")),
        ),
    );
}

#[test]
fn find_rate_and_check_it_greater_than_value_isi_should_be_valid() {
    let _ = IfInstruction::new(
        Not::new(Greater::new(
            QueryBox::from(FindAssetQuantityById::new(AssetId::from_names(
                "btc2eth_rate",
                "exchange",
                "dex",
                "exchange",
            ))),
            10u32,
        )),
        FailBox::new("rate is less or equal to value"),
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

    pub fn into_isi(self) -> IfInstruction {
        IfInstruction::new(
            Not::new(Greater::new(
                QueryBox::from(FindAssetQuantityById::new(AssetId::from_names(
                    &format!("{}2{}_rate", self.from_currency, self.to_currency),
                    "exchange",
                    "dex",
                    "exchange",
                ))),
                self.value,
            )),
            FailBox::new("rate is less or equal to value"),
        )
    }
}

#[test]
fn find_rate_and_check_it_greater_than_value_predefined_isi_should_be_valid() {
    let _ = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
}

#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let free_port = port_check::free_local_port().expect("Failed to allocate a free port.");
    println!("Free port: {}", free_port);
    thread::spawn(move || create_and_start_iroha(free_port));
    thread::sleep(Duration::from_millis(300));
    let mut configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    configuration.torii_api_url = format!("127.0.0.1:{}", free_port);
    let mut iroha_client = Client::new(&configuration);
    iroha_client
        .submit_all(vec![
            RegisterBox::new(IdentifiableBox::Domain(Domain::new("exchange").into())).into(),
            RegisterBox::new(IdentifiableBox::Domain(Domain::new("company").into())).into(),
            RegisterBox::new(IdentifiableBox::Domain(Domain::new("crypto").into())).into(),
            RegisterBox::new(IdentifiableBox::Account(
                Account::new(AccountId::new("seller", "company")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::Account(
                Account::new(AccountId::new("buyer", "company")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::Account(
                Account::new(AccountId::new("dex", "exchange")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new(AssetDefinitionId::new("btc", "crypto")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new(AssetDefinitionId::new("eth", "crypto")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new(AssetDefinitionId::new("btc2eth_rate", "exchange")).into(),
            ))
            .into(),
            MintBox::new(
                Value::U32(200),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("eth", "crypto"),
                    AccountId::new("buyer", "company"),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("btc", "crypto"),
                    AccountId::new("seller", "company"),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("btc2eth_rate", "exchange"),
                    AccountId::new("dex", "exchange"),
                )),
            )
            .into(),
            Pair::new(
                TransferBox::new(
                    IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company")),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::from_names(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ))
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company")),
                ),
                TransferBox::new(
                    IdBox::AssetId(AssetId::from_names("eth", "crypto", "buyer", "company")),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::from_names(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ))
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::from_names("eth", "crypto", "seller", "company")),
                ),
            )
            .into(),
        ])
        .expect("Failed to execute Iroha Special Instruction.");
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    let expected_seller_eth = 20;
    let expected_seller_btc = 0;
    let expected_buyer_eth = 180;
    let expected_buyer_btc = 20;
    if let QueryResult(Value::U32(quantity)) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("eth", "crypto", "seller", "company"))
                .into(),
        ))
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_seller_eth, quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult(Value::U32(quantity)) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("btc", "crypto", "seller", "company"))
                .into(),
        ))
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_seller_btc, quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult(Value::U32(quantity)) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("eth", "crypto", "buyer", "company"))
                .into(),
        ))
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_buyer_eth, quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
    if let QueryResult(Value::U32(quantity)) = iroha_client
        .request(&QueryRequest::new(
            FindAssetQuantityById::new(AssetId::from_names("btc", "crypto", "buyer", "company"))
                .into(),
        ))
        .expect("Failed to execute Iroha Query")
    {
        assert_eq!(expected_buyer_btc, quantity);
    } else {
        panic!("Wrong Query Result Type.");
    }
}

fn create_and_start_iroha(free_port: u16) {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.torii_configuration.torii_api_url = format!("127.0.0.1:{}", free_port);
    configuration
        .kura_configuration
        .kura_block_store_path(temp_dir.path());
    let iroha = Iroha::new(configuration, AllowAll.into());
    task::block_on(iroha.start()).expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    #[allow(clippy::empty_loop)]
    loop {}
}
