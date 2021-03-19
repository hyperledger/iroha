#![allow(clippy::too_many_lines)]

use iroha::config::Configuration;
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_dsl::prelude::*;
use std::{thread, time::Duration};
use test_network::Peer as TestPeer;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";

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
            10_u32,
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
        Self {
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
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration
        .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
        .expect("Failed to load trusted peers.");
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
    let peer = TestPeer::new().expect("Failed to create peer");
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();

    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    let _ = peer.start_with_config(configuration);
    thread::sleep(pipeline_time);

    let mut configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    configuration.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&configuration);
    let _ = iroha_client
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
    thread::sleep(pipeline_time * 3);
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
