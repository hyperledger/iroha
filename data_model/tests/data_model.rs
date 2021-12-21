#![allow(clippy::too_many_lines, clippy::restriction)]

use std::{str::FromStr, thread, time::Duration};

use iroha_client::{client::Client, samples::get_client_config};
use iroha_core::{
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    prelude::*,
    samples::get_config,
};
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, TestRuntime};
use tokio::runtime::Runtime;

#[test]
fn find_rate_and_make_exchange_isi_should_be_valid() {
    let _instruction = Pair::new(
        TransferBox::new(
            IdBox::AssetId(AssetId::test("btc", "crypto", "seller", "company")),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::test(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ))
                .into(),
            ),
            IdBox::AssetId(AssetId::test("btc", "crypto", "buyer", "company")),
        ),
        TransferBox::new(
            IdBox::AssetId(AssetId::test("btc", "crypto", "buyer", "company")),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::test(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ))
                .into(),
            ),
            IdBox::AssetId(AssetId::test("btc", "crypto", "seller", "company")),
        ),
    );
}

#[test]
fn find_rate_and_check_it_greater_than_value_isi_should_be_valid() {
    let _instruction = IfInstruction::new(
        Not::new(Greater::new(
            QueryBox::from(FindAssetQuantityById::new(AssetId::test(
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
                QueryBox::from(FindAssetQuantityById::new(AssetId::test(
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
    let _instruction = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
}

#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let kp = KeyPair {
        public_key: PublicKey::from_str(
            r#"ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"#,
        )
        .unwrap(),
        private_key: PrivateKey {
            digest_function: "ed25519".to_string(),
            payload: hex_literal::hex!("9AC47ABF 59B356E0 BD7DCBBB B4DEC080 E302156A 48CA907E 47CB6AEA 1D32719E 7233BFC8 9DCBD68C 19FDE6CE 61582252 98EC1131 B6A130D1 AEB454C1 AB5183C0")
				.into(),
        },
    };
    let mut peer = <TestPeer>::new().expect("Failed to create peer");
    let configuration = get_config(std::iter::once(peer.id.clone()).collect(), Some(kp.clone()));
    let pipeline_time = Duration::from_millis(configuration.sumeragi.pipeline_time_ms());

    // Given
    let genesis = GenesisNetwork::from_configuration(
        true,
        RawGenesisBlock::new("alice", "wonderland", &kp.public_key)
            .expect("Valid names never fail to parse"),
        &configuration.genesis,
        configuration.sumeragi.max_instruction_number,
    )
    .unwrap();
    let rt = Runtime::test();
    let mut client_configuration = get_client_config(&configuration.sumeragi.key_pair);

    rt.block_on(peer.start_with_config(genesis, configuration));
    thread::sleep(pipeline_time);

    client_configuration.torii_api_url = "http://".to_owned() + &peer.api_address;
    let mut iroha_client = Client::new(&client_configuration);
    iroha_client
        .submit_all(vec![
            RegisterBox::new(IdentifiableBox::Domain(Domain::test("exchange").into())).into(),
            RegisterBox::new(IdentifiableBox::Domain(Domain::test("company").into())).into(),
            RegisterBox::new(IdentifiableBox::Domain(Domain::test("crypto").into())).into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::test("seller", "company")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::test("buyer", "company")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::test("dex", "exchange")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::test("btc", "crypto")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::test("eth", "crypto")).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::test("btc2eth_rate", "exchange"))
                    .into(),
            ))
            .into(),
            MintBox::new(
                Value::U32(200),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::test("eth", "crypto"),
                    AccountId::test("buyer", "company"),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::test("btc", "crypto"),
                    AccountId::test("seller", "company"),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::test("btc2eth_rate", "exchange"),
                    AccountId::test("dex", "exchange"),
                )),
            )
            .into(),
            Pair::new(
                TransferBox::new(
                    IdBox::AssetId(AssetId::test("btc", "crypto", "seller", "company")),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::test(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ))
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::test("btc", "crypto", "buyer", "company")),
                ),
                TransferBox::new(
                    IdBox::AssetId(AssetId::test("eth", "crypto", "buyer", "company")),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::test(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ))
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::test("eth", "crypto", "seller", "company")),
                ),
            )
            .into(),
        ])
        .expect("Failed to execute Iroha Special Instruction.");
    thread::sleep(pipeline_time * 3);
    let expected_seller_eth = 20;
    let expected_buyer_eth = 180;
    let expected_buyer_btc = 20;

    let eth_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::test(
            "eth", "crypto", "seller", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_seller_eth, eth_quantity);

    // For the btc amount we expect an error, as zero assets are purged from accounts
    iroha_client
        .request(FindAssetQuantityById::new(AssetId::test(
            "btc", "crypto", "seller", "company",
        )))
        .expect_err("Failed to execute Iroha Query");

    let buyer_eth_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::test(
            "eth", "crypto", "buyer", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_eth, buyer_eth_quantity);

    let buyer_btc_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::test(
            "btc", "crypto", "buyer", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_btc, buyer_btc_quantity);
}
