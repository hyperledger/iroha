use std::str::FromStr as _;

use iroha_data_model::{prelude::*, ParseError};

#[test]
fn transfer_isi_should_be_valid() {
    let _instruction = TransferExpr::new(
        IdBox::AssetId("btc##seller@crypto".parse().expect("Valid")),
        12_u32,
        IdBox::AccountId("buyer@crypto".parse().expect("Valid")),
    );
}

#[test]
fn find_quantity_and_check_it_greater_than_value_isi_should_be_valid() {
    let asset_id: AssetId = "rose##alice@wonderland".parse().expect("Valid");
    let find_asset = QueryBox::from(FindAssetQuantityById::new(asset_id));

    let _instruction = ConditionalExpr::new(
        Not::new(Greater::new(EvaluatesTo::new_unchecked(find_asset), 10_u32)),
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
        Self {
            from_currency: from_currency.to_string(),
            to_currency: to_currency.to_string(),
            value,
        }
    }

    pub fn into_isi(self) -> ConditionalExpr {
        ConditionalExpr::new(
            Not::new(Greater::new(
                EvaluatesTo::new_unchecked(QueryBox::from(FindAssetQuantityById::new(
                    AssetId::new(
                        format!("{}2{}_rate#exchange", self.from_currency, self.to_currency)
                            .parse()
                            .expect("Valid"),
                        AccountId::from_str("dex@exchange").expect("Valid"),
                    ),
                ))),
                self.value,
            )),
            Fail::new("rate is less or equal to value"),
        )
    }
}

#[test]
fn find_rate_and_check_it_greater_than_value_predefined_isi_should_be_valid() {
    let _instruction = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
}

#[test]
fn account_id_parsing() -> Result<(), ParseError> {
    // `AccountId` should have format `name@domain_name`
    let account_normal: AccountId = "test@hello".parse()?;
    assert_eq!(account_normal.name().as_ref(), "test");
    assert_eq!(account_normal.domain_id().name().as_ref(), "hello");

    let account_empty: Result<AccountId, _> = "@hello".parse();
    assert!(account_empty.is_err());

    let account_invalid: Result<AccountId, _> = "@".parse();
    assert!(account_invalid.is_err());
    Ok(())
}
