use iroha_data_model::{prelude::*, ParseError};

#[test]
fn transfer_isi_should_be_valid() {
    let _instruction = Transfer::asset_numeric(
        "btc##seller@crypto".parse().expect("Valid"),
        Numeric::new(12, 0),
        "buyer@crypto".parse().expect("Valid"),
    );
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
