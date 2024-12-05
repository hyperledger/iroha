use std::{collections::BTreeMap, str::FromStr};

use iroha::{client::QueryError, data_model::prelude::*};
use iroha_data_model::query::{
    builder::SingleQueryError,
    error::{FindError, QueryExecutionFail},
};
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use serde_json::json;

#[test]
fn find_accounts_with_asset() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let key = Name::from_str("key").unwrap();
    let another_key = Name::from_str("another_key").unwrap();

    test_client
        .submit_blocking(SetKeyValue::account(
            BOB_ID.clone(),
            key.clone(),
            json!({"funny": "value"}),
        ))
        .unwrap();
    test_client
        .submit_blocking(SetKeyValue::account(
            BOB_ID.clone(),
            another_key.clone(),
            "value",
        ))
        .unwrap();

    // we have the following configuration:
    //          key                 another_key
    // ALICE    "value"             -
    // BOB      {"funny": "value"}  "value"

    // check that bulk retrieval works as expected
    let key_values = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(ALICE_ID.clone()) | account.id.eq(BOB_ID.clone()))
        .select_with(|account| (account.id, account.metadata.key(key.clone())))
        .execute_all()
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_eq!(key_values.len(), 2);
    assert_eq!(key_values[&ALICE_ID], "value".into());
    assert_eq!(key_values[&BOB_ID], json!({"funny": "value"}).into());

    // check that missing metadata key produces an error
    let alice_no_key_err = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(ALICE_ID.clone()))
        .select_with(|account| account.metadata.key(another_key.clone()))
        .execute_single()
        .unwrap_err();

    let SingleQueryError::QueryError(QueryError::Validation(ValidationFail::QueryFailed(
        QueryExecutionFail::Find(FindError::MetadataKey(returned_key)),
    ))) = alice_no_key_err
    else {
        panic!("Got unexpected query error on missing metadata key {alice_no_key_err:?}",);
    };
    assert_eq!(returned_key, another_key);

    // check single key retrieval
    let another_key_value = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(BOB_ID.clone()))
        .select_with(|account| account.metadata.key(another_key.clone()))
        .execute_single()
        .unwrap();
    assert_eq!(another_key_value, "value".into());

    // check predicates on non-existing metadata (they should just evaluate to false)
    let accounts = test_client
        .query(FindAccounts)
        .filter_with(|account| account.metadata.key(another_key.clone()).eq("value".into()))
        .select_with(|account| account.id)
        .execute_all()
        .unwrap();

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0], BOB_ID.clone());
}
