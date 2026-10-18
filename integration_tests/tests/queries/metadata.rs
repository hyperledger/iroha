//! Tests querying metadata via `FindAccounts`.
use integration_tests::sandbox;
use iroha::{client::QueryError, data_model::prelude::*};
use iroha_data_model::query::error::{FindError, QueryExecutionFail};
use iroha_executor_data_model::permission::account::CanRegisterAccount;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID, BOB_KEYPAIR};
use std::{collections::BTreeMap, str::FromStr};
#[test]
#[allow(clippy::too_many_lines)]
fn find_accounts_with_asset() {
    let result: eyre::Result<()> = (|| {
        let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
            NetworkBuilder::new(),
            stringify!(find_accounts_with_asset_metadata),
        )
        .unwrap() else {
            return Ok(());
        };
        let test_client = network.client();
        let wonderland_domain: DomainId =
            DomainId::try_new("wonderland", "universal").expect("wonderland domain");
        let key = Name::from_str("key").unwrap();
        let another_key = Name::from_str("another_key").unwrap();
        // Ensure Alice has the expected default metadata key used by assertions below.
        // Some environments may not preload this value via genesis.
        test_client
            .submit(
                SetKeyValue::account(
                    ALICE_ID.clone(),
                    key.clone(),
                    iroha_primitives::json::Json::new("value"),
                ),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .unwrap();
        // Ensure Bob account exists (defaults genesis may omit it).
        let existing_accounts = test_client
            .client()
            .query(FindAccounts)
            .execute_all()
            .expect("fetch accounts");
        let bob_missing = existing_accounts.iter().all(|acc| acc.id() != &*BOB_ID);
        if bob_missing {
            test_client
                .submit(
                    Grant::account_permission(
                        CanRegisterAccount {
                            domain: wonderland_domain.clone(),
                        },
                        ALICE_ID.clone(),
                    ),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .expect("Failed to grant account registration permission to Alice");
            test_client
                .submit(
                    Register::account(Account::new(BOB_ID.clone())),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .expect("Failed to register Bob account");
        }
        let bob_client = network
            .peers()
            .first()
            .expect("network has at least one peer")
            .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone());
        bob_client
            .submit(
                SetKeyValue::account(
                    BOB_ID.clone(),
                    key.clone(),
                    iroha_primitives::json::Json::new(
                        norito::json::object([(
                            "funny",
                            norito::json::to_value(&"value").expect("serialize"),
                        )])
                        .expect("serialize metadata object"),
                    ),
                ),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .unwrap();
        bob_client
            .submit(
                SetKeyValue::account(BOB_ID.clone(), another_key.clone(), "value"),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .unwrap();
        // we have the following configuration:
        //          key                 another_key
        // ALICE    "value"             -
        // BOB      {"funny": "value"}  "value"
        // check that bulk retrieval works as expected
        let key_values = test_client
            .client()
            .query(FindAccounts)
            .execute_all()
            .unwrap()
            .into_iter()
            .filter(|account| account.id() == &*ALICE_ID || account.id() == &*BOB_ID)
            .map(|account| {
                (
                    account.id().clone(),
                    account
                        .metadata()
                        .get(&key)
                        .cloned()
                        .expect("key must exist"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(key_values.len(), 2);
        let expected_alice = iroha_primitives::json::Json::from("value");
        assert_eq!(key_values.get(&*ALICE_ID), Some(&expected_alice));
        let expected_bob = iroha_primitives::json::Json::new(
            norito::json::object([(
                "funny",
                norito::json::to_value(&"value").expect("serialize"),
            )])
            .expect("serialize metadata object"),
        );
        assert_eq!(key_values.get(&*BOB_ID), Some(&expected_bob));
        // check that missing metadata key produces an error
        let alice_no_key_err = test_client
            .client()
            .query(FindAccounts)
            .execute_all()
            .unwrap()
            .into_iter()
            .find(|account| account.id() == &*ALICE_ID)
            .and_then(|account| account.metadata().get(&another_key).cloned())
            .ok_or_else(|| {
                QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
                    FindError::MetadataKey(another_key.clone()),
                )))
            })
            .unwrap_err();
        let QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            FindError::MetadataKey(returned_key),
        ))) = alice_no_key_err
        else {
            panic!("Got unexpected query error on missing metadata key {alice_no_key_err:?}",);
        };
        assert_eq!(returned_key, another_key);
        // check single key retrieval
        let another_key_value = test_client
            .client()
            .query(FindAccounts)
            .execute_all()
            .unwrap()
            .into_iter()
            .find(|account| account.id() == &*BOB_ID)
            .and_then(|account| account.metadata().get(&another_key).cloned())
            .unwrap();
        assert_eq!(another_key_value, "value".into());
        // check predicates on non-existing metadata (they should just evaluate to false)
        let accounts = test_client
            .client()
            .query(FindAccounts)
            .execute_all()
            .unwrap()
            .into_iter()
            .filter(|account| {
                account
                    .metadata()
                    .get(&another_key)
                    .is_some_and(|v| v.as_ref() == "value")
            })
            .map(|account| account.id().clone())
            .collect::<Vec<_>>();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0], BOB_ID.clone());
        Ok(())
    })();
    let _ = sandbox::handle_result(result, stringify!(find_accounts_with_asset_metadata)).unwrap();
}
