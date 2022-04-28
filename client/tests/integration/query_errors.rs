#![allow(clippy::restriction)]

use std::str::FromStr;

use iroha_client::client::{self, ClientQueryError};
use iroha_core::smartcontracts::{isi::query::Error as QueryError, FindError};
use iroha_data_model::prelude::*;

#[test]
fn when_unexisting_account_is_requested_then_certain_error_is_returned() {
    let (_rt, _peer, client) = <test_network::Peer>::start_test_with_runtime();
    // we can not wait for genesis committment

    let err = client
        .request(client::account::by_id(
            AccountId::from_str("john_doe@regalia").unwrap(),
        ))
        .expect_err("Should error");

    match err {
        ClientQueryError::Certain(QueryError::Find(err)) => match *err {
            FindError::Domain(id) => assert_eq!(id.name.as_ref(), "regalia"),
            x => panic!("FindError::Domain expected, got {:?}", x),
        },
        x => panic!("Unexpected error: {:?}", x),
    };
}
