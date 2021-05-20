//! Binary to print all types to json string

#![allow(clippy::print_stdout)]

use std::collections::BTreeMap;

use iroha_data_model::prelude::*;
use iroha_data_model::query::QueryBox;
use iroha_schema::prelude::*;

macro_rules! to_json {
    ($($t:ty),* $(,)?) => {{
        let mut out = BTreeMap::new();
        $(<$t as IntoSchema>::schema(&mut out);)*
        serde_json::to_string_pretty(&out).unwrap()
    }};
}

fn main() {
    println!(
        "{}",
        to_json!(
            Account,
            AccountId,
            Value,
            Instruction,
            Domain,
            QueryBox,
            VersionedEvent,
            VersionedTransaction,
            VersionedQueryResult,
        )
    )
}
