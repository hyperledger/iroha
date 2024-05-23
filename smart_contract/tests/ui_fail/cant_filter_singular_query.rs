use iroha_smart_contract::{
    data_model::query::predicate::{string::StringPredicate, value::QueryOutputPredicate},
    prelude::*,
};

fn main() {
    FindPermissionSchema
        .filter(QueryOutputPredicate::Identifiable(
            StringPredicate::starts_with("xor_"),
        ))
        .execute()
}
