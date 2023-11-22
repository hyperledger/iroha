use serde::{Serialize, Deserialize};

use iroha_data_model::prelude::*;

#[derive(Serialize, Deserialize)]
struct MyTestStructEvsTo {}

fn main() {
    // Generic type does not matter in this context
    let evals_to = EvaluatesTo::<Value>::new_unchecked(
        Value::Bool(true),
    );

    let serialized = serde_json::to_string(&evals_to).unwrap();

    let deserialized: Result<EvaluatesTo<MyTestStructEvsTo>, _> = serde_json::from_str(&serialized);
}
