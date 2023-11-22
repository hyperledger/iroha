use iroha_data_model::prelude::*;

fn main() {
    let evals_to_val = EvaluatesTo::<Value>::new_evaluates_to_value(
        Value::Bool(true),
    );

    let serialized = serde_json::to_string(&evals_to_val).unwrap();

    let deserialized: EvaluatesTo<Value> = serde_json::from_str(&serialized).unwrap();

    assert_eq!(evals_to_val, deserialized, "Incorrect deserialize");
}
