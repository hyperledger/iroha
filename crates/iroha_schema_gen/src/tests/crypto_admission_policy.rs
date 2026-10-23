//! The sole ordinary crypto parameter is an explicit public schema root.

use super::{IntoSchema, find_missing_schema_references};
use iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1;

#[test]
fn crypto_admission_policy_export_contains_the_exact_single_set_schema() {
    let expected = CryptoAdmissionPolicyV1::schema();
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "{}",
            descriptor.type_name
        );
    }
    assert!(find_missing_schema_references(&expected).is_empty());
    let Some(iroha_schema::Metadata::Struct(fields)) = expected.get::<CryptoAdmissionPolicyV1>()
    else {
        panic!("ordinary crypto policy must be one named record");
    };
    assert_eq!(fields.declarations.len(), 1);
    assert_eq!(fields.declarations[0].name, "allowed_algorithms");
}
