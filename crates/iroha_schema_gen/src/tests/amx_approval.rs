//! The private-root approval endpoint exposes exact native request and proof schemas.

use super::{IntoSchema, find_missing_schema_references};
use iroha_data_model::{
    sumeragi_amx::{AmxDebitApprovalProofV1, AmxDebitApprovalV1},
    sumeragi_finality::WorldStateSnapshotV1,
};

#[test]
fn amx_approval_export_contains_both_native_frame_schema_closures() {
    let mut expected = AmxDebitApprovalV1::schema();
    AmxDebitApprovalProofV1::update_schema_map(&mut expected);
    iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1::update_schema_map(
        &mut expected,
    );
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted AMX approval descriptor: {}",
            descriptor.type_name,
        );
    }
    assert!(expected.contains_key::<AmxDebitApprovalV1>());
    assert!(expected.contains_key::<AmxDebitApprovalProofV1>());
    assert!(expected.contains_key::<WorldStateSnapshotV1>());
    assert!(find_missing_schema_references(&expected).is_empty());
}
