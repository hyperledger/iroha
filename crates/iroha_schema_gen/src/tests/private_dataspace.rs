//! Exact private-root registration and compact-anchor schemas are public protocol roots.
use super::{IntoSchema, find_missing_schema_references};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    private_dataspace::{
        PrivateDataspaceAnchor, PrivateDataspaceAnchorState, PrivateDataspaceCursor,
        PrivateDataspaceRegistration,
    },
};

#[test]
fn private_dataspace_export_contains_complete_registered_schema_closure() {
    let mut expected = PrivateDataspaceAnchorState::schema();
    iroha_data_model::block::consensus::RootFeePolicy::update_schema_map(&mut expected);
    PrivateDataspaceAnchor::update_schema_map(&mut expected);
    iroha_data_model::private_dataspace::PrivateDataspaceRegistry::update_schema_map(&mut expected);
    iroha_data_model::private_dataspace::PrivateDataspaceAdmissionPolicy::update_schema_map(
        &mut expected,
    );
    iroha_data_model::isi::private_dataspace::RegisterPrivateDataspace::update_schema_map(
        &mut expected,
    );
    iroha_data_model::isi::private_dataspace::AnchorPrivateDataspace::update_schema_map(
        &mut expected,
    );
    iroha_data_model::private_dataspace::PrivateDataspaceRecordProof::update_schema_map(
        &mut expected,
    );
    iroha_data_model::smart_contract::ContractArtifactId::update_schema_map(&mut expected);
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted private-root descriptor: {}",
            descriptor.type_name,
        );
    }
    assert!(expected.contains_key::<SumeragiRootScope>());
    assert!(expected.contains_key::<PrivateDataspaceRegistration>());
    assert!(expected.contains_key::<PrivateDataspaceCursor>());
    assert!(find_missing_schema_references(&expected).is_empty());
}

#[test]
fn provider_discovery_export_contains_the_exact_current_state_schema_closure() {
    use iroha_data_model::sorafs::provider_admission::{
        discovery::ProviderDiscoveryProofV1, history::AdmissionHistoryRecordV1,
    };
    let mut expected = ProviderDiscoveryProofV1::schema();
    AdmissionHistoryRecordV1::update_schema_map(&mut expected);
    iroha_data_model::sorafs::provider_admission::discovery::account_read::RegisteredAccountReadV1::update_schema_map(&mut expected);
    iroha_data_model::sorafs::stream_token_custody::history::StreamTokenCustodyControlIndexV1::update_schema_map(&mut expected);
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted provider discovery descriptor: {}",
            descriptor.type_name
        );
    }
    assert!(find_missing_schema_references(&expected).is_empty());
}

#[test]
fn independent_custody_export_contains_presence_and_absence_schema_closure() {
    use iroha_data_model::sorafs::stream_token_custody::proof::{
        StreamTokenCustodyProofV1, StreamTokenCustodyRecordProofV1,
    };
    let expected = StreamTokenCustodyProofV1::schema();
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted independent custody descriptor: {}",
            descriptor.type_name,
        );
    }
    assert!(expected.contains_key::<Option<StreamTokenCustodyRecordProofV1>>());
    assert!(expected.contains_key::<StreamTokenCustodyRecordProofV1>());
    assert!(find_missing_schema_references(&expected).is_empty());
}

#[test]
fn reserve_account_export_contains_exact_independent_projection_schema_closure() {
    use iroha_data_model::sorafs::reserve::{
        ReserveProviderAccountV1, account_proof::ReserveAccountProofV1, history::ReserveStateV1,
    };
    let mut expected = ReserveAccountProofV1::schema();
    // The originals are canonical byte frames on the response; their semantic owners
    // remain explicit roots and must be covered by the same exported schema inventory.
    ReserveProviderAccountV1::update_schema_map(&mut expected);
    ReserveStateV1::update_schema_map(&mut expected);
    iroha_data_model::sorafs::pricing::ProviderCreditRecord::update_schema_map(&mut expected);
    iroha_data_model::sorafs::capacity::CapacityDeclarationRecord::update_schema_map(&mut expected);
    iroha_data_model::sorafs::pricing::PricingScheduleRecord::update_schema_map(&mut expected);
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted reserve account descriptor: {}",
            descriptor.type_name
        );
    }
    assert!(find_missing_schema_references(&expected).is_empty());
}
