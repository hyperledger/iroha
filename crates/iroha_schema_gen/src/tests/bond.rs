//! The native bond kernel exports its instruction family, record and events.

use super::{IntoSchema, find_missing_schema_references};
use iroha_data_model::{
    bond::{BondCashflowState, BondRecord, BondTerms},
    events::data::bond::BondEvent,
    isi::bond::{BondInstructionBox, RegisterBond},
    query::bond::FindBondById,
};

#[test]
fn bond_export_contains_instructions_record_events_and_singular_query() {
    let mut expected = BondInstructionBox::schema();
    BondRecord::update_schema_map(&mut expected);
    BondEvent::update_schema_map(&mut expected);
    // Iterable queries travel as erased payloads; the singular query is a schema type.
    FindBondById::update_schema_map(&mut expected);
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted bond descriptor: {}",
            descriptor.type_name,
        );
    }
    assert!(expected.contains_key::<RegisterBond>());
    assert!(expected.contains_key::<BondTerms>());
    assert!(expected.contains_key::<BondCashflowState>());
    assert!(find_missing_schema_references(&expected).is_empty());
}
