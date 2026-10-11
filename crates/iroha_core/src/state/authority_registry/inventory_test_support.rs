//! Independent generated-inventory expectations for exhaustive native State controls.
//!
//! The fixture is emitted by `regenerate_state_table_inventory`; expectations are
//! identity sets, independently compared with the production typed registry and
//! each actual capture. A removed owner must be reviewed in that generator first.

use std::collections::BTreeSet;

use super::{Canonical, Field, Role, STATE_FIELDS, WORLD_FIELDS};

fn fixture_fields() -> Vec<norito::json::Value> {
    let fixture = norito::json::from_str::<norito::json::Value>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/state_table_inventory.json"
    )))
    .expect("canonical generated State inventory JSON");
    fixture
        .get("fields")
        .and_then(norito::json::Value::as_array)
        .expect("canonical State inventory fields")
        .to_vec()
}

fn text<'a>(row: &'a norito::json::Value, key: &str) -> &'a str {
    row.get(key)
        .and_then(norito::json::Value::as_str)
        .expect("typed inventory field string")
}

fn fixture_ids(matches: impl Fn(&norito::json::Value) -> bool) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for row in fixture_fields().iter().filter(|row| matches(row)) {
        assert!(
            result.insert(text(row, "id").to_owned()),
            "duplicate fixture identity"
        );
    }
    assert!(
        !result.is_empty(),
        "fixture identity selection cannot be empty"
    );
    result
}

/// Exact generated identities of every classified World field.
pub(in crate::state) fn world_field_ids() -> BTreeSet<String> {
    fixture_ids(|row| text(row, "id").starts_with("world."))
}

/// Exact original overlay fields; delivery events retain a separate original owner.
pub(in crate::state) fn world_overlay_names() -> BTreeSet<String> {
    let mut fields = world_field_ids();
    assert!(fields.remove("world.external_event_buf"));
    fields
        .into_iter()
        .map(|id| {
            id.strip_prefix("world.")
                .expect("World identity")
                .to_owned()
        })
        .collect()
}

/// Exact canonical table output identities, independently of catalog dispatch.
pub(in crate::state) fn canonical_table_ids() -> BTreeSet<String> {
    fixture_ids(|row| text(row, "role") == "canonical" && text(row, "shape") == "table")
}

/// Native raw outputs, excluding the reviewed checked semantic and paired owners.
pub(in crate::state) fn raw_native_table_ids() -> BTreeSet<String> {
    // These owners use checked semantic capture or indivisible membership rather
    // than the generated raw adapter. The parity control still visits every raw
    // adapter and must retain every remaining canonical fixture identity.
    const CHECKED_OUTPUTS: &[&str] = &[
        "world.domains",
        "world.accounts",
        "world.account_rekey_records",
        "world.asset_definitions",
        "world.contract_alias_bindings",
        "world.assets",
        "world.nfts",
        "world.rwas",
        "world.asset_escrows",
        "triggers.data",
        "triggers.pipeline",
        "triggers.time",
        "triggers.by_call",
        "triggers.contracts",
        "world.verifying_keys",
        "world.proofs",
        "world.contract_subject_bindings",
        "world.repo_agreements",
        "world.governance_proposals",
        "world.account_aliases",
        "world.musubi_archive_availability",
        "world.musubi_resolver_index",
        "world.musubi_public_directory",
        "state.transactions.current",
        "state.transactions.rollback",
    ];
    let mut fields = canonical_table_ids();
    for id in CHECKED_OUTPUTS {
        assert!(
            fields.remove(*id),
            "missing or duplicate checked output {id}"
        );
    }
    fields
}

/// Original World delta shape expands the one aggregate into all trigger owners.
pub(in crate::state) fn world_delta_field_count() -> u64 {
    let mut fields = world_overlay_names();
    assert!(fields.remove("triggers"));
    u64::try_from(fields.len() + fixture_ids(|row| text(row, "id").starts_with("triggers.")).len())
        .expect("World delta field count fits u64")
}

fn collect_tables(fields: &[Field], tables: &mut BTreeSet<String>) {
    for field in fields {
        match field.role {
            Role::Canonical(Canonical::Table { .. }) => {
                assert!(
                    tables.insert(field.id.to_owned()),
                    "duplicate typed canonical table"
                );
            }
            Role::Canonical(Canonical::Owner(children)) => collect_tables(children, tables),
            _ => {}
        }
    }
}

#[test]
fn generated_inventory_matches_exhaustive_typed_world_tables_and_trigger_owners() {
    let world: BTreeSet<_> = WORLD_FIELDS
        .iter()
        .map(|field| field.id.to_owned())
        .collect();
    assert_eq!(world.len(), WORLD_FIELDS.len());
    assert_eq!(world, world_field_ids());
    let mut tables = BTreeSet::new();
    collect_tables(STATE_FIELDS, &mut tables);
    assert_eq!(tables, canonical_table_ids());
    let triggers = crate::smartcontracts::isi::triggers::set::AUTHORITY_FIELDS;
    let typed: BTreeSet<_> = triggers.iter().map(|field| field.id.to_owned()).collect();
    assert_eq!(typed.len(), triggers.len());
    assert_eq!(
        typed,
        fixture_ids(|row| text(row, "id").starts_with("triggers."))
    );
    assert_eq!(world_overlay_names().len() + 1, world_field_ids().len());
    assert_eq!(
        world_delta_field_count(),
        u64::try_from(world_overlay_names().len() - 1 + triggers.len())
            .expect("World delta field count fits u64")
    );
}
