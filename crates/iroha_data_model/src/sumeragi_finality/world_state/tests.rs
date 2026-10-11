//! Portable complete-snapshot checks over genuine certificates and synthetic World data.
use super::*;
use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
use crate::{asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};

fn snapshot() -> (
    WorldStateSnapshotV1,
    AssetDefinitionId,
    AxtAssetIncarnationV1,
    u64,
) {
    let asset: AssetDefinitionId = "839FV3NJC8NfgWQvghXU2hEFQm9a".parse().unwrap();
    let incarnation =
        AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"synthetic asset registration").as_ref())
            .unwrap();
    let watermark = 7_u64;
    let snapshot = WorldStateSnapshotV1 {
        schema_hash: Hash::new(b"synthetic complete registry schema"),
        entries: vec![
            WorldStateSnapshotEntryV1 {
                field_id: "world.axt_asset_incarnations".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                value_hash: world_state_value_hash_v1(&incarnation).unwrap(),
            },
            WorldStateSnapshotEntryV1 {
                field_id: "world.soracloud_sequence_watermark".into(),
                kind: WorldStateElementKindV1::Cell,
                key_hash: None,
                value_hash: world_state_value_hash_v1(&watermark).unwrap(),
            },
        ],
    };
    (snapshot, asset, incarnation, watermark)
}

fn certify(snapshot: &WorldStateSnapshotV1) -> VerifiedSumeragiBlock {
    let mut native = NativeFinalityFixture::new();
    let block = native.block_with_submitted_work(native.next_header());
    let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
    native.verifier().verify_retained_decision(&proof).unwrap()
}

#[test]
fn canonical_trigger_owner_identities_roundtrip_and_bind_exact_hash_preimages() {
    let (mut snapshot, _, _, _) = snapshot();
    let trigger: crate::trigger::TriggerId = "snapshot_trigger".parse().unwrap();
    let value = vec![1_u8, 2, 3];
    let fields = [
        "triggers.by_call",
        "triggers.contracts",
        "triggers.data",
        "triggers.pipeline",
        "triggers.time",
    ];
    for (index, field) in fields.into_iter().enumerate() {
        let kind = WorldStateElementKindV1::Table;
        let path = world_state_path_hash_v1(field, kind).unwrap();
        assert_eq!(
            path,
            Hash::new_from_chunks(&[
                PATH,
                &[kind.tag()],
                &(field.len() as u64).to_le_bytes(),
                field.as_bytes(),
            ]),
            "the trigger registry identity is hashed exactly as declared"
        );
        snapshot.entries.insert(
            index,
            WorldStateSnapshotEntryV1 {
                field_id: field.into(),
                kind,
                key_hash: Some(world_state_value_hash_v1(&trigger).unwrap()),
                value_hash: world_state_value_hash_v1(&value).unwrap(),
            },
        );
    }
    let wire = norito::encode_canonical(&snapshot).unwrap();
    let decoded = WorldStateSnapshotV1::decode_bounded_canonical(&wire).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(
        norito::json::from_json::<WorldStateSnapshotV1>(&norito::json::to_json(&snapshot).unwrap())
            .unwrap(),
        snapshot
    );
    let verified = snapshot.authenticate(&certify(&snapshot)).unwrap();
    for field in fields {
        verified
            .verify_table_value(field, &trigger, &value)
            .unwrap();
    }
    let mut changed = snapshot;
    changed.entries.remove(0);
    assert!(changed.authenticate(&certify(&decoded)).is_err());
}

#[test]
fn world_path_hash_rejects_foreign_namespaces_and_empty_identity_components() {
    for field in [
        "state.world",
        "runtime.lanes",
        "data",
        "world.",
        "triggers.",
        "world..accounts",
        "triggers..data",
        "world.accounts.",
        "triggers.data.",
        "triggers.data/row",
    ] {
        assert!(
            world_state_path_hash_v1(field, WorldStateElementKindV1::Table).is_err(),
            "invalid registry identity {field}"
        );
    }
    for namespace in ["world", "triggers"] {
        let excessive = format!("{namespace}.{}", "a".repeat(192));
        assert!(world_state_path_hash_v1(&excessive, WorldStateElementKindV1::Table).is_err());
    }
}

#[test]
fn complete_snapshot_binds_real_typed_asset_and_registry_preimages_to_certified_root() {
    let (snapshot, asset, incarnation, watermark) = snapshot();
    let tip = certify(&snapshot);
    let verified = snapshot.authenticate(&tip).unwrap();
    assert_eq!(verified.height(), tip.height());
    assert_eq!(verified.context_id(), tip.context_id());
    assert_eq!(verified.world_root(), tip.execution().world_state_root);
    assert_eq!(verified.schema_hash(), snapshot.schema_hash);
    assert_eq!(verified.block_time_ms(), tip.header().creation_time_ms);
    verified
        .verify_table_value("world.axt_asset_incarnations", &asset, &incarnation)
        .unwrap();
    verified
        .verify_cell_value("world.soracloud_sequence_watermark", &watermark)
        .unwrap();
    let other =
        AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"reregistered asset").as_ref()).unwrap();
    assert!(
        verified
            .verify_table_value("world.axt_asset_incarnations", &asset, &other)
            .is_err()
    );
    assert!(
        verified
            .verify_cell_value("world.axt_asset_incarnations", &incarnation)
            .is_err()
    );
}

#[test]
fn omitted_added_or_changed_complete_elements_cannot_match_a_certified_root() {
    let (snapshot, _, _, _) = snapshot();
    let tip = certify(&snapshot);
    for mutation in 0..4 {
        let mut altered = snapshot.clone();
        match mutation {
            0 => {
                altered.entries.pop();
            }
            1 => altered.entries[0].value_hash = Hash::new(b"changed incarnation"),
            2 => altered.schema_hash = Hash::new(b"other registry schema"),
            _ => altered.entries[0].key_hash = Some(Hash::new(b"other canonical key")),
        }
        assert!(altered.authenticate(&tip).is_err());
    }
}

#[test]
fn duplicate_cell_table_key_and_incompatible_field_kind_are_refused() {
    let (snapshot, _, _, _) = snapshot();
    for index in 0..2 {
        let mut duplicate = snapshot.clone();
        duplicate
            .entries
            .insert(index, duplicate.entries[index].clone());
        assert!(duplicate.root().is_err());
    }
    let mut incompatible = snapshot.clone();
    incompatible.entries[0].kind = WorldStateElementKindV1::Cell;
    assert!(incompatible.root().is_err());
    let mut reordered = snapshot;
    reordered.entries.reverse();
    assert!(reordered.root().is_err());
}

#[test]
fn sorted_table_rows_cannot_hide_a_later_cell_of_the_same_field() {
    let (snapshot, _, _, _) = snapshot();
    let mut table = snapshot.entries[0].clone();
    let mut entries = vec![table.clone()];
    table.key_hash = Some(Hash::new(b"another canonical table key"));
    entries.push(table);
    entries.sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let mut multiple = WorldStateSnapshotV1 {
        schema_hash: snapshot.schema_hash,
        entries,
    };
    assert!(multiple.root().is_ok());
    let mut cell = snapshot.entries[1].clone();
    cell.field_id = multiple.entries[0].field_id.clone();
    multiple.entries.push(cell);
    assert!(multiple.root().is_err());
}

#[test]
fn exact_native_trigger_children_keep_their_existing_path_hash_namespace() {
    let (mut snapshot, _, _, _) = snapshot();
    for field in [
        "triggers.data",
        "triggers.pipeline",
        "triggers.time",
        "triggers.by_call",
        "triggers.contracts",
    ] {
        let len = field.len() as u64;
        let original_path = Hash::new_from_chunks(&[
            b"iroha:world-state:path:v1\0",
            &[0],
            &len.to_le_bytes(),
            field.as_bytes(),
        ]);
        assert_eq!(
            world_state_path_hash_v1(field, WorldStateElementKindV1::Table).unwrap(),
            original_path
        );
        assert_ne!(
            original_path,
            world_state_path_hash_v1(&format!("world.{field}"), WorldStateElementKindV1::Table)
                .unwrap()
        );
        snapshot.entries.push(WorldStateSnapshotEntryV1 {
            field_id: field.into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(world_state_value_hash_v1(&field).unwrap()),
            value_hash: world_state_value_hash_v1(&vec![1_u8, 2, 3]).unwrap(),
        });
    }
    snapshot
        .entries
        .sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let verified = snapshot.authenticate(&certify(&snapshot)).unwrap();
    verified
        .verify_table_value("triggers.data", &"triggers.data", &vec![1_u8, 2, 3])
        .unwrap();
    for invalid in [
        "triggers.",
        "triggers.ids",
        "triggers.active",
        "triggers.data.extra",
        "other.data",
    ] {
        assert!(world_state_path_hash_v1(invalid, WorldStateElementKindV1::Table).is_err());
    }
}

#[test]
fn canonical_original_rejects_trailing_bytes_and_unknown_residual_lanes() {
    let (snapshot, _, _, _) = snapshot();
    let original = norito::encode_canonical(&snapshot).unwrap();
    assert_eq!(
        WorldStateSnapshotV1::decode_bounded_canonical(&original).unwrap(),
        snapshot
    );
    let mut trailing = original;
    trailing.push(0);
    assert!(WorldStateSnapshotV1::decode_bounded_canonical(&trailing).is_err());
    let mut json = norito::json::to_json(&snapshot).unwrap();
    json.insert_str(1, "\"residual_lanes\":[],");
    assert!(norito::json::from_json::<WorldStateSnapshotV1>(&json).is_err());
}

#[test]
fn ordinary_write_root_and_uncertified_genesis_do_not_authenticate_current_world() {
    let (snapshot, _, _, _) = snapshot();
    let native = NativeFinalityFixture::new();
    let verifier = native.verifier();
    let genesis = verifier
        .verify_retained_decision(native.genesis_proof())
        .unwrap();
    assert!(snapshot.authenticate(&genesis).is_err());
    let ordinary = verifier.verify_retained_decision(native.latest()).unwrap();
    assert!(snapshot.authenticate(&ordinary).is_err());
}

#[test]
fn typed_asset_absence_requires_complete_certified_snapshot_and_exact_native_key() {
    let (mut snapshot, asset, _, _) = snapshot();
    snapshot.entries.insert(
        0,
        WorldStateSnapshotEntryV1 {
            field_id: "world.asset_definitions".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
            value_hash: Hash::new(b"synthetic definition semantic value"),
        },
    );
    let tip = certify(&snapshot);
    let verified = snapshot.authenticate(&tip).unwrap();
    assert!(verified.verify_asset_definition_absent(&asset).is_err());
    let other = crate::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("synthetic.is2").unwrap(),
        "OTHER".parse().unwrap(),
    );
    assert_ne!(asset, other);
    verified.verify_asset_definition_absent(&other).unwrap();
    let mut omitted = snapshot.clone();
    omitted.entries.remove(0);
    // Omitting the selected row must fail certification before absence is available.
    assert!(omitted.authenticate(&tip).is_err());
    // A separately certified complete native cut may have no definitions.
    let empty_tip = certify(&omitted);
    omitted
        .authenticate(&empty_tip)
        .unwrap()
        .verify_asset_definition_absent(&asset)
        .unwrap();
}

#[test]
fn asset_absence_rejects_incompatible_field_kind_even_in_certified_synthetic_data() {
    let (mut snapshot, asset, _, _) = snapshot();
    snapshot.entries.insert(
        0,
        WorldStateSnapshotEntryV1 {
            field_id: "world.asset_definitions".into(),
            kind: WorldStateElementKindV1::Cell,
            key_hash: None,
            value_hash: Hash::new(b"synthetic incompatible field"),
        },
    );
    let tip = certify(&snapshot);
    let verified = snapshot.authenticate(&tip).unwrap();
    assert!(verified.verify_asset_definition_absent(&asset).is_err());
}

#[test]
fn fixed_native_asset_alias_and_state_path_key_sets_authenticate_completeness() {
    use crate::{
        account::{AccountId, rekey::AccountAlias},
        asset::AssetId,
    };
    use iroha_model_base::state_path::StatePath;
    let key = iroha_crypto::KeyPair::from_seed(vec![17; 32], iroha_crypto::Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let (mut snapshot, definition, ..) = snapshot();
    let asset = AssetId::new(definition.clone(), account);
    let path: StatePath = "sns/records/2/synthetic".parse().unwrap();
    let account_alias = AccountAlias {
        label: "synthetic".parse().unwrap(),
        domain: None,
        dataspace: iroha_model_base::topology::DataSpaceId::new(77),
    };
    for (field, key) in [
        (
            "world.account_aliases",
            world_state_value_hash_v1(&account_alias).unwrap(),
        ),
        ("world.assets", world_state_value_hash_v1(&asset).unwrap()),
        (
            "world.asset_definition_alias_bindings",
            world_state_value_hash_v1(&definition).unwrap(),
        ),
        (
            "world.smart_contract_state",
            world_state_value_hash_v1(&path).unwrap(),
        ),
    ] {
        snapshot.entries.push(WorldStateSnapshotEntryV1 {
            field_id: field.into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(key),
            value_hash: world_state_value_hash_v1(&vec![1_u8, 2, 3]).unwrap(),
        });
    }
    snapshot
        .entries
        .sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let verified = snapshot.authenticate(&certify(&snapshot)).unwrap();
    verified
        .verify_asset_keys_complete(std::slice::from_ref(&asset))
        .unwrap();
    verified
        .verify_asset_definition_alias_binding_keys_complete(std::slice::from_ref(&definition))
        .unwrap();
    verified
        .verify_smart_contract_state_keys_complete(std::slice::from_ref(&path))
        .unwrap();
    verified
        .verify_account_alias_keys_complete(std::slice::from_ref(&account_alias))
        .unwrap();
    assert!(verified.verify_account_alias_keys_complete(&[]).is_err());
    assert!(
        verified
            .verify_account_alias_keys_complete(&[account_alias.clone(), account_alias])
            .is_err()
    );
    assert!(verified.verify_asset_keys_complete(&[]).is_err());
    assert!(
        verified
            .verify_asset_keys_complete(&[asset.clone(), asset.clone()])
            .is_err()
    );
    assert!(verified.verify_asset_absent(&asset).is_err());
    assert!(
        verified
            .verify_asset_definition_alias_binding_keys_complete(&[])
            .is_err()
    );
    assert!(
        verified
            .verify_smart_contract_state_keys_complete(&[])
            .is_err()
    );
    let extra: StatePath = "sns/records/2/extra".parse().unwrap();
    assert!(
        verified
            .verify_smart_contract_state_keys_complete(&[path, extra])
            .is_err()
    );
    let mut empty = snapshot.clone();
    empty
        .entries
        .retain(|entry| entry.field_id != "world.assets");
    let empty_verified = empty.authenticate(&certify(&empty)).unwrap();
    empty_verified.verify_asset_keys_complete(&[]).unwrap();
    empty_verified.verify_asset_absent(&asset).unwrap();
    assert!(
        empty.authenticate(&certify(&snapshot)).is_err(),
        "deleting a row cannot retain the original root"
    );
}

#[test]
fn every_fixed_fee_table_absence_and_complete_keys_bind_exact_native_key_types() {
    use crate::{account::AccountId, nexus::*};
    let key = iroha_crypto::KeyPair::from_seed(vec![18; 32], iroha_crypto::Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let (mut snapshot, asset, ..) = snapshot();
    let program = FeeSponsorProgramId::new(account.clone(), "synthetic".parse().unwrap());
    let revision = FeeSponsorProgramRevisionKey::new(program.clone(), 1);
    let enrollment = FeeSponsorEnrollmentKey {
        program_id: program.clone(),
        beneficiary: account,
    };
    let vault = FeeSponsorVaultKey {
        program_id: program.clone(),
        asset_definition_id: asset.clone(),
    };
    let counter = FeeSponsorBudgetCounterKey {
        program_id: program.clone(),
        asset_definition_id: asset,
        window: FeeSponsorBudgetWindow::Block(FeeSponsorBlockBudgetWindow { height: 3 }),
    };
    for (field, key) in [
        (
            "world.fee_sponsor_programs",
            world_state_value_hash_v1(&program).unwrap(),
        ),
        (
            "world.fee_sponsor_program_revisions",
            world_state_value_hash_v1(&revision).unwrap(),
        ),
        (
            "world.fee_sponsor_enrollments",
            world_state_value_hash_v1(&enrollment).unwrap(),
        ),
        (
            "world.fee_sponsor_vaults",
            world_state_value_hash_v1(&vault).unwrap(),
        ),
        (
            "world.fee_sponsor_budget_counters",
            world_state_value_hash_v1(&counter).unwrap(),
        ),
    ] {
        snapshot.entries.push(WorldStateSnapshotEntryV1 {
            field_id: field.into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(key),
            value_hash: Hash::new(b"synthetic typed-key test value"),
        });
    }
    snapshot
        .entries
        .sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let verified = snapshot.authenticate(&certify(&snapshot)).unwrap();
    verified
        .verify_fee_sponsor_program_keys_complete(std::slice::from_ref(&program))
        .unwrap();
    verified
        .verify_fee_sponsor_program_revision_keys_complete(std::slice::from_ref(&revision))
        .unwrap();
    verified
        .verify_fee_sponsor_enrollment_keys_complete(std::slice::from_ref(&enrollment))
        .unwrap();
    verified
        .verify_fee_sponsor_vault_keys_complete(std::slice::from_ref(&vault))
        .unwrap();
    verified
        .verify_fee_sponsor_budget_counter_keys_complete(std::slice::from_ref(&counter))
        .unwrap();
    assert!(
        verified
            .verify_fee_sponsor_program_absent(&program)
            .is_err()
    );
    assert!(
        verified
            .verify_fee_sponsor_program_revision_absent(&revision)
            .is_err()
    );
    assert!(
        verified
            .verify_fee_sponsor_enrollment_absent(&enrollment)
            .is_err()
    );
    assert!(verified.verify_fee_sponsor_vault_absent(&vault).is_err());
    assert!(
        verified
            .verify_fee_sponsor_budget_counter_absent(&counter)
            .is_err()
    );
    assert!(
        verified
            .verify_fee_sponsor_budget_counter_keys_complete(&[])
            .is_err()
    );
    let mut empty = snapshot;
    empty
        .entries
        .retain(|entry| !entry.field_id.starts_with("world.fee_sponsor_"));
    let verified = empty.authenticate(&certify(&empty)).unwrap();
    verified
        .verify_fee_sponsor_program_absent(&program)
        .unwrap();
    verified
        .verify_fee_sponsor_program_revision_absent(&revision)
        .unwrap();
    verified
        .verify_fee_sponsor_enrollment_absent(&enrollment)
        .unwrap();
    verified.verify_fee_sponsor_vault_absent(&vault).unwrap();
    verified
        .verify_fee_sponsor_budget_counter_absent(&counter)
        .unwrap();
    verified
        .verify_fee_sponsor_program_keys_complete(&[])
        .unwrap();
    verified
        .verify_fee_sponsor_program_revision_keys_complete(&[])
        .unwrap();
    verified
        .verify_fee_sponsor_enrollment_keys_complete(&[])
        .unwrap();
    verified
        .verify_fee_sponsor_vault_keys_complete(&[])
        .unwrap();
    verified
        .verify_fee_sponsor_budget_counter_keys_complete(&[])
        .unwrap();
}

#[test]
fn exact_asset_definition_binding_absence_requires_complete_certified_native_cut() {
    let (mut present, definition, ..) = snapshot();
    present.entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.asset_definition_alias_bindings".into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(&definition).unwrap()),
        // Explicit synthetic value; exact key presence is the predicate under test.
        value_hash: world_state_value_hash_v1(&vec![1_u8, 2, 3]).unwrap(),
    });
    present
        .entries
        .sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let present_tip = certify(&present);
    let present_wire = norito::encode_canonical(&present).unwrap();
    let decoded = WorldStateSnapshotV1::decode_bounded_canonical(&present_wire).unwrap();
    let verified = decoded.authenticate(&present_tip).unwrap();
    assert!(
        verified
            .verify_asset_definition_alias_binding_absent(&definition)
            .is_err()
    );
    let mut absent = decoded.clone();
    absent
        .entries
        .retain(|entry| entry.field_id != "world.asset_definition_alias_bindings");
    assert!(
        absent.authenticate(&present_tip).is_err(),
        "omission cannot retain the genuine original certificate"
    );
    let verified_absent = absent.authenticate(&certify(&absent)).unwrap();
    verified_absent
        .verify_asset_definition_alias_binding_absent(&definition)
        .unwrap();
    let mut incompatible = absent;
    incompatible.entries.push(WorldStateSnapshotEntryV1 {
        field_id: "world.asset_definition_alias_bindings".into(),
        kind: WorldStateElementKindV1::Cell,
        key_hash: None,
        value_hash: world_state_value_hash_v1(&vec![4_u8, 5, 6]).unwrap(),
    });
    incompatible
        .entries
        .sort_by_key(|entry| (entry.field_id.clone(), entry.kind, entry.key_hash));
    let wrong_kind = incompatible.authenticate(&certify(&incompatible)).unwrap();
    assert!(
        wrong_kind
            .verify_asset_definition_alias_binding_absent(&definition)
            .is_err()
    );
}

#[test]
fn certified_direct_home_requires_exact_row_current_incarnation_and_domainless_definition() {
    use crate::{
        Registrable,
        account::AccountId,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionDirectHomeV1},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_primitives::numeric::NumericSpec;
    let (_, asset, incarnation, _) = snapshot();
    let key = iroha_crypto::KeyPair::from_seed(vec![27; 32], iroha_crypto::Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let home = DataSpaceId::new(7);
    let row = AssetDefinitionDirectHomeV1 {
        incarnation,
        dataspace_id: home,
    };
    let other =
        AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"another actual registration").as_ref())
            .unwrap();
    for policy in [
        AssetBalancePolicy::Global,
        AssetBalancePolicy::DataspaceRestricted,
    ] {
        let definition = AssetDefinition::new(
            asset.clone(),
            String::from("Test"),
            NumericSpec::fractional(2),
            policy,
            None,
        )
        .build(&owner);
        let make_world = |definition: &AssetDefinition,
                          stored_row: Option<&AssetDefinitionDirectHomeV1>,
                          registered_incarnation: AxtAssetIncarnationV1| {
            let mut entries = vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.asset_definitions".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                    value_hash: world_state_value_hash_v1(definition).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.axt_asset_incarnations".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                    value_hash: world_state_value_hash_v1(&registered_incarnation).unwrap(),
                },
            ];
            if let Some(stored_row) = stored_row {
                entries.push(WorldStateSnapshotEntryV1 {
                    field_id: "world.asset_definition_direct_homes".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                    value_hash: world_state_value_hash_v1(stored_row).unwrap(),
                });
            }
            let mut snapshot = WorldStateSnapshotV1 {
                schema_hash: Hash::new(b"synthetic complete direct home schema"),
                entries,
            };
            snapshot.entries.sort_by(|a, b| {
                (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash))
            });
            snapshot.authenticate(&certify(&snapshot)).unwrap()
        };
        let world = make_world(&definition, Some(&row), incarnation);
        world
            .verify_asset_definition_direct_home(&definition, &row, home)
            .unwrap();
        // Wrong expected dataspace, including the reserved universal dataspace.
        assert!(
            world
                .verify_asset_definition_direct_home(&definition, &row, DataSpaceId::new(8))
                .is_err()
        );
        let universal = AssetDefinitionDirectHomeV1 {
            dataspace_id: DataSpaceId::UNIVERSAL,
            ..row
        };
        assert!(
            world
                .verify_asset_definition_direct_home(
                    &definition,
                    &universal,
                    DataSpaceId::UNIVERSAL
                )
                .is_err()
        );
        // A tampered row (other dataspace) differs from the certified row value.
        let moved = AssetDefinitionDirectHomeV1 {
            dataspace_id: DataSpaceId::new(8),
            ..row
        };
        assert!(
            world
                .verify_asset_definition_direct_home(&definition, &moved, DataSpaceId::new(8))
                .is_err()
        );
        // Foreign incarnation: the row and the live incarnation disagree.
        assert!(
            make_world(&definition, Some(&row), other)
                .verify_asset_definition_direct_home(&definition, &row, home)
                .is_err()
        );
        let foreign = AssetDefinitionDirectHomeV1 {
            incarnation: other,
            ..row
        };
        assert!(
            world
                .verify_asset_definition_direct_home(&definition, &foreign, home)
                .is_err()
        );
        // Missing row.
        assert!(
            make_world(&definition, None, incarnation)
                .verify_asset_definition_direct_home(&definition, &row, home)
                .is_err()
        );
        // A domain-owned definition never has a direct home.
        let mut domain_owned = definition.clone();
        domain_owned.owning_domain = Some(DomainId::try_new("issuer", "public").unwrap());
        assert!(
            make_world(&domain_owned, Some(&row), incarnation)
                .verify_asset_definition_direct_home(&domain_owned, &row, home)
                .is_err()
        );
    }
}
