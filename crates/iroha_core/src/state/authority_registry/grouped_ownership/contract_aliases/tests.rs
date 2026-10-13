//! Retained contract alias checks use original maps and the actual catalog owner.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_contract_alias_bindings_once,
            leaf::{LeafError, LeafLimits},
        },
    },
    test_allocations::allocations_during,
};

use super::test_support::{address, fixture, record};

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedContractAliases::capture(world, work).map(|_| ()));
        }),
        0
    );
    result.unwrap()
}

fn image(previous: bool) -> GroupImage {
    if previous {
        GroupImage::Predecessor
    } else {
        GroupImage::Current
    }
}

#[test]
fn rename_delete_insert_and_redundant_touches_retain_exact_predecessor() {
    let mut world = fixture();
    world
        .contract_alias_bindings
        .insert(address(1), record("removed"));
    world
        .contract_alias_bindings
        .insert(address(2), record("untouched"));
    {
        let mut block = world.contract_alias_bindings.block();
        block.insert(address(0), record("renamed"));
        block.remove(address(1));
        block.insert(address(2), record("untouched"));
        block.insert(address(3), record("inserted"));
        block.remove(address(4));
        block.commit();
    }
    world.rebuild_contract_alias_indexes().unwrap();
    assert_eq!(check(&world, 1_000_000), Ok(()));
    let checked = CheckedContractAliases::capture(&world, 1_000_000).unwrap();
    assert_eq!(
        get_at(checked.rows(), GroupImage::Current, &address(0)),
        Some(&record("renamed"))
    );
    assert_eq!(
        get_at(checked.rows(), GroupImage::Predecessor, &address(0)),
        Some(&record("router"))
    );
    assert_eq!(
        get_at(checked.rows(), GroupImage::Predecessor, &address(1)),
        Some(&record("removed"))
    );
    assert!(get_at(checked.rows(), GroupImage::Current, &address(1)).is_none());
    assert!(get_at(checked.rows(), GroupImage::Predecessor, &address(3)).is_none());
    assert!(checked.rows().undo().contains_key(&address(4)));
}

#[test]
fn missing_wrong_and_foreign_inverse_rows_reject_in_either_image() {
    for previous in [false, true] {
        for defect in 0..3 {
            let mut world = fixture();
            let alias = record("router").alias;
            world.contract_aliases = mv::storage::Storage::new();
            if defect == 1 {
                world.contract_aliases.insert(alias.clone(), address(1));
            } else if defect == 2 {
                world.contract_aliases.insert(alias.clone(), address(0));
                world
                    .contract_aliases
                    .insert(record("foreign").alias, address(0));
            }
            if previous {
                let mut block = world.contract_aliases.block();
                block.insert(alias, address(0));
                block.remove(record("foreign").alias);
                block.commit();
            }
            assert_eq!(
                check(&world, 1_000_000),
                Err(GroupedOwnershipError::Corrupt {
                    index: "world.contract_aliases",
                    image: image(previous),
                    mismatch: if defect == 2 {
                        GroupMismatch::ForeignMember
                    } else {
                        GroupMismatch::MissingMember
                    },
                })
            );
        }
    }
}

#[test]
fn duplicate_canonical_alias_targets_reject_in_either_image() {
    for previous in [false, true] {
        let mut world = fixture();
        world
            .contract_alias_bindings
            .insert(address(1), record("router"));
        if previous {
            let mut block = world.contract_alias_bindings.block();
            block.remove(address(1));
            block.commit();
        }
        assert_eq!(
            check(&world, 1_000_000),
            Err(GroupedOwnershipError::Corrupt {
                index: "world.contract_aliases",
                image: image(previous),
                mismatch: GroupMismatch::MissingMember,
            })
        );
    }
}

#[test]
fn all_invalid_lease_relations_reject_without_repair_in_either_image() {
    for previous in [false, true] {
        for (expiry, grace, bound) in [
            (None, Some(2), 1),
            (Some(1), None, 1),
            (Some(2), Some(1), 1),
        ] {
            let mut world = fixture();
            let mut invalid = record("router");
            invalid.lease_expiry_ms = expiry;
            invalid.grace_until_ms = grace;
            invalid.bound_at_ms = bound;
            world
                .contract_alias_bindings
                .insert(address(0), invalid.clone());
            if previous {
                let mut block = world.contract_alias_bindings.block();
                block.insert(address(0), record("router"));
                block.commit();
            }
            assert_eq!(
                check(&world, 1_000_000),
                Err(GroupedOwnershipError::Source {
                    table: "world.contract_alias_bindings",
                    image: image(previous),
                    reason: alias_lease::violation(expiry, grace, bound).unwrap(),
                })
            );
            let rows = world
                .contract_alias_bindings
                .try_committed_view_nonblocking()
                .unwrap();
            assert_eq!(get_at(&rows, image(previous), &address(0)), Some(&invalid));
        }
    }
}

#[test]
fn undeployed_and_expired_bindings_remain_representable_until_cleanup() {
    let mut world = fixture();
    let mut expired = record("router");
    expired.lease_expiry_ms = Some(2);
    expired.grace_until_ms = Some(3);
    world
        .contract_alias_bindings
        .insert(address(0), expired.clone());
    assert!(expired.is_grace_expired_at(u64::MAX));
    assert!(world.contract_instances.view().get(&address(0)).is_none());
    assert_eq!(check(&world, 688), Ok(()));
}

#[test]
fn exact_work_limit_charges_masked_rows_and_absent_undo_before_filtering() {
    let world = fixture();
    assert_eq!(check(&world, 687), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 688), Ok(()));
    {
        let mut block = world.contract_alias_bindings.block();
        block.insert(address(0), record("router"));
        block.remove(address(1));
        block.commit();
    }
    // Both predecessor source visits inspect three physical rows. Each performs one
    // equality merge plus a second comparison only when the absent key sorts first.
    let exact = if address(1) < address(0) { 1172 } else { 932 };
    assert_eq!(
        check(&world, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, exact), Ok(()));
}

#[test]
fn both_original_readers_detect_publication_after_capture() {
    for source in [false, true] {
        let world = fixture();
        let checked = CheckedContractAliases::capture(&world, 688).unwrap();
        if source {
            world.contract_alias_bindings.block().commit();
        } else {
            world.contract_aliases.block().commit();
        }
        assert!(!checked.matches_current().unwrap());
    }
}

#[test]
fn checked_capture_uses_original_state_budget_and_retained_rows() {
    let state = State::new_for_testing(
        fixture(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 16,
        max_payload_bytes: 16384,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 131_072,
    };
    let pool = state.ivm_execution_budget();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_contract_alias_bindings_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1_000_000 * 1_000_000);
    let snapshot = capture_contract_alias_bindings_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.contract_alias_bindings");
    assert_eq!(snapshot.row_count(), 1);
}

#[test]
fn maximum_canonical_text_pair_costs_the_named_descriptor_allowance() {
    let mut world = fixture();
    let mut longest = record("router");
    let name = "a".repeat(iroha_model_base::name::MAX_NAME_BYTES);
    let domain = "b".repeat(iroha_model_base::name::MAX_NAME_BYTES);
    let dataspace = "c".repeat(iroha_model_base::name::MAX_NAME_BYTES);
    longest.alias = ContractAlias::from_components(&name, Some(&domain), &dataspace).unwrap();
    assert_eq!(longest.alias.as_ref().len(), 768);
    assert_eq!(address(0).as_ref().len(), 60);
    world.contract_alias_bindings.insert(address(0), longest);
    world.rebuild_contract_alias_indexes().unwrap();
    assert_eq!(CONTRACT_ALIAS_WORK_PER_ROW, 6696);
    assert_eq!(check(&world, 6695), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 6696), Ok(()));
}

#[test]
fn equal_noops_new_rows_and_absent_tombstones_have_exact_physical_costs() {
    let world = fixture();
    {
        let mut rows = world.contract_alias_bindings.block();
        rows.insert(address(0), record("router"));
        rows.commit();
        let mut aliases = world.contract_aliases.block();
        aliases.insert(record("router").alias, address(0));
        aliases.commit();
    }
    // Current: 344. Predecessor: eight physical advances + 308 merge-text bytes
    // + 308 inverse-text bytes + 32 lease units = 656.
    assert_eq!(check(&world, 999), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 1000), Ok(()));

    let mut inserted = fixture();
    inserted.contract_alias_bindings = mv::storage::Storage::new();
    inserted.contract_aliases = mv::storage::Storage::new();
    {
        let mut rows = inserted.contract_alias_bindings.block();
        rows.insert(address(0), record("router"));
        rows.commit();
        let mut aliases = inserted.contract_aliases.block();
        aliases.insert(record("router").alias, address(0));
        aliases.commit();
    }
    // Current: 344. Empty predecessor: four physical advances + 120+34 merge bytes.
    assert_eq!(check(&inserted, 501), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&inserted, 502), Ok(()));

    let mut absent = fixture();
    absent.contract_alias_bindings = mv::storage::Storage::new();
    absent.contract_aliases = mv::storage::Storage::new();
    // Commit exact absent preimages in both native tables.
    {
        let mut rows = absent.contract_alias_bindings.block();
        rows.remove(address(0));
        rows.commit();
        let mut aliases = absent.contract_aliases.block();
        aliases.remove(record("router").alias);
        aliases.commit();
    }
    assert_eq!(check(&absent, 1), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&absent, 2), Ok(()));
}

#[test]
fn text_and_physical_advances_are_funded_before_comparison_or_iteration() {
    let left = "\u{e9}::universal";
    let right = "other::domain.universal";
    let exact = u64::try_from(left.len() + right.len()).unwrap();
    assert_eq!(
        compare_text(left, right, &mut Work(exact - 1)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    let mut work = Work(exact);
    assert_eq!(compare_text(left, right, &mut work), Ok(left.cmp(right)));
    assert_eq!(work.0, 0);

    let key = address(0);
    let value = record("router");
    let entries = [(&key, &value)];
    let advances = std::cell::Cell::new(0);
    let mut iterator = entries
        .into_iter()
        .inspect(|_| advances.set(advances.get() + 1));
    assert_eq!(
        next_physical(&mut iterator, &mut Work(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(advances.get(), 0);
    assert_eq!(
        next_physical(&mut iterator, &mut Work(1)).unwrap(),
        Some((&key, &value))
    );
    assert_eq!(advances.get(), 1);
    assert_eq!(next_physical(&mut iterator, &mut Work(0)).unwrap(), None);
}

#[test]
fn either_original_identity_change_overrides_success_corruption_and_work_refusal() {
    for source in [false, true] {
        for verdict in 0..3 {
            let world = fixture();
            let checked = CheckedContractAliases::retain(&world).unwrap();
            let result = match verdict {
                0 => validate(&checked.rows, &checked.aliases, &mut Work(688)),
                1 => Err(GroupedOwnershipError::Corrupt {
                    index: INDEX,
                    image: GroupImage::Current,
                    mismatch: GroupMismatch::MissingMember,
                }),
                2 => validate(&checked.rows, &checked.aliases, &mut Work(0)),
                _ => unreachable!(),
            };
            if source {
                world.contract_alias_bindings.block().commit();
            } else {
                world.contract_aliases.block().commit();
            }
            assert_eq!(
                checked.finish_validation(result).err(),
                Some(GroupedOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}

#[test]
fn original_address_spelling_and_utf8_alias_text_are_not_redecoded_or_normalized() {
    let mut world = fixture();
    let lower = address(0);
    // V1 admits only the canonical lowercase `irohac` spelling. A distinct
    // genuine address tests exact stored identity without an invalid case alias.
    assert!(matches!(
        lower
            .as_ref()
            .to_ascii_uppercase()
            .parse::<ContractAddress>(),
        Err(iroha_data_model::smart_contract::ContractAddressError::InvalidHrp(_))
    ));
    let spelling = address(1).as_ref().to_owned();
    let stored: ContractAddress = spelling.parse().unwrap();
    assert_eq!(stored.as_ref(), spelling);
    assert_ne!(stored, lower);
    let binding = record("caf\u{e9}");
    let alias = binding.alias.clone();
    assert_eq!(alias.as_ref(), "caf\u{e9}::universal");
    // The public model refuses alternate NFD spelling before it becomes stored identity.
    assert!("cafe\u{301}::universal".parse::<ContractAlias>().is_err());
    // Both of these distinct original aliases are valid NFC. Compatibility folding
    // would conflate the fullwidth letters with the original ASCII letters.
    let foreign_alias = record("\u{ff43}\u{ff41}\u{ff46}\u{e9}").alias;
    assert_eq!(
        foreign_alias.as_ref(),
        "\u{ff43}\u{ff41}\u{ff46}\u{e9}::universal"
    );
    assert_ne!(foreign_alias, alias);
    let exact = 2
        * (4 + LEASE_WINDOW_WORK
            + 4 * u64::try_from(alias.as_ref().len() + stored.as_ref().len()).unwrap());
    world.contract_alias_bindings = mv::storage::Storage::from_iter([(stored.clone(), binding)]);
    world.rebuild_contract_alias_indexes().unwrap();
    assert_eq!(
        check(&world, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, exact), Ok(()));
    world.contract_aliases.insert(alias, lower);
    assert_eq!(
        check(&world, 1_000_000),
        Err(GroupedOwnershipError::Corrupt {
            index: INDEX,
            image: GroupImage::Current,
            mismatch: GroupMismatch::MissingMember,
        })
    );
    // A relation that rewrites original UTF-8 by compatibility normalization
    // would incorrectly accept this foreign inverse.
    world.contract_aliases = mv::storage::Storage::from_iter([(foreign_alias, stored)]);
    assert_eq!(
        check(&world, 1_000_000),
        Err(GroupedOwnershipError::Corrupt {
            index: INDEX,
            image: GroupImage::Current,
            mismatch: GroupMismatch::MissingMember,
        })
    );
}
