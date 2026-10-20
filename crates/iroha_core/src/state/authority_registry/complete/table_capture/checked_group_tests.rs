//! Catalog readers must consume retained index checks before leaf encoding.

use super::*;
use crate::state::authority_registry::grouped_ownership::{
    GroupImage, GroupMismatch, GroupedOwnershipError,
};
use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
use iroha_data_model::{account::Account, prelude::Registrable};
use iroha_test_samples::ALICE_ID;
use std::collections::BTreeSet;

#[test]
fn actual_rekey_catalog_checks_original_occurrence_index_before_allocation() {
    use iroha_data_model::account::AccountAlias;
    use iroha_model_base::topology::DataSpaceId;
    for previous in [false, true] {
        for empty in [false, true] {
            let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
            let mut state = State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            // State construction rebuilds the derived occurrence map. Inject
            // only afterwards to test the actual live catalog route.
            let aliases = if empty {
                BTreeSet::new()
            } else {
                BTreeSet::from([AccountAlias::domainless(
                    "missing".parse().unwrap(),
                    DataSpaceId::UNIVERSAL,
                )])
            };
            state
                .world
                .account_rekey_records_by_account
                .insert(ALICE_ID.clone(), aliases);
            if previous {
                let mut block = state.world.account_rekey_records_by_account.block();
                block.remove(ALICE_ID.clone());
                block.commit();
            }
            state.ivm_execution_budget().set_limit_bytes(0);
            let TableMaterializer::Single { capture, .. } = TABLE_MATERIALIZERS
                .iter()
                .find(|owner| {
                    owner
                        .table_ids()
                        .any(|id| id == "world.account_rekey_records")
                })
                .unwrap()
            else {
                panic!("one checked record reader");
            };
            assert_eq!(
                capture(&state, native_test_support::limits()).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: "world.account_rekey_records_by_account",
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: if empty {
                            GroupMismatch::EmptyGroup
                        } else {
                            GroupMismatch::ForeignMember
                        },
                    }
                ))
            );
        }
    }
}

#[test]
fn actual_contract_alias_catalog_rejects_foreign_inverse_before_allocation() {
    use iroha_data_model::smart_contract::{ContractAddress, ContractAlias};
    use iroha_model_base::topology::DataSpaceId;
    for previous in [false, true] {
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let alias: ContractAlias = "foreign::universal".parse().unwrap();
        let address = ContractAddress::derive(
            &crate::state::DEFAULT_TEST_NETWORK_ID,
            &ALICE_ID,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        // State construction rebuilds derived alias indexes. Inject corruption
        // only afterwards, so this exercises the actual live catalog checker.
        state.world.contract_aliases.insert(alias.clone(), address);
        if previous {
            let mut block = state.world.contract_aliases.block();
            block.remove(alias);
            block.commit();
        }
        state.ivm_execution_budget().set_limit_bytes(0);
        let TableMaterializer::Single { capture, .. } = TABLE_MATERIALIZERS
            .iter()
            .find(|owner| {
                owner
                    .table_ids()
                    .any(|id| id == "world.contract_alias_bindings")
            })
            .unwrap()
        else {
            panic!("one checked binding reader");
        };
        assert_eq!(
            capture(&state, native_test_support::limits()).err(),
            Some(LeafError::GroupedOwnership(
                GroupedOwnershipError::Corrupt {
                    index: "world.contract_aliases",
                    image: if previous {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    mismatch: GroupMismatch::ForeignMember,
                }
            ))
        );
    }
}

#[test]
fn actual_catalog_rejects_corrupt_group_indexes_at_both_cuts_before_allocation() {
    for table in [
        "world.nfts",
        "world.rwas",
        "world.asset_escrows",
        "world.repo_agreements",
        "world.asset_definitions",
        "world.assets",
    ] {
        for previous in [false, true] {
            let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
            // Orphan membership rows and invalid counters are rejected even
            // without source rows. The predecessor case repairs only the tip.
            use crate::state::authority_registry::grouped_ownership::{
                asset_definition_test_support as definitions, escrow_test_support as escrow,
                nft_rwa_test_support as nft_rwa,
            };
            macro_rules! corrupt {
                ($field:ident, $key:expr, $value:expr, $mismatch:expr) => {{
                    let key = $key;
                    world.$field.insert(key.clone(), $value);
                    if previous {
                        let mut block = world.$field.block();
                        block.remove(key);
                        block.commit();
                    }
                    (concat!("world.", stringify!($field)), $mismatch)
                }};
            }
            let (index, mismatch) = match table {
                "world.nfts" => corrupt!(
                    nfts_by_owner,
                    (ALICE_ID.clone(), nft_rwa::nft_id()),
                    (),
                    GroupMismatch::ForeignMember
                ),
                "world.rwas" => corrupt!(
                    rwas_by_owner,
                    (ALICE_ID.clone(), nft_rwa::rwa_id()),
                    (),
                    GroupMismatch::ForeignMember
                ),
                "world.asset_escrows" => corrupt!(
                    asset_escrows_by_seller,
                    (ALICE_ID.clone(), escrow::id()),
                    (),
                    GroupMismatch::ForeignMember
                ),
                "world.repo_agreements" => corrupt!(
                    repo_agreements_by_initiator,
                    ALICE_ID.clone(),
                    BTreeSet::new(),
                    GroupMismatch::EmptyGroup
                ),
                "world.asset_definitions" => corrupt!(
                    asset_definitions_by_owner,
                    (ALICE_ID.clone(), definitions::id(0)),
                    (),
                    GroupMismatch::ForeignMember
                ),
                "world.assets" => corrupt!(
                    asset_definition_asset_counts,
                    definitions::id(0),
                    0,
                    GroupMismatch::ForeignMember
                ),
                _ => unreachable!(),
            };
            let state = State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            let pool = state.ivm_execution_budget();
            pool.set_limit_bytes(0);
            let TableMaterializer::Single { capture, .. } = TABLE_MATERIALIZERS
                .iter()
                .find(|owner| owner.table_ids().any(|id| id == table))
                .expect("actual authoritative table catalog")
            else {
                panic!("grouped source requires one checked canonical reader");
            };
            assert_eq!(
                capture(&state, native_test_support::limits()).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index,
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch,
                    }
                )),
                "{table} {previous}",
            );
        }
    }
}
