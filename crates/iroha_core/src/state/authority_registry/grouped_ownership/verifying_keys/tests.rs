//! Both-image inverse semantics and retained original publication identities.

use super::*;
use crate::{
    state::verifying_key_index_validation::test_support::*, test_allocations::allocations_during,
};
use iroha_data_model::confidential::ConfidentialStatus;

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedVerifyingKeys::capture(world, work).map(|_| ()));
        }),
        0
    );
    result.unwrap()
}

#[test]
fn all_statuses_and_inactive_or_withdrawn_missing_key_rows_keep_their_inverse() {
    let mut world = Box::new(World::default());
    for (ordinal, status) in [
        ConfidentialStatus::Proposed,
        ConfidentialStatus::Active,
        ConfidentialStatus::Withdrawn,
    ]
    .into_iter()
    .enumerate()
    {
        let key = VerifyingKeyId::new("unvalidated backend", format!("key-{ordinal}"));
        let mut value = record();
        value.version = u32::try_from(ordinal).expect("fixture value fits u32");
        value.status = status;
        value.key = None;
        value.activation_height = Some(100);
        value.withdraw_height = Some(101);
        world
            .verifying_keys_by_circuit
            .insert((value.circuit_id.clone(), value.version), key.clone());
        world.verifying_keys.insert(key, value);
    }
    assert_eq!(check(&world, 100_000), Ok(()));
}

#[test]
fn omissions_foreign_ids_wrong_tuples_and_ambiguous_sources_fail_in_either_image() {
    for prior in [false, true] {
        for defect in 0..7 {
            let mut world = world();
            let correct = (record().circuit_id, record().version);
            let foreign = VerifyingKeyId::new("foreign", "key");
            let wrong = ("wrong".to_owned(), 99);
            match defect {
                0 => {
                    let mut index = world.verifying_keys_by_circuit.block();
                    index.remove(correct.clone());
                    index.commit();
                }
                1 => {
                    world
                        .verifying_keys_by_circuit
                        .insert(correct.clone(), foreign.clone());
                }
                2 => {
                    let mut index = world.verifying_keys_by_circuit.block();
                    index.remove(correct.clone());
                    index.commit();
                    world
                        .verifying_keys_by_circuit
                        .insert(("wrong".into(), 1), id());
                }
                3 => {
                    let mut index = world.verifying_keys_by_circuit.block();
                    index.remove(correct.clone());
                    index.commit();
                    world
                        .verifying_keys_by_circuit
                        .insert(("circuit".into(), 99), id());
                }
                4 => {
                    world.verifying_keys_by_circuit.insert(wrong.clone(), id());
                }
                5 => {
                    world.verifying_keys.insert(foreign.clone(), record());
                }
                6 => {
                    // Equal cardinalities alone cannot hide two source keys projected to
                    // one tuple and an unrelated inverse row filling the missing slot.
                    world.verifying_keys.insert(foreign.clone(), record());
                    world.verifying_keys_by_circuit.insert(wrong.clone(), id());
                }
                _ => unreachable!(),
            }
            if prior {
                let mut block = world.block();
                block.verifying_keys.remove(foreign);
                block.verifying_keys_by_circuit.remove(wrong);
                block.verifying_keys_by_circuit.remove(("wrong".into(), 1));
                block
                    .verifying_keys_by_circuit
                    .remove(("circuit".into(), 99));
                block.verifying_keys_by_circuit.insert(correct, id());
                block.commit();
            }
            assert_eq!(
                check(&world, 100_000),
                Err(GroupedOwnershipError::Corrupt {
                    index: INDEX,
                    image: if prior {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    mismatch: if defect == 4 {
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
fn either_same_value_original_publication_overrides_success_error_and_local_refusal() {
    for changed in 0..2 {
        for outcome in 0..3 {
            let world = world();
            let checked = CheckedVerifyingKeys::retain(&world).unwrap();
            relation::validate(&checked.rows, &checked.index, &mut Work::bounded(100_000)).unwrap();
            let result = match outcome {
                0 => Ok(()),
                1 => Err(GroupedOwnershipError::WorkLimit),
                _ => Err(GroupedOwnershipError::Corrupt {
                    index: INDEX,
                    image: GroupImage::Current,
                    mismatch: GroupMismatch::MissingMember,
                }),
            };
            match changed {
                0 => {
                    let mut block = world.verifying_keys.block();
                    block.insert(id(), record());
                    block.commit();
                }
                1 => {
                    let mut block = world.verifying_keys_by_circuit.block();
                    block.insert((record().circuit_id, 1), id());
                    block.commit();
                }
                _ => unreachable!(),
            }
            assert!(!checked.matches_current().unwrap());
            assert_eq!(
                checked.finish_validation(result).err(),
                Some(PublicationPreparationError::Changed.into())
            );
        }
    }
}

#[test]
fn dense_valid_registry_requires_only_more_local_work_and_can_retry_unchanged() {
    let mut world = Box::new(World::default());
    for ordinal in 0..128 {
        let key = VerifyingKeyId::new("stark/fri", format!("key-{ordinal}"));
        let mut value = record();
        value.version = ordinal;
        world
            .verifying_keys_by_circuit
            .insert((value.circuit_id.clone(), value.version), key.clone());
        world.verifying_keys.insert(key, value);
    }
    let retained = CheckedVerifyingKeys::retain(&world).unwrap();
    assert_eq!(
        check(&world, 128 * 1024),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, 2_000_000), Ok(()));
    assert!(retained.matches_current().unwrap());
}
