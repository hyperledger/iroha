//! Both proof images, explicit comparison work and original-reader fences.

use super::*;
use crate::{state::proof_status_restore, test_allocations::allocations_during};
use mv::storage::Storage;

fn id(backend: &str, tag: u8) -> ProofId {
    ProofId {
        backend: backend.into(),
        proof_hash: [tag; 32],
    }
}

fn record(key: &ProofId, status: ProofStatus) -> ProofRecord {
    ProofRecord {
        id: key.clone(),
        vk_ref: None,
        vk_commitment: None,
        status,
        verified_at_height: None,
        bridge: None,
    }
}

fn fixture() -> World {
    let mut world = World::default();
    for (tag, status) in STATUSES.into_iter().enumerate() {
        let key = id(
            "stark/fri",
            u8::try_from(tag).expect("fixture value fits u8"),
        );
        world.proofs.insert(key.clone(), record(&key, status));
    }
    proof_status_restore::rebuild(&mut world);
    world
}

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedProofRecords::capture(world, work).map(|_| ()));
        }),
        0,
        "original source/index validation has no cloned keys or scratch heap"
    );
    result.unwrap()
}

fn corrupt(previous: bool, mismatch: GroupMismatch) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index: INDEX,
        image: if previous {
            GroupImage::Predecessor
        } else {
            GroupImage::Current
        },
        mismatch,
    }
}

#[test]
fn every_status_and_stored_key_projection_are_preserved_without_new_admission_rules() {
    let mut world = World::default();
    for (ordinal, backend) in ["", "stark", "stark/fri", "stark:fri", "証明"]
        .into_iter()
        .enumerate()
    {
        for (tag, status) in STATUSES.into_iter().enumerate() {
            let key = id(backend, u8::try_from(tag).expect("fixture value fits u8"));
            let mut value = record(&key, status);
            // Existing reconstruction projects the stored map key. The status
            // relation must not infer additional proof-content admission rules.
            value.id = id("payload identity is checked by its separate owner", 90);
            value.vk_commitment = Some([u8::try_from(ordinal).expect("fixture value fits u8"); 32]);
            value.verified_at_height = Some(ordinal as u64);
            world.proofs.insert(key, value);
        }
    }
    proof_status_restore::rebuild(&mut world);
    assert_eq!(check(&world, 16_384), Ok(()));
    let checked = CheckedProofRecords::capture(&world, 16_384).unwrap();
    assert_eq!(checked.rows().len(), 15);
    assert!(checked.matches_current().unwrap());
}

#[test]
fn merged_predecessor_keeps_moved_removed_inserted_and_redundant_source_rows() {
    let mut world = fixture();
    {
        let mut block = world.proofs.block();
        let moved = id("stark/fri", 0);
        block.insert(moved.clone(), record(&moved, ProofStatus::Verified));
        block.remove(id("stark/fri", 1));
        let unchanged = id("stark/fri", 2);
        block.insert(unchanged.clone(), record(&unchanged, ProofStatus::Rejected));
        for backend in ["", "stark", "stark/fri/child", "証明"] {
            let key = id(backend, 3);
            block.insert(key.clone(), record(&key, ProofStatus::Submitted));
        }
        block.remove(id("zz absent", 9));
        block.commit();
    }
    proof_status_restore::rebuild(&mut world);
    assert_eq!(check(&world, 32_768), Ok(()));
    let expected = {
        let history = world.proofs.history();
        let current = history
            .current()
            .iter()
            .map(|(key, value)| (key.clone(), value.status))
            .collect::<Vec<_>>();
        let mut previous = history
            .iter_before_block()
            .map(|(key, value)| (key.clone(), value.status))
            .collect::<Vec<_>>();
        previous.sort();
        [current, previous]
    };
    let checked = CheckedProofRecords::capture(&world, 32_768).unwrap();
    for (image, expected) in [GroupImage::Current, GroupImage::Predecessor]
        .into_iter()
        .zip(expected)
    {
        let mut actual = Vec::new();
        visit_proofs(checked.rows(), image, &mut Work(32_768), |key, value, _| {
            actual.push((key.clone(), value.status));
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, expected);
    }
    drop(checked);
    world.block_and_revert().commit();
    assert_eq!(check(&world, 32_768), Ok(()));
}

#[test]
fn omitted_empty_wrong_status_duplicate_and_foreign_groups_fail_in_either_image() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut world = fixture();
            let key = id("stark/fri", 0);
            let correct = BTreeSet::from([key.clone()]);
            let replacement = match defect {
                0 => None,
                1 => Some(BTreeSet::new()),
                2 => Some(BTreeSet::from([id("stark/fri", 1)])),
                3 => Some(BTreeSet::from([key.clone(), id("stark/fri", 2)])),
                4 => Some(BTreeSet::from([key.clone(), id("unknown", 99)])),
                _ => unreachable!(),
            };
            world.proofs_by_status = [
                (ProofStatus::Submitted, replacement),
                (
                    ProofStatus::Verified,
                    Some(BTreeSet::from([id("stark/fri", 1)])),
                ),
                (
                    ProofStatus::Rejected,
                    Some(BTreeSet::from([id("stark/fri", 2)])),
                ),
            ]
            .into_iter()
            .filter_map(|(status, members)| members.map(|members| (status, members)))
            .collect::<Storage<_, _>>();
            if previous {
                let mut block = world.proofs_by_status.block();
                block.insert(ProofStatus::Submitted, correct);
                block.commit();
            }
            assert_eq!(
                check(&world, 16_384),
                Err(corrupt(
                    previous,
                    match defect {
                        0 | 2 => GroupMismatch::MissingMember,
                        1 => GroupMismatch::EmptyGroup,
                        3 | 4 => GroupMismatch::ForeignMember,
                        _ => unreachable!(),
                    }
                ))
            );
        }
    }
}

#[test]
fn physical_masked_rows_and_tombstones_have_exact_work_even_when_logically_absent() {
    let mut world = World::default();
    let key = id("x", 1);
    world
        .proofs
        .insert(key.clone(), record(&key, ProofStatus::Verified));
    proof_status_restore::rebuild(&mut world);
    // Each image: one index row, three lookups, three physical source visits,
    // one member and 66 compared key bytes. No undo rows exist initially.
    assert_eq!(check(&world, 147), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 148), Ok(()));
    {
        let mut block = world.proofs.block();
        block.remove(id("y", 2));
        block.commit();
    }
    // Three source passes each visit the tombstone and compare x against y.
    assert_eq!(check(&world, 348), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 349), Ok(()));
    {
        let mut block = world.proofs_by_status.block();
        block.insert(ProofStatus::Verified, BTreeSet::from([key.clone()]));
        block.remove(ProofStatus::Rejected);
        block.commit();
    }
    assert_eq!(check(&world, 350), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 351), Ok(()));
    {
        let mut block = world.proofs.block();
        block.insert(key.clone(), record(&key, ProofStatus::Verified));
        block.remove(id("y", 2));
        block.commit();
    }
    // The now-masked current x and its undo value are both physical work.
    assert_eq!(check(&world, 353), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 354), Ok(()));
}

#[test]
fn variable_backend_bytes_are_prepaid_and_long_valid_keys_only_defer_locally() {
    let backend = "証明:".repeat(2048);
    let left = id(&backend, 1);
    let right = id(&backend, 2);
    let charge = (2 * backend.len() + 64) as u64;
    let mut short = Work(charge - 1);
    assert_eq!(
        compare_keys(&left, &right, &mut short),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(short.0, charge - 1);
    let mut exact = Work(charge);
    assert_eq!(
        compare_keys(&left, &right, &mut exact),
        Ok(left.cmp(&right))
    );
    assert_eq!(exact.0, 0);
    let mut world = World::default();
    world
        .proofs
        .insert(left.clone(), record(&left, ProofStatus::Submitted));
    proof_status_restore::rebuild(&mut world);
    assert_eq!(check(&world, 512), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 2 * charge + 16), Ok(()));
    assert_eq!(
        check(&world, 2 * charge + 15),
        Err(GroupedOwnershipError::WorkLimit)
    );
}

#[test]
fn either_original_reader_change_overrides_success_corruption_and_work_refusal() {
    for changed in 0..2 {
        for error in [
            None,
            Some(GroupedOwnershipError::WorkLimit),
            Some(corrupt(false, GroupMismatch::MissingMember)),
        ] {
            let world = fixture();
            let checked = CheckedProofRecords::retain(&world).unwrap();
            checked.validate(&mut Work(16_384)).unwrap();
            match changed {
                0 => world.proofs.block().commit(),
                1 => world.proofs_by_status.block().commit(),
                _ => unreachable!(),
            }
            assert!(!checked.matches_current().unwrap());
            assert_eq!(
                checked.finish_validation(error.map_or(Ok(()), Err)).err(),
                Some(PublicationPreparationError::Changed.into())
            );
        }
    }
}

#[test]
fn physical_index_admission_precedes_empty_bucket_diagnosis_in_either_image() {
    for previous in [false, true] {
        let mut world = fixture();
        world
            .proofs_by_status
            .insert(ProofStatus::Submitted, BTreeSet::new());
        if previous {
            let mut block = world.proofs_by_status.block();
            for (tag, status) in STATUSES.into_iter().enumerate() {
                // Retain all three physical undo entries, including no-op writes.
                block.insert(
                    status,
                    BTreeSet::from([id(
                        "stark/fri",
                        u8::try_from(tag).expect("fixture value fits u8"),
                    )]),
                );
            }
            block.commit();
        }
        // Current validation costs 264 when valid. The current index has three
        // physical rows; its predecessor additionally has three physical undo
        // entries. Each image's complete index admission precedes inspecting the
        // first logical empty bucket. A short local allowance is deferral, never
        // success or a transaction-validity/gas decision.
        let diagnosis_work = if previous { 264 + 6 } else { 3 };
        assert_eq!(
            check(&world, diagnosis_work - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            check(&world, diagnosis_work),
            Err(corrupt(previous, GroupMismatch::EmptyGroup))
        );
        assert_eq!(
            check(&world, 16_384),
            Err(corrupt(previous, GroupMismatch::EmptyGroup))
        );
        // Repeating the smaller allowance uses the same unchanged original rows.
        assert_eq!(
            check(&world, diagnosis_work - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
    }
}
