//! Rebuild flat proof-tag memberships from both canonical snapshot images.
//!
//! TODO: admit reconstruction scratch through the original snapshot resource
//! owner together with the remaining derived-index reconstruction.

#![expect(
    clippy::zero_sized_map_values,
    reason = "MV snapshot restoration requires complete current and undo key/value maps"
)]

use super::*;
use iroha_data_model::proof::ProofId;

type Memberships = BTreeMap<([u8; 4], ProofId), ()>;

fn project<'a>(
    rows: impl Iterator<Item = (&'a ProofId, &'a Vec<[u8; 4]>)>,
    cut: &str,
) -> Result<Memberships, json::Error> {
    let mut members = Memberships::new();
    for (proof, tags) in rows {
        if tags.is_empty() || tags.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(json::Error::InvalidField {
                field: "world.proof_tags".into(),
                message: format!("{cut} proof tag lists must be nonempty, sorted and unique"),
            });
        }
        for tag in tags {
            members.insert((*tag, proof.clone()), ());
        }
    }
    Ok(members)
}

/// Restore exact current and predecessor membership images from canonical tags.
/// The first-release snapshot stores no duplicate proof-tag inverse table.
pub(in crate::state) fn rebuild(world: &mut World) -> Result<(), json::Error> {
    let index = {
        let history = world.proof_tags.history();
        let current = project(history.current().iter(), "current")?;
        let previous = project(history.iter_before_block(), "predecessor")?;
        let mut touched = BTreeSet::new();
        for (proof, prior) in history.revert_map().iter() {
            for tags in [prior.as_ref(), history.current().get(proof)]
                .into_iter()
                .flatten()
            {
                touched.extend(tags.iter().map(|tag| (*tag, proof.clone())));
            }
        }
        let undo = touched
            .into_iter()
            .map(|key| {
                let prior = previous.get(&key).copied();
                (key, prior)
            })
            .collect();
        Storage::from_snapshot_parts(current, undo)
    };
    world.proofs_by_tag = index;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(sequence: u8) -> ProofId {
        ProofId {
            backend: "halo2/test".into(),
            proof_hash: [sequence; 32],
        }
    }

    #[test]
    fn rebuild_rejects_empty_duplicate_and_unordered_canonical_tags() {
        for tags in [vec![], vec![*b"TAG1", *b"TAG1"], vec![*b"TAG2", *b"TAG1"]] {
            let mut world = World::default();
            world.proof_tags.insert(proof(1), tags);
            let error = rebuild(&mut world).unwrap_err();
            assert!(error.to_string().contains("world.proof_tags"));
            assert!(world.proofs_by_tag.view().is_empty());
        }
    }

    #[test]
    fn predecessor_canonical_tags_are_validated_before_replacing_the_index() {
        let mut world = World::default();
        world.proof_tags.insert(proof(1), vec![*b"TAG2", *b"TAG1"]);
        {
            let mut block = world.proof_tags.block();
            block.insert(proof(1), vec![*b"TAG1", *b"TAG2"]);
            block.commit();
        }
        let error = rebuild(&mut world).unwrap_err();
        assert!(error.to_string().contains("predecessor"));
        assert!(world.proofs_by_tag.view().is_empty());
    }

    #[test]
    fn memberships_restore_shared_tags_and_both_mv_images() {
        let mut world = World::default();
        world.proof_tags.insert(proof(1), vec![*b"TAG1", *b"TAG2"]);
        world.proof_tags.insert(proof(2), vec![*b"TAG1"]);
        {
            let mut block = world.proof_tags.block();
            block.insert(proof(1), vec![*b"TAG2", *b"TAG3"]);
            block.insert(proof(3), vec![*b"TAG1"]);
            block.commit();
        }
        rebuild(&mut world).unwrap();
        let current = world.proofs_by_tag.view();
        assert!(current.get(&(*b"TAG1", proof(1))).is_none());
        assert_eq!(current.get(&(*b"TAG1", proof(2))), Some(&()));
        assert_eq!(current.get(&(*b"TAG1", proof(3))), Some(&()));
        assert_eq!(current.get(&(*b"TAG3", proof(1))), Some(&()));
        drop(current);
        let prior = world.proofs_by_tag.block_and_revert();
        assert_eq!(prior.get(&(*b"TAG1", proof(1))), Some(&()));
        assert_eq!(prior.get(&(*b"TAG1", proof(2))), Some(&()));
        assert!(prior.get(&(*b"TAG1", proof(3))).is_none());
        assert!(prior.get(&(*b"TAG3", proof(1))).is_none());
    }

    #[test]
    fn canonical_snapshot_roundtrip_rebuilds_the_flat_inverse_and_predecessor() {
        let mut world = World::default();
        world.proof_tags.insert(proof(1), vec![*b"TAG1"]);
        {
            let mut block = world.proof_tags.block();
            block.insert(proof(1), vec![*b"TAG2"]);
            block.commit();
        }
        let encoded = json::to_json(&world).unwrap();
        assert!(!encoded.contains("\"proofs_by_tag\""));
        let ivm = IVM::new(0);
        let seed = IvmSeed {
            ivm: &ivm,
            _marker: PhantomData,
        };
        let budget = iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        );
        let restored = parse_world(
            &budget,
            SnapshotJsonMap::parse_world_fixture(&encoded).unwrap(),
            &seed,
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .unwrap();
        assert_eq!(
            restored.proofs_by_tag.view().get(&(*b"TAG2", proof(1))),
            Some(&())
        );
        assert_eq!(
            restored
                .proofs_by_tag
                .block_and_revert()
                .get(&(*b"TAG1", proof(1))),
            Some(&())
        );
        assert!(
            restored
                .proofs_by_tag
                .view()
                .get(&(*b"TAG1", proof(1)))
                .is_none()
        );
    }
}
