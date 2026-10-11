//! Exact first-release persistence of domain endorsement append order.

use super::*;
use iroha_data_model::nexus::{DOMAIN_ENDORSEMENT_VERSION_V1, DomainEndorsementScope};

fn endorsement(
    domain: &DomainId,
    marker: u8,
    accepted_at_height: u64,
) -> (HashOf<DomainEndorsement>, DomainEndorsementRecord) {
    let endorsement = DomainEndorsement {
        version: DOMAIN_ENDORSEMENT_VERSION_V1,
        domain_id: domain.clone(),
        committee_id: "endorsement-snapshot-test".to_owned(),
        statement_hash: Hash::new(&[marker]),
        issued_at_height: accepted_at_height,
        expires_at_height: accepted_at_height + 10,
        scope: DomainEndorsementScope::default(),
        signatures: Vec::new(),
        metadata: Metadata::default(),
    };
    let hash = endorsement.body_hash();
    (
        hash,
        DomainEndorsementRecord {
            endorsement,
            accepted_at_height,
        },
    )
}

fn fixture() -> (
    World,
    DomainId,
    [HashOf<DomainEndorsement>; 3],
    [DomainEndorsementRecord; 3],
) {
    let world = World::default();
    let domain = DomainId::try_new("endorsement-snapshot", "universal").unwrap();
    let (first_hash, first) = endorsement(&domain, 1, 7);
    let (second_hash, second) = endorsement(&domain, 2, 7);
    let (third_hash, third) = endorsement(&domain, 3, 8);
    // The first two entries have the same height, and deliberately use the
    // reverse of hash order. Their append order cannot be reconstructed.
    let (first_hash, first, second_hash, second) = if first_hash > second_hash {
        (first_hash, first, second_hash, second)
    } else {
        (second_hash, second, first_hash, first)
    };
    {
        let mut block = world.block();
        block.domain_endorsements.insert(first_hash, first.clone());
        block
            .domain_endorsements
            .insert(second_hash, second.clone());
        block
            .domain_endorsements_by_domain
            .insert(domain.clone(), vec![first_hash, second_hash]);
        block.commit();
    }
    {
        let mut block = world.block();
        block.domain_endorsements.insert(third_hash, third.clone());
        block
            .domain_endorsements_by_domain
            .insert(domain.clone(), vec![first_hash, second_hash, third_hash]);
        block.commit();
    }
    (
        world,
        domain,
        [first_hash, second_hash, third_hash],
        [first, second, third],
    )
}

fn restore(world: &World) -> Result<World, json::Error> {
    let encoded = json::to_json(world).unwrap();
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&encoded, "world")?,
        &seed,
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
}

#[test]
fn snapshot_roundtrip_preserves_same_height_append_order_and_exact_predecessor() {
    let (world, domain, hashes, records) = fixture();
    assert!(hashes[0] > hashes[1], "fixture reverses hash order");
    let before_index = json::to_json(&world.domain_endorsements_by_domain).unwrap();
    let before_primary = json::to_json(&world.domain_endorsements).unwrap();
    let restored = restore(&world).unwrap();
    assert_eq!(
        json::to_json(&restored.domain_endorsements_by_domain).unwrap(),
        before_index
    );
    assert_eq!(
        json::to_json(&restored.domain_endorsements).unwrap(),
        before_primary
    );
    assert_eq!(
        restored.domain_endorsements_by_domain.view().get(&domain),
        Some(&hashes.to_vec())
    );
    let previous_index = restored.domain_endorsements_by_domain.block_and_revert();
    let previous_primary = restored.domain_endorsements.block_and_revert();
    assert_eq!(previous_index.get(&domain), Some(&hashes[..2].to_vec()));
    assert_eq!(previous_primary.get(&hashes[0]), Some(&records[0]));
    assert_eq!(previous_primary.get(&hashes[1]), Some(&records[1]));
    assert_eq!(previous_primary.get(&hashes[2]), None);
    drop(previous_index);
    drop(previous_primary);
    assert_eq!(
        json::to_json(&restored.domain_endorsements_by_domain).unwrap(),
        before_index,
        "validation and predecessor observation cannot consume the undo map"
    );
}

#[test]
fn endorsement_index_is_a_required_first_release_world_snapshot_field() {
    let encoded = json::to_json(&World::default()).unwrap();
    let mut map = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    assert!(map.remove("domain_endorsements_by_domain").is_some());
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    let error = parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        map,
        &seed,
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
    .err()
    .expect("missing canonical index must fail");
    assert!(
        error.to_string().contains("domain_endorsements_by_domain"),
        "{error}"
    );
}

#[test]
fn malformed_current_endorsement_indexes_fail_restore() {
    for mutation in 0..5 {
        let (world, domain, hashes, _) = fixture();
        {
            let mut block = world.block();
            match mutation {
                0 => {
                    block.domain_endorsements_by_domain.remove(domain.clone());
                }
                1 => {
                    block
                        .domain_endorsements_by_domain
                        .insert(domain.clone(), vec![hashes[0], hashes[2]]);
                }
                2 => {
                    block.domain_endorsements_by_domain.insert(
                        domain.clone(),
                        vec![hashes[0], hashes[1], hashes[1], hashes[2]],
                    );
                }
                3 => {
                    block.domain_endorsements_by_domain.remove(domain.clone());
                    let foreign = DomainId::try_new("foreign", "universal").unwrap();
                    block
                        .domain_endorsements_by_domain
                        .insert(foreign, hashes.to_vec());
                }
                4 => {
                    block.domain_endorsements_by_domain.insert(
                        domain.clone(),
                        vec![
                            hashes[0],
                            hashes[1],
                            HashOf::from_untyped_unchecked(Hash::new(&[0x55_u8])),
                        ],
                    );
                }
                _ => unreachable!(),
            }
            block.commit();
        }
        let error = restore(&world)
            .err()
            .expect("malformed canonical index must fail");
        assert!(
            error
                .to_string()
                .contains("invalid current endorsement index"),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn malformed_actual_mv_predecessor_index_fails_restore() {
    let (mut world, domain, hashes, _) = fixture();
    let (current, mut revert) = {
        let snapshot = world.domain_endorsements_by_domain.snapshot();
        (
            snapshot
                .current()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
            snapshot
                .revert_map()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    };
    revert.insert(domain, Some(vec![hashes[0]]));
    world.domain_endorsements_by_domain = Storage::from_snapshot_parts(current, revert);
    let error = restore(&world)
        .err()
        .expect("malformed actual MV predecessor must fail");
    assert!(
        error
            .to_string()
            .contains("invalid predecessor endorsement index"),
        "{error}"
    );
}
