// Exact source, predecessor, selector and prepublication universal projection checks.

#[test]
fn musubi_universal_authority_is_revision_only_after_exact_source_checks() {
    use crate::state::{
        authority_registry::world::musubi_universal_policy::{
            MusubiDirectoryAuthorityV1, MusubiResolverAuthorityV1,
        },
        world_projection::WorldStateAccumulator,
    };
    use norito::NoritoSchema;

    let (world, release, _, selector) = seeded_musubi_publication_snapshot();
    musubi_universal::validate_musubi_universal_projection_cuts(
        &world,
        world.sccp_committee_generations.allocation_budget(),
    )
    .expect("seeded current and predecessor universal rows are exact");
    let resolver = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .expect("resolver row");
    let directory = world
        .musubi_public_directory
        .view()
        .get(&selector)
        .cloned()
        .expect("directory row");
    assert_eq!(
        MusubiResolverAuthorityV1::nominal_name(),
        "iroha:state:musubi-resolver-authority:v1"
    );
    assert_eq!(
        MusubiDirectoryAuthorityV1::nominal_name(),
        "iroha:state:musubi-directory-authority:v1"
    );
    let resolver_authority = MusubiResolverAuthorityV1::from_record(&resolver);
    let directory_authority = MusubiDirectoryAuthorityV1::from_record(&directory);
    for encoded in [
        norito::encode_canonical(&resolver_authority).unwrap(),
        norito::encode_canonical(&directory_authority).unwrap(),
    ] {
        assert!(!encoded.is_empty());
    }
    assert_eq!(
        norito::decode_canonical::<MusubiResolverAuthorityV1>(
            &norito::encode_canonical(&resolver_authority).unwrap()
        )
        .unwrap(),
        resolver_authority
    );
    assert_eq!(
        norito::decode_canonical::<MusubiDirectoryAuthorityV1>(
            &norito::encode_canonical(&directory_authority).unwrap()
        )
        .unwrap(),
        directory_authority
    );
    let mut block = world.block();
    let baseline = WorldStateAccumulator::capture(&block).unwrap();
    let before_journal = block.publication_state_delta().unwrap();
    let mut changed_resolver = resolver.clone();
    changed_resolver.source_digest = MusubiContentDigestV1::new([0xD8; 32]);
    let mut changed_directory = directory.clone();
    changed_directory.metadata_revision += 1;
    block
        .musubi_resolver_index
        .insert(release.clone(), changed_resolver.clone());
    block
        .musubi_public_directory
        .insert(selector.clone(), changed_directory.clone());
    assert_eq!(
        WorldStateAccumulator::capture(&block).unwrap().root(),
        baseline.root(),
        "duplicated source fields do not become independent authority"
    );
    assert_ne!(
        block.publication_state_delta().unwrap(),
        before_journal,
        "the physical recovery journal keeps complete rows"
    );
    assert_ne!(
        norito::encode_canonical(&changed_resolver).unwrap(),
        norito::encode_canonical(&resolver).unwrap()
    );
    assert_eq!(
        MusubiResolverAuthorityV1::from_record(&changed_resolver),
        resolver_authority
    );
    let mut revised_resolver = resolver;
    revised_resolver.index_revision += 1;
    block
        .musubi_resolver_index
        .insert(release, revised_resolver.clone());
    assert_ne!(
        WorldStateAccumulator::capture(&block).unwrap().root(),
        baseline.root(),
        "independent resolver revision changes the authority baseline"
    );
    assert_ne!(
        MusubiResolverAuthorityV1::from_record(&revised_resolver),
        resolver_authority
    );
    assert_eq!(
        MusubiDirectoryAuthorityV1::from_record(&changed_directory),
        directory_authority
    );
    changed_directory.index_revision += 1;
    assert_ne!(
        MusubiDirectoryAuthorityV1::from_record(&changed_directory),
        directory_authority
    );
}
#[test]
fn musubi_universal_source_substitution_fails_on_current_and_predecessor() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let resolver = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .expect("resolver row");
    let mut stale_resolver = resolver.clone();
    stale_resolver.source_digest = MusubiContentDigestV1::new([0xD9; 32]);
    stale_resolver
        .validate()
        .expect("substitution remains structurally valid");
    let mut mutation = world.musubi_resolver_index.block();
    mutation.insert(release.clone(), stale_resolver);
    mutation.commit();
    let error = musubi_universal::validate_musubi_universal_projection_cuts(
        &world,
        world.sccp_committee_generations.allocation_budget(),
    )
    .expect_err("current resolver substitution must fail");
    assert!(
        error.to_string().contains("musubi_resolver_index")
            && error.to_string().contains("current"),
        "unexpected resolver diagnostic: {error}"
    );
    let mut repair = world.musubi_resolver_index.block();
    repair.insert(release, resolver);
    repair.commit();
    let error = musubi_universal::validate_musubi_universal_projection_cuts(
        &world,
        world.sccp_committee_generations.allocation_budget(),
    )
    .expect_err("repairing current resolver cannot hide stale predecessor");
    assert!(
        error.to_string().contains("musubi_resolver_index")
            && error.to_string().contains("predecessor"),
        "unexpected resolver predecessor diagnostic: {error}"
    );

    let (world, _, _, selector) = seeded_musubi_publication_snapshot();
    let directory = world
        .musubi_public_directory
        .view()
        .get(&selector)
        .cloned()
        .expect("directory row");
    let mut stale_directory = directory.clone();
    stale_directory.metadata_revision += 1;
    stale_directory
        .validate()
        .expect("substitution remains structurally valid");
    let mut mutation = world.musubi_public_directory.block();
    mutation.insert(selector.clone(), stale_directory);
    mutation.commit();
    let error = musubi_universal::validate_musubi_universal_projection_cuts(
        &world,
        world.sccp_committee_generations.allocation_budget(),
    )
    .expect_err("current directory substitution must fail");
    assert!(
        error.to_string().contains("musubi_public_directory")
            && error.to_string().contains("current"),
        "unexpected directory diagnostic: {error}"
    );
    let mut repair = world.musubi_public_directory.block();
    repair.insert(selector, directory);
    repair.commit();
    let error = musubi_universal::validate_musubi_universal_projection_cuts(
        &world,
        world.sccp_committee_generations.allocation_budget(),
    )
    .expect_err("repairing current directory cannot hide stale predecessor");
    assert!(
        error.to_string().contains("musubi_public_directory")
            && error.to_string().contains("predecessor"),
        "unexpected directory predecessor diagnostic: {error}"
    );
}
#[test]
fn musubi_universal_directory_rejects_colliding_package_selector() {
    let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
    let original = world
        .musubi_packages
        .view()
        .get(&release.package)
        .cloned()
        .expect("seeded package");
    let mut colliding = original;
    colliding.package.home_dataspace = DataSpaceId::new(8);
    colliding
        .validate()
        .expect("different home dataspace is structurally valid");
    world
        .musubi_packages
        .insert(colliding.package.clone(), colliding);
    let error = musubi_universal::validate_musubi_universal_projection_cut(
        &world.view(),
        ProjectionCut::Current,
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .expect_err("one directory row cannot satisfy two package identities");
    assert!(
        error.to_string().contains("musubi_public_directory")
            && error.to_string().contains("exact public-directory entry"),
        "unexpected selector collision diagnostic: {error}"
    );
}
#[test]
fn musubi_publication_refuses_substituted_universal_row_without_committing_it() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let original = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .expect("resolver row");
    let mut substituted = original.clone();
    substituted.source_digest = MusubiContentDigestV1::new([0xDA; 32]);
    let mut block = world.block();
    block
        .musubi_resolver_index
        .insert(release.clone(), substituted);
    let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
        &mut block,
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        2,
        &iroha_config::parameters::actual::Nexus::default(),
        &BTreeMap::new(),
        None,
        None,
    )
    .map_err(crate::execution_attempt::expect_completed_rejection) else {
        panic!("substituted resolver content must fail before publication");
    };
    assert!(
        error.contains("musubi_resolver_index"),
        "unexpected publication diagnostic: {error}"
    );
    drop(block);
    assert_eq!(
        world.musubi_resolver_index.view().get(&release),
        Some(&original),
        "failed preparation cannot publish the substituted row"
    );
}
