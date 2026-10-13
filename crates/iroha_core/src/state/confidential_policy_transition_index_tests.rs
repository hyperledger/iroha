fn transition_index_snapshot(world: &World) -> String {
    let mut out = String::new();
    snapshot_storage::serialize(&world.confidential_policy_transition_index, &mut out);
    out
}

#[test]
fn rebuild_uses_only_authoritative_pending_transitions() {
    let policy = policy_with_transition(
        ConfidentialPolicyMode::Convertible,
        ConfidentialPolicyMode::ShieldedOnly,
        41,
        Some(7),
        b"policy-index-rebuild",
    );
    let (definition_id, definition) = definition_with_policy("coin", policy);
    let mut world = World::default();
    world
        .asset_definitions
        .insert(definition_id.clone(), definition);
    world
        .confidential_policy_transition_index
        .insert((99, definition_id.clone()), ());
    world.confidential_policy_transition_counts.insert(99, 1);
    world
        .rebuild_confidential_policy_transition_index()
        .expect("valid authoritative transition rebuilds");
    let transition_index = world.confidential_policy_transition_index.view();
    assert!(transition_index.get(&(99, definition_id.clone())).is_none());
    assert_eq!(
        transition_index.get(&(41, definition_id.clone())),
        Some(&())
    );
    let transition_counts = world.confidential_policy_transition_counts.view();
    assert!(transition_counts.get(&99).is_none());
    assert_eq!(transition_counts.get(&41), Some(&1));
}

#[test]
fn rebuild_restores_consumed_and_changed_transitions_for_replacement() {
    let policy = policy_with_transition(
        ConfidentialPolicyMode::Convertible,
        ConfidentialPolicyMode::ShieldedOnly,
        41,
        Some(7),
        b"policy-index-prior",
    );
    let (first, first_definition) = definition_with_policy("first", policy.clone());
    let (second, second_definition) = definition_with_policy("second", policy);
    let mut world = World::default();
    world
        .asset_definitions
        .insert(first.clone(), first_definition.clone());
    world
        .asset_definitions
        .insert(second.clone(), second_definition.clone());
    {
        let mut changes = world.asset_definitions.block();
        let mut consumed = first_definition;
        consumed.set_confidential_policy(AssetConfidentialPolicy::shielded_only());
        changes.insert(first.clone(), consumed);
        let mut tampered_value = second_definition;
        tampered_value.set_confidential_policy(policy_with_transition(
            ConfidentialPolicyMode::Convertible,
            ConfidentialPolicyMode::ShieldedOnly,
            42,
            Some(7),
            b"policy-index-current",
        ));
        changes.insert(second.clone(), tampered_value);
        changes.commit();
    }
    let source_before = norito::json::to_json(&world.asset_definitions).unwrap();
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    let rebuilt_before = transition_index_snapshot(&world);
    assert_eq!(
        world.confidential_policy_transition_counts.view().get(&42),
        Some(&1)
    );
    assert_eq!(
        world.confidential_policy_transition_counts.view().get(&41),
        None
    );
    {
        let replacement = world.block_and_revert();
        assert_eq!(
            replacement
                .confidential_policy_transition_index
                .get(&(41, first.clone())),
            Some(&())
        );
        assert_eq!(
            replacement
                .confidential_policy_transition_index
                .get(&(41, second.clone())),
            Some(&())
        );
        assert_eq!(
            replacement
                .confidential_policy_transition_index
                .get(&(42, second.clone())),
            None
        );
        assert_eq!(
            replacement.confidential_policy_transition_counts.get(&41),
            Some(&2)
        );
        assert_eq!(
            replacement.confidential_policy_transition_counts.get(&42),
            None
        );
    }
    assert_eq!(
        norito::json::to_json(&world.asset_definitions).unwrap(),
        source_before
    );
    assert_eq!(transition_index_snapshot(&world), rebuilt_before);
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    assert_eq!(transition_index_snapshot(&world), rebuilt_before);
    world.block_and_revert().commit();
    assert_eq!(
        world.confidential_policy_transition_counts.view().get(&41),
        Some(&2)
    );
    assert_eq!(
        world.confidential_policy_transition_counts.view().get(&42),
        None
    );
}

#[test]
fn rebuild_rejects_invalid_prior_transition_without_mutating_indexes() {
    let mut invalid = policy_with_transition(
        ConfidentialPolicyMode::Convertible,
        ConfidentialPolicyMode::ShieldedOnly,
        41,
        Some(7),
        b"policy-invalid-prior",
    );
    invalid.pending_transition.as_mut().unwrap().previous_mode =
        ConfidentialPolicyMode::TransparentOnly;
    let (id, invalid_definition) = definition_with_policy("invalid", invalid);
    let mut world = World::default();
    world
        .asset_definitions
        .insert(id.clone(), invalid_definition);
    {
        let mut changes = world.asset_definitions.block();
        let (_, valid) =
            definition_with_policy("invalid", AssetConfidentialPolicy::shielded_only());
        changes.insert(id.clone(), valid);
        changes.commit();
    }
    world
        .confidential_policy_transition_index
        .insert((99, id), ());
    world.confidential_policy_transition_counts.insert(99, 1);
    let source = norito::json::to_json(&world.asset_definitions).unwrap();
    let index = transition_index_snapshot(&world);
    let counts = norito::json::to_json(&world.confidential_policy_transition_counts).unwrap();
    assert!(
        world
            .rebuild_confidential_policy_transition_index()
            .is_err()
    );
    assert_eq!(
        norito::json::to_json(&world.asset_definitions).unwrap(),
        source
    );
    assert_eq!(transition_index_snapshot(&world), index);
    assert_eq!(
        norito::json::to_json(&world.confidential_policy_transition_counts).unwrap(),
        counts
    );
}
