// Original merge expansion custody at the actual native block validation boundary.

#[test]
fn native_validation_retains_original_proposal_when_expansion_has_another_state_owner() {
    let source = NativeValidationFixture::new();
    let destination = NativeValidationFixture::new();
    assert_eq!(source.chain.network_id(), destination.chain.network_id());
    assert_eq!(
        source.chain.state().state_view_generation(),
        destination.chain.state().state_view_generation()
    );
    let proposal = source.proposal(vec![source.transaction(2_001, None)], source.cadence());
    let (header, bytes) = source.header(&proposal);
    let expansion = expand(
        source.chain.state(),
        &proposal,
        &NoLanes,
        Duration::ZERO,
        &mut crate::sumeragi::lanes::ProposalReadScope::new(),
    )
    .unwrap();
    let mut events = Vec::new();
    let (retained, error) = destination
        .validate_expanded(proposal, &header, &bytes, expansion)
        .unpack(|event| events.push(event))
        .err()
        .unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::LocalStorageRecoveryRequired { .. }
    ));
    assert_eq!(retained.encode_wire().unwrap(), bytes);
    assert!(
        events.is_empty(),
        "a local source substitution cannot reject a peer's block"
    );
    assert_eq!(destination.chain.state().view().height(), 2);
}

#[test]
fn native_validation_retains_original_proposal_when_expansion_generation_advanced() {
    let mut fixture = NativeValidationFixture::new();
    let original_state = Arc::clone(fixture.chain.state());
    let proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    let (header, bytes) = fixture.header(&proposal);
    let generation = original_state.state_view_generation();
    let expansion = expand(
        &original_state,
        &proposal,
        &NoLanes,
        Duration::ZERO,
        &mut crate::sumeragi::lanes::ProposalReadScope::new(),
    )
    .unwrap();
    fixture.chain.commit_at(3_000, Vec::new());
    let observed_generation = original_state.state_view_generation();
    assert_ne!(observed_generation, generation);
    let mut events = Vec::new();
    let (retained, error) = fixture
        .validate_expanded(proposal, &header, &bytes, expansion)
        .unpack(|event| events.push(event))
        .err()
        .unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::NativeSourceChanged {
            authenticated_generation,
            observed_generation: actual_generation,
        } if authenticated_generation == generation && actual_generation == observed_generation
    ));
    assert_eq!(retained.encode_wire().unwrap(), bytes);
    assert!(
        events.is_empty(),
        "a changed local cut cannot reject the original peer proposal"
    );
    assert_eq!(fixture.chain.state().view().height(), 3);
}
