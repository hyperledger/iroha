// Actual ordinary admission checks against native certified execution history.

#[test]
fn native_validation_rejects_duplicate_original_transactions() {
    let fixture = NativeValidationFixture::new();
    let tx = fixture.transaction(2_001, None);
    let proposal = fixture.proposal(vec![tx.clone(), tx], fixture.cadence());
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::DuplicateTransactions
    ));
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_replayed_sealed_signed_identity_from_actual_history() {
    let mut fixture = NativeValidationFixture::new();
    let authority = AccountId::new(fixture.user.public_key().clone());
    let (_, reveal) = crate::block::tests::sealed_set_key_entrypoints(
        fixture.chain.network_id(),
        &authority,
        &fixture.user,
        1,
        9,
        Name::from_str("sealed_replay_native").unwrap(),
    );
    let TransactionEntrypoint::SealedReveal(sealed) = &reveal else {
        unreachable!()
    };
    // The signed identity is in real committed history. The different sealed carrier has
    // never committed, so checking only its outer hash would miss the replay.
    assert_eq!(
        fixture
            .chain
            .commit(vec![sealed.signed_transaction().clone()]),
        vec![true]
    );
    let proposal = fixture.proposal_from_inputs(
        vec![AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(
            reveal,
        ))],
        fixture.cadence(),
    );
    let prepared = ValidBlock::prepare_external_transactions(&proposal);
    {
        let view = fixture.chain.state().view();
        let transactions = crate::state::StateReadOnlyWithTransactions::transactions(&view);
        let signed_heights =
            ValidBlock::committed_heights_for_prepared_transactions(&prepared, transactions);
        let carrier_heights =
            ValidBlock::committed_heights_for_entrypoint_carriers(&proposal, transactions);
        assert!(signed_heights[0].is_some());
        assert!(carrier_heights[0].is_none());
    }
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::HasCommittedTransactions
    ));
    assert_eq!(fixture.chain.state().view().height(), 3);
}

#[test]
fn native_validation_rejects_missing_original_execution_context() {
    let fixture = NativeValidationFixture::new();
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    proposal.set_execution_context(None);
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(
        matches!(*error, BlockValidationError::ExecutionContextInvalid(ref message) if message.contains("missing execution context"))
    );
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_execution_context_route_substitution() {
    let fixture = NativeValidationFixture::new();
    let tx = fixture.transaction(2_001, None);
    let mut proposal = fixture.proposal(vec![tx.clone()], fixture.cadence());
    proposal.set_execution_context(Some(BlockExecutionContextBundle::new(vec![
        ExternalExecutionContext::new(
            tx.hash_as_entrypoint(),
            LaneId::new(7),
            DataSpaceId::UNIVERSAL,
        ),
    ])));
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(
        matches!(*error, BlockValidationError::ExecutionContextInvalid(ref message) if message.contains("native committed execution route"))
    );
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_unknown_execution_context_version_before_publication() {
    let fixture = NativeValidationFixture::new();
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    let generation = fixture.chain.state().state_view_generation();
    let mut context = proposal.execution_context().unwrap().clone();
    context.version = BLOCK_EXECUTION_CONTEXT_BUNDLE_VERSION_V1 + 1;
    proposal.set_execution_context(Some(context));
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(
        matches!(*error, BlockValidationError::ExecutionContextInvalid(ref message)
        if message.contains("unsupported block execution-context bundle version"))
    );
    assert_eq!(fixture.chain.state().view().height(), 2);
    assert_eq!(fixture.chain.state().state_view_generation(), generation);
}

#[test]
fn native_validation_rejects_incomplete_original_execution_context() {
    let fixture = NativeValidationFixture::new();
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    let generation = fixture.chain.state().state_view_generation();
    let mut context = proposal.execution_context().unwrap().clone();
    context.external.clear();
    proposal.set_execution_context(Some(context));
    assert!(fixture.validate(proposal).unpack(|_| {}).is_err());
    assert_eq!(fixture.chain.state().view().height(), 2);
    assert_eq!(fixture.chain.state().state_view_generation(), generation);
}

#[test]
fn native_execution_rejects_forged_and_zero_advertised_fragment_counts() {
    let fixture = NativeValidationFixture::new();
    let proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    let (_, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    assert_eq!(overlay.committed_fragment_count(), 1);
    assert_eq!(
        ValidBlock::validated_committed_fragment_count(&overlay, Some(1)).unwrap(),
        1
    );
    for actual in [0, 99] {
        assert!(
            matches!(ValidBlock::validated_committed_fragment_count(&overlay, Some(actual)),
            Err(BlockValidationError::CommittedFragmentCountMismatch { expected: 1, actual: rejected }) if rejected == actual)
        );
    }
    drop(overlay);
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_enforces_fraud_policy_with_a_populated_stateless_cache() {
    use iroha_data_model::fraud::{FraudAdmissionPolicyV1, FraudRiskBandV1};
    use iroha_primitives::json::Json;
    let fixture = NativeValidationFixture::with_configuration(|config| {
        config.pipeline.stateless_cache_cap = 64;
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Custom(
                FraudAdmissionPolicyV1 {
                    enabled: true,
                    required_minimum_band: Some(FraudRiskBandV1::High),
                    missing_assessment_permitted: false,
                    ..FraudAdmissionPolicyV1::protocol_default()
                }
                .into_custom_parameter(),
            ));
    });
    let mut low_assessment = Metadata::default();
    low_assessment.insert("fraud_assessment_band".parse().unwrap(), Json::new("low"));
    low_assessment.insert(
        "fraud_assessment_score_bps".parse().unwrap(),
        Json::new(100_u64),
    );
    low_assessment.insert(
        "fraud_assessment_tenant".parse().unwrap(),
        Json::new("native-test"),
    );
    for (transaction, expected_message) in [
        (
            fixture.transaction(2_001, None),
            "fraud monitoring requires an attached assessment",
        ),
        (
            fixture.transaction_with_metadata(2_001, None, low_assessment),
            "below required minimum",
        ),
    ] {
        for _ in 0..2 {
            let proposal = fixture.proposal(vec![transaction.clone()], fixture.cadence());
            let (valid, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
            let rejection = valid
                .as_ref()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .as_ref()
                .unwrap_err();
            assert!(matches!(rejection,
            iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted(message)
            ) if message.contains(expected_message)));
            drop(overlay);
        }
        assert!(
            fixture
                .chain
                .state()
                .stateless_validation_cache()
                .lock()
                .contains_key(&crate::tx::StatelessValidationCacheKey::new(&transaction),)
        );
    }
    assert_eq!(fixture.chain.state().view().height(), 2);
}
