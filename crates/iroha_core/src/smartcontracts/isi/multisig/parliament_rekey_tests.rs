// Parliament and account-rekey regression tests for multisig instructions.

use crate::governance::parliament::{
    PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1, ParliamentAttemptStateV1,
    canonical_governance_attempt_ids_v1, parliament_attempt_policy_v1,
};
use iroha_data_model::{
    governance::types::{
        BeaconSessionId, BodyElectionAttemptId, GovernanceAttemptId, GovernanceAttemptStatusV1,
        GovernanceAttemptV1, GovernanceExpectedHeadAbsentV1, GovernanceExpectedHeadV1,
        GovernanceStageV1, MAX_PARLIAMENT_SORTITION_RETRIES_V1, ParliamentBody, ProposalContentId,
        ProposalKind, RiskTierV1, SortitionRequestId, SortitionRequestV1,
        ValidationFeePolicyProposal, parliament_candidate_root_v1,
    },
    isi::governance::ParliamentSortitionRequestRegistrationV1,
    validation_fee::{
        VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION, ValidationFeeChargingMode,
        ValidationFeePolicyV1,
    },
};

fn validation_fee_policy_proposal_for_rekey_test(
    proposal_operator: &AccountId,
    treasury_account_id: AccountId,
    network_id: iroha_data_model::NetworkId,
) -> ProposalKind {
    let contract = iroha_data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &treasury_account_id,
        1,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("rekey fixture treasury wrapper");
    let ds_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("fee asset domain"),
        Name::from_str("ds").expect("fee asset name"),
    );
    let custody = iroha_data_model::validation_fee::ValidationFeeRewardCustodyV1 {
        treasury_account_id: contract.subject_id(),
        contract_address: contract,
        ds_asset_id: ds_asset_id.clone(),
        xor_asset_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "paynet").expect("reward asset domain"),
            Name::from_str("xor").expect("reward asset name"),
        ),
        reward_pool_account_id: treasury_account_id,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
    };
    ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: proposal_operator.clone(),
        policy: ValidationFeePolicyV1 {
            retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
            effective_from_ms: 1_793_451_600_000,
            notice_published_at_ms: 1_790_859_600_000,
            schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            network_id,
            policy_version: 1,
            previous_policy_hash: None,
            ds_asset_id,
            ds_scale: VALIDATION_FEE_DS_SCALE,
            fee: "0.10".parse().unwrap(),
            treasury_account_id: custody.treasury_account_id.clone(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

            exemption_classes: vec!["TREASURY_PAYOUT".into()],
            reward_custody: custody,
        },
    })
}

fn exhausted_validation_fee_attempt_for_rekey_test(
    proposal: &ProposalKind,
) -> ParliamentAttemptStateV1 {
    let governance_attempt_sequence = 0;
    let proposal_content_id = ProposalContentId::new(proposal.fingerprint());
    let governance_attempt_id =
        GovernanceAttemptId::derive_v1(proposal_content_id, governance_attempt_sequence);
    let (risk_tier, required_bodies) = parliament_attempt_policy_v1(proposal);
    let mut attempt = ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: governance_attempt_sequence,
            risk_tier,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        1,
        3,
        proposal.effect_preimage_hash_v1(),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: proposal
                .governed_subject_id_v1()
                .expect("derive validation-fee proposal subject"),
        }),
        required_bodies.clone(),
    )
    .expect("construct proposal-bound rejected Parliament attempt");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("complete rejected-attempt qualification");

    for sortition_sequence in 0..=MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        let request_height = 10_u64 + u64::from(sortition_sequence);
        let registrations = required_bodies
            .iter()
            .filter(|required| required.body != ParliamentBody::ConfirmationJury)
            .map(|required| {
                let body = required.body;
                let mut request = SortitionRequestV1 {
                    id: SortitionRequestId::new([0; 32]),
                    governance_attempt_id,
                    body_election_attempt_id: BodyElectionAttemptId::derive_v1(
                        governance_attempt_id,
                        body,
                        sortition_sequence,
                    ),
                    body,
                    candidate_root: parliament_candidate_root_v1(governance_attempt_id, body, &[]),
                    candidate_count: 0,
                    target_seats: 3,
                    request_height,
                    pulse_height: request_height + 1,
                    beacon_session_id: BeaconSessionId::new([0x51; 32]),
                };
                request.id = request.canonical_id();
                ParliamentSortitionRequestRegistrationV1 {
                    sequence: sortition_sequence,
                    request,
                }
            })
            .collect();
        attempt
            .record_hidden_sortition_capacity_failure_batch(
                governance_attempt_id,
                registrations,
                Vec::new(),
            )
            .expect("exhaust hidden-electorate capacity for rejected-attempt fixture");
    }
    assert_eq!(
        attempt.attempt().status,
        GovernanceAttemptStatusV1::Rejected
    );
    attempt
        .validate_proposal_bindings_v1(proposal)
        .expect("rejected attempt retains exact validation-fee proposal bindings");
    attempt
}

#[test]
fn account_rekey_rejects_active_parliament_candidate_without_partial_mutation() {
    use crate::governance::parliament::{ParliamentDecisionModeV1, RequiredParliamentBodyV1};

    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-active-parliament-candidate"
    );
    let domain_id = DomainId::try_new("parliament", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    let other_candidate = new_account_id(&checked_keypair());
    let third_candidate = new_account_id(&checked_keypair());
    domain!(
        tx,
        old_account,
        domain_id,
        "register Parliament test domain"
    );
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register active Parliament candidate"
    );

    let proposal_content_id = ProposalContentId::new([0x41; 32]);
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let mut attempt = ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: 0,
            risk_tier: RiskTierV1::Standard,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        1,
        1,
        3,
        [0x42; 32],
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: [0x43; 32],
        }),
        vec![RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        }],
    )
    .expect("construct active Parliament rekey fixture");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("complete fixture qualification");
    let mut candidates = vec![old_account.clone(), other_candidate, third_candidate];
    candidates.sort_unstable();
    let election_attempt_id =
        BodyElectionAttemptId::derive_v1(governance_attempt_id, ParliamentBody::PolicyJury, 0);
    let request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        election_attempt_id,
        ParliamentBody::PolicyJury,
        parliament_candidate_root_v1(
            governance_attempt_id,
            ParliamentBody::PolicyJury,
            &candidates,
        ),
        3,
        3,
        1,
        2,
        BeaconSessionId::new([0x44; 32]),
        None,
    )
    .expect("construct active Parliament sortition request");
    attempt
        .register_sortition_request_batch(
            governance_attempt_id,
            vec![ParliamentSortitionRequestRegistrationV1 {
                sequence: 0,
                request,
            }],
            candidates,
        )
        .expect("freeze active Parliament candidate snapshot");
    tx.world
        .put_parliament_attempt(attempt)
        .expect("persist active Parliament rekey fixture");

    let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect_err("active Parliament candidate identity must remain immutable");
    assert!(
        error
            .to_string()
            .contains("retained by an active or certified Parliament attempt"),
        "unexpected error: {error}"
    );
    assert!(tx.world.account(&old_account).is_ok());
    assert!(matches!(
        tx.world.account(&new_account),
        Err(FindError::Account(account)) if account == new_account
    ));
}

#[test]
fn account_rekey_rejects_immutable_validation_fee_authorization_without_partial_mutation() {
    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-validation-fee-authorization",
        21_u64,
        0
    );
    let domain_id = DomainId::try_new("feeauth", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    let treasury = new_account_id(&checked_keypair());
    domain!(
        tx,
        old_account,
        domain_id,
        "register fee authorization domain"
    );
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register fee proposal operator"
    );
    let proposal = validation_fee_policy_proposal_for_rekey_test(
        &old_account,
        treasury,
        tx.network_id.clone(),
    );
    let proposal_id = proposal.fingerprint();
    let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
        &proposal,
        vec![
            new_account_id(&checked_keypair()),
            new_account_id(&checked_keypair()),
            new_account_id(&checked_keypair()),
        ],
        &tx.network_id,
        20,
    );
    tx.world
        .put_parliament_attempt(attempt)
        .expect("persist enacted validation-fee Parliament authorization");
    tx.world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: old_account.clone(),
                kind: proposal,
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Enacted,
            },
        )
        .expect("persist enacted validation-fee proposal");

    let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect_err("validation-fee proposal identities are hash-bound");
    assert!(
        error
            .to_string()
            .contains("operator-bound Parliament authorization"),
        "unexpected error: {error}"
    );
    assert!(tx.world.account(&old_account).is_ok());
    assert!(matches!(
        tx.world.account(&new_account),
        Err(FindError::Account(account)) if account == new_account
    ));
    let retained = tx
        .world
        .governance_proposals
        .get(&proposal_id)
        .expect("rejected rekey preserves fee proposal");
    assert_eq!(retained.proposer, old_account);
}

#[test]
fn account_rekey_rejects_live_deploy_operator_without_partial_mutation() {
    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-live-deploy-operator"
    );
    let domain_id = DomainId::try_new("deployauth", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    domain!(
        tx,
        old_account,
        domain_id,
        "register deploy operator domain"
    );
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register deploy proposal operator"
    );
    let proposal = ProposalKind::DeployContract(
        iroha_data_model::governance::types::DeployContractProposal {
            proposal_operator: old_account.clone(),
            contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address"),
            code_hash: iroha_data_model::governance::types::ContractCodeHash::new([0x31; 32]),
            abi_hash: iroha_data_model::governance::types::ContractAbiHash::new([0x41; 32]),
            abi_version: iroha_data_model::governance::types::AbiVersion::new(1),
            manifest_provenance: None,
        },
    );
    let proposal_id = proposal.fingerprint();
    tx.world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: old_account.clone(),
                kind: proposal,
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Proposed,
            },
        )
        .expect("persist live operator-bound deploy proposal");

    let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect_err("a live deploy operator identity must remain immutable");
    assert!(
        error
            .to_string()
            .contains("operator-bound Parliament authorization"),
        "unexpected error: {error}"
    );
    assert!(tx.world.account(&old_account).is_ok());
    assert!(matches!(
        tx.world.account(&new_account),
        Err(FindError::Account(account)) if account == new_account
    ));
    assert_eq!(
        tx.world
            .governance_proposals
            .get(&proposal_id)
            .expect("failed rekey preserves deploy proposal")
            .proposer,
        old_account
    );
}

#[test]
fn account_rekey_rejects_live_contract_ownership_recipient_without_partial_mutation() {
    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-live-contract-ownership-recipient"
    );
    let domain_id = DomainId::try_new("contractoffer", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    let proposal_operator = new_account_id(&checked_keypair());
    domain!(
        tx,
        old_account,
        domain_id,
        "register contract-offer recipient domain"
    );
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register contract-offer recipient"
    );
    account!(
        tx,
        old_account,
        domain_id,
        proposal_operator,
        "register contract-offer operator"
    );
    let proposal = ProposalKind::ContractLifecycleGovernance(
        iroha_data_model::governance::types::ContractLifecycleGovernanceProposalV1 {
            proposal_operator: proposal_operator.clone(),
            contract_address:
                "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                    .parse()
                    .expect("contract address"),
            expected_revision: 1,
            action: iroha_data_model::governance::types::ContractLifecycleGovernanceActionV1::OfferOwnership(
                iroha_data_model::governance::types::OfferContractOwnershipGovernanceActionV1 {
                    new_owner: old_account.clone(),
                },
            ),
        },
    );
    let proposal_id = proposal.fingerprint();
    tx.world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: proposal_operator,
                kind: proposal.clone(),
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Proposed,
            },
        )
        .expect("persist live contract ownership offer");

    let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect_err("a live ownership recipient identity must remain immutable");
    assert!(
        error
            .to_string()
            .contains("operator-bound Parliament authorization"),
        "unexpected error: {error}"
    );
    assert!(tx.world.account(&old_account).is_ok());
    assert!(matches!(
        tx.world.account(&new_account),
        Err(FindError::Account(account)) if account == new_account
    ));
    let retained = tx
        .world
        .governance_proposals
        .get(&proposal_id)
        .expect("failed rekey preserves contract ownership offer");
    assert_eq!(retained.kind, proposal);
    assert_eq!(retained.kind.fingerprint(), proposal_id);
}

#[test]
fn account_rekey_rejects_terminal_validation_fee_without_proven_exhaustion() {
    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-retryable-terminal-fee-history"
    );
    let domain_id = DomainId::try_new("feeretry", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    domain!(tx, old_account, domain_id, "register fee retry domain");
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register retryable fee operator"
    );
    let proposal = validation_fee_policy_proposal_for_rekey_test(
        &old_account,
        new_account_id(&checked_keypair()),
        tx.network_id.clone(),
    );
    let proposal_id = proposal.fingerprint();
    tx.world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: old_account.clone(),
                kind: proposal.clone(),
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Rejected,
            },
        )
        .expect("persist terminal validation-fee proposal with missing attempt history");

    let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect_err("missing attempt history must not prove redraw exhaustion");
    assert!(
        error
            .to_string()
            .contains("operator-bound Parliament authorization"),
        "unexpected error: {error}"
    );
    assert!(tx.world.account(&old_account).is_ok());
    assert!(matches!(
        tx.world.account(&new_account),
        Err(FindError::Account(account)) if account == new_account
    ));
    let retained = tx
        .world
        .governance_proposals
        .get(&proposal_id)
        .expect("failed rekey preserves unproven fee history");
    assert_eq!(retained.proposer, old_account);
    assert_eq!(retained.kind, proposal);
    assert_eq!(
        retained.status,
        crate::state::GovernanceProposalStatus::Rejected
    );
}

#[test]
fn account_rekey_preserves_exhausted_terminal_validation_fee_history() {
    tx!(
        state,
        block,
        tx,
        World::new(),
        "multisig-rekey-exhausted-terminal-fee-history"
    );
    let domain_id = DomainId::try_new("feeexhaust", "universal").expect("domain id");
    let old_account = new_account_id(&checked_keypair());
    let new_account = new_account_id(&checked_keypair());
    domain!(tx, old_account, domain_id, "register exhausted fee domain");
    account!(
        tx,
        old_account,
        domain_id,
        old_account,
        "register exhausted fee operator"
    );
    let proposal = validation_fee_policy_proposal_for_rekey_test(
        &old_account,
        new_account_id(&checked_keypair()),
        tx.network_id.clone(),
    );
    let proposal_id = proposal.fingerprint();
    let proposal_bytes = norito::encode_canonical(&proposal)
        .expect("encode exhausted terminal proposal before account rekey");
    tx.world
        .put_parliament_attempt(exhausted_validation_fee_attempt_for_rekey_test(&proposal))
        .expect("persist one attempt that exhausts the proposal-wide redraw budget");
    tx.world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: old_account.clone(),
                kind: proposal.clone(),
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Rejected,
            },
        )
        .expect("persist exhausted rejected validation-fee proposal");

    rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
        .expect("provably exhausted terminal fee history must not deny account rekey forever");
    assert!(matches!(
        tx.world.account(&old_account),
        Err(FindError::Account(account)) if account == old_account
    ));
    assert!(tx.world.account(&new_account).is_ok());
    let retained = tx
        .world
        .governance_proposals
        .get(&proposal_id)
        .expect("successful rekey retains exhausted fee history");
    assert_eq!(retained.proposer, old_account);
    assert_eq!(retained.kind, proposal);
    assert_eq!(retained.kind.fingerprint(), proposal_id);
    assert_eq!(
        norito::encode_canonical(&retained.kind)
            .expect("encode exhausted terminal proposal after account rekey"),
        proposal_bytes
    );
    assert_eq!(
        retained.status,
        crate::state::GovernanceProposalStatus::Rejected
    );
    let retained_attempts =
        canonical_governance_attempt_ids_v1(ProposalContentId::new(proposal_id))
            .filter_map(|attempt_id| tx.world.parliament_attempts.get(&attempt_id))
            .count();
    assert_eq!(retained_attempts, 1);
}
