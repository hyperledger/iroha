#[test]
fn accepted_challenge_blocks_reveal_and_closes_without_penalties() {
    let mut fixture = Fixture::new(1);
    let juror = fixture.juror_id(0);
    let challenger = account(&fixture.outsider);
    let reveal = reveal(&fixture.spec, &juror, SoraFsModerationVoteChoice::Uphold, 5);
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal))).execute(&juror, transaction)
        })
        .unwrap();
    assert!(
        fixture
            .run(1_600, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-1".to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x51; 32],
                    "wrong evidence".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "missing-target".to_owned(),
                    ModerationChallengeKindV1::DuplicateCommit,
                    None,
                    [0x50; 32],
                    "target required".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .is_err()
    );
    for (challenge_id, reason) in [
        ("challenge\nbad", "canonical reason"),
        ("challengé", "canonical reason"),
        ("challenge-control", "line\nbreak"),
    ] {
        assert!(
            fixture
                .run(2_500, |transaction| {
                    RaiseSorafsModerationChallenge::new(
                        "case-1".to_owned(),
                        "round-1".to_owned(),
                        challenge_id.to_owned(),
                        ModerationChallengeKindV1::EvidenceMismatch,
                        None,
                        [0x50; 32],
                        reason.to_owned(),
                    )
                    .execute(&challenger, transaction)
                })
                .is_err()
        );
    }
    let unregistered_challenger = account(&keypair(0x7F));
    assert!(
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-unregistered".to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x50; 32],
                    "canonical reason".to_owned(),
                )
                .execute(&unregistered_challenger, transaction)
            })
            .is_err()
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .unwrap()
            .challenge_count,
        0
    );
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x51; 32],
                "wrong evidence".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .unwrap();
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
    let case_after_first = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .expect("case after first challenge");
    let status_after_first = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .expect("status after first challenge");
    let juror_balance_after_first = voting_asset_balance(&fixture.state, &juror);
    assert!(
        fixture
            .run(2_501, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-1".to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x52; 32],
                    "duplicate".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(2_502, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-second".to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x53; 32],
                    "same challenger".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .is_err()
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .expect("case after duplicate rejections"),
        case_after_first,
        "duplicate id and challenger rejections must preserve all case counters and indexes"
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .expect("status after duplicate rejections"),
        status_after_first,
        "duplicate challenge rejections must preserve global counters"
    );
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
    assert_eq!(
        voting_asset_balance(&fixture.state, &juror),
        juror_balance_after_first,
        "duplicate evidence rejection must not debit its alternate challenger"
    );
    assert!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-second".to_owned(),
        )
        .execute(&fixture.state.view())
        .is_err(),
        "duplicate challenger rejection must not retain a record"
    );
    assert!(
        fixture
            .run(2_502, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-same-evidence".to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x51; 32],
                    "same evidence".to_owned(),
                )
                .execute(&juror, transaction)
            })
            .is_err()
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .expect("case after duplicate evidence rejection"),
        case_after_first
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .expect("status after duplicate evidence rejection"),
        status_after_first
    );
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
    assert_eq!(
        voting_asset_balance(&fixture.state, &juror),
        juror_balance_after_first,
        "duplicate evidence rejection must not debit its alternate challenger"
    );
    assert!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-same-evidence".to_owned(),
        )
        .execute(&fixture.state.view())
        .is_err(),
        "duplicate evidence rejection must not retain a record"
    );
    assert!(
        fixture
            .run(3_500, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&reveal)).execute(&juror, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(3_500, |transaction| {
                ResolveSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-1".to_owned(),
                    ModerationChallengeDecisionV1::Accepted,
                )
                .execute(&challenger, transaction)
            })
            .is_err()
    );
    let manager = fixture.manager_id();
    fixture
        .run(2_900, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
                ModerationChallengeDecisionV1::Accepted,
            )
            .execute(&manager, transaction)
        })
        .unwrap();
    assert!(
        fixture
            .run(REVEAL_AT, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&reveal)).execute(&juror, transaction)
            })
            .is_err()
    );
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .unwrap();
    let outcome = FindSorafsModerationOutcome::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(outcome.kind, ModerationOutcomeKindV1::Challenged);
    assert_eq!(outcome.no_show_count, 0);
    let challenge = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-1".to_owned(),
    )
    .execute(&fixture.state.view())
    .unwrap();
    assert_eq!(
        challenge.bond.refunded_amount,
        Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1)
    );
    assert_eq!(challenge.bond.slashed_amount, Quantity::zero());
    assert_bond_custody_distribution(&fixture.state, &challenger, 1_000, 0, 0);
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .unwrap()
            .no_shows,
        0
    );
}
#[test]
fn pending_challenge_retains_challenger_until_permissionless_expiry_settles() {
    let mut fixture = Fixture::new(1);
    let challenger = account(&fixture.outsider);
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-retains-account".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x74; 32],
                "retain refund destination".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("raise bonded challenge");
    let error = fixture
        .run(2_501, |transaction| {
            Unregister::account(challenger.clone()).execute(&challenger, transaction)
        })
        .expect_err("pending challenger must remain a valid refund destination");
    assert!(
        error
            .to_string()
            .contains("retained by moderation pending challenge")
            && error.to_string().contains("challenge-retains-account"),
        "unexpected retained-account error: {error}"
    );
    assert!(fixture.state.view().world().account(&challenger).is_ok());
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
    let expiry_authority = fixture.juror_id(0);
    fixture
        .run(CHALLENGE_RESOLUTION_DEADLINE + 1, |transaction| {
            ExpireSorafsModerationChallenge {
                case_id: "case-1".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-retains-account".to_owned(),
            }
            .execute(&expiry_authority, transaction)
        })
        .expect("permissionless expiry refunds the retained challenger");
    assert_bond_custody_distribution(&fixture.state, &challenger, 1_000, 0, 0);
    fixture
        .run(CHALLENGE_RESOLUTION_DEADLINE + 2, |transaction| {
            Unregister::account(challenger.clone()).execute(&challenger, transaction)
        })
        .expect("settled challenger is no longer retained by moderation");
    assert!(fixture.state.view().world().account(&challenger).is_err());
}
#[test]
fn pending_challenge_blocks_native_multisig_controller_rekey() {
    let mut fixture = Fixture::new(1);
    let initial_signer = account(&fixture.outsider);
    let added_signatory = fixture
        .juror_id(0)
        .controller()
        .single_signatory()
        .expect("juror is a single-signatory account")
        .clone();
    let spec = MultisigSpec {
        signatories: BTreeMap::from([(initial_signer.clone(), 1)]),
        quorum: NonZeroU16::new(1).expect("nonzero quorum"),
        transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
            .expect("nonzero transaction ttl"),
    };
    let member = MultisigMember::new(fixture.outsider.public_key().clone(), 1)
        .expect("valid multisig member");
    let challenger = AccountId::new_multisig(
        MultisigPolicy::new(1, vec![member]).expect("valid multisig policy"),
    );
    let registration_seed = account(&keypair(0x32));
    let voting_asset_id = fixture.state.gov.voting_asset_id.clone();
    fixture
        .run(2_400, |transaction| {
            crate::smartcontracts::isi::multisig::execute_multisig_instruction(
                transaction,
                &initial_signer,
                MultisigInstructionBox::Register(MultisigRegister::with_account(
                    registration_seed,
                    None::<iroha_model_base::domain::DomainId>,
                    spec,
                )),
            )
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(error.to_string().into())
            })?;
            Transfer::asset_quantity(
                AssetId::new(voting_asset_id, initial_signer.clone()),
                1_000_u32,
                challenger.clone(),
            )
            .execute(&initial_signer, transaction)
        })
        .expect("register and fund native multisig challenger");
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-retains-multisig".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x75; 32],
                "retain multisig refund destination".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("raise challenge from native multisig account");

    let error = fixture
        .run(2_501, |transaction| {
            AddSignatory::new(challenger.clone(), added_signatory).execute(&challenger, transaction)
        })
        .expect_err("pending challenger must not escape retention through controller rekey");
    assert!(
        error
            .to_string()
            .contains("retained by moderation pending challenge")
            && error.to_string().contains("challenge-retains-multisig"),
        "unexpected retained-rekey error: {error}"
    );
    assert!(fixture.state.view().world().account(&challenger).is_ok());
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
}
#[test]
fn finalization_stages_multiple_expiries_against_declining_bond_liability() {
    let mut fixture = Fixture::new(1);
    let challengers = [account(&fixture.outsider), fixture.juror_id(0)];
    let challenge_ids = ["challenge-expiry-a", "challenge-expiry-b"];
    for ((challenger, challenge_id), evidence) in challengers
        .iter()
        .zip(challenge_ids)
        .zip([[0x76; 32], [0x77; 32]])
    {
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    challenge_id.to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    evidence,
                    "expire together during finalization".to_owned(),
                )
                .execute(challenger, transaction)
            })
            .expect("raise one of two pending challenges");
    }
    let current_policy = policy();
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::from(300_u32)
    );

    let manager = fixture.manager_id();
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .expect("both indexed pending challenges expire in one finalization");

    let case = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .expect("finalized case");
    assert_eq!(case.status, ModerationCaseStatusV1::Finalized);
    assert_eq!(case.pending_challenge_count, 0);
    assert_eq!(case.expired_challenge_count, 2);
    for (challenger, challenge_id) in challengers.iter().zip(challenge_ids) {
        let challenge = FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            challenge_id.to_owned(),
        )
        .execute(&fixture.state.view())
        .expect("expired challenge");
        assert_eq!(
            challenge.decision,
            Some(ModerationChallengeDecisionV1::Expired)
        );
        assert_eq!(
            challenge.bond.refunded_amount,
            Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1)
        );
        assert_eq!(
            voting_asset_balance(&fixture.state, challenger),
            Quantity::from(1_000_u32)
        );
    }
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::zero()
    );
}
#[test]
fn later_finalization_expiry_failure_rolls_back_prior_staged_expiry() {
    let mut fixture = Fixture::new(1);
    let first_challenger = account(&fixture.outsider);
    let second_challenger = fixture.juror_id(0);
    for (challenger, challenge_id, evidence) in [
        (
            first_challenger.clone(),
            "challenge-staged-rollback-a",
            [0x78; 32],
        ),
        (
            second_challenger.clone(),
            "challenge-staged-rollback-b",
            [0x79; 32],
        ),
    ] {
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    challenge_id.to_owned(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    evidence,
                    "prove staged expiry rollback".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .expect("raise one of two rollback challenges");
    }
    let case_before = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .expect("pending case before failed finalization");
    let first_before = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-staged-rollback-a".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("first pending challenge before failed finalization");
    let second_before = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-staged-rollback-b".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("second pending challenge before failed finalization");
    let current_policy = policy();

    let manager = fixture.manager_id();
    let error = fixture
        .run(FINALIZE_AT, |transaction| {
            assert!(
                transaction
                    .world
                    .accounts
                    .remove(second_challenger.clone())
                    .is_some()
            );
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .expect_err("the second expiry refund destination is deliberately missing");
    assert!(
        matches!(&error, InstructionExecutionError::Find(FindError::Account(missing)) if missing == &second_challenger),
        "unexpected later-expiry failure: {error}"
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .expect("case after failed finalization"),
        case_before
    );
    assert_eq!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-staged-rollback-a".to_owned(),
        )
        .execute(&fixture.state.view())
        .expect("first challenge after failed finalization"),
        first_before,
        "the first staged record transition must roll back"
    );
    assert_eq!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-staged-rollback-b".to_owned(),
        )
        .execute(&fixture.state.view())
        .expect("second challenge after failed finalization"),
        second_before
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &first_challenger),
        Quantity::from(850_u32),
        "the first staged refund must roll back"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &second_challenger),
        Quantity::from(850_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::from(300_u32)
    );
    assert!(
        fixture
            .state
            .view()
            .world()
            .account(&second_challenger)
            .is_ok()
    );
}
#[test]
fn unresolved_challenge_expires_permissionlessly_and_fails_open() {
    let mut fixture = Fixture::new(1);
    let juror = fixture.juror_id(0);
    let challenger = account(&fixture.outsider);
    let reveal = reveal(
        &fixture.spec,
        &juror,
        SoraFsModerationVoteChoice::Uphold,
        0x44,
    );
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal))).execute(&juror, transaction)
        })
        .unwrap();
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-unresolved".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x72; 32],
                "awaiting adjudication".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .unwrap();
    let manager = fixture.manager_id();
    fixture
        .run(2_501, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-swept".to_owned(),
                ModerationChallengeKindV1::Other,
                None,
                [0x73; 32],
                "awaiting final sweep".to_owned(),
            )
            .execute(&manager, transaction)
        })
        .unwrap();
    let current_policy = policy();
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &manager),
        Quantity::from(850_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::from(300_u32)
    );
    assert_eq!(
        voting_asset_balance(
            &fixture.state,
            &current_policy.challenge_slash_receiver_account,
        ),
        Quantity::from(300_u32)
    );
    assert_unique_voting_asset_total(
        &fixture.state,
        &[
            challenger.clone(),
            manager.clone(),
            current_policy.challenge_escrow_account.clone(),
            current_policy.challenge_slash_receiver_account.clone(),
        ],
        2_000,
    );
    assert!(
        fixture
            .run(2_600, |transaction| {
                ResolveSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-unresolved".to_owned(),
                    ModerationChallengeDecisionV1::Expired,
                )
                .execute(&manager, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(CHALLENGE_RESOLUTION_DEADLINE + 1, |transaction| {
                ResolveSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    "challenge-unresolved".to_owned(),
                    ModerationChallengeDecisionV1::Rejected,
                )
                .execute(&manager, transaction)
            })
            .is_err()
    );
    fixture
        .run(REVEAL_AT, |transaction| {
            SubmitSorafsModerationReveal::new(encode(&reveal)).execute(&juror, transaction)
        })
        .unwrap();
    fixture
        .run(REVEAL_AT + 1, |transaction| {
            ExpireSorafsModerationChallenge {
                case_id: "case-1".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-unresolved".to_owned(),
            }
            .execute(&juror, transaction)
        })
        .unwrap();
    fixture
        .run(REVEAL_AT + 2, |transaction| {
            ExpireSorafsModerationChallenge {
                case_id: "case-1".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-unresolved".to_owned(),
            }
            .execute(&juror, transaction)
        })
        .unwrap();
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .unwrap();
    fixture
        .run(FINALIZE_AT + 1, |transaction| {
            ExpireSorafsModerationChallenge {
                case_id: "case-1".to_owned(),
                round_id: "round-1".to_owned(),
                challenge_id: "challenge-swept".to_owned(),
            }
            .execute(&juror, transaction)
        })
        .unwrap();
    let case = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(case.pending_challenge_count, 0);
    assert_eq!(case.expired_challenge_count, 2);
    let challenge = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-unresolved".to_owned(),
    )
    .execute(&fixture.state.view())
    .unwrap();
    assert_eq!(
        challenge.decision,
        Some(ModerationChallengeDecisionV1::Expired)
    );
    assert_eq!(challenge.resolved_by, Some(juror));
    assert_eq!(
        challenge.bond.refunded_amount,
        Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1)
    );
    assert_eq!(challenge.bond.slashed_amount, Quantity::zero());
    assert_bond_custody_distribution(&fixture.state, &challenger, 1_000, 0, 0);
    assert_bond_custody_distribution(&fixture.state, &manager, 1_000, 0, 0);
    assert_unique_voting_asset_total(
        &fixture.state,
        &[
            challenger.clone(),
            manager.clone(),
            current_policy.challenge_escrow_account,
            current_policy.challenge_slash_receiver_account,
        ],
        2_000,
    );
    let outcome = FindSorafsModerationOutcome::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(
        outcome.kind,
        ModerationOutcomeKindV1::Decided(SoraFsModerationVoteChoice::Uphold)
    );
    assert_eq!(outcome.votes_total, 1);
    assert_eq!(outcome.no_show_count, 2);
    for index in [1, 2] {
        let no_show = FindSorafsModerationNoShow::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            fixture.juror_id(index),
        )
        .execute(&fixture.state.view())
        .expect("absent juror retains ordinary no-show penalty");
        assert_eq!(no_show.kind, ModerationNoShowKindV1::MissingCommit);
        assert_eq!(
            no_show.penalty_points,
            policy().missing_commit_penalty_points
        );
    }
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .unwrap()
            .no_shows,
        2
    );
}
#[test]
fn rejected_challenge_unblocks_reveals_and_tied_quorum_is_contested() {
    let mut fixture = Fixture::new(2);
    let juror0 = fixture.juror_id(0);
    let juror1 = fixture.juror_id(1);
    let challenger = account(&fixture.outsider);
    let reveal0 = reveal(
        &fixture.spec,
        &juror0,
        SoraFsModerationVoteChoice::Uphold,
        10,
    );
    let reveal1 = reveal(
        &fixture.spec,
        &juror1,
        SoraFsModerationVoteChoice::Overturn,
        11,
    );
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal0)))
                .execute(&juror0, transaction)?;
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal1)))
                .execute(&juror1, transaction)
        })
        .unwrap();
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-rejected".to_owned(),
                ModerationChallengeKindV1::PayloadMismatch,
                Some(juror0.clone()),
                [0x71; 32],
                "payload reviewed".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .unwrap();
    assert_bond_custody_distribution(&fixture.state, &challenger, 850, 150, 150);
    let manager = fixture.manager_id();
    fixture
        .run(2_600, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-rejected".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            )
            .execute(&manager, transaction)
        })
        .unwrap();
    fixture
        .run(REVEAL_AT, |transaction| {
            SubmitSorafsModerationReveal::new(encode(&reveal0)).execute(&juror0, transaction)?;
            SubmitSorafsModerationReveal::new(encode(&reveal1)).execute(&juror1, transaction)
        })
        .unwrap();
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .unwrap();
    let challenge = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-rejected".to_owned(),
    )
    .execute(&fixture.state.view())
    .unwrap();
    assert_eq!(
        challenge.decision,
        Some(ModerationChallengeDecisionV1::Rejected)
    );
    assert_eq!(challenge.bond.refunded_amount, Quantity::from(113_u32));
    assert_eq!(challenge.bond.slashed_amount, Quantity::from(37_u32));
    assert_bond_custody_distribution(&fixture.state, &challenger, 963, 37, 37);
    let outcome = FindSorafsModerationOutcome::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(outcome.kind, ModerationOutcomeKindV1::Contested);
    assert_eq!(outcome.votes_total, 2);
}
#[test]
fn retained_challenge_settlements_ignore_post_funding_issuer_and_account_controls() {
    for (label, decision, expected_refund, expected_slash) in [
        (
            "accepted",
            ModerationChallengeDecisionV1::Accepted,
            150_u32,
            0_u32,
        ),
        (
            "rejected",
            ModerationChallengeDecisionV1::Rejected,
            113_u32,
            37_u32,
        ),
        (
            "expired",
            ModerationChallengeDecisionV1::Expired,
            150_u32,
            0_u32,
        ),
    ] {
        let escrow = account(&keypair(0x22));
        let slash_receiver = account(&keypair(0x23));
        let case_policy = policy_with_custody(escrow.clone(), slash_receiver.clone());
        let mut fixture = Fixture::new_with_policy(1, case_policy.clone());
        let challenger = account(&fixture.outsider);
        let manager = fixture.manager_id();
        let definition = case_policy.challenge_voting_asset_id.clone();
        let challenge_id = format!("challenge-controlled-{label}");
        fixture
            .run(2_500, |transaction| {
                RaiseSorafsModerationChallenge::new(
                    "case-1".to_owned(),
                    "round-1".to_owned(),
                    challenge_id.clone(),
                    ModerationChallengeKindV1::EvidenceMismatch,
                    None,
                    [0x7B; 32],
                    "settlement remains mandatory after funding".to_owned(),
                )
                .execute(&challenger, transaction)
            })
            .expect("fund a bond under distinct pinned custody");
        fixture
            .run(2_501, |transaction| {
                SetKeyValue::asset_definition(
                    definition.clone(),
                    ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
                        .parse()
                        .expect("issuer usage metadata key"),
                    Json::new(AssetIssuerUsagePolicyV1 {
                        require_subject_binding: true,
                        subject_bindings: BTreeMap::new(),
                    }),
                )
                .execute(&manager, transaction)?;
                SetAssetTransferControl::new(
                    escrow.clone(),
                    definition.clone(),
                    vec![AssetTransferLimit {
                        window: AssetTransferControlWindow::Day,
                        cap_amount: Some(Quantity::zero()),
                    }],
                )
                .execute(&manager, transaction)?;
                SetAssetTransferBlacklist::new(escrow.clone(), definition.clone(), true)
                    .execute(&manager, transaction)?;
                SetAssetTransferAvailability::new(
                    escrow.clone(),
                    definition.clone(),
                    0,
                    AssetTransferAvailability::Enabled,
                    AssetTransferAvailability::Disabled,
                    Some("post-funding escrow hold".to_owned()),
                )
                .execute(&manager, transaction)?;
                SetAssetTransferAvailability::new(
                    challenger.clone(),
                    definition.clone(),
                    0,
                    AssetTransferAvailability::Disabled,
                    AssetTransferAvailability::Enabled,
                    Some("post-funding refund hold".to_owned()),
                )
                .execute(&manager, transaction)?;
                SetAssetHoldingLimit::new(
                    challenger.clone(),
                    definition.clone(),
                    Some(Quantity::from(850_u32)),
                )
                .execute(&manager, transaction)?;
                SetAssetTransferAvailability::new(
                    slash_receiver.clone(),
                    definition.clone(),
                    0,
                    AssetTransferAvailability::Disabled,
                    AssetTransferAvailability::Enabled,
                    Some("post-funding slash hold".to_owned()),
                )
                .execute(&manager, transaction)?;
                SetAssetHoldingLimit::new(
                    slash_receiver.clone(),
                    definition.clone(),
                    Some(Quantity::from(1_000_u32)),
                )
                .execute(&manager, transaction)
            })
            .expect("install issuer and ordinary controls only after the bond is funded");

        let ordinary_source = fixture.juror_id(0);
        let issuer_usage_error = fixture
            .run(2_502, |transaction| {
                Transfer::asset_quantity(
                    AssetId::new(definition.clone(), ordinary_source.clone()),
                    1_u32,
                    manager.clone(),
                )
                .execute(&ordinary_source, transaction)
            })
            .expect_err("post-funding issuer policy must deny an ordinary transfer");
        assert!(
            issuer_usage_error
                .to_string()
                .contains("requires explicit subject binding"),
            "unexpected issuer-usage rejection for {label}: {issuer_usage_error}"
        );

        let ordinary_error = fixture
            .run(2_502, |transaction| {
                Transfer::asset_quantity(
                    AssetId::new(definition.clone(), escrow.clone()),
                    1_u32,
                    manager.clone(),
                )
                .execute(&escrow, transaction)
            })
            .expect_err("ordinary custody transfer must remain subject to the new controls");
        assert!(
            matches!(
                ordinary_error,
                InstructionExecutionError::AssetTransferAdmission(_)
            ),
            "unexpected ordinary-control rejection for {label}: {ordinary_error}"
        );

        if decision == ModerationChallengeDecisionV1::Expired {
            fixture
                .run(CHALLENGE_RESOLUTION_DEADLINE + 1, |transaction| {
                    ExpireSorafsModerationChallenge {
                        case_id: "case-1".to_owned(),
                        round_id: "round-1".to_owned(),
                        challenge_id: challenge_id.clone(),
                    }
                    .execute(&manager, transaction)
                })
                .expect("retained expiry refund overrides ordinary account controls");
        } else {
            fixture
                .run(2_600, |transaction| {
                    ResolveSorafsModerationChallenge::new(
                        "case-1".to_owned(),
                        "round-1".to_owned(),
                        challenge_id.clone(),
                        decision,
                    )
                    .execute(&manager, transaction)
                })
                .expect("retained resolution settlement overrides ordinary account controls");
        }
        let challenge = FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            challenge_id,
        )
        .execute(&fixture.state.view())
        .expect("settled controlled challenge");
        assert_eq!(challenge.decision, Some(decision));
        assert_eq!(
            challenge.bond.refunded_amount,
            Quantity::from(expected_refund)
        );
        assert_eq!(
            challenge.bond.slashed_amount,
            Quantity::from(expected_slash)
        );
        assert_eq!(
            voting_asset_balance(&fixture.state, &challenger),
            Quantity::from(850_u32 + expected_refund)
        );
        assert_eq!(
            voting_asset_balance(&fixture.state, &escrow),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            voting_asset_balance(&fixture.state, &slash_receiver),
            Quantity::from(1_000_u32 + expected_slash)
        );
        assert_unique_voting_asset_total(
            &fixture.state,
            &[challenger, escrow, slash_receiver],
            3_000,
        );
    }
}
#[test]
fn undercollateralized_challenge_settlement_rejects_before_refund() {
    let mut fixture = Fixture::new(1);
    let challenger = account(&fixture.outsider);
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-rollback".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x74; 32],
                "exercise settlement rollback".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("fund the challenge bond");
    let current_policy = policy();
    let escrow_asset = AssetId::new(
        fixture.state.gov.voting_asset_id.clone(),
        current_policy.challenge_escrow_account.clone(),
    );
    fixture
        .run(2_501, |transaction| {
            crate::smartcontracts::isi::asset::isi::replace_numeric_asset_balance_for_corruption_test(
                &mut transaction.world,
                &escrow_asset,
                Quantity::from(149_u32),
            );
            Ok(())
        })
        .expect("simulate one-unit custody undercollateralization");
    let case_before = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .expect("pending challenge case");
    let status_before = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .expect("pending challenge status");
    let challenge_before = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-rollback".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("pending challenge");
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32)
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::from(149_u32)
    );

    let manager = fixture.manager_id();
    let error = fixture
        .run(2_600, |transaction| {
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-rollback".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            )
            .execute(&manager, transaction)
        })
        .expect_err("custody preflight must reject before any settlement leg runs");
    assert!(
        error
            .to_string()
            .contains("must retain unsettled bond liability"),
        "unexpected settlement error: {error}"
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .expect("case after settlement rollback"),
        case_before
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .expect("status after settlement rollback"),
        status_before
    );
    assert_eq!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-rollback".to_owned(),
        )
        .execute(&fixture.state.view())
        .expect("pending challenge after settlement rollback"),
        challenge_before
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32),
        "the custody preflight must not run the refund leg"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &current_policy.challenge_escrow_account),
        Quantity::from(149_u32),
        "failed settlement must preserve undercollateralized custody exactly"
    );
}
#[test]
fn rejected_settlement_rolls_back_refund_when_slash_destination_disappears() {
    let escrow = account(&keypair(0x22));
    let slash_receiver = account(&keypair(0x23));
    let case_policy = policy_with_custody(escrow.clone(), slash_receiver.clone());
    let mut fixture = Fixture::new_with_policy(1, case_policy);
    let challenger = account(&fixture.outsider);
    fixture
        .run(2_500, |transaction| {
            RaiseSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-real-two-leg-rollback".to_owned(),
                ModerationChallengeKindV1::EvidenceMismatch,
                None,
                [0x7C; 32],
                "fail only after the refund applies".to_owned(),
            )
            .execute(&challenger, transaction)
        })
        .expect("fund a rejected-settlement rollback challenge");
    let case_before = FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .expect("case before real two-leg rollback");
    let status_before = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .expect("status before real two-leg rollback");
    let challenge_before = FindSorafsModerationChallenge::new(
        "case-1".to_owned(),
        "round-1".to_owned(),
        "challenge-real-two-leg-rollback".to_owned(),
    )
    .execute(&fixture.state.view())
    .expect("challenge before real two-leg rollback");

    let manager = fixture.manager_id();
    let error = fixture
        .run(2_600, |transaction| {
            assert!(
                transaction
                    .world
                    .accounts
                    .remove(slash_receiver.clone())
                    .is_some()
            );
            ResolveSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-real-two-leg-rollback".to_owned(),
                ModerationChallengeDecisionV1::Rejected,
            )
            .execute(&manager, transaction)
        })
        .expect_err("slash destination disappears only after refund admission");
    assert!(
        matches!(&error, InstructionExecutionError::Find(FindError::Account(missing)) if missing == &slash_receiver),
        "unexpected slash-leg failure: {error}"
    );
    assert_eq!(
        FindSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .expect("case after real two-leg rollback"),
        case_before
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .expect("status after real two-leg rollback"),
        status_before
    );
    assert_eq!(
        FindSorafsModerationChallenge::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            "challenge-real-two-leg-rollback".to_owned(),
        )
        .execute(&fixture.state.view())
        .expect("challenge after real two-leg rollback"),
        challenge_before
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &challenger),
        Quantity::from(850_u32),
        "the already-applied refund leg must be discarded"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &escrow),
        Quantity::from(1_150_u32),
        "the custody debit from the refund leg must be discarded"
    );
    assert_eq!(
        voting_asset_balance(&fixture.state, &slash_receiver),
        Quantity::from(1_000_u32),
        "the deliberately removed slash account must also be restored"
    );
    assert!(
        fixture
            .state
            .view()
            .world()
            .account(&slash_receiver)
            .is_ok()
    );
}
#[test]
fn missed_quorum_persists_distinct_no_show_penalties() {
    let mut fixture = Fixture::new(3);
    let juror0 = fixture.juror_id(0);
    let juror1 = fixture.juror_id(1);
    let juror2 = fixture.juror_id(2);
    let reveal0 = reveal(
        &fixture.spec,
        &juror0,
        SoraFsModerationVoteChoice::Modify,
        6,
    );
    let reveal1 = reveal(
        &fixture.spec,
        &juror1,
        SoraFsModerationVoteChoice::Modify,
        7,
    );
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal0)))
                .execute(&juror0, transaction)?;
            SubmitSorafsModerationCommit::new(encode(&commit(&reveal1)))
                .execute(&juror1, transaction)
        })
        .unwrap();
    fixture
        .run(REVEAL_AT, |transaction| {
            SubmitSorafsModerationReveal::new(encode(&reveal0)).execute(&juror0, transaction)
        })
        .unwrap();
    let manager = fixture.manager_id();
    assert!(
        fixture
            .run(REVEAL_DEADLINE, |transaction| {
                FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                    .execute(&manager, transaction)
            })
            .is_err()
    );
    let outsider = account(&fixture.outsider);
    assert!(
        fixture
            .run(REVEAL_DEADLINE + 1, |transaction| {
                FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                    .execute(&outsider, transaction)
            })
            .is_err()
    );
    fixture
        .run(FINALIZE_AT, |transaction| {
            FinalizeSorafsModerationCase::new("case-1".to_owned(), "round-1".to_owned())
                .execute(&manager, transaction)
        })
        .unwrap();
    let outcome = FindSorafsModerationOutcome::new("case-1".to_owned(), "round-1".to_owned())
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(outcome.kind, ModerationOutcomeKindV1::QuorumNotMet);
    assert_eq!(outcome.votes_total, 1);
    assert_eq!(outcome.no_show_count, 2);
    let unrevealed =
        FindSorafsModerationNoShow::new("case-1".to_owned(), "round-1".to_owned(), juror1)
            .execute(&fixture.state.view())
            .unwrap();
    assert_eq!(unrevealed.kind, ModerationNoShowKindV1::UnrevealedCommit);
    assert_eq!(unrevealed.penalty_points, 23);
    let missing =
        FindSorafsModerationNoShow::new("case-1".to_owned(), "round-1".to_owned(), juror2)
            .execute(&fixture.state.view())
            .unwrap();
    assert_eq!(missing.kind, ModerationNoShowKindV1::MissingCommit);
    assert_eq!(missing.penalty_points, 11);
}
#[test]
fn bounds_permissions_and_counter_overflow_reject_without_partial_case() {
    let manager_pair = keypair(0x41);
    let outsider_pair = keypair(0x42);
    let manager = account(&manager_pair);
    let outsider = account(&outsider_pair);
    let mut state = state(&[&manager_pair, &outsider_pair], &manager);
    assert!(
        transact(&mut state, 2, OPENED_AT, |transaction| {
            SetSorafsModerationPolicy::new(policy()).execute(&outsider, transaction)
        })
        .is_err()
    );
    transact(&mut state, 1, OPENED_AT, |transaction| {
        SetSorafsModerationPolicy::new(policy()).execute(&manager, transaction)
    })
    .unwrap();
    let active = FindSorafsModerationPolicy.execute(&state.view()).unwrap();
    let mut substituted_custody = policy();
    substituted_custody.revision = 2;
    substituted_custody.predecessor_policy_digest = Some(active.policy_digest);
    substituted_custody.challenge_escrow_account = outsider.clone();
    assert!(
        transact(&mut state, 2, OPENED_AT + 1, |transaction| {
            SetSorafsModerationPolicy::new(substituted_custody).execute(&manager, transaction)
        })
        .is_err(),
        "policy activation must bind challenge custody to consensus governance"
    );
    let mut bad_revision = policy();
    bad_revision.revision = 2;
    bad_revision.predecessor_policy_digest = Some([0xFF; 32]);
    assert!(
        transact(&mut state, 2, OPENED_AT + 1, |transaction| {
            SetSorafsModerationPolicy::new(bad_revision).execute(&manager, transaction)
        })
        .is_err()
    );
    assert_eq!(
        FindSorafsModerationPolicy
            .execute(&state.view())
            .unwrap()
            .policy
            .revision,
        1
    );
    let mut fixture = Fixture::new(1);
    let juror = fixture.juror_id(0);
    let rollback_reveal = reveal(&fixture.spec, &juror, SoraFsModerationVoteChoice::Uphold, 8);
    assert!(
        fixture
            .run(OPENED_AT - 1, |transaction| {
                SubmitSorafsModerationCommit::new(encode(&commit(&rollback_reveal)))
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(1_500, |transaction| {
                SubmitSorafsModerationCommit::new(vec![0xAA; PAYLOAD_MAX_BYTES + 1])
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    let mut oversized_nonce = reveal(&fixture.spec, &juror, SoraFsModerationVoteChoice::Uphold, 9);
    oversized_nonce.nonce = vec![9; MODERATION_LEDGER_MAX_NONCE_BYTES_V1 + 1];
    let oversized_commit = commit(&oversized_nonce);
    fixture
        .run(1_500, |transaction| {
            SubmitSorafsModerationCommit::new(encode(&oversized_commit))
                .execute(&juror, transaction)
        })
        .unwrap();
    assert!(
        fixture
            .run(3_500, |transaction| {
                SubmitSorafsModerationReveal::new(encode(&oversized_nonce))
                    .execute(&juror, transaction)
            })
            .is_err()
    );
    assert!(
        FindSorafsModerationReveal::new("case-1".to_owned(), "round-1".to_owned(), juror,)
            .execute(&fixture.state.view())
            .is_err()
    );
}
#[test]
fn genesis_moderation_permission_bypass_matches_executor_policy() {
    let manager_pair = keypair(0x45);
    let genesis_authority_pair = keypair(0x46);
    let manager = account(&manager_pair);
    let genesis_authority = account(&genesis_authority_pair);
    let mut state = state(&[&manager_pair, &genesis_authority_pair], &manager);
    transact(&mut state, 1, OPENED_AT, |transaction| {
        SetSorafsModerationPolicy::new(policy()).execute(&genesis_authority, transaction)
    })
    .expect("genesis policy activation follows executor permission semantics");
    assert_eq!(
        FindSorafsModerationPolicy
            .execute(&state.view())
            .unwrap()
            .activated_by,
        genesis_authority
    );
}
#[test]
fn moderation_durable_frames_preserve_appeal_and_sortition_bindings() {
    fn check<T>(
        world: &impl crate::state::WorldReadOnly,
        key: &StatePath,
        name: &str,
        decode: impl Fn(&[u8]) -> Result<T, InstructionExecutionError>,
    ) where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        let bytes = world
            .smart_contract_state()
            .get(key)
            .expect("persisted owner frame");
        assert_eq!(T::nominal_name(), name);
        assert_eq!(T::frame_name(), name);
        let view = norito::core::from_bytes_view(bytes).expect("valid persisted envelope");
        assert_eq!(view.schema(), norito::schema::identity::frame_hash::<T>());
        let decoded = decode(bytes).expect("bounded production state decoder");
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode all fields"),
            *bytes
        );
        let mut substituted = bytes.clone();
        substituted[6..22]
            .copy_from_slice(&norito::schema::identity::frame_hash::<iroha_crypto::Hash>());
        assert!(matches!(
            norito::decode_canonical::<T>(&substituted),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(decode(&substituted).is_err());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
    let mut fixture = PanelFixture::new();
    fixture.submit(1, 0, 1);
    let view = fixture.state.view();
    let world = view.world();
    let deposit = read_appeal_deposit_binding(world, [0x91; 32])
        .expect("deposit binding agrees with appeal")
        .expect("deposit exists");
    let proof_token = read_appeal_proof_token_binding(world, [0x32; 32])
        .expect("proof-token binding agrees with appeal")
        .expect("proof-token exists");
    assert_eq!(deposit.intake_digest, proof_token.intake_digest);
    let schedule = read_sortition_anchor_schedule(world).expect("validated sortition schedule");
    assert_eq!(schedule.entries.len(), 1);
    assert_eq!(schedule.entries[0].intake_digest, deposit.intake_digest);
    let head = read_event_journal_head(world)
        .expect("journal head agrees with terminal event")
        .expect("journal head exists");
    read_persisted_event(world, head.last_sequence)
        .expect("validated terminal event")
        .expect("terminal event exists");
    check::<AppealDepositBindingStateV1>(
        world,
        &appeal_deposit_key([0x91; 32]),
        "iroha_core::smartcontracts::isi::sorafs_moderation::AppealDepositBindingStateV1",
        |bytes| decode_state_with_current(bytes, "test deposit binding", None),
    );
    check::<AppealProofTokenBindingStateV1>(
        world,
        &appeal_proof_token_key([0x32; 32]),
        "iroha_core::smartcontracts::isi::sorafs_moderation::AppealProofTokenBindingStateV1",
        |bytes| decode_state_with_current(bytes, "test proof-token binding", None),
    );
    check::<ModerationSortitionAnchorScheduleV1>(
        world,
        sortition_anchor_schedule_key(),
        "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationSortitionAnchorScheduleV1",
        |bytes| decode_state_with_current(bytes, "test sortition schedule", None),
    );
    check::<ModerationPersistedEventV1>(
        world,
        &event_key(head.last_sequence),
        "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationPersistedEventV1",
        |bytes| decode_state_with_current(bytes, "test persisted event", None),
    );
    check::<ModerationEventJournalHeadV1>(
        world,
        event_journal_head_key(),
        "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationEventJournalHeadV1",
        |bytes| decode_state_with_current(bytes, "test journal head", None),
    );
    let deposit_frame = world
        .smart_contract_state()
        .get(&appeal_deposit_key([0x91; 32]))
        .expect("deposit frame");
    assert!(matches!(
        norito::decode_canonical::<AppealProofTokenBindingStateV1>(deposit_frame),
        Err(norito::Error::SchemaMismatch)
    ));
    let proof_frame = world
        .smart_contract_state()
        .get(&appeal_proof_token_key([0x32; 32]))
        .expect("proof-token frame");
    assert!(matches!(
        norito::decode_canonical::<AppealDepositBindingStateV1>(proof_frame),
        Err(norito::Error::SchemaMismatch)
    ));
}
#[test]
fn appeal_intake_is_authority_bound_replay_safe_and_transaction_atomic() {
    let mut fixture = PanelFixture::new();
    let manager = fixture.manager_id();
    let appellant = fixture.appellant_id();
    let outsider = fixture.outsider_id();
    let mut malformed = panel_intake(&fixture.appellant, "panel-case", 1, 0, 1, 0x91);
    malformed.proof_token_digest = [0; 32];
    assert!(
        fixture
            .run(1_001_000, |transaction| {
                SubmitSorafsModerationAppeal::new(malformed).execute(&appellant, transaction)
            })
            .is_err()
    );
    let intake = panel_intake(&fixture.appellant, "panel-case", 1, 0, 1, 0x91);
    assert!(
        fixture
            .run(1_001_000, |transaction| {
                SubmitSorafsModerationAppeal::new(intake.clone()).execute(&outsider, transaction)
            })
            .is_err()
    );
    assert!(
        fixture
            .run(1_001_000, |transaction| {
                SubmitSorafsModerationAppeal::new(intake.clone())
                    .execute(&appellant, transaction)?;
                RegisterSorafsModerationJurorEligibility::new(
                    "panel-case".to_owned(),
                    "round-1".to_owned(),
                    vec![0xAA],
                )
                .execute(&manager, transaction)
            })
            .is_err()
    );
    assert!(
        FindSorafsModerationAppeal::new("panel-case".to_owned(), "round-1".to_owned())
            .execute(&fixture.state.view())
            .is_err()
    );
    assert_eq!(
        FindSorafsModerationStatus
            .execute(&fixture.state.view())
            .unwrap()
            .appeal_intakes,
        0
    );
    fixture.submit(1, 0, 1);
    assert!(
        fixture
            .run(1_001_001, |transaction| {
                SubmitSorafsModerationAppeal::new(intake.clone()).execute(&appellant, transaction)
            })
            .is_err()
    );
    let replayed_deposit = panel_intake(&fixture.appellant, "different-case", 1, 0, 1, 0x91);
    assert!(
        fixture
            .run(1_001_001, |transaction| {
                SubmitSorafsModerationAppeal::new(replayed_deposit).execute(&appellant, transaction)
            })
            .is_err()
    );
    let replayed_proof_token = panel_intake(&fixture.appellant, "proof-replay-case", 1, 0, 1, 0x92);
    assert!(
        fixture
            .run(1_001_001, |transaction| {
                SubmitSorafsModerationAppeal::new(replayed_proof_token)
                    .execute(&appellant, transaction)
            })
            .is_err()
    );
    let status = FindSorafsModerationStatus
        .execute(&fixture.state.view())
        .unwrap();
    assert_eq!(status.appeal_intakes, 1);
    assert_eq!(status.eligibility_proofs, 0);
    let mut excluded = PanelFixture::new();
    let excluded_appellant = excluded.appellant_id();
    let excluded_juror = excluded.juror_id();
    let mut excluded_intake = panel_intake(&excluded.appellant, "panel-case", 1, 0, 1, 0x91);
    excluded_intake.exclusions.push(excluded_juror.clone());
    excluded_intake.exclusions.sort_by_key(ToString::to_string);
    excluded
        .run(1_001_000, |transaction| {
            SubmitSorafsModerationAppeal::new(excluded_intake)
                .execute(&excluded_appellant, transaction)
        })
        .unwrap();
    assert!(
        excluded
            .run(1_002_000, |transaction| {
                RegisterSorafsModerationJurorEligibility::new(
                    "panel-case".to_owned(),
                    "round-1".to_owned(),
                    vec![0xAA],
                )
                .execute(&excluded_juror, transaction)
            })
            .is_err()
    );
    assert!(excluded.appeal().eligible_jurors.is_empty());
}
include!("sorafs/moderation_fixture_contract_tests.rs");
include!("sorafs/moderation_tail_tests.rs");
