/// Certified Initial execution admits conditional escrow and repo while Core keeps authority.
mod conditional_escrow_and_repo_admission {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use core::num::NonZeroU32;
    use iroha_data_model::{
        asset::AssetBalancePolicy,
        escrow::{
            AssetEscrowStatus, ConditionalEscrowCondition, ConditionalEscrowOracleCondition,
            ConditionalEscrowPredicate, ConditionalEscrowValue, EscrowId,
        },
        isi::{
            escrow::{AttestEscrowCondition, ExpireConditionalEscrow, OpenConditionalEscrow},
            repo::{RepoInstructionBox, RepoIsi, RepoMarginCallIsi, ReverseRepoIsi},
        },
        repo::{RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
    };

    const OPENER: usize = 0;
    const BENEFICIARY: usize = 1;
    const ATTESTOR: usize = 2;
    const OUTSIDER: usize = 3;

    struct Fixture {
        chain: CertifiedTestChain,
        keys: [KeyPair; 4],
        accounts: [AccountId; 4],
        cash: AssetDefinitionId,
        bond: AssetDefinitionId,
        escrow: EscrowId,
    }

    impl Fixture {
        fn new() -> Self {
            let keys = [0xC1, 0xC2, 0xC3, 0xC4]
                .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519));
            let accounts = keys
                .each_ref()
                .map(|key| AccountId::new(key.public_key().clone()));
            let domain = DomainId::try_new("bonds", "universal").unwrap();
            let cash = AssetDefinitionId::derive_from_components(
                domain.clone(),
                "cash_token".parse().unwrap(),
            );
            let bond = AssetDefinitionId::derive_from_components(
                domain.clone(),
                "bond_token".parse().unwrap(),
            );
            let definition = |id: &AssetDefinitionId, name: &str| {
                AssetDefinition::numeric(
                    id.clone(),
                    name,
                    AssetBalancePolicy::Global,
                    Some(domain.clone()),
                )
                .build(&accounts[OPENER])
            };
            let world = World::with_assets(
                [Domain::new(domain.clone()).build(&accounts[OPENER])],
                accounts.iter().map(|id| Account::new(id.clone()).build(id)),
                [
                    definition(&cash, "Cash token"),
                    definition(&bond, "Bond token"),
                ],
                [
                    Asset::new(
                        AssetId::new(cash.clone(), accounts[OPENER].clone()),
                        Quantity::from(100_u32),
                    ),
                    Asset::new(
                        AssetId::new(bond.clone(), accounts[OPENER].clone()),
                        Quantity::from(50_u32),
                    ),
                    Asset::new(
                        AssetId::new(cash.clone(), accounts[BENEFICIARY].clone()),
                        Quantity::from(1_000_u32),
                    ),
                ],
                [],
            );
            Self {
                chain: CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap(),
                keys,
                accounts,
                cash,
                bond,
                escrow: EscrowId::new(iroha_crypto::Hash::new(b"initial_conditional_escrow")),
            }
        }

        fn next_time(&self) -> u64 {
            (self.chain.height() + 1) * 1_000
        }

        fn submit(&mut self, signer: usize, instruction: InstructionBox, expected: Option<&str>) {
            self.submit_at(signer, instruction, expected, self.next_time());
        }

        fn submit_at(
            &mut self,
            signer: usize,
            instruction: InstructionBox,
            expected: Option<&str>,
            time: u64,
        ) {
            let transaction = self.chain.sign(&self.keys[signer], [instruction], time);
            let outcome = self.chain.commit_at(time, vec![transaction]);
            let committed = self.chain.committed(self.chain.height());
            let error = committed.block().output_error(0);
            if let Some(message) = expected {
                assert_eq!(outcome, [false], "{error:?}");
                assert!(format!("{error:?}").contains(message), "{error:?}");
            } else {
                assert_eq!(outcome, [true], "{error:?}");
            }
        }

        fn balance(&self, definition: &AssetDefinitionId, account: &AccountId) -> Quantity {
            initial_batch_balance(
                self.chain.state().view().world(),
                &AssetId::new(definition.clone(), account.clone()),
            )
        }

        fn open_escrow(&mut self, expires_at_ms: u64) {
            let conditions = vec![ConditionalEscrowCondition::Oracle(
                ConditionalEscrowOracleCondition {
                    id: "coupon_paid".parse().unwrap(),
                    attestor: self.accounts[ATTESTOR].clone(),
                    predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(
                        true,
                    )),
                    sequence: NonZeroU32::new(1).unwrap(),
                },
            )];
            self.submit(
                OPENER,
                OpenConditionalEscrow::new(
                    self.escrow,
                    self.cash.clone(),
                    self.accounts[BENEFICIARY].clone(),
                    40_u32,
                    conditions,
                    expires_at_ms,
                )
                .into(),
                None,
            );
            self.assert_escrow(60, 1_000, 40, AssetEscrowStatus::Locked);
        }

        fn assert_escrow(
            &self,
            opener: u32,
            beneficiary: u32,
            custody: u32,
            status: AssetEscrowStatus,
        ) {
            let view = self.chain.state().view();
            let record = view
                .world()
                .asset_escrows()
                .get(&self.escrow)
                .cloned()
                .expect("committed conditional escrow");
            drop(view);
            assert_eq!(record.status, status);
            assert_eq!(record.seller, self.accounts[OPENER]);
            assert_eq!(record.buyer.as_ref(), Some(&self.accounts[BENEFICIARY]));
            assert_eq!(record.remaining_amount, Quantity::from(custody));
            for (account, expected) in [
                (&self.accounts[OPENER], opener),
                (&self.accounts[BENEFICIARY], beneficiary),
                (&record.custody, custody),
            ] {
                assert_eq!(self.balance(&self.cash, account), Quantity::from(expected));
            }
        }

        fn attest(&self) -> InstructionBox {
            AttestEscrowCondition::new(
                self.escrow,
                "coupon_paid".parse().unwrap(),
                ConditionalEscrowValue::Bool(true),
                None,
            )
            .into()
        }

        fn repo(&self, initiator: usize) -> RepoIsi {
            RepoIsi::new(
                RepoAgreementId::new("initial_repo".parse().unwrap()),
                self.accounts[initiator].clone(),
                self.accounts[BENEFICIARY].clone(),
                None,
                RepoCashLeg::new(self.cash.clone(), 500_u32),
                RepoCollateralLeg::new(self.bond.clone(), 50_u32),
                0,
                1_000_000,
                RepoGovernance::with_defaults(0, 0),
            )
        }

        fn grant_repo_consents(&mut self, repo: &RepoIsi) {
            for (definition, intent_hash) in [
                (self.cash.clone(), repo.initiation_intent_hash()),
                (self.bond.clone(), repo.maturity_intent_hash()),
            ] {
                self.submit(
                    BENEFICIARY,
                    Grant::account_permission(
                        executor_permission::settlement::CanExecuteSettlement {
                            debited_asset: AssetId::new(
                                definition,
                                self.accounts[BENEFICIARY].clone(),
                            ),
                            settlement_id: repo.settlement_id(),
                            intent_hash,
                        },
                        self.accounts[OPENER].clone(),
                    )
                    .into(),
                    None,
                );
            }
        }

        fn assert_repo_balances(&self, opener_cash: u32, opener_bond: u32, active: Option<bool>) {
            assert_eq!(
                self.balance(&self.cash, &self.accounts[OPENER]),
                Quantity::from(opener_cash)
            );
            assert_eq!(
                self.balance(&self.cash, &self.accounts[BENEFICIARY]),
                Quantity::from(1_100 - opener_cash)
            );
            assert_eq!(
                self.balance(&self.bond, &self.accounts[OPENER]),
                Quantity::from(opener_bond)
            );
            assert_eq!(
                self.balance(&self.bond, &self.accounts[BENEFICIARY]),
                Quantity::from(50 - opener_bond)
            );
            let view = self.chain.state().view();
            let agreement = view
                .world()
                .repo_agreements()
                .get(&RepoAgreementId::new("initial_repo".parse().unwrap()))
                .cloned();
            assert_eq!(
                agreement
                    .as_ref()
                    .map(iroha_data_model::repo::RepoAgreement::is_active),
                active
            );
        }
    }

    #[test]
    fn initial_executor_admits_conditional_escrow_and_repo_boxes() {
        let fixture_accounts = [0xD1, 0xD2].map(|seed| {
            AccountId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        });
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bonds", "universal").unwrap(),
            "cash_token".parse().unwrap(),
        );
        let escrow = EscrowId::new(iroha_crypto::Hash::new(b"admission"));
        let agreement = RepoAgreementId::new("admitted_repo".parse().unwrap());
        let repo = RepoIsi::new(
            agreement.clone(),
            fixture_accounts[0].clone(),
            fixture_accounts[1].clone(),
            None,
            RepoCashLeg::new(definition.clone(), 1_u32),
            RepoCollateralLeg::new(definition.clone(), 1_u32),
            0,
            1,
            RepoGovernance::with_defaults(0, 0),
        );
        let instructions: [InstructionBox; 6] = [
            OpenConditionalEscrow::new(
                escrow,
                definition,
                fixture_accounts[1].clone(),
                1_u32,
                Vec::new(),
                1,
            )
            .into(),
            AttestEscrowCondition::new(
                escrow,
                "condition".parse().unwrap(),
                ConditionalEscrowValue::Bool(true),
                None,
            )
            .into(),
            ExpireConditionalEscrow::new(escrow).into(),
            RepoInstructionBox::from(repo).into(),
            RepoInstructionBox::from(ReverseRepoIsi::new(agreement.clone())).into(),
            RepoInstructionBox::from(RepoMarginCallIsi::new(agreement)).into(),
        ];
        for instruction in &instructions {
            assert!(
                initial_native_instruction_is_explicitly_admitted(instruction),
                "{} must reach its native Core authorization checks",
                instruction.id()
            );
        }
    }

    #[test]
    fn initial_conditional_escrow_rejects_non_attestors_and_releases_to_beneficiary() {
        let mut fixture = Fixture::new();
        fixture.open_escrow(1_000_000);
        for intruder in [OUTSIDER, BENEFICIARY, OPENER] {
            let attest = fixture.attest();
            fixture.submit(
                intruder,
                attest,
                Some("only the exact configured attestor may attest this condition"),
            );
            fixture.assert_escrow(60, 1_000, 40, AssetEscrowStatus::Locked);
        }
        let attest = fixture.attest();
        fixture.submit(ATTESTOR, attest, None);
        fixture.assert_escrow(60, 1_040, 0, AssetEscrowStatus::Released);
        let attest = fixture.attest();
        fixture.submit(
            ATTESTOR,
            attest,
            Some("only locked conditional escrows can be attested"),
        );
        fixture.assert_escrow(60, 1_040, 0, AssetEscrowStatus::Released);
    }

    #[test]
    fn initial_conditional_escrow_expiry_is_permissionless_and_refunds_opener() {
        let mut fixture = Fixture::new();
        fixture.open_escrow(100_000);
        fixture.submit(
            OUTSIDER,
            ExpireConditionalEscrow::new(fixture.escrow).into(),
            Some("conditional escrow expiry has not been reached"),
        );
        fixture.assert_escrow(60, 1_000, 40, AssetEscrowStatus::Locked);
        let attest = fixture.attest();
        fixture.submit_at(
            ATTESTOR,
            attest,
            Some("conditional escrow attestation is at or after its expiry"),
            100_000,
        );
        fixture.assert_escrow(60, 1_000, 40, AssetEscrowStatus::Locked);
        fixture.submit_at(
            OUTSIDER,
            ExpireConditionalEscrow::new(fixture.escrow).into(),
            None,
            101_000,
        );
        fixture.assert_escrow(100, 1_000, 0, AssetEscrowStatus::Expired);
    }

    #[test]
    fn initial_repo_requires_signing_initiator_and_recorded_participants() {
        let mut fixture = Fixture::new();
        let repo = fixture.repo(OPENER);
        fixture.grant_repo_consents(&repo);
        // A different signer cannot initiate on the recorded initiator's behalf,
        // even while the exact consents exist.
        fixture.submit(
            OUTSIDER,
            repo.clone().into(),
            Some("repo initiator must match the transaction authority"),
        );
        fixture.assert_repo_balances(100, 50, None);
        let impostor = fixture.repo(OUTSIDER);
        fixture.submit(
            OUTSIDER,
            impostor.into(),
            Some("bilateral settlement requires exact consent from debited account"),
        );
        fixture.assert_repo_balances(100, 50, None);
        fixture.submit(OPENER, repo.clone().into(), None);
        fixture.assert_repo_balances(600, 0, Some(true));
        let agreement = repo.agreement_id().clone();
        fixture.submit(
            OUTSIDER,
            RepoMarginCallIsi::new(agreement.clone()).into(),
            Some("margin call must be initiated by a repo participant"),
        );
        fixture.submit_at(
            OUTSIDER,
            ReverseRepoIsi::new(agreement.clone()).into(),
            Some("must be submitted by a recorded participant"),
            1_000_000,
        );
        fixture.assert_repo_balances(600, 0, Some(true));
        fixture.submit_at(
            BENEFICIARY,
            ReverseRepoIsi::new(agreement).into(),
            None,
            1_001_000,
        );
        fixture.assert_repo_balances(100, 50, Some(false));
    }
}
