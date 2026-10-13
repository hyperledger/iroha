/// Certified Initial execution services native bonds while Core keeps every authority check.
mod bond_admission {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::{
        asset::AssetBalancePolicy,
        bond::{
            BondCallTerms, BondCashflowKind, BondCashflowStatus, BondCashflowTerms, BondDayCount,
            BondIdentifiers, BondLifecycle, BondRecord, BondTerms, bond_vault_account_id,
        },
        isi::bond::{
            BondInstructionBox, CallBond, ClaimBondCashflow, CloseBondCashflow,
            DeclareBondDefault, FundBondCashflow, RecordBondCashflow, RegisterBond,
        },
    };
    use iroha_primitives::numeric::NumericSpec;

    const ISSUER: usize = 0;
    const AGENT: usize = 1;
    const OUTSIDER: usize = 2;
    /// Investors occupy the remaining key slots.
    const FIRST_INVESTOR: usize = 3;
    const INVESTORS: usize = 8;
    /// Key slots reserved for investors; the budget test uses all of them.
    const MAX_INVESTORS: usize = 17;

    /// Compressed schedule: issue at 10s, four semi-annual-rate coupons every 100s and a par
    /// redemption on the last coupon date. Record dates precede payment dates by 10s.
    const ISSUE: u64 = 10_000;
    const PERIOD: u64 = 100_000;
    const RECORD_OFFSET: u64 = 10_000;
    const COUPONS: u16 = 4;

    fn q(text: &str) -> Quantity {
        text.parse().expect("quantity literal")
    }

    fn payment_date(index: u16) -> u64 {
        ISSUE + PERIOD * (u64::from(index) + 1)
    }

    fn maturity() -> u64 {
        payment_date(COUPONS - 1)
    }

    struct Fixture {
        chain: CertifiedTestChain,
        keys: Vec<KeyPair>,
        accounts: Vec<AccountId>,
        domain: DomainId,
        bond: AssetDefinitionId,
        eur: AssetDefinitionId,
        now: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let keys: Vec<KeyPair> = (0..FIRST_INVESTOR + MAX_INVESTORS)
                .map(|slot| {
                    KeyPair::from_seed(
                        vec![0xB0 + u8::try_from(slot).unwrap(); 32],
                        Algorithm::Ed25519,
                    )
                })
                .collect();
            let accounts: Vec<AccountId> = keys
                .iter()
                .map(|key| AccountId::new(key.public_key().clone()))
                .collect();
            let domain = DomainId::try_new("bonds", "universal").unwrap();
            let bond = AssetDefinitionId::derive_from_components(
                domain.clone(),
                "slo_2028".parse().unwrap(),
            );
            let eur =
                AssetDefinitionId::derive_from_components(domain.clone(), "eur".parse().unwrap());
            let world = World::with_assets(
                [Domain::new(domain.clone()).build(&accounts[ISSUER])],
                accounts.iter().map(|id| Account::new(id.clone()).build(id)),
                [AssetDefinition::new(
                    eur.clone(),
                    "EUR e-money",
                    NumericSpec::fractional(2),
                    AssetBalancePolicy::Global,
                    Some(domain.clone()),
                )
                .build(&accounts[AGENT])],
                [
                    Asset::new(
                        AssetId::new(eur.clone(), accounts[AGENT].clone()),
                        Quantity::from(1_000_000_u32),
                    ),
                    Asset::new(
                        AssetId::new(eur.clone(), accounts[ISSUER].clone()),
                        Quantity::from(1_000_u32),
                    ),
                ],
                [],
            );
            Self {
                chain: CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap(),
                keys,
                accounts,
                domain,
                bond,
                eur,
                now: 1_000,
            }
        }

        fn investor(n: usize) -> usize {
            FIRST_INVESTOR + n
        }

        /// Commit one transaction in a block at exactly `time` (or just after the previous block
        /// when that time already passed). The transaction is created one millisecond earlier,
        /// because a block is always later than the transactions it carries.
        fn submit_many(
            &mut self,
            signer: usize,
            instructions: Vec<InstructionBox>,
            time: u64,
            expected: Option<&str>,
        ) {
            let time = time.max(self.now + 2);
            self.now = time;
            let transaction = self.chain.sign(&self.keys[signer], instructions, time - 1);
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

        fn submit(
            &mut self,
            signer: usize,
            instruction: impl Into<InstructionBox>,
            time: u64,
            expected: Option<&str>,
        ) {
            self.submit_many(signer, vec![instruction.into()], time, expected);
        }

        fn terms(&self, call: Option<BondCallTerms>) -> BondTerms {
            let mut cashflows: Vec<BondCashflowTerms> = (0..COUPONS)
                .map(|index| BondCashflowTerms {
                    index,
                    kind: BondCashflowKind::Coupon,
                    record_date_ms: payment_date(index) - RECORD_OFFSET,
                    payment_date_ms: payment_date(index),
                    amount_per_unit: q("1.625"),
                })
                .collect();
            cashflows.push(BondCashflowTerms {
                index: COUPONS,
                kind: BondCashflowKind::Redemption,
                record_date_ms: maturity() - RECORD_OFFSET,
                payment_date_ms: maturity(),
                amount_per_unit: q("50"),
            });
            BondTerms {
                issuer: self.accounts[ISSUER].clone(),
                paying_agent: self.accounts[AGENT].clone(),
                payment_asset: self.eur.clone(),
                denomination: q("50"),
                coupon_rate_bps: 650,
                coupon_frequency: 2,
                day_count: BondDayCount::ActActIcma,
                issue_date_ms: ISSUE,
                maturity_date_ms: maturity(),
                redemption_price_bps: 10_000,
                call,
                cashflows,
                identifiers: BondIdentifiers {
                    isin: Some("SI0031234567".to_owned()),
                    cfi: Some("DBFTFB".to_owned()),
                    issuer_lei: Some("5299000DI3047E2LIV03".to_owned()),
                    bdt_version: "bdt-1.0".to_owned(),
                    bdt_document_sha256: Some([0x5D; 32]),
                },
                terms_sha256: [0x7E; 32],
            }
        }

        /// The issuer registers, mints and registers the bond record in one transaction, then
        /// allots `allotments[i]` units to investor `i`.
        fn issue(&mut self, call: Option<BondCallTerms>, allotments: &[u32]) {
            let issuer = self.accounts[ISSUER].clone();
            let definition = AssetDefinition::new(
                self.bond.clone(),
                "SLO 6.50% 2028",
                NumericSpec::integer(),
                AssetBalancePolicy::Global,
                Some(self.domain.clone()),
            );
            let terms = self.terms(call);
            // A non-issuer cannot register the bond record of the issuer's definition.
            let issuance = vec![
                InstructionBox::from(Register::asset_definition(definition)),
                Mint::asset_quantity(1_000_u32, AssetId::new(self.bond.clone(), issuer.clone()))
                    .into(),
                BondInstructionBox::from(RegisterBond::new(self.bond.clone(), terms.clone()))
                    .into(),
            ];
            self.submit_many(ISSUER, issuance, ISSUE, None);
            self.submit(
                AGENT,
                RegisterBond::new(self.bond.clone(), terms),
                ISSUE,
                Some("bond.unauthorized: registration must be signed by the issuer"),
            );
            // Allot in batches of eight transfers, well inside the per-entry delta budget.
            let transfers: Vec<InstructionBox> = allotments
                .iter()
                .enumerate()
                .map(|(n, units)| {
                    Transfer::asset_quantity(
                        AssetId::new(self.bond.clone(), issuer.clone()),
                        *units,
                        self.accounts[Self::investor(n)].clone(),
                    )
                    .into()
                })
                .collect();
            for batch in transfers.chunks(8) {
                self.submit_many(ISSUER, batch.to_vec(), ISSUE, None);
            }
            let record = self.record();
            assert_eq!(record.state.lifecycle, BondLifecycle::Active);
            assert_eq!(record.state.outstanding_units, q("1000"));
        }

        fn record(&self) -> BondRecord {
            let view = self.chain.state().view();
            view.world()
                .bonds()
                .get(&self.bond)
                .cloned()
                .expect("registered bond")
        }

        fn balance(&self, definition: &AssetDefinitionId, account: &AccountId) -> Quantity {
            initial_batch_balance(
                self.chain.state().view().world(),
                &AssetId::new(definition.clone(), account.clone()),
            )
        }

        fn eur(&self, slot: usize) -> Quantity {
            self.balance(&self.eur, &self.accounts[slot])
        }

        fn units(&self, slot: usize) -> Quantity {
            self.balance(&self.bond, &self.accounts[slot])
        }

        fn vault_eur(&self) -> Quantity {
            self.balance(&self.eur, &bond_vault_account_id(&self.bond))
        }

        fn claim(&self, index: u16, holder: usize) -> InstructionBox {
            BondInstructionBox::from(ClaimBondCashflow::new(
                self.bond.clone(),
                index,
                self.accounts[holder].clone(),
            ))
            .into()
        }

        fn record_and_fund(&mut self, index: u16, record_date: u64) {
            self.submit(
                AGENT,
                BondInstructionBox::from(RecordBondCashflow::new(self.bond.clone(), index)),
                record_date,
                None,
            );
            let source = AssetId::new(self.eur.clone(), self.accounts[AGENT].clone());
            self.submit(
                AGENT,
                BondInstructionBox::from(FundBondCashflow::new(self.bond.clone(), index, source)),
                record_date,
                None,
            );
        }

        fn close(&mut self, index: u16, time: u64) {
            self.submit(
                AGENT,
                BondInstructionBox::from(CloseBondCashflow::new(self.bond.clone(), index)),
                time,
                None,
            );
        }
    }

    #[test]
    fn initial_executor_admits_the_bond_instruction_box() {
        let bond = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bonds", "universal").unwrap(),
            "admitted".parse().unwrap(),
        );
        let holder = AccountId::new(
            KeyPair::from_seed(vec![0xBE; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let instructions: [InstructionBox; 6] = [
            BondInstructionBox::from(RecordBondCashflow::new(bond.clone(), 0)).into(),
            BondInstructionBox::from(FundBondCashflow::new(
                bond.clone(),
                0,
                AssetId::new(bond.clone(), holder.clone()),
            ))
            .into(),
            BondInstructionBox::from(ClaimBondCashflow::new(bond.clone(), 0, holder)).into(),
            BondInstructionBox::from(CloseBondCashflow::new(bond.clone(), 0)).into(),
            BondInstructionBox::from(CallBond::new(bond.clone(), 1)).into(),
            BondInstructionBox::from(DeclareBondDefault::new(bond, 0, [1; 32])).into(),
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
    #[allow(clippy::too_many_lines)]
    fn initial_bond_lifecycle_services_coupons_and_redeems_several_holders() {
        let mut fixture = Fixture::new();
        // Investor n holds 10 * (n + 1) units except investor 7, who holds 3.
        let allotments = [10, 20, 30, 40, 50, 60, 70, 3];
        fixture.issue(None, &allotments);
        // OTC transfer before the first record date moves 5 units from investor 1 to 0.
        let otc = Transfer::asset_quantity(
            AssetId::new(fixture.bond.clone(), fixture.accounts[Fixture::investor(1)].clone()),
            5_u32,
            fixture.accounts[Fixture::investor(0)].clone(),
        );
        fixture.submit(Fixture::investor(1), otc, ISSUE + 1, None);
        let units: Vec<Quantity> = (0..INVESTORS)
            .map(|n| fixture.units(Fixture::investor(n)))
            .collect();
        assert_eq!(units[0], q("15"));
        assert_eq!(units[1], q("15"));
        assert_eq!(fixture.units(ISSUER), q("717"));

        // Recording is the paying agent's, never the issuer's, and only at the record date.
        let record_0 = payment_date(0) - RECORD_OFFSET;
        fixture.submit(
            AGENT,
            BondInstructionBox::from(RecordBondCashflow::new(fixture.bond.clone(), 0)),
            record_0 - 1,
            Some("bond.too_early"),
        );
        fixture.submit(
            ISSUER,
            BondInstructionBox::from(RecordBondCashflow::new(fixture.bond.clone(), 0)),
            record_0,
            Some("recording must be signed by the paying agent"),
        );
        fixture.record_and_fund(0, record_0);
        let cashflow = fixture.record().state.cashflows[0].clone();
        assert_eq!(cashflow.status, BondCashflowStatus::Funded);
        assert_eq!(cashflow.snapshot.len(), INVESTORS);
        assert_eq!(cashflow.entitled_units, q("283"));
        // Each holding times 1.625, rounded down to cents.
        let expected_due = units
            .iter()
            .map(|units| {
                units
                    .try_mul_div_decimal_round(
                        q("1.625").as_numeric(),
                        &iroha_primitives::numeric::Numeric::one(),
                        2,
                        iroha_primitives::numeric::RoundingMode::TowardZero,
                    )
                    .unwrap()
            })
            .try_fold(Quantity::zero(), |total, payment| total.checked_add(&payment))
            .unwrap();
        assert_eq!(cashflow.amount_due, expected_due);
        assert_eq!(fixture.vault_eur(), expected_due);

        // Claims open on the payment date: an outsider cannot claim for a holder.
        let pay_0 = payment_date(0);
        let claim = fixture.claim(0, Fixture::investor(0));
        fixture.submit_many(
            Fixture::investor(0),
            vec![claim.clone()],
            pay_0 - 1,
            Some("bond.too_early"),
        );
        fixture.submit_many(
            OUTSIDER,
            vec![claim.clone()],
            pay_0,
            Some("a claim must be signed by the holder or pushed by the paying agent"),
        );
        // Holder self-claim.
        fixture.submit_many(Fixture::investor(0), vec![claim.clone()], pay_0, None);
        assert_eq!(fixture.eur(Fixture::investor(0)), q("24.37"));
        fixture.submit_many(
            Fixture::investor(0),
            vec![claim],
            pay_0,
            Some("bond.already_claimed"),
        );
        // Paying-agent push claim pays the holder.
        let agent_before = fixture.eur(AGENT);
        let push = fixture.claim(0, Fixture::investor(1));
        fixture.submit_many(AGENT, vec![push], pay_0, None);
        assert_eq!(fixture.eur(Fixture::investor(1)), q("24.37"));
        assert_eq!(fixture.eur(AGENT), agent_before);
        // The remaining six holders are paid by one packed push transaction.
        let packed: Vec<InstructionBox> = (2..INVESTORS)
            .map(|n| fixture.claim(0, Fixture::investor(n)))
            .collect();
        fixture.submit_many(AGENT, packed, pay_0, None);
        assert_eq!(fixture.eur(Fixture::investor(7)), q("4.87"));
        assert_eq!(fixture.vault_eur(), Quantity::zero());
        fixture.close(0, pay_0);
        assert_eq!(
            fixture.record().state.cashflows[0].status,
            BondCashflowStatus::Closed
        );

        // The remaining coupons are serviced with one packed claim transaction each.
        for index in 1..COUPONS {
            fixture.record_and_fund(index, payment_date(index) - RECORD_OFFSET);
            let packed: Vec<InstructionBox> = (0..INVESTORS)
                .map(|n| fixture.claim(index, Fixture::investor(n)))
                .collect();
            fixture.submit_many(AGENT, packed, payment_date(index), None);
            fixture.close(index, payment_date(index));
        }
        assert_eq!(fixture.eur(Fixture::investor(0)), q("97.48"));

        // Recording the redemption freezes every movement of the bond.
        let redemption = COUPONS;
        fixture.record_and_fund(redemption, maturity() - RECORD_OFFSET);
        assert!(fixture.record().state.transfers_frozen);
        assert_eq!(fixture.vault_eur(), q("14150"));
        let frozen = Transfer::asset_quantity(
            AssetId::new(fixture.bond.clone(), fixture.accounts[Fixture::investor(2)].clone()),
            1_u32,
            fixture.accounts[OUTSIDER].clone(),
        );
        fixture.submit(
            Fixture::investor(2),
            frozen,
            maturity() - RECORD_OFFSET,
            Some("bond.transfers_frozen"),
        );
        // Redemption claims burn the holder's units and pay par from the vault; the paying
        // agent may split the packed claims across transactions freely.
        let first: Vec<InstructionBox> = (0..INVESTORS / 2)
            .map(|n| fixture.claim(redemption, Fixture::investor(n)))
            .collect();
        fixture.submit_many(AGENT, first, maturity(), None);
        let second: Vec<InstructionBox> = (INVESTORS / 2..INVESTORS)
            .map(|n| fixture.claim(redemption, Fixture::investor(n)))
            .collect();
        fixture.submit_many(AGENT, second, maturity(), None);
        for n in 0..INVESTORS {
            assert_eq!(fixture.units(Fixture::investor(n)), Quantity::zero());
        }
        assert_eq!(fixture.eur(Fixture::investor(0)), q("847.48"));
        assert_eq!(fixture.vault_eur(), Quantity::zero());
        let record = fixture.record();
        assert_eq!(record.state.redeemed_units, q("283"));
        assert_eq!(record.state.outstanding_units, q("717"));
        let total = fixture
            .chain
            .state()
            .view()
            .world()
            .asset_definitions()
            .get(&fixture.bond)
            .unwrap()
            .total_quantity()
            .clone();
        assert_eq!(total, q("717"));
        fixture.close(redemption, maturity());
        assert_eq!(fixture.record().state.lifecycle, BondLifecycle::Matured);
    }

    #[test]
    fn initial_packed_claims_are_bounded_by_the_bootstrap_delta_budget() {
        let mut fixture = Fixture::new();
        let allotments = [10; MAX_INVESTORS];
        fixture.issue(None, &allotments);
        let claims = |fixture: &Fixture, index: u16, holders: core::ops::Range<usize>| {
            holders
                .map(|n| fixture.claim(index, Fixture::investor(n)))
                .collect::<Vec<InstructionBox>>()
        };
        // Each coupon claim is one transfer delta. Seventeen exceed the bootstrap per-entry
        // budget of sixteen and the whole transaction is refused before any payment.
        fixture.record_and_fund(0, payment_date(0) - RECORD_OFFSET);
        let over = claims(&fixture, 0, 0..MAX_INVESTORS);
        fixture.submit_many(
            AGENT,
            over,
            payment_date(0),
            Some(crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION),
        );
        assert!(fixture.record().state.cashflows[0].claimed.is_empty());
        assert_eq!(fixture.eur(Fixture::investor(0)), Quantity::zero());
        let full = claims(&fixture, 0, 0..16);
        fixture.submit_many(AGENT, full, payment_date(0), None);
        let last = claims(&fixture, 0, 16..MAX_INVESTORS);
        fixture.submit_many(AGENT, last, payment_date(0), None);
        fixture.close(0, payment_date(0));
        for index in 1..COUPONS {
            fixture.record_and_fund(index, payment_date(index) - RECORD_OFFSET);
            for range in [0..16, 16..MAX_INVESTORS] {
                let packed = claims(&fixture, index, range);
                fixture.submit_many(AGENT, packed, payment_date(index), None);
            }
            fixture.close(index, payment_date(index));
        }
        // A redemption claim is one payment delta plus a supply burn, which is captured as a
        // quantity change rather than a transfer delta: the same sixteen-claim bound applies.
        fixture.record_and_fund(COUPONS, maturity() - RECORD_OFFSET);
        let over = claims(&fixture, COUPONS, 0..MAX_INVESTORS);
        fixture.submit_many(
            AGENT,
            over,
            maturity(),
            Some(crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION),
        );
        assert_eq!(fixture.units(Fixture::investor(0)), q("10"));
        assert!(
            fixture.record().state.cashflows[usize::from(COUPONS)]
                .claimed
                .is_empty()
        );
        for range in [0..16, 16..MAX_INVESTORS] {
            let packed = claims(&fixture, COUPONS, range);
            fixture.submit_many(AGENT, packed, maturity(), None);
        }
        assert_eq!(fixture.vault_eur(), Quantity::zero());
        assert_eq!(fixture.record().state.redeemed_units, q("170"));
        fixture.close(COUPONS, maturity());
        assert_eq!(fixture.record().state.lifecycle, BondLifecycle::Matured);
    }

    #[test]
    fn initial_bond_call_redeems_a_single_holder_at_the_call_price() {
        let mut fixture = Fixture::new();
        let call = BondCallTerms {
            first_call_date_ms: payment_date(1),
            price_bps: 10_100,
            notice_ms: 50_000,
        };
        fixture.issue(Some(call), &[100]);
        let holder = Fixture::investor(0);
        let call_date = payment_date(1);
        fixture.record_and_fund(0, payment_date(0) - RECORD_OFFSET);
        let claim = fixture.claim(0, holder);
        fixture.submit_many(holder, vec![claim], payment_date(0), None);
        fixture.close(0, payment_date(0));
        fixture.submit(
            AGENT,
            BondInstructionBox::from(CallBond::new(fixture.bond.clone(), call_date)),
            call_date - 60_000,
            Some("a call must be signed by the issuer"),
        );
        fixture.submit(
            ISSUER,
            BondInstructionBox::from(CallBond::new(fixture.bond.clone(), call_date)),
            call_date - 60_000,
            None,
        );
        let record = fixture.record();
        assert_eq!(record.state.lifecycle, BondLifecycle::Called);
        let redemption = u16::try_from(record.state.cashflows.len() - 1).unwrap();
        assert_eq!(redemption, COUPONS + 1);
        assert_eq!(
            record.state.cashflows[usize::from(redemption)]
                .terms
                .amount_per_unit,
            q("50.5")
        );
        // The call-date coupon is still paid, then the call redemption.
        fixture.record_and_fund(1, call_date - RECORD_OFFSET);
        fixture.record_and_fund(redemption, call_date - RECORD_OFFSET);
        let claims = vec![fixture.claim(1, holder), fixture.claim(redemption, holder)];
        fixture.submit_many(holder, claims, call_date, None);
        fixture.close(1, call_date);
        fixture.close(redemption, call_date);
        assert_eq!(fixture.units(holder), Quantity::zero());
        assert_eq!(fixture.eur(holder), q("5375"));
        let record = fixture.record();
        assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
        assert!(
            record.state.cashflows[2..usize::from(COUPONS) + 1]
                .iter()
                .all(|cashflow| cashflow.status == BondCashflowStatus::Cancelled)
        );
    }

    #[test]
    fn initial_bond_default_stops_servicing_but_keeps_funded_claims() {
        let mut fixture = Fixture::new();
        fixture.issue(None, &[100, 50]);
        fixture.record_and_fund(0, payment_date(0) - RECORD_OFFSET);
        fixture.submit(
            AGENT,
            BondInstructionBox::from(RecordBondCashflow::new(fixture.bond.clone(), 1)),
            payment_date(1) - RECORD_OFFSET,
            None,
        );
        fixture.submit(
            AGENT,
            BondInstructionBox::from(DeclareBondDefault::new(fixture.bond.clone(), 1, [0xDE; 32])),
            payment_date(1),
            Some("has not passed"),
        );
        fixture.submit(
            OUTSIDER,
            BondInstructionBox::from(DeclareBondDefault::new(fixture.bond.clone(), 1, [0xDE; 32])),
            payment_date(1) + 1,
            Some("a default declaration must be signed by the paying agent"),
        );
        fixture.submit(
            AGENT,
            BondInstructionBox::from(DeclareBondDefault::new(fixture.bond.clone(), 1, [0xDE; 32])),
            payment_date(1) + 1,
            None,
        );
        let record = fixture.record();
        assert_eq!(record.state.lifecycle, BondLifecycle::Defaulted);
        assert_eq!(
            record.state.cashflows[1].status,
            BondCashflowStatus::Defaulted
        );
        let source = AssetId::new(fixture.eur.clone(), fixture.accounts[AGENT].clone());
        fixture.submit(
            AGENT,
            BondInstructionBox::from(FundBondCashflow::new(fixture.bond.clone(), 1, source)),
            payment_date(1) + 2,
            Some("is Defaulted"),
        );
        // The coupon funded before the default stays claimable.
        let claims = vec![
            fixture.claim(0, Fixture::investor(0)),
            fixture.claim(0, Fixture::investor(1)),
        ];
        fixture.submit_many(AGENT, claims, payment_date(1) + 2, None);
        fixture.close(0, payment_date(1) + 2);
        assert_eq!(fixture.eur(Fixture::investor(0)), q("162.5"));
        assert_eq!(fixture.eur(Fixture::investor(1)), q("81.25"));
        assert_eq!(fixture.vault_eur(), Quantity::zero());
        assert_eq!(fixture.record().state.lifecycle, BondLifecycle::Defaulted);
    }
}
