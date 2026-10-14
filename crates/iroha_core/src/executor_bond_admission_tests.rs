/// Certified Initial execution services native bonds while Core keeps every authority check.
mod bond_admission {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::transaction::TransactionBuilder;
    use iroha_data_model::{
        asset::AssetBalancePolicy,
        bond::{
            BondCallTerms, BondCashflowStatus, BondCashflowTerms, BondDayCount, BondEntitlementId,
            BondIdentifiers, BondLifecycle, BondRecord, BondScheduleRequest, BondTerms,
            bond_vault_account_id, fixed_rate_bullet_schedule,
        },
        isi::bond::{
            BondInstructionBox, CallBond, ClaimBondCashflow, CloseBondCashflow, DeclareBondDefault,
            FundBondCashflow, RecordBondCashflow, RegisterBond, ReplaceBondPayingAgent,
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

    /// Regular semi-annual schedule from 2026-01-15 to 2028-01-15: four coupons and a par
    /// redemption on the last coupon date. Record dates precede payment dates by one day.
    const DAY: u64 = 86_400_000;
    const ISSUE: u64 = 1_768_435_200_000;
    const MATURITY: u64 = 1_831_507_200_000;
    const RECORD_OFFSET: u64 = DAY;
    const GRACE: u64 = 7 * DAY;
    const COUPONS: u16 = 4;

    fn q(text: &str) -> Quantity {
        text.parse().expect("quantity literal")
    }

    fn schedule() -> Vec<BondCashflowTerms> {
        fixed_rate_bullet_schedule(&BondScheduleRequest {
            denomination: q("50"),
            coupon_rate_bps: 650,
            coupon_frequency: 2,
            issue_date_ms: ISSUE,
            maturity_date_ms: MATURITY,
            redemption_price_bps: 10_000,
            record_offset_ms: RECORD_OFFSET,
        })
        .expect("regular schedule")
    }

    fn payment_date(index: u16) -> u64 {
        schedule()[usize::from(index)].payment_date_ms
    }

    fn maturity() -> u64 {
        MATURITY
    }

    struct Fixture {
        chain: CertifiedTestChain,
        keys: Vec<KeyPair>,
        accounts: Vec<AccountId>,
        domain: DomainId,
        bond: AssetDefinitionId,
        eur: AssetDefinitionId,
        now: u64,
        /// Fee asset every transaction pays a Nexus base fee in, when fees are enabled.
        fee_asset: Option<AssetDefinitionId>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::build(false)
        }

        /// A chain whose signed genesis charges a one-unit Nexus base fee on every
        /// transaction; every account holds the fee asset.
        fn with_fees() -> Self {
            Self::build(true)
        }

        fn build(fees: bool) -> Self {
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
            let fee_asset = fees.then(|| {
                AssetDefinitionId::parse_address_literal(
                    &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
                )
                .expect("canonical fee asset")
            });
            let mut definitions = vec![
                AssetDefinition::new(
                    eur.clone(),
                    "EUR e-money",
                    NumericSpec::fractional(2),
                    AssetBalancePolicy::Global,
                    Some(domain.clone()),
                )
                .build(&accounts[AGENT]),
            ];
            let mut assets = vec![
                Asset::new(
                    AssetId::new(eur.clone(), accounts[AGENT].clone()),
                    Quantity::from(1_000_000_u32),
                ),
                Asset::new(
                    AssetId::new(eur.clone(), accounts[ISSUER].clone()),
                    Quantity::from(1_000_u32),
                ),
            ];
            if let Some(fee_asset) = &fee_asset {
                definitions.push(
                    AssetDefinition::numeric(
                        fee_asset.clone(),
                        "xor".to_owned(),
                        AssetBalancePolicy::Global,
                        None,
                    )
                    .build(&accounts[OUTSIDER]),
                );
                assets.extend(accounts.iter().map(|account| {
                    Asset::new(
                        AssetId::new(fee_asset.clone(), account.clone()),
                        Quantity::from(1_000_u32),
                    )
                }));
            }
            let world = World::with_assets(
                [Domain::new(domain.clone()).build(&accounts[ISSUER])],
                accounts.iter().map(|id| Account::new(id.clone()).build(id)),
                definitions,
                assets,
                [],
            );
            let mut config = TestChainConfig::new(world, 1_000);
            if let Some(fee_asset) = &fee_asset {
                let mut nexus = iroha_config::parameters::actual::Nexus::default();
                nexus.fees.base_fee = Quantity::from(1_u32);
                nexus.fees.per_byte_fee = Quantity::zero();
                nexus.fees.per_instruction_fee = Quantity::zero();
                nexus.fees.per_gas_unit_fee = Quantity::zero();
                nexus.fees.fee_asset_id = fee_asset.to_string();
                nexus.fees.fee_sink_account_id = accounts[OUTSIDER].to_string();
                config.nexus = Some(nexus);
            }
            Self {
                chain: CertifiedTestChain::start(config).unwrap(),
                keys,
                accounts,
                domain,
                bond,
                eur,
                now: 1_000,
                fee_asset,
            }
        }

        /// Sign `instructions` for `signer`, consenting to the fixture's Nexus fee when enabled.
        fn sign(
            &self,
            signer: usize,
            instructions: Vec<InstructionBox>,
            created_ms: u64,
        ) -> SignedTransaction {
            let Some(fee_asset) = &self.fee_asset else {
                return self
                    .chain
                    .sign(&self.keys[signer], instructions, created_ms);
            };
            let mut builder = TransactionBuilder::new(
                self.chain.network_id(),
                self.accounts[signer].clone(),
                FeePaymentIntent::authority(
                    vec![FeeChargeLimit::new(
                        FeeChargeKind::Nexus,
                        fee_asset.clone(),
                        Quantity::from(10_u32),
                    )],
                    None,
                ),
            );
            builder.set_creation_time(core::time::Duration::from_millis(created_ms));
            builder
                .with_instructions(instructions)
                .sign(self.keys[signer].private_key())
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
            let transaction = self.sign(signer, instructions, time - 1);
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
            let cashflows = schedule();
            assert_eq!(cashflows.len(), usize::from(COUPONS) + 1);
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
                payment_grace_ms: GRACE,
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

        fn units_entitled(&self, index: u16, slot: usize) -> Option<Quantity> {
            self.chain
                .state()
                .view()
                .world()
                .bond_entitlements()
                .get(&BondEntitlementId::new(
                    self.bond.clone(),
                    index,
                    self.accounts[slot].clone(),
                ))
                .map(|entitlement| entitlement.units.clone())
        }

        fn record_and_fund(&mut self, index: u16, record_date: u64) {
            self.submit(
                AGENT,
                BondInstructionBox::from(RecordBondCashflow::new(self.bond.clone(), index)),
                record_date,
                None,
            );
            assert_eq!(
                self.record().state.cashflows[usize::from(index)].status,
                BondCashflowStatus::Recorded
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
        let instructions: [InstructionBox; 7] = [
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
            BondInstructionBox::from(DeclareBondDefault::new(bond.clone(), 0, [1; 32])).into(),
            BondInstructionBox::from(ReplaceBondPayingAgent::new(
                bond,
                AccountId::new(
                    KeyPair::from_seed(vec![0xBF; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                ),
            ))
            .into(),
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
            AssetId::new(
                fixture.bond.clone(),
                fixture.accounts[Fixture::investor(1)].clone(),
            ),
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

        // Recording opens at the record date; from then the books stay closed until it is
        // recorded, and any account may record because the result is the holders of record.
        let record_0 = payment_date(0) - RECORD_OFFSET;
        fixture.submit(
            AGENT,
            BondInstructionBox::from(RecordBondCashflow::new(fixture.bond.clone(), 0)),
            record_0 - 1,
            Some("bond.too_early"),
        );
        let closed = Transfer::asset_quantity(
            AssetId::new(
                fixture.bond.clone(),
                fixture.accounts[Fixture::investor(2)].clone(),
            ),
            1_u32,
            fixture.accounts[OUTSIDER].clone(),
        );
        fixture.submit(
            Fixture::investor(2),
            closed,
            record_0,
            Some("bond.books_closed"),
        );
        fixture.submit(
            OUTSIDER,
            BondInstructionBox::from(RecordBondCashflow::new(fixture.bond.clone(), 0)),
            record_0,
            None,
        );
        let source = AssetId::new(fixture.eur.clone(), fixture.accounts[AGENT].clone());
        fixture.submit(
            AGENT,
            BondInstructionBox::from(FundBondCashflow::new(fixture.bond.clone(), 0, source)),
            record_0,
            None,
        );
        let cashflow = fixture.record().state.cashflows[0].clone();
        assert_eq!(cashflow.status, BondCashflowStatus::Funded);
        assert_eq!(cashflow.holders, u32::try_from(INVESTORS).unwrap());
        assert_eq!(
            fixture.units_entitled(0, Fixture::investor(0)),
            Some(q("15"))
        );
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
            .try_fold(Quantity::zero(), |total, payment| {
                total.checked_add(&payment)
            })
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
            AssetId::new(
                fixture.bond.clone(),
                fixture.accounts[Fixture::investor(2)].clone(),
            ),
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
        assert_eq!(fixture.record().state.cashflows[0].claimed_holders, 0);
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
        assert_eq!(
            fixture.record().state.cashflows[usize::from(COUPONS)].claimed_holders,
            0
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

    /// A paid Nexus fee does not use the sixteen-delta entry budget of the claims it
    /// carries: the bootstrap profile bounds the body, and the fee is charged separately.
    #[test]
    fn initial_fee_paying_claims_keep_the_sixteen_claim_bound() {
        let _guard = crate::status::nexus_fee_test_lock()
            .lock()
            .expect("nexus fee test lock");
        crate::status::reset_nexus_economics_for_tests();
        let mut fixture = Fixture::with_fees();
        let fee_asset = fixture.fee_asset.clone().expect("fees enabled");
        let fee_balance =
            |fixture: &Fixture, slot: usize| fixture.balance(&fee_asset, &fixture.accounts[slot]);
        fixture.issue(None, &[10; MAX_INVESTORS]);
        fixture.record_and_fund(0, payment_date(0) - RECORD_OFFSET);
        let claims = |fixture: &Fixture, holders: core::ops::Range<usize>| {
            holders
                .map(|n| fixture.claim(0, Fixture::investor(n)))
                .collect::<Vec<InstructionBox>>()
        };
        let agent_fee = fee_balance(&fixture, AGENT);
        let over = claims(&fixture, 0..MAX_INVESTORS);
        fixture.submit_many(
            AGENT,
            over,
            payment_date(0),
            Some(crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION),
        );
        assert_eq!(fixture.record().state.cashflows[0].claimed_holders, 0);
        let full = claims(&fixture, 0..16);
        fixture.submit_many(AGENT, full, payment_date(0), None);
        assert_eq!(fixture.record().state.cashflows[0].claimed_holders, 16);
        assert!(
            fee_balance(&fixture, AGENT) < agent_fee,
            "the agent paid its fees"
        );
    }

    #[test]
    fn initial_bond_call_redeems_a_single_holder_at_the_call_price() {
        let mut fixture = Fixture::new();
        let call = BondCallTerms {
            first_call_date_ms: payment_date(1),
            price_bps: 10_100,
            notice_ms: 30 * DAY,
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
            call_date - 31 * DAY,
            Some("a call must be signed by the issuer"),
        );
        fixture.submit(
            ISSUER,
            BondInstructionBox::from(CallBond::new(fixture.bond.clone(), call_date)),
            call_date - 31 * DAY,
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
            payment_date(1) + GRACE,
            Some("grace period have not passed"),
        );
        fixture.submit(
            OUTSIDER,
            BondInstructionBox::from(DeclareBondDefault::new(fixture.bond.clone(), 1, [0xDE; 32])),
            payment_date(1) + GRACE + 1,
            Some("a default declaration must be signed by the paying agent"),
        );
        fixture.submit(
            AGENT,
            BondInstructionBox::from(DeclareBondDefault::new(fixture.bond.clone(), 1, [0xDE; 32])),
            payment_date(1) + GRACE + 1,
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
            payment_date(1) + GRACE + 2,
            Some("is Defaulted"),
        );
        // The coupon funded before the default stays claimable.
        let claims = vec![
            fixture.claim(0, Fixture::investor(0)),
            fixture.claim(0, Fixture::investor(1)),
        ];
        fixture.submit_many(AGENT, claims, payment_date(1) + GRACE + 2, None);
        fixture.close(0, payment_date(1) + GRACE + 2);
        assert_eq!(fixture.eur(Fixture::investor(0)), q("162.5"));
        assert_eq!(fixture.eur(Fixture::investor(1)), q("81.25"));
        assert_eq!(fixture.vault_eur(), Quantity::zero());
        assert_eq!(fixture.record().state.lifecycle, BondLifecycle::Defaulted);
    }
}
