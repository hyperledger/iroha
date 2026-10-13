//! Core bond-kernel validation and transition tests (`specs/finance/bond_ops.md`).
use core::num::NonZeroU64;

use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Registrable as _,
    account::Account,
    asset::{Asset, AssetDefinition},
    block::BlockHeader,
    bond::{
        BondCallTerms, BondDayCount, BondIdentifiers, BondScheduleRequest, BondTerms,
        bond_vault_account_id, fixed_rate_bullet_schedule,
    },
    domain::Domain,
    escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, EscrowId,
    },
    isi::{
        Burn, Mint, Transfer, Unregister,
        escrow::OpenConditionalEscrow,
        repo::{RepoIsi, ReverseRepoIsi},
    },
    permission::Permission,
    repo::{RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::NumericSpec;

use super::*;
use crate::{
    kura::Kura,
    prelude::World,
    query::store::LiveQueryStore,
    state::{State, StateReadOnly},
};

const DAY: u64 = 86_400_000;
const ISSUE: u64 = 1_768_435_200_000; // 2026-01-15
const COUPON_0: u64 = 1_784_073_600_000; // 2026-07-15
const COUPON_1: u64 = 1_799_971_200_000; // 2027-01-15
const COUPON_2: u64 = 1_815_609_600_000; // 2027-07-15
const MATURITY: u64 = 1_831_507_200_000; // 2028-01-15

const ISSUER: usize = 0;
const AGENT: usize = 1;
const HOLDER_A: usize = 2;
const HOLDER_B: usize = 3;
const HOLDER_C: usize = 4;
const OUTSIDER: usize = 5;

fn q(text: &str) -> Quantity {
    text.parse().expect("quantity literal")
}

fn accounts() -> [AccountId; 6] {
    [0x31, 0x32, 0x33, 0x34, 0x35, 0x36].map(|seed| {
        AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    })
}

fn domain() -> DomainId {
    DomainId::try_new("bonds", "universal").expect("domain")
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), name.parse().expect("asset name"))
}

/// Semi-annual 6.50 % bond, denomination 50: coupon 1.625 per unit, four coupons and a par
/// redemption, callable from the second coupon date at 101 %.
fn terms(ids: &[AccountId; 6]) -> BondTerms {
    let cashflows = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("50"),
        coupon_rate_bps: 650,
        coupon_frequency: 2,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        record_offset_ms: DAY,
    })
    .expect("regular schedule");
    BondTerms {
        issuer: ids[ISSUER].clone(),
        paying_agent: ids[AGENT].clone(),
        payment_asset: definition("eur"),
        denomination: q("50"),
        coupon_rate_bps: 650,
        coupon_frequency: 2,
        day_count: BondDayCount::Thirty360,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        call: Some(BondCallTerms {
            first_call_date_ms: COUPON_1,
            price_bps: 10_100,
            notice_ms: 30 * DAY,
        }),
        cashflows,
        identifiers: BondIdentifiers {
            isin: Some("SI0031234567".to_owned()),
            cfi: Some("DBFTFB".to_owned()),
            issuer_lei: None,
            bdt_version: "bdt-1.0".to_owned(),
            bdt_document_sha256: None,
        },
        terms_sha256: [9; 32],
    }
}

struct Harness {
    state: State,
    height: u64,
    ids: [AccountId; 6],
    bond: AssetDefinitionId,
    eur: AssetDefinitionId,
}

impl Harness {
    /// Issuer holds 700 units, holders A/B/C hold 200/99/1; the agent and issuer hold EUR.
    fn new() -> Self {
        Self::with_holdings(&[(HOLDER_A, 200), (HOLDER_B, 99), (HOLDER_C, 1)])
    }

    fn with_holdings(holdings: &[(usize, u32)]) -> Self {
        let ids = accounts();
        let bond = definition("slo_bond");
        let eur = definition("eur");
        let issuer = &ids[ISSUER];
        let investor_units: u32 = holdings.iter().map(|(_, units)| units).sum();
        let mut assets = vec![
            Asset::new(
                AssetId::new(bond.clone(), issuer.clone()),
                Quantity::from(1_000 - investor_units),
            ),
            Asset::new(
                AssetId::new(eur.clone(), ids[AGENT].clone()),
                Quantity::from(100_000_u32),
            ),
            Asset::new(
                AssetId::new(eur.clone(), issuer.clone()),
                Quantity::from(100_000_u32),
            ),
            Asset::new(
                AssetId::new(eur.clone(), ids[HOLDER_B].clone()),
                Quantity::from(10_000_u32),
            ),
        ];
        assets.extend(holdings.iter().map(|(holder, units)| {
            Asset::new(
                AssetId::new(bond.clone(), ids[*holder].clone()),
                Quantity::from(*units),
            )
        }));
        let world = World::with_assets(
            [Domain::new(domain()).build(issuer)],
            ids.iter().map(|id| Account::new(id.clone()).build(id)),
            [
                AssetDefinition::new(
                    bond.clone(),
                    "SLO bond",
                    NumericSpec::integer(),
                    AssetBalancePolicy::Global,
                    Some(domain()),
                )
                .build(issuer),
                AssetDefinition::new(
                    eur.clone(),
                    "EUR",
                    NumericSpec::fractional(2),
                    AssetBalancePolicy::Global,
                    Some(domain()),
                )
                .build(issuer),
            ],
            assets,
            [],
        );
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        Self {
            state,
            height: 0,
            ids,
            bond,
            eur,
        }
    }

    /// Execute `f` in its own block at `time_ms`; the transaction is applied only on success.
    fn run<R>(
        &mut self,
        time_ms: u64,
        f: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.height += 1;
        let header = BlockHeader::new(
            NonZeroU64::new(self.height).expect("height"),
            None,
            None,
            time_ms,
            0,
        );
        let mut block = self.state.block(header);
        let result = {
            let mut stx = block.transaction_for_callback_testing();
            let result = f(&mut stx);
            if result.is_ok() {
                stx.apply();
            }
            result
        };
        block
            .commit_world_overlay_for_testing()
            .expect("commit test block");
        result
    }

    fn exec(
        &mut self,
        time_ms: u64,
        signer: usize,
        instruction: impl Into<BondInstructionBox>,
    ) -> Result<(), Error> {
        let authority = self.ids[signer].clone();
        let instruction = instruction.into();
        self.run(time_ms, |stx| instruction.execute(&authority, stx))
    }

    fn exec_ok(&mut self, time_ms: u64, signer: usize, instruction: impl Into<BondInstructionBox>) {
        let instruction = instruction.into();
        let rendered = instruction.to_string();
        if let Err(error) = self.exec(time_ms, signer, instruction) {
            panic!("{rendered} must succeed: {error}");
        }
    }

    fn exec_err(
        &mut self,
        time_ms: u64,
        signer: usize,
        instruction: impl Into<BondInstructionBox>,
        fragment: &str,
    ) {
        let instruction = instruction.into();
        let rendered = instruction.to_string();
        let error = self
            .exec(time_ms, signer, instruction)
            .expect_err(&format!("{rendered} must be rejected"));
        assert!(
            error.to_string().contains(fragment),
            "{rendered}: expected `{fragment}`, got `{error}`"
        );
    }

    fn register(&mut self) {
        let terms = terms(&self.ids);
        self.exec_ok(ISSUE, ISSUER, RegisterBond::new(self.bond.clone(), terms));
    }

    fn record(&self) -> BondRecord {
        self.state
            .view()
            .world()
            .bonds()
            .get(&self.bond)
            .cloned()
            .expect("registered bond")
    }

    fn balance(&self, definition: &AssetDefinitionId, account: &AccountId) -> Quantity {
        self.state
            .view()
            .world()
            .assets()
            .get(&AssetId::new(definition.clone(), account.clone()))
            .map_or_else(Quantity::zero, |value| value.as_ref().clone())
    }

    fn eur_of(&self, who: usize) -> Quantity {
        self.balance(&self.eur, &self.ids[who])
    }

    fn units_of(&self, who: usize) -> Quantity {
        self.balance(&self.bond, &self.ids[who])
    }

    fn vault_eur(&self) -> Quantity {
        self.balance(&self.eur, &bond_vault_account_id(&self.bond))
    }

    fn total_units(&self) -> Quantity {
        self.state
            .view()
            .world()
            .asset_definitions()
            .get(&self.bond)
            .expect("bond definition")
            .total_quantity()
            .clone()
    }

    fn transfer_units(
        &mut self,
        time_ms: u64,
        from: usize,
        to: usize,
        units: u32,
    ) -> Result<(), Error> {
        let source = AssetId::new(self.bond.clone(), self.ids[from].clone());
        let destination = self.ids[to].clone();
        let authority = self.ids[from].clone();
        self.run(time_ms, |stx| {
            Transfer::asset_quantity(source, units, destination).execute(&authority, stx)
        })
    }

    fn record_fund_cashflow(&mut self, index: u16, record_at: u64) {
        self.exec_ok(
            record_at,
            AGENT,
            RecordBondCashflow::new(self.bond.clone(), index),
        );
        let source = AssetId::new(self.eur.clone(), self.ids[AGENT].clone());
        self.exec_ok(
            record_at,
            AGENT,
            FundBondCashflow::new(self.bond.clone(), index, source),
        );
    }

    fn claim(&mut self, time_ms: u64, signer: usize, index: u16, holder: usize) {
        let holder = self.ids[holder].clone();
        self.exec_ok(
            time_ms,
            signer,
            ClaimBondCashflow::new(self.bond.clone(), index, holder),
        );
    }

    fn claim_all(&mut self, time_ms: u64, index: u16) {
        for holder in [HOLDER_A, HOLDER_B, HOLDER_C] {
            self.claim(time_ms, AGENT, index, holder);
        }
    }

    fn service_coupon(&mut self, index: u16) {
        let terms = self.record().state.cashflows[usize::from(index)]
            .terms
            .clone();
        self.record_fund_cashflow(index, terms.record_date_ms);
        self.claim_all(terms.payment_date_ms, index);
        self.exec_ok(
            terms.payment_date_ms,
            AGENT,
            CloseBondCashflow::new(self.bond.clone(), index),
        );
    }
}

fn bond_events(stx: &StateTransaction<'_, '_>) -> Vec<BondEvent> {
    stx.world
        .internal_event_buf
        .iter()
        .filter_map(|event| match event.as_ref() {
            DataEvent::Bond(event) => Some(event.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn registration_requires_the_issuer_owning_a_scale0_global_definition() {
    let mut h = Harness::new();
    let terms = terms(&h.ids);
    // Only the issuer signs.
    h.exec_err(
        ISSUE,
        AGENT,
        RegisterBond::new(h.bond.clone(), terms.clone()),
        "bond.unauthorized: registration must be signed by the issuer",
    );
    // Registered terms must validate.
    let mut invalid = terms.clone();
    invalid.cashflows.pop();
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), invalid),
        "bond.invalid_terms",
    );
    // The payment asset must differ from the bond and exist.
    let mut same = terms.clone();
    same.payment_asset = h.bond.clone();
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), same),
        "payment asset must differ",
    );
    let mut missing = terms.clone();
    missing.payment_asset = definition("missing");
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), missing),
        "Entity missing",
    );
    // A fractional definition cannot carry bond units.
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.eur.clone(), {
            let mut eur_terms = terms.clone();
            eur_terms.payment_asset = h.bond.clone();
            eur_terms
        }),
        "scale 0",
    );
    // The issuer must own the bond definition.
    let mut foreign = terms.clone();
    foreign.issuer = h.ids[OUTSIDER].clone();
    h.exec_err(
        ISSUE,
        OUTSIDER,
        RegisterBond::new(h.bond.clone(), foreign),
        "the issuer must own the bond asset definition",
    );
    // Success: outstanding is the minted total and the vault is derived.
    let event = h
        .run(ISSUE, |stx| {
            RegisterBond::new(h_bond(), terms.clone()).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("registration");
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Active);
    assert_eq!(record.state.outstanding_units, q("1000"));
    assert_eq!(record.state.redeemed_units, Quantity::zero());
    assert!(!record.state.transfers_frozen);
    assert_eq!(record.vault, bond_vault_account_id(&h.bond));
    assert_eq!(record.state.cashflows.len(), 5);
    assert!(
        record
            .state
            .cashflows
            .iter()
            .all(|cashflow| cashflow.status == BondCashflowStatus::Scheduled)
    );
    assert_eq!(
        event,
        [BondEvent::Registered(BondRegistered {
            bond: h.bond.clone(),
            issuer: h.ids[ISSUER].clone(),
            paying_agent: h.ids[AGENT].clone(),
            outstanding_units: q("1000"),
            cashflows: 5,
        })]
    );
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), terms),
        "bond.already_registered",
    );
}

fn h_bond() -> AssetDefinitionId {
    definition("slo_bond")
}

#[test]
fn registration_rejects_unissued_and_dataspace_scoped_bonds() {
    let mut h = Harness::with_holdings(&[]);
    // Burn the issuer's whole supply first: an unissued bond cannot be registered.
    let issuer = h.ids[ISSUER].clone();
    let units = AssetId::new(h.bond.clone(), issuer.clone());
    h.run(ISSUE, |stx| {
        Burn::asset_quantity(1_000_u32, units).execute(&issuer, stx)
    })
    .expect("burn unregistered supply");
    let terms = terms(&h.ids);
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), terms),
        "mint the issued units before registering the bond",
    );
}

#[test]
fn bond_supply_is_locked_after_registration() {
    let mut h = Harness::new();
    h.register();
    let issuer = h.ids[ISSUER].clone();
    let own = AssetId::new(h.bond.clone(), issuer.clone());
    let holder = AssetId::new(h.bond.clone(), h.ids[HOLDER_A].clone());
    let mint = own.clone();
    let error = h
        .run(ISSUE + 1, |stx| {
            Mint::asset_quantity(1_u32, mint).execute(&issuer, stx)
        })
        .expect_err("mint after registration");
    assert!(error.to_string().contains("bond.supply_locked"), "{error}");
    for source in [own, holder] {
        let error = h
            .run(ISSUE + 1, |stx| {
                Burn::asset_quantity(1_u32, source).execute(&issuer, stx)
            })
            .expect_err("burn after registration");
        assert!(error.to_string().contains("bond.supply_locked"), "{error}");
    }
    assert_eq!(h.total_units(), q("1000"));
}

#[test]
fn record_requires_agent_record_date_order_and_builds_investor_snapshot() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.exec_err(
        record_0,
        ISSUER,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.unauthorized: recording must be signed by the paying agent",
    );
    h.exec_err(
        record_0 - 1,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.too_early",
    );
    h.exec_err(
        COUPON_1,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 1),
        "cash flow 0 must be recorded first",
    );
    h.exec_err(
        record_0,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 9),
        "bond.unknown_cashflow",
    );
    // OTC transfer before the record date moves the entitlement.
    h.transfer_units(record_0 - DAY, HOLDER_A, HOLDER_C, 20)
        .expect("transfer before record date");
    let events = h
        .run(record_0, |stx| {
            RecordBondCashflow::new(h_bond(), 0).execute(&accounts()[AGENT], stx)?;
            Ok(bond_events(stx))
        })
        .expect("record");
    let record = h.record();
    let cashflow = &record.state.cashflows[0];
    assert_eq!(cashflow.status, BondCashflowStatus::Recorded);
    assert_eq!(cashflow.recorded_at_ms, Some(record_0));
    // The issuer's 700 retained units are excluded.
    assert_eq!(
        cashflow.snapshot,
        BTreeMap::from([
            (h.ids[HOLDER_A].clone(), q("180")),
            (h.ids[HOLDER_B].clone(), q("99")),
            (h.ids[HOLDER_C].clone(), q("21")),
        ])
    );
    assert_eq!(cashflow.entitled_units, q("300"));
    // 180 x 1.625 = 292.50; 99 x 1.625 = 160.875 -> 160.87; 21 x 1.625 = 34.125 -> 34.12.
    assert_eq!(cashflow.amount_due, q("487.49"));
    assert!(
        !record.state.transfers_frozen,
        "coupons do not freeze transfers"
    );
    assert_eq!(
        events,
        [BondEvent::CashflowRecorded(BondCashflowRecorded {
            bond: h.bond.clone(),
            index: 0,
            kind: BondCashflowKind::Coupon,
            holders: 3,
            entitled_units: q("300"),
            amount_due: q("487.49"),
        })]
    );
    h.exec_err(
        record_0,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "is Recorded, not Scheduled",
    );
    // Transfers after the coupon record date do not change the recorded entitlement.
    h.transfer_units(record_0 + 1, HOLDER_C, HOLDER_A, 21)
        .expect("ex-coupon transfer");
    assert_eq!(h.record().state.cashflows[0].snapshot.len(), 3);
}

#[test]
fn record_rejects_snapshots_above_the_holder_limit() {
    let mut h = Harness::with_holdings(&[]);
    h.register();
    // Seed one more investor balance than a snapshot admits.
    let extra = BOND_MAX_SNAPSHOT_HOLDERS + 1;
    let bond = h.bond.clone();
    h.run(ISSUE + 1, |stx| {
        for seed in 0..extra {
            let seed = u32::try_from(seed).expect("seed");
            let mut bytes = [0x77_u8; 32];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            let holder = AccountId::new(
                KeyPair::from_seed(bytes.to_vec(), Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            );
            crate::smartcontracts::isi::helpers::ensure_custody_account(&holder, stx)?;
            crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                &mut stx.world,
                &AssetId::new(bond.clone(), holder),
                &Quantity::from(1_u32),
            )?;
        }
        Ok(())
    })
    .expect("seed holders");
    h.exec_err(
        COUPON_0 - DAY,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.snapshot_too_large",
    );
}

#[test]
fn fund_moves_exactly_the_amount_due_from_the_signers_balance() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_err(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, agent_eur.clone()),
        "is Scheduled, not Recorded",
    );
    h.exec_ok(record_0, AGENT, RecordBondCashflow::new(h.bond.clone(), 0));
    for (signer, source, fragment) in [
        (
            OUTSIDER,
            AssetId::new(h.eur.clone(), h.ids[OUTSIDER].clone()),
            "funding must be signed by the paying agent or the issuer",
        ),
        (
            AGENT,
            AssetId::new(h.eur.clone(), h.ids[ISSUER].clone()),
            "the funding source must be the signer's global payment-asset balance",
        ),
        (
            AGENT,
            AssetId::new(h.bond.clone(), h.ids[AGENT].clone()),
            "the funding source must be the signer's global payment-asset balance",
        ),
    ] {
        h.exec_err(
            record_0,
            signer,
            FundBondCashflow::new(h.bond.clone(), 0, source),
            fragment,
        );
    }
    // The issuer may fund from its own balance, before the payment date.
    let issuer_eur = AssetId::new(h.eur.clone(), h.ids[ISSUER].clone());
    let events = h
        .run(record_0, |stx| {
            FundBondCashflow::new(h_bond(), 0, issuer_eur).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("issuer funding");
    assert_eq!(h.vault_eur(), q("487.49"));
    assert_eq!(h.eur_of(ISSUER), q("99512.51"));
    let cashflow = h.record().state.cashflows[0].clone();
    assert_eq!(cashflow.status, BondCashflowStatus::Funded);
    assert_eq!(cashflow.funded, q("487.49"));
    assert_eq!(cashflow.funded_at_ms, Some(record_0));
    assert_eq!(
        events,
        [BondEvent::CashflowFunded(BondCashflowFunded {
            bond: h.bond.clone(),
            index: 0,
            amount: q("487.49"),
        })]
    );
    h.exec_err(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, agent_eur),
        "is Funded, not Recorded",
    );
}

#[test]
fn fund_without_balance_changes_nothing() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.exec_ok(record_0, AGENT, RecordBondCashflow::new(h.bond.clone(), 0));
    // Holder B is no funder; give the agent an empty EUR balance by moving it away first.
    let agent = h.ids[AGENT].clone();
    let agent_eur = AssetId::new(h.eur.clone(), agent.clone());
    let sink = h.ids[OUTSIDER].clone();
    let drain = agent_eur.clone();
    h.run(record_0, |stx| {
        Transfer::asset_quantity(drain, 99_900_u32, sink).execute(&agent, stx)
    })
    .expect("drain agent");
    h.exec_err(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, agent_eur),
        "",
    );
    assert_eq!(h.vault_eur(), Quantity::zero());
    assert_eq!(
        h.record().state.cashflows[0].status,
        BondCashflowStatus::Recorded
    );
}

#[test]
fn claims_pay_rounded_entitlements_once_from_the_payment_date() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.exec_ok(record_0, AGENT, RecordBondCashflow::new(h.bond.clone(), 0));
    h.exec_err(
        COUPON_0,
        HOLDER_A,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_A].clone()),
        "is Recorded, not Funded",
    );
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, agent_eur),
    );
    h.exec_err(
        COUPON_0 - 1,
        HOLDER_A,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_A].clone()),
        "bond.too_early",
    );
    h.exec_err(
        COUPON_0,
        OUTSIDER,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_A].clone()),
        "a claim must be signed by the holder or pushed by the paying agent",
    );
    h.exec_err(
        COUPON_0,
        ISSUER,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[ISSUER].clone()),
        "bond.not_in_snapshot",
    );
    // Holder self-claim.
    let events = h
        .run(COUPON_0, |stx| {
            ClaimBondCashflow::new(h_bond(), 0, accounts()[HOLDER_A].clone())
                .execute(&accounts()[HOLDER_A], stx)?;
            Ok(bond_events(stx))
        })
        .expect("holder claim");
    assert_eq!(h.eur_of(HOLDER_A), q("325"));
    assert_eq!(
        events,
        [BondEvent::CashflowClaimed(BondCashflowClaimed {
            bond: h.bond.clone(),
            index: 0,
            holder: h.ids[HOLDER_A].clone(),
            units: q("200"),
            amount: q("325"),
        })]
    );
    h.exec_err(
        COUPON_0,
        HOLDER_A,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_A].clone()),
        "bond.already_claimed",
    );
    // Paying-agent push: the holder, never the agent, receives the payment.
    let agent_before = h.eur_of(AGENT);
    h.claim(COUPON_0, AGENT, 0, HOLDER_B);
    assert_eq!(h.eur_of(HOLDER_B), q("10160.87"));
    assert_eq!(h.eur_of(AGENT), agent_before);
    h.exec_err(
        COUPON_0,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
        "still has unclaimed snapshot holders",
    );
    h.claim(COUPON_0, HOLDER_C, 0, HOLDER_C);
    assert_eq!(h.eur_of(HOLDER_C), q("1.62"));
    let cashflow = h.record().state.cashflows[0].clone();
    assert_eq!(cashflow.paid, q("487.49"));
    assert!(cashflow.all_claimed());
    assert_eq!(h.vault_eur(), Quantity::zero());
    h.exec_err(
        COUPON_0,
        HOLDER_A,
        CloseBondCashflow::new(h.bond.clone(), 0),
        "closing must be signed by the paying agent",
    );
    h.exec_ok(COUPON_0, AGENT, CloseBondCashflow::new(h.bond.clone(), 0));
    let record = h.record();
    assert_eq!(record.state.cashflows[0].status, BondCashflowStatus::Closed);
    assert_eq!(record.state.cashflows[0].closed_at_ms, Some(COUPON_0));
    assert_eq!(record.state.lifecycle, BondLifecycle::Active);
}

#[test]
fn close_returns_any_vault_remainder_to_the_issuer() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.record_fund_cashflow(0, record_0);
    h.claim_all(COUPON_0, 0);
    // Rounded-down claims sum exactly to the amount due, so the residual is zero by
    // construction; force a remainder into the record to exercise the residual movement.
    let bond = h.bond.clone();
    let eur = h.eur.clone();
    h.run(COUPON_0, |stx| {
        let mut record = stx.world.bonds.get(&bond).cloned().expect("record");
        let vault = record.vault.clone();
        record.state.cashflows[0].funded = q("487.50");
        stx.world.bonds.insert(bond.clone(), record);
        crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
            &mut stx.world,
            &AssetId::new(eur, vault),
            &q("0.01"),
        )
    })
    .expect("inject remainder");
    let issuer_before = h.eur_of(ISSUER);
    let events = h
        .run(COUPON_0, |stx| {
            CloseBondCashflow::new(h_bond(), 0).execute(&accounts()[AGENT], stx)?;
            Ok(bond_events(stx))
        })
        .expect("close with residual");
    assert_eq!(
        h.eur_of(ISSUER),
        issuer_before.checked_add(&q("0.01")).unwrap()
    );
    assert_eq!(h.vault_eur(), Quantity::zero());
    assert_eq!(
        events,
        [BondEvent::CashflowClosed(BondCashflowClosed {
            bond: h.bond.clone(),
            index: 0,
            residual: q("0.01"),
        })]
    );
}

#[test]
fn redemption_record_freezes_every_movement_and_claims_burn_then_pay() {
    let mut h = Harness::new();
    h.register();
    for index in 0..4 {
        h.service_coupon(index);
    }
    let redemption_record = MATURITY;
    h.exec_ok(
        redemption_record,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 4),
    );
    let record = h.record();
    assert!(record.state.transfers_frozen);
    assert_eq!(record.state.cashflows[4].amount_due, q("15000"));
    // Ordinary transfers, including by the issuer, are refused.
    let error = h
        .transfer_units(redemption_record, HOLDER_A, OUTSIDER, 1)
        .expect_err("frozen transfer");
    assert!(
        error.to_string().contains("bond.transfers_frozen"),
        "{error}"
    );
    let error = h
        .transfer_units(redemption_record, ISSUER, HOLDER_A, 1)
        .expect_err("frozen issuer transfer");
    assert!(
        error.to_string().contains("bond.transfers_frozen"),
        "{error}"
    );
    // Conditional escrow opening moves bond units into custody and is refused too.
    let bond = h.bond.clone();
    let beneficiary = h.ids[OUTSIDER].clone();
    let attestor = h.ids[AGENT].clone();
    let opener = h.ids[HOLDER_A].clone();
    let error = h
        .run(redemption_record, |stx| {
            open_escrow(&bond, &beneficiary, &attestor, 5).execute(&opener, stx)
        })
        .expect_err("frozen escrow");
    assert!(
        error.to_string().contains("bond.transfers_frozen"),
        "{error}"
    );
    // Repo initiation with the bond as collateral is refused.
    let error = h
        .run(redemption_record, |stx| {
            initiate_repo(stx, HOLDER_A, HOLDER_B, MATURITY + DAY)
        })
        .expect_err("frozen repo");
    assert!(
        error.to_string().contains("bond.transfers_frozen"),
        "{error}"
    );
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        redemption_record,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 4, agent_eur),
    );
    // Holder self-claim burns its units and pays the redemption amount.
    let events = h
        .run(MATURITY, |stx| {
            ClaimBondCashflow::new(h_bond(), 4, accounts()[HOLDER_A].clone())
                .execute(&accounts()[HOLDER_A], stx)?;
            Ok(bond_events(stx))
        })
        .expect("redemption claim");
    assert_eq!(h.units_of(HOLDER_A), Quantity::zero());
    assert_eq!(h.total_units(), q("800"));
    assert_eq!(
        events,
        [BondEvent::CashflowClaimed(BondCashflowClaimed {
            bond: h.bond.clone(),
            index: 4,
            holder: h.ids[HOLDER_A].clone(),
            units: q("200"),
            amount: q("10000"),
        })]
    );
    let record = h.record();
    assert_eq!(record.state.outstanding_units, q("800"));
    assert_eq!(record.state.redeemed_units, q("200"));
    // Paying-agent push redemption.
    h.claim(MATURITY, AGENT, 4, HOLDER_B);
    h.claim(MATURITY, AGENT, 4, HOLDER_C);
    assert_eq!(h.units_of(HOLDER_B), Quantity::zero());
    assert_eq!(h.units_of(HOLDER_C), Quantity::zero());
    assert_eq!(
        h.total_units(),
        q("700"),
        "only issuer-retained units remain"
    );
    assert_eq!(h.vault_eur(), Quantity::zero());
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.outstanding_units, q("700"));
    assert_eq!(record.state.redeemed_units, q("300"));
    // A matured bond accepts no further servicing.
    h.exec_err(
        MATURITY,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 4, [1; 32]),
        "is Matured",
    );
}

#[test]
fn redemption_claim_fails_atomically_when_units_are_missing() {
    let mut h = Harness::new();
    h.register();
    for index in 0..4 {
        h.service_coupon(index);
    }
    h.record_fund_cashflow(4, MATURITY);
    // Remove holder A's units behind the kernel's back: the burn must fail and no payment
    // may leave the vault.
    let bond = h.bond.clone();
    let holder = h.ids[HOLDER_A].clone();
    h.run(MATURITY, |stx| {
        let network = stx.network_id().clone();
        crate::smartcontracts::isi::asset::isi::debit_numeric_asset_balance_for_test(
            &mut stx.world,
            &network,
            &AssetId::new(bond, holder),
            &Quantity::from(1_u32),
        )
    })
    .expect("corrupt balance");
    let vault_before = h.vault_eur();
    h.exec_err(
        MATURITY,
        AGENT,
        ClaimBondCashflow::new(h.bond.clone(), 4, h.ids[HOLDER_A].clone()),
        "",
    );
    assert_eq!(h.vault_eur(), vault_before);
    assert_eq!(h.eur_of(HOLDER_A), q("1300"));
    assert!(h.record().state.cashflows[4].claimed.is_empty());
}

#[test]
fn bond_vault_is_protocol_custody() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    let vault = bond_vault_account_id(&h.bond);
    // Nobody can debit the vault directly, even with a forged vault authority.
    let source = AssetId::new(h.eur.clone(), vault.clone());
    let destination = h.ids[OUTSIDER].clone();
    let error = h
        .run(COUPON_0, |stx| {
            Transfer::asset_quantity(source, 1_u32, destination).execute(&vault, stx)
        })
        .expect_err("vault debit");
    assert!(error.to_string().contains("bond.vault_custody"), "{error}");
    // Nobody can credit the vault outside FundBondCashflow.
    let agent = h.ids[AGENT].clone();
    let agent_eur = AssetId::new(h.eur.clone(), agent.clone());
    let vault_destination = bond_vault_account_id(&h.bond);
    let error = h
        .run(COUPON_0, |stx| {
            Transfer::asset_quantity(agent_eur, 1_u32, vault_destination).execute(&agent, stx)
        })
        .expect_err("vault credit");
    assert!(error.to_string().contains("bond.vault_custody"), "{error}");
    let issuer = h.ids[ISSUER].clone();
    let mint = AssetId::new(h.eur.clone(), bond_vault_account_id(&h.bond));
    let error = h
        .run(COUPON_0, |stx| {
            Mint::asset_quantity(1_u32, mint).execute(&issuer, stx)
        })
        .expect_err("vault mint");
    assert!(error.to_string().contains("bond.vault_custody"), "{error}");
    assert_eq!(h.vault_eur(), q("487.49"));
}

fn open_escrow(
    bond: &AssetDefinitionId,
    beneficiary: &AccountId,
    attestor: &AccountId,
    units: u32,
) -> OpenConditionalEscrow {
    OpenConditionalEscrow::new(
        EscrowId::new(Hash::new(b"bond_allotment")),
        bond.clone(),
        beneficiary.clone(),
        units,
        vec![ConditionalEscrowCondition::Oracle(
            ConditionalEscrowOracleCondition {
                id: "paid".parse().unwrap(),
                attestor: attestor.clone(),
                predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(true)),
                sequence: core::num::NonZeroU32::new(1).unwrap(),
            },
        )],
        MATURITY + 365 * DAY,
    )
}

fn repo(initiator: usize, counterparty: usize, maturity_ms: u64) -> RepoIsi {
    let ids = accounts();
    RepoIsi::new(
        RepoAgreementId::new("bond_repo".parse().unwrap()),
        ids[initiator].clone(),
        ids[counterparty].clone(),
        None,
        RepoCashLeg::new(definition("eur"), 100_u32),
        RepoCollateralLeg::new(definition("slo_bond"), 10_u32),
        0,
        maturity_ms,
        RepoGovernance::new(0, 0, false),
    )
}

/// Initiate a repo where `initiator` pledges 10 bond units to `counterparty` for 100 EUR.
fn initiate_repo(
    stx: &mut StateTransaction<'_, '_>,
    initiator: usize,
    counterparty: usize,
    maturity_ms: u64,
) -> Result<(), Error> {
    let ids = accounts();
    let instruction = repo(initiator, counterparty, maturity_ms);
    let settlement_id = instruction.settlement_id();
    let consents = [
        Permission::from(CanExecuteSettlement {
            debited_asset: AssetId::new(definition("eur"), ids[counterparty].clone()),
            settlement_id: settlement_id.clone(),
            intent_hash: instruction.initiation_intent_hash(),
        }),
        Permission::from(CanExecuteSettlement {
            debited_asset: AssetId::new(definition("slo_bond"), ids[counterparty].clone()),
            settlement_id,
            intent_hash: instruction.maturity_intent_hash(),
        }),
    ];
    let mut permissions = stx
        .world
        .account_permissions
        .get(&ids[initiator])
        .cloned()
        .unwrap_or_default();
    permissions.extend(consents);
    stx.world
        .account_permissions
        .insert(ids[initiator].clone(), permissions);
    instruction.execute(&ids[initiator], stx)
}

#[test]
fn record_is_refused_while_repo_collateral_or_pending_allotments_encumber_units() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    // Holder A pledges 10 units to holder B in an open repo.
    h.run(ISSUE + DAY, |stx| {
        initiate_repo(stx, HOLDER_A, HOLDER_B, COUPON_0 - 2 * DAY)
    })
    .expect("repo initiation");
    h.exec_err(
        record_0,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.encumbered: active repo agreement",
    );
    let agreement = RepoAgreementId::new("bond_repo".parse().unwrap());
    let counterparty = h.ids[HOLDER_B].clone();
    h.run(record_0, |stx| {
        ReverseRepoIsi::new(agreement).execute(&counterparty, stx)
    })
    .expect("repo maturity");
    // The issuer allots units to an investor through a conditional escrow.
    let bond = h.bond.clone();
    let investor = h.ids[OUTSIDER].clone();
    let attestor = h.ids[AGENT].clone();
    let issuer = h.ids[ISSUER].clone();
    h.run(record_0, |stx| {
        open_escrow(&bond, &investor, &attestor, 25).execute(&issuer, stx)
    })
    .expect("allotment escrow");
    h.exec_err(
        record_0,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.encumbered: active native escrow",
    );
    // Release the allotment; the investor now holds the units directly.
    let escrow = EscrowId::new(Hash::new(b"bond_allotment"));
    h.run(record_0, |stx| {
        iroha_data_model::isi::escrow::AttestEscrowCondition::new(
            escrow,
            "paid".parse().unwrap(),
            ConditionalEscrowValue::Bool(true),
            None,
        )
        .execute(&attestor, stx)
    })
    .expect("release allotment");
    h.exec_ok(record_0, AGENT, RecordBondCashflow::new(h.bond.clone(), 0));
    let snapshot = h.record().state.cashflows[0].snapshot.clone();
    assert_eq!(snapshot.get(&h.ids[OUTSIDER]), Some(&q("25")));
    assert_eq!(snapshot.get(&h.ids[HOLDER_A]), Some(&q("200")));
}

#[test]
fn issuer_escrow_custody_is_excluded_from_snapshots() {
    let mut h = Harness::new();
    h.register();
    // An escrow whose beneficiary is the issuer itself is no pending allotment; its custody
    // balance is neither an encumbrance nor an investor holding.
    let bond = h.bond.clone();
    let issuer = h.ids[ISSUER].clone();
    let attestor = h.ids[AGENT].clone();
    let beneficiary = issuer.clone();
    h.run(ISSUE + DAY, |stx| {
        open_escrow(&bond, &beneficiary, &attestor, 50).execute(&issuer, stx)
    })
    .expect("issuer escrow");
    h.exec_ok(
        COUPON_0 - DAY,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
    );
    let cashflow = h.record().state.cashflows[0].clone();
    assert_eq!(cashflow.entitled_units, q("300"));
    assert_eq!(cashflow.snapshot.len(), 3);
}

#[test]
fn call_replaces_later_cashflows_with_one_redemption() {
    let mut h = Harness::new();
    h.register();
    h.service_coupon(0);
    let notice = 30 * DAY;
    // Too little notice: a separate bond reaches the call window late.
    let mut late = Harness::new();
    late.register();
    late.exec_err(
        COUPON_1 - notice + 1,
        ISSUER,
        CallBond::new(late.bond.clone(), COUPON_1),
        "notice",
    );
    h.exec_err(
        COUPON_1 - notice,
        AGENT,
        CallBond::new(h.bond.clone(), COUPON_1),
        "a call must be signed by the issuer",
    );
    h.exec_err(
        COUPON_1 - notice,
        ISSUER,
        CallBond::new(h.bond.clone(), COUPON_0),
        "precedes the first call date",
    );
    h.exec_err(
        COUPON_1 - notice,
        ISSUER,
        CallBond::new(h.bond.clone(), COUPON_1 + DAY),
        "is not a scheduled coupon payment date",
    );
    h.exec_err(
        COUPON_1 - notice,
        ISSUER,
        CallBond::new(h.bond.clone(), MATURITY),
        "a call must precede maturity",
    );
    let events = h
        .run(COUPON_1 - notice, |stx| {
            CallBond::new(h_bond(), COUPON_1).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("call");
    assert_eq!(
        events,
        [BondEvent::Called(BondCalled {
            bond: h.bond.clone(),
            call_date_ms: COUPON_1,
            redemption_index: 5,
        })]
    );
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Called);
    let statuses: Vec<_> = record
        .state
        .cashflows
        .iter()
        .map(|cashflow| cashflow.status)
        .collect();
    assert_eq!(
        statuses,
        [
            BondCashflowStatus::Closed,
            BondCashflowStatus::Scheduled,
            BondCashflowStatus::Cancelled,
            BondCashflowStatus::Cancelled,
            BondCashflowStatus::Cancelled,
            BondCashflowStatus::Scheduled,
        ]
    );
    let call = &record.state.cashflows[5].terms;
    assert_eq!(call.index, 5);
    assert_eq!(call.kind, BondCashflowKind::Redemption);
    assert_eq!(call.payment_date_ms, COUPON_1);
    assert_eq!(call.record_date_ms, COUPON_1 - DAY);
    assert_eq!(call.amount_per_unit, q("50.5"));
    // The registered terms are immutable.
    assert_eq!(record.terms.cashflows.len(), 5);
    h.exec_err(
        COUPON_1 - notice,
        ISSUER,
        CallBond::new(h.bond.clone(), COUPON_1),
        "is Called, not Active",
    );
    // Cancelled cash flows cannot be serviced.
    h.exec_err(
        COUPON_2,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 2),
        "is Cancelled, not Scheduled",
    );
    // The call redemption is recorded after the call-date coupon.
    h.exec_err(
        COUPON_1 - DAY,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 5),
        "cash flow 1 must be recorded first",
    );
    h.service_coupon(1);
    h.record_fund_cashflow(5, COUPON_1);
    assert!(h.record().state.transfers_frozen);
    assert_eq!(h.vault_eur(), q("15150"));
    h.claim_all(COUPON_1, 5);
    h.exec_ok(COUPON_1, AGENT, CloseBondCashflow::new(h.bond.clone(), 5));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.redeemed_units, q("300"));
    assert_eq!(
        h.eur_of(HOLDER_A),
        q("650").checked_add(&q("10100")).unwrap()
    );
}

#[test]
fn default_requires_a_missed_unfunded_payment_and_stops_servicing() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    h.exec_err(
        COUPON_0 + 1,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 0, [7; 32]),
        "is Funded and cannot default",
    );
    h.exec_ok(
        COUPON_1 - DAY,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 1),
    );
    h.exec_err(
        COUPON_1,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 1, [7; 32]),
        "has not passed",
    );
    h.exec_err(
        COUPON_1 + 1,
        ISSUER,
        DeclareBondDefault::new(h.bond.clone(), 1, [7; 32]),
        "a default declaration must be signed by the paying agent",
    );
    let events = h
        .run(COUPON_1 + 1, |stx| {
            DeclareBondDefault::new(h_bond(), 1, [7; 32]).execute(&accounts()[AGENT], stx)?;
            Ok(bond_events(stx))
        })
        .expect("default");
    assert_eq!(
        events,
        [BondEvent::Defaulted(BondDefaulted {
            bond: h.bond.clone(),
            index: 1,
            evidence_sha256: [7; 32],
        })]
    );
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Defaulted);
    assert_eq!(
        record.state.cashflows[1].status,
        BondCashflowStatus::Defaulted
    );
    assert_eq!(record.state.cashflows[1].evidence_sha256, Some([7; 32]));
    // No further recording, funding, call or default.
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_err(
        COUPON_1 + 1,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 1, agent_eur),
        "is Defaulted",
    );
    h.exec_err(
        COUPON_2,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 2),
        "is Defaulted",
    );
    h.exec_err(
        COUPON_2,
        ISSUER,
        CallBond::new(h.bond.clone(), MATURITY - DAY),
        "is Defaulted, not Active",
    );
    // Funds already in the vault stay claimable by their holders and the cash flow closes.
    h.claim_all(COUPON_1 + 1, 0);
    h.exec_ok(
        COUPON_1 + 1,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
    );
    assert_eq!(h.vault_eur(), Quantity::zero());
    assert_eq!(h.record().state.lifecycle, BondLifecycle::Defaulted);
}

#[test]
fn bond_records_retain_definitions_and_accounts() {
    let mut h = Harness::new();
    h.register();
    h.exec_ok(
        COUPON_0 - DAY,
        AGENT,
        RecordBondCashflow::new(h.bond.clone(), 0),
    );
    let issuer = h.ids[ISSUER].clone();
    for definition in [h.bond.clone(), h.eur.clone()] {
        let error = h
            .run(COUPON_0, |stx| {
                Unregister::asset_definition(definition).execute(&issuer, stx)
            })
            .expect_err("retained definition");
        assert!(error.to_string().contains("bond.retained"), "{error}");
    }
    for account in [ISSUER, AGENT, HOLDER_A] {
        let target = h.ids[account].clone();
        let error = h
            .run(COUPON_0, |stx| {
                Unregister::account(target).execute(&issuer, stx)
            })
            .expect_err("retained account");
        assert!(error.to_string().contains("bond.retained"), "{error}");
    }
    let domain = domain();
    let error = h
        .run(COUPON_0, |stx| {
            Unregister::domain(domain).execute(&issuer, stx)
        })
        .expect_err("retained domain definitions");
    assert!(error.to_string().contains("bond.retained"), "{error}");
}

#[test]
fn verified_movements_reject_capabilities_that_do_not_match_the_record() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    let bond = h.bond.clone();
    let eur = h.eur.clone();
    let ids = h.ids.clone();
    let vault = bond_vault_account_id(&bond);
    let cases = [
        // Paying a non-holder.
        (
            VerifiedBondMovementPurpose::Payment,
            AGENT,
            AssetId::new(eur.clone(), vault.clone()),
            AssetId::new(eur.clone(), ids[OUTSIDER].clone()),
            q("1"),
        ),
        // Paying more than the funded remainder.
        (
            VerifiedBondMovementPurpose::Payment,
            AGENT,
            AssetId::new(eur.clone(), vault.clone()),
            AssetId::new(eur.clone(), ids[HOLDER_A].clone()),
            q("487.50"),
        ),
        // Residual before every holder claimed.
        (
            VerifiedBondMovementPurpose::Residual,
            AGENT,
            AssetId::new(eur.clone(), vault.clone()),
            AssetId::new(eur.clone(), ids[ISSUER].clone()),
            q("0.01"),
        ),
        // Funding a funded cash flow.
        (
            VerifiedBondMovementPurpose::Funding,
            AGENT,
            AssetId::new(eur.clone(), ids[AGENT].clone()),
            AssetId::new(eur.clone(), vault.clone()),
            q("487.49"),
        ),
        // Paying a different asset.
        (
            VerifiedBondMovementPurpose::Payment,
            AGENT,
            AssetId::new(bond.clone(), vault.clone()),
            AssetId::new(bond.clone(), ids[HOLDER_A].clone()),
            q("1"),
        ),
    ];
    for (purpose, signer, source, destination, amount) in cases {
        let error = h
            .run(COUPON_0, |stx| {
                crate::smartcontracts::isi::asset::isi::execute_verified_bond_movement(
                    stx,
                    VerifiedBondMovement::new(
                        purpose,
                        &ids[signer],
                        &bond,
                        0,
                        source,
                        destination,
                        amount,
                    ),
                )
            })
            .expect_err("mismatched capability");
        assert!(
            error.to_string().contains("capability does not match"),
            "{error}"
        );
    }
    assert_eq!(h.vault_eur(), q("487.49"));
}
