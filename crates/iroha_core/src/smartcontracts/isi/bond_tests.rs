//! Core bond-kernel validation and transition tests (`specs/finance/bond_ops.md`).
use core::num::NonZeroU64;
use std::collections::BTreeSet;

use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Registrable as _,
    account::{Account, AccountController},
    asset::{
        ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, Asset, AssetDefinition, AssetIssuerUsagePolicyV1,
        AssetSubjectBindingV1,
    },
    block::BlockHeader,
    bond::{
        BOND_RECORDING_PAGE_ENTRIES, BondCallTerms, BondDayCount, BondEntitlement, BondIdentifiers,
        BondScheduleRequest, BondTerms, bond_vault_account_id, fixed_rate_bullet_schedule,
    },
    domain::Domain,
    escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, EscrowId,
    },
    isi::{
        Burn, Mint, SetKeyValue, Transfer, Unregister,
        escrow::{
            AcceptAssetEscrow, AttestEscrowCondition, CancelAssetEscrow, MarkEscrowPaymentSent,
            OpenAssetEscrow, OpenConditionalEscrow, ReleaseAssetEscrow,
        },
        repo::{RepoIsi, ReverseRepoIsi},
        settlement::{
            AtomicSettlementEscrow, AtomicSettlementEscrows, AtomicSettlementMovement,
            AtomicSettlementMovements, SettleAtomic, SettlementId,
        },
        transfer::{TransferAssetBatch, TransferAssetBatchEntry},
    },
    permission::Permission,
    query::error::FindError,
    repo::{RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use iroha_primitives::{json::Json, numeric::NumericSpec};

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
const GRACE: u64 = 7 * DAY;

const ISSUER: usize = 0;
const AGENT: usize = 1;
const HOLDER_A: usize = 2;
const HOLDER_B: usize = 3;
const HOLDER_C: usize = 4;
const OUTSIDER: usize = 5;
const NEW_AGENT: usize = 6;
const ACCOUNTS: usize = 7;

fn q(text: &str) -> Quantity {
    text.parse().expect("quantity literal")
}

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}

fn accounts() -> [AccountId; ACCOUNTS] {
    [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37].map(account)
}

fn domain() -> DomainId {
    DomainId::try_new("bonds", "universal").expect("domain")
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), name.parse().expect("asset name"))
}

/// Semi-annual 6.50 % bond, denomination 50: coupon 1.625 per unit, four coupons and a par
/// redemption, callable from the second coupon date at 101 %, seven days of payment grace.
fn terms(ids: &[AccountId; ACCOUNTS]) -> BondTerms {
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
        payment_grace_ms: GRACE,
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
    ids: [AccountId; ACCOUNTS],
    bond: AssetDefinitionId,
    eur: AssetDefinitionId,
    holdings: Vec<(usize, u32)>,
}

impl Harness {
    /// The issuer mints 1 000 units; after registration holders A/B/C receive 200/99/1.
    fn new() -> Self {
        Self::with_holdings(&[(HOLDER_A, 200), (HOLDER_B, 99), (HOLDER_C, 1)])
    }

    fn with_holdings(holdings: &[(usize, u32)]) -> Self {
        let ids = accounts();
        let bond = definition("slo_bond");
        let eur = definition("eur");
        let issuer = &ids[ISSUER];
        let scale0 = |name: &str, label: &str, policy, owner: &AccountId| {
            AssetDefinition::new(
                definition(name),
                label,
                NumericSpec::integer(),
                policy,
                Some(domain()),
            )
            .build(owner)
        };
        let assets = vec![
            Asset::new(
                AssetId::new(bond.clone(), issuer.clone()),
                Quantity::from(1_000_u32),
            ),
            Asset::new(
                AssetId::new(definition("other_bond"), issuer.clone()),
                Quantity::from(100_u32),
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
        let world = World::with_assets(
            [Domain::new(domain()).build(issuer)],
            ids.iter().map(|id| Account::new(id.clone()).build(id)),
            [
                scale0("slo_bond", "SLO bond", AssetBalancePolicy::Global, issuer),
                scale0(
                    "other_bond",
                    "Other bond",
                    AssetBalancePolicy::Global,
                    issuer,
                ),
                scale0(
                    "ds_bond",
                    "Dataspace bond",
                    AssetBalancePolicy::DataspaceRestricted,
                    issuer,
                ),
                scale0(
                    "orphan_bond",
                    "Bond of an unregistered issuer",
                    AssetBalancePolicy::Global,
                    &account(0x98),
                ),
                AssetDefinition::new(
                    eur.clone(),
                    "EUR",
                    NumericSpec::fractional(2),
                    AssetBalancePolicy::Global,
                    Some(domain()),
                )
                .build(issuer),
                AssetDefinition::new(
                    definition("ds_eur"),
                    "Dataspace EUR",
                    NumericSpec::fractional(2),
                    AssetBalancePolicy::DataspaceRestricted,
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
            holdings: holdings.to_vec(),
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

    /// Register the bond while the issuer holds the whole supply, then distribute it.
    fn register(&mut self) {
        let terms = terms(&self.ids);
        self.exec_ok(ISSUE, ISSUER, RegisterBond::new(self.bond.clone(), terms));
        for (holder, units) in self.holdings.clone() {
            self.transfer_units(ISSUE, ISSUER, holder, units)
                .expect("allotment after registration");
        }
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

    fn cashflow(&self, index: u16) -> BondCashflowState {
        self.record().state.cashflows[usize::from(index)].clone()
    }

    fn entitlement(&self, index: u16, who: &AccountId) -> Option<BondEntitlement> {
        self.state
            .view()
            .world()
            .bond_entitlements()
            .get(&BondEntitlementId::new(
                self.bond.clone(),
                index,
                who.clone(),
            ))
            .cloned()
    }

    fn entitled_units(&self, index: u16, who: usize) -> Option<Quantity> {
        self.entitlement(index, &self.ids[who])
            .map(|entitlement| entitlement.units)
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

    /// Record a cash flow to completion, one page per block.
    fn record_cashflow(&mut self, time_ms: u64, signer: usize, index: u16) -> usize {
        let mut steps = 0;
        loop {
            self.exec_ok(
                time_ms,
                signer,
                RecordBondCashflow::new(self.bond.clone(), index),
            );
            steps += 1;
            if self.cashflow(index).status != BondCashflowStatus::Recording {
                return steps;
            }
            assert!(steps < 64, "recording must finish");
        }
    }

    fn record_fund_cashflow(&mut self, index: u16, record_at: u64) {
        self.record_cashflow(record_at, AGENT, index);
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
        let terms = self.cashflow(index).terms;
        self.record_fund_cashflow(index, terms.record_date_ms);
        self.claim_all(terms.payment_date_ms, index);
        self.exec_ok(
            terms.payment_date_ms,
            AGENT,
            CloseBondCashflow::new(self.bond.clone(), index),
        );
    }

    fn set_usage_policy(&mut self, time: u64, definition: &AssetDefinitionId, bound: &[AccountId]) {
        let policy = AssetIssuerUsagePolicyV1 {
            require_subject_binding: true,
            subject_bindings: bound
                .iter()
                .map(|account| (account.clone(), AssetSubjectBindingV1::default()))
                .collect(),
        };
        let issuer = self.ids[ISSUER].clone();
        let definition = definition.clone();
        self.run(time, |stx| {
            SetKeyValue::asset_definition(
                definition,
                ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
                    .parse()
                    .expect("metadata key"),
                Json::new(policy),
            )
            .execute(&issuer, stx)
        })
        .expect("issuer sets a usage policy");
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

fn h_bond() -> AssetDefinitionId {
    definition("slo_bond")
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
            eur_terms.payment_asset = definition("other_bond");
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
    // Every unit must still be with the issuer: nothing can sit in custody the kernel
    // does not attribute before the record exists.
    h.transfer_units(ISSUE, ISSUER, HOLDER_A, 1)
        .expect("pre-registration transfer");
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), terms.clone()),
        "the issuer must hold the entire minted supply",
    );
    h.transfer_units(ISSUE, HOLDER_A, ISSUER, 1)
        .expect("return the unit");
    // Success: outstanding is the minted total and the vault is derived and indexed.
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
    assert_eq!(
        h.state
            .view()
            .world()
            .bond_vaults()
            .get(&record.vault)
            .cloned(),
        Some(h.bond.clone())
    );
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
        RegisterBond::new(h.bond.clone(), terms.clone()),
        "bond.already_registered",
    );
    // Bonds and payment assets stay disjoint, so a vault never holds bond units.
    let mut on_bond = terms.clone();
    on_bond.payment_asset = h.bond.clone();
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(definition("other_bond"), on_bond),
        "the payment asset must not be a registered bond",
    );
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.eur.clone(), {
            let mut eur_terms = terms;
            eur_terms.payment_asset = definition("other_bond");
            eur_terms
        }),
        "is the payment asset of bond",
    );
}

#[test]
fn registration_rejects_dataspace_scoped_unissued_and_partyless_bonds() {
    let mut h = Harness::with_holdings(&[]);
    let terms = terms(&h.ids);
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(definition("ds_bond"), terms.clone()),
        "bond asset definition must keep global balances",
    );
    let mut dataspace_payment = terms.clone();
    dataspace_payment.payment_asset = definition("ds_eur");
    h.exec_err(
        ISSUE,
        ISSUER,
        RegisterBond::new(h.bond.clone(), dataspace_payment),
        "payment asset definition must keep global balances",
    );
    // The issuer and the paying agent must be existing accounts.
    let mut no_agent = terms.clone();
    no_agent.paying_agent = account(0x99);
    let error = h
        .exec(ISSUE, ISSUER, RegisterBond::new(h.bond.clone(), no_agent))
        .expect_err("missing paying agent");
    assert!(
        matches!(&error, Error::Find(FindError::Account(missing)) if *missing == account(0x99)),
        "{error:?}"
    );
    let orphan_issuer = account(0x98);
    let mut orphan = terms.clone();
    orphan.issuer = orphan_issuer.clone();
    let error = h
        .run(ISSUE, |stx| {
            RegisterBond::new(definition("orphan_bond"), orphan).execute(&orphan_issuer, stx)
        })
        .expect_err("missing issuer account");
    assert!(
        matches!(&error, Error::Find(FindError::Account(missing)) if *missing == account(0x98)),
        "{error:?}"
    );
    // Burn the issuer's whole supply first: an unissued bond cannot be registered.
    let issuer = h.ids[ISSUER].clone();
    let units = AssetId::new(h.bond.clone(), issuer.clone());
    h.run(ISSUE, |stx| {
        Burn::asset_quantity(1_000_u32, units).execute(&issuer, stx)
    })
    .expect("burn unregistered supply");
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
fn recording_is_permissionless_and_captures_record_date_holdings() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.exec_err(
        record_0 - 1,
        OUTSIDER,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "bond.too_early",
    );
    h.exec_err(
        COUPON_1,
        OUTSIDER,
        RecordBondCashflow::new(h.bond.clone(), 1),
        "cash flow 0 must be recorded first",
    );
    h.exec_err(
        record_0,
        OUTSIDER,
        RecordBondCashflow::new(h.bond.clone(), 9),
        "bond.unknown_cashflow",
    );
    // OTC transfer before the record date moves the entitlement.
    h.transfer_units(record_0 - DAY, HOLDER_A, HOLDER_C, 20)
        .expect("transfer before record date");
    // Any account may record: the books are closed, so the result cannot depend on it.
    let events = h
        .run(record_0, |stx| {
            RecordBondCashflow::new(h_bond(), 0).execute(&accounts()[OUTSIDER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("record");
    let cashflow = h.cashflow(0);
    assert_eq!(cashflow.status, BondCashflowStatus::Recorded);
    assert_eq!(cashflow.recorded_at_ms, Some(record_0));
    assert_eq!(cashflow.recording, None);
    // The issuer's 700 retained units are excluded.
    assert_eq!(h.entitled_units(0, HOLDER_A), Some(q("180")));
    assert_eq!(h.entitled_units(0, HOLDER_B), Some(q("99")));
    assert_eq!(h.entitled_units(0, HOLDER_C), Some(q("21")));
    assert_eq!(h.entitled_units(0, ISSUER), None);
    assert_eq!(cashflow.holders, 3);
    assert_eq!(cashflow.entitled_units, q("300"));
    // 180 x 1.625 = 292.50; 99 x 1.625 = 160.875 -> 160.87; 21 x 1.625 = 34.125 -> 34.12.
    assert_eq!(
        h.entitlement(0, &h.ids[HOLDER_B]).unwrap().amount,
        q("160.87")
    );
    assert_eq!(cashflow.amount_due, q("487.49"));
    assert!(
        !h.record().state.transfers_frozen,
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
        "is Recorded, not Scheduled or Recording",
    );
    // Transfers after recording reopen the books and do not change entitlements.
    h.transfer_units(record_0 + 1, HOLDER_C, HOLDER_A, 21)
        .expect("ex-coupon transfer");
    assert_eq!(h.entitled_units(0, HOLDER_C), Some(q("21")));
}

#[test]
fn books_close_from_the_record_date_until_recording_completes() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.transfer_units(record_0 - 1, HOLDER_A, HOLDER_C, 10)
        .expect("transfer before the record date");
    // From the record date nothing moves until the cash flow is recorded, so a late
    // recording still captures the holders of record.
    for (time, from, to) in [
        (record_0, HOLDER_A, HOLDER_C),
        (COUPON_0 + 5 * DAY, HOLDER_C, OUTSIDER),
        (COUPON_0 + 5 * DAY, ISSUER, HOLDER_A),
    ] {
        let error = h
            .transfer_units(time, from, to, 1)
            .expect_err("books are closed");
        assert!(error.to_string().contains("bond.books_closed"), "{error}");
    }
    h.record_cashflow(COUPON_0 + 5 * DAY, OUTSIDER, 0);
    assert_eq!(h.entitled_units(0, HOLDER_A), Some(q("190")));
    assert_eq!(h.entitled_units(0, HOLDER_C), Some(q("11")));
    h.transfer_units(COUPON_0 + 5 * DAY, HOLDER_A, OUTSIDER, 1)
        .expect("books reopen after recording");
    // The final coupon and the redemption share a record date: recording the coupon
    // does not reopen the books before the redemption is recorded too.
    let source = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        COUPON_0 + 5 * DAY,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, source),
    );
    for index in 1..3 {
        h.service_coupon(index);
    }
    h.record_cashflow(MATURITY - DAY, AGENT, 3);
    let error = h
        .transfer_units(MATURITY - DAY, HOLDER_A, OUTSIDER, 1)
        .expect_err("still closed for the redemption");
    assert!(error.to_string().contains("bond.books_closed"), "{error}");
    h.record_cashflow(MATURITY - DAY, AGENT, 4);
    assert!(h.record().state.transfers_frozen);
    assert_eq!(h.entitled_units(3, HOLDER_A), h.entitled_units(4, HOLDER_A));
}

#[test]
fn recording_is_paged_and_unbounded_in_holders() {
    let mut h = Harness::new();
    h.register();
    // Seed more investor balances than one recording step examines.
    let extra = BOND_RECORDING_PAGE_ENTRIES + 90;
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
    let record_0 = COUPON_0 - DAY;
    h.exec_ok(
        record_0,
        OUTSIDER,
        RecordBondCashflow::new(h.bond.clone(), 0),
    );
    let partial = h.cashflow(0);
    assert_eq!(partial.status, BondCashflowStatus::Recording);
    let cursor = partial.recording.clone().expect("cursor");
    assert_eq!(cursor.phase, BondRecordingPhase::Holders);
    assert!(cursor.after_asset.is_some());
    // While the cursor walks the balances nothing moves and nothing defaults.
    let error = h
        .transfer_units(record_0, HOLDER_A, OUTSIDER, 1)
        .expect_err("recording in progress");
    assert!(error.to_string().contains("is being recorded"), "{error}");
    h.exec_err(
        COUPON_0 + GRACE + 1,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 0, [1; 32]),
        "complete the recording first",
    );
    h.exec_err(
        record_0,
        ISSUER,
        RetireBondTreasuryUnits::new(h.bond.clone(), 1_u32),
        "is being recorded",
    );
    let error = h
        .run(record_0, |stx| {
            crate::smartcontracts::isi::multisig::replace_account_controller(
                &accounts()[HOLDER_A],
                stx,
                &accounts()[HOLDER_A],
                AccountController::Single(key(0x51).public_key().clone()),
            )
            .map_err(Error::from)
        })
        .expect_err("rekey during recording");
    assert!(error.to_string().contains("is being recorded"), "{error}");
    let steps = 1 + h.record_cashflow(record_0, OUTSIDER, 0);
    assert_eq!(steps, 2);
    let cashflow = h.cashflow(0);
    assert_eq!(cashflow.status, BondCashflowStatus::Recorded);
    let extra = u32::try_from(extra).unwrap();
    assert_eq!(cashflow.holders, extra + 3);
    assert_eq!(cashflow.entitled_units, Quantity::from(300 + extra));
    // Each seeded holder receives 1.62; the three investors 487.49 between them.
    let seeded = Quantity::from(extra)
        .try_mul_decimal(q("1.62").as_numeric())
        .expect("seeded amount");
    assert_eq!(
        cashflow.amount_due,
        q("487.49").checked_add(&seeded).unwrap()
    );
}

fn escrow_id(label: &str) -> EscrowId {
    EscrowId::new(Hash::new(format!("bond-test-escrow:{label}")))
}

fn open_conditional(
    bond: &AssetDefinitionId,
    label: &str,
    beneficiary: &AccountId,
    attestor: &AccountId,
    units: u32,
) -> OpenConditionalEscrow {
    OpenConditionalEscrow::new(
        escrow_id(label),
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

fn grant_settlement_consents(
    stx: &mut StateTransaction<'_, '_>,
    grantee: &AccountId,
    consents: impl IntoIterator<Item = Permission>,
) {
    let mut permissions = stx
        .world
        .account_permissions
        .get(grantee)
        .cloned()
        .unwrap_or_default();
    permissions.extend(consents);
    stx.world
        .account_permissions
        .insert(grantee.clone(), permissions);
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
    grant_settlement_consents(stx, &ids[initiator], consents);
    instruction.execute(&ids[initiator], stx)
}

/// Settle atomically: `seller` delivers one bond unit (as a movement, or as a conditional
/// escrow leg) against one euro from `buyer`.
fn settle_atomic(
    stx: &mut StateTransaction<'_, '_>,
    seller: usize,
    buyer: usize,
    escrow_leg: bool,
) -> Result<(), Error> {
    let ids = accounts();
    let bond_source = AssetId::new(definition("slo_bond"), ids[seller].clone());
    let cash_source = AssetId::new(definition("eur"), ids[buyer].clone());
    let mut movements = vec![AtomicSettlementMovement {
        source: cash_source.clone(),
        recipient: ids[seller].clone(),
        quantity: Quantity::one(),
    }];
    let mut escrows = Vec::new();
    if escrow_leg {
        escrows.push(AtomicSettlementEscrow {
            source: bond_source.clone(),
            escrow_id: escrow_id("settlement-leg"),
            beneficiary: ids[buyer].clone(),
            amount: Quantity::one(),
            conditions: vec![ConditionalEscrowCondition::Oracle(
                ConditionalEscrowOracleCondition {
                    id: "paid".parse().unwrap(),
                    attestor: ids[AGENT].clone(),
                    predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(
                        true,
                    )),
                    sequence: core::num::NonZeroU32::new(1).unwrap(),
                },
            )],
            expires_at_ms: MATURITY + 365 * DAY,
            evidence_hashes: Vec::new(),
        });
    } else {
        movements.push(AtomicSettlementMovement {
            source: bond_source.clone(),
            recipient: ids[buyer].clone(),
            quantity: Quantity::one(),
        });
    }
    movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    let instruction = SettleAtomic::new(
        stx.network_id.clone(),
        SettlementId::new(
            ids[seller].clone(),
            "frozen_bond_trade".parse().expect("settlement reference"),
        ),
        AtomicSettlementMovements::try_from(movements).expect("canonical movements"),
        AtomicSettlementEscrows::try_from(escrows).expect("canonical escrows"),
        NonZeroU64::new(1_000).expect("expiry"),
        Metadata::default(),
    );
    stx.tx_call_hash = Some(Hash::new(b"frozen-bond-settlement-carrier"));
    let intent_hash = instruction.intent_hash().expect("complete intent");
    let consents = [bond_source, cash_source].map(|source| {
        Permission::from(CanExecuteSettlement {
            debited_asset: source,
            settlement_id: instruction.settlement_id().clone(),
            intent_hash,
        })
    });
    grant_settlement_consents(stx, &ids[seller], consents);
    instruction.execute(&ids[seller], stx)
}

/// Encumbrances cannot veto recording: escrowed units count for their seller, repo
/// collateral for its title holder, and unreleased allotments for the issuer.
#[test]
fn escrows_and_repos_are_attributed_to_holders_of_record_and_cannot_veto_recording() {
    let mut h = Harness::new();
    h.register();
    let bond = h.bond.clone();
    // A never-expiring marketplace escrow of 5 units, accepted by an outsider.
    let seller = h.ids[HOLDER_A].clone();
    let listing = OpenAssetEscrow::new(escrow_id("listing"), bond.clone(), 5_u32);
    h.run(ISSUE + DAY, |stx| listing.execute(&seller, stx))
        .expect("open listing");
    let outsider = h.ids[OUTSIDER].clone();
    h.run(ISSUE + DAY, |stx| {
        AcceptAssetEscrow::new(escrow_id("listing")).execute(&outsider, stx)
    })
    .expect("outsider accepts");
    // A repo from A to B that is never settled: B holds the collateral title.
    h.run(ISSUE + DAY, |stx| {
        initiate_repo(stx, HOLDER_A, HOLDER_B, COUPON_0 - 2 * DAY)
    })
    .expect("repo initiation");
    // An issuer allotment escrow that is still conditional at the record date.
    let issuer = h.ids[ISSUER].clone();
    let attestor = h.ids[AGENT].clone();
    let allotment = open_conditional(&bond, "allotment", &outsider, &attestor, 25);
    h.run(ISSUE + DAY, |stx| allotment.execute(&issuer, stx))
        .expect("allotment escrow");
    assert_eq!(h.units_of(HOLDER_A), q("185"));
    h.record_cashflow(COUPON_0 - DAY, OUTSIDER, 0);
    assert_eq!(h.entitled_units(0, HOLDER_A), Some(q("190")));
    assert_eq!(h.entitled_units(0, HOLDER_B), Some(q("109")));
    assert_eq!(h.entitled_units(0, HOLDER_C), Some(q("1")));
    assert_eq!(h.entitled_units(0, OUTSIDER), None);
    assert_eq!(h.cashflow(0).entitled_units, q("300"));
    assert_eq!(h.cashflow(0).holders, 3);
    // Once recorded, the books reopen and the allotment settles normally.
    h.run(COUPON_0 - DAY, |stx| {
        AttestEscrowCondition::new(
            escrow_id("allotment"),
            "paid".parse().unwrap(),
            ConditionalEscrowValue::Bool(true),
            None,
        )
        .execute(&attestor, stx)
    })
    .expect("release allotment");
    assert_eq!(h.units_of(OUTSIDER), q("25"));
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
    h.record_cashflow(record_0, AGENT, 0);
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
    let cashflow = h.cashflow(0);
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
    h.record_cashflow(record_0, AGENT, 0);
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
    assert_eq!(h.cashflow(0).status, BondCashflowStatus::Recorded);
}

#[test]
fn claims_pay_rounded_entitlements_once_from_the_payment_date() {
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.record_cashflow(record_0, AGENT, 0);
    h.exec_err(
        COUPON_0,
        HOLDER_A,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_A].clone()),
        "is Recorded, not Funded or Closed",
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
        "bond.not_entitled",
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
    assert_eq!(
        h.entitlement(0, &h.ids[HOLDER_A]).unwrap().claimed_at_ms,
        Some(COUPON_0)
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
    h.claim(COUPON_0, HOLDER_C, 0, HOLDER_C);
    assert_eq!(h.eur_of(HOLDER_C), q("1.62"));
    let cashflow = h.cashflow(0);
    assert_eq!(cashflow.paid, q("487.49"));
    assert_eq!(cashflow.claimed_holders, 3);
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

/// A cash flow closes at its payment date whatever its holders do; unclaimed
/// entitlements stay payable from the vault, so nothing is trapped and nobody blocks maturity.
#[test]
fn closing_keeps_unclaimed_entitlements_claimable_and_matures_the_bond() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    h.exec_err(
        COUPON_0 - 1,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
        "bond.too_early",
    );
    let events = h
        .run(COUPON_0, |stx| {
            CloseBondCashflow::new(h_bond(), 0).execute(&accounts()[AGENT], stx)?;
            Ok(bond_events(stx))
        })
        .expect("close with nobody paid");
    assert_eq!(
        events,
        [BondEvent::CashflowClosed(BondCashflowClosed {
            bond: h.bond.clone(),
            index: 0,
            unclaimed_holders: 3,
            unclaimed_amount: q("487.49"),
        })]
    );
    assert_eq!(h.vault_eur(), q("487.49"));
    // Claims of a closed cash flow are still paid from the vault.
    h.claim(COUPON_0 + 30 * DAY, HOLDER_A, 0, HOLDER_A);
    assert_eq!(h.eur_of(HOLDER_A), q("325"));
    assert_eq!(h.vault_eur(), q("162.49"));
    for index in 1..4 {
        h.service_coupon(index);
    }
    // The redemption closes with holder C unclaimed; the bond still matures.
    h.record_fund_cashflow(4, MATURITY);
    h.claim(MATURITY, AGENT, 4, HOLDER_A);
    h.claim(MATURITY, AGENT, 4, HOLDER_B);
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.outstanding_units, q("701"));
    // C redeems after maturity: burn and pay from the vault.
    h.claim(MATURITY + 90 * DAY, HOLDER_C, 4, HOLDER_C);
    assert_eq!(h.units_of(HOLDER_C), Quantity::zero());
    assert_eq!(h.record().state.outstanding_units, q("700"));
    assert_eq!(h.record().state.redeemed_units, q("300"));
    // Only B's and C's unclaimed first coupon remain in the vault.
    assert_eq!(h.vault_eur(), q("162.49"));
}

/// Every movement path of a frozen bond is refused, except escrow custody returning to
/// its seller (the holder of record), which lets that seller redeem.
#[test]
#[allow(clippy::too_many_lines)]
fn redemption_record_freezes_every_movement_and_claims_burn_then_pay() {
    let mut h = Harness::new();
    h.register();
    let bond = h.bond.clone();
    // A lists 5 units (open); B sells 9 units to an outsider who marks payment sent.
    let seller_a = h.ids[HOLDER_A].clone();
    let seller_b = h.ids[HOLDER_B].clone();
    let outsider = h.ids[OUTSIDER].clone();
    let listing = OpenAssetEscrow::new(escrow_id("a-listing"), bond.clone(), 5_u32);
    h.run(ISSUE + DAY, |stx| listing.execute(&seller_a, stx))
        .expect("A lists");
    let sale = OpenAssetEscrow::new(escrow_id("b-sale"), bond.clone(), 9_u32);
    h.run(ISSUE + DAY, |stx| sale.execute(&seller_b, stx))
        .expect("B lists");
    h.run(ISSUE + DAY, |stx| {
        AcceptAssetEscrow::new(escrow_id("b-sale")).execute(&outsider, stx)?;
        MarkEscrowPaymentSent::new(escrow_id("b-sale")).execute(&outsider, stx)
    })
    .expect("outsider pays off chain");
    for index in 0..4 {
        h.service_coupon(index);
    }
    assert_eq!(h.entitled_units(3, HOLDER_A), Some(q("200")));
    let redemption_record = MATURITY;
    h.record_cashflow(redemption_record, AGENT, 4);
    let record = h.record();
    assert!(record.state.transfers_frozen);
    assert_eq!(record.state.cashflows[4].amount_due, q("15000"));
    let frozen = |error: Error| {
        assert!(
            error.to_string().contains("bond.transfers_frozen"),
            "{error}"
        );
    };
    // Ordinary transfers, including by the issuer, are refused.
    frozen(
        h.transfer_units(redemption_record, HOLDER_A, OUTSIDER, 1)
            .expect_err("frozen transfer"),
    );
    frozen(
        h.transfer_units(redemption_record, ISSUER, HOLDER_A, 1)
            .expect_err("frozen issuer transfer"),
    );
    // Batches, atomic settlement movements and escrow legs, conditional escrows and repo.
    let batch = TransferAssetBatch::new(vec![TransferAssetBatchEntry::new(
        seller_a.clone(),
        outsider.clone(),
        bond.clone(),
        1_u32,
    )]);
    frozen(
        h.run(redemption_record, |stx| batch.execute(&seller_a, stx))
            .expect_err("frozen batch"),
    );
    frozen(
        h.run(redemption_record, |stx| {
            settle_atomic(stx, HOLDER_A, HOLDER_B, false)
        })
        .expect_err("frozen settlement movement"),
    );
    frozen(
        h.run(redemption_record, |stx| {
            settle_atomic(stx, HOLDER_A, HOLDER_B, true)
        })
        .expect_err("frozen settlement escrow leg"),
    );
    let attestor = h.ids[AGENT].clone();
    let escrow = open_conditional(&bond, "frozen", &outsider, &attestor, 5);
    frozen(
        h.run(redemption_record, |stx| escrow.execute(&seller_a, stx))
            .expect_err("frozen escrow"),
    );
    frozen(
        h.run(redemption_record, |stx| {
            initiate_repo(stx, HOLDER_A, HOLDER_B, MATURITY + DAY)
        })
        .expect_err("frozen repo"),
    );
    // B's sold escrow cannot release to the buyer: the buyer is not the holder of record.
    frozen(
        h.run(redemption_record, |stx| {
            ReleaseAssetEscrow::new(escrow_id("b-sale")).execute(&seller_b, stx)
        })
        .expect_err("frozen release to buyer"),
    );
    // A's listing returns to A, the holder of record, who then redeems all 200 units.
    h.run(redemption_record, |stx| {
        CancelAssetEscrow::new(escrow_id("a-listing")).execute(&seller_a, stx)
    })
    .expect("escrow returns custody to its seller");
    assert_eq!(h.units_of(HOLDER_A), q("200"));
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        redemption_record,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 4, agent_eur),
    );
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
    // B's 9 units are still in the sale escrow, so B's redemption burn fails atomically
    // and the entitlement stays claimable.
    h.exec_err(
        MATURITY,
        AGENT,
        ClaimBondCashflow::new(h.bond.clone(), 4, h.ids[HOLDER_B].clone()),
        "",
    );
    h.claim(MATURITY, AGENT, 4, HOLDER_C);
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.outstanding_units, q("799"));
    assert_eq!(record.state.redeemed_units, q("201"));
    assert_eq!(h.vault_eur(), q("4950"));
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
    assert_eq!(h.cashflow(4).claimed_holders, 0);
    // The stuck entitlement does not stop the cash flow from closing.
    h.claim(MATURITY, AGENT, 4, HOLDER_B);
    h.claim(MATURITY, AGENT, 4, HOLDER_C);
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    assert_eq!(h.record().state.lifecycle, BondLifecycle::Matured);
    assert_eq!(h.vault_eur(), q("10000"));
}

/// The definition owner cannot block funded redemptions by tightening the bond's usage
/// policy after funding, and the e-money issuer cannot trap payments by binding the
/// key-less vault into its payment asset's usage policy.
#[test]
fn issuer_policies_cannot_trap_funded_payments() {
    let mut h = Harness::new();
    h.register();
    // The payment asset requires an explicit binding; the vault has none.
    let bound: Vec<AccountId> = [ISSUER, AGENT, HOLDER_A, HOLDER_B]
        .map(|who| h.ids[who].clone())
        .to_vec();
    let eur = h.eur.clone();
    h.set_usage_policy(ISSUE + DAY, &eur, &bound);
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    h.claim(COUPON_0, AGENT, 0, HOLDER_A);
    h.claim(COUPON_0, AGENT, 0, HOLDER_B);
    // C is not bound by the e-money issuer; its claim waits without blocking the close.
    h.exec_err(
        COUPON_0,
        AGENT,
        ClaimBondCashflow::new(h.bond.clone(), 0, h.ids[HOLDER_C].clone()),
        "requires explicit subject binding",
    );
    h.exec_ok(COUPON_0, AGENT, CloseBondCashflow::new(h.bond.clone(), 0));
    let mut with_c = bound.clone();
    with_c.push(h.ids[HOLDER_C].clone());
    h.set_usage_policy(COUPON_0 + DAY, &eur, &with_c);
    h.claim(COUPON_0 + DAY, HOLDER_C, 0, HOLDER_C);
    assert_eq!(h.eur_of(HOLDER_C), q("1.62"));
    for index in 1..4 {
        h.service_coupon(index);
    }
    h.record_fund_cashflow(4, MATURITY);
    // After funding, the bond issuer requires a binding nobody has on the bond itself.
    let bond = h.bond.clone();
    h.set_usage_policy(MATURITY, &bond, &[]);
    h.claim_all(MATURITY, 4);
    assert_eq!(h.record().state.redeemed_units, q("300"));
    assert_eq!(h.vault_eur(), Quantity::zero());
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
    let world = h.state.view();
    assert!(is_bond_vault_account(
        world.world(),
        &bond_vault_account_id(&h.bond)
    ));
    assert!(is_bond_vault_asset(
        world.world(),
        &AssetId::new(h.eur.clone(), bond_vault_account_id(&h.bond))
    ));
    assert!(!is_bond_vault_asset(
        world.world(),
        &AssetId::new(h.bond.clone(), bond_vault_account_id(&h.bond))
    ));
}

#[test]
fn registered_bond_units_only_enter_attributed_custody() {
    let mut h = Harness::new();
    h.register();
    let world = h.state.view();
    let world = world.world();
    for purpose in [
        None,
        Some("native-escrow-funding"),
        Some("native-escrow-retained"),
        Some("repo-bilateral"),
        Some("settlement-bilateral"),
    ] {
        ensure_bond_custody_supported(world, &h.bond, purpose).expect("attributed custody");
    }
    for purpose in [
        "game-seat-funding",
        "vpn-lease-funding",
        "native-amx-prepare",
        "sccp-escrow-lock",
        "fx-corridor-owner-funding",
        "privacy-pool-deposit",
        "staking-bond",
    ] {
        let error = ensure_bond_custody_supported(world, &h.bond, Some(purpose))
            .expect_err("unattributed custody");
        assert!(
            error.to_string().contains("bond.custody_unsupported"),
            "{error}"
        );
        ensure_bond_custody_supported(world, &h.eur, Some(purpose))
            .expect("other assets are unaffected");
    }
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
    // The registered schedule is immutable.
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
        "is Cancelled, not Scheduled or Recording",
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
fn default_waits_for_the_payment_grace_period_and_stops_servicing() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    h.exec_err(
        COUPON_0 + GRACE + 1,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 0, [7; 32]),
        "is Funded and cannot default",
    );
    h.record_cashflow(COUPON_1 - DAY, AGENT, 1);
    // Neither the payment date nor the grace period has passed.
    for time in [COUPON_1, COUPON_1 + 1, COUPON_1 + GRACE] {
        h.exec_err(
            time,
            AGENT,
            DeclareBondDefault::new(h.bond.clone(), 1, [7; 32]),
            "grace period have not passed",
        );
    }
    h.exec_err(
        COUPON_1 + GRACE + 1,
        ISSUER,
        DeclareBondDefault::new(h.bond.clone(), 1, [7; 32]),
        "a default declaration must be signed by the paying agent",
    );
    let events = h
        .run(COUPON_1 + GRACE + 1, |stx| {
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
    // The recorded entitlements remain as the record of who was owed.
    assert_eq!(h.entitled_units(1, HOLDER_A), Some(q("200")));
    // No further recording, funding, call or default; the books are open again.
    let agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_err(
        COUPON_1 + GRACE + 1,
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
    h.transfer_units(COUPON_2, HOLDER_A, OUTSIDER, 1)
        .expect("a defaulted bond still trades");
    // Funds already in the vault stay claimable by their holders and the cash flow closes.
    h.claim_all(COUPON_1 + GRACE + 1, 0);
    h.exec_ok(
        COUPON_1 + GRACE + 1,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
    );
    assert_eq!(h.vault_eur(), Quantity::zero());
    assert_eq!(h.record().state.lifecycle, BondLifecycle::Defaulted);
}

#[test]
fn issuer_replaces_the_paying_agent() {
    let mut h = Harness::new();
    h.register();
    let new_agent = h.ids[NEW_AGENT].clone();
    h.exec_err(
        ISSUE,
        AGENT,
        ReplaceBondPayingAgent::new(h.bond.clone(), new_agent.clone()),
        "the paying agent can only be replaced by the issuer",
    );
    h.exec_err(
        ISSUE,
        ISSUER,
        ReplaceBondPayingAgent::new(h.bond.clone(), h.ids[AGENT].clone()),
        "is already the paying agent",
    );
    h.exec_err(
        ISSUE,
        ISSUER,
        ReplaceBondPayingAgent::new(h.bond.clone(), bond_vault_account_id(&h.bond)),
        "a bond vault cannot be a paying agent",
    );
    let events = h
        .run(ISSUE, |stx| {
            ReplaceBondPayingAgent::new(h_bond(), accounts()[NEW_AGENT].clone())
                .execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("replace agent");
    assert_eq!(
        events,
        [BondEvent::PayingAgentReplaced(BondPayingAgentReplaced {
            bond: h.bond.clone(),
            previous: h.ids[AGENT].clone(),
            paying_agent: new_agent.clone(),
        })]
    );
    assert_eq!(h.record().terms.paying_agent, new_agent);
    h.record_cashflow(COUPON_0 - DAY, OUTSIDER, 0);
    let old_agent_eur = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_err(
        COUPON_0 - DAY,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, old_agent_eur),
        "funding must be signed by the paying agent or the issuer",
    );
    let issuer_eur = AssetId::new(h.eur.clone(), h.ids[ISSUER].clone());
    h.exec_ok(
        COUPON_0 - DAY,
        ISSUER,
        FundBondCashflow::new(h.bond.clone(), 0, issuer_eur),
    );
    h.exec_err(
        COUPON_0,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
        "closing must be signed by the paying agent",
    );
    h.exec_ok(
        COUPON_0,
        NEW_AGENT,
        CloseBondCashflow::new(h.bond.clone(), 0),
    );
}

#[test]
fn rekey_moves_bond_parties_and_unclaimed_entitlements() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    let rekey = |h: &mut Harness, who: usize, seed: u8| -> AccountId {
        let old = h.ids[who].clone();
        let new = h
            .run(COUPON_0 - DAY, |stx| {
                crate::smartcontracts::isi::multisig::replace_account_controller(
                    &old,
                    stx,
                    &old,
                    AccountController::Single(key(seed).public_key().clone()),
                )
                .map_err(Error::from)
            })
            .expect("rekey");
        h.ids[who] = new.clone();
        new
    };
    let old_holder = h.ids[HOLDER_A].clone();
    let holder = rekey(&mut h, HOLDER_A, 0x61);
    let issuer = rekey(&mut h, ISSUER, 0x62);
    let agent = rekey(&mut h, AGENT, 0x63);
    let record = h.record();
    assert_eq!(record.terms.issuer, issuer);
    assert_eq!(record.terms.paying_agent, agent);
    assert_eq!(h.entitlement(0, &old_holder), None);
    assert_eq!(h.entitled_units(0, HOLDER_A), Some(q("200")));
    assert_eq!(h.units_of(HOLDER_A), q("200"));
    // The rekeyed holder claims and the rekeyed agent closes.
    let claim = ClaimBondCashflow::new(h.bond.clone(), 0, holder.clone());
    h.exec_ok(COUPON_0, HOLDER_A, claim);
    assert_eq!(h.eur_of(HOLDER_A), q("325"));
    h.claim(COUPON_0, AGENT, 0, HOLDER_B);
    h.exec_ok(COUPON_0, AGENT, CloseBondCashflow::new(h.bond.clone(), 0));
    // The vault itself is never rekeyed.
    let vault = bond_vault_account_id(&h.bond);
    let error = h
        .run(COUPON_0, |stx| {
            crate::smartcontracts::isi::multisig::replace_account_controller(
                &vault,
                stx,
                &vault,
                AccountController::Single(key(0x64).public_key().clone()),
            )
            .map_err(Error::from)
        })
        .expect_err("vault rekey");
    assert!(error.to_string().contains("bond.retained"), "{error}");
}

#[test]
fn bond_records_retain_definitions_vaults_parties_and_holders() {
    let mut h = Harness::new();
    h.register();
    h.record_fund_cashflow(0, COUPON_0 - DAY);
    let issuer = h.ids[ISSUER].clone();
    for definition in [h.bond.clone(), h.eur.clone()] {
        let error = h
            .run(COUPON_0, |stx| {
                Unregister::asset_definition(definition).execute(&issuer, stx)
            })
            .expect_err("retained definition");
        assert!(error.to_string().contains("bond.retained"), "{error}");
    }
    let unregister = |h: &mut Harness, target: AccountId| {
        let authority = target.clone();
        h.run(COUPON_0, |stx| {
            Unregister::account(target).execute(&authority, stx)
        })
    };
    // Issuer and agent of a servicing bond, the vault and every unit holder are retained:
    // unregistering a holder would destroy units outside the supply lock.
    for target in [
        h.ids[ISSUER].clone(),
        h.ids[AGENT].clone(),
        h.ids[HOLDER_A].clone(),
        bond_vault_account_id(&h.bond),
    ] {
        let error = unregister(&mut h, target).expect_err("retained account");
        assert!(error.to_string().contains("bond.retained"), "{error}");
    }
    let domain = domain();
    let error = h
        .run(COUPON_0, |stx| {
            Unregister::domain(domain).execute(&issuer, stx)
        })
        .expect_err("retained domain definitions");
    assert!(error.to_string().contains("bond.retained"), "{error}");
    // A holder that sold out may leave; its unclaimed entitlement is kept and pays out
    // once the account exists again.
    h.transfer_units(COUPON_0, HOLDER_C, HOLDER_A, 1)
        .expect("C sells out");
    let holder_c = h.ids[HOLDER_C].clone();
    unregister(&mut h, holder_c.clone()).expect("unit-less holder may unregister");
    assert!(h.entitlement(0, &holder_c).is_some());
    let registrar = holder_c.clone();
    h.run(COUPON_0, |stx| {
        iroha_data_model::isi::Register::account(Account::new(registrar.clone()))
            .execute(&registrar, stx)
    })
    .expect("re-register C");
    h.claim(COUPON_0, HOLDER_C, 0, HOLDER_C);
    assert_eq!(h.eur_of(HOLDER_C), q("1.62"));
}

fn retire(units: u32) -> RetireBondTreasuryUnits {
    RetireBondTreasuryUnits::new(h_bond(), units)
}

/// The issuer burns units it holds directly; units it owes back as repo collateral and
/// units of other holders stay untouched, and neither closed books nor the redemption
/// freeze stop a retirement because treasury units are never entitled.
#[test]
#[allow(clippy::too_many_lines)]
fn treasury_retirement_burns_only_free_issuer_units() {
    let mut h = Harness::new();
    h.register();
    assert_eq!(h.units_of(ISSUER), q("700"));
    h.exec_err(
        ISSUE + 1,
        AGENT,
        retire(1),
        "bond.unauthorized: treasury units can only be retired by the issuer",
    );
    h.exec_err(ISSUE + 1, HOLDER_A, retire(1), "bond.unauthorized");
    h.exec_err(
        ISSUE + 1,
        ISSUER,
        retire(0),
        "bond.invalid_state: a treasury retirement must burn a positive whole number of units",
    );
    h.exec_err(ISSUE + 1, ISSUER, retire(701), "cannot retire 701");
    for fractional in ["1.5", "0.25"] {
        h.exec_err(
            ISSUE + 1,
            ISSUER,
            RetireBondTreasuryUnits::new(h.bond.clone(), q(fractional)),
            "positive whole number of units",
        );
    }
    let events = h
        .run(ISSUE + 1, |stx| {
            retire(100).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("retirement");
    assert_eq!(
        events,
        [BondEvent::TreasuryUnitsRetired(BondTreasuryUnitsRetired {
            bond: h.bond.clone(),
            issuer: h.ids[ISSUER].clone(),
            quantity: q("100"),
            outstanding_units: q("900"),
            retired_units: q("100"),
            cancelled_cashflows: 0,
        })]
    );
    assert_eq!(h.units_of(ISSUER), q("600"));
    assert_eq!(h.total_units(), q("900"));
    let record = h.record();
    assert_eq!(record.state.outstanding_units, q("900"));
    assert_eq!(record.state.retired_units, q("100"));
    assert_eq!(record.state.lifecycle, BondLifecycle::Active);
    // Ordinary burns stay locked.
    let issuer = h.ids[ISSUER].clone();
    let own = AssetId::new(h.bond.clone(), issuer.clone());
    let error = h
        .run(ISSUE + 1, |stx| {
            Burn::asset_quantity(1_u32, own).execute(&issuer, stx)
        })
        .expect_err("ordinary burn");
    assert!(error.to_string().contains("bond.supply_locked"), "{error}");

    // The issuer lends cash against 10 of A's units: it must return them at reverse.
    h.run(ISSUE + DAY, |stx| {
        initiate_repo(stx, HOLDER_A, ISSUER, COUPON_0 - 2 * DAY)
    })
    .expect("repo with the issuer as cash lender");
    assert_eq!(h.units_of(ISSUER), q("610"));
    h.exec_err(
        ISSUE + DAY,
        ISSUER,
        retire(601),
        "10 of them owed back as repo collateral",
    );
    h.exec_ok(ISSUE + DAY, ISSUER, retire(500));
    assert_eq!(h.units_of(ISSUER), q("110"));
    let initiator = h.ids[HOLDER_A].clone();
    h.run(COUPON_0 - 2 * DAY, |stx| {
        ReverseRepoIsi::new(RepoAgreementId::new("bond_repo".parse().unwrap()))
            .execute(&initiator, stx)
    })
    .expect("the collateral returns to A");
    assert_eq!(h.units_of(HOLDER_A), q("200"));
    assert_eq!(h.units_of(ISSUER), q("100"));

    // Closed books: transfers wait for the recording, a retirement does not.
    let record_0 = COUPON_0 - DAY;
    let error = h
        .transfer_units(record_0, ISSUER, HOLDER_A, 1)
        .expect_err("books closed");
    assert!(error.to_string().contains("bond.books_closed"), "{error}");
    h.exec_ok(record_0, ISSUER, retire(50));
    h.record_cashflow(record_0, OUTSIDER, 0);
    assert_eq!(h.cashflow(0).entitled_units, q("300"));
    assert_eq!(h.cashflow(0).amount_due, q("487.49"));
    let source = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, source),
    );
    h.claim_all(COUPON_0, 0);
    h.exec_ok(COUPON_0, AGENT, CloseBondCashflow::new(h.bond.clone(), 0));
    for index in 1..4 {
        h.service_coupon(index);
    }
    // The redemption freezes movements; the issuer still retires its last units.
    h.record_fund_cashflow(4, MATURITY - DAY);
    assert!(h.record().state.transfers_frozen);
    h.exec_ok(MATURITY - DAY, ISSUER, retire(50));
    assert_eq!(h.units_of(ISSUER), Quantity::zero());
    let record = h.record();
    assert_eq!(record.state.outstanding_units, q("300"));
    assert_eq!(record.state.retired_units, q("700"));
    assert_eq!(record.state.lifecycle, BondLifecycle::Active);
    h.claim_all(MATURITY, 4);
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.outstanding_units, Quantity::zero());
    assert_eq!(record.state.redeemed_units, q("300"));
    assert_eq!(h.total_units(), Quantity::zero());
    h.exec_err(MATURITY, ISSUER, retire(1), "cannot retire 1");
}

/// Cancelling the whole supply (a failed offering) cancels every cash flow not yet
/// recorded, because each would record no holders; recorded ones stay owed.
#[test]
fn retiring_every_outstanding_unit_cancels_unrecorded_cashflows() {
    let mut h = Harness::with_holdings(&[]);
    h.register();
    let events = h
        .run(ISSUE + DAY, |stx| {
            retire(1_000).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("cancel the unsold issue");
    assert_eq!(
        events,
        [BondEvent::TreasuryUnitsRetired(BondTreasuryUnitsRetired {
            bond: h.bond.clone(),
            issuer: h.ids[ISSUER].clone(),
            quantity: q("1000"),
            outstanding_units: Quantity::zero(),
            retired_units: q("1000"),
            cancelled_cashflows: 5,
        })]
    );
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert!(
        record
            .state
            .cashflows
            .iter()
            .all(|cashflow| cashflow.status == BondCashflowStatus::Cancelled)
    );
    assert_eq!(h.total_units(), Quantity::zero());
    h.exec_err(
        COUPON_0,
        OUTSIDER,
        RecordBondCashflow::new(h.bond.clone(), 0),
        "is Matured",
    );

    // Holders of record of a recorded coupon keep their entitlement after selling back.
    let mut h = Harness::new();
    h.register();
    let record_0 = COUPON_0 - DAY;
    h.record_cashflow(record_0, OUTSIDER, 0);
    for (holder, units) in [(HOLDER_A, 200), (HOLDER_B, 99), (HOLDER_C, 1)] {
        h.transfer_units(record_0, holder, ISSUER, units)
            .expect("buy back after the record date");
    }
    h.exec_ok(record_0, ISSUER, retire(1_000));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Active);
    assert_eq!(
        record.state.cashflows[0].status,
        BondCashflowStatus::Recorded
    );
    assert!(
        record.state.cashflows[1..]
            .iter()
            .all(|cashflow| cashflow.status == BondCashflowStatus::Cancelled)
    );
    let source = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    h.exec_ok(
        record_0,
        AGENT,
        FundBondCashflow::new(h.bond.clone(), 0, source),
    );
    h.claim_all(COUPON_0, 0);
    assert_eq!(h.eur_of(HOLDER_A), q("325"));
    h.exec_ok(COUPON_0, AGENT, CloseBondCashflow::new(h.bond.clone(), 0));
    assert_eq!(h.record().state.lifecycle, BondLifecycle::Matured);
    assert_eq!(h.vault_eur(), Quantity::zero());
}

/// A backdated schedule registers with every passed record date recorded without holders:
/// the issuer held every unit, so nothing is owed for those cash flows, the books open at
/// once, and later cash flows pay the investors of record.
#[test]
#[allow(clippy::too_many_lines)]
fn backdated_registration_records_passed_cashflows_without_holders() {
    let mut h = Harness::new();
    let terms = terms(&h.ids);
    // At the redemption record date the bond would be born frozen.
    h.exec_err(
        MATURITY - DAY,
        ISSUER,
        RegisterBond::new(h.bond.clone(), terms.clone()),
        "the bond would register frozen",
    );
    // Coupons 0 and 1 are paid and coupon 2's record date passed; its payment is pending.
    let registered_at = COUPON_2 - DAY / 2;
    let events = h
        .run(registered_at, |stx| {
            RegisterBond::new(h_bond(), terms.clone()).execute(&accounts()[ISSUER], stx)?;
            Ok(bond_events(stx))
        })
        .expect("backdated registration");
    assert_eq!(events.len(), 4);
    for (event, index) in events[1..].iter().zip(0_u16..) {
        assert_eq!(
            event,
            &BondEvent::CashflowRecorded(BondCashflowRecorded {
                bond: h.bond.clone(),
                index,
                kind: BondCashflowKind::Coupon,
                holders: 0,
                entitled_units: Quantity::zero(),
                amount_due: Quantity::zero(),
            })
        );
    }
    let record = h.record();
    for index in 0..3 {
        let cashflow = &record.state.cashflows[index];
        assert_eq!(cashflow.status, BondCashflowStatus::Recorded);
        assert_eq!(cashflow.recorded_at_ms, Some(registered_at));
        assert_eq!(cashflow.holders, 0);
    }
    assert_eq!(
        record.state.cashflows[3].status,
        BondCashflowStatus::Scheduled
    );
    // The books are open: allotments settle in the registration block.
    for (holder, units) in [(HOLDER_A, 200), (HOLDER_B, 99), (HOLDER_C, 1)] {
        h.transfer_units(registered_at, ISSUER, holder, units)
            .expect("allotment after a backdated registration");
    }
    // Nothing is owed for the passed cash flows, so none can default; they are funded
    // without any movement and closed.
    h.exec_err(
        registered_at,
        AGENT,
        DeclareBondDefault::new(h.bond.clone(), 0, [1; 32]),
        "owes nothing and cannot default",
    );
    let agent_eur = h.eur_of(AGENT);
    let source = AssetId::new(h.eur.clone(), h.ids[AGENT].clone());
    for index in 0..3 {
        h.exec_ok(
            registered_at,
            AGENT,
            FundBondCashflow::new(h.bond.clone(), index, source.clone()),
        );
    }
    for index in 0..2 {
        h.exec_ok(
            registered_at,
            AGENT,
            CloseBondCashflow::new(h.bond.clone(), index),
        );
    }
    h.exec_err(
        registered_at,
        AGENT,
        CloseBondCashflow::new(h.bond.clone(), 2),
        "bond.too_early",
    );
    h.exec_ok(COUPON_2, AGENT, CloseBondCashflow::new(h.bond.clone(), 2));
    assert_eq!(h.eur_of(AGENT), agent_eur);
    assert_eq!(h.vault_eur(), Quantity::zero());
    // The final coupon and the redemption pay the holders of record.
    h.service_coupon(3);
    assert_eq!(h.eur_of(HOLDER_A), q("325"));
    h.record_fund_cashflow(4, MATURITY - DAY);
    h.claim_all(MATURITY, 4);
    h.exec_ok(MATURITY, AGENT, CloseBondCashflow::new(h.bond.clone(), 4));
    let record = h.record();
    assert_eq!(record.state.lifecycle, BondLifecycle::Matured);
    assert_eq!(record.state.redeemed_units, q("300"));
    assert_eq!(h.eur_of(HOLDER_A), q("10325"));
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
    let pay_c = |h: &mut Harness| h.claim(COUPON_0, AGENT, 0, HOLDER_C);
    let cases = [
        // Paying a non-holder.
        (
            VerifiedBondMovementPurpose::Payment,
            AGENT,
            AssetId::new(eur.clone(), vault.clone()),
            AssetId::new(eur.clone(), ids[OUTSIDER].clone()),
            q("1"),
        ),
        // Paying a holder other than its exact entitlement.
        (
            VerifiedBondMovementPurpose::Payment,
            AGENT,
            AssetId::new(eur.clone(), vault.clone()),
            AssetId::new(eur.clone(), ids[HOLDER_A].clone()),
            q("325.01"),
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
    // A claimed entitlement cannot be paid twice through a forged capability.
    pay_c(&mut h);
    let error = h
        .run(COUPON_0, |stx| {
            crate::smartcontracts::isi::asset::isi::execute_verified_bond_movement(
                stx,
                VerifiedBondMovement::new(
                    VerifiedBondMovementPurpose::Payment,
                    &ids[AGENT],
                    &bond,
                    0,
                    AssetId::new(eur.clone(), vault.clone()),
                    AssetId::new(eur.clone(), ids[HOLDER_C].clone()),
                    q("1.62"),
                ),
            )
        })
        .expect_err("double payment");
    assert!(
        error.to_string().contains("capability does not match"),
        "{error}"
    );
}

#[test]
fn entitlements_of_one_bond_iterate_as_a_key_range() {
    let mut h = Harness::new();
    h.register();
    h.service_coupon(0);
    h.record_cashflow(COUPON_1 - DAY, OUTSIDER, 1);
    let view = h.state.view();
    let world = view.world();
    let all: Vec<_> = world
        .bond_entitlements_of_bond_iter(&h.bond, None, None)
        .map(|(id, _)| (id.index, id.holder.clone()))
        .collect();
    assert_eq!(all.len(), 6);
    assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(all[..3].iter().all(|(index, _)| *index == 0));
    let first = BondEntitlementId::new(h.bond.clone(), all[0].0, all[0].1.clone());
    let last = BondEntitlementId::new(h.bond.clone(), all[5].0, all[5].1.clone());
    assert_eq!(
        world
            .bond_entitlements_of_bond_iter(&h.bond, Some(&first), Some(&last))
            .count(),
        4
    );
    assert_eq!(
        world
            .bond_entitlements_of_bond_iter(&h.bond, None, None)
            .rev()
            .next()
            .map(|(id, _)| id.clone()),
        Some(last)
    );
    // Another bond's range is empty and never includes these rows.
    assert_eq!(
        world
            .bond_entitlements_of_bond_iter(&h.eur, None, None)
            .count(),
        0
    );
}

#[test]
fn bond_vault_index_rebuilds_from_records() {
    let mut h = Harness::new();
    h.register();
    let vault = bond_vault_account_id(&h.bond);
    let mut world = World::new();
    world.insert_bond_record_for_testing(h.record());
    assert!(world.bond_vaults.view().get(&vault).is_some());
    world.bond_vaults = mv::storage::Storage::default();
    assert!(world.bond_vaults.view().get(&vault).is_none());
    world.rebuild_bond_vault_index();
    assert_eq!(world.bond_vaults.view().get(&vault), Some(&h.bond));
}

#[test]
fn entitlement_keys_group_one_cash_flow() {
    let ids = accounts();
    let bond = h_bond();
    let mut keys = BTreeSet::new();
    for index in [1_u16, 0] {
        for holder in &ids {
            keys.insert(BondEntitlementId::new(bond.clone(), index, holder.clone()));
        }
    }
    let first_flow: Vec<_> = keys.iter().take(ids.len()).map(|key| key.index).collect();
    assert!(first_flow.iter().all(|index| *index == 0));
}
