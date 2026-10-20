//! Native bond-servicing kernel execution (`specs/finance/bond_ops.md`).
//!
//! Every authority, schedule, book-closing, entitlement and balance rule of the
//! bond kernel is enforced here. Balance effects are expressed as one-shot
//! verified capabilities consumed by the central numeric movement and burn
//! paths in the asset module, which re-check them against the stored record
//! and entitlement.
use core::ops::Bound;

use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinitionId, AssetId},
    bond::{
        BOND_RECORDING_PAGE_ENTRIES, BondCashflowKind, BondCashflowState, BondCashflowStatus,
        BondCashflowTerms, BondEntitlement, BondEntitlementId, BondError, BondId, BondLifecycle,
        BondRecord, BondRecordingCursor, BondRecordingPhase, holder_payment, redemption_amount,
    },
    escrow::EscrowId,
    events::data::{
        DataEvent,
        bond::{
            BondCalled, BondCashflowClaimed, BondCashflowClosed, BondCashflowFunded,
            BondCashflowRecorded, BondDefaulted, BondEvent, BondPayingAgentReplaced,
            BondRegistered, BondTreasuryUnitsRetired,
        },
    },
    isi::bond::{
        BondInstructionBox, CallBond, ClaimBondCashflow, CloseBondCashflow, DeclareBondDefault,
        FundBondCashflow, RecordBondCashflow, RegisterBond, ReplaceBondPayingAgent,
        RetireBondTreasuryUnits,
    },
};
use iroha_primitives::numeric::{NumericSpec, Quantity};
use mv::storage::StorageReadOnly;

use super::{Error, Execute};
use crate::state::{StateTransaction, WorldReadOnly};

/// Exact purpose of one verified vault movement.
pub(in crate::smartcontracts::isi) enum VerifiedBondMovementPurpose {
    /// Paying agent or issuer funds the exact recorded amount due.
    Funding,
    /// Vault pays one entitled holder.
    Payment,
}

/// Non-reusable proof that the bond kernel selected one exact vault movement.
pub(in crate::smartcontracts::isi) struct VerifiedBondMovement {
    purpose: VerifiedBondMovementPurpose,
    authority: AccountId,
    bond: BondId,
    index: u16,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
}

impl VerifiedBondMovement {
    fn new(
        purpose: VerifiedBondMovementPurpose,
        authority: &AccountId,
        bond: &BondId,
        index: u16,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose,
            authority: authority.clone(),
            bond: bond.clone(),
            index,
            source_id,
            destination_id,
            amount,
        }
    }

    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        VerifiedBondMovementPurpose,
        AccountId,
        BondId,
        u16,
        AssetId,
        AssetId,
        Quantity,
    ) {
        (
            self.purpose,
            self.authority,
            self.bond,
            self.index,
            self.source_id,
            self.destination_id,
            self.amount,
        )
    }
}

/// Non-reusable proof that a redemption claim burns one holder's exact entitled units.
pub(in crate::smartcontracts::isi) struct VerifiedBondRedemptionBurn {
    authority: AccountId,
    bond: BondId,
    index: u16,
    holder: AccountId,
    units: Quantity,
}

impl VerifiedBondRedemptionBurn {
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (AccountId, BondId, u16, AccountId, Quantity) {
        (
            self.authority,
            self.bond,
            self.index,
            self.holder,
            self.units,
        )
    }
}

/// Non-reusable proof that the issuer retires exact units of its own global balance.
pub(in crate::smartcontracts::isi) struct VerifiedBondTreasuryRetirement {
    authority: AccountId,
    bond: BondId,
    units: Quantity,
}

impl VerifiedBondTreasuryRetirement {
    pub(in crate::smartcontracts::isi) fn into_parts(self) -> (AccountId, BondId, Quantity) {
        (self.authority, self.bond, self.units)
    }
}

fn block_time_ms(state_transaction: &StateTransaction<'_, '_>) -> u64 {
    state_transaction.block_unix_timestamp_ms()
}

/// Load a bond record. Records hold totals only; per-holder entitlements live in
/// `world.bond_entitlements`, so cloning a record is bounded by its schedule.
fn load(state_transaction: &StateTransaction<'_, '_>, bond: &BondId) -> Result<BondRecord, Error> {
    state_transaction
        .world
        .bonds
        .get(bond)
        .cloned()
        .ok_or_else(|| BondError::NotRegistered(bond.to_string()).into())
}

fn store(state_transaction: &mut StateTransaction<'_, '_>, record: BondRecord) {
    state_transaction
        .world
        .bonds
        .insert(record.id.clone(), record);
}

fn emit(state_transaction: &mut StateTransaction<'_, '_>, event: BondEvent) {
    state_transaction
        .world
        .emit_events(core::iter::once(DataEvent::Bond(event)));
}

fn cashflow(record: &BondRecord, index: u16) -> Result<&BondCashflowState, Error> {
    record
        .cashflow(index)
        .ok_or_else(|| BondError::UnknownCashflow(index).into())
}

fn cashflow_mut(record: &mut BondRecord, index: u16) -> Result<&mut BondCashflowState, Error> {
    record
        .cashflow_mut(index)
        .ok_or_else(|| BondError::UnknownCashflow(index).into())
}

const fn is_servicing(record: &BondRecord) -> bool {
    matches!(
        record.state.lifecycle,
        BondLifecycle::Active | BondLifecycle::Called
    )
}

fn ensure_servicing(record: &BondRecord) -> Result<(), Error> {
    if is_servicing(record) {
        Ok(())
    } else {
        Err(
            BondError::InvalidState(format!("bond {} is {}", record.id, record.state.lifecycle))
                .into(),
        )
    }
}

fn ensure_paying_agent(
    record: &BondRecord,
    authority: &AccountId,
    action: &str,
) -> Result<(), Error> {
    if authority == &record.terms.paying_agent {
        Ok(())
    } else {
        Err(BondError::Unauthorized(format!("{action} must be signed by the paying agent")).into())
    }
}

fn arithmetic(error: impl core::fmt::Display) -> Error {
    BondError::Arithmetic(error.to_string()).into()
}

fn ensure_global_definition(
    state_transaction: &StateTransaction<'_, '_>,
    definition: &AssetDefinitionId,
    role: &str,
) -> Result<iroha_data_model::asset::AssetDefinition, Error> {
    let definition = state_transaction.world.asset_definition(definition)?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err(BondError::InvalidTerms(format!(
            "{role} asset definition must keep global balances"
        ))
        .into());
    }
    Ok(definition)
}

fn global_balance(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Quantity {
    world
        .assets()
        .get(&AssetId::new(definition.clone(), account.clone()))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}

/// The cash flow whose passed record date keeps the books of `record` closed at `now`.
///
/// Cash flows are recorded in index order and record dates never decrease, so
/// only the first still `Scheduled` cash flow can close the books. Books are
/// open on a matured or defaulted bond.
fn books_closed_by(record: &BondRecord, now: u64) -> Option<&BondCashflowState> {
    if !is_servicing(record) {
        return None;
    }
    record
        .state
        .cashflows
        .iter()
        .find(|state| state.status == BondCashflowStatus::Scheduled)
        .filter(|state| state.terms.record_date_ms <= now)
}

pub(in crate::smartcontracts::isi) fn recording_in_progress(
    record: &BondRecord,
) -> Option<&BondCashflowState> {
    record
        .state
        .cashflows
        .iter()
        .find(|state| state.status == BondCashflowStatus::Recording)
}

/// Mature a servicing bond once every effective cash flow is closed or cancelled.
///
/// An unpaid coupon keeps the bond servicing (and open to a default declaration).
fn mature_if_complete(record: &mut BondRecord) {
    if is_servicing(record)
        && record.state.cashflows.iter().all(|state| {
            matches!(
                state.status,
                BondCashflowStatus::Closed | BondCashflowStatus::Cancelled
            )
        })
    {
        record.state.lifecycle = BondLifecycle::Matured;
    }
}

/// Running totals of one cash flow's entitlements during recording.
struct RecordingTotals<'a> {
    bond: &'a BondId,
    index: u16,
    amount_per_unit: &'a Quantity,
    payment_spec: NumericSpec,
    holders: u32,
    entitled_units: Quantity,
    amount_due: Quantity,
}

impl RecordingTotals<'_> {
    /// Add `units` to `holder`'s entitlement and keep the totals exact.
    fn credit(
        &mut self,
        state_transaction: &mut StateTransaction<'_, '_>,
        holder: AccountId,
        units: &Quantity,
    ) -> Result<(), Error> {
        let id = BondEntitlementId::new(self.bond.clone(), self.index, holder);
        let previous = state_transaction.world.bond_entitlements.get(&id).cloned();
        let (previous_units, previous_amount) = previous.as_ref().map_or_else(
            || (Quantity::zero(), Quantity::zero()),
            |entitlement| (entitlement.units.clone(), entitlement.amount.clone()),
        );
        let new_units = previous_units.checked_add(units).map_err(arithmetic)?;
        let new_amount = holder_payment(&new_units, self.amount_per_unit, self.payment_spec)?;
        self.amount_due = self
            .amount_due
            .checked_sub(&previous_amount)
            .and_then(|due| due.checked_add(&new_amount))
            .map_err(arithmetic)?;
        self.entitled_units = self.entitled_units.checked_add(units).map_err(arithmetic)?;
        if previous.is_none() {
            self.holders = self
                .holders
                .checked_add(1)
                .ok_or_else(|| BondError::Arithmetic("holder count overflows u32".to_owned()))?;
        }
        state_transaction.world.bond_entitlements.insert(
            id.clone(),
            BondEntitlement {
                id,
                units: new_units,
                amount: new_amount,
                claimed_at_ms: None,
            },
        );
        Ok(())
    }

    /// Remove `account`'s entitlement, returning its units.
    fn take(
        &mut self,
        state_transaction: &mut StateTransaction<'_, '_>,
        account: &AccountId,
    ) -> Result<Option<Quantity>, Error> {
        let id = BondEntitlementId::new(self.bond.clone(), self.index, account.clone());
        let Some(entitlement) = state_transaction.world.bond_entitlements.remove(id) else {
            return Ok(None);
        };
        self.amount_due = self
            .amount_due
            .checked_sub(&entitlement.amount)
            .map_err(arithmetic)?;
        self.entitled_units = self
            .entitled_units
            .checked_sub(&entitlement.units)
            .map_err(arithmetic)?;
        self.holders = self
            .holders
            .checked_sub(1)
            .ok_or_else(|| BondError::Arithmetic("holder count underflows".to_owned()))?;
        Ok(Some(entitlement.units))
    }
}

/// Whether `account` can hold no entitlement in the holders phase.
///
/// Native asset-escrow custody is attributed by the escrows phase instead; this
/// covers the issuer's treasury, bond vaults, game custody and AMX custody.
fn excluded_holder(
    state_transaction: &StateTransaction<'_, '_>,
    record: &BondRecord,
    account: &AccountId,
) -> bool {
    account == &record.terms.issuer
        || account == record.vault()
        || state_transaction.world.bond_vaults.get(account).is_some()
        || state_transaction
            .world
            .game_custody_by_account
            .get(account)
            .is_some()
        || state_transaction
            .world
            .sumeragi_amx_participant()
            .canonical()
            .is_some_and(|participant| &participant.custody == account)
}

/// Examine at most `budget` bond balances after the cursor; returns the entries used and
/// whether the phase finished.
fn record_holders_page(
    state_transaction: &mut StateTransaction<'_, '_>,
    record: &BondRecord,
    cursor: &mut BondRecordingCursor,
    totals: &mut RecordingTotals<'_>,
    budget: usize,
) -> Result<(usize, bool), Error> {
    let page: Vec<AssetId> = crate::state::range_bounds::index_members_after(
        &state_transaction.world.asset_definition_assets,
        &record.id,
        cursor.after_asset.as_ref(),
    )
    .take(budget)
    .cloned()
    .collect();
    let used = page.len();
    for asset_id in page {
        let balance = state_transaction
            .world
            .assets
            .get(&asset_id)
            .map(|value| value.as_ref().clone());
        let holder = asset_id.account().clone();
        cursor.after_asset = Some(asset_id);
        let Some(balance) = balance.filter(|balance| !balance.is_zero()) else {
            continue;
        };
        if excluded_holder(state_transaction, record, &holder) {
            continue;
        }
        totals.credit(state_transaction, holder, &balance)?;
    }
    Ok((used, used < budget))
}

/// Examine at most `budget` escrow records after the cursor and attribute the custody
/// balance of every escrow of this bond to its seller; returns the entries used and
/// whether the phase finished.
fn record_escrows_page(
    state_transaction: &mut StateTransaction<'_, '_>,
    record: &BondRecord,
    cursor: &mut BondRecordingCursor,
    totals: &mut RecordingTotals<'_>,
    budget: usize,
) -> Result<(usize, bool), Error> {
    // TODO: index escrows by asset definition so this phase scans only the bond's
    // escrows instead of every escrow record (`specs/finance/bond_ops.md` §9).
    let page: Vec<(EscrowId, Option<(AccountId, AccountId)>)> = {
        let lower = cursor
            .after_escrow
            .as_ref()
            .map_or(Bound::Unbounded, Bound::Excluded);
        state_transaction
            .world
            .asset_escrows
            .range::<EscrowId>((lower, Bound::Unbounded))
            .take(budget)
            .map(|(id, escrow)| {
                let custody = (escrow.asset_definition == record.id)
                    .then(|| (escrow.custody.clone(), escrow.seller.clone()));
                (*id, custody)
            })
            .collect()
    };
    let used = page.len();
    for (escrow_id, custody) in page {
        cursor.after_escrow = Some(escrow_id);
        let Some((custody, seller)) = custody else {
            continue;
        };
        let Some(units) = totals.take(state_transaction, &custody)? else {
            continue;
        };
        // Until an escrow releases, its seller remains the holder of record.
        if !excluded_holder(state_transaction, record, &seller) {
            totals.credit(state_transaction, seller, &units)?;
        }
    }
    Ok((used, used < budget))
}

impl Execute for RegisterBond {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RegisterBond { bond, terms } = self;
        if authority != &terms.issuer {
            return Err(BondError::Unauthorized(
                "registration must be signed by the issuer".to_owned(),
            )
            .into());
        }
        terms.validate()?;
        if state_transaction.world.bonds.get(&bond).is_some() {
            return Err(BondError::AlreadyRegistered(bond.to_string()).into());
        }
        if terms.payment_asset == bond {
            return Err(BondError::InvalidTerms(
                "the payment asset must differ from the bond".to_owned(),
            )
            .into());
        }
        // Vaults hold payment assets; keeping bonds and payment assets disjoint
        // means a vault never holds units of any bond.
        if state_transaction
            .world
            .bonds
            .get(&terms.payment_asset)
            .is_some()
        {
            return Err(BondError::InvalidTerms(
                "the payment asset must not be a registered bond".to_owned(),
            )
            .into());
        }
        if let Some((other, _)) = state_transaction
            .world
            .bonds
            .iter()
            .find(|(_, record)| record.terms.payment_asset == bond)
        {
            return Err(BondError::InvalidState(format!(
                "asset definition {bond} is the payment asset of bond {other}"
            ))
            .into());
        }
        let definition = ensure_global_definition(state_transaction, &bond, "bond")?;
        if definition.owned_by() != &terms.issuer {
            return Err(BondError::Unauthorized(
                "the issuer must own the bond asset definition".to_owned(),
            )
            .into());
        }
        if definition.spec().scale() != Some(0) {
            return Err(BondError::InvalidTerms(
                "the bond asset definition must have scale 0".to_owned(),
            )
            .into());
        }
        ensure_global_definition(state_transaction, &terms.payment_asset, "payment")?;
        state_transaction.world.account(&terms.issuer)?;
        state_transaction.world.account(&terms.paying_agent)?;
        let outstanding = definition.total_quantity().clone();
        if outstanding.is_zero() {
            return Err(BondError::InvalidState(
                "mint the issued units before registering the bond".to_owned(),
            )
            .into());
        }
        // Every unit starts with the issuer, so no unit can sit in custody the
        // kernel does not attribute; distribution follows registration.
        if global_balance(state_transaction.world(), &bond, &terms.issuer) != outstanding {
            return Err(BondError::InvalidState(
                "the issuer must hold the entire minted supply when registering the bond"
                    .to_owned(),
            )
            .into());
        }
        let cashflows = u16::try_from(terms.cashflows.len()).map_err(arithmetic)?;
        let now = block_time_ms(state_transaction);
        let redemption_record_date = terms
            .cashflows
            .last()
            .map_or(0, |redemption| redemption.record_date_ms);
        if redemption_record_date <= now {
            return Err(BondError::InvalidState(format!(
                "the redemption record date {redemption_record_date} is not after block time {now}; the bond would register frozen"
            ))
            .into());
        }
        let mut record = BondRecord::registered(bond.clone(), terms, outstanding.clone());
        // A backdated schedule may already have passed record dates. The issuer
        // holds every unit at registration and treasury units are excluded, so
        // those cash flows are recorded now with no holders: exactly what a
        // `RecordBondCashflow` in this block would record. The books therefore
        // open immediately and subscriptions can follow in the same transaction.
        let mut recorded = Vec::new();
        for state in record
            .state
            .cashflows
            .iter_mut()
            .take_while(|state| state.terms.record_date_ms <= now)
        {
            state.status = BondCashflowStatus::Recorded;
            state.recorded_at_ms = Some(now);
            recorded.push(BondCashflowRecorded {
                bond: bond.clone(),
                index: state.terms.index,
                kind: state.terms.kind,
                holders: 0,
                entitled_units: Quantity::zero(),
                amount_due: Quantity::zero(),
            });
        }
        let event = BondRegistered {
            bond: bond.clone(),
            issuer: record.terms.issuer.clone(),
            paying_agent: record.terms.paying_agent.clone(),
            outstanding_units: outstanding,
            cashflows,
        };
        state_transaction
            .world
            .bond_vaults
            .insert(record.vault().clone(), bond.clone());
        store(state_transaction, record);
        iroha_logger::info!(%bond, "bond registered");
        emit(state_transaction, BondEvent::Registered(event));
        for event in recorded {
            emit(state_transaction, BondEvent::CashflowRecorded(event));
        }
        Ok(())
    }
}

impl Execute for RecordBondCashflow {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RecordBondCashflow { bond, index } = self;
        let mut record = load(state_transaction, &bond)?;
        ensure_servicing(&record)?;
        let now = block_time_ms(state_transaction);
        let current = cashflow(&record, index)?.clone();
        let mut cursor = match current.status {
            BondCashflowStatus::Scheduled => {
                if now < current.terms.record_date_ms {
                    return Err(BondError::TooEarly(format!(
                        "cash flow {index} record date {} is after block time {now}",
                        current.terms.record_date_ms
                    ))
                    .into());
                }
                if let Some(earlier) =
                    record.state.cashflows[..usize::from(index)]
                        .iter()
                        .find(|earlier| {
                            matches!(
                                earlier.status,
                                BondCashflowStatus::Scheduled | BondCashflowStatus::Recording
                            )
                        })
                {
                    return Err(BondError::InvalidState(format!(
                        "cash flow {} must be recorded first",
                        earlier.terms.index
                    ))
                    .into());
                }
                BondRecordingCursor::start()
            }
            BondCashflowStatus::Recording => current.recording.clone().ok_or_else(|| {
                BondError::InvalidState(format!("cash flow {index} is Recording without a cursor"))
            })?,
            status => {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {status}, not Scheduled or Recording"
                ))
                .into());
            }
        };
        let payment_spec = state_transaction
            .numeric_spec_for(&record.terms.payment_asset)
            .map_err(Error::from)?;
        let mut totals = RecordingTotals {
            bond: &bond,
            index,
            amount_per_unit: &current.terms.amount_per_unit,
            payment_spec,
            holders: current.holders,
            entitled_units: current.entitled_units.clone(),
            amount_due: current.amount_due.clone(),
        };
        let mut budget = BOND_RECORDING_PAGE_ENTRIES;
        let mut finished = false;
        while budget > 0 && !finished {
            let (used, phase_done) = match cursor.phase {
                BondRecordingPhase::Holders => record_holders_page(
                    state_transaction,
                    &record,
                    &mut cursor,
                    &mut totals,
                    budget,
                )?,
                BondRecordingPhase::Escrows => record_escrows_page(
                    state_transaction,
                    &record,
                    &mut cursor,
                    &mut totals,
                    budget,
                )?,
            };
            budget -= used;
            if phase_done {
                match cursor.phase {
                    BondRecordingPhase::Holders => cursor.phase = BondRecordingPhase::Escrows,
                    BondRecordingPhase::Escrows => finished = true,
                }
            }
        }
        let (holders, entitled_units, amount_due) =
            (totals.holders, totals.entitled_units, totals.amount_due);
        if finished && current.terms.kind == BondCashflowKind::Redemption {
            record.state.transfers_frozen = true;
        }
        let state = cashflow_mut(&mut record, index)?;
        state.holders = holders;
        state.entitled_units = entitled_units.clone();
        state.amount_due = amount_due.clone();
        if finished {
            state.status = BondCashflowStatus::Recorded;
            state.recording = None;
            state.recorded_at_ms = Some(now);
        } else {
            state.status = BondCashflowStatus::Recording;
            state.recording = Some(cursor);
        }
        store(state_transaction, record);
        if finished {
            iroha_logger::info!(%bond, index, %amount_due, "bond cash flow recorded");
            emit(
                state_transaction,
                BondEvent::CashflowRecorded(BondCashflowRecorded {
                    bond,
                    index,
                    kind: current.terms.kind,
                    holders,
                    entitled_units,
                    amount_due,
                }),
            );
        }
        Ok(())
    }
}

impl Execute for FundBondCashflow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let FundBondCashflow {
            bond,
            index,
            source,
        } = self;
        let mut record = load(state_transaction, &bond)?;
        if authority != &record.terms.paying_agent && authority != &record.terms.issuer {
            return Err(BondError::Unauthorized(
                "funding must be signed by the paying agent or the issuer".to_owned(),
            )
            .into());
        }
        ensure_servicing(&record)?;
        if source.account() != authority
            || source.definition() != &record.terms.payment_asset
            || source.scope() != &AssetBalanceScope::Global
        {
            return Err(BondError::Unauthorized(
                "the funding source must be the signer's global payment-asset balance".to_owned(),
            )
            .into());
        }
        let amount_due = {
            let current = cashflow(&record, index)?;
            if current.status != BondCashflowStatus::Recorded {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {}, not Recorded",
                    current.status
                ))
                .into());
            }
            current.amount_due.clone()
        };
        if !amount_due.is_zero() {
            let vault = record.vault().clone();
            crate::smartcontracts::isi::helpers::ensure_custody_account(&vault, state_transaction)?;
            let destination = AssetId::new(record.terms.payment_asset.clone(), vault);
            crate::smartcontracts::isi::asset::isi::execute_verified_bond_movement(
                state_transaction,
                VerifiedBondMovement::new(
                    VerifiedBondMovementPurpose::Funding,
                    authority,
                    &bond,
                    index,
                    source,
                    destination,
                    amount_due.clone(),
                ),
            )?;
        }
        let now = block_time_ms(state_transaction);
        let state = cashflow_mut(&mut record, index)?;
        state.status = BondCashflowStatus::Funded;
        state.funded = amount_due.clone();
        state.funded_at_ms = Some(now);
        store(state_transaction, record);
        emit(
            state_transaction,
            BondEvent::CashflowFunded(BondCashflowFunded {
                bond,
                index,
                amount: amount_due,
            }),
        );
        Ok(())
    }
}

impl Execute for ClaimBondCashflow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let ClaimBondCashflow {
            bond,
            index,
            holder,
        } = self;
        let mut record = load(state_transaction, &bond)?;
        if authority != &holder && authority != &record.terms.paying_agent {
            return Err(BondError::Unauthorized(
                "a claim must be signed by the holder or pushed by the paying agent".to_owned(),
            )
            .into());
        }
        let now = block_time_ms(state_transaction);
        let kind = {
            let current = cashflow(&record, index)?;
            if !current.is_claimable() {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {}, not Funded or Closed",
                    current.status
                ))
                .into());
            }
            if now < current.terms.payment_date_ms {
                return Err(BondError::TooEarly(format!(
                    "cash flow {index} payment date {} is after block time {now}",
                    current.terms.payment_date_ms
                ))
                .into());
            }
            current.terms.kind
        };
        let id = BondEntitlementId::new(bond.clone(), index, holder.clone());
        let mut entitlement = state_transaction
            .world
            .bond_entitlements
            .get(&id)
            .cloned()
            .ok_or_else(|| BondError::NotEntitled(holder.to_string()))?;
        if entitlement.claimed_at_ms.is_some() {
            return Err(BondError::AlreadyClaimed(holder.to_string()).into());
        }
        let units = entitlement.units.clone();
        let amount = entitlement.amount.clone();
        if kind == BondCashflowKind::Redemption {
            crate::smartcontracts::isi::asset::isi::execute_verified_bond_redemption_burn(
                state_transaction,
                VerifiedBondRedemptionBurn {
                    authority: authority.clone(),
                    bond: bond.clone(),
                    index,
                    holder: holder.clone(),
                    units: units.clone(),
                },
            )?;
        }
        if !amount.is_zero() {
            let vault = AssetId::new(record.terms.payment_asset.clone(), record.vault().clone());
            let destination = AssetId::new(record.terms.payment_asset.clone(), holder.clone());
            crate::smartcontracts::isi::asset::isi::execute_verified_bond_movement(
                state_transaction,
                VerifiedBondMovement::new(
                    VerifiedBondMovementPurpose::Payment,
                    authority,
                    &bond,
                    index,
                    vault,
                    destination,
                    amount.clone(),
                ),
            )?;
        }
        if kind == BondCashflowKind::Redemption {
            record.state.outstanding_units = record
                .state
                .outstanding_units
                .checked_sub(&units)
                .map_err(arithmetic)?;
            record.state.redeemed_units = record
                .state
                .redeemed_units
                .checked_add(&units)
                .map_err(arithmetic)?;
        }
        let state = cashflow_mut(&mut record, index)?;
        state.claimed_holders = state
            .claimed_holders
            .checked_add(1)
            .ok_or_else(|| BondError::Arithmetic("claimed holders overflow".to_owned()))?;
        state.paid = state.paid.checked_add(&amount).map_err(arithmetic)?;
        store(state_transaction, record);
        entitlement.claimed_at_ms = Some(now);
        state_transaction
            .world
            .bond_entitlements
            .insert(id, entitlement);
        emit(
            state_transaction,
            BondEvent::CashflowClaimed(BondCashflowClaimed {
                bond,
                index,
                holder,
                units,
                amount,
            }),
        );
        Ok(())
    }
}

impl Execute for CloseBondCashflow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let CloseBondCashflow { bond, index } = self;
        let mut record = load(state_transaction, &bond)?;
        ensure_paying_agent(&record, authority, "closing")?;
        let now = block_time_ms(state_transaction);
        let (unclaimed_holders, unclaimed_amount) = {
            let current = cashflow(&record, index)?;
            if current.status != BondCashflowStatus::Funded {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {}, not Funded",
                    current.status
                ))
                .into());
            }
            if now < current.terms.payment_date_ms {
                return Err(BondError::TooEarly(format!(
                    "cash flow {index} payment date {} is after block time {now}",
                    current.terms.payment_date_ms
                ))
                .into());
            }
            (
                current.holders.saturating_sub(current.claimed_holders),
                current
                    .funded
                    .checked_sub(&current.paid)
                    .map_err(arithmetic)?,
            )
        };
        let state = cashflow_mut(&mut record, index)?;
        state.status = BondCashflowStatus::Closed;
        state.closed_at_ms = Some(now);
        mature_if_complete(&mut record);
        store(state_transaction, record);
        emit(
            state_transaction,
            BondEvent::CashflowClosed(BondCashflowClosed {
                bond,
                index,
                unclaimed_holders,
                unclaimed_amount,
            }),
        );
        Ok(())
    }
}

impl Execute for CallBond {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let CallBond { bond, call_date_ms } = self;
        let mut record = load(state_transaction, &bond)?;
        if authority != &record.terms.issuer {
            return Err(
                BondError::Unauthorized("a call must be signed by the issuer".to_owned()).into(),
            );
        }
        if record.state.lifecycle != BondLifecycle::Active {
            return Err(BondError::InvalidState(format!(
                "bond {bond} is {}, not Active",
                record.state.lifecycle
            ))
            .into());
        }
        let call = record
            .terms
            .call
            .ok_or_else(|| BondError::InvalidState(format!("bond {bond} has no call provision")))?;
        if call_date_ms < call.first_call_date_ms {
            return Err(BondError::TooEarly(format!(
                "call date {call_date_ms} precedes the first call date {}",
                call.first_call_date_ms
            ))
            .into());
        }
        let now = block_time_ms(state_transaction);
        if call_date_ms < now.saturating_add(call.notice_ms) {
            return Err(BondError::TooEarly(format!(
                "call date {call_date_ms} gives less than the {}ms notice from block time {now}",
                call.notice_ms
            ))
            .into());
        }
        if call_date_ms >= record.terms.maturity_date_ms {
            return Err(BondError::InvalidState("a call must precede maturity".to_owned()).into());
        }
        let called = record
            .state
            .cashflows
            .iter()
            .find(|state| {
                state.terms.kind == BondCashflowKind::Coupon
                    && state.terms.payment_date_ms == call_date_ms
            })
            .ok_or_else(|| {
                BondError::InvalidState(format!(
                    "call date {call_date_ms} is not a scheduled coupon payment date"
                ))
            })?;
        if called.status != BondCashflowStatus::Scheduled {
            return Err(BondError::InvalidState(format!(
                "the coupon paid on the call date is {}, not Scheduled",
                called.status
            ))
            .into());
        }
        let called_index = called.terms.index;
        let record_date_ms = called.terms.record_date_ms;
        let amount_per_unit = redemption_amount(&record.terms.denomination, call.price_bps)?;
        for state in record
            .state
            .cashflows
            .iter_mut()
            .filter(|state| state.terms.index > called_index)
        {
            if state.status != BondCashflowStatus::Scheduled {
                return Err(BondError::InvalidState(format!(
                    "cash flow {} after the call date is {}",
                    state.terms.index, state.status
                ))
                .into());
            }
            state.status = BondCashflowStatus::Cancelled;
        }
        let redemption_index = u16::try_from(record.state.cashflows.len()).map_err(arithmetic)?;
        record
            .state
            .cashflows
            .push(BondCashflowState::scheduled(BondCashflowTerms {
                index: redemption_index,
                kind: BondCashflowKind::Redemption,
                record_date_ms,
                payment_date_ms: call_date_ms,
                amount_per_unit,
            }));
        record.state.lifecycle = BondLifecycle::Called;
        store(state_transaction, record);
        iroha_logger::info!(%bond, call_date_ms, "bond called");
        emit(
            state_transaction,
            BondEvent::Called(BondCalled {
                bond,
                call_date_ms,
                redemption_index,
            }),
        );
        Ok(())
    }
}

impl Execute for DeclareBondDefault {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let DeclareBondDefault {
            bond,
            index,
            evidence_sha256,
        } = self;
        let mut record = load(state_transaction, &bond)?;
        ensure_paying_agent(&record, authority, "a default declaration")?;
        ensure_servicing(&record)?;
        let now = block_time_ms(state_transaction);
        let grace_ms = record.terms.payment_grace_ms;
        let state = cashflow_mut(&mut record, index)?;
        match state.status {
            BondCashflowStatus::Recorded if state.amount_due.is_zero() => {
                // Nobody is owed anything (for example a cash flow recorded at the
                // registration of a backdated bond): there is no payment to miss.
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} owes nothing and cannot default; fund and close it"
                ))
                .into());
            }
            BondCashflowStatus::Scheduled | BondCashflowStatus::Recorded => {}
            BondCashflowStatus::Recording => {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is being recorded; complete the recording first"
                ))
                .into());
            }
            status => {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {status} and cannot default"
                ))
                .into());
            }
        }
        let deadline = state.terms.payment_date_ms.saturating_add(grace_ms);
        if now <= deadline {
            return Err(BondError::TooEarly(format!(
                "cash flow {index} payment date {} and its {grace_ms}ms grace period have not passed at block time {now}",
                state.terms.payment_date_ms
            ))
            .into());
        }
        state.status = BondCashflowStatus::Defaulted;
        state.evidence_sha256 = Some(evidence_sha256);
        record.state.lifecycle = BondLifecycle::Defaulted;
        store(state_transaction, record);
        iroha_logger::warn!(%bond, index, "bond payment default declared");
        emit(
            state_transaction,
            BondEvent::Defaulted(BondDefaulted {
                bond,
                index,
                evidence_sha256,
            }),
        );
        Ok(())
    }
}

impl Execute for ReplaceBondPayingAgent {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let ReplaceBondPayingAgent { bond, paying_agent } = self;
        let mut record = load(state_transaction, &bond)?;
        if authority != &record.terms.issuer {
            return Err(BondError::Unauthorized(
                "the paying agent can only be replaced by the issuer".to_owned(),
            )
            .into());
        }
        if paying_agent == record.terms.paying_agent {
            return Err(BondError::InvalidState(format!(
                "{paying_agent} is already the paying agent of bond {bond}"
            ))
            .into());
        }
        if state_transaction
            .world
            .bond_vaults
            .get(&paying_agent)
            .is_some()
        {
            return Err(BondError::InvalidState(
                "a bond vault cannot be a paying agent".to_owned(),
            )
            .into());
        }
        state_transaction.world.account(&paying_agent)?;
        let previous = core::mem::replace(&mut record.terms.paying_agent, paying_agent.clone());
        store(state_transaction, record);
        iroha_logger::info!(%bond, %paying_agent, "bond paying agent replaced");
        emit(
            state_transaction,
            BondEvent::PayingAgentReplaced(BondPayingAgentReplaced {
                bond,
                previous,
                paying_agent,
            }),
        );
        Ok(())
    }
}

/// Units of `bond` the issuer holds as repo collateral it must return.
///
/// A repo counterparty or custodian holds the collateral title and returns the
/// same units at reverse; the supply lock means retired units could never be
/// returned, so they are reserved against retirement.
fn issuer_repo_collateral(
    state_transaction: &StateTransaction<'_, '_>,
    bond: &BondId,
    issuer: &AccountId,
) -> Result<Quantity, Error> {
    let custody = AssetId::new(bond.clone(), issuer.clone());
    let mut agreements = std::collections::BTreeSet::new();
    for index in [
        &state_transaction.world.repo_agreements_by_counterparty,
        &state_transaction.world.repo_agreements_by_custodian,
    ] {
        if let Some(ids) = index.get(issuer) {
            agreements.extend(ids.iter().cloned());
        }
    }
    let mut reserved = Quantity::zero();
    for id in agreements {
        let Some(agreement) = state_transaction.world.repo_agreements.get(&id) else {
            continue;
        };
        if agreement.is_active() && agreement.collateral_custody_asset() == &custody {
            reserved = reserved
                .checked_add(agreement.collateral_leg().quantity())
                .map_err(arithmetic)?;
        }
    }
    Ok(reserved)
}

impl Execute for RetireBondTreasuryUnits {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RetireBondTreasuryUnits { bond, quantity } = self;
        let mut record = load(state_transaction, &bond)?;
        if authority != &record.terms.issuer {
            return Err(BondError::Unauthorized(
                "treasury units can only be retired by the issuer".to_owned(),
            )
            .into());
        }
        // Bond units are whole (scale 0); refuse fractional quantities with a bond error
        // before the burn's numeric-spec check.
        if quantity.is_zero() || quantity.as_numeric().scale() != 0 {
            return Err(BondError::InvalidState(format!(
                "a treasury retirement must burn a positive whole number of units, not {quantity}"
            ))
            .into());
        }
        // A recording cursor walks the balances; nothing may change them until it completes.
        if let Some(recording) = recording_in_progress(&record) {
            return Err(BondError::BooksClosed(format!(
                "cash flow {} of bond {bond} is being recorded; complete it with RecordBondCashflow before retiring units",
                recording.terms.index
            ))
            .into());
        }
        let held = global_balance(state_transaction.world(), &bond, authority);
        let reserved = issuer_repo_collateral(state_transaction, &bond, authority)?;
        let available = held
            .checked_sub(&reserved)
            .unwrap_or_else(|_| Quantity::zero());
        if quantity > available {
            return Err(BondError::InvalidState(format!(
                "the issuer holds {held} units of bond {bond}, {reserved} of them owed back as repo collateral; it cannot retire {quantity}"
            ))
            .into());
        }
        crate::smartcontracts::isi::asset::isi::execute_verified_bond_treasury_retirement(
            state_transaction,
            VerifiedBondTreasuryRetirement {
                authority: authority.clone(),
                bond: bond.clone(),
                units: quantity.clone(),
            },
        )?;
        record.state.outstanding_units = record
            .state
            .outstanding_units
            .checked_sub(&quantity)
            .map_err(arithmetic)?;
        record.state.retired_units = record
            .state
            .retired_units
            .checked_add(&quantity)
            .map_err(arithmetic)?;
        // With no unit outstanding (and the supply locked) every cash flow not yet
        // recorded would record no holders: cancel them, and mature the bond once
        // the recorded ones are serviced.
        let mut cancelled_cashflows = 0_u16;
        if record.state.outstanding_units.is_zero() && is_servicing(&record) {
            for state in record
                .state
                .cashflows
                .iter_mut()
                .filter(|state| state.status == BondCashflowStatus::Scheduled)
            {
                state.status = BondCashflowStatus::Cancelled;
                cancelled_cashflows = cancelled_cashflows.saturating_add(1);
            }
            mature_if_complete(&mut record);
        }
        let event = BondTreasuryUnitsRetired {
            bond: bond.clone(),
            issuer: authority.clone(),
            quantity: quantity.clone(),
            outstanding_units: record.state.outstanding_units.clone(),
            retired_units: record.state.retired_units.clone(),
            cancelled_cashflows,
        };
        store(state_transaction, record);
        iroha_logger::info!(%bond, %quantity, "bond treasury units retired");
        emit(state_transaction, BondEvent::TreasuryUnitsRetired(event));
        Ok(())
    }
}

impl Execute for BondInstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Register(isi) => isi.execute(authority, state_transaction),
            Self::RecordCashflow(isi) => isi.execute(authority, state_transaction),
            Self::FundCashflow(isi) => isi.execute(authority, state_transaction),
            Self::ClaimCashflow(isi) => isi.execute(authority, state_transaction),
            Self::CloseCashflow(isi) => isi.execute(authority, state_transaction),
            Self::Call(isi) => isi.execute(authority, state_transaction),
            Self::DeclareDefault(isi) => isi.execute(authority, state_transaction),
            Self::ReplacePayingAgent(isi) => isi.execute(authority, state_transaction),
            Self::RetireTreasuryUnits(isi) => isi.execute(authority, state_transaction),
        }
    }
}

/// Whether `source` is the custody of a native escrow of `source`'s bond whose seller is
/// `destination`'s account: the seller is the holder of record of escrowed units.
fn is_escrow_return_to_seller(
    world: &impl WorldReadOnly,
    source: &AssetId,
    destination: &AssetId,
) -> bool {
    crate::state::range_bounds::index_members(
        world.asset_escrows_by_seller(),
        destination.account(),
    )
    .any(|escrow_id| {
        world.asset_escrows().get(escrow_id).is_some_and(|escrow| {
            escrow.asset_definition == *source.definition() && escrow.custody == *source.account()
        })
    })
}

/// Enforce the book closing and the redemption freeze of a registered bond on one movement.
///
/// Called by the central numeric movement preparation, so it covers ordinary
/// transfers, transfer batches, atomic settlement movements and escrow legs,
/// native escrow funding and release, and repo legs alike.
///
/// - While a cash flow is being recorded every movement is refused: the
///   recording cursor walks the balances.
/// - From the record date of the next scheduled cash flow until it is recorded
///   (books closed), and permanently once the redemption is recorded (frozen),
///   only a native escrow returning custody to its seller may move units: the
///   seller is already the holder of record of escrowed units.
///
/// Redemption claims burn units through a separate verified burn and are not movements.
pub(crate) fn ensure_bond_units_movable(
    state_transaction: &StateTransaction<'_, '_>,
    source: &AssetId,
    destination: &AssetId,
    native_escrow_release: bool,
) -> Result<(), Error> {
    let world = state_transaction.world();
    let Some(record) = world.bonds().get(source.definition()) else {
        return Ok(());
    };
    if let Some(recording) = recording_in_progress(record) {
        return Err(BondError::BooksClosed(format!(
            "cash flow {} of bond {} is being recorded; complete it with RecordBondCashflow before moving units",
            recording.terms.index, record.id
        ))
        .into());
    }
    let closed = books_closed_by(record, block_time_ms(state_transaction));
    if !record.state.transfers_frozen && closed.is_none() {
        return Ok(());
    }
    if native_escrow_release && is_escrow_return_to_seller(world, source, destination) {
        return Ok(());
    }
    if record.state.transfers_frozen {
        return Err(BondError::TransfersFrozen(record.id.to_string()).into());
    }
    let closed = closed.expect("books are closed");
    Err(BondError::BooksClosed(format!(
        "the record date {} of cash flow {} of bond {} has passed; record it with RecordBondCashflow before moving units",
        closed.terms.record_date_ms, closed.terms.index, record.id
    ))
    .into())
}

/// Movement purposes that may carry registered bond units, besides plain transaction transfers.
///
/// Registered bond units rest only in accounts (holders of record) and native
/// asset-escrow custody (attributed to the escrow seller). Every other
/// protocol custody would leave the economic owner outside the entitlements.
const BOND_UNIT_MOVEMENT_PURPOSES: [&str; 4] = [
    "native-escrow-funding",
    "native-escrow-retained",
    "repo-bilateral",
    "settlement-bilateral",
];

/// Reject moving registered bond units through a protocol custody the kernel does not attribute.
///
/// `purpose` is the typed movement purpose tag, or `None` for a plain transaction movement.
pub(crate) fn ensure_bond_custody_supported(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    purpose: Option<&str>,
) -> Result<(), Error> {
    match purpose {
        Some(tag)
            if !BOND_UNIT_MOVEMENT_PURPOSES.contains(&tag)
                && world.bonds().get(definition).is_some() =>
        {
            Err(BondError::CustodyUnsupported(format!(
                "units of bond {definition} cannot move through `{tag}`; registered bond units rest in accounts and native asset escrows"
            ))
            .into())
        }
        _ => Ok(()),
    }
}

/// Reject ordinary supply changes of a registered bond.
///
/// The registered outstanding amount equals the definition total; only
/// redemption claims and treasury retirements burn units afterwards, through
/// their verified burn source policies.
pub(crate) fn ensure_bond_supply_unlocked(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<(), Error> {
    if world.bonds().get(definition).is_some() {
        return Err(BondError::SupplyLocked(definition.to_string()).into());
    }
    Ok(())
}

/// Return whether `account` is the deterministic vault of a registered bond.
///
/// Vaults are key-less; every debit and credit of a vault balance goes through
/// the bond kernel's verified movements. The lookup uses the `bond_vaults` index.
pub(crate) fn is_bond_vault_account(world: &impl WorldReadOnly, account: &AccountId) -> bool {
    world.bond_vaults().get(account).is_some()
}

/// Return whether `asset_id` is the payment-asset balance held by a bond vault.
pub(crate) fn is_bond_vault_asset(world: &impl WorldReadOnly, asset_id: &AssetId) -> bool {
    world
        .bond_vaults()
        .get(asset_id.account())
        .and_then(|bond| world.bonds().get(bond))
        .is_some_and(|record| &record.terms.payment_asset == asset_id.definition())
}

/// Reject retiring asset definitions that a bond record depends on.
///
/// Bond records are permanent, so both the bond definition and its payment
/// asset definition are retained for as long as the ledger exists.
pub(crate) fn ensure_asset_definitions_not_retained_by_bonds(
    world: &impl WorldReadOnly,
    definitions: &std::collections::BTreeSet<AssetDefinitionId>,
    context: &str,
) -> Result<(), Error> {
    for (id, record) in world.bonds().iter() {
        if definitions.contains(id) {
            return Err(BondError::Retained(format!(
                "cannot {context}: asset definition {id} is a registered bond"
            ))
            .into());
        }
        if definitions.contains(&record.terms.payment_asset) {
            return Err(BondError::Retained(format!(
                "cannot {context}: asset definition {} is the payment asset of bond {id}",
                record.terms.payment_asset
            ))
            .into());
        }
    }
    Ok(())
}

/// Whether a bond still needs its issuer and paying agent to act.
fn needs_parties(record: &BondRecord) -> bool {
    is_servicing(record)
        || record.state.cashflows.iter().any(|state| {
            matches!(
                state.status,
                BondCashflowStatus::Recording
                    | BondCashflowStatus::Recorded
                    | BondCashflowStatus::Funded
            )
        })
}

/// Reject unregistering an account that a bond record still depends on.
///
/// Retained: every bond vault, the issuer and paying agent of a bond that is
/// still servicing or has an open cash flow, and every account holding units of
/// a registered bond (unregistering would destroy units outside the supply lock).
/// Unclaimed entitlements of an unregistered account are not destroyed; they
/// stay claimable once the same account exists again.
pub(crate) fn ensure_account_not_retained_by_bonds(
    world: &impl WorldReadOnly,
    account: &AccountId,
    context: &str,
) -> Result<(), Error> {
    if let Some(bond) = world.bond_vaults().get(account) {
        return Err(BondError::Retained(format!(
            "cannot {context}: account {account} is the vault of bond {bond}"
        ))
        .into());
    }
    for (id, record) in world.bonds().iter() {
        let role = if &record.terms.issuer == account {
            Some("issuer")
        } else if &record.terms.paying_agent == account {
            Some("paying agent")
        } else {
            None
        };
        if let Some(role) = role
            && needs_parties(record)
        {
            return Err(BondError::Retained(format!(
                "cannot {context}: account {account} is the {role} of bond {id}"
            ))
            .into());
        }
    }
    if let Some(held) = world.assets_in_account_iter(account).find(|asset| {
        !asset.value().as_ref().is_zero() && world.bonds().get(asset.id().definition()).is_some()
    }) {
        return Err(BondError::Retained(format!(
            "cannot {context}: account {account} holds units of bond {}",
            held.id().definition()
        ))
        .into());
    }
    Ok(())
}

/// Reject a rekey that would invalidate a running recording or move a vault.
///
/// Called before any rekey mutation; [`rekey_bond_references`] performs the
/// migration afterwards.
pub(crate) fn ensure_account_rekey_allowed_by_bonds(
    world: &impl WorldReadOnly,
    old_account: &AccountId,
) -> Result<(), Error> {
    if let Some(bond) = world.bond_vaults().get(old_account) {
        return Err(BondError::Retained(format!(
            "cannot rekey account {old_account}: it is the vault of bond {bond}"
        ))
        .into());
    }
    for (id, record) in world.bonds().iter() {
        let Some(recording) = recording_in_progress(record) else {
            continue;
        };
        let holds_units = !global_balance(world, id, old_account).is_zero();
        let entitled = world
            .bond_entitlements()
            .get(&BondEntitlementId::new(
                id.clone(),
                recording.terms.index,
                old_account.clone(),
            ))
            .is_some();
        if holds_units || entitled {
            return Err(BondError::BooksClosed(format!(
                "cannot rekey account {old_account}: cash flow {} of bond {id} is being recorded",
                recording.terms.index
            ))
            .into());
        }
    }
    Ok(())
}

/// Move bond references of a rekeyed account to its new identifier.
///
/// The issuer and paying agent of every record and every unclaimed entitlement
/// follow the account; claimed entitlements stay as history under the old
/// identifier.
pub(crate) fn rekey_bond_references(
    state_transaction: &mut StateTransaction<'_, '_>,
    old_account: &AccountId,
    new_account: &AccountId,
) -> Result<(), Error> {
    // TODO: an index of entitlements by holder would avoid probing every recorded
    // cash flow of every bond on each rekey (`specs/finance/bond_ops.md` §9).
    let mut records = Vec::new();
    let mut moved = Vec::new();
    for (id, record) in state_transaction.world.bonds.iter() {
        for state in &record.state.cashflows {
            let old_id = BondEntitlementId::new(id.clone(), state.terms.index, old_account.clone());
            if let Some(entitlement) = state_transaction.world.bond_entitlements.get(&old_id)
                && entitlement.claimed_at_ms.is_none()
            {
                moved.push(entitlement.clone());
            }
        }
        if &record.terms.issuer == old_account || &record.terms.paying_agent == old_account {
            records.push(record.clone());
        }
    }
    for mut record in records {
        if &record.terms.issuer == old_account {
            record.terms.issuer = new_account.clone();
        }
        if &record.terms.paying_agent == old_account {
            record.terms.paying_agent = new_account.clone();
        }
        store(state_transaction, record);
    }
    for entitlement in moved {
        let new_id = BondEntitlementId::new(
            entitlement.id.bond.clone(),
            entitlement.id.index,
            new_account.clone(),
        );
        if state_transaction
            .world
            .bond_entitlements
            .get(&new_id)
            .is_some()
        {
            return Err(BondError::Retained(format!(
                "cannot rekey account {old_account}: {new_account} already has an entitlement to cash flow {} of bond {}",
                new_id.index, new_id.bond
            ))
            .into());
        }
        state_transaction
            .world
            .bond_entitlements
            .remove(entitlement.id.clone());
        state_transaction.world.bond_entitlements.insert(
            new_id.clone(),
            BondEntitlement {
                id: new_id,
                ..entitlement
            },
        );
    }
    Ok(())
}

/// Typed bond queries (`FindBonds`, `FindBondById`).
pub mod query {
    use iroha_data_model::{
        bond::BondRecord,
        query::{
            bond::prelude::{FindBondById, FindBonds},
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::{FindError, QueryExecutionFail},
        },
    };
    use mv::storage::StorageReadOnly;

    use crate::{
        prelude::ValidSingularQuery,
        smartcontracts::ValidQuery,
        state::{StateReadOnly, WorldReadOnly},
    };

    impl ValidQuery for FindBonds {
        fn execute(
            self,
            filter: CompoundPredicate<BondRecord>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = BondRecord>, QueryExecutionFail> {
            Ok(state_ro
                .world()
                .bonds()
                .iter()
                .filter_map(move |(_, record)| filter.applies(record).then(|| record.clone())))
        }
    }

    impl ValidSingularQuery for FindBondById {
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<BondRecord, QueryExecutionFail> {
            state_ro
                .world()
                .bonds()
                .get(self.bond())
                .ok_or_else(|| QueryExecutionFail::Find(FindError::Bond(self.bond().clone())))
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
}

#[cfg(any(test, feature = "iroha-core-tests"))]
impl crate::state::World {
    /// Seed one bond record (and its vault index entry) into an owned test world for
    /// read-path fixtures.
    ///
    /// This does not authorize production registration; `RegisterBond` keeps
    /// every issuer, definition and supply check.
    pub fn insert_bond_record_for_testing(&mut self, record: BondRecord) {
        let mut block = self.block();
        {
            let mut transaction = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            transaction
                .bond_vaults
                .insert(record.vault().clone(), record.id.clone());
            transaction.bonds.insert(record.id.clone(), record);
            transaction.apply();
        }
        block.commit();
    }

    /// Seed one bond entitlement into an owned test world for read-path fixtures.
    pub fn insert_bond_entitlement_for_testing(&mut self, entitlement: BondEntitlement) {
        let mut block = self.block();
        {
            let mut transaction = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            transaction
                .bond_entitlements
                .insert(entitlement.id.clone(), entitlement);
            transaction.apply();
        }
        block.commit();
    }
}

#[cfg(test)]
#[path = "bond_tests.rs"]
mod tests;
