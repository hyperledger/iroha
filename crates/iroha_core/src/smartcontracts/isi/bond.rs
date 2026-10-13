//! Native bond-servicing kernel execution (`specs/finance/bond_ops.md`).
//!
//! Every authority, schedule, encumbrance and balance rule of the bond kernel
//! is enforced here. Balance effects are expressed as one-shot verified
//! capabilities consumed by the central numeric movement and burn paths in the
//! asset module, which re-check them against the stored record.
use std::collections::{BTreeMap, BTreeSet};

use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinitionId, AssetId},
    bond::{
        BOND_MAX_SNAPSHOT_HOLDERS, BondCashflowKind, BondCashflowState, BondCashflowStatus,
        BondCashflowTerms, BondError, BondId, BondLifecycle, BondRecord, holder_payment,
        redemption_amount, snapshot_amount_due,
    },
    escrow::AssetEscrowStatus,
    events::data::{
        DataEvent,
        bond::{
            BondCalled, BondCashflowClaimed, BondCashflowClosed, BondCashflowFunded,
            BondCashflowRecorded, BondDefaulted, BondEvent, BondRegistered,
        },
    },
    isi::bond::{
        BondInstructionBox, CallBond, ClaimBondCashflow, CloseBondCashflow, DeclareBondDefault,
        FundBondCashflow, RecordBondCashflow, RegisterBond,
    },
};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;

use super::{Error, Execute};
use crate::state::{StateTransaction, WorldReadOnly};

/// Exact purpose of one verified vault movement.
pub(in crate::smartcontracts::isi) enum VerifiedBondMovementPurpose {
    /// Paying agent or issuer funds the exact recorded amount due.
    Funding,
    /// Vault pays one snapshot holder.
    Payment,
    /// Vault returns a closed cash flow's rounding residual to the issuer.
    Residual,
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
    #[allow(clippy::too_many_arguments)]
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

/// Non-reusable proof that a redemption claim burns one holder's exact snapshot units.
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

fn block_time_ms(state_transaction: &StateTransaction<'_, '_>) -> u64 {
    state_transaction.block_unix_timestamp_ms()
}

// TODO: every instruction clones and rewrites the whole record, including every
// recorded snapshot; move entitlements into a per-holder table before bonds approach
// the 4096-holder snapshot bound (`specs/finance/bond_ops.md` §9).
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

fn ensure_servicing(record: &BondRecord) -> Result<(), Error> {
    if matches!(
        record.state.lifecycle,
        BondLifecycle::Active | BondLifecycle::Called
    ) {
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

/// Reject recording while units of the bond are encumbered.
///
/// An active repo agreement that moves the bond (as collateral or cash) or an
/// active native escrow whose custody holds bond units for anyone other than
/// the issuer would leave the economic owner outside the record-date snapshot.
fn ensure_unencumbered(
    state_transaction: &StateTransaction<'_, '_>,
    record: &BondRecord,
) -> Result<(), Error> {
    let bond = &record.id;
    if let Some((agreement_id, _)) =
        state_transaction
            .world
            .repo_agreements
            .iter()
            .find(|(_, agreement)| {
                agreement.is_active()
                    && (agreement.collateral_leg.asset_definition_id == *bond
                        || agreement.cash_leg.asset_definition_id == *bond)
            })
    {
        return Err(BondError::Encumbered(format!(
            "active repo agreement {agreement_id} uses bond {bond}; settle it before recording"
        ))
        .into());
    }
    let issuer = &record.terms.issuer;
    if let Some((escrow_id, _)) =
        state_transaction
            .world
            .asset_escrows
            .iter()
            .find(|(_, escrow)| {
                escrow.asset_definition == *bond
                    && matches!(
                        escrow.status,
                        AssetEscrowStatus::Open
                            | AssetEscrowStatus::Accepted
                            | AssetEscrowStatus::PaymentSent
                            | AssetEscrowStatus::Disputed
                            | AssetEscrowStatus::Locked
                    )
                    && !escrow.remaining_amount.is_zero()
                    && !(escrow.seller == *issuer
                        && escrow.buyer.as_ref().is_none_or(|buyer| buyer == issuer))
            })
    {
        return Err(BondError::Encumbered(format!(
            "active native escrow {} holds units of bond {bond} pending for a holder; release or expire it before recording",
            escrow_id.as_hash()
        ))
        .into());
    }
    Ok(())
}

/// Build the record-date snapshot of investor holdings.
///
/// Global balances of the bond definition are aggregated per account,
/// excluding the issuer, the bond vault and native protocol escrow custody.
fn build_snapshot(
    state_transaction: &StateTransaction<'_, '_>,
    record: &BondRecord,
) -> Result<BTreeMap<AccountId, Quantity>, Error> {
    let vault = record.vault().clone();
    let mut snapshot: BTreeMap<AccountId, Quantity> = BTreeMap::new();
    let Some(assets) = state_transaction
        .world
        .asset_definition_assets
        .get(&record.id)
        .cloned()
    else {
        return Ok(snapshot);
    };
    let custody = crate::smartcontracts::isi::escrow::native_escrow_custody_accounts_for(
        state_transaction.world(),
        &record.id,
    );
    for asset_id in assets {
        let Some(balance) = state_transaction.world.assets.get(&asset_id) else {
            continue;
        };
        let balance = balance.as_ref().clone();
        let holder = asset_id.account();
        if balance.is_zero()
            || holder == &record.terms.issuer
            || holder == &vault
            || custody.contains(holder)
        {
            continue;
        }
        let entry = snapshot
            .entry(holder.clone())
            .or_insert_with(Quantity::zero);
        *entry = entry.checked_add(&balance).map_err(arithmetic)?;
        if snapshot.len() > BOND_MAX_SNAPSHOT_HOLDERS {
            return Err(BondError::SnapshotTooLarge(snapshot.len()).into());
        }
    }
    Ok(snapshot)
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
        let cashflows = u16::try_from(terms.cashflows.len()).map_err(arithmetic)?;
        let record = BondRecord::registered(bond.clone(), terms, outstanding.clone());
        let event = BondRegistered {
            bond: bond.clone(),
            issuer: record.terms.issuer.clone(),
            paying_agent: record.terms.paying_agent.clone(),
            outstanding_units: outstanding,
            cashflows,
        };
        store(state_transaction, record);
        iroha_logger::info!(%bond, "bond registered");
        emit(state_transaction, BondEvent::Registered(event));
        Ok(())
    }
}

impl Execute for RecordBondCashflow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RecordBondCashflow { bond, index } = self;
        let mut record = load(state_transaction, &bond)?;
        ensure_paying_agent(&record, authority, "recording")?;
        ensure_servicing(&record)?;
        let now = block_time_ms(state_transaction);
        let terms = {
            let current = cashflow(&record, index)?;
            if current.status != BondCashflowStatus::Scheduled {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {}, not Scheduled",
                    current.status
                ))
                .into());
            }
            if now < current.terms.record_date_ms {
                return Err(BondError::TooEarly(format!(
                    "cash flow {index} record date {} is after block time {now}",
                    current.terms.record_date_ms
                ))
                .into());
            }
            current.terms.clone()
        };
        if let Some(earlier) = record.state.cashflows[..usize::from(index)]
            .iter()
            .find(|earlier| earlier.status == BondCashflowStatus::Scheduled)
        {
            return Err(BondError::InvalidState(format!(
                "cash flow {} must be recorded first",
                earlier.terms.index
            ))
            .into());
        }
        ensure_unencumbered(state_transaction, &record)?;
        let snapshot = build_snapshot(state_transaction, &record)?;
        let payment_spec = state_transaction
            .numeric_spec_for(&record.terms.payment_asset)
            .map_err(Error::from)?;
        let amount_due = snapshot_amount_due(&snapshot, &terms.amount_per_unit, payment_spec)?;
        let entitled_units = snapshot
            .values()
            .try_fold(Quantity::zero(), |total, units| total.checked_add(units))
            .map_err(arithmetic)?;
        let holders = u32::try_from(snapshot.len()).map_err(arithmetic)?;
        if terms.kind == BondCashflowKind::Redemption {
            record.state.transfers_frozen = true;
        }
        let state = cashflow_mut(&mut record, index)?;
        state.status = BondCashflowStatus::Recorded;
        state.snapshot = snapshot;
        state.entitled_units = entitled_units.clone();
        state.amount_due = amount_due.clone();
        state.recorded_at_ms = Some(now);
        store(state_transaction, record);
        iroha_logger::info!(%bond, index, %amount_due, "bond cash flow recorded");
        emit(
            state_transaction,
            BondEvent::CashflowRecorded(BondCashflowRecorded {
                bond,
                index,
                kind: terms.kind,
                holders,
                entitled_units,
                amount_due,
            }),
        );
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
        let (kind, units, amount_per_unit) = {
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
            let units = current
                .snapshot
                .get(&holder)
                .cloned()
                .ok_or_else(|| BondError::NotInSnapshot(holder.to_string()))?;
            if current.claimed.contains(&holder) {
                return Err(BondError::AlreadyClaimed(holder.to_string()).into());
            }
            (
                current.terms.kind,
                units,
                current.terms.amount_per_unit.clone(),
            )
        };
        let payment_spec = state_transaction
            .numeric_spec_for(&record.terms.payment_asset)
            .map_err(Error::from)?;
        let amount = holder_payment(&units, &amount_per_unit, payment_spec)?;
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
        state.claimed.insert(holder.clone());
        state.paid = state.paid.checked_add(&amount).map_err(arithmetic)?;
        store(state_transaction, record);
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
        let residual = {
            let current = cashflow(&record, index)?;
            if current.status != BondCashflowStatus::Funded {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} is {}, not Funded",
                    current.status
                ))
                .into());
            }
            if !current.all_claimed() {
                return Err(BondError::InvalidState(format!(
                    "cash flow {index} still has unclaimed snapshot holders"
                ))
                .into());
            }
            current
                .funded
                .checked_sub(&current.paid)
                .map_err(arithmetic)?
        };
        if !residual.is_zero() {
            let vault = AssetId::new(record.terms.payment_asset.clone(), record.vault().clone());
            let destination = AssetId::new(
                record.terms.payment_asset.clone(),
                record.terms.issuer.clone(),
            );
            crate::smartcontracts::isi::asset::isi::execute_verified_bond_movement(
                state_transaction,
                VerifiedBondMovement::new(
                    VerifiedBondMovementPurpose::Residual,
                    authority,
                    &bond,
                    index,
                    vault,
                    destination,
                    residual.clone(),
                ),
            )?;
        }
        let now = block_time_ms(state_transaction);
        let state = cashflow_mut(&mut record, index)?;
        state.status = BondCashflowStatus::Closed;
        state.closed_at_ms = Some(now);
        // The bond matures once its effective redemption and every other
        // effective cash flow are closed; an unpaid coupon keeps it servicing
        // (and open to a default declaration).
        if matches!(
            record.state.lifecycle,
            BondLifecycle::Active | BondLifecycle::Called
        ) && record.state.cashflows.iter().all(|state| {
            matches!(
                state.status,
                BondCashflowStatus::Closed | BondCashflowStatus::Cancelled
            )
        }) {
            record.state.lifecycle = BondLifecycle::Matured;
        }
        store(state_transaction, record);
        emit(
            state_transaction,
            BondEvent::CashflowClosed(BondCashflowClosed {
                bond,
                index,
                residual,
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
        let state = cashflow_mut(&mut record, index)?;
        if !matches!(
            state.status,
            BondCashflowStatus::Scheduled | BondCashflowStatus::Recorded
        ) {
            return Err(BondError::InvalidState(format!(
                "cash flow {index} is {} and cannot default",
                state.status
            ))
            .into());
        }
        if now <= state.terms.payment_date_ms {
            return Err(BondError::TooEarly(format!(
                "cash flow {index} payment date {} has not passed at block time {now}",
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
        }
    }
}

/// Reject any movement of a bond whose redemption has been recorded.
///
/// Called by the central numeric movement preparation, so it covers ordinary
/// transfers, transfer batches, atomic settlement movements and escrow legs,
/// conditional-escrow funding and repo initiation alike. Redemption claims burn
/// units through a separate verified burn and are not movements.
pub(crate) fn ensure_bond_units_movable(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<(), Error> {
    if world
        .bonds()
        .get(definition)
        .is_some_and(|record| record.state.transfers_frozen)
    {
        return Err(BondError::TransfersFrozen(definition.to_string()).into());
    }
    Ok(())
}

/// Reject ordinary supply changes of a registered bond.
///
/// The registered outstanding amount equals the definition total; only
/// redemption claims burn units afterwards.
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
/// the bond kernel's verified movements.
pub(crate) fn is_bond_vault_account(world: &impl WorldReadOnly, account: &AccountId) -> bool {
    world
        .bonds()
        .iter()
        .any(|(_, record)| &record.vault == account)
}

/// Return whether `asset_id` is the payment-asset balance held by a bond vault.
pub(crate) fn is_bond_vault_asset(world: &impl WorldReadOnly, asset_id: &AssetId) -> bool {
    world.bonds().iter().any(|(_, record)| {
        &record.terms.payment_asset == asset_id.definition() && &record.vault == asset_id.account()
    })
}

/// Reject retiring asset definitions that a bond record depends on.
///
/// Bond records are permanent, so both the bond definition and its payment
/// asset definition are retained for as long as the ledger exists.
pub(crate) fn ensure_asset_definitions_not_retained_by_bonds(
    world: &impl WorldReadOnly,
    definitions: &BTreeSet<AssetDefinitionId>,
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

/// Reject removing or rekeying an account that a bond record still depends on.
///
/// The bond vault, the issuer and the paying agent of every registered bond
/// and every unclaimed holder of a recorded or funded cash flow are retained.
pub(crate) fn ensure_account_not_retained_by_bonds(
    world: &impl WorldReadOnly,
    account: &AccountId,
    context: &str,
) -> Result<(), Error> {
    for (id, record) in world.bonds().iter() {
        let retained = if &record.vault == account {
            Some("is its vault")
        } else if &record.terms.issuer == account {
            Some("is its issuer")
        } else if &record.terms.paying_agent == account {
            Some("is its paying agent")
        } else if record.state.cashflows.iter().any(|state| {
            matches!(
                state.status,
                BondCashflowStatus::Recorded | BondCashflowStatus::Funded
            ) && state.snapshot.contains_key(account)
                && !state.claimed.contains(account)
        }) {
            Some("holds an unclaimed entitlement")
        } else {
            None
        };
        if let Some(reason) = retained {
            return Err(BondError::Retained(format!(
                "cannot {context}: account {account} {reason} of bond {id}"
            ))
            .into());
        }
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
    /// Seed one bond record into an owned test world for read-path fixtures.
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
            transaction.bonds.insert(record.id.clone(), record);
            transaction.apply();
        }
        block.commit();
    }
}

#[cfg(test)]
#[path = "bond_tests.rs"]
mod tests;
