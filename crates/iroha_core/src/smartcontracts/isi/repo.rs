//! Settlement logic for repo and reverse-repo instructions.
use super::prelude::*;
use crate::{
    smartcontracts::isi::{
        asset::isi::assert_numeric_spec_with, settlement::ensure_bilateral_counterparty_consent,
    },
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    asset::AssetId,
    events::data::prelude::{
        AccountEvent, RepoAccountEvent, RepoAccountInitiated, RepoAccountMarginCalled,
        RepoAccountRole, RepoAccountSettled,
    },
    isi::{
        error::InstructionExecutionError,
        repo::{RepoInstructionBox, RepoIsi, RepoMarginCallIsi, ReverseRepoIsi},
    },
    prelude::*,
    repo::{RepoAgreement, RepoGovernance},
};
use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity, RoundingMode};
const MAX_HAIRCUT_BPS: u16 = 10_000;
const MS_PER_DAY: u64 = 86_400_000;
const ACT_360_YEAR_MS: u64 = MS_PER_DAY * 360;
/// Non-reusable proof that repo consent and retained-agreement checks selected two exact legs.
pub(in crate::smartcontracts::isi) struct VerifiedRepoNumericPair {
    authority: AccountId,
    binding: Vec<u8>,
    legs: [(AssetId, AssetId, Quantity); 2],
}
impl VerifiedRepoNumericPair {
    fn new<T: norito::NoritoSerialize>(
        authority: AccountId,
        binding: &T,
        legs: [(AssetId, AssetId, Quantity); 2],
    ) -> Result<Self, Error> {
        let binding = norito::encode_canonical(binding).map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to encode exact repo movement binding: {error}").into(),
            )
        })?;
        Ok(Self {
            authority,
            binding,
            legs,
        })
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (AccountId, Vec<u8>, [(AssetId, AssetId, Quantity); 2]) {
        (self.authority, self.binding, self.legs)
    }
}
fn ensure_positive_quantity(quantity: &Quantity, label: &str) -> Result<(), Error> {
    if quantity.is_zero() {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("{label} must be greater than zero").into(),
        ));
    }
    Ok(())
}
fn ensure_agreement_quantities(agreement: &RepoAgreement) -> Result<(), Error> {
    ensure_positive_quantity(agreement.cash_leg().quantity(), "stored repo cash quantity")?;
    ensure_positive_quantity(
        agreement.collateral_leg().quantity(),
        "stored repo collateral quantity",
    )?;
    if agreement.cash_source().account() != agreement.counterparty()
        || agreement.cash_source().definition() != agreement.cash_leg().asset_definition_id()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repo cash consent asset does not match the agreement".into(),
        ));
    }
    let collateral_holder = agreement
        .custodian()
        .as_ref()
        .unwrap_or_else(|| agreement.counterparty());
    if agreement.collateral_custody_asset().account() != collateral_holder
        || agreement.collateral_custody_asset().definition()
            != agreement.collateral_leg().asset_definition_id()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "stored repo collateral consent asset does not match the agreement".into(),
        ));
    }
    Ok(())
}
fn ensure_accounts(
    stx: &StateTransaction<'_, '_>,
    initiator: &AccountId,
    counterparty: &AccountId,
    custodian: Option<&AccountId>,
) -> Result<(), Error> {
    stx.world.account(initiator).map_err(Error::from)?;
    stx.world.account(counterparty).map_err(Error::from)?;
    if let Some(custodian) = custodian {
        stx.world.account(custodian).map_err(Error::from)?;
    }
    Ok(())
}
fn ensure_explicit_governance(governance: RepoGovernance) -> Result<(), Error> {
    if governance.haircut_bps() > MAX_HAIRCUT_BPS {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "repo haircut {} exceeds the maximum of {MAX_HAIRCUT_BPS} basis points",
                governance.haircut_bps()
            )
            .into(),
        ));
    }
    Ok(())
}
fn asset_in_account_with_same_scope(source: &AssetId, account: AccountId) -> AssetId {
    AssetId::with_scope(source.definition().clone(), account, source.scope().clone())
}
fn compute_accrued_interest(
    principal: &Quantity,
    rate_bps: u16,
    elapsed_ms: u64,
    cash_spec: NumericSpec,
) -> Result<Quantity, Error> {
    if rate_bps == 0 || elapsed_ms == 0 || principal.is_zero() {
        return Ok(Quantity::zero());
    }
    let rate_fraction = Numeric::try_new(u128::from(rate_bps), 4).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("failed to normalise repo rate: {err}").into(),
        )
    })?;
    let elapsed_fraction = Numeric::from(elapsed_ms)
        .try_decimal_div_round(
            &Numeric::from(ACT_360_YEAR_MS),
            18,
            RoundingMode::TowardZero,
        )
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to compute repo elapsed fraction: {err}").into(),
            )
        })?;
    let rate_time = rate_fraction
        .try_decimal_mul(&elapsed_fraction)
        .and_then(|value| value.try_quantize(18, RoundingMode::TowardZero))
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("repo interest calculation failed (rate*time): {err}").into(),
            )
        })?;
    let raw_interest = principal
        .as_numeric()
        .try_decimal_mul(&rate_time)
        .and_then(|value| value.try_quantize(28, RoundingMode::TowardZero))
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("repo interest calculation failed (principal * factor): {err}").into(),
            )
        })?;
    let rounded = raw_interest
        .try_quantize(cash_spec.scale().unwrap_or(28), RoundingMode::TowardZero)
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to quantize repo interest: {err}").into(),
            )
        })?;
    assert_numeric_spec_with(&rounded, cash_spec)?;
    Quantity::from_canonical_numeric(rounded).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("repo interest produced an invalid quantity: {err}").into(),
        )
        .into()
    })
}
fn expected_cash_settlement(
    principal: &Quantity,
    rate_bps: u16,
    initiated_timestamp_ms: u64,
    settlement_timestamp_ms: u64,
    cash_spec: NumericSpec,
) -> Result<Quantity, Error> {
    if settlement_timestamp_ms < initiated_timestamp_ms {
        return Err(InstructionExecutionError::InvariantViolation(
            "reverse repo settlement predates agreement initiation".into(),
        ));
    }
    let elapsed_ms = settlement_timestamp_ms - initiated_timestamp_ms;
    let interest = compute_accrued_interest(principal, rate_bps, elapsed_ms, cash_spec)?;
    principal.checked_add(&interest).map_err(|_| {
        InstructionExecutionError::InvariantViolation(
            "repo cash leg overflowed while adding accrued interest".into(),
        )
        .into()
    })
}
#[allow(clippy::too_many_lines)]
impl Execute for RepoIsi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let settlement_id = self.settlement_id();
        let initiation_intent_hash = self.initiation_intent_hash();
        let maturity_intent_hash = self.maturity_intent_hash();
        let RepoIsi {
            agreement_id,
            initiator,
            counterparty,
            custodian,
            cash_leg,
            collateral_leg,
            rate_bps,
            maturity_timestamp_ms,
            governance,
        } = self;
        if &initiator != authority {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo initiator must match the transaction authority".into(),
            ));
        }
        if initiator == counterparty {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo counterparties must be distinct".into(),
            ));
        }
        if custodian
            .as_ref()
            .is_some_and(|custodian| custodian == &initiator || custodian == &counterparty)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo custodian must be distinct from both counterparties".into(),
            ));
        }
        if cash_leg.asset_definition_id() == collateral_leg.asset_definition_id() {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo cash and collateral must use distinct asset definitions".into(),
            ));
        }
        ensure_positive_quantity(cash_leg.quantity(), "repo cash quantity")?;
        ensure_positive_quantity(collateral_leg.quantity(), "repo collateral quantity")?;
        ensure_explicit_governance(governance)?;
        ensure_accounts(
            state_transaction,
            &initiator,
            &counterparty,
            custodian.as_ref(),
        )?;
        if state_transaction
            .world
            .repo_agreements
            .get(&agreement_id)
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("repo agreement {agreement_id} already exists").into(),
            ));
        }
        let initiated_timestamp_ms = u64::try_from(
            state_transaction._curr_block.creation_time().as_millis(),
        )
        .map_err(|_| {
            InstructionExecutionError::InvariantViolation(
                "block creation time exceeds u64::MAX milliseconds".into(),
            )
        })?;
        if maturity_timestamp_ms <= initiated_timestamp_ms {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo maturity must be later than its on-ledger initiation".into(),
            ));
        }
        let cash_def_id = cash_leg.asset_definition_id().clone();
        let collateral_def_id = collateral_leg.asset_definition_id().clone();
        let cash_spec = state_transaction
            .numeric_spec_for(&cash_def_id)
            .map_err(Error::from)?;
        assert_numeric_spec_with(cash_leg.quantity().as_numeric(), cash_spec)?;
        let collateral_spec = state_transaction
            .numeric_spec_for(&collateral_def_id)
            .map_err(Error::from)?;
        assert_numeric_spec_with(collateral_leg.quantity().as_numeric(), collateral_spec)?;
        let collateral_holder_account = custodian.clone().unwrap_or_else(|| counterparty.clone());
        let cash_source = ensure_bilateral_counterparty_consent(
            state_transaction,
            authority,
            &counterparty,
            &cash_def_id,
            &settlement_id,
            initiation_intent_hash,
        )?;
        let collateral_custody_asset = ensure_bilateral_counterparty_consent(
            state_transaction,
            authority,
            &collateral_holder_account,
            &collateral_def_id,
            &settlement_id,
            maturity_intent_hash,
        )?;
        let cash_destination = asset_in_account_with_same_scope(&cash_source, initiator.clone());
        let collateral_source =
            asset_in_account_with_same_scope(&collateral_custody_asset, initiator.clone());
        let movement = VerifiedRepoNumericPair::new(
            authority.clone(),
            &(
                settlement_id.clone(),
                initiation_intent_hash,
                maturity_intent_hash,
            ),
            [
                (
                    cash_source.clone(),
                    cash_destination,
                    cash_leg.quantity().clone(),
                ),
                (
                    collateral_source,
                    collateral_custody_asset.clone(),
                    collateral_leg.quantity().clone(),
                ),
            ],
        )?;
        crate::smartcontracts::isi::asset::isi::execute_verified_repo_numeric_pair(
            state_transaction,
            movement,
        )?;
        let agreement = RepoAgreement::new(
            agreement_id.clone(),
            initiator.clone(),
            counterparty.clone(),
            cash_leg.clone(),
            cash_source,
            collateral_leg.clone(),
            collateral_custody_asset,
            rate_bps,
            maturity_timestamp_ms,
            initiated_timestamp_ms,
            governance,
            custodian.clone(),
        );
        state_transaction
            .world
            .insert_repo_agreement_entry(agreement.clone());
        iroha_logger::info!(
            %agreement_id,
            initiator=%initiator,
            counterparty=%counterparty,
            custodian=?custodian,
            "repo agreement initiated"
        );
        let mut repo_events =
            Vec::with_capacity(2_usize.saturating_add(usize::from(custodian.is_some())));
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::Initiated(
            RepoAccountInitiated::new(
                initiator.clone(),
                counterparty.clone(),
                agreement.clone(),
                RepoAccountRole::Initiator,
            ),
        )));
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::Initiated(
            RepoAccountInitiated::new(
                counterparty.clone(),
                initiator.clone(),
                agreement.clone(),
                RepoAccountRole::Counterparty,
            ),
        )));
        if let Some(custodian_account) = &custodian {
            repo_events.push(AccountEvent::Repo(RepoAccountEvent::Initiated(
                RepoAccountInitiated::new(
                    custodian_account.clone(),
                    initiator.clone(),
                    agreement,
                    RepoAccountRole::Custodian,
                ),
            )));
        }
        state_transaction.world.emit_events(repo_events);
        Ok(())
    }
}
impl Execute for RepoInstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            RepoInstructionBox::Initiate(isi) => (*isi).execute(authority, state_transaction),
            RepoInstructionBox::Reverse(isi) => isi.execute(authority, state_transaction),
            RepoInstructionBox::MarginCall(isi) => isi.execute(authority, state_transaction),
        }
    }
}
#[allow(clippy::too_many_lines)]
impl Execute for ReverseRepoIsi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let ReverseRepoIsi { agreement_id } = self;
        let mut stored_agreement = state_transaction
            .world
            .repo_agreements
            .get(&agreement_id)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("repo agreement {agreement_id} is not active").into(),
                )
            })?;
        if !stored_agreement.is_active() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("repo agreement {agreement_id} has already settled").into(),
            ));
        }
        ensure_agreement_quantities(&stored_agreement)?;
        let initiator = stored_agreement.initiator().clone();
        let counterparty = stored_agreement.counterparty().clone();
        let is_initiator = authority == &initiator;
        let is_participant = is_initiator
            || authority == &counterparty
            || stored_agreement
                .custodian()
                .as_ref()
                .is_some_and(|custodian| custodian == authority);
        if !is_participant {
            return Err(InstructionExecutionError::InvariantViolation(
                "repo settlement must be submitted by a recorded participant".into(),
            ));
        }
        ensure_accounts(
            state_transaction,
            &initiator,
            &counterparty,
            stored_agreement.custodian().as_ref(),
        )?;
        let block_timestamp_ms = u64::try_from(
            state_transaction._curr_block.creation_time().as_millis(),
        )
        .map_err(|_| {
            InstructionExecutionError::InvariantViolation(
                "block creation time exceeds u64::MAX milliseconds".into(),
            )
        })?;
        let early_repayment = block_timestamp_ms < *stored_agreement.maturity_timestamp_ms();
        if early_repayment {
            // Only an agreement whose consented governance opted in can close
            // early, and only the borrower may shorten its own loan.
            if !stored_agreement.governance().allow_early_repayment() {
                return Err(InstructionExecutionError::InvariantViolation(
                    "repo agreement cannot settle before its recorded maturity".into(),
                ));
            }
            if !is_initiator {
                return Err(InstructionExecutionError::InvariantViolation(
                    "repo early repayment before maturity must be submitted by the initiator"
                        .into(),
                ));
            }
        }
        // Interest accrues to min(block time, maturity): an opted-in early
        // repayment pays only for the elapsed term, and a late submission
        // never accrues past the agreed maturity.
        let settlement_timestamp_ms =
            stored_agreement.effective_settlement_timestamp_ms(block_timestamp_ms);
        let cash_def_id = stored_agreement.cash_leg().asset_definition_id().clone();
        let cash_spec = state_transaction
            .numeric_spec_for(&cash_def_id)
            .map_err(Error::from)?;
        let expected_cash_quantity = expected_cash_settlement(
            stored_agreement.cash_leg().quantity(),
            *stored_agreement.rate_bps(),
            *stored_agreement.initiated_timestamp_ms(),
            settlement_timestamp_ms,
            cash_spec,
        )?;
        assert_numeric_spec_with(expected_cash_quantity.as_numeric(), cash_spec)?;
        let cash_destination = stored_agreement.cash_source().clone();
        let cash_source = asset_in_account_with_same_scope(&cash_destination, initiator.clone());
        let collateral_source = stored_agreement.collateral_custody_asset().clone();
        let collateral_destination =
            asset_in_account_with_same_scope(&collateral_source, initiator.clone());
        let collateral_leg = stored_agreement.collateral_leg().clone();
        let cash_leg =
            iroha_data_model::repo::RepoCashLeg::new(cash_def_id, expected_cash_quantity.clone());
        let movement = VerifiedRepoNumericPair::new(
            authority.clone(),
            &(agreement_id.clone(), settlement_timestamp_ms),
            [
                (cash_source, cash_destination, expected_cash_quantity),
                (
                    collateral_source,
                    collateral_destination,
                    collateral_leg.quantity().clone(),
                ),
            ],
        )?;
        crate::smartcontracts::isi::asset::isi::execute_verified_repo_numeric_pair(
            state_transaction,
            movement,
        )?;
        if !stored_agreement.settle(block_timestamp_ms) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("repo agreement {agreement_id} has already settled").into(),
            ));
        }
        state_transaction
            .world
            .insert_repo_agreement_entry(stored_agreement.clone());
        iroha_logger::info!(
            %agreement_id,
            initiator=%initiator,
            counterparty=%counterparty,
            custodian=?stored_agreement.custodian(),
            settlement_timestamp_ms,
            early_repayment,
            "repo agreement settled"
        );
        let mut repo_events = Vec::with_capacity(
            2_usize.saturating_add(usize::from(stored_agreement.custodian().is_some())),
        );
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::Settled(
            RepoAccountSettled::new(
                initiator.clone(),
                counterparty.clone(),
                agreement_id.clone(),
                cash_leg.clone(),
                collateral_leg.clone(),
                settlement_timestamp_ms,
                RepoAccountRole::Initiator,
            ),
        )));
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::Settled(
            RepoAccountSettled::new(
                counterparty.clone(),
                initiator.clone(),
                agreement_id.clone(),
                cash_leg.clone(),
                collateral_leg.clone(),
                settlement_timestamp_ms,
                RepoAccountRole::Counterparty,
            ),
        )));
        if let Some(custodian_account) = stored_agreement.custodian() {
            repo_events.push(AccountEvent::Repo(RepoAccountEvent::Settled(
                RepoAccountSettled::new(
                    custodian_account.clone(),
                    initiator.clone(),
                    agreement_id.clone(),
                    cash_leg.clone(),
                    collateral_leg,
                    settlement_timestamp_ms,
                    RepoAccountRole::Custodian,
                ),
            )));
        }
        state_transaction.world.emit_events(repo_events);
        Ok(())
    }
}
impl Execute for RepoMarginCallIsi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RepoMarginCallIsi { agreement_id } = self;
        let mut agreement = state_transaction
            .world
            .repo_agreements
            .get(&agreement_id)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!("repo agreement {agreement_id} is not active").into(),
                )
            })?;
        ensure_agreement_quantities(&agreement)?;
        if !agreement.is_active() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("repo agreement {agreement_id} has already settled").into(),
            ));
        }
        let is_authorised = authority == agreement.initiator()
            || authority == agreement.counterparty()
            || agreement
                .custodian()
                .as_ref()
                .is_some_and(|custodian| custodian == authority);
        if !is_authorised {
            return Err(InstructionExecutionError::InvariantViolation(
                "margin call must be initiated by a repo participant".into(),
            ));
        }
        if agreement.governance().margin_frequency_secs() == 0 {
            return Err(InstructionExecutionError::InvariantViolation(
                "margin checks are disabled for this agreement".into(),
            ));
        }
        let current_timestamp_ms = u64::try_from(
            state_transaction._curr_block.creation_time().as_millis(),
        )
        .map_err(|_| {
            InstructionExecutionError::InvariantViolation(
                "block creation time exceeds u64::MAX milliseconds".into(),
            )
        })?;
        if current_timestamp_ms >= *agreement.maturity_timestamp_ms() {
            return Err(InstructionExecutionError::InvariantViolation(
                "margin checks cannot be recorded at or after repo maturity".into(),
            ));
        }
        if !agreement.is_margin_check_due(current_timestamp_ms) {
            return Err(InstructionExecutionError::InvariantViolation(
                "margin check is not yet due for this agreement".into(),
            ));
        }
        agreement.record_margin_check(current_timestamp_ms);
        state_transaction
            .world
            .insert_repo_agreement_entry(agreement.clone());
        iroha_logger::info!(
            %agreement_id,
            initiator=%agreement.initiator(),
            counterparty=%agreement.counterparty(),
            custodian=?agreement.custodian(),
            margin_timestamp=current_timestamp_ms,
            "repo margin call recorded"
        );
        let mut repo_events = Vec::with_capacity(
            2_usize.saturating_add(usize::from(agreement.custodian().is_some())),
        );
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::MarginCalled(
            RepoAccountMarginCalled::new(
                agreement.initiator().clone(),
                agreement.counterparty().clone(),
                agreement_id.clone(),
                current_timestamp_ms,
                RepoAccountRole::Initiator,
            ),
        )));
        repo_events.push(AccountEvent::Repo(RepoAccountEvent::MarginCalled(
            RepoAccountMarginCalled::new(
                agreement.counterparty().clone(),
                agreement.initiator().clone(),
                agreement_id.clone(),
                current_timestamp_ms,
                RepoAccountRole::Counterparty,
            ),
        )));
        if let Some(custodian_account) = agreement.custodian().as_ref() {
            repo_events.push(AccountEvent::Repo(RepoAccountEvent::MarginCalled(
                RepoAccountMarginCalled::new(
                    custodian_account.clone(),
                    agreement.initiator().clone(),
                    agreement_id.clone(),
                    current_timestamp_ms,
                    RepoAccountRole::Custodian,
                ),
            )));
        }
        state_transaction.world.emit_events(repo_events);
        Ok(())
    }
}
/// Repo-related query implementations.
pub mod query {
    use super::*;
    use crate::{
        smartcontracts::ValidQuery,
        state::{StateReadOnly, WorldReadOnly},
    };
    use eyre::Result;
    use iroha_data_model::{
        account::AccountId,
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail as Error,
            json::PredicateJson,
            repo::prelude::FindRepoAgreements,
        },
        repo::{RepoAgreement, RepoAgreementId},
    };
    use iroha_telemetry::metrics;
    use norito::json::Value;
    use std::collections::BTreeSet;
    #[derive(Clone, Copy)]
    enum RepoAgreementAccountIndex {
        Initiator,
        Counterparty,
        Custodian,
    }
    fn repo_agreement_id_field(field: &str) -> bool {
        field == "id"
    }
    fn repo_agreement_account_index(field: &str) -> Option<RepoAgreementAccountIndex> {
        match field {
            "initiator" => Some(RepoAgreementAccountIndex::Initiator),
            "counterparty" => Some(RepoAgreementAccountIndex::Counterparty),
            "custodian" => Some(RepoAgreementAccountIndex::Custodian),
            _ => None,
        }
    }
    fn repo_agreement_id_from_value(value: &Value) -> Option<RepoAgreementId> {
        value
            .as_str()
            .and_then(|raw| raw.parse::<RepoAgreementId>().ok())
    }
    fn account_id_from_value(value: &Value) -> Option<AccountId> {
        value
            .as_str()
            .and_then(|raw| AccountId::parse_encoded(raw).ok())
    }
    fn intersect_candidate_ids(
        best: &mut Option<BTreeSet<RepoAgreementId>>,
        candidates: BTreeSet<RepoAgreementId>,
    ) {
        let Some(current) = best.take() else {
            *best = Some(candidates);
            return;
        };
        *best = Some(current.intersection(&candidates).cloned().collect());
    }
    fn ids_for_accounts(
        world: &impl WorldReadOnly,
        index: RepoAgreementAccountIndex,
        accounts: impl IntoIterator<Item = AccountId>,
    ) -> BTreeSet<RepoAgreementId> {
        let mut ids = BTreeSet::new();
        for account_id in accounts {
            let agreements = match index {
                RepoAgreementAccountIndex::Initiator => {
                    world.repo_agreements_by_initiator().get(&account_id)
                }
                RepoAgreementAccountIndex::Counterparty => {
                    world.repo_agreements_by_counterparty().get(&account_id)
                }
                RepoAgreementAccountIndex::Custodian => {
                    world.repo_agreements_by_custodian().get(&account_id)
                }
            };
            if let Some(agreements) = agreements {
                ids.extend(agreements.iter().cloned());
            }
        }
        ids
    }
    pub(super) fn repo_agreement_candidate_ids(
        predicate: &PredicateJson,
        world: &impl WorldReadOnly,
    ) -> Option<BTreeSet<RepoAgreementId>> {
        let mut best = None;
        for cond in &predicate.equals {
            if repo_agreement_id_field(&cond.field) {
                intersect_candidate_ids(
                    &mut best,
                    repo_agreement_id_from_value(&cond.value)
                        .into_iter()
                        .collect(),
                );
                continue;
            }
            if let Some(index) = repo_agreement_account_index(&cond.field) {
                intersect_candidate_ids(
                    &mut best,
                    ids_for_accounts(world, index, account_id_from_value(&cond.value)),
                );
            }
        }
        for cond in &predicate.r#in {
            if repo_agreement_id_field(&cond.field) {
                intersect_candidate_ids(
                    &mut best,
                    cond.values
                        .iter()
                        .filter_map(repo_agreement_id_from_value)
                        .collect(),
                );
                continue;
            }
            if let Some(index) = repo_agreement_account_index(&cond.field) {
                intersect_candidate_ids(
                    &mut best,
                    ids_for_accounts(
                        world,
                        index,
                        cond.values.iter().filter_map(account_id_from_value),
                    ),
                );
            }
        }
        best
    }
    impl ValidQuery for FindRepoAgreements {
        #[metrics(+"find_repo_agreements")]
        fn execute(
            self,
            filter: CompoundPredicate<RepoAgreement>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = RepoAgreement>, Error> {
            let world = state_ro.world();
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            if let Some(candidate_ids) = predicate_json
                .as_ref()
                .and_then(|predicate| repo_agreement_candidate_ids(predicate, world))
            {
                let iter: Box<dyn Iterator<Item = RepoAgreement> + '_> =
                    Box::new(candidate_ids.into_iter().filter_map(move |id| {
                        world
                            .repo_agreements()
                            .get(&id)
                            .filter(|agreement| filter.applies(*agreement))
                            .cloned()
                    }));
                return Ok(iter);
            }
            let iter: Box<dyn Iterator<Item = RepoAgreement> + '_> = Box::new(
                world
                    .repo_agreements()
                    .iter()
                    .filter(move |&(_, agreement)| filter.applies(agreement))
                    .map(|(_, agreement)| agreement.clone()),
            );
            Ok(iter)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura, prelude::World, query::store::LiveQueryStore, smartcontracts::ValidQuery,
        state::State,
    };
    use hex::encode_upper;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::{Account, AccountId},
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition,
            AssetTransferAvailability, AssetTransferControlRecord,
            prelude::{AssetDefinitionId, AssetId},
        },
        block::BlockHeader,
        domain::Domain,
        events::data::prelude::{AccountEvent, DataEvent, RepoAccountEvent, RepoAccountRole},
        isi::{InstructionBox, error::AssetTransferAdmissionError, repo::RepoInstructionBox},
        permission::Permission,
        query::{dsl::CompoundPredicate, repo::prelude::FindRepoAgreements},
        repo::{RepoAgreement, RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
    };
    use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;
    use norito::json::{Map, Number, Value};
    #[test]
    fn repo_numeric_capability_preserves_typed_consent_and_maturity_frames() {
        use iroha_data_model::isi::settlement::SettlementId;
        let (_state, agreement, cash, collateral) = setup_state();
        let legs = [
            (
                AssetId::new(cash.clone(), ALICE_ID.clone()),
                AssetId::new(cash, BOB_ID.clone()),
                Quantity::from(10_u32),
            ),
            (
                AssetId::new(collateral.clone(), BOB_ID.clone()),
                AssetId::new(collateral, ALICE_ID.clone()),
                Quantity::from(12_u32),
            ),
        ];
        let settlement = SettlementId::new(ALICE_ID.clone(), "consent_trade".parse().unwrap());
        let initiation = (
            settlement,
            Hash::new(b"initiation-consent"),
            Hash::new(b"maturity-consent"),
        );
        let pair =
            VerifiedRepoNumericPair::new(ALICE_ID.clone(), &initiation, legs.clone()).unwrap();
        let (authority, binding, retained_legs) = pair.into_parts();
        assert_eq!(authority, *ALICE_ID);
        assert_eq!(retained_legs, legs);
        assert_eq!(
            norito::decode_canonical::<(SettlementId, Hash, Hash)>(&binding).unwrap(),
            initiation
        );
        assert_eq!(binding, norito::encode_canonical(&initiation).unwrap());
        assert!(matches!(
            norito::decode_canonical::<(RepoAgreementId, Hash, Hash)>(&binding),
            Err(norito::Error::SchemaMismatch)
        ));
        let mut different_consent = initiation.clone();
        different_consent.2 = Hash::new(b"other-maturity-consent");
        let (_, changed, _) =
            VerifiedRepoNumericPair::new(ALICE_ID.clone(), &different_consent, legs.clone())
                .unwrap()
                .into_parts();
        assert_ne!(Hash::new(&binding), Hash::new(&changed));
        assert!(
            norito::decode_canonical::<(SettlementId, Hash, Hash)>(&binding[..binding.len() - 1])
                .is_err()
        );
        let maturity = (agreement, 1_700_000_000_000_u64);
        let (_, binding, retained_legs) =
            VerifiedRepoNumericPair::new(ALICE_ID.clone(), &maturity, legs.clone())
                .unwrap()
                .into_parts();
        assert_eq!(retained_legs, legs);
        assert_eq!(
            norito::decode_canonical::<(RepoAgreementId, u64)>(&binding).unwrap(),
            maturity
        );
        assert!(matches!(
            norito::decode_canonical::<(SettlementId, u64)>(&binding),
            Err(norito::Error::SchemaMismatch)
        ));
        let (_, later, _) =
            VerifiedRepoNumericPair::new(ALICE_ID.clone(), &(maturity.0, maturity.1 + 1), legs)
                .unwrap()
                .into_parts();
        assert_ne!(Hash::new(&binding), Hash::new(&later));
    }
    fn checked_account_id() -> AccountId {
        let key_pair = KeyPair::try_random().expect("repo fixture key generation should succeed");
        AccountId::new(key_pair.public_key().clone())
    }
    #[test]
    fn checked_account_id_preserves_default_algorithm() {
        let account_id = checked_account_id();
        assert_eq!(
            account_id.expect_single_signatory().algorithm(),
            Algorithm::default()
        );
    }
    #[test]
    fn repo_quantity_boundaries_reject_negative_and_zero_values() {
        assert!(Quantity::try_from_numeric(Numeric::new(-1_i32, 0)).is_err());
        let error = ensure_positive_quantity(&Quantity::zero(), "repo cash quantity")
            .expect_err("zero repo quantity must be rejected");
        assert!(matches!(
            error,
            InstructionExecutionError::InvariantViolation(_)
        ));
    }
    fn setup_state() -> (State, RepoAgreementId, AssetDefinitionId, AssetDefinitionId) {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob_account = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let cash_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            );
        let collateral_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            );
        let cash_def = {
            let __asset_definition_id = cash_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let collateral_def = {
            let __asset_definition_id = collateral_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let bob_cash = Asset::new(
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
            Quantity::from(2_000u32),
        );
        let alice_collateral = Asset::new(
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(1_500u32),
        );
        let world = World::with_assets(
            [domain],
            [alice_account, bob_account],
            [cash_def, collateral_def],
            [bob_cash, alice_collateral],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        let agreement_id: RepoAgreementId = "daily_repo".parse().unwrap();
        (state, agreement_id, cash_def_id, collateral_def_id)
    }
    fn setup_state_with_custodian() -> (
        State,
        RepoAgreementId,
        AssetDefinitionId,
        AssetDefinitionId,
        AccountId,
    ) {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob_account = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let custodian_id = checked_account_id();
        let custodian_account = Account::new(custodian_id.clone()).build(&ALICE_ID);
        let cash_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            );
        let collateral_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            );
        let cash_def = {
            let __asset_definition_id = cash_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let collateral_def = {
            let __asset_definition_id = collateral_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let bob_cash = Asset::new(
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
            Quantity::from(2_000u32),
        );
        let alice_collateral = Asset::new(
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(1_500u32),
        );
        let world = World::with_assets(
            [domain],
            [alice_account, bob_account, custodian_account],
            [cash_def, collateral_def],
            [bob_cash, alice_collateral],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        let agreement_id: RepoAgreementId = "daily_repo".parse().unwrap();
        (
            state,
            agreement_id,
            cash_def_id,
            collateral_def_id,
            custodian_id,
        )
    }
    fn repo_setup_instruction(
        agreement_id: &RepoAgreementId,
        cash_def_id: &AssetDefinitionId,
        collateral_def_id: &AssetDefinitionId,
    ) -> RepoIsi {
        repo_setup_instruction_with_maturity(
            agreement_id,
            cash_def_id,
            collateral_def_id,
            1_704_000_000_000 + MS_PER_DAY,
        )
    }
    fn repo_setup_instruction_with_maturity(
        agreement_id: &RepoAgreementId,
        cash_def_id: &AssetDefinitionId,
        collateral_def_id: &AssetDefinitionId,
        maturity_timestamp_ms: u64,
    ) -> RepoIsi {
        RepoIsi::new(
            agreement_id.clone(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
            None,
            RepoCashLeg {
                asset_definition_id: cash_def_id.clone(),
                quantity: Quantity::from(1_000u32),
            },
            RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1_100u32)),
            250,
            maturity_timestamp_ms,
            RepoGovernance::new(1_500, 86_400, false),
        )
    }
    fn seed_repo_consents(stx: &mut StateTransaction<'_, '_>, instruction: &RepoIsi) {
        let holder = instruction
            .custodian()
            .as_ref()
            .unwrap_or_else(|| instruction.counterparty());
        seed_repo_consents_for_assets(
            stx,
            instruction,
            AssetId::new(
                instruction.cash_leg().asset_definition_id().clone(),
                instruction.counterparty().clone(),
            ),
            AssetId::new(
                instruction.collateral_leg().asset_definition_id().clone(),
                holder.clone(),
            ),
        );
    }
    fn seed_repo_consents_for_assets(
        stx: &mut StateTransaction<'_, '_>,
        instruction: &RepoIsi,
        cash_source: AssetId,
        collateral_custody_asset: AssetId,
    ) {
        let settlement_id = instruction.settlement_id();
        let consents = [
            Permission::from(CanExecuteSettlement {
                debited_asset: cash_source,
                settlement_id: settlement_id.clone(),
                intent_hash: instruction.initiation_intent_hash(),
            }),
            Permission::from(CanExecuteSettlement {
                debited_asset: collateral_custody_asset,
                settlement_id,
                intent_hash: instruction.maturity_intent_hash(),
            }),
        ];
        let mut permissions = stx
            .world
            .account_permissions
            .get(instruction.initiator())
            .cloned()
            .unwrap_or_default();
        permissions.extend(consents);
        stx.world
            .account_permissions
            .insert(instruction.initiator().clone(), permissions);
    }
    fn execute_repo_with_consents(
        stx: &mut StateTransaction<'_, '_>,
        instruction: RepoIsi,
    ) -> Result<(), Error> {
        seed_repo_consents(stx, &instruction);
        instruction.execute(&ALICE_ID, stx)
    }
    fn repo_asset_balance(stx: &StateTransaction<'_, '_>, asset_id: &AssetId) -> Quantity {
        stx.world
            .assets
            .get(asset_id)
            .map_or_else(Quantity::zero, |asset| (**asset).clone())
    }
    #[test]
    fn repo_numeric_pair_requires_a_retained_component_invocation() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let instruction = repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        let bob_cash = AssetId::new(cash_def_id, BOB_ID.clone());
        let alice_collateral = AssetId::new(collateral_def_id, ALICE_ID.clone());
        {
            let mut unowned = block.transaction();
            seed_repo_consents(&mut unowned, &instruction);
            let error = instruction
                .clone()
                .execute(&ALICE_ID, &mut unowned)
                .expect_err("bilateral consent does not invent the invocation source");
            assert!(
                error
                    .to_string()
                    .contains("protocol source has no authenticated mandatory owner")
            );
            assert_eq!(
                repo_asset_balance(&unowned, &bob_cash),
                Quantity::from(2_000_u32)
            );
            assert_eq!(
                repo_asset_balance(&unowned, &alice_collateral),
                Quantity::from(1_500_u32)
            );
            assert!(unowned.world.repo_agreements.get(&agreement_id).is_none());
        }
        // A refused source poisons its disposable block owner. Start the positive
        // control from an independent component block over the unchanged State.
        drop(block);
        let mut block = state.block(header);
        // The explicit finite callback fixture retains the original direct-execution slot.
        // It authenticates neither a signed Network input nor block publication.
        let mut owned = block.transaction_for_callback_testing();
        execute_repo_with_consents(&mut owned, instruction).expect("retained numeric component");
        assert!(owned.world.repo_agreements.get(&agreement_id).is_some());
    }
    #[test]
    fn repo_open_requires_exact_consents_for_unchanged_terms() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let instruction = repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        let bob_cash = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
        let alice_collateral = AssetId::new(collateral_def_id, ALICE_ID.clone());
        let error = instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect_err("an initiator cannot debit a counterparty without exact consent");
        assert!(error.to_string().contains("exact consent"));
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500_u32)
        );
        assert!(stx.world.repo_agreements.get(&agreement_id).is_none());
        seed_repo_consents(&mut stx, &instruction);
        let mut changed_terms = instruction.clone();
        changed_terms.cash_leg.quantity = Quantity::from(1_001_u32);
        let error = changed_terms
            .execute(&ALICE_ID, &mut stx)
            .expect_err("changing any economic term requires new bilateral consent");
        assert!(error.to_string().contains("exact consent"));
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500_u32)
        );
        assert!(stx.world.repo_agreements.get(&agreement_id).is_none());
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("the byte-identical consented proposal must open");
    }
    #[test]
    fn repo_open_is_atomic_when_second_leg_cannot_settle() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let mut instruction =
            repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        instruction.collateral_leg.quantity = Quantity::from(1_501_u32);
        seed_repo_consents(&mut stx, &instruction);
        let bob_cash = AssetId::new(cash_def_id, BOB_ID.clone());
        let alice_collateral = AssetId::new(collateral_def_id, ALICE_ID.clone());
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("insufficient collateral must reject the entire pair");
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500_u32)
        );
        assert!(stx.world.repo_agreements.get(&agreement_id).is_none());
        assert!(
            stx.world
                .internal_event_buf
                .iter()
                .all(|event| !matches!(event.as_ref(), DataEvent::Account(AccountEvent::Repo(_)))),
            "a rejected pair must not emit repo lifecycle events"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn repo_uses_only_the_exact_consent_selected_dataspace_balances() {
        let cash_scope = DataSpaceId::new(11);
        let collateral_scope = DataSpaceId::new(7);
        let wrong_cash_scope = DataSpaceId::new(19);
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain");
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let cash_def_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "usd".parse().expect("cash name"),
        );
        let collateral_def_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "bond".parse().expect("collateral name"),
        );
        let cash_definition = AssetDefinition::numeric(
            cash_def_id.clone(),
            "usd".to_owned(),
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain_id.clone()),
        )
        .build(&ALICE_ID);
        let collateral_definition = AssetDefinition::numeric(
            collateral_def_id.clone(),
            "bond".to_owned(),
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain_id),
        )
        .build(&ALICE_ID);
        let bob_cash = AssetId::with_scope(
            cash_def_id.clone(),
            BOB_ID.clone(),
            AssetBalanceScope::Dataspace(cash_scope),
        );
        let alice_collateral = AssetId::with_scope(
            collateral_def_id.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(collateral_scope),
        );
        let world = World::with_assets(
            [domain],
            [alice, bob],
            [cash_definition, collateral_definition],
            [
                Asset::new(bob_cash.clone(), Quantity::from(2_000_u32)),
                Asset::new(alice_collateral.clone(), Quantity::from(1_500_u32)),
            ],
            [],
        );
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let wrong_id: RepoAgreementId = "wrong_scope_repo".parse().expect("agreement id");
        let wrong_instruction = repo_setup_instruction(&wrong_id, &cash_def_id, &collateral_def_id);
        let wrong_cash = AssetId::with_scope(
            cash_def_id.clone(),
            BOB_ID.clone(),
            AssetBalanceScope::Dataspace(wrong_cash_scope),
        );
        let collateral_custody = AssetId::with_scope(
            collateral_def_id.clone(),
            BOB_ID.clone(),
            AssetBalanceScope::Dataspace(collateral_scope),
        );
        seed_repo_consents_for_assets(
            &mut stx,
            &wrong_instruction,
            wrong_cash.clone(),
            collateral_custody.clone(),
        );
        wrong_instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("an unfunded consent scope must not discover another balance");
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500_u32)
        );
        assert_eq!(repo_asset_balance(&stx, &wrong_cash), Quantity::zero());
        assert!(stx.world.repo_agreements.get(&wrong_id).is_none());
        let agreement_id: RepoAgreementId = "exact_scope_repo".parse().expect("agreement id");
        let instruction = repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        seed_repo_consents_for_assets(
            &mut stx,
            &instruction,
            bob_cash.clone(),
            collateral_custody.clone(),
        );
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("the two exact consent-selected scopes must settle");
        let agreement = stx
            .world
            .repo_agreements
            .get(&agreement_id)
            .expect("agreement stored");
        assert_eq!(agreement.cash_source(), &bob_cash);
        assert_eq!(agreement.collateral_custody_asset(), &collateral_custody);
        assert_eq!(
            repo_asset_balance(
                &stx,
                &AssetId::with_scope(
                    cash_def_id,
                    ALICE_ID.clone(),
                    AssetBalanceScope::Dataspace(cash_scope),
                ),
            ),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &collateral_custody),
            Quantity::from(1_100_u32)
        );
        assert_eq!(repo_asset_balance(&stx, &wrong_cash), Quantity::zero());
    }
    #[test]
    fn repo_initiation_transfers_assets_and_records_agreement() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let repo_instruction =
            repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        execute_repo_with_consents(&mut stx, repo_instruction).expect("repo execution");
        let mut initiator_event = None;
        let mut counterparty_event = None;
        let mut custodian_event = None;
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Initiated(payload))) =
                event.as_ref()
            {
                match payload.role {
                    RepoAccountRole::Initiator => initiator_event = Some(payload.clone()),
                    RepoAccountRole::Counterparty => counterparty_event = Some(payload.clone()),
                    RepoAccountRole::Custodian => custodian_event = Some(payload.clone()),
                }
            }
        }
        let initiator_event =
            initiator_event.expect("initiator should receive a repo initiation event");
        let counterparty_event =
            counterparty_event.expect("counterparty should receive a repo initiation event");
        assert_eq!(initiator_event.account.clone(), ALICE_ID.clone());
        assert_eq!(initiator_event.counterparty.clone(), BOB_ID.clone());
        assert_eq!(initiator_event.agreement.id(), &agreement_id);
        assert_eq!(initiator_event.role, RepoAccountRole::Initiator);
        assert_eq!(counterparty_event.account.clone(), BOB_ID.clone());
        assert_eq!(counterparty_event.counterparty.clone(), ALICE_ID.clone());
        assert_eq!(counterparty_event.agreement.id(), &agreement_id);
        assert_eq!(counterparty_event.role, RepoAccountRole::Counterparty);
        assert!(
            custodian_event.is_none(),
            "custodian should be absent in two-party repo"
        );
        assert!(stx.world.repo_agreements.get(&agreement_id).is_some());
        let recorded = stx
            .world
            .repo_agreements
            .get(&agreement_id)
            .expect("agreement");
        assert_eq!(recorded.initiated_timestamp_ms, 0);
        let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        let bob_cash_id = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx.world.assets.get(&alice_cash_id).expect("alice cash"),
            Quantity::from(1_000u32)
        );
        assert_eq!(
            **stx.world.assets.get(&bob_cash_id).expect("bob cash"),
            Quantity::from(1_000u32)
        );
        let alice_collateral_id = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
        let bob_collateral_id = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_collateral_id)
                .expect("alice collateral"),
            Quantity::from(400u32)
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&bob_collateral_id)
                .expect("bob collateral"),
            Quantity::from(1_100u32)
        );
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit succeeds");
        let view = state.view();
        assert!(view.world.repo_agreements().get(&agreement_id).is_some());
    }
    #[test]
    fn find_repo_agreements_uses_id_predicate_lookup() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        execute_repo_with_consents(
            &mut stx,
            repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id),
        )
        .expect("repo execution");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit succeeds");
        let view = state.view();
        let predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
            predicate.equals("id", agreement_id.to_string())
        });
        let found = FindRepoAgreements
            .execute(predicate, &view)
            .expect("query repo agreements")
            .map(|agreement| agreement.id)
            .collect::<Vec<_>>();
        assert_eq!(found, vec![agreement_id.clone()]);
        let missing: RepoAgreementId = "missing_repo".parse().unwrap();
        let predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
            predicate.in_values("id", [agreement_id.to_string(), missing.to_string()])
        });
        let found = FindRepoAgreements
            .execute(predicate, &view)
            .expect("query repo agreements by id set")
            .map(|agreement| agreement.id)
            .collect::<Vec<_>>();
        assert_eq!(found, vec![agreement_id]);
    }
    #[test]
    fn find_repo_agreements_uses_participant_indexes() {
        let (state, agreement_id, cash_def_id, collateral_def_id, custodian_id) =
            setup_state_with_custodian();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let instruction = RepoIsi::new(
            agreement_id.clone(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
            Some(custodian_id.clone()),
            RepoCashLeg {
                asset_definition_id: cash_def_id.clone(),
                quantity: Quantity::from(1_000u32),
            },
            RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1_100u32)),
            250,
            1_704_000_000_000,
            RepoGovernance::new(1_500, 86_400, false),
        );
        execute_repo_with_consents(&mut stx, instruction).expect("repo execution");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit succeeds");
        let view = state.view();
        assert!(
            view.world
                .repo_agreements_by_initiator()
                .get(&ALICE_ID)
                .is_some_and(|agreements| agreements.contains(&agreement_id))
        );
        assert!(
            view.world
                .repo_agreements_by_counterparty()
                .get(&BOB_ID)
                .is_some_and(|agreements| agreements.contains(&agreement_id))
        );
        assert!(
            view.world
                .repo_agreements_by_custodian()
                .get(&custodian_id)
                .is_some_and(|agreements| agreements.contains(&agreement_id))
        );
        for (field, account_id) in [
            ("initiator", ALICE_ID.clone()),
            ("counterparty", BOB_ID.clone()),
            ("custodian", custodian_id.clone()),
        ] {
            let predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
                predicate.equals(field, account_id.to_string())
            });
            let found = FindRepoAgreements
                .execute(predicate, &view)
                .expect("query repo agreements by participant")
                .map(|agreement| agreement.id)
                .collect::<Vec<_>>();
            assert_eq!(found, vec![agreement_id.clone()]);
        }
        let missing_predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
            predicate.equals("initiator", custodian_id.to_string())
        });
        assert_eq!(
            FindRepoAgreements
                .execute(missing_predicate, &view)
                .expect("query repo agreements by missing participant")
                .count(),
            0
        );
        drop(view);
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        stx.world.remove_repo_agreement_entry(&agreement_id);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit succeeds");
        let view = state.view();
        assert!(
            view.world
                .repo_agreements_by_initiator()
                .get(&ALICE_ID)
                .is_none()
        );
        let predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
            predicate.equals("initiator", ALICE_ID.to_string())
        });
        assert_eq!(
            FindRepoAgreements
                .execute(predicate, &view)
                .expect("query removed repo agreements by participant")
                .count(),
            0
        );
    }
    #[test]
    fn repo_agreement_candidates_intersect_participant_indexes() {
        let (state, target_id, cash_def_id, collateral_def_id, custodian_id) =
            setup_state_with_custodian();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let make_agreement =
            |id: RepoAgreementId, initiator: AccountId, counterparty: AccountId| {
                RepoAgreement::new(
                    id,
                    initiator.clone(),
                    counterparty.clone(),
                    RepoCashLeg {
                        asset_definition_id: cash_def_id.clone(),
                        quantity: Quantity::from(1_000u32),
                    },
                    AssetId::new(cash_def_id.clone(), counterparty.clone()),
                    RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1_100u32)),
                    AssetId::new(collateral_def_id.clone(), counterparty),
                    250,
                    1_704_000_000_000,
                    0,
                    RepoGovernance::new(1_500, 86_400, false),
                    None,
                )
            };
        let same_initiator_id: RepoAgreementId = "same_initiator".parse().unwrap();
        let same_counterparty_id: RepoAgreementId = "same_counterparty".parse().unwrap();
        for agreement in [
            make_agreement(target_id.clone(), ALICE_ID.clone(), BOB_ID.clone()),
            make_agreement(same_initiator_id, ALICE_ID.clone(), custodian_id.clone()),
            make_agreement(same_counterparty_id, custodian_id, BOB_ID.clone()),
        ] {
            stx.world.insert_repo_agreement_entry(agreement);
        }
        let predicate = CompoundPredicate::<RepoAgreement>::build(|predicate| {
            predicate
                .equals("initiator", ALICE_ID.to_string())
                .equals("counterparty", BOB_ID.to_string())
        });
        let predicate_json = predicate
            .json_payload()
            .and_then(|raw| {
                norito::json::from_str::<iroha_data_model::query::json::PredicateJson>(raw).ok()
            })
            .expect("predicate JSON");
        let candidate_ids = query::repo_agreement_candidate_ids(&predicate_json, &stx.world)
            .expect("indexed candidates");
        assert_eq!(candidate_ids, std::collections::BTreeSet::from([target_id]));
    }
    #[test]
    fn repo_instruction_box_executes_via_instruction_dispatch() {
        let (component, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let state = crate::pipeline::overlay::test_support::state_after_genesis(component.world);
        let parent = state
            .view()
            .latest_block_hash()
            .expect("original genesis parent");
        let header = BlockHeader::new(nonzero!(2_u64), Some(parent), None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let repo_instruction =
            repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        seed_repo_consents(&mut stx, &repo_instruction);
        let boxed: InstructionBox = RepoInstructionBox::from(repo_instruction).into();
        boxed
            .execute(&ALICE_ID, &mut stx)
            .expect("repo instruction box execution");
        assert!(
            stx.world.repo_agreements.get(&agreement_id).is_some(),
            "repo instruction box should record the agreement"
        );
    }
    #[test]
    fn repo_initiation_with_custodian_routes_collateral() {
        let (state, agreement_id, cash_def_id, collateral_def_id, custodian_id) =
            setup_state_with_custodian();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let repo_instruction = RepoIsi::new(
            agreement_id.clone(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
            Some(custodian_id.clone()),
            RepoCashLeg {
                asset_definition_id: cash_def_id.clone(),
                quantity: Quantity::from(1_000u32),
            },
            RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1_100u32)),
            250,
            1_704_000_000_000,
            RepoGovernance::new(1_500, 86_400, false),
        );
        execute_repo_with_consents(&mut stx, repo_instruction).expect("repo execution");
        let mut roles = Vec::new();
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Initiated(payload))) =
                event.as_ref()
            {
                roles.push((payload.account.clone(), payload.role));
                if payload.role == RepoAccountRole::Custodian {
                    assert_eq!(&payload.account, &custodian_id);
                    assert_eq!(&payload.counterparty, &*ALICE_ID);
                }
            }
        }
        assert!(roles.contains(&(ALICE_ID.clone(), RepoAccountRole::Initiator)));
        assert!(roles.contains(&(BOB_ID.clone(), RepoAccountRole::Counterparty)));
        assert!(roles.contains(&(custodian_id.clone(), RepoAccountRole::Custodian)));
        let custodian_collateral_id = AssetId::new(collateral_def_id.clone(), custodian_id.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&custodian_collateral_id)
                .expect("custodian collateral"),
            Quantity::from(1_100u32)
        );
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit succeeds");
        let view = state.view();
        let stored = view
            .world
            .repo_agreements()
            .get(&agreement_id)
            .expect("agreement stored");
        assert_eq!(stored.custodian(), &Some(custodian_id));
    }
    #[test]
    fn reverse_repo_rejects_pre_maturity_without_mutating_state() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms = 1_704_000_000_000_u64;
        let maturity_ms = initiation_ms + super::MS_PER_DAY;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            execute_repo_with_consents(
                &mut stx,
                repo_setup_instruction_with_maturity(
                    &agreement_id,
                    &cash_def_id,
                    &collateral_def_id,
                    maturity_ms,
                ),
            )
            .expect("repo opens");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let header = BlockHeader::new(nonzero!(2_u64), None, None, maturity_ms - 1, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let alice_cash = AssetId::new(cash_def_id, ALICE_ID.clone());
        let bob_collateral = AssetId::new(collateral_def_id, BOB_ID.clone());
        let cash_before = repo_asset_balance(&stx, &alice_cash);
        let collateral_before = repo_asset_balance(&stx, &bob_collateral);
        let error = ReverseRepoIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("fixed-maturity settlement must reject an early unwind");
        assert!(error.to_string().contains("before its recorded maturity"));
        assert_eq!(repo_asset_balance(&stx, &alice_cash), cash_before);
        assert_eq!(repo_asset_balance(&stx, &bob_collateral), collateral_before);
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(RepoAgreement::is_active)
        );
    }
    /// Open an opted-in early-repayment agreement and commit it.
    fn open_early_repayment_repo(
        state: &State,
        agreement_id: &RepoAgreementId,
        cash_def_id: &AssetDefinitionId,
        collateral_def_id: &AssetDefinitionId,
        initiation_ms: u64,
        maturity_ms: u64,
    ) {
        let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let mut instruction = repo_setup_instruction_with_maturity(
            agreement_id,
            cash_def_id,
            collateral_def_id,
            maturity_ms,
        );
        instruction.governance = RepoGovernance::new(1_500, 86_400, true);
        execute_repo_with_consents(&mut stx, instruction).expect("opted-in repo opens");
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
    }
    #[test]
    fn reverse_repo_early_repayment_pays_exact_accrued_interest_and_returns_collateral() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms = 1_704_000_000_000_u64;
        let maturity_ms = initiation_ms + 30 * super::MS_PER_DAY;
        let repayment_ms = initiation_ms + super::MS_PER_DAY / 2;
        open_early_repayment_repo(
            &state,
            &agreement_id,
            &cash_def_id,
            &collateral_def_id,
            initiation_ms,
            maturity_ms,
        );
        let header = BlockHeader::new(nonzero!(2_u64), None, None, repayment_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let cash_spec = stx.numeric_spec_for(&cash_def_id).expect("cash spec");
        let principal = Quantity::from(1_000u32);
        // ACT/360 for 12 hours at 250 bps, each step rounded toward zero:
        // 0.025 * 0.001388888888888888 * 1000.
        let interest =
            super::compute_accrued_interest(&principal, 250, super::MS_PER_DAY / 2, cash_spec)
                .expect("half-day interest");
        assert_eq!(
            interest,
            Quantity::try_from_numeric(Numeric::new(34_722_222_222_222_u64, 15))
                .expect("exact accrued interest")
        );
        let full_term_interest =
            super::compute_accrued_interest(&principal, 250, 30 * super::MS_PER_DAY, cash_spec)
                .expect("full-term interest");
        assert!(interest < full_term_interest);
        let alice_cash = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        let bob_cash = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
        let alice_collateral = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
        let bob_collateral = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
        crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
            &mut stx.world,
            &alice_cash,
            &interest,
        )
        .expect("seed accrued interest");
        ReverseRepoIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("the opted-in borrower repays early");
        let expected_repayment = principal.checked_add(&interest).expect("repayment");
        assert_eq!(repo_asset_balance(&stx, &alice_cash), Quantity::zero());
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(1_000u32)
                .checked_add(&expected_repayment)
                .expect("counterparty cash")
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500u32)
        );
        assert_eq!(repo_asset_balance(&stx, &bob_collateral), Quantity::zero());
        let settled = stx
            .world
            .repo_agreements
            .get(&agreement_id)
            .cloned()
            .expect("settled tombstone");
        assert!(!settled.is_active());
        assert_eq!(settled.settlement_timestamp_ms(), &Some(repayment_ms));
        let settled_events = stx
            .world
            .internal_event_buf
            .iter()
            .filter_map(|event| match event.as_ref() {
                DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Settled(payload))) => {
                    Some(payload.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(settled_events.len(), 2);
        for event in settled_events {
            assert_eq!(event.cash_leg().quantity(), &expected_repayment);
            assert_eq!(event.settled_timestamp_ms(), &repayment_ms);
        }
    }
    #[test]
    fn reverse_repo_early_repayment_rejects_non_borrower_participants() {
        let (state, agreement_id, cash_def_id, collateral_def_id, custodian) =
            setup_state_with_custodian();
        let initiation_ms = 1_704_000_000_000_u64;
        let maturity_ms = initiation_ms + super::MS_PER_DAY;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let mut instruction = repo_setup_instruction_with_maturity(
                &agreement_id,
                &cash_def_id,
                &collateral_def_id,
                maturity_ms,
            );
            instruction.custodian = Some(custodian.clone());
            instruction.governance = RepoGovernance::new(1_500, 86_400, true);
            execute_repo_with_consents(&mut stx, instruction).expect("tri-party repo opens");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let header = BlockHeader::new(nonzero!(2_u64), None, None, maturity_ms - 1, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let alice_cash = AssetId::new(cash_def_id, ALICE_ID.clone());
        let custody_collateral = AssetId::new(collateral_def_id, custodian.clone());
        let cash_before = repo_asset_balance(&stx, &alice_cash);
        let collateral_before = repo_asset_balance(&stx, &custody_collateral);
        for participant in [BOB_ID.clone(), custodian] {
            let error = ReverseRepoIsi::new(agreement_id.clone())
                .execute(&participant, &mut stx)
                .expect_err("only the borrower may repay early");
            assert!(
                error
                    .to_string()
                    .contains("early repayment before maturity must be submitted by the initiator"),
                "{error}"
            );
        }
        assert_eq!(repo_asset_balance(&stx, &alice_cash), cash_before);
        assert_eq!(
            repo_asset_balance(&stx, &custody_collateral),
            collateral_before
        );
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(RepoAgreement::is_active)
        );
    }
    #[test]
    fn opted_in_repo_settles_at_maturity_unchanged_when_submitted_late() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms = 1_704_000_000_000_u64;
        let maturity_ms = initiation_ms + super::MS_PER_DAY;
        open_early_repayment_repo(
            &state,
            &agreement_id,
            &cash_def_id,
            &collateral_def_id,
            initiation_ms,
            maturity_ms,
        );
        let late_ms = maturity_ms + 5 * super::MS_PER_DAY;
        let header = BlockHeader::new(nonzero!(2_u64), None, None, late_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let cash_spec = stx.numeric_spec_for(&cash_def_id).expect("cash spec");
        let expected_cash = super::expected_cash_settlement(
            &Quantity::from(1_000u32),
            250,
            initiation_ms,
            maturity_ms,
            cash_spec,
        )
        .expect("maturity repayment");
        let interest = expected_cash
            .checked_sub(&Quantity::from(1_000u32))
            .expect("interest");
        let alice_cash = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
            &mut stx.world,
            &alice_cash,
            &interest,
        )
        .expect("seed maturity interest");
        // At or after maturity the counterparty may settle an opted-in agreement too.
        ReverseRepoIsi::new(agreement_id.clone())
            .execute(&BOB_ID, &mut stx)
            .expect("maturity settlement by the counterparty");
        assert_eq!(
            repo_asset_balance(&stx, &AssetId::new(cash_def_id, BOB_ID.clone())),
            Quantity::from(1_000u32)
                .checked_add(&expected_cash)
                .expect("counterparty cash")
        );
        assert_eq!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .and_then(|agreement| *agreement.settlement_timestamp_ms()),
            Some(maturity_ms),
            "interest and the tombstone never extend past maturity"
        );
    }
    #[test]
    fn repo_open_respects_counterparty_cash_freeze() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let instruction = repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
        seed_repo_consents(&mut stx, &instruction);
        let mut control = AssetTransferControlRecord::new(cash_def_id.clone());
        control.availability_revision = 1;
        control.outgoing_availability = AssetTransferAvailability::Disabled;
        crate::smartcontracts::isi::asset::isi::update_control_record(&mut stx, &BOB_ID, control)
            .expect("install counterparty cash freeze");
        let bob_cash = AssetId::new(cash_def_id, BOB_ID.clone());
        let alice_collateral = AssetId::new(collateral_def_id, ALICE_ID.clone());
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("owner consent must not bypass ordinary transfer controls");
        assert!(matches!(
            error,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::OutgoingDisabled(_)
            )
        ));
        assert_eq!(
            repo_asset_balance(&stx, &bob_cash),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &alice_collateral),
            Quantity::from(1_500_u32)
        );
        assert!(stx.world.repo_agreements.get(&agreement_id).is_none());
    }
    #[test]
    fn repo_maturity_settlement_respects_collateral_holder_freeze_atomically() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms = 1_704_000_000_000_u64;
        let maturity_ms = initiation_ms + super::MS_PER_DAY;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let mut instruction = repo_setup_instruction_with_maturity(
                &agreement_id,
                &cash_def_id,
                &collateral_def_id,
                maturity_ms,
            );
            instruction.rate_bps = 0;
            execute_repo_with_consents(&mut stx, instruction).expect("repo opens");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let header = BlockHeader::new(nonzero!(2_u64), None, None, maturity_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let mut control = AssetTransferControlRecord::new(collateral_def_id.clone());
        control.availability_revision = 1;
        control.outgoing_availability = AssetTransferAvailability::Disabled;
        crate::smartcontracts::isi::asset::isi::update_control_record(&mut stx, &BOB_ID, control)
            .expect("install collateral-holder freeze");
        let alice_cash = AssetId::new(cash_def_id, ALICE_ID.clone());
        let bob_collateral = AssetId::new(collateral_def_id, BOB_ID.clone());
        let cash_before = repo_asset_balance(&stx, &alice_cash);
        let collateral_before = repo_asset_balance(&stx, &bob_collateral);
        let error = ReverseRepoIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("maturity consent must not bypass current collateral controls");
        assert!(matches!(
            error,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::OutgoingDisabled(_)
            )
        ));
        assert_eq!(repo_asset_balance(&stx, &alice_cash), cash_before);
        assert_eq!(repo_asset_balance(&stx, &bob_collateral), collateral_before);
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(RepoAgreement::is_active)
        );
    }
    #[allow(clippy::too_many_lines)]
    #[test]
    fn reverse_repo_restores_assets_and_seals_agreement() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        {
            let initiation_ms: u64 = 1_704_000_000_000;
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let repo_instruction =
                repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id);
            execute_repo_with_consents(&mut stx, repo_instruction).expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let settlement_ms: u64 = 1_704_000_000_000 + super::MS_PER_DAY;
        let stored_agreement = {
            let view = state.view();
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .cloned()
                .expect("agreement snapshot")
        };
        let header = BlockHeader::new(nonzero!(2_u64), None, None, settlement_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let cash_spec = stx
            .numeric_spec_for(&cash_def_id)
            .expect("cash spec for settlement");
        let expected_cash = super::expected_cash_settlement(
            stored_agreement.cash_leg().quantity(),
            *stored_agreement.rate_bps(),
            *stored_agreement.initiated_timestamp_ms(),
            settlement_ms,
            cash_spec,
        )
        .expect("interest calculation");
        let interest_due = expected_cash
            .checked_sub(stored_agreement.cash_leg().quantity())
            .expect("interest non-negative");
        let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        if !interest_due.is_zero() {
            crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                &mut stx.world,
                &alice_cash_id,
                &interest_due,
            )
            .expect("seed interest funds");
        }
        let reverse_instruction = ReverseRepoIsi::new(agreement_id.clone());
        reverse_instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("reverse repo execute");
        let mut initiator_event = None;
        let mut counterparty_event = None;
        let mut custodian_event = None;
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Settled(payload))) =
                event.as_ref()
            {
                match payload.role() {
                    RepoAccountRole::Initiator => initiator_event = Some(payload.clone()),
                    RepoAccountRole::Counterparty => counterparty_event = Some(payload.clone()),
                    RepoAccountRole::Custodian => custodian_event = Some(payload.clone()),
                }
            }
        }
        let initiator_event =
            initiator_event.expect("initiator should receive a repo settlement event");
        let counterparty_event =
            counterparty_event.expect("counterparty should receive a repo settlement event");
        assert_eq!(initiator_event.agreement_id(), &agreement_id);
        assert_eq!(initiator_event.account().clone(), ALICE_ID.clone());
        assert_eq!(initiator_event.counterparty().clone(), BOB_ID.clone());
        assert_eq!(initiator_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            initiator_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(initiator_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(initiator_event.role(), &RepoAccountRole::Initiator);
        assert_eq!(counterparty_event.agreement_id(), &agreement_id);
        assert_eq!(counterparty_event.account().clone(), BOB_ID.clone());
        assert_eq!(counterparty_event.counterparty().clone(), ALICE_ID.clone());
        assert_eq!(counterparty_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            counterparty_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(counterparty_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(counterparty_event.role(), &RepoAccountRole::Counterparty);
        assert!(
            custodian_event.is_none(),
            "custodian event unexpected for repo without custodian"
        );
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active()),
            "settlement must retain a one-shot agreement tombstone"
        );
        let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        let bob_cash_id = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
        assert!(
            stx.world.assets.get(&alice_cash_id).is_none(),
            "alice cash entry should be pruned when balance returns to zero"
        );
        assert_eq!(
            **stx.world.assets.get(&bob_cash_id).expect("bob cash"),
            Quantity::from(2_000u32)
                .checked_add(&interest_due)
                .expect("principal + interest")
        );
        let alice_collateral_id = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
        let bob_collateral_id = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_collateral_id)
                .expect("alice collateral"),
            Quantity::from(1_500u32)
        );
        assert!(
            stx.world.assets.get(&bob_collateral_id).is_none(),
            "counterparty collateral should be fully returned"
        );
        let replay_error = ReverseRepoIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a settled repo identifier must be one-shot");
        assert!(replay_error.to_string().contains("already settled"));
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
        let view = state.view();
        assert!(
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .is_some_and(|agreement| {
                    agreement.settlement_timestamp_ms() == &Some(settlement_ms)
                })
        );
    }
    #[test]
    fn maturity_settlement_does_not_require_stale_consent_permissions() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms: u64 = 1_704_000_000_000;
        let maturity_ms = initiation_ms + MS_PER_DAY;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let mut instruction = repo_setup_instruction_with_maturity(
                &agreement_id,
                &cash_def_id,
                &collateral_def_id,
                maturity_ms,
            );
            instruction.rate_bps = 0;
            execute_repo_with_consents(&mut stx, instruction).expect("repo opens");
            assert!(
                stx.world
                    .account_permissions
                    .remove(ALICE_ID.clone())
                    .is_some(),
                "opening should have required exact owner-issued consent permissions"
            );
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit open agreement");
        }
        let header = BlockHeader::new(nonzero!(2_u64), None, None, maturity_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let outsider = checked_account_id();
        let outsider_error = ReverseRepoIsi::new(agreement_id.clone())
            .execute(&outsider, &mut stx)
            .expect_err("a non-participant cannot trigger maturity settlement");
        assert!(
            outsider_error.to_string().contains("recorded participant"),
            "unexpected non-participant rejection: {outsider_error}"
        );
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(RepoAgreement::is_active),
            "rejected outsider submission must not settle the agreement"
        );
        ReverseRepoIsi::new(agreement_id.clone())
            .execute(&BOB_ID, &mut stx)
            .expect("counterparty can trigger the recorded maturity after permission revocation");
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active()),
            "successful maturity settlement must retain the consumed identifier"
        );
        assert_eq!(
            repo_asset_balance(&stx, &AssetId::new(cash_def_id.clone(), BOB_ID.clone())),
            Quantity::from(2_000_u32)
        );
        assert_eq!(
            repo_asset_balance(&stx, &AssetId::new(collateral_def_id, ALICE_ID.clone())),
            Quantity::from(1_500_u32)
        );
    }
    #[allow(clippy::too_many_lines)]
    #[test]
    fn reverse_repo_ignores_unrelated_collateral_and_uses_stored_terms() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let initiation_ms: u64 = 1_704_500_000_000;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            execute_repo_with_consents(
                &mut stx,
                repo_setup_instruction_with_maturity(
                    &agreement_id,
                    &cash_def_id,
                    &collateral_def_id,
                    initiation_ms + super::MS_PER_DAY,
                ),
            )
            .expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let settlement_ms = initiation_ms + super::MS_PER_DAY;
        let stored_agreement = {
            let view = state.view();
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .cloned()
                .expect("agreement snapshot")
        };
        let header = BlockHeader::new(nonzero!(2_u64), None, None, settlement_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let cash_spec = stx
            .numeric_spec_for(&cash_def_id)
            .expect("cash spec for settlement");
        let expected_cash = super::expected_cash_settlement(
            stored_agreement.cash_leg().quantity(),
            *stored_agreement.rate_bps(),
            *stored_agreement.initiated_timestamp_ms(),
            settlement_ms,
            cash_spec,
        )
        .expect("interest calculation");
        let interest_due = expected_cash
            .checked_sub(stored_agreement.cash_leg().quantity())
            .expect("interest non-negative");
        let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        if !interest_due.is_zero() {
            crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                &mut stx.world,
                &alice_cash_id,
                &interest_due,
            )
            .expect("seed interest funds");
        }
        // An unrelated balance cannot be selected by the ID-only settlement instruction.
        let extra_collateral = Quantity::from(50u32);
        let bob_collateral_id = AssetId::new(collateral_def_id.clone(), BOB_ID.clone());
        crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
            &mut stx.world,
            &bob_collateral_id,
            &extra_collateral,
        )
        .expect("seed substitution collateral");
        let reverse_instruction = ReverseRepoIsi::new(agreement_id.clone());
        reverse_instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("reverse repo execute");
        let mut initiator_event = None;
        let mut counterparty_event = None;
        let mut custodian_event = None;
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Settled(payload))) =
                event.as_ref()
            {
                match payload.role() {
                    RepoAccountRole::Initiator => initiator_event = Some(payload.clone()),
                    RepoAccountRole::Counterparty => counterparty_event = Some(payload.clone()),
                    RepoAccountRole::Custodian => custodian_event = Some(payload.clone()),
                }
            }
        }
        let initiator_event =
            initiator_event.expect("initiator should receive a repo settlement event");
        let counterparty_event =
            counterparty_event.expect("counterparty should receive a repo settlement event");
        assert_eq!(initiator_event.agreement_id(), &agreement_id);
        assert_eq!(initiator_event.account().clone(), ALICE_ID.clone());
        assert_eq!(initiator_event.counterparty().clone(), BOB_ID.clone());
        assert_eq!(initiator_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            initiator_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(initiator_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(initiator_event.role(), &RepoAccountRole::Initiator);
        assert_eq!(counterparty_event.agreement_id(), &agreement_id);
        assert_eq!(counterparty_event.account().clone(), BOB_ID.clone());
        assert_eq!(counterparty_event.counterparty().clone(), ALICE_ID.clone());
        assert_eq!(counterparty_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            counterparty_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(counterparty_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(counterparty_event.role(), &RepoAccountRole::Counterparty);
        assert!(
            custodian_event.is_none(),
            "custodian event unexpected for repo without custodian"
        );
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active()),
            "settlement must retain its one-shot tombstone"
        );
        let bob_cash_id = AssetId::new(cash_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx.world.assets.get(&bob_cash_id).expect("bob cash"),
            Quantity::from(2_000u32)
                .checked_add(&interest_due)
                .expect("principal + interest")
        );
        let alice_collateral_id = AssetId::new(collateral_def_id.clone(), ALICE_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_collateral_id)
                .expect("alice collateral"),
            Quantity::from(1_500u32)
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&bob_collateral_id)
                .expect("unrelated collateral remains"),
            extra_collateral,
        );
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
        let view = state.view();
        assert!(
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active())
        );
    }
    #[allow(clippy::too_many_lines)]
    #[test]
    fn reverse_repo_with_custodian_emits_events_for_all_parties() {
        let (state, agreement_id, cash_def_id, collateral_def_id, custodian_id) =
            setup_state_with_custodian();
        let initiation_ms: u64 = 1_705_000_000_000;
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, initiation_ms, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let instruction = RepoIsi::new(
                agreement_id.clone(),
                ALICE_ID.clone(),
                BOB_ID.clone(),
                Some(custodian_id.clone()),
                RepoCashLeg {
                    asset_definition_id: cash_def_id.clone(),
                    quantity: Quantity::from(1_000u32),
                },
                RepoCollateralLeg::new(collateral_def_id.clone(), Quantity::from(1_100u32)),
                250,
                initiation_ms + super::MS_PER_DAY,
                RepoGovernance::new(1_500, 86_400, false),
            );
            execute_repo_with_consents(&mut stx, instruction).expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let settlement_ms = initiation_ms + super::MS_PER_DAY;
        let stored_agreement = {
            let view = state.view();
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .cloned()
                .expect("agreement snapshot")
        };
        let header = BlockHeader::new(nonzero!(2_u64), None, None, settlement_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        let cash_spec = stx
            .numeric_spec_for(&cash_def_id)
            .expect("cash spec for settlement");
        let expected_cash = super::expected_cash_settlement(
            stored_agreement.cash_leg().quantity(),
            *stored_agreement.rate_bps(),
            *stored_agreement.initiated_timestamp_ms(),
            settlement_ms,
            cash_spec,
        )
        .expect("interest calculation");
        let interest_due = expected_cash
            .checked_sub(stored_agreement.cash_leg().quantity())
            .expect("interest non-negative");
        let alice_cash_id = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
        if !interest_due.is_zero() {
            crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                &mut stx.world,
                &alice_cash_id,
                &interest_due,
            )
            .expect("seed interest funds");
        }
        ReverseRepoIsi::new(agreement_id.clone())
            .execute(&custodian_id, &mut stx)
            .expect("recorded custodian can trigger maturity settlement");
        let mut initiator_event = None;
        let mut counterparty_event = None;
        let mut custodian_event = None;
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::Settled(payload))) =
                event.as_ref()
            {
                match payload.role() {
                    RepoAccountRole::Initiator => initiator_event = Some(payload.clone()),
                    RepoAccountRole::Counterparty => counterparty_event = Some(payload.clone()),
                    RepoAccountRole::Custodian => custodian_event = Some(payload.clone()),
                }
            }
        }
        let initiator_event =
            initiator_event.expect("initiator should receive a repo settlement event");
        let counterparty_event =
            counterparty_event.expect("counterparty should receive a repo settlement event");
        let custodian_event =
            custodian_event.expect("custodian should receive a repo settlement event");
        assert_eq!(initiator_event.account().clone(), ALICE_ID.clone());
        assert_eq!(initiator_event.role(), &RepoAccountRole::Initiator);
        assert_eq!(initiator_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            initiator_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(initiator_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(counterparty_event.account().clone(), BOB_ID.clone());
        assert_eq!(counterparty_event.role(), &RepoAccountRole::Counterparty);
        assert_eq!(counterparty_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            counterparty_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(counterparty_event.settled_timestamp_ms(), &settlement_ms);
        assert_eq!(custodian_event.account().clone(), custodian_id.clone());
        assert_eq!(custodian_event.role(), &RepoAccountRole::Custodian);
        assert_eq!(custodian_event.counterparty().clone(), ALICE_ID.clone());
        assert_eq!(custodian_event.cash_leg().quantity(), &expected_cash);
        assert_eq!(
            custodian_event.collateral_leg().quantity(),
            stored_agreement.collateral_leg().quantity()
        );
        assert_eq!(custodian_event.settled_timestamp_ms(), &settlement_ms);
        assert!(
            stx.world
                .repo_agreements
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active()),
            "agreement tombstone should survive settlement"
        );
        let custodian_collateral_id = AssetId::new(collateral_def_id.clone(), custodian_id.clone());
        assert!(
            stx.world.assets.get(&custodian_collateral_id).is_none(),
            "custodian collateral should return to the initiator"
        );
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
        let view = state.view();
        assert!(
            view.world
                .repo_agreements()
                .get(&agreement_id)
                .is_some_and(|agreement| !agreement.is_active())
        );
    }
    #[test]
    fn repo_margin_call_updates_schedule_and_emits_events() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            execute_repo_with_consents(
                &mut stx,
                repo_setup_instruction_with_maturity(
                    &agreement_id,
                    &cash_def_id,
                    &collateral_def_id,
                    2 * super::MS_PER_DAY,
                ),
            )
            .expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let margin_timestamp_ms = super::MS_PER_DAY;
        let header = BlockHeader::new(nonzero!(2_u64), None, None, margin_timestamp_ms, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        RepoMarginCallIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("margin call execute");
        let mut roles = Vec::new();
        for event in &stx.world.internal_event_buf {
            if let DataEvent::Account(AccountEvent::Repo(RepoAccountEvent::MarginCalled(payload))) =
                event.as_ref()
            {
                roles.push((payload.account().clone(), *payload.role()));
                assert_eq!(payload.agreement_id(), &agreement_id);
                assert_eq!(payload.margin_timestamp_ms(), &margin_timestamp_ms);
            }
        }
        assert!(roles.contains(&(ALICE_ID.clone(), RepoAccountRole::Initiator)));
        assert!(roles.contains(&(BOB_ID.clone(), RepoAccountRole::Counterparty)));
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
        let view = state.view();
        let recorded = view
            .world
            .repo_agreements()
            .get(&agreement_id)
            .expect("repo agreement persists");
        assert_eq!(
            recorded.last_margin_check_timestamp_ms(),
            &margin_timestamp_ms
        );
    }
    #[test]
    fn repo_margin_call_rejected_when_not_due() {
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            execute_repo_with_consents(
                &mut stx,
                repo_setup_instruction(&agreement_id, &cash_def_id, &collateral_def_id),
            )
            .expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        let header = BlockHeader::new(nonzero!(2_u64), None, None, super::MS_PER_DAY / 2, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let err = RepoMarginCallIsi::new(agreement_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("margin call should be rejected when not due");
        assert!(err.to_string().contains("margin check is not yet due"));
    }
    #[allow(clippy::too_many_lines)]
    fn capture_proof_stage(
        state: &State,
        stage_label: &'static str,
        tracked_assets: &[AssetId],
        agreement_id: &RepoAgreementId,
        base_timestamp_ms: u64,
    ) -> Value {
        fn string_value(value: &impl ToString) -> Value {
            Value::String(value.to_string())
        }
        fn number_value(value: u64) -> Value {
            Value::Number(Number::from(value))
        }
        let view = state.view();
        let agreement_snapshot = view.world.repo_agreements().get(agreement_id).cloned();
        let agreement_value = agreement_snapshot.map_or_else(
            || {
                let mut cleared = Map::new();
                cleared.insert("id".into(), string_value(agreement_id));
                cleared.insert("status".into(), Value::String("missing".into()));
                Value::Object(cleared)
            },
            |agreement| {
                let mut obj = Map::new();
                obj.insert("id".into(), string_value(agreement.id()));
                obj.insert(
                    "status".into(),
                    Value::String(
                        if agreement.is_active() {
                            "active"
                        } else {
                            "settled"
                        }
                        .into(),
                    ),
                );
                obj.insert("initiator".into(), string_value(agreement.initiator()));
                obj.insert(
                    "counterparty".into(),
                    string_value(agreement.counterparty()),
                );
                obj.insert(
                    "custodian".into(),
                    agreement
                        .custodian()
                        .as_ref()
                        .map_or(Value::Null, string_value),
                );
                obj.insert(
                    "rate_bps".into(),
                    number_value(u64::from(*agreement.rate_bps())),
                );
                obj.insert(
                    "haircut_bps".into(),
                    number_value(u64::from(agreement.governance().haircut_bps())),
                );
                obj.insert(
                    "margin_frequency_secs".into(),
                    number_value(agreement.governance().margin_frequency_secs()),
                );
                obj.insert(
                    "initiated_offset_ms".into(),
                    number_value(
                        agreement
                            .initiated_timestamp_ms()
                            .saturating_sub(base_timestamp_ms),
                    ),
                );
                obj.insert(
                    "last_margin_offset_ms".into(),
                    number_value(
                        agreement
                            .last_margin_check_timestamp_ms()
                            .saturating_sub(base_timestamp_ms),
                    ),
                );
                obj.insert(
                    "maturity_offset_ms".into(),
                    number_value(
                        agreement
                            .maturity_timestamp_ms()
                            .saturating_sub(base_timestamp_ms),
                    ),
                );
                obj.insert(
                    "settlement_offset_ms".into(),
                    agreement
                        .settlement_timestamp_ms()
                        .map_or(Value::Null, |timestamp| {
                            number_value(timestamp.saturating_sub(base_timestamp_ms))
                        }),
                );
                let mut cash = Map::new();
                cash.insert(
                    "asset".into(),
                    string_value(agreement.cash_leg().asset_definition_id()),
                );
                cash.insert(
                    "quantity".into(),
                    string_value(agreement.cash_leg().quantity()),
                );
                cash.insert("source".into(), string_value(agreement.cash_source()));
                obj.insert("cash".into(), Value::Object(cash));
                let mut collateral = Map::new();
                collateral.insert(
                    "asset".into(),
                    string_value(agreement.collateral_leg().asset_definition_id()),
                );
                collateral.insert(
                    "quantity".into(),
                    string_value(agreement.collateral_leg().quantity()),
                );
                collateral.insert(
                    "custody_asset".into(),
                    string_value(agreement.collateral_custody_asset()),
                );
                obj.insert("collateral".into(), Value::Object(collateral));
                Value::Object(obj)
            },
        );
        let mut sorted_assets = tracked_assets.to_vec();
        sorted_assets.sort();
        let assets = sorted_assets
            .into_iter()
            .map(|asset_id| {
                let value = view.world.assets().get(&asset_id);
                let present = value.is_some();
                let quantity = value.map_or_else(|| "0".to_string(), |asset| (**asset).to_string());
                let mut entry = Map::new();
                entry.insert("id".into(), string_value(&asset_id));
                entry.insert("present".into(), Value::Bool(present));
                entry.insert("quantity".into(), Value::String(quantity));
                Value::Object(entry)
            })
            .collect::<Vec<_>>();
        let mut frame = Map::new();
        frame.insert("stage".into(), Value::String(stage_label.to_string()));
        frame.insert("agreement".into(), agreement_value);
        frame.insert("assets".into(), Value::Array(assets));
        Value::Object(frame)
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn repo_deterministic_lifecycle_proof_matches_fixture() {
        const PROOF_FIXTURE_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/repo_lifecycle_proof.json"
        ));
        const PROOF_FIXTURE_DIGEST_HEX: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/repo_lifecycle_proof.digest"
        ));
        const BASE_TIMESTAMP_MS: u64 = 1_704_111_000_000;
        // Refresh the fixtures with `scripts/regen_repo_proof_fixture.sh` under
        // the pinned toolchain whenever repo semantics change so governance
        // evidence stays reproducible.
        let (state, agreement_id, cash_def_id, collateral_def_id) = setup_state();
        let tracked_assets = vec![
            AssetId::new(cash_def_id.clone(), ALICE_ID.clone()),
            AssetId::new(cash_def_id.clone(), BOB_ID.clone()),
            AssetId::new(collateral_def_id.clone(), ALICE_ID.clone()),
            AssetId::new(collateral_def_id.clone(), BOB_ID.clone()),
        ];
        let mut frames = Vec::new();
        {
            let header = BlockHeader::new(nonzero!(1_u64), None, None, BASE_TIMESTAMP_MS, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            execute_repo_with_consents(
                &mut stx,
                repo_setup_instruction_with_maturity(
                    &agreement_id,
                    &cash_def_id,
                    &collateral_def_id,
                    BASE_TIMESTAMP_MS + (2 * super::MS_PER_DAY),
                ),
            )
            .expect("repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        frames.push(capture_proof_stage(
            &state,
            "repo_initiated",
            &tracked_assets,
            &agreement_id,
            BASE_TIMESTAMP_MS,
        ));
        {
            let margin_timestamp = BASE_TIMESTAMP_MS + super::MS_PER_DAY;
            let header = BlockHeader::new(nonzero!(2_u64), None, None, margin_timestamp, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            RepoMarginCallIsi::new(agreement_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("margin call execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        frames.push(capture_proof_stage(
            &state,
            "margin_called",
            &tracked_assets,
            &agreement_id,
            BASE_TIMESTAMP_MS,
        ));
        {
            let unwind_timestamp = BASE_TIMESTAMP_MS + (2 * super::MS_PER_DAY);
            let stored_agreement = state
                .view()
                .world
                .repo_agreements()
                .get(&agreement_id)
                .cloned()
                .expect("agreement snapshot");
            let header = BlockHeader::new(nonzero!(3_u64), None, None, unwind_timestamp, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction_for_callback_testing();
            let cash_spec = stx
                .numeric_spec_for(&cash_def_id)
                .expect("cash spec snapshot");
            let expected_cash = super::expected_cash_settlement(
                stored_agreement.cash_leg().quantity(),
                *stored_agreement.rate_bps(),
                *stored_agreement.initiated_timestamp_ms(),
                unwind_timestamp,
                cash_spec,
            )
            .expect("interest calculation");
            let interest_due = expected_cash
                .checked_sub(stored_agreement.cash_leg().quantity())
                .expect("interest non-negative");
            if !interest_due.is_zero() {
                let alice_cash = AssetId::new(cash_def_id.clone(), ALICE_ID.clone());
                crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                    &mut stx.world,
                    &alice_cash,
                    &interest_due,
                )
                .expect("seed interest funds");
            }
            ReverseRepoIsi::new(agreement_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("reverse repo execute");
            stx.apply();
            block.commit_world_overlay_for_testing().expect("commit");
        }
        frames.push(capture_proof_stage(
            &state,
            "settled_at_maturity",
            &tracked_assets,
            &agreement_id,
            BASE_TIMESTAMP_MS,
        ));
        let proof = norito::json!({
            "scenario": "repo_lifecycle_deterministic",
            "frames": frames,
        });
        let proof_bytes = norito::json::to_vec_pretty(&proof).expect("serialize proof");
        if let Ok(path) = std::env::var("REPO_PROOF_SNAPSHOT_OUT") {
            let snapshot_path = std::path::PathBuf::from(&path);
            if let Some(parent) = snapshot_path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|err| {
                    panic!("failed to create repo proof snapshot parent dirs: {err}");
                });
            }
            std::fs::write(&snapshot_path, &proof_bytes).unwrap_or_else(|err| {
                panic!("failed to write repo proof snapshot to {path}: {err}");
            });
        }
        let digest_hex = encode_upper(Hash::new(&proof_bytes).as_ref());
        if let Ok(path) = std::env::var("REPO_PROOF_DIGEST_OUT") {
            let digest_path = std::path::PathBuf::from(&path);
            if let Some(parent) = digest_path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|err| {
                    panic!("failed to create repo proof digest parent dirs: {err}");
                });
            }
            std::fs::write(&digest_path, format!("{digest_hex}\n")).unwrap_or_else(|err| {
                panic!("failed to write repo proof digest to {path}: {err}");
            });
        }
        let expected_proof: Value =
            norito::json::from_str(PROOF_FIXTURE_JSON).expect("repo proof fixture parses");
        let normalized_fixture_bytes =
            norito::json::to_vec_pretty(&expected_proof).expect("serialize fixture");
        let normalized_fixture_pretty =
            String::from_utf8(normalized_fixture_bytes.clone()).expect("fixture pretty JSON utf8");
        assert_eq!(
            PROOF_FIXTURE_JSON.trim_end_matches('\n'),
            normalized_fixture_pretty,
            "repo proof fixture formatting drifted; run scripts/regen_repo_proof_fixture.sh"
        );
        assert_eq!(
            proof, expected_proof,
            "repo lifecycle proof fixture mismatch; run scripts/regen_repo_proof_fixture.sh"
        );
        assert_eq!(
            proof_bytes, normalized_fixture_bytes,
            "repo lifecycle proof snapshot drifted; run scripts/regen_repo_proof_fixture.sh"
        );
        let expected_digest_hex = PROOF_FIXTURE_DIGEST_HEX.trim();
        let fixture_digest_hex = encode_upper(Hash::new(&normalized_fixture_bytes).as_ref());
        assert_eq!(
            fixture_digest_hex, expected_digest_hex,
            "repo proof digest fixture is out of sync; run scripts/regen_repo_proof_fixture.sh"
        );
        assert_eq!(
            digest_hex, expected_digest_hex,
            "repo lifecycle proof digest snapshot mismatch: {digest_hex}"
        );
    }
}
