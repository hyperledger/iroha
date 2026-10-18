//! Exact-consent, prefunded N-payment atomic settlement execution.
//!
//! Optional conditional escrow legs are opened by the same all-or-nothing
//! execution: their custody funding joins the prepared movement batch, so a
//! failing movement or escrow leg leaves balances, accounts, escrows and the
//! receipt unchanged.
//!
//! TODO: Complete composed native tests and network qualification before claiming
//! matched-control execution results.

use super::*;
use crate::smartcontracts::isi::escrow::{
    ConditionalEscrowOpening, ConditionalEscrowTerms, prepare_conditional_escrow_opening,
    remove_created_custody_account,
};
use iroha_data_model::isi::{ResolvedSettlementMovements, SettleAtomic, SettlementDetails};

/// An unforgeable, non-reusable capability issued only after complete intent validation.
pub(in crate::smartcontracts::isi) struct VerifiedSettlementNumericBatch {
    authority: AccountId,
    movements: ResolvedSettlementMovements,
    escrow_fundings: Vec<(AssetId, AssetId, Quantity)>,
}
impl VerifiedSettlementNumericBatch {
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        AccountId,
        ResolvedSettlementMovements,
        Vec<(AssetId, AssetId, Quantity)>,
    ) {
        (self.authority, self.movements, self.escrow_fundings)
    }
}

/// Complete validated intent: the movement batch capability, its hash and escrow openings.
struct VerifiedAtomicIntent {
    batch: VerifiedSettlementNumericBatch,
    intent_hash: Hash,
    openings: Vec<ConditionalEscrowOpening>,
}

fn validate_atomic_intent(
    authority: &AccountId,
    stx: &StateTransaction<'_, '_>,
    instruction: &SettleAtomic,
) -> Result<VerifiedAtomicIntent, Error> {
    instruction
        .validate()
        .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?;
    if instruction.network_id() != &stx.network_id {
        return Err(InstructionExecutionError::InvariantViolation(
            "atomic settlement network does not match the executing genesis".into(),
        ));
    }
    if stx._curr_block.height().get() > instruction.expires_at_height().get() {
        return Err(InstructionExecutionError::InvariantViolation(
            "atomic settlement inclusive expiry height has passed".into(),
        ));
    }
    ensure_settlement_id_unused(stx, instruction.settlement_id())?;
    stx.world.account(authority)?;
    let intent_hash = instruction.intent_hash().map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("atomic settlement canonical intent cannot be encoded: {error}").into(),
        )
    })?;
    let consents =
        settlement_consent_sources(stx, authority, instruction.settlement_id(), intent_hash);
    // The caller's exact signed instruction authorizes its own balances. Every
    // other movement or escrow source needs owner-issued consent to the complete
    // intent, including every escrow term.
    let ensure_consented = |source: &AssetId| {
        if source.account() != authority && !consents.contains(source) {
            return Err(InstructionExecutionError::InvariantViolation(
                "atomic settlement requires exact whole-intent consent for every foreign source bucket".into(),
            ));
        }
        Ok(())
    };
    for movement in instruction.movements().as_slice() {
        ensure_consented(&movement.source)?;
    }
    for escrow in instruction.escrows().as_slice() {
        ensure_consented(&escrow.source)?;
    }
    let movements = instruction
        .movements()
        .resolve()
        .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?;
    let openings = instruction
        .escrows()
        .as_slice()
        .iter()
        .map(|escrow| {
            prepare_conditional_escrow_opening(
                stx,
                escrow.source.clone(),
                ConditionalEscrowTerms {
                    escrow_id: escrow.escrow_id,
                    beneficiary: escrow.beneficiary.clone(),
                    amount: escrow.amount.clone(),
                    conditions: escrow.conditions.clone(),
                    expires_at_ms: escrow.expires_at_ms,
                    evidence_hashes: escrow.evidence_hashes.clone(),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Escrow custody is credited only by its own funding leg, so a recorded
    // escrow's custody balance always equals its remaining amount.
    let custody_accounts = openings
        .iter()
        .map(ConditionalEscrowOpening::custody_account)
        .collect::<BTreeSet<_>>();
    if instruction
        .movements()
        .as_slice()
        .iter()
        .any(|movement| custody_accounts.contains(&movement.recipient))
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "atomic settlement movements cannot credit escrow custody of the same intent".into(),
        ));
    }
    let escrow_fundings = openings
        .iter()
        .map(|opening| {
            (
                opening.source().clone(),
                opening.custody_asset(),
                opening.amount().clone(),
            )
        })
        .collect();
    Ok(VerifiedAtomicIntent {
        batch: VerifiedSettlementNumericBatch {
            authority: authority.clone(),
            movements,
            escrow_fundings,
        },
        intent_hash,
        openings,
    })
}

/// Create every absent escrow custody account, removing them all again on failure.
fn create_escrow_custody_accounts(
    stx: &mut StateTransaction<'_, '_>,
    openings: &[ConditionalEscrowOpening],
) -> Result<Vec<AccountId>, Error> {
    let mut created = Vec::new();
    for opening in openings {
        match opening.ensure_custody_account(stx) {
            Ok(true) => created.push(opening.custody_account().clone()),
            Ok(false) => {}
            Err(error) => {
                remove_escrow_custody_accounts(stx, &created);
                return Err(error);
            }
        }
    }
    Ok(created)
}

fn remove_escrow_custody_accounts(stx: &mut StateTransaction<'_, '_>, created: &[AccountId]) {
    for custody in created {
        remove_created_custody_account(stx, custody);
    }
}

/// Validate exact atomic intent, current owner consents and complete movement policies.
///
/// This path prepares the same whole batch as execution, including escrow
/// custody funding, and never applies it. Custody accounts created only for the
/// preparation are removed before returning.
pub(crate) fn admission_validate_atomic(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    instruction: &SettleAtomic,
) -> Result<(), Error> {
    let intent = validate_atomic_intent(authority, stx, instruction)?;
    let created = create_escrow_custody_accounts(stx, &intent.openings)?;
    let result = crate::smartcontracts::isi::asset::isi::validate_verified_settlement_numeric_batch(
        stx,
        intent.batch,
    );
    remove_escrow_custody_accounts(stx, &created);
    result
}

impl Execute for SettleAtomic {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let VerifiedAtomicIntent {
            batch,
            intent_hash,
            openings,
        } = validate_atomic_intent(authority, stx, &self)?;
        // Construct all receipt material before the first balance mutation. The
        // asset owner will reject any prepared bucket different from this exact
        // signed vector, so receipt scopes never depend on post-execution lookup.
        let receipt = settlement_receipt(
            stx,
            authority,
            self.metadata().clone(),
            SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                movements: batch.movements.clone(),
                intent_hash,
                escrow_ids: self.escrows().escrow_ids(),
            }),
        );
        // Escrow custody must exist before the batch prepares its ExistingAccount
        // credits. Every account created here is removed if any leg fails.
        let created = create_escrow_custody_accounts(stx, &openings)?;
        if let Err(error) =
            crate::smartcontracts::isi::asset::isi::execute_verified_settlement_numeric_batch(
                stx, batch,
            )
        {
            remove_escrow_custody_accounts(stx, &created);
            return Err(error);
        }
        // The unique settlement and escrow IDs were checked in this exclusive
        // StateTransaction, and no callback or other instruction can insert a
        // receipt or escrow while the private asset plan applies. All remaining
        // operations are infallible staging.
        for opening in openings {
            opening.record_funded(stx);
        }
        stx.world
            .settlement_receipts
            .insert(self.settlement_id().clone(), receipt);
        Ok(())
    }
}
