//! Fresh native Musubi inventory readback over one original State and signed Check.
//!
//! These move-only stages authenticate authority-wide absence or one entire high-water row.
//! Their result is a read-only observation, never permission to initialize a replacement
//! outbox, sign a pin, enter Queue, or publish. Those effects require their own closed owner.

pub use crate::query::signer_check::NativeCheckBindingErrorV1;

use std::{sync::Arc, time::Instant};

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::consensus::SumeragiRootScope,
    isi::musubi::{CheckMusubiPinOutboxV1, MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1},
    musubi::{
        MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1, MusubiPinOutboxHighWaterV1,
    },
    transaction::SignedTransaction,
};
use iroha_model_base::chain::ChainId;
use mv::storage::StorageReadOnly as _;

use crate::{
    query::signer_check::{
        BindingFailure, BindingScope, BorrowedCheckExecutionCutV1, BoundNativeCheckV1,
        NativeCheckErrorV1, NativeCheckFloorV1, NativeCheckRoundV1, NativeCustodyCheckPurposeV1,
        NativeCustodyCheckRefV1, PreparedCheckExecutionV1, SignedCheckAttempt,
        SignerCertifiedWalkV1, bind_signed_check_v1, validate_native_signatory_v1,
        with_native_check_read_limits,
    },
    state::{
        State, StateReadOnly as _, StateView, WorldReadOnly as _, is_stable_state_view_generation,
    },
    sumeragi::crypto::BlsCrypto,
};

/// Independently selected readback coordinates. Decoding or constructing these grants no proof.
pub struct MusubiPinOutboxCheckExpectedV1 {
    /// Exact configured chain label, independently selected before any history response.
    pub chain_id: ChainId,
    /// Genesis-derived network selected by the deployment owner.
    pub network_id: NetworkId,
    /// Sole signed authority whose entire current row is queried.
    pub pin_authority: AccountId,
    /// Original locally retained signing session, including for absence.
    pub session_id: [u8; 32],
    /// Complete locally retained inventory, including for absence.
    pub inventory_digest: [u8; 32],
    /// Independently retained native floor; the supplied State must authenticate it.
    pub floor: MusubiPinOutboxCheckFloorV1,
    /// Authority-wide absence or exact equality of every high-water field.
    pub expected: MusubiPinOutboxCheckExpectationV1,
}

/// Closed readback failure; none represents a submitted transaction or pin completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MusubiPinOutboxCheckErrorV1 {
    /// Invalid independently selected scope, deadline, field or capacity.
    #[error("invalid Musubi pin-outbox Check request")]
    Invalid,
    /// The original monotonic lifetime expired without renewal.
    #[error("Musubi pin-outbox Check deadline expired")]
    Expired,
    /// A fresh nonzero challenge could not be obtained.
    #[error("Musubi pin-outbox Check challenge unavailable")]
    Entropy,
    /// The supplied signed transaction differs from the exact prepared native Check.
    #[error("Musubi pin-outbox signed Check differs")]
    Transaction,
    /// The original signed Check has no successful local application proof after its floor.
    #[error("Musubi pin-outbox Check has no successful local application proof")]
    NotApplied,
    /// Original bounded native history or its certified execution relation is unavailable.
    #[error("Musubi pin-outbox Check finality unavailable")]
    Finality,
    /// Original State identity, publication generation or complete current row differs.
    #[error("Musubi pin-outbox current State differs")]
    CurrentState,
}
use MusubiPinOutboxCheckErrorV1 as Error;

impl From<NativeCheckErrorV1> for Error {
    fn from(error: NativeCheckErrorV1) -> Self {
        match error {
            NativeCheckErrorV1::Invalid => Self::Invalid,
            NativeCheckErrorV1::Expired => Self::Expired,
            NativeCheckErrorV1::Entropy => Self::Entropy,
            NativeCheckErrorV1::Transaction => Self::Transaction,
            NativeCheckErrorV1::NotApplied => Self::NotApplied,
            NativeCheckErrorV1::Finality | NativeCheckErrorV1::Execution => Self::Finality,
        }
    }
}

/// Original fresh challenge and bounded exact instruction; no Clone or decoded constructor.
#[must_use = "bind only the exact signed Check within its original deadline"]
pub struct PreparedMusubiPinOutboxCheckV1 {
    state: Arc<State>,
    chain_id: ChainId,
    instruction: CheckMusubiPinOutboxV1,
    round: NativeCheckRoundV1,
}

/// One original signed Check awaiting native execution authentication.
#[must_use = "reconcile and verify the original signed Check without re-signing"]
pub struct PendingMusubiPinOutboxCheckV1 {
    prepared: PreparedMusubiPinOutboxCheckV1,
    bound: BoundNativeCheckV1,
}

/// One verified native execution, still requiring the final same-State current-row fence.
#[must_use = "consume against the exact original State before using this readback"]
pub struct VerifiedMusubiPinOutboxCheckV1 {
    prepared: PreparedMusubiPinOutboxCheckV1,
    bound: BoundNativeCheckV1,
    generation: u64,
    applied_floor: MusubiPinOutboxCheckFloorV1,
}

/// A failed read attempt retaining the unchanged original paid Check for reconciliation.
/// No failure renews the challenge, signed bytes, floor, expected row or absolute deadline.
pub struct MusubiPinOutboxCheckAttemptFailureV1 {
    error: crate::execution_attempt::ExecutionAttemptError<Error>,
    pending: PendingMusubiPinOutboxCheckV1,
}
impl MusubiPinOutboxCheckAttemptFailureV1 {
    /// Borrow the unchanged typed cause without discarding original pending custody.
    #[must_use]
    pub fn error(&self) -> &crate::execution_attempt::ExecutionAttemptError<Error> {
        &self.error
    }
    /// Inspect only a completed semantic rejection.
    pub fn rejection(&self) -> Option<Error> {
        match &self.error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => Some(*error),
            _ => None,
        }
    }
    /// Whether the same original attempt may retry within its unchanged deadline.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        )
    }
    /// Original absolute deadline, never renewed by verification or current-row retry.
    pub fn deadline(&self) -> Instant {
        self.pending.deadline()
    }
    /// Borrow the exact original signed transaction without re-signing.
    pub fn signed_transaction(&self) -> &SignedTransaction {
        self.pending.signed_transaction()
    }
    /// Recover original custody and require a fresh native verification before consumption.
    pub fn into_pending(self) -> PendingMusubiPinOutboxCheckV1 {
        self.pending
    }
}
impl core::fmt::Debug for MusubiPinOutboxCheckAttemptFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MusubiPinOutboxCheckAttemptFailureV1")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Display for MusubiPinOutboxCheckAttemptFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.error, formatter)
    }
}
impl std::error::Error for MusubiPinOutboxCheckAttemptFailureV1 {}

/// One consumed, read-only native observation at an exact publication cut.
///
/// This has no Clone, codec or public constructor. Its historical facts do not authorize
/// later effects, rollback recovery, replacement custody, signing or Queue submission.
pub struct MusubiPinOutboxCurrentReadbackV1 {
    instruction: CheckMusubiPinOutboxV1,
    applied_floor: MusubiPinOutboxCheckFloorV1,
    canonical_external: iroha_allocation::ChargedBuffer<u8>,
    check_block_hash: [u8; 32],
}

fn native_floor(floor: MusubiPinOutboxCheckFloorV1) -> NativeCheckFloorV1 {
    NativeCheckFloorV1 {
        height: floor.height,
        block_hash: floor.block_hash,
        context_id: floor.context_id,
    }
}

fn public_floor(floor: NativeCheckFloorV1) -> MusubiPinOutboxCheckFloorV1 {
    MusubiPinOutboxCheckFloorV1 {
        height: floor.height,
        block_hash: floor.block_hash,
        context_id: floor.context_id,
    }
}

fn current_row(view: &StateView<'_>, instruction: &CheckMusubiPinOutboxV1) -> Result<(), Error> {
    let actual = view
        .world
        .musubi_pin_outbox_high_waters()
        .get(&instruction.pin_authority);
    match (&instruction.expected, actual) {
        (MusubiPinOutboxCheckExpectationV1::Absent, None) => Ok(()),
        (MusubiPinOutboxCheckExpectationV1::Present(expected), Some(actual))
            if expected == actual =>
        {
            Ok(())
        }
        _ => Err(Error::CurrentState),
    }
}

fn global_instance(
    prepared: &PreparedMusubiPinOutboxCheckV1,
) -> Result<iroha_sumeragi::types::Hash32, Error> {
    // This uses only the existing native instance hash derivation, not a verifier or key set.
    SumeragiRootScope::Global
        .instance_id(
            &BlsCrypto::new(),
            prepared.instruction.network_id,
            prepared.chain_id.as_str(),
        )
        .map_err(|_| Error::Invalid)
}

/// Begin one fresh challenged readback within the caller's original absolute deadline.
///
/// The independent floor is verified against original native execution before any signed
/// Check is requested. Genesis alone cannot authenticate its execution result. A successful
/// preparation grants no signing credential, permission, custody or Queue capability.
///
/// # Errors
/// Refuses invalid fields, an expired/overlong deadline, changed current rows, a different
/// network/chain/private root, missing native history or the inherited resource allowance.
pub fn begin_musubi_pin_outbox_check_v1(
    state: Arc<State>,
    expected: MusubiPinOutboxCheckExpectedV1,
    deadline: Instant,
) -> Result<PreparedMusubiPinOutboxCheckV1, crate::execution_attempt::ExecutionAttemptError<Error>>
{
    let mut round = NativeCheckRoundV1::start_until(deadline).map_err(Error::from)?;
    with_native_check_read_limits(|| {
        iroha_primitives::chain_id::validate_chain_id(expected.chain_id.as_str())
            .map_err(|_| Error::Invalid)?;
        validate_native_signatory_v1(&expected.pin_authority).map_err(Error::from)?;
        let mut instruction = CheckMusubiPinOutboxV1 {
            network_id: expected.network_id,
            pin_authority: expected.pin_authority,
            session_id: expected.session_id,
            inventory_digest: expected.inventory_digest,
            challenge: [1; 32],
            floor: expected.floor,
            expected: expected.expected,
        };
        if norito::canonical_frame_len(&instruction).map_err(|error| {
            crate::execution_attempt::norito_decode_attempt_error(error, |_| Error::Invalid)
        })? > MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1
        {
            return Err(Error::Invalid.into());
        }
        instruction.validate_fields().map_err(|_| Error::Invalid)?;
        instruction.challenge = round.issue_challenge().map_err(Error::from)?;
        let prepared = PreparedMusubiPinOutboxCheckV1 {
            state,
            chain_id: expected.chain_id,
            instruction,
            round,
        };
        let generation = prepared.state.state_view_generation();
        let view = prepared.state.view();
        if !is_stable_state_view_generation(generation, prepared.state.state_view_generation())
            || view.network_id() != &prepared.instruction.network_id
            || view.chain_id() != &prepared.chain_id
        {
            return Err(Error::CurrentState.into());
        }
        current_row(&view, &prepared.instruction)?;
        let chain =
            SignerCertifiedWalkV1::new(&view).map_err(|error| error.map_rejection(Error::from))?;
        let expected_instance = global_instance(&prepared)?;
        let floor = prepared.instruction.floor;
        for receipt in chain.walk(floor.height, floor.height.max(2)) {
            prepared.round.ensure_live().map_err(Error::from)?;
            let receipt = receipt.map_err(|error| error.map_rejection(Error::from))?;
            let block = receipt.in_view(&view).map_err(Error::from)?;
            if block.height() == floor.height
                && (*block.block_hash().as_ref() != floor.block_hash
                    || block.id() != floor.context_id)
            {
                return Err(Error::Finality.into());
            }
            if block.height() >= 2
                && block
                    .header()
                    .is_none_or(|header| header.instance != expected_instance)
            {
                return Err(Error::Finality.into());
            }
        }
        prepared.round.ensure_live().map_err(Error::from)?;
        if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
            return Err(Error::CurrentState.into());
        }
        drop(chain);
        drop(view);
        Ok(prepared)
    })
}

impl PreparedMusubiPinOutboxCheckV1 {
    /// Exact bounded instruction which the configured pin authority must sign alone.
    #[must_use]
    pub const fn instruction(&self) -> &CheckMusubiPinOutboxV1 {
        &self.instruction
    }
    /// Unchanged absolute deadline established before preparation.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.round.deadline()
    }
    /// Bind the exact sole signed native Check without renewing the original round.
    ///
    /// # Errors
    /// Retains signed custody on expiry, signature/profile failure, substitution or local capacity refusal.
    /// Every failure retains the exact signed graph and original preparation. Local refusals may
    /// retry only that same attempt; terminal rejection never reopens signing or renews its deadline.
    pub fn bind_signed_transaction(
        self,
        signed: SignedTransaction,
    ) -> Result<PendingMusubiPinOutboxCheckV1, MusubiPinOutboxCheckBindingFailureV1> {
        bind_signed_check_v1(self, SignedCheckAttempt::new(signed), Self::binding_scope)
            .map(|(prepared, bound)| PendingMusubiPinOutboxCheckV1 { prepared, bound })
            .map_err(MusubiPinOutboxCheckBindingFailureV1)
    }

    /// Bind the exact signed Check already copied under this original State's physical pool.
    ///
    /// The move-only graph owner survives binding/finality refusal and current-row retry. This
    /// uses the same signature/profile/floor verifier as ordinary binding, not an admission bypass.
    /// # Errors
    /// Retains the complete original allocated graph on any refusal, including a foreign pool.
    pub fn bind_allocated_transaction(
        self,
        signed: iroha_data_model::transaction::signed::pin_allocation::AllocatedPinTransactionV1,
    ) -> Result<PendingMusubiPinOutboxCheckV1, MusubiPinOutboxCheckBindingFailureV1> {
        bind_signed_check_v1(
            self,
            SignedCheckAttempt::from_allocated_pin(signed),
            Self::binding_scope,
        )
        .map(|(prepared, bound)| PendingMusubiPinOutboxCheckV1 { prepared, bound })
        .map_err(MusubiPinOutboxCheckBindingFailureV1)
    }

    fn binding_scope(&mut self) -> Result<BindingScope<'_>, NativeCheckErrorV1> {
        Ok(BindingScope {
            state: &self.state,
            round: &mut self.round,
            instruction: NativeCustodyCheckRefV1::MusubiPinOutbox(&self.instruction),
            chain_id: self.chain_id.as_str(),
            network_id: *self.instruction.network_id.as_bytes(),
            authority: &self.instruction.pin_authority,
            floor: native_floor(self.instruction.floor),
        })
    }
}

fn authenticate<'view, 'state, 'bound>(
    view: &'view StateView<'state>,
    prepared: &PreparedMusubiPinOutboxCheckV1,
    bound: &'bound mut Option<BoundNativeCheckV1>,
) -> Result<
    BorrowedCheckExecutionCutV1<'view, 'state, 'bound>,
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    with_native_check_read_limits(|| {
        let mut proof = PreparedCheckExecutionV1::new(
            view,
            NativeCustodyCheckPurposeV1::MusubiPinOutbox,
            bound,
            &prepared.round,
        )
        .map_err(|error| error.map_rejection(Error::from))?;
        let chain =
            SignerCertifiedWalkV1::new(view).map_err(|error| error.map_rejection(Error::from))?;
        let instance = global_instance(prepared)?;
        for receipt in chain.walk(proof.floor_height(), proof.applied_height()) {
            prepared.round.ensure_live().map_err(Error::from)?;
            let receipt = receipt.map_err(|error| error.map_rejection(Error::from))?;
            let block = receipt.in_view(view).map_err(Error::from)?;
            if block.height() >= 2
                && block
                    .header()
                    .is_none_or(|header| header.instance != instance)
            {
                return Err(Error::Finality.into());
            }
            proof
                .consume(&receipt)
                .map_err(|error| error.map_rejection(Error::from))?;
        }
        current_row(view, &prepared.instruction)?;
        proof
            .finish()
            .map_err(|error| error.map_rejection(Error::from))
    })
}

fn verify_attempt(
    prepared: &PreparedMusubiPinOutboxCheckV1,
    bound: &mut Option<BoundNativeCheckV1>,
) -> Result<
    (u64, MusubiPinOutboxCheckFloorV1),
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    prepared.round.ensure_live().map_err(Error::from)?;
    let generation = prepared.state.state_view_generation();
    let view = prepared.state.view();
    if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
        return Err(Error::CurrentState.into());
    }
    let cut = authenticate(&view, prepared, bound)?;
    let applied_floor = public_floor(cut.applied_floor());
    prepared.round.ensure_live().map_err(Error::from)?;
    if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
        return Err(Error::CurrentState.into());
    }
    Ok((generation, applied_floor))
}

/// Exact original signed attempt retained after binding refusal.
/// Retry cannot replace the signer output, challenge, State pool, or original deadline.
#[must_use = "retain the original signed Check until binding completes or the attempt is retired"]
pub struct MusubiPinOutboxCheckBindingFailureV1(
    BindingFailure<PreparedMusubiPinOutboxCheckV1, Error>,
);

impl MusubiPinOutboxCheckBindingFailureV1 {
    /// Borrow the original local refusal or completed rejection without erasing custody.
    #[must_use]
    pub fn error(&self) -> &NativeCheckBindingErrorV1<Error> {
        &self.0.error
    }

    /// Inspect a completed native rejection; local refusals have no transaction verdict.
    #[must_use]
    pub fn rejection(&self) -> Option<Error> {
        match &self.0.error {
            NativeCheckBindingErrorV1::Rejected(error) => Some(*error),
            _ => None,
        }
    }

    /// The unchanged absolute deadline, including after any number of local retries.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.0.prepared.round.deadline()
    }

    /// Retry only this exact signed attempt; terminal failures return the same owner.
    ///
    /// # Errors
    /// Returns the unchanged signed custody and original rejection or latest local refusal.
    pub fn retry(self) -> Result<PendingMusubiPinOutboxCheckV1, Self> {
        if !self.0.error.is_retryable() {
            return Err(self);
        }
        bind_signed_check_v1(
            self.0.prepared,
            self.0.signed,
            PreparedMusubiPinOutboxCheckV1::binding_scope,
        )
        .map(|(prepared, bound)| PendingMusubiPinOutboxCheckV1 { prepared, bound })
        .map_err(Self)
    }
}
impl std::fmt::Debug for MusubiPinOutboxCheckBindingFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MusubiPinOutboxCheckBindingFailureV1")
            .field("error", &self.0.error)
            .finish_non_exhaustive()
    }
}

impl PendingMusubiPinOutboxCheckV1 {
    /// Original exact signed Check; callers must retain its bytes before dispatch.
    #[must_use]
    pub fn signed_transaction(&self) -> &SignedTransaction {
        self.bound.signed_transaction()
    }
    /// Original absolute deadline, never extended by submission or reconciliation.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.prepared.round.deadline()
    }
    /// Authenticate exact successful execution and full current row on the original State.
    ///
    /// # Errors
    /// Returns unchanged original custody on missing/failed execution, changed rows, expiry or unavailable history.
    pub fn verify_finalized(
        self,
    ) -> Result<VerifiedMusubiPinOutboxCheckV1, MusubiPinOutboxCheckAttemptFailureV1> {
        let mut original = Some(self.bound);
        match verify_attempt(&self.prepared, &mut original) {
            Ok((generation, applied_floor)) => Ok(VerifiedMusubiPinOutboxCheckV1 {
                prepared: self.prepared,
                bound: original.take().expect("verified binding remains original"),
                generation,
                applied_floor,
            }),
            Err(error) => Err(MusubiPinOutboxCheckAttemptFailureV1 {
                error,
                pending: PendingMusubiPinOutboxCheckV1 {
                    prepared: self.prepared,
                    bound: original
                        .take()
                        .expect("failed verification retains original binding"),
                },
            }),
        }
    }
}

fn consume_attempt(
    prepared: &PreparedMusubiPinOutboxCheckV1,
    bound: &mut Option<BoundNativeCheckV1>,
    generation: u64,
    applied_floor: MusubiPinOutboxCheckFloorV1,
    expected_state: &Arc<State>,
) -> Result<
    (iroha_allocation::ChargedBuffer<u8>, [u8; 32]),
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    if !Arc::ptr_eq(expected_state, &prepared.state) {
        return Err(Error::CurrentState.into());
    }
    prepared.round.ensure_live().map_err(Error::from)?;
    if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
        return Err(Error::CurrentState.into());
    }
    let view = prepared.state.view();
    if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
        return Err(Error::CurrentState.into());
    }
    let cut = authenticate(&view, prepared, bound)?;
    if public_floor(cut.applied_floor()) != applied_floor {
        return Err(Error::CurrentState.into());
    }
    {
        let _publication = prepared.state.musubi_pin_outbox_publication_lease();
        if !is_stable_state_view_generation(generation, prepared.state.state_view_generation()) {
            return Err(Error::CurrentState.into());
        }
        current_row(&view, &prepared.instruction)?;
        prepared.round.ensure_live().map_err(Error::from)?;
    }
    Ok(cut.into_verified_entry())
}

impl VerifiedMusubiPinOutboxCheckV1 {
    /// Consume under the exact recipient State and a final short current-row publication fence.
    ///
    /// Native history reads precede the lease. Under it this owner checks only the original
    /// generation, deadline and complete authority-keyed row. No caller callback can replace
    /// those predicates or perform effects. Failure retains the original Pending Check and drops
    /// only this verified cut; retry must reauthenticate before another consumption.
    ///
    /// # Errors
    /// Returns original custody on another State (even byte-identical), intervening publication,
    /// changed rows, missing native source, inherited resource refusal or the original deadline.
    pub fn consume_current(
        self,
        expected_state: &Arc<State>,
    ) -> Result<MusubiPinOutboxCurrentReadbackV1, MusubiPinOutboxCheckAttemptFailureV1> {
        let mut original = Some(self.bound);
        match consume_attempt(
            &self.prepared,
            &mut original,
            self.generation,
            self.applied_floor,
            expected_state,
        ) {
            Ok((canonical_external, check_block_hash)) => Ok(MusubiPinOutboxCurrentReadbackV1 {
                instruction: self.prepared.instruction,
                applied_floor: self.applied_floor,
                canonical_external,
                check_block_hash,
            }),
            Err(error) => Err(MusubiPinOutboxCheckAttemptFailureV1 {
                error,
                pending: PendingMusubiPinOutboxCheckV1 {
                    prepared: self.prepared,
                    bound: original
                        .take()
                        .expect("failed consumption retains original binding"),
                },
            }),
        }
    }
}

impl MusubiPinOutboxCurrentReadbackV1 {
    /// Exact successfully executed Check, including independent session/inventory and challenge.
    #[must_use]
    pub const fn instruction(&self) -> &CheckMusubiPinOutboxV1 {
        &self.instruction
    }
    /// Authority-wide absence or the entire authenticated expected row at this cut.
    #[must_use]
    pub fn high_water(&self) -> Option<&MusubiPinOutboxHighWaterV1> {
        match &self.instruction.expected {
            MusubiPinOutboxCheckExpectationV1::Absent => None,
            MusubiPinOutboxCheckExpectationV1::Present(row) => Some(row),
        }
    }
    /// Native applied tip authenticated through the original floor and exact signed Check.
    #[must_use]
    pub const fn applied_floor(&self) -> MusubiPinOutboxCheckFloorV1 {
        self.applied_floor
    }
    /// Exact successfully executed canonical External bytes, retained within the shared bound.
    #[must_use]
    pub fn canonical_external(&self) -> &[u8] {
        self.canonical_external.as_slice()
    }
    /// Canonical hash of the block containing that exact successful Check.
    #[must_use]
    pub const fn check_block_hash(&self) -> [u8; 32] {
        self.check_block_hash
    }
}

#[cfg(test)]
mod tests;
