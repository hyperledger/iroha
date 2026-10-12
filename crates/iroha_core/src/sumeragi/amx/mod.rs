//! AMX two-phase commit on the global chain (`specs/sumeragi.md` §11).
//!
//! The global chain `G` keeps its AMX state in the World cell `sumeragi_amx`
//! ([`iroha_data_model::sumeragi_amx::SumeragiAmxState`]) and changes it only through the pure, deterministic transitions of that
//! state. The executor requires the authenticated global root for all four coordinator
//! instructions, including genesis; a private dataspace bootstrap cannot install this role:
//!
//! - `RegisterAmxDataspaceV1` registers a participant dataspace with a foreign-committee tracker
//!   anchored at an authenticated epoch context of its consensus instance (in genesis, or by an
//!   authority holding `CanSetParameters`);
//! - `BeginAmxV1` records `Begin{x, participants, d}` (a second `Begin` for `x` is rejected);
//! - `RelayAmxPreparedV1` verifies a participant's `Prepared` record proof with its tracker; the
//!   first `No` decides `Abort`, the `Yes` that completes the votes at a height `≤ d` decides
//!   `Commit`, and later proofs are ignored;
//! - `RelayAmxHandoffV1` advances a participant's tracker by one epoch;
//! - after every block's transactions, [`StateBlock::advance_sumeragi_amx`] (the output seal's
//!   finalizer) aborts every transaction whose deadline passed undecided — in the first block
//!   with a height `> d` — and drops the transactions whose deadline passed.
//!
//! Every record (`Begin`, `Decision`) is also written into the block's execution witness under
//! its reserved key ([`crate::exec_witness::record_write_amx_record`]), so the ordinary-write root
//! of the block's certified result `R` commits it and a participant verifies it with a record
//! proof, without any change to `R`'s layout. Instruction writes land in the transaction's
//! witness overlay and roll back with a rejected transaction.
//! The mandatory native context archive persists each original complete write set under its
//! exact carrier. [`amx_record_proof`] authenticates that carrier and its complete write root
//! before constructing a historical record proof, including after deadline pruning and replay.
//!
//! **Participants.** Native private roots use an original-pool charged immutable participant
//! graph and dedicated monetary custody. Signed-genesis installation authenticates the complete
//! canonical global genesis and its real H2 successor through the native prefix verifier;
//! the source frames, derived authority and exact original transfer records remain retained.
//! Prepare and Settle consume the component protocol over a separately funded candidate before
//! protected monetary effects. Host failure retains the original participant for retry.
//! Decoding a snapshot admits memory without granting the unencoded execution capability;
//! authenticated participant restoration currently requires genuine genesis/journal replay.
//! Inherited decoder limits remain typed local refusals through anchors, records and certified
//! proofs. An executing instruction retains that refusal outside its canonical result, including
//! when contract code catches the inner error; a refused attempt cannot publish World effects.
//! Each daemon supervises its signed root with an independent State and mandatory native
//! context archive. Lane instances still share `G`'s State (`specs/sumeragi_lanes.md` §0).
//! Managed bootstrap retains the authenticated G1/H2 source; explicit administrative parent
//! registration retains its original transaction and independently verified native outcome.
//! TODO(S6): qualify that managed lifecycle, complete outbound proof custody and durable
//! validator relaying for pending proofs (§11.4), then qualify native monetary and
//! whole-network commit/abort/deadline/restart behavior across independent root daemons.
//! The resumable AMX reader retains its original carrier, archive descriptor and acquired bytes
//! through local refusal. Its move-only source can outlive the original StateView after the
//! same reader certifies the carrier and pins the archive descriptor. It prepays the complete
//! portable proof graph and tree scratch from
//! the same finite pool; its canonical InstructionBox successor retains those charges through
//! local signed admission, Queue and payload clones. Receiving decoder/envelope custody, other
//! native receipt proof graphs, historical reader internals and durable outbound relay remain
//! distinct open resource and whole-network qualification boundaries.

pub use crate::query::native_receipts::amx_record_proof;

use iroha_data_model::{
    account::AccountId,
    isi::{
        error::InstructionExecutionError as Error,
        sumeragi_amx::{BeginAmxV1, RegisterAmxDataspaceV1, RelayAmxHandoffV1, RelayAmxPreparedV1},
    },
    permission::Permission,
    sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_amx::{AmxError, AmxForeignInstanceV1, AmxRecordV1, AmxRelayOutcome},
    sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
};
use mv::storage::StorageReadOnly;

use crate::{
    smartcontracts::Execute,
    state::{StateBlock, StateTransaction, WorldReadOnly},
};

/// Retain decoder refusal outside every deterministic instruction/result carrier.
fn amx_error(error: AmxError, transaction: &mut StateTransaction<'_, '_>) -> Error {
    if let Some(resource) = classified_decode_refusal(&error)
        && !cfg!(all(test, sumeragi_core_mutation = "HC19"))
    {
        transaction.arm_local_storage_refusal(crate::state::StateStorageAdmissionError::AmxDecode(
            resource,
        ));
    }
    Error::InvariantViolation(format!("AMX: {error}").into())
}

/// Retain the original captured decoder owner after its scope retires.
/// Sticky State and native graph custody keep its opaque scope identity; copied
/// diagnostic numbers never replace the cause or create a pool release source.
pub(crate) fn classified_decode_refusal(
    error: &AmxError,
) -> Option<norito::core::DecodeLocalRefusal> {
    let AmxError::Resource(original) = error else {
        return None;
    };
    crate::execution_attempt::canonical_decode_deferral(original)?
        .decode_refusal()
        .cloned()
}

/// Record `record` as a World write of the executing block.
fn write(record: &AmxRecordV1) -> Result<(), AmxError> {
    crate::exec_witness::record_write_amx_record(record)
}

/// Borrow the exact canonical `CanSetParameters` grant, directly or through a role.
/// Constructing a token would allocate JSON under the caller's inherited decoder limit.
fn has_permission(world: &impl WorldReadOnly, authority: &AccountId) -> bool {
    let matches = |permission: &Permission| {
        permission.name() == "CanSetParameters" && permission.payload().get().as_str() == "null"
    };
    world
        .account_permissions_iter(authority)
        .is_ok_and(|permissions| permissions.into_iter().any(matches))
        || world.account_roles_iter(authority).any(|role| {
            world
                .roles()
                .get(role)
                .is_some_and(|role| role.permissions().any(matches))
        })
}

/// Decode a trust anchor: one canonical `ValidatorEpochContextV1` frame within the bound of a
/// result preimage, under the same cumulative limits as the certified results that carry it.
fn decode_anchor(bytes: &[u8]) -> Result<ValidatorEpochContextV1, AmxError> {
    if bytes.is_empty() || bytes.len() > MAX_RESULT_PREIMAGE_BYTES {
        return Err(AmxError::Anchor("the anchor exceeds its bound".into()));
    }
    let canonical = norito::canonical_decode_limits(bytes.len());
    norito::core::classify_decode_attempt(|| {
        norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(
                96,
                MAX_RESULT_PREIMAGE_BYTES,
                canonical.max_total_elements(),
                canonical.max_total_allocated_bytes(),
                32,
            ),
        )
    })
    .map_err(|error| {
        if error.kind() != norito::core::DecodeAttemptErrorKind::Invalid {
            return AmxError::Resource(error);
        }
        AmxError::Anchor(error.to_string())
    })
}

impl Execute for RegisterAmxDataspaceV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if !state_transaction._curr_block.is_genesis()
            && !has_permission(&state_transaction.world, authority)
        {
            return Err(amx_error(
                AmxError::State("registering an AMX dataspace needs genesis or CanSetParameters"),
                state_transaction,
            ));
        }
        let anchor =
            decode_anchor(&self.anchor).map_err(|error| amx_error(error, state_transaction))?;
        let tracker = AmxForeignInstanceV1::new(
            self.instance,
            anchor,
            iroha_data_model::sumeragi_finality::CertifiedResultScope::NonGlobal,
        )
        .map_err(|error| amx_error(error, state_transaction))?;
        state_transaction
            .world
            .sumeragi_amx
            .get_mut()
            .register_dataspace(self.dataspace, tracker)
            .map_err(|error| amx_error(error, state_transaction))
    }
}

impl Execute for BeginAmxV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let height = state_transaction._curr_block.height().get();
        let record = state_transaction
            .world
            .sumeragi_amx
            .get_mut()
            .begin(height, &self.transaction)
            .map_err(|error| amx_error(error, state_transaction))?;
        write(&record).map_err(|error| amx_error(error, state_transaction))
    }
}

impl Execute for RelayAmxPreparedV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_relay_prepared_original(&self, _authority, state_transaction)
    }
}

/// Execute the actual registered AMX fields without cloning their retained proof graph.
pub(crate) fn execute_relay_prepared_original(
    instruction: &RelayAmxPreparedV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let height = state_transaction._curr_block.height().get();
    // Proofs of unknown or decided transactions are ignored without touching the cell.
    let known = state_transaction
        .world
        .sumeragi_amx()
        .transaction(&instruction.proof.record.tx())
        .is_some_and(|entry| entry.decided.is_none());
    if !known {
        return Ok(());
    }
    let outcome = state_transaction
        .world
        .sumeragi_amx
        .get_mut()
        .relay_prepared(height, &instruction.proof)
        .map_err(|error| amx_error(error, state_transaction))?;
    if let AmxRelayOutcome::Decided(decision) = outcome {
        write(&AmxRecordV1::Decision(decision))
            .map_err(|error| amx_error(error, state_transaction))?;
    }
    Ok(())
}

impl Execute for RelayAmxHandoffV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        state_transaction
            .world
            .sumeragi_amx
            .get_mut()
            .relay_handoff(self.dataspace, &self.proof)
            .map(|_| ())
            .map_err(|error| amx_error(error, state_transaction))
    }
}

impl StateBlock<'_> {
    /// The AMX deadline step of the block this overlay executes (§11.5), run by the output
    /// seal's finalizer after the block's transactions: every transaction whose deadline passed
    /// without a decision is aborted and its `Decision` recorded, and every transaction whose
    /// deadline passed is dropped from the state. A block that has nothing to expire leaves the
    /// cell untouched.
    ///
    /// # Errors
    /// Preserve the original record/allocator refusal. No pending entry is removed before
    /// every decision write completes; provisional witness writes retry under the same keys.
    pub(crate) fn advance_sumeragi_amx(&mut self) -> Result<usize, AmxError> {
        self.advance_sumeragi_amx_with(write)
    }

    /// The same deadline owner accepts an injected record writer in unit controls.
    /// TODO: fund the existing global cell graph and witness encoding/storage independently.
    fn advance_sumeragi_amx_with(
        &mut self,
        mut record: impl FnMut(&AmxRecordV1) -> Result<(), AmxError>,
    ) -> Result<usize, AmxError> {
        let height = self._curr_block.height().get();
        if !self
            .world
            .sumeragi_amx
            .get()
            .transactions
            .iter()
            .any(|entry| entry.begin.deadline < height)
        {
            return Ok(0);
        }
        let outcome = self
            .world
            .sumeragi_amx
            .get_mut()
            .expire(height, |decision| record(&AmxRecordV1::Decision(decision)));
        #[cfg(all(test, sumeragi_core_mutation = "HC161"))]
        {
            outcome.map_err(|error| AmxError::Encoding(error.to_string()))
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC161")))]
        {
            outcome
        }
    }
}

#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod tests;

mod native;
pub(crate) use native::VerifiedAmxMovement;
pub(crate) use native::admit_world_state;
pub(crate) use native::empty_participant_cell;
pub use native::{NativeAmxAdmissionError, RetainedNativeAmx};
pub(crate) use native::{NativeAmxLegExecution, NativeAmxLegPreparations};
pub(crate) use native::{ensure_retained_definitions, retained_account};
pub(crate) use native::{execute_prepare_original, execute_settle_original};

#[cfg(test)]
pub(crate) use native::{
    NativeLegExecutionError, NativeLegRetryObservation, with_paid_multisig_prepare_retry_fixture,
    with_paid_prepare_pruning_fixture, with_paid_prepare_retry_fixture,
};
