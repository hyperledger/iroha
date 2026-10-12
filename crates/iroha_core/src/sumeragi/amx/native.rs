//! Signed-root native participant transitions and exclusively authenticated monetary custody.

mod retained;
pub use retained::{GraphError as NativeAmxAdmissionError, RetainedNativeAmx};

use crate::{
    smartcontracts::Execute,
    state::{StateReadOnly, StateStorageAdmissionError, StateTransaction, WorldReadOnly},
};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_data_model::{
    account::AccountId,
    asset::AssetBalanceScope,
    block::consensus::SumeragiRootScope,
    isi::{
        error::InstructionExecutionError as Error,
        sumeragi_amx::{
            PrepareAmxV1, RegisterAmxParticipantV1, RelayGlobalAmxHandoffV1, SettleAmxV1,
        },
    },
    sumeragi_amx::{
        AllocatedAmxTransferLegV1, AmxError, AmxEscrow, AmxLegDecodeErrorV1, AmxLegV1,
        AmxOutcomeV1, AmxParticipantError, AmxRecordV1, MAX_AMX_DEADLINE_WINDOW,
        NativeAmxParticipantStateV1, PendingAmxTransferLegDecodeV1,
    },
};
use iroha_model_base::topology::DataSpaceId;
use mv::{
    cell::{Cell, CellInitialization},
    storage::StorageReadOnly,
};
use retained::{Candidate, EscrowInput, GraphError, RegistrationSource, RetainedGlobalSource};
mod retry;
#[cfg(test)]
pub(crate) use retry::LegExecutionError as NativeLegExecutionError;
pub(crate) use retry::{NativeAmxLegExecution, NativeAmxLegPreparations};

fn cell_admission_error(
    error: mv::cell::CellInitializationError,
) -> mv::storage::AdmittedStorageError {
    match error {
        mv::cell::CellInitializationError::Admission(error) => {
            mv::storage::AdmittedStorageError::Allocation(error)
        }
        mv::cell::CellInitializationError::Allocator { layout } => {
            mv::storage::AdmittedStorageError::Allocator { layout }
        }
    }
}

pub(crate) fn empty_participant_cell(
    budget: &AllocationBudget,
) -> Result<Cell<RetainedNativeAmx, AllocationCharge>, mv::storage::AdmittedStorageError> {
    CellInitialization::try_reserve(budget)
        .map(|initial| initial.initialize(RetainedNativeAmx::default(), None))
        .map_err(cell_admission_error)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}

/// Keep the original custody account permanently and both parties until every Yes is closed.
pub(crate) fn retained_account(world: &impl WorldReadOnly, account: &AccountId) -> bool {
    world
        .sumeragi_amx_participant()
        .canonical()
        .is_some_and(|state| {
            &state.custody == account
                || state.escrows.iter().any(|record| {
                    record.settled.is_none()
                        && (record.leg.source.account() == account
                            || &record.leg.destination == account)
                })
        })
}

/// Preserve monetary definitions referenced by immutable original AMX records.
pub(crate) fn ensure_retained_definitions(
    world: &impl WorldReadOnly,
    definitions: &std::collections::BTreeSet<iroha_data_model::asset::AssetDefinitionId>,
) -> Result<(), Error> {
    if world
        .sumeragi_amx_participant()
        .canonical()
        .is_some_and(|state| {
            state
                .escrows
                .iter()
                .any(|record| definitions.contains(record.leg.source.definition()))
        })
    {
        return Err(invalid(
            "asset definition is retained by original native AMX monetary custody",
        ));
    }
    Ok(())
}

fn graph_error(error: GraphError, state: &mut StateTransaction<'_, '_>) -> Error {
    if matches!(
        error,
        GraphError::Admission(_) | GraphError::Allocator { .. } | GraphError::Codec(_)
    ) {
        state.arm_local_storage_refusal(StateStorageAdmissionError::NativeAmx(error.clone()));
    }
    invalid(error.to_string())
}

/// Install both initial Cell generations and every immutable graph in the new State's own pool.
/// Construction admits memory only. Even a live owner's capability belongs to its original
/// certified execution history and cannot cross a new-State boundary without replay.
pub(crate) fn admit_world_state(
    world: &mut crate::state::World,
    budget: &AllocationBudget,
) -> Result<(), StateStorageAdmissionError> {
    let current = world.sumeragi_amx_participant.view();
    let previous = world.sumeragi_amx_participant.predecessor_view();
    let admit = |source: &RetainedNativeAmx| {
        source
            .canonical()
            .map(|value| RetainedNativeAmx::admit(value, budget))
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(StateStorageAdmissionError::NativeAmx)
    };
    let current_value = admit(&current)?;
    let previous_value = previous.as_ref().map(admit).transpose()?;
    let initial = CellInitialization::try_reserve(budget).map_err(cell_admission_error)?;
    drop((current, previous));
    world.sumeragi_amx_participant = initial.initialize(current_value, previous_value);
    Ok(())
}

fn participant_error(
    error: AmxParticipantError<Error>,
    state: &mut StateTransaction<'_, '_>,
) -> Error {
    match error {
        AmxParticipantError::Protocol(error) => super::amx_error(error, state),
        AmxParticipantError::Resource(resource) => {
            super::amx_error(AmxError::Resource(resource), state)
        }
        AmxParticipantError::Escrow(error) => error,
    }
}

fn private_scope(
    state: &mut StateTransaction<'_, '_>,
    target: DataSpaceId,
) -> Result<iroha_data_model::NetworkId, Error> {
    let scope = crate::executor::root_scope::execution_root_scope(state)
        .map_err(|error| invalid(error.to_string()))?;
    match scope {
        SumeragiRootScope::Dataspace {
            parent_network_id,
            dataspace_id,
        } if target == dataspace_id
            && state.current_dataspace_id == Some(dataspace_id)
            && state.world.current_dataspace_id == Some(dataspace_id) =>
        {
            Ok(parent_network_id)
        }
        _ => Err(invalid(
            "native AMX participant requires its exact authenticated private root",
        )),
    }
}

fn custody(network: iroha_data_model::NetworkId) -> AccountId {
    AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
        b"iroha-native-amx-custody-v1",
        &[network.as_bytes()],
    ))
}

fn original(
    state: &mut StateTransaction<'_, '_>,
    target: DataSpaceId,
) -> Result<RetainedNativeAmx, Error> {
    let parent = private_scope(state, target)?;
    let owner = state.world.sumeragi_amx_participant().clone();
    let canonical = owner
        .canonical()
        .ok_or_else(|| invalid("native AMX participant was not installed by signed genesis"))?;
    let budget = state.pipeline_ivm_prepared_cache.execution_budget();
    if canonical.participant.dataspace != target
        || canonical.participant.global.current.network_id != parent
        || canonical.custody != custody(*state.network_id())
        || !owner.belongs_to(budget)
        || !owner.is_authenticated()
    {
        return Err(invalid(
            "native AMX participant lost its signed root or original pool",
        ));
    }
    Ok(owner)
}

/// Decode exactly one bounded canonical source without changing inherited caller limits.
fn decode_global_source(
    wire: &[u8],
    budget: &AllocationBudget,
) -> Result<
    iroha_data_model::block::SharedSignedBlock,
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    use crate::execution_attempt::{canonical_decode_attempt_error, norito_decode_attempt_error};
    if wire.is_empty()
        || !u64::try_from(wire.len()).is_ok_and(|length| {
            length <= iroha_data_model::block::consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES
        })
    {
        return Err(
            invalid("native AMX global source exceeds the canonical block format bound").into(),
        );
    }
    let shell = iroha_data_model::block::SharedSignedBlock::reserve(budget)
        .map_err(|error| crate::execution_attempt::ExecutionAttemptError::Deferred(error.into()))?;
    let block =
        norito::core::with_decode_limits_scope(norito::canonical_decode_limits(wire.len()), || {
            iroha_data_model::block::decode_framed_signed_block(wire)
        })
        .map_err(|error| {
            canonical_decode_attempt_error(error, |error| invalid(error.to_string()))
        })?;
    let identity = block
        .canonical_wire_identity()
        .map_err(|error| norito_decode_attempt_error(error, |error| invalid(error.to_string())))?;
    if identity != (wire.len() as u64, iroha_crypto::Hash::new(wire)) {
        return Err(
            invalid("native AMX global source is not the exact canonical SignedBlockWire").into(),
        );
    }
    Ok(shell.initialize(block))
}

/// Admit only the physical prefix slot before calling the sole signed-source verifier.
/// TODO(S6): the shared verifier's nested decoded/crypto graphs need their own original-pool
/// custody; this exact slot charge does not claim to fund those separate allocations.
fn global_source_prefix(
    chain_id: &iroha_model_base::chain::ChainId,
    parent: iroha_data_model::NetworkId,
    wire: &[u8],
    budget: &AllocationBudget,
) -> Result<
    iroha_allocation::ChargedBuffer<crate::sumeragi::certified_chain::CertifiedPrefix>,
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    let genesis = decode_global_source(wire, budget)?;
    if iroha_data_model::NetworkId::from_genesis_hash(genesis.hash()) != parent {
        return Err(
            invalid("native AMX global genesis differs from the signed private parent").into(),
        );
    }
    let metadata = iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
        .map_err(|error| {
            crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                invalid(error.to_string())
            })
        })?;
    if metadata.sumeragi_context.root_scope != SumeragiRootScope::Global {
        return Err(invalid("native AMX parent genesis does not own the Global root").into());
    }
    crate::sumeragi::certified_chain::CertifiedPrefix::new_admitted(
        chain_id, parent, genesis, budget,
    )
    .map_err(|error| error.map_rejection(|error| invalid(error.to_string())))
}

// Same local graph refusal owner as native World admission, without mutating State
// during the side-effect-free source verifier. Completed shape errors remain rejected.
fn global_source_graph_error(
    error: GraphError,
) -> crate::execution_attempt::ExecutionAttemptError<Error> {
    use crate::execution_attempt::ExecutionAttemptError;
    match error {
        GraphError::Admission(error) => ExecutionAttemptError::Deferred(error.into()),
        GraphError::Allocator { .. } => ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        ),
        GraphError::Codec(resource) => {
            // Graph admission already validated the original opaque attempt. These exact
            // fields retain that classification after its scope retires; a new active
            // scope must never decide whether the original refusal was local.
            let reason = match resource {
                norito::core::DecodeResourceError::AllocationFailed { .. } => {
                    ivm::error::ExecutionDeferral::AllocationUnavailable
                }
                _ => ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
            };
            ExecutionAttemptError::Deferred(reason.into())
        }
        invalid_graph => invalid(invalid_graph.to_string()).into(),
    }
}

#[cfg(test)]
mod graph_refusal_tests {
    use super::*;

    #[test]
    fn global_source_refusal_keeps_classification_after_original_scope_retires() {
        use crate::execution_attempt::ExecutionAttemptError;
        let original = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || norito::core::classify_decode_attempt(|| norito::core::reserve_decode_allocation(1)),
        )
        .unwrap_err();
        let graph = GraphError::from(AmxError::Resource(original));
        let mapped = global_source_graph_error(graph);
        let ExecutionAttemptError::Deferred(local) = mapped else {
            panic!("captured graph refusal lost its origin: {mapped:?}");
        };
        assert_eq!(
            local.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(local.allocation_refusal().is_none());
        assert!(matches!(
            global_source_graph_error(GraphError::Invalid("completed".into())),
            ExecutionAttemptError::Rejected(_)
        ));
    }
}

/// Consume the complete H2 verification receipt in its own bounded stack stage.
fn authenticate_global_successor(
    prefix: &mut crate::sumeragi::certified_chain::CertifiedPrefix,
    wire: &[u8],
    budget: &AllocationBudget,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let successor = decode_global_source(wire, budget)?;
    let has_original_genesis_anchor = prefix
        .push_admitted_with_finish(successor, budget, |step| step.has_genesis_anchor())
        .map_err(|error| error.map_rejection(|error| invalid(error.to_string())))?;
    if !has_original_genesis_anchor {
        return Err(invalid("native AMX global genesis has no genuine H2 execution anchor").into());
    }
    Ok(())
}

/// Authenticate complete canonical sources through the sole native prefix verifier.
/// The real H2 quorum binds the otherwise unsigned genesis execution result.
fn authenticated_global_source(
    chain_id: &iroha_model_base::chain::ChainId,
    parent: iroha_data_model::NetworkId,
    genesis_wire: &[u8],
    successor_wire: &[u8],
    budget: &AllocationBudget,
) -> Result<RetainedGlobalSource, crate::execution_attempt::ExecutionAttemptError<Error>> {
    let mut original = global_source_prefix(chain_id, parent, genesis_wire, budget)?;
    let prefix = &mut original.as_mut_slice()[0];
    let instance = prefix.instance();
    let global = RetainedGlobalSource::admit(instance.0, prefix.current_epoch_context(), budget)
        .map_err(global_source_graph_error)?;
    authenticate_global_successor(prefix, successor_wire, budget)?;
    // Preserve the original tracker validation after the genuine H2 has authenticated
    // genesis execution. Admission/copying alone never publishes authority.
    global
        .canonical()
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(global)
}

impl Execute for RegisterAmxParticipantV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let parent = private_scope(state, self.dataspace)?;
        // A genesis-shaped header or a governance permission cannot manufacture this capability.
        if state.genesis_execution_scope.is_none()
            || !state._curr_block.is_genesis()
            || state.world.sumeragi_amx_participant().canonical().is_some()
        {
            return Err(invalid(
                "native AMX participant installation requires its original signed genesis exactly once",
            ));
        }
        let budget = state.pipeline_ivm_prepared_cache.execution_budget().clone();
        let global = authenticated_global_source(
            &self.global_chain_id,
            parent,
            &self.global_genesis,
            &self.global_successor,
            &budget,
        )
        .map_err(|error| state.attempt_error_to_instruction_error(error))?;
        let mut label =
            iroha_allocation::ChargedBuffer::new(self.global_chain_id.as_str().len(), &budget)
                .map_err(|error| graph_error(error.into(), state))?;
        label
            .append(self.global_chain_id.as_str().as_bytes())
            .map_err(|error| invalid(error.to_string()))?;
        let custody = custody(*state.network_id());
        // The returned context and original label scratch stay alive while the same
        // graph copier admits the final World owner. No context is moved uncharged.
        let owner = RetainedNativeAmx::admit_registration(
            RegistrationSource {
                dataspace: self.dataspace,
                global: &global,
                global_genesis: &self.global_genesis,
                global_successor: &self.global_successor,
                global_chain_label: label.as_slice(),
                custody: &custody,
            },
            &budget,
        )
        .map_err(|error| graph_error(error, state))?
        .authenticate();
        crate::smartcontracts::isi::helpers::ensure_custody_account(&custody, state)?;
        *state.world.sumeragi_amx_participant.get_mut() = owner;
        Ok(())
    }
}

/// One exact native movement selected only after the original proof/authority checks.
/// Its private construction prevents ordinary escrow or user code from selecting retained custody.
pub(crate) struct VerifiedAmxMovement {
    owner: RetainedNativeAmx,
    slot: usize,
    outcome: Option<AmxOutcomeV1>,
}
impl VerifiedAmxMovement {
    /// Consume the exact checked leg. The monetary kernel independently rejoins retained State.
    pub(crate) fn into_parts(self) -> (RetainedNativeAmx, usize, Option<AmxOutcomeV1>) {
        (self.owner, self.slot, self.outcome)
    }
}

/// A side-effect-free component host selecting one already prepaid monetary movement.
/// The real kernel executes after the candidate's complete graph has become immutable.
struct Intent {
    tx: [u8; 32],
    effects: Option<[u8; 32]>,
    expected_outcome: Option<AmxOutcomeV1>,
    invoked: bool,
}
impl AmxEscrow for Intent {
    type Error = Error;
    fn escrow(&mut self, tx: &[u8; 32], _leg: &AmxLegV1) -> Result<Option<[u8; 32]>, Error> {
        if tx != &self.tx || self.expected_outcome.is_some() || self.invoked {
            return Err(invalid("native AMX prepare intent changed or repeated"));
        }
        self.invoked = true;
        Ok(self.effects)
    }
    fn apply(&mut self, tx: &[u8; 32]) -> Result<(), Error> {
        self.settle(tx, AmxOutcomeV1::Commit)
    }
    fn release(&mut self, tx: &[u8; 32]) -> Result<(), Error> {
        self.settle(tx, AmxOutcomeV1::Abort)
    }
}
impl Intent {
    fn settle(&mut self, tx: &[u8; 32], outcome: AmxOutcomeV1) -> Result<(), Error> {
        if tx != &self.tx || self.expected_outcome != Some(outcome) || self.invoked {
            return Err(invalid("native AMX settlement intent changed or repeated"));
        }
        self.invoked = true;
        Ok(())
    }
}

#[cfg(test)]
mod retry_probe;

fn decode_leg(
    bytes: &[u8],
    budget: &AllocationBudget,
) -> Result<AllocatedAmxTransferLegV1, AmxLegDecodeErrorV1> {
    let result = with_leg_decode_pool(budget, |budget| {
        PendingAmxTransferLegDecodeV1::new(bytes, budget).try_decode(bytes)
    });
    #[cfg(test)]
    if let Ok(owner) = &result {
        retry_probe::decoded(
            bytes,
            owner.canonical(),
            owner.allocation_bytes().unwrap(),
            budget,
        );
    }
    result
}

fn decode_retained_leg(
    pending: &mut PendingAmxTransferLegDecodeV1,
    bytes: &[u8],
    budget: &AllocationBudget,
) -> Result<iroha_data_model::sumeragi_amx::CompletedAmxTransferLegDecodeV1, AmxLegDecodeErrorV1> {
    if !pending.belongs_to(budget) {
        return Err(AmxLegDecodeErrorV1::Invariant(
            "original native AMX decoder pool changed",
        ));
    }
    #[cfg(test)]
    let before = budget.reserved_bytes();
    let result = pending.try_decode_retained(bytes);
    #[cfg(test)]
    retry_probe::retained_attempt(&result, before, budget);
    #[cfg(test)]
    if let Ok(owner) = &result {
        retry_probe::decoded(
            bytes,
            owner.canonical(),
            owner.allocation_bytes().unwrap(),
            budget,
        );
    }
    result
}

fn with_leg_decode_pool<R>(
    budget: &AllocationBudget,
    decode: impl FnOnce(&AllocationBudget) -> R,
) -> R {
    // HC149 changes only the owning pool, in both canonical lifetime variants.
    #[cfg(all(test, sumeragi_core_mutation = "HC149"))]
    {
        let foreign = AllocationBudget::new(budget.limit_bytes());
        decode(&foreign)
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC149")))]
    decode(budget)
}

fn leg_decode_bookkeeping_error(state: &mut StateTransaction<'_, '_>) -> Error {
    state.attempt_error_to_instruction_error(
        crate::execution_attempt::ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
        ),
    )
}

fn leg_decode_error(error: AmxLegDecodeErrorV1, state: &mut StateTransaction<'_, '_>) -> Error {
    match error {
        AmxLegDecodeErrorV1::Allocation(error) => graph_error(error.into(), state),
        AmxLegDecodeErrorV1::Decode(error) => {
            let original =
                crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                    // Diagnostics are an existing separate allocation boundary; the
                    // original classifier decides local refusal before this branch.
                    invalid(error.to_string())
                });
            state.attempt_error_to_instruction_error(original)
        }
        // The sole Model validator already completed this intrinsic relation.
        // Retain its exact cause until the existing terminal diagnostic boundary;
        // no allocation/scope refusal or local retry origin is inferred here.
        AmxLegDecodeErrorV1::Multisig(error) => invalid(error.to_string()),
        AmxLegDecodeErrorV1::Codec(error) => invalid(error.to_string()),
        AmxLegDecodeErrorV1::Scope(error) => match error {
            norito::core::PreparedDecodeScopeError::Allocation(
                iroha_allocation::PrepaidSharedError::Allocator { requested_bytes },
            ) => graph_error(
                GraphError::Allocator {
                    bytes: requested_bytes,
                },
                state,
            ),
            norito::core::PreparedDecodeScopeError::ForeignPool => {
                leg_decode_bookkeeping_error(state)
            }
            norito::core::PreparedDecodeScopeError::Reservation(_)
            | norito::core::PreparedDecodeScopeError::Allocation(
                iroha_allocation::PrepaidSharedError::Reservation(_),
            ) => leg_decode_bookkeeping_error(state),
            norito::core::PreparedDecodeScopeError::AttemptExhausted => {
                leg_decode_bookkeeping_error(state)
            }
        },
        AmxLegDecodeErrorV1::Record(message) => super::amx_error(AmxError::Record(message), state),
        AmxLegDecodeErrorV1::Invariant(_) => leg_decode_bookkeeping_error(state),
    }
}

impl Execute for PrepareAmxV1 {
    fn execute(
        self,
        authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_prepare_original(&self, authority, state)
    }
}

/// Execute the actual registered AMX fields without cloning their retained proof graph.
pub(crate) fn execute_prepare_original(
    instruction: &PrepareAmxV1,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let original = original(state, instruction.dataspace)?;
    let source = original.canonical().expect("checked participant");
    let leg = instruction
        .transaction
        .leg(instruction.dataspace)
        .ok_or_else(|| invalid("native AMX transaction has no exact local leg"))?;
    let budget = state.pipeline_ivm_prepared_cache.execution_budget().clone();
    // The optional attempt borrow is installed only by the authenticated native
    // block driver. Taking it separates its mutable bank from State, not authority.
    let mut execution = state.native_amx_leg_execution.take();
    let ordinal = state.current_direct_amx_instruction_index;
    let result = if let (Some(execution), Some(ordinal)) = (execution.as_mut(), ordinal) {
        execution
            .with_leg(instruction, ordinal, &budget, |transfer| {
                execute_prepare_with_transfer(
                    instruction,
                    authority,
                    state,
                    source,
                    transfer,
                    &budget,
                )
            })
            .map_err(|error| match error {
                retry::LegExecutionError::Decode(error) => leg_decode_error(error, state),
                retry::LegExecutionError::Metadata(error) => graph_error(error.into(), state),
                retry::LegExecutionError::Invariant => leg_decode_bookkeeping_error(state),
                retry::LegExecutionError::Execution(error) => error,
            })
    } else {
        // Contract/trigger/ad-hoc consumers retain the same canonical funded
        // decoder and authority checks; this patch does not retain their attempts.
        // TODO: carry completed owners across those enclosing invocation lifetimes.
        decode_leg(&leg.payload, &budget)
            .map_err(|error| leg_decode_error(error, state))
            .and_then(|transfer| {
                execute_prepare_with_transfer(
                    instruction,
                    authority,
                    state,
                    source,
                    transfer.canonical(),
                    &budget,
                )
            })
    };
    state.native_amx_leg_execution = execution;
    result
}

fn execute_prepare_with_transfer(
    instruction: &PrepareAmxV1,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
    source: &NativeAmxParticipantStateV1,
    transfer: &iroha_data_model::sumeragi_amx::AmxTransferLegV1,
    budget: &AllocationBudget,
) -> Result<(), Error> {
    #[cfg(test)]
    retry_probe::borrowed(transfer);
    if (!cfg!(all(test, sumeragi_core_mutation = "HC95")) && transfer.source.account() != authority)
        || transfer.source.scope() != &AssetBalanceScope::Dataspace(instruction.dataspace)
        || transfer.source.account() == &transfer.destination
        || transfer.amount.is_zero()
        || transfer.source.account() == &source.custody
        || transfer.destination == source.custody
    {
        return Err(invalid(
            "native AMX transfer requires its exact signed local source and positive distinct-party leg",
        ));
    }
    state.world.account(authority)?;
    state.world.account(&transfer.destination)?;
    let tx = instruction
        .transaction
        .id()
        .map_err(|error| super::amx_error(error, state))?;
    let held = source
        .participant
        .held
        .binary_search_by_key(&tx, |held| held.decision.tx)
        .is_ok();
    let available = state
        .world
        .assets
        .get(&transfer.source)
        .is_some_and(|balance| **balance >= transfer.amount);
    // This host supports ordinary non-retail transfers. Unsupported enrolled-wallet or
    // protected retail monetary legs record No before any maintenance or payment hook.
    let supported = crate::retail_fee::native_amx_leg_supported(
        &state.world,
        &transfer.source,
        &transfer.destination,
    )
    .map_err(|error| state.attempt_error_to_instruction_error(error.map_rejection(invalid)))?;
    let effects = iroha_data_model::sumeragi_amx::native_transfer_effects_hash(transfer)
        .map_err(|error| super::amx_error(error, state))?;
    let record = (!held && available && supported).then_some(EscrowInput {
        tx,
        effects_hash: effects,
        leg: transfer,
        custody: &source.custody,
        settled: None,
    });
    let mut candidate = Candidate::copy(source, budget, 1, 0, record, None).map_err(|error| {
        #[cfg(test)]
        retry_probe::candidate_refused(&error);
        graph_error(error, state)
    })?;
    let mut intent = Intent {
        tx,
        effects: record.as_ref().map(|record| record.effects_hash),
        expected_outcome: None,
        invoked: false,
    };
    let value = candidate
        .value
        .as_mut()
        .expect("original prepaid candidate");
    let prepared = value
        .participant
        .prepare(&mut intent, &instruction.transaction, &instruction.begin)
        .map_err(|error| participant_error(error, state))?;
    value.escrows.sort_unstable_by_key(|record| record.tx);
    let next = candidate
        .finish()
        .map_err(|error| graph_error(error, state))?
        .authenticate();
    // Witness encoding precedes monetary movement, so a resource refusal never follows a debit.
    super::write(&prepared).map_err(|error| super::amx_error(error, state))?;
    if record.is_some() {
        if !intent.invoked {
            return Err(invalid(
                "native AMX paid record was not selected by verified Prepare",
            ));
        }
        let movement = VerifiedAmxMovement {
            slot: next
                .canonical()
                .ok_or_else(|| invalid("native AMX candidate lost its original graph"))?
                .escrows
                .binary_search_by_key(&tx, |record| record.tx)
                .map_err(|_| invalid("native AMX candidate lost its exact funded escrow slot"))?,
            owner: next.clone(),
            outcome: None,
        };
        if let Err(error) =
            crate::smartcontracts::isi::asset::isi::execute_verified_amx_movement(state, movement)
        {
            state.reject_native_amx_effects(error.clone());
            return Err(error);
        }
    }
    *state.world.sumeragi_amx_participant.get_mut() = next;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Test-only finite admission of an untouched native Cell writer.
/// Nested authority remains shared with its original graph; these controls admit only the two
/// actual EBR allocations used by World acquisition/publication contention tests.
#[cfg(test)]
pub(crate) trait NativeAmxCellFixtureBlock {
    /// Acquire this exact field independently without acquiring other World writers.
    fn block(&self) -> mv::cell::Block<'_, RetainedNativeAmx, AllocationCharge>;
}
#[cfg(test)]
impl NativeAmxCellFixtureBlock for Cell<RetainedNativeAmx, AllocationCharge> {
    fn block(&self) -> mv::cell::Block<'_, RetainedNativeAmx, AllocationCharge> {
        let budget = AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        );
        let [current, undo] = Self::allocation_layouts();
        let mut original = budget
            .try_reserve_layouts([current, undo])
            .expect("native fixture EBR capacity");
        let charges = mv::cell::CellAllocationCharges::new(
            original
                .try_split(current)
                .expect("native fixture current EBR"),
            original.try_split(undo).expect("native fixture undo EBR"),
        );
        self.block_charged(charges)
    }
}

impl Execute for SettleAmxV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_settle_original(&self, _authority, state)
    }
}

/// Execute the actual registered AMX fields without cloning their retained proof graph.
pub(crate) fn execute_settle_original(
    instruction: &SettleAmxV1,
    _authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let original = original(state, instruction.dataspace)?;
    let source = original.canonical().expect("checked participant");
    let AmxRecordV1::Decision(decision) = instruction.decision.record else {
        return Err(invalid(
            "native AMX settlement needs the certified global Decision",
        ));
    };
    let record_slot = source
        .escrows
        .binary_search_by_key(&decision.tx, |record| record.tx)
        .ok()
        .filter(|slot| source.escrows[*slot].settled.is_none());
    let budget = state.pipeline_ivm_prepared_cache.execution_budget().clone();
    let mut candidate = Candidate::copy(
        source,
        &budget,
        0,
        usize::from(source.participant.entry(&decision.tx).is_none()),
        None,
        None,
    )
    .map_err(|error| graph_error(error, state))?;
    let mut intent = Intent {
        tx: decision.tx,
        effects: None,
        expected_outcome: Some(decision.outcome),
        invoked: false,
    };
    let value = candidate
        .value
        .as_mut()
        .expect("original prepaid candidate");
    value
        .participant
        .settle(&mut intent, &instruction.decision)
        .map_err(|error| participant_error(error, state))?;
    if intent.invoked {
        let slot = value
            .escrows
            .binary_search_by_key(&decision.tx, |record| record.tx)
            .map_err(|_| invalid("native AMX settlement lost its original escrow"))?;
        value.escrows[slot].settled = Some(decision.outcome);
    }
    let next = candidate
        .finish()
        .map_err(|error| graph_error(error, state))?
        .authenticate();
    if intent.invoked {
        let slot = record_slot.ok_or_else(|| {
            invalid("native AMX Yes settlement lost its original monetary record")
        })?;
        let movement = VerifiedAmxMovement {
            slot,
            owner: original.clone(),
            outcome: Some(decision.outcome),
        };
        if let Err(error) =
            crate::smartcontracts::isi::asset::isi::execute_verified_amx_movement(state, movement)
        {
            state.reject_native_amx_effects(error.clone());
            return Err(error);
        }
    }
    *state.world.sumeragi_amx_participant.get_mut() = next;
    Ok(())
}

impl Execute for RelayGlobalAmxHandoffV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let original = original(state, self.dataspace)?;
        let source = original.canonical().expect("checked participant");
        let global = &source.participant.global;
        let verified = global
            .verify_block(&self.proof.block)
            .map_err(|error| super::amx_error(error, state))?;
        if verified.epoch != global.epoch() {
            return Ok(());
        }
        if verified.height != global.current.authorization.last_height {
            return Err(invalid(
                "native AMX global handoff needs the certified last epoch block",
            ));
        }
        let boundary = verified
            .commitment
            .schedule
            .boundary
            .as_ref()
            .ok_or_else(|| invalid("native AMX global handoff has no certified boundary"))?;
        boundary
            .validate_against(&global.current)
            .map_err(invalid)?;
        let budget = state.pipeline_ivm_prepared_cache.execution_budget().clone();
        let mut candidate = Candidate::copy(source, &budget, 0, 0, None, Some(&boundary.next))
            .map_err(|error| graph_error(error, state))?;
        let participant = &mut candidate
            .value
            .as_mut()
            .expect("original prepaid candidate")
            .participant;
        participant.global_height = participant.global_height.max(verified.height);
        participant.prepared.retain(|entry| {
            entry.deadline >= participant.global_height
                || entry.settled.is_none()
                    && matches!(
                        entry.vote,
                        iroha_data_model::sumeragi_amx::AmxVoteV1::Yes(_)
                    )
        });
        participant.held.retain(|held| {
            held.height.saturating_add(MAX_AMX_DEADLINE_WINDOW) >= participant.global_height
        });
        let next = candidate
            .finish()
            .map_err(|error| graph_error(error, state))?
            .authenticate();
        *state.world.sumeragi_amx_participant.get_mut() = next;
        Ok(())
    }
}

/// Reuse the existing genuine paid roots and signed Begin in the Worker retry control.
#[cfg(test)]
pub(crate) fn with_paid_prepare_retry_fixture(
    test: impl FnOnce(
        &crate::sumeragi::test_chain::CertifiedTestChain,
        iroha_data_model::isi::InstructionBox,
        iroha_crypto::KeyPair,
    ),
) {
    tests::with_paid_prepare_retry_fixture(test);
}

/// Reuse a genuine signed Begin whose original receiver is canonically multisig.
#[cfg(test)]
pub(crate) fn with_paid_multisig_prepare_retry_fixture(
    test: impl FnOnce(
        &crate::sumeragi::test_chain::CertifiedTestChain,
        iroha_data_model::isi::InstructionBox,
        iroha_crypto::KeyPair,
    ),
) {
    tests::with_paid_multisig_prepare_retry_fixture(test);
}

#[cfg(test)]
pub(crate) use retry_probe::Observation as NativeLegRetryObservation;

/// Reuse genuine paid parent proofs to settle/prune a No vote in the same private block.
#[cfg(test)]
pub(crate) fn with_paid_prepare_pruning_fixture(
    test: impl FnOnce(
        &crate::sumeragi::test_chain::CertifiedTestChain,
        [iroha_data_model::isi::InstructionBox; 3],
        iroha_crypto::KeyPair,
        [[u8; 32]; 2],
    ),
) {
    tests::with_paid_prepare_pruning_fixture(test);
}
