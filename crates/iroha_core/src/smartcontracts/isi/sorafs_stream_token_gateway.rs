//! Governed native gateway admissions, quotas, callback acknowledgements and lease recovery.
//!
//! Operators attest Torii's private token and route validation. This owner derives execution
//! coordinates from the exact signed transaction and publishes only atomic World transitions.
//! A successful instruction does not itself prove finalized or currently eligible serving.

use super::{Execute, sorafs_reputation::stream_token_delivery as delivery};
use crate::{
    query::stream_token_gateway::{
        commitment::instruction_digest,
        rows::TransitionError,
        storage::{self, WorldGatewayRows},
        transition::{self, TransitionInputs},
    },
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    account::AccountId,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::MutateSorafsStreamTokenGateway,
    },
    permission::Permission,
    sorafs::stream_token_gateway::native::{
        StreamTokenGatewayActionV1 as Action, StreamTokenGatewayExecutionV1,
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanManageSorafsReputationJournalPolicy, CanManageSorafsStreamTokenGateway,
    CanOperateSorafsStreamTokenGateway,
};
use mv::storage::StorageReadOnly;

pub(crate) mod direct_source;

fn rejected(error: TransitionError) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(format!(
        "stream-token gateway rejected: {error:?}"
    )))
}

fn has_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    permission: Permission,
) -> bool {
    world.accounts().get(authority).is_some()
        && (world.account_contains_inherent_permission(authority, &permission)
            || world
                .account_roles_iter(authority)
                .filter_map(|id| world.roles().get(id))
                .any(|role| role.permissions().any(|token| token == &permission)))
}

fn apply(
    instruction: &MutateSorafsStreamTokenGateway,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
    execution: &StreamTokenGatewayExecutionV1,
) -> Result<(), TransitionError> {
    let request = &instruction.request;
    request.validate().map_err(|_| TransitionError::Invalid)?;
    if &request.network_id != tx.network_id() {
        return Err(TransitionError::BindingMismatch);
    }
    if matches!(request.action, Action::Check(_)) {
        if execution.authority != *authority {
            return Err(TransitionError::BindingMismatch);
        }
        return crate::query::stream_token_gateway::check::evaluate_check(tx, request, execution)
            .map(|_| ());
    }
    let required = if matches!(request.action, Action::Configure(_)) {
        CanManageSorafsStreamTokenGateway.into()
    } else if matches!(request.action, Action::CancelReputationDelivery { .. }) {
        CanManageSorafsReputationJournalPolicy.into()
    } else {
        CanOperateSorafsStreamTokenGateway {
            gateway_id: request.gateway_id,
        }
        .into()
    };
    if !has_permission(tx.world(), authority, required) {
        return Err(TransitionError::BindingMismatch);
    }
    let digest = instruction_digest(instruction, authority)?;
    if let Action::Configure(policy) = &request.action {
        if policy
            .operators
            .iter()
            .chain(&policy.observers)
            .any(|account| tx.world().accounts().get(account).is_none())
        {
            return Err(TransitionError::BindingMismatch);
        }
        return storage::configure(
            tx,
            policy,
            request.expected_policy_revision,
            request.expected_policy_digest,
            execution,
            digest,
        );
    }
    let current = storage::read_current(tx.world(), &request.network_id, request.gateway_id)?
        .ok_or(TransitionError::Unavailable)?;
    let policy = &current.policy.policy;
    if policy.qualification.revision != request.expected_policy_revision
        || policy.qualification.policy_digest != request.expected_policy_digest
    {
        return Err(TransitionError::Conflict);
    }
    if let Action::CancelReputationDelivery {
        record,
        expected_recorder_policy_digest,
        reason,
    } = &request.action
    {
        delivery::prepare_cancellation(
            tx,
            authority,
            record,
            *expected_recorder_policy_digest,
            *reason,
            execution,
            policy.qualification,
        )
        .map_err(|_| TransitionError::BindingMismatch)?
        .publish(tx);
        return Ok(());
    }
    let (ack_writes, ack_delivery) = if let Action::Acknowledge(record) = &request.action {
        let (writes, delivery) = delivery::prepare_acknowledgement(tx, record, execution)
            .map_err(|_| TransitionError::BindingMismatch)?;
        (writes, Some(delivery))
    } else {
        (delivery::Prepared::default(), None)
    };
    let rows = WorldGatewayRows::new(tx.world(), &request.network_id, request.gateway_id)?;
    let input = TransitionInputs {
        policy,
        head: current.head.head,
        execution,
    };
    let delta = match &request.action {
        Action::Admit(request) => transition::admit(input, &rows, request),
        Action::Acknowledge(record) => transition::acknowledge(
            input,
            &rows,
            record,
            ack_delivery.ok_or(TransitionError::Invalid)?,
        ),
        Action::ReleaseLease(record) => transition::release_lease(input, &rows, record),
        Action::Expire { max_items } => transition::expire(input, &rows, *max_items),
        Action::Configure(_) | Action::Check(_) | Action::CancelReputationDelivery { .. } => {
            return Err(TransitionError::Invalid);
        }
    }?;
    let source_writes =
        delivery::prepare_admission(tx, &delta).map_err(|_| TransitionError::BindingMismatch)?;
    let gateway_writes = storage::prepare_delta(tx, &current, execution, digest, &delta)?;
    // Nothing below this line can fail: the three owners publish into the same World overlay.
    gateway_writes.publish(tx);
    source_writes.publish(tx);
    ack_writes.publish(tx);
    Ok(())
}

impl Execute for MutateSorafsStreamTokenGateway {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        // Consume the gateway-specific marker before validation, including rejection paths.
        let execution = direct_source::execution(tx, authority).map_err(|_| {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "stream-token gateway requires exact direct signed execution".into(),
            ))
        })?;
        apply(&self, authority, tx, &execution).map_err(rejected)
    }
}

#[cfg(test)]
mod tests;
