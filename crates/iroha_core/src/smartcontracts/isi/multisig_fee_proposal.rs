//! Exact native proposal evidence for scoped sponsorship admission and settlement.
use super::*;

/// Read the canonical registered controller and validate its native policy.
/// Metadata alone never establishes a native multisig registration.
pub(crate) fn read_registered_account_state<W: WorldReadOnly>(
    world: &W,
    account: &AccountId,
) -> Result<Option<MultisigAccountState>, Attempt<ValidationFail>> {
    let key = multisig_account_state_key(account);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let state = norito::decode_from_bytes::<MultisigAccountState>(bytes)
        .map_err(multisig_decode_attempt)?;
    validate_registered_account_state(world, account.clone(), state).map(Some)
}

fn validate_registered_account_state<W: WorldReadOnly>(
    world: &W,
    resolved_account: AccountId,
    state: MultisigAccountState,
) -> Result<MultisigAccountState, Attempt<ValidationFail>> {
    if state.account_id != resolved_account {
        return Err(
            ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
                "native multisig account state is bound to `{}`, not `{resolved_account}`",
                state.account_id
            )))
            .into(),
        );
    }
    ensure_quorum_reachable(&state.spec)?;
    ensure_signatories_are_single(&state.spec)?;
    let expected_account = AccountId::new_multisig(
        multisig_policy_from_spec(&state.spec).map_err(ValidationFail::InstructionFailed)?,
    );
    if expected_account != resolved_account {
        return Err(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
            format!(
                "native multisig account state policy derives `{expected_account}`, not `{resolved_account}`"
            ),
        )).into());
    }
    let account = world.account(&resolved_account).map_err(map_find_error)?;
    // Json::as_ref removes outer quotes from strings; typed decoders need the
    // exact canonical JSON document retained by get().
    if let Some(metadata_spec) = account.metadata().get(&spec_key()) {
        let metadata_spec = norito::json::from_str::<MultisigSpec>(metadata_spec.get().as_str())
            .map_err(|err| {
                json_decode_attempt_error(err, |err| {
                    ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
                        "invalid multisig/spec metadata for `{resolved_account}`: {err}"
                    )))
                })
            })?;
        if metadata_spec != state.spec {
            return Err(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
                format!(
                    "multisig/spec metadata disagrees with canonical native account state for `{resolved_account}`"
                ),
            )).into());
        }
    }
    if let Some(metadata_home_domain) = account.metadata().get(&home_domain_key()) {
        let metadata_home_domain = norito::json::from_str::<
            Option<iroha_model_base::domain::DomainId>,
        >(metadata_home_domain.get().as_str())
        .map_err(|err| {
            json_decode_attempt_error(err, |err| {
                ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
                    "invalid multisig home-domain metadata for `{resolved_account}`: {err}"
                )))
            })
        })?;
        if metadata_home_domain != state.home_domain {
            return Err(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
                format!(
                    "multisig home-domain metadata disagrees with canonical native account state for `{resolved_account}`"
                ),
            )).into());
        }
    }
    Ok(state)
}

/// Sponsor a new proposal only when both exact native lifecycle keys are absent.
/// Existing, malformed, expired, or terminal bodies cannot be replay-paid as new work.
pub(crate) fn fee_proposal_key_is_unused<W: WorldReadOnly>(
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> bool {
    world
        .smart_contract_state()
        .get(&multisig_proposal_state_key(account, instructions_hash))
        .is_none()
        && world
            .smart_contract_state()
            .get(&multisig_proposal_terminal_state_key(
                account,
                instructions_hash,
            ))
            .is_none()
}

/// Project only an exact, live, non-relayed pending proposal for admission.
/// Terminal history cannot make a new approval eligible for sponsorship.
pub(crate) fn read_pending_fee_proposal<W: WorldReadOnly>(
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    observation_time_ms: u64,
) -> Result<Option<Vec<InstructionBox>>, Attempt<ValidationFail>> {
    let Some(proposal) = read_proposal_state(world, account, instructions_hash)? else {
        return Ok(None);
    };
    if world
        .smart_contract_state()
        .get(&multisig_proposal_terminal_state_key(
            account,
            instructions_hash,
        ))
        .is_some()
    {
        return Err(invalid_proposal_binding().into());
    }
    if proposal.is_relayed.is_some()
        || observation_time_ms < proposal.proposed_at_ms
        || observation_time_ms >= proposal.expires_at_ms
    {
        return Ok(None);
    }
    Ok(Some(proposal.instructions))
}

/// Recover a successful proposal only for this exact transaction's fee settlement.
/// The immutable terminal record is written before inner execution; its matching
/// `Executed` outcome is also mandatory. Callers must never use this for admission.
pub(crate) fn read_settled_fee_proposal<W: WorldReadOnly>(
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    current_entrypoint_hash: [u8; Hash::LENGTH],
    current_block_height: u64,
) -> Result<Option<Vec<InstructionBox>>, Attempt<ValidationFail>> {
    let terminal_key = multisig_proposal_terminal_state_key(account, instructions_hash);
    let Some(terminal_bytes) = world.smart_contract_state().get(&terminal_key) else {
        return Ok(None);
    };
    // A canonical non-relayed proposal is removed before becoming terminal.
    // Do not choose whichever of two contradictory versions grants authority.
    if world
        .smart_contract_state()
        .get(&multisig_proposal_state_key(account, instructions_hash))
        .is_some()
    {
        return Err(invalid_proposal_binding().into());
    }
    let terminal = norito::decode_from_bytes::<MultisigProposalTerminalState>(terminal_bytes)
        .map_err(multisig_decode_attempt)?;
    let actual_hash = HashOf::try_new(&terminal.proposal.instructions)
        .map_err(|error| multisig_instruction_decode_attempt(error, multisig_state_encode_error))?;
    if terminal.multisig_account_id != *account
        || terminal.instructions_hash != *instructions_hash
        || actual_hash != *instructions_hash
    {
        return Err(invalid_proposal_binding().into());
    }
    if terminal.status != MultisigProposalTerminalStatus::Finalized
        || terminal.proposal.is_relayed.is_some()
    {
        return Ok(None);
    }
    let execution_key = multisig_proposal_terminal_execution_state_key(
        current_entrypoint_hash,
        account,
        instructions_hash,
    );
    let outcome_key =
        multisig_approval_outcome_state_key(current_entrypoint_hash, account, instructions_hash);
    let (Some(execution_bytes), Some(outcome_bytes)) = (
        world.smart_contract_state().get(&execution_key),
        world.smart_contract_state().get(&outcome_key),
    ) else {
        return Ok(None);
    };
    let execution =
        norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(execution_bytes)
            .map_err(multisig_decode_attempt)?;
    let outcome = norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(outcome_bytes)
        .map_err(multisig_decode_attempt)?;
    if !same_terminal_evidence(&execution.terminal, &terminal)?
        || execution.entrypoint_account_id != *account
        || execution.terminal_entrypoint_hash != current_entrypoint_hash
        || execution.terminal_block_height != current_block_height
        || outcome.entrypoint_account_id != *account
        || outcome.resolved_multisig_account_id != *account
        || outcome.instructions_hash != *instructions_hash
        || outcome.entrypoint_hash != current_entrypoint_hash
        || outcome.block_height != current_block_height
    {
        return Err(invalid_proposal_binding().into());
    }
    if outcome.status != MultisigApprovalOutcomeStatusV1::Executed {
        return Ok(None);
    }
    Ok(Some(terminal.proposal.instructions))
}

/// Compare the complete lifecycle projection without `InstructionBox`'s infallible equality.
/// Both inner bodies must reproduce the same approved hash through checked streaming encoding.
fn same_terminal_evidence(
    left: &MultisigProposalTerminalState,
    right: &MultisigProposalTerminalState,
) -> Result<bool, Attempt<ValidationFail>> {
    if left.multisig_account_id != right.multisig_account_id
        || left.instructions_hash != right.instructions_hash
        || left.status != right.status
        || left.terminal_at_ms != right.terminal_at_ms
        || left.proposal.proposed_at_ms != right.proposal.proposed_at_ms
        || left.proposal.expires_at_ms != right.proposal.expires_at_ms
        || left.proposal.approvals != right.proposal.approvals
        || left.proposal.is_relayed != right.proposal.is_relayed
    {
        return Ok(false);
    }
    let hash = |instructions: &Vec<InstructionBox>| {
        HashOf::try_new(instructions).map_err(|error| {
            multisig_instruction_decode_attempt(error, multisig_state_encode_error)
        })
    };
    Ok(hash(&left.proposal.instructions)? == left.instructions_hash
        && hash(&right.proposal.instructions)? == right.instructions_hash)
}

/// Seed component-only settlement read evidence through the native canonical writers.
/// This does not execute the inner instructions or claim a committed transaction.
#[cfg(test)]
pub(crate) fn install_executed_fee_proposal_fixture(
    tx: &mut StateTransaction<'_, '_>,
    terminal: &MultisigProposalTerminalState,
    entrypoint_hash: [u8; Hash::LENGTH],
) -> Result<(), ValidationFail> {
    assert_eq!(terminal.status, MultisigProposalTerminalStatus::Finalized);
    assert!(terminal.proposal.is_relayed.is_none());
    assert!(
        tx.world
            .smart_contract_state
            .get(&multisig_proposal_state_key(
                &terminal.multisig_account_id,
                &terminal.instructions_hash,
            ))
            .is_none()
    );
    tx.tx_call_hash = Some(Hash::prehashed(entrypoint_hash));
    store_multisig_proposal_terminal_state(tx, terminal)?;
    store_multisig_proposal_terminal_execution_state(tx, terminal, &terminal.multisig_account_id)?;
    store_multisig_approval_outcome(
        tx,
        &terminal.multisig_account_id,
        &terminal.multisig_account_id,
        &terminal.instructions_hash,
        MultisigApprovalOutcomeStatusV1::Executed,
    )
}

#[cfg(test)]
#[path = "multisig_fee_proposal_tests.rs"]
mod tests;
